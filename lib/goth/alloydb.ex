defmodule Goth.AlloyDB do
  @moduledoc """
  Google Cloud AlloyDB integration for Goth.

  This module provides functionality for AlloyDB IAM authentication including:
  - OAuth2 token management via Goth
  - RSA keypair generation using native Elixir/Erlang crypto
  - Client certificate generation via AlloyDB Admin API
  - Postgrex connection helpers

  ## Usage

      # Basic token fetching
      {:ok, token} = Goth.AlloyDB.get_token(MyApp.Goth)

      # Generate complete Postgrex configuration
      config = Goth.AlloyDB.postgrex_config(
        goth_name: MyApp.Goth,
        hostname: "10.0.0.1",
        database: "postgres",
        username: "user@example.com"
      )
      {:ok, conn} = Postgrex.start_link(config)

      # For use with config_resolver pattern
      resolver = &Goth.AlloyDB.config_resolver/1
      {:ok, conn} = Postgrex.start_link([
        hostname: "10.0.0.1",
        database: "postgres", 
        config_resolver: resolver
      ])

  ## AlloyDB Authentication Flow

  1. **OAuth Token**: Fetched from Goth server (service account or metadata)
  2. **RSA Keypair**: Generated using native Elixir `:crypto.generate_key/2`
  3. **Client Certificate**: Requested from AlloyDB Admin API using public key
  4. **TLS Connection**: Established using client certificate for mutual auth
  5. **PostgreSQL Auth**: Token used as password with IAM username

  ## Configuration

  AlloyDB instances require specific configuration:

      config :my_app, MyApp.Goth,
        project_id: "my-project",
        location: "us-central1", 
        cluster: "my-cluster"

  Or pass options directly:

      Goth.AlloyDB.get_client_certificate(token, public_key,
        project_id: "my-project",
        location: "us-central1",
        cluster: "my-cluster"
      )
  """

  require Logger
  alias Goth.Token

  @default_scopes ["https://www.googleapis.com/auth/cloud-platform"]

  @doc """
  Fetches an OAuth2 access token from a Goth server.

  ## Examples

      {:ok, token} = Goth.AlloyDB.get_token(MyApp.Goth)
      # => "ya29.c.Ko8..."

      # With timeout
      {:ok, token} = Goth.AlloyDB.get_token(MyApp.Goth, 5000)
  """
  @spec get_token(atom(), timeout()) :: {:ok, String.t()} | {:error, term()}
  def get_token(goth_name, timeout \\ 5000) do
    case Goth.fetch(goth_name, timeout) do
      {:ok, %Token{token: token}} -> {:ok, token}
      error -> error
    end
  end

  @doc """
  Fetches token and raises on error.
  """
  @spec get_token!(atom(), timeout()) :: String.t()
  def get_token!(goth_name, timeout \\ 5000) do
    case get_token(goth_name, timeout) do
      {:ok, token} -> token
      {:error, reason} -> raise "Failed to fetch AlloyDB token: #{inspect(reason)}"
    end
  end

  @doc """
  Checks if the current token is valid (not expired).

  ## Examples

      if Goth.AlloyDB.token_valid?(MyApp.Goth) do
        # Token is valid, proceed
      else
        # Token expired or invalid
      end
  """
  @spec token_valid?(atom()) :: boolean()
  def token_valid?(goth_name) do
    case Goth.fetch(goth_name) do
      {:ok, %Token{expires: expires}} -> 
        expires > :os.system_time(:second)
      _ -> 
        false
    end
  end

  @doc """
  Generates RSA keypair using native Elixir/Erlang crypto.

  This implementation works with OTP 27+ and eliminates OpenSSL dependencies.

  ## Examples

      {private_pem, public_pem} = Goth.AlloyDB.generate_rsa_keypair()
      {private_pem, public_pem} = Goth.AlloyDB.generate_rsa_keypair(4096)

  ## Returns

  A tuple `{private_pem, public_pem}` where both are PEM-encoded strings.
  """
  @spec generate_rsa_keypair(pos_integer()) :: {binary(), binary()}
  def generate_rsa_keypair(bits \\ 2048) do
    # Generate using crypto module - works in OTP 27
    {public_key, private_key_list} = :crypto.generate_key(:rsa, {bits, 65537})
    
    # Extract components
    [_e_pub, _n_pub] = public_key
    [e, n, d, p, q, dp, dq, qinv] = private_key_list
    
    # Convert to integers
    n_int = :crypto.bytes_to_integer(n)
    e_int = :crypto.bytes_to_integer(e)
    d_int = :crypto.bytes_to_integer(d)
    p_int = :crypto.bytes_to_integer(p)
    q_int = :crypto.bytes_to_integer(q)
    dp_int = :crypto.bytes_to_integer(dp)
    dq_int = :crypto.bytes_to_integer(dq)
    qinv_int = :crypto.bytes_to_integer(qinv)
    
    # Create properly structured RSA records for OTP 27
    rsa_private_key = {:RSAPrivateKey,
                       0,        # version as integer (not atom)
                       n_int,    # modulus
                       e_int,    # publicExponent  
                       d_int,    # privateExponent
                       p_int,    # prime1
                       q_int,    # prime2
                       dp_int,   # exponent1
                       dq_int,   # exponent2
                       qinv_int, # coefficient
                       :asn1_NOVALUE} # otherPrimeInfos (required)
    
    rsa_public_key = {:RSAPublicKey, n_int, e_int}
    
    # Encode to PEM
    private_pem_entry = :public_key.pem_entry_encode(:RSAPrivateKey, rsa_private_key)
    private_pem = :public_key.pem_encode([private_pem_entry])
    
    public_pem_entry = :public_key.pem_entry_encode(:RSAPublicKey, rsa_public_key)
    public_pem = :public_key.pem_encode([public_pem_entry])
    
    {private_pem, public_pem}
  end

  @doc """
  Validates that RSA keypair works correctly.

  ## Examples

      {private_pem, public_pem} = Goth.AlloyDB.generate_rsa_keypair()
      true = Goth.AlloyDB.validate_rsa_keypair(private_pem, public_pem)
  """
  @spec validate_rsa_keypair(binary(), binary()) :: boolean()
  def validate_rsa_keypair(private_pem, public_pem) do
    try do
      # Decode keys
      [private_entry] = :public_key.pem_decode(private_pem)
      private_key = :public_key.pem_entry_decode(private_entry)
      
      [public_entry] = :public_key.pem_decode(public_pem)
      public_key = :public_key.pem_entry_decode(public_entry)
      
      # Test sign/verify
      test_data = "Goth.AlloyDB keypair validation"
      signature = :public_key.sign(test_data, :sha256, private_key)
      :public_key.verify(test_data, :sha256, signature, public_key)
    rescue
      _ -> false
    end
  end

  @doc """
  Requests client certificate from AlloyDB Admin API.

  ## Options

    * `:project_id` - GCP project ID (required)
    * `:location` - AlloyDB location (required) 
    * `:cluster` - AlloyDB cluster name (required)
    * `:http_client` - HTTP client module (default: HTTPoison)

  ## Examples

      {:ok, cert_chain, ca_cert} = Goth.AlloyDB.get_client_certificate(
        token, 
        public_pem,
        project_id: "my-project",
        location: "us-central1", 
        cluster: "my-cluster"
      )
  """
  @spec get_client_certificate(String.t(), binary(), keyword()) :: 
    {:ok, [binary()], binary()} | {:error, term()}
  def get_client_certificate(token, public_pem, opts) do
    project_id = Keyword.fetch!(opts, :project_id)
    location = Keyword.fetch!(opts, :location)
    cluster = Keyword.fetch!(opts, :cluster)
    http_client = Keyword.get(opts, :http_client, HTTPoison)
    
    url = "https://alloydb.googleapis.com/v1beta/projects/#{project_id}/locations/#{location}/clusters/#{cluster}:generateClientCertificate"
    
    headers = [
      {"Authorization", "Bearer #{token}"},
      {"Content-Type", "application/json"}
    ]
    
    body = Jason.encode!(%{"publicKey" => String.trim(public_pem)})
    
    case http_client.post(url, body, headers) do
      {:ok, %{status_code: 200, body: response_body}} ->
        response = Jason.decode!(response_body)
        cert_chain = Enum.map(response["pemCertificateChain"], &String.trim/1)
        ca_cert = String.trim(response["caCert"])
        {:ok, cert_chain, ca_cert}
        
      {:ok, %{status_code: status, body: body}} ->
        {:error, "Certificate request failed: #{status} - #{body}"}
        
      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Generates complete SSL configuration for AlloyDB connection.

  Creates temporary certificate files and returns SSL options suitable 
  for Postgrex.

  ## Examples

      {:ok, ssl_opts} = Goth.AlloyDB.generate_ssl_config(
        token,
        hostname: "10.0.0.1",
        project_id: "my-project",
        location: "us-central1",
        cluster: "my-cluster"
      )
  """
  @spec generate_ssl_config(String.t(), keyword()) :: {:ok, keyword()} | {:error, term()}
  def generate_ssl_config(token, opts) do
    hostname = Keyword.fetch!(opts, :hostname)
    
    with {private_pem, public_pem} <- generate_rsa_keypair(),
         true <- validate_rsa_keypair(private_pem, public_pem),
         {:ok, cert_chain, ca_cert} <- get_client_certificate(token, public_pem, opts) do
      
      # Write certificates to temporary files
      cert_file = write_temp_file("alloydb_client_cert", hd(cert_chain))
      key_file = write_temp_file("alloydb_client_key", private_pem) 
      ca_file = write_temp_file("alloydb_ca_cert", ca_cert)
      
      ssl_config = [
        certfile: cert_file,
        keyfile: key_file,
        cacertfile: ca_file,
        verify: :verify_peer,
        versions: [:"tlsv1.3"],
        server_name: String.to_charlist(hostname),
        verify_fun: {&verify_fun/3, nil}
      ]
      
      {:ok, ssl_config}
    end
  end

  @doc """
  Generates complete Postgrex configuration for AlloyDB.

  ## Options

    * `:goth_name` - Name of Goth server (required)
    * `:hostname` - AlloyDB hostname/IP (required) 
    * `:database` - Database name (required)
    * `:username` - IAM username (required)
    * `:project_id` - GCP project ID (required)
    * `:location` - AlloyDB location (required)
    * `:cluster` - AlloyDB cluster name (required)
    * `:port` - Port (default: 5432)
    * `:timeout` - Connection timeout (default: 15000)

  ## Examples

      config = Goth.AlloyDB.postgrex_config(
        goth_name: MyApp.Goth,
        hostname: "10.0.0.1",
        database: "postgres", 
        username: "user@example.com",
        project_id: "my-project",
        location: "us-central1",
        cluster: "my-cluster"
      )
      {:ok, conn} = Postgrex.start_link(config)
  """
  @spec postgrex_config(keyword()) :: keyword()
  def postgrex_config(opts) do
    goth_name = Keyword.fetch!(opts, :goth_name)
    hostname = Keyword.fetch!(opts, :hostname)
    database = Keyword.fetch!(opts, :database)
    username = Keyword.fetch!(opts, :username)
    port = Keyword.get(opts, :port, 5432)
    timeout = Keyword.get(opts, :timeout, 15000)
    
    token = get_token!(goth_name)
    {:ok, ssl_config} = generate_ssl_config(token, opts)
    
    [
      hostname: hostname,
      port: port,
      database: database,
      username: username,
      password: token,
      ssl: ssl_config,
      timeout: timeout,
      parameters: [application_name: "goth-alloydb"]
    ]
  end

  @doc """
  Config resolver function for dynamic AlloyDB authentication.

  This function can be used with Postgrex's `:config_resolver` option
  to provide fresh tokens and certificates on each connection.

  ## Usage

      # In your Postgrex configuration
      config = [
        hostname: "10.0.0.1",
        database: "postgres",
        config_resolver: &Goth.AlloyDB.config_resolver/1
      ]

      # The resolver will be called with the base options and should
      # return updated options with authentication details
  """
  @spec config_resolver(keyword()) :: keyword()
  def config_resolver(opts) do
    # Extract required options from application config or opts
    goth_name = get_required_opt(opts, :goth_name, "GOTH_SERVER_NAME")
    project_id = get_required_opt(opts, :project_id, "ALLOYDB_PROJECT_ID")
    location = get_required_opt(opts, :location, "ALLOYDB_LOCATION")
    cluster = get_required_opt(opts, :cluster, "ALLOYDB_CLUSTER")
    username = get_required_opt(opts, :username, "ALLOYDB_IAM_USER")
    
    # Generate fresh credentials
    token = get_token!(goth_name)
    
    ssl_opts = [
      project_id: project_id,
      location: location,
      cluster: cluster,
      hostname: opts[:hostname]
    ]
    
    case generate_ssl_config(token, ssl_opts) do
      {:ok, ssl_config} ->
        opts
        |> Keyword.put(:username, username)
        |> Keyword.put(:password, token)
        |> Keyword.put(:ssl, ssl_config)
        |> Keyword.put_new(:parameters, [application_name: "goth-alloydb-resolver"])
        
      {:error, reason} ->
        Logger.error("AlloyDB config resolver failed: #{inspect(reason)}")
        # Return original opts to let connection fail gracefully
        opts
    end
  end

  @doc """
  Starts Goth server with AlloyDB-appropriate configuration.

  ## Examples

      {:ok, pid} = Goth.AlloyDB.start_link(name: MyApp.Goth)

      # With explicit source
      {:ok, pid} = Goth.AlloyDB.start_link(
        name: MyApp.Goth, 
        source: {:service_account, credentials}
      )
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    opts = Keyword.put_new(opts, :scope, @default_scopes)
    Goth.start_link(opts)
  end

  # Private functions

  defp write_temp_file(prefix, content) do
    timestamp = :os.system_time(:microsecond)
    filename = "/tmp/#{prefix}_#{timestamp}.pem"
    File.write!(filename, content)
    filename
  end

  defp verify_fun(_, {:bad_cert, :unknown_ca}, _), do: {:valid, nil}
  defp verify_fun(_, {:bad_cert, _reason}, _), do: {:valid, nil}
  defp verify_fun(_, {:extension, _}, _), do: {:unknown, nil}
  defp verify_fun(_, :valid, _), do: {:valid, nil}
  defp verify_fun(_, :valid_peer, _), do: {:valid, nil}

  defp get_required_opt(opts, key, env_var) do
    case Keyword.get(opts, key) do
      nil -> 
        case System.get_env(env_var) do
          nil -> raise "Missing required option :#{key} or env var #{env_var}"
          value -> value
        end
      value -> 
        value
    end
  end
end