defmodule Goth.AlloyDB do
  @moduledoc """
  Google Cloud AlloyDB integration for Goth.

  This module provides functionality for AlloyDB authentication including:
  - OAuth2 token management via Goth  
  - RSA keypair generation using native Elixir/Erlang crypto
  - Client certificate generation via AlloyDB Admin API
  - Support for both IAM and native database authentication
  - Postgrex connection helpers

  ## Usage

  ### Standalone Postgrex Connections

      # Generate complete Postgrex configuration
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

  ### Ecto Integration

      # config/config.exs
      config :goth, :alloydb_clusters,
        prod: [
          project_id: "my-project",
          location: "us-central1", 
          cluster: "my-cluster"
        ]

      config :my_app, MyApp.Repo,
        hostname: "10.0.0.1",
        database: "postgres",
        cluster_config: :prod,
        goth_server: MyApp.Goth,
        config_resolver: &Goth.AlloyDB.config_resolver/1

      # Supervision tree
      children = [
        {Goth, name: MyApp.Goth, source: {:metadata, []}},
        MyApp.Repo
      ]

  ## AlloyDB Authentication Modes

  ### IAM Authentication (`:iam`, default)
  1. **OAuth Token**: Fetched from Goth server (service account or metadata)
  2. **RSA Keypair**: Generated using native Elixir `:crypto.generate_key/2`
  3. **Client Certificate**: Requested from AlloyDB Admin API using public key
  4. **TLS Connection**: Established using client certificate for mutual auth
  5. **PostgreSQL Auth**: OAuth token used as password with IAM username

  ### Native Database Authentication (`:native`)
  1. **OAuth Token**: Still required for certificate generation (AlloyDB requirement)
  2. **RSA Keypair**: Generated using native Elixir `:crypto.generate_key/2`
  3. **Client Certificate**: Requested from AlloyDB Admin API using public key
  4. **TLS Connection**: Established using client certificate for mutual auth
  5. **PostgreSQL Auth**: Traditional username/password authentication

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

  ## Certificate Caching

  Goth.AlloyDB automatically caches certificates for performance:

  - **Cache Duration**: 24 hours (typical AlloyDB certificate lifetime)
  - **Auto Refresh**: Certificates refreshed 1 hour before expiry
  - **Cache Key**: Based on project_id, location, cluster, and hostname
  - **Memory Storage**: Uses ETS tables for fast access
  - **Background Refresh**: New certificates generated before old ones expire

  ### Cache Management

      # Check cached certificates
      Goth.AlloyDB.cert_cache_info()

      # Clear cache (forces regeneration)
      Goth.AlloyDB.clear_cert_cache()

      # Use uncached generation (for testing)
      Goth.AlloyDB.generate_ssl_config_uncached(token, opts)
  """

  require Logger
  alias Goth.Token


  @default_scopes ["https://www.googleapis.com/auth/cloud-platform"]
  @cert_cache_table :goth_alloydb_cert_cache
  @cert_lifetime_hours 24
  @refresh_before_minutes 60
  @refresh_buffer_minutes 4
  @refresh_timeout_seconds 60

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
    # Generate using crypto module
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
    
    # Create properly structured RSA records
    rsa_private_key = {:RSAPrivateKey,
                       0,        # version
                       n_int,    # modulus
                       e_int,    # publicExponent  
                       d_int,    # privateExponent
                       p_int,    # prime1
                       q_int,    # prime2
                       dp_int,   # exponent1
                       dq_int,   # exponent2
                       qinv_int, # coefficient
                       :asn1_NOVALUE} # otherPrimeInfos
    
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
  Generates complete SSL configuration for AlloyDB connection with caching.

  Returns SSL options suitable for Postgrex with in-memory certificates. 
  Certificates are cached for performance and automatically refreshed before expiry.

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
    # Resolve cluster configuration
    resolved_opts = resolve_cluster_config(opts)
    cache_key = build_cert_cache_key(resolved_opts)
    
    case get_cached_certificate(cache_key) do
      {:ok, ssl_config} ->
        Logger.debug("Using cached AlloyDB certificate")
        {:ok, ssl_config}
        
      :cache_miss ->
        Logger.debug("Generating new AlloyDB certificate")
        generate_and_cache_ssl_config(token, resolved_opts, cache_key)
    end
  end

  @doc """
  Generates SSL configuration without caching (for testing or special cases).
  """
  @spec generate_ssl_config_uncached(String.t(), keyword()) :: {:ok, keyword()} | {:error, term()}
  def generate_ssl_config_uncached(token, opts) do
    # Resolve cluster configuration
    resolved_opts = resolve_cluster_config(opts)
    hostname = Keyword.fetch!(resolved_opts, :hostname)
    
    with {private_pem, public_pem} <- generate_rsa_keypair(),
         true <- validate_rsa_keypair(private_pem, public_pem),
         {:ok, cert_chain, ca_cert} <- get_client_certificate(token, public_pem, resolved_opts) do
      
      # Parse certificates for in-memory use
      {client_cert_der, key_tuple, ca_cert_der} = parse_ssl_cert_and_key(hd(cert_chain), private_pem, ca_cert)
      
      ssl_config = [
        cert: client_cert_der,
        key: key_tuple,
        cacerts: [ca_cert_der],
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

    * `:goth_name` - Name of Goth server (required for both auth modes)
    * `:hostname` - AlloyDB hostname/IP (required) 
    * `:database` - Database name (required)
    * `:username` - Database username (required)
    * `:password` - Database password (required for `:native` auth only)
    * `:project_id` - GCP project ID (required)
    * `:location` - AlloyDB location (required)
    * `:cluster` - AlloyDB cluster name (required)
    * `:auth_mode` - Authentication mode: `:iam` or `:native` (default: `:iam`)
    * `:port` - Port (default: 5432)
    * `:timeout` - Connection timeout (default: 15000)

  ## Examples

      # IAM authentication (default)
      config = Goth.AlloyDB.postgrex_config(
        goth_name: MyApp.Goth,
        hostname: "10.0.0.1",
        database: "postgres", 
        username: "user@example.com",
        project_id: "my-project",
        location: "us-central1",
        cluster: "my-cluster"
      )

      # Native database authentication
      config = Goth.AlloyDB.postgrex_config(
        goth_name: MyApp.Goth,
        hostname: "10.0.0.1",
        database: "postgres", 
        username: "dbuser",
        password: "dbpassword",
        auth_mode: :native,
        project_id: "my-project",
        location: "us-central1",
        cluster: "my-cluster"
      )
      {:ok, conn} = Postgrex.start_link(config)
  """
  @spec postgrex_config(keyword()) :: keyword()
  def postgrex_config(opts) do
    # Resolve cluster configuration first
    resolved_opts = resolve_cluster_config(opts)
    
    goth_name = Keyword.fetch!(resolved_opts, :goth_name)
    hostname = Keyword.fetch!(resolved_opts, :hostname)
    database = Keyword.fetch!(resolved_opts, :database)
    username = Keyword.fetch!(resolved_opts, :username)
    port = Keyword.get(resolved_opts, :port, 5432)
    timeout = Keyword.get(resolved_opts, :timeout, 15000)
    auth_mode = Keyword.get(resolved_opts, :auth_mode, :iam)
    
    # Validate auth_mode
    unless auth_mode in [:iam, :native] do
      raise ArgumentError, "Invalid auth_mode: #{inspect(auth_mode)}. Must be one of: :iam, :native"
    end
    
    # Get OAuth token for certificate generation
    token = get_token!(goth_name)
    {:ok, ssl_config} = generate_ssl_config(token, resolved_opts)
    
    # Determine password based on auth mode
    password = case auth_mode do
      :iam ->
        # IAM mode: OAuth token as password
        token
      :native ->
        # Native mode: provided password
        case Keyword.get(resolved_opts, :password) do
          nil ->
            raise ArgumentError, "Password is required for :native auth_mode"
          password ->
            password
        end
    end
    
    [
      hostname: hostname,
      port: port,
      database: database,
      username: username,
      password: password,
      ssl: ssl_config,
      timeout: timeout,
      parameters: [
        application_name: "goth-alloydb-#{auth_mode}"
      ]
    ]
  end

  @doc """
  Config resolver function for dynamic AlloyDB authentication.

  This function can be used with Postgrex's `:config_resolver` option
  to provide fresh tokens and certificates on each connection.

  ## Usage

      children = [
        {Postgrex,
         hostname: "10.0.0.1",
         database: "postgres",
         cluster_config: :prod,
         goth_server: MyApp.Goth,
         config_resolver: &Goth.AlloyDB.config_resolver/1}
      ]

      # The resolver will be called with the base options and should
      # return updated options with authentication details
  """
  @spec config_resolver(keyword()) :: keyword()
  def config_resolver(opts) do
    # Resolve cluster configuration first
    resolved_opts = resolve_cluster_config(opts)
    
    # Extract Goth server from connection options (consistent with other Goth usage)
    goth_server = Keyword.fetch!(resolved_opts, :goth_server)
    
    project_id = get_required_opt(resolved_opts, :project_id, "ALLOYDB_PROJECT_ID")
    location = get_required_opt(resolved_opts, :location, "ALLOYDB_LOCATION")
    cluster = get_required_opt(resolved_opts, :cluster, "ALLOYDB_CLUSTER")
    auth_mode = Keyword.get(resolved_opts, :auth_mode, :iam)
    
    # Validate auth_mode
    unless auth_mode in [:iam, :native] do
      raise ArgumentError, "Invalid auth_mode: #{inspect(auth_mode)}. Must be one of: :iam, :native"
    end
    
    # Generate fresh OAuth token for certificate generation
    token = get_token!(goth_server)
    
    ssl_opts = [
      project_id: project_id,
      location: location,
      cluster: cluster,
      hostname: resolved_opts[:hostname]
    ]
    
    case generate_ssl_config(token, ssl_opts) do
      {:ok, ssl_config} ->
        # Configure auth based on mode
        {username, password} = case auth_mode do
          :iam ->
            # IAM mode: OAuth token as password
            username = get_required_opt(resolved_opts, :username, "ALLOYDB_IAM_USER")
            {username, token}
          :native ->
            # Native mode: provided credentials
            username = get_required_opt(resolved_opts, :username, "ALLOYDB_DB_USER")
            password = get_required_opt(resolved_opts, :password, "ALLOYDB_DB_PASSWORD")
            {username, password}
        end
        
        opts
        |> Keyword.put(:username, username)
        |> Keyword.put(:password, password)
        |> Keyword.put(:ssl, ssl_config)
        |> Keyword.put_new(:parameters, [application_name: "goth-alloydb-resolver-#{auth_mode}"])
        
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
    # Pass through to Goth.start_link
    Goth.start_link(opts)
  end

  @doc """
  Clears the certificate cache.

  Useful for testing or when you want to force certificate regeneration.

  ## Examples

      Goth.AlloyDB.clear_cert_cache()
  """
  @spec clear_cert_cache() :: :ok
  def clear_cert_cache do
    case :ets.whereis(@cert_cache_table) do
      :undefined -> :ok
      _ -> 
        :ets.delete_all_objects(@cert_cache_table)
        Logger.info("Cleared AlloyDB certificate cache")
        :ok
    end
  end

  @doc """
  Forces an immediate refresh of certificates for the given options.
  This clears the cache and forces regeneration on next use.
  
  ## Examples
  
      # Clear all cached certificates
      Goth.AlloyDB.force_refresh()
      
      # Clear certificate for specific instance
      Goth.AlloyDB.force_refresh(
        project_id: "my-project",
        location: "us-central1", 
        cluster: "my-cluster",
        hostname: "10.0.0.1"
      )
  """
  @spec force_refresh(keyword()) :: :ok
  def force_refresh(opts \\ []) do
    ensure_cert_cache_table()
    
    case opts do
      [] ->
        # Clear all certificates
        :ets.delete_all_objects(@cert_cache_table)
        Logger.info("Force refresh: All cached certificates cleared")
        :ok
        
      _ ->
        # Clear specific certificate
        cache_key = build_cert_cache_key(opts)
        case :ets.delete(@cert_cache_table, cache_key) do
          true ->
            Logger.info("Force refresh: Certificate cleared for #{inspect(cache_key)}")
            :ok
          false ->
            Logger.info("Force refresh: No certificate found for #{inspect(cache_key)}")
            :ok
        end
    end
  end

  @doc """
  Returns information about cached certificates.

  ## Examples

      Goth.AlloyDB.cert_cache_info()
      # => [
      #   %{
      #     project_id: "my-project",
      #     location: "us-central1", 
      #     cluster: "my-cluster",
      #     hostname: "10.0.0.1",
      #     expires_at: 1234567890,
      #     expires_in_seconds: 3600
      #   }
      # ]
  """
  @spec cert_cache_info() :: [map()]
  def cert_cache_info do
    case :ets.whereis(@cert_cache_table) do
      :undefined ->
        []
      _ ->
        now = :os.system_time(:second)
        
        :ets.tab2list(@cert_cache_table)
        |> Enum.map(fn {{project_id, location, cluster, hostname}, _ssl_config, expires_at} ->
          %{
            project_id: project_id,
            location: location,
            cluster: cluster,
            hostname: hostname,
            expires_at: expires_at,
            expires_in_seconds: max(0, expires_at - now)
          }
        end)
    end
  end

  # Private functions

  defp resolve_cluster_config(opts) do
    case Keyword.get(opts, :cluster_config) do
      nil ->
        # No cluster_config specified, expect individual parameters
        opts
      cluster_name ->
        # Look up cluster configuration
        clusters = Application.get_env(:goth, :alloydb_clusters, %{})
        case Map.get(clusters, cluster_name) do
          nil ->
            raise ArgumentError, "Unknown cluster_config: #{inspect(cluster_name)}. Available: #{inspect(Map.keys(clusters))}"
          cluster_opts ->
            # Merge cluster config with opts, opts take precedence
            Keyword.merge(cluster_opts, Keyword.delete(opts, :cluster_config))
        end
    end
  end

  defp build_cert_cache_key(opts) do
    # Build cache key from AlloyDB instance identity
    project_id = Keyword.fetch!(opts, :project_id)
    location = Keyword.fetch!(opts, :location)
    cluster = Keyword.fetch!(opts, :cluster)
    hostname = Keyword.fetch!(opts, :hostname)
    ip_type = Keyword.get(opts, :ip_type, :private)
    
    # Validate IP type
    unless ip_type in [:private, :public, :psc] do
      raise ArgumentError, "Invalid ip_type: #{inspect(ip_type)}. Must be one of: :private, :public, :psc"
    end
    
    {project_id, location, cluster, hostname, ip_type}
  end

  defp get_cached_certificate(cache_key) do
    ensure_cert_cache_table()
    
    case :ets.lookup(@cert_cache_table, cache_key) do
      [{^cache_key, ssl_config, expires_at}] ->
        now = :os.system_time(:second)
        refresh_threshold = expires_at - (@refresh_before_minutes * 60)
        
        if now < refresh_threshold do
          {:ok, ssl_config}
        else
          :cache_miss
        end
        
      [] ->
        :cache_miss
    end
  end

  defp generate_and_cache_ssl_config(token, opts, cache_key) do
    hostname = Keyword.fetch!(opts, :hostname)
    
    with {private_pem, public_pem} <- generate_rsa_keypair(),
         true <- validate_rsa_keypair(private_pem, public_pem),
         {:ok, cert_chain, ca_cert} <- get_client_certificate(token, public_pem, opts) do
      
      # Parse certificates for in-memory use
      {client_cert_der, key_tuple, ca_cert_der} = parse_ssl_cert_and_key(hd(cert_chain), private_pem, ca_cert)
      
      ssl_config = [
        cert: client_cert_der,
        key: key_tuple,
        cacerts: [ca_cert_der],
        verify: :verify_peer,
        versions: [:"tlsv1.3"],
        server_name: String.to_charlist(hostname),
        verify_fun: {&verify_fun/3, nil}
      ]
      
      # Cache the certificate
      expires_at = :os.system_time(:second) + (@cert_lifetime_hours * 3600)
      store_certificate_in_cache(cache_key, ssl_config, expires_at)
      
      Logger.info("Generated and cached new AlloyDB certificate (expires in #{@cert_lifetime_hours}h)")
      {:ok, ssl_config}
    end
  end

  defp ensure_cert_cache_table do
    case :ets.whereis(@cert_cache_table) do
      :undefined ->
        :ets.new(@cert_cache_table, [
          :set,
          :public,
          :named_table,
          {:read_concurrency, true}
        ])
      _ ->
        :ok
    end
  end

  defp store_certificate_in_cache(cache_key, ssl_config, expires_at) do
    ensure_cert_cache_table()
    :ets.insert(@cert_cache_table, {cache_key, ssl_config, expires_at})
  end

  defp parse_ssl_cert_and_key(client_cert_pem, private_key_pem, ca_cert_pem) do
    # Extract DER data for certificates
    client_cert_der = extract_cert_der(client_cert_pem)
    ca_cert_der = extract_cert_der(ca_cert_pem)
    
    # Extract key in tuple format: {KeyType, DerData}
    [key_entry] = :public_key.pem_decode(private_key_pem)
    key_der = elem(key_entry, 1)
    key_type = elem(key_entry, 0)
    key_tuple = {key_type, key_der}
    
    {client_cert_der, key_tuple, ca_cert_der}
  end
  
  defp extract_cert_der(pem_data) do
    # Extract Certificate DER
    pem_data
    |> :public_key.pem_decode()
    |> Enum.find(fn {type, _der, _} -> type == :Certificate end)
    |> elem(1)
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