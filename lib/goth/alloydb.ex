defmodule Goth.AlloyDB do
  @moduledoc """
  Google Cloud AlloyDB IAM authentication support for Postgrex using Goth.

  This module provides password provider functions that can be used with
  the modified Postgrex `:password_provider` option to authenticate to
  AlloyDB using IAM tokens instead of passwords.

  ## Usage

  First, start a Goth server with appropriate credentials:

      # Using Application Default Credentials
      {:ok, _} = Goth.start_link(name: MyApp.Goth)

      # Or with explicit service account
      credentials = "service-account.json" |> File.read!() |> Jason.decode!()
      {:ok, _} = Goth.start_link(
        name: MyApp.Goth,
        source: {:service_account, credentials}
      )

  Then use the password provider with Postgrex:

      Postgrex.start_link(
        hostname: "10.x.x.x",  # AlloyDB IP
        database: "mydb",
        username: "user@example.com",  # IAM user
        password_provider: {Goth.AlloyDB, :get_token, [MyApp.Goth]},
        ssl: true,
        ssl_profile: :cloud
      )

  Or with Ecto:

      config :my_app, MyApp.Repo,
        adapter: Ecto.Adapters.Postgres,
        hostname: System.fetch_env!("ALLOYDB_HOST"),
        database: System.fetch_env!("ALLOYDB_DATABASE"),
        username: System.fetch_env!("IAM_DB_USER"),
        password_provider: {Goth.AlloyDB, :get_token, [MyApp.Goth]},
        ssl: true,
        ssl_profile: :cloud
  """

  require Logger

  @alloydb_scope "https://www.googleapis.com/auth/cloud-platform"
  @alloydb_iam_scope "https://www.googleapis.com/auth/sqlservice.login"

  @doc """
  Gets an access token suitable for AlloyDB IAM authentication.

  This function fetches a token from the specified Goth server and returns
  just the token string, which is what AlloyDB expects as the password.

  ## Parameters

    * `goth_name` - The name of the Goth server to fetch the token from

  ## Returns

  The access token string to use as the password for AlloyDB authentication.

  ## Examples

      # As a password provider in Postgrex
      password_provider: {Goth.AlloyDB, :get_token, [MyApp.Goth]}

      # Called directly
      token = Goth.AlloyDB.get_token(MyApp.Goth)
      "ya29.a0AWY7Ckn..."

  """
  @spec get_token(atom() | {:via, atom(), term()}) :: String.t()
  def get_token(goth_name) do
    case Goth.fetch(goth_name) do
      {:ok, %{token: token}} ->
        token

      {:error, reason} ->
        raise """
        Failed to fetch AlloyDB IAM token from Goth server #{inspect(goth_name)}.
        Reason: #{inspect(reason)}

        Make sure:
        1. The Goth server is started with appropriate credentials
        2. The service account has the required Cloud SQL permissions
        3. The IAM database user exists in AlloyDB
        """
    end
  end

  @doc """
  Gets a token with custom timeout.

  Useful when you need longer timeouts for token fetching in slow networks.

  ## Examples

      password_provider: {Goth.AlloyDB, :get_token_with_timeout, [MyApp.Goth, 10_000]}

  """
  @spec get_token_with_timeout(atom() | {:via, atom(), term()}, timeout()) :: String.t()
  def get_token_with_timeout(goth_name, timeout) do
    case Goth.fetch(goth_name, timeout) do
      {:ok, %{token: token}} ->
        token

      {:error, reason} ->
        raise """
        Failed to fetch AlloyDB IAM token from Goth server #{inspect(goth_name)}.
        Reason: #{inspect(reason)}
        """
    end
  end

  @doc """
  Gets a token using a zero-arity function wrapper.

  This is useful when you want to use an anonymous function as the password provider.

  ## Examples

      # Define a wrapper function
      def get_my_token, do: Goth.AlloyDB.get_token(MyApp.Goth)

      # Use with Postgrex
      password_provider: fn -> MyModule.get_my_token() end

  """
  @spec get_token_fn(atom() | {:via, atom(), term()}) :: (() -> String.t())
  def get_token_fn(goth_name) do
    fn -> get_token(goth_name) end
  end

  @doc """
  Ensures a Goth server is started with AlloyDB-appropriate scopes.

  This is a convenience function that starts a Goth server with the correct
  scopes for AlloyDB IAM authentication.

  ## Options

  Same as `Goth.start_link/1` but automatically adds AlloyDB scopes.

  ## Examples

      # Start with Application Default Credentials
      {:ok, _} = Goth.AlloyDB.start_link(name: MyApp.Goth)

      # Start with service account
      credentials = File.read!("service-account.json") |> Jason.decode!()
      {:ok, _} = Goth.AlloyDB.start_link(
        name: MyApp.Goth,
        source: {:service_account, credentials}
      )

  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    # Ensure we have the right scopes for AlloyDB
    opts = ensure_alloydb_scopes(opts)
    Goth.start_link(opts)
  end

  @doc """
  Creates a child spec for supervision tree.

  ## Examples

      children = [
        {Goth.AlloyDB, name: MyApp.Goth},
        MyApp.Repo
      ]

      Supervisor.start_link(children, strategy: :one_for_one)

  """
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(opts) do
    opts = ensure_alloydb_scopes(opts)
    Goth.child_spec(opts)
  end

  @doc """
  Verifies that the current token is valid for AlloyDB.

  This performs a basic check that the token exists and hasn't expired.
  Note that this doesn't guarantee the token will work with AlloyDB,
  only that it's structurally valid.

  ## Examples

      iex> Goth.AlloyDB.token_valid?(MyApp.Goth)
      true

  """
  @spec token_valid?(atom() | {:via, atom(), term()}) :: boolean()
  def token_valid?(goth_name) do
    case Goth.fetch(goth_name) do
      {:ok, %{token: token, expires: expires}} when is_binary(token) ->
        # Check if token exists and hasn't expired
        expires > System.system_time(:second)

      _ ->
        false
    end
  end

  @doc """
  Creates a Postgrex configuration with AlloyDB IAM authentication.

  This is a convenience function that generates a proper Postgrex/Ecto
  configuration with all the recommended settings for AlloyDB.

  ## Options

    * `:goth_name` - The name of the Goth server (required)
    * `:hostname` - AlloyDB instance IP or hostname (required)
    * `:database` - Database name (required)
    * `:username` - IAM database user email (required)
    * `:pool_size` - Connection pool size (default: 10)
    * `:ssl` - Enable SSL (default: true)
    * `:ssl_profile` - TLS profile to use (default: :cloud)

  ## Examples

      config = Goth.AlloyDB.postgrex_config(
        goth_name: MyApp.Goth,
        hostname: "10.x.x.x",
        database: "mydb",
        username: "user@example.com"
      )

      {:ok, pid} = Postgrex.start_link(config)

  """
  @spec postgrex_config(keyword()) :: keyword()
  def postgrex_config(opts) do
    goth_name = Keyword.fetch!(opts, :goth_name)
    hostname = Keyword.fetch!(opts, :hostname)
    database = Keyword.fetch!(opts, :database)
    username = Keyword.fetch!(opts, :username)

    [
      hostname: hostname,
      database: database,
      username: username,
      password_provider: {__MODULE__, :get_token, [goth_name]},
      ssl: Keyword.get(opts, :ssl, true),
      ssl_profile: Keyword.get(opts, :ssl_profile, :cloud),
      pool_size: Keyword.get(opts, :pool_size, 10)
    ]
    |> Keyword.merge(Keyword.drop(opts, [:goth_name, :hostname, :database, :username, :ssl, :ssl_profile, :pool_size]))
  end

  # Private functions

  defp ensure_alloydb_scopes(opts) do
    case Keyword.get(opts, :source) do
      {:service_account, credentials, scope_opts} ->
        # Add AlloyDB scopes if not already present
        scope_opts = Keyword.put_new(scope_opts, :scopes, [@alloydb_scope, @alloydb_iam_scope])
        Keyword.put(opts, :source, {:service_account, credentials, scope_opts})

      {:metadata, scope_opts} ->
        # For metadata server, add scopes
        scope_opts = Keyword.put_new(scope_opts, :scopes, [@alloydb_scope, @alloydb_iam_scope])
        Keyword.put(opts, :source, {:metadata, scope_opts})

      nil ->
        # When using default source detection, we can't easily inject scopes
        # Log a warning to inform the user
        Logger.debug("""
        Using default Goth source detection for AlloyDB.
        Make sure your credentials have the required scopes:
        - #{@alloydb_scope}
        - #{@alloydb_iam_scope}
        """)

        opts

      _ ->
        opts
    end
  end
end