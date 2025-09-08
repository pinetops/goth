defmodule AlloyDBExample do
  @moduledoc """
  Complete example of using Goth with AlloyDB IAM authentication.

  This example demonstrates various ways to connect to Google Cloud AlloyDB
  using IAM authentication with Goth and the modified Postgrex.
  """

  @doc """
  Example 1: Basic connection using Application Default Credentials.
  
  This is the simplest approach when running on Google Cloud or with
  gcloud configured locally.
  """
  def connect_with_adc do
    # Start Goth with ADC
    {:ok, _} = Goth.start_link(name: MyApp.Goth)

    # Connect to AlloyDB
    {:ok, conn} = Postgrex.start_link(
      hostname: System.fetch_env!("ALLOYDB_HOST"),  # e.g., "10.x.x.x"
      database: System.fetch_env!("ALLOYDB_DATABASE"),
      username: System.fetch_env!("IAM_DB_USER"),  # e.g., "user@example.com"
      password_provider: {Goth.AlloyDB, :get_token, [MyApp.Goth]},
      ssl: true,
      ssl_profile: :cloud
    )

    # Test the connection
    {:ok, result} = Postgrex.query(conn, "SELECT current_user, now()", [])
    IO.inspect(result, label: "Connected as")

    conn
  end

  @doc """
  Example 2: Using a service account JSON file.
  
  This is typical for production deployments with explicit credentials.
  """
  def connect_with_service_account do
    # Load service account credentials
    credentials = 
      System.fetch_env!("GOOGLE_APPLICATION_CREDENTIALS")
      |> File.read!()
      |> Jason.decode!()

    # Start Goth with service account
    {:ok, _} = Goth.start_link(
      name: MyApp.Goth,
      source: {:service_account, credentials, scopes: [
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/sqlservice.login"
      ]}
    )

    # Connect to AlloyDB
    {:ok, conn} = Postgrex.start_link(
      hostname: System.fetch_env!("ALLOYDB_HOST"),
      database: System.fetch_env!("ALLOYDB_DATABASE"),
      username: System.fetch_env!("IAM_DB_USER"),
      password_provider: {Goth.AlloyDB, :get_token, [MyApp.Goth]},
      ssl: true,
      ssl_profile: :cloud,
      pool_size: 10
    )

    conn
  end

  @doc """
  Example 3: Using the convenience functions from Goth.AlloyDB.
  """
  def connect_with_convenience_functions do
    # Start Goth with AlloyDB-specific configuration
    {:ok, _} = Goth.AlloyDB.start_link(name: MyApp.Goth)

    # Generate Postgrex configuration
    config = Goth.AlloyDB.postgrex_config(
      goth_name: MyApp.Goth,
      hostname: System.fetch_env!("ALLOYDB_HOST"),
      database: System.fetch_env!("ALLOYDB_DATABASE"),
      username: System.fetch_env!("IAM_DB_USER"),
      pool_size: 20
    )

    # Connect
    {:ok, conn} = Postgrex.start_link(config)
    conn
  end

  @doc """
  Example 4: Ecto Repo configuration for Phoenix applications.
  
  Add this to your config/runtime.exs:
  """
  def ecto_config_example do
    """
    # config/runtime.exs
    import Config

    # Start Goth in your application supervisor
    # In lib/my_app/application.ex:
    def start(_type, _args) do
      children = [
        # Start Goth for AlloyDB authentication
        {Goth.AlloyDB, name: MyApp.Goth},
        
        # Start the Ecto repository
        MyApp.Repo,
        
        # Start the endpoint
        MyAppWeb.Endpoint
      ]
      
      Supervisor.start_link(children, strategy: :one_for_one)
    end

    # Configure the repository
    config :my_app, MyApp.Repo,
      adapter: Ecto.Adapters.Postgres,
      hostname: System.fetch_env!("ALLOYDB_HOST"),
      database: System.fetch_env!("ALLOYDB_DATABASE"),
      username: System.fetch_env!("IAM_DB_USER"),
      password_provider: {Goth.AlloyDB, :get_token, [MyApp.Goth]},
      ssl: true,
      ssl_profile: :cloud,
      pool_size: 10,
      queue_target: 50,
      queue_interval: 100
    """
  end

  @doc """
  Example 5: Using with Private IP and Cloud SQL Proxy alternative.
  
  When connecting directly to AlloyDB's private IP from within GCP.
  """
  def connect_private_ip do
    # For connections within the same VPC
    {:ok, _} = Goth.start_link(
      name: MyApp.Goth,
      source: :metadata  # Use metadata server when running on GCE/GKE
    )

    {:ok, conn} = Postgrex.start_link(
      hostname: "10.0.0.5",  # Private IP
      port: 5432,
      database: "production",
      username: System.fetch_env!("IAM_DB_USER"),
      password_provider: {Goth.AlloyDB, :get_token, [MyApp.Goth]},
      ssl: true,
      ssl_profile: :cloud,
      pool_size: 50,  # Higher pool for production
      timeout: 15_000,
      connect_timeout: 10_000
    )

    conn
  end

  @doc """
  Example 6: Using anonymous function as password provider.
  
  Sometimes you need more flexibility in how tokens are fetched.
  """
  def connect_with_function_provider do
    {:ok, _} = Goth.start_link(name: MyApp.Goth)

    # Create a custom provider function
    token_provider = fn ->
      # You can add custom logic here
      Logger.info("Fetching new AlloyDB token...")
      
      case Goth.fetch(MyApp.Goth) do
        {:ok, %{token: token}} ->
          Logger.info("Token fetched successfully")
          token
          
        {:error, reason} ->
          Logger.error("Failed to fetch token: #{inspect(reason)}")
          raise "Token fetch failed"
      end
    end

    {:ok, conn} = Postgrex.start_link(
      hostname: System.fetch_env!("ALLOYDB_HOST"),
      database: System.fetch_env!("ALLOYDB_DATABASE"),
      username: System.fetch_env!("IAM_DB_USER"),
      password_provider: token_provider,
      ssl: true,
      ssl_profile: :cloud
    )

    conn
  end

  @doc """
  Example 7: Health check and token validation.
  """
  def health_check do
    # Check if token is valid
    if Goth.AlloyDB.token_valid?(MyApp.Goth) do
      IO.puts("✓ Token is valid")
    else
      IO.puts("✗ Token is invalid or expired")
    end

    # Try to connect and run a query
    try do
      config = Goth.AlloyDB.postgrex_config(
        goth_name: MyApp.Goth,
        hostname: System.fetch_env!("ALLOYDB_HOST"),
        database: System.fetch_env!("ALLOYDB_DATABASE"),
        username: System.fetch_env!("IAM_DB_USER")
      )

      {:ok, conn} = Postgrex.start_link(config)
      {:ok, %{rows: [[version]]}} = Postgrex.query(conn, "SELECT version()", [])
      
      IO.puts("✓ Successfully connected to AlloyDB")
      IO.puts("  Database version: #{version}")
      
      GenServer.stop(conn)
      :ok
    rescue
      e ->
        IO.puts("✗ Failed to connect: #{inspect(e)}")
        :error
    end
  end

  @doc """
  Example 8: Setting up IAM database users in AlloyDB.
  
  Run these SQL commands as a superuser to create IAM database users:
  """
  def setup_iam_users_sql do
    """
    -- Create an IAM user for a service account
    CREATE USER "my-service@my-project.iam.gserviceaccount.com" 
    WITH LOGIN 
    IN GROUP cloudsqliamusers;

    -- Create an IAM user for a regular Google account
    CREATE USER "developer@example.com" 
    WITH LOGIN 
    IN GROUP cloudsqliamusers;

    -- Grant necessary permissions
    GRANT CONNECT ON DATABASE mydb TO "developer@example.com";
    GRANT USAGE ON SCHEMA public TO "developer@example.com";
    GRANT CREATE ON SCHEMA public TO "developer@example.com";
    
    -- Grant table permissions
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public 
    TO "developer@example.com";
    
    -- Grant permissions on future tables
    ALTER DEFAULT PRIVILEGES IN SCHEMA public 
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES 
    TO "developer@example.com";
    """
  end

  @doc """
  Example 9: Troubleshooting connection issues.
  """
  def troubleshoot do
    IO.puts("Troubleshooting AlloyDB IAM connection...")
    
    # 1. Check environment variables
    IO.puts("\n1. Checking environment variables:")
    check_env_var("ALLOYDB_HOST")
    check_env_var("ALLOYDB_DATABASE") 
    check_env_var("IAM_DB_USER")
    check_env_var("GOOGLE_APPLICATION_CREDENTIALS")
    
    # 2. Check Goth token
    IO.puts("\n2. Checking Goth token:")
    case Goth.fetch(MyApp.Goth) do
      {:ok, %{token: token, expires: expires}} ->
        IO.puts("  ✓ Token fetched successfully")
        IO.puts("  Token length: #{String.length(token)} characters")
        IO.puts("  Expires at: #{DateTime.from_unix!(expires)}")
        
      {:error, reason} ->
        IO.puts("  ✗ Failed to fetch token: #{inspect(reason)}")
    end
    
    # 3. Test basic connectivity
    IO.puts("\n3. Testing network connectivity:")
    hostname = System.get_env("ALLOYDB_HOST", "not-set")
    case :gen_tcp.connect(String.to_charlist(hostname), 5432, [], 5000) do
      {:ok, socket} ->
        IO.puts("  ✓ Can connect to #{hostname}:5432")
        :gen_tcp.close(socket)
        
      {:error, reason} ->
        IO.puts("  ✗ Cannot connect to #{hostname}:5432 - #{inspect(reason)}")
    end
    
    # 4. Try actual connection
    IO.puts("\n4. Attempting database connection:")
    try do
      config = [
        hostname: System.fetch_env!("ALLOYDB_HOST"),
        database: System.fetch_env!("ALLOYDB_DATABASE"),
        username: System.fetch_env!("IAM_DB_USER"),
        password_provider: {Goth.AlloyDB, :get_token, [MyApp.Goth]},
        ssl: true,
        ssl_profile: :cloud,
        timeout: 10_000,
        connect_timeout: 10_000
      ]
      
      {:ok, conn} = Postgrex.start_link(config)
      IO.puts("  ✓ Successfully connected!")
      GenServer.stop(conn)
      
    rescue
      e ->
        IO.puts("  ✗ Connection failed:")
        IO.puts("    #{Exception.message(e)}")
    end
  end
  
  defp check_env_var(name) do
    case System.get_env(name) do
      nil -> IO.puts("  ✗ #{name} is not set")
      value -> IO.puts("  ✓ #{name} = #{String.slice(value, 0..20)}...")
    end
  end
end

# Module with examples for different deployment scenarios
defmodule AlloyDBDeployment do
  @moduledoc """
  Deployment-specific examples for AlloyDB with IAM.
  """

  @doc """
  Google Kubernetes Engine (GKE) deployment with Workload Identity.
  """
  def gke_workload_identity_example do
    """
    # 1. Enable Workload Identity on your GKE cluster
    gcloud container clusters update CLUSTER_NAME \\
      --workload-pool=PROJECT_ID.svc.id.goog

    # 2. Create a Kubernetes service account
    kubectl create serviceaccount app-ksa

    # 3. Create a Google service account
    gcloud iam service-accounts create app-gsa

    # 4. Bind the accounts
    gcloud iam service-accounts add-iam-policy-binding \\
      app-gsa@PROJECT_ID.iam.gserviceaccount.com \\
      --role roles/iam.workloadIdentityUser \\
      --member "serviceAccount:PROJECT_ID.svc.id.goog[NAMESPACE/app-ksa]"

    # 5. Annotate the Kubernetes service account
    kubectl annotate serviceaccount app-ksa \\
      iam.gke.io/gcp-service-account=app-gsa@PROJECT_ID.iam.gserviceaccount.com

    # 6. Grant Cloud SQL permissions
    gcloud projects add-iam-policy-binding PROJECT_ID \\
      --member="serviceAccount:app-gsa@PROJECT_ID.iam.gserviceaccount.com" \\
      --role="roles/cloudsql.client"

    # 7. Create IAM database user in AlloyDB
    CREATE USER "app-gsa@PROJECT_ID.iam.gserviceaccount.com" 
    WITH LOGIN IN GROUP cloudsqliamusers;

    # 8. In your application, use metadata source
    {:ok, _} = Goth.start_link(
      name: MyApp.Goth,
      source: :metadata
    )
    """
  end

  @doc """
  Cloud Run deployment example.
  """
  def cloud_run_example do
    """
    # Deploy to Cloud Run with AlloyDB connection
    
    # 1. Create a service account
    gcloud iam service-accounts create alloydb-app

    # 2. Grant necessary permissions
    gcloud projects add-iam-policy-binding PROJECT_ID \\
      --member="serviceAccount:alloydb-app@PROJECT_ID.iam.gserviceaccount.com" \\
      --role="roles/cloudsql.client"

    # 3. Deploy the Cloud Run service
    gcloud run deploy my-app \\
      --image gcr.io/PROJECT_ID/my-app \\
      --service-account alloydb-app@PROJECT_ID.iam.gserviceaccount.com \\
      --set-env-vars ALLOYDB_HOST=10.x.x.x \\
      --set-env-vars ALLOYDB_DATABASE=mydb \\
      --set-env-vars IAM_DB_USER=alloydb-app@PROJECT_ID.iam.gserviceaccount.com \\
      --vpc-connector projects/PROJECT_ID/locations/REGION/connectors/CONNECTOR_NAME

    # In your app, Goth will automatically use the metadata server
    {:ok, _} = Goth.start_link(name: MyApp.Goth, source: :metadata)
    """
  end

  @doc """
  Local development with gcloud CLI.
  """
  def local_development_example do
    """
    # For local development with AlloyDB

    # 1. Authenticate with gcloud
    gcloud auth application-default login

    # 2. Set up SSH tunnel to bastion host (if needed)
    gcloud compute ssh bastion-host \\
      --tunnel-through-iap \\
      --zone=us-central1-a \\
      -- -L 5432:ALLOYDB_PRIVATE_IP:5432

    # 3. Set environment variables
    export ALLOYDB_HOST=localhost
    export ALLOYDB_DATABASE=mydb
    export IAM_DB_USER=developer@example.com

    # 4. Run your application
    mix phx.server

    # Goth will use Application Default Credentials
    {:ok, _} = Goth.start_link(name: MyApp.Goth)
    """
  end
end