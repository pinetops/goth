defmodule Goth.AlloyDBTest do
  use ExUnit.Case
  import ExUnit.CaptureLog

  alias Goth.AlloyDB

  describe "generate_rsa_keypair/1" do
    test "generates valid RSA keypair with default 2048 bits" do
      {private_pem, public_pem} = AlloyDB.generate_rsa_keypair()
      
      assert is_binary(private_pem)
      assert is_binary(public_pem)
      assert String.contains?(private_pem, "-----BEGIN RSA PRIVATE KEY-----")
      assert String.contains?(private_pem, "-----END RSA PRIVATE KEY-----")
      assert String.contains?(public_pem, "-----BEGIN RSA PUBLIC KEY-----")
      assert String.contains?(public_pem, "-----END RSA PUBLIC KEY-----")
    end

    test "generates valid RSA keypair with custom bits" do
      {private_pem, public_pem} = AlloyDB.generate_rsa_keypair(4096)
      
      assert is_binary(private_pem)
      assert is_binary(public_pem)
      # 4096-bit keys should be longer than 2048-bit keys
      assert byte_size(private_pem) > 3000
    end

    test "generated keypairs are different on each call" do
      {private1, public1} = AlloyDB.generate_rsa_keypair()
      {private2, public2} = AlloyDB.generate_rsa_keypair()
      
      assert private1 != private2
      assert public1 != public2
    end
  end

  describe "validate_rsa_keypair/2" do
    test "validates correctly generated keypair" do
      {private_pem, public_pem} = AlloyDB.generate_rsa_keypair()
      
      assert AlloyDB.validate_rsa_keypair(private_pem, public_pem) == true
    end

    test "rejects mismatched keypair" do
      {private1, _public1} = AlloyDB.generate_rsa_keypair()
      {_private2, public2} = AlloyDB.generate_rsa_keypair()
      
      assert AlloyDB.validate_rsa_keypair(private1, public2) == false
    end

    test "handles malformed PEM gracefully" do
      invalid_pem = "-----BEGIN RSA PRIVATE KEY-----\ninvalid\n-----END RSA PRIVATE KEY-----"
      {_private, public} = AlloyDB.generate_rsa_keypair()
      
      assert AlloyDB.validate_rsa_keypair(invalid_pem, public) == false
    end
  end

  describe "get_token/2" do
    test "fetches token from Goth server" do
      # Mock Goth.fetch to return a token
      token_value = "ya29.test_token"
      
      expect_goth_fetch(fn _name, _timeout ->
        {:ok, %Goth.Token{token: token_value}}
      end)
      
      assert {:ok, ^token_value} = AlloyDB.get_token(:test_goth)
    end

    test "handles Goth errors" do
      expect_goth_fetch(fn _name, _timeout ->
        {:error, :some_error}
      end)
      
      assert {:error, :some_error} = AlloyDB.get_token(:test_goth)
    end

    test "passes timeout to Goth.fetch" do
      expect_goth_fetch(fn _name, timeout ->
        assert timeout == 10000
        {:ok, %Goth.Token{token: "test"}}
      end)
      
      AlloyDB.get_token(:test_goth, 10000)
    end
  end

  describe "get_token!/2" do
    test "returns token on success" do
      expect_goth_fetch(fn _name, _timeout ->
        {:ok, %Goth.Token{token: "ya29.test"}}
      end)
      
      assert AlloyDB.get_token!(:test_goth) == "ya29.test"
    end

    test "raises on error" do
      expect_goth_fetch(fn _name, _timeout ->
        {:error, :failed}
      end)
      
      assert_raise RuntimeError, ~r/Failed to fetch AlloyDB token/, fn ->
        AlloyDB.get_token!(:test_goth)
      end
    end
  end

  describe "token_valid?/1" do
    test "returns true for valid unexpired token" do
      future_time = :os.system_time(:second) + 3600
      
      expect_goth_fetch(fn _name ->
        {:ok, %Goth.Token{expires: future_time}}
      end)
      
      assert AlloyDB.token_valid?(:test_goth) == true
    end

    test "returns false for expired token" do
      past_time = :os.system_time(:second) - 3600
      
      expect_goth_fetch(fn _name ->
        {:ok, %Goth.Token{expires: past_time}}
      end)
      
      assert AlloyDB.token_valid?(:test_goth) == false
    end

    test "returns false on fetch error" do
      expect_goth_fetch(fn _name ->
        {:error, :some_error}
      end)
      
      assert AlloyDB.token_valid?(:test_goth) == false
    end
  end

  describe "get_client_certificate/3" do
    setup do
      {private_pem, public_pem} = AlloyDB.generate_rsa_keypair()
      %{private_pem: private_pem, public_pem: public_pem}
    end

    test "successfully requests certificate", %{public_pem: public_pem} do
      token = "ya29.test_token"
      opts = [
        project_id: "test-project",
        location: "us-central1", 
        cluster: "test-cluster",
        http_client: MockHTTPClient
      ]
      
      cert_chain = ["-----BEGIN CERTIFICATE-----\ncert1\n-----END CERTIFICATE-----"]
      ca_cert = "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----"
      
      expect_http_post(fn url, body, headers ->
        assert String.contains?(url, "test-project")
        assert String.contains?(url, "us-central1")
        assert String.contains?(url, "test-cluster")
        assert {"Authorization", "Bearer ya29.test_token"} in headers
        
        body_map = Jason.decode!(body)
        assert String.contains?(body_map["publicKey"], "BEGIN RSA PUBLIC KEY")
        
        response_body = Jason.encode!(%{
          "pemCertificateChain" => cert_chain,
          "caCert" => ca_cert
        })
        
        {:ok, %{status_code: 200, body: response_body}}
      end)
      
      assert {:ok, ^cert_chain, ^ca_cert} = 
        AlloyDB.get_client_certificate(token, public_pem, opts)
    end

    test "handles API errors", %{public_pem: public_pem} do
      token = "ya29.test_token"
      opts = [
        project_id: "test-project",
        location: "us-central1",
        cluster: "test-cluster", 
        http_client: MockHTTPClient
      ]
      
      expect_http_post(fn _url, _body, _headers ->
        {:ok, %{status_code: 403, body: "Forbidden"}}
      end)
      
      assert {:error, error} = AlloyDB.get_client_certificate(token, public_pem, opts)
      assert String.contains?(error, "403")
      assert String.contains?(error, "Forbidden")
    end

    test "handles HTTP client errors", %{public_pem: public_pem} do
      token = "ya29.test_token"
      opts = [
        project_id: "test-project",
        location: "us-central1",
        cluster: "test-cluster",
        http_client: MockHTTPClient
      ]
      
      expect_http_post(fn _url, _body, _headers ->
        {:error, :timeout}
      end)
      
      assert {:error, :timeout} = AlloyDB.get_client_certificate(token, public_pem, opts)
    end
  end

  describe "generate_ssl_config/2" do
    test "generates complete SSL configuration" do
      token = "ya29.test_token"
      opts = [
        hostname: "10.0.0.1",
        project_id: "test-project", 
        location: "us-central1",
        cluster: "test-cluster",
        http_client: MockHTTPClient
      ]
      
      # Mock successful certificate request
      expect_http_post(fn _url, _body, _headers ->
        response_body = Jason.encode!(%{
          "pemCertificateChain" => ["-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----"],
          "caCert" => "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----"
        })
        {:ok, %{status_code: 200, body: response_body}}
      end)
      
      assert {:ok, ssl_config} = AlloyDB.generate_ssl_config(token, opts)
      
      assert Keyword.has_key?(ssl_config, :certfile)
      assert Keyword.has_key?(ssl_config, :keyfile)
      assert Keyword.has_key?(ssl_config, :cacertfile)
      assert ssl_config[:verify] == :verify_peer
      assert ssl_config[:versions] == [:"tlsv1.3"]
      assert ssl_config[:server_name] == ~c"10.0.0.1"
      assert Keyword.has_key?(ssl_config, :verify_fun)
      
      # Verify certificate files exist
      assert File.exists?(ssl_config[:certfile])
      assert File.exists?(ssl_config[:keyfile])
      assert File.exists?(ssl_config[:cacertfile])
    end
  end

  describe "postgrex_config/1" do
    test "generates complete Postgrex configuration" do
      expect_goth_fetch(fn _name, _timeout ->
        {:ok, %Goth.Token{token: "ya29.test_token"}}
      end)
      
      expect_http_post(fn _url, _body, _headers ->
        response_body = Jason.encode!(%{
          "pemCertificateChain" => ["-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----"],
          "caCert" => "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----"
        })
        {:ok, %{status_code: 200, body: response_body}}
      end)
      
      opts = [
        goth_name: :test_goth,
        hostname: "10.0.0.1",
        database: "postgres",
        username: "user@example.com",
        project_id: "test-project",
        location: "us-central1", 
        cluster: "test-cluster",
        http_client: MockHTTPClient
      ]
      
      config = AlloyDB.postgrex_config(opts)
      
      assert config[:hostname] == "10.0.0.1"
      assert config[:port] == 5432
      assert config[:database] == "postgres"
      assert config[:username] == "user@example.com"
      assert config[:password] == "ya29.test_token"
      assert is_list(config[:ssl])
      assert config[:timeout] == 15000
      assert config[:parameters] == [application_name: "goth-alloydb"]
    end

    test "allows custom port and timeout" do
      expect_goth_fetch(fn _name, _timeout ->
        {:ok, %Goth.Token{token: "ya29.test_token"}}
      end)
      
      expect_http_post(fn _url, _body, _headers ->
        response_body = Jason.encode!(%{
          "pemCertificateChain" => ["cert"],
          "caCert" => "ca"
        })
        {:ok, %{status_code: 200, body: response_body}}
      end)
      
      opts = [
        goth_name: :test_goth,
        hostname: "10.0.0.1",
        database: "postgres", 
        username: "user@example.com",
        project_id: "test-project",
        location: "us-central1",
        cluster: "test-cluster",
        port: 5433,
        timeout: 30000,
        http_client: MockHTTPClient
      ]
      
      config = AlloyDB.postgrex_config(opts)
      assert config[:port] == 5433
      assert config[:timeout] == 30000
    end
  end

  describe "start_link/1" do
    test "starts Goth server with AlloyDB scopes" do
      # This would require mocking GenServer.start_link
      # For now, just test that it calls Goth.start_link with scopes
      
      opts = [name: :test_goth]
      
      # Mock Goth.start_link to verify it's called with scopes
      expect_goth_start_link(fn received_opts ->
        assert received_opts[:scope] == ["https://www.googleapis.com/auth/cloud-platform"]
        {:ok, :mock_pid}
      end)
      
      assert {:ok, :mock_pid} = AlloyDB.start_link(opts)
    end

    test "preserves custom scopes if provided" do
      custom_scopes = ["https://www.googleapis.com/auth/cloud-platform.read-only"]
      opts = [name: :test_goth, scope: custom_scopes]
      
      expect_goth_start_link(fn received_opts ->
        assert received_opts[:scope] == custom_scopes
        {:ok, :mock_pid}
      end)
      
      AlloyDB.start_link(opts)
    end
  end

  # Test helper functions

  defp expect_goth_fetch(fun) do
    original_fetch = &Goth.fetch/2
    :meck.new(Goth, [:non_strict])
    :meck.expect(Goth, :fetch, fun)
    
    on_exit(fn ->
      :meck.unload(Goth)
    end)
  end

  defp expect_goth_start_link(fun) do
    :meck.new(Goth, [:non_strict, :passthrough])
    :meck.expect(Goth, :start_link, fun)
    
    on_exit(fn ->
      :meck.unload(Goth)
    end)
  end

  defp expect_http_post(fun) do
    :meck.new(MockHTTPClient)
    :meck.expect(MockHTTPClient, :post, fun)
    
    on_exit(fn ->
      :meck.unload(MockHTTPClient)
    end)
  end
end

# Mock HTTP client for testing
defmodule MockHTTPClient do
  def post(_url, _body, _headers), do: {:error, :not_mocked}
end