defmodule Goth.AlloyDBTest do
  use ExUnit.Case, async: true
  
  @moduletag :alloydb

  describe "postgrex_config/1" do
    test "generates proper configuration with required options" do
      config = Goth.AlloyDB.postgrex_config(
        goth_name: TestGoth,
        hostname: "10.0.0.1",
        database: "testdb",
        username: "test@example.com"
      )

      assert config[:hostname] == "10.0.0.1"
      assert config[:database] == "testdb"
      assert config[:username] == "test@example.com"
      assert config[:password_provider] == {Goth.AlloyDB, :get_token, [TestGoth]}
      assert config[:ssl] == true
      assert config[:ssl_profile] == :cloud
      assert config[:pool_size] == 10
    end

    test "allows overriding default options" do
      config = Goth.AlloyDB.postgrex_config(
        goth_name: TestGoth,
        hostname: "10.0.0.1",
        database: "testdb",
        username: "test@example.com",
        ssl: false,
        ssl_profile: :strict,
        pool_size: 20,
        timeout: 30_000
      )

      assert config[:ssl] == false
      assert config[:ssl_profile] == :strict
      assert config[:pool_size] == 20
      assert config[:timeout] == 30_000
    end

    test "raises when required options are missing" do
      assert_raise KeyError, fn ->
        Goth.AlloyDB.postgrex_config(goth_name: TestGoth)
      end
    end
  end

  describe "get_token_fn/1" do
    test "returns a zero-arity function" do
      token_fn = Goth.AlloyDB.get_token_fn(TestGoth)
      assert is_function(token_fn, 0)
    end
  end

  describe "password provider compatibility" do
    test "MFA tuple format matches Postgrex expectations" do
      # This tests that our MFA tuple is in the correct format
      # that the modified Postgrex expects
      config = Goth.AlloyDB.postgrex_config(
        goth_name: TestGoth,
        hostname: "test",
        database: "test",
        username: "test"
      )
      
      {module, function, args} = config[:password_provider]
      assert module == Goth.AlloyDB
      assert function == :get_token
      assert args == [TestGoth]
      assert is_atom(module)
      assert is_atom(function)
      assert is_list(args)
    end

    test "function provider format" do
      token_fn = Goth.AlloyDB.get_token_fn(TestGoth)
      
      # Test that it's callable
      assert is_function(token_fn, 0)
      
      # In real usage, this would call Goth.fetch
      # Here we just verify the function exists and is callable
    end
  end

  describe "ensure_alloydb_scopes/1" do
    test "adds AlloyDB scopes to service account source" do
      # This is a private function, but we can test it indirectly
      # by checking the child_spec output
      
      credentials = %{"type" => "service_account"}
      spec = Goth.AlloyDB.child_spec(
        name: TestGoth,
        source: {:service_account, credentials, []}
      )
      
      assert spec.id == Goth
      {Goth, :start_link, [opts]} = spec.start
      
      # Check that the options contain the right values
      assert Keyword.get(opts, :name) == TestGoth
      {:service_account, ^credentials, scope_opts} = Keyword.get(opts, :source)
      assert scope_opts[:scopes] == [
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/sqlservice.login"
      ]
    end

    test "adds AlloyDB scopes to metadata source" do
      spec = Goth.AlloyDB.child_spec(
        name: TestGoth,
        source: {:metadata, []}
      )
      
      assert spec.id == Goth
      {Goth, :start_link, [opts]} = spec.start
      
      # Verify the source includes proper scopes
      {:metadata, scope_opts} = Keyword.get(opts, :source)
      assert scope_opts[:scopes] == [
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/sqlservice.login"
      ]
    end
  end
end