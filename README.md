# Goth

![CI](https://github.com/peburrows/goth/workflows/CI/badge.svg)


Google + Auth = Goth

A simple library to generate and retrieve OAuth2 tokens for use with Google
Cloud Service accounts.

## Installation

**Note:** below are instructions for using Goth v1.3+. For more information on
earlier versions of Goth, [see v1.2.0 documentation on hexdocs.pm](https://hexdocs.pm/goth/1.2.0).

1. Add `:goth` to your list of dependencies in `mix.exs`.

   ```elixir
   def deps do
     [
       {:goth, "~> 1.4"}
     ]
   end
   ```

2. Add Goth to your supervision tree:

   ```elixir
   defmodule MyApp.Application do
     use Application

     def start(_type, _args) do
       credentials =
         "GOOGLE_APPLICATION_CREDENTIALS_JSON"
         |> System.fetch_env!()
         |> Jason.decode!()

       source = {:service_account, credentials}

       children = [
         {Goth, name: MyApp.Goth, source: source}
       ]

       Supervisor.start_link(children, strategy: :one_for_one)
     end
   end
   ```

   If you set `GOOGLE_APPLICATION_CREDENTIALS` or
   `GOOGLE_APPLICATION_CREDENTIALS_JSON`, have a
   `~/.config/gcloud/application_default_credentials.json` file,
   `~/.config/gcloud/configurations/config_default` file or deploy
   your application to Google Cloud, you can omit the `:source` option:

   ```elixir
   def start(_type, _args) do
     children = [
       {Goth, name: MyApp.Goth}
     ]

     Supervisor.start_link(children, strategy: :one_for_one)
   end
   ```

   If you want to use multiple credentials, you may consider doing:

   ```elixir
   def start(_type, _args) do
     Supervisor.start_link(servers(), strategy: :one_for_one)
   end

   defp servers do
     servers = [
       {MyApp.Cred1, source1},
       ...
       {MyApp.CredN, source2}
     ]

     for {name, source} <- servers do
       Supervisor.child_spec({Goth, name: name, source: source}, id: name)
     end
   end
   ```

3. Fetch the token:

   ```elixir
   iex> Goth.fetch!(MyApp.Goth)
   %Goth.Token{
     expires: 1453356568,
     token: "ya29.cALlJ4ICWRvMkYB-WsAR-CZnExE459PA7QPqKg5nei9y2T9-iqmbcgxq8XrTATNn_BPim",
     type: "Bearer",
     ...
   }
   ```

See `Goth.start_link/1` for more information about possible configuration options.


## AlloyDB Integration

Goth includes built-in support for Google Cloud AlloyDB IAM authentication with automatic certificate management:

```elixir
# Start Goth server
{:ok, _} = Goth.AlloyDB.start_link(name: MyApp.Goth)

# Generate complete Postgrex configuration
config = Goth.AlloyDB.postgrex_config(
  goth_name: MyApp.Goth,
  hostname: "10.0.0.1",  # AlloyDB private IP
  database: "postgres",
  username: "user@example.com",  # IAM user
  project_id: "my-project",
  location: "us-central1",
  cluster: "my-alloydb-cluster"
)

{:ok, conn} = Postgrex.start_link(config)
```

Features:
- **Native RSA Key Generation** - Zero OpenSSL dependencies using Elixir/Erlang crypto
- **Automatic Certificate Management** - Dynamic client certificates via AlloyDB Admin API  
- **Token Refresh** - Automatic OAuth2 token renewal
- **Postgrex Integration** - Drop-in configuration helpers
- **Config Resolver Support** - Dynamic credential injection for connection pools

For advanced usage with dynamic credentials:

```elixir
# Use config resolver for automatic credential refresh
{:ok, conn} = Postgrex.start_link([
  hostname: "10.0.0.1",
  database: "postgres",
  config_resolver: &Goth.AlloyDB.config_resolver/1
])
```

See `Goth.AlloyDB` module documentation for complete API reference.

## Upgrading from Goth 1.2

See [Upgrading from Goth 1.2](UPGRADE_GUIDE.md) guide for more information.

## Community resources

- [How to upload on YouTube Data API with elixir ?](https://mrdotb.com/posts/upload-on-youtube-with-elixir/)

## Copyright and License

Copyright (c) 2016 Phil Burrows

This work is free. You can redistribute it and/or modify it under the terms of
the MIT License. See the [LICENSE.md](./LICENSE.md) file for more details.
