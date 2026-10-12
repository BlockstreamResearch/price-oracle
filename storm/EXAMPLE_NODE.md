# Example node

The `basic` binary runs a Storm node with a terminal UI. Configuration stores the node's
secp256k1 private key as 64 hexadecimal characters. Treat configuration and generated peer
files as secrets where appropriate.

Start a discovery coordinator:

```sh
cargo run -p storm --bin basic -- run --discovery --config storm/config/discovery.toml
```

Start a node that discovers the network through that coordinator:

```sh
cargo run -p storm --bin basic -- run --discoverable --config storm/config/discoverable.toml
```

Start the third node in another terminal:

```sh
cargo run -p storm --bin basic -- run --discoverable --config storm/config/discoverable-third.toml
```

After discovery has produced the configured `peers_file`, restore a node directly:

```sh
cargo run -p storm --bin basic -- run --config storm/config/restored.toml
```

## DNS and saved-address overrides

Socket endpoints accept `IP:port`, `[IPv6]:port`, and `hostname:port`. Storm
resolves hostnames again on reconnect and preserves them after authentication.
The local `listen_address` remains the bind address; optionally set a reachable
`advertised_address` for the local peer table.

The `[discoverer]` section also overrides the coordinator's saved endpoint in
restored mode, without restarting discovery. Other endpoints can be overridden
by compressed public key with `[peer_addresses]`:

```toml
advertised_address = "node-2.oracle.svc.cluster.local:9101"

[discoverer]
public_key = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
socket_address = "coordinator.oracle.svc.cluster.local:9100"

[peer_addresses]
"02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337" = "node-3.oracle.svc.cluster.local:9102"
```

Merge these sections into the node's existing config, using the actual member
keys. Overrides apply locally on startup and persist in the saved peer table;
they do not add members or remove bans. Configured discoverer and advertised
addresses take precedence over the corresponding `peer_addresses` entries.
Upgrade all nodes before introducing DNS into discovery tables, then roll config
changes one node at a time while keeping keys and `peers_file` unchanged. No
rediscovery is needed. Each DNS endpoint must route to one Storm identity.
