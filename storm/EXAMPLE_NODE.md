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
