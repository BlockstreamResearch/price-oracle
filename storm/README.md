# Storm

Storm is a Rust peer-to-peer messaging crate. It authenticates secp256k1 peers,
encrypts TCP connections with Noise, discovers known nodes, and carries custom
application messages.

Run the interactive example:

```sh
cargo run -p storm --bin basic -- run --discoverable --config storm/config/discoverable.toml
```

See [the example-node guide](EXAMPLE_NODE.md) for discovery and restore modes.
