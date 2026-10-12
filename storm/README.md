# Storm

Storm is a Rust peer-to-peer messaging crate. It authenticates secp256k1 peers,
encrypts TCP connections with Noise, discovers known nodes, and carries custom
application messages.

Run the interactive example:

```sh
cargo run -p storm --bin basic -- run --discoverable --config storm/config/discoverable.toml
```

See [the example-node guide](EXAMPLE_NODE.md) for discovery and restore modes.

Peer endpoints support IP and DNS with a port. DNS is resolved afresh on every
reconnect. Use `StormHandle::set_peer_address` to override a saved endpoint without
changing peer identity or interrupting an active connection. See the guide for
configuration and rolling migration from IP-only networks.
