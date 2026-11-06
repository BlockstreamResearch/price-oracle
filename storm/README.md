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

## Handshake Key Confirmation

Storm uses Noise IK with an additional encrypted initiator key-confirmation
frame. After reading Noise message 2, the initiator sends the fixed plaintext
`Storm/key-confirmation/v1` as its first encrypted transport frame. The responder
must authenticate and match that frame before claiming a connection slot,
marking a peer active, learning its address, or triggering discovery. Confirmation
is covered by the existing 10-second handshake deadline. Normal initiator traffic
continues at the next transport nonce; confirmation is not an application message.

A captured message 1 cannot establish a connection, and a captured confirmation
cannot authenticate against a fresh responder handshake. Failed or abandoned
confirmations do not modify peer state or release a genuine active connection.
This does not address exhaustion of the shared pre-authentication connection pool.

The original Noise prologue is unchanged. Earlier binaries still do not implement
the mandatory confirmation frame: updated responders wait for confirmation from
old initiators, while old responders treat it as application traffic. Upgrade all
network members together, including joining members and discovery endpoints;
preserving the prologue does not make mixed-version connections compatible.
Existing peer identities and persisted peer tables do not need to be reset.
