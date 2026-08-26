# high-storm

`high-storm` persists Storm discovery state in PostgreSQL and restores it on later runs.

## Three-node Docker deployment

The included Compose stack starts PostgreSQL and three preconfigured development
nodes. On the first start, node 1 hosts discovery and nodes 2 and 3 join it. Later
starts restore each node from its own database. Manage it from any directory with:

```sh
high-storm/docker.sh create # Reset data, rebuild, and start everything.
high-storm/docker.sh up     # Start while preserving initialized state.
high-storm/docker.sh rebuild # Rebuild Rust and restart nodes, preserving state.
high-storm/docker.sh down   # Stop while preserving initialized state.
high-storm/docker.sh connections 1 # List node 1's active connections.
```

The Storm listeners are exposed on host ports `9000`, `9001`, and `9002`; their
REST APIs are exposed on `9100`, `9101`, and `9102`.
Each node has its own operator platform at `http://127.0.0.1:9200`,
`http://127.0.0.1:9201`, and `http://127.0.0.1:9202`, respectively. For local
development, log in with the matching deterministic secret from
`docker/node-1.toml`, `docker/node-2.toml`, or `docker/node-3.toml`. Each node
registers that key through `storm-operator` when its IPC socket becomes available.
PostgreSQL is exposed on `5432`. Follow the node logs with:

```sh
docker compose -f high-storm/compose.yml logs -f node-1 node-2 node-3
```

Heartbeat send and receive events are emitted at trace level. Enable them with
`RUST_LOG=info,high_storm=debug,storm=debug,storm::heartbeat=trace`.

The checked-in identities and database password are for local development only.

## Configuration

Copy `config.example.toml` to `config.toml`, then set the listener port, signer key,
and PostgreSQL connection fields. The `service.db.url` value is the database host
and optional port, for example `localhost:5432`. Set `service.ipc_path` to a unique
Unix socket path for each high-storm process running on the same host. The REST API
binds to `service.rest_address`, which defaults to `127.0.0.1:9001`.

## Initialize a network

Start the discovery host with every other member's compressed secp256k1 public key.
The host public key is derived from the signer private key in `config.toml`:

```sh
cargo run -p high-storm -- initialize host \
  --config config.toml \
  --public-key <member-public-key>
```

Each other member joins through the host:

```sh
cargo run -p high-storm -- initialize join \
  --config config.toml \
  --discovery-public-key <host-public-key> \
  --discovery-address <host:port>
```

Initialization remains running after the complete peer table is saved. Stop it with
Ctrl-C after all members report successful initialization.

## Run an initialized node

```sh
cargo run -p high-storm -- run --config config.toml
```

## Manage node operators

While high-storm is running, add and remove node operators by their compressed,
hex-encoded secp256k1 public key:

```sh
cargo run -p storm-operator -- operator add <public-key>
cargo run -p storm-operator -- operator remove <public-key>
```

High-storm verifies the Unix peer credentials before reading a command. Only the
user that started the node and the root user are authorized to use the socket.

When high-storm uses a non-default `service.ipc_path`, pass the same path to the
client with `--socket <path>`.

## REST API

Operator identities are compressed secp256k1 public keys. High-storm derives each
key's mainnet P2WPKH address and verifies BIP322-simple signatures against it.

| Method | Path | Authentication |
| --- | --- | --- |
| `POST` | `/operators/auth/challenge` | Operator public key in JSON |
| `POST` | `/operators/auth/token` | BIP322 signature of the returned challenge |
| `GET` | `/operators/state` | `Authorization: Bearer <token>` |
| `GET` | `/operators/state/peers` | `Authorization: Bearer <token>` |
| `GET` | `/operators/voting` | `Authorization: Bearer <token>` |
| `GET` | `/operators/voting/{hash}` | `Authorization: Bearer <token>` |
| `POST` | `/operators/voting` | Signed request envelope |
| `POST` | `/operators/voting/{hash}/approve` | Signed request envelope |

Challenge and token requests use these shapes:

```json
{"public_key":"<66 hex characters>"}
```

```json
{"public_key":"<key>","message":"<challenge message>","signature":"<BIP322 base64>"}
```

Writes use an envelope containing `public_key`, Unix `timestamp`, unique `nonce`,
BIP322 `signature`, and `payload`. Sign this exact newline-delimited message:

```text
high-storm:operator-write:v1
POST
<request path>
<timestamp>
<nonce>
<lowercase SHA256 hex of canonical payload JSON>
```

Canonical payload JSON is compact JSON with object keys sorted recursively; array
order is preserved. Timestamps must be within five minutes of the server clock and
nonces may only be used once during that window. Vote payloads use the tagged kinds
`update_network_members`, `merge_storm_eyes`, and `split_storm_eye`. Approval uses
an empty object as its payload. `/users/*` currently returns `501 Not Implemented`.

The API has no TLS termination. Keep the default loopback bind or place it behind
an authenticated TLS reverse proxy before exposing it beyond a trusted network.

The integration harness in `tests/common` creates isolated in-memory SQLx stores,
deterministic identities, and available listener ports for future node-level tests.
