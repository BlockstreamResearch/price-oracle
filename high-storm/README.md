# high-storm

`high-storm` persists Storm discovery state in PostgreSQL and restores it on later runs.

## Local Docker deployment

The included Compose stack starts PostgreSQL, three preconfigured High Storm nodes,
three operator platforms, and three interconnected Elements nodes. On the first
start, High Storm node 1 hosts discovery and nodes 2 and 3 join it. Later starts
restore each node from its own database. Manage it from any directory with:

```sh
high-storm/devenv.sh create # Reset data, rebuild, and start everything.
high-storm/devenv.sh up     # Start while preserving initialized state.
high-storm/devenv.sh rebuild # Rebuild Rust and restart nodes, preserving state.
high-storm/devenv.sh down   # Stop while preserving initialized state.
high-storm/devenv.sh connections 1 # List node 1's active connections.
high-storm/devenv.sh elements 1 getblockchaininfo # Call node 1's Elements RPC.
```

The Storm listeners are exposed on host ports `9000`, `9001`, and `9002`; their
external APIs are exposed on `9100`, `9101`, and `9102`.
Each node has its own operator platform at `http://127.0.0.1:9200`,
`http://127.0.0.1:9201`, and `http://127.0.0.1:9202`, respectively. For local
development, log in with the matching deterministic secret from
`docker/node-1.toml`, `docker/node-2.toml`, or `docker/node-3.toml`. Each node
registers that key through `storm-operator` when its IPC socket becomes available.
PostgreSQL is exposed on `5432`. Follow the node logs with:

```sh
docker compose -f high-storm/compose.yml logs -f node-1 node-2 node-3
```

Elements RPC is exposed on host ports `18884`, `18885`, and `18886`. Every High
Storm node uses its matching Elements daemon through `service.elements_rpc`.
Elements `29.4.1rc1` is built from its release tag and verified against commit
`a4d4c96ac7a7a9171b6f777e287ee4df18d779e1` and the checked-in source archive
checksum.

The bootstrap service claims the development chain's initial free coins and sends
exactly 50 LBTC to node 1's development key. It then mines one block immediately
and one block every 60 seconds. The coordinator waits for this funding to complete.
The bootstrap is idempotent, so restarting it does not fund the key again. Inspect
the funded wallet with:

```sh
docker compose -f high-storm/compose.yml exec -T elements-1 \
  elements-cli -chain=elementsregtest -rpcport=18884 \
  -rpcuser=high-storm -rpcpassword=high-storm \
  -rpcwallet=funded-key getbalance
```

The chain, RPC credentials, signer keys, and funded private key are for local
development only.

On its first successful startup, the coordinator compiles the Storm Eye covenant
with the current Storm Tree root and a three-year rescue height, issues the fixed
10,000-unit asset from its configured Elements wallet, and persists the signed
transaction before broadcasting it. A restart rebroadcasts the same pending
transaction or reuses the active asset; it never prepares a second issuance.
Active asset metadata is delivered idempotently to every network member and is
retried for peers that were offline.

Heartbeat send and receive events are emitted at trace level. Enable them with
`RUST_LOG=info,high_storm=debug,storm=debug,storm::heartbeat=trace`.

The checked-in identities and database password are for local development only.

## Configuration

Copy `config.example.toml` to `config.toml`, then set the listener port, signer key,
Elements RPC endpoint, and PostgreSQL connection fields. The
`service.elements_rpc.url` value is the full HTTP endpoint for that node's Elements
daemon. `service.elements_rpc.wallet` selects the coordinator wallet that funds
the one-time Storm Eye issuance and defaults to `funded-key`. The `service.db.url`
value is the database host and optional port, for example `localhost:5432`. Set
`service.ipc_path` to a unique Unix socket path for each high-storm process running
on the same host. The external API binds to `service.external_api_address`, which
defaults to `127.0.0.1:9001`.

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

## External API

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
| `POST` | `/users/requests` | User Schnorr signature in JSON |
| `GET` | `/users/requests/{request_hash}` | None; coordinator node only |

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
an empty object as its payload.

User submissions contain a `header` and a non-empty `requests` array. Each fee
UTXO is encoded as `<64-character txid>:<u32 output index>`. The coordinator
currently validates only this format; it does not query Elements to verify the
UTXO, its value, or its ownership. Only `tick-utxo` requests are accepted at this
stage. Its `payload` is a JSON-encoded string with this shape:

```json
{"utxo_auth_method":{"kind":"signature-auth","auth_data":"<64-character x-only public key>"}}
```

The supported UTXO authentication kinds are `asset-id-auth`,
`scriptPubKey-auth`, and `signature-auth`. Sign the BIP-340 tagged hash named
`OracleNetworkV1/NetworkUserRequests` with the x-only key in
`header.public_key`. The tagged-hash message is the byte concatenation of each
request's payload, in array order, followed by each fee UTXO string, in array
order. Encode the 64-byte Schnorr signature as hex in `header.signature`.

Accepted submissions return `201` and a `request_hash`; submitting the same
request again returns `409`. `GET /users/requests/{request_hash}` initially
returns `{"status":"pending","payload":null}`. A node that is not the current
coordinator returns `503` for both user routes. `signed-price-data` returns `422`
until price request processing is implemented.

The API has no TLS termination. Keep the default loopback bind or place it behind
an authenticated TLS reverse proxy before exposing it beyond a trusted network.

The integration harness in `tests/common` creates isolated in-memory SQLx stores,
deterministic identities, and available listener ports for future node-level tests.
