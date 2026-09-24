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
high-storm/devenv.sh deploy-node 4 # Deploy a candidate node for a later vote.
high-storm/devenv.sh public-key 4 # Print its compressed public key.
high-storm/devenv.sh connections 1 # List node 1's active connections.
high-storm/devenv.sh elements 1 getblockchaininfo # Call node 1's Elements RPC.
```

`deploy-node NODE` accepts node numbers from 4 through 99. It creates a persistent
development signer configuration and PostgreSQL database, then starts the node on
host ports `8999 + NODE` and `9099 + NODE`. The node waits to be admitted by an
approved membership vote and completes discovery once the active network stages
its public key. Generated signer configurations live in the ignored
`high-storm/.devenv-nodes` directory. Re-running the command preserves the node's
identity and database. `down` removes extra-node containers but preserves their
configuration and database; `create` resets both.

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

Elements RPC is exposed on host ports `18884`, `18885`, and `18886`. Port `18884`
uses a localhost-only CORS gateway so browser clients can call node 1 directly. Every High
Storm node uses its matching Elements daemon through `service.elements_rpc`.
Elements `29.4.1rc1` is built from its release tag and verified against commit
`a4d4c96ac7a7a9171b6f777e287ee4df18d779e1` and the checked-in source archive
checksum.

The Elements nodes use the stock `29.4.1rc1` regtest genesis and a development-only
50 LBTC block subsidy. On a fresh chain, the bootstrap service mines 102 blocks so
100 LBTC matures, then sends exactly 50 LBTC to node 1's development key. It mines
one additional block every 60 seconds. The coordinator waits for this funding to
complete. The bootstrap is idempotent, so restarting it does not fund the key again.
Inspect the funded wallet with:

```sh
docker compose -f high-storm/compose.yml exec -T elements-1 \
  elements-cli -chain=elementsregtest -rpcport=18884 \
  -rpcuser=high-storm -rpcpassword=high-storm \
  -rpcwallet=funded-key getbalance
```

The chain, RPC credentials, signer keys, and funded private key are for local
development only.

`devenv.sh` creates a dedicated Docker bridge on the first `create`, `up`, or
`rebuild`. It selects an unused `/24` subnet and stores the prefix in the ignored
`.devenv-network.env` file. The external bridge remains reserved after `down` so
persisted peer addresses stay stable and other Compose projects cannot claim its
subnet. Set `STORM_NETWORK_PREFIX` before the first start to choose a specific
three-octet prefix, such as `172.30.4`.

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
defaults to `127.0.0.1:9001`. Elements must run with `txindex=1` so HighStorm can
reconcile confirmed request transactions after they leave the mempool. Protocol-wide
fee budgets, burn reserves, and Tick lifetime are grouped under `service.protocol`.
The legacy `service.user_requests` section remains accepted for existing deployments.

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
| `GET` | `/operators/droplets` | `Authorization: Bearer <token>` |
| `POST` | `/operators/droplets/exchange` | Signed request envelope |
| `GET` | `/operators/voting` | `Authorization: Bearer <token>` |
| `GET` | `/operators/voting/{hash}` | `Authorization: Bearer <token>` |
| `POST` | `/operators/voting` | Signed request envelope |
| `POST` | `/operators/voting/{hash}/approve` | Signed request envelope |
| `POST` | `/users/requests` | User Schnorr signature in JSON |
| `GET` | `/users/requests/{request_hash}` | None; coordinator node only |
| `GET` | `/price-feeds` | None; coordinator node only |
| `GET` | `/price-feeds/{id}` | None; coordinator node only |

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

Droplets exchanges specify the LBTC amount in satoshis and an unconfidential
destination address for the node's current Elements network:

```json
{"amount":1000,"address":"<unconfidential Elements address>"}
```

The node selects indexed explicit Treasury LBTC, constructs and validates the
PSET with the configured `exchange_transaction_fee_sats`, and persists it. The
node invokes the request only when it is the current block leader. A new valid
request replaces that node's previous request. Droplets responses expose the fee
as `exchange_fee_sats`. The recipient receives the requested amount; the fee is
an Elements transaction fee output and is not returned to Treasury, so the
member's Droplets balance must cover the requested amount plus that fee.

User submissions contain a `header` and a non-empty `requests` array. Each fee
UTXO is encoded as `<64-character txid>:<u32 output index>`. The coordinator
queries Elements before accepting a request and requires every fee UTXO to be
unspent, explicit policy asset, and locked by the requester's Account covenant.
Their combined value must cover the configured operational fee and Tick burn
reserve for every requested output, plus one issuance transaction fee. Accepted
fee UTXOs are reserved atomically, cannot be reused by another request, and remain
reserved until the issuance transaction confirms. The accepted request kinds are
`tick-utxo` and `signed-price-data`. Each `payload` is a JSON-encoded string
with this shape:

```json
{"utxo_auth_method":{"kind":"signature-auth","auth_data":"<64-character x-only public key>"}}
```

A `signed-price-data` request adds the feed it is issued at, and a `tick-utxo`
request must not name one:

```json
{"utxo_auth_method":{"kind":"signature-auth","auth_data":"<key>"},"feed_id":4}
```

The supported UTXO authentication kinds are `asset-id-auth`,
`scriptPubKey-auth`, and `signature-auth`. Sign the BIP-340 tagged hash named
`OracleNetworkV1/NetworkUserRequests` with the x-only key in
`header.public_key`. The tagged-hash message is the byte concatenation of each
request's payload, in array order, followed by each fee UTXO string, in array
order. Encode the 64-byte Schnorr signature as hex in `header.signature`.

Accepted submissions return `201` and a `request_hash`; submitting the same
request, or another request using one of its reserved fee UTXOs, returns `409`.
`GET /users/requests/{request_hash}` initially returns
`{"status":"pending","payload":null}`. After each newly indexed Liquid block, the
coordinator divides the first half of the live Storm Eye UTXOs into issuance rounds
across the next 60 seconds. With six Storm Eyes, issuance runs at offsets 0, 20, and
40 seconds; burning uses the other half at offsets 15, 30, and 45 seconds. The
schedule is recalculated whenever the confirmed Storm Eye count changes. Each
issuance round takes the oldest pending requests and packs the largest FIFO prefix
whose conservative weight estimate does not exceed `400000 / storm_eye_count`.
The exact finalized weight is checked again after signing and before broadcast.
Consecutive issuance rounds chain through the Tick reissuance token in the mempool.
The coordinator collects a two-thirds Storm Tree signature and broadcasts the
covenant transaction. The status becomes `processing` after broadcast,
`included` once the issuance transaction is in a block, and `executed` once that
block reaches the configured finality confirmations; a reorg that orphans the
block returns the request to `processing`. A request the coordinator cannot
issue becomes `failed`, releases its fee UTXOs, and carries the reason as
`payload` text instead of the result JSON. A node that is not the current
coordinator returns `503` for both user routes.

One batch names at most one feed, and one issuance round is issued at one feed:
the first pending batch that names one sets the round's feed, batches naming
another wait for a round of their own, and plain `tick-utxo` requests ride along
with either. The coordinator takes its own current value for that feed, encodes
it as the 32-byte `PriceFeedData`, and carries it beside every batch issued at
it; a request whose feed the coordinator cannot price yet waits for a later
round, since a feed is unavailable after a restart and between polls, and fails
once it has waited ten blocks, so a feed this node never prices does not hold
its fee UTXOs reserved forever. Before signing, each member checks the
instructed rate against the value it holds itself and rejects the whole message
on the first failure: an unregistered feed, no valid local price, a rate the
node clock has passed, one stamped ahead of its clock or valid for longer than
`VALIDITY_WINDOW` from when it was received, one quoted at other decimals than
its feed, or one that differs from its own by `MAX_ACCEPT_DEVIATION_FEED` (one
percent) or more. A round issued at a rate signs that rate as a second message,
the `OracleNetworkV1/Price` tagged hash over the 32-byte `PriceFeedData`, with
the same two-thirds Storm Tree branch that signs the transaction. Every signer
derives that message from the rate it validated itself, so the signature is one
no coordinator can obtain for a price the network did not accept. A
`signed-price-data` request receives it as its result `payload`:

```json
{"timestamp":1700000000,"price_data":"<64 hex characters>","storm_tree_bloom":{"signature":"<128 hex characters>","branch":"<64 hex characters>","proof":[{"right":true,"hash":"<64 hex characters>"}]}}
```

`price_data` is the canonical `PriceFeedData` the signature covers, and `branch`
is the x-only key it verifies under. `proof` carries that branch's inclusion
path, leaf to root; the root it proves against is the Storm Eye's on-chain one,
so a reader takes that from the chain rather than from this payload.
`timestamp` is the issued Tick's, since the Tick UTXO is still the one a
`tick-utxo` request produces: the transaction commits to the batch, not to the
price, and recording the rate on-chain needs a covenant field that does not
exist yet.

`GET /price-feeds` lists the registry every node shares: each feed with its id
and symbols, in id order. `GET /price-feeds/{id}` returns the current rate for
one feed, in the same shape for a Direct feed and a Cross pair:

```json
{"main":{"feed":{"feed_id":0,"price":9876543210,"decimals":8,"received_at":1700000000,"valid_until":1700000300},"signature":"<128 hex characters>","public_key":"<64 hex characters>"},"auxiliary":[]}
```

`main` is the coordinator's own attestation; `auxiliary` holds the attestations
of the same feed from the other current members, so what a removed member last
attested is not served on. A read answers from what the node holds, so it needs
no coordination round and stays available while issuance is stopped. No price is
served past its `valid_until`: an expired attestation is left out of `auxiliary`
entirely. A feed id that is not a number returns `400`, an unregistered one
`404`, and a feed the coordinator holds no valid price of its own for returns
`503`, saying whether that feed has expired or was never attested. A rate
response is `no-store`, so no cache between the node and a client may serve a
price the node itself would no longer serve.

Each `signature` is a BIP-340 signature by `public_key` over
`SHA256(SHA256(tag) || SHA256(tag) || feed)`, where `tag` is the ASCII string
`OracleNetworkV1/Price` and `feed` is its 32 canonical bytes: `feed_id` and
`decimals` as 4-byte big-endian integers, `price`, `received_at`, and
`valid_until` as 8-byte big-endian integers, laid out in the order `feed_id`,
`decimals`, `price`, `received_at`, `valid_until`. A client can therefore check
that the coordinator did not alter what a member signed.

It cannot check what the coordinator left out or added: this API exposes no
member list, so the keys in `auxiliary` are only as trustworthy as the
coordinator serving them. Obtain the member keys out of band — an operator can
read them from `GET /operators/state/peers` — and treat `auxiliary` as
unverified until you do.

An attestation says that the member saw that price, not that the price is
right. A feed with no source of its own never becomes available and answers
`503` permanently, and so does a Cross pair whose legs have none.

Each node indexes confirmed Tick outputs and their dedicated Account burn
reserves. A Tick expires after 60 blocks, or one hour at the target one-minute
block interval, in both production and the bundled Docker deployment. The
deterministic round-robin leader batches expired Ticks across users, obtains a
Storm Tree signature, and burns their summed value into one empty `OP_RETURN`. The
remaining reserve is returned to each Account covenant after deducting its
share of `burn_transaction_fee_sats`. After broadcasting, the leader announces
the burn transaction and selected Tick outpoints to the other nodes. Nodes also
reconcile their burn state from the mempool before each leader round so missed
announcements do not cause duplicate burns. Unconfirmed burns return to the
expired queue after five blocks. The indexer immediately removes confirmed
spent Ticks; the returned Account output becomes eligible for later requests
once no tracked Tick still reserves it and it has the required confirmation.

The API has no TLS termination. Keep the default loopback bind or place it behind
an authenticated TLS reverse proxy before exposing it beyond a trusted network.

The integration harness in `tests/common` creates isolated in-memory SQLx stores,
deterministic identities, and available listener ports for future node-level tests.
