# @price-oracle/sdk

Browser-oriented TypeScript SDK for the Price Oracle network: the API of its
nodes, and the chain through Esplora or Elements JSON-RPC.

```ts
import {
  EsploraClient,
  PriceOracleClient,
  createTickRequest,
  publicKeyFromPrivateKey,
  verifyExecutedTick,
} from "@price-oracle/sdk";
import { loadLeafCompiler } from "@price-oracle/sdk/leaves";

const privateKey = "<development-only 32-byte hex key>";
const publicKey = publicKeyFromPrivateKey(privateKey);
const oracle = new PriceOracleClient("http://127.0.0.1:9100");
const leaves = await loadLeafCompiler();
const verification = leaves.accountVerification({
  ownerPublicKey: publicKey,
  network: "elementsregtest",
  stormEyeAssetId: "<independently verified Storm Eye asset ID>",
  tickAssetId: "<independently verified Tick asset ID>",
  verifierAssetId: "<independently verified Verifier asset ID>",
});
const account = await oracle.getAccount(publicKey, verification);

const chain = new EsploraClient("<independently trusted Esplora URL>");
// A fresh Account. Later on, leave out the change an issuance returned to it:
// that is the burn reserve of what the issuance created.
const feeUtxos = await chain.getScriptUtxos(account.script_pubkey);
const request = createTickRequest(
  privateKey,
  feeUtxos.map(({ txid, vout }) => `${txid}:${vout}`),
);
const { request_hash } = await oracle.submitTickRequest(request);

const status = await oracle.waitForTickRequest(request_hash);
const tick = await verifyExecutedTick(status, verification, chain);
```

## Contract Leaves

`getAccount` and the chain checks pin two tapleaf hashes that only a compiler
can produce. `@price-oracle/sdk/leaves` ships that compiler: the SimplicityHL
compiler the nodes run, built for WebAssembly together with the contract
sources of this SDK's revision. It is a separate entry point, so a page that
compiles nothing does not download its module, about 0.9 MB and a third of
that compressed.

```ts
import { loadLeafCompiler } from "@price-oracle/sdk/leaves";

const leaves = await loadLeafCompiler();
const accountTapleafHash = leaves.accountTapleafHash(stormEyeAssetId, owner);
const tickTapleafHash = leaves.voucherTapleafHash(stormEyeAssetId, {
  kind: "signature-auth",
  auth_data: owner,
});
```

`voucherTapleafHash` takes the authentication method a request names, and its
leaf is the one a Tick and a Verifier of that method share. The `auth_data` of
`asset-id-auth` goes into the covenant as it is given: the asset ID's bytes in
the order the chain stores them, which is the reverse of how Elements and
explorers print an asset ID.
`accountVerification(context)` fills both leaves of an `AccountVerification`:
the Tick for `authScriptPubKey` when one is given, for the owner's signature
otherwise. A leaf belongs to its arguments, so each owner, Storm Eye asset and
authentication method is compiled for separately; one compilation takes tens
of milliseconds.

`loadLeafCompiler()` fetches `leaves.wasm` from beside the module, and reads it
from disk outside a browser. A bundler that does not follow
`new URL("./leaves.wasm", import.meta.url)` needs the address spelled out:
import `@price-oracle/sdk/leaves.wasm` as an asset and pass its URL, a
`Response`, or the bytes. A page with a Content Security Policy has to allow
WebAssembly (`'wasm-unsafe-eval'`).

The compiler replaces the local Rust build, not the judgement behind it: the
leaves are those of the contract version built into this SDK, and the Storm Eye
asset ID given to it is still a trust anchor to obtain independently.

The module is a build product and is not kept in the repository.
`bun run build:leaves` builds `dist/leaves.wasm` in a container from the
workspace's contracts and its locked compiler version. Build it before using
this entry point from a checkout or packing the SDK, and again whenever a
contract or the compiler changes. `cargo test` in `leaves` holds every leaf
against the one the `contracts` crate compiles, and `bun test` holds the built
module against leaves pinned from Rust, skipping those tests while the module
is not built.

## Chain Access

The chain is read through a `ChainClient`, which two classes implement:

- `EsploraClient(url)` reads an Esplora HTTP API, which public Liquid explorers
  serve to browsers. It lists a script's confirmed, explicit UTXOs, the ones a
  request can be paid from, and checks one output; it does not broadcast.
- `ElementsRpcClient({ url, username, password })` calls a node's JSON-RPC. It
  also broadcasts, with the burn allowance a Tick redemption needs, and its
  `getScriptUtxos` runs `scantxoutset`, which public endpoints seldom allow.

Every chain check takes either. Whichever is used is a trust anchor: it must
not be an endpoint the coordinator chose. An Esplora URL must use HTTPS, except
HTTP on loopback, and redirects are rejected.

A failed RPC call throws an `ElementsRpcError` with the node's own message and
JSON-RPC `code`, and a failed Esplora read an `EsploraError`; both carry the
HTTP `status`. Each endpoint is given 15 seconds to answer, `timeoutMs` in the
options of either client, and one that does not throws with `status` 0.

## Errors, Retries and Several Nodes

A failed coordinator call throws an `OracleApiError`. Its `message` is the
node's reason, `status` the HTTP status, and `code` what kind of failure it
was: `invalid_request`, `unauthorized`, `not_found`, `conflict`, `timeout`,
`rate_limited`, `not_coordinator`, `unavailable`, `server_error`,
`invalid_response`, or `network` when no node answered. A node is given 15
seconds to answer; one that does not counts as a `timeout` with `status` 0.

```ts
try {
  await oracle.submitTickRequest(request);
} catch (error) {
  if (error instanceof OracleApiError && error.code === "conflict") {
    // Already queued, or a fee UTXO is taken by another request.
  }
}
```

A read is repeated when no node answered it in time or one answered 408, 429
or a server error (5xx): twice by default, after 500 ms and then 1 s.
`new PriceOracleClient(url, { retries, retryDelayMs, timeoutMs })` changes
that, and `retries: 0` turns it off. A submission is never repeated: a node that
did not answer, or failed while handling it, may still have queued it, and
sending it again answers `conflict` if it did.

Only the coordinator serves requests and prices, and the role moves between
members. Given several node URLs, the client asks the next one when a node
answers that it is not the coordinator, and for reads also when a node fails
in a way worth repeating, then stays with the one that answered:

```ts
const oracle = new PriceOracleClient([
  "https://node-1.example",
  "https://node-2.example",
  "https://node-3.example",
]);
```

`oracle.nodeUrl` is the node the next call goes to first. Every URL must be a
member of the same network; none of them replaces the trust anchors below.

## Network Metadata

`getNetwork()` reads the active `network`, the Storm Eye, Tick and Oracle
Verifier asset IDs and the current `storm_tree_root` from the coordinator.
These are that node's own claims: using them unchecked delegates deployment and
root selection to it. Pin the values held from an independent source and each
one supplied is compared with the response:

```ts
const network = await oracle.getNetwork({
  network: "liquidv1",
  stormEyeAssetId: trustedStormEyeAssetId,
  tickAssetId: trustedTickAssetId,
  verifierAssetId: trustedVerifierAssetId,
});
```

A mismatch throws, and a malformed pinned value fails before fetching. Any
subset may be pinned; a field left out is returned as received and is not a
trust anchor for the checks below. `stormTreeRoot` can be pinned too, but it
changes with membership.

## Waiting for a Request

`waitForTickRequest(requestHash, options)` polls the request until it is
`executed` and returns that status. The earlier statuses are not final:
`processing` is broadcast, and `included` is in a block a reorg can still
orphan. A `failed` request rejects with the coordinator's reason.

`options` takes `timeoutMs` (15 minutes by default), `intervalMs` (5 seconds),
an `AbortSignal`, and an `onStatus` callback called with every status read. A
timeout or abort ends the wait, not the request: it stays queued and can be
waited on again. A status read is retried like any other read, and an error
that outlasts the retries ends the wait. The timeout and the signal also cut
short a status read in progress, so a node that stops answering cannot hold the
wait past them.

Issuance follows block production. With one-minute blocks and two finality
confirmations a request takes a few minutes, and a priced one can wait up to ten
blocks for a feed the coordinator cannot price before it fails.

## Tick Verification

`verifyExecutedTick(status, verification, chain)` is the Tick counterpart of
`verifyExecutedSignedPrice`. It takes the batch's single `tick-utxo` result and
checks it through an independently trusted chain source: the output is
unspent, mempool spends included, has at least one confirmation, carries the
trusted Tick asset, an amount equal to the reported timestamp, and the Elements
Taproot script of the trusted voucher leaf under the fixed unspendable internal
key. It returns the `IssuedTick` that `createTickSpendPlan` takes, `null` before
the request is `executed`, and throws on any mismatch.

`verification` needs `tickAssetId` and `tickTapleafHash`, so the
`AccountVerification` given to `getAccount` can be passed as it is. This is a
point-in-time check, not a guarantee against later spends, expiry, or reorgs.

## Humid Wallet Requests

`createWalletTickRequest(compressedPublicKey, feeUtxos, walletScript)` constructs
an unsigned script-authorized Tick request without accepting a private key.
Send `walletRequestSigningMessage(request)` to Humid's scoped `signMessage`
method with the wallet address and `protocol: "ecdsa"`, assign the returned
hex-recoverable-ecdsa-65 signature to `request.header.signature`, then submit
the request normally.

For wallet-authorized Ticks, call `getAccount(xOnlyPublicKey, verification)`
with `verification.authScriptPubKey` set to the wallet script and
`verification.tickTapleafHash` independently compiled for that script's SHA-256.
The Account leaf is still compiled for the x-only owner key. The ECDSA header declares
`bitcoin-signed-message-ecdsa-v1` and carries both the compressed signing key
and its x-only account key. Its canonical message binds both keys, fee
outpoints, and complete request kinds/payloads.

`createTickSpendPlan` validates the cross-covenant layout required when a
prediction position consumes a Tick. Program and witness
assembly remains in Rust/Simplex because reproducing consensus-critical
Simplicity compilation in browser JavaScript is unsafe.

## Account Verification

`getAccount(publicKey, verification)` now requires an `AccountVerification`
context. This is a breaking API change: the old unchecked and wallet-script-only
calls are rejected. The SDK derives the Account and Tick scripts locally with
the fixed unspendable internal key and Elements Taproot tweak, then encodes the
Account's Bech32m address for the trusted network. Every returned address,
script, asset ID and network must match before the method returns. The returned
object contains locally derived values, not unchecked coordinator fields.

Obtain asset IDs from independently verified issuance or trusted configuration,
not the same coordinator response. Obtain the leaves from the leaf compiler
described above, or in Rust: `accountTapleafHash` from
`AccountProgram::get_tapleaf_hash()` after local Rust/Simplex compilation with
`AccountArguments` containing the verified Storm Eye asset's consensus bytes
and the intended owner's x-only key. Obtain `tickTapleafHash` from
`Voucher::get_tapleaf_hash()` with the same Storm Eye asset and the intended
signature or script authentication method. Use the matching reviewed contract
version. These leaves are specific to their arguments: recompile for a new
owner, Storm Eye asset or Tick authentication method. The SDK does not itself
compile Simplicity or prove that supplied trust anchors were derived correctly.

`deriveAccount(verification)` is also exported for offline derivation using
those same independent anchors. A wrong or missing verification context fails
before fetching. Network prefixes are checked against Rust-generated vectors
for Liquid mainnet, Liquid testnet and Elements regtest.

This verifies the funding destination and advertised network metadata; it does
not establish an on-chain deposit, spendability, confirmation count, or network
liveness. Accounts remain custodial under the existing contract design.

## Signed Price Verification

`verifySignedPriceData(details, verification)` and
`parseExecutedSignedPrice(status, verification)` now require a trusted context.
This is a breaking change: a signature under a key in the coordinator response
alone is not oracle authentication. Missing context fails closed.

```ts
const verification = {
  stormTreeRoot: trustedCurrentStormEyeRoot,
  feedId: expectedFeedId,
  decimals: expectedDecimals,
  now: BigInt(Math.floor(Date.now() / 1000)),
};

const valid = verifySignedPriceData(details, verification);
const executed = parseExecutedSignedPrice(status, verification);
```

Obtain the current root from independently verified Storm Eye state or a trusted
network configuration. Do not copy it from the response being checked. Refresh
it after membership changes, and do not trust a network past its rescue height.
Choose the expected feed and decimals locally and use a trusted clock. Verification
checks the branch's inclusion proof, the tagged Schnorr signature, the expected
feed and decimals, and `receivedAt <= now < validUntil`, with a maximum 300-second
validity window. Invalid data returns `false`; the executed parser throws.

Neither synchronous helper proves that the coordinator's returned Verifier
outpoint exists. For confirmed, unspent issuance, use the independent chain check:

```ts
const executed = await verifyExecutedSignedPrice(status, {
  ...verification,
  verifierAssetId: trustedVerifierAssetId,
  verifierTapleafHash: locallyCompiledVoucherTapleafHash,
}, chain);
```

Import these helpers from `@price-oracle/sdk`. The `chain` client must use an
independently trusted Elements RPC or Esplora endpoint. Pin the asset ID from
verified network issuance and the voucher leaf from the leaf compiler or a
local Rust/Simplex compilation for the requested authentication method.
Neither value should come unchecked from the coordinator. The check reads the
output with mempool spends
included, requires at least one confirmation, the explicit Verifier asset and
one-unit amount, and the Elements Taproot script committing to the signed branch
and trusted leaf. This is a point-in-time check, not a guarantee against later
spends, expiry, or reorgs; on-chain consumers must still enforce their covenant.

A contract holds a signed price against the time of a Tick spent beside its
Verifier. `createSignedPriceRequest(privateKey, feeUtxos, feedId, authMethod,
{ withTick: true })` orders both in one batch under the same authentication
method, as `createWalletSignedPriceRequest` does for a wallet. Both are issued
in one transaction: the batch pays the per-output fee twice and the issuance fee
once, and its fee UTXOs must also cover a burn reserve for each output.

`verifyExecutedTickWithPrice(status, verification, chain)` checks such a batch
as the contract's `verify_tick_with_price` will: the Tick and the Verifier are
each the confirmed, unspent output their covenant expects, a member of the
trusted Storm Tree signed the rate for the expected feed and decimals, and the
rate is still valid at the time the Tick carries.

```ts
const pair = await verifyExecutedTickWithPrice(status, {
  stormTreeRoot: trustedCurrentStormEyeRoot,
  feedId: expectedFeedId,
  decimals: expectedDecimals,
  verifierAssetId: trustedVerifierAssetId,
  verifierTapleafHash: tickTapleafHash,
  tickAssetId: trustedTickAssetId,
  tickTapleafHash,
}, chain);
```

It takes no `now`: the contract holds the rate against the Tick's time, not
against a clock, so a pair that passes stays spendable together until the Tick
expires. It returns the `IssuedTick`, the Verifier's output index, the signed
rate and its decoded `price`, and `null` before the request is `executed`.
`verifyExecutedSignedPrice` and `verifyExecutedTick` check either output alone.

Coordinator URLs must use HTTPS, except HTTP on `localhost`, `127.0.0.1`, or
`[::1]` for local development. Redirects are rejected. HTTPS does not replace
the independent trust anchors above, or Account verification.