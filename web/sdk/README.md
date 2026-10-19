# @price-oracle/sdk

Browser-oriented TypeScript SDK for the Price Oracle coordinator and public
Elements JSON-RPC endpoints.

```ts
import {
  ElementsRpcClient,
  PriceOracleClient,
  createTickRequest,
  publicKeyFromPrivateKey,
} from "@price-oracle/sdk";

const privateKey = "<development-only 32-byte hex key>";
const publicKey = publicKeyFromPrivateKey(privateKey);
const oracle = new PriceOracleClient("http://127.0.0.1:9100");
const verification = {
  ownerPublicKey: publicKey,
  network: "elementsregtest" as const,
  stormEyeAssetId: "<independently verified Storm Eye asset ID>",
  tickAssetId: "<independently verified Tick asset ID>",
  verifierAssetId: "<independently verified Verifier asset ID>",
  accountTapleafHash: "<locally compiled Account leaf for this owner>",
  tickTapleafHash: "<locally compiled signature-authorized voucher leaf>",
};
const account = await oracle.getAccount(publicKey, verification);

const elements = new ElementsRpcClient({ url: "<CORS-enabled public RPC URL>" });
const feeUtxos = await elements.getScriptUtxos(account.script_pubkey);
const request = createTickRequest(
  privateKey,
  feeUtxos.map(({ txid, vout }) => `${txid}:${vout}`),
);
const { request_hash } = await oracle.submitTickRequest(request);
```

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
not the same coordinator response. Obtain `accountTapleafHash` from
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
}, elements);
```

Import these helpers from `@price-oracle/sdk`. The `elements` client must use an
independently trusted Elements RPC endpoint. Pin the asset ID from verified
network issuance and the voucher leaf from local Rust/Simplex compilation for
the requested authentication method and network. Neither value should come
unchecked from the coordinator. The check uses `gettxout` with mempool spends
included, requires at least one confirmation, the explicit Verifier asset and
one-unit amount, and the Elements Taproot script committing to the signed branch
and trusted leaf. This is a point-in-time check, not a guarantee against later
spends, expiry, or reorgs; on-chain consumers must still enforce their covenant.

Coordinator URLs must use HTTPS, except HTTP on `localhost`, `127.0.0.1`, or
`[::1]` for local development. Redirects are rejected. HTTPS does not replace
the independent trust anchors above, or Account verification.