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
const account = await oracle.getAccount(publicKey);

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

`getAccount(xOnlyPublicKey, walletScript)` derives the corresponding
script-authorized Tick script. The optional wallet-script argument leaves
existing signature-authorized clients unchanged. The ECDSA header declares
`bitcoin-signed-message-ecdsa-v1` and carries both the compressed signing key
and its x-only account key. Its canonical message binds both keys, fee
outpoints, and complete request kinds/payloads.

`createTickSpendPlan` validates the cross-covenant layout required when a
prediction position consumes a Tick. Program and witness
assembly remains in Rust/Simplex because reproducing consensus-critical
Simplicity compilation in browser JavaScript is unsafe.