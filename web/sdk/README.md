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

`createTickSpendPlan` validates the cross-covenant layout required when a
prediction position consumes a signature-authorized Tick. Program and witness
assembly remains in Rust/Simplex because reproducing consensus-critical
Simplicity compilation in browser JavaScript is unsafe.