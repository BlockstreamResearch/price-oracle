# Storm Operator

React operator console for `high-storm`. The app provides network status, peer visibility, queued Droplets exchanges, voting creation and approval, and operator session settings.

## Development

Bun is required.

```sh
bun install
bun run dev
```

Vite proxies `/operators/*` to Compose node 1 at `http://127.0.0.1:9100`. Set `OPERATOR_API_TARGET` to use another high-storm external API address.

```sh
OPERATOR_API_TARGET=http://127.0.0.1:9100 bun run dev
```

## Validation

```sh
bun run lint
bun run build
```

## Humid authentication

Install and unlock Humid before connecting. The dashboard requests access to `getWalletDescriptor` and `signMessage`, derives the fixed external `/0/0` operator identity from the approved public descriptor, and asks Humid to approve every login and write signature. Private key material never enters the dashboard.

The bearer token, expiry, compressed public key, signing address, account identifier, and chain ID are stored in tab-scoped session storage so authenticated reads survive a refresh. Logout revokes the Humid session and clears that public metadata.

### Write approval details

Every write signature uses `high-storm:operator-write:v3` and includes labeled
signature scheme, HTTP method, API path, Unix timestamp, nonce, payload SHA-256,
and the complete request payload as indented JSON. Addresses, amounts, member
keys, transaction IDs, output indices, and split counts are not shortened.
Amounts use the API's integer units without conversion. Login challenges are
unchanged.

Voting approval and execution send the full proposal as their signed payload,
not an empty object. The server verifies that the signed proposal matches its
stored request before approving or executing it. Both BIP322 and Humid ECDSA
write signatures use the new format; old hash-only signatures are rejected.
Deploy the console and backend together, and update other write clients to the
same format and proposal payloads.

These readable prompts do not secure delivery of the console itself. Deploy
behind HTTPS with appropriate CSP and anti-framing headers; a compromised page
can still request malicious actions, so review the wallet's signed text.

Liquid mainnet and testnet use Humid's built-in chains. Elements regtest uses the custom chain remembered in local storage. The default Esplora backend is `http://127.0.0.1:3001`, matching the local Compose stack; override it for another backend:

```sh
VITE_HUMID_REGTEST_BACKEND_URL=http://127.0.0.1:3001 bun run dev
```
