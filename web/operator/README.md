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

Liquid mainnet and testnet use Humid's built-in chains. Elements regtest uses the custom chain remembered in local storage. The default Esplora backend is `http://127.0.0.1:3001`, matching the local Compose stack; override it for another backend:

```sh
VITE_HUMID_REGTEST_BACKEND_URL=http://127.0.0.1:3001 bun run dev
```
