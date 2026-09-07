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

## Key handling

The login form accepts a 32-byte secp256k1 secret key as hexadecimal text. The browser derives the compressed public key and signs BIP322 messages locally. The bearer token, expiry, identity, and secret key are stored in tab-scoped session storage so authenticated reads and signed actions survive a page refresh. Logout, tab closure, or token expiry clears the session. The secret key is never sent to HighStorm, but scripts running in the same browser origin can access it while the tab session exists.
