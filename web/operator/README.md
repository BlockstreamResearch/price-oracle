# Storm Operator

React operator console for `high-storm`. The app provides network status, peer visibility, voting creation and approval, and operator session settings.

## Development

Bun is required.

```sh
bun install
bun run dev
```

Vite proxies `/operators/*` to Compose node 1 at `http://127.0.0.1:9100`. Set `OPERATOR_API_TARGET` to use another high-storm REST address.

```sh
OPERATOR_API_TARGET=http://127.0.0.1:9100 bun run dev
```

## Validation

```sh
bun run lint
bun run build
```

## Key handling

The login form accepts a 32-byte secp256k1 secret key as hexadecimal text. The browser derives the compressed public key and signs BIP322 messages locally. Secret key material remains only in application memory and is cleared on logout or page exit. The bearer token, expiry, public key, and address are stored in tab-scoped session storage so read access survives a refresh; logout, tab closure, or token expiry clears that session. Signed actions after a hard refresh require re-authentication because the secret key is never persisted.
