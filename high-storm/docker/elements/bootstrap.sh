#!/usr/bin/env bash

set -Eeuo pipefail

rpc_user="${ELEMENTS_RPC_USER:-high-storm}"
rpc_password="${ELEMENTS_RPC_PASSWORD:-high-storm}"
rpc_host="${ELEMENTS_RPC_HOST:-elements-1}"
rpc_port="${ELEMENTS_RPC_PORT:-18884}"
block_interval="${BLOCK_INTERVAL_SECONDS:-60}"
private_key_file="${FUNDED_PRIVATE_KEY_FILE:-/docker/funded-private-key.txt}"
rpc_args=(
	-chain=elementsregtest
	-rpcconnect="${rpc_host}"
	-rpcport="${rpc_port}"
	-rpcuser="${rpc_user}"
	-rpcpassword="${rpc_password}"
)

rpc() {
	elements-cli "${rpc_args[@]}" "$@"
}

wallet_rpc() {
	local wallet="$1"
	shift
	elements-cli "${rpc_args[@]}" -rpcwallet="${wallet}" "$@"
}

ensure_wallet() {
	local wallet="$1"
	local blank="$2"
	if wallet_rpc "${wallet}" getwalletinfo >/dev/null 2>&1; then
		return
	fi
	if ! rpc createwallet "${wallet}" false "${blank}" "" false true true >/dev/null 2>&1; then
		rpc loadwallet "${wallet}" true >/dev/null 2>&1 || true
	fi
	wallet_rpc "${wallet}" getwalletinfo >/dev/null
}

until rpc getblockchaininfo >/dev/null 2>&1; do
	sleep 1
done

ensure_wallet bootstrap false
ensure_wallet funded-key true
wallet_rpc bootstrap rescanblockchain >/dev/null

if [[ -n "${FUNDED_PRIVATE_KEY:-}" ]]; then
	private_key="${FUNDED_PRIVATE_KEY}"
else
	private_key="$(tr -d '[:space:]' < "${private_key_file}")"
fi
if [[ ! "${private_key}" =~ ^[[:xdigit:]]{64}$ ]]; then
	echo "FUNDED_PRIVATE_KEY or ${private_key_file} must provide one 32-byte hexadecimal private key." >&2
	exit 1
fi

wif="$(python3 - "${private_key}" <<'PY'
import hashlib
import sys

alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
payload = bytes([239]) + bytes.fromhex(sys.argv[1]) + b"\x01"
encoded = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
number = int.from_bytes(encoded, "big")
result = ""
while number:
    number, remainder = divmod(number, 58)
    result = alphabet[remainder] + result
padding = len(encoded) - len(encoded.lstrip(b"\0"))
print(alphabet[0] * padding + result)
PY
)"
descriptor_checksum="$(rpc getdescriptorinfo "wpkh(${wif})" | python3 -c 'import json, sys; print(json.load(sys.stdin)["checksum"])')"
descriptor="wpkh(${wif})#${descriptor_checksum}"
funded_address="$(rpc deriveaddresses "${descriptor}" | python3 -c 'import json, sys; print(json.load(sys.stdin)[0])')"
is_mine="$(wallet_rpc funded-key getaddressinfo "${funded_address}" | python3 -c 'import json, sys; print(str(json.load(sys.stdin).get("ismine", False)).lower())')"
if [[ "${is_mine}" != "true" ]]; then
	wallet_rpc funded-key importdescriptors \
		"[{\"desc\":\"${descriptor}\",\"timestamp\":\"now\"}]" \
		| python3 -c 'import json, sys; result = json.load(sys.stdin)[0]; assert result["success"], result'
fi

received="$(wallet_rpc funded-key getreceivedbyaddress "${funded_address}" 0 | python3 -c 'import json, sys; print(json.load(sys.stdin).get("bitcoin", 0))')"
case "$(python3 - "${received}" <<'PY'
from decimal import Decimal
import sys

amount = Decimal(sys.argv[1])
print("empty" if amount == 0 else "funded" if amount > 0 else "unexpected")
PY
)" in
	empty)
		wallet_rpc bootstrap sendtoaddress "${funded_address}" 50 >/dev/null
		;;
	funded)
		;;
	*)
		echo "Expected funded key to have received a non-negative LBTC amount, found ${received}." >&2
		exit 1
		;;
esac

echo "Funded development address: ${funded_address}"
touch /tmp/bootstrap-ready
while true; do
	mining_address="$(wallet_rpc bootstrap getnewaddress "" bech32)"
	rpc generatetoaddress 1 "${mining_address}" >/dev/null
	sleep "${block_interval}"
done