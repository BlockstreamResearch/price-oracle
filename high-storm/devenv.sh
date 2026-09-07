#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
compose_file="${script_dir}/compose.yml"
network_state_file="${script_dir}/.devenv-network.env"

project_name="${COMPOSE_PROJECT_NAME:-high-storm-local}"
network_name="${STORM_NETWORK_NAME:-${project_name}_storm}"
STORM_NETWORK_NAME="${network_name}"
export STORM_NETWORK_NAME

existing_subnets() {
    local network

    while IFS= read -r network; do
        docker network inspect "${network}" \
            --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}'
    done < <(docker network ls --quiet)
}

select_free_network_prefix() {
    existing_subnets | python3 -c '
import ipaddress
import sys

used = []
for value in sys.stdin:
    try:
        used.append(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        pass

for second_octet in range(20, 32):
    for third_octet in range(256):
        candidate = ipaddress.ip_network(f"172.{second_octet}.{third_octet}.0/24")
        if not any(candidate.overlaps(network) for network in used):
            print(str(candidate.network_address).removesuffix(".0"))
            raise SystemExit

raise SystemExit("No free Docker /24 subnet was found in 172.20.0.0/12.")
'
}

read_saved_network_value() {
    local key value

    [[ -f "${network_state_file}" ]] || return 0
    while IFS='=' read -r key value; do
        if [[ "${key}" == "$1" ]]; then
            printf '%s' "${value}"
            return 0
        fi
    done < "${network_state_file}"
}

network_prefix_from_subnet() {
    python3 -c '
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1], strict=True)
if network.version != 4 or network.prefixlen != 24:
    raise SystemExit(f"Expected an IPv4 /24 network, got {network}.")
print(str(network.network_address).removesuffix(".0"))
' "$1"
}

ensure_storm_network() {
    local configured_prefix existing_subnet saved_network_name selected_prefix

    configured_prefix="${STORM_NETWORK_PREFIX:-}"
    saved_network_name="$(read_saved_network_value STORM_NETWORK_NAME)"
    if [[ -z "${configured_prefix}" && "${saved_network_name}" == "${network_name}" ]]; then
        configured_prefix="$(read_saved_network_value STORM_NETWORK_PREFIX)"
    fi
    if docker network inspect "${network_name}" >/dev/null 2>&1; then
        existing_subnet="$(docker network inspect "${network_name}" \
            --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' \
            | head -n 1)"
        selected_prefix="$(network_prefix_from_subnet "${existing_subnet}")"
    else
        selected_prefix="${configured_prefix:-$(select_free_network_prefix)}"
        docker network create \
            --driver bridge \
            --subnet "${selected_prefix}.0/24" \
            "${network_name}" >/dev/null
        echo "Created Docker network ${network_name} on ${selected_prefix}.0/24."
    fi

    STORM_NETWORK_NAME="${network_name}"
    STORM_NETWORK_PREFIX="${selected_prefix}"
    export STORM_NETWORK_NAME STORM_NETWORK_PREFIX
    printf 'STORM_NETWORK_NAME=%s\nSTORM_NETWORK_PREFIX=%s\n' \
        "${network_name}" "${selected_prefix}" > "${network_state_file}"
}

compose() {
    docker compose -f "${compose_file}" "$@"
}

require_docker() {
    if ! docker info >/dev/null 2>&1; then
        echo "Docker daemon is not available." >&2
        exit 1
    fi
}

usage() {
    cat <<EOF
Usage: $(basename "$0") {create|up|rebuild|down|connections NODE|top-up-droplets NODE AMOUNT|elements NODE [RPC ARGUMENTS...]}

    create             Delete the deployment and data, rebuild, and start fresh.
    up                 Start the deployment while preserving existing data.
    rebuild            Rebuild application images and restart while preserving data.
    down               Stop and remove the deployment while preserving existing data.
    connections NODE   List active Storm connections for node 1, 2, or 3.
    top-up-droplets NODE AMOUNT
                       Deposit AMOUNT LBTC to Treasury and credit all Droplets to NODE.
    elements NODE ...  Call Elements RPC on node 1, 2, or 3. Defaults to getblockchaininfo.
EOF
}

require_docker

case "${1:-}" in
    create)
        ensure_storm_network
        compose down --volumes --remove-orphans
        compose up --detach --build --force-recreate
        ;;
    up)
        ensure_storm_network
        compose up --detach
        ;;
    rebuild)
        ensure_storm_network
        compose up --detach --build --force-recreate \
            elements-1 elements-2 elements-3 elements-bootstrap \
            node-1 node-2 node-3 operator-1 operator-2 operator-3
        ;;
    down)
        compose down --remove-orphans
        ;;
    connections)
        case "${2:-}" in
            1|2|3)
                database="high-storm-node-${2}"
                ;;
            *)
                echo "NODE must be 1, 2, or 3." >&2
                exit 2
                ;;
        esac
        if [[ "$(compose ps --status running --services "node-${2}")" != "node-${2}" ]]; then
            echo "node-${2} is not running." >&2
            exit 1
        fi
        compose exec -T postgres psql \
            --username high-storm \
            --dbname "${database}" \
            --pset pager=off \
            --command "SELECT public_key AS peer_public_key, socket_address, to_timestamp(last_seen) AS last_heartbeat FROM network_peers WHERE status = 'active' AND last_seen >= EXTRACT(EPOCH FROM now())::BIGINT - 15 ORDER BY public_key"
        ;;
    top-up-droplets)
        case "${2:-}" in
            1|2|3)
                database="high-storm-node-${2}"
                ;;
            *)
                echo "NODE must be 1, 2, or 3." >&2
                exit 2
                ;;
        esac
        amount="${3:-}"
        amount_digits="${amount//./}"
        amount_digits="${amount_digits//0/}"
        if [[ ! "${amount}" =~ ^[0-9]+([.][0-9]{1,8})?$ ]] || \
            [[ "${amount}" =~ ^0[0-9] ]] || [[ -z "${amount_digits}" ]]; then
            echo "AMOUNT must be a positive LBTC amount with at most 8 decimals." >&2
            exit 2
        fi
        for service in postgres elements-1; do
            if [[ "$(compose ps --status running --services "${service}")" != "${service}" ]]; then
                echo "${service} is not running." >&2
                exit 1
            fi
        done

        compressed_key="$(compose exec -T postgres psql \
            --username high-storm \
            --dbname "${database}" \
            --tuples-only \
            --no-align \
            --command "SELECT public_key FROM network_peers WHERE status = 'controlled'")"
        treasury_script="$(compose exec -T postgres psql \
            --username high-storm \
            --dbname "${database}" \
            --tuples-only \
            --no-align \
            --command "SELECT encode(contract_script, 'hex') FROM network_assets WHERE kind = 'tick-asset'")"
        if [[ ! "${compressed_key}" =~ ^0[23][0-9a-fA-F]{64}$ ]] || [[ -z "${treasury_script}" ]]; then
            echo "node-${2} does not have initialized member or Treasury state." >&2
            exit 1
        fi
        xonly_key="${compressed_key:2}"
        member_marker="4f4401${xonly_key}"

        decoded_script="$(compose exec -T elements-1 elements-cli \
            -chain=elementsregtest \
            -rpcport=18884 \
            -rpcuser=high-storm \
            -rpcpassword=high-storm \
            decodescript "${treasury_script}")"
        treasury_address="$(python3 -c 'import json, sys; value = json.load(sys.stdin); print(value.get("address") or value.get("segwit", {}).get("address") or "")' <<<"${decoded_script}")"
        if [[ -z "${treasury_address}" ]]; then
            echo "Elements could not derive the Treasury address from its script." >&2
            exit 1
        fi

        outputs="[{\"${treasury_address}\":${amount}},{\"data\":\"${member_marker}\"}]"
        wallet_utxos="$(compose exec -T elements-1 elements-cli \
            -chain=elementsregtest -rpcport=18884 -rpcuser=high-storm -rpcpassword=high-storm \
            -rpcwallet=funded-key listunspent 1 9999999)"
        change_address="$(python3 -c 'import json, sys; utxos = json.load(sys.stdin); print(next((utxo["address"] for utxo in utxos if utxo.get("spendable")), ""))' <<<"${wallet_utxos}")"
        if [[ -z "${change_address}" ]]; then
            echo "funded-key has no confirmed spendable address for change." >&2
            exit 1
        fi
        raw="$(compose exec -T elements-1 elements-cli \
            -chain=elementsregtest -rpcport=18884 -rpcuser=high-storm -rpcpassword=high-storm \
            -rpcwallet=funded-key createrawtransaction '[]' "${outputs}")"
        funded="$(compose exec -T elements-1 elements-cli \
            -chain=elementsregtest -rpcport=18884 -rpcuser=high-storm -rpcpassword=high-storm \
            -rpcwallet=funded-key fundrawtransaction "${raw}" "{\"changeAddress\":\"${change_address}\"}")"
        funded_hex="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["hex"])' <<<"${funded}")"
        signed="$(compose exec -T elements-1 elements-cli \
            -chain=elementsregtest -rpcport=18884 -rpcuser=high-storm -rpcpassword=high-storm \
            -rpcwallet=funded-key signrawtransactionwithwallet "${funded_hex}")"
        signed_hex="$(python3 -c 'import json, sys; value = json.load(sys.stdin); assert value["complete"]; print(value["hex"])' <<<"${signed}")"
        txid="$(compose exec -T elements-1 elements-cli \
            -chain=elementsregtest -rpcport=18884 -rpcuser=high-storm -rpcpassword=high-storm \
            sendrawtransaction "${signed_hex}")"
        mining_address="$(compose exec -T elements-1 elements-cli \
            -chain=elementsregtest -rpcport=18884 -rpcuser=high-storm -rpcpassword=high-storm \
            -rpcwallet=bootstrap getnewaddress '' bech32)"
        compose exec -T elements-1 elements-cli \
            -chain=elementsregtest -rpcport=18884 -rpcuser=high-storm -rpcpassword=high-storm \
            generatetoaddress 1 "${mining_address}" >/dev/null

        echo "Deposited ${amount} LBTC for node-${2} (${xonly_key}) in ${txid}."
        ;;
    elements)
        case "${2:-}" in
            1|2|3)
                ;;
            *)
                echo "NODE must be 1, 2, or 3." >&2
                exit 2
                ;;
        esac
        if [[ "$(compose ps --status running --services "elements-${2}")" != "elements-${2}" ]]; then
            echo "elements-${2} is not running." >&2
            exit 1
        fi
        rpc_arguments=("${@:3}")
        if [[ ${#rpc_arguments[@]} -eq 0 ]]; then
            rpc_arguments=(getblockchaininfo)
        fi
        compose exec -T "elements-${2}" elements-cli \
            -chain=elementsregtest \
            -rpcport=18884 \
            -rpcuser=high-storm \
            -rpcpassword=high-storm \
            "${rpc_arguments[@]}"
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac