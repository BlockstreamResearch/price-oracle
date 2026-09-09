#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
compose_file="${script_dir}/compose.yml"
network_state_file="${script_dir}/.devenv-network.env"
extra_nodes_dir="${script_dir}/.devenv-nodes"

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

require_node_number() {
    if [[ ! "${1:-}" =~ ^[0-9]+$ ]] || (( $1 < 1 || $1 > 99 )); then
        echo "NODE must be an integer from 1 to 99." >&2
        exit 2
    fi
}

node_config_path() {
    local node="$1"

    if (( node <= 3 )); then
        printf '%s/docker/node-%s.toml' "${script_dir}" "${node}"
    else
        printf '%s/node-%s.toml' "${extra_nodes_dir}" "${node}"
    fi
}

private_key_from_config() {
    sed -n 's/^private_key = "\([0-9a-fA-F]*\)"$/\1/p' "$1"
}

public_key_from_private_key() {
    local encoded_der private_key public_key

    private_key="$1"
    if [[ ! "${private_key}" =~ ^[0-9a-fA-F]{64}$ ]]; then
        return 1
    fi
    encoded_der="$(
        printf '302e0201010420%sA00706052B8104000A' "${private_key}" \
            | xxd -r -p \
            | openssl ec -inform DER -conv_form compressed -pubout -outform DER 2>/dev/null \
            | xxd -p -c 1000
    )" || return 1
    public_key="${encoded_der:${#encoded_der}-66}"
    if [[ ! "${public_key}" =~ ^0[23][0-9a-fA-F]{64}$ ]]; then
        return 1
    fi

    printf '%s\n' "${public_key}" | tr '[:upper:]' '[:lower:]'
}

node_public_key() {
    local config_path private_key

    require_node_number "$1"
    config_path="$(node_config_path "$1")"
    if [[ ! -f "${config_path}" ]]; then
        echo "node-$1 is not configured; deploy it first." >&2
        exit 1
    fi
    private_key="$(private_key_from_config "${config_path}")"
    if ! public_key_from_private_key "${private_key}"; then
        echo "node-$1 has an invalid signer private key." >&2
        exit 1
    fi
}

remove_extra_node_containers() {
    local containers

    containers="$(docker ps --all --quiet \
        --filter "label=high-storm.devenv.project=${project_name}" \
        --filter "label=high-storm.devenv.role=extra-node")"
    if [[ -n "${containers}" ]]; then
        docker rm --force ${containers} >/dev/null
    fi
}

deploy_node() {
    local config_path container_name database database_exists image_name node
    local peer_port api_port address_suffix private_key public_key coordinator_public_key

    node="$1"
    require_node_number "${node}"
    if (( node <= 3 )); then
        echo "NODE must be 4 or greater; nodes 1, 2, and 3 are managed by Compose." >&2
        exit 2
    fi

    ensure_storm_network
    for service in postgres elements-1 node-1; do
        if [[ "$(compose ps --status running --services "${service}")" != "${service}" ]]; then
            echo "${service} is not running; start the base deployment first." >&2
            exit 1
        fi
    done

    config_path="$(node_config_path "${node}")"
    database="high-storm-node-${node}"
    database_exists="$(compose exec -T postgres psql \
        --username high-storm \
        --dbname postgres \
        --tuples-only \
        --no-align \
        --command "SELECT 1 FROM pg_database WHERE datname = '${database}'")"
    if [[ ! -f "${config_path}" && "${database_exists}" == "1" ]]; then
        echo "${database} exists but ${config_path} does not; refusing to replace its identity." >&2
        exit 1
    fi

    if [[ ! -f "${config_path}" ]]; then
        mkdir -p "${extra_nodes_dir}"
        chmod 700 "${extra_nodes_dir}"
        while :; do
            private_key="$(openssl rand -hex 32)"
            if public_key_from_private_key "${private_key}" >/dev/null; then
                break
            fi
        done
        cat > "${config_path}" <<EOF
[service]
port = 9000
external_api_address = "0.0.0.0:9100"

[service.signer]
private_key = "${private_key}"

[service.elements_rpc]
url = "http://elements-1:18884"
username = "high-storm"
password = "high-storm"
wallet = "funded-key"

[service.protocol]
operational_fee_sats = 1000
tick_burn_reserve_sats = 1000
issuance_transaction_fee_sats = 1000
burn_transaction_fee_sats = 500
exchange_transaction_fee_sats = 500
tick_lifetime_blocks = 60

[service.db]
url = "postgres:5432"
username = "high-storm"
password = "high-storm"
database = "${database}"
max_connections = 5
EOF
        chmod 600 "${config_path}"
    fi

    if [[ "${database_exists}" != "1" ]]; then
        compose exec -T postgres createdb \
            --username high-storm \
            --owner high-storm \
            "${database}"
    fi

    compose build node-1
    image_name="${project_name}-node-1:latest"
    public_key="$(node_public_key "${node}")"
    coordinator_public_key="$(node_public_key 1)"
    container_name="${project_name}-extra-node-${node}"
    peer_port="$((8999 + node))"
    api_port="$((9099 + node))"
    address_suffix="$((100 + node))"

    docker rm --force "${container_name}" >/dev/null 2>&1 || true
    docker run --detach \
        --name "${container_name}" \
        --user "$(id -u):$(id -g)" \
        --label "high-storm.devenv.project=${project_name}" \
        --label "high-storm.devenv.role=extra-node" \
        --network "${network_name}" \
        --ip "${STORM_NETWORK_PREFIX}.${address_suffix}" \
        --publish "${peer_port}:9000" \
        --publish "${api_port}:9100" \
        --volume "${config_path}:/etc/high-storm/config.toml:ro" \
        --env "OPERATOR_PUBLIC_KEY=${public_key}" \
        --env "RUST_LOG=${RUST_LOG:-info,high_storm=debug,storm=debug,sqlx=warn}" \
        --entrypoint /bin/sh \
        "${image_name}" \
        -c "(while [ ! -S /tmp/high-storm.sock ]; do sleep 1; done; until storm-operator operator add \"\${OPERATOR_PUBLIC_KEY}\"; do sleep 1; done) & high-storm run --config /etc/high-storm/config.toml || exec high-storm initialize join --config /etc/high-storm/config.toml --discovery-public-key ${coordinator_public_key} --discovery-address ${STORM_NETWORK_PREFIX}.11:9000" \
        >/dev/null

    echo "Deployed node-${node} at ${STORM_NETWORK_PREFIX}.${address_suffix}:9000 (host ports ${peer_port} and ${api_port})."
    echo "Public key: ${public_key}"
}

usage() {
    cat <<EOF
Usage: $(basename "$0") {create|up|rebuild|down|deploy-node NODE|public-key NODE|connections NODE|droplets NODE SATS|elements NODE [RPC ARGUMENTS...]}

    create             Delete the deployment and data, rebuild, and start fresh.
    up                 Start the deployment while preserving existing data.
    rebuild            Rebuild application images and restart while preserving data.
    down               Stop and remove the deployment while preserving existing data.
    deploy-node NODE   Deploy an initialized-or-waiting extra node (NODE >= 4).
    public-key NODE    Print a node's compressed secp256k1 public key.
    connections NODE   List active Storm connections for node 1, 2, or 3.
    droplets NODE SATS
                       Deposit SATS to Treasury and credit all Droplets to NODE.
    elements NODE ...  Call Elements RPC on node 1, 2, or 3. Defaults to getblockchaininfo.
EOF
}

require_docker

case "${1:-}" in
    create)
        ensure_storm_network
        remove_extra_node_containers
        rm -rf "${extra_nodes_dir}"
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
        remove_extra_node_containers
        compose down --remove-orphans
        ;;
    deploy-node)
        deploy_node "${2:-}"
        ;;
    public-key)
        node_public_key "${2:-}"
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
    droplets)
        case "${2:-}" in
            1|2|3)
                database="high-storm-node-${2}"
                ;;
            *)
                echo "NODE must be 1, 2, or 3." >&2
                exit 2
                ;;
        esac
        amount_sats="${3:-}"
        if [[ ! "${amount_sats}" =~ ^[1-9][0-9]*$ ]]; then
            echo "SATS must be a positive integer." >&2
            exit 2
        fi
        amount_lbtc="$(python3 -c 'import sys; sats = int(sys.argv[1]); print(f"{sats // 100_000_000}.{sats % 100_000_000:08d}")' "${amount_sats}")"
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

        outputs="[{\"${treasury_address}\":${amount_lbtc}},{\"data\":\"${member_marker}\"}]"
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
            -rpcwallet=funded-key fundrawtransaction "${raw}" \
            "{\"changeAddress\":\"${change_address}\",\"changePosition\":2}")"
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

        echo "Deposited ${amount_sats} sats for node-${2} (${xonly_key}) in ${txid}."
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