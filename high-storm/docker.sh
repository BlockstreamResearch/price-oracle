#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
compose_file="${script_dir}/compose.yml"

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
Usage: $(basename "$0") {create|up|rebuild|down|connections NODE}

  create  Delete the existing deployment and data, rebuild, and start fresh.
  up      Start the deployment while preserving existing data.
    rebuild Rebuild the Rust image and restart nodes while preserving data.
  down    Stop and remove the deployment while preserving existing data.
    connections NODE
                    List active connections for node 1, 2, or 3.
EOF
}

require_docker

case "${1:-}" in
    create)
        compose down --volumes --remove-orphans
        compose up --detach --build --force-recreate
        ;;
    up)
        compose up --detach
        ;;
    rebuild)
        compose up --detach --build --force-recreate node-1 node-2 node-3
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
    *)
        usage >&2
        exit 2
        ;;
esac