#!/usr/bin/env bash
# Builds dist/leaves.wasm, the leaf compiler `@price-oracle/sdk/leaves` loads.
#
# The build runs in a container: the compiler has C parts, and building those
# for WebAssembly takes a clang with that backend, which macOS does not ship.
# The contract sources are read from contracts/src/artifacts, so `simplex
# build` has to have run in contracts first.

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd -- "${script_dir}/../../.." && pwd)"
image="${LEAVES_BUILD_IMAGE:-rust:1.97.1-trixie}"

for contract in account voucher; do
    source="${repo_dir}/contracts/src/artifacts/simf/${contract}.simf"
    if [[ ! -f "${source}" ]]; then
        echo "${source} is missing: run 'simplex build' in contracts first" >&2
        exit 1
    fi
done

# The workspace lock decides the compiler version, so the module compiles
# with the one the nodes run.
cp "${repo_dir}/Cargo.lock" "${script_dir}/Cargo.lock"
mkdir -p "${script_dir}/target/registry"

docker run --rm \
    --volume "${repo_dir}:/src" \
    --volume "${script_dir}/target/registry:/usr/local/cargo/registry" \
    --workdir /src/web/sdk/leaves \
    "${image}" bash -euc '
        apt-get update -qq
        apt-get install --yes -qq --no-install-recommends clang llvm wasi-libc >/dev/null
        rustup target add wasm32-wasip1 >/dev/null
        export CC_wasm32_wasip1=clang AR_wasm32_wasip1=llvm-ar
        export CFLAGS_wasm32_wasip1="-isystem /usr/include/wasm32-wasi"
        cargo build --jobs "${LEAVES_BUILD_JOBS:-4}" --release --target wasm32-wasip1
    '

mkdir -p "${script_dir}/../dist"
cp "${script_dir}/target/wasm32-wasip1/release/price_oracle_leaves.wasm" \
    "${script_dir}/../dist/leaves.wasm"
ls -l "${script_dir}/../dist/leaves.wasm"
