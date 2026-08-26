FROM rust:1.97.1-bookworm AS builder

WORKDIR /workspace
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY high-storm ./high-storm
COPY storm ./storm
COPY storm-operator ./storm-operator
COPY storm-tree ./storm-tree
RUN cargo build --locked --release --package high-storm --package storm-operator

FROM debian:bookworm-slim AS runtime

RUN useradd --create-home --uid 10001 high-storm
COPY --from=builder /workspace/target/release/high-storm /usr/local/bin/high-storm
COPY --from=builder /workspace/target/release/storm-operator /usr/local/bin/storm-operator

USER high-storm
ENTRYPOINT ["high-storm"]