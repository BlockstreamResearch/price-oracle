FROM rust:1.97.1-bookworm AS builder

ARG SIMPLEX_COMMIT=299c1e61add3d7b62466399d17eace06005b917b

WORKDIR /workspace
RUN apt-get update \
	&& apt-get install --yes --no-install-recommends jq \
	&& rm -rf /var/lib/apt/lists/*
RUN cargo install --locked \
	--git https://github.com/BlockstreamResearch/smplx.git \
	--rev "${SIMPLEX_COMMIT}" \
	smplx-cli
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY contracts ./contracts
COPY high-storm ./high-storm
COPY price-feed ./price-feed
COPY storm ./storm
COPY storm-operator ./storm-operator
COPY storm-tree ./storm-tree
RUN cd contracts \
	&& simplex install \
	&& simplex build

ARG HIGH_STORM_GIT_SHA=unknown
RUN cargo build --locked --release --package high-storm --package storm-operator

FROM debian:bookworm-slim AS runtime

RUN useradd --create-home --uid 10001 high-storm
COPY --from=builder /workspace/target/release/high-storm /usr/local/bin/high-storm
COPY --from=builder /workspace/target/release/storm-operator /usr/local/bin/storm-operator

USER high-storm
ENTRYPOINT ["high-storm"]