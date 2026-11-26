FROM rust:1.97.1-bookworm AS builder

ARG SIMPLEX_VERSION=0.3.0

WORKDIR /workspace
RUN apt-get update \
	&& apt-get install --yes --no-install-recommends jq \
	&& rm -rf /var/lib/apt/lists/*
# Simplex fetches a `tag` dependency with `git clone --revision`, which needs
# Git 2.49; Debian bookworm ships 2.39.
ARG GIT_VERSION=2.56.1
ARG GIT_SHA256=f0b0bf89264b9bd2e1c640363e7529643989da76281600473c50745cd34a607f
RUN curl -sSfL "https://mirrors.edge.kernel.org/pub/software/scm/git/git-${GIT_VERSION}.tar.xz" -o /tmp/git.tar.xz \
	&& echo "${GIT_SHA256}  /tmp/git.tar.xz" | sha256sum -c - \
	&& tar -xf /tmp/git.tar.xz -C /tmp \
	&& make -C "/tmp/git-${GIT_VERSION}" -j"$(nproc)" prefix=/usr/local \
		NO_TCLTK=1 NO_GETTEXT=1 NO_PERL=1 NO_PYTHON=1 install \
	&& rm -rf /tmp/git.tar.xz "/tmp/git-${GIT_VERSION}"
RUN cargo install --locked \
	--git https://github.com/BlockstreamResearch/smplx.git \
	--tag "v${SIMPLEX_VERSION}" \
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