FROM rust:1.97.1-bookworm AS builder

ENV PATH="/root/.simplex/bin:${PATH}"

WORKDIR /workspace
RUN apt-get update \
	&& apt-get install --yes --no-install-recommends jq \
	&& rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY contracts ./contracts
COPY high-storm ./high-storm
COPY storm ./storm
COPY storm-operator ./storm-operator
COPY storm-tree ./storm-tree
RUN curl -L https://smplx.simplicity-lang.org | bash \
	&& sed --in-place \
		--expression '/say "Successfully compiled simplex from commit:/a\    BINS=("${SMPLX_BIN_NAME}")\n    use' \
		--expression 's|ensure git clone --revision="${commit}" --depth=1 "${repo_url}" "${tmp_dir}"|ensure git init "${tmp_dir}" \&\& ensure git -C "${tmp_dir}" fetch --depth=1 "${repo_url}" "${commit}" \&\& ensure git -C "${tmp_dir}" checkout --detach FETCH_HEAD|' \
		/root/.simplex/bin/simplexup \
	&& simplexup -C 53087018cd1a8e12c710a44bafc5e32c077edc5a \
	&& cd contracts \
	&& simplex install \
	&& simplex build
RUN cargo build --locked --release --package high-storm --package storm-operator

FROM debian:bookworm-slim AS runtime

RUN useradd --create-home --uid 10001 high-storm
COPY --from=builder /workspace/target/release/high-storm /usr/local/bin/high-storm
COPY --from=builder /workspace/target/release/storm-operator /usr/local/bin/storm-operator

USER high-storm
ENTRYPOINT ["high-storm"]