FROM debian:bookworm-slim AS builder

ARG ELEMENTS_TAG=elements-29.4.1rc1
ARG ELEMENTS_COMMIT=a4d4c96ac7a7a9171b6f777e287ee4df18d779e1
ARG ELEMENTS_SHA256=da32434a6c142c390c23790820b2383ea08c43cc72d8adcd77a0c91fbb40788d

RUN apt-get update \
	&& apt-get install --yes --no-install-recommends \
		build-essential \
		ca-certificates \
		cmake \
		curl \
		libboost-dev \
		libevent-dev \
		libsqlite3-dev \
		pkgconf \
		python3 \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /src/elements
RUN curl --fail --location --output /tmp/elements.tar.gz \
		https://github.com/ElementsProject/elements/archive/refs/tags/${ELEMENTS_TAG}.tar.gz \
	&& echo "${ELEMENTS_SHA256}  /tmp/elements.tar.gz" | sha256sum --check \
	&& tar --extract --gzip --file /tmp/elements.tar.gz --strip-components=1 \
	&& rm /tmp/elements.tar.gz

RUN cmake -B build \
		-DCMAKE_BUILD_TYPE=Release \
		-DBUILD_BENCH=OFF \
		-DBUILD_TESTS=OFF \
		-DBUILD_TX=OFF \
		-DBUILD_UTIL=OFF \
		-DBUILD_WALLET_TOOL=OFF \
		-DENABLE_EXTERNAL_SIGNER=OFF \
		-DINSTALL_MAN=OFF \
	&& cmake --build build --parallel "$(nproc)" --target elementsd elements-cli

FROM debian:bookworm-slim AS runtime

ARG ELEMENTS_TAG=elements-29.4.1rc1
ARG ELEMENTS_COMMIT=a4d4c96ac7a7a9171b6f777e287ee4df18d779e1

LABEL org.opencontainers.image.source="https://github.com/ElementsProject/elements" \
	org.opencontainers.image.version="${ELEMENTS_TAG}" \
	org.opencontainers.image.revision="${ELEMENTS_COMMIT}"

RUN apt-get update \
	&& apt-get install --yes --no-install-recommends \
		ca-certificates \
		libevent-2.1-7 \
		libevent-extra-2.1-7 \
		libevent-pthreads-2.1-7 \
		libsqlite3-0 \
		python3 \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd --create-home --uid 10001 elements \
	&& mkdir --parents /home/elements/.elements \
	&& chown elements:elements /home/elements/.elements

COPY --from=builder /src/elements/build/bin/elements-cli /usr/local/bin/elements-cli
COPY --from=builder /src/elements/build/bin/elementsd /usr/local/bin/elementsd

USER elements
ENTRYPOINT ["elementsd"]