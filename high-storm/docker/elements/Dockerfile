FROM blockstream/elementsd:23.3.4@sha256:f3b4037de5e8378af5cb9ccf8bdba88e2437d330d6cf3638fe666420ba70a9f8

RUN apt-get update \
	&& apt-get install --yes --no-install-recommends python3 \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd --create-home --uid 10001 elements \
	&& mkdir --parents /home/elements/.elements \
	&& chown elements:elements /home/elements/.elements

USER elements
ENTRYPOINT ["elementsd"]