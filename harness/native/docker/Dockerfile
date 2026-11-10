# One harness node per container (HARNESS_DOCKER=1): the host-built ciris-server
# is bind-mounted, so this image carries only its shared libraries and iproute2
# (tc/netem for the A/V impairment runs, CIRISServer 0.5.246 A/V gate).
FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3 libsqlite3-0 iproute2 socat ca-certificates \
 && rm -rf /var/lib/apt/lists/*
