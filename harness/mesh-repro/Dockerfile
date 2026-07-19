# mesh-repro harness image — one image, two roles (canonical + agent).
#
# TEST-ANCHOR build: installs the locally-built `test-anchor` wheel from
# `wheels/` (produced by `build_wheel.sh` → cargo build + pack_wheel.py). That
# wheel carries the SW single-key trust root so a fresh local mesh roots with NO
# operator YubiKeys (CIRISServer#258). The `test-anchor` feature is NEVER in the
# published prod wheel — the feature's absence is the wall. The agent role adds a
# boot shim driving the same federation-delivery path CIRISAgent's embedded edge
# uses; the canonical role uses the `ciris-server` console script directly.
FROM python:3.12-slim

# The wheel is built on the host (build_wheel.sh) and dropped into wheels/. Its
# abi3 .so needs glibc >= 2.39 — python:3.12-slim (trixie) satisfies this.
COPY wheels/ /opt/harness/wheels/
RUN pip install --no-cache-dir /opt/harness/wheels/ciris_server-*.whl

# iptables — the NAT-sim (CIRIS_HARNESS_NAT_ONLY / NAT353) needs it to DROP new
# inbound and make the agent an initiator-only peer. The slim base lacks it, so
# for a long time the NAT-sim silently degraded to collision-only ("iptables:
# No such file"); the scenario claimed to test NAT while it wasn't. Install it
# so NAT actually engages, and (agent_boot) hard-fail if it's still missing.
RUN apt-get update && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

# iproute2 — `tc netem` for the lossy-link sim (CIRIS_HARNESS_NETEM_*): the
# field failure is on a real NAT'd mobile link with packet loss + latency,
# which a zero-loss Docker bridge structurally cannot express. netem injects
# loss/delay/jitter so the reverse-path IdentityOccurrence round can be pushed
# to the same failure the field sees. Same noisy contract: agent_boot hard-fails
# if tc is missing when a netem run is requested.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Match a stable uid so bind/named volumes are writable.
RUN useradd --uid 1000 --create-home --shell /bin/bash ciris
# Pre-create the home with ciris ownership: a FRESH NAMED VOLUME copies the
# image dir's ownership on first mount (the configured-home variant uses named
# volumes; without this the volume is root-owned and the uid-1000 node dies on
# `create /var/lib/ciris/data`). tmpfs mounts never hit this (world-writable).
RUN mkdir -p /var/lib/ciris && chown 1000:1000 /var/lib/ciris

# The agent boot shim (reproduces CIRISAgent's Engine + init_edge_runtime +
# start_federation_delivery — see agent_boot.py). The canonical role ignores it
# and uses the `ciris-server` console script directly (set in compose).
COPY agent_boot.py /opt/harness/agent_boot.py

USER 1000:1000
WORKDIR /home/ciris
# No ENTRYPOINT: compose sets each role's command explicitly so one image serves
# both the canonical (`ciris-server …`) and the agent (`python agent_boot.py`).
