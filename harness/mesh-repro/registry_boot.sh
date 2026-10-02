#!/bin/sh
# registry_boot.sh — the SECOND registry node in the `manifest` topology.
#
# A node conferred the registry slice holds build manifests, which are commons
# blobs, and edge's store gate pulls a commons blob only from a holder on a
# roster (CIRISEdge#581, axis 1). In production that roster is the canonical
# servers baked into the genesis seed, so it is in the directory before the
# node boots. Here the first registry mints a fresh key on every run, so its id
# is not knowable until it is up — and edge v38's puller takes the roster by
# value when it is spawned.
#
# So this script does what an operator handed a roster would do: ask the first
# registry who it is, and name it in CIRIS_BLOB_COMMONS_HOLDERS before the
# server starts. Everything after that is node_boot.sh.
set -eu

PEER="${CIRIS_REGISTRY_PEER_RECORD:?registry_boot.sh needs CIRIS_REGISTRY_PEER_RECORD}"
holder=""
for _ in $(seq 1 60); do
  holder="$(python -c '
import json, sys, urllib.request
try:
    print(json.load(urllib.request.urlopen(sys.argv[1], timeout=5))["record"]["key_id"])
except Exception:
    pass' "$PEER" 2>/dev/null || true)"
  [ -n "$holder" ] && break
  sleep 2
done
if [ -n "$holder" ]; then
  echo "[registry_boot] commons holder roster: $holder"
  export CIRIS_BLOB_COMMONS_HOLDERS="$holder"
else
  # NOT fatal, for node_boot.sh's reason: the ladder names the rung this breaks.
  echo "[registry_boot] WARN: the peer registry never answered at $PEER — this node will hold no commons blob"
fi
exec sh /opt/harness/node_boot.sh
