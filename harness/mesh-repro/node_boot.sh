#!/bin/sh
# node_boot.sh — the NON-canonical `ciris-server` role for the chat topology.
#
# A canonical needs no bootstrap peers (it IS the dial target). Every other node
# does, and Server 0.5 takes zero env vars for it: `net.bootstrap_peers` is a
# signed `config:*` CEG object, read ONCE at boot (compose.rs, before the edge is
# built). So the dial set has to exist in the node's own graph BEFORE the server
# starts — which is exactly what the console-trusted `config set` CLI is for
# ("Lets a HEADLESS node set knobs (e.g. `net.bootstrap_peers`) that otherwise
# only the app/owner-session /v1/config surface could reach").
#
# Two boots on one home, deliberately: `config set` opens the engine, mints the
# keystore, writes the row and exits; `ciris-server` then boots on that same
# home. The alternative — set the peers over HTTP after boot — cannot work, because
# the value is boot-STRUCTURAL and would not be read until the next restart.
set -eu

HOME_DIR="${CIRIS_HOME:-/var/lib/ciris}"
KEY_ID="${CIRIS_NODE_KEY_ID:?node_boot.sh needs CIRIS_NODE_KEY_ID}"
PEERS="${CIRIS_NODE_BOOTSTRAP_PEERS:-}"

if [ -n "$PEERS" ]; then
  echo "[node_boot] config set net.bootstrap_peers ${PEERS} (home=${HOME_DIR} key-id=${KEY_ID})"
  # NOT fatal. A node with no dial set still boots and still answers HTTP; the
  # ladder's `peered` stage is what reports the consequence, and a boot that dies
  # here would report it as "the stack failed to come up" instead.
  ciris-server config set net.bootstrap_peers "$PEERS" \
    --home "$HOME_DIR" --key-id "$KEY_ID" --reason "mesh-harness chat topology" \
    || echo "[node_boot] WARN: config set net.bootstrap_peers FAILED — this node will dial nothing"
fi

echo "[node_boot] exec ciris-server --home ${HOME_DIR} --key-id ${KEY_ID}"
exec ciris-server --home "$HOME_DIR" --key-id "$KEY_ID"
