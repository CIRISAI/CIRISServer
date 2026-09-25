#!/usr/bin/env bash
# One container: node, display, UI — started in that order, each waited for
# rather than slept past.
set -euo pipefail

HOME_DIR="${CIRIS_HOME:-/var/lib/ciris}"
KEY_ID="${CIRIS_KEY_ID:-node}"
ROLE="${UI_ROLE:-node}"          # node | canonical
mkdir -p "$HOME_DIR"

log() { printf '[entrypoint %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

log "role=$ROLE key_id=$KEY_ID home=$HOME_DIR"

# ── 0. the dial set ──────────────────────────────────────────────────────────
# THE CANONICAL HAS TO BE INJECTED. A node's federation directory starts with
# the baked accord holders and nothing else — `/v1/accord/canonical/servers`
# answers `{"servers":[]}` — so nothing advertises, nothing discovers, and every
# later stage fails somewhere far away from the cause: `authorFederationConsent`
# reports "no canonical server in {servers:[]}", and adding a contact refuses
# `contacts.unknown_fed_id` because the peer's key was never admitted.
#
# `net.bootstrap_peers` is boot-STRUCTURAL: a signed config:* CEG object read
# once, before the edge is built. Setting it over HTTP after boot would not be
# read until the next restart, so it is set here — the same two-boot pattern
# mesh-repro's node_boot.sh uses. `config set` opens the engine, mints the
# keystore, writes the row and exits; the server then boots on that home.
if [ -n "${CIRIS_NODE_BOOTSTRAP_PEERS:-}" ]; then
  log "config set net.bootstrap_peers ${CIRIS_NODE_BOOTSTRAP_PEERS}"
  if ciris-server config set net.bootstrap_peers "$CIRIS_NODE_BOOTSTRAP_PEERS" \
       --home "$HOME_DIR" --key-id "$KEY_ID" \
       --reason "ui-chat harness: inject the synthetic canonical" 2>&1 | sed 's/^/  /'; then
    log "dial set written"
  else
    # Not fatal: a node with no dial set still boots and still answers HTTP. The
    # drive stages report the consequence, which is more useful than a container
    # that dies here and reads as "the stack failed to come up".
    log "WARN: config set failed — this node will not find the canonical"
  fi
else
  log "no CIRIS_NODE_BOOTSTRAP_PEERS (expected for the canonical itself)"
fi

# ── 1. the node ──────────────────────────────────────────────────────────────
log "starting ciris-server"
ciris-server --home "$HOME_DIR" --key-id "$KEY_ID" > /var/log/node.log 2>&1 &
NODE_PID=$!

# Wait for the READ API, not for the process: a node that exits at second 3
# leaves a pid that was briefly real, and every later step then fails against a
# dead port with an error that names the wrong thing.
for i in $(seq 1 120); do
  if curl -sf --max-time 2 http://127.0.0.1:4243/v1/health >/dev/null 2>&1; then
    log "node healthy after ${i}s"; break
  fi
  if ! kill -0 "$NODE_PID" 2>/dev/null; then
    log "FATAL: node exited during boot. Last lines:" >&2
    tail -25 /var/log/node.log >&2
    exit 1
  fi
  sleep 1
done

# The canonical is the dial target and trust anchor only — it is not a party to
# the chat, so it runs no UI. Keeping it UI-less also keeps the evidence honest:
# a transcript can only come from a node someone actually drove.
if [ "$ROLE" = "canonical" ]; then
  log "canonical: no UI, holding the node in foreground"
  log "canonical servers it will advertise:"
  curl -sf --max-time 4 http://127.0.0.1:4243/v1/accord/canonical/servers 2>/dev/null | head -c 300 | sed 's/^/  /'; echo
  wait "$NODE_PID"
fi

# ── 2. the display ───────────────────────────────────────────────────────────
# Clear a stale lock first. `docker compose restart` keeps the container's
# filesystem, so /tmp/.X99-lock survives from the previous run and Xvfb refuses
# the display — the entrypoint then dies "FATAL: no display" on the SECOND boot
# only, which reads like a flake and is a leftover file.
rm -f /tmp/.X99-lock /tmp/.X11-unix/X99 2>/dev/null || true
Xvfb :99 -screen 0 1600x1200x24 -nolisten tcp > /var/log/xvfb.log 2>&1 &
for i in $(seq 1 30); do
  if xdpyinfo -display :99 >/dev/null 2>&1; then
    log "display :99 up after ${i}s"; break
  fi
  sleep 1
done
xdpyinfo -display :99 >/dev/null 2>&1 || { log "FATAL: no display"; exit 1; }

# ── 3. the UI ────────────────────────────────────────────────────────────────
# CIRIS_NODE_URL is set to the default on purpose: it must agree with
# LOCAL_NODE_URL, and in this netns both are this container's own node.
# Expose the loopback-bound automation server on a routable address so a
# published port can reach it. 9092 is the outside face of 9091.
socat TCP-LISTEN:9092,fork,reuseaddr TCP:127.0.0.1:9091 > /var/log/socat.log 2>&1 &
log "socat 0.0.0.0:9092 -> 127.0.0.1:9091"

JAR=$(ls /opt/ui/*.jar | head -1)
log "node sees canonical servers:"
curl -sf --max-time 4 http://127.0.0.1:4243/v1/accord/canonical/servers 2>/dev/null | head -c 300 | sed 's/^/  /'; echo
log "launching UI: $JAR"
exec java -jar "$JAR"
