#!/usr/bin/env bash
# mesh-repro CONFIGURED-HOME variant (CIRISServer#264 ask 3) — the class the
# fresh-node SUCCESS verdict structurally cannot catch: a node that boots fine
# on a FRESH home but dies/hangs on a CONFIGURED one (populated persist DB,
# existing identity) or on an in-process/container restart. #264's fold hang was
# exactly this shape: fresh = 10s bind, configured = silent never-bind.
#
#   Phase 1: boot the mesh on PERSISTENT homes (named volumes, not tmpfs) →
#            wait for the canonical to be healthy + the agent to admit/root
#            (this CONFIGURES both homes: keys, genesis, directory rows).
#   Phase 2: RESTART both containers on the SAME homes → assert the canonical
#            binds 4243 again within the window and the agent seeds delivery
#            again — a configured-home boot, end to end.
#
#   ./run_configured.sh            # default 240s per-phase window
#   KEEP=1 ./run_configured.sh     # leave the stack up afterwards
set -euo pipefail
cd "$(dirname "$0")"

PROJECT="ciris-mesh-repro-cfg"
WINDOW="${1:-240}"

compose() { docker compose -p "$PROJECT" -f docker-compose.yml -f docker-compose.configured.yml "$@"; }

cleanup() {
  if [ "${KEEP:-0}" = "1" ]; then
    echo "── KEEP=1: stack left up (docker compose -p $PROJECT down -v to drop)"
  else
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_healthy() {
  local phase="$1" deadline="$2" waited=0
  while [ "$waited" -lt "$deadline" ]; do
    state=$(compose ps canonical --format '{{.Health}}' 2>/dev/null || echo "")
    [ "$state" = "healthy" ] && { echo "── [$phase] canonical healthy at ${waited}s"; return 0; }
    running=$(compose ps canonical --format '{{.State}}' 2>/dev/null || echo "")
    [ "$running" != "running" ] && [ -n "$running" ] && { echo "── [$phase] canonical state=$running (died)"; return 1; }
    sleep 5; waited=$((waited + 5))
  done
  echo "── [$phase] canonical NOT healthy in ${deadline}s"; return 1
}

wait_agent_seeded() {
  local phase="$1" deadline="$2" waited=0
  while [ "$waited" -lt "$deadline" ]; do
    if compose logs --since 90s agent 2>/dev/null | grep -qE "federation delivery started: [1-9]|KEX-GATE.*PRESENT"; then
      echo "── [$phase] agent seeded delivery"; return 0
    fi
    if compose logs --since 90s agent 2>/dev/null | grep -q "FATAL"; then
      echo "── [$phase] agent FATAL"; compose logs --tail 5 agent; return 1
    fi
    sleep 5; waited=$((waited + 5))
  done
  echo "── [$phase] agent did not seed in ${deadline}s"; return 1
}

echo "── mesh-repro CONFIGURED-home variant (#264) ─────────────────────────────"
compose down -v --remove-orphans >/dev/null 2>&1 || true
compose build >/dev/null
compose up -d >/dev/null

wait_healthy  "phase1-fresh" "$WINDOW" || { echo "VERDICT: FRESH-BOOT-FAILED (not the #264 class)"; exit 3; }
wait_agent_seeded "phase1-fresh" "$WINDOW" || { echo "VERDICT: FRESH-SEED-FAILED"; exit 3; }

echo "── homes are now CONFIGURED. Restarting both containers on the SAME homes ──"
compose restart canonical agent >/dev/null

if ! wait_healthy "phase2-configured" "$WINDOW"; then
  echo "VERDICT: CONFIGURED-HOME-REPRO — the node binds on a fresh home but NOT on a"
  echo "configured one (#264 class). Canonical tail:"
  compose logs --tail 15 canonical | sed 's/^/  /'
  exit 2
fi
if ! wait_agent_seeded "phase2-configured" "$WINDOW"; then
  echo "VERDICT: CONFIGURED-AGENT-REPRO — canonical rebinds but the agent's configured"
  echo "re-boot fails (#264 class, agent side)."
  exit 2
fi

echo "VERDICT: SUCCESS — configured-home restart binds + re-seeds on both roles."
exit 0
