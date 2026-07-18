#!/usr/bin/env bash
# mesh-repro lifecycle — the state-ladder conformance gate.
#
# Drives the two-node test-anchor mesh through every lifecycle state reachable
# from our tier (L5+, see FSD/RNS_LIFECYCLE_STATES.md) and asserts each one's
# OBSERVABLE — one PASS/FAIL row per state, exit code = states missed. Born
# from the 2026-07 delivery saga: every one of these rows was, at some point,
# a silent state that cost an RCA. If a row regresses, this gate names the
# layer before anyone greps a production box.
#
#   ./run_lifecycle.sh                  # 300s window
#   ./run_lifecycle.sh 480              # longer window (slow machines)
#   LIFECYCLE_KILL=1 ./run_lifecycle.sh # + hard-kill agent mid-traffic to
#                                       #   assert FramesDropped surfaces
#                                       #   (the leviculum#25 guard)
#   KEEP=1 ./run_lifecycle.sh           # leave the stack up afterwards
#
# Ladder (state → observable, from the state table):
#   L0 announce        → announce logger / peer_admitted line
#   L3 advisory admit  → peer_admitted … provenance=Advisory
#   L3 rooted          → "announce rooted" | knows_peer=true ([DELIVERY-STATUS])
#   L3 kex present     → "kex_present":true  ([DELIVERY-STATUS] json)
#   L3 deliverable     → "deliverable":true  ([DELIVERY-STATUS] json)
#   L4 round applied   → dispatch_inbound | IdentityOccurrence applied
#   L1 link identified → "link identified" (LinkIdentified → attribution table)
#   L1 teardown        → link closed: PeerClosed   (down phase)
#   L2 frames dropped  → FramesDropped WARN        (LIFECYCLE_KILL=1 only)
set -uo pipefail
cd "$(dirname "$0")"

PROJECT="ciris-mesh-repro"
WINDOW="${1:-300}"
export CIRIS_HARNESS_LIFECYCLE=true
export CIRIS_SERVER_VERSION="${CIRIS_SERVER_VERSION:-0.5.126}"

compose() { docker compose -p "$PROJECT" "$@"; }
logs_all() { compose logs --no-color 2>/dev/null; }

cleanup() {
  if [ "${KEEP:-0}" = "1" ]; then
    echo "── KEEP=1: stack left up (docker compose -p $PROJECT down -v to stop)"
  else
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "── lifecycle gate: ciris-server==${CIRIS_SERVER_VERSION}, window=${WINDOW}s ──"
compose down -v --remove-orphans >/dev/null 2>&1 || true
compose build >/dev/null
compose up -d
# ── Stack-up gate: a ladder walked against a dead stack is 8 meaningless FAILs.
#    Verify both containers are actually RUNNING before asserting anything; a
#    crashed role gets its own distinct verdict + its logs, and exit 99.
sleep 5
for svc in canonical agent; do
  state=$(compose ps "$svc" --format '{{.State}}' 2>/dev/null | head -1)
  if [ "$state" != "running" ]; then
    echo
    echo "── VERDICT: STACK-FAILED — $svc is '$state' (not running); ladder not walked ──"
    echo "   last 15 log lines from $svc:"
    compose logs --no-color --tail 15 "$svc" 2>/dev/null | sed 's/^/     /'
    exit 99
  fi
done
echo "── stack up (both roles running); walking the state ladder ──"

# Ladder rows: "<id>|<label>|<extended-regex over the combined logs>"
LADDER=(
  "announce|L0 announce heard|announce|peer_admitted"
  "advisory|L3 advisory admit|provenance=Advisory"
  "rooted|L3 rooted (knows_peer)|announce rooted|\"knows_peer\":true"
  "kex|L3 KEX present|\"kex_present\":true"
  "deliverable|L3 deliverable|\"deliverable\":true"
  "round|L4 round applied|dispatch_inbound|IdentityOccurrence.*applied|envelopes.*applied|\"admitted\""
  "identified|L1 link identified|link identified"
)

declare -A HIT
deadline=$(( $(date +%s) + WINDOW ))
remaining=${#LADDER[@]}
while [ "$(date +%s)" -lt "$deadline" ] && [ "$remaining" -gt 0 ]; do
  L=$(logs_all)
  remaining=0
  line="  "
  for row in "${LADDER[@]}"; do
    id="${row%%|*}"; rest="${row#*|}"; pat="${rest#*|}"
    if [ -z "${HIT[$id]:-}" ]; then
      if grep -qiE "$pat" <<<"$L"; then HIT[$id]=$(date +%s); fi
    fi
    if [ -n "${HIT[$id]:-}" ]; then line+="[x]$id "; else line+="[ ]$id "; remaining=$((remaining+1)); fi
  done
  printf '\r%s(%ss left)   ' "$line" "$(( deadline - $(date +%s) ))"
  sleep 5
done
echo

# ── Down-phase: teardown + (optional) frame-loss assertion ──────────────────
KILLED=0
if [ "${LIFECYCLE_KILL:-0}" = "1" ]; then
  echo "── LIFECYCLE_KILL: hard-killing the agent mid-traffic (FramesDropped assert) ──"
  docker kill -s KILL "$(compose ps -q agent)" >/dev/null 2>&1 && KILLED=1
  sleep 25   # give canonical a dispatch tick + the disconnect event
else
  echo "── stopping the agent (clean teardown → PeerClosed) ──"
  compose stop agent >/dev/null 2>&1
  sleep 15
fi
TEAR_PAT="link closed: (PeerClosed|Timeout|Stale)"
tear_deadline=$(( $(date +%s) + 90 ))   # stale-time is 60s; poll past it
while [ "$(date +%s)" -lt "$tear_deadline" ]; do
  L=$(logs_all)
  if grep -qiE "$TEAR_PAT" <<<"$L"; then HIT[teardown]=1; break; fi
  sleep 5
done
if [ "$KILLED" = "1" ]; then
  grep -qiE "FramesDropped|frames=[0-9]+.*dropped|disconnected during dispatch" <<<"$L" && HIT[frames]=1
fi

# ── Verdict table ───────────────────────────────────────────────────────────
echo
echo "── lifecycle state coverage ────────────────────────────────────────────"
missed=0
report_row() { # id label
  if [ -n "${HIT[$1]:-}" ]; then printf "  PASS  %s\n" "$2"; else printf "  FAIL  %s\n" "$2"; missed=$((missed+1)); fi
}
for row in "${LADDER[@]}"; do
  id="${row%%|*}"; rest="${row#*|}"; label="${rest%%|*}"
  if [ "$id" = "advisory" ] && [ -z "${HIT[advisory]:-}" ] && ! grep -qiE "provenance=" <<<"$(logs_all)"; then
    # Test-anchor blesses BOTH nodes, so admits go straight to Rooted — the
    # Advisory rung is topology-inexpressible here. The field-faithful variant
    # (unblessed agent -> advisory-admit -> KEX) is the run_lifecycle NAT/
    # unblessed follow-up; do not report a state the topology cannot reach.
    printf "  SKIP  %s (test-anchor topology: direct Rooted; needs unblessed-agent variant)\n" "$label"
    continue
  fi
  report_row "$id" "$label"
done
report_row teardown "L1 teardown (link closed)"
[ "$KILLED" = "1" ] && report_row frames "L2 frames dropped surfaced (leviculum#25 guard)"

echo
if [ "$missed" -eq 0 ]; then
  echo "── VERDICT: LIFECYCLE COMPLETE — every state observable from our tier ──"
else
  echo "── VERDICT: $missed state(s) NOT observed — the FIRST missing rung names the layer ──"
  echo "   (state table + debugging map: FSD/RNS_LIFECYCLE_STATES.md)"
  echo "   last [DELIVERY-STATUS] from the agent:"
  logs_all | grep "\[DELIVERY-STATUS\]" | tail -2 | sed 's/^/     /'
fi
exit "$missed"
