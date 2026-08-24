#!/usr/bin/env bash
# run_traceflow.sh — the FULL local trace-flow E2E verdict (CIRISServer#315 /
# gate #922): seal real traces on the agent, watch the canonical for arrival +
# scoring. Uses the test-anchor wheel built from the CURRENT working tree
# (pack_wheel.py), so tree fixes are verdict-testable before any cut.
#
#   ./run_traceflow.sh            # 420s watch
#   ./run_traceflow.sh 600        # longer
#   KEEP=1 ./run_traceflow.sh     # leave the stack up
#
# Verdict (exit codes):
#   0 TRACEFLOW-SUCCESS  — canonical scored the agent (emitted>0 about agent key)
#   2 NO-CARRIER         — traces sealed + rounds green, but canonical corpus
#                          never saw them (the missing trace/corpus plane)
#   3 SEAL-FAILED        — the agent could not seal (consent/pipeline error)
#   4 INCONCLUSIVE       — timing/infra ambiguity; read the logs
set -euo pipefail
cd "$(dirname "$0")"

PROJECT="ciris-traceflow"
WINDOW="${1:-420}"

# Build the test-anchor wheel from the CURRENT tree (release .so + hand-packed
# pyo3 layout — pack_wheel.py). This is what both roles install.
echo "── building test-anchor wheel from the working tree ──"
( cd ../.. && cargo build --release --features test-anchor,python 2>&1 | tail -2 )
python3 pack_wheel.py
WHEEL=$(ls -t wheels/ciris_server-*.whl | head -1)
echo "── wheel: $WHEEL ──"
export CIRIS_SERVER_VERSION="local"

compose() { docker compose -p "$PROJECT" -f docker-compose.yml -f docker-compose.traceflow.yml "$@"; }

cleanup() {
  if [ "${KEEP:-0}" = "1" ]; then
    echo "── KEEP=1: stack left up. Tear down with: docker compose -p $PROJECT down -v"
  else
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

compose down -v --remove-orphans >/dev/null 2>&1 || true
compose build
compose up -d

echo "── waiting for the canonical to become healthy ──"
for _ in $(seq 1 24); do
  state=$(compose ps canonical --format '{{.Health}}' 2>/dev/null || echo "")
  [ "$state" = "healthy" ] && break
  sleep 5
done

echo "── watching (${WINDOW}s): seal → arrival → canonical scoring ──"
SEALED=0 ARRIVED=0 SCORED=0 SELFSKIP=0
deadline=$(( $(date +%s) + WINDOW ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  sleep 15
  AGENT_LOG=$(compose logs agent 2>/dev/null || true)
  CANON_LOG=$(compose logs canonical 2>/dev/null || true)
  # STRIP ANSI ONCE, HERE. Rust's tracing writer colorises, so a field renders
  # as `n_summaries<ESC>[2m=<ESC>[0m3` and a literal `n_summaries=[1-9]` pattern
  # matches NOTHING — the probe reports 0 against a perfectly healthy run, and a
  # probe that matches nothing reads exactly like a probe that matches zero.
  #
  # Measured on the 2026-08-24 run: raw 0, stripped 192. This runner reported
  # "canonical saw summaries: 0" inside a SUCCESS verdict whose own log showed
  # n_summaries=3.
  #
  # `lib/harness.sh`'s `harness_log_count` has stripped ANSI for exactly this
  # reason for some time — with a comment saying the fix belongs there so no
  # scenario has to remember it. This runner does not go through it, so it
  # remembered nothing. Fixed at the source of the text rather than at each
  # probe, for the same reason.
  AGENT_LOG=$(printf '%s' "$AGENT_LOG" | sed -E 's/\x1b\[[0-9;]*m//g')
  CANON_LOG=$(printf '%s' "$CANON_LOG" | sed -E 's/\x1b\[[0-9;]*m//g')
  SEALED=$(echo "$AGENT_LOG" | grep -c "sealed_and_persisted" || true)
  # the canonical has NO brain: any n_summaries>0 on its scorer = agent traces ARRIVED
  ARRIVED=$(echo "$CANON_LOG" | grep -cE "n_summaries=[1-9]" || true)
  # `emitted=[1-9]`, not "a pass completed": the scorer logs a completed pass in
  # BOTH directions, so matching the pass alone reports success for a pass that
  # authored nothing. scenarios/traceflow.sh already carries this lesson in
  # `stage_score`; this runner did not.
  SCORED=$(echo "$CANON_LOG" | grep -cE "capacity scorer pass complete.*emitted=[1-9]" || true)
  SELFSKIP=$(echo "$AGENT_LOG" | grep -c "anti-Goodhart" || true)
  SEALERR=$(echo "$AGENT_LOG" | grep -c "TRACEFLOW: capture_event.*ERROR" || true)
  echo "  sealed=$SEALED arrived_pass=$ARRIVED canonical_scored=$SCORED agent_selfskip=$SELFSKIP sealerr=$SEALERR"
  # Early exits (iteration speed): full success; hard seal failure; or
  # NO-CARRIER once sealing succeeded, the mesh is green, and the canonical
  # has run >=6 consecutive empty scorer passes (2 min at the 20s cadence).
  [ "$SCORED" -gt 0 ] && break
  [ "$SEALERR" -gt 0 ] && [ "$SEALED" -eq 0 ] && break
  if [ "$SEALED" -gt 0 ] && [ "$ARRIVED" -eq 0 ]; then
    EMPTY_PASSES=$(echo "$CANON_LOG" | grep -c "n_summaries=0" || true)
    [ "$EMPTY_PASSES" -ge 6 ] && break
  fi
done

echo
echo "── agent TRACEFLOW/KEX evidence ──"
compose logs agent 2>/dev/null | grep -E "TRACEFLOW|KEX-GATE|FATAL|Traceback|Error" | tail -20
echo "── canonical scorer evidence ──"
compose logs canonical 2>/dev/null | grep -E "scorer|capacity" | tail -8
echo
echo "═══ TRACEFLOW VERDICT ═══"
echo "  agent sealed traces      : $SEALED (LensClient sealed_and_persisted)"
echo "  canonical saw summaries  : $ARRIVED (scorer pass n_summaries>0)"
echo "  canonical scored agent   : $SCORED (capacity attestation authored)"
echo "  agent self-skip (§7.5)   : $SELFSKIP"
if [ "$SCORED" -gt 0 ]; then
  echo "  → TRACEFLOW-SUCCESS: the full carrier exists — traces reached the canonical and were scored."
  exit 0
elif [ "$SEALED" -gt 0 ] && [ "$ARRIVED" -eq 0 ]; then
  echo "  → NO-CARRIER: traces sealed + mesh green, but no plane moved them to the canonical."
  echo "    (The next cut needs the trace/corpus replication leg — this is the gate-#922 carrier.)"
  exit 2
elif [ "$SEALED" -eq 0 ]; then
  echo "  → SEAL-FAILED: the agent could not seal traces; read the TRACEFLOW lines in the agent log."
  exit 3
else
  echo "  → INCONCLUSIVE: read both logs."
  exit 4
fi
