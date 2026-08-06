#!/usr/bin/env bash
# run_traceflow2.sh — traceflow E2E with a STAGE-LADDER probe: every stage of
# the chain is independently detected, and a failure names the FIRST broken
# stage + the likely fix (runbook §refs). "If it breaks we know exactly where."
#
#   Stage 1  seal        agent: LensClient sealed_and_persisted
#   Stage 2  consent     agent: consent:replication authored (attestation_id)
#   Stage 3  converge    agent: reconciler converged to >=1 consent peers
#   Stage 4  ship        agent: replication_plane.carriage.envelopes_served_total
#                        > 0 (DELIVERY-STATUS) — the REPLICATION-plane counter;
#                        envelopes_sent_total is the application plane and is 0
#                        on every healthy trace run (CIRISServer#377)
#   Stage 5  arrive      canonical: trace_events rows > 0 (DIRECT DB QUERY —
#                        independent of any log line; catches silent persist)
#   Stage 6  summarize   canonical: scorer n_summaries > 0
#   Stage 7  score       canonical: capacity scorer pass complete (emitted>0)
#
#   ./run_traceflow2.sh [window_secs]   (default 360)   KEEP=1 to keep stack up
set -euo pipefail
cd "$(dirname "$0")"

PROJECT="ciris-traceflow"
WINDOW="${1:-780}"

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

# Direct DB row count at the canonical — no log dependency. Finds the persist
# sqlite file under the node home and counts trace_events (0 if absent/early).
canon_rows() {
  compose exec -T canonical python -c "import glob,sqlite3;r=0
for d in glob.glob('/var/lib/ciris/**/*.db*',recursive=True):
    if d.endswith(('-wal','-shm')): continue
    try: r=max(r,sqlite3.connect(d).execute('SELECT count(*) FROM trace_events').fetchone()[0])
    except Exception: pass
print(r)" 2>/dev/null || echo "-1"
}

# Stage 1b — does the AGENT hold a trace:* attestation after seal? Splits the
# stage-4 fork: 0 ⇒ the seal path never authors the trace:complete:v1 carrier
# (runbook §3 step 2 missing at the source); >0 ⇒ authored but the replication
# plane never ships it (filter/scope/vocabulary).
agent_trace_atts() {
  compose exec -T agent python -c "import glob,sqlite3;n=0
for d in glob.glob('/var/lib/ciris/**/*.db*',recursive=True):
    if d.endswith(('-wal','-shm')): continue
    try:
        c=sqlite3.connect(d)
        for (t,) in c.execute(\"SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%attestation%'\"):
            try: n+=c.execute('SELECT count(*) FROM '+t+\" WHERE CAST(attestation_envelope AS TEXT) LIKE '%trace:%'\").fetchone()[0]
            except Exception: pass
    except Exception: pass
print(n)" 2>/dev/null || echo "-1"
}

echo "── watching (${WINDOW}s): the 7-stage ladder ──"
S1=0 S1B=0 S2=0 S3=0 S4=0 S5=0 S6=0 S7=0 SEALERR=0
deadline=$(( $(date +%s) + WINDOW ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  sleep 15
  AGENT_LOG=$(compose logs agent 2>/dev/null || true)
  CANON_LOG=$(compose logs canonical 2>/dev/null || true)
  S1=$(echo "$AGENT_LOG" | grep -c "sealed_and_persisted" || true)
  SEALERR=$(echo "$AGENT_LOG" | grep -c "TRACEFLOW: capture_event.*ERROR" || true)
  S2=$(echo "$AGENT_LOG" | grep -c "CONSENT: consent:replication authored" || true)
  S3=$(echo "$AGENT_LOG" | grep -cE "converged to [1-9][0-9]* consent peers" || true)
  # CIRISServer#377 — the REPLICATION-plane counter. `envelopes_sent_total` is
  # edge's application-plane counter and reads 0 on every healthy trace run, so
  # keying stage 4 on it made the rung unable to pass and therefore unable to
  # fail (CIRISEdge#433/#434).
  S4=$(echo "$AGENT_LOG" | grep -cE '"envelopes_served_total":[1-9]' || true)
  # v21.10.0 trace_plane diagnostic (CIRISAgent#932): armed = a live grant
  # COVERS trace: with a non-self audience — the one-call answer to "why
  # didn't it cross" that replaces sqlite-poking for preconditions.
  ARMED=$(echo "$AGENT_LOG" | grep -cE '"covers_trace": ?true' || true)
  S1B=$(agent_trace_atts | tr -d '[:space:]')
  S5=$(canon_rows | tr -d '[:space:]')
  S6=$(echo "$CANON_LOG" | grep -cE "n_summaries=[1-9]" || true)
  S7=$(echo "$CANON_LOG" | grep -c "capacity scorer pass complete" || true)
  echo "  [ladder] 1.seal=$S1(err=$SEALERR) 1b.trace_atts=$S1B 2.consent=$S2 3.converge=$S3 3b.armed=$ARMED 4.ship=$S4 5.arrive_rows=$S5 6.summaries=$S6 7.scored=$S7"
  [ "$S7" -gt 0 ] && break
  [ "$SEALERR" -gt 0 ] && [ "$S1" -eq 0 ] && break
done

# FINAL RE-SAMPLE (closure-run artifact: traces land + scorer fires AFTER the
# last loop tick — sampling early printed NO-CARRIER against a working pipeline)
sleep 30
AGENT_LOG=$(compose logs agent 2>/dev/null || true)
CANON_LOG=$(compose logs canonical 2>/dev/null || true)
S4=$(echo "$AGENT_LOG" | grep -cE '"envelopes_served_total":[1-9]' || true)
S5=$(canon_rows | tr -d '[:space:]')
S6=$(echo "$CANON_LOG" | grep -cE "n_summaries=[1-9]" || true)
S7=$(echo "$CANON_LOG" | grep -c "capacity scorer pass complete" || true)
echo "  [final-resample] 4.ship=$S4 5.arrive_rows=$S5 6.summaries=$S6 7.scored=$S7"

echo
echo "── trace_plane verdict (the #932 one-call diagnostic) ──"
compose logs agent 2>/dev/null | grep -oE '"trace_plane":\{[^}]*\}' | tail -1
echo "── evidence: agent consent/seal/deliver ──"
compose logs agent 2>/dev/null | grep -E "TRACEFLOW|CONSENT|consent|envelopes_served|KEX-GATE|FATAL|Error" | tail -25
echo "── evidence: canonical ingest/scorer ──"
compose logs canonical 2>/dev/null | grep -iE "scorer|capacity|trace_event|attestation|ingest|consent" | tail -15

echo
echo "═══ TRACEFLOW STAGE-LADDER VERDICT ═══"
echo "  1.seal=$S1  2.consent=$S2  3.converge=$S3  4.ship=$S4  5.arrive_rows=$S5  6.summaries=$S6  7.scored=$S7"
if   [ "$S7" -gt 0 ]; then echo "  → SUCCESS: full chain — trace sealed, consented, shipped, arrived, scored."; exit 0
elif [ "$S1" -eq 0 ]; then echo "  → BROKEN AT 1 (SEAL): LensClient pipeline — read TRACEFLOW ERROR lines (wire schema? consent gate?)."; exit 3
elif [ "$S2" -eq 0 ]; then echo "  → BROKEN AT 2 (CONSENT): author_federation_consent failed/absent — runbook §1; check CONSENT lines + CIRIS_TESTING_MODE fence."; exit 5
elif [ "$S3" -eq 0 ]; then echo "  → BROKEN AT 3 (CONVERGE): grant authored but reconciler never converged >=1 consent peers — runbook §2c; check replication_reconcile/list_consent_peers."; exit 6
elif [ "$S4" -eq 0 ]; then
  if [ "${S1B:-0}" -le 0 ]; then
    echo "  → BROKEN AT 4a (CARRIER NEVER AUTHORED): agent holds NO trace:* attestation after seal (1b=$S1B) — the seal path does not author the trace:complete:v1 carrier (runbook §3 step 2); the fix is at the SOURCE (lens-core seal / post-seal emit), not replication."
  else
    echo "  → BROKEN AT 4b (AUTHORED, NOT SHIPPED): agent holds $S1B trace:* attestation(s) but carriage stayed 0 (replication_plane.carriage) — read carriage.standing: 'withholding' names the refusing gate in withholds.by_reason; 'idle'/'not_exercised' point at replication filter/scope/vocabulary; check the grant prefixes (trace: in scope?) + round_diagnostics."
  fi
  exit 7
elif [ "$S5" -le 0 ]; then echo "  → BROKEN AT 5 (ARRIVE): envelopes sent but canonical trace_events=$S5 — ingest/#501 materialization; check canonical ingest errors (schema_malformed? verify_unknown_key?)."; exit 8
elif [ "$S6" -eq 0 ]; then echo "  → BROKEN AT 6 (SUMMARIZE): rows landed but scorer sees n_summaries=0 — summary projection/window; check trace_level/CallerScope/window."; exit 9
else echo "  → BROKEN AT 7 (SCORE): summaries seen but no pass completed — read the emitted-ZERO WARN counts (unregistered_agents? anti-Goodhart? FK?)."; exit 10
fi
