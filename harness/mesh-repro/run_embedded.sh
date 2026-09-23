#!/usr/bin/env bash
# mesh-repro EMBEDDED-FOLD variant (CIRISServer#264 must-have 2) — live in-process
# Engine+Edge, then serve_with_python_adapter on the SAME process (the agent-
# embedded topology where the tokio reentrancy panic lived). PASS = the fold's
# read-API binds 4243 on the agent container. See agent_boot.py EMBEDDED-FOLD.
set -euo pipefail
cd "$(dirname "$0")"
PROJECT="ciris-mesh-repro-emb"
compose() { docker compose -p "$PROJECT" "$@"; }
cleanup() { [ "${KEEP:-0}" = "1" ] || compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
compose down -v --remove-orphans >/dev/null 2>&1 || true
CIRIS_HARNESS_EMBEDDED_FOLD=true compose build >/dev/null
compose up -d >/dev/null
# pass the flag through to the agent service env
docker compose -p "$PROJECT" stop agent >/dev/null 2>&1 || true
docker compose -p "$PROJECT" rm -f agent >/dev/null 2>&1 || true
CIRIS_HARNESS_EMBEDDED_FOLD=true docker compose -p "$PROJECT" up -d agent >/dev/null 2>&1 || true
for i in $(seq 1 40); do
  # `grep -c … || true`, NOT `grep -q`: these scripts run under `set -euo
  # pipefail`, and `grep -q` exits the instant it matches — which SIGPIPEs the
  # `compose logs` feeding it, so the PIPELINE exits 141 and the `if` is FALSE
  # **on a successful match**. It fails only once the log is big enough that
  # `compose logs` is still writing when grep leaves, so it reads as a flaky
  # readiness check rather than a bug. Measured in scenarios/selffiles.sh, where
  # it made three ladder rungs report 0 against logs that plainly matched.
  if [ "$(compose logs agent 2>/dev/null | grep -c "read-API BOUND on 4243" || true)" -gt 0 ]; then
    echo "VERDICT: SUCCESS — embedded fold bound 4243 (reentrancy shield holds)"; exit 0
  fi
  if [ "$(compose logs agent 2>/dev/null | grep -cE "EMBEDDED-FOLD (FAILED|VERDICT)" || true)" -gt 0 ]; then
    echo "VERDICT: REPRO — embedded fold failed:"; compose logs agent | grep -E "EMBEDDED-FOLD" | tail -3; exit 2
  fi
  sleep 5
done
echo "VERDICT: INCONCLUSIVE (no embedded-fold signal in 200s)"; exit 4
