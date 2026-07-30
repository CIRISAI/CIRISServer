#!/usr/bin/env bash
# lib/harness.sh — shared mesh-harness infrastructure.
#
# Everything here is scenario-AGNOSTIC: wheel build, compose lifecycle, health
# wait, direct-DB probes, the stage-ladder driver, and the verdict printer. A
# scenario file (scenarios/<name>.sh) supplies only WHAT to measure; this file
# owns HOW the run is driven and reported.
#
# Design rules, learned the hard way this arc:
#
#  1. A stage probe returns a COUNT on stdout and nothing else. Never a verdict.
#  2. Probes prefer DIRECT DB reads over log greps. A log line is a claim about
#     behaviour; a row is the behaviour. The `NO-CARRIER`-on-a-working-pipeline
#     false negative that cost two full cycles was a log-timing artifact.
#  3. The ladder ALWAYS re-samples after the loop ends. Late-landing rows are
#     normal — the scorer runs on a cadence, so the last loop tick is not the
#     end of the story.
#  4. A failure names the FIRST broken stage and its fix hint. "It broke" is not
#     an acceptable output; the whole point is "we know exactly where."
#  5. Exit codes are stable and per-stage, so CI can distinguish a regression at
#     stage 4 from one at stage 7 without parsing prose.

set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${PROJECT:-ciris-mesh-harness}"
: "${COMPOSE_FILES:=-f docker-compose.yml}"

compose() {
  # shellcheck disable=SC2086
  docker compose -p "$PROJECT" $COMPOSE_FILES "$@"
}

# ── build ───────────────────────────────────────────────────────────────────
# Build the test-anchor wheel from the WORKING TREE, so a fix is verdict-testable
# before it is committed. `SKIP_BUILD=1` reuses whatever is already in wheels/
# (CI reuses one build across scenarios).
harness_build_wheel() {
  if [ "${SKIP_BUILD:-0}" = "1" ] && ls "$HARNESS_DIR"/wheels/ciris_server-*.whl >/dev/null 2>&1; then
    echo "── SKIP_BUILD=1: reusing $(ls -t "$HARNESS_DIR"/wheels/ciris_server-*.whl | head -1)"
    return 0
  fi
  echo "── building test-anchor wheel from the working tree ──"
  ( cd "$HARNESS_DIR/../.." && cargo build --release --features test-anchor,python 2>&1 | tail -2 )
  ( cd "$HARNESS_DIR" && python3 pack_wheel.py )
  echo "── wheel: $(ls -t "$HARNESS_DIR"/wheels/ciris_server-*.whl | head -1) ──"
}

harness_up() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  compose build
  compose up -d
}

harness_cleanup() {
  if [ "${KEEP:-0}" = "1" ]; then
    echo "── KEEP=1: stack left up. Tear down: docker compose -p $PROJECT down -v"
  else
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}

harness_wait_healthy() {
  local svc="${1:-canonical}" tries="${2:-24}"
  echo "── waiting for $svc to become healthy ──"
  for _ in $(seq 1 "$tries"); do
    if [ "$(compose ps "$svc" --format '{{.Health}}' 2>/dev/null || echo)" = "healthy" ]; then
      return 0
    fi
    sleep 5
  done
  echo "  WARN: $svc never reported healthy — continuing (the ladder will localise it)"
}

# ── probes ──────────────────────────────────────────────────────────────────
# Count rows matching an optional WHERE across every sqlite db under a service's
# node home. Table-absent / db-early is 0, never an error: a probe must be safe
# to call before the schema exists. `-1` means the exec itself failed.
harness_db_count() {
  local svc="$1" table="$2" where="${3:-}"
  local sql="SELECT count(*) FROM $table"
  if [ -n "$where" ]; then sql="$sql WHERE $where"; fi
  # The SQL travels as ARGV, never interpolated into the Python source. A WHERE
  # clause legitimately ends in a quote (LIKE '%trace:%'), which collided with a
  # triple-quoted literal and produced a SyntaxError that surfaced only as a
  # silent `-1`. argv has no quoting surface to collide with.
  compose exec -T "$svc" python -c 'import glob,sqlite3,sys
q=sys.argv[1]; r=0
for d in glob.glob("/var/lib/ciris/**/*.db*", recursive=True):
    if d.endswith(("-wal","-shm")): continue
    try: r=max(r, sqlite3.connect(d).execute(q).fetchone()[0])
    except Exception: pass
print(r)' "$sql" 2>/dev/null | tr -d '[:space:]' || echo "-1"
}

harness_log_count() {
  local svc="$1" pattern="$2"
  # STRIP ANSI FIRST. Rust's tracing writer colorises, so a field renders as
  # `n_summaries<ESC>[2m=<ESC>[0m3` — a literal `n_summaries=3` pattern matches
  # nothing and the probe reports 0 against a perfectly healthy run. This bit the
  # harness itself; the fix belongs here so no scenario has to remember it.
  compose logs "$svc" 2>/dev/null \
    | sed -E 's/\x1b\[[0-9;]*m//g' \
    | grep -cE "$pattern" || true
}

# ── the ladder ──────────────────────────────────────────────────────────────
# A scenario declares:
#   STAGES=(seal consent ...)              # ordered stage ids
#   stage_<id>()      -> echoes a count    # the probe
#   HINT_<id>="…"                          # what to do when it is the first zero
#   EXIT_<id>=<n>                          # stable per-stage exit code
#   SUCCESS_STAGE=<id>                     # reaching this non-zero ⇒ SUCCESS
# Optional:
#   DIAG_<id>()                            # extra evidence printed on failure
#   harness_scenario_evidence()            # always-printed evidence tail
harness_run_ladder() {
  local window="${1:-780}" resample="${2:-30}"
  declare -gA COUNT
  echo "── watching (${window}s): the ${#STAGES[@]}-stage ladder ──"
  local deadline=$(( $(date +%s) + window ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 15
    harness_sample
    harness_print_ladder
    # `if`, NOT `[ … ] && break`: under `set -e` a FALSE `&&` list returns
    # non-zero and terminates the script, which silently killed the ladder after
    # one tick. Guarding a loop with a bare test-and-break is a trap here.
    if [ "${COUNT[$SUCCESS_STAGE]:-0}" -gt 0 ]; then break; fi
  done
  # Rule 3 — ALWAYS re-sample. Late rows are normal, not failure.
  echo "── final re-sample (+${resample}s: the scorer runs on a cadence) ──"
  sleep "$resample"
  harness_sample
  harness_print_ladder
}

harness_sample() {
  local s
  for s in "${STAGES[@]}"; do
    COUNT[$s]=$("stage_$s" 2>/dev/null | tr -d '[:space:]' || echo 0)
    if [ -z "${COUNT[$s]}" ]; then COUNT[$s]=0; fi
  done
}

harness_print_ladder() {
  local out="  [ladder]" i=1 s
  for s in "${STAGES[@]}"; do
    out="$out $i.$s=${COUNT[$s]}"
    i=$((i+1))
  done
  echo "$out"
}

# Print the verdict and EXIT with the stable code. SUCCESS iff SUCCESS_STAGE > 0;
# otherwise name the FIRST zero stage, its hint, and any stage-specific diagnosis.
harness_verdict() {
  echo
  if declare -F harness_scenario_evidence >/dev/null; then
    echo "── evidence ──"; harness_scenario_evidence || true
  fi
  echo
  echo "═══ ${SCENARIO_NAME:-scenario} STAGE-LADDER VERDICT ═══"
  harness_print_ladder
  # NOTE the ordering: the audit branch must be evaluated BEFORE the
  # success-stage short-circuit. Otherwise a scenario whose success stage happens
  # to be positive reports SUCCESS while independent preconditions are still
  # unmet — which is precisely the false green this mode exists to prevent.
  if [ "${VERDICT_MODE:-monotonic}" != "audit" ] && [ "${COUNT[$SUCCESS_STAGE]:-0}" -gt 0 ]; then
    echo "  → SUCCESS: ${SUCCESS_MESSAGE:-full chain green}"
    exit 0
  fi
  # AUDIT MODE (VERDICT_MODE=audit): report EVERY failing stage, not just the
  # first. A monotonic "first break" verdict is right for a CARRIER scenario —
  # one pipeline, one blockage. It is wrong for an AUDIT scenario, where the
  # question is "which of these independent preconditions hold?" and stopping at
  # the first zero hides the rest. That difference is exactly how a fixture can
  # pass four deltas at once and look like one problem.
  if [ "${VERDICT_MODE:-monotonic}" = "audit" ]; then
    local failed=0 s hint code first_code=0
    for s in "${STAGES[@]}"; do
      if [ "${COUNT[$s]:-0}" -le 0 ]; then
        hint="HINT_$s"; code="EXIT_$s"
        echo "  ✗ $s — ${!hint:-no hint recorded}"
        if declare -F "DIAG_$s" >/dev/null; then "DIAG_$s" || true; fi
        failed=$((failed+1))
        [ "$first_code" -eq 0 ] && first_code="${!code:-1}"
      else
        echo "  ✓ $s"
      fi
    done
    if [ "$failed" -eq 0 ]; then
      echo "  → SUCCESS: ${SUCCESS_MESSAGE:-every precondition holds}"
      exit 0
    fi
    echo "  → $failed PRECONDITION(S) UNMET — see each ✗ above. Exit code names the FIRST."
    exit "$first_code"
  fi

  # MONOTONIC LADDER: find the furthest stage with positive evidence. Everything
  # at or before it is PROVEN regardless of its own probe — a later stage cannot
  # have happened without the earlier ones. Only stages after the high-water mark
  # are candidates for blame. Without this, one weak intermediate probe (e.g. a
  # counter that stays 0 on a healthy run) produces a confidently wrong verdict.
  local hi=-1 idx=0 s hint code
  for s in "${STAGES[@]}"; do
    if [ "${COUNT[$s]:-0}" -gt 0 ]; then hi=$idx; fi
    idx=$((idx+1))
  done
  if [ "$hi" -ge 0 ]; then
    echo "  (stages 1..$((hi+1)) proven by downstream evidence)"
  fi
  idx=0
  for s in "${STAGES[@]}"; do
    if [ "$idx" -le "$hi" ]; then idx=$((idx+1)); continue; fi
    idx=$((idx+1))
    if [ "${COUNT[$s]:-0}" -le 0 ]; then
      hint="HINT_$s"; code="EXIT_$s"
      echo "  → BROKEN AT $s: ${!hint:-no hint recorded}"
      if declare -F "DIAG_$s" >/dev/null; then echo "── diagnosis ──"; "DIAG_$s" || true; fi
      exit "${!code:-1}"
    fi
  done
  echo "  → INCONCLUSIVE: every stage reported non-zero but the success stage did not."
  exit 4
}
