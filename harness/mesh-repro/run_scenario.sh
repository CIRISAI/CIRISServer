#!/usr/bin/env bash
# run_scenario.sh — the modular mesh-harness entry point.
#
#   ./run_scenario.sh <scenario> [window_secs]
#   ./run_scenario.sh --list
#
#   KEEP=1        leave the stack up for inspection
#   SKIP_BUILD=1  reuse the wheel already in wheels/ (CI reuses one build)
#   PROJECT=…     override the compose project name (parallel runs)
#
# Adding a scenario is one file: drop scenarios/<name>.sh declaring STAGES, a
# stage_<id> probe per stage, HINT_<id>/EXIT_<id>, and SUCCESS_STAGE. The driver
# (lib/harness.sh) owns build, lifecycle, sampling, the final re-sample, and the
# verdict — so a new scenario cannot accidentally reintroduce the sample-too-early
# false negative that cost this project two full cycles.
#
# Exit codes: 0 SUCCESS · 2 usage · 3 stack failed to come up ·
#             10+ per-stage (the scenario's EXIT_<id>; stable for CI)
set -euo pipefail
cd "$(dirname "$0")"

SCENARIOS_DIR="scenarios"

list_scenarios() {
  echo "available scenarios:"
  for f in "$SCENARIOS_DIR"/*.sh; do
    [ -e "$f" ] || continue
    local n; n="$(basename "$f" .sh)"
    printf '  %-14s %s\n' "$n" "$(grep -m1 '^# scenarios/' "$f" | sed 's|^# [^—]*— ||')"
  done
}

[ "${1:-}" = "--list" ] && { list_scenarios; exit 0; }

SCENARIO="${1:-}"
WINDOW="${2:-780}"
if [ -z "$SCENARIO" ]; then
  echo "usage: $0 <scenario> [window_secs]   (or --list)" >&2
  list_scenarios >&2
  exit 2
fi
SCENARIO_FILE="$SCENARIOS_DIR/$SCENARIO.sh"
if [ ! -f "$SCENARIO_FILE" ]; then
  echo "no such scenario: $SCENARIO" >&2
  list_scenarios >&2
  exit 2
fi

# The scenario is sourced FIRST: it sets COMPOSE_FILES (and may set PROJECT),
# which the library's compose() wrapper closes over.
PROJECT="${PROJECT:-ciris-$SCENARIO}"
# shellcheck source=/dev/null
source "$SCENARIO_FILE"
# shellcheck source=lib/harness.sh
source lib/harness.sh

echo "═══ mesh harness: $SCENARIO_NAME (window ${WINDOW}s, project $PROJECT) ═══"

trap harness_cleanup EXIT

harness_build_wheel
export CIRIS_SERVER_VERSION="local"
harness_up || { echo "→ stack failed to come up"; exit 3; }
harness_wait_healthy "${HEALTH_SERVICE:-canonical}"
# Before ANY stage runs: is the code under test the code in the tree? A ladder
# that measures a stale image is not a weaker signal, it is a false one.
for _svc in $(compose ps --services 2>/dev/null); do
  harness_assert_image_matches_wheel "$_svc" || exit 3
done
# OPTIONAL scenario hook, between "the stack is up" and "start measuring".
# A carrier scenario needs none — traceflow's agent drives itself from inside its
# container. A scenario whose subject is an OWNER-GATED HTTP surface does: nothing
# in the containers can claim a node, and a claim is not a measurement. It is
# invoked only when the scenario defines it, so every existing scenario is
# unaffected. It must not `exit` — a failed setup has to reach the ladder, which
# is what names the stage it broke at.
if declare -F harness_scenario_prepare >/dev/null; then
  echo "═══ $SCENARIO_NAME: scenario prepare ═══"
  harness_scenario_prepare || echo "── prepare returned non-zero — continuing to the ladder"
fi
harness_run_ladder "$WINDOW" "${RESAMPLE_SECS:-30}"
harness_verdict
