#!/usr/bin/env bash
# Run what CI runs, before pushing — in parallel.
#
# WHY THIS EXISTS
#
# v0.5.158 went to main with three reds, and all three were the same mistake:
# something NEAR the CI command was run instead of the CI command.
#
#   tests/release_gates/ladder.rs:1264  rustfmt   — never ran `cargo fmt --check`
#   tests/trace_round_e2e.rs:737        clippy    — ran clippy WITHOUT --features
#                                                   test-anchor; the unused import
#                                                   is invisible without it
#   tests/blocked_upstream_gate.rs:218  windows   — HOME is unset there
#
# None was a hard bug. All three were free to find. The cost was not the fixes —
# it was that a red ci.yml run blocked the iOS release asset, because the harvest
# job waits on CI. A formatting nit deleted a 58 MiB artifact from the release.
#
# WHY IT IS PARALLEL, AND WHY THAT IS NOT JUST SPEED
#
# A preflight nobody runs is worth nothing, and the thing that stops people
# running one is the wall clock. Serially these checks are dominated by CARGO
# FEATURE THRASH: default, `python` and `test-anchor` produce different build
# fingerprints, so a shared target dir rebuilds the world every time the lane
# changes — the same crates, three times, in sequence.
#
# So each feature set gets its OWN target dir. That removes the thrash AND the
# build lock that would otherwise serialize the lanes no matter how they were
# launched (cargo holds an exclusive lock on a target dir for a whole command —
# backgrounding alone buys nothing). Costs disk, returns wall clock.
#
#   lane 1  default features    target/pf-default
#   lane 2  --features python   target/pf-python
#   lane 3  --features anchor   target/pf-anchor
#   lane 4  no build at all     — fmt, evidence, localization, version
#
# DRIFT
#
# These commands are duplicated from .github/workflows/ci.yml, and a duplicate
# that can drift is worth less than no duplicate: it would keep reporting green
# about a CI that had moved on. `gate0_preflight_runs_what_ci_runs` in
# tests/release_gates/ladder.rs asserts every cargo command in ci.yml's fmt and
# clippy-test jobs appears here. Platform-only legs (ios, macOS) are named in
# that gate's allow-list — a skip written down is a decision; a silent one is a
# gap nobody knows they have.
#
#   ./scripts/preflight.sh            # everything
#   ./scripts/preflight.sh --fast     # skip the slow test-anchor round-trip
#   PF_SEQUENTIAL=1 ./scripts/preflight.sh    # one lane at a time (low disk)
set -uo pipefail
cd "$(dirname "$0")/.."

FAST=0
[ "${1:-}" = "--fast" ] && FAST=1
SEQUENTIAL="${PF_SEQUENTIAL:-0}"

LOG=$(mktemp -d)
trap 'rm -rf "$LOG"' EXIT
START=$SECONDS

# ── Stale-lane prune ──────────────────────────────────────────────────────
# Each lane keeps its own target dir, which is what buys the parallelism. The
# cost nobody sees: a SUBSTRATE REPIN invalidates all of them at once, and the
# old artifacts are not reclaimed — cargo keeps them keyed by the previous
# fingerprint. Four repins in one session grew target/pf-default to 58 GB and
# took the disk to 88%, at which point preflight started dying with no output,
# which reads as a harness bug rather than a full disk.
#
# So: if the substrate pins have moved since these dirs were built, drop them.
# The rebuild costs ~4 minutes; not noticing costs a debugging session.
PIN_STAMP=$(grep -ohE 'tag = "v[0-9.]+"' Cargo.toml crates/*/Cargo.toml 2>/dev/null \
              | sort | md5sum | cut -c1-12)
STAMP_FILE="target/.preflight-pins"
if [ -d target ] && [ "$(cat "$STAMP_FILE" 2>/dev/null)" != "$PIN_STAMP" ]; then
  stale=$(du -sh target/pf-* 2>/dev/null | awk '{s=$1} END {print s}')
  rm -rf target/pf-default target/pf-python target/pf-anchor 2>/dev/null
  [ -n "$stale" ] && echo "preflight: substrate pins moved — dropped stale lane dirs"
fi
mkdir -p target && printf '%s' "$PIN_STAMP" > "$STAMP_FILE"

# One check: name, then the command. Output is captured per check so parallel
# lanes do not interleave into an unreadable stream.
declare -a NAMES=() STATUS=()
check() {
  local name="$1"; shift
  local slug=${name//[^a-zA-Z0-9]/_}
  if "$@" >"$LOG/$slug.out" 2>&1; then echo "0" >"$LOG/$slug.rc"; else echo "1" >"$LOG/$slug.rc"; fi
}

# A lane is a sequence of checks sharing one target dir. Lanes run concurrently;
# checks inside a lane run in order, because they contend for that dir's lock.
lane() {
  local tgt="$1"; shift
  # An EMPTY CARGO_TARGET_DIR is not "unset" — cargo rejects it outright, and
  # `cargo fmt` reports that by printing its full usage text with the actual
  # reason on the line above, which reads as a malformed command rather than a
  # bad environment. Lane 4 builds nothing and wants no target dir at all.
  if [ -n "$tgt" ]; then export CARGO_TARGET_DIR="$tgt"; else unset CARGO_TARGET_DIR; fi
  while [ $# -gt 0 ]; do
    local name="$1" cmd="$2"; shift 2
    check "$name" bash -c "$cmd"
  done
}

echo "preflight: 4 lanes, $( [ "$SEQUENTIAL" = 1 ] && echo sequential || echo parallel )"

# `cargo test` runs `admin_ops` and `mesh_config_consumers`, which resolve the
# localization bundle through the INSTALLED `ciris-client` (CIRISServer#471 —
# the bundle is a package artifact now, not a path in this tree) and fail HARD
# when it is absent rather than skipping. Same step, same reason, as ci.yml's
# clippy-test job; gate0 asserts the two lists agree.
L1=( "client-pin"          "python3 tools/client_pin.py --install"
     "clippy"              "cargo clippy --all-targets -- -D warnings"
     "tests"               "cargo test"
     "tests-lens-core"     "cargo test -p ciris-lens-core --lib"
     "noise-floor"         "cargo test --test noise_floor -- --nocapture" )
# The genesis checks default to `sqlite::memory:`, so running them bare here
# would duplicate the `tests` lane and prove nothing about Postgres. The wrapper
# supplies a database (yours via CIRIS_TEST_DSN, else a throwaway container) and
# REFUSES if it cannot — a skip that prints ok is how CIRISServer#381 shipped.
if [ "$FAST" = "0" ]; then
  L1+=( "genesis-postgres" \
        "scripts/with_test_postgres.sh cargo test --test genesis_bundle_validate -- --test-threads=1" )
fi

L2=( "clippy-python"       "cargo clippy --lib --features python -- -D warnings" )

L3=( "clippy-test-anchor"  "cargo clippy --all-targets --features test-anchor -- -D warnings" )
if [ "$FAST" = "0" ]; then
  L3+=( "trace-round+trust-root" \
        "cargo test --features test-anchor --test trace_round_e2e --test trust_root_qa" )
fi

# Lane 4 builds nothing, so it needs no target dir and always runs alongside.
L4=( "rustfmt"             "cargo fmt --all --check"
     "evidence"            "python3 tools/check_evidence.py"
     # The #38 ratchet. Lives here with the other python guards rather than in a
     # cargo lane: it builds nothing, so it costs a subprocess. The ceiling must
     # match ci.yml — a preflight that passes what CI fails is worse than no
     # preflight, because it teaches people to trust it.
     "cohort-scope"        "python3 tools/audit_cohort_scope_callers.py --max-federation 43"
     "localization"        "python3 tools/check_server_localization.py --strict"
     "release-gates"       "CARGO_TARGET_DIR=target/pf-default cargo test --test release_gates" )

if [ "$SEQUENTIAL" = "1" ]; then
  lane target/pf-default "${L1[@]}"
  lane target/pf-python  "${L2[@]}"
  lane target/pf-anchor  "${L3[@]}"
  lane ""                "${L4[@]}"
else
  lane target/pf-default "${L1[@]}" &
  lane target/pf-python  "${L2[@]}" &
  lane target/pf-anchor  "${L3[@]}" &
  lane ""                "${L4[@]}" &
  wait
fi

# ── report ────────────────────────────────────────────────────────────────
FAILED=(); RAN=0
for f in "$LOG"/*.rc; do
  [ -e "$f" ] || continue
  RAN=$((RAN+1))
  name=$(basename "$f" .rc)
  if [ "$(cat "$f")" != "0" ]; then FAILED+=("$name"); fi
done

for n in "${FAILED[@]}"; do
  printf '\n\033[31m── FAILED: %s\033[0m\n' "$n"
  tail -30 "$LOG/$n.out" | sed 's/^/    /'
done

printf '\n\033[1m%d check(s) run in %ds, %d failed\033[0m\n' "$RAN" "$((SECONDS-START))" "${#FAILED[@]}"

# A zero denominator is the error, not a pass — the same rule the release ladder
# applies to itself. If nothing ran, something is wrong with this script.
if [ "$RAN" -eq 0 ]; then
  printf '\033[31mpreflight ran ZERO checks — that is a failure, not a pass\033[0m\n'
  exit 1
fi
if [ "${#FAILED[@]}" -gt 0 ]; then
  printf '\033[31m  %s\033[0m\n' "${FAILED[@]}"
  exit 1
fi
printf '\033[32mpreflight clean — safe to push\033[0m\n'
