#!/usr/bin/env bash
# Canonical-scale KEX-none RCA — concurrent-peer load sweep.
#
# Reproduces the field variable a 2-node bridge can't: ~85 concurrent peers
# contending for the canonical's per-peer round scheduler. Brings up ONE
# canonical + ONE measured PROBE (field topology: advisory admit + NAT, clean
# link — so any KEX failure is contention, not network) + N blessed LOAD agents
# each driving their own rounds. Sweeps N and records the probe's time-to-KEX
# (or KEX-none). A KEX time that climbs with N — or flips to KEX-none past a
# threshold — is the reproduced RCA and localizes the fix to canonical round
# fairness / resource-transfer scheduling under load.
#
#   ./run_load_repro.sh                  # default N = 0 20 40 60
#   SIZES="0 40 80" ./run_load_repro.sh
#   WINDOW=200 ./run_load_repro.sh       # probe KEX deadline per level
set -uo pipefail
cd "$(dirname "$0")"

PROJECT="ciris-mesh-repro-load"
WINDOW="${WINDOW:-180}"
SIZES="${SIZES:-0 20 40 60}"
export CIRIS_SERVER_VERSION="${CIRIS_SERVER_VERSION:-0.5.126}"
export CIRIS_HARNESS_LIFECYCLE=true   # the PROBE prints [DELIVERY-STATUS]
FILES=(-f docker-compose.yml -f docker-compose.field.yml -f docker-compose.load.yml)

compose() { docker compose "${FILES[@]}" -p "$PROJECT" "$@"; }
plogs() { compose logs --no-color agent 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g'; }  # probe only

cleanup() { compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "── CANONICAL-SCALE SWEEP — ciris-server==${CIRIS_SERVER_VERSION}, probe window=${WINDOW}s/level,"
echo "   probe=advisory+NAT (clean link), load sizes=[${SIZES}] ──"
compose build >/dev/null

declare -a ROWS
for n in $SIZES; do
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  # Probe stays 1; scale the load pool to N.
  compose up -d --scale load-agent="$n" >/dev/null 2>&1

  # Probe readiness: netem/nat verified OR delivery started (poll, don't race).
  ready=""; failed=""
  rdeadline=$(( $(date +%s) + 60 ))
  while [ "$(date +%s)" -lt "$rdeadline" ]; do
    pstate=$(compose ps agent --format '{{.State}}' 2>/dev/null | head -1)
    if [ "$pstate" != "running" ] && [ -n "$pstate" ]; then failed="$pstate"; break; fi
    grep -q "federation delivery started" <<<"$(plogs)" && { ready=1; break; }
    sleep 4
  done
  if [ -n "$failed" ]; then
    ROWS+=("$(printf 'N=%3s   PROBE-FAILED (%s)' "$n" "$failed")")
    printf '  N=%3s → PROBE FAILED (%s)\n' "$n" "$failed"; continue
  fi
  # Count load peers the canonical actually rooted (contention is only real if
  # they're up) — report it so a level with fewer live peers is visible.
  live=$(compose ps load-agent --format '{{.State}}' 2>/dev/null | grep -c running)

  # Poll the probe's delivery-status for kex_present:true.
  t0=$(date +%s); kex=""
  deadline=$(( t0 + WINDOW ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -qE '"kex_present":true' <<<"$(plogs)"; then kex=$(( $(date +%s) - t0 )); break; fi
    sleep 4
  done

  if [ -n "$kex" ]; then
    ROWS+=("$(printf 'N=%3s (live=%3s)   KEX ok @ %ss' "$n" "$live" "$kex")")
    printf '  N=%3s (live=%s) → probe KEX @ %ss\n' "$n" "$live" "$kex"
  else
    last=$(plogs | grep '\[DELIVERY-STATUS\]' | tail -1 | grep -oE '"kex_present":[a-z]+,"key_id":"[^"]+","knows_peer":[a-z]+')
    ROWS+=("$(printf 'N=%3s (live=%3s)   KEX-NONE (%ss)  last=%s' "$n" "$live" "$WINDOW" "${last:-none}")")
    printf '  N=%3s (live=%s) → probe KEX-NONE after %ss  ← REPRODUCED\n' "$n" "$live" "$WINDOW"
  fi
done

echo
echo "══ CANONICAL-SCALE SWEEP — RCA table (probe advisory+NAT, v13.4.0) ═════════"
printf ' load    result\n'
printf ' %s\n' "${ROWS[@]}"
echo "════════════════════════════════════════════════════════════════════════════"
echo "Read: probe KEX time rising with N (or → KEX-NONE) = canonical contention"
echo "reproduced. That localizes the fix to per-peer round/resource scheduling."
