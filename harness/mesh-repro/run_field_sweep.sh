#!/usr/bin/env bash
# Field KEX-none RCA — loss sweep.
#
# The field failure (ciris-agent-bootstrap-4lf56coiez: knows_peer=true,
# kex_present=false on Node A/0.5.126) could NOT be reproduced on a zero-loss
# bridge: with advisory-admit + verified NAT, the reverse IdentityOccurrence
# round completes via the v13.4.0 #353-ask-2 link-packet reply (kex resolves).
# The one variable a Docker bridge can't express is the field's lossy NAT'd
# mobile link. This sweep adds `tc netem` loss to the field topology at rising
# rates and records, per rate, whether KEX resolves and how long it took — the
# threshold where the round collapses is the RCA.
#
#   ./run_field_sweep.sh                 # default rates 0 10 20 30 40 50 60
#   LOSS_RATES="0 25 50 75" ./run_field_sweep.sh
#   DELAY_MS=150 JITTER_MS=40 ./run_field_sweep.sh   # add base latency too
#   WINDOW=180 ./run_field_sweep.sh
set -uo pipefail
cd "$(dirname "$0")"

PROJECT="ciris-mesh-repro-sweep"
WINDOW="${WINDOW:-150}"
DELAY_MS="${DELAY_MS:-0}"
JITTER_MS="${JITTER_MS:-0}"
LOSS_RATES="${LOSS_RATES:-0 10 20 30 40 50 60}"
export CIRIS_SERVER_VERSION="${CIRIS_SERVER_VERSION:-0.5.126}"
export CIRIS_HARNESS_LIFECYCLE=true   # agent prints [DELIVERY-STATUS] → kex grep works
FILES=(-f docker-compose.yml -f docker-compose.field.yml)

compose() { docker compose "${FILES[@]}" -p "$PROJECT" "$@"; }
logs() { compose logs --no-color 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g'; }

cleanup() { compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "── FIELD LOSS SWEEP — ciris-server==${CIRIS_SERVER_VERSION}, window=${WINDOW}s/rate,"
echo "   delay=${DELAY_MS}ms jitter=${JITTER_MS}ms, rates=[${LOSS_RATES}] ──"
compose build >/dev/null

declare -a ROWS
for loss in $LOSS_RATES; do
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  FIELD_LOSS="$loss" FIELD_DELAY="$DELAY_MS" FIELD_JITTER="$JITTER_MS" compose up -d >/dev/null 2>&1

  # Readiness gate — POLL (don't race a fixed sleep; the heavy py+rust image
  # can take >10s to reach the NETEM log line, which falsely read NOT-ARMED).
  # Wait up to 40s for ONE of: agent exited (STACK-FAILED) | netem VERIFIED
  # (loss>0) | federation delivery started (loss==0). No-silent-degrade intact.
  ready=""; failed=""
  rdeadline=$(( $(date +%s) + 40 ))
  while [ "$(date +%s)" -lt "$rdeadline" ]; do
    astate=$(compose ps agent --format '{{.State}}' 2>/dev/null | head -1)
    if [ "$astate" != "running" ] && [ -n "$astate" ]; then failed="$astate"; break; fi
    L=$(logs)
    if [ "$loss" = "0" ]; then
      grep -q "federation delivery started" <<<"$L" && { ready=1; break; }
    else
      grep -qE "NETEM:.*loss=${loss}(\.[0-9]+)?%.*VERIFIED" <<<"$L" && { ready=1; break; }
      grep -q "NETEM FATAL\|NAT-SIM FATAL" <<<"$L" && { failed="netem/nat-fatal"; break; }
    fi
    sleep 3
  done
  if [ -n "$failed" ]; then
    tail=$(compose logs --no-color --tail 3 agent 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' | tr '\n' '|')
    ROWS+=("$(printf '%3s%%   STACK-FAILED   agent=%s   %s' "$loss" "$failed" "$tail")")
    printf '  loss %3s%% → STACK-FAILED (%s)\n' "$loss" "$failed"
    continue
  fi
  if [ -z "$ready" ]; then
    ROWS+=("$(printf '%3s%%   NOT-READY (no netem/delivery line in 40s — inconclusive)' "$loss")")
    printf '  loss %3s%% → NOT READY in 40s (inconclusive, not counted as KEX result)\n' "$loss"
    continue
  fi

  # Poll for kex_present:true up to the window; record time-to-KEX or TIMEOUT.
  t0=$(date +%s); kex=""; adv=""
  deadline=$(( t0 + WINDOW ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    L=$(logs)
    [ -z "$adv" ] && grep -qE "provenance=Advisory" <<<"$L" && adv="yes"
    if grep -qE '"kex_present":true' <<<"$L"; then kex=$(( $(date +%s) - t0 )); break; fi
    sleep 4
  done

  if [ -n "$kex" ]; then
    ROWS+=("$(printf '%3s%%   KEX ok @ %ss        advisory=%s' "$loss" "$kex" "${adv:-no}")")
    printf '  loss %3s%% → KEX resolved @ %ss\n' "$loss" "$kex"
  else
    last=$(logs | grep '\[DELIVERY-STATUS\]' | tail -1 | grep -oE '"kex_present":[a-z]+,"key_id":"[^"]+","knows_peer":[a-z]+')
    ROWS+=("$(printf '%3s%%   KEX-NONE (timeout %ss)  advisory=%s  last=%s' "$loss" "$WINDOW" "${adv:-no}" "${last:-none}")")
    printf '  loss %3s%% → KEX-NONE after %ss  ← REPRODUCED\n' "$loss" "$WINDOW"
  fi
done

echo
echo "══ FIELD LOSS SWEEP — RCA table (advisory+NAT+loss, v13.4.0) ═══════════════"
printf ' loss   result\n'
printf ' %s\n' "${ROWS[@]}"
echo "════════════════════════════════════════════════════════════════════════════"
echo "Read: the lowest loss rate showing KEX-NONE is the round's collapse threshold."
echo "That the field (real mobile link) sits above it = the reproduced RCA."
