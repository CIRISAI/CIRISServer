#!/usr/bin/env bash
# mesh-repro probe — watch both nodes for the DELIVERY state and print a verdict.
#
# SUCCESS  = the round completed: an attributed frame reached the canonical's
#            dispatch_inbound AND a KEX / envelope shows on the agent.
# REPRO    = the failing state: canonical links establish, then die of
#            keepalive_timeout with the round never completing (0 envelopes).
# STALLED  = no link ever established (an EARLIER-layer problem — routing/heal).
#
# Reads `docker compose logs`, so it needs the stack already `up`. run.sh calls
# this after bringing the stack up.
set -uo pipefail

WINDOW_SECS="${1:-180}"    # how long to watch before verdicting
PROJECT="ciris-mesh-repro"

compose() { docker compose -p "$PROJECT" "$@"; }

logs() { compose logs --no-color "$@" 2>/dev/null; }

count() { logs | grep -icE "$1" 2>/dev/null || true; }

echo "── mesh-repro probe: watching ${WINDOW_SECS}s ─────────────────────────────"
deadline=$(( $(date +%s) + WINDOW_SECS ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  estab=$(count 'LINK_ESTAB|LinkEstablished|link.*established')
  died=$(count 'LINK_DIED|keepalive_timeout')
  heal=$(count 'route HEALED|HEALED from a verified announce')
  inbound=$(count 'dispatch_inbound|source_key_id=[a-z].*attribut|inbound.*frame.*applied')
  skipped=$(count 'SkippedNoSourceKeyId|source_key_id=None')
  kex=$(count 'KEX PRESENT|kex.*present|KEX established|shared_secret')
  env=$(count 'envelopes_sent|envelope.*delivered|round complete|IdentityOccurrence.*applied')
  printf '\r  heal=%s estab=%s died=%s inbound=%s skipped=%s kex=%s env=%s   ' \
         "$heal" "$estab" "$died" "$inbound" "$skipped" "$kex" "$env"
  # Early SUCCESS exit
  if [ "${kex:-0}" -gt 0 ] || [ "${env:-0}" -gt 0 ] || [ "${inbound:-0}" -gt 0 ]; then
    echo; echo "── VERDICT: SUCCESS — round reached the canonical (kex/env/inbound > 0) ──"
    echo "   the zero-loss local round COMPLETES → the remote failure is packet-loss"
    echo "   resilience of the resource transfer, not a coordinator bug."
    exit 0
  fi
  sleep 5
done
echo

estab=$(count 'LINK_ESTAB|LinkEstablished|link.*established')
died=$(count 'LINK_DIED|keepalive_timeout')
env=$(count 'envelopes_sent|envelope.*delivered|round complete')

if [ "${estab:-0}" -gt 0 ] && [ "${died:-0}" -gt 0 ] && [ "${env:-0}" -eq 0 ]; then
  echo "── VERDICT: REPRO — links establish (${estab}) then die keepalive_timeout (${died}), 0 envelopes ──"
  echo "   the state is reproduced with ZERO loss → it is NOT remote packet loss;"
  echo "   it is a real coordinator/resource-send-over-link bug. Dig from here:"
  echo "     docker compose -p $PROJECT logs agent     | grep -iE 'send_resource|resource|LINK_DIED|coordinator'"
  echo "     docker compose -p $PROJECT logs canonical | grep -iE 'dispatch_inbound|source_key_id|resource'"
  exit 2
elif [ "${estab:-0}" -eq 0 ]; then
  echo "── VERDICT: STALLED — no canonical link ever established ──"
  echo "   the blocker is BELOW the round (routing/heal/attribution). Check:"
  echo "     docker compose -p $PROJECT logs agent | grep -iE 'route HEALED|no route|LINK_REQUEST_TX|seeded'"
  echo "   If 'seeded=0', the agent isn't targeting THIS canonical — see README §Fidelity."
  exit 3
else
  echo "── VERDICT: INCONCLUSIVE within ${WINDOW_SECS}s (estab=${estab} died=${died} env=${env}) ──"
  echo "   re-run with a longer window:  ./probe.sh 360"
  exit 4
fi
