#!/usr/bin/env bash
# mesh-repro #353 — the NAT'd-initiator busy-link scenario, as a verdict.
#
# Reproduces (and, on a fixed edge, verifies the fix for) CIRISEdge#353: a
# responder's round reply to a NAT'd, initiator-only peer must ride the peer's
# existing INBOUND link. The v13.1.0 fix did that for the idle case; the field
# then showed the BUSY-LINK case — when that inbound link is mid resource
# transfer ("resource transfer already in progress"), the reply fell back to an
# outbound dial the NAT blocks, and the link closed `Timeout`.
#
# This scenario forces exactly that: the agent is initiator-only (iptables DROPs
# NEW inbound to its edge port) AND keeps its link to the canonical saturated
# with real trace resource-transfers (the busy-link generator imports fat traces
# that federation delivery seals + ships). The canonical's 15s-cadence round
# reply then collides mid-transfer.
#
#   ./run_353.sh                    # 0.5.113 wheel (pre-fix → REPRO expected)
#   CIRIS_SERVER_VERSION=0.5.122 ./run_353.sh   # v13.1.2-adopting wheel (→ FIXED)
#   ./run_353.sh 240                # longer watch window
#   KEEP=1 ./run_353.sh
set -euo pipefail
cd "$(dirname "$0")"

PROJECT="ciris-mesh-repro"
WINDOW="${1:-200}"
export CIRIS_SERVER_VERSION="${CIRIS_SERVER_VERSION:-0.5.113}"

compose() {
  docker compose -f docker-compose.yml -f docker-compose.353.yml -p "$PROJECT" "$@"
}
logs() { compose logs --no-color "$@" 2>/dev/null; }
cnt()  { logs "$1" 2>/dev/null | grep -icE "$2" 2>/dev/null || true; }

cleanup() {
  if [ "${KEEP:-0}" = "1" ]; then
    echo "── KEEP=1: stack up. Tear down: docker compose -p $PROJECT down -v"
  else
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "── mesh-repro #353 (NAT'd initiator + busy link): ciris-server==${CIRIS_SERVER_VERSION} ──"
compose down -v --remove-orphans >/dev/null 2>&1 || true
compose build
compose up -d

echo "── waiting for the canonical to become healthy ──"
for _ in $(seq 1 24); do
  [ "$(compose ps canonical --format '{{.Health}}' 2>/dev/null || echo '')" = "healthy" ] && break
  sleep 5
done

# Confirm the scenario actually armed — a REPRO/FIXED verdict is only meaningful
# if the agent is genuinely initiator-only AND generating busy-link pressure.
echo "── confirming the #353 preconditions armed ──"
armed_deadline=$(( $(date +%s) + 90 ))
nat_ok=0; busy_ok=0
while [ "$(date +%s)" -lt "$armed_deadline" ]; do
  [ "$(cnt agent 'NAT-SIM: NEW inbound .* DROPPED')" -gt 0 ] && nat_ok=1
  [ "$(cnt agent 'BUSY-LINK: batch')" -gt 0 ] && busy_ok=1
  { [ "$nat_ok" = 1 ] && [ "$busy_ok" = 1 ]; } && break
  sleep 5
done
if [ "$nat_ok" != 1 ] || [ "$busy_ok" != 1 ]; then
  echo "── VERDICT: SCENARIO-NOT-ARMED (nat_sim=${nat_ok} busy_link=${busy_ok}) ──"
  echo "   the container likely lacks NET_ADMIN/root for iptables, or import_traces failed."
  logs agent | grep -iE "NAT-SIM|BUSY-LINK" | tail -6 | sed 's/^/     /'
  exit 5
fi
echo "   armed: initiator-only NAT + busy-link generator both live."

echo "── watching ${WINDOW}s for the reverse-path-busy → Timeout signature ──"
deadline=$(( $(date +%s) + WINDOW ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  revfail=$(cnt canonical 'reverse-path send failed|falling back to outbound dial')
  busy=$(cnt canonical 'resource transfer already in progress')
  timeouts=$(cnt canonical 'link closed: Timeout')
  peerclosed=$(cnt canonical 'link closed: PeerClosed')
  # Fix-side signals (v13.1.2): a reply that rode the inbound link via retry or a
  # plain link packet instead of the blocked dial. Names are tolerant — match any
  # plausible phrasing the fix emits.
  recovered=$(cnt canonical 'reverse-path.*(retr|queued|succeeded|delivered)|reply via link packet|inbound-link reply')
  rounds=$(cnt canonical 'dispatch_inbound|round complete|IdentityOccurrence.*applied|envelope.*delivered')
  printf '\r  revpath_fallback=%s busy_collision=%s Timeout=%s PeerClosed=%s recovered=%s rounds=%s   ' \
         "$revfail" "$busy" "$timeouts" "$peerclosed" "$recovered" "$rounds"
  sleep 5
done
echo; echo

revfail=$(cnt canonical 'reverse-path send failed|falling back to outbound dial')
busy=$(cnt canonical 'resource transfer already in progress')
timeouts=$(cnt canonical 'link closed: Timeout')
peerclosed=$(cnt canonical 'link closed: PeerClosed')
recovered=$(cnt canonical 'reverse-path.*(retr|queued|succeeded|delivered)|reply via link packet|inbound-link reply')
rounds=$(cnt canonical 'dispatch_inbound|round complete|IdentityOccurrence.*applied|envelope.*delivered')

echo "── #353 tallies ──────────────────────────────────────────────────────────"
echo "   reverse-path fallbacks : $revfail"
echo "   busy-link collisions   : $busy"
echo "   Timeout link closes    : $timeouts   (the field failure signature)"
echo "   PeerClosed link closes : $peerclosed  (clean)"
echo "   fix-path recoveries    : $recovered"
echo "   rounds reaching canon  : $rounds"
echo

# ── Verdict ────────────────────────────────────────────────────────────────
# REPRO : the busy collision drives the fallback dial and links die Timeout
#         while round replies stall — the pre-fix field state.
# FIXED : the busy collision is handled (reverse-path retry / link-packet reply)
#         — rounds keep reaching the canonical and Timeout closes do NOT
#         accumulate despite continuous busy-link pressure.
if [ "$busy" -eq 0 ]; then
  echo "── VERDICT: NO-COLLISION — the busy-link generator never collided with a round"
  echo "   reply (busy=0). Increase pressure (NAT353_PAD_KB / lower NAT353_PERIOD_S) or"
  echo "   the window; without a collision this scenario proves nothing about #353."
  exit 4
elif [ "$timeouts" -gt 0 ] && [ "$recovered" -eq 0 ]; then
  echo "── VERDICT: REPRO — busy collision (${busy}) → fallback dial (${revfail}) → ${timeouts} Timeout closes,"
  echo "   no recovery path. This is the CIRISEdge#353 busy-link field state."
  exit 2
elif [ "$recovered" -gt 0 ] || { [ "$rounds" -gt 0 ] && [ "$timeouts" -eq 0 ]; }; then
  echo "── VERDICT: FIXED — busy collision (${busy}) occurred but the reply reached the NAT'd"
  echo "   agent over the inbound link (recovered=${recovered}, rounds=${rounds}, Timeout=${timeouts})."
  echo "   The #353 busy-link case is handled on this wheel."
  exit 0
else
  echo "── VERDICT: INCONCLUSIVE (busy=${busy} timeouts=${timeouts} recovered=${recovered} rounds=${rounds}) ──"
  echo "   re-run with a longer window:  ./run_353.sh 360"
  exit 3
fi
