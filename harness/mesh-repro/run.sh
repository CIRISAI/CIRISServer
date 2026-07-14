#!/usr/bin/env bash
# mesh-repro — one command: build, boot the two-node mesh, probe, verdict.
#
#   ./run.sh                       # version 0.5.113, 180s watch
#   CIRIS_SERVER_VERSION=0.5.114 ./run.sh
#   ./run.sh 360                   # longer watch window
#   KEEP=1 ./run.sh                # leave the stack up after the verdict
set -euo pipefail
cd "$(dirname "$0")"

PROJECT="ciris-mesh-repro"
WINDOW="${1:-180}"
export CIRIS_SERVER_VERSION="${CIRIS_SERVER_VERSION:-0.5.113}"

compose() { docker compose -p "$PROJECT" "$@"; }

cleanup() {
  if [ "${KEEP:-0}" = "1" ]; then
    echo "── KEEP=1: stack left up. Tear down with: docker compose -p $PROJECT down -v"
  else
    echo "── tearing down (set KEEP=1 to keep the stack) ──"
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "── mesh-repro: ciris-server==${CIRIS_SERVER_VERSION} ──────────────────────"
compose down -v --remove-orphans >/dev/null 2>&1 || true
compose build
compose up -d

echo "── waiting for the canonical to become healthy ──"
for _ in $(seq 1 24); do
  state=$(compose ps canonical --format '{{.Health}}' 2>/dev/null || echo "")
  [ "$state" = "healthy" ] && break
  sleep 5
done

set +e
./probe.sh "$WINDOW"
verdict=$?
set -e

echo
echo "── last 20 log lines each (for context) ──────────────────────────────────"
echo "### canonical ###"; compose logs --no-color --tail 20 canonical 2>/dev/null | sed 's/^/  /'
echo "### agent ###";     compose logs --no-color --tail 20 agent     2>/dev/null | sed 's/^/  /'

exit "$verdict"
