#!/usr/bin/env bash
# ui-chat — stand up canonical + two nodes, each with its own UI, and drive a
# chat from A to B entirely through the interface.
#
#   ./run.sh                 build what is missing, run, tear down
#   KEEP=1 ./run.sh          leave the containers up for inspection
#   SKIP_BUILD=1 ./run.sh    reuse the existing image
set -euo pipefail
cd "$(dirname "$0")"

REPO_ROOT="$(cd ../.. && pwd)"
JAR_SRC_DIR="${CIRIS_CLIENT_JARS:-$HOME/CIRISClient/client/desktopApp/build/compose/jars}"

say() { printf '\n\033[1m── %s ──\033[0m\n' "$*"; }

# ── the node wheel ───────────────────────────────────────────────────────────
# test-anchor, because the SW single-key trust root is what lets a fresh mesh
# root with no operator YubiKeys. Its absence is the wall between this harness
# and a production node, and that is deliberate.
say "node wheel"
mkdir -p wheels
if ! ls wheels/ciris_server-*.whl >/dev/null 2>&1; then
  echo "no wheel in wheels/ — build one first:"
  echo "  cd $REPO_ROOT && cargo build --release --features extension-module,test-anchor"
  echo "  python3 harness/mesh-repro/pack_wheel.py   # writes the wheel"
  echo "then copy it into harness/ui-chat/wheels/"
  exit 1
fi
ls -la wheels/*.whl | sed 's/^/  /'

# ── the client uber-jar ──────────────────────────────────────────────────────
say "desktop uber-jar"
mkdir -p jars
if ! ls jars/*.jar >/dev/null 2>&1; then
  latest=$(ls -t "$JAR_SRC_DIR"/CIRIS-linux-x64-*.jar 2>/dev/null | head -1 || true)
  if [ -z "$latest" ]; then
    echo "no uber-jar found in $JAR_SRC_DIR — build one:"
    echo "  cd \$CIRISCLIENT/client && ./gradlew :desktopApp:packageUberJarForCurrentOS"
    exit 1
  fi
  cp "$latest" jars/
fi
ls -la jars/*.jar | sed 's/^/  /'

# ── up ───────────────────────────────────────────────────────────────────────
say "compose up"
[ "${SKIP_BUILD:-0}" = "1" ] || docker compose build
docker compose up -d
trap '[ "${KEEP:-0}" = "1" ] || { echo; echo "── tearing down ──"; docker compose down -v >/dev/null 2>&1 || true; }' EXIT

say "waiting for both UIs to render"
for port in 9101 9102; do
  ok=0
  for i in $(seq 1 90); do
    n=$(curl -sf --max-time 3 "http://127.0.0.1:$port/tree" 2>/dev/null \
        | python3 -c 'import json,sys;print(json.load(sys.stdin).get("count",0))' 2>/dev/null || echo 0)
    if [ "${n:-0}" -gt 0 ]; then echo "  :$port rendering after ~$((i*4))s"; ok=1; break; fi
    sleep 4
  done
  if [ "$ok" != 1 ]; then
    echo "  ✗ :$port never rendered. Container logs:"
    docker compose logs --tail 40
    exit 1
  fi
done

# ── drive ────────────────────────────────────────────────────────────────────
say "driving the UI"
set +e
python3 drive.py --a-ui 9101 --b-ui 9102 --a-api 14243 --b-api 24243
rc=$?
set -e

say "evidence"
for svc in canonical node-a node-b; do
  echo "  [$svc] $(docker compose logs --tail 3 "$svc" 2>/dev/null | tr '\n' ' ' | cut -c1-150)"
done

exit $rc
