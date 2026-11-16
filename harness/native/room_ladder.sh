#!/usr/bin/env bash
# The room ladder: N runs of `big_room` on ONE test-anchor binary, then a
# side-by-side report (harness/native/room_report.py).
#
#   harness/native/room_ladder.sh [runs=3] [out-dir]
#     ROOM_N=6 ROOM_CONTACTS=mesh|star ROOM_LIMIT=<n|none> ROOM_OWNER_PREWAIT=0|1
#     CARGO_TARGET_DIR=…   the target to build in (default: target)
#     BIN_CACHE=…          where built binaries are kept (default: <out-dir>/../room-bin)
#     KEEP_HOMES=1         keep each node's home (stores, keys) after its run
#
# The binary is built once per source state: it is copied to
# BIN_CACHE/ciris-server-<hash>, the hash taken over src/, crates/, Cargo.toml and
# Cargo.lock, so a second ladder on the same tree starts at once, and a run
# can be repeated later on the exact binary it used. Runs are sequential (the
# box's CPU is part of what a seat's timing measures). After each run the
# nodes are stopped and their homes removed (logs, report and timeline kept).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
RUNS=${1:-3}
OUT=${2:-$ROOT/target/room-ladder/$(date -u +%Y%m%dT%H%M%SZ)}
TARGET=${CARGO_TARGET_DIR:-$ROOT/target}
BIN_CACHE=${BIN_CACHE:-$(dirname "$OUT")/room-bin}
mkdir -p "$OUT" "$BIN_CACHE"
cd "$ROOT" || exit 2

hash=$( (git ls-files -s src crates Cargo.toml Cargo.lock; git diff HEAD -- src crates Cargo.toml Cargo.lock) \
        | sha256sum | cut -c1-16)
BIN="$BIN_CACHE/ciris-server-$hash"
if [ ! -x "$BIN" ]; then
  echo "building the test-anchor binary for source state $hash"
  GUARD=${CARGO_GUARD:-$HOME/CIRISPersist/scripts/cargo_guard.sh}
  run_cargo() { if [ -x "$GUARD" ]; then "$GUARD" cargo "$@"; else cargo "$@"; fi; }
  CARGO_TARGET_DIR="$TARGET" run_cargo build --features test-anchor --bin ciris-server \
      --example test_ceremony_anchor || exit 2
  cp "$TARGET/debug/ciris-server" "$BIN.tmp" && mv "$BIN.tmp" "$BIN"
  mkdir -p "$BIN_CACHE/examples"
  cp "$TARGET/debug/examples/test_ceremony_anchor" "$BIN_CACHE/examples/" 2>/dev/null || true
else
  echo "reusing $BIN"
fi

echo "ladder: $RUNS run(s) of big_room, ROOM_N=${ROOM_N:-6} contacts=${ROOM_CONTACTS:-mesh} -> $OUT"
dirs=()
for i in $(seq 1 "$RUNS"); do
  w="$OUT/run$i"
  dirs+=("$w")
  echo "── run $i/$RUNS  $(date -u +%H:%M:%SZ)"
  timeout "${RUN_TIMEOUT:-3600}" python3 -m harness.native big_room --binary "$BIN" --work "$w" --keep \
      --owner-wait "${OWNER_WAIT:-900}" \
      --rust-log "${RUST_LOG_LADDER:-info,ciris_server::room_seat=debug}" > "$w.log" 2>&1
  rc=$?
  python3 -m harness.native down --work "$w" > /dev/null 2>&1
  grep -m1 '"verdict"' "$w.log" | tr -d ' ' || true
  echo "   rc=$rc  log=$w.log"
  if [ "${KEEP_HOMES:-0}" != "1" ]; then
    for home in "$w"/*/home; do [ -d "$home" ] && rm -rf "$home"; done
  fi
done
python3 -m harness.native.room_report "${dirs[@]}" --csv | tee "$OUT/summary.txt"
