#!/usr/bin/env bash
# Keep the KMP client's CLIENT_VERSION in lockstep with the release version
# (Cargo.toml [package] version) so the node-vs-client "update recommended"
# banner never false-fires on a wheel-bundled local node.
#
# ONE source of truth, TWO callers (DRY):
#   • .git/hooks/pre-commit          → syncs + re-stages on a version-bump commit
#   • build-wheels.yml (CI, --check) → FAILS if the committed value drifted
#
# CI must NEVER mutate source at build time: the desktop JAR is a Compose/Kotlin
# compile, and CLIENT_VERSION is a `const val` in the foundational commonMain
# module — editing it in CI recompiled the whole client every leg and defeated
# the gradle cache warm→tag (CIRISServer#272). Committed-source-authoritative +
# a CI check keeps the cache warm and the tree honest.
#
#   scripts/sync-client-version.sh           # write the version into the source
#   scripts/sync-client-version.sh --check   # exit 1 if it differs (CI gate)
set -euo pipefail
cd "$(dirname "$0")/.."

CV=$(grep -m1 '^version = ' Cargo.toml | sed -E 's/^version = "([^"]+)".*/\1/')
CVF="client/shared/src/commonMain/kotlin/ai/ciris/mobile/shared/models/ClientMode.kt"
CUR=$(grep -m1 'const val CLIENT_VERSION' "$CVF" | sed -E 's/.*"([^"]*)".*/\1/')

if [ "${1:-}" = "--check" ]; then
  if [ "$CUR" != "$CV" ]; then
    echo "CLIENT_VERSION drift: $CVF has '$CUR' but Cargo.toml is '$CV'." >&2
    echo "Run: scripts/sync-client-version.sh && git add $CVF" >&2
    exit 1
  fi
  echo "CLIENT_VERSION ok ($CV)"
  exit 0
fi

if [ "$CUR" = "$CV" ]; then
  echo "CLIENT_VERSION already $CV — no change"
  exit 0
fi
# portable in-place (GNU + BSD/macOS both accept -i.bak)
sed -i.bak "s/const val CLIENT_VERSION = \"[^\"]*\"/const val CLIENT_VERSION = \"$CV\"/" "$CVF"
rm -f "$CVF.bak"
echo "synced CLIENT_VERSION: $CUR -> $CV"
