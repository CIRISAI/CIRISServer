#!/usr/bin/env bash
# Boot the BUILT artifact and ask it what it serves (CIRISServer#439).
#
# WHY THIS EXISTS
#
# 0.5.178 shipped, and then two people spent an afternoon arguing about whether
# the binary contained `web_signin` — one running `strings` on the release asset,
# one running `strings` on a local rebuild, both reasoning from a proxy. Nobody
# could answer the only question that mattered: *what does the shipped artifact
# actually return?* The release workflow built, signed, uploaded and published
# without ever once asking the thing it produced to respond.
#
# `strings` is not the contract. The response is. So this boots the artifact and
# reads the JSON, which takes seconds and cannot be argued with.
#
# This is the same distinct-zeroes rule the rest of the tree follows: "we built
# it" must not be allowed to read as "we shipped what we built".
set -euo pipefail

BIN="${1:?usage: verify_release_surface.sh <path-to-ciris-server-binary>}"
[[ -x "$BIN" ]] || { echo "not executable: $BIN" >&2; exit 2; }

HOME_DIR="$(mktemp -d -t ciris-relverify-XXXXXX)"
LOG="$HOME_DIR/boot.log"
cleanup() { [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null || true; }
trap cleanup EXIT

"$BIN" --home "$HOME_DIR" >"$LOG" 2>&1 &
PID=$!

# The node binds after migrations + genesis validation; 90s is generous on a
# cold CI runner and still fails fast on a binary that will never bind.
ADDR=""
for _ in $(seq 1 90); do
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "FAIL: the artifact exited during boot" >&2; tail -30 "$LOG" >&2; exit 1
  fi
  ADDR="$(grep -oE 'listen_addr: "[0-9.]+:[0-9]+"' "$LOG" | tail -1 | grep -oE '[0-9]+$' || true)"
  [[ -n "$ADDR" ]] && curl -sf --max-time 3 "http://127.0.0.1:$ADDR/v1/health" >/dev/null 2>&1 && break
  sleep 1
done
[[ -n "$ADDR" ]] || { echo "FAIL: artifact never reported a listen address" >&2; tail -30 "$LOG" >&2; exit 1; }

fail=0
check() { # <path> <jq-filter> <human name>
  local body
  body="$(curl -sf --max-time 8 "http://127.0.0.1:$ADDR$1" 2>/dev/null || true)"
  if [[ -z "$body" ]]; then
    echo "  FAIL  $1 did not answer" >&2; fail=1; return
  fi
  if jq -e "$2" >/dev/null 2>&1 <<<"$body"; then
    echo "  ok    $3"
  else
    echo "  FAIL  $3 — $1 returned: ${body:0:220}" >&2; fail=1
  fi
}

echo "Release surface, read off the running artifact (port $ADDR):"
# Every key a client is DOCUMENTED to read. A release that cannot answer these
# is a release whose adoption instructions are wrong, which is exactly what
# 0.5.178 was accused of and nobody could settle.
check /v1/auth/oauth/providers 'has("web_signin")'         'providers.web_signin'
check /v1/auth/oauth/providers 'has("managed")'            'providers.managed'
check /v1/auth/oauth/providers 'has("callback_base")'      'providers.callback_base'
check /v1/auth/oauth/providers 'has("exchange_query_key")' 'providers.exchange_query_key'
check /v1/auth/signin-state    'has("claimed")'            'signin-state.claimed'
check /v1/auth/signin-state    'has("session_delivery")'   'signin-state.session_delivery'
check /v1/auth/signin-state    '.new_identity | has("outcome")' 'signin-state.new_identity.outcome'

if (( fail )); then
  echo "" >&2
  echo "The artifact does not serve its own documented surface. Do NOT publish it." >&2
  echo "A client told to read these fields would find them absent." >&2
  exit 1
fi
echo "Release surface verified against the running artifact."
