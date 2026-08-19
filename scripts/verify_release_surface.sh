#!/usr/bin/env bash
# Boot the BUILT artifact and ask it what it serves (CIRISServer#439).
#
# WHY THIS EXISTS
#
# 0.5.178 shipped, and then an afternoon went into arguing whether the binary
# contained `web_signin` — one side running `strings` on the release asset, the
# other on a local rebuild, both reasoning from a PROXY. Nobody could answer the
# only question that mattered: what does the shipped artifact actually return?
# release.yml built, stripped, signed, uploaded and published without once
# asking its output to respond.
#
# WHY ITS FIRST VERSION FAILED A RELEASE (0.5.179), AND WHAT CHANGED
#
# v1 discovered the port by grepping the boot log for `listen_addr`. That was
# wrong twice over:
#
#   1. The process's stderr is BLOCK-buffered into a file, so while the node
#      stays alive the log is EMPTY. v1 only ever "worked" locally because the
#      node CRASHED there — exiting flushed the buffer. Its happy path had never
#      once executed, and it was wired to fail the build regardless.
#   2. `net.listen_addr` (:4242) is the RETICULUM transport. The node's entire
#      HTTP interface is :4243 (compose.rs — "this one listener also carries
#      /v1/identity, auth, setup/claim, config, ingest").
#
# So there is no discovery step left to get wrong: readiness IS the endpoint
# under test answering. If it never answers, that is the finding.
set -euo pipefail

# Point at an ALREADY-RUNNING node instead of booting one. This exists so the
# assertion half can be exercised on demand — the reason v1 shipped broken is
# that nothing here had ever run green.
BASE="${CIRIS_VERIFY_BASE_URL:-}"

if [[ -z "$BASE" ]]; then
  BIN="${1:?usage: verify_release_surface.sh <binary>   (or set CIRIS_VERIFY_BASE_URL)}"
  [[ -x "$BIN" ]] || { echo "not executable: $BIN" >&2; exit 2; }
  HOME_DIR="$(mktemp -d -t ciris-relverify-XXXXXX)"
  LOG="$HOME_DIR/boot.log"
  cleanup() { [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null || true; }
  trap cleanup EXIT

  # A 200 FROM A PORT IS NOT PROOF IT IS YOUR NODE (CIRISServer#410).
  #
  # Caught while testing this script: a binary that died instantly still
  # "verified", because an UNRELATED node was already serving :4243 and the
  # readiness probe was answered by a stranger. In CI that silently greenlights
  # a broken artifact against someone else's healthy one — the worst possible
  # failure for a gate whose entire job is proving what THIS build serves.
  #
  # So: nothing may already be answering before we start. If something is, this
  # cannot verify the artifact and says so rather than measuring the wrong
  # process.
  if curl -sf --max-time 3 "http://127.0.0.1:4243/v1/auth/oauth/providers" >/dev/null 2>&1; then
    echo "FAIL: something is ALREADY serving 127.0.0.1:4243 before this artifact booted." >&2
    echo "      Cannot verify this build — any answer would come from that process." >&2
    exit 1
  fi
  # stdbuf keeps the diagnostic log usable while the process is still alive —
  # without it a failure here reports nothing, which is exactly what 0.5.179 did.
  stdbuf -oL -eL "$BIN" --home "$HOME_DIR" >"$LOG" 2>&1 &
  PID=$!
  BASE="http://127.0.0.1:4243"

  ready=0
  for _ in $(seq 1 120); do
    if ! kill -0 "$PID" 2>/dev/null; then
      echo "FAIL: the artifact exited during boot" >&2; tail -40 "$LOG" >&2; exit 1
    fi
    if curl -sf --max-time 3 "$BASE/v1/auth/oauth/providers" >/dev/null 2>&1; then
      # Re-confirm OUR process is the one alive; a stranger binding the port
      # mid-boot must not read as our artifact coming up.
      kill -0 "$PID" 2>/dev/null || {
        echo "FAIL: the artifact died, yet :4243 answered — another process holds it" >&2
        tail -40 "$LOG" >&2; exit 1
      }
      ready=1; break
    fi
    sleep 1
  done
  if (( ! ready )); then
    echo "FAIL: the artifact never served $BASE/v1/auth/oauth/providers within 120s" >&2
    tail -40 "$LOG" >&2; exit 1
  fi
fi

fail=0
check() { # <path> <jq filter> <human name>
  local body
  body="$(curl -sf --max-time 8 "$BASE$1" 2>/dev/null || true)"
  if [[ -z "$body" ]]; then
    echo "  FAIL  $3 — $1 did not answer" >&2; fail=1; return
  fi
  if jq -e "$2" >/dev/null 2>&1 <<<"$body"; then
    echo "  ok    $3"
  else
    echo "  FAIL  $3 — $1 returned: ${body:0:200}" >&2; fail=1
  fi
}

echo "Release surface, read off the running artifact ($BASE):"
check /v1/auth/oauth/providers 'has("web_signin")'             'providers.web_signin'
check /v1/auth/oauth/providers 'has("managed")'                'providers.managed'
check /v1/auth/oauth/providers 'has("callback_base")'          'providers.callback_base'
check /v1/auth/oauth/providers 'has("exchange_query_key")'     'providers.exchange_query_key'
check /v1/auth/signin-state    'has("claimed")'                'signin-state.claimed'
check /v1/auth/signin-state    'has("session_delivery")'       'signin-state.session_delivery'
check /v1/auth/signin-state    '.new_identity|has("outcome")'  'signin-state.new_identity.outcome'

# THE SURFACE BEING PRESENT IS NOT THE FLOW WORKING (CIRISServer#445).
#
# 0.5.180 passed every check above and still could not sign a browser in: the
# callback handed a remote browser the loopback-only hand-off page and minted no
# redemption code. Six hours, three attempts, zero codes — on a node that
# answered `web_signin: true` to this very script.
#
# Asserting a field EXISTS cannot fail in the direction that matters. So drive
# the actual front door: start a flow with NO redirect_uri and NO app_nonce,
# exactly as a GUI does, and require the node to send us somewhere carrying a
# code. A 200 here means the hand-off page came back, which is the defect.
echo "Front-door browser flow:"
# `|| true` on BOTH: under `set -euo pipefail` a grep that matches nothing exits
# 1 and kills the script mid-assignment — which is how the first draft of this
# very block printed NOTHING at all and looked like it had passed. A gate that
# dies silently is worse than no gate.
login_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
  "$BASE/v1/auth/oauth/google/login" 2>/dev/null || true)"
login_hdrs="$(curl -s -o /dev/null -D - --max-time 8 \
  "$BASE/v1/auth/oauth/google/login" 2>/dev/null || true)"
loc="$(printf '%s' "$login_hdrs" | grep -i '^location:' 2>/dev/null | tail -1 | tr -d '\r' | cut -d' ' -f2- || true)"

if [[ -z "$login_code" || "$login_code" == "000" ]]; then
  # THE ENDPOINT DID NOT ANSWER. Distinct from "answered, no provider" — the
  # first is a broken artifact, the second is an unconfigured one, and calling
  # both "skip" is how a silence reads as coverage.
  echo "  FAIL  /login did not answer at all" >&2; fail=1
elif [[ -z "$loc" ]]; then
  # Answered, but did not redirect. TWO different worlds, and the whole point of
  # this block is that they must not share an outcome:
  #
  #   * no provider configured  → genuinely unexercisable, report and move on
  #   * provider configured     → THE #445 DEFECT. A browser asked to sign in and
  #                               got a page instead of a trip to the provider.
  #
  # The providers list is what tells them apart, so ask it rather than guess. A
  # first draft of this check reported BOTH as "skip" and exited 0 — it would
  # have passed the very release it was written for.
  provider_count="$(curl -sf --max-time 8 "$BASE/v1/auth/oauth/providers" 2>/dev/null \
    | jq -r '(.providers // []) | length' 2>/dev/null || echo 0)"
  if [[ "${provider_count:-0}" -gt 0 ]]; then
    echo "  FAIL  /login answered $login_code with NO redirect while $provider_count \
provider(s) are configured — a browser gets a page it cannot use, not a sign-in" >&2
    fail=1
  else
    echo "  skip  /login answered $login_code, no provider configured — not exercised" >&2
  fi
else
  case "$loc" in
    *accounts.google.com*|*oauth*|*authorize*)
      echo "  ok    /login redirects to the provider" ;;
    *)
      echo "  FAIL  /login did not reach a provider: ${loc:0:120}" >&2; fail=1 ;;
  esac
fi

if (( fail )); then
  echo "" >&2
  echo "The artifact does not serve its own documented surface. Do NOT publish it." >&2
  echo "A client told to read these fields would find them absent." >&2
  exit 1
fi
echo "Release surface verified against the running artifact."
