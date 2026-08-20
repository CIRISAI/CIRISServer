#!/usr/bin/env bash
# TIER 2 — the same four phases, over REAL HTTP against a BOOTED release binary.
#
# `benches/chat_throughput.rs` (Tier 1) drives `contacts_chat::router` in-process:
# real router, real substrate, but one process, one allocator, no boot. This
# drives the SHIPPED artifact — the binary that actually serves people — and
# samples the SERVER process's RSS rather than the driver's. Different question,
# same four phase boundaries: cold start, a warm set, a burst, an idle tail.
#
# ── WHAT THIS LEG CAN AND CANNOT MEASURE (read this before trusting a number) ──
#
# It CANNOT emit chat messages, and it says so in its own output rather than
# quietly benching something easier.
#
# A chat message needs a COMMUNITY, a community needs a CONTACT, and
# `POST /v1/contacts` refuses any key_id that is not already in this node's
# federation directory (`contacts.unknown_fed_id`). Admitting one means
# `POST /v1/federation/peering` — the full federation wire act: the peer's
# hybrid-signed key record, CEG wire-version negotiation, the WIRE_VOCABULARY
# hash pin, and the conformance declaration exchange. A bench harness cannot mint
# that, and the node is right to refuse a key that has none. Self-chat is closed
# too, deliberately: `contacts.self_contact` refuses this node's own identity.
#
# So the emit leg reports `ran: false` with that reason and `messages_emitted: 0`.
# It is never reported as a skip, and never as a pass. What DOES run is the
# owner-authenticated read surface — the owner gate, session resolution, the
# owner-binding check, and the revocation-folded consent-peer projection behind
# `GET /v1/contacts` — driven at the same 100/1000 volumes, which is a real
# measurement of the real binary even though it is not the emit path.
#
# Unblocking it needs a SECOND booted node to peer with (both claimed, A peers B,
# A's owner then adds B's node key as a contact). That is a two-node harness, not
# a flag, which is why this is the honest partial rather than a stub.
#
# ── SAFETY ─────────────────────────────────────────────────────────────────────
#
# CIRIS_HOME is redirected into the temp dir for BOTH the node and the claim CLI.
# Without it `ciris_verify_core::ceg_outbox::keys_dir()` resolves to `~/ciris/keys`
# and a bench run would mint a user fed-ID into the operator's real key store.
#
# Usage:   tools/chat_bench_http.sh <path-to-ciris-server-binary>
# Output:  jsonl on stdout (one object per phase), diagnostics on stderr.
# Knobs:   CHAT_BENCH_WARM (100) CHAT_BENCH_BURST (900) CHAT_BENCH_IDLE_SECS (30)
set -euo pipefail

BIN="${1:?usage: chat_bench_http.sh <ciris-server binary>}"
[[ -x "$BIN" ]] || { echo "not executable: $BIN" >&2; exit 2; }
command -v jq   >/dev/null || { echo "jq is required" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }

WARM="${CHAT_BENCH_WARM:-100}"
BURST="${CHAT_BENCH_BURST:-900}"
IDLE_SECS="${CHAT_BENCH_IDLE_SECS:-30}"

BASE="http://127.0.0.1:4243"
WORK="$(mktemp -d -t ciris-chatbench-XXXXXX)"
NODE_HOME="$WORK/node"
CLAIM_HOME="$WORK/claimer"
LOG="$WORK/boot.log"
mkdir -p "$NODE_HOME" "$CLAIM_HOME" "$WORK/ciris"
export CIRIS_HOME="$WORK/ciris"

fail=0
PID=""
cleanup() { [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true; }
trap cleanup EXIT

emit() { printf '%s\n' "$1"; }
note() { echo "$*" >&2; }

# The FAILING line out of a CLI log, not the last three lines of it.
#
# The first draft used `tail -3`, and the CLI's last three lines are tracing INFO
# about which secure-storage backend it picked — so the reported reason was a
# wall of ANSI escapes that said nothing about the failure while the real line,
# `Error: re-open sealed ML-DSA-65 half …`, sat just above it. A reason nobody
# can read is the same as no reason. Strip ANSI, prefer the `Error:` line.
err_line() {
  local f="$1" cleaned
  cleaned="$(sed -e 's/\x1b\[[0-9;]*m//g' "$f" 2>/dev/null || true)"
  printf '%s' "$cleaned" | grep -E '^(Error|error):' | tail -1 \
    || printf '%s' "$cleaned" | tail -1
}

# A phase that could not run says so, with the reason. Never a silent skip.
emit_not_ran() {
  emit "$(jq -nc --arg phase "$1" --arg reason "$2" \
    '{tier:2, phase:$phase, ran:false, reason:$reason}')"
}

# ── Server-side RSS ────────────────────────────────────────────────────────────
# The number that matters for Tier 2 is the NODE's resident set, not this
# script's. Absent procfs it is null WITH a reason — a zero would read as
# "used no memory", which is the one answer that is never true.
server_rss_kb() {
  if [[ -n "$PID" && -r "/proc/$PID/status" ]]; then
    awk '/^VmRSS:/ {print $2}' "/proc/$PID/status" 2>/dev/null || echo ""
  else
    echo ""
  fi
}
rss_json() {
  local v; v="$(server_rss_kb)"
  if [[ -n "$v" ]]; then jq -nc --argjson v "$v" '{server_rss_kb:$v}'
  else jq -nc '{server_rss_kb:null, rss_reason:"/proc/<pid>/status unreadable — server RSS not sampled"}'
  fi
}

# ── Phase 1: cold start (boot + claim + owner session) ─────────────────────────
#
# A 200 FROM A PORT IS NOT PROOF IT IS YOUR NODE (CIRISServer#410). If anything
# is already answering :4243 we cannot measure this artifact, and any number we
# printed would be some other process's.
if curl -sf --max-time 3 "$BASE/v1/auth/oauth/providers" >/dev/null 2>&1; then
  emit_not_ran cold_start "something is ALREADY serving 127.0.0.1:4243 — any measurement would be of that process, not this artifact"
  for p in warm burst idle emit summary; do emit_not_ran "$p" "cold_start did not boot"; done
  exit 1
fi

cold_t0=$(date +%s.%N)
# stdbuf keeps the boot log readable WHILE the process lives. Without it the log
# sits in a block buffer and a failure here reports nothing — exactly the
# 0.5.179 release-gate defect.
stdbuf -oL -eL "$BIN" --home "$NODE_HOME" >"$LOG" 2>&1 &
PID=$!

ready=0
for _ in $(seq 1 180); do
  if ! kill -0 "$PID" 2>/dev/null; then
    emit_not_ran cold_start "the artifact exited during boot"
    note "--- boot log ---"; tail -40 "$LOG" >&2
    for p in warm burst idle emit summary; do emit_not_ran "$p" "the node never booted"; done
    exit 1
  fi
  if curl -sf --max-time 3 "$BASE/v1/federation/node-code" >/dev/null 2>&1; then
    kill -0 "$PID" 2>/dev/null || {
      emit_not_ran cold_start "the artifact died, yet :4243 answered — another process holds it"
      for p in warm burst idle emit summary; do emit_not_ran "$p" "the node never booted"; done
      exit 1
    }
    ready=1; break
  fi
  sleep 1
done
if (( ! ready )); then
  emit_not_ran cold_start "the artifact never served $BASE/v1/federation/node-code within 180s"
  note "--- boot log ---"; tail -40 "$LOG" >&2
  for p in warm burst idle emit summary; do emit_not_ran "$p" "the node never became ready"; done
  exit 1
fi
rss_boot="$(server_rss_kb)"

# The claim: PIN off disk, NodeCode off the wire, owner-binding minted + signed
# by the CLI's own software fed-ID. `--owner-password` is what leaves a ROOT cert
# we can log in as; without it the claim succeeds and hands back nothing usable.
# The field is `code` (federation_nodecode::render_response_json), NOT `node_code`
# — the request body member the claim POSTs is named `node_code`, the response
# member carrying it is named `code`, and reading the wrong one is silent: jq
# returns empty and the claim simply never happens. The first draft of this
# script did exactly that, and the only reason it did not read as a pass is that
# the phase reported ran:false with the reason instead of skipping.
NODE_CODE="$(curl -sf --max-time 8 "$BASE/v1/federation/node-code" 2>/dev/null | jq -r '.code // empty' || true)"
CLAIM_PIN="$(cat "$NODE_HOME/claim_pin" 2>/dev/null || true)"
OWNER_PASSWORD="bench-$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"

TOKEN=""
if [[ -z "$NODE_CODE" ]]; then
  claim_reason="GET /v1/federation/node-code returned no node_code — the claim cannot be addressed"
elif [[ -z "$CLAIM_PIN" ]]; then
  claim_reason="no claim PIN at $NODE_HOME/claim_pin — the node did not mint one (already claimed?)"
else
  claim_reason=""
  # MINT THE CLAIMING USER'S FED-ID FIRST. `ciris-server claim` OPENS an existing
  # user identity, it never creates one — `hardware_user_local_signer` calls
  # `open_user_signer(.., false)` and then re-opens the sealed ML-DSA-65 half,
  # which fails with "Key not found: mldsa65.seed" on a machine that has never
  # minted one. That is the correct behaviour (a claim must not silently invent
  # the identity it claims as) and it is why this step exists.
  #
  # Both halves land under CIRIS_HOME/keys, which is redirected into the temp dir
  # at the top of this script — nothing touches the operator's real key store.
  if ! "$BIN" identity create --home "$CLAIM_HOME" --backend software \
        >"$WORK/mint.log" 2>&1; then
    claim_reason="ciris-server identity create failed: $(err_line "$WORK/mint.log")"
  elif ! "$BIN" claim \
        --home "$CLAIM_HOME" --backend software \
        --node-code "$NODE_CODE" --claim-pin "$CLAIM_PIN" \
        --target-url "$BASE" --cohort-scope self \
        --owner-username benchowner --owner-password "$OWNER_PASSWORD" \
        >"$WORK/claim.log" 2>&1; then
    claim_reason="ciris-server claim failed: $(err_line "$WORK/claim.log")"
  else
    TOKEN="$(curl -sf --max-time 10 -X POST "$BASE/v1/auth/login" \
      -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg u benchowner --arg p "$OWNER_PASSWORD" '{username:$u,password:$p}')" \
      2>/dev/null | jq -r '.access_token // empty' || true)"
    [[ -n "$TOKEN" ]] || claim_reason="claim accepted but POST /v1/auth/login minted no access_token"
  fi
fi

cold_t1=$(date +%s.%N)
cold_ms="$(awk -v a="$cold_t0" -v b="$cold_t1" 'BEGIN{printf "%.3f",(b-a)*1000}')"

if [[ -n "$claim_reason" ]]; then
  emit "$(jq -nc --arg ms "$cold_ms" --arg reason "$claim_reason" --argjson rss "$(rss_json)" \
    '{tier:2, phase:"cold_start", ran:false, reason:$reason, boot_and_claim_ms:($ms|tonumber)} + $rss')"
  for p in warm burst idle summary; do emit_not_ran "$p" "no owner session: $claim_reason"; done
  emit_not_ran emit "no owner session: $claim_reason"
  exit 1
fi
emit "$(jq -nc --arg ms "$cold_ms" --arg rb "${rss_boot:-}" --argjson rss "$(rss_json)" \
  '{tier:2, phase:"cold_start", ran:true,
    what:"release binary booted --home <tmp>, claimed via the CLI 1-phase claim, owner session minted",
    boot_and_claim_ms:($ms|tonumber),
    server_rss_at_ready_kb:(if $rb=="" then null else ($rb|tonumber) end)} + $rss')"

# ── The load generator ─────────────────────────────────────────────────────────
#
# ONE curl process for the whole batch, driving N URLs over a reused connection —
# the same sequential-pipeline shape Tier 1's reqwest loop has, so the two tiers'
# latency numbers are comparable. Per-request curl spawns would have measured
# process creation instead.
run_batch() { # <count> <path> → writes "<http_code> <seconds>" per request to stdout
  local n="$1" path="$2" cfg="$WORK/urls.txt"
  : >"$cfg"
  # BOTH lines per request. curl pairs the Nth `output` with the Nth `url`; a
  # single command-line `-o` would cover only the FIRST transfer and dump the
  # other 999 response bodies onto stdout, interleaved with the timing lines we
  # are trying to read.
  for ((i=0; i<n; i++)); do
    printf 'output = "/dev/null"\nurl = "%s%s"\n' "$BASE" "$path" >>"$cfg"
  done
  # %{http_code} IS LOAD BEARING. Without it a run of 1000 401s measures the same
  # as a run of 1000 200s — faster, in fact, since a refusal never reaches the
  # store — and the bench would report its best throughput on the day the owner
  # session broke. The caller refuses any batch that is not all-200.
  curl -s -K "$cfg" \
    -H "Authorization: Bearer $TOKEN" \
    -w '%{http_code} %{time_total}\n' 2>/dev/null || true
}

# min / p50 / p95 / max over stdin seconds → a JSON object in ms.
lat_json() {
  sort -g | awk '
    {v[NR]=$1*1000}
    END{
      if (NR==0) { print "{\"samples\":0,\"min_ms\":null,\"p50_ms\":null,\"p95_ms\":null,\"max_ms\":null}"; exit }
      p50=v[int((NR-1)*0.50)+1]; p95=v[int((NR-1)*0.95)+1];
      printf "{\"samples\":%d,\"min_ms\":%.3f,\"p50_ms\":%.3f,\"p95_ms\":%.3f,\"max_ms\":%.3f}", NR, v[1], p50, p95, v[NR]
    }'
}

phase_load() { # <phase> <count>
  local phase="$1" n="$2" t0 t1 secs
  t0=$(date +%s.%N)
  run_batch "$n" "/v1/contacts" >"$WORK/$phase.raw"
  t1=$(date +%s.%N)
  secs="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.6f",(b-a)}')"
  local got; got="$(wc -l <"$WORK/$phase.raw" | tr -d ' ')"
  if [[ "$got" != "$n" ]]; then
    emit_not_ran "$phase" "$got of $n requests answered — the load leg did not complete"
    fail=1; return 1
  fi
  local not200; not200="$(awk '$1 != 200 {c[$1]++} END{for (k in c) printf "%s×%d ", k, c[k]}' "$WORK/$phase.raw")"
  if [[ -n "$not200" ]]; then
    emit_not_ran "$phase" "not every request was answered 200 (${not200% }) — a refused request is cheaper than a served one, so these timings would flatter the node rather than measure it"
    fail=1; return 1
  fi
  awk '{print $2}' "$WORK/$phase.raw" >"$WORK/$phase.lat"
  emit "$(jq -nc \
      --arg phase "$phase" --argjson n "$n" --arg secs "$secs" \
      --argjson lat "$(lat_json <"$WORK/$phase.lat")" --argjson rss "$(rss_json)" \
      '{tier:2, phase:$phase, ran:true,
        surface:"GET /v1/contacts (owner gate + owner-binding check + revocation-folded consent-peer projection)",
        requests:$n,
        seconds:($secs|tonumber),
        requests_per_sec:(if ($secs|tonumber) > 0 then (($n/($secs|tonumber))*1000|round/1000) else null end),
        request_latency:$lat} + $rss')"
}

# ── Phases 2 + 3: warm, then burst ─────────────────────────────────────────────
rss_cold="$(server_rss_kb)"
phase_load warm  "$WARM"  || true
rss_warm="$(server_rss_kb)"
phase_load burst "$BURST" || true
rss_burst="$(server_rss_kb)"

# ── The emit leg — reported, never skipped ─────────────────────────────────────
emit "$(jq -nc '{
  tier:2, phase:"emit", ran:false, messages_emitted:0,
  reason:"a chat message needs a community, a community needs a contact, and POST /v1/contacts refuses a key_id absent from the federation directory (contacts.unknown_fed_id). Admitting one is POST /v1/federation/peering — a hybrid-signed peer key record, CEG wire-version negotiation and a conformance exchange, which this harness cannot mint. Self-chat is refused by design (contacts.self_contact).",
  unblocked_by:"a two-node harness: boot + claim a second node, A peers B, A owner adds B node key as a contact",
  measured_instead:"the owner-authenticated read surface at the same 100/1000 volumes (see the warm/burst phases)"
}')"

# ── Phase 4: idle tail ─────────────────────────────────────────────────────────
idle_samples="[]"
elapsed=0
while (( elapsed < IDLE_SECS )); do
  sleep 5
  elapsed=$(( elapsed + 5 ))
  v="$(server_rss_kb)"
  idle_samples="$(jq -nc --argjson acc "$idle_samples" --argjson at "$elapsed" --arg v "${v:-}" \
    '$acc + [{at_secs:$at, server_rss_kb:(if $v=="" then null else ($v|tonumber) end)}]')"
done
rss_idle="$(server_rss_kb)"
emit "$(jq -nc --argjson secs "$IDLE_SECS" --argjson s "$idle_samples" --argjson rss "$(rss_json)" \
  '{tier:2, phase:"idle", ran:true, idle_secs:$secs, samples:$s} + $rss')"

# ── Summary: deltas, and a ceiling derived from THIS run ───────────────────────
kb() { [[ -n "${1:-}" ]] && echo "$1" || echo null; }
emit "$(jq -nc \
  --argjson cold  "$(kb "${rss_cold:-}")"  --argjson warm "$(kb "${rss_warm:-}")" \
  --argjson burst "$(kb "${rss_burst:-}")" --argjson idle "$(kb "${rss_idle:-}")" \
  --argjson nburst "$BURST" '
  def d(a;b): if a==null or b==null then null else b-a end;
  {tier:2, phase:"summary", ran:true,
   server_rss_kb:{cold:$cold, warm:$warm, burst:$burst, idle:$idle},
   server_rss_delta_kb:{cold_to_warm:d($cold;$warm), warm_to_burst:d($warm;$burst),
                        burst_to_idle:d($burst;$idle), cold_to_idle:d($cold;$idle)},
   server_rss_growth_kb_per_1000_requests:
     (if d($warm;$burst)==null then null else ((d($warm;$burst)/$nburst)*1000*1000|round/1000) end),
   gating:false,
   gating_note:"first iteration RECORDS. Any ceiling must come from a baseline series, not from this one run."}')"

if (( fail )); then
  note "one or more Tier 2 legs did not complete — see the ran:false lines above"
  exit 1
fi
