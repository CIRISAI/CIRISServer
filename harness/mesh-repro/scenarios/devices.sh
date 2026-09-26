#!/usr/bin/env bash
# scenarios/devices.sh — a person's SECOND device joins a conversation already under way, and a household reaches a member's node.
#
# THE CHAT LADDER, THEN TWO THINGS IT CANNOT ASK. This scenario runs the whole
# chat ladder first (it sources scenarios/chat.sh: the same three nodes, the same
# claims, the same derived room, the same message) and then, with a message
# already exchanged, asks two questions about people rather than nodes:
#
#   1. SECOND DEVICE (0.5.218 GOAL: "signing in with a fedID on a second device
#      by approving a request on the first device, and files and chats just show
#      up"). Person B's FIRST device (node-b) claims a fresh node (node-c) for the
#      same fed-ID through `POST /v1/setup/claim-remote` — node-c shows its node
#      code and one-time PIN, node-b signs the owner-binding with B's pen and
#      delivers it over the code's transport. Then: does node-c LIST the
#      conversation, and can it OPEN the message B received before node-c existed?
#      The second is history PLUS a content-key rewrap to a new occurrence.
#   2. HOUSEHOLD (CIRISServer#647). Person A charters a family, adds person B,
#      and writes a `cohort: family` file. Does B's node see the household, list
#      the file, and open it?
#
# WHY A SEPARATE SCENARIO and not more rungs on chat.sh: the chat ladder gates
# the tag and runs in CI on every substrate PR; these rungs are RED-EXPECTED by
# design (each names its missing piece), claim a FOURTH node (the `scale`
# profile), and would lengthen every chat run. Sourcing chat.sh keeps ONE copy of
# every chat stage — nothing here restates one.
#
# WHAT IS RED-EXPECTED, AND WHY (the union is the ask):
#
#   c_opens_history   NO REWRAP TO A NEW OCCURRENCE OF AN EXISTING MEMBER. A
#                     community body is sealed under the minter's epoch DEK and
#                     wrapped to the member OCCURRENCES persist knows at seal time
#                     (`community_dek::ensure_epoch_dek`). node-c's occurrence of
#                     B does not exist until node-c provisions it
#                     (`contacts_chat::ensure_owner_content_occurrence`, on its
#                     first chat door). Nothing then wraps the EXISTING epochs to
#                     it: persist has `rekey_self_occurrence_add` (self blobs
#                     only, and the server calls it only from
#                     `POST /v1/self/occurrence`, never on claim) and
#                     `rekey_family_member_add` (a new MEMBER), and no
#                     community-epoch occurrence-add. `ensure_epoch_dek` fills a
#                     late occurrence only on the MINTER's NEXT seal in the SAME
#                     epoch, so history opens on node-c only by accident — after
#                     the other person speaks again, if the epoch has not moved.
#   family_on_b,      #646 (the Family plane had no coordinator — fixed on this
#   family_file_*     branch) AND CIRISPersist#910: the member is ADDED after
#                     create, so the record B needs is a GROWN one, and a grown
#                     family record neither re-indexes the wire
#                     (`supersede_group_row`) nor re-puts at a peer that holds
#                     the founding one (`put_family` is a plain INSERT).
#
# EACH IS PROMOTED TO REQUIRED WHEN ITS PIECE LANDS — not before, and not left
# RED-EXPECTED after: a marked stage that has gone green is a claim nobody is
# gating. The run loop leaves early once SUCCESS_STAGE is positive and nothing
# REQUIRED is pending, so a RED-EXPECTED rung is measured only until then (plus
# the final re-sample); promoting it is what makes the window wait for it.

# shellcheck source=scenarios/chat.sh
. "$(dirname "${BASH_SOURCE[0]}")/chat.sh"

SCENARIO_NAME="devices"
# node-c lives behind the `scale` profile in docker-compose.chat.yml.
export COMPOSE_PROFILES="${COMPOSE_PROFILES:-scale}"
DEV_SECOND="${DEV_SECOND:-node-c}"
DEV_SECOND_BASE="http://${DEV_SECOND}:4243"
DEV_FAMILY_TEXT="${DEV_FAMILY_TEXT:-household file proof $(date -u +%Y%m%dT%H%M%SZ)}"

STAGES=("${STAGES[@]}" second_device c_peered b_lists_c_device c_opens_old_self_file c_announced_by_b c_lists_room c_opens_history
        family family_on_b family_file family_file_listed_on_b family_file_opened_on_b)
# The claim of THIS scenario is the second device listing the conversation;
# chat's own REQUIRED stages (arrived, comm_file, comm_file_on_b) stay required.
SUCCESS_STAGE="c_lists_room"
SUCCESS_MESSAGE="the chat ladder is green AND a second device claimed through claim-remote LISTS the conversation its owner was already in."
REQUIRED_second_device=1
REQUIRED_c_lists_room=1
# CIRISServer#678: the approving device re-wraps old self files for the new
# device, and announces it (announce is per device; the pen stays on node-b).
# The client's review asked whether the approved device appears in the device
# list, or only as an owned node: it must be an OCCURRENCE of the person, listed
# on the first device's My Identity roster (CIRISServer#678, CC 3.3.6).
REQUIRED_b_lists_c_device=1
REQUIRED_c_opens_old_self_file=1
REQUIRED_c_announced_by_b=1
REQUIRED_family=1
REQUIRED_family_file=1

XFAIL_c_opens_history="no content-key REWRAP to a new occurrence of an EXISTING member: the message was sealed under the minter's community epoch DEK and wrapped to the member occurrences persist knew then; node-c's occurrence of B is provisioned later (ensure_owner_content_occurrence) and nothing wraps existing epochs to it — persist has rekey_self_occurrence_add (self blobs; the server calls it only from POST /v1/self/occurrence, not on claim-remote) and rekey_family_member_add (a new member), and no community-epoch occurrence-add; ensure_epoch_dek fills a late occurrence only on the minter's NEXT seal in the SAME epoch. Ask: a persist door that wraps every epoch/blob an existing occurrence of the identity can open to the new occurrence, driven by the server when a claimed node's content occurrence appears"
XFAIL_family_on_b="EXPECTED TO PASS from 0.5.218 (persist v49.0.0 fixed CIRISPersist#910 and the server routes FamilyMembershipWidening, kind 18) — remove this mark after the first green devices run. Was: CIRISServer#646 (no Family replication round; fixed on this branch) + CIRISPersist#910: B is added AFTER create, so B's node needs the GROWN record, and supersede_group_row re-stamps admitted_at without re-indexing the wire while put_family is a plain INSERT at a peer holding the founding record"
XFAIL_family_file_listed_on_b="EXPECTED TO PASS from 0.5.218 (persist v49.0.0 fixed CIRISPersist#910 and the server routes FamilyMembershipWidening, kind 18) — remove this mark after the first green devices run. Was: downstream of family_on_b (CIRISPersist#910): a family row's audience is the family's members' nodes as B's node folds them, and B's node does not hold the grown record naming B"
XFAIL_family_file_opened_on_b="EXPECTED TO PASS from 0.5.218 (persist v49.0.0 fixed CIRISPersist#910 and the server routes FamilyMembershipWidening, kind 18) — remove this mark after the first green devices run. Was: downstream of family_file_listed_on_b (CIRISPersist#910); REQUIRED once the family plane converges (#647 asks for the bytes stage to be REQUIRED)"

_dev_load() { _chat_load; [ -f "$CHAT_STATE/dev.sh" ] && . "$CHAT_STATE/dev.sh"; return 0; }

# One HTTP call from INSIDE a service's container, as a given bearer, over its
# own loopback (claim-remote and peering are loopback-guarded setup/owner doors).
# Prints `{"status": N, "body": {...}}`, never fails.
_dev_api() {
  local svc="$1" token="$2" method="$3" path="$4" body="${5:-}"
  compose exec -T "$svc" python - "$token" "$method" "$path" "$body" <<'PY' 2>/dev/null || echo '{"status": 0, "body": {}}'
import json, sys, urllib.request, urllib.error
token, method, path, body = sys.argv[1:5]
data = body.encode() if body else None
headers = {"Content-Type": "application/json"}
if token:
    headers["Authorization"] = "Bearer " + token
req = urllib.request.Request("http://127.0.0.1:4243" + path, method=method, data=data, headers=headers)
try:
    r = urllib.request.urlopen(req, timeout=60)
    raw = r.read().decode() or "{}"
    try: b = json.loads(raw)
    except Exception: b = {"raw": raw[:300]}
    print(json.dumps({"status": r.status, "body": b}))
except urllib.error.HTTPError as e:
    raw = e.read().decode() or "{}"
    try: b = json.loads(raw)
    except Exception: b = {"raw": raw[:300]}
    print(json.dumps({"status": e.code, "body": b}))
except Exception as e:  # noqa: BLE001
    print(json.dumps({"status": 0, "body": {"detail": repr(e)[:200]}}))
PY
}

# Read one field off a saved `_dev_api` result. Empty on anything unexpected.
_dev_field() {
  python3 -c '
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print(""); raise SystemExit
cur=d
for k in sys.argv[2].split("."):
    cur = cur.get(k) if isinstance(cur, dict) else None
print("" if cur is None else (cur if isinstance(cur, str) else json.dumps(cur)))' "$1" "$2" 2>/dev/null || true
}

# Rename chat's prepare/evidence so these can extend them rather than copy them.
eval "_chat_prepare() $(declare -f harness_scenario_prepare | sed '1d')"
eval "_chat_evidence() $(declare -f harness_scenario_evidence | sed '1d')"

harness_scenario_prepare() {
  _chat_prepare || true
  _dev_load
  : >"$CHAT_STATE/dev.sh"
  _dev_second_device || true
  _dev_household || true
}

# ── SECOND DEVICE: B's first device claims node-c for the same fed-ID ────────
_dev_second_device() {
  echo "── devices: $DEV_SECOND joins as ${CHAT_B_OWNER:-<no owner>}'s second device ──"
  harness_wait_healthy "$DEV_SECOND" 36 || true
  if [ -z "${CHAT_B_TOKEN:-}" ] || [ -z "${CHAT_B_OWNER:-}" ]; then
    echo "  ✗ the chat prepare yielded no session for ${CHAT_RECIPIENT_SVC:-node-b}; nothing can claim $DEV_SECOND"
    return 0
  fi
  local pin="" waited=0 code body token owner
  # A SELF FILE WRITTEN BEFORE THE SECOND DEVICE EXISTS (CIRISServer#678): it
  # is sealed to node-b's occurrences only, so it opens on node-c only if the
  # device holding the pen re-wraps it once node-c's occurrence arrives.
  _dev_api "${CHAT_RECIPIENT_SVC:-node-b}" "$CHAT_B_TOKEN" POST /v1/files "$(python3 -c '
import base64, json
print(json.dumps({"cohort":"self","bytes_base64":base64.b64encode(b"written before the second device").decode(),
                  "media_type":"text/plain","filename":"before-the-claim.txt"}))')" >"$CHAT_STATE/old-self-file.json"
  printf 'DEV_OLD_SELF_ID=%q\n' "$(_dev_field "$CHAT_STATE/old-self-file.json" body.attestation_id)" >>"$CHAT_STATE/dev.sh"
  echo "  old self file on ${CHAT_RECIPIENT_SVC:-node-b}: status=$(_dev_field "$CHAT_STATE/old-self-file.json" status)"
  while [ "$waited" -lt 90 ]; do
    pin="$(compose exec -T "$DEV_SECOND" sh -c 'cat /var/lib/ciris/claim_pin 2>/dev/null' 2>/dev/null | tr -d '\r\n')"
    if [ -n "$pin" ]; then break; fi
    sleep 5; waited=$((waited + 5))
  done
  code="$(compose exec -T "$DEV_SECOND" python -c 'import json,urllib.request;print(json.load(urllib.request.urlopen("http://127.0.0.1:4243/v1/federation/node-code",timeout=10))["code"])' 2>/dev/null | tr -d '\r\n[:space:]')"
  if [ -z "$pin" ] || [ -z "$code" ]; then
    echo "  ✗ $DEV_SECOND: pin=${pin:+yes} code=${code:+yes} — it is not showing a claimable node code"
    return 0
  fi
  # THE PRODUCT FLOW: the FIRST device's own node signs with B's pen and delivers
  # the owner-binding to the target over its transport (`target_url`, because a
  # server node's code carries no external address). `self`, because a second
  # device IS the owner's self.
  body="$(python3 -c 'import json,sys;print(json.dumps({"node_code":sys.argv[1],"claim_pin":sys.argv[2],"cohort_scope":"self","target_url":sys.argv[3]}))' \
            "$code" "$pin" "$DEV_SECOND_BASE")"
  _dev_api "${CHAT_RECIPIENT_SVC:-node-b}" "$CHAT_B_TOKEN" POST /v1/setup/claim-remote "$body" \
    >"$CHAT_STATE/claim-remote.json"
  # THE SESSION STAYS ON THE NEW DEVICE (CIRISServer#678, client review). The
  # claim response no longer carries node-c's owner session back through node-b;
  # node-c's own wizard collects it over ITS loopback with the PIN it showed.
  # A token in the claim-remote response is itself a regression.
  if [ -n "$(_dev_field "$CHAT_STATE/claim-remote.json" body.access_token)" ]; then
    echo "  ✗ claim-remote returned the new device's owner session to the approving device"
  fi
  _dev_api "$DEV_SECOND" "" POST /v1/setup/claimed-session \
    "$(python3 -c 'import json,sys;print(json.dumps({"claim_pin":sys.argv[1]}))' "$pin")" \
    >"$CHAT_STATE/claimed-session.json"
  token="$(_dev_field "$CHAT_STATE/claimed-session.json" body.access_token)"
  echo "  $DEV_SECOND collects its own session: status=$(_dev_field "$CHAT_STATE/claimed-session.json" status) pickup=$(_dev_field "$CHAT_STATE/claim-remote.json" body.session_pickup)"
  owner="$(_dev_field "$CHAT_STATE/claim-remote.json" body.identity_key_id)"
  printf 'DEV_C_TOKEN=%q\nDEV_C_OWNER=%q\n' "$token" "$owner" >>"$CHAT_STATE/dev.sh"
  echo "  claim-remote: status=$(_dev_field "$CHAT_STATE/claim-remote.json" status) owner=${owner:-<none>} token=${token:+yes} local_directory_updated=$(_dev_field "$CHAT_STATE/claim-remote.json" body.local_directory_updated)"
  if [ -z "$token" ]; then
    echo "  ✗ no session for $DEV_SECOND: $(head -c 400 "$CHAT_STATE/claim-remote.json")"
    return 0
  fi

  # ANNOUNCE, attempted and RECORDED, not assumed. The announce re-signs the
  # owner-binding at federation scope with the OWNER'S PEN, and a device claimed
  # through claim-remote holds no pen (it stays on the first device) — so this is
  # expected to refuse, and that refusal is itself a finding: without it no node
  # but the owner's own can place this device in a row's audience, and whatever
  # reaches it must be relayed by the first device.
  _dev_api "$DEV_SECOND" "$token" POST /v1/federation/announce '{}' >"$CHAT_STATE/announce-c.json"
  echo "  $DEV_SECOND announce: status=$(_dev_field "$CHAT_STATE/announce-c.json" status) $(head -c 200 "$CHAT_STATE/announce-c.json")"
  # The pen stays on the first device, so node-c cannot announce itself (the
  # line above records that refusal as evidence). The approving device
  # announces it: POST /v1/self/nodes/{node}/announce (CIRISServer#678).
  local c_key
  c_key="$(compose exec -T "$DEV_SECOND" python -c 'import json,urllib.request;print(json.load(urllib.request.urlopen("http://127.0.0.1:4243/v1/identity",timeout=10))["key_id"])' 2>/dev/null | tr -d '\r\n[:space:]')"
  printf 'DEV_C_KEY=%q\n' "$c_key" >>"$CHAT_STATE/dev.sh"
  if [ -n "$c_key" ]; then
    _dev_api "${CHAT_RECIPIENT_SVC:-node-b}" "$CHAT_B_TOKEN" POST "/v1/self/nodes/$c_key/announce" '{}' >"$CHAT_STATE/announce-c-by-b.json"
    echo "  ${CHAT_RECIPIENT_SVC:-node-b} announces $DEV_SECOND: status=$(_dev_field "$CHAT_STATE/announce-c-by-b.json" status)"
  fi

  # PEER THE TWO DEVICES. claim-remote records the target's key, its binding and
  # an RNS seed (`net.bootstrap_peers`, effective on the NEXT boot) — it opens no
  # replication link, and a `self` row needs no grant but DOES need a peer link
  # (`send_set_for`'s `nodes_of` is a directory read, and coordinators exist per
  # consent peer). Same act, same prefix set, as scenarios/selffiles.sh.
  local a b ta tb rec
  for a in "${CHAT_RECIPIENT_SVC:-node-b}" "$DEV_SECOND"; do
    _dev_api "$a" "" GET /v1/federation/test-blessed-self-record >"$CHAT_STATE/record-$a.json"
  done
  for a in "${CHAT_RECIPIENT_SVC:-node-b}" "$DEV_SECOND"; do
    for b in "${CHAT_RECIPIENT_SVC:-node-b}" "$DEV_SECOND"; do
      [ "$a" = "$b" ] && continue
      if [ "$a" = "$DEV_SECOND" ]; then ta="$token"; else ta="$CHAT_B_TOKEN"; fi
      rec="$(python3 -c '
import json,sys
r=json.load(open(sys.argv[1])).get("body") or {}
print(json.dumps({"peer_key_id": r["record"]["key_id"], "peer_key_record": r,
                  "attestation_prefixes": ["capacity:","chat:","file:","ownership:","self:delegates_to:","trace:"]}))' \
        "$CHAT_STATE/record-$b.json" 2>/dev/null || true)"
      if [ -z "$rec" ]; then echo "  ! no blessed self record for $b"; continue; fi
      _dev_api "$a" "$ta" POST /v1/federation/peering "$rec" >"$CHAT_STATE/peering-$a-$b.json"
      echo "  peering $a->$b: status=$(_dev_field "$CHAT_STATE/peering-$a-$b.json" status)"
    done
  done
  tb=""; : "$tb"
}

# ── HOUSEHOLD: A charters a family, adds B, writes a family file ─────────────
_dev_household() {
  echo "── devices: ${CHAT_SENDER_SVC:-node-a} charters a household and adds ${CHAT_B_OWNER:-<no owner>} ──"
  if [ -z "${CHAT_A_TOKEN:-}" ] || [ -z "${CHAT_B_OWNER:-}" ]; then
    echo "  ✗ no sender session or no recipient owner; no household"
    return 0
  fi
  _dev_api "${CHAT_SENDER_SVC:-node-a}" "$CHAT_A_TOKEN" POST /v1/families '{"name":"mesh-harness household"}' \
    >"$CHAT_STATE/family-create.json"
  local fid
  fid="$(_dev_field "$CHAT_STATE/family-create.json" body.family_id)"
  printf 'DEV_FAMILY_ID=%q\n' "$fid" >>"$CHAT_STATE/dev.sh"
  echo "  create: status=$(_dev_field "$CHAT_STATE/family-create.json" status) family_id=${fid:-<none>}"
  if [ -z "$fid" ]; then return 0; fi
  # ADDED AFTER CREATE, deliberately: that is the grown-record path #910 names,
  # and the one a real household takes (you found it, then you invite).
  _dev_api "${CHAT_SENDER_SVC:-node-a}" "$CHAT_A_TOKEN" POST "/v1/families/$fid/members" \
    "$(python3 -c 'import json,sys;print(json.dumps({"key_id":sys.argv[1]}))' "$CHAT_B_OWNER")" \
    >"$CHAT_STATE/family-add.json"
  echo "  add member: status=$(_dev_field "$CHAT_STATE/family-add.json" status) dek_rewrap=$(_dev_field "$CHAT_STATE/family-add.json" body.dek_rewrap)"
  _dev_api "${CHAT_SENDER_SVC:-node-a}" "$CHAT_A_TOKEN" POST /v1/files "$(python3 -c '
import base64, json, sys
print(json.dumps({"cohort":"family","room_id":sys.argv[1],
                  "bytes_base64":base64.b64encode(sys.argv[2].encode()).decode(),
                  "media_type":"text/plain","filename":"household-proof.txt"}))' "$fid" "$DEV_FAMILY_TEXT")" \
    >"$CHAT_STATE/family-file.json"
  echo "  family file: $(head -c 300 "$CHAT_STATE/family-file.json")"
}

# ── the second-device rungs ──────────────────────────────────────────────────
stage_second_device() {
  _dev_load
  if [ -n "${DEV_C_TOKEN:-}" ] && [ -n "${DEV_C_OWNER:-}" ] && [ "$DEV_C_OWNER" = "${CHAT_B_OWNER:-}" ]; then
    echo 1
  else
    echo 0
  fi
}
HINT_second_device="claim-remote from the first device did not yield a session for the second, or bound it to a different identity. Read claim-remote.json: a 401/403 is node-b's owner gate (the chat claim's bearer, SystemAdmin + FullAccess, verb ClaimRemote); a 503 'no responsible-user identity' is B's pen not resolving on node-b (the active-user alias); a 4xx forwarded from the target is setup/root refusing the PIN, the node code, or the signed binding's cohort"
EXIT_second_device=60
DIAG_second_device() { head -c 900 "$CHAT_STATE/claim-remote.json" 2>/dev/null; echo; }

stage_c_peered() {
  local n=0 f
  for f in "$CHAT_STATE/peering-${CHAT_RECIPIENT_SVC:-node-b}-$DEV_SECOND.json" \
           "$CHAT_STATE/peering-$DEV_SECOND-${CHAT_RECIPIENT_SVC:-node-b}.json"; do
    if [ "$(_dev_field "$f" status)" = "200" ]; then n=$((n + 1)); fi
  done
  if [ "$n" -eq 2 ]; then echo 1; else echo 0; fi
}
HINT_c_peered="the two devices of one person are not mutual replication peers. claim-remote opens no replication link (it seeds net.bootstrap_peers for the NEXT boot), so the harness peers them the way selffiles does; a refusal here is the peering door's own (see peering-*.json)"
EXIT_c_peered=61
DIAG_c_peered() {
  local f
  for f in "$CHAT_STATE"/peering-*"$DEV_SECOND"*.json; do
    echo "  $(basename "$f"): $(head -c 300 "$f" 2>/dev/null)"
  done
}

stage_b_lists_c_device() {
  _dev_load
  if [ -z "${DEV_C_OWNER:-}" ] || [ -z "${DEV_C_KEY:-}" ]; then echo 0; return; fi
  local waited=0
  while :; do
    _dev_api "${CHAT_RECIPIENT_SVC:-node-b}" "$CHAT_B_TOKEN" GET \
      "/v1/self/occurrences?identity_key_id=$DEV_C_OWNER" >"$CHAT_STATE/b-occurrences.json"
    if python3 -c '
import json,sys
d=json.load(open(sys.argv[1])).get("body") or {}
sys.exit(0 if any(o.get("occurrence_key_id")==sys.argv[2] for o in d.get("occurrences",[])) else 1)
' "$CHAT_STATE/b-occurrences.json" "$DEV_C_KEY"; then echo 1; return; fi
    [ "$waited" -ge 90 ] && { echo 0; return; }
    sleep 10; waited=$((waited + 10))
  done
}
HINT_b_lists_c_device="the first device's device roster (GET /v1/self/occurrences, owner audience) does not list the second device. node-c provisions its occurrence of the owner on its self-room tick and the SIGNED row replicates to node-b; if node-c lists it and node-b does not, the IdentityOccurrence plane did not cross (peering, or CIRISEdge#682 gating). If neither lists it, node-c never provisioned it (CIRISServer#678)"
EXIT_b_lists_c_device=71
DIAG_b_lists_c_device() {
  echo "  node-b roster: $(head -c 500 "$CHAT_STATE/b-occurrences.json" 2>/dev/null)"
  echo "  node-c key: ${DEV_C_KEY:-<none>}"
}

stage_c_opens_old_self_file() {
  _dev_load
  if [ -z "${DEV_C_TOKEN:-}" ] || [ -z "${DEV_OLD_SELF_ID:-}" ]; then echo 0; return; fi
  _dev_api "$DEV_SECOND" "$DEV_C_TOKEN" GET "/v1/files/$DEV_OLD_SELF_ID?cohort=self" >"$CHAT_STATE/c-old-self-file.json"
  if [ "$(_dev_field "$CHAT_STATE/c-old-self-file.json" status)" = "200" ]; then echo 1; else echo 0; fi
}
HINT_c_opens_old_self_file="the second device cannot OPEN a self file written before it was claimed. 409 drive.not_fetched = the grant exists but the bytes never crossed (the self room / pull); 403 drive.not_granted = no wrap names node-c's occurrence: the pen holder (node-b) never ran the re-wrap. Check node-b's log for 'self files RE-WRAPPED for a new device' and that node-b holds node-c's occurrence WITH encryption pubkeys (CIRISServer#678)"
EXIT_c_opens_old_self_file=69
DIAG_c_opens_old_self_file() {
  echo "  node-c: $(head -c 400 "$CHAT_STATE/c-old-self-file.json" 2>/dev/null)"
  echo "  node-b re-wrap lines: $(compose logs "${CHAT_RECIPIENT_SVC:-node-b}" 2>/dev/null | grep -c 'RE-WRAPPED for a new device' || true)"
}

stage_c_announced_by_b() {
  _dev_load
  if [ "$(_dev_field "$CHAT_STATE/announce-c-by-b.json" status)" = "200" ]; then echo 1; else echo 0; fi
}
HINT_c_announced_by_b="the approving device could not announce the second device. 403 self.announce_not_your_node = node-b does not see node-c as its owner's (the claim's owner-binding did not land locally); 401 = the harness session; read announce-c-by-b.json (CIRISServer#678)"
EXIT_c_announced_by_b=70
DIAG_c_announced_by_b() { head -c 400 "$CHAT_STATE/announce-c-by-b.json" 2>/dev/null; echo; }

stage_c_lists_room() {
  _dev_load
  if [ -z "${DEV_C_TOKEN:-}" ] || [ -z "${CHAT_CID_B:-}" ]; then echo 0; return; fi
  _dev_api "$DEV_SECOND" "$DEV_C_TOKEN" GET "/v1/communities?limit=200" >"$CHAT_STATE/c-communities.json"
  python3 -c '
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print(0); raise SystemExit
rows=(d.get("body") or {}).get("communities") or []
print(1 if d.get("status")==200 and any(r.get("community_id")==sys.argv[2] for r in rows) else 0)' \
    "$CHAT_STATE/c-communities.json" "$CHAT_CID_B" 2>/dev/null || echo 0
}
HINT_c_lists_room="the second device does not LIST the conversation its owner was already in. The room's record has to reach node-c from node-b (the only node that can place node-c in its audience: node-b holds B's binding for node-c, while node-a cannot learn it because node-c cannot announce — see announce-c.json). Check, in order: c_peered; that node-c holds the Community row at all (federation_communities on node-c); that node-c admitted it (E4 verifies against the row's REGISTERED signer and every member must be a registered key — node-b's Key plane is self_own, so node-a's owner key reaches node-c only if something else carries it)"
EXIT_c_lists_room=62
DIAG_c_lists_room() {
  echo "  node-c communities: $(head -c 600 "$CHAT_STATE/c-communities.json" 2>/dev/null)"
  echo "  node-c holds the room row: $(harness_db_count "$DEV_SECOND" federation_communities "community_key_id = '${CHAT_CID_B:-none}'")"
  echo "  node-c holds A's owner key: $(harness_db_count "$DEV_SECOND" federation_keys "key_id = '${CHAT_A_OWNER:-none}'")"
  echo "  node-c announce: $(head -c 300 "$CHAT_STATE/announce-c.json" 2>/dev/null)"
}

stage_c_opens_history() {
  _dev_load
  if [ -z "${DEV_C_TOKEN:-}" ] || [ -z "${CHAT_CID_B:-}" ] || [ -z "${CHAT_ATT_ID:-}" ]; then echo 0; return; fi
  # The SAME probe the chat ladder's `arrived` uses, against the second device:
  # the sender's attestation_id, a non-empty body, status live.
  compose exec -T "$DEV_SECOND" python /opt/harness/chat_drive.py arrived \
    "$DEV_SECOND_BASE" "$DEV_C_TOKEN" "$CHAT_CID_B" "$CHAT_ATT_ID" 2>/dev/null | tr -d '[:space:]'
}
HINT_c_opens_history="the second device cannot OPEN a message sent before it existed. The diagnosis quotes node-c's own reason: \`absent\` = the row never reached node-c (history did not replicate — see c_lists_room); an unopened NotGranted = the row is there and no wrap of its epoch DEK names node-c's occurrence (the missing REWRAP, see XFAIL); NotFetched = the grant exists and the bytes were never pulled"
EXIT_c_opens_history=63
DIAG_c_opens_history() {
  _dev_load
  printf '  node-c says: '
  compose exec -T "$DEV_SECOND" python /opt/harness/chat_drive.py arrived_reason \
    "$DEV_SECOND_BASE" "${DEV_C_TOKEN:-}" "${CHAT_CID_B:-}" "${CHAT_ATT_ID:-}" 2>/dev/null || echo "<probe failed>"
  echo "  node-c holds the message row: $(harness_db_count "$DEV_SECOND" federation_attestations "attestation_id = '${CHAT_ATT_ID:-none}'")"
  echo "  node-c occurrences of B: $(harness_db_count "$DEV_SECOND" federation_identity_occurrences "identity_key_id = '${CHAT_B_OWNER:-none}'")"
}

# ── the household rungs (CIRISServer#647) ────────────────────────────────────
stage_family() {
  local c a
  c="$(_dev_field "$CHAT_STATE/family-create.json" status)"
  a="$(_dev_field "$CHAT_STATE/family-add.json" status)"
  case "$c:$a" in
    20?:20?) echo 1 ;;
    *) echo 0 ;;
  esac
}
HINT_family="person A could not charter a household or add person B on A's own node. family.unknown_member_key = B's owner key is not registered on node-a (the contact phase admits it); family.not_authorized = the founder_only rule; read family-create.json / family-add.json"
EXIT_family=64
DIAG_family() {
  echo "  create: $(head -c 400 "$CHAT_STATE/family-create.json" 2>/dev/null)"
  echo "  add:    $(head -c 400 "$CHAT_STATE/family-add.json" 2>/dev/null)"
}

stage_family_on_b() {
  _dev_load
  if [ -z "${DEV_FAMILY_ID:-}" ] || [ -z "${CHAT_B_TOKEN:-}" ]; then echo 0; return; fi
  _dev_api "${CHAT_RECIPIENT_SVC:-node-b}" "$CHAT_B_TOKEN" GET /v1/families >"$CHAT_STATE/family-b.json"
  python3 -c '
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print(0); raise SystemExit
b=d.get("body") or {}
rows=b.get("families") if isinstance(b, dict) else b
rows=rows or []
print(1 if d.get("status")==200 and any((r.get("family_id") if isinstance(r, dict) else None)==sys.argv[2] for r in rows) else 0)' \
    "$CHAT_STATE/family-b.json" "$DEV_FAMILY_ID" 2>/dev/null || echo 0
}
HINT_family_on_b="B's node does not list the household it was added to. With #646 on this branch the Family plane has a round, so this is the grown-record gap (CIRISPersist#910) unless the diagnosis shows node-b holding NO family row at all"
EXIT_family_on_b=65
DIAG_family_on_b() {
  echo "  node-b families: $(head -c 400 "$CHAT_STATE/family-b.json" 2>/dev/null)"
  echo "  node-b holds the family row: $(harness_db_count "${CHAT_RECIPIENT_SVC:-node-b}" federation_families "family_key_id = '${DEV_FAMILY_ID:-none}'")"
}

stage_family_file() {
  python3 -c '
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print(0); raise SystemExit
b=d.get("body") or {}
print(1 if d.get("status")==200 and b.get("crossed") is True else 0)' "$CHAT_STATE/family-file.json" 2>/dev/null || echo 0
}
HINT_family_file="the family file was refused or did not cross. drive.family_id_required / not a member = the write named a family the author's node does not fold them into; crossed=false = local-tier (E5), reached nobody"
EXIT_family_file=66
DIAG_family_file() { head -c 600 "$CHAT_STATE/family-file.json" 2>/dev/null; echo; }

# Listed, then opened — separate facts, as in selffiles (#647).
_dev_family_read_b() {
  _dev_load
  local att
  att="$(_dev_field "$CHAT_STATE/family-file.json" body.attestation_id)"
  if [ -z "$att" ] || [ -z "${DEV_FAMILY_ID:-}" ] || [ -z "${CHAT_B_TOKEN:-}" ]; then return 0; fi
  compose exec -T "${CHAT_RECIPIENT_SVC:-node-b}" python - \
    "$CHAT_B_BASE" "$CHAT_B_TOKEN" "$DEV_FAMILY_ID" "$att" \
    >"$CHAT_STATE/family-file-b.json" 2>/dev/null <<'PY' || true
import json, sys, urllib.parse, urllib.request, urllib.error
base, token, fid, att = sys.argv[1:5]
def get(path):
    req = urllib.request.Request(base + path, headers={"Authorization": "Bearer " + token})
    try:
        r = urllib.request.urlopen(req, timeout=45)
        return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode() or "{}")
        except Exception: return e.code, {}
    except Exception as e:  # noqa: BLE001
        return 0, {"detail": repr(e)[:200]}
q = urllib.parse.urlencode({"cohort": "family", "room_id": fid})
ls, lb = get(f"/v1/drive?{q}")
listed = any(e.get("attestation_id") == att for e in (lb.get("entries") or []))
rs, rb = get(f"/v1/files/{att}?{q}")
print(json.dumps({"list_status": ls, "listed": listed, "read_status": rs, "read": rb}))
PY
}

stage_family_file_listed_on_b() {
  _dev_family_read_b
  python3 -c '
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print(0); raise SystemExit
print(1 if d.get("listed") else 0)' "$CHAT_STATE/family-file-b.json" 2>/dev/null || echo 0
}
HINT_family_file_listed_on_b="B's node does not LIST the household file. Downstream of family_on_b unless that is green: then the row did not cross (persist send_set_for's family arm reads the family's members' nodes on the AUTHOR's node)"
EXIT_family_file_listed_on_b=67
DIAG_family_file_listed_on_b() { head -c 900 "$CHAT_STATE/family-file-b.json" 2>/dev/null; echo; }

stage_family_file_opened_on_b() {
  python3 -c '
import base64,json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print(0); raise SystemExit
if not d.get("listed") or d.get("read_status")!=200: print(0); raise SystemExit
try: print(1 if base64.b64decode(d["read"]["bytes_base64"]) else 0)
except Exception: print(0)' "$CHAT_STATE/family-file-b.json" 2>/dev/null || echo 0
}
HINT_family_file_opened_on_b="B's node LISTS the household file but cannot OPEN it. not_fetched (409) = the bytes never left node-a (a family pull reads family:author_nodes, never a claim index); not_granted (403) = B's occurrence was not a wrap target when A sealed — the family add's dek_rewrap covers blobs that existed at add time, and this file was written after, so its wrap set is the fold A's node held then"
EXIT_family_file_opened_on_b=68
DIAG_family_file_opened_on_b() { head -c 900 "$CHAT_STATE/family-file-b.json" 2>/dev/null; echo; }

harness_scenario_evidence() {
  _chat_evidence || true
  _dev_load
  echo
  echo "── the second device ──"
  echo "· claim-remote:  $(head -c 300 "$CHAT_STATE/claim-remote.json" 2>/dev/null)"
  echo "· announce (c):  $(head -c 300 "$CHAT_STATE/announce-c.json" 2>/dev/null)"
  echo "· owner on c:    ${DEV_C_OWNER:-<none>} (B=${CHAT_B_OWNER:-<none>})"
  echo "· household:     ${DEV_FAMILY_ID:-<none>}"
}
