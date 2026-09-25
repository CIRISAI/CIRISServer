#!/usr/bin/env bash
# scenarios/selffiles.sh — my stuff on my other devices: one person, two nodes, a file that crosses and opens.
#
# THE TOPOLOGY IS THE POINT. The chat ladder puts two PEOPLE on two nodes; this
# puts ONE PERSON on two nodes, which is the only shape a self room exists for.
# node-a mints the owner's fed-ID and claims itself with it; node-c is claimed
# with the SAME identity, so `owner_of` answers the same person for both and
# `nodes_owned_by(owner)` — the roster `self_room::roster` reads — has two
# entries. That is what a second device IS to the substrate.
#
# WHAT EACH RUNG MEANS (FSD/CONTENT_TRANSFER.md §5.3, the rung table):
#
#   one_owner  both nodes resolve to ONE owner. Without this there is no
#              self-collective and everything above is vacuous.
#   roster     node-a's drive sees two nodes in the roster. The directory has
#              converged; the MLS tree has not necessarily.
#   room       the self room exists — a node CREATED it and says so. Edge
#              decides who creates (`self_room::decide`); we only read that it
#              happened, because two rooms would be the CIRISEdge#646 shape.
#   note       a note (self-chat) is written and placed. The row plane alone.
#   file       a file is published at `self` AND `crossed == true`. False here
#              means it reached nobody: local-tier rows are kept out of every
#              federation stream by persist's E5 invariant, so the file would be
#              invisible to the other device AND to this node's own drive.
#              Since 0.5.218 (#626) also: tier InvisibleEncrypted, `excluded`
#              empty, no `Stored { announced: true }` and no `holds_bytes:` row
#              on either device — a self blob emits no holder claim (CC 5.2).
#   mine_on_b  node-c's `GET /v1/drive` LISTS the file. The row crossed. This is
#              REQUIRED and is the rung the whole cut exists for.
#   opened_on_b  node-c OPENS the bytes. The room's addresses resolved and the
#              pull completed — the last rung, and the one that needs the room.
#              Red on any self pull regression by name (#626): `NoHolders`,
#              `NoMeaning(GroupWithoutId)`, or a `self:claim_index` source.
#
# `mine_on_b` and `opened_on_b` are both REQUIRED since 0.5.216 (the self-room
# drive adopts edge's room-keyed handshake, CIRISEdge#656). A red here names its
# rung; that is the whole reason the table exists.

SCENARIO_NAME="selffiles"
# The same three-node compose the chat ladder uses; node-c lives behind the
# `scale` profile there, and this scenario needs it — two nodes for ONE person
# is the whole topology.
COMPOSE_FILES="-f docker-compose.chat.yml"
export COMPOSE_PROFILES="${COMPOSE_PROFILES:-scale}"
PROJECT="${PROJECT:-ciris-selffiles}"
# `opened_on_b` — the BYTES on the second device — is the claim of this ladder
# since 0.5.216. It was BLOCKED UPSTREAM on CIRISEdge#656 through 0.5.215:
# `self_room::decide` returned `PublishKeyPackage` and `Add`, but edge exposed
# `key_package_attestation` / `welcome_attestation` only in a form that derives
# a PAIR room, so those two rows landed in `chat:pair:v1:<hash>` and the
# creator's `key_package_from(<joiner>, <self room>)` never matched —
# `Added(0)` forever, room stuck at one member, and the second device read
# `not_fetched`. Edge v30.0.0 shipped the room-keyed `*_attestation_in` twins
# and `welcome_for`; `src/self_room_drive.rs` adopts them in 0.5.216, so the
# rung is PROMOTED to SUCCESS_STAGE and made REQUIRED.
SUCCESS_STAGE="opened_on_b"
STAGES=(rooted one_owner roster room note file mine_on_b opened_on_b)

# `mine_on_b` is the claim of this scenario: inferring it from a later stage is
# exactly the mistake the chat ladder made with `arrived` for six releases.
REQUIRED_mine_on_b=1
REQUIRED_file=1
# The BYTES, not inferred from the row: a green `mine_on_b` with a red
# `opened_on_b` is exactly the 0.5.215 state this cut exists to end.
REQUIRED_opened_on_b=1

SELF_STATE="${TMPDIR:-/tmp}/ciris-selffiles-${PROJECT:-ciris-selffiles}"
SELF_NODES="${SELF_NODES:-node-a node-c}"
SELF_PRIMARY="${SELF_NODES%% *}"
SELF_SECOND="${SELF_NODES#* }"
SELF_SERVICES="canonical $SELF_NODES"
SELF_CONSOLE="/opt/harness/ciris-server-bin"
# ONE alias for both nodes: the owner's identity is the same person, and the
# alias is the input to the #247 derivation, so the same seed under the same
# alias derives the same fed-ID on both.
SELF_OWNER_ALIAS="${SELF_OWNER_ALIAS:-ciris-owner-one}"
SELF_FILE_TEXT="${SELF_FILE_TEXT:-self-file proof $(date -u +%Y%m%dT%H%M%SZ)}"
SELF_NOTE_TEXT="${SELF_NOTE_TEXT:-note to self $(date -u +%Y%m%dT%H%M%SZ)}"

_self_load() {
  # shellcheck source=/dev/null
  [ -f "$SELF_STATE/vars.sh" ] && . "$SELF_STATE/vars.sh"
  return 0
}

# Ask a node's HTTP API as its owner. One helper, because every probe below is
# "what does THIS node say about the same identity".
_self_api() {
  local svc="$1" method="$2" path="$3" body="${4:-}" token
  _self_load
  eval "token=\${SELF_TOKEN_${svc//-/_}:-}"
  compose exec -T "$svc" python - "$token" "$method" "$path" "$body" <<'PY' 2>/dev/null
import json, sys, urllib.request, urllib.error
token, method, path, body = sys.argv[1:5]
data = body.encode() if body else None
req = urllib.request.Request(
    "http://127.0.0.1:4243" + path, method=method, data=data,
    headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
try:
    r = urllib.request.urlopen(req, timeout=45)
    print(json.dumps({"status": r.status, "body": json.loads(r.read().decode() or "{}")}))
except urllib.error.HTTPError as e:
    try: b = json.loads(e.read().decode() or "{}")
    except Exception: b = {}
    print(json.dumps({"status": e.code, "body": b}))
except Exception as e:  # noqa: BLE001
    print(json.dumps({"status": 0, "body": {"detail": repr(e)[:200]}}))
PY
}

# Does this service's log match? ONE helper, because `grep -q` is a trap here.
#
# THE BUG THIS EXISTS FOR (it cost a whole ladder run): the harness runs under
# `set -euo pipefail`. `grep -q` exits the moment it matches, which SIGPIPEs
# the `docker compose logs` feeding it, which makes the PIPELINE exit 141 — so
# `... | grep -q X && n=$((n+1))` never increments ON A SUCCESSFUL MATCH. Every
# log-scraping rung read 0 while the logs plainly contained the line, and the
# roster wait timed out against a roster that had already converged.
#
# `grep -c` reads the whole stream, so nothing upstream is signalled; it still
# exits 1 on zero matches, hence the `|| true`. See lib/harness.sh's note at
# `harness_timeline` — same class, different facet.
_self_log_has() {
  local svc="$1" re="$2" n
  n="$(compose logs "$svc" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' | grep -cE "$re" || true)"
  [ "${n:-0}" -gt 0 ]
}

harness_scenario_prepare() {
  rm -rf "$SELF_STATE"; mkdir -p "$SELF_STATE"; : >"$SELF_STATE/vars.sh"
  local svc
  echo "── selffiles: waiting for the nodes ──"
  for svc in $SELF_NODES; do harness_wait_healthy "$svc" 36; done

  if ! compose exec -T "$SELF_PRIMARY" test -x "$SELF_CONSOLE" >/dev/null 2>&1; then
    echo "  ✗ $SELF_CONSOLE is not executable in the containers — build it first:"
    echo "    cargo build --release --features test-anchor,python"
    return 0
  fi

  # ── THE ONE IDENTITY, MINTED ONCE ────────────────────────────────────────
  # Minted on the primary, then its seed files are carried to the second node.
  # That is the harness standing in for `POST /v1/self/associate` with a
  # portable keyset: what matters to the roster is that both nodes end up
  # OWNER-BOUND to the same fed-ID.
  echo "── selffiles: minting ONE owner identity on $SELF_PRIMARY ──"
  compose exec -T "$SELF_PRIMARY" "$SELF_CONSOLE" identity create --backend software \
    --home /var/lib/ciris --key-id "$SELF_OWNER_ALIAS" >"$SELF_STATE/mint.out" 2>"$SELF_STATE/mint.err" || true
  sed -n 's/^ *ed25519 pub *: *//p' "$SELF_STATE/mint.out" | head -1 >"$SELF_STATE/owner.ed" || true

  echo "── selffiles: carrying the owner's HOME key material to $SELF_SECOND ──"
  # WHAT A SECOND DEVICE OF ONE PERSON NEEDS, and where 0.5.214 put it.
  #
  # The mint files the identity under the CONVENTIONAL `<alias>-user` name, and
  # since the home-scoping cut (CIRISServer#621 / CIRISVerify#285) its two
  # halves live in two places:
  #
  #   identity/user/<alias>-user.ed25519.seed   the classical half, raw
  #   identity/user/<alias>-user.backend        which custody re-opens it
  #   identity/keys/<alias>-user.mldsa65.seed.blob   the PQC half, SEALED
  #   identity/keys/<alias>-user.master.key          the seal's master key
  #
  # There is no raw `.mldsa65.seed` any more — that is the point of home
  # scoping, and it is also why this copy is a faithful stand-in for
  # `POST /v1/self/associate` with a portable keyset: a home's key material is
  # now a self-contained unit, so carrying it carries the identity.
  local user_alias="${SELF_OWNER_ALIAS}-user"
  local moved=0 pair src dst name
  for pair in "identity/user:${user_alias}.ed25519.seed" \
              "identity/user:${user_alias}.backend" \
              "identity/keys:${user_alias}.mldsa65.seed.blob" \
              "identity/keys:${user_alias}.master.key"; do
    src="${pair%%:*}"; name="${pair#*:}"; dst="$src"
    compose exec -T "$SELF_PRIMARY" sh -c "base64 -w0 < /var/lib/ciris/$src/$name 2>/dev/null" \
      >"$SELF_STATE/$name.b64" 2>/dev/null || true
    if [ -s "$SELF_STATE/$name.b64" ]; then
      compose exec -T "$SELF_SECOND" sh -c \
        "mkdir -p /var/lib/ciris/$dst && base64 -d > /var/lib/ciris/$dst/$name && chmod 600 /var/lib/ciris/$dst/$name" \
        <"$SELF_STATE/$name.b64" 2>/dev/null || true
      moved=$((moved + 1))
    else
      echo "  ! $src/$name is empty or missing on $SELF_PRIMARY"
    fi
  done
  # The alias pointer, so the second node re-opens the SAME identity.
  compose exec -T "$SELF_SECOND" sh -c \
    "printf '%s' '$user_alias' > /var/lib/ciris/identity/user/active_user_alias" 2>/dev/null || true
  echo "  carried $moved/4 key files"

  # ── CLAIM BOTH NODES WITH THAT IDENTITY ──────────────────────────────────
  local pin code claim claim_json token owner waited
  for svc in $SELF_NODES; do
    pin=""; waited=0
    while [ "$waited" -lt 90 ]; do
      pin="$(compose exec -T "$svc" sh -c 'cat /var/lib/ciris/claim_pin 2>/dev/null' 2>/dev/null | tr -d '\r\n')"
      [ -n "$pin" ] && break
      sleep 5; waited=$((waited + 5))
    done
    [ -z "$pin" ] && { echo "  ✗ $svc: no claim PIN after ${waited}s"; continue; }
    code="$(compose exec -T "$svc" python -c 'import json,urllib.request;print(json.load(urllib.request.urlopen("http://127.0.0.1:4243/v1/federation/node-code",timeout=10))["code"])' 2>/dev/null | tr -d '\r\n[:space:]')"
    [ -z "$code" ] && { echo "  ✗ $svc: no node-code"; continue; }
    claim="$(compose exec -T "$svc" "$SELF_CONSOLE" claim --backend software \
               --home /var/lib/ciris --key-id "$SELF_OWNER_ALIAS" \
               --node-code "$code" --claim-pin "$pin" \
               --cohort-scope self --target-url http://127.0.0.1:4243 2>"$SELF_STATE/claim-$svc.err")"
    printf '%s\n' "$claim" >"$SELF_STATE/claim-$svc.out"
    claim_json="$(printf '%s\n' "$claim" | sed -n '/^{/,$p')"
    token="$(printf '%s' "$claim_json" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("access_token") or "")
except Exception: print("")')"
    owner="$(printf '%s' "$claim_json" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("identity_key_id") or "")
except Exception: print("")')"
    printf 'SELF_TOKEN_%s=%s\n' "${svc//-/_}" "$token" >>"$SELF_STATE/vars.sh"
    printf 'SELF_OWNER_%s=%s\n' "${svc//-/_}" "$owner" >>"$SELF_STATE/vars.sh"
    echo "  $svc: owner=${owner:-<none>} token=${token:+yes}"

    # ANNOUNCE, or the node is P2P-only and every room row is withheld both
    # ways (the 0.5.213 lesson, and the reason this is beside the claim).
    _self_api "$svc" POST /v1/federation/announce '{}' >"$SELF_STATE/announce-$svc.json" || true
  done

  # ── PEER THE TWO DEVICES ─────────────────────────────────────────────────
  # WHY A SELF ROOM STILL NEEDS PEERING, even though a self row carries no
  # grant. persist's `send_set_for` (v46.3.1 `federation/self_collective.rs`)
  # answers, for cohort_scope `self`, `consent_peers ∪ nodes_of(principals(k))`
  # — the owner's own nodes, no grant required. But `nodes_of` is a DIRECTORY
  # read: node-a can only union node-c if node-a's directory HOLDS node-c's
  # owner-binding, and that binding is a `self:delegates_to:` row that crosses
  # only over an admitted peer link. Without this block every node answers
  # `SoleDevice` forever and every rung above `one_owner` is vacuous — which is
  # exactly what runs 1-4 measured.
  #
  # `file:` is in the prefix set deliberately: a file row rides its own
  # `file:v1` dimension (edge `files::FILE_DIMENSION`) and edge's
  # DEFAULT_CONSENT_PREFIXES does NOT cover it. For the self plane the send set
  # is scope-derived so the prefix is not load-bearing, but a community file to
  # a consented peer IS grant-covered, and a missing prefix is SILENT — the
  # same shape the `chat:` entry in that constant is commented for.
  echo "── selffiles: peering the two devices ──"
  local a b rec peered=0
  for svc in $SELF_NODES; do
    compose exec -T "$svc" python -c 'import json,urllib.request;print(json.dumps(json.load(urllib.request.urlopen("http://127.0.0.1:4243/v1/federation/test-blessed-self-record",timeout=20))))' \
      >"$SELF_STATE/record-$svc.json" 2>/dev/null || true
    [ -s "$SELF_STATE/record-$svc.json" ] || echo "  ! $svc: no blessed self record"
  done
  for a in $SELF_NODES; do
    for b in $SELF_NODES; do
      [ "$a" = "$b" ] && continue
      [ -s "$SELF_STATE/record-$b.json" ] || continue
      rec="$(python3 -c '
import json,sys
r=json.load(open(sys.argv[1]))
print(json.dumps({"peer_key_id": r["record"]["key_id"], "peer_key_record": r,
                  "attestation_prefixes": ["capacity:","chat:","file:","ownership:","self:delegates_to:","trace:"]}))' \
        "$SELF_STATE/record-$b.json" 2>/dev/null)"
      [ -n "$rec" ] || continue
      _self_api "$a" POST /v1/federation/peering "$rec" >"$SELF_STATE/peering-$a-$b.json" || true
      if python3 -c '
import json,sys
try: print(0 if json.load(open(sys.argv[1])).get("status")!=200 else 1)
except Exception: print(0)' "$SELF_STATE/peering-$a-$b.json" 2>/dev/null | grep -q 1; then
        peered=$((peered + 1))
      else
        echo "  ! peering $a->$b: $(head -c 200 "$SELF_STATE/peering-$a-$b.json" 2>/dev/null)"
      fi
    done
  done
  echo "  peered $peered pairs"

  # WAIT FOR THE ROSTER, NOT JUST FOR THE PEER. Peering is admitted
  # synchronously, so `peers >= 1` is true a millisecond later and proves
  # nothing about the thing the write below depends on: `files::publish` wraps
  # the DEK to the occurrences the directory knows AT WRITE TIME. Seal before
  # node-c's owner-binding has crossed and node-c is `excluded` — it would list
  # the row and read `not_granted`, which looks like a key bug and is really a
  # harness that raced its own setup.
  #
  # The honest signal is the drive's own: a tick that is not `SoleDevice` means
  # `nodes_owned_by(owner)` has answered two. That is the same thing
  # `stage_roster` reads, deliberately — the rung and the precondition are one
  # fact, and inventing a second probe for it is how they drift apart.
  local waited=0 seen=0 rostered=0
  while [ "$waited" -lt 180 ]; do
    seen="$(_self_api "$SELF_PRIMARY" GET /v1/federation/peers '' 2>/dev/null | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: print(0); raise SystemExit
print(len(d.get("body",{}).get("peers",[]) or []))' 2>/dev/null || echo 0)"
    # The tick names are the LOG's spelling, not the action enum's:
    # `PublishedKeyPackage`, past tense. `PublishKeyPackage` matched nothing.
    if _self_log_has "$SELF_PRIMARY" 'self room drive tick=(Created|Added|PublishedKeyPackage|Idle)'; then
      rostered=1; break
    fi
    sleep 10; waited=$((waited + 10))
  done
  echo "  $SELF_PRIMARY: peers=${seen:-0} roster_converged=$rostered after ${waited}s"
  [ "$rostered" = 1 ] || echo "  ! writing anyway so the ladder NAMES the rung that fails rather than hanging"

  # ── WRITE A NOTE AND A FILE ON THE PRIMARY ───────────────────────────────
  echo "── selffiles: writing a note and a self file on $SELF_PRIMARY ──"
  _self_api "$SELF_PRIMARY" POST /v1/notes "$(python3 -c 'import json,sys;print(json.dumps({"body":sys.argv[1]}))' "$SELF_NOTE_TEXT")" \
    >"$SELF_STATE/note.json" || true
  _self_api "$SELF_PRIMARY" POST /v1/files "$(python3 -c '
import base64, json, sys
print(json.dumps({"cohort":"self","bytes_base64":base64.b64encode(sys.argv[1].encode()).decode(),
                  "media_type":"text/plain","filename":"proof.txt"}))' "$SELF_FILE_TEXT")" \
    >"$SELF_STATE/file.json" || true
  cat "$SELF_STATE/file.json" 2>/dev/null | head -c 400; echo
}

stage_rooted() {
  local svc n=0
  for svc in $SELF_NODES; do
    # The line reads "TEST TRUST ROOT active" in caps, hence the alternation.
    _self_log_has "$svc" '[Tt][Rr][Uu][Ss][Tt] [Rr][Oo][Oo][Tt]' && n=$((n+1))
  done
  echo "$n"
}
HINT_rooted="a node never rooted to the test trust root — the anchor block is per persist/verify pair; run anchor_block_verifies"
EXIT_rooted=30

stage_one_owner() {
  _self_load
  local a b
  eval "a=\${SELF_OWNER_${SELF_PRIMARY//-/_}:-}"
  eval "b=\${SELF_OWNER_${SELF_SECOND//-/_}:-}"
  [ -n "$a" ] && [ "$a" = "$b" ] && echo 1 || echo 0
}
HINT_one_owner="the two nodes did not claim the SAME fed-ID. Read claim-*.out: if the second node minted its own identity, the owner's seed files did not arrive, and there is no self-collective to test"
EXIT_one_owner=41

stage_roster() {
  # The directory's answer, read off the primary's own drive surface: a self
  # room needs two nodes owned by one person before anything can converge.
  local svc n=0
  for svc in $SELF_NODES; do
    _self_log_has "$svc" 'self room drive tick=(Created|Added|Idle|PublishedKeyPackage)' && n=$((n+1))
  done
  echo "$n"
}
HINT_roster="neither node's self-room drive advanced past SoleDevice — \`nodes_owned_by(owner)\` still answers one node, so the directory has not converged the second owner-binding"
EXIT_roster=42

stage_room() {
  local svc
  for svc in $SELF_NODES; do
    if _self_log_has "$svc" 'self room CREATED'; then echo 1; return; fi
  done
  echo 0
}
HINT_room="no node created the self room. \`self_room::decide\` returns Create only for the node the rule picks; if every node says SoleDevice the roster never reached two"
EXIT_room=43

stage_note() {
  python3 -c '
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print(0); raise SystemExit
print(1 if d.get("status")==200 and d.get("body",{}).get("attestation_id") else 0)' "$SELF_STATE/note.json" 2>/dev/null || echo 0
}
HINT_note="the note was refused. A note is a chat row in the self room — if this fails the owner's pen is unavailable or the row could not be placed"
EXIT_note=44

# ── #626: the write-side checks, and the three pull regressions ─────────────
#
# Edge's adoption note for the file door (CIRISServer#626 §5) names what a SELF
# write must look like, and three outcomes that must NEVER appear for a self
# pull. Each is a distinct regression, so each is checked by NAME and the
# diagnosis says which one fired rather than lumping them into "red".
#
#   write side (stage_file):
#     tier == InvisibleEncrypted    a self file is sealed to the owner's devices
#     excluded == []                non-empty = partial readability: those
#                                   occurrences will read not_granted
#     no `announced: true`          a self blob NEVER emits a holder claim (CC 5.2 /
#                                   persist I52); edge logs the pull as
#                                   `Stored { announced: false }`, and `true` is a
#                                   conformance break, not a nicety
#     no holds_bytes: row           the same fact read off the ROWS: no holder
#                                   claim exists on either device for a self write
#   pull side (stage_opened_on_b):
#     no `outcome=NoHolders`        the §6.2 source rule regressed — a self pull
#                                   must never consult the claim index
#     no `NoMeaning(GroupWithoutId` the §6.2 projector regressed (NOT the same as
#                                   `AuthorUnresolved`, the legitimate wait)
#     no `self:claim_index` key     the first regression seen from edge's
#                                   `blob_pull_sources` counter (GET
#                                   /v1/federation/metrics, since 0.5.218)
#
# Every scan is `grep -c … || true` (see `_self_log_has`), and every conditional
# is an `if`: a false `[ … ] && x` as a function's last command returns non-zero
# under `set -e`.

# How many lines in THIS service's log match? Numeric, never empty.
_self_log_count() {
  local svc="$1" re="$2" n
  n="$(compose logs "$svc" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' | grep -cE "$re" || true)"
  echo "${n:-0}"
}

# The file write's own claims, from its 200 body. Prints one word per failed
# check (empty = all hold), so the stage and its diagnosis read the same fact.
_self_file_write_faults() {
  python3 -c '
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print("no_response"); raise SystemExit
b=d.get("body",{}) or {}
out=[]
if d.get("status")!=200: out.append("status=%s" % d.get("status"))
if b.get("crossed") is not True: out.append("crossed=%s" % b.get("crossed"))
if b.get("tier")!="InvisibleEncrypted": out.append("tier=%s" % b.get("tier"))
if b.get("excluded")!=[]: out.append("excluded=%s" % json.dumps(b.get("excluded")))
print(" ".join(out))' "$SELF_STATE/file.json" 2>/dev/null || echo "unreadable"
}

# Cross-node faults a self write must never produce. One word per fault.
_self_file_mesh_faults() {
  local svc n out=""
  for svc in $SELF_NODES; do
    n="$(_self_log_count "$svc" 'Stored \{ announced: true')"
    if [ "$n" -gt 0 ]; then out="$out announced_true@$svc=$n"; fi
    n="$(harness_db_count "$svc" federation_attestations "attestation_type LIKE 'holds_bytes:%'")"
    case "$n" in
      0) ;;
      -1|"") out="$out holds_bytes_unreadable@$svc" ;;
      *) out="$out holds_bytes@$svc=$n" ;;
    esac
  done
  echo "$out"
}

# The three pull regressions. One word per fault. Also refreshes
# metrics-<svc>.json, which the diagnosis and the evidence tail print.
_self_pull_faults() {
  local svc n out=""
  for svc in $SELF_NODES; do
    n="$(_self_log_count "$svc" 'outcome=NoHolders')"
    if [ "$n" -gt 0 ]; then out="$out NoHolders@$svc=$n"; fi
    n="$(_self_log_count "$svc" 'NoMeaning\(GroupWithoutId')"
    if [ "$n" -gt 0 ]; then out="$out GroupWithoutId@$svc=$n"; fi
    _self_api "$svc" GET /v1/federation/metrics '' >"$SELF_STATE/metrics-$svc.json" 2>/dev/null || true
    n="$(python3 -c '
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print(0); raise SystemExit
src=((d.get("body") or {}).get("data") or {}).get("blob_pull_sources") or {}
print(sum(v for k,v in src.items() if k in ("self:claim_index","family:claim_index")))' \
      "$SELF_STATE/metrics-$svc.json" 2>/dev/null || echo 0)"
    if [ "${n:-0}" -gt 0 ]; then out="$out claim_index_source@$svc=$n"; fi
  done
  echo "$out"
}

# The pull sources, as the metrics snapshot last reported them.
_self_pull_sources() {
  python3 -c '
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print("{}"); raise SystemExit
print(json.dumps(((d.get("body") or {}).get("data") or {}).get("blob_pull_sources") or {}))' \
    "$SELF_STATE/metrics-$1.json" 2>/dev/null || echo "{}"
}

stage_file() {
  # 200 AND crossed AND the #626 write-side shape. `crossed == false` is a file
  # that reached nobody; the rest are the conformance checks above.
  local w m
  w="$(_self_file_write_faults)"
  m="$(_self_file_mesh_faults)"
  if [ -z "${w// /}" ] && [ -z "${m// /}" ]; then echo 1; else echo 0; fi
}
HINT_file="the self file write is not what a self write must be (CIRISServer#626 §5); the diagnosis names the failed check. crossed=false is local-tier (persist's E5 invariant keeps it out of every federation stream, so no device lists it); tier≠InvisibleEncrypted is the wrong room tier; a non-empty excluded is partial readability (those occurrences read not_granted); announced_true or a holds_bytes: row is a self blob that emitted a holder claim, which CC 5.2 / persist I52 forbid"
EXIT_file=45
DIAG_file() {
  echo "  write-side faults: $(_self_file_write_faults)"
  echo "  mesh faults:       $(_self_file_mesh_faults)"
  local svc
  for svc in $SELF_NODES; do
    echo "  $svc: Stored{announced:false}=$(_self_log_count "$svc" 'Stored \{ announced: false') Stored{announced:true}=$(_self_log_count "$svc" 'Stored \{ announced: true')"
  done
  echo "  write body: $(head -c 500 "$SELF_STATE/file.json" 2>/dev/null)"
}

stage_mine_on_b() {
  # THE CLAIM: the second device LISTS the file.
  _self_api "$SELF_SECOND" GET /v1/drive '' >"$SELF_STATE/drive-b.json" 2>/dev/null || true
  python3 -c '
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print(0); raise SystemExit
print(1 if any(e.get("filename")=="proof.txt" for e in d.get("body",{}).get("entries",[])) else 0)' \
    "$SELF_STATE/drive-b.json" 2>/dev/null || echo 0
}
HINT_mine_on_b="the second device does not LIST the file. The row did not cross: check persist send_set_for (a self row reaches the owner's own nodes with no grant), and that both nodes announced"
EXIT_mine_on_b=46

stage_opened_on_b() {
  # A regression in the pull's source rule or projector fails this rung even if
  # the bytes opened (a claim-index source can find a holder by accident on a
  # two-node mesh) — #626 asks for each by name.
  if [ -n "$(_self_pull_faults | tr -d ' ')" ]; then echo 0; return; fi
  python3 -c '
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print(0); raise SystemExit
print(1 if any(e.get("filename")=="proof.txt" and e.get("bytes")=="here"
               for e in d.get("body",{}).get("entries",[])) else 0)' \
    "$SELF_STATE/drive-b.json" 2>/dev/null || echo 0
}
HINT_opened_on_b="the second device cannot OPEN the file's bytes, or a self pull regressed. If the diagnosis lists NoHolders or claim_index_source, the §6.2 SOURCE RULE regressed (a self pull reads self:author_nodes, never the claim index); GroupWithoutId means the §6.2 PROJECTOR regressed (not AuthorUnresolved, the legitimate wait). Otherwise the self room did not admit it: check \`tick=Added(0)\` on the creator (it cannot see the joiner's KeyPackage — is the row in the SELF room, not \`chat:pair:v1:*\`? src/self_room_drive.rs must use key_package_attestation_in / welcome_attestation_in, CIRISEdge#656), then \`self room JOINED\` on the joiner (welcome_for must find a Welcome naming THIS node), then the scope-address install on both"
EXIT_opened_on_b=47
DIAG_opened_on_b() {
  echo "  pull regressions: $(_self_pull_faults)"
  local svc
  for svc in $SELF_NODES; do
    echo "  $svc blob_pull_sources: $(_self_pull_sources "$svc")"
  done
}

harness_scenario_evidence() {
  echo "── the self-room drive, both nodes ──"
  harness_timeline 'self room|self-room|drive_once|SelfRoomTick' $SELF_NODES 2>/dev/null | tail -24
  echo
  echo "── what the second device sees ──"
  head -c 900 "$SELF_STATE/drive-b.json" 2>/dev/null; echo
  echo "── the write ──"
  head -c 500 "$SELF_STATE/file.json" 2>/dev/null; echo
  echo "── pull sources (MUST be self:author_nodes, never self:claim_index) ──"
  # Read from the metrics snapshot (GET /v1/federation/metrics
  # `blob_pull_sources`, 0.5.218). This was a log grep, and edge never LOGS the
  # counter, so it could only ever print nothing.
  echo "  regressions: $(_self_pull_faults)"
  local svc
  for svc in $SELF_NODES; do
    echo "  $svc: $(_self_pull_sources "$svc")"
  done
}
