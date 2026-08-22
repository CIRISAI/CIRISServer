#!/usr/bin/env bash
# scenarios/chat.sh — a message written by a person on node A must ARRIVE, intact and attributed, on node B.
#
# THE LEG SINGLE-NODE CI CANNOT REACH (CIRISServer#455). `tests/contacts_chat.rs`
# and `benches/chat_throughput.rs` both drive the REAL router against ONE
# substrate: every message is written and read through the same Engine, so the
# whole delivery question — does the row leave this node, does the other node
# admit it, does it survive the wire with its CEG identity — is answered by
# assignment rather than by measurement. The bench says so itself, reporting
# `ran: false` for the cross-node phase. This scenario is that phase.
#
# The claim under test is NOT "chat works". It is the narrower, checkable one the
# derived community id makes: TWO NODES THAT NEVER COORDINATED FIND THE SAME ROOM,
# AND ONE'S BYTES REACH THE OTHER'S TRANSCRIPT. `pair_community_key_id` is proven
# order-free by a unit test in one process; `room` below proves it across two
# sovereign directories, which is the only place it could actually diverge.
#
# ── What each node is ────────────────────────────────────────────────────────
#
#   canonical — a real canonical (test_bless: `canonical,node` + `infra:serve`),
#               the dial target and the transport relay. NOT a member of the room.
#   node-a    — the SENDER. Ordinary owner-claimed node, no canonical bless.
#   node-b    — the RECIPIENT.
#
# All three are `ciris-server` processes because `/v1/contacts` and `/v1/chat`
# live in `serve_with_adapter`; the base file's python `agent` role mounts no HTTP
# router at all and could not be a party to a chat.
#
# ── Honesty posture ──────────────────────────────────────────────────────────
#
# Every stage is probed independently rather than inferred from the end state,
# for the same reason traceflow's are: a green transcript on node B could mean
# the row replicated, or it could mean node B derived the same room and is
# reading its OWN message back. `arrived` therefore keys on the SENDER's
# `attestation_id`, captured from node A's send response — a value node B has no
# way to produce for itself — and `hamburger` re-checks the attester, so a row
# that arrived stripped of its identity fails rather than counting.
#
# ORDER IS THE OTHER HALF OF THAT. The monotonic verdict treats a positive later
# stage as proof of every earlier one, so a stage that does NOT depend on
# delivery must not sit behind delivery in the array: `dark` and `one_sided` both
# pass or fail on their own, and either one placed after `arrived` would silently
# certify a delivery that never happened. They sit before it. `hamburger` is the
# one stage that genuinely reads the delivered row, so it is last.
#
# ── The two phases, and why the driver is split ──────────────────────────────
#
# `harness_scenario_prepare` runs the driver twice. Phase SEND peers everyone and
# then the SENDER ALONE opens the room and speaks; phase JOIN has each recipient
# derive the same room and open it. Between them is a bounded window in which
# exactly one node has authored the roster — and that window is the only moment
# `one_sided` can be asked, because after JOIN every recipient holds a room row it
# MINTED and no probe can tell that from a replicated one. The first version of
# this driver opened both rooms up front and could not ask the question at all.

# ── WHAT THIS MEASURED (2026-08-20, server 0.5.185; two runs, fresh key material
#    each time, identical outcome) ──────────────────────────────────────────────
#
# Stages 1-6 GREEN, and TWO reds — one expected, one not.
#
#   rooted ✓  peered ✓  contact ✓  room ✓  sent ✓  dark ✓
#   one_sided ⚠ RED-EXPECTED    arrived ✗    hamburger · downstream
#
# ONE_SIDED, the expected red, measured from the product surface: while only the
# sender held the roster, the recipient answered `404 chat.unknown_community` and
# held 0 `federation_communities` rows for that id. It then DERIVED the identical
# id in phase JOIN (`fresh=True` — it minted its own). So a room reaches the other
# party only by convergent derivation, never by invitation; see XFAIL_one_sided
# for the one-line composition gap behind it.
#
# The two nodes converged on ONE derived community id from public inputs alone —
# byte-identical on both sides, and on BOTH runs despite entirely different
# owner and node keys. Node A's send returned an attestation_id, and the
# replication plane CARRIED the row: node B logged the envelope delivered ~30 s
# later (one anti-entropy round). Node B then REFUSED it at persist's bulk
# ingest gate:
#
#   federation-tier attestation "db61c116-…"
#   (attesting_key_id="ciris-node-a-user-y364lsrrrh") rejected at the bulk
#   ingest gate: hybrid-verify: crypto: Classical signature verification
#   failed: Ed25519 (verify_hybrid_crypto)
#
# THE MECHANISM: on node A that row carries
# `attesting_key_id = ciris-node-a-user-…` (the OWNER — the human wrote it) and
# `scrub_key_id = ciris-node-a-…` (the NODE). `send_message` stages the row with
# `attestation_upsert_local` naming the owner as attester and DEFERS the
# signature to `attestation_promote`, which signs with the Engine's own composed
# signer — the node's key. Persist's `verify_row_hybrid_signature` verifies that
# signature against the ATTESTER's registered pubkeys and consults `scrub_key_id`
# nowhere; there is no signer-acts-for path in that gate. So the row is authored
# by the person and signed by the box, and only the wire can tell.
#
# The same run supplies the control: SEVEN other node-A-authored federation-tier
# rows, over the SAME link in the SAME rounds — including both consent grants,
# admitted 30.0 s after they were authored — all had `attesting_key_id ==
# scrub_key_id` and ALL landed on node B. Every refused row — four of them — had
# the split. That correlation is what makes this a diagnosis rather than a guess,
# and it is why the DIAG prints both counts rather than only the failure.
#
# WHAT WENT RIGHT AND IS NOW PINNED ACROSS TWO REAL NODES: the derived room
# converged on two independent runs with entirely different key material, and the
# consent WIDENING path landed. `POST /v1/contacts` arrived at a peer that already
# held a `self:delegates_to:`-only grant (the admission door authors one) and
# superseded it with the union — measured on node A as two rows 17 ms apart:
#
#   4958828a…  ['self:delegates_to:']
#   3e4daa88…  ['capacity:', 'chat:', 'self:delegates_to:', 'trace:']
#
# That is `ensure_replication_consent_covers` (CIRISServer PR #464 P1) working on
# the exact case that used to be a silent no-op, verified over the wire rather
# than in one process.
#
# `dark` IS GREEN, and it earns it: the canonical — holding a `chat:`-covering
# consent grant from BOTH nodes — asked for the room and got
# `404 chat.unknown_community`, with no message text anywhere in the body. It
# also held ZERO copies of the message row, which is reported separately rather
# than folded into the pass: the refusal is the claim, and what the refuser was
# holding is context. (An earlier draft GATED this stage on `arrived` to dodge a
# monotonic false green; moving it before `arrived` in the array does the same
# job without hiding a property that passes on its own.)
#
# WHY `arrived` IS NOT MARKED RED-EXPECTED, though `one_sided` is. The marking
# exists so a KNOWN, NAMED gap does not become a recurring CI failure everyone
# routes around — not so a ladder can be green. `one_sided` earns it: the roster
# plane is unwired, the product consequence is bounded and stated, and delivery
# still works by convergent derivation. `arrived` does not: with it red, chat
# does not cross a node boundary AT ALL, and a green gate over that is exactly
# the false green this repo keeps paying for. This ladder gates PRs, so it stays
# red until the producer signs as the owner — which is the point of gating on it.
#
# It is NOT fixable in this directory: the producer is `src/contacts_chat.rs`.
# `owner_signer_capsule::acquire` (CIRISServer#342) is the mechanism that would
# put the OWNER's own signature on the row without the key leaving the node.
# Until that lands, this ladder is honestly red at `arrived`, exactly as
# `genesis_seed` is honestly red at its unmet preconditions.

# ── THE ASKS, in full — the union of this ladder's reds ─────────────────────
#
# The point of probing every stage independently is that when one goes red, the
# red is a SENTENCE someone can act on. Three, in dependency order:
#
#  1. SERVER — sign the message as its attester. `send_message` must put the
#     OWNER's own hybrid signature on the row (`owner_signer_capsule::acquire`,
#     CIRISServer#342) instead of deferring to `attestation_promote`, whose
#     signer is the node. Until then `arrived` is red and chat cannot cross a
#     node boundary at all. WHEN THIS LANDS: nothing here changes; re-run.
#
#  2. SERVER — register the roster plane. `compose::build_replication_peers`
#     (src/compose.rs:3045) needs `EnvelopeKind::Community` (and `Family`, by the
#     same argument). Edge and persist both implement the plane end to end; only
#     the registration is missing. WHEN THIS LANDS: delete `XFAIL_one_sided`
#     below — that one deletion turns the stage into a live gate, and nothing
#     else in this file needs to move.
#
#  3. PERSIST — decide the `chat:` family. This is the ONLY persist-side ask, and
#     it is one registry row. `chat:message:v1` resolves
#     `AttestationFamily::Unknown` today, so `projection_for` gives it the
#     conservative default — which at `cohort_scope: community` is
#     `Projection::Cohort`, i.e. ADVERTISED. That is confirmed empirically here,
#     not assumed: the recipient logged the envelope DELIVERED before refusing it
#     at the ingest gate, so chat is NOT blocked by an undecided family and never
#     was. What is missing is that the cell is INHERITED rather than chosen. The
#     precedent is `moderation:*` in persist v37.0.1, which enumerated its commons
#     tiers explicitly for exactly this reason: a later consistency sweep that
#     "finished" a wildcard-inherited row would lift the ceiling silently, and no
#     test looked at that cell. The answer chat wants is the community roster.
#
# Nothing else is missing. Everything else this ladder touches is green.

SCENARIO_NAME="chat"
COMPOSE_FILES="-f docker-compose.chat.yml"
SUCCESS_STAGE="hamburger"
SUCCESS_MESSAGE="cross-node chat PROVEN — two nodes converged on one derived room with no coordination, A's bytes landed in B's transcript with their CEG identity intact (attester the node, author the owner, verified on the real receive path), and the canonical that carries the mesh cannot read the room."

# ORDERED BY DEPENDENCY, because the monotonic verdict treats a positive later
# stage as PROOF of every earlier one. `dark` and `one_sided` are independent of
# delivery, so they sit BEFORE `arrived`: put either after it and a green there
# would silently certify a delivery that never happened. That ordering rule is
# the whole reason this ladder is not simply the narrative order.
STAGES=(rooted peered contact room sent dark one_sided arrived hamburger)
# (The definitions below are grouped by topic, not by ladder position — each
#  header carries its own number, and THIS array is the running order.)

# Per-run scratch. Everything the probes need is flattened into `vars.sh` by
# `harness_scenario_prepare`, because a probe runs in a command-substitution
# SUBSHELL (lib/harness.sh `harness_sample`) and cannot inherit state any other way.
CHAT_STATE="${TMPDIR:-/tmp}/ciris-chat-${PROJECT:-ciris-chat}"
CHAT_MESSAGE_TEXT="${CHAT_MESSAGE_TEXT:-mesh-harness cross-node chat proof $(date -u +%Y%m%dT%H%M%SZ)}"

# THE PARTY LIST, not a hardcoded pair. `CHAT_NODES` is ordered: the FIRST is
# the sender, the rest are recipients, and every stage below is stated over
# (sender, recipient) rather than over "a and b". Adding a node is one entry here
# plus one service block in the compose file (which allocates 172.29.77.11+N and
# is otherwise a copy) — the future scale scenarios for voting and video compose
# from these same stages, so two-ness is nowhere in the logic.
CHAT_NODES="${CHAT_NODES:-node-a node-b}"
CHAT_SENDER="${CHAT_NODES%% *}"
CHAT_RECIPIENTS="${CHAT_NODES#* }"
# Every service that gets claimed. The canonical is always present: it is the
# dial target, and it is the non-member the `dark` stage interrogates.
CHAT_SERVICES="canonical $CHAT_NODES"

# WHO MAY ATTEST A COMMUNITY-SCOPED CHAT ROW, and what the route calls the AUTHOR.
#
# `attesting_key_id` is the key that SIGNED; the author field is the person the
# signed envelope attributes the words to. They are separate questions and the
# projection answers them separately (team-lead ruling, §8.1.12.7 fidelity).
#
#   CHAT_ATTESTER_WORLD=node   persist v38 — `put_attestation` refuses every
#                              community-scope row at the write gate, so
#                              `attestation_promote`'s re-seal is the only minting
#                              door and it signs with the engine (e81a103). The
#                              split is the design; the stage asserts it.
#   CHAT_ATTESTER_WORLD=owner  after persist ask (a) or (b) — the producer's
#                              signature survives promotion and the two converge.
#
# CHAT_AUTHOR_FIELD is EMPTY until server-wire reports the name it chose. Empty
# means the stage refuses to assert rather than probe a guess: a name that does
# not exist and a feature that does not work read identically from here.
CHAT_ATTESTER_WORLD="${CHAT_ATTESTER_WORLD:-node}"
CHAT_AUTHOR_FIELD="${CHAT_AUTHOR_FIELD:-author}"
# The console binary, bind-mounted from the SAME release build that produced the
# wheel (docker-compose.chat.yml). `identity create` and `claim` live only in the
# Rust bin target; the wheel's `ciris-server` console script cannot run them.
CHAT_CONSOLE="/opt/harness/ciris-server-bin"
# The keystore alias each `ciris-server` boots under (docker-compose.chat.yml).
# The alias is the INPUT to the #247 key derivation, not its output — the derived
# federation key_id is read back off the directory in `chat_drive.py`.
_chat_alias() {
  case "$1" in
    canonical) echo "ciris-canonical-1" ;;
    *) echo "ciris-$1" ;;
  esac
}

_chat_load() {
  # shellcheck source=/dev/null
  [ -f "$CHAT_STATE/vars.sh" ] && . "$CHAT_STATE/vars.sh"
  return 0
}

# ── prepare: claim three nodes, then drive contacts → room → send ────────────
harness_scenario_prepare() {
  rm -rf "$CHAT_STATE"
  mkdir -p "$CHAT_STATE"
  echo "── chat: waiting for all three nodes ──"
  local svc
  for svc in $CHAT_NODES; do harness_wait_healthy "$svc" 36; done

  # Fail LOUD if the console binary did not come through the bind mount: docker
  # silently creates a DIRECTORY for a missing bind source, and every claim below
  # would then fail with a shell error that says nothing about the cause.
  if ! compose exec -T canonical test -x "$CHAT_CONSOLE" >/dev/null 2>&1; then
    echo "  ✗ $CHAT_CONSOLE is not an executable inside the containers — the bind"
    echo "    mount of target/release/ciris-server did not resolve. Build it first:"
    echo "    cargo build --release --features test-anchor,python"
  fi

  : >"$CHAT_STATE/vars.sh"
  local state_json="$CHAT_STATE/state.json"
  python3 - "$state_json" "$CHAT_MESSAGE_TEXT" "$CHAT_SENDER" "$CHAT_RECIPIENTS" <<'PY'
import json, sys
path, message, sender, recipients = sys.argv[1:5]
json.dump({
    "message": message,
    "sender": sender,
    "recipients": recipients.split(),
    "owner_key_wait_secs": 90,
    # 45 s ≈ 1.5 anti-entropy rounds at the measured ~30 s cadence: long enough
    # that "the roster did not arrive" is a verdict and not a race.
    "one_sided_wait_secs": 45,
    "nodes": {},
}, open(path, "w"))
PY

  local svc alias code pin mint ed pqc claim claim_json token owner
  for svc in $CHAT_SERVICES; do
    alias="$(_chat_alias "$svc")"

    # THE ONE-TIME CLAIM PIN is console-only — printed to the node's log and
    # written 0600 to <home>/claim_pin, NEVER served over HTTP. Reading it inside
    # the container is the harness standing in for an operator at the console.
    pin=""
    local waited=0
    while [ "$waited" -lt 90 ]; do
      pin="$(compose exec -T "$svc" sh -c 'cat /var/lib/ciris/claim_pin 2>/dev/null' 2>/dev/null | tr -d '\r\n')"
      [ -n "$pin" ] && break
      sleep 5
      waited=$((waited + 5))
    done
    if [ -z "$pin" ]; then
      echo "  ✗ $svc: no claim PIN after ${waited}s — the node never armed first-run setup"
      continue
    fi

    # The NodeCode is the PUBLIC identity pin the claim carries, so the claimant
    # proves it reached the node it meant to.
    code="$(compose exec -T "$svc" python -c 'import json,urllib.request;print(json.load(urllib.request.urlopen("http://127.0.0.1:4243/v1/federation/node-code",timeout=10))["code"])' 2>/dev/null | tr -d '\r\n[:space:]')"
    if [ -z "$code" ]; then
      echo "  ✗ $svc: /v1/federation/node-code served nothing"
      continue
    fi

    # Mint the responsible party's USER fed-ID on the node's own console. NO
    # --label: `run_claim` re-opens the signer under the CONVENTIONAL alias
    # (`<keystore_alias>-user`), so a label here would mint a keyset the claim
    # could not find.
    mint="$(compose exec -T "$svc" "$CHAT_CONSOLE" identity create --backend software \
              --home /var/lib/ciris --key-id "$alias" 2>"$CHAT_STATE/mint-$svc.err")"
    printf '%s\n' "$mint" >"$CHAT_STATE/mint-$svc.out"
    ed="$(printf '%s\n' "$mint" | sed -n 's/^ *ed25519 pub *: *//p' | head -1 | tr -d '\r')"
    pqc="$(printf '%s\n' "$mint" | sed -n 's/^ *ml-dsa-65 pub *: *//p' | head -1 | tr -d '\r')"

    # The 1-phase claim, over loopback against the node's own read-API. It builds
    # and hybrid-signs the owner-binding in the node's substrate and POSTs it to
    # /v1/setup/root — which mints the owner SESSION in its response, so no
    # password round-trip is needed (CIRISServer#393).
    claim="$(compose exec -T "$svc" "$CHAT_CONSOLE" claim --backend software \
               --home /var/lib/ciris --key-id "$alias" \
               --node-code "$code" --claim-pin "$pin" \
               --cohort-scope self --target-url http://127.0.0.1:4243 \
               2>"$CHAT_STATE/claim-$svc.err")"
    printf '%s\n' "$claim" >"$CHAT_STATE/claim-$svc.out"
    claim_json="$(printf '%s\n' "$claim" | sed -n '/^{/,$p')"
    token="$(printf '%s' "$claim_json" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("access_token") or "")
except Exception: print("")')"
    owner="$(printf '%s' "$claim_json" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("identity_key_id") or "")
except Exception: print("")')"
    if [ -z "$token" ] || [ -z "$owner" ]; then
      echo "  ✗ $svc: claim did not yield a session (see $CHAT_STATE/claim-$svc.{out,err})"
      tail -3 "$CHAT_STATE/claim-$svc.err" 2>/dev/null | sed 's/^/      /'
      continue
    fi
    echo "  ✓ $svc claimed — owner=$owner"

    python3 - "$state_json" "$svc" "$token" "$owner" "$ed" "$pqc" <<'PY'
import json, sys
path, svc, token, owner, ed, pqc = sys.argv[1:7]
d = json.load(open(path))
d["nodes"][svc] = {
    "base": f"http://{svc}:4243",
    "token": token,
    "owner_key_id": owner,
    "owner_ed25519": ed,
    "owner_ml_dsa_65": pqc,
}
json.dump(d, open(path, "w"))
PY
  done

  # ── PHASE 1: peer everyone; the SENDER alone opens the room and speaks ────
  # Driven from INSIDE the sender's container: every service resolves the others
  # by name on the mesh bridge, and no read-API port has to be published.
  echo "── chat: phase SEND (peering, sender's contact + room + message) ──"
  if ! compose exec -T "$CHAT_SENDER" python /opt/harness/chat_drive.py drive send \
        <"$state_json" >"$CHAT_STATE/result_send.json" 2>"$CHAT_STATE/send.err"; then
    echo "  WARN: chat_drive.py drive send exited non-zero — the ladder will localise it"
  fi
  { sed 's/^/  /' "$CHAT_STATE/send.err" 2>/dev/null | tail -40; } || true

  # ── THE MEASUREMENT BETWEEN THE PHASES ────────────────────────────────────
  # Exactly one node has authored the community roster. Count the recipients'
  # OWN copies NOW: after phase 2 every recipient holds a row it DERIVED, and no
  # later probe could tell a replicated roster from a locally-minted one.
  local cid_sender recipient rows
  cid_sender="$(python3 -c 'import json,sys
try: print((json.load(open(sys.argv[1])).get("rooms") or {}).get(sys.argv[2], {}).get("community_id") or "")
except Exception: print("")' "$CHAT_STATE/result_send.json" "$CHAT_SENDER")"
  : >"$CHAT_STATE/one_sided_rows"
  for recipient in $CHAT_RECIPIENTS; do
    rows="$(harness_db_count "$recipient" federation_communities \
      "community_key_id = '${cid_sender:-none}'")"
    echo "  one-sided roster rows on $recipient: ${rows:-0}"
    echo "$recipient=${rows:-0}" >>"$CHAT_STATE/one_sided_rows"
  done

  # ── PHASE 2: the recipients DERIVE the same room and open it ──────────────
  echo "── chat: phase JOIN (each recipient's contact + room, by derivation) ──"
  if ! compose exec -T "$CHAT_SENDER" python /opt/harness/chat_drive.py drive join \
        <"$state_json" >"$CHAT_STATE/result_join.json" 2>"$CHAT_STATE/join.err"; then
    echo "  WARN: chat_drive.py drive join exited non-zero — the ladder will localise it"
  fi
  { sed 's/^/  /' "$CHAT_STATE/join.err" 2>/dev/null | tail -20; } || true

  python3 - "$CHAT_STATE" "$CHAT_MESSAGE_TEXT" "$CHAT_SENDER" "$CHAT_RECIPIENTS" <<'VARS'
import json, os, shlex, sys
state_dir, message, sender, recipients_raw = sys.argv[1:5]
recipients = recipients_raw.split()
first = recipients[0] if recipients else ""


def load(name):
    try:
        return json.load(open(os.path.join(state_dir, name)))
    except Exception:
        return {}


state = load("state.json")
send = load("result_send.json")
join = load("result_join.json")
nodes = state.get("nodes", {})
# The node key_id is discovered in BOTH phases; either result is authoritative.
disc = {**(send.get("nodes") or {}), **(join.get("nodes") or {})}
rooms = {**(send.get("rooms") or {}), **(join.get("rooms") or {})}
contacts = {**(send.get("contacts") or {}), **(join.get("contacts") or {})}
one_sided = (send.get("one_sided") or {}).get(first) or {}

# The roster-row counts the shell sampled BETWEEN the phases.
rows = {}
try:
    for line in open(os.path.join(state_dir, "one_sided_rows")):
        k, _, v = line.strip().partition("=")
        if k:
            rows[k] = v
except Exception:
    pass


def g(svc, key):
    return (nodes.get(svc) or {}).get(key) or ""


def n(svc):
    return (disc.get(svc) or {}).get("node_key_id") or ""


out = {
    "CHAT_MESSAGE": message,
    "CHAT_SENDER_SVC": sender,
    "CHAT_RECIPIENT_SVC": first,
    "CHAT_CANON_BASE": g("canonical", "base"),
    "CHAT_CANON_TOKEN": g("canonical", "token"),
    "CHAT_CANON_NODE_KEY": n("canonical"),
    "CHAT_A_BASE": g(sender, "base"),
    "CHAT_A_TOKEN": g(sender, "token"),
    "CHAT_A_OWNER": g(sender, "owner_key_id"),
    "CHAT_A_NODE_KEY": n(sender),
    "CHAT_B_BASE": g(first, "base"),
    "CHAT_B_TOKEN": g(first, "token"),
    "CHAT_B_OWNER": g(first, "owner_key_id"),
    "CHAT_B_NODE_KEY": n(first),
    "CHAT_CID_A": (rooms.get(sender) or {}).get("community_id") or "",
    "CHAT_CID_B": (rooms.get(first) or {}).get("community_id") or "",
    "CHAT_ATT_ID": (send.get("sent") or {}).get("attestation_id") or "",
    "CHAT_CONTACT_A_FRESH": str((contacts.get(sender) or {}).get("freshly_emitted")),
    "CHAT_CONTACT_B_FRESH": str((contacts.get(first) or {}).get("freshly_emitted")),
    "CHAT_OWNER_ADMIT_VIA": json.dumps(send.get("owner_admit_via") or {}),
    # The one-sided window, recorded verbatim: the HTTP answer the recipient gave
    # while only the sender held the roster, and the roster rows it held then.
    "CHAT_ONE_SIDED_STATUS": str(one_sided.get("status") or 0),
    "CHAT_ONE_SIDED_REASON": str(one_sided.get("reason_id") or ""),
    "CHAT_ONE_SIDED_ROWS": rows.get(first, "?"),
    "CHAT_DRIVE_ERRORS": " | ".join(
        (send.get("errors") or []) + (join.get("errors") or [])) or "<none>",
}
with open(os.path.join(state_dir, "vars.sh"), "w") as f:
    for k, v in out.items():
        f.write("%s=%s\n" % (k, shlex.quote(str(v))))
print("  prepare: " + " ".join(
    "%s=%s" % (k, v) for k, v in out.items()
    if k in ("CHAT_A_OWNER", "CHAT_B_OWNER", "CHAT_CID_A", "CHAT_CID_B", "CHAT_ATT_ID",
             "CHAT_OWNER_ADMIT_VIA", "CHAT_ONE_SIDED_STATUS", "CHAT_ONE_SIDED_REASON",
             "CHAT_ONE_SIDED_ROWS")))
VARS
}

# ── 1. rooted — all three nodes hold the synthetic trust root's graph ────────
# The root's SELF-REFERENTIAL charter plus this node's OWN `delegates_to(self →
# root)` edge. Both are minted locally by the test-anchor ceremony
# (`perform_trust_root_ceremony`); the point of probing them is that a node whose
# ceremony silently skipped roots to nothing, and every later admission then
# lands ADVISORY instead of Rooted — which surfaces three stages downstream as
# "the round times out", with no hint of the cause.
#
# ROOT-AGNOSTIC, on purpose, and the first draft was NOT. It keyed the charter on
# `attestation_id = 'genesis-charter'`, which is the id the BAKED bundle carries;
# the ceremony mints a UUID, so the probe read 0 on three perfectly rooted nodes
# and the stage was red while `peered`, `contact`, `room` and `sent` were all
# green — a monotonic ladder is what caught it, by proving stage 1 from
# downstream evidence. Ask the STRUCTURAL question instead: is there a charter at
# all (a delegates_to whose attester IS its subject), and has this node authored a
# trust edge to something that is not another ciris node.
_chat_rooted_one() {
  local svc="$1" prefix="$2" charter edge
  charter="$(harness_db_count "$svc" federation_attestations \
    "attestation_type='delegates_to' AND attesting_key_id = attested_key_id")"
  edge="$(harness_db_count "$svc" federation_attestations \
    "attestation_type='delegates_to' AND attesting_key_id LIKE '${prefix}-%' \
     AND attesting_key_id NOT LIKE '${prefix}-user%' \
     AND attested_key_id NOT LIKE 'ciris-%'")"
  if [ "${charter:-0}" -gt 0 ] && [ "${edge:-0}" -gt 0 ]; then echo 1; else echo 0; fi
}
stage_rooted() {
  local svc total=0 n=0
  for svc in $CHAT_SERVICES; do
    n=$((n + 1))
    total=$((total + $(_chat_rooted_one "$svc" "$(_chat_alias "$svc")")))
  done
  # All or nothing: one unrooted node admits its peers ADVISORY and the
  # consequence surfaces stages later with no hint of the cause.
  if [ "$total" -eq "$n" ]; then echo "$total"; else echo 0; fi
}
HINT_rooted="not every node holds the test trust root's graph (charter + their own trust edge). A node that minted no ceremony admits peers ADVISORY, and the consequence surfaces much later as a stalled round. Check CIRIS_TESTING_MODE + CIRIS_TEST_TRUST_ROOT_SEED on the RED node."
EXIT_rooted=30
DIAG_rooted() {
  local s
  for s in $CHAT_SERVICES; do
    echo "  $s: charters=$(harness_db_count "$s" federation_attestations "attestation_type='delegates_to' AND attesting_key_id = attested_key_id") delegates_to=$(harness_db_count "$s" federation_attestations "attestation_type='delegates_to'") keys=$(harness_db_count "$s" federation_keys)"
  done
  compose logs "$CHAT_SENDER" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' \
    | grep -iE "TEST-ANCHOR|ceremony" | tail -5
}

# ── 2. peered — a and b hold each other's key records ───────────────────────
# Admitted through the PRODUCTION `POST /v1/federation/peering` route carrying the
# peer's test-root-BLESSED self record, so the row is scrub-anchored and the peer
# roots Rooted rather than advisory.
stage_peered() {
  _chat_load
  if [ -z "${CHAT_A_NODE_KEY:-}" ] || [ -z "${CHAT_B_NODE_KEY:-}" ]; then echo 0; return; fi
  local ab ba
  ab="$(harness_db_count "$CHAT_SENDER" federation_keys "key_id = '$CHAT_B_NODE_KEY'")"
  ba="$(harness_db_count "${CHAT_RECIPIENT_SVC:-node-b}" federation_keys "key_id = '$CHAT_A_NODE_KEY'")"
  if [ "${ab:-0}" -gt 0 ] && [ "${ba:-0}" -gt 0 ]; then echo 2; else echo 0; fi
}
HINT_peered="the sender and the recipient did not mutually admit. Read the peering:* lines in the prepare output — a 403 is the CC 2.2 conformance gate or a missing owner-binding; a 400 is the fail-secure admission gate refusing the peer's record."
EXIT_peered=31
DIAG_peered() {
  grep -E "peering:|self-record:" "$CHAT_STATE/send.err" 2>/dev/null | tail -8
}

# ── 3. contact — the person-to-person consent grant, WITH `chat:` ───────────
# A contact IS a `consent:replication:v1` grant, and the `chat:` prefix is what
# makes it cover chat rows. This stage exists because the prefix is the half that
# can be silently absent: `emit_replication_consent`'s idempotency guard matches
# on (type, subject, dimension) and never compares prefix sets, so for years any
# peer that already held a grant — which after peering is every peer — took a
# later, WIDER request as a no-op. The widening path
# (`ensure_replication_consent_covers`, CIRISServer PR #464 P1) supersedes the
# narrow standing grant with the union instead. Asserting the prefix rather than
# the grant is what tells those two worlds apart, and the harness reaches the
# interesting one on purpose: the owner key is admitted through a door that
# authors its own narrow grant first (see chat_drive.py), so every run has a
# standing grant for `POST /v1/contacts` to widen.
_chat_contact_one() {
  # CIRISServer#472 — a routable contact grant names the peer's bound NODE;
  # the person-subject form remains as the unclaimed-contact fallback and the
  # legacy shape. Coverage on EITHER subject is a contact.
  local svc="$1" owner="$2" node="$3"
  harness_db_count "$svc" federation_attestations \
    "attestation_type='scores' \
     AND CAST(attestation_envelope AS TEXT) LIKE '%consent:replication%' \
     AND (CAST(attestation_envelope AS TEXT) LIKE '%${owner}%' \
          OR CAST(attestation_envelope AS TEXT) LIKE '%${node}%') \
     AND CAST(attestation_envelope AS TEXT) LIKE '%chat:%'"
}
stage_contact() {
  _chat_load
  if [ -z "${CHAT_A_OWNER:-}" ] || [ -z "${CHAT_B_OWNER:-}" ]; then echo 0; return; fi
  local a b
  a="$(_chat_contact_one "$CHAT_SENDER" "$CHAT_B_OWNER" "${CHAT_B_NODE_KEY:-__none__}")"
  b="$(_chat_contact_one "${CHAT_RECIPIENT_SVC:-node-b}" "$CHAT_A_OWNER" "${CHAT_A_NODE_KEY:-__none__}")"
  if [ "${a:-0}" -gt 0 ] && [ "${b:-0}" -gt 0 ]; then echo 2; else echo 0; fi
}
HINT_contact="the contact grant naming the peer's OWNER does not carry the \`chat:\` prefix on both nodes. Read the contact call's freshly_emitted: FALSE means \`ensure_replication_consent_covers\` decided the standing grant already covered everything asked for — check what that standing grant actually covers (the admission door authors one covering \`self:delegates_to:\` alone), because a grant that looks authoritative and covers nothing chat rides on is the CIRISServer#458 shape. TRUE with no \`chat:\` in the row means the widening ran and the union came out wrong."
EXIT_contact=32
DIAG_contact() {
  _chat_load
  echo "  freshly_emitted (true ⇒ the standing grant was WIDENED + superseded):"
  echo "    node-a=${CHAT_CONTACT_A_FRESH:-?} node-b=${CHAT_CONTACT_B_FRESH:-?}"
  echo "  owner key admitted via: ${CHAT_OWNER_ADMIT_VIA:-?}"
  grep -hE "contact:|owner-key:" "$CHAT_STATE/send.err" "$CHAT_STATE/join.err" 2>/dev/null | tail -8
}

# ── 4. room — the SAME community_id, derived independently on both nodes ────
# The convergent-derivation claim, proven across two sovereign directories rather
# than in one process. `pair_community_key_id` sorts the pair, so this can only
# diverge if the two nodes disagree about WHICH two keys are in the room — which
# is precisely what a single-process test cannot check.
stage_room() {
  _chat_load
  if [ -n "${CHAT_CID_A:-}" ] && [ "${CHAT_CID_A:-}" = "${CHAT_CID_B:-}" ]; then echo 1; else echo 0; fi
}
HINT_room="the two nodes did not converge on one community_id. A DIFFERENT id on each side means they disagree about the member pair — check that the sender's contact is the recipient's OWNER fedID and vice versa (not the node keys). An EMPTY id means POST /v1/chat was refused: chat.not_a_contact (the grant is not in the consent projection) or chat.unknown_fed_id."
EXIT_room=33
DIAG_room() {
  _chat_load
  echo "  node-a community_id: ${CHAT_CID_A:-<none>}"
  echo "  node-b community_id: ${CHAT_CID_B:-<none>}"
  grep -hE "room:" "$CHAT_STATE/send.err" "$CHAT_STATE/join.err" 2>/dev/null | tail -4
}

# ── 5. sent — the message row exists on node A ──────────────────────────────
stage_sent() {
  _chat_load
  if [ -n "${CHAT_ATT_ID:-}" ]; then echo 1; else echo 0; fi
}
HINT_sent="POST /v1/chat/{id}/messages did not return an attestation_id. chat.not_a_member means build_caller_admission did not resolve the owner into the community (the roster is read from the directory, never asserted); chat.emit_failed names the substrate refusal — most likely check_promotion_cohort_standing, which refuses a community placement naming any party but its producer."
EXIT_sent=34
DIAG_sent() {
  grep -E "send:" "$CHAT_STATE/send.err" 2>/dev/null | tail -4
}

# ── 8. arrived — A's BYTES in B's transcript. THE STAGE THIS EXISTS FOR ─────
# Keyed on the SENDER's attestation_id, so "B derived the room" cannot pass for
# "A's message arrived": that id is minted in node A's substrate and node B has
# no way to produce it. Body non-empty and status `live` are part of arrival —
# a row that landed stripped or already superseded is not a delivered message.
stage_arrived() {
  _chat_load
  if [ -z "${CHAT_ATT_ID:-}" ] || [ -z "${CHAT_CID_B:-}" ]; then echo 0; return; fi
  compose exec -T "${CHAT_RECIPIENT_SVC:-node-b}" python /opt/harness/chat_drive.py arrived \
    "$CHAT_B_BASE" "$CHAT_B_TOKEN" "$CHAT_CID_B" "$CHAT_ATT_ID" 2>/dev/null | tr -d '[:space:]'
}
HINT_arrived="the sender's message never reached the recipient. The diagnosis below says WHICH of the three it is — never served, refused at the recipient, or admitted-but-not-projected. The three readings, and what each one asks for:

 (1) IS THE ROW SIGNED BY ITS OWN ATTESTER? Compare \`attesting_key_id\` and
     \`scrub_key_id\` on the sender's copy (the DIAG prints both). \`send_message\`
     stages the row with \`attesting_key_id = <owner fed-ID>\` and defers the
     signature to \`attestation_promote\`, which signs with the ENGINE's own
     composed signer — the NODE's key. Nothing checks that locally (a
     trusted-local write is exempt), but persist's
     \`verify_federation_tier_ingest\` verifies the signature against the
     ATTESTER's registered pubkeys and consults \`scrub_key_id\` NOWHERE, with no
     signer-acts-for delegation path. A split therefore refuses the row at EVERY
     peer, in every topology: \`federation_federation_tier_unverified\`. The row
     is authored by the person and signed by the box, and only the wire can tell.

 (2) DID THE PLANE CARRY IT? If the recipient's log shows no delivered envelope
     for this content hash, check the sender's consent send-set — edge resolves
     recipients by EXACT key match against \`list_consent_peers(local)\`, so
     the recipient's NODE key must be in it (a grant naming their OWNER is not
     routable: a person's fed-ID has no transport binding) — and that the grant
     covers \`chat:\`.

 (3) DID THE READ SIDE HIDE IT? If the row IS in the recipient's DB but not in the
     transcript, \`collect_messages\` anchors on \`active_community_members\`, so
     the recipient must hold the community row AND the author must still be a member."
EXIT_arrived=35
# THE THREE-WAY SPLIT. "It did not arrive" is three different asks, addressed to
# three different owners, and a diagnosis that does not say which is a diagnosis
# nobody can act on:
#
#   NEVER SERVED    — the row was never advertised or fetched. The question is
#                     edge's advertise/serve policy and the sender's send-set.
#   REFUSED AT B    — it crossed and the recipient's put gate rejected it. The
#                     question is the row's own shape (this is where the
#                     attester/signer split lands) or persist's admission rules.
#   NOT PROJECTED   — it was admitted and the READ does not show it. The question
#                     is the route: `collect_messages` anchors on
#                     `active_community_members`, so an admitted row is invisible
#                     if the roster or the author's membership is not there.
#
# Plus the controlled comparison, because printing only the failure would leave
# "the peer refuses our rows" ambiguous between a broken plane and a broken row.
# These counts come from the SAME run over the SAME link.
DIAG_arrived() {
  _chat_load
  local recip="${CHAT_RECIPIENT_SVC:-node-b}"
  local at_b served refused
  at_b="$(harness_db_count "$recip" federation_attestations "attestation_id = '${CHAT_ATT_ID:-none}'")"
  refused="$(compose logs "$recip" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' \
    | grep -c "REFUSED.*${CHAT_ATT_ID:-none}" || true)"
  served="$(compose logs "$recip" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' \
    | grep -c "${CHAT_ATT_ID:-none}" || true)"
  echo "  ── which of the three? ──"
  if [ "${at_b:-0}" -gt 0 ]; then
    echo "  NOT PROJECTED: the row IS in ${recip}'s directory and the route does not"
    echo "    return it. Look at collect_messages: it anchors on"
    echo "    active_community_members, so the roster and the author's membership"
    echo "    are what to check, NOT the replication plane."
  elif [ "${refused:-0}" -gt 0 ]; then
    echo "  REFUSED AT ${recip}: the plane CARRIED it and the put gate rejected it."
    echo "    The replication side is exonerated; the row's own shape is the ask."
  elif [ "${served:-0}" -gt 0 ]; then
    echo "  CROSSED BUT UNRESOLVED: ${recip} mentions the row without a refusal and"
    echo "    without storing it — read the lines below verbatim before concluding."
  else
    echo "  NEVER SERVED: ${recip} has never seen this attestation_id at all."
    echo "    The sender never advertised or served it — check node ${CHAT_SENDER}'s"
    echo "    consent send-set (edge matches recipients by EXACT key against"
    echo "    list_consent_peers(local), and a grant naming a PERSON is not routable:"
    echo "    a person's fed-ID carries no transport binding) and the advertise"
    echo "    projection for this dimension."
  fi
  echo "  ── the row's own shape (attester | signer) ──"
  compose exec -T "$CHAT_SENDER" python -c '
import glob,sqlite3,sys
att=sys.argv[1]
for d in glob.glob("/var/lib/ciris/**/*.db*", recursive=True):
    if d.endswith(("-wal","-shm")): continue
    try:
        for r in sqlite3.connect(d).execute(
            "SELECT attesting_key_id, scrub_key_id, tier, cohort_scope FROM federation_attestations WHERE attestation_id=?", (att,)):
            print("    attesting_key_id=%s\n    scrub_key_id    =%s\n    tier=%s cohort_scope=%s" % r)
            print("    SPLIT — the row is signed by a key that is not its attester" if r[0] != r[1]
                  else "    signer IS the attester")
    except Exception: pass' "${CHAT_ATT_ID:-none}" 2>/dev/null
  echo "  ── counts ──"
  echo "  rows for this attestation_id on $recip:  ${at_b:-0}"
  echo "  chat:message rows (any) on $recip:       $(harness_db_count "$recip" federation_attestations "CAST(attestation_envelope AS TEXT) LIKE '%chat:message:v1%'")"
  echo "  rows for this id on the canonical:       $(harness_db_count canonical federation_attestations "attestation_id = '${CHAT_ATT_ID:-none}'")"
  # THE CONTROL: sender-authored federation rows whose attester is the NODE
  # (signer == attester) that DID land, over the same link in the same rounds.
  echo "  ${CHAT_SENDER}-authored rows that DID land on $recip: $(harness_db_count "$recip" federation_attestations "attesting_key_id = '${CHAT_A_NODE_KEY:-none}'")"
  echo "  ── $recip ingest refusals (verified against the ATTESTER's key) ──"
  compose logs "$recip" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' \
    | grep -oE 'federation-tier attestation "[^"]+" \(attesting_key_id="[^"]+"\)' | sort -u | tail -6
  echo "  ── ${CHAT_SENDER} withholds ──"
  compose logs "$CHAT_SENDER" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' \
    | grep -oE "attestation (plane )?withheld[^\"]{0,120}" | sort | uniq -c | tail -5
}

# ── 9. hamburger — the arrived row still carries its CEG identity ───────────
# Arrival that strips identity is delivery of a RUMOUR, not testimony: without
# `attestation_id` there is nothing for Supersede/Withdraw/Recant to target,
# without `attesting_key_id` nobody may revise it, and without `cohort_scope` the
# audience the tier promised is unverifiable. Checked on B's copy, not A's.
stage_hamburger() {
  _chat_load
  if [ -z "${CHAT_ATT_ID:-}" ] || [ -z "${CHAT_CID_B:-}" ]; then echo 0; return; fi
  compose exec -T "${CHAT_RECIPIENT_SVC:-node-b}" python /opt/harness/chat_drive.py hamburger \
    "$CHAT_B_BASE" "$CHAT_B_TOKEN" "$CHAT_CID_B" "$CHAT_ATT_ID" \
    "$CHAT_A_OWNER" "$CHAT_A_NODE_KEY" "${CHAT_AUTHOR_FIELD:-}" "${CHAT_ATTESTER_WORLD:-node}" \
    2>/dev/null | tr -d '[:space:]'
}
HINT_hamburger="the row reached the recipient but not with its identity intact — attesting_key_id is not the sender's owner, cohort_scope is not \`community\`, the subject set does not name the author, or the status folded away from \`live\`. Any of those makes the arrived object a different object from the one that was sent."
EXIT_hamburger=36
DIAG_hamburger() {
  _chat_load
  compose exec -T "${CHAT_RECIPIENT_SVC:-node-b}" python -c '
import json,sys,urllib.request
base,token,cid=sys.argv[1:4]
r=urllib.request.Request(f"{base}/v1/chat/{cid}/messages",headers={"Authorization":"Bearer "+token})
print(json.dumps(json.load(urllib.request.urlopen(r,timeout=20)),indent=1)[:1200])' \
    "$CHAT_B_BASE" "$CHAT_B_TOKEN" "$CHAT_CID_B" 2>/dev/null || true
}

# ── 6. dark — the THIRD PARTY is refused, and its refusal leaks nothing ─────
# The canonical carries the mesh and is a consent peer of BOTH nodes. It is not in
# the room's roster, and `CallerScope::admits` is persist's own §4.3 predicate
# resolved from the DIRECTORY — so owning a node is not membership in a cohort. A
# pass needs the typed refusal AND a body that does not contain the message text:
# a refusal that quotes what it will not serve has already served it.
#
# IT SITS BEFORE `arrived`, and that placement is load bearing. It depends on the
# room existing and on a message having been written into it — not on delivery —
# so under the monotonic verdict a green here must not be able to certify the
# delivery stages behind it. Ordering it after `arrived` would do exactly that.
# (An earlier draft instead gated it ON arrival, which is the same fix by a
# worse route: it made a real, independently-passing property invisible.)
#
# WHETHER THE CANONICAL EVER HELD THE BYTES is measured separately (`canonical
# holds the message row` in the evidence tail) rather than assumed. The refusal
# is the claim; what the refuser was holding is context.
stage_dark() {
  _chat_load
  if [ -z "${CHAT_CID_A:-}" ] || [ -z "${CHAT_CANON_TOKEN:-}" ]; then echo 0; return; fi
  compose exec -T canonical python /opt/harness/chat_drive.py dark \
    "$CHAT_CANON_BASE" "$CHAT_CANON_TOKEN" "$CHAT_CID_A" "$CHAT_MESSAGE" 2>/dev/null | tr -d '[:space:]'
}
HINT_dark="the third party was NOT cleanly refused. Either it answered 200 (a non-member read community-scoped content — the contextual-integrity line is down, and owning a node has become membership in a cohort), or the refusal carried the message text (a refusal that quotes what it will not serve has already served it), or the refusal was untyped (a client cannot localize it, CIRISServer#389)."
EXIT_dark=37
DIAG_dark() {
  _chat_load
  compose exec -T canonical python -c '
import json,sys,urllib.request,urllib.error
base,token,cid=sys.argv[1:4]
r=urllib.request.Request(f"{base}/v1/chat/{cid}/messages",headers={"Authorization":"Bearer "+token})
try:
    resp=urllib.request.urlopen(r,timeout=20); print("status",resp.status,resp.read().decode()[:600])
except urllib.error.HTTPError as e:
    print("status",e.code,e.read().decode()[:600])' \
    "$CHAT_CANON_BASE" "$CHAT_CANON_TOKEN" "$CHAT_CID_A" 2>/dev/null || true
}

# ── 7. one_sided — does the ROOM ITSELF replicate? (RED-EXPECTED) ───────────
#
# THE ONLY MOMENT THIS QUESTION CAN BE ASKED. `harness_scenario_prepare` runs the
# driver in two phases: the sender alone opens the room and speaks, then — after a
# bounded window — the recipients derive the same room and open it. In between,
# exactly one node has authored the roster. Once a recipient runs `POST /v1/chat`
# it holds a row it MINTED, and no later probe can tell that from a replicated
# one. So the window is the measurement, and it is recorded at prepare time.
#
# It asks about the COMMUNITY plane alone, deliberately kept clear of the
# attestation plane's own troubles: the observable is the recipient's answer for
# a room it has not opened —
#
#   404 chat.unknown_community — the roster did not reach this node   (RED)
#   403 chat.not_a_member      — it reached it; the caller is not on the roster
#   200                        — it reached it AND the caller may read
#
# The mechanism behind the expected red is one line of composition, verified
# rather than assumed: `compose::build_replication_peers` (src/compose.rs:3045)
# registers coordinators for Attestation, Key, IdentityOccurrence and
# TransportDestination — and none for Community. Edge implements the plane end to
# end (`list_communities` bridge.rs:1315, `apply_community` → `put_community`
# bridge.rs:1705/3423, serve policy `cohort`/`public` serve_policy.rs:51), and
# persist has `put_community`. Nothing is missing but the registration, so no
# anti-entropy round for that kind ever runs and a roster never crosses.
#
# THE CONSEQUENCE IS THE PRODUCT ONE, not a curiosity: a one-sided invitation is
# impossible. A can only ever chat with someone who independently decided to open
# the same room — which the convergent id makes possible, and which is why this
# ladder can still prove delivery at all.
stage_one_sided() {
  _chat_load
  # 1 only if the ROSTER crossed. `chat.unknown_community` is the recipient
  # saying it never received the room; anything else means it did.
  if [ -z "${CHAT_ONE_SIDED_STATUS:-}" ] || [ "${CHAT_ONE_SIDED_STATUS:-0}" = "0" ]; then
    echo 0; return
  fi
  if [ "${CHAT_ONE_SIDED_REASON:-}" = "chat.unknown_community" ]; then echo 0; else echo 1; fi
}
HINT_one_sided="the recipient could not resolve a room the sender had already created — the community roster did not replicate."
EXIT_one_sided=38
# RED-EXPECTED. The value names the mechanism because that is the entire point of
# the marking: this line, not a CI failure everyone routes around, is the ask.
XFAIL_one_sided="the roster now CROSSES THE WIRE (Community-plane frames delivered on the a<->b link — the coordinator (71adb94), the publish-own owner widening, and the self:delegates_to: prefix policy all took) and the residual is CONGESTION, not policy: the recipient's coordinator inbound channel drops the frames under load (CIRISEdge#373 backpressure, counted), and re-offers race the bounded window. No Community refusal was ever logged. Expected to converge with channel tuning (#373's court) or a longer window — the writer-resolution door that used to sit behind it is FIXED (persist v38.3.0 / #765; arrived and hamburger are REQUIRED stages now and pass). This stage flips live when a one-sided room resolves cross-node."
DIAG_one_sided() {
  _chat_load
  echo "  recipient's answer for the sender's room, before it opened one:"
  echo "    HTTP ${CHAT_ONE_SIDED_STATUS:-?}  reason_id=${CHAT_ONE_SIDED_REASON:-<none>}"
  echo "    federation_communities rows for that id on ${CHAT_RECIPIENT_SVC:-?} at that moment: ${CHAT_ONE_SIDED_ROWS:-?}"
  echo "  (a 404 chat.unknown_community with 0 rows IS the expected reading —"
  echo "   the roster plane has no coordinator, so nothing could have carried it)"
  # SELF-CHECK on the probe itself. The recipient has since opened its OWN copy,
  # so this count MUST be non-zero; a zero here would mean the DB probe cannot see
  # the table at all and the 0 measured during the window said nothing. A probe
  # that matches nothing and a probe that matches zero read the same — that is how
  # traceflow's `ship` rung went blind for its whole life.
  echo "  sanity — rows for that id on ${CHAT_RECIPIENT_SVC:-node-b} NOW (it has opened its own): $(harness_db_count "${CHAT_RECIPIENT_SVC:-node-b}" federation_communities "community_key_id = '${CHAT_CID_B:-none}'")"
  grep -E "one-sided:" "$CHAT_STATE/send.err" 2>/dev/null | tail -4
}

# ── evidence tail (always printed) ─────────────────────────────────────────
harness_scenario_evidence() {
  _chat_load
  echo "· owners:      A=${CHAT_A_OWNER:-<none>}  B=${CHAT_B_OWNER:-<none>}"
  echo "· node keys:   A=${CHAT_A_NODE_KEY:-<none>}  B=${CHAT_B_NODE_KEY:-<none>}  canonical=${CHAT_CANON_NODE_KEY:-<none>}"
  echo "· community:   A=${CHAT_CID_A:-<none>}"
  echo "               B=${CHAT_CID_B:-<none>}"
  echo "· message:     attestation_id=${CHAT_ATT_ID:-<none>}"
  # WHO SAID IT vs WHO SIGNED IT. One line, always printed, because it is the
  # single fact that decides whether a chat row can cross a node boundary at all
  # — persist's federation-tier ingest verifies the signature against the
  # ATTESTER's registered key and never looks at `scrub_key_id`.
  echo "· message row attester | signer (on the sender):"
  compose exec -T "$CHAT_SENDER" python -c '
import glob,sqlite3,sys
att=sys.argv[1]
for d in glob.glob("/var/lib/ciris/**/*.db*", recursive=True):
    if d.endswith(("-wal","-shm")): continue
    try:
        for r in sqlite3.connect(d).execute(
            "SELECT attesting_key_id, scrub_key_id FROM federation_attestations WHERE attestation_id=?", (att,)):
            print("     %s | %s%s" % (r[0], r[1], "   <- SPLIT" if r[0] != r[1] else ""))
    except Exception: pass' "${CHAT_ATT_ID:-none}" 2>/dev/null
  echo "· contact grant freshly_emitted: A=${CHAT_CONTACT_A_FRESH:-?} B=${CHAT_CONTACT_B_FRESH:-?}"
  echo "· peer-owner key admitted via:   ${CHAT_OWNER_ADMIT_VIA:-?}"
  # Every consent grant node A holds toward node B's OWNER, with its covered
  # prefix set. Two rows means the standing grant was widened and superseded;
  # one row covering only `self:delegates_to:` is the #458 shape.
  echo "· sender's consent grants naming the recipient's owner (id | prefixes):"
  compose exec -T "$CHAT_SENDER" python -c '
import glob,sqlite3,sys,json
owner=sys.argv[1]
for d in glob.glob("/var/lib/ciris/**/*.db*", recursive=True):
    if d.endswith(("-wal","-shm")): continue
    try:
        # Every literal is a BOUND PARAMETER, so this SQL carries no quote
        # character at all — the block lives inside a single-quoted shell string,
        # and one apostrophe in it silently truncates the command.
        for r in sqlite3.connect(d).execute(
            "SELECT attestation_id, CAST(attestation_envelope AS TEXT) FROM federation_attestations "
            "WHERE attestation_type = ? AND CAST(attestation_envelope AS TEXT) LIKE ? "
            "AND CAST(attestation_envelope AS TEXT) LIKE ?",
            ("scores", "%consent:replication%", "%" + owner + "%")):
            try: pfx = json.loads(r[1]).get("payload", {}).get("attestation_prefixes")
            except Exception: pfx = "<unparsed>"
            print("     %s | %s" % (r[0], pfx))
    except Exception as e: print("     <query failed: %s>" % e)' "${CHAT_B_OWNER:-none}"
  # Whether the RELAY actually holds the bytes it relayed. `dark` asserts the
  # canonical cannot READ the room; this line says whether it ever had a copy,
  # so the claim about the relay is measured rather than assumed.
  echo "· canonical holds the message row: $(harness_db_count canonical federation_attestations "attestation_id = '${CHAT_ATT_ID:-none}'")"
  echo "· recipient holds the message row: $(harness_db_count "${CHAT_RECIPIENT_SVC:-node-b}" federation_attestations "attestation_id = '${CHAT_ATT_ID:-none}'")"
  echo "· drive errors: ${CHAT_DRIVE_ERRORS:-<unread>}"
}
