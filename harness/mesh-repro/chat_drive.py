#!/usr/bin/env python3
"""chat_drive.py — the cross-node chat driver + the ladder's live probes.

Runs INSIDE a harness container (any of them; every service resolves the others
by name on the `mesh` bridge). The scenario shell owns the parts that must run on
a specific node's own console — minting the owner fed-ID and the one-time-PIN
claim — because both need that node's on-disk keystore. Everything after that is
plain HTTP against the three read-APIs, so it lives here where it can be written
once and read as a sequence.

    python chat_drive.py drive send   < state.json  > result_send.json
    python chat_drive.py drive join   < state.json  > result_join.json
    python chat_drive.py drive speak  < state.json  > result_speak.json
    python chat_drive.py arrived      <base> <token> <community_id> <attestation_id>
    python chat_drive.py hamburger    <base> <token> <community_id> <attestation_id> <attester>
    python chat_drive.py dark         <base> <token> <community_id> <needle>

The probe subcommands print ONE integer and nothing else — the stage-ladder
contract (lib/harness.sh rule 1). `drive` prints one JSON object.

── The two admission routes, and why both are here ─────────────────────────

`POST /v1/federation/peering` is the production owner act: it admits the peer's
SignedKeyRecord through the fail-secure gate AND authors this node's
`consent:replication:v1` grant carrying the OPERATOR's prefix set. Handing it the
peer's TEST-ROOT-BLESSED self record (`GET /v1/federation/test-blessed-self-record`)
means the admitted row is scrub-anchored, so the peer roots as `Rooted` rather
than advisory — the property the harness's own `test-admit-peer` exists to give,
obtained through the route a real operator uses.

`test-admit-peer` is still the only way to admit a key whose self-signed record
this driver cannot obtain over HTTP (there is no route that exports one), which
is the case for the OTHER NODE'S OWNER — a `user` identity that lives only in its
own node's directory. So the driver FIRST waits to see whether the key plane
replicates that row on its own, and only falls back to `test-admit-peer` if it
does not. Which path was taken is recorded (`owner_admit_via`), because it
changes what the `contact` stage is measuring: `test-admit-peer` authors a
reciprocal `consent:replication` grant of its own, covering `self:delegates_to:`
alone. A later `POST /v1/contacts` therefore arrives at a peer that ALREADY has a
standing grant — which is exactly the case `ensure_replication_consent_covers`
(CIRISServer PR #464 P1) exists for, and exactly the case that used to be a
silent no-op because the idempotency guard compares (type, subject, dimension)
and never the prefix set. So the fallback path is not a degraded run: it is the
one that puts the widening under test.

── The announce, and why it is the driver's FIRST act ──────────────────────

Setup-complete writes the owner-binding `delegates_to(owner → node)` at
`cohort_scope: self`. That is the privacy default (CC 1.13.3.4) and it is
correct — and it is also a row NO peer may ever hold: the CC 5.2 audience gate
withholds a `self` row from every node that is not one of the owner's own. A
peer that cannot walk `node → owner` cannot place that node in ANY community
row's audience, so a two-person room's MLS KeyPackage is withheld in both
directions and the handshake never completes. Measured 2026-09-03: 15 rows
"withheld — the recipient is not in the row's audience", 0 delivered.

`POST /v1/federation/announce` is the OWNER re-stating that binding at
federation scope (persist v31 put `cohort_scope` inside the signed bytes, so a
wider audience is a new signature by the claimant, not a relabel). The wizard
does it by default — announcing is an opt-OUT — and the scenario shell does it on
each node's console right after the claim (the route is loopback-only), before
the first anti-entropy round, because that is the step that makes
`owner_of(peer_node)` answerable on the far side. Edge's own
bench-mesh runner never needs the step: its `owner_binding_attestation` mints
the binding AT federation scope. Ours is born `self` and widened; the two
runners differ in where the widening happens, not in what replicates.
"""

import json
import sys
import time
import urllib.error
import urllib.request

TIMEOUT = 30
# The chat namespace prefix a grant must cover for a message to federate. Spelled
# once here; the scenario reads it back out of the result rather than restating it.
CHAT_PREFIX = "chat:"
# What a node peers with — the operator's declared replication scope for the
# plane between two NODES, which is the plane a chat message actually rides. It
# is stated here rather than left to the default because the contact grant names
# a PERSON, and a person's fed-ID carries no transport binding: edge resolves
# recipients by exact key match against `list_consent_peers(local)`, so the row
# leaves this node only if the peer NODE is in that set.
# self:delegates_to: carries the owner-binding rows — without it no node can
# resolve who speaks for whom beyond one hop (the #472 arc's measured starve).
PEER_PREFIXES = ["capacity:", "chat:", "self:delegates_to:", "trace:"]


def req(method, url, token=None, body=None):
    """One HTTP call → (status, parsed-or-raw-body). Never raises on an HTTP
    status; a refusal IS data here (the `dark` stage asserts one)."""
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=TIMEOUT) as resp:
            raw = resp.read().decode()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        status = e.code
    except Exception as e:  # noqa: BLE001 — transport failure is a reportable outcome
        return 0, {"transport_error": f"{type(e).__name__}: {e}"}
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, raw


def log(msg):
    print(f"[chat-drive] {msg}", file=sys.stderr, flush=True)


# ─── drive ──────────────────────────────────────────────────────────────────


def drive(state, phase):
    """`send` — peer everyone, then the SENDER alone opens the room and speaks.
    `join` — the recipients open the same room, by derivation.

    THE SPLIT IS THE MEASUREMENT. Between the two phases there is a window in
    which exactly one node has authored the community roster, and that is the
    only moment at which "does the roster replicate?" can be asked: once the
    recipient runs `POST /v1/chat` it holds a row it DERIVED, and no later probe
    can tell a replicated roster from a locally-minted one. A driver that opened
    both rooms up front — as this one did in its first version — cannot ask the
    question at all, and would report the convergent path's green while the
    one-sided path's gap stayed invisible.
    """
    nodes = state["nodes"]
    sender = state.get("sender", "node-a")
    recipients = state.get("recipients", ["node-b"])
    out = {"phase": phase, "steps": [], "nodes": {}, "errors": []}

    def step(name, status, detail):
        ok = 200 <= status < 300
        out["steps"].append({"step": name, "status": status, "ok": ok, "detail": detail})
        if not ok:
            out["errors"].append(f"{name}: {status} {detail}")
        log(f"{'OK ' if ok else 'ERR'} {name} [{status}] {detail}")
        return ok

    # ── 0. each node's own federation key_id + its blessed self record ───────
    # The NodeCode's key_id is the keystore ALIAS axis; the directory's key_id is
    # the #247 DERIVED one, and it is the derived one every consent grant,
    # contact and community member names. Read it off the record the directory
    # itself serves so the two axes cannot be confused. Re-read in BOTH phases:
    # one HTTP call per node, and it keeps `join` stateless.
    for name, n in nodes.items():
        status, rec = req("GET", f"{n['base']}/v1/federation/test-blessed-self-record")
        if not step(f"self-record:{name}", status, str(rec)[:120]):
            continue
        n["record"] = rec
        n["node_key_id"] = rec["record"]["key_id"]
        out["nodes"][name] = {
            "node_key_id": n["node_key_id"],
            "owner_key_id": n.get("owner_key_id"),
            "base": n["base"],
        }

    if phase == "join":
        return _phase_join(nodes, sender, recipients, out, step)
    if phase == "speak":
        return _phase_speak(nodes, sender, recipients, state, out, step)
    return _phase_send(nodes, sender, recipients, state, out, step)


def _announce(nodes, out, step):
    """Every claimed node has announced itself — the wizard's default, and the
    scenario shell's act, not this driver's: `/v1/federation/announce` is a
    setup route and setup routes are LOOPBACK-ONLY (this driver reaches nodes
    by name over the mesh bridge and was answered `403 setup routes are
    localhost-only`). The shell runs it on each node's own console right after
    the claim and hands the result in via state; this logs it in sequence so a
    red `bound` can say whether the announce never ran or ran and never
    replicated. Recorded per node: the HTTP status and the id of the
    federation-scoped binding it minted (`None` on an idempotent re-announce)."""
    out["announce"] = {}
    for name, n in nodes.items():
        ann = n.get("announce")
        if not isinstance(ann, dict):
            out["announce"][name] = {"status": 0, "detail": "not announced by the scenario shell"}
            step(f"announce:{name}", 0, "NOT ANNOUNCED — the shell recorded no announce for this node")
            continue
        out["announce"][name] = ann
        status = int(ann.get("status") or 0)
        promoted = ann.get("promoted_owner_binding_attestation_id")
        if 200 <= status < 300:
            complete = ann.get("federation_discoverable")
            detail = (
                f"bundle {ann.get('bundle_visible')}/{ann.get('bundle_expected')} federation-visible "
                f"({'COMPLETE' if complete else 'INCOMPLETE: missing ' + str(ann.get('bundle_missing'))}); "
                f"owner-binding widened: {promoted or '(already federation-scoped)'}"
            )
            # An announce that answered 200 with rows still invisible is not a
            # green: name it as the 299 the ladder localises.
            step(f"announce:{name}", 200 if complete else 299, detail)
        else:
            step(f"announce:{name}", status, str(ann.get("detail"))[:160])


def _phase_send(nodes, sender, recipients, state, out, step):
    # ── 0. announce: the owner-binding has left `self` scope ─────────────────
    # Done by the shell at claim time (loopback-only route); logged here so the
    # sequence reads in one place and a missing announce is named, not inferred.
    _announce(nodes, out, step)

    # ── 1. peer every ordered pair through the PRODUCTION peering route ──────
    # Admission + the directed grant in one owner-authorized act, with the
    # operator's prefix set. The record handed over is the peer's test-root
    # BLESSED one, so the admitted row is scrub-anchored (Rooted provenance).
    for a in nodes:
        for b in nodes:
            if a == b or "record" not in nodes[b] or not nodes[a].get("token"):
                continue
            status, body = req(
                "POST",
                f"{nodes[a]['base']}/v1/federation/peering",
                token=nodes[a]["token"],
                body={
                    "peer_key_id": nodes[b]["node_key_id"],
                    "peer_key_record": nodes[b]["record"],
                    "attestation_prefixes": PEER_PREFIXES,
                },
            )
            step(
                f"peering:{a}->{b}",
                status,
                f"prefixes={body.get('attestation_prefixes') if isinstance(body, dict) else body} "
                f"fresh={body.get('freshly_emitted') if isinstance(body, dict) else '?'}",
            )

    # ── 2. every party's OWNER key, in both directions ───────────────────────
    # A person's fedID is a `user` row in their own node's directory. Wait to see
    # whether the key plane carries it across on its own; fall back to the
    # harness admit door only if it does not, and RECORD which happened.
    pairs = _owner_key_pairs(sender, recipients, nodes)
    out["owner_admit_via"] = {}
    deadline = time.time() + float(state.get("owner_key_wait_secs", 90))
    pending = list(pairs)
    while pending and time.time() < deadline:
        still = []
        for host, guest in pending:
            owner = nodes[guest]["owner_key_id"]
            status, _ = req(
                "GET",
                f"{nodes[host]['base']}/v1/federation/peers/{owner}",
                token=nodes[host]["token"],
            )
            if status == 200:
                out["owner_admit_via"][f"{host}<-{guest}"] = "replication"
                step(f"owner-key:{host}<-{guest}", 200, "arrived by REPLICATION")
            else:
                still.append((host, guest))
        pending = still
        if pending:
            time.sleep(10)
    for host, guest in pending:
        owner = nodes[guest]["owner_key_id"]
        # The fallback. `test-admit-peer` scrub-signs with the SW test root and
        # admits — and, under CIRIS_TESTING_MODE, ALSO authors a reciprocal
        # `consent:replication` grant covering only `self:delegates_to:`. That
        # grant pre-exists when `POST /v1/contacts` later asks for `chat:`, which
        # is the case the `contact` stage measures. Recorded, not hidden.
        rec = json.loads(json.dumps(nodes[guest]["record"]))
        rec["record"]["key_id"] = owner
        rec["record"]["identity_type"] = "user"
        rec["record"]["pubkey_ed25519_base64"] = nodes[guest]["owner_ed25519"]
        rec["record"]["pubkey_ml_dsa_65_base64"] = nodes[guest]["owner_ml_dsa_65"]
        status, body = req(
            "POST", f"{nodes[host]['base']}/v1/federation/test-admit-peer", body=rec
        )
        out["owner_admit_via"][f"{host}<-{guest}"] = "test-admit-peer"
        step(f"owner-key:{host}<-{guest}", status, f"FALLBACK test-admit-peer: {str(body)[:120]}")

    # ── 3. the SENDER alone: contact + room (the CREATOR's half) ─────────────
    # No message yet. The room is an MLS pair group, and the creator cannot add
    # a member it holds no KeyPackage for: the joiner publishes one when IT
    # opens the room (phase JOIN), and it has to replicate back here first. The
    # message is phase SPEAK, after that handshake — sending here measured
    # `503 chat.room_key_failed` on every run and could measure nothing else.
    out["contacts"] = {}
    out["rooms"] = {}
    out["handshake"] = {}
    for guest in recipients:
        owner = nodes[guest].get("owner_key_id")
        if not owner:
            continue
        status, body = req(
            "POST",
            f"{nodes[sender]['base']}/v1/contacts",
            token=nodes[sender]["token"],
            body={"key_id": owner},
        )
        out["contacts"][sender] = body if isinstance(body, dict) else {"raw": body}
        step(
            f"contact:{sender}->{guest}-owner",
            status,
            f"fresh={body.get('freshly_emitted') if isinstance(body, dict) else '?'} "
            f"source={body.get('source') if isinstance(body, dict) else '?'} "
            f"reachable_nodes={body.get('reachable_nodes') if isinstance(body, dict) else '?'}",
        )
        status, body = req(
            "POST",
            f"{nodes[sender]['base']}/v1/chat",
            token=nodes[sender]["token"],
            body={"key_id": owner},
        )
        out["rooms"][sender] = body if isinstance(body, dict) else {"raw": body}
        step(
            f"room:{sender}",
            status,
            f"community_id={body.get('community_id') if isinstance(body, dict) else body} "
            f"fresh={body.get('freshly_created') if isinstance(body, dict) else '?'}",
        )
        break  # the room is a PAIR; the first recipient is the other member

    cid = (out["rooms"].get(sender) or {}).get("community_id")
    if cid:
        out["handshake"][sender] = _handshake(nodes[sender]["base"], nodes[sender]["token"], cid)
        step(f"handshake:{sender}", 200, str(out["handshake"][sender]))

    # ── 4. THE ONE-SIDED WINDOW ──────────────────────────────────────────────
    # Exactly one node has authored the roster. Ask every recipient for the room
    # BEFORE it derives its own copy. The three answers are three different
    # facts, so the reason_id is recorded verbatim rather than collapsed to a
    # boolean:
    #   404 chat.unknown_community — the roster did not reach this node
    #   403 chat.not_a_member      — the roster reached it; the caller is not on it
    #   200                        — it reached it AND the caller may read
    out["one_sided"] = {}
    if cid:
        wait = float(state.get("one_sided_wait_secs", 45))
        log(f"one-sided window: {wait:.0f}s with only {sender} holding the roster")
        time.sleep(wait)
        for guest in recipients:
            status, body = req(
                "GET",
                f"{nodes[guest]['base']}/v1/chat/{cid}/messages",
                token=nodes[guest]["token"],
            )
            reason = body.get("reason_id") if isinstance(body, dict) else None
            total = body.get("total") if isinstance(body, dict) else None
            out["one_sided"][guest] = {
                "status": status,
                "reason_id": reason,
                "total": total,
            }
            step(f"one-sided:{guest}", 200 if status == 200 else 299,
                 f"HTTP {status} reason_id={reason} total={total}")
    return out


def _phase_join(nodes, sender, recipients, out, step):
    """The recipients derive the SAME room from public inputs and open it."""
    owner_of_sender = nodes[sender].get("owner_key_id")
    out["contacts"] = {}
    out["rooms"] = {}
    for guest in recipients:
        if not owner_of_sender:
            continue
        status, body = req(
            "POST",
            f"{nodes[guest]['base']}/v1/contacts",
            token=nodes[guest]["token"],
            body={"key_id": owner_of_sender},
        )
        out["contacts"][guest] = body if isinstance(body, dict) else {"raw": body}
        step(f"contact:{guest}->{sender}-owner", status,
             f"fresh={body.get('freshly_emitted') if isinstance(body, dict) else '?'}")
        status, body = req(
            "POST",
            f"{nodes[guest]['base']}/v1/chat",
            token=nodes[guest]["token"],
            body={"key_id": owner_of_sender},
        )
        out["rooms"][guest] = body if isinstance(body, dict) else {"raw": body}
        step(f"room:{guest}", status,
             f"community_id={body.get('community_id') if isinstance(body, dict) else body} "
             f"fresh={body.get('freshly_created') if isinstance(body, dict) else '?'}")
        cid = body.get("community_id") if isinstance(body, dict) else None
        if cid:
            out.setdefault("handshake", {})[guest] = _handshake(
                nodes[guest]["base"], nodes[guest]["token"], cid)
            step(f"handshake:{guest}", 200, str(out["handshake"][guest]))
    return out


def _handshake(base, token, cid):
    """The room's own account of where the handshake stands, from the product
    surface: `ready` plus the localized system note's id (`chat.state.*`). A
    transcript that is not ready carries exactly one system entry saying why."""
    status, body = req("GET", f"{base}/v1/chat/{cid}/messages", token=token)
    if not isinstance(body, dict):
        return {"status": status, "ready": False, "state": None}
    notes = [m.get("message_id") for m in (body.get("messages") or []) if m.get("kind") == "system"]
    # `ready` is stated on every transcript since 0.5.197; before that only the
    # PENDING transcript carried it (`false`, beside its system note), so an
    # absent field on a 200 with no system note is a keyed room, not an
    # unknown one. Reading it that way keeps the probe honest on either shape.
    ready = body.get("ready")
    if ready is None and status == 200:
        ready = not notes
    return {
        "status": status,
        "ready": bool(ready),
        "state": notes[0] if notes else None,
        "reason_id": body.get("reason_id"),
    }


def _phase_speak(nodes, sender, recipients, state, out, step):
    """The SENDER waits for the room to be keyed, then speaks.

    Ready means: the joiner's KeyPackage crossed to this node, this node added
    the member and published the Welcome. Every poll logs the room's own
    `chat.state.*` note, so a stall reads as WHICH half is missing rather than
    as a timeout. The wait is bounded in anti-entropy rounds (~30 s each)."""
    out["rooms"] = {}
    out["sent"] = {}
    out["handshake"] = {}
    guest = recipients[0] if recipients else None
    owner = nodes[guest].get("owner_key_id") if guest else None
    if not owner:
        step(f"speak:{sender}", 0, "no recipient owner — nothing to send to")
        return out
    # Idempotent: the same derived room, `freshly_created: false`.
    status, body = req("POST", f"{nodes[sender]['base']}/v1/chat",
                       token=nodes[sender]["token"], body={"key_id": owner})
    out["rooms"][sender] = body if isinstance(body, dict) else {"raw": body}
    cid = body.get("community_id") if isinstance(body, dict) else None
    if not step(f"room:{sender}", status, f"community_id={cid}") or not cid:
        return out

    deadline = time.time() + float(state.get("ready_wait_secs", 150))
    hs = _handshake(nodes[sender]["base"], nodes[sender]["token"], cid)
    while not hs["ready"] and time.time() < deadline:
        log(f"handshake:{sender} not ready — {hs['state'] or hs['reason_id'] or hs['status']}")
        time.sleep(10)
        hs = _handshake(nodes[sender]["base"], nodes[sender]["token"], cid)
    out["handshake"][sender] = hs
    step(f"handshake:{sender}", 200 if hs["ready"] else 299,
         f"ready={hs['ready']} state={hs['state']}"
         + ("" if hs["ready"] else
            " — the joiner's KeyPackage never reached this node; see the `bound` stage"))

    status, body = req(
        "POST",
        f"{nodes[sender]['base']}/v1/chat/{cid}/messages",
        token=nodes[sender]["token"],
        body={"body": state["message"]},
    )
    out["sent"] = body if isinstance(body, dict) else {"raw": body}
    step("send:%s" % sender, status,
         f"attestation_id={body.get('attestation_id') if isinstance(body, dict) else body}")
    return out


def _owner_key_pairs(sender, recipients, nodes):
    """(host, guest) directions in which an OWNER key must be admitted: every
    party to a room must be resolvable in the other's directory. Derived from the
    node list rather than hardcoded, so a third node costs one list entry."""
    pairs = []
    for guest in recipients:
        pairs.append((sender, guest))
        pairs.append((guest, sender))
    return [
        (h, g)
        for h, g in pairs
        if h in nodes and g in nodes and nodes[g].get("owner_key_id")
    ]


# ─── probes ─────────────────────────────────────────────────────────────────


def _messages(base, token, cid):
    status, body = req("GET", f"{base}/v1/chat/{cid}/messages", token=token)
    if status != 200 or not isinstance(body, dict):
        return status, body, []
    return status, body, body.get("messages") or []


def probe_arrived(base, token, cid, att_id):
    """A's bytes on B's node: the row is there, its body is non-empty, and it is
    `live`. A row that arrived stripped or already superseded is not arrival."""
    _, _, msgs = _messages(base, token, cid)
    for m in msgs:
        if m.get("attestation_id") == att_id and m.get("body") and m.get("status") == "live":
            return 1
    return 0


def probe_hamburger(base, token, cid, att_id, owner, node_key, author_field, world):
    """THE TWO-FACT ASSERTION: who SIGNED and who AUTHORED are separate fields,
    and both must be right.

    `attesting_key_id` is WIRE-TRUE — the key that actually signed and that a
    peer verified. Rewriting it to the owner would make one field answer two
    questions with one answer wrong, on the provenance surface of all places.
    The person is carried beside it, in `author_field`, derived from the signed
    envelope's attribution. "Node attests, envelope names the owner, the
    owner-binding is live" is not a rumour: it is a signed on-behalf record whose
    authority chain a peer can walk.

    `author == owner` is asserted UNCONDITIONALLY, so this survives the day
    persist can express a signer-explicit community write and the attester
    converges to the owner. `world` names which key may legitimately attest
    TODAY, and is the one thing that moves between those worlds.
    """
    if not author_field:
        # No guessed name. An absent field and a wrong name look identical from
        # here, and calling the second one a product failure would be a lie.
        return 0
    _, _, msgs = _messages(base, token, cid)
    for m in msgs:
        if m.get("attestation_id") != att_id:
            continue
        author = m.get(author_field)
        ok = (
            author == owner
            and m.get("cohort_scope") == "community"
            and m.get("status") == "live"
            and m.get("community_id") == cid
            # PRODUCER-ONLY, stated as persist states it, so this survives both
            # worlds: `check_promotion_cohort_standing` refuses a community
            # placement whose attested_key_id or any subject_key_ids entry is
            # anyone but the producer (admission.rs:2236-2240). So the subject set
            # tracks whoever attests — the OWNER today, the NODE the moment the
            # node attests. Asserting `owner in subject_key_ids` would therefore
            # go red on a correct row, which is why it does not appear here.
            and (m.get("subject_key_ids") or []) == [m.get("attesting_key_id")]
        )
        if world == "owner":
            # The post-ask world: the producer's own signature survived, so the
            # two fields converge — and that convergence is the proof, not a
            # weakening of the check.
            ok = ok and m.get("attesting_key_id") == owner
        else:
            # persist v38: community rows are node-signed by construction. The
            # split is the DESIGN here, so it is asserted, not tolerated.
            ok = ok and m.get("attesting_key_id") == node_key and author != m.get("attesting_key_id")
        return 1 if ok else 0
    return 0


def probe_dark(base, token, cid, needle):
    """The relay is refused, and its refusal leaks nothing.

    A pass needs BOTH: a typed refusal (`chat.not_a_member` — it holds the room's
    bytes but is not in the roster — or `chat.unknown_community` — it never
    materialised the community row), and a response body that does not contain
    the message text."""
    status, body = req("GET", f"{base}/v1/chat/{cid}/messages", token=token)
    raw = json.dumps(body) if not isinstance(body, str) else body
    if needle and needle in raw:
        return 0
    reason = body.get("reason_id") if isinstance(body, dict) else None
    if status in (403, 404) and reason in ("chat.not_a_member", "chat.unknown_community"):
        return 1
    return 0


def main():
    if len(sys.argv) < 2:
        print("usage: chat_drive.py <drive|arrived|hamburger|dark> …", file=sys.stderr)
        return 2
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "drive":
        phase = args[0] if args else "send"
        state = json.load(sys.stdin)
        print(json.dumps(drive(state, phase), indent=2))
        return 0
    table = {
        "arrived": (4, probe_arrived),
        "hamburger": (8, probe_hamburger),
        "dark": (4, probe_dark),
    }
    if cmd not in table:
        print("0")
        return 2
    n, fn = table[cmd]
    if len(args) < n:
        print("0")
        return 2
    try:
        print(fn(*args[:n]))
    except Exception as e:  # noqa: BLE001 — a probe must be safe to call early
        log(f"probe {cmd} error: {type(e).__name__}: {e}")
        print("0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
