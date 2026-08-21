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
PEER_PREFIXES = ["capacity:", "chat:", "trace:"]


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
    return _phase_send(nodes, sender, recipients, state, out, step)


def _phase_send(nodes, sender, recipients, state, out, step):
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

    # ── 3. the SENDER alone: contact, room, message ──────────────────────────
    out["contacts"] = {}
    out["rooms"] = {}
    out["sent"] = {}
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
            f"fresh={body.get('freshly_emitted') if isinstance(body, dict) else '?'}",
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
        status, body = req(
            "POST",
            f"{nodes[sender]['base']}/v1/chat/{cid}/messages",
            token=nodes[sender]["token"],
            body={"body": state["message"]},
        )
        out["sent"] = body if isinstance(body, dict) else {"raw": body}
        step("send:%s" % sender, status,
             f"attestation_id={body.get('attestation_id') if isinstance(body, dict) else body}")
    else:
        step("send:%s" % sender, 0, "no community_id on the sender — nothing to send into")

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


def probe_hamburger(base, token, cid, att_id, attester):
    """The CEG identity fields on B's copy. Arrival that strips identity is
    delivery of a rumour, not testimony — so every field the hamburger renders
    (`attestation_id`, `attesting_key_id`, `cohort_scope`, `status`) is checked,
    not just presence of a row."""
    _, _, msgs = _messages(base, token, cid)
    for m in msgs:
        if m.get("attestation_id") != att_id:
            continue
        if (
            m.get("attesting_key_id") == attester
            and m.get("cohort_scope") == "community"
            and m.get("status") == "live"
            and m.get("community_id") == cid
            and attester in (m.get("subject_key_ids") or [])
        ):
            return 1
        return 0
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
        "hamburger": (5, probe_hamburger),
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
