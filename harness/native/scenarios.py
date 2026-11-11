"""Scenarios over the native mesh. Each is a function `(mesh, args) -> dict`
that records what it measured, step by step, and raises `MeshError` at the
first step that cannot proceed — naming it.

Add one by writing a function and registering it in `SCENARIOS`.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .mesh import HARNESS, Mesh, MeshError, Node, wait_for

Record = Dict[str, Any]


class Steps:
    """A timeline that EXPLAINS itself: each step says what it proves; a failed
    step says what it means and shows the log lines that decide it."""

    def __init__(self, plan: str) -> None:
        self.t0 = time.monotonic()
        self.log: List[Record] = []
        self.first_failure: Optional[Record] = None
        self.notes: List[str] = []
        print("── PLAN ──\n" + plan.strip() + "\n──", flush=True)

    def __call__(self, name: str, proves: str = "", **seen: Any) -> None:
        rec = {"t": round(time.monotonic() - self.t0, 1), "step": name, **seen}
        if proves:
            rec["proves"] = proves
        self.log.append(rec)
        print(json.dumps(rec), flush=True)

    def fail(self, name: str, means: str, nodes: List[Node], patterns: str,
             layer: str = "", rel: str = "", cc: str = "", **seen: Any) -> None:
        """A step that did not happen: what that MEANS, and the evidence —
        structured (CIRISClient#134 §5): `layer`, `rel`, `cc` ride as fields
        so a runner's report line can say `layer=relations/message cc=CC 5.4.6`."""
        evidence = {n.name: [line[-300:] for line in n.grep(patterns)[-8:]] for n in nodes}
        fields = {k: v for k, v in (("layer", layer), ("rel", rel), ("cc", cc)) if v}
        self.first_failure = self.first_failure or {"step": name, **fields}
        self(name, means=means, evidence=evidence, **fields, **seen)
        print(f"   ↳ {means}", flush=True)
        for n, lines in evidence.items():
            for line in lines:
                print(f"     {n}: {line}", flush=True)


# ── chat between two PEOPLE, production routes (CIRISServer#698) ────────────


def chat(mesh: Mesh, args: Any) -> Record:
    """Two people, each on their own node, add each other and key a pair room,
    using only the routes a released node exposes. The CIRISServer#698 path."""
    topology = ("bob also dials alice: DIRECT neighbours" if args.direct
                else "both dial only the canonical: 2 hops apart, NOT direct neighbours")
    step = Steps(f"""
CHAT — two people, each on their own node, one pair room, one message (CSD-091, CIRISServer#698).
  trust root: the harness's synthetic anchor; the canonical holds it; no node dials production.
  topology:   {topology}. Scoped content (chat bodies, files) reaches DIRECTLY-ATTACHED peers
              only (CC 5.4.6, CIRISEdge#499) — this choice decides whether bodies can cross.
  routes:     production only — self-key-record + /v1/federation/peering, /v1/contacts, /v1/chat.
  proves, in order: boot → claim → announce → peer → owner keys cross → contacts → the same
              room id on both → the room KEYS (the #698 claim) → a body crosses (CSD-091's row).""")
    a = mesh.add("alice")
    b = mesh.add("bob", dial=[a] if args.direct else None)
    step("booted", alice=a.url, bob=b.url, canonical=mesh.canonical.url, topology=topology)
    a.claim("alice-person")
    b.claim("bob-person")
    step("claimed", alice_owner=a.owner_key_id, bob_owner=b.owner_key_id)
    for n in (a, b):
        n.announce()
        n.self_record()
    step("announced")
    a.peer_with(b)
    b.peer_with(a)
    step("peered", via="self-key-record + /v1/federation/peering")
    # ROOTED is a PAIR fact (CIRISEdge#659): both owners must hold a valid root
    # in common, or every attestation between them is withheld — including the
    # key grants a body needs. Named here so a red below is never mistaken for
    # a chat defect when the precondition is what failed.
    try:
        wait_for("alice and bob to be Rooted with each other",
                 lambda: a.rooted_with(b) and b.rooted_with(a), args.rooted_wait, every=3)
        step("rooted", proves="edge's rooted_with found a valid root in common, both ways")
    except MeshError:
        step.fail("NOT_rooted",
                  "edge sees no valid trust root in common between the two OWNERS (rooted_with walks "
                  "the owner-bindings): attestations between them are withheld, so key grants and "
                  "bodies cannot cross. Either the owners never accepted the root (the claim path "
                  "did not write delegates_to(owner→root)) or the root's charter has not replicated",
                  [a, b], r"rooted_with|root_binding|trust root|accept.*root|not Rooted",
                  alice_sees_bob=a.rooted_with(b), bob_sees_alice=b.rooted_with(a))

    def owner_known(host: Node, guest: Node) -> bool:
        return host.knows(guest.owner_key_id)

    for host, guest in ((a, b), (b, a)):
        try:
            wait_for(f"{host.name} to hold {guest.name}'s owner key",
                     lambda: owner_known(host, guest), args.owner_wait)
            step(f"owner_key_crossed:{host.name}<-{guest.name}")
        except MeshError as e:
            step(f"owner_key_NOT_crossed:{host.name}<-{guest.name}", detail=str(e)[:200])
    via = getattr(args, "contact_via", "owner")
    for host, guest in ((a, b), (b, a)):
        key = guest.owner_key_id if via == "owner" else guest.contact_code()
        # REACHABLE, not just known. `reachable_nodes=0` means the guest's
        # owner→node binding has not reached this node at federation scope yet;
        # a contact and room made in that state keyed but every body then read
        # `not_granted` with no self-heal (measured 3× on 2026-09-29). The gate
        # re-adds until the node is reachable; `--reachable-wait 0` disables it
        # to reproduce the race on purpose.
        deadline = time.monotonic() + args.reachable_wait
        tries = 0
        while True:
            got = host.add_contact(key)
            tries += 1
            if (got.get("reachable_nodes") or 0) >= 1 or time.monotonic() >= deadline:
                break
            time.sleep(3)
        step(f"contact:{host.name}->{guest.name}", via=via, key=str(got.get("key_id"))[:60],
             reachable_nodes=got.get("reachable_nodes"), tries=tries,
             proves="the guest's owner→node binding is held here: the room can address their node")
    cid_a = a.open_pair(b.owner_key_id)
    cid_b = b.open_pair(a.owner_key_id)
    step("room_opened", same_room=cid_a == cid_b, room=cid_a)
    # THE JOINER ASKS ONCE AND NEVER READS THE ROOM AGAIN (the Docker chat
    # ladder's shape, and production's: a person asks for a chat and waits).
    # `PairRole` gives the smaller fed-ID the creator's role. Only the CREATOR
    # is polled for keying: it reads `ready` only once the joiner's KeyPackage
    # arrived, which on the joiner's node is the pair-room driver's work, not
    # a read's. Polling both sides used to drive the joiner on every poll and
    # hid exactly that (v38 adopt, 2026-10-01).
    creator, joiner = (a, b) if a.owner_key_id < b.owner_key_id else (b, a)
    cid_c, cid_j = (cid_a, cid_b) if creator is a else (cid_b, cid_a)

    def keyed() -> Any:
        rc = creator.room(cid_c)
        return rc["ready"] and rc

    try:
        wait_for("the pair room to key on the creator with the joiner never reading", keyed,
                 args.ready_wait, every=3)
        step("room_keyed", creator=creator.name, joiner_reads="once (POST /v1/chat)")
    except MeshError:
        rc = creator.room(cid_c)
        step.fail("room_NOT_keyed",
                  "the MLS handshake did not complete with the joiner never reading: the "
                  "joiner's acceptance, the creator's widening, the joiner's KeyPackage or the "
                  "creator's Welcome never happened (the pair-room driver's four acts)",
                  [a, b], _HANDSHAKE, creator_state=rc["state"])
        raise
    text = f"hello from {creator.name} {int(time.time())}"
    att = creator.say(cid_c, text)
    step("sent", attestation_id=att, by=creator.name)

    def arrived() -> bool:
        return any(m.get("attestation_id") == att and m.get("body") == text
                   for m in joiner.room(cid_j)["messages"])

    try:
        wait_for(f"{creator.name}'s message on {joiner.name}'s node", arrived, args.arrive_wait,
                 every=2)
    except MeshError:
        rj = joiner.room(cid_j)
        mine = [m for m in rj["messages"] if m.get("attestation_id") == att]
        step.fail("body_NOT_arrived",
                  "the row may be here but its BODY did not open on the joiner: the recipient "
                  "pulls the body from a holder over the room's DERIVED address, which only a "
                  "direct neighbour can reach (CC 5.4.6); a `no route to peer … has_path=false` "
                  "line below is that, `outcome=Stored` means it DID arrive and the transcript "
                  "is the problem",
                  [a, b], _BODY, row_on_joiner=mine[:1], transcript_len=len(rj["messages"]))
        raise
    step("arrived", proves="CSD-091: the peer's message, by attestation id, with its body, on the other person's node")
    values = {"PEER_URL": b.url, "PEER_KEY_ID": b.owner_key_id, "PEER_NODE_KEY_ID": b.node_key_id,
              "PEER_OWNER_KEY_ID": b.owner_key_id, "LOCAL_OWNER_KEY_ID": a.owner_key_id,
              "LOCAL_NODE_KEY_ID": a.node_key_id, "ROOM_ID": cid_a, "MESSAGE_TEXT": text,
              "MESSAGE_ATTESTATION_ID": att, "MESSAGE_ARRIVED": "true", "CONTACT_VIA": via}
    return {"verdict": "PASS", "steps": step.log, "values": values}


_HANDSHAKE = (r"ADVISORY|not conferred|SignedTransportDestination|KeyPackage|Welcome|"
              r"withheld|UnknownKey|room not keyed|handshake cannot complete")
_BODY = (r"no route to peer|has_path=|derived destination|holder retired|outcome=(Stored|FetchFailed)|"
         r"transcript is empty|not_fetched|NoHolders")


# ── a FILE in the pair room, read on the other person's node ─────────────────


def room_file(mesh: Mesh, args: Any) -> Record:
    """A file shared in a chat room reaches the other person: alice puts files in
    the pair room's drive (cohort `community`, the room's id), and bob reads the
    same bytes on his node. Builds on `chat`, so the room is keyed and a body has
    already crossed — a red here is the FILE's path, not the room's."""
    base = chat(mesh, args)
    room = base["values"]["ROOM_ID"]
    a, b = mesh.nodes["alice"], mesh.nodes["bob"]
    step = Steps(f"""
ROOM FILE — a file in the pair room reaches the other person (CSD-107 for rooms).
  builds on: the chat scenario (room {room} keyed, a message crossed).
  proves:    alice writes files into the room's drive; bob reads the SAME bytes, by digest,
             on his node: a small one, and one above 1 MiB (a chunk DAG) whose first chunk
             is above 256 KiB (the first-Resource case edge v43.3.0 fixed).""")
    step.log.extend(base["steps"])
    sizes = {"small": 64 * 1024, "large": 3 * 1024 * 1024 + 4321}
    written: Dict[str, Tuple[str, str]] = {}
    for label, size in sizes.items():
        data = os.urandom(size)
        digest = hashlib.sha256(data).hexdigest()
        got = a.must("POST", "/v1/files", {
            "cohort": "community", "room_id": room,
            "bytes_base64": base64.b64encode(data).decode(),
            "media_type": "application/octet-stream", "filename": f"{label}.bin",
        }, timeout=300)
        written[label] = (got["attestation_id"], digest)
        step(f"written:{label}", attestation_id=got["attestation_id"], bytes=size,
             addressed=got.get("addressed"), crossed=got.get("crossed"), tier=got.get("tier"))

    for label, (att, digest) in written.items():
        def same_bytes(att: str = att, digest: str = digest) -> Optional[bool]:
            st, body = b.api("GET", f"/v1/files/{att}?cohort=community&room_id={room}&raw=1",
                             raw=True, timeout=300)
            return True if st == 200 and hashlib.sha256(body).hexdigest() == digest else None
        try:
            wait_for(f"alice's {label} file on bob's node", same_bytes, args.arrive_wait, every=3)
            step(f"read:{label}", proves="the same bytes, by SHA-256, on the other person's node")
        except MeshError:
            st, body = b.api("GET", f"/v1/files/{att}?cohort=community&room_id={room}",
                             timeout=60)
            step.fail(f"file_NOT_read:{label}",
                      "the file's row or bytes did not reach the other member: the row crosses to "
                      "the room like a message; the bytes are a room-DEK blob the reader pulls "
                      "from a holder (holds_bytes claim, scoped fetch)",
                      [a, b], _BODY, status=st, meta=body if isinstance(body, dict) else str(body)[:300])
            raise
    # THE FILE AS A MESSAGE: alice sends the small file into the conversation;
    # bob's transcript carries it by id, and the node says it takes attachments.
    small_att = written["small"][0]
    sent = a.must("POST", f"/v1/chat/{room}/messages",
                  {"body": "see attached", "attachment_attestation_id": small_att}, timeout=120)
    step("attachment:sent", attestation_id=sent.get("attestation_id"), file=small_att)

    def attached() -> Optional[Dict[str, Any]]:
        st, body = b.api("GET", f"/v1/chat/{room}/messages", timeout=60)
        if st != 200 or not isinstance(body, dict) or body.get("accepts_attachments") is not True:
            return None
        for m in body.get("messages", []):
            if m.get("attestation_id") == sent.get("attestation_id") and m.get("attachment") == small_att:
                return m
        return None
    try:
        got = wait_for("alice's attachment in bob's transcript", attached, args.arrive_wait, every=3)
        step("attachment:read", caption=got.get("body"),
             proves="a message carrying a room file reaches the other member, naming the file")
    except MeshError:
        st, body = b.api("GET", f"/v1/chat/{room}/messages", timeout=60)
        step.fail("attachment_NOT_read",
                  "the message row crosses like any message; `attachment` is edge's "
                  "ChatMessage.attachment (attachment_attestation_id on the row)",
                  [a, b], _BODY, status=st,
                  accepts_attachments=body.get("accepts_attachments") if isinstance(body, dict) else None)
        raise
    return {"verdict": "PASS", "steps": step.log, "values": {**base["values"], "ROOM_FILES": {
        k: v[0] for k, v in written.items()}}}


_TAKEDOWN = r"takedown|purge|reconsideration|room takedowns|withheld|Purged"


def room_takedown(mesh: Mesh, args: Any) -> Record:
    """A room's takedown reaches the OTHER member's node, and so does its appeal
    (CC 4.5.3, CC 4.5.5; Eric 2026-11-11, 0.5.246). Builds on `chat`, so the
    pair room is keyed. Bob writes a file and a message into the room; alice
    (a founder, so she holds `takedown` and `review`) takes both down on HER
    node. Bob's OWN node, which wrote and holds the bytes, must stop serving
    them: edge has no purge plane, so the notice row crosses like any signed
    row and bob's server applies it (`room_takedown::sweep`). Then bob appeals
    from his node, alice reverses from hers, and the file reads again on bob's."""
    base = chat(mesh, args)
    room = base["values"]["ROOM_ID"]
    a, b = mesh.nodes["alice"], mesh.nodes["bob"]
    step = Steps(f"""
ROOM TAKEDOWN — a moderator's takedown and its appeal cross to the other member (CC 4.5.3).
  builds on: the chat scenario (room {room} keyed, a message crossed).
  proves:    bob's file and message, taken down on alice's node, are withheld on BOB's node
             (the author, the holder) with no reveal; bob's appeal reaches alice; alice's
             reversal reaches bob and the file serves again there.""")
    step.log.extend(base["steps"])
    data = os.urandom(64 * 1024)
    digest = hashlib.sha256(data).hexdigest()
    got = b.must("POST", "/v1/files", {
        "cohort": "community", "room_id": room,
        "bytes_base64": base64.b64encode(data).decode(),
        "media_type": "application/octet-stream", "filename": "contested.bin",
    }, timeout=300)
    att = got["attestation_id"]
    step("written", attestation_id=att, by="bob")
    q = f"cohort=community&room_id={room}"

    def reads(n: Node) -> Optional[bool]:
        st, body = n.api("GET", f"/v1/files/{att}?{q}&raw=1", raw=True, timeout=120)
        return True if st == 200 and hashlib.sha256(body).hexdigest() == digest else None

    wait_for("bob's file on alice's node", lambda: reads(a), args.arrive_wait, every=3)
    step("read:alice", proves="the file crossed before the takedown")
    sent = b.must("POST", f"/v1/chat/{room}/messages", {"body": "contested words"}, timeout=120)
    msg = sent["attestation_id"]

    def message_on(n: Node) -> Optional[Dict[str, Any]]:
        st, body = n.api("GET", f"/v1/chat/{room}/messages", timeout=60)
        if st != 200 or not isinstance(body, dict):
            return None
        return next((m for m in body.get("messages", []) if m.get("attestation_id") == msg), None)

    wait_for("bob's message on alice's node",
             lambda: (m := message_on(a)) and m.get("body") == "contested words" and m or None,
             args.arrive_wait, every=3)
    step("message:read:alice")

    # ALICE TAKES BOTH DOWN, on her node.
    for item in (att, msg):
        got = a.must("POST", f"/v1/chat/{room}/items/{item}/takedown",
                     {"reason": "breaks the room's standards"}, timeout=120)
        step(f"takedown:{item[:12]}", withheld=(got.get("takedown") or {}).get("withheld"),
             notice=got.get("notice_attestation_id"))

    def entry_on(n: Node) -> Optional[Dict[str, Any]]:
        st, body = n.api("GET", f"/v1/drive?{q}", timeout=60)
        if st != 200 or not isinstance(body, dict):
            return None
        return next((e for e in body.get("entries", []) if e.get("attestation_id") == att), None)

    def withheld_on_bob() -> Optional[Dict[str, Any]]:
        e = entry_on(b)
        if not e or not (e.get("takedown") or {}).get("withheld"):
            return None
        st, _ = b.api("GET", f"/v1/files/{att}?{q}&raw=1", raw=True, timeout=60)
        return e if st != 200 else None

    try:
        e = wait_for("the takedown applied on BOB's node (his own bytes withheld)",
                     withheld_on_bob, args.arrive_wait, every=5)
        step("withheld:bob", bytes=e.get("bytes"), by=(e.get("takedown") or {}).get("taken_down_by"),
             proves="the notice crossed to the author's node and his server applied it: "
                    "his own copy of the bytes no longer serves")
    except MeshError:
        step.fail("takedown_NOT_on_bob",
                  "the notice row did not reach bob's node, or his sweep did not apply it "
                  "(content row or alice's duty not held there yet = takedown_content_unbound / "
                  "takedown_unauthorised, retried each 30 s tick)",
                  [a, b], _TAKEDOWN, entry=entry_on(b))
        raise
    try:
        m = wait_for("the message's body taken down on bob's node",
                     lambda: (m := message_on(b)) and m.get("unopened_reason") == "taken_down"
                     and m or None, args.arrive_wait, every=5)
        step("message:withheld:bob", has_body="body" in m)
    except MeshError:
        step.fail("message_takedown_NOT_on_bob", "as above, for the message body",
                  [a, b], _TAKEDOWN, message=message_on(b))
        raise
    st, _ = b.api("POST", f"/v1/chat/{room}/items/{att}/reveal", {}, timeout=60)
    step("reveal:refused", status=st, proves="nothing reveals a takedown")

    # BOB APPEALS from his node; ALICE sees it and reverses from hers.
    got = b.must("POST", f"/v1/chat/{room}/items/{att}/reconsider",
                 {"grounds": "new_evidence"}, timeout=120)
    step("appeal:filed:bob", appeal=(got.get("takedown") or {}).get("appeal"))
    try:
        wait_for("bob's appeal on alice's node",
                 lambda: (e := entry_on(a)) and (e.get("takedown") or {}).get("appeal") == "filed"
                 and e or None, args.arrive_wait, every=5)
        step("appeal:seen:alice", proves="the filing crossed to the reviewer's node")
    except MeshError:
        step.fail("appeal_NOT_on_alice", "the community-scope filing did not reach alice's node",
                  [a, b], _TAKEDOWN, entry=entry_on(a))
        raise
    got = a.must("POST", f"/v1/chat/{room}/items/{att}/rule", {"outcome": "reversed"}, timeout=120)
    step("appeal:reversed:alice", withheld=(got.get("takedown") or {}).get("withheld"))
    try:
        wait_for("the file serves again on bob's node", lambda: reads(b), args.arrive_wait, every=5)
        step("restored:bob", proves="the reversal crossed and lifted the withholding inside the window")
    except MeshError:
        step.fail("reversal_NOT_on_bob", "the ruling did not reach bob's node, or persist did not "
                  "lift the tombstone there", [a, b], _TAKEDOWN, entry=entry_on(b))
        raise
    return {"verdict": "PASS", "steps": step.log,
            "values": {**base["values"], "TAKEDOWN_FILE": att, "TAKEDOWN_MESSAGE": msg}}


# ── two people peered directly, NO canonical (CIRISServer#808) ──────────────


def remote_admin(mesh: Mesh, args: Any) -> Record:
    """A person administers a node they own from another of their devices, through
    their own node, over the mesh (steward 2026-11-05). The owner is checked against
    the self-key roster, so a key the binding never named still counts. The same
    check against a removed key and an agent is `self_roster_key`'s, on one engine."""
    step = Steps("""
REMOTE ADMIN — a roster device reads and acts on a node its person owns, over the relay.
  nodes:  the canonical; A (alice: claimed, announced, the target); B (joined to alice's roster
          by the real add-device flow); S (a stranger with their own owner).
  proves: (1) B holds a roster key, not the key A's binding names;
          (2) B reads A's metrics and logs through the relay, with no session on A;
          (3) the answer is A's, not B's;
          (4) S, owner of its own node, is refused by A;
          (5) a route off the allow-list is refused on the gateway and signs nothing.""")
    ok = True
    cnl, _anchor, _done = mint_accord_root(mesh, args, step)
    a = mesh.add("alice")
    a.claim("alice-person")
    a.announce()
    a.self_record()
    a.peer_with(cnl)
    cnl.peer_with(a)
    b = mesh.add("newdev")
    s = mesh.add("stranger")
    s.claim("stranger-person")
    s.announce()
    s.self_record()
    s.peer_with(cnl)
    cnl.peer_with(s)
    b_pin = (b.home / "claim_pin").read_text().strip()
    b.self_record()
    step("booted", alice_owner=a.owner_key_id, a_node=a.node_key_id, b_node=b.node_key_id,
         stranger_owner=s.owner_key_id)

    a.must("POST", "/v1/self/device-requests/open", {"seconds": 600})
    code_link = a.contact_code()
    last: Any = None

    def ask() -> Optional[Tuple[int, Any]]:
        nonlocal last
        last = b.api("POST", "/v1/setup/add-device", {"contact": code_link, "label": "second device"})
        return last if last[0] == 202 else None
    # This proves administration, not first-contact speed, which contact_edges times.
    wait_for("B to reach A with its join request", ask, max(args.owner_wait, 300), every=5)
    rows = a.must("GET", "/v1/self/device-requests").get("requests", [])
    row = next(r for r in rows if r.get("node_key_id") == b.node_key_id)
    occ = a.must("POST", f"/v1/self/device-requests/{row['request_id']}/approve").get("occurrence_key_id")

    def held() -> Optional[Dict[str, Any]]:
        st = b.must("GET", "/v1/setup/add-device")
        return st if st.get("state") == "approved" else None
    wait_for("B to hold the owner's approval", held, args.arrive_wait, every=2)
    b.must("POST", "/v1/setup/add-device/complete",
           {"owner_username": "second-device", "owner_password": "a-long-local-password"})
    # In the client's order: it reads the PIN file only after the claim has landed.
    # Reading it first passed here for months while no real device could sign in.
    pin_file = b.home / "claim_pin"
    after_pin = pin_file.read_text().strip() if pin_file.exists() else ""
    if after_pin != b_pin:
        ok = False
        step.fail("pin_after_claim", "the PIN must still be readable to collect the session", [b],
                  r"claim PIN", found=bool(after_pin))
    b.token = b.must("POST", "/v1/setup/claimed-session", {"claim_pin": after_pin or b_pin})["access_token"]
    if pin_file.exists():
        ok = False
        step.fail("pin_kept", "the PIN file must go once the session is collected", [b], r"claim PIN")
    # An agent restart ends that session, so the device must be able to sign in.
    code, login = b.api("POST", "/v1/auth/login",
                        {"username": "second-device", "password": "a-long-local-password"})
    if code != 200:
        ok = False
        step.fail("device_login", "a device added by approval must be able to sign in", [b],
                  r"login", status=code, body=str(login)[:200])
    step("b_can_sign_in", status=code)
    if not occ or occ == a.owner_key_id:
        ok = False
        step.fail("roster_key", "B must hold its own roster key, not the key the binding names", [a, b],
                  r"occurrence", occurrence=occ)
    step("b_on_the_roster", occurrence=occ, binding_names=a.owner_key_id)

    def relay(n: Node, method: str, path: str) -> Tuple[int, Any]:
        return n.api("POST", "/v1/mesh/relay",
                     {"target_key_id": a.node_key_id, "method": method, "path": path})

    last_read: Any = None

    def read_metrics() -> Optional[Tuple[int, Any]]:
        nonlocal last_read
        last_read = relay(b, "GET", "/v1/federation/metrics")
        return last_read if last_read[0] == 200 else None
    try:
        code, metrics = wait_for("B to read A's metrics through the relay", read_metrics,
                                 args.arrive_wait, every=5)
    except MeshError:
        code, metrics = last_read
    if code != 200:
        ok = False
        step.fail("relay_metrics", "a roster device must read its person's node through the relay", [a, b],
                  r"mesh control|relay|signer does not", status=code, body=str(metrics)[:300])
    step("metrics_over_the_relay", status=code)

    code, logs = relay(b, "GET", "/v1/telemetry/logs?limit=5")
    if code != 200:
        ok = False
        step.fail("relay_logs", "logs must cross the relay for a roster device", [a, b],
                  r"mesh control|relay", status=code, body=str(logs)[:300])
    step("logs_over_the_relay", status=code)

    code, seen = relay(b, "GET", "/v1/federation/self-key-record")
    answered_by_a = a.node_key_id in str(seen) or a.owner_key_id in str(seen)
    if code != 200 or not answered_by_a:
        ok = False
        step.fail("answer_is_the_targets", "the relayed answer must come from the target", [a, b],
                  r"mesh control|relay", status=code, body=str(seen)[:300])
    step("the_answer_is_As", status=code)

    code, refused = relay(s, "GET", "/v1/federation/metrics")
    if code == 200:
        ok = False
        step.fail("stranger", "a stranger must not read a node it does not own", [a, s],
                  r"mesh control|signer does not", status=code, body=str(refused)[:300])
    step("stranger_refused", status=code, body=str(refused)[:160])

    code, offlist = relay(b, "POST", "/v1/system/data/wipe-signing-key")
    if code != 403:
        ok = False
        step.fail("allow_list", "a route off the allow-list must be refused on the gateway", [b],
                  r"relayable", status=code, body=str(offlist)[:300])
    step("off_the_list_refused", status=code)
    return {"verdict": "PASS" if ok else "FAIL", "steps": step.log, "first_failure": step.first_failure}


def _first_seen(node: Node, pattern: str, after: float) -> Optional[float]:
    """Seconds after `after` (epoch) of the first log line matching `pattern`."""
    for line in node.grep(pattern):
        m = re.search(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+)Z", line)
        if not m:
            continue
        at = datetime.strptime(m.group(1)[:26], "%Y-%m-%dT%H:%M:%S.%f")
        secs = at.replace(tzinfo=timezone.utc).timestamp() - after
        if secs >= 0:
            return round(secs, 1)
    return None


def _relay_pair(mesh: Mesh, args: Any, i: int) -> Dict[str, Any]:
    """One pair that meets only through the code, as a client does: no peering."""
    a = mesh.add(f"p{i}a")
    b = mesh.add(f"p{i}b")
    a.claim(f"p{i}a-person")
    b.claim(f"p{i}b-person")
    for n in (a, b):
        n.announce()
        n.self_record()
        n.peer_with(mesh.canonical)  # An agent's mesh-participation consent.
        wait_for(f"{n.name} to publish its transit route", n.transit_route, 60)
    code = lambda n: wait_for(  # noqa: E731
        f"{n.name}'s code to carry a node",
        lambda: "CIRIS-V3" in (c := n.contact_code()) and c, 60, every=2)
    code_b, code_a = code(b), code(a)
    rec: Dict[str, Any] = {"pair": i, "alice": a.name, "bob": b.name}
    # 202 is the ordinary answer for a stranger: the node keeps resolving them.
    def add(host: Node, code: str) -> None:
        got = host.api("POST", "/v1/contacts", {"key_id": code})
        if got[0] not in (200, 201, 202):
            raise MeshError(f"{host.name}: POST /v1/contacts answered {got[0]}: {got[1]}")

    t0 = time.time()
    add(a, code_b)

    def seen() -> bool:
        return a.owner_key_id in str(b.must("GET", "/v1/contacts/requests"))

    def stage(name: str, fn: Callable[[], Any], wait: float) -> bool:
        try:
            wait_for(f"p{i} {name}", fn, wait, every=1)
            rec[name] = round(time.time() - t0, 1)
            return True
        except MeshError:
            rec[name] = None
            return False

    if stage("request_seen", seen, args.ready_wait):
        add(b, code_a)
        rec["mutual_added"] = round(time.time() - t0, 1)
        cid_a = a.open_pair(b.owner_key_id)
        cid_b = b.open_pair(a.owner_key_id)
        creator, cid = (a, cid_a) if a.owner_key_id < b.owner_key_id else (b, cid_b)
        stage("keyed", lambda: creator.room(cid)["ready"], args.ready_wait)
    rec["re_aimed"] = _first_seen(a, r"re-aimed", t0)
    if rec.get("keyed") is not None and rec["re_aimed"] is not None:
        rec["keyed_after_re_aim"] = round(rec["keyed"] - rec["re_aimed"], 1)
    if rec.get("request_seen") is not None and rec["re_aimed"] is not None:
        rec["seen_after_re_aim"] = round(rec["request_seen"] - rec["re_aimed"], 1)
    rec["link_requests"] = len(a.grep(r"[Ll]ink request|LINKREQUEST|initiate_link"))
    return rec


def relay_rig(mesh: Mesh, args: Any) -> Record:
    """The stalled-link rig: pairs that meet only through one relay, each stage timed.

    RIG_PAIRS pairs (default 10). RIG_SHAPE: a shape file to seed the relay with,
    using RIG_SEEDER (`seed_synthetic_seat`). RIG_KEEP_PAIRS=1 leaves each pair
    running, so later pairs have earlier ones behind the relay. RIG_RELAY_PRESSURE
    (warning, critical) holds the relay at that level. Results go to
    <work>/rig.jsonl and every node's log to <work>/<node>/node.log."""
    pairs = int(os.environ.get("RIG_PAIRS", "10"))
    keep = os.environ.get("RIG_KEEP_PAIRS") == "1"
    shape = os.environ.get("RIG_SHAPE")
    step = Steps(f"""
RELAY RIG — {pairs} pairs through one relay, contact code only, no peering.
  shape: {shape or 'fresh relay'}; earlier pairs {'stay up' if keep else 'stop'}.""")
    relay = mesh.start_canonical()
    pressure = os.environ.get("RIG_RELAY_PRESSURE")
    if shape or pressure:
        relay.stop()
        if shape:
            subprocess.run([os.environ["RIG_SEEDER"], str(relay.home / "data" / "ciris_engine.db"),
                            shape], check=True, capture_output=True, timeout=300)
        if pressure:
            relay.env["CIRIS_TEST_LOAD_PRESSURE"] = pressure
        relay.start()
    step("relay_up", url=relay.url, seeded=bool(shape), pressure=pressure)
    out = mesh.work / "rig.jsonl"
    rows = []
    for i in range(pairs):
        rec = _relay_pair(mesh, args, i)
        rows.append(rec)
        with out.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        step("pair", **{k: v for k, v in rec.items() if k not in ("alice", "bob")})
        if not keep:
            mesh.nodes[rec["alice"]].stop()
            mesh.nodes[rec["bob"]].stop()
    reads = relay.api("GET", "/v1/node/diagnostics/reads")
    (mesh.work / "relay-reads.json").write_text(json.dumps(reads[1]), encoding="utf-8")
    missed = [r["pair"] for r in rows if r.get("keyed") is None]
    return {"verdict": "FAIL" if missed else "PASS", "steps": step.log, "rows": rows,
            "unkeyed_pairs": missed}


def _person_contact(mesh: Mesh, args: Any, adder: Node, accepter: Node) -> Dict[str, Any]:
    """`adder` adds `accepter` by code, as a client does; the stages are timed."""
    codes = {}
    for n in (adder, accepter):
        codes[n.name] = wait_for(
            f"{n.name}'s code to carry a node",
            lambda m=n: "CIRIS-V3" in (c := m.contact_code()) and c, 90, every=2)

    def add(host: Node, code: str) -> None:
        got = host.api("POST", "/v1/contacts", {"key_id": code})
        if got[0] not in (200, 201, 202):
            raise MeshError(f"{host.name}: POST /v1/contacts answered {got[0]}: {got[1]}")

    def seen() -> bool:
        return adder.owner_key_id in str(accepter.must("GET", "/v1/contacts/requests"))

    rec: Dict[str, Any] = {"adder": adder.name, "accepter": accepter.name}
    t0 = time.time()

    def stage(name: str, fn: Callable[[], Any]) -> bool:
        try:
            wait_for(f"{adder.name}→{accepter.name} {name}", fn, args.ready_wait, every=1)
            rec[name] = round(time.time() - t0, 1)
            return True
        except MeshError:
            rec[name] = None
            return False

    add(adder, codes[accepter.name])
    if stage("request_seen", seen):
        add(accepter, codes[adder.name])
        rec["accepted"] = round(time.time() - t0, 1)
        cid_a = adder.open_pair(accepter.owner_key_id)
        cid_b = accepter.open_pair(adder.owner_key_id)
        first = adder.owner_key_id < accepter.owner_key_id
        creator, cid = (adder, cid_a) if first else (accepter, cid_b)
        stage("keyed", lambda: creator.room(cid)["ready"])
    rec["re_aimed"] = _first_seen(adder, r"re-aimed", t0)
    return rec


def _reads(node: Node) -> Dict[str, List[int]]:
    """Reads per persist door on `node`, since it booted: {door: [calls, rows, bytes]}."""
    snap = node.api("GET", "/v1/node/diagnostics/reads")[1]
    out: Dict[str, List[int]] = {}
    for d in snap.get("reads", []) if isinstance(snap, dict) else []:
        out[str(d.get("door"))] = [int(d.get(k, 0)) for k in ("reads", "rows", "bytes")]
    return out


def _late_joiner(founder: Node, joiner: Node, history: int, wait: float) -> Dict[str, Any]:
    """A room with history on the seeded node, then a contact who joins late: how long
    until the joiner holds the room and reads the backlog. Times from the accept."""
    got = founder.must("POST", "/v1/communities", {"name": "history"})
    cid = got.get("community_id") or got.get("id")
    for i in range(history):
        founder.say(cid, f"history {i}")
    code, body = founder.api("POST", f"/v1/communities/{cid}/invites",
                             {"key_id": joiner.owner_key_id})
    if code not in (200, 201, 202):
        raise MeshError(f"invite answered {code}: {body}")
    rec: Dict[str, Any] = {"room": cid, "history": history}
    t0 = time.time()

    def invite() -> Optional[str]:
        rows = joiner.must("GET", "/v1/self/invites").get("invites", [])
        return next((r["proposal_id"] for r in rows if r.get("group_id") == cid), None)

    try:
        pid = wait_for("the joiner to list the invitation", invite, wait, every=2)
    except MeshError:
        rec["invite_seen"] = None
        return rec
    rec["invite_seen"] = round(time.time() - t0, 1)
    joiner.must("POST", f"/v1/self/invites/{pid}/accept", {})
    t1 = time.time()

    # MLS: a joiner holds the backlog's rows but cannot open bodies sealed before it
    # joined. What it must get promptly: the rows, the room keyed, then a message.
    def transcript(n: Node) -> Dict[str, Any]:
        code, body = n.api("GET", f"/v1/chat/{cid}/messages")
        return body if code == 200 and isinstance(body, dict) else {}

    def rows_held() -> bool:
        return len(transcript(joiner).get("messages", [])) >= history

    def keyed() -> bool:
        transcript(founder)  # the founder's app has the room open
        return bool(transcript(joiner).get("ready"))

    for name, fn in (("backlog_rows_held", rows_held), ("keyed", keyed)):
        try:
            wait_for(f"the joiner: {name}", fn, wait, every=3)
            rec[name] = round(time.time() - t1, 1)
        except MeshError:
            rec[name] = None
    if rec.get("keyed") is not None:
        sent = founder.say(cid, "after the join")
        t2 = time.time()
        try:
            wait_for("the joiner to read a new message", lambda: any(
                m.get("attestation_id") == sent and m.get("body")
                for m in transcript(joiner).get("messages", [])), wait, every=2)
            rec["new_message_read"] = round(time.time() - t2, 1)
        except MeshError:
            rec["new_message_read"] = None
    return rec


def person_store(mesh: Mesh, args: Any) -> Record:
    """A long-lived person's node meets a stranger, in both directions.

    The seeded node's store has the shape of a real one, every row really signed
    and admitted (`seed_person_store`). PERSON_SEEDER names that binary, PERSON_SHAPE
    the shape file, PERSON_SCALE scales it for a smoke run. Results go to
    <work>/person-store.json, the seed tally to <work>/seed.json."""
    shape = os.environ.get("PERSON_SHAPE") or str(HARNESS / "native" / "shapes" / "person-store.json")
    seeder = os.environ.get("PERSON_SEEDER") or str(
        Path(args.binary).parent / "examples" / "seed_person_store")
    scale = os.environ.get("PERSON_SCALE", "1.0")
    root = os.environ.get("PERSON_ROOT", "test-accord-holder-0")
    step = Steps(f"""
PERSON STORE — a seeded person's node and a stranger, through one relay, both directions.
  shape: {shape} at scale {scale}.
  proves: the seeded node can request (1) and accept (2) a contact and key a room, without
          walking its store for a row the stranger needs.""")
    relay = mesh.start_canonical()
    # Seeded before it is claimed: a boot makes the schema and holds the root, and
    # the claim's session then outlives no restart.
    s = mesh.add("seeded")
    s.stop()
    t0 = time.time()
    done = subprocess.run([seeder, str(s.home / "data" / "ciris_engine.db"), shape, root, scale],
                          capture_output=True, text=True, timeout=3600,
                          env={**os.environ, **s.env})
    (mesh.work / "seed.log").write_text(done.stderr, encoding="utf-8")
    if done.returncode != 0:
        step.fail("seed_failed", done.stderr[-400:], [s], r"$^")
        return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
    seed = json.loads(done.stdout.strip().splitlines()[-1])
    (mesh.work / "seed.json").write_text(json.dumps(seed, indent=1), encoding="utf-8")
    step("seeded", secs=round(time.time() - t0),
         admitted={k: v["admitted"] for k, v in seed["dimensions"].items()},
         refused={k: v["refused"] for k, v in seed["dimensions"].items() if v["refused"]})
    t0 = time.time()
    s.start(health_timeout=600.0)
    step("seeded_booted", secs=round(time.time() - t0))
    s.claim("seeded-person")
    s.announce()
    s.self_record()
    s.peer_with(relay)
    wait_for("seeded to publish its transit route", s.transit_route, 60)
    step("seeded_claimed", owner=s.owner_key_id)

    def stranger(name: str) -> Node:
        n = mesh.add(name)
        n.claim(f"{name}-person")
        n.announce()
        n.self_record()
        n.peer_with(relay)
        wait_for(f"{name} to publish its transit route", n.transit_route, 60)
        return n

    before = _reads(s)
    p = stranger("stranger1")
    asking = _person_contact(mesh, args, s, p)
    step("seeded_requesting", **asking)
    q = stranger("stranger2")
    answering = _person_contact(mesh, args, q, s)
    step("seeded_accepting", **answering)
    late = _late_joiner(s, q, int(os.environ.get("PERSON_HISTORY", "20")),
                        float(os.environ.get("PERSON_LATE_WAIT", "900")))
    step("late_joiner", **late)
    after = _reads(s)
    moved = {d: [v[i] - before.get(d, [0, 0, 0])[i] for i in range(3)] for d, v in after.items()}
    busiest = dict(sorted(moved.items(), key=lambda kv: -kv[1][1])[:8])
    step("reads_on_the_seeded_node", doors_reads_rows_bytes=busiest)
    (mesh.work / "person-store.json").write_text(
        json.dumps({"seed": seed, "requesting": asking, "accepting": answering,
                    "late_joiner": late, "reads": busiest}, indent=1), encoding="utf-8")
    ok = all(r.get("keyed") is not None for r in (asking, answering)) and late.get("new_message_read") is not None
    return {"verdict": "PASS" if ok else "FAIL", "steps": step.log,
            "requesting": asking, "accepting": answering}


def pair_alice_announced(mesh: Mesh, args: Any) -> Record:
    """`pair_unannounced` with only the room's creator announced."""
    return pair_unannounced(mesh, args, announced=("alice",))


def pair_bob_announced(mesh: Mesh, args: Any) -> Record:
    """`pair_unannounced` with only the room's joiner announced."""
    return pair_unannounced(mesh, args, announced=("bob",))


def pair_both_announced(mesh: Mesh, args: Any) -> Record:
    """The control for the two above: `pair_unannounced` with both announced."""
    return pair_unannounced(mesh, args, announced=("alice", "bob"))


def pair_unannounced(mesh: Mesh, args: Any, announced: Tuple[str, ...] = ()) -> Record:
    """CIRISPersist#1140: two people who never announced, no canonical anywhere, each
    node sealing for its owner. A peer lifts a node to its person through the owner-
    binding, which an unannounced owner holds at `self`, so no peer ever receives it.
    Unsplit nodes, so a pass is necessary and not sufficient: the issue is written
    for a split home, where the node seals and the agent doesn't."""
    step = Steps("""
PAIR, UNANNOUNCED — two people's nodes, no canonical, neither owner announced (CIRISPersist#1140).
  proves:  (1) they reach each other by direct peering; (2) a pair room seats and keys;
           (3) a sealed message crosses and reads back; (4) neither side refused a row with
           signer_not_active_member or NoHolders, the issue's failure.""")
    a = mesh.add("alice", canonical=False)
    b = mesh.add("bob", dial=[a], canonical=False)
    a.claim("alice-person")
    b.claim("bob-person")
    for n in (a, b):
        if n.name in announced:
            n.announce()
        n.self_record()
    step("claimed", alice_owner=a.owner_key_id, bob_owner=b.owner_key_id, announced=announced)
    a.peer_with(b)
    b.peer_with(a)
    for host, guest in ((a, b), (b, a)):
        wait_for(f"{host.name} to hold {guest.name}'s owner key",
                 lambda h=host, g=guest: h.knows(g.owner_key_id), args.owner_wait)
    step("keys_crossed")
    a.add_contact(b.contact_code())
    b.add_contact(a.contact_code())
    step("contacts_added")
    room = a.open_pair(b.owner_key_id)
    b.open_pair(a.owner_key_id)
    step("room_opened", room=room)

    def keyed() -> Optional[bool]:
        return True if a.room(room)["ready"] and b.room(room)["ready"] else None
    bad = r"signer_not_active_member|NoHolders"
    try:
        wait_for("the pair room to key on both sides", keyed, args.arrive_wait, every=2)
    except MeshError:
        step.fail("room_not_keyed", "a pair room between unannounced owners must key", [a, b], bad)
        return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
    step("room_keyed")
    secret = f"unannounced-{os.urandom(4).hex()}"
    a.say(room, secret)

    def read() -> Optional[bool]:
        return True if any(secret in str(m) for m in b.room(room)["messages"]) else None
    try:
        wait_for("bob to read alice's message", read, args.arrive_wait, every=2)
    except MeshError:
        step.fail("message_not_read", "the sealed body must cross", [a, b], bad)
        return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
    step("message_read")
    seen = {n.name: len(n.grep(bad)) for n in (a, b)}
    if any(seen.values()):
        step.fail("refused_rows", "the issue's refusal appeared", [a, b], bad, seen=seen)
        return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
    step("no_refusals", seen=seen)
    return {"verdict": "PASS", "steps": step.log}


def av_call(mesh: Mesh, args: Any) -> Record:
    """Two people's nodes on the canonical, a keyed pair room, then a call over the
    QA call routes (CIRIS_QA_CALLS=1): both join, both stream generated frames, both
    read stats, both leave. Env AV_RATE_HZ (30), AV_FRAME_BYTES (600), AV_SECONDS (10)."""
    rate = int(os.environ.get("AV_RATE_HZ", "30"))
    size = int(os.environ.get("AV_FRAME_BYTES", "600"))
    secs = int(os.environ.get("AV_SECONDS", "10"))
    step = Steps(f"""
AV CALL — a pair room's call over the QA call routes (0.5.245).
  proves:  join on both sides → each publishes {rate} Hz x {size} B for {secs} s → each hears
           the other's stream (>= 80% of what the other sent) → both leave cleanly.""")
    os.environ["CIRIS_QA_CALLS"] = "1"
    a = mesh.add("alice")
    b = mesh.add("bob")
    for n in (a, b):
        n.claim(f"{n.name}-person")
        n.announce()
        n.self_record()
        n.peer_with(mesh.canonical)
    for host, guest in ((a, b), (b, a)):
        wait_for(f"{host.name} to hold {guest.name}'s owner key",
                 lambda h=host, g=guest: h.knows(g.owner_key_id), args.owner_wait)
    a.add_contact(b.contact_code())
    b.add_contact(a.contact_code())
    room = a.open_pair(b.owner_key_id)
    b.open_pair(a.owner_key_id)
    t0 = time.time()
    wait_for("the pair room to key on both sides",
             lambda: True if a.room(room)["ready"] and b.room(room)["ready"] else None,
             args.arrive_wait, every=2)
    step("room_keyed", room=room, keyed_s=round(time.time() - t0, 1))
    for n in (a, b):
        st, got = n.api("POST", "/v1/qa/call/start", {"room": room})
        if st != 200:
            step.fail(f"join_refused:{n.name}", "join_call refused", [a, b],
                      r"qa call|join_call|CallError", status=st, body=got)
            return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
        step(f"joined:{n.name}", legs=got.get("legs"), budget=got.get("frame_budget_bytes"))
    # The peer is in the call once this side has a leg to it; the frame budget
    # is known only then (the smallest leg's Channel limit less chunk overhead).
    budgets = {}
    for n in (a, b):
        def leg_up(n=n) -> Optional[int]:
            _, s = n.api("GET", f"/v1/qa/call/stats?room={room}")
            c = (s or {}).get("call") or {}
            return c.get("frame_budget_bytes") if c.get("legs") else None
        try:
            budgets[n.name] = wait_for(f"{n.name}'s call leg", leg_up, 60, every=1)
        except MeshError:
            step.fail(f"no_leg:{n.name}", "no call leg to the peer within 60 s", [a, b],
                      r"call leg|dial failed|av_call")
            return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
    size = min([size] + list(budgets.values()))
    step("legs_up", budgets=budgets, frame_bytes=size)
    for n in (a, b):
        n.must("POST", "/v1/qa/call/stream",
               {"room": room, "rate_hz": rate, "frame_bytes": size, "seconds": secs})
    time.sleep(secs + 4)
    stats = {}
    for n in (a, b):
        _, stats[n.name] = n.api("POST", "/v1/qa/call/stop", {"room": room})
        s = stats[n.name]
        step(f"stats:{n.name}", sent=s.get("sent"), received=s.get("received"),
             call=s.get("call"), summary=s.get("summary"), events=s.get("events"))
    ok = True
    for me, other in (("alice", "bob"), ("bob", "alice")):
        sent = (stats[other].get("sent") or {}).get("frames") or 0
        got = (stats[me].get("received") or {}).get("frames") or 0
        ratio = got / sent if sent else 0.0
        step(f"heard:{me}<-{other}", sent=sent, received=got, ratio=round(ratio, 3))
        ok = ok and sent > 0 and ratio >= 0.8
    if not ok:
        step.fail("stream_not_heard", "each side must hear >= 80% of the other's frames", [a, b],
                  r"qa call|av_call|call|stream")
        return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
    return {"verdict": "PASS", "steps": step.log}


def av_room(mesh: Mesh, args: Any) -> Record:
    """A live call in a room of three, then the orders edge asked for (Eric,
    2026-11-10: calls and scale are what 0.5.246 adds). No retries: every call
    placed and every phase is reported, and a lossy phase is a FAIL.

    Phases, on one timeline (AV_PHASE_S, default 40 s each):
      1. alice and bob join and stream; carol joins LATE (time to her first frame);
      2. all three stream; dave is added to the room mid-call (an MLS epoch roll);
      3. bob LEAVES mid-call (the others' gap is read from their counters);
      4. bob REJOINS (a new stream_id, never the old one);
      5. all stream to the end; the whole call runs AV_TOTAL_S (default 210 s).
    Env AV_RATE_HZ (30), AV_FRAME_BYTES (600)."""
    rate = int(os.environ.get("AV_RATE_HZ", "30"))
    size = int(os.environ.get("AV_FRAME_BYTES", "600"))
    phase = int(os.environ.get("AV_PHASE_S", "40"))
    total = int(os.environ.get("AV_TOTAL_S", "210"))
    step = Steps(f"""
AV ROOM — a call in a three-member community room (0.5.246 gate).
  proves:  late join → epoch roll mid-call → a publisher leaves → it rejoins with a new
           stream → all three hear each other at >= 80% in every phase, {total} s in all.""")
    os.environ["CIRIS_QA_CALLS"] = "1"
    names = ("alice", "bob", "carol", "dave")
    nodes = {n: mesh.add(n) for n in names}
    for n in nodes.values():
        n.claim(f"{n.name}-person")
        n.announce()
        n.self_record()
        n.peer_with(mesh.canonical)
    everyone = list(nodes.values())
    for host in everyone:
        for guest in everyone:
            if host is not guest:
                wait_for(f"{host.name} to hold {guest.name}'s owner key",
                         lambda h=host, g=guest: h.knows(g.owner_key_id), args.owner_wait)
    for host in everyone:
        for guest in everyone:
            if host is not guest:
                host.add_contact(guest.contact_code())
    a, b, c, d = (nodes[n] for n in names)
    got = a.must("POST", "/v1/communities", {"name": "av-room"})
    room = got.get("community_id") or got.get("id")

    seated_members: List[Node] = [a]

    def admit(member: Node) -> None:
        code, body = a.api("POST", f"/v1/communities/{room}/invites",
                           {"key_id": member.owner_key_id})
        if code not in (200, 201, 202):
            raise MeshError(f"invite {member.name} answered {code}: {body}")

        def invite() -> Optional[str]:
            rows = member.must("GET", "/v1/self/invites").get("invites", [])
            return next((r["proposal_id"] for r in rows if r.get("group_id") == room), None)

        pid = wait_for(f"{member.name} to list the invitation", invite, args.arrive_wait, every=2)
        member.must("POST", f"/v1/self/invites/{pid}/accept", {})
        # Setup waits, not call retries: the founder must SEAT the acceptance
        # and the member must read the room as a member, before anyone joins.
        t_acc = time.time()

        def seated() -> Optional[bool]:
            # The founder's app lists the room's invites, which re-attempts the
            # seat with the owner's pen (widen_held_acceptances). The background
            # sweep alone left an invitee unseated for 6 min (2026-11-10).
            a.api("GET", f"/v1/communities/{room}/invites")
            _, room_view = a.api("GET", f"/v1/communities/{room}")
            ms = (room_view or {}).get("members") or [] if isinstance(room_view, dict) else []
            return True if any(member.owner_key_id in json.dumps(x) for x in ms) else None

        roster_now = [x for x in seated_members if x is not member]
        if len(roster_now) >= 2:
            # A room of two or more seats by quorum (majority: > half of the
            # CURRENT members). The founder's one voice is 1 of 2, so the other
            # members co-sign on their own nodes and the founder assembles —
            # the flow a real room needs (no server prompt for it yet, 0.5.246).
            env = a.must("POST", f"/v1/communities/{room}/changes/envelope",
                         {"op": "add", "key_id": member.owner_key_id})
            sigs = list(env.get("signatures") or [])
            for other in roster_now:
                if other is a:
                    continue
                got = other.must("POST", f"/v1/communities/{room}/changes/cosign",
                                 {"change_envelope": env["change_envelope"]})
                sigs.append(got["signature"])
            # Setup wait: the founder must HOLD the joiner's acceptance before the
            # add can land ("membership.awaiting_acceptance" until it replicates).
            t_wait = time.time()

            def assembled() -> Optional[Any]:
                code, body = a.api("POST", f"/v1/communities/{room}/changes/assemble",
                                   {"change_envelope": env["change_envelope"], "signatures": sigs})
                if code in (200, 201, 202):
                    return body
                if isinstance(body, dict) and body.get("reason_id") == "membership.awaiting_acceptance":
                    return None
                raise MeshError(f"assemble answered {code}: {body}")

            done = wait_for(f"alice to hold {member.name}'s acceptance and assemble", assembled,
                            args.arrive_wait * 2, every=2)
            step(f"acceptance_reached_founder:{member.name}", seconds=round(time.time() - t_wait, 1))
            step(f"cosigned:{member.name}", signers=len(sigs),
                 required=env.get("required"), result=str(done)[:200])
        wait_for(f"alice to seat {member.name}", seated, args.arrive_wait * 2, every=2)
        seated_members.append(member)
        wait_for(f"{member.name} to read the room as a member",
                 lambda: True if member.room(room)["status"] == 200 else None,
                 args.arrive_wait * 2, every=2)
        step(f"seated:{member.name}", seated_s=round(time.time() - t_acc, 1))

    # Every member must resolve every other's person to a node first (the
    # handshake needs the owner->node binding, not only the owner key).
    t_res = time.time()
    for host in (a, b, c):
        for guest in (a, b, c):
            if host is not guest:
                wait_for(f"{host.name} to resolve {guest.name} to a node", lambda h=host, g=guest:
                         True if g.node_key_id and h.knows(g.node_key_id) else None,
                         args.arrive_wait * 2, every=2)
    step("resolved", seconds=round(time.time() - t_res, 1))
    for m in (b, c):
        admit(m)
    members = [a, b, c]
    # Edge: the room's MLS group must be on every member before a join, so
    # one sealed chat row read everywhere is the check.
    probe = a.say(room, "before the call")
    for m in members:
        def read_probe(m: Node = m) -> Optional[bool]:
            a.room(room)  # the founder's app has the room open
            return True if any(x.get("attestation_id") == probe and x.get("body")
                               for x in m.room(room)["messages"]) else None
        wait_for(f"{m.name} to read the room's sealed row", read_probe, args.arrive_wait * 2, every=2)
    step("room_keyed", room=room, members=[m.name for m in members])

    t_start = time.time()
    placed: List[Record] = []

    def join(n: Node) -> bool:
        st, body = n.api("POST", "/v1/qa/call/start", {"room": room})
        placed.append({"node": n.name, "at_s": round(time.time() - t_start, 1),
                       "status": st, "legs": (body or {}).get("legs") if isinstance(body, dict) else None,
                       "body": body if st != 200 else None})
        return st == 200

    size_box = [size]

    def stream(n: Node, seconds: int) -> None:
        n.must("POST", "/v1/qa/call/stream",
               {"room": room, "rate_hz": rate, "frame_bytes": size_box[0], "seconds": seconds})

    def stats(n: Node) -> Dict[str, Any]:
        _, s = n.api("GET", f"/v1/qa/call/stats?room={room}")
        return s if isinstance(s, dict) else {}

    def snap(tag: str, who: List[Node]) -> Dict[str, Any]:
        out = {}
        for n in who:
            s = stats(n)
            call = s.get("call") or {}
            out[n.name] = {
                "sent": (s.get("sent") or {}).get("frames"),
                "received": (s.get("received") or {}).get("frames"),
                "delay_ms_p50": (s.get("received") or {}).get("delay_ms_p50"),
                "delay_ms_p95": (s.get("received") or {}).get("delay_ms_p95"),
                "by_publisher": (s.get("received") or {}).get("by_publisher"),
                "state": call.get("state"), "tier": call.get("service_tier"),
                "legs": call.get("legs"), "streams": call.get("streams"),
                "alm": call.get("alm"), "reorder": call.get("reorder"),
                "chunk_auth": call.get("chunk_auth"),
                "leg_sends": (s.get("sent") or {}).get("legs"),
                "events_tail": (s.get("events") or [])[-6:]}
        step(f"snapshot:{tag}", **out)
        return out

    def heard_ok(before: Dict[str, Any], after: Dict[str, Any], senders: int,
                 seconds: float) -> Dict[str, Any]:
        # Each receiver should hear (senders other than itself) x rate x seconds.
        verdict = {}
        for name, now in after.items():
            prev = before.get(name, {})
            got = (now.get("received") or 0) - (prev.get("received") or 0)
            want = max(0, senders - 1) * rate * seconds
            verdict[name] = {"got": got, "expected": int(want),
                             "ratio": round(got / want, 3) if want else None}
        return verdict

    failures: List[str] = []

    # Phase 1: alice and bob join and stream; carol joins late.
    for n in (a, b):
        if not join(n):
            step.fail(f"join_refused:{n.name}", "join_call refused", members,
                      r"qa call|join_call|CallError", placed=placed)
            return {"verdict": "FAIL", "steps": step.log, "placed": placed,
                    "first_failure": step.first_failure}
    # Frames must fit the call's chunk budget (the smallest leg's limit less
    # chunk overhead), known only once a leg is up — as av_call does.
    budgets = {}
    for n in (a, b):
        def leg_budget(n: Node = n) -> Optional[int]:
            c = stats(n).get("call") or {}
            return c.get("frame_budget_bytes") if c.get("legs") else None
        budgets[n.name] = wait_for(f"{n.name}'s call leg", leg_budget, 60, every=1)
    nonlocal_size = min([size] + list(budgets.values()))
    step("legs_up", budgets=budgets, frame_bytes=nonlocal_size)
    size_box[0] = nonlocal_size
    for n in (a, b):
        stream(n, total)
    time.sleep(phase / 2)
    t_c = time.time()
    if not join(c):
        step.fail("join_refused:carol", "late join refused", members,
                  r"qa call|join_call|CallError", placed=placed)
        return {"verdict": "FAIL", "steps": step.log, "placed": placed,
                "first_failure": step.first_failure}
    stream(c, total - int(time.time() - t_start))
    try:
        wait_for("carol's first frame", lambda: (stats(c).get("received") or {}).get("frames") or None,
                 120, every=0.5)
        step("late_join_first_frame", carol_s=round(time.time() - t_c, 1))
    except MeshError:
        step("late_join_first_frame", carol_s=None)
        failures.append("late_join_no_frame")
    time.sleep(max(0, phase / 2))
    p1 = snap("phase1_end", members)

    # Phase 2: all stream; dave added mid-call (an epoch roll).
    t2 = time.time()
    try:
        admit(d)
        step("epoch_roll", added="dave", at_s=round(time.time() - t_start, 1))
    except MeshError as e:
        step("epoch_roll", added=None, error=str(e))
        failures.append("epoch_roll_admit_failed")
    time.sleep(phase)
    p2 = snap("phase2_end", members)
    v2 = heard_ok(p1, p2, 3, time.time() - t2)
    step("heard:phase2_epoch_roll", **v2)
    failures += [f"phase2:{k}" for k, v in v2.items() if (v["ratio"] or 0) < 0.8]

    # Phase 3: bob leaves mid-call.
    old_b = (p2.get("bob") or {}).get("streams")
    t3 = time.time()
    _, left = b.api("POST", "/v1/qa/call/stop", {"room": room})
    step("bob_left", at_s=round(t3 - t_start, 1), final=left)
    time.sleep(phase)
    p3 = snap("phase3_end", [a, c])
    v3 = heard_ok(p2, p3, 2, time.time() - t3)
    step("heard:phase3_after_leave", **v3)
    failures += [f"phase3:{k}" for k, v in v3.items() if (v["ratio"] or 0) < 0.8]

    # Phase 4: bob rejoins; his stream must be new.
    t4 = time.time()
    if join(b):
        stream(b, max(10, total - int(time.time() - t_start)))
        time.sleep(phase)
        p4 = snap("phase4_end", members)
        step("rejoin_streams", before=old_b, after=(p4.get("bob") or {}).get("streams"),
             others_see=[(p4.get(n) or {}).get("streams") for n in ("alice", "carol")])
        v4 = heard_ok(p3, p4, 3, time.time() - t4)
        v4.pop("bob", None)  # bob's own baseline restarted with his new slot
        step("heard:phase4_after_rejoin", **v4)
        failures += [f"phase4:{k}" for k, v in v4.items() if (v["ratio"] or 0) < 0.8]
    else:
        failures.append("rejoin_refused")
        p4 = p3

    # Phase 5: run to the end, then everyone leaves.
    rest = total - (time.time() - t_start)
    if rest > 0:
        time.sleep(rest)
    final = {}
    for n in members:
        _, final[n.name] = n.api("POST", "/v1/qa/call/stop", {"room": room})
    step("call_duration", seconds=round(time.time() - t_start, 1))
    step("final", **{k: {"sent": (v.get("sent") or {}), "received": (v.get("received") or {}),
                         "call": v.get("call")} for k, v in final.items() if isinstance(v, dict)})
    alm_lines = {n.name: n.grep(r"edge\.alm\.decision|alm_|chunk_auth_counts")[-20:] for n in members}
    step("alm_lines", **{k: len(v) for k, v in alm_lines.items()})
    rec: Record = {"steps": step.log, "placed": placed, "alm_lines": alm_lines}
    if failures:
        step.fail("phases", "a phase heard under 80% or an order failed: " + ", ".join(failures),
                  members, r"qa call|av_call|call|stream|alm|epoch")
        rec.update({"verdict": "FAIL", "failures": failures, "first_failure": step.first_failure})
        return rec
    rec["verdict"] = "PASS"
    return rec


def _versions() -> Dict[str, str]:
    root = Path(__file__).resolve().parents[2]
    out = {}
    try:
        out["server_commit"] = subprocess.run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
                                              capture_output=True, text=True).stdout.strip()
        out["server_dirty"] = bool(subprocess.run(["git", "-C", str(root), "status", "--porcelain"],
                                                  capture_output=True, text=True).stdout.strip())
        lock = (root / "Cargo.lock").read_text()
        for crate in ("ciris-edge", "ciris-persist", "ciris-verify-core", "leviculum-core"):
            m = re.search(rf'name = "{crate}"\nversion = "([^"]+)"', lock)
            if m:
                out[crate] = m.group(1)
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    return out


def _evidence(record: Dict[str, Any], name: str) -> str:
    root = Path(__file__).resolve().parents[2]
    d = root / "evidence" / "av"
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{name}.jsonl"
    with open(path, "a") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
    return str(path)


def av_mesh(mesh: Mesh, args: Any) -> Record:
    """N members, member relays ON, everyone publishing; then one publisher's uplink
    is capped mid-call (tc netem in its own container, HARNESS_DOCKER=1) and later
    lifted. Proves calls scale by member relay, not N-1 uplink (Eric, 2026-11-10).

    Env: AV_MEMBERS (4), AV_RATE_HZ (30), AV_FRAME_BYTES (600, clamped to the call's
    budget), AV_BASE_S (45), AV_CAP_S (90), AV_LIFT_S (60), AV_CAP_KBIT (250: about
    2.5 copies of one stream on the wire), AV_RELAY (1). One JSONL line per run to
    evidence/av/av_mesh.jsonl, with the versions."""
    n_members = int(os.environ.get("AV_MEMBERS", "4"))
    rate = int(os.environ.get("AV_RATE_HZ", "30"))
    size = int(os.environ.get("AV_FRAME_BYTES", "600"))
    base_s = int(os.environ.get("AV_BASE_S", "45"))
    cap_s = int(os.environ.get("AV_CAP_S", "90"))
    lift_s = int(os.environ.get("AV_LIFT_S", "60"))
    cap_kbit = int(os.environ.get("AV_CAP_KBIT", "250"))
    relay = os.environ.get("AV_RELAY", "1") == "1"
    capping = bool(mesh.docker) and cap_s > 0
    step = Steps(f"""
AV MESH — {n_members} members, relay={'on' if relay else 'off'}, all publishing.
  proves:  baseline {base_s} s → cap the first publisher's uplink to {cap_kbit} kbit/s for {cap_s} s
           (subscribers move to member relays, everyone still hears it) → lift it for {lift_s} s.""")
    os.environ["CIRIS_QA_CALLS"] = "1"
    names = [f"m{i}" for i in range(n_members)]
    nodes = [mesh.add(nm) for nm in names]
    for n in nodes:
        n.claim(f"{n.name}-person")
        n.announce()
        n.self_record()
        n.peer_with(mesh.canonical)
    for h in nodes:
        for g in nodes:
            if h is not g:
                wait_for(f"{h.name} to hold {g.name}'s owner key",
                         lambda h=h, g=g: h.knows(g.owner_key_id), args.owner_wait)
    for h in nodes:
        for g in nodes:
            if h is not g:
                h.add_contact(g.contact_code())
    founder = nodes[0]
    got = founder.must("POST", "/v1/communities", {"name": "av-mesh"})
    room = got.get("community_id") or got.get("id")
    seated: List[Node] = [founder]
    t_setup = time.time()
    for m in nodes[1:]:
        code, body = founder.api("POST", f"/v1/communities/{room}/invites", {"key_id": m.owner_key_id})
        if code not in (200, 201, 202):
            raise MeshError(f"invite {m.name} answered {code}: {body}")
        pid = wait_for(f"{m.name} to list the invitation", lambda m=m: next(
            (r["proposal_id"] for r in m.must("GET", "/v1/self/invites").get("invites", [])
             if r.get("group_id") == room), None), args.arrive_wait, every=2)
        m.must("POST", f"/v1/self/invites/{pid}/accept", {})
        if len(seated) >= 2:
            env = founder.must("POST", f"/v1/communities/{room}/changes/envelope",
                               {"op": "add", "key_id": m.owner_key_id})
            sigs = list(env.get("signatures") or [])
            for o in seated[1:]:
                sigs.append(o.must("POST", f"/v1/communities/{room}/changes/cosign",
                                   {"change_envelope": env["change_envelope"]})["signature"])

            def assembled() -> Optional[Any]:
                c, b = founder.api("POST", f"/v1/communities/{room}/changes/assemble",
                                   {"change_envelope": env["change_envelope"], "signatures": sigs})
                if c in (200, 201, 202):
                    return b
                if isinstance(b, dict) and b.get("reason_id") == "membership.awaiting_acceptance":
                    return None
                raise MeshError(f"assemble {m.name} answered {c}: {b}")

            wait_for(f"{m.name} seated by quorum", assembled, args.arrive_wait * 2, every=2)

        def is_seated(m: Node = m) -> Optional[bool]:
            founder.api("GET", f"/v1/communities/{room}/invites")
            _, rv = founder.api("GET", f"/v1/communities/{room}")
            ms = (rv or {}).get("members") or [] if isinstance(rv, dict) else []
            return True if any(m.owner_key_id in json.dumps(x) for x in ms) else None

        wait_for(f"{m.name} seated", is_seated, args.arrive_wait * 2, every=2)
        seated.append(m)
    probe = founder.say(room, "before the call")
    for m in nodes:
        def read_probe(m: Node = m) -> Optional[bool]:
            founder.room(room)
            return True if any(x.get("attestation_id") == probe and x.get("body")
                               for x in m.room(room)["messages"]) else None
        wait_for(f"{m.name} to read the room", read_probe, args.arrive_wait * 2, every=2)
    step("room_ready", members=n_members, setup_s=round(time.time() - t_setup, 1))

    placed = []
    for n in nodes:
        st, body = n.api("POST", "/v1/qa/call/start", {"room": room, "relay": relay})
        placed.append({"node": n.name, "status": st})
        if st != 200:
            step.fail(f"join_refused:{n.name}", "join_call refused", nodes,
                      r"qa call|join_call|CallError", status=st, body=body)
            return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}

    def stats(n: Node) -> Dict[str, Any]:
        _, s = n.api("GET", f"/v1/qa/call/stats?room={room}")
        return s if isinstance(s, dict) else {}

    def budget(n: Node) -> Optional[int]:
        c = stats(n).get("call") or {}
        return c.get("frame_budget_bytes") if len(c.get("legs") or []) >= n_members - 1 else None

    budgets = {n.name: wait_for(f"{n.name}'s legs to all members", lambda n=n: budget(n), 120, every=1)
               for n in nodes}
    size = min([size] + list(budgets.values()))
    step("legs_up", budgets=budgets, frame_bytes=size)
    total = base_s + cap_s + lift_s + 10
    for n in nodes:
        n.must("POST", "/v1/qa/call/stream",
               {"room": room, "rate_hz": rate, "frame_bytes": size, "seconds": total})

    capped = nodes[0]
    capped_key = capped.node_key_id or capped.key_id

    def heard_from(n: Node, pub: Node) -> int:
        bp = (stats(n).get("received") or {}).get("by_publisher") or {}
        key = pub.node_key_id or pub.key_id
        for k, v in bp.items():
            if k == key or k.startswith(pub.key_id):
                return int(v.get("frames") or 0)
        return 0

    def snapshot(tag: str) -> Dict[str, Any]:
        out = {}
        for n in nodes:
            s = stats(n)
            c = s.get("call") or {}
            out[n.name] = {
                "sent": (s.get("sent") or {}).get("frames"),
                "publish_refused": (s.get("sent") or {}).get("publish_refused"),
                "leg_sends": (s.get("sent") or {}).get("legs"),
                "received": (s.get("received") or {}).get("frames"),
                "by_publisher": (s.get("received") or {}).get("by_publisher"),
                "streams": c.get("streams"), "alm": c.get("alm"),
                "chunk_auth": c.get("chunk_auth"), "state": c.get("state"),
                "tier": c.get("service_tier")}
        step(f"snapshot:{tag}", **out)
        return out

    def watch(seconds: float) -> Dict[str, Dict[str, Any]]:
        """Poll every receiver's count of the capped publisher's frames; the longest
        stretch with no new frame is that receiver's gap."""
        last = {n.name: (heard_from(n, capped), time.time()) for n in nodes if n is not capped}
        gaps = {k: 0.0 for k in last}
        end = time.time() + seconds
        while time.time() < end:
            time.sleep(1)
            now = time.time()
            for n in nodes:
                if n is capped:
                    continue
                cnt = heard_from(n, capped)
                prev_cnt, prev_t = last[n.name]
                if cnt > prev_cnt:
                    last[n.name] = (cnt, now)
                else:
                    gaps[n.name] = max(gaps[n.name], now - prev_t)
        return {k: {"max_gap_s": round(v, 1)} for k, v in gaps.items()}

    def ratios(before: Dict[str, Any], after: Dict[str, Any], seconds: float) -> Dict[str, Any]:
        r = {}
        for n in nodes:
            if n is capped:
                continue
            b = heard_from_snap(before, n.name)
            a = heard_from_snap(after, n.name)
            want = rate * seconds
            r[n.name] = {"got": a - b, "expected": int(want), "ratio": round((a - b) / want, 3)}
        return r

    def heard_from_snap(snap: Dict[str, Any], name: str) -> int:
        bp = (snap.get(name) or {}).get("by_publisher") or {}
        for k, v in bp.items():
            if k == capped_key or k.startswith(capped.key_id):
                return int(v.get("frames") or 0)
        return 0

    s0 = snapshot("start")
    t0 = time.time()
    time.sleep(base_s)
    s1 = snapshot("baseline_end")
    r_base = ratios(s0, s1, time.time() - t0)
    step("heard_capped_publisher:baseline", **r_base)
    phases = {"baseline": r_base}
    gaps_cap: Dict[str, Any] = {}
    if capping:
        capped.netem("rate", f"{cap_kbit}kbit", "limit", "1000")
        t1 = time.time()
        step("cap_on", node=capped.name, kbit=cap_kbit)
        gaps_cap = watch(cap_s)
        s2 = snapshot("cap_end")
        r_cap = ratios(s1, s2, time.time() - t1)
        step("heard_capped_publisher:capped", **r_cap, gaps=gaps_cap)
        phases["capped"] = r_cap
        capped.netem()
        t2 = time.time()
        step("cap_off", node=capped.name)
        gaps_lift = watch(lift_s)
        s3 = snapshot("lift_end")
        r_lift = ratios(s2, s3, time.time() - t2)
        step("heard_capped_publisher:lifted", **r_lift, gaps=gaps_lift)
        phases["lifted"] = r_lift
    else:
        step("cap_skipped", reason="needs HARNESS_DOCKER=1" if not mesh.docker else "AV_CAP_S=0")
        s3 = s1
    final = {}
    for n in nodes:
        _, final[n.name] = n.api("POST", "/v1/qa/call/stop", {"room": room})
    legs_capped = {n.name: [x.get("leg") for x in ((s3.get(n.name) or {}).get("streams") or [])
                            if str(x.get("publisher") or "").startswith(capped.key_id)]
                   for n in nodes if n is not capped}
    alm = {n.name: (s3.get(n.name) or {}).get("alm") for n in nodes}
    auth = {n.name: (s3.get(n.name) or {}).get("chunk_auth") for n in nodes}
    failures = [f"{ph}:{k}" for ph, rs in phases.items() for k, v in rs.items() if v["ratio"] < 0.99]
    verdict = "PASS" if not failures else "FAIL"
    record = {"scenario": "av_mesh", "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "versions": _versions(), "docker": bool(mesh.docker), "members": n_members,
              "relay": relay, "rate_hz": rate, "frame_bytes": size, "cap_kbit": cap_kbit if capping else None,
              "phase_seconds": {"base": base_s, "cap": cap_s if capping else 0, "lift": lift_s if capping else 0},
              "heard_capped_publisher": phases, "gaps_while_capped": gaps_cap,
              "capped_publisher_legs_at_end": legs_capped, "alm": alm, "chunk_auth": auth,
              "placed": placed, "verdict": verdict, "failures": failures}
    path = _evidence(record, "av_mesh")
    step("evidence", path=path)
    rec: Record = {"steps": step.log, "verdict": verdict, "evidence": path}
    if failures:
        step.fail("phases", "the capped publisher was heard under 99% in a phase: " + ", ".join(failures),
                  nodes, r"alm|shed|relay|offer|call")
        rec["first_failure"] = step.first_failure
    return rec


def av_member(mesh: Mesh, args: Any) -> Record:
    """The MEMBER call surface end to end (CIRISServer#859): two people join their
    pair room's call through POST /v1/chat/{room}/call, open the frames socket
    with their single-use tickets, send real Opus frames (the frames-v1 vector's
    packet, 50 per second) for AV_SECONDS (10), read each other's frames off the
    socket, then one leaves and the other must see attendee_left. No retries."""
    import struct
    import threading
    import websocket  # websocket-client

    secs = int(os.environ.get("AV_SECONDS", "10"))
    vec = json.loads((Path(__file__).resolve().parents[2] / "tests" / "vectors"
                      / "call_frames_v1.json").read_text())
    opus = bytes.fromhex(vec["client_to_node"][0]["payload_hex"])
    step = Steps(f"""
AV MEMBER — the production call routes, frames socket and events.
  proves:  join as the member → ticketed socket → {secs} s of 20 ms Opus frames both ways →
           each hears >= 99% of the other → a leave is seen as attendee_left.""")
    a = mesh.add("alice")
    b = mesh.add("bob")
    for n in (a, b):
        n.claim(f"{n.name}-person")
        n.announce()
        n.self_record()
        n.peer_with(mesh.canonical)
    for host, guest in ((a, b), (b, a)):
        wait_for(f"{host.name} to hold {guest.name}'s owner key",
                 lambda h=host, g=guest: h.knows(g.owner_key_id), args.owner_wait)
    a.add_contact(b.contact_code())
    b.add_contact(a.contact_code())
    room = a.open_pair(b.owner_key_id)
    b.open_pair(a.owner_key_id)
    wait_for("the pair room to key on both sides",
             lambda: True if a.room(room)["ready"] and b.room(room)["ready"] else None,
             args.arrive_wait, every=2)
    st, conf = a.api("GET", "/v1/federation/conformance")
    feats = ((conf or {}).get("data") or conf or {}).get("features") if isinstance(conf, dict) else None
    step("feature_declared", features=feats)
    joins = {}
    for n in (a, b):
        st, got = n.api("POST", f"/v1/chat/{room}/call", {"video": False})
        if st != 200:
            step.fail(f"join_refused:{n.name}", "the member join was refused", [a, b],
                      r"call|join_call|CallError", status=st, body=got)
            return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
        joins[n.name] = got
        step(f"joined:{n.name}", budget=got.get("frame_budget_bytes"), legs=got.get("legs"),
             stream_id=got.get("stream_id"), ticket=bool(got.get("frames_ticket")))
    _, gs = a.api("GET", f"/v1/chat/{room}/call")
    step("call_state", live=(gs or {}).get("live"), room_may_keep=(gs or {}).get("room_may_keep"),
         visible_to_watcher=(gs or {}).get("visible_to_watcher"))

    received = {"alice": {}, "bob": {}}
    events = {"alice": [], "bob": []}
    socks = {}

    def reader(name: str, ws: Any) -> None:
        while True:
            try:
                op, data = ws.recv_data()
            except Exception:  # noqa: BLE001
                return
            if op == websocket.ABNF.OPCODE_BINARY:
                pl = struct.unpack(">H", data[5:7])[0]
                pub = data[7:7 + pl].decode()
                received[name][pub] = received[name].get(pub, 0) + 1
            elif op == websocket.ABNF.OPCODE_TEXT:
                events[name].append(json.loads(data))
            elif op == websocket.ABNF.OPCODE_CLOSE:
                return

    for n in (a, b):
        url = n.url.replace("http://", "ws://") + f"/v1/chat/{room}/call/frames?ticket=" + \
            joins[n.name]["frames_ticket"]
        ws = websocket.create_connection(url, timeout=10)
        socks[n.name] = ws
        threading.Thread(target=reader, args=(n.name, ws), daemon=True).start()
    step("sockets_open")
    t_ready = time.time()
    wait_for("both sockets to say ready", lambda: True if all(
        any(e.get("type") == "ready" for e in events[n]) for n in events) else None, 60, every=0.2)
    step("ready", seconds=round(time.time() - t_ready, 2),
         budgets={n: next(e.get("frame_budget_bytes") for e in events[n] if e.get("type") == "ready")
                  for n in events})
    frame = bytes([1, 0xFF, 0, 0, 0]) + opus
    sent = {"alice": 0, "bob": 0}
    t0 = time.time()
    tick = 0
    while time.time() - t0 < secs:
        for name, ws in socks.items():
            ws.send_binary(frame)
            sent[name] += 1
        tick += 1
        nxt = t0 + tick * 0.02
        time.sleep(max(0.0, nxt - time.time()))
    time.sleep(2)
    a_key = a.node_key_id or a.key_id
    b_key = b.node_key_id or b.key_id

    def heard(me: str, pub_key: str) -> int:
        return sum(v for k, v in received[me].items() if k == pub_key or k.startswith(pub_key.rsplit("-", 1)[0]))

    ratio_ab = heard("bob", a_key) / max(1, sent["alice"])
    ratio_ba = heard("alice", b_key) / max(1, sent["bob"])
    step("heard", alice_sent=sent["alice"], bob_heard_alice=heard("bob", a_key), ratio_bob=round(ratio_ab, 3),
         bob_sent=sent["bob"], alice_heard_bob=heard("alice", b_key), ratio_alice=round(ratio_ba, 3),
         received_keys={k: list(v) for k, v in received.items()},
         refusals={k: [e for e in v if e.get("type") == "publish_refused"][:3] for k, v in events.items()})
    _, left = b.api("DELETE", f"/v1/chat/{room}/call")
    step("bob_left", answer=left)
    wait_for("alice to see attendee_left", lambda: True if any(
        e.get("type") == "attendee_left" for e in events["alice"]) else None, 30, every=0.5)
    step("events", alice=[e.get("type") for e in events["alice"]][:12], bob=[e.get("type") for e in events["bob"]][:12])
    left_ev = next((e for e in events["alice"] if e.get("type") == "attendee_left"), {})
    ready_ev = next((e for e in events["alice"] if e.get("type") == "ready"), {})
    people = joins["bob"].get("attendee_people")
    step("person_beside_member", left_member=left_ev.get("member"), left_person=left_ev.get("person"),
         bob_person=b.owner_key_id, ready_fragmenting=ready_ev.get("fragmenting"), join_people=people)
    for ws in socks.values():
        try:
            ws.close()
        except Exception:  # noqa: BLE001
            pass
    record = {"scenario": "av_member", "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "versions": _versions(), "seconds": secs, "frame_bytes": len(frame),
              "sent": sent, "ratio": {"bob_from_alice": round(ratio_ab, 4), "alice_from_bob": round(ratio_ba, 4)},
              "features": feats}
    ok = (ratio_ab >= 0.99 and ratio_ba >= 0.99 and feats and "chat:call" in feats
          and left_ev.get("person") == b.owner_key_id and ready_ev.get("fragmenting") is False)
    record["verdict"] = "PASS" if ok else "FAIL"
    _evidence(record, "av_member")
    if not ok:
        step.fail("member_call", "each side must hear >= 99% and the node must declare chat:call",
                  [a, b], r"call|frames|publish")
        return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
    return {"verdict": "PASS", "steps": step.log}


def decisions(mesh: Mesh, args: Any) -> Record:
    """The pending-decisions queue's first kind (0.5.246): in a room of two, a third
    person's accepted invitation shows to BOTH members as "approve joining" with the
    room's count, and an approval is recorded and reported as waiting on the others
    (in-mesh cosignatures land with persist 61.3.0 / edge 45.1)."""
    step = Steps("""
DECISIONS — "approve X joining" reaches every member with standing.
  proves:  alice + bob seated → carol invited and accepts → both see the decision with
           required = 2 → alice approves → 202 awaiting_members, and her answer shows.""")
    names = ("alice", "bob", "carol")
    nodes = {n: mesh.add(n) for n in names}
    for n in nodes.values():
        n.claim(f"{n.name}-person")
        n.announce()
        n.self_record()
        n.peer_with(mesh.canonical)
    allx = list(nodes.values())
    for h in allx:
        for g in allx:
            if h is not g:
                wait_for(f"{h.name} to hold {g.name}'s owner key",
                         lambda h=h, g=g: h.knows(g.owner_key_id), args.owner_wait)
                h.add_contact(g.contact_code())
    a, b, c = (nodes[n] for n in names)
    room = a.must("POST", "/v1/communities", {"name": "decisions"}).get("community_id")

    def invite_and_accept(m: Node) -> None:
        code, body = a.api("POST", f"/v1/communities/{room}/invites", {"key_id": m.owner_key_id})
        if code not in (200, 201, 202):
            raise MeshError(f"invite {m.name} answered {code}: {body}")
        pid = wait_for(f"{m.name} to list the invitation", lambda: next(
            (r["proposal_id"] for r in m.must("GET", "/v1/self/invites").get("invites", [])
             if r.get("group_id") == room), None), args.arrive_wait, every=2)
        m.must("POST", f"/v1/self/invites/{pid}/accept", {})

    invite_and_accept(b)
    wait_for("bob seated", lambda: True if (a.api("GET", f"/v1/communities/{room}/invites") and any(
        b.owner_key_id in json.dumps(x) for x in (a.api("GET", f"/v1/communities/{room}")[1] or {}).get("members", [])))
        else None, args.arrive_wait * 2, every=2)
    step("bob_seated")
    invite_and_accept(c)

    def queued(n: Node) -> Optional[Dict[str, Any]]:
        _, body = n.api("GET", f"/v1/self/decisions?circle={room}")
        items = (body or {}).get("decisions") or [] if isinstance(body, dict) else []
        return next((d for d in items if d.get("subject") == c.owner_key_id), None)

    seen = {}
    for n in (a, b):
        seen[n.name] = wait_for(f"{n.name} to see 'approve carol joining'", lambda n=n: queued(n),
                                args.arrive_wait * 2, every=2)
        d = seen[n.name]
        step(f"queued:{n.name}", required=d.get("required"), protocol=d.get("consensus_protocol"),
             eligible=len(d.get("eligible") or []), says=d.get("says"))
    did = seen["alice"]["decision_id"]
    st, ans = a.api("POST", f"/v1/self/decisions/{did}/answer", {"answer": "approve"})
    step("alice_approved", status=st, state=(ans or {}).get("state"), reason=(ans or {}).get("reason_id"))
    mine = queued(a)
    ok = (seen["alice"].get("required") == 2 and seen["bob"].get("required") == 2
          and st == 202 and (ans or {}).get("state") == "awaiting_members"
          and (mine or {}).get("my_answer") == "approve"
          and seen["alice"]["decision_id"] == seen["bob"]["decision_id"])
    step("my_answer_shown", my_answer=(mine or {}).get("my_answer"),
         same_id_on_both=seen["alice"]["decision_id"] == seen["bob"]["decision_id"])
    if not ok:
        step.fail("decisions", "the decision must reach both members with required=2, and an "
                  "approval must be recorded as awaiting the others", allx, r"decision|membership|widen")
        return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
    return {"verdict": "PASS", "steps": step.log}


def av_echo(mesh: Mesh, args: Any) -> Record:
    """The QA echo node (0.5.246): one client leg calls ONE node. bob's node runs
    POST /v1/qa/call/echo (CIRIS_QA_CALLS=1) and republishes every frame it hears;
    alice joins through the MEMBER routes and must get her own frames back, codec_id
    and layer unchanged, from bob's person. No retries."""
    import struct
    import threading
    import websocket

    secs = int(os.environ.get("AV_SECONDS", "10"))
    os.environ["CIRIS_QA_CALLS"] = "1"
    vec = json.loads((Path(__file__).resolve().parents[2] / "tests" / "vectors"
                      / "call_frames_v1.json").read_text())
    opus = bytes.fromhex(vec["client_to_node"][0]["payload_hex"])
    step = Steps(f"""
AV ECHO — one client leg against one echoing node.
  proves:  bob echoes → alice sends {secs} s of Opus → alice hears >= 99% back, unchanged.""")
    a = mesh.add("alice")
    b = mesh.add("bob")
    for n in (a, b):
        n.claim(f"{n.name}-person")
        n.announce()
        n.self_record()
        n.peer_with(mesh.canonical)
    for host, guest in ((a, b), (b, a)):
        wait_for(f"{host.name} to hold {guest.name}'s owner key",
                 lambda h=host, g=guest: h.knows(g.owner_key_id), args.owner_wait)
    a.add_contact(b.contact_code())
    b.add_contact(a.contact_code())
    room = a.open_pair(b.owner_key_id)
    b.open_pair(a.owner_key_id)
    wait_for("the pair room to key", lambda: True if a.room(room)["ready"] and b.room(room)["ready"] else None,
             args.arrive_wait, every=2)
    st, got = b.api("POST", "/v1/qa/call/echo", {"room": room})
    step("echo_started", status=st, body=got)
    if st != 200:
        step.fail("echo_refused", "the echo node did not start", [a, b], r"qa call|echo|join")
        return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
    st, j = a.api("POST", f"/v1/chat/{room}/call", {"video": False})
    if st != 200:
        step.fail("join_refused", "alice's member join was refused", [a, b], r"call|join")
        return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
    back = {"frames": 0, "codecs": set(), "layers": set(), "publishers": set(), "payload_ok": 0}
    events: List[Dict[str, Any]] = []
    url = a.url.replace("http://", "ws://") + f"/v1/chat/{room}/call/frames?ticket=" + j["frames_ticket"]
    ws = websocket.create_connection(url, timeout=10)

    def reader() -> None:
        while True:
            try:
                op, data = ws.recv_data()
            except Exception:  # noqa: BLE001
                return
            if op == websocket.ABNF.OPCODE_BINARY:
                pl = struct.unpack(">H", data[5:7])[0]
                back["frames"] += 1
                back["codecs"].add(data[1])
                back["layers"].add(tuple(data[2:5]))
                back["publishers"].add(data[7:7 + pl].decode())
                # pub_len, publisher, stream_id, epoch+chunk_seq, source_ts_ms+flags+frame_seq
                if data[7 + pl + 32 + 16 + 13:] == opus:
                    back["payload_ok"] += 1
            elif op == websocket.ABNF.OPCODE_TEXT:
                events.append(json.loads(data))
            else:
                return

    threading.Thread(target=reader, daemon=True).start()
    wait_for("alice's socket to say ready", lambda: True if any(e.get("type") == "ready" for e in events)
             else None, 60, every=0.2)
    frame = bytes([1, 0xFF, 0, 0, 0]) + opus
    sent = 0
    t0 = time.time()
    while time.time() - t0 < secs:
        ws.send_binary(frame)
        sent += 1
        time.sleep(max(0.0, t0 + sent * 0.02 - time.time()))
    time.sleep(3)
    _, stopped = b.api("POST", "/v1/qa/call/echo/stop", {"room": room})
    ratio = back["frames"] / max(1, sent)
    step("echoed", sent=sent, back=back["frames"], ratio=round(ratio, 3), payload_intact=back["payload_ok"],
         codecs=sorted(back["codecs"]), layers=sorted(back["layers"]), publishers=sorted(back["publishers"]),
         node_counts=stopped)
    try:
        ws.close()
    except Exception:  # noqa: BLE001
        pass
    ok = ratio >= 0.99 and back["codecs"] == {0xFF} and back["layers"] == {(0, 0, 0)} \
        and back["payload_ok"] == back["frames"] and all(p.startswith(b.key_id.rsplit("-", 1)[0]) or p for p in back["publishers"])
    _evidence({"scenario": "av_echo", "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "versions": _versions(), "sent": sent, "back": back["frames"], "ratio": round(ratio, 4),
               "verdict": "PASS" if ok else "FAIL"}, "av_echo")
    if not ok:
        step.fail("echo", "alice must hear >= 99% of her frames back, codec and layer unchanged", [a, b],
                  r"echo|qa call|publish")
        return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
    return {"verdict": "PASS", "steps": step.log}


def peer_pair(mesh: Mesh, args: Any) -> Record:
    """The client's two-node fixture: two nodes, no canonical anywhere, claimed,
    announced and peered both ways over the production routes. Under the sealed
    transport the link needs each side's transit pair; peering carries it."""
    step = Steps("""
PEER PAIR — two people's nodes peered DIRECTLY, no canonical (CIRISServer#808).
  routes:  claim, announce, self-key-record + self-transport-destination + /v1/federation/peering.
  proves:  peering admits the peer's signed transit route → a sealed link forms → each owner's
           key reaches the other node with no relay.""")
    a = mesh.add("alice", canonical=False)
    b = mesh.add("bob", dial=[a], canonical=False)
    step("booted", alice=a.url, bob=b.url, canonical=None)
    a.claim("alice-person")
    b.claim("bob-person")
    for n in (a, b):
        n.announce()
        n.self_record()
    step("claimed_and_announced", alice_owner=a.owner_key_id, bob_owner=b.owner_key_id)
    got_ab = a.peer_with(b)
    got_ba = b.peer_with(a)
    step("peered", alice_admitted=got_ab.get("peer_transit_route"),
         bob_admitted=got_ba.get("peer_transit_route"))
    if got_ab.get("peer_transit_route") != "admitted" or got_ba.get("peer_transit_route") != "admitted":
        step.fail("transit_route_NOT_admitted", "peering refused the peer's signed transit route",
                  [a, b], r"transit route|transit_route|transport_destination")
        return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
    for host, guest in ((a, b), (b, a)):
        try:
            wait_for(f"{host.name} to hold {guest.name}'s owner key",
                     lambda: host.knows(guest.owner_key_id), args.owner_wait)
            step(f"owner_key_crossed:{host.name}<-{guest.name}")
        except MeshError:
            step.fail(f"owner_key_NOT_crossed:{host.name}<-{guest.name}",
                      "no sealed link formed between two directly peered nodes",
                      [host, guest], r"link_seal_refused|transit seal|no usable transit|un-routable")
            return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
    return {"verdict": "PASS", "steps": step.log}


# ── one person, two devices, the transfer corpus (the ≥1 MiB question) ──────


def corpus(mesh: Mesh, args: Any) -> Record:
    """One person on two devices; the corpus written on the first, read raw on
    BOTH, compared byte for byte with the originals."""
    topology = ("the second device also dials the first: DIRECT neighbours" if args.direct
                else "both devices dial only the canonical: NOT direct neighbours")
    step = Steps(f"""
CORPUS — one person, two devices, the transfer corpus written on the first and read raw on BOTH
  (CSD-007 files / CSD-008 notes on a second device; the ≥1 MiB question from the selffiles ladder).
  trust root: synthetic anchor; canonical holds it.  topology: {topology}.
  proves: same owner on both → peered → self room on both → files written (first reads them back
          byte-identical) → the second device pulls and opens each one byte-identical.""")
    a = mesh.add("first")
    a.claim("one-person")
    b = mesh.add("second", start=False, dial=[a] if args.direct else None)
    b.home.mkdir(parents=True, exist_ok=True)
    b.carry_owner_from(a, "one-person")
    b.start()
    b.claim("one-person")
    step("claimed", same_owner=a.owner_key_id == b.owner_key_id, owner=a.owner_key_id)
    for n in (a, b):
        n.announce()
        n.self_record()
    a.peer_with(b)
    b.peer_with(a)
    step("peered")
    wait_for("the self room on both devices",
             lambda: a.grep(r"self room (CREATED|JOINED)") and b.grep(r"self room (CREATED|JOINED)"),
             args.ready_wait, every=3)
    step("self_room")

    out = mesh.work / "corpus"
    subprocess.run([sys.executable, str(HARNESS / "mesh-repro" / "lib" / "media_corpus.py"), str(out)],
                   check=True, capture_output=True)
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    only = set(args.only.split(",")) if getattr(args, "only", "") else None
    written = []
    for row in manifest:
        if only and row["name"] not in only:
            continue
        data = (out / row["name"]).read_bytes()
        got = a.write_file(data, row["media_type"], row["filename"])
        written.append({**row, "id": got["attestation_id"]})
    step("written", files=len(written))

    def compare(n: Node, row: Record) -> Record:
        status, raw = n.read_raw(row["id"])
        want = (out / row["name"]).read_bytes()
        r: Record = {"status": status, "size": len(raw) if status == 200 else None,
                     "expected": len(want)}
        if status == 200:
            r["match"] = hashlib.sha256(raw).hexdigest() == row["sha256"]
            if not r["match"]:
                m = min(len(raw), len(want))
                first = next((i for i in range(m) if raw[i] != want[i]), None)
                r.update(first_diff=first if first is not None else m,
                         prefix=first is None and len(raw) < len(want),
                         differing=sum(1 for i in range(m) if raw[i] != want[i]))
        else:
            r["body"] = raw[:200].decode(errors="replace")
        return r

    results: Record = {}
    deadline = time.monotonic() + args.arrive_wait
    pending = {w["name"]: w for w in written}
    for w in written:
        results[w["name"]] = {"first": compare(a, w)}
    while pending and time.monotonic() < deadline:
        for name, w in list(pending.items()):
            r = compare(b, w)
            results[name]["second"] = r
            if r["status"] == 200:
                del pending[name]
        if pending:
            time.sleep(3)
    bad = {k: v for k, v in results.items()
           if not v["first"].get("match") or not v.get("second", {}).get("match")}
    step("compared", ok=len(results) - len(bad), bad=len(bad),
         proves="each file's bytes on the first device, and on the second, against the original")
    if bad:
        no_row = [k for k, v in bad.items() if v.get("second", {}).get("status") == 404]
        not_here = [k for k, v in bad.items() if v.get("second", {}).get("status") == 409]
        wrong = [k for k, v in bad.items() if v.get("second", {}).get("status") == 200]
        means = []
        if no_row:
            means.append(f"{len(no_row)} ROWS never reached the second device (404 not_in_room: the row itself is "
                         "not held there, so no pull was attempted) — replication of the attestation, not the bytes; "
                         "look for `stalled mid-frame` / `REFUSED` on the sender's rounds toward it")
        if not_here:
            means.append(f"{len(not_here)} never reached the second device (not_fetched): the pull over the "
                         "room's derived address failed — a `no route to peer` / `holder retired` line "
                         "is a topology fault (direct neighbours needed, CC 5.4.6), `NoHolders` is the pull's source rule")
        if wrong:
            means.append(f"{len(wrong)} arrived with DIFFERENT bytes: a transfer defect; `first_diff`/`prefix` say where")
        step.fail("corpus_mismatch", "; ".join(means), [a, b],
                  _BODY + r"|stalled mid-frame|delivered envelope REFUSED|frame DROPPED", files=bad)
    return {"verdict": "PASS" if not bad else "FAIL", "steps": step.log, "results": results}


# ── the final genesis, end to end (FSD/FINAL_GENESIS.md §3 "Dry run") ──────


def _owned_canonical_baseline(mesh: Mesh, args: Any, step: "Steps") -> Record:
    """The same three pairs on the harness's blessed synthetic root, with the
    canonical CLAIMED as in production — separates a genesis defect from one
    any owned canonical has (FINAL_GENESIS_BASELINE=1)."""
    c = mesh.start_canonical()
    c.claim("operator-person")
    c.announce()
    c.self_record()
    a = mesh.add("alice")
    b = mesh.add("bob")
    a.claim("alice-person")
    b.claim("bob-person")
    for n in (a, b):
        n.announce()
        n.self_record()
        n.peer_with(c)
        c.peer_with(n)
    a.peer_with(b)
    b.peer_with(a)
    step("baseline_booted_claimed_peered")
    ok = True
    for x, y in ((a, b), (a, c), (b, c)):
        try:
            wait_for(f"{x.name} and {y.name} Rooted", lambda: x.rooted_with(y) and y.rooted_with(x),
                     args.rooted_wait or 120, every=3)
            step(f"rooted:{x.name}<->{y.name}")
        except MeshError:
            ok = False
            step(f"NOT_rooted:{x.name}<->{y.name}", x_sees_y=x.rooted_with(y), y_sees_x=y.rooted_with(x))
    return {"verdict": "PASS" if ok else "FAIL", "steps": step.log, "baseline": True}


def _serve_input(n: Node) -> Dict[str, Any]:
    """A seat the ceremony host has never met: its whole record, as a bundle takes it."""
    r = n.record["record"]
    roles = ["infra:attest", "infra:serve", "infra:store", "infra:transport"]
    envelope = {**(r.get("registration_envelope") or {}), "roles": roles,
                "transport_hints": [{"kind": "ip", "destination": n.transport}]}
    return {"key_id": r["key_id"], "identity_type": "canonical,node",
            "pubkey_ed25519_base64": r["pubkey_ed25519_base64"],
            "pubkey_ml_dsa_65_base64": r["pubkey_ml_dsa_65_base64"],
            "capability_roles": roles, "registration_envelope": envelope,
            "attestation_evidence": r.get("attestation_evidence")}


def mint_accord_root(mesh: Mesh, args: Any, step: "Steps", announce: bool = True,
                     second_seat: bool = False):
    """Layers 1-2 of the T8 catalogue entry: the 0.5.220 ceremony over the
    routes with THREE software holders, and a canonical rebooted on the minted
    bundle as its baked genesis, claimed and announced. Returns
    (canonical, anchor, done): `anchor["holders"]` carries each holder's
    `key_id` and `seed_b64`, which the test-anchor accord doors accept as
    `test_holder_seed_b64`; every node the mesh adds afterwards boots on the
    bundle (`mesh.base_env[CIRIS_TEST_GENESIS_BUNDLE]`)."""
    anchor_bin = mesh.binary.parent / "examples" / "test_ceremony_anchor"
    if not anchor_bin.is_file():
        raise MeshError(f"no {anchor_bin}: cargo build --features test-anchor --example test_ceremony_anchor")
    anchor = json.loads(subprocess.run([str(anchor_bin)], capture_output=True, text=True,
                                       check=True).stdout)
    mesh.base_env.update(anchor["env"])
    mesh.base_env["CIRIS_TEST_NO_CEREMONY"] = "true"
    step("anchor", holders=[h["key_id"] for h in anchor["holders"]])

    # 1. The ceremony host: the canonical, booted on NO genesis of its own yet.
    c = mesh._node("canonical", {"CIRIS_TEST_BLESS_CANONICAL": "false",
                                 "CIRIS_DEVICE_CLASS": "server"})
    c.configure(dial=[])
    c.start()
    mesh.canonical, mesh.nodes["canonical"] = c, c
    c.self_record()
    step("canonical_booted", key_id=c.node_key_id)
    seat2: Optional[Node] = None
    if second_seat:
        seat2 = mesh._node("seat2", {"CIRIS_TEST_BLESS_CANONICAL": "false",
                                     "CIRIS_DEVICE_CLASS": "server"})
        seat2.configure(dial=[])
        seat2.start()
        mesh.nodes["seat2"] = seat2
        seat2.self_record()
        step("second_seat_booted", key_id=seat2.node_key_id)

    # 2. The ceremony, over the routes.
    planned = c.must("POST", "/v1/accord/final-genesis/plan", {
        # Where peers dial it — as the baked canonical carries it.
        "serve_nodes": [{"key_id": c.node_key_id,
                         "transport_hints": [{"kind": "ip", "destination": c.transport}]}]
                       + ([_serve_input(seat2)] if seat2 else []),
        "recovery_keys": anchor["recovery_keys"],
        "serve_transport_destinations": ([wait_for("seat 2's transit route", seat2.transit_route, 60)]
                                         if seat2 else []),
        "clock_checked": True})
    step("planned", complete=planned.get("complete"), owed=planned.get("owed"))
    for rnd in (1, 2):
        for h in anchor["holders"]:
            got = c.must("POST", "/v1/accord/final-genesis/sign", {
                "key_id": h["key_id"], "mldsa_usb_path": "/unused/software-holder",
                "test_holder_seed_b64": h["seed_b64"]})
            step(f"signed:round{rnd}:{h['key_id']}", signed=got.get("signed"),
                 complete=got.get("complete"))
    status = c.must("GET", "/v1/accord/final-genesis")
    if not status.get("complete"):
        raise MeshError(f"items still owed after two rounds: {status}")
    done = c.must("POST", "/v1/accord/final-genesis/finish", {})
    bundle_path = done["bundle_path"]
    step("finished", proves="persist assembled the bundle and verify_ceremony_outputs passed",
         bundle_sha256=done.get("bundle_sha256"), verified=done.get("verified"))

    # 3. The fleet boots on it.
    mesh.base_env["CIRIS_TEST_GENESIS_BUNDLE"] = bundle_path
    c.env["CIRIS_TEST_GENESIS_BUNDLE"] = bundle_path
    c.stop()
    # A FRESH directory under the same keys: the canonical's identity (what the
    # bundle seats) is kept, its database is not. The ceremony host's first
    # boot seeded a family under a DIFFERENT roster than the test holders, and
    # an unrelated family is rightly never succeeded — in production the old
    # and new family share A1/B1/C1 (persist's successor path); a freshly keyed
    # canonical (canonical-2/-3) boots exactly like this.
    for f in (c.home / "data").glob("ciris_engine.db*"):
        f.unlink()
    c.configure(dial=[])  # the listen address lives in the database's config:*
    c.start()
    if seat2:
        seat2.env["CIRIS_TEST_GENESIS_BUNDLE"] = bundle_path
        seat2.stop()
        for f in (seat2.home / "data").glob("ciris_engine.db*"):
            f.unlink()
        seat2.configure(dial=[c.transport])
        seat2.start()
        seat2.claim("operator-two")
        if announce:
            seat2.announce()
        seat2.self_record()
    step("canonical_rebooted_on_bundle",
         evidence=c.grep(r"booting on a ceremony-minted genesis bundle")[-1:])
    # The production canonical is OWNED (the operator's fedID) — an unowned
    # node refuses federation peering.
    c.claim("operator-person")
    if announce:
        c.announce()
    c.self_record()
    step("canonical_claimed", owner=c.owner_key_id)
    mesh.accord_holders = anchor["holders"]
    return c, anchor, done


def _held_rows(n: Node, author: str, dimension: str) -> int:
    """How many rows of `dimension` by `author` this node's store holds. Read-only."""
    db = sqlite3.connect(f"file:{n.home / 'data' / 'ciris_engine.db'}?mode=ro", uri=True, timeout=5)
    try:
        return db.execute(
            "select count(*) from federation_attestations where attesting_key_id = ? "
            "and json_extract(attestation_envelope, '$.dimension') = ?",
            (author, dimension)).fetchone()[0]
    finally:
        db.close()


def two_seats(mesh: Mesh, args: Any) -> Record:
    """CC 5.2: two serve seats walk the commons between themselves, and a seat offers
    a person's node only what is required or appropriate.

    Not a witness for `recognised_seats`: both seats are in the bundle, so the
    directory fallback finds them and the scenario passes with it unset. It proves
    the walk on one bundle, nothing about a seat the directory doesn't name. The
    second assertion also passes on edge v44.0.0, so it is a floor, not a witness."""
    step = Steps("""
TWO SEATS — two seats on one bundle, a person behind each.
  proves: (1) a row a person published at seat 1 reaches seat 2 by the commons walk;
          (2) a person at seat 2 who never asked is not handed it.""")
    c, _, _ = mint_accord_root(mesh, args, step, second_seat=True)
    seat2 = mesh.nodes["seat2"]
    c.peer_with(seat2)
    seat2.peer_with(c)
    step("seats_peered")
    a = mesh.add("alice")
    a.claim("alice-person")
    a.announce()
    a.self_record()
    a.peer_with(c)
    c.peer_with(a)
    b = mesh.add("bob", canonical=False, dial=[seat2])
    b.claim("bob-person")
    b.announce()
    b.self_record()
    b.peer_with(seat2)
    seat2.peer_with(b)
    step("people_up", alice_owner=a.owner_key_id, bob_owner=b.owner_key_id)
    # A key, an owner-binding and an acceptance are the announced set everyone may
    # hold. A consent row is commons between seats and appropriate to no stranger.
    def holds_consent(n: Node) -> bool:
        return _held_rows(n, a.owner_key_id, "consent:replication:v1") > 0

    try:
        wait_for("seat 2 to hold alice's consent row", lambda: holds_consent(seat2),
                 args.owner_wait, every=2)
    except MeshError:
        step.fail("commons_walk_stopped", "seats do not walk the commons between themselves",
                  [c, seat2], r"recognised|seat|withheld")
        return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
    step("commons_crossed_seats")
    time.sleep(90)
    unasked = holds_consent(b)
    step("person_left_alone", bob_holds_alice_consent=unasked)
    if unasked:
        step.fail("person_handed_the_commons", "a seat offered a person's node a row that is "
                  "neither required nor appropriate", [seat2, b], r"SEND SET|offered")
        return {"verdict": "FAIL", "steps": step.log, "first_failure": step.first_failure}
    return {"verdict": "PASS", "steps": step.log}


def mint_accord_mesh(mesh: Mesh, args: Any, step: "Steps"):
    """The root plus two people (alice, bob) claimed, announced and peered —
    the FINAL_GENESIS scenario's layers 1-3 and the halt scenario's fixture."""
    c, anchor, done = mint_accord_root(mesh, args, step)
    a = mesh.add("alice")
    b = mesh.add("bob")
    a.claim("alice-person")
    b.claim("bob-person")
    for n in (a, b):
        n.announce()
        n.self_record()
        n.peer_with(c)
        c.peer_with(n)
    a.peer_with(b)
    b.peer_with(a)
    step("people_booted_claimed_peered")
    return c, a, b, anchor, done


def final_genesis(mesh: Mesh, args: Any) -> Record:
    """Mint the root through the ceremony ROUTES with three software holders,
    then boot a fleet on that bundle as its baked genesis — production
    admission, no locally minted trust rows anywhere."""
    step = Steps("""
FINAL GENESIS — the 0.5.220 ceremony, minted and then booted on (FSD/FINAL_GENESIS.md §3).
  trust root: a THREE-holder test anchor (persist's software ceremony holders); every node runs
              CIRIS_TEST_NO_CEREMONY=true, so it holds only what it was SEEDED or SENT.
  mint:       on the canonical's own loopback routes — plan (serve node = the canonical's real
              key), each holder signs twice, finish → ONE v3 bundle.
  boot:       canonical + two person nodes restart/boot with that bundle installed as the baked
              genesis (CIRIS_TEST_GENESIS_BUNDLE), peer over the production routes.
  proves:     the bundle verifies at boot on every node, the root is valid, ciris-canonical is in
              force with the canonical seated, and the people's nodes are Rooted with it.""")
    if os.environ.get("FINAL_GENESIS_BASELINE") == "1":
        return _owned_canonical_baseline(mesh, args, step)
    c, a, b, anchor, done = mint_accord_mesh(mesh, args, step)

    # 4. What every node now holds.
    verdict: Record = {}
    for n in (c, a, b):
        roots = n.trust_roots()
        verdict[n.name] = roots
        step(f"trust_roots:{n.name}", roots=roots)
    # The verdict rests on what the GENESIS decides: every node holds the
    # minted root as valid, and two people root through it (the chat ladder's
    # pair). Person <-> OWNED canonical is reported, not judged: it converges
    # unevenly on the old blessed root too (FINAL_GENESIS_BASELINE=1), so a red
    # there is not evidence against the bundle (Codex on #726).
    ok = True
    for n in (c, a, b):
        roots = (verdict.get(n.name) or {}).get("roots") or []
        if not any((r.get("verdict") or {}).get("valid") for r in roots):
            ok = False
            step.fail(f"root_NOT_valid:{n.name}", "the minted root is not valid on this node",
                      [n], r"trust root|genesis|bundle|charter")
    try:
        wait_for("alice and bob Rooted with each other",
                 lambda: a.rooted_with(b) and b.rooted_with(a), args.rooted_wait or 120, every=3)
        step("rooted:alice<->bob", proves="two people root through the minted bundle")
    except MeshError:
        ok = False
        step.fail("NOT_rooted:alice<->bob", "two people find no valid root in common on the minted bundle",
                  [a, b], r"rooted_with|NO TRUST ROOT")
    diagnostic: Record = {}
    for n in (a, b):
        try:
            wait_for(f"{n.name} and the canonical Rooted", lambda: n.rooted_with(c) and c.rooted_with(n),
                     60, every=3)
            diagnostic[f"{n.name}<->canonical"] = "rooted"
        except MeshError:
            diagnostic[f"{n.name}<->canonical"] = {"person_sees": n.rooted_with(c),
                                                   "canonical_sees": c.rooted_with(n)}
    step("diagnostic:person<->owned_canonical", pairs=diagnostic)
    # FSD/FINAL_GENESIS.md §3's dry run also names two checks this scenario
    # does NOT run; said in the report so a PASS is never read as covering
    # them (Codex on #726).
    not_covered = [
        "a real YubiKey signing the serve record (hardware; software holders here)",
        "a node more than 300 s behind the ceremony refusing the bundle and keeping its old root",
    ]
    step("not_covered", checks=not_covered)
    return {"verdict": "PASS" if ok else "FAIL", "steps": step.log,
            "bundle_sha256": done.get("bundle_sha256"), "trust_roots": verdict,
            "owned_canonical_pairs": diagnostic, "not_covered": not_covered,
            "first_failure": step.first_failure}




# ── CSD-129: drill, halt, announce — end to end (federation → safety, T8) ───


def _inv(kind: str, inv_id: str, payload: bytes, **binding: str) -> Record:
    """An `accord:invoke` / `accord:lifecycle` row in the shape the server
    deserializes (verify 20.1 `Invocation`): a holder-minted nonce, a short
    validity, the payload digest, and the ONE binding line a lifecycle kind
    carries (`resumes_halt_id` / `confirms_halt_id`)."""
    import base64
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    row: Record = {
        "invocation_kind": kind,
        "invocation_id": inv_id,
        "nonce": base64.b64encode(os.urandom(32)).decode(),
        "asserted_at": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "valid_until": (now + dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }
    row.update(binding)
    return row


def halt(mesh: Mesh, args: Any) -> Record:
    """CSD-129 — the kill switch end to end on the T8 topology (CC 4.2.1.1 /
    4.2.1.3 as amended by CIRISConstitution#146, rc7)."""
    fuse = int(os.environ.get("CIRIS_TEST_HALT_FUSE_SECS", "20"))
    step = Steps(f"""
CSD-129 — DRILL, HALT, ANNOUNCE: END TO END (federation → safety, topology T8).
  root:     the ceremony-minted humanity accord, three software holders, quorum 2/3;
            charter fuse overridden to {fuse} s (CIRIS_TEST_HALT_FUSE_SECS, test anchor only).
  nodes:    the canonical (serve) + alice + bob, claimed, announced, peered, Rooted.
  steps:    drill (one holder) → announce (one holder) → FIRE (one holder) → every node
            latched, still serving, ingest still admits → CONFIRM (majority, within the fuse)
            → RESUME (majority, resumes_halt_id) → a second FIRE lapses after the fuse and a
            late confirmation confirms nothing.
  asserts:  CC 4.2.1.1 one-row fire / idempotent latch / agent pause with zero data
            disruption / the fuse; CC 4.2.1.3 confirmed + active at a strict majority;
            4.2.1.2 a drill never halts; NO data door reads the latch (0.5.226, CC re-pin
            17): the ingest door admits while the latch stands, so a refused act's
            ACTION_RESULT can reach the record.""")
    mesh.base_env["CIRIS_TEST_HALT_FUSE_SECS"] = str(fuse)
    c, a, b, anchor, _done = mint_accord_mesh(mesh, args, step)
    holders = anchor["holders"]
    nodes = [c, a, b]
    ok = True

    def status(n: Node) -> Record:
        return n.must("GET", "/v1/accord/halt-status")

    def latched_everywhere(expect: bool) -> bool:
        return all(bool(status(n)["halted"]) is expect for n in nodes)

    def sign(h: Record) -> Record:
        return {"key_id": h["key_id"], "test_holder_seed_b64": h["seed_b64"]}

    def deliver_everywhere(obj: Record, skip: Node) -> Dict[str, Record]:
        """Publication rides any channel (CC 4.2.1.1): the row is also handed to
        every node directly, out of band, beside the peer fan-out."""
        return {n.name: n.must("POST", "/v1/accord/message", obj) for n in nodes if n is not skip}

    for n in nodes:
        if status(n)["halted"] is not False:
            ok = False
            step.fail(f"baseline_halted:{n.name}", "a fresh node reads halted before any row", [n], r"HALT")
    step("baseline", proves="no node is halted", nodes=[n.name for n in nodes])

    # 1. DRILL — one holder rehearses the fire path; nothing latches (4.2.1.2).
    drill = _inv("drill", "csd129-drill", b"csd129 drill")
    r = c.must("POST", "/v1/accord/drill", {"invocation": drill, **sign(holders[0])})
    deliver_everywhere(r.get("invocation") or r, c)
    events = c.must("GET", "/v1/accord/events")
    drilled = any(e.get("invocation_id") == "csd129-drill" for e in events.get("drills", []))
    if not (r.get("quorum_met") is True and drilled and latched_everywhere(False)):
        ok = False
        step.fail("drill", "a one-holder drill must complete, surface, and halt nobody", [c], r"DRILL|drill",
                  cc="CC 4.2.1.2", got=r)
    step("drill", proves="one holder completes a drill; it is surfaced; no latch anywhere", quorum_met=r.get("quorum_met"))

    # 2. ANNOUNCE — one holder's notify, visibly distinct from a halt.
    msg = "CSD-129 drill of the accord notify channel"
    notify = _inv("notify", "csd129-notify", msg.encode())
    r = c.must("POST", "/v1/accord/announce", {"invocation": notify, "message": msg, **sign(holders[1])})
    events = c.must("GET", "/v1/accord/events")
    announced = any(e.get("invocation_id") == "csd129-notify" for e in events.get("announcements", []))
    if not (announced and latched_everywhere(False)):
        ok = False
        step.fail("announce", "a one-holder notify must surface as an announcement and halt nobody", [c], r"ANNOUNCE|notify", cc="CC 4.2.1.2")
    step("announce", proves="a notify is an announcement, never a halt")

    # 3. FIRE — one holder, from alice (its peer fan-out reaches the canonical),
    #    then handed to bob out of band.
    fire = _inv("constitutional", "csd129-halt-1", b"csd129 halt 1")
    r = a.must("POST", "/v1/accord/halt", {"invocation": fire, **sign(holders[0])})
    obj = r.get("invocation") or r
    delivered = deliver_everywhere(obj, a)
    # The open door answers the signed object + quorum_met; whether the node
    # LATCHED is read where the agent gate reads it: /v1/accord/halt-status.
    if r.get("quorum_met") is not True or not latched_everywhere(True):
        ok = False
        step.fail("fire", "ONE holder's constitutional row must latch on every node that holds the root",
                  nodes, r"HALT", cc="CC 4.2.1.1", quorum_met=r.get("quorum_met"), delivered=delivered)
    st = {n.name: status(n) for n in nodes}
    step("fire", proves="one row, fired on receipt, latched everywhere; each node counts its own fuse",
         lapses_at={k: v.get("halt", {}).get("lapses_at") for k, v in st.items()},
         received_at={k: v.get("halt", {}).get("received_at") for k, v in st.items()})

    # 3a. Zero data disruption: the node still serves.
    serving = {n.name: n.api("GET", "/health")[0] for n in nodes}
    if any(code != 200 for code in serving.values()):
        ok = False
        step.fail("serving_while_halted", "a halt pauses agents; the node must keep serving", nodes, r"halt", cc="CC 4.2.1.1", health=serving)
    step("serving_while_halted", proves="/health answers 200 on every halted node", health=serving)

    # 3b. Zero data disruption at the data doors: the ingest door is NOT a
    # reader of the latch (0.5.226). The latch's one reader is the agent's act
    # gate; the ACTION_RESULT of an act it refused must land through this door,
    # so a 423 here would make the pause erase its own evidence (CC 4.2.1.1).
    batch = json.dumps({"events": [{"trace": {"trace_id": "csd129-trace", "components": [
        {"event_type": "LLM_CALL", "data": {"model": "gpt-4o"}}]}}]}).encode()
    code, body = c.api("POST", "/v1/ingest/accord-events", json.loads(batch))
    if code == 423 or (body or {}).get("error") == "accord_halt_in_effect":
        ok = False
        step.fail("ingest_admits_while_halted", "a data door must not read the latch: the ingest door answered the halt refusal",
                  [c], r"halt gate|HTTP ingest REFUSED", cc="CC 4.2.1.1", got={"status": code, "body": body})
    step("ingest_admits_while_halted", proves="no data door reads the latch; the ingest door does its ordinary work under a halt", status=code)

    # 3c. Idempotent: the same row again changes nothing.
    again = c.must("POST", "/v1/accord/message", obj)
    step("replay", proves="a replayed halt re-latches idempotently", halted=again.get("halted"))

    # 4. CONFIRM — a strict majority (B+C) names the halt within the fuse.
    confirm = _inv("lifecycle:confirmed", "csd129-confirm-1", b"csd129 confirm", confirms_halt_id="csd129-halt-1")
    opened = c.must("POST", "/v1/accord/invocation", {"invocation": confirm, **sign(holders[1])})
    concurred = c.must("POST", "/v1/accord/invocation/concur",
                       {"invocation_kind": "lifecycle:confirmed", "invocation_id": "csd129-confirm-1", **sign(holders[2])})
    cobj = concurred.get("invocation") or concurred
    delivered = deliver_everywhere(cobj, c)
    st = {n.name: status(n) for n in nodes}
    confirmed = all(v.get("halted") is True and v.get("halt", {}).get("lapses_at") is None for v in st.values())
    if opened.get("quorum_met") is not False or not confirmed:
        ok = False
        step.fail("confirm", "one signature must not confirm; a strict majority within the fuse must, everywhere",
                  nodes, r"CONFIRMED|confirm", cc="CC 4.2.1.3", opened=opened.get("quorum_met"), delivered=delivered)
    step("confirm", proves="a lone signature confirms nothing; the majority keeps the halt past its fuse")

    # 5. RESUME — a strict majority naming THIS halt ends it, everywhere.
    wrong = _inv("lifecycle:active", "csd129-resume-wrong", b"csd129 resume", resumes_halt_id="csd129-other")
    c.must("POST", "/v1/accord/invocation", {"invocation": wrong, **sign(holders[1])})
    w = c.must("POST", "/v1/accord/invocation/concur",
               {"invocation_kind": "lifecycle:active", "invocation_id": "csd129-resume-wrong", **sign(holders[2])})
    if status(c)["halted"] is not True:
        ok = False
        step.fail("resume_wrong_halt", "a resumption naming another halt must release nothing", [c], r"RELEASED", cc="CC 4.2.1.3", got=w)
    step("resume_wrong_halt", proves="resumes_halt_id binds the resumption to one halt")
    resume = _inv("lifecycle:active", "csd129-resume-1", b"csd129 resume", resumes_halt_id="csd129-halt-1")
    c.must("POST", "/v1/accord/invocation", {"invocation": resume, **sign(holders[1])})
    r = c.must("POST", "/v1/accord/invocation/concur",
               {"invocation_kind": "lifecycle:active", "invocation_id": "csd129-resume-1", **sign(holders[2])})
    deliver_everywhere(r.get("invocation") or r, c)
    if not latched_everywhere(False):
        ok = False
        step.fail("resume", "a strict majority naming the halt must end it on every node", nodes, r"RELEASED", cc="CC 4.2.1.3")
    code, body = c.api("POST", "/v1/ingest/accord-events", json.loads(batch))
    step("resume", proves="the latch is gone everywhere and the ingest door opens again", ingest_status=code)

    # 6. THE FUSE — a lone halt lapses `fuse` seconds after each node received it.
    fire2 = _inv("constitutional", "csd129-halt-2", b"csd129 halt 2")
    r = b.must("POST", "/v1/accord/halt", {"invocation": fire2, **sign(holders[2])})
    deliver_everywhere(r.get("invocation") or r, b)
    if not latched_everywhere(True):
        ok = False
        step.fail("fire2", "the second halt must latch everywhere", nodes, r"HALT", cc="CC 4.2.1.1")
    try:
        wait_for("the lone halt to lapse everywhere", lambda: latched_everywhere(False), fuse + 15, every=1.0)
        step("fuse_lapsed", proves=f"an unconfirmed halt lapses {fuse} s after receipt, on each node's own clock",
             lapsed={n.name: status(n).get("lapsed") for n in nodes})
    except MeshError:
        ok = False
        step.fail("fuse_lapsed", "an unconfirmed halt must lapse after the fuse", nodes, r"LAPSED|lapse", cc="CC 4.2.1.1 the fuse")
    late = _inv("lifecycle:confirmed", "csd129-confirm-late", b"csd129 confirm late", confirms_halt_id="csd129-halt-2")
    c.must("POST", "/v1/accord/invocation", {"invocation": late, **sign(holders[1])})
    r = c.must("POST", "/v1/accord/invocation/concur",
               {"invocation_kind": "lifecycle:confirmed", "invocation_id": "csd129-confirm-late", **sign(holders[2])})
    if status(c)["halted"] is not False:
        ok = False
        step.fail("late_confirm", "a confirmation after the fuse confirms nothing", [c], r"halt_fuse_lapsed", cc="CC 4.2.1.3", got=r)
    step("late_confirm", proves="a confirmation after the fuse confirms nothing; a fresh halt is fired instead")

    not_covered = [
        "an agent process on a node whose act gate reads /v1/accord/halt-status (CIRISAgent#1231 / PR #1262: ActionDispatcher._refuse_under_accord_halt emits the terminal ACTION_RESULT this door must now admit)",
        "rows.jsonl per node for CC's offline replay (T8 iii) and roster_fold_digest (T8 vii)",
        "a real YubiKey holder (software holders here)",
    ]
    step("not_covered", checks=not_covered)
    return {"verdict": "PASS" if ok else "FAIL", "steps": step.log, "fuse_secs": fuse,
            "not_covered": not_covered, "first_failure": step.first_failure}


def halt_agent(mesh: Mesh, args: Any) -> Record:
    """CSD-129, the AGENT step — what `halt` lists under `not_covered`: an agent
    process whose act gate reads `/v1/accord/halt-status` on its OWN node fold,
    that node booted inside this T8 mesh, a holder's halt latched on it, one act
    refused, and the refused act's terminal ACTION_RESULT admitted by the data
    doors and held by the canonical (CC 4.2.1.1: "a refused act's terminal
    ACTION_RESULT must reach the record, or the pause erases its own evidence").

    Two processes meet through files under `--work` (the agent is another
    repo's process — CIRISAgent#1231 / PR #1262 — launched by its own runner):

      agent_handoff.json  (written here)  the env the agent's node must boot
                                          under, the canonical's url/record, the
                                          software holders, and these file names
      agent_ready.json    (agent writes)  {"agent_id_hash": …, "token": optional
                                          owner bearer of the agent's node}
      halt_fired.json     (written here)  {"invocation_id": …} once the agent's
                                          node reads halted:true and the halt is
                                          CONFIRMED (so it outlives the fuse)
      agent_acted.json    (agent writes)  {"status": 423, "trace_id": <the
                                          terminal ACTION_RESULT's trace>,
                                          "agent_id_hash": …}
      done.json           (written here)  after the resume

    The agent's node is reached at `--agent-url` (its fold, 127.0.0.1:4243 by
    default — the harness never binds that port itself)."""
    # A longer fuse than `halt`'s 20 s: the agent's refusal happens on its next
    # dispatcher step after the latch, and the confirm below is what keeps the
    # halt standing while the runner interacts and the trace replicates.
    fuse = int(os.environ.get("CIRIS_TEST_HALT_FUSE_SECS", "120"))
    agent_url = str(getattr(args, "agent_url", "http://127.0.0.1:4243")).rstrip("/")
    agent_wait = float(getattr(args, "agent_wait", 1800))
    step = Steps(f"""
CSD-129 — THE AGENT STEP (CC 4.2.1.1 one reader; CC 1.13.6 totality), topology T8 + one
  agent-hosted node.
  root:     the ceremony-minted humanity accord, three software holders, quorum 2/3;
            fuse {fuse} s (CIRIS_TEST_HALT_FUSE_SECS); the halt is CONFIRMED so it stands
            while the agent acts.
  nodes:    the canonical (serve) + alice + bob (this harness) + the AGENT's node fold at
            {agent_url} (the agent's own process, booted on agent_handoff.json's env).
  steps:    mesh up → handoff → agent node up, claimed → peered with the canonical →
            FIRE + CONFIRM → agent's act REFUSED (423, terminal ACTION_RESULT) → that
            trace HELD by the canonical (receipt + row) while the latch still stands →
            RESUME → agent node reads halted:false.
  asserts:  the latch has ONE reader (the agent's act gate); every data door between the
            refused act and the canonical did its ordinary work under the halt.""")
    mesh.base_env["CIRIS_TEST_HALT_FUSE_SECS"] = str(fuse)
    c, a, b, anchor, _done = mint_accord_mesh(mesh, args, step)
    holders = anchor["holders"]
    ok = True
    from .mesh import http  # the agent's node is driven without a bearer

    def sign(h: Record) -> Record:
        return {"key_id": h["key_id"], "test_holder_seed_b64": h["seed_b64"]}

    def status_of(url: str) -> Record:
        code, body = http("GET", f"{url}/v1/accord/halt-status")
        if code != 200 or not isinstance(body, dict):
            raise MeshError(f"halt-status at {url} answered {code}: {str(body)[:200]}")
        return body

    files = {k: str(mesh.work / f"{k}.json") for k in ("agent_handoff", "agent_ready", "halt_fired", "agent_acted", "done")}
    for k in ("agent_ready", "halt_fired", "agent_acted", "done"):
        Path(files[k]).unlink(missing_ok=True)

    # 0. HANDOFF — everything the agent's node needs to boot INSIDE this mesh.
    env = {k: v for k, v in mesh.base_env.items() if k.startswith("CIRIS_")}
    env.update({"CIRIS_TEST_BLESS_CANONICAL": "false", "CIRIS_TEST_CANONICAL_DIAL": c.transport,
                "CIRIS_DEVICE_CLASS": "laptop", "CIRIS_TEST_HALT_FUSE_SECS": str(fuse)})
    handoff = {"env": env, "agent_url": agent_url,
               "canonical": {"url": c.url, "transport": c.transport, "node_key_id": c.node_key_id,
                             "record": c.record, "owner_key_id": c.owner_key_id},
               "people": {n.name: {"url": n.url, "node_key_id": n.node_key_id} for n in (a, b)},
               "holders": holders, "fuse_secs": fuse, "files": files,
               "protocol": ["boot the agent with env exported and a FRESH CIRIS_HOME; the node MUST BE OWNED before agent_ready (claim via POST /v1/setup/root or the PIN flow) — an unowned node refuses federation peering and ships no trace to a canonical; then announce",
                            "OPTIONAL, before the message: write agent_up.json {node_home: <the embedded node's home dir, where it wrote claim_pin>} and wait for agent_claimed.json — the harness claims + announces your node for you",
                            "submit one real-LLM message; when its round has STARTED (an act is in flight), write agent_ready.json {agent_id_hash, token?} — the halt lands on your node within seconds",
                            "wait for halt_fired.json (written the instant your node reads halted:true), then POST /v1/agent/interact once (expect 423)",
                            "write agent_acted.json {status, trace_id: the trace carrying the in-flight act's refusal ACTION_RESULT, agent_id_hash}",
                            "wait for done.json"]}
    Path(files["agent_handoff"]).write_text(json.dumps(handoff, indent=1, default=str), encoding="utf-8")
    step("handoff", path=files["agent_handoff"], agent_url=agent_url, canonical=c.transport)
    print(f"handoff written: {files['agent_handoff']}  (waiting up to {agent_wait:.0f} s for the agent's node at {agent_url})", flush=True)

    # 1. THE AGENT'S NODE — up, identified, then its runner says it is claimed.
    def agent_record() -> Optional[Record]:
        code, body = http("GET", f"{agent_url}/v1/federation/self-key-record")
        return body if code == 200 and isinstance(body, dict) and body.get("record") else None
    rec = wait_for("the agent's node fold to answer its self-key-record", agent_record, agent_wait, every=3.0)
    agent = Node(name="agent", binary=mesh.binary, home=mesh.work / "agent", key_id=rec["record"]["key_id"],
                 port=int(agent_url.rsplit(":", 1)[1]) - 1, env={}, log_path=mesh.work / "agent" / "unused.log")
    agent.record, agent.node_key_id = rec, rec["record"]["key_id"]
    mesh.nodes["agent"] = agent
    step("agent_node_up", node_key_id=agent.node_key_id)

    # 1b. OWNED — an unowned node refuses federation peering and ships nothing to
    #     a canonical (CC 3.2 / 1.13.5). The runner's API setup path leaves the
    #     node unowned, so when it writes agent_up.json {"node_home": <the
    #     embedded node's home>} BEFORE submitting its message, this harness
    #     claims the node the way the ladders do (owner identity minted here,
    #     `claim` over the console PIN the node wrote under its home), announces
    #     it, and answers with agent_claimed.json {owner_key_id, token}. A runner
    #     that claimed by itself skips straight to agent_ready.json.
    up_path, claimed_path = mesh.work / "agent_up.json", mesh.work / "agent_claimed.json"
    claimed: Any = "runner_did_not_ask"
    first = wait_for("agent_up.json (to claim) or agent_ready.json (already owned)",
                     lambda: "up" if up_path.is_file() else ("ready" if Path(files["agent_ready"]).is_file() else None),
                     agent_wait, every=1.0)
    if first == "up":
        up = json.loads(up_path.read_text())
        agent.home = Path(str(up.get("node_home") or ""))
        agent.env = dict(env)
        try:
            agent.claim("agent-person", pin_timeout=30.0)
            agent.announce()
            agent.self_record()
            claimed = {"owner_key_id": agent.owner_key_id, "announced": True}
            claimed_path.write_text(json.dumps({"owner_key_id": agent.owner_key_id, "token": agent.token}), encoding="utf-8")
        except MeshError as e:
            ok = False
            claimed = {"error": str(e)[:600]}
            claimed_path.write_text(json.dumps({"error": str(e)[:600]}), encoding="utf-8")
            step.fail("agent_claimed", "the harness could not claim the agent's node over its console PIN", [c], r"claim", node_home=str(agent.home), got=str(e)[:400])
    step("agent_claimed", proves="the agent's node has a responsible party and is announced", claimed=claimed)

    # 2. PEERED — production peering from the canonical's side, as soon as the
    #    agent's node answers (its own side is the node's prime to
    #    CIRIS_TEST_CANONICAL_DIAL; no owner claim is required of it). Rooted
    #    is OBSERVED, never waited on past the runner's ready signal: the
    #    runner writes agent_ready.json when an act is IN FLIGHT, and the halt
    #    must land before that act completes.
    c.peer_with(agent)
    ready_path = Path(files["agent_ready"])
    rooted: Optional[bool] = None
    t0 = time.time()
    while time.time() - t0 < 120 and not ready_path.is_file():
        rooted = c.rooted_with(agent)
        if rooted:
            break
        time.sleep(2.0)
    step("agent_peered", proves="the agent's node is a production peer of the canonical", rooted=rooted)
    ready = wait_for("agent_ready.json (the runner has an act in flight)",
                     lambda: json.loads(ready_path.read_text()) if ready_path.is_file() else None, agent_wait, every=0.5)
    agent.token = agent.token or str(ready.get("token") or "")
    # Best-effort from the agent's side: an UNOWNED node refuses federation
    # peering (CC 3.2 / 1.13.5 — "claim ownership first via POST /v1/setup/root")
    # and ships nothing to a canonical; record the answer, let step 5 be the judge.
    peered_back: Any = "not_attempted"
    if agent.token:
        if c.record is None:
            c.self_record()
        peered_back = agent.api("POST", "/v1/federation/peering", {
            "peer_key_id": c.record["record"]["key_id"], "peer_key_record": c.record,
            "attestation_prefixes": ["capacity:", "chat:", "file:", "ownership:", "self:delegates_to:", "trace:"]})
    ready_at = time.time()
    step("agent_ready", agent_id_hash=ready.get("agent_id_hash"), has_owner_token=bool(agent.token), peered_back=peered_back)

    # 3. FIRE — one holder, from alice; the row goes to the agent's node FIRST,
    #    out of band, then to the rest of the mesh. halt_fired.json is written
    #    the instant the agent's node reads halted:true (the runner's act is in
    #    flight); the CONFIRM follows so the halt outlives the fuse.
    if status_of(agent_url)["halted"] is not False:
        ok = False
        step.fail("agent_baseline", "the agent's node reads halted before any row", [c], r"HALT")
    inv_id = "csd129-agent-halt-1"
    fire = _inv("constitutional", inv_id, b"csd129 agent halt 1")
    r = a.must("POST", "/v1/accord/halt", {"invocation": fire, **sign(holders[0])})
    obj = r.get("invocation") or r
    delivered: Dict[str, Any] = {"agent": http("POST", f"{agent_url}/v1/accord/message", body=obj)}
    try:
        wait_for("the agent's node to latch", lambda: True if status_of(agent_url)["halted"] is True else None, 30, every=0.25)
    except MeshError:
        ok = False
        step.fail("fire", "ONE holder's constitutional row must latch on the agent's node", [c, a], r"HALT", cc="CC 4.2.1.1", delivered=delivered)
    st = status_of(agent_url)
    Path(files["halt_fired"]).write_text(json.dumps({"invocation_id": inv_id, "halt": st.get("halt"), "fired_at": time.time()}), encoding="utf-8")
    latched_after = round(time.time() - ready_at, 2)
    step("fire", proves="one row, fired on receipt, latched on the agent's node while its act is in flight",
         seconds_after_ready=latched_after, halt=st.get("halt"))
    print(f"halt latched on {agent_url} {latched_after}s after agent_ready: {files['halt_fired']}", flush=True)
    for n in (c, b):
        delivered[n.name] = n.must("POST", "/v1/accord/message", obj)
    confirm = _inv("lifecycle:confirmed", "csd129-agent-confirm-1", b"csd129 agent confirm", confirms_halt_id=inv_id)
    c.must("POST", "/v1/accord/invocation", {"invocation": confirm, **sign(holders[1])})
    concurred = c.must("POST", "/v1/accord/invocation/concur",
                       {"invocation_kind": "lifecycle:confirmed", "invocation_id": "csd129-agent-confirm-1", **sign(holders[2])})
    cobj = concurred.get("invocation") or concurred
    http("POST", f"{agent_url}/v1/accord/message", body=cobj)
    for n in (a, b):
        n.must("POST", "/v1/accord/message", cobj)
    try:
        wait_for("the agent's node to read the halt as confirmed",
                 # `confirmed` is the confirming row {invocation_id, received_at, signers}, null until a majority lands.
                 lambda: True if (status_of(agent_url).get("halt") or {}).get("confirmed") else None, 30, every=1.0)
    except MeshError:
        ok = False
        step.fail("confirm", "a strict majority must confirm the halt on the agent's node within the fuse", [c], r"CONFIRMED|confirm", cc="CC 4.2.1.3")
    step("confirm", proves="the halt stands on the agent's node, confirmed, past any fuse", halt=status_of(agent_url).get("halt"))
    print(f"halt confirmed (waiting up to {agent_wait:.0f} s for agent_acted.json)", flush=True)

    # 4. THE REFUSED ACT — the agent's runner acts once and reports.
    acted = wait_for("agent_acted.json", lambda: json.loads(Path(files["agent_acted"]).read_text()) if Path(files["agent_acted"]).is_file() else None,
                     agent_wait, every=2.0)
    still = status_of(agent_url)
    if int(acted.get("status") or 0) != 423 or still.get("halted") is not True:
        ok = False
        step.fail("act_refused", "the act gate must refuse (423) while the latch stands on its node", [c], r"accord_halt_in_effect",
                  cc="CC 4.2.1.1 / CIRISAgent#1231", got=acted, latch=still.get("halted"))
    step("act_refused", proves="the ONE reader of the latch, the agent's act gate, refused the act", status=acted.get("status"),
         trace_id=acted.get("trace_id"), latch_stood=still.get("halted"))

    # 5. THE RECORD — the refused act's terminal ACTION_RESULT crossed every data
    #    door under the halt: the canonical HOLDS that trace (its signed receipt,
    #    and the row itself), asked while the latch still stands.
    trace_id, hash_ = str(acted.get("trace_id") or ""), str(acted.get("agent_id_hash") or ready.get("agent_id_hash") or "")
    def receipt() -> Optional[Record]:
        code, body = http("GET", f"{c.url}/v1/traces/receipt?agent_id_hash={hash_}&trace_id={trace_id}&nonce=csd129")
        if code != 200 or not isinstance(body, dict):
            return None
        data = body.get("data") if isinstance(body.get("data"), dict) else body
        return body if data.get("holds_trace") is True else None
    held: Any = None
    try:
        held = wait_for("the canonical to hold the refused act's trace", receipt, float(getattr(args, "arrive_wait", 180)), every=3.0)
    except MeshError:
        held = None
    rows = c.rows("SELECT count(*) FROM trace_events WHERE trace_id = ?", (trace_id,))
    row_count = sum(int(r[0]) for r in rows) if rows else 0
    if not trace_id or held is None or row_count < 1:
        ok = False
        step.fail("record_holds_refusal", "the refused act's terminal ACTION_RESULT must reach the record while the halt stands",
                  [c, agent], r"ingest|replicat|refus", cc="CC 4.2.1.1", trace_id=trace_id, agent_id_hash=hash_, rows=row_count,
                  latch_on_canonical=status_of(c.url).get("halted"))
    step("record_holds_refusal", proves="no data door read the latch: the terminal ACTION_RESULT of a refused act is held by the canonical under the halt",
         trace_id=trace_id, canonical_rows=row_count, receipt=(held or {}).get("data", held),
         latch_on_canonical=status_of(c.url).get("halted"), latch_on_agent=status_of(agent_url).get("halted"))

    # 6. RESUME — a strict majority naming THIS halt ends it, on the agent's node too.
    resume = _inv("lifecycle:active", "csd129-agent-resume-1", b"csd129 agent resume", resumes_halt_id=inv_id)
    c.must("POST", "/v1/accord/invocation", {"invocation": resume, **sign(holders[1])})
    r = c.must("POST", "/v1/accord/invocation/concur",
               {"invocation_kind": "lifecycle:active", "invocation_id": "csd129-agent-resume-1", **sign(holders[2])})
    robj = r.get("invocation") or r
    for n in (a, b):
        n.must("POST", "/v1/accord/message", robj)
    http("POST", f"{agent_url}/v1/accord/message", body=robj)
    try:
        wait_for("the agent's node to release", lambda: True if status_of(agent_url)["halted"] is False else None, 30, every=1.0)
    except MeshError:
        ok = False
        step.fail("resume", "a strict majority naming the halt must end it on the agent's node", [c], r"RELEASED", cc="CC 4.2.1.3")
    Path(files["done"]).write_text(json.dumps({"verdict": "PASS" if ok else "FAIL", "resumed_at": time.time()}), encoding="utf-8")
    step("resume", proves="the latch is gone on the agent's node; the agent may act again")

    not_covered = [
        "rows.jsonl per node for CC's offline replay (T8 iii) and roster_fold_digest (T8 vii)",
        "a real YubiKey holder (software holders here)",
    ]
    step("not_covered", checks=not_covered)
    return {"verdict": "PASS" if ok else "FAIL", "steps": step.log, "fuse_secs": fuse, "agent_url": agent_url,
            "agent": {"node_key_id": agent.node_key_id, "agent_id_hash": hash_, "trace_id": trace_id},
            "not_covered": not_covered, "first_failure": step.first_failure}


def add_device(mesh: Mesh, args: Any) -> Record:
    """CIRISServer#177 (FSD/ADD_DEVICE.md, formal/add_device) on the real wire:
    a fresh, UNOWNED node B asks its person's existing node A to add it, peer to
    peer on edge's first-contact plane (device-join kind 0x0000_0002); the owner
    consents on A; B ends owned by the same identity with its OWN occurrence
    keys, and a self file written on A before the join opens on B."""
    step = Steps("""
ADD A DEVICE — a new device joins its owner's identity as a new occurrence (CIRISServer#177).
  nodes:  the canonical; A (alice: claimed, announced, joined); B (fresh, UNOWNED); C (fresh,
          UNOWNED — a stranger who also asks).
  proves: (1) a request while A's window is closed is refused, not queued (N2);
          (2) B's request is held with a matching code A derived; C's code differs (N1);
          (3) the owner approves B: owner-binding + B's occurrence signed by the owner (N4);
          (4) B applies it with its own claim PIN and collects its session locally;
          (5) B's occurrence is active under the owner's identity on A AND on B;
          (6) a self file written on A BEFORE the join opens on B (the self DEK re-wrap);
          (7) the owner denies C; C reads denied; A's pending set is empty again (N3).""")
    ok = True
    # The production shape: the root is a ceremony-minted genesis bundle every node
    # boots on, and no node is self-blessed (CIRIS_TEST_NO_CEREMONY) — so a fresh,
    # unowned device's key record stays SELF-SIGNED, which edge's first contact
    # requires, and it holds the root it will be Rooted under once owned.
    cnl, _anchor, _done = mint_accord_root(mesh, args, step)
    a = mesh.add("alice")
    a.claim("alice-person")
    a.announce()
    a.self_record()
    a.peer_with(cnl)
    cnl.peer_with(a)
    b = mesh.add("newdev")
    c = mesh.add("stranger")
    d = mesh.add("changer")   # withdraws before approval (8)
    e = mesh.add("regret")    # withdraws after approval (9)
    f = mesh.add("barefedid") # holds only a fedID, never a code (8b)
    b_pin = (b.home / "claim_pin").read_text().strip()
    b.self_record()
    c.self_record()
    d.self_record()
    e.self_record()
    f.self_record()
    step("booted", alice_owner=a.owner_key_id, b_node=b.node_key_id, c_node=c.node_key_id)

    # A self file on A before anything joins.
    secret = os.urandom(64)
    written = a.write_file(secret, "application/octet-stream", "before-join.bin")
    file_id = written.get("attestation_id") or written.get("id")
    step("self_file_on_A", attestation_id=file_id)

    code_link = a.contact_code()
    # (1) window closed → refused, not queued.
    # Retry past "not reachable yet" to a DEFINITIVE answer: 502 (no route, the
    # pre-seal shape) and 503 add_device.owner_route_pending (edge v43: the other
    # device's sealed route is still on its way through the canonical, answered
    # with Retry-After — a client retries it).
    closed: Any = None

    def closed_answer() -> Optional[Tuple[int, Any]]:
        nonlocal closed
        closed = c.api("POST", "/v1/setup/add-device", {"contact": code_link, "label": "stranger"})
        return closed if closed[0] not in (502, 503) else None
    try:
        code, body = wait_for("C to get a definitive answer while A's window is closed", closed_answer,
                              args.owner_wait, every=5)
    except MeshError:
        code, body = closed
    if code != 409 or (body or {}).get("reason_id") != "add_device.not_accepting":
        ok = False
        step.fail("closed_window", "a request while A's window is closed must be refused, not queued", [a, c],
                  r"device-join|add-device", got={"status": code, "body": body})
    step("closed_window_refused", status=code, reason_id=(body or {}).get("reason_id"))

    a.must("POST", "/v1/self/device-requests/open", {"seconds": 600})
    step("window_opened")

    # (2) B asks, then C asks.
    def ask(n: Node, label: str) -> Tuple[int, Any]:
        last: Any = None

        def once() -> Optional[Tuple[int, Any]]:
            nonlocal last
            last = n.api("POST", "/v1/setup/add-device", {"contact": code_link, "label": label})
            return last if last[0] == 202 else None
        try:
            return wait_for(f"{n.name} to reach A with its join request", once, args.owner_wait, every=5)
        except MeshError:
            return last
    b_code, b_body = ask(b, "new laptop")
    c_code, c_body = ask(c, "not yours")
    b_match, c_match = (b_body or {}).get("match_code"), (c_body or {}).get("match_code")
    if b_code != 202 or c_code != 202 or not b_match or b_match == c_match:
        ok = False
        step.fail("requests_held", "both requests must be held, each with its own A-derived code", [a, b, c],
                  r"device-join|add-device", b={"status": b_code, "body": b_body}, c={"status": c_code, "body": c_body})
    step("requests_held", b_match=b_match, c_match=c_match)
    listed = a.must("GET", "/v1/self/device-requests").get("requests", [])
    b_row = next((r for r in listed if r.get("node_key_id") == b.node_key_id), None)
    c_row = next((r for r in listed if r.get("node_key_id") == c.node_key_id), None)
    if not b_row or b_row.get("match_code") != b_match:
        ok = False
        step.fail("owner_sees_code", "A's owner must see B's request with the code B shows", [a], r"device-join",
                  listed=listed)
    step("owner_sees_codes", pending=len(listed), b_code_matches=bool(b_row and b_row.get("match_code") == b_match))

    # (2b) completing before the owner approves is refused — nothing to apply.
    early_code, early_body = b.api("POST", "/v1/setup/add-device/complete", {})
    if early_code != 409:
        ok = False
        step.fail("complete_before_approval", "completing before approval must be refused (409)", [b],
                  r"add-device", status=early_code, body=str(early_body)[:200])
    step("complete_before_approval_refused", status=early_code)

    # (3) the owner approves B — the request whose code matches the device in hand.
    approved = a.must("POST", f"/v1/self/device-requests/{b_row['request_id']}/approve")
    occ = approved.get("occurrence_key_id")
    step("approved", occurrence=occ, self_dek_granted=approved.get("self_dek_granted"))

    # (4) B VERIFIES the approval offline (against the owner's v3 code it carries
    # and the fedID the person entered) and HOLDS it — the claim is not applied
    # mid-wizard, so first-run timing matches the new-identity path.
    def b_state() -> Optional[Dict[str, Any]]:
        st = b.must("GET", "/v1/setup/add-device")
        return st if st.get("state") in ("approved", "applied", "failed", "denied", "expired") else None
    try:
        held = wait_for("B to verify and hold the owner's approval", b_state, args.arrive_wait, every=2)
    except MeshError:
        held = b.must("GET", "/v1/setup/add-device")
    owner_shown = held.get("owner_key_id")
    still_unclaimed = b.api("GET", "/v1/setup/status")[1]
    if held.get("state") != "approved" or owner_shown != a.owner_key_id:
        ok = False
        step.fail("approved_held", "B must verify the approval and hold it, naming the owner's fedID for the "
                  "wizard to show (never asking for it)", [a, b], r"add-device", state=held)
    step("b_verified_and_held", state=held.get("state"), owner_key_id=owner_shown,
         setup_status=str(still_unclaimed)[:200],
         proves="the owner's consent is validated offline before the claim; the fedID comes from the existing identity")

    # (5) the end of B's first-run wizard: apply the held claim.
    code_c, final = b.api("POST", "/v1/setup/add-device/complete", {})
    if code_c != 200 or (final or {}).get("state") != "applied":
        ok = False
        step.fail("applied", "completing first run must apply the held approval", [a, b],
                  r"add-device|setup/root|occurrence", status=code_c, state=final)
    step("b_applied", state=(final or {}).get("state"))
    code, sess = b.api("POST", "/v1/setup/claimed-session", {"claim_pin": b_pin})
    if code != 200 or not (sess or {}).get("access_token"):
        ok = False
        step.fail("session", "B's wizard must collect its owner session with its own PIN", [b], r"claimed-session|claim",
                  got={"status": code, "body": sess})
    else:
        b.token = sess["access_token"]
    step("b_session", status=code)

    # (5) B's occurrence is active under the owner's identity on A and on B.
    q = ("SELECT count(*) FROM federation_identity_occurrences WHERE identity_key_id = ? "
         "AND occurrence_key_id = ?")
    on_a = sum(int(r[0]) for r in a.rows(q, (a.owner_key_id, occ)))
    on_b = sum(int(r[0]) for r in b.rows(q, (a.owner_key_id, occ)))
    owner_b = b.rows("SELECT count(*) FROM federation_keys WHERE key_id = ?", (a.owner_key_id,))
    if not (on_a >= 1 and on_b >= 1):
        ok = False
        step.fail("occurrence", "B's occurrence must be active under the owner on both nodes", [a, b], r"occurrence",
                  on_a=on_a, on_b=on_b)
    step("occurrence_on_both", on_a=on_a, on_b=on_b, owner_key_on_b=sum(int(r[0]) for r in owner_b))

    # (6) the self file written on A before the join opens on B.
    def opened() -> Optional[bool]:
        code, raw = b.read_raw(file_id)
        return True if code == 200 and raw == secret else None
    try:
        wait_for("the pre-join self file to open on B", opened, args.arrive_wait, every=3)
        step("self_file_opens_on_B", proves="the self DEKs were re-wrapped to B and the file replicated")
    except MeshError:
        code, raw = b.read_raw(file_id)
        ok = False
        step.fail("self_file", "a self file written on A before the join must open on B", [a, b],
                  r"rewrap|re-wrap|self_dek|files|grant", status=code, body=str(raw)[:200])

    # (7) the owner denies C; C reads denied; A's pending set is empty.
    if c_row:
        a.must("POST", f"/v1/self/device-requests/{c_row['request_id']}/deny")
        try:
            got = wait_for("C to read denied", lambda: (lambda s: s if s.get("state") == "denied" else None)(
                c.must("GET", "/v1/setup/add-device")), 60, every=2)
        except MeshError:
            got = c.must("GET", "/v1/setup/add-device")
        left = a.must("GET", "/v1/self/device-requests").get("requests", [])
        if got.get("state") != "denied" or left:
            ok = False
            step.fail("deny", "a denied stranger reads denied and frees its slot", [a, c], r"device-join",
                      c_state=got, still_pending=left)
        step("stranger_denied", c_state=got.get("state"), pending_after=len(left))

    # (8) a device that changes its mind BEFORE approval: DELETE on the new
    # device drops the request from the owner's list (the Withdraw op).
    d_code, _ = ask(d, "changed my mind")
    in_list = lambda: next((r for r in a.must("GET", "/v1/self/device-requests").get("requests", [])
                            if r.get("node_key_id") == d.node_key_id), None)
    seen = in_list() is not None
    c_code2, c_body2 = d.api("DELETE", "/v1/setup/add-device")
    try:
        wait_for("A to drop the withdrawn request", lambda: True if in_list() is None else None, 60, every=2)
        dropped = True
    except MeshError:
        dropped = False
    if d_code != 202 or not seen or c_code2 != 200 or (c_body2 or {}).get("state") != "idle" or not dropped:
        ok = False
        step.fail("withdraw_pending", "a pending request withdrawn by its device leaves the owner's list", [a, d],
                  r"device-join|add-device", request=d_code, seen=seen, cancel=c_code2, body=c_body2,
                  dropped=dropped)
    step("withdrawn_pending_dropped", request=d_code, seen_before=seen, cancel_status=c_code2, dropped=dropped)

    # (8b) A BARE FEDID, no code at all (steward 2026-11-04): a fresh device knows
    # only `alice-person-…`. F has never seen a code: it must find alice's nodes
    # through the canonical and reach the same held request.
    f_bare, _ = wait_for("the bare fedID to reach alice", lambda: (lambda r: r if r[0] == 202 else None)(
        f.api("POST", "/v1/setup/add-device", {"contact": a.owner_key_id, "label": "bare-fedid"})),
        args.arrive_wait, every=5)
    bare_seen = any(r.get("node_key_id") == f.node_key_id
                    for r in a.must("GET", "/v1/self/device-requests").get("requests", []))
    f.api("DELETE", "/v1/setup/add-device")
    if f_bare != 202 or not bare_seen:
        ok = False
        step.fail("bare_fedid", "a bare fedID finds the person's nodes through the canonical", [a, f],
                  r"device-join|add-device", request=f_bare, seen=bare_seen)
    step("bare_fedid_reached_the_owner", request=f_bare, seen_on_a=bare_seen,
         proves="a device holding only a fedID finds the person's announced nodes through the canonical")

    # (9) a device that changes its mind AFTER approval: the owner's device
    # evicts what it recorded (B's occurrence revoked) — nothing lingers.
    e_code, _ = ask(e, "regret")
    e_row = in_row = next((r for r in a.must("GET", "/v1/self/device-requests").get("requests", [])
                           if r.get("node_key_id") == e.node_key_id), None)
    occ_e = None
    if e_row:
        # CC 3.3.6.3 (persist v59): alice's roster now holds two keys (genesis +
        # B), so a third device's addition is a PROPOSAL the self roster holds —
        # it lands by the quorum or the lone path (routes: CIRISServer#794). The
        # approval answers 409 add_device.roster_change_held, naming it.
        st_e, body_e = a.api("POST", f"/v1/self/device-requests/{e_row['request_id']}/approve")
        # (Since the held-approval path it answers 202 {"approved": false, "held": true};
        # it resumes when the roster lands the key.)
        held_e = st_e == 202 and (body_e or {}).get("held") is True
        if held_e or (st_e == 409 and (body_e or {}).get("reason_id") == "add_device.roster_change_held"):
            e.api("DELETE", "/v1/setup/add-device")
            step("third_device_held", status=st_e, reason_id=(body_e or {}).get("reason_id"),
                 proves="from a roster of two, an addition is held as a proposal (CC 3.3.6.3)")
            return {"verdict": "PASS" if ok else "FAIL", "steps": step.log, "first_failure": step.first_failure}
        if st_e not in (200, 201):
            raise MeshError(f"alice: approve E answered {st_e}: {str(body_e)[:400]}")
        occ_e = (body_e or {}).get("occurrence_key_id")
        try:
            wait_for("E to verify and hold", lambda: (lambda st: st if st.get("state") == "approved" else None)(
                e.must("GET", "/v1/setup/add-device")), args.arrive_wait, every=2)
        except MeshError:
            pass
    e_cancel, _ = e.api("DELETE", "/v1/setup/add-device")
    revq = ("SELECT count(*) FROM federation_identity_occurrence_revocations "
            "WHERE identity_key_id = ? AND occurrence_key_id = ?")
    def revoked() -> Optional[bool]:
        n = sum(int(r[0]) for r in a.rows(revq, (a.owner_key_id, occ_e or "")))
        return True if n >= 1 else None
    try:
        wait_for("A to revoke the withdrawn device's occurrence", revoked, 90, every=3)
        is_revoked = True
    except MeshError:
        is_revoked = False
    if e_code != 202 or not occ_e or e_cancel != 200 or not is_revoked:
        ok = False
        step.fail("withdraw_approved", "an approval withdrawn by its device is undone on the owner's device "
                  "(occurrence revoked)", [a, e], r"device-join|evict|revok", request=e_code, occurrence=occ_e,
                  cancel=e_cancel, revoked=is_revoked)
    step("withdrawn_approval_undone", occurrence=occ_e, cancel_status=e_cancel, revoked_on_a=is_revoked)
    return {"verdict": "PASS" if ok else "FAIL", "steps": step.log, "first_failure": step.first_failure}


# Add to the other person's `request-seen` (steward 2026-11-04: "we need this to
# be rapid, even when relayed").
NEW_CONTACT_LIMIT_SECS = 30


def contact_edges(mesh: Mesh, args: Any) -> Record:
    """The contact edges from Eric's report (CIRISServer#777, #778), on the real
    wire: add by fed ID before the person is known, then after they converge;
    add by v3 code before this node holds their key, then watch it finish with
    NO further client call."""
    step = Steps("""
CONTACT EDGES — the add-contact paths that failed on Eric's desktop (2026-10-16).
  #778  add by FED ID: bob not yet announced → 404 contacts.unknown_fed_id (a person's
        "who?", final) → bob announces → alice's directory converges → the SAME add
        succeeds, bob is listed, POST /v1/chat opens.
  #777  add by v3 CODE before alice holds carol's key → 202 contacts.awaiting_key_body →
        with NO second paste, carol appears in alice's contacts once her key arrives,
        and POST /v1/chat opens.""")
    ok = True
    cnl = mesh.canonical if mesh.canonical is not None else mesh.start_canonical()

    def join(n: Node) -> None:
        # Production's mesh participation: the node consents to replicate to the
        # canonical (the agent's "Send traces" consent), which is what carries a
        # person's key and owner-binding to the canonical at all.
        n.self_record()
        n.peer_with(cnl)

    a = mesh.add("alice")
    a.claim("alice-person")
    a.announce()
    join(a)
    b = mesh.add("bob")
    b.claim("bob-person")
    join(b)
    step("booted", alice=a.owner_key_id, bob=b.owner_key_id)

    def contacts(n: Node) -> List[str]:
        return [c.get("key_id", "") for c in n.must("GET", "/v1/contacts").get("contacts", [])]

    # ── #778 ──
    code, body = a.api("POST", "/v1/contacts", {"key_id": b.owner_key_id})
    if code != 404 or (body or {}).get("reason_id") != "contacts.unknown_fed_id":
        ok = False
        step.fail("fed_id_unknown", "an unknown fed ID must be a 404 contacts.unknown_fed_id", [a], r"contacts",
                  got={"status": code, "body": body})
    step("fed_id_unknown", status=code, reason_id=(body or {}).get("reason_id"))
    b.announce()
    b.self_record()
    # Convergence is judged by the act itself — the same add a person retries —
    # not by a directory probe (the peers listing never lists USER keys).
    t_announced = time.monotonic()
    last: Any = None

    def added() -> Optional[bool]:
        nonlocal last
        last = a.api("POST", "/v1/contacts", {"key_id": b.owner_key_id})
        return True if last[0] in (200, 201) else None
    try:
        wait_for("the same fed-ID add to succeed once bob's key converges", added, args.owner_wait, every=5)
        step("fed_id_converged", seconds=round(time.monotonic() - t_announced, 1),
             proves="bob announced; his key reached alice through the canonical; the add succeeded")
    except MeshError:
        ok = False
        step.fail("fed_id_never_converged", "bob announced but the fed-ID add never succeeded",
                  [a, b, mesh.canonical], r"announce|Key|refus|contacts", last=last)
    code, body = last if last else (0, None)
    listed = b.owner_key_id in contacts(a)
    chat_code, chat_body = a.api("POST", "/v1/chat", {"key_id": b.owner_key_id})
    if not (code in (200, 201) and listed and chat_code in (200, 201)):
        ok = False
        step.fail("fed_id_added", "after convergence the same fed-ID add must list bob and open a chat", [a],
                  r"contacts|chat", add={"status": code, "body": body}, listed=listed,
                  chat={"status": chat_code, "body": chat_body})
    step("fed_id_added", status=code, listed=listed, chat_status=chat_code)

    # ── #777 ──
    c = mesh.add("carol")
    c.claim("carol-person")
    c.announce()
    join(c)
    carol_code = c.contact_code()
    code, body = a.api("POST", "/v1/contacts", {"key_id": carol_code})
    reason = (body or {}).get("reason_id")
    if code != 202 or reason != "contacts.awaiting_key_body":
        # Alice already held carol's key: the synchronous path ran, so the
        # pending path this step exists for was NOT exercised. Say so.
        ok = False
        step.fail("code_pending_not_exercised",
                  "alice already held carol's key before the paste, so the pending path was not exercised "
                  "(rerun; this step needs the paste to beat replication)", [a],
                  r"contacts", got={"status": code, "reason_id": reason})
    step("code_pending", status=code, reason_id=reason, converges_on_its_own=(body or {}).get("converges_on_its_own"))
    try:
        wait_for("carol to appear in alice's contacts with no second paste",
                 lambda: c.owner_key_id in contacts(a), args.arrive_wait, every=3)
        step("code_completed_on_its_own", proves="the node finished the pending contact when carol's key arrived")
    except MeshError:
        ok = False
        step.fail("code_never_completed", "the pending v3 contact never completed on its own", [a],
                  r"pending|contacts")
    chat_code, chat_body = a.api("POST", "/v1/chat", {"key_id": c.owner_key_id})
    if chat_code not in (200, 201):
        ok = False
        step.fail("code_chat", "a completed pending contact must open a chat", [a], r"chat",
                  got={"status": chat_code, "body": chat_body})
    step("code_chat", status=chat_code)

    # ── A NEW PERSON, ADDED BY FED ID ONCE ── the person reinstalled and came back
    # as someone alice's node has never met. One add, no retry: the canonical
    # names their node, and the request has to reach them inside the limit.
    d = mesh.add("dan")
    d.claim("dan-person")
    d.announce()
    join(d)
    d.self_record()
    wait_for("the canonical to name dan's node",
             lambda: d.node_key_id in (cnl.must("GET", f"/v1/federation/people/{d.owner_key_id}/nodes").get("nodes") or []),
             args.owner_wait, every=1)
    t_added = time.monotonic()
    code, body = a.api("POST", "/v1/contacts", {"key_id": d.owner_key_id})
    if code not in (200, 201, 202):
        ok = False
        step.fail("new_person_add", "a fed ID the canonical can name must be accepted first time", [a],
                  r"contacts", got={"status": code, "body": body})
    step("new_person_added", status=code, reason_id=(body or {}).get("reason_id"))

    def request_seen() -> bool:
        reqs = d.must("GET", "/v1/contacts/requests").get("requests", [])
        return any(r.get("requester_key_id") == a.owner_key_id for r in reqs)
    # Wait past the limit, so a miss still reports the real time.
    try:
        wait_for("dan to see alice's request", request_seen, args.arrive_wait, every=1)
    except MeshError:
        pass
    seconds = round(time.monotonic() - t_added, 1)
    if seconds > NEW_CONTACT_LIMIT_SECS:
        ok = False
        step.fail("new_person_request_slow", f"the request must arrive inside {NEW_CONTACT_LIMIT_SECS} s of the add",
                  [a, d, mesh.canonical], r"contacts|re-aimed|CONTACT|RATE LIMITED|parked", seconds=seconds)
    else:
        step("new_person_saw_the_request", seconds=seconds, limit=NEW_CONTACT_LIMIT_SECS)

    # ── THE ROOM, END TO END ── through the canonical, from dan accepting to a first
    # message read on the other side. Measured, not gated: no target is set yet.
    t_room = time.monotonic()
    lap = lambda: round(time.monotonic() - t_room, 1)
    d.must("POST", "/v1/contacts", {"key_id": a.owner_key_id})
    step("room:accepted", seconds=lap())
    cid = a.open_pair(d.owner_key_id)
    if d.open_pair(a.owner_key_id) != cid:
        ok = False
        step.fail("room_two_rooms", "both people must land in one pair room", [a, d], r"chat|pair")
    step("room:opened", seconds=lap())
    creator, joiner = (a, d) if a.owner_key_id < d.owner_key_id else (d, a)
    try:
        wait_for("the pair room to key", lambda: creator.room(cid)["ready"], args.ready_wait, every=1)
        step("room:keyed", seconds=lap(), creator=creator.name)
        sent = creator.say(cid, "first message")
        step("room:sent", seconds=lap())
        wait_for("the first message to arrive", lambda: any(
            m.get("attestation_id") == sent and m.get("body") for m in joiner.room(cid)["messages"]),
            args.arrive_wait, every=1)
        step("room:first_message_read", seconds=lap(), proves="accepted, seated, keyed, sent, read")
    except MeshError:
        ok = False
        step.fail("room_not_end_to_end", "the pair room must reach a read message", [a, d, mesh.canonical],
                  _HANDSHAKE, seconds=lap(), creator_state=creator.room(cid)["state"])
    return {"verdict": "PASS" if ok else "FAIL", "steps": step.log, "first_failure": step.first_failure}


# The log signatures of the fresh-claim replication storm on Eric's desktop
# (server 0.5.223, 2026-10-16) — each counted from raw lines PLUS the totals
# log_dedup folds repeats into ("event repeated N times … sample=<line>").
_STORM = {
    "item2_drops": r"item 2 FAILED",
    "unattributed_crpl": r"source_key_id=None",
    "round_timeouts": r"round timed out waiting for peer reply",
    "occurrence_refusals": r"is neither identity .* nor an active occurrence|typed asserted_at diverges",
}


def _storm_counts(n: Node) -> Dict[str, int]:
    import re as _re
    out = {k: 0 for k in _STORM}
    try:
        text = n.log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for raw in text.splitlines():
        line = _re.sub(r"\x1b\[[0-9;]*m", "", raw)
        m = _re.search(r"event repeated (\d+) times.*?\(\d+ suppressed\)", line)
        for k, pat in _STORM.items():
            if _re.search(pat, line):
                # a dedup summary stands for the suppressed repeats it folded
                sup = _re.search(r"\((\d+) suppressed\)", line)
                out[k] += int(sup.group(1)) if (m and sup) else 1
    return out


def fresh_claim(mesh: Mesh, args: Any) -> Record:
    """CIRISServer#779 — a freshly claimed LAPTOP node on the real wire must admit
    its owner's rows at the canonical within a bounded window, with no replication
    storm. Fixed in 0.5.225 (edge v40.0.12 + CIRISEdge#858 + release_parked_on);
    gate: this FAILS against a v0.5.223 binary and passes on main."""
    window = float(getattr(args, "arrive_wait", 180))
    ceilings = {"item2_drops": 10, "unattributed_crpl": 10, "round_timeouts": 20, "occurrence_refusals": 10}
    step = Steps(f"""
FRESH CLAIM — the 0.5.223 storm on Eric's desktop, as a regression test (CIRISServer#779).
  topology: the canonical + ONE fresh laptop-class node, claimed by a person, announced, and
            joined to the mesh as an agent joins it (consent to replicate to the canonical).
  asserts:  within {window:.0f} s the canonical holds the owner's key AND rows the owner signed;
            over the window the node logs at most {ceilings} of the storm signatures
            (raw lines + log_dedup folded repeats).""")
    cnl = mesh.canonical if mesh.canonical is not None else mesh.start_canonical()
    a = mesh.add("laptop")
    t0 = time.monotonic()
    a.claim("fresh-owner")
    a.announce()
    a.self_record()
    a.peer_with(cnl)
    step("claimed_announced_joined", owner=a.owner_key_id, node=a.node_key_id)

    def owner_rows_at_canonical() -> Optional[Dict[str, int]]:
        keys = cnl.rows("SELECT count(*) FROM federation_keys WHERE key_id = ?", (a.owner_key_id,))
        atts = cnl.rows("SELECT count(*) FROM federation_attestations WHERE attesting_key_id = ?",
                        (a.owner_key_id,))
        k = sum(int(r[0]) for r in keys) if keys else 0
        n = sum(int(r[0]) for r in atts) if atts else 0
        return {"owner_key": k, "owner_rows": n} if (k > 0 and n > 0) else None
    ok = True
    try:
        got = wait_for("the canonical to hold the owner's key and owner-signed rows",
                       owner_rows_at_canonical, window, every=3)
        step("owner_rows_admitted", seconds=round(time.monotonic() - t0, 1), **got)
    except MeshError:
        ok = False
        step.fail("owner_rows_NOT_admitted", "a freshly claimed node's owner rows never reached the canonical",
                  [a, cnl], r"refus|park|parked|item 2|round timed out|occurrence")
    rest = window - (time.monotonic() - t0)
    if rest > 0:
        time.sleep(rest)
    counts = _storm_counts(a)
    over = {k: v for k, v in counts.items() if v > ceilings[k]}
    if over:
        ok = False
        step.fail("storm", "the fresh node logged a replication storm", [a], "|".join(_STORM.values()),
                  counts=counts, ceilings=ceilings)
    step("storm_counts", counts=counts, ceilings=ceilings, window_s=window)
    return {"verdict": "PASS" if ok else "FAIL", "steps": step.log, "storm": counts,
            "first_failure": step.first_failure}


def owner_key_tpm_appears(mesh: Mesh, args: Any) -> Record:
    """CIRISServer#783 / PR #784 on the real wire: an owner fed-ID minted
    `platform-sealed` while the TPM plugin is invisible lands in the keyring's
    SOFTWARE tier; when the plugin becomes loadable and the node restarts, the
    owner key must still open (0.5.227: the re-open archives it and every owner
    act fails `Key not found: ed25519.seed`). Phase 2 then puts the home into the
    exact shape Eric's desktop was left in and asserts the node heals it."""
    plugin = os.environ.get("CIRIS_TPM_PLUGIN_REAL", "")
    if not plugin or not Path(plugin).is_file():
        raise MeshError("set CIRIS_TPM_PLUGIN_REAL to a libciris_tpm_plugin.so path (a usable TPM is required)")
    step = Steps("""
OWNER KEY WHEN A TPM APPEARS — Eric's desktop, 2026-10-08 (CIRISServer#783, PR #784).
  phase 1: claim with --backend platform-sealed while the TPM plugin is INVISIBLE → the key is
           in the SOFTWARE tier; restart with the plugin VISIBLE; an owner act must still sign and
           nothing may be archived.
  phase 2: put the home in Eric's exact shape (software pair archived to *.superseded-pre-v8 beside
           an empty TPM seal); restart; the node must restore the key and sign again.""")
    ok = True
    n = mesh.add("laptop", start=False)
    n.env["CIRIS_TPM_PLUGIN"] = "/nonexistent/libciris_tpm_plugin.so"
    n.start()
    n.claim("tpm-owner", backend="platform-sealed")
    user_dir = n.home / "identity" / "user"

    def files() -> List[str]:
        return sorted(p.name for p in user_dir.iterdir()) if user_dir.is_dir() else []
    minted = files()
    if not any(f.endswith(".ed25519.seed.blob") for f in minted):
        raise MeshError(f"expected the platform-sealed mint to fall back to the software tier, got {minted}")
    step("minted_software_tier", files=minted)

    def widener_since(mark: int) -> Optional[str]:
        """The owner pen, opened by the node itself at runtime start: compose
        installs the membership widener only with the owner's person key. Eric's
        desktop logged 'membership widener NOT installed (no owner pen …)'."""
        lines = n.grep(r"membership widener")
        new = lines[mark:]
        return new[-1] if new else None

    def owner_act(mark: int) -> Tuple[int, Any]:
        try:
            line = wait_for("the restarted node to try the owner pen", lambda: widener_since(mark), 60, every=1)
        except MeshError:
            return 0, "no membership-widener line after restart"
        return (200, line) if "NOT installed" not in line else (500, line)

    def restart_with_plugin() -> None:
        n.stop()
        n.env["CIRIS_TPM_PLUGIN"] = plugin
        n.start()

    mark = len(n.grep(r"membership widener"))
    restart_with_plugin()
    code, body = owner_act(mark)
    after = files()
    stranded = [f for f in after if f.endswith("superseded-pre-v8")]
    keynotfound = n.grep(r"Key not found: ed25519\.seed")
    if stranded or code not in (200, 201) or keynotfound:
        ok = False
        step.fail("tpm_appeared", "the owner key must still open once the TPM plugin is loadable",
                  [n], r"superseded|SUPERSEDED|Key not found|owner's \(.*\) signer|announce",
                  status=code, archived=stranded, key_not_found_lines=len(keynotfound))
    step("tpm_appeared", owner_pen=str(body)[:120], files=after, archived=stranded)

    # Phase 2 — Eric's exact on-disk shape.
    n.stop()
    for f in files():
        if f.endswith(".ed25519.seed.blob") or (f.endswith(".master.key") and not f.endswith("superseded-pre-v8")):
            (user_dir / f).rename(user_dir / f"{f}.superseded-pre-v8")
    alias = next((f.split(".")[0] for f in files() if f.endswith(".backend")), "")
    if alias:
        (user_dir / f"{alias}.tpmplugin_seal").write_bytes(b"empty TPM tier: a master, no blobs")
    shaped = files()
    step("eric_shape", files=shaped)
    mark = len(n.grep(r"membership widener"))
    n.start()
    code, body = owner_act(mark)
    healed = files()
    restored = n.grep(r"KEY RESTORED")
    if code not in (200, 201) or any(f.endswith("superseded-pre-v8") for f in healed) or not restored:
        ok = False
        step.fail("healed", "a key superseded into an empty TPM tier must be restored and sign again", [n],
                  r"KEY RESTORED|superseded|Key not found|announce", status=code, files=healed)
    step("healed", owner_pen=str(body)[:120], files=healed, restore_logged=bool(restored))
    return {"verdict": "PASS" if ok else "FAIL", "steps": step.log, "first_failure": step.first_failure}


def kex_fresh_node(mesh: Mesh, args: Any) -> Record:
    """CIRISServer#788: does a fresh node ever hold the canonical's KEX keys?

    Key exchange reads the canonical's identity OCCURRENCE (X25519 + ML-KEM),
    and the receive gate admits the canonical's frames only once the node holds
    its SIGNED transport destination (CIRISEdge#393 item 2). The baked trust
    root carries neither. Two nodes, one difference:
      P - production shape: claimed, announced, peers WITH the canonical; the
          canonical never peers back (it does not in production).
      Q - harness shape: the same, plus the canonical peers back
          (`cnl.peer_with(q)`, what most ladders do).
    PASS only when P holds both rows within the window: the #788 e2e."""
    step = Steps(kex_fresh_node.__doc__ or "")
    cnl, _anchor, _done = mint_accord_root(mesh, args, step)
    if not cnl.node_key_id:
        cnl.self_record()
    ck = cnl.node_key_id  # the REGISTERED id; `key_id` is the keystore alias

    def held(n: Node) -> Dict[str, int]:
        occ = n.rows("SELECT count(*) FROM federation_identity_occurrences "
                     "WHERE occurrence_key_id = ? AND pubkey_x25519_base64 IS NOT NULL", (ck,))
        route = n.rows("SELECT count(*) FROM transport_destinations "
                       "WHERE occurrence_key_id = ? AND signature IS NOT NULL", (ck,))
        return {"kex_occurrence": sum(r[0] for r in occ), "signed_route": sum(r[0] for r in route)}

    p = mesh.add("prodshape")
    p.claim("p-person")
    p.announce()
    p.self_record()
    p.peer_with(cnl)
    q = mesh.add("harnessshape")
    q.claim("q-person")
    q.announce()
    q.self_record()
    q.peer_with(cnl)
    cnl.peer_with(q)
    step("peered", p="node -> canonical only", q="node -> canonical AND canonical -> node")

    window = float(getattr(args, "arrive_wait", 90) or 90)
    t0 = time.monotonic()
    first: Dict[str, Optional[float]] = {"P": None, "Q": None}
    seen: Dict[str, Dict[str, int]] = {}
    while time.monotonic() - t0 < window:
        for tag, n in (("P", p), ("Q", q)):
            seen[tag] = held(n)
            if first[tag] is None and seen[tag]["kex_occurrence"] and seen[tag]["signed_route"]:
                first[tag] = round(time.monotonic() - t0, 1)
        if first["P"] is not None and first["Q"] is not None:
            break
        time.sleep(3)
    dropped = {tag: len([l for l in n.grep(r"item 2 FAILED") if ck in l]) for tag, n in (("P", p), ("Q", q))}
    step("held", window_s=window, P=seen.get("P"), Q=seen.get("Q"),
         P_kex_at_s=first["P"], Q_kex_at_s=first["Q"], canonical_frames_dropped=dropped,
         proves="which peering shape delivers the canonical's KEX occurrence and signed route")
    ok = first["P"] is not None
    if not ok:
        step.fail("prod_shape_kex", "a node peered the production way never holds the canonical's KEX "
                  "occurrence and signed route — key exchange cannot complete (CIRISServer#788)",
                  [p, cnl], r"item 2 FAILED|SignedTransportDestination|rooting_unknown_key_id")
    return {"verdict": "PASS" if ok else "FAIL", "steps": step.log, "first_failure": step.first_failure}


def kex_unannounced_canonical(mesh: Mesh, args: Any) -> Record:
    """CIRISServer#788, production-faithful: the canonical is claimed by its
    owner but NOT announced (production sat at `cohort_scope: self` from
    2026-07-02). Edge serves an owned node's identity rows to everyone only once
    it is announced (CIRISEdge#682), so a fresh node cannot reach the
    canonical's KEX occurrence or signed route. Then the canonical restarts with
    its owner's pen on disk: the boot check must announce it, signed by the
    owner, and the fresh node must then hold both rows.
      phase 1  unannounced  → the fresh node does NOT hold them (the field bug)
      restart  boot check   → `canonical_announce: announced` on /health
      phase 2  announced    → the fresh node holds both rows"""
    step = Steps(kex_unannounced_canonical.__doc__ or "")
    cnl, _anchor, _done = mint_accord_root(mesh, args, step, announce=False)
    if not cnl.node_key_id:
        cnl.self_record()
    ck = cnl.node_key_id

    def held(n: Node) -> Dict[str, int]:
        occ = n.rows("SELECT count(*) FROM federation_identity_occurrences "
                     "WHERE occurrence_key_id = ? AND pubkey_x25519_base64 IS NOT NULL", (ck,))
        route = n.rows("SELECT count(*) FROM transport_destinations "
                       "WHERE occurrence_key_id = ? AND signature IS NOT NULL", (ck,))
        return {"kex_occurrence": sum(r[0] for r in occ), "signed_route": sum(r[0] for r in route)}

    def node_block(n: Node) -> Dict[str, Any]:
        st, body = n.api("GET", "/health")
        return (body or {}).get("node", {}) if isinstance(body, dict) else {}

    p = mesh.add("fresh")
    p.claim("fresh-person")
    p.announce()
    p.self_record()
    p.peer_with(cnl)
    ok = True

    phase1 = float(getattr(args, "unannounced_wait", 45) or 45)
    t0 = time.monotonic()
    got1 = held(p)
    while time.monotonic() - t0 < phase1 and not (got1["kex_occurrence"] and got1["signed_route"]):
        time.sleep(3)
        got1 = held(p)
    leaked = bool(got1["kex_occurrence"] and got1["signed_route"])
    step("phase1_unannounced", held=got1, window_s=phase1, canonical_node_block=node_block(cnl),
         proves="an owned, unannounced canonical withholds its KEX occurrence and route from a fresh node")
    if leaked:
        ok = False
        step.fail("phase1_unannounced", "the fresh node received the canonical's rows while the canonical "
                  "was unannounced — the scenario does not reproduce the field condition", [p, cnl],
                  r"IdentityRowNodeNotAnnounced|announce")

    cnl.stop()
    cnl.start()
    blk = node_block(cnl)
    announced_line = cnl.grep(r"seated canonical (was NOT announced — announced now|is ANNOUNCED)")
    step("canonical_restarted", canonical_announce=blk.get("canonical_announce"),
         boot_line=(announced_line[-1][-220:] if announced_line else None))
    if blk.get("canonical_announce") != "announced":
        ok = False
        step.fail("canonical_announce", "the seated canonical did not announce itself at boot with its "
                  "owner's pen on disk (CIRISServer#788)", [cnl], r"seated canonical")

    phase2 = float(getattr(args, "arrive_wait", 120) or 120)
    t0 = time.monotonic()
    got2 = held(p)
    while time.monotonic() - t0 < phase2 and not (got2["kex_occurrence"] and got2["signed_route"]):
        time.sleep(3)
        got2 = held(p)
    arrived = bool(got2["kex_occurrence"] and got2["signed_route"])
    step("phase2_announced", held=got2, after_s=round(time.monotonic() - t0, 1),
         proves="once announced, a fresh node holds the canonical's KEX occurrence and signed route")
    if not arrived:
        ok = False
        step.fail("phase2_announced", "the canonical is announced but the fresh node still lacks its KEX "
                  "occurrence or signed route", [p, cnl], r"item 2 FAILED|IdentityRow|announce")
    return {"verdict": "PASS" if ok else "FAIL", "steps": step.log, "first_failure": step.first_failure}


SCENARIOS: Dict[str, Callable[[Mesh, Any], Record]] = {
    "room_file": room_file,
    "room_takedown": room_takedown,
    "final_genesis": final_genesis,
    "halt": halt,
    "halt_agent": halt_agent,
    "add_device": add_device,
    "remote_admin": remote_admin,
    "kex_fresh_node": kex_fresh_node,
    "kex_unannounced_canonical": kex_unannounced_canonical,
    "contact_edges": contact_edges,
    "fresh_claim": fresh_claim,
    "owner_key_tpm_appears": owner_key_tpm_appears,
    "chat": chat,
    "corpus": corpus,
    "peer_pair": peer_pair,
    "av_call": av_call,
    "av_room": av_room,
    "av_mesh": av_mesh,
    "av_member": av_member,
    "decisions": decisions,
    "av_echo": av_echo,
    "pair_unannounced": pair_unannounced,
    "relay_rig": relay_rig,
    "two_seats": two_seats,
    "person_store": person_store,
    "pair_alice_announced": pair_alice_announced,
    "pair_bob_announced": pair_bob_announced,
    "pair_both_announced": pair_both_announced,
}
