"""Scenarios over the native mesh. Each is a function `(mesh, args) -> dict`
that records what it measured, step by step, and raises `MeshError` at the
first step that cannot proceed — naming it.

Add one by writing a function and registering it in `SCENARIOS`.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List

from .mesh import HARNESS, Mesh, MeshError, Node, wait_for

Record = Dict[str, Any]


class Steps:
    """A timeline that EXPLAINS itself: each step says what it proves; a failed
    step says what it means and shows the log lines that decide it."""

    def __init__(self, plan: str) -> None:
        self.t0 = time.monotonic()
        self.log: List[Record] = []
        print("── PLAN ──\n" + plan.strip() + "\n──", flush=True)

    def __call__(self, name: str, proves: str = "", **seen: Any) -> None:
        rec = {"t": round(time.monotonic() - self.t0, 1), "step": name, **seen}
        if proves:
            rec["proves"] = proves
        self.log.append(rec)
        print(json.dumps(rec), flush=True)

    def fail(self, name: str, means: str, nodes: List[Node], patterns: str, **seen: Any) -> None:
        """A step that did not happen: what that MEANS, and the evidence."""
        evidence = {n.name: [line[-300:] for line in n.grep(patterns)[-8:]] for n in nodes}
        self(name, means=means, evidence=evidence, **seen)
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

    def keyed() -> Any:
        ra, rb = a.room(cid_a), b.room(cid_b)
        return (ra["ready"] and rb["ready"]) and (ra, rb)

    try:
        wait_for("the pair room to key on both sides", keyed, args.ready_wait, every=3)
        step("room_keyed")
    except MeshError:
        ra, rb = a.room(cid_a), b.room(cid_b)
        step.fail("room_NOT_keyed",
                  "the MLS handshake did not complete: the joiner's KeyPackage or the creator's "
                  "Welcome never reached the other node (CIRISServer#698's claim)",
                  [a, b], _HANDSHAKE, alice_state=ra["state"], bob_state=rb["state"])
        raise
    text = f"hello from bob {int(time.time())}"
    att = b.say(cid_b, text)
    step("sent", attestation_id=att)

    def arrived() -> bool:
        return any(m.get("attestation_id") == att and m.get("body") == text
                   for m in a.room(cid_a)["messages"])

    try:
        wait_for("bob's message on alice's node", arrived, args.arrive_wait, every=2)
    except MeshError:
        ra = a.room(cid_a)
        mine = [m for m in ra["messages"] if m.get("attestation_id") == att]
        step.fail("body_NOT_arrived",
                  "the row may be here but its BODY did not open on alice: the recipient pulls "
                  "the body from a holder over the room's DERIVED address, which only a direct "
                  "neighbour can reach (CC 5.4.6); a `no route to peer … has_path=false` line "
                  "below is that, `outcome=Stored` means it DID arrive and the transcript is "
                  "the problem",
                  [a, b], _BODY, row_on_alice=mine[:1], transcript_len=len(ra["messages"]))
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
        not_here = [k for k, v in bad.items() if v.get("second", {}).get("status") == 409]
        wrong = [k for k, v in bad.items() if v.get("second", {}).get("status") == 200]
        means = []
        if not_here:
            means.append(f"{len(not_here)} never reached the second device (not_fetched): the pull over the "
                         "room's derived address failed — a `no route to peer` / `holder retired` line "
                         "is a topology fault (direct neighbours needed, CC 5.4.6), `NoHolders` is the pull's source rule")
        if wrong:
            means.append(f"{len(wrong)} arrived with DIFFERENT bytes: a transfer defect; `first_diff`/`prefix` say where")
        step.fail("corpus_mismatch", "; ".join(means), [a, b], _BODY, files=bad)
    return {"verdict": "PASS" if not bad else "FAIL", "steps": step.log, "results": results}


SCENARIOS: Dict[str, Callable[[Mesh, Any], Record]] = {
    "chat": chat,
    "corpus": corpus,
}
