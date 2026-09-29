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
    """A timeline: each step's name, seconds since start, and what it saw."""

    def __init__(self) -> None:
        self.t0 = time.monotonic()
        self.log: List[Record] = []

    def __call__(self, name: str, **seen: Any) -> None:
        rec = {"t": round(time.monotonic() - self.t0, 1), "step": name, **seen}
        self.log.append(rec)
        print(json.dumps(rec), flush=True)


# ── chat between two PEOPLE, production routes (CIRISServer#698) ────────────


def chat(mesh: Mesh, args: Any) -> Record:
    """Two people, each on their own node, add each other and key a pair room,
    using only the routes a released node exposes. The CIRISServer#698 path."""
    step = Steps()
    a, b = mesh.add("alice"), mesh.add("bob")
    step("booted", alice=a.url, bob=b.url, canonical=mesh.canonical.url)
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
        got = host.add_contact(key)
        step(f"contact:{host.name}->{guest.name}", via=via, key=str(got.get("key_id"))[:60],
             reachable_nodes=got.get("reachable_nodes"))
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
        step("room_NOT_keyed", alice_state=ra["state"], bob_state=rb["state"],
             alice_log=_why(a), bob_log=_why(b))
        raise
    text = f"hello from bob {int(time.time())}"
    att = b.say(cid_b, text)
    step("sent", attestation_id=att)

    def arrived() -> bool:
        return any(m.get("attestation_id") == att and m.get("body") == text
                   for m in a.room(cid_a)["messages"])

    wait_for("bob's message on alice's node", arrived, args.arrive_wait, every=2)
    step("arrived")
    return {"verdict": "PASS", "steps": step.log}


def _why(n: Node) -> List[str]:
    """The lines that explain a stuck handshake, newest last."""
    pats = (r"ADVISORY|not conferred|SignedTransportDestination|KeyPackage|Welcome|"
            r"withheld|withhold|refus|UnknownKey|chat: .*room")
    return [line[-260:] for line in n.grep(pats)[-12:]]


# ── one person, two devices, the transfer corpus (the ≥1 MiB question) ──────


def corpus(mesh: Mesh, args: Any) -> Record:
    """One person on two devices; the corpus written on the first, read raw on
    BOTH, compared byte for byte with the originals."""
    step = Steps()
    a = mesh.add("first")
    a.claim("one-person")
    b = mesh.add("second", start=False)
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
    step("compared", ok=len(results) - len(bad), bad=len(bad))
    for k, v in bad.items():
        step(f"mismatch:{k}", **v)
    return {"verdict": "PASS" if not bad else "FAIL", "steps": step.log, "results": results}


SCENARIOS: Dict[str, Callable[[Mesh, Any], Record]] = {
    "chat": chat,
    "corpus": corpus,
}
