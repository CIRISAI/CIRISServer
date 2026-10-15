"""Scenarios over the native mesh. Each is a function `(mesh, args) -> dict`
that records what it measured, step by step, and raises `MeshError` at the
first step that cannot proceed — naming it.

Add one by writing a function and registering it in `SCENARIOS`.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

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


def mint_accord_root(mesh: Mesh, args: Any, step: "Steps"):
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

    # 2. The ceremony, over the routes.
    planned = c.must("POST", "/v1/accord/final-genesis/plan", {
        # Where peers dial it — as the baked canonical carries it.
        "serve_nodes": [{"key_id": c.node_key_id,
                         "transport_hints": [{"kind": "ip", "destination": c.transport}]}],
        "recovery_keys": anchor["recovery_keys"],
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
    step("canonical_rebooted_on_bundle",
         evidence=c.grep(r"booting on a ceremony-minted genesis bundle")[-1:])
    # The production canonical is OWNED (the operator's fedID) — an unowned
    # node refuses federation peering.
    c.claim("operator-person")
    c.announce()
    c.self_record()
    step("canonical_claimed", owner=c.owner_key_id)
    mesh.accord_holders = anchor["holders"]
    return c, anchor, done


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
                 lambda: True if (status_of(agent_url).get("halt") or {}).get("confirmed") is True else None, 30, every=1.0)
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


SCENARIOS: Dict[str, Callable[[Mesh, Any], Record]] = {
    "final_genesis": final_genesis,
    "halt": halt,
    "halt_agent": halt_agent,
    "chat": chat,
    "corpus": corpus,
}
