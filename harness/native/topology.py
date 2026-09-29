"""Build the topology a use case declares (FSD/TOPOLOGY.md), from the root down.

    python -m harness.native build --topology harness/native/topologies/csd-091-user-chat.yaml \\
        --binary target/debug/ciris-server

Three verbs on one declaration: `load` (parse + realizability rules), `derive`
(node count, root ceremony, build order — what the CSD checker consumes) and
`build` (stand it up layer by layer on a `Mesh`, checking each predicate and
naming the first layer that does not hold).
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .mesh import Mesh, MeshError, Node, wait_for
from .scenarios import Steps, _BODY, _HANDSHAKE

Decl = Dict[str, Any]

# What the synthetic anchor mints today (src/test_bless.rs): ONE key root, ONE
# software holder, lifecycle active. Everything else is declared and refused.
BUILDABLE_ROOT = {"kind": "key", "holders": 1, "custody": "software_test", "lifecycle": "active"}

LAYERS = ["roots", "canonicals", "nodes", "persons", "relations", "actor", "negatives"]


class Unrealizable(ValueError):
    """The declaration cannot hold, by rule number (FSD/TOPOLOGY.md §3)."""


# ── load + rules ────────────────────────────────────────────────────────────


def load(path: Path) -> Decl:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    t = doc.get("topology", doc)
    for k in ("roots", "canonicals", "nodes", "persons", "relations", "actor"):
        if k not in t:
            raise Unrealizable(f"missing layer `{k}`")
    check(t)
    return t


def _ids(t: Decl, layer: str) -> Dict[str, Decl]:
    return {x["id"]: x for x in t[layer]}


def check(t: Decl) -> List[str]:
    """Realizability (§3). Returns the list of what the builder cannot mint yet
    (`buildable: false` items); raises on a contradiction."""
    roots, canon, nodes, persons = (_ids(t, k) for k in ("roots", "canonicals", "nodes", "persons"))
    not_yet: List[str] = []
    for r in roots.values():
        if r.get("kind") == "family":
            f, m = r.get("founders", {}), r.get("quorum", 0)
            if f.get("n", 0) < m + 1:
                raise Unrealizable(f"rule 1: root {r['id']} quorum {m} needs founders.n >= {m + 1}")
            w = r.get("witnesses")
            if w and (w.get("n", 0) < 2 * w.get("k", 1) - 1 or not w.get("independent_custody")):
                raise Unrealizable(f"rule 1: root {r['id']} witnesses need n >= 2k-1 and independent_custody")
        for k, v in BUILDABLE_ROOT.items():
            if r.get(k, v) != v:
                not_yet.append(f"root {r['id']}: {k}={r.get(k)!r} (the anchor mints {v!r})")
    for c in canon.values():
        if c["holds"] not in roots:
            raise Unrealizable(f"canonical {c['id']} holds unknown root {c['holds']}")
    for n in nodes.values():
        for d in n.get("dials", []):
            if d not in nodes and d not in canon:
                raise Unrealizable(f"node {n['id']} dials unknown {d}")
        if n.get("accepts") and n["accepts"] not in roots:
            raise Unrealizable(f"node {n['id']} accepts unknown root {n['accepts']}")
    for p in persons.values():
        for nid in p["owns"]:
            if nid not in nodes:
                raise Unrealizable(f"person {p['id']} owns unknown node {nid}")
            if p.get("accepts") and nodes[nid].get("accepts") != p["accepts"]:
                raise Unrealizable(f"rule 2: {p['id']} accepts {p['accepts']} but owns {nid} which does not")
    owner_of = {nid: p["id"] for p in persons.values() for nid in p["owns"]}
    for rel in t["relations"]:
        kind = rel["rel"]
        if kind == "rooted_with":
            a, b = (persons[x] for x in rel["between"])
            if not (a.get("accepts") and a.get("accepts") == b.get("accepts")):
                raise Unrealizable(f"rule 3: rooted_with({a['id']},{b['id']}) needs a common accepted root")
        if kind in ("message", "file"):
            src = rel.get("from") or rel["person"]
            dsts = [rel["to"]] if kind == "message" else [q for q in persons if q == src]
            for q in dsts:
                for na in persons[src]["owns"]:
                    for nb in persons[q]["owns"]:
                        if na != nb and nb not in nodes[na].get("dials", []) and na not in nodes[nb].get("dials", []):
                            raise Unrealizable(f"rule 4: {kind} {src}->{q}: {na} and {nb} are not direct neighbours "
                                               f"(scoped content is one-hop, CC 5.4.6); add a `dials`")
        if kind == "reachable":
            q = rel["person"]
            if not any(nodes[n].get("announced") for n in persons[q]["owns"]):
                raise Unrealizable(f"rule 5: reachable(..., {q}) needs one of {q}'s nodes announced")
        if kind == "contact" and rel.get("via") == "code":
            q = rel["to"]
            if not any(nodes[n].get("announced") for n in persons[q]["owns"]):
                raise Unrealizable(f"rule 6: contact via code needs {q}'s node announced")
    t.setdefault("_owner_of", owner_of)
    return not_yet


def derive(t: Decl) -> Decl:
    persons = _ids(t, "persons")
    return {
        "nodes": len(t["nodes"]) + len(t["canonicals"]),
        "persons": len(persons),
        "devices": {p: len(v["owns"]) for p, v in persons.items()},
        "roots": [{k: r.get(k) for k in ("id", "kind", "holders", "founders", "quorum", "witnesses", "lifecycle", "custody")}
                  for r in t["roots"]],
        "direct_links": [(n["id"], d) for n in t["nodes"] for d in n.get("dials", []) if d not in _ids(t, "canonicals")],
        "build_order": LAYERS,
        "not_buildable_yet": check(t),
    }


# ── build ───────────────────────────────────────────────────────────────────


def build(mesh: Mesh, t: Decl, args: Any) -> Decl:
    d = derive(t)
    if d["not_buildable_yet"]:
        raise MeshError("declared but not buildable yet: " + "; ".join(d["not_buildable_yet"]))
    persons = _ids(t, "persons")
    owner_of = t["_owner_of"]
    plan = "\n".join(
        [f"TOPOLOGY {args.topology}", f"  roots: {d['roots']}",
         f"  nodes: {d['nodes']} ({len(t['canonicals'])} canonical), persons: {d['persons']}, devices: {d['devices']}",
         f"  direct links: {d['direct_links'] or 'none — every pair is relayed through a canonical'}",
         "  build order: " + " → ".join(LAYERS)])
    step = Steps(plan)
    N: Dict[str, Node] = {}

    # 1–2. roots + canonicals: the synthetic anchor's ceremony, one canonical.
    for c in t["canonicals"]:
        N[c["id"]] = mesh.start_canonical()
        step("root+canonical", layer="roots/canonicals", canonical=c["id"], holds=c["holds"],
             proves="the anchor's ceremony ran: charter root→root, grant root→node, trust edge node→root",
             evidence=N[c["id"]].grep(r"TEST-ANCHOR ceremony: trust_root_valid GREEN")[-1:])

    # 3. nodes, in an order that lets `dials` resolve.
    pending = [n for n in t["nodes"]]
    while pending:
        progressed = False
        for n in list(pending):
            deps = [x for x in n.get("dials", []) if x not in N]
            if deps:
                continue
            N[n["id"]] = mesh.add(n["id"], dial=[N[x] for x in n.get("dials", []) if x in _ids(t, "nodes")])
            pending.remove(n)
            progressed = True
        if not progressed:
            raise MeshError(f"nodes dial each other in a cycle: {[n['id'] for n in pending]}")
    step("nodes", layer="nodes", up={n: N[n].url for n in _ids(t, "nodes")})

    # 4. persons: first node claimed with a minted identity; the rest carried.
    for p in t["persons"]:
        first, *rest = p["owns"]
        alias = f"{p['id']}-person"
        N[first].claim(alias)
        for nid in rest:
            n = N[nid]
            n.stop()
            n.carry_owner_from(N[first], alias)
            n.start()
            n.claim(alias)
        owners = {nid: N[nid].owner_key_id for nid in p["owns"]}
        if len(set(owners.values())) != 1:
            raise MeshError(f"{p['id']}'s devices claimed different owners: {owners}")
        step(f"person:{p['id']}", layer="persons", owner=N[first].owner_key_id, devices=p["owns"],
             proves="one owner key across every declared device")
    for n in t["nodes"]:
        if n.get("announced"):
            N[n["id"]].announce()
        N[n["id"]].self_record()
    step("announced", layer="nodes", announced=[n["id"] for n in t["nodes"] if n.get("announced")])

    # 5. relations, in declared order.
    values: Dict[str, str] = {}
    rooms: Dict[str, str] = {}
    added: set = set()  # (host node id, guest person) pairs already POSTed by a `reachable` gate
    for rel in t["relations"]:
        k = rel["rel"]
        if k == "peered":
            a, b = rel["between"]
            N[a].peer_with(N[b], rel.get("prefixes"))
            N[b].peer_with(N[a], rel.get("prefixes"))
            step(f"peered:{a}<->{b}", layer="relations", proves="production peering both ways")
        elif k == "rooted_with":
            p, q = rel["between"]
            na, nb = N[persons[p]["owns"][0]], N[persons[q]["owns"][0]]
            ok = False
            try:
                wait_for(f"rooted_with({p},{q})", lambda: na.rooted_with(nb) and nb.rooted_with(na),
                         float(rel.get("wait", 0)) or 1, every=3)
                ok = True
            except MeshError:
                pass
            if ok:
                step(f"rooted_with:{p}<->{q}", layer="relations", proves="edge found a valid root in common, both ways")
            elif rel.get("require"):
                step.fail(f"NOT_rooted:{p}<->{q}", "the two OWNERS hold no valid root in common (rooted_with walks the "
                          "owner-bindings): attestations between them are withheld", [na, nb],
                          r"rooted_with|root_binding|accept.*root|not Rooted")
                raise MeshError("required rooted_with did not hold")
            else:
                step(f"rooted_with:{p}<->{q}", layer="relations", observed=False,
                     note="not required by this declaration; recorded")
        elif k == "reachable":
            host, q = N[rel["node"]], persons[rel["person"]]
            target = N[q["owns"][0]].owner_key_id
            deadline = time.monotonic() + float(rel.get("wait", 120))
            tries, got = 0, {}
            while True:
                # Known comes before reachable: a 404 (the guest's key has not
                # crossed yet) is "not yet", the same as reachable_nodes=0.
                status, got = host.api("POST", "/v1/contacts", {"key_id": target})
                got = got if isinstance(got, dict) else {}
                tries += 1
                if status == 200 and (got.get("reachable_nodes") or 0) >= int(rel.get("min", 1)):
                    break
                if status not in (200, 404) or time.monotonic() >= deadline:
                    break
                time.sleep(3)
            if (got.get("reachable_nodes") or 0) < int(rel.get("min", 1)):
                step.fail(f"NOT_reachable:{rel['node']}->{rel['person']}",
                          f"{rel['person']}'s owner→node binding is not held on {rel['node']} at federation scope "
                          "(CIRISServer#699): a room made now keys but its bodies read not_granted",
                          [host], r"handshake cannot complete|resolves to no node|reachable")
                raise MeshError("reachable gate did not hold")
            added.add((rel["node"], rel["person"]))
            step(f"reachable:{rel['node']}->{rel['person']}", layer="relations", reachable_nodes=got.get("reachable_nodes"),
                 tries=tries, proves="the guest's binding is held here; the room can address their node")
        elif k == "contact":
            p, q = rel["from"], rel["to"]
            host, guest = N[persons[p]["owns"][0]], N[persons[q]["owns"][0]]
            if rel.get("via", "owner") == "owner" and (persons[p]["owns"][0], q) in added:
                # The `reachable` gate's POST IS the contact. A second POST for a
                # live contact re-issues its grant, and three builds that did so
                # never keyed the room afterwards (2026-09-29); the scenario that
                # posts once keys it in ~7 s. Recorded, not repeated.
                step(f"contact:{p}->{q}", layer="relations", via="owner", added_by="reachable gate")
                continue
            key = guest.owner_key_id if rel.get("via", "owner") == "owner" else guest.contact_code(rel.get("nodes", "all"))
            got = host.add_contact(key)
            step(f"contact:{p}->{q}", layer="relations", via=rel.get("via", "owner"), key=str(got.get("key_id"))[:60],
                 reachable_nodes=got.get("reachable_nodes"))
            if rel.get("via") == "code":
                values["PEER_CONTACT_CODE"] = key
        elif k == "room":
            if rel["kind"] == "pair":
                p, q = rel["members"]
                a, b = N[persons[p]["owns"][0]], N[persons[q]["owns"][0]]
                ca, cb = a.open_pair(b.owner_key_id), b.open_pair(a.owner_key_id)
                if ca != cb:
                    raise MeshError(f"the two sides derived different pair rooms: {ca} vs {cb}")
                rooms[rel.get("id", "pair")] = ca
                # POLL BOTH SIDES EVERY TICK. The joiner's half of the handshake
                # (publish the KeyPackage, consume the Welcome) advances on its
                # transcript reads; a short-circuit `a and b` never read B while
                # A was not ready, so B never published (five builds, 2026-09-29).
                def both_keyed() -> bool:
                    ra, rb = a.room(ca), b.room(ca)
                    return bool(ra["ready"] and rb["ready"])
                try:
                    wait_for("the pair room to key", both_keyed, float(rel.get("wait", 180)), every=3)
                except MeshError:
                    step.fail("room_NOT_keyed", "the MLS handshake did not complete", [a, b], _HANDSHAKE)
                    raise
                step(f"room:{rel.get('id', 'pair')}", layer="relations", room=ca, keyed=True,
                     proves="the same room id on both sides, keyed on both")
            elif rel["kind"] == "self":
                p = rel["person"]
                devs = [N[x] for x in persons[p]["owns"]]
                try:
                    wait_for("every device in the self room",
                             lambda: all(x.grep(r"self room (CREATED|JOINED)") for x in devs),
                             float(rel.get("wait", 180)), every=3)
                except MeshError:
                    step.fail("self_room_NOT_joined", "a device never joined its person's self room", devs,
                              r"self room|KeyPackage|Welcome|Added\(|Rejoin")
                    raise
                step(f"room:self:{p}", layer="relations", devices=persons[p]["owns"], proves="the self room spans every device")
            else:
                raise MeshError(f"room kind {rel['kind']!r}: declared, no builder yet")
        elif k == "message":
            p, q = rel["from"], rel["to"]
            a, b = N[persons[p]["owns"][0]], N[persons[q]["owns"][0]]
            cid = rooms[rel.get("room", "pair")]
            text = f"{rel.get('text', 'hello')} {int(time.time())}"
            att = a.say(cid, text)
            try:
                wait_for("the body on the recipient", lambda: any(
                    m.get("attestation_id") == att and m.get("body") == text for m in b.room(cid)["messages"]),
                    float(rel.get("wait", 120)), every=2)
            except MeshError:
                mine = [m for m in b.room(cid)["messages"] if m.get("attestation_id") == att]
                step.fail("body_NOT_arrived", "the row may be here but its BODY did not open on the recipient",
                          [a, b], _BODY, row_on_recipient=mine[:1])
                raise
            step(f"message:{p}->{q}", layer="relations", attestation_id=att,
                 proves="the row and its body on the other person's node")
            values.update({"ROOM_ID": cid, "MESSAGE_TEXT": text, "MESSAGE_ATTESTATION_ID": att, "MESSAGE_ARRIVED": "true"})
        elif k == "file":
            p = rel["person"]
            devs = persons[p]["owns"]
            src = N[rel.get("device", devs[0])]
            data = hashlib.sha256(b"seed").digest() * max(1, int(rel.get("size", 4096)) // 32)
            got = src.write_file(data, rel.get("media_type", "application/octet-stream"), rel.get("name", "topology.bin"))
            fid = got["attestation_id"]
            for other in devs:
                if other == src.name:
                    continue
                dev = N[other]
                try:
                    wait_for(f"{other} to open the file", lambda: dev.read_raw(fid)[0] == 200, float(rel.get("wait", 240)), every=5)
                except MeshError:
                    st, body = dev.read_raw(fid)
                    step.fail(f"file_NOT_open:{other}", "the second device did not open the file", [src, dev],
                              _BODY + r"|stalled mid-frame|not_in_room", status=st, body=body[:160].decode(errors="replace"))
                    raise
                st, raw = dev.read_raw(fid)
                if raw != data:
                    step.fail(f"file_WRONG_BYTES:{other}", f"{len(raw)} bytes back for {len(data)} written", [src, dev], _BODY)
                    raise MeshError("bytes differ")
            step(f"file:{p}", layer="relations", size=len(data), devices=devs, proves="byte-identical on every device")
        else:
            raise MeshError(f"relation {k!r}: declared, no builder yet")

    # 6. negatives.
    for neg in t.get("negatives", []):
        if neg["check"] == "cannot_list_room":
            n = N[persons[neg["person"]]["owns"][0]]
            st, _ = n.api("GET", f"/v1/chat/{rooms[neg.get('room', 'pair')]}/messages")
            if st == 200:
                raise MeshError(f"NEGATIVE FAILED: {neg['person']} can list the room")
            step(f"negative:cannot_list_room:{neg['person']}", layer="negatives", status=st)
        elif neg["check"] == "holds_no_row":
            n = N[neg["node"]]
            pid = N[persons[neg["person"]]["owns"][0]].owner_key_id
            rows = n.rows("select attestation_id, attestation_envelope from federation_attestations")
            hits = [a for a, env in rows if (env or "").find(neg["dimension"]) >= 0 and pid in (env or "")]
            if hits:
                raise MeshError(f"NEGATIVE FAILED: {neg['node']} holds {len(hits)} {neg['dimension']} rows of {neg['person']}")
            step(f"negative:holds_no_row:{neg['node']}", layer="negatives", dimension=neg["dimension"], control=len(rows))

    # the actor's view, in the client fixture's shape
    act = t["actor"]
    me = N[act["device"]]
    others = [p for p in persons if p != act["person"]]
    if others:
        peer = N[persons[others[0]]["owns"][0]]
        values.update({"PEER_URL": peer.url, "PEER_KEY_ID": peer.owner_key_id, "PEER_NODE_KEY_ID": peer.node_key_id,
                       "PEER_OWNER_KEY_ID": peer.owner_key_id})
    values.update({"LOCAL_OWNER_KEY_ID": me.owner_key_id, "LOCAL_NODE_KEY_ID": me.node_key_id})
    return {"verdict": "PASS", "steps": step.log, "derived": d, "values": values}
