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
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .mesh import Mesh, MeshError, Node, wait_for
from .scenarios import Steps, _BODY, _HANDSHAKE

Decl = Dict[str, Any]

# What the synthetic anchor mints today (src/test_bless.rs): ONE key root, ONE
# software holder, lifecycle active. Everything else is declared and refused.
BUILDABLE_ROOT = {"kind": "key", "holders": 1, "custody": "software_test",
                  "lifecycle": {"recipe": {}, "verdict": "rooted"}}

LAYERS = ["roots", "canonicals", "nodes", "persons", "relations", "actor", "negatives"]
LAST_STEPS: Any = None  # the running build's Steps, so a failure can name its first failing layer


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
            raise Unrealizable(f"root {r['id']}: kind `family` (the accord family, CC 4.2.6) has no model "
                               "behind it and is not a trust root the harness can mint — use `key` or `infrastructure`")
        if r.get("kind") == "infrastructure":
            f, m = r.get("founders", {}), r.get("quorum", 0)
            if f.get("seated", 0) < m + 1:
                raise Unrealizable(f"rule 1: root {r['id']} quorum {m} needs founders.seated >= {m + 1} (T7)")
            if f.get("conferrable", 0) < 1:
                raise Unrealizable(f"rule 1: root {r['id']} needs founders.conferrable >= 1, or T7 recovery has nobody to widen in")
            w = r.get("witnesses")
            if w:
                if "k" in w:
                    raise Unrealizable(f"rule 1: root {r['id']}: `k` is derived (CC T6: K = floor(n/2)+1), not declared")
                if not w.get("independent_custody"):
                    raise Unrealizable(f"rule 1: root {r['id']} witnesses need independent_custody")
        lc = r.get("lifecycle")
        if isinstance(lc, str):
            raise Unrealizable(f"root {r['id']}: lifecycle is a row recipe + asserted verdict, e.g. "
                               "{recipe: {resignations: 1}, verdict: stalled}, not the flag {lc!r}")
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


def _root_derived(r: Decl) -> Decl:
    """The model constants CC derives from the block (CIRISConstitution#131)."""
    out: Decl = {}
    w = r.get("witnesses") or {}
    if w.get("n"):
        out["K"] = w["n"] // 2 + 1
    c = r.get("charter") or {}
    if c.get("attach_window_secs") and c.get("witness_cadence_secs"):
        out["AttachWindow"] = -(-c["attach_window_secs"] // c["witness_cadence_secs"])
    f = r.get("founders") or {}
    if f:
        out["Founders"] = f.get("seated", 0) + f.get("conferrable", 0)
        out["NodeKeys"] = f.get("node_bearing", 0)
    return out


def derive(t: Decl) -> Decl:
    persons = _ids(t, "persons")
    return {
        "nodes": len(t["nodes"]) + len(t["canonicals"]),
        "persons": len(persons),
        "devices": {p: len(v["owns"]) for p, v in persons.items()},
        "roots": [{**{k: r.get(k) for k in ("id", "kind", "holders", "founders", "quorum", "witnesses", "charter", "lifecycle", "custody")},
                   "derived": _root_derived(r)} for r in t["roots"]],
        "direct_links": [(n["id"], d) for n in t["nodes"] for d in n.get("dials", []) if d not in _ids(t, "canonicals")],
        "build_order": LAYERS,
        "not_buildable_yet": check(t),
    }


# ── build ───────────────────────────────────────────────────────────────────


def export_rows(mesh: Mesh) -> Decl:
    """Per node: every admitted federation row, in admission order, as JSONL —
    the fold-replayable form (FSD/TOPOLOGY.md §4.1)."""
    out: Decl = {}
    for name, n in mesh.nodes.items():
        rows = n.rows("select * from federation_attestations order by rowid")
        cols = n.rows("select name from pragma_table_info('federation_attestations') order by cid")
        colnames = [c[0] for c in cols]
        path = n.log_path.parent / "rows.jsonl"
        h = hashlib.sha256()
        with open(path, "w", encoding="utf-8") as f:
            for row in rows:
                line = json.dumps(dict(zip(colnames, row)), default=str, sort_keys=True)
                f.write(line + "\n")
                h.update(line.encode())
        # The signed routes this node holds (persist `transport_destinations`,
        # one row per (occurrence, transport_kind); CIRISEdge#722): the
        # #393 item-2 gate reads attesting_key_id / signed_envelope / signature.
        routes = n.rows("select occurrence_key_id, transport_kind, attesting_key_id, "
                        "signed_envelope is not null, signature is not null, "
                        "length(signed_envelope), length(signature) from transport_destinations")
        (n.log_path.parent / "transport_destinations.jsonl").write_text(
            "\n".join(json.dumps(dict(zip(("occurrence_key_id", "transport_kind", "attesting_key_id",
                                            "signed_envelope_present", "signature_present",
                                            "signed_envelope_len", "signature_len"), r)), default=str) for r in routes),
            encoding="utf-8")
        # The node's metrics snapshot (GET /v1/federation/metrics): edge's
        # counters — blob_pull_sources, blob_pull_refusals,
        # channel_first_skipped_over_cap (CIRISEdge#722) — as the node last
        # reported them, beside the rows they explain.
        try:
            st_, metrics = n.api("GET", "/v1/federation/metrics", timeout=20)
            (n.log_path.parent / "metrics.json").write_text(json.dumps(metrics if st_ == 200 else {"status": st_}, indent=1, default=str), encoding="utf-8")
        except Exception as e:  # noqa: BLE001
            (n.log_path.parent / "metrics.json").write_text(json.dumps({"error": str(e)[:200]}), encoding="utf-8")
        keys = n.rows("select key_id, identity_type, valid_from, valid_until, scrub_key_id from federation_keys")
        (n.log_path.parent / "keys.jsonl").write_text(
            "\n".join(json.dumps(dict(zip(("key_id", "identity_type", "valid_from", "valid_until", "scrub_key_id"), k)), default=str) for k in keys),
            encoding="utf-8")
        # CC's two per-node additions (CIRISConstitution#131): the standing
        # verdict for each root, and the witnessed head digest + instant.
        tr = n.trust_roots() if n.token or True else {}
        roots = tr.get("roots") if isinstance(tr, dict) else None
        standing = {r.get("root_key_id"): {
            "standing": (r.get("verdict") or {}).get("standing"),
            "valid": (r.get("verdict") or {}).get("valid"),
            "accepted": r.get("accepted"),
            "lineage_head": (r.get("verdict") or {}).get("lineage_head"),
        } for r in (roots or [])} if roots else {"unreadable": tr}
        out[name] = {"rows": len(rows), "keys": len(keys), "routes": len(routes), "sha256": h.hexdigest(), "path": str(path),
                     "roots": standing}
    return out


def build(mesh: Mesh, t: Decl, args: Any) -> Decl:
    try:
        return _build(mesh, t, args)
    except MeshError as e:
        ff = getattr(LAST_STEPS, "first_failure", None) if LAST_STEPS else None
        raise MeshError(json.dumps({"error": str(e), "first_failing_layer": ff})) from e
    finally:
        try:
            exported = export_rows(mesh)
            print(json.dumps({"step": "rows_exported", "layer": "export", **{k: {kk: vv for kk, vv in v.items() if kk != "path"} for k, v in exported.items()}}), flush=True)
            (mesh.work / "rows_export.json").write_text(json.dumps(exported, indent=1), encoding="utf-8")
        except Exception as e:  # noqa: BLE001 — the export must never mask the verdict
            print(json.dumps({"step": "rows_export_failed", "error": str(e)[:200]}), flush=True)


def _build(mesh: Mesh, t: Decl, args: Any) -> Decl:
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
    global LAST_STEPS
    LAST_STEPS = step
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
    # A claimed node that dials a canonical also PEERS with it — the owner's
    # HTTP act in production (`POST /v1/federation/peering` with the canonical's
    # record, traceflow_prod.sh step 7, after claim + announce; the baked seed
    # primes the canonical's key on a production node,
    # `compose::prime_canonical_bootstrap_peers`). Dialling alone makes the
    # canonical a Reticulum relay and nothing more: no round ever targets an
    # unkeyed peer, so the canonical admits no node key, roots with nobody and
    # distributes nothing (edge's v34.3.0 run: the canonical's keys.jsonl held
    # only its own key; every relation rode the direct links).
    peered_canonicals = []
    for n in t["nodes"]:
        for c in n.get("dials", []):
            if c in _ids(t, "canonicals"):
                N[n["id"]].peer_with(N[c])
                peered_canonicals.append((n["id"], c))
    step("canonical_peered", layer="nodes", pairs=peered_canonicals,
         proves="every claimed node holds the record of the canonical it dials, as the owner's peering act leaves it in production")

    # 5. relations, in declared order.
    values: Dict[str, str] = {}
    rooms: Dict[str, str] = {}
    added: set = set()  # (host node id, guest person) pairs already POSTed by a `reachable` gate
    # Files the relations wrote, for a later `custody` relation: `last` is the
    # most recent `file` (or the last file a `corpus` wrote); a corpus file is
    # also named by its manifest name (`large`, `inline_over`, ...). Each entry
    # records the device it was written on — the AUTHOR device, the one whose
    # store admits every delivery receipt.
    files_written: Dict[str, Dict[str, Any]] = {}
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
                          r"rooted_with|root_binding|accept.*root|not Rooted",
                          layer="relations", rel="rooted_with", cc="CC 3.2 / CIRISEdge#659")
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
                          [host], r"handshake cannot complete|resolves to no node|reachable",
                          layer="relations", rel="reachable", cc="CC 5.2")
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
                values["ROOM_ID"] = ca
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
                    step.fail("room_NOT_keyed", "the MLS handshake did not complete", [a, b], _HANDSHAKE,
                              layer="relations", rel="room", cc="CC 4.4.3")
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
                              r"self room|KeyPackage|Welcome|Added\(|Rejoin",
                              layer="relations", rel="room", cc="CC 4.4.3.2.4")
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
                          [a, b], _BODY, layer="relations", rel="message", cc="CC 5.4.6", row_on_recipient=mine[:1])
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
                              _BODY + r"|stalled mid-frame|not_in_room", layer="relations", rel="file", cc="CC 5.4.6",
                              status=st, body=body[:160].decode(errors="replace"))
                    raise
                st, raw = dev.read_raw(fid)
                if raw != data:
                    step.fail(f"file_WRONG_BYTES:{other}", f"{len(raw)} bytes back for {len(data)} written", [src, dev], _BODY,
                              layer="relations", rel="file", cc="CC 5.3.2.5")
                    raise MeshError("bytes differ")
            files_written["last"] = {"id": fid, "device": src.name, "size": len(data), "person": p}
            step(f"file:{p}", layer="relations", size=len(data), devices=devs, proves="byte-identical on every device")
        elif k == "bigfile":
            # ONE self file of `size` bytes (CIRISEdge#734 lane 7 asked for the
            # end-to-end that includes the drive; edge benches the wire alone):
            # written on `device` as streamed multipart, timed; pulled by every
            # other device, timed from the row's arrival (`/meta` 200) to its
            # byte-state `here`; read back through a streamed `?raw=1` and
            # compared by SHA-256 — the bytes never sit in this process.
            # `resume_at: 0.5` stops the puller once its home has grown by that
            # fraction of the file and restarts it; the pull must then finish.
            # Byte-identical and timed is the claim; the numbers are recorded,
            # never asserted — a floor belongs in the CSD, not here.
            #
            # CEILING (server-owned, named by the step): since 0.5.218 the
            # drive STREAMS both doors — a multipart upload with a `size` field
            # before the `file` part goes through edge's `files::publish_stream`
            # (CIRISEdge#744) and `?raw=1` above 64 MiB streams back through
            # `FileRow::chunks()` (#737). The ceiling is `drive.rs`
            # `STREAMED_FILE_CEILING` = edge's stated ~2.5 GiB single-file limit
            # (persist's inline manifest cap until persist v52), with
            # `STREAMED_UPLOAD_BODY_LIMIT` = that + 1 MiB of form. A 413 here is
            # a file above THAT, or an upload that omitted `size` (which falls
            # back to the 64 MiB whole-buffered cap, `UPLOAD_BODY_LIMIT` for
            # the JSON form).
            import random
            p = rel["person"]
            devs = persons[p]["owns"]
            src = N[rel.get("device", devs[0])]
            size = int(rel.get("size", 2 << 30))
            seed = int(rel.get("seed", 7))
            blob = mesh.work / f"bigfile-{size}.bin"
            h = hashlib.sha256()
            if not blob.exists() or blob.stat().st_size != size:
                rng = random.Random(seed)
                with open(blob, "wb") as f:
                    left = size
                    while left:
                        piece = rng.randbytes(min(1 << 20, left))
                        f.write(piece)
                        h.update(piece)
                        left -= len(piece)
                want_sha = h.hexdigest()
                (blob.with_suffix(".sha256")).write_text(want_sha)
            else:
                want_sha = blob.with_suffix(".sha256").read_text().strip()
            t0 = time.monotonic()
            st, got = src.write_file_streamed(blob, rel.get("media_type", "application/octet-stream"),
                                              rel.get("name", f"bigfile-{size}.bin"))
            publish_s = time.monotonic() - t0
            if st == 413:
                step.fail(f"bigfile_REFUSED_BY_DRIVE:{p}",
                          f"the drive refused {size} bytes with 413: above STREAMED_FILE_CEILING (edge's ~2.5 GiB "
                          "single-file limit, persist's inline manifest cap until v52), or the upload carried no `size` "
                          "field and fell back to the 64 MiB whole-buffered cap", [src],
                          r"413|payload too large|drive\.too_large|STREAMED_FILE_CEILING", layer="relations", rel="bigfile", cc="CC 5.3.2.5",
                          size=size, status=st, body=str(got)[:200])
                raise MeshError("bigfile refused by the drive's body limit")
            if st not in (200, 201):
                step.fail(f"bigfile_NOT_WRITTEN:{p}", f"POST /v1/files answered {st}", [src], _BODY,
                          layer="relations", rel="bigfile", cc="CC 5.3.2.5", size=size, status=st, body=str(got)[:200])
                raise MeshError(f"bigfile write answered {st}")
            fid = got["attestation_id"]
            seal_lines = src.grep(r"chunk|sealed|publish")[-3:]
            timings: Dict[str, Any] = {"size": size, "publish_s": round(publish_s, 2),
                                       "publish_MiB_s": round(size / (1 << 20) / max(publish_s, 1e-6), 1),
                                       "sha256": want_sha, "attestation_id": fid, "seal_evidence": seal_lines, "pulls": {}}
            resume_at = rel.get("resume_at")
            deadline = time.monotonic() + float(rel.get("wait", 3600))
            for other in devs:
                if other == src.name:
                    continue
                dev = N[other]
                base_disk = dev.disk_bytes()
                t_row = t_here = None
                resumed = False
                state = None
                while time.monotonic() < deadline:
                    ms, meta = dev.file_meta(fid)
                    if ms == 200 and t_row is None:
                        t_row = time.monotonic()
                    # `bytes` is the drive's byte-state word (`drive::BYTE_STATES`:
                    # here | not_fetched | not_granted | …), the same word `GET /v1/drive` uses.
                    state = meta.get("bytes") if isinstance(meta, dict) else None
                    if ms == 200 and state == "here":
                        t_here = time.monotonic()
                        break
                    if resume_at and not resumed and t_row is not None and dev.disk_bytes() - base_disk >= resume_at * size:
                        dev.stop()
                        time.sleep(2)
                        dev.start()
                        resumed = True
                        timings["pulls"][other] = {"resumed_at_bytes": dev.disk_bytes() - base_disk}
                    time.sleep(2)
                if t_here is None:
                    step.fail(f"bigfile_NOT_PULLED:{other}",
                              f"the file never reached byte-state `here` on {other} (last meta state {state!r}, "
                              f"{dev.disk_bytes() - base_disk} bytes grown)", [src, dev],
                              _BODY + r"|chunk|DAG|manifest|not_fetched", layer="relations", rel="bigfile", cc="CC 5.4.6",
                              size=size, resumed=resumed)
                    raise MeshError("bigfile not pulled")
                t1 = time.monotonic()
                rs, sha, n, body = dev.read_raw_digest(fid)
                read_s = time.monotonic() - t1
                if rs != 200 or sha != want_sha or n != size:
                    step.fail(f"bigfile_WRONG_BYTES:{other}",
                              f"{other} read {n} bytes (status {rs}) sha {sha[:16]}… for {size} bytes sha {want_sha[:16]}…",
                              [src, dev], _BODY + r"|seal_mismatch|chunk", layer="relations", rel="bigfile", cc="CC 5.3.2.5",
                              status=rs, body=body[:160].decode(errors="replace"))
                    raise MeshError("bigfile bytes differ")
                pull_s = t_here - (t_row or t0)
                timings["pulls"][other] = {**timings["pulls"].get(other, {}),
                                           "row_seen_after_s": round((t_row or t_here) - t0, 2),
                                           "pull_s": round(pull_s, 2), "pull_MiB_s": round(size / (1 << 20) / max(pull_s, 1e-6), 1),
                                           "read_s": round(read_s, 2), "read_MiB_s": round(size / (1 << 20) / max(read_s, 1e-6), 1),
                                           "resumed": resumed}
            values[f"BIGFILE_ATTESTATION_ID"] = fid
            step(f"bigfile:{p}", layer="relations", **timings,
                 proves="one file of the declared size, streamed in, pulled by every other device"
                        + (" (one of them restarted mid-pull)" if resume_at else "") + ", read back streamed, SHA-256 equal")
        elif k == "roster":
            # THE DEVICE ROSTER (CSD-037, CIRISServer#655 per-device announce
            # ruling): every device of the person lists every device of the
            # person; a node that is not the person's sees the ANNOUNCED
            # devices only — never an unannounced one.
            p = rel["person"]
            devs = persons[p]["owns"]
            pid = N[devs[0]].owner_key_id
            want = {N[d].node_key_id for d in devs}
            def roster_of(n: Node) -> set:
                st, body = n.api("GET", f"/v1/self/occurrences?identity_key_id={pid}")
                return {o.get("occurrence_key_id") for o in (body.get("occurrences") or [])} if st == 200 and isinstance(body, dict) else set()
            try:
                wait_for(f"{p}'s devices to list each other", lambda: all(want <= roster_of(N[d]) for d in devs),
                         float(rel.get("wait", 120)), every=5)
            except MeshError:
                step.fail(f"roster_NOT_complete:{p}", "a device of the person does not list every other device — the "
                          "identity occurrences did not converge across the person's nodes", [N[d] for d in devs],
                          r"occurrence|IdentityOccurrence|roster", layer="relations", rel="roster", cc="CC 2.1",
                          seen={d: sorted(roster_of(N[d])) for d in devs})
                raise
            seen_by_outsiders = {}
            announced = {N[d].node_key_id for d in devs if next(x for x in t["nodes"] if x["id"] == d).get("announced")}
            # `visible_from_complete: true` (default false, so a topology that
            # did not declare it keeps the leak-only semantics): an outsider
            # must list ALL of the person's announced devices, not a subset.
            # CC 5.4.6 (CIRISConstitution#111) — "a person is contactable
            # through the nodes they chose to announce, and that set IS their
            # public roster" — and the canonical relays them (0.5.218,
            # `announced_relay`), so an outsider that peers only ONE of the
            # person's devices still converges on every announced one.
            complete = bool(rel.get("visible_from_complete", False))
            for o in rel.get("visible_from", []):
                if complete:
                    try:
                        wait_for(f"{o} to list every announced device of {p}",
                                 lambda: announced <= roster_of(N[o]), float(rel.get("wait", 120)), every=5)
                    except MeshError:
                        got = roster_of(N[o])
                        step.fail(f"roster_NOT_public:{p}@{o}", "an outsider does not list every device the person "
                                  "announced — the canonical did not relay an announced device's key/occurrence "
                                  "(CC 5.4.6, announced_relay)", [N[o]] + [N[d] for d in devs],
                                  r"announced relay|IdentityOccurrence|first contact|occurrence",
                                  layer="relations", rel="roster", cc="CC 5.4.6",
                                  seen={o: sorted(got), "announced": sorted(announced),
                                        "missing": sorted(announced - got)})
                        raise
                got = roster_of(N[o])
                unannounced_leak = got - announced
                seen_by_outsiders[o] = {"listed": len(got), "announced": len(announced), "complete_required": complete}
                if unannounced_leak:
                    raise MeshError(f"NEGATIVE FAILED: {o} lists unannounced devices of {p}: {sorted(unannounced_leak)}")
            step(f"roster:{p}", layer="relations", devices=devs, visible_from=seen_by_outsiders,
                 proves="each device lists every device; an outsider sees announced devices only"
                        + (", and ALL of them (CC 5.4.6)" if complete else ""))
        elif k == "note":
            p = rel["person"]
            devs = persons[p]["owns"]
            src = N[rel.get("device", devs[0])]
            text = f"{rel.get('text', 'note to self')} {int(time.time())}"
            got = src.must("POST", "/v1/notes", {"body": text})
            nid = got.get("attestation_id")
            for other in devs:
                if other == src.name:
                    continue
                dev = N[other]
                try:
                    wait_for(f"{other} to list the note", lambda: any(
                        n.get("attestation_id") == nid for n in (dev.must("GET", "/v1/notes?limit=50").get("notes") or [])),
                        float(rel.get("wait", 180)), every=5)
                except MeshError:
                    step.fail(f"note_NOT_listed:{other}", "the note row never reached the other device", [src, dev],
                              _BODY + r"|stalled mid-frame", layer="relations", rel="note", cc="CC 5.2")
                    raise
            step(f"note:{p}", layer="relations", attestation_id=nid, proves="a note written on one device lists on the others")
        elif k == "corpus":
            # The transfer corpus (harness/mesh-repro/lib/media_corpus.py): every
            # file written on one device, read raw on every other device of the
            # person, compared byte for byte. Per file the outcome names its
            # layer: 404 = the ROW never crossed (CIRISEdge#716 on a direct
            # link), 409 = row here, bytes not pulled, 200+wrong = the bytes
            # (CIRISEdge#717 serves a chunk-DAG's manifest), 200+match = opened.
            import subprocess
            p = rel["person"]
            devs = persons[p]["owns"]
            src = N[rel.get("device", devs[0])]
            out = mesh.work / "corpus"
            from .mesh import HARNESS
            subprocess.run([sys.executable, str(HARNESS / "mesh-repro" / "lib" / "media_corpus.py"), str(out)],
                           check=True, capture_output=True)
            manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
            only = set(rel["only"]) if rel.get("only") else None
            written = []
            for row in manifest:
                if only and row["name"] not in only:
                    continue
                data = (out / row["name"]).read_bytes()
                got = src.write_file(data, row["media_type"], row["filename"])
                written.append({**row, "id": got["attestation_id"]})
                files_written[row["name"]] = {"id": got["attestation_id"], "device": src.name,
                                              "size": len(data), "person": p}
                files_written["last"] = files_written[row["name"]]
            step(f"corpus_written:{p}", layer="relations", files=len(written), device=src.name)
            deadline = time.monotonic() + float(rel.get("wait", 300))
            results: Dict[str, Dict[str, Any]] = {w["name"]: {} for w in written}
            pending = {(w["name"], o) for w in written for o in devs if o != src.name}
            while pending and time.monotonic() < deadline:
                for name, other in list(pending):
                    w = next(x for x in written if x["name"] == name)
                    st, raw = N[other].read_raw(w["id"])
                    want = (out / name).read_bytes()
                    r: Dict[str, Any] = {"status": st}
                    if st == 200:
                        r["match"] = raw == want
                        r["size"] = len(raw)
                        if not r["match"]:
                            r["expected"] = len(want)
                            r["first_diff"] = next((i for i in range(min(len(raw), len(want))) if raw[i] != want[i]), min(len(raw), len(want)))
                        pending.discard((name, other))
                    else:
                        try:
                            r["reason_id"] = json.loads(raw.decode()).get("reason_id")
                        except Exception:  # noqa: BLE001
                            r["reason_id"] = raw[:80].decode(errors="replace")
                    results[name][other] = r
                if pending:
                    time.sleep(5)
            opened = [n for n, per in results.items() if per and all(v.get("match") for v in per.values())]
            by_class: Dict[str, List[str]] = {"row_never_crossed": [], "bytes_not_pulled": [], "wrong_bytes": [], "refused": []}
            for n, per in results.items():
                for other, v in per.items():
                    if v.get("match"):
                        continue
                    if v.get("status") == 404:
                        by_class["row_never_crossed"].append(f"{n}@{other}")
                    elif v.get("status") == 409:
                        by_class["bytes_not_pulled"].append(f"{n}@{other}")
                    elif v.get("status") == 200:
                        by_class["wrong_bytes"].append(f"{n}@{other}:{v.get('size')}/{v.get('expected')}")
                    else:
                        by_class["refused"].append(f"{n}@{other}:{v.get('status')}:{v.get('reason_id')}")
            step(f"corpus_compared:{p}", layer="relations", opened=len(opened), total=len(written),
                 **{k: v for k, v in by_class.items() if v},
                 proves="each corpus file byte-identical on every other device of the person")
            if len(opened) != len(written):
                means = []
                if by_class["row_never_crossed"]:
                    means.append("rows never reached the other device — the direct link stalls multi-fragment frames (CIRISEdge#716)")
                if by_class["bytes_not_pulled"]:
                    means.append("rows arrived, bytes not pulled — the derived-address pull (CC 5.4.6 / CIRISEdge#499)")
                if by_class["wrong_bytes"]:
                    means.append("bytes returned differ — a chunk-DAG's manifest served as the file (CIRISEdge#717)")
                if by_class["refused"]:
                    means.append("refused by name — drive.seal_mismatch is the drive refusing #717's manifest")
                step.fail(f"corpus_NOT_opened:{p}", "; ".join(means), [src] + [N[o] for o in devs if o != src.name],
                          _BODY + r"|stalled mid-frame|seal_mismatch", layer="relations", rel="corpus", cc="CC 5.3.2.5")
                if rel.get("require", True):
                    raise MeshError("corpus did not open byte-identical on every device")
        elif k == "withdraw":
            # A WITHDRAWN FILE IS GONE EVERYWHERE (CC 2.3): the author withdraws a
            # file the person's other devices already hold, and every one of them
            # must then read it 410 `withdrawn` — never the bytes. Caught a real
            # leak on the v53 pin (edge #763's `custody:ack here` counted as a live
            # binding, so a holder kept reading and serving a withdrawn file).
            p = rel["person"]
            devs = persons[p]["owns"]
            which = rel.get("file", "last")
            if which not in files_written:
                raise MeshError(f"withdraw: no file {which!r} was written before this relation")
            f = files_written[which]
            cohort = rel.get("cohort", "self")
            src = N[rel.get("device", f["device"])]
            others = [N[o] for o in devs if o != src.name]
            wait = float(rel.get("wait", 180))
            for o in others:
                wait_for(f"{o.name} to hold {which} before the withdrawal",
                         lambda o=o: o.read_raw(f["id"], cohort)[0] == 200, wait, every=5)
            st, got = src.api("DELETE", f"/v1/files/{f['id']}?cohort={cohort}")
            if st != 200:
                step.fail(f"withdraw_REFUSED:{which}", f"the author's withdrawal answered {st}", [src],
                          r"withdraw", layer="relations", rel="withdraw", cc="CC 2.3", body=got)
                raise MeshError("the author could not withdraw the file")
            last: Dict[str, int] = {}

            def gone_everywhere() -> bool:
                for o in others:
                    last[o.name] = o.read_raw(f["id"], cohort)[0]
                return all(code == 410 for code in last.values())
            try:
                wait_for(f"every other device to read {which} as withdrawn", gone_everywhere, wait, every=5)
            except MeshError:
                step.fail(f"withdraw_LEAKED:{which}",
                          "a device that held the file still reads it after its author withdrew it — the "
                          "withdrawal did not reach it, or a binding on that device outlives the tombstone",
                          [src] + others, r"withdraw|custody_ack|tombstone",
                          layer="relations", rel="withdraw", cc="CC 2.3", reads=dict(last))
                raise
            step(f"withdraw:{which}", layer="relations", author=src.name, reads=dict(last),
                 proves="a withdrawn file reads 410 on every device that held it")
        elif k == "custody":
            # WHERE THE FILE IS (FSD/FILE_CUSTODY.md): `GET /v1/files/{id}/custody`
            # on the AUTHOR device must name every other device of the person as
            # `received` (a delivery receipt, CC 5.3.3.6 — signed by the puller on
            # its DAG pull, admitted here by the bridge) and count the person's
            # devices. `file: last | <corpus name>` picks the file. Only a chunk
            # DAG (> 1 MiB) carries receipts at this pin; an inline file answers
            # `receipts_supported: false` and fails this relation by name.
            p = rel["person"]
            devs = persons[p]["owns"]
            which = rel.get("file", "last")
            if which not in files_written:
                raise MeshError(f"custody: no file {which!r} was written before this relation "
                                f"(have: {sorted(files_written)}) — declare a `file` or `corpus` first")
            f = files_written[which]
            src = N[rel.get("device", f["device"])]
            others = [N[o] for o in devs if o != src.name]
            want = {o.node_key_id for o in others}
            path = f"/v1/files/{f['id']}/custody?cohort={rel.get('cohort', 'self')}"
            seen: Dict[str, Any] = {}

            def all_received() -> bool:
                st, got = src.api("GET", path)
                seen.clear()
                seen.update({"status": st, "body": got})
                if st != 200 or not isinstance(got, dict):
                    return False
                if got.get("receipts_supported") is False:
                    return True  # answered below by name: an inline file has no receipt to wait for
                received = {d.get("node_key_id") for d in got.get("devices", []) if d.get("holds") == "received"}
                return want <= received
            try:
                wait_for(f"{src.name}'s custody of {which} to name every other device as received",
                         all_received, float(rel.get("wait", 180)), every=5)
            except MeshError:
                body = seen.get("body") if isinstance(seen.get("body"), dict) else {}
                step.fail(f"custody_NOT_received:{which}",
                          "the author device holds no delivery receipt from the other device — the puller did not "
                          "sign one (on_dag_pulled), the receipt row did not cross, or the bridge refused it",
                          [src] + others, r"delivery receipt|NOT receipted|delivery_receipt|receipt_",
                          layer="relations", rel="custody", cc="CC 5.3.3.6", status=seen.get("status"),
                          devices=(body or {}).get("devices"), why=(body or {}).get("why"),
                          other_keys=(body or {}).get("receipts_from_other_keys"))
                raise
            got = seen["body"]
            if got.get("receipts_supported") is False:
                step.fail(f"custody_INLINE:{which}",
                          f"{which} is an inline file ({got.get('receipts_unsupported_reason')}) — it carries no "
                          "delivery receipt at this pin; name a chunk-DAG file (> 1 MiB)",
                          [src], r"custody", layer="relations", rel="custody", cc="CC 5.3.3.6", why=got.get("why"))
                raise MeshError("custody: an inline file has no receipts to assert")
            if got.get("devices_total") != len(devs):
                step.fail(f"custody_WRONG_TOTAL:{which}",
                          f"devices_total {got.get('devices_total')} for a person owning {len(devs)} devices",
                          [src], r"custody|nodes_owned_by", layer="relations", rel="custody", cc="CC 5.2",
                          devices=got.get("devices"))
                raise MeshError("custody devices_total differs from the person's device count")
            step(f"custody:{which}", layer="relations", device=src.name, devices_total=got.get("devices_total"),
                 received=[d["node_key_id"] for d in got["devices"] if d.get("holds") == "received"],
                 held_here=got.get("held_here"), copies_observable=got.get("copies_observable"),
                 proves="the author device's custody names every other device of the person as received")
        elif k == "session":
            # ONE DEVICE HANDLES EACH EXCHANGE (CC 3.1.3.1, FSD/SESSION_CLAIMS.md):
            # the person is active on `device` (every owner-bearer request marks
            # the device attended — `resolve_bearer`), and every device of the
            # person must name the SAME handler for every exchange it lists on
            # `GET /v1/self/sessions`. Non-vacuous: at least one exchange must be
            # listed (the self room's commit duty or a re-wrap, claimed when the
            # second device joined and renewed while the person stays); an empty
            # list on every device proves nothing and fails by name.
            p = rel["person"]
            devs = persons[p]["owns"]
            src = N[rel.get("device", devs[0])]

            def handlers(n: Node) -> Dict[Tuple[str, str], str]:
                st, body = n.api("GET", "/v1/self/sessions")
                if st != 200 or not isinstance(body, dict):
                    return {}
                return {(x.get("community_id"), x.get("session_id")): x.get("handler_occurrence_key_id")
                        for x in (body.get("sessions") or [])}

            seen: Dict[str, Dict[Tuple[str, str], str]] = {}

            def agree() -> bool:
                src.api("GET", "/v1/self/sessions")  # the person's activity on `device`
                for d in devs:
                    seen[d] = handlers(N[d])
                first = seen[devs[0]]
                return bool(first) and all(seen[d] == first for d in devs)

            try:
                wait_for(f"{p}'s devices to name one handler per exchange", agree,
                         float(rel.get("wait", 180)), every=5)
            except MeshError:
                empty = all(not v for v in seen.values())
                step.fail(f"session_NOT_agreed:{p}",
                          "no device lists any claimed exchange — nothing was ever gated, or the claim "
                          "never crossed (session:claim:v1 rides the self plane)" if empty else
                          "the person's devices name DIFFERENT handlers for one exchange — two devices "
                          "would act", [N[d] for d in devs],
                          r"session claim|session:claim|handled by occurrence|unclaimed", layer="relations",
                          rel="session", cc="CC 3.1.3.1",
                          seen={d: {f"{c[:12]}/{s_}": h for (c, s_), h in v.items()} for d, v in seen.items()})
                if rel.get("require", True):
                    raise
            else:
                one = seen[devs[0]]
                step(f"session:{p}", layer="relations", device=src.name, exchanges=len(one),
                     handlers=sorted({h for h in one.values()}),
                     proves="every device of the person names the same handler for each exchange")
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
            # The outsider holds no self-plane row of the person — and the check
            # is non-vacuous only if the outsider holds SOMETHING from the
            # person's keys (peering, owner-binding): a node nothing reached is
            # not evidence (the selffiles ladder's first outsider was exactly that).
            n = N[neg["node"]]
            keys = {N[d].owner_key_id for d in persons[neg["person"]]["owns"]} | {N[d].node_key_id for d in persons[neg["person"]]["owns"]}
            pid = N[persons[neg["person"]]["owns"][0]].owner_key_id
            rows = n.rows("select attestation_id, attesting_key_id, attestation_envelope from federation_attestations")
            control = sum(1 for _, att, _ in rows if att in keys)
            hits = [a for a, _, env in rows if (env or "").find(neg["dimension"]) >= 0 and pid in (env or "")]
            if hits:
                raise MeshError(f"NEGATIVE FAILED: {neg['node']} holds {len(hits)} {neg['dimension']} rows of {neg['person']}")
            if control == 0:
                raise MeshError(f"NEGATIVE VACUOUS: {neg['node']} holds nothing at all from {neg['person']}'s keys — peer it as a contact")
            step(f"negative:holds_no_row:{neg['node']}", layer="negatives", dimension=neg["dimension"], control=control,
                 proves="a peered outsider holds the person's public rows and none of their self plane")
        elif neg["check"] == "no_wider_self_rows":
            # On the person's OWN devices, every self-plane row (file:v1, or a
            # chat:* row naming the owner) stays at cohort_scope self — a wider
            # row is the file's existence distributed past the person
            # (CIRISPersist#919's shape).
            pid = N[persons[neg["person"]]["owns"][0]].owner_key_id
            wide: Dict[str, List[str]] = {}
            for d in persons[neg["person"]]["owns"]:
                rows = N[d].rows("select attestation_id, cohort_scope, attestation_envelope from federation_attestations")
                bad = [f"{a[:18]}@{sc}" for a, sc, env in rows
                       if (('"dimension": "file:v1"' in (env or "") or '"dimension":"file:v1"' in (env or ""))
                           or ('"dimension": "chat:' in (env or "") and pid in (env or ""))) and sc != "self"]
                if bad:
                    wide[d] = bad[:8]
            if wide:
                raise MeshError(f"NEGATIVE FAILED: self-plane rows wider than self on the person's own devices: {wide}")
            step(f"negative:no_wider_self_rows:{neg['person']}", layer="negatives", devices=persons[neg["person"]]["owns"],
                 proves="every self-plane row on the person's devices is at cohort_scope self")

    # the actor's view, in the client fixture's shape — KEYED BY DECLARED ID
    # (CIRISClient#134 §1): `PERSON_<id>_OWNER_KEY_ID`, `NODE_<id>_URL`, …;
    # the positional PEER_* names stay as aliases for the first non-actor
    # person. `notes` names every value a flow might expect that this
    # declaration did not produce.
    act = t["actor"]
    me = N[act["device"]]
    for pid, p in persons.items():
        first = N[p["owns"][0]]
        values[f"PERSON_{pid.upper()}_OWNER_KEY_ID"] = first.owner_key_id
        values[f"PERSON_{pid.upper()}_DEVICES"] = ",".join(p["owns"])
    for nid, node in N.items():
        values[f"NODE_{nid.upper()}_URL"] = node.url
        values[f"NODE_{nid.upper()}_KEY_ID"] = node.node_key_id or node.key_id
    others = [p for p in persons if p != act["person"]]
    if others:
        peer = N[persons[others[0]]["owns"][0]]
        values.update({"PEER_URL": peer.url, "PEER_KEY_ID": peer.owner_key_id, "PEER_NODE_KEY_ID": peer.node_key_id,
                       "PEER_OWNER_KEY_ID": peer.owner_key_id, "PEER_PERSON": others[0]})
    else:
        step.notes.append("no PEER_*: the declaration has one person")
    values.update({"LOCAL_OWNER_KEY_ID": me.owner_key_id, "LOCAL_NODE_KEY_ID": me.node_key_id,
                   "ACTOR_PERSON": act["person"], "ACTOR_DEVICE": act["device"]})
    for want in ("ROOM_ID", "MESSAGE_ATTESTATION_ID", "PEER_CONTACT_CODE"):
        if want not in values:
            step.notes.append(f"no {want}: the declaration has no relation that produces it")
    return {"verdict": "PASS", "steps": step.log, "derived": d, "values": values, "notes": step.notes}
