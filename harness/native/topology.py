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
import re
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .mesh import Mesh, MeshError, Node, wait_for
from .scenarios import Steps, _BODY, _HANDSHAKE, mint_accord_root

Decl = Dict[str, Any]

# What the harness mints today: the synthetic anchor's ONE key root, ONE
# software holder, lifecycle active (src/test_bless.rs); and, since 0.5.225
# (T8, CSD-129), an INFRASTRUCTURE root minted by the 0.5.220 ceremony over the
# routes with three software holders (`scenarios.mint_accord_root`). Everything
# else is declared and refused.
BUILDABLE_ROOT = {"kind": "key", "holders": 1, "custody": "software_test",
                  "lifecycle": {"recipe": {}, "verdict": "rooted"}}
BUILDABLE_ACCORD_ROOT = {"kind": "infrastructure", "custody": "software_test",
                         "lifecycle": {"recipe": {"ceremony": "final_genesis"}, "verdict": "rooted"}}


def _is_accord_root(r: Decl) -> bool:
    return all(r.get(k) == v for k, v in BUILDABLE_ACCORD_ROOT.items())

# What the builder states it CANNOT build, by name (FSD/CSD4.md §5). The
# model (harness/native/model.py) reads this map, never a copy of it, so a
# catalogue entry carrying one of these relations is built up to it and no
# further — every requirement whose states hold before it is still tested.
REFUSED_RELATIONS: Dict[str, str] = {
    "guardian_bond": "the guardian bond (CC 3.4.13): no server route writes it — family roles are free words "
                     "(src/family_api.rs), CSD-119 drives the route",
    "age_assurance": "POST /v1/safety/age-assurance is authorized by the x-ciris-* HYBRID request signature "
                     "(src/auth/verify.rs), which this harness has no signer for",
    "authority": "a licensing authority affiliation (CSD-120–126, the Registry fold): no server route",
    "delegation": "a delegates_to CHAIN between persons (CC 4.4.3.2.8): POST /v1/auth/device/delegate writes "
                  "owner→actor only, and sub-delegation is the delegate's own act",
    "agent": "a CIRISAgent process hard-bound to the node: the server serves no agent routes without one "
             "(src/py_adapter.rs proxy_routes); halt_agent drives an EXTERNAL agent",
    "steward": "the agent's steward bond (CSD-115): no route yet",
    "wise_authority": "a Wise Authority (CIRISAgent `wa`): no server route",
    # Catalogue v2 (CC topology vocabulary version 2).
    "consent_decay": "the agent's consent decay (identity_severed → patterns_anonymized → complete, CC 3.3.1) "
                     "is a self-report of a CIRISAgent process; no agent runs in this harness",
    "agent_bond": "the agent's bond to its node (CC 1.13.2): needs a CIRISAgent process",
    "agent_act": "the agent's halt gate (CC 4.2.1.1): needs a CIRISAgent process",
    "retirement": "retirement under the Standard (CC 7.5.5): the agent's own ladder; needs a CIRISAgent process",
    "seat_node_bearing": "a node-bearing seat on a SUCCESSOR family head: the anchor mints one family per mesh, "
                         "so there is no successor head to seat it on (one root per mesh, as T9)",
}
# Relations whose route the PRODUCT is missing, each with its open issue. The
# catalogue marks every such step `known_red: <the same issue>` (model.evaluate
# checks they agree), so a plan reports which states wait on which issue; the
# builder raises on them, naming the issue, when asked to build through.
AWAITING_ROUTE: Dict[str, str] = {
    # evict_propose / evict_cosign: built (CIRISServer#794, the quorum path).
    "evict_lone": "CIRISServer#794",      # lone path over W_self: waits on persist's test-anchor W_self seam
    "moderator_lapse": "CIRISServer#795",
    "merit_promote": "CIRISServer#795",
    "invite_window": "CIRISServer#796",   # CC 4.5.13 two-path invitation: window + approval floor
    "consent_grant": "CIRISServer#182",   # consent:state lifecycle; /v1/auth/consent wants a hybrid request signature
    "consent_revoke": "CIRISServer#182",
    "consent_expire": "CIRISServer#182",
    "community_trust": "CIRISServer#790",
    "community_trust_bound": "CIRISServer#790",
    "lineage_head": "CIRISServer#693",    # lineage-head cosign route; a stale head needs one
    "purge": "CIRISServer#756",           # the steward purge surface
    "delegation_withdraw": "CIRISServer#751",
    "delegation_expire": "CIRISServer#751",
    "goals_stage": "CIRISServer#834",      # the Goals ceremony routes (CSD-130); persist #1154
    "goals_propose": "CIRISServer#834",
    "goals_cosign": "CIRISServer#834",
    "goals_amend": "CIRISServer#834",
    "goals_withdraw": "CIRISServer#834",
    "goals_recant": "CIRISServer#834",
}
# Relations whose route EXISTS and whose builder branch is not written yet —
# harness work, not a product defect. Named with the route a branch will drive.
PENDING_BUILDER: Dict[str, str] = {
    "resign": "POST /v1/accord/family/supersede + /cosign (a founder leaves the seated roster); the witness is "
              "persist's hard_case:community_liveness_stalled row, not /v1/trust-root's posture string",
    "confer": "POST /v1/accord/family/supersede + /cosign (a conferred human widens the roster: T7 recovery)",
    "holder": "the T8 accord machinery: honest signs, lost never signs, coerced signs an invocation the "
              "standing rule refuses, censored signs but its rows are withheld past the window",
    "deadmit": "POST /v1/admin/deadmit (preview/commit; `after` = revoked_after, omitted = revoked_all)",
    "invite": "POST /v1/communities/{id}/invites (a proposal, not yet accepted)",
    "accept": "the invitee's acceptance while the group's quorum is pending",
    "decline": "POST /v1/self/invites/{proposal_id}/decline",
    "remove": "DELETE /v1/communities/{id}/members/{key_id}",
    "leave": "POST /v1/communities/{id}/leave",
    "fail_secure": "POST /v1/safety/moderation with no resolving moderator chain (absence never admits)",
    "scoped_file": "POST /v1/files to a family or community cohort (src/drive.rs)",
    "key_grant": "persist emits key_grant:content:v1 per recipient on a sealed share; no read witnesses it yet",
}
# One root per mesh: `mint_accord_root` rewrites the mesh's base env (every
# later node boots on its bundle with no ceremony of its own), so a second
# canonical holding a DIFFERENT root cannot share the mesh with the first.
MAX_CANONICALS = 1

LAYERS = ["roots", "canonicals", "nodes", "persons", "relations", "actor", "negatives"]
LAST_STEPS: Any = None  # the running build's Steps, so a failure can name its first failing layer


class Unrealizable(ValueError):
    """The declaration cannot hold, by rule number (FSD/TOPOLOGY.md §3)."""


class StopBuild(Exception):
    """The runner asked the build to stop before a step (the first one the
    builder refuses): what was built so far stands, and is reported."""


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
        if _is_accord_root(r):
            f, m = r.get("founders", {}), r.get("quorum", 0)
            if (f.get("seated"), m) != (3, 2):
                not_yet.append(f"root {r['id']}: founders.seated={f.get('seated')} quorum={m} "
                               "(the ceremony mints exactly three seated holders at quorum:2/3)")
            continue
        for k, v in BUILDABLE_ROOT.items():
            if r.get(k, v) != v:
                not_yet.append(f"root {r['id']}: {k}={r.get(k)!r} (the anchor mints {v!r})")
    if len(canon) > MAX_CANONICALS:
        not_yet.append(f"canonicals: {len(canon)} declared, the builder stands up {MAX_CANONICALS} per mesh "
                       "(one root per mesh)")
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
    for p in persons.values():
        stray = [j for j in p.get("joins", []) if j not in p["owns"]]
        if stray:
            raise Unrealizable(f"person {p['id']} joins {stray}, which it does not own")
        if p.get("joins") and p["owns"][0] in p["joins"]:
            raise Unrealizable(f"person {p['id']}: the first owned node is claimed with a fresh identity; "
                               "only a LATER device can join by approval")
    owner_of = {nid: p["id"] for p in persons.values() for nid in p["owns"]}
    for rel in t["relations"]:
        kind = rel["rel"]
        if kind in ("halt", "confirm", "resume", "join_request",
                    "goals_stage", "goals_propose", "goals_cosign", "goals_amend", "goals_withdraw",
                    "goals_recant") and not any(
                _is_accord_root(r) for r in roots.values()):
            raise Unrealizable(f"relation {kind} needs the infrastructure root (the ceremony's holders sign it; "
                               "a fresh device's record stays self-signed only under CIRIS_TEST_NO_CEREMONY)")
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


def _roster_answer(by: "Node", proposal_id: Optional[str], answer: str, kind: str, target: str) -> Dict[str, Any]:
    """Answer a held self-roster change from `by` (CIRISServer#794): the
    proposal must be listed there, then the answer is signed by `by`'s pen."""
    if not proposal_id:
        raise MeshError(f"no held {kind} proposal for {target} to answer")

    def listed() -> Optional[bool]:
        props = by.must("GET", "/v1/self/roster/proposals").get("proposals", [])
        return True if any(x["proposal"]["id"] == proposal_id for x in props) else None
    wait_for(f"{by.name} to hold the {kind} proposal of {target}", listed, 60.0, every=2)
    code, got = by.api("POST", f"/v1/self/roster/proposals/{proposal_id}/{answer}", {})
    if code != 200:
        raise MeshError(f"{by.name}: {answer} on {proposal_id} answered {code}: {str(got)[:300]}")
    return got or {}


def build(mesh: Mesh, t: Decl, args: Any, checkpoint: Any = None, stop_before: Optional[str] = None) -> Decl:
    """Stand `t` up. `checkpoint(step_id, ctx)` runs after every step, with the
    step ids `model.steps(t)` names (the runner tests there); `stop_before` ends
    the build, as a PASS of what was built, before that step."""
    try:
        return _build(mesh, t, args, checkpoint, stop_before)
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


class Ctx:
    """What a checkpoint sees: the live nodes by declared id, and what the
    relations produced so far."""

    def __init__(self, mesh: Mesh, t: Decl) -> None:
        self.mesh, self.t = mesh, t
        self.N: Dict[str, Node] = {}
        self.values: Dict[str, str] = {}
        self.rooms: Dict[str, str] = {}
        self.groups: Dict[str, Dict[str, Any]] = {}
        self.joins: Dict[str, Dict[str, Any]] = {}
        self.changes: Dict[str, Dict[str, Any]] = {}
        self.halts: Dict[str, str] = {}
        self.files: Dict[str, Dict[str, Any]] = {}
        self.done: List[str] = []


def _build(mesh: Mesh, t: Decl, args: Any, checkpoint: Any = None, stop_before: Optional[str] = None) -> Decl:
    from . import model
    d = derive(t)
    if d["not_buildable_yet"] and stop_before is None:
        raise MeshError("declared but not buildable yet: " + "; ".join(d["not_buildable_yet"]))
    expected = [s.id for s in model.steps(t)]
    ctx = Ctx(mesh, t)

    def gate(step_id: str) -> None:
        if step_id == stop_before:
            raise StopBuild(step_id)

    def progress(step_id: str) -> None:
        """A step finished: compare against the model's trace, then test."""
        ctx.done.append(step_id)
        want = expected[len(ctx.done) - 1] if len(ctx.done) <= len(expected) else None
        if want != step_id:
            raise MeshError(f"builder/model drift: the builder finished {step_id!r} where model.steps "
                            f"names {want!r} — the checkpoints would test the wrong state")
        if checkpoint is not None:
            checkpoint(step_id, ctx)

    try:
        return _build_steps(mesh, t, args, d, ctx, gate, progress)
    except MeshError as e:
        # A failure at a step declared `known_red` names its issue: the
        # defect is filed, this is its reproduction, not a new regression.
        failing = expected[len(ctx.done)] if len(ctx.done) < len(expected) else None
        m = re.match(r"rel\[(\d+)\]:", failing or "")
        red = t["relations"][int(m.group(1))].get("known_red") if m else None
        if red:
            raise MeshError(f"KNOWN RED ({red}) at {failing}: {e}") from e
        raise
    except StopBuild as stop:
        return {"verdict": "PASS", "partial": True, "stopped_before": str(stop), "built": ctx.done,
                "steps": LAST_STEPS.log if LAST_STEPS else [], "derived": d, "values": ctx.values,
                "notes": (LAST_STEPS.notes if LAST_STEPS else []) + [f"stopped before {stop}: the builder refuses it"]}


def _invite_and_accept(host: Node, guest: Node, path: str, role: Optional[str], wait: float) -> str:
    """Membership needs the invitee's consent (FSD/MEMBERSHIP_INVITES.md): the
    host proposes, the proposal reaches the guest's node, the GUEST accepts."""
    body: Dict[str, Any] = {"key_id": guest.owner_key_id}
    if role:
        body["role"] = role
    got = host.must("POST", path, body, ok=(202,))
    pid = got["proposal_id"]

    def arrived() -> Optional[bool]:
        st_, inv = guest.api("GET", "/v1/self/invites")
        listed = (inv or {}).get("invites", []) if st_ == 200 and isinstance(inv, dict) else []
        return True if any(i.get("proposal_id") == pid for i in listed) else None
    wait_for(f"the invitation {pid[:24]} to reach {guest.name}", arrived, wait, every=3)
    guest.must("POST", f"/v1/self/invites/{pid}/accept", {})
    return pid


def _seated(host: Node, path: str, key_id: str) -> bool:
    st_, room = host.api("GET", path)
    if st_ != 200 or not isinstance(room, dict):
        return False
    return any((m.get("key_id") if isinstance(m, dict) else m) == key_id for m in room.get("members", []))


def _build_steps(mesh: Mesh, t: Decl, args: Any, d: Decl, ctx: Ctx, gate: Any, progress: Any) -> Decl:
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
    N: Dict[str, Node] = ctx.N
    joining = {nid for p in persons.values() for nid in p.get("joins", [])}

    # 1–2. roots + canonicals: the synthetic anchor's ceremony, one canonical —
    #      or, for an infrastructure root (T8), the 0.5.220 ceremony over the
    #      routes with three software holders, and the canonical rebooted on it.
    roots_by_id = _ids(t, "roots")
    for c in t["canonicals"]:
        gate(f"canonical:{c['id']}")
        root = roots_by_id[c["holds"]]
        if _is_accord_root(root):
            fuse = (root.get("charter") or {}).get("halt_fuse_secs")
            if fuse:
                mesh.base_env.setdefault("CIRIS_TEST_HALT_FUSE_SECS", str(fuse))
            N[c["id"]], anchor, _done = mint_accord_root(mesh, args, step)
            step("root+canonical", layer="roots/canonicals", canonical=c["id"], holds=c["holds"],
                 proves="the ceremony minted the accord root; the canonical boots on the bundle, claimed and announced",
                 holders=[h["key_id"] for h in anchor["holders"]])
            progress(f"canonical:{c['id']}")
            continue
        # A `key` root under the SEALED transport (edge v43, CC 5.3.3.5 E1): a
        # node reaches a canonical only holding its transit pair, which only a
        # bundle v4 seeds (CC 5.3.4). The synthetic anchor's blessed canonical
        # carries no bundle, so nothing could reach it (CIRISServer#801 — every
        # key-root entry stopped at its first relayed step). Production has no
        # unbundled canonical either; the key root is realized as the bundle the
        # ceremony mints, which is the only root a v43 mesh can stand on.
        N[c["id"]], anchor, _done = mint_accord_root(mesh, args, step)
        step("root+canonical", layer="roots/canonicals", canonical=c["id"], holds=c["holds"],
             proves="the key root realized as a ceremony-minted bundle v4 (the sealed transport needs the "
                    "canonical's transit pair); the canonical boots on it, claimed and announced",
             holders=[h["key_id"] for h in anchor["holders"]])
        progress(f"canonical:{c['id']}")

    # 3. nodes, in an order that lets `dials` resolve. With no canonical (T0)
    #    the mesh boots none: the node dials only what it declares.
    gate("nodes")
    pending = [n for n in t["nodes"]]
    while pending:
        progressed = False
        for n in list(pending):
            deps = [x for x in n.get("dials", []) if x not in N]
            if deps:
                continue
            N[n["id"]] = mesh.add(n["id"], dial=[N[x] for x in n.get("dials", []) if x in _ids(t, "nodes")],
                                  canonical=bool(t["canonicals"]))
            pending.remove(n)
            progressed = True
        if not progressed:
            raise MeshError(f"nodes dial each other in a cycle: {[n['id'] for n in pending]}")
    step("nodes", layer="nodes", up={n: N[n].url for n in _ids(t, "nodes")})
    progress("nodes")

    # 4. persons: first node claimed with a minted identity; the rest carried —
    #    except a device the person `joins` by approval (FSD/ADD_DEVICE.md),
    #    which stays UNOWNED until its join_complete relation.
    for p in t["persons"]:
        gate(f"person:{p['id']}")
        first, *rest = [x for x in p["owns"] if x not in joining]
        alias = f"{p['id']}-person"
        N[first].claim(alias)
        for nid in rest:
            n = N[nid]
            n.stop()
            n.carry_owner_from(N[first], alias)
            n.start()
            n.claim(alias)
        owners = {nid: N[nid].owner_key_id for nid in p["owns"] if nid not in joining}
        if len(set(owners.values())) != 1:
            raise MeshError(f"{p['id']}'s devices claimed different owners: {owners}")
        step(f"person:{p['id']}", layer="persons", owner=N[first].owner_key_id, devices=p["owns"],
             joins=p.get("joins", []), proves="one owner key across every declared device")
        progress(f"person:{p['id']}")
    gate("announced")
    for n in t["nodes"]:
        if n["id"] in joining:
            N[n["id"]].self_record()  # unowned: nothing to announce until it joins
            continue
        if n.get("announced"):
            N[n["id"]].announce()
        N[n["id"]].self_record()
    step("announced", layer="nodes", announced=[n["id"] for n in t["nodes"] if n.get("announced") and n["id"] not in joining])
    progress("announced")
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
    if any(c in _ids(t, "canonicals") for n in t["nodes"] for c in n.get("dials", [])):
        gate("canonical_peered")
        for n in t["nodes"]:
            if n["id"] in joining:
                continue  # an unowned node peers nobody; join_complete peers it
            for c in n.get("dials", []):
                if c in _ids(t, "canonicals"):
                    N[n["id"]].peer_with(N[c])
                    peered_canonicals.append((n["id"], c))
        step("canonical_peered", layer="nodes", pairs=peered_canonicals,
             proves="every claimed node holds the record of the canonical it dials, as the owner's peering act leaves it in production")
        progress("canonical_peered")

    # 5. relations, in declared order.
    values: Dict[str, str] = ctx.values
    rooms: Dict[str, str] = ctx.rooms
    added: set = set()  # (host node id, guest person) pairs already POSTed by a `reachable` gate
    # Files the relations wrote, for a later `custody` relation: `last` is the
    # most recent `file` (or the last file a `corpus` wrote); a corpus file is
    # also named by its manifest name (`large`, `inline_over`, ...). Each entry
    # records the device it was written on — the AUTHOR device, the one whose
    # store admits every delivery receipt.
    files_written: Dict[str, Dict[str, Any]] = ctx.files
    canon = N[t["canonicals"][0]["id"]] if t["canonicals"] else None
    prev: Optional[str] = None
    for ri, rel in enumerate(t["relations"]):
        if prev:
            progress(prev)
        k = rel["rel"]
        prev = f"rel[{ri}]:{k}"
        gate(prev)
        if k in REFUSED_RELATIONS:
            raise MeshError(f"relation {k!r}: the builder refuses it — {REFUSED_RELATIONS[k]}")
        if k in AWAITING_ROUTE:
            raise MeshError(f"relation {k!r}: the product has no route yet — {AWAITING_ROUTE[k]}")
        if k in PENDING_BUILDER:
            raise MeshError(f"relation {k!r}: route exists, builder branch not written — {PENDING_BUILDER[k]}")
        if rel.get("known_red"):
            step.notes.append(f"{prev}: building through a KNOWN RED step ({rel['known_red']})")
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
                # The withdrawing device too: a 200 DELETE that left the author
                # reading its own bytes is the same leak (Codex on #725).
                for o in [src] + others:
                    last[o.name] = o.read_raw(f["id"], cohort)[0]
                return all(code == 410 for code in last.values())
            try:
                wait_for(f"every device, the author's included, to read {which} as withdrawn",
                         gone_everywhere, wait, every=5)
            except MeshError:
                step.fail(f"withdraw_LEAKED:{which}",
                          "a device that held the file still reads it after its author withdrew it — the "
                          "withdrawal did not reach it, or a binding on that device outlives the tombstone",
                          [src] + others, r"withdraw|custody_ack|tombstone",
                          layer="relations", rel="withdraw", cc="CC 2.3", reads=dict(last))
                raise
            # The bytes plane (edge `blob_serve_refusals["withdrawn"]`): recorded,
            # not asserted — nothing in this topology asks a holder for a
            # withdrawn file's chunks afterwards (the author holds its own copy and
            # edge never re-pulls a withdrawn file).
            serve_refusals = {}
            for o in others:
                st_m, m = o.api("GET", "/v1/federation/metrics")
                data = (m or {}).get("data", {}) if isinstance(m, dict) else {}
                serve_refusals[o.name] = (data.get("blob_serve_refusals") or {}).get("withdrawn", 0)
            step(f"withdraw:{which}", layer="relations", author=src.name, reads=dict(last),
                 withdrawn_serve_refusals=serve_refusals,
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
        elif k == "join_request":
            # FSD/ADD_DEVICE.md §1: the new, UNOWNED device asks its person's
            # existing device over first contact; the owner opened the window.
            p = persons[rel["person"]]
            new = N[rel["device"]]
            host = N[rel.get("via") or p["owns"][0]]
            host.must("POST", "/v1/self/device-requests/open", {"seconds": 600})
            code_link = host.contact_code()
            pin = (new.home / "claim_pin").read_text(encoding="utf-8").strip()
            last: Any = None

            def asked() -> Optional[Tuple[int, Any]]:
                nonlocal last
                last = new.api("POST", "/v1/setup/add-device",
                               {"contact": code_link, "label": rel.get("label", rel["device"])})
                return last if last[0] == 202 else None
            try:
                wait_for(f"{rel['device']} to reach {host.name} with its join request", asked,
                         float(rel.get("wait", 180)), every=5)
            except MeshError:
                step.fail(f"join_NOT_requested:{rel['device']}", "the join request was never held by the existing device",
                          [host, new], r"device-join|add-device", layer="relations", rel="join_request",
                          cc="FSD/ADD_DEVICE.md §1", got=str(last)[:300])
                raise
            match = (last[1] or {}).get("match_code")
            listed = host.must("GET", "/v1/self/device-requests").get("requests", [])
            row = next((r for r in listed if r.get("node_key_id") == new.node_key_id), None)
            if not row or row.get("match_code") != match:
                raise MeshError(f"the owner's list does not show {rel['device']}'s request with the code it shows: {listed}")
            ctx.joins[rel["device"]] = {"host": host, "row": row, "pin": pin}
            step(f"join_request:{rel['device']}", layer="relations", match_code=match,
                 proves="the request is held on the existing device with the code the new device shows")
        elif k == "join_approve":
            j = ctx.joins[rel["device"]]
            new = N[rel["device"]]
            code_a, approved = j["host"].api("POST", f"/v1/self/device-requests/{j['row']['request_id']}/approve")
            approved = approved or {}
            j["occurrence"] = approved.get("occurrence_key_id")
            if rel.get("held"):
                # From a roster of two or more keys the addition is a PROPOSAL
                # (CC 3.3.6.3): the approval is held until the roster lands it.
                if code_a != 202 or not approved.get("held") or not approved.get("proposal_id"):
                    step.fail(f"join_NOT_held_by_roster:{rel['device']}", "from two roster keys an approval must be "
                              "HELD as a self-roster proposal", [j["host"], new], r"add-device|device-join|roster",
                              layer="relations", rel="join_approve", cc="CC 3.3.6.3", status=code_a, got=approved)
                    raise MeshError("join approval not held by the roster")
                j["proposal"] = approved["proposal_id"]
                # The state is the SELF's: it holds once the person's other
                # devices hold the addition proposal and can answer it.
                for d in persons[rel["person"]]["owns"]:
                    other = N[d]
                    if other is j["host"] or other is new or not other.token:
                        continue

                    def holds_add(n: "Node" = other) -> Optional[bool]:
                        props = n.must("GET", "/v1/self/roster/proposals").get("proposals", [])
                        return True if any(x["proposal"]["id"] == j["proposal"] for x in props) else None
                    wait_for(f"{d} to hold the addition proposal", holds_add, float(rel.get("wait", 60)), every=1)
                step(f"join_approve_held:{rel['device']}", layer="relations", proposal=j["proposal"],
                     proves="the approval is a held self-roster proposal; the new device keeps waiting")
                continue
            if code_a != 200:
                raise MeshError(f"{j['host'].name}: approve answered {code_a}: {str(approved)[:300]}")

            def held() -> Optional[Dict[str, Any]]:
                st_ = new.must("GET", "/v1/setup/add-device")
                return st_ if st_.get("state") in ("approved", "applied", "failed", "denied", "expired") else None
            got = wait_for(f"{rel['device']} to verify and hold the approval", held, float(rel.get("wait", 180)), every=2)
            if got.get("state") != "approved" or got.get("owner_key_id") != j["host"].owner_key_id:
                step.fail(f"join_NOT_held:{rel['device']}", "the new device must verify the approval offline and HOLD it",
                          [j["host"], new], r"add-device", layer="relations", rel="join_approve",
                          cc="FSD/ADD_DEVICE.md §2.1", state=got)
                raise MeshError("join approval not held")
            step(f"join_approve:{rel['device']}", layer="relations", occurrence=j["occurrence"],
                 proves="approved on the existing device; verified and held, unapplied, on the new one")
        elif k == "join_assent":
            # Another roster key assents to a held addition (CC 3.3.6.3 quorum
            # path); the owner's device then delivers the approval it held.
            j = ctx.joins[rel["device"]]
            new, by = N[rel["device"]], N[rel["by"]]
            _roster_answer(by, j["proposal"], "assent", "add", j["occurrence"])

            def held_now() -> Optional[Dict[str, Any]]:
                st_ = new.must("GET", "/v1/setup/add-device")
                return st_ if st_.get("state") in ("approved", "applied", "failed", "denied", "expired") else None
            got = wait_for(f"{rel['device']} to receive the approval the roster landed", held_now,
                           float(rel.get("wait", 180)), every=2)
            if got.get("state") != "approved":
                raise MeshError(f"{rel['device']}: after the assent the join is {got}")
            step(f"join_assent:{rel['device']}", layer="relations", by=rel["by"], proposal=j["proposal"],
                 proves="a second roster key assented; the addition landed by the quorum path and the held "
                        "approval reached the new device")
        elif k in ("evict_propose", "evict_cosign"):
            p_ = rel["person"]
            target = ctx.joins.get(rel["target"], {}).get("occurrence")
            if not target:
                raise MeshError(f"{k}: {rel['target']} has no roster key in this build")
            by = N[rel["by"]]
            if k == "evict_propose":
                code_r, got = by.api("POST", "/v1/self/occurrence/revoke",
                                     {"identity_key_id": by.owner_key_id, "occurrence_key_id": target,
                                      "reason": f"{rel['target']} stolen (harness)"})
                if code_r != 200 or not (got or {}).get("held"):
                    step.fail(f"evict_NOT_held:{rel['target']}", "from two or more roster keys an eviction must be "
                              "HELD as a proposal", [by], r"roster|occurrence|revoke", layer="relations",
                              rel=k, cc="CC 3.3.6.3", status=code_r, got=got)
                    raise MeshError("eviction not held")
                listed = by.must("GET", "/v1/self/roster/proposals").get("proposals", [])
                prop = next((x for x in listed if x["proposal"]["kind"] == "evict"
                             and x["proposal"]["target"] == target), None)
                if not prop:
                    raise MeshError(f"{rel['by']} lists no held eviction of {target}: {listed}")
                ctx.joins[rel["target"]]["evict_proposal"] = prop["proposal"]["id"]
                # The state is the SELF's, not the proposer's: it holds once the
                # person's other devices hold the proposal and can answer it.
                pid_ = prop["proposal"]["id"]
                for d in persons[p_]["owns"]:
                    other = N[d]
                    if other is by or not other.token:
                        continue

                    def holds(n: "Node" = other) -> Optional[bool]:
                        props = n.must("GET", "/v1/self/roster/proposals").get("proposals", [])
                        return True if any(x["proposal"]["id"] == pid_ for x in props) else None
                    wait_for(f"{d} to hold the eviction proposal", holds, float(rel.get("wait", 60)), every=1)
                step(f"evict_propose:{rel['target']}", layer="relations", by=rel["by"], proposal=prop["proposal"]["id"],
                     proves="the eviction is a held proposal (CC 3.3.6.3)")
            else:
                pid = ctx.joins[rel["target"]].get("evict_proposal")
                _roster_answer(by, pid, "assent", "evict", target)

                def gone() -> Optional[bool]:
                    roster = by.must("GET", "/v1/self/roster/proposals").get("roster", [])
                    return True if target not in roster else None
                wait_for(f"{target} to leave {p_}'s roster", gone, float(rel.get("wait", 60)), every=2)
                step(f"evict_cosign:{rel['target']}", layer="relations", by=rel["by"], proposal=pid,
                     proves="a second roster key co-signed; the eviction landed by the quorum path")
        elif k == "join_complete":
            j = ctx.joins[rel["device"]]
            new = N[rel["device"]]
            code_c, final = new.api("POST", "/v1/setup/add-device/complete", {})
            if code_c != 200 or (final or {}).get("state") != "applied":
                step.fail(f"join_NOT_applied:{rel['device']}", "the end of first run must apply the held approval",
                          [j["host"], new], r"add-device|setup/root|occurrence", layer="relations",
                          rel="join_complete", cc="FSD/ADD_DEVICE.md §2.1", status=code_c, got=final)
                raise MeshError("join not applied")
            code_s, sess = new.api("POST", "/v1/setup/claimed-session", {"claim_pin": j["pin"]})
            if code_s != 200 or not (sess or {}).get("access_token"):
                raise MeshError(f"{rel['device']}: claimed-session after the join answered {code_s}: {str(sess)[:300]}")
            new.token, new.owner_key_id = sess["access_token"], j["host"].owner_key_id
            decl = _ids(t, "nodes")[rel["device"]]
            if decl.get("announced"):
                new.announce()
            new.self_record()
            # Its peerings (the canonical's included) are declared as `peered`
            # relations after this one: each is an owner act on the new device
            # (CIRISServer#793), and a refusal there must name its own step.
            step(f"join_complete:{rel['device']}", layer="relations", owner=new.owner_key_id,
                 proves="the held claim applied; the new device is owned by the existing ID, with its own session")
        elif k in ("halt", "confirm", "resume"):
            # CSD-129 (CC 4.2.1.1 / 4.2.1.3) on the catalogue's T8: the rows the
            # `halt` scenario signs, one relation per lifecycle state so a test
            # can run while the root is halted and before it resumes.
            from .scenarios import _inv
            holders = getattr(mesh, "accord_holders", None)
            if not holders or canon is None:
                raise MeshError(f"relation {k}: no ceremony holders in this mesh (needs the infrastructure root)")
            live = [n for n in N.values() if n.token]

            def sign(h: Dict[str, Any]) -> Dict[str, Any]:
                return {"key_id": h["key_id"], "test_holder_seed_b64": h["seed_b64"]}

            def deliver(obj: Dict[str, Any], skip: Node) -> None:
                for n in live:
                    if n is not skip:
                        n.must("POST", "/v1/accord/message", obj)

            def latched(expect: bool) -> Optional[bool]:
                return True if all(bool(n.must("GET", "/v1/accord/halt-status")["halted"]) is expect for n in live) else None
            hid = rel.get("halt", rel.get("id", "halt-1"))
            if k == "halt":
                src = N[rel.get("from") or t["actor"]["device"]]
                r = src.must("POST", "/v1/accord/halt", {"invocation": _inv("constitutional", hid, hid.encode()),
                                                        **sign(holders[0])})
                deliver(r.get("invocation") or r, src)
                wait_for("the halt to latch on every node", lambda: latched(True), float(rel.get("wait", 60)), every=1)
                ctx.halts[hid] = "latched"
                step(f"halt:{hid}", layer="relations", proves="one holder's row latched on every node (CC 4.2.1.1)")
            else:
                kind = "lifecycle:confirmed" if k == "confirm" else "lifecycle:active"
                binding = {"confirms_halt_id": hid} if k == "confirm" else {"resumes_halt_id": hid}
                iid = f"{hid}-{k}"
                canon.must("POST", "/v1/accord/invocation",
                           {"invocation": _inv(kind, iid, iid.encode(), **binding), **sign(holders[1])})
                r = canon.must("POST", "/v1/accord/invocation/concur",
                               {"invocation_kind": kind, "invocation_id": iid, **sign(holders[2])})
                deliver(r.get("invocation") or r, canon)
                if k == "confirm":
                    def confirmed() -> Optional[bool]:
                        st_ = [n.must("GET", "/v1/accord/halt-status") for n in live]
                        return True if all(s.get("halted") is True and (s.get("halt") or {}).get("lapses_at") is None
                                           for s in st_) else None
                    wait_for("the confirmation on every node", confirmed, float(rel.get("wait", 60)), every=1)
                    step(f"confirm:{hid}", layer="relations", proves="a strict majority keeps the halt past its fuse (CC 4.2.1.3)")
                else:
                    wait_for("the resume on every node", lambda: latched(False), float(rel.get("wait", 60)), every=1)
                    ctx.halts[hid] = "resumed"
                    step(f"resume:{hid}", layer="relations", proves="a strict majority naming the halt ends it everywhere")
        elif k in ("community", "household"):
            founder = N[persons[rel["founder"]]["owns"][0]]
            if k == "community":
                got = founder.must("POST", "/v1/communities", {
                    "name": rel.get("name", rel["id"]), "members": [], "tier": rel.get("tier", "community"),
                    "consensus_protocol": rel.get("protocol", "founder_only")}, ok=(200, 201))
                gid, base = got["community_id"], f"/v1/communities/{got['community_id']}"
            else:
                got = founder.must("POST", "/v1/families", {
                    "name": rel.get("name", rel["id"]), "members": [],
                    "consensus_protocol": rel.get("protocol", "founder_only")}, ok=(200, 201))
                gid, base = got["family_id"], f"/v1/families/{got['family_id']}"
            ctx.groups[rel["id"]] = {"id": gid, "base": base, "founder": founder,
                                     "protocol": rel.get("protocol", "founder_only")}
            values[f"GROUP_{rel['id'].upper()}_ID"] = gid
            step(f"{k}:{rel['id']}", layer="relations", group_id=gid, protocol=rel.get("protocol", "founder_only"))
        elif k == "member":
            g = ctx.groups[rel.get("community") or rel["household"]]
            host = g["founder"]
            guest = N[persons[rel["invitee"]]["owns"][0]]
            role = rel.get("role")
            _invite_and_accept(host, guest, f"{g['base']}/invites", role, float(rel.get("wait", 180)))
            last: Any = None

            def seated() -> Optional[bool]:
                nonlocal last
                if _seated(host, g["base"], guest.owner_key_id):
                    return True
                if g["protocol"] == "founder_only":
                    last = host.api("GET", f"{g['base']}/invites")  # the founder's read seats an accepted invite
                else:
                    # A quorum room seats by an `add` change; with the founder
                    # alone it is 1 of 1. Persist admits the widening only once
                    # the invitee's acceptance has reached this node
                    # (`membership.awaiting_acceptance` until then), so retry.
                    env = host.must("POST", f"{g['base']}/changes/envelope",
                                    {"op": "add", "key_id": guest.owner_key_id, **({"role": role} if role else {})})
                    last = host.api("POST", f"{g['base']}/changes/assemble",
                                    {"change_envelope": env["change_envelope"], "signatures": env["signatures"]})
                return True if _seated(host, g["base"], guest.owner_key_id) else None
            try:
                wait_for(f"{rel['invitee']} seated in {rel.get('community') or rel['household']}", seated,
                         float(rel.get("wait", 180)), every=3)
            except MeshError:
                step.fail(f"member_NOT_seated:{rel['invitee']}", "an invited person who accepted was never seated",
                          [host, guest], r"invite|widening|membership|seat", layer="relations", rel="member",
                          cc="FSD/MEMBERSHIP_INVITES.md", last=str(last)[:400])
                raise
            step(f"member:{rel['invitee']}", layer="relations", role=role,
                 proves="invited, accepted by the invitee on their own node, seated")
        elif k == "quorum_change":
            g = ctx.groups[rel["community"]]
            by = N[persons[rel["by"]]["owns"][0]]
            guest = N[persons[rel["invitee"]]["owns"][0]]
            _invite_and_accept(g["founder"], guest, f"{g['base']}/invites", None, float(rel.get("wait", 180)))
            env = by.must("POST", f"{g['base']}/changes/envelope", {"op": "add", "key_id": guest.owner_key_id})
            if env.get("valid", 0) >= env.get("required", 1):
                raise MeshError(f"the change met quorum on one signature ({env.get('valid')}/{env.get('required')}): "
                                "nothing is held — the community needs more members or a stricter protocol")
            st_, refused = by.api("POST", f"{g['base']}/changes/assemble",
                                  {"change_envelope": env["change_envelope"], "signatures": env["signatures"]})
            if st_ != 409 or (refused or {}).get("reason_id") != "community.quorum_pending":
                raise MeshError(f"assembling below quorum must answer 409 community.quorum_pending, got {st_}: {str(refused)[:300]}")
            ctx.changes[rel.get("id", "change")] = {"group": g, "env": env, "by": by, "guest": guest}
            step(f"quorum_change:{rel.get('id', 'change')}", layer="relations", valid=env.get("valid"),
                 required=env.get("required"), proves="the change is held below quorum; assembling it now is refused")
        elif k == "cosign":
            c_ = ctx.changes[rel.get("change", "change")]
            g, signer = c_["group"], N[persons[rel["by"]]["owns"][0]]
            sig: Dict[str, Any] = {}

            def cosigned() -> Optional[bool]:
                st_, got = signer.api("POST", f"{g['base']}/changes/cosign",
                                      {"change_envelope": c_["env"]["change_envelope"]})
                if st_ == 200:
                    sig.update(got)
                    return True
                return None
            wait_for(f"{rel['by']}'s node to fold the room and co-sign", cosigned, float(rel.get("wait", 120)), every=3)
            done: Dict[str, Any] = {}

            def assembled() -> Optional[bool]:
                st_, got = c_["by"].api("POST", f"{g['base']}/changes/assemble",
                                        {"change_envelope": c_["env"]["change_envelope"],
                                         "signatures": c_["env"]["signatures"] + [sig["signature"]]})
                done.update({"status": st_, "body": got})
                # 409 membership.awaiting_acceptance: the joiner's acceptance has
                # not reached this node yet — the quorum is met, the door waits.
                return True if st_ == 200 else None
            try:
                wait_for("the co-signed change to apply", assembled, float(rel.get("wait", 120)), every=3)
            except MeshError:
                raise MeshError(f"the co-signed change did not apply: {str(done)[:400]}")
            if not _seated(c_["by"], g["base"], c_["guest"].owner_key_id):
                raise MeshError(f"applied, but {rel['by']}'s node does not seat the invitee: {str(done)[:300]}")
            step(f"cosign:{rel.get('change', 'change')}", layer="relations", by=rel["by"],
                 proves="the second signature met quorum; the held change applied")
        elif k == "moderator":
            # The moderate duty is a delegates_to chain from a founder
            # (persist appointed_moderators_of), read back on the room.
            g = ctx.groups[rel["community"]]
            guest = N[persons[rel["to"]]["owns"][0]]
            g["founder"].must("POST", "/v1/auth/device/delegate",
                              {"mode": "existing", "existing_key_id": guest.owner_key_id, "scope": ["moderate"]})

            def appointed() -> Optional[bool]:
                st_, room = g["founder"].api("GET", g["base"])
                return True if st_ == 200 and guest.owner_key_id in (room or {}).get("moderators", []) else None
            try:
                wait_for(f"{rel['to']} listed as an appointed moderator", appointed, float(rel.get("wait", 60)), every=3)
            except MeshError:
                st_, room = g["founder"].api("GET", g["base"])
                step.fail(f"moderator_NOT_appointed:{rel['to']}", "a moderate-scoped delegation from the founder is not "
                          "read back as an appointed moderator on the room", [g["founder"]], r"delegat|moderat",
                          layer="relations", rel="moderator", cc="CC 4.5 / CIRISPersist#591",
                          moderators=(room or {}).get("moderators"))
                raise
            step(f"moderator:{rel['to']}", layer="relations", proves="the founder's moderate delegation names an appointed moderator")
        elif k == "replication_withdraw":
            # CC 3.3.7: each side withdraws the consent:replication grant it
            # authored for the other. Re-posting the peering is idempotent and
            # answers the live grant's attestation_id.
            a, b = rel["between"]
            for x, y in ((a, b), (b, a)):
                got = N[x].peer_with(N[y], rel.get("prefixes"))
                att = (got or {}).get("grant_attestation_id")
                if not att:
                    raise MeshError(f"replication_withdraw: {x}'s peering with {y} names no grant_attestation_id: {str(got)[:300]}")
                N[x].must("POST", "/v1/federation/peering/revoke", {"attestation_id": att})
            step(f"replication_withdraw:{a}-{b}", layer="relations",
                 proves="both consent:replication grants withdrawn (CC 3.3.7: replication = none)")
        elif k == "steal":
            # A staging (CC formal/roster `thief`): the device keeps its live
            # roster key, and from here the model reads it as held by a thief.
            # Nothing on the wire changes — which is the point of the state.
            step(f"steal:{rel['device']}", layer="relations",
                 proves="the device's roster key is from here held by the thief (a staging, CC 3.3.6.3)")
        elif k == "lose":
            # Lost for good: the device's process stops and never returns.
            N[rel["device"]].stop()
            step(f"lose:{rel['device']}", layer="relations", proves="the device is unreachable for good (CC 3.3.6.3)")
        else:
            raise MeshError(f"relation {k!r}: declared, no builder yet")
    if prev:
        progress(prev)

    # 6. negatives.
    for ni, neg in enumerate(t.get("negatives", [])):
        if ni:
            progress(f"neg[{ni - 1}]:{t['negatives'][ni - 1]['check']}")
        gate(f"neg[{ni}]:{neg['check']}")
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

    if t.get("negatives"):
        progress(f"neg[{len(t['negatives']) - 1}]:{t['negatives'][-1]['check']}")
    gate("negatives")
    progress("negatives")

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
    gate("actor")
    progress("actor")
    return {"verdict": "PASS", "steps": step.log, "derived": d, "values": values, "notes": step.notes, "built": ctx.done}
