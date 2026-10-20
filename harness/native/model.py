"""The CSD/4 catalogue model (FSD/CSD4.md): what each catalogue topology is,
state by state, as it is built — computed from the declaration, with no node
running.

Three questions it answers, each one a verb on `python -m harness.native`:

    evaluate   is the catalogue sound? every entry realizable (TOPOLOGY.md §3),
               every state it promises reached, every vocabulary state reached
               by some entry, every requirement covered, and what the builder
               cannot build yet, by name.
    plan       given CSD requirements (each: the states that must hold AT THE
               SAME INSTANT for its test), choose the catalogue entries that
               reach all of them at least cost, and the build step after which
               each test runs (the earliest one where its states hold).
    run        the plan, executed: build each chosen entry layer by layer and
               run every scheduled test at its checkpoint (topology.build's
               `checkpoint` hook), before a later step destroys its state.

A STATE is an atom from `ATOMS`, the closed vocabulary of catalogue version 1.
Atoms are DERIVED from the steps (`effects`), never declared by hand, so an
entry cannot claim a state its steps do not produce. Some atoms are transient:
`node.unclaimed` holds only until the claim, `root.halted` only until the
resume, `device.join_approved` only until the complete. A test that needs one
must run inside its window; that is why the runner tests at intermediate
states instead of at the end.
"""
from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

import yaml

CATALOGUE_VERSION = 3
CATALOG_IDS = [f"T{i}" for i in range(20)]
HERE = Path(__file__).parent
CATALOG_DIR = HERE / "topologies" / "catalog"
REQUIREMENTS = CATALOG_DIR / "requirements.yaml"

Decl = Dict[str, Any]

# A relation marked `known_red: <Repo>#<n>` exercises a PRODUCT defect that is
# filed and open: it ends the buildable prefix like a refusal (the tests past
# it are reported blocked by that issue, not failed), unless the runner is
# asked to build through it (`--include-known-red`) to see whether it is fixed.
INCLUDE_KNOWN_RED = False

# ── the vocabulary (catalogue version 1; FSD/CSD4.md §3) ────────────────────
#
# Closed, and the CONSTITUTION's (steward decision 2026-10-18): CC publishes
# manifests/topology_vocabulary.json (atom → plane state predicate → CC
# decimal → meaning) and this model LOADS it — the vendored byte copy beside
# the catalogue, pinned by commit and sha256 in topology_vocabulary.pin. A new
# atom or a changed meaning is a CC PR and a catalogue version bump, never an
# edit here.
VOCABULARY = CATALOG_DIR / "topology_vocabulary.json"
VOCABULARY_PIN = CATALOG_DIR / "topology_vocabulary.pin"


def _load_vocabulary(path: Path = VOCABULARY) -> Dict[str, Decl]:
    import json
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    meta = doc.get("_meta") or {}
    if meta.get("catalogue_version") != CATALOGUE_VERSION:
        raise ValueError(f"{path.name}: catalogue_version {meta.get('catalogue_version')!r}, "
                         f"this model implements {CATALOGUE_VERSION} — refusing another vocabulary")
    atoms = doc.get("atoms") or {}
    if meta.get("n_atoms") is not None and meta["n_atoms"] != len(atoms):
        raise ValueError(f"{path.name}: _meta.n_atoms={meta['n_atoms']} but {len(atoms)} atoms")
    return atoms


VOCABULARY_ROWS: Dict[str, Decl] = _load_vocabulary()
ATOMS: Dict[str, str] = {a: row["meaning"] for a, row in VOCABULARY_ROWS.items()}

# ── steps and their effects ─────────────────────────────────────────────────


@dataclass(frozen=True)
class Step:
    """One build step: the unit after which the runner may test. `id` is the
    label topology.build passes to its checkpoint hook, so the model's trace
    and the builder's progress are compared by name."""
    id: str
    layer: str
    kind: str
    adds: FrozenSet[str]
    removes: FrozenSet[str] = frozenset()


def _ids(t: Decl, layer: str) -> Dict[str, Decl]:
    return {x["id"]: x for x in t.get(layer, [])}


def steps(t: Decl) -> List[Step]:
    """The build, step by step, in the order topology.build runs it."""
    out: List[Step] = []
    roots = _ids(t, "roots")
    nodes = _ids(t, "nodes")
    persons = _ids(t, "persons")
    joins = {nid for p in persons.values() for nid in p.get("joins", [])}
    held_roots: List[str] = []

    for c in t.get("canonicals", []):
        r = roots[c["holds"]]
        adds = {f"root.{r['kind']}"}
        if (r.get("lifecycle") or {}).get("verdict") == "rooted":
            adds.add("root.rooted")
        if r.get("kind") == "infrastructure":
            # The accord's seated founders are humans, more than M of them
            # active (CC 3.2 T7): a live root on human seats.
            adds |= {"seat.identity_type.human", "root.liveness.live"}
        held_roots.append(r["id"])
        if len(set(held_roots)) >= 2:
            adds.add("root.two")
        out.append(Step(f"canonical:{c['id']}", "roots/canonicals", "canonical", frozenset(adds)))

    adds = {"node.unclaimed"} if nodes else set()
    if held_roots and any(not n.get("accepts") or n["accepts"] not in held_roots for n in nodes.values()):
        adds.add("party.outside_roots")
    out.append(Step("nodes", "nodes", "nodes", frozenset(adds)))

    claimed: Set[str] = set()
    owned = {nid for p in persons.values() for nid in p["owns"]}
    unowned = set(nodes) - owned
    roster: Dict[str, int] = {}  # person → live roster keys (CC 3.3.6.3: one per device)
    for p in t.get("persons", []):
        carried = [nid for nid in p["owns"] if nid not in joins]
        claimed |= set(carried)
        roster[p["id"]] = len(carried)
        adds = {"node.claimed", "key.holder.owner", "key.revocation.none"}
        if len(carried) >= 2:
            adds.add("person.multi_device")
        still = (owned - claimed) | unowned
        a, r = _roster_atoms(roster)
        out.append(Step(f"person:{p['id']}", "persons", "person", frozenset(adds | a),
                        (frozenset() if still else frozenset({"node.unclaimed"})) | r))
    related = _related_persons(t)
    if any(pid not in related and pid != t.get("actor", {}).get("person") for pid in persons):
        out[-1] = Step(out[-1].id, out[-1].layer, out[-1].kind, out[-1].adds | {"person.outsider"}, out[-1].removes)

    adds = set()
    if any(n.get("announced") for n in nodes.values()):
        adds |= {"node.announced", "node.announce.announced"}
    if any(not n.get("announced") for n in nodes.values()):
        adds.add("node.unannounced")
    out.append(Step("announced", "nodes", "announced", frozenset(adds)))
    if any(d in _ids(t, "canonicals") for n in nodes.values() for d in n.get("dials", [])):
        out.append(Step("canonical_peered", "nodes", "canonical_peered", frozenset({"canonical.peered"})))

    pending_joins = set(joins)
    for i, rel in enumerate(t.get("relations", [])):
        a, r = effects(rel, t)
        if rel["rel"] == "join_complete":
            pending_joins.discard(rel["device"])
            if not pending_joins and not unowned:
                r = r | {"node.unclaimed"}
        if rel["rel"] in ROSTER_DELTA:
            roster[rel["person"]] = roster.get(rel["person"], 0) + ROSTER_DELTA[rel["rel"]]
            ra, rr = _roster_atoms(roster)
            a, r = a | ra, r | rr
        out.append(Step(f"rel[{i}]:{rel['rel']}", "relations", rel["rel"], frozenset(a), frozenset(r)))
    for i, neg in enumerate(t.get("negatives", [])):
        out.append(Step(f"neg[{i}]:{neg['check']}", "negatives", "negative", frozenset()))
    out.append(Step("negatives", "negatives", "negatives", frozenset({"negatives.held"})))
    if t.get("actor"):
        out.append(Step("actor", "actor", "actor", frozenset({"values.ready"})))
    return out


# How a relation changes its person's roster (`person:` names it).
ROSTER_DELTA = {"join_complete": +1, "evict_cosign": -1, "evict_lone": -1}
ROSTER_SIZE_ATOMS = ("self.roster_size.one", "self.roster_size.three_more")


def _roster_atoms(roster: Dict[str, int]) -> Tuple[Set[str], Set[str]]:
    """The roster-size atoms over every person's live roster: `one` while some
    person's roster is genesis only, `three_more` while some person's holds
    three or more keys (the two-path regime). Both are re-decided at every
    step that changes a roster, so each holds exactly while it is true."""
    on = set()
    if any(n == 1 for n in roster.values()):
        on.add("self.roster_size.one")
    if any(n >= 3 for n in roster.values()):
        on.add("self.roster_size.three_more")
    return on, set(ROSTER_SIZE_ATOMS) - on


def _related_persons(t: Decl) -> Set[str]:
    """Persons that appear in any relation (an outsider appears in none)."""
    seen: Set[str] = set()
    owner_of = {nid: p["id"] for p in t.get("persons", []) for nid in p["owns"]}
    for rel in t.get("relations", []):
        for k in ("between", "members"):
            for x in rel.get(k, []) or []:
                seen.add(owner_of.get(x, x))
        for k in ("from", "to", "person", "of", "by", "guardian", "child", "invitee", "node", "member"):
            v = rel.get(k)
            if isinstance(v, str):
                seen.add(owner_of.get(v, v))
    return seen


def effects(rel: Decl, t: Decl) -> Tuple[Set[str], Set[str]]:
    """(adds, removes) of one relation. Unknown kinds add nothing and are
    caught by `unknown_relations`."""
    k = rel["rel"]
    simple = {
        "peered": {"peer.direct"},
        "rooted_with": {"pair.rooted"},
        "reachable": {"contact.reachable"},
        "message": {"message.delivered"},
        "file": {"file.held"},
        "bigfile": {"file.held", "file.large"},
        "corpus": {"file.held", "file.large"},
        "custody": {"file.custody_received"},
        "roster": {"roster.visible"},
        "note": {"note.synced"},
        "session": {"session.unified"},
        "join_request": {"device.join_requested"},
        "household": {"household.formed"},
        "age_assurance": {"age.assured"},
        "community": {"community.formed"},
        "moderator": {"moderator.named"},
        "authority": {"authority.licensing"},
        "delegation": {"delegation.chain"},
        "agent": {"agent.bound"},
        "steward": {"steward.bonded"},
        "wise_authority": {"wa.present"},
        "halt": {"root.halted", "root.holder_disposition.honest"},
        # catalogue v2
        "steal": {"key.holder.thief"},
        "lose": {"key.holder.lost"},
        "evict_propose": {"key.membership.proposed_evict"},
        "lineage_head": {"root.head.stale"},
        "seat_node_bearing": {"seat.identity_type.node_bearing"},
        "deadmit": set(),
        "invite": {"member.stage.proposed"},
        "merit_promote": {"group.moderator.merit_promoted"},
        "fail_secure": {"group.moderator.fail_secure"},
        "consent_grant": {"consent.state.granted"},
        "community_trust": {"consent.community_trust.granted"},
        "replication_withdraw": {"consent.replication.none"},
        "purge": {"blob.custody.purged"},
        "delegation_withdraw": {"delegation.link.withdrawn"},
        "delegation_expire": {"delegation.link.expired"},
        "key_grant": {"grant.state.held"},
        "agent_act": {"agent.halt_gate.acting"},
    }
    if k in simple:
        adds = set(simple[k])
        if k == "rooted_with" and rel.get("require") is not True:
            adds = set()  # observed, not required: the builder records it, never ensures it
        if k == "file" and int(rel.get("size", 0)) > 1048576:
            adds.add("file.large")  # past the inline ceiling: streamed, chunked, receipted
        if k in ("file", "bigfile", "corpus"):
            adds.add("row.standing.admitted")
        if k == "deadmit":
            adds.add("key.revocation.revoked_after" if rel.get("after") else "key.revocation.revoked_all")
        return adds, set()
    if k == "contact":
        return ({"contact.added", "contact.via_code"} if rel.get("via") == "code" else {"contact.added"}), set()
    if k == "room":
        return ({"room.pair.keyed"} if rel["kind"] == "pair" else {"room.self.keyed"}), set()
    if k == "withdraw":
        return {"file.withdrawn", "row.standing.tombstoned"}, {"file.held", "file.custody_received"}
    if k == "evict_cosign":
        return {"key.membership.evicted"}, {"key.membership.proposed_evict"}
    if k == "evict_lone":
        return {"key.membership.evicted"}, set()
    if k == "resign":
        # A founder leaves the seated roster: at M or fewer active, the root
        # stalls (CC 3.2 T7) — the declaration says whether this one does.
        return ({"root.standing.Stalled", "root.liveness.stalled"}, {"root.liveness.live"}) \
            if rel.get("stalls") else (set(), set())
    if k == "confer":
        return ({"seat.identity_type.human", "root.liveness.live"},
                {"root.standing.Stalled", "root.liveness.stalled"})
    if k == "holder":
        return {f"root.holder_disposition.{rel['disposition']}"}, set()
    if k == "accept":
        return {"member.stage.accepted_awaiting_group"}, {"member.stage.proposed"}
    if k == "decline":
        return {"member.stage.declined"}, {"member.stage.proposed"}
    if k == "invite_window":
        # CC 4.5.13: the window closed below the approval floor — silence alone
        # never admits (manifests/governance_policy_vectors.json, community_invite).
        return {"member.stage.declined"}, {"member.stage.proposed"}
    if k == "remove":
        return {"member.stage.removed"}, set()
    if k == "leave":
        return {"member.stage.resigned"}, set()
    if k == "moderator_lapse":
        # A lapsed community cannot federate (CC 4.5.4).
        return {"group.moderator.lapsed", "group.federating.no"}, {"moderator.named"}
    if k == "consent_revoke":
        return {"consent.state.revoked"}, {"consent.state.granted"}
    if k == "consent_expire":
        return {"consent.state.expired"}, {"consent.state.granted"}
    if k == "community_trust_bound":
        return {"consent.community_trust.bounded"}, {"consent.community_trust.granted"}
    if k == "consent_decay":
        order = ["identity_severed", "patterns_anonymized", "complete"]
        return {f"consent.decay.{rel['stage']}"}, {f"consent.decay.{x}" for x in order if x != rel["stage"]}
    if k == "scoped_file":
        return {"file.held", "row.standing.admitted", f"row.scope.{rel['scope']}"}, set()
    if k == "agent_bond":
        return ({f"agent.bond.{rel['state']}"}, {"agent.bond.unbound", "agent.bond.lapsed"} - {f"agent.bond.{rel['state']}"})
    if k == "retirement":
        stage = f"agent.retirement.{rel['stage']}"
        return {stage}, {a for a in ATOMS if a.startswith("agent.retirement.") and a != stage}
    if k == "join_approve":
        if rel.get("held"):
            # From two roster keys the approval is an ADDITION PROPOSAL (CC
            # 3.3.6.3); the new device is still only requested.
            return {"key.membership.proposed_add"}, set()
        return {"device.join_approved"}, {"device.join_requested"}
    if k == "join_assent":
        return {"device.join_approved"}, {"device.join_requested", "key.membership.proposed_add"}
    if k == "join_complete":
        return {"device.joined", "node.claimed", "person.multi_device"}, {"device.join_approved", "device.join_requested"}
    if k == "member":
        if rel.get("community"):
            return {"community.member"}, set()
        if rel.get("role") == "child":
            # Seated with no bond yet: guardian.bond = none until a bond row (CC 3.4.13).
            return {"household.member", "child.member", "guardian.bond.none"}, set()
        return {"household.member"}, set()
    if k == "quorum_change":
        need, got = int(rel.get("quorum", 2)), int(rel.get("cosigns", 1))
        return ({"quorum_change.applied"}, {"quorum_change.held"}) if got >= need else ({"quorum_change.held"}, set())
    if k == "cosign":
        return {"quorum_change.applied"}, {"quorum_change.held"}
    if k == "guardian_bond":
        return {"guardian.bound"}, {"guardian.bond.none"}
    if k == "confirm":
        return {"root.halt_confirmed"}, set()
    if k == "resume":
        return {"root.resumed"}, {"root.halted", "root.halt_confirmed"}
    return set(), set()


KNOWN_RELATIONS = {
    "peered", "rooted_with", "reachable", "contact", "room", "message", "file", "bigfile", "corpus",
    "custody", "roster", "note", "session", "withdraw", "join_request", "join_approve", "join_assent", "join_complete",
    "household", "member", "age_assurance", "community", "moderator", "quorum_change", "cosign",
    "authority", "delegation", "agent", "steward", "wise_authority", "halt", "confirm", "resume",
    "guardian_bond", "moderator",
    # catalogue v2
    "steal", "lose", "evict_propose", "evict_cosign", "evict_lone", "deadmit", "resign", "confer",
    "lineage_head", "seat_node_bearing", "holder", "invite", "invite_window", "accept", "decline", "remove", "leave",
    "moderator_lapse", "merit_promote", "fail_secure", "consent_grant", "consent_revoke", "consent_expire",
    "consent_decay", "community_trust", "community_trust_bound", "replication_withdraw", "scoped_file",
    "purge", "delegation_withdraw", "delegation_expire", "key_grant", "agent_bond", "agent_act", "retirement",
}


def trace(t: Decl) -> List[Tuple[Step, FrozenSet[str]]]:
    """Each step with the state AFTER it. The initial state is `root.none`
    when the declaration holds no root at all."""
    state: Set[str] = set() if t.get("canonicals") else {"root.none"}
    out = []
    for s in steps(t):
        state = (state - s.removes) | s.adds
        out.append((s, frozenset(state)))
    return out


def reachable(t: Decl) -> Dict[str, int]:
    """Every atom the trace reaches, with the FIRST step index it holds at."""
    first: Dict[str, int] = {}
    if not t.get("canonicals"):
        first["root.none"] = -1
    for i, (_, st) in enumerate(trace(t)):
        for a in st:
            first.setdefault(a, i)
    return first


def windows(t: Decl) -> Dict[str, Tuple[int, int]]:
    """Transient atoms: [first index it holds, first index it no longer
    holds). A test needing one must run inside this window."""
    tr = trace(t)
    out: Dict[str, Tuple[int, int]] = {}
    for a in ATOMS:
        held = [i for i, (_, st) in enumerate(tr) if a in st]
        if held and held[-1] < len(tr) - 1:
            out[a] = (held[0], held[-1] + 1)
    return out


def first_index(t: Decl, need: Iterable[str], limit: Optional[int] = None) -> Optional[int]:
    """The earliest step after which every atom of `need` holds at once —
    within the first `limit` steps when given (the buildable prefix)."""
    need = frozenset(need)
    if not t.get("canonicals") and need <= {"root.none"}:
        return -1
    for i, (_, st) in enumerate(trace(t)):
        if limit is not None and i >= limit:
            return None
        if need <= st:
            return i
    return None


# ── what the builder can build ──────────────────────────────────────────────


def built_relations() -> Set[str]:
    """The relation kinds topology.build has a branch for — READ from its
    source, not mirrored here (a mirrored list drifts; memory: mirrored-rule
    class)."""
    src = (HERE / "topology.py").read_text(encoding="utf-8")
    return set(re.findall(r'k == "([a-z_]+)"', src)) | set(
        x for grp in re.findall(r"k in \(([^)]*)\)", src) for x in re.findall(r'"([a-z_]+)"', grp))


def refused_steps(t: Decl) -> Dict[str, str]:
    """Step id → why the builder refuses it. The builder's own statements
    (topology.REFUSED_RELATIONS, MAX_CANONICALS, the roots it can mint) are
    read, not copied."""
    from . import topology as topo
    out: Dict[str, str] = {}
    roots = _ids(t, "roots")
    for i, c in enumerate(t.get("canonicals", [])):
        sid = f"canonical:{c['id']}"
        if i >= topo.MAX_CANONICALS:
            out[sid] = (f"a canonical beyond the first ({c['id']}): one root per mesh — mint_accord_root "
                        "rewrites the mesh's base env, so a second root cannot share it")
            continue
        r = roots.get(c["holds"], {})
        if topo._is_accord_root(r):
            f = r.get("founders", {})
            if (f.get("seated"), r.get("quorum")) != (3, 2):
                out[sid] = "the ceremony mints exactly three seated holders at quorum:2/3"
        else:
            bad = [f"{k}={r.get(k, v)!r}" for k, v in topo.BUILDABLE_ROOT.items() if r.get(k, v) != v]
            if bad:
                out[sid] = f"root {r.get('id')}: {', '.join(bad)} (the anchor mints {topo.BUILDABLE_ROOT})"
    have = built_relations()
    for i, rel in enumerate(t.get("relations", [])):
        k, sid = rel["rel"], f"rel[{i}]:{rel['rel']}"
        if rel.get("known_red") and not INCLUDE_KNOWN_RED:
            out[sid] = f"known red: {rel['known_red']} (a filed product defect; --include-known-red builds through it)"
        elif k in topo.REFUSED_RELATIONS:
            out[sid] = f"relation `{k}`: {topo.REFUSED_RELATIONS[k]}"
        elif k in topo.AWAITING_ROUTE:
            out[sid] = f"relation `{k}`: no product route yet — {topo.AWAITING_ROUTE[k]}"
        elif k in topo.PENDING_BUILDER:
            out[sid] = f"relation `{k}`: route exists, builder branch not written — {topo.PENDING_BUILDER[k]}"
        elif k not in have:
            out[sid] = f"relation `{k}`: no builder yet"
    return out


def buildable_prefix(t: Decl) -> int:
    """How many steps the builder stands up before the first one it refuses
    (len(steps) = the whole entry)."""
    refused = refused_steps(t)
    for i, s in enumerate(steps(t)):
        if s.id in refused:
            return i
    return len(steps(t))


def not_buildable(t: Decl) -> List[str]:
    """Why `run` would stop short on this entry, by name (empty = buildable)."""
    from . import topology as topo
    try:
        topo.check(dict(t))
    except topo.Unrealizable as e:
        return [f"unrealizable: {e}"]
    return [f"{sid}: {why}" for sid, why in refused_steps(t).items()]


# ── the catalogue ───────────────────────────────────────────────────────────


@dataclass
class Entry:
    catalog_id: str
    title: str
    path: Path
    topology: Decl
    serves: List[str] = field(default_factory=list)
    promises: List[str] = field(default_factory=list)
    extends: Optional[str] = None

    @property
    def cost(self) -> int:
        """Nodes dominate (each is a process and a claim), then steps."""
        t = self.topology
        return 10 * (len(t.get("nodes", [])) + len(t.get("canonicals", []))) + len(steps(t))


def load_entry(path: Path) -> Entry:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if doc.get("catalogue_version") != CATALOGUE_VERSION:
        raise ValueError(f"{path.name}: catalogue_version {doc.get('catalogue_version')!r}, this model is {CATALOGUE_VERSION}")
    t = doc["topology"]
    t.setdefault("negatives", [])
    return Entry(doc["catalog_id"], doc.get("title", ""), Path(path), t, doc.get("serves", []),
                 doc.get("promises", []), doc.get("extends"))


def catalogue(root: Path = CATALOG_DIR) -> Dict[str, Entry]:
    out = {}
    for p in sorted(root.glob("T*.yaml")):
        e = load_entry(p)
        out[e.catalog_id] = e
    return out


@dataclass
class Requirement:
    """One test a CSD needs: the atoms that hold at once when it runs, the
    entry the CSD names (a hint — the planner may choose a cheaper one that
    reaches the same states), and the probe to run there."""
    csd: str
    name: str
    at: FrozenSet[str]
    topology: Optional[str] = None
    probe: Optional[Decl] = None

    @property
    def key(self) -> str:
        return f"{self.csd}/{self.name}"


def load_requirements(path: Path = REQUIREMENTS) -> List[Requirement]:
    """`requirements.yaml`: `CSD-nnn: {topology: Tn, tests: {name: {at: [atoms], probe: {...}}}}`."""
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    out = []
    for csd, spec in doc.items():
        for name, test in (spec.get("tests") or {}).items():
            if True in (test.get("probe") or {}):
                raise ValueError(f"{csd}/{name}: the probe names its node with `on:`, which YAML 1.1 reads as "
                                 "the boolean true — use `node:`")
            out.append(Requirement(csd, name, frozenset(test["at"]), spec.get("topology"), test.get("probe")))
    return out


# ── the planner ─────────────────────────────────────────────────────────────


@dataclass
class Plan:
    """`stop_before`: entry → the first step the builder refuses, where the
    runner ends that build (absent = the whole entry is built)."""
    entries: List[str]
    schedule: Dict[str, Dict[str, List[str]]]   # entry → step id → requirement keys
    uncovered: Dict[str, str]                  # requirement key → why
    reselected: Dict[str, str]                 # requirement key → "Tn → Tm" when the hint was not chosen
    cost: int
    stop_before: Dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> Decl:
        return {"entries": self.entries, "cost": self.cost, "schedule": self.schedule,
                "stop_before": self.stop_before, "uncovered": self.uncovered, "reselected": self.reselected}


def plan(reqs: List[Requirement], cat: Dict[str, Entry], buildable_only: bool = True) -> Plan:
    """The least-cost SET of catalogue entries whose traces reach every
    requirement's states, and each requirement's checkpoint: the earliest
    step of the cheapest chosen entry where its atoms hold at once.

    Exact: the catalogue is closed (ten entries), so every subset is tried —
    1024 at most, each a set check. The catalogue is never extended to fit a
    requirement (the steward's ruling: a catalogue, not a grammar); a
    requirement no entry reaches is UNCOVERED, by name."""
    usable = dict(cat)
    limits = {cid: (buildable_prefix(e.topology) if buildable_only else None) for cid, e in cat.items()}
    hit: Dict[str, Dict[str, int]] = {r.key: {} for r in reqs}
    for r in reqs:
        for cid, e in usable.items():
            i = first_index(e.topology, r.at, limits[cid])
            if i is not None:
                hit[r.key][cid] = i
    uncovered: Dict[str, str] = {}
    for r in reqs:
        if hit[r.key]:
            continue
        unknown = sorted(r.at - set(ATOMS))
        if unknown:
            uncovered[r.key] = f"atoms not in the catalogue vocabulary: {unknown}"
            continue
        anywhere = [cid for cid, e in cat.items() if first_index(e.topology, r.at) is not None]
        if anywhere:
            # Name the entry the CSD itself names when it reaches the states;
            # otherwise the cheapest that does.
            cid = r.topology if r.topology in anywhere else min(anywhere, key=lambda c: (cat[c].cost, c))
            e = cat[cid].topology
            sid = steps(e)[buildable_prefix(e)].id
            uncovered[r.key] = f"reached only past {cid} {sid} — {refused_steps(e)[sid]}"
        else:
            uncovered[r.key] = f"no catalogue entry reaches {sorted(r.at)} at one instant"
    coverable = [r for r in reqs if hit[r.key]]
    ids = sorted((c for c in usable if any(c in hit[r.key] for r in coverable)), key=lambda c: (usable[c].cost, c))
    best: Optional[Tuple[int, Tuple[str, ...]]] = None
    for n in range(0, len(ids) + 1):
        for combo in itertools.combinations(ids, n):
            if all(any(c in hit[r.key] for c in combo) for r in coverable):
                cost = sum(usable[c].cost for c in combo)
                if best is None or cost < best[0]:
                    best = (cost, combo)
        if best is not None:
            break  # fewest builds first; among those, least cost
    chosen = list(best[1]) if best else []
    schedule: Dict[str, Dict[str, List[str]]] = {c: {} for c in chosen}
    reselected: Dict[str, str] = {}
    for r in coverable:
        options = sorted((c for c in chosen if c in hit[r.key]), key=lambda c: (usable[c].cost, hit[r.key][c]))
        c = r.topology if r.topology in options else options[0]
        step_id = _step_id(usable[c].topology, hit[r.key][c])
        schedule[c].setdefault(step_id, []).append(r.key)
        if r.topology and r.topology != c:
            reselected[r.key] = f"{r.topology} → {c}"
    stop = {}
    if buildable_only:
        for c in chosen:
            n, all_steps = buildable_prefix(usable[c].topology), steps(usable[c].topology)
            if n < len(all_steps):
                stop[c] = all_steps[n].id
    return Plan(chosen, schedule, uncovered, reselected, best[0] if best else 0, stop)


def _step_id(t: Decl, i: int) -> str:
    return "start" if i < 0 else steps(t)[i].id


# ── evaluation ──────────────────────────────────────────────────────────────


def unknown_relations(t: Decl) -> List[str]:
    return sorted({r["rel"] for r in t.get("relations", [])} - KNOWN_RELATIONS)


def evaluate(cat: Optional[Dict[str, Entry]] = None, reqs: Optional[List[Requirement]] = None) -> Decl:
    """The catalogue's soundness report. `ok` is False on a CONTRADICTION
    (a broken promise, an unknown atom, a missing entry, an unrealizable
    declaration, a requirement nobody reaches); what the builder cannot build
    yet is reported, not failed — that is the honest state of the harness."""
    from . import topology as topo
    cat = catalogue() if cat is None else cat
    reqs = load_requirements() if reqs is None else reqs
    problems: List[str] = []
    entries: Decl = {}
    missing = [c for c in CATALOG_IDS if c not in cat]
    if missing:
        problems.append(f"catalogue entries missing: {missing}")
    extra = [c for c in cat if c not in CATALOG_IDS]
    if extra:
        problems.append(f"entries outside the closed catalogue: {extra}")
    reached_anywhere: Set[str] = set()
    for cid, e in sorted(cat.items(), key=lambda kv: int(kv[0][1:])):
        t = e.topology
        if e.path.stem.split("-")[0] != cid:
            problems.append(f"{e.path.name}: file name does not start with its catalog_id {cid}")
        try:
            topo.check(dict(t))
            realizable = True
        except topo.Unrealizable as err:
            realizable = False
            problems.append(f"{cid}: unrealizable: {err}")
        unk = unknown_relations(t)
        if unk:
            problems.append(f"{cid}: relations outside the typing: {unk}")
        for i, rel in enumerate(t.get("relations", [])):
            want = topo.AWAITING_ROUTE.get(rel["rel"])
            if want and rel.get("known_red") != want:
                problems.append(f"{cid}: rel[{i}] `{rel['rel']}` awaits {want} — mark it `known_red: {want}` "
                                f"(has {rel.get('known_red')!r})")
        first = reachable(t)
        reached_anywhere |= set(first)
        bad_atoms = sorted(set(e.promises) - set(ATOMS))
        if bad_atoms:
            problems.append(f"{cid}: promises atoms outside the vocabulary: {bad_atoms}")
        broken = sorted(a for a in e.promises if a in ATOMS and a not in first)
        if broken:
            problems.append(f"{cid}: promises {broken} but its steps never reach them")
        if e.extends:
            parent = cat.get(e.extends)
            if parent is None:
                problems.append(f"{cid}: extends unknown {e.extends}")
            else:
                lost = sorted(set(parent.promises) - set(first))
                if lost:
                    problems.append(f"{cid}: extends {e.extends} but never reaches its {lost}")
        refused = not_buildable(t) if realizable else ["unrealizable"]
        prefix = buildable_prefix(t) if realizable else 0
        entries[cid] = {
            "title": e.title, "file": e.path.name, "cost": e.cost, "serves": e.serves,
            "nodes": len(t.get("nodes", [])) + len(t.get("canonicals", [])),
            "persons": len(t.get("persons", [])),
            "steps": [s.id for s in steps(t)],
            "reaches": sorted(first, key=lambda a: (first[a], a)),
            "transient": {a: list(w) for a, w in windows(t).items()},
            "buildable": not refused, "refused_by": refused,
            "buildable_steps": prefix,
            "reaches_buildable": sorted(a for a in first if first[a] < prefix),
        }
    orphans = sorted(set(ATOMS) - reached_anywhere)
    if orphans:
        problems.append(f"vocabulary atoms no catalogue entry reaches: {orphans}")
    p = plan(reqs, cat, buildable_only=False)
    for k, why in p.uncovered.items():
        problems.append(f"requirement {k}: {why}")
    pb = plan(reqs, cat, buildable_only=True)
    for r in reqs:
        if r.topology and r.topology not in cat:
            problems.append(f"requirement {r.key}: names unknown topology {r.topology}")
        elif r.topology and first_index(cat[r.topology].topology, r.at) is None:
            problems.append(f"requirement {r.key}: names {r.topology}, which never reaches {sorted(r.at)}")
    return {
        "catalogue_version": CATALOGUE_VERSION,
        "ok": not problems,
        "problems": problems,
        "entries": entries,
        "vocabulary": len(ATOMS),
        "requirements": len(reqs),
        "plan_all": p.as_dict(),
        "plan_buildable": pb.as_dict(),
    }


def summary(rep: Decl) -> str:
    """The report as a table a person reads."""
    lines = [f"CSD/4 catalogue v{rep['catalogue_version']} — {'SOUND' if rep['ok'] else 'PROBLEMS'}; "
             f"{rep['vocabulary']} atoms, {rep['requirements']} requirements", ""]
    lines.append(f"{'id':4} {'nodes':>5} {'steps':>5} {'cost':>5}  buildable  title")
    for cid, e in rep["entries"].items():
        built = "yes" if e["buildable"] else f"{e['buildable_steps']}/{len(e['steps'])}"
        lines.append(f"{cid:4} {e['nodes']:>5} {len(e['steps']):>5} {e['cost']:>5}  {built:9}  {e['title']}")
        for why in e["refused_by"]:
            lines.append(f"{'':27}↳ {why}")
        if e["transient"]:
            lines.append(f"{'':27}transient: " + ", ".join(f"{a}[{w[0]},{w[1]})" for a, w in e["transient"].items()))
    for label in ("plan_all", "plan_buildable"):
        pl = rep[label]
        lines += ["", f"{label}: build {pl['entries']} (cost {pl['cost']})"]
        for cid, sid in pl.get("stop_before", {}).items():
            lines.append(f"  {cid} is built up to (not including) {sid}")
        for cid, sched in pl["schedule"].items():
            for sid, keys in sched.items():
                lines.append(f"  {cid} after {sid}: {', '.join(keys)}")
        for k, why in pl["uncovered"].items():
            lines.append(f"  UNCOVERED {k}: {why}")
        for k, how in pl["reselected"].items():
            lines.append(f"  reselected {k}: {how}")
    if rep["problems"]:
        lines += ["", "problems:"] + [f"  - {p}" for p in rep["problems"]]
    return "\n".join(lines)


def traces() -> Dict[str, Any]:
    """**The catalogue as a release asset** (`csd4-traces.json`): every entry's
    steps with the atoms holding after each, its buildable prefix and refused
    steps, under the catalogue version and the sha256 of each entry file. The
    shape CIRISClient's `packaging/vendor_csd4.py` produced by running this
    model itself; published per release so the client's CSD/4 checker needs no
    server code and pins bytes that cannot change under it."""
    import hashlib
    cat = catalogue()
    rep = evaluate(cat)
    if not rep.get("ok"):
        raise ValueError(f"the catalogue does not evaluate clean: {rep.get('problems')!r}")
    entries = {}
    for cid, e in sorted(cat.items(), key=lambda kv: int(kv[0][1:])):
        t = e.topology
        entries[cid] = {
            "file": e.path.name,
            "title": e.title,
            "promises": list(e.promises),
            "initial": [] if t.get("canonicals") else ["root.none"],
            "steps": [{"id": s.id, "atoms": sorted(st)} for s, st in trace(t)],
            "buildable_prefix": buildable_prefix(t),
            "refused": refused_steps(t),
        }
    return {
        "_meta": {
            "catalogue_version": CATALOGUE_VERSION,
            "catalog_ids": CATALOG_IDS,
            "sources": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in sorted(CATALOG_DIR.glob("T*.yaml"))},
            "generator": "python -m harness.native trace (harness.native.model.traces)",
        },
        "entries": entries,
    }
