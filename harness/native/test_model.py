"""The CSD/4 catalogue model, checked without a node (FSD/CSD4.md §7).

    python3 -m pytest -q harness/native/test_model.py
"""
from __future__ import annotations

import copy

import pytest

from . import model, topology


@pytest.fixture(scope="module")
def cat():
    return model.catalogue()


def test_the_catalogue_is_sound(cat):
    rep = model.evaluate(cat)
    assert rep["ok"], rep["problems"]


def test_the_catalogue_is_closed_and_versioned(cat):
    assert sorted(cat, key=lambda c: int(c[1:])) == model.CATALOG_IDS
    for e in cat.values():
        assert e.path.name.startswith(e.catalog_id + "-")


def test_every_relation_in_the_typing_is_built_or_refused_by_name():
    built = model.built_relations()
    named = set(topology.REFUSED_RELATIONS) | set(topology.AWAITING_ROUTE) | set(topology.PENDING_BUILDER)
    loose = model.KNOWN_RELATIONS - built - named
    assert not loose, f"relations the model types that the builder neither builds nor names as refused, " \
                      f"awaiting a route or pending a branch: {loose}"
    assert not (built & named), \
        "a relation both built and refused — the refusal wins at build time and the branch is dead"
    tables = [set(topology.REFUSED_RELATIONS), set(topology.AWAITING_ROUTE), set(topology.PENDING_BUILDER)]
    assert not any(a & b for i, a in enumerate(tables) for b in tables[i + 1:]), "a relation in two status tables"


def test_every_step_awaiting_a_route_is_marked_known_red_by_its_issue(cat):
    bad = copy.deepcopy(cat)
    rel = next(r for r in bad["T11"].topology["relations"] if r["rel"] == "evict_lone")
    del rel["known_red"]
    assert any("awaits CIRISServer#794" in p for p in model.evaluate(bad)["problems"])
    rel["known_red"] = "CIRISServer#1"
    assert any("awaits CIRISServer#794" in p for p in model.evaluate(bad)["problems"])


def test_a_roster_size_holds_exactly_while_it_is_true(cat):
    t11 = cat["T11"].topology
    tr = model.trace(t11)
    ids = [s.id for s, _ in tr]
    at = lambda sid: dict((s.id, st) for s, st in tr)[sid]
    last_join = max(i for i, x in enumerate(ids) if x.endswith(":join_complete"))
    assert "self.roster_size.three_more" in tr[last_join][1]
    assert "self.roster_size.one" not in tr[last_join][1]
    end = tr[-1][1]
    assert "self.roster_size.one" in end and "self.roster_size.three_more" not in end
    assert "key.membership.evicted" in end and "key.holder.lost" in end
    assert at("person:alice") >= {"self.roster_size.one", "key.holder.owner", "key.revocation.none"}


def test_each_new_v2_atom_is_promised_by_an_entry(cat):
    import json
    doc = json.loads(model.VOCABULARY.read_text(encoding="utf-8"))
    v2 = {a for a, r in doc["atoms"].items() if r.get("added_in") == 2}
    promised = {a for e in cat.values() for a in e.promises}
    assert not (v2 - promised), f"version-2 atoms no entry promises: {sorted(v2 - promised)}"
    for e in doc["entries_proposed"]:
        assert set(e["promises"]) <= set(cat[e["id"]].promises), (e["id"], set(e["promises"]) - set(cat[e["id"]].promises))


def test_step_ids_are_unique_per_entry(cat):
    for cid, e in cat.items():
        ids = [s.id for s in model.steps(e.topology)]
        assert len(ids) == len(set(ids)), cid


def test_transient_states_close_where_the_step_says(cat):
    t8 = cat["T8"].topology
    w = model.windows(t8)
    ids = [s.id for s in model.steps(t8)]
    assert ids[w["root.halted"][0]].endswith(":halt")
    assert ids[w["root.halted"][1]].endswith(":resume")
    t3 = model.windows(cat["T3"].topology)
    # requested < approved < joined, and the device stays unclaimed until it joins
    assert t3["device.join_requested"][1] == t3["device.join_approved"][0]
    assert t3["node.unclaimed"][1] == t3["device.join_approved"][1]


def test_the_planner_picks_the_cheapest_entry_that_reaches_the_states(cat):
    r = model.Requirement("CSD-X", "self_room", frozenset({"room.self.keyed"}), topology="T4")
    p = model.plan([r], cat)
    assert p.entries == ["T1"], p.as_dict()
    assert p.reselected == {"CSD-X/self_room": "T4 → T1"}


def test_the_planner_keeps_a_hint_that_is_already_chosen(cat):
    reqs = [model.Requirement("CSD-A", "a", frozenset({"device.joined"})),
            model.Requirement("CSD-B", "b", frozenset({"room.self.keyed"}), topology="T3")]
    p = model.plan(reqs, cat)
    assert p.entries == ["T3"]  # T3 alone covers both: one build, not two
    assert not p.reselected


def test_states_that_never_hold_together_are_uncovered_by_name(cat):
    r = model.Requirement("CSD-X", "both", frozenset({"root.halted", "root.resumed"}))
    p = model.plan([r], cat)
    assert "CSD-X/both" in p.uncovered and "at one instant" in p.uncovered["CSD-X/both"]
    r2 = model.Requirement("CSD-X", "typo", frozenset({"room.keyed"}))
    assert "vocabulary" in model.plan([r2], cat).uncovered["CSD-X/typo"]


def test_a_refused_step_ends_the_buildable_prefix_not_the_entry(cat):
    t4 = cat["T4"].topology
    n = model.buildable_prefix(t4)
    assert model.steps(t4)[n].kind == "guardian_bond"
    seated = model.Requirement("CSD-101", "child", frozenset({"child.member"}))
    bond = model.Requirement("CSD-119", "bond", frozenset({"guardian.bound"}))
    sub = {c: e for c, e in cat.items() if c != "T18"}  # T18 also seats a child, more cheaply
    p = model.plan([seated, bond], sub)
    assert p.entries == ["T4"] and p.stop_before == {"T4": model.steps(t4)[n].id}
    assert "CSD-119/bond" in p.uncovered and "CSD-101/child" not in p.uncovered
    assert "CSD-119/bond" not in model.plan([seated, bond], sub, buildable_only=False).uncovered


def test_each_test_is_scheduled_at_the_earliest_step_its_states_hold(cat):
    reqs = model.load_requirements()
    p = model.plan(reqs, cat)
    for cid, sched in p.schedule.items():
        tr = {s.id: st for s, st in model.trace(cat[cid].topology)}
        order = [s.id for s in model.steps(cat[cid].topology)]
        for sid, keys in sched.items():
            for key in keys:
                need = next(r.at for r in reqs if r.key == key)
                assert need <= tr[sid], (cid, sid, key)
                before = order[:order.index(sid)]
                assert not any(need <= tr[b] for b in before), (cid, sid, key, "an earlier step already held it")


def test_a_broken_promise_is_a_problem(cat):
    bad = copy.deepcopy(cat)
    bad["T2"].promises = bad["T2"].promises + ["root.halted"]
    assert any("T2: promises ['root.halted']" in p for p in model.evaluate(bad)["problems"])


def test_an_unrealizable_entry_is_a_problem(cat):
    bad = copy.deepcopy(cat)
    for n in bad["T2"].topology["nodes"]:
        n["dials"] = ["C"]  # B no longer dials A: a message is two hops (rule 4)
    assert any(p.startswith("T2: unrealizable: rule 4") for p in model.evaluate(bad)["problems"])


def test_every_atom_is_documented_in_the_standard():
    from pathlib import Path
    doc = (Path(__file__).resolve().parents[2] / "FSD" / "CSD4.md").read_text(encoding="utf-8")
    missing = [a for a in model.ATOMS if f"| `{a}` |" not in doc]
    assert not missing, f"FSD/CSD4.md §3 does not list {missing}"


def test_a_known_red_step_blocks_by_its_issue_unless_built_through(cat):
    red = copy.deepcopy(cat)
    t3 = red["T3"].topology
    i = next(i for i, r in enumerate(t3["relations"]) if r["rel"] == "join_complete") + 1
    t3["relations"][i]["known_red"] = "CIRISServer#0000"
    assert model.steps(t3)[model.buildable_prefix(t3)].id == f"rel[{i}]:{t3['relations'][i]['rel']}"
    r = model.Requirement("CSD-094", "joined", frozenset({"device.joined", "file.held"}))
    p = model.plan([r], red)
    assert "CIRISServer#0000" in p.uncovered["CSD-094/joined"]
    # …and the cheapest other entry is NOT chosen for a state only T3 reaches.
    assert p.entries == []
    model.INCLUDE_KNOWN_RED = True
    try:
        assert not model.plan([r], red).uncovered
    finally:
        model.INCLUDE_KNOWN_RED = False


def test_the_vocabulary_is_the_constitutions_pinned_copy():
    import hashlib
    pin = dict(line.split("=", 1) for line in model.VOCABULARY_PIN.read_text(encoding="utf-8").splitlines()
               if line and not line.startswith("#"))
    got = hashlib.sha256(model.VOCABULARY.read_bytes()).hexdigest()
    assert got == pin["sha256"], (
        f"topology_vocabulary.json is not the byte copy of {pin['repo']}@{pin['commit'][:12]} "
        f"{pin['path']} — vocabulary changes land in CIRISConstitution first, then the pin moves")
    assert len(model.ATOMS) == 120


def test_another_catalogue_version_of_the_vocabulary_is_refused(tmp_path):
    import json
    doc = json.loads(model.VOCABULARY.read_text(encoding="utf-8"))
    doc["_meta"]["catalogue_version"] = 4
    bumped = tmp_path / "topology_vocabulary.json"
    bumped.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ValueError, match="catalogue_version 4, this model implements 5"):
        model._load_vocabulary(bumped)


def test_the_release_trace_asset_has_the_shape_the_client_pins():
    # `csd4-traces.json` (release.yml) is what CIRISClient's CSD/4 checker
    # vendors per release; its keys are that checker's contract.
    d = model.traces()
    assert d["_meta"]["catalogue_version"] == model.CATALOGUE_VERSION
    assert d["_meta"]["catalog_ids"] == model.CATALOG_IDS
    assert set(d["entries"]) == set(model.CATALOG_IDS)
    for e in d["entries"].values():
        assert set(e) == {"file", "title", "promises", "realized_by", "initial", "steps", "buildable_prefix",
                          "refused"}
        assert set(e["realized_by"]) <= set(e["promises"])
        assert all(set(s) == {"id", "atoms"} for s in e["steps"])


def test_a_promise_realized_elsewhere_is_bounded_but_not_claimed(cat):
    t7 = cat["T7"]
    agent = {"agent.deferral.pending", "agent.deferral.approved", "agent.deferral.rejected", "agent.identity.amended"}
    assert {a: r for a, r in t7.realized_by.items()} == {a: "CIRISAgent" for a in agent}
    assert agent <= set(t7.promises) and not (agent & set(t7.own_promises))
    assert not (agent & set(model.reachable(t7.topology))), "the harness builds no agent"
    # an atom outside the vocabulary is refused whoever realizes it
    bad = copy.deepcopy(cat)
    bad["T7"].promises.append("agent.flies")
    bad["T7"].realized_by["agent.flies"] = "CIRISAgent"
    assert any("T7: promises atoms outside the vocabulary: ['agent.flies']" in p for p in model.evaluate(bad)["problems"])
    # dropping the realizer makes the harness claim it, and its steps never reach it
    bad = copy.deepcopy(cat)
    del bad["T7"].realized_by["agent.identity.amended"]
    assert any("T7: promises ['agent.identity.amended'] but its steps never reach them" in p
               for p in model.evaluate(bad)["problems"])


def test_a_realizer_names_another_repo(tmp_path):
    src = (model.CATALOG_DIR / "T7-agent-steward-wa.yaml").read_text(encoding="utf-8")
    for bad in ("CIRISServer", "someone"):
        p = tmp_path / "T7-agent-steward-wa.yaml"
        p.write_text(src.replace("realizer: CIRISAgent}", f"realizer: {bad}}}", 1), encoding="utf-8")
        with pytest.raises(ValueError, match="another CIRIS repo"):
            model.load_entry(p)


def test_atoms_awaiting_an_entry_are_reported_not_failed(cat):
    durable = {a for a in model.ATOMS if a.startswith("file.durable")}
    assert len(durable) == 6 and set(model.AWAITING_ENTRY) == durable
    rep = model.evaluate(cat)
    assert rep["awaiting_entry"] == {a: "T20 (CIRISServer#809)" for a in durable}
    assert "awaiting T20 (CIRISServer#809)" in model.summary(rep)
    # once an entry promises one, the listing is stale and says so
    bad = copy.deepcopy(cat)
    bad["T7"].promises.append("file.durable")
    bad["T7"].realized_by["file.durable"] = "CIRISAgent"
    assert any("awaiting an entry that one now reaches: ['file.durable']" in p for p in model.evaluate(bad)["problems"])
