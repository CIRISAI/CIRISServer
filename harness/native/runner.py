"""Run CSD tests at the states they need (FSD/CSD4.md §6).

    python -m harness.native plan [--csd CSD-091,CSD-129]          # no binary
    python -m harness.native run  --binary <test-anchor ciris-server> [--csd ...]
                                  [--at-state-cmd 'client-flow ${CSD} ${TEST}']

`plan` asks the model (harness/native/model.py) which catalogue entries reach
every requested test's states, at least cost, and after which build step each
test runs. `run` builds each chosen entry on its own mesh, up to the first step
the builder refuses, and at every checkpoint:

  1. checks the model against the live nodes — each atom with a WITNESS (a
     read that decides it) must be present exactly when the model says so; a
     disagreement is `model_drift`, a failure of the model, not of the CSD;
  2. writes `checkpoints/<step>.json` (the values, the atoms, every node's URL
     and token) — the fixture a client flow drives at THAT state;
  3. runs each test scheduled there: its declared probe, then `--at-state-cmd`
     with CSD/TEST/STEP/ENTRY/VALUES in the environment.

A failed test is recorded and the build continues (the next state may serve
other tests); a failed BUILD step ends that entry and names its layer.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import model
from .mesh import Mesh, MeshError, Node

Decl = Dict[str, Any]


# ── witnesses: atoms a live read decides ────────────────────────────────────


def _person_nodes(ctx: Any) -> List[Node]:
    canon = {c["id"] for c in ctx.t.get("canonicals", [])}
    return [n for nid, n in ctx.N.items() if nid not in canon and n.proc]  # a lost device reads nothing


def _first_run(n: Node) -> Optional[bool]:
    st, body = n.api("GET", "/v1/setup/status")
    return ((body or {}).get("data") or {}).get("is_first_run") if st == 200 and isinstance(body, dict) else None


def _w_unclaimed(ctx: Any) -> Optional[bool]:
    seen = [_first_run(n) for n in _person_nodes(ctx)]
    return None if not seen or any(s is None for s in seen) else any(seen)


def _w_halted(ctx: Any) -> Optional[bool]:
    live = [n for n in ctx.N.values() if n.token and n.proc]
    if not live or not getattr(ctx.mesh, "accord_holders", None):
        return None
    st, body = live[0].api("GET", "/v1/accord/halt-status")
    return bool((body or {}).get("halted")) if st == 200 else None


def _join_states(ctx: Any) -> Optional[List[Optional[str]]]:
    """Each joining device's add-device state (an entry may join several in
    turn, T10/T11). A stopped device (`lose`) reads as no state."""
    joining = [nid for p in ctx.t.get("persons", []) for nid in p.get("joins", []) if nid in ctx.N]
    if not joining:
        return None
    out: List[Optional[str]] = []
    for nid in joining:
        try:
            st, body = ctx.N[nid].api("GET", "/v1/setup/add-device")
        except Exception:  # noqa: BLE001 — a stopped node holds no join in flight
            out.append(None)
            continue
        out.append((body or {}).get("state") if st == 200 and isinstance(body, dict) else None)
    return out


def _w_join(want: str) -> Callable[[Any], Optional[bool]]:
    def w(ctx: Any) -> Optional[bool]:
        states = _join_states(ctx)
        return None if states is None else any(s == want for s in states)
    return w


WITNESSES: Dict[str, Callable[[Any], Optional[bool]]] = {
    "node.unclaimed": _w_unclaimed,
    "root.halted": _w_halted,
    "device.join_requested": _w_join("requested"),
    "device.join_approved": _w_join("approved"),
}


# ── probes ──────────────────────────────────────────────────────────────────


def _subst(s: str, values: Dict[str, str]) -> str:
    return re.sub(r"\$\{([A-Z0-9_]+)\}", lambda m: str(values.get(m.group(1), m.group(0))), s)


def _dig(obj: Any, path: str) -> Any:
    for part in path.split("."):
        obj = obj.get(part) if isinstance(obj, dict) else None
    return obj


def run_probe(probe: Decl, ctx: Any) -> Decl:
    if True in probe:  # `on:` — YAML 1.1 reads the key as the boolean true
        return {"ok": False, "why": "the probe names its node with `on:`, which YAML reads as `true`; use `node:`"}
    node = ctx.N[probe.get("node") or ctx.t["actor"]["device"]]
    path = _subst(probe["path"], ctx.values)
    if "${" in path:
        return {"ok": False, "why": f"unresolved value in {path} — no earlier step produced it"}
    st, body = node.api(probe.get("method", "GET"), path, probe.get("body"))
    want_st = probe.get("status", 200)
    bad = {k: _dig(body, k) for k, v in (probe.get("expect") or {}).items() if _dig(body, k) != v}
    ok = st == want_st and not bad
    return {"ok": ok, "status": st, "path": path, **({"mismatch": bad} if bad else {}),
            **({} if ok else {"body": str(body)[:300]})}


# ── the run ─────────────────────────────────────────────────────────────────


def select(reqs: List[model.Requirement], csds: str) -> List[model.Requirement]:
    want = {c.strip() for c in csds.split(",") if c.strip()}
    if not want:
        return reqs
    unknown = want - {r.csd for r in reqs}
    if unknown:
        raise SystemExit(f"no requirements for {sorted(unknown)} in {model.REQUIREMENTS}")
    return [r for r in reqs if r.csd in want]


def run(args: Any) -> int:
    from . import topology as topo
    cat = model.catalogue()
    reqs = select(model.load_requirements(args.requirements), args.csd)
    by_key = {r.key: r for r in reqs}
    p = model.plan(reqs, cat, buildable_only=True)
    print("── PLAN ──\n" + json.dumps(p.as_dict(), indent=1), flush=True)
    results: Dict[str, Decl] = {k: {"verdict": "NOT_RUN", "why": why} for k, why in p.uncovered.items()}
    entries: Decl = {}
    code = 0
    for cid in p.entries:
        e = cat[cid]
        t = e.topology
        tr = {s.id: st for s, st in model.trace(t)}
        sched = p.schedule.get(cid, {})
        work = Path(args.work) / cid
        ckdir = work / "checkpoints"
        drift: List[Decl] = []

        def checkpoint(step_id: str, ctx: Any) -> None:
            atoms = tr[step_id]
            for atom, witness in WITNESSES.items():
                try:
                    live = witness(ctx)
                except Exception as err:  # noqa: BLE001 — a witness that cannot read decides nothing
                    live = None
                    print(json.dumps({"witness_error": atom, "step": step_id, "error": str(err)[:200]}), flush=True)
                if live is not None and live != (atom in atoms):
                    drift.append({"step": step_id, "atom": atom, "model": atom in atoms, "live": live})
                    print(json.dumps({"model_drift": atom, "step": step_id, "model": atom in atoms, "live": live}), flush=True)
            if not sched.get(step_id) and not args.snapshot_all:
                return
            ckdir.mkdir(parents=True, exist_ok=True)
            snap = {"entry": cid, "step": step_id, "atoms": sorted(atoms), "values": dict(ctx.values),
                    "nodes": {nid: {"url": n.url, "token": n.token, "owner_key_id": n.owner_key_id,
                                    "node_key_id": n.node_key_id} for nid, n in ctx.N.items()}}
            snap_path = ckdir / f"{re.sub(r'[^A-Za-z0-9_.-]+', '_', step_id)}.json"
            snap_path.write_text(json.dumps(snap, indent=1), encoding="utf-8")
            for key in sched.get(step_id, []):
                r = by_key[key]
                out: Decl = {"entry": cid, "step": step_id, "at": sorted(r.at), "snapshot": str(snap_path)}
                missing = sorted(r.at - atoms)
                ok = not missing
                if missing:
                    out["why"] = f"the planner scheduled it where {missing} do not hold (planner bug)"
                if ok and r.probe:
                    out["probe"] = run_probe(r.probe, ctx)
                    ok = out["probe"]["ok"]
                if ok and args.at_state_cmd:
                    env = {**os.environ, "CSD": r.csd, "TEST": r.name, "STEP": step_id, "ENTRY": cid,
                           "VALUES": str(snap_path)}
                    cmd = _subst(args.at_state_cmd, {"CSD": r.csd, "TEST": r.name, "STEP": step_id,
                                                     "ENTRY": cid, "VALUES": str(snap_path)})
                    got = subprocess.run(shlex.split(cmd), capture_output=True, text=True, env=env,
                                         timeout=args.cmd_timeout)
                    out["cmd"] = {"exit": got.returncode, "tail": (got.stdout + got.stderr)[-600:]}
                    ok = got.returncode == 0
                out["verdict"] = "PASS" if ok else "FAIL"
                results[key] = out
                print(json.dumps({"test": key, **{k: v for k, v in out.items() if k != "snapshot"}}), flush=True)

        args.topology = f"{cid} ({e.path.name})"
        mesh = Mesh(args.binary, work, keep=args.keep, rust_log=args.rust_log)
        with mesh:
            try:
                built = topo.build(mesh, t, args, checkpoint=checkpoint, stop_before=p.stop_before.get(cid))
                verdict = "PASS"
            except MeshError as err:
                built = {"error": str(err)[:2000]}
                verdict = "BROKEN"
            except Exception as err:  # noqa: BLE001
                built = {"error": f"{type(err).__name__}: {err}"[:2000]}
                verdict = "CRASH"
        if drift:
            verdict = "MODEL_DRIFT" if verdict == "PASS" else verdict
        entries[cid] = {"verdict": verdict, "built": built.get("built"), "stopped_before": built.get("stopped_before"),
                        "error": built.get("error"), "drift": drift, "work": str(work)}
        for steps_ in sched.values():
            for key in steps_:
                results.setdefault(key, {"verdict": "NOT_REACHED", "entry": cid,
                                         "why": f"the build of {cid} ended before this test's checkpoint"})
        print(json.dumps({"entry": cid, "verdict": verdict, "stopped_before": built.get("stopped_before"),
                          "error": (built.get("error") or "")[:300]}), flush=True)
    failed = [k for k, v in results.items() if v["verdict"] in ("FAIL", "NOT_REACHED")]
    broken = [c for c, v in entries.items() if v["verdict"] != "PASS"]
    if failed or broken:
        code = 1
    report = {"plan": p.as_dict(), "entries": entries, "results": results,
              "not_run": sorted(k for k, v in results.items() if v["verdict"] == "NOT_RUN"),
              "failed": failed, "broken_entries": broken}
    Path(args.work).mkdir(parents=True, exist_ok=True)
    (Path(args.work) / "csd4_report.json").write_text(json.dumps(report, indent=1, default=str), encoding="utf-8")
    print("═══ CSD/4 RUN", json.dumps({"entries": {c: v["verdict"] for c, v in entries.items()},
                                       "passed": sum(1 for v in results.values() if v["verdict"] == "PASS"),
                                       "failed": failed, "not_run": report["not_run"]}, indent=1))
    print(f"report: {Path(args.work) / 'csd4_report.json'}")
    return code
