"""Run a native-mesh scenario, or the CSD/4 catalogue (FSD/CSD4.md).

    python -m harness.native <scenario> --binary target/debug/ciris-server [--keep]
    python -m harness.native evaluate [--json]          # the catalogue model; no binary
    python -m harness.native plan [--csd CSD-091,...]   # which entries, which checkpoints; no binary
    python -m harness.native run --binary ... [--csd ...] [--at-state-cmd '...']
    python -m harness.native build --topology T3 --binary ...   # a catalogue id or a yaml path

`--binary` is any `ciris-server` built with `--features test-anchor` (the
synthetic trust root is only honoured there). `--keep` leaves every node
running and prints their URLs and tokens, so the next question is asked of the
same nodes. Node logs: <work>/<node>/node.log.
"""
from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

from .mesh import Mesh, MeshError
from .scenarios import SCENARIOS


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario", choices=sorted(SCENARIOS) + ["build", "derive", "down", "evaluate", "plan", "run", "trace"])
    ap.add_argument("--topology", type=str, help="build/derive: a catalogue id (T0–T9) or a FSD/TOPOLOGY.md declaration")
    ap.add_argument("--binary", type=Path, help="a test-anchor ciris-server (every verb but evaluate/plan/down)")
    ap.add_argument("--csd", default="", help="plan/run: comma-separated CSD ids (default: every requirement)")
    ap.add_argument("--requirements", type=Path, default=None, help="plan/run: requirements.yaml (default: the catalogue's)")
    ap.add_argument("--at-state-cmd", default="", help="run: a command run at each test's checkpoint "
                    "(${CSD} ${TEST} ${STEP} ${ENTRY} ${VALUES} substituted and in the environment)")
    ap.add_argument("--cmd-timeout", type=float, default=900)
    ap.add_argument("--snapshot-all", action="store_true", help="run: write a checkpoint snapshot after EVERY step")
    ap.add_argument("--json", action="store_true", help="evaluate/plan: print JSON instead of the table")
    ap.add_argument("--include-known-red", action="store_true",
                    help="plan/run: build THROUGH steps marked known_red (a filed defect) to see whether it is fixed")
    ap.add_argument("--work", type=Path, default=Path("/tmp/ciris-native-mesh"))
    ap.add_argument("--keep", action="store_true", help="leave the nodes running")
    ap.add_argument("--owner-wait", type=float, default=90)
    ap.add_argument("--ready-wait", type=float, default=180)
    ap.add_argument("--arrive-wait", type=float, default=180)
    ap.add_argument("--contact-via", choices=["owner", "code"], default="owner")
    ap.add_argument("--rooted-wait", type=float, default=0, help="chat: seconds to wait for the pair to be Rooted (0 = observe only)")
    ap.add_argument("--reachable-wait", type=float, default=120, help="chat: seconds to re-add a contact until reachable_nodes>=1 (0 = no gate)")
    ap.add_argument("--only", default="", help="corpus: comma-separated file names")
    ap.add_argument("--rust-log", default="info,ciris_edge=debug")
    ap.add_argument("--agent-url", default="http://127.0.0.1:4243",
                    help="halt_agent: the agent's own node fold (never bound by this harness)")
    ap.add_argument("--agent-wait", type=float, default=1800,
                    help="halt_agent: seconds to wait for the agent's node, its ready file and its act")
    ap.add_argument("--direct", action="store_true",
                    help="chat: the second node also dials the first (direct neighbours)")
    args = ap.parse_args()
    if args.include_known_red:
        from . import model
        model.INCLUDE_KNOWN_RED = True
    if args.scenario == "trace":
        from . import model
        print(json.dumps(model.traces(), indent=1, sort_keys=True))
        return 0
    if args.scenario in ("evaluate", "plan"):
        from . import model
        if args.scenario == "evaluate":
            rep = model.evaluate(reqs=model.load_requirements(args.requirements or model.REQUIREMENTS))
            print(json.dumps(rep, indent=1, default=str) if args.json else model.summary(rep))
            return 0 if rep["ok"] else 1
        from .runner import select
        reqs = select(model.load_requirements(args.requirements or model.REQUIREMENTS), args.csd)
        p = model.plan(reqs, model.catalogue())
        print(json.dumps(p.as_dict(), indent=1))
        return 0
    if args.binary is None and args.scenario != "down":
        ap.error("--binary is required for " + args.scenario)
    if args.scenario == "run":
        from .runner import run
        from . import model
        args.requirements = args.requirements or model.REQUIREMENTS
        if args.work == Path("/tmp/ciris-native-mesh"):
            args.work = Path("/tmp/ciris-native-csd4")
        return run(args)
    if args.topology and not args.topology.endswith((".yaml", ".yml")):
        from . import model
        cat = model.catalogue()
        if args.topology not in cat:
            print(json.dumps({"verdict": "UNREALIZABLE", "error": f"no catalogue entry {args.topology}"}))
            return 2
        # A catalogue id builds its BUILDABLE PREFIX: it stops, as a PASS of
        # what stands, before the first step the builder refuses (FSD/CSD4.md §5).
        entry = cat[args.topology]
        n = model.buildable_prefix(entry.topology)
        all_steps = model.steps(entry.topology)
        args.stop_before = all_steps[n].id if n < len(all_steps) else None
        args.topology = str(entry.path)
    if args.scenario == "down":
        print(json.dumps({"stopped": Mesh.down(args.work)}))
        return 0
    if args.scenario in ("build", "derive"):
        from . import topology as topo
        try:
            decl = topo.load(args.topology)
        except topo.Unrealizable as e:
            print(json.dumps({"verdict": "UNREALIZABLE", "error": str(e)}))
            return 2
        if args.scenario == "derive":
            print(json.dumps(topo.derive(decl), indent=1, default=str))
            return 0
        SCENARIOS["build"] = lambda mesh, a: topo.build(mesh, decl, a, stop_before=getattr(a, "stop_before", None))

    mesh = Mesh(args.binary, args.work, keep=args.keep, rust_log=args.rust_log)
    code = 0
    with mesh:
        try:
            result = SCENARIOS[args.scenario](mesh, args)
        except MeshError as e:
            result = {"verdict": "BROKEN", "error": str(e)}
            try:  # a build failure carries its first failing layer as JSON
                parsed = json.loads(str(e))
                result.update({"error": parsed.get("error"), "first_failing_layer": parsed.get("first_failing_layer")})
            except Exception:  # noqa: BLE001
                pass
            code = 2
        except Exception:  # noqa: BLE001
            result = {"verdict": "CRASH", "error": traceback.format_exc()[-2000:]}
            code = 3
        if result.get("verdict") == "FAIL":
            code = 1
        print("═══ VERDICT", json.dumps({k: v for k, v in result.items() if k not in ("steps", "results")}, indent=1))
        report = {"scenario": args.scenario, "binary": str(mesh.binary), "args": vars(args) | {"binary": str(args.binary), "work": str(args.work)},
                  **result, "nodes": mesh.state()}
        (mesh.work / "report.json").write_text(json.dumps(report, indent=1, default=str), encoding="utf-8")
        if result.get("values"):
            # The client's two-node fixture shape (testing/gate/two_node.py values.json):
            # a client flow reads ${PEER_KEY_ID}, ${MESSAGE_ATTESTATION_ID}, … from here.
            (mesh.work / "values.json").write_text(json.dumps(result["values"], indent=1), encoding="utf-8")
        print(f"report: {mesh.work / 'report.json'}" + (f"  values: {mesh.work / 'values.json'}" if result.get("values") else ""))
        if args.keep:
            print("nodes left running — `python -m harness.native down --work " + str(mesh.work) + "` stops them")
            print(json.dumps(mesh.state(), indent=1))
    return code


if __name__ == "__main__":
    sys.exit(main())
