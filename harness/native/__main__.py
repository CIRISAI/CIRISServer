"""Run a native-mesh scenario.

    python -m harness.native <scenario> --binary target/debug/ciris-server [--keep]

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
    ap.add_argument("scenario", choices=sorted(SCENARIOS) + ["build", "derive", "down"])
    ap.add_argument("--topology", type=Path, help="build/derive: a FSD/TOPOLOGY.md declaration")
    ap.add_argument("--binary", type=Path, required=True)
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
    ap.add_argument("--direct", action="store_true",
                    help="chat: the second node also dials the first (direct neighbours)")
    args = ap.parse_args()
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
        SCENARIOS["build"] = lambda mesh, a: topo.build(mesh, decl, a)

    mesh = Mesh(args.binary, args.work, keep=args.keep, rust_log=args.rust_log)
    code = 0
    with mesh:
        try:
            result = SCENARIOS[args.scenario](mesh, args)
        except MeshError as e:
            result = {"verdict": "BROKEN", "error": str(e)}
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
