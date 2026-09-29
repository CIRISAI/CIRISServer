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
    ap.add_argument("scenario", choices=sorted(SCENARIOS))
    ap.add_argument("--binary", type=Path, required=True)
    ap.add_argument("--work", type=Path, default=Path("/tmp/ciris-native-mesh"))
    ap.add_argument("--keep", action="store_true", help="leave the nodes running")
    ap.add_argument("--owner-wait", type=float, default=90)
    ap.add_argument("--ready-wait", type=float, default=180)
    ap.add_argument("--arrive-wait", type=float, default=180)
    ap.add_argument("--contact-via", choices=["owner", "code"], default="owner")
    ap.add_argument("--only", default="", help="corpus: comma-separated file names")
    ap.add_argument("--rust-log", default="info,ciris_edge=debug")
    args = ap.parse_args()

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
        print("═══ VERDICT", json.dumps({k: v for k, v in result.items() if k != "steps"}, indent=1))
        if args.keep:
            print(json.dumps({n: {"url": x.url, "token": x.token, "log": str(x.log_path)}
                              for n, x in mesh.nodes.items()}, indent=1))
    return code


if __name__ == "__main__":
    sys.exit(main())
