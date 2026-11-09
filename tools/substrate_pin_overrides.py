#!/usr/bin/env python3
"""Print the cohabitation `pin-overrides` JSON from this server's own Cargo pins.

The CIRISConformance cohabitation gate installs a "coherent set" of the separate
edge / persist / verify wheels next to the ciris-server wheel under test. With no
override it takes that set from CIRISConformance's live matrix on `main`, which
moves on its own schedule. When the matrix lagged our pins (0.5.245: matrix edge
v44.0.0 / persist v61.0.4, our wheel edge v44.1.0 / persist v61.0.5) the process
loaded two builds of each substrate and segfaulted on postgres, red on a PR and
blocking the tag's PyPI publish.

So the gate tests the substrate we SHIP: these overrides come from Cargo.toml,
the same pins the wheel is built from (CIRISEdge's `extract-substrate-pins`
shape). Stdlib only; one copy, called by conformance.yml and publish-pypi.yml.

Usage:
    python3 tools/substrate_pin_overrides.py            # print the JSON
    python3 tools/substrate_pin_overrides.py --github   # `json=<...>` for $GITHUB_OUTPUT
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _pin(text: str, lock: str, crate: str) -> tuple[str, str]:
    """(version, git ref) for the FIRST `crate = { ... }` pin in Cargo.toml.

    A `tag = "vX.Y.Z"` pin names both; a `rev = "<sha>"` pin (a prestage) takes
    the version from Cargo.lock and the ref from the sha.
    """
    m = re.search(
        rf'^{re.escape(crate)}\s*=\s*\{{[^}}]*tag\s*=\s*"v(\d+\.\d+\.\d+)"', text, re.M
    )
    if m:
        return m.group(1), f"v{m.group(1)}"
    m = re.search(
        rf'^{re.escape(crate)}\s*=\s*\{{[^}}]*rev\s*=\s*"([0-9a-f]{{7,40}})"', text, re.M
    )
    if m:
        v = re.search(rf'^name = "{re.escape(crate)}"\nversion = "([^"]+)"', lock, re.M)
        if not v:
            raise SystemExit(f"no {crate} entry in Cargo.lock")
        return v.group(1), m.group(1)
    raise SystemExit(f"no tag or rev pin for {crate} in Cargo.toml")


def overrides(root: pathlib.Path = ROOT) -> dict[str, str]:
    text = (root / "Cargo.toml").read_text(encoding="utf-8")
    lock = (root / "Cargo.lock").read_text(encoding="utf-8")
    _, edge_ref = _pin(text, lock, "ciris-edge")
    _, persist_ref = _pin(text, lock, "ciris-persist")
    verify, _ = _pin(text, lock, "ciris-verify-core")
    major = int(verify.split(".")[0])
    return {
        "ciris-edge": f"git+https://github.com/CIRISAI/CIRISEdge.git@{edge_ref}",
        "ciris-persist": f"git+https://github.com/CIRISAI/CIRISPersist.git@{persist_ref}",
        # A plain PyPI range: CIRISVerify's Python project is not at the repo
        # root, and a major range mirrors persist's own Requires-Dist firewall.
        "ciris-verify": f"ciris-verify>={major},<{major + 1}",
    }


def main(argv: list[str]) -> int:
    pins = json.dumps(overrides(), separators=(",", ":"))
    print(f"json={pins}" if "--github" in argv else pins)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
