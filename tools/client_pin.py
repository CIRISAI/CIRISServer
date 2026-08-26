#!/usr/bin/env python3
"""Print the `ciris-client` requirement this server pins, from `pyproject.toml`.

CIRISServer#471 made the client an installed dependency rather than a vendored
tree, which moved its version into `pyproject.toml` — and immediately spawned
FIVE copies of that version string: two CI install steps, the Rust test
support's panic message, the Python guard's, and the dependency itself. That is
the same shape as the substrate stamps living in four places, and it fails the
same way: the pin moves, the copies do not, and CI installs a version the code
was never tested against while every message confidently names the old one.

So there is one copy and everything else asks this. Stdlib only, because the CI
step that needs it runs BEFORE any pip install has happened.

Usage:
    python3 tools/client_pin.py             # print the pin
    python3 tools/client_pin.py --install   # install it, refusing a silent downgrade
"""

import pathlib
import re
import subprocess
import sys

# tomllib is 3.11+; this must run on whatever python3 a runner happens to ship
# before setup-python, so parse the one line we need rather than import it.
PIN = re.compile(r'^\s*"(ciris-client(?:\[[^\]]+\])?[^"]*)"\s*,?\s*$', re.MULTILINE)


def client_pin(root: pathlib.Path) -> str:
    pyproject = root / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    found = PIN.findall(text)
    if not found:
        raise SystemExit(
            f"no `ciris-client[...]` requirement found in {pyproject}.\n"
            "This script exists so the pin has exactly one home; if the "
            "dependency was renamed or restructured, update PIN here — do not "
            "reintroduce a hand-copied version string at the call sites."
        )
    if len(found) > 1:
        raise SystemExit(
            f"{pyproject} names ciris-client more than once: {found}.\n"
            "Two pins is the drift this script prevents."
        )
    return found[0]


def install(pin: str) -> int:
    """`pip install` the pin, failing on an install pip merely WARNED about.

    pip does not refuse an extra a package does not publish — it prints
    `WARNING: ciris-client 0.5.188 does not provide the extra 'node'` and
    installs the base distribution. The exit code is 0. So a pin naming a
    flavour that was never published looks exactly like one that was, and the
    thing you asked for is silently not what you got.

    That is this repo's most expensive shape (the optional-half class, the
    zero-denominator gates): a request quietly downgraded instead of refused.
    It cost 0.5.189 a pin that documented a `[node]` extra which does not
    exist. Here, that warning is an error.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "install", pin],
        capture_output=True,
        text=True,
    )
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        return proc.returncode

    blob = proc.stdout + proc.stderr
    downgraded = [
        line
        for line in blob.splitlines()
        if "does not provide the extra" in line or "Ignoring invalid extra" in line
    ]
    if downgraded:
        sys.stderr.write(
            "\nREFUSED: pip installed something other than what was pinned.\n"
            + "\n".join(f"  {line.strip()}" for line in downgraded)
            + f"\n\nThe pin is `{pin}` (from pyproject.toml). pip treats an unknown\n"
            "extra as a warning and installs the base distribution, exit code 0 —\n"
            "so this would otherwise pass as a normal install. Either the extra was\n"
            "renamed upstream or it never existed; fix the pin in pyproject.toml.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    pin = client_pin(pathlib.Path(__file__).resolve().parents[1])
    if "--install" in sys.argv[1:]:
        sys.exit(install(pin))
    print(pin)
    sys.exit(0)
