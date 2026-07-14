#!/usr/bin/env python3
"""Deterministically package the test-anchor abi3 wheel.

maturin mis-detects edge v13's linked-in uniffi scaffolding symbols and tries to
build a uniffi wheel (wrong layout — no PyInit glue). The compiled
`target/release/libciris_server.so` is already a valid pyo3 abi3 extension
(exports `PyInit__native`), so we skip maturin's binding guess and lay out the
pyo3 wheel by hand: `ciris_server/_native.abi3.so` + the hand-written Python
package (`python/ciris_server/*.py`). This is the QA-runner's build step; it is
NEVER how the prod wheel is built (that is maturin in CI, without test-anchor).
"""
import base64, csv, hashlib, io, sys, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]          # CIRISServer/
SO = ROOT / "target" / "release" / "libciris_server.so"
PYPKG = ROOT / "python" / "ciris_server"
OUT_DIR = Path(__file__).resolve().parent / "wheels"

def version() -> str:
    for line in (ROOT / "Cargo.toml").read_text().splitlines():
        if line.startswith("version = "):
            return line.split('"')[1]
    raise SystemExit("no version in Cargo.toml")

def sha_rec(data: bytes) -> str:
    d = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(d).rstrip(b"=").decode()

def main() -> int:
    if not SO.exists():
        raise SystemExit(f"missing {SO} — build first: cargo build --release --features extension-module,test-anchor")
    ver = version()
    dist = f"ciris_server-{ver}"
    # abi3 for CPython 3.10+, Linux x86_64 (harness Docker base is controlled).
    tag = "cp310-abi3-linux_x86_64"
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    whl = OUT_DIR / f"ciris_server-{ver}-{tag}.whl"

    # (arcname, bytes) for every member; the .so + the pure-python launcher glue.
    members: list[tuple[str, bytes]] = []
    members.append(("ciris_server/_native.abi3.so", SO.read_bytes()))
    for py in sorted(PYPKG.glob("*.py")):
        members.append((f"ciris_server/{py.name}", py.read_bytes()))

    metadata = (
        "Metadata-Version: 2.3\n"
        "Name: ciris-server\n"
        f"Version: {ver}\n"
        "Summary: The fabric node (TEST-ANCHOR harness build — not for release).\n"
        "Author-email: Eric Moore <eric@ciris.ai>\n"
        "Requires-Python: >=3.10\n"
    ).encode()
    wheel_meta = (
        "Wheel-Version: 1.0\n"
        "Generator: ciris-mesh-repro pack_wheel\n"
        "Root-Is-Purelib: false\n"
        f"Tag: {tag}\n"
    ).encode()
    # Console scripts (pyproject [project.scripts]) — the canonical role runs the
    # `ciris-server` entry point, so the wheel MUST declare it.
    entry_points = (
        "[console_scripts]\n"
        "ciris-server = ciris_server.cli:main\n"
        "ciris-server-headless = ciris_server.cli:server\n"
        "ciris-desktop = ciris_server.cli:desktop\n"
    ).encode()
    members.append((f"{dist}.dist-info/METADATA", metadata))
    members.append((f"{dist}.dist-info/WHEEL", wheel_meta))
    members.append((f"{dist}.dist-info/entry_points.txt", entry_points))

    # RECORD lists every file with hash+size; its own row has no hash.
    record = io.StringIO()
    w = csv.writer(record, lineterminator="\n")
    for name, data in members:
        w.writerow([name, sha_rec(data), len(data)])
    w.writerow([f"{dist}.dist-info/RECORD", "", ""])
    members.append((f"{dist}.dist-info/RECORD", record.getvalue().encode()))

    if whl.exists():
        whl.unlink()
    with zipfile.ZipFile(whl, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members:
            z.writestr(name, data)
    print(f"packed {whl}  ({whl.stat().st_size // (1024*1024)} MB, {len(members)} members)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
