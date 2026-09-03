#!/usr/bin/env python3
"""Assemble a PEP 730 iOS wheel from a cross-compiled `_native.abi3.so`.

## Why this exists instead of `maturin build --target aarch64-apple-ios`

maturin refuses the cross-compile outright, and says so plainly:

    💥 maturin failed
      Caused by: Failed to get information from the python interpreter at python3
      Caused by: platform.system() in python, linux, and the rust target,
                 Target { os: Ios, ... }, don't match ಠ_ಠ

That check fires before any compilation, on darwin→iOS as well as linux→iOS
(ci.yml records the same conclusion for persist's lane). So the iOS slice is
built by `cargo build --lib` with the PyO3 cross env — which `ios-asset.yml`
already does, and has done for every release — and the wheel is assembled here
from the result.

## The metadata is maturin's, not ours

The one thing worth being careful about: a hand-written METADATA is a SECOND
spelling of the packaging rules, and the moment `pyproject.toml` changes, the
iOS wheel describes a different package from the other eight. So this does not
write METADATA. It runs `maturin pep517 write-dist-info`, which is the same code
path pip drives for `prepare_metadata_for_build_wheel` and needs no compiler, and
takes the dist-info verbatim. Checked against the published
`ciris_server-0.5.196-cp310-abi3-macosx_11_0_arm64.whl`: byte-identical but for
one README line the tree had legitimately moved since that release.

Only `WHEEL` is rewritten, because only its `Tag:` is platform-specific.

Usage:
    tools/build_ios_wheel.py \\
        --so dist/ios-device/_native.abi3.so \\
        --sdk iphoneos --out dist-wheel
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# `cp310-abi3` matches every other wheel in the matrix: pyo3's `abi3-py310`
# means one wheel serves CPython 3.10+. Kept beside the iOS bits rather than
# derived, because a wrong ABI tag here would be as silent as a wrong platform
# one — and the source of truth for it is Cargo.toml's pyo3 feature, which this
# script has no business re-reading.
PY_ABI_TAG = "cp310-abi3"


def _sha256_b64(data: bytes) -> str:
    """RECORD hashes are urlsafe-base64 of the digest, with `=` padding stripped."""
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).decode().rstrip("=")


def dist_info(tmp: Path) -> Path:
    """Ask maturin for the dist-info. No compilation, no second spelling."""
    out = tmp / "dist-info"
    out.mkdir()
    subprocess.run(
        ["maturin", "pep517", "write-dist-info", "--metadata-directory", str(out)],
        cwd=REPO,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    dirs = list(out.glob("*.dist-info"))
    if len(dirs) != 1:
        raise SystemExit(f"expected one .dist-info from maturin, got {dirs}")
    return dirs[0]


def build(so: Path, sdk: str, arch: str, ios_min: str, out_dir: Path) -> Path:
    if not so.is_file():
        raise SystemExit(f"no such extension: {so}")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        di = dist_info(tmp)
        name_version = di.name[: -len(".dist-info")]
        version = name_version.split("-")[-1]

        major, minor = ios_min.split(".")[:2]
        tag = f"{PY_ABI_TAG}-ios_{major}_{minor}_{arch}_{sdk}"
        wheel_name = f"{name_version.replace('-', '-', 1)}-{tag}.whl"

        # Only the Tag line is platform-specific; everything else maturin wrote
        # stays exactly as it wrote it.
        (di / "WHEEL").write_text(
            "Wheel-Version: 1.0\n"
            f"Generator: maturin via {Path(__file__).name}\n"
            "Root-Is-Purelib: false\n"
            f"Tag: {tag}\n"
        )

        records: list[tuple[str, str, int]] = []
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:

            def add(arcname: str, data: bytes) -> None:
                zf.writestr(arcname, data)
                records.append((arcname, _sha256_b64(data), len(data)))

            # The hand-written Python package, exactly as `python-source` says.
            # `__pycache__` is excluded: shipping a host interpreter's .pyc into
            # a wheel for a DIFFERENT platform is at best dead weight and at
            # worst a stale import shadowing the real module.
            pysrc = REPO / "python"
            for f in sorted(pysrc.rglob("*")):
                if not f.is_file() or "__pycache__" in f.parts:
                    continue
                add(str(f.relative_to(pysrc)).replace("\\", "/"), f.read_bytes())

            # The compiled extension, at the path `ciris_server/__init__.py`
            # imports (`from ._native import *`).
            add("ciris_server/_native.abi3.so", so.read_bytes())

            for f in sorted(di.rglob("*")):
                if f.is_file():
                    rel = f.relative_to(di.parent)
                    add(str(rel).replace("\\", "/"), f.read_bytes())

            # RECORD lists every member and itself, hashless — PEP 427.
            rec = io.StringIO()
            w = csv.writer(rec, lineterminator="\n")
            for arcname, digest, size in records:
                w.writerow([arcname, digest, size])
            w.writerow([f"{name_version}.dist-info/RECORD", "", ""])
            zf.writestr(f"{name_version}.dist-info/RECORD", rec.getvalue())

        out_dir.mkdir(parents=True, exist_ok=True)
        dest = out_dir / wheel_name
        dest.write_bytes(buf.getvalue())
        print(f"✓ {dest}  ({dest.stat().st_size:,} bytes, version {version})")
        return dest


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--so", required=True, type=Path, help="the cross-compiled _native.abi3.so")
    ap.add_argument("--sdk", required=True, choices=["iphoneos", "iphonesimulator"])
    ap.add_argument("--arch", default="arm64")
    ap.add_argument(
        "--ios-min",
        default="13.0",
        help="minimum iOS, and the version in the tag. MUST match the binary's "
        "own floor — tools/check_ios_wheel.py refuses a wheel where it does not.",
    )
    ap.add_argument("--out", required=True, type=Path)
    a = ap.parse_args(argv)
    if not shutil.which("maturin"):
        raise SystemExit("maturin is not on PATH; it generates the dist-info")
    build(a.so, a.sdk, a.arch, a.ios_min, a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
