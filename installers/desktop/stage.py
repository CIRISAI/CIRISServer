"""Stage one CIRIS desktop payload for an installer shell.

The agent builds the payload (CIRISAgent `.github/workflows/desktop-payload.yml`):
`ciris-payload-<ver>-<target>.{tar.zst,payload.json,payload.lock,SHA256SUMS}`. This
checks every file against SHA256SUMS, checks payload.json against the archive's own
copy, and unpacks the archive (no top-level directory) into `--out`. The shells
(windows/, macos/, linux/) then wrap `--out` as the install prefix.

    python installers/desktop/stage.py --payload-dir DIR --out STAGE [--github-output FILE]

Prints the payload facts as JSON, and with `--github-output` also writes them as
step outputs (version, target, desktop, interpreter, launch, upgrade). Needs the
`zstandard` package (`pip install zstandard`): Windows' tar has no zstd.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
from pathlib import Path


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def check_sums(d: Path) -> list[Path]:
    sums = list(d.glob("*.SHA256SUMS"))
    if len(sums) != 1:
        sys.exit(f"stage: want exactly one *.SHA256SUMS in {d}, found {len(sums)}")
    checked = []
    for line in sums[0].read_text().splitlines():
        if not line.strip():
            continue
        want, name = line.split(maxsplit=1)
        name = name.lstrip("*").strip()
        f = d / Path(name).name
        if not f.is_file():
            sys.exit(f"stage: SHA256SUMS names {name}, which is not in {d}")
        got = sha256(f)
        if got != want:
            sys.exit(f"stage: {f.name}: sha256 {got} is not the {want} SHA256SUMS states")
        checked.append(f)
    return checked


def unpack(archive: Path, out: Path) -> None:
    import zstandard  # noqa: PLC0415 - only the staging step needs it

    out.mkdir(parents=True, exist_ok=True)
    with archive.open("rb") as raw:
        reader = zstandard.ZstdDecompressor().stream_reader(raw)
        with tarfile.open(fileobj=reader, mode="r|") as tar:
            # The payload is ours (checked above), but never let a member escape.
            tar.extractall(out, filter="tar")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--payload-dir", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--github-output", type=Path)
    a = ap.parse_args()
    checked = check_sums(a.payload_dir)
    archive = next((f for f in checked if f.name.endswith(".tar.zst")), None)
    if archive is None:
        sys.exit("stage: SHA256SUMS covers no .tar.zst")
    unpack(archive, a.out)
    inner = a.out / "payload.json"
    if not inner.is_file():
        sys.exit("stage: the archive carries no payload.json at its root")
    facts = json.loads(inner.read_text())
    outer = next(a.payload_dir.glob("*.payload.json"), None)
    if outer is not None and json.loads(outer.read_text()) != facts:
        sys.exit("stage: the release's payload.json differs from the archive's own")
    if facts.get("schema") != 1:
        sys.exit(f"stage: payload schema {facts.get('schema')!r}; this shell knows schema 1")
    interp = a.out / facts["interpreter"]
    if not interp.is_file():
        sys.exit(f"stage: the interpreter {facts['interpreter']} is not in the payload")
    out = {
        "version": facts["agent_version"],
        "server": facts["server_version"],
        "client": facts["client_version"],
        "target": facts["target"],
        "desktop": bool(facts.get("desktop")),
        "jre": facts.get("jre"),
        "interpreter": facts["interpreter"],
        "launch": json.dumps(facts["launch_argv"]),
        "upgrade": json.dumps(facts["upgrade_argv"]),
        "signed": bool(facts.get("signed")),
    }
    print(json.dumps(out, indent=1))
    if a.github_output:
        with a.github_output.open("a") as f:
            for k, v in out.items():
                v = str(v).lower() if isinstance(v, bool) else v
                f.write(f"{k}={'' if v is None else v}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
