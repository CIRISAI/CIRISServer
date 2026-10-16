#!/usr/bin/env python3
"""Re-check WARN/ERROR issue citations against GitHub (CIRISServer#782).

tests/log_citations.rs (offline) enforces the FORM: every issue cited in a
`tracing::warn!` / `tracing::error!` message reads `history: X#N` or
`tracked: X#N`. This script checks the STATE, which needs the network: a
`tracked:` issue must still be OPEN (otherwise the line keeps promising work
that is done) and a `history:` issue must be CLOSED/MERGED (otherwise the line
hides open work as history). Run before a cut:

    python3 tools/check_log_citations.py          # exit 1 on any mismatch
"""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CITE = re.compile(r"(history|tracked): ([A-Z][A-Za-z]+)?#(\d{2,4})\b")
ALIAS = {"CC": "CIRISConstitution", "": "CIRISServer", None: "CIRISServer"}


def macro_texts(src: str):
    for opener in ("tracing::warn!(", "tracing::error!("):
        start = 0
        while (k := src.find(opener, start)) >= 0:
            end = src.find(");", k)
            end = len(src) if end < 0 else end
            yield src[:k].count("\n") + 1, src[k:end]
            start = end + 1


def state(repo: str, num: str) -> str:
    for kind in ("issue", "pr"):
        out = subprocess.run(["gh", kind, "view", num, "--repo", f"CIRISAI/{repo}", "--json", "state"],
                             capture_output=True, text=True)
        if out.returncode == 0:
            return json.loads(out.stdout)["state"]
    return "UNKNOWN"


def main() -> int:
    seen, bad = {}, []
    for f in sorted((ROOT / "src").rglob("*.rs")):
        src = f.read_text(errors="replace")
        for line, text in macro_texts(src):
            for tag, repo, num in CITE.findall(text):
                repo = ALIAS.get(repo, repo)
                st = seen.setdefault((repo, num), state(repo, num))
                ok = (st == "OPEN") if tag == "tracked" else (st in ("CLOSED", "MERGED"))
                if not ok:
                    bad.append(f"{f.relative_to(ROOT)}:{line}: {tag}: {repo}#{num} is {st}")
    for b in bad:
        print(b)
    print(f"{len(seen)} distinct citations checked, {len(bad)} mismatched")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
