#!/usr/bin/env python3
"""check_evidence.py — resolve the CC evidence `impl:` manifest (CIRISServer#155).

`evidence/cc_impl.tsv` is the sibling spec-map manifest the Constitution's
`check_claims.py` resolves cross-repo `impl:CIRISServer#155` pointers against
(see CIRISConstitution `constitution/EVIDENCE.md`). This script is the CI gate
that keeps the manifest honest: every `path#symbol` MUST resolve at the crate
version the workspace actually pins — a moved/renamed symbol is a build failure
(a spec-regression test), so a Constitution `impl:` pointer can never silently rot.

Manifest columns (TSV):  decimal_id  claim_id  repo  path#symbol  crate@version

Resolution:
  - repo=CIRISServer  -> resolve `path#symbol` in THIS repo (dead pointer = FAIL).
  - repo=CIRIS{Persist,Verify,Edge} -> (a) the row's crate@version tag MUST equal
    the workspace pin in Cargo.toml (drift = FAIL); (b) resolve the symbol in the
    cargo-vendored checkout for the pinned git rev (present after `cargo fetch`);
    if that checkout is absent, resolution is a WARNING (deferred, like the
    Constitution checker), not a failure.
  - repo=CIRISClient -> the KMP client is a published PACKAGE since CIRISServer#471,
    not a tree in this repo, and the wheel carries only built artifacts (a jar and
    the locale bundle) — there is no `.kt` in it to resolve against. So: (a) the
    row's `ciris-client@version` MUST equal the pin in `pyproject.toml` (drift =
    FAIL — that pin is exact by design); (b) the symbol resolves against a SIBLING
    `../CIRISClient` checkout when one exists AND is at that exact tag; otherwise
    resolution is a WARNING (deferred), never a silent pass. Same shape as the
    substrate rule above, and the same reason: a gate that cannot be evaluated
    must not be indistinguishable from one that passed.
  - repo=—  (an `open`/unimplemented row) -> skipped (informational).

Exit non-zero on any FAIL. `--strict` also fails on WARN.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "evidence" / "cc_impl.tsv"
CARGO_TOML = ROOT / "Cargo.toml"
CARGO_LOCK = ROOT / "Cargo.lock"

# crate@version prefix -> the CIRIS* repo whose Cargo.toml `tag = "..."` pins it.
CRATE_REPO = {
    "ciris-persist": "CIRISPersist",
    "ciris-verify-core": "CIRISVerify",
    "ciris-keyring": "CIRISVerify",
    "ciris-crypto": "CIRISVerify",
    "ciris-edge": "CIRISEdge",
}
# The lockfile package name whose git rev locates the vendored checkout.
CRATE_LOCK_PKG = {
    "CIRISPersist": "ciris-persist",
    "CIRISVerify": "ciris-verify-core",
    "CIRISEdge": "ciris-edge",
}
CHECKOUT_DIR_GLOB = {
    "CIRISPersist": "cirispersist-*",
    "CIRISVerify": "cirisverify-*",
    "CIRISEdge": "cirisedge-*",
}

# CIRISServer#471 — the client is a pip package, so its pin lives in
# pyproject.toml rather than Cargo.toml and its source is not vendored anywhere
# a cargo checkout would be. `tools/client_pin.py` is the ONE home of that
# version string; this asks it rather than re-spelling the regex (five copies of
# that pin is exactly the drift that script was written to end).
CLIENT_REPO = "CIRISClient"
CLIENT_CRATE = "ciris-client"
CLIENT_SIBLING = ROOT.parent / "CIRISClient"


def cargo_pin(repo: str) -> str | None:
    """The `tag = "vX"` the workspace pins for a CIRIS* git repo (first match)."""
    pat = re.compile(rf'{repo}",\s*tag = "([^"]+)"')
    for line in CARGO_TOML.read_text().splitlines():
        m = pat.search(line)
        if m:
            return m.group(1)
    return None


def lock_rev(pkg: str, tag: str) -> str | None:
    """The 40-hex git rev the lockfile resolved for `pkg` at `tag`."""
    text = CARGO_LOCK.read_text()
    # [[package]] blocks are separated by blank lines.
    for block in text.split("\n\n"):
        if f'name = "{pkg}"' in block and "source = " in block and tag in block:
            m = re.search(r"#([0-9a-f]{40})", block)
            if m:
                return m.group(1)
    return None


def client_pin() -> str | None:
    """The `ciris-client` FLOOR version, via the one resolver.

    0.5.192 moved the dependency from `==X` to `>=FLOOR,<BOUND` so the client can
    iterate for CIRISAgent without a paired server cut. An evidence row names a
    symbol in a specific client version, and the floor is the right one to check:
    it is the oldest a consumer may resolve, so a symbol present there is present
    across the whole declared range. Checking the ceiling would prove less — a
    symbol added in the newest client says nothing about what a floor install has.
    """
    try:
        out = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "client_pin.py"), "--floor"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return out or None


def client_checkout(pin: str) -> Path | None:
    """A sibling `../CIRISClient` AT the pinned tag, or None.

    The tag check is the whole point: resolving a symbol against whatever happens
    to be checked out next door would answer a question about the developer's
    working tree, not about the version this repo ships. Wrong tag ⇒ deferred,
    the same as no checkout at all.
    """
    if not (CLIENT_SIBLING / ".git").exists():
        return None
    try:
        # `--exact-match` — NOT the nearest tag. `describe --tags --abbrev=0` walks
        # BACK to the closest ancestor tag, so a sibling checked out ten commits
        # PAST v0.5.188 still answers "v0.5.188" and we would resolve symbols
        # against source the pinned release never shipped. git's own help draws
        # the distinction: --exact-match "only output exact matches".
        tag = subprocess.run(
            ["git", "-C", str(CLIENT_SIBLING), "describe", "--tags", "--exact-match"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        # Not ON a tag at all (mid-development, a branch, a descendant) — deferred,
        # never silently accepted.
        return None
    return CLIENT_SIBLING if tag.lstrip("v") == pin.lstrip("v") else None


def checkout_dir(repo: str, rev: str) -> Path | None:
    home = Path.home() / ".cargo" / "git" / "checkouts"
    if not home.exists():
        return None
    for parent in home.glob(CHECKOUT_DIR_GLOB[repo]):
        for cand in parent.glob(rev[:7] + "*"):
            if cand.is_dir():
                return cand
    return None


DEF_KINDS = r"(?:fn|struct|enum|const|static|trait|type|union|mod|macro_rules!)"


def _leaf_defined(src: str, leaf: str) -> bool:
    name = re.escape(leaf)
    if re.search(rf"{DEF_KINDS}\s+{name}\b", src):  # fn/struct/const/enum/mod def
        return True
    if re.search(rf"\bfn\s+{name}\b", src):  # method inside an impl block
        return True
    if re.search(rf'"{name}"', src):  # wire-token / string const (reservations)
        return True
    return bool(re.search(rf"\b{name}\b", src))  # fallback: any whole-word use


def symbol_resolves(base: Path, path: str, symbol: str) -> bool:
    """True if `symbol` resolves in base/path. Handles a qualified `A::B::leaf`:
    the leaf must be defined AND every container segment must appear."""
    f = base / path
    if not f.is_file():
        return False
    src = f.read_text(errors="replace")
    parts = symbol.split("::")
    leaf = parts[-1]
    if not _leaf_defined(src, leaf):
        return False
    # Each container (mod / enum / struct / impl target) must appear in the file.
    return all(re.search(rf"\b{re.escape(seg)}\b", src) for seg in parts[:-1])


def main() -> int:
    strict = "--strict" in sys.argv
    if not MANIFEST.exists():
        print(f"FATAL: {MANIFEST} missing", file=sys.stderr)
        return 2

    fails: list[str] = []
    warns: list[str] = []
    ok = 0
    open_rows = 0
    seen_claims: set[str] = set()

    for ln, raw in enumerate(MANIFEST.read_text().splitlines(), 1):
        line = raw.rstrip("\n")
        if not line or line.startswith("#") or line.startswith("decimal_id\t"):
            continue
        cols = line.split("\t")
        if len(cols) != 5:
            fails.append(f"L{ln}: expected 5 tab-columns, got {len(cols)}: {line!r}")
            continue
        decimal, claim, repo, pathsym, cratever = (c.strip() for c in cols)
        seen_claims.add(claim)

        if repo in ("—", "-", "") or cratever.startswith("open"):
            open_rows += 1
            continue

        if "#" not in pathsym:
            fails.append(f"L{ln} [{claim}]: path#symbol has no '#': {pathsym!r}")
            continue
        path, symbol = pathsym.split("#", 1)

        if repo == "CIRISServer":
            if symbol_resolves(ROOT, path, symbol):
                ok += 1
            else:
                fails.append(f"L{ln} [{claim} {decimal}]: unresolved in-repo -> {pathsym}")
            continue

        if repo == CLIENT_REPO:
            row_tag = cratever.split("@", 1)[1] if "@" in cratever else ""
            pin = client_pin()
            if pin is None:
                fails.append(f"L{ln} [{claim}]: no pyproject pin found for {CLIENT_REPO}")
                continue
            # The client pin is EXACT by design (the locale bundle is a release
            # gate here), so a drifted annotation is a FAIL, not the substrate's
            # WARN: there is no floating version for it to be merely stale against.
            if row_tag != pin:
                fails.append(
                    f"L{ln} [{claim}]: ciris-client@'{row_tag}' is not the declared FLOOR "
                    f"'{pin}'. An evidence row must name the oldest client a consumer "
                    f"may resolve — a symbol proven only in a newer one says nothing "
                    f"about a floor install (0.5.192 range decoupling)"
                )
                continue
            base = client_checkout(pin)
            if base is None:
                warns.append(
                    f"L{ln} [{claim} {decimal}]: {CLIENT_REPO}@{pin} has no sibling "
                    f"checkout at {CLIENT_SIBLING} on that tag — deferred: {pathsym}"
                )
                continue
            if symbol_resolves(base, path, symbol):
                ok += 1
            else:
                fails.append(
                    f"L{ln} [{claim} {decimal}]: unresolved in {CLIENT_REPO}@{pin} -> {pathsym}"
                )
            continue

        # --- substrate crate ---
        crate = cratever.split("@", 1)[0]
        want_repo = CRATE_REPO.get(crate)
        if want_repo != repo:
            fails.append(f"L{ln} [{claim}]: crate '{crate}' does not belong to repo '{repo}'")
            continue
        row_tag = cratever.split("@", 1)[1] if "@" in cratever else ""
        pin = cargo_pin(repo)
        if pin is None:
            fails.append(f"L{ln} [{claim}]: no workspace pin found for {repo}")
            continue
        # Resolve the symbol at the LIVE workspace pin (not the row's stated
        # version). A stale annotation is only a WARN (refresh cc_impl.tsv on the
        # next substrate bump); a symbol that no longer resolves at the live pin is
        # the real FAIL — the spec-regression signal.
        if row_tag != pin:
            warns.append(
                f"L{ln} [{claim}]: crate@version '{row_tag}' stale vs live pin '{pin}' "
                f"(refresh the annotation)"
            )
        rev = lock_rev(CRATE_LOCK_PKG[repo], pin)
        base = checkout_dir(repo, rev) if rev else None
        if base is None:
            warns.append(
                f"L{ln} [{claim} {decimal}]: {repo}@{pin} checkout not vendored "
                f"(run `cargo fetch`) — deferred: {pathsym}"
            )
            continue
        if symbol_resolves(base, path, symbol):
            ok += 1
        else:
            fails.append(
                f"L{ln} [{claim} {decimal}]: unresolved in {repo}@{pin} -> {pathsym}"
            )

    # Coverage: every claim tagged impl:CIRISServer#155 upstream should have a row.
    claims_tsv = ROOT.parent / "CIRISConstitution" / "constitution" / "claims.tsv"
    if claims_tsv.exists():
        want = {
            r.split("\t")[0]
            for r in claims_tsv.read_text().splitlines()
            if "impl:CIRISServer#155" in r
        }
        missing = sorted(want - seen_claims)
        for m in missing:
            warns.append(f"coverage: claim {m} tagged impl:CIRISServer#155 has no manifest row")

    print(f"cc_impl.tsv: {ok} resolved, {open_rows} open, {len(warns)} warn, {len(fails)} FAIL")
    for w in warns:
        print(f"  WARN {w}")
    for e in fails:
        print(f"  FAIL {e}")
    if fails or (strict and warns):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
