#!/usr/bin/env python3
"""Guard the vendored CIRIS client localization bundles (CIRISServer copy).

Adapted from CIRISAgent's ``tools/dev/check_localization_sync.py`` for the
vendored KMP client under ``client/``. The client UI strings live in TWO
locations that MUST stay byte-identical (the desktopApp copy has historically
gone stale and shadowed the shared copy):

  - client/shared/src/desktopMain/resources/localization/*.json   (CANONICAL)
  - client/desktopApp/src/main/resources/localization/*.json

``en.json`` is the source of truth. The supported-language list is read from
the bundle ``manifest.json`` (never hardcoded).

Checks, two severities:

  ERROR (exit 1 — blocks CI):
    1. Mirror parity. The two localization dirs above MUST carry byte-identical
       file sets, and every per-language file MUST match across the two dirs
       (so the desktopApp copy can't silently go stale). This is the primary
       regression guard.
    2. JSON validity. Every *.json in both dirs must parse.
    3. Reference coverage. Every string-literal key passed to
       ``localizedString("…")`` / ``getString("…")`` in commonMain Kotlin MUST
       resolve in ``en.json`` (the universal fallback) — an undefined key
       renders RAW on every platform (cf. CIRISAgent#240).

  WARNING (exit 0 by default; exit 1 only under --strict):
    3. Cross-language parity. Within the canonical bundle, each locale file
       should carry the same flattened key set as ``en.json``. Missing
       translations degrade gracefully (fallback to English at runtime), so
       this informs rather than blocks — it is what the ``localize-ui`` Claude
       workflow fixes.

Usage:
    python3 client/tools/check_localization_sync.py            # ERRORs block, warnings print
    python3 client/tools/check_localization_sync.py --strict   # warnings also block

Exit codes:
    0 - no errors (and no warnings under --strict)
    1 - mirror/JSON error (or any warning under --strict)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

# Repo root: this file lives at <root>/client/tools/check_localization_sync.py
REPO_ROOT = Path(__file__).resolve().parents[2]

# The two kept-in-sync UI string bundles. The first is canonical; the second
# is the desktopApp packaging copy that must mirror it exactly.
CANONICAL_BUNDLE = "client/shared/src/desktopMain/resources/localization"
MIRROR_BUNDLES: Tuple[str, ...] = (
    "client/shared/src/desktopMain/resources/localization",
    "client/desktopApp/src/main/resources/localization",
)

# Kotlin source set whose literal string keys must resolve against en.json.
COMMON_MAIN = "client/shared/src/commonMain"

# localizedString("key" …) / getString("key" …) — capture the literal first arg.
# ``[^"$\\]`` rejects interpolated keys ("mobile.foo_${x}") which can't be
# checked statically; those are skipped, not failed.
_KEY_CALL = re.compile(r'(?:localizedString|getString)\(\s*"([^"$\\]+)"')

# Per-file bookkeeping subtree (translator, review_status, native_name, …) —
# legitimately varies between locales and is never a UI key, so it's excluded
# from every key-set comparison.
_IGNORED_ROOTS = ("_meta",)


def flatten(obj: dict, prefix: str = "") -> Set[str]:
    """Flatten a nested localization dict to dotted leaf keys (excluding _meta)."""
    out: Set[str] = set()
    for k, v in obj.items():
        if prefix == "" and k in _IGNORED_ROOTS:
            continue
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out |= flatten(v, key)
        else:
            out.add(key)
    return out


def load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_flat(path: Path) -> Set[str]:
    return flatten(load_json(path))


def manifest_languages(bundle: Path) -> List[str]:
    """Read the supported-language list from the bundle manifest (source of truth)."""
    manifest = load_json(bundle / "manifest.json")
    langs = manifest.get("languages")
    if isinstance(langs, dict):
        return list(langs.keys())
    if isinstance(langs, list):
        return [x.get("code") if isinstance(x, dict) else x for x in langs]
    raise SystemExit("ERROR: could not read 'languages' from manifest.json")


def referenced_keys() -> Dict[str, Path]:
    """Map each statically-extractable localization key -> first Kotlin call site."""
    keys: Dict[str, Path] = {}
    common = REPO_ROOT / COMMON_MAIN
    if not common.exists():
        return keys
    for kt in common.rglob("*.kt"):
        text = kt.read_text(encoding="utf-8")
        for m in _KEY_CALL.finditer(text):
            keys.setdefault(m.group(1), kt.relative_to(REPO_ROOT))
    return keys


def check_reference_coverage(en_keys: Set[str]) -> List[str]:
    """ERROR: every literal key in commonMain must resolve in en.json."""
    errors: List[str] = []
    refs = referenced_keys()
    unresolved = sorted((k, p) for k, p in refs.items() if k not in en_keys)
    if unresolved:
        errors.append(
            f"{len(unresolved)} key(s) referenced in commonMain are undefined in "
            f"en.json (they render RAW on every platform):"
        )
        for key, site in unresolved:
            errors.append(f"    - {key}    ({site})")
    return errors


def check_json_validity() -> List[str]:
    """ERROR: every *.json in both bundles must parse."""
    errors: List[str] = []
    for b in MIRROR_BUNDLES:
        bundle = REPO_ROOT / b
        if not bundle.exists():
            errors.append(f"bundle dir missing: {b}")
            continue
        for f in sorted(bundle.glob("*.json")):
            try:
                load_json(f)
            except Exception as e:  # noqa: BLE001 - report any parse failure
                errors.append(f"invalid JSON: {f.relative_to(REPO_ROOT)}: {e}")
    return errors


def check_mirror_parity() -> List[str]:
    """ERROR: the two localization dirs must carry identical file sets, and each
    file must be byte-identical across them."""
    errors: List[str] = []
    canonical = REPO_ROOT / MIRROR_BUNDLES[0]
    if not canonical.exists():
        return [f"canonical bundle missing: {MIRROR_BUNDLES[0]}"]
    canonical_files = {p.name for p in canonical.glob("*.json")}

    for b in MIRROR_BUNDLES[1:]:
        other = REPO_ROOT / b
        if not other.exists():
            errors.append(f"mirror bundle missing: {b}")
            continue
        other_files = {p.name for p in other.glob("*.json")}
        missing = canonical_files - other_files
        extra = other_files - canonical_files
        for f in sorted(missing):
            errors.append(f"{b}: missing file present in canonical: {f}")
        for f in sorted(extra):
            errors.append(f"{b}: extra file not in canonical: {f}")
        for f in sorted(canonical_files & other_files):
            a = (canonical / f).read_bytes()
            c = (other / f).read_bytes()
            if a != c:
                errors.append(
                    f"{b}/{f} differs from {MIRROR_BUNDLES[0]}/{f} "
                    f"(the two dirs must be byte-identical)"
                )
    return errors


def check_cross_language(bundle: Path, langs: List[str], en_keys: Set[str]) -> List[str]:
    """WARNING: each locale file should match en.json's key set."""
    warnings: List[str] = []
    for lang in langs:
        if lang == "en":
            continue
        f = bundle / f"{lang}.json"
        if not f.exists():
            warnings.append(f"{lang}.json missing from {bundle.name} bundle")
            continue
        keys = load_flat(f)
        # An empty-string value counts as "missing translation" too.
        data = load_json(f)
        empty = {k for k in flatten(data) if _is_empty(data, k)}
        missing = (en_keys - keys) | (empty & en_keys)
        extra = keys - en_keys
        if missing or extra:
            detail = []
            if missing:
                detail.append(f"missing {len(missing)} ({', '.join(sorted(missing)[:3])}…)")
            if extra:
                detail.append(f"extra {len(extra)} ({', '.join(sorted(extra)[:3])}…)")
            warnings.append(f"{lang}.json: {'; '.join(detail)}")
    return warnings


def _is_empty(obj: dict, dotted: str) -> bool:
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False
    return isinstance(cur, str) and cur.strip() == ""


def main() -> int:
    ap = argparse.ArgumentParser(description="CIRIS client localization bundle guard")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="treat cross-language drift (untranslated keys) as a failure too",
    )
    args = ap.parse_args()

    canonical = REPO_ROOT / CANONICAL_BUNDLE
    if not (canonical / "en.json").exists():
        print(f"ERROR: canonical en.json not found at {CANONICAL_BUNDLE}")
        return 1

    langs = manifest_languages(canonical)
    en_keys = load_flat(canonical / "en.json")

    print("Localization guard (CIRISServer vendored client)")
    print(f"   canonical: {CANONICAL_BUNDLE}  ({len(en_keys)} keys, {len(langs)} languages)")
    print()

    errors: List[str] = []
    errors += check_json_validity()
    errors += check_mirror_parity()
    errors += check_reference_coverage(en_keys)

    warnings = check_cross_language(canonical, langs, en_keys)

    if errors:
        print("ERRORS (block):")
        for e in errors:
            print(f"  - {e}")
        print()
    else:
        print("OK: JSON valid + the two dirs are byte-identical")
        print()

    if warnings:
        sev = "ERRORS (--strict)" if args.strict else "WARNINGS (translation drift — fallback to English)"
        print(sev + ":")
        for w in warnings:
            print(f"  - {w}")
        print()
    else:
        print("OK: all locales at key parity")
        print()

    failed = bool(errors) or (args.strict and bool(warnings))
    if failed:
        print("localization check FAILED")
        if warnings and not errors:
            print("   Fix: run the `localize-ui` Claude workflow to fill missing translations.")
        return 1

    print("localization check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
