#!/usr/bin/env python3
"""Audit cohort_scope at every CEG emit site (CIRISServer#38, FSD §3.2 default flip).

Scope-native privacy (CC 1.13.3.4) makes **anonymity-by-default at the smallest
scope** the post-v6.0.0 behavior: a caller that OMITS `cohort_scope` no longer
silently means `federation` — it now resolves to the smallest scope consistent
with the publisher's stated audience. This one-shot audit scans the Rust sources
and reports, per emit site, which `cohort_scope` it uses, so an operator can
review explicitly:

  - FEDERATION  → broadest visibility. EACH such site is flagged for review:
                  is federation scope genuinely intended, or a pre-flip habit?
  - self/family/community → scoped (the protective posture); informational.
  - (omitted)   → would now resolve to the smallest scope for the audience.
                  We can't statically prove omission at every call, so we also
                  list the attestation/publish builders for manual review.

Exit code is always 0 (this is an advisory review aid, not a gate). Use
--strict to exit 1 when any FEDERATION-scope site is found (for a CI nudge).

Usage:
    python3 tools/audit_cohort_scope_callers.py [--strict]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"

# A cohort_scope set to federation tier, in any of the shapes the code uses.
_FED = re.compile(r"cohort_scope.{0,40}?(FEDERATION|\"federation\")")
# Any cohort_scope assignment (to classify the scoped ones).
_SCOPED = re.compile(r"cohort_scope.{0,40}?(SELF|FAMILY|COMMUNITY|\"(self|family|community)\")")
# Emit/publish builders that produce CEG objects (review for scope intent).
_EMIT = re.compile(r"\b(put_attestation|attestation_upsert_local|emit_signed_attestation|"
                   r"emit_age_assurance|emit_owner_binding|attestation_promote)\b")


def main() -> int:
    ap = argparse.ArgumentParser(description="cohort_scope emit-site audit (CIRISServer#38)")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if any federation-scope site is found")
    args = ap.parse_args()

    fed: list[tuple[str, int, str]] = []
    scoped: list[tuple[str, int, str]] = []
    emit: list[tuple[str, int, str]] = []

    for rs in sorted(SRC.rglob("*.rs")):
        rel = rs.relative_to(REPO_ROOT)
        for n, line in enumerate(rs.read_text(encoding="utf-8").splitlines(), 1):
            s = line.strip()
            if s.startswith("//") or "COHORT_SCOPES" in s:
                continue
            if _FED.search(s):
                fed.append((str(rel), n, s))
            elif _SCOPED.search(s):
                scoped.append((str(rel), n, s))
            if _EMIT.search(s):
                emit.append((str(rel), n, s))

    print("cohort_scope audit (CIRISServer#38 — FSD §3.2 default flip)")
    print(f"   scanned {SRC.relative_to(REPO_ROOT)}/**.rs\n")

    print(f"FEDERATION-scope emit sites ({len(fed)}) — REVIEW each: is broad visibility intended?")
    for f, n, s in fed:
        print(f"  - {f}:{n}  {s[:96]}")
    print()

    print(f"Scoped (self/family/community) sites ({len(scoped)}) — protective default, informational:")
    for f, n, s in scoped:
        print(f"  - {f}:{n}  {s[:96]}")
    print()

    print(f"CEG emit/publish builders ({len(emit)}) — confirm each carries the intended scope:")
    for f, n, s in emit:
        print(f"  - {f}:{n}  {s[:96]}")
    print()

    print("Guidance: post-v6.0.0, a cohort_scope-omitted emit resolves to the SMALLEST")
    print("scope for the audience (anonymity-by-default). Federation scope is now an")
    print("EXPLICIT operator choice — confirm each federation site above is intended.")

    if args.strict and fed:
        print(f"\nFAIL (--strict): {len(fed)} federation-scope site(s) need explicit review.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
