#!/usr/bin/env bash
# Reconcile the LIVE `state:blocked-upstream` label against the checked-in manifest.
#
# `tests/blocked_upstream_gate.rs` does everything an offline test can: it evaluates
# each blocking predicate against the substrate revisions Cargo.lock pins, and it
# fails if the manifest and the pinned issue list disagree. The one thing it cannot
# do is notice that somebody applied the label to a NEW issue — that needs the
# GitHub API, which a test must not have. This script is that half, and it is the
# whole of it.
#
#   ./tools/check_blocked_upstream.sh
#
# Exit 0 = the label and the manifest name the same issues. Exit 1 = they do not,
# and the difference is printed. Requires `gh` authenticated against this repo.
set -euo pipefail

cd "$(dirname "$0")/.."

MANIFEST=evidence/blocked_upstream.tsv
GATE=tests/blocked_upstream_gate.rs

# Column 1 of every non-comment, non-header row.
manifest_issues=$(
  grep -v '^#' "$MANIFEST" | tail -n +2 | cut -f1 | sort -un
)

# The constant the gate pins independently of the manifest.
gate_issues=$(
  sed -n 's/^const BLOCKED_UPSTREAM_ISSUES: &\[u32\] = &\[\(.*\)\];$/\1/p' "$GATE" |
    tr -d ' ' | tr ',' '\n' | grep -v '^$' | sort -un
)

live_issues=$(
  gh issue list --label state:blocked-upstream --state open \
    --limit 200 --json number --jq '.[].number' | sort -un
)

fail=0

if [ "$manifest_issues" != "$gate_issues" ]; then
  echo "MISMATCH: $MANIFEST and $GATE::BLOCKED_UPSTREAM_ISSUES disagree." >&2
  diff <(echo "$manifest_issues") <(echo "$gate_issues") >&2 || true
  fail=1
fi

missing=$(comm -23 <(echo "$live_issues") <(echo "$manifest_issues"))
stale=$(comm -13 <(echo "$live_issues") <(echo "$manifest_issues"))

if [ -n "$missing" ]; then
  echo "" >&2
  echo "LABELLED BUT UNTRACKED — these carry state:blocked-upstream and have no row in" >&2
  echo "$MANIFEST, so nothing will notice when their blocker clears:" >&2
  # shellcheck disable=SC2001
  echo "$missing" | sed 's/^/  #/' >&2
  echo "" >&2
  echo "Add a row naming the upstream fact each waits on (absence | drift | untestable)" >&2
  echo "and add the number to BLOCKED_UPSTREAM_ISSUES." >&2
  fail=1
fi

if [ -n "$stale" ]; then
  echo "" >&2
  echo "TRACKED BUT NOT LABELLED — rows exist for issues that are no longer open with" >&2
  echo "state:blocked-upstream (relabelled, closed, or renumbered):" >&2
  # shellcheck disable=SC2001
  echo "$stale" | sed 's/^/  #/' >&2
  echo "" >&2
  echo "Remove the row AND the constant entry. Leaving them makes the gate assert a" >&2
  echo "predicate nobody is waiting on." >&2
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "blocked-upstream: $(echo "$live_issues" | wc -l) labelled issue(s), all tracked in $MANIFEST"
fi

exit "$fail"
