#!/usr/bin/env python3
"""Identity survival across an upgrade — CIRISServer#586 / the long-jump lane.

A node that boots is not the same as a node that is still ITSELF. The dangerous
upgrade failure is not a crash; it is a process that comes up green wearing an
old data directory's clothes, having quietly minted a fresh identity. Every
liveness signal passes and the node is a stranger to the mesh.

So this reads the node's identity out of its own store, twice: once BEFORE the
upgrade (the baseline) and once after. Taking a baseline matters as much as the
assertion — without it, "no identity after" cannot be told from "no identity
ever", and the job reports data loss against a fixture that never had any. A
check that cries wolf is a check people learn to skip.

Usage:
    check_longjump_state.py --home <dir> --emit-baseline
    check_longjump_state.py --home <dir> --baseline '<value>'
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sqlite3
import sys


def find_db(home: pathlib.Path) -> pathlib.Path | None:
    """The node's engine database, wherever the layout puts it."""
    for pattern in ("data/ciris_engine.db", "ciris_engine.db", "**/ciris_engine.db"):
        hits = sorted(home.glob(pattern))
        if hits:
            return hits[0]
    return None


def identity(home: pathlib.Path) -> dict:
    """What this node calls itself, from the store it actually opens.

    The V070 row is included on purpose: CIRISPersist#840 was a migration
    CHECKSUM mismatch, so the recorded checksum is the fact that decides whether
    a with-history node can open at all. Reporting it makes a checksum failure
    self-describing instead of just absent.
    """
    db = find_db(home)
    if db is None:
        return {"db": None}
    out: dict = {"db": db.name}
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        try:
            row = con.execute(
                "SELECT version, checksum FROM refinery_schema_history "
                "WHERE version=70"
            ).fetchone()
            out["v070_checksum"] = row[1] if row else None
            head = con.execute(
                "SELECT max(version) FROM refinery_schema_history"
            ).fetchone()
            out["schema_head"] = head[0] if head else None
        except sqlite3.Error:
            # No history table at all is itself a finding, not a crash.
            out["v070_checksum"] = None
            out["schema_head"] = None
        try:
            keys = con.execute(
                "SELECT key_id FROM federation_keys ORDER BY key_id"
            ).fetchall()
            out["federation_keys"] = [k[0] for k in keys]
        except sqlite3.Error:
            out["federation_keys"] = []
    finally:
        con.close()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--home", required=True)
    ap.add_argument("--emit-baseline", action="store_true")
    ap.add_argument("--baseline", default="")
    args = ap.parse_args()

    home = pathlib.Path(args.home)
    state = identity(home)

    if args.emit_baseline:
        print(f"BASELINE={json.dumps(state, sort_keys=True)}")
        print(f"  db={state.get('db')} schema_head={state.get('schema_head')} "
              f"keys={len(state.get('federation_keys') or [])}", file=sys.stderr)
        return 0

    if not args.baseline:
        print("::error::no baseline was recorded, so identity survival cannot be "
              "judged — the lane must snapshot BEFORE the upgrade")
        return 2

    before = json.loads(args.baseline)

    # A fixture that never had a database proves nothing either way. Say so
    # rather than passing quietly, so a broken capture cannot masquerade as a
    # successful jump.
    if before.get("db") is None:
        print("::error::the fixture carried no engine database — the capture step "
              "produced nothing to upgrade, and this lane cannot pretend to have "
              "tested a long jump")
        return 2

    after = state
    if after.get("db") is None:
        print("::error::FAILURE MODE 1 — after the upgrade there is no engine "
              "database. The node did not open its store.")
        return 1

    before_keys = set(before.get("federation_keys") or [])
    after_keys = set(after.get("federation_keys") or [])

    print(f"before: schema_head={before.get('schema_head')} "
          f"v070={before.get('v070_checksum')} keys={len(before_keys)}")
    print(f"after : schema_head={after.get('schema_head')} "
          f"v070={after.get('v070_checksum')} keys={len(after_keys)}")

    lost = before_keys - after_keys
    if lost:
        print("::error::FAILURE MODE 2 — federation identity did NOT survive the "
              f"upgrade. {len(lost)} key(s) present before are gone after: "
              f"{sorted(lost)[:5]}. A node that boots green with a new identity is "
              "a stranger to the mesh, and every liveness check passes.")
        return 1

    if before_keys and not after_keys:
        print("::error::FAILURE MODE 2 — the federation key table is empty after "
              "an upgrade that started with keys.")
        return 1

    # The schema head may legitimately ADVANCE; it must never go backwards.
    b_head, a_head = before.get("schema_head"), after.get("schema_head")
    if isinstance(b_head, int) and isinstance(a_head, int) and a_head < b_head:
        print(f"::error::the schema head went BACKWARDS ({b_head} -> {a_head}), "
              "which means the node opened a different database than the one it "
              "was given")
        return 1

    print(f"identity survived: {len(after_keys)} federation key(s) intact, "
          f"schema {b_head} -> {a_head}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
