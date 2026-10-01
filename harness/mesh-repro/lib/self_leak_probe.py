"""Run INSIDE a node container: does this node hold anything of one person's
self plane that it must not? The negative half of the selffiles ladder.

    python self_leak_probe.py holder   <owner_key_id> <names_json>
    python self_leak_probe.py outsider <owner_key_id> <names_json> <author_keys_json>

Prints one JSON object. Reads the node's own sqlite files directly (a row is
the behaviour; a log line is only a claim about it), read-only.

WHAT IS A SELF-PLANE ROW. A self room's content id IS the owner's identity key
id (edge `ScopeRoom::self_collective(identity)` → `content_group_id`), so:

  - every `file:v1` row (the only files this scenario writes are self files);
  - every `chat:*` row whose envelope names the owner's id — the notes, and the
    self-room handshake (KeyPackage / Welcome / Commit).

The owner's id legitimately appears in rows that DO widen — the owner-binding
(`delegates_to`) becomes federation-scoped on announce — so the match is
restricted to the two dimensions above, never "any row that mentions the owner".

holder    (the owner's own devices): every self-plane row must be at
          cohort_scope `self`. A row at a wider scope is the file's EXISTENCE
          (its metadata, its room, its handshake) distributed past the person —
          CIRISPersist#919 is exactly this: the #530 consent sweep superseded
          every self file row with a federation-scoped copy.
outsider  (a node that is NOT the person's: the canonical, a bystander): must
          hold NO self-plane row at any scope, and no row whose envelope text
          carries one of the scenario's file names. `control` counts rows it
          holds from the person's keys at all, so a clean result can be told
          apart from a node nothing ever reached (a vacuous negative).
"""
import glob
import json
import sqlite3
import sys


def rows():
    for d in glob.glob("/var/lib/ciris/**/*.db", recursive=True):
        try:
            con = sqlite3.connect(f"file:{d}?mode=ro", uri=True)
            yield from con.execute(
                "SELECT attestation_id, attesting_key_id, attestation_type, tier, "
                "cohort_scope, attestation_envelope FROM federation_attestations"
            )
        except Exception:  # noqa: BLE001 — not every .db carries the table
            continue


def self_plane(dim, env_text, owner):
    if dim == "file:v1":
        return True
    return dim.startswith("chat:") and owner in env_text


def main():
    mode, owner, names = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
    authors = set(json.loads(sys.argv[4])) if len(sys.argv) > 4 else set()
    authors.add(owner)
    out = {"mode": mode, "self_rows": 0, "wide": [], "leaked": [], "control": 0}
    seen = set()
    for aid, att, typ, tier, scope, env_text in rows():
        if aid in seen:
            continue
        seen.add(aid)
        env_text = env_text or ""
        try:
            dim = (json.loads(env_text) or {}).get("dimension") or ""
        except Exception:  # noqa: BLE001
            dim = ""
        mine = self_plane(dim, env_text, owner)
        if att in authors:
            out["control"] += 1
        row = f"{aid[:20]} dim={dim or typ} by={att} scope={scope} tier={tier}"
        if mode == "holder":
            if mine:
                out["self_rows"] += 1
                if scope != "self":
                    out["wide"].append(row)
        else:
            named = [n for n in names if n and n in env_text]
            if mine or named:
                out["leaked"].append(row + (f" names={named[:3]}" if named else ""))
    for k in ("wide", "leaked"):
        out[k + "_count"] = len(out[k])
        out[k] = out[k][:12]
    print(json.dumps(out))


if __name__ == "__main__":
    main()
