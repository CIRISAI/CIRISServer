"""Write the transfer corpus on one node, then read it back on another and
compare every byte. Runs INSIDE a node container (stdlib only, loopback API).

    python3 corpus_client.py write <token> <dir>   # POST /v1/files for each file
    python3 corpus_client.py read  <token> <dir>   # GET  /v1/files/{id}?raw=1

`<dir>` holds the files and `manifest.json` from `media_corpus.py` (and, on the
reading device, the author's `written.json`). Results go to /tmp/corpus-state:
`write` records `written.json` (id or refusal per file), and `read` records
`read.json` and prints one JSON summary line. `read` is safe to call on every ladder sample:
a file already verified is not fetched again.

A file counts as OPENED only when the second device returns the raw bytes and
their SHA-256 equals the digest computed where the fixture was generated.
Listing the row, or a `bytes: "here"` state, is not proof of the bytes.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:4243"
#: Where results go. The input directory is copied in by `docker compose cp`,
#: which leaves it owned by root, and the node runs as its own user; so the
#: client writes into a directory it creates itself.
STATE = Path("/tmp/corpus-state")


def _call(token: str, method: str, path: str, body: dict | None = None, timeout: int = 180):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, method=method, data=data, headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # noqa: BLE001 — a transport failure is a result, not a crash
        return 0, json.dumps({"detail": repr(e)[:200]}).encode()


def _json(raw: bytes) -> dict:
    try:
        v = json.loads(raw.decode() or "{}")
        return v if isinstance(v, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def write(token: str, d: Path) -> None:
    manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    out = []
    for row in manifest:
        data = (d / row["name"]).read_bytes()
        status, raw = _call(token, "POST", "/v1/files", {
            "cohort": "self",
            "bytes_base64": base64.b64encode(data).decode(),
            "media_type": row["media_type"],
            "filename": row["filename"],
        })
        body = _json(raw)
        out.append({
            "name": row["name"],
            "status": status,
            "attestation_id": body.get("attestation_id"),
            "reason_id": body.get("reason_id"),
            "crossed": body.get("crossed"),
            "excluded": body.get("excluded"),
        })
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / "written.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    known = {r["name"] for r in manifest if r.get("known_defect")}
    good = lambda r: r["status"] == 200 and r["attestation_id"]  # noqa: E731
    print(json.dumps({
        "written": sum(1 for r in out if good(r) and r["name"] not in known),
        "total": len(out) - len(known),
        "refused": [f'{r["name"]}:{r["status"]}:{r["reason_id"]}'
                    for r in out if not good(r) and r["name"] not in known],
        # A known defect that WROTE is a fixed defect still marked: red.
        "known_defect_now_passes": [r["name"] for r in out if good(r) and r["name"] in known],
    }))


def read(token: str, d: Path) -> None:
    manifest = {r["name"]: r for r in json.loads((d / "manifest.json").read_text(encoding="utf-8"))}
    written = json.loads((d / "written.json").read_text(encoding="utf-8"))
    STATE.mkdir(parents=True, exist_ok=True)
    done_path = STATE / "read.json"
    done = {r["name"]: r for r in json.loads(done_path.read_text(encoding="utf-8"))} if done_path.exists() else {}
    for w in written:
        name = w["name"]
        if not w.get("attestation_id") or done.get(name, {}).get("match"):
            continue
        q = urllib.parse.quote(w["attestation_id"], safe="")
        status, raw = _call(token, "GET", f"/v1/files/{q}?cohort=self&raw=1")
        if status == 200:
            got = hashlib.sha256(raw).hexdigest()
            done[name] = {"name": name, "status": status, "size": len(raw),
                          "match": got == manifest[name]["sha256"],
                          "sha256": got}
        else:
            body = _json(raw)
            done[name] = {"name": name, "status": status, "match": False,
                          "reason_id": body.get("reason_id"),
                          "detail": str(body.get("error") or body.get("detail") or "")[:160]}
    done_path.write_text(json.dumps(list(done.values()), indent=1), encoding="utf-8")
    known = {n for n, r in manifest.items() if r.get("known_defect")}
    ids = [w for w in written if w.get("attestation_id")]
    opened = [n for n, r in done.items() if r.get("match") and n not in known]
    corrupt = [n for n, r in done.items() if r.get("status") == 200 and not r.get("match")]
    waiting = sorted({f'{n}:{r.get("status")}:{r.get("reason_id")}'
                      for n, r in done.items() if r.get("status") != 200})
    print(json.dumps({"opened": len(opened), "expected": len(ids),
                      "total": len(written) - len(known),
                      "corrupt": corrupt, "waiting": waiting}))


if __name__ == "__main__":
    verb, token, directory = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    {"write": write, "read": read}[verb](token, directory)
