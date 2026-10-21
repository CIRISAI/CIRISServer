"""The final-genesis ceremony over the routes, run INSIDE the canonical container.

The Docker mesh's half of CIRISServer#801 — the same ceremony
`harness/native/scenarios.py::mint_accord_root` drives: plan (the canonical's
own signed transport row, with its transit pair, is gathered into the bundle,
CC 5.3.4), two signing rounds with the three software test holders, finish.
Stdlib only (the image is python:3.12-slim + the wheel). Reads the holders from
/genesis/anchor.json (the harness wrote it from `test_ceremony_anchor`);
prints ONE JSON line: {"bundle_path", "key_id", "bundle_sha256"}.

    python - <serve dial "host:port"> < genesis_ceremony.py
"""
import json
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:4243"


def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")[:800]
    except OSError as e:
        return 0, str(e)


def must(method, path, body=None):
    st, got = call(method, path, body)
    if st not in (200, 201):
        sys.exit(f"genesis ceremony: {method} {path} answered {st}: {got}")
    return got


def main():
    dial = sys.argv[1]
    anchor = json.load(open("/genesis/anchor.json"))
    key_id = None
    for _ in range(60):
        st, rec = call("GET", "/v1/federation/self-key-record")
        if st == 200:
            key_id = rec["record"]["key_id"]
            break
        time.sleep(2)
    if not key_id:
        sys.exit("genesis ceremony: the canonical never served its self-key-record")
    plan = {
        "serve_nodes": [{"key_id": key_id,
                         "transport_hints": [{"kind": "ip", "destination": dial}]}],
        "recovery_keys": anchor["recovery_keys"],
        "clock_checked": True,
    }
    # The canonical publishes its own transport row (with the transit pair) a
    # moment after boot; until then the plan refuses
    # `final_genesis.serve_node_without_transit_pair`. Retry, bounded.
    last = None
    for _ in range(60):
        st, last = call("POST", "/v1/accord/final-genesis/plan", plan)
        if st in (200, 201):
            break
        time.sleep(2)
    else:
        sys.exit(f"genesis ceremony: plan never accepted: {last}")
    for _ in (1, 2):
        for h in anchor["holders"]:
            must("POST", "/v1/accord/final-genesis/sign", {
                "key_id": h["key_id"], "mldsa_usb_path": "/unused/software-holder",
                "test_holder_seed_b64": h["seed_b64"]})
    status = must("GET", "/v1/accord/final-genesis")
    if not status.get("complete"):
        sys.exit(f"genesis ceremony: items still owed after two rounds: {status}")
    done = must("POST", "/v1/accord/final-genesis/finish", {})
    print(json.dumps({"bundle_path": done["bundle_path"], "key_id": key_id,
                      "bundle_sha256": done.get("bundle_sha256")}))


main()
