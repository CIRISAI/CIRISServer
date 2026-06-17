#!/usr/bin/env python3
"""Run the agent's EXISTING Python QA-runner module definitions against a live
`ciris-server` (the Rust fabric node) and report conformance.

This is NOT a port. It imports the agent's UNMODIFIED `qa_runner` module
test-case definitions (`config.QATestCase`, `modules/api_tests.py`,
`modules/sdk_tests.py`, ...) — the encoded EXPECTED behaviour — and executes each
`QATestCase` against ciris-server using the SAME pass criterion the agent's
`QARunner._execute_single_test` uses: `response.status_code == expected_status`
(+ optional validation_rules/custom_validation), with retries. Auth is obtained
exactly as the runner does: POST /v1/auth/login → access_token → Bearer header.

Why a thin driver instead of `QARunner` itself: `QARunner.__init__` imports
`qa_runner.server` (APIServerManager) and `_module_metadata`, which assume the
agent dev-tree layout and auto-start a Python agent. The mission says point the
runner at an ALREADY-RUNNING node (`--no-auto-start`) and never auto-start. This
driver is that no-auto-start harness — it consumes the module definitions and the
runner's execution contract verbatim.

Usage:  python qa/run_fabric.py --url http://127.0.0.1:4243
"""
import argparse
import json
import sys
import time
from pathlib import Path

import requests

# Make `qa_runner` importable from qa/.
QA_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(QA_DIR))

# The agent's `qa_runner/__init__.py` and `modules/__init__.py` eagerly import
# brain-coupled siblings (billing_tests → ciris_sdk → ciris_engine), and
# `runner.py` imports `server.py` (the auto-start machinery we are explicitly NOT
# using — mission: point at an already-running node). We therefore load the THREE
# UNMODIFIED definition files we need (config, api_tests, sdk_tests) directly,
# wiring just enough package namespace for their `from ..config import ...` to
# resolve. The files themselves are byte-identical to the agent's; we only avoid
# the package __init__ side-effects.
import importlib.util  # noqa: E402
import types  # noqa: E402


def _load(modname, relpath, package=None):
    spec = importlib.util.spec_from_file_location(modname, QA_DIR / relpath)
    mod = importlib.util.module_from_spec(spec)
    if package:
        mod.__package__ = package
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


# Minimal package shells so relative imports (`from ..config`) resolve without
# executing the brain-coupled __init__.py files.
_pkg = types.ModuleType("qa_runner")
_pkg.__path__ = [str(QA_DIR / "qa_runner")]
sys.modules["qa_runner"] = _pkg
_mods = types.ModuleType("qa_runner.modules")
_mods.__path__ = [str(QA_DIR / "qa_runner" / "modules")]
sys.modules["qa_runner.modules"] = _mods

_config = _load("qa_runner.config", "qa_runner/config.py", package="qa_runner")
QAConfig, QAModule, QATestCase = _config.QAConfig, _config.QAModule, _config.QATestCase
APITestModule = _load(
    "qa_runner.modules.api_tests", "qa_runner/modules/api_tests.py", package="qa_runner.modules"
).APITestModule
SDKTestModule = _load(
    "qa_runner.modules.sdk_tests", "qa_runner/modules/sdk_tests.py", package="qa_runner.modules"
).SDKTestModule

# ── The fabric surface ciris-server actually serves (compose.rs) ───────────────
# read-API listener (listen+1): /v1/identity, /v1/self/login, /v1/auth/*,
# /v1/setup/connect-node*, /lens/api/v1/*.  Everything else is agent-brain.
FABRIC_PREFIXES = (
    "/v1/auth/",
    "/v1/identity",
    "/v1/self/login",
    "/v1/setup/connect-node",
    "/v1/setup/reset-device-auth",
    "/lens/api/v1/",
)


def is_fabric_endpoint(ep: str) -> bool:
    return any(ep.startswith(p) for p in FABRIC_PREFIXES)


class FabricConformance:
    """Replicates QARunner's HTTP execution + pass criterion (no auto-start)."""

    def __init__(self, base_url: str, config: QAConfig):
        self.base_url = base_url.rstrip("/")
        self.config = config
        self.token = None
        self.results = []

    # mirror of QARunner._authenticate
    def authenticate(self) -> bool:
        r = requests.post(
            f"{self.base_url}/v1/auth/login",
            json={"username": self.config.admin_username, "password": self.config.admin_password},
            timeout=10,
        )
        if r.status_code == 200:
            self.token = r.json()["access_token"]
            return True
        print(f"  AUTH FAILED {r.status_code}: {r.text[:200]}")
        return False

    # mirror of QARunner._execute_single_test (HTTP subset) + pass criterion
    def execute(self, test: QATestCase):
        headers = {}
        if test.requires_auth and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        url = f"{self.base_url}{test.endpoint}"
        start = time.time()
        last = None
        for attempt in range(self.config.retry_count):
            try:
                if test.method == "GET":
                    resp = requests.get(url, headers=headers, timeout=test.timeout)
                elif test.method == "POST":
                    resp = requests.post(url, headers=headers, json=test.payload, timeout=test.timeout)
                elif test.method == "PUT":
                    resp = requests.put(url, headers=headers, json=test.payload, timeout=test.timeout)
                elif test.method == "DELETE":
                    resp = requests.delete(url, headers=headers, timeout=test.timeout)
                elif test.method == "WEBSOCKET":
                    return None, {"status_code": None, "note": "websocket (skipped: not served by fabric)"}
                else:
                    return False, {"error": f"unknown method {test.method}"}
                last = resp
                if resp.status_code == test.expected_status:
                    # token-refresh special-case (matches runner)
                    if test.name == "SDK token refresh" and resp.status_code == 200:
                        try:
                            nt = resp.json().get("access_token")
                            if nt:
                                self.token = nt
                        except Exception:
                            pass
                    ok, vresult = self._validate(test, resp)
                    return ok, {"status_code": resp.status_code, "duration": time.time() - start, **vresult}
                if attempt < self.config.retry_count - 1:
                    time.sleep(0.2)
                    continue
                return False, {
                    "status_code": resp.status_code,
                    "expected_status": test.expected_status,
                    "error": resp.text[:200],
                    "duration": time.time() - start,
                }
            except Exception as e:
                if attempt < self.config.retry_count - 1:
                    time.sleep(0.2)
                    continue
                return False, {"error": str(e), "duration": time.time() - start}
        return False, {"error": "max retries", "last": getattr(last, "status_code", None)}

    def _validate(self, test: QATestCase, resp):
        # mirror of QARunner._validate_response (rules + custom)
        try:
            data = resp.json()
        except Exception:
            data = {"raw_text": resp.text}
        if getattr(test, "validation_rules", None):
            for name, fn in test.validation_rules.items():
                try:
                    if not fn(data):
                        return False, {"validation_error": f"rule {name} failed"}
                except Exception as e:
                    return False, {"validation_error": f"rule {name} raised {e}"}
        if getattr(test, "custom_validation", None):
            try:
                if not test.custom_validation(data):
                    return False, {"validation_error": "custom_validation failed"}
            except Exception as e:
                return False, {"validation_error": f"custom_validation raised {e}"}
        return True, {}

    def run_tests(self, label, tests):
        print(f"\n=== module: {label} ({len(tests)} tests) ===")
        for t in tests:
            fab = is_fabric_endpoint(t.endpoint)
            ok, info = self.execute(t)
            if ok is None:
                verdict = "SKIP"
            elif ok:
                verdict = "PASS"
            elif not fab:
                verdict = "N-A "  # endpoint is agent-brain, not a fabric route
            else:
                verdict = "GAP "
            self.results.append(
                {
                    "module": label,
                    "name": t.name,
                    "method": t.method,
                    "endpoint": t.endpoint,
                    "expected_status": t.expected_status,
                    "fabric": fab,
                    "verdict": verdict,
                    "info": info,
                }
            )
            sc = info.get("status_code")
            tag = "" if fab else "  [agent-brain endpoint]"
            print(f"  [{verdict}] {t.method:6} {t.endpoint:32} exp={t.expected_status} got={sc}{tag}")
            if verdict == "GAP":
                print(f"          -> {json.dumps(info)[:240]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:4243")
    ap.add_argument("--username", default="jeff")
    ap.add_argument("--password", default="qa_test_password_12345")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    cfg = QAConfig(
        base_url=args.url,
        admin_username=args.username,
        admin_password=args.password,
        auto_start_server=False,
        retry_count=2,
    )
    fc = FabricConformance(args.url, cfg)

    print(f"Target ciris-server read-API: {args.url}")
    if not fc.authenticate():
        print("FATAL: could not authenticate as the seeded admin user.")
        sys.exit(2)
    print(f"  authenticated as {args.username} (token suffix ...{fc.token[-8:]})")

    # The agent's UNMODIFIED module definitions. AUTH + SDK are the fabric HTTP
    # modules whose endpoints can be served headless; the per-test fabric/brain
    # split is done by endpoint at runtime.
    fc.run_tests("auth", APITestModule.get_auth_tests(admin_username=args.username, admin_password=args.password))
    fc.run_tests("sdk", SDKTestModule.get_sdk_tests(admin_username=args.username, admin_password=args.password))
    # The remaining APITestModule lists are entirely agent-brain endpoints
    # (telemetry/agent/system/memory/audit/tools/guidance) — included to make the
    # N-A surface explicit and machine-checkable rather than asserted.
    fc.run_tests("telemetry", APITestModule.get_telemetry_tests())
    fc.run_tests("agent", APITestModule.get_agent_tests())
    fc.run_tests("system", APITestModule.get_system_tests())
    fc.run_tests("memory", APITestModule.get_memory_tests())
    fc.run_tests("audit", APITestModule.get_audit_tests())
    fc.run_tests("tools", APITestModule.get_tool_tests())
    fc.run_tests("guidance", APITestModule.get_guidance_tests())

    # ── CEG-native fabric routes ──────────────────────────────────────────────
    # The agent's consent/dsar/partnership QA modules drive a DIFFERENT,
    # brain-side REST service (/v1/consent/*, /v1/partnership/*, created via
    # client.interact()) — see FSD/QA_AGAINST_RUST.md. ciris-server re-expresses
    # consent/erasure CEG-NATIVELY (/v1/auth/consent, /v1/auth/erasure), gated by
    # a federation hybrid signature. There is no agent QATestCase for these, so we
    # assert their fail-closed contract directly (unauthenticated => 401).
    print("\n=== module: ceg-native-fabric (direct contract probes) ===")
    ceg_probes = [
        ("POST", "/v1/auth/consent", {"consenting_key_id": "k", "dimension": "data_processing", "granted": True}, 401),
        ("POST", "/v1/auth/erasure", {"attesting_key_id": "k"}, 401),
        ("POST", "/v1/auth/attestation", {}, 401),
        ("POST", "/v1/self/login", {}, 401),
        ("GET", "/v1/identity", None, 200),
        ("GET", "/v1/auth/oauth/providers", None, 200),
        ("GET", "/v1/auth/owner-hint", None, 200),
    ]
    for method, ep, payload, expected in ceg_probes:
        try:
            if method == "GET":
                resp = requests.get(f"{fc.base_url}{ep}", timeout=10)
            else:
                resp = requests.post(f"{fc.base_url}{ep}", json=payload, timeout=10)
            ok = resp.status_code == expected
        except Exception as e:
            ok, resp = False, None
        verdict = "PASS" if ok else "GAP "
        sc = resp.status_code if resp is not None else None
        fc.results.append(
            {"module": "ceg-native-fabric", "name": f"{method} {ep}", "method": method,
             "endpoint": ep, "expected_status": expected, "fabric": True, "verdict": verdict,
             "info": {"status_code": sc}}
        )
        print(f"  [{verdict}] {method:6} {ep:32} exp={expected} got={sc}")

    # ── Summary ──
    by = {"PASS": 0, "GAP ": 0, "N-A ": 0, "SKIP": 0}
    fabric_pass = fabric_gap = 0
    for r in fc.results:
        by[r["verdict"]] += 1
        if r["fabric"] and r["verdict"] == "PASS":
            fabric_pass += 1
        if r["fabric"] and r["verdict"] == "GAP ":
            fabric_gap += 1
    print("\n==================== SUMMARY ====================")
    print(f"  total tests executed : {len(fc.results)}")
    print(f"  PASS                 : {by['PASS']}")
    print(f"  GAP  (fabric route, wrong shape) : {by['GAP ']}")
    print(f"  N-A  (agent-brain endpoint)      : {by['N-A ']}")
    print(f"  SKIP (websocket/unsupported)     : {by['SKIP']}")
    print(f"  --- FABRIC-ROUTE tests: {fabric_pass} PASS / {fabric_gap} GAP ---")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(fc.results, indent=2, default=str))
        print(f"  wrote {args.json_out}")
    sys.exit(1 if fabric_gap else 0)


if __name__ == "__main__":
    main()
