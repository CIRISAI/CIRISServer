"""A native mesh: N `ciris-server` processes on 127.0.0.1 under the SYNTHETIC
trust root, no Docker, in seconds.

WHY. The mesh-repro ladders answer in ~45 minutes (wheel build, image, compose,
a 13-minute watch). A question like "does a 1 MiB self file come back
byte-identical on the second device?" or "do two people's nodes key a pair
room over the PRODUCTION peering routes?" needs an answer in minutes, and the
next question needs the same nodes again. So: one binary (any build with
`--features test-anchor`), one directory per node, and small steps that
compose.

THE TRUST ROOT is the harness's own synthetic anchor, read from
`harness/mesh-repro/docker-compose.yml` (`x-test-anchor-env`), so the fixture
and the ladders never carry two copies of it. Under a live test anchor a node
dials only what it is told (edge #661) — never the production canonical — and a
`canonical` node blessed as the test root's holder is what every other node
roots through, exactly as in the ladders.

PRODUCTION ROUTES BY DEFAULT. Peering is `GET /v1/federation/self-key-record`
+ `POST /v1/federation/peering`, the routes a released node exposes. The
ladders' `test-admit-peer` shortcut is available (`Node.test_admit`) but a
scenario must ask for it by name: it is the shortcut that kept the chat ladder
green while two released nodes could not key a pair room (CIRISServer#698).

Everything here is a library: `scenarios.py` composes it, `__main__` runs it,
and a REPL can drive the same objects by hand.
"""
from __future__ import annotations

import base64
import glob
import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

HARNESS = Path(__file__).resolve().parent.parent
COMPOSE = HARNESS / "mesh-repro" / "docker-compose.yml"


class MeshError(RuntimeError):
    """A step could not do what it says. Carries the evidence, never a guess."""


def anchor_env() -> Dict[str, str]:
    """The synthetic trust root and harness knobs, as the ladders set them.

    Parsed from the `x-test-anchor-env` block of the mesh-repro compose file:
    every `KEY: "value"` line until the block ends."""
    env: Dict[str, str] = {}
    inside = False
    for line in COMPOSE.read_text(encoding="utf-8").splitlines():
        if line.startswith("x-test-anchor-env:"):
            inside = True
            continue
        if inside:
            if line and not line.startswith((" ", "\t")):
                break
            m = re.match(r'^\s+([A-Z][A-Z0-9_]+):\s*"(.*)"\s*$', line)
            if m:
                env[m.group(1)] = m.group(2)
    if "CIRIS_TEST_TRUST_ROOT" not in env:
        raise MeshError(f"no CIRIS_TEST_TRUST_ROOT in the x-test-anchor-env block of {COMPOSE}")
    return env


def free_port_pair(start: int = 7242) -> int:
    """A port p with p and p+1 both free (edge on p, HTTP on p+1)."""
    p = start
    while p < 65000:
        ok = True
        for q in (p, p + 1):
            with socket.socket() as s:
                try:
                    s.bind(("127.0.0.1", q))
                except OSError:
                    ok = False
                    break
        if ok:
            return p
        p += 2
    raise MeshError("no free port pair")


def http(method: str, url: str, token: Optional[str] = None, body: Any = None,
         timeout: float = 60.0, raw: bool = False) -> Tuple[int, Any]:
    """(status, parsed JSON | bytes when raw). A transport failure is status 0."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = r.read()
            status = r.status
    except urllib.error.HTTPError as e:
        payload, status = e.read(), e.code
    except Exception as e:  # noqa: BLE001 — a result, not a crash
        return 0, {"detail": repr(e)[:300]}
    if raw:
        return status, payload
    try:
        return status, json.loads(payload.decode() or "{}")
    except Exception:  # noqa: BLE001
        return status, {"raw": payload[:300].decode(errors="replace")}


def wait_for(what: str, probe: Callable[[], Any], timeout: float, every: float = 2.0) -> Any:
    """Poll `probe` until it returns something truthy; raise naming `what`."""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last:
            return last
        time.sleep(every)
    raise MeshError(f"timed out after {timeout:.0f}s waiting for {what} (last: {str(last)[:300]})")


# ── one node ────────────────────────────────────────────────────────────────


@dataclass
class Node:
    name: str
    binary: Path
    home: Path
    key_id: str
    port: int
    env: Dict[str, str]
    log_path: Path
    proc: Optional[subprocess.Popen] = None
    token: str = ""
    owner_key_id: str = ""
    node_key_id: str = ""
    record: Any = None

    # -- process --

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port + 1}"

    @property
    def transport(self) -> str:
        return f"127.0.0.1:{self.port}"

    def _cli(self, *args: str, timeout: float = 180.0) -> str:
        cmd = [str(self.binary), *args, "--home", str(self.home), "--key-id", self.key_id]
        got = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                             env={**os.environ, **self.env})
        if got.returncode != 0:
            raise MeshError(f"{self.name}: `{' '.join(args[:3])}` exited {got.returncode}: "
                            f"{(got.stderr or got.stdout)[-800:]}")
        return got.stdout

    def configure(self, dial: List[str]) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        self._cli("config", "set", "net.listen_addr", json.dumps(self.transport))
        if dial:
            self._cli("config", "set", "net.bootstrap_peers", json.dumps(dial),
                      "--reason", "native mesh fixture")

    def start(self, health_timeout: float = 120.0) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        log = open(self.log_path, "ab")
        self.proc = subprocess.Popen(
            [str(self.binary), "--home", str(self.home), "--key-id", self.key_id],
            stdout=log, stderr=subprocess.STDOUT, env={**os.environ, **self.env},
            start_new_session=True)

        def healthy() -> bool:
            if self.proc and self.proc.poll() is not None:
                raise MeshError(f"{self.name} exited {self.proc.returncode} during boot; "
                                f"tail of {self.log_path}:\n{self.log_tail(40)}")
            return http("GET", f"{self.url}/health", timeout=3)[0] == 200

        wait_for(f"{self.name} /health", healthy, health_timeout, every=1.0)

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=15)
            except Exception:  # noqa: BLE001
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except Exception:  # noqa: BLE001
                    pass
        self.proc = None

    def log_tail(self, n: int = 60) -> str:
        try:
            lines = self.log_path.read_text(errors="replace").splitlines()
        except FileNotFoundError:
            return ""
        return "\n".join(_strip_ansi(line) for line in lines[-n:])

    def grep(self, pattern: str) -> List[str]:
        rx = re.compile(pattern)
        try:
            text = self.log_path.read_text(errors="replace")
        except FileNotFoundError:
            return []
        return [_strip_ansi(line) for line in text.splitlines() if rx.search(_strip_ansi(line))]

    # -- HTTP --

    def api(self, method: str, path: str, body: Any = None, **kw: Any) -> Tuple[int, Any]:
        return http(method, self.url + path, self.token, body, **kw)

    def must(self, method: str, path: str, body: Any = None, ok: Tuple[int, ...] = (200, 201),
             **kw: Any) -> Any:
        status, got = self.api(method, path, body, **kw)
        if status not in ok:
            raise MeshError(f"{self.name}: {method} {path} answered {status}: {str(got)[:500]}")
        return got

    # -- identity --

    def claim(self, alias: Optional[str] = None, pin_timeout: float = 90.0) -> None:
        """Mint (or reuse) an owner identity under `alias` and claim this node
        with it over the console claim, as the ladders do."""
        alias = alias or f"{self.key_id}-owner"
        pin_file = self.home / "claim_pin"
        wait_for(f"{self.name} claim PIN", pin_file.is_file, pin_timeout, every=0.5)
        pin = pin_file.read_text(encoding="utf-8").strip()
        code = self.must("GET", "/v1/federation/node-code")["code"]
        user_seed = self.home / "identity" / "user" / f"{alias}-user.ed25519.seed"
        if not user_seed.exists():
            # `--key-id` here is the OWNER's alias, not the node's: not `_cli`.
            got = subprocess.run(
                [str(self.binary), "identity", "create", "--backend", "software",
                 "--home", str(self.home), "--key-id", alias],
                capture_output=True, text=True, timeout=180, env={**os.environ, **self.env})
            if got.returncode != 0:
                raise MeshError(f"{self.name}: identity create exited {got.returncode}: "
                                f"{(got.stderr or got.stdout)[-800:]}")
        out = subprocess.run(
            [str(self.binary), "claim", "--backend", "software", "--home", str(self.home),
             "--key-id", alias, "--node-code", code, "--claim-pin", pin,
             "--cohort-scope", "self", "--target-url", self.url],
            capture_output=True, text=True, timeout=180, env={**os.environ, **self.env})
        blob = out.stdout[out.stdout.find("{"):] if "{" in out.stdout else ""
        try:
            got = json.loads(blob)
        except Exception:  # noqa: BLE001
            raise MeshError(f"{self.name}: claim printed no JSON (exit {out.returncode}): "
                            f"{(out.stderr or out.stdout)[-800:]}")
        self.token = got.get("access_token") or ""
        self.owner_key_id = got.get("identity_key_id") or ""
        if not self.token or not self.owner_key_id:
            raise MeshError(f"{self.name}: claim returned no token/identity: {str(got)[:400]}")

    def carry_owner_from(self, other: "Node", alias: str) -> None:
        """Make this node a SECOND DEVICE of `other`'s owner: carry the owner's
        home key material (as the selffiles ladder does, standing in for
        `POST /v1/self/associate` with a portable keyset)."""
        user_alias = f"{alias}-user"
        for sub, name in (("identity/user", f"{user_alias}.ed25519.seed"),
                          ("identity/user", f"{user_alias}.backend"),
                          ("identity/keys", f"{user_alias}.mldsa65.seed.blob"),
                          ("identity/keys", f"{user_alias}.master.key")):
            src = other.home / sub / name
            if not src.exists():
                raise MeshError(f"{other.name} has no {sub}/{name} to carry")
            dst = self.home / sub / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            dst.chmod(0o600)
        (self.home / "identity" / "user" / "active_user_alias").write_text(user_alias)

    def announce(self) -> Any:
        return self.must("POST", "/v1/federation/announce", {})

    def self_record(self) -> Any:
        rec = self.must("GET", "/v1/federation/self-key-record")
        self.record, self.node_key_id = rec, rec["record"]["key_id"]
        return rec

    # -- peering / contacts / chat --

    def peer_with(self, other: "Node", prefixes: Optional[List[str]] = None) -> Any:
        """PRODUCTION peering: the other node's self-key-record, admitted here."""
        if other.record is None:
            other.self_record()
        return self.must("POST", "/v1/federation/peering", {
            "peer_key_id": other.record["record"]["key_id"],
            "peer_key_record": other.record,
            "attestation_prefixes": prefixes or DEFAULT_PREFIXES})

    def test_admit(self, other: "Node") -> Any:
        """The ladders' SHORTCUT (test-anchor only). Opt-in; see the module note."""
        rec = http("GET", f"{other.url}/v1/federation/test-blessed-self-record")[1]
        return self.must("POST", "/v1/federation/test-admit-peer", rec)

    def knows(self, key_id: str) -> bool:
        return self.api("GET", f"/v1/federation/peers/{key_id}")[0] == 200

    def add_contact(self, key_or_code: str) -> Any:
        return self.must("POST", "/v1/contacts", {"key_id": key_or_code})

    def contact_code(self, nodes: str = "all") -> str:
        got = self.must("GET", f"/v1/self/contact-code?nodes={nodes}")
        return got.get("code") or got.get("contact_code") or ""

    def open_pair(self, with_key: str) -> str:
        got = self.must("POST", "/v1/chat", {"key_id": with_key})
        return got["community_id"]

    def room(self, cid: str) -> Dict[str, Any]:
        status, body = self.api("GET", f"/v1/chat/{cid}/messages")
        msgs = body.get("messages") if isinstance(body, dict) else None
        msgs = msgs or []
        ready = body.get("ready") if isinstance(body, dict) else None
        if ready is None and status == 200:
            ready = not any(m.get("kind") == "system" for m in msgs)
        return {"status": status, "ready": bool(ready), "messages": msgs,
                "state": next((m.get("message_id") for m in msgs if m.get("kind") == "system"), None)}

    def say(self, cid: str, text: str) -> str:
        got = self.must("POST", f"/v1/chat/{cid}/messages", {"body": text})
        return got.get("attestation_id") or ""

    # -- files --

    def write_file(self, data: bytes, media_type: str, filename: Optional[str],
                   cohort: str = "self") -> Dict[str, Any]:
        body = {"cohort": cohort, "bytes_base64": base64.b64encode(data).decode(),
                "media_type": media_type}
        if filename:
            body["filename"] = filename
        return self.must("POST", "/v1/files", body, timeout=300)

    def read_raw(self, attestation_id: str, cohort: str = "self") -> Tuple[int, bytes]:
        return self.api("GET", f"/v1/files/{attestation_id}?cohort={cohort}&raw=1",
                        raw=True, timeout=300)

    def drive(self, cohort: str = "self") -> List[Dict[str, Any]]:
        return (self.must("GET", f"/v1/drive?cohort={cohort}&limit=500") or {}).get("entries") or []

    # -- the node's own database, read-only --

    def rows(self, sql: str, args: Tuple[Any, ...] = ()) -> List[Tuple[Any, ...]]:
        out: List[Tuple[Any, ...]] = []
        for db in glob.glob(str(self.home / "**" / "*.db"), recursive=True):
            try:
                con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
                out.extend(con.execute(sql, args).fetchall())
                con.close()
            except sqlite3.Error:
                continue
        return out


DEFAULT_PREFIXES = ["capacity:", "chat:", "file:", "ownership:", "self:delegates_to:", "trace:"]

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    return _ANSI.sub("", s)


# ── the mesh ────────────────────────────────────────────────────────────────


class Mesh:
    """A canonical (the synthetic root's holder) plus the nodes a scenario adds.

    `with Mesh(binary, work) as m:` stops every node on exit unless `keep`."""

    def __init__(self, binary: Path, work: Path, keep: bool = False,
                 rust_log: str = "info,ciris_edge=debug", extra_env: Optional[Dict[str, str]] = None):
        self.binary = Path(binary).resolve()
        if not self.binary.is_file():
            raise MeshError(f"no binary at {self.binary}")
        self.work = Path(work).resolve()
        self.keep = keep
        self.base_env = {**anchor_env(), "RUST_LOG": rust_log, **(extra_env or {})}
        self.nodes: Dict[str, Node] = {}
        self.canonical: Optional[Node] = None
        self._next_port = 7242

    def _node(self, name: str, env: Dict[str, str]) -> Node:
        port = free_port_pair(self._next_port)
        self._next_port = port + 2
        key_id = f"native-{name}"
        return Node(name=name, binary=self.binary, home=self.work / name / "home",
                    key_id=key_id, port=port, env={**self.base_env, **env},
                    log_path=self.work / name / "node.log")

    def start_canonical(self) -> Node:
        n = self._node("canonical", {})
        n.env["CIRIS_TEST_BLESS_CANONICAL"] = "true"
        n.env["CIRIS_TEST_CANONICAL_DIAL"] = n.transport
        n.configure(dial=[])
        n.start()
        self.canonical = n
        self.nodes["canonical"] = n
        return n

    def add(self, name: str, start: bool = True) -> Node:
        if self.canonical is None:
            self.start_canonical()
        assert self.canonical is not None
        n = self._node(name, {"CIRIS_TEST_BLESS_CANONICAL": "false",
                              "CIRIS_TEST_CANONICAL_DIAL": self.canonical.transport})
        n.configure(dial=[self.canonical.transport])
        self.nodes[name] = n
        if start:
            n.start()
        return n

    def stop(self) -> None:
        for n in self.nodes.values():
            n.stop()

    def __enter__(self) -> "Mesh":
        if self.work.exists() and not self.keep:
            shutil.rmtree(self.work, ignore_errors=True)
        self.work.mkdir(parents=True, exist_ok=True)
        return self

    def __exit__(self, *exc: Any) -> None:
        if not self.keep:
            self.stop()
