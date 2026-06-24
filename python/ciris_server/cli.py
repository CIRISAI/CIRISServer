"""CIRIS Server CLI — desktop-first launcher with a headless node fallback.

Mirrors CIRISAgent's ``ciris_engine/cli.py`` control flow, adapted to the
ciris-server wheel (the node is the compiled Rust extension, not a main.py):

    ciris-server                  # start the node + launch the desktop UI
    ciris-server --home X --key-id Y   # headless node (Node A/B path)
    ciris-server-headless ...     # always headless (alias; never the UI)
    ciris-server import-traces D  # legacy-trace import (delegates to the ext)
    ciris-server --server | --headless # force headless (bare node, defaults)

    ciris-desktop                 # UI only (node assumed already running)

THE NODE'S ARGUMENT CONTRACT (Rust ``py_main`` / ``parse_serve_flags`` in
src/lib.rs): the wheel node accepts ONLY ``--home <path>`` / ``--key-id <name>``
(both optional; ``import-traces <dir>`` for the legacy import) or a *bare* boot
with baked defaults. There is no ``serve`` subcommand on the wheel path.

ADDITIVE GUARANTEE: any node-directed invocation (``--home`` / ``--key-id`` /
``import-traces``) still boots a headless node, exactly as before. The ONLY
behavior change is that a *bare* ``ciris-server`` (no arguments) now launches the
desktop UI on top of a freshly-spawned node, instead of a bare headless node —
the desktop-first default. Headless deployments (Node A/B) always pass explicit
``--home``/``--key-id``, so they are never surprised by a UI launch; if a host
truly wants a *bare* headless node it uses ``ciris-server-headless`` or
``ciris-server --server``.
"""

import os
import subprocess
import sys
import time
from typing import Optional


# ── headless node (the existing Rust py_main path) ──────────────────────────
# Node-directed tokens the Rust extension's py_main consumes directly. Their
# presence means "the user is driving the node" → run headless, never the UI.
_NODE_TOKENS = {"import-traces", "--home", "--key-id"}
# Launcher-only markers that force a *bare* headless node (stripped before the
# args reach the node, which does not understand them).
_FORCE_HEADLESS = {"--server", "--headless"}


def _run_node_headless() -> None:
    """Boot the headless node via the compiled extension's ``main``.

    Delegates to ``ciris_server._native.main`` (PyO3), which reads ``sys.argv``
    and parses ``--home`` / ``--key-id`` / ``import-traces`` exactly as the
    ``ciris-server`` binary does. A leading ``--server`` / ``--headless`` marker
    is launcher-only (not a node flag), so strip it first → a bare node boot.
    """
    while len(sys.argv) > 1 and sys.argv[1] in _FORCE_HEADLESS:
        del sys.argv[1]
    from ciris_server._native import main as _native_main

    _native_main()


def _wants_desktop() -> bool:
    """True only for a bare ``ciris-server`` (no node-directed arguments).

    Anything the node understands (``--home`` / ``--key-id`` / ``import-traces``)
    or an explicit ``--server`` / ``--headless`` marker keeps us headless. Any
    other leading token is also routed to the node (which fails loud on unknown
    serve args) — never to the UI — so the desktop is a strict opt-in default.
    """
    args = sys.argv[1:]
    if not args:
        return True
    return False


# ── desktop-first mode ──────────────────────────────────────────────────────
def _read_api_url(port: int = 4243) -> str:
    return f"http://localhost:{port}"


def _wait_for_node_health(
    server_url: str, node_proc: "subprocess.Popen[bytes]", timeout: float = 60.0
) -> bool:
    """Poll ``GET {server_url}/health`` until the node answers 200 or it dies."""
    import json
    import urllib.error
    import urllib.request

    health_url = f"{server_url}/health"
    start = time.time()
    attempt = 0
    while time.time() - start < timeout:
        if node_proc.poll() is not None:
            return False
        attempt += 1
        try:
            with urllib.request.urlopen(health_url, timeout=3) as resp:
                if resp.status == 200:
                    try:
                        body = json.loads(resp.read().decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        body = {}
                    if body.get("status", "ok") in ("ok", "starting", "degraded"):
                        elapsed = time.time() - start
                        print(f"Node ready ({elapsed:.1f}s)")
                        return True
        except (urllib.error.URLError, OSError, TimeoutError):
            pass
        if attempt % 10 == 0:
            print(f"Waiting for node... (attempt {attempt})")
        time.sleep(0.5)
    return False


def _spawn_headless_node(extra_args: Optional[list] = None) -> "subprocess.Popen[bytes]":
    """Spawn a bare headless node in a child process.

    ``python -m ciris_server --headless`` → the node with baked defaults (the
    wheel node takes no ``serve`` subcommand; only ``--home``/``--key-id``). A
    subprocess (not in-process) lets the node's tokio runtime and the JVM run
    concurrently, and lets the launcher tear the node down when the UI exits.
    """
    if getattr(sys, "frozen", False):
        # PyInstaller bundle (the Windows installer): there is no `python -m`
        # runpy inside a frozen build, and ``sys.executable`` is ciris-server.exe
        # itself. Re-invoke the same frozen exe with ``--headless`` — cli.main()
        # routes that straight to the headless node (never the UI), so this is
        # the bare-node child the desktop parent waits on.
        cmd = [sys.executable, "--headless"]
    else:
        cmd = [sys.executable, "-m", "ciris_server", "--headless"]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.Popen(cmd, env=os.environ.copy())


def _run_desktop_mode() -> None:
    """Start the headless node, wait for its read API, then launch the UI."""
    port = 4243
    server_url = _read_api_url(port)

    print("Starting CIRIS node...")
    node_proc = _spawn_headless_node()

    # Give it a moment; surface an immediate crash clearly.
    time.sleep(2.0)
    exit_code = node_proc.poll()
    if exit_code is not None:
        print("\n" + "=" * 60, file=sys.stderr)
        print("ERROR: CIRIS node failed to start!", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        if exit_code != 0:
            print(f"Node exited with code: {exit_code}", file=sys.stderr)
        print("\nCommon causes:", file=sys.stderr)
        print(f"  - Port {port - 1}/{port} already in use by another process", file=sys.stderr)
        print("  - Missing data home / key material", file=sys.stderr)
        print("=" * 60 + "\n", file=sys.stderr)
        sys.exit(exit_code if exit_code != 0 else 1)

    try:
        print("Waiting for node read API to be ready...")
        if not _wait_for_node_health(server_url, node_proc, timeout=60.0):
            exit_code = node_proc.poll()
            if exit_code is not None:
                print(f"ERROR: Node process exited with code {exit_code}", file=sys.stderr)
                sys.exit(exit_code if exit_code != 0 else 1)
            print("WARNING: Node not yet answering health checks; launching UI anyway.")
            print("         The desktop app will retry connecting.")

        try:
            from ciris_server.desktop_launcher import launch_desktop_app

            print("\nLaunching CIRIS Desktop...")
            exit_code = launch_desktop_app(server_url=server_url)
        except ImportError as e:
            print(f"Desktop launcher not available: {e}", file=sys.stderr)
            print(f"\nNode running at: {server_url}")
            print("Press Ctrl+C to stop...")
            exit_code = 0
            try:
                node_proc.wait()
            except KeyboardInterrupt:
                pass
        except Exception as e:
            print(f"ERROR: Failed to launch desktop app: {e}", file=sys.stderr)
            print(f"\nNode still running at: {server_url}")
            print("Press Ctrl+C to stop...")
            exit_code = 1
            try:
                node_proc.wait()
            except KeyboardInterrupt:
                pass
    finally:
        print("\nShutting down node...")
        node_proc.terminate()
        try:
            node_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            node_proc.kill()

    sys.exit(exit_code)


# ── entry points (pyproject [project.scripts]) ──────────────────────────────
def main() -> None:
    """``ciris-server`` — default = node + desktop UI; serve/--home = headless."""
    if _wants_desktop():
        _run_desktop_mode()
    else:
        _run_node_headless()


def server() -> None:
    """``ciris-server-headless`` — always run the headless node (never the UI)."""
    _run_node_headless()


def desktop() -> None:
    """``ciris-desktop`` — launch the desktop UI only."""
    from ciris_server.desktop_launcher import main as desktop_main

    desktop_main()


if __name__ == "__main__":
    main()
