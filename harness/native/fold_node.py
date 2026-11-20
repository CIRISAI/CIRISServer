#!/usr/bin/env python3
"""A native-mesh node that boots the way the agent does: the FOLD.

    python3 -m harness.native.fold_node --home H --key-id K --listen IP:PORT [--peers a,b]

The agent (CIRISAgent edge_runtime.py) does not run the `ciris-server` binary.
In one Python process it:

1. opens persist on the node's own store with ITS key (an actor, registered as
   `agent`);
2. provisions a separate node identity and starts the embedded edge with
   `use_node_identity=True`. The edge's own signer is the AGENT key; the node
   key is only the advertised (wire) identity;
3. runs compose on that live edge: `serve_with_python_adapter`.

The `ciris-server` binary never reaches step 2's shape: its `build_edge` gives
edge the node key as its signer. So a call on a split binary always worked,
while every agent install answered `call.plumbing` (Eric's laptop,
2026-11-18): edge acted "as the node" with the actor's key until edge 45.1.6
added `Edge::set_node_signer` and compose handed it the node key. Only this
boot path tests that.

The package comes from the installed `ciris_server` wheel, or, with
`HARNESS_FOLD_SO=<path to libciris_server.so>`, from that library plus
`python/ciris_server/*.py` laid out under the node's work dir (the way
`harness/mesh-repro/pack_wheel.py` lays out the test-anchor wheel).
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _package_from_so(so: Path, into: Path) -> None:
    pkg = into / "ciris_server"
    if pkg.exists():
        shutil.rmtree(pkg)
    shutil.copytree(ROOT / "python" / "ciris_server", pkg)
    shutil.copy2(so, pkg / "_native.abi3.so")
    sys.path.insert(0, str(into))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--home", required=True)
    ap.add_argument("--key-id", required=True)
    ap.add_argument("--listen", required=True)
    ap.add_argument("--peers", default="")
    a = ap.parse_args()
    home = Path(a.home)
    so = os.environ.get("HARNESS_FOLD_SO", "").strip()
    if so:
        _package_from_so(Path(so), home.parent / "fold_pkg")

    import ciris_server
    from ciris_server import Engine
    from ciris_server.edge import init_edge_runtime

    if hasattr(ciris_server, "init_tracing"):
        ciris_server.init_tracing()

    def log(msg: str) -> None:
        print(f"[fold] {msg}", flush=True)

    # compose's own store and seed files (ServerConfig::from_home / seed_path),
    # so the key the engine registers as `agent` and the key compose loads are
    # one keypair: the precondition for the split to be about a real actor.
    (home / "data").mkdir(parents=True, exist_ok=True)
    ident = home / "identity"
    ident.mkdir(parents=True, exist_ok=True)
    seed, pqc_seed = ident / "ed25519.seed", ident / "ml_dsa_65.seed"
    # The harness configures the node with the CLI before it boots, and the CLI
    # seals the configured key's seed into the keyring, keeping the original
    # as `ed25519.seed.migrated`. That file IS the key compose loads; minting a
    # fresh one would give the engine a second identity (CIRISServer#380).
    migrated = ident / "ed25519.seed.migrated"
    if not seed.exists() and migrated.exists():
        seed = migrated
    for s in (seed, pqc_seed):
        if not s.exists():
            s.write_bytes(os.urandom(32))
            s.chmod(0o600)

    engine = Engine(
        f"sqlite:///{home / 'data' / 'ciris_engine.db'}",
        a.key_id,
        local_key_id=a.key_id,
        local_key_path=str(seed),
        local_pqc_key_id=a.key_id,
        local_pqc_key_path=str(pqc_seed),
    )
    try:
        log(f"registered the actor key: {engine.register_self_federation_key('agent', a.key_id)}")
    except Exception as e:  # noqa: BLE001 - already present is benign
        log(f"actor key registration: {type(e).__name__}: {e}")

    node_key_id = ciris_server.provision_node_identity(a.key_id, str(ident))
    log(f"node identity provisioned: {node_key_id} (the actor {a.key_id} keeps its own key)")
    peers = [p for p in a.peers.split(",") if p]
    # The direct-link facilitator: the binary's compose defaults it to the
    # first bootstrap peer (`compose::direct_links`), and the canonical serves
    # one. The PyO3 init takes it only when named (or from the baked
    # production canonical, which a test trust root gates off). Without it,
    # two members two hops apart never get a direct link, and a call's
    # derived A/V destination answers a one-hop neighbour only: both join,
    # and no leg ever forms (CIRISEdge, 2026-11-19).
    facilitator = os.environ.get("HARNESS_FOLD_FACILITATOR") or (peers[0] if peers else None)
    edge = init_edge_runtime(
        engine,
        str(home / "edge_identity.rid"),
        listen_addr=a.listen,
        bootstrap_peers=peers,
        direct_link_facilitator=facilitator,
        agent_mode="server",
        enable_transport=True,
        use_node_identity=True,
        node_identity_dir=str(ident),
        node_keystore_alias=node_key_id.rsplit("-", 1)[0],
    )
    log(f"embedded edge up: signer_key_id={edge.signer_key_id()} listen={a.listen}")

    class _StubAdapter:
        adapter_type = "harness-fold-node"
        enabled = True

        def proxy_routes(self):
            return []

        def start(self):
            return None

        def stop(self):
            return None

    log(f"serve_with_python_adapter(home={home}, key_id={a.key_id})")
    ciris_server.serve_with_python_adapter(_StubAdapter(), str(home), a.key_id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
