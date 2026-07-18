#!/usr/bin/env python3
"""mesh-repro harness — the AGENT role.

Reproduces, from the ONE published `ciris-server` wheel, the exact federation
boot CIRISAgent's embedded edge runs (ciris_engine/logic/runtime/edge_runtime.py):

    engine = Engine("sqlite:///<db>", key_id)          # persist
    edge   = init_edge_runtime(engine, identity.rid,   # embedded edge + transport
                 listen_addr, bootstrap_peers=[canonical:4242], enable_transport=True)
    ciris_server.start_federation_delivery()           # drive rounds to the canonical

`start_federation_delivery` is the one call a bare agent makes after its edge is
up: it seeds the baked canonical key_ids as replication targets, authors this
node's `consent:replication` grant at the canonical peer, and starts the
ReplicationRuntime + reconcile loop. That is the machinery under test — the
IdentityOccurrence round whose resource transfer stalls over the (remote,
lossy) canonical link. Here it runs over a zero-loss Docker bridge, so a stall
is a real coordinator/resource bug and a completion means the remote failure is
packet-loss resilience.

All knobs are env vars (same names CIRISAgent uses):
  CIRIS_HOME                 home dir            (default /var/lib/ciris)
  CIRIS_KEY_ID               keystore alias      (default ciris-agent-harness-1)
  CIRIS_EDGE_LISTEN_ADDR     RNS listen          (default 0.0.0.0:4242)
  CIRIS_EDGE_BOOTSTRAP_PEERS host:port CSV to dial (e.g. canonical:4242)
  CIRIS_AGENT_MODE           client|proxy|server (default server)
  CIRIS_FEDERATION_DELIVERY  true/false          (default true)
"""

import os
import pathlib
import socket
import sys
import time


def log(msg: str) -> None:
    print(f"[HARNESS-AGENT] {msg}", flush=True)


def setup_nat_sim(listen: str) -> None:
    """NAT-sim for the CIRISEdge#353 scenario: make this agent an
    **initiator-only** peer, exactly like the live Node A ↔ Android repro.

    DROPs NEW inbound TCP to the edge listen port (silent drop = faithful NAT
    behavior: the canonical's fallback outbound dial hangs to timeout, not
    connection-refused). ESTABLISHED/RELATED stays ACCEPTed so replies riding
    OUR OWN outbound connection keep flowing — which is precisely the #353
    contract: the responder's reply must ride the existing inbound link,
    because a fresh dial back to us can never connect.

    Needs root + NET_ADMIN (the docker-compose.353.yml overlay provides both).
    Failure is non-fatal but loudly logged: without the drop the scenario can
    still show the busy-link collision, just not the Timeout consequence.
    """
    import subprocess

    port = listen.rsplit(":", 1)[1] if ":" in listen else "4242"
    rules = [
        ["iptables", "-A", "INPUT", "-m", "conntrack",
         "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", port,
         "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"],
    ]
    try:
        for r in rules:
            subprocess.run(r, check=True, capture_output=True, text=True)
        log(f"NAT-SIM: NEW inbound tcp/{port} silently DROPPED — this agent is "
            f"initiator-only (dial-back can never connect; #353 topology)")
    except Exception as e:  # noqa: BLE001
        log(f"NAT-SIM WARN: iptables setup failed ({type(e).__name__}: {e}) — "
            f"scenario degrades to collision-only (fallback dial will succeed)")


def busy_link_generator(stop, pad_kb: int, period_s: float) -> None:
    """CIRISEdge#353 busy-link pressure: keep this agent's link to the canonical
    OCCUPIED with real trace resource-transfers, so the canonical's round reply
    collides with an in-progress transfer ("resource transfer already in
    progress") and exercises the reverse-path-busy → fallback-dial path.

    Mechanism = the REAL trace-duplication path, not a synthetic blast: each
    period writes an `accord_traces.jsonl` batch of fat traces (padded context
    component) and runs `ciris_server.import_traces` — the imported trace
    events land in this agent's store and the federation-delivery controller
    seals + ships them to the canonical as resource transfers, exactly like a
    live agent duplicating a trace. Big payloads stretch each transfer so the
    canonical's 15s-cadence round replies land INSIDE one.
    """
    import datetime
    import json
    import shutil
    import tempfile
    import uuid

    import ciris_server

    batch = 0
    while not stop.is_set():
        batch += 1
        dump = pathlib.Path(tempfile.mkdtemp(prefix="busy353-"))
        try:
            pad = "b" * (pad_kb * 1024)
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            rows = []
            for i in range(3):
                rows.append(json.dumps({
                    "trace_id": f"busy353-{batch}-{i}-{uuid.uuid4().hex[:8]}",
                    "thought_id": f"busy353-thought-{batch}-{i}",
                    "started_at": now,
                    "completed_at": now,
                    "trace_level": "generic",
                    "schema_version": "1.9.3",
                    # A real component column (context → environmental_context):
                    # the pad rides INSIDE the reconstructed CEG batch, making
                    # each sealed envelope a long resource transfer.
                    "context": {"busy353_pad": pad, "batch": batch, "i": i},
                }))
            (dump / "accord_traces.jsonl").write_text("\n".join(rows) + "\n")
            ciris_server.import_traces(str(dump))
            log(f"BUSY-LINK: batch {batch} imported (3 traces × ~{pad_kb}KB pad) — "
                f"delivery seals+ships as resource transfers")
        except Exception as e:  # noqa: BLE001
            log(f"BUSY-LINK WARN: batch {batch} failed: {type(e).__name__}: {e}")
        finally:
            shutil.rmtree(dump, ignore_errors=True)
        stop.wait(period_s)


def main() -> int:
    home = pathlib.Path(os.environ.get("CIRIS_HOME", "/var/lib/ciris"))
    key_id = os.environ.get("CIRIS_KEY_ID", "ciris-agent-harness-1")
    listen = os.environ.get("CIRIS_EDGE_LISTEN_ADDR", "0.0.0.0:4242")
    raw_peers = [p.strip() for p in os.environ.get("CIRIS_EDGE_BOOTSTRAP_PEERS", "").split(",") if p.strip()]
    # init_edge_runtime parses each entry as a SocketAddr (IP:port), so resolve
    # the Docker service name (`canonical`) to its bridge IP first.
    peers = []
    for hp in raw_peers:
        host, sep, port = hp.rpartition(":")
        if not sep:
            peers.append(hp)
            continue
        try:
            peers.append(f"{socket.gethostbyname(host)}:{port}")
        except socket.gaierror:
            peers.append(hp)
    agent_mode = os.environ.get("CIRIS_AGENT_MODE", "server")
    delivery_on = os.environ.get("CIRIS_FEDERATION_DELIVERY", "true").strip().lower() not in ("0", "false", "no", "off")
    nat353 = os.environ.get("CIRIS_HARNESS_NAT353", "").strip().lower() == "true"
    nat_only = os.environ.get("CIRIS_HARNESS_NAT_ONLY", "").strip().lower() == "true"

    # CIRISEdge#353 scenario: become initiator-only BEFORE the edge binds, so the
    # very first link the canonical opens back to us is already un-dialable.
    if nat353 or nat_only:
        setup_nat_sim(listen)

    (home / "data").mkdir(parents=True, exist_ok=True)
    (home / "logs").mkdir(parents=True, exist_ok=True)
    db = home / "data" / "ciris.db"
    identity_path = str(home / "edge_identity.rid")

    # One wheel, one PyO3 type registry: import Engine and init_edge_runtime from
    # the SAME ciris_server module so the Engine handed to edge is the identical
    # registered Rust type (avoids the cross-crate "'Engine' is not an instance
    # of 'Engine'" cohabitation refusal).
    import ciris_server
    from ciris_server import Engine
    from ciris_server.edge import init_edge_runtime

    # Surface the rust-side tracing (RUST_LOG-filtered) — without this a Python
    # host process shows NO rust logs, hiding the delivery/rooting diagnostics.
    if hasattr(ciris_server, "init_tracing"):
        ciris_server.init_tracing()

    log(f"ciris_server {getattr(ciris_server, '__version__', '?')} | key_id={key_id} peers={peers} mode={agent_mode} delivery={delivery_on}")

    # The embedded-edge init needs a SOFTWARE Ed25519 (+ ML-DSA) signer, not the
    # default hardware/HSM keyring (which yields a 65-byte EC pubkey edge rejects).
    # Mirror CIRISAgent's bootstrap: two 32-byte seed files, minted on first boot.
    seed = home / "data" / "local_signing.seed"
    pqc_seed = home / "data" / "local_pqc_signing.seed"
    for s in (seed, pqc_seed):
        if not s.exists():
            s.write_bytes(os.urandom(32))
            try:
                s.chmod(0o600)
            except OSError:
                pass
    engine = Engine(
        f"sqlite:///{db}",
        key_id,
        local_key_id=key_id,
        local_key_path=str(seed),
        local_pqc_key_id=key_id,
        local_pqc_key_path=str(pqc_seed),
    )
    log("persist engine opened (software Ed25519 + ML-DSA seeds)")

    # Register THIS node's own key in its own federation directory (what the
    # real CIRISAgent's edge_runtime.py does at boot) — the consent grant
    # authored at delivery start attests AS this key, and emit_attestation_self
    # requires the attesting key to be an admitted federation_keys row.
    self_key = None
    try:
        self_key = engine.register_self_federation_key("agent", key_id)
        log(f"registered own federation key: {self_key}")
    except Exception as e:  # noqa: BLE001 — Conflict (already present) is benign
        log(f"self-key registration: {type(e).__name__}: {e} (benign if already present)")

    edge = init_edge_runtime(
        engine,
        identity_path,
        listen_addr=listen,
        bootstrap_peers=peers,
        agent_mode=agent_mode,
        enable_transport=delivery_on,
    )
    try:
        signer = edge.signer_key_id()
    except Exception:  # noqa: BLE001 — best-effort label for the log only
        signer = "?"
    log(f"embedded edge up: signer_key_id={signer} listen={listen}")

    # TEST-ANCHOR harness: the test override skips the baked canonical genesis
    # (CIRISPersist#449), so the agent admits the HARNESS canonical explicitly —
    # fetch its test-root-BLESSED directory row (`canonical,node` + dial hint,
    # scrubbed by the seeded SW holder) and register it. Admission runs the full
    # untouched gates: Strict hybrid scrub-verify against the (PQC-complete,
    # scrub-verifying) seeded holder + the m-of-n canonical add gate (1-of-1
    # over the test roster). After this, canonical_bootstrap_hints() on THIS
    # engine yields the harness canonical → delivery seeds it as a target.
    if os.environ.get("CIRIS_TESTING_MODE", "").strip().lower() == "true" and raw_peers:
        import json
        import urllib.request
        canon_host = raw_peers[0].rpartition(":")[0] or raw_peers[0]
        url = f"http://{canon_host}:4243/v1/federation/test-blessed-self-record"
        blessed = None
        for attempt in range(12):
            try:
                blessed = urllib.request.urlopen(url, timeout=5).read().decode()
                break
            except Exception as e:  # noqa: BLE001 — canonical may still be booting
                log(f"blessed-record fetch attempt {attempt + 1}: {type(e).__name__}: {e}")
                time.sleep(5)
        if blessed is None:
            log("WARN could not fetch the canonical's blessed record — delivery will seed 0 targets")
        else:
            rec = json.loads(blessed)
            try:
                engine.register_federation_key(json.dumps(rec))
                log(f"admitted harness canonical {rec['record']['key_id']} "
                    f"(identity_type={rec['record']['identity_type']})")
            except Exception as e:  # noqa: BLE001 — surface admission failures loudly
                log(f"WARN admit harness canonical failed: {type(e).__name__}: {e}")

        # And the REVERSE admission: hand OUR self record to the canonical so it
        # can ATTRIBUTE our inbound round envelopes (without a directory row the
        # source_key_id resolves to None → frame dropped pre-dispatch (#317) →
        # every round times out awaiting the reply). Stands in for the
        # owner-gated claim/peering flows of a production mesh.
        try:
            my_row = engine.lookup_public_key(self_key) if self_key else None
            if my_row:
                body = json.dumps({"record": json.loads(my_row)}).encode()
                req = urllib.request.Request(
                    f"http://{canon_host}:4243/v1/federation/test-admit-peer",
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                resp = urllib.request.urlopen(req, timeout=10).read().decode()
                log(f"registered self at canonical: {resp}")
            else:
                log("WARN own directory row not found — canonical cannot attribute our frames")
        except Exception as e:  # noqa: BLE001 — surface loudly
            log(f"WARN register self at canonical failed: {type(e).__name__}: {e}")

    if delivery_on:
        # cadence_seconds=None → default round cadence (~30s). Returns the number
        # of admitted canonical targets seeded; 0 means the agent has not yet
        # rooted/admitted the canonical (it will after the dial + announce heal).
        seeded = ciris_server.start_federation_delivery(cadence_seconds=None, announce_logger=True)
        log(f"federation delivery started: {seeded} canonical target(s) seeded")
        if seeded == 0:
            log("NOTE seeded=0 — the agent has not admitted a canonical peer yet; "
                "if it stays 0, the canonical identity the agent targets (baked genesis) "
                "differs from this harness canonical — see README §Fidelity.")

        # CIRISEdge#353 busy-link pressure: once delivery is live, keep OUR link
        # to the canonical saturated with real trace resource-transfers so the
        # canonical's round replies collide mid-transfer. Combined with the
        # NAT-sim (initiator-only), the fallback outbound dial then can't reach
        # us → the link times out (Timeout close), exactly the field signature.
        if nat353:
            import threading

            pad_kb = int(os.environ.get("CIRIS_HARNESS_NAT353_PAD_KB", "256"))
            period_s = float(os.environ.get("CIRIS_HARNESS_NAT353_PERIOD_S", "4"))
            stop353 = threading.Event()
            threading.Thread(
                target=busy_link_generator,
                args=(stop353, pad_kb, period_s),
                name="busy-link-353",
                daemon=True,
            ).start()
            log(f"NAT353: busy-link generator running (pad={pad_kb}KB, every {period_s}s) "
                f"— reproducing the reverse-path-busy → fallback-dial → Timeout path")

    # ── CIRISServer#260 trace gate (intermediate assert) ─────────────────────
    # Rounds completing is NECESSARY but not SUFFICIENT for trace delivery: the
    # sealed-envelope path additionally needs resolve_peer_kex_pubkeys(canonical)
    # = Some (the canonical's self-occurrence encryption_pubkeys must have
    # replicated INTO this agent's store via the IdentityOccurrence round). Poll
    # it and, to disambiguate #260's candidates, also dump what occurrence rows
    # this agent actually holds for the canonical.
    canon_key = None
    try:
        import json as _j
        canon = _j.loads(engine.list_canonical_servers() or "[]")
        canon_key = canon[0]["key_id"] if canon else None
    except Exception as e:  # noqa: BLE001
        log(f"KEX-GATE: list_canonical_servers failed: {e}")
    if canon_key and delivery_on:
        deadline, waited = 420, 0
        while waited < deadline:
            time.sleep(15)
            waited += 15
            try:
                kex = edge.resolve_peer_kex_pubkeys(canon_key)
            except Exception as e:  # noqa: BLE001
                kex = None
                log(f"KEX-GATE: resolve error: {type(e).__name__}: {e}")
            if kex:
                log(f"KEX-GATE: resolve_peer_kex_pubkeys({canon_key}) = PRESENT after {waited}s "
                    f"— sealed-envelope path UNBLOCKED (trace gate would PASS)")
                break
            if waited % 60 == 0:
                # Disambiguate: does this agent hold ANY occurrence row for the
                # canonical (round carried it but resolve fails), or none (the
                # round never carried the canonical's self-occurrence)?
                row = None
                for meth in ("lookup_identity_for_occurrence", "get_identity_occurrence"):
                    try:
                        row = getattr(engine, meth)(canon_key)
                        break
                    except AttributeError:
                        continue
                    except Exception as e:  # noqa: BLE001
                        row = f"<{type(e).__name__}: {e}>"
                        break
                log(f"KEX-GATE: still None at {waited}s — occurrence row at agent for "
                    f"{canon_key}: {'PRESENT' if isinstance(row, str) and row.startswith('{') else row!r}")
        else:
            log(f"KEX-GATE VERDICT: resolve_peer_kex_pubkeys({canon_key}) = None after {deadline}s "
                f"with rounds completing — #260 REPRODUCED locally (sealed envelopes blocked)")

    # ── EMBEDDED-FOLD variant (CIRISServer#264 must-have 2) ──────────────────
    # The topology run_configured.sh structurally cannot reproduce: a LIVE
    # in-process Engine + Edge (their tokio runtime active) and THEN
    # serve_with_python_adapter on the same process — the agent-embedded shape
    # where the `Cannot start a runtime from within a runtime` reentrancy panic
    # fired on every mobile boot. With the #264 rt_block_on thread-hop shield
    # the fold must BIND 4243; without it, this reproduces the panic (now a
    # loud RuntimeError with file:line + backtrace, never silence).
    if os.environ.get("CIRIS_HARNESS_EMBEDDED_FOLD", "").strip().lower() == "true":
        import threading
        import urllib.request as _rq

        class _StubAdapter:
            adapter_type = "harness-embedded"
            enabled = True

        home2 = str(home / "foldnode")

        def _fold() -> None:
            try:
                log("EMBEDDED-FOLD: invoking serve_with_python_adapter on the LIVE engine/edge process")
                ciris_server.serve_with_python_adapter(_StubAdapter(), home2, key_id)
            except BaseException as e:  # noqa: BLE001 — catch PanicException too (it derives BaseException)
                log(f"EMBEDDED-FOLD FAILED: {type(e).__name__}: {e}")

        threading.Thread(target=_fold, name="harness-embedded-fold", daemon=True).start()
        bound = False
        for waited in range(0, 120, 5):
            time.sleep(5)
            try:
                _rq.urlopen("http://127.0.0.1:4243/health", timeout=3)
                bound = True
                log(f"EMBEDDED-FOLD: read-API BOUND on 4243 after ~{waited + 5}s — reentrancy shield holds")
                break
            except Exception:  # noqa: BLE001
                continue
        if not bound:
            log("EMBEDDED-FOLD VERDICT: 4243 did NOT bind in 120s — #264 embedded-topology REPRO")

    # ── Lifecycle probe (run_lifecycle.sh, FSD/RNS_LIFECYCLE_STATES.md) ──────
    # Print the L3/L5 delivery state as a grep-able [DELIVERY-STATUS] line each
    # poll, so the lifecycle conformance gate asserts states (advisory→rooted→
    # kex→deliverable) from log lines instead of inferring them from absence.
    lifecycle = os.environ.get("CIRIS_HARNESS_LIFECYCLE", "").strip().lower() == "true"
    if lifecycle and not hasattr(ciris_server, "delivery_status"):
        log("LIFECYCLE: wheel has no delivery_status() (needs >=0.5.125) — probe disabled")
        lifecycle = False

    log("running — federation delivery drives rounds on its own cadence; watch both logs")
    while True:
        time.sleep(10)
        if lifecycle:
            try:
                log(f"[DELIVERY-STATUS] {ciris_server.delivery_status()}")
            except Exception as e:  # noqa: BLE001
                log(f"[DELIVERY-STATUS] probe error: {type(e).__name__}: {e}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 — surface any boot failure loudly to docker logs
        log(f"FATAL {type(e).__name__}: {e}")
        raise
