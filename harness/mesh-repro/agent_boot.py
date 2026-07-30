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


def emit_synthetic_traces(engine, key_id: str, n: int) -> None:
    """Seal `n` synthetic reasoning traces through the REAL trace pipeline
    (ciris_server.LensClient → seal on ACTION_RESULT → receive_and_persist).

    Component payloads mirror the shapes the CIRISAgent accord adapter emits
    on-device (2026-07-24 fold DB), INCLUDING the flat summary aliases
    (CIRISAgent 577e2bb39/dfea44cd3) that persist's trace-summary projection
    extracts — so the sealed rows carry non-NULL essential feature dims and
    the scorer's feature matrix is populated wherever these traces land.
    Every capture outcome is logged verbatim: a consent_blocked / rejected /
    error outcome is a visible next step, never a silent stall.
    """
    import datetime
    import hashlib

    import ciris_server

    agent_id_hash = hashlib.sha256(key_id.encode()).hexdigest()[:16]
    now = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()  # noqa: E731

    try:
        client = ciris_server.LensClient(
            now(),                      # consent timestamp (harness consent)
            "generic",                  # the lowest tier every deployment ships
            engine=engine,
            deployment_profile={
                # v20 typed EnvelopeCore sources these from the PROFILE dict
                # (not the ctor kwargs). EXACT key set of the CIRISAgent
                # adapter's _build_deployment_profile — the wire batch schema
                # requires each of these fields present.
                "agent_role": "mesh-repro",
                "agent_template": "mesh-repro-harness",
                "deployment_domain": "general",
                "deployment_type": "production",
                "deployment_region": None,
                "deployment_trust_mode": "sovereign",
            },
            consent_attesting_key_id=key_id,
            # v20 typed EnvelopeCore: agent_template/role/type are REQUIRED
            # envelope fields (the 0.5.138 run failed ingest with
            # schema_malformed_json: missing field `agent_template`). Mirror
            # the kwargs the CIRISAgent accord adapter passes.
            deployment_type="harness",
            agent_role="mesh-repro",
            agent_template="mesh-repro-harness",
        )
    except Exception as e:  # noqa: BLE001
        log(f"TRACEFLOW: LensClient construction FAILED: {type(e).__name__}: {e}")
        return

    sealed = 0
    for i in range(n):
        tid = f"th_harness_{i:03d}"
        components = [
            ("THOUGHT_START", {"thought_type": "seed", "thought_depth": 1, "round_number": i, "task_priority": 0}),
            ("DMA_RESULTS", {
                "csdma": {"plausibility_score": 0.9}, "dsdma": {"domain_alignment": 0.8, "domain": "harness"},
                "pdma": {"has_conflicts": False},
                "csdma_plausibility_score": 0.9, "dsdma_domain_alignment": 0.8, "dsdma_domain": "harness",
            }),
            ("IDMA_RESULT", {
                "k_eff": 2.0, "correlation_risk": 0.3, "fragility_flag": False, "phase": "healthy",
                "idma_k_eff": 2.0, "idma_correlation_risk": 0.3, "idma_fragility_flag": False, "idma_phase": "healthy",
            }),
            ("CONSCIENCE_RESULT", {
                "conscience_passed": True, "action_was_overridden": False,
                "entropy_passed": True, "coherence_passed": True,
                "optimization_veto_passed": True, "epistemic_humility_passed": True,
            }),
            ("ACTION_RESULT", {
                "execution_success": True, "success": True, "action_executed": "speak",
                "execution_time_ms": 12.5, "tokens_total": 100, "llm_calls": 1,
                "has_execution_error": False, "has_positive_moment": False,
            }),
        ]
        for ev_type, data in components:
            comp = {
                "event_type": ev_type,
                "thought_id": tid,
                "timestamp": now(),
                "agent_id_hash": agent_id_hash,
                "task_id": f"task_harness_{i:03d}",
                "data": data,
            }
            try:
                out = client.capture_event(comp)
            except Exception as e:  # noqa: BLE001
                log(f"TRACEFLOW: capture_event({ev_type}) ERROR: {type(e).__name__}: {e}")
                out = None
                break
            if ev_type == "ACTION_RESULT":
                log(f"TRACEFLOW: trace {tid} terminal outcome: {out}")
                if isinstance(out, dict) and out.get("outcome") == "sealed_and_persisted":
                    sealed += 1
    log(f"TRACEFLOW: SEALED {sealed}/{n} synthetic traces on the agent node "
        f"(agent_id_hash={agent_id_hash}) — watch the canonical for arrival + scoring")


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
    except Exception as e:  # noqa: BLE001
        # HARD FAIL — never silently degrade. A NAT-sim that can't install the
        # DROP rule is a NAT run that isn't NAT'd; letting it continue produces a
        # false "field topology" verdict (this masked the repro for many runs:
        # iptables was absent from the slim image, so every NAT-sim no-op'd while
        # claiming initiator-only). Crash loudly so the run is unmistakably wrong.
        detail = getattr(e, "stderr", "") or ""
        log(f"NAT-SIM FATAL: iptables DROP install failed ({type(e).__name__}: {e}) {detail} "
            f"— refusing to run a NAT scenario without NAT (install iptables in the image)")
        raise SystemExit(3)
    # Verify the rule is actually in the table — belt-and-suspenders against a
    # silent accept (some sandboxes accept the command but no-op the filter).
    check = subprocess.run(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", port,
                            "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"],
                           capture_output=True, text=True)
    if check.returncode != 0:
        log(f"NAT-SIM FATAL: DROP rule not present after install (verify rc={check.returncode}) "
            f"— NAT is not actually engaged")
        raise SystemExit(3)
    log(f"NAT-SIM: NEW inbound tcp/{port} DROP installed + VERIFIED — this agent is "
        f"initiator-only (dial-back can never connect; #353 topology)")


def setup_netem(loss_pct: float, delay_ms: int, jitter_ms: int) -> None:
    """Lossy-link sim: apply `tc netem` to the agent's default-route interface so
    the reverse-path IdentityOccurrence round runs over a link with real packet
    loss + latency — the field's NAT'd mobile link, which a zero-loss Docker
    bridge cannot express. netem is EGRESS (agent→canonical); on RNS that starves
    the round symmetrically — the agent's link keepalives/acks/round-request
    packets drop, so the canonical's reply can't ride a link the agent can no
    longer keep alive, reproducing the field kex-none.

    Hard-fails (SystemExit 3) if tc is missing or the qdisc doesn't verify — same
    no-silent-degrade contract as the NAT-sim: a loss run that isn't lossy is a
    false verdict.
    """
    import re
    import subprocess

    # Default-route interface (docker usually eth0, but detect it, don't assume).
    try:
        route = subprocess.run(["ip", "route", "get", "1.1.1.1"],
                               check=True, capture_output=True, text=True).stdout
        m = re.search(r"\bdev\s+(\S+)", route)
        iface = m.group(1) if m else "eth0"
    except Exception as e:  # noqa: BLE001
        log(f"NETEM FATAL: could not resolve default iface ({type(e).__name__}: {e})")
        raise SystemExit(3)

    netem = ["tc", "qdisc", "add", "dev", iface, "root", "netem"]
    if loss_pct > 0:
        netem += ["loss", f"{loss_pct:g}%"]
    if delay_ms > 0:
        netem += ["delay", f"{delay_ms}ms"] + ([f"{jitter_ms}ms"] if jitter_ms > 0 else [])
    try:
        subprocess.run(netem, check=True, capture_output=True, text=True)
    except Exception as e:  # noqa: BLE001
        detail = getattr(e, "stderr", "") or ""
        log(f"NETEM FATAL: tc qdisc install failed on {iface} ({type(e).__name__}: {e}) {detail} "
            f"— refusing to run a lossy-link scenario without loss (install iproute2)")
        raise SystemExit(3)
    # Verify the qdisc is actually there.
    show = subprocess.run(["tc", "qdisc", "show", "dev", iface],
                          capture_output=True, text=True).stdout
    if "netem" not in show:
        log(f"NETEM FATAL: netem qdisc not present after install on {iface} "
            f"(show={show!r}) — loss is not actually engaged")
        raise SystemExit(3)
    log(f"NETEM: {iface} loss={loss_pct:g}% delay={delay_ms}ms jitter={jitter_ms}ms "
        f"installed + VERIFIED — reverse-path round now runs over a lossy link")


def nat_rebind_loop(stop, period_s: float, blackout_s: float, canon_ip: str) -> None:
    """Mobile NAT-rebind sim — the field's link-storm cause.

    A real cellular/NAT mapping for the agent's OUTBOUND link to the canonical
    expires every ~45-60s; when it rebinds, the established connection's packets
    are silently dropped, RNS sees the link die (stale/keepalive-timeout), tears
    it down and re-dials — a NEW link. Repeat = the field's ~20-links/min storm,
    and every in-flight multi-round-trip IdentityOccurrence exchange is cut off
    mid-round, so KEX never completes. This is what plain loss (retransmit on the
    SAME link) cannot reproduce.

    Mechanism: every `period_s`, insert an iptables rule that DROPs all traffic
    to/from the canonical IP for `blackout_s` (longer than a keepalive retransmit
    so the link is declared dead), then remove it → RNS re-dials → new link. Uses
    iptables (already installed); no new dependency.
    """
    import subprocess

    def rule(action):  # -A add / -D delete
        for chain, io in (("OUTPUT", "-d"), ("INPUT", "-s")):
            subprocess.run(["iptables", action, chain, io, canon_ip, "-j", "DROP"],
                           capture_output=True, text=True)

    n = 0
    while not stop.wait(period_s):
        n += 1
        rule("-A")
        log(f"NAT-REBIND: blackout #{n} — dropping canonical {canon_ip} for {blackout_s}s "
            f"(mapping expiry → link dies → re-dial; models the field link storm)")
        stop.wait(blackout_s)
        rule("-D")


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

    # Lossy-link sim (applied BEFORE the edge binds so the very first handshake
    # already runs over loss). netem_loss/delay model the field's NAT'd mobile
    # link — the last variable a zero-loss bridge can't express.
    netem_loss = float(os.environ.get("CIRIS_HARNESS_NETEM_LOSS", "0") or "0")
    netem_delay = int(os.environ.get("CIRIS_HARNESS_NETEM_DELAY", "0") or "0")
    netem_jitter = int(os.environ.get("CIRIS_HARNESS_NETEM_JITTER", "0") or "0")
    if netem_loss > 0 or netem_delay > 0:
        setup_netem(netem_loss, netem_delay, netem_jitter)

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

    # Mobile NAT-rebind sim (the field link-storm cause): periodically black out
    # the canonical so the established link dies + re-dials. Requires the canonical
    # IP (resolved into `peers`) + NET_ADMIN (field/353 overlay). 0 = off.
    rebind_secs = float(os.environ.get("CIRIS_HARNESS_NAT_REBIND_SECS", "0") or "0")
    if rebind_secs > 0 and peers:
        import threading

        canon_ip = peers[0].rpartition(":")[0]
        blackout_s = float(os.environ.get("CIRIS_HARNESS_NAT_REBIND_BLACKOUT_S", "5"))
        stop_rebind = threading.Event()
        threading.Thread(
            target=nat_rebind_loop,
            args=(stop_rebind, rebind_secs, blackout_s, canon_ip),
            name="nat-rebind",
            daemon=True,
        ).start()
        log(f"NAT-REBIND: loop running (every {rebind_secs}s, {blackout_s}s blackout of "
            f"{canon_ip}) — models mobile NAT mapping expiry → the field link storm")

    # ── EXPLICIT CONSENT (runbook §1): consent is no longer auto-authored ────
    # Production wizards POST /v1/federation/consent (owner-gated HTTP). The
    # bare harness boot has no serve stack/owner session, so it uses the
    # TESTING-MODE-fenced author_federation_consent (refused outside
    # CIRIS_TESTING_MODE). Without this grant the canonical never becomes a
    # consent peer and traces cannot replicate — the runbook's §3 failure mode.
    n_traces = int(os.environ.get("CIRIS_HARNESS_EMIT_TRACES", "0") or "0")
    if n_traces > 0 and delivery_on:
        author = getattr(ciris_server, "author_federation_consent", None)
        if author is None:
            log("CONSENT: wheel has no author_federation_consent — traces will NOT replicate")
        else:
            import json as _cj
            canon_for_consent = None
            for attempt in range(6):
                try:
                    canon = _cj.loads(engine.list_canonical_servers() or "[]")
                    canon_for_consent = canon[0]["key_id"] if canon else None
                except Exception as e:  # noqa: BLE001
                    log(f"CONSENT: list_canonical_servers failed: {e}")
                if canon_for_consent:
                    try:
                        gid = author(canon_for_consent, ["trace:", "capacity:"])
                        log(f"CONSENT: consent:replication authored for {canon_for_consent} "
                            f"(attestation_id={gid}) scope=trace:,capacity:")
                        # #530 caveat 1: the bare embedded path may not run the
                        # server reconcile that auto-fires the repair sweep —
                        # invoke it directly (strictly widening; pure placement).
                        rep = getattr(engine, "repair_stranded_scope_backlog", None)
                        if rep is not None:
                            try:
                                fixed = rep()
                                log(f"CONSENT: repair_stranded_scope_backlog -> {fixed}")
                            except Exception as e:  # noqa: BLE001
                                log(f"CONSENT: repair sweep failed (non-fatal): {type(e).__name__}: {e}")
                        break
                    except Exception as e:  # noqa: BLE001
                        log(f"CONSENT: author attempt {attempt + 1} failed: {type(e).__name__}: {e}")
                time.sleep(10)
            else:
                log("CONSENT: FAILED to author after 6 attempts — traces will NOT replicate")

    # ── TRACEFLOW E2E (CIRISServer#315 endgame / the gate-#922 carrier) ──────
    # Seal REAL traces on the agent node through the exact pipeline the mobile
    # brain uses (LensClient.capture_event → seal on ACTION_RESULT →
    # Engine::receive_and_persist), then let the harness watch whether ANY
    # plane carries them to the canonical — and whether the CANONICAL's scorer
    # (a distinct sovereign identity, so CEG §7.5 anti-Goodhart PASSES there)
    # authors a capacity attestation about this agent. This is the local
    # 100%-confidence answer to "what must the next cut carry for the first
    # mobile trace to land at Node A".
    n_traces = int(os.environ.get("CIRIS_HARNESS_EMIT_TRACES", "0") or "0")
    if n_traces > 0:
        emit_synthetic_traces(engine, key_id, n_traces)

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
                # Emit delivery_status DURING the stuck gate so round_diagnostics
                # (send-failure classes + the differential hint) is observable
                # exactly when KEX is failing — the whole point of the accessor.
                if hasattr(ciris_server, "delivery_status"):
                    try:
                        log(f"[DELIVERY-STATUS] {ciris_server.delivery_status()}")
                    except Exception as e:  # noqa: BLE001
                        log(f"[DELIVERY-STATUS] probe error: {type(e).__name__}: {e}")
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
