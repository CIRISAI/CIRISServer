# FSD: lens-core v0.5 — capture-locally, filter-on-egress, key-addressed

**Status:** Locked
**Target version:** v0.5.0
**Created:** 2026-05-15
**Closes:** CIRISLensCore#7 (Edge integration), #8 (accord_metrics adapter replacement)
**Drives:** CIRISAgent's accord_metrics adapter retirement; PoB §3.1 fold-into-agent prep
**Risk:** Architectural. v0.5 elevates lens-core from a science-layer crate the deployed lens consumes to the **agent's bidirectional wire-contract substrate**. Three role expansions: audit-service replacement, local trace store, filter-on-egress forwarder. Substrate-side risk is low (persist v0.9.1 + edge v0.1.4 already expose everything we compose against); contract-side risk is the AuditService API surface CIRISAgent has been using for years, which lens-core now owns.

---

## 1. Mission alignment

Per `MISSION.md` §1: lens-core is *"what makes signed traces measurable."* v0.5 broadens that to *"what makes signed traces measurable, durable, and forwardable under per-recipient privacy policy."*

The Accord's M-1 (sustainable adaptive coherence; diverse sentient beings; flourishing under justice and wonder) reads on three v0.5 design choices:

1. **Agent always has its complete audit trail locally.** If federation is offline, audit doesn't lose data. Sovereign-mode deployments + low-bandwidth deployments + adversary-controlled-network deployments all keep behavioral history; the federation's view becomes a *filtered projection* of that trail, not the trail itself.
2. **Lens identity is the agent's federation public key, not its hostname.** DNS isn't in the trust path. Reticulum / LoRa / I²P drop in as alternative transports without any lens-core code change because the address space is key-based.
3. **Privacy is per-recipient policy, not per-emission choice.** The agent captures FULL_TRACES locally always; egress is filtered down to GENERIC / DETAILED / FULL_TRACES per the destination lens's trust posture + the agent operator's policy. One emission point, N forwarding decisions.

This is what the Accord's "diverse sentient beings may pursue their own flourishing" requires of the substrate: a way for the agent to remember everything it did *and* a way to share that selectively with peers chosen by identity, not infrastructure.

---

## 2. Architectural reframe

### 2.1 The shift in one sentence

> v0.1.1 — lens-core is what the agent emits *through to* the network *to reach* a lens.
> v0.5    — lens-core is the substrate the agent emits *to*; the network reach is filtered policy on top of a local audit trail.

### 2.2 What changes

| Concern | v0.1.1 | v0.5 |
|---|---|---|
| Trace capture | Agent's `ciris_adapters/ciris_accord_metrics` Python adapter emits inline at the configured trace_level. Nothing kept locally. | Lens-core captures **FULL_TRACES** locally, always. trace_level becomes a per-recipient egress policy, not a capture policy. |
| Audit log | Agent's in-process `AuditService` (legacy Python); persist v0.8.1 absorbed the *storage* substrate but the agent-facing API still lives in Python. | Lens-core *is* the agent's AuditService — single emission point. Persist's hash-chained audit log (v0.8.1) is the storage backend lens-core composes against. The agent's Python `AuditService` becomes a thin shim over `lens.audit.*`. |
| Storage retention | None (agent has no local store). | Lens-core manages eviction per a storage-budget policy (size + age). Pi-class might keep 24h; production 90d; sovereign-anchor indefinitely. |
| Forwarding | Direct HTTP POST to a hostname (`lens.ciris.ai`). Single recipient per trace. | Filter local-FULL → remote-required trace_level; address by `destination_lens_steward_key_id`; **multi-recipient per trace** (different filters per upstream); transport-agnostic via Edge. |
| Identity / discovery | Hostname-bound. Key rotation = DNS change. Spoofable by anyone with DNS control. | Key-bound. Key rotation = persist's `federation_keys` directory update + `peer_urls` config refresh. Signature-verifiable, not DNS-trusted. |
| Wire contract | Hand-rolled Python serializers in the adapter; drifts from persist's canonical Rust types (incident log: every wire-contract bug this past week sat here). | Frozen public ABI in `ciris-lens-core` Rust types. Adding fields = minor version. Renaming or removing = major version. Drift = compile error at the agent, not a 22h production diagnostic cycle. |

### 2.3 Why this is right

Three independent benefits compound:

**Audit posture.** The agent always has its complete trail. Today, if the lens endpoint is unreachable for an hour, the agent's in-flight queue evaporates with the process. v0.5 captures FULL_TRACES to local persist immediately; forwarding is a separate operation against the durable store. Federation outages don't lose audit data.

**Sovereign + mesh feasibility.** Key-addressed routing through Edge's transport abstraction means agents discover and route to lenses without DNS. Pi-class on a LAN, sovereign-mode on Reticulum, edge deployments on I²P — same lens-core code, different transport plug-in.

**Privacy clarity.** Today's `trace_level` decision is forced at emit time, before the agent knows which lens(es) it will share with. v0.5 inverts: capture FULL locally (the operator can audit their own agent), forward GENERIC to the federation anchor (the federation needs cohort routing + manifold conformity, not raw text), DETAILED to a sovereign-mode peer in the trust circle (cross-verification without revealing user prompts to the broader federation). One operator policy doc, N recipient relationships.

---

## 3. Three modes — client / relay / node

v0.5 ships one binary that takes a Mode at construction time. Modes are not flag-toggled feature gates; they're runtime postures the same code adopts:

```rust
pub enum Mode {
    /// Agent-side: emits OWN traces, captures locally, forwards to N upstreams.
    /// No inbound accept.
    Client {
        upstream: Vec<UpstreamLens>,
        retention: RetentionPolicy,
    },

    /// Relay: accepts inbound from peers + forwards upstream. Plus client behavior
    /// if the deployment ALSO emits its own traces.
    Relay {
        listen_addr: SocketAddr,
        peer_acl: PeerAcl,
        upstream: Vec<UpstreamLens>,
        retention: RetentionPolicy,
        client_emit: Option<Vec<UpstreamLens>>,  // None = pure relay
    },

    /// Node: relay behavior + UX endpoints (HTTP API + read views).
    /// Federation-anchor deployments (safety.ciris.ai-class).
    Node {
        listen_addr: SocketAddr,
        peer_acl: PeerAcl,
        upstream: Vec<UpstreamLens>,
        retention: RetentionPolicy,
        scoring_config: ScoringConfig,
        ux_endpoints: UxConfig,
    },
}

pub struct UpstreamLens {
    /// Destination lens identity — not a hostname. Edge resolves to transport.
    pub lens_steward_key_id: String,

    /// What gets filtered out before forwarding to this upstream.
    pub egress_filter: EgressFilter,
}

pub struct EgressFilter {
    pub trace_level: TraceLevel,           // GENERIC | DETAILED | FULL_TRACES
    pub min_severity: Option<Severity>,    // None = forward all; Some(Warning) = drop info
    pub include_detection_events: bool,    // signed detector firings
    pub include_scores: bool,              // manifold-conformity output
    pub redact_user_prompts: bool,         // even at DETAILED, scrub user text
    pub redact_completions: bool,          // even at DETAILED, scrub LLM responses
}
```

### 3.1 Deployment matrix

| Deployment | Mode | Typical config |
|---|---|---|
| Default CIRISAgent | Client | upstream = `[lens.ciris.ai (GENERIC)]`; retention = 30 days |
| Sovereign-mode agent | Client | upstream = `[sovereign_anchor_key_id (FULL_TRACES)]`; retention = unbounded |
| Pi-class agent | Client | upstream = `[lens.ciris.ai (GENERIC)]`; retention = 24h on 8GB disk |
| Federation-bridge | Relay | listen on mesh peer port; upstream = `[lens.ciris.ai (GENERIC)]`; relays for a cluster of agents |
| safety.ciris.ai | Node | listen on federation entry; upstream = peer anchors; serves scoring UX |
| Community lens viewer | Node (read-only) | listen on community port; serves wire-format-frozen score API |

Same binary. Same code-paths through the Rust surface. Different `Mode` enum variant at construction.

---

## 4. Substrate composition

The single most important architectural claim of v0.5: **lens-core writes ~zero substrate code.** Every primitive lens-core needs is in persist v0.9.1 or edge v0.1.4. Lens-core is policy + glue + the agent-facing API surface.

### 4.1 Audit substrate (persist v0.8.1+)

Persist's `audit::*` module — hash-chained audit log absorbed in v0.8.1 — is the storage backend. Lens-core's `audit` PyO3 surface delegates per method:

```rust
// lens-core internal
impl AuditApi<'_> {
    pub async fn log_action(&self, action: AuditedAction) -> Result<AuditEntryId> {
        // canonicalize + sign via engine.steward_signer
        // append to engine.audit_log (hash-chained)
        // forward (filtered) to upstream lenses per egress policy
        self.engine.audit_append(action).await
    }

    pub async fn log_consent_event(&self, evt: ConsentEvent) -> Result<AuditEntryId>;
    pub async fn log_wbd(&self, wbd: WisdomBasedDeferral) -> Result<AuditEntryId>;
    pub async fn log_identity_change(&self, change: IdentityChange) -> Result<AuditEntryId>;
}
```

Lens-core owns: the *typed action vocabulary* + the *forwarding policy*.
Persist owns: hash chain, storage, query, verification.

### 4.2 Trace-events storage (persist's ingest pipeline)

Persist's `ingest::IngestPipeline` is the existing wire-to-storage boundary. v0.7.4 closed `extract` wiring into `receive_and_persist`; v0.6.0 added `scrub` + `classify` + `extract` modules. Lens-core's `capture` PyO3 surface composes:

```rust
impl CaptureApi<'_> {
    pub async fn event(&self, component: TraceComponent) -> Result<()> {
        // append to in-memory partial trace
        // if component_type == ACTION_RESULT: complete + persist via engine.receive_and_persist
        self.partial_traces.append(component)?;
        if component.is_terminal() {
            self.complete_and_persist().await
        } else {
            Ok(())
        }
    }

    pub async fn complete_and_persist(&self) -> Result<()> {
        let complete = self.partial_traces.seal()?;
        let envelope = self.engine.canonicalize_envelope_for_signing(complete)?;
        let signed = self.engine.steward_sign_envelope(envelope).await?;

        // Local: full-trace capture (always FULL_TRACES at the receive boundary)
        self.engine.receive_and_persist(signed.clone()).await?;

        // Egress: per-upstream filter + forward (durable queue)
        for upstream in &self.config.upstream {
            let filtered = self.egress_filter.apply(&signed, &upstream.egress_filter)?;
            self.engine.edge_outbound_queue_enqueue(
                upstream.lens_steward_key_id.clone(),
                filtered,
            ).await?;
        }
        Ok(())
    }
}
```

Lens-core owns: per-upstream egress filtering, the multi-recipient fan-out.
Persist owns: ingest, canonicalization, scrub/classify/extract, storage, durable outbound queue.

### 4.3 Pipeline modules (persist's scrub + classify + extract)

Persist v0.6.0+ ships `pipeline::scrub` (regex + NER) + `pipeline::classify` (5-dimension taxonomy) + `pipeline::extract` (typed Features). v0.5 lens-core uses these primitives **twice**:

1. **Inbound (relay + node mode)**: persist's `receive_and_persist` already invokes the pipeline. Lens-core doesn't re-invoke; it inherits.
2. **Outbound egress filtering**: for each upstream, lens-core applies the upstream's `EgressFilter` to a copy of the canonical envelope before durable-enqueue. The filter calls `persist::pipeline::scrub::scrub_trace(envelope, target_trace_level)` directly — exact same code path persist runs at ingest.

Net: trace_level downsampling is done by persist's own scrubber on the egress side. **No second scrubber implementation.** Federation single-source-of-truth for redaction discipline.

### 4.4 Edge transport

Edge v0.1.4 exposes:
- `Edge::register_handler<M, H>` for typed inbound dispatch
- `EdgeBuilder` with `directory`, `queue`, `signer`, `transport` slots
- `HttpTransport` today; `Transport` trait for Phase 3 (Reticulum / LoRa / I²P)
- `Edge::send_durable(destination_key_id, message)` for outbound through persist's `edge_outbound_queue`

Lens-core constructs an `Edge` instance per mode:

- **Client mode**: Edge with no inbound listener; only `send_durable` for forwarding
- **Relay mode**: Edge with `HttpTransport` (or Reticulum) listener; registers `LensCoreHandler` for `AccordEventsBatch`
- **Node mode**: Edge listener + UX axum app on the same port (different routes), share the listener socket

Lens-core *never* implements transport. Phase 3 = Edge releases Reticulum-backed `Transport`; lens-core picks it up as a config string.

### 4.5 What lens-core actually owns

The new code in v0.5:

| Module | LOC est | What it does |
|---|---|---|
| `src/role/{client,relay,node}.rs` | ~400 | Mode-specific construction + lifecycle |
| `src/audit/api.rs` | ~250 | Typed action vocabulary; delegates storage to persist |
| `src/capture/partial.rs` | ~200 | In-memory partial-trace assembly; component-stream to complete-trace state machine |
| `src/egress/filter.rs` | ~300 | EgressFilter logic; calls `persist::pipeline::scrub` for trace_level downsampling |
| `src/egress/fanout.rs` | ~150 | Per-upstream copy + durable-enqueue |
| `src/retention/policy.rs` | ~250 | Disk-budget + time-budget eviction; calls `engine.delete_traces_older_than()` (persist ask if new) |
| `src/wire/contract.rs` | ~350 | Public ABI: CompleteTrace, BatchEnvelope, BatchEvent, TraceComponent, Ed25519TraceSigner, TraceDetailLevel as `pub` Rust types + PyO3 classes |
| `src/ffi/pyo3.rs` (expansion) | ~600 (was 326) | `LensCore.client/relay/node`, `.audit.*`, `.capture.*`, `.scores.*`, `.alerts.*`, retention APIs |
| `src/scores/lookup.rs` | ~150 | Agent-side read path: `get_for_trace`, `get_for_agent_window`, score-aggregate queries via persist's detection_events table |
| `src/alerts/subscription.rs` | ~200 | Alert delivery — in-process callback for embedded mode, persist pub/sub for distributed; typed alert payloads |
| `src/detector/{cohort_mismatch,manifold_outlier,unconsented_external_probe}.rs` | ~400 | Real detector impls landing alongside RATCHET calibration; UnconsentedExternalProbe is RATCHET's Counter-RII contribution, gated on consent-role primitives upstream |

Total v0.5 net-new code: ~3,250 LOC on top of v0.1.1's 2,498. Final footprint ~5,750 LOC, of which roughly 55% is the PyO3 surface (mostly straight delegation) + 30% is policy logic (egress filtering, retention, role construction) + 15% is the detector implementations gated on RATCHET calibration. Substrate composition; not substrate writing.

### 4.6 The agent's self-awareness loop

A v0.5 invariant worth stating explicitly: **the agent never computes its own scores.** All scoring originates in lens-core. The agent emits via `lens.capture.event(...)`; lens-core scores; the agent reads back via `lens.scores.*` and subscribes to alerts via `lens.alerts.subscribe(...)`.

```text
Agent emits ──────► LensCore ──────► Scoring engine ──────► persist::derived (signed)
                                          │
                                          ├──► alerts ────► agent (callback / pub-sub)
                                          │
                                          └──► forwarding (filtered per upstream)

Agent reads ◄─────── LensCore.scores ◄─────── persist::derived (Engine.get_detection_events)
```

This closes the loop. The agent doesn't reimplement manifold-conformity math; the agent doesn't carry detector code; the agent doesn't second-guess RATCHET calibration. Single source of scoring truth = lens-core. Agent's behavior-adjustment code reads `lens.scores.get_for_trace(trace_id)` after its decisions and reacts to alerts.

This is what enables the agent-fold (PoB §3.1): when lens-core folds into the agent, the score-and-react loop becomes intra-process Rust function calls, not an external service call. Same code path; tighter coupling.

### 4.7 Detector catalog (v0.5)

Lens-core ships detector implementations as separate modules under `src/detector/`. Each lands when RATCHET's calibration is ready and the upstream substrate dependencies close.

| Detector | RATCHET spec | What it detects | Lens-core dependencies (upstream) |
|---|---|---|---|
| `cohort_declared_inferred_mismatch` | CIRISLensCore THREAT_MODEL.md LC-AV-2 | Declared 6-tuple cohort ≠ inferred cohort from features. P0 in lens-core's threat model. | RATCHET calibration bundle (CIRISLensCore#3 closure) |
| `manifold_conformity_outlier` | RATCHET CCA paper §F + CRC paper | Trace's 16-feature projection ≥ N σ from cohort centroid. The primary numeric scoring path. | RATCHET calibration bundle |
| `unconsented_external_probe` | RATCHET `FSD/COUNTER_RII_DETECTION.md` | RII-shaped (Recursive Instance Inspection) activity originating outside the agent's consent and audit perimeter. The lens-core piece of a four-layer defense (silicon / wire / trace / federation). | (1) Accord §RC `consent_role` primitive (CIRISAgent — OQ-1, OQ-2, OQ-3 open); (2) `consent_role` schema in `federation_keys` (CIRISPersist ask); (3) `edge_detection_events` table (CIRISPersist ask); (4) `ProbePatternObserver` module (CIRISEdge ask); (5) joint correlation with edge's detection event for the same `signing_key_id` |

**The five existing CCA paper §F ratchet detectors** (cross-agent divergence, intra-agent stability, hash-chain integrity, temporal drift, conscience-override pattern) are aspirational v0.6+ work — v0.5 ships the three above and the framework that lets §F detectors land as additional `src/detector/<name>.rs` modules.

**Why UnconsentedExternalProbe is structurally distinct from the manifold detector:** Manifold-conformity is *content-anomaly* on the agent's own reasoning trace. UnconsentedExternalProbe is *induced-response anomaly* — comparing the agent's response to an inbound probe against the consent posture of the probe's sender. The lens-core detector uses the same 16-feature projection but joins it to edge's `ProbePatternObserver` signal for the same `signing_key_id` over the same window. RATCHET's spec names the specific induced-response markers: elevated `idma_correlation_risk`, depressed `idma_k_eff`, flipping `idma_phase`, displacement on `entropy_level` + `coherence_level`, processing-time + `llm_calls` anomalies.

The detector NEVER fires on SelfConscience traffic (agent's own H3ERE) — that's a formally-proved invariant in RATCHET's `formal/RATCHET/Core/ConsentGate.lean` (F-CR-3 zero-by-construction). Lens-core's implementation MUST honor this by gating signal emission on the consent role of the sender; the formal proof is the design contract.

---

## 5. Wire-contract freeze

Per CIRISLensCore#8 acceptance: *"Wire-format frozen as a public contract; lens.ciris.ai consumes it; community lenses consume it."* That elevates the trace event types from "lens-core internal struct shapes" to a **federation-public ABI**.

### 5.1 Frozen types (v0.5.0)

```rust
// re-exported from ciris_lens_core::wire::contract:

pub struct BatchEnvelope { /* batch_id, batch_timestamp, consent_timestamp, trace_level, batch_signature, events */ }
pub struct BatchEvent    { /* event_type, trace, signature */ }
pub struct CompleteTrace { /* trace_id, thought_id, task_id, started_at, completed_at, trace_level, trace_schema_version, deployment_profile, components, signature, signature_key_id */ }
pub struct TraceComponent { /* component_type, event_type, timestamp, attempt_index, data, agent_id_hash */ }
pub struct DeploymentProfile { /* agent_role, agent_template, deployment_domain, deployment_type, deployment_region, deployment_trust_mode */ }
pub enum   TraceDetailLevel { Generic, Detailed, FullTraces }
pub enum   ReasoningEventType { ThoughtStart, SnapshotAndContext, DmaResults, IdmaResult, AspdmaResult, TsaspdmaResult, ConsciencerResult, ActionResult, /* +future */ }
pub struct Ed25519TraceSigner;   // construction-time identity binding; mirrors persist::StewardSigner usage
```

All `Serialize + Deserialize`. PyO3-exported as Python classes via `#[pyclass]`. Frozen at v0.5.0 — semver discipline matches `ciris-persist::PUBLIC_SCHEMA_CONTRACT.md`:

- Adding a field with a default = **minor** version bump.
- Renaming or removing = **major** version bump.
- Changing semantics of an existing field = **major**.
- Internal struct reorganization without serde-shape change = **patch**.

### 5.2 Wire-format determinism

Persist's `canonicalize_envelope_for_signing` is the single canonicalizer (CIRISPersist#7 single-source-of-truth, established in v0.4.1). Lens-core's `Ed25519TraceSigner.sign(trace)` calls into persist's canonicalizer; the bytes signed at the agent are bit-identical to the bytes persist would canonicalize on receipt. Verify always succeeds when the trace is unmodified.

### 5.3 The audit-service ABI specifically

CIRISAgent has been calling `AuditService.log_action(...)` for ~5+ years. The signature is stable, the consumer set is large. v0.5 doesn't change the call sites; it changes the implementation behind them.

Migration: agent-side `AuditService` becomes a 10-line Python shim that constructs `lens.audit` once and delegates each method. The 142-test suite in `tests/services/test_audit_service.py` passes against the shim (proves behavior parity). When confidence builds, the shim can fold into agent code-paths directly. No CIRISAgent consumer rewrites.

---

## 6. PyO3 surface — v0.5 final

```python
import ciris_lens_core as cl
import ciris_persist as cp

engine = cp.Engine(...)  # construction unchanged from v0.1.1

# ─── CLIENT MODE (agent-side, default) ──────────────────────────────

lens = cl.LensCore.client(
    engine=engine,
    upstream=[
        cl.UpstreamLens(
            lens_steward_key_id="lens-prod-eu-west-key-id",
            egress_filter=cl.EgressFilter(trace_level="GENERIC"),
        ),
        cl.UpstreamLens(
            lens_steward_key_id="my-sovereign-anchor-key-id",
            egress_filter=cl.EgressFilter(trace_level="FULL_TRACES"),
        ),
    ],
    retention=cl.RetentionPolicy(max_disk_gb=50, max_age_days=90),
)

# Audit primitives — replace agent's old AuditService.log_*:
lens.audit.log_action(action_type="speak", thought_id="th_...", rationale="...", ...)
lens.audit.log_consent_event(event_type="grant", stream_id="...", duration_days=30, ...)
lens.audit.log_wbd(deferral_reason="...", deferred_to="human_oversight", ...)
lens.audit.log_identity_change(field="agent_role", old="datum", new="ally", ...)

# Trace capture — replace today's reasoning_event_stream subscriber:
lens.capture.event(component={"event_type": "THOUGHT_START", ...})  # or strongly-typed py class
lens.capture.event(component={"event_type": "DMA_RESULTS", ...})
lens.capture.event(component={"event_type": "ACTION_RESULT", ...})  # seals + persists + fans out

# Periodic ops:
flush_summary = lens.flush()                     # forces durable-queue drain attempt
orphan_summary = lens.orphan_sweep(max_age=3600) # purge incomplete partial-traces
evict_summary = lens.evict_per_retention_policy()
lens.shutdown()                                  # graceful: flush + close Edge runtime

# ─── RELAY MODE (federation-bridge) ─────────────────────────────────

relay = cl.LensCore.relay(
    engine=engine,
    listen_addr="0.0.0.0:8080",
    peer_acl=cl.PeerAcl.allow_all(),  # or cl.PeerAcl.from_directory(engine)
    upstream=[cl.UpstreamLens(lens_steward_key_id="lens-anchor", egress_filter=...)],
    retention=cl.RetentionPolicy(max_disk_gb=500),
)
# `relay` accepts AccordEventsBatch via Edge listener;
# verifies each via persist's verify_hybrid_via_directory;
# applies egress filter; durable-enqueues forwards.

# ─── NODE MODE (federation-anchor with UX) ──────────────────────────

node = cl.LensCore.node(
    engine=engine,
    listen_addr="0.0.0.0:8080",
    peer_acl=cl.PeerAcl.from_directory(engine),
    scoring=cl.ScoringConfig(sample_size_gate=500, ratchet_calibration_version=2),
    ux=cl.UxConfig(api_root="/lens/api/v1", web_root="/lens"),
)
# Same as relay PLUS:
# - serves /lens/api/v1/scores, /lens/api/v1/detection_events, etc.
# - serves /lens read web app (the federation's UI)
```

### 6.1 Backward-compat: v0.1.1's 4-function contract preserved

The 4 free functions from v0.1.1 (`process_trace_batch`, `scrub_trace`, `scrub_traces_batch`, `ner_is_configured`) stay exposed at the module level. The deployed lens's current `import ciris_lens_core as cirislens_core` swap continues to work. v0.5 adds the `LensCore` class hierarchy alongside; consumers migrate at their own pace.

`process_trace_batch` semantics for v0.5: equivalent to `LensCore.node(...).process_batch(...)` for callers that don't construct a long-lived LensCore. Same Engine-as-parameter pattern; same locked return shape.

---

## 7. Rust rlib surface — PoB §3.1 fold prep

Post-fold, the agent links lens-core as an rlib and bypasses PyO3 entirely. The Rust surface mirrors PyO3 1:1:

```rust
use ciris_lens_core::{LensCore, Mode, UpstreamLens, RetentionPolicy};
use ciris_persist::Engine;
use std::sync::Arc;

let engine = Arc::new(Engine::new(config)?);
let lens = LensCore::new(
    engine.clone(),
    Mode::Client {
        upstream: vec![UpstreamLens { ... }],
        retention: RetentionPolicy { ... },
    },
).await?;

lens.audit().log_action(action).await?;
lens.capture().event(component).await?;
lens.flush().await?;
lens.shutdown().await?;
```

The agent's `AuditService` Rust impl (post-fold) constructs a `LensCore::client(...)` once at startup; existing AuditService consumers call `lens.audit().log_*` via thin wrappers; no Python-Rust FFI hop.

---

## 8. Retention policy

Lens-core owns the eviction logic; persist exposes the deletion primitive.

### 8.1 Policy shape

```rust
pub struct RetentionPolicy {
    /// Maximum disk usage for the local trace + audit store. Soft cap;
    /// triggers eviction once 90% reached.
    pub max_disk_gb: Option<u64>,

    /// Maximum age. Traces older than this auto-evict regardless of
    /// disk pressure. None = no time-bound eviction.
    pub max_age_days: Option<u32>,

    /// Per-trace_level retention. Allows keeping FULL_TRACES short
    /// (privacy posture) while keeping GENERIC scores long (analysis).
    /// None = inherits max_age_days for all levels.
    pub per_level_max_age: Option<HashMap<TraceLevel, u32>>,

    /// Detection events have separate retention (signed federation
    /// evidence; typically kept longer than the underlying traces).
    pub detection_events_max_age_days: u32,  // default: never (kept indefinitely)

    /// Audit log retention. Hash chain must be unbroken; eviction is
    /// "archive + truncate" not "delete". Default: never.
    pub audit_log_max_age_days: Option<u32>,
}
```

### 8.2 Eviction trigger

`lens.evict_per_retention_policy()` runs:
1. Compute disk usage from persist's `engine.storage_summary()`.
2. If `>= 90% of max_disk_gb`: walk traces oldest-first, delete until `<= 80%`.
3. Walk traces older than the per-level age caps; delete those.
4. Archive audit log entries older than `audit_log_max_age_days` to compressed sidecar (preserves hash chain by archiving in contiguous range).
5. Return an `EvictSummary` with row counts + freed disk.

### 8.3 Persist ask: storage_summary + delete_traces_older_than

Persist today exposes:
- `Engine.delete_traces_for_agent(agent_id_hash, signature_key_id)` — DSAR scope (CIRISPersist#15)

What v0.5 lens-core needs:
- `Engine.storage_summary() -> {disk_bytes, trace_count, audit_entry_count, oldest_trace_ts}`
- `Engine.delete_traces_older_than(ts, max_rows)` — batch eviction primitive
- `Engine.archive_audit_range(from_ts, to_ts) -> archive_handle` — preserves hash chain

These will be filed as CIRISPersist asks during v0.4 implementation. Closure-pattern: persist owns the storage primitives; lens-core owns the eviction *policy*.

---

## 9. Egress filter

The translation from local-FULL to remote-required happens here.

### 9.1 Filter pipeline

For each upstream lens, for each trace ready to forward:

```rust
pub fn apply(&self, signed_envelope: &SignedBatchEnvelope, filter: &EgressFilter) -> Result<SignedBatchEnvelope> {
    let mut filtered = signed_envelope.clone();

    // 1. Trace-level downsampling — uses persist's pipeline::scrub.
    let target_level = filter.trace_level;
    filtered.envelope.trace_level = target_level;
    for event in &mut filtered.envelope.events {
        event.trace = ciris_persist::pipeline::scrub::scrub_trace(
            event.trace.clone(),
            target_level,
        )?;
    }

    // 2. Severity filter — drop events whose detector firings are below threshold.
    if let Some(min_sev) = filter.min_severity {
        filtered.envelope.events.retain(|e| e.severity >= min_sev);
    }

    // 3. Detection events / scores inclusion.
    if !filter.include_detection_events {
        filtered.envelope.events.retain(|e| !e.is_detection_event());
    }
    if !filter.include_scores {
        filtered.envelope.events.retain(|e| !e.is_score());
    }

    // 4. User-text redaction (even at DETAILED, scrub user prompts).
    if filter.redact_user_prompts {
        for event in &mut filtered.envelope.events {
            redact_field(&mut event.trace, "user_prompt")?;
        }
    }
    if filter.redact_completions {
        for event in &mut filtered.envelope.events {
            redact_field(&mut event.trace, "llm_completion")?;
        }
    }

    // 5. Re-sign — the envelope changed shape; old signature is invalid.
    //    Sign with agent's steward identity; recipient verifies via persist's directory.
    filtered.batch_signature = self.signer.sign_envelope(&filtered.envelope)?;

    Ok(filtered)
}
```

### 9.2 Re-signing on egress

When egress filtering modifies envelope shape, lens-core re-signs as the agent's steward identity. The recipient lens verifies via persist's `verify_hybrid_via_directory` against the agent's `federation_keys` row. This means:

- Federation peers don't see the agent's local-FULL bytes. They see *the agent's signed claim* about what to share.
- The agent's audit history (local) and the federation's view (remote) are different signed records — both verifiable, neither denying the other.
- If a federation peer wants to verify "what the agent emitted at the time of decision X," they ask the agent (or trust circle peer with FULL_TRACES access) for the local-FULL canonical bytes.

### 9.3 Privacy invariants

Per the Accord's "diverse sentient beings may pursue their own flourishing under justice":

- **Operator can audit their own agent at FULL_TRACES** locally, always. Privacy posture for the agent's user does NOT remove the operator's ability to inspect agent behavior.
- **Federation anchor sees GENERIC** by default. Numeric scores, manifold-conformity, signed detection events. No user prompts, no LLM completions, no PII.
- **Sovereign-mode trust circle sees DETAILED or FULL_TRACES** by per-relationship policy. The operator chooses who is in the circle; lens-core enforces it at the egress boundary.
- **Community lens viewers see node-mode UX endpoints only.** They consume the wire-format-frozen score API; they never see the underlying envelope bytes.

---

## 10. Federation addressing — key_id over transport

### 10.1 Resolution path

Agent's lens-core has a config map: `destination_key_id → peer_url` (for HTTP) or `destination_key_id → reticulum_addr` (for mesh). Edge handles the resolution:

```rust
edge.send_durable(
    destination_key_id: "lens-prod-eu-west-key-id",
    message: AccordEventsBatch { /* filtered envelope */ },
).await?;
```

Edge looks up `lens-prod-eu-west-key-id` in its `peer_urls` config, dispatches via the registered `Transport` impl, retries through persist's `edge_outbound_queue` if delivery fails.

### 10.2 Transport phases

| Phase | Transport | Discovery | Status |
|---|---|---|---|
| 1 (today) | HTTP via `ciris_edge::HttpTransport` | Static `peer_urls` config | Edge v0.1.4 |
| 2 | HTTP + federation directory lookup (DNS optional) | Persist `federation_keys` + lens-side directory service | Edge v0.2.x (planned) |
| 3 | Reticulum (mesh-routed by identity hash) | RNS announces; key_id = identity hash | Edge v0.3.x (Phase 3) |
| 4 | LoRa / I²P / additional transports | Same key_id abstraction | Drop-in via Edge `Transport` trait |

Lens-core v0.5 is **Phase 3 ready** — when edge ships the Reticulum `Transport`, lens-core's config switches from `peer_urls: {key_id → http_url}` to `peer_urls: {key_id → reticulum_addr}` and the rest of the code is unchanged.

### 10.3 Key rotation

Agent rotates its steward identity:
1. Generate new keypair; sign attestation chaining old→new (persist's `attestation` substrate, v0.4.x).
2. Register new public key in `federation_keys` (persist's `Engine.put_public_key` + federation peer replication).
3. Lens-core picks up new signing identity at next restart (or via hot-reload primitive if implemented).
4. Other federation peers verify the attestation chain; subsequent traces signed under new key continue to verify.

No DNS change. No service rotation downtime. No hostname change. Same agent identity, different signing key. **This is what key-addressing enables.**

---

## 11. Migration sequence (v0.1.1 → v0.5.0)

Per-minor milestones. Each ships independently usable; each closes specific issues.

### v0.2 — Wire-contract freeze + Edge integration

| Issue | Scope |
|---|---|
| `Wire-contract: expose CompleteTrace, BatchEnvelope, BatchEvent, TraceComponent, TraceDetailLevel, ReasoningEventType, Ed25519TraceSigner as Python types` | Federation-public ABI; foundation for both client + relay |
| `init_edge_runtime PyO3 fn + LensCore::relay(...) rlib ctor` (closes #7) | Lens-deployed-product FastAPI → Edge cutover; addressable by `lens_steward_key_id` |

**Acceptance**: Deployed lens-API can construct an Edge runtime via lens-core; agents emit to `lens.ciris.ai` by key_id (HTTP transport); v0.1.1's 4-function PyO3 contract continues to work for legacy callers.

### v0.3 — Client mode + AuditService replacement

| Issue | Scope |
|---|---|
| `LensCore.client PyO3 surface: partial-trace capture + complete-trace persistence + signed emit` | First half of #8 Phase 1: replaces accord_metrics's emit path |
| `LensCore.audit PyO3 surface: typed action vocabulary + persist audit-log delegation` | Replaces agent's in-process AuditService; 142-test suite parity |
| `Wire-contract enforcement: parent_event_type sentinel normalization at the Rust boundary` | Closes the wire-contract-drift incident class (CIRISAgent#757) |
| `PII fuzz at construction time: _fuzz_location_to_region in the Rust crate` | Closes the lat/lng precision incident |

**Acceptance**: CIRISAgent's `ciris_adapters/ciris_accord_metrics/` deleted; agent imports `ciris_lens_core.LensCore.client(...)` + thin shim; existing AuditService callers unchanged.

### v0.4 — Retention + egress filter + node mode

| Issue | Scope |
|---|---|
| `RetentionPolicy: disk-budget + time-budget eviction + per-level age caps` | New lens-core module; files persist asks for `storage_summary`, `delete_traces_older_than`, `archive_audit_range` |
| `EgressFilter: per-upstream trace_level downsampling + severity gate + user-text redaction + re-signing` | Calls persist's pipeline::scrub on outbound copies |
| `Multi-upstream fan-out: persist edge_outbound_queue enqueue per upstream with independent filters` | Reuses persist's durable outbound queue |
| `Node mode Phase 3: score/manifold/detection read API endpoints` (closes #8 Phase 3) | UX endpoints; wire-format-frozen public contract |
| `Persist asks for v0.4 (filed alongside the lens-core work)` | `storage_summary`, `delete_traces_older_than`, `archive_audit_range` — closure-pattern with persist |

**Acceptance**: Pi-class agent runs lens-core with 8GB disk budget + 24h retention; federation-bridge runs relay mode with 500GB budget + 90d retention; safety.ciris.ai-class runs node mode serving community-lens viewers.

### v0.5 — Reticulum + sovereign-mode + rlib parity

| Issue | Scope |
|---|---|
| `Reticulum transport: consume Edge Phase 3 Transport impl` | Drop-in via config when edge ships; no lens-core code change |
| `Sovereign-mode agent: agent constructs LensCore via rlib (PoB §3.1 fold prep)` | rlib API parity with PyO3; validates agent-fold trajectory |
| `Multi-recipient fan-out under mesh transport: outbound queue partitions per destination_key_id × transport` | Generalize fan-out for arbitrary transports |
| `Wire-contract v1.0 freeze: stable ABI guarantee for community lens consumers` | Semver discipline doc; locks the public types |

**Acceptance**: Sovereign-mode CIRISAgent on a Pi over Reticulum (no DNS, no internet) talks to a federation anchor via key_id; agent has no PyO3 path; lens-core is linked rlib; federation tree single-version-clean.

---

## 12. Open questions

### OQ-13: Audit log eviction semantics

The hash-chained audit log can't tolerate gaps (verification requires unbroken chain). v0.5's `audit_log_max_age_days` proposes "archive + truncate" rather than delete. How exactly?

**Starting position**: Compressed sidecar archive (zstd-compressed `audit_log_<from_ts>_<to_ts>.archive`) signed by agent's steward identity; head of in-database chain becomes the archive's terminal hash. Recoverable for forensic queries but cold-path. CIRISPersist ask in v0.4.

### OQ-14: Wire-contract version negotiation between agents and lenses

If agent ships v1.0 of the wire contract and the federation anchor is still on v0.9, what happens? Strict-reject? Negotiate down?

**Starting position**: Strict reject with a typed "unsupported_wire_version" detection event. Forces operator-visible mismatch surfacing rather than silent drift. Negotiation logic adds complexity for negligible gain (federation upgrades within a release cycle).

### OQ-15: Re-signing on egress — agent's steward identity vs forwarding-lens's identity

When a relay-mode lens-core forwards filtered traces upstream, who signs the filtered envelope? The original agent? The relay?

**Starting position**: Relay re-signs with its own steward identity; agent's original signature preserved as a nested `original_signature` field. Upstream verifies the relay's signature (proves relay claims this filter was applied); if forensic dispute, upstream can ask agent for canonical bytes + verify against `original_signature` directly.

### OQ-16: Multi-tenancy — can one LensCore instance serve N agents on a host?

Co-located deployments (multiple CIRISAgents on one machine) might want to share a LensCore daemon to avoid N persist connections.

**Starting position**: v0.5 ships single-agent-per-LensCore. Multi-tenancy is a v0.6+ concern; the daemon-mode wrapping happens above lens-core, not inside it.

### OQ-17: Node-mode UX endpoint schema — public ABI freeze timing

Node mode's UX endpoints become a public contract community lens viewers consume. Freeze timing?

**Starting position**: Freeze with v0.5.0. The endpoints are: `GET /lens/api/v1/scores`, `/lens/api/v1/scores/{trace_id}`, `/lens/api/v1/detection_events`, `/lens/api/v1/manifold_conformity_aggregate`. Path shape and response schema are part of the v0.5 wire-contract freeze.

### OQ-18: Reticulum identity-hash → steward_key_id mapping

Reticulum addresses by 16-byte identity hash. Federation addresses by `signing_key_id`. Bidirectional mapping?

**Starting position**: `signing_key_id = sha256(steward_pubkey_bytes)[:16]` (16 bytes hex); Reticulum identity = same 16 bytes. Single hash function. Edge's Reticulum `Transport` impl derives the mapping; lens-core stays transport-agnostic.

---

## References

- `MISSION.md` — mission alignment; PoB §3.1 fold trajectory
- `docs/THREAT_MODEL.md` — LC-AVs; LC-AV-9 cold-start; LC-AV-11 fail-secure; LC-AV-18 sample-size gate
- `FSD/CIRIS_LENS_CORE.md` — original architecture doc
- `FSD/OPEN_QUESTIONS.md` — OQ-01 through OQ-12 (closed); OQ-13 onward this doc
- CIRISLensCore#7 (Edge integration, init_edge_runtime)
- CIRISLensCore#8 (accord_metrics adapter replacement, client/relay/node taxonomy)
- CIRISPersist v0.9.1 — substrate composition source
- CIRISEdge v0.1.4 — transport composition source
- CIRISAgent commits `b23c99ceb` (audit late-binding), `ad84bcc30` (FFI loader)
- CIRISLens#13 — bridge diagnostic cycle that surfaced wire-contract drift
- The Accord §M-1 — meta-goal alignment for "diverse sentient beings may pursue their own flourishing"
