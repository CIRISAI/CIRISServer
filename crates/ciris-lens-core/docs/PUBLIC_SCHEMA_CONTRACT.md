# PUBLIC_SCHEMA_CONTRACT.md

`ciris-lens-core`'s public ABI is the surface every federation peer
that imports lens-core composes against — the deployed Python lens,
CIRISAgent (post-PoB §3.1 fold), NodeCore, RATCHET calibration
consumers, and sovereign-mode operators running lens-core as an
rlib. This doc defines what shape that surface has and what stability
guarantees lens-core makes against it.

Sister doc to
[`CIRISPersist/docs/PUBLIC_SCHEMA_CONTRACT.md`](https://github.com/CIRISAI/CIRISPersist/blob/main/docs/PUBLIC_SCHEMA_CONTRACT.md)
(persist's SQL column contract) — same tier model, different surface
shape: persist contracts SQL columns its readers SELECT; lens-core
contracts Rust types + PyO3 functions its consumers `import` /
`use ciris_lens_core::...`.

## Scope

This contract applies to:

1. **Top-level Rust re-exports** from `lib.rs` (everything reachable
   as `ciris_lens_core::Foo`)
2. **The `wire` module** (`ciris_lens_core::wire::*`) — federation-
   public ABI re-exported from persist
3. **The PyO3 surface** — every `#[pyfunction]` and `#[pyclass]`
   registered in the `ciris_lens_core` Python module (including the
   `LensClient` pyclass added in v1.0)
4. **The CEG §5.5 typed primitives** (`capacity::*`,
   `detector::CoherenceRatchetDetector`, etc.) — load-bearing
   invariants enforced by the type system
5. **The `capture/` module** (`src/capture/*`) — the client/emit
   surface (CIRISLensCore#11): `CaptureClient`, `LensClient` (PyO3),
   `InboundEvent`, `CaptureEventOutcome`, `ReasoningEventType`,
   `ComponentType`, `CorrelationMetadata`, `ConsentConfig`,
   `ConsentResolution`, `build_canonical_envelope`, `canonical_bytes`,
   `strip_empty`, `BatchProvenance`, `BatchBuildError`, `SealSummary`,
   `ClientError`, `TRACE_SCHEMA_VERSION`, `CONSENT_DIMENSION`

This contract does **NOT** apply to:

- `src/pipeline/lifecycle.rs` internals — `LensCore::process` is
  changing through v0.4/v0.5 as the detector family lands
- `src/scoring/` internal types — `ManifoldConformity` is in the
  contract; the assembly routing inside `scoring::assemble` is not
- Anything under `src/extract/` beyond the re-exported persist
  `Features` — projection internals can change as RATCHET ships
  calibration anchors
- Anything under `src/role/handler.rs` — relay handler internals

## Stability tiers

Mirrors persist's tier model:

- **`stable`** — semver-guaranteed. Removal or signature change
  requires a major version bump *and* a deprecation window of one
  minor version minimum. Downstream code can rely on these existing
  across patch and minor versions of lens-core.
- **`stable-frozen`** — same guarantees as `stable`, **plus** a
  promise that the shape doesn't change across major versions without
  a coordinated federation cutover. The wire types under
  `crate::wire::*` and the full client-emit surface are
  `stable-frozen` because federation peers parsing canonical bytes
  and the PoB §3.1 agent fold shim both depend on exact wire shapes
  and outcome strings. Renames require the entire federation
  re-cutting.
- **`internal`** — no stability guarantee. May change shape,
  semantics, or disappear at any minor version. Documented here
  only so consumers know not to depend on them.

**v1.0.0 status:** The wire-contract freeze (CIRISLensCore#18)
**shipped in v1.0.0**. Every type listed as `stable-frozen` below is
now frozen; the post-1.0 semver rules are live (see
[Semver discipline](#semver-discipline)). Items explicitly listed as
`stable` (not `-frozen`) remain on the additive-evolution path.

---

## Client-emit surface (CIRISLensCore#11) — the fold ABI

The `src/capture/` module is the centerpiece of v1.0. It replaces the
emit half of CIRISAgent's `accord_metrics/services.py` (~3000 LOC
Python) and is the surface the PoB §3.1 agent fold links against.
The capture → seal → sign → persist pipeline is documented here with
its exact v1.0 type signatures; see the source files under
`src/capture/` for implementation detail.

### `CaptureClient` — rlib orchestrator (`src/capture/client.rs`)

```rust
pub struct CaptureClient { /* … */ }                                 // stable-frozen

impl CaptureClient {
    pub fn new(
        engine:                   Arc<Engine>,
        scrubber:                 Arc<dyn Scrubber + Send + Sync>,
        trace_level:              String,
        trace_schema_version:     String,
        correlation:              Option<CorrelationMetadata>,
        consent_attesting_key_id: Option<String>,
        consent_config:           ConsentConfig,
        deployment_profile:       Option<serde_json::Value>,
        local_copy_dir:           Option<std::path::PathBuf>,
    ) -> Self;                                                        // stable-frozen

    pub async fn capture_event(
        &self,
        event: InboundEvent,
    ) -> Result<CaptureEventOutcome, ClientError>;                    // stable-frozen

    pub async fn orphan_sweep(
        &self,
        now:          DateTime<Utc>,
        max_age_secs: u64,
    ) -> usize;                                                       // stable-frozen
}
```

`CaptureClient::new` is `stable-frozen`: it is the 9-argument
constructor the shim and every sovereign rlib caller uses. The
argument order and types lock the fold ABI — adding a parameter
(other than via `#[non_exhaustive]` struct fields) is a major break.

`capture_event` and `orphan_sweep` are `stable-frozen`: they are the
two live methods the agent shim calls per thought and per sweep cycle.

### `CaptureEventOutcome` — per-event result (`src/capture/client.rs`)

```rust
#[derive(Debug)]
pub enum CaptureEventOutcome {                                        // stable-frozen
    Opened,
    Appended,
    Rejected { raw: String },
    SealedAndPersisted {
        trace_id: String,
        summary:  SealSummary,
    },
    ConsentBlocked { reason: &'static str },  // "withdrawn" | "no_consent"
}
```

`CaptureEventOutcome` is `stable-frozen`: the variant names and their
payload shapes are the wire-ish contract the shim depends on. The
`ConsentBlocked.reason` values `"withdrawn"` and `"no_consent"` are
the two `&'static str` values the shim maps to Python strings — they
are part of this contract. `#[non_exhaustive]` is intentionally
**not** applied: the shim's match arms must stay exhaustive so a new
variant is a compile-time break forcing a shim update.

### `SealSummary` — persist ingest counts (`src/capture/client.rs`)

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealSummary {                                              // stable-frozen
    pub trace_events_inserted: usize,
    pub signatures_verified:   usize,
}
```

`SealSummary` is `stable-frozen`: its two fields are surfaced directly
in the `LensClient.capture_event` result dict (keys
`trace_events_inserted` and `signatures_verified`). Adding fields is a
minor-version operation given the struct is not `#[non_exhaustive]`;
callers should not destructure exhaustively, but the existing fields
cannot be removed or renamed post-1.0.

### `ClientError` — capture-pipeline error (`src/capture/client.rs`)

```rust
#[derive(Debug, thiserror::Error)]
pub enum ClientError {                                                // stable-frozen
    #[error("seal: {0}")]    Seal(#[from] SealSignError),
    #[error("batch: {0}")]   Batch(#[from] BatchBuildError),
    #[error("persist: {0}")] Persist(String),
    #[error("consent: {0}")] Consent(String),
}
```

`ClientError` is `stable-frozen`: the four variants are the four
failure modes callers must handle; the `Persist` and `Consent`
variants are stringified to avoid coupling to persist's internal error
types at the public boundary. `#[non_exhaustive]` is intentionally
absent: adding a variant is a major change.

### `InboundEvent` — component-event wire type (`src/capture/partial.rs`)

```rust
#[derive(Debug, Clone)]
pub struct InboundEvent {                                             // stable-frozen
    pub event_type:    String,
    pub thought_id:    String,
    pub task_id:       Option<String>,
    pub agent_id_hash: String,
    pub timestamp:     String,
    pub trace_level:   Option<String>,
    pub data:          serde_json::Value,
}
```

`InboundEvent` is `stable-frozen`: it is what the PyO3 shim
constructs from the agent's event dict and passes to
`CaptureClient::capture_event`. All seven fields carry observable
meanings in the assembled trace wire format.

### `ReasoningEventType` — 15-variant closed enum (`src/capture/event.rs`)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReasoningEventType {                                         // stable-frozen
    ThoughtStart,
    SnapshotAndContext,
    DmaResults,
    IdmaResult,
    AspdmaResult,
    TsaspdmaResult,     // DEPRECATED — use VerbSecondPassResult
    VerbSecondPassResult,
    ConscienceResult,
    ActionResult,       // seals the trace
    LlmCall,
    DeferralRouted,
    DeferralReceived,
    DeferralResolved,
    GratitudeSignaled,
    CreditGenerated,
}

impl ReasoningEventType {
    pub const ALL: [ReasoningEventType; 15];                         // stable-frozen
    pub const fn as_wire_str(self) -> &'static str;                  // stable-frozen
    pub const fn component_type(self) -> ComponentType;              // stable-frozen
    pub const fn seals_trace(self) -> bool;                          // stable-frozen
    pub fn parse(raw: &str) -> Option<Self>;                         // stable-frozen
}
```

`ReasoningEventType` and its wire-string mappings are `stable-frozen`:
the 15 variants (and their `as_wire_str()` return values) are the
wire taxonomy. Adding a variant post-1.0 is a major break because
the agent's stream would emit it and the shim would see
`Rejected { raw }` until the new variant is deployed. The 15-count
lock is enforced by `all_has_fifteen_variants` in the test suite.

The `as_wire_str → component_type` mapping is `stable-frozen`:
the 12-entry `ComponentType` wire-string table is locked by
`component_wire_strings_locked`; any drift is a federation-silent
mis-component (the CIRISAgent#757 class structurally prevented here).

### `ComponentType` — 12-variant bucket enum (`src/capture/event.rs`)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComponentType {                                              // stable-frozen
    Observation, Context, Rationale, VerbSecondPass,
    Conscience, Action, LlmCall, DeferralRouted,
    DeferralReceived, DeferralResolved, GratitudeSignaled,
    CreditGenerated,
}

impl ComponentType {
    pub const fn as_wire_str(self) -> &'static str;                  // stable-frozen
}
```

Wire-string mappings: `observation`, `context`, `rationale`,
`verb_second_pass`, `conscience`, `action`, `llm_call`,
`deferral_routed`, `deferral_received`, `deferral_resolved`,
`gratitude_signaled`, `credit_generated`. These are carried in the
signed canonical bytes — a rename is a federation-signing break.

### `TRACE_SCHEMA_VERSION` — wire-schema sentinel (`src/capture/partial.rs`)

```rust
pub const TRACE_SCHEMA_VERSION: &str = "2.7.9";                     // stable-frozen
```

Changing `TRACE_SCHEMA_VERSION` changes the signed canonical bytes;
it is a major break equivalent to a wire-format version bump.

### Canonical-bytes and sign contract (`src/capture/seal.rs`)

```rust
// Pure envelope builder — shapes the 9(+1)-field signed object.
pub fn build_canonical_envelope(trace: &CompleteTrace) -> Value;    // stable-frozen

// Delegating canonicalizer — returns persist's PythonJsonDumpsCanonicalizer
// bytes; byte-exact to CIRISAgent's _build_canonical_message.
pub fn canonical_bytes(trace: &CompleteTrace) -> Result<Vec<u8>, String>; // stable-frozen

// Recursive null/""/[]/{}  stripper — KEEPS 0 and false.
pub fn strip_empty(value: Value) -> Value;                           // stable-frozen

// Stamp a computed Ed25519 signature onto a sealed trace.
pub fn apply_signature(
    trace:     &mut CompleteTrace,
    sig_bytes: &[u8],
    key_id:    &str,
);                                                                    // stable-frozen

// Async sign via HardwareSigner (v4.13+ Engine path).
pub async fn sign_trace_via_hardware_signer(
    signer: &dyn HardwareSigner,
    trace:  &mut CompleteTrace,
) -> Result<(), SealSignError>;                                       // stable-frozen

// Sync sign via LocalSigner (test / sovereign-rlib path).
pub fn sign_trace(
    signer: &ciris_persist::prelude::LocalSigner,
    trace:  &mut CompleteTrace,
) -> Result<(), TraceSealError>;                                      // stable-frozen

// Ed25519 verify — the federation-verifier algorithm.
pub fn verify_trace_signature(
    trace:         &CompleteTrace,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> bool;                                                            // stable-frozen
```

The canonical-bytes contract is byte-exact to the agent: 9 top-level
fields (10 when `deployment_profile` is set), `strip_empty` inside
each component's payload, `attempt_index` injected **inside** `data`
(not a sibling key), delegating serialization to persist's
`PythonJsonDumpsCanonicalizer` (`json.dumps(sort_keys=True,
separators=(",",":"))`). Any deviation causes every federation verifier
to reject traces this library seals. The parity harness
(`canonical_bytes_match_agent_fixtures`) locks this byte-for-byte
against agent-generated fixtures.

### `build_batch_bytes` + `BatchProvenance` (`src/capture/batch.rs`)

```rust
pub fn build_batch_bytes(
    traces:     &[CompleteTrace],
    provenance: &BatchProvenance,
) -> Result<Vec<u8>, BatchBuildError>;                                // stable-frozen

#[derive(Debug, Clone, PartialEq)]
pub struct BatchProvenance {                                          // stable-frozen
    pub batch_timestamp:      String,   // RFC-3339 per-seal wall-clock
    pub consent_timestamp:    String,   // RFC-3339; hard gate (persist 422s missing)
    pub trace_level:          String,   // "generic" | "detailed" | "full_traces"
    pub trace_schema_version: String,   // "2.7.9"
    pub correlation_metadata: Option<serde_json::Value>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum BatchBuildError {                                            // stable-frozen
    #[error("cannot build a batch with zero traces")]
    EmptyBatch,
    #[error("trace {trace_id} is unsigned (seal + sign before batching)")]
    UnsignedTrace { trace_id: String },
    #[error("serialize batch: {0}")]
    Serialize(String),
}
```

`build_batch_bytes` produces the `BatchEnvelope` wire JSON that
`Engine::receive_and_persist` and the edge outbound dispatcher
consume. It is `stable-frozen` because the byte output must be
accepted by persist's real `BatchEnvelope::from_json` and
`verify_trace` — a shape change is a persist-ingest break.

### `CorrelationMetadata` — PII-fuzz wire invariant (`src/capture/correlation.rs`)

```rust
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CorrelationMetadata {                                      // stable-frozen
    pub deployment_region: Option<String>,
    pub deployment_type:   Option<String>,
    pub agent_role:        Option<String>,
    pub agent_template:    Option<String>,
    pub user_location:     Option<String>,
    pub user_timezone:     Option<String>,
    pub user_latitude:     Option<String>,  // fuzzed 1-decimal; set only via build()
    pub user_longitude:    Option<String>,  // fuzzed 1-decimal; set only via build()
}

impl CorrelationMetadata {
    pub fn build(
        deployment_region: impl Into<String>,
        deployment_type:   impl Into<String>,
        agent_role:        impl Into<String>,
        agent_template:    impl Into<String>,
        share_location:    bool,
        user_location:     impl Into<String>,
        user_timezone:     impl Into<String>,
        user_latitude:     Option<f64>,   // raw; fuzzed to 1-decimal on construction
        user_longitude:    Option<f64>,   // raw; fuzzed to 1-decimal on construction
    ) -> Self;                                                        // stable-frozen

    pub fn is_empty(&self) -> bool;                                   // stable-frozen
    pub fn to_value(&self) -> serde_json::Value;                      // stable-frozen
}

/// Byte-exact to the agent's _fuzz_location_to_region.
pub fn fuzz_location_to_region(value: f64) -> String;                // stable-frozen
```

`CorrelationMetadata::build` is the **only constructor** —
there is no API surface that accepts a pre-formed latitude/longitude
string, so un-fuzzed coordinates cannot reach the wire. This is the
construction-time invariant that closes the CIRISAgent#757 PII leak:
raw lat/lng float → fuzzed 1-decimal string, at construction, not
as a post-construction validation step. The invariant is
`stable-frozen`: removing or weakening it would re-open the
CIRISAgent#757 class.

`fuzz_location_to_region` is `stable-frozen`: its output is
byte-exact to the Python adapter's `_fuzz_location_to_region`. Any
change to the number of decimal places or the rounding convention
changes the wire bytes on the `correlation_metadata` block.

### `ConsentConfig` / `ConsentResolution` (`src/capture/consent.rs`)

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct ConsentConfig {                                            // stable-frozen
    pub consent_timestamp: Option<String>,   // RFC-3339 or None
}

pub const CONSENT_DIMENSION: &str = "consent:community_trust:v1";   // stable-frozen

#[derive(Debug, Clone, PartialEq)]
pub enum ConsentResolution {                       // stable (NOT frozen — see note)
    CegGrant { asserted_at: DateTime<Utc> },
    ConfigFallback { consent_timestamp: String },
    Withdrawn { at: DateTime<Utc> },
    NoConsent,
}

pub fn resolve_consent(
    grant:  GrantState,
    config: &ConsentConfig,
) -> ConsentResolution;                                               // stable-frozen

pub async fn resolve_consent_via_engine(
    engine:              &Engine,
    attesting_key_id:    &str,
    config:              &ConsentConfig,
) -> Result<ConsentResolution, ConsentError>;                         // stable (NOT frozen)
```

`ConsentConfig` and `CONSENT_DIMENSION` are `stable-frozen`:
`ConsentConfig` is a constructor parameter on `CaptureClient::new`
and `LensClient.__init__`; `CONSENT_DIMENSION` is the dimension string
the consent gate reads — changing either changes which grants are
recognized as consent.

`resolve_consent` (the pure predicate) is `stable-frozen`: its
`Withdrawn → Withdrawn (not config)` invariant is the privacy-critical
hard stop — a CEG recant MUST stop emission and MUST NOT fall back to
config, per CIRISAgent#870 / CIRISLensCore#34.

`ConsentResolution` and `resolve_consent_via_engine` are `stable`
(NOT frozen): the CEG sourcing path for consent is still settling as
CIRISAgent#870 progresses. The variant set and the engine-read
implementation may extend additively post-1.0 without breaking the
`resolve_consent` predicate contract. Callers should treat
`ConsentResolution` match arms as non-exhaustive in practice.

### `LensClient` — PyO3 pyclass (`src/ffi/pyo3.rs`)

```python
class LensClient:                                    # stable-frozen
    def __init__(
        self,
        consent_timestamp:         Optional[str],          # RFC-3339; hard gate
        trace_level:               str,                    # "generic"|"detailed"|"full_traces"
        trace_schema_version:      str    = "2.7.9",
        deployment_profile:        Optional[dict] = None,  # 6-field cohort block
        consent_attesting_key_id:  Optional[str] = None,
        local_copy_dir:            Optional[str] = None,
        deployment_region:         Optional[str] = None,
        deployment_type:           Optional[str] = None,
        agent_role:                Optional[str] = None,
        agent_template:            Optional[str] = None,
        share_location:            bool          = False,
        user_location:             Optional[str] = None,
        user_timezone:             Optional[str] = None,
        user_latitude:             Optional[float] = None,
        user_longitude:            Optional[float] = None,
    ) -> None: ...

    def capture_event(self, component: dict) -> dict: ...
    # Returns one of:
    #   {"outcome": "opened"}
    #   {"outcome": "appended"}
    #   {"outcome": "rejected",            "raw": str}
    #   {"outcome": "sealed_and_persisted","trace_id": str,
    #    "trace_events_inserted": int,     "signatures_verified": int}
    #   {"outcome": "consent_blocked",     "reason": "withdrawn"|"no_consent"}

    def orphan_sweep(self, max_age_secs: int = 3600) -> int: ...
```

`LensClient` is `stable-frozen`: the kwarg constructor (15 named
kwargs in the exact order above), `capture_event(component: dict) ->
dict`, and `orphan_sweep(max_age_secs=3600) -> int` are the fold ABI
the agent shim calls. The five outcome string values (`"opened"`,
`"appended"`, `"rejected"`, `"sealed_and_persisted"`,
`"consent_blocked"`) and the two reason strings (`"withdrawn"`,
`"no_consent"`) are wire-ish string constants that MUST NOT be
renamed post-1.0.

The `capture_event` `component` dict required fields are
`event_type`, `thought_id`, `timestamp`, `agent_id_hash`;
optional fields are `task_id`, `trace_level`, `data`.

**Note on `ConsentBlocked`:** the fifth outcome variant was added in
the v1.0 freeze. Code that predates v1.0 and handles only the first
four outcomes will not receive a sealed trace for a consent-blocked
event but must handle the fifth key gracefully (or the caller will see
an unhandled key in the returned dict).

---

## Stability notes on non-frozen `capture/` types

The following `capture/` types are `stable` but **not** `stable-frozen`
— they extend additively post-1.0 and are not part of the hard freeze:

- **`ConsentResolution`** — the CEG sourcing is still settling
  (CIRISAgent#870); new variants may be added additively. Treat the
  enum as non-exhaustive in practice.
- **`resolve_consent_via_engine`** — the engine-read path for consent
  may change as the CEG directory API evolves. The pure `resolve_consent`
  predicate is frozen; this async wrapper is not.
- **`GrantState`**, **`ConsentError`** — internal consent-engine types;
  `stable`, additive.
- **`SealSignError`**, **`TraceSealError`** — signing error types;
  `stable`, additive.
- **`CompleteTrace`**, **`TraceComponent`**, **`PartialTraceStore`**,
  **`CaptureOutcome`** — the rlib partial-assembly types; `stable`.
  The durable-store variant is tracked at CIRISLensCore#35.
- **`BatchProvenance`** — individual provenance fields are `stable-frozen`;
  `BatchProvenance` itself is `stable` (new optional fields may be
  added at minor versions).

---

## Rust crate surface

### `LensCore` — the mode-entry handle

```rust
// src/pipeline/lifecycle.rs
pub struct LensCore { /* … */ }

impl LensCore {
    pub fn new(signer: Arc<LocalSigner>, journal: Arc<Journal>) -> Self;     // stable
    pub async fn process(&self, trace: VerifiedTrace,                        // stable-frozen
        sample_size_gate: u32, ratchet_calibration_version: i32)
        -> Result<Outcome, ProcessError>;
    pub async fn relay(engine: Arc<Engine>, key_id: impl Into<String>,       // stable
        seed_dir: PathBuf, listen_addr: SocketAddr,
        peer_urls: HashMap<String, String>)
        -> Result<RelayHandle, RelayError>;
    pub async fn attach_handler(edge: &Edge, engine: Arc<Engine>)            // stable-frozen
        -> Result<(), EdgeError>;
}
```

`attach_handler` is `stable-frozen` because it's the cohabitation
entry point — every agent + NodeCore deployment in production after
v1.0 calls it. The signature locks: `&Edge` + `Arc<Engine>`, returns
`Result<(), EdgeError>`. Adding a parameter is a major break.

### `LensCoreHandler` — the Edge handler

```rust
// src/role/handler.rs
pub struct LensCoreHandler;                                                  // stable

impl LensCoreHandler {
    pub fn new(engine: Arc<Engine>) -> Self;                                 // stable
}

#[async_trait]
impl Handler<AccordEventsBatch> for LensCoreHandler {                        // stable-frozen
    async fn handle(&self, msg: AccordEventsBatch, ctx: HandlerContext)
        -> Result<AccordEventsResponse, HandlerError>;
}
```

The `Handler<AccordEventsBatch>` impl is `stable-frozen`: it's the
trait signature that edge's dispatch loop calls. Federation peers
expect lens-core's handler to match `AccordEventsBatch` →
`AccordEventsResponse` exactly. Changing the `Message::Response`
type would require a coordinated three-repo bump (persist + edge +
lens-core).

### `RelayHandle` — standalone-mode shutdown

```rust
// src/role/relay.rs
pub struct RelayHandle { /* … */ }                                           // stable

impl RelayHandle {
    pub fn listen_addr(&self) -> SocketAddr;                                 // stable
    pub async fn shutdown(self) -> Result<(), RelayError>;                   // stable
}

pub enum RelayError {                                                        // stable
    NotSqliteBacked,
    Signer(String),
    Transport(TransportError),
    Edge(EdgeError),
    Join(String),
}
```

`#[non_exhaustive]` on `RelayError` — new variants are minor-version
additions; downstream `match` arms must include `_ => ...`.

### `Score` / `Outcome` / `ManifoldConformity` — per-trace results

```rust
// src/pipeline/lifecycle.rs + src/scoring/result.rs
pub struct Outcome {                                                         // stable-frozen
    pub score: Score,
    pub event: DetectionEvent,
}

pub struct Score {                                                           // stable-frozen
    pub conformity: ManifoldConformity,
    pub cohort_id: String,
    pub lens_core_version: &'static str,
    pub detection_events: Vec<DetectionEvent>,
}

pub enum ManifoldConformity {                                                // stable-frozen
    Numeric(f64),
    Indeterminate { reason: IndeterminateReason },
    Unavailable { reason: UnavailableReason },
}
```

`ManifoldConformity` is `stable-frozen` because the enum **IS** the
contract — `Indeterminate` and `Unavailable` are not magic numeric
values, they're typed signals federation peers join on. Collapsing
to `f64` would silently lose the fail-secure information that
LC-AV-18 / LC-AV-11 / LC-AV-9 depend on.

### `ScoresOracle` — agent-side read path

```rust
// src/scores/oracle.rs
pub struct ScoresOracle<'a> { /* … */ }                                      // stable

impl<'a> ScoresOracle<'a> {
    pub fn new(engine: &'a Engine) -> Self;                                  // stable
    pub async fn for_trace(&self, trace_id: &str)                            // stable
        -> Result<Vec<DetectionEvent>, OracleError>;
    pub async fn for_agent_window(&self,                                     // stable
        window_start: DateTime<Utc>, window_end: DateTime<Utc>,
        detector_filter: Option<&[String]>)
        -> Result<AgentScoreAggregate, OracleError>;
    pub async fn detector_history(&self,                                     // stable
        detector: &str, since: DateTime<Utc>,
        min_severity: DetectionSeverity)
        -> Result<Vec<DetectionEvent>, OracleError>;
}

pub struct AgentScoreAggregate { /* … */ }                                   // stable
pub struct SeverityDistribution { /* … */ }                                  // stable
pub fn compute_aggregate(...) -> AgentScoreAggregate;                        // stable
```

### `RetentionPolicy` + the eviction primitives

```rust
// src/config/retention.rs + src/retention/eviction.rs
#[non_exhaustive]
pub struct RetentionPolicy {                                                 // stable
    pub max_disk_gb: Option<u64>,
    pub max_age_days: Option<u32>,
    pub per_level_max_age: Option<HashMap<TraceLevel, u32>>,
    pub detection_events_max_age_days: Option<u32>,
    pub audit_log_max_age_days: Option<u32>,
}

pub struct EvictionPlan { /* … */ }                                          // stable
pub struct EvictionSummary { /* … */ }                                       // stable
pub fn plan_eviction(...) -> EvictionPlan;                                   // stable
pub async fn execute_plan(...) -> Result<EvictionSummary, EvictionError>;    // stable
pub async fn evict_per_retention_policy(...)                                 // stable
    -> Result<EvictionSummary, EvictionError>;
```

`RetentionPolicy` is `#[non_exhaustive]`. Adding fields is a
minor-version operation; v0.4 → v0.5 will not add fields in this
struct in any case (the deferred enforcement is documented in
`docs/RELEASE_NOTES.md`).

### `UpstreamLens` / `EgressFilter` — pan-mode config

```rust
// src/config/upstream.rs + src/config/egress.rs
#[non_exhaustive]
pub struct UpstreamLens {                                                    // stable
    pub lens_steward_key_id: String,
    pub egress_filter: EgressFilter,
}

#[non_exhaustive]
pub struct EgressFilter {                                                    // stable
    pub trace_level: TraceLevel,
    // v0.4 — CIRISLensCore#14 will add: min_severity,
    //   include_detection_events, include_scores,
    //   redact_user_prompts, redact_completions
}
```

v0.4 extends `EgressFilter` with five behaviors. The struct is
`#[non_exhaustive]` so additions are minor-version operations;
existing `EgressFilter::new(level)` calls keep working.

---

## CEG §5.5 typed primitives — load-bearing invariants

These types encode CEG-spec invariants at the type-system level
rather than as runtime validation. The construction-time invariants
are part of the contract — anyone relying on lens-core's CEG
primitives gets the invariant for free.

### `CoherenceRatchetDetector` — CEG §5.5.1

```rust
// src/detector/coherence_ratchet.rs
#[non_exhaustive]
pub enum CoherenceRatchetDetector {                                          // stable-frozen
    CrossAgentDivergence,
    IntraAgentConsistency,
    HashChainIntegrity,
    TemporalDrift,
    ConscienceOverrideRate,
}

impl CoherenceRatchetDetector {
    pub const fn dimension_label(&self) -> &'static str;                     // stable-frozen
    pub const ALL: [Self; 5];                                                // stable
}
```

`dimension_label()` mappings are `stable-frozen` — every variant's
return string is the wire-stable `detection:*` dimension label
federation peers join on. A rename is a substrate-MAJOR break (not
just lens-core major). The `wire_label_exactness` test locks them.

### `CapacityAttestation` — CEG §7.5 anti-Goodhart

```rust
// src/capacity/attestation.rs
pub struct CapacityAttestation {                                             // stable-frozen
    pub attesting_key_id: String,
    pub attested_key_id: String,
}

impl CapacityAttestation {
    pub fn new(attesting: impl Into<String>, attested: impl Into<String>)    // stable-frozen
        -> Result<Self, AntiGoodhartViolation>;
}

pub enum AntiGoodhartViolation {                                             // stable
    SelfAttestation { key_id: String },
}
```

`CapacityAttestation::new` is `stable-frozen`: returning
`Err(AntiGoodhartViolation::SelfAttestation)` when
`attesting == attested` is the *type* contract, not a validation
hook. Implementations must preserve this invariant; `Deserialize`
re-validates so wire bytes can't bypass.

### `CapacityFactors` — CEG §5.5.4 𝒞_CIRIS composite

```rust
// src/capacity/score.rs
pub struct CapacityFactors {                                                 // stable-frozen
    pub core_identity: f64,
    pub integrity: f64,
    pub resilience: f64,
    pub incompleteness_awareness: f64,
    pub sustained_coherence: f64,
}

impl CapacityFactors {
    pub fn new(c: f64, i_int: f64, r: f64, i_inc: f64, s: f64)               // stable-frozen
        -> Result<Self, CapacityFactorError>;
    pub fn composite(&self) -> f64;                                          // stable-frozen
}
```

The multiplicative composite (𝒞_CIRIS = C·I_int·R·I_inc·S) is
`stable-frozen` — switching to an additive or weighted-average
form would silently invalidate every existing detection event that
included a capacity composite. Locked by spec (CEG §5.5.4) + the
`any_zero_zeros_composite_per_ceg_design` test.

---

## `crate::wire::*` — federation-public ABI

The `wire` module re-exports persist's federation-public types under
a single stable path. **Every type here is `stable-frozen`** — they
cross the wire to federation peers parsing canonical-JSON bytes;
renames or shape changes break the federation at the protocol
level, not just at lens-core's source level.

```rust
// src/wire/mod.rs

// from ciris_persist::schema::envelope
pub use BatchEnvelope;                                                       // stable-frozen
pub use BatchEvent;                                                          // stable-frozen
pub use CorrelationMetadata;                                                 // stable-frozen
pub use TraceLevel;                                                          // stable-frozen

// from ciris_persist::schema::trace
pub use CompleteTrace;                                                       // stable-frozen
pub use DeploymentProfile;                                                   // stable-frozen
pub use TraceComponent;                                                      // stable-frozen

// from ciris_persist::schema::events
pub use AuditAnchor;                                                         // stable-frozen
pub use ComponentType;                                                       // stable-frozen
pub use CostSummary;                                                         // stable-frozen
pub use LlmCallStatus;                                                       // stable-frozen
pub use LlmCallSummary;                                                      // stable-frozen
pub use ReasoningEventType;                                                  // stable-frozen

// from ciris_persist::federation::goal (CIRISPersist#114)
pub use DeliberationRef;                                                     // stable-frozen
pub use Goal;                                                                // stable-frozen
pub use GoalScope;                                                           // stable-frozen
pub use GoalsFilter;                                                         // stable
pub use M1Dimension;                                                         // stable-frozen
pub use MetaGoalAlignment;                                                   // stable-frozen
```

`GoalsFilter` is `stable` (not `-frozen`) because it's a query-time
filter — adding fields is additive and doesn't change wire bytes.

### Compile-time enforcement — `re_export_accessibility`

`src/wire/mod.rs` contains a `re_export_accessibility` test that
declares dummy functions accepting `&BatchEnvelope`, `&Goal`,
`&MetaGoalAlignment`, etc. Any persist relocation that breaks one
of the re-exports breaks this test with a precise compiler error
pointing at the moved type — the contract drift is caught at PR
time, not after a federation peer fails to parse bytes.

---

## PyO3 surface

The `ciris_lens_core` Python module:

```python
import ciris_lens_core
```

Top-level functions:

| Function                                  | Tier              | Notes |
|---                                        |---                |---    |
| `process_trace_batch(engine, events, …)`  | stable            | v0.1.1 drop-in for the deployed lens; orchestrates the science layer over a batch |
| `scrub_trace(trace_json, level)`          | stable            | Delegates to `ciris_persist.pipeline.scrub.scrub_trace`; returns scrubbed JSON |
| `scrub_traces_batch(traces_json, level)`  | stable            | Batch form of `scrub_trace` |
| `ner_is_configured() -> bool`             | stable            | Whether persist's scrubber has NER backend configured |
| `install_relay(edge)`                     | **stable-frozen** | v0.2.0 cohabitation bootstrap; agent post-fold + post-cutover both call this |

Top-level classes:

| Class         | Tier              | Notes |
|---            |---                |---    |
| `LensClient`  | **stable-frozen** | v1.0 client-emit pyclass (CIRISLensCore#11). Constructor kwargs + `capture_event(component: dict) -> dict` + `orphan_sweep(max_age_secs=3600) -> int`. Full contract above in the "Client-emit surface" section. |

Module attributes:

| Attribute            | Tier   | Notes |
|---                   |---     |---    |
| `PROJECTION_VERSION` | stable | Currently `"crc-v1"`; a future minor may bump to `"crc-v2"` after RATCHET calibration ships |

`install_relay` is `stable-frozen` because every cohabitation agent
in production after v1.0 calls it. The signature is locked:
`install_relay(edge: ciris_edge.Edge) -> None`.

`LensClient` is `stable-frozen` (see "Client-emit surface" section
above): the constructor kwarg set, `capture_event` result-dict outcome
strings, and `orphan_sweep` signature are the fold ABI the agent shim
links against.

---

## Semver discipline

**Pre-1.0 history (v0.X.Y — for reference):**

- **major (0.X.0 → 0.(X+1).0):** new feature surface; pre-1.0
  callers may need source changes. Examples: v0.1.1 → v0.2.0 added
  `install_relay` cohabitation entry.
- **minor (0.X.Y → 0.X.(Y+1)):** bug fix, CI fix, doc-only,
  CIRISConformance-tracked pin bump that doesn't change lens-core's
  surface.
- **breaking (0.X.* → 0.(X+1).0):** wire-contract changes, removed
  PyO3 functions, persist-pin majors that cascade through the
  lens-core surface (e.g. signer API shift LocalSigner →
  HardwareSigner).

**Post-1.0 (v1.0.0 and later — the wire-contract freeze is live):**

These rules are now active as of v1.0.0 (CIRISLensCore#18 shipped):

- **major (X.Y.Z → (X+1).0.0):** removal or shape change of any
  `stable-frozen` item. Requires coordinated federation cutover.
  Adding a variant to `ReasoningEventType`, renaming a
  `CaptureEventOutcome` variant or its outcome string, changing
  `canonical_bytes` output, removing a `LensClient` kwarg — all are
  major breaks.
- **minor (X.Y.Z → X.(Y+1).0):** new functionality compatible with
  the contract; additions to `stable` (not `-frozen`) enums/structs;
  new PyO3 functions. Examples: extending `EgressFilter` with new
  optional fields (CIRISLensCore#14), new `ConsentResolution`
  variants, new `LensClient` optional kwargs.
- **patch (X.Y.Z → X.Y.(Z+1)):** bug fixes that don't change the
  surface; CI fixes; documentation; CIRISConformance-tracked pin
  bumps.

---

## CIRISConformance harness participation

Lens-core's contract is verified against the federation's
[cross-artifact conformance harness](https://github.com/CIRISAI/CIRISConformance)
at the matrix level — every cohabitation triple bump in
CIRISConformance re-runs the harness against lens-core's pinned
artifact. The harness's `requires_lens` pytest mark gates the
suite to deployments where lens-core is installed; once the harness
entry lands (per the spike's Phase 0c deliverable), CIRISConformance
becomes the authoritative verification surface for this contract.

---

## References

- [CIRISPersist `docs/PUBLIC_SCHEMA_CONTRACT.md`](https://github.com/CIRISAI/CIRISPersist/blob/main/docs/PUBLIC_SCHEMA_CONTRACT.md)
  — sister contract for the SQL schema
- [CIRISLensCore#18](https://github.com/CIRISAI/CIRISLensCore/issues/18)
  — v1.0.0 wire-contract freeze (shipped; promoted the wire + emit +
  cohabitation ABIs to `stable-frozen`)
- [`docs/RELEASE_NOTES.md`](RELEASE_NOTES.md) — what shipped when
- [`docs/COHABITATION.md`](COHABITATION.md) — the install paths
  whose signatures this contract locks
- [`Cargo.toml`](../Cargo.toml) — current cohabitation triple pin
- [CIRISConformance](https://github.com/CIRISAI/CIRISConformance)
  — the cross-artifact harness this contract is verified against
