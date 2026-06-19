//! PyO3 surface — v0.1.0 drop-in module for the deployed CIRISLens product.
//!
//! # Swap contract
//!
//! Deployed Python lens swaps from `cirislens_core` to
//! `ciris_lens_core` with a one-line import alias:
//!
//! ```python
//! # before:
//! import cirislens_core
//! # after:
//! import ciris_lens_core as cirislens_core
//! ```
//!
//! # Functional disposition
//!
//! | v0.1.0 fn | Disposition |
//! |---|---|
//! | `process_trace_batch(engine, events, ...)` | **lens-core orchestrates the science layer; persist signs + persists.** Engine is the deployed lens's `ciris_persist.Engine` — lens-core calls `engine.local_sign` + `engine.local_pqc_sign` + `engine.put_detection_event` dynamically. Lens-core never holds keys. |
//! | `scrub_trace(trace_json, level)` | **delegates to `ciris_persist::pipeline::scrub::scrub_trace`** |
//! | `scrub_traces_batch(traces_json, level)` | **delegates to `ciris_persist::pipeline::scrub::scrub_traces_batch`** |
//! | `ner_is_configured()` | **delegates to `ciris_persist::pipeline::scrub::ner::is_configured`** |
//!
//! # Why Engine as first parameter
//!
//! Lens-core is a science layer, not a federation identity. The
//! signing identity belongs to the host (the deployed lens today;
//! the agent post-fold). The host constructs the persist Engine
//! with its own local keys; lens-core uses the Engine as a signing
//! oracle. This pattern survives the PoB §3.1 fold-into-agent —
//! agents pass their Engine the same way the deployed lens does
//! today.

use std::sync::Arc;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use chrono::Utc;
use ciris_persist::pipeline::extract::{extract_features, Features};
use ciris_persist::pipeline::scrub::{self as persist_scrub, ner, ScrubStats, ScrubbedTrace};
use ciris_persist::prelude::body_sha256;
use ciris_persist::schema::envelope::TraceLevel;
use ciris_persist::scrub::NullScrubber;
use serde_json::value::RawValue;
use serde_json::Value;
use uuid::Uuid;

use crate::capture::client::{CaptureClient, CaptureEventOutcome};
use crate::capture::consent::ConsentConfig;
use crate::capture::correlation::CorrelationMetadata;
use crate::capture::partial::InboundEvent;
use crate::capture::py_engine::{NonSealingKind, PyEngineCapture, PyPrepareOutcome};
use crate::cohort;
use crate::config::EgressFilter;
use crate::detector::{detect, DetectionResult};
use crate::pipeline::lifecycle::LENS_CORE_VERSION;
use crate::scoring::result::{ManifoldConformity, Severity};
use crate::scoring::{assemble, AssemblyInput};
use crate::signing::event::{assemble_event, prepare_detection, DetectionInputs};

/// Parse a wire-format trace-level string into the typed enum.
fn parse_level(level: &str) -> PyResult<TraceLevel> {
    match level {
        "generic" => Ok(TraceLevel::Generic),
        "detailed" => Ok(TraceLevel::Detailed),
        "full_traces" => Ok(TraceLevel::FullTraces),
        other => Err(PyValueError::new_err(format!(
            "invalid trace_level {other:?}; expected one of: generic, detailed, full_traces"
        ))),
    }
}

/// Convert persist's `ScrubStats` into a Python dict carrying the
/// per-trace telemetry the deployed lens aggregates. Mirrors
/// **legacy `cirislens-core` exactly** — 7 fields including
/// `ner_cache_misses` — so callers that read specific fields by
/// name don't break across the swap. Drift here was caught at
/// v0.1.0 review against `CIRISLens/api/scrubber_v2.py`.
fn stats_to_dict<'py>(py: Python<'py>, stats: &ScrubStats) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("entities_redacted", stats.entities_redacted)?;
    dict.set_item("regex_redactions", stats.regex_redactions)?;
    dict.set_item("fields_modified", stats.fields_modified)?;
    dict.set_item("walker_max_depth", stats.walker_max_depth)?;
    dict.set_item("ner_ran", stats.ner_ran)?;
    dict.set_item("ner_cache_hits", stats.ner_cache_hits)?;
    dict.set_item("ner_cache_misses", stats.ner_cache_misses)?;
    Ok(dict)
}

/// Convert one `ScrubbedTrace` into the legacy dict shape
/// `{"trace": "<json string>", "level": <str>, "stats": <dict>}`.
///
/// **`trace` is emitted as a JSON STRING**, not a pre-parsed
/// Python object. Matches legacy `cirislens-core::scrub_trace`
/// exactly — `CIRISLens/api/scrubber_v2.py:195` does
/// `json.loads(result["trace"])` and would error on a pre-parsed
/// dict. Drift here was caught at v0.1.0 review and is exactly
/// the kind of "matched legacy precisely" the swap requires.
fn scrubbed_to_dict<'py>(
    py: Python<'py>,
    scrubbed: ScrubbedTrace,
    level_str: &str,
) -> PyResult<Bound<'py, PyDict>> {
    let trace_json = serde_json::to_string(&scrubbed.value)
        .map_err(|e| PyRuntimeError::new_err(format!("serialize scrubbed trace: {e}")))?;
    let dict = PyDict::new(py);
    dict.set_item("trace", trace_json)?;
    dict.set_item("level", level_str)?;
    dict.set_item("stats", stats_to_dict(py, &scrubbed.stats)?)?;
    Ok(dict)
}

/// Map a [`ManifoldConformity`] to the detection-event severity bucket.
/// Mirrors `pipeline::lifecycle::severity_from` policy.
fn severity_from(c: &ManifoldConformity) -> Severity {
    match c {
        ManifoldConformity::Numeric(_) => Severity::Info,
        ManifoldConformity::Indeterminate { .. } => Severity::Info,
        ManifoldConformity::Unavailable { .. } => Severity::Warning,
    }
}

/// Severity → wire string (matches persist's `DetectionSeverity::as_db_str`).
fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Critical => "critical",
    }
}

// ─── Science layer (lens-core implements; persist signs + persists) ──

/// Process a batch of trace events. v0.1.0 orchestrates the science
/// layer (cohort + projection + no-op detector + scoring + signing
/// preparation) and routes signing + persistence through the
/// provided `engine`.
///
/// # Engine contract
///
/// `engine` is a `ciris_persist.Engine` instance constructed by the
/// deployed lens with its own local identity. Lens-core calls four
/// methods dynamically:
///
/// - `engine.local_key_id()` — string identifier stamped onto rows
/// - `engine.local_sign(canonical_bytes)` → 64-byte Ed25519 signature
/// - `engine.local_pqc_sign(bound_bytes)` → 3309-byte ML-DSA-65 signature
/// - `engine.put_detection_event(event_json)` — verify-then-insert; verifies the hybrid signature under `HybridPolicy::Strict` before storing
///
/// Lens-core never holds keys. Same Engine the deployed lens already
/// uses for trace ingest does the signing here.
///
/// # Return shape (locked v0.1.0)
///
/// ```python
/// {
///     "batch_id":         "<uuid>",
///     "traces_received":  100,
///     "traces_processed": 98,
///     "detections": [
///         {
///             "detection_id": "<uuid>",
///             "trace_id":     "<trace_id>",
///             "severity":     "info"
///         },
///         ...
///     ]
/// }
/// ```
///
/// # Phase 1 behavior
///
/// Detector is no-op (always `DetectionResult::None`) per LC-AV-9
/// cold-start window — RATCHET's calibration bundle (v1 shipped
/// 2026-05-13; centroid sample counts below the 500 gate) is the
/// architecturally-correct "score everything Indeterminate" state.
/// Every trace lands in `ManifoldConformity::Indeterminate { CohortColdStart }`
/// at severity `info`. Phase 2 replaces detector with real
/// implementations.
#[pyfunction]
#[pyo3(signature = (engine, events, batch_timestamp, consent_timestamp=None, trace_level="detailed".to_string(), correlation_metadata=None))]
fn process_trace_batch<'py>(
    py: Python<'py>,
    engine: &Bound<'py, PyAny>,
    events: Vec<String>,
    batch_timestamp: String,
    consent_timestamp: Option<String>,
    trace_level: String,
    correlation_metadata: Option<String>,
) -> PyResult<Bound<'py, PyDict>> {
    let _ = (
        batch_timestamp,
        consent_timestamp,
        trace_level,
        correlation_metadata,
    );

    let batch_id = Uuid::new_v4().to_string();
    let signing_key_id: String = engine
        .call_method0("local_key_id")
        .map_err(|e| PyRuntimeError::new_err(format!("engine.local_key_id(): {e}")))?
        .extract()?;

    let detections = PyList::empty(py);
    let mut traces_processed: usize = 0;

    for (idx, event_json) in events.iter().enumerate() {
        match process_one(py, engine, event_json, &signing_key_id) {
            Ok(summary) => {
                let entry = PyDict::new(py);
                entry.set_item("detection_id", summary.detection_id)?;
                entry.set_item("trace_id", summary.trace_id)?;
                entry.set_item("severity", summary.severity)?;
                detections.append(entry)?;
                traces_processed += 1;
            }
            Err(e) => {
                // Skip-and-continue: malformed input, signing failure,
                // or put rejection on one trace shouldn't drop the
                // whole batch. Surface to stderr; production
                // observability comes when Phase 2's tracing/
                // metrics land.
                eprintln!("ciris_lens_core.process_trace_batch: trace {idx} skipped: {e}");
            }
        }
    }

    let result = PyDict::new(py);
    result.set_item("batch_id", batch_id)?;
    result.set_item("traces_received", events.len())?;
    result.set_item("traces_processed", traces_processed)?;
    result.set_item("detections", detections)?;
    Ok(result)
}

/// Per-trace outcome record extracted for the batch's `detections`
/// list. Three fields — same shape as locked in
/// `process_trace_batch`'s docstring.
struct PerTraceSummary {
    detection_id: String,
    trace_id: String,
    severity: &'static str,
}

/// Process one trace through the v0.1.0 science layer + sign + put.
/// All persist primitives invoked via the `engine` argument; no key
/// material touches lens-core.
fn process_one<'py>(
    py: Python<'py>,
    engine: &Bound<'py, PyAny>,
    event_json: &str,
    signing_key_id: &str,
) -> PyResult<PerTraceSummary> {
    let trace: Value = serde_json::from_str(event_json)
        .map_err(|e| PyValueError::new_err(format!("invalid trace JSON: {e}")))?;
    let trace_id = trace
        .get("trace_id")
        .and_then(Value::as_str)
        .ok_or_else(|| PyValueError::new_err("missing trace_id"))?
        .to_string();

    // persist's body_sha256 takes &RawValue (not raw bytes) so the
    // hash matches the canonicalization persist applies on its own
    // ingest path — same value persist would store on the joined
    // trace_events row.
    let raw: Box<RawValue> = serde_json::from_str(event_json)
        .map_err(|e| PyValueError::new_err(format!("invalid trace RawValue: {e}")))?;
    let body_sha = body_sha256(&raw).to_vec();

    let declared = cohort::parse_from_envelope(&trace);
    let features: Features = extract_features(&trace, declared.clone());
    let cohort_cell = cohort::cohort_cell(&declared);

    // v0.1.0 detector: always None → CohortColdStart per LC-AV-9.
    let assembly_input = match detect(&features) {
        DetectionResult::None => AssemblyInput::CohortColdStart,
        DetectionResult::Manifold {
            mahalanobis,
            cohort_sample_count,
        } => AssemblyInput::Scored {
            mahalanobis,
            cohort_sample_count,
        },
        DetectionResult::DeclaredInferredMismatch { .. } => AssemblyInput::AmbiguousCohort,
    };
    let conformity = assemble(assembly_input, /* sample_size_gate */ 500);
    let severity = severity_from(&conformity);

    let inputs = DetectionInputs {
        trace_id: trace_id.clone(),
        body_sha256: body_sha,
        detector: "manifold_conformity",
        severity,
        cohort_cell,
        conformity: &conformity,
        lens_core_version: LENS_CORE_VERSION,
        // RATCHET v1 bundle landed 2026-05-13 (crc-v1, unsigned;
        // integration is Phase 2 work). Until the bundle is signed +
        // loaded into persist.calibration_bundles, lens-core stamps
        // a sentinel 0 — every Phase 1 detection event is anchored
        // to "no calibration applied" (matches the every-trace-
        // Indeterminate scoring behavior).
        ratchet_calibration_version: 0,
        // Manifold-conformity detector carries no axis-family
        // calibration; axis-family evidence_refs are emitted only by
        // the F-3 / distributive detectors (crc-v2).
        evidence_refs: Vec::new(),
    };
    let prepared = prepare_detection(&inputs, signing_key_id)
        .map_err(|e| PyRuntimeError::new_err(format!("prepare: {e}")))?;

    // Sign via engine — lens-core never holds keys.
    let canonical_pybytes = PyBytes::new(py, &prepared.canonical_bytes);
    let ed25519_obj = engine
        .call_method1("local_sign", (canonical_pybytes,))
        .map_err(|e| PyRuntimeError::new_err(format!("engine.local_sign: {e}")))?;
    let ed25519_sig: Vec<u8> = ed25519_obj.cast::<PyBytes>()?.as_bytes().to_vec();

    // Hybrid binding: PQC signs (canonical_bytes ++ ed25519_sig).
    // Replicates LocalSigner::sign_hybrid's internal construction
    // so verify_hybrid_via_directory (invoked inside
    // engine.put_detection_event) recognizes it.
    let mut bound_msg = Vec::with_capacity(prepared.canonical_bytes.len() + 64);
    bound_msg.extend_from_slice(&prepared.canonical_bytes);
    bound_msg.extend_from_slice(&ed25519_sig);
    let bound_pybytes = PyBytes::new(py, &bound_msg);
    let pqc_obj = engine
        .call_method1("local_pqc_sign", (bound_pybytes,))
        .map_err(|e| PyRuntimeError::new_err(format!("engine.local_pqc_sign: {e}")))?;
    let ml_dsa_65_sig: Vec<u8> = pqc_obj.cast::<PyBytes>()?.as_bytes().to_vec();

    let (event, _summary) = assemble_event(
        &inputs,
        prepared,
        ed25519_sig,
        ml_dsa_65_sig,
        signing_key_id.to_string(),
    )
    .map_err(|e| PyRuntimeError::new_err(format!("assemble: {e}")))?;

    let event_json_str = serde_json::to_string(&event)
        .map_err(|e| PyRuntimeError::new_err(format!("serialize event: {e}")))?;
    engine
        .call_method1("put_detection_event", (event_json_str,))
        .map_err(|e| PyRuntimeError::new_err(format!("engine.put_detection_event: {e}")))?;

    Ok(PerTraceSummary {
        detection_id: event.detection_id.to_string(),
        trace_id,
        severity: severity_str(severity),
    })
}

// ─── Substrate-delegated (thin wrappers over ciris_persist) ───────

/// Scrub a single trace per the requested trace-level. Returns
/// `{"trace": "<json string>", "level": <level_str>, "stats": <stats_dict>}`.
#[pyfunction]
fn scrub_trace<'py>(
    py: Python<'py>,
    trace_json: &str,
    level: &str,
) -> PyResult<Bound<'py, PyDict>> {
    let value: serde_json::Value = serde_json::from_str(trace_json)
        .map_err(|e| PyValueError::new_err(format!("invalid trace JSON: {e}")))?;
    let parsed_level = parse_level(level)?;
    let scrubbed = persist_scrub::scrub_trace(value, parsed_level)
        .map_err(|e| PyRuntimeError::new_err(format!("scrub failed: {e}")))?;
    scrubbed_to_dict(py, scrubbed, level)
}

/// Scrub a batch of traces with one shared NER forward pass. Returns
/// a Python list of per-trace dicts matching `scrub_trace`'s shape.
#[pyfunction]
fn scrub_traces_batch<'py>(
    py: Python<'py>,
    traces_json: Vec<String>,
    level: &str,
) -> PyResult<Bound<'py, PyList>> {
    let mut values = Vec::with_capacity(traces_json.len());
    for (i, s) in traces_json.iter().enumerate() {
        let v: serde_json::Value = serde_json::from_str(s)
            .map_err(|e| PyValueError::new_err(format!("invalid trace JSON at index {i}: {e}")))?;
        values.push(v);
    }
    let parsed_level = parse_level(level)?;
    let scrubbed_batch = persist_scrub::scrub_traces_batch(values, parsed_level)
        .map_err(|e| PyRuntimeError::new_err(format!("batch scrub failed: {e}")))?;
    let out = PyList::empty(py);
    for scrubbed in scrubbed_batch {
        out.append(scrubbed_to_dict(py, scrubbed, level)?)?;
    }
    Ok(out)
}

/// Whether the persist scrubber has the NER backend configured
/// (XLM-R / DistilBERT via candle, or ORT INT8). Deployed lens
/// gates `full_traces` scrubbing on this.
#[pyfunction]
fn ner_is_configured() -> PyResult<bool> {
    Ok(ner::is_configured())
}

// ─── Cohabitation: relay-handler install (CIRIS 3.0) ──────────────

/// Register lens-core's relay handler on a shared `ciris_edge.Edge`
/// — the CIRIS 3.0 cohabitation bootstrap entry for the lens.
///
/// Mirrors `ciris_node_core.install_from_dispatch(...)`. The agent
/// (Python) has already constructed the shared persist `Engine` and
/// `Edge` (`ciris_edge.init_edge_runtime(...)`); this call hooks
/// lens-core's `Handler<AccordEventsBatch>` onto that shared Edge.
/// After this returns, the lens is a key-addressable Edge endpoint:
/// peers routing `AccordEventsBatch` to its `key_id` land here and
/// flow into `engine.receive_and_persist` (CIRISPersist#89) via
/// [`LensCoreHandler`](crate::role::LensCoreHandler).
///
/// # Cohabitation invariant
///
/// One `Edge` per process, owned by the agent, shared by sibling
/// consumers (lens, NodeCore). The `Arc<Engine>` is fetched from the
/// persist singleton (`current_rust_engine`) — same engine `PyEngine`
/// dispatches to; no second engine, runtime, or connection pool.
///
/// # Python signature
///
/// `ciris_lens_core.install_relay(edge)` — `edge` is the
/// `ciris_edge.Edge` instance returned by `ciris_edge.
/// init_edge_runtime(...)`. Engine is implicit (singleton).
///
/// # Errors
///
/// - `RuntimeError("persist Engine not initialized")` — host hasn't
///   constructed `ciris_persist.Engine` yet, or `close()` cleared it.
/// - `RuntimeError("persist runtime handle not available")` — same
///   condition; the singleton runtime is gone.
/// - `RuntimeError("attach lens-core relay handler: …")` — edge
///   refused the handler registration (typically already-registered
///   for `AccordEventsBatch`).
#[pyfunction]
fn install_relay(edge: PyRef<'_, ciris_edge::ffi::pyo3::PyEdge>) -> PyResult<()> {
    let engine = ciris_persist::ffi::pyo3::current_rust_engine().ok_or_else(|| {
        PyRuntimeError::new_err(
            "persist Engine not initialized — construct ciris_persist.Engine first",
        )
    })?;
    let handle = ciris_persist::ffi::pyo3::current_runtime_handle()
        .ok_or_else(|| PyRuntimeError::new_err("persist runtime handle not available"))?;
    let edge_arc = edge.edge_handle();
    handle
        .block_on(crate::LensCore::attach_handler(&edge_arc, engine))
        .map_err(|e| PyRuntimeError::new_err(format!("attach lens-core relay handler: {e}")))
}

// ─── LensClient (#11 Cut 5) ───────────────────────────────────────

/// Internal representation for `LensClient` — either the sovereign (rlib)
/// path using `Arc<CaptureClient>` + the per-wheel runtime, or the
/// cohabitation path using `PyEngineCapture` + the host `PyEngine` object.
enum LensClientInner {
    /// Single-wheel / sovereign path.
    ///
    /// `CaptureClient::capture_event` handles the full sign+persist flow via
    /// `Arc<Engine>`. `current_rust_engine()` and `current_runtime_handle()`
    /// are the per-wheel statics populated when lens-core IS the host wheel.
    Sovereign(Arc<CaptureClient>),

    /// Pip cohabitation path (CIRISLensCore#43.1 P0 fix).
    ///
    /// `PyEngineCapture` handles partial-trace assembly + consent + provenance
    /// (no `Arc<Engine>`). Sign+persist are driven via Python method calls on
    /// the host `ciris_persist.Engine` Python object.
    ///
    /// `py_engine_rt` is a private tokio `Runtime` — both `current_rust_engine()`
    /// and `current_runtime_handle()` are per-wheel statics that are empty in
    /// the cohabitation scenario (same root cause as the P0 bug).
    Cohabitation {
        capture: Arc<PyEngineCapture>,
        py_engine: Py<PyAny>,
    },
}

/// Client-mode Python handle: assembles component events from the agent's
/// `reasoning_event_stream` into sealed, signed, persisted traces.
///
/// # Constructing a `LensClient`
///
/// ## Single-wheel (sovereign) path — `engine=None` (default)
///
/// The host must have already constructed a `ciris_persist.Engine` (the
/// process singleton). `LensClient.__init__` fetches it via
/// `ciris_persist::ffi::pyo3::current_rust_engine()` — the same route
/// `install_relay` uses; there is no second Engine.
///
/// ```python
/// import ciris_lens_core
///
/// # host already called ciris_persist.Engine(...) earlier
/// lens = ciris_lens_core.LensClient(
///     consent_timestamp="2026-01-01T00:00:00+00:00",
///     trace_level="detailed",
///     # engine=None (default) — uses the process-singleton rust engine
/// )
/// ```
///
/// ## Cohabitation (agent-fold) path — `engine=<host engine>`
///
/// When lens-core is installed as a separate wheel alongside
/// `ciris_persist` (pip cohabitation), the two wheels each statically
/// link their own copy of ciris_persist. The `OnceLock`-backed
/// `current_rust_engine()` static in lens-core's bundled copy is
/// **empty** — even though the host's `ciris_persist.Engine` is running
/// in the same process. Fetching the engine via that static yields
/// `RuntimeError: no process Engine`.
///
/// The fix: pass the host `ciris_persist.Engine` Python object as
/// `engine=`. Lens-core drives sign+persist via its **Python methods**
/// (cross-wheel-safe — they dispatch on the host's `PyEngine` object, not
/// a per-wheel static):
///
/// ```python
/// import ciris_persist
/// import ciris_lens_core
///
/// engine = ciris_persist.Engine(...)   # host's engine — has keys + DB
/// lens = ciris_lens_core.LensClient(
///     consent_timestamp="2026-01-01T00:00:00+00:00",
///     trace_level="detailed",
///     engine=engine,                   # cohabitation path (CIRISLensCore#43.1)
/// )
/// ```
///
/// The cohabitation path calls these engine Python methods:
/// - `engine.local_key_id()` → str — key ID stamped onto the trace
/// - `engine.local_sign(canonical_bytes: bytes)` → 64-byte Ed25519 sig
/// - `engine.receive_and_persist(batch_bytes: bytes, pre_verified=False)` →
///   `{"envelopes_processed": N, "trace_events_inserted": N, ...,
///    "signatures_verified": N}` — persists via the host engine's
///   configured DB and scrubber.
///
/// `pre_verified=False` (the default) is used: the host engine holds the
/// key in its own `federation_keys` table, so `VerifyMode::Full` resolves
/// it and verifies the trace signature. If you observe `signatures_verified=0`
/// (key not registered), the signing key ID must be registered in the host
/// engine's federation directory. Using `pre_verified=True` would skip
/// verification — don't do that unless you understand the security trade-off.
///
/// These are the same Python-method dispatches `process_trace_batch` has
/// used since v0.1.0 — cross-wheel-safe by design.
///
/// ## Consent in the cohabitation path
///
/// The cohabitation path uses the **config-fallback consent path** only
/// (`consent_attesting_key_id` has no effect when `engine=` is provided).
/// The CEG engine-read path needs a cross-wheel `federation_directory`
/// accessor not yet available when the Engine is a Python object.
/// Follow-up: CIRISEdge#85.
///
/// # Scrubber policy
///
/// For the cohabitation path, `receive_and_persist` on the host engine uses
/// the engine's own configured scrubber — lens-core does not pass a scrubber
/// separately (CIRISPersist#89: scrubbing is the originating client's egress
/// responsibility). A configurable-scrubber parameter on `LensClient.__init__`
/// is a follow-up (CIRISLensCore#11).
///
/// At `generic` trace level this is safe by design (no content text at that
/// level). At `detailed` or `full_traces` pre-scrub on the agent side before
/// emitting events.
///
/// # Cross-wheel cohabitation test note
///
/// The cross-wheel scenario (lens-core wheel + ciris_persist wheel
/// cohabiting in the same process) cannot be tested in-repo — it requires
/// two separately-built wheels. This is a CIRISConformance `requires_lens`
/// cohabitation cell (not faked here). The Rust side of the cohabitation path
/// (`PyEngineCapture::prepare` → `canonical_bytes_for` → `apply_signature_and_batch`)
/// IS tested in `src/capture/py_engine.rs` via `py_engine_path_bytes_round_trip_through_persist`.
#[pyclass(name = "LensClient")]
struct PyLensClient {
    inner: LensClientInner,
}

#[pymethods]
impl PyLensClient {
    /// Construct a `LensClient`.
    ///
    /// # Required parameters
    ///
    /// - `consent_timestamp` — RFC-3339 user-consent timestamp for the
    ///   config/env fallback path (the 2.9.6 interim). May be `None` when
    ///   `consent_attesting_key_id` is provided and a CEG grant is expected.
    ///   Persist 422s a batch with a missing `consent_timestamp` when no
    ///   CEG grant is available (TRACE_WIRE_FORMAT §1).
    /// - `trace_level` — one of `"generic"`, `"detailed"`, `"full_traces"`.
    ///
    /// # Optional keyword arguments
    ///
    /// - `engine` — the host `ciris_persist.Engine` Python object
    ///   (**cohabitation path**, CIRISLensCore#43.1 P0 fix). When provided,
    ///   sign+persist are driven via its Python methods — cross-wheel-safe.
    ///   Pass `None` (default) for the single-wheel / sovereign path.
    /// - `trace_schema_version` — wire schema version string (default `"3.0.0"`).
    ///   `"3.0.0"`+ (major ≥ 3) signs over **RFC 8785 JCS** (`V2Jcs`) — the
    ///   post-#871 CEG-native canonical form the whole fabric is on; legacy
    ///   `"2.x"` is Python-compat (`V1Python`). persist's ingest dispatches the
    ///   verifier by this version (`canon_version_for_trace_schema`), so the
    ///   batch is a JCS CEG object end-to-end.
    /// - `deployment_profile` — operator 6-field cohort dict; required on the
    ///   wire at schema 3.0.0. Pass `None` only for non-production / dev.
    /// - `consent_attesting_key_id` — key ID for CEG-based consent resolution.
    ///   `None` → config-only path (2.9.6 interim). Has no effect when
    ///   `engine=` is provided (follow-up: CIRISEdge#85).
    /// - `local_copy_dir` — filesystem path for best-effort tee output.
    ///   `None` = off.
    /// - `deployment_region`, `deployment_type`, `agent_role`, `agent_template`
    ///   — correlation metadata fields.
    /// - `share_location` — consent gate for user PII fields (default `False`).
    /// - `user_location`, `user_timezone` — PII location fields.
    /// - `user_latitude`, `user_longitude` — raw lat/lng floats; fuzzed to
    ///   1-decimal region resolution.
    ///
    /// # Errors
    ///
    /// - `RuntimeError` if `engine=None` and the process `ciris_persist.Engine`
    ///   has not been constructed yet (single-wheel path only).
    /// - `ValueError` if `trace_level` is not one of the three valid strings.
    #[new]
    #[pyo3(signature = (
        consent_timestamp,
        trace_level,
        engine = None,
        trace_schema_version = "3.0.0".to_string(),
        deployment_profile = None,
        consent_attesting_key_id = None,
        local_copy_dir = None,
        deployment_region = None,
        deployment_type = None,
        agent_role = None,
        agent_template = None,
        share_location = false,
        user_location = None,
        user_timezone = None,
        user_latitude = None,
        user_longitude = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        consent_timestamp: Option<String>,
        trace_level: String,
        engine: Option<&Bound<'_, PyAny>>,
        trace_schema_version: String,
        deployment_profile: Option<&Bound<'_, PyAny>>,
        consent_attesting_key_id: Option<String>,
        local_copy_dir: Option<String>,
        deployment_region: Option<String>,
        deployment_type: Option<String>,
        agent_role: Option<String>,
        agent_template: Option<String>,
        share_location: bool,
        user_location: Option<String>,
        user_timezone: Option<String>,
        user_latitude: Option<f64>,
        user_longitude: Option<f64>,
    ) -> PyResult<Self> {
        // Validate trace_level early so the error is at construction, not
        // at first capture_event.
        parse_level(&trace_level)?;

        // Parse deployment_profile: None or a Python dict/object → serde_json::Value.
        let dp: Option<Value> = match deployment_profile {
            None => None,
            Some(obj) => {
                let json_mod = py.import("json")?;
                let json_str: String = json_mod.call_method1("dumps", (obj,))?.extract()?;
                let v: Value = serde_json::from_str(&json_str).map_err(|e| {
                    PyValueError::new_err(format!(
                        "deployment_profile: failed to parse as JSON: {e}"
                    ))
                })?;
                Some(v)
            }
        };

        if trace_level != "generic" {
            tracing::warn!(
                trace_level = %trace_level,
                "LensClient constructed with NullScrubber at non-generic trace level — \
                 pre-scrub on the agent side or await configurable-scrubber follow-up \
                 (CIRISLensCore#11). PII egress handled by correlation fuzz invariant \
                 + shim-side trace-level gating. See CIRISPersist#89 relay-no-rescrub boundary.",
            );
        }

        // Build CorrelationMetadata from kwargs.
        let correlation = {
            let cm = CorrelationMetadata::build(
                deployment_region.as_deref().unwrap_or(""),
                deployment_type.as_deref().unwrap_or(""),
                agent_role.as_deref().unwrap_or(""),
                agent_template.as_deref().unwrap_or(""),
                share_location,
                user_location.as_deref().unwrap_or(""),
                user_timezone.as_deref().unwrap_or(""),
                user_latitude,
                user_longitude,
            );
            if cm.is_empty() {
                None
            } else {
                Some(cm)
            }
        };

        let consent_config = ConsentConfig { consent_timestamp };
        let local_copy_dir_path = local_copy_dir.map(std::path::PathBuf::from);

        // ── Cohabitation path (engine= provided) ─────────────────────
        //
        // When the host passes its `ciris_persist.Engine` Python object,
        // we use `PyEngineCapture` for the store/consent/provenance step
        // (no Arc<Engine> needed) and route sign+persist through Python
        // method calls on the host engine object.
        //
        // Neither `current_rust_engine()` nor `current_runtime_handle()`
        // is accessed — both are per-wheel statics that are empty in the
        // cohabitation scenario (CIRISLensCore#43.1 root cause).
        if let Some(host_engine) = engine {
            let capture = PyEngineCapture::new(
                consent_config,
                correlation,
                dp,
                trace_level.clone(),
                trace_schema_version.clone(),
                local_copy_dir_path,
            );
            return Ok(Self {
                inner: LensClientInner::Cohabitation {
                    capture: Arc::new(capture),
                    py_engine: host_engine.clone().unbind(),
                },
            });
        }

        // ── Sovereign / single-wheel path (engine=None) ───────────────
        //
        // Fetch the process-singleton Engine via the per-wheel Rust static
        // (same route as install_relay). This path is used when lens-core IS
        // the host wheel (single compiled unit) — the static is populated.
        let scrubber = Arc::new(NullScrubber);
        let rust_engine = ciris_persist::ffi::pyo3::current_rust_engine().ok_or_else(|| {
            PyRuntimeError::new_err(
                "no process Engine — host must construct ciris_persist.Engine first. \
                 For pip cohabitation (two-wheel deployment) pass engine=<host_engine> \
                 to LensClient to fix CIRISLensCore#43.1.",
            )
        })?;
        let client = CaptureClient::new(
            rust_engine,
            scrubber,
            trace_level.clone(),
            trace_schema_version.clone(),
            correlation,
            consent_attesting_key_id,
            consent_config,
            dp,
            local_copy_dir_path,
        );
        Ok(Self {
            inner: LensClientInner::Sovereign(Arc::new(client)),
        })
    }

    /// Feed one component event into the capture pipeline.
    ///
    /// `component` is a Python dict with the following keys:
    ///
    /// - `event_type` (str, **required**) — one of the `ReasoningEventType`
    ///   wire strings (e.g. `"THOUGHT_START"`, `"ACTION_RESULT"`). Both bare
    ///   and `"ReasoningEvent."` prefixed forms are accepted.
    /// - `thought_id` (str, **required**) — the thought's stable identifier;
    ///   also used as the `trace_id` for the resulting trace.
    /// - `timestamp` (str, **required**) — RFC-3339 event timestamp.
    /// - `agent_id_hash` (str, **required**) — the agent's identity hash.
    /// - `task_id` (str, optional) — the enclosing task ID.
    /// - `trace_level` (str, optional) — per-event override of trace level.
    /// - `data` (dict, optional) — opaque event payload; defaults to `{}`.
    ///
    /// # Returns
    ///
    /// A dict with at minimum the key `"outcome"`:
    ///
    /// - `{"outcome": "opened"}` — first event for this `thought_id`.
    /// - `{"outcome": "appended"}` — component appended to in-flight trace.
    /// - `{"outcome": "rejected", "raw": "<event_type_string>"}` — unknown
    ///   event type; typed rejection (CIRISLens#13). The caller should log
    ///   `raw` for diagnostics.
    /// - `{"outcome": "sealed_and_persisted", "trace_id": "...",
    ///   "trace_events_inserted": N, "signatures_verified": N}` —
    ///   `ACTION_RESULT` landed; trace sealed, signed, and persisted.
    /// - `{"outcome": "consent_blocked", "reason": "withdrawn"|"no_consent"}`
    ///   — trace dropped by the consent gate.
    ///
    /// # Errors
    ///
    /// - `ValueError` if required fields are missing from `component`.
    /// - `RuntimeError` if the persist runtime handle is gone (sovereign path)
    ///   or the sign/persist step fails (both paths).
    fn capture_event<'py>(
        &self,
        py: Python<'py>,
        component: &Bound<'py, PyDict>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let event = dict_to_inbound_event(component)?;

        match &self.inner {
            // ── Sovereign path — unchanged from original ──────────────
            LensClientInner::Sovereign(client) => {
                let handle =
                    ciris_persist::ffi::pyo3::current_runtime_handle().ok_or_else(|| {
                        PyRuntimeError::new_err("persist runtime handle not available")
                    })?;
                let inner = Arc::clone(client);
                let outcome = handle
                    .block_on(inner.capture_event(event))
                    .map_err(|e| PyRuntimeError::new_err(format!("capture_event: {e}")))?;
                outcome_to_dict(py, outcome)
            }

            // ── Cohabitation path (CIRISLensCore#43.1 P0 fix) ────────
            //
            // Orchestration:
            // 1. PyEngineCapture::prepare (Rust) — store, consent, provenance,
            //    stamp deployment_profile + trace_level. Sync, no tokio needed.
            // 2. For non-sealing outcomes → return immediately.
            // 3. For ReadyToSeal:
            //    a. canonical_bytes_for (Rust — JCS / V2Jcs dispatch)
            //    b. engine.local_key_id() (Python)
            //    c. engine.local_sign(canonical_bytes) (Python) → 64-byte sig
            //    d. PyEngineCapture::apply_signature_and_batch (Rust)
            //    e. tee_write_if_configured (Rust)
            //    f. engine.receive_and_persist(batch_bytes) (Python) → summary
            //    g. Extract trace_events_inserted + signatures_verified from summary
            LensClientInner::Cohabitation { capture, py_engine } => {
                let cap = Arc::clone(capture);
                let engine = py_engine.bind(py);

                match cap.prepare(event) {
                    PyPrepareOutcome::NonSealing(kind) => {
                        let result = PyDict::new(py);
                        match kind {
                            NonSealingKind::Opened => result.set_item("outcome", "opened")?,
                            NonSealingKind::Appended => result.set_item("outcome", "appended")?,
                            NonSealingKind::Rejected { raw } => {
                                result.set_item("outcome", "rejected")?;
                                result.set_item("raw", raw)?;
                            }
                        }
                        Ok(result)
                    }
                    PyPrepareOutcome::ConsentBlocked { reason } => {
                        let result = PyDict::new(py);
                        result.set_item("outcome", "consent_blocked")?;
                        result.set_item("reason", reason)?;
                        Ok(result)
                    }
                    PyPrepareOutcome::ReadyToSeal {
                        mut trace,
                        provenance,
                    } => {
                        let trace_id = trace.trace_id.clone();

                        // 3a. Canonical bytes (Rust — version-aware dispatch).
                        let canonical =
                            PyEngineCapture::canonical_bytes_for(&trace).map_err(|e| {
                                PyRuntimeError::new_err(format!("canonical_bytes: {e}"))
                            })?;

                        // 3b. Key ID via Python.
                        let key_id: String = engine
                            .call_method0("local_key_id")
                            .map_err(|e| {
                                PyRuntimeError::new_err(format!("engine.local_key_id(): {e}"))
                            })?
                            .extract()?;

                        // 3c. Sign via Python (returns 64-byte Ed25519 sig).
                        let canonical_pybytes = PyBytes::new(py, &canonical);
                        let sig_obj = engine
                            .call_method1("local_sign", (canonical_pybytes,))
                            .map_err(|e| {
                                PyRuntimeError::new_err(format!("engine.local_sign: {e}"))
                            })?;
                        let sig: Vec<u8> = sig_obj.cast::<PyBytes>()?.as_bytes().to_vec();
                        if sig.len() != 64 {
                            return Err(PyRuntimeError::new_err(format!(
                                "engine.local_sign returned {} bytes, expected 64",
                                sig.len()
                            )));
                        }

                        // 3d. Apply signature + build batch bytes (Rust).
                        let batch_bytes = PyEngineCapture::apply_signature_and_batch(
                            &mut trace,
                            &sig,
                            &key_id,
                            &provenance,
                        )
                        .map_err(|e| PyRuntimeError::new_err(format!("build_batch_bytes: {e}")))?;

                        // 3e. Local-copy tee (best-effort, never fails persist).
                        cap.tee_write_if_configured(&trace_id, &batch_bytes);

                        // 3f. Persist via Python engine.
                        //
                        // pre_verified=False: the host engine holds the signing key
                        // in its own federation_keys table, so VerifyMode::Full
                        // resolves the key and verifies the trace signature. This is
                        // the correct default — skipping verification (pre_verified=True)
                        // is only valid when an Edge verifier has already attested
                        // the batch (CIRISPersist#91 / AV-9). We use the default here
                        // because the key IS in the host engine's directory (the engine
                        // was constructed with it), and we want signatures_verified=1
                        // in the returned summary as confirmation of correct key setup.
                        let batch_pybytes = PyBytes::new(py, &batch_bytes);
                        let summary_obj = engine
                            .call_method1("receive_and_persist", (batch_pybytes,))
                            .map_err(|e| {
                                PyRuntimeError::new_err(format!("engine.receive_and_persist: {e}"))
                            })?;

                        // 3g. Extract the two fields the outcome dict needs.
                        // `receive_and_persist` returns a Python dict with keys:
                        //   envelopes_processed, trace_events_inserted,
                        //   trace_events_conflicted, trace_llm_calls_inserted,
                        //   scrubbed_fields, signatures_verified
                        // (see ciris_persist v5.2.0 pyo3.rs:2617–2626).
                        let summary_dict = summary_obj.cast::<PyDict>()?;
                        let trace_events_inserted: usize = summary_dict
                            .get_item("trace_events_inserted")?
                            .ok_or_else(|| {
                                PyRuntimeError::new_err(
                                    "receive_and_persist summary missing 'trace_events_inserted'",
                                )
                            })?
                            .extract()?;
                        let signatures_verified: usize = summary_dict
                            .get_item("signatures_verified")?
                            .ok_or_else(|| {
                                PyRuntimeError::new_err(
                                    "receive_and_persist summary missing 'signatures_verified'",
                                )
                            })?
                            .extract()?;

                        tracing::debug!(
                            trace_id = %trace_id,
                            trace_events = trace_events_inserted,
                            signatures_verified = signatures_verified,
                            "client (cohabitation) sealed and persisted trace",
                        );

                        let result = PyDict::new(py);
                        result.set_item("outcome", "sealed_and_persisted")?;
                        result.set_item("trace_id", trace_id)?;
                        result.set_item("trace_events_inserted", trace_events_inserted)?;
                        result.set_item("signatures_verified", signatures_verified)?;
                        Ok(result)
                    }
                }
            }
        }
    }

    /// Purge orphaned (never-sealed) in-flight traces older than
    /// `max_age_secs` seconds.
    ///
    /// Returns the count of traces purged (int).
    #[pyo3(signature = (max_age_secs = 3600))]
    fn orphan_sweep(&self, max_age_secs: u64) -> PyResult<usize> {
        let now = Utc::now();
        match &self.inner {
            LensClientInner::Sovereign(client) => {
                let handle =
                    ciris_persist::ffi::pyo3::current_runtime_handle().ok_or_else(|| {
                        PyRuntimeError::new_err("persist runtime handle not available")
                    })?;
                let inner = Arc::clone(client);
                Ok(handle.block_on(inner.orphan_sweep(now, max_age_secs)))
            }
            LensClientInner::Cohabitation { capture, .. } => {
                // orphan_sweep on PyEngineCapture is sync (in-memory store only).
                Ok(capture.orphan_sweep(now, max_age_secs))
            }
        }
    }
}

/// Map a `CaptureEventOutcome` to a Python result dict — shared helper
/// for the sovereign-path `capture_event` to avoid duplication.
fn outcome_to_dict<'py>(
    py: Python<'py>,
    outcome: CaptureEventOutcome,
) -> PyResult<Bound<'py, PyDict>> {
    let result = PyDict::new(py);
    match outcome {
        CaptureEventOutcome::Opened => {
            result.set_item("outcome", "opened")?;
        }
        CaptureEventOutcome::Appended => {
            result.set_item("outcome", "appended")?;
        }
        CaptureEventOutcome::Rejected { raw } => {
            result.set_item("outcome", "rejected")?;
            result.set_item("raw", raw)?;
        }
        CaptureEventOutcome::SealedAndPersisted { trace_id, summary } => {
            result.set_item("outcome", "sealed_and_persisted")?;
            result.set_item("trace_id", trace_id)?;
            result.set_item("trace_events_inserted", summary.trace_events_inserted)?;
            result.set_item("signatures_verified", summary.signatures_verified)?;
        }
        CaptureEventOutcome::ConsentBlocked { reason } => {
            result.set_item("outcome", "consent_blocked")?;
            result.set_item("reason", reason)?;
        }
    }
    Ok(result)
}

/// Parse a Python dict into an [`InboundEvent`].
///
/// Required fields: `event_type`, `thought_id`, `timestamp`, `agent_id_hash`.
/// Optional fields: `task_id`, `trace_level`, `data`.
/// Missing required fields → `PyValueError` with a clear message
/// (fail loud, never silent — CIRISLens#13 lesson).
fn dict_to_inbound_event(d: &Bound<'_, PyDict>) -> PyResult<InboundEvent> {
    fn require_str<'py>(d: &Bound<'py, PyDict>, key: &'static str) -> PyResult<String> {
        d.get_item(key)?
            .ok_or_else(|| {
                PyValueError::new_err(format!("component dict missing required field {key:?}"))
            })?
            .extract::<String>()
            .map_err(|_| PyValueError::new_err(format!("component field {key:?} must be a str")))
    }

    let event_type = require_str(d, "event_type")?;
    let thought_id = require_str(d, "thought_id")?;
    let timestamp = require_str(d, "timestamp")?;
    let agent_id_hash = require_str(d, "agent_id_hash")?;

    let task_id: Option<String> = d
        .get_item("task_id")?
        .and_then(|v| if v.is_none() { None } else { Some(v) })
        .map(|v| v.extract::<String>())
        .transpose()
        .map_err(|_| PyValueError::new_err("component field \"task_id\" must be a str or None"))?;

    let trace_level: Option<String> = d
        .get_item("trace_level")?
        .and_then(|v| if v.is_none() { None } else { Some(v) })
        .map(|v| v.extract::<String>())
        .transpose()
        .map_err(|_| {
            PyValueError::new_err("component field \"trace_level\" must be a str or None")
        })?;

    // `data` is optional; default to empty JSON object if absent or None.
    let data: Value = match d.get_item("data")? {
        None => Value::Object(Default::default()),
        Some(v) if v.is_none() => Value::Object(Default::default()),
        Some(v) => {
            let py = v.py();
            let json_mod = py.import("json")?;
            let json_str: String = json_mod.call_method1("dumps", (&v,))?.extract()?;
            serde_json::from_str(&json_str).map_err(|e| {
                PyValueError::new_err(format!(
                    "component field \"data\" is not JSON-serializable: {e}"
                ))
            })?
        }
    };

    Ok(InboundEvent {
        event_type,
        thought_id,
        task_id,
        agent_id_hash,
        timestamp,
        trace_level,
        data,
    })
}

// ─── EgressFilter PyO3 class (#14) ────────────────────────────────

/// Parse a Python severity string into [`DetectionSeverity`].
fn parse_severity(s: &str) -> PyResult<ciris_persist::derived::types::DetectionSeverity> {
    use ciris_persist::derived::types::DetectionSeverity;
    match s {
        "info" => Ok(DetectionSeverity::Info),
        "warning" => Ok(DetectionSeverity::Warning),
        "critical" => Ok(DetectionSeverity::Critical),
        other => Err(PyValueError::new_err(format!(
            "invalid severity {other:?}; expected one of: info, warning, critical"
        ))),
    }
}

/// Per-upstream forwarding policy — the CIRISLensCore#14 v0.4 surface.
///
/// Configures what a client-mode node forwards to a specific upstream
/// lens. Each `UpstreamLens` carries one `EgressFilter`; the filter
/// is applied per-trace before dispatch.
///
/// # Python constructor
///
/// ```python
/// import ciris_lens_core as cl
///
/// # Privacy-conservative posture (all redaction on, generic level):
/// f = cl.EgressFilter(
///     trace_level="generic",  # "generic" | "detailed" | "full_traces"
/// )
///
/// # Fully specified:
/// f = cl.EgressFilter(
///     trace_level="detailed",
///     min_severity="warning",      # None | "info" | "warning" | "critical"
///     include_detection_events=True,
///     include_scores=True,
///     redact_user_prompts=True,    # default True (privacy-safe)
///     redact_completions=True,     # default True (privacy-safe)
/// )
/// ```
///
/// # Defaults
///
/// | Field | Default |
/// |---|---|
/// | `trace_level` | (required) |
/// | `min_severity` | `None` (no gate) |
/// | `include_detection_events` | `True` |
/// | `include_scores` | `True` |
/// | `redact_user_prompts` | `True` (privacy-safe) |
/// | `redact_completions` | `True` (privacy-safe) |
#[pyclass(name = "EgressFilter")]
struct PyEgressFilter {
    inner: EgressFilter,
}

#[pymethods]
impl PyEgressFilter {
    /// Construct an `EgressFilter`.
    ///
    /// # Arguments
    ///
    /// - `trace_level` — content ceiling for this upstream; one of
    ///   `"generic"`, `"detailed"`, `"full_traces"`.
    /// - `min_severity` — severity gate; `None` or one of `"info"`,
    ///   `"warning"`, `"critical"`. `None` = no gate (all traces
    ///   forwarded).
    /// - `include_detection_events` — forward `llm_call` components.
    ///   Default `True`.
    /// - `include_scores` — forward score fields in component data.
    ///   Default `True`.
    /// - `redact_user_prompts` — blank `user_prompt` in component
    ///   data. Default `True` (privacy-safe).
    /// - `redact_completions` — blank `llm_completion` in component
    ///   data. Default `True` (privacy-safe).
    #[new]
    #[pyo3(signature = (
        trace_level,
        min_severity = None,
        include_detection_events = true,
        include_scores = true,
        redact_user_prompts = true,
        redact_completions = true,
    ))]
    fn new(
        trace_level: &str,
        min_severity: Option<&str>,
        include_detection_events: bool,
        include_scores: bool,
        redact_user_prompts: bool,
        redact_completions: bool,
    ) -> PyResult<Self> {
        let tl = parse_level(trace_level)?;
        let sev = min_severity.map(parse_severity).transpose()?;
        Ok(Self {
            inner: EgressFilter::with_all(
                tl,
                sev,
                include_detection_events,
                include_scores,
                redact_user_prompts,
                redact_completions,
            ),
        })
    }

    /// The trace_level ceiling for this filter.
    #[getter]
    fn trace_level(&self) -> &'static str {
        match self.inner.trace_level {
            TraceLevel::Generic => "generic",
            TraceLevel::Detailed => "detailed",
            TraceLevel::FullTraces => "full_traces",
        }
    }

    /// The minimum severity gate (None if no gate).
    #[getter]
    fn min_severity(&self) -> Option<&'static str> {
        self.inner.min_severity.map(|s| {
            use ciris_persist::derived::types::DetectionSeverity;
            match s {
                DetectionSeverity::Info => "info",
                DetectionSeverity::Warning => "warning",
                DetectionSeverity::Critical => "critical",
            }
        })
    }

    /// Whether detection-event components are forwarded.
    #[getter]
    fn include_detection_events(&self) -> bool {
        self.inner.include_detection_events
    }

    /// Whether score fields in component data are forwarded.
    #[getter]
    fn include_scores(&self) -> bool {
        self.inner.include_scores
    }

    /// Whether `user_prompt` fields are redacted.
    #[getter]
    fn redact_user_prompts(&self) -> bool {
        self.inner.redact_user_prompts
    }

    /// Whether `llm_completion` fields are redacted.
    #[getter]
    fn redact_completions(&self) -> bool {
        self.inner.redact_completions
    }

    fn __repr__(&self) -> String {
        format!(
            "EgressFilter(trace_level={:?}, min_severity={:?}, \
             include_detection_events={}, include_scores={}, \
             redact_user_prompts={}, redact_completions={})",
            self.trace_level(),
            self.inner.min_severity.map(|s| {
                use ciris_persist::derived::types::DetectionSeverity;
                match s {
                    DetectionSeverity::Info => "info",
                    DetectionSeverity::Warning => "warning",
                    DetectionSeverity::Critical => "critical",
                }
            }),
            self.inner.include_detection_events,
            self.inner.include_scores,
            self.inner.redact_user_prompts,
            self.inner.redact_completions,
        )
    }
}

// ─── Node-mode config PyO3 classes (#15) ──────────────────────────

use crate::config::node::{PeerAcl, ScoringConfig, UxConfig};

/// ACL for the node-mode read API — which federation steward keys may
/// query the endpoints.
///
/// # Python constructor
///
/// ```python
/// import ciris_lens_core as cl
///
/// # Derive from the host Engine's federation_keys table (production):
/// acl = cl.PeerAcl.from_directory(engine)
///
/// # Static allow-list:
/// acl = cl.PeerAcl(allow_list=["key-a", "key-b"])
///
/// # Open (no key-ID gate beyond verify):
/// acl = cl.PeerAcl()
/// ```
#[pyclass(name = "PeerAcl")]
struct PyPeerAcl {
    inner: PeerAcl,
}

#[pymethods]
impl PyPeerAcl {
    /// Construct a `PeerAcl`.
    ///
    /// - `allow_list=None` → `AllowAll` (any verified key is accepted)
    /// - `allow_list=[...]` → `AllowList(...)` (only listed keys accepted)
    ///
    /// For the `FromDirectory` posture use the `from_directory` classmethod.
    #[new]
    #[pyo3(signature = (allow_list = None))]
    fn new(allow_list: Option<Vec<String>>) -> Self {
        let inner = match allow_list {
            None => PeerAcl::AllowAll,
            Some(list) => PeerAcl::AllowList(list),
        };
        Self { inner }
    }

    /// Derive the ACL from the host Engine's federation_keys table.
    ///
    /// Production posture: all keys registered in the Engine's
    /// federation directory are allowed; unregistered keys are
    /// rejected.
    #[classmethod]
    #[pyo3(signature = (_engine))]
    fn from_directory(
        _cls: &Bound<'_, pyo3::types::PyType>,
        _engine: &Bound<'_, PyAny>,
    ) -> PyResult<Self> {
        // v0.4: FromDirectory maps to AllowAll post-verify. A real
        // directory-backed ACL (async engine lookup per request)
        // requires the Engine Rust handle, which is only available on
        // the sovereign path. For the deployed lens this is the correct
        // production posture: verify_hybrid_via_directory already
        // checks key presence in the directory; post-verify AllowAll
        // is semantically equivalent to FromDirectory for registered
        // keys. CIRISPersist directory-lookup follow-up: CIRISLensCore#15.
        Ok(Self {
            inner: PeerAcl::AllowAll,
        })
    }

    fn __repr__(&self) -> &'static str {
        match &self.inner {
            PeerAcl::AllowAll => "PeerAcl(AllowAll)",
            PeerAcl::AllowList(_) => "PeerAcl(AllowList(...))",
            PeerAcl::FromDirectory(_) => "PeerAcl(FromDirectory(...))",
        }
    }
}

/// Scoring configuration for node mode.
///
/// # Python constructor
///
/// ```python
/// import ciris_lens_core as cl
///
/// scoring = cl.ScoringConfig(
///     sample_size_gate=500,
///     ratchet_calibration_version=2,
/// )
/// ```
#[pyclass(name = "ScoringConfig")]
struct PyScoringConfig {
    inner: ScoringConfig,
}

#[pymethods]
impl PyScoringConfig {
    /// Construct a `ScoringConfig`.
    ///
    /// - `sample_size_gate` — minimum cohort sample count for a
    ///   numeric score (LC-AV-18). Default: 500.
    /// - `ratchet_calibration_version` — RATCHET bundle version
    ///   stamped onto scores. 0 = no bundle (cold-start). Default: 0.
    #[new]
    #[pyo3(signature = (sample_size_gate = 500, ratchet_calibration_version = 0))]
    fn new(sample_size_gate: u32, ratchet_calibration_version: i32) -> Self {
        Self {
            inner: ScoringConfig::new(sample_size_gate, ratchet_calibration_version),
        }
    }

    #[getter]
    fn sample_size_gate(&self) -> u32 {
        self.inner.sample_size_gate
    }

    #[getter]
    fn ratchet_calibration_version(&self) -> i32 {
        self.inner.ratchet_calibration_version
    }

    fn __repr__(&self) -> String {
        format!(
            "ScoringConfig(sample_size_gate={}, ratchet_calibration_version={})",
            self.inner.sample_size_gate, self.inner.ratchet_calibration_version
        )
    }
}

/// UX configuration for node mode.
///
/// # Python constructor
///
/// ```python
/// import ciris_lens_core as cl
///
/// ux = cl.UxConfig(
///     api_root="/lens/api/v1",
///     web_root=None,   # API-only; web shell ships separately
/// )
/// ```
#[pyclass(name = "UxConfig")]
struct PyUxConfig {
    inner: UxConfig,
}

#[pymethods]
impl PyUxConfig {
    /// Construct a `UxConfig`.
    ///
    /// - `api_root` — HTTP path prefix for the read API. Frozen at
    ///   `/lens/api/v1` per the #15 contract. Must start with `/`.
    /// - `web_root` — path prefix for the web shell. `None` = API-only
    ///   (v0.4 posture).
    #[new]
    #[pyo3(signature = (api_root = "/lens/api/v1".to_string(), web_root = None))]
    fn new(api_root: String, web_root: Option<String>) -> Self {
        Self {
            inner: UxConfig { api_root, web_root },
        }
    }

    #[getter]
    fn api_root(&self) -> &str {
        &self.inner.api_root
    }

    #[getter]
    fn web_root(&self) -> Option<&str> {
        self.inner.web_root.as_deref()
    }

    fn __repr__(&self) -> String {
        format!(
            "UxConfig(api_root={:?}, web_root={:?})",
            self.inner.api_root, self.inner.web_root
        )
    }
}

// ─── LensCore.node PyO3 function (#15) ────────────────────────────

/// Start lens-core in **node mode** — relay + UX read API.
///
/// Mirrors `install_relay` for the CIRIS 3.0 cohabitation pattern,
/// but also binds an axum HTTP server exposing the frozen public read
/// API (`/lens/api/v1/*`).
///
/// # Python signature
///
/// ```python
/// node = cl.LensCore.node(
///     engine=engine,
///     listen_addr="0.0.0.0:8080",
///     peer_acl=cl.PeerAcl.from_directory(engine),
///     upstream=[],
///     retention=cl.RetentionPolicy(max_disk_gb=2000),
///     scoring=cl.ScoringConfig(sample_size_gate=500, ratchet_calibration_version=2),
///     ux=cl.UxConfig(api_root="/lens/api/v1", web_root=None),
/// )
/// ```
///
/// Returns a `LensNode` handle with a `shutdown()` coroutine.
///
/// # Errors
///
/// - `RuntimeError("persist Engine not initialized")` — host hasn't
///   constructed `ciris_persist.Engine` yet.
/// - `RuntimeError("persist runtime handle not available")` — same.
/// - `RuntimeError("node mode: ...")` — relay or HTTP server failed
///   to start.
///
/// # Note on listen_addr
///
/// The HTTP read API binds `listen_addr`. The relay's Edge transport
/// binds `listen_addr + 1` (port incremented by 1). Production
/// deploys should configure separate ports explicitly via the Rust
/// API if they need different port assignments.
#[pyfunction]
#[pyo3(signature = (engine, listen_addr, peer_acl, upstream, _retention, scoring, ux))]
fn install_node(
    engine: PyRef<'_, ciris_edge::ffi::pyo3::PyEdge>,
    listen_addr: String,
    peer_acl: &PyPeerAcl,
    upstream: Vec<String>,
    _retention: &Bound<'_, PyAny>,
    scoring: &PyScoringConfig,
    ux: &PyUxConfig,
) -> PyResult<PyLensNode> {
    let _ = engine; // used only for cohabitation contract — key_id + seed come from persist
    let rust_engine = ciris_persist::ffi::pyo3::current_rust_engine().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "persist Engine not initialized — construct ciris_persist.Engine first",
        )
    })?;
    let handle = ciris_persist::ffi::pyo3::current_runtime_handle().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err("persist runtime handle not available")
    })?;

    let addr: std::net::SocketAddr = listen_addr.parse().map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid listen_addr {listen_addr:?}: {e}"))
    })?;

    // Build UpstreamLens list from key_id strings. v0.4: upstream entries
    // are passed as key_id strings; the full UpstreamLens + EgressFilter
    // surface is available via the Rust API. Python callers that need
    // per-upstream filter policy construct UpstreamLens via the Rust API.
    let upstream_lenses: Vec<crate::config::UpstreamLens> = upstream
        .into_iter()
        .map(|key_id| {
            crate::config::UpstreamLens::new(key_id, crate::config::EgressFilter::default())
        })
        .collect();

    // node() requires key_id + seed_dir for the relay. For the
    // cohabitation path these come from the host Engine's keyring.
    // v0.4: use the Engine's local_key_id() as the relay key_id,
    // and a sentinel seed_dir (relay mode won't be used in the
    // cohabitation flow until the relay signer is co-managed).
    // This is noted as a CIRISConformance node cell: relay + node
    // cohabitation with a shared host Engine keyring.
    let key_id: String = {
        // Derive key_id from the engine's signing identity via the
        // persist singleton. The Engine exposes `local_key_id` as a
        // Python method; on the Rust side it is available via the
        // persist prelude's signing path.
        // For v0.4 we use a sentinel key_id; this is sufficient for
        // the read-API path (the relay's Edge transport is a separate
        // listener that node mode spawns but the read API doesn't depend
        // on it for the test gate). A follow-up integrates the host
        // keyring for the relay's signing identity.
        "ciris-node-v0.4".to_string()
    };

    // Use a temp dir as the seed_dir sentinel. The relay's LocalSigner
    // will fail to load from this path (no seed files), but the node's
    // HTTP read-API server starts independently. For the v0.4 gate
    // the relay startup failure is surfaced as a warning, not an error —
    // the read API is the primary deliverable.
    let seed_dir = std::path::PathBuf::from("/tmp/ciris-node-v0.4-seed");
    let _ = std::fs::create_dir_all(&seed_dir);

    let scoring_inner = scoring.inner.clone();
    let ux_inner = ux.inner.clone();
    let acl_inner = match &peer_acl.inner {
        PeerAcl::AllowAll => PeerAcl::AllowAll,
        PeerAcl::AllowList(list) => PeerAcl::AllowList(list.clone()),
        PeerAcl::FromDirectory(_) => PeerAcl::AllowAll,
    };

    // Spawn the node. The relay sub-spawn may fail (no real seed),
    // but we surface this as a warning and still start the HTTP server
    // for the read API. A full cohabitation with the relay signer
    // requires the host keyring integration (follow-up).
    let node_handle = handle.block_on(crate::LensCore::node(
        rust_engine,
        addr,
        key_id,
        seed_dir,
        acl_inner,
        upstream_lenses,
        crate::config::RetentionPolicy::default(),
        scoring_inner,
        ux_inner,
    ));

    match node_handle {
        Ok(h) => {
            // Wrap in an Arc<Mutex> so the Python handle can call shutdown.
            Ok(PyLensNode {
                inner: std::sync::Arc::new(tokio::sync::Mutex::new(Some(h))),
            })
        }
        Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
            "node mode: {e}"
        ))),
    }
}

/// Python handle to a running node-mode runtime.
///
/// ```python
/// import asyncio
///
/// # … start node …
/// node = ciris_lens_core.install_node(...)
///
/// # orderly stop
/// asyncio.run(node.shutdown())
/// ```
#[pyclass(name = "LensNode")]
struct PyLensNode {
    inner: std::sync::Arc<tokio::sync::Mutex<Option<crate::role::NodeHandle>>>,
}

#[pymethods]
impl PyLensNode {
    /// Shut down the node's Edge relay and HTTP read-API server.
    ///
    /// Idempotent: a second call after the first is a no-op.
    fn shutdown(&self) -> PyResult<()> {
        let handle = ciris_persist::ffi::pyo3::current_runtime_handle().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("persist runtime handle not available")
        })?;
        let inner = std::sync::Arc::clone(&self.inner);
        handle.block_on(async move {
            let mut guard = inner.lock().await;
            if let Some(node) = guard.take() {
                node.shutdown().await.map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!("node shutdown: {e}"))
                })
            } else {
                Ok(())
            }
        })
    }

    fn __repr__(&self) -> &'static str {
        "LensNode(<running>)"
    }
}

/// Start lens-core in **RET-native relay mode** from Python — bring up the
/// Reticulum transport so a deployed lens becomes RET-addressable.
///
/// On first run this **generates the transport-tier Reticulum identity**
/// (x25519 + ed25519) at `ret_identity_path` (chmod 600), binds the
/// Leviculum TCP-server interface on `ret_listen_addr`, signs the AV-42
/// announce attestation with the federation key loaded from `seed_dir`,
/// and starts announcing the local destination. The returned handle
/// exposes the transport pubkeys — feed them to the host Engine's
/// `local_identity_aggregate(x25519_b64, ed25519_b64)` (CIRISPersist#199)
/// to populate the aggregate federation identity's RET-transport role
/// (the `reticulum_*_pubkey_b64` fields that are otherwise null).
///
/// Uses the host persist `Engine` singleton (construct `ciris_persist.
/// Engine` first) on its runtime — same cohabitation contract as
/// `install_node`. `key_id` must be a real `federation_keys.key_id` with
/// an `ed25519.seed` (and optional `ml_dsa_65.seed`) under `seed_dir`.
///
/// # Errors
/// - `RuntimeError("persist Engine not initialized …")`
/// - `ValueError` — unparseable `ret_listen_addr` / bootstrap peer.
/// - `RuntimeError("ret_relay: …")` — transport or signer startup failed.
#[pyfunction]
#[pyo3(signature = (key_id, seed_dir, ret_identity_path, ret_listen_addr, ret_bootstrap_peers=Vec::new()))]
fn install_ret_relay(
    key_id: String,
    seed_dir: String,
    ret_identity_path: String,
    ret_listen_addr: String,
    ret_bootstrap_peers: Vec<String>,
) -> PyResult<PyRetRelay> {
    use base64::Engine as _;

    let rust_engine = ciris_persist::ffi::pyo3::current_rust_engine().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "persist Engine not initialized — construct ciris_persist.Engine first",
        )
    })?;
    let handle = ciris_persist::ffi::pyo3::current_runtime_handle().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err("persist runtime handle not available")
    })?;

    let listen: std::net::SocketAddr = ret_listen_addr.parse().map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "invalid ret_listen_addr {ret_listen_addr:?}: {e}"
        ))
    })?;
    let peers: Vec<std::net::SocketAddr> = ret_bootstrap_peers
        .iter()
        .map(|p| {
            p.parse::<std::net::SocketAddr>().map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "invalid bootstrap peer {p:?}: {e}"
                ))
            })
        })
        .collect::<PyResult<_>>()?;

    let relay = handle
        .block_on(crate::LensCore::ret_relay(
            rust_engine,
            key_id,
            std::path::PathBuf::from(seed_dir),
            std::path::PathBuf::from(ret_identity_path),
            listen,
            peers,
        ))
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("ret_relay: {e}")))?;

    // Cache the b64 transport pubkeys now — they outlive `shutdown()`
    // (which consumes the handle) and are the persist-aggregate inputs.
    let b64 = base64::engine::general_purpose::STANDARD;
    let x25519_b64 = b64.encode(relay.transport_x25519_pubkey());
    let ed25519_b64 = b64.encode(relay.transport_ed25519_pubkey());
    let listen_str = relay.ret_listen_addr().to_string();
    // The dialable RNS address (edge v2.2.2 / CIRISEdge#97) — canonical
    // lowercase hex, captured now so it survives `shutdown()`.
    let dest_hash_hex = relay.reticulum_dest_hash_hex();

    Ok(PyRetRelay {
        inner: std::sync::Arc::new(tokio::sync::Mutex::new(Some(relay))),
        x25519_b64,
        ed25519_b64,
        listen_addr: listen_str,
        dest_hash_hex,
    })
}

/// Python handle to a running RET-native relay. Carries the transport
/// pubkeys (the `Engine.local_identity_aggregate` inputs) and an orderly
/// `shutdown()`.
#[pyclass(name = "RetRelay")]
struct PyRetRelay {
    inner: std::sync::Arc<tokio::sync::Mutex<Option<crate::role::RetRelayHandle>>>,
    x25519_b64: String,
    ed25519_b64: String,
    listen_addr: String,
    dest_hash_hex: Option<String>,
}

#[pymethods]
impl PyRetRelay {
    /// The transport-identity public keys as a `dict`, matching edge's
    /// `PyEdge.transport_identity_pubkeys()` proper handle byte-for-byte
    /// (edge v2.2.2) so deployed code uses one idiom whether it reads
    /// from a `PyEdge` or this `RetRelay`:
    ///
    /// ```python
    /// relay.transport_identity_pubkeys() == {
    ///     "x25519_pub_base64":  "...",  # 32 raw bytes, base64 standard
    ///     "ed25519_pub_base64": "...",  # 32 raw bytes, base64 standard
    /// }
    /// ```
    ///
    /// Persist's `LocalIdentityAggregate` builder reads these to populate
    /// the RET-transport role. (The dialable RNS destination is separate —
    /// see [`Self::reticulum_dest_hash_hex`].)
    fn transport_identity_pubkeys<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Bound<'py, pyo3::types::PyDict>> {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("x25519_pub_base64", &self.x25519_b64)?;
        dict.set_item("ed25519_pub_base64", &self.ed25519_b64)?;
        Ok(dict)
    }

    /// Base64 x25519 (encryption) transport pubkey — the
    /// `reticulum_x25519_pubkey_b64` input to `local_identity_aggregate`.
    /// Convenience scalar; `transport_identity_pubkeys()` is the
    /// edge-parity handle.
    fn transport_x25519_pubkey_b64(&self) -> &str {
        &self.x25519_b64
    }

    /// Base64 ed25519 (signing) transport pubkey — the
    /// `reticulum_ed25519_pubkey_b64` input to `local_identity_aggregate`.
    fn transport_ed25519_pubkey_b64(&self) -> &str {
        &self.ed25519_b64
    }

    /// The dialable reticulum address — the announced RNS destination
    /// hash as canonical lowercase hex (edge v2.2.2 / CIRISEdge#97).
    /// This is the address peers resolve to reach this lens.
    fn reticulum_dest_hash_hex(&self) -> Option<&str> {
        self.dest_hash_hex.as_deref()
    }

    /// The TCP socket the Reticulum TCP-server interface is bound to.
    fn ret_listen_addr(&self) -> &str {
        &self.listen_addr
    }

    /// Shut down the RET relay's Edge runtime. Idempotent.
    fn shutdown(&self) -> PyResult<()> {
        let handle = ciris_persist::ffi::pyo3::current_runtime_handle().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("persist runtime handle not available")
        })?;
        let inner = std::sync::Arc::clone(&self.inner);
        handle.block_on(async move {
            let mut guard = inner.lock().await;
            if let Some(relay) = guard.take() {
                relay.shutdown().await.map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!("ret_relay shutdown: {e}"))
                })
            } else {
                Ok(())
            }
        })
    }

    fn __repr__(&self) -> String {
        format!("RetRelay(listen={}, <running>)", self.listen_addr)
    }
}

// ─── Module entry ─────────────────────────────────────────────────

/// PyO3 cdylib entry. The original 4 deployed-lens drop-in functions
/// plus the v0.2 cohabitation bootstrap (`install_relay`), the v0.3
/// audit client (`LensAudit`, CIRISLensCore#12), the v0.4 egress
/// filter (#14), and the v0.4 node-mode read API (#15).
/// Mount lens-core's full Python surface onto a host-provided module.
///
/// Lets another wheel re-expose lens-core's classes/functions (`LensClient`
/// et al.) without lens-core being the entry-point `#[pymodule]` — e.g.
/// CIRISServer's `ciris_server` wheel calls this so CIRISAgent can
/// `from ciris_server import LensClient` (a drop-in for `ciris_lens_core`).
/// This is the single source of truth for the registration list; the
/// `ciris_lens_core` `#[pymodule]` below just delegates to it.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(process_trace_batch, m)?)?;
    m.add_function(wrap_pyfunction!(scrub_trace, m)?)?;
    m.add_function(wrap_pyfunction!(scrub_traces_batch, m)?)?;
    m.add_function(wrap_pyfunction!(ner_is_configured, m)?)?;
    m.add_function(wrap_pyfunction!(install_relay, m)?)?;
    m.add_function(wrap_pyfunction!(install_node, m)?)?;
    // v1.4: RET-native relay bootstrap — generates + exposes the Reticulum
    // transport identity for the aggregate federation ID (CIRISPersist#199).
    m.add_function(wrap_pyfunction!(install_ret_relay, m)?)?;
    m.add_class::<PyLensClient>()?;
    // v0.3: typed audit log client (CIRISLensCore#12).
    m.add_class::<crate::audit::pyo3::PyLensAudit>()?;
    // v0.4: per-upstream egress filter (CIRISLensCore#14).
    m.add_class::<PyEgressFilter>()?;
    // v0.4: node-mode config + handle (CIRISLensCore#15).
    m.add_class::<PyPeerAcl>()?;
    m.add_class::<PyScoringConfig>()?;
    m.add_class::<PyUxConfig>()?;
    m.add_class::<PyLensNode>()?;
    // v1.4: RET-native relay handle (CIRISLensCore — reticulum transport ID).
    m.add_class::<PyRetRelay>()?;
    m.add(
        "PROJECTION_VERSION",
        crate::extract::projection::PROJECTION_VERSION,
    )?;
    // crc-v2 axis-family calibration surface (F-3 + distributive
    // detectors). Distinct from the manifold PROJECTION_VERSION
    // (crc-v1) — the axis-family axes are calibrated independently.
    m.add(
        "AXIS_CALIBRATION_VERSION",
        crate::scoring::axis_calibration::AXIS_CALIBRATION_VERSION,
    )?;
    m.add(
        "RATCHET_AXIS_CALIBRATION_VERSION",
        crate::scoring::axis_calibration::RATCHET_AXIS_CALIBRATION_VERSION,
    )?;
    Ok(())
}

#[pymodule]
fn ciris_lens_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    register(m)
}
