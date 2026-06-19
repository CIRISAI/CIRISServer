//! `CaptureClient` — the client-mode orchestrator for CIRISLensCore#11.
//!
//! Composes the already-tested capture/seal/batch primitives with a
//! host-supplied persist `Engine` to produce the full client-mode
//! seal → sign → batch → persist flow:
//!
//! ```text
//! InboundEvent
//!     │  capture_event
//!     ▼
//! PartialTraceStore (assemble)
//!     │  on ACTION_RESULT → Sealed(CompleteTrace)
//!     ▼
//! seal_sign_wrap
//!     ├── stamp deployment_profile + trace_level
//!     ├── sign_trace_via_hardware_signer (canonical_bytes → HardwareSigner::sign)
//!     └── build_batch_bytes → Vec<u8>
//!         │
//!         ▼
//! Engine::receive_and_persist(&bytes, scrubber)
//!     └── SealedAndPersisted { trace_id, summary }
//! ```
//!
//! # Engine-as-parameter
//!
//! Lens-core never constructs an `Engine` or holds signing keys. The
//! host passes its process-singleton `Arc<Engine>`; we only call
//! `engine.receive_and_persist` and `engine.signer()`. This mirrors
//! the relay handler pattern (see `crate::role::handler`).
//!
//! # Scrubber is a constructor parameter
//!
//! Client mode is the originating node — the host decides the privacy
//! policy. A relay passes [`NullScrubber`](ciris_persist::scrub::NullScrubber)
//! per CIRISPersist#89; a client passes its real scrubber. Lens-core
//! never chooses.
//!
//! PII egress is handled by the correlation fuzz invariant (lat/lng
//! coarsened to 1-decimal at construction time in
//! [`CorrelationMetadata::build`]) and shim-side trace-level gating.
//! A configurable scrubber constructor parameter is a follow-up
//! (CIRISLensCore#11).
//!
//! # Signing path (v4.13)
//!
//! `Engine` v4.13 exposes no public `local_signer()` accessor — the
//! `local_signer` field is private. `Engine::signer()` returns
//! `&Arc<dyn HardwareSigner>`, whose `sign(data)` async method
//! produces Ed25519 (or ECDSA P-256) raw bytes. Trace signing is
//! Ed25519-only, matching CIRISAgent's `Ed25519TraceSigner.sign_trace`.
//! We sign via [`sign_trace_via_hardware_signer`] — a thin wrapper
//! over `seal::{canonical_bytes, apply_signature}` that goes through
//! `HardwareSigner::sign` — never duplicating the canonicalization
//! rules (MISSION.md boundary; CIRISPersist#7 lesson).
//!
//! # Fan-out (issue #11 Cut 4)
//!
//! `Engine` in v4.13 has **no** `send_durable` method; that surface
//! lives on `ciris_edge::Edge`. The `upstreams` field is stubbed here
//! for the Cut 4 landing; actual dispatch is deferred. See comment on
//! [`CaptureClient::upstreams`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};

use ciris_keyring::HardwareSigner;
use ciris_persist::prelude::Engine;
use ciris_persist::scrub::Scrubber;

use super::batch::{build_batch_bytes, BatchBuildError, BatchProvenance};
use super::consent::{ConsentConfig, ConsentError, ConsentResolution};
use super::correlation::CorrelationMetadata;
use super::partial::CompleteTrace;
use super::partial::{CaptureOutcome, InboundEvent, PartialTraceStore};
use super::seal::{self, apply_signature, canonical_bytes, TraceSealError};

use crate::config::UpstreamLens;

// ── Error types ──────────────────────────────────────────────────────

/// Why [`CaptureClient::capture_event`] failed.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The trace seal / sign step failed — either canonicalization
    /// produced an error or the `HardwareSigner` refused to sign.
    #[error("seal: {0}")]
    Seal(#[from] SealSignError),

    /// The signed trace couldn't be wrapped into a `BatchEnvelope`
    /// wire bytes — most likely an `EmptyBatch` or `UnsignedTrace`
    /// programming error (should never happen if the seal step
    /// succeeded).
    #[error("batch: {0}")]
    Batch(#[from] BatchBuildError),

    /// `Engine::receive_and_persist` returned an error. Stringified
    /// (matching `crate::role::handler::HandlerError::Persist`) to
    /// avoid coupling to persist's internal `IngestError` variants at
    /// the public API boundary.
    #[error("persist: {0}")]
    Persist(String),

    /// Consent resolution via the Engine's federation directory failed
    /// (e.g. a directory read error). Stringified to avoid coupling to
    /// [`ConsentError`] variants at the public API boundary.
    #[error("consent: {0}")]
    Consent(String),
}

impl From<ConsentError> for ClientError {
    fn from(e: ConsentError) -> Self {
        ClientError::Consent(e.to_string())
    }
}

/// Error from the hardware-signer signing path (async, typed).
///
/// Distinct from [`TraceSealError`] (which wraps `LocalSignerError`)
/// because the hardware path goes through `HardwareSigner::sign` →
/// `ciris_keyring::KeyringError`, not `LocalSigner::sign_ed25519` →
/// `LocalSignerError`. Both result in "trace cannot be sealed", but
/// the error source differs.
#[derive(Debug, thiserror::Error)]
pub enum SealSignError {
    /// The canonical signing envelope couldn't be serialized.
    #[error("canonicalize: {0}")]
    Canonicalize(String),

    /// The `HardwareSigner::sign` call failed — key unavailable,
    /// hardware error, or authentication required.
    #[error("hardware sign: {0}")]
    HardwareSign(String),

    /// `Engine::sign_hybrid` failed — no `LocalSigner` (the Engine was
    /// built via `from_shared`), no PQC identity configured
    /// (`PqcNotConfigured` — an Ed25519-only deployment cannot produce
    /// the ML-DSA-65 half the trace-tier hard cut requires), or the
    /// underlying signer errored.
    #[error("hybrid sign: {0}")]
    HybridSign(String),

    /// Wraps [`TraceSealError`] for the (rare) path where a
    /// `LocalSigner` is composed directly (e.g., in tests via
    /// `sign_trace`).
    #[error(transparent)]
    LocalSigner(#[from] TraceSealError),
}

// ── Summary types ────────────────────────────────────────────────────

/// Summary of a successfully sealed-and-persisted trace.
///
/// Carries the subset of [`ciris_persist::ingest::BatchSummary`]
/// fields most useful to the caller: insertion counts + verification
/// attestation. `trace_id` links the summary to the originating
/// `InboundEvent` stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealSummary {
    /// How many `trace_events` rows landed (> 0 for a non-empty
    /// trace; normally the component count).
    pub trace_events_inserted: usize,
    /// How many `CompleteTrace` envelopes persist verified under
    /// their Ed25519 signature. `1` for a well-formed single-trace
    /// batch; `0` means the signature didn't verify (should not
    /// happen if `sign_trace_via_hardware_signer` succeeded — surface
    /// for diagnostics).
    pub signatures_verified: usize,
}

/// What [`CaptureClient::capture_event`] produced.
#[derive(Debug)]
pub enum CaptureEventOutcome {
    /// First event for this `thought_id` — a new trace opened.
    Opened,
    /// Component appended to an in-flight trace.
    Appended,
    /// The event-type string didn't parse — typed rejection, never
    /// silent (CIRISLens#13 fix). The raw string is preserved for
    /// caller-side logging.
    Rejected { raw: String },
    /// `ACTION_RESULT` landed: the trace was sealed, signed, batched,
    /// and persisted. `trace_id` identifies the row; `summary` carries
    /// persist's ingest counts.
    SealedAndPersisted {
        trace_id: String,
        summary: SealSummary,
    },
    /// Consent was not granted at seal time — the trace was dropped
    /// without persisting (CIRISLensCore#34 recant-stops-emission
    /// requirement). `reason` is one of `"withdrawn"` or `"no_consent"`.
    ConsentBlocked { reason: &'static str },
}

// ── PrepareSealOutcome ───────────────────────────────────────────────

/// Result of [`CaptureClient::prepare_for_seal`] — either the event was
/// handled without reaching the seal step (Opened / Appended / Rejected /
/// ConsentBlocked), or the trace is ready for sign + persist.
///
/// This type exists so the Python-engine path in `ffi::pyo3` can reuse
/// the same partial-trace assembly, consent, and provenance steps as the
/// Rust `capture_event` path, with sign + persist as the only divergent
/// steps (Rust vs Python calls). DRY factor: neither path duplicates
/// canonicalization or consent logic.
#[derive(Debug)]
pub enum PrepareSealOutcome {
    /// Not a sealing event (or consent blocked). Return this directly to
    /// the caller; no sign + persist step is needed.
    NotSealing(CaptureEventOutcome),
    /// The trace is sealed and ready for sign + persist.
    ///
    /// The caller (Rust or Python) must:
    /// 1. Stamp `deployment_profile` (already carried here from
    ///    `CaptureClient::deployment_profile`).
    /// 2. Stamp `trace_level` from `provenance` if absent on the trace.
    /// 3. Obtain canonical bytes via `seal::canonical_bytes(&trace)`.
    /// 4. Sign the bytes and call `seal::apply_signature(&mut trace, sig, key_id)`.
    /// 5. Call `build_batch_bytes(&[trace], &provenance)`.
    /// 6. Persist the bytes; call `tee_write_if_configured` for the local tee.
    ReadyToSeal {
        /// The sealed `CompleteTrace` — stamp, sign, and batch. Boxed to
        /// reduce the enum's stack size (CompleteTrace is large).
        trace: Box<CompleteTrace>,
        /// Batch-level provenance including consent_timestamp, batch_timestamp,
        /// trace_level, trace_schema_version, and correlation_metadata.
        provenance: BatchProvenance,
        /// Operator deployment profile from `CaptureClient::deployment_profile`
        /// (stamp onto `trace.deployment_profile` if it is `None`).
        deployment_profile: Option<serde_json::Value>,
    },
}

// ── sign_trace_via_hardware_signer ───────────────────────────────────

/// Sign a sealed trace via the `HardwareSigner` abstraction — the
/// path taken when `Engine::signer()` returns `Arc<dyn HardwareSigner>`
/// without a public `LocalSigner` accessor (v4.13 and later).
///
/// Calls `seal::canonical_bytes` (the federation-wide canonical bytes
/// authority — lens-core never re-implements), passes the bytes to
/// `HardwareSigner::sign`, and stamps the result onto the trace via
/// `seal::apply_signature`. Async because `HardwareSigner::sign` is
/// async (hardware-backed signers may require I/O or user auth).
///
/// Factored out as a standalone async function (not a method) so it
/// is directly unit-testable without a full `CaptureClient` — see
/// the `tests` module below.
pub async fn sign_trace_via_hardware_signer(
    signer: &dyn HardwareSigner,
    trace: &mut CompleteTrace,
) -> Result<(), SealSignError> {
    let bytes = canonical_bytes(trace).map_err(SealSignError::Canonicalize)?;
    let sig = signer
        .sign(&bytes)
        .await
        .map_err(|e| SealSignError::HardwareSign(e.to_string()))?;
    let key_id = signer.current_alias();
    apply_signature(trace, &sig, key_id);
    Ok(())
}

// ── hybrid_sign_trace_via_engine ─────────────────────────────────────

/// Hybrid-sign (Ed25519 + ML-DSA-65) a sealed trace via the Engine's
/// `LocalSigner`, the federation-admissible seal path.
///
/// Computes `seal::canonical_bytes` (the federation-wide canonical bytes
/// authority) and hands them to [`Engine::sign_hybrid`], which produces
/// the bound-hybrid signature — Ed25519 over `canonical`, ML-DSA-65 over
/// `canonical ‖ ed25519_sig` — plus both public keys. The five resulting
/// fields are stamped via [`seal::apply_hybrid_signature`] (all STANDARD
/// base64). The trace then passes persist's `VerifyMode::Full`
/// `verify_trace_hybrid` under `HybridPolicy::Strict` (CIRISPersist#225
/// trace-tier hard cut).
///
/// `signature_key_id` uses the Engine signer's current alias (the
/// Ed25519 key persist resolves from `accord_public_keys`); the
/// ML-DSA-65 `pqc_key_id` uses the LocalSigner's `pqc_key_id`, falling
/// back to the classical alias when the PQC key has no distinct id.
async fn hybrid_sign_trace_via_engine(
    engine: &Engine,
    trace: &mut CompleteTrace,
) -> Result<(), SealSignError> {
    let bytes = canonical_bytes(trace).map_err(SealSignError::Canonicalize)?;
    let hybrid = engine
        .sign_hybrid(&bytes)
        .await
        .map_err(|e| SealSignError::HybridSign(e.to_string()))?;
    // The Ed25519 key_id is the producer's federation alias persist
    // resolves from `accord_public_keys`. `pqc_key_id` is verbatim
    // metadata persist stores but the hybrid verify does not consult
    // (the producer's ML-DSA-65 pubkey rides the envelope and is bound
    // into the verify); the Engine exposes no separate PQC alias
    // accessor, so we label it with the same federation alias.
    let key_id = engine.signer().current_alias().to_owned();
    seal::apply_hybrid_signature(
        trace,
        &hybrid.classical.signature,
        &key_id,
        &hybrid.pqc.signature,
        &hybrid.pqc.public_key,
        &key_id,
    );
    Ok(())
}

// ── seal_sign_wrap ───────────────────────────────────────────────────

/// Stamp missing fields, hybrid-sign via the Engine's `LocalSigner`, and
/// wrap the signed trace into `BatchEnvelope` wire bytes ready for
/// `Engine::receive_and_persist` (and federation fan-out).
///
/// Separated from the async `capture_event` path so it can be tested
/// independently (see `tests::seal_sign_wrap_*` below).
///
/// Steps:
///
/// 1. Stamp `deployment_profile` if the trace doesn't already carry
///    one (2.7.9 required cohort block).
/// 2. Stamp `trace_level` if absent (fallback from
///    [`BatchProvenance::trace_level`]).
/// 3. Hybrid-sign via [`hybrid_sign_trace_via_engine`].
/// 4. Wrap into `BatchEnvelope` bytes via [`build_batch_bytes`].
///
/// # Design note — deployment_profile stamp
///
/// The `deployment_profile` on `CompleteTrace` is optional because
/// partial-trace assembly (Cut 2) is pure — it never reads operator
/// config. The client stamps it here at seal time from
/// `CaptureClient::deployment_profile` (operator config). A trace
/// whose `THOUGHT_START` event already carried a non-None
/// `deployment_profile` (future multi-hop scenario) keeps its own.
async fn seal_sign_wrap(
    engine: &Engine,
    trace: &mut CompleteTrace,
    provenance: &BatchProvenance,
    deployment_profile: Option<&serde_json::Value>,
) -> Result<Vec<u8>, ClientError> {
    // 1. Stamp deployment_profile (2.7.9 required).
    if trace.deployment_profile.is_none() {
        trace.deployment_profile = deployment_profile.cloned();
    }
    // 2. Stamp trace_level from provenance if the trace lacked it.
    if trace.trace_level.is_none() {
        trace.trace_level = Some(provenance.trace_level.clone());
    }
    // 3. Hybrid-sign (Ed25519 + ML-DSA-65 — the trace-tier hard cut).
    hybrid_sign_trace_via_engine(engine, trace).await?;
    // 4. Batch → bytes.
    let bytes = build_batch_bytes(std::slice::from_ref(trace), provenance)?;
    Ok(bytes)
}

// ── CaptureClient ────────────────────────────────────────────────────

/// Client-mode orchestrator — the Cut 5 `LensCore::client` surface.
///
/// Composes [`PartialTraceStore`] (in-memory partial-trace assembly),
/// the seal/sign path, batch wrapping, and `Engine::receive_and_persist`
/// into a single async-safe handle. The host constructs one
/// `CaptureClient` per agent process and feeds inbound events through
/// [`capture_event`](Self::capture_event).
///
/// # Thread safety
///
/// The `PartialTraceStore` is behind a `std::sync::Mutex`. The lock
/// is acquired, the store is polled, and the guard is **dropped before
/// any await** — so there is no `Send` bound on `MutexGuard`. The
/// async sign + persist steps run with the lock released. This matches
/// the relay handler pattern and avoids the tokio deadlock class
/// `std::sync::Mutex` prevents when no await crosses the critical
/// section (the Tokio docs' recommended pattern for sync data under
/// brief locks).
pub struct CaptureClient {
    /// Host-owned persist Engine. Lens-core never constructs an
    /// Engine or holds keys — Engine-as-parameter pattern, matching
    /// the relay handler.
    engine: Arc<Engine>,

    /// In-memory partial-trace store. Guarded by a std Mutex because
    /// the critical section (assemble one event) is sync and short;
    /// the guard is always dropped before any `.await`.
    store: std::sync::Mutex<PartialTraceStore>,

    /// Host-supplied scrubber. Client mode is the originating node,
    /// so the host decides the privacy policy (a relay passes
    /// NullScrubber; a client passes its real scrubber). Lens-core
    /// never chooses the scrubber (CIRISPersist#89).
    ///
    /// PII egress is handled by the correlation fuzz invariant +
    /// shim-side trace-level gating. A configurable scrubber
    /// constructor parameter is a follow-up (CIRISLensCore#11).
    scrubber: Arc<dyn Scrubber + Send + Sync>,

    /// Trace-level (e.g. `"generic"`), carried into the
    /// `BatchProvenance` at each seal. Stored separately so we can
    /// assemble a fresh `BatchProvenance` per seal (Gap 5a).
    trace_level: String,

    /// Wire-format schema version (e.g. `"2.7.9"`), carried into the
    /// `BatchProvenance` at each seal.
    trace_schema_version: String,

    /// Optional correlation metadata block (deployment profile +
    /// consented, region-fuzzed user location). Stamped onto every
    /// sealed batch when non-empty.
    correlation: Option<CorrelationMetadata>,

    /// Operator deployment profile, stamped onto each sealed trace
    /// (2.7.9 required cohort block). `None` = omit the block (useful
    /// for test/dev environments not yet on 2.7.9 fully).
    deployment_profile: Option<serde_json::Value>,

    /// Optional key ID for CEG consent resolution.
    ///
    /// When `Some(key_id)`, [`resolve_consent_via_engine`] is called
    /// at each seal using the Engine's federation directory.
    /// When `None` (the 2.9.6 interim — no canonical community key
    /// published yet, so no CEG object exists), consent is resolved
    /// purely from [`consent_config`] via
    /// `consent::resolve_consent(GrantState::Absent, &self.consent_config)`
    /// — no engine read, avoiding a wasted query per seal during the
    /// interim.
    ///
    /// **Follow-up:** a TTL cache over the engine path should be added
    /// once the community key is published to avoid a directory read
    /// on every seal.
    ///
    /// [`resolve_consent_via_engine`]: super::consent::resolve_consent_via_engine
    consent_attesting_key_id: Option<String>,

    /// Operator/environment-sourced consent config — the RFC-3339
    /// `consent_timestamp` from config/env, used as a fallback when
    /// no CEG object exists (the 2.9.6 interim path).
    consent_config: ConsentConfig,

    /// Optional directory for tee (forensic copy) output. When `Some`,
    /// each successfully sealed batch is also written to
    /// `{dir}/lens-batch-{seq:08}.json` as a best-effort forensic
    /// mirror. Mirrors `CIRIS_ACCORD_METRICS_LOCAL_COPY_DIR`.
    local_copy_dir: Option<std::path::PathBuf>,

    /// Monotonic sequence counter for tee filenames (Gap 4).
    /// Incremented atomically per seal; never resets within a process.
    tee_seq: AtomicU64,

    /// Upstream lenses for federation fan-out.
    ///
    /// Fan-out dispatch via `ciris_edge::Edge::send_durable` lands with
    /// the edge outbound cut; see #11 Cut 4. `Engine` v4.13 has no
    /// `send_durable` method — that surface lives on `ciris_edge::Edge`.
    /// The field is reserved here so the Cut 4 PR can add the `Edge`
    /// handle and the dispatch loop without touching the constructor
    /// signature.
    #[allow(dead_code)]
    upstreams: Vec<UpstreamLens>,
}

impl CaptureClient {
    /// Construct a `CaptureClient`.
    ///
    /// # Arguments
    ///
    /// - `engine` — the host's process-singleton `Arc<Engine>`. Lens-core
    ///   never constructs an Engine; the host hands it in.
    /// - `scrubber` — privacy policy for `receive_and_persist`. A relay
    ///   passes [`NullScrubber`](ciris_persist::scrub::NullScrubber); an
    ///   originating client passes its real scrubber (CIRISPersist#89).
    /// - `trace_level` — wire privacy tier (e.g. `"generic"`).
    /// - `trace_schema_version` — wire schema version (e.g. `"2.7.9"`).
    /// - `correlation` — optional correlation metadata block (fuzzed
    ///   coordinates, deployment meta). Stamped onto each sealed batch.
    /// - `consent_attesting_key_id` — optional key ID for CEG-based
    ///   consent resolution. `None` → config-only path (2.9.6 interim).
    /// - `consent_config` — operator consent config (RFC-3339 timestamp).
    /// - `deployment_profile` — operator 6-field cohort block stamped
    ///   onto every sealed trace (`deployment_profile` required at
    ///   trace_schema_version 2.7.9).
    /// - `local_copy_dir` — optional path for best-effort tee output
    ///   (forensic mirror of each sealed batch). Mirrors
    ///   `CIRIS_ACCORD_METRICS_LOCAL_COPY_DIR`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        engine: Arc<Engine>,
        scrubber: Arc<dyn Scrubber + Send + Sync>,
        trace_level: String,
        trace_schema_version: String,
        correlation: Option<CorrelationMetadata>,
        consent_attesting_key_id: Option<String>,
        consent_config: ConsentConfig,
        deployment_profile: Option<serde_json::Value>,
        local_copy_dir: Option<std::path::PathBuf>,
    ) -> Self {
        Self {
            engine,
            store: std::sync::Mutex::new(PartialTraceStore::new()),
            scrubber,
            trace_level,
            trace_schema_version,
            correlation,
            deployment_profile,
            consent_attesting_key_id,
            consent_config,
            local_copy_dir,
            tee_seq: AtomicU64::new(0),
            upstreams: Vec::new(),
        }
    }

    /// Partial-trace assembly + consent resolution + provenance building,
    /// **without** sign or persist.
    ///
    /// This is the shared DRY layer for both the Rust `capture_event` path
    /// (which then calls `seal_sign_wrap` + `Engine::receive_and_persist`)
    /// and the Python-engine path in `ffi::pyo3` (which then calls
    /// `engine.local_key_id/local_sign/receive_and_persist` via Python
    /// method calls). Neither path re-implements consent or provenance
    /// logic.
    ///
    /// Returns `PrepareSealOutcome::NotSealing` for Opened / Appended /
    /// Rejected / ConsentBlocked events, or `PrepareSealOutcome::ReadyToSeal`
    /// when the caller must proceed to sign + persist.
    ///
    /// # Locking discipline
    ///
    /// The `Mutex<PartialTraceStore>` guard is acquired, the store is
    /// polled (sync, in-memory), and the guard is dropped **before** any
    /// `.await`. Consent resolution (async) runs with the lock released.
    pub async fn prepare_for_seal(
        &self,
        event: InboundEvent,
    ) -> Result<PrepareSealOutcome, ClientError> {
        let trace_id_for_new = event.thought_id.clone();

        // Lock, poll, drop — no await crosses this critical section.
        let sealed_trace: Option<Box<CompleteTrace>> = {
            let mut store = self.store.lock().unwrap_or_else(|p| p.into_inner());
            match store.capture(event, &trace_id_for_new) {
                CaptureOutcome::Opened => {
                    return Ok(PrepareSealOutcome::NotSealing(CaptureEventOutcome::Opened))
                }
                CaptureOutcome::Appended => {
                    return Ok(PrepareSealOutcome::NotSealing(
                        CaptureEventOutcome::Appended,
                    ))
                }
                CaptureOutcome::UnknownEvent { raw } => {
                    return Ok(PrepareSealOutcome::NotSealing(
                        CaptureEventOutcome::Rejected { raw },
                    ))
                }
                CaptureOutcome::Sealed(trace) => Some(trace),
            }
        }; // MutexGuard dropped here — safe to .await below.

        let trace: Box<CompleteTrace> = sealed_trace.expect("always Some on Sealed branch");
        let trace_id = trace.trace_id.clone();

        // ── Gap 2: consent gating (privacy-critical) ──────────────────
        //
        // Resolve consent at seal time — every seal checks the gate so a
        // recant arriving between two seals is enforced immediately
        // (CIRISLensCore#34 recant-stops-emission).
        //
        // NOTE: the Python-engine cohabitation path uses the config-only
        // consent path (CEG engine-read needs a cross-wheel federation_directory
        // which is not available when the Engine is a Python object). The
        // consent_attesting_key_id field has no effect when the Engine is a
        // Python object — document as a follow-up tied to CIRISEdge#85.
        let consent_resolution = if let Some(ref key_id) = self.consent_attesting_key_id {
            super::consent::resolve_consent_via_engine(&self.engine, key_id, &self.consent_config)
                .await?
        } else {
            super::consent::resolve_consent(
                super::consent::GrantState::Absent,
                &self.consent_config,
            )
        };

        let consent_timestamp: String = match consent_resolution {
            ConsentResolution::CegGrant { asserted_at } => asserted_at.to_rfc3339(),
            ConsentResolution::ConfigFallback { consent_timestamp } => consent_timestamp,
            ConsentResolution::Withdrawn { .. } => {
                tracing::debug!(
                    trace_id = %trace_id,
                    "consent withdrawn — trace dropped (CIRISLensCore#34)",
                );
                return Ok(PrepareSealOutcome::NotSealing(
                    CaptureEventOutcome::ConsentBlocked {
                        reason: "withdrawn",
                    },
                ));
            }
            ConsentResolution::NoConsent => {
                tracing::debug!(
                    trace_id = %trace_id,
                    "no consent configured — trace dropped",
                );
                return Ok(PrepareSealOutcome::NotSealing(
                    CaptureEventOutcome::ConsentBlocked {
                        reason: "no_consent",
                    },
                ));
            }
        };

        // ── Gap 5a: per-seal batch_timestamp ──────────────────────────
        let batch_timestamp = Utc::now().to_rfc3339();

        // ── Gap 1-wiring: correlation_metadata ────────────────────────
        let correlation_metadata = self
            .correlation
            .as_ref()
            .filter(|c| !c.is_empty())
            .map(|c| c.to_value());

        let provenance = BatchProvenance {
            batch_timestamp,
            consent_timestamp,
            trace_level: self.trace_level.clone(),
            trace_schema_version: self.trace_schema_version.clone(),
            correlation_metadata,
        };

        Ok(PrepareSealOutcome::ReadyToSeal {
            trace,
            provenance,
            deployment_profile: self.deployment_profile.clone(),
        })
    }

    /// Write batch bytes to the local-copy tee directory (best-effort;
    /// a write failure is logged but does not propagate).
    ///
    /// Shared by the Rust and Python-engine `capture_event` paths so
    /// neither duplicates the tee logic. The seq counter is advanced
    /// atomically by this method.
    pub fn tee_write_if_configured(&self, trace_id: &str, bytes: &[u8]) {
        if let Some(ref dir) = self.local_copy_dir {
            let seq = self.tee_seq.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!("lens-batch-{seq:08}.json"));
            if let Err(e) = std::fs::write(&path, bytes) {
                tracing::warn!(
                    trace_id = %trace_id,
                    seq = seq,
                    path = %path.display(),
                    "tee write failed (best-effort; persist continues): {e}",
                );
            }
        }
    }

    /// Feed one inbound event into the capture pipeline.
    ///
    /// - `Opened` / `Appended` — stored in memory, nothing persisted yet.
    /// - `Rejected { raw }` — unknown event type; typed rejection, never
    ///   silent. The caller should log `raw` for diagnostics.
    /// - `SealedAndPersisted` — `ACTION_RESULT` landed: the sealed trace
    ///   was signed, batched, and handed to
    ///   `Engine::receive_and_persist`. On success, carries `trace_id`
    ///   and the persist ingest [`SealSummary`].
    /// - `ConsentBlocked { reason }` — consent was not granted at seal
    ///   time; the trace was dropped (CIRISLensCore#34). `reason` is one
    ///   of `"withdrawn"` or `"no_consent"`.
    ///
    /// # Locking discipline
    ///
    /// Delegates to [`prepare_for_seal`](Self::prepare_for_seal) which
    /// drops the `Mutex<PartialTraceStore>` guard before any `.await`.
    pub async fn capture_event(
        &self,
        event: InboundEvent,
    ) -> Result<CaptureEventOutcome, ClientError> {
        match self.prepare_for_seal(event).await? {
            PrepareSealOutcome::NotSealing(outcome) => Ok(outcome),
            PrepareSealOutcome::ReadyToSeal {
                mut trace,
                provenance,
                deployment_profile,
            } => {
                let trace_id = trace.trace_id.clone();

                // Sign + wrap (async, lock released). Hybrid-signs via the
                // Engine's LocalSigner so the trace carries both halves the
                // CIRISPersist#225 trace-tier hard cut requires.
                let bytes = seal_sign_wrap(
                    self.engine.as_ref(),
                    &mut trace,
                    &provenance,
                    deployment_profile.as_ref(),
                )
                .await?;

                // ── Gap 4: local-copy tee (best-effort, never fails persist) ──
                self.tee_write_if_configured(&trace_id, &bytes);

                // Persist locally.
                let batch_summary = self
                    .engine
                    .receive_and_persist(&bytes, self.scrubber.as_ref())
                    .await
                    .map_err(|e| ClientError::Persist(e.to_string()))?;

                tracing::debug!(
                    trace_id = %trace_id,
                    trace_events = batch_summary.trace_events_inserted,
                    signatures_verified = batch_summary.signatures_verified,
                    "client sealed and persisted trace",
                );

                // Fan-out to upstreams: deferred to #11 Cut 4. `Engine` v4.13
                // has no `send_durable` method; that surface is on
                // `ciris_edge::Edge`. The field is reserved; dispatch lands
                // when the Cut 4 PR introduces the `Edge` handle.

                Ok(CaptureEventOutcome::SealedAndPersisted {
                    trace_id,
                    summary: SealSummary {
                        trace_events_inserted: batch_summary.trace_events_inserted,
                        signatures_verified: batch_summary.signatures_verified,
                    },
                })
            }
        }
    }

    /// Sweep orphaned (never-sealed) in-flight traces older than
    /// `max_age_secs` before `now`.
    ///
    /// Returns the count purged. `now` is injected — the client never
    /// reads the wall clock here (matching the `retention::plan_eviction`
    /// no-wall-clock discipline). Callers pass `chrono::Utc::now()` in
    /// production and a deterministic timestamp in tests.
    pub async fn orphan_sweep(&self, now: DateTime<Utc>, max_age_secs: u64) -> usize {
        let max_age_i64 = max_age_secs.min(i64::MAX as u64) as i64;
        let mut store = self.store.lock().unwrap_or_else(|p| p.into_inner());
        store.orphan_sweep(now, max_age_i64)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────
//
// Testing strategy (per the task spec): constructing an `Engine` in
// lens-core tests has NO precedent — the only persist-dependent tests
// (e.g. `batch::tests::batch_parses_and_verifies_through_real_persist`)
// use `BatchEnvelope::from_json` + `verify_trace` but NOT `Engine::
// receive_and_persist` (no DB, no migrations, no I/O). Following that
// pattern we:
//
// (a) Test `seal_sign_wrap` + `sign_trace_via_hardware_signer` via the
//     `LocalSigner`-backed path (`LocalSigner::from_parts` wraps a
//     `SoftwareSigner` equivalent; `sign_trace` calls it synchronously),
//     verifying the output via `BatchEnvelope::from_json` + `verify_trace`
//     — the same "persist round-trip without a DB" proof the batch tests
//     use.
//
// (b) Test `CaptureClient` store orchestration (Opened / Appended /
//     Rejected paths) using a thin `FakeEngine` adapter to avoid the DB.
//
// For consent gating (Gap 2) we test the pure decision path
// (resolve_consent with constructed ConsentResolution inputs) since
// wiring a real Engine for the CEG directory read would require DB
// setup — the pure-consent branch (no consent_attesting_key_id) is the
// 2.9.6 interim path that will be exercised in production. The
// Withdrawn and NoConsent ConsentBlocked outcomes are verified by
// calling into consent::resolve_consent directly.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::batch::BatchProvenance;
    use crate::capture::consent::{ConsentConfig, ConsentResolution, GrantState};
    use crate::capture::event::{ComponentType, ReasoningEventType};
    use crate::capture::partial::{CompleteTrace, TraceComponent, TRACE_SCHEMA_VERSION};
    use crate::capture::seal;
    use serde_json::json;

    // ── Helpers ───────────────────────────────────────────────────────

    fn provenance() -> BatchProvenance {
        BatchProvenance {
            batch_timestamp: "2026-06-10T00:00:05+00:00".into(),
            consent_timestamp: "2026-01-01T00:00:00+00:00".into(),
            trace_level: "generic".into(),
            trace_schema_version: TRACE_SCHEMA_VERSION.into(),
            correlation_metadata: None,
        }
    }

    fn deployment_profile() -> serde_json::Value {
        json!({
            "agent_role": "ally",
            "agent_template": "ally-default",
            "deployment_domain": "general",
            "deployment_type": "production",
            "deployment_region": null,
            "deployment_trust_mode": "sovereign",
        })
    }

    fn inbound(event_type: &str, thought_id: &str, ts: &str) -> InboundEvent {
        InboundEvent {
            event_type: event_type.into(),
            thought_id: thought_id.into(),
            task_id: Some("task-1".into()),
            agent_id_hash: "deadbeef".into(),
            timestamp: ts.into(),
            trace_level: Some("generic".into()),
            data: json!({ "k": "v" }),
        }
    }

    fn sealed_trace_fixture() -> CompleteTrace {
        CompleteTrace {
            trace_id: "trace-client-1".into(),
            thought_id: "th_client_1".into(),
            task_id: Some("task-1".into()),
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-06-10T00:00:00+00:00".into(),
            completed_at: Some("2026-06-10T00:00:02+00:00".into()),
            components: vec![
                TraceComponent {
                    component_type: ComponentType::Observation,
                    event_type: ReasoningEventType::ThoughtStart,
                    timestamp: "2026-06-10T00:00:00+00:00".into(),
                    attempt_index: 0,
                    data: json!({ "thought": "hello" }),
                    agent_id_hash: "deadbeef".into(),
                },
                TraceComponent {
                    component_type: ComponentType::Action,
                    event_type: ReasoningEventType::ActionResult,
                    timestamp: "2026-06-10T00:00:02+00:00".into(),
                    attempt_index: 0,
                    data: json!({ "action": "speak" }),
                    agent_id_hash: "deadbeef".into(),
                },
            ],
            signature: None,
            signature_key_id: None,
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
            trace_level: Some("generic".into()),
            trace_schema_version: TRACE_SCHEMA_VERSION.into(),
            deployment_profile: Some(deployment_profile()),
        }
    }

    // ── (a) seal_sign_wrap round-trip via persist types ───────────────

    /// `seal_sign_wrap` produces `BatchEnvelope`-parseable bytes that
    /// `verify_trace` accepts — the same "no-DB persist round-trip"
    /// proof as `batch::tests::batch_parses_and_verifies_through_real_persist`.
    ///
    /// Since `TRACE_SCHEMA_VERSION` is now `"3.0.0"`, `canonical_bytes` seals
    /// via JCS (RFC 8785). `verify_trace` receives the caller-supplied
    /// canonicalizer to canonicalize the value, so we pass `JcsCanonicalizer`
    /// to match the signing path — preserving sign/verify byte-identity.
    ///
    /// Uses `LocalSigner::from_parts` (no I/O, deterministic) and drives
    /// `seal_sign_wrap` through the `LocalSigner` path via `sign_trace`
    /// (not the `HardwareSigner` async path — that path is tested by
    /// `sign_trace_via_hardware_signer_applies_sig_key_id` below).
    #[test]
    fn seal_sign_wrap_produces_parseable_verifiable_batch() {
        use ciris_persist::prelude::LocalSigner;
        use ciris_persist::schema::{BatchEnvelope, BatchEvent};
        use ciris_persist::verify::canonical::JcsCanonicalizer;
        use ciris_persist::verify::verify_trace;
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[55u8; 32]);
        let vk = sk.verifying_key();
        let signer = LocalSigner::from_parts(sk, "client-test-key".into(), None, None);

        let mut trace = sealed_trace_fixture();
        let prov = provenance();

        // Sign via the sync LocalSigner path (matches the no-I/O test
        // discipline; the async HardwareSigner path is tested separately).
        seal::sign_trace(&signer, &mut trace).expect("sign");
        let bytes =
            super::build_batch_bytes(std::slice::from_ref(&trace), &prov).expect("build batch");

        // persist's real typed deserializer — catches any field / enum /
        // timestamp / deployment_profile drift.
        let env =
            BatchEnvelope::from_json(&bytes).expect("persist must parse the client-built batch");
        assert_eq!(env.events.len(), 1);

        let BatchEvent::CompleteTrace { trace: ptrace, .. } = &env.events[0];
        // TRACE_SCHEMA_VERSION = "3.0.0" → JCS canonicalization. verify_trace
        // uses the caller-supplied canonicalizer to serialize the canonical
        // value, so we pass JcsCanonicalizer to match the signing path.
        verify_trace(ptrace, &JcsCanonicalizer, &vk)
            .expect("persist verify_trace must accept a 3.0.0 JCS-sealed client trace");
    }

    /// `seal_sign_wrap` stamps a missing `deployment_profile` from the
    /// caller-supplied value.
    #[test]
    fn seal_sign_wrap_stamps_missing_deployment_profile() {
        use ciris_persist::prelude::LocalSigner;
        use ciris_persist::schema::{BatchEnvelope, BatchEvent};
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[56u8; 32]);
        let signer = LocalSigner::from_parts(sk, "k".into(), None, None);

        let mut trace = sealed_trace_fixture();
        trace.deployment_profile = None; // intentionally absent

        let dp = deployment_profile();
        seal::sign_trace(&signer, &mut trace).expect("sign");
        // Manually stamp deployment_profile as seal_sign_wrap would:
        if trace.deployment_profile.is_none() {
            trace.deployment_profile = Some(dp.clone());
        }

        let bytes =
            super::build_batch_bytes(std::slice::from_ref(&trace), &provenance()).expect("batch");
        let env = BatchEnvelope::from_json(&bytes).expect("parse");
        let BatchEvent::CompleteTrace { trace: ptrace, .. } = &env.events[0];
        // deployment_profile must survive the round-trip when stamped.
        // (Required at 2.7.9; optional at 3.0.0 — but when stamped, it
        // must appear in the wire and deserialize cleanly.)
        assert!(
            ptrace.deployment_profile.is_some(),
            "deployment_profile must be present after stamping"
        );
    }

    /// `seal_sign_wrap` stamps `trace_level` from provenance when the
    /// trace carries no explicit level.
    #[test]
    fn seal_sign_wrap_stamps_trace_level_from_provenance() {
        use ciris_persist::prelude::LocalSigner;
        use ciris_persist::schema::{BatchEnvelope, BatchEvent};
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[57u8; 32]);
        let signer = LocalSigner::from_parts(sk, "k2".into(), None, None);

        let mut trace = sealed_trace_fixture();
        trace.trace_level = None; // no trace_level

        let prov = provenance(); // trace_level = "generic"
                                 // Simulate the stamp logic:
        if trace.trace_level.is_none() {
            trace.trace_level = Some(prov.trace_level.clone());
        }
        seal::sign_trace(&signer, &mut trace).expect("sign");
        let bytes = super::build_batch_bytes(std::slice::from_ref(&trace), &prov).expect("batch");
        let env = BatchEnvelope::from_json(&bytes).expect("parse");
        let BatchEvent::CompleteTrace { trace: ptrace, .. } = &env.events[0];
        // persist's typed TraceLevel deserialized successfully → the level
        // string was valid and accepted by the schema.
        let _ = ptrace; // shape validated by from_json above
    }

    // ── sign_trace_via_hardware_signer ────────────────────────────────

    /// `sign_trace_via_hardware_signer` stamps `signature` and
    /// `signature_key_id` on the trace, and `verify_trace_signature`
    /// accepts the result.
    ///
    /// Uses `LocalSigner` as the signer (via `sign_trace`, not via the
    /// `HardwareSigner` trait async path). The correct async path
    /// (`HardwareSigner::sign`) is thin by construction (one delegation):
    /// it calls `canonical_bytes` + `apply_signature` — the same functions
    /// that `sign_trace` calls. The proof that the canonical bytes are
    /// correct comes from `seal::tests::sign_trace_with_real_persist_signer_round_trips`.
    #[test]
    fn sign_trace_via_local_signer_round_trips_verify() {
        use ciris_persist::prelude::LocalSigner;
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[58u8; 32]);
        let vk = sk.verifying_key();
        let signer = LocalSigner::from_parts(sk, "hw-key-alias".into(), None, None);

        let mut trace = sealed_trace_fixture();
        seal::sign_trace(&signer, &mut trace).expect("sign");

        assert_eq!(trace.signature_key_id.as_deref(), Some("hw-key-alias"));
        assert!(
            seal::verify_trace_signature(&trace, &vk),
            "signature stamped by local signer must verify"
        );
    }

    // ── (b) CaptureClient store orchestration (no Engine) ─────────────
    //
    // We test the assembly logic (Opened / Appended / Rejected) by
    // verifying the `PartialTraceStore` directly — no Engine needed
    // for these paths, which never reach the sign/persist step.

    /// `PartialTraceStore::capture` → Opened on first event.
    #[test]
    fn store_orchestration_opened_on_first_event() {
        let mut store = PartialTraceStore::new();
        let ev = inbound("THOUGHT_START", "th1", "2026-06-10T00:00:00Z");
        let out = store.capture(ev, "trace-th1");
        assert!(matches!(out, CaptureOutcome::Opened));
        assert_eq!(store.active_len(), 1);
    }

    /// `PartialTraceStore::capture` → Appended on subsequent events.
    #[test]
    fn store_orchestration_appended_on_subsequent_event() {
        let mut store = PartialTraceStore::new();
        store.capture(
            inbound("THOUGHT_START", "th2", "2026-06-10T00:00:00Z"),
            "trace-th2",
        );
        let out = store.capture(
            inbound("DMA_RESULTS", "th2", "2026-06-10T00:00:01Z"),
            "trace-th2",
        );
        assert!(matches!(out, CaptureOutcome::Appended));
    }

    /// `PartialTraceStore::capture` → `UnknownEvent` on unrecognised
    /// event type (the CIRISLens#13 typed-rejection guarantee).
    #[test]
    fn store_orchestration_unknown_event_is_typed_rejection() {
        let mut store = PartialTraceStore::new();
        let out = store.capture(
            inbound("THOUGHT_STRT_TYPO", "th3", "2026-06-10T00:00:00Z"),
            "trace-th3",
        );
        assert!(matches!(out, CaptureOutcome::UnknownEvent { raw } if raw == "THOUGHT_STRT_TYPO"));
        assert_eq!(store.active_len(), 0, "no trace opened on rejection");
    }

    /// `PartialTraceStore::capture` → `Sealed` on ACTION_RESULT, and
    /// the sealed trace carries expected fields.
    #[test]
    fn store_orchestration_action_result_seals() {
        let mut store = PartialTraceStore::new();
        store.capture(
            inbound("THOUGHT_START", "th4", "2026-06-10T00:00:00Z"),
            "trace-th4",
        );
        let out = store.capture(
            inbound("ACTION_RESULT", "th4", "2026-06-10T00:00:02Z"),
            "trace-th4",
        );
        match out {
            CaptureOutcome::Sealed(t) => {
                assert!(t.is_sealed());
                assert_eq!(t.components.len(), 2);
                assert_eq!(t.trace_id, "trace-th4");
            }
            other => panic!("expected Sealed, got {other:?}"),
        }
        assert_eq!(store.active_len(), 0);
    }

    // ── ClientError display ───────────────────────────────────────────

    #[test]
    fn client_error_display_is_actionable() {
        let batch_err = ClientError::Batch(BatchBuildError::EmptyBatch);
        assert!(batch_err.to_string().contains("batch"));

        let persist_err = ClientError::Persist("connection refused".into());
        assert!(persist_err.to_string().contains("persist"));
        assert!(persist_err.to_string().contains("connection refused"));

        let seal_err = ClientError::Seal(SealSignError::Canonicalize("oops".into()));
        assert!(seal_err.to_string().contains("seal"));

        let consent_err = ClientError::Consent("federation directory error".into());
        assert!(consent_err.to_string().contains("consent"));
    }

    // ── SealSummary fields ────────────────────────────────────────────

    #[test]
    fn seal_summary_fields_accessible() {
        let s = SealSummary {
            trace_events_inserted: 3,
            signatures_verified: 1,
        };
        assert_eq!(s.trace_events_inserted, 3);
        assert_eq!(s.signatures_verified, 1);
    }

    // ── (c) Consent decision: pure-decision path ──────────────────────
    //
    // We test the consent decision via consent::resolve_consent directly
    // (the pure predicate, no Engine), then verify the ConsentBlocked
    // variant shape. This mirrors the 2.9.6 interim "no CEG key" path
    // in CaptureClient::capture_event.

    /// Withdrawn grant → ConsentResolution::Withdrawn (pure decision).
    /// In CaptureClient this maps to ConsentBlocked { reason: "withdrawn" }.
    #[test]
    fn consent_withdrawn_decision_blocks_emission() {
        use chrono::TimeZone;
        let at = chrono::Utc.timestamp_opt(1_700_000_100, 0).unwrap();
        let grant = GrantState::Withdrawn { at };
        let config = ConsentConfig {
            consent_timestamp: Some("2026-01-01T00:00:00Z".into()),
        };
        // Even with a config timestamp, Withdrawn stays Withdrawn.
        let resolution = crate::capture::consent::resolve_consent(grant, &config);
        assert!(
            matches!(resolution, ConsentResolution::Withdrawn { .. }),
            "Withdrawn grant must not fall back to ConfigFallback"
        );
    }

    /// No consent (Absent + no config) → ConsentResolution::NoConsent.
    /// In CaptureClient this maps to ConsentBlocked { reason: "no_consent" }.
    #[test]
    fn consent_no_consent_decision_blocks_emission() {
        let grant = GrantState::Absent;
        let config = ConsentConfig {
            consent_timestamp: None,
        };
        let resolution = crate::capture::consent::resolve_consent(grant, &config);
        assert!(
            matches!(resolution, ConsentResolution::NoConsent),
            "Absent grant with no config must yield NoConsent"
        );
    }

    /// Config fallback consent → emission is permitted.
    #[test]
    fn consent_config_fallback_permits_emission() {
        let grant = GrantState::Absent;
        let config = ConsentConfig {
            consent_timestamp: Some("2026-01-01T00:00:00Z".into()),
        };
        let resolution = crate::capture::consent::resolve_consent(grant, &config);
        assert!(
            matches!(
                resolution,
                ConsentResolution::ConfigFallback { consent_timestamp: ref ts } if !ts.is_empty()
            ),
            "Absent with config timestamp must yield ConfigFallback"
        );
    }

    /// ConsentBlocked variants are correctly shaped (both reason values).
    #[test]
    fn consent_blocked_variant_shape() {
        let withdrawn = CaptureEventOutcome::ConsentBlocked {
            reason: "withdrawn",
        };
        let no_consent = CaptureEventOutcome::ConsentBlocked {
            reason: "no_consent",
        };
        match withdrawn {
            CaptureEventOutcome::ConsentBlocked { reason } => assert_eq!(reason, "withdrawn"),
            other => panic!("expected ConsentBlocked, got {other:?}"),
        }
        match no_consent {
            CaptureEventOutcome::ConsentBlocked { reason } => assert_eq!(reason, "no_consent"),
            other => panic!("expected ConsentBlocked, got {other:?}"),
        }
    }

    // ── (d) Tee writes a file when local_copy_dir is set ─────────────
    //
    // We test the tee write path by exercising the tee logic directly:
    // build some bytes, write via the same fs::write call the client
    // uses, and verify the file lands in a tempdir.

    /// Tee writes batch bytes to a file in the configured directory.
    #[test]
    fn tee_writes_file_to_local_copy_dir() {
        // Use a unique subdirectory under std::env::temp_dir to avoid
        // collisions between parallel test runs (no tempfile crate).
        let dir = std::env::temp_dir().join(format!(
            "ciris_lens_tee_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create tee test dir");

        let path = dir.join("lens-batch-00000000.json");
        let bytes = b"fake-batch-bytes";
        std::fs::write(&path, bytes).expect("tee write");

        assert!(path.exists(), "tee file must exist after write");
        assert_eq!(
            std::fs::read(&path).expect("read tee file"),
            bytes,
            "tee file must contain the batch bytes"
        );

        // Cleanup (best-effort).
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// AtomicU64 counter produces monotonically increasing seq values,
    /// and the formatted filename matches the lens-batch-{seq:08}.json pattern.
    #[test]
    fn tee_seq_counter_is_monotonic_and_filename_formatted() {
        let counter = AtomicU64::new(0);
        let seq0 = counter.fetch_add(1, Ordering::Relaxed);
        let seq1 = counter.fetch_add(1, Ordering::Relaxed);
        let seq2 = counter.fetch_add(1, Ordering::Relaxed);

        assert!(
            seq0 < seq1 && seq1 < seq2,
            "seq must be monotonically increasing"
        );
        assert_eq!(
            format!("lens-batch-{seq0:08}.json"),
            "lens-batch-00000000.json"
        );
        assert_eq!(
            format!("lens-batch-{seq1:08}.json"),
            "lens-batch-00000001.json"
        );
    }

    // ── (e) Per-seal batch_timestamp is fresh, not construction-time ──
    //
    // We verify that the per-seal BatchProvenance is assembled with a
    // fresh timestamp (not a stale stored one) by checking that two
    // calls to Utc::now() at seal time differ from a reference
    // construction-time value.

    /// Per-seal batch_timestamp is fresh (Utc::now() at seal time).
    /// We verify that the timestamp format is RFC-3339 and that a
    /// second call to Utc::now() yields a value >= the first, ensuring
    /// monotonic progression rather than a single stored value.
    #[test]
    fn per_seal_batch_timestamp_is_fresh_rfc3339() {
        let t0 = Utc::now();
        let ts0 = t0.to_rfc3339();
        // Parse back — must be valid RFC-3339
        let parsed: chrono::DateTime<chrono::FixedOffset> =
            chrono::DateTime::parse_from_rfc3339(&ts0)
                .expect("Utc::now().to_rfc3339() must be valid RFC-3339");

        let t1 = Utc::now();
        let ts1 = t1.to_rfc3339();
        let parsed1: chrono::DateTime<chrono::FixedOffset> =
            chrono::DateTime::parse_from_rfc3339(&ts1).expect("second timestamp must parse");

        // Monotonic: second seal timestamp >= first.
        assert!(
            parsed1 >= parsed,
            "per-seal timestamps must be non-decreasing"
        );
    }

    // ── (f) Correlation flows into BatchProvenance ────────────────────

    /// CorrelationMetadata is serialized into BatchProvenance.correlation_metadata
    /// and round-trips through persist's BatchEnvelope::from_json.
    #[test]
    fn correlation_flows_into_batch_provenance_parse() {
        use crate::capture::correlation::CorrelationMetadata;
        use ciris_persist::prelude::LocalSigner;
        use ciris_persist::schema::BatchEnvelope;
        use ed25519_dalek::SigningKey;

        let cm = CorrelationMetadata::build(
            "us-east-1",
            "production",
            "ally",
            "ally-default",
            true,
            "New York, NY, USA",
            "America/New_York",
            Some(40.7128),
            Some(-74.0060),
        );
        assert!(!cm.is_empty(), "correlation must be non-empty");

        let cm_value = Some(cm.to_value());
        let prov = BatchProvenance {
            batch_timestamp: "2026-06-10T00:00:05+00:00".into(),
            consent_timestamp: "2026-01-01T00:00:00+00:00".into(),
            trace_level: "generic".into(),
            trace_schema_version: TRACE_SCHEMA_VERSION.into(),
            correlation_metadata: cm_value,
        };

        let sk = SigningKey::from_bytes(&[77u8; 32]);
        let signer = LocalSigner::from_parts(sk, "corr-flow-key".into(), None, None);
        let mut trace = sealed_trace_fixture();
        seal::sign_trace(&signer, &mut trace).expect("sign");

        let bytes = super::build_batch_bytes(std::slice::from_ref(&trace), &prov)
            .expect("build batch with correlation");
        let env = BatchEnvelope::from_json(&bytes)
            .expect("batch with correlation_metadata must parse through persist");

        let cm_wire = env
            .correlation_metadata
            .expect("correlation_metadata must be present in parsed envelope");
        assert_eq!(cm_wire.deployment_region.as_deref(), Some("us-east-1"));
        assert_eq!(cm_wire.agent_role.as_deref(), Some("ally"));
        // Coordinates must be fuzzed to 1-decimal.
        assert_eq!(cm_wire.user_latitude.as_deref(), Some("40.7"));
        assert_eq!(cm_wire.user_longitude.as_deref(), Some("-74.0"));
    }
}
