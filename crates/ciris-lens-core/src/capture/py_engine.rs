//! Python-engine cohabitation path for `LensClient` (CIRISLensCore#43.1 P0).
//!
//! In the pip cohabitation deployment (lens-core wheel + ciris_persist wheel
//! in the same process), each wheel statically links its own copy of
//! ciris_persist. The `OnceLock`-backed `current_rust_engine()` static in
//! lens-core's bundled copy of ciris_persist is **never populated** — only
//! the host wheel's static is. Calling `current_rust_engine()` from lens-core
//! returns `None` → `RuntimeError: no process Engine`.
//!
//! The fix (`LensClient(engine=...)`) passes the host's
//! `ciris_persist.Engine` Python object explicitly. Sign+persist steps are
//! driven via Python method calls on that object, which dispatch through the
//! host's `PyEngine` — cross-wheel-safe because they go through the Python
//! layer, not the Rust static.
//!
//! This module contains [`PyEngineCapture`] — the partial-trace store +
//! consent/provenance state for the Python-engine path. It mirrors
//! [`CaptureClient`](super::client::CaptureClient) structurally but holds no
//! `Arc<Engine>` (since that Rust type is only accessible through the
//! per-wheel static, which is empty in the cohabitation case).
//!
//! # DRY discipline
//!
//! This module reuses every pure Rust helper:
//! - [`PartialTraceStore`](super::partial::PartialTraceStore) — in-memory trace assembly
//! - [`super::consent::resolve_consent`] — pure consent predicate (config path only)
//! - [`BatchProvenance`](super::batch::BatchProvenance) + [`build_batch_bytes`](super::batch::build_batch_bytes) — batch wire format
//! - [`canonical_bytes`](super::seal::canonical_bytes) + [`apply_signature`](super::seal::apply_signature) — signing envelope
//!
//! The only non-reused steps are sign+persist, which are driven via
//! `engine.local_key_id()` / `engine.local_sign(bytes)` /
//! `engine.receive_and_persist(bytes)` Python method calls from `ffi::pyo3`.
//!
//! # Consent path
//!
//! The Python-engine cohabitation path uses the **config-fallback consent
//! path only** — no CEG engine read. The CEG path needs a cross-wheel
//! `federation_directory` accessor not yet available when the Engine is a
//! Python object. Follow-up: CIRISEdge#85.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::batch::{build_batch_bytes, BatchBuildError, BatchProvenance};
use super::consent::{ConsentConfig, ConsentResolution, GrantState};
use super::correlation::CorrelationMetadata;
use super::partial::{CaptureOutcome, CompleteTrace, InboundEvent, PartialTraceStore};
use super::seal;
use crate::config::UpstreamLens;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors from the Python-engine cohabitation capture path.
#[derive(Debug, thiserror::Error)]
pub enum PyEngineError {
    /// Partial-trace assembly + consent + bytes building (Rust side) failed.
    #[error("prepare: {0}")]
    Prepare(String),
    /// Batch bytes building failed.
    #[error("batch: {0}")]
    Batch(#[from] BatchBuildError),
    /// Consent was withdrawn or not configured — trace dropped.
    #[error("consent_blocked: {reason}")]
    ConsentBlocked { reason: &'static str },
}

// ── PrepareOutcome ────────────────────────────────────────────────────────────

/// Result of [`PyEngineCapture::prepare`] — either the event was handled
/// without reaching the seal step, or the trace is ready for sign+persist
/// via the host Python engine.
#[derive(Debug)]
pub enum PyPrepareOutcome {
    /// Event was non-sealing (Opened / Appended / Rejected). No further
    /// action required from the caller.
    NonSealing(NonSealingKind),
    /// Consent blocked — trace was dropped.
    ConsentBlocked { reason: &'static str },
    /// Trace is sealed, consent granted, provenance assembled. The caller
    /// (ffi::pyo3) must now:
    /// 1. Call `engine.local_key_id()` → key_id: str
    /// 2. Call `engine.local_sign(canonical_bytes)` → sig: bytes (64 bytes)
    /// 3. Call `seal::apply_signature(&mut trace, &sig, &key_id)`
    /// 4. Call `build_batch_bytes(&[trace], &provenance)` → batch_bytes
    /// 5. Call `engine.receive_and_persist(batch_bytes)` → summary dict
    /// 6. Call `tee_write_if_configured(&trace_id, &batch_bytes)`
    ReadyToSeal {
        /// Boxed to keep the enum's stack size reasonable (CompleteTrace is large).
        trace: Box<CompleteTrace>,
        provenance: BatchProvenance,
    },
}

#[derive(Debug)]
pub enum NonSealingKind {
    Opened,
    Appended,
    Rejected { raw: String },
}

// ── PyEngineCapture ───────────────────────────────────────────────────────────

/// Partial-trace store + consent/provenance config for the Python-engine
/// cohabitation path.
///
/// Mirrors [`CaptureClient`](super::client::CaptureClient) but holds no
/// `Arc<Engine>` — it can be constructed without a Rust Engine handle,
/// which is unavailable in the cohabitation scenario.
pub struct PyEngineCapture {
    /// In-memory partial-trace store. Same locking discipline as
    /// `CaptureClient`: the guard is always dropped before any async
    /// operation (there are none here — `prepare` is sync).
    store: Mutex<PartialTraceStore>,

    /// Operator/environment-sourced consent config — the RFC-3339
    /// `consent_timestamp` from config/env (2.9.6 interim).
    consent_config: ConsentConfig,

    /// Optional correlation metadata block. Stamped onto every sealed batch.
    correlation: Option<CorrelationMetadata>,

    /// Operator deployment profile, stamped onto each sealed trace.
    deployment_profile: Option<Value>,

    /// Trace-level (e.g. `"generic"`), carried into the `BatchProvenance`.
    trace_level: String,

    /// Wire-format schema version (e.g. `"2.7.9"` or `"3.0.0"`).
    trace_schema_version: String,

    /// Optional directory for tee (forensic copy) output.
    local_copy_dir: Option<std::path::PathBuf>,

    /// Monotonic sequence counter for tee filenames.
    tee_seq: AtomicU64,

    /// Upstream lenses (reserved for Cut 4 fan-out; empty).
    #[allow(dead_code)]
    upstreams: Vec<UpstreamLens>,
}

impl PyEngineCapture {
    /// Construct a `PyEngineCapture`.
    ///
    /// No `Arc<Engine>` required — this is the cohabitation path where the
    /// Rust Engine handle is unavailable in lens-core's address space.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        consent_config: ConsentConfig,
        correlation: Option<CorrelationMetadata>,
        deployment_profile: Option<Value>,
        trace_level: String,
        trace_schema_version: String,
        local_copy_dir: Option<std::path::PathBuf>,
    ) -> Self {
        Self {
            store: Mutex::new(PartialTraceStore::new()),
            consent_config,
            correlation,
            deployment_profile,
            trace_level,
            trace_schema_version,
            local_copy_dir,
            tee_seq: AtomicU64::new(0),
            upstreams: Vec::new(),
        }
    }

    /// Partial-trace assembly + consent resolution + provenance building,
    /// **without** sign or persist.
    ///
    /// This is a **sync** function — no tokio required. The store operation
    /// is in-memory; consent is resolved from config (no engine read). The
    /// caller (ffi::pyo3's `capture_event`) proceeds to sign+persist via
    /// Python method calls when `PyPrepareOutcome::ReadyToSeal` is returned.
    ///
    /// # Consent note
    ///
    /// Uses config-fallback only — `GrantState::Absent` (no CEG key, no
    /// engine read). A withdrawn grant check requires a CEG object, which
    /// is not accessible cross-wheel. When the cohabitation path is in use,
    /// `consent_timestamp` in `ConsentConfig` is the enforcement mechanism.
    /// Follow-up: CIRISEdge#85.
    pub fn prepare(&self, event: InboundEvent) -> PyPrepareOutcome {
        let trace_id_for_new = event.thought_id.clone();

        // Lock, poll, drop — short sync critical section.
        let maybe_trace: Option<Box<CompleteTrace>> = {
            let mut store = self.store.lock().unwrap_or_else(|p| p.into_inner());
            match store.capture(event, &trace_id_for_new) {
                CaptureOutcome::Opened => {
                    return PyPrepareOutcome::NonSealing(NonSealingKind::Opened)
                }
                CaptureOutcome::Appended => {
                    return PyPrepareOutcome::NonSealing(NonSealingKind::Appended)
                }
                CaptureOutcome::UnknownEvent { raw } => {
                    return PyPrepareOutcome::NonSealing(NonSealingKind::Rejected { raw })
                }
                CaptureOutcome::Sealed(trace) => Some(trace),
            }
        };

        let mut trace: Box<CompleteTrace> = maybe_trace.expect("always Some on Sealed branch");
        let trace_id = trace.trace_id.clone();

        // ── Consent: config-fallback only (no CEG engine read) ───────────
        let consent_resolution =
            super::consent::resolve_consent(GrantState::Absent, &self.consent_config);

        let consent_timestamp: String = match consent_resolution {
            ConsentResolution::CegGrant { asserted_at } => asserted_at.to_rfc3339(),
            ConsentResolution::ConfigFallback { consent_timestamp } => consent_timestamp,
            ConsentResolution::Withdrawn { .. } => {
                tracing::debug!(
                    trace_id = %trace_id,
                    "consent withdrawn — trace dropped (CIRISLensCore#34, cohabitation path)",
                );
                return PyPrepareOutcome::ConsentBlocked {
                    reason: "withdrawn",
                };
            }
            ConsentResolution::NoConsent => {
                tracing::debug!(
                    trace_id = %trace_id,
                    "no consent configured — trace dropped (cohabitation path)",
                );
                return PyPrepareOutcome::ConsentBlocked {
                    reason: "no_consent",
                };
            }
        };

        // ── Stamp deployment_profile + trace_level from config ───────────
        if trace.deployment_profile.is_none() {
            trace.deployment_profile = self.deployment_profile.clone();
        }
        if trace.trace_level.is_none() {
            trace.trace_level = Some(self.trace_level.clone());
        }

        // ── Per-seal batch_timestamp (wall-clock; allowed in I/O layer) ──
        let batch_timestamp = Utc::now().to_rfc3339();

        // ── Correlation metadata ──────────────────────────────────────────
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

        PyPrepareOutcome::ReadyToSeal { trace, provenance }
    }

    /// Canonical bytes for a prepared (stamped) sealed trace.
    ///
    /// Delegates to [`seal::canonical_bytes`] — the federation-wide
    /// canonicalization authority (lens-core never re-implements it).
    ///
    /// Separate method so ffi::pyo3 can call it between `prepare` and
    /// `apply_signature_and_batch`, keeping the sign step (Python call)
    /// outside Rust.
    pub fn canonical_bytes_for(trace: &CompleteTrace) -> Result<Vec<u8>, String> {
        seal::canonical_bytes(trace)
    }

    /// Apply the host-signed Ed25519 signature to a prepared trace, then
    /// build the `BatchEnvelope` wire bytes.
    ///
    /// Called by ffi::pyo3 after receiving the 64-byte signature from
    /// `engine.local_sign(canonical_bytes)`.
    ///
    /// Delegates to [`seal::apply_signature`] and [`build_batch_bytes`] —
    /// never re-implements signing or wire-format rules.
    pub fn apply_signature_and_batch(
        trace: &mut CompleteTrace,
        sig_bytes: &[u8],
        key_id: &str,
        provenance: &BatchProvenance,
    ) -> Result<Vec<u8>, BatchBuildError> {
        seal::apply_signature(trace, sig_bytes, key_id);
        build_batch_bytes(std::slice::from_ref(trace), provenance)
    }

    /// Apply a HYBRID (Ed25519 + ML-DSA-65) signature to a prepared trace,
    /// then build the `BatchEnvelope` wire bytes — the federation-admissible
    /// seal persist v10's `VerifyMode::Full` hard cut (`HybridPolicy::Strict`)
    /// requires (CIRISServer#121 / CIRISPersist#225). Called by ffi::pyo3 after
    /// it obtains the Ed25519 half from `engine.local_sign(canonical)` and the
    /// ML-DSA-65 half from `engine.local_pqc_sign(canonical ‖ ed25519_sig)`
    /// (the bound construction), plus the producer's ML-DSA-65 pubkey.
    /// Delegates to [`seal::apply_hybrid_signature`] — never rolls crypto.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_hybrid_signature_and_batch(
        trace: &mut CompleteTrace,
        ed25519_sig: &[u8],
        key_id: &str,
        ml_dsa_65_sig: &[u8],
        pubkey_ml_dsa_65: &[u8],
        pqc_key_id: &str,
        provenance: &BatchProvenance,
    ) -> Result<Vec<u8>, BatchBuildError> {
        seal::apply_hybrid_signature(
            trace,
            ed25519_sig,
            key_id,
            ml_dsa_65_sig,
            pubkey_ml_dsa_65,
            pqc_key_id,
        );
        build_batch_bytes(std::slice::from_ref(trace), provenance)
    }

    /// Write batch bytes to the local-copy tee directory (best-effort).
    ///
    /// Shared with the Rust-path `CaptureClient::tee_write_if_configured`
    /// in purpose; implemented here independently so neither path has a
    /// direct dependency on the other.
    pub fn tee_write_if_configured(&self, trace_id: &str, bytes: &[u8]) {
        if let Some(ref dir) = self.local_copy_dir {
            let seq = self.tee_seq.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!("lens-batch-{seq:08}.json"));
            if let Err(e) = std::fs::write(&path, bytes) {
                tracing::warn!(
                    trace_id = %trace_id,
                    seq = seq,
                    path = %path.display(),
                    "tee write failed (best-effort; persist continues): {e} [cohabitation path]",
                );
            }
        }
    }

    /// Orphan sweep — purge in-flight traces older than `max_age_secs` before `now`.
    ///
    /// Mirrors `CaptureClient::orphan_sweep` without requiring a tokio runtime
    /// (sync operation on the in-memory store).
    pub fn orphan_sweep(&self, now: DateTime<Utc>, max_age_secs: u64) -> usize {
        let max_age_i64 = max_age_secs.min(i64::MAX as u64) as i64;
        let mut store = self.store.lock().unwrap_or_else(|p| p.into_inner());
        store.orphan_sweep(now, max_age_i64)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::partial::TRACE_SCHEMA_VERSION;
    use serde_json::json;

    fn consent_config(ts: Option<&str>) -> ConsentConfig {
        ConsentConfig {
            consent_timestamp: ts.map(String::from),
        }
    }

    fn make_capture(consent_ts: Option<&str>) -> PyEngineCapture {
        PyEngineCapture::new(
            consent_config(consent_ts),
            None,
            Some(json!({
                "agent_role": "ally",
                "agent_template": "ally-default",
                "deployment_domain": "general",
                "deployment_type": "production",
                "deployment_region": null,
                "deployment_trust_mode": "sovereign",
            })),
            "generic".into(),
            TRACE_SCHEMA_VERSION.into(),
            None,
        )
    }

    fn ev(event_type: &str, thought_id: &str, ts: &str) -> InboundEvent {
        InboundEvent {
            event_type: event_type.into(),
            thought_id: thought_id.into(),
            task_id: Some("task-py-engine-1".into()),
            agent_id_hash: "deadbeef".into(),
            timestamp: ts.into(),
            trace_level: Some("generic".into()),
            data: json!({"py_engine": true}),
        }
    }

    // ── Non-sealing paths ──────────────────────────────────────────────────

    #[test]
    fn prepare_opened_on_first_event() {
        let cap = make_capture(Some("2026-01-01T00:00:00Z"));
        let out = cap.prepare(ev("THOUGHT_START", "th1", "2026-06-10T00:00:00Z"));
        assert!(matches!(
            out,
            PyPrepareOutcome::NonSealing(NonSealingKind::Opened)
        ));
    }

    #[test]
    fn prepare_appended_on_subsequent_event() {
        let cap = make_capture(Some("2026-01-01T00:00:00Z"));
        cap.prepare(ev("THOUGHT_START", "th2", "2026-06-10T00:00:00Z"));
        let out = cap.prepare(ev("DMA_RESULTS", "th2", "2026-06-10T00:00:01Z"));
        assert!(matches!(
            out,
            PyPrepareOutcome::NonSealing(NonSealingKind::Appended)
        ));
    }

    #[test]
    fn prepare_rejected_on_unknown_event_type() {
        let cap = make_capture(Some("2026-01-01T00:00:00Z"));
        let out = cap.prepare(ev("THOUGHT_STRT_TYPO", "th3", "2026-06-10T00:00:00Z"));
        assert!(
            matches!(out, PyPrepareOutcome::NonSealing(NonSealingKind::Rejected { raw }) if raw == "THOUGHT_STRT_TYPO")
        );
    }

    // ── Consent gating ────────────────────────────────────────────────────

    #[test]
    fn prepare_consent_blocked_when_no_consent_configured() {
        let cap = make_capture(None); // no consent_timestamp
        cap.prepare(ev("THOUGHT_START", "th4", "2026-06-10T00:00:00Z"));
        let out = cap.prepare(ev("ACTION_RESULT", "th4", "2026-06-10T00:00:02Z"));
        assert!(
            matches!(out, PyPrepareOutcome::ConsentBlocked { reason } if reason == "no_consent")
        );
    }

    // ── Seal path ─────────────────────────────────────────────────────────

    /// When consent is configured and ACTION_RESULT arrives, `prepare` returns
    /// `ReadyToSeal` with a stamped trace and a valid provenance.
    #[test]
    fn prepare_ready_to_seal_on_action_result_with_consent() {
        let cap = make_capture(Some("2026-01-01T00:00:00Z"));
        cap.prepare(ev("THOUGHT_START", "th5", "2026-06-10T00:00:00Z"));
        let out = cap.prepare(ev("ACTION_RESULT", "th5", "2026-06-10T00:00:02Z"));
        match out {
            PyPrepareOutcome::ReadyToSeal { trace, provenance } => {
                assert_eq!(trace.trace_id, "th5");
                // deployment_profile stamped from config
                assert!(
                    trace.deployment_profile.is_some(),
                    "deployment_profile must be stamped"
                );
                // trace_level stamped from config
                assert_eq!(trace.trace_level.as_deref(), Some("generic"));
                // provenance carries the consent_timestamp
                assert_eq!(
                    provenance.consent_timestamp, "2026-01-01T00:00:00Z",
                    "provenance consent_timestamp must match config"
                );
                assert_eq!(provenance.trace_level, "generic");
            }
            other => panic!("expected ReadyToSeal, got {other:?}"),
        }
    }

    /// End-to-end bytes build: `prepare` → `canonical_bytes_for` →
    /// Ed25519 sign → `apply_signature_and_batch` → round-trip via
    /// persist's `BatchEnvelope::from_json`. Exercises the full Rust
    /// side of the cohabitation path without needing a Python engine.
    #[test]
    fn py_engine_path_bytes_round_trip_through_persist() {
        use ciris_persist::schema::{BatchEnvelope, BatchEvent};
        use ciris_persist::verify::canonical::JcsCanonicalizer;
        use ciris_persist::verify::verify_trace;
        use ed25519_dalek::{Signer, SigningKey};

        let sk = SigningKey::from_bytes(&[99u8; 32]);
        let vk = sk.verifying_key();

        let cap = make_capture(Some("2026-01-01T00:00:00Z"));
        cap.prepare(ev("THOUGHT_START", "th-rt-1", "2026-06-10T00:00:00Z"));
        let out = cap.prepare(ev("ACTION_RESULT", "th-rt-1", "2026-06-10T00:00:02Z"));

        let (mut trace, provenance) = match out {
            // trace is Box<CompleteTrace>
            PyPrepareOutcome::ReadyToSeal { trace, provenance } => (trace, provenance),
            other => panic!("expected ReadyToSeal, got {other:?}"),
        };

        // Step 3: canonical bytes (Rust — same function CaptureClient uses).
        // Box<CompleteTrace> deref-coerces to &CompleteTrace for the call.
        let canonical = PyEngineCapture::canonical_bytes_for(&trace).expect("canonical_bytes");

        // Step 4: sign (simulates what engine.local_sign() returns — 64-byte Ed25519 sig).
        let sig = sk.sign(&canonical).to_bytes();
        assert_eq!(sig.len(), 64, "Ed25519 sig must be 64 bytes");

        // Step 5: apply_signature_and_batch (Rust).
        let batch_bytes = PyEngineCapture::apply_signature_and_batch(
            &mut trace,
            &sig,
            "py-engine-test-key",
            &provenance,
        )
        .expect("apply_signature_and_batch");

        // Round-trip through persist's real typed deserializer.
        let env = BatchEnvelope::from_json(&batch_bytes)
            .expect("persist must parse the py-engine-path batch");
        assert_eq!(env.events.len(), 1);

        let BatchEvent::CompleteTrace { trace: ptrace, .. } = &env.events[0];
        // TRACE_SCHEMA_VERSION = "3.0.0" → JCS canonicalization.
        verify_trace(ptrace, &JcsCanonicalizer, &vk)
            .expect("verify_trace must accept the py-engine-path sealed trace");
    }

    /// Orphan sweep returns 0 when no in-flight traces remain (sealed trace
    /// is removed from the store on seal).
    #[test]
    fn orphan_sweep_returns_zero_after_seal() {
        let cap = make_capture(Some("2026-01-01T00:00:00Z"));
        cap.prepare(ev("THOUGHT_START", "th-sw-1", "2026-06-10T00:00:00Z"));
        // Seal it.
        cap.prepare(ev("ACTION_RESULT", "th-sw-1", "2026-06-10T00:00:02Z"));
        // No in-flight orphans remain.
        let purged = cap.orphan_sweep(Utc::now(), 3600);
        assert_eq!(purged, 0, "sealed trace must not appear as an orphan");
    }

    /// An in-flight (never-sealed) trace older than max_age_secs IS purged.
    #[test]
    fn orphan_sweep_purges_old_inflight_trace() {
        use chrono::Duration;
        let cap = make_capture(Some("2026-01-01T00:00:00Z"));
        cap.prepare(ev("THOUGHT_START", "th-sw-2", "2026-06-10T00:00:00Z"));
        // Advance time past max_age_secs.
        let future = Utc::now() + Duration::seconds(7200);
        let purged = cap.orphan_sweep(future, 3600);
        assert_eq!(
            purged, 1,
            "old in-flight trace must be purged by orphan_sweep"
        );
    }
}
