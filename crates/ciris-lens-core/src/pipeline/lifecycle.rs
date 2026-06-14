//! Per-trace lifecycle orchestration. The rlib-path entry point that
//! drives the eight-stage science-layer pipeline on a single
//! [`VerifiedTrace`]:
//!
//! ```text
//! VerifiedTrace ──► LensCore::process
//!                       ├── parse declared 6-tuple from envelope
//!                       ├── extract features (persist's free fn)
//!                       ├── build cohort_cell JSON
//!                       ├── detector (v0.1.0 no-op → cold start)
//!                       ├── scoring assembly (LC-AV-18 gate)
//!                       ├── sign detection event (hybrid)
//!                       └── return Outcome { score, event }
//! ```
//!
//! # Substrate inheritance
//!
//! `VerifiedTrace` arrives from edge with verify already complete —
//! lens-core never re-verifies (AV-9 structural attestation).
//! Detection events are signed via persist's `LocalSigner`; the
//! caller writes them to persist via `DerivedSchema::put_detection_event`
//! after [`process`] returns.
//!
//! The orchestrator does NOT call `Engine.put_detection_event` itself
//! — that's the caller's responsibility. Two reasons:
//! 1. Keeps `LensCore` free of `Arc<dyn DerivedSchema>` (smaller
//!    handle surface, easier to test).
//! 2. PyO3 path can route writes through the deployed lens's already-
//!    constructed `Engine` rather than constructing a second one
//!    inside lens-core.
//!
//! # Phase 1 status
//!
//! - Detector stage is no-op (returns
//!   [`DetectionResult::None`][crate::detector::DetectionResult::None])
//!   so v0.1.0 traces route through bundle-aware fallback only.
//! - **CIRISLensCore#3 partial closure (2026-05-13).** RATCHET shipped
//!   the `crc-v1` calibration bundle; lens-core consumes it via
//!   [`LensCore::with_calibration_bundle`]. Bundle-aware routing:
//!   cohort not in the centroid table →
//!   [`AssemblyInput::CohortColdStart`][crate::scoring::AssemblyInput::CohortColdStart];
//!   cohort below `sample_size_gate` →
//!   [`AssemblyInput::BundleSampleBelowGate`][crate::scoring::AssemblyInput::BundleSampleBelowGate]
//!   → `Indeterminate { SampleSizeBelowGate }`. Every cohort cell in
//!   `crc-v1` is below the 500-sample gate (119 / 90 / 55), so every
//!   trace still returns `Indeterminate` — but with a different,
//!   sharper reason than the pre-bundle blanket cold-start. Phase 2
//!   replaces the no-op detector with the real implementations, at
//!   which point above-gate cohorts return numeric scores.
//! - SLO budget enforcement (LC-AV-11
//!   [`ManifoldConformity::Unavailable`]) is **not** wired in this
//!   commit; lifecycle is currently best-effort. Production
//!   deployments wrap [`process`] in a `tokio::time::timeout` until
//!   the orchestrator-level budget machinery lands.

use std::sync::Arc;

use ciris_edge::VerifiedTrace;
use ciris_persist::pipeline::extract::extract_features;
use ciris_persist::prelude::{DetectionEvent, LocalSigner};
use ciris_persist::Journal;
use serde_json::Value;

use crate::cohort;
use crate::detector::{detect, detect_manifold, DetectionResult};
use crate::extract::project;
use crate::scoring::calibration::CalibrationBundle;
use crate::scoring::result::{
    IndeterminateReason, ManifoldConformity, Score, Severity, UnavailableReason,
};
use crate::scoring::{assemble, AssemblyInput};
use crate::signing::{sign_detection, DetectionInputs, SigningError};

/// Lens-core's `&'static str` version stamp for LC-AV-19
/// reproducibility — populated from `CARGO_PKG_VERSION` at compile
/// time.
pub const LENS_CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Hot-path handle. Holds substrate handles wired once at startup;
/// per trace, [`process`] walks the science-layer pipeline.
///
/// [`Journal`] is held but not yet consumed by lifecycle — reserved
/// for the SLO budget + observability spans landing in Phase 2.
pub struct LensCore {
    signer: Arc<LocalSigner>,
    #[allow(dead_code)]
    journal: Arc<Journal>,
    /// Optional RATCHET-shipped calibration bundle. `None` ≡
    /// pre-CIRISLensCore#3 cold-start: every trace routes through
    /// [`AssemblyInput::CohortColdStart`]. `Some` ≡ post-#3: the
    /// bundle drives cohort lookup, and lifecycle returns
    /// `Indeterminate { SampleSizeBelowGate }` for cohorts below the
    /// bundle's `sample_size_gate` (every cohort in `crc-v1`).
    bundle: Option<Arc<CalibrationBundle>>,
}

impl LensCore {
    /// Construct a `LensCore` from substrate handles. Both must be
    /// shared (`Arc`) because the orchestrator may be invoked from
    /// multiple worker threads in the deployed lens.
    ///
    /// Constructed without a calibration bundle; every trace lands
    /// in `Indeterminate { CohortColdStart }`. Use
    /// [`LensCore::with_calibration_bundle`] to hydrate a
    /// RATCHET-shipped bundle.
    pub fn new(signer: Arc<LocalSigner>, journal: Arc<Journal>) -> Self {
        Self {
            signer,
            journal,
            bundle: None,
        }
    }

    /// Attach a RATCHET-shipped calibration bundle. Consumes the
    /// `LensCore` and returns the bundle-hydrated form — builder-style
    /// to keep the no-bundle constructor backwards-compatible for
    /// existing callers (`LensCoreHandler::new(engine)`, relay-mode
    /// tests).
    pub fn with_calibration_bundle(mut self, bundle: Arc<CalibrationBundle>) -> Self {
        self.bundle = Some(bundle);
        self
    }

    /// Borrow the hydrated calibration bundle, if any. Used by
    /// downstream observability + tests; the hot-path `process`
    /// dispatches on `self.bundle` directly.
    pub fn calibration_bundle(&self) -> Option<&Arc<CalibrationBundle>> {
        self.bundle.as_ref()
    }

    /// Process one [`VerifiedTrace`] through the science-layer
    /// pipeline. Returns the [`Outcome`] for the caller to act on
    /// (write event to persist via `DerivedSchema::put_detection_event`,
    /// surface score via API, etc.).
    ///
    /// `sample_size_gate` and `ratchet_calibration_version` are
    /// caller-supplied defaults used when no calibration bundle has
    /// been hydrated on this `LensCore`. When
    /// [`with_calibration_bundle`][Self::with_calibration_bundle]
    /// was called, the bundle's own values override the arguments —
    /// LC-AV-19 reproducibility ties detection events to the bundle
    /// that scored them, not the call-site default.
    ///
    /// # Bundle-aware routing (post-CIRISLensCore#3)
    ///
    /// - **No bundle hydrated:** every trace lands in
    ///   `Indeterminate { CohortColdStart }` (pre-#3 behavior).
    /// - **Bundle hydrated, cohort not in centroid table:**
    ///   `Indeterminate { CohortColdStart }` (still cold-start, just
    ///   for this specific cohort).
    /// - **Bundle hydrated, cohort below `sample_size_gate`:**
    ///   `Indeterminate { SampleSizeBelowGate { current, gate } }` —
    ///   different reason, same fail-secure shape.
    /// - **Bundle hydrated, cohort at-or-above gate:** detector body
    ///   runs (Phase 2 will land that); for now still cold-start
    ///   because the v0.1.0 detector is a no-op.
    pub async fn process(
        &self,
        trace: VerifiedTrace,
        sample_size_gate: u32,
        ratchet_calibration_version: i32,
    ) -> Result<Outcome, ProcessError> {
        // 1. Parse the envelope body once.
        let body: Value = serde_json::from_str(trace.envelope.body.get())
            .map_err(|e| ProcessError::ParseBody(e.to_string()))?;

        let trace_id = body
            .get("trace_id")
            .and_then(Value::as_str)
            .ok_or(ProcessError::MissingTraceId)?
            .to_string();

        // 2. Pull declared 6-tuple from the deployment_profile block.
        let declared = cohort::parse_from_envelope(&body);

        // 3. Extract typed Features via persist's free function.
        let features = extract_features(&body, declared.clone());

        // 3b. Project the typed Features to the 16-element numeric vector
        // for Mahalanobis scoring. Done once here and threaded through the
        // manifold detector; the 5 Coherence-Ratchet detectors are Phase 2
        // and still no-op, so they don't consume this vector yet.
        let raw_projection = project(&features);

        // 4. Build the cohort_cell JSON for the signed event.
        let cohort_cell = cohort::cohort_cell(&declared);

        // 5. Detector → DetectionResult. The 5 Coherence-Ratchet
        // detectors are still no-op (Phase 2 TBD); only the manifold
        // conformity path is live as of CIRISLensCore#3 Phase 2.
        let detection = detect(&features);

        // 6. Resolve the calibration-derived inputs. When a bundle is
        // hydrated, its `sample_size_gate` and
        // `ratchet_calibration_version` override the caller-supplied
        // defaults — the bundle is authoritative once present.
        let (effective_gate, effective_version) = match self.bundle.as_deref() {
            Some(b) => (b.sample_size_gate, b.ratchet_calibration_version),
            None => (sample_size_gate, ratchet_calibration_version),
        };

        // 7. Convert detection outcome to assembly input. The bundle
        // lookup informs the cold-start vs. sample-below-gate fork
        // when the detector hasn't produced a Mahalanobis distance.
        // When the cohort centroid is present and above the sample-size
        // gate, the Phase-2 manifold scorer runs and returns either a
        // numeric distance or `Unavailable { DegenerateCovariance }`.
        let assembly_input = match detection {
            DetectionResult::None => {
                match assembly_input_from_bundle(
                    self.bundle.as_deref(),
                    &cohort_cell,
                    &raw_projection,
                ) {
                    Ok(input) => input,
                    Err(unavailable_reason) => {
                        // Manifold scorer failed (degenerate covariance or NaN).
                        // Route directly to Unavailable — skip assembly.
                        let conformity = ManifoldConformity::Unavailable {
                            reason: unavailable_reason,
                        };
                        let inputs = DetectionInputs {
                            trace_id: trace_id.clone(),
                            body_sha256: trace.body_sha256.to_vec(),
                            detector: "manifold_conformity",
                            severity: severity_from(&conformity),
                            cohort_cell,
                            conformity: &conformity,
                            lens_core_version: LENS_CORE_VERSION,
                            ratchet_calibration_version: effective_version,
                            evidence_refs: Vec::new(),
                        };
                        let (event, summary) = sign_detection(&self.signer, inputs).await?;
                        let cohort_id = format_cohort_id(&features.declared);
                        return Ok(Outcome {
                            score: Score {
                                conformity,
                                cohort_id,
                                lens_core_version: LENS_CORE_VERSION,
                                detection_events: vec![summary],
                            },
                            event,
                        });
                    }
                }
            }
            DetectionResult::Manifold {
                mahalanobis,
                cohort_sample_count,
            } => AssemblyInput::Scored {
                mahalanobis,
                cohort_sample_count,
            },
            DetectionResult::DeclaredInferredMismatch { .. } => AssemblyInput::AmbiguousCohort,
        };

        // 8. LC-AV-18 gate — produces ManifoldConformity.
        let conformity = assemble(assembly_input, effective_gate);

        // 9. Sign the detection event. The
        // `ratchet_calibration_version` stamp uses the bundle's
        // version when one is hydrated (LC-AV-19: detection events
        // reproducibility-tie to the bundle that scored them).
        let inputs = DetectionInputs {
            trace_id: trace_id.clone(),
            body_sha256: trace.body_sha256.to_vec(),
            detector: "manifold_conformity",
            severity: severity_from(&conformity),
            cohort_cell,
            conformity: &conformity,
            lens_core_version: LENS_CORE_VERSION,
            ratchet_calibration_version: effective_version,
            evidence_refs: Vec::new(),
        };
        let (event, summary) = sign_detection(&self.signer, inputs).await?;

        let cohort_id = format_cohort_id(&features.declared);

        Ok(Outcome {
            score: Score {
                conformity,
                cohort_id,
                lens_core_version: LENS_CORE_VERSION,
                detection_events: vec![summary],
            },
            event,
        })
    }
}

/// Per-trace pipeline result. `score` is the lens-core observability
/// view; `event` is the signed, persist-ready row the caller writes
/// via `DerivedSchema::put_detection_event`.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub score: Score,
    pub event: DetectionEvent,
}

/// Errors from [`LensCore::process`].
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    /// Envelope body was not valid JSON.
    #[error("parse body: {0}")]
    ParseBody(String),
    /// Envelope body had no `trace_id` field — wire spec §3 requires
    /// it; pre-2.7.0 envelopes may omit. Treat as a malformed input.
    #[error("missing trace_id in envelope body")]
    MissingTraceId,
    /// Signing the detection event failed.
    #[error("sign: {0}")]
    Sign(#[from] SigningError),
}

/// Decide the assembly input when the 5 Coherence-Ratchet detectors
/// produced no detection (still no-op in Phase 2). The manifold
/// conformity path runs here when the bundle + centroid lookup
/// succeeds and the cohort is at-or-above the sample-size gate.
///
/// The fork:
///
/// - No bundle hydrated → `Ok(CohortColdStart)` (pre-#3 cold-start).
/// - Bundle present, cohort not in `cohort_centroids` →
///   `Ok(CohortColdStart)` (this specific cohort hasn't been observed
///   in calibration corpus).
/// - Bundle present, cohort sample below gate →
///   `Ok(BundleSampleBelowGate { current, gate })`. Routes through the
///   same `Indeterminate { SampleSizeBelowGate }` shape as
///   detector-fired `Scored`-below-gate.
/// - Bundle present, cohort at-or-above gate → **Phase 2 manifold
///   scorer runs.** Returns `Ok(Scored { mahalanobis, cohort_sample_count })`
///   on success, or `Err(UnavailableReason)` when the covariance is
///   degenerate (NaN/Inf, non-positive-definite diagonal). The caller
///   must surface `Err` as `ManifoldConformity::Unavailable`.
fn assembly_input_from_bundle(
    bundle: Option<&CalibrationBundle>,
    cohort_cell: &Value,
    raw_projection: &[f64; crate::extract::projection::PROJECTION_DIM],
) -> Result<AssemblyInput, UnavailableReason> {
    let Some(bundle) = bundle else {
        return Ok(AssemblyInput::CohortColdStart);
    };
    let Some(centroid) = bundle.lookup_cohort(cohort_cell) else {
        return Ok(AssemblyInput::CohortColdStart);
    };
    let current = u32::try_from(centroid.sample_count).unwrap_or(u32::MAX);
    if current < bundle.sample_size_gate {
        return Ok(AssemblyInput::BundleSampleBelowGate {
            current,
            gate: bundle.sample_size_gate,
        });
    }
    // Cohort is at-or-above the sample-size gate: run the Phase-2
    // manifold scorer. CIRISLensCore#3 Phase 2 closure.
    detect_manifold(raw_projection, bundle, centroid).map(|detection| match detection {
        DetectionResult::Manifold {
            mahalanobis,
            cohort_sample_count,
        } => AssemblyInput::Scored {
            mahalanobis,
            cohort_sample_count,
        },
        // detect_manifold only returns Manifold or errors; the
        // other variants come from different detector paths.
        other => {
            tracing::warn!(
                "unexpected DetectionResult from detect_manifold: {other:?}; \
                     routing to CohortColdStart"
            );
            AssemblyInput::CohortColdStart
        }
    })
}

/// Map a [`ManifoldConformity`] to the detection-event severity
/// bucket. v0.1.0 policy:
///
/// - Cold-start / sample-below-gate / ambiguous-cohort → `Info`
///   (telemetry; no operator action implied)
/// - Numeric in expected band → `Info`
/// - Unavailable (SLO breach, persist read failure) → `Warning`
///
/// Phase 2 elaborates: Numeric outliers > N σ → `Warning`/`Critical`
/// per RATCHET-calibrated thresholds.
fn severity_from(c: &ManifoldConformity) -> Severity {
    match c {
        ManifoldConformity::Numeric(_) => Severity::Info,
        ManifoldConformity::Indeterminate { .. } => Severity::Info,
        ManifoldConformity::Unavailable { .. } => Severity::Warning,
    }
}

/// Render a compact cohort identifier for the observability `Score`.
/// Format: `role/template/domain/type/region/trust_mode`, with `?`
/// for absent axes. Not federation-stable; for logs only.
fn format_cohort_id(declared: &ciris_persist::pipeline::extract::DeclaredCohortAxes) -> String {
    let q = |o: &Option<String>| o.as_deref().unwrap_or("?").to_string();
    format!(
        "{}/{}/{}/{}/{}/{}",
        q(&declared.agent_role),
        q(&declared.agent_template),
        q(&declared.deployment_domain),
        q(&declared.deployment_type),
        q(&declared.deployment_region),
        q(&declared.deployment_trust_mode),
    )
}

// Suppress unused warning when IndeterminateReason isn't matched —
// the type is part of the public scoring API surface and is consumed
// by signing/event.rs via the ManifoldConformity payload.
#[allow(dead_code)]
fn _silence_indeterminate_reason() -> Option<IndeterminateReason> {
    None
}
