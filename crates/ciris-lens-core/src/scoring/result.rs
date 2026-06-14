//! Score result types. Type-system enforces the LC-AV-18 + LC-AV-11
//! P0 invariants: insufficient sample → `Indeterminate`, never a
//! fabricated `Numeric`; SLO breach → `Unavailable`, never a
//! pass-through pretending to be a score.

use std::time::Duration;

/// Result of `LensCore::process(trace)`. Carries the score variant +
/// the cohort + the version + any detection events produced.
#[derive(Debug, Clone)]
pub struct Score {
    pub conformity: ManifoldConformity,
    pub cohort_id: String,
    pub lens_core_version: &'static str,
    /// Empty when no detector flagged. Detection events are signed
    /// + persisted internally; this field is for caller observability.
    pub detection_events: Vec<DetectionEvent>,
}

/// Manifold-conformity score variants. **Never collapse to f64.**
/// The enum IS the contract: `Indeterminate` and `Unavailable` are
/// not magic numeric values, they're typed signals to the caller
/// that scoring fell through to fail-secure mode.
#[derive(Debug, Clone)]
pub enum ManifoldConformity {
    /// Sufficient sample size; score in band; standard case.
    /// Cohort-relative; published-signal discretization happens at
    /// federation publication boundary, not here.
    Numeric(f64),

    /// LC-AV-18 fail-secure. Sample size below cohort gate, OR
    /// inferred cohort cannot be computed (insufficient features),
    /// OR cohort is in cold-start (centroid not yet calibrated).
    /// Federation acceptance falls through to M1+M2 fallback.
    Indeterminate { reason: IndeterminateReason },

    /// LC-AV-11 fail-secure. SLO budget exceeded OR persist read
    /// failure. **Operationally visible** — not a silent
    /// pass-through.
    Unavailable { reason: UnavailableReason },
}

#[derive(Debug, Clone)]
pub enum IndeterminateReason {
    /// Cohort centroid not yet calibrated (cold-start window per
    /// LC-AV-9). Federation tolerates the agent under M1+M2 only
    /// until enough corpus accumulates.
    CohortColdStart,
    /// Sample size below per-cohort minimum-sample-size gate
    /// (LC-AV-18). Calendar-time-windowed gate per LC-AV-17.
    SampleSizeBelowGate { current: u32, gate: u32 },
    /// Inferred-cohort classifier cannot disambiguate (LC-AV-2 edge case).
    InferredCohortAmbiguous,
    /// CEG §11.2.1 per-axis-family calibration gate.
    ///
    /// **RATCHET's `crc-v1` shipped 2026-05-13** and covers CEG §5.5.1
    /// (manifold conformity + 16-field projection — see
    /// [reference_ratchet_calibration.md][m] in auto-memory). What it
    /// does NOT cover is the per-axis operational definitions +
    /// statistical floors + threshold functions for CEG §5.5.3 F-3
    /// (`detection:correlated_action:{axis}`) and CEG §5.5.5
    /// distributive-access (`detection:distributive:access:{resource_type}`).
    /// Those axis families need a follow-up RATCHET release that
    /// extends the calibration package to cover them; until then the
    /// detector returns this variant for all inputs.
    ///
    /// [m]: ../../../memory/reference_ratchet_calibration.md
    ///
    /// **Why this is `Indeterminate` not `Unavailable`:** the substrate
    /// is healthy, the corpus is present, the score function isn't
    /// broken — the operational meaning of the score on these specific
    /// axis families is what's missing. That's exactly the LC-AV-18 /
    /// anti-pattern #2 shape (don't fabricate numerics when
    /// sample-size / spec doesn't justify them) plus a CEG §11.2
    /// governance lock — the calibration workshop hasn't shipped the
    /// per-axis operating point yet. MISSION.md §3 anti-pattern #9
    /// names this discipline.
    AxisAwaitingCalibration {
        /// Which CEG §5.5.x axis family is awaiting calibration.
        /// Stamped into the emitted envelope's `evidence_refs` so
        /// consumers can distinguish "F-3 axes uncalibrated" from
        /// "distributive-access uncalibrated" — distinct gaps in the
        /// RATCHET roadmap, distinct follow-on calibration workshops.
        family: AxisFamily,
    },
}

/// Names which CEG §5.5.x axis family is awaiting per-axis calibration
/// extension by RATCHET. Closed enum — every variant maps to a CEG
/// §5.5.x sub-section whose axis vocabulary isn't covered by the
/// currently-shipped calibration package (`crc-v1` as of writing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxisFamily {
    /// CEG §5.5.3 — `detection:correlated_action:{axis}`. Open-vocab
    /// axis vocabulary; calibration package owns the per-axis
    /// operational definition, statistical floor, threshold function.
    /// Historical name (pre-CEG): `detection:emergent_deception:{axis}`
    /// per FSD-002 v1.1; the rename will land as a CEG §6
    /// `delegates_to` chain (`correlated_action_v{N+1}:from:
    /// emergent_deception_v{N}`) at the same release that ships the
    /// first calibrated operating point.
    F3CorrelatedAction,
    /// CEG §5.5.5 — `detection:distributive:access:{resource_type}`.
    /// Closed resource-type vocabulary (see `DistributiveAccessResource`
    /// in `src/detector/distributive_access.rs`); calibration package
    /// owns the per-resource Gini / HHI / cohort-size-floor spec.
    DistributiveAccess,
}

#[derive(Debug, Clone)]
pub enum UnavailableReason {
    /// LC-AV-11 SLO breach. Bounded queue dropped this trace's score.
    SloBreach {
        budget: Duration,
        observed: Duration,
    },
    /// Persist read failed; cohort centroid lookup unavailable.
    PersistReadFailure,
    /// Detector implementation panicked. Marked with
    /// lens_core_version per LC-AV-19.
    DetectorPanic { detector: &'static str },
    /// Local-sign failure on the detection event side; the score
    /// itself was computed, but the signed-record path didn't land.
    /// Caller decides whether to surface or retry.
    LocalSignFailure,
    /// The calibration bundle's covariance data is degenerate — a
    /// retained feature has `variance ≤ 0`, or the standardization
    /// produced NaN/Inf (e.g. `std = 0` in a retained field). This is
    /// a RATCHET-bundle data quality problem, not an SLO failure.
    ///
    /// Distinct from `CohortColdStart` (centroid simply not present)
    /// and `SampleSizeBelowGate` (centroid present but underpopulated).
    /// Here the centroid *exists* and the sample gate *passed*, but the
    /// math to produce a valid Mahalanobis distance failed because the
    /// precision matrix is not positive-definite.
    ///
    /// Per LC-AV-18 P0: we refuse to emit a fabricated numeric score.
    /// Callers should surface this as `ManifoldConformity::Unavailable`
    /// and alert RATCHET that the bundle needs re-calibration.
    DegenerateCovariance,
}

/// A single detection event from one of the layered detectors
/// (cohort mismatch, manifold conformity, 5 ratchet detectors).
/// Signed via persist.local_sign before this struct surfaces;
/// caller observes for alerting + audit.
#[derive(Debug, Clone)]
pub struct DetectionEvent {
    pub detector: &'static str,
    pub severity: Severity,
    /// Hex sha256 of the signed canonical bytes; join key to
    /// persist's detection-event row.
    pub event_hash: String,
}

#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}
