//! Detector module — manifold-conformity + 5 ratchet detectors.
//!
//! # v0.1.0 status
//!
//! Ships a **no-op detector** that returns [`DetectionResult::None`]
//! for every trace. Combined with the bundle-aware lifecycle this
//! routes every v0.1.0 trace through either
//! [`crate::scoring::AssemblyInput::CohortColdStart`] →
//! [`ManifoldConformity::Indeterminate { CohortColdStart }`][ind]
//! (no bundle / cohort missing from bundle) or
//! [`crate::scoring::AssemblyInput::BundleSampleBelowGate`] →
//! [`ManifoldConformity::Indeterminate { SampleSizeBelowGate }`][ind]
//! (bundle present, cohort represented, sample-count below gate).
//!
//! That's the architecturally-correct fail-secure behavior per
//! LC-AV-9 (cold-start window) and LC-AV-18 (sample-size gate). The
//! detector body itself returns Indeterminate **until the Phase 2
//! detector implementations land** — RATCHET's `crc-v1` calibration
//! bundle has shipped (CIRISLensCore#3 partial closure 2026-05-13),
//! but the Mahalanobis scorer that consumes the centroids still
//! ports from `CIRISLens/api/analysis/coherence_ratchet.py`.
//! Federation acceptance routes through M1+M2 fallback during this
//! window.
//!
//! # Real detectors (Phase 2)
//!
//! Phase 2 ports the four §F detectors from
//! `CIRISLens/api/analysis/coherence_ratchet.py`
//! (`_detect_cross_agent_divergence_via_persist` + 3 siblings) plus
//! the manifold-conformity scorer that consumes
//! [`crate::extract::project`]'s 16-feature output against the
//! `crc-v1` centroids hydrated via
//! [`crate::scoring::CalibrationBundle`]. All four detectors compose
//! against persist v0.7.x §F primitives directly via the rlib path;
//! no PyO3 hop.
//!
//! [ind]: crate::scoring::ManifoldConformity::Indeterminate

use ciris_persist::pipeline::extract::Features;

pub mod axis_metrics;
pub mod coherence_ratchet;
pub mod correlated_action;
pub mod distributive_access;
pub mod manifold;

pub use axis_metrics::{axis_score, score_against_axis, AxisScore};
pub use coherence_ratchet::CoherenceRatchetDetector;
pub use correlated_action::{CorrelatedActionAxis, CorrelatedActionInput};
pub use distributive_access::{DistributiveAccessInput, DistributiveAccessResource};
pub use manifold::{detect_manifold, score_mahalanobis, ManifoldScoreOutcome};

/// Per-trace detection outcome from the detector stage. Maps to an
/// [`AssemblyInput`][ai] variant in the orchestrator.
///
/// [ai]: crate::scoring::AssemblyInput
#[derive(Debug, Clone)]
pub enum DetectionResult {
    /// No detector flagged — the v0.1.0 default. Orchestrator
    /// routes through the bundle-aware fallback: cohort missing from
    /// the calibration bundle → [`AssemblyInput::CohortColdStart`][ccs]
    /// (LC-AV-9 cold-start window); cohort present but below
    /// `sample_size_gate` →
    /// [`AssemblyInput::BundleSampleBelowGate`][bs]. This branch
    /// dominates until the Phase 2 detector body lands.
    ///
    /// [ccs]: crate::scoring::AssemblyInput::CohortColdStart
    /// [bs]: crate::scoring::AssemblyInput::BundleSampleBelowGate
    None,

    /// Manifold-conformity scorer produced a Mahalanobis-σ distance
    /// against the inferred cohort's centroid. Carried with the
    /// cohort's `sample_count` so [`crate::scoring::assemble`] can
    /// apply the LC-AV-18 sample-size gate.
    Manifold {
        /// Mahalanobis distance in σ-units.
        mahalanobis: f64,
        /// Sample count for the inferred cohort (from the calibration
        /// bundle's `CohortCentroid.sample_count`).
        cohort_sample_count: u32,
    },

    /// LC-AV-2 declared-vs-inferred cohort disagreement. The agent
    /// declared one cohort identity; the inferred classifier landed
    /// the trace in a different cohort. Federation evidence; signed
    /// with severity `warning` by the orchestrator.
    DeclaredInferredMismatch {
        /// Agent-declared 6-tuple (from `Features.declared`).
        declared: serde_json::Value,
        /// Inferred 6-tuple (from cohort classifier).
        inferred: serde_json::Value,
    },
}

/// v0.1.0 no-op detector. Returns [`DetectionResult::None`] for
/// every trace until the Phase 2 detector body lands.
///
/// This is not laziness — it's the architecturally correct
/// fail-secure behavior. RATCHET's `crc-v1` calibration bundle has
/// shipped, but the Mahalanobis scorer that consumes those centroids
/// is still being ported from
/// `CIRISLens/api/analysis/coherence_ratchet.py`. A detector that
/// fired without the implemented scoring body would emit fabricated
/// scores; we explicitly refuse and route every trace through the
/// bundle-aware fallback in
/// [`crate::pipeline::lifecycle`] → either
/// [`crate::scoring::ManifoldConformity::Indeterminate`] with reason
/// `CohortColdStart` or `SampleSizeBelowGate` depending on whether
/// the trace's cohort appears in the hydrated bundle.
pub fn detect(_features: &Features) -> DetectionResult {
    DetectionResult::None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_persist::pipeline::extract::Features;
    use std::collections::HashMap;

    fn empty_features() -> Features {
        Features {
            declared: Default::default(),
            step_timestamps: Default::default(),
            observation_weights: Default::default(),
            models_used: vec![],
            component_blobs: HashMap::new(),
            cost_estimate: 0.0,
            total_tokens: 0,
            model_class: Default::default(),
        }
    }

    #[test]
    fn v010_detector_always_returns_none() {
        // v0.1.0 fail-secure: every trace returns None until the
        // Phase 2 detector body lands. RATCHET has delivered the
        // crc-v1 calibration bundle; the remaining gap is the
        // Mahalanobis-scoring port from CIRISLens's coherence_ratchet.
        match detect(&empty_features()) {
            DetectionResult::None => (),
            other => panic!("v0.1.0 must return None, got {other:?}"),
        }
    }
}
