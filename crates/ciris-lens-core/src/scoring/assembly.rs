//! Manifold-conformity assembly — collapses raw scoring inputs into
//! a [`ManifoldConformity`] enum, enforcing the LC-AV-18 P0
//! fail-secure invariant at the type-system boundary.
//!
//! # LC-AV-18 P0 invariant
//!
//! *Insufficient sample → `Indeterminate`, never a fabricated
//! `Numeric`.* This module is the only place lens-core constructs
//! [`ManifoldConformity::Numeric`]; everything else routes through
//! [`assemble`] which refuses to emit a number when the sample-size
//! gate or cohort-availability preconditions aren't met.
//!
//! # SLO + persist-failure path
//!
//! LC-AV-11 (`Unavailable`) is **not** handled here — the pipeline
//! orchestrator wraps the whole per-trace lifecycle in a budget
//! timer + panic isolator and produces `Unavailable` at that layer
//! regardless of what assembly returns. Assembly is pure science:
//! "given these inputs, what's the principled output?"
//!
//! # Pipeline position
//!
//! ```text
//! cohort/inferred ──► detector/manifold ──► assembly ──► sign_detection
//!     │                       │                  │
//!     │ ambiguous?            │ cold start?      │ sample below gate?
//!     │ ──────────────────────┴──────────────────┘
//!     │              all three reasons feed Indeterminate variants
//!     └─────► AssemblyInput
//! ```

use crate::scoring::result::{IndeterminateReason, ManifoldConformity};

/// Inputs to [`assemble`]. Four variants cover every outcome of the
/// upstream cohort + detector + calibration stages:
///
/// - [`AssemblyInput::Scored`] — detector produced a Mahalanobis
///   distance against a known cohort centroid.
/// - [`AssemblyInput::CohortColdStart`] — cohort centroid not yet
///   calibrated (RATCHET hasn't shipped this cohort in any bundle
///   so far, or no bundle is loaded at all).
/// - [`AssemblyInput::AmbiguousCohort`] — inferred-cohort classifier
///   couldn't disambiguate among multiple candidates.
/// - [`AssemblyInput::BundleSampleBelowGate`] — calibration bundle
///   loaded, the cohort is represented, but its `sample_count` is
///   below the bundle's `sample_size_gate`. Used by the lifecycle
///   when the lookup hits the gate before any detector body runs
///   (so we don't need a fabricated `mahalanobis` value to thread
///   through `Scored`).
#[derive(Debug, Clone)]
pub enum AssemblyInput {
    /// Scoring completed successfully — detector produced a
    /// Mahalanobis distance and the cohort sample size is known.
    Scored {
        /// Raw Mahalanobis distance from cohort centroid (σ-units).
        mahalanobis: f64,
        /// Number of corpus samples in the inferred cohort (from
        /// the calibration bundle's `sample_count`).
        cohort_sample_count: u32,
    },
    /// Cohort centroid is missing from the calibration bundle —
    /// cold-start window per LC-AV-9. Federation acceptance falls
    /// through to M1+M2 until enough corpus accumulates.
    CohortColdStart,
    /// Inferred-cohort classifier couldn't decide among multiple
    /// candidate centroids (LC-AV-2 edge case).
    AmbiguousCohort,
    /// Calibration-bundle lookup found the cohort but its sample
    /// count is below the bundle's gate. Routes directly to
    /// `Indeterminate { SampleSizeBelowGate }` without needing a
    /// fabricated Mahalanobis value (which `Scored` would require).
    BundleSampleBelowGate { current: u32, gate: u32 },
}

/// Collapse `input` into a [`ManifoldConformity`] under the
/// LC-AV-18 P0 gate. Pure function — no I/O, no panics, no
/// allocation beyond the returned enum.
pub fn assemble(input: AssemblyInput, sample_size_gate: u32) -> ManifoldConformity {
    match input {
        AssemblyInput::CohortColdStart => ManifoldConformity::Indeterminate {
            reason: IndeterminateReason::CohortColdStart,
        },
        AssemblyInput::AmbiguousCohort => ManifoldConformity::Indeterminate {
            reason: IndeterminateReason::InferredCohortAmbiguous,
        },
        AssemblyInput::BundleSampleBelowGate { current, gate } => {
            ManifoldConformity::Indeterminate {
                reason: IndeterminateReason::SampleSizeBelowGate { current, gate },
            }
        }
        AssemblyInput::Scored {
            mahalanobis,
            cohort_sample_count,
        } => {
            if cohort_sample_count < sample_size_gate {
                ManifoldConformity::Indeterminate {
                    reason: IndeterminateReason::SampleSizeBelowGate {
                        current: cohort_sample_count,
                        gate: sample_size_gate,
                    },
                }
            } else {
                ManifoldConformity::Numeric(mahalanobis)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_start_yields_indeterminate_cold_start() {
        let out = assemble(AssemblyInput::CohortColdStart, 30);
        matches!(
            out,
            ManifoldConformity::Indeterminate {
                reason: IndeterminateReason::CohortColdStart
            }
        );
    }

    #[test]
    fn ambiguous_cohort_yields_indeterminate_ambiguous() {
        let out = assemble(AssemblyInput::AmbiguousCohort, 30);
        matches!(
            out,
            ManifoldConformity::Indeterminate {
                reason: IndeterminateReason::InferredCohortAmbiguous
            }
        );
    }

    #[test]
    fn scored_with_sufficient_sample_yields_numeric() {
        let out = assemble(
            AssemblyInput::Scored {
                mahalanobis: 2.71,
                cohort_sample_count: 100,
            },
            30,
        );
        match out {
            ManifoldConformity::Numeric(score) => assert_eq!(score, 2.71),
            other => panic!("expected Numeric, got {other:?}"),
        }
    }

    #[test]
    fn scored_with_sample_below_gate_yields_indeterminate_with_numbers() {
        let out = assemble(
            AssemblyInput::Scored {
                mahalanobis: 2.71,
                cohort_sample_count: 12,
            },
            30,
        );
        match out {
            ManifoldConformity::Indeterminate {
                reason: IndeterminateReason::SampleSizeBelowGate { current, gate },
            } => {
                assert_eq!(current, 12);
                assert_eq!(gate, 30);
            }
            other => panic!("expected Indeterminate::SampleSizeBelowGate, got {other:?}"),
        }
    }

    #[test]
    fn sample_equal_to_gate_passes_lc_av_18() {
        // LC-AV-18 reads "*below* the gate," not "at or below". A
        // cohort with exactly `gate` samples is the minimum
        // trustworthy case — passes.
        let out = assemble(
            AssemblyInput::Scored {
                mahalanobis: 1.0,
                cohort_sample_count: 30,
            },
            30,
        );
        match out {
            ManifoldConformity::Numeric(_) => (),
            other => panic!("expected Numeric at gate boundary, got {other:?}"),
        }
    }

    #[test]
    fn sample_one_below_gate_fails_lc_av_18() {
        let out = assemble(
            AssemblyInput::Scored {
                mahalanobis: 1.0,
                cohort_sample_count: 29,
            },
            30,
        );
        match out {
            ManifoldConformity::Indeterminate {
                reason: IndeterminateReason::SampleSizeBelowGate { current, gate },
            } => {
                assert_eq!(current, 29);
                assert_eq!(gate, 30);
            }
            other => panic!("expected Indeterminate at sample = gate-1, got {other:?}"),
        }
    }

    #[test]
    fn negative_mahalanobis_passes_through_assembly() {
        // Assembly doesn't validate the score's sign — that's the
        // detector's responsibility. If detector hands a negative
        // (theoretically impossible for σ-distance but defensively
        // possible from numeric instability), assembly passes it
        // through as Numeric. Caller can clamp / sanity-check.
        let out = assemble(
            AssemblyInput::Scored {
                mahalanobis: -0.5,
                cohort_sample_count: 100,
            },
            30,
        );
        match out {
            ManifoldConformity::Numeric(s) => assert_eq!(s, -0.5),
            other => panic!("expected Numeric, got {other:?}"),
        }
    }

    #[test]
    fn nan_mahalanobis_passes_through_assembly() {
        // Same posture as negative: detector's responsibility, not
        // assembly's. If the projection produced NaN (e.g. wrong-
        // type field in payload) and detector didn't catch it,
        // assembly emits Numeric(NaN). Downstream Mahalanobis-vs-
        // threshold comparison will fail to flag (NaN < any
        // threshold = false), which is the fail-secure outcome.
        let out = assemble(
            AssemblyInput::Scored {
                mahalanobis: f64::NAN,
                cohort_sample_count: 100,
            },
            30,
        );
        match out {
            ManifoldConformity::Numeric(s) => assert!(s.is_nan()),
            other => panic!("expected Numeric, got {other:?}"),
        }
    }

    #[test]
    fn bundle_sample_below_gate_yields_indeterminate_with_numbers() {
        // Lifecycle path when bundle hydration found the cohort but
        // its sample_count was below the gate. Routes to the same
        // IndeterminateReason::SampleSizeBelowGate as Scored-below-gate
        // does, just without needing a fabricated mahalanobis value.
        let out = assemble(
            AssemblyInput::BundleSampleBelowGate {
                current: 119,
                gate: 500,
            },
            500,
        );
        match out {
            ManifoldConformity::Indeterminate {
                reason: IndeterminateReason::SampleSizeBelowGate { current, gate },
            } => {
                assert_eq!(current, 119);
                assert_eq!(gate, 500);
            }
            other => panic!("expected SampleSizeBelowGate, got {other:?}"),
        }
    }

    #[test]
    fn zero_gate_passes_any_sample_size() {
        // Operator override: gate=0 means "no minimum"; any cohort
        // with at least one sample scores numerically. Documented
        // semantics; useful for development / sovereign-mode.
        let out = assemble(
            AssemblyInput::Scored {
                mahalanobis: 1.5,
                cohort_sample_count: 0,
            },
            0,
        );
        match out {
            ManifoldConformity::Numeric(_) => (),
            other => panic!("expected Numeric at gate=0, got {other:?}"),
        }
    }
}
