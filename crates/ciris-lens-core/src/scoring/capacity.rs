//! Capacity — the federation-confidence band [0, 1] for one subject's window,
//! or **Indeterminate** when the window cannot carry a number (LC-AV-18).
//!
//! ```text
//!   rows < sample_gate_rows            → Indeterminate (too few rows)
//!   feature_dim < min_feature_dim      → Indeterminate (rank ceiling too low)
//!   n_eff <= n_eff_floor               → 0.0
//!   otherwise  clamp01( (n_eff - n_eff_floor) / (target_n_eff - n_eff_floor) )
//! ```
//!
//! # Units (CIRISServer#757)
//!
//! The sample gate is a ROW count and is compared against rows. `n_eff` is an
//! effective rank, bounded by `feature_dim` (≤ 11 for the lens feature set),
//! and is banded above a rank floor. The previous `capacity(n_eff, gate,
//! target)` compared `n_eff` against the 20-ROW gate, so it returned 0.0 for
//! every window that could exist: all 6,465 production scores from 2026-08-01
//! to 2026-10-09 were 0.0. Two quantities in two units each get their own
//! comparison here, in one function, so the units cannot be crossed again.
//!
//! # Indeterminate is not a number
//!
//! LC-AV-18 (`MISSION.md`, `THREAT_MODEL.md`): "insufficient sample →
//! Indeterminate, never numeric". A signed 0.0 below the gate claimed "we
//! measured this agent and it has no capacity" when the truth was "we cannot
//! tell yet". Callers emit nothing for [`CapacityAssessment::Indeterminate`].
//!
//! The defaults are RATCHET's (`experiments/capacity_rows/proposed_values.json`);
//! the server's `config:scorer.*` knobs carry them.

/// The thresholds a window is assessed against.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CapacityGates {
    /// Fewest surviving feature ROWS a window needs (measure_n_eff.py refuses
    /// fewer than 20).
    pub sample_gate_rows: u32,
    /// Fewest features the window must cover; `n_eff` cannot exceed it.
    pub min_feature_dim: u32,
    /// The rank floor the band starts from (rank 1 = one direction of variance).
    pub n_eff_floor: f64,
    /// The `n_eff` at which capacity saturates at 1.0. Must exceed the floor.
    pub target_n_eff: f64,
}

/// Why a window carries no number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityIndeterminate {
    /// Fewer surviving rows than the sample gate.
    BelowSampleGate { rows: usize, gate: u32 },
    /// The window covers too few features to reach a meaningful rank.
    BelowFeatureCoverage { feature_dim: usize, min: u32 },
    /// `target_n_eff <= n_eff_floor`, or a non-finite `n_eff`: no band exists.
    NoBand,
}

/// A window's capacity: a number in [0, 1], or nothing to say yet.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CapacityAssessment {
    Score(f64),
    Indeterminate(CapacityIndeterminate),
}

/// Assess one window. `rows` = surviving feature rows, `feature_dim` = features
/// the window covers, `n_eff` = its participation-ratio effective rank.
#[must_use]
pub fn assess_capacity(
    rows: usize,
    feature_dim: usize,
    n_eff: f64,
    g: &CapacityGates,
) -> CapacityAssessment {
    use CapacityAssessment::{Indeterminate, Score};
    if rows < g.sample_gate_rows as usize {
        return Indeterminate(CapacityIndeterminate::BelowSampleGate {
            rows,
            gate: g.sample_gate_rows,
        });
    }
    if feature_dim < g.min_feature_dim as usize {
        return Indeterminate(CapacityIndeterminate::BelowFeatureCoverage {
            feature_dim,
            min: g.min_feature_dim,
        });
    }
    let span = g.target_n_eff - g.n_eff_floor;
    if !n_eff.is_finite() || !span.is_finite() || span <= 0.0 {
        return Indeterminate(CapacityIndeterminate::NoBand);
    }
    if n_eff <= g.n_eff_floor {
        return Score(0.0);
    }
    Score(((n_eff - g.n_eff_floor) / span).clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RATCHET's proposed values (CIRISServer#757).
    const G: CapacityGates = CapacityGates {
        sample_gate_rows: 20,
        min_feature_dim: 4,
        n_eff_floor: 1.0,
        target_n_eff: 4.5,
    };

    fn score(a: CapacityAssessment) -> f64 {
        match a {
            CapacityAssessment::Score(s) => s,
            other => panic!("expected a score, got {other:?}"),
        }
    }

    #[test]
    fn the_production_maximum_is_no_longer_zero() {
        // The highest n_eff_pr ever issued on the canonical (5.31, at most 11
        // features, 156 rows) scored 0.0 under gate=20-against-n_eff. It
        // saturates now.
        assert_eq!(score(assess_capacity(156, 11, 5.31, &G)), 1.0);
        // And the plateau median (2.96) lands mid-band.
        let mid = score(assess_capacity(30, 8, 2.96, &G));
        assert!((mid - (1.96 / 3.5)).abs() < 1e-9, "{mid}");
    }

    #[test]
    fn too_few_rows_is_indeterminate_not_zero() {
        // 1,393 production scores came from 2 rows. That is no measurement.
        assert_eq!(
            assess_capacity(2, 11, 1.0, &G),
            CapacityAssessment::Indeterminate(CapacityIndeterminate::BelowSampleGate {
                rows: 2,
                gate: 20
            })
        );
        assert!(matches!(
            assess_capacity(19, 11, 4.0, &G),
            CapacityAssessment::Indeterminate(_)
        ));
        assert!(matches!(
            assess_capacity(20, 11, 4.0, &G),
            CapacityAssessment::Score(_)
        ));
    }

    #[test]
    fn a_window_covering_too_few_features_is_indeterminate() {
        assert_eq!(
            assess_capacity(100, 3, 2.9, &G),
            CapacityAssessment::Indeterminate(CapacityIndeterminate::BelowFeatureCoverage {
                feature_dim: 3,
                min: 4
            })
        );
    }

    #[test]
    fn rank_one_scores_zero_and_the_band_is_linear_to_the_target() {
        assert_eq!(score(assess_capacity(50, 6, 1.0, &G)), 0.0);
        assert_eq!(score(assess_capacity(50, 6, 0.5, &G)), 0.0);
        assert!((score(assess_capacity(50, 6, 2.75, &G)) - 0.5).abs() < 1e-9);
        assert_eq!(score(assess_capacity(50, 6, 4.5, &G)), 1.0);
        assert_eq!(score(assess_capacity(50, 6, 9.0, &G)), 1.0);
    }

    #[test]
    fn no_band_is_indeterminate_never_nan() {
        let flat = CapacityGates {
            target_n_eff: 1.0,
            ..G
        };
        assert_eq!(
            assess_capacity(50, 6, 3.0, &flat),
            CapacityAssessment::Indeterminate(CapacityIndeterminate::NoBand)
        );
        assert_eq!(
            assess_capacity(50, 6, f64::NAN, &G),
            CapacityAssessment::Indeterminate(CapacityIndeterminate::NoBand)
        );
    }

    #[test]
    fn every_score_is_in_the_unit_interval() {
        for milli in 0..=12_000 {
            let n = milli as f64 / 1000.0;
            if let CapacityAssessment::Score(s) = assess_capacity(40, 11, n, &G) {
                assert!((0.0..=1.0).contains(&s), "n_eff {n} → {s}");
            }
        }
    }
}
