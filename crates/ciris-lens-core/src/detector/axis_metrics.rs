//! crc-v2 axis metric kernels + threshold-with-polarity scoring.
//!
//! Shared between [`crate::detector::distributive_access`] (CEG §5.5.5)
//! and [`crate::detector::correlated_action`] (CEG §5.5.3). Each metric
//! function implements ONE axis's `measurement_procedure` from
//! `crc-v2/bundle.yaml` exactly; the bundle line is cited in each
//! function's doc comment so the math is auditable against the signed
//! calibration.
//!
//! # Corpus shape
//!
//! The detectors receive `corpus: &[serde_json::Value]` — one JSON
//! object **per agent** (keyed by `agent_id_hash`, NOT `channel_id`,
//! per the crc-v2 README §"Statistical floors"). Each object is a
//! per-agent aggregate of the shape RATCHET's
//! `01b_aggregate_agents_v2.py` produces (see `crc-v2/data/agents.jsonl`):
//!
//! ```json
//! { "agent_id_hash": "abccbd48…", "cost_usd_sum": 2.156,
//!   "llm_model_counts": {"Qwen/Qwen3.6-35B-A3B": 390},
//!   "dsdma_flags_count": {"out_of_domain": 1, …}, "n_distinct_domains": 7,
//!   "pdma_total": 30, "pdma_conflict_count": 0, "federation_member": true,
//!   "n_action": 30, "cognitive_state_dominant": "work",
//!   "agent_role": "…" }
//! ```
//!
//! LensCore deployments are responsible for producing this aggregate
//! from signed trace_events before calling the detector; the metric
//! kernels here operate on the aggregate, matching the calibration's
//! Pass-A derivation.
//!
//! # Polarity + scaling
//!
//! Both polarities in crc-v2 emit a **negative** attestation when the
//! cohort metric crosses its concern threshold (the README's two
//! polarity rows differ only in which *direction* "good" is, but both
//! threshold-crossing rules fire at `metric >= threshold`):
//!
//! - `positive_when_distributed`: low = good; **concern when metric ≥
//!   threshold** (high concentration).
//! - `negative_when_detected`: high = concern; **concern when metric ≥
//!   threshold**.
//!
//! Below threshold ⇒ conforming (no concern). At/above threshold ⇒
//! `Numeric(score)` where `score` is `score_at_threshold` at the
//! threshold and grows more negative as the metric exceeds it
//! (`scaling: magnitude_scales_with_severity_above_threshold`).
//!
//! # Zero-variance baseline (fail-secure)
//!
//! `federation_membership` + `rights_asymmetry` carry a `1e-6`
//! sentinel threshold (`zero_variance_baseline`). When the observed
//! metric is `0` (the degenerate calibration case — production shows
//! no variance), emitting a confident `Numeric` would fabricate a
//! signal the calibration cannot support. We instead return
//! `Indeterminate { AxisAwaitingCalibration }` for the zero case (the
//! sentinel never legitimately fires until variance accumulates), and
//! only emit `Numeric` when an actual non-zero deviation is observed.

use crate::scoring::axis_calibration::{AxisEntry, CalibrationOutcome, ConcernDirection};
use crate::scoring::result::{AxisFamily, IndeterminateReason, ManifoldConformity};

/// The result of measuring an axis metric over a corpus. Carries both
/// the metric value (for evidence) and the conformity verdict.
#[derive(Debug, Clone)]
pub struct AxisScore {
    /// The raw cohort metric value (Gini / HHI / CV / …). `None` when
    /// the corpus was too degenerate to compute the metric at all
    /// (e.g. empty cohort) — the caller routes that to `Indeterminate`.
    pub metric_value: Option<f64>,
    /// The conformity verdict.
    pub conformity: ManifoldConformity,
}

// ---------------------------------------------------------------------------
// Metric kernels — each cites its bundle.yaml measurement_procedure.
// ---------------------------------------------------------------------------

/// Gini coefficient over a non-negative population.
///
/// Mean-absolute-difference form:
/// `G = Σᵢ Σⱼ |xᵢ − xⱼ| / (2 · n² · x̄)`.
///
/// Returns `0.0` for a perfectly equal population and approaches `1.0`
/// for maximal concentration. Returns `None` if the population is
/// empty or its sum is `0` (Gini undefined when mean is 0).
///
/// `compute_gini` per `bundle.yaml::axes.distributive:access:compute.
/// measurement_procedure`: "Gini coefficient across per-agent totals".
pub fn gini(values: &[f64]) -> Option<f64> {
    let n = values.len();
    if n == 0 {
        return None;
    }
    let sum: f64 = values.iter().sum();
    if sum <= 0.0 {
        return None;
    }
    let mut abs_diff_sum = 0.0_f64;
    for &xi in values {
        for &xj in values {
            abs_diff_sum += (xi - xj).abs();
        }
    }
    let mean = sum / n as f64;
    Some(abs_diff_sum / (2.0 * (n as f64) * (n as f64) * mean))
}

/// Herfindahl-Hirschman Index over a category-count map.
///
/// `HHI = Σ_k sᵢ²` where `sᵢ` is the share of category `k`. Range
/// `[1/K, 1]`; `1` = single-category dominance, `1/K` = uniform across
/// `K` categories. Returns `None` if the total count is `0`.
///
/// `models_hhi` per `bundle.yaml::axes.distributive:access:models.
/// measurement_procedure`: "Pool LLM_CALL.payload.model across all
/// agents in the cohort. Compute HHI = sum of squared model shares."
pub fn hhi(counts: &[u64]) -> Option<f64> {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return None;
    }
    let total_f = total as f64;
    Some(
        counts
            .iter()
            .map(|&c| {
                let s = c as f64 / total_f;
                s * s
            })
            .sum(),
    )
}

/// Coefficient of variation: `CV = σ / μ` (population std over mean).
///
/// Returns `None` if the population is empty or its mean is `0` (CV
/// undefined). Uses the population standard deviation (divide by `n`),
/// matching numpy's `std()` default used in RATCHET's pipeline.
///
/// `info_asym_cv` per `bundle.yaml::axes.correlated_action:
/// informational_asymmetry.measurement_procedure`: "Coefficient of
/// variation of per-agent dsdma flag totals within the cohort."
pub fn coefficient_of_variation(values: &[f64]) -> Option<f64> {
    let n = values.len();
    if n == 0 {
        return None;
    }
    let mean = values.iter().sum::<f64>() / n as f64;
    if mean == 0.0 {
        return None;
    }
    let var = values.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n as f64;
    Some(var.sqrt() / mean)
}

/// Fraction of the population strictly below the population median.
///
/// `part_excl_frac` per `bundle.yaml::axes.correlated_action:
/// participation_exclusion.measurement_procedure`: "Fraction of agents
/// in the cohort whose distinct-domain count is below the cohort
/// median." Returns `None` for an empty population.
pub fn fraction_below_median(values: &[f64]) -> Option<f64> {
    let n = values.len();
    if n == 0 {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    };
    let below = values.iter().filter(|&&v| v < median).count();
    Some(below as f64 / n as f64)
}

/// Capability diversity: distinct `(cognitive_state_dominant,
/// agent_role)` tuples normalized by cohort size.
///
/// `cap_diversity` per `bundle.yaml::axes.distributive:access:
/// agent_capabilities.measurement_procedure`: "Number of distinct
/// (cognitive_state_dominant, agent_role) tuples in the cohort,
/// normalized by cohort size." Returns `None` for an empty cohort.
pub fn capability_diversity(tuples: &[(String, String)]) -> Option<f64> {
    let n = tuples.len();
    if n == 0 {
        return None;
    }
    let mut distinct: Vec<&(String, String)> = tuples.iter().collect();
    distinct.sort();
    distinct.dedup();
    Some(distinct.len() as f64 / n as f64)
}

/// Aggregate footprint: total action count × log10(cohort size).
///
/// `agg_fp` per `bundle.yaml::axes.correlated_action:aggregate_footprint.
/// measurement_procedure`: "Cohort aggregate ACTION_RESULT count ×
/// log10(cohort_n_agents)." Returns `None` for an empty cohort.
/// `log10(1) == 0`, so a single-agent cohort yields footprint `0`.
pub fn aggregate_footprint(total_actions: u64, cohort_n_agents: usize) -> Option<f64> {
    if cohort_n_agents == 0 {
        return None;
    }
    Some(total_actions as f64 * (cohort_n_agents as f64).log10())
}

/// Pooled rate: `numerator / denominator`. Used by `pdma_rate_within`
/// (rights_asymmetry) and `nonmember_frac` (federation_membership).
///
/// `pdma_rate_within` per `bundle.yaml::axes.correlated_action:
/// rights_asymmetry.measurement_procedure`: "pooled PDMA-conflict rate
/// = sum(has_conflicts==True) / sum(DMA_RESULTS with pdma block)".
/// `nonmember_frac` per `bundle.yaml::axes.distributive:access:
/// federation_membership`: "Fraction of non-members in the cohort."
/// Returns `None` when the denominator is `0`.
pub fn pooled_rate(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        return None;
    }
    Some(numerator as f64 / denominator as f64)
}

// ---------------------------------------------------------------------------
// Threshold + polarity → conformity verdict.
// ---------------------------------------------------------------------------

/// Apply an axis's threshold-with-polarity to a measured metric value,
/// producing the conformity verdict.
///
/// # Verdict rules (both polarities fire at `metric >= threshold`)
///
/// - `metric < threshold` ⇒ conforming. We surface conformity as a
///   `Numeric` whose score is `0.0` (in-band; no concern). This
///   matches the manifold detector's convention that a `Numeric`
///   verdict is the "the math ran and produced a score" outcome.
/// - `metric >= threshold` ⇒ concern. `Numeric(score)` where `score`
///   is `score_at_threshold` exactly at the threshold and ramps more
///   negative with severity above it (see [`severity_scaled_score`]).
///
/// # Zero-variance baseline (fail-secure)
///
/// For `zero_variance_baseline` axes (`1e-6` sentinel threshold), a
/// measured value of `0.0` is the degenerate calibration case — the
/// metric showed no variance in the corpus, so a `Numeric` would be
/// false-confident. We return `Indeterminate { AxisAwaitingCalibration }`
/// for the zero case. A genuinely non-zero deviation (≥ the `1e-6`
/// sentinel) does cross and emits the negative `Numeric` — that's the
/// "any nonzero deviation" semantics the bundle's k_eff notes specify.
pub fn score_against_axis(
    metric_value: f64,
    axis: &AxisEntry,
    family: AxisFamily,
) -> ManifoldConformity {
    let tf = &axis.threshold_function;
    let direction = tf.concern_direction();

    // Zero-variance fail-secure: never emit a confident verdict on the
    // degenerate (no-variance) case for a sentinel-threshold axis. The
    // crc-v2 zero-variance axes are federation_membership (at_or_above)
    // and rights_asymmetry (outside_corridor); the degenerate case is
    // metric == 0, which must NOT fire the sentinel under either.
    if matches!(
        tf.calibration_outcome,
        Some(CalibrationOutcome::ZeroVarianceBaseline)
    ) && metric_value <= 0.0
    {
        return ManifoldConformity::Indeterminate {
            reason: IndeterminateReason::AxisAwaitingCalibration { family },
        };
    }

    let crosses = match direction {
        ConcernDirection::AtOrAbove => metric_value >= tf.threshold_value,
        ConcernDirection::AtOrBelow => metric_value <= tf.threshold_value,
        ConcernDirection::OutsideCorridor => {
            // Concern when the metric exits the healthy corridor at either
            // pole. crc-v2 calibrates only the upper bound (== threshold_
            // value); lower_bound is null/uncalibrated, so the lower-pole
            // term is inert until crc-v3+ sets it. Forward-correct: a
            // future bundle shipping lower_bound fires chaos-pole concern.
            let above = metric_value >= tf.corridor_upper_bound();
            let below = tf
                .corridor_lower_bound()
                .is_some_and(|lb| metric_value <= lb);
            above || below
        }
    };

    if crosses {
        ManifoldConformity::Numeric(severity_scaled_score(metric_value, axis))
    } else {
        // On the conforming side of the threshold; in-band, no concern.
        ManifoldConformity::Numeric(0.0)
    }
}

/// Compute the severity-scaled score for a metric at/above threshold.
///
/// Anchored at `score_at_threshold` exactly at the threshold; scales
/// more negative as the metric exceeds the threshold, normalized by
/// the head-room between the threshold and the metric's natural ceiling
/// per polarity. `scaling: magnitude_scales_with_severity_above_threshold`.
///
/// # Scaling model
///
/// Let `s0 = score_at_threshold` (negative), `t = threshold`,
/// `m = metric (>= t)`. We linearly ramp the score from `s0` at `m = t`
/// toward `2·s0` (double the concern) as `m` traverses the head-room
/// `[t, ceiling]`:
///
/// ```text
/// frac  = (m − t) / (ceiling − t)      ∈ [0, 1]   (clamped)
/// score = s0 · (1 + frac)              ∈ [s0, 2·s0]
/// ```
///
/// The `ceiling` is `1.0` for bounded metrics (Gini, HHI, CV-as-
/// fraction-style, rates, fractions) and the metric value itself for
/// unbounded metrics (aggregate_footprint, CV) so the ramp stays well-
/// defined; when `ceiling <= t` we pin to `s0` (no head-room to scale
/// into). This keeps the published score monotone in severity and
/// anchored at the calibrated `score_at_threshold`.
pub fn severity_scaled_score(metric_value: f64, axis: &AxisEntry) -> f64 {
    use crate::scoring::axis_calibration::ConcernDirection;

    let tf = &axis.threshold_function;
    let s0 = tf.score_at_threshold;
    let t = tf.threshold_value;

    let frac = match tf.concern_direction() {
        // OutsideCorridor fires upper-pole in crc-v2 (upper_bound ==
        // threshold_value, lower_bound null), so its severity ramp is the
        // same upper-tail ramp as AtOrAbove. When crc-v3+ calibrates a
        // lower_bound, chaos-pole scaling gets its own arm.
        ConcernDirection::AtOrAbove | ConcernDirection::OutsideCorridor => {
            // Severity grows as the metric exceeds the threshold toward
            // a per-metric ceiling. Bounded [0,1] metrics ramp toward
            // 1.0; unbounded metrics (footprint, CV) ramp over [t, 2t].
            let ceiling = match tf.metric.as_str() {
                "compute_gini" | "models_hhi" | "part_excl_frac" | "pdma_rate_within"
                | "nonmember_frac" => 1.0,
                _ => 2.0 * t,
            };
            if ceiling <= t {
                // No head-room (models_hhi threshold = 1.0 = ceiling).
                return s0;
            }
            ((metric_value - t) / (ceiling - t)).clamp(0.0, 1.0)
        }
        ConcernDirection::AtOrBelow => {
            // Lower-tail concern (cap_diversity): severity grows as the
            // metric falls below the threshold toward the 0.0 floor.
            if t <= 0.0 {
                return s0;
            }
            ((t - metric_value) / t).clamp(0.0, 1.0)
        }
    };
    s0 * (1.0 + frac)
}

/// Bridge a measured metric over a corpus into an [`AxisScore`].
/// `metric` is `None` when the corpus couldn't yield a metric (empty
/// cohort, undefined denominator) → routed to
/// `Indeterminate { AxisAwaitingCalibration }` (we have no signal, not
/// a calibrated zero).
pub fn axis_score(metric: Option<f64>, axis: &AxisEntry, family: AxisFamily) -> AxisScore {
    match metric {
        Some(m) => AxisScore {
            metric_value: Some(m),
            conformity: score_against_axis(m, axis, family),
        },
        None => AxisScore {
            metric_value: None,
            conformity: ManifoldConformity::Indeterminate {
                reason: IndeterminateReason::AxisAwaitingCalibration { family },
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Metric kernels — hand-computed values.
    // -----------------------------------------------------------------

    #[test]
    fn gini_perfectly_equal_is_zero() {
        let g = gini(&[5.0, 5.0, 5.0, 5.0]).unwrap();
        assert!(g.abs() < 1e-12, "equal population Gini must be 0, got {g}");
    }

    #[test]
    fn gini_maximal_concentration_approaches_one() {
        // One agent holds everything: [0,0,0,10]. For n=4,
        // G = (n-1)/n for a single holder = 3/4 = 0.75.
        let g = gini(&[0.0, 0.0, 0.0, 10.0]).unwrap();
        assert!(
            (g - 0.75).abs() < 1e-12,
            "single-holder Gini n=4 = 0.75, got {g}"
        );
    }

    #[test]
    fn gini_known_two_point() {
        // [1, 3]: Σ|xi-xj| = |1-1|+|1-3|+|3-1|+|3-3| = 0+2+2+0 = 4
        // mean = 2, n=2 → G = 4 / (2·2²·2) = 4/16 = 0.25
        let g = gini(&[1.0, 3.0]).unwrap();
        assert!((g - 0.25).abs() < 1e-12, "Gini([1,3]) = 0.25, got {g}");
    }

    #[test]
    fn gini_empty_and_zero_sum_none() {
        assert!(gini(&[]).is_none());
        assert!(gini(&[0.0, 0.0]).is_none());
    }

    #[test]
    fn hhi_single_model_is_one() {
        let h = hhi(&[390]).unwrap();
        assert!((h - 1.0).abs() < 1e-12, "single-model HHI = 1.0, got {h}");
    }

    #[test]
    fn hhi_uniform_is_inverse_k() {
        // Two equal models: shares 0.5, 0.5 → HHI = 0.25 + 0.25 = 0.5 = 1/2.
        let h = hhi(&[50, 50]).unwrap();
        assert!((h - 0.5).abs() < 1e-12, "uniform-2 HHI = 0.5, got {h}");
        // Four equal: HHI = 4·0.25² = 0.25 = 1/4.
        let h4 = hhi(&[10, 10, 10, 10]).unwrap();
        assert!((h4 - 0.25).abs() < 1e-12, "uniform-4 HHI = 0.25, got {h4}");
    }

    #[test]
    fn hhi_known_skewed() {
        // counts [9, 1]: shares 0.9, 0.1 → 0.81 + 0.01 = 0.82.
        let h = hhi(&[9, 1]).unwrap();
        assert!((h - 0.82).abs() < 1e-12, "HHI([9,1]) = 0.82, got {h}");
    }

    #[test]
    fn cv_known() {
        // [2,4,4,4,5,5,7,9]: mean=5, population var=4, std=2 → CV = 2/5 = 0.4.
        let v = coefficient_of_variation(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]).unwrap();
        assert!((v - 0.4).abs() < 1e-12, "CV = 0.4, got {v}");
    }

    #[test]
    fn cv_zero_mean_none() {
        assert!(coefficient_of_variation(&[0.0, 0.0]).is_none());
        assert!(coefficient_of_variation(&[]).is_none());
    }

    #[test]
    fn fraction_below_median_known() {
        // [1,2,3,4,5]: median 3; below = {1,2} = 2/5 = 0.4.
        let f = fraction_below_median(&[1.0, 2.0, 3.0, 4.0, 5.0]).unwrap();
        assert!((f - 0.4).abs() < 1e-12, "frac below median = 0.4, got {f}");
        // [1,1,1,1]: median 1; none strictly below → 0.
        let f2 = fraction_below_median(&[1.0, 1.0, 1.0, 1.0]).unwrap();
        assert!(f2.abs() < 1e-12, "uniform → 0 below median, got {f2}");
    }

    #[test]
    fn capability_diversity_known() {
        // 4 agents, 2 distinct tuples → 2/4 = 0.5.
        let tuples = vec![
            ("work".to_string(), "scout".to_string()),
            ("work".to_string(), "scout".to_string()),
            ("play".to_string(), "scout".to_string()),
            ("play".to_string(), "scout".to_string()),
        ];
        let d = capability_diversity(&tuples).unwrap();
        assert!((d - 0.5).abs() < 1e-12, "cap_diversity = 0.5, got {d}");
    }

    #[test]
    fn aggregate_footprint_known() {
        // 100 actions, 10 agents → 100 · log10(10) = 100 · 1 = 100.
        let fp = aggregate_footprint(100, 10).unwrap();
        assert!((fp - 100.0).abs() < 1e-9, "agg_fp = 100, got {fp}");
        // single-agent cohort: log10(1)=0 → 0.
        let fp1 = aggregate_footprint(500, 1).unwrap();
        assert!(fp1.abs() < 1e-12, "single-agent footprint = 0, got {fp1}");
    }

    #[test]
    fn pooled_rate_known() {
        assert!((pooled_rate(3, 12).unwrap() - 0.25).abs() < 1e-12);
        assert!(pooled_rate(0, 0).is_none());
        assert!(pooled_rate(0, 30).unwrap().abs() < 1e-12);
    }

    // -----------------------------------------------------------------
    // Threshold + polarity scoring.
    // -----------------------------------------------------------------

    use crate::scoring::axis_calibration::{Polarity, StatisticalFloor, ThresholdFunction};

    fn axis(metric: &str, threshold: f64, polarity: Polarity, s0: f64, zvb: bool) -> AxisEntry {
        // Default to upper-tail (p75) concern; cap_diversity-style
        // lower-tail axes use `axis_pctile` below.
        axis_pctile(metric, threshold, 0.75, polarity, s0, zvb)
    }

    fn axis_pctile(
        metric: &str,
        threshold: f64,
        pctile: f64,
        polarity: Polarity,
        s0: f64,
        zvb: bool,
    ) -> AxisEntry {
        AxisEntry {
            axis: "test:axis".into(),
            tier: 1,
            measurement_procedure: "test".into(),
            threshold_function: ThresholdFunction {
                metric: metric.into(),
                threshold_value: threshold,
                threshold_pctile_of_observed: pctile,
                polarity,
                score_at_threshold: s0,
                scaling: "magnitude_scales_with_severity_above_threshold".into(),
                calibration_outcome: zvb.then_some(CalibrationOutcome::ZeroVarianceBaseline),
                // These helpers exercise the pctile-inference path
                // (concern_direction_field None); the explicit-field +
                // corridor path is covered by its own test below.
                concern_direction_field: None,
                corridor: None,
            },
            statistical_floor: StatisticalFloor {
                min_cohort_size_events: 1000,
                min_goal_aligned_cluster_size_agents: 30,
                min_window_days: 30,
                power_target: 0.95,
            },
            evidence_required: vec![],
        }
    }

    #[test]
    fn below_threshold_conforming() {
        let a = axis(
            "compute_gini",
            0.17,
            Polarity::PositiveWhenDistributed,
            -0.6,
            false,
        );
        match score_against_axis(0.10, &a, AxisFamily::DistributiveAccess) {
            ManifoldConformity::Numeric(s) => {
                assert!(s.abs() < 1e-12, "below threshold = 0, got {s}")
            }
            other => panic!("expected Numeric(0), got {other:?}"),
        }
    }

    #[test]
    fn at_threshold_anchors_at_score_at_threshold() {
        let a = axis(
            "compute_gini",
            0.17,
            Polarity::PositiveWhenDistributed,
            -0.6,
            false,
        );
        match score_against_axis(0.17, &a, AxisFamily::DistributiveAccess) {
            ManifoldConformity::Numeric(s) => {
                // At threshold, frac=0 → score = s0 = -0.6.
                assert!((s - (-0.6)).abs() < 1e-9, "at threshold = -0.6, got {s}");
            }
            other => panic!("expected Numeric, got {other:?}"),
        }
    }

    #[test]
    fn above_threshold_scales_more_negative() {
        let a = axis(
            "compute_gini",
            0.17,
            Polarity::PositiveWhenDistributed,
            -0.6,
            false,
        );
        // Halfway from 0.17 to ceiling 1.0: frac=(0.585-0.17)/(1-0.17)=0.5
        // score = -0.6·1.5 = -0.9.
        let mid = 0.17 + (1.0 - 0.17) * 0.5;
        match score_against_axis(mid, &a, AxisFamily::DistributiveAccess) {
            ManifoldConformity::Numeric(s) => {
                assert!((s - (-0.9)).abs() < 1e-9, "halfway = -0.9, got {s}");
            }
            other => panic!("expected Numeric, got {other:?}"),
        }
    }

    #[test]
    fn outside_corridor_fires_upper_pole_lower_inert_until_calibrated() {
        use crate::scoring::axis_calibration::{ConcernDirection, Corridor};
        // crc-v2 corridor axis: explicit OutsideCorridor + upper_bound ==
        // threshold_value, lower_bound null (uncalibrated).
        let mut a = axis(
            "compute_gini",
            0.169785,
            Polarity::PositiveWhenDistributed,
            -0.6,
            false,
        );
        a.threshold_function.concern_direction_field = Some(ConcernDirection::OutsideCorridor);
        a.threshold_function.corridor = Some(Corridor {
            upper_bound: Some(0.169785),
            lower_bound: None,
        });
        assert_eq!(
            a.threshold_function.concern_direction(),
            ConcernDirection::OutsideCorridor
        );
        // Above the upper bound → concern (anchored at s0 = -0.6).
        match score_against_axis(0.169785, &a, AxisFamily::DistributiveAccess) {
            ManifoldConformity::Numeric(s) => assert!((s - (-0.6)).abs() < 1e-9, "at upper = -0.6"),
            other => panic!("expected Numeric, got {other:?}"),
        }
        // Below the upper bound with NO calibrated lower bound → conforming
        // (chaos pole not flagged in crc-v2).
        match score_against_axis(0.05, &a, AxisFamily::DistributiveAccess) {
            ManifoldConformity::Numeric(s) => assert!(s.abs() < 1e-12, "below, lower null = 0"),
            other => panic!("expected Numeric(0), got {other:?}"),
        }
        // Forward-correctness: once crc-v3 calibrates a lower_bound, the
        // chaos pole fires too.
        a.threshold_function.corridor = Some(Corridor {
            upper_bound: Some(0.169785),
            lower_bound: Some(0.02),
        });
        match score_against_axis(0.01, &a, AxisFamily::DistributiveAccess) {
            ManifoldConformity::Numeric(s) => assert!(s < 0.0, "below lower_bound → concern"),
            other => panic!("expected Numeric concern, got {other:?}"),
        }
    }

    #[test]
    fn models_hhi_threshold_at_ceiling_pins_to_anchor() {
        // models_hhi threshold = 1.0 = ceiling → no head-room → pin s0.
        let a = axis(
            "models_hhi",
            1.0,
            Polarity::PositiveWhenDistributed,
            -0.5,
            false,
        );
        match score_against_axis(1.0, &a, AxisFamily::DistributiveAccess) {
            ManifoldConformity::Numeric(s) => assert!((s - (-0.5)).abs() < 1e-9),
            other => panic!("expected Numeric(-0.5), got {other:?}"),
        }
    }

    #[test]
    fn zero_variance_zero_metric_is_indeterminate() {
        // federation_membership/rights_asymmetry: metric 0 → fail-secure.
        let a = axis(
            "nonmember_frac",
            1e-6,
            Polarity::PositiveWhenDistributed,
            -0.4,
            true,
        );
        match score_against_axis(0.0, &a, AxisFamily::DistributiveAccess) {
            ManifoldConformity::Indeterminate {
                reason: IndeterminateReason::AxisAwaitingCalibration { .. },
            } => {}
            other => panic!("zero-variance metric=0 must be Indeterminate, got {other:?}"),
        }
    }

    #[test]
    fn zero_variance_nonzero_deviation_fires() {
        // A genuine non-zero deviation crosses the 1e-6 sentinel.
        let a = axis(
            "pdma_rate_within",
            1e-6,
            Polarity::NegativeWhenDetected,
            -0.6,
            true,
        );
        match score_against_axis(0.05, &a, AxisFamily::F3CorrelatedAction) {
            ManifoldConformity::Numeric(s) => assert!(s < 0.0, "deviation must concern, got {s}"),
            other => panic!("non-zero deviation must fire Numeric, got {other:?}"),
        }
    }

    #[test]
    fn cap_diversity_lower_tail_concern() {
        // cap_diversity: p25 threshold → AtOrBelow. LOW diversity = concern.
        let a = axis_pctile(
            "cap_diversity",
            0.037088,
            0.25,
            Polarity::PositiveWhenDistributed,
            -0.3,
            false,
        );
        // Below threshold → concern.
        match score_against_axis(0.02, &a, AxisFamily::DistributiveAccess) {
            ManifoldConformity::Numeric(s) => assert!(s < 0.0, "low diversity → concern, got {s}"),
            other => panic!("expected Numeric concern, got {other:?}"),
        }
        // Above threshold → conforming (healthy diversity).
        match score_against_axis(0.06, &a, AxisFamily::DistributiveAccess) {
            ManifoldConformity::Numeric(s) => {
                assert!(s.abs() < 1e-12, "high diversity → conforming, got {s}")
            }
            other => panic!("expected Numeric(0), got {other:?}"),
        }
    }

    #[test]
    fn axis_score_none_metric_indeterminate() {
        let a = axis(
            "compute_gini",
            0.17,
            Polarity::PositiveWhenDistributed,
            -0.6,
            false,
        );
        let r = axis_score(None, &a, AxisFamily::DistributiveAccess);
        assert!(r.metric_value.is_none());
        assert!(matches!(
            r.conformity,
            ManifoldConformity::Indeterminate {
                reason: IndeterminateReason::AxisAwaitingCalibration { .. }
            }
        ));
    }
}
