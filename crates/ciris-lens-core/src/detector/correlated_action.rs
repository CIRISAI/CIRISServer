//! CEG §5.5.3 — F-3 correlated-action / structural-injustice detector.
//!
//! Population-scale detector that reads federation-emitted signed
//! traces and reports correlation structure (`ρ`, `k_eff`) over goal-
//! aligned individually-compliant pursuit by groups whose aggregate
//! trajectory affects individuals or groups outside the pursuit.
//!
//! # Wire format
//!
//! The emitted prefix is `detection:correlated_action:{axis}`, where
//! `{axis}` is **open vocabulary** per CEG §5.5.3 (new axes admitted
//! via the §11.2 amendment process). CEG names a canonical seed
//! taxonomy of eight axes; lens-core ships these as known variants
//! and accepts unknown axes as `Custom(String)` so calibration-package
//! amendments don't require a lens-core release.
//!
//! # Historical name — `detection:emergent_deception:{axis}`
//!
//! FSD-002 v1.1 originally named this prefix `emergent_deception`
//! (the Magnifica-Humanitas-encyclical-derived name); CEG §5.5.3
//! adopted `correlated_action` as the framework-native operational
//! name. The two name the SAME detector. A CEG §6 `delegates_to`
//! rename-chain (`correlated_action_v{N+1}:from:emergent_deception_v
//! {N}`) will land at the same release that ships the first
//! calibrated operating point; until then, lens-core emits the
//! CEG-canonical name only.
//!
//! # crc-v2 status — LIVE for 4 axes
//!
//! RATCHET's `crc-v2` axis-family calibration (shipped 2026-06-12)
//! lights up the F-3 detector for four axes; the four
//! `ecology_of_communication:*` aspects stay deferred (no inter-agent
//! messaging in the substrate, gated on CIRISAgent#876/#877).
//!
//! | Axis | Metric | Threshold | Status |
//! |---|---|---|---|
//! | `rights_asymmetry` | `pdma_rate_within` | ≥ 1e-6 sentinel | LIVE (Tier-1, zero-variance) |
//! | `participation_exclusion` | `part_excl_frac` | ≥ 0.444444 | LIVE (Tier-2 proxy) |
//! | `informational_asymmetry` | `info_asym_cv` | ≥ 0.707337 | LIVE (Tier-2 proxy) |
//! | `aggregate_footprint` | `agg_fp` | ≥ 619.416079 | LIVE (Tier-2 proxy) |
//! | `ecology_of_communication:*` | — | — | DEFERRED (Tier-3) |
//!
//! [`score_calibrated`] runs the measurement procedure with a hydrated
//! [`AxisCalibration`]; the legacy [`score`] (no bundle) returns
//! `AxisAwaitingCalibration` for every axis — MISSION.md §3
//! anti-pattern #9 fail-secure default.
//! [#26 umbrella](https://github.com/CIRISAI/CIRISLensCore/issues/26).
//!
//! See [MISSION.md §2 `detector/`](../../../MISSION.md) for the
//! categorical-not-redundant layering argument (§5.5.1 catches
//! individual deviation, §5.5.3 catches coordinated compliance,
//! §5.5.5 catches the concentration substrate).

use serde_json::Value;

use crate::detector::axis_metrics::{
    aggregate_footprint, axis_score, coefficient_of_variation, fraction_below_median, pooled_rate,
};
use crate::scoring::axis_calibration::AxisCalibration;
use crate::scoring::result::{AxisFamily, IndeterminateReason, ManifoldConformity};

/// The axis a `detection:correlated_action:{axis}` envelope is
/// reporting against. **Open vocabulary** per CEG §5.5.3 — the
/// canonical-name variants are the seed taxonomy; `Custom` admits
/// calibration-package-amendment axes without a lens-core release.
///
/// # Canonical axes (CEG §5.5.3)
///
/// - `rights_asymmetry:{population}` — rights distribution asymmetry
///   across a named population.
/// - `participation_exclusion:{cohort}` /
///   `participation_inclusion:{cohort}` — who has / lacks a seat at
///   the goal-articulation table.
/// - `informational_asymmetry:{scope}` /
///   `informational_symmetry:{scope}` — who knows / doesn't know
///   what the goal-pursuit's aggregate trajectory entails.
/// - `aggregate_footprint:{harm_class}` /
///   `aggregate_benefit:{class}` — aggregate-impact distribution.
/// - `ecology_of_communication:{aspect}` — echo-chamber / coordinated-
///   messaging / cross-cohort information-flow patterns (CIRISLensCore
///   #24's Magnifica Humanitas T-3 candidate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrelatedActionAxis {
    /// `rights_asymmetry:{population}`
    RightsAsymmetry {
        /// Population name; opaque to lens-core, defined by the
        /// calibration package.
        population: String,
    },
    /// `participation_exclusion:{cohort}`
    ParticipationExclusion { cohort: String },
    /// `participation_inclusion:{cohort}`
    ParticipationInclusion { cohort: String },
    /// `informational_asymmetry:{scope}`
    InformationalAsymmetry { scope: String },
    /// `informational_symmetry:{scope}`
    InformationalSymmetry { scope: String },
    /// `aggregate_footprint:{harm_class}`
    AggregateFootprint { harm_class: String },
    /// `aggregate_benefit:{class}`
    AggregateBenefit { class: String },
    /// `ecology_of_communication:{aspect}` — known aspects per
    /// CIRISLensCore#24: `echo_chamber_density`,
    /// `information_silo_correlation`, `coordinated_messaging_pattern`,
    /// `cross_cohort_information_flow`. Aspect membership is
    /// calibration-package-owned; lens-core treats `{aspect}` as
    /// opaque string.
    EcologyOfCommunication { aspect: String },
    /// Axis introduced by a CEG §11.2 amendment after this lens-core
    /// release; the raw `{axis}` substring is preserved verbatim for
    /// forward-compatibility. Calibration package owns the operational
    /// definition.
    Custom { axis: String },
}

impl CorrelatedActionAxis {
    /// CEG wire-stable suffix — the `{axis}` portion of
    /// `detection:correlated_action:{axis}`. Joined with the prefix
    /// at envelope-construction time.
    pub fn wire_suffix(&self) -> String {
        match self {
            Self::RightsAsymmetry { population } => format!("rights_asymmetry:{population}"),
            Self::ParticipationExclusion { cohort } => {
                format!("participation_exclusion:{cohort}")
            }
            Self::ParticipationInclusion { cohort } => {
                format!("participation_inclusion:{cohort}")
            }
            Self::InformationalAsymmetry { scope } => format!("informational_asymmetry:{scope}"),
            Self::InformationalSymmetry { scope } => format!("informational_symmetry:{scope}"),
            Self::AggregateFootprint { harm_class } => format!("aggregate_footprint:{harm_class}"),
            Self::AggregateBenefit { class } => format!("aggregate_benefit:{class}"),
            Self::EcologyOfCommunication { aspect } => {
                format!("ecology_of_communication:{aspect}")
            }
            Self::Custom { axis } => axis.clone(),
        }
    }

    /// Full CEG `detection:correlated_action:{axis}` wire label.
    pub fn dimension_label(&self) -> String {
        format!("detection:correlated_action:{}", self.wire_suffix())
    }

    /// The crc-v2 `axes` map key for this axis — the **bare** axis
    /// family label (no `{population}` / `{cohort}` / `{scope}`
    /// suffix), since the calibration is per axis-family, not per
    /// instance. Returns `None` for axes that crc-v2 does not calibrate
    /// (the inclusion/symmetry/benefit duals, `ecology_of_communication:*`
    /// Tier-3 aspects, and post-release `Custom` amendments) — the
    /// caller routes those to `AxisAwaitingCalibration`.
    pub fn calibration_axis_label(&self) -> Option<&'static str> {
        match self {
            Self::RightsAsymmetry { .. } => Some("correlated_action:rights_asymmetry"),
            Self::ParticipationExclusion { .. } => {
                Some("correlated_action:participation_exclusion")
            }
            Self::InformationalAsymmetry { .. } => {
                Some("correlated_action:informational_asymmetry")
            }
            Self::AggregateFootprint { .. } => Some("correlated_action:aggregate_footprint"),
            // Not calibrated in crc-v2: positive-direction duals,
            // ecology_of_communication (Tier-3), and Custom amendments.
            Self::ParticipationInclusion { .. }
            | Self::InformationalSymmetry { .. }
            | Self::AggregateBenefit { .. }
            | Self::EcologyOfCommunication { .. }
            | Self::Custom { .. } => None,
        }
    }
}

/// Population-level input to the F-3 scorer.
///
/// `corpus` is the per-agent aggregate cohort (one
/// [`serde_json::Value`] per `agent_id_hash`, per crc-v2 README). Each
/// record carries the fields RATCHET's Pass-A aggregation produces; see
/// [`crate::detector::axis_metrics`].
#[derive(Debug, Clone)]
pub struct CorrelatedActionInput<'a> {
    /// The axis being scored. Carries through to the emitted envelope.
    pub axis: CorrelatedActionAxis,
    /// Federation-emitted per-agent aggregate corpus.
    pub corpus: &'a [serde_json::Value],
}

/// F-3 scorer — **legacy no-calibration path**. Returns
/// `ManifoldConformity::Indeterminate { AxisAwaitingCalibration }` for
/// every axis. Callers with a hydrated `crc-v2` [`AxisCalibration`] use
/// [`score_calibrated`] instead.
///
/// **Why `Indeterminate` not `Unavailable`:** the substrate is healthy
/// and the corpus is present. What's missing is the calibration-package
/// operational definition for `axis`. That's exactly LC-AV-18 /
/// anti-pattern #2 shape, not LC-AV-11 substrate failure.
pub fn score(_input: &CorrelatedActionInput<'_>) -> ManifoldConformity {
    ManifoldConformity::Indeterminate {
        reason: IndeterminateReason::AxisAwaitingCalibration {
            family: AxisFamily::F3CorrelatedAction,
        },
    }
}

/// F-3 scorer against a hydrated `crc-v2` [`AxisCalibration`]. Measures
/// the per-axis metric over the per-agent aggregate `corpus` and
/// applies the calibrated threshold + polarity. Axes crc-v2 does not
/// calibrate (Tier-3 `ecology_of_communication:*`, the positive duals,
/// `Custom`) return `Indeterminate { AxisAwaitingCalibration }`.
///
/// Per-axis measurement procedure (each cites its bundle line in
/// [`crate::detector::axis_metrics`]):
///
/// - `rights_asymmetry` → pooled PDMA-conflict rate
///   `Σ pdma_conflict_count / Σ pdma_total` (zero-variance sentinel).
/// - `participation_exclusion` → fraction of agents below the cohort
///   median `n_distinct_domains`.
/// - `informational_asymmetry` → CV of per-agent dsdma flag totals.
/// - `aggregate_footprint` → `Σ n_action × log10(cohort size)`.
pub fn score_calibrated(
    input: &CorrelatedActionInput<'_>,
    calibration: &AxisCalibration,
) -> ManifoldConformity {
    let Some(label) = input.axis.calibration_axis_label() else {
        return ManifoldConformity::Indeterminate {
            reason: IndeterminateReason::AxisAwaitingCalibration {
                family: AxisFamily::F3CorrelatedAction,
            },
        };
    };
    let Some(axis) = calibration.axis(label) else {
        // Mapped to a bundle label that is nonetheless absent (e.g. a
        // future calibration that drops an axis) — fail-secure.
        return ManifoldConformity::Indeterminate {
            reason: IndeterminateReason::AxisAwaitingCalibration {
                family: AxisFamily::F3CorrelatedAction,
            },
        };
    };

    let metric = match &input.axis {
        CorrelatedActionAxis::RightsAsymmetry { .. } => {
            // Pooled PDMA-conflict rate across the cohort.
            let mut conflicts = 0u64;
            let mut total = 0u64;
            for a in input.corpus {
                conflicts += a
                    .get("pdma_conflict_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                total += a.get("pdma_total").and_then(Value::as_u64).unwrap_or(0);
            }
            pooled_rate(conflicts, total)
        }
        CorrelatedActionAxis::ParticipationExclusion { .. } => {
            // Fraction below cohort-median distinct-domain count.
            let domains: Vec<f64> = input
                .corpus
                .iter()
                .map(|a| {
                    a.get("n_distinct_domains")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0)
                })
                .collect();
            fraction_below_median(&domains)
        }
        CorrelatedActionAxis::InformationalAsymmetry { .. } => {
            // CV of per-agent total dsdma flag counts.
            let flag_totals: Vec<f64> = input
                .corpus
                .iter()
                .map(|a| {
                    a.get("dsdma_flags_count")
                        .and_then(Value::as_object)
                        .map(|m| m.values().filter_map(Value::as_u64).sum::<u64>())
                        .unwrap_or(0) as f64
                })
                .collect();
            coefficient_of_variation(&flag_totals)
        }
        CorrelatedActionAxis::AggregateFootprint { .. } => {
            // Σ action count × log10(cohort size).
            let total_actions: u64 = input
                .corpus
                .iter()
                .map(|a| a.get("n_action").and_then(Value::as_u64).unwrap_or(0))
                .sum();
            aggregate_footprint(total_actions, input.corpus.len())
        }
        // Unreachable: calibration_axis_label() returned Some only for
        // the four arms above.
        _ => None,
    };

    axis_score(metric, axis, AxisFamily::F3CorrelatedAction).conformity
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_label_for_canonical_axes() {
        // CEG §5.5.3 canonical axes round-trip through the wire-label
        // function. If any of these strings drift, the federation
        // can't recognize the dimension.
        let cases = [
            (
                CorrelatedActionAxis::RightsAsymmetry {
                    population: "indigenous_nations".into(),
                },
                "detection:correlated_action:rights_asymmetry:indigenous_nations",
            ),
            (
                CorrelatedActionAxis::ParticipationExclusion {
                    cohort: "cohort_42".into(),
                },
                "detection:correlated_action:participation_exclusion:cohort_42",
            ),
            (
                CorrelatedActionAxis::EcologyOfCommunication {
                    aspect: "echo_chamber_density".into(),
                },
                "detection:correlated_action:ecology_of_communication:echo_chamber_density",
            ),
        ];
        for (axis, expected) in cases {
            assert_eq!(axis.dimension_label(), expected);
        }
    }

    #[test]
    fn wire_label_custom_axis_passes_through_verbatim() {
        // Open-vocab discipline: an axis introduced by post-release
        // CEG amendment is preserved without modification. The
        // amendment process owns the operational definition; lens-
        // core just transports the string.
        let axis = CorrelatedActionAxis::Custom {
            axis: "future_amendment_axis:some_facet".into(),
        };
        assert_eq!(
            axis.dimension_label(),
            "detection:correlated_action:future_amendment_axis:some_facet"
        );
    }

    #[test]
    fn score_always_returns_axis_awaiting_calibration() {
        // MISSION.md §3 anti-pattern #9: never ship a numeric verdict
        // before RATCHET calibrates. This test locks the discipline.
        let input = CorrelatedActionInput {
            axis: CorrelatedActionAxis::RightsAsymmetry {
                population: "p".into(),
            },
            corpus: &[],
        };
        match score(&input) {
            ManifoldConformity::Indeterminate {
                reason:
                    IndeterminateReason::AxisAwaitingCalibration {
                        family: AxisFamily::F3CorrelatedAction,
                    },
            } => (),
            other => panic!(
                "v0.3 F-3 must return Indeterminate {{ AxisAwaitingCalibration {{ F3CorrelatedAction }} }}; \
                 got {other:?}"
            ),
        }
    }

    #[test]
    fn score_indeterminate_regardless_of_corpus_size() {
        // Sweep corpus size from empty through "definitely enough
        // signal" — the result MUST NOT change. The substrate not
        // being calibrated is independent of how much data we have.
        for size in [0usize, 1, 100, 10_000] {
            let corpus: Vec<serde_json::Value> =
                (0..size).map(|i| serde_json::json!({ "i": i })).collect();
            let input = CorrelatedActionInput {
                axis: CorrelatedActionAxis::AggregateFootprint {
                    harm_class: "h".into(),
                },
                corpus: &corpus,
            };
            assert!(matches!(
                score(&input),
                ManifoldConformity::Indeterminate {
                    reason: IndeterminateReason::AxisAwaitingCalibration {
                        family: AxisFamily::F3CorrelatedAction
                    }
                }
            ));
        }
    }

    // -----------------------------------------------------------------
    // crc-v2 calibrated path.
    // -----------------------------------------------------------------

    const SHIPPED_V2: &str = "/home/emoore/RATCHET/release/calibration/crc-v2/bundle.yaml";

    fn cal() -> Option<std::sync::Arc<AxisCalibration>> {
        let yaml = std::fs::read_to_string(SHIPPED_V2).ok()?;
        AxisCalibration::from_yaml(&yaml).ok()
    }

    #[test]
    fn rights_asymmetry_zero_conflicts_is_indeterminate() {
        let Some(c) = cal() else {
            eprintln!("skipping: crc-v2 absent");
            return;
        };
        // Zero-variance axis: all agents 0 conflicts → rate 0 → fail-secure.
        let corpus = vec![
            serde_json::json!({ "pdma_conflict_count": 0, "pdma_total": 30 }),
            serde_json::json!({ "pdma_conflict_count": 0, "pdma_total": 25 }),
        ];
        let input = CorrelatedActionInput {
            axis: CorrelatedActionAxis::RightsAsymmetry {
                population: "p".into(),
            },
            corpus: &corpus,
        };
        match score_calibrated(&input, &c) {
            ManifoldConformity::Indeterminate {
                reason: IndeterminateReason::AxisAwaitingCalibration { .. },
            } => {}
            other => panic!("zero conflicts → Indeterminate, got {other:?}"),
        }
    }

    #[test]
    fn rights_asymmetry_nonzero_conflict_fires() {
        let Some(c) = cal() else {
            return;
        };
        // Non-zero pooled rate crosses the 1e-6 sentinel → concern.
        let corpus = vec![
            serde_json::json!({ "pdma_conflict_count": 2, "pdma_total": 30 }),
            serde_json::json!({ "pdma_conflict_count": 0, "pdma_total": 30 }),
        ];
        let input = CorrelatedActionInput {
            axis: CorrelatedActionAxis::RightsAsymmetry {
                population: "p".into(),
            },
            corpus: &corpus,
        };
        match score_calibrated(&input, &c) {
            ManifoldConformity::Numeric(s) => assert!(s < 0.0, "conflicts present → concern"),
            other => panic!("expected Numeric concern, got {other:?}"),
        }
    }

    #[test]
    fn informational_asymmetry_high_cv_fires() {
        let Some(c) = cal() else {
            return;
        };
        // info_asym_cv threshold 0.707337. flag totals [1, 1, 1, 10]:
        // mean=3.25, var=14.9, std≈3.86, CV≈1.19 ≥ 0.707 → concern.
        let flags = |n: u64| serde_json::json!({ "dsdma_flags_count": { "f": n } });
        let corpus = vec![flags(1), flags(1), flags(1), flags(10)];
        let input = CorrelatedActionInput {
            axis: CorrelatedActionAxis::InformationalAsymmetry { scope: "s".into() },
            corpus: &corpus,
        };
        match score_calibrated(&input, &c) {
            ManifoldConformity::Numeric(s) => assert!(s < 0.0, "high CV → concern, got {s}"),
            other => panic!("expected Numeric concern, got {other:?}"),
        }
    }

    #[test]
    fn informational_asymmetry_low_cv_conforming() {
        let Some(c) = cal() else {
            return;
        };
        // Uniform flag totals → CV 0 < 0.707 → conforming.
        let flags = |n: u64| serde_json::json!({ "dsdma_flags_count": { "f": n } });
        let corpus = vec![flags(5), flags(5), flags(5)];
        let input = CorrelatedActionInput {
            axis: CorrelatedActionAxis::InformationalAsymmetry { scope: "s".into() },
            corpus: &corpus,
        };
        match score_calibrated(&input, &c) {
            ManifoldConformity::Numeric(s) => assert!(s.abs() < 1e-12, "uniform → conforming"),
            other => panic!("expected Numeric(0), got {other:?}"),
        }
    }

    #[test]
    fn participation_exclusion_fires_above_threshold() {
        let Some(c) = cal() else {
            return;
        };
        // part_excl_frac threshold 0.444444 (fraction STRICTLY below the
        // cohort median). n=10, [0×5, 1×5]: median = (0+1)/2 = 0.5;
        // strictly-below-0.5 = 5 → 5/10 = 0.5 ≥ 0.444444 → concern.
        let dom = |n: u64| serde_json::json!({ "n_distinct_domains": n });
        let corpus = vec![
            dom(0),
            dom(0),
            dom(0),
            dom(0),
            dom(0),
            dom(1),
            dom(1),
            dom(1),
            dom(1),
            dom(1),
        ];
        let input = CorrelatedActionInput {
            axis: CorrelatedActionAxis::ParticipationExclusion { cohort: "c".into() },
            corpus: &corpus,
        };
        match score_calibrated(&input, &c) {
            ManifoldConformity::Numeric(s) => assert!(s < 0.0, "frac below median high → concern"),
            other => panic!("expected Numeric concern, got {other:?}"),
        }
    }

    #[test]
    fn aggregate_footprint_fires_above_threshold() {
        let Some(c) = cal() else {
            return;
        };
        // agg_fp threshold 619.416079 = actions × log10(N). With N=100
        // (log10=2), need actions ≥ 310 to cross. 200 agents each 4 actions
        // → 800 actions × log10(200)≈2.30 ≈ 1841 ≥ 619 → concern.
        let act = serde_json::json!({ "n_action": 4 });
        let corpus: Vec<Value> = (0..200).map(|_| act.clone()).collect();
        let input = CorrelatedActionInput {
            axis: CorrelatedActionAxis::AggregateFootprint {
                harm_class: "h".into(),
            },
            corpus: &corpus,
        };
        match score_calibrated(&input, &c) {
            ManifoldConformity::Numeric(s) => assert!(s < 0.0, "big footprint → concern, got {s}"),
            other => panic!("expected Numeric concern, got {other:?}"),
        }
    }

    #[test]
    fn ecology_of_communication_stays_awaiting_calibration() {
        let Some(c) = cal() else {
            return;
        };
        // Tier-3 deferred: not calibrated in crc-v2.
        let input = CorrelatedActionInput {
            axis: CorrelatedActionAxis::EcologyOfCommunication {
                aspect: "echo_chamber_density".into(),
            },
            corpus: &[],
        };
        match score_calibrated(&input, &c) {
            ManifoldConformity::Indeterminate {
                reason: IndeterminateReason::AxisAwaitingCalibration { .. },
            } => {}
            other => panic!("ecology axes must stay AxisAwaitingCalibration, got {other:?}"),
        }
    }
}
