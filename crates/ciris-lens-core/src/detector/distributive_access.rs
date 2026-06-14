//! CEG §5.5.5 — Distributive-access detector.
//!
//! Population-scale resource-concentration detector. Same F-3
//! machinery as [`crate::detector::correlated_action`]; different
//! trace source (resource events vs action events) and a **closed**
//! resource-type vocabulary.
//!
//! # Wire format
//!
//! `detection:distributive:access:{resource_type}`, where
//! `{resource_type}` is one of the five CEG §5.5.5 enumerated
//! resource types. Unlike F-3's open-vocab axis, distributive-access
//! is a closed enum because CEG §5.5.5 fully enumerates the
//! federation-relevant resource categories. Adding a sixth resource
//! type requires a CEG amendment AND a lens-core release.
//!
//! Per CIRISLensCore#24 (Magnifica Humanitas "Universal Destination
//! of Goods" mapping), the closed-enum lock is load-bearing —
//! distributive-access claims about an unspecified resource would
//! pull the verdict semantics out of the calibration package's
//! per-resource specification (Gini / HHI / floor / threshold).
//!
//! # crc-v2 status — LIVE for 3 of 5 resource types
//!
//! RATCHET's `crc-v2` axis-family calibration (shipped 2026-06-12)
//! lights up the distributive detectors. With an [`AxisCalibration`]
//! in hand, [`score`] measures the per-resource metric over the corpus
//! and applies the calibrated threshold + polarity:
//!
//! | Resource | Metric | Threshold | Status |
//! |---|---|---|---|
//! | `compute` | `compute_gini` (Gini over per-agent cost_usd) | ≥ 0.169785 | LIVE (Tier-1) |
//! | `models` | `models_hhi` (HHI over pooled model usage) | ≥ 1.0 | LIVE (Tier-1) |
//! | `agent_capabilities` | `cap_diversity` ((state,role) tuples / N) | ≥ 0.037088 | LIVE (Tier-2) |
//! | `federation_membership` | `nonmember_frac` | ≥ 1e-6 sentinel | LIVE (Tier-1, zero-variance) |
//! | `training_data` | — | — | DEFERRED (Tier-3, no substrate emit) |
//!
//! `training_data` has no substrate emission path (gated on
//! CIRISAgent#880) and stays
//! [`ManifoldConformity::Indeterminate { AxisAwaitingCalibration }`].
//! The legacy no-calibration [`score`] (called without a bundle) also
//! returns `AxisAwaitingCalibration` for every resource — fail-secure
//! per MISSION.md §3 anti-pattern #9.
//! [#24](https://github.com/CIRISAI/CIRISLensCore/issues/24) +
//! [#26 umbrella](https://github.com/CIRISAI/CIRISLensCore/issues/26).

use std::collections::BTreeMap;

use serde_json::Value;

use crate::detector::axis_metrics::{axis_score, capability_diversity, gini, hhi, pooled_rate};
use crate::scoring::axis_calibration::AxisCalibration;
use crate::scoring::result::{AxisFamily, IndeterminateReason, ManifoldConformity};

/// The resource type a `detection:distributive:access:{resource_type}`
/// envelope is reporting against. **Closed enumeration** per CEG
/// §5.5.5 — these are the five federation-relevant distributive
/// categories the calibration workshop has scoped.
///
/// Adding a variant requires:
/// 1. CEG §5.5.5 amendment (governance per §11.2).
/// 2. RATCHET calibration package update (per-resource operational
///    spec + statistical floor + threshold function).
/// 3. Lens-core release that lands the new variant + maps its
///    wire suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributiveAccessResource {
    /// `compute` — concentration of federation compute consumption.
    /// Calibration: HHI over per-participant compute, cohort floor
    /// per RATCHET spec.
    Compute,
    /// `models` — concentration of model-access licensing / hosting.
    Models,
    /// `training_data` — concentration of training-data access /
    /// holding rights.
    TrainingData,
    /// `agent_capabilities` — concentration of capability-token
    /// holding across federation actors.
    AgentCapabilities,
    /// `federation_membership` — concentration of membership /
    /// voting weight across the federation.
    FederationMembership,
}

impl DistributiveAccessResource {
    /// CEG wire-stable resource-type suffix.
    pub const fn wire_suffix(self) -> &'static str {
        match self {
            Self::Compute => "compute",
            Self::Models => "models",
            Self::TrainingData => "training_data",
            Self::AgentCapabilities => "agent_capabilities",
            Self::FederationMembership => "federation_membership",
        }
    }

    /// The crc-v2 `axes` map key (CEG axis label) for this resource.
    /// Tier-3 `training_data` has no calibrated axis, so it maps to a
    /// label absent from the bundle and routes to `AxisAwaitingCalibration`.
    pub const fn axis_label(self) -> &'static str {
        match self {
            Self::Compute => "distributive:access:compute",
            Self::Models => "distributive:access:models",
            Self::TrainingData => "distributive:access:training_data",
            Self::AgentCapabilities => "distributive:access:agent_capabilities",
            Self::FederationMembership => "distributive:access:federation_membership",
        }
    }

    /// Full CEG `detection:distributive:access:{resource_type}` wire
    /// label.
    pub fn dimension_label(self) -> String {
        format!("detection:distributive:access:{}", self.wire_suffix())
    }

    /// Closed-enum membership lock. Adding a variant requires updating
    /// this constant + the [`wire_suffix`] match. Both are checked at
    /// compile-time by the exhaustiveness checker.
    ///
    /// [`wire_suffix`]: Self::wire_suffix
    pub const ALL: [DistributiveAccessResource; 5] = [
        Self::Compute,
        Self::Models,
        Self::TrainingData,
        Self::AgentCapabilities,
        Self::FederationMembership,
    ];
}

/// Population-level input to the distributive-access scorer.
///
/// `corpus` is the per-agent aggregate cohort (one
/// [`serde_json::Value`] per `agent_id_hash`, per crc-v2 README §
/// "Statistical floors" — NOT `channel_id`). Each record carries the
/// fields RATCHET's Pass-A aggregation produces; see
/// [`crate::detector::axis_metrics`] for the shape.
#[derive(Debug, Clone)]
pub struct DistributiveAccessInput<'a> {
    /// Which resource type is being scored.
    pub resource: DistributiveAccessResource,
    /// Federation-emitted per-agent aggregate corpus.
    pub corpus: &'a [serde_json::Value],
}

/// Distributive-access scorer — **legacy no-calibration path**.
///
/// Returns `ManifoldConformity::Indeterminate { AxisAwaitingCalibration }`
/// for every resource. Callers with a hydrated `crc-v2`
/// [`AxisCalibration`] use [`score_calibrated`] instead. This entry
/// is preserved for the no-bundle fail-secure default.
pub fn score(_input: &DistributiveAccessInput<'_>) -> ManifoldConformity {
    ManifoldConformity::Indeterminate {
        reason: IndeterminateReason::AxisAwaitingCalibration {
            family: AxisFamily::DistributiveAccess,
        },
    }
}

/// Distributive-access scorer against a hydrated `crc-v2`
/// [`AxisCalibration`]. Measures the per-resource metric over the
/// per-agent aggregate `corpus` and applies the calibrated threshold +
/// polarity.
///
/// Tier-3 `training_data` (absent from the bundle) returns
/// `Indeterminate { AxisAwaitingCalibration }`. Each LIVE resource
/// runs its bundle-cited measurement procedure:
///
/// - `compute` → Gini over per-agent `cost_usd_sum`.
/// - `models` → HHI over pooled `llm_model_counts`.
/// - `agent_capabilities` → distinct `(cognitive_state_dominant,
///   agent_role)` tuples / cohort size.
/// - `federation_membership` → fraction of non-`federation_member`
///   agents (zero-variance sentinel).
pub fn score_calibrated(
    input: &DistributiveAccessInput<'_>,
    calibration: &AxisCalibration,
) -> ManifoldConformity {
    let Some(axis) = calibration.axis(input.resource.axis_label()) else {
        // Tier-3 deferred (training_data) — no calibrated axis.
        return ManifoldConformity::Indeterminate {
            reason: IndeterminateReason::AxisAwaitingCalibration {
                family: AxisFamily::DistributiveAccess,
            },
        };
    };

    let metric = match input.resource {
        DistributiveAccessResource::Compute => {
            // Gini across per-agent summed LLM_CALL cost_usd.
            let costs: Vec<f64> = input
                .corpus
                .iter()
                .map(|a| a.get("cost_usd_sum").and_then(Value::as_f64).unwrap_or(0.0))
                .collect();
            gini(&costs)
        }
        DistributiveAccessResource::Models => {
            // HHI over pooled per-model usage counts across the cohort.
            let mut pooled: BTreeMap<String, u64> = BTreeMap::new();
            for a in input.corpus {
                if let Some(map) = a.get("llm_model_counts").and_then(Value::as_object) {
                    for (model, c) in map {
                        *pooled.entry(model.clone()).or_insert(0) += c.as_u64().unwrap_or(0);
                    }
                }
            }
            let counts: Vec<u64> = pooled.values().copied().collect();
            hhi(&counts)
        }
        DistributiveAccessResource::AgentCapabilities => {
            // Distinct (cognitive_state_dominant, agent_role) / cohort size.
            let tuples: Vec<(String, String)> = input
                .corpus
                .iter()
                .map(|a| {
                    let state = a
                        .get("cognitive_state_dominant")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let role = a
                        .get("agent_role")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    (state, role)
                })
                .collect();
            capability_diversity(&tuples)
        }
        DistributiveAccessResource::FederationMembership => {
            // Fraction of non-members in the cohort (zero-variance axis).
            let n = input.corpus.len() as u64;
            let nonmembers = input
                .corpus
                .iter()
                .filter(|a| {
                    !a.get("federation_member")
                        .and_then(Value::as_bool)
                        .unwrap_or(true)
                })
                .count() as u64;
            pooled_rate(nonmembers, n)
        }
        DistributiveAccessResource::TrainingData => {
            unreachable!("training_data has no calibrated axis; guarded by the axis() lookup above")
        }
    };

    axis_score(metric, axis, AxisFamily::DistributiveAccess).conformity
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_label_locked_for_every_variant() {
        // CEG §5.5.5 names the five resource_type strings exactly.
        // If any string drifts, federation consumers can't recognize
        // the dimension.
        let expected = [
            (
                DistributiveAccessResource::Compute,
                "detection:distributive:access:compute",
            ),
            (
                DistributiveAccessResource::Models,
                "detection:distributive:access:models",
            ),
            (
                DistributiveAccessResource::TrainingData,
                "detection:distributive:access:training_data",
            ),
            (
                DistributiveAccessResource::AgentCapabilities,
                "detection:distributive:access:agent_capabilities",
            ),
            (
                DistributiveAccessResource::FederationMembership,
                "detection:distributive:access:federation_membership",
            ),
        ];
        for (resource, expected) in expected {
            assert_eq!(resource.dimension_label(), expected);
        }
    }

    #[test]
    fn all_constant_has_exactly_five_variants() {
        // CEG §5.5.5 lock: the closed enum is exactly five resources.
        // Adding a sixth requires CEG amendment + RATCHET update.
        // This test makes the addition deliberate at code-review time.
        assert_eq!(DistributiveAccessResource::ALL.len(), 5);
    }

    #[test]
    fn all_constant_contains_each_variant_exactly_once() {
        // Exhaustiveness + dedup check on the ALL constant.
        let mut sorted: Vec<_> = DistributiveAccessResource::ALL.iter().collect();
        sorted.sort_by_key(|r| r.wire_suffix());
        sorted.dedup();
        assert_eq!(sorted.len(), 5);
    }

    #[test]
    fn score_always_returns_axis_awaiting_calibration_for_every_resource() {
        // Run the v0.3 stub over every resource type — all must
        // return Indeterminate { AxisAwaitingCalibration { DistributiveAccess } }.
        for resource in DistributiveAccessResource::ALL {
            let input = DistributiveAccessInput {
                resource,
                corpus: &[],
            };
            match score(&input) {
                ManifoldConformity::Indeterminate {
                    reason:
                        IndeterminateReason::AxisAwaitingCalibration {
                            family: AxisFamily::DistributiveAccess,
                        },
                } => (),
                other => panic!(
                    "no-calibration distributive-access must return Indeterminate \
                     {{ AxisAwaitingCalibration {{ DistributiveAccess }} }} for {resource:?}; \
                     got {other:?}"
                ),
            }
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

    fn agent(cost: f64, model: &str, n_model: u64, state: &str, role: &str, member: bool) -> Value {
        serde_json::json!({
            "cost_usd_sum": cost,
            "llm_model_counts": { model: n_model },
            "cognitive_state_dominant": state,
            "agent_role": role,
            "federation_member": member,
        })
    }

    #[test]
    fn compute_gini_above_threshold_is_numeric_concern() {
        let Some(c) = cal() else {
            eprintln!("skipping: crc-v2 bundle absent");
            return;
        };
        // Concentrated cohort: one agent holds ~all compute.
        // Gini for [0,0,0,0,100] (n=5, single holder) = (n-1)/n = 0.8 ≥ 0.169785.
        let corpus = vec![
            agent(0.0, "m", 1, "work", "scout", true),
            agent(0.0, "m", 1, "work", "scout", true),
            agent(0.0, "m", 1, "work", "scout", true),
            agent(0.0, "m", 1, "work", "scout", true),
            agent(100.0, "m", 1, "work", "scout", true),
        ];
        let input = DistributiveAccessInput {
            resource: DistributiveAccessResource::Compute,
            corpus: &corpus,
        };
        match score_calibrated(&input, &c) {
            ManifoldConformity::Numeric(s) => assert!(s < 0.0, "concentrated → concern, got {s}"),
            other => panic!("expected Numeric concern, got {other:?}"),
        }
    }

    #[test]
    fn compute_gini_below_threshold_is_conforming() {
        let Some(c) = cal() else {
            return;
        };
        // Perfectly equal compute → Gini 0 < 0.169785 → conforming (0.0).
        let corpus = vec![
            agent(10.0, "m", 1, "work", "scout", true),
            agent(10.0, "m", 1, "work", "scout", true),
            agent(10.0, "m", 1, "work", "scout", true),
        ];
        let input = DistributiveAccessInput {
            resource: DistributiveAccessResource::Compute,
            corpus: &corpus,
        };
        match score_calibrated(&input, &c) {
            ManifoldConformity::Numeric(s) => assert!(s.abs() < 1e-12, "equal → conforming 0"),
            other => panic!("expected Numeric(0), got {other:?}"),
        }
    }

    #[test]
    fn models_hhi_single_model_dominance_fires() {
        let Some(c) = cal() else {
            return;
        };
        // All agents on one model → HHI = 1.0 ≥ 1.0 threshold → concern.
        let corpus = vec![
            agent(1.0, "OnlyModel", 100, "work", "scout", true),
            agent(1.0, "OnlyModel", 200, "work", "scout", true),
        ];
        let input = DistributiveAccessInput {
            resource: DistributiveAccessResource::Models,
            corpus: &corpus,
        };
        match score_calibrated(&input, &c) {
            ManifoldConformity::Numeric(s) => {
                // models_hhi threshold == ceiling == 1.0 → pinned to s0 = -0.5.
                assert!((s - (-0.5)).abs() < 1e-9, "HHI=1 → -0.5 anchor, got {s}");
            }
            other => panic!("expected Numeric, got {other:?}"),
        }
    }

    #[test]
    fn models_hhi_two_models_conforming() {
        let Some(c) = cal() else {
            return;
        };
        // Two equal models → HHI = 0.5 < 1.0 → conforming.
        let corpus = vec![
            agent(1.0, "ModelA", 100, "work", "scout", true),
            agent(1.0, "ModelB", 100, "work", "scout", true),
        ];
        let input = DistributiveAccessInput {
            resource: DistributiveAccessResource::Models,
            corpus: &corpus,
        };
        match score_calibrated(&input, &c) {
            ManifoldConformity::Numeric(s) => assert!(s.abs() < 1e-12, "HHI 0.5 → conforming"),
            other => panic!("expected Numeric(0), got {other:?}"),
        }
    }

    #[test]
    fn federation_membership_zero_variance_zero_is_indeterminate() {
        let Some(c) = cal() else {
            return;
        };
        // All members → nonmember_frac = 0 → zero-variance fail-secure.
        let corpus = vec![
            agent(1.0, "m", 1, "work", "scout", true),
            agent(1.0, "m", 1, "work", "scout", true),
        ];
        let input = DistributiveAccessInput {
            resource: DistributiveAccessResource::FederationMembership,
            corpus: &corpus,
        };
        match score_calibrated(&input, &c) {
            ManifoldConformity::Indeterminate {
                reason: IndeterminateReason::AxisAwaitingCalibration { .. },
            } => {}
            other => panic!("all-members → Indeterminate (zero-variance), got {other:?}"),
        }
    }

    #[test]
    fn federation_membership_nonzero_deviation_fires() {
        let Some(c) = cal() else {
            return;
        };
        // One non-member → nonmember_frac = 0.5 ≥ 1e-6 sentinel → concern.
        let corpus = vec![
            agent(1.0, "m", 1, "work", "scout", true),
            agent(1.0, "m", 1, "work", "scout", false),
        ];
        let input = DistributiveAccessInput {
            resource: DistributiveAccessResource::FederationMembership,
            corpus: &corpus,
        };
        match score_calibrated(&input, &c) {
            ManifoldConformity::Numeric(s) => assert!(s < 0.0, "nonmember present → concern"),
            other => panic!("expected Numeric concern, got {other:?}"),
        }
    }

    #[test]
    fn training_data_stays_awaiting_calibration() {
        let Some(c) = cal() else {
            return;
        };
        // Tier-3 deferred: no calibrated axis in the bundle.
        let corpus = vec![agent(1.0, "m", 1, "work", "scout", true)];
        let input = DistributiveAccessInput {
            resource: DistributiveAccessResource::TrainingData,
            corpus: &corpus,
        };
        match score_calibrated(&input, &c) {
            ManifoldConformity::Indeterminate {
                reason: IndeterminateReason::AxisAwaitingCalibration { .. },
            } => {}
            other => panic!("training_data must stay AxisAwaitingCalibration, got {other:?}"),
        }
    }

    #[test]
    fn agent_capabilities_low_diversity_fires() {
        let Some(c) = cal() else {
            return;
        };
        // cap_diversity threshold ≤ 0.037088 (positive_when_distributed:
        // LOW diversity is the concern). Build a large cohort with a
        // single (state,role) tuple → diversity = 1/N. Need N ≥ 27 for
        // 1/N ≤ 0.037088.
        let corpus: Vec<Value> = (0..30)
            .map(|_| agent(1.0, "m", 1, "work", "scout", true))
            .collect();
        let input = DistributiveAccessInput {
            resource: DistributiveAccessResource::AgentCapabilities,
            corpus: &corpus,
        };
        // diversity = 1/30 ≈ 0.0333 ≤ 0.037088 → concern.
        match score_calibrated(&input, &c) {
            ManifoldConformity::Numeric(s) => assert!(s < 0.0, "low diversity → concern, got {s}"),
            other => panic!("expected Numeric concern, got {other:?}"),
        }
    }
}
