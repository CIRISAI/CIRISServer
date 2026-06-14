//! [`CoherenceRatchetDetector`] — the closed enum for CEG §5.5.1's
//! five Coherence-Ratchet detection dimensions.
//!
//! CEG §5.5.1 names exactly five detection dimensions that lens-core
//! owns under the Coherence-Ratchet family:
//!
//! - `detection:cross_agent_divergence`
//! - `detection:intra_agent_consistency`
//! - `detection:hash_chain_integrity`
//! - `detection:temporal_drift`
//! - `detection:conscience_override_rate`
//!
//! These ARE the dimension labels that appear on signed
//! [`DetectionEvent`](ciris_persist::prelude::DetectionEvent) rows
//! lens-core emits — federation-stable wire vocabulary. Adding a
//! variant is a semver-minor substrate operation; renaming or
//! removing one is a substrate-MAJOR break.
//!
//! Closed enum (not free-text `String`) per the same posture
//! [`M1Dimension`](crate::wire::M1Dimension),
//! [`CapacityAttestation`](crate::capacity::CapacityAttestation),
//! and [`CapacityFactors`](crate::capacity::CapacityFactors) take:
//! forces the emitter to pick from the named taxonomy rather than
//! slap arbitrary detector names that route around the framework
//! (CEG §11.2.1 axis-vocabulary discipline).

use serde::{Deserialize, Serialize};

/// The five Coherence-Ratchet detection dimensions (CEG §5.5.1).
/// Each variant carries the wire-stable `detection:*` dimension
/// label via [`Self::dimension_label`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CoherenceRatchetDetector {
    /// **§5.5.1.a `detection:cross_agent_divergence`.**
    /// Detects when an agent's reasoning trajectory diverges from
    /// the cohort manifold relative to other co-cohort members on
    /// the same kind of prompt. The signed detection event carries
    /// the divergence metric + the cohort baseline + the calibration
    /// version.
    CrossAgentDivergence,

    /// **§5.5.1.b `detection:intra_agent_consistency`.**
    /// Detects when the same agent reasons differently across
    /// adversarial framings of the same underlying question
    /// (translation, frame-shift, repeated re-prompting).
    IntraAgentConsistency,

    /// **§5.5.1.c `detection:hash_chain_integrity`.**
    /// Detects audit-log hash-chain breaks — gaps, replays,
    /// signature failures on prior entries. Federation evidence
    /// for tampering or substrate corruption.
    HashChainIntegrity,

    /// **§5.5.1.d `detection:temporal_drift`.**
    /// Detects shift in the agent's reasoning distribution over
    /// time relative to its own calibration baseline. The signal
    /// for slow-attractor capture that a single-frame detector
    /// would miss.
    TemporalDrift,

    /// **§5.5.1.e `detection:conscience_override_rate`.**
    /// Detects elevated `ConscienceResult` override frequency
    /// (conscience triggering on inputs that historically passed),
    /// or the inverse (conscience never triggering when it
    /// historically did). Either polarity is evidence of drift in
    /// the conscience policy or in the agent's reasoning pattern.
    ConscienceOverrideRate,
}

impl CoherenceRatchetDetector {
    /// The wire-stable `detection:*` dimension label this detector
    /// emits on signed evidence. Federation peers join detection
    /// events on this exact string — a rename is a substrate-MAJOR
    /// break. The `wire_label_exactness` test (below) is the
    /// drift-protection.
    pub const fn dimension_label(&self) -> &'static str {
        match self {
            Self::CrossAgentDivergence => "detection:cross_agent_divergence",
            Self::IntraAgentConsistency => "detection:intra_agent_consistency",
            Self::HashChainIntegrity => "detection:hash_chain_integrity",
            Self::TemporalDrift => "detection:temporal_drift",
            Self::ConscienceOverrideRate => "detection:conscience_override_rate",
        }
    }

    /// All five detectors. Iteration order matches CEG §5.5.1's
    /// listing order (a/b/c/d/e). Useful for fan-out (apply every
    /// detector to a trace) and for documentation generators.
    pub const ALL: [Self; 5] = [
        Self::CrossAgentDivergence,
        Self::IntraAgentConsistency,
        Self::HashChainIntegrity,
        Self::TemporalDrift,
        Self::ConscienceOverrideRate,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Wire-label exactness.** These strings are federation-stable
    /// vocabulary — peers join detection events on them. A rename
    /// here is a substrate-MAJOR break and this test must fail with
    /// a precise diff so the breakage is caught at PR time.
    #[test]
    fn wire_label_exactness() {
        assert_eq!(
            CoherenceRatchetDetector::CrossAgentDivergence.dimension_label(),
            "detection:cross_agent_divergence",
        );
        assert_eq!(
            CoherenceRatchetDetector::IntraAgentConsistency.dimension_label(),
            "detection:intra_agent_consistency",
        );
        assert_eq!(
            CoherenceRatchetDetector::HashChainIntegrity.dimension_label(),
            "detection:hash_chain_integrity",
        );
        assert_eq!(
            CoherenceRatchetDetector::TemporalDrift.dimension_label(),
            "detection:temporal_drift",
        );
        assert_eq!(
            CoherenceRatchetDetector::ConscienceOverrideRate.dimension_label(),
            "detection:conscience_override_rate",
        );
    }

    #[test]
    fn all_contains_each_variant_exactly_once() {
        let labels: std::collections::HashSet<_> = CoherenceRatchetDetector::ALL
            .iter()
            .map(|d| d.dimension_label())
            .collect();
        assert_eq!(
            labels.len(),
            5,
            "ALL must contain each variant exactly once"
        );
    }

    #[test]
    fn all_iteration_order_matches_ceg_5_5_1() {
        // CEG §5.5.1 lists the five in this order. The `ALL`
        // constant must preserve it — operator-facing docs and
        // fan-out cadence depend on the stable order.
        assert_eq!(
            CoherenceRatchetDetector::ALL,
            [
                CoherenceRatchetDetector::CrossAgentDivergence,
                CoherenceRatchetDetector::IntraAgentConsistency,
                CoherenceRatchetDetector::HashChainIntegrity,
                CoherenceRatchetDetector::TemporalDrift,
                CoherenceRatchetDetector::ConscienceOverrideRate,
            ],
        );
    }

    #[test]
    fn serde_uses_snake_case() {
        // Variants serialize as snake_case — matches persist's
        // schema-wide serde convention. NOT the same as
        // `dimension_label()` (which carries the `detection:` prefix
        // for the wire). The serde form is for storing the variant
        // discriminant; `dimension_label()` is for emitting on the
        // signed evidence row's `detector` / `dimension` column.
        let v = CoherenceRatchetDetector::CrossAgentDivergence;
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, r#""cross_agent_divergence""#);
    }

    #[test]
    fn serde_roundtrip_each_variant() {
        for v in CoherenceRatchetDetector::ALL {
            let json = serde_json::to_string(&v).unwrap();
            let back: CoherenceRatchetDetector = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn dimension_label_starts_with_detection_prefix() {
        // CEG §5.5 names every Coherence-Ratchet dimension as
        // `detection:*`. Lock the prefix so a variant added with a
        // different prefix (e.g. `capacity:*` or `cohort:*`) gets
        // caught at PR time — prefix shadowing is the CEG §7.4
        // detector-only-emission invariant.
        for v in CoherenceRatchetDetector::ALL {
            assert!(
                v.dimension_label().starts_with("detection:"),
                "{:?} dimension label `{}` must start with `detection:`",
                v,
                v.dimension_label(),
            );
        }
    }
}
