//! [`CapacityFactors`] and the [`CapacityFactors::composite`]
//! product — CEG §5.5.4's `𝒞_CIRIS = C · I_int · R · I_inc · S`.
//!
//! Lens-core ships the five-factor *product*; RATCHET's calibration
//! package supplies the per-factor *derivation* (which trace
//! signals roll up into each factor, what the cohort-relative
//! anchors are). v0.4 lands the typed product so consumers can
//! already build against the shape; v0.5+ wires the derivation.
//!
//! # Why a typed `CapacityFactors` and not just five `f64`s
//!
//! Because mixing them up at a call site (passing `integrity` where
//! `resilience` was expected) silently produces a wrong composite
//! that's still a well-formed number — exactly the kind of bug the
//! type system should catch. Same load-bearing-invariants-as-types
//! posture that [`CapacityAttestation`](super::CapacityAttestation)
//! takes for §7.5 anti-Goodhart and that
//! [`MetaGoalAlignment`](crate::wire::MetaGoalAlignment) takes for
//! M-1.

use serde::{Deserialize, Serialize};

/// The five Capacity-Score factors named in CEG §5.5.4. Each is a
/// score in `[0.0, 1.0]`; the federation-signed composite is the
/// product. Construct via [`CapacityFactors::new`] for range
/// validation; raw fields are accessible for serde and for
/// constructors that have already validated upstream.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct CapacityFactors {
    /// **C — core_identity.** Cross-context identity coherence:
    /// the agent presents the same identity under different
    /// adversarial framings (CEG §5.5.4.C).
    pub core_identity: f64,

    /// **I_int — integrity.** Per-action ethical-review compliance:
    /// PDMA + OptimizationVetoConscience pass-rate, override
    /// remediation, conscience-result temporal stability (CEG §5.5.4.I).
    pub integrity: f64,

    /// **R — resilience.** Recovery from perturbation: drift
    /// magnitude after attempted attractor capture, time-to-baseline
    /// after a refusal, conscience-override duration (CEG §5.5.4.R).
    pub resilience: f64,

    /// **I_inc — incompleteness_awareness.** Calibration of
    /// epistemic humility: explicit `Indeterminate` rate when
    /// evidence is thin, refusal-to-overclaim under uncertainty
    /// (CEG §5.5.4.I_inc).
    pub incompleteness_awareness: f64,

    /// **S — sustained_coherence.** Long-window N_eff +
    /// manifold-conformity stability: the agent's reasoning stays
    /// inside the cohort manifold across the calibration window
    /// (CEG §5.5.4.S).
    pub sustained_coherence: f64,
}

impl CapacityFactors {
    /// Construct factors with range validation. Each must be in
    /// `[0.0, 1.0]` and finite (no NaN, no Infinity).
    pub fn new(
        core_identity: f64,
        integrity: f64,
        resilience: f64,
        incompleteness_awareness: f64,
        sustained_coherence: f64,
    ) -> Result<Self, CapacityFactorError> {
        Self::validate("core_identity", core_identity)?;
        Self::validate("integrity", integrity)?;
        Self::validate("resilience", resilience)?;
        Self::validate("incompleteness_awareness", incompleteness_awareness)?;
        Self::validate("sustained_coherence", sustained_coherence)?;
        Ok(Self {
            core_identity,
            integrity,
            resilience,
            incompleteness_awareness,
            sustained_coherence,
        })
    }

    fn validate(name: &'static str, v: f64) -> Result<(), CapacityFactorError> {
        if !v.is_finite() {
            return Err(CapacityFactorError::NotFinite {
                factor: name,
                value: v,
            });
        }
        if !(0.0..=1.0).contains(&v) {
            return Err(CapacityFactorError::OutOfRange {
                factor: name,
                value: v,
            });
        }
        Ok(())
    }

    /// **𝒞_CIRIS = C · I_int · R · I_inc · S** (CEG §5.5.4).
    ///
    /// Multiplicative composite: any factor at zero produces a zero
    /// composite. This is the federation's stated design — a single
    /// failed dimension can't be averaged away. Forces all five to
    /// be operationally meaningful.
    pub fn composite(&self) -> f64 {
        self.core_identity
            * self.integrity
            * self.resilience
            * self.incompleteness_awareness
            * self.sustained_coherence
    }
}

// Deserialize re-validates the range invariant on incoming wire
// bytes — same posture as `CapacityAttestation`.
impl<'de> Deserialize<'de> for CapacityFactors {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Shadow {
            core_identity: f64,
            integrity: f64,
            resilience: f64,
            incompleteness_awareness: f64,
            sustained_coherence: f64,
        }
        let s = Shadow::deserialize(deserializer)?;
        Self::new(
            s.core_identity,
            s.integrity,
            s.resilience,
            s.incompleteness_awareness,
            s.sustained_coherence,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Failures from [`CapacityFactors::new`] (and the equivalent serde
/// re-validation path).
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CapacityFactorError {
    /// A factor was outside `[0.0, 1.0]`. Capacity factors are
    /// proportional scores; values outside that range have no
    /// CEG-defined meaning.
    #[error("{factor} = {value} is outside [0.0, 1.0]")]
    OutOfRange { factor: &'static str, value: f64 },

    /// A factor was NaN or ±Infinity. Composite multiplication
    /// would propagate NaN silently — reject at construction.
    #[error("{factor} = {value} is not finite")]
    NotFinite { factor: &'static str, value: f64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 1e-12;

    #[test]
    fn all_ones_composite_is_one() {
        let f = CapacityFactors::new(1.0, 1.0, 1.0, 1.0, 1.0).unwrap();
        assert!((f.composite() - 1.0).abs() < EPS);
    }

    #[test]
    fn all_zeros_composite_is_zero() {
        let f = CapacityFactors::new(0.0, 0.0, 0.0, 0.0, 0.0).unwrap();
        assert_eq!(f.composite(), 0.0);
    }

    #[test]
    fn any_zero_zeros_composite_per_ceg_design() {
        // CEG §5.5.4: multiplicative composite means a single failed
        // dimension can't be averaged away. Test each of the five
        // positions to lock the property.
        for i in 0..5 {
            let mut v = [0.9, 0.9, 0.9, 0.9, 0.9];
            v[i] = 0.0;
            let f = CapacityFactors::new(v[0], v[1], v[2], v[3], v[4]).unwrap();
            assert_eq!(
                f.composite(),
                0.0,
                "zero in factor {i} must zero the composite"
            );
        }
    }

    #[test]
    fn mid_range_composite_matches_product() {
        let f = CapacityFactors::new(0.9, 0.8, 0.7, 0.6, 0.5).unwrap();
        let expected = 0.9 * 0.8 * 0.7 * 0.6 * 0.5; // 0.1512
        assert!((f.composite() - expected).abs() < EPS);
    }

    #[test]
    fn composite_monotonic_in_each_factor() {
        // Raising any factor (others fixed) must raise the composite
        // monotonically. Locks "any factor matters" against accidental
        // averaging refactors.
        let baseline = CapacityFactors::new(0.5, 0.5, 0.5, 0.5, 0.5).unwrap();
        let bumps = [
            CapacityFactors::new(0.6, 0.5, 0.5, 0.5, 0.5).unwrap(),
            CapacityFactors::new(0.5, 0.6, 0.5, 0.5, 0.5).unwrap(),
            CapacityFactors::new(0.5, 0.5, 0.6, 0.5, 0.5).unwrap(),
            CapacityFactors::new(0.5, 0.5, 0.5, 0.6, 0.5).unwrap(),
            CapacityFactors::new(0.5, 0.5, 0.5, 0.5, 0.6).unwrap(),
        ];
        for bumped in bumps.iter() {
            assert!(bumped.composite() > baseline.composite());
        }
    }

    #[test]
    fn out_of_range_rejected_above_one() {
        let err = CapacityFactors::new(1.1, 0.5, 0.5, 0.5, 0.5).unwrap_err();
        assert!(matches!(
            err,
            CapacityFactorError::OutOfRange {
                factor: "core_identity",
                ..
            }
        ));
    }

    #[test]
    fn out_of_range_rejected_below_zero() {
        let err = CapacityFactors::new(0.5, -0.01, 0.5, 0.5, 0.5).unwrap_err();
        assert!(matches!(
            err,
            CapacityFactorError::OutOfRange {
                factor: "integrity",
                ..
            }
        ));
    }

    #[test]
    fn nan_rejected() {
        let err = CapacityFactors::new(0.5, 0.5, f64::NAN, 0.5, 0.5).unwrap_err();
        assert!(matches!(
            err,
            CapacityFactorError::NotFinite {
                factor: "resilience",
                ..
            }
        ));
    }

    #[test]
    fn infinity_rejected() {
        let err = CapacityFactors::new(0.5, 0.5, 0.5, f64::INFINITY, 0.5).unwrap_err();
        assert!(matches!(
            err,
            CapacityFactorError::NotFinite {
                factor: "incompleteness_awareness",
                ..
            }
        ));
    }

    #[test]
    fn serde_roundtrip_in_range() {
        let f = CapacityFactors::new(0.9, 0.8, 0.7, 0.6, 0.5).unwrap();
        let json = serde_json::to_string(&f).unwrap();
        let back: CapacityFactors = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn deserialize_rejects_out_of_range_on_the_wire() {
        // Peer hand-crafting wire bytes with a 1.5 factor can't slip
        // past the type — the Deserialize impl re-asserts the
        // construction-time range check.
        let bad = r#"{
            "core_identity": 0.9,
            "integrity": 1.5,
            "resilience": 0.9,
            "incompleteness_awareness": 0.9,
            "sustained_coherence": 0.9
        }"#;
        let result: Result<CapacityFactors, _> = serde_json::from_str(bad);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("integrity"),
            "diagnostic must name the bad factor: {msg}"
        );
    }

    #[test]
    fn boundary_values_accepted() {
        // Exactly 0.0 and exactly 1.0 are valid — they're the
        // limits of the operational range, not outside it.
        assert!(CapacityFactors::new(0.0, 1.0, 0.5, 1.0, 0.0).is_ok());
    }
}
