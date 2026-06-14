//! 16-feature CRC projection function — maps a typed [`Features`]
//! struct to the fixed-shape numeric input for manifold-conformity
//! scoring against RATCHET-calibrated cohort centroids.
//!
//! # Projection v1 spec
//!
//! Locked per CIRISLensCore#3 (RATCHET-confirmed 2026-05-04):
//!
//! - 10 floats + 6 bools = 16 scalars
//! - bool → f64 (`0.0` / `1.0`)
//! - null / missing / wrong-type → [`f64::NAN`]
//! - Fixed canonical order (do NOT reorder; [`PROJECTION_VERSION`]
//!   bump required if the order or set changes, which invalidates
//!   any centroids RATCHET calibrated against the prior version —
//!   see CIRISPersist#18 `calibration_bundles.projection_version`)
//!
//! # Source data
//!
//! Reads per-event_type JSON blobs from [`Features::component_blobs`]
//! (lowercase snake_case keys per persist's `blob_key_for`). Field
//! paths match the `cirislens.trace_events.payload` JSONB column
//! shape per RATCHET 2026-05-04 + CIRISPersist
//! `PUBLIC_SCHEMA_CONTRACT.md` @ v0.3.2.
//!
//! # Known semantic gap — CONSCIENCE_RESULT first-wins vs last-wins
//!
//! Persist's `extract_features` (v0.6.0) stores the **first** observed
//! `CONSCIENCE_RESULT` blob per trace (`or_insert_with` semantics).
//! RATCHET's projection v1 spec requires the **last** `CONSCIENCE_RESULT`
//! (FINALIZE_ACTION emission, post-bounce stable state). For traces
//! without conscience overrides, first == last and the value is
//! correct. For traces with PDMA bounces (4× on Tiananmen-class
//! prompts per CIRIS-RED MISSION) the conscience snapshot lens-core
//! reads is the initial pass, not the post-bounce final pass.
//!
//! This [`project`] function's *shape* is correct against RATCHET's
//! spec; the underlying *value correctness* on bouncing traces
//! depends on persist updating its extraction semantics. Tracked as
//! a follow-up to CIRISPersist#19; not a blocker for the manifold
//! scoring scaffold lens-core builds on top of `project`.

use serde_json::Value;

use super::Features;

/// Calibration-version anchor. Bumped whenever the projection's
/// feature set or order changes — invalidates RATCHET centroids
/// computed against the prior version. See CIRISLensCore#3 + the
/// `projection_version` column on CIRISPersist's `calibration_bundles`
/// table.
pub const PROJECTION_VERSION: &str = "crc-v1";

/// Output dimensionality. Anchored to [`PROJECTION_VERSION`].
pub const PROJECTION_DIM: usize = 16;

/// Map a typed [`Features`] to a fixed-shape 16-element numeric
/// vector for Mahalanobis distance against RATCHET-calibrated
/// cohort centroids.
///
/// Pure function. No I/O, no allocation beyond the returned array,
/// no error path. Wrong-type / missing fields emit [`f64::NAN`]
/// rather than erroring — calibration handles NaN imputation per
/// the [`projection_metadata.imputation`] field RATCHET publishes
/// alongside centroids.
///
/// [`projection_metadata.imputation`]: https://github.com/CIRISAI/CIRISPersist/issues/18
pub fn project(features: &Features) -> [f64; PROJECTION_DIM] {
    let dma = features.component_blobs.get("dma_results");
    let idma = features.component_blobs.get("idma_result");
    let conscience = features.component_blobs.get("conscience_result");

    [
        f64_at(dma, &["csdma", "plausibility_score"]),
        f64_at(dma, &["dsdma", "domain_alignment"]),
        f64_at(conscience, &["coherence_level"]),
        f64_at(conscience, &["entropy_level"]),
        f64_at(idma, &["k_eff"]),
        f64_at(idma, &["correlation_risk"]),
        f64_at(conscience, &["entropy_score"]),
        f64_at(conscience, &["coherence_score"]),
        f64_at(conscience, &["optimization_veto_entropy_ratio"]),
        f64_at(conscience, &["epistemic_humility_certainty"]),
        bool_at(conscience, &["conscience_passed"]),
        bool_at(conscience, &["entropy_passed"]),
        bool_at(conscience, &["coherence_passed"]),
        bool_at(conscience, &["optimization_veto_passed"]),
        bool_at(conscience, &["epistemic_humility_passed"]),
        bool_at(conscience, &["action_was_overridden"]),
    ]
}

fn f64_at(blob: Option<&Value>, path: &[&str]) -> f64 {
    descend(blob, path)
        .and_then(Value::as_f64)
        .unwrap_or(f64::NAN)
}

fn bool_at(blob: Option<&Value>, path: &[&str]) -> f64 {
    descend(blob, path)
        .and_then(Value::as_bool)
        .map(|b| if b { 1.0 } else { 0.0 })
        .unwrap_or(f64::NAN)
}

fn descend<'a>(blob: Option<&'a Value>, path: &[&str]) -> Option<&'a Value> {
    let mut cursor = blob?;
    for key in path {
        cursor = cursor.get(*key)?;
    }
    Some(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
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
    fn projection_version_locked() {
        assert_eq!(PROJECTION_VERSION, "crc-v1");
        assert_eq!(PROJECTION_DIM, 16);
    }

    #[test]
    fn empty_features_yield_all_nan() {
        let v = project(&empty_features());
        for (i, x) in v.iter().enumerate() {
            assert!(x.is_nan(), "field {i} should be NaN, got {x}");
        }
    }

    #[test]
    fn full_trace_extracts_all_16_in_canonical_order() {
        let mut f = empty_features();
        f.component_blobs.insert(
            "dma_results".into(),
            json!({
                "csdma": { "plausibility_score": 0.873 },
                "dsdma": { "domain_alignment": 0.812 },
            }),
        );
        f.component_blobs.insert(
            "idma_result".into(),
            json!({ "k_eff": 2.5, "correlation_risk": 0.18 }),
        );
        f.component_blobs.insert(
            "conscience_result".into(),
            json!({
                "coherence_level": 0.92,
                "entropy_level": 0.41,
                "entropy_score": 0.7,
                "coherence_score": 0.85,
                "optimization_veto_entropy_ratio": 0.55,
                "epistemic_humility_certainty": 0.78,
                "conscience_passed": true,
                "entropy_passed": true,
                "coherence_passed": true,
                "optimization_veto_passed": false,
                "epistemic_humility_passed": true,
                "action_was_overridden": false,
            }),
        );

        let v = project(&f);

        assert_eq!(v[0], 0.873); //  1. csdma_plausibility_score
        assert_eq!(v[1], 0.812); //  2. dsdma_domain_alignment
        assert_eq!(v[2], 0.92); //  3. coherence_level
        assert_eq!(v[3], 0.41); //  4. entropy_level
        assert_eq!(v[4], 2.5); //  5. idma_k_eff
        assert_eq!(v[5], 0.18); //  6. idma_correlation_risk
        assert_eq!(v[6], 0.7); //  7. entropy_score
        assert_eq!(v[7], 0.85); //  8. coherence_score
        assert_eq!(v[8], 0.55); //  9. optimization_veto_entropy_ratio
        assert_eq!(v[9], 0.78); // 10. epistemic_humility_certainty
        assert_eq!(v[10], 1.0); // 11. conscience_passed
        assert_eq!(v[11], 1.0); // 12. entropy_passed
        assert_eq!(v[12], 1.0); // 13. coherence_passed
        assert_eq!(v[13], 0.0); // 14. optimization_veto_passed
        assert_eq!(v[14], 1.0); // 15. epistemic_humility_passed
        assert_eq!(v[15], 0.0); // 16. action_was_overridden
    }

    #[test]
    fn conditional_fields_emit_nan_when_absent() {
        // Conscience-gated fields (7-10, 12-15) fire only when the
        // conscience check is triggered. When absent, project emits
        // NaN. RATCHET's calibration bundle provides per-field
        // imputation means to fill at scoring time.
        let mut f = empty_features();
        f.component_blobs.insert(
            "conscience_result".into(),
            json!({
                "coherence_level": 0.9,
                "entropy_level": 0.4,
                "conscience_passed": true,
                "action_was_overridden": false,
            }),
        );

        let v = project(&f);

        assert_eq!(v[2], 0.9);
        assert_eq!(v[3], 0.4);
        assert_eq!(v[10], 1.0);
        assert_eq!(v[15], 0.0);

        for i in [6, 7, 8, 9, 11, 12, 13, 14] {
            assert!(v[i].is_nan(), "conditional field {i} should be NaN");
        }
    }

    #[test]
    fn wrong_type_yields_nan_not_panic() {
        // Field present but wrong-typed (e.g. legacy wire shape had
        // `correlation_risk` as a categorical string before persist's
        // PUBLIC_SCHEMA_CONTRACT normalization). project emits NaN
        // rather than panicking — fail-secure per LC-AV-18.
        let mut f = empty_features();
        f.component_blobs.insert(
            "idma_result".into(),
            json!({ "k_eff": "wrong-type", "correlation_risk": "low" }),
        );

        let v = project(&f);
        assert!(v[4].is_nan());
        assert!(v[5].is_nan());
    }

    #[test]
    fn integer_values_coerce_to_f64() {
        // serde_json's as_f64 handles integer-typed JSON numbers
        // transparently (idma.k_eff sometimes ships as int 3 vs
        // float 3.0 depending on agent).
        let mut f = empty_features();
        f.component_blobs.insert(
            "idma_result".into(),
            json!({ "k_eff": 3, "correlation_risk": 0 }),
        );

        let v = project(&f);
        assert_eq!(v[4], 3.0);
        assert_eq!(v[5], 0.0);
    }
}
