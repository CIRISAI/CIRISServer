//! Manifold-conformity scorer — Phase 2 Mahalanobis implementation.
//!
//! # What this module does
//!
//! Computes a **squared Mahalanobis distance** of a standardized
//! feature vector `x` against a cohort centroid `μ` using the
//! cohort's per-feature variances as the diagonal precision matrix
//! `Σ⁻¹`:
//!
//! ```text
//! d²  = (x − μ)ᵀ Σ⁻¹ (x − μ)
//!     = Σᵢ (x_std_i − μᵢ)² / varᵢ
//!
//! d_σ = √d²        (Mahalanobis in σ-units)
//! ```
//!
//! The input vector `x_raw` (16 floats from
//! [`crate::extract::projection::project`]) must be **standardized
//! then retention-masked** before the distance is computed. Both
//! transforms are carried in [`crate::scoring::CalibrationBundle`]'s
//! `projection` field; [`score_mahalanobis`] performs them
//! internally so callers don't have to.
//!
//! # `crc-v1` covariance model
//!
//! The shipped `bundle.yaml` carries a *diagonal*-only covariance per
//! cohort (`CohortCentroid.variance: Vec<f64>`, length = retained
//! dimension count = 14 for `crc-v1`). The off-diagonal entries are
//! zero; the diagonal Σ⁻¹ is simply `1.0 / var_i`. A full
//! covariance / precision matrix is a v0.2+ option per the bundle
//! notes; this module implements the diagonal path only and would
//! need to be extended (Cholesky factorisation of a packed upper
//! triangle) when a full precision matrix arrives.
//!
//! # Fail-secure discipline (LC-AV-18 / MISSION LC-AV-11)
//!
//! | Condition | Output |
//! |-----------|--------|
//! | Sample count below gate | caller routes `BundleSampleBelowGate`; this fn is not called |
//! | NaN in standardized/retained vector | `Unavailable { DegenerateCovariance }` |
//! | Any `var_i ≤ 0` | `Unavailable { DegenerateCovariance }` |
//! | `d²` overflows to infinity | `Unavailable { DegenerateCovariance }` |
//! | All guards pass | `DetectionResult::Manifold { mahalanobis: d_σ, cohort_sample_count }` |
//!
//! The `Indeterminate { CohortColdStart }` / `Indeterminate { SampleSizeBelowGate }`
//! branches are handled upstream (in `pipeline/lifecycle.rs`'s
//! `assembly_input_from_bundle`); this module only runs when the
//! bundle + centroid lookup already succeeded and the sample gate
//! was satisfied by the caller.

use crate::detector::DetectionResult;
use crate::extract::projection::PROJECTION_DIM;
use crate::scoring::calibration::{CalibrationBundle, CohortCentroid};
use crate::scoring::result::UnavailableReason;

/// Outcome of the Mahalanobis scoring step — either a valid distance
/// or an `Unavailable` reason that the caller should propagate.
#[derive(Debug)]
pub enum ManifoldScoreOutcome {
    /// Scoring succeeded.
    Distance {
        /// Mahalanobis distance in σ-units: `√d²`.
        d_sigma: f64,
    },
    /// Scoring failed due to a degenerate covariance or NaN input.
    /// Caller should produce `ManifoldConformity::Unavailable`.
    Unavailable(UnavailableReason),
}

/// Standardize a raw 16-vector using the bundle's per-feature means
/// and stds, then apply the retention mask and return the retained
/// sub-vector.
///
/// Returns `None` if any retained element is NaN after imputation
/// or if standardization produced NaN (std ≤ 0 causes NaN / Inf).
///
/// # NaN imputation
///
/// For each position in the raw vector, if the value is NaN, the
/// bundle's `projection.imputation` map provides the corpus-mean
/// fill-in. The imputation key is `projection.field_order[i]`.
/// After imputation, the standardized form `(x_i − mean_i) / std_i`
/// is computed.
///
/// This function does NOT silently propagate NaN: if after imputation
/// any retained element is still NaN (e.g. std_i == 0.0 so division
/// gives NaN/Inf, or imputation itself was NaN), it returns `None` so
/// the caller emits `Unavailable { DegenerateCovariance }`.
pub fn standardize_and_retain(
    raw: &[f64; PROJECTION_DIM],
    bundle: &CalibrationBundle,
) -> Option<Vec<f64>> {
    let proj = &bundle.projection;
    let means = &proj.standardization.means;
    let stds = &proj.standardization.stds;
    let mask = &proj.retention_mask;
    let field_order = &proj.field_order;
    let imputation = &proj.imputation;

    // All length invariants were verified by CalibrationBundle::validate().
    debug_assert_eq!(means.len(), PROJECTION_DIM);
    debug_assert_eq!(stds.len(), PROJECTION_DIM);
    debug_assert_eq!(mask.len(), PROJECTION_DIM);

    let mut retained = Vec::with_capacity(mask.iter().filter(|&&b| b).count());

    for i in 0..PROJECTION_DIM {
        if !mask[i] {
            continue; // Dropped by retention mask.
        }

        // Step 1: Impute NaN → corpus mean.
        let raw_val = if raw[i].is_nan() {
            let field_name = &field_order[i];
            *imputation.get(field_name.as_str()).unwrap_or(&f64::NAN)
        } else {
            raw[i]
        };

        // Step 2: Standardize.
        let std_i = stds[i];
        if std_i <= 0.0 || std_i.is_nan() {
            // Std of zero or negative means this field was constant in
            // the calibration corpus. The retention mask should have
            // dropped it (that's how crc-v1 dropped idma_k_eff and
            // epistemic_humility_passed), but if somehow it slipped
            // through, we can't divide → degenerate.
            return None;
        }
        let z = (raw_val - means[i]) / std_i;

        if !z.is_finite() {
            return None;
        }
        retained.push(z);
    }

    Some(retained)
}

/// Compute the squared Mahalanobis distance between a standardized
/// retained vector and a cohort centroid using the diagonal precision
/// matrix implied by `CohortCentroid.variance`.
///
/// # Arguments
///
/// * `x_std` — standardized, retention-masked feature vector (length
///   `D = retention_mask.retained_count`).
/// * `centroid` — matched `CohortCentroid` from the calibration bundle.
///
/// # Returns
///
/// `Some(d²)` when all variance entries are positive and no NaN is
/// encountered. `None` for any non-PD (var ≤ 0) or NaN element.
pub fn mahalanobis_sq(x_std: &[f64], centroid: &CohortCentroid) -> Option<f64> {
    debug_assert_eq!(x_std.len(), centroid.centroid.len());
    debug_assert_eq!(x_std.len(), centroid.variance.len());

    let mut d_sq = 0.0_f64;
    for ((x, mu), var_i) in x_std
        .iter()
        .zip(centroid.centroid.iter())
        .zip(centroid.variance.iter())
    {
        if *var_i <= 0.0 || var_i.is_nan() {
            // Non-positive-definite diagonal entry → not invertible.
            return None;
        }
        let diff = x - mu;
        d_sq += (diff * diff) / var_i;
    }

    if !d_sq.is_finite() {
        return None;
    }
    Some(d_sq)
}

/// End-to-end manifold conformity score: project raw features →
/// standardize+retain → Mahalanobis distance → `ManifoldScoreOutcome`.
///
/// The full pipeline:
///
/// 1. Standardize+impute the raw 16-vector using the bundle's means,
///    stds, and imputation map.
/// 2. Apply the retention mask (drops the 2 features with zero std in
///    `crc-v1`).
/// 3. Compute `d² = Σᵢ (x_std_i − μᵢ)² / varᵢ` (diagonal Σ⁻¹).
/// 4. Return `d_σ = √d²` in σ-units.
///
/// Any NaN in retained features, any non-positive variance, or any
/// overflow returns `Unavailable { DegenerateCovariance }`.
///
/// # Arguments
///
/// * `raw` — the 16-element raw projection vector (from
///   [`crate::extract::projection::project`]).
/// * `bundle` — the hydrated calibration bundle.
/// * `centroid` — the cohort centroid matched for this trace.
pub fn score_mahalanobis(
    raw: &[f64; PROJECTION_DIM],
    bundle: &CalibrationBundle,
    centroid: &CohortCentroid,
) -> ManifoldScoreOutcome {
    let x_std = match standardize_and_retain(raw, bundle) {
        Some(v) => v,
        None => {
            return ManifoldScoreOutcome::Unavailable(UnavailableReason::DegenerateCovariance);
        }
    };

    match mahalanobis_sq(&x_std, centroid) {
        Some(d_sq) => ManifoldScoreOutcome::Distance {
            d_sigma: d_sq.sqrt(),
        },
        None => ManifoldScoreOutcome::Unavailable(UnavailableReason::DegenerateCovariance),
    }
}

/// Convenience wrapper: run the full manifold detector against a
/// bundle + cohort centroid, returning a `DetectionResult` ready for
/// the lifecycle assembly step.
///
/// Returns `DetectionResult::Manifold` on success, or callers must
/// handle `ManifoldScoreOutcome::Unavailable` to produce a
/// `ManifoldConformity::Unavailable` upstream.
pub fn detect_manifold(
    raw: &[f64; PROJECTION_DIM],
    bundle: &CalibrationBundle,
    centroid: &CohortCentroid,
) -> Result<DetectionResult, UnavailableReason> {
    match score_mahalanobis(raw, bundle, centroid) {
        ManifoldScoreOutcome::Distance { d_sigma } => {
            let cohort_sample_count = u32::try_from(centroid.sample_count).unwrap_or(u32::MAX);
            Ok(DetectionResult::Manifold {
                mahalanobis: d_sigma,
                cohort_sample_count,
            })
        }
        ManifoldScoreOutcome::Unavailable(reason) => Err(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::projection::PROJECTION_DIM;
    use crate::scoring::calibration::{
        CalibrationBundle, CohortCentroid, Projection, Standardization, CRC_V1_FIELD_ORDER,
    };
    use std::collections::BTreeMap;
    use std::sync::Arc;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Minimal valid bundle for unit tests. Uses the real `crc-v1` field
    /// order / retention mask shape but with controlled standardization
    /// values (mean=0, std=1 for all retained fields) so the math is
    /// predictable.
    fn unit_bundle(
        retention_mask: Vec<bool>,
        means: Vec<f64>,
        stds: Vec<f64>,
    ) -> Arc<CalibrationBundle> {
        assert_eq!(retention_mask.len(), PROJECTION_DIM);
        assert_eq!(means.len(), PROJECTION_DIM);
        assert_eq!(stds.len(), PROJECTION_DIM);

        Arc::new(CalibrationBundle {
            ratchet_calibration_version: 1,
            projection_version: "crc-v1".into(),
            calibrated_at: None,
            sample_size_gate: 500,
            manifold_threshold_global: 2.5,
            projection: Projection {
                field_order: CRC_V1_FIELD_ORDER.iter().map(|s| s.to_string()).collect(),
                imputation: BTreeMap::new(),
                standardization: Standardization { means, stds },
                retention_mask,
            },
            cohort_centroids: vec![],
        })
    }

    /// A centroid with all-zero centroid and unit variance in `dim` dimensions.
    fn zero_centroid(dim: usize) -> CohortCentroid {
        CohortCentroid {
            cohort: serde_json::Value::Null,
            centroid: vec![0.0; dim],
            variance: vec![1.0; dim],
            sample_count: 1000,
            above_sample_size_gate: true,
        }
    }

    /// All-zero raw vector (projects to all 0.0).
    fn zero_raw() -> [f64; PROJECTION_DIM] {
        [0.0; PROJECTION_DIM]
    }

    // -----------------------------------------------------------------------
    // mahalanobis_sq unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn at_centroid_d_sq_is_zero() {
        // x == μ → d² = 0.
        let centroid = zero_centroid(3);
        let x = vec![0.0_f64, 0.0, 0.0];
        let d_sq = mahalanobis_sq(&x, &centroid).expect("should compute");
        assert!(
            (d_sq - 0.0).abs() < 1e-12,
            "d² at centroid must be 0, got {d_sq}"
        );
    }

    #[test]
    fn known_diagonal_mahalanobis() {
        // x = [1, 2, 3], μ = [0, 0, 0], Σ = diag(1, 4, 9)
        // d² = 1²/1 + 2²/4 + 3²/9 = 1 + 1 + 1 = 3
        let mut centroid = zero_centroid(3);
        centroid.variance = vec![1.0, 4.0, 9.0];
        let x = vec![1.0_f64, 2.0, 3.0];
        let d_sq = mahalanobis_sq(&x, &centroid).expect("should compute");
        assert!((d_sq - 3.0).abs() < 1e-10, "d² should be 3.0, got {d_sq}");
    }

    #[test]
    fn known_diagonal_mahalanobis_d_sigma() {
        // d² = 3 → d_σ = √3
        let mut centroid = zero_centroid(3);
        centroid.variance = vec![1.0, 4.0, 9.0];
        let x = vec![1.0_f64, 2.0, 3.0];
        let d_sq = mahalanobis_sq(&x, &centroid).expect("should compute");
        let d_sigma = d_sq.sqrt();
        assert!(
            (d_sigma - 3.0_f64.sqrt()).abs() < 1e-10,
            "d_σ should be √3, got {d_sigma}"
        );
    }

    #[test]
    fn non_pd_variance_zero_returns_none() {
        // var_i = 0 → non-positive-definite → None.
        let mut centroid = zero_centroid(2);
        centroid.variance = vec![1.0, 0.0]; // second entry is zero
        let x = vec![1.0_f64, 1.0];
        assert!(
            mahalanobis_sq(&x, &centroid).is_none(),
            "zero variance must return None"
        );
    }

    #[test]
    fn negative_variance_returns_none() {
        // var_i < 0 → non-positive-definite → None.
        let mut centroid = zero_centroid(2);
        centroid.variance = vec![1.0, -0.5];
        let x = vec![1.0_f64, 1.0];
        assert!(
            mahalanobis_sq(&x, &centroid).is_none(),
            "negative variance must return None"
        );
    }

    #[test]
    fn nan_in_x_std_produces_non_finite_and_none() {
        // NaN in x_std → NaN accumulates into d_sq → overflow check catches it.
        // (The standardize_and_retain layer should catch this before reaching here,
        // but mahalanobis_sq itself must also be robust.)
        let centroid = zero_centroid(2);
        let x = vec![f64::NAN, 1.0];
        // NaN propagates through arithmetic; the finite guard catches it.
        let result = mahalanobis_sq(&x, &centroid);
        // NaN + 1 = NaN, not finite → None.
        assert!(result.is_none(), "NaN in x_std must return None");
    }

    // -----------------------------------------------------------------------
    // standardize_and_retain tests
    // -----------------------------------------------------------------------

    #[test]
    fn standardize_identity_transform() {
        // mean=0, std=1, all retained → output == raw.
        let mask = vec![true; PROJECTION_DIM];
        let means = vec![0.0; PROJECTION_DIM];
        let stds = vec![1.0; PROJECTION_DIM];
        let bundle = unit_bundle(mask, means, stds);
        let raw = {
            let mut r = [0.0_f64; PROJECTION_DIM];
            for (i, v) in r.iter_mut().enumerate() {
                *v = i as f64;
            }
            r
        };
        let result = standardize_and_retain(&raw, &bundle).expect("should succeed");
        assert_eq!(result.len(), PROJECTION_DIM);
        for (i, &v) in result.iter().enumerate() {
            assert!(
                (v - i as f64).abs() < 1e-12,
                "identity: position {i} got {v}"
            );
        }
    }

    #[test]
    fn retention_mask_drops_correct_indices() {
        // mask = [true, false, true, ...] → output only carries positions 0, 2, ...
        let mut mask = vec![true; PROJECTION_DIM];
        mask[1] = false;
        mask[3] = false;
        let means = vec![0.0; PROJECTION_DIM];
        let stds = vec![1.0; PROJECTION_DIM];
        let bundle = unit_bundle(mask, means, stds);
        let raw = [1.0_f64; PROJECTION_DIM];
        let result = standardize_and_retain(&raw, &bundle).expect("should succeed");
        // PROJECTION_DIM - 2 retained.
        assert_eq!(result.len(), PROJECTION_DIM - 2);
    }

    #[test]
    fn nan_imputation_fills_value() {
        // raw[0] = NaN; imputation["csdma_plausibility_score"] = 0.5
        // → standardized value = (0.5 - 0.0) / 1.0 = 0.5
        let mask = vec![true; PROJECTION_DIM];
        let means = vec![0.0; PROJECTION_DIM];
        let stds = vec![1.0; PROJECTION_DIM];
        let bundle = CalibrationBundle {
            ratchet_calibration_version: 1,
            projection_version: "crc-v1".into(),
            calibrated_at: None,
            sample_size_gate: 500,
            manifold_threshold_global: 2.5,
            projection: Projection {
                field_order: CRC_V1_FIELD_ORDER.iter().map(|s| s.to_string()).collect(),
                imputation: {
                    let mut m = BTreeMap::new();
                    m.insert("csdma_plausibility_score".to_string(), 0.5);
                    m
                },
                standardization: Standardization { means, stds },
                retention_mask: mask,
            },
            cohort_centroids: vec![],
        };

        let mut raw = [1.0_f64; PROJECTION_DIM];
        raw[0] = f64::NAN; // field 0 = csdma_plausibility_score

        let result = standardize_and_retain(&raw, &Arc::new(bundle)).expect("should succeed");
        // First retained element should be imputed + standardized = (0.5 - 0.0) / 1.0 = 0.5
        assert!(
            (result[0] - 0.5).abs() < 1e-12,
            "imputed value wrong: {}",
            result[0]
        );
    }

    #[test]
    fn zero_std_in_retained_field_returns_none() {
        // std_i = 0 in a retained field → division NaN/Inf → None.
        let mask = vec![true; PROJECTION_DIM];
        let means = vec![0.0; PROJECTION_DIM];
        let mut stds = vec![1.0; PROJECTION_DIM];
        stds[0] = 0.0; // zero std in first retained field
        let bundle = unit_bundle(mask, means, stds);
        let raw = [1.0_f64; PROJECTION_DIM];
        assert!(
            standardize_and_retain(&raw, &bundle).is_none(),
            "zero std in retained field must return None"
        );
    }

    // -----------------------------------------------------------------------
    // Trichotomy integration tests (in-bundle+enough-sample → DetectionResult::Manifold,
    // cold-start → Indeterminate, degenerate → Unavailable)
    // -----------------------------------------------------------------------

    #[test]
    fn degenerate_covariance_yields_unavailable() {
        // Build a centroid with variance=0 in one dimension.
        // score_mahalanobis must return Unavailable { DegenerateCovariance }.
        let mask = vec![true; PROJECTION_DIM];
        let means = vec![0.0; PROJECTION_DIM];
        let stds = vec![1.0; PROJECTION_DIM];
        let bundle = unit_bundle(mask, means, stds);
        let dim = PROJECTION_DIM;
        let mut centroid = zero_centroid(dim);
        centroid.variance[0] = 0.0; // degenerate

        let raw = [0.5_f64; PROJECTION_DIM];
        let result = score_mahalanobis(&raw, &bundle, &centroid);
        match result {
            ManifoldScoreOutcome::Unavailable(UnavailableReason::DegenerateCovariance) => {}
            other => panic!("expected Unavailable(DegenerateCovariance), got {other:?}"),
        }
    }

    #[test]
    fn score_mahalanobis_at_centroid_yields_zero_distance() {
        // When x == μ after standardization, d_σ = 0.
        // Setup: mean=0, std=1, all retained, centroid=[0,...,0], var=[1,...,1].
        // raw = [0,...,0] → standardized = [0,...,0] → d² = 0 → d_σ = 0.
        let mask = vec![true; PROJECTION_DIM];
        let means = vec![0.0; PROJECTION_DIM];
        let stds = vec![1.0; PROJECTION_DIM];
        let bundle = unit_bundle(mask, means, stds);
        let centroid = zero_centroid(PROJECTION_DIM);
        let raw = zero_raw();

        match score_mahalanobis(&raw, &bundle, &centroid) {
            ManifoldScoreOutcome::Distance { d_sigma } => {
                assert!(
                    d_sigma.abs() < 1e-12,
                    "at-centroid d_σ must be 0, got {d_sigma}"
                );
            }
            ManifoldScoreOutcome::Unavailable(r) => {
                panic!("expected Distance, got Unavailable({r:?})")
            }
        }
    }

    #[test]
    fn score_mahalanobis_known_distance() {
        // Controlled 2D example after retention mask.
        // mask: retain only positions 0 and 1 (14 total but use a compact
        // construction where only 2 are retained).
        //
        // Use PROJECTION_DIM=16, retain only first 2, rest false.
        // mean=[0,...], std=[1,...], centroid=[1.0, 2.0], variance=[4.0, 1.0]
        // raw=[3.0, 3.0, ...rest 0...]
        // x_std[0] = (3.0-0)/1 = 3.0, x_std[1] = (3.0-0)/1 = 3.0
        // d² = (3-1)²/4 + (3-2)²/1 = 4/4 + 1/1 = 1 + 1 = 2
        // d_σ = √2

        let mut mask = vec![false; PROJECTION_DIM];
        mask[0] = true;
        mask[1] = true;
        let means = vec![0.0; PROJECTION_DIM];
        let stds = vec![1.0; PROJECTION_DIM];
        let bundle = unit_bundle(mask, means, stds);

        let centroid = CohortCentroid {
            cohort: serde_json::Value::Null,
            centroid: vec![1.0, 2.0],
            variance: vec![4.0, 1.0],
            sample_count: 1000,
            above_sample_size_gate: true,
        };

        let mut raw = [0.0_f64; PROJECTION_DIM];
        raw[0] = 3.0;
        raw[1] = 3.0;

        match score_mahalanobis(&raw, &bundle, &centroid) {
            ManifoldScoreOutcome::Distance { d_sigma } => {
                let expected = 2.0_f64.sqrt();
                assert!(
                    (d_sigma - expected).abs() < 1e-10,
                    "d_σ should be √2={expected}, got {d_sigma}"
                );
            }
            ManifoldScoreOutcome::Unavailable(r) => {
                panic!("expected Distance, got Unavailable({r:?})")
            }
        }
    }

    #[test]
    fn detect_manifold_above_gate_returns_detection_result() {
        // Full pipeline: raw → DetectionResult::Manifold.
        let mask = vec![true; PROJECTION_DIM];
        let means = vec![0.0; PROJECTION_DIM];
        let stds = vec![1.0; PROJECTION_DIM];
        let bundle = unit_bundle(mask, means, stds);
        let mut centroid = zero_centroid(PROJECTION_DIM);
        centroid.sample_count = 1000;

        let raw = zero_raw();
        match detect_manifold(&raw, &bundle, &centroid) {
            Ok(DetectionResult::Manifold {
                mahalanobis,
                cohort_sample_count,
            }) => {
                assert!(mahalanobis.abs() < 1e-12, "at-centroid d_σ must be 0");
                assert_eq!(cohort_sample_count, 1000);
            }
            Ok(other) => panic!("expected Manifold, got {other:?}"),
            Err(r) => panic!("expected Ok, got Err({r:?})"),
        }
    }

    #[test]
    fn detect_manifold_degenerate_returns_err() {
        let mask = vec![true; PROJECTION_DIM];
        let means = vec![0.0; PROJECTION_DIM];
        let stds = vec![1.0; PROJECTION_DIM];
        let bundle = unit_bundle(mask, means, stds);
        let mut centroid = zero_centroid(PROJECTION_DIM);
        centroid.variance[0] = 0.0; // degenerate

        let raw = zero_raw();
        match detect_manifold(&raw, &bundle, &centroid) {
            Err(UnavailableReason::DegenerateCovariance) => {}
            other => panic!("expected Err(DegenerateCovariance), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Integration test against the real crc-v1 bundle
    // -----------------------------------------------------------------------

    const SHIPPED_BUNDLE_PATH: &str = "/home/emoore/RATCHET/release/calibration/crc-v1/bundle.yaml";

    fn shipped_bundle() -> Option<Arc<CalibrationBundle>> {
        let yaml = std::fs::read_to_string(SHIPPED_BUNDLE_PATH).ok()?;
        CalibrationBundle::from_yaml(&yaml).ok()
    }

    #[test]
    fn crc_v1_all_null_cohort_at_centroid_yields_zero() {
        let Some(bundle) = shipped_bundle() else {
            eprintln!("skipping: {SHIPPED_BUNDLE_PATH} not present");
            return;
        };

        let all_null_key = serde_json::json!({
            "agent_role": null,
            "agent_template": null,
            "deployment_domain": null,
            "deployment_type": null,
            "deployment_region": null,
            "deployment_trust_mode": null,
        });

        let centroid = bundle
            .lookup_cohort(&all_null_key)
            .expect("all-null cohort must exist in crc-v1");

        // Build a raw vector that, after standardization + retention,
        // equals the centroid exactly.
        //
        // x_std = centroid.centroid
        // x_raw[i] = centroid[i] * std[i] + mean[i]   (for retained i)
        // For dropped fields, raw value doesn't matter (set to mean so
        // standardization is 0, though those positions are discarded).
        let proj = &bundle.projection;
        let mut raw = [0.0_f64; PROJECTION_DIM];
        let mut retained_idx = 0_usize;
        for (i, raw_i) in raw.iter_mut().enumerate() {
            if proj.retention_mask[i] {
                *raw_i = centroid.centroid[retained_idx] * proj.standardization.stds[i]
                    + proj.standardization.means[i];
                retained_idx += 1;
            } else {
                *raw_i = proj.standardization.means[i]; // maps to 0 after std, dropped anyway
            }
        }

        match score_mahalanobis(&raw, &bundle, centroid) {
            ManifoldScoreOutcome::Distance { d_sigma } => {
                assert!(
                    d_sigma.abs() < 1e-8,
                    "at-centroid distance must be ~0, got {d_sigma}"
                );
            }
            ManifoldScoreOutcome::Unavailable(r) => {
                panic!("crc-v1 all-null cohort at centroid failed: {r:?}");
            }
        }
    }

    #[test]
    fn crc_v1_known_offset_distance() {
        // Move one step away from the all-null centroid:
        // shift the first retained dimension by sqrt(variance[0])
        // → that single term contributes d²=1, so d_σ=1 (plus the
        // other terms from the centroid position itself... wait:
        // we want to start at centroid then shift).
        //
        // x_std = centroid + [√var₀, 0, 0, ...]
        // d² = (√var₀)²/var₀ + 0 + ... = 1 → d_σ = 1 (for the shift
        // contribution), but the starting point is centroid so all
        // other terms are 0. Total d_σ = 1.

        let Some(bundle) = shipped_bundle() else {
            eprintln!("skipping: {SHIPPED_BUNDLE_PATH} not present");
            return;
        };
        let all_null_key = serde_json::json!({
            "agent_role": null,
            "agent_template": null,
            "deployment_domain": null,
            "deployment_type": null,
            "deployment_region": null,
            "deployment_trust_mode": null,
        });
        let centroid = bundle
            .lookup_cohort(&all_null_key)
            .expect("all-null cohort in crc-v1");

        let proj = &bundle.projection;
        // Build raw at centroid + shift first retained dimension by +√var₀.
        let shift = centroid.variance[0].sqrt();
        let mut raw = [0.0_f64; PROJECTION_DIM];
        let mut retained_idx = 0_usize;
        for (i, raw_i) in raw.iter_mut().enumerate() {
            if proj.retention_mask[i] {
                let mut z = centroid.centroid[retained_idx];
                if retained_idx == 0 {
                    z += shift; // shift first retained dim by +1σ
                }
                *raw_i = z * proj.standardization.stds[i] + proj.standardization.means[i];
                retained_idx += 1;
            } else {
                *raw_i = proj.standardization.means[i];
            }
        }

        match score_mahalanobis(&raw, &bundle, centroid) {
            ManifoldScoreOutcome::Distance { d_sigma } => {
                // d² = (shift/√var₀)² * var₀ / var₀... Let's be precise:
                // x_std[0] = centroid[0] + shift
                // (x_std[0] - μ[0])²/var[0] = shift²/var[0] = var[0]/var[0] = 1
                // All other terms = 0 (x_std[k] = μ[k] for k>0)
                // d² = 1, d_σ = 1
                assert!(
                    (d_sigma - 1.0).abs() < 1e-8,
                    "one-sigma shift must give d_σ=1, got {d_sigma}"
                );
            }
            ManifoldScoreOutcome::Unavailable(r) => {
                panic!("crc-v1 one-sigma shift failed: {r:?}");
            }
        }
    }

    #[test]
    fn crc_v1_all_cohorts_score_without_panic() {
        // Smoke test: score a raw vector of corpus means (all-NaN → all
        // imputed → all-means → standardized-to-0) against every cohort
        // in the bundle. All are below sample_size_gate=500 so production
        // would still return Indeterminate, but the scoring math must not
        // panic or return Unavailable.
        let Some(bundle) = shipped_bundle() else {
            eprintln!("skipping: {SHIPPED_BUNDLE_PATH} not present");
            return;
        };

        let raw = [f64::NAN; PROJECTION_DIM]; // all NaN → all imputed to means → z=0 for each

        for cohort_centroid in &bundle.cohort_centroids {
            match score_mahalanobis(&raw, &bundle, cohort_centroid) {
                ManifoldScoreOutcome::Distance { d_sigma } => {
                    assert!(
                        d_sigma.is_finite(),
                        "d_σ must be finite for cohort {:?}, got {d_sigma}",
                        cohort_centroid.cohort
                    );
                }
                ManifoldScoreOutcome::Unavailable(r) => {
                    panic!(
                        "expected Distance for cohort {:?}, got Unavailable({r:?})",
                        cohort_centroid.cohort
                    );
                }
            }
        }
    }
}
