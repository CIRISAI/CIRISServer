//! Typed calibration bundle — RATCHET's `crc-v1` (and successor)
//! artifact, hydrated into lens-core's hot path.
//!
//! # Wire shape sources
//!
//! Two ingestion paths share one in-memory representation:
//!
//! 1. **YAML / file-side.** RATCHET's release directory ships
//!    `bundle.yaml` (human-readable). [`CalibrationBundle::from_yaml`]
//!    deserialises that into the typed struct. Used by startup loaders
//!    on sovereign-mode lenses that ship the bundle next to the binary,
//!    and by tests.
//! 2. **Persist / row-side.** `cirislens_derived.calibration_bundles`
//!    stores the same logical object (per
//!    [`ciris_persist::derived::CalibrationBundle`]). The persist row
//!    keeps `projection_metadata` and `cohort_centroids` as opaque
//!    JSONB; [`CalibrationBundle::from_persist_row`] performs the
//!    strict deserialisation lens-core needs at score time.
//!
//! # Hard invariants
//!
//! - [`CalibrationBundle::projection_version`] **must** match
//!   [`crate::extract::projection::PROJECTION_VERSION`]. A mismatch
//!   means the bundle was calibrated against a different feature
//!   contract than the one this build of lens-core projects against —
//!   silently accepting it would fabricate scores. Returned as
//!   [`BundleError::ProjectionVersionMismatch`].
//! - [`Standardization::means`], [`Standardization::stds`], and
//!   [`Projection::retention_mask`] must all have length 16 (matching
//!   the CRC-v1 spec).
//! - [`Projection::field_order`] must match the canonical 16-field
//!   ordering lens-core's projection emits. Disagreement is rejected.
//!
//! # What this module deliberately doesn't do
//!
//! - Verify hybrid signatures on the bundle. That is persist's
//!   responsibility on the put path — `Engine::put_calibration_bundle`
//!   runs `verify_hybrid_via_directory` under `HybridPolicy::Strict`
//!   before the row reaches `cirislens_derived.calibration_bundles`.
//!   Lens-core consumes the row trusting that gate; LC-AV-9 structural
//!   attestation.
//! - Score traces. That's [`crate::scoring::assemble`] +
//!   [`crate::detector`]'s job; this module just hands them the
//!   numbers + the cohort lookup table.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::extract::projection::{PROJECTION_DIM, PROJECTION_VERSION};

/// Canonical 16-field ordering for the `crc-v1` projection. Matches
/// `src/extract/projection.rs::project`'s emission order one-for-one.
/// Bumped together with [`PROJECTION_VERSION`] when the projection
/// contract changes.
pub const CRC_V1_FIELD_ORDER: [&str; PROJECTION_DIM] = [
    "csdma_plausibility_score",
    "dsdma_domain_alignment",
    "coherence_level",
    "entropy_level",
    "idma_k_eff",
    "idma_correlation_risk",
    "entropy_score",
    "coherence_score",
    "optimization_veto_entropy_ratio",
    "epistemic_humility_certainty",
    "conscience_passed",
    "entropy_passed",
    "coherence_passed",
    "optimization_veto_passed",
    "epistemic_humility_passed",
    "action_was_overridden",
];

/// Per-feature standardization (mean + std) the Mahalanobis-σ math
/// uses to map a raw 16-vector into the cohort centroid's space.
///
/// `means.len() == stds.len() == PROJECTION_DIM`. Validated on
/// construction; mismatched lengths reject the bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Standardization {
    pub means: Vec<f64>,
    pub stds: Vec<f64>,
}

/// Projection metadata shipped alongside the centroids — the
/// transform-time inputs lens-core needs to deterministically
/// reproduce RATCHET's standardization + retention step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Projection {
    /// Field-order pinned by `projection_version`. Verification-
    /// redundant with the constant but checked at load.
    pub field_order: Vec<String>,
    /// Per-field corpus-mean fill-in for nulls (NaN imputation).
    pub imputation: BTreeMap<String, f64>,
    /// Per-feature mean + std.
    pub standardization: Standardization,
    /// `false` for features whose corpus std fell below `1e-9` and
    /// were dropped from scoring. `crc-v1` retains 14/16 (drops
    /// `idma_k_eff` + `epistemic_humility_passed` — see bundle notes).
    pub retention_mask: Vec<bool>,
}

/// One cohort centroid in standardized + retained space. `centroid`
/// and `variance` are length `D = retention_mask.iter().filter(|x|
/// **x).count()`. Persist's wire type (`ciris_persist::derived::
/// CohortCentroid`) carries this same shape; lens-core re-deserialises
/// strictly so the score loop can index without per-row option
/// unwraps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CohortCentroid {
    /// 6-tuple cohort key (same shape as
    /// [`crate::cohort::cohort_cell`] output).
    pub cohort: serde_json::Value,
    /// Per-feature centroid in standardized+retained space.
    pub centroid: Vec<f64>,
    /// Per-feature variance (diagonal-only, sufficient for σ-distance
    /// scoring at `crc-v1`; full covariance is a v0.2+ option).
    pub variance: Vec<f64>,
    /// Number of corpus samples that landed in this cohort.
    pub sample_count: u64,
    /// `sample_count >= sample_size_gate`. Calibration-time stamp;
    /// re-derived at score time against the bundle's gate.
    #[serde(default)]
    pub above_sample_size_gate: bool,
}

/// Typed mirror of `bundle.yaml` / `cirislens_derived.calibration_bundles`.
///
/// Single source-of-truth for scoring against RATCHET-shipped
/// centroids. Hydrated once at startup, stored on
/// [`crate::LensCore`] as `Arc<CalibrationBundle>` and threaded through
/// every `process` call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationBundle {
    /// Monotonic version stamp. Detection events copy this into
    /// `detection_events.ratchet_calibration_version` for LC-AV-19
    /// reproducibility.
    pub ratchet_calibration_version: i32,
    /// Pins the field-order + retention-mask contract. Must equal
    /// [`PROJECTION_VERSION`] at load — mismatch is a hard error.
    pub projection_version: String,
    /// Wall-clock at which RATCHET produced the bundle.
    #[serde(default)]
    pub calibrated_at: Option<String>,
    /// Per-cohort sample-count gate at score time. `crc-v1` ships
    /// `500`; every cohort cell in `crc-v1` is below this so every
    /// trace returns `SampleSizeBelowGate`.
    pub sample_size_gate: u32,
    /// Mahalanobis-σ outlier threshold. `crc-v1` ships `2.5` (provisional;
    /// v0.2 will land an empirically-fit ROC threshold).
    pub manifold_threshold_global: f64,
    /// Projection metadata.
    pub projection: Projection,
    /// Centroid table. Lookup is by structural-equality on the cohort
    /// JSON object; [`CalibrationBundle::lookup_cohort`] handles it.
    pub cohort_centroids: Vec<CohortCentroid>,
}

impl CalibrationBundle {
    /// Parse a RATCHET-shipped `bundle.yaml`. Performs schema validation
    /// (projection_version match + length invariants) before returning
    /// a usable bundle.
    pub fn from_yaml(s: &str) -> Result<Arc<Self>, BundleError> {
        let parsed: Self = serde_yaml::from_str(s).map_err(|e| BundleError::Yaml(e.to_string()))?;
        parsed.validate()?;
        Ok(Arc::new(parsed))
    }

    /// Hydrate from a persist `CalibrationBundle` row.
    ///
    /// The persist row keeps `projection_metadata` and
    /// `cohort_centroids` as opaque `serde_json::Value`s; this method
    /// performs the strict deserialization lens-core needs at score
    /// time. Persist already verified the row's hybrid signature on
    /// the put path; we do not re-verify here.
    pub fn from_persist_row(
        row: &ciris_persist::derived::CalibrationBundle,
    ) -> Result<Arc<Self>, BundleError> {
        let projection: Projection = serde_json::from_value(row.projection_metadata.clone())
            .map_err(|e| BundleError::ProjectionMetadataJson(e.to_string()))?;
        let cohort_centroids: Vec<CohortCentroid> =
            serde_json::from_value(row.cohort_centroids.clone())
                .map_err(|e| BundleError::CohortCentroidsJson(e.to_string()))?;

        let bundle = CalibrationBundle {
            ratchet_calibration_version: row.ratchet_calibration_version,
            projection_version: row.projection_version.clone(),
            calibrated_at: Some(row.calibrated_at.to_rfc3339()),
            sample_size_gate: u32::try_from(row.sample_size_gate)
                .map_err(|_| BundleError::SampleSizeGateNegative(row.sample_size_gate))?,
            manifold_threshold_global: f64::from(row.manifold_threshold_global),
            projection,
            cohort_centroids,
        };
        bundle.validate()?;
        Ok(Arc::new(bundle))
    }

    /// Validate the structural invariants documented at module-level.
    /// Run on every constructor; callers don't have to invoke it.
    pub fn validate(&self) -> Result<(), BundleError> {
        if self.projection_version != PROJECTION_VERSION {
            return Err(BundleError::ProjectionVersionMismatch {
                bundle: self.projection_version.clone(),
                lens_core: PROJECTION_VERSION,
            });
        }
        if self.projection.field_order.len() != PROJECTION_DIM {
            return Err(BundleError::FieldOrderLength {
                got: self.projection.field_order.len(),
                expected: PROJECTION_DIM,
            });
        }
        for (i, (got, want)) in self
            .projection
            .field_order
            .iter()
            .zip(CRC_V1_FIELD_ORDER.iter())
            .enumerate()
        {
            if got != want {
                return Err(BundleError::FieldOrderMismatch {
                    index: i,
                    bundle: got.clone(),
                    lens_core: want,
                });
            }
        }
        if self.projection.standardization.means.len() != PROJECTION_DIM
            || self.projection.standardization.stds.len() != PROJECTION_DIM
        {
            return Err(BundleError::StandardizationLength {
                means: self.projection.standardization.means.len(),
                stds: self.projection.standardization.stds.len(),
                expected: PROJECTION_DIM,
            });
        }
        if self.projection.retention_mask.len() != PROJECTION_DIM {
            return Err(BundleError::RetentionMaskLength {
                got: self.projection.retention_mask.len(),
                expected: PROJECTION_DIM,
            });
        }
        let retained: usize = self
            .projection
            .retention_mask
            .iter()
            .filter(|x| **x)
            .count();
        for c in &self.cohort_centroids {
            if c.centroid.len() != retained {
                return Err(BundleError::CentroidLength {
                    got: c.centroid.len(),
                    expected: retained,
                });
            }
            if c.variance.len() != retained {
                return Err(BundleError::VarianceLength {
                    got: c.variance.len(),
                    expected: retained,
                });
            }
        }
        Ok(())
    }

    /// Look up a cohort centroid by its 6-tuple cohort cell.
    ///
    /// Match is structural-equality on the JSON object (same shape
    /// `crate::cohort::cohort_cell` produces). Returns `None` when the
    /// trace's inferred cohort isn't represented in the bundle —
    /// caller routes to `CohortColdStart`.
    pub fn lookup_cohort(&self, cohort_cell: &serde_json::Value) -> Option<&CohortCentroid> {
        self.cohort_centroids
            .iter()
            .find(|c| &c.cohort == cohort_cell)
    }
}

/// Errors surfacing from bundle hydration / validation.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum BundleError {
    /// Bundle YAML could not be parsed.
    #[error("bundle yaml: {0}")]
    Yaml(String),
    /// Persist row's `projection_metadata` JSONB couldn't be
    /// deserialized into the typed [`Projection`].
    #[error("projection_metadata json: {0}")]
    ProjectionMetadataJson(String),
    /// Persist row's `cohort_centroids` JSONB couldn't be deserialized
    /// into `Vec<CohortCentroid>`.
    #[error("cohort_centroids json: {0}")]
    CohortCentroidsJson(String),
    /// Persist row's `sample_size_gate` was negative — schema allows
    /// `i32` but values must be `>= 0`.
    #[error("sample_size_gate negative: {0}")]
    SampleSizeGateNegative(i32),
    /// `projection_version` in the bundle disagrees with the constant
    /// this build of lens-core projects against. Hard error — we will
    /// NOT silently use a bundle calibrated against a different
    /// feature contract.
    #[error("projection_version mismatch: bundle={bundle} lens_core={lens_core}")]
    ProjectionVersionMismatch {
        bundle: String,
        lens_core: &'static str,
    },
    /// `field_order` length isn't 16.
    #[error("field_order length: got {got} expected {expected}")]
    FieldOrderLength { got: usize, expected: usize },
    /// `field_order` doesn't match canonical ordering at some index.
    #[error("field_order mismatch at {index}: bundle={bundle} lens_core={lens_core}")]
    FieldOrderMismatch {
        index: usize,
        bundle: String,
        lens_core: &'static str,
    },
    /// Standardization vector length mismatch.
    #[error("standardization length: means={means} stds={stds} expected {expected}")]
    StandardizationLength {
        means: usize,
        stds: usize,
        expected: usize,
    },
    /// Retention mask length mismatch.
    #[error("retention_mask length: got {got} expected {expected}")]
    RetentionMaskLength { got: usize, expected: usize },
    /// A cohort centroid's vector length doesn't match the retention
    /// mask's retained-dim count.
    #[error("centroid length: got {got} expected {expected}")]
    CentroidLength { got: usize, expected: usize },
    /// A cohort centroid's variance vector length doesn't match the
    /// retention mask's retained-dim count.
    #[error("variance length: got {got} expected {expected}")]
    VarianceLength { got: usize, expected: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped `bundle.yaml` lives outside the repo (RATCHET's
    /// release tree). Tests read it at test time via `fs::read_to_string`
    /// rather than `include_str!` so a missing file produces a runnable
    /// failure instead of a compile-time block.
    const SHIPPED_BUNDLE_PATH: &str = "/home/emoore/RATCHET/release/calibration/crc-v1/bundle.yaml";

    fn shipped_yaml() -> Option<String> {
        std::fs::read_to_string(SHIPPED_BUNDLE_PATH).ok()
    }

    #[test]
    fn parses_shipped_crc_v1_bundle() {
        let Some(yaml) = shipped_yaml() else {
            eprintln!("skipping: {SHIPPED_BUNDLE_PATH} not present");
            return;
        };
        let bundle = CalibrationBundle::from_yaml(&yaml).expect("from_yaml parses");
        assert_eq!(bundle.projection_version, "crc-v1");
        assert_eq!(bundle.ratchet_calibration_version, 1);
        assert_eq!(bundle.sample_size_gate, 500);
        assert!((bundle.manifold_threshold_global - 2.5).abs() < 1e-9);
        assert_eq!(bundle.projection.field_order.len(), 16);
        assert_eq!(bundle.projection.standardization.means.len(), 16);
        assert_eq!(bundle.projection.standardization.stds.len(), 16);
        assert_eq!(bundle.projection.retention_mask.len(), 16);
        // crc-v1 drops idma_k_eff (index 4) + epistemic_humility_passed
        // (index 14) per bundle notes.
        assert!(!bundle.projection.retention_mask[4]);
        assert!(!bundle.projection.retention_mask[14]);
        let retained = bundle
            .projection
            .retention_mask
            .iter()
            .filter(|x| **x)
            .count();
        assert_eq!(retained, 14);
        // All centroid vectors have length 14.
        for c in &bundle.cohort_centroids {
            assert_eq!(c.centroid.len(), 14);
            assert_eq!(c.variance.len(), 14);
        }
        // All crc-v1 cohort cells are below sample_size_gate=500.
        for c in &bundle.cohort_centroids {
            assert!(
                (c.sample_count as u32) < bundle.sample_size_gate,
                "expected all crc-v1 cohorts below gate, but {} >= {}",
                c.sample_count,
                bundle.sample_size_gate,
            );
        }
        assert_eq!(bundle.cohort_centroids.len(), 3);
    }

    #[test]
    fn projection_version_must_match_lens_core_constant() {
        // Synthesize a minimal-shape bundle with wrong projection_version
        // and confirm validation rejects it. The "field_order matches
        // CRC_V1_FIELD_ORDER" check still has to pass for this to be a
        // pure projection_version test; using the canonical order keeps
        // the test focused.
        let bad = CalibrationBundle {
            ratchet_calibration_version: 1,
            projection_version: "crc-v0-DEFINITELY-NOT-REAL".into(),
            calibrated_at: None,
            sample_size_gate: 500,
            manifold_threshold_global: 2.5,
            projection: Projection {
                field_order: CRC_V1_FIELD_ORDER.iter().map(|s| s.to_string()).collect(),
                imputation: BTreeMap::new(),
                standardization: Standardization {
                    means: vec![0.0; PROJECTION_DIM],
                    stds: vec![1.0; PROJECTION_DIM],
                },
                retention_mask: vec![true; PROJECTION_DIM],
            },
            cohort_centroids: vec![],
        };
        match bad.validate() {
            Err(BundleError::ProjectionVersionMismatch { bundle, lens_core }) => {
                assert_eq!(bundle, "crc-v0-DEFINITELY-NOT-REAL");
                assert_eq!(lens_core, PROJECTION_VERSION);
            }
            other => panic!("expected ProjectionVersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn field_order_mismatch_rejected_at_index() {
        let mut bad_order: Vec<String> = CRC_V1_FIELD_ORDER.iter().map(|s| s.to_string()).collect();
        bad_order.swap(0, 1); // canary: reorder two fields
        let bad = CalibrationBundle {
            ratchet_calibration_version: 1,
            projection_version: PROJECTION_VERSION.into(),
            calibrated_at: None,
            sample_size_gate: 500,
            manifold_threshold_global: 2.5,
            projection: Projection {
                field_order: bad_order,
                imputation: BTreeMap::new(),
                standardization: Standardization {
                    means: vec![0.0; PROJECTION_DIM],
                    stds: vec![1.0; PROJECTION_DIM],
                },
                retention_mask: vec![true; PROJECTION_DIM],
            },
            cohort_centroids: vec![],
        };
        match bad.validate() {
            Err(BundleError::FieldOrderMismatch { index, .. }) => assert_eq!(index, 0),
            other => panic!("expected FieldOrderMismatch, got {other:?}"),
        }
    }

    #[test]
    fn lookup_cohort_returns_none_for_unknown_cohort() {
        let Some(yaml) = shipped_yaml() else {
            eprintln!("skipping: shipped bundle not present");
            return;
        };
        let bundle = CalibrationBundle::from_yaml(&yaml).expect("from_yaml parses");
        let bogus = serde_json::json!({
            "agent_role": "definitely-not-a-real-role",
            "agent_template": null,
            "deployment_domain": null,
            "deployment_type": null,
            "deployment_region": null,
            "deployment_trust_mode": null,
        });
        assert!(bundle.lookup_cohort(&bogus).is_none());
    }

    #[test]
    fn lookup_cohort_returns_some_for_known_cohort() {
        let Some(yaml) = shipped_yaml() else {
            eprintln!("skipping: shipped bundle not present");
            return;
        };
        let bundle = CalibrationBundle::from_yaml(&yaml).expect("from_yaml parses");
        // The "all-null" cohort is in crc-v1 (sample_count=119).
        let all_null = serde_json::json!({
            "agent_role": null,
            "agent_template": null,
            "deployment_domain": null,
            "deployment_type": null,
            "deployment_region": null,
            "deployment_trust_mode": null,
        });
        let found = bundle
            .lookup_cohort(&all_null)
            .expect("all-null cohort exists in crc-v1");
        assert_eq!(found.sample_count, 119);
    }
}
