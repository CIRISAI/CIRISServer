//! Typed axis-family calibration — RATCHET's `crc-v2` artifact, the
//! per-axis operational definitions + statistical floors + threshold
//! functions for CEG §5.5.3 (F-3 `correlated_action:{axis}`) and CEG
//! §5.5.5 (distributive-access `distributive:access:{resource_type}`).
//!
//! # Relationship to [`crate::scoring::calibration`]
//!
//! [`crate::scoring::calibration::CalibrationBundle`] models the
//! `crc-v1` **manifold** artifact (CEG §5.5.1): the 16-field
//! projection contract + per-cohort centroids + diagonal covariance
//! for Mahalanobis-σ scoring. That artifact is keyed by
//! [`crate::extract::projection::PROJECTION_VERSION`] (`crc-v1`) and is
//! **unchanged** by crc-v2.
//!
//! `crc-v2` is a *different schema entirely* — it carries no
//! field_order, no centroids, no standardization. It carries an
//! `axes` map: one entry per detector axis, each with a
//! [`ThresholdFunction`] (metric name, threshold, polarity, scaling,
//! optional `zero_variance_baseline` outcome), `tier`,
//! `statistical_floor`, and `evidence_required`. The two artifacts are
//! versioned independently:
//!
//! - manifold: `PROJECTION_VERSION = "crc-v1"`,
//!   `ratchet_calibration_version = 1`.
//! - axis-family: [`AXIS_CALIBRATION_VERSION`] = `"crc-v2"`,
//!   [`RATCHET_AXIS_CALIBRATION_VERSION`] = `2`.
//!
//! # Wire shape source
//!
//! RATCHET's release directory ships
//! `release/calibration/crc-v2/bundle.yaml`. [`AxisCalibration::from_yaml`]
//! deserialises it into the typed struct. (A `bundle.cbor` ships too
//! for binary runtime consumption, but lens-core already depends on
//! `serde_yaml`, so the YAML path is canonical here; a CBOR loader is
//! a drop-in addition once `ciborium` lands as a dependency.)
//!
//! # What this module deliberately doesn't do
//!
//! - Verify the bundle signature. Same discipline as the manifold
//!   bundle: persist's put path runs `verify_hybrid_via_directory`
//!   under `HybridPolicy::Strict` before the calibration ever reaches
//!   lens-core's hot path. (`bundle.signing.txt` is the signing
//!   scaffold.)
//! - Aggregate the corpus. That's the per-axis detector's job
//!   ([`crate::detector::distributive_access`] +
//!   [`crate::detector::correlated_action`]); this module hands them
//!   the typed threshold + polarity + floor.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// Axis-family calibration version string. Pins which RATCHET
/// axis-calibration release this build consumes. **Distinct from**
/// [`crate::extract::projection::PROJECTION_VERSION`] (`crc-v1`, the
/// manifold projection contract) — the F-3 + distributive axes are
/// calibrated independently of the manifold projection.
pub const AXIS_CALIBRATION_VERSION: &str = "crc-v2";

/// Monotonic integer stamp for the axis-family calibration. Copied
/// into emitted `detection:*` envelopes so consumers can join the
/// attestation back to the exact calibration that produced it.
pub const RATCHET_AXIS_CALIBRATION_VERSION: i32 = 2;

/// Polarity convention per the crc-v2 README + per-axis
/// `threshold_function.polarity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Polarity {
    /// High values = good (broad access / low concentration). A
    /// negative attestation is emitted when the cohort metric **meets
    /// or exceeds** the concentration threshold. (Distributive axes:
    /// compute, models, agent_capabilities, federation_membership.)
    #[serde(rename = "positive_when_distributed")]
    PositiveWhenDistributed,
    /// High values = concern (concentrated / asymmetric pattern
    /// present). A negative attestation is emitted when the cohort
    /// metric **meets or exceeds** the concern threshold. (F-3 axes:
    /// rights_asymmetry, participation_exclusion,
    /// informational_asymmetry, aggregate_footprint.)
    #[serde(rename = "negative_when_detected")]
    NegativeWhenDetected,
}

/// Which tail of the metric distribution is the concern. Derived from
/// `threshold_pctile_of_observed`: an upper-tail (p75) threshold fires
/// concern at `metric >= threshold`; a lower-tail (p25) threshold fires
/// concern at `metric <= threshold`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConcernDirection {
    /// Concern when `metric >= threshold` (high concentration /
    /// asymmetry). federation_membership, participation_exclusion,
    /// aggregate_footprint.
    #[serde(rename = "at_or_above")]
    AtOrAbove,
    /// Concern when `metric <= threshold` (low diversity). cap_diversity
    /// only (`README: cap_diversity ≤ 0.037`).
    #[serde(rename = "at_or_below")]
    AtOrBelow,
    /// Concern when the metric exits the healthy corridor at EITHER pole
    /// (compute_gini, models_hhi, rights_asymmetry, info_asym_cv).
    /// crc-v2 calibrates ONLY the upper bound (== `threshold_value`); the
    /// lower bound is `structurally_documented_uncalibrated_in_v2`, so
    /// lower-pole concern is not flagged until crc-v3+ sets
    /// `corridor.lower_bound`. Framework basis: CCA both-pole fragility
    /// (rigidity pole ρ→1 + chaos pole ρ→0), per
    /// `bundle.yaml::consumer_contract.concern_direction_convention`.
    #[serde(rename = "outside_corridor")]
    OutsideCorridor,
}

/// The healthy-coordination corridor for an `outside_corridor` axis.
/// Mirrors `bundle.yaml::axes.{axis}.threshold_function.corridor`
/// (status/doc sub-fields are ignored; only the bounds drive logic).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Corridor {
    /// Upper concern bound — corpus-calibrated in crc-v2 (== the axis
    /// `threshold_value`). `metric >= upper_bound` ⇒ concern.
    #[serde(default)]
    pub upper_bound: Option<f64>,
    /// Lower concern bound — `null` in crc-v2 (uncalibrated); set in
    /// crc-v3+ once corpus variance permits. When present,
    /// `metric <= lower_bound` ⇒ (chaos-pole) concern.
    #[serde(default)]
    pub lower_bound: Option<f64>,
}

/// Calibration-time outcome flag carried on axes whose corpus showed
/// no within-cohort variance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CalibrationOutcome {
    /// All qualifying cohorts in the crc-v2 corpus showed this metric
    /// = 0 (`federation_membership`, `rights_asymmetry`). The
    /// threshold is a `1e-6` lowest-detectable-signal sentinel, not an
    /// evidence-based operating point. Per fail-secure discipline the
    /// detector must NOT emit a false-confident `Numeric` for the
    /// degenerate (metric == 0) case — see
    /// [`crate::detector`]'s zero-variance handling.
    #[serde(rename = "zero_variance_baseline")]
    ZeroVarianceBaseline,
}

/// The threshold function for one axis. Mirrors
/// `bundle.yaml::axes.{axis}.threshold_function`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThresholdFunction {
    /// Metric name (`compute_gini`, `models_hhi`, `info_asym_cv`, …).
    /// The detector dispatches its measurement procedure on this.
    pub metric: String,
    /// Threshold value above which the cohort is judged
    /// concentrated/asymmetric. Sentinel `1e-6` for zero-variance axes.
    pub threshold_value: f64,
    /// Which percentile of the observed cohort metrics the threshold
    /// was set at. **Load-bearing for concern direction:** a
    /// `0.75` (upper-tail) threshold means concern is `metric ≥
    /// threshold` (compute_gini, models_hhi, the F-3 axes); a `0.25`
    /// (lower-tail) threshold means concern is `metric ≤ threshold`
    /// (`cap_diversity` — low capability diversity is the concentrated
    /// case, per README `cap_diversity ≤ 0.037`). See
    /// [`ThresholdFunction::concern_direction`].
    pub threshold_pctile_of_observed: f64,
    /// Polarity convention for this axis.
    pub polarity: Polarity,
    /// The score emitted exactly at the threshold (the anchor for the
    /// severity-scaling ramp). Always negative in crc-v2.
    pub score_at_threshold: f64,
    /// Free-form scaling tag. crc-v2 ships
    /// `magnitude_scales_with_severity_above_threshold` for all axes.
    pub scaling: String,
    /// Present only on zero-variance axes.
    #[serde(default)]
    pub calibration_outcome: Option<CalibrationOutcome>,
    /// Explicit concern direction (crc-v2 post-RATCHET#6). When present
    /// it is AUTHORITATIVE — [`ThresholdFunction::concern_direction`]
    /// returns it directly instead of inferring from the pctile tail.
    /// Absent on pre-#6 bundles → pctile-inference fallback.
    #[serde(default, rename = "concern_direction")]
    pub concern_direction_field: Option<ConcernDirection>,
    /// The healthy corridor for `outside_corridor` axes. `upper_bound`
    /// is corpus-calibrated (== `threshold_value`); `lower_bound` is
    /// null until crc-v3+. Absent on single-pole axes.
    #[serde(default)]
    pub corridor: Option<Corridor>,
}

impl ThresholdFunction {
    /// Concern direction derived from `threshold_pctile_of_observed`.
    /// A threshold set at the upper tail (pctile > 0.5) means high
    /// metric values are the concern (`metric >= threshold`); a
    /// lower-tail threshold (pctile <= 0.5) means low metric values are
    /// the concern (`metric <= threshold`). This disambiguates
    /// `cap_diversity` (p25, low-is-bad) from the other
    /// `positive_when_distributed` axes (p75, high-is-bad). The
    /// zero-variance sentinel axes are p75 → `AtOrAbove` (any nonzero
    /// deviation crosses).
    ///
    /// crc-v2 (post-RATCHET#6) ships an explicit `concern_direction`;
    /// when present it is authoritative and the pctile heuristic is
    /// bypassed entirely (it also surfaces `outside_corridor`, which the
    /// pctile alone cannot express). The inference remains the fallback
    /// for any bundle that predates the field.
    pub fn concern_direction(&self) -> ConcernDirection {
        if let Some(dir) = self.concern_direction_field {
            return dir;
        }
        if self.threshold_pctile_of_observed <= 0.5 {
            ConcernDirection::AtOrBelow
        } else {
            ConcernDirection::AtOrAbove
        }
    }

    /// The upper concern bound for an `outside_corridor` axis, falling
    /// back to `threshold_value` (they are equal in crc-v2). Used by the
    /// scorer's corridor-exit test.
    pub fn corridor_upper_bound(&self) -> f64 {
        self.corridor
            .as_ref()
            .and_then(|c| c.upper_bound)
            .unwrap_or(self.threshold_value)
    }

    /// The lower concern bound for an `outside_corridor` axis, if
    /// calibrated (`None` in crc-v2 → lower-pole not flagged).
    pub fn corridor_lower_bound(&self) -> Option<f64> {
        self.corridor.as_ref().and_then(|c| c.lower_bound)
    }
}

/// Statistical floor for one axis. Mirrors
/// `bundle.yaml::axes.{axis}.statistical_floor`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatisticalFloor {
    pub min_cohort_size_events: u64,
    pub min_goal_aligned_cluster_size_agents: u64,
    pub min_window_days: u64,
    pub power_target: f64,
}

/// One calibrated axis. Mirrors a single `bundle.yaml::axes.{axis}`
/// entry. Only the fields lens-core consumes at score time are typed;
/// the rest of the YAML (calibration stats, notes, measurement_procedure)
/// is `#[serde(flatten)]`-skipped via per-field selection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AxisEntry {
    /// CEG axis label, e.g. `"distributive:access:compute"`.
    pub axis: String,
    /// 1 = full calibration, 2 = proxy, 3 = deferred (not present in
    /// the parsed `axes` map — Tier-3 axes have no YAML entry).
    pub tier: u8,
    /// Human-readable measurement procedure (carried for audit /
    /// evidence; the detector's code is the load-bearing definition).
    pub measurement_procedure: String,
    /// Threshold + polarity + scaling.
    pub threshold_function: ThresholdFunction,
    /// Statistical floor (sample-size / window gates).
    pub statistical_floor: StatisticalFloor,
    /// Axis-specific evidence fields that the attestation's
    /// `evidence_refs[]` must carry.
    pub evidence_required: Vec<String>,
}

impl AxisEntry {
    /// True when this axis is a zero-variance-baseline axis (threshold
    /// is a `1e-6` sentinel, not an evidence-based operating point).
    pub fn is_zero_variance_baseline(&self) -> bool {
        matches!(
            self.threshold_function.calibration_outcome,
            Some(CalibrationOutcome::ZeroVarianceBaseline)
        )
    }
}

/// The crc-v2 calibration corpus provenance — the hashes that the
/// per-axis attestation's `evidence_refs[]` cite.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationCorpus {
    /// SHA-256 of the `trace_events.jsonl.gz` the calibration derived
    /// from. Cited as `0612_prod_traces:trace_events.jsonl.gz:<hash>`.
    pub trace_events_sha256: String,
    /// SHA-256 of the `trace_llm_calls` table.
    #[serde(default)]
    pub trace_llm_calls_sha256: Option<String>,
}

/// Typed mirror of `crc-v2/bundle.yaml`. Single source-of-truth for
/// the F-3 + distributive detectors' threshold/polarity/floor lookups.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AxisCalibration {
    /// Monotonic integer stamp (`2` for crc-v2).
    pub ratchet_calibration_version: i32,
    /// Version string (`"crc-v2"`). Validated against
    /// [`AXIS_CALIBRATION_VERSION`] at load.
    pub projection_version: String,
    /// Wall-clock at which RATCHET produced the bundle.
    #[serde(default)]
    pub calibrated_at: Option<String>,
    /// The prior version this bundle supersedes (`"crc-v1"`), used to
    /// drive the CEG §15.2 R2 dual-hash transition discipline.
    #[serde(default)]
    pub supersedes: Option<String>,
    /// Corpus provenance (hashes for `evidence_refs[]`).
    pub calibration_corpus: CalibrationCorpus,
    /// Per-axis calibration. Keyed by the CEG axis label. Tier-3
    /// deferred axes are intentionally absent (no YAML entry).
    pub axes: BTreeMap<String, AxisEntry>,
}

impl AxisCalibration {
    /// Parse a RATCHET-shipped crc-v2 `bundle.yaml`. Validates the
    /// version stamp before returning.
    pub fn from_yaml(s: &str) -> Result<Arc<Self>, AxisCalibrationError> {
        let parsed: Self =
            serde_yaml::from_str(s).map_err(|e| AxisCalibrationError::Yaml(e.to_string()))?;
        parsed.validate()?;
        Ok(Arc::new(parsed))
    }

    /// Validate the version invariant: the bundle must declare the
    /// `projection_version` this build of lens-core was wired against.
    /// A mismatch means the bundle was calibrated under a different
    /// axis contract — accepting it would attach the wrong thresholds
    /// to a signed federation attestation.
    pub fn validate(&self) -> Result<(), AxisCalibrationError> {
        if self.projection_version != AXIS_CALIBRATION_VERSION {
            return Err(AxisCalibrationError::VersionMismatch {
                bundle: self.projection_version.clone(),
                lens_core: AXIS_CALIBRATION_VERSION,
            });
        }
        if self.ratchet_calibration_version != RATCHET_AXIS_CALIBRATION_VERSION {
            return Err(AxisCalibrationError::CalibrationVersionMismatch {
                bundle: self.ratchet_calibration_version,
                lens_core: RATCHET_AXIS_CALIBRATION_VERSION,
            });
        }
        Ok(())
    }

    /// Look up the calibration for a CEG axis label. Returns `None`
    /// for Tier-3 deferred axes (absent from the bundle) — the caller
    /// routes those to `AxisAwaitingCalibration`.
    pub fn axis(&self, axis_label: &str) -> Option<&AxisEntry> {
        self.axes.get(axis_label)
    }

    /// The `crc-v2:bundle.sha256:<hash>` evidence ref. The hash is the
    /// caller-supplied digest of `bundle.yaml` (read from the shipped
    /// `bundle.sha256` sidecar), bound to this version string.
    pub fn bundle_evidence_ref(&self, bundle_sha256: &str) -> String {
        format!(
            "{}:bundle.sha256:{}",
            self.projection_version, bundle_sha256
        )
    }
}

/// Errors surfacing from axis-calibration hydration / validation.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum AxisCalibrationError {
    /// Bundle YAML could not be parsed.
    #[error("axis-calibration yaml: {0}")]
    Yaml(String),
    /// `projection_version` disagrees with the constant this build was
    /// wired against. Hard error — a signed attestation must not carry
    /// the wrong thresholds.
    #[error("axis-calibration version mismatch: bundle={bundle} lens_core={lens_core}")]
    VersionMismatch {
        bundle: String,
        lens_core: &'static str,
    },
    /// `ratchet_calibration_version` disagrees with the expected stamp.
    #[error("axis-calibration ratchet version mismatch: bundle={bundle} lens_core={lens_core}")]
    CalibrationVersionMismatch { bundle: i32, lens_core: i32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHIPPED_V2_PATH: &str = "/home/emoore/RATCHET/release/calibration/crc-v2/bundle.yaml";

    fn shipped_yaml() -> Option<String> {
        std::fs::read_to_string(SHIPPED_V2_PATH).ok()
    }

    #[test]
    fn parses_shipped_crc_v2_bundle() {
        let Some(yaml) = shipped_yaml() else {
            eprintln!("skipping: {SHIPPED_V2_PATH} not present");
            return;
        };
        let cal = AxisCalibration::from_yaml(&yaml).expect("from_yaml parses");
        assert_eq!(cal.projection_version, "crc-v2");
        assert_eq!(cal.ratchet_calibration_version, 2);
        assert_eq!(cal.supersedes.as_deref(), Some("crc-v1"));

        // 8 calibrated axes (4 Tier-1 + 4 Tier-2); Tier-3 axes absent.
        assert_eq!(cal.axes.len(), 8);

        // Tier-1 full calibration present.
        let compute = cal
            .axis("distributive:access:compute")
            .expect("compute axis present");
        assert_eq!(compute.tier, 1);
        assert_eq!(compute.threshold_function.metric, "compute_gini");
        assert!((compute.threshold_function.threshold_value - 0.169785).abs() < 1e-9);
        assert_eq!(
            compute.threshold_function.polarity,
            Polarity::PositiveWhenDistributed
        );
        assert!(!compute.is_zero_variance_baseline());

        // Zero-variance axes carry the outcome flag + 1e-6 sentinel.
        let fed = cal
            .axis("distributive:access:federation_membership")
            .expect("federation_membership present");
        assert!(fed.is_zero_variance_baseline());
        assert!((fed.threshold_function.threshold_value - 1e-6).abs() < 1e-12);
        let rights = cal
            .axis("correlated_action:rights_asymmetry")
            .expect("rights_asymmetry present");
        assert!(rights.is_zero_variance_baseline());
        assert_eq!(
            rights.threshold_function.polarity,
            Polarity::NegativeWhenDetected
        );

        // Explicit concern_direction (crc-v2 post-RATCHET#6) is read
        // directly, NOT inferred from the pctile. The four corridor axes
        // surface OutsideCorridor with upper_bound == threshold_value and
        // an uncalibrated (null) lower_bound; the single-pole axes carry
        // at_or_above / at_or_below.
        assert_eq!(
            compute.threshold_function.concern_direction(),
            ConcernDirection::OutsideCorridor
        );
        assert!(
            (compute.threshold_function.corridor_upper_bound()
                - compute.threshold_function.threshold_value)
                .abs()
                < 1e-12
        );
        assert_eq!(compute.threshold_function.corridor_lower_bound(), None);
        assert_eq!(
            rights.threshold_function.concern_direction(),
            ConcernDirection::OutsideCorridor
        );
        assert_eq!(
            fed.threshold_function.concern_direction(),
            ConcernDirection::AtOrAbove
        );
        let caps = cal
            .axis("distributive:access:agent_capabilities")
            .expect("agent_capabilities present");
        assert_eq!(
            caps.threshold_function.concern_direction(),
            ConcernDirection::AtOrBelow
        );

        // Tier-3 deferred axes are absent from the bundle.
        assert!(cal.axis("distributive:access:training_data").is_none());
        assert!(cal
            .axis("correlated_action:ecology_of_communication:echo_chamber_density")
            .is_none());
    }

    #[test]
    fn version_mismatch_rejected() {
        let cal = AxisCalibration {
            ratchet_calibration_version: 2,
            projection_version: "crc-v99-NOT-REAL".into(),
            calibrated_at: None,
            supersedes: None,
            calibration_corpus: CalibrationCorpus {
                trace_events_sha256: "deadbeef".into(),
                trace_llm_calls_sha256: None,
            },
            axes: BTreeMap::new(),
        };
        match cal.validate() {
            Err(AxisCalibrationError::VersionMismatch { bundle, lens_core }) => {
                assert_eq!(bundle, "crc-v99-NOT-REAL");
                assert_eq!(lens_core, AXIS_CALIBRATION_VERSION);
            }
            other => panic!("expected VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn bundle_evidence_ref_is_version_bound() {
        let cal = AxisCalibration {
            ratchet_calibration_version: 2,
            projection_version: "crc-v2".into(),
            calibrated_at: None,
            supersedes: Some("crc-v1".into()),
            calibration_corpus: CalibrationCorpus {
                trace_events_sha256: "abc".into(),
                trace_llm_calls_sha256: None,
            },
            axes: BTreeMap::new(),
        };
        assert_eq!(
            cal.bundle_evidence_ref("c1f011ec"),
            "crc-v2:bundle.sha256:c1f011ec"
        );
    }
}
