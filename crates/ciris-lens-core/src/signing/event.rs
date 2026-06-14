//! Build + sign one detection event.
//!
//! # Pipeline position
//!
//! ```text
//! cohort + detector + scoring  ──►  sign_detection  ──►  put_detection_event
//!     (produce ManifoldConformity)        │                       │
//!                                         ▼                       ▼
//!                          canonicalize + LocalSigner    cirislens_derived.detection_events
//! ```
//!
//! The orchestrator (`pipeline::lifecycle::process`) gathers the
//! inputs from upstream stages, calls [`sign_detection`], and hands
//! the resulting [`ciris_persist::prelude::DetectionEvent`] to
//! persist's `DerivedSchema::put_detection_event` for storage. The
//! summary record is appended to the caller's `Score.detection_events`
//! list for observability.
//!
//! # Hybrid signature binding
//!
//! Replicates `LocalSigner::sign_hybrid`'s internal construction —
//! the PQC (ML-DSA-65) signature is computed over the canonical
//! bytes **bound with the Ed25519 signature**:
//!
//! ```text
//! ed25519_sig    = sign_ed25519(canonical_bytes)
//! ml_dsa_65_sig  = sign_ml_dsa_65(canonical_bytes ++ ed25519_sig)
//! ```
//!
//! This is what `ciris_persist::prelude::verify_hybrid_via_directory`
//! verifies under `HybridPolicy::Strict`. We manually compose the
//! same primitive here rather than calling `sign_hybrid` so the
//! function doesn't need to deconstruct the
//! `ciris_crypto::HybridSignature` struct (which would force a
//! direct dep on `ciris_crypto`).

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use ciris_persist::prelude::{
    canonicalize_envelope_for_signing, ConformityVariant, DetectionEvent, DetectionSeverity,
    LocalSigner, LocalSignerError,
};
use serde_json::{json, Value};

use crate::scoring::axis_calibration::{AxisCalibration, AxisEntry};
use crate::scoring::result::{
    DetectionEvent as Summary, IndeterminateReason, ManifoldConformity, Severity, UnavailableReason,
};

/// Cohort delineation artifact for an axis-family attestation's
/// `evidence_refs[]` (crc-v2 README §"Consumer contract"): a cohort id
/// with the member `agent_id_hash` list, OR (when the explicit
/// membership isn't materialized) the derivation-algorithm version.
pub enum CohortDelineation {
    /// Explicit cohort id + member `agent_id_hash` list.
    Members {
        cohort_id: String,
        member_agent_id_hashes: Vec<String>,
    },
    /// Cohort derivation algorithm version (when the explicit member
    /// list isn't materialized at attestation time).
    AlgorithmVersion(String),
}

/// Build the `evidence_refs[]` for an axis-family (`crc-v2`) detection
/// attestation per the crc-v2 README §"Consumer contract" +
/// `bundle.yaml::consumer_contract`.
///
/// The returned vector carries, in order:
///
/// 1. `crc-v2:bundle.sha256:<hash>` — the active bundle hash
///    (`bundle_sha256`, read from the shipped `bundle.sha256` sidecar).
/// 2. **CEG §15.2 R2 dual-hash transition discipline:** when
///    `prior_bundle_sha256` is `Some`, the prior `crc-v{N-1}` bundle
///    hash is ALSO emitted (`<supersedes>:bundle.sha256:<hash>`) so the
///    attestation cites both bundles during a transition window,
///    defeating straddle attacks. The prior version string is read
///    from `calibration.supersedes`.
/// 3. `0612_prod_traces:trace_events.jsonl.gz:<hash>` — the corpus
///    `trace_events_sha256` from the bundle.
/// 4. `corpus_trace_events:<hash>` — the hash of the live corpus this
///    attestation scored over (caller-supplied; binds the verdict to
///    the exact traces).
/// 5. Cohort delineation (`cohort_delineation:cohort_id:<id>` +
///    `cohort_member:<agent_id_hash>` per member, OR
///    `cohort_derivation_algorithm:<version>`).
/// 6. The axis-specific `evidence_required` field names from the
///    bundle (`evidence_required:<field>`), so consumers know which
///    evidence shape backs this axis.
pub fn build_axis_evidence_refs(
    calibration: &AxisCalibration,
    axis: &AxisEntry,
    bundle_sha256: &str,
    prior_bundle_sha256: Option<&str>,
    corpus_trace_events_sha256: &str,
    cohort: &CohortDelineation,
) -> Vec<String> {
    let mut refs = Vec::new();

    // (1) Active bundle hash, version-bound.
    refs.push(calibration.bundle_evidence_ref(bundle_sha256));

    // (2) Dual-hash transition discipline (CEG §15.2 R2): also cite the
    // superseded bundle during the transition window.
    if let Some(prior) = prior_bundle_sha256 {
        let prior_version = calibration.supersedes.as_deref().unwrap_or("crc-prior");
        refs.push(format!("{prior_version}:bundle.sha256:{prior}"));
    }

    // (3) Calibration-corpus trace_events hash (from the bundle).
    refs.push(format!(
        "0612_prod_traces:trace_events.jsonl.gz:{}",
        calibration.calibration_corpus.trace_events_sha256
    ));

    // (4) Live-corpus trace_events hash (binds the verdict to the
    // exact traces this attestation scored over).
    refs.push(format!("corpus_trace_events:{corpus_trace_events_sha256}"));

    // (5) Cohort delineation.
    match cohort {
        CohortDelineation::Members {
            cohort_id,
            member_agent_id_hashes,
        } => {
            refs.push(format!("cohort_delineation:cohort_id:{cohort_id}"));
            for m in member_agent_id_hashes {
                refs.push(format!("cohort_member:{m}"));
            }
        }
        CohortDelineation::AlgorithmVersion(v) => {
            refs.push(format!("cohort_derivation_algorithm:{v}"));
        }
    }

    // (6) Axis-specific required-evidence field names.
    for field in &axis.evidence_required {
        refs.push(format!("evidence_required:{field}"));
    }

    refs
}

/// Errors building + signing a detection event. Wraps the two upstream
/// failure surfaces (canonicalization + local signing) plus a
/// signature-shape sanity check that fail-fast catches a misconfigured
/// signer before we hand a malformed event to persist.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// `canonicalize_envelope_for_signing` failed — typically means
    /// the envelope contains a non-serializable value. Shouldn't
    /// happen in practice; surface for diagnostics if it does.
    #[error("canonicalize: {0}")]
    Canonicalize(String),
    /// Local signing failed — seed read, PQC backend error,
    /// or PQC not configured (federation evidence requires hybrid,
    /// not Ed25519-only).
    #[error("sign: {0}")]
    Sign(#[from] LocalSignerError),
    /// Signature byte length didn't match the federation-stable
    /// expectation (Ed25519: 64 bytes; ML-DSA-65: 3309 bytes per
    /// FIPS 204 final). Caller's persist row would fail the DB CHECK
    /// constraint anyway; we fail-fast here for a clearer error.
    #[error("signature shape: {field} length is {actual}, expected {expected}")]
    SignatureShape {
        /// Which signature failed the length check.
        field: &'static str,
        /// Observed byte length.
        actual: usize,
        /// Federation-stable expected length.
        expected: usize,
    },
}

/// Inputs to one detection event. Borrowed where ergonomic; owned
/// where the assembled [`DetectionEvent`] requires ownership.
pub struct DetectionInputs<'a> {
    /// Trace this detection fired against.
    pub trace_id: String,
    /// 32-byte SHA-256 of the wire body. Forensic join key.
    pub body_sha256: Vec<u8>,
    /// Detector token — stable string identifying which detector
    /// fired (`"cohort_declared_inferred_mismatch"`,
    /// `"manifold_conformity_outlier"`, etc.).
    pub detector: &'static str,
    /// Triage bucket.
    pub severity: Severity,
    /// 6-tuple cohort key as a typed JSON object (per OQ-10).
    pub cohort_cell: Value,
    /// Conformity outcome from the scoring stage.
    pub conformity: &'a ManifoldConformity,
    /// Lens-core version stamped onto the row for LC-AV-19
    /// reproducibility.
    pub lens_core_version: &'static str,
    /// Calibration bundle version active at score time. Joins to
    /// `cirislens_derived.calibration_bundles.ratchet_calibration_version`.
    pub ratchet_calibration_version: i32,
    /// Federation-attestation `evidence_refs[]` (crc-v2 README §
    /// "Consumer contract"). Bound into the signed envelope so the
    /// attestation cites the exact calibration bundle hash(es), corpus
    /// hash, cohort delineation, and axis-specific evidence fields.
    /// Empty for the manifold / cohort-mismatch detectors (which carry
    /// no axis-family calibration). See [`build_axis_evidence_refs`].
    pub evidence_refs: Vec<String>,
}

/// Pre-signing state — the canonicalized envelope, the bytes that
/// need signing, and the typed-converter outputs cached for
/// downstream assembly. Returned by [`prepare_detection`] for both
/// rlib and PyO3 paths; the difference is who calls `sign_*` next.
pub struct PreparedDetection {
    /// UUID v4 generated for this detection event.
    pub detection_id: Uuid,
    /// Wall-clock at preparation time. Recorded in both the canonical
    /// envelope (in case verifiers want to bound) and the eventual
    /// row's `ts` column.
    pub ts: DateTime<Utc>,
    /// Canonical-JSON bytes the caller signs. Sent to the local
    /// signer (Ed25519 + ML-DSA-65 hybrid) by either path.
    pub canonical_bytes: Vec<u8>,
    /// Pre-mapped persist severity enum (`info` / `warning` / `critical`).
    pub severity_persist: DetectionSeverity,
    /// Pre-mapped conformity discriminant (`numeric` / `indeterminate`
    /// / `unavailable`).
    pub conformity_variant: ConformityVariant,
    /// Variant-specific payload (score / indeterminate-reason /
    /// unavailable-reason). Already JSON-encoded.
    pub conformity_payload: Value,
    /// Cohort cell JSON, unchanged from inputs.
    pub cohort_cell: Value,
}

/// Build the canonical envelope + canonical bytes from inputs. Pure
/// function. Used by both `sign_detection` (rlib path, signer
/// invokes itself) and the PyO3 `process_trace_batch` (engine
/// invokes the signer via `Engine.local_sign` /
/// `Engine.local_pqc_sign`).
pub fn prepare_detection(
    inputs: &DetectionInputs<'_>,
    signing_key_id: &str,
) -> Result<PreparedDetection, SigningError> {
    let detection_id = Uuid::new_v4();
    let ts = Utc::now();
    let severity_persist = severity_to_persist(inputs.severity);
    let (variant, payload) = conformity_to_persist(inputs.conformity);

    let envelope = json!({
        "detection_id":                detection_id.to_string(),
        "trace_id":                    inputs.trace_id,
        "body_sha256_hex":             hex::encode(&inputs.body_sha256),
        "detector":                    inputs.detector,
        "severity":                    severity_persist.as_db_str(),
        "cohort_cell":                 inputs.cohort_cell,
        "conformity_variant":          variant.as_db_str(),
        "conformity_payload":          payload,
        "lens_core_version":           inputs.lens_core_version,
        "ratchet_calibration_version": inputs.ratchet_calibration_version,
        "evidence_refs":               inputs.evidence_refs,
        "signing_key_id":              signing_key_id,
        "ts":                          ts.to_rfc3339(),
    });

    let canonical_bytes = canonicalize_envelope_for_signing(&envelope)
        .map_err(|e| SigningError::Canonicalize(format!("{e}")))?;

    Ok(PreparedDetection {
        detection_id,
        ts,
        canonical_bytes,
        severity_persist,
        conformity_variant: variant,
        conformity_payload: payload,
        cohort_cell: envelope["cohort_cell"].clone(),
    })
}

/// Assemble the final [`DetectionEvent`] from prepared state + the
/// hybrid signature pair. Validates signature byte lengths. Both
/// paths converge here.
pub fn assemble_event(
    inputs: &DetectionInputs<'_>,
    prepared: PreparedDetection,
    ed25519_sig: Vec<u8>,
    ml_dsa_65_sig: Vec<u8>,
    signing_key_id: String,
) -> Result<(DetectionEvent, Summary), SigningError> {
    if ed25519_sig.len() != 64 {
        return Err(SigningError::SignatureShape {
            field: "ed25519_sig",
            actual: ed25519_sig.len(),
            expected: 64,
        });
    }
    if ml_dsa_65_sig.len() != 3309 {
        return Err(SigningError::SignatureShape {
            field: "ml_dsa_65_sig",
            actual: ml_dsa_65_sig.len(),
            expected: 3309,
        });
    }

    let event_hash = hex::encode(Sha256::digest(&prepared.canonical_bytes));

    let event = DetectionEvent {
        detection_id: prepared.detection_id,
        trace_id: inputs.trace_id.clone(),
        body_sha256: inputs.body_sha256.clone(),
        detector: inputs.detector.to_string(),
        severity: prepared.severity_persist,
        cohort_cell: prepared.cohort_cell,
        conformity_variant: prepared.conformity_variant,
        conformity_payload: prepared.conformity_payload,
        lens_core_version: inputs.lens_core_version.to_string(),
        ratchet_calibration_version: inputs.ratchet_calibration_version,
        canonical_bytes: prepared.canonical_bytes,
        ed25519_sig,
        ml_dsa_65_sig,
        signing_key_id,
        ts: prepared.ts,
    };

    let summary = Summary {
        detector: inputs.detector,
        severity: inputs.severity,
        event_hash,
    };

    Ok((event, summary))
}

/// Build a [`DetectionEvent`] from `inputs`, canonicalize the signed
/// envelope, hybrid-sign with `signer`, return the ready-to-persist
/// row alongside a lens-core summary. RLib path; the PyO3 path
/// composes [`prepare_detection`] + `Engine.local_sign` / `_pqc_sign`
/// + [`assemble_event`] directly.
///
/// Async because [`LocalSigner::sign_ml_dsa_65`] is async.
pub async fn sign_detection(
    signer: &LocalSigner,
    inputs: DetectionInputs<'_>,
) -> Result<(DetectionEvent, Summary), SigningError> {
    let prepared = prepare_detection(&inputs, signer.key_id())?;

    let ed25519_sig = signer.sign_ed25519(&prepared.canonical_bytes)?;
    let mut bound = Vec::with_capacity(prepared.canonical_bytes.len() + 64);
    bound.extend_from_slice(&prepared.canonical_bytes);
    bound.extend_from_slice(&ed25519_sig);
    let ml_dsa_65_sig = signer.sign_ml_dsa_65(&bound).await?;

    let signing_key_id = signer.key_id().to_string();
    assemble_event(
        &inputs,
        prepared,
        ed25519_sig.to_vec(),
        ml_dsa_65_sig,
        signing_key_id,
    )
}

fn severity_to_persist(s: Severity) -> DetectionSeverity {
    match s {
        Severity::Info => DetectionSeverity::Info,
        Severity::Warning => DetectionSeverity::Warning,
        Severity::Critical => DetectionSeverity::Critical,
    }
}

fn conformity_to_persist(c: &ManifoldConformity) -> (ConformityVariant, Value) {
    match c {
        ManifoldConformity::Numeric(score) => {
            (ConformityVariant::Numeric, json!({ "score": score }))
        }
        ManifoldConformity::Indeterminate { reason } => (
            ConformityVariant::Indeterminate,
            indeterminate_payload(reason),
        ),
        ManifoldConformity::Unavailable { reason } => {
            (ConformityVariant::Unavailable, unavailable_payload(reason))
        }
    }
}

fn indeterminate_payload(reason: &IndeterminateReason) -> Value {
    match reason {
        IndeterminateReason::CohortColdStart => json!({ "reason": "cohort_cold_start" }),
        IndeterminateReason::SampleSizeBelowGate { current, gate } => json!({
            "reason": "sample_size_below_gate",
            "current": current,
            "gate": gate,
        }),
        IndeterminateReason::InferredCohortAmbiguous => {
            json!({ "reason": "inferred_cohort_ambiguous" })
        }
        IndeterminateReason::AxisAwaitingCalibration { family } => json!({
            "reason": "axis_awaiting_calibration",
            "family": axis_family_str(*family),
        }),
    }
}

fn axis_family_str(t: crate::scoring::result::AxisFamily) -> &'static str {
    use crate::scoring::result::AxisFamily::*;
    match t {
        F3CorrelatedAction => "f3_correlated_action",
        DistributiveAccess => "distributive_access",
    }
}

fn unavailable_payload(reason: &UnavailableReason) -> Value {
    match reason {
        UnavailableReason::SloBreach { budget, observed } => json!({
            "reason": "slo_breach",
            "budget_ms": budget.as_millis() as u64,
            "observed_ms": observed.as_millis() as u64,
        }),
        UnavailableReason::PersistReadFailure => json!({ "reason": "persist_read_failure" }),
        UnavailableReason::DetectorPanic { detector } => json!({
            "reason": "detector_panic",
            "detector": detector,
        }),
        UnavailableReason::LocalSignFailure => json!({ "reason": "local_sign_failure" }),
        UnavailableReason::DegenerateCovariance => {
            json!({ "reason": "degenerate_covariance" })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn severity_maps_to_persist_db_strings() {
        assert_eq!(severity_to_persist(Severity::Info).as_db_str(), "info");
        assert_eq!(
            severity_to_persist(Severity::Warning).as_db_str(),
            "warning"
        );
        assert_eq!(
            severity_to_persist(Severity::Critical).as_db_str(),
            "critical"
        );
    }

    #[test]
    fn conformity_numeric_carries_score_in_payload() {
        let (variant, payload) = conformity_to_persist(&ManifoldConformity::Numeric(2.71));
        assert_eq!(variant, ConformityVariant::Numeric);
        assert_eq!(payload["score"], 2.71);
    }

    #[test]
    fn conformity_indeterminate_cold_start_payload() {
        let (variant, payload) = conformity_to_persist(&ManifoldConformity::Indeterminate {
            reason: IndeterminateReason::CohortColdStart,
        });
        assert_eq!(variant, ConformityVariant::Indeterminate);
        assert_eq!(payload["reason"], "cohort_cold_start");
    }

    #[test]
    fn conformity_indeterminate_sample_size_carries_numbers() {
        let (variant, payload) = conformity_to_persist(&ManifoldConformity::Indeterminate {
            reason: IndeterminateReason::SampleSizeBelowGate {
                current: 12,
                gate: 30,
            },
        });
        assert_eq!(variant, ConformityVariant::Indeterminate);
        assert_eq!(payload["reason"], "sample_size_below_gate");
        assert_eq!(payload["current"], 12);
        assert_eq!(payload["gate"], 30);
    }

    #[test]
    fn conformity_indeterminate_ambiguous() {
        let (_, payload) = conformity_to_persist(&ManifoldConformity::Indeterminate {
            reason: IndeterminateReason::InferredCohortAmbiguous,
        });
        assert_eq!(payload["reason"], "inferred_cohort_ambiguous");
    }

    #[test]
    fn conformity_unavailable_slo_breach_carries_durations() {
        let (variant, payload) = conformity_to_persist(&ManifoldConformity::Unavailable {
            reason: UnavailableReason::SloBreach {
                budget: Duration::from_millis(50),
                observed: Duration::from_millis(73),
            },
        });
        assert_eq!(variant, ConformityVariant::Unavailable);
        assert_eq!(payload["reason"], "slo_breach");
        assert_eq!(payload["budget_ms"], 50);
        assert_eq!(payload["observed_ms"], 73);
    }

    #[test]
    fn conformity_unavailable_persist_read_failure() {
        let (_, payload) = conformity_to_persist(&ManifoldConformity::Unavailable {
            reason: UnavailableReason::PersistReadFailure,
        });
        assert_eq!(payload["reason"], "persist_read_failure");
    }

    #[test]
    fn conformity_unavailable_detector_panic_carries_name() {
        let (_, payload) = conformity_to_persist(&ManifoldConformity::Unavailable {
            reason: UnavailableReason::DetectorPanic {
                detector: "manifold_conformity_outlier",
            },
        });
        assert_eq!(payload["reason"], "detector_panic");
        assert_eq!(payload["detector"], "manifold_conformity_outlier");
    }

    #[test]
    fn conformity_unavailable_local_sign_failure() {
        let (_, payload) = conformity_to_persist(&ManifoldConformity::Unavailable {
            reason: UnavailableReason::LocalSignFailure,
        });
        assert_eq!(payload["reason"], "local_sign_failure");
    }

    // -----------------------------------------------------------------
    // evidence_refs[] + CEG §15.2 R2 dual-hash transition discipline.
    // -----------------------------------------------------------------

    const SHIPPED_V2: &str = "/home/emoore/RATCHET/release/calibration/crc-v2/bundle.yaml";

    fn cal() -> Option<std::sync::Arc<AxisCalibration>> {
        let yaml = std::fs::read_to_string(SHIPPED_V2).ok()?;
        AxisCalibration::from_yaml(&yaml).ok()
    }

    #[test]
    fn evidence_refs_single_hash_outside_transition() {
        let Some(c) = cal() else {
            eprintln!("skipping: crc-v2 absent");
            return;
        };
        let axis = c.axis("distributive:access:compute").unwrap();
        let cohort = CohortDelineation::Members {
            cohort_id: "cohort_3".into(),
            member_agent_id_hashes: vec!["abc".into(), "def".into()],
        };
        let refs = build_axis_evidence_refs(
            &c,
            axis,
            "BUNDLEHASH",
            None, // not in a transition window
            "CORPUSHASH",
            &cohort,
        );
        // (1) active bundle hash, version-bound.
        assert!(refs.contains(&"crc-v2:bundle.sha256:BUNDLEHASH".to_string()));
        // No prior bundle hash outside a transition.
        assert!(!refs.iter().any(|r| r.contains("crc-v1:bundle.sha256")));
        // Corpus hashes present.
        assert!(refs
            .iter()
            .any(|r| r.starts_with("0612_prod_traces:trace_events.jsonl.gz:")));
        assert!(refs.contains(&"corpus_trace_events:CORPUSHASH".to_string()));
        // Cohort delineation present.
        assert!(refs.contains(&"cohort_delineation:cohort_id:cohort_3".to_string()));
        assert!(refs.contains(&"cohort_member:abc".to_string()));
        // Axis-specific evidence fields.
        assert!(refs.contains(&"evidence_required:per_agent_cost_usd_aggregate".to_string()));
    }

    #[test]
    fn evidence_refs_dual_hash_during_transition() {
        let Some(c) = cal() else {
            return;
        };
        let axis = c.axis("distributive:access:compute").unwrap();
        let cohort = CohortDelineation::AlgorithmVersion("kmeans-20260612".into());
        // During a crc-v2 → crc-v3 transition the consumer also holds
        // the prior (crc-v1) bundle hash; per CEG §15.2 R2 we emit BOTH.
        let refs =
            build_axis_evidence_refs(&c, axis, "V2HASH", Some("V1HASH"), "CORPUSHASH", &cohort);
        assert!(refs.contains(&"crc-v2:bundle.sha256:V2HASH".to_string()));
        // supersedes == "crc-v1" → prior hash emitted under that version.
        assert!(refs.contains(&"crc-v1:bundle.sha256:V1HASH".to_string()));
        // Algorithm-version cohort delineation.
        assert!(refs.contains(&"cohort_derivation_algorithm:kmeans-20260612".to_string()));
    }

    #[test]
    fn evidence_refs_bound_into_signed_envelope() {
        // The refs must land in the canonical (signed) envelope so the
        // attestation cites them under signature.
        let conformity = ManifoldConformity::Numeric(-0.6);
        let inputs = DetectionInputs {
            trace_id: "t1".into(),
            body_sha256: vec![0u8; 32],
            detector: "distributive_access",
            severity: Severity::Warning,
            cohort_cell: json!({ "agent_role": null }),
            conformity: &conformity,
            lens_core_version: "x",
            ratchet_calibration_version: 2,
            evidence_refs: vec![
                "crc-v2:bundle.sha256:AAA".into(),
                "crc-v1:bundle.sha256:BBB".into(),
            ],
        };
        let prepared = prepare_detection(&inputs, "key-1").unwrap();
        let envelope: Value = serde_json::from_slice(&prepared.canonical_bytes).unwrap();
        let refs = envelope["evidence_refs"].as_array().unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0], "crc-v2:bundle.sha256:AAA");
        assert_eq!(refs[1], "crc-v1:bundle.sha256:BBB");
    }
}
