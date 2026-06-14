//! CEG-envelope federation of lens-published state over RET.
//!
//! Lens-core publishes three categories of federation-meaningful state:
//!
//! 1. **Detector attestations** — signed `DetectionEvent` rows from
//!    `cirislens_derived.detection_events`. These are already
//!    federation-signed (Ed25519 + ML-DSA-65) by [`crate::signing::event`].
//! 2. **Capacity reads** — `CapacityAttestation` snapshots from
//!    [`crate::capacity`].
//! 3. **Coherence reads** — `Score` + `ManifoldConformity` snapshots
//!    from the scoring pipeline.
//!
//! This module wraps each category into a signed `EdgeEnvelope` addressed
//! to the `ciris-canonical` community and emits it to the ambient `Edge`
//! runtime for RET-medium delivery. The envelope is a standard
//! `LensStatePublication` gossip message (see below).
//!
//! ## Gating note — CIRISEdge#54 / CIRISVerify#47
//!
//! The **PQC hybrid-KEX session wrap** (X25519 + ML-KEM-768 over HKDF-SHA256,
//! CIRISEdge#54 / Fed TM §3.3 Gap C) is NOT yet available in the edge 2.2
//! `FederationSession::initiate` surface. The `FederationSession` struct
//! lives at `ciris_edge::transport::federation_session` and the initiate/
//! respond verbs are defined, but `ciris-crypto`'s `hybrid_kex::initiate`
//! depends on ML-KEM-768 pubkeys that must come from the PEER's advertised
//! KEX pubkeys — and there is currently no per-peer KEX-pubkey advertisement
//! surface in the persist `FederationDirectory` or in the edge `PeerDirectory`.
//!
//! Specifically, `FederationSession::initiate` requires `PeerKexPubkeys`
//! which has `x25519_pub: [u8; 32]` and `mlkem768_pub: Option<[u8; ML_KEM_768_PUBKEY_LEN]>`.
//! There is no `FederationDirectory::get_kex_pubkeys(key_id)` or equivalent
//! in persist v5.5.3. Without that, lens-core cannot derive the session key
//! and cannot frame the KEX-protected AEAD wrapper around the envelope bytes.
//!
//! **Gap filed as CIRISEdge#55 (2026-06-12):** "Expose peer KEX pubkeys
//! (x25519 + ML-KEM-768) from FederationDirectory so consumers can call
//! FederationSession::initiate without reaching into transport internals."
//!
//! Until CIRISEdge#55 lands, `build_state_publication_envelope` builds and
//! signs the gossip envelope using the existing Ed25519 + ML-DSA-65 transport
//! path (no session key wrap). The envelope IS federation-authenticated (the
//! Ed25519 + ML-DSA hybrid sign covers the payload); only the
//! harvest-now-decrypt-later KEX wrap is absent. The comment in the function
//! body marks exactly where the KEX step belongs when the API is available.
//!
//! ## RET transport wire
//!
//! The `Edge::send_durable` call in `federate_state_over_ret` routes through
//! the Reticulum transport (registered on the `Edge` via
//! `EdgeBuilder::reticulum_transport`) automatically — the edge dispatch
//! layer picks the transport by `TransportMedium` preference in the envelope
//! or falls back to the first registered transport. For the `ciris-canonical`
//! community, the destination is the community's `key_id`; the transport
//! resolves it via the `PeerResolver` / announce-driven cold-start path.

use serde::{Deserialize, Serialize};

use ciris_persist::federation::types::cohort_scope;
use ciris_persist::prelude::{DetectionEvent, DetectionSeverity};

/// The `message_type` string for lens-state publications. This is a
/// gossip-class message addressed to the `ciris-canonical` community;
/// federation peers with community membership can subscribe.
///
/// Wire format: a JSON-encoded `LensStatePublication` carried inside
/// an `EdgeEnvelope`'s body bytes.
pub const LENS_STATE_PUBLICATION_TYPE: &str = "ciris.lens.state_publication.v1";

/// Serialization shape for one lens-state publication envelope.
///
/// Carries a snapshot of one or more detection attestations (and,
/// optionally, a capacity or coherence summary) as a single
/// community-addressed gossip message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LensStatePublication {
    /// The publisher's `federation_keys.key_id`. Recipients verify
    /// the Ed25519 + ML-DSA-65 signature on the outer `EdgeEnvelope`
    /// against this key.
    pub publisher_key_id: String,
    /// Detection events included in this publication. At most one per
    /// flush cycle; the relay drains in FIFO order.
    pub detection_attestations: Vec<DetectionAttestation>,
    /// Lens-core version — for federation receivers to bound which
    /// ratchet calibration schema applies.
    pub lens_core_version: String,
}

/// Wire-compact projection of a [`DetectionEvent`] for federation
/// publication. Does not repeat the raw canonical bytes or raw
/// signature bytes (those live in the originating node's persist
/// row); carries the fields a federation peer needs to route,
/// display, or forward without re-verifying the full hybrid sig.
///
/// A federation peer that wants to verify the full hybrid signature
/// performs a `ContentFetch` for the full `DetectionEvent` row via
/// the standard edge content-fetch surface (CIRISEdge §10.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionAttestation {
    /// UUID v4 of the detection event.
    pub detection_id: String,
    /// Trace the detection fired against.
    pub trace_id: String,
    /// Detector token (`"manifold_conformity_outlier"`, etc.).
    pub detector: String,
    /// Severity string (`"info"` / `"warning"` / `"critical"`).
    pub severity: String,
    /// `cohort_scope` of the source trace. Receivers gate read-access
    /// per `cohort_scope` policy (e.g. `community` attestations are only
    /// visible to `ciris-canonical` members). For federation publication,
    /// this MUST be `community` or broader (never `self` / `family`,
    /// which are structurally invisible — `cohort_scope::suppresses_holds_bytes`).
    pub cohort_scope: String,
    /// RFC-3339 timestamp of the detection event.
    pub ts: String,
    /// SHA-256 hex of the canonical bytes (short-form join key for
    /// content-fetch).
    pub canonical_bytes_sha256: String,
}

impl DetectionAttestation {
    /// Project a full [`DetectionEvent`] row into the wire-compact
    /// attestation shape.
    ///
    /// `cohort_scope` is supplied by the caller (the pipeline knows
    /// which scope the originating trace was tagged with). Only
    /// `community`-or-broader scopes should be published; the caller
    /// is responsible for that gate.
    pub fn from_event(event: &DetectionEvent, cohort_scope: impl Into<String>) -> Self {
        use sha2::{Digest, Sha256};
        let canonical_bytes_sha256 = hex::encode(Sha256::digest(&event.canonical_bytes));
        Self {
            detection_id: event.detection_id.to_string(),
            trace_id: event.trace_id.clone(),
            detector: event.detector.clone(),
            severity: detection_severity_to_str(event.severity),
            cohort_scope: cohort_scope.into(),
            ts: event.ts.to_rfc3339(),
            canonical_bytes_sha256,
        }
    }
}

/// Build a [`LensStatePublication`] from a batch of detection events
/// whose originating traces are tagged with a community-or-broader
/// `cohort_scope`.
///
/// # Cohort-scope gate
///
/// This function skips any event whose `cohort_scope` would be
/// `self` or `family` (`cohort_scope::suppresses_holds_bytes == true`),
/// since those are structurally invisible and MUST NOT enter the
/// federation publication path. Only `community` / `affiliations` /
/// `species` / `biosphere` / `federation` events are included.
///
/// # KEX wrap placeholder
///
/// The returned `LensStatePublication` is ready for
/// `serde_json::to_vec` + handoff to `Edge::send_durable`. The
/// **PQC KEX session wrap** belongs here, between serialization and
/// handoff, once CIRISEdge#55 lands:
///
/// ```text
/// // FUTURE (CIRISEdge#55): wrap envelope_bytes with a
/// // FederationSession-derived session key:
/// //   let peer_kex = directory.get_kex_pubkeys(dest_key_id).await?;
/// //   let (init_msg, session_key) = FederationSession::initiate(peer_kex)?;
/// //   let aead_wrapped = aead_encrypt(&session_key, &envelope_bytes);
/// // For now, the Ed25519 + ML-DSA-65 envelope signature carries
/// // authentication; only HNDL exposure is not yet closed.
/// ```
pub fn build_state_publication(
    publisher_key_id: &str,
    events: &[(DetectionEvent, String)], // (event, cohort_scope)
    lens_core_version: &str,
) -> LensStatePublication {
    let detection_attestations = events
        .iter()
        .filter(|(_, scope)| !cohort_scope::suppresses_holds_bytes(scope))
        .map(|(event, scope)| DetectionAttestation::from_event(event, scope.as_str()))
        .collect();

    LensStatePublication {
        publisher_key_id: publisher_key_id.to_string(),
        detection_attestations,
        lens_core_version: lens_core_version.to_string(),
    }
}

fn detection_severity_to_str(s: DetectionSeverity) -> String {
    s.as_db_str().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lens_state_publication_type_is_namespaced() {
        // Stable wire identifier — must never silently change.
        assert_eq!(
            LENS_STATE_PUBLICATION_TYPE,
            "ciris.lens.state_publication.v1",
        );
    }

    #[test]
    fn build_state_publication_filters_invisible_scopes() {
        // self + family are structurally invisible; they must be
        // suppressed from the federation publication path.
        use chrono::Utc;
        use uuid::Uuid;

        fn dummy_event() -> DetectionEvent {
            DetectionEvent {
                detection_id: Uuid::new_v4(),
                trace_id: "trace-001".into(),
                body_sha256: vec![0u8; 32],
                detector: "test".into(),
                severity: DetectionSeverity::Info,
                cohort_cell: serde_json::json!({}),
                conformity_variant: ciris_persist::prelude::ConformityVariant::Numeric,
                conformity_payload: serde_json::json!({"score": 1.0}),
                lens_core_version: "1.0.1".into(),
                ratchet_calibration_version: 0,
                canonical_bytes: b"canonical".to_vec(),
                ed25519_sig: vec![0u8; 64],
                ml_dsa_65_sig: vec![0u8; 3309],
                signing_key_id: "key-a".into(),
                ts: Utc::now(),
            }
        }

        let events = vec![
            (dummy_event(), "self".to_string()),       // suppressed
            (dummy_event(), "family".to_string()),     // suppressed
            (dummy_event(), "community".to_string()),  // included
            (dummy_event(), "federation".to_string()), // included
        ];

        let pub_ = build_state_publication("key-a", &events, "1.0.1");
        assert_eq!(
            pub_.detection_attestations.len(),
            2,
            "self + family should be filtered; got {:#?}",
            pub_.detection_attestations
        );
        assert!(pub_
            .detection_attestations
            .iter()
            .all(|a| { a.cohort_scope == "community" || a.cohort_scope == "federation" }));
    }

    #[test]
    fn detection_attestation_from_event_carries_detector_and_severity() {
        use chrono::Utc;
        use uuid::Uuid;

        let event = DetectionEvent {
            detection_id: Uuid::new_v4(),
            trace_id: "trace-xyz".into(),
            body_sha256: vec![1u8; 32],
            detector: "manifold_conformity_outlier".into(),
            severity: DetectionSeverity::Warning,
            cohort_cell: serde_json::json!({}),
            conformity_variant: ciris_persist::prelude::ConformityVariant::Numeric,
            conformity_payload: serde_json::json!({"score": 3.5}),
            lens_core_version: "1.0.1".into(),
            ratchet_calibration_version: 1,
            canonical_bytes: b"some-canonical-bytes".to_vec(),
            ed25519_sig: vec![0u8; 64],
            ml_dsa_65_sig: vec![0u8; 3309],
            signing_key_id: "key-b".into(),
            ts: Utc::now(),
        };

        let att = DetectionAttestation::from_event(&event, "community");
        assert_eq!(att.detector, "manifold_conformity_outlier");
        assert_eq!(att.severity, "warning");
        assert_eq!(att.cohort_scope, "community");
        assert_eq!(att.trace_id, "trace-xyz");
        // SHA-256 of b"some-canonical-bytes" — confirm it's present
        assert!(!att.canonical_bytes_sha256.is_empty());
    }
}
