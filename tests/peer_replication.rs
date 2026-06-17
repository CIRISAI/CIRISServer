//! Directed-consent federation peering — Node A side (CIRISServer federation
//! Round 2, deliverable 4).
//!
//! Node A is in the canonical CIRIS infrastructure community; Node B
//! (`ciris-status`) is OUT of it. Bidirectional replication A<->B is authorized
//! by DIRECTED CONSENT + MUTUAL KEY REGISTRATION, not in-group trust. This test
//! proves the two directory-level halves Node A owns:
//!
//!   1. **Admission** — with B's witness key registered (via
//!      `peer::register_peer_key`), a B-signed `health:liveness:v1` attestation
//!      fed through the directory `put_attestation` (exactly what the inbound
//!      replication route applies B's frames into) lands ADMITTED in A's corpus,
//!      readable back by `list_attestations_by(B)`. A control with B's key NOT
//!      registered is REJECTED at the FK gate — proving registration is the real
//!      admission door, not a rubber stamp.
//!   2. **Consent** — `peer::emit_replication_consent` writes the directed
//!      `consent:replication:v1` `scores` row (subject = [B], federation tier),
//!      and is idempotent on re-run.
//!
//! ## Transport-path honesty
//!
//! The full Reticulum round-trip (B's edge → A's edge inbound loop →
//! `install_replication_routing` → `ReplicationRegistry::route_inbound_bytes` →
//! coordinator → directory apply) is **integration-only**: `Edge::run` owns the
//! `Transport::listen` loop, so exercising it needs two live Reticulum stacks
//! in-process (covered by edge's own replication round-trip tests). This test
//! drives the directory-level admission + consent-emit logic directly — the same
//! `put_attestation` admit surface the routed coordinator ultimately calls — so
//! the Node-A logic is proven without standing up the transport.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::types::{
    algorithm, attestation_tier, attestation_type, identity_type, Attestation, KeyRecord,
    SignedAttestation, SignedKeyRecord,
};
use ciris_persist::prelude::{canonicalize_envelope_for_signing, Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

use ciris_server::peer::{self, CONSENT_DIMENSION};
use ciris_server::PeerB;

const NODE_A_KEY_ID: &str = "ciris-server";
const NODE_B_KEY_ID: &str = "ciris-status";
/// B's `health:liveness:v1` names a keyed CIRIS service as its subject — here A
/// itself (B witnesses A's liveness). Registered so the attested-key FK resolves.
const SERVICE_KEY_ID: &str = "ciris-server";

/// Stand up Node A: in-memory substrate keyed by a HYBRID node-identity signer
/// (Ed25519 + ML-DSA-65 software seed) so `sign_hybrid` (the consent emit) works.
/// Mirrors `tests/capacity_scorer.rs::node_a`.
async fn node_a() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_A_KEY_ID}-pqc"))
            .expect("node-a ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_A_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_A_KEY_ID}-pqc")),
    ));
    let engine = Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("Engine::with_signer (sqlite::memory:) must succeed");
    Arc::new(engine)
}

/// Node B's published hybrid identity (the bytes A's config would carry in the
/// `CIRIS_PEER_B_*` env). Real keys so the registration is genuine + the
/// `health:liveness` row is genuinely B-signed.
struct NodeB {
    ed: SigningKey,
    mldsa: MlDsa65SoftwareSigner,
}

impl NodeB {
    fn new() -> Self {
        NodeB {
            ed: SigningKey::from_bytes(&[0xB0; 32]),
            mldsa: MlDsa65SoftwareSigner::from_seed_bytes(
                &[0xB1; 32],
                format!("{NODE_B_KEY_ID}-pqc"),
            )
            .expect("node-b ML-DSA-65 seed"),
        }
    }

    /// B's *self-signed* `SignedKeyRecord` (proof-of-possession) — the v8.8.0
    /// admission-gate shape A's config now carries (the deserialized
    /// `CIRIS_PEER_B_KEY_RECORD`). B signs the registration envelope with its OWN
    /// hybrid keys (`scrub_key_id == key_id`), over `ceg_produce_canonicalize`,
    /// PQC bound over `canonical || ed_sig` (exactly what `verify_hybrid` checks).
    async fn signed_key_record(&self) -> ciris_persist::federation::types::SignedKeyRecord {
        use ciris_persist::federation::types::{
            algorithm, identity_type, KeyRecord, SignedKeyRecord,
        };

        let now = chrono::Utc::now();
        let envelope = serde_json::json!({ "key_id": NODE_B_KEY_ID });
        let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize B registration");
        let original_content_hash = hex::encode(Sha256::digest(&canonical));

        // Ed25519 over canonical; ML-DSA-65 over the BOUND input (canonical || ed_sig).
        let ed_sig = self.ed.sign(&canonical).to_bytes();
        let mut bound = Vec::with_capacity(canonical.len() + ed_sig.len());
        bound.extend_from_slice(&canonical);
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = self.mldsa.sign(&bound).await.expect("ml-dsa sign B reg");

        let record = KeyRecord {
            key_id: NODE_B_KEY_ID.to_string(),
            pubkey_ed25519_base64: BASE64.encode(self.ed.verifying_key().to_bytes()),
            pubkey_ml_dsa_65_base64: Some(
                BASE64.encode(self.mldsa.public_key().await.expect("ml-dsa pk")),
            ),
            algorithm: algorithm::HYBRID.into(),
            // B (ciris-status) speaks ABOUT services as an external witness.
            identity_type: identity_type::WITNESS.into(),
            identity_ref: NODE_B_KEY_ID.to_string(),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash,
            scrub_signature_classical: BASE64.encode(ed_sig),
            scrub_signature_pqc: Some(BASE64.encode(&pqc_sig)),
            // Self-signed proof-of-possession: scrub_key_id == key_id.
            scrub_key_id: NODE_B_KEY_ID.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
        };
        SignedKeyRecord { record }
    }

    /// The peer-config A registers B from (v8.8.0: B's self-signed record).
    async fn peer_config(&self) -> PeerB {
        PeerB {
            key_id: NODE_B_KEY_ID.to_string(),
            key_record: self.signed_key_record().await,
        }
    }

    /// Build a genuinely B-signed `health:liveness:v1` `scores` attestation — the
    /// SAME shape ciris-status (`src/ceg.rs::LivenessEnvelope`) emits and what the
    /// inbound replication route applies into A's corpus via `put_attestation`.
    async fn liveness_for(&self, subject_key_id: &str) -> SignedAttestation {
        let now = chrono::Utc::now();
        let valid_until = now + chrono::Duration::minutes(5);
        let envelope = serde_json::json!({
            "dimension": "health:liveness:v1",
            "score": 1.0,
            "confidence": 1.0,
            "context": "US (Chicago) — billing+proxy",
            "valid_until": valid_until.to_rfc3339(),
            "epistemic_mode": "direct",
            "witness_relation": "external",
            "stake": "reputational",
            "attested_key_id": subject_key_id,
        });
        let canonical =
            canonicalize_envelope_for_signing(&envelope).expect("canonicalize liveness envelope");
        let original_content_hash = hex::encode(Sha256::digest(&canonical));
        let ed_sig = self.ed.sign(&canonical).to_bytes();
        let pqc_sig = self
            .mldsa
            .sign(&canonical)
            .await
            .expect("ml-dsa sign liveness");

        let attestation = Attestation {
            attestation_id: "b-liveness-0001".to_string(),
            attesting_key_id: NODE_B_KEY_ID.to_string(),
            attested_key_id: subject_key_id.to_string(),
            attestation_type: attestation_type::SCORES.to_string(),
            weight: Some(1.0),
            asserted_at: now,
            expires_at: Some(valid_until),
            attestation_envelope: envelope,
            original_content_hash,
            scrub_signature_classical: BASE64.encode(ed_sig),
            scrub_signature_pqc: Some(BASE64.encode(pqc_sig)),
            scrub_key_id: NODE_B_KEY_ID.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            subject_key_ids: vec![subject_key_id.to_string()],
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
            tier: attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
        };
        SignedAttestation { attestation }
    }
}

/// Register Node A's own steward key via the v8.8.0 canonical admission gate
/// (`Engine::register_federation_key`) — the `put_attestation` attesting-key FK
/// precondition for the consent emit. Self-signed proof-of-possession over
/// `ceg_produce_canonicalize` (the form the gate verifies). Mirrors
/// `compose::register_self_key`.
async fn register_self(engine: &Engine) {
    let now = chrono::Utc::now();
    // A self-signed steward row; pubkeys from the node's own hybrid signer.
    // CEG produce-canonical (V2/JCS) so it matches verify_key_registration.
    let envelope = serde_json::json!({ "key_id": NODE_A_KEY_ID });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize self envelope");
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .expect("self hybrid sign");
    let record = KeyRecord {
        key_id: NODE_A_KEY_ID.to_string(),
        pubkey_ed25519_base64: BASE64.encode(&sig.classical.public_key),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(&sig.pqc.public_key)),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::STEWARD.into(),
        identity_ref: NODE_A_KEY_ID.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: NODE_A_KEY_ID.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .register_federation_key(SignedKeyRecord { record })
        .await
        .expect("register node A steward key via admission gate");
}

/// The full Node-A directed-consent peering spine: register B's witness key →
/// admit a B-signed health:liveness into A's corpus → emit + verify the directed
/// consent grant (idempotently).
#[tokio::test]
async fn peer_b_registered_admits_b_liveness_and_a_emits_directed_consent() {
    let engine = node_a().await;
    register_self(&engine).await;

    let node_b = NodeB::new();
    let peer = node_b.peer_config().await;

    // ── 1. Admission: register B's witness key ───────────────────────────────
    peer::register_peer_key(&engine, &peer)
        .await
        .expect("register Node B witness key");

    // Re-registration of the identical key is a benign no-op (idempotent).
    peer::register_peer_key(&engine, &peer)
        .await
        .expect("re-register B key is benign/idempotent");

    let b_key = engine
        .federation_directory()
        .lookup_public_key(NODE_B_KEY_ID)
        .await
        .expect("lookup B key")
        .expect("B key present after registration");
    assert_eq!(
        b_key.identity_type,
        identity_type::WITNESS,
        "B must be registered as a witness"
    );

    // ── B's health:liveness:v1 lands ADMITTED in A's corpus ──────────────────
    // (the directory put the routed replication coordinator ultimately calls).
    engine
        .federation_directory()
        .put_attestation(node_b.liveness_for(SERVICE_KEY_ID).await)
        .await
        .expect("B-signed health:liveness must be admitted into A's corpus");

    let by_b = engine
        .federation_directory()
        .list_attestations_by(NODE_B_KEY_ID)
        .await
        .expect("list attestations by B");
    assert_eq!(by_b.len(), 1, "exactly one B-attested row admitted");
    assert_eq!(
        by_b[0]
            .attestation_envelope
            .get("dimension")
            .and_then(|d| d.as_str()),
        Some("health:liveness:v1"),
        "the admitted row is B's health:liveness"
    );

    // ── 2. Consent: A emits the directed consent:replication:v1 grant at B ────
    let emitted = peer::emit_replication_consent(&engine, NODE_A_KEY_ID, NODE_B_KEY_ID)
        .await
        .expect("emit replication consent");
    assert!(emitted, "first emit must write a fresh grant row");

    // The directed consent row exists: scores, subject = [B], federation tier.
    let by_a = engine
        .federation_directory()
        .list_attestations_by(NODE_A_KEY_ID)
        .await
        .expect("list attestations by A");
    let grant = by_a
        .iter()
        .find(|a| {
            a.attestation_envelope
                .get("dimension")
                .and_then(|d| d.as_str())
                == Some(CONSENT_DIMENSION)
        })
        .expect("A must have a consent:replication:v1 grant");
    assert_eq!(grant.attestation_type, attestation_type::SCORES);
    assert_eq!(grant.attesting_key_id, NODE_A_KEY_ID);
    assert_eq!(
        grant.subject_key_ids,
        vec![NODE_B_KEY_ID.to_string()],
        "consent must be DIRECTED at the SINGLE recipient B (subject_key_ids = [B])"
    );
    assert_eq!(grant.tier, attestation_tier::FEDERATION);
    assert_eq!(grant.cohort_scope, "federation");

    let env = &grant.attestation_envelope;
    // ── RC29 LOCKED shape (CEG §5.6.8.15) ────────────────────────────────────
    // ENVELOPE: positive score (magnitude not load-bearing).
    assert!(
        env.get("score").and_then(|s| s.as_f64()).unwrap_or(0.0) > 0.0,
        "score must be positive"
    );
    // ENVELOPE: witness_relation = "self" (REQUIRED — forecloses third-party forgery).
    assert_eq!(
        env.get("witness_relation").and_then(|w| w.as_str()),
        Some("self"),
        "witness_relation MUST be \"self\" (G attests its own replication intent)"
    );
    // ENVELOPE: topical_relation = "bilateral_pair" (SHOULD — pair A→B with B→A).
    assert_eq!(
        env.get("topical_relation").and_then(|t| t.as_str()),
        Some("bilateral_pair"),
        "topical_relation SHOULD be \"bilateral_pair\""
    );
    assert_eq!(
        env.get("cohort_scope").and_then(|c| c.as_str()),
        Some("federation")
    );
    // PAYLOAD: subject_kind = "consent_replication" (§4.2.2.3 payload member).
    assert_eq!(
        env.get("subject_kind").and_then(|s| s.as_str()),
        Some("consent_replication"),
        "subject_kind payload member MUST be \"consent_replication\""
    );
    let payload = env.get("payload").expect("payload member present");
    // PAYLOAD: grants = "replication" (constant).
    assert_eq!(
        payload.get("grants").and_then(|g| g.as_str()),
        Some("replication"),
        "payload.grants MUST be the constant \"replication\""
    );
    // PAYLOAD: attestation_prefixes = sorted-ascending + deduplicated JCS array.
    let prefixes: Vec<String> = payload
        .get("attestation_prefixes")
        .and_then(|p| p.as_array())
        .expect("attestation_prefixes array present")
        .iter()
        .map(|v| v.as_str().expect("prefix is a string").to_string())
        .collect();
    assert_eq!(
        prefixes,
        vec!["capacity:".to_string()],
        "attestation_prefixes carries A's replicated namespace prefixes (trailing ':')"
    );
    let mut sorted_dedup = prefixes.clone();
    sorted_dedup.sort();
    sorted_dedup.dedup();
    assert_eq!(
        prefixes, sorted_dedup,
        "attestation_prefixes MUST be sorted ascending + deduplicated (byte-for-byte agreement)"
    );

    // ── Idempotency: a second emit is a no-op (no duplicate grant row) ────────
    let again = peer::emit_replication_consent(&engine, NODE_A_KEY_ID, NODE_B_KEY_ID)
        .await
        .expect("second emit must not error");
    assert!(!again, "re-emit must be a guarded no-op");
    let grants = engine
        .federation_directory()
        .list_attestations_by(NODE_A_KEY_ID)
        .await
        .expect("re-list attestations by A")
        .into_iter()
        .filter(|a| {
            a.attestation_envelope
                .get("dimension")
                .and_then(|d| d.as_str())
                == Some(CONSENT_DIMENSION)
        })
        .count();
    assert_eq!(grants, 1, "exactly one consent grant after re-emit");
}

/// Control: WITHOUT registering B's key, a B-signed health:liveness is REJECTED
/// at the FK admission gate — proving mutual key registration is the real
/// admission door (not a rubber stamp).
#[tokio::test]
async fn unregistered_peer_liveness_is_rejected() {
    let engine = node_a().await;
    register_self(&engine).await;

    let node_b = NodeB::new();
    // Deliberately DO NOT register B's key.
    let res = engine
        .federation_directory()
        .put_attestation(node_b.liveness_for(SERVICE_KEY_ID).await)
        .await;
    let err = res.expect_err("unregistered-peer attestation must be rejected");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("does not exist") || msg.contains("InvalidArgument"),
        "rejection must be the attesting-key FK gate, got: {msg}"
    );
}

/// v8.8.0 fail-secure: a FORGED / unverifiable peer `SignedKeyRecord` (the
/// signature does not match the registration envelope) is REJECTED by
/// `register_peer_key` → `register_federation_key`'s verify, and the key is NOT
/// stored — so the forger's replicated rows can never be admitted. A can no
/// longer mint a peer key from raw pubkeys; the security check is B's signature.
#[tokio::test]
async fn forged_peer_record_is_rejected_and_not_stored() {
    let engine = node_a().await;
    register_self(&engine).await;

    let node_b = NodeB::new();
    let mut peer = node_b.peer_config().await;

    // Tamper: flip the registration envelope AFTER signing so the carried
    // signature no longer covers it. Keep original_content_hash consistent with
    // the NEW envelope so the failure surfaces as the (stronger) signature-
    // mismatch guard, not just the hash cross-check.
    peer.key_record.record.registration_envelope = serde_json::json!({
        "key_id": NODE_B_KEY_ID,
        "purpose": "FORGED",
    });
    let new_canonical = ceg_produce_canonicalize(&peer.key_record.record.registration_envelope)
        .expect("canonicalize forged envelope");
    peer.key_record.record.original_content_hash = hex::encode(Sha256::digest(&new_canonical));

    let err = peer::register_peer_key(&engine, &peer)
        .await
        .expect_err("forged peer record must be rejected by the fail-secure admission gate");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("verify") || msg.contains("signature") || msg.contains("invalid"),
        "rejection must be the registration verify gate, got: {msg}"
    );

    // Fail-secure: the forged key is NOT in the directory.
    let looked_up = engine
        .federation_directory()
        .lookup_public_key(NODE_B_KEY_ID)
        .await
        .expect("lookup B key");
    assert!(
        looked_up.is_none(),
        "a rejected (forged) registration must leave NO directory row"
    );
}
