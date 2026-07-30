//! **Standing witness for persist's federation-tier ingest gate** (CIRISServer#327 §2).
//!
//! # Why this test exists
//!
//! Persist admits a `tier = federation` Attestation only if it satisfies
//! [`verify_federation_tier_ingest`] (persist `federation/tier_ingest.rs`, the gate
//! introduced in persist v9.0.0 / CIRISPersist#237 and unchanged across the whole
//! v21 line). A federation-tier row MUST carry:
//!
//!   1. `SHA256(ceg_produce_canonicalize(envelope)) == original_content_hash`
//!      (canonicalizer agreement — fail-secure),
//!   2. an `attesting_key_id` REGISTERED in the directory, resolving BOTH an
//!      Ed25519 and an ML-DSA-65 public key (an unknown attester is rejected),
//!   3. a valid HYBRID signature under `HybridPolicy::Strict` — Ed25519 over
//!      JCS(envelope) AND ML-DSA-65 over the bound `JCS(envelope)‖ed25519_sig`.
//!      There is no `require_hybrid: false` posture: a classical-only or
//!      hybrid-pending (`scrub_signature_pqc: None`) federation-tier row is
//!      REFUSED (CC 5.3.2.4.3.1). Local-tier rows are exempt.
//!
//! Failure raises `Error::FederationTierUnverified`, whose stable `kind()` token is
//! `federation_federation_tier_unverified`.
//!
//! # The gap this closes
//!
//! Before this file, the server exercised that gate only TRANSITIVELY — every
//! producer path runs `put_attestation`, which runs the gate — so a regression
//! surfaced as an unrelated integration failure with a confusing message, and
//! nothing pinned the gate's server-side behaviour in isolation. The persist
//! v21.10.0 adoption (CIRISServer#327) turned on this exact question and could
//! only answer it by reading source, which is precisely the kind of claim that
//! should be a test instead.
//!
//! # What is pinned
//!
//! * **POSITIVE** — the server's real `consent:replication:v1` producer
//!   ([`ciris_server::peer::emit_replication_consent`]) emits a federation-tier row
//!   that ADMITS. This holds by construction because the producer rides
//!   `Engine::emit_attestation_self`, which canonicalizes ONCE and uses the same
//!   bytes it hashes for `original_content_hash` and hybrid-signs, then stamps both
//!   scrub signatures — so it is structurally incapable of emitting a
//!   classical-only row. "By construction" is exactly the kind of claim that rots
//!   silently, hence the pin.
//! * **NEGATIVE** — a hand-assembled `tier = federation` row with
//!   `scrub_signature_pqc: None` is REFUSED with `federation_federation_tier_unverified`.
//!   This proves the gate is live in THIS build rather than vacuously passing, so
//!   the positive assertion above means something.
//!
//! If the negative ever passes, the hybrid-mandatory posture has been weakened
//! somewhere in the substrate and every "hybrid by construction" claim in this repo
//! needs re-verification.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_keyring::PqcSigner as _;
use ciris_persist::federation::types::{algorithm, attestation_tier, identity_type};
use ciris_persist::federation::types::{Attestation, SignedAttestation};
use ciris_persist::federation::{FederationDirectory as _, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};

/// A node whose LocalSigner is hybrid (Ed25519 + ML-DSA-65) — the shape every real
/// server node boots with. Returns the engine and its DERIVED federation key_id
/// (CIRISPersist#247: the derived `<label>-<fp>` id, NOT the keystore alias — the
/// distinction 0.5.138 closed an identity-fork class over).
async fn hybrid_node() -> (Arc<Engine>, String) {
    const ALIAS: &str = "witness-node";
    let signing_key = SigningKey::from_bytes(&[0xC1; 32]);
    let ed_pub_b64 = BASE64.encode(signing_key.verifying_key().to_bytes());
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xC2; 32], format!("{ALIAS}-pqc"))
            .expect("ML-DSA-65 software signer from seed"),
    );
    let mldsa_pub_b64 = BASE64.encode(pqc.public_key().await.expect("ML-DSA-65 pubkey"));

    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        ALIAS.to_string(),
        Some(pqc),
        Some(format!("{ALIAS}-pqc")),
    ));
    let engine = Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer (sqlite::memory:)"),
    );

    let key_id = engine
        .local_derived_key_id()
        .await
        .expect("derive local federation key_id");

    // Requirement (2): the attester must be REGISTERED with BOTH pubkeys before any
    // federation-tier emit. In production this is `compose::register_self_key`,
    // ordered ahead of every emit at boot.
    put_hybrid_key(
        &engine,
        &key_id,
        &ed_pub_b64,
        Some(&mldsa_pub_b64),
        identity_type::NODE,
    )
    .await;

    (engine, key_id)
}

async fn put_hybrid_key(
    engine: &Engine,
    key_id: &str,
    ed_pubkey_b64: &str,
    mldsa_pubkey_b64: Option<&str>,
    id_type: &str,
) {
    let now = chrono::Utc::now();
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: ed_pubkey_b64.to_string(),
        pubkey_ml_dsa_65_base64: mldsa_pubkey_b64.map(str::to_string),
        algorithm: algorithm::HYBRID.into(),
        identity_type: id_type.to_string(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": key_id }),
        original_content_hash: "deadbeef".into(),
        scrub_signature_classical: ed_pubkey_b64.to_string(),
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .sqlite_backend()
        .expect("sqlite backend present")
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register hybrid key in the federation directory");
}

/// POSITIVE — the server's real consent-grant producer emits a federation-tier row
/// that persist ADMITS. Guards the "hybrid by construction" property of
/// `emit_attestation_self`: canonicalize once, hash and sign the SAME bytes, stamp
/// both scrub signatures.
#[tokio::test]
async fn server_consent_grant_emit_admits_at_federation_tier() {
    let (engine, node_key_id) = hybrid_node().await;

    // The grant's subject must be an admitted peer key.
    let peer_key_id = "witness-peer-aaaaaaaaaa";
    let peer_ed = BASE64.encode([0xD1u8; 32]);
    let peer_pqc = BASE64.encode([0xD2u8; 1952]);
    put_hybrid_key(
        &engine,
        peer_key_id,
        &peer_ed,
        Some(&peer_pqc),
        identity_type::NODE,
    )
    .await;

    let grant = ciris_server::peer::emit_replication_consent(
        &engine,
        &node_key_id,
        peer_key_id,
        &["capacity:"],
    )
    .await
    .expect(
        "the server's consent:replication:v1 producer must emit a federation-tier row that \
         persist's hybrid-mandatory ingest gate ADMITS — if this fails with \
         `federation_federation_tier_unverified`, a server emit path has stopped being \
         hybrid-by-construction (CIRISServer#327 §2)",
    );

    let row = engine
        .federation_directory()
        .get_attestation(&grant.attestation_id)
        .await
        .expect("read back the emitted grant")
        .expect("the emitted grant must be present");

    assert_eq!(
        row.tier,
        attestation_tier::FEDERATION,
        "the consent grant must be federation-tier — a local-tier row would bypass the ingest \
         gate entirely (tier_ingest.rs local-tier exemption) and make this witness vacuous",
    );
    assert!(
        row.scrub_signature_pqc.is_some(),
        "requirement (3): the ML-DSA-65 half must be present — a hybrid-pending federation-tier \
         row is refused under HybridPolicy::Strict (CC 5.3.2.4.3.1)",
    );
    assert_eq!(
        row.attesting_key_id, node_key_id,
        "requirement (2): the attester must be the node's DERIVED key_id, which is the id \
         registered at boot (CIRISPersist#247 — alias vs derived is the identity-fork class \
         0.5.138 closed)",
    );
}

/// NEGATIVE — a hand-assembled `tier = federation` row WITHOUT the ML-DSA-65 half is
/// REFUSED. Proves the gate is live in this build, so the positive test above is not
/// passing vacuously.
#[tokio::test]
async fn hybrid_pending_federation_tier_row_is_refused() {
    let (engine, node_key_id) = hybrid_node().await;
    let now = chrono::Utc::now();

    let envelope = serde_json::json!({
        "dimension": "witness:hybrid_pending:v1",
        "attesting_key_id": node_key_id,
        "subject_key_ids": [node_key_id],
        "score": 1.0,
        "cohort_scope": ciris_persist::federation::types::cohort_scope::FEDERATION,
        "asserted_at": now.to_rfc3339(),
    });

    let row = Attestation {
        attestation_id: "witness-hybrid-pending-0001".to_string(),
        attesting_key_id: node_key_id.clone(),
        attested_key_id: node_key_id.clone(),
        attestation_type: ciris_persist::federation::types::attestation_type::SCORES.to_string(),
        weight: Some(1.0),
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: "deadbeef".to_string(),
        scrub_signature_classical: "AA==".to_string(),
        // The defect under test: the classical half only, PQC deferred.
        scrub_signature_pqc: None,
        scrub_key_id: node_key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: vec![node_key_id.clone()],
        withdraws_admission_rule: None,
        tier: attestation_tier::FEDERATION.to_string(),
        cohort_scope: ciris_persist::federation::types::cohort_scope::FEDERATION.to_string(),
        promoted_at: None,
    };

    let err = engine
        .sqlite_backend()
        .expect("sqlite backend present")
        .put_attestation(SignedAttestation { attestation: row })
        .await
        .expect_err(
            "a federation-tier row with `scrub_signature_pqc: None` MUST be refused. If this \
             now succeeds, persist's hybrid-mandatory posture (HybridPolicy::Strict, no \
             `require_hybrid: false`) has been weakened — re-verify every \
             'hybrid by construction' claim in this repo before shipping",
        );

    assert_eq!(
        err.kind(),
        "federation_federation_tier_unverified",
        "the refusal must be the federation-tier ingest gate specifically, not an incidental \
         failure — a different token means this test is no longer exercising the gate it names \
         (got: {err})",
    );
}
