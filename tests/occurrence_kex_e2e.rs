//! End-to-end proof of the **occurrence-KEX plane** (CIRISEdge#305, adopted in 0.5.99).
//!
//! This is the data path that was dark before this release — the field symptom was
//! `resolve_peer_kex_pubkeys(canonical)=None → "target admitted but [no seal]" → 0
//! envelopes`. The test drives the WHOLE path with the real components:
//!
//!   1. An **agent publishes its node's self-occurrence** carrying content-enc pubkeys
//!      derived from the node's Ed25519 seed (`derive_self_enc_pubkeys` — exactly what
//!      the agent does at mint, since agent = node = one keypair).
//!   2. The edge bridge, given the **publish-own `occurrence_selector`** (the #305 hook
//!      this release wires into `start_replication_runtime`), advertises that OWN
//!      occurrence — where before it only fanned out over the cohort and never its own.
//!   3. One anti-entropy hop (`list → fetch → apply`, the exact `ReplicationDirectory`
//!      calls the scheduler makes over a socket) carries the occurrence to the peer.
//!   4. The peer's directory now `resolve_encryption_keys` → `Some` — the same lookup
//!      `Edge::resolve_peer_kex_pubkeys` delegates to — with the SAME enc keys.
//!   5. A real hybrid `FederationSession` seals on the sender (`initiate`) and the
//!      recipient recomputes the identical session key (`respond`/decrypt).
//!
//! Only the socket is stubbed (the raw Reticulum loopback is edge's own test); every
//! directory op, the selector, the self-enc derivation, and the KEX are the real code.
//! If this passes, an agent-published occurrence genuinely becomes sealable across the
//! mesh — trace-flow is proven, not inferred from a field report.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use ciris_edge::replication::{
    CohortProvider, EnvelopeKind, FederationDirectoryReplicationBridge, ReplicationDirectory,
};
use ciris_edge::transport::federation_session::{
    FederationSession, KexAlgorithm, OwnKexKeys, PeerKexPubkeys,
};
use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::types::{
    algorithm, identity_type, IdentityOccurrence, KeyRecord, SignedIdentityOccurrence,
    SignedKeyRecord,
};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

const NODE_A_KEY_ID: &str = "kex-node-a";
const NODE_B_KEY_ID: &str = "kex-node-b";
/// B's Ed25519 base seed — the ONE secret the whole content-enc keypair derives from
/// (the agent holds it; the occurrence publishes the public halves).
const NODE_B_ED_SEED: [u8; 32] = [0xB0; 32];
const NODE_B_ML_SEED: [u8; 32] = [0xB1; 32];

/// A fresh in-memory substrate keyed by a hybrid node signer (Ed25519 + ML-DSA-65).
async fn engine(key_id: &str, ed_seed: [u8; 32], ml_seed: [u8; 32]) -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&ml_seed, format!("{key_id}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&ed_seed),
        key_id.to_string(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer(sqlite::memory:)"),
    )
}

/// B's self-signed proof-of-possession `SignedKeyRecord` (the shape
/// `register_federation_key`'s hybrid gate admits). Mirrors `peer_replication.rs`.
async fn node_b_key_record() -> SignedKeyRecord {
    let ed = SigningKey::from_bytes(&NODE_B_ED_SEED);
    let mldsa =
        MlDsa65SoftwareSigner::from_seed_bytes(&NODE_B_ML_SEED, format!("{NODE_B_KEY_ID}-pqc"))
            .expect("B ML-DSA seed");
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": NODE_B_KEY_ID });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize B registration");
    let original_content_hash = hex::encode(Sha256::digest(&canonical));
    let ed_sig = ed.sign(&canonical).to_bytes();
    let mut bound = Vec::with_capacity(canonical.len() + ed_sig.len());
    bound.extend_from_slice(&canonical);
    bound.extend_from_slice(&ed_sig);
    let pqc_sig = mldsa.sign(&bound).await.expect("ml-dsa sign B reg");
    let record = KeyRecord {
        key_id: NODE_B_KEY_ID.to_string(),
        pubkey_ed25519_base64: BASE64.encode(ed.verifying_key().to_bytes()),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(mldsa.public_key().await.expect("ml-dsa pk"))),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::NODE.into(),
        identity_ref: NODE_B_KEY_ID.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash,
        scrub_signature_classical: BASE64.encode(ed_sig),
        scrub_signature_pqc: Some(BASE64.encode(&pqc_sig)),
        scrub_key_id: NODE_B_KEY_ID.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    SignedKeyRecord { record }
}

fn directory_of(engine: &Arc<Engine>) -> Arc<dyn FederationDirectory> {
    engine
        .sqlite_backend()
        .expect("sqlite-backed engine")
        .clone()
}

fn selector(key_id: &str) -> CohortProvider {
    let k = key_id.to_string();
    Arc::new(move || vec![k.clone()])
}

#[tokio::test]
async fn agent_published_occurrence_replicates_and_becomes_sealable() {
    // ── Node B (the sender's peer / the "canonical" in the field case) and Node A
    //    (the node that must SEAL a trace to B). B's key is admitted on both sides
    //    (the occurrence table FK-references federation_keys).
    let engine_a = engine(NODE_A_KEY_ID, [0xA0; 32], [0xA2; 32]).await;
    let engine_b = engine(NODE_B_KEY_ID, NODE_B_ED_SEED, NODE_B_ML_SEED).await;
    let b_record = node_b_key_record().await;
    engine_b
        .register_federation_key(b_record.clone())
        .await
        .expect("register B on B");
    engine_a
        .register_federation_key(b_record)
        .await
        .expect("register B on A");

    let dir_a = directory_of(&engine_a);
    let dir_b = directory_of(&engine_b);

    // ── (1) The AGENT publishes B's self-occurrence with content-enc pubkeys derived
    //    from B's Ed25519 seed. This is `derive_self_enc_pubkeys` — the exact call the
    //    agent makes at mint; the public halves go on the wire, the private halves the
    //    agent keeps for `federation_session_respond`.
    let b_enc = ciris_server::identity::derive_self_enc_pubkeys(&NODE_B_ED_SEED)
        .expect("derive B content-enc pubkeys");
    dir_b
        .put_identity_occurrence(SignedIdentityOccurrence {
            identity_occurrence: IdentityOccurrence {
                identity_key_id: NODE_B_KEY_ID.to_string(),
                occurrence_key_id: NODE_B_KEY_ID.to_string(),
                device_class: "agent".to_string(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(b_enc.clone()),
                persist_row_hash: String::new(),
            },
        })
        .await
        .expect("publish B self-occurrence");

    // ── (2) The publish-own selector is what makes the plane advertise B's OWN
    //    occurrence. Proof it's load-bearing: WITHOUT it (empty cohort) the plane
    //    advertises nothing; WITH it, exactly B's occurrence surfaces.
    let bridge_b_no_sel =
        FederationDirectoryReplicationBridge::new(Arc::clone(&dir_b), Arc::new(Vec::new));
    assert!(
        bridge_b_no_sel
            .list_envelope_refs(EnvelopeKind::IdentityOccurrence)
            .await
            .is_empty(),
        "without occurrence_selector the plane must NOT advertise B's own occurrence \
         (the pre-#305 cohort-only projection — the bug)"
    );

    let bridge_b = FederationDirectoryReplicationBridge::new(Arc::clone(&dir_b), Arc::new(Vec::new))
        .with_occurrence_selector(Some(selector(NODE_B_KEY_ID)));
    let refs = bridge_b
        .list_envelope_refs(EnvelopeKind::IdentityOccurrence)
        .await;
    assert_eq!(
        refs.len(),
        1,
        "with occurrence_selector, B advertises its OWN occurrence (the #305 fix)"
    );

    // ── (3) One anti-entropy hop: fetch the advertised occurrence off B, apply it into
    //    A — the exact ReplicationDirectory calls the scheduler makes over the socket.
    let bytes = bridge_b
        .fetch_envelope_bytes(EnvelopeKind::IdentityOccurrence, &refs[0].envelope_hash)
        .await
        .expect("fetch B occurrence bytes");
    let bridge_a = FederationDirectoryReplicationBridge::new(Arc::clone(&dir_a), Arc::new(Vec::new));
    assert!(
        bridge_a
            .apply_envelope_bytes(EnvelopeKind::IdentityOccurrence, &bytes)
            .await,
        "A applies B's replicated occurrence"
    );

    // ── (4) A can now resolve B's KEX pubkeys — the lookup that returned `None` in the
    //    field (this is exactly what Edge::resolve_peer_kex_pubkeys delegates to).
    let resolved = dir_a
        .resolve_encryption_keys(NODE_B_KEY_ID)
        .await
        .expect("resolve_encryption_keys ok")
        .expect("B's enc keys resolve on A after replication (was None → the bug)");
    assert_eq!(
        resolved.x25519_base64, b_enc.x25519_base64,
        "resolved x25519 == what B published"
    );
    assert_eq!(
        resolved.ml_kem_768_base64, b_enc.ml_kem_768_base64,
        "resolved ML-KEM-768 == what B published"
    );

    // ── (5) The seal actually works: A (sender) initiates a hybrid session to B's
    //    resolved pubkeys; B (recipient) recomputes the SAME session key with the
    //    private halves the agent re-derives from B's seed. Equal keys ⇒ the trace
    //    A seals is one B can open. This is the "[no seal]" turning into a live seal.
    let peer = PeerKexPubkeys {
        x25519_pub: BASE64
            .decode(&resolved.x25519_base64)
            .expect("x25519 b64")
            .try_into()
            .expect("x25519 32B"),
        mlkem768_pub: Some(BASE64.decode(&resolved.ml_kem_768_base64).expect("ml-kem b64")),
    };
    let (handshake, sender_key) =
        FederationSession::initiate(&peer, KexAlgorithm::Hybrid).expect("A seals to B (initiate)");

    let (x_priv, _x_pub) = ciris_crypto::self_enc::derive_self_enc_x25519(&NODE_B_ED_SEED);
    let (ml_priv, ml_pub) =
        ciris_crypto::self_enc::derive_self_enc_mlkem768(&NODE_B_ED_SEED).expect("B ml-kem derive");
    let own_b = OwnKexKeys {
        x25519_priv: x_priv,
        mlkem768_priv: Some(ml_priv),
        mlkem768_pub: Some(ml_pub),
    };
    let recipient_key = FederationSession::respond(&own_b, &handshake).expect("B opens (respond)");

    assert_eq!(
        sender_key.as_bytes(),
        recipient_key.as_bytes(),
        "sealed session key matches on both ends — A's trace to B is genuinely sealable/openable"
    );
}
