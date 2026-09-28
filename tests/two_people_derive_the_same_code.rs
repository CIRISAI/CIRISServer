//! **Two people comparing a verification code see the SAME code**
//! (CIRISServer#683).
//!
//! `GET /v1/federation/peers/{key_id}/sas` computed over THIS NODE's key and
//! the contact's PERSON key, so Alice's node showed sas(nodeA, Bob) and Bob's
//! showed sas(nodeB, Alice): two different pairs, so an honest comparison
//! always read as a mismatch. For a person the pair is now {my person, their
//! person}, the pair a chat uses, and both sides derive it identically.

use std::sync::Arc;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::SignedKeyRecord;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use tower::ServiceExt as _;

#[allow(dead_code)]
mod support {
    include!("support/drive_fixture.rs");
}
use support::*;

async fn other_engine(alias: &str, ed: u8, pqc: u8) -> Arc<Engine> {
    let pqc_signer = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[pqc; 32], format!("{alias}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[ed; 32]),
        alias.to_string(),
        Some(pqc_signer),
        Some(format!("{alias}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine"),
    )
}

/// Put `person`'s key into `engine`'s directory as a contact exchange leaves
/// it — the same local door the fixture uses for an owner's key.
async fn hold_contact(engine: &Engine, person: &OwnerIdentity) {
    use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord};
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": person.key_id });
    let record = KeyRecord {
        key_id: person.key_id.clone(),
        pubkey_ed25519_base64: person.pubkey_ed25519_base64.clone(),
        pubkey_ml_dsa_65_base64: Some(person.pubkey_ml_dsa_65_base64.clone()),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::USER.into(),
        identity_ref: person.key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: person.key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("hold the contact's person key");
}

async fn sas(engine: Arc<Engine>, peer: &str) -> serde_json::Value {
    let resp = ciris_server::federation_peers::router(engine)
        .oneshot(
            axum::http::Request::get(format!("/v1/federation/peers/{peer}/sas"))
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    40001,
                ))))
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("serve");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(status, 200, "{v}");
    v["data"].clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alice_and_bob_derive_the_same_words_and_digits_for_each_other() {
    init_tracing();
    let node_a = node_engine().await;
    let alice = OwnerIdentity::mint().await;
    let key_a = register_self(&node_a).await;
    bind_owner(&node_a, &alice, &key_a).await;

    let node_b = other_engine("ciris-sas-node-b", 0xB1, 0xB2).await;
    let bob = OwnerIdentity::mint().await;
    let key_b = register_self(&node_b).await;
    bind_owner(&node_b, &bob, &key_b).await;

    // Each node holds the OTHER person's key, as a contact exchange leaves it.
    hold_contact(&node_a, &bob).await;
    hold_contact(&node_b, &alice).await;

    let on_a = sas(Arc::clone(&node_a), &bob.key_id).await;
    let on_b = sas(Arc::clone(&node_b), &alice.key_id).await;
    assert_eq!(on_a["words"], on_b["words"], "a: {on_a} b: {on_b}");
    assert_eq!(on_a["digits"], on_b["digits"], "a: {on_a} b: {on_b}");
}
