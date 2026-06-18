//! Claim-remote (the SUBSTRATE-NATIVE, node-to-node 1-phase owner-binding).
//!
//! Node L (the responsible user's LOCAL node, holding a USER identity) claims
//! target node T:
//!
//!   - L builds + substrate-signs the `delegates_to(user → T, infra:*)`
//!     owner-binding with the USER's key ([`build_signed_owner_binding`] /
//!     `claim_remote::build_claim_for_target`);
//!   - T receives via the 1-phase `POST /v1/setup/root`, verifies the USER's
//!     hybrid signature, registers the user, persists a delegates_to whose
//!     signature verifies against the USER's pubkeys (`scrub_key_id == user`),
//!     binds ROOT, and `is_owner_bound(T) == the user`;
//!   - tamper (agency scope / attested != T / wrong sig) → rejected, no ROOT.
//!
//! Both the directory-level pieces (build on L, apply on T directly) AND the full
//! L→T HTTP round-trip are exercised in-process.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{
    algorithm, attestation_type, identity_type, KeyRecord, SignedKeyRecord,
};
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::WaRole;

use ciris_server::auth::bootstrap;
use ciris_server::auth::ownership::{
    apply_signed_owner_binding, build_signed_owner_binding, is_owner_bound,
    OWNER_BINDING_INFRA_SCOPES,
};
use ciris_server::auth::store;
use ciris_server::claim_remote;
use ciris_server::nodecode::NodeCode;

const T_NODE_KEY_ID: &str = "ciris-target-node";
const L_USER_KEY_ID: &str = "ciris-local-user";
const TEST_CLAIM_PIN: &str = "TEST-PIN1";

/// Target node T's in-memory substrate, keyed by its node-steward signer.
async fn target_node(key_id: &str) -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{key_id}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        key_id.to_string(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer"),
    )
}

/// Node T's federation pubkey (base64) — matches `target_node`'s seed.
fn t_node_pubkey_b64() -> String {
    BASE64.encode(
        SigningKey::from_bytes(&[0xA1; 32])
            .verifying_key()
            .to_bytes(),
    )
}

/// The responsible USER's signer held by the LOCAL node L (distinct keypair).
fn local_user_signer(key_id: &str) -> LocalSigner {
    let signing_key = SigningKey::from_bytes(&[0xF1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xF2; 32], format!("{key_id}-pqc"))
            .expect("user ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        signing_key,
        key_id.to_string(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    )
}

/// Register T's own node key (identity_type "node") — the FK precondition for
/// inbound delegates_to rows.
async fn register_target(engine: &Engine, key_id: &str) {
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize");
    let sig = engine.sign_hybrid(&canonical).await.expect("sign");
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: BASE64.encode(&sig.classical.public_key),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(&sig.pqc.public_key)),
        algorithm: algorithm::HYBRID.into(),
        identity_type: "node".into(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .register_federation_key(SignedKeyRecord { record })
        .await
        .expect("register target node key");
}

fn infra_scopes() -> Vec<String> {
    OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// T's NodeCode with a `transport_hint` pointing at `base` (so claim_remote can
/// reach it over HTTP).
fn target_node_code(base: &str) -> String {
    let nc = NodeCode {
        key_id: T_NODE_KEY_ID.to_string(),
        pubkey_ed25519_base64: t_node_pubkey_b64(),
        transport_hint: Some(base.to_string()),
        alias_hint: None,
    };
    ciris_server::nodecode::encode(&nc).expect("encode node code")
}

/// Serve T's 1-phase `POST /v1/setup/root`.
async fn serve_target(engine: Arc<Engine>) -> (String, tokio::task::JoinHandle<()>) {
    let app = bootstrap::router(
        engine,
        HybridPolicy::Strict,
        T_NODE_KEY_ID.to_string(),
        t_node_pubkey_b64(),
        Some(TEST_CLAIM_PIN.to_string()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

// ─── Directory-level: L builds, T applies (no HTTP) ──────────────────────────

#[tokio::test]
async fn l_builds_and_t_applies_owner_binding_directly() {
    let t = target_node(T_NODE_KEY_ID).await;
    register_target(&t, T_NODE_KEY_ID).await;
    let user = local_user_signer(L_USER_KEY_ID);

    // L builds + substrate-signs the owner-binding (the responsible USER's key).
    let binding = build_signed_owner_binding(&user, T_NODE_KEY_ID, &infra_scopes())
        .await
        .expect("L builds signed owner-binding");
    assert_eq!(binding.attesting_key_id, L_USER_KEY_ID);

    // T applies it: verify + register user + persist the user-signed delegates_to.
    let applied = apply_signed_owner_binding(&t, T_NODE_KEY_ID, HybridPolicy::Strict, &binding)
        .await
        .expect("T applies the owner-binding");
    assert_eq!(applied.responsible_user_key_id, L_USER_KEY_ID);

    // T now reads a user-signed owner edge.
    assert_eq!(
        is_owner_bound(&t, T_NODE_KEY_ID).await.as_deref(),
        Some(L_USER_KEY_ID)
    );

    // The user is registered as identity_type "user".
    let uk = t
        .federation_directory()
        .lookup_public_key(L_USER_KEY_ID)
        .await
        .unwrap()
        .expect("user registered");
    assert_eq!(uk.identity_type, identity_type::USER);

    // The persisted delegates_to is genuinely USER-signed.
    let edges = t
        .federation_directory()
        .list_attestations_for(T_NODE_KEY_ID)
        .await
        .unwrap();
    let row = edges
        .iter()
        .find(|e| e.attestation_type == attestation_type::DELEGATES_TO)
        .expect("a delegates_to exists");
    assert_eq!(row.scrub_key_id, L_USER_KEY_ID);
    let canonical = ceg_produce_canonicalize(&row.attestation_envelope).unwrap();
    assert!(ciris_persist::prelude::verify_hybrid(
        &canonical,
        &row.scrub_signature_classical,
        row.scrub_signature_pqc.as_deref(),
        &uk.pubkey_ed25519_base64,
        uk.pubkey_ml_dsa_65_base64.as_deref(),
        HybridPolicy::Strict,
        None,
    )
    .is_ok());
}

// ─── Full L→T HTTP round-trip via claim_remote ───────────────────────────────

#[tokio::test]
async fn claim_remote_http_round_trip_binds_root_to_user() {
    let t = target_node(T_NODE_KEY_ID).await;
    register_target(&t, T_NODE_KEY_ID).await;
    let (base, _h) = serve_target(Arc::clone(&t)).await;
    let user = local_user_signer(L_USER_KEY_ID);

    let http = reqwest::Client::new();
    let result = claim_remote::claim_remote(
        &http,
        &user,
        &target_node_code(&base),
        TEST_CLAIM_PIN,
        "family",
    )
    .await
    .expect("L claims T over HTTP");

    assert_eq!(result["identity_key_id"], L_USER_KEY_ID);
    assert_eq!(result["cohort_scope"], "family");
    assert_eq!(result["role"], "SYSTEM_ADMIN");

    // T bound ROOT to the user.
    let roots = store::list_by_role(&t, WaRole::Root, 10).await.unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].pubkey, L_USER_KEY_ID);

    // is_owner_bound(T) == the user.
    assert_eq!(
        is_owner_bound(&t, T_NODE_KEY_ID).await.as_deref(),
        Some(L_USER_KEY_ID)
    );
}

// ─── Tamper rejection (no ROOT) ──────────────────────────────────────────────

#[tokio::test]
async fn apply_rejects_agency_attested_mismatch_and_wrong_sig() {
    let t = target_node(T_NODE_KEY_ID).await;
    register_target(&t, T_NODE_KEY_ID).await;
    let user = local_user_signer(L_USER_KEY_ID);
    let good = build_signed_owner_binding(&user, T_NODE_KEY_ID, &infra_scopes())
        .await
        .expect("build");

    // (a) agency scope → rejected.
    let mut agency = good.clone();
    agency.envelope["scope"] = serde_json::json!(["agency:reason"]);
    assert!(
        apply_signed_owner_binding(&t, T_NODE_KEY_ID, HybridPolicy::Strict, &agency)
            .await
            .is_err()
    );

    // (b) attested != T → rejected.
    let mut wrong_node = good.clone();
    wrong_node.envelope["node_key_id"] = "another-node".into();
    assert!(
        apply_signed_owner_binding(&t, T_NODE_KEY_ID, HybridPolicy::Strict, &wrong_node)
            .await
            .is_err()
    );

    // (c) wrong signature (imposter sig over the same envelope) → rejected.
    let mut wrong_sig = good.clone();
    let imposter = local_user_signer("ciris-imposter");
    // imposter uses different seeds via key_id-derived pqc alias only; force a
    // genuinely different keypair:
    let imposter = {
        let _ = imposter;
        let sk = SigningKey::from_bytes(&[0x55; 32]);
        let pqc = Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&[0x66; 32], "imp-pqc".to_string()).unwrap(),
        );
        LocalSigner::from_parts(
            sk,
            "ciris-imposter".to_string(),
            Some(pqc),
            Some("imp-pqc".into()),
        )
    };
    let canonical = ceg_produce_canonicalize(&good.envelope).unwrap();
    let bad = imposter.sign_hybrid(&canonical).await.unwrap();
    wrong_sig.ed25519_sig_b64 = BASE64.encode(&bad.classical.signature);
    wrong_sig.ml_dsa_65_sig_b64 = BASE64.encode(&bad.pqc.signature);
    assert!(
        apply_signed_owner_binding(&t, T_NODE_KEY_ID, HybridPolicy::Strict, &wrong_sig)
            .await
            .is_err()
    );

    // No ROOT bound, node still unowned.
    assert!(store::list_by_role(&t, WaRole::Root, 10)
        .await
        .unwrap()
        .is_empty());
    assert!(is_owner_bound(&t, T_NODE_KEY_ID).await.is_none());
}
