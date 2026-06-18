//! Node ownership = the RESPONSIBLE-PARTY model (CC 4.4.3.5 + CC 3.2 + CC 1.13.5).
//!
//! Proves, over the real persist v8.8.0 substrate + the live setup/root HTTP
//! stack, that:
//!
//!   - the infra/agency scope-split verifier accepts `infra:*` and REJECTS
//!     `agency:*` + legacy unprefixed agency kinds (CC 1.13.5);
//!   - `emit_owner_binding` refuses agency scopes (producer-side gate);
//!   - `is_owner_bound` is `Some(user)` after a live `user → node` infra
//!     delegation, and `None` without one / when the granter isn't `user`-role /
//!     when the binding is revoked;
//!   - the first-run `POST /v1/setup/root` claim establishes the owner-binding +
//!     records the cohort scope + derives `SYSTEM_ADMIN` bound to the
//!     responsible user; and an `agency:*` scope in the claim is rejected;
//!   - the node self-registers as `identity_type "node"` (not "steward").

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{
    algorithm, attestation_tier, attestation_type, identity_type, Attestation, KeyRecord,
    SignedAttestation, SignedKeyRecord,
};
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::WaRole;

use ciris_server::auth::bootstrap;
use ciris_server::auth::ownership::{
    emit_owner_binding, is_owner_bound, scopes_are_infra_only, OwnershipError,
    OWNER_BINDING_INFRA_SCOPES,
};
use ciris_server::auth::roles::UserRole;
use ciris_server::auth::store;

// ─── shared helpers (mirror tests/root_bootstrap.rs) ────────────────────────

const NODE_KEY_ID: &str = "ciris-own-node";

/// An in-memory substrate keyed by a HYBRID node-identity signer.
async fn node(key_id: &str) -> Arc<Engine> {
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
    let engine = Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("Engine::with_signer (sqlite::memory:)");
    Arc::new(engine)
}

/// Register the node's own key as `identity_type "node"` (the corrected fabric
/// role) via the canonical admission gate — the FK precondition for emitting
/// inbound `delegates_to` rows against it.
async fn register_node(engine: &Engine, key_id: &str) {
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize node envelope");
    let sig = engine.sign_hybrid(&canonical).await.expect("node sign");
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
        .expect("register node key via admission gate");
}

/// Register a directory key with an arbitrary `identity_type` (put_public_key —
/// no PoP re-verify), used to stand up a granter of a chosen role.
async fn register_party(engine: &Engine, key_id: &str, identity_type_str: &str) {
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize party envelope");
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: BASE64.encode([3u8; 32]),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode([4u8; 32])),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type_str.to_string(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register party key");
}

fn infra_scopes() -> Vec<String> {
    OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect()
}

// ─── (1) the CC 1.13.5 scope-split verifier ─────────────────────────────────

#[test]
fn scopes_are_infra_only_accepts_infra_rejects_agency_and_legacy() {
    // infra:* accepted.
    assert!(scopes_are_infra_only(&infra_scopes()));
    assert!(scopes_are_infra_only(&["infra:store".to_string()]));
    // agency:* rejected.
    assert!(!scopes_are_infra_only(
        &["agency:act_on_behalf".to_string()]
    ));
    // legacy unprefixed agency kind (act_on_behalf) rejected.
    assert!(!scopes_are_infra_only(&["act_on_behalf".to_string()]));
    // mixed set: a single agency scope poisons it.
    assert!(!scopes_are_infra_only(&[
        "infra:serve".to_string(),
        "agency:reason".to_string(),
    ]));
    // empty rejected (a node binding must grant some infra scope).
    assert!(!scopes_are_infra_only(&[]));
}

// ─── (2) emit_owner_binding refuses agency ──────────────────────────────────

#[tokio::test]
async fn emit_owner_binding_refuses_agency_scopes() {
    let engine = node(NODE_KEY_ID).await;
    register_node(&engine, NODE_KEY_ID).await;
    register_party(&engine, "owner-user", identity_type::USER).await;

    let err = emit_owner_binding(
        &engine,
        "owner-user",
        NODE_KEY_ID,
        &["agency:act_on_behalf".to_string()],
    )
    .await
    .expect_err("agency scope must be refused");
    assert!(matches!(err, OwnershipError::AgencyScopeRefused));

    // And it persisted nothing → still unowned.
    assert!(is_owner_bound(&engine, NODE_KEY_ID).await.is_none());
}

// ─── (3) is_owner_bound: true / false / revoked / non-user granter ──────────

#[tokio::test]
async fn is_owner_bound_true_after_user_infra_delegation() {
    let engine = node(NODE_KEY_ID).await;
    register_node(&engine, NODE_KEY_ID).await;
    register_party(&engine, "owner-user", identity_type::USER).await;

    assert!(
        is_owner_bound(&engine, NODE_KEY_ID).await.is_none(),
        "unbound before any delegation"
    );

    emit_owner_binding(&engine, "owner-user", NODE_KEY_ID, &infra_scopes())
        .await
        .expect("emit infra-only owner-binding");

    assert_eq!(
        is_owner_bound(&engine, NODE_KEY_ID).await.as_deref(),
        Some("owner-user"),
        "bound to the responsible user after a live user → node infra delegation"
    );
}

#[tokio::test]
async fn is_owner_bound_false_when_granter_is_not_user_role() {
    let engine = node(NODE_KEY_ID).await;
    register_node(&engine, NODE_KEY_ID).await;
    // The granter is a NODE-role key, NOT a user — ownership must NOT root in it.
    register_party(&engine, "other-node", "node").await;

    emit_owner_binding(&engine, "other-node", NODE_KEY_ID, &infra_scopes())
        .await
        .expect("emit (granter is node-role)");

    assert!(
        is_owner_bound(&engine, NODE_KEY_ID).await.is_none(),
        "a node-role granter does not confer ownership (CC 3.2: must be a user)"
    );
}

#[tokio::test]
async fn is_owner_bound_false_when_revoked() {
    let engine = node(NODE_KEY_ID).await;
    register_node(&engine, NODE_KEY_ID).await;
    register_party(&engine, "owner-user", identity_type::USER).await;
    emit_owner_binding(&engine, "owner-user", NODE_KEY_ID, &infra_scopes())
        .await
        .expect("emit owner-binding");
    assert!(is_owner_bound(&engine, NODE_KEY_ID).await.is_some());

    // The granter withdraws the binding against the node → ownership ends.
    emit_withdraws(&engine, "owner-user", NODE_KEY_ID).await;

    assert!(
        is_owner_bound(&engine, NODE_KEY_ID).await.is_none(),
        "a withdrawn owner-binding no longer confers ownership"
    );
}

/// Emit a `withdraws` from `granter` against `target` (the granter retracts its
/// delegation). Bytes are node-signed (the substrate does not re-verify scrub).
async fn emit_withdraws(engine: &Engine, granter: &str, target: &str) {
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({
        "kind": "withdraws",
        "dimension": "ownership:withdraw:node:v1",
        "attesting_key_id": granter,
        "node_key_id": target,
    });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize withdraws");
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .expect("sign withdraws");
    let attestation = Attestation {
        attestation_id: format!("withdraw-{granter}-{target}"),
        attesting_key_id: granter.to_string(),
        attested_key_id: target.to_string(),
        attestation_type: attestation_type::WITHDRAWS.to_string(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: NODE_KEY_ID.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: vec![target.to_string()],
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
    };
    engine
        .federation_directory()
        .put_attestation(SignedAttestation { attestation })
        .await
        .expect("put withdraws");
}

// ─── (4) the first-run claim establishes the owner-binding + cohort scope ────

fn node_pubkey_b64() -> String {
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    BASE64.encode(signing_key.verifying_key().to_bytes())
}

fn founder_signer(key_id: &str) -> LocalSigner {
    let signing_key = SigningKey::from_bytes(&[0xF1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xF2; 32], format!("{key_id}-founder-pqc"))
            .expect("founder ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        signing_key,
        key_id.to_string(),
        Some(pqc),
        Some(format!("{key_id}-founder-pqc")),
    )
}

const TEST_CLAIM_PIN: &str = "TEST-PIN1";

async fn serve_setup(
    engine: Arc<Engine>,
    node_key_id: &str,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = bootstrap::router(
        engine,
        HybridPolicy::Strict,
        node_key_id.to_string(),
        node_pubkey_b64(),
        Some(TEST_CLAIM_PIN.to_string()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

fn node_code_string(key_id: &str) -> String {
    let nc = ciris_server::nodecode::NodeCode {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: node_pubkey_b64(),
        transport_hint: None,
        alias_hint: None,
    };
    ciris_server::nodecode::encode(&nc).expect("encode node code")
}

/// Build + hybrid-sign a claim body. `extra` members are merged into the body
/// (e.g. `cohort_scope`, `infra_scopes`). Returns `(body, ed_sig_b64, ml_sig_b64)`.
async fn signed_claim(
    node_key_id: &str,
    founder_key_id: &str,
    extra: serde_json::Value,
) -> (Vec<u8>, String, String) {
    let fsigner = founder_signer(founder_key_id);
    let probe = fsigner.sign_hybrid(b"probe").await.expect("probe sign");
    let mut claim = serde_json::json!({
        "node_code": node_code_string(node_key_id),
        "founder": {
            "key_id": founder_key_id,
            "ed25519_pubkey_b64": BASE64.encode(&probe.classical.public_key),
            "ml_dsa_65_pubkey_b64": BASE64.encode(&probe.pqc.public_key),
        },
        "claim_pin": TEST_CLAIM_PIN,
    });
    if let serde_json::Value::Object(extra_map) = extra {
        for (k, v) in extra_map {
            claim[k] = v;
        }
    }
    let body = serde_json::to_vec(&claim).unwrap();
    let sig = fsigner.sign_hybrid(&body).await.expect("sign body");
    (
        body,
        BASE64.encode(&sig.classical.signature),
        BASE64.encode(&sig.pqc.signature),
    )
}

#[tokio::test]
async fn claim_establishes_owner_binding_cohort_and_system_admin() {
    let node_key_id = "ciris-claim-node";
    let founder_key_id = "ciris-responsible-user";
    let engine = node(node_key_id).await;
    register_node(&engine, node_key_id).await;
    let (base, _h) = serve_setup(Arc::clone(&engine), node_key_id).await;
    let client = reqwest::Client::new();

    let (body, ed, ml) = signed_claim(
        node_key_id,
        founder_key_id,
        serde_json::json!({ "cohort_scope": "family" }),
    )
    .await;

    let resp = client
        .post(format!("{base}/v1/setup/root"))
        .header("x-ciris-signing-key-id", founder_key_id)
        .header("x-ciris-signature-ed25519", &ed)
        .header("x-ciris-signature-ml-dsa-65", &ml)
        .body(body)
        .send()
        .await
        .expect("POST setup/root");
    assert_eq!(resp.status(), 201, "responsible-party claim must succeed");
    let json: serde_json::Value = resp.json().await.expect("setup response json");
    assert_eq!(json["identity_key_id"], founder_key_id);
    assert_eq!(json["role"], "SYSTEM_ADMIN");
    assert_eq!(json["cohort_scope"], "family", "cohort scope recorded");
    assert!(
        json["owner_binding_attestation_id"].as_str().is_some(),
        "response carries the owner-binding attestation id"
    );

    // ROOT/SystemAdmin derived + bound to the responsible user.
    let roots = store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .expect("list roots");
    assert_eq!(roots.len(), 1);
    assert_eq!(UserRole::from_wa_role(roots[0].role), UserRole::SystemAdmin);
    assert_eq!(roots[0].pubkey, founder_key_id);

    // The responsible user is registered as identity_type "user" (not steward).
    let user_key = engine
        .federation_directory()
        .lookup_public_key(founder_key_id)
        .await
        .expect("lookup user")
        .expect("user key present after claim");
    assert_eq!(user_key.identity_type, identity_type::USER);

    // The structural owner-binding exists and resolves: is_owner_bound → the user.
    assert_eq!(
        is_owner_bound(&engine, node_key_id).await.as_deref(),
        Some(founder_key_id),
        "the claim emitted a live delegates_to(user → node, infra:*) owner-binding"
    );
}

#[tokio::test]
async fn claim_with_agency_scope_is_rejected() {
    let node_key_id = "ciris-agency-node";
    let founder_key_id = "ciris-agency-claimant";
    let engine = node(node_key_id).await;
    register_node(&engine, node_key_id).await;
    let (base, _h) = serve_setup(Arc::clone(&engine), node_key_id).await;
    let client = reqwest::Client::new();

    // The claim carries an agency:* scope — a node delegation cannot carry agency.
    let (body, ed, ml) = signed_claim(
        node_key_id,
        founder_key_id,
        serde_json::json!({
            "cohort_scope": "self",
            "infra_scopes": ["agency:act_on_behalf"],
        }),
    )
    .await;

    let resp = client
        .post(format!("{base}/v1/setup/root"))
        .header("x-ciris-signing-key-id", founder_key_id)
        .header("x-ciris-signature-ed25519", &ed)
        .header("x-ciris-signature-ml-dsa-65", &ml)
        .body(body)
        .send()
        .await
        .expect("POST setup/root (agency)");
    assert_eq!(
        resp.status(),
        400,
        "an agency:* scope in the claim must be rejected (CC 1.13.5)"
    );

    // Rejected ⇒ no ROOT, no owner-binding.
    assert!(
        store::list_by_role(&engine, WaRole::Root, 10)
            .await
            .expect("list roots")
            .is_empty(),
        "a rejected claim mints no ROOT"
    );
    assert!(is_owner_bound(&engine, node_key_id).await.is_none());
}

#[tokio::test]
async fn claim_without_cohort_scope_is_rejected() {
    let node_key_id = "ciris-nocohort-node";
    let founder_key_id = "ciris-nocohort-claimant";
    let engine = node(node_key_id).await;
    register_node(&engine, node_key_id).await;
    let (base, _h) = serve_setup(Arc::clone(&engine), node_key_id).await;
    let client = reqwest::Client::new();

    // No cohort_scope member.
    let (body, ed, ml) = signed_claim(node_key_id, founder_key_id, serde_json::json!({})).await;
    let resp = client
        .post(format!("{base}/v1/setup/root"))
        .header("x-ciris-signing-key-id", founder_key_id)
        .header("x-ciris-signature-ed25519", &ed)
        .header("x-ciris-signature-ml-dsa-65", &ml)
        .body(body)
        .send()
        .await
        .expect("POST setup/root (no cohort)");
    assert_eq!(
        resp.status(),
        400,
        "a claim without cohort_scope is rejected"
    );
}
