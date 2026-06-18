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

/// Register a party from a signer, with the signer's REAL hybrid pubkeys, under
/// `identity_type`. persist v9.0.0's federation-tier ingest gate verifies an
/// emitted `delegates_to`/`withdraws` against `attesting_key_id`'s registered
/// pubkeys, so a party that will ATTEST (sign) a federation-tier row must be
/// registered with the keys it actually signs with. Returns the signer.
async fn register_party_signed(
    engine: &Engine,
    key_id: &str,
    identity_type_str: &str,
) -> LocalSigner {
    use ciris_keyring::PqcSigner as _;
    let signer = party_signer(key_id);
    let ed_pub = BASE64.encode(
        SigningKey::from_bytes(&party_ed_seed(key_id))
            .verifying_key()
            .to_bytes(),
    );
    let mldsa_pub = {
        let pqc = MlDsa65SoftwareSigner::from_seed_bytes(
            &party_pqc_seed(key_id),
            format!("{key_id}-pqc"),
        )
        .expect("party ML-DSA-65 seed");
        BASE64.encode(pqc.public_key().await.expect("party ML-DSA-65 pubkey"))
    };
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize party envelope");
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: ed_pub,
        pubkey_ml_dsa_65_base64: Some(mldsa_pub),
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
        .expect("register signed party key");
    signer
}

/// Deterministic per-key-id Ed25519 seed for a party signer (distinct from the
/// node steward's `[0xA1;32]`).
fn party_ed_seed(key_id: &str) -> [u8; 32] {
    let mut s = [0xE1u8; 32];
    for (i, b) in key_id.bytes().enumerate().take(32) {
        s[i] ^= b;
    }
    s
}

/// Deterministic per-key-id ML-DSA-65 seed for a party signer.
fn party_pqc_seed(key_id: &str) -> [u8; 32] {
    let mut s = [0xE2u8; 32];
    for (i, b) in key_id.bytes().enumerate().take(32) {
        s[i] ^= b;
    }
    s
}

/// A party's `LocalSigner` (hybrid), matching [`register_party_signed`]'s keys.
fn party_signer(key_id: &str) -> LocalSigner {
    let signing_key = SigningKey::from_bytes(&party_ed_seed(key_id));
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&party_pqc_seed(key_id), format!("{key_id}-pqc"))
            .expect("party ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        signing_key,
        key_id.to_string(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    )
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
    let owner = register_party_signed(&engine, "owner-user", identity_type::USER).await;

    let err = emit_owner_binding(
        &engine,
        &owner,
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
    let owner = register_party_signed(&engine, "owner-user", identity_type::USER).await;

    assert!(
        is_owner_bound(&engine, NODE_KEY_ID).await.is_none(),
        "unbound before any delegation"
    );

    emit_owner_binding(&engine, &owner, NODE_KEY_ID, &infra_scopes())
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
    let other_node = register_party_signed(&engine, "other-node", identity_type::NODE).await;

    emit_owner_binding(&engine, &other_node, NODE_KEY_ID, &infra_scopes())
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
    let owner = register_party_signed(&engine, "owner-user", identity_type::USER).await;
    emit_owner_binding(&engine, &owner, NODE_KEY_ID, &infra_scopes())
        .await
        .expect("emit owner-binding");
    assert!(is_owner_bound(&engine, NODE_KEY_ID).await.is_some());

    // The granter withdraws the binding against the node → ownership ends.
    emit_withdraws(&engine, &owner, NODE_KEY_ID).await;

    assert!(
        is_owner_bound(&engine, NODE_KEY_ID).await.is_none(),
        "a withdrawn owner-binding no longer confers ownership"
    );
}

/// Emit a `withdraws` from `granter` against `target` (the granter retracts its
/// delegation). Signed by the GRANTER's key — persist v9.0.0 verifies this
/// federation-tier row against `attesting_key_id` (== granter), so attester ==
/// signer.
async fn emit_withdraws(engine: &Engine, granter: &LocalSigner, target: &str) {
    let granter_key_id = granter.key_id().to_string();
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({
        "kind": "withdraws",
        "dimension": "ownership:withdraw:node:v1",
        "attesting_key_id": granter_key_id,
        "node_key_id": target,
    });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize withdraws");
    let sig = granter
        .sign_hybrid(&canonical)
        .await
        .expect("sign withdraws");
    let attestation = Attestation {
        attestation_id: format!("withdraw-{granter_key_id}-{target}"),
        attesting_key_id: granter_key_id.clone(),
        attested_key_id: target.to_string(),
        attestation_type: attestation_type::WITHDRAWS.to_string(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: granter_key_id.clone(),
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

// ─── (4) the first-run 1-phase claim establishes the owner-binding + cohort ──

fn node_pubkey_b64() -> String {
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    BASE64.encode(signing_key.verifying_key().to_bytes())
}

/// The responsible USER's signer (a distinct keypair from the node steward).
fn user_signer(key_id: &str) -> LocalSigner {
    let signing_key = SigningKey::from_bytes(&[0xF1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xF2; 32], format!("{key_id}-user-pqc"))
            .expect("user ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        signing_key,
        key_id.to_string(),
        Some(pqc),
        Some(format!("{key_id}-user-pqc")),
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

/// Build the 1-phase claim body: the NodeCode pin + cohort + PIN + a COMPLETE,
/// user-signed owner-binding built in the substrate (the responsible USER signs
/// the delegates_to canonical bytes). `extra` members are merged into the body.
async fn one_phase_claim_body(
    node_key_id: &str,
    user: &LocalSigner,
    cohort_scope: &str,
    binding: ciris_server::auth::ownership::SignedOwnerBinding,
) -> Vec<u8> {
    let _ = user;
    let claim = serde_json::json!({
        "node_code": node_code_string(node_key_id),
        "cohort_scope": cohort_scope,
        "claim_pin": TEST_CLAIM_PIN,
        "owner_binding": binding,
    });
    serde_json::to_vec(&claim).unwrap()
}

#[tokio::test]
async fn claim_establishes_owner_binding_cohort_and_system_admin() {
    let node_key_id = "ciris-claim-node";
    let user_key_id = "ciris-responsible-user";
    let engine = node(node_key_id).await;
    register_node(&engine, node_key_id).await;
    let (base, _h) = serve_setup(Arc::clone(&engine), node_key_id).await;
    let client = reqwest::Client::new();
    let user = user_signer(user_key_id);

    // The LOCAL (claiming) node builds + hybrid-signs the owner-binding with the
    // USER's key (substrate-native — no app crypto).
    let binding = ciris_server::auth::ownership::build_signed_owner_binding(
        &user,
        node_key_id,
        &infra_scopes(),
    )
    .await
    .expect("build signed owner-binding");
    assert_eq!(binding.attesting_key_id, user_key_id);
    assert_eq!(
        binding.envelope["node_key_id"], node_key_id,
        "attests the node"
    );
    assert_eq!(
        binding.envelope["attesting_key_id"], user_key_id,
        "attests the user"
    );
    assert!(
        binding.envelope["scope"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s.as_str().unwrap().starts_with("infra:")),
        "infra-only delegates_to"
    );

    // 1-phase POST /v1/setup/root: verify + persist the user-signed binding + bind
    // ROOT in ONE round-trip.
    let body = one_phase_claim_body(node_key_id, &user, "family", binding).await;
    let resp = client
        .post(format!("{base}/v1/setup/root"))
        .body(body)
        .send()
        .await
        .expect("POST setup/root (1-phase)");
    assert_eq!(resp.status(), 201, "1-phase claim must succeed");
    let fin: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(fin["identity_key_id"], user_key_id);
    assert_eq!(fin["cohort_scope"], "family", "cohort scope echoed");
    assert_eq!(fin["role"], "SYSTEM_ADMIN");
    assert!(
        fin["owner_binding_attestation_id"].as_str().is_some(),
        "response carries the owner-binding attestation id"
    );

    // ROOT/SystemAdmin derived + bound to the responsible user.
    let roots = store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .expect("list roots");
    assert_eq!(roots.len(), 1);
    assert_eq!(UserRole::from_wa_role(roots[0].role), UserRole::SystemAdmin);
    assert_eq!(roots[0].pubkey, user_key_id);

    // The responsible user is registered as identity_type "user".
    let user_key = engine
        .federation_directory()
        .lookup_public_key(user_key_id)
        .await
        .expect("lookup user")
        .expect("user key present after claim");
    assert_eq!(user_key.identity_type, identity_type::USER);

    // is_owner_bound → the user.
    assert_eq!(
        is_owner_bound(&engine, node_key_id).await.as_deref(),
        Some(user_key_id),
        "the claim emitted a live delegates_to(user → node, infra:*) owner-binding"
    );

    // The persisted delegates_to is GENUINELY USER-SIGNED: scrub_key_id is the
    // user and its signature verifies against the USER's pubkeys, NOT the node's.
    let edges = engine
        .federation_directory()
        .list_attestations_for(node_key_id)
        .await
        .expect("inbound edges");
    let binding_row = edges
        .iter()
        .find(|e| e.attestation_type == attestation_type::DELEGATES_TO)
        .expect("a delegates_to owner-binding exists");
    assert_eq!(
        binding_row.scrub_key_id, user_key_id,
        "scrub_key_id is the USER (genuinely user-signed), not the node"
    );
    let canonical =
        ceg_produce_canonicalize(&binding_row.attestation_envelope).expect("re-canonicalize");
    let outcome = ciris_persist::prelude::verify_hybrid(
        &canonical,
        &binding_row.scrub_signature_classical,
        binding_row.scrub_signature_pqc.as_deref(),
        &user_key.pubkey_ed25519_base64,
        user_key.pubkey_ml_dsa_65_base64.as_deref(),
        HybridPolicy::Strict,
        None,
    );
    assert!(
        outcome.is_ok(),
        "the owner-binding signature verifies against the USER's pubkeys: {outcome:?}"
    );
    // And it does NOT verify against the NODE's pubkeys.
    let node_key = engine
        .federation_directory()
        .lookup_public_key(node_key_id)
        .await
        .expect("lookup node")
        .expect("node key present");
    let against_node = ciris_persist::prelude::verify_hybrid(
        &canonical,
        &binding_row.scrub_signature_classical,
        binding_row.scrub_signature_pqc.as_deref(),
        &node_key.pubkey_ed25519_base64,
        node_key.pubkey_ml_dsa_65_base64.as_deref(),
        HybridPolicy::Strict,
        None,
    );
    assert!(
        against_node.is_err(),
        "the owner-binding does NOT verify against the node's pubkeys (it is user-signed)"
    );
}

/// A claim whose owner-binding is TAMPERED is rejected, and no ROOT is bound:
///   (a) an agency scope, (b) attested != node, (c) a wrong/forged signature.
#[tokio::test]
async fn claim_rejects_tampered_binding_and_signature() {
    let node_key_id = "ciris-tamper-node";
    let user_key_id = "ciris-tamper-user";
    let engine = node(node_key_id).await;
    register_node(&engine, node_key_id).await;
    let (base, _h) = serve_setup(Arc::clone(&engine), node_key_id).await;
    let client = reqwest::Client::new();
    let user = user_signer(user_key_id);

    let good = ciris_server::auth::ownership::build_signed_owner_binding(
        &user,
        node_key_id,
        &infra_scopes(),
    )
    .await
    .expect("build binding");

    // (a) Tamper the envelope to carry an agency scope → 400 (and the user's sig is
    //     over the ORIGINAL canonical bytes, so the structural agency reject fires).
    let mut agency = good.clone();
    agency.envelope["scope"] = serde_json::json!(["agency:act_on_behalf"]);
    let body = one_phase_claim_body(node_key_id, &user, "self", agency).await;
    let resp = client
        .post(format!("{base}/v1/setup/root"))
        .body(body)
        .send()
        .await
        .expect("POST (agency)");
    assert_eq!(resp.status(), 400, "an agency scope is rejected");
    assert!(
        store::list_by_role(&engine, WaRole::Root, 10)
            .await
            .unwrap()
            .is_empty(),
        "a rejected claim binds no ROOT"
    );

    // (b) Tamper attested node → 400.
    let mut wrong_node = good.clone();
    wrong_node.envelope["node_key_id"] = "some-other-node".into();
    let body = one_phase_claim_body(node_key_id, &user, "self", wrong_node).await;
    let resp = client
        .post(format!("{base}/v1/setup/root"))
        .body(body)
        .send()
        .await
        .expect("POST (wrong node)");
    assert_eq!(resp.status(), 400, "attested != THIS node is rejected");
    assert!(store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .unwrap()
        .is_empty());

    // (c) Wrong signature: a DIFFERENT key's pubkeys/sigs (envelope still attests
    //     the user) → 401 (the supplied sig won't verify against the supplied
    //     pubkeys after we swap only the signature in).
    let mut wrong_sig = good.clone();
    // Re-sign the SAME envelope with an imposter key, but claim it is the user's:
    // keep attesting_key_id + pubkeys as the user's, swap in the imposter's sig.
    let imposter = {
        let signing_key = SigningKey::from_bytes(&[0x77; 32]);
        let pqc = Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&[0x88; 32], "imposter-pqc".to_string())
                .expect("imposter ML-DSA-65 seed"),
        );
        LocalSigner::from_parts(
            signing_key,
            "ciris-imposter".to_string(),
            Some(pqc),
            Some("imposter-pqc".to_string()),
        )
    };
    let canonical = ceg_produce_canonicalize(&good.envelope).expect("canonicalize");
    let bad = imposter
        .sign_hybrid(&canonical)
        .await
        .expect("imposter sign");
    wrong_sig.ed25519_sig_b64 = BASE64.encode(&bad.classical.signature);
    wrong_sig.ml_dsa_65_sig_b64 = BASE64.encode(&bad.pqc.signature);
    let body = one_phase_claim_body(node_key_id, &user, "self", wrong_sig).await;
    let resp = client
        .post(format!("{base}/v1/setup/root"))
        .body(body)
        .send()
        .await
        .expect("POST (wrong sig)");
    assert_eq!(
        resp.status(),
        401,
        "a signature that does not verify is rejected"
    );
    assert!(
        store::list_by_role(&engine, WaRole::Root, 10)
            .await
            .unwrap()
            .is_empty(),
        "no ROOT bound on a bad-signature claim"
    );

    // The node is still unowned after all rejected claims.
    assert!(is_owner_bound(&engine, node_key_id).await.is_none());
}

#[tokio::test]
async fn claim_with_agency_scope_built_is_refused_by_builder() {
    // The producer-side gate: build_signed_owner_binding refuses agency scopes.
    let user = user_signer("ciris-agency-user");
    let e = ciris_server::auth::ownership::build_signed_owner_binding(
        &user,
        "ciris-agency-node",
        &["agency:act_on_behalf".to_string()],
    )
    .await
    .expect_err("agency scope must be refused at build time");
    assert!(matches!(e, OwnershipError::AgencyScopeRefused));
}

#[tokio::test]
async fn claim_without_cohort_scope_is_rejected() {
    let node_key_id = "ciris-nocohort-node";
    let user_key_id = "ciris-nocohort-user";
    let engine = node(node_key_id).await;
    register_node(&engine, node_key_id).await;
    let (base, _h) = serve_setup(Arc::clone(&engine), node_key_id).await;
    let client = reqwest::Client::new();
    let user = user_signer(user_key_id);
    let binding = ciris_server::auth::ownership::build_signed_owner_binding(
        &user,
        node_key_id,
        &infra_scopes(),
    )
    .await
    .expect("build binding");

    // No cohort_scope member.
    let claim = serde_json::json!({
        "node_code": node_code_string(node_key_id),
        "claim_pin": TEST_CLAIM_PIN,
        "owner_binding": binding,
    });
    let body = serde_json::to_vec(&claim).unwrap();
    let resp = client
        .post(format!("{base}/v1/setup/root"))
        .body(body)
        .send()
        .await
        .expect("POST (no cohort)");
    assert_eq!(
        resp.status(),
        400,
        "a claim without cohort_scope is rejected"
    );
}

#[tokio::test]
async fn claim_with_wrong_pin_is_rejected() {
    let node_key_id = "ciris-pin-node";
    let user_key_id = "ciris-pin-user";
    let engine = node(node_key_id).await;
    register_node(&engine, node_key_id).await;
    let (base, _h) = serve_setup(Arc::clone(&engine), node_key_id).await;
    let client = reqwest::Client::new();
    let user = user_signer(user_key_id);
    let binding = ciris_server::auth::ownership::build_signed_owner_binding(
        &user,
        node_key_id,
        &infra_scopes(),
    )
    .await
    .expect("build binding");

    let claim = serde_json::json!({
        "node_code": node_code_string(node_key_id),
        "cohort_scope": "self",
        "claim_pin": "WRONG-PIN",
        "owner_binding": binding,
    });
    let body = serde_json::to_vec(&claim).unwrap();
    let resp = client
        .post(format!("{base}/v1/setup/root"))
        .body(body)
        .send()
        .await
        .expect("POST (wrong pin)");
    assert_eq!(resp.status(), 401, "a wrong claim PIN is rejected");
    assert!(is_owner_bound(&engine, node_key_id).await.is_none());
}
