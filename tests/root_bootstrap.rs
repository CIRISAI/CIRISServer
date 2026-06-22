//! ROOT-user bootstrap + first-time-setup integration (CIRISServer#19).
//!
//! Proves the founder-becomes-SYSTEM_ADMIN flow end to end over the real
//! `wa_cert` substrate + the live HTTP/auth stack:
//!
//!   (a) a fresh engine + a baked seed → `bootstrap_if_needed` stores a ROOT
//!       WaCert whose role bridges to `UserRole::SystemAdmin`;
//!   (b) a second `bootstrap_if_needed` with a ROOT present is an idempotent no-op;
//!   (c) `POST /v1/setup/root` claims ROOT on a seedless node, and a second claim
//!       is rejected (409 — no silent re-claim);
//!   (d) `auto_mint_root_if_needed` elevates an admin-eligible identity to a ROOT
//!       WaCert.
//!
//! Why this matters: the owner-gated `POST /v1/federation/peering` requires
//! `UserRole::SystemAdmin`. `WaRole::Root → SystemAdmin`, so each path here makes
//! the founder the owner — closing the gap that blocked peering.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::WaRole;

use ciris_server::auth::bootstrap::{
    self, auto_mint_root_if_needed, bootstrap_if_needed, is_admin_eligible, BootstrapOutcome,
};
use ciris_server::auth::roles::UserRole;
use ciris_server::auth::store;

/// An in-memory substrate keyed by a HYBRID node-identity signer (so `sign_hybrid`
/// works for the setup/root signature path). `key_id` is the node's federation id.
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
        .expect("Engine::with_signer (sqlite::memory:) must succeed");
    Arc::new(engine)
}

/// Register this node's own steward key via the canonical admission gate — the
/// precondition for `verify_request` to resolve the node's `key_id` (setup/root).
async fn register_self(engine: &Engine, key_id: &str) {
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize self envelope");
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .expect("self hybrid sign");
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: BASE64.encode(&sig.classical.public_key),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(&sig.pqc.public_key)),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::STEWARD.into(),
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
        .expect("register node steward key via admission gate");
}

/// The node's raw Ed25519 pubkey (base64) for `key_id` — derived from the SAME
/// `[0xA1; 32]` seed `node()` builds its signer from. This is the pubkey carried
/// on the node's NodeCode (CEG §0.10) and the value the first-run claim must pin.
fn node_pubkey_b64() -> String {
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    BASE64.encode(signing_key.verifying_key().to_bytes())
}

// ─── (a) seed-import utility → ROOT WaCert; (b) idempotent no-op ─────────────

// Server 0.5 (zero env): the boot path NEVER pre-seeds a root from env/file — it
// always takes the no-seed claim route. The seed-import *utilities*
// (`root_cert_from_seed` + `system_wa_cert`) are still exercised here directly (an
// explicit out-of-band import tool, NOT the boot path) to keep coverage of the
// agent's `root_pub.json` shape; AFTER seeding, `bootstrap_if_needed` is the
// idempotent no-op it must remain when a ROOT already exists.
#[tokio::test]
async fn seed_import_utility_creates_root_then_bootstrap_is_idempotent_noop() {
    let engine = node("ciris-seed-node").await;

    // The agent's root_pub.json shape, parsed by the pub utility (no env/file boot
    // read — we deserialize the shape directly, mirroring an import tool).
    let seed: bootstrap::RootSeed = serde_json::from_value(serde_json::json!({
        "wa_id": "wa-2025-06-14-ROOT00",
        "name": "ciris_root",
        "role": "root",
        "pubkey": "QK0ZQ9FhWKMtP8YL3wXU_n0cmqYyV3HoDi-AIJgSHi0",
        "jwt_kid": "wa-jwt-root00",
        "scopes_json": "[\"*\"]",
        "created": "2025-06-16T20:55:42.680865Z",
        "active": 1,
        "token_type": "standard"
    }))
    .expect("parse agent root_pub.json shape");

    // (a) Import via the pub utilities (the boot path no longer does this).
    let cert = bootstrap::root_cert_from_seed(&seed).expect("root cert from seed");
    store::upsert(&engine, cert).await.expect("upsert root");
    store::upsert(&engine, bootstrap::system_wa_cert("wa-2025-06-14-ROOT00"))
        .await
        .expect("upsert system wa");

    let roots = store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .expect("list roots");
    assert_eq!(roots.len(), 1, "exactly one ROOT WaCert after seed import");
    let root = &roots[0];
    assert_eq!(root.wa_id, "wa-2025-06-14-ROOT00");
    assert_eq!(root.role, WaRole::Root);
    assert!(root.active);
    // Role bridges to the owner role.
    assert_eq!(UserRole::from_wa_role(root.role), UserRole::SystemAdmin);
    // A child-of-root SYSTEM WA was created.
    let system = store::get(&engine, "wa-system-00")
        .await
        .expect("get system wa")
        .expect("system wa present");
    assert_eq!(system.parent_wa_id.as_deref(), Some("wa-2025-06-14-ROOT00"));

    // (b) bootstrap_if_needed with a ROOT present → idempotent no-op (unchanged).
    let outcome = bootstrap_if_needed(&engine).await.expect("bootstrap");
    assert_eq!(outcome, BootstrapOutcome::AlreadyBootstrapped);
    let roots2 = store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .expect("list roots 2");
    assert_eq!(
        roots2.len(),
        1,
        "no duplicate ROOT after bootstrap_if_needed"
    );
}

// Server 0.5 (zero env): a fresh node ALWAYS takes the no-seed (claim) path — the
// boot bootstrap is a clean no-op-then-claim with NO env reads.
#[tokio::test]
async fn bootstrap_on_fresh_node_is_a_clean_noseed_noop() {
    let engine = node("ciris-noseed-node").await;

    let outcome = bootstrap_if_needed(&engine).await.expect("bootstrap");
    assert_eq!(outcome, BootstrapOutcome::NoSeedAvailable);
    let roots = store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .expect("list roots");
    assert!(
        roots.is_empty(),
        "fresh node ⇒ no ROOT (first-run claim available at POST /v1/setup/root)"
    );
}

// ─── (c) first-run 1-phase POST /v1/setup/root claim ─────────────────────────

/// The responsible USER's hybrid signer (Ed25519 + ML-DSA-65), distinct from the
/// node's signer. The claiming node signs the owner-binding with THIS key (the
/// 1-phase, substrate-native claim); the user is registered + ROOT bound to it.
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

/// A known, fixed one-time claim PIN the tests arm the router with (the boot path
/// mints a random one; here we pin a value so a test can supply the correct PIN).
const TEST_CLAIM_PIN: &str = "TEST-PIN1";

/// Serve the bootstrap (setup) router on an ephemeral port; return its base URL.
async fn serve(engine: Arc<Engine>, node_key_id: &str) -> (String, tokio::task::JoinHandle<()>) {
    serve_with_pin(engine, node_key_id, Some(TEST_CLAIM_PIN.to_string())).await
}

/// Serve the bootstrap router armed with an EXPLICIT claim PIN (or `None`).
async fn serve_with_pin(
    engine: Arc<Engine>,
    node_key_id: &str,
    claim_pin: Option<String>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = bootstrap::router(
        engine,
        HybridPolicy::Strict,
        node_key_id.to_string(),
        node_pubkey_b64(),
        claim_pin,
        None,
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

/// THIS node's NodeCode string (CEG §0.10) for the identity-pin.
fn node_code_string(key_id: &str) -> String {
    let nc = ciris_server::nodecode::NodeCode {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: node_pubkey_b64(),
        transport_hint: None,
        alias_hint: None,
    };
    ciris_server::nodecode::encode(&nc).expect("encode node code")
}

/// Build the 1-phase claim body for `user` claiming `node_key_id`: the NodeCode
/// pin + cohort + PIN + a COMPLETE, user-signed owner-binding (built in the
/// substrate via `build_signed_owner_binding`). `claim_pin`/`cohort` overridable.
async fn one_phase_body(
    node_key_id: &str,
    user: &LocalSigner,
    claim_pin: Option<&str>,
    cohort_scope: Option<&str>,
) -> Vec<u8> {
    let infra_scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let binding =
        ciris_server::auth::ownership::build_signed_owner_binding(user, node_key_id, &infra_scopes)
            .await
            .expect("build signed owner-binding");
    let mut claim = serde_json::json!({
        "node_code": node_code_string(node_key_id),
        "owner_binding": binding,
    });
    if let Some(pin) = claim_pin {
        claim["claim_pin"] = pin.into();
    }
    if let Some(c) = cohort_scope {
        claim["cohort_scope"] = c.into();
    }
    serde_json::to_vec(&claim).unwrap()
}

async fn post_claim(
    client: &reqwest::Client,
    base: &str,
    body: Vec<u8>,
) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = client
        .post(format!("{base}/v1/setup/root"))
        .body(body)
        .send()
        .await
        .expect("POST setup/root");
    let status = resp.status();
    let json: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn first_run_setup_root_claims_then_rejects_second_claim() {
    let node_key_id = "ciris-founder-node";
    let user_key_id = "ciris-fresh-user";
    let engine = node(node_key_id).await;
    register_self(&engine, node_key_id).await;
    assert!(
        engine
            .federation_directory()
            .lookup_public_key(user_key_id)
            .await
            .expect("lookup user")
            .is_none(),
        "user key must be ABSENT before the claim (registered by the claim)"
    );

    let (base, _h) = serve(Arc::clone(&engine), node_key_id).await;
    let client = reqwest::Client::new();
    let user = user_signer(user_key_id);

    // 1-phase claim → 201, ROOT bound + user registered.
    let body = one_phase_body(node_key_id, &user, Some(TEST_CLAIM_PIN), Some("self")).await;
    let (status, fin) = post_claim(&client, &base, body).await;
    assert_eq!(status, 201, "1-phase claim must succeed");
    assert_eq!(fin["identity_key_id"], user_key_id);
    assert_eq!(fin["role"], "SYSTEM_ADMIN");

    let roots = store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(UserRole::from_wa_role(roots[0].role), UserRole::SystemAdmin);
    assert_eq!(roots[0].pubkey, user_key_id);
    // The user key is registered after the claim.
    assert!(engine
        .federation_directory()
        .lookup_public_key(user_key_id)
        .await
        .unwrap()
        .is_some());

    // Second claim (replay) → 409 (no silent re-claim).
    let body2 = one_phase_body(node_key_id, &user, Some(TEST_CLAIM_PIN), Some("self")).await;
    let (status3, _) = post_claim(&client, &base, body2).await;
    assert_eq!(status3, 409, "root already claimed ⇒ replay is 409");
    assert_eq!(
        store::list_by_role(&engine, WaRole::Root, 10)
            .await
            .unwrap()
            .len(),
        1
    );
}

/// A claim whose owner-binding signature is TAMPERED is rejected (401), no ROOT.
#[tokio::test]
async fn first_run_setup_root_rejects_tampered_signature() {
    let node_key_id = "ciris-tamper-node";
    let user_key_id = "ciris-tamper-user";
    let engine = node(node_key_id).await;
    register_self(&engine, node_key_id).await;
    let (base, _h) = serve(Arc::clone(&engine), node_key_id).await;
    let client = reqwest::Client::new();
    let user = user_signer(user_key_id);

    let infra_scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut binding = ciris_server::auth::ownership::build_signed_owner_binding(
        &user,
        node_key_id,
        &infra_scopes,
    )
    .await
    .expect("build binding");
    // Tamper the Ed25519 signature: flip the last byte.
    let mut sig = BASE64.decode(&binding.ed25519_sig_b64).unwrap();
    *sig.last_mut().unwrap() ^= 0x01;
    binding.ed25519_sig_b64 = BASE64.encode(&sig);

    let claim = serde_json::json!({
        "node_code": node_code_string(node_key_id),
        "cohort_scope": "self",
        "claim_pin": TEST_CLAIM_PIN,
        "owner_binding": binding,
    });
    let (status, _) = post_claim(&client, &base, serde_json::to_vec(&claim).unwrap()).await;
    assert_eq!(status, 401, "a tampered signature must be rejected");
    assert!(store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .unwrap()
        .is_empty());
    assert!(engine
        .federation_directory()
        .lookup_public_key(user_key_id)
        .await
        .unwrap()
        .is_none());
}

/// A claim whose NodeCode pins a DIFFERENT node is rejected (400), no ROOT.
#[tokio::test]
async fn first_run_setup_root_rejects_wrong_node_pin() {
    let key_id = "ciris-target-node";
    let user_key_id = "ciris-wrongpin-user";
    let engine = node(key_id).await;
    register_self(&engine, key_id).await;
    let (base, _h) = serve(Arc::clone(&engine), key_id).await;
    let client = reqwest::Client::new();
    let user = user_signer(user_key_id);

    // A NodeCode for a DIFFERENT node (a spoof).
    let wrong = ciris_server::nodecode::NodeCode {
        key_id: "some-other-node".to_string(),
        pubkey_ed25519_base64: BASE64.encode([0x42u8; 32]),
        transport_hint: None,
        alias_hint: None,
    };
    let wrong_code = ciris_server::nodecode::encode(&wrong).expect("encode wrong code");
    let infra_scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let binding =
        ciris_server::auth::ownership::build_signed_owner_binding(&user, key_id, &infra_scopes)
            .await
            .expect("build binding");
    let claim = serde_json::json!({
        "node_code": wrong_code,
        "cohort_scope": "self",
        "claim_pin": TEST_CLAIM_PIN,
        "owner_binding": binding,
    });
    let (status, _) = post_claim(&client, &base, serde_json::to_vec(&claim).unwrap()).await;
    assert_eq!(
        status, 400,
        "a NodeCode pinning a different node must be rejected"
    );
    assert!(store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .unwrap()
        .is_empty());
}

/// A claim with NO NodeCode pin is rejected (400) — the pin is mandatory.
#[tokio::test]
async fn first_run_setup_root_requires_a_pin() {
    let key_id = "ciris-pinless-node";
    let engine = node(key_id).await;
    register_self(&engine, key_id).await;
    let (base, _h) = serve(Arc::clone(&engine), key_id).await;
    let client = reqwest::Client::new();

    let body = serde_json::to_vec(&serde_json::json!({})).unwrap();
    let (status, _) = post_claim(&client, &base, body).await;
    assert_eq!(status, 400, "a claim with no NodeCode pin is rejected");
    assert!(store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .unwrap()
        .is_empty());
}

// ─── one-time CLAIM PIN — the operator-presence secret gate ──────────────────

/// The correct PIN binds ROOT and the PIN is CONSUMED — a second claim (even with
/// the same correct PIN) is 409-closed.
#[tokio::test]
async fn claim_pin_is_consumed_after_successful_claim() {
    let node_key_id = "ciris-pin-consume-node";
    let user_key_id = "ciris-pin-consume-user";
    let engine = node(node_key_id).await;
    register_self(&engine, node_key_id).await;
    let (base, _h) = serve(Arc::clone(&engine), node_key_id).await;
    let client = reqwest::Client::new();
    let user = user_signer(user_key_id);

    let body = one_phase_body(node_key_id, &user, Some(TEST_CLAIM_PIN), Some("self")).await;
    let (s, _) = post_claim(&client, &base, body).await;
    assert_eq!(s, 201, "correct PIN binds ROOT");
    assert_eq!(
        store::list_by_role(&engine, WaRole::Root, 10)
            .await
            .unwrap()
            .len(),
        1
    );

    // A second claim (fresh user, same correct PIN) → 409 (route first-run-closed).
    let replayer = user_signer("ciris-pin-replayer");
    let body2 = one_phase_body(node_key_id, &replayer, Some(TEST_CLAIM_PIN), Some("self")).await;
    let (sr, _) = post_claim(&client, &base, body2).await;
    assert_eq!(
        sr, 409,
        "after a successful claim the route is first-run-closed"
    );
    assert_eq!(
        store::list_by_role(&engine, WaRole::Root, 10)
            .await
            .unwrap()
            .len(),
        1
    );
}

/// A WRONG PIN → 401, NO ROOT minted, user not registered.
#[tokio::test]
async fn claim_with_wrong_pin_is_rejected() {
    let node_key_id = "ciris-wrongpin2-node";
    let user_key_id = "ciris-wrongpin2-user";
    let engine = node(node_key_id).await;
    register_self(&engine, node_key_id).await;
    let (base, _h) = serve(Arc::clone(&engine), node_key_id).await;
    let client = reqwest::Client::new();
    let user = user_signer(user_key_id);

    let body = one_phase_body(node_key_id, &user, Some("WRNG-PIN0"), Some("self")).await;
    let (status, _) = post_claim(&client, &base, body).await;
    assert_eq!(status, 401, "a wrong PIN is rejected");
    assert!(store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .unwrap()
        .is_empty());
    assert!(engine
        .federation_directory()
        .lookup_public_key(user_key_id)
        .await
        .unwrap()
        .is_none());
}

/// A MISSING PIN → 401, NO ROOT minted.
#[tokio::test]
async fn claim_with_missing_pin_is_rejected() {
    let node_key_id = "ciris-nopin-node";
    let user_key_id = "ciris-nopin-user";
    let engine = node(node_key_id).await;
    register_self(&engine, node_key_id).await;
    let (base, _h) = serve(Arc::clone(&engine), node_key_id).await;
    let client = reqwest::Client::new();
    let user = user_signer(user_key_id);

    let body = one_phase_body(node_key_id, &user, None, Some("self")).await;
    let (status, _) = post_claim(&client, &base, body).await;
    assert_eq!(status, 401, "a missing PIN is rejected");
    assert!(store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .unwrap()
        .is_empty());
}

/// An UN-ARMED node (router built with `claim_pin: None`) rejects every claim with
/// 401 — the PIN gate fails closed when no PIN is armed.
#[tokio::test]
async fn unarmed_node_rejects_claims() {
    let node_key_id = "ciris-unarmed-node";
    let user_key_id = "ciris-unarmed-user";
    let engine = node(node_key_id).await;
    register_self(&engine, node_key_id).await;
    let (base, _h) = serve_with_pin(Arc::clone(&engine), node_key_id, None).await;
    let client = reqwest::Client::new();
    let user = user_signer(user_key_id);

    let body = one_phase_body(node_key_id, &user, Some(TEST_CLAIM_PIN), Some("self")).await;
    let (status, _) = post_claim(&client, &base, body).await;
    assert_eq!(status, 401, "an un-armed node rejects all claims");
    assert!(store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .unwrap()
        .is_empty());
}

/// Unit: `generate_claim_pin` produces an `XXXX-XXXX` Crockford-base32 PIN, and
/// successive PINs differ (random source).
#[test]
fn generate_claim_pin_shape_and_randomness() {
    let p1 = bootstrap::generate_claim_pin();
    assert_eq!(p1.len(), 9, "8 chars + 1 dash");
    assert_eq!(&p1[4..5], "-", "dash splits the two groups");
    let groups: Vec<&str> = p1.split('-').collect();
    assert_eq!(groups.len(), 2);
    assert!(groups.iter().all(|g| g.len() == 4));
    // Crockford alphabet only (no I/L/O/U; uppercase + digits).
    const ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    assert!(p1
        .chars()
        .filter(|&c| c != '-')
        .all(|c| ALPHABET.contains(c)));
    // Overwhelmingly likely to differ (40 bits of entropy).
    let p2 = bootstrap::generate_claim_pin();
    assert_ne!(p1, p2, "successive PINs differ");
}

// ─── (d) auto_mint_root_if_needed elevates an admin-eligible identity ────────

#[tokio::test]
async fn auto_mint_elevates_admin_eligible_identity() {
    let engine = node("ciris-mint-node").await;
    let identity = "ciris-founder-identity";

    // Not admin-eligible → no-op, no ROOT.
    let minted_none = auto_mint_root_if_needed(&engine, identity, false)
        .await
        .expect("auto-mint non-admin");
    assert!(!minted_none, "non-admin is a no-op");
    assert!(store::list_by_role(&engine, WaRole::Root, 1)
        .await
        .expect("list roots")
        .is_empty());

    // Admin-eligible → mints a ROOT WaCert bound to the identity.
    let minted = auto_mint_root_if_needed(&engine, identity, true)
        .await
        .expect("auto-mint admin");
    assert!(minted, "admin-eligible identity is minted as ROOT");
    let roots = store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .expect("list roots");
    assert_eq!(roots.len(), 1);
    assert_eq!(
        roots[0].pubkey, identity,
        "ROOT cert bound to the identity key"
    );
    assert_eq!(UserRole::from_wa_role(roots[0].role), UserRole::SystemAdmin);

    // Idempotent: a second mint for the same identity is a no-op.
    let minted_again = auto_mint_root_if_needed(&engine, identity, true)
        .await
        .expect("auto-mint admin again");
    assert!(!minted_again, "re-mint of an existing ROOT is a no-op");
    assert_eq!(
        store::list_by_role(&engine, WaRole::Root, 10)
            .await
            .expect("list roots")
            .len(),
        1,
        "no duplicate ROOT"
    );
}

// Server 0.5 (zero env): admin eligibility is the boot-resolved config:*
// `auth.admin_key_ids` allowlist, passed as a slice (no CIRIS_ADMIN_KEY_IDS /
// CIRIS_ROOT_KEY_ID env).
#[tokio::test]
async fn admin_eligibility_reads_config_allowlist() {
    let allow: Vec<String> = vec!["alice".into(), " bob ".into(), "carol".into()];
    assert!(is_admin_eligible("alice", &allow));
    assert!(is_admin_eligible("bob", &allow), "whitespace is trimmed");
    assert!(is_admin_eligible("carol", &allow));
    assert!(!is_admin_eligible("mallory", &allow));

    // An empty allowlist admits no one.
    assert!(!is_admin_eligible("alice", &[]));
}
