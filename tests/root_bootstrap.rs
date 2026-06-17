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

use std::sync::{Arc, Mutex, OnceLock};

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

/// Serializes the env-touching tests (process-global `CIRIS_ROOT_*` env). A guard
/// that recovers from a poisoned lock (a panicking test must not cascade-fail the
/// rest — each env test fully sets the vars it reads).
fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

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

/// A FRESH founder hybrid signer (Ed25519 + ML-DSA-65), distinct from the node's
/// signer and NOT registered in the directory. Seeded distinctly per `key_id` so
/// each founder identity is unique. This is the claimant the self-attested
/// first-run flow admits: the founder presents these pubkeys + proves possession.
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

/// Serve the bootstrap (setup) router on an ephemeral port; return its base URL.
/// Pins the router to the node's identity (`key_id` + its Ed25519 pubkey).
async fn serve(engine: Arc<Engine>, node_key_id: &str) -> (String, tokio::task::JoinHandle<()>) {
    let app = bootstrap::router(
        engine,
        HybridPolicy::Strict,
        node_key_id.to_string(),
        node_pubkey_b64(),
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

// ─── (a) seed → ROOT WaCert; (b) idempotent no-op ───────────────────────────

// The env guard is deliberately held across awaits: it SERIALIZES the
// process-global `CIRIS_ROOT_*` env across these tests (that's the whole point),
// and the std Mutex is uncontended-by-design (one env test at a time) so no
// deadlock can arise. An async Mutex would defeat the serialization intent.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn seed_bootstrap_creates_root_then_is_idempotent() {
    let _guard = env_guard();
    let engine = node("ciris-seed-node").await;

    // Write the agent's root_pub.json shape to a unique temp file.
    let seed_path =
        std::env::temp_dir().join(format!("ciris_root_seed_{}.json", std::process::id()));
    let seed = serde_json::json!({
        "wa_id": "wa-2025-06-14-ROOT00",
        "name": "ciris_root",
        "role": "root",
        "pubkey": "QK0ZQ9FhWKMtP8YL3wXU_n0cmqYyV3HoDi-AIJgSHi0",
        "jwt_kid": "wa-jwt-root00",
        "scopes_json": "[\"*\"]",
        "created": "2025-06-16T20:55:42.680865Z",
        "active": 1,
        "token_type": "standard"
    });
    std::fs::write(&seed_path, serde_json::to_vec_pretty(&seed).unwrap()).unwrap();
    std::env::set_var(bootstrap::ENV_SEED_PATH, &seed_path);
    // Ensure the inline-pubkey path doesn't interfere.
    std::env::remove_var(bootstrap::ENV_ROOT_PUBKEY);
    std::env::remove_var(bootstrap::ENV_ROOT_WA_ID);

    // (a) Fresh engine → seed loaded.
    let outcome = bootstrap_if_needed(&engine).await.expect("bootstrap");
    assert_eq!(outcome, BootstrapOutcome::SeededRoot);

    let roots = store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .expect("list roots");
    assert_eq!(
        roots.len(),
        1,
        "exactly one ROOT WaCert after seed bootstrap"
    );
    let root = &roots[0];
    assert_eq!(root.wa_id, "wa-2025-06-14-ROOT00");
    assert_eq!(root.role, WaRole::Root);
    assert!(root.active);
    // Role bridges to the owner role.
    assert_eq!(UserRole::from_wa_role(root.role), UserRole::SystemAdmin);
    // A child-of-root SYSTEM WA was ensured.
    let system = store::get(&engine, "wa-system-00")
        .await
        .expect("get system wa")
        .expect("system wa present");
    assert_eq!(system.parent_wa_id.as_deref(), Some("wa-2025-06-14-ROOT00"));

    // (b) Second bootstrap with a ROOT present → idempotent no-op.
    let outcome2 = bootstrap_if_needed(&engine).await.expect("bootstrap 2");
    assert_eq!(outcome2, BootstrapOutcome::AlreadyBootstrapped);
    let roots2 = store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .expect("list roots 2");
    assert_eq!(roots2.len(), 1, "no duplicate ROOT after re-bootstrap");

    std::env::remove_var(bootstrap::ENV_SEED_PATH);
    let _ = std::fs::remove_file(&seed_path);
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn bootstrap_without_seed_is_a_clean_noop() {
    let _guard = env_guard();
    std::env::remove_var(bootstrap::ENV_SEED_PATH);
    std::env::remove_var(bootstrap::ENV_ROOT_PUBKEY);
    std::env::remove_var(bootstrap::ENV_ROOT_WA_ID);
    let engine = node("ciris-noseed-node").await;

    let outcome = bootstrap_if_needed(&engine).await.expect("bootstrap");
    assert_eq!(outcome, BootstrapOutcome::NoSeedAvailable);
    let roots = store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .expect("list roots");
    assert!(
        roots.is_empty(),
        "no seed ⇒ no ROOT (first-run claim available)"
    );
}

// ─── (c) first-run POST /v1/setup/root claims, second claim rejected ────────

/// Build THIS node's NodeCode string (CEG §0.10) for the identity-pin — the
/// out-of-band handle the founder's app holds. Uses the SAME `[0xA1; 32]` seed.
fn node_code_string(key_id: &str) -> String {
    let nc = ciris_server::nodecode::NodeCode {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: node_pubkey_b64(),
        transport_hint: None,
        alias_hint: None,
    };
    ciris_server::nodecode::encode(&nc).expect("encode node code")
}

/// Build the self-attested first-run claim body for `founder_key_id` pinning the
/// node `node_key_id`. Returns `(body_bytes, ed25519_pubkey_b64, ml_dsa_65_pubkey_b64)`.
fn founder_claim_body(node_key_id: &str, founder_key_id: &str) -> serde_json::Value {
    serde_json::json!({
        "node_code": node_code_string(node_key_id),
        "founder": {
            "key_id": founder_key_id,
            // Pubkeys are filled in by the caller after signing (they come off the
            // HybridSignature), so this placeholder is replaced below.
        }
    })
}

#[tokio::test]
async fn first_run_setup_root_claims_then_rejects_second_claim() {
    let node_key_id = "ciris-founder-node";
    let founder_key_id = "ciris-fresh-founder";
    let engine = node(node_key_id).await;
    // The NODE's own steward key is registered (so the node has an identity), but
    // the FOUNDER's key is deliberately NOT in the directory — proving the claim is
    // self-attested, not directory-resolved.
    register_self(&engine, node_key_id).await;
    assert!(
        engine
            .federation_directory()
            .lookup_public_key(founder_key_id)
            .await
            .expect("lookup founder")
            .is_none(),
        "founder key must be ABSENT from the directory before the claim (self-attested)"
    );

    let (base, _h) = serve(Arc::clone(&engine), node_key_id).await;
    let client = reqwest::Client::new();

    // The founder is a FRESH hybrid identity. The signed body carries the NodeCode
    // pin (CEG §0.10) AND the founder's OWN pubkeys; the hybrid signature (founder's
    // keypair) covers the whole body — self-attested proof-of-possession.
    let fsigner = founder_signer(founder_key_id);
    let mut claim = founder_claim_body(node_key_id, founder_key_id);
    // We need the pubkeys, which come off a sign over the FINAL body — so sign a
    // first time to extract pubkeys, fill them in, then re-sign the final body.
    let probe = fsigner.sign_hybrid(b"probe").await.expect("probe sign");
    claim["founder"]["ed25519_pubkey_b64"] = BASE64.encode(&probe.classical.public_key).into();
    claim["founder"]["ml_dsa_65_pubkey_b64"] = BASE64.encode(&probe.pqc.public_key).into();
    let body = serde_json::to_vec(&claim).unwrap();
    let sig = fsigner.sign_hybrid(&body).await.expect("sign setup body");
    let ed_b64 = BASE64.encode(&sig.classical.signature);
    let mldsa_b64 = BASE64.encode(&sig.pqc.signature);

    // No ROOT yet → claim succeeds (201) and binds the FOUNDER identity as ROOT.
    let resp = client
        .post(format!("{base}/v1/setup/root"))
        .header("x-ciris-signing-key-id", founder_key_id)
        .header("x-ciris-signature-ed25519", &ed_b64)
        .header("x-ciris-signature-ml-dsa-65", &mldsa_b64)
        .body(body.clone())
        .send()
        .await
        .expect("POST setup/root");
    assert_eq!(
        resp.status(),
        201,
        "first-run self-attested claim must succeed"
    );
    let json: serde_json::Value = resp.json().await.expect("setup response json");
    assert_eq!(json["identity_key_id"], founder_key_id);
    assert_eq!(json["role"], "SYSTEM_ADMIN");

    // A ROOT WaCert now exists, bridging to SystemAdmin, bound to the founder.
    let roots = store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .expect("list roots");
    assert_eq!(roots.len(), 1, "exactly one ROOT after first-run claim");
    assert_eq!(UserRole::from_wa_role(roots[0].role), UserRole::SystemAdmin);
    assert_eq!(
        roots[0].pubkey, founder_key_id,
        "ROOT bound to founder.key_id"
    );

    // The founder's key is now REGISTERED in the directory (admitted thereafter).
    assert!(
        engine
            .federation_directory()
            .lookup_public_key(founder_key_id)
            .await
            .expect("lookup founder after claim")
            .is_some(),
        "founder key must be REGISTERED after a successful claim"
    );

    // Second claim → 409 (no silent re-claim).
    let resp2 = client
        .post(format!("{base}/v1/setup/root"))
        .header("x-ciris-signing-key-id", founder_key_id)
        .header("x-ciris-signature-ed25519", &ed_b64)
        .header("x-ciris-signature-ml-dsa-65", &mldsa_b64)
        .body(body)
        .send()
        .await
        .expect("second POST setup/root");
    assert_eq!(resp2.status(), 409, "root already claimed ⇒ 409");
    let roots2 = store::list_by_role(&engine, WaRole::Root, 10)
        .await
        .expect("list roots 2");
    assert_eq!(roots2.len(), 1, "no second ROOT minted");
}

/// A first-run claim whose hybrid signature is TAMPERED is rejected (401) and
/// claims NO ROOT — proof-of-possession fails.
#[tokio::test]
async fn first_run_setup_root_rejects_tampered_signature() {
    let node_key_id = "ciris-tamper-node";
    let founder_key_id = "ciris-tamper-founder";
    let engine = node(node_key_id).await;
    register_self(&engine, node_key_id).await;
    let (base, _h) = serve(Arc::clone(&engine), node_key_id).await;
    let client = reqwest::Client::new();

    let fsigner = founder_signer(founder_key_id);
    let mut claim = founder_claim_body(node_key_id, founder_key_id);
    let probe = fsigner.sign_hybrid(b"probe").await.expect("probe sign");
    claim["founder"]["ed25519_pubkey_b64"] = BASE64.encode(&probe.classical.public_key).into();
    claim["founder"]["ml_dsa_65_pubkey_b64"] = BASE64.encode(&probe.pqc.public_key).into();
    let body = serde_json::to_vec(&claim).unwrap();
    let sig = fsigner.sign_hybrid(&body).await.expect("sign setup body");
    // Tamper the Ed25519 signature: flip the last byte before base64.
    let mut ed_sig = sig.classical.signature.clone();
    *ed_sig.last_mut().unwrap() ^= 0x01;
    let ed_b64 = BASE64.encode(&ed_sig);
    let mldsa_b64 = BASE64.encode(&sig.pqc.signature);

    let resp = client
        .post(format!("{base}/v1/setup/root"))
        .header("x-ciris-signing-key-id", founder_key_id)
        .header("x-ciris-signature-ed25519", &ed_b64)
        .header("x-ciris-signature-ml-dsa-65", &mldsa_b64)
        .body(body)
        .send()
        .await
        .expect("POST setup/root (tampered)");
    assert_eq!(resp.status(), 401, "a tampered signature must be rejected");
    assert!(
        store::list_by_role(&engine, WaRole::Root, 10)
            .await
            .expect("list roots")
            .is_empty(),
        "a rejected (tampered) claim must mint NO ROOT"
    );
    assert!(
        engine
            .federation_directory()
            .lookup_public_key(founder_key_id)
            .await
            .expect("lookup founder")
            .is_none(),
        "a rejected claim must NOT register the founder key"
    );
}

/// A first-run claim whose NodeCode pins a DIFFERENT node is rejected (400) and
/// claims NO ROOT — the spoof defense (CEG §0.10). First-run-only still holds:
/// the route is open (no ROOT yet), but the wrong-node pin closes it for this
/// claim.
#[tokio::test]
async fn first_run_setup_root_rejects_wrong_node_pin() {
    let key_id = "ciris-target-node";
    let founder_key_id = "ciris-wrongpin-founder";
    let engine = node(key_id).await;
    register_self(&engine, key_id).await;
    let (base, _h) = serve(Arc::clone(&engine), key_id).await;
    let client = reqwest::Client::new();

    // A NodeCode for a DIFFERENT node (a spoof the founder was tricked into).
    let wrong = ciris_server::nodecode::NodeCode {
        key_id: "some-other-node".to_string(),
        pubkey_ed25519_base64: BASE64.encode([0x42u8; 32]),
        transport_hint: None,
        alias_hint: None,
    };
    let wrong_code = ciris_server::nodecode::encode(&wrong).expect("encode wrong code");
    // A valid fresh founder — only the node pin is wrong.
    let fsigner = founder_signer(founder_key_id);
    let probe = fsigner.sign_hybrid(b"probe").await.expect("probe sign");
    let claim_body = serde_json::json!({
        "node_code": wrong_code,
        "founder": {
            "key_id": founder_key_id,
            "ed25519_pubkey_b64": BASE64.encode(&probe.classical.public_key),
            "ml_dsa_65_pubkey_b64": BASE64.encode(&probe.pqc.public_key),
        }
    });
    let body = serde_json::to_vec(&claim_body).unwrap();
    let sig = fsigner.sign_hybrid(&body).await.expect("sign setup body");
    let ed_b64 = BASE64.encode(&sig.classical.signature);
    let mldsa_b64 = BASE64.encode(&sig.pqc.signature);

    let resp = client
        .post(format!("{base}/v1/setup/root"))
        .header("x-ciris-signing-key-id", founder_key_id)
        .header("x-ciris-signature-ed25519", &ed_b64)
        .header("x-ciris-signature-ml-dsa-65", &mldsa_b64)
        .body(body)
        .send()
        .await
        .expect("POST setup/root (wrong pin)");
    assert_eq!(
        resp.status(),
        400,
        "a NodeCode pinning a different node must be rejected"
    );
    assert!(
        store::list_by_role(&engine, WaRole::Root, 10)
            .await
            .expect("list roots")
            .is_empty(),
        "a rejected (wrong-pin) claim must mint NO ROOT"
    );
}

/// A first-run claim with NO NodeCode pin is rejected (400) — the pin is
/// mandatory. First-run-only still holds (no ROOT minted).
#[tokio::test]
async fn first_run_setup_root_requires_a_pin() {
    let key_id = "ciris-pinless-node";
    let founder_key_id = "ciris-pinless-founder";
    let engine = node(key_id).await;
    register_self(&engine, key_id).await;
    let (base, _h) = serve(Arc::clone(&engine), key_id).await;
    let client = reqwest::Client::new();

    // Empty-object body — no pin (the pin check runs first, before the founder).
    let body = serde_json::to_vec(&serde_json::json!({})).unwrap();
    let fsigner = founder_signer(founder_key_id);
    let sig = fsigner.sign_hybrid(&body).await.expect("sign setup body");
    let ed_b64 = BASE64.encode(&sig.classical.signature);
    let mldsa_b64 = BASE64.encode(&sig.pqc.signature);

    let resp = client
        .post(format!("{base}/v1/setup/root"))
        .header("x-ciris-signing-key-id", founder_key_id)
        .header("x-ciris-signature-ed25519", &ed_b64)
        .header("x-ciris-signature-ml-dsa-65", &mldsa_b64)
        .body(body)
        .send()
        .await
        .expect("POST setup/root (no pin)");
    assert_eq!(
        resp.status(),
        400,
        "a claim with no NodeCode pin is rejected"
    );
    assert!(
        store::list_by_role(&engine, WaRole::Root, 10)
            .await
            .expect("list roots")
            .is_empty(),
        "a pinless claim must mint NO ROOT"
    );
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

#[tokio::test]
async fn admin_eligibility_reads_env_allowlist() {
    let _guard = env_guard();
    std::env::set_var(bootstrap::ENV_ADMIN_KEY_IDS, "alice, bob ,carol");
    std::env::remove_var(bootstrap::ENV_ROOT_KEY_ID);
    assert!(is_admin_eligible("alice"));
    assert!(is_admin_eligible("bob"), "whitespace is trimmed");
    assert!(is_admin_eligible("carol"));
    assert!(!is_admin_eligible("mallory"));
    std::env::remove_var(bootstrap::ENV_ADMIN_KEY_IDS);

    // The CIRIS_ROOT_KEY_ID single-identity path.
    std::env::set_var(bootstrap::ENV_ROOT_KEY_ID, "the-founder");
    assert!(is_admin_eligible("the-founder"));
    assert!(!is_admin_eligible("someone-else"));
    std::env::remove_var(bootstrap::ENV_ROOT_KEY_ID);
}
