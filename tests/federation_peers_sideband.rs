//! The #261 federation-peers WRITE SIDEBAND + SAS — the agent-compat routes
//! the CIRISAgent wave-2 DRY purge deletes from Python:
//!
//!   - `PUT /v1/federation/peers/{key_id}/trust` (OWNER)
//!   - `PUT /v1/federation/peers/{key_id}/appearance` (OWNER)
//!   - `PUT /v1/federation/peers/{key_id}/sas` (OWNER)
//!   - `GET /v1/federation/peers/{key_id}/sas` (open read)
//!
//! Drives the real [`ciris_server::federation_peers`] router over a bound TCP
//! listener (full HTTP + auth stack), mirroring `tests/federation_admin.rs`,
//! and proves:
//!
//!   1. The sideband PUT/GET ROUND-TRIP: an owner PUT of trust + appearance
//!      lands in the config-as-CEG store and is overlaid on BOTH the peer
//!      detail read and the peer list read (the `{"data": LocalPeerState}`
//!      envelope carries the fresh state immediately).
//!   2. The SAS leg: GET serves the deterministic `ciris_edge::sas` words +
//!      digits (recomputed independently in the test — byte-equal), and the
//!      owner PUT records the out-of-band verification state the GET then
//!      surfaces.
//!   3. The gates: no session ⇒ 401, non-owner role ⇒ 403, unknown peer ⇒
//!      404 `PEER_NOT_FOUND` — and a rejected PUT writes NO sideband.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};

use ciris_server::auth::store;
use ciris_server::federation_peers;

const NODE_A_KEY_ID: &str = "ciris-server";
const PEER_KEY_ID: &str = "ciris-status";

/// Stand up THIS node: an in-memory substrate keyed by a HYBRID node-identity
/// signer so `sign_hybrid` (the self-record + config:v1 sideband emit) works.
/// Mirrors `tests/federation_admin.rs::node`.
async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_A_KEY_ID}-pqc"))
            .expect("node ML-DSA-65 seed"),
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

/// The node's #247 DERIVED federation key_id (== prod's `cfg.key_id`) — what
/// the router excludes from listings and `emit_attestation_self` attests under.
async fn node_a_key_id(engine: &Engine) -> String {
    engine
        .local_derived_key_id()
        .await
        .expect("derive node-A federation key_id")
}

/// Register this node's own steward key via the canonical admission gate — the
/// `put_attestation` attesting-key FK precondition for the sideband config
/// emit. Mirrors `tests/federation_admin.rs::register_self`.
async fn register_self(engine: &Engine) {
    let now = chrono::Utc::now();
    let key_id = node_a_key_id(engine).await;
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize self envelope");
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .expect("self hybrid sign");
    let record = KeyRecord {
        key_id: key_id.clone(),
        pubkey_ed25519_base64: BASE64.encode(&sig.classical.public_key),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(&sig.pqc.public_key)),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::STEWARD.into(),
        identity_ref: key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .register_federation_key(SignedKeyRecord { record })
        .await
        .expect("register node steward key via admission gate");
}

/// The responsible-party (owner) user key_id + deterministic seeds — the
/// serve-only floor (`require_owner_bound`) refuses sideband writes on an
/// owner-UNBOUND node, so the fixture binds one exactly as
/// `tests/federation_admin.rs::bind_owner` does.
const OWNER_USER_KEY_ID: &str = "ciris-owner-user";
const OWNER_ED_SEED: [u8; 32] = [0xF1; 32];
const OWNER_PQC_SEED: [u8; 32] = [0xF2; 32];

fn owner_user_signer() -> LocalSigner {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&OWNER_PQC_SEED, format!("{OWNER_USER_KEY_ID}-pqc"))
            .expect("owner ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        SigningKey::from_bytes(&OWNER_ED_SEED),
        OWNER_USER_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{OWNER_USER_KEY_ID}-pqc")),
    )
}

async fn bind_owner(engine: &Engine) {
    let owner_signer = owner_user_signer();
    let owner_ed_pub = BASE64.encode(
        SigningKey::from_bytes(&OWNER_ED_SEED)
            .verifying_key()
            .to_bytes(),
    );
    let owner_mldsa_pub = {
        let pqc = MlDsa65SoftwareSigner::from_seed_bytes(
            &OWNER_PQC_SEED,
            format!("{OWNER_USER_KEY_ID}-pqc"),
        )
        .expect("owner ML-DSA-65 seed");
        BASE64.encode(pqc.public_key().await.expect("owner ML-DSA-65 pubkey"))
    };
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": OWNER_USER_KEY_ID });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize owner envelope");
    let record = KeyRecord {
        key_id: OWNER_USER_KEY_ID.to_string(),
        pubkey_ed25519_base64: owner_ed_pub,
        pubkey_ml_dsa_65_base64: Some(owner_mldsa_pub),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::USER.into(),
        identity_ref: OWNER_USER_KEY_ID.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: OWNER_USER_KEY_ID.to_string(),
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
        .expect("register responsible-party user key");

    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let node_key_id = node_a_key_id(engine).await;
    ciris_server::auth::ownership::emit_steward_binding(
        engine,
        &owner_signer,
        &node_key_id,
        &scopes,
    )
    .await
    .expect("emit owner-binding delegates_to(user -> node, infra:*)");
}

/// Seed the PEER whose sideband the tests write: a self-signed witness key
/// placed straight into the directory (the sideband routes only require the
/// row to EXIST — admission-path coverage lives in tests/federation_admin.rs).
/// Returns the peer's Ed25519 pubkey for the SAS recompute.
async fn seed_peer(engine: &Engine) -> [u8; 32] {
    let ed = SigningKey::from_bytes(&[0xB0; 32]);
    let mldsa = MlDsa65SoftwareSigner::from_seed_bytes(&[0xB1; 32], format!("{PEER_KEY_ID}-pqc"))
        .expect("peer ML-DSA-65 seed");

    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": PEER_KEY_ID });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize peer registration");
    let ed_sig = ed.sign(&canonical).to_bytes();

    let record = KeyRecord {
        key_id: PEER_KEY_ID.to_string(),
        pubkey_ed25519_base64: BASE64.encode(ed.verifying_key().to_bytes()),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(mldsa.public_key().await.expect("ml-dsa pk"))),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::WITNESS.into(),
        identity_ref: PEER_KEY_ID.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(ed_sig),
        scrub_signature_pqc: None,
        scrub_key_id: PEER_KEY_ID.to_string(),
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
        .expect("seed peer key into directory");
    ed.verifying_key().to_bytes()
}

/// Mint an active `wa_cert` of the given role + return a bound session bearer
/// token (`sess:<wa_id>:<rand>` — the exact shape `resolve_bearer` parses).
async fn mint_session(engine: &Engine, wa_id: &str, role: WaRole) -> String {
    let now = chrono::Utc::now();
    let cert = WaCert {
        wa_id: wa_id.to_string(),
        name: wa_id.to_string(),
        role,
        pubkey: BASE64.encode([0u8; 32]),
        jwt_kid: format!("kid-{wa_id}"),
        password_hash: None,
        api_key_hash: None,
        oauth_provider: None,
        oauth_external_id: None,
        oauth_links: None,
        veilid_id: None,
        auto_minted: false,
        parent_wa_id: None,
        parent_signature: None,
        scopes: serde_json::json!([]),
        custom_permissions: None,
        adapter_id: None,
        adapter_name: None,
        adapter_metadata: None,
        token_type: TokenType::Session,
        created: now,
        last_login: None,
        active: true,
    };
    store::upsert(engine, cert).await.expect("mint wa_cert");
    format!("sess:{wa_id}:testtoken")
}

/// Serve the federation-peers router on an ephemeral port; return its base URL
/// + the JoinHandle (dropped at test end).
async fn serve(engine: Arc<Engine>) -> (String, tokio::task::JoinHandle<()>) {
    let node_key_id = node_a_key_id(&engine).await;
    let app = federation_peers::router(engine, node_key_id);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn owner_sideband_put_get_round_trip() {
    let engine = node().await;
    register_self(&engine).await;
    bind_owner(&engine).await;
    let peer_ed_pub = seed_peer(&engine).await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    // ── PUT trust → the {"data": LocalPeerState} envelope carries it ──────────
    let resp = client
        .put(format!("{base}/v1/federation/peers/{PEER_KEY_ID}/trust"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "trust": "blocked" }))
        .send()
        .await
        .expect("PUT trust");
    assert_eq!(resp.status(), 200, "owner trust PUT must succeed");
    let json: serde_json::Value = resp.json().await.expect("trust response json");
    assert_eq!(json["data"]["key_id"], PEER_KEY_ID);
    assert_eq!(json["data"]["trust"], "blocked");

    // ── PUT appearance (partial tuple — icon + fg only) ───────────────────────
    let resp = client
        .put(format!(
            "{base}/v1/federation/peers/{PEER_KEY_ID}/appearance"
        ))
        .bearer_auth(&owner)
        .json(&serde_json::json!({
            "appearance": { "icon": "satellite", "fg_color": "#ffffff" }
        }))
        .send()
        .await
        .expect("PUT appearance");
    assert_eq!(resp.status(), 200, "owner appearance PUT must succeed");
    let json: serde_json::Value = resp.json().await.expect("appearance response json");
    assert_eq!(json["data"]["appearance"]["icon"], "satellite");
    assert_eq!(json["data"]["appearance"]["fg_color"], "#ffffff");
    // The earlier trust write survives the appearance write (read-modify-write
    // on ONE sideband row, not last-writer-clobbers).
    assert_eq!(json["data"]["trust"], "blocked");

    // ── GET detail overlays the sideband ──────────────────────────────────────
    let resp = client
        .get(format!("{base}/v1/federation/peers/{PEER_KEY_ID}"))
        .send()
        .await
        .expect("GET peer detail");
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.expect("detail json");
    assert_eq!(json["peer"]["trust"], "blocked");
    assert_eq!(json["peer"]["appearance"]["icon"], "satellite");

    // ── GET list overlays the sideband too ────────────────────────────────────
    let resp = client
        .get(format!("{base}/v1/federation/peers"))
        .send()
        .await
        .expect("GET peer list");
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.expect("list json");
    let peer = json["peers"]
        .as_array()
        .expect("peers array")
        .iter()
        .find(|p| p["key_id"] == PEER_KEY_ID)
        .expect("seeded peer present in list");
    assert_eq!(peer["trust"], "blocked");
    assert_eq!(peer["appearance"]["icon"], "satellite");

    // ── GET sas — deterministic ciris_edge::sas words + digits ────────────────
    let resp = client
        .get(format!("{base}/v1/federation/peers/{PEER_KEY_ID}/sas"))
        .send()
        .await
        .expect("GET sas");
    assert_eq!(resp.status(), 200, "SAS read is unauthenticated");
    let json: serde_json::Value = resp.json().await.expect("sas json");
    assert_eq!(json["data"]["key_id"], PEER_KEY_ID);
    let words: Vec<String> = json["data"]["words"]
        .as_array()
        .expect("words array")
        .iter()
        .map(|w| w.as_str().expect("word").to_string())
        .collect();
    let digits = json["data"]["digits"].as_str().expect("digits");
    assert_eq!(words.len(), 5, "default SAS word count");
    assert_eq!(digits.len(), 6, "default SAS digit count");
    assert_eq!(
        json["data"]["verified"],
        serde_json::Value::Null,
        "no verification recorded yet"
    );
    // Recompute independently — the served SAS must be the pure
    // ciris_edge::sas function of (local_pub, peer_pub), byte-equal.
    let local_pub: [u8; 32] = engine
        .signer()
        .public_key()
        .await
        .expect("local signer pubkey")
        .as_slice()
        .try_into()
        .expect("32-byte Ed25519");
    let expected_words =
        ciris_edge::sas::peer_sas_words(&local_pub, &peer_ed_pub, 5).expect("recompute SAS words");
    let expected_digits = ciris_edge::sas::peer_sas_digits(&local_pub, &peer_ed_pub, 6)
        .expect("recompute SAS digits");
    assert_eq!(words, expected_words, "served words == pure-function words");
    assert_eq!(
        digits, expected_digits,
        "served digits == pure-function digits"
    );

    // ── PUT sas verified → GET surfaces the recorded state ────────────────────
    let resp = client
        .put(format!("{base}/v1/federation/peers/{PEER_KEY_ID}/sas"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "verified": true }))
        .send()
        .await
        .expect("PUT sas");
    assert_eq!(resp.status(), 200, "owner SAS PUT must succeed");
    let json: serde_json::Value = resp.json().await.expect("sas put json");
    assert_eq!(json["data"]["verified"], true);
    assert!(
        json["data"]["verified_at"].as_str().is_some(),
        "a true write stamps verified_at"
    );

    let resp = client
        .get(format!("{base}/v1/federation/peers/{PEER_KEY_ID}/sas"))
        .send()
        .await
        .expect("GET sas after verify");
    let json: serde_json::Value = resp.json().await.expect("sas json after verify");
    assert_eq!(json["data"]["verified"], true);
    assert_eq!(json["data"]["words"], serde_json::json!(expected_words));
}

#[tokio::test]
async fn unauthorized_and_unknown_peer_are_rejected() {
    let engine = node().await;
    register_self(&engine).await;
    bind_owner(&engine).await;
    seed_peer(&engine).await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let observer = mint_session(&engine, "wa-observer", WaRole::Observer).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();
    let body = serde_json::json!({ "trust": "blocked" });

    // No bearer at all → 401.
    let no_auth = client
        .put(format!("{base}/v1/federation/peers/{PEER_KEY_ID}/trust"))
        .json(&body)
        .send()
        .await
        .expect("PUT trust (no auth)");
    assert_eq!(no_auth.status(), 401, "missing session ⇒ 401");

    // Insufficient role (Observer, not SYSTEM_ADMIN) → 403.
    let forbidden = client
        .put(format!("{base}/v1/federation/peers/{PEER_KEY_ID}/trust"))
        .bearer_auth(&observer)
        .json(&body)
        .send()
        .await
        .expect("PUT trust (observer)");
    assert_eq!(forbidden.status(), 403, "non-owner role ⇒ 403");

    // Neither rejected call wrote a sideband: the read still serves the
    // directory default.
    let resp = client
        .get(format!("{base}/v1/federation/peers/{PEER_KEY_ID}"))
        .send()
        .await
        .expect("GET peer detail");
    let json: serde_json::Value = resp.json().await.expect("detail json");
    assert_eq!(
        json["peer"]["trust"], "trusted",
        "a rejected PUT must write NO sideband"
    );

    // Unknown peer → 404 PEER_NOT_FOUND (the agent's envelope shape).
    let missing = client
        .put(format!("{base}/v1/federation/peers/no-such-peer/trust"))
        .bearer_auth(&owner)
        .json(&body)
        .send()
        .await
        .expect("PUT trust (unknown peer)");
    assert_eq!(missing.status(), 404, "unknown peer ⇒ 404");
    let json: serde_json::Value = missing.json().await.expect("404 json");
    assert_eq!(json["error"], "PEER_NOT_FOUND");
    assert_eq!(json["key_id"], "no-such-peer");

    // A garbage trust token → 400 (vocabulary locked to EdgePeerTrust).
    let bad_vocab = client
        .put(format!("{base}/v1/federation/peers/{PEER_KEY_ID}/trust"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "trust": "bestie" }))
        .send()
        .await
        .expect("PUT trust (bad vocab)");
    assert_eq!(bad_vocab.status(), 400, "unknown trust token ⇒ 400");
}
