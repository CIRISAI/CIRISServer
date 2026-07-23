//! **CC 2.2 conformance levels + CC 2.6.4 versioning policy** (CIRISServer#159).
//!
//! Both sections are of the shape "declare a level/version, then ENFORCE it", so
//! this test drives the real router over a bound TCP listener (full HTTP + auth
//! stack) and proves the *enforcement*, not just the declaration:
//!
//!   1. **Declared + honored** — a node that has declared nothing claims what this
//!      build implements (CCP + CCC + CCS, [`BUILD_PROFILES`]); it is READABLE by a
//!      peer at `GET /v1/federation/conformance`; and peering (which exercises all
//!      three profiles) is ADMITTED.
//!   2. **An op above the declared level is REFUSED** — a node whose owner narrowed
//!      its declaration to `["CCC"]` (a consume-only node) is refused peering with
//!      `403 conformance_level` naming the missing profiles — and authors NO grant
//!      and admits NO peer key (refusal precedes every effect).
//!   3. **Fail-closed** — an INVALID declaration (an unknown profile token) claims
//!      NOTHING; every wire op is refused until it is fixed.
//!   4. **CC 2.6.4 negotiation** — a peer announcing OUR wire version + OUR pinned
//!      `WIRE_VOCABULARY.md` hash is accepted (and the negotiated version is echoed);
//!      a peer announcing a MAJOR-incompatible version, a malformed version, or a
//!      DIFFERENT wire vocabulary is REFUSED `409` — and authors no grant.
//!
//! The peering harness (node / owner-binding / synthetic peer / session) mirrors
//! `tests/federation_admin.rs`; the assertions here are entirely about the two new
//! gates in front of it.

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
use ciris_server::conformance::{
    wire_vocabulary_sha256, BUILD_PROFILES, CEG_WIRE_VERSION, KEY_CONFORMANCE_PROFILES,
};
use ciris_server::federation_admin;
use ciris_server::graph_config::{set_config, ConfigScope, ConfigValue};
use ciris_server::peer::CONSENT_DIMENSION;

const NODE_A_KEY_ID: &str = "ciris-server";
const PEER_KEY_ID: &str = "ciris-status";
const OWNER_USER_KEY_ID: &str = "ciris-owner-user";
const OWNER_ED_SEED: [u8; 32] = [0xF1; 32];
const OWNER_PQC_SEED: [u8; 32] = [0xF2; 32];

// ─── Harness (mirrors tests/federation_admin.rs) ─────────────────────────────

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

async fn node_key_id(engine: &Engine) -> String {
    engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id")
}

async fn register_self(engine: &Engine) {
    let now = chrono::Utc::now();
    let key_id = node_key_id(engine).await;
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
        roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .register_federation_key(SignedKeyRecord { record })
        .await
        .expect("register node steward key via admission gate");
}

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

/// The CC 3.2 owner-binding — the serve-only floor in front of peering. Without it
/// the node 403s every owner-op regardless of conformance, which would mask the
/// gates under test.
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
        roles: Vec::new(),
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
    let node = node_key_id(engine).await;
    ciris_server::auth::ownership::emit_steward_binding(engine, &owner_signer, &node, &scopes)
        .await
        .expect("emit owner-binding delegates_to(user -> node, infra:*)");
}

async fn self_key_record_json(engine: &Engine) -> String {
    let now = chrono::Utc::now();
    let key_id = node_key_id(engine).await;
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
        roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    serde_json::to_string(&SignedKeyRecord { record }).expect("serialize self key record")
}

/// A synthetic peer's self-signed `SignedKeyRecord` (hybrid proof-of-possession).
async fn peer_signed_key_record() -> SignedKeyRecord {
    let ed = SigningKey::from_bytes(&[0xB0; 32]);
    let mldsa = MlDsa65SoftwareSigner::from_seed_bytes(&[0xB1; 32], format!("{PEER_KEY_ID}-pqc"))
        .expect("peer ML-DSA-65 seed");
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": PEER_KEY_ID });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize peer registration");
    let original_content_hash = hex::encode(Sha256::digest(&canonical));
    let ed_sig = ed.sign(&canonical).to_bytes();
    let mut bound = Vec::with_capacity(canonical.len() + ed_sig.len());
    bound.extend_from_slice(&canonical);
    bound.extend_from_slice(&ed_sig);
    let pqc_sig = mldsa.sign(&bound).await.expect("ml-dsa sign peer reg");
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
        original_content_hash,
        scrub_signature_classical: BASE64.encode(ed_sig),
        scrub_signature_pqc: Some(BASE64.encode(&pqc_sig)),
        scrub_key_id: PEER_KEY_ID.to_string(),
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

async fn serve(engine: Arc<Engine>, skr: String) -> (String, tokio::task::JoinHandle<()>) {
    let key_id = node_key_id(&engine).await;
    let app = federation_admin::router(engine, key_id, skr, None);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// An owned, self-registered node + a live owner session + the served router.
async fn owned_node() -> (Arc<Engine>, String, String, tokio::task::JoinHandle<()>) {
    let engine = node().await;
    register_self(&engine).await;
    bind_owner(&engine).await;
    let skr = self_key_record_json(&engine).await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, handle) = serve(Arc::clone(&engine), skr).await;
    (engine, base, owner, handle)
}

/// Write the node's CC 2.2 declaration as the `config:*` CEG object the gate reads.
async fn declare(engine: &Arc<Engine>, tokens: &[&str]) {
    let key_id = node_key_id(engine).await;
    let list = ConfigValue::List(
        tokens
            .iter()
            .map(|t| serde_json::Value::String((*t).to_string()))
            .collect(),
    );
    set_config(
        engine,
        KEY_CONFORMANCE_PROFILES,
        list,
        &key_id,
        ConfigScope::Identity,
    )
    .await
    .expect("write the CC 2.2 conformance declaration");
}

/// Did this node author a `consent:replication:v1` grant? (The observable effect a
/// refusal must PREVENT.)
async fn authored_grant(engine: &Arc<Engine>) -> bool {
    let key_id = node_key_id(engine).await;
    engine
        .federation_directory()
        .list_attestations_by(&key_id)
        .await
        .expect("list attestations by node")
        .iter()
        .any(|a| {
            a.attestation_envelope
                .get("dimension")
                .and_then(|d| d.as_str())
                == Some(CONSENT_DIMENSION)
        })
}

async fn peer_admitted(engine: &Arc<Engine>) -> bool {
    engine
        .federation_directory()
        .lookup_public_key(PEER_KEY_ID)
        .await
        .expect("lookup peer key")
        .is_some()
}

/// A peering body; `wire` is merged in at the top level (the flattened CC 2.6.4
/// announcement).
async fn peering_body(wire: serde_json::Value) -> serde_json::Value {
    let mut body = serde_json::json!({
        "peer_key_id": PEER_KEY_ID,
        "peer_key_record": peer_signed_key_record().await,
        "attestation_prefixes": ["capacity:"],
    });
    if let (Some(obj), Some(w)) = (body.as_object_mut(), wire.as_object()) {
        for (k, v) in w {
            obj.insert(k.clone(), v.clone());
        }
    }
    body
}

// ─── CC 2.2 — the level is DECLARED, EXPOSED and HONORED ─────────────────────

#[tokio::test]
async fn declared_level_is_exposed_and_honored() {
    let (engine, base, owner, _h) = owned_node().await;
    let client = reqwest::Client::new();

    // The peer-facing declaration surface (unauthenticated — a peer must be able to
    // read what we claim BEFORE committing to a federation relationship).
    let decl: serde_json::Value = client
        .get(format!("{base}/v1/federation/conformance"))
        .send()
        .await
        .expect("GET conformance")
        .json()
        .await
        .expect("conformance json");
    assert_eq!(
        decl["profiles"],
        serde_json::json!(["CCP", "CCC", "CCS"]),
        "a node that has declared nothing claims what the BUILD implements (CC 2.2)"
    );
    assert_eq!(decl["declared_by_config"], false);
    assert_eq!(decl["ceg_wire_version"], CEG_WIRE_VERSION);
    assert_eq!(decl["wire_vocabulary_sha256"], wire_vocabulary_sha256());
    assert_eq!(
        decl["build_profiles"].as_array().map(Vec::len),
        Some(BUILD_PROFILES.len())
    );

    // HONORED: peering exercises CCP + CCC + CCS, all of which the node claims.
    let resp = client
        .post(format!("{base}/v1/federation/peering"))
        .bearer_auth(&owner)
        .json(&peering_body(serde_json::json!({})).await)
        .send()
        .await
        .expect("POST peering");
    assert_eq!(resp.status(), 200, "a fully-conforming node may peer");
    let json: serde_json::Value = resp.json().await.expect("peering json");
    // The response carries the negotiated wire + our declaration back (symmetric
    // negotiation: the requester can refuse US).
    assert_eq!(json["negotiated_ceg_wire_version"], CEG_WIRE_VERSION);
    assert_eq!(
        json["conformance"]["profiles"],
        serde_json::json!(["CCP", "CCC", "CCS"])
    );
    assert!(authored_grant(&engine).await, "the grant was authored");
    assert!(peer_admitted(&engine).await, "the peer key was admitted");
}

#[tokio::test]
async fn op_above_the_declared_level_is_refused() {
    let (engine, base, owner, _h) = owned_node().await;
    // The owner narrows the node to a CONSUME-ONLY posture: it verifies + admits
    // (CCC) but does not claim to produce (CCP) or to run the CC 5.3 substrate (CCS).
    declare(&engine, &["CCC"]).await;
    let client = reqwest::Client::new();

    let decl: serde_json::Value = client
        .get(format!("{base}/v1/federation/conformance"))
        .send()
        .await
        .expect("GET conformance")
        .json()
        .await
        .expect("conformance json");
    assert_eq!(decl["profiles"], serde_json::json!(["CCC"]));
    assert_eq!(decl["declared_by_config"], true);

    let resp = client
        .post(format!("{base}/v1/federation/peering"))
        .bearer_auth(&owner)
        .json(&peering_body(serde_json::json!({})).await)
        .send()
        .await
        .expect("POST peering");
    assert_eq!(
        resp.status(),
        403,
        "an op the declared level does not claim MUST be refused (CC 2.2)"
    );
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["error"], "conformance_level");
    assert_eq!(json["verb"], "peer");
    assert_eq!(json["missing"], serde_json::json!(["CCP", "CCS"]));
    assert_eq!(json["declared"], serde_json::json!(["CCC"]));

    // The refusal PRECEDES every effect: no peer admitted, no grant authored.
    assert!(
        !peer_admitted(&engine).await,
        "a refused peering must not admit the peer key"
    );
    assert!(
        !authored_grant(&engine).await,
        "a refused peering must not author a consent grant"
    );
}

#[tokio::test]
async fn an_invalid_declaration_claims_nothing_fail_closed() {
    let (engine, base, owner, _h) = owned_node().await;
    // A profile token this build does not implement (a typo, or a profile from a
    // future CC). We do NOT silently drop it and act on the remainder.
    declare(&engine, &["CCP", "CCX"]).await;
    let client = reqwest::Client::new();

    let decl: serde_json::Value = client
        .get(format!("{base}/v1/federation/conformance"))
        .send()
        .await
        .expect("GET conformance")
        .json()
        .await
        .expect("conformance json");
    assert_eq!(
        decl["profiles"],
        serde_json::json!([]),
        "an unparseable declaration claims NOTHING (fail-closed)"
    );

    let resp = client
        .post(format!("{base}/v1/federation/peering"))
        .bearer_auth(&owner)
        .json(&peering_body(serde_json::json!({})).await)
        .send()
        .await
        .expect("POST peering");
    assert_eq!(
        resp.status(),
        403,
        "claiming nothing ⇒ every wire op refused"
    );
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["error"], "conformance_level");
    assert_eq!(json["missing"], serde_json::json!(["CCP", "CCC", "CCS"]));
    assert!(!authored_grant(&engine).await);
}

// ─── CC 2.6.4 — the wire version is NEGOTIATED, and a break is REFUSED ───────

#[tokio::test]
async fn compatible_peer_wire_version_is_accepted() {
    let (engine, base, owner, _h) = owned_node().await;
    let client = reqwest::Client::new();

    // The peer announces our exact wire version AND our pinned wire vocabulary.
    let body = peering_body(serde_json::json!({
        "ceg_wire_version": CEG_WIRE_VERSION,
        "wire_vocabulary_sha256": wire_vocabulary_sha256(),
    }))
    .await;
    let resp = client
        .post(format!("{base}/v1/federation/peering"))
        .bearer_auth(&owner)
        .json(&body)
        .send()
        .await
        .expect("POST peering");
    assert_eq!(resp.status(), 200, "a compatible wire must be accepted");
    let json: serde_json::Value = resp.json().await.expect("peering json");
    assert_eq!(json["negotiated_ceg_wire_version"], CEG_WIRE_VERSION);
    assert!(authored_grant(&engine).await);
}

#[tokio::test]
async fn incompatible_peer_wire_version_is_refused() {
    let (engine, base, owner, _h) = owned_node().await;
    let client = reqwest::Client::new();

    // A MAJOR bump IS the CC 2.6.4 announcement of a wire-incompatible change.
    let resp = client
        .post(format!("{base}/v1/federation/peering"))
        .bearer_auth(&owner)
        .json(&peering_body(serde_json::json!({ "ceg_wire_version": "2.0.0" })).await)
        .send()
        .await
        .expect("POST peering");
    assert_eq!(
        resp.status(),
        409,
        "an incompatible peer wire version MUST be refused, not silently tolerated"
    );
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["error"], "wire_version_incompatible");
    assert_eq!(json["peer_ceg_wire_version"], "2.0.0");
    assert_eq!(json["local_ceg_wire_version"], CEG_WIRE_VERSION);

    // A version we cannot even parse tells us NOTHING about interoperability ⇒ refuse.
    let resp = client
        .post(format!("{base}/v1/federation/peering"))
        .bearer_auth(&owner)
        .json(&peering_body(serde_json::json!({ "ceg_wire_version": "not-a-semver" })).await)
        .send()
        .await
        .expect("POST peering");
    assert_eq!(resp.status(), 409);
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["error"], "wire_version_malformed");

    // A DIFFERENT ratified wire vocabulary ⇒ the peers recognize different
    // message-type sets ("a hash mismatch at cohabitation is a substrate-tier build
    // failure, not a warning" — CC 2.6.4).
    let resp = client
        .post(format!("{base}/v1/federation/peering"))
        .bearer_auth(&owner)
        .json(
            &peering_body(serde_json::json!({
                "ceg_wire_version": CEG_WIRE_VERSION,
                "wire_vocabulary_sha256": "11".repeat(32),
            }))
            .await,
        )
        .send()
        .await
        .expect("POST peering");
    assert_eq!(resp.status(), 409);
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["error"], "wire_vocabulary_mismatch");

    // NONE of the three refusals may leave an effect behind.
    assert!(
        !peer_admitted(&engine).await,
        "a refused wire must not admit the peer key"
    );
    assert!(
        !authored_grant(&engine).await,
        "a refused wire must not author a consent grant"
    );
}
