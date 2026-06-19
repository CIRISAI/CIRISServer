//! Owner-directed federation operations — the on-demand `consent:replication`
//! peering keystone (`GET /v1/federation/self-key-record` +
//! `POST /v1/federation/peering`).
//!
//! These are owner-AUTHORITY operations on the node, not "endpoints for a
//! client": the node authors its OWN directed `consent:replication:v1` grant
//! (`attesting_key_id` = this node), and the owner gate authorizes the cross-node
//! data flow. This test drives the real router over a bound TCP listener (full
//! HTTP + auth stack) and proves:
//!
//!   1. `POST /v1/federation/peering` with a synthetic peer's *self-signed*
//!      `SignedKeyRecord` → the peer key is ADMITTED into this node's federation
//!      directory AND this node's directed `consent:replication:v1` grant exists,
//!      carrying the caller-supplied prefixes SORTED + DEDUPED.
//!   2. An unauthorized caller (no session / insufficient role) is REJECTED
//!      (401 / 403) and authors NO grant.
//!   3. `GET /v1/federation/self-key-record` returns a record that round-trips
//!      through `register_federation_key` on a FRESH engine (it really is an
//!      admissible self-signed key record).

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::types::{
    algorithm, attestation_type, identity_type, KeyRecord, SignedKeyRecord,
};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};

use ciris_server::auth::store;
use ciris_server::federation_admin;
use ciris_server::peer::CONSENT_DIMENSION;

const NODE_A_KEY_ID: &str = "ciris-server";
const PEER_KEY_ID: &str = "ciris-status";

/// Stand up THIS node: an in-memory substrate keyed by a HYBRID node-identity
/// signer so `sign_hybrid` (the self-record + consent emit) works. Mirrors
/// `tests/peer_replication.rs::node_a`.
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

/// Register this node's own steward key via the canonical admission gate — the
/// `put_attestation` attesting-key FK precondition for the consent emit.
async fn register_self(engine: &Engine) {
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": NODE_A_KEY_ID });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize self envelope");
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .expect("self hybrid sign");
    let record = KeyRecord {
        key_id: NODE_A_KEY_ID.to_string(),
        pubkey_ed25519_base64: BASE64.encode(&sig.classical.public_key),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(&sig.pqc.public_key)),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::STEWARD.into(),
        identity_ref: NODE_A_KEY_ID.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: NODE_A_KEY_ID.to_string(),
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

/// The responsible-party (owner) user key_id the owner-binding tests use.
const OWNER_USER_KEY_ID: &str = "ciris-owner-user";

/// Establish the CC 3.2 owner-binding for THIS node: register a `user`-role
/// responsible party in the directory, then emit
/// `delegates_to(user → node, infra:*)`. After this, `is_owner_bound(node)` is
/// `Some(owner)` and the serve-only-floor gate on peering passes. The node key
/// must already be registered ([`register_self`]).
async fn bind_owner(engine: &Engine) {
    // Register the responsible party as a `user`-role key with the user signer's
    // REAL hybrid pubkeys — persist v9.0.0's federation-tier ingest gate verifies
    // the owner-binding against `attesting_key_id` (== the user), so the user must
    // be registered with the keys it actually signs the binding with.
    use ciris_keyring::PqcSigner as _;
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
    ciris_server::auth::ownership::emit_owner_binding(
        engine,
        &owner_signer,
        NODE_A_KEY_ID,
        &scopes,
    )
    .await
    .expect("emit owner-binding delegates_to(user -> node, infra:*)");
}

/// The owner user's deterministic Ed25519 / ML-DSA-65 seeds (distinct from the
/// node steward's `[0xA1;32]`/`[0xA2;32]`).
const OWNER_ED_SEED: [u8; 32] = [0xF1; 32];
const OWNER_PQC_SEED: [u8; 32] = [0xF2; 32];

/// The owner user's `LocalSigner` (hybrid) — matches the pubkeys [`bind_owner`]
/// registers; signs the owner-binding (attester == signer for the v9.0.0 gate).
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

/// Build THIS node's own self-signed `SignedKeyRecord` JSON exactly as
/// `compose::self_key_record_json` does (so the GET served value matches).
async fn self_key_record_json(engine: &Engine) -> String {
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": NODE_A_KEY_ID });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize self envelope");
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .expect("self hybrid sign");
    let record = KeyRecord {
        key_id: NODE_A_KEY_ID.to_string(),
        pubkey_ed25519_base64: BASE64.encode(&sig.classical.public_key),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(&sig.pqc.public_key)),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::STEWARD.into(),
        identity_ref: NODE_A_KEY_ID.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: NODE_A_KEY_ID.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    };
    serde_json::to_string(&SignedKeyRecord { record }).expect("serialize self key record")
}

/// A synthetic PEER's self-signed `SignedKeyRecord` (proof-of-possession) — the
/// JSON the owner POSTs. The peer signs the registration envelope with its OWN
/// hybrid keys (`scrub_key_id == key_id`), over `ceg_produce_canonicalize`, PQC
/// bound over `canonical || ed_sig` (what `verify_hybrid` checks). Mirrors
/// `tests/peer_replication.rs::NodeB`.
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
    };
    SignedKeyRecord { record }
}

/// Mint an active `wa_cert` of the given role + return a bound session bearer
/// token (`sess:<wa_id>:<rand>` — the exact shape `resolve_bearer` parses).
async fn mint_session(engine: &Engine, wa_id: &str, role: WaRole) -> String {
    let now = chrono::Utc::now();
    let cert = WaCert {
        wa_id: wa_id.to_string(),
        name: wa_id.to_string(),
        role,
        // Session rows require a non-empty pubkey; a placeholder is fine — the
        // session bridge only checks `wa_id` + `active`.
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

/// Serve the federation-admin router on an ephemeral port; return its base URL +
/// the JoinHandle (dropped at test end).
async fn serve(
    engine: Arc<Engine>,
    self_key_record_json: String,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = federation_admin::router(
        engine,
        NODE_A_KEY_ID.to_string(),
        self_key_record_json,
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

#[tokio::test]
async fn owner_peering_admits_peer_and_authors_directed_consent() {
    let engine = node().await;
    register_self(&engine).await;
    // Serve-only floor (CC 3.2 / CC 1.13.5): peering requires a responsible party
    // bound to the node — establish the owner-binding first.
    bind_owner(&engine).await;
    let skr = self_key_record_json(&engine).await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine), skr).await;
    let client = reqwest::Client::new();

    let peer_record = peer_signed_key_record().await;
    // Caller-supplied prefixes deliberately UNSORTED + with a duplicate + an empty
    // entry, to prove the handler normalizes (sorts / dedupes / drops empty).
    let body = serde_json::json!({
        "peer_key_id": PEER_KEY_ID,
        "peer_key_record": peer_record,
        "attestation_prefixes": ["health:", "capacity:", "capacity:", "  "],
    });

    let resp = client
        .post(format!("{base}/v1/federation/peering"))
        .bearer_auth(&owner)
        .json(&body)
        .send()
        .await
        .expect("POST peering");
    assert_eq!(resp.status(), 200, "owner peering must succeed");
    let json: serde_json::Value = resp.json().await.expect("peering response json");
    assert_eq!(json["peer_key_id"], PEER_KEY_ID);
    assert_eq!(json["freshly_emitted"], true);
    assert!(
        json["grant_attestation_id"].as_str().is_some(),
        "response carries the grant attestation_id"
    );
    assert!(
        json["grant_content_hash"].as_str().is_some(),
        "response carries the grant content_hash"
    );
    assert_eq!(
        json["attestation_prefixes"],
        serde_json::json!(["capacity:", "health:"]),
        "prefixes echoed sorted + deduped + empty-dropped"
    );

    // ── The peer key is ADMITTED into this node's federation directory ────────
    let peer_key = engine
        .federation_directory()
        .lookup_public_key(PEER_KEY_ID)
        .await
        .expect("lookup peer key")
        .expect("peer key present after peering");
    assert_eq!(peer_key.identity_type, identity_type::WITNESS);

    // ── This node authored a directed consent:replication:v1 grant at the peer ─
    let by_node = engine
        .federation_directory()
        .list_attestations_by(NODE_A_KEY_ID)
        .await
        .expect("list attestations by node");
    let grant = by_node
        .iter()
        .find(|a| {
            a.attestation_envelope
                .get("dimension")
                .and_then(|d| d.as_str())
                == Some(CONSENT_DIMENSION)
        })
        .expect("node must have a consent:replication:v1 grant");
    assert_eq!(grant.attestation_type, attestation_type::SCORES);
    assert_eq!(grant.attesting_key_id, NODE_A_KEY_ID);
    assert_eq!(grant.subject_key_ids, vec![PEER_KEY_ID.to_string()]);
    let prefixes: Vec<String> = grant.attestation_envelope["payload"]["attestation_prefixes"]
        .as_array()
        .expect("prefixes array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        prefixes,
        vec!["capacity:".to_string(), "health:".to_string()],
        "the grant carries the caller-supplied prefixes, sorted + deduped"
    );

    // ── Idempotent re-POST: no fresh grant, same attestation_id ───────────────
    let resp2 = client
        .post(format!("{base}/v1/federation/peering"))
        .bearer_auth(&owner)
        .json(&body)
        .send()
        .await
        .expect("second POST peering");
    assert_eq!(resp2.status(), 200);
    let json2: serde_json::Value = resp2.json().await.expect("second peering json");
    assert_eq!(
        json2["freshly_emitted"], false,
        "re-POST is an idempotent no-op"
    );
    assert_eq!(
        json2["grant_attestation_id"], json["grant_attestation_id"],
        "idempotent no-op echoes the existing grant id"
    );
}

#[tokio::test]
async fn unauthorized_caller_is_rejected_and_authors_no_grant() {
    let engine = node().await;
    register_self(&engine).await;
    // Owner-bind the node so this test exercises the SESSION/ROLE gate (401/403),
    // not the serve-only-floor gate (which would 403 an unbound node regardless).
    bind_owner(&engine).await;
    let skr = self_key_record_json(&engine).await;
    // A non-owner (Observer) session + the no-session case.
    let observer = mint_session(&engine, "wa-observer", WaRole::Observer).await;
    let (base, _h) = serve(Arc::clone(&engine), skr).await;
    let client = reqwest::Client::new();

    let peer_record = peer_signed_key_record().await;
    let body = serde_json::json!({
        "peer_key_id": PEER_KEY_ID,
        "peer_key_record": peer_record,
        "attestation_prefixes": ["capacity:"],
    });

    // No bearer at all → 401.
    let no_auth = client
        .post(format!("{base}/v1/federation/peering"))
        .json(&body)
        .send()
        .await
        .expect("POST peering (no auth)");
    assert_eq!(no_auth.status(), 401, "missing session ⇒ 401");

    // Insufficient role (Observer, not SYSTEM_ADMIN) → 403.
    let forbidden = client
        .post(format!("{base}/v1/federation/peering"))
        .bearer_auth(&observer)
        .json(&body)
        .send()
        .await
        .expect("POST peering (observer)");
    assert_eq!(forbidden.status(), 403, "non-owner role ⇒ 403");

    // Neither rejected call may have admitted the peer or authored a grant.
    assert!(
        engine
            .federation_directory()
            .lookup_public_key(PEER_KEY_ID)
            .await
            .expect("lookup peer key")
            .is_none(),
        "a rejected peering must admit NO peer key"
    );
    let grants = engine
        .federation_directory()
        .list_attestations_by(NODE_A_KEY_ID)
        .await
        .expect("list attestations by node")
        .into_iter()
        .filter(|a| {
            a.attestation_envelope
                .get("dimension")
                .and_then(|d| d.as_str())
                == Some(CONSENT_DIMENSION)
        })
        .count();
    assert_eq!(grants, 0, "a rejected peering must author NO consent grant");
}

#[tokio::test]
async fn self_key_record_round_trips_through_register_on_a_fresh_engine() {
    let engine = node().await;
    register_self(&engine).await;
    let skr = self_key_record_json(&engine).await;
    let (base, _h) = serve(Arc::clone(&engine), skr).await;
    let client = reqwest::Client::new();

    // GET is unauthenticated by design (a federation key record is public).
    let resp = client
        .get(format!("{base}/v1/federation/self-key-record"))
        .send()
        .await
        .expect("GET self-key-record");
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.expect("self-key-record body");
    let record: SignedKeyRecord =
        serde_json::from_str(&text).expect("served body is a SignedKeyRecord");
    assert_eq!(record.record.key_id, NODE_A_KEY_ID);

    // It really is an admissible self-signed key record: a FRESH peer engine
    // registers it through the fail-secure admission gate without error.
    let peer_engine = {
        let signing_key = SigningKey::from_bytes(&[0xC1; 32]);
        let pqc = Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&[0xC2; 32], "fresh-pqc".to_string())
                .expect("fresh ML-DSA-65 seed"),
        );
        let signer = Arc::new(LocalSigner::from_parts(
            signing_key,
            "fresh-peer".to_string(),
            Some(pqc),
            Some("fresh-pqc".to_string()),
        ));
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("fresh Engine")
    };
    peer_engine
        .register_federation_key(record)
        .await
        .expect("served self-key-record must register on a fresh engine (admissible)");
    assert!(
        peer_engine
            .federation_directory()
            .lookup_public_key(NODE_A_KEY_ID)
            .await
            .expect("lookup")
            .is_some(),
        "the round-tripped record is admitted on the fresh engine"
    );
}

/// Serve-only floor (CC 3.2 / CC 1.13.5): an UNOWNED node (no responsible-party
/// owner-binding) REFUSES federation peering — even from a SYSTEM_ADMIN session.
/// The node has no accountable party to root the cross-node authority in, so it
/// may only serve cleartext from the canonical root.
#[tokio::test]
async fn unowned_node_refuses_peering_even_for_system_admin() {
    let engine = node().await;
    register_self(&engine).await;
    // Deliberately DO NOT bind_owner — the node is owner-unbound.
    assert!(
        ciris_server::auth::ownership::is_owner_bound(&engine, NODE_A_KEY_ID)
            .await
            .is_none(),
        "precondition: node is owner-unbound"
    );
    let skr = self_key_record_json(&engine).await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine), skr).await;
    let client = reqwest::Client::new();

    let peer_record = peer_signed_key_record().await;
    let body = serde_json::json!({
        "peer_key_id": PEER_KEY_ID,
        "peer_key_record": peer_record,
        "attestation_prefixes": ["capacity:"],
    });

    let resp = client
        .post(format!("{base}/v1/federation/peering"))
        .bearer_auth(&owner)
        .json(&body)
        .send()
        .await
        .expect("POST peering (unowned)");
    assert_eq!(
        resp.status(),
        403,
        "an unowned node must refuse peering (serve-only floor) even for SYSTEM_ADMIN"
    );

    // No peer admitted, no grant authored.
    assert!(
        engine
            .federation_directory()
            .lookup_public_key(PEER_KEY_ID)
            .await
            .expect("lookup peer")
            .is_none(),
        "a floor-refused peering must admit NO peer key"
    );

    // Now bind an owner and re-POST: it succeeds (the floor lifts).
    bind_owner(&engine).await;
    assert!(
        ciris_server::auth::ownership::is_owner_bound(&engine, NODE_A_KEY_ID)
            .await
            .is_some(),
        "node is owner-bound after bind_owner"
    );
    let resp2 = client
        .post(format!("{base}/v1/federation/peering"))
        .bearer_auth(&owner)
        .json(&body)
        .send()
        .await
        .expect("POST peering (owned)");
    assert_eq!(
        resp2.status(),
        200,
        "once a responsible party is bound, peering succeeds"
    );
}
