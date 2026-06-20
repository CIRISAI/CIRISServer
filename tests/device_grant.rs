//! Node-side device-authorization grant (RFC 8628 shape) — "authorize an agent to
//! act on my behalf" (CIRISServer device-grant), now **CEG-native**.
//!
//! Drives the real `device_grant::router` over a bound TCP listener (full HTTP +
//! auth stack) and proves:
//!
//!   1. code → owner-approve → token. Approval emits a DURABLE, signed
//!      `delegates_to(owner → actor, owner:act-on-behalf)` attestation (the owner
//!      re-opens its local fed-ID signer and signs); the minted `dgrant:` bearer
//!      resolves to a caller carrying the OWNER's authority + `actor` attribution,
//!      and is graph-backed: `resolve_bearer` re-checks `reachable_under_scope`.
//!   2. revoke emits a signed `withdraws` → the edge is no longer reachable → the
//!      previously-minted bearer is immediately DEAD and the owner's grant list is
//!      empty (revocation is real, not just TTL).
//!   3. the actor (`client_id`) MUST be a registered federation identity →
//!      `invalid_client` otherwise (it is the edge's `attested_key_id`).
//!   4. RFC-8628 mechanics unchanged: poll before approve → 428; deny → 403;
//!      expired device_code → 410; wrong client_id → 400; unknown → 400.
//!   5. approve WITHOUT an owner session (none / non-owner) → 401/403.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::types::{algorithm, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};

use ciris_server::auth::device_grant;
use ciris_server::auth::roles::UserRole;
use ciris_server::auth::session::resolve_bearer;
use ciris_server::auth::store;
use ciris_server::identity::UserIdentityBackend;

const NODE_KEY_ID: &str = "ciris-server";
const SCOPE: &str = "owner:act-on-behalf";

/// One shared `CIRIS_HOME` for the whole test binary (the ML-DSA seal + outbox
/// live under it). Set ONCE so parallel tests don't stomp the env; tests use
/// UNIQUE `owner_key_id`s so their per-key seal files never collide.
fn ciris_home() -> PathBuf {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("ciris-devgrant-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create CIRIS_HOME");
        std::env::set_var("CIRIS_HOME", &dir);
        dir
    })
    .clone()
}

/// Stand up THIS node: an in-memory hybrid substrate.
async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    let engine = Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("Engine::with_signer (sqlite::memory:) must succeed");
    Arc::new(engine)
}

/// Insert a `federation_keys` row (prod drains the genesis from the CEG outbox;
/// the test admits the key directly). No PoP is verified on `put_public_key`.
async fn register_key(
    engine: &Engine,
    key_id: &str,
    identity_type: &str,
    ed_b64: &str,
    mldsa_b64: Option<String>,
) {
    let now = chrono::Utc::now();
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: ed_b64.to_string(),
        pubkey_ml_dsa_65_base64: mldsa_b64,
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type.to_string(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": key_id }),
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register federation key");
}

/// Mint the LOCAL responsible-owner's fed-ID on disk (software custody) under the
/// keystore alias `owner_alias` so the handler's `resolve_user_signer(owner_alias,
/// seed_dir)` re-opens the SAME signer at approve/revoke. Admits its USER key into
/// `federation_keys` under the #247 DERIVED key_id (what the signer reports as
/// `key_id()` and emits under), with the REAL minted pubkeys so the federation-tier
/// verify passes. Returns the derived federation key_id (the edge issuer / graph id).
async fn setup_local_owner(engine: &Engine, owner_alias: &str, seed_dir: &Path) -> String {
    let minted = ciris_server::identity::mint_user_identity(
        UserIdentityBackend::Software,
        owner_alias,
        Some("Test Owner"),
        seed_dir.to_path_buf(),
    )
    .await
    .expect("mint owner identity");
    // #247: the recorded key_id is the DERIVED form (alias is the seal storage key).
    assert!(
        minted.key_id.starts_with(&format!("{owner_alias}-")),
        "expected a derived `{owner_alias}-<fp>` key_id, got {}",
        minted.key_id
    );
    register_key(
        engine,
        &minted.key_id,
        "user",
        &minted.pubkey_ed25519_base64,
        Some(minted.pubkey_ml_dsa_65_base64),
    )
    .await;
    minted.key_id
}

/// Register the actor (agent) fed-ID. It is the `attested_key_id` of the edge —
/// its pubkeys are never cryptographically checked in this flow (only the owner
/// signs), but the row must EXIST (FK) and be non-node `identity_type` so the
/// CC 4.4.3.4.3 node-agency gate admits the non-`infra:*` act-on-behalf scope.
async fn register_actor(engine: &Engine, actor_key_id: &str) {
    let ed = {
        let mut seed = [0x5Au8; 32];
        for (i, b) in actor_key_id.bytes().enumerate().take(32) {
            seed[i] ^= b;
        }
        BASE64.encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
    };
    let mldsa = {
        let mut seed = [0x6Bu8; 32];
        for (i, b) in actor_key_id.bytes().enumerate().take(32) {
            seed[i] ^= b;
        }
        let p = MlDsa65SoftwareSigner::from_seed_bytes(&seed, format!("{actor_key_id}-pqc"))
            .expect("actor ML-DSA-65 seed");
        BASE64.encode(p.public_key().await.expect("actor ML-DSA-65 pubkey"))
    };
    register_key(engine, actor_key_id, "agent", &ed, Some(mldsa)).await;
}

/// Mint an active `wa_cert` of the given role + return a bound session bearer
/// (`sess:<wa_id>:<rand>` — the shape `resolve_bearer` parses).
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

/// Serve the device-grant router on an ephemeral port.
async fn serve(
    engine: Arc<Engine>,
    owner_key_id: String,
    seed_dir: PathBuf,
    ttl: u64,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = device_grant::router_with_ttl(engine, owner_key_id, seed_dir, ttl);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// POST /v1/auth/device/code → (device_code, user_code).
async fn request_code(
    client: &reqwest::Client,
    base: &str,
    actor_key_id: &str,
) -> (String, String) {
    let resp = client
        .post(format!("{base}/v1/auth/device/code"))
        .json(&serde_json::json!({ "client_id": actor_key_id }))
        .send()
        .await
        .expect("POST device/code");
    assert_eq!(resp.status(), 200, "device/code must succeed");
    let json: serde_json::Value = resp.json().await.expect("device/code json");
    assert!(json["verification_uri"].as_str().is_some());
    (
        json["device_code"]
            .as_str()
            .expect("device_code")
            .to_string(),
        json["user_code"].as_str().expect("user_code").to_string(),
    )
}

#[tokio::test]
async fn ceg_native_approve_emits_delegation_token_works_and_revoke_kills_it() {
    let home = ciris_home();
    let engine = node().await;
    let owner_key_id = "dg-owner-happy";
    let actor_key_id = "dg-actor-happy";
    // owner_key_id is the keystore ALIAS (the router's resolve key); the owner's
    // wire/graph id is the #247 DERIVED form mint records + the signer emits under.
    let owner_fed_id = setup_local_owner(&engine, owner_key_id, &home).await;
    register_actor(&engine, actor_key_id).await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(
        Arc::clone(&engine),
        owner_key_id.to_string(),
        home.clone(),
        600,
    )
    .await;
    let client = reqwest::Client::new();

    let (device_code, user_code) = request_code(&client, &base, actor_key_id).await;

    // Poll BEFORE approve → 428.
    let pending = client
        .post(format!("{base}/v1/auth/device/token"))
        .json(&serde_json::json!({ "device_code": device_code, "client_id": actor_key_id }))
        .send()
        .await
        .expect("poll pending");
    assert_eq!(pending.status(), 428, "pending poll ⇒ 428");

    // Owner approves → emits a signed delegates_to(owner → actor).
    let approve = client
        .post(format!("{base}/v1/auth/device/approve"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "user_code": user_code }))
        .send()
        .await
        .expect("owner approve");
    assert_eq!(approve.status(), 200, "owner approval must succeed");
    let aj: serde_json::Value = approve.json().await.unwrap();
    assert_eq!(aj["status"], "approved");
    assert_eq!(aj["approved_by"], "wa-owner");
    assert!(
        aj["delegation_attestation_id"].as_str().is_some(),
        "approval emits a durable delegates_to attestation"
    );

    // The authority is a LIVE edge in the graph.
    assert!(
        engine
            .reachable_under_scope(&owner_fed_id, actor_key_id, SCOPE, 4)
            .await
            .unwrap(),
        "owner → actor delegation is reachable under the act-on-behalf scope"
    );

    // Poll after approve → 200 + a graph-backed Bearer dgrant: token.
    let token_resp = client
        .post(format!("{base}/v1/auth/device/token"))
        .json(&serde_json::json!({ "device_code": device_code, "client_id": actor_key_id }))
        .send()
        .await
        .expect("poll approved");
    assert_eq!(token_resp.status(), 200, "approved poll ⇒ 200 + token");
    let tj: serde_json::Value = token_resp.json().await.unwrap();
    let access_token = tj["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();
    assert!(access_token.starts_with("dgrant:"));

    // The bearer resolves (graph live) with owner authority + actor attribution.
    let caller = resolve_bearer(&engine, &access_token)
        .await
        .expect("resolve_bearer")
        .expect("delegated token resolves while the edge is live");
    assert_eq!(caller.wa_id, "wa-owner", "principal = owner");
    assert_eq!(caller.role, UserRole::SystemAdmin, "owner's authority");
    assert_eq!(
        caller.actor.as_deref(),
        Some(actor_key_id),
        "attribution = the actor"
    );

    // The owner's Delegations list IS the graph — it shows the live edge.
    let grants: serde_json::Value = client
        .get(format!("{base}/v1/auth/device/grants"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("list grants")
        .json()
        .await
        .unwrap();
    assert!(
        grants["grants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["client_id"] == actor_key_id),
        "live delegation listed; got {grants}"
    );

    // Revoke → signed withdraws → edge no longer reachable.
    let rev: serde_json::Value = client
        .post(format!("{base}/v1/auth/device/revoke"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "client_id": actor_key_id }))
        .send()
        .await
        .expect("revoke")
        .json()
        .await
        .unwrap();
    assert!(rev["revoked"].as_u64().unwrap() >= 1, "≥1 edge withdrawn");
    assert!(
        !engine
            .reachable_under_scope(&owner_fed_id, actor_key_id, SCOPE, 4)
            .await
            .unwrap(),
        "withdrawn edge is no longer reachable"
    );

    // The previously-minted bearer is now DEAD (graph re-check fails), and the
    // list is empty — revocation is real, not just TTL.
    assert!(
        resolve_bearer(&engine, &access_token)
            .await
            .expect("resolve_bearer")
            .is_none(),
        "revoked delegation immediately kills the bearer"
    );
    let grants_after: serde_json::Value = client
        .get(format!("{base}/v1/auth/device/grants"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("list grants after revoke")
        .json()
        .await
        .unwrap();
    assert!(
        grants_after["grants"].as_array().unwrap().is_empty(),
        "no live delegations after revoke; got {grants_after}"
    );
}

#[tokio::test]
async fn unregistered_actor_is_invalid_client() {
    let home = ciris_home();
    let engine = node().await;
    let (base, _h) = serve(
        Arc::clone(&engine),
        "dg-owner-noactor".to_string(),
        home.clone(),
        600,
    )
    .await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/v1/auth/device/code"))
        .json(&serde_json::json!({ "client_id": "agent-with-no-fed-id" }))
        .send()
        .await
        .expect("POST device/code");
    assert_eq!(resp.status(), 400, "an unregistered actor ⇒ invalid_client");
    assert_eq!(
        resp.json::<serde_json::Value>().await.unwrap()["error"]
            .as_str()
            .unwrap()
            .split(':')
            .next()
            .unwrap(),
        "invalid_client"
    );
}

#[tokio::test]
async fn deny_then_poll_is_access_denied() {
    let home = ciris_home();
    let engine = node().await;
    let actor = "dg-actor-deny";
    register_actor(&engine, actor).await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(
        Arc::clone(&engine),
        "dg-owner-deny".to_string(),
        home.clone(),
        600,
    )
    .await;
    let client = reqwest::Client::new();

    let (device_code, user_code) = request_code(&client, &base, actor).await;

    let deny = client
        .post(format!("{base}/v1/auth/device/deny"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "user_code": user_code }))
        .send()
        .await
        .expect("owner deny");
    assert_eq!(deny.status(), 200);

    let poll = client
        .post(format!("{base}/v1/auth/device/token"))
        .json(&serde_json::json!({ "device_code": device_code, "client_id": actor }))
        .send()
        .await
        .expect("poll denied");
    assert_eq!(poll.status(), 403, "denied poll ⇒ 403");
}

#[tokio::test]
async fn wrong_client_id_on_poll_is_rejected() {
    let home = ciris_home();
    let engine = node().await;
    let actor = "dg-actor-wrongclient";
    register_actor(&engine, actor).await;
    let (base, _h) = serve(
        Arc::clone(&engine),
        "dg-owner-wc".to_string(),
        home.clone(),
        600,
    )
    .await;
    let client = reqwest::Client::new();

    let (device_code, _user_code) = request_code(&client, &base, actor).await;

    let poll = client
        .post(format!("{base}/v1/auth/device/token"))
        .json(&serde_json::json!({ "device_code": device_code, "client_id": "someone-else" }))
        .send()
        .await
        .expect("poll wrong client");
    assert_eq!(poll.status(), 400, "client_id mismatch ⇒ 400");
    assert_eq!(
        poll.json::<serde_json::Value>().await.unwrap()["error"],
        "invalid_client"
    );
}

#[tokio::test]
async fn unknown_device_code_is_invalid_grant() {
    let home = ciris_home();
    let engine = node().await;
    let (base, _h) = serve(
        Arc::clone(&engine),
        "dg-owner-unknown".to_string(),
        home.clone(),
        600,
    )
    .await;
    let client = reqwest::Client::new();

    let poll = client
        .post(format!("{base}/v1/auth/device/token"))
        .json(&serde_json::json!({ "device_code": "nonexistent", "client_id": "x" }))
        .send()
        .await
        .expect("poll unknown");
    assert_eq!(poll.status(), 400);
    assert_eq!(
        poll.json::<serde_json::Value>().await.unwrap()["error"],
        "invalid_grant"
    );
}

/// An expired device_code ⇒ 410 (TTL = 0: the code is born already past its TTL).
#[tokio::test]
async fn expired_device_code_is_410() {
    let home = ciris_home();
    let engine = node().await;
    let actor = "dg-actor-expired";
    register_actor(&engine, actor).await;
    let (base, _h) = serve(
        Arc::clone(&engine),
        "dg-owner-expired".to_string(),
        home.clone(),
        0,
    )
    .await;
    let client = reqwest::Client::new();

    let (device_code, _user_code) = request_code(&client, &base, actor).await;
    let poll = client
        .post(format!("{base}/v1/auth/device/token"))
        .json(&serde_json::json!({ "device_code": device_code, "client_id": actor }))
        .send()
        .await
        .expect("poll expired");
    assert_eq!(poll.status(), 410, "expired device_code ⇒ 410");
    assert_eq!(
        poll.json::<serde_json::Value>().await.unwrap()["error"],
        "expired_token"
    );
}

#[tokio::test]
async fn approve_without_owner_session_is_rejected() {
    let home = ciris_home();
    let engine = node().await;
    let actor = "dg-actor-noowner";
    register_actor(&engine, actor).await;
    let observer = mint_session(&engine, "wa-observer", WaRole::Observer).await;
    let (base, _h) = serve(
        Arc::clone(&engine),
        "dg-owner-gate".to_string(),
        home.clone(),
        600,
    )
    .await;
    let client = reqwest::Client::new();

    let (_device_code, user_code) = request_code(&client, &base, actor).await;

    // No bearer at all → 401.
    let no_auth = client
        .post(format!("{base}/v1/auth/device/approve"))
        .json(&serde_json::json!({ "user_code": user_code }))
        .send()
        .await
        .expect("approve no auth");
    assert_eq!(no_auth.status(), 401, "missing session ⇒ 401");

    // Non-owner role (Observer) → 403.
    let forbidden = client
        .post(format!("{base}/v1/auth/device/approve"))
        .bearer_auth(&observer)
        .json(&serde_json::json!({ "user_code": user_code }))
        .send()
        .await
        .expect("approve observer");
    assert_eq!(forbidden.status(), 403, "non-owner role ⇒ 403");
}
