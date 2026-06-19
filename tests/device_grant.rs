//! Node-side device-authorization grant (RFC 8628 shape) — "authorize an agent to
//! act on my behalf" (CIRISServer device-grant).
//!
//! Drives the real `device_grant::router` over a bound TCP listener (full HTTP +
//! auth stack) and proves:
//!
//!   1. code → owner-approve (with an OWNER session) → token yields a Bearer
//!      DELEGATED token that `resolve_bearer` resolves to a caller carrying the
//!      OWNER's wa_id + role (delegated AUTHORITY) AND `actor = Some(client_id)`
//!      (ATTRIBUTION).
//!   2. poll before approve → 428; after deny → 403; expired device_code → 410;
//!      wrong client_id → 400.
//!   3. approve WITHOUT an owner session (none / non-owner bearer) → rejected
//!      (401/403) — the hardware-owner-gate holds.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};

use ciris_server::auth::device_grant;
use ciris_server::auth::roles::UserRole;
use ciris_server::auth::session::resolve_bearer;
use ciris_server::auth::store;

const NODE_KEY_ID: &str = "ciris-server";
const CLIENT_ID: &str = "agent-acme-cli";

/// Stand up THIS node: an in-memory hybrid substrate (mirrors
/// `tests/federation_admin.rs::node`).
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

/// Mint an active `wa_cert` of the given role + return a bound session bearer
/// (`sess:<wa_id>:<rand>` — the shape `resolve_bearer` parses). Copied from
/// `tests/federation_admin.rs::mint_session`.
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
async fn serve(engine: Arc<Engine>) -> (String, tokio::task::JoinHandle<()>) {
    let app = device_grant::router(engine);
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
async fn request_code(client: &reqwest::Client, base: &str) -> (String, String) {
    let resp = client
        .post(format!("{base}/v1/auth/device/code"))
        .json(&serde_json::json!({ "client_id": CLIENT_ID }))
        .send()
        .await
        .expect("POST device/code");
    assert_eq!(resp.status(), 200, "device/code must succeed");
    let json: serde_json::Value = resp.json().await.expect("device/code json");
    assert_eq!(json["expires_in"], 600);
    assert_eq!(json["interval"], 5);
    assert!(json["verification_uri"].as_str().is_some());
    assert!(json["verification_uri_complete"].as_str().is_some());
    (
        json["device_code"]
            .as_str()
            .expect("device_code")
            .to_string(),
        json["user_code"].as_str().expect("user_code").to_string(),
    )
}

#[tokio::test]
async fn code_approve_token_yields_delegated_token_with_owner_authority_and_actor() {
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let (device_code, user_code) = request_code(&client, &base).await;

    // Poll BEFORE approve → 428 authorization_pending.
    let pending = client
        .post(format!("{base}/v1/auth/device/token"))
        .json(&serde_json::json!({ "device_code": device_code, "client_id": CLIENT_ID }))
        .send()
        .await
        .expect("poll pending");
    assert_eq!(pending.status(), 428, "pending poll ⇒ 428");
    assert_eq!(
        pending.json::<serde_json::Value>().await.unwrap()["error"],
        "authorization_pending"
    );

    // Owner approves (hardware-rooted owner session).
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

    // Poll after approve → 200 + Bearer delegated token.
    let token_resp = client
        .post(format!("{base}/v1/auth/device/token"))
        .json(&serde_json::json!({ "device_code": device_code, "client_id": CLIENT_ID }))
        .send()
        .await
        .expect("poll approved");
    assert_eq!(token_resp.status(), 200, "approved poll ⇒ 200 + token");
    let tj: serde_json::Value = token_resp.json().await.unwrap();
    assert_eq!(tj["token_type"], "Bearer");
    let access_token = tj["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();
    assert!(
        access_token.starts_with("dgrant:"),
        "delegated token is a dgrant: opaque token"
    );

    // ── ATTRIBUTION: the delegated token resolves to a caller wielding the
    //    OWNER's authority but ATTRIBUTED to the actor (client_id). ────────────
    let caller = resolve_bearer(&engine, &access_token)
        .await
        .expect("resolve_bearer")
        .expect("delegated token resolves to a caller");
    assert_eq!(caller.wa_id, "wa-owner", "principal = owner's wa_id");
    assert_eq!(
        caller.role,
        UserRole::SystemAdmin,
        "delegated AUTHORITY = owner's role"
    );
    assert_eq!(
        caller.actor.as_deref(),
        Some(CLIENT_ID),
        "ATTRIBUTION: actor = the client_id, distinct from the principal"
    );

    // Single-use: re-polling a consumed grant ⇒ invalid_grant (400).
    let reuse = client
        .post(format!("{base}/v1/auth/device/token"))
        .json(&serde_json::json!({ "device_code": device_code, "client_id": CLIENT_ID }))
        .send()
        .await
        .expect("re-poll");
    assert_eq!(reuse.status(), 400, "consumed grant ⇒ invalid_grant");
}

#[tokio::test]
async fn deny_then_poll_is_access_denied() {
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let (device_code, user_code) = request_code(&client, &base).await;

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
        .json(&serde_json::json!({ "device_code": device_code, "client_id": CLIENT_ID }))
        .send()
        .await
        .expect("poll denied");
    assert_eq!(poll.status(), 403, "denied poll ⇒ 403");
    assert_eq!(
        poll.json::<serde_json::Value>().await.unwrap()["error"],
        "access_denied"
    );
}

#[tokio::test]
async fn wrong_client_id_on_poll_is_rejected() {
    let engine = node().await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let (device_code, _user_code) = request_code(&client, &base).await;

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
    let engine = node().await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let poll = client
        .post(format!("{base}/v1/auth/device/token"))
        .json(&serde_json::json!({ "device_code": "nonexistent", "client_id": CLIENT_ID }))
        .send()
        .await
        .expect("poll unknown");
    assert_eq!(poll.status(), 400);
    assert_eq!(
        poll.json::<serde_json::Value>().await.unwrap()["error"],
        "invalid_grant"
    );
}

/// An expired device_code ⇒ 410 expired_token. Driven deterministically with a
/// `0`-second grant TTL ([`device_grant::router_with_ttl`]): the code is born
/// already past its TTL, so the very next poll hits the expiry branch.
#[tokio::test]
async fn expired_device_code_is_410() {
    let engine = node().await;
    // Grants expire instantly (TTL = 0).
    let app = device_grant::router_with_ttl(Arc::clone(&engine), 0);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let _h = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let (device_code, _user_code) = request_code_expiring(&client, &base).await;
    let poll = client
        .post(format!("{base}/v1/auth/device/token"))
        .json(&serde_json::json!({ "device_code": device_code, "client_id": CLIENT_ID }))
        .send()
        .await
        .expect("poll expired");
    assert_eq!(poll.status(), 410, "expired device_code ⇒ 410");
    assert_eq!(
        poll.json::<serde_json::Value>().await.unwrap()["error"],
        "expired_token"
    );
}

/// Like [`request_code`] but without the `expires_in == 600` assertion (the
/// expiry test runs with TTL = 0).
async fn request_code_expiring(client: &reqwest::Client, base: &str) -> (String, String) {
    let resp = client
        .post(format!("{base}/v1/auth/device/code"))
        .json(&serde_json::json!({ "client_id": CLIENT_ID }))
        .send()
        .await
        .expect("POST device/code");
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.expect("device/code json");
    (
        json["device_code"]
            .as_str()
            .expect("device_code")
            .to_string(),
        json["user_code"].as_str().expect("user_code").to_string(),
    )
}

#[tokio::test]
async fn approve_without_owner_session_is_rejected() {
    let engine = node().await;
    // A non-owner (Observer) session + the no-session case.
    let observer = mint_session(&engine, "wa-observer", WaRole::Observer).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let (_device_code, user_code) = request_code(&client, &base).await;

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
