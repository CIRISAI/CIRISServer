// STAGE 3 gate — owner delegates to an agent via the ONE-STEP `delegate`+`claim`
// flow and the agent claims a `dgrant:` bearer that authorises acting on the
// owner's behalf. Software keys, in-process. Drives the REAL handlers.
//
// Proves (as per the Stage 3 release plan):
//   1. `POST /v1/auth/device/delegate` with `mode=create` + a label, presented WITH
//      an owner session → 200, body has `pin` (user_code) + `client_id` + `claim_url`
//      + `scope`. WITHOUT an owner session → 401; with a non-owner (Observer) → 403.
//   2. `POST /v1/auth/device/claim` with that `pin` → 200, body has an `access_token`
//      that is `dgrant:`-prefixed + `token_type:"Bearer"`.
//   3. The minted token resolves via `resolve_bearer` to a caller that carries the
//      OWNER's authority (`wa_id` = owner, `role` = SystemAdmin) AND `actor`
//      attribution = the delegated `client_id` (act-on-behalf, graph-backed).

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};

use ciris_server::auth::device_grant;
use ciris_server::auth::roles::UserRole;
use ciris_server::auth::session::resolve_bearer;
use ciris_server::auth::store;
use ciris_server::identity::UserIdentityBackend;

// ── constants ────────────────────────────────────────────────────────────────

const NODE_KEY_ID: &str = "ciris-gate3";

// ── CIRIS_HOME (process-global, set once per binary) ─────────────────────────
//
// This is a separate test binary from `tests/device_grant.rs`, so we can safely
// own the env var here with our own OnceLock. The dir name is distinct from the
// device_grant test dir so even a future merged binary wouldn't collide.

fn ciris_home() -> PathBuf {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("ciris-gate-stage3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create CIRIS_HOME for stage3 gate");
        std::env::set_var("CIRIS_HOME", &dir);
        dir
    })
    .clone()
}

// ── substrate helpers (mirror device_grant.rs exactly) ───────────────────────

async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xB1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xB2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer must succeed"),
    )
}

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

/// Mint the LOCAL owner's fed-ID (software custody) so `resolve_owner_signer`
/// in the delegate handler can re-open the SAME signer. Returns the DERIVED
/// federation key_id (`<alias>-<fp>`).
async fn setup_local_owner(
    engine: &Engine,
    owner_alias: &str,
    seed_dir: &std::path::Path,
) -> String {
    let minted = ciris_server::identity::mint_user_identity(
        UserIdentityBackend::Software,
        owner_alias,
        Some("Gate3 Owner"),
        seed_dir.to_path_buf(),
    )
    .await
    .expect("mint owner identity");
    assert!(
        minted.key_id.starts_with(&format!("{owner_alias}-")),
        "expected derived `{owner_alias}-<fp>` key_id, got {}",
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

/// Mint an active `wa_cert` session bearer (`sess:<wa_id>:testtoken`).
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

/// Serve the device-grant router on an ephemeral port, return `(base_url, handle)`.
async fn serve(
    engine: Arc<Engine>,
    owner_key_id: String,
    seed_dir: PathBuf,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = device_grant::router_with_ttl(engine, owner_key_id, seed_dir, 600);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

// ── GATE 3.1 — happy path: delegate(mode=create) → claim → resolve ────────────

/// The full delegation chain with a fresh software-backed agent identity:
///   POST /v1/auth/device/delegate  →  pin + client_id
///   POST /v1/auth/device/claim     →  dgrant: access_token
///   resolve_bearer                  →  owner authority + actor attribution
#[tokio::test]
async fn gate3_delegate_claim_resolves_with_owner_authority_and_actor_attribution() {
    let home = ciris_home();
    let engine = node().await;

    // Mint + register the owner's software fed-ID so the handler can re-open its
    // signer and emit the signed delegates_to attestation.
    let owner_alias = "g3-owner-happy";
    setup_local_owner(&engine, owner_alias, &home).await;

    // Mint the owner's session bearer (Root → SystemAdmin in the API role map).
    let owner_bearer = mint_session(&engine, "wa-g3-owner", WaRole::Root).await;

    let (base, _h) = serve(Arc::clone(&engine), owner_alias.to_string(), home.clone()).await;
    let client = reqwest::Client::new();

    // ── 1. delegate(mode=create) ─────────────────────────────────────────────
    //
    // The handler mints a fresh software fed-ID for the agent, registers it in the
    // federation directory (register_minted_agent_key), emits a signed delegates_to
    // attestation (inline approval), and returns the PIN.
    let delegate_resp = client
        .post(format!("{base}/v1/auth/device/delegate"))
        .bearer_auth(&owner_bearer)
        .json(&serde_json::json!({ "mode": "create", "label": "g3-test-agent" }))
        .send()
        .await
        .expect("POST /v1/auth/device/delegate");
    assert_eq!(
        delegate_resp.status(),
        200,
        "delegate with owner session must succeed"
    );
    let dj: serde_json::Value = delegate_resp.json().await.expect("delegate response JSON");

    // Verify required response fields (exact field names from the handler).
    let pin = dj["pin"]
        .as_str()
        .expect("delegate response must have 'pin'")
        .to_string();
    let client_id = dj["client_id"]
        .as_str()
        .expect("delegate response must have 'client_id'")
        .to_string();
    assert!(
        dj["claim_url"].as_str().is_some(),
        "delegate response must have 'claim_url'"
    );
    assert!(
        dj["scope"].as_array().is_some(),
        "delegate response must have 'scope' array"
    );
    assert!(
        dj["expires_in"].as_u64().is_some(),
        "delegate response must have 'expires_in'"
    );

    // mode=create generates a derived key_id (label + fingerprint suffix).
    assert!(!client_id.is_empty(), "minted client_id must be non-empty");

    // ── 2. claim(pin) ────────────────────────────────────────────────────────
    //
    // The agent redeems the single-use PIN for the delegated bearer. The claim
    // handler re-checks the graph (reachable_under_scope) before minting.
    let claim_resp = client
        .post(format!("{base}/v1/auth/device/claim"))
        .json(&serde_json::json!({ "pin": pin }))
        .send()
        .await
        .expect("POST /v1/auth/device/claim");
    assert_eq!(
        claim_resp.status(),
        200,
        "claim with valid PIN must succeed"
    );
    let cj: serde_json::Value = claim_resp.json().await.expect("claim response JSON");

    let access_token = cj["access_token"]
        .as_str()
        .expect("claim response must have 'access_token'")
        .to_string();
    assert!(
        access_token.starts_with("dgrant:"),
        "access_token must be dgrant:-prefixed, got: {access_token}"
    );
    assert_eq!(
        cj["token_type"].as_str().unwrap_or(""),
        "Bearer",
        "token_type must be 'Bearer'"
    );

    // ── 3. resolve_bearer → owner authority + actor attribution ──────────────
    //
    // The graph-backed bearer carries the OWNER's authority (wa_id + SystemAdmin)
    // and the ACTOR's attribution (client_id). This proves it is a real
    // act-on-behalf grant, not a raw session or an elevated actor token.
    let caller = resolve_bearer(&engine, &access_token)
        .await
        .expect("resolve_bearer must not error")
        .expect("dgrant token must resolve while the delegation edge is live");

    assert_eq!(
        caller.wa_id, "wa-g3-owner",
        "resolved caller's principal must be the owner"
    );
    assert_eq!(
        caller.role,
        UserRole::SystemAdmin,
        "resolved caller must carry the owner's SystemAdmin authority"
    );
    assert_eq!(
        caller.actor.as_deref(),
        Some(client_id.as_str()),
        "resolved caller's actor attribution must be the minted client_id"
    );
}

// ── GATE 3.2 — auth gate: missing session → 401; Observer role → 403 ─────────

/// `POST /v1/auth/device/delegate` without a bearer → 401.
/// `POST /v1/auth/device/delegate` with a non-owner (Observer) bearer → 403.
#[tokio::test]
async fn gate3_delegate_without_owner_session_is_rejected() {
    let home = ciris_home();
    let engine = node().await;

    // Mint an Observer session (non-owner role).
    let observer_bearer = mint_session(&engine, "wa-g3-observer", WaRole::Observer).await;

    let (base, _h) = serve(
        Arc::clone(&engine),
        "g3-owner-gate".to_string(),
        home.clone(),
    )
    .await;
    let client = reqwest::Client::new();
    let body = serde_json::json!({ "mode": "create", "label": "g3-gatetest-agent" });

    // No bearer → 401.
    let no_auth = client
        .post(format!("{base}/v1/auth/device/delegate"))
        .json(&body)
        .send()
        .await
        .expect("POST delegate no auth");
    assert_eq!(
        no_auth.status(),
        401,
        "missing bearer must yield 401 (got {})",
        no_auth.status()
    );

    // Observer role (insufficient) → 403.
    let forbidden = client
        .post(format!("{base}/v1/auth/device/delegate"))
        .bearer_auth(&observer_bearer)
        .json(&body)
        .send()
        .await
        .expect("POST delegate observer");
    assert_eq!(
        forbidden.status(),
        403,
        "Observer role must yield 403 (got {})",
        forbidden.status()
    );
}

// ── GATE 3.3 — invalid PIN on claim → 404 ────────────────────────────────────

/// `POST /v1/auth/device/claim` with an unknown PIN → 404 (not 500 or 200).
/// Verifies the claim route is wired and the error path is correct.
#[tokio::test]
async fn gate3_claim_unknown_pin_is_404() {
    let home = ciris_home();
    let engine = node().await;

    let (base, _h) = serve(
        Arc::clone(&engine),
        "g3-owner-claimgate".to_string(),
        home.clone(),
    )
    .await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/v1/auth/device/claim"))
        .json(&serde_json::json!({ "pin": "ZZZZ-ZZZZ" }))
        .send()
        .await
        .expect("POST claim unknown pin");
    assert_eq!(
        resp.status(),
        404,
        "unknown pin must yield 404 (got {})",
        resp.status()
    );
}
