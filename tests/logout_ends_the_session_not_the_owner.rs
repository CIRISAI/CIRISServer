//! **Logout revokes the SESSION, not the OWNER** (CIRISServer#403).
//!
//! `POST /v1/auth/logout` was implemented as `store::set_active(wa_id, false)`
//! — cert deactivation. The token is stateless (`sess:<wa_id>:<nonce>.<mac>`,
//! nothing stored at issuance), so deactivating the cert was the only lever
//! within reach, and it revoked the IDENTITY:
//!
//!   - every sibling session of the same account died with the one that
//!     logged out;
//!   - on a personal node the cert is the owner's ROOT, so "sign out" locked
//!     the owner out of their own node irreversibly (nothing reactivates a
//!     ROOT);
//!   - with zero active roots, `is_first_run` reopened — the next claimant
//!     could own the node.
//!
//! The fix is a per-session nonce revocation set inside the ONE token gate
//! (`session_token_is_authentic`), so a revoked session fails every door —
//! resolve, refresh, me — while the cert, the owner, and every sibling session
//! stand. These tests drive the REAL router (`session::router` via tower
//! oneshot, the `tests/ingest_http.rs` pattern) over the
//! `tests/session_token_is_verified.rs` engine/owner fixtures.
//!
//! The session secret and the revocation set are PROCESS-GLOBAL (that is the
//! design: one issuer per node), so every test here takes `SERIAL` — the
//! cap-rotation test invalidates every outstanding token in the process, which
//! is correct in production and cross-talk in a parallel test binary.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};
use ciris_server::auth::{bootstrap, session, store};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use tower::ServiceExt as _; // for `oneshot`

/// Serializes the tests in this file — see the module doc. An ASYNC mutex
/// because the guard is deliberately held across awaits (that is its whole
/// job), and tokio's guard neither poisons nor trips `await_holding_lock`.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL.lock().await
}

async fn engine() -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xE2; 32], "ciris-server-pqc".to_string())
            .expect("seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xE1; 32]),
        "ciris-server".to_string(),
        Some(pqc),
        Some("ciris-server-pqc".to_string()),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine"),
    )
}

/// An owner ROOT with a password, the way the wizard's claim stamps one — the
/// password is what lets the re-login leg prove recovery end-to-end.
async fn owner(e: &Engine, wa_id: &str, name: &str) {
    let now = chrono::Utc::now();
    store::upsert(
        e,
        WaCert {
            wa_id: wa_id.to_string(),
            name: name.to_string(),
            role: WaRole::Root,
            pubkey: format!("system-of:{wa_id}"),
            jwt_kid: format!("kid-{wa_id}"),
            password_hash: Some(session::hash_password("hunter2")),
            api_key_hash: None,
            oauth_provider: None,
            oauth_external_id: None,
            oauth_links: None,
            veilid_id: None,
            auto_minted: false,
            adapter_id: None,
            adapter_name: None,
            adapter_metadata: None,
            scopes: serde_json::json!([]),
            custom_permissions: None,
            token_type: TokenType::Standard,
            parent_wa_id: None,
            parent_signature: None,
            created: now,
            last_login: None,
            active: true,
        },
    )
    .await
    .expect("stamp the owner");
}

fn bearer_post(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}

async fn logout(app: &axum::Router, token: &str) -> StatusCode {
    app.clone()
        .oneshot(bearer_post("/v1/auth/logout", token))
        .await
        .expect("logout call")
        .status()
}

/// **THE DEFECT, pinned.** Two live sessions for ONE account; logging out the
/// first must kill exactly it. Under the pre-#403 implementation (cert
/// deactivation) token B dies with A — this assertion is what fails there.
#[tokio::test]
async fn logging_out_one_session_leaves_the_sibling_session_alive() {
    let _guard = serial().await;
    let e = engine().await;
    let wa = "wa-root-two-sessions";
    owner(&e, wa, "two sessions").await;
    let app = session::router(e.clone());

    let a = session::test_support_issue_session_token(wa);
    let b = session::test_support_issue_session_token(wa);

    assert_eq!(logout(&app, &a).await, StatusCode::NO_CONTENT);

    assert!(
        session::resolve_bearer(&e, &a)
            .await
            .expect("store")
            .is_none(),
        "the logged-out session must be dead"
    );
    assert!(
        session::resolve_bearer(&e, &b)
            .await
            .expect("store")
            .is_some(),
        "sibling session B died with A — logout revoked the IDENTITY, not the session. \
         That is the #403 defect: one tap on sign-out ends every session of the account"
    );
}

/// Logout must leave the OWNER standing: cert active, ROOT listed, first-run
/// closed. Under cert-deactivation all three fail — and the third is the one
/// that hands the node to the next claimant.
#[tokio::test]
async fn logout_leaves_the_owner_cert_active_and_first_run_closed() {
    let _guard = serial().await;
    let e = engine().await;
    let wa = "wa-root-still-owner";
    owner(&e, wa, "still owner").await;
    let app = session::router(e.clone());

    let t = session::test_support_issue_session_token(wa);
    assert_eq!(logout(&app, &t).await, StatusCode::NO_CONTENT);

    let cert = store::get(&e, wa).await.expect("store").expect("cert row");
    assert!(cert.active, "logout deactivated the owner's cert (#403)");
    assert!(
        !store::list_by_role(&e, WaRole::Root, 8)
            .await
            .expect("store")
            .is_empty(),
        "the node must still list an active ROOT after a logout"
    );
    assert!(
        !bootstrap::is_first_run(&e).await,
        "logout REOPENED first-run — with zero active roots the next claimant owns the node"
    );
}

/// Recovery is an ordinary re-login: 200, a fresh working token — and the
/// logged-out one STAYS dead (revocation is not undone by signing in again).
#[tokio::test]
async fn after_logout_the_owner_relogs_in_and_the_old_token_stays_dead() {
    let _guard = serial().await;
    let e = engine().await;
    let wa = "wa-root-relogin";
    owner(&e, wa, "relogin owner").await;
    let app = session::router(e.clone());

    let old = session::test_support_issue_session_token(wa);
    assert_eq!(logout(&app, &old).await, StatusCode::NO_CONTENT);

    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"username": "relogin owner", "password": "hunter2"})
                        .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("login call");
    assert_eq!(
        login.status(),
        StatusCode::OK,
        "re-login must succeed — under cert-deactivation this is a 403 forever"
    );
    let body = login.into_body().collect().await.expect("body").to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let fresh = v
        .get("access_token")
        .and_then(|t| t.as_str())
        .expect("access_token")
        .to_string();

    assert!(
        session::resolve_bearer(&e, &fresh)
            .await
            .expect("store")
            .is_some(),
        "the fresh session must work"
    );
    assert!(
        session::resolve_bearer(&e, &old)
            .await
            .expect("store")
            .is_none(),
        "the logged-out token must STAY dead after a re-login"
    );
}

/// A revoked session must not refresh itself back to life — refresh sits
/// behind the same composite gate (`wa_id_from_token` verifies MAC AND
/// revocation), so the 401 is structural, not a per-handler check.
#[tokio::test]
async fn a_revoked_token_cannot_refresh() {
    let _guard = serial().await;
    let e = engine().await;
    let wa = "wa-root-no-refresh";
    owner(&e, wa, "no refresh").await;
    let app = session::router(e.clone());

    let t = session::test_support_issue_session_token(wa);
    assert_eq!(logout(&app, &t).await, StatusCode::NO_CONTENT);

    let refresh = app
        .clone()
        .oneshot(bearer_post("/v1/auth/refresh", &t))
        .await
        .expect("refresh call");
    assert_eq!(
        refresh.status(),
        StatusCode::UNAUTHORIZED,
        "a logged-out session refreshed itself into a fresh, genuine token — logout would \
         be one POST away from meaningless"
    );
}

/// A forged token must log NOBODY out. The wa_id is public (owner-hint), so if
/// the logout gate were the parse rather than the MAC, an unauthenticated GET
/// plus one POST would end the owner's sessions.
#[tokio::test]
async fn a_forged_token_cannot_log_anyone_out() {
    let _guard = serial().await;
    let e = engine().await;
    let wa = "wa-root-forge-target";
    owner(&e, wa, "forge target").await;
    let app = session::router(e.clone());

    let live = session::test_support_issue_session_token(wa);
    assert_eq!(
        logout(&app, &format!("sess:{wa}:FORGEDXXXXXX")).await,
        StatusCode::UNAUTHORIZED,
        "a forged bearer must be refused, not treated as a session to end"
    );
    let cert = store::get(&e, wa).await.expect("store").expect("cert row");
    assert!(cert.active, "…and the cert must be untouched");
    assert!(
        session::resolve_bearer(&e, &live)
            .await
            .expect("store")
            .is_some(),
        "…and the real session must still be alive"
    );
}

/// Double logout is 204/204 — the gate is the MAC alone, not the composite, so
/// an already-revoked (but genuine) token reads as "already done", never as an
/// attack.
#[tokio::test]
async fn double_logout_is_idempotent_204_then_204() {
    let _guard = serial().await;
    let e = engine().await;
    let wa = "wa-root-double";
    owner(&e, wa, "double logout").await;
    let app = session::router(e.clone());

    let t = session::test_support_issue_session_token(wa);
    assert_eq!(logout(&app, &t).await, StatusCode::NO_CONTENT);
    assert_eq!(
        logout(&app, &t).await,
        StatusCode::NO_CONTENT,
        "a second logout of the same token is the same end state — 204, not 401"
    );
}

/// **Rotation, not eviction, at the cap.** Revoke CAP+1 tokens and EVERY one
/// must still be rejected. This is the assertion that tells the two designs
/// apart: under FIFO eviction the earliest revocations are silently dropped to
/// make room, so token #1 comes back to life — revoked-then-un-revoked, by
/// design. Under rotation the secret changes, which kills all of them at once.
#[tokio::test]
async fn revoking_past_the_cap_rotates_rather_than_resurrecting_old_tokens() {
    let _guard = serial().await;
    let e = engine().await;
    let wa = "wa-root-cap";
    owner(&e, wa, "cap owner").await;
    let app = session::router(e.clone());

    let n = session::REVOKED_SESSION_CAP + 1;
    let mut tokens = Vec::with_capacity(n);
    for _ in 0..n {
        tokens.push(session::test_support_issue_session_token(wa));
    }
    // Earlier tests in this (serialized) process already revoked a handful of
    // nonces, so the rotation fires a few logouts EARLY — and from that point
    // the remaining tokens were minted under the retired secret, so their
    // logout answers 401 ("nothing to revoke": the rotation already killed
    // them). Both answers describe a dead token; what is NEVER acceptable is
    // a live one, which the resolve loop below asserts for all n.
    let mut revoked_204 = 0usize;
    for t in &tokens {
        match logout(&app, t).await {
            StatusCode::NO_CONTENT => revoked_204 += 1,
            StatusCode::UNAUTHORIZED => {}
            other => panic!("logout answered {other} — expected 204 (revoked) or 401 (already dead via rotation)"),
        }
    }
    assert!(
        revoked_204 >= n - 64,
        "only {revoked_204} of {n} logouts were ordinary 204s — far more than this file's \
         handful of earlier revocations should ever pre-fill the set, so the cap is \
         tripping much too early"
    );
    for (i, t) in tokens.iter().enumerate() {
        assert!(
            session::resolve_bearer(&e, t)
                .await
                .expect("store")
                .is_none(),
            "token #{i} of {n} authenticates again after the revocation set passed its cap — \
             the cap is being enforced by EVICTION, which silently un-revokes logged-out \
             tokens. The cap must rotate the session secret instead (restart semantics)"
        );
    }
}

/// The two DELIBERATE `set_active(false)` callers survive #403: the api-key
/// DELETE still deactivates an API key, and still refuses to deactivate the
/// owner's ROOT through the same route.
#[tokio::test]
async fn api_key_delete_still_works_and_still_refuses_the_root_id() {
    let _guard = serial().await;
    let e = engine().await;
    let wa = "wa-root-keyholder";
    owner(&e, wa, "key holder").await;

    // An API-key row, the shape `create_api_key` writes.
    let now = chrono::Utc::now();
    store::upsert(
        &e,
        WaCert {
            wa_id: "wa-apikey-test-1".to_string(),
            name: "test key".to_string(),
            role: WaRole::Observer,
            pubkey: "apikey:test-1".to_string(),
            jwt_kid: "kid-apikey-test-1".to_string(),
            password_hash: None,
            api_key_hash: Some("deadbeef".to_string()),
            oauth_provider: None,
            oauth_external_id: None,
            oauth_links: None,
            veilid_id: None,
            auto_minted: true,
            adapter_id: None,
            adapter_name: None,
            adapter_metadata: None,
            scopes: serde_json::json!([]),
            custom_permissions: None,
            token_type: TokenType::ApiKey,
            parent_wa_id: Some(wa.to_string()),
            parent_signature: None,
            created: now,
            last_login: None,
            active: true,
        },
    )
    .await
    .expect("stamp an api-key row");

    let keys = ciris_server::auth::api_keys::router(e.clone());
    let owner_token = session::test_support_issue_session_token(wa);
    let delete = |uri: String| {
        Request::builder()
            .method("DELETE")
            .uri(uri)
            .header("authorization", format!("Bearer {owner_token}"))
            .body(Body::empty())
            .expect("request")
    };

    let ok = keys
        .clone()
        .oneshot(delete("/v1/auth/api-keys/wa-apikey-test-1".to_string()))
        .await
        .expect("api-key delete");
    assert_eq!(
        ok.status(),
        StatusCode::NO_CONTENT,
        "deactivating an API KEY is the deliberate set_active(false) — it must survive #403"
    );

    let refused = keys
        .clone()
        .oneshot(delete(format!("/v1/auth/api-keys/{wa}")))
        .await
        .expect("root delete attempt");
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "the api-key route must still refuse to deactivate a non-key cert (the owner)"
    );
    let cert = store::get(&e, wa).await.expect("store").expect("cert row");
    assert!(cert.active, "…and the owner must still be active");
}
