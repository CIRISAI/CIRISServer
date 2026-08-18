//! **Every OAuth surface answers in ITS OWN shape** (CIRISServer#429/#424/#425).
//!
//! One responder (`finish_oauth_login`) served two callers with opposite
//! contracts: the NATIVE token exchange (SDK code decoding JSON) and the
//! provider CALLBACK (a human's browser needing a page). The fusion shipped
//! the hand-off PAGE to the Apple decoder (#429), JSON walls to humans (#424),
//! and a hand-off slot that could not say "failed" (#425).
//!
//! These tests drive the REAL router — `oauth::router_with_client` with a stub
//! [`ProviderClient`], tower oneshot — over a CLAIMED node (the
//! `tests/session_token_is_verified.rs` fixture shape: `resolve_oauth_user`
//! only refuses when the node is claimed AND unmanaged, so an unclaimed
//! fixture would test nothing).
//!
//! The stub's `exchange_code` can be GATED (two `Notify`s) so the
//! consume→park window — THE race — is held open deterministically while the
//! hand-off is polled.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};
use ciris_server::auth::oauth::{self, OAuthIdentity, ProviderClient};
use ciris_server::auth::store;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use tokio::sync::Notify;
use tower::ServiceExt as _; // for `oneshot`

const OWNER_SUB: &str = "sub-owner";

async fn engine() -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xF2; 32], "ciris-server-pqc".to_string())
            .expect("seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xF1; 32]),
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

/// CLAIM the node: an owner ROOT carrying the (google, sub-owner) sign-in pair
/// — the state after a real wizard claim, and the state in which
/// `resolve_oauth_user` resolves the owner and refuses strangers.
async fn claimed_owner(e: &Engine) {
    let now = chrono::Utc::now();
    let wa_id = "wa-root-surface-owner";
    store::upsert(
        e,
        WaCert {
            wa_id: wa_id.to_string(),
            name: format!("root:{wa_id}"),
            role: WaRole::Root,
            pubkey: format!("system-of:{wa_id}"),
            jwt_kid: format!("kid-{wa_id}"),
            password_hash: None,
            api_key_hash: None,
            oauth_provider: Some("google".to_string()),
            oauth_external_id: Some(OWNER_SUB.to_string()),
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
    .expect("claim the node");
}

/// The provider seam, scripted by the CODE / ID_TOKEN value:
/// `ok-owner`/`good-owner` → the owner's identity; `ok-unknown`/`good-unknown`
/// → a stranger; `fail` → an upstream error string. `gate` holds
/// `exchange_code` open between `entered` and `release` for the race test.
struct StubProvider {
    gate: Option<(Arc<Notify>, Arc<Notify>)>,
}

/// The stub answers the way Google does: an ID token arrives in the SAME
/// response as the access token (CIRISServer#434), so any hop that drops it
/// between the exchange and the app is visible end-to-end.
fn ident(sub: &str) -> OAuthIdentity {
    OAuthIdentity {
        provider: "google".to_string(),
        external_id: sub.to_string(),
        email: Some(format!("{sub}@example.com")),
        name: Some(sub.to_string()),
        id_token: Some(format!("stub-id-token-for-{sub}")),
    }
}

/// A provider that issues NO ID token — an OAuth2-only seam like GitHub. The
/// sign-in must still succeed; absence is a fact about the provider, not a
/// failure of the flow.
fn ident_without_id_token(sub: &str) -> OAuthIdentity {
    OAuthIdentity {
        id_token: None,
        ..ident(sub)
    }
}

#[async_trait::async_trait]
impl ProviderClient for StubProvider {
    /// Echoes the `redirect_uri` back, which is what makes the node's resolved
    /// callback base observable from OUTSIDE the process (CIRISServer#435) —
    /// exactly as a real provider console sees it, and exactly the value that
    /// mismatches when the node guessed loopback.
    fn authorize_url(
        &self,
        _provider: &str,
        _client_id: &str,
        state: &str,
        redirect_uri: &str,
        _code_challenge: &str,
    ) -> String {
        format!("https://stub.invalid/authorize?state={state}&redirect_uri={redirect_uri}")
    }
    async fn exchange_code(
        &self,
        _provider: &str,
        _cfg_client_id: &str,
        _cfg_client_secret: &str,
        code: &str,
        _redirect_uri: &str,
        _code_verifier: &str,
    ) -> Result<OAuthIdentity, String> {
        if let Some((entered, release)) = &self.gate {
            entered.notify_one();
            release.notified().await;
        }
        match code {
            "ok-owner" => Ok(ident(OWNER_SUB)),
            "ok-no-id-token" => Ok(ident_without_id_token(OWNER_SUB)),
            "ok-unknown" => Ok(ident("sub-stranger")),
            other => Err(format!(
                "stub upstream refused code {other:?}: 502 from provider"
            )),
        }
    }
    async fn verify_native(
        &self,
        _provider: &str,
        id_token: &str,
        _allowed_audiences: &[String],
    ) -> Result<OAuthIdentity, String> {
        match id_token {
            "good-owner" => Ok(ident(OWNER_SUB)),
            "good-unknown" => Ok(ident("sub-stranger")),
            _ => Err("Google could not verify this ID token.".to_string()),
        }
    }
}

/// A claimed node's router with the stub seam, provider pre-configured.
async fn app_with(gate: Option<(Arc<Notify>, Arc<Notify>)>) -> axum::Router {
    app_with_callback_base(gate, "http://127.0.0.1:4243").await
}

/// [`app_with`] with the stored `auth.oauth_callback_base_url` chosen by the
/// caller — `""` is the UNCLAIMED node that has never been able to write one.
async fn app_with_callback_base(
    gate: Option<(Arc<Notify>, Arc<Notify>)>,
    callback_base: &str,
) -> axum::Router {
    let e = engine().await;
    claimed_owner(&e).await;
    let app = oauth::router_with_client(
        e,
        callback_base.to_string(),
        Arc::new(StubProvider { gate }),
    );
    // Configure the provider the way an operator (or the manager) does.
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/oauth/providers")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "provider": "google",
                        "client_id": "cid",
                        "client_secret": "sec",
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("configure provider");
    assert_eq!(r.status(), StatusCode::OK, "provider configuration failed");
    app
}

/// Start a flow; return the one-use `state` parsed out of the authorize
/// redirect the stub built.
async fn start_flow(app: &axum::Router, query: &str) -> String {
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/auth/oauth/google/login{query}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("login call");
    assert_eq!(
        r.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "the login leg must redirect to the provider"
    );
    let loc = r
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("authorize redirect");
    loc.split("state=")
        .nth(1)
        .expect("state in the authorize URL")
        .split('&')
        .next()
        .expect("state value")
        .to_string()
}

/// [`start_flow`] but returning the WHOLE authorize URL — the redirect_uri the
/// provider is handed is the subject of the #435 test, not just the state.
async fn start_flow_url(app: &axum::Router, query: &str) -> String {
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/auth/oauth/google/login{query}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("login call");
    assert_eq!(r.status(), StatusCode::TEMPORARY_REDIRECT);
    r.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("authorize redirect")
        .to_string()
}

fn callback_req(code: &str, state: &str, accept: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(format!(
        "/v1/auth/oauth/google/callback?code={code}&state={state}"
    ));
    if let Some(a) = accept {
        b = b.header("accept", a);
    }
    b.body(Body::empty()).expect("request")
}

/// The hand-off is loopback-gated; oneshot has no socket, so the ConnectInfo
/// the gate reads is supplied as an extension — the same value the real
/// listener injects.
fn handoff_req(nonce: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/v1/auth/oauth/handoff?app_nonce={nonce}"))
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 51423))))
        .body(Body::empty())
        .expect("request")
}

async fn body_json(r: axum::response::Response) -> serde_json::Value {
    let b = r.into_body().collect().await.expect("body").to_bytes();
    serde_json::from_slice(&b).expect("json body")
}

async fn body_text(r: axum::response::Response) -> String {
    let b = r.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&b).to_string()
}

fn content_type(r: &axum::response::Response) -> String {
    r.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// #429, the success half: a native exchange on a CLAIMED node answers 200
/// `application/json` carrying every field the published spec requires —
/// never the hand-off page.
#[tokio::test]
async fn a_native_exchange_answers_json_with_every_required_field() {
    let app = app_with(None).await;
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/native/google")
                .header("content-type", "application/json")
                // `Accept: */*` — the default every HTTP client sends, and the
                // exact header under which #429 served HTML.
                .header("accept", "*/*")
                .body(Body::from(
                    serde_json::json!({"id_token": "good-owner"}).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("native call");
    assert_eq!(r.status(), StatusCode::OK);
    assert!(
        content_type(&r).starts_with("application/json"),
        "the native exchange must be JSON under Accept: */* — this is #429"
    );
    let v = body_json(r).await;
    for field in [
        "access_token",
        "expires_in",
        "user_id",
        "role",
        "token_type",
    ] {
        assert!(
            v.get(field).is_some_and(|x| !x.is_null()),
            "native response is missing `{field}` — the generated client's decode dies here"
        );
    }
    assert_eq!(v.get("token_type").and_then(|x| x.as_str()), Some("Bearer"));
    assert!(
        v.get("email").is_some() && v.get("name").is_some(),
        "email/name are emitted always (null when absent)"
    );
}

/// #429, the refusal half: an unknown identity on a claimed node is a 403 in
/// JSON — including when the caller's Accept header asks for HTML, because
/// the native surface does not negotiate (D1).
#[tokio::test]
async fn a_native_refusal_is_json_even_when_the_caller_asks_for_html() {
    let app = app_with(None).await;
    for accept in ["*/*", "text/html"] {
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/native/google")
                    .header("content-type", "application/json")
                    .header("accept", accept)
                    .body(Body::from(
                        serde_json::json!({"id_token": "good-unknown"}).to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("native call");
        assert_eq!(
            r.status(),
            StatusCode::FORBIDDEN,
            "claimed + unknown identity is the typed 403"
        );
        assert!(
            content_type(&r).starts_with("application/json"),
            "native refusals are JSON regardless of Accept ({accept}) — D1"
        );
        let v = body_json(r).await;
        assert_eq!(
            v.get("reason_id").and_then(|x| x.as_str()),
            Some("auth.oauth.no_local_identity")
        );
    }
}

/// The browser callback's SUCCESS is a human page (no redirect requested), and
/// the parked session is collectable over the loopback hand-off with the
/// additive `"status": "complete"`.
#[tokio::test]
async fn a_callback_success_is_a_page_and_the_handoff_completes() {
    let app = app_with(None).await;
    let state = start_flow(&app, "?app_nonce=n-page").await;

    let r = app
        .clone()
        .oneshot(callback_req("ok-owner", &state, None))
        .await
        .expect("callback");
    assert_eq!(r.status(), StatusCode::OK);
    assert!(
        content_type(&r).starts_with("text/html"),
        "the provider callback is reached by a BROWSER — it answers with a page"
    );
    let page = body_text(r).await;
    assert!(page.contains("You're signed in"), "the hand-off page");

    let h = app
        .clone()
        .oneshot(handoff_req("n-page"))
        .await
        .expect("handoff poll");
    assert_eq!(h.status(), StatusCode::OK);
    let v = body_json(h).await;
    assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("complete"));
    assert!(
        v.get("access_token").is_some_and(|x| x.is_string()),
        "the flattened session payload, exactly as before the status member"
    );
}

/// **The ID token survives every hop from the provider to the app**
/// (CIRISServer#434).
///
/// The desktop client cannot see the provider's response — its only view is
/// the hand-off. So CIRIS_PROXY, whose `api_key` IS a Google ID token, told
/// users signed in with Google that Google sign-in was required, and the mode
/// could not be selected at all. The native clients were fine because they
/// supply the ID token themselves as the login credential.
///
/// Driven END TO END deliberately. A struct-level check passes while any
/// middle hop drops the field — verified: nulling it in `resolve_login` left
/// the serialization test green, and only this test caught it. Same lesson
/// this file's `serde_json::to_value(&p)` assertion already recorded.
#[tokio::test]
async fn the_id_token_reaches_the_app_through_the_whole_browser_flow() {
    let app = app_with(None).await;
    let state = start_flow(&app, "?app_nonce=n-idtok").await;

    let r = app
        .clone()
        .oneshot(callback_req("ok-owner", &state, None))
        .await
        .expect("callback");
    assert_eq!(r.status(), StatusCode::OK);

    let v = body_json(
        app.clone()
            .oneshot(handoff_req("n-idtok"))
            .await
            .expect("handoff poll"),
    )
    .await;
    assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("complete"));
    assert_eq!(
        v.get("id_token").and_then(|x| x.as_str()),
        Some(format!("stub-id-token-for-{OWNER_SUB}").as_str()),
        "the ID token the provider issued must reach the app VERBATIM — it is \
         a signed credential, so any hop that re-encodes or drops it breaks \
         desktop CIRIS_PROXY"
    );
    // It rides ALONGSIDE the session, not instead of it.
    assert!(
        v.get("access_token").is_some_and(|x| x.is_string()),
        "the flattened session grant is unchanged"
    );
}

/// A provider that issues no ID token still signs the user in, and the key is
/// ABSENT rather than null or empty (CIRISServer#434).
///
/// The distinct-zero half: a client must be able to tell "this provider issues
/// none" from "one arrived and was empty".
#[tokio::test]
async fn a_provider_with_no_id_token_still_signs_in_and_omits_the_key() {
    let app = app_with(None).await;
    let state = start_flow(&app, "?app_nonce=n-noid").await;

    let r = app
        .clone()
        .oneshot(callback_req("ok-no-id-token", &state, None))
        .await
        .expect("callback");
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "no ID token is not a sign-in failure"
    );

    let v = body_json(
        app.clone()
            .oneshot(handoff_req("n-noid"))
            .await
            .expect("handoff poll"),
    )
    .await;
    assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("complete"));
    assert!(
        v.get("access_token").is_some_and(|x| x.is_string()),
        "the session is issued regardless"
    );
    assert!(
        v.get("id_token").is_none(),
        "absent, never null and never empty string — got {v:?}"
    );
}

/// **What the provider is actually told the callback is** (CIRISServer#435).
///
/// A fresh deployment could not write `auth.oauth_callback_base_url`: doing so
/// needs an owner session, getting an owner session needs signing in, and
/// signing in is what the key configures. The node fell back to
/// `127.0.0.1:4243`, no provider console has that registered, and the flow died
/// at the provider with `redirect_uri_mismatch`.
///
/// Asserted through the AUTHORIZE REDIRECT because that is where the value
/// leaves the node — the same string the provider compares against its
/// allow-list. A test of the resolver alone leaves the wiring uncovered
/// (verified: making env beat stored config passed every other test here).
#[tokio::test]
async fn the_callback_base_reaching_the_provider_prefers_config_then_env() {
    fn clear() {
        std::env::remove_var("CIRIS_OAUTH_CALLBACK_BASE_URL");
        std::env::remove_var("OAUTH_CALLBACK_BASE_URL");
    }
    // Serialized in one test: these mutate PROCESS environment, and the other
    // tests in this binary run on sibling threads.
    clear();

    // A node with a STORED value ignores the environment completely. An
    // operator who set this at runtime meant it, and a stale deployment
    // variable must never silently override them.
    std::env::set_var("CIRIS_OAUTH_CALLBACK_BASE_URL", "https://env.example");
    let app = app_with_callback_base(None, "https://stored.example").await;
    let url = start_flow_url(&app, "?app_nonce=n-cfg").await;
    assert!(
        url.contains("redirect_uri=https://stored.example/"),
        "stored config must win over the environment, got {url}"
    );

    // The boot hole: nothing stored — the deployment's declaration is used
    // instead of a loopback address no provider console has ever seen.
    let app = app_with_callback_base(None, "").await;
    let url = start_flow_url(&app, "?app_nonce=n-env").await;
    assert!(
        url.contains("redirect_uri=https://env.example/"),
        "an unclaimed node must use the declared base, got {url}"
    );

    // Nothing stored and nothing declared: the loopback default, unchanged.
    clear();
    let app = app_with_callback_base(None, "").await;
    let url = start_flow_url(&app, "?app_nonce=n-def").await;
    assert!(
        url.contains("redirect_uri=http://127.0.0.1:4243/"),
        "the last-resort default is unchanged for local development, got {url}"
    );
}

/// **A WEB sign-in comes back with something the page can redeem**
/// (CIRISServer#439).
///
/// The web branch used to redirect to the destination carrying NOTHING. The
/// sign-in had succeeded and the session was parked on a loopback-only route a
/// remote browser cannot reach, so the page saw no token and no `error` — and
/// CIRISGUI's bare `else` reported `oauth_failed` on a SUCCESSFUL sign-in.
/// "No session came back" and "the provider refused" were one branch.
///
/// What this must NOT become is the old contract. A live bearer in the redirect
/// lands in history, in `Referer`, and in every proxy log on the path, which is
/// why it was removed. So the assertions below are two-sided: a code IS
/// present, and the session is NOT.
#[tokio::test]
async fn a_web_signin_redirect_carries_a_redemption_code_and_never_the_session() {
    let app = app_with(None).await;
    let state = start_flow(&app, "?app_nonce=n-web&redirect_uri=/dashboard").await;

    let r = app
        .clone()
        .oneshot(callback_req("ok-owner", &state, None))
        .await
        .expect("callback");
    assert_eq!(r.status(), StatusCode::SEE_OTHER, "D3: 303 to the page");
    let loc = r
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("redirect location")
        .to_string();

    assert!(
        loc.starts_with("/dashboard"),
        "still the caller's own destination: {loc}"
    );
    assert!(
        loc.contains("ciris_code="),
        "the page must receive a redemption code or it cannot tell success from \
         refusal — that is the whole defect: {loc}"
    );
    // THE HALF THAT MUST NEVER REGRESS.
    for forbidden in ["access_token", "token_type", "user_id=", "sess:"] {
        assert!(
            !loc.contains(forbidden),
            "`{forbidden}` is back in the redirect URL — a bearer in a URL is \
             the unsafe contract this replaced: {loc}"
        );
    }

    // Redeem it: the session arrives in the BODY, once.
    let code = loc
        .split("ciris_code=")
        .nth(1)
        .expect("code present")
        .split('&')
        .next()
        .expect("code value")
        .to_string();
    let ex = |c: &str| {
        Request::builder()
            .method("POST")
            .uri("/v1/auth/oauth/exchange")
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"code":"{c}"}}"#)))
            .expect("request")
    };

    let first = app.clone().oneshot(ex(&code)).await.expect("exchange");
    assert_eq!(first.status(), StatusCode::OK);
    let v = body_json(first).await;
    assert!(
        v.get("access_token").is_some_and(|x| x.is_string()),
        "the session rides the BODY: {v:?}"
    );
    assert_eq!(v.get("provider").and_then(|x| x.as_str()), Some("google"));

    // ONE redemption. A code recovered from history later is spent.
    let second = app
        .clone()
        .oneshot(ex(&code))
        .await
        .expect("exchange again");
    assert_eq!(
        second.status(),
        StatusCode::UNAUTHORIZED,
        "a redeemed code must not issue a second session"
    );
    let v2 = body_json(second).await;
    assert_eq!(
        v2.get("reason_id").and_then(|x| x.as_str()),
        Some("auth.oauth.exchange_code_invalid")
    );
}

/// An unknown code and a spent code are the SAME refusal — telling them apart
/// confirms a real code to whoever is probing, and no page can act on it.
#[tokio::test]
async fn an_unknown_exchange_code_is_refused_indistinguishably() {
    let app = app_with(None).await;
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/oauth/exchange")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"code":"never-existed"}"#))
                .expect("request"),
        )
        .await
        .expect("exchange");
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let v = body_json(r).await;
    assert_eq!(
        v.get("reason_id").and_then(|x| x.as_str()),
        Some("auth.oauth.exchange_code_invalid"),
        "same id as a SPENT code — see the other test: {v:?}"
    );
}

/// **The node states its deployment shape** (CIRISServer#439 finding 2).
///
/// CIRISGUI decided "managed" with `hostname === 'agents.ciris.ai'`, so every
/// other hosted node — scout included — was classified unmanaged and built its
/// API base URL wrong. A client cannot derive this; the node knows it at boot.
#[tokio::test]
async fn the_providers_endpoint_states_the_nodes_deployment_shape() {
    // A bare origin. Deliberately NOT a real deployment's hostname: this
    // asserts the SHAPE rule, and naming a live host here would read as a claim
    // about how that host is actually deployed.
    let app = app_with_callback_base(None, "https://node.example").await;
    let v = body_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/auth/oauth/providers")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("providers"),
    )
    .await;

    assert_eq!(
        v.get("callback_base").and_then(|x| x.as_str()),
        Some("https://node.example"),
        "the node must state the base its redirects resolve against: {v:?}"
    );
    assert_eq!(
        v.get("web_signin").and_then(|x| x.as_bool()),
        Some(true),
        "a page needs to know whether the browser flow is served at all"
    );
    // `managed` is stated, and it is an AUTH-POLICY fact — whether this node
    // admits MULTIPLE logins — not a statement about its URL. See the
    // dedicated test below for the property that matters.
    assert!(
        v.get("managed").is_some_and(|x| x.is_boolean()),
        "the node must state its managed posture: {v:?}"
    );
    assert_eq!(
        v.get("exchange_query_key").and_then(|x| x.as_str()),
        Some("ciris_code"),
        "the key is read from the node, not spelled a second time in the client"
    );
}

/// **`managed` is an AUTH-POLICY fact and must NOT move with the URL** (#439).
///
/// A first draft derived it from whether the callback base carried a path — a
/// ROUTING question wearing the name of a policy one, which is this repo's own
/// axis-fusion class. `managed` means the deployment admits MULTIPLE logins:
/// CIRIS Manager provisions people ahead of time, so a stranger signing in gets
/// an observer default rather than the `NoLocalIdentity` refusal a personal
/// node gives. scout is managed because it allows many users, not because of
/// how it is addressed.
///
/// So the property under test is an INDEPENDENCE, not a value: four callback
/// bases of deliberately different shapes must all report the SAME posture,
/// because none of them says anything about who may log in. The path-derived
/// draft fails this — it answers true for two of them and false for two.
#[tokio::test]
async fn managed_is_an_auth_policy_and_does_not_move_with_the_callback_base() {
    async fn managed_for(base: &str) -> bool {
        let app = app_with_callback_base(None, base).await;
        let v = body_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/v1/auth/oauth/providers")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("providers"),
        )
        .await;
        v.get("managed")
            .and_then(|x| x.as_bool())
            .expect("managed is stated")
    }

    let bare = managed_for("https://node.example").await;
    let prefixed = managed_for("https://gateway.example/api/scout").await;
    let loopback = managed_for("http://127.0.0.1:4243").await;
    let deep = managed_for("https://gateway.example/a/b/c").await;

    assert_eq!(
        [bare, prefixed, loopback, deep],
        [bare; 4],
        "managed moved with the callback base — it is a statement about who may \
         LOG IN, and a URL says nothing about that. (bare={bare}, \
         prefixed={prefixed}, loopback={loopback}, deep={deep})"
    );

    // And it is the SAME predicate the admission gate uses, so what a client is
    // told cannot drift from what the node does. Under the test harness no
    // managed indicator is present, so this is the personal-node answer.
    assert!(
        !bare,
        "a test process is not a managed deployment — if this flips, \
         `deployment::is_managed()` has started reading something the harness \
         happens to satisfy, and every client would be told a node admits \
         strangers when it refuses them"
    );
}

/// D3: a flow that asked for `redirect_uri=/dashboard` gets a 303 See Other to
/// it — and the session STILL travels only via the hand-off (no token in the
/// redirect).
#[tokio::test]
async fn a_callback_success_with_a_post_login_redirect_303s_to_it() {
    let app = app_with(None).await;
    let state = start_flow(&app, "?app_nonce=n-redir&redirect_uri=/dashboard").await;

    let r = app
        .clone()
        .oneshot(callback_req("ok-owner", &state, None))
        .await
        .expect("callback");
    assert_eq!(
        r.status(),
        StatusCode::SEE_OTHER,
        "the flow asked for a destination — 303, the redirect-after-completion shape"
    );
    let loc = r
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("location");
    // The DESTINATION is still the caller's, unchanged. What is appended is a
    // single-use redemption code (CIRISServer#439) — the page previously got
    // nothing at all and could not tell a successful sign-in from a refusal.
    assert!(
        loc.starts_with("/dashboard"),
        "the caller's own destination, not the node's: {loc}"
    );
    // THE PROPERTY THIS TEST WAS WRITTEN FOR, unchanged and now stated more
    // strongly. D3's "web token delivery is out of scope" has been answered —
    // but answered with a code, never with the bearer. A token in a URL lands
    // in history, `Referer`, and every proxy log on the path.
    for forbidden in ["sess:", "access_token", "token_type"] {
        assert!(
            !loc.contains(forbidden),
            "`{forbidden}` may never ride the redirect: {loc}"
        );
    }

    let h = app
        .clone()
        .oneshot(handoff_req("n-redir"))
        .await
        .expect("handoff poll");
    assert_eq!(h.status(), StatusCode::OK, "the session is still parked");
}

/// #424: a claimed node refusing an unknown browser identity answers with a
/// PAGE — reason_id in small print, the D2 remedy line, no JSON wall — and
/// with `{error, reason_id}` JSON when the caller explicitly asks.
#[tokio::test]
async fn a_callback_refusal_is_a_page_for_humans_and_json_on_request() {
    let app = app_with(None).await;

    // Browser leg.
    let state = start_flow(&app, "?app_nonce=n-html").await;
    let r = app
        .clone()
        .oneshot(callback_req("ok-unknown", &state, None))
        .await
        .expect("callback");
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(
        content_type(&r).starts_with("text/html"),
        "a human hit this refusal — it must be a page (#424)"
    );
    let page = body_text(r).await;
    assert!(
        page.contains("auth.oauth.no_local_identity"),
        "reason_id in small print, so a screenshot is diagnosable"
    );
    assert!(
        page.contains("Sign in with your local username and password."),
        "the D2 remedy line, exactly — no OAuth-linking suggestion (no client can complete one)"
    );

    // Programmatic leg: same refusal, explicit Accept → JSON.
    let state = start_flow(&app, "?app_nonce=n-json").await;
    let r = app
        .clone()
        .oneshot(callback_req("ok-unknown", &state, Some("application/json")))
        .await
        .expect("callback");
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(content_type(&r).starts_with("application/json"));
    let v = body_json(r).await;
    assert_eq!(
        v.get("reason_id").and_then(|x| x.as_str()),
        Some("auth.oauth.no_local_identity")
    );
}

/// #425: the hand-off's verdicts in sequence — pending (204) while the human
/// is at the provider, a one-time `"status":"failed"` once the exchange dies,
/// then 410 expired; and a nonce nothing ever knew is 410 immediately.
#[tokio::test]
async fn the_handoff_reports_pending_then_failure_then_expired() {
    let app = app_with(None).await;

    // Nothing anywhere → 410, not an eternal 204.
    let h = app
        .clone()
        .oneshot(handoff_req("n-never-issued"))
        .await
        .expect("poll");
    assert_eq!(
        h.status(),
        StatusCode::GONE,
        "a flow the node never heard of must not read as 'keep waiting'"
    );
    let v = body_json(h).await;
    assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("expired"));
    assert_eq!(
        v.get("reason_id").and_then(|x| x.as_str()),
        Some("auth.oauth.flow_expired")
    );

    // A started flow is PENDING while unconsumed.
    let state = start_flow(&app, "?app_nonce=n-seq").await;
    let h = app
        .clone()
        .oneshot(handoff_req("n-seq"))
        .await
        .expect("poll");
    assert_eq!(
        h.status(),
        StatusCode::NO_CONTENT,
        "human still at the provider ⇒ 204 keep-waiting"
    );

    // The exchange fails → the failure is parked, observable ONCE.
    let r = app
        .clone()
        .oneshot(callback_req("fail", &state, None))
        .await
        .expect("callback");
    assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
    assert!(
        content_type(&r).starts_with("text/html"),
        "the human's browser gets a page for the exchange failure too"
    );
    let page = body_text(r).await;
    assert!(
        !page.contains("502 from provider"),
        "the RAW upstream string must go to the LOG only — never into the page a human \
         screenshots and pastes"
    );

    let h = app
        .clone()
        .oneshot(handoff_req("n-seq"))
        .await
        .expect("poll");
    assert_eq!(h.status(), StatusCode::OK);
    let v = body_json(h).await;
    assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("failed"));
    assert_eq!(
        v.get("reason_id").and_then(|x| x.as_str()),
        Some("auth.oauth.exchange_failed")
    );

    // Collected once — after that the flow is gone.
    let h = app
        .clone()
        .oneshot(handoff_req("n-seq"))
        .await
        .expect("poll");
    assert_eq!(h.status(), StatusCode::GONE);
}

/// **THE RACE, held open** (#425): with the CSRF entry consumed and the
/// provider exchange still in flight, a poll must read PENDING — remove the
/// `begin_flight` insert in `oauth_callback` and this test fails with a 410
/// verdict on a flow that is about to succeed.
#[tokio::test]
async fn a_poll_during_the_provider_exchange_reads_pending_not_expired() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let app = app_with(Some((entered.clone(), release.clone()))).await;

    let state = start_flow(&app, "?app_nonce=n-race").await;
    let racing = tokio::spawn({
        let app = app.clone();
        let state = state.clone();
        async move {
            app.oneshot(callback_req("ok-owner", &state, None))
                .await
                .expect("callback")
        }
    });
    // The callback has consumed the state and is INSIDE the exchange.
    entered.notified().await;

    let h = app
        .clone()
        .oneshot(handoff_req("n-race"))
        .await
        .expect("poll");
    assert_eq!(
        h.status(),
        StatusCode::NO_CONTENT,
        "poll inside the consume→park window verdicted the flow expired — the in-flight \
         marker is missing, and a succeeding sign-in is being reported dead (the #425 race)"
    );

    release.notify_one();
    let r = racing.await.expect("callback task");
    assert_eq!(r.status(), StatusCode::OK);

    let h = app
        .clone()
        .oneshot(handoff_req("n-race"))
        .await
        .expect("poll");
    assert_eq!(h.status(), StatusCode::OK);
    let v = body_json(h).await;
    assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("complete"));
}

/// #424, the XSS pin at the HTTP surface: a hostile provider segment is
/// refused at the door and NEVER reflected — neither leg, neither format.
#[tokio::test]
async fn a_hostile_provider_segment_is_refused_and_never_reflected() {
    let app = app_with(None).await;
    for uri in [
        "/v1/auth/oauth/%3Cscript%3Ealert(1)%3C%2Fscript%3E/login",
        "/v1/auth/oauth/%3Cscript%3Ealert(1)%3C%2Fscript%3E/callback?code=x&state=y",
    ] {
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("call");
        assert_eq!(
            r.status(),
            StatusCode::NOT_FOUND,
            "a non-provider-shaped segment is refused at the door ({uri})"
        );
        let page = body_text(r).await;
        assert!(
            !page.contains("<script>alert"),
            "the hostile segment was REFLECTED unescaped ({uri}) — that is exactly the \
             reflected XSS the provider-name gate exists to prevent"
        );
    }
}
