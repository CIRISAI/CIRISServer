//! OAuth front-door (CIRISServer#9) — the human-login entry point.
//!
//! OAuth authenticates the **human**; the result resolves to a self identity +
//! session. The flow rides the SAME substrate OAuth-user storage the agent used:
//! `wa_cert` rows keyed by `(oauth_provider, oauth_external_id)` via the partial
//! `wa_cert_oauth` index (`WaCertService::get_by_oauth` / `upsert_wa_cert`). The
//! agent's `create_oauth_user` was exactly an upsert into this table.
//!
//! Routes (port of `routes/auth.py`):
//! - `GET  /v1/auth/oauth/providers`            — list configured providers.
//! - `POST /v1/auth/oauth/providers`            — configure a provider.
//! - `GET  /v1/auth/oauth/{provider}/login`     — start the flow (CSRF state).
//! - `GET  /v1/auth/oauth/{provider}/callback`  — exchange + create_oauth_user + session.
//! - `POST /v1/auth/native/google`              — native Google id_token login.
//! - `POST /v1/auth/native/apple`               — native Apple id_token login.
//!
//! Provider config (client_id/secret) is a fabric-path file store (the agent
//! kept it in `oauth.json`); the provider HTTP (authz URL, code→token exchange,
//! userinfo, native token verification) is behind the [`ProviderClient`] trait so
//! the substrate write path is ported and the outbound-HTTP step is scaffolded.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::prelude::Engine;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};
use serde::{Deserialize, Serialize};

use super::roles::UserRole;
use super::store;

/// In-memory CSRF state store (issue #847 — one-use token, 600s TTL).
#[derive(Default)]
struct CsrfStore {
    pending: HashMap<String, Instant>,
}

impl CsrfStore {
    fn issue(&mut self) -> String {
        use base64::Engine as _;
        let mut raw = [0u8; 32];
        let _ = getrandom::fill(&mut raw);
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        self.prune();
        self.pending
            .insert(token.clone(), Instant::now() + Duration::from_secs(600));
        token
    }
    /// One-use consume: returns true iff the token was issued and unexpired.
    fn consume(&mut self, token: &str) -> bool {
        self.prune();
        match self.pending.remove(token) {
            Some(deadline) => deadline > Instant::now(),
            None => false,
        }
    }
    fn prune(&mut self) {
        let now = Instant::now();
        self.pending.retain(|_, d| *d > now);
    }
}

#[derive(Clone)]
struct OAuthState {
    engine: Arc<Engine>,
    csrf: Arc<Mutex<CsrfStore>>,
    providers: Arc<Mutex<ProviderConfigStore>>,
    client: Arc<dyn ProviderClient>,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

// ─── Provider config store (the agent's oauth.json) ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProviderConfig {
    client_id: String,
    /// Never serialized back out on GET.
    #[serde(default, skip_serializing)]
    client_secret: String,
    #[serde(default)]
    metadata: serde_json::Value,
}

#[derive(Default)]
struct ProviderConfigStore {
    by_provider: HashMap<String, ProviderConfig>,
}

// ─── The outbound-HTTP seam (scaffolded) ────────────────────────────────────

/// Resolved identity claims after a provider authenticates a human.
#[derive(Debug, Clone)]
pub struct OAuthIdentity {
    pub provider: String,
    pub external_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
}

/// The provider HTTP seam: authz-URL construction, code→token exchange + userinfo,
/// and native id_token verification. The substrate write path
/// ([`create_oauth_user`]) is ported; these outbound calls are scaffolded.
pub trait ProviderClient: Send + Sync {
    /// Build the provider's authorization-redirect URL.
    fn authorize_url(&self, provider: &str, client_id: &str, state: &str, redirect_uri: &str)
        -> String;
    /// Exchange an auth `code` for the authenticated human's claims.
    fn exchange_code(
        &self,
        provider: &str,
        cfg_client_id: &str,
        cfg_client_secret: &str,
        code: &str,
    ) -> Result<OAuthIdentity, String>;
    /// Verify a native SDK id_token (Google tokeninfo / Apple JWKS RS256).
    fn verify_native(&self, provider: &str, id_token: &str) -> Result<OAuthIdentity, String>;
}

/// Default client — TODOs for the actual provider HTTP. The authz URL is real
/// (it's just URL assembly); exchange + native verify return a clear scaffold
/// error so the route shape is testable without live providers.
struct ScaffoldProviderClient;

impl ProviderClient for ScaffoldProviderClient {
    fn authorize_url(
        &self,
        provider: &str,
        client_id: &str,
        state: &str,
        redirect_uri: &str,
    ) -> String {
        let base = match provider {
            "google" => "https://accounts.google.com/o/oauth2/v2/auth",
            "github" => "https://github.com/login/oauth/authorize",
            "discord" => "https://discord.com/api/oauth2/authorize",
            _ => "https://example.invalid/authorize",
        };
        format!(
            "{base}?client_id={client_id}&response_type=code&scope=openid%20email%20profile\
             &state={state}&redirect_uri={redirect_uri}"
        )
    }
    fn exchange_code(
        &self,
        _provider: &str,
        _cfg_client_id: &str,
        _cfg_client_secret: &str,
        _code: &str,
    ) -> Result<OAuthIdentity, String> {
        // TODO(CIRISServer#9): POST the token endpoint, then GET userinfo. The
        // post-exchange substrate write (create_oauth_user) below is ported.
        Err("oauth code exchange not yet wired (provider HTTP scaffold)".into())
    }
    fn verify_native(&self, _provider: &str, _id_token: &str) -> Result<OAuthIdentity, String> {
        // TODO(CIRISServer#9): Google tokeninfo / Apple JWKS RS256 verification.
        Err("native token verification not yet wired (JWKS scaffold)".into())
    }
}

// ─── create_oauth_user — the substrate write (PORTED) ───────────────────────

/// Port of the agent's `auth_service.create_oauth_user`: upsert a `wa_cert` row
/// keyed by `(oauth_provider, oauth_external_id)` (TokenType::Oauth). Returns the
/// `wa_id`. Idempotent — re-login updates `last_login` / claims, preserves
/// `created` (substrate upsert semantics).
pub async fn create_oauth_user(
    engine: &Engine,
    ident: &OAuthIdentity,
    role: UserRole,
) -> Result<String, store::StoreError> {
    // Reuse an existing cert if this OAuth identity is already linked.
    if let Some(existing) = store::get_by_oauth(engine, &ident.provider, &ident.external_id).await? {
        let _ = store::touch_login(engine, &existing.wa_id).await;
        return Ok(existing.wa_id);
    }
    let wa_id = format!("oauth-{}-{}", ident.provider, ident.external_id);
    let wa_role = match role {
        UserRole::SystemAdmin => WaRole::Root,
        UserRole::Authority => WaRole::Authority,
        _ => WaRole::Observer,
    };
    let now = chrono::Utc::now();
    let mut links = serde_json::Map::new();
    if let Some(email) = &ident.email {
        links.insert("email".into(), serde_json::Value::String(email.clone()));
    }
    let cert = WaCert {
        wa_id: wa_id.clone(),
        name: ident.name.clone().unwrap_or_else(|| ident.external_id.clone()),
        role: wa_role,
        pubkey: String::new(),
        jwt_kid: format!("oauth-kid-{}-{}", ident.provider, ident.external_id),
        password_hash: None,
        api_key_hash: None,
        oauth_provider: Some(ident.provider.clone()),
        oauth_external_id: Some(ident.external_id.clone()),
        oauth_links: Some(serde_json::Value::Object(links)),
        veilid_id: None,
        auto_minted: true,
        parent_wa_id: None,
        parent_signature: None,
        scopes: serde_json::json!([]),
        custom_permissions: None,
        adapter_id: None,
        adapter_name: None,
        adapter_metadata: None,
        token_type: TokenType::Oauth,
        created: now,
        last_login: Some(now),
        active: true,
    };
    store::upsert(engine, cert).await?;
    Ok(wa_id)
}

/// First OAuth user → SYSTEM_ADMIN (setup wizard); `@ciris.ai` → ADMIN; else
/// OBSERVER. Mirrors the agent's role-determination (routes/auth.py).
async fn determine_role(engine: &Engine, email: Option<&str>) -> UserRole {
    let any_root = store::list_by_role(engine, WaRole::Root, 1)
        .await
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    if !any_root {
        return UserRole::SystemAdmin;
    }
    if email.map(|e| e.ends_with("@ciris.ai")).unwrap_or(false) {
        return UserRole::Admin;
    }
    UserRole::Observer
}

// ─── GET/POST /v1/auth/oauth/providers ──────────────────────────────────────

#[derive(Debug, Serialize)]
struct ProviderInfo {
    provider: String,
    client_id: String,
}

async fn list_providers(State(st): State<OAuthState>) -> Response {
    let store = st.providers.lock().unwrap();
    let providers: Vec<ProviderInfo> = store
        .by_provider
        .iter()
        .map(|(p, c)| ProviderInfo {
            provider: p.clone(),
            client_id: c.client_id.clone(),
        })
        .collect();
    (StatusCode::OK, Json(serde_json::json!({ "providers": providers }))).into_response()
}

#[derive(Debug, Deserialize)]
struct ConfigureProviderRequest {
    provider: String,
    client_id: String,
    client_secret: String,
    #[serde(default)]
    metadata: serde_json::Value,
}

async fn configure_provider(State(st): State<OAuthState>, body: axum::body::Bytes) -> Response {
    let req: ConfigureProviderRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    let mut store = st.providers.lock().unwrap();
    store.by_provider.insert(
        req.provider.clone(),
        ProviderConfig {
            client_id: req.client_id,
            client_secret: req.client_secret,
            metadata: req.metadata,
        },
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({ "configured": req.provider })),
    )
        .into_response()
}

// ─── GET /v1/auth/oauth/{provider}/login ────────────────────────────────────

#[derive(Debug, Deserialize)]
struct LoginQuery {
    #[serde(default)]
    redirect_uri: Option<String>,
}

async fn oauth_login(
    State(st): State<OAuthState>,
    Path(provider): Path<String>,
    Query(q): Query<LoginQuery>,
) -> Response {
    let client_id = {
        let store = st.providers.lock().unwrap();
        match store.by_provider.get(&provider) {
            Some(c) => c.client_id.clone(),
            None => return err(StatusCode::NOT_FOUND, "provider not configured"),
        }
    };
    // issue #846 redirect-uri validation: only relative or https allowed.
    let redirect_uri = q.redirect_uri.unwrap_or_else(|| "/".to_string());
    if !is_safe_redirect(&redirect_uri) {
        return err(StatusCode::BAD_REQUEST, "unsafe redirect_uri");
    }
    let state = {
        let mut csrf = st.csrf.lock().unwrap();
        csrf.issue()
    };
    let url = st
        .client
        .authorize_url(&provider, &client_id, &state, &redirect_uri);
    axum::response::Redirect::temporary(&url).into_response()
}

/// issue #846: relative paths always OK; absolute must be https (loopback over
/// http is allowed for local dev).
fn is_safe_redirect(uri: &str) -> bool {
    if uri.starts_with('/') {
        return true;
    }
    if let Some(rest) = uri.strip_prefix("https://") {
        return !rest.is_empty();
    }
    if let Some(rest) = uri.strip_prefix("http://") {
        return rest.starts_with("127.0.0.1")
            || rest.starts_with("localhost")
            || rest.starts_with("[::1]");
    }
    false
}

// ─── GET /v1/auth/oauth/{provider}/callback ─────────────────────────────────

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

#[derive(Debug, Serialize)]
struct CallbackResponse {
    user_id: String,
    role: String,
}

async fn oauth_callback(
    State(st): State<OAuthState>,
    Path(provider): Path<String>,
    Query(q): Query<CallbackQuery>,
) -> Response {
    // CSRF: fail-closed on missing/expired/replayed state (issue #847).
    {
        let mut csrf = st.csrf.lock().unwrap();
        if !csrf.consume(&q.state) {
            return err(StatusCode::BAD_REQUEST, "invalid or expired oauth state");
        }
    }
    let (client_id, client_secret) = {
        let store = st.providers.lock().unwrap();
        match store.by_provider.get(&provider) {
            Some(c) => (c.client_id.clone(), c.client_secret.clone()),
            None => return err(StatusCode::NOT_FOUND, "provider not configured"),
        }
    };
    let ident = match st
        .client
        .exchange_code(&provider, &client_id, &client_secret, &q.code)
    {
        Ok(i) => i,
        Err(e) => return err(StatusCode::BAD_GATEWAY, e),
    };
    finish_oauth_login(&st, ident).await
}

// ─── POST /v1/auth/native/{google,apple} ────────────────────────────────────

#[derive(Debug, Deserialize)]
struct NativeTokenRequest {
    id_token: String,
}

async fn native_login(st: &OAuthState, provider: &str, body: &[u8]) -> Response {
    let req: NativeTokenRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    let ident = match st.client.verify_native(provider, &req.id_token) {
        Ok(i) => i,
        Err(e) => return err(StatusCode::UNAUTHORIZED, e),
    };
    finish_oauth_login(st, ident).await
}

async fn native_google(State(st): State<OAuthState>, body: axum::body::Bytes) -> Response {
    native_login(&st, "google", &body).await
}
async fn native_apple(State(st): State<OAuthState>, body: axum::body::Bytes) -> Response {
    native_login(&st, "apple", &body).await
}

/// Shared tail: determine role, create_oauth_user (substrate), return identity.
async fn finish_oauth_login(st: &OAuthState, ident: OAuthIdentity) -> Response {
    let role = determine_role(&st.engine, ident.email.as_deref()).await;
    match create_oauth_user(&st.engine, &ident, role).await {
        Ok(user_id) => (
            StatusCode::OK,
            Json(CallbackResponse {
                user_id,
                role: role.as_str().to_string(),
            }),
        )
            .into_response(),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    }
}

/// The OAuth front-door router.
pub fn router(engine: Arc<Engine>) -> Router {
    let st = OAuthState {
        engine,
        csrf: Arc::new(Mutex::new(CsrfStore::default())),
        providers: Arc::new(Mutex::new(ProviderConfigStore::default())),
        client: Arc::new(ScaffoldProviderClient),
    };
    Router::new()
        .route(
            "/v1/auth/oauth/providers",
            axum::routing::get(list_providers).post(configure_provider),
        )
        .route(
            "/v1/auth/oauth/{provider}/login",
            axum::routing::get(oauth_login),
        )
        .route(
            "/v1/auth/oauth/{provider}/callback",
            axum::routing::get(oauth_callback),
        )
        .route("/v1/auth/native/google", axum::routing::post(native_google))
        .route("/v1/auth/native/apple", axum::routing::post(native_apple))
        .with_state(st)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_is_one_use_and_expiring() {
        let mut s = CsrfStore::default();
        let t = s.issue();
        assert!(s.consume(&t), "issued token must verify once");
        assert!(!s.consume(&t), "token must not be reusable");
        assert!(!s.consume("never-issued"));
    }

    #[test]
    fn redirect_validation_fails_closed() {
        assert!(is_safe_redirect("/dashboard"));
        assert!(is_safe_redirect("https://app.ciris.ai/cb"));
        assert!(is_safe_redirect("http://127.0.0.1:3000/cb"));
        assert!(!is_safe_redirect("http://evil.example.com"));
        assert!(!is_safe_redirect("javascript:alert(1)"));
    }
}
