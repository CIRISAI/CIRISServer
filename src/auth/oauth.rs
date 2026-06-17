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
    /// Base URL the OAuth callback is registered under (e.g.
    /// `https://app.ciris.ai`); the per-provider callback path is appended. The
    /// agent reads `OAUTH_CALLBACK_BASE_URL`.
    callback_base: String,
}

/// The per-provider OAuth callback URL (the agent's `get_oauth_callback_url`):
/// `{base}/v1/auth/oauth/{provider}/callback`. This MUST match the
/// `redirect_uri` the provider has registered and the one sent at authorize time.
fn oauth_callback_url(base: &str, provider: &str) -> String {
    format!(
        "{}/v1/auth/oauth/{provider}/callback",
        base.trim_end_matches('/')
    )
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
/// and native id_token verification. The default impl ([`HttpProviderClient`])
/// performs the real provider HTTP; the trait is kept so tests can substitute a
/// stub without live providers.
#[async_trait::async_trait]
pub trait ProviderClient: Send + Sync {
    /// Build the provider's authorization-redirect URL.
    fn authorize_url(
        &self,
        provider: &str,
        client_id: &str,
        state: &str,
        redirect_uri: &str,
    ) -> String;
    /// Exchange an auth `code` for the authenticated human's claims.
    async fn exchange_code(
        &self,
        provider: &str,
        cfg_client_id: &str,
        cfg_client_secret: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<OAuthIdentity, String>;
    /// Verify a native SDK id_token (Google tokeninfo / Apple JWKS RS256).
    async fn verify_native(
        &self,
        provider: &str,
        id_token: &str,
        allowed_audiences: &[String],
    ) -> Result<OAuthIdentity, String>;
}

/// The real provider HTTP client (CIRISServer#9, gaps #2/#3). Reproduces the
/// agent's `_handle_{google,github,discord}_oauth` code→token→userinfo flows and
/// the `_verify_{google,apple}_id_token` native paths over `reqwest` (rustls).
pub struct HttpProviderClient {
    http: reqwest::Client,
}

impl Default for HttpProviderClient {
    fn default() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("reqwest client"),
        }
    }
}

#[async_trait::async_trait]
impl ProviderClient for HttpProviderClient {
    /// Matches `routes/auth.py` `oauth_login`: the per-provider authorize base +
    /// query params (`urllib.parse.urlencode`). Google adds `access_type=offline`
    /// + `prompt=consent`; scopes are provider-specific.
    fn authorize_url(
        &self,
        provider: &str,
        client_id: &str,
        state: &str,
        redirect_uri: &str,
    ) -> String {
        let enc = |s: &str| urlencoding::encode(s).into_owned();
        match provider {
            "google" => format!(
                "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}\
                 &response_type=code&scope={}&state={}&access_type=offline&prompt=consent",
                enc(client_id),
                enc(redirect_uri),
                enc("openid email profile"),
                enc(state),
            ),
            "github" => format!(
                "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}\
                 &scope={}&state={}",
                enc(client_id),
                enc(redirect_uri),
                enc("read:user user:email"),
                enc(state),
            ),
            "discord" => format!(
                "https://discord.com/api/oauth2/authorize?client_id={}&redirect_uri={}\
                 &response_type=code&scope={}&state={}",
                enc(client_id),
                enc(redirect_uri),
                enc("identify email"),
                enc(state),
            ),
            _ => format!("https://example.invalid/authorize?state={}", enc(state)),
        }
    }

    async fn exchange_code(
        &self,
        provider: &str,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<OAuthIdentity, String> {
        match provider {
            "google" => {
                self.exchange_google(client_id, client_secret, code, redirect_uri)
                    .await
            }
            "github" => {
                self.exchange_github(client_id, client_secret, code, redirect_uri)
                    .await
            }
            "discord" => {
                self.exchange_discord(client_id, client_secret, code, redirect_uri)
                    .await
            }
            other => Err(format!("unsupported OAuth provider: {other}")),
        }
    }

    async fn verify_native(
        &self,
        provider: &str,
        id_token: &str,
        allowed_audiences: &[String],
    ) -> Result<OAuthIdentity, String> {
        match provider {
            "google" => self.verify_google_native(id_token, allowed_audiences).await,
            "apple" => self.verify_apple_native(id_token, allowed_audiences).await,
            other => Err(format!("unsupported native provider: {other}")),
        }
    }
}

// Valid issuers / endpoints — pinned to match the agent (routes/auth.py).
const VALID_GOOGLE_ISSUERS: [&str; 2] = ["accounts.google.com", "https://accounts.google.com"];
const VALID_APPLE_ISSUER: &str = "https://appleid.apple.com";
const APPLE_JWKS_URL: &str = "https://appleid.apple.com/auth/keys";

impl HttpProviderClient {
    async fn exchange_google(
        &self,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<OAuthIdentity, String> {
        // POST https://oauth2.googleapis.com/token (form), then GET userinfo.
        let token: serde_json::Value = self
            .http
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("code", code),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| format!("google token endpoint: {e}"))?
            .error_for_status()
            .map_err(|e| format!("google token endpoint: {e}"))?
            .json()
            .await
            .map_err(|e| format!("google token decode: {e}"))?;
        let access_token = token
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or("google token response missing access_token")?;
        let info: serde_json::Value = self
            .http
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| format!("google userinfo: {e}"))?
            .error_for_status()
            .map_err(|e| format!("google userinfo: {e}"))?
            .json()
            .await
            .map_err(|e| format!("google userinfo decode: {e}"))?;
        let external_id = info
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("google userinfo missing id")?
            .to_string();
        let email = info
            .get("email")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let name = info
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| email.clone());
        Ok(OAuthIdentity {
            provider: "google".into(),
            external_id,
            email,
            name,
        })
    }

    async fn exchange_github(
        &self,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<OAuthIdentity, String> {
        let token: serde_json::Value = self
            .http
            .post("https://github.com/login/oauth/access_token")
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("code", code),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("redirect_uri", redirect_uri),
            ])
            .send()
            .await
            .map_err(|e| format!("github token endpoint: {e}"))?
            .error_for_status()
            .map_err(|e| format!("github token endpoint: {e}"))?
            .json()
            .await
            .map_err(|e| format!("github token decode: {e}"))?;
        let access_token = token
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or("github token response missing access_token")?;
        let info: serde_json::Value = self
            .http
            .get("https://api.github.com/user")
            .header(reqwest::header::USER_AGENT, "ciris-server")
            .header(
                reqwest::header::AUTHORIZATION,
                format!("token {access_token}"),
            )
            .send()
            .await
            .map_err(|e| format!("github user: {e}"))?
            .error_for_status()
            .map_err(|e| format!("github user: {e}"))?
            .json()
            .await
            .map_err(|e| format!("github user decode: {e}"))?;
        let external_id = info
            .get("id")
            .map(|v| v.to_string())
            .ok_or("github user missing id")?;
        let mut email = info
            .get("email")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let name = info
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| {
                info.get("login")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
            });
        // Private email ⇒ fetch the primary from /user/emails (agent parity).
        if email.is_none() {
            if let Ok(resp) = self
                .http
                .get("https://api.github.com/user/emails")
                .header(reqwest::header::USER_AGENT, "ciris-server")
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("token {access_token}"),
                )
                .send()
                .await
            {
                if let Ok(emails) = resp.json::<Vec<serde_json::Value>>().await {
                    email = emails
                        .iter()
                        .find(|e| e.get("primary").and_then(|p| p.as_bool()) == Some(true))
                        .and_then(|e| e.get("email").and_then(|v| v.as_str()).map(str::to_owned));
                }
            }
        }
        Ok(OAuthIdentity {
            provider: "github".into(),
            external_id,
            email,
            name,
        })
    }

    async fn exchange_discord(
        &self,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<OAuthIdentity, String> {
        let token: serde_json::Value = self
            .http
            .post("https://discord.com/api/oauth2/token")
            .form(&[
                ("code", code),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| format!("discord token endpoint: {e}"))?
            .error_for_status()
            .map_err(|e| format!("discord token endpoint: {e}"))?
            .json()
            .await
            .map_err(|e| format!("discord token decode: {e}"))?;
        let access_token = token
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or("discord token response missing access_token")?;
        let info: serde_json::Value = self
            .http
            .get("https://discord.com/api/users/@me")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| format!("discord user: {e}"))?
            .error_for_status()
            .map_err(|e| format!("discord user: {e}"))?
            .json()
            .await
            .map_err(|e| format!("discord user decode: {e}"))?;
        let external_id = info
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("discord user missing id")?
            .to_string();
        let email = info
            .get("email")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let name = info
            .get("username")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| email.clone());
        Ok(OAuthIdentity {
            provider: "discord".into(),
            external_id,
            email,
            name,
        })
    }

    /// Google native id_token verify — `_verify_google_id_token`: GET
    /// `oauth2.googleapis.com/tokeninfo?id_token=…`, then validate aud (if any
    /// configured audiences), iss ∈ google issuers, exp, and require `sub`.
    async fn verify_google_native(
        &self,
        id_token: &str,
        allowed_audiences: &[String],
    ) -> Result<OAuthIdentity, String> {
        let info: serde_json::Value = self
            .http
            .get("https://oauth2.googleapis.com/tokeninfo")
            .query(&[("id_token", id_token)])
            .send()
            .await
            .map_err(|e| format!("google tokeninfo: {e}"))?
            .error_for_status()
            .map_err(|_| "Google could not verify this ID token.".to_string())?
            .json()
            .await
            .map_err(|e| format!("google tokeninfo decode: {e}"))?;

        // aud — skipped when no audiences configured (the agent's on-device mode).
        if !allowed_audiences.is_empty() {
            let aud = info.get("aud").and_then(|v| v.as_str()).unwrap_or("");
            if !allowed_audiences.iter().any(|a| a == aud) {
                return Err(
                    "Token was not issued for this application (audience mismatch).".into(),
                );
            }
        }
        // iss
        let iss = info.get("iss").and_then(|v| v.as_str()).unwrap_or("");
        if !VALID_GOOGLE_ISSUERS.contains(&iss) {
            return Err("Token was not issued by Google (issuer mismatch).".into());
        }
        // exp (string seconds in tokeninfo)
        if let Some(exp) = info.get("exp").and_then(|v| v.as_str()) {
            if let Ok(exp_ts) = exp.parse::<i64>() {
                if exp_ts < chrono::Utc::now().timestamp() {
                    return Err("Google ID token has expired.".into());
                }
            }
        }
        let sub = info
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or("Google ID token missing user ID (sub claim).")?
            .to_string();
        Ok(OAuthIdentity {
            provider: "google".into(),
            external_id: sub,
            email: info
                .get("email")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            name: info.get("name").and_then(|v| v.as_str()).map(str::to_owned),
        })
    }

    /// Apple native id_token verify — `_verify_apple_id_token`: fetch Apple JWKS,
    /// select the RS256 key by the token's `kid`, then RS256-verify with
    /// aud ∈ configured audiences, iss = appleid.apple.com, require sub/aud/iss/exp.
    async fn verify_apple_native(
        &self,
        id_token: &str,
        allowed_audiences: &[String],
    ) -> Result<OAuthIdentity, String> {
        use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

        if allowed_audiences.is_empty() {
            return Err("Apple native auth is not configured for this application.".into());
        }
        let header =
            decode_header(id_token).map_err(|_| "Apple could not verify this ID token.")?;
        if header.alg != Algorithm::RS256 {
            return Err("Apple could not verify this ID token.".into());
        }
        let kid = header.kid.ok_or("Apple could not verify this ID token.")?;

        let jwks: serde_json::Value = self
            .http
            .get(APPLE_JWKS_URL)
            .send()
            .await
            .map_err(|e| format!("apple jwks: {e}"))?
            .error_for_status()
            .map_err(|_| "Apple verification service unavailable. Please try again.".to_string())?
            .json()
            .await
            .map_err(|e| format!("apple jwks decode: {e}"))?;
        let key = jwks
            .get("keys")
            .and_then(|k| k.as_array())
            .and_then(|keys| {
                keys.iter().find(|j| {
                    j.get("kid").and_then(|v| v.as_str()) == Some(kid.as_str())
                        && j.get("kty").and_then(|v| v.as_str()) == Some("RSA")
                })
            })
            .ok_or("Apple could not verify this ID token.")?;
        let n = key
            .get("n")
            .and_then(|v| v.as_str())
            .ok_or("apple jwk missing n")?;
        let e = key
            .get("e")
            .and_then(|v| v.as_str())
            .ok_or("apple jwk missing e")?;
        let decoding_key =
            DecodingKey::from_rsa_components(n, e).map_err(|_| "apple jwk invalid")?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(allowed_audiences);
        validation.set_issuer(&[VALID_APPLE_ISSUER]);
        validation.set_required_spec_claims(&["sub", "aud", "iss", "exp"]);

        let claims: serde_json::Value =
            decode::<serde_json::Value>(id_token, &decoding_key, &validation)
                .map_err(|e| match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        "Apple ID token has expired.".to_string()
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                        "Token was not issued for this application (audience mismatch).".to_string()
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                        "Token was not issued by Apple (issuer mismatch).".to_string()
                    }
                    _ => "Apple could not verify this ID token.".to_string(),
                })?
                .claims;

        let sub = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or("Apple ID token missing user ID (sub claim).")?
            .to_string();
        Ok(OAuthIdentity {
            provider: "apple".into(),
            external_id: sub,
            email: claims
                .get("email")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            name: claims
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
        })
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
    if let Some(existing) = store::get_by_oauth(engine, &ident.provider, &ident.external_id).await?
    {
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
        name: ident
            .name
            .clone()
            .unwrap_or_else(|| ident.external_id.clone()),
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
    (
        StatusCode::OK,
        Json(serde_json::json!({ "providers": providers })),
    )
        .into_response()
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
    // The provider redirect_uri is ALWAYS our registered callback (not the
    // app-supplied post-login `redirect_uri`, which is validated above and would
    // be carried separately in real deployments). This matches the agent, which
    // always sends `get_oauth_callback_url(provider)` to the provider.
    let _ = redirect_uri;
    let callback = oauth_callback_url(&st.callback_base, &provider);
    let url = st
        .client
        .authorize_url(&provider, &client_id, &state, &callback);
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
    let redirect_uri = oauth_callback_url(&st.callback_base, &provider);
    let ident = match st
        .client
        .exchange_code(
            &provider,
            &client_id,
            &client_secret,
            &q.code,
            &redirect_uri,
        )
        .await
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

/// Gather the allowed native audiences for `provider` from its stored config —
/// matching the agent's `_get_allowed_audiences_from_config` (google reads
/// `client_id`+`android_client_id`) and `_get_allowed_apple_audiences_from_config`
/// (apple reads `client_id`/`ios_client_id`/`native_client_id`/`bundle_id`).
fn native_audiences(store: &ProviderConfigStore, provider: &str) -> Vec<String> {
    let Some(cfg) = store.by_provider.get(provider) else {
        return Vec::new();
    };
    let mut auds = Vec::new();
    if !cfg.client_id.is_empty() {
        auds.push(cfg.client_id.clone());
    }
    let fields: &[&str] = match provider {
        "google" => &["android_client_id"],
        "apple" => &["ios_client_id", "native_client_id", "bundle_id"],
        _ => &[],
    };
    for f in fields {
        if let Some(v) = cfg.metadata.get(*f).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                auds.push(v.to_string());
            }
        }
    }
    auds
}

async fn native_login(st: &OAuthState, provider: &str, body: &[u8]) -> Response {
    let req: NativeTokenRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    let audiences = {
        let store = st.providers.lock().unwrap();
        native_audiences(&store, provider)
    };
    let ident = match st
        .client
        .verify_native(provider, &req.id_token, &audiences)
        .await
    {
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
        Ok(user_id) => {
            // Auto-mint ROOT for a SYSTEM_ADMIN OAuth user (CIRISServer#19, port of
            // `_auto_mint_system_admin_if_needed`): the first OAuth user (setup
            // wizard) is determined SYSTEM_ADMIN, so the founder's OAuth identity is
            // elevated to WaRole::Root → UserRole::SystemAdmin, reaching the
            // owner-gated POST /v1/federation/peering. The user_id (the bound
            // wa_cert) IS the identity bound; mint is idempotent. Non-admin OAuth
            // logins are a no-op; a store failure is logged, never fatal to login.
            if role == UserRole::SystemAdmin {
                if let Err(e) =
                    super::bootstrap::auto_mint_root_if_needed(&st.engine, &user_id, true).await
                {
                    tracing::warn!(error = %e, user_id = %user_id, "auto-mint ROOT on OAuth login failed (founder can claim manually)");
                }
            }
            (
                StatusCode::OK,
                Json(CallbackResponse {
                    user_id,
                    role: role.as_str().to_string(),
                }),
            )
                .into_response()
        }
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    }
}

/// The OAuth front-door router.
pub fn router(engine: Arc<Engine>) -> Router {
    let callback_base = std::env::var("OAUTH_CALLBACK_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:8080".to_string());
    let st = OAuthState {
        engine,
        csrf: Arc::new(Mutex::new(CsrfStore::default())),
        providers: Arc::new(Mutex::new(ProviderConfigStore::default())),
        client: Arc::new(HttpProviderClient::default()),
        callback_base,
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
    fn authorize_url_matches_agent_params() {
        let c = HttpProviderClient::default();
        let u = c.authorize_url(
            "google",
            "cid",
            "st8",
            "https://app.ciris.ai/v1/auth/oauth/google/callback",
        );
        assert!(u.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(u.contains("client_id=cid"));
        assert!(u.contains("response_type=code"));
        assert!(u.contains("scope=openid%20email%20profile"));
        assert!(u.contains("state=st8"));
        assert!(u.contains("access_type=offline"));
        assert!(u.contains("prompt=consent"));
        assert!(u.contains("redirect_uri=https%3A%2F%2Fapp.ciris.ai"));
        // github uses its own scope set.
        let g = c.authorize_url("github", "cid", "st8", "https://x/cb");
        assert!(g.starts_with("https://github.com/login/oauth/authorize?"));
        assert!(g.contains("scope=read%3Auser%20user%3Aemail"));
    }

    #[test]
    fn callback_url_is_per_provider() {
        assert_eq!(
            oauth_callback_url("https://app.ciris.ai/", "google"),
            "https://app.ciris.ai/v1/auth/oauth/google/callback"
        );
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
