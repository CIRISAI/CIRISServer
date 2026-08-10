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

/// One pending authorization: its expiry and its PKCE verifier.
struct Pending {
    deadline: Instant,
    /// RFC 7636 `code_verifier` — held server-side, never sent to the browser,
    /// and presented only at token exchange.
    code_verifier: String,
}

/// In-memory CSRF + PKCE state store (issue #847 — one-use token, 600s TTL).
///
/// # Why the verifier lives here (CIRISServer#384 follow-up)
///
/// The desktop build ships a Google **installed-app** client, whose secret is not
/// confidential — Google documents it as shipped in the binary, and RFC 8252
/// treats native apps as public clients. That is fine, but ONLY because PKCE, not
/// the secret, is what binds the authorization code to the client that requested
/// it.
///
/// Without PKCE, a loopback redirect is interceptable by any local process that
/// races the callback: it captures the `code` and exchanges it using the secret we
/// shipped. The secret being public is the premise, not the flaw — the flaw would
/// be relying on it. So the verifier is generated per authorization, bound to the
/// same one-use CSRF token, kept server-side, and required at exchange.
#[derive(Default)]
struct CsrfStore {
    pending: HashMap<String, Pending>,
}

impl CsrfStore {
    /// Issue a one-use state token and its PKCE verifier.
    /// Returns `(state, code_challenge)` — the challenge goes in the authorize
    /// URL; the verifier stays here.
    fn issue(&mut self) -> (String, String) {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        const B64: base64::engine::general_purpose::GeneralPurpose =
            base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let mut raw = [0u8; 32];
        ciris_crypto::random::fill(&mut raw).expect("CSPRNG for OAuth CSRF token");
        let token = B64.encode(raw);

        // RFC 7636 §4.1 — 43..128 chars of unreserved ASCII. 32 random bytes
        // base64url-encodes to 43, the minimum, and is the recommended shape.
        let mut vraw = [0u8; 32];
        ciris_crypto::random::fill(&mut vraw).expect("CSPRNG for PKCE verifier");
        let code_verifier = B64.encode(vraw);
        // S256 only. `plain` is permitted by RFC 7636 but offers nothing here —
        // it would put the verifier in the authorize URL, which is the exact
        // exposure PKCE exists to remove.
        let code_challenge = B64.encode(Sha256::digest(code_verifier.as_bytes()));

        self.prune();
        self.pending.insert(
            token.clone(),
            Pending {
                deadline: Instant::now() + Duration::from_secs(600),
                code_verifier,
            },
        );
        (token, code_challenge)
    }

    /// One-use consume: returns the PKCE verifier iff the token was issued and
    /// unexpired. `None` means the exchange must be refused — a missing verifier
    /// and a wrong one are the same answer here, deliberately.
    fn consume(&mut self, token: &str) -> Option<String> {
        self.prune();
        let p = self.pending.remove(token)?;
        (p.deadline > Instant::now()).then_some(p.code_verifier)
    }

    fn prune(&mut self) {
        let now = Instant::now();
        self.pending.retain(|_, p| p.deadline > now);
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

/// **The CIRIS Google DESKTOP-app OAuth client, shipped in the wheel.**
///
/// # Why a secret is in committed source, and why this one only
///
/// RFC 8252 §8.5: a natively-installed app is a PUBLIC client — it cannot keep a
/// secret, because the secret ships wherever the binary ships. Google issues one
/// for the *Desktop app* client type anyway and documents it as not confidential
/// ("in this context, the client secret is obviously not treated as a secret"),
/// because it authenticates nothing on its own. What actually binds an
/// authorization code to THIS client is PKCE (RFC 7636): the verifier is
/// generated per-flow, never leaves the node, and the exchange fails without it.
/// Every authorize URL this module builds carries `code_challenge` +
/// `code_challenge_method=S256`, and every exchange sends `code_verifier`.
///
/// **The distinction that matters:** the CIRIS *Web application* client
/// (`…-l421…`, rendered into the lens/billing hosts by ansible) has a genuinely
/// confidential secret and MUST NOT be embedded — a web client's secret is a
/// bearer credential for the client itself. This is the DESKTOP client, minted
/// separately for exactly this purpose. If you ever find yourself reaching for
/// the web pair to make a build work, that is the bug this comment exists to
/// prevent.
///
/// Redirect: Google allows loopback redirects for desktop clients without
/// registering each port, which is what lets this reach the local node on
/// `http://127.0.0.1:4243/v1/auth/oauth/google/callback` (see
/// [`oauth_callback_url`]).
const BUILTIN_GOOGLE_DESKTOP_CLIENT_ID: &str =
    option_env!("CIRIS_DESKTOP_GOOGLE_OAUTH_CLIENT_ID").unwrap_or("");
/// See [`BUILTIN_GOOGLE_DESKTOP_CLIENT_ID`] — public by design for a native app.
const BUILTIN_GOOGLE_DESKTOP_CLIENT_SECRET: &str = option_env!("CIRIS_DESKTOP_GOOGLE_OAUTH_CLIENT_SECRET").unwrap_or("");
/// The Android client (same project). Present so `native_audiences` accepts a
/// phone's id_token — client IDs are public identifiers, never credentials.
const BUILTIN_GOOGLE_ANDROID_CLIENT_ID: &str =
    option_env!("CIRIS_ANDROID_GOOGLE_OAUTH_CLIENT_ID").unwrap_or("");
/// The Web client ID — the AUDIENCE Android's `requestIdToken` stamps. Its
/// SECRET is confidential and lives only on the lens/billing hosts; only the
/// public identifier appears here.
const BUILTIN_GOOGLE_WEB_CLIENT_ID: &str =
    option_env!("CIRIS_WEB_GOOGLE_OAUTH_CLIENT_ID").unwrap_or("");

struct ProviderConfigStore {
    by_provider: HashMap<String, ProviderConfig>,
}

impl Default for ProviderConfigStore {
    /// Google is configured OUT OF THE BOX.
    ///
    /// The store used to start empty, so a freshly-installed desktop node served
    /// `/v1/auth/oauth/google/login` with no client and the only way to sign in
    /// was for the operator to POST their own credentials to
    /// `/v1/auth/oauth/providers` first — which nothing told them to do. Sign-in
    /// is a first-run step, so requiring configuration BEFORE first run made the
    /// documented path unreachable.
    ///
    /// `configure_provider` still overwrites this: an operator with their own
    /// Google client (or a fork) POSTs it and their value wins. This is a
    /// DEFAULT, not a lock.
    fn default() -> Self {
        let mut by_provider = HashMap::new();
        by_provider.insert(
            "google".to_string(),
            ProviderConfig {
                client_id: BUILTIN_GOOGLE_DESKTOP_CLIENT_ID.to_string(),
                client_secret: BUILTIN_GOOGLE_DESKTOP_CLIENT_SECRET.to_string(),
                metadata: serde_json::json!({
                    "builtin": true,
                    "client_type": "desktop",
                    "android_client_id": BUILTIN_GOOGLE_ANDROID_CLIENT_ID,
                    "web_client_id": BUILTIN_GOOGLE_WEB_CLIENT_ID,
                }),
            },
        );
        Self { by_provider }
    }
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
        code_challenge: &str,
    ) -> String;
    /// Exchange an auth `code` for the authenticated human's claims.
    async fn exchange_code(
        &self,
        provider: &str,
        cfg_client_id: &str,
        cfg_client_secret: &str,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
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
        code_challenge: &str,
    ) -> String {
        let enc = |s: &str| urlencoding::encode(s).into_owned();
        // RFC 7636 — every provider below advertises S256. The challenge is public
        // by design; the verifier it commits to never leaves this process.
        let pkce = format!(
            "&code_challenge={}&code_challenge_method=S256",
            enc(code_challenge)
        );
        match provider {
            "google" => format!(
                "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}\
                 &response_type=code&scope={}&state={}&access_type=offline&prompt=consent{}",
                enc(client_id),
                enc(redirect_uri),
                enc("openid email profile"),
                enc(state),
                pkce,
            ),
            // Apple: `response_mode=form_post` is REQUIRED whenever a scope is
            // requested — Apple POSTs the callback rather than redirecting, and
            // omitting it makes Apple drop the scope silently rather than error.
            // Note the exchange for Apple needs an ES256 client-secret JWT, not a
            // static string: see `exchange_code`.
            "apple" => format!(
                "https://appleid.apple.com/auth/authorize?client_id={}&redirect_uri={}\
                 &response_type=code&scope={}&response_mode=form_post&state={}{}",
                enc(client_id),
                enc(redirect_uri),
                enc("name email"),
                enc(state),
                pkce,
            ),
            "github" => format!(
                "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}\
                 &scope={}&state={}{}",
                enc(client_id),
                enc(redirect_uri),
                enc("read:user user:email"),
                enc(state),
                pkce,
            ),
            "discord" => format!(
                "https://discord.com/api/oauth2/authorize?client_id={}&redirect_uri={}\
                 &response_type=code&scope={}&state={}{}",
                enc(client_id),
                enc(redirect_uri),
                enc("identify email"),
                enc(state),
                pkce,
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
        code_verifier: &str,
    ) -> Result<OAuthIdentity, String> {
        match provider {
            "google" => {
                self.exchange_google(client_id, client_secret, code, redirect_uri, code_verifier)
                    .await
            }
            "github" => {
                self.exchange_github(client_id, client_secret, code, redirect_uri, code_verifier)
                    .await
            }
            "discord" => {
                self.exchange_discord(client_id, client_secret, code, redirect_uri, code_verifier)
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
        code_verifier: &str,
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
                // RFC 7636 §4.5 — proves this client requested the code.
                ("code_verifier", code_verifier),
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
        code_verifier: &str,
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
                // GitHub omits `grant_type`, so this body did not match the
                // shared anchor the other providers did — it needs the verifier
                // stated explicitly or PKCE is silently absent on this leg.
                ("code_verifier", code_verifier),
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
        code_verifier: &str,
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
                // RFC 7636 §4.5 — proves this client requested the code.
                ("code_verifier", code_verifier),
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

        // aud — FAIL CLOSED. "No audiences configured" is not "any audience is
        // acceptable": skipping the check accepts an id_token minted for SOMEONE
        // ELSE'S Google client, which is the confused-deputy this claim exists to
        // stop. The owner signs into an unrelated site, that site receives a token
        // carrying the owner's `sub`, and replaying it here used to authenticate
        // as the owner — now that a claim binds ROOT to `(google, sub)`
        // (CIRISServer#384) that is the SYSTEM_ADMIN session.
        //
        // The two providers disagreed about what an empty list MEANT — Apple
        // below refuses, Google skipped — which is the distinct-zeroes bug:
        // "nothing configured" read as "nothing to enforce". They now agree.
        if allowed_audiences.is_empty() {
            return Err("Google native auth is not configured for this application.".into());
        }
        let aud = info.get("aud").and_then(|v| v.as_str()).unwrap_or("");
        if !allowed_audiences.iter().any(|a| a == aud) {
            return Err("Token was not issued for this application (audience mismatch).".into());
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
    // The verifier stays in the store; only its S256 challenge goes to the browser.
    let (state, code_challenge) = {
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
        .authorize_url(&provider, &client_id, &state, &callback, &code_challenge);
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
    // One-use: consuming the state YIELDS the PKCE verifier. A replayed or
    // expired state and a missing verifier are the same refusal — there is no
    // path that exchanges a code without the secret that committed to it.
    let code_verifier = {
        let mut csrf = st.csrf.lock().unwrap();
        match csrf.consume(&q.state) {
            Some(v) => v,
            None => return err(StatusCode::BAD_REQUEST, "invalid or expired oauth state"),
        }
    };
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
            &code_verifier,
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
        // `web_client_id` is NOT redundant with the desktop `client_id`: Android's
        // GoogleSignIn `requestIdToken(WEB_CLIENT_ID)` mints a token whose `aud`
        // is the WEB client, not the Android one — so a node that accepted only
        // its own client_id would reject every phone. Three surfaces, three
        // audiences, one identity.
        "google" => &["android_client_id", "web_client_id"],
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

/// The default OAuth callback base URL when `auth.oauth_callback_base_url` is
/// unset (an empty config:* value). Was the `OAUTH_CALLBACK_BASE_URL` env fallback.
/// **The NODE's own loopback read-API base — the port this router is mounted on.**
///
/// This used to default to `http://localhost:8080`, the Python brain's port. But
/// `oauth::router` is merged into the node read API (`:4243`, beside
/// `auth::session` and `auth::api_keys`), so the default named a service that
/// does not serve this callback — and on a NODE build (`HAS_AGENT == false`)
/// there is no `:8080` at all. Google would redirect the browser to a dead port
/// after a correct sign-in, and the failure surfaces as a browser error page
/// rather than as anything this node ever logs.
///
/// One name, two axes again: "where the app lives" and "where THIS router
/// answers" are not the same question, and only the second one is a callback
/// base. Deployments that DO front OAuth from the brain or a public host still
/// set `auth.oauth_callback_base_url` explicitly; this is only the fallback, and
/// the fallback should name the port that actually answers.
pub const DEFAULT_OAUTH_CALLBACK_BASE_URL: &str = "http://127.0.0.1:4243";

/// The OAuth front-door router.
///
/// `callback_base` is the boot-resolved `auth.oauth_callback_base_url` config:*
/// value (Server 0.5 — replaces the `OAUTH_CALLBACK_BASE_URL` env); an empty value
/// falls back to [`DEFAULT_OAUTH_CALLBACK_BASE_URL`].
pub fn router(engine: Arc<Engine>, callback_base: String) -> Router {
    let callback_base = if callback_base.trim().is_empty() {
        DEFAULT_OAUTH_CALLBACK_BASE_URL.to_string()
    } else {
        callback_base
    };
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
        let (t, _challenge) = s.issue();
        assert!(s.consume(&t).is_some(), "issued token must verify once");
        assert!(s.consume(&t).is_none(), "token must not be reusable");
        assert!(s.consume("never-issued").is_none());
    }

    /// The challenge published to the browser is the S256 hash of a verifier that
    /// never leaves this process, and consuming the state yields THAT verifier.
    ///
    /// Both halves matter. If the challenge were not the hash, the provider would
    /// reject every exchange; if consume returned a different verifier, PKCE would
    /// be theatre — present in the URL, unenforced at the token endpoint.
    #[test]
    fn pkce_challenge_is_s256_of_the_retained_verifier() {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let mut s = CsrfStore::default();
        let (state, challenge) = s.issue();
        let verifier = s.consume(&state).expect("verifier on first consume");

        // RFC 7636 §4.1 — 43..128 unreserved chars.
        assert!(
            (43..=128).contains(&verifier.len()),
            "verifier length {} is outside RFC 7636 bounds",
            verifier.len()
        );
        let expect = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, expect, "challenge must be S256(verifier)");
        assert_ne!(
            challenge, verifier,
            "challenge must not BE the verifier (plain)"
        );
    }

    /// Every provider that exchanges an authorization code sends `code_verifier`.
    ///
    /// This exists because of how it was nearly missed. The verifier was added to
    /// the token bodies with one replace anchored on `grant_type` — which GitHub
    /// does not send. The build stayed green, the URL still advertised S256, and
    /// PKCE was silently absent on exactly one provider. A per-leg property is
    /// exactly the kind that a shared-shape edit skips.
    #[test]
    fn every_code_exchange_sends_the_verifier() {
        let src = include_str!("oauth.rs");
        let mut missing = Vec::new();
        let mut checked = 0usize;
        for prov in ["google", "github", "discord"] {
            let Some(start) = src.find(&format!("async fn exchange_{prov}")) else {
                missing.push(format!("{prov} (no exchange fn)"));
                continue;
            };
            let body = &src[start..];
            let end = body.find("\n    async fn ").unwrap_or(body.len());
            checked += 1;
            if !body[..end].contains("(\"code_verifier\", code_verifier)") {
                missing.push(prov.to_string());
            }
        }
        assert_eq!(checked, 3, "all three code-exchange legs must be examined");
        assert!(
            missing.is_empty(),
            "provider exchange(s) {missing:?} do not send code_verifier — PKCE would be \
             advertised in the authorize URL and unenforced at the token endpoint"
        );
    }

    #[test]
    fn authorize_url_matches_agent_params() {
        let c = HttpProviderClient::default();
        let u = c.authorize_url(
            "google",
            "cid",
            "st8",
            "https://app.ciris.ai/v1/auth/oauth/google/callback",
            "chal",
        );
        assert!(u.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        // PKCE must reach the provider, or the exchange's verifier proves nothing.
        assert!(u.contains("code_challenge=chal"));
        assert!(u.contains("code_challenge_method=S256"));
        assert!(u.contains("client_id=cid"));
        assert!(u.contains("response_type=code"));
        assert!(u.contains("scope=openid%20email%20profile"));
        assert!(u.contains("state=st8"));
        assert!(u.contains("access_type=offline"));
        assert!(u.contains("prompt=consent"));
        assert!(u.contains("redirect_uri=https%3A%2F%2Fapp.ciris.ai"));
        // github uses its own scope set.
        let g = c.authorize_url("github", "cid", "st8", "https://x/cb", "chal");
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

    /// Google is usable the moment the node boots — no operator step first.
    ///
    /// The store shipped EMPTY, so a fresh desktop install served
    /// `/v1/auth/oauth/google/login` with no client and sign-in was impossible
    /// until someone POSTed credentials to `/v1/auth/oauth/providers`. Sign-in is
    /// a FIRST-RUN step, so "configure it before first run" was unreachable.
    #[test]
    fn google_is_configured_out_of_the_box() {
        let store = ProviderConfigStore::default();
        let cfg = store
            .by_provider
            .get("google")
            .expect("google configured at boot");
        assert!(cfg.client_id.ends_with(".apps.googleusercontent.com"));
        assert!(!cfg.client_secret.is_empty(), "desktop exchange needs it");
        // The DESKTOP client, never the web one — the web secret is confidential
        // and must never reach a distributed wheel.
        assert_eq!(cfg.metadata.get("client_type").unwrap(), "desktop");
        assert_ne!(cfg.client_id, BUILTIN_GOOGLE_WEB_CLIENT_ID);
    }

    /// All THREE surfaces authenticate: desktop, Android, and the web audience
    /// Android's `requestIdToken` actually stamps.
    #[test]
    fn native_audiences_cover_every_google_surface() {
        let auds = native_audiences(&ProviderConfigStore::default(), "google");
        for expected in [
            BUILTIN_GOOGLE_DESKTOP_CLIENT_ID,
            BUILTIN_GOOGLE_ANDROID_CLIENT_ID,
            BUILTIN_GOOGLE_WEB_CLIENT_ID,
        ] {
            assert!(auds.iter().any(|a| a == expected), "missing {expected}");
        }
    }

    /// An UNCONFIGURED provider yields NO audiences — and the verifier must read
    /// that as "refuse", never as "skip the check".
    ///
    /// Google's native path used to skip `aud` when the list was empty while
    /// Apple refused: the same zero meaning opposite things. Skipping accepts an
    /// id_token minted for someone else's Google client, and since a claim binds
    /// ROOT to `(google, sub)` (CIRISServer#384) that is the owner's SYSTEM_ADMIN
    /// session. This pins the EMPTY case, which is the one that regressed.
    #[test]
    fn an_unconfigured_provider_has_no_audiences_to_accept() {
        let empty = ProviderConfigStore {
            by_provider: std::collections::HashMap::new(),
        };
        assert!(native_audiences(&empty, "google").is_empty());
        assert!(native_audiences(&empty, "apple").is_empty());
        // And BOTH providers refuse rather than skip. Counted per-provider: a
        // single shared substring would also match this assertion's own literal
        // and pass on its own text.
        let src = include_str!("oauth.rs");
        for provider in ["Google", "Apple"] {
            assert!(
                src.contains(&format!(
                    "{provider} native auth is not configured for this application."
                )),
                "{provider} must REFUSE an empty audience list, not skip the aud check"
            );
        }
    }

    /// The default callback base names the port this router actually answers on.
    ///
    /// It defaulted to the Python brain's `:8080` while being mounted on the
    /// node read API `:4243`. On a node build there is no `:8080`, so Google
    /// returned the browser to a dead port after a correct sign-in — a failure
    /// that appears in the BROWSER and never in this node's logs.
    #[test]
    fn the_default_callback_base_is_the_port_this_router_serves() {
        assert!(
            DEFAULT_OAUTH_CALLBACK_BASE_URL.contains("4243"),
            "oauth::router is mounted on the node read API (:4243); a default \
             naming any other port sends the browser somewhere nothing answers"
        );
        assert_eq!(
            oauth_callback_url(DEFAULT_OAUTH_CALLBACK_BASE_URL, "google"),
            "http://127.0.0.1:4243/v1/auth/oauth/google/callback",
            "and this is the loopback URL a Google DESKTOP client may redirect to"
        );
    }
}
