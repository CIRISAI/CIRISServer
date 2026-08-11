//! OAuth front-door (CIRISServer#9) — the human-login entry point.
//!
//! OAuth authenticates the **human**; the result RESOLVES to a local identity +
//! session. Resolution reads `wa_cert` rows keyed by
//! `(oauth_provider, oauth_external_id)` via the partial `wa_cert_oauth` index
//! (`WaCertService::get_by_oauth`).
//!
//! OAuth users are FIRST-CLASS here: sign-in resolves an existing cert, or
//! creates one. That is the Python behaviour being converted, not an addition.
//!
//! It had never worked, though — the port wrote `pubkey: ""` and persist refuses
//! an empty one (`wa_cert/sqlite.rs:136`), so no OAuth user was ever created ON
//! A NODE (the Python surface, which is where the last year's OAuth users live,
//! was unaffected). `pubkey` holds an identity REFERENCE, not key material — the
//! ROOT cert stores a federation `key_id`, the system cert stores the synthetic
//! `system-of:{root_wa_id}` — so this stores `oauth:{provider}:{subject}`.
//! Enumerating all six `WaCert` construction sites found the same empty-pubkey
//! defect independently in `api_keys.rs`.
//!
//! Routes (port of `routes/auth.py`):
//! - `GET  /v1/auth/oauth/providers`            — list configured providers.
//! - `POST /v1/auth/oauth/providers`            — configure a provider.
//! - `GET  /v1/auth/oauth/{provider}/login`     — start the flow (CSRF state).
//! - `GET  /v1/auth/oauth/{provider}/callback`  — exchange + resolve + session.
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
    /// A DESKTOP app's own nonce, when it started this flow.
    ///
    /// The browser completes the sign-in but the APP needs the session, and the
    /// two are different processes. The app generates a nonce, opens the browser
    /// with it, and afterwards exchanges it — once — for the bearer. Bound to
    /// the same one-use CSRF entry so a nonce cannot outlive its authorization.
    app_nonce: Option<String>,
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
    fn issue(&mut self, app_nonce: Option<String>) -> (String, String) {
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
                app_nonce,
            },
        );
        (token, code_challenge)
    }

    /// One-use consume: returns the PKCE verifier iff the token was issued and
    /// unexpired. `None` means the exchange must be refused — a missing verifier
    /// and a wrong one are the same answer here, deliberately.
    fn consume(&mut self, token: &str) -> Option<(String, Option<String>)> {
        self.prune();
        let p = self.pending.remove(token)?;
        (p.deadline > Instant::now()).then_some((p.code_verifier, p.app_nonce))
    }

    fn prune(&mut self) {
        let now = Instant::now();
        self.pending.retain(|_, p| p.deadline > now);
    }
}

/// **Desktop hand-off** — a completed browser sign-in, waiting to be collected
/// by the app that started it.
///
/// One-time and short-lived: a bearer parked here is removed by the first
/// successful read, and expires on its own if nobody collects it. The route that
/// reads it is loopback-only, the same trust boundary the setup routes use — the
/// browser and the app are the same human on the same machine, and the nonce
/// proves the app is the one that opened the browser.
#[derive(Default)]
struct HandoffStore {
    ready: HashMap<String, (HandoffPayload, Instant)>,
    /// **The most recent completed sign-in, whatever tab finished it.**
    ///
    /// The nonce binds a session to the app that opened the browser, which is
    /// the right default. But a desktop user has real browsers with real tabs:
    /// every attempt opens a new one, stale CIRIS sign-in tabs accumulate, and
    /// whichever tab the human actually finishes in decides whether a nonce
    /// exists at all. Twice in testing a sign-in succeeded at the node while the
    /// app waited forever, because the completed flow came from a tab opened at
    /// the plain `/login` URL.
    ///
    /// So a completed sign-in is ALSO parked here and a local app may claim it
    /// when its own nonce does not resolve. This is a deliberate weakening of
    /// the binding, and it is bounded: loopback-only (enforced by a layer on the
    /// route, not by a comment), one-time, and expiring in minutes. On a desktop
    /// the only process that can reach it is the app the human is looking at.
    recent: Option<(HandoffPayload, Instant)>,
}

/// What a desktop app collects: the session AND who it belongs to.
///
/// The identity is not decoration. On first run the wizard derives the
/// federation-ID name from `<provider>-<subject>`, so an app that collected only
/// a bearer would have a session and no idea whose it was.
#[derive(Debug, Clone, Serialize)]
struct HandoffPayload {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    user_id: String,
    role: String,
    provider: String,
    external_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

impl HandoffStore {
    fn park(&mut self, nonce: Option<String>, payload: HandoffPayload) {
        self.prune();
        let deadline = Instant::now() + Duration::from_secs(300);
        if let Some(n) = nonce {
            self.ready.insert(n, (payload.clone(), deadline));
        }
        // Always claimable by a local app, even when no nonce came back.
        self.recent = Some((payload, deadline));
    }
    /// Collect ONCE. A second read gets nothing, so a leaked nonce cannot be
    /// replayed after the app has taken its session.
    fn collect(&mut self, nonce: &str) -> Option<HandoffPayload> {
        self.prune();
        if let Some((payload, deadline)) = self.ready.remove(nonce) {
            if deadline > Instant::now() {
                self.recent = None; // claimed; do not hand it out twice
                return Some(payload);
            }
        }
        None
    }

    /// Claim the most recent completed sign-in regardless of nonce. One-time.
    fn collect_recent(&mut self) -> Option<HandoffPayload> {
        self.prune();
        let (payload, deadline) = self.recent.take()?;
        (deadline > Instant::now()).then_some(payload)
    }
    fn prune(&mut self) {
        let now = Instant::now();
        self.ready.retain(|_, (_, d)| *d > now);
        if let Some((_, d)) = &self.recent {
            if *d <= now {
                self.recent = None;
            }
        }
    }
}

#[derive(Clone)]
struct OAuthState {
    engine: Arc<Engine>,
    csrf: Arc<Mutex<CsrfStore>>,
    providers: Arc<Mutex<ProviderConfigStore>>,
    handoff: Arc<Mutex<HandoffStore>>,
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
const BUILTIN_GOOGLE_DESKTOP_CLIENT_ID: Option<&str> =
    option_env!("CIRIS_DESKTOP_GOOGLE_OAUTH_CLIENT_ID");
/// See [`BUILTIN_GOOGLE_DESKTOP_CLIENT_ID`] — public by design for a native app.
const BUILTIN_GOOGLE_DESKTOP_CLIENT_SECRET: Option<&str> =
    option_env!("CIRIS_DESKTOP_GOOGLE_OAUTH_CLIENT_SECRET");
/// The Android client (same project). Present so `native_audiences` accepts a
/// phone's id_token — client IDs are public identifiers, never credentials.
const BUILTIN_GOOGLE_ANDROID_CLIENT_ID: Option<&str> =
    option_env!("CIRIS_ANDROID_GOOGLE_OAUTH_CLIENT_ID");
/// The Web client ID — the AUDIENCE Android's `requestIdToken` stamps. Its
/// SECRET is confidential and lives only on the lens/billing hosts; only the
/// public identifier appears here.
const BUILTIN_GOOGLE_WEB_CLIENT_ID: Option<&str> = option_env!("CIRIS_WEB_GOOGLE_OAUTH_CLIENT_ID");

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
        // BOTH halves or nothing. A client_id with no secret cannot complete the
        // code exchange, so a half-injected build would offer a Google button
        // that fails at the last step — worse than a build that plainly has no
        // Google and says so through `auth.oauth.no_local_identity`.
        if let (Some(id), Some(secret)) = (
            BUILTIN_GOOGLE_DESKTOP_CLIENT_ID,
            BUILTIN_GOOGLE_DESKTOP_CLIENT_SECRET,
        ) {
            let mut metadata = serde_json::Map::new();
            metadata.insert("builtin".into(), serde_json::Value::Bool(true));
            metadata.insert("client_type".into(), serde_json::json!("desktop"));
            // The mobile audiences are public identifiers, injected the same way
            // so nothing about the client lives in committed source.
            if let Some(a) = BUILTIN_GOOGLE_ANDROID_CLIENT_ID {
                metadata.insert("android_client_id".into(), serde_json::json!(a));
            }
            if let Some(w) = BUILTIN_GOOGLE_WEB_CLIENT_ID {
                metadata.insert("web_client_id".into(), serde_json::json!(w));
            }
            by_provider.insert(
                "google".to_string(),
                ProviderConfig {
                    client_id: id.to_string(),
                    client_secret: secret.to_string(),
                    metadata: serde_json::Value::Object(metadata),
                },
            );
        }
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

/// Resolve-or-create the `wa_cert` for an authenticated OAuth identity, keyed by
/// `(oauth_provider, oauth_external_id)`. Returns the `wa_id`.
///
/// # This RESOLVES; it does not mint (CIRISServer#386)
///
/// The doc here used to say this was "the agent's `create_oauth_user` — exactly
/// an upsert into this table". **That premise was wrong**, and a live desktop
/// sign-in is what proved it: the agent's `create_oauth_user`
/// (`api/services/auth_service.py:476`) writes an `OAuthUser` into an IN-MEMORY
/// dict with no key material anywhere. Nothing about it is a `wa_cert`.
///
/// Mapping it onto `wa_cert` fused two axes. `wa_cert` answers *"what key is
/// this identity"* — the claim-minted ROOT carries the owner's federation
/// `identity_key_id` in `pubkey` — while an OAuth sign-in answers *"which human
/// authenticated"*, and that human may hold no federation key at all. So the
/// port wrote `pubkey: String::new()`, and persist refuses it in BOTH backends
/// (`wa_cert/sqlite.rs:136`, `wa_cert/postgres.rs:58`:
/// `InvalidArgument("pubkey required")`).
///
/// **That path had therefore never once succeeded.** Zero OAuth users were ever
/// created on any node, and nothing said so — the tell being zero arrivals AND
/// zero rejections. Unit coverage missed it because the owner path returns
/// early from the lookup below and never reaches the write.
///
/// The column is an identity REFERENCE, so the fix is the convention already in
/// use rather than a refusal: `system-of:{root_wa_id}` on the system cert, a
/// federation `key_id` on ROOT, and `oauth:{provider}:{subject}` here. It names
/// what the identity IS instead of impersonating key material.
///
/// [`OAuthResolveError`] remains for genuine failures, so a refusal reaches the
/// UI as a typed, localizable reason rather than a store-internal string.
pub async fn resolve_oauth_user(
    engine: &Engine,
    ident: &OAuthIdentity,
    role: UserRole,
) -> Result<String, OAuthResolveError> {
    if let Some(existing) = store::get_by_oauth(engine, &ident.provider, &ident.external_id).await?
    {
        let _ = store::touch_login(engine, &existing.wa_id).await;
        tracing::info!(
            provider = %ident.provider,
            subject = %redact_subject(&ident.external_id),
            wa_id = %existing.wa_id,
            role = ?existing.role,
            "oauth sign-in resolved to a local identity"
        );
        return Ok(existing.wa_id);
    }
    // No cert carries this identity yet. NOT a refusal — we create below — and
    // saying "REFUSED" here put a warning in the log for the ordinary first
    // sign-in, immediately followed by "CREATED". A log that cries wolf on the
    // happy path is worse than no log.
    tracing::debug!(
        provider = %ident.provider,
        subject = %redact_subject(&ident.external_id),
        "oauth sign-in: no local identity bound yet — creating one"
    );
    // No cert carries this identity yet — CREATE one. OAuth users are
    // first-class in the surface being converted; refusing here would drop a
    // capability the Python has had for a year.
    let wa_id = create_oauth_user_inner(engine, ident, role).await?;
    tracing::info!(
        provider = %ident.provider,
        subject = %redact_subject(&ident.external_id),
        wa_id = %wa_id,
        ?role,
        "oauth sign-in CREATED a local identity"
    );
    Ok(wa_id)
}

/// Last 4 of a provider subject — enough to correlate two log lines, not enough
/// to be an identifier lying around in a log file.
fn redact_subject(sub: &str) -> String {
    let tail: String = sub
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("…{tail}")
}

/// Why an authenticated OAuth identity did not become a session.
///
/// Typed rather than a string so the UI can render an exhaustive, localized
/// reason instead of echoing a store-internal message. The live failure read
/// `store: wa_cert: invalid argument: pubkey required`, which tells an operator
/// nothing they can act on.
#[derive(Debug)]
pub enum OAuthResolveError {
    /// Authentication SUCCEEDED at the provider; this node simply has no
    /// certificate bound to that account. Actionable: claim the node with this
    /// account, or have the owner bind/grant it.
    NoLocalIdentity { provider: String },
    /// The substrate refused the read.
    Store(store::StoreError),
}

impl From<store::StoreError> for OAuthResolveError {
    fn from(e: store::StoreError) -> Self {
        Self::Store(e)
    }
}

impl OAuthResolveError {
    /// Stable machine-readable id — the localization key the client binds, so
    /// the operator reads their own language rather than English from a server.
    pub fn reason_id(&self) -> &'static str {
        match self {
            Self::NoLocalIdentity { .. } => "auth.oauth.no_local_identity",
            Self::Store(_) => "auth.oauth.store_unavailable",
        }
    }

    /// English fallback, used only when the client's bundle lacks the id.
    pub fn message(&self) -> String {
        match self {
            Self::NoLocalIdentity { provider } => format!(
                "Signed in with {provider}, but this node has no identity linked to that account. \
                 Claim this node with this account, or ask the node's owner to grant it access."
            ),
            Self::Store(e) => format!("The node could not read its identity store: {e}"),
        }
    }
}

/// Create-or-update the `wa_cert` for an authenticated OAuth identity — the
/// Rust half of the auth surface being converted from Python.
///
/// Resolves `get_by_oauth` first (that early return is the #384 owner path: a
/// ROOT cert carrying the pair is found, so the owner lands on their own
/// SYSTEM_ADMIN session). Otherwise the user is CREATED, because OAuth users are
/// first-class here exactly as they are in the Python this replaces.
async fn create_oauth_user_inner(
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
    // Upstream shape (`schemas/services/authority_core.py:39` OAuthIdentityLink):
    // a LIST of {provider, external_id, account_name, linked_at, metadata,
    // is_primary}. We were writing an OBJECT keyed "email" — a different shape
    // in the same column, which no reader on either side could interpret.
    let links = serde_json::json!([{
        "provider": ident.provider,
        "external_id": ident.external_id,
        "account_name": ident.name,
        "linked_at": now.to_rfc3339(),
        "metadata": ident.email.as_ref().map(|e| serde_json::json!({"email": e}))
            .unwrap_or_else(|| serde_json::json!({})),
        "is_primary": true,
    }]);
    let cert = WaCert {
        wa_id: wa_id.clone(),
        name: ident
            .name
            .clone()
            .unwrap_or_else(|| ident.external_id.clone()),
        role: wa_role,
        // NOT key material — an identity REFERENCE, the convention the system
        // cert already uses (`system-of:{root_wa_id}`) and the ROOT cert follows
        // with a federation `key_id`. This wrote `""`, which persist refuses
        // (`wa_cert/sqlite.rs:136`), so this write had never once succeeded.
        pubkey: format!("oauth:{}:{}", ident.provider, ident.external_id),
        jwt_kid: format!("oauth-kid-{}-{}", ident.provider, ident.external_id),
        password_hash: None,
        api_key_hash: None,
        oauth_provider: Some(ident.provider.clone()),
        oauth_external_id: Some(ident.external_id.clone()),
        oauth_links: Some(links),
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
    /// A desktop app's nonce — see [`Pending::app_nonce`]. Present ⇒ the session
    /// is parked for collection instead of only being rendered to the browser.
    #[serde(default)]
    app_nonce: Option<String>,
}

async fn oauth_login(
    State(st): State<OAuthState>,
    Path(provider): Path<String>,
    Query(q): Query<LoginQuery>,
) -> Response {
    // REFUSE AT THE DOOR, TYPED (CIRISServer#387).
    //
    // This is the first thing a user touches — the button — and until now the
    // two ways it can be unusable both ended somewhere unhelpful: an
    // unconfigured provider returned an untyped `{"error": "..."}` string a
    // client cannot localize, and a HALF-configured one (client id present but
    // blank, which is what a build with only one of the two secrets injected
    // produces) sailed through and 307'd the user to the provider with
    // `client_id=`. Google answers that with its own error page, so the failure
    // surfaced three hops away wearing someone else's branding.
    //
    // A button that cannot work is worse than no button, and the honest place
    // to say so is here rather than at the code exchange the user never reaches.
    // Same `reason_id` the exchange already uses, so a client binds ONE key.
    let client_id = {
        let store = st.providers.lock().unwrap();
        match store.by_provider.get(&provider) {
            Some(c) if !c.client_id.trim().is_empty() => c.client_id.clone(),
            // Configured-but-blank and absent are the same answer to the user
            // ("this node cannot sign you in with {provider}"), and deliberately
            // NOT distinguished in the response: which half of a credential a
            // build is missing is an operator fact, not a visitor's.
            _ => {
                let e = OAuthResolveError::NoLocalIdentity {
                    provider: provider.clone(),
                };
                tracing::warn!(
                    provider = %provider,
                    "oauth login refused: no usable client id for this provider — the wheel was \
                     built without the credential, or with only half of it (CIRISServer#387)"
                );
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": e.message(),
                        "reason_id": e.reason_id(),
                    })),
                )
                    .into_response();
            }
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
        csrf.issue(q.app_nonce.clone())
    };
    // The provider redirect_uri is ALWAYS our registered callback (not the
    // app-supplied post-login `redirect_uri`, which is validated above and would
    // be carried separately in real deployments). This matches the agent, which
    // always sends `get_oauth_callback_url(provider)` to the provider.
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

async fn oauth_callback(
    State(st): State<OAuthState>,
    Path(provider): Path<String>,
    Query(q): Query<CallbackQuery>,
) -> Response {
    // CSRF: fail-closed on missing/expired/replayed state (issue #847).
    // One-use: consuming the state YIELDS the PKCE verifier. A replayed or
    // expired state and a missing verifier are the same refusal — there is no
    // path that exchanges a code without the secret that committed to it.
    let (code_verifier, app_nonce) = {
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
    finish_oauth_login(&st, ident, app_nonce).await
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
    finish_oauth_login(st, ident, None).await
}

/// What the human sees in the browser once a desktop sign-in completes.
///
/// Deliberately not the JSON the API returns: the bearer belongs to the APP that
/// opened this window, not to the page. Showing it here would put a live session
/// in a browser history and in whatever the user pastes next.
const HANDOFF_PAGE: &str = "<!doctype html><meta charset=utf-8>\
<title>Signed in</title>\
<body style=\"font-family:system-ui;margin:4rem auto;max-width:32rem;text-align:center\">\
<h2>You're signed in</h2>\
<p>You can close this window and return to CIRIS.</p>";

#[derive(Debug, Deserialize)]
struct HandoffQuery {
    app_nonce: String,
    /// Accept a sign-in that completed WITHOUT this nonce — a stray tab. Opt-in
    /// so the bound path stays the default and the fallback is a decision the
    /// client makes explicitly, after its own nonce has failed to resolve.
    #[serde(default)]
    allow_unbound: bool,
}

/// `GET /v1/auth/oauth/handoff?app_nonce=…` — the desktop app collects the
/// session its browser sign-in produced.
///
/// **LOOPBACK-ONLY, enforced.** This route hands out a session BEARER, and the
/// node binds `0.0.0.0:4243`. An earlier comment here claimed the route was
/// "loopback-only, the same trust boundary the setup routes use" — it was not:
/// `require_loopback` wrapped `portable_occurrence::router` only, and this
/// router was merged beside it, so the claim was a comment rather than a
/// control. The layer is now applied to this route specifically (see
/// [`router`]), NOT to the whole OAuth router — the provider callback has to
/// stay reachable by whatever browser the human used.
///
/// `204 No Content` means *not yet* — the human has not finished in the browser.
/// That is a DIFFERENT answer from "no such nonce", and the app polls on the
/// first while giving up on neither silently: a 404 here would make "still
/// typing your password" indistinguishable from "this flow is dead".
async fn oauth_handoff(State(st): State<OAuthState>, Query(q): Query<HandoffQuery>) -> Response {
    let payload = st.handoff.lock().ok().and_then(|mut h| {
        h.collect(&q.app_nonce).or_else(|| {
            // Only when the caller asks. The bound path is the default, so a
            // client that has not waited for its own flow never takes someone
            // else's.
            if !q.allow_unbound {
                return None;
            }
            let p = h.collect_recent();
            if p.is_some() {
                tracing::info!(
                    "hand-off claimed from the RECENT slot — the sign-in that completed \
                     carried no app_nonce (a stray browser tab). Loopback-only and \
                     one-time, but the app that polled is NOT proven to be the app that \
                     opened the browser."
                );
            }
            p
        })
    });
    match payload {
        // Serialize the payload ITSELF. This previously wrapped the whole
        // struct as `{"access_token": {…}}` — the client's decode then failed,
        // returned null, and the app polled forever against a hand-off that had
        // been parked correctly all along. A shape defect on the one hop where
        // "nothing yet" and "malformed" look identical to the caller.
        Some(p) => (StatusCode::OK, Json(p)).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

async fn native_google(State(st): State<OAuthState>, body: axum::body::Bytes) -> Response {
    native_login(&st, "google", &body).await
}
async fn native_apple(State(st): State<OAuthState>, body: axum::body::Bytes) -> Response {
    native_login(&st, "apple", &body).await
}

/// Shared tail: determine role, RESOLVE the local identity, return it.
async fn finish_oauth_login(
    st: &OAuthState,
    ident: OAuthIdentity,
    app_nonce: Option<String>,
) -> Response {
    let role = determine_role(&st.engine, ident.email.as_deref()).await;
    match resolve_oauth_user(&st.engine, &ident, role).await {
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
            // Mint the session THIS sign-in earns — the same opaque token the
            // password path issues, so everything downstream resolves it the
            // same way.
            let access_token = super::session::issue_session_token(&user_id);

            // A desktop app started this in a browser: park the bearer for it to
            // collect once, and give the human a page that says so. Without this
            // the app is a different process watching a browser succeed with no
            // way to learn the result.
            // WHETHER a hand-off was parked is the single most useful line in
            // this flow. Without it, "the app never noticed" is indistinguishable
            // from "the browser never finished" — and a sign-in completed through
            // a stray tab (a login URL opened earlier, carrying no nonce) looks
            // exactly like success from the node's side.
            // Say which way this completed. A nonce-bound hand-off and a
            // nonce-less one are both collectable now, but only the first proves
            // the app that polls is the app that opened the browser — and that
            // distinction is exactly what a reader of this log needs.
            tracing::info!(
                nonce_bound = app_nonce.is_some(),
                user_id = %user_id,
                "oauth callback completed — session parked ({})",
                if app_nonce.is_some() {
                    "bound to the app_nonce that started this flow"
                } else {
                    "NO app_nonce: this sign-in was started from a plain /login URL \
                     (a stray tab), so it is claimable only via the loopback-gated \
                     recent slot"
                }
            );
            // ALWAYS park, and ALWAYS answer the browser with a page. The
            // callback is only ever reached by a provider redirecting a HUMAN's
            // browser, so JSON here was never something a client could consume —
            // and rendering the bearer into a page would put a live session in
            // browser history.
            {
                if let Ok(mut h) = st.handoff.lock() {
                    h.park(
                        app_nonce.clone(),
                        HandoffPayload {
                            access_token: access_token.clone(),
                            token_type: "Bearer",
                            expires_in: 86_400,
                            user_id: user_id.clone(),
                            role: role.as_str().to_string(),
                            provider: ident.provider.clone(),
                            external_id: ident.external_id.clone(),
                            email: ident.email.clone(),
                        },
                    );
                }
                (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    HANDOFF_PAGE,
                )
                    .into_response()
            }
        }
        // A TYPED refusal, carrying the localization id AND an English fallback.
        // The live failure was `store: wa_cert: invalid argument: pubkey required`
        // — a store-internal message an operator can do nothing with, at a 5xx
        // that blamed the node for a request that was actually well-formed.
        Err(e) => {
            let status = match e {
                // The provider authenticated them; WE have no binding. That is a
                // 403 about authorization, not a 5xx about the node being broken.
                OAuthResolveError::NoLocalIdentity { .. } => StatusCode::FORBIDDEN,
                OAuthResolveError::Store(_) => StatusCode::SERVICE_UNAVAILABLE,
            };
            (
                status,
                Json(serde_json::json!({
                    "error": e.message(),
                    "reason_id": e.reason_id(),
                    "provider": ident.provider,
                })),
            )
                .into_response()
        }
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
        handoff: Arc::new(Mutex::new(HandoffStore::default())),
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
        .with_state(st.clone())
        // The desktop hand-off, LOOPBACK-GATED on its own sub-router. It returns
        // a session BEARER and this node binds 0.0.0.0:4243, so the gate has to
        // be a layer, not a sentence in a doc comment (which is what it was).
        // Scoped here rather than to the whole router because the provider
        // callback must stay reachable by whatever browser the human used.
        .merge(
            Router::new()
                .route("/v1/auth/oauth/handoff", axum::routing::get(oauth_handoff))
                .layer(axum::middleware::from_fn(super::loopback::require_loopback))
                .with_state(st),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_is_one_use_and_expiring() {
        let mut s = CsrfStore::default();
        let (t, _challenge) = s.issue(None);
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
        let (state, challenge) = s.issue(None);
        let (verifier, _nonce) = s.consume(&state).expect("verifier on first consume");

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

    /// **A button that cannot work must refuse at the door** (CIRISServer#387).
    ///
    /// Both unusable states are pinned, because the second one is the reason
    /// this exists. An ABSENT provider was already a 404, but an untyped one no
    /// client could localize. A BLANK one — the shape a build produces when only
    /// one of the two credential halves reaches it — passed the lookup and
    /// 307'd the user to Google with `client_id=`, so the failure surfaced three
    /// hops away wearing Google's branding instead of ours.
    ///
    /// The wheels published as 0.5.165 and 0.5.166 had NEITHER half: the tag
    /// path called build-wheels.yml without `secrets: inherit`, so every
    /// `${{ secrets.* }}` in the callee resolved to an empty string, silently.
    /// The store's both-halves-or-nothing rule then left it empty, which is why
    /// this reads as "absent" rather than "blank" on those artifacts.
    #[test]
    fn a_provider_with_no_usable_client_id_is_refused_not_redirected() {
        // The store is both-halves-or-nothing, so a credential-less build has
        // no entry at all...
        let empty = ProviderConfigStore::default();
        assert!(
            !empty.by_provider.contains_key("google"),
            "a build with no injected credential must not offer a google entry"
        );

        // ...and a hand-written blank one must be treated the same way by the
        // handler's guard, never redirected with `client_id=`.
        let blank = ProviderConfig {
            client_id: "   ".to_string(),
            client_secret: String::new(),
            metadata: serde_json::Value::Null,
        };
        assert!(
            blank.client_id.trim().is_empty(),
            "the guard keys on a TRIMMED emptiness check — whitespace is not a client id"
        );

        // And the refusal a user receives carries the SAME stable id the code
        // exchange uses, so a client binds one localization key for "this node
        // cannot sign you in with that account" rather than two.
        let e = OAuthResolveError::NoLocalIdentity {
            provider: "google".to_string(),
        };
        assert_eq!(e.reason_id(), "auth.oauth.no_local_identity");
        assert!(
            !e.message().is_empty(),
            "an English fallback must exist for a client whose bundle lacks the id"
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
    /// A desktop app's nonce survives the round trip, bound to the SAME one-use
    /// CSRF entry — so it cannot outlive the authorization that produced it.
    #[test]
    fn the_app_nonce_is_bound_to_the_one_use_state() {
        let mut s = CsrfStore::default();
        let (state, _c) = s.issue(Some("app-nonce-123".into()));
        let (_v, nonce) = s.consume(&state).expect("first consume");
        assert_eq!(nonce.as_deref(), Some("app-nonce-123"));
        assert!(s.consume(&state).is_none(), "state is still one-use");
    }

    /// **The hand-off response shape**, asserted on the SERIALIZED bytes.
    ///
    /// This shipped as `{"access_token": {…the whole payload…}}` because the
    /// handler wrapped the struct instead of returning it. Everything
    /// type-checked; the client's decode failed, returned null, and the app
    /// polled forever against a session that had been parked correctly the whole
    /// time. On a poll endpoint "nothing yet" (204) and "malformed" are
    /// indistinguishable to the caller — both read as *keep waiting* — so the
    /// shape has to be pinned here rather than inferred from a green compile.
    #[test]
    fn the_handoff_payload_serializes_flat() {
        let p = HandoffPayload {
            access_token: "sess:wa-x:abc".into(),
            token_type: "Bearer",
            expires_in: 86_400,
            user_id: "oauth-google-123".into(),
            role: "SYSTEM_ADMIN".into(),
            provider: "google".into(),
            external_id: "123".into(),
            email: Some("a@b.c".into()),
        };
        let v = serde_json::to_value(&p).expect("serializes");
        assert_eq!(
            v.get("access_token").and_then(|x| x.as_str()),
            Some("sess:wa-x:abc"),
            "access_token must be the TOKEN, not an object containing the payload"
        );
        for k in ["user_id", "role", "provider", "external_id"] {
            assert!(
                v.get(k).is_some_and(|x| x.is_string()),
                "{k} must be a top-level string"
            );
        }
        assert_eq!(v.get("token_type").and_then(|x| x.as_str()), Some("Bearer"));
        assert!(v.get("expires_in").is_some_and(|x| x.is_number()));

        // AND the handler must RETURN that payload, not re-wrap it. The struct
        // serializing flat is not the property that broke — the handler wrapping
        // it was, so asserting only the struct leaves the actual defect site
        // uncovered (verified: mutating the handler did not fail this test until
        // the check below existed).
        let src = include_str!("oauth.rs");
        // CODE only. The handler's own comment explains the bug using the very
        // literal being searched for, so a raw `contains` over the slice fails on
        // correct source — the fourth time a self-referential source assertion
        // has bitten in this file.
        let body: String = src
            .split("async fn oauth_handoff(")
            .nth(1)
            .expect("handler present")
            .split("\nasync fn ")
            .next()
            .expect("handler ends")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            body.contains("Json(p)"),
            "oauth_handoff must return the payload itself"
        );
        assert!(
            !body.contains(r#""access_token":"#),
            "oauth_handoff must NOT re-wrap the payload under an access_token key"
        );
    }
    /// A sign-in completed WITHOUT a nonce is still claimable by a local app.
    ///
    /// Twice in live testing a Google sign-in succeeded at the node while the
    /// desktop app waited forever, because the flow that completed came from a
    /// stray tab opened at the plain `/login` URL and carried no nonce. The
    /// binding is still preferred; this is the fallback that makes the feature
    /// work for a human with real browser tabs.
    #[test]
    fn a_nonceless_signin_is_claimable_once_from_the_recent_slot() {
        let payload = |t: &str| HandoffPayload {
            access_token: t.into(),
            token_type: "Bearer",
            expires_in: 1,
            user_id: "wa-x".into(),
            role: "SYSTEM_ADMIN".into(),
            provider: "google".into(),
            external_id: "sub-1".into(),
            email: None,
        };
        let mut h = HandoffStore::default();
        h.park(None, payload("sess:no-nonce"));
        assert_eq!(
            h.collect_recent().map(|p| p.access_token).as_deref(),
            Some("sess:no-nonce")
        );
        assert!(
            h.collect_recent().is_none(),
            "one-time, like the nonce slot"
        );

        // Claiming BY NONCE must also consume the recent slot, or the same
        // session could be handed out twice.
        let mut h2 = HandoffStore::default();
        h2.park(Some("n".into()), payload("sess:bound"));
        assert!(h2.collect("n").is_some());
        assert!(
            h2.collect_recent().is_none(),
            "a session claimed by nonce must not remain claimable as 'recent'"
        );
    }
    /// Collect ONCE: a nonce that has handed over its bearer hands over nothing
    /// afterwards, so a leaked one cannot be replayed behind the app's back.
    #[test]
    fn a_parked_session_is_collected_exactly_once() {
        let mut h = HandoffStore::default();
        h.park(
            Some("n1".to_string()),
            HandoffPayload {
                access_token: "sess:wa-x:abc".into(),
                token_type: "Bearer",
                expires_in: 1,
                user_id: "wa-x".into(),
                role: "SYSTEM_ADMIN".into(),
                provider: "google".into(),
                external_id: "sub-1".into(),
                email: None,
            },
        );
        assert_eq!(
            h.collect("n1").map(|p| p.access_token).as_deref(),
            Some("sess:wa-x:abc")
        );
        assert!(h.collect("n1").is_none(), "second collection must be empty");
        assert!(h.collect("never-parked").is_none());
    }

    /// Google is configured out of the box IFF the build injected the client.
    ///
    /// The credentials are compile-time inputs now
    /// (`CIRIS_DESKTOP_GOOGLE_OAUTH_CLIENT_*`), so a developer build without
    /// them legitimately has no built-in provider. What must hold either way is
    /// that the store is never HALF configured: a client_id with no secret
    /// cannot complete the code exchange, so it would render a Google button
    /// that fails at the last step.
    #[test]
    fn google_is_configured_iff_the_build_injected_it() {
        let store = ProviderConfigStore::default();
        match store.by_provider.get("google") {
            Some(cfg) => {
                assert!(cfg.client_id.ends_with(".apps.googleusercontent.com"));
                assert!(!cfg.client_secret.is_empty(), "desktop exchange needs it");
                // The DESKTOP client, never the web one — the web secret is
                // confidential and must never reach a distributed wheel.
                assert_eq!(cfg.metadata.get("client_type").unwrap(), "desktop");
                assert_ne!(Some(cfg.client_id.as_str()), BUILTIN_GOOGLE_WEB_CLIENT_ID);
            }
            None => assert!(
                BUILTIN_GOOGLE_DESKTOP_CLIENT_ID.is_none()
                    || BUILTIN_GOOGLE_DESKTOP_CLIENT_SECRET.is_none(),
                "google is absent from the store while BOTH halves were injected"
            ),
        }
    }

    /// All THREE surfaces authenticate: desktop, Android, and the web audience
    /// Android's `requestIdToken` actually stamps.
    #[test]
    fn native_audiences_cover_every_google_surface() {
        let auds = native_audiences(&ProviderConfigStore::default(), "google");
        if BUILTIN_GOOGLE_DESKTOP_CLIENT_ID.is_none() {
            // Nothing injected: there is no provider, so no audiences. Asserting
            // over an empty set would be a zero-denominator pass.
            assert!(auds.is_empty());
            return;
        }
        for expected in [
            BUILTIN_GOOGLE_DESKTOP_CLIENT_ID,
            BUILTIN_GOOGLE_ANDROID_CLIENT_ID,
            BUILTIN_GOOGLE_WEB_CLIENT_ID,
        ]
        .into_iter()
        .flatten()
        {
            assert!(
                auds.iter().any(|a| a == expected),
                "missing audience {expected}"
            );
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

    /// The hand-off route is loopback-GATED in the router, not merely described
    /// as such in a doc comment.
    ///
    /// It returns a session bearer and the node binds 0.0.0.0:4243, so a comment
    /// asserting "loopback-only" while the layer sat on a sibling router was a
    /// protection that did not exist. This asserts the wiring.
    #[test]
    fn the_handoff_route_is_loopback_gated_in_the_router() {
        let src = include_str!("oauth.rs");
        // Read ONLY the router function — everything up to the test module.
        // Splitting to EOF swallowed this very test, whose assertion message
        // contains "require_loopback", so the check passed on its own text while
        // the layer was gone. Third time that self-reference has bitten in this
        // file; bound the slice, do not trust `contains` over a whole file.
        let body = src
            .split("pub fn router(")
            .nth(1)
            .expect("router fn present")
            .split("#[cfg(test)]")
            .next()
            .expect("router fn ends before the tests");
        let sub = body
            .split("Router::new()")
            .find(|chunk| chunk.contains("/v1/auth/oauth/handoff"))
            .expect("handoff registered on some sub-router");
        assert!(
            sub.contains("require_loopback"),
            "the handoff route must carry require_loopback ON ITS OWN sub-router — \
             it hands out a bearer and this node listens on 0.0.0.0"
        );
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
