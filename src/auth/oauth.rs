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
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::prelude::Engine;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};
use serde::{Deserialize, Serialize};

use super::roles::UserRole;
use super::session;
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
    /// Where to send the BROWSER after a successful sign-in (CIRISServer#429,
    /// CIRISAgent#1057 finding 5).
    ///
    /// `oauth_login` validated `redirect_uri` and then DROPPED it, so a web
    /// client that asked to land on `/dashboard` always got the static
    /// hand-off page. Carried here — on the same one-use entry as the PKCE
    /// verifier — so the callback can 303 the browser where the flow asked.
    post_login_redirect: Option<String>,
}

/// What consuming a one-use CSRF state yields — everything the callback needs
/// that was decided at `oauth_login` time. A struct rather than a widening
/// tuple: three positional `Option<String>`s is how a nonce ends up passed as
/// a redirect.
struct ConsumedState {
    /// RFC 7636 verifier — presented at the token exchange.
    code_verifier: String,
    /// The desktop app's nonce, when an app started this flow.
    app_nonce: Option<String>,
    /// The validated post-login browser destination, when the flow asked.
    post_login_redirect: Option<String>,
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
    fn issue(
        &mut self,
        app_nonce: Option<String>,
        post_login_redirect: Option<String>,
    ) -> (String, String) {
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
                post_login_redirect,
            },
        );
        (token, code_challenge)
    }

    /// One-use consume: returns the PKCE verifier iff the token was issued and
    /// unexpired. `None` means the exchange must be refused — a missing verifier
    /// and a wrong one are the same answer here, deliberately.
    fn consume(&mut self, token: &str) -> Option<ConsumedState> {
        self.prune();
        let p = self.pending.remove(token)?;
        (p.deadline > Instant::now()).then_some(ConsumedState {
            code_verifier: p.code_verifier,
            app_nonce: p.app_nonce,
            post_login_redirect: p.post_login_redirect,
        })
    }

    /// Is some UNCONSUMED authorization still carrying `app_nonce`? The
    /// hand-off poll asks this to tell "the human is still typing their
    /// password" (keep polling) from "this flow is dead" (stop) —
    /// CIRISServer#425.
    fn has_pending_nonce(&mut self, app_nonce: &str) -> bool {
        self.prune();
        self.pending
            .values()
            .any(|p| p.app_nonce.as_deref() == Some(app_nonce))
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
    ready: HashMap<String, (HandoffOutcome, Instant)>,
    /// **The most recent terminal sign-in outcome, whatever tab finished it.**
    ///
    /// The nonce binds a session to the app that opened the browser, which is
    /// the right default. But a desktop user has real browsers with real tabs:
    /// every attempt opens a new one, stale CIRIS sign-in tabs accumulate, and
    /// whichever tab the human actually finishes in decides whether a nonce
    /// exists at all. Twice in testing a sign-in succeeded at the node while the
    /// app waited forever, because the completed flow came from a tab opened at
    /// the plain `/login` URL.
    ///
    /// So a terminal outcome is ALSO parked here and a local app may claim it
    /// when its own nonce does not resolve. This is a deliberate weakening of
    /// the binding, and it is bounded: loopback-only (enforced by a layer on the
    /// route, not by a comment), one-time, and expiring in minutes. On a desktop
    /// the only process that can reach it is the app the human is looking at.
    recent: Option<(HandoffOutcome, Instant)>,
    /// **Flows between CSRF-consume and outcome-park** (CIRISServer#425, the
    /// race).
    ///
    /// `oauth_callback` consumes the one-use CSRF entry BEFORE the provider
    /// exchange — a live network round trip. A poll landing in that window sees
    /// no pending entry and no outcome, and without this map would be told
    /// "expired" about a flow that is SUCCEEDING. An entry here means "the
    /// callback holds your flow right now: keep polling". Inserted right after
    /// a successful consume, removed when [`Self::park`] records the terminal
    /// outcome; the TTL prune is a leak-guard for a callback that dies between
    /// the two (nothing else removes the entry).
    in_flight: HashMap<String, Instant>,
}

/// How long an in-flight marker may outlive its insert. Generous next to the
/// provider client's 15s HTTP timeout — a too-short window here IS the race
/// this map exists to close, while a leaked entry merely keeps an abandoned
/// poller at 204 until the prune.
const IN_FLIGHT_TTL: Duration = Duration::from_secs(300);

/// A terminal sign-in outcome, parked for the app that started the flow
/// (CIRISServer#425).
///
/// The slot used to hold only successes, so from the polling app's side
/// "provider refused" and "human still typing" were the same 204 forever — a
/// desktop app had NO way to learn its sign-in had failed. Terminal now means
/// terminal: success parks `Complete`, a failed exchange parks `Failed`, and
/// the poll can finally distinguish pending / complete / failed / expired.
#[derive(Debug, Clone)]
enum HandoffOutcome {
    Complete(HandoffPayload),
    Failed {
        /// The stable localization id the client binds (`auth.oauth.*`).
        reason_id: &'static str,
        /// English fallback — NEVER the raw upstream body (that goes to the
        /// node log only; it can carry anything the provider felt like saying).
        message: String,
        provider: String,
    },
}

/// What a desktop app collects: the session AND who it belongs to.
///
/// The identity is not decoration. On first run the wizard derives the
/// federation-ID name from `<provider>-<subject>`, so an app that collected only
/// a bearer would have a session and no idea whose it was.
///
/// The session half is the flattened [`session::SessionGrant`] — the ONE
/// issuance shape (CIRISServer#393). The wire bytes are identical to the
/// hand-rolled fields this used to carry (same keys, same 86_400), so the
/// change is structural only: the hand-off can no longer disagree with
/// `/v1/auth/login` about what a session looks like.
#[derive(Debug, Clone, Serialize)]
struct HandoffPayload {
    #[serde(flatten)]
    session: session::SessionGrant,
    provider: String,
    external_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    /// The provider's ID token, forwarded to the app that started this flow
    /// (CIRISServer#434).
    ///
    /// This is the field whose absence made CIRIS_PROXY unselectable on
    /// desktop: the mode needs a Google ID token as its `api_key`, the native
    /// clients hold one already, and the desktop client's only view of the
    /// provider response is this payload. Omitted entirely when the flow
    /// produced none, so a client can tell "no ID token" from "empty string".
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

impl HandoffStore {
    fn park(&mut self, nonce: Option<String>, outcome: HandoffOutcome) {
        self.prune();
        let deadline = Instant::now() + Duration::from_secs(300);
        if let Some(n) = nonce {
            // The flow has its terminal outcome — it is no longer in flight.
            self.in_flight.remove(&n);
            self.ready.insert(n, (outcome.clone(), deadline));
        }
        // Always claimable by a local app, even when no nonce came back.
        self.recent = Some((outcome, deadline));
    }
    /// Collect ONCE. A second read gets nothing, so a leaked nonce cannot be
    /// replayed after the app has taken its session.
    fn collect(&mut self, nonce: &str) -> Option<HandoffOutcome> {
        self.prune();
        if let Some((outcome, deadline)) = self.ready.remove(nonce) {
            if deadline > Instant::now() {
                self.recent = None; // claimed; do not hand it out twice
                return Some(outcome);
            }
        }
        None
    }

    /// Claim the most recent terminal outcome regardless of nonce. One-time.
    fn collect_recent(&mut self) -> Option<HandoffOutcome> {
        self.prune();
        let (outcome, deadline) = self.recent.take()?;
        (deadline > Instant::now()).then_some(outcome)
    }

    /// Mark `nonce`'s flow as being processed by the callback RIGHT NOW —
    /// between CSRF consume and outcome park (see the `in_flight` field).
    fn begin_flight(&mut self, nonce: &str) {
        self.prune();
        self.in_flight.insert(nonce.to_string(), Instant::now());
    }

    /// Is `nonce`'s flow inside the consume→park window?
    fn is_in_flight(&mut self, nonce: &str) -> bool {
        self.prune();
        self.in_flight.contains_key(nonce)
    }

    fn prune(&mut self) {
        let now = Instant::now();
        self.ready.retain(|_, (_, d)| *d > now);
        if let Some((_, d)) = &self.recent {
            if *d <= now {
                self.recent = None;
            }
        }
        self.in_flight
            .retain(|_, started| now.duration_since(*started) < IN_FLIGHT_TTL);
    }
}

#[derive(Clone)]
struct OAuthState {
    engine: Arc<Engine>,
    csrf: Arc<Mutex<CsrfStore>>,
    providers: Arc<Mutex<ProviderConfigStore>>,
    handoff: Arc<Mutex<HandoffStore>>,
    client: Arc<dyn ProviderClient>,
    /// Boot-resolved fallback for the callback base. **Read
    /// [`OAuthState::callback_base`] instead** — it consults the live config
    /// first and only falls back to this.
    ///
    /// This used to be the only source, captured here at compose time. A folded
    /// node therefore built its OAuth router before anything could tell it its
    /// public origin, so `PUT /v1/config/auth.oauth_callback_base_url` appeared
    /// to do nothing and the emitted `redirect_uri` stayed on the loopback
    /// default — which read as "the node cannot know its public origin" rather
    /// than "the value must be set before boot" (CIRISServer#412).
    boot_callback_base: String,
}

impl OAuthState {
    /// The base the callback URL is built from, read LIVE.
    ///
    /// `auth.oauth_callback_base_url` is a `config:*` CEG key, so an operator or
    /// a folded agent can set it at any time; taking effect only on the next
    /// restart is an ordering constraint nothing announces. OAuth logins are
    /// rare, so a config read per login costs nothing next to that surprise.
    ///
    /// Falls back to the boot-resolved value when the key is unset or unreadable
    /// — an unreadable config must not silently change where users are sent.
    async fn callback_base(&self) -> String {
        match crate::graph_config::get_str(
            &self.engine,
            crate::config_reconcile::KEY_OAUTH_CALLBACK_BASE_URL,
        )
        .await
        {
            Ok(Some(v)) if !v.trim().is_empty() => v,
            Ok(_) => self.boot_callback_base.clone(),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    key = crate::config_reconcile::KEY_OAUTH_CALLBACK_BASE_URL,
                    fallback = %self.boot_callback_base,
                    "could not read the OAuth callback base from config — using the \
                     boot-resolved value. A redirect_uri that does not match what the \
                     provider has registered will be REFUSED by the provider."
                );
                self.boot_callback_base.clone()
            }
        }
    }
}

/// The per-provider OAuth callback URL (the agent's `get_oauth_callback_url`):
/// `{base}/v1/auth/oauth/{provider}/callback`. This MUST match the
/// `redirect_uri` the provider has registered and the one sent at authorize time.
/// Test-visible wrapper for [`oauth_callback_url`] — the emitted URI must equal
/// the path the router serves, and a provider compares that string exactly.
#[doc(hidden)]
pub fn oauth_callback_url_for_test(base: &str, provider: &str) -> String {
    oauth_callback_url(base, provider)
}

/// Test hook for [`redirect_uri_for`] — the registered-vs-derived decision.
pub fn redirect_uri_for_test(registered: Option<&str>, base: &str, provider: &str) -> String {
    redirect_uri_for(registered, base, provider)
}

fn oauth_callback_url(base: &str, provider: &str) -> String {
    format!(
        "{}/v1/auth/oauth/{provider}/callback",
        base.trim_end_matches('/')
    )
}

/// The `redirect_uri` for a flow: the REGISTERED public URL when the deployment
/// gave us one, the derived shape otherwise.
///
/// Both ends of a flow must send byte-identical values — the authorize redirect
/// and the code exchange — or the provider rejects the exchange after the user
/// has already consented. Routing both through one function makes that
/// structural rather than a convention two call sites happen to share.
fn redirect_uri_for(registered: Option<&str>, base: &str, provider: &str) -> String {
    match registered {
        Some(u) if !u.trim().is_empty() => u.trim().to_string(),
        _ => oauth_callback_url(base, provider),
    }
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
    /// **The URL registered with the provider's console** — sent verbatim as
    /// `redirect_uri`, never derived (CIRISServer#421).
    ///
    /// A provider compares `redirect_uri` as an exact STRING, so the only
    /// authority on its value is the deployment that registered it — and this
    /// node cannot derive it, because the public URL is not the path the node
    /// serves.
    ///
    /// In the hosted deployment nginx routes the public three-segment URL and
    /// STRIPS the agent-id before forwarding. That is how ONE Google client
    /// (datum's) serves every agent: the agent-id exists for proxy routing and
    /// console registration and never reaches the app. So the node correctly
    /// receives, and correctly routes, two segments. Deriving `redirect_uri`
    /// from the path this node serves advertises an INTERNAL path: nginx will
    /// not route it (its location regex requires the agent segment) and no
    /// console entry carries it.
    ///
    /// It took TWO deltas together, which is why neither alone explained it:
    /// the derived path lacked the agent-id AND the base fell back to loopback,
    /// because the config PUT that sets `auth.oauth_callback_base_url` 403s on
    /// an unclaimed node. The deployment never changed.
    ///
    /// The value must come from the agent's OWN environment —
    /// `{OAUTH_CALLBACK_BASE_URL}/v1/auth/oauth/{CIRIS_AGENT_ID}/{provider}/callback`
    /// — and NOT from a provisioning file's `callback_url`, which holds the
    /// registering agent's URL (every non-datum agent would send datum's). It
    /// travels on `configure_provider`, which is unauthenticated, so it also
    /// sidesteps the 403 that blocks the owner-gated config key.
    ///
    /// `None` keeps the derived shape, so desktop and loopback are untouched:
    /// desktop registers a loopback redirect that IS the served path.
    #[serde(default)]
    callback_url: Option<String>,
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
                    // The baked desktop client registers a LOOPBACK redirect,
                    // which IS the served path — no proxy, nothing to register.
                    callback_url: None,
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
    /// The provider's OIDC **ID token**, when the flow produced one
    /// (CIRISServer#434).
    ///
    /// Google returns it in the SAME token response as `access_token`, and this
    /// node was parsing that response and dropping the field. The native mobile
    /// path had one — it arrives as the login credential — so mobile worked and
    /// desktop did not, from one omission.
    ///
    /// It is functional, not decorative: CIRIS_PROXY mode sends the Google ID
    /// token AS the LLM api_key, so a desktop user signed in with Google was
    /// told "Google sign-in is required" while signed in with Google, and could
    /// not select the proxy at all.
    ///
    /// `None` wherever the flow genuinely has none — an opaque-token provider,
    /// or a path that never saw one. Absent is a fact, not a failure.
    pub id_token: Option<String>,
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
        // Same response, one field over (CIRISServer#434). Not required: a
        // provider or scope combination that yields no id_token must still log
        // the user in, so this is Option and never an error arm.
        let id_token = token
            .get("id_token")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
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
            // The field this whole issue is about: captured above from the
            // SAME token response (CIRISServer#434).
            id_token,
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
            // GitHub is OAuth2, not OIDC — there is no id_token to omit.
            id_token: None,
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
            // Discord issues no OIDC id_token on this flow.
            id_token: None,
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
            // The native path's login credential IS the id_token — carry it
            // through so both surfaces answer the same question the same way.
            id_token: Some(id_token.to_string()),
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
            // Apple's native credential is likewise the id_token.
            id_token: Some(id_token.to_string()),
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
    // ── A PERSONAL NODE IS NOT A SIGN-UP SURFACE (CIRISServer#396) ──────────
    //
    // Auto-creating an account for any presentable Google identity belongs to a
    // MANAGED deployment (CIRISManager / web), where an operator provisions
    // people ahead of time and an observer account is a meaningful default. On a
    // personal install — this desktop, this phone — it is the opposite: the node
    // has exactly one human, and a stranger who can reach the port should get
    // NOTHING for proving they control some unrelated email.
    //
    // First-run is the deliberate exception: the owner's very first sign-in is
    // how they establish themselves, before any cert exists to recognise them.
    // Once the node is CLAIMED, an unrecognised identity is refused, and it is
    // refused with the SAME typed reason a known-but-unlinked identity gets, so
    // the wire cannot be used to enumerate who is and is not enrolled here.
    // MANAGED deployments keep creating (CIRISServer#396). CIRIS Manager
    // provisions people ahead of time and an observer default is meaningful
    // there; refusing would lock every web agent's users out. Detection is
    // COPIED from the agent's `is_managed()`, majority-of-five, because a
    // second cleverer answer to a question they have already answered in
    // production is how two systems drift apart.
    if !super::bootstrap::is_first_run(engine).await && !crate::deployment::is_managed() {
        tracing::info!(
            provider = %ident.provider,
            subject = %redact_subject(&ident.external_id),
            "oauth sign-in REFUSED — this node is claimed and no local identity is linked to \
             that account. A personal node does not create accounts for whoever signs in; that \
             is a managed-deployment behaviour."
        );
        return Err(OAuthResolveError::NoLocalIdentity {
            provider: ident.provider.clone(),
        });
    }

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
    /// **This build cannot start an OAuth flow with that provider at all** — no
    /// usable client id (CIRISServer#387).
    ///
    /// A DISTINCT variant, not a reuse of [`Self::NoLocalIdentity`], and the
    /// distinction is the whole point. Both are "you cannot sign in this way", so
    /// folding them looked like a kindness: which half of a credential a build is
    /// missing is an operator fact, not a visitor's, and the folded message avoided
    /// saying. But it did not merely withhold — it ASSERTED two things that are
    /// false here: that the visitor signed in with the provider (the flow never
    /// started), and that claiming the node with that account would fix it (it
    /// cannot; there is no credential to start the flow with). An operator who
    /// believes the message goes and tries exactly the thing that is guaranteed to
    /// fail, which is worse than being told nothing.
    ///
    /// Withholding an operator detail is fine. Naming a remedy that cannot work is
    /// not. This says only what the visitor needs — this node cannot do it, use a
    /// password — and still names no credential half.
    ProviderUnavailable { provider: String },
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
            Self::ProviderUnavailable { .. } => "auth.oauth.provider_unavailable",
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
            Self::ProviderUnavailable { provider } => format!(
                "This node cannot sign you in with {provider} — this build has no {provider} \
                 sign-in configured. Sign in with a username and password instead."
            ),
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

/// Test seam: drive the resolve-or-create + role decision the callback uses
/// (`tests/owner_is_the_identity.rs`).
#[doc(hidden)]
pub async fn test_support_resolve_oauth_user(
    engine: &Engine,
    provider: &str,
    external_id: &str,
    email: Option<&str>,
) -> Result<String, String> {
    let ident = OAuthIdentity {
        id_token: None,
        provider: provider.to_string(),
        external_id: external_id.to_string(),
        email: email.map(str::to_owned),
        name: None,
    };
    let role = determine_role(engine, ident.email.as_deref()).await;
    resolve_oauth_user(engine, &ident, role)
        .await
        .map_err(|e| e.reason_id().to_string())
}

/// `@ciris.ai` → ADMIN; else OBSERVER.
///
/// # A DOOR DOES NOT OWN THE HOUSE (CIRISServer#391)
///
/// This used to hand SYSTEM_ADMIN to the first OAuth user on a node with no
/// ROOT, so signing in with Google CLAIMED the node — minting an owner named
/// after the auth pair (`oauth-<provider>-<external_id>`). Three things then
/// went wrong at once:
///
///  1. The owner was named after the DOOR, not the person. Everywhere else the
///     owner is `wa-root-<identity_key_id>` — derived from the federation
///     identity, which is what signs CEG rows and what the node's
///     `ownership:responsible_party:node:v1` edge points FROM. Production
///     (canonical-server-1) has the identity-derived shape; only this path
///     disagreed.
///  2. It closed first-run. The wizard's own claim step — the one that binds the
///     owner to their fed-ID and writes the ownership edge — then failed
///     `409 root already claimed`, and the app fell back to local login with the
///     fed-ID imported and nothing bound.
///  3. The resulting owner held no key. An OAuth identity carries no key
///     material (this module touches none), so a node "owned" this way had an
///     owner that could not sign a single federation row.
///
/// OAuth proves a human controls an email. It is a way IN to an account, and it
/// is revocable by a third party. Ownership is established by the CLAIM, from
/// the federation identity, on one path — whether the human arrives by OAuth or
/// by password. The sign-in still stamps its pair onto that owner (see
/// `SetupRootRequest::owner_oauth_provider`), so Google remains a way in; it
/// simply stops being the thing that decides who the owner IS.
async fn determine_role(engine: &Engine, email: Option<&str>) -> UserRole {
    let _ = engine;
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
    // A provider with no client id is NOT available, and listing it is what lets
    // a dead sign-in button render (CIRISServer#387). "Configured" and "usable"
    // are two questions, and this endpoint is asked the second one — a caller
    // deciding which buttons to draw cannot act on the first.
    let providers: Vec<ProviderInfo> = store
        .by_provider
        .iter()
        .filter(|(_, c)| !c.client_id.trim().is_empty())
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
    /// The registered console URL, built by the agent from its own env. Until
    /// CIRISServer#421 this was dropped SILENTLY at `200` — the node then
    /// derived a different URI and the mismatch surfaced one redirect later at
    /// the provider, as `redirect_uri_mismatch`.
    #[serde(default)]
    callback_url: Option<String>,
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
            callback_url: req.callback_url,
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
    headers: HeaderMap,
    Query(q): Query<LoginQuery>,
) -> Response {
    // The provider segment is caller-controlled and flows into refusal text —
    // gate its SHAPE before anything reads it (CIRISServer#424, the XSS half).
    if !provider_name_is_wellformed(&provider) {
        return browser_refusal(
            &headers,
            StatusCode::NOT_FOUND,
            "auth.oauth.provider_unavailable",
            NOT_A_PROVIDER_NAME,
            "No such sign-in provider",
            None,
        );
    }
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
    let registered_callback = {
        let store = st.providers.lock().unwrap();
        store
            .by_provider
            .get(&provider)
            .and_then(|c| c.callback_url.clone())
    };
    let client_id = {
        let store = st.providers.lock().unwrap();
        match store.by_provider.get(&provider) {
            Some(c) if !c.client_id.trim().is_empty() => c.client_id.clone(),
            // Configured-but-blank and absent are the same answer to the user
            // ("this node cannot sign you in with {provider}"), and still
            // deliberately not distinguished: which half of a credential a build
            // is missing is an operator fact, not a visitor's.
            //
            // What they are NOT is the same answer as `NoLocalIdentity`. That
            // reuse shipped, and it told an operator they had signed in with
            // Google and should claim the node with that account — on a build
            // with no Google credential, so the flow had never started and the
            // remedy could not work. Withholding an operator detail is fine;
            // naming a remedy that cannot work sends them down a guaranteed dead
            // end (CIRISServer#387).
            _ => {
                let e = OAuthResolveError::ProviderUnavailable {
                    provider: provider.clone(),
                };
                tracing::warn!(
                    provider = %provider,
                    "oauth login refused: no usable client id for this provider — the wheel was \
                     built without the credential, or with only half of it (CIRISServer#387)"
                );
                // This is a BROWSER leg — the human just clicked a sign-in
                // button — so the refusal is a page (CIRISServer#424); JSON
                // only when explicitly asked for.
                return browser_refusal(
                    &headers,
                    StatusCode::NOT_FOUND,
                    "auth.oauth.provider_unavailable",
                    &e.message(),
                    "This sign-in is not available here",
                    None,
                );
            }
        }
    };
    // issue #846 redirect-uri validation: only relative or https allowed.
    let redirect_uri = q.redirect_uri.unwrap_or_else(|| "/".to_string());
    if !is_safe_redirect(&redirect_uri) {
        return browser_refusal(
            &headers,
            StatusCode::BAD_REQUEST,
            "auth.oauth.unsafe_redirect",
            "unsafe redirect_uri",
            "That link can't be followed",
            None,
        );
    }
    // The post-login destination rides the one-use CSRF entry to the callback
    // (CIRISServer#429; the drop was CIRISAgent#1057 finding 5). "/" is the
    // no-preference default the client sends, not a destination.
    let post_login_redirect = Some(redirect_uri).filter(|r| r != "/");
    // The verifier stays in the store; only its S256 challenge goes to the browser.
    let (state, code_challenge) = {
        let mut csrf = st.csrf.lock().unwrap();
        csrf.issue(q.app_nonce.clone(), post_login_redirect)
    };
    // The provider redirect_uri is ALWAYS our registered callback — the
    // app-supplied post-login `redirect_uri` is a DIFFERENT axis (where the
    // BROWSER goes after we finish) and is carried on the CSRF entry above.
    // This matches the agent, which always sends
    // `get_oauth_callback_url(provider)` to the provider.
    let callback = redirect_uri_for(
        registered_callback.as_deref(),
        &st.callback_base().await,
        &provider,
    );
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
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    // Shape-gate the caller-controlled provider segment FIRST — it flows into
    // refusal text on every arm below (CIRISServer#424).
    if !provider_name_is_wellformed(&provider) {
        return browser_refusal(
            &headers,
            StatusCode::NOT_FOUND,
            "auth.oauth.provider_unavailable",
            NOT_A_PROVIDER_NAME,
            "No such sign-in provider",
            None,
        );
    }
    // CSRF: fail-closed on missing/expired/replayed state (issue #847).
    // One-use: consuming the state YIELDS the PKCE verifier. A replayed or
    // expired state and a missing verifier are the same refusal — there is no
    // path that exchanges a code without the secret that committed to it.
    //
    // NO outcome can be parked on this arm: the app_nonce lives INSIDE the
    // entry that failed to consume, so there is no slot to address. The polling
    // client is covered by the hand-off's own 410 (`auth.oauth.flow_expired`) —
    // no pending entry, no in-flight marker, no outcome IS the expired verdict.
    let consumed = {
        let mut csrf = st.csrf.lock().unwrap();
        match csrf.consume(&q.state) {
            Some(v) => v,
            None => {
                return browser_refusal(
                    &headers,
                    StatusCode::BAD_REQUEST,
                    "auth.oauth.state_invalid",
                    "invalid or expired oauth state",
                    "This sign-in attempt has expired",
                    None,
                )
            }
        }
    };
    let ConsumedState {
        code_verifier,
        app_nonce,
        post_login_redirect,
    } = consumed;
    // ── THE RACE (CIRISServer#425): the one-use state is now GONE, and the
    // provider exchange below is a live network round trip. A hand-off poll in
    // that window would see no pending entry and no outcome and conclude
    // "expired" about a flow that is succeeding. Mark the flow in-flight for
    // the poll to see; `park` (success or failure) clears the marker. ──────────
    if let Some(n) = &app_nonce {
        if let Ok(mut h) = st.handoff.lock() {
            h.begin_flight(n);
        }
    }
    let (client_id, client_secret, registered_callback) = {
        let store = st.providers.lock().unwrap();
        match store.by_provider.get(&provider) {
            Some(c) => (
                c.client_id.clone(),
                c.client_secret.clone(),
                c.callback_url.clone(),
            ),
            None => {
                // Terminal for the app too: park the failure so the poller
                // learns its flow is dead instead of waiting forever (#425).
                if let Ok(mut h) = st.handoff.lock() {
                    h.park(
                        app_nonce,
                        HandoffOutcome::Failed {
                            reason_id: "auth.oauth.provider_unavailable",
                            message: PROVIDER_NOT_CONFIGURED.to_string(),
                            provider: provider.clone(),
                        },
                    );
                }
                return browser_refusal(
                    &headers,
                    StatusCode::NOT_FOUND,
                    "auth.oauth.provider_unavailable",
                    PROVIDER_NOT_CONFIGURED,
                    "This sign-in is not available here",
                    post_login_redirect.as_deref(),
                );
            }
        }
    };
    // MUST equal what the authorize redirect sent — the provider compares the
    // string and rejects the exchange otherwise. Same resolver, same inputs.
    let redirect_uri = redirect_uri_for(
        registered_callback.as_deref(),
        &st.callback_base().await,
        &provider,
    );
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
        Err(e) => {
            // The RAW upstream string goes to the LOG ONLY. It is a provider's
            // arbitrary body and this response is a 502 — http_log captures
            // 4xx/5xx response bodies, so anything placed in the body lands in
            // the log ANYWAY, plus in the human's browser and their next paste.
            tracing::warn!(
                provider = %provider,
                upstream = %e,
                "oauth code exchange FAILED at the provider — raw upstream error retained \
                 here only (CIRISServer#424)"
            );
            let message = format!(
                "the {provider} sign-in could not be completed — the provider rejected the \
                 code exchange. Try again; if it keeps failing, this node's log has the \
                 provider's answer."
            );
            if let Ok(mut h) = st.handoff.lock() {
                h.park(
                    app_nonce,
                    HandoffOutcome::Failed {
                        reason_id: "auth.oauth.exchange_failed",
                        message: message.clone(),
                        provider: provider.clone(),
                    },
                );
            }
            return browser_refusal(
                &headers,
                StatusCode::BAD_GATEWAY,
                "auth.oauth.exchange_failed",
                &message,
                "Sign-in didn't complete",
                post_login_redirect.as_deref(),
            );
        }
    };
    browser_finish(&st, ident, app_nonce, post_login_redirect, &headers).await
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

/// The `POST /v1/auth/native/{provider}` responder — JSON UNCONDITIONALLY
/// (decision D1, CIRISServer#429).
///
/// The native exchange is called by SDK code (the mobile apps' hand-rolled
/// decoders), never by a browser. It used to share `finish_oauth_login` with
/// the callback, so a native success was answered with the HANDOFF PAGE — a
/// blob of HTML where the app's decoder expected `{access_token, …}`, and the
/// Apple flow failed AFTER Apple had said yes. No Accept-negotiation here:
/// every default HTTP client sends `Accept: */*`, and negotiating on that is
/// precisely how the page reached the decoder.
async fn native_login(st: &OAuthState, provider: &str, body: &[u8]) -> Response {
    let req: NativeTokenRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => {
            return super::refusal::refuse(
                StatusCode::BAD_REQUEST,
                "auth.oauth.malformed_body",
                format!("bad request: {e}"),
            )
        }
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
        // The provider-facing sentences are UNCHANGED (they teach the remedy);
        // the stable id is what was missing (CIRISServer#389).
        Err(e) => {
            return super::refusal::refuse(
                StatusCode::UNAUTHORIZED,
                "auth.oauth.native_token_invalid",
                e,
            )
        }
    };
    match resolve_login(st, &ident).await {
        Ok(r) => (
            StatusCode::OK,
            Json(NativeTokenResponse {
                session: r.session,
                email: r.email,
                name: r.name,
            }),
        )
            .into_response(),
        Err(e) => resolve_refusal_json(&e, &ident.provider),
    }
}

/// The native token-exchange response body — the shape
/// `client/openapi.json#/components/schemas/NativeTokenResponse` publishes,
/// pinned by `the_native_response_carries_every_field_the_published_spec_requires`.
///
/// `token_type` MUST serialize: the Apple client's hand-rolled decoder declares
/// it non-null, so an omitted field fails their decode after a successful
/// sign-in. `email`/`name` are emitted ALWAYS (null when absent) — the spec
/// declares them nullable, not omittable.
#[derive(Debug, Serialize)]
struct NativeTokenResponse {
    #[serde(flatten)]
    session: session::SessionGrant,
    email: Option<String>,
    name: Option<String>,
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

/// Minimal HTML escaping for text and attribute positions — the five
/// characters that end a text node, an attribute, or open a tag. No dependency:
/// this is the whole job, and a crate would be one more thing to audit.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// The provider path segment is CALLER-CONTROLLED input; only this shape is a
/// provider name. Rejecting everything else at the door (CIRISServer#424) is
/// half of the XSS posture — [`esc`] on every interpolation is the other half,
/// and BOTH are load-bearing: the gate keeps hostile strings out of logs and
/// error flows entirely, the escape makes the page safe even for strings that
/// arrive by some future path this gate does not cover.
fn provider_name_is_wellformed(provider: &str) -> bool {
    (1..=32).contains(&provider.len())
        && provider
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Does this request prefer JSON over a human page? Browser routes (login
/// redirect, provider callback) consult this so a programmatic caller can still
/// get `{error, reason_id}`; native routes NEVER call it — they are JSON
/// unconditionally (decision D1: Accept-negotiation on a native route is what
/// re-breaks #429 for `Accept: */*`, which every default HTTP client sends).
fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("application/json"))
}

/// A human-readable refusal page for the BROWSER legs of the flow
/// (CIRISServer#424).
///
/// The provider callback and the login redirect are only ever reached by a
/// human's browser, and they answered refusals in JSON — a wall of
/// `{"error":…}` where a person needed to be told what happened and what to do
/// next. Same inline-style school as [`HANDOFF_PAGE`]; `reason_id` rides in
/// small print so a screenshot is diagnosable; `back` renders a real link when
/// the flow knows where the human came from.
///
/// EVERY interpolation goes through [`esc`] — `provider` flows from the URL
/// path into refusal text, and unescaped that is reflected XSS (pinned by
/// `a_browser_refusal_escapes_the_provider_name`).
fn browser_error_page(
    reason_id: &str,
    headline: &str,
    explanation: &str,
    next_step: &str,
    back: Option<&str>,
) -> String {
    let back_link = back
        .map(|b| format!("<p><a href=\"{}\">Go back and try again</a></p>", esc(b)))
        .unwrap_or_default();
    format!(
        "<!doctype html><meta charset=utf-8>\
         <title>{title}</title>\
         <body style=\"font-family:system-ui;margin:4rem auto;max-width:32rem;text-align:center\">\
         <h2>{headline}</h2>\
         <p>{explanation}</p>\
         <p>{next_step}</p>\
         {back_link}\
         <p style=\"color:#888;font-size:0.8rem\">{reason}</p>",
        title = esc(headline),
        headline = esc(headline),
        explanation = esc(explanation),
        next_step = esc(next_step),
        back_link = back_link,
        reason = esc(reason_id),
    )
}

/// Per D2: the one remedy line every browser refusal offers. The OAuth-linking
/// surfaces exist but have no working caller in any client, so suggesting a
/// link flow would send a human somewhere nothing can complete — the #387
/// lesson again (never name a remedy that cannot work).
const BROWSER_NEXT_STEP: &str = "Sign in with your local username and password.";

/// The refusal for a path segment that is not even provider-SHAPED. A const so
/// the id↔text pairing the localization guard scrapes stays the one at
/// `auth.oauth.provider_unavailable`'s primary (unconfigured-provider) arm.
const NOT_A_PROVIDER_NAME: &str = "that is not a recognisable sign-in provider name";

/// The callback's answer when its provider vanished between authorize and
/// exchange (an operator re-POSTed `/providers` mid-flow, or the state was
/// minted by an older process).
const PROVIDER_NOT_CONFIGURED: &str = "provider not configured";

/// The hand-off poll's terminal "stop polling" id — a const so log sites can
/// name it without the localization guard pairing the id with a LOG line as
/// its English text.
const FLOW_EXPIRED_REASON: &str = "auth.oauth.flow_expired";

/// One browser-leg refusal: HTML for the human, `{error, reason_id}` JSON when
/// the caller explicitly asked for JSON (`Accept: application/json`). Logs with
/// the reason_id either way — the browser page is the one refusal surface an
/// operator can otherwise never grep for.
fn browser_refusal(
    headers: &HeaderMap,
    code: StatusCode,
    reason_id: &'static str,
    msg: &str,
    headline: &str,
    back: Option<&str>,
) -> Response {
    if wants_json(headers) {
        return super::refusal::refuse(code, reason_id, msg);
    }
    tracing::info!(reason_id, "auth refused (browser page): {msg}");
    (
        code,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        browser_error_page(reason_id, headline, msg, BROWSER_NEXT_STEP, back),
    )
        .into_response()
}

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
/// The poll's four answers, in resolution order (CIRISServer#425):
///  1. a TERMINAL outcome bound to this nonce → `200` with `"status"`
///     `"complete"` (the flattened session payload) or `"failed"` (the typed
///     reason);
///  2. (`allow_unbound` only) the recent slot's terminal outcome → same `200`s;
///  3. the flow is still PENDING — an unconsumed authorization carries this
///     nonce, or the callback holds it between CSRF-consume and outcome-park
///     (the in-flight window, THE race) → `204` *not yet*;
///  4. nothing anywhere → `410` `{"status":"expired", …}` — this flow is dead
///     and polling harder will not revive it.
///
/// `204` means *keep waiting* and ONLY that. It used to also mean "your flow
/// failed" (failures parked nothing) and "no such flow ever existed" — three
/// verdicts folded into the one answer the client reads as *still typing*.
///
/// The `"status"` member is ADDITIVE: the generated client decodes with
/// `ignoreUnknownKeys`, so a `complete` body decodes exactly as before, and a
/// `failed` body simply fails their payload decode → they keep polling →
/// today's behaviour, never a wrong state.
async fn oauth_handoff(State(st): State<OAuthState>, Query(q): Query<HandoffQuery>) -> Response {
    let outcome = st.handoff.lock().ok().and_then(|mut h| {
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
    match outcome {
        // Serialize the payload ITSELF (plus the additive status). This
        // previously wrapped the whole struct as `{"access_token": {…}}` — the
        // client's decode then failed, returned null, and the app polled
        // forever against a hand-off that had been parked correctly all along.
        Some(HandoffOutcome::Complete(p)) => {
            let mut body = serde_json::to_value(&p).unwrap_or_default();
            if let Some(obj) = body.as_object_mut() {
                obj.insert("status".into(), serde_json::json!("complete"));
            }
            (StatusCode::OK, Json(body)).into_response()
        }
        Some(HandoffOutcome::Failed {
            reason_id,
            message,
            provider,
        }) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "failed",
                "error": message,
                "reason_id": reason_id,
                "provider": provider,
            })),
        )
            .into_response(),
        None => {
            // Still pending? Either the authorization is unconsumed (human
            // still at the provider) or the callback is mid-exchange (the
            // in-flight window). Check the in-flight side FIRST — it holds the
            // handoff lock the shortest time and covers the racing case.
            let pending = st
                .handoff
                .lock()
                .map(|mut h| h.is_in_flight(&q.app_nonce))
                .unwrap_or(false)
                || st
                    .csrf
                    .lock()
                    .map(|mut c| c.has_pending_nonce(&q.app_nonce))
                    .unwrap_or(false);
            if pending {
                StatusCode::NO_CONTENT.into_response()
            } else {
                tracing::info!(
                    reason_id = FLOW_EXPIRED_REASON,
                    "hand-off poll for a flow with no pending authorization, no in-flight \
                     exchange, and no outcome — telling the app to stop polling"
                );
                (
                    StatusCode::GONE,
                    Json(serde_json::json!({
                        "status": "expired",
                        "reason_id": FLOW_EXPIRED_REASON,
                    })),
                )
                    .into_response()
            }
        }
    }
}

async fn native_google(State(st): State<OAuthState>, body: axum::body::Bytes) -> Response {
    native_login(&st, "google", &body).await
}
async fn native_apple(State(st): State<OAuthState>, body: axum::body::Bytes) -> Response {
    native_login(&st, "apple", &body).await
}

/// Everything a completed provider authentication resolves to on THIS node:
/// the minted session plus the identity facts each responder shapes its answer
/// from. The core of the #429 split — one resolution, two responders (native
/// JSON, browser page/redirect), so the answer's FORM can never again leak
/// across surfaces.
struct ResolvedLogin {
    session: session::SessionGrant,
    provider: String,
    external_id: String,
    email: Option<String>,
    name: Option<String>,
    /// The provider's OIDC ID token when the flow produced one
    /// (CIRISServer#434). Resolution does not USE it — it is carried so the
    /// browser responder can hand it to the desktop app, which cannot see the
    /// provider response the way a native client can.
    id_token: Option<String>,
}

/// Shared core: determine role, RESOLVE the local identity, mint the session —
/// and say NOTHING about how to answer the caller (CIRISServer#429).
///
/// `finish_oauth_login` fused those axes: the native token exchange shared it
/// with the provider callback, so a native success was answered with the
/// browser's hand-off PAGE and the Apple app's decoder choked on HTML after
/// Apple had said yes.
async fn resolve_login(
    st: &OAuthState,
    ident: &OAuthIdentity,
) -> Result<ResolvedLogin, OAuthResolveError> {
    let role = determine_role(&st.engine, ident.email.as_deref()).await;
    let user_id = resolve_oauth_user(&st.engine, ident, role).await?;
    // NO AUTO-MINT HERE (CIRISServer#391). This used to call
    // `auto_mint_root_if_needed(&user_id)` — passing the OAuth wa_id as if it
    // were a federation identity, which would mint
    // `wa-root-oauth-google-<external_id>`: an owner named after a door,
    // holding no key. Ownership is the CLAIM's job, from the fed-ID, on one
    // path for OAuth and password alike. See `determine_role`.
    //
    // Mint the session THIS sign-in earns, through SessionGrant::issue — THE
    // issuance point (session.rs documents it as the sole caller of
    // `issue_session_token`, and the direct call here was the violation).
    // `SESSION_TTL_SECS` is the 86_400 this path hard-coded, so the wire is
    // unchanged — and OAuth now deliberately INHERITS however the
    // login-vs-refresh lifetime disagreement (session.rs) is later resolved,
    // instead of holding a fourth private copy of the policy.
    let session = session::SessionGrant::issue(&user_id, &role);
    Ok(ResolvedLogin {
        session,
        provider: ident.provider.clone(),
        external_id: ident.external_id.clone(),
        email: ident.email.clone(),
        name: ident.name.clone(),
        id_token: ident.id_token.clone(),
    })
}

/// Status for a typed resolve failure — one mapping, both responders.
fn resolve_error_status(e: &OAuthResolveError) -> StatusCode {
    match e {
        // The provider authenticated them; WE have no binding. That is a
        // 403 about authorization, not a 5xx about the node being broken.
        OAuthResolveError::NoLocalIdentity { .. } => StatusCode::FORBIDDEN,
        OAuthResolveError::Store(_) => StatusCode::SERVICE_UNAVAILABLE,
        // Unreachable from the exchange — the login handler refuses long
        // before a code exists. Matched explicitly rather than by `_` so
        // that if a future path CAN reach it, the compiler makes someone
        // decide the status instead of silently inheriting one.
        OAuthResolveError::ProviderUnavailable { .. } => StatusCode::NOT_IMPLEMENTED,
    }
}

/// The MACHINE answer to a typed resolve failure — today's status mapping and
/// today's JSON body, byte-for-byte (the native surface's published contract).
/// A TYPED refusal, carrying the localization id AND an English fallback: the
/// live failure was `store: wa_cert: invalid argument: pubkey required` — a
/// store-internal message an operator can do nothing with, at a 5xx that
/// blamed the node for a request that was actually well-formed.
fn resolve_refusal_json(e: &OAuthResolveError, provider: &str) -> Response {
    tracing::info!(reason_id = e.reason_id(), provider, "oauth sign-in refused");
    (
        resolve_error_status(e),
        Json(serde_json::json!({
            "error": e.message(),
            "reason_id": e.reason_id(),
            "provider": provider,
        })),
    )
        .into_response()
}

/// The BROWSER responder: park the terminal outcome for the polling app, then
/// answer the human (CIRISServer#429/#424/#425).
async fn browser_finish(
    st: &OAuthState,
    ident: OAuthIdentity,
    app_nonce: Option<String>,
    post_login_redirect: Option<String>,
    headers: &HeaderMap,
) -> Response {
    match resolve_login(st, &ident).await {
        Ok(r) => {
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
                user_id = %r.session.user_id,
                "oauth callback completed — session parked ({})",
                if app_nonce.is_some() {
                    "bound to the app_nonce that started this flow"
                } else {
                    "NO app_nonce: this sign-in was started from a plain /login URL \
                     (a stray tab), so it is claimable only via the loopback-gated \
                     recent slot"
                }
            );
            // ALWAYS park. A desktop app started this in a browser: the bearer
            // is collected once over the loopback hand-off. Never render it
            // into the page — that would put a live session in browser history.
            if let Ok(mut h) = st.handoff.lock() {
                h.park(
                    app_nonce.clone(),
                    HandoffOutcome::Complete(HandoffPayload {
                        session: r.session.clone(),
                        provider: r.provider.clone(),
                        external_id: r.external_id.clone(),
                        email: r.email.clone(),
                        id_token: r.id_token.clone(),
                    }),
                );
            }
            match post_login_redirect {
                // The flow asked for a destination (a web client's own page):
                // 303 See Other, the redirect-after-POST-shaped answer. Token
                // delivery to the web page is deliberately OUT of scope (D3) —
                // the session still travels only via the hand-off.
                Some(dest) => axum::response::Redirect::to(&dest).into_response(),
                None => (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    HANDOFF_PAGE,
                )
                    .into_response(),
            }
        }
        Err(e) => {
            // Terminal outcome FIRST (#425): the polling app must learn its
            // flow died, or it waits forever on a 204 that will never change.
            if let Ok(mut h) = st.handoff.lock() {
                h.park(
                    app_nonce,
                    HandoffOutcome::Failed {
                        reason_id: e.reason_id(),
                        message: e.message(),
                        provider: ident.provider.clone(),
                    },
                );
            }
            if wants_json(headers) {
                return resolve_refusal_json(&e, &ident.provider);
            }
            tracing::info!(
                reason_id = e.reason_id(),
                provider = %ident.provider,
                "oauth sign-in refused (browser page)"
            );
            (
                resolve_error_status(&e),
                [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                browser_error_page(
                    e.reason_id(),
                    "Sign-in didn't complete",
                    &e.message(),
                    BROWSER_NEXT_STEP,
                    post_login_redirect.as_deref(),
                ),
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

/// The callback base a DEPLOYMENT declares before the process starts
/// (CIRISServer#435).
///
/// Server 0.5 moved configuration into `config:*` and retired the env vars, which
/// is right for values an operator changes at runtime. This one is not that: it
/// is known before boot, identical on every boot, and — critically — writing it
/// requires `PUT /v1/config/...`, which requires an owner session, which an
/// UNCLAIMED node cannot have.
///
/// That produced an ordering paradox on a fresh deployment: signing in is how an
/// operator claims the node, and the key that is unwritable until the node is
/// claimed is the one that makes signing in work. The node fell back to
/// `127.0.0.1:4243`, which no provider console has registered, so the flow died
/// at the provider with a `redirect_uri_mismatch` — the same class as #421,
/// arriving by configuration rather than by derivation.
///
/// Precedence is deliberate and one-directional: the stored `config:*` value
/// WINS when present (an operator who has set it at runtime meant it), the
/// environment fills the boot-time hole, and the loopback default is the last
/// resort. So this can only ever help a node that would otherwise have had
/// nothing.
///
/// Both spellings are accepted: `CIRIS_OAUTH_CALLBACK_BASE_URL` for this
/// project's prefix convention, and the `OAUTH_CALLBACK_BASE_URL` the agent's
/// deployments already set — refusing to read a variable the fleet has been
/// setting all along would be a distinction with no user on the other side of it.
fn callback_base_from_env() -> Option<String> {
    for key in ["CIRIS_OAUTH_CALLBACK_BASE_URL", "OAUTH_CALLBACK_BASE_URL"] {
        if let Ok(v) = std::env::var(key) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                tracing::info!(
                    env = key,
                    callback_base = %v,
                    "OAuth callback base taken from the environment — no stored \
                     auth.oauth_callback_base_url yet (CIRISServer#435)"
                );
                return Some(v);
            }
        }
    }
    None
}

/// The OAuth front-door router.
///
/// `callback_base` is the boot-resolved `auth.oauth_callback_base_url` config:*
/// value. Empty falls back to the ENVIRONMENT, then to
/// [`DEFAULT_OAUTH_CALLBACK_BASE_URL`] — see [`callback_base_from_env`].
pub fn router(engine: Arc<Engine>, callback_base: String) -> Router {
    router_with_client(
        engine,
        callback_base,
        Arc::new(HttpProviderClient::default()),
    )
}

/// [`router`] with the provider-HTTP seam injectable — the ONLY difference.
///
/// Exists because `router` hard-coded `HttpProviderClient::default()`, which
/// made every route-level property here untestable without live providers: the
/// [`ProviderClient`] trait was built as a test seam and then buried behind the
/// one constructor tests must use. Production composes through [`router`];
/// tests inject a stub (`tests/oauth_surface_shapes.rs`).
#[doc(hidden)]
pub fn router_with_client(
    engine: Arc<Engine>,
    callback_base: String,
    client: Arc<dyn ProviderClient>,
) -> Router {
    let callback_base = if callback_base.trim().is_empty() {
        callback_base_from_env().unwrap_or_else(|| DEFAULT_OAUTH_CALLBACK_BASE_URL.to_string())
    } else {
        callback_base
    };
    let st = OAuthState {
        engine,
        csrf: Arc::new(Mutex::new(CsrfStore::default())),
        providers: Arc::new(Mutex::new(ProviderConfigStore::default())),
        handoff: Arc::new(Mutex::new(HandoffStore::default())),
        client,
        boot_callback_base: callback_base,
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
        // ── DEFENCE IN DEPTH ONLY: `/v1/auth/oauth/{agent_id}/{provider}/…` ──
        //
        // In the hosted deployment the node NEVER sees this shape. nginx owns
        // the public three-segment URL and strips the agent-id before
        // forwarding, so what arrives here is two segments — which is why the
        // routes above are correct and always were.
        //
        // These exist for a direct-to-node request that skips the proxy. They
        // are NOT the fix for CIRISServer#421 and must not be mistaken for it:
        // that defect is in what this node EMITS (see `redirect_uri_for`), not
        // in what it routes. Anyone reading these and concluding the emitted
        // URI should be made to match them would re-break every hosted login.
        .route(
            "/v1/auth/oauth/{agent_id}/{provider}/login",
            axum::routing::get(oauth_login),
        )
        .route(
            "/v1/auth/oauth/{agent_id}/{provider}/callback",
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
        let (t, _challenge) = s.issue(None, None);
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
        let (state, challenge) = s.issue(None, None);
        let verifier = s
            .consume(&state)
            .expect("verifier on first consume")
            .code_verifier;

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
            callback_url: None,
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
        let (state, _c) = s.issue(Some("app-nonce-123".into()), None);
        let consumed = s.consume(&state).expect("first consume");
        assert_eq!(consumed.app_nonce.as_deref(), Some("app-nonce-123"));
        assert!(s.consume(&state).is_none(), "state is still one-use");
    }

    /// The post-login destination survives the round trip on the SAME one-use
    /// entry as the verifier — it was validated at `oauth_login` and then
    /// DROPPED, which is CIRISAgent#1057 finding 5: a web client that asked
    /// for `/dashboard` always landed on the static hand-off page.
    #[test]
    fn the_post_login_redirect_rides_the_one_use_state() {
        let mut s = CsrfStore::default();
        let (state, _c) = s.issue(None, Some("/dashboard".into()));
        let consumed = s.consume(&state).expect("first consume");
        assert_eq!(consumed.post_login_redirect.as_deref(), Some("/dashboard"));
        assert!(s.consume(&state).is_none(), "state is still one-use");
    }

    /// `has_pending_nonce` answers "is the human still at the provider" — the
    /// hand-off poll's *keep waiting* verdict before the callback ever runs
    /// (CIRISServer#425).
    #[test]
    fn a_pending_authorization_is_visible_by_its_nonce_until_consumed() {
        let mut s = CsrfStore::default();
        let (state, _c) = s.issue(Some("n-pending".into()), None);
        assert!(s.has_pending_nonce("n-pending"), "unconsumed ⇒ pending");
        assert!(!s.has_pending_nonce("some-other-nonce"));
        let _ = s.consume(&state);
        assert!(
            !s.has_pending_nonce("n-pending"),
            "consumed ⇒ no longer pending here — the in-flight marker on the \
             HandoffStore takes over for the exchange window"
        );
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
            session: session::SessionGrant {
                access_token: "sess:wa-x:abc".into(),
                token_type: "Bearer",
                expires_in: 86_400,
                role: "SYSTEM_ADMIN".into(),
                user_id: "oauth-google-123".into(),
            },
            provider: "google".into(),
            external_id: "123".into(),
            email: Some("a@b.c".into()),
            id_token: None,
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
            body.contains("serde_json::to_value(&p)"),
            "oauth_handoff must serialize the payload ITSELF (the additive status member is \
             inserted into that same object, never wrapped around it)"
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
    /// Test fixture: a Complete outcome around a flattened payload.
    fn complete(token: &str) -> HandoffOutcome {
        HandoffOutcome::Complete(HandoffPayload {
            session: session::SessionGrant {
                access_token: token.into(),
                token_type: "Bearer",
                expires_in: 1,
                role: "SYSTEM_ADMIN".into(),
                user_id: "wa-x".into(),
            },
            provider: "google".into(),
            external_id: "sub-1".into(),
            email: None,
            id_token: None,
        })
    }

    /// The desktop app's ONLY view of the provider's ID token is this payload
    /// (CIRISServer#434) — and "absent" must stay distinguishable from "empty".
    ///
    /// The mobile clients get their ID token as the login credential they
    /// themselves supplied, so they never noticed this field missing. Desktop
    /// signs in through a browser and can see only what the hand-off carries,
    /// which is why CIRIS_PROXY — a mode whose api_key IS a Google ID token —
    /// was unselectable there while the user was demonstrably signed in with
    /// Google.
    #[test]
    fn the_handoff_forwards_the_id_token_when_the_provider_issued_one() {
        let mut p = match complete("sess:t") {
            HandoffOutcome::Complete(p) => p,
            _ => unreachable!(),
        };

        // No ID token: the key is ABSENT, never `null` and never "". A client
        // reading it can act on the difference between "this provider issues
        // none" and "one arrived but was empty".
        let v = serde_json::to_value(&p).expect("serializes");
        assert!(
            v.get("id_token").is_none(),
            "a flow with no ID token must omit the key entirely, got {v:?}"
        );

        p.id_token = Some("eyJhbGciOi.PAYLOAD.sig".into());
        let v = serde_json::to_value(&p).expect("serializes");
        assert_eq!(
            v.get("id_token").and_then(|x| x.as_str()),
            Some("eyJhbGciOi.PAYLOAD.sig"),
            "the ID token must reach the app VERBATIM — it is a signed \
             credential, so any re-encoding invalidates it"
        );
        // Flat, alongside the session — not nested under a sub-object the
        // existing clients would have to learn about.
        assert!(
            v.get("access_token").is_some(),
            "still the flat grant shape"
        );
    }

    /// The boot-time hole #435 fills, and the precedence that keeps it safe.
    ///
    /// Serialized on one test rather than split across three: these mutate
    /// PROCESS environment, and cargo runs unit tests on threads of one
    /// process, so separate `#[test]` fns would race each other's `set_var`.
    #[test]
    fn the_callback_base_falls_back_to_the_environment_but_never_over_config() {
        // A helper's `let _ =` on a Result would be a hard no elsewhere in this
        // tree; remove_var returns unit, so there is no outcome being discarded.
        fn clear() {
            std::env::remove_var("CIRIS_OAUTH_CALLBACK_BASE_URL");
            std::env::remove_var("OAUTH_CALLBACK_BASE_URL");
        }

        clear();
        assert_eq!(
            callback_base_from_env(),
            None,
            "a deployment that declared nothing must read as nothing — the \
             loopback default is then chosen by the caller, visibly"
        );

        // The project-prefixed spelling.
        std::env::set_var("CIRIS_OAUTH_CALLBACK_BASE_URL", "https://node.example");
        assert_eq!(
            callback_base_from_env().as_deref(),
            Some("https://node.example")
        );

        // The bare spelling the agent's deployments already set.
        clear();
        std::env::set_var("OAUTH_CALLBACK_BASE_URL", "https://legacy.example");
        assert_eq!(
            callback_base_from_env().as_deref(),
            Some("https://legacy.example"),
            "the fleet has been setting this name all along; refusing to read \
             it would be a distinction with no user behind it"
        );

        // Prefixed WINS over bare when a deployment sets both.
        std::env::set_var("CIRIS_OAUTH_CALLBACK_BASE_URL", "https://node.example");
        assert_eq!(
            callback_base_from_env().as_deref(),
            Some("https://node.example")
        );

        // Set-but-empty is NOT a declaration. An unset var in a compose file
        // expands to "", and that must not beat the default with nothing.
        clear();
        std::env::set_var("CIRIS_OAUTH_CALLBACK_BASE_URL", "   ");
        assert_eq!(
            callback_base_from_env(),
            None,
            "whitespace-only is an unexpanded variable, not a callback base"
        );

        clear();
    }

    /// The capture site itself: Google returns `id_token` in the SAME response
    /// this node already parses for `access_token`, and the node was reading
    /// one field and dropping the other.
    ///
    /// Pins the read, not the plumbing — the plumbing is type-checked, but
    /// nothing would make a compiler complain if this parse were deleted and
    /// every downstream `Option` quietly went `None` forever.
    #[test]
    fn the_google_exchange_reads_the_id_token_from_the_token_response() {
        let src = include_str!("oauth.rs");
        let body: String = src
            .split("async fn exchange_google(")
            .nth(1)
            .expect("exchange_google present")
            .split("\n    async fn ")
            .next()
            .expect("function ends")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            body.contains(r#"get("id_token")"#),
            "exchange_google must read id_token out of the token response \
             (CIRISServer#434); without this read the field is None forever \
             and desktop CIRIS_PROXY silently stops working again"
        );
    }

    /// The collected outcome's access token, when it is a Complete.
    fn token_of(o: Option<HandoffOutcome>) -> Option<String> {
        match o {
            Some(HandoffOutcome::Complete(p)) => Some(p.session.access_token),
            _ => None,
        }
    }

    #[test]
    fn a_nonceless_signin_is_claimable_once_from_the_recent_slot() {
        let mut h = HandoffStore::default();
        h.park(None, complete("sess:no-nonce"));
        assert_eq!(
            token_of(h.collect_recent()).as_deref(),
            Some("sess:no-nonce")
        );
        assert!(
            h.collect_recent().is_none(),
            "one-time, like the nonce slot"
        );

        // Claiming BY NONCE must also consume the recent slot, or the same
        // session could be handed out twice.
        let mut h2 = HandoffStore::default();
        h2.park(Some("n".into()), complete("sess:bound"));
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
        h.park(Some("n1".to_string()), complete("sess:wa-x:abc"));
        assert_eq!(token_of(h.collect("n1")).as_deref(), Some("sess:wa-x:abc"));
        assert!(h.collect("n1").is_none(), "second collection must be empty");
        assert!(h.collect("never-parked").is_none());
    }

    /// **A terminal failure is observable on the hand-off slot**
    /// (CIRISServer#425). The slot used to hold only successes, so a desktop
    /// app whose sign-in FAILED at the node polled a 204 forever — "provider
    /// refused" and "human still typing" were the same answer.
    #[test]
    fn a_terminal_failure_is_observable_on_the_handoff_slot() {
        let mut h = HandoffStore::default();
        h.park(
            Some("n-fail".to_string()),
            HandoffOutcome::Failed {
                reason_id: "auth.oauth.exchange_failed",
                message: "the provider rejected the code exchange".into(),
                provider: "google".into(),
            },
        );
        match h.collect("n-fail") {
            Some(HandoffOutcome::Failed {
                reason_id,
                provider,
                ..
            }) => {
                assert_eq!(reason_id, "auth.oauth.exchange_failed");
                assert_eq!(provider, "google");
            }
            other => panic!("expected the parked failure, got {other:?}"),
        }
        assert!(
            h.collect("n-fail").is_none(),
            "a failure is one-time exactly like a success — a replayed nonce learns nothing"
        );
    }

    /// **The consume→park window reads as PENDING, not expired** — the #425
    /// race, at the store level. `oauth_callback` consumes the one-use state
    /// BEFORE the provider round trip; in that window the only pending signal
    /// is the in-flight marker, and `park` (either outcome) retires it.
    #[test]
    fn the_exchange_window_is_pending_via_the_in_flight_marker() {
        let mut csrf = CsrfStore::default();
        let (state, _c) = csrf.issue(Some("n-race".into()), None);
        let mut h = HandoffStore::default();

        let consumed = csrf.consume(&state).expect("consume");
        let nonce = consumed.app_nonce.expect("nonce");
        h.begin_flight(&nonce);

        assert!(
            !csrf.has_pending_nonce("n-race"),
            "the CSRF entry is gone — without the in-flight marker this window reads expired"
        );
        assert!(h.collect("n-race").is_none(), "no outcome yet");
        assert!(
            h.is_in_flight("n-race"),
            "the in-flight marker IS the pending verdict inside the exchange window"
        );

        h.park(Some(nonce), complete("sess:raced"));
        assert!(!h.is_in_flight("n-race"), "park retires the marker");
        assert!(h.collect("n-race").is_some());
    }

    /// **A native success is JSON, never the hand-off page** (CIRISServer#429).
    /// Source-slice over the comment-stripped native path: the defect was the
    /// native exchange sharing the browser's responder, and the Apple client's
    /// decoder receiving HTML after Apple said yes.
    #[test]
    fn native_success_is_json_never_the_handoff_page() {
        let src = include_str!("oauth.rs");
        let after = src
            .split("async fn native_login(")
            .nth(1)
            .expect("native_login present");
        // Bound the slice at the next async fn OR the page const's own
        // definition, whichever comes first — the const is DEFINED between
        // native_login and the next handler, and a slice that swallows the
        // definition fails on correct source (the self-reference lesson this
        // file has now paid for five times).
        let end = after
            .find("\nasync fn ")
            .unwrap_or(after.len())
            .min(after.find("\nconst HANDOFF_PAGE").unwrap_or(after.len()));
        let body: String = after[..end]
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            body.contains("Json("),
            "the native path must answer in JSON"
        );
        assert!(
            !body.contains("HANDOFF_PAGE"),
            "the native path must NEVER reference the browser hand-off page — that is #429"
        );
        assert!(
            !body.contains("wants_json"),
            "and it must not Accept-negotiate either (D1): every default HTTP client sends \
             `Accept: */*`, and negotiating on that is exactly how the page reached the decoder"
        );
    }

    /// **THE GATE THAT WOULD HAVE CAUGHT #429**: every field the PUBLISHED spec
    /// (`client/openapi.json` — the file the client generator consumes) marks
    /// required is present and non-null in what the native path serializes,
    /// plus `token_type`, which the Apple client's hand-rolled decoder declares
    /// non-null despite the spec leaving it defaulted.
    #[test]
    fn the_native_response_carries_every_field_the_published_spec_requires() {
        let spec_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("client/openapi.json");
        let spec: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&spec_path).expect("client/openapi.json unreadable"),
        )
        .expect("client/openapi.json is not valid JSON");
        let mut required: Vec<String> = spec
            .pointer("/components/schemas/NativeTokenResponse/required")
            .and_then(|v| v.as_array())
            .expect("the published spec declares NativeTokenResponse.required")
            .iter()
            .map(|v| v.as_str().expect("required names are strings").to_string())
            .collect();
        assert!(
            !required.is_empty(),
            "an empty required list would make this gate vacuous"
        );
        // The published spec defaults token_type rather than requiring it, but
        // the Apple decoder treats it as non-null — hold the stronger line.
        required.push("token_type".to_string());

        let body = serde_json::to_value(NativeTokenResponse {
            session: session::SessionGrant {
                access_token: "sess:wa-x:nonce.mac".into(),
                token_type: "Bearer",
                expires_in: 86_400,
                role: "SYSTEM_ADMIN".into(),
                user_id: "wa-x".into(),
            },
            email: None,
            name: None,
        })
        .expect("serializes");
        for field in &required {
            assert!(
                body.get(field).is_some_and(|v| !v.is_null()),
                "NativeTokenResponse omits (or nulls) `{field}`, which the published spec \
                 requires — the generated client's decode fails on exactly this, after the \
                 provider already said yes"
            );
        }
        // And the nullable identity fields are EMITTED (null, not absent) —
        // the spec declares them nullable, not omittable.
        for field in ["email", "name"] {
            assert!(
                body.get(field).is_some(),
                "`{field}` must serialize even when absent (as null)"
            );
        }
    }

    /// **A browser refusal escapes the provider name** — the XSS pin
    /// (CIRISServer#424). `provider` comes from the URL path and flows into
    /// error text; rendered unescaped as HTML that is reflected XSS. Both
    /// halves are pinned: the escape, and the shape gate that keeps hostile
    /// segments out of the flow entirely.
    #[test]
    fn a_browser_refusal_escapes_the_provider_name() {
        let hostile = "<script>alert(1)</script>";
        let reason = "auth.oauth.provider_unavailable";
        let page = browser_error_page(
            reason,
            "Sign-in didn't complete",
            &format!("This node cannot sign you in with {hostile}."),
            BROWSER_NEXT_STEP,
            Some("/dash\"><script>alert(2)</script>"),
        );
        assert!(
            !page.contains("<script>alert"),
            "the hostile provider string reached the page UNESCAPED — reflected XSS"
        );
        assert!(
            page.contains("&lt;script&gt;alert(1)"),
            "the text position must carry the escaped form"
        );
        assert!(
            page.contains("&quot;&gt;&lt;script&gt;"),
            "the back-link ATTRIBUTE position must escape quotes too — breaking out of an \
             href is the same XSS one character later"
        );

        // The shape gate is the other half: a hostile segment never becomes a
        // provider at all.
        assert!(!provider_name_is_wellformed(hostile));
        assert!(!provider_name_is_wellformed(""));
        assert!(!provider_name_is_wellformed(&"a".repeat(33)));
        assert!(provider_name_is_wellformed("google"));
        assert!(provider_name_is_wellformed("my-fork_2"));
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
