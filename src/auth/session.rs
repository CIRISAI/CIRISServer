//! The login session — the one token issuer (CIRISServer#9), replacing the
//! agent's OAuth → WA → HS256-JWT chain. The fabric is the **single token
//! issuer**; the agent becomes a consumer.
//!
//! Sessions are NOT a persist primitive (confirmed: persist has `TokenType::
//! Session` rows + `set_active`/`last_login` but no per-session revocation API).
//! So the session issuer is fabric-owned logic over `wa_cert` rows — exactly as
//! the agent did it: a session is a short-lived bearer keyed to an authenticated
//! `wa_id`, revoked by `set_active(false)`.
//!
//! Routes (port of `routes/auth.py`):
//! - `POST /v1/auth/login`     — username+password → session token.
//! - `POST /v1/auth/logout`    — revoke the calling session.
//! - `GET  /v1/auth/me`        — the caller's user info + permissions.
//! - `POST /v1/auth/refresh`   — re-issue a session token.
//! - `GET  /v1/auth/owner-hint`— unauth'd founding-owner hint (masked).

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::prelude::Engine;
use ciris_persist::wa_cert::WaRole;
use serde::{Deserialize, Serialize};

use super::roles::{permissions_for, Permission, Role, UserRole};
use super::store;

/// A bound login session — issued on a successful login. The fabric token is an
/// opaque bearer (`sess_<random>`) bound to the `wa_id`; the binding is checked
/// against the `wa_cert` row's `active` flag on every request.
#[derive(Debug, Clone)]
pub struct Session {
    /// The signed-in occurrence key (`device_class: phone | laptop`).
    pub occurrence_key_id: String,
    /// The identity this occurrence belongs to.
    pub identity_key_id: String,
    /// The roles the identity holds (the CEG role-set).
    pub roles: Vec<Role>,
}

#[derive(Clone)]
struct SessionState {
    engine: Arc<Engine>,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

// ─── Password verification (caller-side; persist stores the hash opaque) ────

/// PBKDF2 parameters — pinned BYTE-FOR-BYTE to the agent's `_hash_password` /
/// `_verify_password` (`services/auth_service.py`):
/// `PBKDF2HMAC(algorithm=SHA256, length=32, salt=secrets.token_bytes(32),
///  iterations=100000)`; stored as `base64(salt(32) || key(32))` (standard
/// base64, NOT url-safe). These MUST NOT change or existing `wa_cert`
/// `password_hash` rows stop authenticating.
const PBKDF2_SALT_LEN: usize = 32;
const PBKDF2_KEY_LEN: usize = 32;
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Hash a password the agent's way: `base64(salt(32) || PBKDF2-HMAC-SHA256(
/// password, salt, 100_000, dklen=32))`. The salt is freshly random per call
/// (so re-hashing the same password yields a different string — exactly the
/// agent's `secrets.token_bytes(32)` behaviour). Used by the user-create helper.
pub fn hash_password(password: &str) -> String {
    use base64::Engine as _;
    let mut salt = [0u8; PBKDF2_SALT_LEN];
    let _ = getrandom::fill(&mut salt);
    let mut key = [0u8; PBKDF2_KEY_LEN];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut key);
    let mut blob = Vec::with_capacity(PBKDF2_SALT_LEN + PBKDF2_KEY_LEN);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&key);
    base64::engine::general_purpose::STANDARD.encode(blob)
}

/// Verify a presented password against a stored hash.
///
/// Byte-compatible port of the agent's `_verify_password`: standard-base64
/// decode the stored hash, split `salt(32) || stored_key(32)`, re-derive
/// PBKDF2-HMAC-SHA256(password, salt, 100_000, dklen=32) and constant-time
/// compare. Any malformed hash (wrong length, bad base64) → `false`, matching
/// the agent's `except: return False`. Empty hash → `false` (no password set ⇒
/// no password login).
pub fn verify_password(presented: &str, stored_hash: &str) -> bool {
    use base64::Engine as _;
    use subtle::ConstantTimeEq as _;
    if stored_hash.is_empty() {
        return false;
    }
    let decoded = match base64::engine::general_purpose::STANDARD.decode(stored_hash) {
        Ok(d) => d,
        Err(_) => return false,
    };
    // The agent slices [:32] / [32:]; a short blob yields a too-short stored_key
    // that can never equal a 32-byte derived key, so reject anything that isn't
    // exactly salt+key length (this is stricter only against corrupt rows).
    if decoded.len() != PBKDF2_SALT_LEN + PBKDF2_KEY_LEN {
        return false;
    }
    let (salt, stored_key) = decoded.split_at(PBKDF2_SALT_LEN);
    let mut key = [0u8; PBKDF2_KEY_LEN];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(presented.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key.ct_eq(stored_key).into()
}

// ─── POST /v1/auth/login ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    role: String,
    user_id: String,
}

/// Issue an opaque session token bound to `wa_id`.
fn issue_session_token(wa_id: &str) -> String {
    use base64::Engine as _;
    let mut raw = [0u8; 24];
    let _ = getrandom::fill(&mut raw);
    let r = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    format!("sess:{wa_id}:{r}")
}

/// Parse the `wa_id` out of an opaque session token (`sess:<wa_id>:<rand>`).
pub fn wa_id_from_token(token: &str) -> Option<&str> {
    token
        .strip_prefix("sess:")?
        .rsplit_once(':')
        .map(|(id, _)| id)
}

/// A bearer→session-resolved caller — the fabric analogue of the agent's
/// `AuthContext`. Returned by [`resolve_bearer`] when a presented bearer token is
/// a live fabric session.
#[derive(Debug, Clone)]
pub struct SessionCaller {
    /// The authenticated `wa_id` (the absorbed login identifier).
    pub wa_id: String,
    /// The caller's display name (`wa_cert.name`).
    pub name: String,
    /// The API role bridged from `wa_cert.role`.
    pub role: UserRole,
    /// The effective permission set for the role.
    pub permissions: Vec<Permission>,
    /// ATTRIBUTION (CIRISServer device-grant): the distinct ACTOR a delegated
    /// device-grant token acts AS. `None` for a normal owner/user session (the
    /// principal IS the actor); `Some(client_id)` for a delegated token issued by
    /// the RFC-8628-shaped device-authorization grant — the caller wields the
    /// owner's AUTHORITY (`wa_id`/`role`/`permissions` are the owner's) but every
    /// action is attributable to this actor, NOT to the owner directly.
    pub actor: Option<String>,
}

// ─── Delegated device-grant token registry (CIRISServer device-grant) ─────────
//
// A delegated token is an opaque random bearer registered HERE when the owner
// approves a device-authorization grant (see `super::device_grant`). It is NOT a
// `wa_cert` session row — it is an in-process grant of the owner's authority to a
// distinct actor (the `client_id`). Kept in-process (MVP, matching the manager's
// in-memory device-code store); a node restart drops outstanding delegations.

/// A live delegated grant: the owner's authority + the actor it is attributed to.
#[derive(Debug, Clone)]
pub struct DelegatedGrant {
    /// The PRINCIPAL — the approving owner's `wa_id`. The delegated caller acts
    /// with this identity's authority.
    pub owner_wa_id: String,
    /// The owner's role at approval time — the authority the actor wields.
    pub owner_role: UserRole,
    /// The ACTOR — the `client_id` the grant was issued to (attribution).
    pub client_id: String,
    /// The granted scope (informational; e.g. `owner:act-on-behalf`).
    pub scope: String,
    /// Unix-epoch seconds after which the delegated token is expired.
    pub expires_at: u64,
}

/// The opaque-delegated-token prefix. A delegated token is `dgrant:<rand>` — a
/// random opaque handle into [`DELEGATED_GRANTS`] (the owner_wa_id / client_id
/// live in the registry, NOT in the token string, so the token leaks nothing).
pub const DELEGATED_TOKEN_PREFIX: &str = "dgrant:";

static DELEGATED_GRANTS: LazyLock<Mutex<HashMap<String, DelegatedGrant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Current unix-epoch seconds.
pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Register a delegated grant and return its opaque bearer token (`dgrant:<rand>`).
/// Called by `super::device_grant` when the owner approves + the client polls.
pub fn register_delegated_grant(grant: DelegatedGrant) -> String {
    use base64::Engine as _;
    let mut raw = [0u8; 24];
    let _ = getrandom::fill(&mut raw);
    let r = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let token = format!("{DELEGATED_TOKEN_PREFIX}{r}");
    DELEGATED_GRANTS
        .lock()
        .expect("delegated grants lock")
        .insert(token.clone(), grant);
    token
}

/// Resolve a delegated token to its live, unexpired grant (expired entries are
/// pruned on access). Returns `None` for an unknown or expired token.
fn lookup_delegated_grant(token: &str) -> Option<DelegatedGrant> {
    let mut map = DELEGATED_GRANTS.lock().expect("delegated grants lock");
    let grant = map.get(token)?.clone();
    if grant.expires_at <= now_unix() {
        map.remove(token);
        return None;
    }
    Some(grant)
}

/// The bearer→session bridge (CIRISServer#9, gap #6).
///
/// Where the agent's `dependencies/auth.py` accepted a bearer **JWT**, the fabric
/// is the single token issuer and accepts its own opaque **session** token. This
/// resolves a raw bearer token (the value AFTER `Bearer `) to a [`SessionCaller`]:
///
/// 1. it MUST be a fabric session token (`sess:<wa_id>:<rand>`) — anything else
///    (API key, `service:` token, `username:password`) is NOT a session and
///    returns `Ok(None)` so the caller can fall through to those other auth modes
///    exactly as the agent's dispatch chain did;
/// 2. the bound `wa_cert` row must exist and be `active` — a logged-out/revoked
///    session (`set_active(false)`) fails closed (`Ok(None)`).
pub async fn resolve_bearer(
    engine: &Engine,
    bearer_token: &str,
) -> Result<Option<SessionCaller>, store::StoreError> {
    // (0) A DELEGATED device-grant token (`dgrant:<rand>`) resolves to a caller
    // wielding the OWNER's authority but ATTRIBUTED to the actor (`client_id`).
    // This is the "auth an agent to act on my behalf" path: principal = owner,
    // actor = client. Checked first because it is a distinct, self-contained
    // token namespace that never touches the wa_cert store.
    if bearer_token.starts_with(DELEGATED_TOKEN_PREFIX) {
        let Some(grant) = lookup_delegated_grant(bearer_token) else {
            return Ok(None); // unknown or expired delegated token — fail closed.
        };
        // Attribution: every authorized action under this token is logged with the
        // distinct actor and the owner it acts on behalf of.
        tracing::info!(
            actor = %grant.client_id,
            on_behalf_of = %grant.owner_wa_id,
            "delegated device-grant caller"
        );
        return Ok(Some(SessionCaller {
            wa_id: grant.owner_wa_id,      // PRINCIPAL: the owner's identity.
            name: grant.client_id.clone(), // display = the acting client.
            role: grant.owner_role,        // AUTHORITY: the owner's role.
            permissions: permissions_for(grant.owner_role),
            actor: Some(grant.client_id), // ATTRIBUTION: the distinct actor.
        }));
    }

    let Some(wa_id) = wa_id_from_token(bearer_token) else {
        return Ok(None); // not a session token — let other auth modes handle it.
    };
    let Some(cert) = store::get(engine, wa_id).await? else {
        return Ok(None);
    };
    if !cert.active {
        return Ok(None);
    }
    let role = UserRole::from_wa_role(cert.role);
    Ok(Some(SessionCaller {
        wa_id: cert.wa_id,
        name: cert.name,
        role,
        permissions: permissions_for(role),
        actor: None, // a normal session: the principal IS the actor.
    }))
}

async fn login(State(st): State<SessionState>, body: axum::body::Bytes) -> Response {
    let req: LoginRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };

    // The agent's `_users` cache scanned `wa_cert` by username. The substrate
    // keys on `wa_id`; the agent treats `wa_id` (or jwt_kid) as the login id.
    // Here `username` IS the `wa_id` (the absorbed identifier).
    let cert = match store::get(&st.engine, &req.username).await {
        Ok(Some(c)) => c,
        Ok(None) => return err(StatusCode::UNAUTHORIZED, "invalid credentials"),
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    };
    if !cert.active {
        return err(StatusCode::FORBIDDEN, "account is inactive");
    }
    let Some(hash) = cert.password_hash.as_deref() else {
        return err(StatusCode::UNAUTHORIZED, "no password set for this account");
    };
    if !verify_password(&req.password, hash) {
        return err(StatusCode::UNAUTHORIZED, "invalid credentials");
    }

    let _ = store::touch_login(&st.engine, &cert.wa_id).await;
    let role = UserRole::from_wa_role(cert.role);
    let token = issue_session_token(&cert.wa_id);
    (
        StatusCode::OK,
        Json(LoginResponse {
            access_token: token,
            token_type: "Bearer",
            expires_in: 86_400,
            role: role.as_str().to_string(),
            user_id: cert.wa_id,
        }),
    )
        .into_response()
}

// ─── POST /v1/auth/logout ───────────────────────────────────────────────────

async fn logout(State(st): State<SessionState>, headers: HeaderMap) -> Response {
    let Some(wa_id) = bearer(&headers).and_then(|t| wa_id_from_token(t).map(str::to_owned)) else {
        return err(
            StatusCode::UNAUTHORIZED,
            "missing or malformed bearer token",
        );
    };
    // Revoke = mark inactive (the agent's `revoke_api_key` semantics: preserve
    // the row for audit). NOTE: this deactivates the WA cert; a per-session
    // revocation list is the finer-grained future increment (sessions are not a
    // persist primitive).
    match store::set_active(&st.engine, &wa_id, false).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    }
}

// ─── GET /v1/auth/me ────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct UserInfo {
    user_id: String,
    username: String,
    role: String,
    permissions: Vec<Permission>,
    active: bool,
}

async fn me(State(st): State<SessionState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer(&headers) else {
        return err(
            StatusCode::UNAUTHORIZED,
            "missing or malformed bearer token",
        );
    };
    // The bearer→session bridge: resolve the opaque session token to its bound,
    // active `wa_cert` row (revoked/logged-out sessions fail closed here).
    match resolve_bearer(&st.engine, token).await {
        Ok(Some(caller)) => (
            StatusCode::OK,
            Json(UserInfo {
                user_id: caller.wa_id,
                username: caller.name,
                role: caller.role.as_str().to_string(),
                permissions: caller.permissions,
                active: true,
            }),
        )
            .into_response(),
        Ok(None) => err(StatusCode::UNAUTHORIZED, "unknown or inactive session"),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    }
}

// ─── POST /v1/auth/refresh ──────────────────────────────────────────────────

async fn refresh(State(st): State<SessionState>, headers: HeaderMap) -> Response {
    let Some(wa_id) = bearer(&headers).and_then(|t| wa_id_from_token(t).map(str::to_owned)) else {
        return err(
            StatusCode::UNAUTHORIZED,
            "missing or malformed bearer token",
        );
    };
    match store::get(&st.engine, &wa_id).await {
        Ok(Some(c)) if c.active => {
            let role = UserRole::from_wa_role(c.role);
            // SYSTEM_ADMIN gets the short (24h) window; others 30d — mirrors the
            // agent's refresh policy.
            let expires_in = if role == UserRole::SystemAdmin {
                86_400
            } else {
                2_592_000
            };
            (
                StatusCode::OK,
                Json(LoginResponse {
                    access_token: issue_session_token(&c.wa_id),
                    token_type: "Bearer",
                    expires_in,
                    role: role.as_str().to_string(),
                    user_id: c.wa_id,
                }),
            )
                .into_response()
        }
        Ok(_) => err(StatusCode::UNAUTHORIZED, "session not active"),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    }
}

// ─── GET /v1/auth/owner-hint (unauthenticated) ──────────────────────────────

#[derive(Debug, Serialize)]
struct OwnerHint {
    masked_email: Option<String>,
    first_name: Option<String>,
    auth_type: Option<String>,
    oauth_provider: Option<String>,
}

/// Mask an email for the GDPR-safe owner hint (`a***@e***.com`).
fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            let l = local
                .chars()
                .next()
                .map(|c| c.to_string())
                .unwrap_or_default();
            let d = domain
                .chars()
                .next()
                .map(|c| c.to_string())
                .unwrap_or_default();
            format!("{l}***@{d}***")
        }
        None => "***".to_string(),
    }
}

async fn owner_hint(State(st): State<SessionState>) -> Response {
    // The founding owner is the earliest ROOT (SYSTEM_ADMIN) WA cert. We list
    // ROOT-role active certs (ordered created DESC) and take the oldest.
    let founder = match store::list_by_role(&st.engine, WaRole::Root, 1000).await {
        Ok(v) => v.into_iter().min_by_key(|c| c.created),
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    };
    let hint = founder.map(|c| {
        // The agent surfaces a masked email + first name only (GDPR). The email
        // lives in oauth_links / name; we mask whatever's available.
        let email = c
            .oauth_links
            .as_ref()
            .and_then(|v| v.get("email"))
            .and_then(|v| v.as_str())
            .map(mask_email);
        OwnerHint {
            masked_email: email,
            first_name: c.name.split_whitespace().next().map(str::to_owned),
            auth_type: Some(c.token_type.as_sql_str().to_string()),
            oauth_provider: c.oauth_provider,
        }
    });
    (
        StatusCode::OK,
        Json(serde_json::json!({ "owner_hint": hint })),
    )
        .into_response()
}

// ─── helpers ────────────────────────────────────────────────────────────────

/// Extract a bearer token from the `Authorization` header.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

/// The session router — merge onto the read-API listener.
pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route("/v1/auth/login", axum::routing::post(login))
        .route("/v1/auth/logout", axum::routing::post(logout))
        .route("/v1/auth/me", axum::routing::get(me))
        .route("/v1/auth/refresh", axum::routing::post(refresh))
        .route("/v1/auth/owner-hint", axum::routing::get(owner_hint))
        .with_state(SessionState { engine })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_token_round_trips_wa_id() {
        let t = issue_session_token("wa-2026-01-01-ABCDEF");
        assert_eq!(wa_id_from_token(&t), Some("wa-2026-01-01-ABCDEF"));
        assert!(t.starts_with("sess:"));
    }

    #[test]
    fn email_masking_is_gdpr_safe() {
        assert_eq!(mask_email("alice@example.com"), "a***@e***");
        assert_eq!(mask_email("nodomain"), "***");
    }

    /// Byte-compat vector produced by the AGENT'S OWN KDF
    /// (`cryptography.PBKDF2HMAC(SHA256, length=32, salt=bytes(range(32)),
    /// iterations=100000).derive(b"correct horse battery staple")`, then
    /// `base64.b64encode(salt + key)`). If this fails, existing agent
    /// `password_hash` rows would stop authenticating after migration.
    #[test]
    fn verify_password_matches_agent_pbkdf2_vector() {
        let agent_hash =
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh/viXCJThHDAjg+nTGyIJeRecLolkEA86maUs3Hzm+fdw==";
        assert!(
            verify_password("correct horse battery staple", agent_hash),
            "must verify the agent-produced PBKDF2-SHA256(100k) hash"
        );
        assert!(
            !verify_password("wrong password", agent_hash),
            "wrong password must fail"
        );
    }

    #[test]
    fn hash_password_round_trips_and_is_salted() {
        let h1 = hash_password("hunter2");
        let h2 = hash_password("hunter2");
        // Fresh random salt each call ⇒ different stored strings (agent parity).
        assert_ne!(h1, h2);
        assert!(verify_password("hunter2", &h1));
        assert!(verify_password("hunter2", &h2));
        assert!(!verify_password("hunter3", &h1));
    }

    #[test]
    fn verify_password_rejects_malformed_hashes() {
        assert!(!verify_password("x", ""), "empty hash ⇒ no password login");
        assert!(!verify_password("x", "not base64 !!!"));
        assert!(!verify_password("x", "dG9vc2hvcnQ="), "too-short blob"); // "tooshort"
    }
}
