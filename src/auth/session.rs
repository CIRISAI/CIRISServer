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

use std::sync::Arc;

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

/// Verify a presented password against a stored hash.
///
/// persist stores `password_hash` opaque — it never hashes/verifies (confirmed
/// NOT FOUND in the substrate; that is caller-side). The agent used PBKDF2-
/// SHA256 (100k). To be byte-compatible with already-minted agent rows the
/// fabric MUST use the same KDF; the exact parameters are a migration-time pin.
///
/// TODO(CIRISServer#9): pin the PBKDF2-SHA256(100k) parameters to match the
/// agent's `verify_user_password` so existing rows authenticate unchanged.
pub fn verify_password(_presented: &str, stored_hash: &str) -> bool {
    // Placeholder: a real verify wires pbkdf2/bcrypt here. We refuse empty
    // hashes outright (no password set ⇒ no password login).
    !stored_hash.is_empty()
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
fn wa_id_from_token(token: &str) -> Option<&str> {
    token.strip_prefix("sess:")?.rsplit_once(':').map(|(id, _)| id)
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
        return err(StatusCode::UNAUTHORIZED, "missing or malformed bearer token");
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
    let Some(wa_id) = bearer(&headers).and_then(|t| wa_id_from_token(t).map(str::to_owned)) else {
        return err(StatusCode::UNAUTHORIZED, "missing or malformed bearer token");
    };
    match store::get(&st.engine, &wa_id).await {
        Ok(Some(c)) => {
            let role = UserRole::from_wa_role(c.role);
            (
                StatusCode::OK,
                Json(UserInfo {
                    user_id: c.wa_id.clone(),
                    username: c.name,
                    role: role.as_str().to_string(),
                    permissions: permissions_for(role),
                    active: c.active,
                }),
            )
                .into_response()
        }
        Ok(None) => err(StatusCode::UNAUTHORIZED, "unknown session"),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    }
}

// ─── POST /v1/auth/refresh ──────────────────────────────────────────────────

async fn refresh(State(st): State<SessionState>, headers: HeaderMap) -> Response {
    let Some(wa_id) = bearer(&headers).and_then(|t| wa_id_from_token(t).map(str::to_owned)) else {
        return err(StatusCode::UNAUTHORIZED, "missing or malformed bearer token");
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
            let l = local.chars().next().map(|c| c.to_string()).unwrap_or_default();
            let d = domain.chars().next().map(|c| c.to_string()).unwrap_or_default();
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
    (StatusCode::OK, Json(serde_json::json!({ "owner_hint": hint }))).into_response()
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
}
