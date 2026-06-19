//! Node-side device-authorization grant (RFC 8628 shape) — "authorize an agent
//! to act on my behalf" (CIRISServer device-grant).
//!
//! This is the MIRROR-DIRECTION of [`super::device_auth`]: where `device_auth` is
//! THIS node connecting to a *Portal's* grant (we are the client), this module is
//! THIS node ISSUING grants so an external client/agent can be authorized to act
//! on the OWNER's behalf via the node API (we are the authorization server). It
//! ports the shape of CIRISManager's `ciris_manager/api/device_auth_routes.py`.
//!
//! The flow (RFC 8628 with an OWNER-APPROVAL security core):
//!
//! 1. `POST /v1/auth/device/code  {client_id, scope?}` → `{device_code, user_code,
//!    verification_uri, verification_uri_complete, expires_in, interval}`. The
//!    client shows the human-typeable `user_code` to the owner.
//! 2. The OWNER (authenticated by their hardware-backed fed-ID self-login session)
//!    approves via `POST /v1/auth/device/approve {user_code}` — OWNER-GATED, the
//!    same SYSTEM_ADMIN gate `POST /v1/federation/peering` uses. (Or `…/deny`.)
//!    THIS is the security core: the hardware-rooted owner consents to delegate.
//! 3. The client polls `POST /v1/auth/device/token {device_code, client_id}`:
//!    pending → 428, denied → 403, expired → 410, approved → 200 + a DELEGATED
//!    token carrying the owner's AUTHORITY and the client's ATTRIBUTION.
//!
//! Store is in-memory (MVP, matching the manager's in-process dict): a
//! `device_code → DeviceGrant` map plus a `user_code → device_code` index.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::prelude::Engine;
use serde::{Deserialize, Serialize};

use super::roles::{Permission, UserRole};
use super::session::{
    now_unix, register_delegated_grant, resolve_bearer, DelegatedGrant, SessionCaller,
};

/// Grant lifetime (RFC 8628 `expires_in`, default 600s like the manager).
const GRANT_TTL_SECS: u64 = 600;
/// Recommended client poll interval (RFC 8628 `interval`).
const POLL_INTERVAL_SECS: u64 = 5;
/// The delegated token's lifetime once minted (1h — a short act-on-behalf window).
const DELEGATED_TTL_SECS: u64 = 3_600;
/// Default scope when the client requests none.
const DEFAULT_SCOPE: &str = "owner:act-on-behalf";

/// The approval state of a device grant.
#[derive(Debug, Clone)]
enum GrantStatus {
    /// Awaiting the owner's decision.
    Pending,
    /// The owner approved — carries WHO approved (attribution of the principal).
    Approved {
        owner_wa_id: String,
        owner_role: UserRole,
    },
    /// The owner explicitly denied.
    Denied,
}

/// A pending/approved/denied device-authorization grant.
#[derive(Debug, Clone)]
struct DeviceGrant {
    /// The human-typeable code the owner approves (`XXXX-XXXX`).
    user_code: String,
    /// The requesting client/agent's id (the prospective ACTOR).
    client_id: String,
    /// The requested scope.
    scope: String,
    /// Unix-epoch seconds after which the grant is expired.
    expires_at: u64,
    /// The approval state.
    status: GrantStatus,
}

#[derive(Clone)]
struct DeviceGrantState {
    engine: Arc<Engine>,
    /// `device_code → DeviceGrant`.
    grants: Arc<Mutex<HashMap<String, DeviceGrant>>>,
    /// `user_code → device_code` index (the owner approves by user_code).
    user_index: Arc<Mutex<HashMap<String, String>>>,
    /// Grant TTL in seconds. [`GRANT_TTL_SECS`] in production; overridable for
    /// tests (e.g. `0` to mint an already-expired grant for the 410 path).
    grant_ttl_secs: u64,
}

fn err(code: StatusCode, error: &str) -> Response {
    (code, Json(serde_json::json!({ "error": error }))).into_response()
}

// ─── code generation ─────────────────────────────────────────────────────────

/// The user_code alphabet — Crockford-ish: no ambiguous `0/O/1/I` chars, so an
/// owner can read it off a screen and type it without error.
const USER_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// A human-typeable `XXXX-XXXX` user code from unambiguous chars.
fn gen_user_code() -> String {
    let mut raw = [0u8; 8];
    let _ = getrandom::fill(&mut raw);
    let mut s = String::with_capacity(9);
    for (i, b) in raw.iter().enumerate() {
        if i == 4 {
            s.push('-');
        }
        s.push(USER_CODE_ALPHABET[(*b as usize) % USER_CODE_ALPHABET.len()] as char);
    }
    s
}

/// A `secrets`-style opaque random device code.
fn gen_device_code() -> String {
    use base64::Engine as _;
    let mut raw = [0u8; 32];
    let _ = getrandom::fill(&mut raw);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

// ─── POST /v1/auth/device/code ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct DeviceCodeRequest {
    client_id: String,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
}

async fn device_code(State(st): State<DeviceGrantState>, body: axum::body::Bytes) -> Response {
    let req: DeviceCodeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    if req.client_id.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "client_id is required");
    }
    let scope = req.scope.unwrap_or_else(|| DEFAULT_SCOPE.to_string());
    let user_code = gen_user_code();
    let device_code = gen_device_code();
    let expires_at = now_unix() + st.grant_ttl_secs;

    let grant = DeviceGrant {
        user_code: user_code.clone(),
        client_id: req.client_id,
        scope,
        expires_at,
        status: GrantStatus::Pending,
    };
    st.grants
        .lock()
        .expect("grants lock")
        .insert(device_code.clone(), grant);
    st.user_index
        .lock()
        .expect("user_index lock")
        .insert(user_code.clone(), device_code.clone());

    // The owner approves via POST /v1/auth/device/approve from an owner session;
    // `verification_uri` documents the human-facing approval surface base.
    let verification_uri = "/v1/auth/device".to_string();
    let verification_uri_complete = format!("/v1/auth/device?user_code={user_code}");
    (
        StatusCode::OK,
        Json(DeviceCodeResponse {
            device_code,
            user_code,
            verification_uri,
            verification_uri_complete,
            expires_in: st.grant_ttl_secs,
            interval: POLL_INTERVAL_SECS,
        }),
    )
        .into_response()
}

// ─── owner gate (mirrors federation_admin::require_owner) ─────────────────────

/// Require a live OWNER session: the SAME apex gate `POST /v1/federation/peering`
/// uses — `SYSTEM_ADMIN` role AND [`Permission::FullAccess`], resolved through the
/// session bearer→[`SessionCaller`] bridge. The owner reaches this state by
/// self-login with their hardware-backed (YubiKey/TPM) fed-ID, so an approval is
/// a hardware-rooted human consent to delegate. A delegated token MUST NOT be
/// able to approve further grants (no self-amplification), so reject any caller
/// that is itself an actor (`actor.is_some()`).
async fn require_owner(
    st: &DeviceGrantState,
    headers: &HeaderMap,
) -> Result<SessionCaller, Response> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "missing bearer session token",
        ));
    };
    match resolve_bearer(&st.engine, token).await {
        Ok(Some(caller))
            if caller.actor.is_none()
                && caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) =>
        {
            Ok(caller)
        }
        Ok(Some(_)) => Err(err(
            StatusCode::FORBIDDEN,
            "device-grant approval requires the owner (SYSTEM_ADMIN) role",
        )),
        Ok(None) => Err(err(StatusCode::UNAUTHORIZED, "invalid or expired session")),
        Err(e) => Err(err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}"))),
    }
}

// ─── POST /v1/auth/device/approve  &  /deny (OWNER-GATED) ─────────────────────

#[derive(Debug, Deserialize)]
struct DecisionRequest {
    user_code: String,
}

/// Resolve a `user_code` to its `device_code` via the index.
fn device_code_for_user_code(st: &DeviceGrantState, user_code: &str) -> Option<String> {
    st.user_index
        .lock()
        .expect("user_index lock")
        .get(user_code)
        .cloned()
}

async fn approve(
    State(st): State<DeviceGrantState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // OWNER-GATE FIRST: no information about the grant leaks to a non-owner.
    let owner = match require_owner(&st, &headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let req: DecisionRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    let Some(device_code) = device_code_for_user_code(&st, &req.user_code) else {
        return err(StatusCode::NOT_FOUND, "unknown user_code");
    };
    let mut grants = st.grants.lock().expect("grants lock");
    let Some(grant) = grants.get_mut(&device_code) else {
        return err(StatusCode::NOT_FOUND, "unknown user_code");
    };
    if grant.expires_at <= now_unix() {
        return err(StatusCode::GONE, "expired_token");
    }
    grant.status = GrantStatus::Approved {
        owner_wa_id: owner.wa_id.clone(),
        owner_role: owner.role,
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "approved",
            "user_code": grant.user_code,
            "client_id": grant.client_id,
            "approved_by": owner.wa_id,
        })),
    )
        .into_response()
}

async fn deny(
    State(st): State<DeviceGrantState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner(&st, &headers).await {
        return resp;
    }
    let req: DecisionRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    let Some(device_code) = device_code_for_user_code(&st, &req.user_code) else {
        return err(StatusCode::NOT_FOUND, "unknown user_code");
    };
    let mut grants = st.grants.lock().expect("grants lock");
    let Some(grant) = grants.get_mut(&device_code) else {
        return err(StatusCode::NOT_FOUND, "unknown user_code");
    };
    grant.status = GrantStatus::Denied;
    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "denied", "user_code": grant.user_code })),
    )
        .into_response()
}

// ─── POST /v1/auth/device/token (poll) ────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TokenRequest {
    device_code: String,
    client_id: String,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
}

async fn token(State(st): State<DeviceGrantState>, body: axum::body::Bytes) -> Response {
    let req: TokenRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };

    // Snapshot the grant (and prune it on the terminal mint/expire paths) without
    // holding the lock across the response build.
    let mut grants = st.grants.lock().expect("grants lock");
    let Some(grant) = grants.get(&req.device_code).cloned() else {
        // Unknown device_code — RFC 8628 treats this as an invalid grant.
        return err(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    // client_id binding: the poller MUST be the client the code was issued to.
    if grant.client_id != req.client_id {
        return err(StatusCode::BAD_REQUEST, "invalid_client");
    }
    if grant.expires_at <= now_unix() {
        grants.remove(&req.device_code);
        st.user_index
            .lock()
            .expect("user_index lock")
            .remove(&grant.user_code);
        return err(StatusCode::GONE, "expired_token");
    }

    match grant.status {
        GrantStatus::Pending => err(StatusCode::PRECONDITION_REQUIRED, "authorization_pending"),
        GrantStatus::Denied => err(StatusCode::FORBIDDEN, "access_denied"),
        GrantStatus::Approved {
            owner_wa_id,
            owner_role,
        } => {
            // Single-use: consume the grant so a leaked device_code can't re-mint.
            grants.remove(&req.device_code);
            st.user_index
                .lock()
                .expect("user_index lock")
                .remove(&grant.user_code);
            drop(grants);

            // Mint the DELEGATED token: principal = owner authority, actor =
            // client_id attribution. Registered in the session module's delegated
            // grants registry so `resolve_bearer` resolves it back to a caller with
            // the owner's wa_id/role and `actor = Some(client_id)`.
            let access_token = register_delegated_grant(DelegatedGrant {
                owner_wa_id,
                owner_role,
                client_id: grant.client_id,
                scope: grant.scope,
                expires_at: now_unix() + DELEGATED_TTL_SECS,
            });
            (
                StatusCode::OK,
                Json(TokenResponse {
                    access_token,
                    token_type: "Bearer",
                    expires_in: DELEGATED_TTL_SECS,
                }),
            )
                .into_response()
        }
    }
}

// ─── router ───────────────────────────────────────────────────────────────────

/// The device-grant router — merge onto the read-API listener alongside
/// `session::router` / `api_keys::router` / `self_login::router`. Grants live for
/// [`GRANT_TTL_SECS`] (RFC 8628 `expires_in`).
pub fn router(engine: Arc<Engine>) -> Router {
    router_with_ttl(engine, GRANT_TTL_SECS)
}

/// Build the router with an explicit grant TTL (seconds). Production uses
/// [`router`] (600s); a TTL of `0` mints already-expired grants, letting tests
/// drive the `410 expired_token` poll path deterministically.
pub fn router_with_ttl(engine: Arc<Engine>, grant_ttl_secs: u64) -> Router {
    let state = DeviceGrantState {
        engine,
        grants: Arc::new(Mutex::new(HashMap::new())),
        user_index: Arc::new(Mutex::new(HashMap::new())),
        grant_ttl_secs,
    };
    Router::new()
        .route("/v1/auth/device/code", axum::routing::post(device_code))
        .route("/v1/auth/device/approve", axum::routing::post(approve))
        .route("/v1/auth/device/deny", axum::routing::post(deny))
        .route("/v1/auth/device/token", axum::routing::post(token))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_code_is_typeable_and_unambiguous() {
        let c = gen_user_code();
        assert_eq!(c.len(), 9, "XXXX-XXXX");
        assert_eq!(&c[4..5], "-");
        // No ambiguous chars.
        for ch in c.chars().filter(|c| *c != '-') {
            assert!(
                !"01OI".contains(ch),
                "user_code must avoid ambiguous chars, got {ch}"
            );
            assert!(USER_CODE_ALPHABET.contains(&(ch as u8)));
        }
    }

    #[test]
    fn device_code_is_opaque_random() {
        let a = gen_device_code();
        let b = gen_device_code();
        assert_ne!(a, b);
        assert!(a.len() >= 40, "32 random bytes base64url");
    }
}
