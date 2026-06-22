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
//! ## CEG-native delegation (the authority is the graph)
//!
//! The RFC-8628 handshake (`device_code`↔`user_code`, pending/approved/denied) is
//! ephemeral protocol state and stays in-memory. But the AUTHORIZATION itself is a
//! durable, signed, revocable CEG object: on approve the node resolves the LOCAL
//! owner's federation signer and emits a signed `delegates_to(owner → actor,
//! [scope])` attestation (`ownership::emit_signed_attestation`). For a
//! hardware-backed owner identity (YubiKey / TPM / SE) the `sign_hybrid` BLOCKS on
//! the key being inserted + touched — that physical presence IS the consent.
//!
//! - The minted `dgrant:` bearer is only a session credential; its authority is
//!   re-checked against the graph (`reachable_under_scope`) on every use
//!   ([`resolve_bearer`]), so a `withdraws` revokes it immediately.
//! - `GET …/grants` lists the LIVE `delegates_to` edges (the list IS the graph,
//!   not a parallel store); `POST …/revoke` emits a signed `withdraws`.
//! - The actor (`client_id`) MUST be a registered federation identity — it is the
//!   `attested_key_id` of the edge (the put-time FK), so an agent registers its
//!   fed-ID before requesting a code.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::federation::types::attestation_type;
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
/// The durable `delegates_to` edge outlives it; the bearer is just the session.
const DELEGATED_TTL_SECS: u64 = 3_600;
/// Default scope when the client requests none — the act-on-behalf delegation
/// scope stamped on the `delegates_to` edge + re-checked by `reachable_under_scope`.
const DEFAULT_SCOPE: &str = "owner:act-on-behalf";
/// Delegation-chain depth the graph walks re-check (a direct owner→actor edge is
/// depth 1; small cap leaves room for a future deputization hop).
const DELEGATION_DEPTH: usize = 4;

/// The approval state of a device grant.
#[derive(Debug, Clone)]
enum GrantStatus {
    /// Awaiting the owner's decision.
    Pending,
    /// The owner approved — carries WHO approved (attribution of the principal)
    /// and the owner's federation key_id (the `delegates_to` edge issuer, which
    /// the token graph-gate re-checks). The emitted edge's attestation_id is
    /// returned to the approver but not stored: revoke resolves the live edge
    /// from the graph, not from this ephemeral handshake state.
    Approved {
        owner_wa_id: String,
        owner_role: UserRole,
        /// The owner's federation key_id (the edge's `attesting_key_id`).
        owner_key_id: String,
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
    /// The LOCAL responsible-owner's federation key_id (`<keystore_alias>-user`)
    /// — the issuer of the `delegates_to` edge. Its signer is re-opened at approve
    /// time from [`Self::seed_dir`] (hardware presence prompted there).
    owner_key_id: String,
    /// Where the owner's federation signer is re-opened from (the conventional
    /// user-seed path); passed to `resolve_user_signer` on approve/revoke.
    seed_dir: PathBuf,
    /// `device_code → DeviceGrant`.
    grants: Arc<Mutex<HashMap<String, DeviceGrant>>>,
    /// `user_code → device_code` index (the owner approves by user_code).
    user_index: Arc<Mutex<HashMap<String, String>>>,
    /// Grant TTL in seconds. [`GRANT_TTL_SECS`] in production; overridable for
    /// tests (e.g. `0` to mint an already-expired grant for the 410 path).
    grant_ttl_secs: u64,
}

/// Resolve the LOCAL owner's federation signer (re-opening its hardware/software
/// custody from the conventional seed path). For a hardware-backed identity the
/// caller's subsequent `sign_hybrid` BLOCKS until the key is inserted + touched.
/// `Err` is a ready-to-return response (no owner fed-ID ⇒ the node cannot sign a
/// delegation as its owner).
async fn resolve_owner_signer(
    st: &DeviceGrantState,
) -> Result<Arc<ciris_persist::prelude::LocalSigner>, Response> {
    // OwnerSession: the device approve/revoke handlers gate on `require_owner`
    // (SystemAdmin + FullAccess) before reaching here, so the fed-ID is wielded only
    // under a live owner session.
    match crate::compose::resolve_user_signer(
        &st.engine,
        crate::compose::FedIdUse::OwnerSession,
        &st.owner_key_id,
        st.seed_dir.clone(),
    )
    .await
    {
        Ok(Some(signer)) => Ok(signer),
        Ok(None) => Err(err(
            StatusCode::CONFLICT,
            "owner federation identity is not available on this node — the responsible \
             owner must hold a fed-ID here to sign a delegation",
        )),
        Err(e) => Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("resolve owner signer: {e}"),
        )),
    }
}

/// The scope string declared on a `delegates_to` envelope (`scope` is an array or
/// a bare string). Returns the first scope, or empty.
fn edge_scope(envelope: &serde_json::Value) -> String {
    match envelope.get("scope") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(a)) => a
            .first()
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .unwrap_or_default(),
        _ => String::new(),
    }
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
    let client_id = req.client_id.trim().to_string();
    if client_id.is_empty() {
        return err(StatusCode::BAD_REQUEST, "client_id is required");
    }
    // The actor (client_id) IS the `attested_key_id` of the durable
    // `delegates_to` edge approval will emit — it MUST be a registered federation
    // identity (the put-time FK), so the agent registers its fed-ID first. Fail
    // here (not at approve) so the client learns immediately.
    match st
        .engine
        .federation_directory()
        .lookup_public_key(&client_id)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_client: the actor (client_id) must be a registered federation \
                 identity — register the agent's fed-ID before requesting a device code",
            )
        }
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")),
    }
    let scope = req.scope.unwrap_or_else(|| DEFAULT_SCOPE.to_string());
    let user_code = gen_user_code();
    let device_code = gen_device_code();
    let expires_at = now_unix() + st.grant_ttl_secs;

    let grant = DeviceGrant {
        user_code: user_code.clone(),
        client_id,
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
    // Snapshot the pending grant's coordinates without holding the lock across the
    // (hardware-blocking) signing await.
    let (actor_key_id, scope) = {
        let grants = st.grants.lock().expect("grants lock");
        let Some(grant) = grants.get(&device_code) else {
            return err(StatusCode::NOT_FOUND, "unknown user_code");
        };
        if grant.expires_at <= now_unix() {
            return err(StatusCode::GONE, "expired_token");
        }
        if matches!(grant.status, GrantStatus::Approved { .. }) {
            return err(StatusCode::CONFLICT, "already approved");
        }
        (grant.client_id.clone(), grant.scope.clone())
    };

    // Resolve the owner's federation signer (hardware presence prompted on
    // sign_hybrid below for a YubiKey/TPM/SE-backed identity).
    let owner_signer = match resolve_owner_signer(&st).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    // Emit the DURABLE, signed `delegates_to(owner → actor, [scope])` — the
    // act-on-behalf authority lives in the graph, not in memory. Built via the
    // §11.10-admissible envelope helper + the working user-signed emit path
    // (attester == the owner's REGISTERED key_id; sub_delegation = false: the
    // actor may act, not re-delegate). The owner's hardware key is touched HERE.
    let envelope = ciris_persist::federation::delegates_to_envelope(
        &actor_key_id,
        std::slice::from_ref(&scope),
        false,
    );
    let attestation_id = match crate::auth::ownership::emit_signed_attestation(
        &st.engine,
        &owner_signer,
        attestation_type::DELEGATES_TO,
        &actor_key_id,
        envelope,
        vec![actor_key_id.clone()],
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("emit delegates_to(owner→actor): {e}"),
            )
        }
    };

    // Mark approved, carrying the owner identity + the emitted edge (the revoke
    // target). Re-check the grant under lock (it could have expired/raced).
    let mut grants = st.grants.lock().expect("grants lock");
    let Some(grant) = grants.get_mut(&device_code) else {
        return err(StatusCode::NOT_FOUND, "unknown user_code");
    };
    grant.status = GrantStatus::Approved {
        owner_wa_id: owner.wa_id.clone(),
        owner_role: owner.role,
        owner_key_id: owner_signer.key_id().to_string(),
    };
    tracing::info!(
        actor = %actor_key_id,
        owner = %owner_signer.key_id(),
        attestation_id = %attestation_id,
        "owner approved device grant — emitted signed delegates_to(owner → actor, act-on-behalf)"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "approved",
            "user_code": grant.user_code,
            "client_id": grant.client_id,
            "approved_by": owner.wa_id,
            "delegation_attestation_id": attestation_id,
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

    // All in-memory handshake work happens in this block so the (std, !Send)
    // MutexGuard is unambiguously dropped BEFORE the graph-gate await below (an
    // explicit drop() doesn't reliably shorten the async generator's captured
    // region; a block scope does). Terminal paths (unknown/expired/pending/denied)
    // return from inside. On approval the handshake grant is consumed (single-use)
    // and the owner/actor coordinates fall out for the graph gate + mint.
    let (owner_wa_id, owner_role, owner_key_id, client_id, scope) = {
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
            GrantStatus::Pending => {
                return err(StatusCode::PRECONDITION_REQUIRED, "authorization_pending")
            }
            GrantStatus::Denied => return err(StatusCode::FORBIDDEN, "access_denied"),
            GrantStatus::Approved {
                owner_wa_id,
                owner_role,
                owner_key_id,
                ..
            } => {
                // Single-use: consume the handshake so a leaked code can't re-mint.
                grants.remove(&req.device_code);
                st.user_index
                    .lock()
                    .expect("user_index lock")
                    .remove(&grant.user_code);
                (
                    owner_wa_id,
                    owner_role,
                    owner_key_id,
                    grant.client_id,
                    grant.scope,
                )
            }
        }
    };

    // GRAPH GATE before minting: the durable delegates_to(owner → actor) edge must
    // be LIVE (not revoked between approve and this poll). reachable_under_scope is
    // withdraws-aware; a dead edge ⇒ access_denied.
    match st
        .engine
        .reachable_under_scope(&owner_key_id, &client_id, &scope, DELEGATION_DEPTH)
        .await
    {
        Ok(true) => {}
        Ok(false) => return err(StatusCode::FORBIDDEN, "access_denied"),
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")),
    }

    // Mint the DELEGATED bearer: principal = owner authority, actor = client_id
    // attribution. Carries owner_key_id so resolve_bearer re-checks the graph on
    // every use (immediate revocation). The durable authority is the edge; this
    // bearer is just the ephemeral session credential.
    let access_token = register_delegated_grant(DelegatedGrant {
        owner_wa_id,
        owner_role,
        owner_key_id,
        client_id,
        scope,
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

// ─── GET /v1/auth/device/grants (list) + POST /v1/auth/device/revoke (OWNER) ──

#[derive(Debug, Serialize)]
struct GrantSummary {
    /// The actor (agent) the delegation is attributed to (the edge recipient).
    client_id: String,
    /// The granted scope (e.g. `owner:act-on-behalf`).
    scope: String,
    /// The `delegates_to` attestation_id backing the grant (the revoke target).
    attestation_id: String,
}

/// The owner's LIVE act-on-behalf delegations, read FROM THE GRAPH under the
/// owner's DERIVED federation key_id (`owner_fed_id` = the signer's `key_id()` —
/// NOT `st.owner_key_id`, which is the keystore alias the edges are NOT authored
/// under). Outbound `delegates_to(owner → actor)` edges carrying a non-`infra:*`
/// scope (so node owner-bindings are excluded), confirmed live via
/// `reachable_under_scope` (withdraws-aware). Returns `(actor, scope, attestation_id)`.
async fn live_delegations(engine: &Engine, owner_fed_id: &str) -> Vec<(String, String, String)> {
    let dir = engine.federation_directory();
    let rows = dir
        .list_attestations_by(owner_fed_id)
        .await
        .unwrap_or_default();
    let mut out = Vec::new();
    for edge in rows {
        if edge.attestation_type != attestation_type::DELEGATES_TO {
            continue;
        }
        let scope = edge_scope(&edge.attestation_envelope);
        // Skip owner-bindings (infra:*) — those are node ownership, not agency.
        if scope.is_empty() || scope.starts_with("infra:") {
            continue;
        }
        let actor = edge.attested_key_id.clone();
        if engine
            .reachable_under_scope(owner_fed_id, &actor, &scope, DELEGATION_DEPTH)
            .await
            .unwrap_or(false)
        {
            out.push((actor, scope, edge.attestation_id));
        }
    }
    out
}

/// `GET /v1/auth/device/grants` — list the owner's LIVE act-on-behalf delegations.
/// Owner-gated. The list IS the graph (live `delegates_to` edges), not a parallel
/// in-memory store.
async fn list_grants(State(st): State<DeviceGrantState>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_owner(&st, &headers).await {
        return resp;
    }
    // The owner's edges are authored under its DERIVED federation key_id; resolve
    // the signer to learn it (reading the pubkey opens, but does not TOUCH, the key).
    let owner_signer = match resolve_owner_signer(&st).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let grants: Vec<GrantSummary> = live_delegations(&st.engine, owner_signer.key_id())
        .await
        .into_iter()
        .map(|(client_id, scope, attestation_id)| GrantSummary {
            client_id,
            scope,
            attestation_id,
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "grants": grants })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct RevokeRequest {
    client_id: String,
}

/// `POST /v1/auth/device/revoke {client_id}` — withdraw the owner's act-on-behalf
/// delegation(s) to a client. Owner-gated. Emits a signed `withdraws` against each
/// live `delegates_to(owner → client)` edge (the owner's hardware key is touched
/// to sign), then drops any in-memory bearer for the client. Returns how many
/// edges were withdrawn.
async fn revoke(
    State(st): State<DeviceGrantState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner(&st, &headers).await {
        return resp;
    }
    let req: RevokeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    let client_id = req.client_id.trim().to_string();

    // Resolve the owner signer ONCE — its key_id() is the DERIVED id the edges are
    // authored under (for the graph scan) AND the granter that signs the withdraws.
    let owner_signer = match resolve_owner_signer(&st).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    // Find the live edge(s) for this client in the graph (under the derived id).
    let targets: Vec<String> = live_delegations(&st.engine, owner_signer.key_id())
        .await
        .into_iter()
        .filter(|(actor, _, _)| actor == &client_id)
        .map(|(_, _, attestation_id)| attestation_id)
        .collect();

    // Emit a signed `withdraws` against each (owner is the original granter →
    // rule-1 self-revocation; hardware touch on sign).
    let mut revoked = 0usize;
    if !targets.is_empty() {
        for target_id in targets {
            let envelope = ciris_persist::federation::withdraws_attestation_envelope(
                &target_id,
                attestation_type::DELEGATES_TO,
            );
            match crate::auth::ownership::emit_signed_attestation(
                &st.engine,
                &owner_signer,
                attestation_type::WITHDRAWS,
                &client_id,
                envelope,
                vec![client_id.clone()],
            )
            .await
            {
                Ok(_) => revoked += 1,
                Err(e) => {
                    return err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("emit withdraws(delegates_to {target_id}): {e}"),
                    )
                }
            }
        }
    }

    // Drop any ephemeral bearer for the client (the graph re-check would also kill
    // it on next use, but prune eagerly).
    super::session::revoke_delegated_grants_for(&client_id);

    (
        StatusCode::OK,
        Json(serde_json::json!({ "revoked": revoked, "client_id": client_id })),
    )
        .into_response()
}

// ─── router ───────────────────────────────────────────────────────────────────

/// The device-grant router — merge onto the read-API listener alongside
/// `session::router` / `api_keys::router` / `self_login::router`. Grants live for
/// [`GRANT_TTL_SECS`] (RFC 8628 `expires_in`).
///
/// `owner_key_id` is the LOCAL responsible-owner's federation key_id (the issuer
/// of the `delegates_to` edges) and `seed_dir` is where its signer is re-opened
/// (hardware presence prompted on approve/revoke).
pub fn router(engine: Arc<Engine>, owner_key_id: String, seed_dir: PathBuf) -> Router {
    router_with_ttl(engine, owner_key_id, seed_dir, GRANT_TTL_SECS)
}

/// Build the router with an explicit grant TTL (seconds). Production uses
/// [`router`] (600s); a TTL of `0` mints already-expired grants, letting tests
/// drive the `410 expired_token` poll path deterministically.
pub fn router_with_ttl(
    engine: Arc<Engine>,
    owner_key_id: String,
    seed_dir: PathBuf,
    grant_ttl_secs: u64,
) -> Router {
    let state = DeviceGrantState {
        engine,
        owner_key_id,
        seed_dir,
        grants: Arc::new(Mutex::new(HashMap::new())),
        user_index: Arc::new(Mutex::new(HashMap::new())),
        grant_ttl_secs,
    };
    Router::new()
        .route("/v1/auth/device/code", axum::routing::post(device_code))
        .route("/v1/auth/device/approve", axum::routing::post(approve))
        .route("/v1/auth/device/deny", axum::routing::post(deny))
        .route("/v1/auth/device/token", axum::routing::post(token))
        .route("/v1/auth/device/grants", axum::routing::get(list_grants))
        .route("/v1/auth/device/revoke", axum::routing::post(revoke))
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
