//! API keys + service tokens (CIRISServer#9) — ported over the substrate.
//!
//! API keys are `wa_cert` rows with `token_type = api_key` and the secret in
//! `api_key_hash` (the agent's `store_api_key` / `revoke_api_key` rode the same
//! table). Service-token **revocation** is the sibling `revoked_service_tokens`
//! substrate (`ServiceTokenRevocationService`, CIRISPersist#64) — the ONLY
//! service-token API in persist (mint stays caller-side; revoke is shared).
//!
//! Routes (port of `routes/auth.py`):
//! - `POST   /v1/auth/api-keys`             — create an API key (secret shown once).
//! - `GET    /v1/auth/api-keys`             — list the caller's API-key certs.
//! - `DELETE /v1/auth/api-keys/{wa_id}`     — revoke (deactivate) an API key.
//! - `POST   /v1/auth/service-token/revoke` — record a service-token revocation.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::prelude::Engine;
use ciris_persist::service_token_revocation::{RevokedServiceToken, ServiceTokenRevocationService};
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::roles::Permission;
use super::session::{resolve_bearer, SessionCaller};
use super::store;

#[derive(Clone)]
struct ApiKeyState {
    engine: Arc<Engine>,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// Authz gate for the api-key + service-token routes: the caller MUST present a
/// live session bearer token whose role carries `manage_user_permissions` — the
/// agent gates these the same way (`routes/auth.py`). Closes the one residual the
/// QA conformance run flagged (these handlers were ungated). Returns the verified
/// caller, or a `401`/`403`/`503` response to short-circuit.
async fn require_manage_users(
    st: &ApiKeyState,
    headers: &HeaderMap,
) -> Result<SessionCaller, Response> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return Err(err(StatusCode::UNAUTHORIZED, "missing bearer session token"));
    };
    match resolve_bearer(&st.engine, token).await {
        Ok(Some(caller))
            if caller
                .permissions
                .contains(&Permission::ManageUserPermissions) =>
        {
            Ok(caller)
        }
        Ok(Some(_)) => Err(err(
            StatusCode::FORBIDDEN,
            "requires manage_user_permissions",
        )),
        Ok(None) => Err(err(StatusCode::UNAUTHORIZED, "invalid or expired session")),
        Err(e) => Err(err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}"))),
    }
}

// ─── POST /v1/auth/api-keys ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CreateApiKeyRequest {
    /// Human-readable label.
    description: String,
    /// Lifetime in minutes (the agent bounds 30..=10080). Optional.
    #[serde(default)]
    expires_in_minutes: Option<i64>,
}

#[derive(Debug, Serialize)]
struct CreateApiKeyResponse {
    /// The secret — shown ONCE; only its hash is stored.
    api_key: String,
    wa_id: String,
    description: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Mint a fresh API-key secret. The row stores only the SHA-256 hash.
fn mint_api_key() -> (String, String) {
    use base64::Engine as _;
    let mut raw = [0u8; 32];
    let _ = getrandom::fill(&mut raw);
    let secret = format!(
        "ak_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
    );
    let hash = hex::encode(Sha256::digest(secret.as_bytes()));
    (secret, hash)
}

async fn create_api_key(
    State(st): State<ApiKeyState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_manage_users(&st, &headers).await {
        return resp;
    }
    let req: CreateApiKeyRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    let (secret, hash) = mint_api_key();
    let now = chrono::Utc::now();
    let wa_id = format!("ak-{}", &hash[..16]);
    let cert = WaCert {
        wa_id: wa_id.clone(),
        name: req.description.clone(),
        role: WaRole::Observer,
        // An API key has no signing pubkey/jwt of its own; mirror the agent's
        // api-key cert shape (api_key_hash carries the secret hash).
        pubkey: String::new(),
        jwt_kid: format!("ak-kid-{}", &hash[..16]),
        password_hash: None,
        api_key_hash: Some(hash),
        oauth_provider: None,
        oauth_external_id: None,
        oauth_links: None,
        veilid_id: None,
        auto_minted: false,
        parent_wa_id: None,
        parent_signature: None,
        scopes: serde_json::json!([]),
        custom_permissions: req
            .expires_in_minutes
            .map(|m| serde_json::json!({ "expires_in_minutes": m })),
        adapter_id: None,
        adapter_name: None,
        adapter_metadata: None,
        token_type: TokenType::ApiKey,
        created: now,
        last_login: None,
        active: true,
    };
    match store::upsert(&st.engine, cert).await {
        Ok(()) => (
            StatusCode::CREATED,
            Json(CreateApiKeyResponse {
                api_key: secret,
                wa_id,
                description: req.description,
                created_at: now,
            }),
        )
            .into_response(),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    }
}

// ─── GET /v1/auth/api-keys ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct ApiKeyInfo {
    wa_id: String,
    description: String,
    active: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used: Option<chrono::DateTime<chrono::Utc>>,
}

async fn list_api_keys(State(st): State<ApiKeyState>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_manage_users(&st, &headers).await {
        return resp;
    }
    // API-key certs ride `role = observer`; filter the listing to api_key type.
    match store::list_by_role(&st.engine, WaRole::Observer, 1000).await {
        Ok(certs) => {
            let keys: Vec<ApiKeyInfo> = certs
                .into_iter()
                .filter(|c| c.token_type == TokenType::ApiKey)
                .map(|c| ApiKeyInfo {
                    wa_id: c.wa_id,
                    description: c.name,
                    active: c.active,
                    created_at: c.created,
                    last_used: c.last_login,
                })
                .collect();
            (StatusCode::OK, Json(serde_json::json!({ "api_keys": keys }))).into_response()
        }
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    }
}

// ─── DELETE /v1/auth/api-keys/{wa_id} ───────────────────────────────────────

async fn revoke_api_key(
    State(st): State<ApiKeyState>,
    headers: HeaderMap,
    Path(wa_id): Path<String>,
) -> Response {
    if let Err(resp) = require_manage_users(&st, &headers).await {
        return resp;
    }
    // Revoke = deactivate (preserve the row for audit — the agent's semantics).
    match store::set_active(&st.engine, &wa_id, false).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => err(StatusCode::NOT_FOUND, "no such API key"),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    }
}

// ─── POST /v1/auth/service-token/revoke ─────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ServiceTokenRevokeRequest {
    /// The service token to revoke (>= 8 chars). Hashed before storage.
    token: String,
    /// Free-form reason (audit trail).
    reason: String,
    /// Who triggered the revocation.
    #[serde(default)]
    revoked_by: Option<String>,
}

#[derive(Debug, Serialize)]
struct ServiceTokenRevokeResponse {
    success: bool,
    /// Partial hash for logging (never the full token).
    token_hash_prefix: String,
}

async fn revoke_service_token(
    State(st): State<ApiKeyState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_manage_users(&st, &headers).await {
        return resp;
    }
    let req: ServiceTokenRevokeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    if req.token.len() < 8 {
        return err(StatusCode::BAD_REQUEST, "token too short");
    }
    let token_hash = hex::encode(Sha256::digest(req.token.as_bytes()));
    let backend = match store::revocation_backend(&st.engine) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    };
    let rec = RevokedServiceToken {
        token_hash: token_hash.clone(),
        revoked_at: chrono::Utc::now(),
        revoked_by: req.revoked_by.unwrap_or_else(|| "fabric".to_string()),
        reason: req.reason,
    };
    match backend.record_revocation(rec).await {
        Ok(()) => (
            StatusCode::OK,
            Json(ServiceTokenRevokeResponse {
                success: true,
                token_hash_prefix: token_hash[..16.min(token_hash.len())].to_string(),
            }),
        )
            .into_response(),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, format!("revocation: {e}")),
    }
}

/// The API-keys + service-token-revoke router.
pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route(
            "/v1/auth/api-keys",
            axum::routing::post(create_api_key).get(list_api_keys),
        )
        .route(
            "/v1/auth/api-keys/{wa_id}",
            axum::routing::delete(revoke_api_key),
        )
        .route(
            "/v1/auth/service-token/revoke",
            axum::routing::post(revoke_service_token),
        )
        .with_state(ApiKeyState { engine })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_key_hashes_to_stored_value() {
        let (secret, hash) = mint_api_key();
        assert!(secret.starts_with("ak_"));
        assert_eq!(hex::encode(Sha256::digest(secret.as_bytes())), hash);
    }
}
