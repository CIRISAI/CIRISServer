//! **Config-as-CEG HTTP** (Server 0.5 Phase 1) — the owner-gated `/v1/config`
//! surface over [`crate::graph_config`].
//!
//! Mirrors [`crate::federation_admin`]'s peering handler: a config WRITE is an
//! owner-authority act, so it is gated the SAME two ways peering is —
//!
//!   1. the **serve-only floor** ([`crate::auth::gate::require_owner_bound`]): an
//!      owner-UNBOUND node refuses every config write (it has no responsible party
//!      to root the authority in), and
//!   2. the **SYSTEM_ADMIN (owner) session** gate ([`require_owner`], the same
//!      `resolve_bearer → SessionCaller → role+permission` spine peering uses).
//!
//! Reads are owner-scoped by default — config carries a node's operational posture,
//! so listing/reading config requires the same owner session as a write (matching
//! the consent/safety routes' authenticated posture). The cleartext-from-canonical
//! floor for an unowned node means an unowned node simply has no owner-authored
//! config to serve.
//!
//! ## Phase boundary (load-bearing)
//!
//! This phase ONLY adds the store + API + tests. It removes NO env var. The
//! `reconcile_notify` is plumbed through (and fired on a successful write) so the
//! Phase-2 config reconciler can wire to it without touching this handler; today
//! `compose.rs` passes `None`.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::Deserialize;

use ciris_persist::prelude::Engine;

use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::{resolve_bearer, SessionCaller};
use crate::graph_config::{self, ConfigScope, ConfigValue};

#[derive(Clone)]
struct ConfigApiState {
    engine: Arc<Engine>,
    /// THIS node's federation `key_id` (the `attesting_key_id` of every config row
    /// it authors, and the owner-binding subject the gate checks).
    node_key_id: String,
    /// Phase-2 config-reconciler nudge — fired after a successful write. `None`
    /// today (no reconciler wired yet); the signal is harmless when present.
    reconcile_notify: Option<Arc<tokio::sync::Notify>>,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// Owner-authority gate — IDENTICAL to [`crate::federation_admin`]'s `require_owner`:
/// require the `SYSTEM_ADMIN` (owner) role AND its [`Permission::FullAccess`].
/// Returns the verified caller, or a `401`/`403`/`503` response to short-circuit.
async fn require_owner(
    st: &ConfigApiState,
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
            if caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) =>
        {
            Ok(caller)
        }
        Ok(Some(_)) => Err(err(
            StatusCode::FORBIDDEN,
            "config management requires the owner (SYSTEM_ADMIN) role",
        )),
        Ok(None) => Err(err(StatusCode::UNAUTHORIZED, "invalid or expired session")),
        Err(e) => Err(err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}"))),
    }
}

/// The serve-only-floor gate (CC 3.2 / CC 1.13.5) — an owner-UNBOUND node refuses
/// every config op. Mirrors the peering handler's `require_owner_bound` check.
async fn require_owner_bound(st: &ConfigApiState) -> Result<(), Response> {
    if crate::auth::gate::require_owner_bound(&st.engine, &st.node_key_id)
        .await
        .is_err()
    {
        return Err(err(
            StatusCode::FORBIDDEN,
            "this node has no responsible party (owner-binding) — config refused; an unowned \
             node serves cleartext from the canonical root only (CC 3.2 / CC 1.13.5). Claim \
             ownership first via POST /v1/setup/root.",
        ));
    }
    Ok(())
}

// ─── POST /v1/config (owner-gated write) ─────────────────────────────────────

#[derive(Debug, Deserialize)]
struct SetConfigRequest {
    key: String,
    value: ConfigValue,
    #[serde(default)]
    scope: ConfigScope,
}

async fn set_config(
    State(st): State<ConfigApiState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // (1) serve-only floor: unowned node refuses (independent of the session).
    if let Err(resp) = require_owner_bound(&st).await {
        return resp;
    }
    // (2) owner session.
    let caller = match require_owner(&st, &headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let req: SetConfigRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    if req.key.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "config key must not be empty");
    }

    // `updated_by` = the authenticated owner identity (the directing party) —
    // the session's `wa_id` (the absorbed login identifier).
    let updated_by = caller.wa_id.clone();

    match graph_config::set_config(
        &st.engine,
        &st.node_key_id,
        &req.key,
        req.value,
        &updated_by,
        req.scope,
    )
    .await
    {
        Ok(entry) => {
            // Phase-2 reconciler nudge (no-op today — None).
            if let Some(notify) = st.reconcile_notify.as_ref() {
                notify.notify_one();
            }
            (StatusCode::OK, Json(entry)).into_response()
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("set config: {e}"),
        ),
    }
}

// ─── GET /v1/config[?prefix=] (owner-gated list) ─────────────────────────────

#[derive(Debug, Deserialize)]
struct ListQuery {
    prefix: Option<String>,
}

async fn list_config(
    State(st): State<ConfigApiState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Response {
    if let Err(resp) = require_owner_bound(&st).await {
        return resp;
    }
    if let Err(resp) = require_owner(&st, &headers).await {
        return resp;
    }
    match graph_config::list_configs(&st.engine, &st.node_key_id, q.prefix.as_deref()).await {
        Ok(map) => (StatusCode::OK, Json(map)).into_response(),
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("list config: {e}"),
        ),
    }
}

// ─── GET /v1/config/{key} (owner-gated read) ─────────────────────────────────

async fn get_config(
    State(st): State<ConfigApiState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    if let Err(resp) = require_owner_bound(&st).await {
        return resp;
    }
    if let Err(resp) = require_owner(&st, &headers).await {
        return resp;
    }
    match graph_config::get_config(&st.engine, &st.node_key_id, &key).await {
        Ok(Some(entry)) => (StatusCode::OK, Json(entry)).into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, format!("no config for key {key:?}")),
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("get config: {e}"),
        ),
    }
}

/// The owner-gated config router — merge onto the read-API listener beside the
/// other auth/federation routers in `compose.rs`.
///
/// `reconcile_notify` is the Phase-2 config-reconciler nudge: a successful write
/// fires it (when `Some`). `compose.rs` passes `None` in Phase 1 (no reconciler).
pub fn router(
    engine: Arc<Engine>,
    node_key_id: String,
    reconcile_notify: Option<Arc<tokio::sync::Notify>>,
) -> Router {
    let state = ConfigApiState {
        engine,
        node_key_id,
        reconcile_notify,
    };
    Router::new()
        .route(
            "/v1/config",
            axum::routing::post(set_config).get(list_config),
        )
        .route("/v1/config/{key}", axum::routing::get(get_config))
        .with_state(state)
}
