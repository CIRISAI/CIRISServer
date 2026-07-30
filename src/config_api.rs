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

/// **The config-write delegation-constraint gate** (`CapabilityVerb::ConfigWrite`).
/// A config WRITE is an owner-authority act, so — exactly like peering
/// ([`crate::federation_admin`] gates `CapabilityVerb::Peer`) — a DELEGATED caller
/// may be bounded out of it by the owner's grant (`config_write` on the delegation
/// deny-list, or absent from a set allow-list). An owner acting DIRECTLY
/// (`actor.is_none()`) always passes. Returns the ready `403` to short-circuit, or
/// `None` to proceed. Reads carry no delegatable verb, so this gate is WRITE-only.
///
/// Before this was wired, `config_api` ran only `require_owner_bound` +
/// `require_owner` — the `ConfigWrite` verb existed (`auth::gate`) but nothing
/// invoked it, so a constrained delegate wielding the owner's SYSTEM_ADMIN role
/// could write config the owner's grant meant to forbid. This closes that gap and
/// makes the module's stated "gated the SAME two ways peering is" actually hold.
fn require_config_write(caller: &SessionCaller) -> Option<Response> {
    crate::auth::gate::require_verb(caller, crate::auth::gate::CapabilityVerb::ConfigWrite)
}

/// The serve-only-floor gate (CC 3.2 / CC 1.13.5) — an owner-UNBOUND node refuses
/// every config op. Mirrors the peering handler's `require_owner_bound` check.
async fn require_owner_bound(st: &ConfigApiState) -> Result<(), Response> {
    // ONE identity (#312/#315): the owner-binding subject is the ENGINE's derived
    // federation key — the id the delegates_to(owner→node) rows actually name —
    // never a caller-passed alias.
    let node_key_id = match crate::graph_config::self_key_id(&st.engine).await {
        Ok(id) => id,
        Err(e) => {
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("resolve node identity: {e}").as_str(),
            ))
        }
    };
    if crate::auth::gate::require_owner_bound(&st.engine, &node_key_id)
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
    // (3) delegation-constraint gate — a bounded delegate may be denied `config_write`.
    if let Some(resp) = require_config_write(&caller) {
        return resp;
    }

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

    match graph_config::set_config(&st.engine, &req.key, req.value, &updated_by, req.scope).await {
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
    match graph_config::list_configs(&st.engine, q.prefix.as_deref()).await {
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
    match graph_config::get_config(&st.engine, &key).await {
        Ok(Some(entry)) => (StatusCode::OK, Json(entry)).into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, format!("no config for key {key:?}")),
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("get config: {e}"),
        ),
    }
}

// ─── PUT /v1/config/{key} (owner-gated upsert; the shared-client contract) ────

/// The agent's `ConfigUpdate` body shape (the vendored client SDK targets it):
/// `{ value, reason? }`. The key is in the path; scope defaults (the by-key upsert
/// is the runtime-tunable path — `config:* Local`). `reason` is advisory (audited
/// in the log; the signed row already records `updated_by`).
#[derive(Debug, Deserialize)]
struct UpdateConfigRequest {
    value: ConfigValue,
    #[serde(default)]
    reason: Option<String>,
}

async fn update_config(
    State(st): State<ConfigApiState>,
    headers: HeaderMap,
    Path(key): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner_bound(&st).await {
        return resp;
    }
    let caller = match require_owner(&st, &headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    if let Some(resp) = require_config_write(&caller) {
        return resp;
    }
    if key.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "config key must not be empty");
    }
    let req: UpdateConfigRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    let updated_by = caller.wa_id.clone();
    match graph_config::set_config(
        &st.engine,
        &key,
        req.value,
        &updated_by,
        ConfigScope::default(),
    )
    .await
    {
        Ok(entry) => {
            if let Some(reason) = req.reason.as_deref() {
                tracing::info!(key = %key, reason, "config upsert (PUT /v1/config/{{key}})");
            }
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

// ─── DELETE /v1/config/{key} (owner-gated tombstone) ─────────────────────────

async fn delete_config(
    State(st): State<ConfigApiState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    if let Err(resp) = require_owner_bound(&st).await {
        return resp;
    }
    let caller = match require_owner(&st, &headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    if let Some(resp) = require_config_write(&caller) {
        return resp;
    }
    if key.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "config key must not be empty");
    }
    match graph_config::delete_config(&st.engine, &key, &caller.wa_id).await {
        Ok(_) => {
            if let Some(notify) = st.reconcile_notify.as_ref() {
                notify.notify_one();
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({ "status": "deleted", "key": key })),
            )
                .into_response()
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("delete config: {e}"),
        ),
    }
}

/// The owner-gated config router — merge onto the read-API listener beside the
/// other auth/federation routers in `compose.rs`.
///
/// `reconcile_notify` is the Phase-2 config-reconciler nudge: a successful write
/// fires it (when `Some`). `compose.rs` passes `None` in Phase 1 (no reconciler).
pub fn router(engine: Arc<Engine>, reconcile_notify: Option<Arc<tokio::sync::Notify>>) -> Router {
    let state = ConfigApiState {
        engine,
        reconcile_notify,
    };
    Router::new()
        .route(
            "/v1/config",
            axum::routing::post(set_config).get(list_config),
        )
        .route(
            "/v1/config/{key}",
            axum::routing::get(get_config)
                .put(update_config)
                .delete(delete_config),
        )
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::roles::permissions_for;
    use crate::auth::session::DelegationConstraints;

    /// Build a SessionCaller: `actor=Some` ⇒ delegated (constraints apply);
    /// `actor=None` ⇒ the owner acting directly (unconstrained). Mirrors the
    /// `auth::gate` test helper so the two gates are exercised the same way.
    fn caller(actor: Option<&str>, constraints: Option<DelegationConstraints>) -> SessionCaller {
        SessionCaller {
            wa_id: "wa-owner".into(),
            name: actor.unwrap_or("owner").into(),
            role: UserRole::SystemAdmin,
            permissions: permissions_for(UserRole::SystemAdmin),
            constraints,
            actor: actor.map(str::to_string),
        }
    }

    #[test]
    fn owner_direct_config_write_passes() {
        // The owner acting directly is never bounded by delegation constraints.
        assert!(require_config_write(&caller(None, None)).is_none());
    }

    #[test]
    fn delegated_default_grant_may_write_config() {
        // `config_write` is NOT never-delegatable — an unconstrained delegated
        // grant (legacy full grant) passes, exactly like `peer`.
        let c = caller(Some("agent-1"), Some(DelegationConstraints::default()));
        assert!(require_config_write(&c).is_none());
    }

    #[test]
    fn delegated_config_write_on_deny_list_is_refused() {
        // The owner put `config_write` on the delegate's deny-list → 403. This is
        // the enforcement that was UNWIRED before the gate was added to the
        // handlers: a constrained delegate could write config regardless.
        let c = caller(
            Some("agent-1"),
            Some(DelegationConstraints {
                actions_deny: vec!["config_write".into()],
                ..Default::default()
            }),
        );
        let resp =
            require_config_write(&c).expect("a config_write-denied delegate MUST be refused");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn delegated_allow_list_omitting_config_write_is_refused() {
        // A SET allow-list that omits `config_write` denies it (allow-list = the
        // ONLY permitted verbs).
        let c = caller(
            Some("agent-1"),
            Some(DelegationConstraints {
                actions_allow: Some(vec!["announce".into()]),
                ..Default::default()
            }),
        );
        assert!(
            require_config_write(&c).is_some(),
            "config_write absent from a set allow-list must be refused"
        );
    }

    #[test]
    fn delegated_allow_list_including_config_write_passes() {
        let c = caller(
            Some("agent-1"),
            Some(DelegationConstraints {
                actions_allow: Some(vec!["config_write".into()]),
                ..Default::default()
            }),
        );
        assert!(require_config_write(&c).is_none());
    }
}
