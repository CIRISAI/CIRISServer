//! Data-management endpoints for the client's Data page — mirrors the CIRIS agent's
//! `system/data` surface ([`/home/emoore/CIRISAgent` `data_management.py`]):
//!
//! - `POST /v1/system/data/reset-account` — **data-only** wipe. Clears the persist
//!   DB (and the config/owner-binding CEG it holds) + the claim-PIN, **preserving
//!   all signing-key material** (the node + user fed-ID seeds/seals). The node stays
//!   "you"; the setup wizard re-runs on restart.
//! - `POST /v1/system/data/wipe-signing-key` — **data + keys** wipe. Additionally
//!   destroys the identity dir (Ed25519 / ML-DSA seeds, keyring, the user fed-ID
//!   under `identity/user/`) AND verify's sealed `keys_dir()` — a fresh identity on
//!   restart. Double-confirmed (`confirm` + `confirm_wallet_loss`).
//! - `GET /v1/my-data/lens-identifier` — the Data page's refresh probe. The node
//!   sends no CIRISLens traces, so it reports a node-appropriate identity record
//!   (consent off, zero traces) instead of 404'ing the page.
//!
//! Both wipes are **owner-gated** (SYSTEM_ADMIN + FullAccess). Deletion is
//! best-effort: a sqlite file held open by the running node is unlinked now and gone
//! after the client restarts the node — the response says exactly that.

use std::path::Path;
use std::sync::Arc;

use axum::{
    extract::State, http::HeaderMap, http::StatusCode, response::IntoResponse, response::Response,
    Json,
};
use ciris_persist::prelude::Engine;
use serde::Deserialize;
use serde_json::json;

use crate::config::ServerConfig;

#[derive(Clone)]
struct SystemDataState {
    engine: Arc<Engine>,
    cfg: ServerConfig,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

/// Owner gate — SYSTEM_ADMIN + FullAccess (mirrors `portable_occurrence::require_owner`).
async fn require_owner(engine: &Engine, headers: &HeaderMap) -> Result<(), Response> {
    use crate::auth::roles::{Permission, UserRole};
    use crate::auth::session::resolve_bearer;

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
    match resolve_bearer(engine, token).await {
        Ok(Some(caller))
            if caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) =>
        {
            Ok(())
        }
        Ok(Some(_)) => Err(err(
            StatusCode::FORBIDDEN,
            "data wipe requires the owner (SYSTEM_ADMIN) role",
        )),
        Ok(None) => Err(err(StatusCode::UNAUTHORIZED, "invalid or expired session")),
        Err(e) => Err(err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}"))),
    }
}

/// Best-effort recursive removal. `NotFound` is success (already gone). Returns the
/// first real error's text so the handler can report a partial wipe honestly.
fn remove(path: &Path) -> Result<(), String> {
    let res = if path.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    match res {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// The data-tier paths (cleared by BOTH wipes): the persist DB + everything in the
/// data dir, the claim-PIN sink. Signing keys live OUTSIDE these (in `identity/`).
fn data_paths(cfg: &ServerConfig) -> Vec<std::path::PathBuf> {
    vec![cfg.data_dir.clone(), cfg.claim_pin_file()]
}

/// The key-tier paths (cleared ONLY by the data+keys wipe): the node identity dir
/// (federation seed, transport `.rid`, keyring, AND the user fed-ID under `user/`)
/// plus verify's sealed `keys_dir()` (the ML-DSA-65 halves).
fn key_paths(cfg: &ServerConfig) -> Vec<std::path::PathBuf> {
    vec![
        cfg.identity_dir.clone(),
        ciris_verify_core::ceg_outbox::keys_dir(),
    ]
}

fn wipe_all(paths: &[std::path::PathBuf]) -> Vec<String> {
    paths.iter().filter_map(|p| remove(p).err()).collect()
}

// ─── POST /v1/system/data/reset-account (data-only) ──────────────────────────

#[derive(Debug, Deserialize)]
struct ResetAccountRequest {
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    #[allow(dead_code)]
    reason: Option<String>,
}

async fn reset_account(
    State(st): State<SystemDataState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner(&st.engine, &headers).await {
        return resp;
    }
    let req: ResetAccountRequest = serde_json::from_slice(&body).unwrap_or(ResetAccountRequest {
        confirm: false,
        reason: None,
    });
    if !req.confirm {
        return err(
            StatusCode::BAD_REQUEST,
            "confirmation required: set confirm=true",
        );
    }

    let errors = wipe_all(&data_paths(&st.cfg));
    tracing::warn!(
        wiped = "data-only",
        errors = errors.len(),
        "DATA RESET — persist DB + config cleared; signing keys PRESERVED"
    );
    let success = errors.is_empty();
    let message = if success {
        "Account data reset. Signing key preserved. Restart the app to re-run setup.".to_string()
    } else {
        format!(
            "Data reset completed with {} path error(s); a DB held open by the running \
             node is removed fully on the next restart. {}",
            errors.len(),
            errors.join("; ")
        )
    };
    exit_after_response("data-only reset");
    (
        StatusCode::OK,
        Json(json!({
            "data": {
                "success": true,
                "message": message,
                "signing_key_preserved": true,
            }
        })),
    )
        .into_response()
}

/// Schedule a clean process exit shortly after the current response flushes.
///
/// A wipe clears the persist DB (and, for the key wipe, the signing keys) out
/// from under THIS still-running process, which keeps open handles — so every
/// subsequent query death-spirals with "disk I/O error" (observed in the field).
/// The data are already the desired clean state; the only consistent way back is
/// a fresh boot, which re-runs first-run (the 0.5.58 `open_or_create` unbrick
/// mints a new identity, migrations re-apply, the claim PIN reprints). So we
/// exit ~800ms after responding (enough for the body to reach the client): a
/// desktop launcher / systemd / the operator restarts into the setup wizard.
/// Mirrors the CIRIS agent's wipe-then-restart.
fn exit_after_response(kind: &'static str) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        tracing::warn!(
            wipe = kind,
            "post-wipe: exiting so the node restarts clean into first-run \
             (avoids the disk-I/O death-spiral against the wiped DB)"
        );
        std::process::exit(0);
    });
}

// ─── POST /v1/system/data/wipe-signing-key (data + keys) ──────────────────────

#[derive(Debug, Deserialize)]
struct WipeSigningKeyRequest {
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_wallet_loss: bool,
    #[serde(default)]
    #[allow(dead_code)]
    reason: Option<String>,
}

async fn wipe_signing_key(
    State(st): State<SystemDataState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner(&st.engine, &headers).await {
        return resp;
    }
    let req: WipeSigningKeyRequest =
        serde_json::from_slice(&body).unwrap_or(WipeSigningKeyRequest {
            confirm: false,
            confirm_wallet_loss: false,
            reason: None,
        });
    if !req.confirm {
        return err(
            StatusCode::BAD_REQUEST,
            "confirmation required: set confirm=true",
        );
    }
    if !req.confirm_wallet_loss {
        return err(
            StatusCode::BAD_REQUEST,
            "DANGER: set confirm_wallet_loss=true — this destroys the signing key; \
             any wallet funds are lost forever",
        );
    }

    let mut errors = wipe_all(&data_paths(&st.cfg));
    errors.extend(wipe_all(&key_paths(&st.cfg)));
    tracing::warn!(
        wiped = "data+keys",
        errors = errors.len(),
        "IDENTITY WIPE — data + signing keys destroyed; fresh identity on restart"
    );
    let message = if errors.is_empty() {
        "Signing key and all data wiped. Wallet access permanently destroyed. \
         Restart the app to set up a fresh identity."
            .to_string()
    } else {
        format!(
            "Wipe completed with {} path error(s); files held open by the running node \
             are removed on the next restart. {}",
            errors.len(),
            errors.join("; ")
        )
    };
    exit_after_response("data+keys");
    (
        StatusCode::OK,
        Json(json!({
            "data": {
                "success": true,
                "message": message,
                "wallet_access_destroyed": true,
            }
        })),
    )
        .into_response()
}

// ─── GET /v1/my-data/lens-identifier ──────────────────────────────────────────

async fn lens_identifier(State(st): State<SystemDataState>) -> Response {
    use sha2::{Digest, Sha256};
    let agent_id = st.cfg.key_id.clone();
    // Stable display hash (the key_id already encodes the pubkey fingerprint, so
    // hashing it is a stable per-identity id matching the agent's hash-of-key shape).
    let agent_id_hash = {
        let digest = Sha256::digest(agent_id.as_bytes());
        hex::encode(digest)[..16].to_string()
    };
    // A node sends no CIRISLens traces — report an honest "no telemetry shared" record
    // so the Data page loads instead of 404'ing.
    Json(json!({
        "data": {
            "agent_id_hash": agent_id_hash,
            "agent_id": agent_id,
            "consent_given": false,
            "consent_timestamp": serde_json::Value::Null,
            "trace_level": serde_json::Value::Null,
            "traces_sent": 0,
            "endpoint_url": serde_json::Value::Null,
        }
    }))
    .into_response()
}

/// The system-data + my-data router.
pub fn router(engine: Arc<Engine>, cfg: ServerConfig) -> axum::Router {
    axum::Router::new()
        .route(
            "/v1/system/data/reset-account",
            axum::routing::post(reset_account),
        )
        .route(
            "/v1/system/data/wipe-signing-key",
            axum::routing::post(wipe_signing_key),
        )
        .route(
            "/v1/my-data/lens-identifier",
            axum::routing::get(lens_identifier),
        )
        .with_state(SystemDataState { engine, cfg })
}
