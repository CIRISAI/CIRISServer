//! **HUMANITY_ACCORD server surface** (CIRISServer#41, CC 4.2 / §9.2) — the
//! safe-mesh kill-switch + the accord-holder registry. This is the server-side
//! half that is buildable TODAY on verify v6.6.x's accord verification surface
//! (`humanity_accord::{Invocation, verify_invocation, InvocationDedup}` +
//! `threshold`) and persist v9.4.0's `accord_holder` `federation_keys` rows
//! (`list_keys_by_identity_type`, CIRISPersist#105):
//!
//!   1. `POST /v1/accord/holder` (OWNER-GATED) — admit a holder's **self-signed**
//!      `accord_holder` `SignedKeyRecord` through the canonical
//!      [`Engine::register_federation_key`] gate. Holders self-provision their OWN
//!      keys at genesis (no human provisions another's — runbook §3/§6); the node
//!      owner registers the genesis-established holder records here.
//!   2. `GET /v1/accord-holders` — the **cold-start recognition** roster (runbook
//!      §10.2): a fresh consumer reads the accord-holder pubkeys with NO TOFU, so
//!      it can verify a 2-of-3 invocation against pinned keys.
//!   3. `POST /v1/accord/verify-invocation` — the **authoritative server-side
//!      2-of-3** verification of a HUMANITY_ACCORD invocation (the operational
//!      kill-switch, CC 4.2.1 / §9.2.1): [`verify_invocation`] over the registered
//!      holder set + an [`InvocationDedup`] anti-replay window. The verify CLI's
//!      local quorum is advisory; THIS is canonical (against `federation_keys`).
//!
//! ## What is NOT here yet (and why the mesh waits)
//!
//! The accord keys MUST be held under the **portable high-secure key mode** (FIPS
//! YubiKey + USB-held ML-DSA, both-keys+PIN+touch — CIRISVerify#91) and the
//! multi-party genesis ceremony (co-sign → assemble) + family-management UX
//! (CIRISServer#41 screens 1/2/4) are follow-ons. The canonical mesh stays on the
//! 0.5.X series — 0.6 (+registry) bakes `CANONICAL_BOOTSTRAP_PEERS` and bootstraps
//! the mesh, which MUST NOT happen before the accord kill-switch is enforceable
//! AND its keys are under genuine 2-factor distributed-human custody.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use ciris_persist::federation::types::{identity_type, SignedKeyRecord};
use ciris_persist::prelude::Engine;
use ciris_verify_core::humanity_accord::{verify_invocation, Invocation, InvocationDedup};
use ciris_verify_core::threshold::{ThresholdMember, ThresholdSignature};

use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::resolve_bearer;

/// The §9.2.1 2-of-3 holder threshold (verify enforces this internally; surfaced
/// here for the response + the cold-start roster sanity check).
const ACCORD_THRESHOLD: usize = 2;

#[derive(Clone)]
struct AccordState {
    engine: Arc<Engine>,
    /// §9.2.1 anti-replay window — rejects a duplicate `(kind, invocation_id)`
    /// within its `valid_until`. In-memory (a node restart re-opens the window);
    /// the canonical 2-of-3 holder signatures are the load-bearing check.
    dedup: Arc<Mutex<InvocationDedup>>,
}

fn err(code: StatusCode, error: &str) -> Response {
    (code, Json(serde_json::json!({ "error": error }))).into_response()
}

/// Require a live OWNER session — the SAME apex gate `POST /v1/federation/peering`
/// + the device-grant approval use (`SYSTEM_ADMIN` + [`Permission::FullAccess`],
/// and NOT itself a delegated actor — registering an accord holder is a
/// constitutional governance act, never a self-amplifying delegated one).
async fn require_owner(st: &AccordState, headers: &HeaderMap) -> Result<(), Response> {
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
            Ok(())
        }
        Ok(Some(_)) => Err(err(
            StatusCode::FORBIDDEN,
            "registering an accord holder requires the owner (SYSTEM_ADMIN) role",
        )),
        Ok(None) => Err(err(StatusCode::UNAUTHORIZED, "invalid or expired session")),
        Err(e) => Err(err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}"))),
    }
}

// ─── POST /v1/accord/holder (OWNER-GATED) ─────────────────────────────────────

/// A holder's self-signed `accord_holder` key record (the genesis-established
/// holder identity the node admits). Same `SignedKeyRecord` shape a peer presents
/// — the canonical gate hybrid-verifies the self-signed proof-of-possession.
#[derive(Debug, Deserialize)]
struct RegisterHolderRequest {
    key_record: SignedKeyRecord,
}

async fn register_holder(
    State(st): State<AccordState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner(&st, &headers).await {
        return resp;
    }
    let req: RegisterHolderRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    // The record MUST declare identity_type = accord_holder — this is the role the
    // 2-of-3 kill-switch recognizes; admitting any other type here would be a
    // silent role confusion.
    if req.key_record.record.identity_type != identity_type::ACCORD_HOLDER {
        return err(
            StatusCode::BAD_REQUEST,
            "key_record.identity_type must be \"accord_holder\"",
        );
    }
    let key_id = req.key_record.record.key_id.clone();
    match st.engine.register_federation_key(req.key_record).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "registered": true, "key_id": key_id })),
        )
            .into_response(),
        Err(e) => err(
            StatusCode::BAD_REQUEST,
            &format!("register accord holder (admission gate): {e}"),
        ),
    }
}

// ─── GET /v1/accord-holders (cold-start recognition) ──────────────────────────

#[derive(Debug, Serialize)]
struct HolderSummary {
    key_id: String,
    pubkey_ed25519_base64: String,
    pubkey_ml_dsa_65_base64: Option<String>,
}

/// `GET /v1/accord-holders` — the cold-start recognition roster (runbook §10.2):
/// every `accord_holder` `federation_keys` row, so a fresh consumer can pin the
/// holder pubkeys and verify a 2-of-3 invocation with NO trust-on-first-use.
async fn list_holders(State(st): State<AccordState>) -> Response {
    let rows = match st
        .engine
        .federation_directory()
        .list_keys_by_identity_type(identity_type::ACCORD_HOLDER)
        .await
    {
        Ok(rows) => rows,
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")),
    };
    let holders: Vec<HolderSummary> = rows
        .into_iter()
        .map(|r| HolderSummary {
            key_id: r.key_id,
            pubkey_ed25519_base64: r.pubkey_ed25519_base64,
            pubkey_ml_dsa_65_base64: r.pubkey_ml_dsa_65_base64,
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "threshold": ACCORD_THRESHOLD,
            "holder_count": holders.len(),
            "holders": holders,
        })),
    )
        .into_response()
}

// ─── POST /v1/accord/verify-invocation (the kill-switch, server-canonical 2/3) ─

#[derive(Debug, Deserialize)]
struct VerifyInvocationRequest {
    invocation: Invocation,
    /// The (≤ N) holder cosignatures toward the 2-of-3. Each `member_id` MUST be a
    /// registered `accord_holder` `key_id`.
    signatures: Vec<ThresholdSignature>,
    /// §9.2.1 canonical RFC-3339 "now" the dedup window evicts against. Supplied by
    /// the caller (the node has no wall-clock injection seam in this handler).
    now: String,
}

/// `POST /v1/accord/verify-invocation` — the AUTHORITATIVE server-side 2-of-3
/// verification of a HUMANITY_ACCORD invocation (CC 4.2.1 / §9.2.1). Builds the
/// holder set from the registered `accord_holder` rows, runs [`verify_invocation`]
/// (2-of-3 hybrid sigs over the §9.2.1 canonical bytes), and applies the
/// [`InvocationDedup`] anti-replay window. NOT owner-gated: the 2-of-3 holder
/// signatures ARE the authority; this endpoint is the canonical recognizer a
/// relying node / consumer calls (the verify CLI's local quorum is advisory).
async fn verify_invocation_handler(
    State(st): State<AccordState>,
    body: axum::body::Bytes,
) -> Response {
    let req: VerifyInvocationRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };

    // The holder set the threshold verifies against = the registered accord_holder
    // rows (NOT caller-supplied — the registry is the authority on WHO can halt).
    let rows = match st
        .engine
        .federation_directory()
        .list_keys_by_identity_type(identity_type::ACCORD_HOLDER)
        .await
    {
        Ok(rows) => rows,
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")),
    };
    if rows.len() < ACCORD_THRESHOLD {
        return err(
            StatusCode::CONFLICT,
            "fewer registered accord holders than the 2-of-3 threshold — accord not established",
        );
    }
    let holders: Vec<ThresholdMember> = rows
        .into_iter()
        .map(|r| ThresholdMember {
            member_id: r.key_id,
            ed25519_public_key_base64: r.pubkey_ed25519_base64,
            mldsa65_public_key_base64: r.pubkey_ml_dsa_65_base64,
            role: None,
        })
        .collect();

    // Anti-replay FIRST (fail-closed on a duplicate id within its window).
    {
        let mut dedup = st.dedup.lock().expect("invocation dedup lock");
        if let Err(e) = dedup.record_or_reject(&req.invocation, &req.now) {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "verified": false,
                    "reason": "duplicate_invocation",
                    "detail": e.to_string(),
                })),
            )
                .into_response();
        }
    }

    match verify_invocation(&req.invocation, &holders, &req.signatures) {
        Ok(valid) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "verified": true,
                "kind": req.invocation.invocation_kind.as_str(),
                "invocation_id": req.invocation.invocation_id,
                "valid_signatures": valid,
                "threshold": ACCORD_THRESHOLD,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "verified": false,
                "reason": "quorum_not_met",
                "detail": e.to_string(),
                "threshold": ACCORD_THRESHOLD,
            })),
        )
            .into_response(),
    }
}

/// The accord router — merge onto the read-API listener.
pub fn router(engine: Arc<Engine>) -> Router {
    let state = AccordState {
        engine,
        dedup: Arc::new(Mutex::new(InvocationDedup::new())),
    };
    Router::new()
        .route("/v1/accord/holder", axum::routing::post(register_holder))
        .route("/v1/accord-holders", axum::routing::get(list_holders))
        .route(
            "/v1/accord/verify-invocation",
            axum::routing::post(verify_invocation_handler),
        )
        .with_state(state)
}
