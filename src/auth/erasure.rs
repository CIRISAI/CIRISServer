//! Erasure — GDPR Art. 17, CEG-native (CIRISServer#9). `POST /v1/auth/erasure`.
//!
//! The right to be forgotten, expressed over the substrate's actor-eviction
//! primitive. In persist v8.4.0 the hard-delete primitive is
//! [`Engine::evict_actor`] (CIRISPersist#125): for the named actor it
//!
//! 1. resolves the actor's live `federation_blobs` holdings,
//! 2. emits a `withdraws` structural composer against each `holds_bytes`
//!    attestation (signed by the Engine's federation signer, canonicalized via
//!    the §121 produce-side discipline — CEG §10.1.2), and
//! 3. hard-deletes the corresponding `federation_blobs` rows.
//!
//! It is **fail-honest**: the blob is deleted even if its `withdraws` emission
//! fails (an orphan withdraws is better than undeleted content); the report's
//! `withdraws_failed` surfaces the partial-failure path so the caller re-invokes.
//!
//! NOTE on the mission brief: it referenced
//! `Engine::evict_fountain_content_hard_delete(content_id, corpus_kind)` for
//! §19.7. That symbol is **NOT present in persist v8.4.0** (verified against the
//! checked-out source). `evict_actor` is the shipped erasure primitive and is in
//! fact stronger — it bundles the §10.1.2 `withdraws` emission with the delete,
//! which the per-content call would have required the caller to do by hand.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::prelude::{Engine, HybridPolicy};
use serde::{Deserialize, Serialize};

use super::verify::{self, VerifyError};

#[derive(Clone)]
struct ErasureState {
    engine: Arc<Engine>,
    policy: HybridPolicy,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

#[derive(Debug, Deserialize)]
struct ErasureRequest {
    /// The actor whose held content is to be erased — the data subject's
    /// `federation_keys.key_id`.
    attesting_key_id: String,
}

#[derive(Debug, Serialize)]
struct ErasureResponse {
    blobs_evicted: usize,
    withdraws_emitted: usize,
    withdraws_failed: usize,
    /// True if more holdings may remain (re-invoke until `blobs_evicted == 0`).
    incomplete: bool,
}

async fn erasure(State(st): State<ErasureState>, headers: HeaderMap, body: Bytes) -> Response {
    let caller = match verify::verify_request(&st.engine, &headers, &body, st.policy).await {
        Ok(c) => c,
        Err(VerifyError::MissingHeader(h)) => {
            return err(StatusCode::UNAUTHORIZED, format!("missing {h}"))
        }
        Err(VerifyError::NoDirectory) => {
            return err(StatusCode::SERVICE_UNAVAILABLE, "no federation directory")
        }
        Err(VerifyError::SignatureInvalid(e)) => {
            return err(
                StatusCode::UNAUTHORIZED,
                format!("signature verification failed: {e}"),
            )
        }
    };

    let req: ErasureRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };

    // Erasure must be authorized by the data subject (or an admitted occurrence
    // of them) — the same §5.6.8.8 admission as consent.
    if !verify::signer_acts_for(&st.engine, &caller.key_id, &req.attesting_key_id).await {
        return err(
            StatusCode::FORBIDDEN,
            "erasure must be authorized by the data subject or an admitted occurrence of it",
        );
    }

    match st
        .engine
        .evict_actor(&req.attesting_key_id, chrono::Utc::now())
        .await
    {
        Ok(report) => (
            StatusCode::OK,
            Json(ErasureResponse {
                blobs_evicted: report.blobs_evicted,
                withdraws_emitted: report.withdraws_emitted,
                withdraws_failed: report.withdraws_failed,
                incomplete: report.blobs_evicted > 0, // re-invoke until zero
            }),
        )
            .into_response(),
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("evict_actor: {e}"),
        ),
    }
}

/// The erasure router. Default [`HybridPolicy::Strict`].
pub fn router(engine: Arc<Engine>, policy: HybridPolicy) -> Router {
    Router::new()
        .route("/v1/auth/erasure", axum::routing::post(erasure))
        .with_state(ErasureState { engine, policy })
}
