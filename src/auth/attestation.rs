//! Attestation (CIRISServer#9) — `POST /v1/auth/attestation`.
//!
//! Port of the agent's `/auth/attestation`: emit a CEG attestation over the
//! shared substrate. Two tiers (CEG §10.1.3 / §10.1.5):
//!
//! - **local** — `FederationDirectory::attestation_upsert_local` writes a
//!   `cohort_scope: self` row, private to the producing occurrence (mirrors
//!   `Engine::self_at_login`'s local-tier emit).
//! - **federation** — `Engine::attestation_promote` canonicalizes the row's
//!   envelope (produce-side JCS, §0.9), hybrid-signs it (Ed25519 + ML-DSA-65),
//!   and flips the tier. The signing bytes are the §0.9-canonical envelope, so a
//!   promoted row is byte-identical to a natively-federation attestation.
//!
//! The signer + canonicalization live entirely inside `attestation_promote`, so
//! the route never touches `ceg_produce_canonicalize` / `sign_hybrid` directly —
//! it just drives the two substrate calls. Federation-signed via [`super::verify`].

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::federation::types::LocalAttestationInput;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{Engine, HybridPolicy};
use serde::{Deserialize, Serialize};

use super::verify::{self, VerifyError};

#[derive(Clone)]
struct AttestState {
    engine: Arc<Engine>,
    policy: HybridPolicy,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

#[derive(Debug, Deserialize)]
struct AttestationRequest {
    /// The producing occurrence's `federation_keys.key_id`.
    attesting_key_id: String,
    /// Primary attested key. Defaults to a self-attestation when omitted.
    #[serde(default)]
    attested_key_id: Option<String>,
    /// The §3 structural primitive (`scores` / `supersedes` / …).
    attestation_type: String,
    /// The CEG attestation envelope — MUST carry a `"dimension"` string.
    attestation_envelope: serde_json::Value,
    #[serde(default)]
    subject_key_ids: Vec<String>,
    /// Promote to the federation tier after the local write?
    #[serde(default)]
    promote: bool,
}

#[derive(Debug, Serialize)]
struct AttestationResponse {
    attestation_id: String,
    promoted: bool,
}

async fn attestation(State(st): State<AttestState>, headers: HeaderMap, body: Bytes) -> Response {
    // Federation-signed request (the producer signs the emit).
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

    let req: AttestationRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };

    // The signer must be the attesting occurrence (or an admitted occurrence of
    // it) — the §5.6.8.8 admission rule (user-direct OR agent-delegate).
    if !verify::signer_acts_for(&st.engine, &caller.key_id, &req.attesting_key_id).await {
        return err(
            StatusCode::FORBIDDEN,
            "signer is neither the attesting key nor an admitted occurrence of it",
        );
    }

    let directory = match st.engine.sqlite_backend() {
        Some(d) => d,
        None => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "no SQLite federation directory",
            )
        }
    };

    let input = LocalAttestationInput {
        attesting_key_id: req.attesting_key_id,
        attested_key_id: req.attested_key_id,
        attestation_type: req.attestation_type,
        weight: None,
        expires_at: None,
        attestation_envelope: req.attestation_envelope,
        subject_key_ids: req.subject_key_ids,
        cohort_scope: "self".to_string(), // local-tier rows MUST be `self`
    };

    let attestation_id = match directory.attestation_upsert_local(input).await {
        Ok(id) => id,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("upsert_local: {e}"),
            )
        }
    };

    let promoted = if req.promote {
        match st.engine.attestation_promote(&attestation_id).await {
            Ok(p) => p,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, format!("promote: {e}")),
        }
    } else {
        false
    };

    (
        StatusCode::OK,
        Json(AttestationResponse {
            attestation_id,
            promoted,
        }),
    )
        .into_response()
}

/// The attestation router. Default [`HybridPolicy::Strict`].
pub fn router(engine: Arc<Engine>, policy: HybridPolicy) -> Router {
    Router::new()
        .route("/v1/auth/attestation", axum::routing::post(attestation))
        .with_state(AttestState { engine, policy })
}
