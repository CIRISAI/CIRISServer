//! Consent — CEG-native (CIRISServer#9). `POST /v1/auth/consent`.
//!
//! The 2.x → 3.x shift: once the user's own occurrence is admitted + active
//! (via [`super::self_login`]), CEG **consent** is signed by the user's
//! self-occurrence, not by the agent. A consent record is an attestation:
//! `attestation_upsert_local` (local tier, `cohort_scope: self`) and, when the
//! grant is federation-visible, `attestation_promote` (canonicalize → hybrid-sign
//! → flip tier) — the exact emit recipe `Engine::self_at_login` uses for its own
//! partnership/delegation attestations.
//!
//! This is the same substrate path as [`super::attestation`]; consent is just
//! the `attestation_type: "consent"` specialization with a fixed dimension, so
//! the client doesn't have to assemble the envelope by hand.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::federation::types::{cohort_scope, LocalAttestationInput};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{Engine, HybridPolicy};
use serde::{Deserialize, Serialize};

use super::verify::{self, VerifyError};

#[derive(Clone)]
struct ConsentState {
    engine: Arc<Engine>,
    policy: HybridPolicy,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

#[derive(Debug, Deserialize)]
struct ConsentRequest {
    /// The consenting occurrence's `federation_keys.key_id` (the user's self).
    consenting_key_id: String,
    /// What is being consented to (the consent dimension, e.g. `data_processing`).
    dimension: String,
    /// `true` = grant, `false` = withdraw (the GDPR Art.7(3) withdrawal).
    granted: bool,
    /// Optional subjects the consent names.
    #[serde(default)]
    subject_key_ids: Vec<String>,
    /// Promote to federation visibility?
    #[serde(default)]
    promote: bool,
}

#[derive(Debug, Serialize)]
struct ConsentResponse {
    attestation_id: String,
    granted: bool,
    promoted: bool,
}

async fn consent(State(st): State<ConsentState>, headers: HeaderMap, body: Bytes) -> Response {
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

    let req: ConsentRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };

    // Consent MUST be signed by the consenting user's self-occurrence (or an
    // admitted occurrence of it) — the whole point of the 2.x → 3.x shift.
    if !verify::signer_acts_for(&st.engine, &caller.key_id, &req.consenting_key_id).await {
        return err(
            StatusCode::FORBIDDEN,
            "consent must be signed by the consenting identity or an admitted occurrence of it",
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

    // The CEG consent envelope. MUST carry a `"dimension"` (the (occurrence,
    // dimension) upsert key + the local-tier gate read it).
    let envelope = serde_json::json!({
        "dimension": req.dimension,
        "granted": req.granted,
    });
    let input = LocalAttestationInput {
        attesting_key_id: req.consenting_key_id,
        attested_key_id: None,
        attestation_type: "consent".to_string(),
        weight: None,
        expires_at: None,
        attestation_envelope: envelope,
        subject_key_ids: req.subject_key_ids,
        cohort_scope: cohort_scope::SELF.to_string(),
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
        Json(ConsentResponse {
            attestation_id,
            granted: req.granted,
            promoted,
        }),
    )
        .into_response()
}

/// The consent router. Default [`HybridPolicy::Strict`].
pub fn router(engine: Arc<Engine>, policy: HybridPolicy) -> Router {
    Router::new()
        .route("/v1/auth/consent", axum::routing::post(consent))
        .with_state(ConsentState { engine, policy })
}
