//! Self-at-login (§8.1.12.7) — the login ceremony of the auth subsystem.
//!
//! Composes persist v8.4.0's [`Engine::self_at_login`] (CIRISPersist#183): an
//! **app** occurrence (`device_class: phone | laptop`) and an **agent**
//! occurrence (`device_class: agent`) are co-admitted as two occurrences of ONE
//! user identity, self-DEK-cascaded, partnered, delegated (user → agent), and
//! promoted to the federation tier. The substrate does the flow; this is the
//! wiring.
//!
//! It is the prerequisite for **user-managed consent** (the 2.x → 3.x shift):
//! once the user's own occurrence is admitted + active, CEG consent (and
//! `withdraws`/erasure — GDPR Art. 17) are signed by the user's self-occurrence,
//! not by the agent.
//!
//! Endpoint: `POST /v1/self/login`, federation-signed by the user's identity
//! **or any admitted occurrence of it** (the corrected §5.6.8.8 admission — the
//! consenting user and the generating agent are both valid signers). Verified
//! through [`super::verify`], default [`HybridPolicy::Strict`].

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::engine::{SelfAtLoginInput, SelfAtLoginOccurrence};
use ciris_persist::federation::EncryptionPubkeys;
use ciris_persist::prelude::{Engine, HybridPolicy};
use serde::{Deserialize, Serialize};

use super::verify::{self, VerifyError};

#[derive(Clone)]
struct SelfLoginState {
    engine: Arc<Engine>,
    policy: HybridPolicy,
}

#[derive(Debug, Deserialize)]
struct EncPubkeysDto {
    x25519_base64: String,
    ml_kem_768_base64: String,
}

impl From<EncPubkeysDto> for EncryptionPubkeys {
    fn from(d: EncPubkeysDto) -> Self {
        EncryptionPubkeys {
            x25519_base64: d.x25519_base64,
            ml_kem_768_base64: d.ml_kem_768_base64,
        }
    }
}

#[derive(Debug, Deserialize)]
struct OccurrenceDto {
    occurrence_key_id: String,
    /// `phone | laptop` for the app, `agent` for the agent.
    device_class: String,
    #[serde(default)]
    hardware_attestation: Option<String>,
    #[serde(default)]
    encryption_pubkeys: Option<EncPubkeysDto>,
    #[serde(default)]
    transport_destinations: Vec<(String, String)>,
}

impl From<OccurrenceDto> for SelfAtLoginOccurrence {
    fn from(d: OccurrenceDto) -> Self {
        SelfAtLoginOccurrence {
            occurrence_key_id: d.occurrence_key_id,
            device_class: d.device_class,
            hardware_attestation: d.hardware_attestation,
            encryption_pubkeys: d.encryption_pubkeys.map(Into::into),
            transport_destinations: d.transport_destinations,
        }
    }
}

#[derive(Debug, Deserialize)]
struct SelfLoginRequest {
    identity_key_id: String,
    app: OccurrenceDto,
    agent: OccurrenceDto,
    bilateral_pair_id: String,
    #[serde(default)]
    delegation_scope: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct SelfLoginResponse {
    partnership_grant_id: String,
    partnership_accept_id: String,
    delegation_id: String,
    delegation_promoted: bool,
    self_dek_granted: usize,
    self_dek_excluded: Vec<String>,
    transport_destinations_registered: usize,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

async fn self_login(State(st): State<SelfLoginState>, headers: HeaderMap, body: Bytes) -> Response {
    // (1) Verify the request signature over its exact body bytes.
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

    // (2) Parse.
    let req: SelfLoginRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request body: {e}")),
    };

    // (3) Admission (§5.6.8.8): the signer must be the identity itself or an
    // admitted occurrence of it — the consenting user OR the generating agent.
    if !verify::signer_acts_for(&st.engine, &caller.key_id, &req.identity_key_id).await {
        return err(
            StatusCode::FORBIDDEN,
            "signer is neither the identity key nor an admitted occurrence of it",
        );
    }

    // (4) Drive the substrate flow.
    let input = SelfAtLoginInput {
        identity_key_id: req.identity_key_id,
        app: req.app.into(),
        agent: req.agent.into(),
        bilateral_pair_id: req.bilateral_pair_id,
        delegation_scope: req.delegation_scope,
    };
    match st.engine.self_at_login(input).await {
        Ok(o) => (
            StatusCode::OK,
            Json(SelfLoginResponse {
                partnership_grant_id: o.partnership_grant_id,
                partnership_accept_id: o.partnership_accept_id,
                delegation_id: o.delegation_id,
                delegation_promoted: o.delegation_promoted,
                self_dek_granted: o.self_dek_granted,
                self_dek_excluded: o.self_dek_excluded,
                transport_destinations_registered: o.transport_destinations_registered,
            }),
        )
            .into_response(),
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("self_at_login: {e}"),
        ),
    }
}

/// The `/v1/self/login` router — merge onto the read-API listener alongside
/// `/v1/identity`. Default [`HybridPolicy::Strict`] (no classical-only path).
pub fn router(engine: Arc<Engine>, policy: HybridPolicy) -> Router {
    Router::new()
        .route("/v1/self/login", axum::routing::post(self_login))
        .with_state(SelfLoginState { engine, policy })
}
