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

use super::refusal::refuse;
use super::verify::{self, VerifyError};

#[derive(Clone)]
struct SelfLoginState {
    engine: Arc<Engine>,
    policy: HybridPolicy,
    /// Admin-eligible federation `key_id`s (the auto-mint eligibility allowlist),
    /// resolved at boot from the `auth.admin_key_ids` config:* object (Server 0.5
    /// — no env). Threaded into [`super::bootstrap::is_admin_eligible`].
    admin_key_ids: Arc<Vec<String>>,
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

async fn self_login(State(st): State<SelfLoginState>, headers: HeaderMap, body: Bytes) -> Response {
    // EVERY refusal below is typed + logged via `refuse` (CIRISServer#389).
    // These six arms were the SILENT ones: a signed login ceremony could be
    // refused with a bare string and nothing in the node's log to say the
    // request had even arrived — the exact shape that cost the #1028 adoption.
    //
    // (1) Verify the request signature over its exact body bytes.
    let caller = match verify::verify_request(&st.engine, &headers, &body, st.policy).await {
        Ok(c) => c,
        Err(VerifyError::MissingHeader(h)) => {
            return refuse(
                StatusCode::UNAUTHORIZED,
                "auth.self_login.missing_signature_header",
                format!("missing {h}"),
            )
        }
        Err(VerifyError::NoDirectory) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.self_login.no_directory",
                "no federation directory",
            )
        }
        Err(VerifyError::SignatureInvalid(e)) => {
            return refuse(
                StatusCode::UNAUTHORIZED,
                "auth.self_login.signature_invalid",
                format!("signature verification failed: {e}"),
            )
        }
    };

    // (2) Parse.
    let req: SelfLoginRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "auth.self_login.malformed_body",
                format!("bad request body: {e}"),
            )
        }
    };

    // (3) Admission (§5.6.8.8): the signer must be the identity itself or an
    // admitted occurrence of it — the consenting user OR the generating agent.
    if !verify::signer_acts_for(&st.engine, &caller.key_id, &req.identity_key_id).await {
        return refuse(
            StatusCode::FORBIDDEN,
            "auth.self_login.signer_not_admitted",
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
        Ok(o) => {
            // Auto-mint ROOT for an admin-eligible founder identity (CIRISServer#19,
            // port of `_auto_mint_system_admin_if_needed`): on a successful login the
            // founder's identity becomes WaRole::Root → UserRole::SystemAdmin, so the
            // owner-gated POST /v1/federation/peering is reachable. Non-eligible
            // signers are a no-op; a store failure is logged, never fatal to login
            // (the agent's `except: warn; user can mint manually`).
            let eligible = super::bootstrap::is_admin_eligible(&caller.key_id, &st.admin_key_ids);
            if let Err(e) =
                super::bootstrap::auto_mint_root_if_needed(&st.engine, &caller.key_id, eligible)
                    .await
            {
                tracing::warn!(error = %e, identity = %caller.key_id, "auto-mint ROOT on self-login failed (founder can claim manually)");
            }
            (
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
                .into_response()
        }
        Err(e) => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth.self_login.substrate_error",
            format!("self_at_login: {e}"),
        ),
    }
}

/// The `/v1/self/login` router — merge onto the read-API listener alongside
/// `/v1/identity`. Default [`HybridPolicy::Strict`] (no classical-only path).
///
/// `admin_key_ids` is the boot-resolved `auth.admin_key_ids` config:* allowlist
/// (Server 0.5 — replaces the `CIRIS_ADMIN_KEY_IDS` / `CIRIS_ROOT_KEY_ID` env):
/// an identity in it is auto-minted as ROOT → SYSTEM_ADMIN on first self-login.
pub fn router(engine: Arc<Engine>, policy: HybridPolicy, admin_key_ids: Vec<String>) -> Router {
    Router::new()
        .route("/v1/self/login", axum::routing::post(self_login))
        .with_state(SelfLoginState {
            engine,
            policy,
            admin_key_ids: Arc::new(admin_key_ids),
        })
}
