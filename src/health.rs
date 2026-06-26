//! **Server health** — the fabric node's OWN liveness endpoint.
//!
//! The kill-switch/ownership flows aside, a relying client (the desktop/mobile app,
//! a load balancer, a peer) must be able to ask "is this NODE up?" without an agent
//! running on top. That is what ciris-server answers here. It is the MANDATORY base
//! health: a bare node serves it.
//!
//! Layering (CIRISServer = the server; agent = server + brain):
//!   - `GET /health`            — plain liveness (`{"status":"ok"}`), for LBs.
//!   - `GET /v1/health`         — the structured SERVER health the client checks.
//!   - `GET /v1/system/health`  — the SAME server-health base; an agent running on
//!     top INHERITS this endpoint and ENRICHES it with its optional cognitive
//!     health (`cognitive_state`, the 22 services). The agent's cognitive health is
//!     OPTIONAL; the server health is NOT — so the client's required check resolves
//!     here on a bare node, and the agent's adapter extends it when present.
//!
//! Unauthenticated by design (liveness is public; it carries no owner-gated data).

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use ciris_persist::prelude::Engine;

/// Plain liveness — `{"status":"ok","version":"…"}`.
async fn plain_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Structured SERVER health (the `{"data":{…}}` envelope the client parses). A bare
/// node reports `status: "ok"` with no `cognitive_state` — that field appears only
/// when an agent enriches this endpoint (optional). `services` is the server's own
/// (empty at this layer; the agent adds its service map).
async fn server_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "data": {
            "status": "ok",
            "role": "fabric-node",
            "version": env!("CARGO_PKG_VERSION"),
            "services": {},
        }
    }))
}

/// The server-health routes, merged onto the read API. Stateless (liveness only).
pub fn router() -> Router {
    Router::new()
        .route("/health", get(plain_health))
        .route("/v1/health", get(server_health))
        // The base the agent inherits + enriches (optional cognitive health on top).
        .route("/v1/system/health", get(server_health))
}

/// State for the read-only verify-status endpoint: the node Engine (to report its
/// derived federation key_id) + the custody hardware-class label.
#[derive(Clone)]
pub struct VerifyStatusState {
    pub engine: Arc<Engine>,
    /// `TPM_2_0` | `EXTERNAL_SECURE_ELEMENT` | `PKCS11` | `SOFTWARE_ONLY`.
    pub hardware_type: String,
}

/// `GET /v1/system/verify-status` — read-only CIRISVerify / attestation status for
/// the client's Trust & Security display.
///
/// CIRISVerify is part of the node substrate (it's statically linked into the
/// wheel), so `loaded`/`binary_ok` are always true on a bare node; the node's
/// federation identity is reported via its derived key_id. This closes the gap
/// where the client GET-ed the POST-only `/v1/auth/attestation` *emit* route (405)
/// and there was no read-only verify-status route at all. Unauthenticated like
/// `/v1/system/health` — the key_id is public (it's in the NodeCode / federation_keys).
async fn verify_status(State(st): State<VerifyStatusState>) -> Json<serde_json::Value> {
    let key_id = st.engine.local_derived_key_id().await.ok();
    let has_key = key_id.is_some();
    Json(serde_json::json!({
        "data": {
            "loaded": true,
            "binary_ok": true,
            "agent_version": env!("CARGO_PKG_VERSION"),
            "hardware_type": st.hardware_type,
            "key_status": if has_key { "active" } else { "none" },
            "key_id": key_id,
            "attestation_status": if has_key { "verified" } else { "not_attempted" },
            "disclaimer": "CIRISVerify provides cryptographic attestation of agent identity.",
        }
    }))
}

/// The verify-status route (state-bearing — needs the node Engine + custody class).
/// Merged onto the read API next to [`router`].
pub fn verify_status_router(engine: Arc<Engine>, hardware_type: String) -> Router {
    Router::new()
        .route("/v1/system/verify-status", get(verify_status))
        .with_state(VerifyStatusState {
            engine,
            hardware_type,
        })
}
