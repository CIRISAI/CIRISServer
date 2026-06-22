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

use axum::routing::get;
use axum::{Json, Router};

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
