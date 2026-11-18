//! **`POST /v1/system/local-shutdown`: the desktop app stops the node it
//! attached to** (0.5.250; CIRISAgent five-platform runs 44006352958,
//! 44127415181 and 44346546111).
//!
//! A device reset deletes the node's home. On Windows a live node's open
//! store handles make `data\` undeletable, so the reset half-failed and the
//! next boot met a half-wiped identity. The client already calls this route
//! and waits until nothing answers before it wipes; until 0.5.250 the node
//! answered 404 and the client gave up at once.
//!
//! It asks the node to stop through the same switch the embedding host's
//! `shutdown_node()` uses ([`crate::node_control::request_shutdown_from`]):
//! the serve drains, releases the store and the ports, and exits.
//!
//! No session, the agent's contract (`routes/system/shutdown.py`), so it is
//! held to the caller's position instead:
//! - a loopback peer only (the setup routes' guard, which fails closed);
//! - never through a proxy: a same-host reverse proxy connects from loopback,
//!   so a relayed request is refused ([`crate::diag::require_direct`]);
//! - never on a server-class node: a seat or a docker server has no desktop
//!   app to reset it, and is stopped by its operator.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};

/// The route the desktop client calls.
pub const ROUTE: &str = "/v1/system/local-shutdown";

/// The router, mounted on the read API beside the diagnostics routes.
pub fn router() -> Router {
    Router::new()
        .route(ROUTE, post(local_shutdown))
        .layer(axum::middleware::from_fn(crate::diag::require_direct))
        .layer(axum::middleware::from_fn(
            crate::auth::loopback::require_loopback,
        ))
}

async fn local_shutdown() -> Response {
    if crate::backend::host_device_class() == ciris_persist::federation::types::device_class::SERVER
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "reason_id": "system.not_a_personal_node",
                "error": "This node is a server; its operator stops it, not an app on this machine.",
            })),
        )
            .into_response();
    }
    crate::node_control::request_shutdown_from("POST /v1/system/local-shutdown (loopback)");
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "state": "stopping" })),
    )
        .into_response()
}
