//! Localhost-only guard for the setup/apex routes.
//!
//! The setup/bootstrap routes (`/v1/self/identity`, `/v1/setup/claim-remote`,
//! `/v1/setup/root`, `/v1/setup/status`) open during first-run WITHOUT an owner
//! session (see [`super::bootstrap::is_first_run`]). To keep that bootstrap window
//! from being reachable off-box, these routes are additionally restricted to
//! **loopback peers** — the same posture as the agent's default `127.0.0.1` setup
//! bind. The read API itself binds `0.0.0.0:<port+1>` (federation reads are
//! public), so this per-route guard is what scopes the privileged routes to the
//! local operator.
//!
//! Requires the listener to have been served with
//! `into_make_service_with_connect_info::<SocketAddr>()` (done in
//! `ciris-lens-core` `read_api_with_extra`). If peer info is somehow absent, the
//! guard fails CLOSED (403).

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{extract::Request, middleware::Next};

/// Axum middleware: allow the request only when the peer address is loopback
/// (`127.0.0.0/8` or `::1`). Apply via
/// `.layer(axum::middleware::from_fn(require_loopback))` on the setup routers.
/// Is THIS caller on the loopback interface?
///
/// Extracted so the gate and anything that REPORTS the gate read one predicate.
/// `/v1/auth/signin-state` tells a caller which session-delivery route is open
/// to it, and a second copy of this rule there would eventually disagree with
/// the layer that actually enforces it — which is precisely how the
/// loopback-only hand-off became invisible to remote browsers in the first
/// place.
///
/// Missing `ConnectInfo` reads NOT loopback: the permissive direction here
/// would hand a bearer to a caller whose address we could not establish.
pub fn caller_is_loopback(ext: &axum::http::Extensions) -> bool {
    ext.get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().is_loopback())
        .unwrap_or(false)
}

pub async fn require_loopback(req: Request, next: Next) -> Response {
    // `ConnectInfo` is injected by `into_make_service_with_connect_info`. Pull it
    // from extensions so a missing value fails closed rather than 500-ing.
    let is_loopback = caller_is_loopback(req.extensions());

    if is_loopback {
        next.run(req).await
    } else {
        (
            StatusCode::FORBIDDEN,
            "setup routes are localhost-only (run the wizard on the node's own host)",
        )
            .into_response()
    }
}
