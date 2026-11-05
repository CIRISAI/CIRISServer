//! **What a node's operator reads is the operator's** (steward 2026-11-05).
//!
//! The read API binds the listen address, `0.0.0.0` by default, so a route with no
//! check of its own is open to the network. Logs, metrics, the event streams and
//! the memory graph each say what this node is doing, and a metrics poller can read
//! a shaped node's real activity, which is what shaping hides.
//!
//! These routes answer two callers: someone on the node's own host, and the owner.
//! The owner's other devices reach them through the mesh relay
//! (`crate::mesh_relay`), which checks the signer against the owner's self-key
//! roster and dispatches here as a local call. So a person sees every node they
//! own from their own client, with no session on the remote node.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use ciris_persist::prelude::Engine;

/// Let the request through for the node's own host, or for an owner session.
pub async fn require_operator(
    State(engine): State<Arc<Engine>>,
    req: Request,
    next: Next,
) -> Response {
    if super::loopback::caller_is_loopback(req.extensions()) {
        return next.run(req).await;
    }
    match crate::federation_peers::require_owner_session(&engine, req.headers()).await {
        Ok(_) => next.run(req).await,
        Err(refused) => refused,
    }
}
