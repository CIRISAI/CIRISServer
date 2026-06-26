//! HTTP error-response logging — the "never guess" middleware.
//!
//! Every 4xx/5xx the node returns is logged to the node log file
//! (`<home>/logs/ciris-server.log`, see [`crate::init_tracing_with`]) with the
//! request method + path + status + the **full** JSON error body. So a failed
//! request always leaves a complete trace on disk — even when the client
//! truncates the HTTP body in its own logs (the createDelegation-500 lesson,
//! where the load-bearing `verify_hybrid_required` / `attesting_key_id` detail
//! was cut off client-side and we had to reproduce by hand).
//!
//! There are 22 per-module `err(...)` helpers + inline error responses across
//! the handlers; none log. Rather than touch all of them, this single layer wraps
//! the whole router so coverage is total and uniform — and any future handler is
//! covered for free. Success responses stream through untouched; only the error
//! path buffers the (tiny) body.

use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

/// Cap the error body we buffer for logging. Error JSON is tiny; this is just a
/// safety bound so a pathological body can't blow up memory.
const MAX_LOG_BODY: usize = 64 * 1024;

/// Axum middleware: log every 4xx/5xx response with its full body. Wire as a
/// top-level `.layer(axum::middleware::from_fn(log_error_responses))` on the
/// final merged router (see `compose.rs`).
pub async fn log_error_responses(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let resp = next.run(req).await;
    let status = resp.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return resp;
    }
    // Buffer the body so we can log it, then rebuild the response unchanged.
    let (parts, body) = resp.into_parts();
    let bytes = match to_bytes(body, MAX_LOG_BODY).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                %method, %uri, status = status.as_u16(),
                "request failed ({}); error body was unreadable: {e}", status.as_u16()
            );
            return Response::from_parts(parts, Body::empty());
        }
    };
    let body_str = String::from_utf8_lossy(&bytes);
    if status.is_server_error() {
        tracing::error!(
            %method, %uri, status = status.as_u16(), body = %body_str,
            "request FAILED (5xx) — full error body above"
        );
    } else {
        tracing::warn!(
            %method, %uri, status = status.as_u16(), body = %body_str,
            "request rejected (4xx) — full error body above"
        );
    }
    Response::from_parts(parts, Body::from(bytes))
}
