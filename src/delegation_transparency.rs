//! Delegation transparency — the "no silent authority" middleware.
//!
//! Whenever a request is authenticated by a **delegation grant** (`dgrant:` bearer),
//! this layer attaches the grant's FULL [`GrantCharacteristics`](crate::auth::session::GrantCharacteristics)
//! to the response as the [`DELEGATION_HEADER`] — on EVERY use, success or error,
//! for every route. So a delegated caller can always see exactly what authority it
//! is operating under (scope, purpose, expiry, backing attestation, the acting
//! actor + the owner it acts for) without having to remember what it was granted.
//!
//! Issuance responses (`/v1/auth/device/{claim,token}`) additionally embed the same
//! object in their JSON body (`"delegation": {…}`), so the very first response the
//! consumer sees already carries it. This layer guarantees the property holds for
//! all *subsequent* calls too, uniformly — a single wrap of the merged router, so
//! any future handler is covered for free (mirrors [`crate::http_log`]).
//!
//! Non-delegated requests (owner sessions, API keys, unauthenticated) are untouched.

use axum::extract::Request;
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

/// The response header carrying the compact-JSON grant characteristics. UTF-8 JSON
/// (obs-text tolerated by `HeaderValue::from_bytes`); consumers parse it as JSON.
pub const DELEGATION_HEADER: &str = "x-ciris-delegation";

/// Axum middleware: for a `dgrant:` bearer, stamp the live grant's characteristics
/// onto the response. Wire as a top-level
/// `.layer(axum::middleware::from_fn(attach_delegation_header))` on the final merged
/// router (see `compose.rs`), alongside the error-logging layer.
pub async fn attach_delegation_header(req: Request, next: Next) -> Response {
    // Snapshot the bearer BEFORE the request is consumed by the inner service.
    let token = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim().to_owned());

    let mut resp = next.run(req).await;

    if let Some(token) = token {
        // Resolves to `None` for any non-delegated / unknown / expired token — a
        // normal owner session or API key never gets the header. The lookup also
        // prunes an expired grant, so a lapsed delegation stops advertising itself.
        if let Some(characteristics) = crate::auth::session::characteristics_for_token(&token) {
            if let Ok(json) = serde_json::to_string(&characteristics) {
                // `from_bytes` tolerates UTF-8 obs-text (a non-ASCII `purpose`),
                // rejecting only control chars — compact JSON has none.
                if let Ok(val) = HeaderValue::from_bytes(json.as_bytes()) {
                    resp.headers_mut().insert(DELEGATION_HEADER, val);
                }
            }
        }
    }
    resp
}
