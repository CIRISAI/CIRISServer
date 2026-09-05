//! **The one refusal shape of the auth surface** (CIRISServer#389).
//!
//! Every refusal a client can see carries a stable `reason_id` beside the
//! English `error`, and every refusal leaves a node-side log line. Those two
//! properties lived apart: some arms had a typed id and no log, most had a log
//! and no id, and six arms (self-login) had neither — a signed request could be
//! refused with a bare string and NOTHING in the node's log to say the request
//! ever arrived. That is what cost CIRISAgent the #1028 adoption: a 401 whose
//! two possible causes have opposite fixes, and no way to tell which.
//!
//! [`refuse`] binds the id and the log in ONE place, so an arm cannot gain a
//! `reason_id` without gaining the log line, or vice versa. Sites that want
//! structured fields (a `wa_id`, a provider, a scanned-count) emit their own
//! `tracing` event FIRST and then call this — the pattern the oauth login
//! guard already uses. The body shape is the auth surface's `{error,
//! reason_id}` — deliberately NOT admin_ops' envelope; two surfaces, two
//! contracts, and clients bind localization keys against this one.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Refuse with `{error, reason_id}` and log the refusal at INFO.
///
/// `reason_id` is the client's localization key (nested-dotted, e.g.
/// `auth.login.invalid_credentials`); `msg` is the English fallback a client
/// renders when its bundle lacks the id. The log line carries the id so an
/// operator greps ONE token to find every occurrence of a refusal class.
/// [`refuse`] with extra members beside `error` and `reason_id` — for the typed
/// NOT-YET answers (202) that carry what the client needs to wait well:
/// `converges_on_its_own`, the id being fetched, and so on. The localization
/// guard scrapes this name exactly as it scrapes `refuse`, so the id is still
/// counted as emitted.
pub fn refuse_with(
    code: StatusCode,
    reason_id: &'static str,
    msg: impl Into<String>,
    extra: serde_json::Value,
) -> Response {
    let msg = msg.into();
    tracing::info!(reason_id, "auth refused: {msg}");
    let mut body = json!({ "error": msg, "reason_id": reason_id });
    if let (Some(dst), Some(src)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in src {
            dst.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    (code, Json(body)).into_response()
}

pub fn refuse(code: StatusCode, reason_id: &'static str, msg: impl Into<String>) -> Response {
    let msg = msg.into();
    tracing::info!(reason_id, "auth refused: {msg}");
    (code, Json(json!({ "error": msg, "reason_id": reason_id }))).into_response()
}
