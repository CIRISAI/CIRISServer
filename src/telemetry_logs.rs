//! `GET /v1/telemetry/logs` — the node's own logs, for the client Logs screen.
//!
//! The node logs reliably to `<home>/logs/ciris-server.log` (daily-rolling, so the
//! real files carry a `.YYYY-MM-DD` suffix — see [`crate::init_tracing_with`]). This
//! handler tails those files, parses the default `tracing_subscriber::fmt` line
//! shape (`<rfc3339-ts>  <LEVEL> <target>: <message>`), filters by `level`/`service`,
//! and returns the newest `limit` entries in the exact JSON the client's generated
//! `SuccessResponseLogsResponse` expects:
//!
//! ```json
//! { "data": { "logs": [ { "timestamp","level","service","message",
//!                         "context": null, "trace_id": null } ],
//!             "total": <int>, "has_more": <bool> } }
//! ```
//!
//! Read-only + localhost (mounted on the same read-API listener as
//! `/v1/memory/*`), so it is ungated like the memory read endpoints.

use std::path::PathBuf;

use axum::{extract::Query, extract::State, response::IntoResponse, response::Response, Json};
use serde::Deserialize;
use serde_json::json;

#[derive(Clone)]
struct LogsState {
    /// `<home>/logs` — where `ciris-server.log*` lives.
    log_dir: PathBuf,
}

#[derive(Debug, Deserialize)]
struct LogsParams {
    /// Case-insensitive exact level filter (`ERROR` / `WARN` / `INFO` / …).
    level: Option<String>,
    /// Substring match against the tracing target (the "service").
    service: Option<String>,
    /// Max entries returned (newest-first). Default 100, hard cap 5000.
    limit: Option<usize>,
    // start_time / end_time are accepted (the client sends them) but not yet used;
    // the rolling file is already day-bounded and the limit keeps the page small.
    #[allow(dead_code)]
    #[serde(default)]
    start_time: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    end_time: Option<String>,
}

/// One parsed log line.
struct Entry {
    timestamp: String,
    level: String,
    service: String,
    message: String,
}

/// Parse one default-fmt line: `<ts>  <LEVEL> <target>: <message>`.
/// Returns `None` for a continuation line (a multi-line message body / panic
/// backtrace) — the caller appends those to the previous entry's message.
fn parse_line(line: &str) -> Option<Entry> {
    let trimmed = line.trim_start();
    let (ts, rest) = trimmed.split_once(char::is_whitespace)?;
    // A real entry starts with an RFC3339-ish timestamp: leading digit + a 'T'.
    if !ts.starts_with(|c: char| c.is_ascii_digit()) || !ts.contains('T') {
        return None;
    }
    let rest = rest.trim_start();
    let (level, rest) = rest.split_once(char::is_whitespace)?;
    if !matches!(level, "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR") {
        return None;
    }
    let rest = rest.trim_start();
    // `target: message` — the target uses `::` (no single ": "), so the first
    // ": " separates target from message. Fall back to the whole rest as message.
    let (service, message) = match rest.split_once(": ") {
        Some((t, m)) => (t.to_string(), m.to_string()),
        None => ("ciris-server".to_string(), rest.to_string()),
    };
    Some(Entry {
        timestamp: ts.to_string(),
        level: level.to_string(),
        service,
        message,
    })
}

/// Read + parse all `ciris-server.log*` files in date order (oldest first).
fn read_entries(log_dir: &std::path::Path) -> Vec<Entry> {
    let mut files: Vec<PathBuf> = match std::fs::read_dir(log_dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("ciris-server.log"))
            })
            .collect(),
        Err(_) => return Vec::new(),
    };
    // Names sort chronologically (`ciris-server.log` < `ciris-server.log.2026-06-27`).
    files.sort();

    let mut entries: Vec<Entry> = Vec::new();
    for f in files {
        let Ok(content) = std::fs::read_to_string(&f) else {
            continue;
        };
        for line in content.lines() {
            match parse_line(line) {
                Some(e) => entries.push(e),
                None => {
                    // Continuation line — append to the previous entry's message.
                    if let Some(last) = entries.last_mut() {
                        last.message.push('\n');
                        last.message.push_str(line);
                    }
                }
            }
        }
    }
    entries
}

async fn get_logs(State(st): State<LogsState>, Query(p): Query<LogsParams>) -> Response {
    let limit = p.limit.unwrap_or(100).clamp(1, 5000);
    let level_filter = p.level.as_deref().map(|s| s.to_ascii_uppercase());
    let service_filter = p.service.as_deref();

    let all = read_entries(&st.log_dir);
    // Apply filters (oldest-first order preserved).
    let matched: Vec<&Entry> = all
        .iter()
        .filter(|e| {
            level_filter
                .as_deref()
                .is_none_or(|lvl| e.level.eq_ignore_ascii_case(lvl))
                && service_filter.is_none_or(|svc| e.service.contains(svc))
        })
        .collect();

    let total = matched.len();
    let has_more = total > limit;
    // Newest `limit`, newest-first.
    let logs: Vec<serde_json::Value> = matched
        .iter()
        .rev()
        .take(limit)
        .map(|e| {
            json!({
                "timestamp": e.timestamp,
                "level": e.level,
                "service": e.service,
                "message": e.message,
                "context": serde_json::Value::Null,
                "trace_id": serde_json::Value::Null,
            })
        })
        .collect();

    Json(json!({
        "data": { "logs": logs, "total": total, "has_more": has_more }
    }))
    .into_response()
}

/// The `/v1/telemetry/logs` router. `log_dir` is `<home>/logs`.
pub fn router(log_dir: PathBuf) -> axum::Router {
    axum::Router::new()
        .route("/v1/telemetry/logs", axum::routing::get(get_logs))
        .with_state(LogsState { log_dir })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_fmt_line() {
        let e = parse_line(
            "2026-06-27T05:12:22.102974Z  INFO ciris_server::compose: node listening key=val",
        )
        .expect("parse");
        assert_eq!(e.level, "INFO");
        assert_eq!(e.service, "ciris_server::compose");
        assert_eq!(e.message, "node listening key=val");
        assert!(e.timestamp.starts_with("2026-06-27T"));
    }

    #[test]
    fn rejects_continuation_line() {
        assert!(parse_line("    at some::backtrace::frame").is_none());
        assert!(parse_line("plain text with no timestamp").is_none());
    }

    #[test]
    fn parses_error_and_message_without_target_colon() {
        let e = parse_line("2026-06-27T05:12:22.0Z ERROR boom").expect("parse");
        assert_eq!(e.level, "ERROR");
        assert_eq!(e.service, "ciris-server");
        assert_eq!(e.message, "boom");
    }
}
