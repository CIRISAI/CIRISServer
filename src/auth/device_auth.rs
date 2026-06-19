//! Device-auth / setup connect-node (CIRISServer#9) — the Portal device-grant.
//!
//! Port of `routes/setup/device_auth_routes.py` + `setup/device_auth.py`: the
//! setup-tier flow that pairs a fresh install with the CIRIS Portal over an
//! OAuth device-authorization grant (RFC 8628 shape) and (in the agent) registers
//! the node's self-custody key (FSD-002).
//!
//! This is a **Portal-HTTP** flow, not a substrate flow — it carries no new
//! persist primitive. The Portal contract, byte-compatible with the agent:
//! - `POST {portal}/api/device/authorize` → `{verification_uri_complete,
//!   device_code, user_code, expires_in, interval, challenge_nonce?}`.
//! - `POST {portal}/api/device/token` (poll) → 428 pending / 403 denied /
//!   200 `{agent_record, licensed_package, registration_challenge, org_id?}`.
//! - `POST {portal}/api/device/register-key` (self-custody) — public key only.
//!
//! SSRF posture (ported verbatim from `_validate_portal_url`): the Portal URL is
//! validated against [`ALLOWED_PORTAL_HOSTS`]; the request URL is reconstructed
//! from validated components only (scheme+netloc), never the raw user string
//! (CVE-2023-24329 class). `http` is allowed only for `localhost`/`127.0.0.1`.
//!
//! The session is persisted to `home/.device_auth_session.json` (Server 0.5: the
//! node data root, not `CIRIS_HOME`/`$HOME`), so an in-flight pairing survives a
//! restart and `reset-device-auth` clears the SAME file.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::prelude::Engine;
use serde::{Deserialize, Serialize};

/// The trusted CIRIS Portal hosts (verbatim from the agent's
/// `ALLOWED_PORTAL_HOSTS`). Any other host is rejected as SSRF.
pub const ALLOWED_PORTAL_HOSTS: &[&str] = &[
    "portal.ciris.ai",
    "portal.ciris-services-1.ai",
    "portal.ciris-services-2.ai",
    "localhost",
    "127.0.0.1",
];

/// Validate a Portal URL and return a sanitized base URL reconstructed from
/// validated components ONLY (`scheme://host[:port]`) — never the raw input.
/// Port of `_validate_portal_url`. `Err` carries a human reason on rejection.
pub fn validate_portal_url(raw: &str) -> Result<String, String> {
    // Normalize: add https:// if the user gave a bare host (agent parity).
    let url = if raw.starts_with("http://") || raw.starts_with("https://") {
        raw.trim_end_matches('/').to_string()
    } else {
        format!("https://{}", raw.trim_end_matches('/'))
    };
    let parsed = reqwest::Url::parse(&url).map_err(|_| "Invalid URL format".to_string())?;
    let scheme = parsed.scheme();
    if scheme != "https" && scheme != "http" {
        return Err("URL must use https".into());
    }
    let host = parsed.host_str().unwrap_or("").to_lowercase();
    if !ALLOWED_PORTAL_HOSTS.contains(&host.as_str()) {
        return Err(format!(
            "Untrusted host '{host}'. Only CIRIS Portal domains are allowed."
        ));
    }
    if scheme == "http" && host != "localhost" && host != "127.0.0.1" {
        return Err("HTTP only allowed for localhost".into());
    }
    // Reconstruct from validated parts only (scheme + host + optional port).
    let base = match parsed.port() {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    };
    Ok(base)
}

/// The conventional device-auth session filename under the node's home (Server
/// 0.5: `home/.device_auth_session.json` — no `CIRIS_HOME`/`$HOME` env). Mirrors
/// the agent's `_get_device_auth_session_path`, repointed to the node home.
const DEVICE_AUTH_SESSION_FILE: &str = ".device_auth_session.json";

#[derive(Clone)]
struct DeviceAuthState {
    #[allow(dead_code)] // the substrate touch lands when pairing writes a node identity.
    engine: Arc<Engine>,
    http: reqwest::Client,
    /// The device-auth session file path (`home/.device_auth_session.json`),
    /// derived from the node home at boot (Server 0.5 — no env).
    session_path: PathBuf,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

// ─── POST /v1/setup/connect-node ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ConnectNodeRequest {
    /// The Portal URL the operator entered (`node_url` in the agent).
    node_url: String,
}

#[derive(Debug, Serialize)]
struct ConnectNodeResponse {
    verification_uri_complete: String,
    device_code: String,
    user_code: String,
    portal_url: String,
    expires_in: u64,
    interval: u64,
}

/// Initiate device auth via the Portal — port of `connect_node`. Validates the
/// Portal URL (SSRF), POSTs `/api/device/authorize`, persists the session, and
/// returns the verification URL for the operator to open.
async fn connect_node(State(st): State<DeviceAuthState>, body: axum::body::Bytes) -> Response {
    let req: ConnectNodeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    let portal_url = match validate_portal_url(req.node_url.trim()) {
        Ok(u) => u,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("Invalid portal URL: {e}")),
    };

    // POST {portal}/api/device/authorize — path is hardcoded onto the validated base.
    let authorize_url = format!("{portal_url}/api/device/authorize");
    let resp = st
        .http
        .post(&authorize_url)
        .json(&serde_json::json!({ "portal_url": portal_url }))
        .send()
        .await;
    let data: serde_json::Value = match resp {
        Ok(r) => match r.error_for_status() {
            Ok(r) => match r.json().await {
                Ok(j) => j,
                Err(e) => return err(StatusCode::BAD_GATEWAY, format!("Portal decode: {e}")),
            },
            Err(e) => {
                return err(
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to initiate device auth with Portal at {portal_url}: {e}"),
                )
            }
        },
        Err(e) => {
            return err(
                StatusCode::BAD_GATEWAY,
                format!("Failed to initiate device auth with Portal at {portal_url}: {e}"),
            )
        }
    };

    let device_code = data
        .get("device_code")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let verification_uri = data
        .get("verification_uri_complete")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let user_code = data
        .get("user_code")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let expires_in = data
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(900);
    let interval = data.get("interval").and_then(|v| v.as_u64()).unwrap_or(5);

    save_device_auth_session(
        &st.session_path,
        &device_code,
        &portal_url,
        &verification_uri,
        &user_code,
        expires_in,
        interval,
    );

    (
        StatusCode::OK,
        Json(ConnectNodeResponse {
            verification_uri_complete: verification_uri,
            device_code,
            user_code,
            portal_url,
            expires_in,
            interval,
        }),
    )
        .into_response()
}

/// Persist the in-flight device-auth session (agent's `_save_device_auth_session`).
#[allow(clippy::too_many_arguments)]
fn save_device_auth_session(
    path: &PathBuf,
    device_code: &str,
    portal_url: &str,
    verification_uri_complete: &str,
    user_code: &str,
    expires_in: u64,
    interval: u64,
) {
    let now = chrono::Utc::now().timestamp() as f64;
    let session = serde_json::json!({
        "device_code": device_code,
        "portal_url": portal_url,
        "verification_uri_complete": verification_uri_complete,
        "user_code": user_code,
        "expires_in": expires_in,
        "interval": interval,
        "expires_at": now + expires_in as f64,
        "created_at": now,
    });
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, serde_json::to_vec(&session).unwrap_or_default());
}

/// Clear the persisted device-auth session (agent's `_clear_device_auth_session`).
fn clear_device_auth_session(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
}

// ─── GET /v1/setup/connect-node/status ──────────────────────────────────────

#[derive(Debug, Deserialize)]
struct StatusQuery {
    device_code: String,
    portal_url: String,
}

#[derive(Debug, Serialize)]
struct ConnectNodeStatusResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    template: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    adapters: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stewardship_tier: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_download_url: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_template_id: Option<serde_json::Value>,
}

/// Poll device-auth status — port of `connect_node_status`. Validates the Portal
/// URL (SSRF), POSTs `/api/device/token`; 428 = pending, 403 = denied (clears
/// session), 200 = complete (extracts provisioned data, clears session).
async fn connect_node_status(
    State(st): State<DeviceAuthState>,
    axum::extract::Query(q): axum::extract::Query<StatusQuery>,
) -> Response {
    let safe_base = match validate_portal_url(&q.portal_url) {
        Ok(u) => u,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("Invalid portal URL: {e}")),
    };
    let token_url = format!("{safe_base}/api/device/token");
    let resp = st
        .http
        .post(&token_url)
        .json(&serde_json::json!({ "device_code": q.device_code }))
        .send()
        .await;
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            return err(
                StatusCode::BAD_GATEWAY,
                format!("Failed to poll Portal token endpoint: {e}"),
            )
        }
    };
    let code = resp.status().as_u16();
    // 428 = authorization_pending (RFC 8628) — keep polling.
    if code == 428 {
        return (StatusCode::OK, Json(status_only("pending"))).into_response();
    }
    // 403 = denied — clear the session so the operator can retry.
    if code == 403 {
        clear_device_auth_session(&st.session_path);
        return (StatusCode::OK, Json(status_only("error"))).into_response();
    }
    if code != 200 {
        return err(
            StatusCode::BAD_GATEWAY,
            format!("Portal token endpoint error: HTTP {code}"),
        );
    }
    let data: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(e) => return err(StatusCode::BAD_GATEWAY, format!("Portal decode: {e}")),
    };

    // Self-custody key registration is the FSD-002 step; in the fabric the node's
    // sealed federation signer owns the key and registration rides the keyring/
    // federation surface — recorded here as the completion of pairing. (The
    // public-key registration POST is a follow-on once the keyring signer is wired
    // into this route; the device-grant itself — the gap — is complete.)
    let agent_record = data
        .get("agent_record")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let licensed_package = data
        .get("licensed_package")
        .cloned()
        .unwrap_or(serde_json::Value::Object(Default::default()));

    clear_device_auth_session(&st.session_path);

    let resp = ConnectNodeStatusResponse {
        status: "complete".into(),
        template: agent_record.get("identity_template").cloned(),
        adapters: agent_record.get("approved_adapters").cloned(),
        org_id: data.get("org_id").cloned(),
        stewardship_tier: agent_record.get("stewardship_tier").cloned(),
        package_download_url: licensed_package.get("download_url").cloned(),
        package_template_id: licensed_package.get("template_id").cloned(),
    };
    (StatusCode::OK, Json(resp)).into_response()
}

fn status_only(s: &str) -> ConnectNodeStatusResponse {
    ConnectNodeStatusResponse {
        status: s.into(),
        template: None,
        adapters: None,
        org_id: None,
        stewardship_tier: None,
        package_download_url: None,
        package_template_id: None,
    }
}

// ─── POST /v1/setup/reset-device-auth ───────────────────────────────────────

/// Clear the device-auth session state (agent's `reset_device_auth`). No auth —
/// it only affects local session state.
async fn reset_device_auth(State(st): State<DeviceAuthState>) -> Response {
    clear_device_auth_session(&st.session_path);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "reset", "message": "Device auth session cleared" })),
    )
        .into_response()
}

/// The device-auth router. `home` is the node data root (Server 0.5 — the
/// device-auth session file is `home/.device_auth_session.json`, not env-derived).
pub fn router(engine: Arc<Engine>, home: PathBuf) -> Router {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none()) // SSRF: no redirect-following.
        .build()
        .expect("reqwest client");
    let session_path = home.join(DEVICE_AUTH_SESSION_FILE);
    Router::new()
        .route("/v1/setup/connect-node", axum::routing::post(connect_node))
        .route(
            "/v1/setup/connect-node/status",
            axum::routing::get(connect_node_status),
        )
        .route(
            "/v1/setup/reset-device-auth",
            axum::routing::post(reset_device_auth),
        )
        .with_state(DeviceAuthState {
            engine,
            http,
            session_path,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_url_ssrf_allowlist() {
        // Trusted hosts pass and are reconstructed scheme+host only.
        assert_eq!(
            validate_portal_url("https://portal.ciris.ai/api/x?y=1").unwrap(),
            "https://portal.ciris.ai"
        );
        assert_eq!(
            validate_portal_url("portal.ciris.ai").unwrap(),
            "https://portal.ciris.ai"
        );
        // localhost may use http.
        assert_eq!(
            validate_portal_url("http://localhost:9000").unwrap(),
            "http://localhost:9000"
        );
        // Untrusted host rejected (SSRF).
        assert!(validate_portal_url("https://evil.example.com").is_err());
        // http on a non-loopback trusted host rejected.
        assert!(validate_portal_url("http://portal.ciris.ai").is_err());
        // metadata endpoint rejected.
        assert!(validate_portal_url("http://169.254.169.254/latest/meta-data").is_err());
    }
}
