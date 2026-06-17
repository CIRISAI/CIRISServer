//! Device-auth / setup connect-node (CIRISServer#9) — **scaffold**.
//!
//! Port of `routes/setup/device_auth_routes.py`: the setup-tier flow that pairs
//! a fresh install with the CIRIS Portal (OAuth device-authorization grant,
//! RFC 8628 shape) and registers the node's self-custody key (FSD-002).
//!
//! This is a **Portal-HTTP** flow, not a substrate flow — it carries no new
//! persist primitive, so it is left scaffolded with the Portal contract
//! documented. The one substrate touch (recording the resulting node identity /
//! licensed package) rides the existing `wa_cert` / identity surface once the
//! pairing completes.
//!
//! Portal contract (from the agent):
//! - `POST {portal}/api/device/authorize` → `{verification_uri_complete,
//!   device_code, user_code, expires_in, interval, challenge_nonce?}`.
//! - `POST {portal}/api/device/token` (poll) → 428 pending / 403 denied /
//!   200 `{agent_record, licensed_package, registration_challenge}`.
//! - self-custody: register the node's Ed25519 pubkey with the Portal; the
//!   private key never leaves the node (the fabric's sealed federation signer).
//!
//! SSRF posture: the Portal URL is validated against an allowlist; downloads
//! reconstruct the URL from validated parts and verify the SHA-256 checksum
//! header (CVE-2023-24329 class). Those guards port verbatim when wired.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::prelude::Engine;

#[derive(Clone)]
struct DeviceAuthState {
    #[allow(dead_code)] // wired when the Portal client lands.
    engine: Arc<Engine>,
}

fn not_yet(route: &str) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "device-auth not yet wired",
            "route": route,
            "todo": "CIRISServer#9: Portal device-authorization client + self-custody key registration"
        })),
    )
        .into_response()
}

// TODO(CIRISServer#9): POST {portal}/api/device/authorize, persist the session,
// submit inline attestation if a challenge_nonce is returned.
async fn connect_node() -> Response {
    not_yet("/v1/setup/connect-node")
}

// TODO(CIRISServer#9): poll {portal}/api/device/token; on 200 register the
// self-custody key + clear the session.
async fn connect_node_status() -> Response {
    not_yet("/v1/setup/connect-node/status")
}

// TODO(CIRISServer#9): clear the persisted device-auth session.
async fn reset_device_auth() -> Response {
    not_yet("/v1/setup/reset-device-auth")
}

// TODO(CIRISServer#9): validated download + checksum + unzip of the licensed
// package (out of the auth core; setup-tier).
async fn download_package() -> Response {
    not_yet("/v1/setup/download-package")
}

/// The device-auth router (scaffold — every route returns 501 with its TODO).
pub fn router(engine: Arc<Engine>) -> Router {
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
        .route(
            "/v1/setup/download-package",
            axum::routing::post(download_package),
        )
        .with_state(DeviceAuthState { engine })
}
