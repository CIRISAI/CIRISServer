//! **Claim remote ownership** — the SUBSTRATE-NATIVE, node-to-node claiming side
//! of the 1-phase owner-binding (the mirror of `auth::bootstrap::setup_root`).
//!
//! The client is itself a node: it runs a local `ciris-server` with the full
//! substrate (JCS + hybrid signing). So when an operator/app wants to claim
//! ownership of a *remote* node, the app does NO crypto — it asks its LOCAL node
//! to do it. The local node:
//!
//!   1. decodes the target's NodeCode ([`nodecode::decode`]) → the target's
//!      `key_id` + Ed25519 pubkey + `transport_hint`;
//!   2. builds the `delegates_to(LOCAL USER → target node, infra:*)` owner-binding
//!      envelope, JCS-canonicalizes it, and HYBRID-SIGNS the canonical bytes with
//!      the **responsible USER's** signer (NOT the node's steward signer), via the
//!      substrate ([`ownership::build_signed_owner_binding`]); and
//!   3. POSTs the COMPLETE, user-signed [`SignedOwnerBinding`](crate::auth::ownership::SignedOwnerBinding)
//!      to the target's `POST /v1/setup/root` (Role 1) over the federation HTTP
//!      client (reaching the target via its `transport_hint`).
//!
//! Exposed as `POST /v1/setup/claim-remote` on the LOCAL node (body
//! `{ node_code, claim_pin, cohort_scope }`), owner/operator-gated. This is the
//! op the app calls; the local node does ALL the crypto + node-to-node.
//!
//! ## The local USER identity — and the keyring gap (FILED UPSTREAM)
//!
//! Step 2 MUST sign as the **responsible user**, not the node's steward key (the
//! owner-binding asserts an accountable *human* is responsible). The substrate
//! `Engine` holds exactly ONE [`LocalSigner`](ciris_persist::prelude::LocalSigner)
//! — the node's steward identity — and `ciris-keyring` v5.11.0 ships NO
//! user-identity / YubiKey(PKCS#11) signer accessor. So the local node must be
//! handed a user-role `LocalSigner` explicitly (config-provided user key seeds,
//! wired into [`router`]). Until the keyring grows a user-identity / hardware
//! (PKCS#11) accessor, that is the only way to sign as a distinct user.
//!
//! **GAP to file upstream (likely a `ciris-keyring` ask):** a user-identity
//! signer surface — load/seal a user-role Ed25519+ML-DSA-65 keypair distinct from
//! the node steward key, ideally backed by a YubiKey/PKCS#11 token — so the
//! responsible human's owner-binding signature can be hardware-custodied by the
//! human, not co-resident with the node's steward key.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::prelude::{Engine, LocalSigner};
use serde::{Deserialize, Serialize};

use crate::auth::ownership::{self, SignedOwnerBinding, OWNER_BINDING_INFRA_SCOPES};
use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::{resolve_bearer, SessionCaller};
use crate::nodecode;

/// The cohort scopes a node may be claimed under (CC 4.4.3.4.1). Mirrors the
/// receiving side's closed set; validated before any node-to-node call. The
/// 3-value restriction is intentional (a narrower subset of the persist
/// `cohort_scope` vocabulary).
const COHORT_SCOPES: &[&str] = &[
    ciris_persist::federation::types::cohort_scope::SELF,
    ciris_persist::federation::types::cohort_scope::FAMILY,
    ciris_persist::federation::types::cohort_scope::COMMUNITY,
];

/// Errors the claim-remote build/execute pipeline can surface.
#[derive(Debug)]
pub enum ClaimRemoteError {
    /// The supplied NodeCode could not be decoded.
    BadNodeCode(String),
    /// The cohort scope is absent or outside the closed set.
    BadCohortScope(String),
    /// Building / signing the owner-binding in the substrate failed.
    Build(ownership::OwnershipError),
    /// The target node has no usable transport (no `transport_hint`).
    NoTransport,
    /// The HTTP round-trip to the target failed (connect / send / timeout).
    Transport(String),
    /// The target's `POST /v1/setup/root` returned a non-success status.
    TargetRejected { status: u16, body: String },
}

impl std::fmt::Display for ClaimRemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimRemoteError::BadNodeCode(e) => write!(f, "decode target NodeCode: {e}"),
            ClaimRemoteError::BadCohortScope(e) => write!(f, "cohort_scope: {e}"),
            ClaimRemoteError::Build(e) => write!(f, "build owner-binding: {e}"),
            ClaimRemoteError::NoTransport => write!(
                f,
                "target NodeCode carries no transport_hint — cannot reach the node to claim it"
            ),
            ClaimRemoteError::Transport(e) => write!(f, "reach target node: {e}"),
            ClaimRemoteError::TargetRejected { status, body } => {
                write!(f, "target rejected the claim (HTTP {status}): {body}")
            }
        }
    }
}
impl std::error::Error for ClaimRemoteError {}

impl From<ownership::OwnershipError> for ClaimRemoteError {
    fn from(e: ownership::OwnershipError) -> Self {
        ClaimRemoteError::Build(e)
    }
}

/// Validate a cohort scope against the closed set.
fn validate_cohort_scope(raw: &str) -> Result<String, ClaimRemoteError> {
    let v = raw.trim();
    if COHORT_SCOPES.contains(&v) {
        Ok(v.to_string())
    } else {
        Err(ClaimRemoteError::BadCohortScope(format!(
            "invalid {v:?} — must be one of self|family|community"
        )))
    }
}

/// The full `POST /v1/setup/root` body the local node sends the target — the
/// 1-phase claim (NodeCode pin + cohort + claim PIN + the complete, user-signed
/// owner-binding). Serde-shaped to match the receiver's `SetupRootRequest`.
#[derive(Debug, Serialize)]
struct RemoteSetupRootRequest {
    /// The target's full `CIRIS-V1-...` NodeCode (the identity pin).
    node_code: String,
    /// The cohort scope the node is claimed under (`self` / `family` / `community`).
    cohort_scope: String,
    /// The one-time claim PIN (operator-presence secret) read off the target.
    claim_pin: String,
    /// The complete, already-user-signed owner-binding.
    owner_binding: SignedOwnerBinding,
}

/// **The directory-level build step (the LOCAL node's substrate work).** Decode
/// the target NodeCode, then build + JCS-canonicalize + hybrid-sign the
/// `delegates_to(LOCAL USER → target node, infra:*)` owner-binding with the
/// `user_signer` (the responsible user's key). Returns the decoded
/// [`NodeCode`](crate::nodecode::NodeCode) and the complete
/// [`SignedOwnerBinding`] ready to POST. The app never sees crypto.
///
/// This is the unit-testable core (no HTTP): a test can drive it on node L and
/// feed the result straight into [`ownership::apply_signed_owner_binding`] on
/// node T.
pub async fn build_claim_for_target(
    user_signer: &LocalSigner,
    target_node_code: &str,
) -> Result<(nodecode::NodeCode, SignedOwnerBinding), ClaimRemoteError> {
    let nc = nodecode::decode(target_node_code)
        .map_err(|e| ClaimRemoteError::BadNodeCode(e.to_string()))?;
    let infra_scopes: Vec<String> = OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let binding = ownership::build_signed_owner_binding(user_signer, &nc.key_id, &infra_scopes)
        .await
        .map_err(ClaimRemoteError::Build)?;
    Ok((nc, binding))
}

/// **The full claim-remote op (build + node-to-node).** Build the user-signed
/// owner-binding on the LOCAL node (via [`build_claim_for_target`]) and POST the
/// complete 1-phase claim to the target's `POST /v1/setup/root`, reached via the
/// NodeCode's `transport_hint`. Returns the target's claim-result JSON.
///
/// `http` is the federation HTTP client (rustls). The target base URL is the
/// `transport_hint` on the NodeCode (e.g. `https://node.example`); the claim is
/// POSTed to `{transport_hint}/v1/setup/root`.
pub async fn claim_remote(
    http: &reqwest::Client,
    user_signer: &LocalSigner,
    target_node_code: &str,
    claim_pin: &str,
    cohort_scope: &str,
) -> Result<serde_json::Value, ClaimRemoteError> {
    let cohort = validate_cohort_scope(cohort_scope)?;
    let (nc, owner_binding) = build_claim_for_target(user_signer, target_node_code).await?;

    let base = nc
        .transport_hint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(ClaimRemoteError::NoTransport)?;
    let url = format!("{}/v1/setup/root", base.trim_end_matches('/'));

    let req = RemoteSetupRootRequest {
        // Re-encode the canonical NodeCode (round-trips byte-identically) so the
        // target's identity-pin check sees the exact pin form it expects.
        node_code: target_node_code.to_string(),
        cohort_scope: cohort,
        claim_pin: claim_pin.to_string(),
        owner_binding,
    };

    let resp = http
        .post(&url)
        .json(&req)
        .send()
        .await
        .map_err(|e| ClaimRemoteError::Transport(e.to_string()))?;
    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(ClaimRemoteError::TargetRejected {
            status: status.as_u16(),
            body: body_text,
        });
    }
    let json: serde_json::Value =
        serde_json::from_str(&body_text).unwrap_or(serde_json::Value::Null);
    Ok(json)
}

// ─── POST /v1/setup/claim-remote (owner/operator-gated) ──────────────────────

#[derive(Clone)]
struct ClaimRemoteState {
    engine: Arc<Engine>,
    /// THIS node's federation `key_id` — used to check the serve-only floor (the
    /// local node must itself be owner-bound to author a remote claim) is NOT
    /// applicable here: the LOCAL node drives the claim with the USER's signer,
    /// so authority is the operator session, not an owner-binding. Retained for
    /// logging/symmetry.
    #[allow(dead_code)]
    node_key_id: String,
    /// The responsible USER's signer (NOT the node steward signer). Wired at
    /// compose time from a config-provided user key. See the module docs for the
    /// keyring/YubiKey gap.
    user_signer: Arc<LocalSigner>,
    http: reqwest::Client,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// Owner/operator-authority gate. Claiming a REMOTE node on the operator's behalf
/// is an apex act (it establishes the operator's user as that node's responsible
/// party), so it is gated on `SYSTEM_ADMIN` + [`Permission::FullAccess`] — the
/// same apex gate `federation_admin::require_owner` uses for peering.
async fn require_owner(
    st: &ClaimRemoteState,
    headers: &HeaderMap,
) -> Result<SessionCaller, Response> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "missing bearer session token",
        ));
    };
    match resolve_bearer(&st.engine, token).await {
        Ok(Some(caller))
            if caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) =>
        {
            Ok(caller)
        }
        Ok(Some(_)) => Err(err(
            StatusCode::FORBIDDEN,
            "claim-remote requires the owner (SYSTEM_ADMIN) role",
        )),
        Ok(None) => Err(err(StatusCode::UNAUTHORIZED, "invalid or expired session")),
        Err(e) => Err(err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}"))),
    }
}

/// `POST /v1/setup/claim-remote` request — the inputs the APP supplies (no
/// crypto): the target's NodeCode, the target's one-time claim PIN, and the
/// cohort scope to claim under.
#[derive(Debug, Deserialize)]
struct ClaimRemoteRequest {
    /// The target node's `CIRIS-V1-...` NodeCode (carrying its `transport_hint`).
    node_code: String,
    /// The target node's one-time claim PIN (read off the target's console).
    claim_pin: String,
    /// The cohort scope to claim the target under (`self` / `family` / `community`).
    cohort_scope: String,
}

async fn claim_remote_handler(
    State(st): State<ClaimRemoteState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner(&st, &headers).await {
        return resp;
    }
    let req: ClaimRemoteRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };

    match claim_remote(
        &st.http,
        &st.user_signer,
        &req.node_code,
        &req.claim_pin,
        &req.cohort_scope,
    )
    .await
    {
        Ok(target_result) => (StatusCode::OK, Json(target_result)).into_response(),
        Err(e) => {
            let code = match e {
                ClaimRemoteError::BadNodeCode(_) | ClaimRemoteError::BadCohortScope(_) => {
                    StatusCode::BAD_REQUEST
                }
                ClaimRemoteError::Build(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ClaimRemoteError::NoTransport => StatusCode::BAD_REQUEST,
                ClaimRemoteError::Transport(_) => StatusCode::BAD_GATEWAY,
                // Surface the target's status to the operator (it is the target's
                // verdict on the claim, not a local error).
                ClaimRemoteError::TargetRejected { status, .. } => {
                    StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY)
                }
            };
            err(code, format!("claim-remote failed: {e}"))
        }
    }
}

/// The claim-remote router — merge onto the control API listener. `user_signer`
/// is the responsible USER's signer (NOT the node steward signer); see the module
/// docs for how it is obtained and the keyring/YubiKey gap.
pub fn router(engine: Arc<Engine>, node_key_id: String, user_signer: Arc<LocalSigner>) -> Router {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_default();
    let state = ClaimRemoteState {
        engine,
        node_key_id,
        user_signer,
        http,
    };
    Router::new()
        .route(
            "/v1/setup/claim-remote",
            axum::routing::post(claim_remote_handler),
        )
        .with_state(state)
}
