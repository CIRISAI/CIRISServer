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
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
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
    /// OPTIONAL owner login password forwarded to the target's setup/root (sets
    /// the ROOT cert's password_hash → owner session via /v1/auth/login). Only
    /// sent on a loopback self-claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_password: Option<String>,
    /// OPTIONAL friendly owner username → the target ROOT cert's `name` (loopback
    /// self-claim only), so the owner can log in with it.
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_username: Option<String>,
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
// The claim is a single cohesive operation; its inputs (transport, signer, target
// code, PIN, scope, self-fallback, owner password + username) are all required and
// independent — bundling them into a struct would obscure, not clarify.
#[allow(clippy::too_many_arguments)]
pub async fn claim_remote(
    http: &reqwest::Client,
    user_signer: &LocalSigner,
    target_node_code: &str,
    claim_pin: &str,
    cohort_scope: &str,
    self_fallback_url: Option<&str>,
    owner_password: Option<&str>,
    owner_username: Option<&str>,
) -> Result<serde_json::Value, ClaimRemoteError> {
    let cohort = validate_cohort_scope(cohort_scope)?;
    let (nc, owner_binding) = build_claim_for_target(user_signer, target_node_code).await?;

    // The target base URL is the NodeCode's `transport_hint`. A LOOPBACK node (a
    // desktop/local node with no public transport) carries NO hint — for that
    // SELF-claim we fall back to the local node's own loopback URL so the founder
    // can claim the node they're running on.
    let base = nc
        .transport_hint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| self_fallback_url.map(str::to_owned))
        .ok_or(ClaimRemoteError::NoTransport)?;
    let url = format!("{}/v1/setup/root", base.trim_end_matches('/'));

    let req = RemoteSetupRootRequest {
        // Re-encode the canonical NodeCode (round-trips byte-identically) so the
        // target's identity-pin check sees the exact pin form it expects.
        node_code: target_node_code.to_string(),
        cohort_scope: cohort,
        claim_pin: claim_pin.to_string(),
        owner_binding,
        owner_password: owner_password.map(str::to_owned),
        owner_username: owner_username.map(str::to_owned),
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
    /// THIS node's federation `key_id`. Authority for the claim is the operator
    /// session (not an owner-binding), but the key_id is also the CONFIG AUTHOR for
    /// the local `net.bootstrap_peers` update after a successful claim (0.5.73:
    /// record what we claimed so the claimer can reach it over RNS) and the
    /// self-claim discriminator (target == self ⇒ setup/root already recorded it).
    node_key_id: String,
    /// Inputs to resolve the responsible USER's signer AT REQUEST TIME (NOT at
    /// boot). The fed-ID is minted DURING the first-run wizard — after this node
    /// booted — so a boot-resolved signer would be absent for the very self-claim
    /// that follows the mint. We re-read the on-disk user seed per request via
    /// [`crate::compose::resolve_user_signer`].
    user_key_id: String,
    user_seed_dir: std::path::PathBuf,
    /// This node's own loopback read-API URL (e.g. `http://127.0.0.1:4243`) — the
    /// SELF-claim fallback target when a loopback node's NodeCode carries no
    /// `transport_hint`.
    local_self_url: String,
    /// Hybrid-verify policy for the local upgrade-owner apply (default Strict).
    policy: HybridPolicy,
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
    /// OPTIONAL explicit target base URL (e.g. `http://108.61.242.236:4243`).
    /// Overrides the NodeCode's `transport_hint` — use when the NodeCode has no
    /// hint (server nodes that don't know their external IP) or the hint is stale.
    #[serde(default)]
    target_url: Option<String>,
    /// OPTIONAL owner login password (loopback self-claim only) — forwarded to the
    /// target's setup/root to set the ROOT cert's password_hash, so the owner can
    /// get a SYSTEM_ADMIN session (the device-grant approve prerequisite).
    #[serde(default)]
    owner_password: Option<String>,
    /// OPTIONAL friendly owner username (loopback self-claim only) — forwarded so
    /// the owner can log in with it instead of the derived wa_id.
    #[serde(default)]
    owner_username: Option<String>,
}

async fn claim_remote_handler(
    State(st): State<ClaimRemoteState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Owner-gated once owned; open during first-run (no ROOT yet) so the founder's
    // FIRST claim — the act that establishes ownership — is reachable on a fresh
    // node. The route is loopback-only via the setup-route guard. (`require_owner`'s
    // result is gate-only — not consumed below — so the bypass is safe.) Mirrors
    // the agent's require_setup_mode.
    let first_run = crate::auth::bootstrap::is_first_run(&st.engine).await;
    if !first_run {
        match require_owner(&st, &headers).await {
            Ok(caller) => {
                if let Some(resp) = crate::auth::gate::require_verb(
                    &caller,
                    crate::auth::gate::CapabilityVerb::ClaimRemote,
                ) {
                    return resp;
                }
            }
            Err(resp) => return resp,
        }
    } else {
        tracing::info!(
            "claim-remote: first-run (no ROOT) — claiming without an owner session (loopback-only)"
        );
    }
    let req: ClaimRemoteRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };

    // Resolve the responsible-user signer NOW (not at boot): the fed-ID minted
    // earlier in this same first-run wizard is on disk by the time the automated
    // self-claim runs. Absent ⇒ the user hasn't created their fed-ID yet. The fed-ID
    // is bound to the login: first-run = bootstrap (creates the owner); otherwise the
    // require_owner gate above already proved a live owner session.
    let auth = if first_run {
        crate::compose::FedIdUse::FirstRunBootstrap
    } else {
        crate::compose::FedIdUse::OwnerSession
    };
    let user_signer = match crate::compose::resolve_user_signer(
        &st.engine,
        auth,
        // Resolve the owner user alias at REQUEST TIME from the active-alias pointer
        // the mint wrote (CIRISServer 0.5.59) — the user's chosen name (e.g.
        // `eric-moore-v1`), NOT the boot-captured `<node>-user`. Falls back to the
        // boot value for an identity minted before the pointer existed.
        &crate::active_user_alias(&st.user_seed_dir, &st.user_key_id),
        st.user_seed_dir.clone(),
    )
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "no responsible-user identity yet — create your federation ID \
                 (POST /v1/self/identity) before claiming ownership",
            )
        }
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("resolve user signer: {e}"),
            )
        }
    };

    // `target_url` overrides the NodeCode's transport_hint — needed for server
    // nodes that don't embed their external IP in the NodeCode.
    let fallback = req
        .target_url
        .as_deref()
        .unwrap_or(st.local_self_url.as_str());
    match claim_remote(
        &st.http,
        &user_signer,
        &req.node_code,
        &req.claim_pin,
        &req.cohort_scope,
        Some(fallback),
        req.owner_password.as_deref(),
        req.owner_username.as_deref(),
    )
    .await
    {
        Ok(target_result) => {
            // ── Best-effort LOCAL directory update (0.5.73) ───────────────────
            // The claim above SUCCEEDED on the target; now record what we claimed
            // in OUR OWN corpus so the claimer KNOWS it (owned-nodes lists the
            // target) and can REACH it over RNS (its address joins bootstrap_peers).
            // NEVER fail the claim over a local-persist hiccup — log + report a flag.
            let local_directory_updated = record_claimed_target_locally(
                &st,
                &user_signer,
                &req.node_code,
                req.cohort_scope.trim(),
                req.target_url.as_deref(),
            )
            .await;
            let body = with_local_flag(target_result, local_directory_updated);
            (StatusCode::OK, Json(body)).into_response()
        }
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

/// The Reticulum node port (`net.listen_addr` default `0.0.0.0:4242`). A target's
/// read-API URL is HTTP (e.g. `http://1.2.3.4:4243`); the RNS SEED we dial is the
/// same HOST at the node port — NOT the HTTP port. (Documented assumption: nodes
/// run their RNS listener on 4242; if the target uses a different RNS port the
/// operator can amend `net.bootstrap_peers` via `ciris-server config set`.)
const RNS_DEFAULT_PORT: u16 = 4242;

/// Derive the RNS mesh SEED address (`host:4242`) from a target's read-API URL or
/// NodeCode `transport_hint`. Strips the scheme + path + any userinfo, keeps the
/// HOST, and pins [`RNS_DEFAULT_PORT`] (the read-API/HTTP port is discarded — see
/// its doc). Returns the input verbatim when no host can be extracted, so nothing
/// is silently dropped (a malformed entry is skipped later by
/// [`crate::config::parse_bootstrap_peers`], which only admits `host:port`).
fn rns_seed_from_target(url: &str) -> Option<String> {
    let s = url.trim();
    if s.is_empty() {
        return None;
    }
    // Drop the scheme (`http://` / `https://` / `ret://` …) if present.
    let after_scheme = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    // Authority = up to the first '/', then drop any `user@` prefix.
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    if hostport.is_empty() {
        return None;
    }
    // Extract the host, handling `[ipv6]:port`, `host:port`, and bare `host`.
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        rest.split(']').next().map(|h| format!("[{h}]"))
    } else {
        hostport.split(':').next().map(str::to_string)
    };
    match host {
        Some(h) if !h.is_empty() => Some(format!("{h}:{RNS_DEFAULT_PORT}")),
        // Couldn't parse a host — record the raw authority so nothing is lost.
        _ => Some(hostport.to_string()),
    }
}

/// Register a just-claimed TARGET node's key record into the LOCAL federation
/// directory — as a FULL HYBRID row, never an Ed25519-only bookmark.
///
/// The NodeCode the target offered is Ed25519-only (a QR-compact handle; the
/// ML-DSA-65 pubkey is ~2 KB and can't ride in a scannable code). But a node we
/// just claimed is **by definition reachable** — so we "look back and ask for
/// both": fetch the target's OWN self-signed hybrid `SignedKeyRecord` (Ed25519 +
/// ML-DSA-65 + proof-of-possession) from its unauthenticated
/// `GET /v1/federation/self-key-record`, verify it is the SAME identity that
/// offered the NodeCode (key_id + the scanned Ed25519 must match — no
/// substitution), and admit it through the STRICT
/// [`register_federation_key`](ciris_persist::prelude::Engine::register_federation_key)
/// gate, which re-verifies the hybrid PoP. The result is a hybrid-COMPLETE row.
///
/// This matters beyond hygiene: the RNS announce-rooting path runs under
/// `HybridPolicy::Strict`, which REJECTS a hybrid-pending link — so a bookmark
/// row can never root and the peer stays permanently unreachable over the mesh.
/// A hybrid-pending row is therefore a bug; we refuse to write one (if the full
/// record can't be fetched we return an error rather than leave a pending row).
///
/// Idempotent: a row already present (e.g. a prior peering) is a no-op — never
/// clobber an existing richer row.
async fn register_target_key(
    engine: &Arc<Engine>,
    http: &reqwest::Client,
    nc: &nodecode::NodeCode,
    base_url: Option<&str>,
) -> Result<(), String> {
    use ciris_persist::federation::types::identity_type;
    use ciris_persist::federation::SignedKeyRecord;

    // Idempotent: already-known target ⇒ nothing to do (never clobber a richer,
    // hybrid-complete row a prior peering may have admitted).
    if let Ok(Some(_)) = engine
        .federation_directory()
        .lookup_public_key(&nc.key_id)
        .await
    {
        return Ok(());
    }

    // "They offered their Ed25519 (the NodeCode) — look back and ask for BOTH."
    let base = base_url.ok_or_else(|| {
        "no reachable target URL to fetch the full hybrid key record — refusing to write a \
         hybrid-pending bookmark (it could never root over RNS)"
            .to_string()
    })?;
    let url = format!(
        "{}/v1/federation/self-key-record",
        base.trim_end_matches('/')
    );
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("fetch {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("fetch {url}: HTTP {}", resp.status()));
    }
    let signed: SignedKeyRecord = resp
        .json()
        .await
        .map_err(|e| format!("parse self-key-record from {url}: {e}"))?;

    // SECURITY — the fetched record MUST be the SAME identity that offered the
    // NodeCode: same key_id, and the operator-scanned Ed25519 must match the
    // fetched one. Otherwise a substituted/MITM target could get ITS OWN key
    // admitted under our claim. The Ed25519 is the anchor the operator scanned.
    if signed.record.key_id != nc.key_id {
        return Err(format!(
            "self-key-record key_id {} != claimed NodeCode key_id {} (identity substitution?)",
            signed.record.key_id, nc.key_id
        ));
    }
    if signed.record.pubkey_ed25519_base64 != nc.pubkey_ed25519_base64 {
        return Err(
            "self-key-record Ed25519 does not match the offered NodeCode Ed25519 \
             (identity substitution?)"
                .to_string(),
        );
    }
    // Safe-mesh floor (mirrors `peer::register_peer_key`): an `accord_holder`
    // (kill-switch SEAT) may be admitted ONLY through the custody-gated
    // `POST /v1/accord/holder` — never via a claim side door.
    if signed.record.identity_type == identity_type::ACCORD_HOLDER {
        return Err(
            "refusing to admit an accord_holder key via claim — accord holders must go through \
             the custody-gated POST /v1/accord/holder"
                .to_string(),
        );
    }

    // STRICT hybrid PoP gate — re-verifies the target's self-signature over BOTH
    // halves; a forged or incomplete record is rejected here, not stored.
    engine
        .register_federation_key(signed)
        .await
        .map_err(|e| format!("register target hybrid key (strict gate): {e}"))
}

/// Append `addr` to the LOCAL node's `net.bootstrap_peers` config:* list (deduped),
/// so the local node dials the claimed target on its NEXT boot (the "≥1 node with
/// an IP" that makes the mesh reachable). Returns `Ok(true)` when a new entry was
/// added, `Ok(false)` when `addr` was already present (idempotent). `net.listen_addr`
/// is boot-structural, so this takes effect on restart.
async fn append_bootstrap_peer(
    engine: &Arc<Engine>,
    node_key_id: &str,
    addr: &str,
) -> Result<bool, String> {
    use crate::graph_config::{get_config, set_config, ConfigScope, ConfigValue};

    let mut list: Vec<serde_json::Value> = match get_config(
        engine,
        node_key_id,
        crate::config_reconcile::KEY_BOOTSTRAP_PEERS,
    )
    .await
    .map_err(|e| e.to_string())?
    {
        Some(entry) => match entry.value {
            ConfigValue::List(items) => items,
            // Any non-list stored value: start a fresh list (don't clobber-panic).
            _ => Vec::new(),
        },
        None => Vec::new(),
    };
    if list.iter().any(|v| v.as_str() == Some(addr)) {
        return Ok(false);
    }
    list.push(serde_json::Value::String(addr.to_string()));
    set_config(
        engine,
        node_key_id,
        crate::config_reconcile::KEY_BOOTSTRAP_PEERS,
        ConfigValue::List(list),
        "claim-remote",
        ConfigScope::default(),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(true)
}

/// **Best-effort local directory update after a SUCCESSFUL remote claim (0.5.73).**
/// Records the just-claimed target into THIS node's corpus so the claimer keeps a
/// record of what it claimed AND can reach it over RNS:
///
///   1. the target's **key record** → `federation_keys` (so we KNOW the target);
///   2. the **owner-binding** `delegates_to(owner → target)` → local corpus (so
///      `GET /v1/setup/owned-nodes` / `nodes_stewarded_by(owner)` lists the target
///      on the claimer); and
///   3. the target's **RNS seed** → `net.bootstrap_peers` (so the local node can
///      dial the target — the mesh-reachability fix).
///
/// Returns `true` iff every applicable step succeeded. A failure is logged and
/// swallowed (the remote claim already succeeded — a local hiccup must not 500 it).
/// A loopback SELF-claim (target == this node) is a no-op success: `setup/root`
/// already persisted the binding on THIS same engine, and self-peering is pointless.
async fn record_claimed_target_locally(
    st: &ClaimRemoteState,
    user_signer: &LocalSigner,
    node_code: &str,
    cohort_scope: &str,
    target_url: Option<&str>,
) -> bool {
    // Re-derive the decoded NodeCode + a user-signed owner-binding for the target.
    // (A fresh envelope — the LOCAL record need not be byte-identical to the one the
    // target stored; it just has to be a valid user-signed delegates_to(owner→target).)
    let (nc, owner_binding) = match build_claim_for_target(user_signer, node_code).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "claim-remote: could not rebuild target binding for the local directory record (non-fatal)");
            return false;
        }
    };

    // Loopback self-claim: the target IS this node, so setup/root already persisted
    // the key + owner-binding on THIS engine. Skip (avoid duplicate rows + self-peer).
    if nc.key_id == st.node_key_id {
        tracing::debug!(target = %nc.key_id, "claim-remote: self-claim — local directory already updated by setup/root");
        return true;
    }

    let mut ok = true;

    // The target's reachable base URL — the operator-supplied `target_url` wins
    // (an explicit address), else the NodeCode's own `transport_hint`. Used both
    // to fetch the full hybrid key record (1) and to seed `net.bootstrap_peers` (3).
    let base_url = target_url.or(nc.transport_hint.as_deref());

    // (1) target key record — fetched as a FULL HYBRID record from the target and
    // admitted through the strict PoP gate (never a hybrid-pending bookmark).
    if let Err(e) = register_target_key(&st.engine, &st.http, &nc, base_url).await {
        tracing::warn!(target = %nc.key_id, error = %e, "claim-remote: register target hybrid key locally FAILED (non-fatal)");
        ok = false;
    }

    // (2) owner-binding delegates_to(owner → target) into the LOCAL corpus.
    match ownership::apply_signed_owner_binding(
        &st.engine,
        &nc.key_id,
        cohort_scope,
        st.policy,
        &owner_binding,
    )
    .await
    {
        Ok(applied) => tracing::info!(
            target = %nc.key_id,
            owner = %applied.responsible_user_key_id,
            attestation_id = %applied.attestation_id,
            "claim-remote: recorded owner-binding locally (owned-nodes now lists the claimed target)"
        ),
        Err(e) => {
            tracing::warn!(target = %nc.key_id, error = %e, "claim-remote: local owner-binding persist FAILED (non-fatal)");
            ok = false;
        }
    }

    // (3) transport: append the target's RNS seed to net.bootstrap_peers (dedup),
    // using the same reachable base URL resolved above.
    if let Some(raw) = base_url {
        if let Some(addr) = rns_seed_from_target(raw) {
            match append_bootstrap_peer(&st.engine, &st.node_key_id, &addr).await {
                Ok(true) => {
                    tracing::info!(addr = %addr, "claim-remote: added target RNS seed to net.bootstrap_peers (mesh-reachable next boot)")
                }
                Ok(false) => {
                    tracing::debug!(addr = %addr, "claim-remote: target RNS seed already in net.bootstrap_peers")
                }
                Err(e) => {
                    tracing::warn!(addr = %addr, error = %e, "claim-remote: net.bootstrap_peers update FAILED (non-fatal)");
                    ok = false;
                }
            }
        }
    }

    ok
}

/// Merge the `local_directory_updated` flag into the target's claim-result JSON so
/// the operator sees whether the LOCAL record + mesh-reachability update succeeded
/// (the remote claim itself already succeeded — this is the local side-effect flag).
/// When the target result is a JSON object we add the field in place; otherwise we
/// wrap it as `{ "target": <result>, "local_directory_updated": <bool> }`.
fn with_local_flag(target_result: serde_json::Value, updated: bool) -> serde_json::Value {
    match target_result {
        serde_json::Value::Object(mut map) => {
            map.insert(
                "local_directory_updated".to_string(),
                serde_json::Value::Bool(updated),
            );
            serde_json::Value::Object(map)
        }
        other => serde_json::json!({
            "target": other,
            "local_directory_updated": updated,
        }),
    }
}

/// `POST /v1/self/upgrade-owner` — **upgrade an existing (already-owned) node to a
/// fed-ID owner-binding** (the WAs-need-fed-IDs migration; the agent team's 2.9.7).
///
/// An existing node may be owned the legacy way — a ROOT WA with a password/OAuth
/// login but NO fed-ID `delegates_to` owner-binding. This binds that node to a
/// (already-minted) fed-ID by persisting `delegates_to(fed-ID-user → node, infra:*)`
/// — the SAME CC 3.2 owner-binding the first-run claim uses, but authorized by the
/// EXISTING owner's session (not first-run/PIN) and applied locally (no setup/root,
/// so the existing ROOT is untouched and the password/OAuth login is PRESERVED).
/// Non-destructive (owner-binding model). After it, `is_steward_bound(node)` resolves
/// to the fed-ID user, and the node appears in the CEG-native owned-nodes list.
///
/// Flow: client logs in as the existing admin → mints the fed-ID
/// (`POST /v1/self/identity`, owner-gated) → calls this. Loopback + owner-gated.
async fn upgrade_owner_handler(State(st): State<ClaimRemoteState>, headers: HeaderMap) -> Response {
    // ALWAYS owner-session-gated: a node must already be owned to upgrade how its
    // ownership is rooted. The existing admin's session authorizes the fed-ID bind.
    if let Err(resp) = require_owner(&st, &headers).await {
        return resp;
    }
    // Resolve the fed-ID signer the client just minted (POST /v1/self/identity).
    let user_signer = match crate::compose::resolve_user_signer(
        &st.engine,
        crate::compose::FedIdUse::OwnerSession,
        // Resolve the owner user alias at REQUEST TIME from the active-alias pointer
        // the mint wrote (CIRISServer 0.5.59) — the user's chosen name (e.g.
        // `eric-moore-v1`), NOT the boot-captured `<node>-user`. Falls back to the
        // boot value for an identity minted before the pointer existed.
        &crate::active_user_alias(&st.user_seed_dir, &st.user_key_id),
        st.user_seed_dir.clone(),
    )
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "no federation ID on this node yet — create one (POST /v1/self/identity) \
                 before upgrading this account to a fed-ID owner-binding",
            )
        }
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("resolve user signer: {e}"),
            )
        }
    };

    // Build + locally apply the user-signed owner-binding (registers the fed-ID as a
    // `user` identity + persists the delegates_to). Reuses the claim substrate path,
    // minus the node-to-node HTTP and the first-run ROOT creation.
    let infra: Vec<String> = OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let binding =
        match ownership::build_signed_owner_binding(&user_signer, &st.node_key_id, &infra).await {
            Ok(b) => b,
            Err(e) => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("build owner-binding: {e}"),
                )
            }
        };
    // CIRISServer#125: upgrade-owner re-roots an existing node on a fed-ID — bind
    // it self-scoped by default (no federation announce until the owner opts in).
    match ownership::apply_signed_owner_binding(
        &st.engine,
        &st.node_key_id,
        ciris_persist::federation::types::cohort_scope::SELF,
        st.policy,
        &binding,
    )
    .await
    {
        Ok(applied) => {
            tracing::info!(
                responsible_user = %applied.responsible_user_key_id,
                node_key_id = %st.node_key_id,
                attestation_id = %applied.attestation_id,
                "upgrade-owner: existing node re-rooted on a fed-ID owner-binding \
                 (delegates_to(user → node, infra:*) persisted; legacy login preserved)"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "owner": applied.responsible_user_key_id,
                    "node_key_id": st.node_key_id,
                    "owner_binding_attestation_id": applied.attestation_id,
                })),
            )
                .into_response()
        }
        Err(e) => {
            let code = match e {
                ownership::OwnershipError::AgencyScopeRefused
                | ownership::OwnershipError::Validation(_)
                | ownership::OwnershipError::Canonicalize(_) => StatusCode::BAD_REQUEST,
                ownership::OwnershipError::Verify(_) => StatusCode::UNAUTHORIZED,
                ownership::OwnershipError::Sign(_) | ownership::OwnershipError::Persist(_) => {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            };
            err(code, format!("upgrade-owner failed: {e}"))
        }
    }
}

#[derive(Debug, Deserialize)]
struct SetAgeSelfRequest {
    /// `"minor"` | `"adult"` — the owner's self-declared age band.
    band: String,
}

/// `POST /v1/self/age` — record the BOUND OWNER's self-declared age band
/// (loopback + owner-session-gated). The federation `/v1/safety/age-assurance`
/// route requires an x-ciris-signed REQUEST (the subject signs), which the app
/// (no crypto) cannot produce. This wizard-time sibling lets the LOCAL node record
/// the owner's self-declared age in its substrate: the subject is the node's bound
/// owner fed-ID ([`ownership::is_steward_bound`]) and
/// [`crate::safety::age::emit_age_assurance`] persists + node-co-signs the
/// promotion (no caller signature needed). MUST run AFTER the claim (the owner
/// must exist), before the wizard closes.
async fn set_age_self(
    State(st): State<ClaimRemoteState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Owner-session-gated: post-claim the node is owned → require_owner enforces a
    // session (the wizard logs in with the account password before this call).
    match require_owner(&st, &headers).await {
        Ok(caller) => {
            if let Some(resp) =
                crate::auth::gate::require_verb(&caller, crate::auth::gate::CapabilityVerb::SetAge)
            {
                return resp;
            }
        }
        Err(resp) => return resp,
    }
    let req: SetAgeSelfRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    let Some(band) = crate::safety::age::AgeBand::from_token(req.band.trim()) else {
        return err(
            StatusCode::BAD_REQUEST,
            "band must be \"minor\" or \"adult\"",
        );
    };
    // The subject signs their OWN self-declared age with their fed-ID — a
    // CEG-native, hybrid-signed federation attestation (NOT the unsigned
    // local-upsert+promote path, broken by CIRISPersist#247). The node holds the
    // owner's fed-ID signer (resolved at request time, same as the self-claim).
    let signer =
        match crate::compose::resolve_user_signer(
            &st.engine,
            crate::compose::FedIdUse::OwnerSession,
            // Resolve the ACTIVE owner alias (the name-driven fed-ID, e.g.
            // eric-moore-v1) via the pointer file — NOT the raw <node>-user
            // default. Without this, set-age looked for <node>-user, missed the
            // just-minted fed-ID, and 409'd post-claim (the age band never got
            // recorded). Mirrors the claim-remote signer resolution above.
            &crate::active_user_alias(&st.user_seed_dir, &st.user_key_id),
            st.user_seed_dir.clone(),
        )
        .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return err(
                StatusCode::CONFLICT,
                "node has no federation ID yet — create one + claim ownership before setting age",
            ),
            Err(e) => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("resolve user signer: {e}"),
                )
            }
        };
    let subject = signer.key_id().to_string();
    match crate::safety::age::emit_age_assurance_signed(
        &st.engine,
        &signer,
        crate::safety::age::AssuranceLevel::SelfDeclared,
        band,
    )
    .await
    {
        Ok(attestation_id) => {
            tracing::info!(subject = %subject, band = %band.as_str(), "self-age recorded (CEG-native, subject-fed-ID-signed; loopback owner session)");
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "subject_key_id": subject,
                    "band": band.as_str(),
                    "attestation_id": attestation_id,
                })),
            )
                .into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("set age: {e}")),
    }
}

/// `POST /v1/federation/announce` — **announce yourself to the federation**
/// (CIRISServer#125, owner-gated, loopback-only). The OPT-IN that turns a
/// self-scoped node into a federation participant. Two TIED effects:
///
///   1. **PROMOTE** this node's owner-binding `delegates_to(owner → node)` from
///      `cohort_scope: self` to `federation` ([`ownership::promote_owner_binding_to_federation`])
///      — public responsible-party accountability. Re-persists the EXISTING
///      user-signed envelope + the owner's original signatures at the wider cohort
///      (cohort is not in the signed envelope, so the proven signature re-verifies);
///      no fresh signing / no user signer needed.
///   2. **ENABLE the Reticulum identity announce** — set the boot-structural
///      `net.announce_ownership` config:* key to `true` (owner-authored CEG write).
///      On the NEXT boot [`crate::compose`] wires the federation signer into the
///      announce so it carries the AV-42 authenticated identity attestation (peers
///      can root `key_id → destination`). Until then the node stays
///      identity-silent on the mesh (transport bring-up is unaffected either way).
///
/// Idempotent (a re-announce no-ops the already-federation promote and re-affirms
/// the config). Owner-session-gated (SYSTEM_ADMIN) — and the promote itself errors
/// if the node is not yet owner-bound (you cannot announce an ownership you do not
/// hold). DEFAULT (no announce) = self-scoped + no identity announce; you only
/// promote if you want a federation role.
async fn announce_self_handler(State(st): State<ClaimRemoteState>, headers: HeaderMap) -> Response {
    // Always owner-session-gated: announcing your node to the federation is an apex
    // act, never reachable first-run/unowned (the promote below also enforces
    // owner-bound). No first-run bypass (unlike claim-remote, which BOOTSTRAPS
    // ownership — this op presupposes it).
    let caller = match require_owner(&st, &headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    // A delegate may announce only if its grant permits the `announce` verb.
    if let Some(resp) =
        crate::auth::gate::require_verb(&caller, crate::auth::gate::CapabilityVerb::Announce)
    {
        return resp;
    }

    // (1) Promote the owner-binding self → FEDERATION.
    let promoted = match crate::auth::ownership::promote_owner_binding_to_federation(
        &st.engine,
        &st.node_key_id,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            let code = match e {
                ownership::OwnershipError::Validation(_) => StatusCode::CONFLICT,
                ownership::OwnershipError::Persist(_) => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return err(
                code,
                format!("announce (promote owner-binding) failed: {e}"),
            );
        }
    };

    // (2) Enable the boot-structural Reticulum identity announce (owner-authored
    // CEG write). Takes effect on the next boot (the announce attestation is built
    // once at transport construction).
    if let Err(e) = crate::graph_config::set_config(
        &st.engine,
        &st.node_key_id,
        crate::config_reconcile::KEY_ANNOUNCE_OWNERSHIP,
        crate::graph_config::ConfigValue::Bool(true),
        &caller.wa_id,
        crate::graph_config::ConfigScope::default(),
    )
    .await
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("announce (enable Reticulum identity announce) failed: {e}"),
        );
    }

    tracing::info!(
        responsible_user = %promoted.responsible_user_key_id,
        node_key_id = %st.node_key_id,
        promoted_attestation_id = ?promoted.attestation_id,
        "announce-self: owner-binding promoted to FEDERATION + net.announce_ownership=true \
         (Reticulum identity announce takes effect on next boot)"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "owner": promoted.responsible_user_key_id,
            "node_key_id": st.node_key_id,
            "cohort_scope": ciris_persist::federation::types::cohort_scope::FEDERATION,
            // None ⇒ the binding was already federation-scoped (idempotent re-announce).
            "promoted_owner_binding_attestation_id": promoted.attestation_id,
            "announce_ownership": true,
            "announce_takes_effect": "next_boot",
        })),
    )
        .into_response()
}

/// The claim-remote router — merge onto the control API listener. `user_signer`
/// is the responsible USER's signer (NOT the node steward signer); see the module
/// docs for how it is obtained and the keyring/YubiKey gap.
pub fn router(
    engine: Arc<Engine>,
    node_key_id: String,
    user_key_id: String,
    user_seed_dir: std::path::PathBuf,
    local_self_url: String,
    policy: HybridPolicy,
) -> Router {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_default();
    let state = ClaimRemoteState {
        engine,
        node_key_id,
        user_key_id,
        user_seed_dir,
        local_self_url,
        policy,
        http,
    };
    Router::new()
        .route(
            "/v1/setup/claim-remote",
            axum::routing::post(claim_remote_handler),
        )
        .route(
            "/v1/self/upgrade-owner",
            axum::routing::post(upgrade_owner_handler),
        )
        .route("/v1/self/age", axum::routing::post(set_age_self))
        .route(
            "/v1/federation/announce",
            axum::routing::post(announce_self_handler),
        )
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::{rns_seed_from_target, with_local_flag};

    #[test]
    fn rns_seed_derives_host_at_node_port_from_read_api_url() {
        // The read-API URL is HTTP on 4243; the RNS seed keeps the HOST + pins 4242.
        assert_eq!(
            rns_seed_from_target("http://108.61.242.236:4243").as_deref(),
            Some("108.61.242.236:4242")
        );
        assert_eq!(
            rns_seed_from_target("https://108.61.242.236:4243/").as_deref(),
            Some("108.61.242.236:4242")
        );
        // Bare host:port (no scheme) and a trailing path both reduce to host:4242.
        assert_eq!(
            rns_seed_from_target("108.61.242.236:4243").as_deref(),
            Some("108.61.242.236:4242")
        );
        assert_eq!(
            rns_seed_from_target("http://node.example.org:8080/v1/x").as_deref(),
            Some("node.example.org:4242")
        );
        // userinfo is stripped; the host is kept.
        assert_eq!(
            rns_seed_from_target("http://user@1.2.3.4:9000").as_deref(),
            Some("1.2.3.4:4242")
        );
        // IPv6 literal keeps its brackets so the result parses as a SocketAddr.
        assert_eq!(
            rns_seed_from_target("http://[2001:db8::1]:4243").as_deref(),
            Some("[2001:db8::1]:4242")
        );
        // Empty / whitespace ⇒ nothing to record.
        assert_eq!(rns_seed_from_target("   "), None);
    }

    #[test]
    fn with_local_flag_merges_into_object_or_wraps() {
        // Object result: the flag is added in place.
        let merged = with_local_flag(serde_json::json!({ "owner": "u1" }), true);
        assert_eq!(merged["owner"], "u1");
        assert_eq!(merged["local_directory_updated"], true);
        // Non-object result: wrapped under `target`.
        let wrapped = with_local_flag(serde_json::json!("ok"), false);
        assert_eq!(wrapped["target"], "ok");
        assert_eq!(wrapped["local_directory_updated"], false);
    }
}
