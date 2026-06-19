//! Owner-directed federation operations — the **code of a decentralized fabric
//! node** that lets a node's OWNER set up `consent:replication` peering on demand,
//! not just at boot from the `CIRIS_PEER_B_*` env (see `compose::setup_peer_replication`).
//!
//! These are owner-authority operations on the node itself, NOT "server endpoints
//! for a client": each node AUTHORS ITS OWN directed `consent:replication:v1`
//! grant (`attesting_key_id` = THIS node), preserving the RC29 normative model
//! where a consent object is self-attested by the granting party (forecloses
//! third-party forgery of a consent grant, CEG 1.0-RC29 §5.6.8.15). The fabric
//! app (CIRISAgent/client) orchestrates the BILATERAL A↔B setup by driving the
//! pair of owner operations — fetch A's + B's self-key-records, then POST peering
//! to A (peer = B) and to B (peer = A) — but the authority for each grant stays
//! local to the node that signs it.
//!
//! Two operations, merged onto the control API beside the other auth routers:
//!
//!   1. `GET  /v1/federation/self-key-record` — THIS node's own self-signed
//!      [`SignedKeyRecord`](ciris_persist::federation::SignedKeyRecord) as JSON.
//!      This is the PUBLIC key record a peer must register (via its own peering
//!      op) to admit this node's replicated rows — the same JSON a peer would put
//!      in `CIRIS_PEER_B_KEY_RECORD` / `STATUS_PEER_A_KEY_RECORD`. A federation
//!      key record is public proof-of-possession (it carries only pubkeys + a
//!      self-signature), so this read is **unauthenticated by design** — there is
//!      nothing secret to gate, and a peer must be able to fetch it to bootstrap.
//!
//!   2. `POST /v1/federation/peering` — owner/SYSTEM_ADMIN-gated. Idempotently
//!      (a) registers the peer's self-signed key via the fail-secure admission
//!      gate ([`crate::peer::register_peer_key`] → `Engine::register_federation_key`),
//!      then (b) emits THIS node's directed `consent:replication:v1` grant at the
//!      peer carrying the caller-supplied `attestation_prefixes`
//!      ([`crate::peer::emit_replication_consent`]). Because this authorizes
//!      CROSS-NODE DATA FLOW, it is gated on the highest authority the role model
//!      exposes — see [`require_owner`].

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::federation::SignedKeyRecord;
use ciris_persist::prelude::Engine;
use serde::{Deserialize, Serialize};

use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::{resolve_bearer, SessionCaller};
use crate::config::PeerB;

#[derive(Clone)]
struct FederationAdminState {
    engine: Arc<Engine>,
    /// THIS node's federation `key_id` (the `attesting_key_id` of every grant it
    /// authors).
    node_key_id: String,
    /// THIS node's own self-signed `SignedKeyRecord` as JSON — built ONCE at boot
    /// from the node's signer (stable for the node's lifetime), served verbatim.
    self_key_record_json: Arc<String>,
    /// Nudge for the CEG-driven replication reconciler
    /// ([`crate::replication_reconcile`]). After a successful consent write this
    /// handler fires `notify_one()` so the reconcile loop converges promptly —
    /// it NEVER touches the runtime itself (the architecture rule: the API writes
    /// CEG, the runtime is CEG-driven). `None` when no runtime exists to converge
    /// (no transport) — the consent CEG is still written.
    reconcile_notify: Option<Arc<tokio::sync::Notify>>,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// Owner-authority gate for `POST /v1/federation/peering`. Peering authorizes
/// cross-node data flow (this node consents to replicate its rows to a peer AND
/// admits the peer's rows), so it is gated on the APEX of the role hierarchy:
/// `SYSTEM_ADMIN` (the owner role), carrying [`Permission::FullAccess`]. This is
/// strictly higher than the `manage_user_permissions` gate the api-keys routes
/// use (which `AUTHORITY` also satisfies) — federation peering is an owner-only
/// act. Reuses the same `resolve_bearer → SessionCaller → check` spine as
/// `api_keys::require_manage_users`. Returns the verified caller, or a
/// `401`/`403`/`503` response to short-circuit.
async fn require_owner(
    st: &FederationAdminState,
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
        // Apex-gate: require the SYSTEM_ADMIN (owner) role AND its FullAccess
        // permission — both, so neither a future role-permission drift nor a
        // permission-only check can silently widen who may author cross-node flow.
        Ok(Some(caller))
            if caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) =>
        {
            Ok(caller)
        }
        Ok(Some(_)) => Err(err(
            StatusCode::FORBIDDEN,
            "federation peering requires the owner (SYSTEM_ADMIN) role",
        )),
        Ok(None) => Err(err(StatusCode::UNAUTHORIZED, "invalid or expired session")),
        Err(e) => Err(err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}"))),
    }
}

// ─── GET /v1/federation/self-key-record (unauthenticated; see module docs) ───

async fn self_key_record(State(st): State<FederationAdminState>) -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        (*st.self_key_record_json).clone(),
    )
        .into_response()
}

// ─── POST /v1/federation/peering (owner-gated) ───────────────────────────────

#[derive(Debug, Deserialize)]
struct PeeringRequest {
    /// The peer's federation `key_id` (must match `peer_key_record.record.key_id`).
    peer_key_id: String,
    /// The peer's OWN self-signed `SignedKeyRecord` (proof-of-possession) — passed
    /// verbatim to the fail-secure admission gate, which verifies the peer's hybrid
    /// signature BEFORE storing. A forged/unverifiable record is rejected and never
    /// stored.
    peer_key_record: SignedKeyRecord,
    /// The namespace-prefix set THIS node consents to replicate to the peer
    /// (trailing ":" significant). Normalized (trimmed / empty-dropped / sorted /
    /// deduped) before it lands in the grant payload.
    #[serde(default)]
    attestation_prefixes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PeeringResponse {
    /// The peer `key_id` that was admitted.
    peer_key_id: String,
    /// This node's grant row id (`attestation_id`).
    grant_attestation_id: String,
    /// The grant envelope's `original_content_hash`.
    grant_content_hash: String,
    /// `true` when this call wrote a fresh grant; `false` on an idempotent no-op
    /// (the durable grant already existed).
    freshly_emitted: bool,
    /// The normalized prefix set the grant carries (echo of the request, sorted +
    /// deduped).
    attestation_prefixes: Vec<String>,
    /// Human-readable note that the consent was recorded as CEG and the node's
    /// reconcile loop (NOT this API call) converges the live runtime to it.
    reconciler_note: String,
}

async fn peering(
    State(st): State<FederationAdminState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // (serve-only floor — CC 3.2 / CC 1.13.5) An UNOWNED node refuses every
    // owner-op and serves cleartext federation data from the canonical root
    // ONLY. Federation peering authorizes cross-node data flow, so it requires a
    // live RESPONSIBLE PARTY bound to THIS node (a `user`-role
    // `delegates_to(user → node, infra:*)` owner-binding). This gate is
    // independent of the session/role check below: even a SYSTEM_ADMIN session
    // cannot peer an owner-unbound node — the node has no accountable party to
    // root the cross-node authority in.
    if crate::auth::gate::require_owner_bound(&st.engine, &st.node_key_id)
        .await
        .is_err()
    {
        return err(
            StatusCode::FORBIDDEN,
            "this node has no responsible party (owner-binding) — federation peering refused; \
             an unowned node serves cleartext from the canonical root only (CC 3.2 / CC 1.13.5). \
             Claim ownership first via POST /v1/setup/root.",
        );
    }
    if let Err(resp) = require_owner(&st, &headers).await {
        return resp;
    }
    let req: PeeringRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };

    // Consistency: the carried record's key_id MUST match the declared peer_key_id
    // (refuse an inconsistent peering, mirroring the boot-env config check).
    if req.peer_key_record.record.key_id != req.peer_key_id {
        return err(
            StatusCode::BAD_REQUEST,
            "peer_key_id does not match peer_key_record.record.key_id",
        );
    }

    // ── (a) Admission: register the peer's self-signed key (fail-secure verify;
    //    benign Conflict on a matching existing row). ──────────────────────────
    let peer = PeerB {
        key_id: req.peer_key_id.clone(),
        key_record: req.peer_key_record,
    };
    if let Err(e) = crate::peer::register_peer_key(&st.engine, &peer).await {
        // register_peer_key swallows benign Conflict; a real error here is the
        // fail-secure verify rejecting a forged/unverifiable peer record.
        return err(
            StatusCode::BAD_REQUEST,
            format!("peer key registration rejected: {e}"),
        );
    }

    // ── (b) Consent: emit THIS node's directed consent:replication:v1 grant at
    //    the peer, carrying the caller-supplied prefixes (idempotent). ──────────
    let grant = match crate::peer::emit_replication_consent(
        &st.engine,
        &st.node_key_id,
        &peer.key_id,
        &req.attestation_prefixes,
    )
    .await
    {
        Ok(g) => g,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("emit replication consent: {e}"),
            )
        }
    };

    // ── Nudge the CEG-driven reconciler ───────────────────────────────────────
    // The handler does NOT touch the runtime (the architecture rule). It only
    // signals "CEG changed, reconcile now"; the reconcile loop reads the consent
    // objects back and converges the live runtime to them. A no-op when no runtime
    // exists (no transport) — the consent CEG is durable either way.
    if let Some(notify) = st.reconcile_notify.as_ref() {
        notify.notify_one();
    }

    (
        StatusCode::OK,
        Json(PeeringResponse {
            peer_key_id: peer.key_id,
            grant_attestation_id: grant.attestation_id,
            grant_content_hash: grant.content_hash,
            freshly_emitted: grant.freshly_emitted,
            attestation_prefixes: crate::peer::normalize_prefixes(&req.attestation_prefixes),
            reconciler_note: "consent:replication recorded; the node's reconcile loop converges \
                              the live replication runtime to it at runtime via set_peers — the \
                              peer becomes an active Initiator immediately, no restart (edge \
                              v5.1.0, CIRISEdge#173 resolved)"
                .to_owned(),
        }),
    )
        .into_response()
}

/// The owner-directed federation-operations router — merge onto the control API
/// listener beside the other auth routers. `self_key_record_json` is THIS node's
/// own self-signed `SignedKeyRecord` JSON, built once at boot.
///
/// `reconcile_notify` is the CEG-driven reconciler's nudge ([`crate::replication_reconcile`]):
/// after a successful consent write, the peering handler fires it so convergence is
/// prompt. It is `None` when no replication runtime exists (no transport) — the
/// consent CEG is still written; there is just no runtime to converge. **The
/// handler never touches the runtime** — this is the only coupling, and it is a
/// one-way signal, not a runtime call.
pub fn router(
    engine: Arc<Engine>,
    node_key_id: String,
    self_key_record_json: String,
    reconcile_notify: Option<Arc<tokio::sync::Notify>>,
) -> Router {
    let state = FederationAdminState {
        engine,
        node_key_id,
        self_key_record_json: Arc::new(self_key_record_json),
        reconcile_notify,
    };
    Router::new()
        .route(
            "/v1/federation/self-key-record",
            axum::routing::get(self_key_record),
        )
        .route("/v1/federation/peering", axum::routing::post(peering))
        .with_state(state)
}
