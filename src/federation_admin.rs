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
    /// **CC 2.6.4 wire-version negotiation** (CIRISServer#159). The peer's declared
    /// CEG wire version + pinned `WIRE_VOCABULARY.md` SHA-256. Optional-with-
    /// documented-default (a peer that predates negotiation omits them and is judged
    /// against [`crate::conformance::PRE_NEGOTIATION_WIRE_VERSION`]); a peer that
    /// DOES announce an incompatible wire is REFUSED (`409`), never silently
    /// tolerated. Flattened so the fields ride the request body top-level
    /// (`ceg_wire_version` / `wire_vocabulary_sha256`).
    #[serde(default, flatten)]
    wire: crate::conformance::PeerWireAnnouncement,
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
    /// **CC 2.6.4** — the wire version this node NEGOTIATED with the peer (the
    /// peer's announced version, positively established as interoperable with ours).
    negotiated_ceg_wire_version: String,
    /// **CC 2.2** — THIS node's declared conformance level, echoed so negotiation is
    /// SYMMETRIC: the requester can refuse US if our declaration does not claim the
    /// profiles it needs from a replication peer.
    conformance: crate::conformance::DeclaredConformance,
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
    match require_owner(&st, &headers).await {
        Ok(caller) => {
            if let Some(resp) =
                crate::auth::gate::require_verb(&caller, crate::auth::gate::CapabilityVerb::Peer)
            {
                return resp;
            }
        }
        Err(resp) => return resp,
    }
    // ── (CC 2.2 — conformance levels, CIRISServer#159) ────────────────────────
    // Peering is the full federation-wire act: this node EMITS a hybrid-signed
    // consent grant (CCP), ADMITS the peer's key record through the fail-secure
    // admission gate (CCC), and thereafter REPLICATES rows under the CC 5.3.1 /
    // 5.3.2 storage+transport guarantees (CCS). A node performs on the wire ONLY
    // the roles it CLAIMS: if its declared level
    // (`config:node.conformance_profiles`) does not claim all three, peering is
    // REFUSED (403) — before any key is admitted and before any grant is authored.
    // Fail-closed: an unreadable / invalid declaration claims NOTHING.
    if let Some(resp) = crate::conformance::require_op(
        &st.engine,
        &st.node_key_id,
        crate::auth::gate::CapabilityVerb::Peer,
    )
    .await
    {
        return resp;
    }

    let req: PeeringRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };

    // ── (CC 2.6.4 — versioning policy, CIRISServer#159) ───────────────────────
    // "A peer knows from the version alone whether it can still interoperate."
    // Negotiate the peer's announced CEG wire version (SemVer 2.0.0 mapping: a
    // differing MAJOR — or, pre-1.0-publication, a differing MINOR / pre-release —
    // is a WIRE BREAK) and its pinned WIRE_VOCABULARY.md hash ("a hash mismatch at
    // cohabitation is a substrate-tier build failure, not a warning"). An
    // incompatible / malformed wire is REFUSED (409) BEFORE the peer's key is
    // admitted: admitting a key from a peer whose envelopes we cannot correctly
    // canonicalize is exactly the silent divergence CC 2.6.4 forecloses.
    let negotiated = match crate::conformance::negotiate(&req.wire) {
        Ok(v) => v,
        Err(refusal) => {
            tracing::warn!(
                peer_key_id = %req.peer_key_id,
                error = refusal.error,
                peer_wire = %refusal.peer_ceg_wire_version,
                local_wire = %refusal.local_ceg_wire_version,
                "CC 2.6.4: peering REFUSED — incompatible peer wire"
            );
            return crate::conformance::wire_refusal_response(*refusal);
        }
    };

    // Consistency: the carried record's key_id MUST match the declared peer_key_id
    // (refuse an inconsistent peering, mirroring the boot-env config check).
    if req.peer_key_record.record.key_id != req.peer_key_id {
        return err(
            StatusCode::BAD_REQUEST,
            "peer_key_id does not match peer_key_record.record.key_id",
        );
    }

    // ── CC 4.1.4 (CIRISServer#159) — withdraws-arbitrage refusal ─────────────
    // Before we agree to CONSUME a peer's corpus, judge how it *retracts*. An
    // attester that emits `withdraws` (free) where an honest one emits `recants`
    // (costly — it admits the row was false at issuance) is buying the effect of a
    // retraction without paying the epistemic-error price; over a rolling window a
    // ratio above the configured threshold (CC 4.1.4 default 5:1) is the signature
    // of that arbitrage (see `crate::withdraws_arbitrage`). CC 4.1.4 puts the
    // countermeasure in CONSUMER POLICY, not the wire: we do not refuse the peer's
    // `withdraws` rows at admission (CC 2.4.1.1 makes that a substrate MUST-admit,
    // and a wire-level refusal would be the CC 4.1.2 anti-pattern) — we refuse the
    // *peering*, which is the one lever a consumer legitimately holds.
    //
    // The ledger is built from the rows THIS node already holds for that attester
    // (a first-contact peer has none → clean → admitted; a peer we have been
    // replicating with, and whose behavior we have therefore observed, is judged on
    // that observed history). Fail closed: an unreadable ledger refuses too.
    {
        let policy = crate::withdraws_arbitrage::load_policy(&st.engine, &st.node_key_id).await;
        if let Err(refusal) = crate::withdraws_arbitrage::enforce(
            &st.engine,
            &req.peer_key_id,
            policy,
            chrono::Utc::now(),
        )
        .await
        {
            tracing::warn!(
                peer_key_id = %req.peer_key_id,
                refusal = %refusal,
                "CC 4.1.4 withdraws-arbitrage: REFUSING federation peering"
            );
            return err(StatusCode::FORBIDDEN, refusal.to_string());
        }
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
            negotiated_ceg_wire_version: negotiated.to_string(),
            conformance: crate::conformance::declared(&st.engine, &st.node_key_id).await,
        }),
    )
        .into_response()
}

// ─── GET /v1/federation/conformance (unauthenticated; the peer-facing surface) ─

/// `GET /v1/federation/conformance` — THIS node's **declared CC 2.2 conformance
/// level** + its **CC 2.6.4 wire identity** (CIRISServer#159).
///
/// CC 2.2 exists so that "conforming" means the same thing to every peer — which
/// requires the claim to be READABLE by a peer BEFORE it commits to a federation
/// relationship. This is that surface: a peer fetches it alongside
/// `/v1/federation/self-key-record` and can refuse us (wrong wire version, wrong
/// wire vocabulary, or a declaration that does not claim the profile it needs from
/// a replication partner) exactly as we refuse it in `peering`. Negotiation is
/// SYMMETRIC or it is theatre.
///
/// Unauthenticated by design, like the self-key-record beside it: a conformance
/// declaration is public governance data (it carries no secret — only what this node
/// claims to be), and a peer must be able to read it to bootstrap.
async fn conformance(State(st): State<FederationAdminState>) -> Response {
    let declared = crate::conformance::declared(&st.engine, &st.node_key_id).await;
    (StatusCode::OK, Json(declared)).into_response()
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
/// Body for `POST /v1/federation/adopt-scrubbed`: an accord-holder-scrubbed
/// `SignedKeyRecord` for a key already registered on this node (typically THIS
/// node's own row). The record is **self-authenticating** — `adopt_scrub_upgrade`
/// verifies the scrub signature against the seeded accord anchor — so the node
/// does no signing and need not trust the delivering operator.
#[derive(Debug, Deserialize)]
struct AdoptScrubbedRequest {
    record: SignedKeyRecord,
}

#[derive(Debug, Serialize)]
struct AdoptScrubbedResponse {
    key_id: String,
    /// `"upgraded"` (the self-signed row was replaced by the anchor-scrubbed
    /// record) or `"already_adopted"` (idempotent no-op).
    outcome: String,
}

/// `POST /v1/federation/adopt-scrubbed` — owner-gated. **The seed PRODUCER's
/// remote leg** (CIRISServer#150 / CIRISPersist#351): adopt an accord-holder
/// (A1)-scrubbed record onto an existing `federation_keys` row (this node's own
/// row) so the node roots at the accord anchor and its Key plane publishes an
/// anchored, rootable record.
///
/// Why an endpoint (not just admit-node's local adopt): the holder keys live on
/// the operator's crypto-ops machine, NOT on the canonical node. The operator
/// runs `admit-node target=A` there to PRODUCE A's scrubbed record, then delivers
/// it here so **A** adopts it onto **A's own** row (rooting is a receiver-side
/// directory lookup — a peer roots its own stored copy). The scrub signature is
/// verified against the seeded anchor by `adopt_scrub_upgrade`, so this is safe
/// even though the record arrived over the wire; owner-gating is defence-in-depth.
async fn adopt_scrubbed(
    State(st): State<FederationAdminState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if crate::auth::gate::require_owner_bound(&st.engine, &st.node_key_id)
        .await
        .is_err()
    {
        return err(
            StatusCode::FORBIDDEN,
            "this node has no responsible party (owner-binding) — adopt-scrubbed refused. \
             Claim ownership first via POST /v1/setup/root.",
        );
    }
    if let Err(resp) = require_owner(&st, &headers).await {
        return resp;
    }
    let req: AdoptScrubbedRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    let key_id = req.record.record.key_id.clone();
    match st.engine.adopt_scrub_upgrade(req.record).await {
        Ok(outcome) => {
            use ciris_persist::federation::register::AdoptScrubOutcome;
            let outcome = match outcome {
                AdoptScrubOutcome::Upgraded => "upgraded",
                AdoptScrubOutcome::AlreadyAdopted => "already_adopted",
            };
            tracing::info!(
                key_id = %key_id,
                outcome,
                "adopt-scrubbed: adopted the accord-scrubbed record onto the local row"
            );
            (
                StatusCode::OK,
                Json(AdoptScrubbedResponse {
                    key_id,
                    outcome: outcome.to_string(),
                }),
            )
                .into_response()
        }
        // Gated failure: the row isn't a valid self-signed→scrubbed upgrade, the
        // scrub sig doesn't verify against the seeded anchor, or the pubkey drifts.
        Err(e) => err(
            StatusCode::BAD_REQUEST,
            format!("adopt-scrubbed rejected for {key_id}: {e}"),
        ),
    }
}

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
        // CC 2.2 / CC 2.6.4 (CIRISServer#159) — the peer-facing declaration.
        .route(
            "/v1/federation/conformance",
            axum::routing::get(conformance),
        )
        .route(
            "/v1/federation/adopt-scrubbed",
            axum::routing::post(adopt_scrubbed),
        )
        .with_state(state)
}
