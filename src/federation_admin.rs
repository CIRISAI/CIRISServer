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
//!
//!   3. `POST /v1/federation/consent` — owner-gated. The first-class, EXPLICIT
//!      consent act: author THIS node's directed `consent:replication:v1` grant
//!      at an ALREADY-ADMITTED peer (no key registration — that is `peering`),
//!      carrying an explicit owner-chosen scope. Consent is ALWAYS an
//!      owner-authored CEG claim, never auto-generated; the agent's setup wizard
//!      calls this on owner opt-in (e.g. "Send traces to CIRIS L3C"). See
//!      [`consent`].

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
    if let Some(resp) =
        crate::conformance::require_op(&st.engine, crate::auth::gate::CapabilityVerb::Peer).await
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
        let policy = crate::withdraws_arbitrage::load_policy(&st.engine).await;
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
            conformance: crate::conformance::declared(&st.engine).await,
        }),
    )
        .into_response()
}

// ─── POST /v1/federation/consent (owner-gated; the explicit consent act) ──────

/// Request body for [`consent`].
#[derive(Debug, Deserialize)]
struct EraseTracesRequest {
    /// The agent whose trace corpus is erased — hash, not a key id: erasure
    /// covers ALL of that agent's signing keys (persist keys on agent_id_hash
    /// alone for exactly this reason).
    agent_id_hash: String,
    /// MANDATORY. Recorded in the log line beside the counts. An erasure with
    /// no stated reason cannot be told from an unauthorized one afterwards.
    reason: String,
}

#[derive(Debug, Deserialize)]
struct ConsentRequest {
    /// The peer this node consents to replicate to. MUST already be an admitted
    /// `federation_keys` row (e.g. the baked canonical). This route does NOT
    /// register keys — that is [`peering`]'s job; here we only author consent to
    /// a peer the node already knows.
    peer_key_id: String,
    /// The EXPLICIT replication scope — the attestation-dimension prefixes this
    /// grant covers (e.g. `["capacity:"]`, `["trace:"]`). Consent is always
    /// explicit about WHAT it covers: an empty set is refused (400).
    #[serde(default)]
    attestation_prefixes: Vec<String>,
    /// Optional owner-chosen recipient cohort — one of the 7 closed
    /// [`cohort_scope`](ciris_persist::federation::types::cohort_scope) values
    /// (`self` / `family` / … / `federation`). Omitted ⇒ persist's default
    /// (`federation`). A bad token is refused (400) — the owner narrows the
    /// audience explicitly (#510 P2).
    #[serde(default)]
    audience: Option<String>,
    /// Optional payload-declared expiry (RFC3339). Omitted ⇒ no expiry.
    #[serde(default)]
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Optional restrictions on the covered flow — parsed straight into persist's
    /// OWN closed [`RestrictionOp`](ciris_persist::federation::consent_grammar::RestrictionOp)
    /// enum (`{"op":"strip_field","path":…}` / `{"op":"recipient_capability",
    /// "capability":…}`), so an unrecognized `op` fails deserialization of the whole
    /// request (400) — the same fail-closed posture persist admission uses.
    #[serde(default)]
    restrictions: Vec<ciris_persist::federation::consent_grammar::RestrictionOp>,
    /// **CIRISConstitution#46 — consent to BE SCORED.** When true, this route also
    /// authors the `analyze`-scoped grant that lets `peer_key_id` author
    /// `capacity:*` claims about this node.
    ///
    /// Why it rides the same request: v22 refuses a `capacity:*` claim about a
    /// subject unless a live `analyze` consent from that subject covers the
    /// attester. Until now NOTHING in production could author that row — the only
    /// producer was the test-anchor harness — so capacity scoring was structurally
    /// dead in every real deployment (CIRISServer#331). It belongs here because it
    /// matches the owner's actual mental model: "send my traces to X" already
    /// means "X may score them" — being scored is *why* the traces are sent.
    ///
    /// Still explicit, never implied: default `false`, and the two grants are
    /// distinct CEG objects that can be withdrawn independently.
    #[serde(default)]
    analyze: bool,
}

/// Response body for [`consent`].
#[derive(Debug, Serialize)]
struct ConsentResponse {
    consented: bool,
    peer_key_id: String,
    grant_attestation_id: String,
    grant_content_hash: String,
    freshly_emitted: bool,
    attestation_prefixes: Vec<String>,
    /// The recipient cohort the grant was authored with (echoes the resolved
    /// audience — the owner-supplied value, or `federation` when omitted).
    audience: String,
    /// The `analyze` grant's attestation id when one was authored (CC#46), else
    /// `None`. Distinct from the replication grant: two objects, two lifetimes.
    analyze_grant_attestation_id: Option<String>,
    reconciler_note: &'static str,
}

/// `POST /v1/federation/erase-agent-traces` — GDPR Art. 17 / DSAR full erasure
/// of one agent's trace corpus, keyed on `agent_id_hash`.
///
/// # Why this route exists
///
/// `Engine::delete_traces_for_agent_id_hash` has shipped in persist since
/// v6.9.0 (#222) and had NO caller anywhere in this repo. The erasure primitive
/// was built, atomic, tombstoning and audited — and unreachable. An operator
/// facing a deletion demand had the capability and no way to invoke it.
///
/// Persist does the hard part in one transaction: hard-deletes `trace_events` +
/// `trace_llm_calls`, TOMBSTONES the derived `detection_events` (NULLs the PII
/// linkage, stamps `erased_at` — the analytics survive, the subject linkage is
/// severed), and emits a `hard_case:trace_erasure` audit row. Idempotent: a
/// second call returns all-zero counts rather than an error.
///
/// # Scope — what this deliberately does NOT reach
///
/// TRACES ONLY. A payload can hide in any of six arbitrary-payload fields
/// (`attestation_envelope`, `registration_envelope`, `attestation_evidence`
/// (raw bytes), `policy_blob` x2, `HardCaseEvent.detail`), and every erasure
/// primitive persist exposes is keyed by a ROLE — agent, actor, content_id,
/// tier — never by OBJECT. There is no `(table, row_id)` erasure at all.
/// Filed as CIRISPersist#573. Until that lands, the only lever for a payload
/// outside the trace corpus is `evict_actor` on the whole key, which is the
/// CA-distrust problem: a tool so blunt it never gets pulled.
///
/// Owner-gated identically to consent/peering: owner-binding, owner session,
/// and the `Peer` verb. Erasure is not a routine read.
async fn erase_agent_traces(
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
            "this node has no responsible party (owner-binding) — erasure refused; \
             an unowned node performs no erasure on anyone's behalf.",
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

    let req: EraseTracesRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    if req.agent_id_hash.trim().is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "agent_id_hash is required — erasure is never inferred from context",
        );
    }
    if req.reason.trim().is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "reason is required — an erasure that does not record why it happened is \
             indistinguishable from an unauthorized one once the actor is gone",
        );
    }

    match st
        .engine
        .delete_traces_for_agent_id_hash(&req.agent_id_hash)
        .await
    {
        Ok(sum) => {
            tracing::warn!(
                agent_id_hash = %req.agent_id_hash,
                reason = %req.reason,
                trace_events = sum.trace_events,
                trace_llm_calls = sum.trace_llm_calls,
                detection_events_tombstoned = sum.detection_events_tombstoned,
                "ERASURE performed (GDPR Art. 17 / DSAR) — traces hard-deleted, detection \
                 linkage tombstoned, hard_case:trace_erasure emitted by persist"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "erased": true,
                    "agent_id_hash": req.agent_id_hash,
                    "trace_events": sum.trace_events,
                    "trace_llm_calls": sum.trace_llm_calls,
                    "detection_events_tombstoned": sum.detection_events_tombstoned,
                    "erased_at": sum.erased_at.to_rfc3339(),
                    "scope_note": "traces only — payloads in attestation/registration envelopes, \
                                   attestation_evidence, policy_blob or hard_case detail are NOT \
                                   reached by any erasure primitive (CIRISPersist#573)",
                })),
            )
                .into_response()
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("erasure failed: {e}"),
        ),
    }
}

/// `POST /v1/federation/consent` — author THIS node's directed
/// `consent:replication:v1` grant at an ALREADY-ADMITTED peer, carrying an
/// EXPLICIT caller-chosen scope.
///
/// This is the first-class, explicit consent act. **Consent is ALWAYS an
/// owner-authored signed CEG claim — never auto-generated.** A pure server
/// produces no traces, so it never has cause to auto-consent to replicate them;
/// the boot path ([`crate::federation_delivery::prime_canonicals`]) therefore
/// only establishes *reachability* (transport rooting) and authors NO consent.
/// The agent's setup wizard calls this route when the owner opts into sharing
/// (e.g. "Send traces to CIRIS L3C"), carrying the scope the owner chose — no
/// env vars, no config-sniffing, just the CEG consent object authored by the
/// responsible party.
///
/// Unlike [`peering`] it does NOT register a peer key: the peer must already be
/// an admitted `federation_keys` row (the baked canonical is), so the wizard can
/// author consent with nothing but the peer's `key_id` + the chosen prefixes.
/// Owner-gated identically to peering (owner-binding + owner session + `Peer`
/// verb + CC 2.2 conformance). Idempotent (re-consent is a no-op).
async fn consent(
    State(st): State<FederationAdminState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Same owner-authority floor as `peering`: authoring cross-node data-flow
    // consent requires a live responsible party bound to THIS node.
    if crate::auth::gate::require_owner_bound(&st.engine, &st.node_key_id)
        .await
        .is_err()
    {
        return err(
            StatusCode::FORBIDDEN,
            "this node has no responsible party (owner-binding) — consent refused; \
             an unowned node authors no cross-node consent. Claim ownership first via \
             POST /v1/setup/root.",
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
    // A node authors consent only for a role it CLAIMS to perform on the wire
    // (CC 2.2) — same gate peering applies before writing a grant.
    if let Some(resp) =
        crate::conformance::require_op(&st.engine, crate::auth::gate::CapabilityVerb::Peer).await
    {
        return resp;
    }

    let req: ConsentRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };

    // Consent is ALWAYS explicit about its scope — refuse an empty prefix set
    // rather than silently defaulting (the whole point of this route).
    let prefixes = crate::peer::normalize_prefixes(&req.attestation_prefixes);
    if prefixes.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "consent must name an explicit scope: `attestation_prefixes` is empty \
             (e.g. [\"capacity:\"] or [\"trace:\"])",
        );
    }

    // Resolve + validate the owner-chosen recipient cohort here for a clean 400
    // (peer::emit re-validates as a fail-closed producer floor). Omitted ⇒
    // persist's default (`federation`).
    let audience = req
        .audience
        .clone()
        .unwrap_or_else(|| ciris_persist::federation::types::cohort_scope::FEDERATION.to_string());
    if !ciris_persist::federation::types::cohort_scope::is_valid(&audience) {
        return err(
            StatusCode::BAD_REQUEST,
            format!(
                "audience {audience:?} is not one of the closed cohort_scope values \
                 (self/family/community/affiliations/species/biosphere/federation)"
            ),
        );
    }

    // The peer must already be admitted — this route authors consent, it does
    // NOT register keys (that is `peering`). Fail-closed on an unknown peer.
    match st
        .engine
        .federation_directory()
        .lookup_public_key(&req.peer_key_id)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return err(
                StatusCode::BAD_REQUEST,
                format!(
                    "peer_key_id '{}' is not an admitted federation key — register it first \
                     (POST /v1/federation/peering) before consenting to replicate to it",
                    req.peer_key_id
                ),
            )
        }
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    }

    // Author the FULL consent-transfer payload (#510 P2): the owner's chosen
    // audience / expiry / restrictions ride the closed grammar via
    // `emit_replication_consent_with_policy`. Restrictions are already typed
    // through persist's closed `RestrictionOp` (an unknown op 400'd at parse).
    let opts = crate::peer::ConsentGrantOptions {
        author_signer: None,
        audience: req.audience.clone(),
        valid_until: req.valid_until,
        restrictions: req.restrictions.clone(),
        // Route callers do not yet expose these; None ⇒ the resolved default is
        // still WRITTEN into the payload (see peer::ExhaustiveConsent).
        kinds: None,
        direction: None,
        principle: None,
        purpose: None,
    };
    let grant = match crate::peer::emit_replication_consent_with_policy(
        &st.engine,
        &st.node_key_id,
        &req.peer_key_id,
        &req.attestation_prefixes,
        &opts,
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

    // CIRISConstitution#46 (CIRISServer#331 ask 1) — author the `analyze` grant
    // ATOMICALLY with the replication grant when the owner asked for it. One
    // consent action, complete set: "send my traces to X" already means "X may
    // score them", which is the whole reason the traces are being sent.
    //
    // NON-FATAL by design: the replication grant is already durable at this point,
    // and failing the whole request would discard a valid consent the owner just
    // gave. The failure is logged loudly and reported as a null id in the response
    // so the caller can see the set is incomplete rather than assume success.
    let analyze_grant_attestation_id = if req.analyze {
        match crate::peer::emit_analyze_consent(&st.engine, &st.node_key_id, &req.peer_key_id).await
        {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(
                    peer_key_id = %req.peer_key_id,
                    error = %e,
                    "replication consent authored but the CC#46 `analyze` grant FAILED — this \
                     peer can receive traces from us and may NOT score them; capacity scoring \
                     stays dead until it is re-authored"
                );
                None
            }
        }
    } else {
        None
    };

    // Nudge the CEG-driven reconciler (same as peering); the consent object is
    // durable regardless — this only makes convergence prompt.
    if let Some(notify) = st.reconcile_notify.as_ref() {
        notify.notify_one();
    }

    (
        StatusCode::OK,
        Json(ConsentResponse {
            analyze_grant_attestation_id,
            consented: true,
            peer_key_id: req.peer_key_id,
            grant_attestation_id: grant.attestation_id,
            grant_content_hash: grant.content_hash,
            freshly_emitted: grant.freshly_emitted,
            attestation_prefixes: prefixes,
            audience,
            reconciler_note: "consent:replication recorded; the reconcile loop converges the live \
                              replication runtime to it — the peer becomes an active Initiator \
                              target without restart",
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
    let declared = crate::conformance::declared(&st.engine).await;
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
        // The explicit consent act — author a consent:replication grant at an
        // already-admitted peer (the agent wizard calls this on owner opt-in).
        .route("/v1/federation/consent", axum::routing::post(consent))
        .route(
            "/v1/federation/erase-agent-traces",
            axum::routing::post(erase_agent_traces),
        )
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
