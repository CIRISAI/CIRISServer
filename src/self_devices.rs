//! **The owner's own devices** (`FSD/ROSTER_AND_DRIVE_CRUD.md` §2).
//!
//! Two routes the self-device surface lacked:
//!
//! - `POST /v1/self/nodes/{node_key_id}/release` — the owner lets a node go.
//!   Ownership IS a row: the owner-binding `delegates_to(user → node, infra:*)`
//!   the claim wrote. Releasing is therefore the owner's signed `withdraws` of
//!   every live binding they hold on that node, authored with their own fed-ID
//!   pen — never the node's key, because a machine cannot un-own itself on its
//!   owner's behalf. Afterwards persist's `nodes_owned_by(owner)` no longer
//!   lists the node, the self-room drive drops it on its next tick (its roster
//!   is that projection), and the node itself reverts to the unowned
//!   fail-closed floor. Releasing the node you are TALKING TO ends your own
//!   session's authority here, so it needs `force_self: true`.
//! - `POST /v1/self/occurrence/label` — a display name for a device key. The
//!   persist occurrence row has no label member and its admission is
//!   idempotent on `(identity, occurrence)`, so a label cannot be written INTO
//!   it. It is a separate owner-signed row at `cohort_scope: self` (dimension
//!   [`LABEL_DIMENSION`]): the first label is a `scores`, every relabel a
//!   `supersedes` naming the previous head, and the newest wins. Self-scoped, so
//!   it reaches the owner's own devices and nobody else.
//!
//! - `POST /v1/self/nodes/{node_key_id}/announce` — announce ANOTHER of the
//!   owner's devices from the device holding the pen (CIRISServer#678): the
//!   owner re-signs the owner-binding user→that node at `federation`, the same
//!   promote `POST /v1/federation/announce` runs for the node it is served by.
//!
//! Refusals are `{error, reason_id, detail}` with stable ids, like the family
//! surface ([`crate::family_api`]), whose owner gate this shares.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::Deserialize;

use ciris_persist::federation::admission::{is_owner_binding_envelope, nodes_owned_by, owner_of};
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::types::{attestation_type, cohort_scope, Attestation};
use ciris_persist::prelude::Engine;

use crate::family_api::{owner_caller, GateRefusal, OwnerCaller};
use crate::owner_signer_capsule::{self, OwnerSignerCapsule};

/// The dimension a device label is written under.
pub const LABEL_DIMENSION: &str = "self:device_label:v1";

const MAX_LABEL_CHARS: usize = 64;

#[derive(Clone)]
struct SelfState {
    engine: Arc<Engine>,
    user_seed_dir: std::path::PathBuf,
}

// ─── Refusals ───────────────────────────────────────────────────────────────

fn refuse(code: StatusCode, id: &'static str, text: &'static str) -> Response {
    (
        code,
        Json(serde_json::json!({ "error": text, "reason_id": id, "detail": text })),
    )
        .into_response()
}

fn refuse_with(code: StatusCode, id: &'static str, text: &'static str, detail: String) -> Response {
    (
        code,
        Json(serde_json::json!({ "error": text, "reason_id": id, "detail": detail })),
    )
        .into_response()
}

fn session_required(code: StatusCode) -> Response {
    refuse(
        code,
        "self.owner_session_required",
        "your devices are the node owner's own surface — sign in as the owner of this claimed node",
    )
}

fn delegate_may_not_author() -> Response {
    refuse(
        StatusCode::FORBIDDEN,
        "self.delegate_may_not_author",
        "a delegated session may not change the owner's devices — the change is signed with the \
         owner's own key, and that signature would outlive the delegation",
    )
}

fn store_unavailable(detail: String) -> Response {
    refuse_with(
        StatusCode::SERVICE_UNAVAILABLE,
        "self.store_unavailable",
        "the identity store could not be read or written",
        detail,
    )
}

fn signer_unavailable(detail: String) -> Response {
    refuse_with(
        StatusCode::FORBIDDEN,
        "self.author_signer_unavailable",
        "your federation identity could not be opened to sign this change",
        detail,
    )
}

fn bad_request(detail: String) -> Response {
    refuse_with(
        StatusCode::BAD_REQUEST,
        "self.bad_request",
        "the request body is not a valid device request",
        detail,
    )
}

#[allow(clippy::result_large_err)]
fn gate(r: Result<OwnerCaller, GateRefusal>) -> Result<OwnerCaller, Response> {
    r.map_err(|e| match e {
        GateRefusal::NoSession => session_required(StatusCode::UNAUTHORIZED),
        GateRefusal::NotOwner | GateRefusal::Unowned => session_required(StatusCode::FORBIDDEN),
        GateRefusal::Delegated => delegate_may_not_author(),
        GateRefusal::Store(d) => store_unavailable(d),
    })
}

async fn pen(st: &SelfState, caller: &OwnerCaller) -> Result<OwnerSignerCapsule, Response> {
    owner_signer_capsule::acquire(
        &st.engine,
        Some(&caller.bearer),
        &caller.owner_key_id,
        st.user_seed_dir.clone(),
    )
    .await
    .map_err(|e| match e {
        owner_signer_capsule::CapsuleRefusal::Delegated => delegate_may_not_author(),
        other => signer_unavailable(other.to_string()),
    })
}

/// Stamp `spec` as the capsule's owner, sign it with the owner's pen, store it
/// through the authored door. The ONE way this module writes a row
/// (`crate::attest` is the recipe; the capsule never releases its signer, so
/// the two stages are driven here with the capsule's `sign_hybrid`).
async fn emit_as_owner(
    engine: &Engine,
    capsule: &OwnerSignerCapsule,
    spec: crate::attest::Spec,
) -> Result<String, String> {
    let stamped = crate::attest::Emit::stamp(capsule.key_id(), spec).map_err(|e| format!("{e}"))?;
    let sig = capsule.sign_hybrid(stamped.canonical()).await?;
    let row = stamped
        .assemble_from_b64(
            &B64.encode(&sig.classical_signature),
            &B64.encode(&sig.pqc_signature),
        )
        .map_err(|e| format!("{e}"))?;
    crate::attest::put(engine, row)
        .await
        .map_err(|e| format!("{e}"))
}

// ─── POST /v1/self/nodes/{node_key_id}/release ──────────────────────────────

#[derive(Debug, Default, Deserialize)]
struct ReleaseRequest {
    /// Required to release the node this request is being served BY: doing so
    /// ends the owner's authority here, including this session's.
    #[serde(default)]
    force_self: bool,
}

/// The live owner-binding rows `owner` holds on `node` — the rows a release
/// withdraws. A binding already withdrawn by `owner` is skipped: it confers
/// nothing, and a second `withdraws` of it is noise.
async fn live_bindings(
    engine: &Engine,
    owner: &str,
    node: &str,
) -> Result<Vec<Attestation>, String> {
    let dir = engine.federation_directory();
    let inbound = dir
        .list_attestations_for(node)
        .await
        .map_err(|e| format!("list_attestations_for({node}): {e:#}"))?;
    let withdrawn: std::collections::HashSet<String> = dir
        .list_attestations_by(owner)
        .await
        .map_err(|e| format!("list_attestations_by({owner}): {e:#}"))?
        .into_iter()
        .filter(|a| a.attestation_type == attestation_type::WITHDRAWS)
        .filter_map(|a| {
            a.attestation_envelope
                .get(paths::REFERENCES_ATTESTATION_ID)
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .collect();
    Ok(inbound
        .into_iter()
        .filter(|a| {
            a.attestation_type == attestation_type::DELEGATES_TO
                && a.attesting_key_id == owner
                && is_owner_binding_envelope(&a.attestation_envelope)
                && !withdrawn.contains(&a.attestation_id)
        })
        .collect())
}

async fn release_node(
    State(st): State<SelfState>,
    headers: HeaderMap,
    Path(node_key_id): Path<String>,
    body: Bytes,
) -> Response {
    let caller = match gate(owner_caller(&st.engine, &headers, false).await) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let req: ReleaseRequest = if body.is_empty() {
        ReleaseRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => return bad_request(e.to_string()),
        }
    };
    let dir = st.engine.federation_directory();
    // THE CALLER MUST OWN IT — by persist's single-owner projection, the same
    // walk every peer makes. Anything else (another person's node, an unowned
    // node, a key this node has never heard of) is not the caller's to release,
    // and is refused under ONE id so the route does not become an oracle for
    // who owns what.
    match owner_of(dir.as_ref(), &node_key_id).await {
        Ok(Some(o)) if o == caller.owner_key_id => {}
        Ok(_) | Err(ciris_persist::federation::Error::AmbiguousNodeOwner { .. }) => {
            return refuse_with(
                StatusCode::FORBIDDEN,
                "self.not_your_node",
                "that node is not one you own, so it is not yours to release",
                node_key_id,
            )
        }
        Err(e) => return store_unavailable(format!("owner_of: {e:#}")),
    }
    let this_actor = st.engine.local_derived_key_id().await.ok();
    let is_this_node =
        node_key_id == caller.node_key_id || this_actor.as_deref() == Some(node_key_id.as_str());
    if is_this_node && !req.force_self {
        return refuse(
            StatusCode::CONFLICT,
            "self.release_self_requires_force",
            "that is the node you are talking to — releasing it ends your ownership here, \
             including this session. Send force_self: true to do it anyway",
        );
    }
    let bindings = match live_bindings(&st.engine, &caller.owner_key_id, &node_key_id).await {
        Ok(b) => b,
        Err(e) => return store_unavailable(e),
    };
    let capsule = match pen(&st, &caller).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut withdrawn = Vec::with_capacity(bindings.len());
    for b in &bindings {
        // At the BINDING's own audience: a federation-scoped binding is
        // withdrawn where peers can see the withdrawal, a self-scoped one where
        // the owner's devices can.
        let spec = crate::attest::Spec::new(
            attestation_type::WITHDRAWS,
            b.cohort_scope.clone(),
            ciris_persist::federation::withdraws_attestation_envelope(
                &b.attestation_id,
                attestation_type::DELEGATES_TO,
            ),
        )
        .about(&node_key_id);
        match emit_as_owner(&st.engine, &capsule, spec).await {
            Ok(id) => withdrawn.push(serde_json::json!({
                "binding": b.attestation_id,
                "withdraws": id,
                "cohort_scope": b.cohort_scope,
            })),
            Err(e) => {
                return store_unavailable(format!(
                    "withdraws(owner-binding {}): {e}",
                    b.attestation_id
                ))
            }
        }
    }
    // THE WITNESS, read back rather than assumed: the projection every other
    // surface (the switcher, the self room's roster) reads must no longer list it.
    let still = match nodes_owned_by(dir.as_ref(), &caller.owner_key_id).await {
        Ok(v) => v,
        Err(e) => return store_unavailable(format!("nodes_owned_by: {e:#}")),
    };
    if still.iter().any(|n| n == &node_key_id) {
        return refuse_with(
            StatusCode::INTERNAL_SERVER_ERROR,
            "self.release_incomplete",
            "the release was signed but the node is still listed as yours — a binding this node \
             cannot see is still live",
            format!(
                "withdrew {} binding(s); nodes_owned_by still lists it",
                withdrawn.len()
            ),
        );
    }
    tracing::info!(
        owner = %caller.owner_key_id, node = %node_key_id, bindings = withdrawn.len(),
        released_self = is_this_node,
        "self: node RELEASED — the owner withdrew every owner-binding on it"
    );
    let _ = crate::compose::kick_replication("self:release_node");
    Json(serde_json::json!({
        "node_key_id": node_key_id,
        "released": true,
        "released_self": is_this_node,
        "withdrawn": withdrawn,
        "nodes_owned_by": still,
    }))
    .into_response()
}

// ─── POST /v1/self/nodes/{node_key_id}/announce ─────────────────────────────

/// **Announce ANOTHER of my devices, from the device holding my pen**
/// (CIRISServer#678, item 3).
///
/// Announcing is per node (the #655 ruling): the owner chooses, device by
/// device, which of their nodes people can reach them through, and the choice
/// is the owner re-signing the owner-binding user→THAT node at `federation`.
/// `POST /v1/federation/announce` makes that choice for the node it is served
/// by, and needs the owner's pen there. A second device claimed through
/// `claim-remote` never holds the pen — it stays on the device that approved
/// the claim — so it could not be announced at all. This route is the same act
/// made from the device that CAN sign it, for a node of the caller's choosing
/// ([`crate::auth::ownership::promote_owner_binding_to_federation`], unchanged).
///
/// What it does not do: flip the target's `net.announce_ownership` (its
/// Reticulum identity announce). That is a config row on the target, written
/// by the target's own owner session; the owner-binding is what peers walk to
/// place the node in an audience, and it crosses on the next round.
async fn announce_node(
    State(st): State<SelfState>,
    headers: HeaderMap,
    Path(node_key_id): Path<String>,
) -> Response {
    let caller = match gate(owner_caller(&st.engine, &headers, false).await) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let dir = st.engine.federation_directory();
    // THE CALLER MUST OWN IT, by the same single-owner walk `release` uses, and
    // under ONE id for every way it is not theirs (another person's node, an
    // unowned node, a key never heard of) so the route is not an oracle.
    match owner_of(dir.as_ref(), &node_key_id).await {
        Ok(Some(o)) if o == caller.owner_key_id => {}
        Ok(_) | Err(ciris_persist::federation::Error::AmbiguousNodeOwner { .. }) => {
            return refuse_with(
                StatusCode::FORBIDDEN,
                "self.announce_not_your_node",
                "that node is not one you own, so it is not yours to announce",
                node_key_id,
            )
        }
        Err(e) => return store_unavailable(format!("owner_of: {e:#}")),
    }
    let capsule = match pen(&st, &caller).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let promoted = match crate::auth::ownership::promote_owner_binding_to_federation(
        &st.engine,
        capsule.local_signer(),
        &node_key_id,
    )
    .await
    {
        Ok(p) => p,
        Err(crate::auth::ownership::OwnershipError::Validation(d)) => {
            return refuse_with(
                StatusCode::CONFLICT,
                "self.announce_refused",
                "the ownership of that node could not be announced from this device",
                d,
            )
        }
        Err(e) => return store_unavailable(format!("promote owner-binding: {e}")),
    };
    let this_actor = st.engine.local_derived_key_id().await.ok();
    let is_this_node =
        node_key_id == caller.node_key_id || this_actor.as_deref() == Some(node_key_id.as_str());
    tracing::info!(
        owner = %promoted.responsible_user_key_id,
        node = %node_key_id,
        promoted_attestation_id = ?promoted.attestation_id,
        this_node = is_this_node,
        "self: device ANNOUNCED — the owner re-signed the owner-binding for that node at \
         federation scope from this device (per-node announce, #655; CIRISServer#678)"
    );
    // The widened binding is OWNER-attested; the kick admits the owner to the
    // publish-own set before it rounds, so the row rides this round.
    let _ = crate::compose::kick_replication("self: another device announced");
    Json(serde_json::json!({
        "node_key_id": node_key_id,
        "owner": promoted.responsible_user_key_id,
        // None ⇒ that node's binding was already federation-scoped.
        "promoted_owner_binding_attestation_id": promoted.attestation_id,
        "already_announced": promoted.attestation_id.is_none(),
        "this_node": is_this_node,
    }))
    .into_response()
}

// ─── POST /v1/self/occurrence/label ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct LabelRequest {
    occurrence_key_id: String,
    label: String,
}

/// The label rows `owner` authored, newest head per occurrence.
async fn label_heads(engine: &Engine, owner: &str) -> Result<HashMap<String, Attestation>, String> {
    let rows = engine
        .federation_directory()
        .list_attestations_by(owner)
        .await
        .map_err(|e| format!("list_attestations_by({owner}): {e:#}"))?;
    let mut heads: HashMap<String, Attestation> = HashMap::new();
    for a in rows {
        let is_label = (a.attestation_type == attestation_type::SCORES
            || a.attestation_type == attestation_type::SUPERSEDES)
            && a.attestation_envelope
                .get(paths::DIMENSION)
                .and_then(|v| v.as_str())
                == Some(LABEL_DIMENSION);
        if !is_label {
            continue;
        }
        let newer = heads.get(&a.attested_key_id).is_none_or(|h| {
            (a.asserted_at, &a.attestation_id) > (h.asserted_at, &h.attestation_id)
        });
        if newer {
            heads.insert(a.attested_key_id.clone(), a);
        }
    }
    Ok(heads)
}

/// `occurrence_key_id → label` for `owner`'s devices. Read by the occurrence
/// list when the caller is that owner.
pub(crate) async fn labels_for(engine: &Engine, owner: &str) -> HashMap<String, String> {
    label_heads(engine, owner)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(k, a)| {
            a.attestation_envelope
                .get("label")
                .and_then(|v| v.as_str())
                .map(|l| (k, l.to_owned()))
        })
        .collect()
}

async fn label_occurrence(
    State(st): State<SelfState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = match gate(owner_caller(&st.engine, &headers, false).await) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let req: LabelRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return bad_request(e.to_string()),
    };
    let label = req.label.trim();
    if label.is_empty() || label.chars().count() > MAX_LABEL_CHARS {
        return refuse(
            StatusCode::BAD_REQUEST,
            "self.label_empty",
            "a device label must be between 1 and 64 characters",
        );
    }
    // The device must be one of the CALLER's occurrences (active or not — a
    // revoked phone may still deserve a name in the history).
    let dir = st.engine.federation_directory();
    let mine = match dir
        .list_identity_occurrences_for(&caller.owner_key_id)
        .await
    {
        Ok(v) => v
            .iter()
            .any(|o| o.occurrence_key_id == req.occurrence_key_id),
        Err(e) => return store_unavailable(format!("list_identity_occurrences_for: {e:#}")),
    };
    if !mine {
        return refuse_with(
            StatusCode::NOT_FOUND,
            "self.not_your_device",
            "that key is not one of your devices",
            req.occurrence_key_id,
        );
    }
    let head = match label_heads(&st.engine, &caller.owner_key_id).await {
        Ok(h) => h
            .get(&req.occurrence_key_id)
            .map(|a| a.attestation_id.clone()),
        Err(e) => return store_unavailable(e),
    };
    let capsule = match pen(&st, &caller).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut envelope = serde_json::json!({
        (paths::DIMENSION): LABEL_DIMENSION,
        "score": 1.0,
        "witness_relation": "self",
        "occurrence_key_id": req.occurrence_key_id,
        "label": label,
    });
    let kind = if let Some(prior) = &head {
        envelope[paths::REFERENCES_ATTESTATION_ID] = serde_json::Value::String(prior.clone());
        attestation_type::SUPERSEDES
    } else {
        attestation_type::SCORES
    };
    let spec = crate::attest::Spec::new(kind, cohort_scope::SELF, envelope)
        .attested_to(&req.occurrence_key_id)
        .weighing(Some(1.0));
    let id = match emit_as_owner(&st.engine, &capsule, spec).await {
        Ok(id) => id,
        Err(e) => return store_unavailable(format!("emit label: {e}")),
    };
    let _ = crate::compose::kick_replication("self:label");
    Json(serde_json::json!({
        "occurrence_key_id": req.occurrence_key_id,
        "label": label,
        "attestation_id": id,
        "supersedes": head,
    }))
    .into_response()
}

// ─── Router ─────────────────────────────────────────────────────────────────

/// The self-device routes. `user_seed_dir` is where the owner's fed-ID is
/// re-opened to sign — the same directory the drive and family routers take.
pub fn router(engine: Arc<Engine>, user_seed_dir: std::path::PathBuf) -> Router {
    Router::new()
        .route(
            "/v1/self/nodes/{node_key_id}/release",
            axum::routing::post(release_node),
        )
        .route(
            "/v1/self/nodes/{node_key_id}/announce",
            axum::routing::post(announce_node),
        )
        .route(
            "/v1/self/occurrence/label",
            axum::routing::post(label_occurrence),
        )
        .with_state(SelfState {
            engine,
            user_seed_dir,
        })
}
