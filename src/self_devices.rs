//! **The owner's own devices** (`FSD/ROSTER_AND_DRIVE_CRUD.md` §2).
//!
//! Three routes the self-device surface lacked:
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
//!   Since 0.5.218 a release also revokes the node's content-KEM occurrence of
//!   the owner (signed, replicating) — without it the released machine kept
//!   being wrapped every new self file ([`evict_device`]).
//! - `POST /v1/self/occurrence/label` — a display name for a device key. The
//!   persist occurrence row has no label member and its admission is
//!   idempotent on `(identity, occurrence)`, so a label cannot be written INTO
//!   it. It is a separate owner-signed row at `cohort_scope: self` (dimension
//!   [`LABEL_DIMENSION`]): the first label is a `scores`, every relabel a
//!   `supersedes` naming the previous head, and the newest wins. Self-scoped, so
//!   it reaches the owner's own devices and nobody else.
//! - `GET /v1/self/contact-code` (CIRISServer#673) — the person's shareable
//!   contact code: a v3 fedcode naming them and, by their choice (`?nodes=`),
//!   any of their ANNOUNCED nodes with each node's transport key. The string
//!   (and its QR form) another person pastes into `POST /v1/contacts`.
//!
//! - `POST /v1/self/occurrence/revoke` (0.5.218, CSD-037) — revoke a device
//!   occurrence. Moved here from [`crate::auth::occurrence`], and it and
//!   `release` are now ONE act, [`evict_device`]: withdraw the owner-binding(s)
//!   the device is a node under, write a SIGNED occurrence revocation (the
//!   replicating door, signed by the owner's pen), kick replication, and read
//!   both halves back from persist. **Eviction withholds new content only**:
//!   already-shared history stays readable by the evicted device — no DEK is
//!   rotated and nothing is re-encrypted ([`EVICTION_HISTORY_NOTE`]).
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

/// The dimension a device label is written under (CC 3.1.1, registered in rc6;
/// the maintainer's ruling on CIRISConstitution#137 / CIRISServer#717).
pub const LABEL_DIMENSION: &str = "device:label:v1";

/// The name labels were written under through 0.5.219. `self` is a cohort
/// scope, not a family, and the rc6 registry refuses the stem — so nothing
/// writes it now. It is READ: a label is a self-scope row that lives only on
/// its owner's devices, and those rows are still there. A relabel supersedes
/// an old-name head with a new-name row, so the old name drains as people
/// rename; a label nobody touches stays readable.
///
/// Spelled with `concat!` so the registered-dimension gate, which checks every
/// dimension literal this server EMITS, does not read it as one.
pub const LEGACY_LABEL_DIMENSION: &str = concat!("self:", "device_label:v1");

/// Is `dimension` a device label, under either name?
fn is_label_dimension(dimension: &str) -> bool {
    dimension == LABEL_DIMENSION || dimension == LEGACY_LABEL_DIMENSION
}

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
        "Your devices are the owner's own surface. Sign in as the owner of this node.",
    )
}

fn delegate_may_not_author() -> Response {
    refuse(
        StatusCode::FORBIDDEN,
        "self.delegate_may_not_author",
        "A delegated session cannot change your devices. The change is signed with your own key, so sign in as yourself.",
    )
}

fn store_unavailable(detail: String) -> Response {
    refuse_with(
        StatusCode::SERVICE_UNAVAILABLE,
        "self.store_unavailable",
        "The node could not read or write its identity store. Nothing was changed.",
        detail,
    )
}

fn signer_unavailable(detail: String) -> Response {
    refuse_with(
        StatusCode::FORBIDDEN,
        "self.author_signer_unavailable",
        "Your identity could not be opened to sign this change.",
        detail,
    )
}

fn bad_request(detail: String) -> Response {
    refuse_with(
        StatusCode::BAD_REQUEST,
        "self.bad_request",
        "The node could not read that device request.",
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
pub(crate) async fn emit_as_owner(
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

// ─── EVICT A DEVICE — the one act both routes converge on ───────────────────

/// What eviction does NOT do, said in every answer and never softened
/// (CSD-037, CC 3.3.6.1). An eviction stops the device receiving anything NEW:
/// the next self file is wrapped to the owner's ACTIVE occurrences only, and the
/// self room removes the node at its next epoch. It does not reach back. Every
/// DEK the device was already granted stays granted — there is no DEK rotation
/// and no re-encryption of history — so whatever it could already read, it can
/// still read, on the device and in any copy taken from it.
pub const EVICTION_HISTORY_NOTE: &str = "Already-shared history stays readable by the evicted \
     device: nothing already granted to it is rotated or re-encrypted. Only new content and new \
     self-room epochs are withheld from it.";

/// One part of an eviction that did not complete, by name.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EvictFailure {
    /// `owner_binding_withdrawal` | `owner_binding_witness` |
    /// `occurrence_revocation` | `occurrence_witness`.
    pub part: &'static str,
    /// The binding, node or occurrence the part was about.
    pub target: String,
    /// The store's / signer's own words (`{:#}` — the whole chain).
    pub error: String,
}

/// **What an eviction did, part by part** — the answer both
/// `POST /v1/self/nodes/{node}/release` and `POST /v1/self/occurrence/revoke`
/// return, because they are now the same act.
#[derive(Debug, Default, serde::Serialize)]
pub struct EvictionReport {
    /// The owner's nodes whose owner-bindings this eviction withdrew.
    pub nodes: Vec<String>,
    /// One entry per withdrawn owner-binding:
    /// `{node_key_id, binding, withdraws, cohort_scope}`.
    pub withdrawn: Vec<serde_json::Value>,
    /// One entry per SIGNED occurrence revocation written:
    /// `{occurrence_key_id, attesting_key_id, effective_at}`.
    pub occurrences_revoked: Vec<serde_json::Value>,
    /// Occurrences of the owner the eviction named that were already out of the
    /// active roster — nothing to sign for them.
    pub occurrences_already_revoked: Vec<String>,
    /// Every part that did not complete, by name. Empty on a full eviction.
    pub failed: Vec<EvictFailure>,
    /// `true` when a replication round was kicked NOW; `false` when this
    /// process runs no replication runtime (a bare harness engine), in which
    /// case the rows ride the next cadence round of whatever runtime serves
    /// this store.
    pub replication_kicked: bool,
    /// The owner's nodes as persist's projection lists them AFTER the act.
    pub nodes_owned_by: Vec<String>,
    /// [`EVICTION_HISTORY_NOTE`], verbatim, in every answer.
    pub history: &'static str,
}

impl EvictionReport {
    fn fail(&mut self, part: &'static str, target: &str, error: String) {
        self.failed.push(EvictFailure {
            part,
            target: target.to_owned(),
            error,
        });
    }
}

/// Build and sign ONE occurrence revocation as the owner, for persist's SIGNED
/// door (`put_identity_occurrence_revocation`, CIRISPersist#421).
///
/// The envelope carries exactly the members the gate reads back
/// (`identity_key_id`, `occurrence_key_id`, `revoked_at`, `effective_at`) plus
/// the witness set and reason, so what is signed is what is stored. It is
/// canonicalized with persist's OWN canonicalizer — the bytes its gate
/// re-canonicalizes — and signed with the owner's pen, which is the identity
/// the occurrence belongs to: `signer_acts_for(owner, owner)` holds by
/// construction, and no other key has the mandate (a node key signing its
/// owner's revocation is the infrastructure-authors-the-human's-act class,
/// CC 3.3.6).
///
/// The instant is NOT truncated. The fold revokes only when
/// `effective_at >= occurrence.asserted_at`, occurrences are asserted at
/// nanosecond precision, and RFC-3339 with nanoseconds round-trips exactly
/// through the gate's `ts_field` comparison, so a millisecond cut would only
/// open a window in which the revocation revokes nothing.
async fn signed_occurrence_revocation(
    capsule: &OwnerSignerCapsule,
    owner: &str,
    occurrence: &str,
    reason: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<ciris_persist::federation::SignedIdentityOccurrenceRevocation, String> {
    let at = now.to_rfc3339();
    let mut envelope = serde_json::json!({
        "identity_key_id": owner,
        "occurrence_key_id": occurrence,
        "revoked_at": at,
        "effective_at": at,
        "witness_set": [capsule.key_id()],
    });
    if let Some(r) = reason {
        envelope["reason"] = serde_json::Value::String(r.to_owned());
    }
    let bytes = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .map_err(|e| format!("canonicalize the revocation envelope: {e:#}"))?;
    let sig = capsule.sign_hybrid(&bytes).await?;
    Ok(
        ciris_persist::federation::SignedIdentityOccurrenceRevocation {
            identity_occurrence_revocation:
                ciris_persist::federation::types::IdentityOccurrenceRevocation {
                    identity_key_id: owner.to_owned(),
                    occurrence_key_id: occurrence.to_owned(),
                    revoked_at: now,
                    effective_at: now,
                    reason: reason.map(str::to_owned),
                    witness_set: vec![capsule.key_id().to_owned()],
                    persist_row_hash: String::new(),
                },
            attesting_key_id: capsule.key_id().to_owned(),
            signed_envelope: envelope,
            signature: ciris_verify_core::transport_binding::TransportBindingSignature {
                ed25519_signature_base64: B64.encode(&sig.classical_signature),
                mldsa65_signature_base64: Some(B64.encode(&sig.pqc_signature)),
            },
        },
    )
}

/// **Evict a device from its owner's self — ONE act** (CSD-037, the
/// stolen-device path; 0.5.218).
///
/// # Why one act
///
/// Until 0.5.218 there were two unconnected routes and neither finished the
/// job. `release` withdrew the owner-binding, so the self room dropped the node
/// on its next tick (edge `self_room::decide` reads `nodes_owned_by`) — but it
/// left the node's content-KEM identity OCCURRENCE live, and persist wraps every
/// new self file to `list_identity_occurrences_active(owner)`
/// (`at_rest_cascade::resolve_recipients`), so the "released" machine kept being
/// handed the key to every new file. `occurrence/revoke` wrote the revocation
/// through the trusted-LOCAL door (`put_identity_occurrence_revocation_local`):
/// unsigned, and EXCLUDED from replication by construction, so every other
/// device of the owner went on wrapping to the stolen one; and it never touched
/// the owner-binding, so the room kept it too. Each half looked done from the
/// device that ran it.
///
/// # What it does
///
/// 1. **Withdraw** every live owner-binding the owner holds on each of `nodes`
///    — the owner's signed `withdraws`, at the binding's own audience (a
///    federation binding is withdrawn where peers see it, a self one where the
///    owner's devices do).
/// 2. **Revoke** each of `occurrences` that is still active, through persist's
///    SIGNED door, signed by the owner's pen
///    ([`signed_occurrence_revocation`]). A signed revocation is what the
///    `IdentityOccurrenceRevocation` replication plane carries (`compose.rs`,
///    CIRISServer#646); an unsigned one never leaves this store.
/// 3. **Kick** replication so both ride this round, not the next cadence.
/// 4. **Witness** each half from persist's own projections rather than from our
///    writes: `nodes_owned_by(owner)` must no longer list the nodes, and
///    `list_identity_occurrences_active(owner)` must no longer list the
///    occurrences.
///
/// Every part is attempted even when an earlier one failed — a half-eviction
/// that stops at the first error leaves the stolen device with the other half —
/// and every failure is reported by part and target, never folded into an
/// `Ok`.
///
/// # What it does not do
///
/// [`EVICTION_HISTORY_NOTE`]: no DEK is rotated and nothing already shared is
/// re-encrypted. Content the device was granted before the eviction stays
/// readable to it. Only NEW content (new self files are wrapped to active
/// occurrences only) and NEW self-room epochs are withheld.
pub(crate) async fn evict_device(
    engine: &Engine,
    capsule: &OwnerSignerCapsule,
    owner: &str,
    nodes: &[String],
    occurrences: &[String],
    reason: Option<&str>,
) -> EvictionReport {
    let dir = engine.federation_directory();
    let mut report = EvictionReport {
        nodes: nodes.to_vec(),
        history: EVICTION_HISTORY_NOTE,
        ..EvictionReport::default()
    };

    // (1) The owner-bindings.
    for node in nodes {
        let bindings = match live_bindings(engine, owner, node).await {
            Ok(b) => b,
            Err(e) => {
                report.fail("owner_binding_withdrawal", node, e);
                continue;
            }
        };
        for b in &bindings {
            // At the BINDING's own audience: a federation-scoped binding is
            // withdrawn where peers can see the withdrawal, a self-scoped one
            // where the owner's devices can.
            let spec = crate::attest::Spec::new(
                attestation_type::WITHDRAWS,
                b.cohort_scope.clone(),
                ciris_persist::federation::withdraws_attestation_envelope(
                    &b.attestation_id,
                    attestation_type::DELEGATES_TO,
                ),
            )
            .about(node);
            match emit_as_owner(engine, capsule, spec).await {
                Ok(id) => report.withdrawn.push(serde_json::json!({
                    "node_key_id": node,
                    "binding": b.attestation_id,
                    "withdraws": id,
                    "cohort_scope": b.cohort_scope,
                })),
                Err(e) => report.fail("owner_binding_withdrawal", &b.attestation_id, e),
            }
        }
    }

    // (2) The occurrences — signed, so they replicate.
    let active: Option<std::collections::HashSet<String>> =
        match dir.list_identity_occurrences_active(owner).await {
            Ok(v) => Some(v.into_iter().map(|o| o.occurrence_key_id).collect()),
            Err(e) => {
                for occ in occurrences {
                    report.fail(
                        "occurrence_revocation",
                        occ,
                        format!("list_identity_occurrences_active({owner}): {e:#}"),
                    );
                }
                None
            }
        };
    if let Some(active) = &active {
        for occ in occurrences {
            if !active.contains(occ) {
                report.occurrences_already_revoked.push(occ.clone());
                continue;
            }
            let now = chrono::Utc::now();
            let signed = match signed_occurrence_revocation(capsule, owner, occ, reason, now).await
            {
                Ok(s) => s,
                Err(e) => {
                    report.fail("occurrence_revocation", occ, e);
                    continue;
                }
            };
            match dir.put_identity_occurrence_revocation(signed).await {
                Ok(()) => report.occurrences_revoked.push(serde_json::json!({
                    "occurrence_key_id": occ,
                    "attesting_key_id": capsule.key_id(),
                    "effective_at": now.to_rfc3339(),
                })),
                Err(e) => report.fail(
                    "occurrence_revocation",
                    occ,
                    format!("put_identity_occurrence_revocation: {e:#}"),
                ),
            }
        }
    }

    // (3) Make both halves cross now.
    report.replication_kicked = crate::compose::kick_replication("self:evict_device");

    // (4) The witnesses, read back rather than assumed.
    match nodes_owned_by(dir.as_ref(), owner).await {
        Ok(still) => {
            for node in nodes {
                if still.iter().any(|n| n == node) {
                    report.fail(
                        "owner_binding_witness",
                        node,
                        "nodes_owned_by still lists it: an owner-binding this node cannot see is \
                         still live"
                            .to_owned(),
                    );
                }
            }
            report.nodes_owned_by = still;
        }
        Err(e) => report.fail(
            "owner_binding_witness",
            owner,
            format!("nodes_owned_by: {e:#}"),
        ),
    }
    if !occurrences.is_empty() {
        match dir.list_identity_occurrences_active(owner).await {
            Ok(v) => {
                for occ in occurrences {
                    if v.iter().any(|o| &o.occurrence_key_id == occ) {
                        report.fail(
                            "occurrence_witness",
                            occ,
                            "list_identity_occurrences_active still lists it".to_owned(),
                        );
                    }
                }
            }
            Err(e) => report.fail(
                "occurrence_witness",
                owner,
                format!("list_identity_occurrences_active: {e:#}"),
            ),
        }
    }
    tracing::info!(
        owner = %owner,
        nodes = ?nodes,
        occurrences = ?occurrences,
        withdrawn = report.withdrawn.len(),
        revoked = report.occurrences_revoked.len(),
        failed = report.failed.len(),
        replication_kicked = report.replication_kicked,
        "self: device EVICTED — owner-binding(s) withdrawn and occurrence(s) revoked as ONE \
         signed act; already-shared history stays readable to the device (no DEK rotation)"
    );
    report
}

/// The answer an eviction route gives: 200 with the report when every part
/// completed, else a refusal naming what did not — carrying the same report,
/// so the caller sees what DID complete (it stays done).
fn eviction_response(report: &EvictionReport, extra: serde_json::Value) -> Response {
    let mut body = serde_json::to_value(report).unwrap_or_else(|_| serde_json::json!({}));
    if let (Some(b), Some(x)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in x {
            b.insert(k.clone(), v.clone());
        }
    }
    if report.failed.is_empty() {
        return Json(body).into_response();
    }
    // A binding persist still sees as live, and nothing else wrong, is the
    // release's own long-standing refusal; any other incomplete part is named
    // under the eviction's.
    let only_binding_witness = report
        .failed
        .iter()
        .all(|f| f.part == "owner_binding_witness");
    let (id, text): (&'static str, &'static str) = if only_binding_witness {
        (
            "self.release_incomplete",
            "The release was signed, but the node still lists that node as yours: an ownership record it cannot see is still live. What it could withdraw stays withdrawn.",
        )
    } else {
        (
            "self.evict_incomplete",
            "Part of removing that device did not complete. What was done stays done; the answer names what was not.",
        )
    };
    let detail = report
        .failed
        .iter()
        .map(|f| format!("{} {}: {}", f.part, f.target, f.error))
        .collect::<Vec<_>>()
        .join("; ");
    if let Some(b) = body.as_object_mut() {
        b.insert("error".into(), text.into());
        b.insert("reason_id".into(), id.into());
        b.insert("detail".into(), detail.into());
    }
    (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
}

/// Every key the node `node` may hold its owner's content occurrence under.
/// For another machine that is its node key: since the split fix a claim
/// provisions the content occurrence under the wire key
/// (`ensure_content_occurrence` takes it explicitly), and a pre-split install
/// has one key. For THIS node it is every key this node is — a split install
/// that predates that fix still holds its occurrence under the ACTOR key
/// (`actor-vs-node-key-on-a-split-install`; [`crate::peer::own_keys_of_this_node`]).
///
/// What this cannot see: another machine's ACTOR key when that machine is a
/// pre-fix split install. Nothing in the directory links a remote node key to
/// its actor key, so that occurrence is not found from here; revoking it by
/// its own key (`POST /v1/self/occurrence/revoke`) reaches it.
async fn occurrence_keys_of_node(engine: &Engine, node: &str, is_this_node: bool) -> Vec<String> {
    let mut keys = vec![node.to_owned()];
    if is_this_node {
        if let Ok(engine_key) = engine.local_derived_key_id().await {
            for k in crate::peer::own_keys_of_this_node(&engine_key) {
                if !keys.contains(&k) {
                    keys.push(k);
                }
            }
        }
    }
    keys
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

/// **Release a node — an eviction** (0.5.218). The owner's signed `withdraws`
/// of every owner-binding on the node AND the signed revocation of the node's
/// content-KEM occurrence of the owner, through [`evict_device`]. Before
/// 0.5.218 a release withdrew the binding only, and the released machine kept
/// being wrapped every new self file.
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
                "That node is not one you own, so it is not yours to release.",
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
            "That is the node you are talking to. Releasing it ends your ownership here, including this session.",
        );
    }
    // The node's content occurrence(s) of the owner: the keys it may hold one
    // under, filtered to those that ARE occurrences of the owner — a node that
    // never provisioned one has nothing to revoke, which is not a failure.
    let occurrences = match dir
        .list_identity_occurrences_for(&caller.owner_key_id)
        .await
    {
        Ok(all) => {
            let keys = occurrence_keys_of_node(&st.engine, &node_key_id, is_this_node).await;
            let mut occ: Vec<String> = all
                .into_iter()
                .map(|o| o.occurrence_key_id)
                .filter(|k| keys.contains(k))
                .collect();
            occ.sort();
            occ.dedup();
            occ
        }
        Err(e) => return store_unavailable(format!("list_identity_occurrences_for: {e:#}")),
    };
    let capsule = match pen(&st, &caller).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let report = evict_device(
        &st.engine,
        &capsule,
        &caller.owner_key_id,
        std::slice::from_ref(&node_key_id),
        &occurrences,
        Some("released by its owner"),
    )
    .await;
    tracing::info!(
        owner = %caller.owner_key_id, node = %node_key_id,
        bindings = report.withdrawn.len(), occurrences = report.occurrences_revoked.len(),
        failed = report.failed.len(), released_self = is_this_node,
        "self: node RELEASED — the owner withdrew every owner-binding on it and revoked its \
         content occurrence"
    );
    let released = report.failed.is_empty();
    eviction_response(
        &report,
        serde_json::json!({
            "node_key_id": node_key_id,
            "released": released,
            "released_self": is_this_node,
        }),
    )
}

// ─── POST /v1/self/occurrence/revoke ────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RevokeOccurrenceRequest {
    /// The identity the occurrence belongs to — must be the caller's own.
    identity_key_id: String,
    /// The occurrence (device) to remove from the self.
    occurrence_key_id: String,
    /// Optional annotation (e.g. "laptop lost 2026-06-23"), carried in the
    /// signed revocation envelope.
    #[serde(default)]
    reason: Option<String>,
    /// Required when the occurrence is (one of the keys of) the node this
    /// request is served BY: evicting it withdraws this node's owner-binding
    /// and ends the owner's authority here, as a self-release does.
    #[serde(default)]
    force_self: bool,
}

/// **Revoke a device occurrence — an eviction** (0.5.218, CSD-037).
///
/// Authorised like [`release_node`]: the OWNER's session on this node, and the
/// revocation is signed server-side with the owner's pen. Before 0.5.218 this
/// route wanted a request hybrid-signed by a surviving device key, which the
/// app (a bearer client) never sends — every revoke from the app answered 401 —
/// and then wrote the revocation through the trusted-LOCAL door, unsigned and
/// excluded from replication (the #227 S2 carriage gap). Now it is the signed,
/// replicating door, and when the occurrence IS one of the owner's nodes the
/// same act withdraws that node's owner-binding, so the self room drops it too
/// ([`evict_device`]).
///
/// Refused: no session (401), a session that is not the owner's, a delegated
/// session (the row is signed with the owner's key and would outlive the
/// delegation), and an identity or occurrence that is not the caller's — under
/// ONE id (`self.not_your_device`) whether the key is someone else's or nobody's.
async fn revoke_occurrence(
    State(st): State<SelfState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = match gate(owner_caller(&st.engine, &headers, false).await) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let req: RevokeOccurrenceRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return bad_request(e.to_string()),
    };
    let not_yours = |k: &str| {
        refuse_with(
            StatusCode::NOT_FOUND,
            "self.not_your_device",
            "That key is not one of your devices.",
            k.to_owned(),
        )
    };
    if req.identity_key_id != caller.owner_key_id {
        return not_yours(&req.occurrence_key_id);
    }
    let dir = st.engine.federation_directory();
    // One of the caller's occurrences, active or not: an occurrence revoked
    // under the old LOCAL door is still the owner's, and re-running the
    // eviction on it withdraws whatever owner-binding that door left behind.
    match dir
        .list_identity_occurrences_for(&caller.owner_key_id)
        .await
    {
        Ok(v)
            if v.iter()
                .any(|o| o.occurrence_key_id == req.occurrence_key_id) => {}
        Ok(_) => return not_yours(&req.occurrence_key_id),
        Err(e) => return store_unavailable(format!("list_identity_occurrences_for: {e:#}")),
    }
    // Is the device one of the owner's NODES? Directly (its occurrence is under
    // its node key), or as one of THIS node's keys (a split install's actor
    // occurrence of a node bound under its wire key).
    let owned = match nodes_owned_by(dir.as_ref(), &caller.owner_key_id).await {
        Ok(v) => v,
        Err(e) => return store_unavailable(format!("nodes_owned_by: {e:#}")),
    };
    let this_keys = occurrence_keys_of_node(&st.engine, &caller.node_key_id, true).await;
    let mut nodes: Vec<String> = Vec::new();
    if owned.contains(&req.occurrence_key_id) {
        nodes.push(req.occurrence_key_id.clone());
    }
    if this_keys.contains(&req.occurrence_key_id)
        && owned.contains(&caller.node_key_id)
        && !nodes.contains(&caller.node_key_id)
    {
        nodes.push(caller.node_key_id.clone());
    }
    let is_this_node = nodes.iter().any(|n| this_keys.contains(n));
    if is_this_node && !req.force_self {
        return refuse(
            StatusCode::CONFLICT,
            "self.release_self_requires_force",
            "That is the node you are talking to. Releasing it ends your ownership here, including this session.",
        );
    }
    let capsule = match pen(&st, &caller).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let report = evict_device(
        &st.engine,
        &capsule,
        &caller.owner_key_id,
        &nodes,
        std::slice::from_ref(&req.occurrence_key_id),
        req.reason.as_deref(),
    )
    .await;
    let revoked = report.failed.is_empty();
    eviction_response(
        &report,
        serde_json::json!({
            "identity_key_id": req.identity_key_id,
            "occurrence_key_id": req.occurrence_key_id,
            "revoked": revoked,
            "revoked_by": capsule.key_id(),
            "released_self": is_this_node,
        }),
    )
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
                .is_some_and(is_label_dimension);
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
            "A device name must be between 1 and 64 characters.",
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
            "That key is not one of your devices.",
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

// ─── GET /v1/self/contact-code ──────────────────────────────────────────────

/// One node the code names — echoed beside the code so a client can say WHICH
/// of the person's machines a stranger will be able to reach.
#[derive(Debug, serde::Serialize)]
struct CodeNode {
    key_id: String,
    transport_pubkey_ed25519_base64: String,
}

/// `?nodes=` on `GET /v1/self/contact-code`.
#[derive(Debug, Default, Deserialize)]
struct ContactCodeQuery {
    /// Absent: every node the owner ANNOUNCED. `none`: no nodes (the code then
    /// resolves through the public directory). Otherwise a comma-separated list
    /// of announced node key ids — exactly those.
    #[serde(default)]
    nodes: Option<String>,
}

/// **The owner's CURRENT contact code** (CIRISServer#673): a v3 fedcode naming
/// the person (their fed-ID key and the commitment to its ML-DSA-65 half) and,
/// by the person's CHOICE, some of their announced nodes, each with the
/// TRANSPORT key a destination derives from.
///
/// With nodes, this is the input `POST /v1/contacts` resolves with no
/// directory (edge's `ReadyFromCode`): the code carries what a stranger's
/// directory cannot. With none (`?nodes=none`, or no node announced) it is
/// still a valid code — the person's key and PQC commitment — and the adder
/// resolves the person through the public directory, the lightnet path an
/// announce makes possible. A node code is the wrong thing to share — a node
/// cannot consent, and its owner is unknown to the adder — and the one place a
/// person's code was served before was `POST /v1/self/identity`, at MINT,
/// before any node was claimed.
///
/// **Only ANNOUNCED nodes may be named** (the maintainer's rulings on #655 /
/// #673, 2026-09-25): announce is per node, each node's wizard asks, and the
/// devices a person announced are the ones people contact them through. The
/// choice is the person's — `available_nodes` lists what they may include,
/// `included_nodes` what this code carries — and naming an unannounced or
/// foreign node refuses `self.node_not_announced`. An announced node with no
/// live reticulum transport binding here is reported under
/// `nodes_without_transport` rather than guessed at, because the transport key
/// is NOT derivable from the node's federation key (CIRISServer#335).
///
/// Built with verify's own encoder (`fedcode::FedCode` + `encode` /
/// `encode_qr`), never by hand. Lightnet facts only (CC 5.4.6): a fed-ID key,
/// announced node ids and their transport keys. Nothing group-scoped rides a
/// code.
async fn contact_code(
    State(st): State<SelfState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ContactCodeQuery>,
) -> Response {
    use ciris_verify_core::fedcode;
    // A read of public material: a delegated session may read it too.
    let caller = match gate(owner_caller(&st.engine, &headers, true).await) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let owner = caller.owner_key_id;
    let dir = st.engine.federation_directory();
    let record = match dir.lookup_public_key(&owner).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return refuse_with(
                StatusCode::CONFLICT,
                "self.contact_code_owner_key_absent",
                "This node does not hold your identity's key record, so it can't make your contact code.",
                owner,
            )
        }
        Err(e) => return store_unavailable(format!("lookup_public_key({owner}): {e:#}")),
    };
    // A person's code, and only a person's: a code of any other kind resolves
    // to `NotContactable` at the adder (edge `resolve_contact`).
    let types = ciris_persist::federation::types::identity_type::parse_set(&record.identity_type);
    if !types.contains(&ciris_persist::federation::types::identity_type::USER) {
        return refuse_with(
            StatusCode::CONFLICT,
            "self.contact_code_not_a_person",
            "Your identity is not registered as a person, and only a person can be added as a contact.",
            record.identity_type,
        );
    }
    let Ok(ed_pub) = B64.decode(record.pubkey_ed25519_base64.as_bytes()) else {
        return store_unavailable(format!(
            "the Ed25519 half registered for {owner} is not base64"
        ));
    };
    // THE CODE MUST DERIVE ITS OWN ID. The adder re-derives `key_id` from the
    // pubkey the code carries and refuses a mismatch as impersonation (edge
    // `verify_code_binds_its_key`); an identity registered under a non-derived
    // id (the pre-#247 `{key_id}`-only envelope) would hand out a code every
    // adder refuses. Said here, by name, instead of there.
    let label = owner.rsplit_once('-').map_or("", |(label, _fp)| label);
    if fedcode::derive_key_id(label, &ed_pub) != owner {
        return refuse_with(
            StatusCode::CONFLICT,
            "self.contact_code_key_not_derived",
            "Your identity's key id does not match its key, so everyone you shared a code with would refuse it.",
            owner,
        );
    }
    // The PQC commitment (CIRISVerify#272): without it the adder cannot bind the
    // ML-DSA-65 half it pulls to this code, and admission fails closed.
    let Some(pqc) = record
        .pubkey_ml_dsa_65_base64
        .as_deref()
        .and_then(|b| B64.decode(b.as_bytes()).ok())
    else {
        return refuse_with(
            StatusCode::CONFLICT,
            "self.contact_code_no_pqc_half",
            "Your identity has no post-quantum key half, so no one could add you from a code.",
            owner,
        );
    };
    let commitment = {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(&pqc))
    };
    // THE ANNOUNCED NODES are what the person may choose from. Announce is per
    // node — each node's wizard asks — and a node they did not announce never
    // rides a code, whatever their other nodes chose.
    let announced = match crate::auth::ownership::announced_nodes_of(&st.engine, &owner).await {
        Ok(v) => v,
        Err(e) => return store_unavailable(e),
    };
    // WHICH of them this code carries — the person's choice.
    let selected: Vec<String> = match q.nodes.as_deref().map(str::trim) {
        None => announced.clone(),
        Some(none) if none.eq_ignore_ascii_case("none") => Vec::new(),
        Some(list) => {
            let mut chosen: Vec<String> = list
                .split(',')
                .map(str::trim)
                .filter(|k| !k.is_empty())
                .map(str::to_owned)
                .collect();
            chosen.sort();
            chosen.dedup();
            if chosen.is_empty() {
                return bad_request(
                    "nodes must be `none` or a comma-separated list of announced node key ids"
                        .to_owned(),
                );
            }
            let refused: Vec<&String> = chosen.iter().filter(|k| !announced.contains(k)).collect();
            if !refused.is_empty() {
                return refuse_with(
                    StatusCode::BAD_REQUEST,
                    "self.node_not_announced",
                    "That device isn't reachable, so it can't go in a code.",
                    refused
                        .iter()
                        .map(|k| k.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
            chosen
        }
    };
    // This node's own keys: a split install binds the NODE key but may hold its
    // transport route under another of its keys, so a route for this node is
    // looked up under all of them.
    let engine_key = st.engine.local_derived_key_id().await.ok();
    let own: Vec<String> = engine_key
        .as_deref()
        .map(crate::peer::own_keys_of_this_node)
        .unwrap_or_default();
    let labels = labels_for(&st.engine, &owner).await;
    let mut available: Vec<serde_json::Value> = Vec::with_capacity(announced.len());
    let mut named: Vec<CodeNode> = Vec::new();
    let mut without_transport: Vec<String> = Vec::new();
    for node in &announced {
        let lookup: Vec<String> = if own.contains(node) {
            let mut keys = vec![node.clone()];
            keys.extend(own.iter().filter(|k| *k != node).cloned());
            keys
        } else {
            vec![node.clone()]
        };
        let mut transport = None;
        for key in &lookup {
            match dir.list_transport_destinations_for(key).await {
                Ok(routes) => {
                    transport = routes
                        .into_iter()
                        .find(|d| {
                            d.transport_kind == "reticulum"
                                && d.retired_at.is_none()
                                && d.transport_ed25519_pubkey_base64.is_some()
                        })
                        .and_then(|d| d.transport_ed25519_pubkey_base64);
                }
                Err(e) => {
                    return store_unavailable(format!(
                        "list_transport_destinations_for({key}): {e:#}"
                    ))
                }
            }
            if transport.is_some() {
                break;
            }
        }
        // The owner's own name for the device, when they gave it one — under
        // any of this node's keys when this is the node.
        let label = lookup.iter().find_map(|k| labels.get(k).cloned());
        let mut entry = serde_json::json!({
            "node_key_id": node,
            "announced": true,
            "has_transport": transport.is_some(),
            "this_node": own.contains(node),
        });
        if let Some(label) = label {
            entry["label"] = serde_json::Value::String(label);
        }
        available.push(entry);
        if !selected.contains(node) {
            continue;
        }
        match transport {
            Some(transport) => named.push(CodeNode {
                key_id: node.clone(),
                transport_pubkey_ed25519_base64: transport,
            }),
            None => without_transport.push(node.clone()),
        }
    }
    let mut fc = fedcode::FedCode::new(
        fedcode::FedKind::User,
        owner.clone(),
        record.pubkey_ed25519_base64.clone(),
    )
    .with_ml_dsa_65_pubkey_sha256(commitment.clone())
    .with_owned_nodes(
        named
            .iter()
            .map(|n| {
                fedcode::OwnedNode::new(n.key_id.clone(), n.transport_pubkey_ed25519_base64.clone())
            })
            .collect(),
    );
    if !label.is_empty() {
        fc = fc.with_alias_hint(label.to_owned());
    }
    let (code, qr_payload) = match (fedcode::encode(&fc), fedcode::encode_qr(&fc)) {
        (Ok(c), Ok(q)) => (c, q),
        (Err(e), _) | (_, Err(e)) => {
            return refuse_with(
                StatusCode::CONFLICT,
                "self.contact_code_unencodable",
                "Your contact code could not be made from the keys this node holds.",
                format!("{e}"),
            )
        }
    };
    Json(serde_json::json!({
        "key_id": owner,
        "code": code,
        // The SAME code in verify's ungrouped QR form (`encode_qr`): one
        // identity, one content — only the dashes differ, and `decode` reads
        // either. Render this into the QR symbol; show `code` as text.
        "qr_payload": qr_payload,
        "format": "fedcode-v3",
        "ml_dsa_65_pubkey_sha256": commitment,
        // What the person may choose from: their ANNOUNCED nodes.
        "available_nodes": available,
        // What THIS code carries (each with the transport key it embeds).
        "included_nodes": named,
        // Chosen, announced, but with no transport binding here to embed.
        "nodes_without_transport": without_transport,
        // Whether a stranger can reach you from this code alone. `false` means
        // it still identifies you and resolves through the public directory,
        // where your announced nodes are known.
        "reachable_without_directory": !named.is_empty(),
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
        // 0.5.218 (CSD-037): moved here from `auth::occurrence` — the revoke is
        // the owner's act, authorised by the owner's session and signed with
        // the owner's pen, which is this router's posture, not that one's.
        .route(
            "/v1/self/occurrence/revoke",
            axum::routing::post(revoke_occurrence),
        )
        // CIRISServer#673 — the person's shareable contact code (and QR form).
        .route("/v1/self/contact-code", axum::routing::get(contact_code))
        .with_state(SelfState {
            engine,
            user_seed_dir,
        })
}

#[cfg(test)]
mod label_dimension_tests {
    use super::*;

    #[test]
    fn a_label_is_written_under_the_registered_name_and_read_under_both() {
        assert_eq!(LABEL_DIMENSION, "device:label:v1");
        assert_eq!(LEGACY_LABEL_DIMENSION, "self:device_label:v1");
        assert!(is_label_dimension(LABEL_DIMENSION));
        assert!(
            is_label_dimension(LEGACY_LABEL_DIMENSION),
            "a label written through 0.5.219 lives only on its owner's devices and must stay readable"
        );
        assert!(!is_label_dimension("device:label:v2"));
        assert!(!is_label_dimension("self:delegates_to:v1"));
    }
}
