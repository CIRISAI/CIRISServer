//! Node ownership = the **RESPONSIBLE-PARTY** model (CC 4.4.3.5 + CC 3.2 +
//! CC 1.13.5).
//!
//! A fabric node is `node`-role and **MUST NOT have agency** ("infrastructure
//! must not have agency", CC 1.13.5). So "ownership" is NOT the AGENT's
//! joint-agency partnership — it is a **responsible party**: the owning
//! `user`-role identity emits
//!
//! ```text
//! delegates_to(user → node, delegated_scope: [infra:*])
//! ```
//!
//! with **infra scopes ONLY** (`infra:network_presence`, membership standing,
//! …). This binds the node's identity + group-membership standing UNDER the
//! user's authority, with NO agency. (Contrast: the AGENT's joint-agency
//! partnership uses `agency:*` scopes + `consent:partnership_grant/accept` —
//! that stays in the agent, NOT here.)
//!
//! ## The wire-checkable invariant (CC 4.4.3.5)
//!
//! A `delegates_to` whose attested key is a `node`-only identity MUST carry
//! **only** `infra:*` scopes; a verifier MUST **reject** any `agency:*` (or
//! other non-infra) scope on a node-key delegation. [`scopes_are_infra_only`]
//! is that verifier — it makes "no agency for infra" cryptographic.
//!
//! ## Server-side vs deferred-upstream (substrate v8.8.0)
//!
//! The substrate ships `delegates_to` ([`attestation_type::DELEGATES_TO`]) and
//! a scoped delegation walk, but does NOT ship the `infra:*` / `agency:*` scope
//! prefixes, an `identity_type::NODE` constant, or the reject-agency-on-node
//! gate. Those are enforced **here, server-side**, pending upstream support:
//!
//! - the node self-registers as the free-form `identity_type` string `"node"`
//!   (CC 3.4.7.1: `identity_type` is free-form TEXT), and
//! - the infra/agency split + the reject-agency gate live in this module.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_persist::federation::types::{
    attestation_tier, attestation_type, Attestation, SignedAttestation,
};
use ciris_persist::prelude::Engine;
use sha2::{Digest, Sha256};

// ─── The CC 4.4.3.5 reserved two-prefix scope split ─────────────────────────

/// The server-class scope prefix — the ONLY class a `node`-role delegate may
/// carry. A `delegates_to(user → node)` binding is conformant iff every scope
/// starts with this prefix.
pub const INFRA_SCOPE_PREFIX: &str = "infra:";

/// The brain-only scope prefix — `agency:*` is FORBIDDEN on a pure `node`-role
/// delegate (CC 1.13.5). A verifier MUST reject it on a node-key delegation.
pub const AGENCY_SCOPE_PREFIX: &str = "agency:";

/// `infra:network_presence` — announce/resolve the node's reachability (the
/// CC 3.3.6.2 `transport_destination`) under the owner's authority.
pub const INFRA_NETWORK_PRESENCE: &str = "infra:network_presence";
/// `infra:membership` — hold (non-infra) group-membership *standing* under the
/// owner's authority. The CC 3.2 owner-binding that lets a node count as a
/// member without itself being an accountable party.
pub const INFRA_MEMBERSHIP: &str = "infra:membership";
/// `infra:serve` — serve reads / relay / store / transport (the serve-only
/// floor an unowned node is limited to).
pub const INFRA_SERVE: &str = "infra:serve";

/// The canonical owner-binding scope set: identity + membership standing +
/// serve, all infra-class, in sorted (canonical) order. This is what
/// [`emit_owner_binding`] stamps when the caller does not narrow it.
pub const OWNER_BINDING_INFRA_SCOPES: &[&str] =
    &[INFRA_MEMBERSHIP, INFRA_NETWORK_PRESENCE, INFRA_SERVE];

/// The legacy unprefixed agency kinds (the pre-split Self-at-login act-on-behalf
/// vocabulary). On a node-key delegation these are agency and MUST be rejected
/// just as `agency:*` is — they are the unprefixed equivalents (CC 4.4.3.5).
const LEGACY_AGENCY_KINDS: &[&str] = &[
    "act_on_behalf",
    "message_io",
    "reason",
    "decide",
    "sub_delegation",
];

/// `delegation_purpose` recorded on an owner-binding `delegates_to` — "this user
/// is the responsible party for this node" (the CC 3.2 owner-binding intent).
pub const OWNER_BINDING_PURPOSE: &str = "responsible_for";

/// `dimension` for the owner-binding `delegates_to` envelope. Versioned (`:v1`)
/// to satisfy the substrate's `require_version_segment` dimension gate.
pub const DIMENSION_OWNER_BINDING: &str = "ownership:responsible_party:node:v1";

// ─── The CC 1.13.5 verifier — infra-only scope gate ─────────────────────────

/// **The CC 1.13.5 verifier.** True iff EVERY scope is `infra:*` — i.e. the
/// scope set is conformant for a `node`-role delegate. Returns `false` (REJECT)
/// for:
///
/// - any `agency:*` scope (the brain-only class — forbidden on a node key),
/// - any legacy unprefixed agency kind (`act_on_behalf` / `message_io` /
///   `reason` / `decide` / `sub_delegation` — the pre-split agency vocabulary),
/// - any other non-`infra:` scope, and
/// - an **empty** scope set (a node binding must grant *some* infra scope; an
///   empty set is not an infra-only grant, it is no grant).
///
/// This makes "no agency for infra" cryptographic: a node-key `delegates_to`
/// literally cannot carry agency and still pass.
pub fn scopes_are_infra_only(scopes: &[String]) -> bool {
    if scopes.is_empty() {
        return false;
    }
    scopes.iter().all(|s| {
        let s = s.trim();
        s.starts_with(INFRA_SCOPE_PREFIX)
            && !s.starts_with(AGENCY_SCOPE_PREFIX)
            && !LEGACY_AGENCY_KINDS.contains(&s)
    })
}

// ─── identity_type set membership (CC 3.4.7.1) ──────────────────────────────

/// True iff the stored free-form `identity_type` string (CC 3.4.7.1 — a SET,
/// stored as one text column on this substrate) contains the `role` token.
///
/// The substrate stores `identity_type` as a single exact-match column, so a
/// "set" is encoded as whitespace/comma-separated tokens. We accept the common
/// shapes: an exact single token (`"user"`), or a delimited set
/// (`"user wise_authority"` / `"user,wise_authority"`).
pub fn identity_type_contains(identity_type: &str, role: &str) -> bool {
    identity_type
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .any(|t| t.trim() == role)
}

// ─── Emit the owner-binding (user → node, infra:*) ──────────────────────────

/// Emit the CC 3.2 owner-binding: a `delegates_to(responsible_user → node)`
/// attestation carrying ONLY `infra:*` scopes.
///
/// **Refuses to emit agency to a node.** [`scopes_are_infra_only`] is asserted
/// FIRST; an `agency:*` (or legacy agency) scope is rejected before any sign /
/// persist — the CC 1.13.5 invariant is enforced on the *producer* side too, not
/// only the verifier side.
///
/// Modeled on `peer.rs::emit_replication_consent` (the canonicalize →
/// hybrid-sign → `put_attestation` recipe) and the `self_at_login`
/// `delegates_to` envelope shape, but with the user→node + infra-only profile.
///
/// ## Substrate-expressiveness note (deferred upstream)
///
/// The delegation walk reads edges via `list_attestations_by(issuer)` /
/// `list_attestations_for(target)`, keyed on `attesting_key_id`. For the walk to
/// resolve the user as the issuer we set `attesting_key_id =
/// responsible_user_key_id`. The bytes are hybrid-signed by the *node's* engine
/// signer (the server has no access to the user's private key at emit time), so
/// `scrub_key_id` is recorded honestly as the node's key. The substrate
/// `put_attestation` does NOT re-verify the scrub signature against
/// `attesting_key_id`, so this is accepted today — but it means the owner-binding
/// is node-attested-on-behalf-of-the-user rather than user-self-signed. A
/// substrate that lets the user co-sign the binding (or a client-supplied,
/// user-signed `delegates_to`) is the principled fix (filed upstream).
pub async fn emit_owner_binding(
    engine: &Engine,
    responsible_user_key_id: &str,
    node_key_id: &str,
    infra_scopes: &[String],
) -> Result<String, OwnershipError> {
    // CC 1.13.5: refuse to emit agency to a node — the producer-side gate.
    if !scopes_are_infra_only(infra_scopes) {
        return Err(OwnershipError::AgencyScopeRefused);
    }
    // Canonical (sorted) scope set for deterministic JCS bytes.
    let mut scopes: Vec<String> = infra_scopes.to_vec();
    scopes.sort();
    scopes.dedup();

    let now = chrono::Utc::now();

    // The owner-binding `delegates_to` envelope (user → node, infra-only). The
    // `scope` array is the shape the substrate delegation walk's
    // scope-containment predicate reads.
    let envelope = serde_json::json!({
        "kind": "delegates_to",
        "dimension": DIMENSION_OWNER_BINDING,
        "attesting_key_id": responsible_user_key_id,
        "node_key_id": node_key_id,
        "delegation_purpose": OWNER_BINDING_PURPOSE,
        "scope": scopes,
        "asserted_at": now.to_rfc3339(),
    });

    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .map_err(|e| OwnershipError::Canonicalize(e.to_string()))?;
    let original_content_hash = hex::encode(Sha256::digest(&canonical));

    // Hybrid-sign over the canonical bytes (node engine signer — see the
    // substrate-expressiveness note above; scrub_key_id is the node's key).
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .map_err(|e| OwnershipError::Sign(e.to_string()))?;

    let attestation_id = new_uuid_v4();
    let attestation = Attestation {
        attestation_id: attestation_id.clone(),
        // Issuer = the responsible user (so the delegation walk resolves the
        // user → node edge via list_attestations_by(user) / _for(node)).
        attesting_key_id: responsible_user_key_id.to_owned(),
        attested_key_id: node_key_id.to_owned(),
        attestation_type: attestation_type::DELEGATES_TO.to_owned(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash,
        scrub_signature_classical: B64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
        // Honest: the node engine produced the bytes (the user's private key is
        // not available server-side at emit time).
        scrub_key_id: node_key_id.to_owned(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: vec![node_key_id.to_owned()],
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_owned(),
        tier: attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
    };

    engine
        .federation_directory()
        .put_attestation(SignedAttestation { attestation })
        .await
        .map_err(|e| OwnershipError::Persist(e.to_string()))?;

    tracing::info!(
        responsible_user = %responsible_user_key_id,
        node_key_id = %node_key_id,
        attestation_id = %attestation_id,
        scopes = ?scopes,
        "emitted owner-binding delegates_to(user → node, infra:*) — responsible-party model (CC 3.2)"
    );
    Ok(attestation_id)
}

// ─── Read the owner-binding (is the node owned?) ────────────────────────────

/// Return the responsible user's `key_id` iff a **LIVE, unrevoked**
/// `delegates_to(user → node_key_id)` carrying `infra:*` scope exists whose
/// granter's `identity_type` set contains `"user"`.
///
/// This is the CC 3.2 owner-binding reader: it answers "does this node have a
/// responsible party?" Returns `None` for an UNOWNED node (the serve-only floor
/// applies).
///
/// ## How it walks (substrate v8.8.0)
///
/// The substrate's purpose-built scoped-delegation walk
/// (`issuer_reaches_target_via_scoped_delegation`) is **private**; the public
/// surface is `list_attestations_for` / `list_attestations_by` /
/// `lookup_public_key` / `revocations_for`. We therefore implement the
/// (depth-1) owner-binding check directly over the inbound edges to the node:
///
/// 1. `list_attestations_for(node_key_id)` — the inbound `delegates_to` edges.
/// 2. keep `delegates_to` edges whose `scope` is **infra-only**
///    ([`scopes_are_infra_only`]) — this is the CC 1.13.5 gate applied at READ
///    time too: an edge that carries agency does NOT confer ownership.
/// 3. require the granter (`attesting_key_id`) to be a registered key whose
///    `identity_type` set contains `"user"` (CC 3.2: ownership roots in an
///    accountable human, never a bare node).
/// 4. require the edge to be live: not expired and not revoked (a `withdraws` /
///    `recants` by the granter against the node, or a `revocations_for` row).
///
/// ## Where the substrate walk couldn't express this
///
/// A user→node owner-binding is, by the CC model, a **direct** (depth-1) edge —
/// a user is the responsible party, not a transitive sub-delegate — so the
/// depth-1 inbound scan is sufficient and faithful. A *transitive* responsible
/// chain (user → org → node) is NOT expressible through the public surface here
/// (the scoped walk that would express it is private); if the model later allows
/// indirect responsibility, this needs the substrate to export the scoped walk
/// (filed upstream).
pub async fn is_owner_bound(engine: &Engine, node_key_id: &str) -> Option<String> {
    let directory = engine.federation_directory();
    let now = chrono::Utc::now();

    let inbound = directory.list_attestations_for(node_key_id).await.ok()?;

    for edge in inbound {
        if edge.attestation_type != attestation_type::DELEGATES_TO {
            continue;
        }
        // CC 1.13.5 at read time: an edge that is not infra-only does not own.
        let scopes = scope_set_of(&edge.attestation_envelope);
        if !scopes_are_infra_only(&scopes) {
            continue;
        }
        // Liveness: not expired.
        if let Some(exp) = edge.expires_at {
            if exp <= now {
                continue;
            }
        }
        let granter = edge.attesting_key_id.clone();
        // CC 3.2: the granter must be a registered `user`-role identity.
        let Ok(Some(granter_key)) = directory.lookup_public_key(&granter).await else {
            continue;
        };
        if !identity_type_contains(&granter_key.identity_type, "user") {
            continue;
        }
        // Liveness: granter key not past its own validity window.
        if let Some(until) = granter_key.valid_until {
            if until <= now {
                continue;
            }
        }
        // Revocation: a withdraws/recants by the granter against the node.
        if delegation_revoked(engine, &granter, node_key_id).await {
            continue;
        }
        return Some(granter);
    }
    None
}

/// Minimal RFC-4122 v4 row id (no `uuid` dep) — same recipe as
/// `peer.rs::new_uuid_v4` / `scorer.rs::new_uuid_v4`. The content hash is the
/// integrity anchor, not this id.
fn new_uuid_v4() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let t = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default() as u64;
    let a = t ^ (n.rotate_left(17));
    let b = t.rotate_left(31) ^ n;
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (a >> 32) as u32,
        (a >> 16) as u16,
        (a as u16) & 0x0fff,
        ((b >> 48) as u16 & 0x3fff) | 0x8000,
        b & 0xffff_ffff_ffff,
    )
}

/// The scope set declared by a `delegates_to` envelope's `scope` field (bare
/// string OR array — the two wire shapes the substrate walk accepts).
fn scope_set_of(envelope: &serde_json::Value) -> Vec<String> {
    match envelope.get("scope") {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// True iff the owner-binding from `granter` to `node_key_id` has been revoked —
/// by a `withdraws`/`recants` attestation the granter authored against the node,
/// or by a `revocations_for(node)` row naming the granter as revoker.
async fn delegation_revoked(engine: &Engine, granter: &str, node_key_id: &str) -> bool {
    let directory = engine.federation_directory();
    if let Ok(by_granter) = directory.list_attestations_by(granter).await {
        for a in by_granter {
            let is_retraction = a.attestation_type == attestation_type::WITHDRAWS
                || a.attestation_type == attestation_type::RECANTS;
            if is_retraction && a.attested_key_id == node_key_id {
                return true;
            }
        }
    }
    if let Ok(revs) = directory.revocations_for(node_key_id).await {
        if !revs.is_empty() {
            return true;
        }
    }
    false
}

/// Errors [`emit_owner_binding`] can surface.
#[derive(Debug)]
pub enum OwnershipError {
    /// The supplied scope set carried a non-`infra:*` (agency / legacy-agency)
    /// scope — refused (CC 1.13.5: a node delegation cannot carry agency).
    AgencyScopeRefused,
    /// Canonicalization of the binding envelope failed.
    Canonicalize(String),
    /// Hybrid-signing the binding failed.
    Sign(String),
    /// Persisting the binding (`put_attestation`) failed.
    Persist(String),
}

impl std::fmt::Display for OwnershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OwnershipError::AgencyScopeRefused => write!(
                f,
                "refused to emit owner-binding: a node delegation MUST carry only infra:* scopes \
                 (no agency:* / no legacy agency kinds) — CC 1.13.5"
            ),
            OwnershipError::Canonicalize(e) => write!(f, "canonicalize owner-binding: {e}"),
            OwnershipError::Sign(e) => write!(f, "hybrid-sign owner-binding: {e}"),
            OwnershipError::Persist(e) => write!(f, "persist owner-binding: {e}"),
        }
    }
}
impl std::error::Error for OwnershipError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infra_only_accepts_infra_prefixed() {
        assert!(scopes_are_infra_only(&[
            INFRA_NETWORK_PRESENCE.to_string(),
            INFRA_MEMBERSHIP.to_string(),
            INFRA_SERVE.to_string(),
        ]));
        assert!(scopes_are_infra_only(&["infra:store".to_string()]));
    }

    #[test]
    fn infra_only_rejects_agency_prefixed() {
        assert!(!scopes_are_infra_only(
            &["agency:act_on_behalf".to_string()]
        ));
        // Mixed: one agency scope poisons the whole set.
        assert!(!scopes_are_infra_only(&[
            INFRA_SERVE.to_string(),
            "agency:reason".to_string(),
        ]));
    }

    #[test]
    fn infra_only_rejects_legacy_agency_kinds() {
        // The pre-split unprefixed agency vocabulary is still agency on a node key.
        for k in [
            "act_on_behalf",
            "message_io",
            "reason",
            "decide",
            "sub_delegation",
        ] {
            assert!(
                !scopes_are_infra_only(&[k.to_string()]),
                "legacy agency kind {k} must be rejected on a node delegation"
            );
        }
    }

    #[test]
    fn infra_only_rejects_empty_and_other() {
        assert!(!scopes_are_infra_only(&[]));
        assert!(!scopes_are_infra_only(&["network_presence".to_string()])); // unprefixed
        assert!(!scopes_are_infra_only(&["read".to_string()]));
    }

    #[test]
    fn identity_type_set_membership() {
        assert!(identity_type_contains("user", "user"));
        assert!(identity_type_contains("user wise_authority", "user"));
        assert!(identity_type_contains(
            "user,wise_authority",
            "wise_authority"
        ));
        assert!(!identity_type_contains("node", "user"));
        assert!(!identity_type_contains("steward", "user"));
    }
}
