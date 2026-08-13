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
//! ## Server-side + substrate alignment (substrate v9.0.0)
//!
//! persist v9.0.0 (CIRISPersist#235/#236 closed) now SHIPS the federation-identity
//! vocabulary this module pioneered server-side:
//!
//! - `federation::types::identity_type::NODE` (`"node"`) — the canonical role
//!   token. [`build_self_key_record`](crate::compose) registers it directly.
//! - `federation::admission::scopes_are_infra_only(&HashSet<String>)` — semantics
//!   persist documents as EXACT to ours. Our [`scopes_are_infra_only`] now
//!   **composes** it (keeping the `&[String]` caller shape).
//! - `federation::types::identity_type::set_contains` — composed by our
//!   [`identity_type_contains`].
//! - `federation::admission::check_node_agency_admission` — the reject-agency-on-
//!   node gate, wired into `put_attestation` on all backends. Our producer-side
//!   refusal ([`build_owner_binding_envelope`] gates `scopes_are_infra_only`
//!   first) now composes the SAME predicate, so the server-side gate and the
//!   substrate admission gate cannot disagree.
//!
//! What stays server-side (a STRICTER, return-richer wrapper over the substrate):
//!
//! - [`is_steward_bound`] returns the granter `key_id` (callers bind ROOT to the
//!   responsible user) AND requires the owner-binding edge to be `infra:*`-only
//!   (the CC 1.13.5 read-time gate). persist's general
//!   `federation::admission::is_steward_bound` is scope-agnostic and returns only
//!   `bool` — it is the substrate-internal predicate the v9.0.0 community-
//!   membership gate composes; ours is the node-ownership wrapper the auth
//!   subsystem needs, so it is KEPT (it composes the substrate's leaf predicates
//!   but is not replaced by the substrate's bool form).
//!
//! ## The owner-binding is GENUINELY USER-SIGNED (1-phase, SUBSTRATE-NATIVE)
//!
//! The owner-binding asserts that an accountable human is responsible for the
//! node, so the binding MUST carry the **user's own signature**, not a
//! node-attested-on-behalf one. Because the claiming party is **itself a node**
//! running the full substrate (JCS + hybrid signing), the canonicalization +
//! signing happen IN THE SUBSTRATE ON BOTH ENDS — never in the app. The claim is
//! therefore **1-phase**:
//!
//! - **Claiming side** (the responsible user's LOCAL node):
//!   [`build_signed_owner_binding`] builds the `delegates_to(user → node,
//!   infra:*)` envelope ([`build_owner_binding_envelope`]),
//!   JCS-canonicalizes it ([`canonicalize_owner_binding_envelope`]), HYBRID-SIGNS
//!   the canonical bytes with the **responsible user's** signer (NOT the node's
//!   steward signer), and packages the result as a self-describing
//!   [`SignedOwnerBinding`] (envelope + the user's two signatures + the user's
//!   `key_id` + pubkeys). The app drives this; the local node does all crypto.
//!
//! - **Receiving side** (the node being claimed): `POST /v1/setup/root` accepts
//!   that complete [`SignedOwnerBinding`] and [`apply_signed_owner_binding`]
//!   validates it (node = this node, scopes infra-only, purpose
//!   `responsible_for`, attesting key is the claiming user), re-canonicalizes the
//!   envelope to re-derive the exact signed bytes, verifies the user's hybrid
//!   signature over them against the user's SUPPLIED pubkeys (Strict), registers
//!   the user's key (`identity_type "user"`), then [`persist_user_signed_owner_binding`]
//!   stores the `SignedAttestation` whose `scrub_*` fields hold the USER's
//!   `key_id` + signatures. [`is_steward_bound`] then reads a USER-signed edge.
//!
//! [`emit_steward_binding`] is the one-shot user-signed emit (it takes the user's
//! `LocalSigner` directly: attester == signer, the v9.0.0-conformant shape) for
//! internal emit sites that already hold the user's signer; the CLAIM path uses
//! the 1-phase [`build_signed_owner_binding`] / [`apply_signed_owner_binding`].

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::types::{
    algorithm, attestation_type, cohort_scope, identity_type, Attestation, KeyRecord,
    SignedKeyRecord,
};
use ciris_persist::prelude::{verify_hybrid, Engine, HybridPolicy, LocalSigner};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ─── The CC 4.4.3.5 reserved two-prefix scope split ─────────────────────────

/// The server-class scope prefix — the ONLY class a `node`-role delegate may
/// carry. A `delegates_to(user → node)` binding is conformant iff every scope
/// starts with this prefix.
pub const INFRA_SCOPE_PREFIX: &str = "infra:";

/// The brain-only scope prefix — `agency:*` is FORBIDDEN on a pure `node`-role
/// delegate (CC 1.13.5). A verifier MUST reject it on a node-key delegation.
pub use ciris_persist::federation::types::delegation_scope::AGENCY_PREFIX as AGENCY_SCOPE_PREFIX;

/// `infra:hold_community_membership` — occupy a member seat on **community**
/// rosters under the owner's standing. Membership is STANDING, not judgment:
/// steward/moderator/founder roles are bestowed on the MEMBER (the user/agent)
/// and are never node-holdable (CC 1.13.5 / CC 4.4.3.4.3 conformance rule).
///
/// RC3 crystal-vocabulary hard cut (`FSD/TRUST_ROOT_CAPABILITY_GATE.md`): this
/// token and the family twin RETIRE both `infra:membership` (server legacy)
/// and `infra:join_communities` (CC RC2 / persist) — which, being exact-string
/// matched, never even matched EACH OTHER on the wire. No aliases; pre-fleet,
/// no backwards compat.
///
/// DRY (the split-surface audit, 2026-07-23): these are RE-EXPORTS of persist's
/// `delegation_scope` constants, not local literals. Redeclared copies drift —
/// verify's copy of this very vocabulary fell a whole RC behind (CIRISVerify#217)
/// while the shared-import vocabularies (attestation_type / cohort_scope /
/// identity_type) produced zero drift findings. One source; imports don't drift.
pub use ciris_persist::federation::types::delegation_scope::INFRA_HOLD_COMMUNITY_MEMBERSHIP;
/// `infra:hold_family_membership` — occupy a member seat on **family** rosters
/// under the owner's standing. Split from the community twin because family and
/// community are distinct CEG objects in different sensitivity classes — an
/// owner can give a node community standing while keeping it out of the family.
pub use ciris_persist::federation::types::delegation_scope::INFRA_HOLD_FAMILY_MEMBERSHIP;
/// `infra:network_presence` — announce/resolve the node's reachability (the
/// CC 3.3.6.2 `transport_destination`) under the owner's authority.
pub use ciris_persist::federation::types::delegation_scope::INFRA_NETWORK_PRESENCE;
/// `infra:serve` — serve reads / relay / store / transport (the serve-only
/// floor an unowned node is limited to).
pub use ciris_persist::federation::types::delegation_scope::INFRA_SERVE;

/// **Now, truncated to microseconds** (persist v31.0.0, CIRISPersist#598).
///
/// `Utc::now()` carries nanoseconds. Postgres `TIMESTAMPTZ` stores microseconds,
/// so a nanosecond-precision instant is not merely rounded on the way in — it
/// changes the ANSWER: persist's own words, *"the same op sequence would be a
/// strict order on sqlite/memory and a TIE on postgres."*
///
/// That is a fold deciding differently depending on which backend a node runs.
/// The producer truncates so both backends see the same instant, and persist
/// refuses sub-microsecond values rather than silently accepting a value it
/// cannot round-trip.
///
/// Every timestamp this module puts on a signed row goes through here. One
/// call site left on `Utc::now()` reintroduces the divergence for exactly the
/// rows that site writes, and it would fail only on postgres — which is the
/// deployment least likely to be the one you tested.
fn now_micros() -> chrono::DateTime<chrono::Utc> {
    use chrono::SubsecRound as _;
    chrono::Utc::now().trunc_subsecs(6)
}

/// The canonical owner-binding scope set: identity + membership standing
/// (community + family seats) + serve, all infra-class, in sorted (canonical)
/// order. This is what [`emit_steward_binding`] stamps when the caller does not
/// narrow it (tighten-only: the owner may drop the family seat, etc.).
pub const OWNER_BINDING_INFRA_SCOPES: &[&str] = &[
    INFRA_HOLD_COMMUNITY_MEMBERSHIP,
    INFRA_HOLD_FAMILY_MEMBERSHIP,
    INFRA_NETWORK_PRESENCE,
    INFRA_SERVE,
];

/// The legacy unprefixed agency kinds (the pre-split Self-at-login act-on-behalf
/// vocabulary). On a node-key delegation these are agency and MUST be rejected
/// just as `agency:*` is — they are the unprefixed equivalents (CC 4.4.3.5).
/// Retained as the documented rejected vocabulary; the reject itself is now the
/// single "every token starts with `infra:`" predicate (persist's
/// `scopes_are_infra_only`, which these kinds fail), so this list is no longer a
/// separate admission branch (matches the substrate's own rationale).
#[allow(dead_code)]
const LEGACY_AGENCY_KINDS: &[&str] = &[
    "act_on_behalf",
    "message_io",
    "reason",
    "decide",
    "sub_delegation",
];

/// `delegation_purpose` recorded on an owner-binding `delegates_to` — "this user
/// is the responsible party for this node" (the CC 3.2 owner-binding intent).
/// Sourced from the substrate so the wire contract can never drift: persist keys
/// its single-owner gate + `owner_of` on this exact pair (its docs pin these to
/// be byte-identical to ours).
pub const OWNER_BINDING_PURPOSE: &str = ciris_persist::federation::types::owner_binding::PURPOSE;

/// `dimension` for the owner-binding `delegates_to` envelope. Versioned (`:v1`)
/// to satisfy the substrate's `require_version_segment` dimension gate. Sourced
/// from the substrate ([`owner_binding::DIMENSION`](ciris_persist::federation::types::owner_binding::DIMENSION))
/// — the exact string persist's `owner_of` / single-owner gate key on.
pub const DIMENSION_OWNER_BINDING: &str =
    ciris_persist::federation::types::owner_binding::DIMENSION;

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
///
/// ## Substrate alignment (persist v9.0.0, CIRISPersist#236)
///
/// persist v9.0.0 now publishes `federation::admission::scopes_are_infra_only`
/// (`&HashSet<String> -> bool`) with semantics persist documents as EXACT to
/// ours (accept `infra:*`, reject `agency:*` + legacy agency kinds + empty +
/// other — the legacy-agency and other-prefix cases are subsumed by the single
/// "every token starts with `infra:`" predicate). We **compose** it rather than
/// duplicate the rule: this wrapper keeps our `&[String]` signature (the shape
/// our callers + the JCS scope array use) and trims each token before delegating
/// to the substrate predicate. The infra:*/agency:* split (CC 1.13.5) thus stays
/// enforced server-side AND is now the same predicate the substrate's
/// `check_node_agency_admission` gate applies at `put_attestation`.
pub fn scopes_are_infra_only(scopes: &[String]) -> bool {
    let set: std::collections::HashSet<String> =
        scopes.iter().map(|s| s.trim().to_owned()).collect();
    ciris_persist::federation::admission::scopes_are_infra_only(&set)
}

// ─── identity_type set membership (CC 3.4.7.1) ──────────────────────────────

/// True iff the stored free-form `identity_type` string (CC 3.4.7.1 — a SET,
/// stored as one text column on this substrate) contains the `role` token.
///
/// The substrate stores `identity_type` as a single exact-match column, so a
/// "set" is encoded as whitespace/comma-separated tokens.
///
/// ## Substrate alignment (persist v9.0.0)
///
/// persist v9.0.0 publishes `federation::types::identity_type::set_contains`
/// (the canonical §7.0.1 set membership the substrate's own node-agency +
/// owner-binding gates use). We **compose** it so producer + verifier parse the
/// set identically (e.g. the duplicate-token `"node,node"` robustness from
/// SecReview F1).
pub fn identity_type_contains(identity_type: &str, role: &str) -> bool {
    ciris_persist::federation::types::identity_type::set_contains(identity_type, role)
}

/// The scope set declared by a `delegates_to` envelope's `scope` field (bare
/// string OR array — the two wire shapes the substrate walk accepts). Used by
/// the WRITE-side validation gate ([`apply_signed_owner_binding`] /
/// [`build_owner_binding_envelope`]) to enforce CC 1.13.5 (`infra:*`-only) at
/// emit time; the READ-side owner-binding check defers entirely to the
/// substrate's [`Engine::steward_bindings_of`] (#249 Cut B).
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

// ─── Build + canonicalize the owner-binding envelope (the bytes the USER signs) ─

/// Build the CC 3.2 owner-binding `delegates_to(responsible_user → node)`
/// envelope (user → node, infra-only) — the `serde_json::Value` that is JCS-
/// canonicalized into the bytes the responsible party signs.
///
/// **Refuses to build an agency binding.** [`scopes_are_infra_only`] is asserted
/// FIRST; an `agency:*` (or legacy agency) scope is rejected before the envelope
/// is shaped — the CC 1.13.5 invariant on the *producer* side. The scope set is
/// sorted + deduped so the JCS bytes are deterministic for a given (user, node,
/// scope-set).
///
/// # This is the DIMENSION BODY, not the whole envelope
///
/// It carries what an owner-binding MEANS. It does not carry `asserted_at`, the
/// row id, or the typed-column mirror — those are stamped by
/// [`crate::attest::Emit::stamp`] on the way to the signature, because every one
/// of them must agree with a column and only the substrate knows the whole list.
///
/// It used to take `asserted_at` as a parameter, and that parameter was the
/// defect: whoever called this chose the instant, and whoever built the row chose
/// another one. persist v31 refuses the divergence (CIRISPersist#598), rightly —
/// a column no signature covers is a replay knob. The instant is now sampled
/// exactly once, inside the stamp, before the bytes exist.
///
/// The `scope` array is the shape the substrate delegation walk's
/// scope-containment predicate reads; `attesting_key_id` is the user (so the
/// walk resolves the user → node edge); `attested_key_id` is the node.
pub fn build_owner_binding_envelope(
    responsible_user_key_id: &str,
    node_key_id: &str,
    infra_scopes: &[String],
) -> Result<serde_json::Value, OwnershipError> {
    // CC 1.13.5: refuse to build an agency binding — the producer-side gate.
    if !scopes_are_infra_only(infra_scopes) {
        return Err(OwnershipError::AgencyScopeRefused);
    }
    // Canonical (sorted) scope set for deterministic JCS bytes.
    let mut scopes: Vec<String> = infra_scopes.to_vec();
    scopes.sort();
    scopes.dedup();

    Ok(serde_json::json!({
        "kind": "delegates_to",
        (paths::DIMENSION): DIMENSION_OWNER_BINDING,
        "attesting_key_id": responsible_user_key_id,
        "node_key_id": node_key_id,
        "delegation_purpose": OWNER_BINDING_PURPOSE,
        "scope": scopes,
    }))
}

/// JCS-canonicalize an owner-binding envelope into the exact bytes the user
/// signs (and the server re-derives in phase 2). This is the SAME
/// `ceg_produce_canonicalize` the attestation sign-path uses, so the client
/// never needs JCS: it signs the server-provided canonical bytes verbatim.
pub fn canonicalize_owner_binding_envelope(
    envelope: &serde_json::Value,
) -> Result<Vec<u8>, OwnershipError> {
    ciris_persist::verify::canonical::ceg_produce_canonicalize(envelope)
        .map_err(|e| OwnershipError::Canonicalize(e.to_string()))
}

// ─── Assemble + persist a USER-SIGNED owner-binding (phase 2) ────────────────

/// Assemble a [`SignedAttestation`] from a user-built `delegates_to` envelope
/// PLUS the responsible party's OWN hybrid signatures over its canonical bytes,
/// and persist it via `put_attestation` — so the stored owner-binding is
/// GENUINELY USER-SIGNED ([`is_steward_bound`] then reads a user-signed edge).
///
/// This is the principled fix for the prior node-attested-on-behalf binding:
/// the `scrub_*` fields carry the USER's `key_id` + the user's Ed25519 + ML-DSA-65
/// signatures (not the node engine's), so the responsible party cryptographically
/// asserts their own ownership. The caller MUST have already (a) re-canonicalized
/// the envelope to the same bytes the user signed, and (b) verified the user's
/// hybrid signature over those bytes against the user's registered pubkeys.
///
/// persist v9.0.0 (CC 5.3.2.4.3.1) NOW re-verifies the federation-tier hybrid
/// scrub signature at the `put_attestation` admission gate: it canonicalizes
/// `attestation_envelope` via `ceg_produce_canonicalize`, cross-checks
/// `SHA-256(canonical) == original_content_hash`, and Strict-`verify_hybrid`s
/// both halves against `scrub_key_id`'s registered pubkey. This path satisfies
/// that gate — the user signs `canonicalize_owner_binding_envelope(envelope)`
/// (the SAME `ceg_produce_canonicalize`) with `LocalSigner::sign_hybrid` (the
/// bound ML-DSA form), `original_content_hash = SHA-256(canonical)`, and
/// `scrub_key_id` = the user, whose hybrid pubkeys phase 1 registers. So the
/// user MUST be registered before this call (phase 1 registers them). Returns the
/// persisted attestation id.
///
/// ## cohort_scope is CHECKED here, not chosen here (CIRISPersist#643)
///
/// `cohort_scope` used to be pure row metadata this function stamped from the
/// claim — the receiving node deciding how widely the owner's ownership claim
/// would be published, with the owner's signature saying nothing about it.
/// persist v31 binds it into the signed mirror, so it now arrives already stated
/// by the owner and the `cohort_scope` argument becomes a CHECK: it must equal
/// what the owner signed, or the binding is refused. A receiver that silently
/// preferred its own value would be re-publishing someone else's claim to an
/// audience they never agreed to, and would in any case mint a row every peer
/// refuses.
///
/// The tier stays `federation` — the row is genuinely hybrid-signed and must keep
/// passing (and benefiting from) the federation-tier ingest re-verify; `local`
/// tier would BOTH skip that re-verify AND mean "private to the producing
/// occurrence", defeating the §10.1.4 self-replication this design needs. A
/// `self`-scoped binding self-replicates to the owner's other
/// `identity_occurrences` and is structurally invisible to the federation
/// (cohort `self`/`family` ⇒ no `holds_bytes`).
#[allow(clippy::too_many_arguments)]
pub async fn persist_user_signed_owner_binding(
    engine: &Engine,
    envelope: serde_json::Value,
    responsible_user_key_id: &str,
    node_key_id: &str,
    cohort_scope: &str,
    user_ed25519_sig_b64: &str,
    user_ml_dsa_65_sig_b64: &str,
) -> Result<String, OwnershipError> {
    // ── Re-open the row the owner signed ──────────────────────────────────────
    //
    // Every column comes back out of the signed envelope; nothing is re-decided
    // here. This function used to hand-roll a 21-field `Attestation` beside the
    // envelope and require the two to agree — the CIRISServer#402 class, and the
    // reason first-run claim broke four separate ways on v31.
    //
    // Adoption TRANSPORTS a claim; it does not test one. The binding check inside
    // `assemble` is tautological on an adopted row (the columns were read out of
    // the mirror), so the two real defences are the ones below and the caller's
    // signature verification — see [`crate::attest`].
    let adopted = crate::attest::Emit::adopt(&envelope)
        .map_err(|e| OwnershipError::Validation(e.to_string()))?;

    // ── Check the signed claims against what THIS node independently knows ────
    //
    // These are the checks that are NOT tautological: each compares a field the
    // owner signed against a fact this node holds on its own account. Without
    // them a perfectly-valid binding for a different node, a different owner, or
    // a wider audience would be adopted here purely because its signature checks
    // out.
    let mirror_says = |field: &str, signed: &str, ours: &str| {
        OwnershipError::Validation(format!(
            "owner-binding `{field}` is {signed:?} in the envelope the owner SIGNED, but this \
             node is applying it as {ours:?}. Refused rather than reconciled: the signed value is \
             the owner's statement and the local value is this node's, and silently preferring \
             either one is how a claim gets applied to something its owner never agreed to \
             (CIRISPersist#643)"
        ))
    };
    if adopted.attesting_key_id() != responsible_user_key_id {
        return Err(mirror_says(
            "attesting_key_id",
            adopted.attesting_key_id(),
            responsible_user_key_id,
        ));
    }
    if adopted.attested_key_id() != node_key_id {
        return Err(mirror_says(
            "attested_key_id",
            adopted.attested_key_id(),
            node_key_id,
        ));
    }
    if adopted.cohort_scope() != cohort_scope {
        return Err(mirror_says(
            "cohort_scope",
            adopted.cohort_scope(),
            cohort_scope,
        ));
    }
    if adopted.attestation_type() != attestation_type::DELEGATES_TO {
        return Err(mirror_says(
            "attestation_type",
            adopted.attestation_type(),
            attestation_type::DELEGATES_TO,
        ));
    }
    // The node must be able to revoke the binding that names it. A row conferring
    // authority over this node with this node absent from `subject_key_ids` is
    // authority nobody here can ever withdraw.
    if !adopted.subject_key_ids().iter().any(|k| k == node_key_id) {
        return Err(OwnershipError::Validation(format!(
            "owner-binding `subject_key_ids` {:?} does not name this node ({node_key_id}). \
             `subject_key_ids` is what grants revocation authority, so a binding that confers \
             authority over this node without naming it as a subject is authority this node can \
             never withdraw",
            adopted.subject_key_ids(),
        )));
    }

    // ── Assemble from the owner's OWN signature halves + store ────────────────
    let row = adopted
        .assemble_from_b64(user_ed25519_sig_b64, user_ml_dsa_65_sig_b64)
        .map_err(|e| OwnershipError::Validation(e.to_string()))?;
    let attestation_id = crate::attest::put(engine, row)
        .await
        .map_err(|e| OwnershipError::Persist(e.to_string()))?;

    tracing::info!(
        responsible_user = %responsible_user_key_id,
        node_key_id = %node_key_id,
        attestation_id = %attestation_id,
        cohort_scope = %cohort_scope,
        "persisted USER-SIGNED owner-binding delegates_to(user → node, infra:*) — \
         responsible party asserts own ownership (CC 3.2 / CC 1.13.5)"
    );
    Ok(attestation_id)
}

// ─── SUBSTRATE-NATIVE 1-phase owner-binding (build on the claiming node, ─────
//     apply on the node being claimed) ──────────────────────────────────────

/// A COMPLETE, already-user-signed owner-binding — the self-describing wire
/// object the claiming node hands the node being claimed in the 1-phase
/// `POST /v1/setup/root` body.
///
/// It bundles everything the receiver needs to verify + persist a GENUINELY
/// USER-SIGNED `delegates_to(user → node, infra:*)` WITHOUT the receiver (or any
/// app) ever canonicalizing/signing on the user's behalf:
///
/// - `envelope` — the `delegates_to` envelope the user signed
///   ([`build_owner_binding_envelope`]); the receiver re-canonicalizes IT
///   ([`canonicalize_owner_binding_envelope`]) to re-derive the exact signed
///   bytes (so nothing in the envelope can be tampered without breaking the sig);
/// - `attesting_key_id` — the responsible USER's `key_id` (the
///   `delegates_to` granter; MUST equal `envelope.attesting_key_id`);
/// - `ed25519_pubkey_b64` / `ml_dsa_65_pubkey_b64` — the user's hybrid PUBLIC
///   keys (the receiver registers them as the `user`-role identity AND verifies
///   the signatures against them);
/// - `ed25519_sig_b64` / `ml_dsa_65_sig_b64` — the user's hybrid SIGNATURES over
///   the JCS-canonical bytes of `envelope` (produced by the substrate signer on
///   the claiming node).
///
/// Both the build side ([`build_signed_owner_binding`]) and the apply side
/// ([`apply_signed_owner_binding`]) live in the substrate, so the app needs NO
/// crypto code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedOwnerBinding {
    /// The `delegates_to(user → node, infra:*)` envelope the user signed.
    pub envelope: serde_json::Value,
    /// The responsible user's `key_id` (the granter). MUST equal
    /// `envelope.attesting_key_id`.
    pub attesting_key_id: String,
    /// The user's raw Ed25519 public key (base64-standard, 32 bytes).
    pub ed25519_pubkey_b64: String,
    /// The user's raw ML-DSA-65 public key (base64-standard).
    pub ml_dsa_65_pubkey_b64: String,
    /// The user's Ed25519 signature over the JCS-canonical bytes of `envelope`.
    pub ed25519_sig_b64: String,
    /// The user's ML-DSA-65 signature over the JCS-canonical bytes of `envelope`.
    pub ml_dsa_65_sig_b64: String,
    /// The user's Ed25519 signature over the JCS-canonical bytes of the **key
    /// registration envelope** (`{ "key_id": <user_key_id> }`) — so the user's
    /// `federation_keys` row can be admitted through the canonical
    /// [`Engine::register_federation_key`] gate (which re-verifies the scrub
    /// signature over the registration envelope), not the bypass `put_public_key`
    /// (CIRISServer#31). `None` for legacy bindings produced before this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reg_envelope_ed25519_sig_b64: Option<String>,
    /// The user's ML-DSA-65 signature over the registration-envelope canonical
    /// bytes (the PQC half of [`Self::reg_envelope_ed25519_sig_b64`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reg_envelope_ml_dsa_65_sig_b64: Option<String>,
}

/// **Claiming side (substrate-native).** Build a COMPLETE, user-signed
/// owner-binding on the responsible user's LOCAL node: build the
/// `delegates_to(user → target node, infra:*)` envelope, JCS-canonicalize it,
/// and HYBRID-SIGN the canonical bytes with the **responsible USER's** signer
/// (`user_signer` — NOT the node's steward signer). Returns a
/// [`SignedOwnerBinding`] the app POSTs verbatim to the target's
/// `POST /v1/setup/root`. All crypto happens in the substrate here; the app
/// supplies only inputs.
///
/// `user_signer` carries the user's `key_id` + hybrid keypair; its public keys
/// are read straight off the produced [`HybridSignature`](ciris_crypto::HybridSignature),
/// so the receiver registers exactly the keys that signed.
///
/// Refuses to build an agency binding ([`build_owner_binding_envelope`] gates
/// `scopes_are_infra_only` first — CC 1.13.5).
///
/// # `cohort_scope` is signed here, not stamped there (CIRISPersist#643)
///
/// The audience of the binding used to be chosen by the RECEIVING node and
/// written onto the row unsigned — so the node being claimed decided how widely
/// its owner's ownership claim was published, and the owner's signature said
/// nothing about it. persist v31 binds `cohort_scope` into the signed mirror,
/// which ends that: the owner states the audience, the receiver checks it against
/// the cohort the claim was made under, and a mismatch is refused rather than
/// silently resolved in the receiver's favour. That is the contextual-integrity
/// reading too — widening who can see a claim is the claimant's call.
pub async fn build_signed_owner_binding(
    user_signer: &LocalSigner,
    node_key_id: &str,
    infra_scopes: &[String],
    cohort_scope: &str,
) -> Result<SignedOwnerBinding, OwnershipError> {
    let user_key_id = user_signer.key_id().to_string();

    // ── ONE AUTHOR FOR THE ROW AND ITS ENVELOPE (CIRISServer#402) ─────────────
    //
    // This used to build the envelope here and the row on the RECEIVING side,
    // independently, and require them to agree. persist v31 refuses every way
    // they can disagree and found four of them on this one claim: the missing
    // subject binding (#659), the divergent `asserted_at` column (#598), its
    // sub-microsecond precision (#598), and the absent typed-column mirror
    // (#643). Each arrived as its own 500 on a live first-run claim, and each
    // looked like its own small bug. They are one bug — two authors for one fact
    // — so they get one cure: [`crate::attest`], the only door that mints a row.
    //
    // The row is ASSEMBLED here, on the claiming node, and its envelope is what
    // travels. That is deliberate: a binding the substrate would refuse now fails
    // in front of the operator running the claim, rather than as a 500 from a
    // machine whose logs they cannot read.
    let stamped = crate::attest::Emit::stamp(
        &user_key_id,
        crate::attest::Spec::new(
            attestation_type::DELEGATES_TO,
            cohort_scope,
            build_owner_binding_envelope(&user_key_id, node_key_id, infra_scopes)?,
        )
        // The node is the subject: `subject_key_ids` is what will let it be
        // revoked, so it is signed rather than stamped by whoever stores the row.
        .about(node_key_id),
    )
    .map_err(|e| OwnershipError::Canonicalize(e.to_string()))?;

    // HYBRID-sign the canonical bytes with the USER's signer (the responsible
    // party's key) — the substrate produces both halves + carries both pubkeys.
    let sig = user_signer
        .sign_hybrid(stamped.canonical())
        .await
        .map_err(|e| OwnershipError::Sign(e.to_string()))?;
    let ed25519_pubkey_b64 = B64.encode(&sig.classical.public_key);
    let ml_dsa_65_pubkey_b64 = B64.encode(&sig.pqc.public_key);
    let ed25519_sig_b64 = B64.encode(&sig.classical.signature);
    let ml_dsa_65_sig_b64 = B64.encode(&sig.pqc.signature);

    // Assemble the row the RECEIVER will assemble, and put ITS envelope on the
    // wire. Assembling is what re-checks the seven-column binding at the mint;
    // discarding the row afterwards is the point — this node does not store it.
    let envelope = stamped
        .assemble(sig)
        .map_err(|e| OwnershipError::Canonicalize(e.to_string()))?
        .attestation_envelope;

    // ALSO sign the key REGISTRATION envelope so the receiver can admit the user's
    // federation_keys row through the canonical register_federation_key gate
    // (CIRISServer#31), canonicalized identically (ceg_produce_canonicalize).
    //
    // persist v31.0.0 (#659) — the envelope must BIND ITS SUBJECT: key_id,
    // identity_type and both pubkey legs. A bare `{ "key_id" }` is refused, and
    // the refusal is the whole point: "every signature over this row is verified
    // over those bytes ONLY, so an envelope that does not name its subject stands
    // for ANY record it is pasted onto."
    //
    // This broke FIRST-RUN CLAIM outright on v31 — the owner-binding's user key
    // could not register, so `setup/root` answered 500 and the wizard looped.
    // The binder must run on BOTH sides over identical bytes: here before
    // signing, and in `apply_signed_owner_binding` before verifying. They are in
    // this one module precisely so they cannot drift apart.
    let mut reg_envelope = serde_json::json!({ "key_id": user_key_id });
    ciris_persist::federation::admission::bind_subject_into_envelope(
        &mut reg_envelope,
        &user_key_id,
        identity_type::USER,
        &ed25519_pubkey_b64,
        Some(&ml_dsa_65_pubkey_b64),
    )
    .map_err(OwnershipError::Sign)?;
    let reg_canonical = canonicalize_owner_binding_envelope(&reg_envelope)?;
    let reg_sig = user_signer
        .sign_hybrid(&reg_canonical)
        .await
        .map_err(|e| OwnershipError::Sign(e.to_string()))?;

    Ok(SignedOwnerBinding {
        envelope,
        attesting_key_id: user_key_id,
        ed25519_pubkey_b64,
        ml_dsa_65_pubkey_b64,
        ed25519_sig_b64,
        ml_dsa_65_sig_b64,
        reg_envelope_ed25519_sig_b64: Some(B64.encode(&reg_sig.classical.signature)),
        reg_envelope_ml_dsa_65_sig_b64: Some(B64.encode(&reg_sig.pqc.signature)),
    })
}

/// The outcome of [`apply_signed_owner_binding`]: the responsible user and the
/// persisted owner-binding row id, so the caller can bind ROOT to the user.
#[derive(Debug, Clone)]
pub struct AppliedOwnerBinding {
    /// The responsible user's `key_id` ROOT is bound to.
    pub responsible_user_key_id: String,
    /// The persisted `delegates_to` owner-binding attestation id.
    pub attestation_id: String,
}

/// **Receiving side (the node being claimed).** Validate a complete, user-signed
/// [`SignedOwnerBinding`] against THIS node, verify the user's hybrid signature
/// over the JCS-canonical bytes of its envelope (Strict), register the user's
/// key as `identity_type "user"`, and persist the GENUINELY USER-SIGNED
/// `delegates_to` via [`persist_user_signed_owner_binding`]. Returns the
/// responsible user + the persisted attestation id (the caller binds ROOT).
///
/// Validation (all enforced; any failure → `Err`, nothing persisted):
/// - `envelope.node_key_id` == `this_node_key_id` (CC: attests THIS node);
/// - `envelope.delegation_purpose` == [`OWNER_BINDING_PURPOSE`];
/// - `envelope.scope` is infra-only ([`scopes_are_infra_only`] — REJECT agency,
///   CC 1.13.5);
/// - `envelope.attesting_key_id` == `binding.attesting_key_id` (the claiming
///   user; no third-party / mismatched granter);
/// - the user's hybrid signature verifies over `canonicalize(envelope)` against
///   the SUPPLIED user pubkeys ([`verify_hybrid`], Strict — both halves).
///
/// The user's key is registered through
/// [`put_public_key`](ciris_persist::federation::FederationDirectory::put_public_key)
/// as `identity_type "user"` BEFORE persisting the binding (so
/// `put_attestation`'s attesting-key-exists FK is satisfied and
/// [`is_steward_bound`]'s granter-is-user check resolves).
///
/// `cohort_scope` is the cohort the node is claimed under (CIRISServer#125 —
/// `self` by default; the caller threads it from the validated claim). It is NOT
/// part of the user-signed envelope, so it is stamped only on the persisted row
/// (see [`persist_user_signed_owner_binding`]); changing it cannot affect the
/// signature verified above.
pub async fn apply_signed_owner_binding(
    engine: &Engine,
    this_node_key_id: &str,
    cohort_scope: &str,
    policy: HybridPolicy,
    binding: &SignedOwnerBinding,
) -> Result<AppliedOwnerBinding, OwnershipError> {
    let envelope = &binding.envelope;

    // ── Structural validation (independent of the signature) ──────────────────
    let attested_node = envelope
        .get("node_key_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if attested_node != this_node_key_id {
        return Err(OwnershipError::Validation(
            "owner-binding does not attest THIS node (node_key_id mismatch)".into(),
        ));
    }
    let purpose = envelope
        .get("delegation_purpose")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if purpose != OWNER_BINDING_PURPOSE {
        return Err(OwnershipError::Validation(format!(
            "owner-binding delegation_purpose must be {OWNER_BINDING_PURPOSE:?}"
        )));
    }
    let scopes = scope_set_of(envelope);
    // CC 1.13.5: REJECT agency on a node delegation.
    if !scopes_are_infra_only(&scopes) {
        return Err(OwnershipError::AgencyScopeRefused);
    }
    let env_attesting = envelope
        .get("attesting_key_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if env_attesting.is_empty() || env_attesting != binding.attesting_key_id {
        return Err(OwnershipError::Validation(
            "owner-binding envelope attesting_key_id is empty or does not match the \
             claiming user (binding.attesting_key_id)"
                .into(),
        ));
    }

    // ── Re-canonicalize → the EXACT bytes the user signed ─────────────────────
    let canonical = canonicalize_owner_binding_envelope(envelope)?;

    // ── Verify the USER's hybrid signature over those bytes against the ───────
    //    user's SUPPLIED pubkeys (Strict — both halves). PoP for the binding.
    verify_hybrid(
        &canonical,
        &binding.ed25519_sig_b64,
        Some(&binding.ml_dsa_65_sig_b64),
        &binding.ed25519_pubkey_b64,
        Some(&binding.ml_dsa_65_pubkey_b64),
        policy,
        None,
    )
    .map_err(|e| OwnershipError::Verify(e.to_string()))?;

    // ── Register the user's key as identity_type "user" (CC 3.2) ──────────────
    register_user_key(engine, binding).await?;

    // ── Persist the GENUINELY USER-SIGNED delegates_to ────────────────────────
    let attestation_id = persist_user_signed_owner_binding(
        engine,
        envelope.clone(),
        &binding.attesting_key_id,
        this_node_key_id,
        cohort_scope,
        &binding.ed25519_sig_b64,
        &binding.ml_dsa_65_sig_b64,
    )
    .await?;

    Ok(AppliedOwnerBinding {
        responsible_user_key_id: binding.attesting_key_id.clone(),
        attestation_id,
    })
}

/// Register the claiming user's hybrid key in `federation_keys` as
/// `identity_type "user"` (CC 3.2: ownership roots in an accountable human) via
/// [`put_public_key`](ciris_persist::federation::FederationDirectory::put_public_key).
///
/// The proof-of-possession is already established by [`apply_signed_owner_binding`]'s
/// [`verify_hybrid`] over the owner-binding canonical bytes against THESE pubkeys,
/// so we record the proven identity directly (rather than requiring a SECOND
/// registration-envelope signature for `register_federation_key`). The `scrub_*`
/// fields carry a self-attested envelope hash + the binding signatures for
/// row-shape completeness; they are NOT re-verified by `put_public_key`.
/// Idempotent for a matching row.
async fn register_user_key(
    engine: &Engine,
    binding: &SignedOwnerBinding,
) -> Result<(), OwnershipError> {
    // If the user is already registered as a `user`-role identity, no-op (a
    // re-applied binding must not fail on the FK gate).
    if let Ok(Some(existing)) = engine
        .federation_directory()
        .lookup_public_key(&binding.attesting_key_id)
        .await
    {
        if identity_type_contains(&existing.identity_type, "user") {
            return Ok(());
        }
    }

    let now = now_micros();
    // Reconstruct the SAME subject-bound envelope the signer produced (#659).
    // Identical binder, identical inputs — the receiver derives the preimage
    // rather than trusting one supplied on the wire, which is what makes the
    // signature mean anything.
    let mut reg_envelope = serde_json::json!({ "key_id": binding.attesting_key_id });
    ciris_persist::federation::admission::bind_subject_into_envelope(
        &mut reg_envelope,
        &binding.attesting_key_id,
        identity_type::USER,
        &binding.ed25519_pubkey_b64,
        Some(&binding.ml_dsa_65_pubkey_b64),
    )
    .map_err(OwnershipError::Sign)?;
    let reg_canonical = canonicalize_owner_binding_envelope(&reg_envelope)?;

    // CIRISServer#31: prefer the AUTHORITATIVE admission gate. When the binding
    // carries a registration-envelope signature (the canonical hybrid PoP over
    // `{ key_id }` — the SAME shape every other identity registers under), the
    // scrub signature signs the registration envelope, so the row is admissible
    // through `Engine::register_federation_key`, which RE-VERIFIES it → a
    // verifiable row. A legacy binding (no reg sig) falls back to the bypass
    // `put_public_key` with the owner-binding signatures as scrub material (the
    // row is PoP-proven by apply_signed_owner_binding's verify_hybrid over the
    // binding bytes, but is not re-verifiable by the admission gate).
    let via_gate = match (
        &binding.reg_envelope_ed25519_sig_b64,
        &binding.reg_envelope_ml_dsa_65_sig_b64,
    ) {
        (Some(ed), Some(pqc)) => Some((ed.clone(), pqc.clone())),
        _ => None,
    };
    let (scrub_ed, scrub_pqc) = via_gate.clone().unwrap_or_else(|| {
        (
            binding.ed25519_sig_b64.clone(),
            binding.ml_dsa_65_sig_b64.clone(),
        )
    });
    let record = KeyRecord {
        key_id: binding.attesting_key_id.clone(),
        pubkey_ed25519_base64: binding.ed25519_pubkey_b64.clone(),
        pubkey_ml_dsa_65_base64: Some(binding.ml_dsa_65_pubkey_b64.clone()),
        algorithm: algorithm::HYBRID.into(),
        // CC 3.2 / CC 3.4.7.1: the responsible party is a `user`-role identity.
        identity_type: identity_type::USER.into(),
        identity_ref: binding.attesting_key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: reg_envelope,
        original_content_hash: hex::encode(Sha256::digest(&reg_canonical)),
        scrub_signature_classical: scrub_ed,
        scrub_signature_pqc: Some(scrub_pqc),
        scrub_key_id: binding.attesting_key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        // No Counter-RII consent role at registration (persist v13 #365):
        // None ⇔ the stored `unregistered` default; assigned later via
        // set_consent_role and excluded from the registration hash.
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    let signed = SignedKeyRecord { record };
    if via_gate.is_some() {
        // CC 4.2.2.1 (CIRISServer#159) — through the hardware-class chokepoint.
        crate::hardware_attestation::register_attested_federation_key(engine, signed)
            .await
            .map_err(|e| OwnershipError::Persist(e.to_string()))?;
    } else {
        // The direct-directory path skips persist's PoP gate, so it MUST NOT skip the
        // class gate too — that would be the one door left open (CC 4.2.2.1). This
        // row is server-built from the binding and carries no attestation_evidence,
        // so today the gate resolves to `SoftwareUnattested`; the call is here so a
        // future evidence-bearing binding cannot slip a class claim in unchecked.
        crate::hardware_attestation::admit_hardware_class(&signed.record, chrono::Utc::now())
            .map_err(|e| OwnershipError::Persist(e.to_string()))?;
        engine
            .federation_directory()
            .put_public_key(signed)
            .await
            .map_err(|e| OwnershipError::Persist(e.to_string()))?;
    }
    Ok(())
}

// ─── Emit the owner-binding (user → node, infra:*) — user-signed ─────────────

/// Emit the CC 3.2 owner-binding: a `delegates_to(responsible_user → node)`
/// attestation carrying ONLY `infra:*` scopes, **signed by the responsible
/// user's own key** (`user_signer`).
///
/// **Refuses to emit agency to a node.** [`scopes_are_infra_only`] is asserted
/// FIRST (via [`build_owner_binding_envelope`]); an `agency:*` (or legacy
/// agency) scope is rejected before any sign / persist.
///
/// ## v9.0.0 conformance — the attester MUST be the signer
///
/// persist v9.0.0's federation-tier ingest gate (CC 5.3.2.4.3.1) verifies the
/// row's hybrid signature against **`attesting_key_id`**'s registered pubkeys
/// (NOT `scrub_key_id`). An owner-binding's `attesting_key_id` is, by the CC 3.2
/// model, the responsible USER (the `delegates_to` granter the walk resolves), so
/// the row MUST be signed by the user's key. The pre-v9.0.0 "node-attested-on-
/// behalf" form (node signs, user claimed as attester) is now structurally
/// rejected by the gate — there is no conformant federation-tier owner-binding
/// without the user's own signature. `user_signer.key_id()` MUST therefore equal
/// `responsible_user_key_id`, and the user MUST be registered with this signer's
/// hybrid pubkeys. This is the same single-signer shape
/// [`build_signed_owner_binding`] / [`persist_user_signed_owner_binding`] use for
/// the 1-phase CLAIM; this entry point is for internal emit sites that hold the
/// user's `LocalSigner` directly.
pub async fn emit_steward_binding(
    engine: &Engine,
    user_signer: &LocalSigner,
    node_key_id: &str,
    infra_scopes: &[String],
) -> Result<String, OwnershipError> {
    let responsible_user_key_id = user_signer.key_id().to_string();

    // Through the ONE door (CIRISServer#402). This used to hand-roll a 21-field
    // row beside the envelope; see [`crate::attest`] for why every such site is
    // an instance of the same defect rather than a set of small ones.
    //
    // NOTE (DRY audit): `Engine::emit_attestation` is NOT a drop-in here. It
    // attributes the row to `signer.derived_key_id()`, whereas this flow passes a
    // USER signer whose `key_id()` is ALREADY the registered (derived) federation
    // id — so it would DOUBLE-derive (`<id>-<fp>-<fp>`) and the `attesting_key_id`
    // FK to `federation_keys` would fail. `crate::attest::emit` uses
    // `signer.key_id()` verbatim, which is the contract `register_user_key` /
    // `build_signed_owner_binding` / `is_steward_bound` key on end to end.
    let attestation_id = crate::attest::emit(
        engine,
        user_signer,
        crate::attest::Spec::new(
            attestation_type::DELEGATES_TO,
            cohort_scope::FEDERATION,
            build_owner_binding_envelope(&responsible_user_key_id, node_key_id, infra_scopes)?,
        )
        .about(node_key_id),
    )
    .await
    .map_err(|e| OwnershipError::Persist(e.to_string()))?;

    tracing::info!(
        responsible_user = %responsible_user_key_id,
        node_key_id = %node_key_id,
        attestation_id = %attestation_id,
        "emitted USER-SIGNED owner-binding delegates_to(user → node, infra:*)"
    );
    Ok(attestation_id)
}

/// **Emit a signed, federation-tier CEG attestation.** Canonicalize the envelope
/// (`ceg_produce_canonicalize`) → hybrid-sign with `signer` → build the
/// federation-tier [`Attestation`] row (attester == signer == `scrub_key_id`, the
/// shape the v9.0.0 ingest gate verifies against the signer's REGISTERED key) →
/// `put_attestation`. Returns the `attestation_id`.
///
/// NOTE (DRY audit): persist v13.2.0 exposes `Engine::emit_attestation(signer,
/// input)`, but it is NOT a drop-in here. It attributes the row to
/// `signer.derived_key_id()` (= `derive_key_id(signer.key_id(), pubkey)`); this
/// emit path is called with signers whose `key_id()` is ALREADY the registered
/// (derived) federation id, so the substrate primitive would DOUBLE-derive it and
/// the `attesting_key_id` FK would fail. `signer.key_id()` MUST be the signer's
/// registered (derived) key_id; the attester is bound to it verbatim.
pub async fn emit_signed_attestation(
    engine: &Engine,
    signer: &LocalSigner,
    attestation_type: &str,
    // ONE parameter, not two (CIRISServer#402). `attested_key_id` (what the
    // delegation walk joins on) and `subject_key_ids` (what lets that subject
    // revoke) used to be passed separately, and every one of the four callers
    // passed `vec![attested_key_id]` — two arguments for one fact, with a silent
    // failure mode if they ever drifted: a row conferring authority nobody can
    // withdraw. `Spec::about` sets both, so drifting is no longer expressible.
    subject_key_id: &str,
    envelope: serde_json::Value,
    // The edge's absolute expiry (CC 2.4.1.2 `delegation_valid_until`). `Some` makes
    // the attestation self-expiring: `steward_bindings_of` folds edge expiry, so a
    // lapsed delegation stops conferring authority WITHOUT a `withdraws` and survives
    // restarts (unlike the in-memory grant TTL). `None` = never expires (the prior
    // hardcoded behavior — correct for non-time-bounded rows like `scores`/`withdraws`).
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<String, OwnershipError> {
    // Through the ONE door (CIRISServer#402) — see [`crate::attest`]. The
    // `signer.key_id()` (not `derived_key_id()`) contract is the whole reason
    // this helper exists rather than `Engine::emit_attestation`; it is documented
    // above and carried by `crate::attest::emit`.
    crate::attest::emit(
        engine,
        signer,
        crate::attest::Spec::new(attestation_type, cohort_scope::FEDERATION, envelope)
            .expiring(expires_at)
            // `attested_key_id` and `subject_key_ids` are set together and to the
            // same key: the first is what the delegation walk joins on, the
            // second is what lets that subject later revoke.
            .about(subject_key_id),
    )
    .await
    .map_err(|e| OwnershipError::Persist(e.to_string()))
}

// ─── Read the owner-binding (is the node owned?) ────────────────────────────

/// Return the responsible user's `key_id` iff `node_key_id` is owner-bound — a
/// **LIVE, unrevoked** `delegates_to(user → node_key_id)` whose granter is a
/// registered `user`-role identity (CC 3.2: ownership roots in an accountable
/// human, never a bare node). Returns `None` for an UNOWNED node (the
/// serve-only floor applies).
///
/// ## Collapsed onto the substrate (CIRISPersist#249 Cut B)
///
/// This was a hand-rolled inbound-edge walk over `list_attestations_for` +
/// `lookup_public_key` + a local `delegation_revoked`. v9.3.0 exposes the
/// purpose-built reader [`Engine::steward_bindings_of`], which enumerates the
/// same three clauses our walk tested (own user-key / occurrence-of-a-user /
/// live `delegates_to(U → k)`), with edge expiry **and** the §11.10
/// `withdraws`/`recants` edge-retraction bucketing folded in. We return the
/// first anchor it yields.
///
/// ### Why dropping the read-time `infra:*` re-check is safe
///
/// Our hand-roll re-checked CC 1.13.5 (`scopes_are_infra_only`) at READ time so
/// an agency-bearing edge wouldn't confer ownership. That check is now
/// **redundant**: persist's CC 4.4.3.4.3 node-agency gate runs at WRITE time
/// (`put_attestation` rejects a non-`infra:*` `delegates_to` to a node-only
/// key), so any `delegates_to(U → node)` that EXISTS already carried only
/// `infra:*` scope. The write gate is the load-bearing one; re-deriving it on
/// every read was duplicate work. (`owner_of` also omits the granter
/// `valid_until` liveness check our walk did — edge expiry + retraction are the
/// canonical liveness signals in the §11.10 model.)
///
/// ## Single-owner `self` boundary (CIRISServer#162 / CIRISConstitution#23, persist v13)
///
/// persist v13 exposes [`admission::owner_of`] — the dimension-precise ownership
/// projection (owner-binding edges only, a subset of `steward_bindings_of`) that
/// resolves *the* single responsible owner (CC 1.13.3.3 / CC 3.2). We use it
/// instead of `steward_bindings_of(..).next()`: a node with **more than one**
/// distinct live owner returns [`Error::AmbiguousNodeOwner`], which we treat as
/// **fail-closed** (→ `None`, an unresolvable `self` boundary is not ownership)
/// rather than silently picking one off a sorted set. The single-owner admission
/// gate (`NodeAlreadyOwned`) makes the ambiguous state unreachable going forward;
/// this read is the fail-closed backstop for any legacy multi-owner row.
///
/// ## `revoked_after` (CIRISServer#355 / CIRISPersist#570 ask 4)
///
/// `owner_of` folds liveness, retraction, expiry and role — it does NOT fold
/// the revocation plane, and it cannot: it returns a bare granter key_id with
/// no row and no instant, so there is nothing left to date against a bound.
/// The bound is checked HERE, where the node's inbound edges are reachable, by
/// [`owner_binding_stands`].
pub async fn is_steward_bound(engine: &Engine, node_key_id: &str) -> Option<String> {
    use ciris_persist::federation::admission;
    let owner = match admission::owner_of(engine.federation_directory().as_ref(), node_key_id).await
    {
        Ok(owner) => owner?, // Some(owner) if owned, None if unowned
        Err(e) => {
            // Ambiguous / unresolvable single owner ⇒ no `self` boundary. Fail closed.
            tracing::warn!(
                node = %node_key_id,
                error = %e,
                "owner_of: unresolvable single owner — treating node as unowned (fail closed)"
            );
            return None;
        }
    };
    if owner_binding_stands(engine, node_key_id, &owner).await {
        Some(owner)
    } else {
        None
    }
}

/// Does the owner-binding that made `node_key_id` owned still stand, given the
/// revocations this node holds against `owner` (CIRISServer#355)?
///
/// # Why the cheap path comes first
///
/// `is_steward_bound` runs on every owner-gated request (`auth::gate`'s
/// `may_join_resolved` / `require_owner_bound`, the bootstrap, the memory API,
/// the mesh relay). A key with NO revocations against it — every key, on every
/// healthy node — costs exactly one targeted indexed lookup here and stops. The
/// second read (the node's inbound edges, to date the binding) happens only
/// once a revocation actually exists, which is the moment its cost is worth
/// paying.
///
/// # Fail-closed, in both of the two ways this can go wrong
///
/// A backend failure on either read ⇒ `false`. An owner that `owner_of`
/// resolved but whose owner-binding edge cannot be found ⇒ `false`: if the
/// binding cannot be DATED it cannot be shown to predate the bound, and
/// "unmeasurable" must not read as "fine" (the same choice
/// [`crate::key_standing::UNDATED_STATEMENT_AT`] makes one level down).
///
/// # Any surviving edge is enough
///
/// An owner may hold several live owner-binding rows (a refresh authors a new
/// one). The relation stands if ANY of them was signed at or before the bound —
/// the ownership was established before the compromise, and that is exactly the
/// case `revoked_after` exists to preserve.
async fn owner_binding_stands(engine: &Engine, node_key_id: &str, owner: &str) -> bool {
    use ciris_persist::federation::admission::is_owner_binding_envelope;
    use ciris_persist::federation::types::attestation_type;

    let held = match crate::key_standing::HeldRevocations::for_keys(engine, [owner.to_owned()])
        .await
    {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(
                node = %node_key_id,
                owner = %owner,
                error = %e,
                "revoked_after: could not read revocations for the owner — treating the node as \
                 unowned (fail closed)"
            );
            return false;
        }
    };
    if held.is_empty() {
        return true;
    }

    let rows = match engine
        .federation_directory()
        .list_attestations_for(node_key_id)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(
                node = %node_key_id,
                owner = %owner,
                error = %e,
                "revoked_after: the owner is revoked and this node's owner-binding edges could \
                 not be read to date it — treating the node as unowned (fail closed)"
            );
            return false;
        }
    };

    // `is_owner_binding_envelope` is persist's own predicate — the one
    // `owner_of` and the single-owner admission gate both key on. Re-deriving
    // "what an owner-binding IS" here would put this check and the resolver on
    // two definitions of one relation.
    let now = now_micros();
    let bindings: Vec<&Attestation> = rows
        .iter()
        .filter(|a| {
            a.attesting_key_id == owner
                && a.attestation_type == attestation_type::DELEGATES_TO
                && is_owner_binding_envelope(&a.attestation_envelope)
        })
        .collect();

    if bindings.is_empty() {
        tracing::warn!(
            node = %node_key_id,
            owner = %owner,
            "revoked_after: the owner is revoked and no owner-binding edge is readable to date \
             against the bound — treating the node as unowned (fail closed)"
        );
        return false;
    }

    if let Some(surviving) = bindings.iter().find(|a| !held.suspects(a, now)) {
        tracing::debug!(
            node = %node_key_id,
            owner = %owner,
            attestation_id = %surviving.attestation_id,
            "revoked_after: the owner's key is revoked, but this owner-binding was signed at or \
             before the history bound — ownership stands"
        );
        return true;
    }

    for a in &bindings {
        crate::key_standing::warn_suspect("auth::ownership", a, &held.statement_standing(a, now));
    }
    false
}

/// **CEG projection — "nodes owned by this fed ID".** The inverse of
/// [`is_steward_bound`]: every node key_id `owner_user_key_id` owner-binds. The
/// owner-bindings ARE the graph, so the list is a projection over them (no
/// client-side parallel store). By construction it returns the local node once
/// it has been self-claimed (the claim persists exactly that `delegates_to`).
///
/// ## Collapsed onto the substrate (CIRISPersist#249 Cut B)
///
/// persist exposes no "delegations BY a key" reader (only the inbound
/// [`Engine::delegations_to`] / [`Engine::steward_bindings_of`]), so we still scan
/// the user's OUTGOING `delegates_to` edges (`list_attestations_by`) to find
/// candidate recipients — but the liveness / revocation / user-role / infra
/// logic is no longer hand-walked: each candidate is **confirmed** through
/// [`Engine::steward_bindings_of`] (which folds all of that in). The recipient is
/// the edge's `attested_key_id` — persist's canonical recipient field, which the
/// §11.10 retraction bucketing and `steward_bindings_of` both key on — NOT an
/// `envelope["node_key_id"]` field (so this stays correct under either the
/// hand-rolled or the `owner_bind` `delegates_to` envelope shape).
pub async fn nodes_stewarded_by(engine: &Engine, steward_user_key_id: &str) -> Vec<String> {
    // CIRISPersist#299: persist 11 exposes the outbound steward-binding reader as a
    // first-class substrate call — "list the nodes I steward" is now ONE read with
    // read-after-write correctness owned by persist, not a hand-rolled edge scan.
    engine
        .nodes_stewarded_by(steward_user_key_id)
        .await
        .unwrap_or_default()
        .into_iter()
        // persist 11's reader includes the steward's own identity (a user is
        // is_steward_bound — self-sovereign); a steward does not *steward
        // themselves*, so exclude self from the "wards I steward" projection
        // that drives the node switcher.
        .filter(|k| k != steward_user_key_id)
        .collect()
}

// ─── Promote the owner-binding self → FEDERATION (CIRISServer#125 opt-in) ─────

/// The outcome of [`promote_owner_binding_to_federation`].
#[derive(Debug, Clone)]
pub struct PromotedOwnerBinding {
    /// The responsible owner whose binding is now (or already was) federation-scoped.
    pub responsible_user_key_id: String,
    /// The newly-persisted FEDERATION-cohort owner-binding attestation id, or `None`
    /// when a federation-cohort binding already existed (idempotent no-op).
    pub attestation_id: Option<String>,
}

/// **Promote this node's owner-binding self → FEDERATION (CIRISServer#125 — the
/// "announce yourself to the federation" opt-in).**
///
/// The default owner-binding is persisted `cohort_scope: self` (full self/family +
/// local node-admin use, structurally invisible to the federation). Announcing to
/// the federation is the owner's explicit opt-in; it WIDENS the responsible-party
/// owner-binding to `cohort_scope: federation` (public accountability) so the node
/// counts as a federation participant.
///
/// ## Mechanism — re-persist the PROVEN envelope at the wider cohort
///
/// `cohort_scope` is NOT part of the user-signed envelope
/// ([`build_owner_binding_envelope`]) — it is pure persisted-row metadata. So this
/// re-persists the EXISTING binding's envelope and the owner's ORIGINAL hybrid
/// signatures under `cohort_scope: federation`. The federation-tier ingest gate
/// (`verify_federation_tier_ingest`) re-derives the canonical bytes from the
/// (unchanged) envelope, cross-checks the (unchanged) `original_content_hash`, and
/// Strict-re-verifies the owner's hybrid signature against the owner's REGISTERED
/// pubkeys — so the SAME already-proven signature admits at the wider scope. No
/// fresh signing, no user signer needed.
///
/// # Why this needs the owner's signer (CIRISPersist#643)
///
/// It did not use to. The promote re-persisted the owner's EXISTING envelope and
/// their original signatures under a wider `cohort_scope`, on the reasoning that
/// the cohort was pure row metadata outside the signed bytes — so the already-
/// proven signature re-verified and no user signer was needed.
///
/// That reasoning was the defect, and persist v31 removed its premise.
/// `cohort_scope` is now inside the signed typed-column mirror, which means the
/// old promote is not merely refused, it is INCOHERENT: it asked the owner's
/// signature to vouch for an audience the owner never stated. A node could widen
/// its owner's ownership claim from `self` to the whole federation without the
/// owner's key being present, and the resulting row carried the owner's signature
/// while saying something the owner had not signed.
///
/// So promotion is now what it always should have been: **the owner making a
/// wider claim**, signed at the moment they make it. The signer must be the
/// SAME owner already bound — a node that can reach *a* signer must not be able
/// to promote with it.
///
/// Idempotent: a no-op (returns `attestation_id: None`) when a federation-cohort
/// owner-binding for (owner → node) already exists. Errors if the node is not yet
/// owner-bound (you cannot announce an ownership you do not hold).
pub async fn promote_owner_binding_to_federation(
    engine: &Engine,
    owner_signer: &LocalSigner,
    node_key_id: &str,
) -> Result<PromotedOwnerBinding, OwnershipError> {
    // The node MUST already be owned — `is_steward_bound` resolves the responsible
    // owner. (You cannot announce an ownership you do not hold.)
    let owner = is_steward_bound(engine, node_key_id).await.ok_or_else(|| {
        OwnershipError::Validation(
            "node is not owner-bound — claim ownership before announcing it to the federation"
                .into(),
        )
    })?;

    // …and the key doing the promoting MUST be that owner's. Widening the
    // audience of an ownership claim is the claimant's act; a different signer
    // making it is a third party publishing someone else's claim.
    if owner_signer.key_id() != owner {
        return Err(OwnershipError::Validation(format!(
            "promote refused: this node is owner-bound to {owner}, but the promotion would be \
             signed by {}. Widening the audience of an ownership claim is the OWNER's act — \
             CIRISPersist#643 puts `cohort_scope` inside the signed bytes precisely so a node \
             cannot publish its owner's claim more widely than the owner stated",
            owner_signer.key_id(),
        )));
    }

    // Read this node's inbound owner-binding edges (federation tier). The
    // responsible-party binding is the live `delegates_to(owner → node)` with the
    // owner-binding purpose.
    let rows = engine
        .federation_directory()
        .list_attestations_for(node_key_id)
        .await
        .map_err(|e| OwnershipError::Persist(e.to_string()))?;

    let is_owner_binding = |a: &Attestation| -> bool {
        a.attestation_type == attestation_type::DELEGATES_TO
            && a.attesting_key_id == owner
            && a.attestation_envelope
                .get("delegation_purpose")
                .and_then(|v| v.as_str())
                == Some(OWNER_BINDING_PURPOSE)
    };

    // Idempotent: already federation-scoped ⇒ nothing to widen.
    if rows
        .iter()
        .any(|a| is_owner_binding(a) && a.cohort_scope == cohort_scope::FEDERATION)
    {
        tracing::info!(
            responsible_user = %owner,
            node_key_id = %node_key_id,
            "promote owner-binding: already federation-scoped (idempotent no-op)"
        );
        return Ok(PromotedOwnerBinding {
            responsible_user_key_id: owner,
            attestation_id: None,
        });
    }

    // The narrower binding whose scopes the wider claim carries forward. Read the
    // scope set off the ROW rather than re-deriving it from the constant: the
    // promotion must say what the owner already said, at a wider audience, and
    // nothing more.
    let existing = rows.iter().find(|a| is_owner_binding(a)).ok_or_else(|| {
        OwnershipError::Validation(
            "no responsible-party owner-binding found on this node to promote".into(),
        )
    })?;
    let infra_scopes = scope_set_of(&existing.attestation_envelope);

    // A NEW binding, freshly signed by the owner at the wider cohort. The old one
    // is left in place: it is a true statement about a narrower audience, and
    // `is_steward_bound` folds both.
    let attestation_id =
        emit_steward_binding(engine, owner_signer, node_key_id, &infra_scopes).await?;

    tracing::info!(
        responsible_user = %owner,
        node_key_id = %node_key_id,
        attestation_id = %attestation_id,
        "promoted owner-binding to cohort_scope=federation (owner re-signed at the wider audience)"
    );
    Ok(PromotedOwnerBinding {
        responsible_user_key_id: owner,
        attestation_id: Some(attestation_id),
    })
}

/// Errors [`emit_steward_binding`] can surface.
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
    /// The supplied owner-binding failed structural validation (wrong node,
    /// purpose, mismatched attesting key, …).
    Validation(String),
    /// The user's hybrid signature over the owner-binding canonical bytes did
    /// not verify against the supplied pubkeys.
    Verify(String),
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
            OwnershipError::Validation(e) => write!(f, "owner-binding validation: {e}"),
            OwnershipError::Verify(e) => write!(f, "owner-binding signature verify: {e}"),
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
            INFRA_HOLD_COMMUNITY_MEMBERSHIP.to_string(),
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
        // Now composes persist's `identity_type::set_contains` (CEG §7.0.1),
        // which is the COMMA-joined set form — the substrate canon. A single
        // token and a comma-joined set both resolve; whitespace is NOT a set
        // delimiter (that was our pre-alignment over-permissive parse).
        assert!(identity_type_contains("user", "user"));
        assert!(identity_type_contains("user,wise_authority", "user"));
        assert!(identity_type_contains(
            "user,wise_authority",
            "wise_authority"
        ));
        assert!(!identity_type_contains("node", "user"));
        assert!(!identity_type_contains("steward", "user"));
    }
}
