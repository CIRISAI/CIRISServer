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
//! - [`is_owner_bound`] returns the granter `key_id` (callers bind ROOT to the
//!   responsible user) AND requires the owner-binding edge to be `infra:*`-only
//!   (the CC 1.13.5 read-time gate). persist's general
//!   `federation::admission::is_owner_bound` is scope-agnostic and returns only
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
//!   `key_id` + signatures. [`is_owner_bound`] then reads a USER-signed edge.
//!
//! [`emit_owner_binding`] is the one-shot user-signed emit (it takes the user's
//! `LocalSigner` directly: attester == signer, the v9.0.0-conformant shape) for
//! internal emit sites that already hold the user's signer; the CLAIM path uses
//! the 1-phase [`build_signed_owner_binding`] / [`apply_signed_owner_binding`].

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_persist::federation::types::{
    algorithm, attestation_tier, attestation_type, cohort_scope, identity_type, Attestation,
    KeyRecord, SignedAttestation, SignedKeyRecord,
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
/// substrate's [`Engine::owner_bindings_of`] (#249 Cut B).
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
/// scope-set, asserted_at).
///
/// `asserted_at` is threaded IN as an explicit RFC-3339 string so the same
/// envelope (and therefore the same canonical bytes) can be rebuilt/echoed
/// across the 2-phase claim: phase 1 stamps `asserted_at = now`, returns the
/// envelope + its canonical bytes; phase 2 re-canonicalizes the SAME envelope
/// the client echoed back (no fresh timestamp) so the bytes match what the user
/// signed.
///
/// The `scope` array is the shape the substrate delegation walk's
/// scope-containment predicate reads; `attesting_key_id` is the user (so the
/// walk resolves the user → node edge); `attested_key_id` is the node.
pub fn build_owner_binding_envelope(
    responsible_user_key_id: &str,
    node_key_id: &str,
    infra_scopes: &[String],
    asserted_at_rfc3339: &str,
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
        "dimension": DIMENSION_OWNER_BINDING,
        "attesting_key_id": responsible_user_key_id,
        "node_key_id": node_key_id,
        "delegation_purpose": OWNER_BINDING_PURPOSE,
        "scope": scopes,
        "asserted_at": asserted_at_rfc3339,
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
/// GENUINELY USER-SIGNED ([`is_owner_bound`] then reads a user-signed edge).
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
#[allow(clippy::too_many_arguments)]
pub async fn persist_user_signed_owner_binding(
    engine: &Engine,
    envelope: serde_json::Value,
    responsible_user_key_id: &str,
    node_key_id: &str,
    canonical: &[u8],
    user_ed25519_sig_b64: &str,
    user_ml_dsa_65_sig_b64: &str,
) -> Result<String, OwnershipError> {
    let now = chrono::Utc::now();
    let original_content_hash = hex::encode(Sha256::digest(canonical));

    let attestation_id = crate::ids::new_id();
    let attestation = Attestation {
        attestation_id: attestation_id.clone(),
        // Issuer = the responsible user (the delegation walk resolves the
        // user → node edge via list_attestations_by(user) / _for(node)).
        attesting_key_id: responsible_user_key_id.to_owned(),
        attested_key_id: node_key_id.to_owned(),
        attestation_type: attestation_type::DELEGATES_TO.to_owned(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash,
        // GENUINELY USER-SIGNED: the responsible party's OWN hybrid signatures
        // over the canonical bytes, with scrub_key_id = the user's key. The
        // owner-binding now cryptographically asserts the user's own ownership.
        scrub_signature_classical: user_ed25519_sig_b64.to_owned(),
        scrub_signature_pqc: Some(user_ml_dsa_65_sig_b64.to_owned()),
        scrub_key_id: responsible_user_key_id.to_owned(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: vec![node_key_id.to_owned()],
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_owned(),
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
pub async fn build_signed_owner_binding(
    user_signer: &LocalSigner,
    node_key_id: &str,
    infra_scopes: &[String],
) -> Result<SignedOwnerBinding, OwnershipError> {
    let user_key_id = user_signer.key_id().to_string();
    let now = chrono::Utc::now();
    let envelope =
        build_owner_binding_envelope(&user_key_id, node_key_id, infra_scopes, &now.to_rfc3339())?;
    let canonical = canonicalize_owner_binding_envelope(&envelope)?;

    // HYBRID-sign the canonical bytes with the USER's signer (the responsible
    // party's key) — the substrate produces both halves + carries both pubkeys.
    let sig = user_signer
        .sign_hybrid(&canonical)
        .await
        .map_err(|e| OwnershipError::Sign(e.to_string()))?;

    Ok(SignedOwnerBinding {
        envelope,
        attesting_key_id: user_key_id,
        ed25519_pubkey_b64: B64.encode(&sig.classical.public_key),
        ml_dsa_65_pubkey_b64: B64.encode(&sig.pqc.public_key),
        ed25519_sig_b64: B64.encode(&sig.classical.signature),
        ml_dsa_65_sig_b64: B64.encode(&sig.pqc.signature),
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
/// [`is_owner_bound`]'s granter-is-user check resolves).
pub async fn apply_signed_owner_binding(
    engine: &Engine,
    this_node_key_id: &str,
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
        &canonical,
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

    let now = chrono::Utc::now();
    let reg_envelope = serde_json::json!({ "key_id": binding.attesting_key_id });
    let reg_canonical = canonicalize_owner_binding_envelope(&reg_envelope)?;
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
        // The user's owner-binding signatures (over the binding canonical bytes),
        // recorded as scrub material for row-shape completeness. PoP was verified
        // by apply_signed_owner_binding over those same bytes.
        scrub_signature_classical: binding.ed25519_sig_b64.clone(),
        scrub_signature_pqc: Some(binding.ml_dsa_65_sig_b64.clone()),
        scrub_key_id: binding.attesting_key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .map_err(|e| OwnershipError::Persist(e.to_string()))?;
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
pub async fn emit_owner_binding(
    engine: &Engine,
    user_signer: &LocalSigner,
    node_key_id: &str,
    infra_scopes: &[String],
) -> Result<String, OwnershipError> {
    let responsible_user_key_id = user_signer.key_id().to_string();
    let now = chrono::Utc::now();
    let envelope = build_owner_binding_envelope(
        &responsible_user_key_id,
        node_key_id,
        infra_scopes,
        &now.to_rfc3339(),
    )?;

    let canonical = canonicalize_owner_binding_envelope(&envelope)?;
    let original_content_hash = hex::encode(Sha256::digest(&canonical));

    // Hybrid-sign over the canonical bytes with the USER's signer — attester ==
    // signer == scrub_key_id (the v9.0.0 federation-tier ingest gate verifies the
    // row against `attesting_key_id`'s registered pubkeys).
    let sig = user_signer
        .sign_hybrid(&canonical)
        .await
        .map_err(|e| OwnershipError::Sign(e.to_string()))?;

    let attestation_id = crate::ids::new_id();
    let attestation = Attestation {
        attestation_id: attestation_id.clone(),
        attesting_key_id: responsible_user_key_id.clone(),
        attested_key_id: node_key_id.to_owned(),
        attestation_type: attestation_type::DELEGATES_TO.to_owned(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash,
        scrub_signature_classical: B64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
        // The responsible user produced the bytes (attester == signer).
        scrub_key_id: responsible_user_key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: vec![node_key_id.to_owned()],
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_owned(),
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
        "emitted USER-SIGNED owner-binding delegates_to(user → node, infra:*)"
    );
    Ok(attestation_id)
}

/// **Emit a signed, federation-tier CEG attestation.** The ciris-server local
/// stand-in for [CIRISPersist#248] (until persist exposes a first-class
/// `Engine::emit_attestation`): canonicalize the envelope
/// (`ceg_produce_canonicalize`) → hybrid-sign with `signer` → build the
/// federation-tier [`Attestation`] row (attester == signer == `scrub_key_id`, the
/// shape the v9.0.0 ingest gate verifies against the signer's REGISTERED key) →
/// `put_attestation`. Returns the `attestation_id`.
///
/// This is the WORKING federation-emit path (the one `emit_owner_binding` uses and
/// that reads back) — it deliberately does NOT go through `attestation_promote`,
/// which is currently broken on real nodes ([CIRISPersist#247]: promote writes
/// `scrub_key_id = signer.current_alias()`, not the derived federation key_id → FK
/// violation). `signer.key_id()` MUST be the signer's registered (derived) key_id.
pub async fn emit_signed_attestation(
    engine: &Engine,
    signer: &LocalSigner,
    attestation_type: &str,
    attested_key_id: &str,
    envelope: serde_json::Value,
    subject_key_ids: Vec<String>,
) -> Result<String, OwnershipError> {
    let attester = signer.key_id().to_string();
    let now = chrono::Utc::now();
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .map_err(|e| OwnershipError::Canonicalize(e.to_string()))?;
    let original_content_hash = hex::encode(Sha256::digest(&canonical));
    let sig = signer
        .sign_hybrid(&canonical)
        .await
        .map_err(|e| OwnershipError::Sign(e.to_string()))?;
    let attestation_id = crate::ids::new_id();
    let attestation = Attestation {
        attestation_id: attestation_id.clone(),
        attesting_key_id: attester.clone(),
        attested_key_id: attested_key_id.to_owned(),
        attestation_type: attestation_type.to_owned(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash,
        scrub_signature_classical: B64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
        scrub_key_id: attester.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids,
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_owned(),
        tier: attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
    };
    engine
        .federation_directory()
        .put_attestation(SignedAttestation { attestation })
        .await
        .map_err(|e| OwnershipError::Persist(e.to_string()))?;
    Ok(attestation_id)
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
/// purpose-built reader [`Engine::owner_bindings_of`], which enumerates the
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
/// every read was duplicate work. (`owner_bindings_of` also omits the granter
/// `valid_until` liveness check our walk did — edge expiry + retraction are the
/// canonical liveness signals in the §11.10 model.)
pub async fn is_owner_bound(engine: &Engine, node_key_id: &str) -> Option<String> {
    engine
        .owner_bindings_of(node_key_id)
        .await
        .ok()
        .and_then(|owners| owners.into_iter().next())
}

/// **CEG projection — "nodes owned by this fed ID".** The inverse of
/// [`is_owner_bound`]: every node key_id `owner_user_key_id` owner-binds. The
/// owner-bindings ARE the graph, so the list is a projection over them (no
/// client-side parallel store). By construction it returns the local node once
/// it has been self-claimed (the claim persists exactly that `delegates_to`).
///
/// ## Collapsed onto the substrate (CIRISPersist#249 Cut B)
///
/// persist exposes no "delegations BY a key" reader (only the inbound
/// [`Engine::delegations_to`] / [`Engine::owner_bindings_of`]), so we still scan
/// the user's OUTGOING `delegates_to` edges (`list_attestations_by`) to find
/// candidate recipients — but the liveness / revocation / user-role / infra
/// logic is no longer hand-walked: each candidate is **confirmed** through
/// [`Engine::owner_bindings_of`] (which folds all of that in). The recipient is
/// the edge's `attested_key_id` — persist's canonical recipient field, which the
/// §11.10 retraction bucketing and `owner_bindings_of` both key on — NOT an
/// `envelope["node_key_id"]` field (so this stays correct under either the
/// hand-rolled or the `owner_bind` `delegates_to` envelope shape).
pub async fn nodes_owned_by(engine: &Engine, owner_user_key_id: &str) -> Vec<String> {
    let directory = engine.federation_directory();
    let Ok(rows) = directory.list_attestations_by(owner_user_key_id).await else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for edge in rows {
        if edge.attestation_type != attestation_type::DELEGATES_TO {
            continue;
        }
        let node = edge.attested_key_id;
        if node.is_empty() || out.iter().any(|n| n == &node) {
            continue;
        }
        // Confirm via the substrate reader: liveness + withdraws/recants
        // retraction + the granter being a live user-role anchor.
        if let Ok(owners) = engine.owner_bindings_of(&node).await {
            if owners.iter().any(|o| o == owner_user_key_id) {
                out.push(node);
            }
        }
    }
    out
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
