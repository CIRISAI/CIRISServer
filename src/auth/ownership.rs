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
//! The legacy node-attested [`emit_owner_binding`] is retained for internal
//! emit sites with no user signature available; the CLAIM path no longer uses it.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_persist::federation::types::{
    algorithm, attestation_tier, attestation_type, identity_type, Attestation, KeyRecord,
    SignedAttestation, SignedKeyRecord,
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
/// `put_attestation` does NOT re-verify the scrub signature against the
/// directory, but it DOES require `attesting_key_id` (the user) to be a
/// registered `federation_keys` row — so the user MUST be registered before this
/// call (phase 1 registers them). Returns the persisted attestation id.
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

    let attestation_id = new_uuid_v4();
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

// ─── Emit the owner-binding (user → node, infra:*) — legacy node-attested ────

/// Emit the CC 3.2 owner-binding: a `delegates_to(responsible_user → node)`
/// attestation carrying ONLY `infra:*` scopes, **node-attested-on-behalf** of
/// the user (the node engine signs the bytes).
///
/// **Refuses to emit agency to a node.** [`scopes_are_infra_only`] is asserted
/// FIRST (via [`build_owner_binding_envelope`]); an `agency:*` (or legacy
/// agency) scope is rejected before any sign / persist.
///
/// ## Legacy / internal-only — the CLAIM path no longer uses this
///
/// This is the node-attested-on-behalf form: the bytes are hybrid-signed by the
/// *node's* engine signer, so `scrub_key_id` is the node's key. The substrate
/// `put_attestation` does NOT re-verify the scrub signature, so this is accepted,
/// but the binding is NOT user-self-signed. The first-run CLAIM now produces a
/// GENUINELY USER-SIGNED binding via the 2-phase
/// `POST /v1/setup/root` (begin) + `/finalize` flow
/// ([`persist_user_signed_owner_binding`]). This function is retained for
/// internal/non-claim emit sites that have no user signature available.
pub async fn emit_owner_binding(
    engine: &Engine,
    responsible_user_key_id: &str,
    node_key_id: &str,
    infra_scopes: &[String],
) -> Result<String, OwnershipError> {
    let now = chrono::Utc::now();
    let envelope = build_owner_binding_envelope(
        responsible_user_key_id,
        node_key_id,
        infra_scopes,
        &now.to_rfc3339(),
    )?;

    let canonical = canonicalize_owner_binding_envelope(&envelope)?;
    let original_content_hash = hex::encode(Sha256::digest(&canonical));

    // Hybrid-sign over the canonical bytes (node engine signer — legacy
    // node-attested-on-behalf; scrub_key_id is the node's key).
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .map_err(|e| OwnershipError::Sign(e.to_string()))?;

    let attestation_id = new_uuid_v4();
    let attestation = Attestation {
        attestation_id: attestation_id.clone(),
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
        // Honest: the node engine produced the bytes (legacy on-behalf form).
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
        "emitted (legacy node-attested) owner-binding delegates_to(user → node, infra:*)"
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
