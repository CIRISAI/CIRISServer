//! Directed-consent federation peering (CIRISServer federation Round 2).
//!
//! Node A is a member of the canonical CIRIS infrastructure community; Node B
//! (`ciris-status`) is **out** of that group. Bidirectional replication A<->B is
//! therefore authorized NOT by in-group trust but by **directed consent
//! attestations** at federation scope, plus **mutual key registration** as the
//! admission door. This module owns Node A's side of that contract:
//!
//!   1. [`register_peer_key`] — register B's published hybrid pubkeys in A's
//!      `federation_keys` (identity_type `"witness"`), so B's replicated
//!      `health:liveness:*` attestations are admitted (`put_attestation`
//!      requires the attesting key to exist as a `federation_keys` row).
//!   2. [`emit_replication_consent`] — emit a directed `consent:replication:v1`
//!      `scores` attestation (subject = [B's key_id]) recording "A consents to
//!      replicate `capacity:*` to B." This is the auditable consent object;
//!      revocation rides the CEG withdraws/recants structural primitive later.
//!
//! Both are modeled on `compose::register_self_key` (key registration; benign
//! Conflict) and `scorer.rs` / CIRISStatus `ceg.rs::emit_liveness` (the
//! canonicalize → hybrid-sign → `put_attestation` emit recipe). The shared wire
//! contract (Node B builds the mirror side to the SAME shapes) fixes:
//! `consent:replication:v1`, a directed `scores` attestation, `cohort_scope =
//! "federation"`, FEDERATION tier, hybrid-signed by the granting node's steward
//! key, payload recording the grant intent.

use anyhow::Result;
use sha2::{Digest, Sha256};

use ciris_persist::federation::consent_grammar::RestrictionOp;
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::types::{attestation_type, cohort_scope, identity_type};
use ciris_persist::federation::{EmitAttestationInput, Error as FederationError};
use ciris_persist::prelude::Engine;
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

use crate::config::PeerB;

/// The directed-consent dimension the A<->B replication grant rides on.
/// **Versioned** (`:v1`) to satisfy persist's
/// `DimensionAdmissionPolicy { require_version_segment: true }`. Open-vocab
/// (`consent:` is NOT a reserved prefix), so a steward-keyed attestation on it
/// is admitted without a reserved-prefix role.
pub const CONSENT_DIMENSION: &str = "consent:replication:v1";

/// What A consents to replicate to B by **default** (boot-env peering, when the
/// caller supplies no explicit set) — the `capacity:*` attestation family A
/// produces (the scorer's `capacity:sustained_coherence:v1` and any future
/// `capacity:*` leaves). The grant payload carries these as the JCS array of
/// namespace-prefix strings (trailing ":" significant), **sorted ascending +
/// deduplicated** (see [`normalize_prefixes`]) so consumers agree byte-for-byte.
pub const DEFAULT_GRANT_ATTESTATION_PREFIXES: &[&str] = &["capacity:"];

/// `consent:replication` payload `subject_kind` (CEG 1.0-RC29 §4.2.2.3): a
/// payload member (NOT an envelope field) declaring the grant's subject shape.
const SUBJECT_KIND_CONSENT_REPLICATION: &str = "consent_replication";

/// The outcome of [`emit_replication_consent`]: which grant row now exists for
/// the directed (this node → peer) `consent:replication:v1` consent, and whether
/// THIS call wrote it (`freshly_emitted == true`) or found a durable existing
/// grant (idempotent no-op, `freshly_emitted == false`). `attestation_id` /
/// `content_hash` identify the grant either way, so an owner-authority caller can
/// echo the same handle on a repeat POST.
#[derive(Debug, Clone)]
pub struct ConsentGrant {
    /// The grant row's `attestation_id`.
    pub attestation_id: String,
    /// The grant envelope's `original_content_hash` (the integrity anchor).
    pub content_hash: String,
    /// `true` when this call wrote a fresh grant; `false` on an idempotent no-op.
    pub freshly_emitted: bool,
}

/// The owner-chosen policy dimensions of a `consent:replication:v1` grant BEYOND
/// the covered prefixes — the contextual-integrity tuple fields persist's closed
/// consent grammar ([`ciris_persist::federation::consent_grammar::ConsentTransferPolicy`],
/// validated by `parse_grant_payload`) accepts. Boot / default callers use
/// [`ConsentGrantOptions::default`] (audience = `federation`, no expiry, no
/// restrictions); the owner-gated `POST /v1/federation/consent` route fills these
/// from the operator's request so an owner can narrow the recipient cohort, time-box
/// the grant, or attach `strip_field` / `recipient_capability` restrictions
/// (CIRISServer#327 §2 / #510 P2).
#[derive(Debug, Clone, Default)]
pub struct ConsentGrantOptions {
    /// The recipient cohort — one of the 7 closed
    /// [`cohort_scope`](ciris_persist::federation::types::cohort_scope) values.
    /// `None` ⇒ persist's `default_audience()` (`federation`). A supplied value
    /// is validated against the closed set at the producer (fail-closed) so a bad
    /// token never reaches persist admission.
    pub audience: Option<String>,
    /// The grant's payload-declared expiry (distinct from the row's `expires_at`
    /// column). `None` ⇒ no payload-declared expiry.
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Restrictions applied to the covered flow — typed through persist's OWN
    /// closed [`RestrictionOp`] enum, so an unknown `op` cannot be authored (edge
    /// honors these at serve; persist applies `StripField` at promotion).
    pub restrictions: Vec<RestrictionOp>,
}

/// Normalize a caller-supplied (or default) prefix set into the byte-for-byte
/// form that goes into the grant payload so every consumer (and B's mirror)
/// agrees on the JCS array: trimmed, empty-dropped, **sorted ascending +
/// deduplicated**. The owner (via `POST /v1/federation/peering`) or the boot-env
/// path both flow their prefix set through here so the on-wire shape is identical
/// regardless of who authored the grant.
///
/// **Narrowing note (RC29 §5.6.8.15):** partial narrowing of the prefix set MUST
/// go via a `supersedes` attestation carrying a *narrower* set — never a silent
/// drop. Not implemented here; this helper deliberately does not preclude it.
pub fn normalize_prefixes<S: AsRef<str>>(prefixes: &[S]) -> Vec<String> {
    let mut v: Vec<String> = prefixes
        .iter()
        .map(|s| s.as_ref().trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// The default prefix set as owned strings (boot-env peering convenience).
pub fn default_attestation_prefixes() -> Vec<String> {
    normalize_prefixes(DEFAULT_GRANT_ATTESTATION_PREFIXES)
}

/// Register Node B's *self-signed* `SignedKeyRecord` in A's federation directory
/// through the **single canonical admission gate** —
/// `Engine::register_federation_key` (persist v8.8.0, CIRISPersist#234,
/// CEG 1.0-RC29 §5.6.8.15) — the ADMISSION mechanism for directed-consent
/// replication. Until B's key is a verified `federation_keys` row, A's
/// `put_attestation` rejects any B-attested `health:liveness:*` row B replicates
/// in (`InvalidArgument`: attesting_key_id does not exist).
///
/// **v8.8.0 fail-secure shape:** the gate REQUIRES B's *self-signed* record
/// (proof-of-possession) — A can no longer mint B's row from raw pubkeys. A
/// hands B's exported `SignedKeyRecord` ([`PeerB::key_record`], supplied via
/// `CIRIS_PEER_B_KEY_RECORD`) straight to `register_federation_key`, which
/// `verify_key_registration`s B's hybrid signature (Ed25519+ML-DSA-65, Strict,
/// over `ceg_produce_canonicalize(registration_envelope)` against B's own
/// pubkeys, `scrub_key_id == key_id`) BEFORE any store. An unverifiable/forged
/// peer record is rejected and never stored — the security check is the
/// signature, not A's say-so.
///
/// Idempotent: a row that already matches returns `Ok(())`; a `Conflict` (a
/// *differing* row already holds B's key_id) is benign (logged at debug) — we
/// must not fail boot over a directory race, and B's stable published identity
/// should never legitimately conflict.
pub async fn register_peer_key(engine: &Engine, peer: &PeerB) -> Result<()> {
    // Safe-mesh floor (B1): an `accord_holder` identity — a kill-switch SEAT — may be
    // admitted ONLY through the custody-gated `POST /v1/accord/holder` (which mandates
    // a verified FIPS YubiKey custody attestation). This generic peer-key route does
    // NOT verify custody, so it must REFUSE accord_holder records — otherwise an owner
    // could seat a non-FIPS kill-switch holder via the side door.
    if peer.key_record.record.identity_type == identity_type::ACCORD_HOLDER {
        return Err(anyhow::anyhow!(
            "refusing to register an accord_holder key via the peering route — accord holders \
             must be admitted through the custody-gated POST /v1/accord/holder"
        ));
    }
    // CC 4.2.2.1 (CIRISServer#159): the peering route is the classic unchecked-
    // self-report surface — a peer hands us its own record, hardware_class and all.
    // `register_attested_federation_key` proves any hardware-class claim (chain to a
    // pinned root + bound to THIS record's key) before persist's PoP gate stores it.
    match crate::hardware_attestation::register_attested_federation_key(
        engine,
        peer.key_record.clone(),
    )
    .await
    {
        Ok(()) => {
            tracing::info!(
                peer_key_id = %peer.key_id,
                identity_type = %peer.key_record.record.identity_type,
                "registered Node B's self-signed key via register_federation_key \
                 (fail-secure admission gate; directed-consent replication admission)"
            );
            Ok(())
        }
        Err(FederationError::Conflict(msg)) => {
            tracing::debug!(
                peer_key_id = %peer.key_id,
                conflict = %msg,
                "peer-key registration is a benign conflict (key already present) — continuing"
            );
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!(
            "register Node B federation key (fail-secure verify): {e}"
        )),
    }
}

/// Boot / default / test entry (backward-compatible 4-arg form): author the
/// directed `consent:replication:v1` grant with DEFAULT policy
/// ([`ConsentGrantOptions::default`] — audience `federation`, no payload expiry,
/// no restrictions). The full closed-grammar payload and the non-vacuous-prefix
/// guard still apply — those are producer invariants, not owner options. The
/// owner-gated consent route uses [`emit_replication_consent_with_policy`] to
/// carry an owner-chosen policy.
pub async fn emit_replication_consent<S: AsRef<str>>(
    engine: &Engine,
    node_key_id: &str,
    peer_key_id: &str,
    attestation_prefixes: &[S],
) -> Result<ConsentGrant> {
    emit_replication_consent_with_policy(
        engine,
        node_key_id,
        peer_key_id,
        attestation_prefixes,
        &ConsentGrantOptions::default(),
    )
    .await
}

/// Emit Node A's directed `consent:replication:v1` attestation at Node B:
/// "A consents to replicate `capacity:*` to B." A directed `scores` attestation,
/// `subject_key_ids = [B]`, `cohort_scope = "federation"`, FEDERATION tier,
/// hybrid-signed by A's steward key (`node_key_id`).
///
/// **Idempotent**: if A has already emitted a `consent:replication:v1` row
/// directed at this peer (the grant is durable, not per-boot), this is a no-op
/// returning the existing grant's handle with `freshly_emitted == false` —
/// `scores` rows are NOT collapsed by dimension on the federation tier (each
/// `put_attestation` mints a fresh `attestation_id`), so we guard the emit with a
/// directory lookup rather than blindly re-emitting. Returns a [`ConsentGrant`]
/// with `freshly_emitted == true` when a fresh grant row was written.
///
/// Revocation (not built here, per the contract) rides the CEG
/// withdraws/recants structural primitive targeting this grant's
/// `attestation_id` — the same mechanism CIRISAgent's `build_community_structural`
/// uses for the community-trust grant.
///
/// `attestation_prefixes` is the caller-supplied namespace-prefix set this node
/// consents to replicate to the peer (trailing ":" significant). It is
/// [`normalize_prefixes`]d (trimmed / empty-dropped / sorted-ascending / deduped)
/// before it lands in the grant payload, so the on-wire JCS array is byte-for-byte
/// agreed regardless of caller input order. The boot-env path passes
/// [`default_attestation_prefixes`]; the owner-authority `POST /v1/federation/peering`
/// path passes the operator's set. A **vacuous** (empty-after-normalize) set is
/// REFUSED here — persist's `parse_grant_payload` rejects an empty-STRING entry
/// but NOT an empty ARRAY, and a grant that `covers()` nothing is a governance
/// object that looks authoritative and grants nothing (CIRISServer#327 §2's
/// non-vacuous-prefix guard, the `"scores:"`-token bug class the walk found).
///
/// `opts` carries the rest of the closed #510 consent-transfer payload the
/// producer authors in FULL (grants / audience / attestation_prefixes /
/// valid_until / restrictions) — see [`ConsentGrantOptions`]. The grant is
/// deliberately **NOT** stamped `delivery_mode = "mandatory"`: a grant is not a
/// revocation. `delivery_mode` is a SELECTIVE fail-secure flag (edge v15.0.0's
/// `decide` maps `(Mandatory, no-path) → FailLoudNoPath`), reserved for the
/// withdraws / recants / kill-switch-tier class where a *silent drop* is a
/// security failure. A grant that misses a temporarily-unreachable peer is an
/// ordinary best-effort case that retry converges — stamping it `mandatory`
/// would convert that into a self-inflicted loud outage. Absent ⇒ BestEffort,
/// which is correct here (CIRISServer#327 §2 delivery_mode-is-selective ruling).
///
/// The 4-arg [`emit_replication_consent`] wrapper is the boot / default / test
/// entry (default policy); this `_with_policy` form is the owner-gated
/// `POST /v1/federation/consent` route's entry, carrying the operator's chosen
/// audience / expiry / restrictions.
pub async fn emit_replication_consent_with_policy<S: AsRef<str>>(
    engine: &Engine,
    node_key_id: &str,
    peer_key_id: &str,
    attestation_prefixes: &[S],
    opts: &ConsentGrantOptions,
) -> Result<ConsentGrant> {
    let directory = engine.federation_directory();

    // Idempotency guard: has A already granted replication consent to this peer?
    let existing = directory
        .list_attestations_by(node_key_id)
        .await
        .map_err(|e| anyhow::anyhow!("list attestations by {node_key_id}: {e}"))?;
    let already = existing.iter().find(|a| {
        a.attestation_type == attestation_type::SCORES
            && a.subject_key_ids.iter().any(|s| s == peer_key_id)
            && a.attestation_envelope
                .get(paths::DIMENSION)
                .and_then(|d| d.as_str())
                == Some(CONSENT_DIMENSION)
    });
    if let Some(existing) = already {
        tracing::debug!(
            peer_key_id,
            "replication-consent grant already present — skipping re-emit (idempotent)"
        );
        return Ok(ConsentGrant {
            attestation_id: existing.attestation_id.clone(),
            content_hash: existing.original_content_hash.clone(),
            freshly_emitted: false,
        });
    }

    let now = chrono::Utc::now();

    // ── The RC29 LOCKED consent:replication grant (CEG §5.6.8.15, resolves
    //    CIRISRegistry#98). A bare `scores` Attestation. ──────────────────────
    //
    // ENVELOPE level (envelope fields per §4.2.2.x):
    //   - attesting_key_id = A; dimension = consent:replication:v1
    //   - score > 0 (positive — magnitude NOT load-bearing)
    //   - subject_key_ids = [B] (the SINGLE recipient peer)
    //   - cohort_scope = "federation"
    //   - witness_relation = "self" (REQUIRED — G attests its own replication
    //     intent; forecloses third-party forgery of a consent grant)
    //   - topical_relation = "bilateral_pair" (SHOULD — lets a consumer pair
    //     A→B with B→A)
    //   - delivery_mode: deliberately UNSET (⇒ BestEffort). A grant is not a
    //     revocation; `mandatory` is reserved for the withdraws/recants/
    //     kill-switch class where a silent drop is a security failure. See the
    //     `_with_policy` doc comment for the full rationale.
    //
    // PAYLOAD level (a payload member under subject_kind, §4.2.2.3 — NOT envelope
    // fields): the FULL closed #510 consent-transfer grammar
    // (`consent_grammar::ConsentTransferPolicy`, validated at admission by
    // `parse_grant_payload`), authored complete rather than leaning on persist's
    // field defaults (CIRISServer#327 §2 / #510 P2):
    //   - subject_kind = "consent_replication"
    //   - grants = "replication" (the legacy-compat token; parse accepts it)
    //   - audience = the owner-chosen recipient cohort (default `federation`)
    //   - attestation_prefixes = the JCS array of namespace-prefix strings A
    //     replicates (trailing ":" significant), sorted ascending + deduped so
    //     consumers agree byte-for-byte — NON-VACUOUS (guarded below)
    //   - valid_until = optional payload-declared expiry
    //   - restrictions = strip_field / recipient_capability ops (persist's OWN
    //     closed RestrictionOp enum — an unknown op is unrepresentable)
    let prefixes = normalize_prefixes(attestation_prefixes);
    if prefixes.is_empty() {
        return Err(anyhow::anyhow!(
            "refusing to author a consent:replication grant with an empty (vacuous) \
             attestation-prefix set — persist admits an empty array but the grant would \
             cover nothing (CIRISServer#327 §2 non-vacuous-prefix guard)"
        ));
    }
    let audience = opts
        .audience
        .clone()
        .unwrap_or_else(|| cohort_scope::FEDERATION.to_string());
    if !cohort_scope::is_valid(&audience) {
        return Err(anyhow::anyhow!(
            "consent audience {audience:?} is not one of the closed cohort_scope values \
             (self/family/community/affiliations/species/biosphere/federation)"
        ));
    }
    let mut payload = serde_json::json!({
        "grants": "replication",
        "audience": audience,
        "attestation_prefixes": prefixes,
        "restrictions": opts.restrictions,
    });
    if let Some(valid_until) = opts.valid_until {
        payload["valid_until"] = serde_json::json!(valid_until);
    }
    let envelope = serde_json::json!({
        (paths::DIMENSION): CONSENT_DIMENSION,
        "attesting_key_id": node_key_id,
        "subject_key_ids": [peer_key_id],
        "score": 1.0,
        "cohort_scope": cohort_scope::FEDERATION,
        "witness_relation": "self",
        "topical_relation": "bilateral_pair",
        "asserted_at": now.to_rfc3339(),
        // §4.2.2.3 payload member (subject_kind + its payload), NOT envelope fields.
        "subject_kind": SUBJECT_KIND_CONSENT_REPLICATION,
        "payload": payload,
    });
    // NOTE: `delivery_mode` is intentionally NOT set (⇒ persist/edge treat its
    // absence as BestEffort). See the fn doc comment: a grant is the ordinary
    // class, not the withdraws/recants/kill-switch mandatory-delivery class, so it
    // must never fail loud on an unreachable peer.

    // ── Emit (CIRISPersist#253 collapse) ─────────────────────────────────────
    // The hand-rolled canonicalize→hash→hybrid-sign→assemble→put recipe is now
    // `Engine::emit_attestation_self` (signs with the engine's OWN composed
    // hardware-hybrid signer; attester/scrub = the node's #247 DERIVED federation
    // key_id == `node_key_id` here — wire-preserving). `weight = Some(1.0)`
    // matches the trust model's `unwrap_or(1.0)` default (preserved explicitly).
    //
    // `content_hash` (the integrity anchor surfaced to the operator via the
    // peering admin response) is the SAME JCS canonical hash emit computes
    // internally — derived here for the ConsentGrant return without a read-back.
    let canonical = ceg_produce_canonicalize(&envelope).map_err(|e| {
        anyhow::anyhow!("ceg_produce_canonicalize replication-consent envelope: {e}")
    })?;
    let content_hash = hex::encode(Sha256::digest(&canonical));

    let mut input = EmitAttestationInput::with_envelope(
        attestation_type::SCORES,
        ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope)?,
        // consent:replication:v1 is federation-scope MANDATORY (the grant must
        // be readable by the peer it names, and by the CCS leg).
        cohort_scope::FEDERATION,
    );
    input.attested_key_id = Some(peer_key_id.to_owned());
    input.subject_key_ids = vec![peer_key_id.to_owned()];
    input.weight = Some(1.0);
    let attestation_id = engine
        .emit_attestation_self(input)
        .await
        .map_err(|e| anyhow::anyhow!("emit_attestation_self(consent:replication:v1): {e}"))?;

    tracing::info!(
        peer_key_id,
        dimension = CONSENT_DIMENSION,
        attestation_id = %attestation_id,
        "emitted directed replication-consent grant (this node consents to replicate to peer)"
    );
    Ok(ConsentGrant {
        attestation_id,
        content_hash,
        freshly_emitted: true,
    })
}

/// Read this node's **desired replication topology back out of the corpus**: the
/// set of peer `key_id`s this node has authored a `consent:replication:v1` grant
/// for. This is the CEG-driven reconciler's source of truth — the consent objects
/// in the corpus ARE the desired Initiator/Responder set
/// ([`crate::replication_reconcile`]).
///
/// A `consent:replication` grant is the EXACT row [`emit_replication_consent`]
/// writes: a `scores` attestation authored by `node_key_id` whose
/// `attestation_envelope["dimension"] == CONSENT_DIMENSION`. The peers are the
/// `subject_key_ids` carried on those rows (each grant is directed at a single
/// peer, but the set unions across all grant rows). The returned set is **sorted
/// + deduped** so callers (and the reconciler's set-difference) are deterministic.
///
/// **Revocation is folded in (persist v21.0.0, CIRISPersist#502 E7).** This now
/// delegates to persist's [`list_consent_peers`](ciris_persist::federation::FederationDirectory::list_consent_peers),
/// which projects the consent peer set from the corpus with the CEG
/// `withdraws`/`supersedes` structural modifiers applied — a grant whose
/// `attestation_id` has been withdrawn is dropped before the subjects are
/// unioned (RC29 §5.6.8.15). This closes the former `presence == active`
/// classical edge: a revoked peer stops being replicated to on the next
/// reconcile tick, which is the nuclear-un-trust property the doctrine depends
/// on. The hand-rolled `list_attestations_by` + dimension filter it replaced
/// had no such filter, so a withdrawn grant kept replicating forever.
pub async fn replication_peers_from_consent(
    engine: &std::sync::Arc<Engine>,
    node_key_id: &str,
) -> Result<Vec<String>> {
    // persist returns the revocation-folded peer set already sorted + deduped
    // (a projection maintained by the Registry-of-Record), so this is a direct
    // read — no client-side filtering that could re-introduce the drift.
    engine
        .federation_directory()
        .list_consent_peers(node_key_id)
        .await
        .map_err(|e| anyhow::anyhow!("list consent peers for {node_key_id}: {e}"))
}
