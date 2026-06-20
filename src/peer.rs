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

use ciris_persist::federation::types::{attestation_type, cohort_scope};
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
    match engine
        .register_federation_key(peer.key_record.clone())
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
/// path passes the operator's set.
pub async fn emit_replication_consent<S: AsRef<str>>(
    engine: &Engine,
    node_key_id: &str,
    peer_key_id: &str,
    attestation_prefixes: &[S],
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
                .get("dimension")
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
    //   - (valid_until omitted — not time-boxing this grant)
    //
    // PAYLOAD level (a payload member under subject_kind, §4.2.2.3 — NOT envelope
    // fields):
    //   - subject_kind = "consent_replication"
    //   - grants = "replication" (constant)
    //   - attestation_prefixes = the JCS array of namespace-prefix strings A
    //     replicates (trailing ":" significant), sorted ascending + deduped so
    //     consumers agree byte-for-byte.
    let prefixes = normalize_prefixes(attestation_prefixes);
    let envelope = serde_json::json!({
        "dimension": CONSENT_DIMENSION,
        "attesting_key_id": node_key_id,
        "subject_key_ids": [peer_key_id],
        "score": 1.0,
        "cohort_scope": cohort_scope::FEDERATION,
        "witness_relation": "self",
        "topical_relation": "bilateral_pair",
        "asserted_at": now.to_rfc3339(),
        // §4.2.2.3 payload member (subject_kind + its payload), NOT envelope fields.
        "subject_kind": SUBJECT_KIND_CONSENT_REPLICATION,
        "payload": {
            "grants": "replication",
            "attestation_prefixes": prefixes,
        },
    });

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

    let mut input = EmitAttestationInput::with_envelope(attestation_type::SCORES, envelope);
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
/// peer, but we union across all grant rows). The returned set is **sorted +
/// deduped** so callers (and the reconciler's set-difference) are deterministic.
///
/// The match logic is the same predicate [`emit_replication_consent`]'s
/// idempotency guard uses (`SCORES` + the consent dimension), so a row read here
/// is exactly a row that emit would treat as an existing grant.
///
// TODO(consent revocation): RC29 §5.6.8.15 models grant revocation via the CEG
// withdraws/recants structural primitive targeting the grant's `attestation_id`
// (the same mechanism CIRISAgent's `build_community_structural` uses). No such
// supersede/withdraw filter is applied here yet — **presence == active**. When
// the withdraw primitive is honored on the federation tier, this reader must drop
// any grant whose `attestation_id` is withdrawn before unioning the subjects.
pub async fn replication_peers_from_consent(
    engine: &std::sync::Arc<Engine>,
    node_key_id: &str,
) -> Result<Vec<String>> {
    let rows = engine
        .federation_directory()
        .list_attestations_by(node_key_id)
        .await
        .map_err(|e| anyhow::anyhow!("list attestations by {node_key_id}: {e}"))?;
    let mut peers: Vec<String> = rows
        .iter()
        .filter(|a| {
            a.attestation_type == attestation_type::SCORES
                && a.attestation_envelope
                    .get("dimension")
                    .and_then(|d| d.as_str())
                    == Some(CONSENT_DIMENSION)
        })
        .flat_map(|a| a.subject_key_ids.iter().cloned())
        .collect();
    peers.sort();
    peers.dedup();
    Ok(peers)
}
