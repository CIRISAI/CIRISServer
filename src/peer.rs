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

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use ciris_persist::federation::types::{
    attestation_tier, attestation_type, Attestation, SignedAttestation,
};
use ciris_persist::federation::Error as FederationError;
use ciris_persist::prelude::Engine;
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

use crate::config::PeerB;

/// The directed-consent dimension the A<->B replication grant rides on.
/// **Versioned** (`:v1`) to satisfy persist's
/// `DimensionAdmissionPolicy { require_version_segment: true }`. Open-vocab
/// (`consent:` is NOT a reserved prefix), so a steward-keyed attestation on it
/// is admitted without a reserved-prefix role.
pub const CONSENT_DIMENSION: &str = "consent:replication:v1";

/// What A consents to replicate to B — the `capacity:*` attestation family A
/// produces (the scorer's `capacity:sustained_coherence:v1` and any future
/// `capacity:*` leaves). The grant payload carries these as the JCS array of
/// namespace-prefix strings (trailing ":" significant), **sorted ascending +
/// deduplicated** (see [`attestation_prefixes`]) so consumers agree byte-for-byte.
const GRANT_ATTESTATION_PREFIXES: &[&str] = &["capacity:"];

/// `consent:replication` payload `subject_kind` (CEG 1.0-RC29 §4.2.2.3): a
/// payload member (NOT an envelope field) declaring the grant's subject shape.
const SUBJECT_KIND_CONSENT_REPLICATION: &str = "consent_replication";

/// Sorted + deduplicated copy of [`GRANT_ATTESTATION_PREFIXES`] — the byte-for-
/// byte form that goes into the grant payload so every consumer (and B's mirror)
/// agrees on the JCS array.
///
/// **Narrowing note (RC29 §5.6.8.15):** partial narrowing of the prefix set MUST
/// go via a `supersedes` attestation carrying a *narrower* set — never a silent
/// drop. Not implemented here; this helper deliberately does not preclude it.
fn attestation_prefixes() -> Vec<String> {
    let mut v: Vec<String> = GRANT_ATTESTATION_PREFIXES
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    v.sort();
    v.dedup();
    v
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
/// returning `Ok(false)` — `scores` rows are NOT collapsed by dimension on the
/// federation tier (each `put_attestation` mints a fresh `attestation_id`), so
/// we guard the emit with a directory lookup rather than blindly re-emitting.
/// Returns `Ok(true)` when a fresh grant row was written.
///
/// Revocation (not built here, per the contract) rides the CEG
/// withdraws/recants structural primitive targeting this grant's
/// `attestation_id` — the same mechanism CIRISAgent's `build_community_structural`
/// uses for the community-trust grant.
pub async fn emit_replication_consent(
    engine: &Engine,
    node_key_id: &str,
    peer_key_id: &str,
) -> Result<bool> {
    let directory = engine.federation_directory();

    // Idempotency guard: has A already granted replication consent to this peer?
    let existing = directory
        .list_attestations_by(node_key_id)
        .await
        .map_err(|e| anyhow::anyhow!("list attestations by {node_key_id}: {e}"))?;
    let already = existing.iter().any(|a| {
        a.attestation_type == attestation_type::SCORES
            && a.subject_key_ids.iter().any(|s| s == peer_key_id)
            && a.attestation_envelope
                .get("dimension")
                .and_then(|d| d.as_str())
                == Some(CONSENT_DIMENSION)
    });
    if already {
        tracing::debug!(
            peer_key_id,
            "replication-consent grant already present — skipping re-emit (idempotent)"
        );
        return Ok(false);
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
    let prefixes = attestation_prefixes();
    let envelope = serde_json::json!({
        "dimension": CONSENT_DIMENSION,
        "attesting_key_id": node_key_id,
        "subject_key_ids": [peer_key_id],
        "score": 1.0,
        "cohort_scope": "federation",
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

    // ── Emit recipe — modeled on scorer.rs / ceg.rs::emit_liveness ───────────
    // 1. CEG produce-canonical bytes (V2/JCS — the signing basis, CEG §0.9).
    let canonical = ceg_produce_canonicalize(&envelope).map_err(|e| {
        anyhow::anyhow!("ceg_produce_canonicalize replication-consent envelope: {e}")
    })?;
    // 2. original_content_hash = hex(SHA-256(canonical)).
    let original_content_hash = hex::encode(Sha256::digest(&canonical));
    // 3. Hybrid sign (Ed25519 hardware-sealed + ML-DSA-65) over the canonical bytes.
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .context("hybrid-sign replication-consent envelope")?;
    let classical_b64 = B64.encode(&sig.classical.signature);
    let pqc_b64 = B64.encode(&sig.pqc.signature);

    // 4. Assemble the FEDERATION-tier, directed row (subject = [B]).
    let attestation = Attestation {
        attestation_id: new_uuid_v4(),
        attesting_key_id: node_key_id.to_owned(),
        attested_key_id: peer_key_id.to_owned(),
        attestation_type: attestation_type::SCORES.to_owned(),
        weight: Some(1.0),
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash,
        scrub_signature_classical: classical_b64,
        scrub_signature_pqc: Some(pqc_b64),
        scrub_key_id: node_key_id.to_owned(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(), // server-computed on insert
        // Directed: this consent is bilateral A→B, never broadcast.
        subject_key_ids: vec![peer_key_id.to_owned()],
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_owned(),
        tier: attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
    };

    directory
        .put_attestation(SignedAttestation { attestation })
        .await
        .map_err(|e| anyhow::anyhow!("put_attestation(consent:replication:v1): {e}"))?;

    tracing::info!(
        peer_key_id,
        dimension = CONSENT_DIMENSION,
        "emitted directed replication-consent grant (A consents to replicate capacity:* to B)"
    );
    Ok(true)
}

/// Minimal RFC-4122 v4 row id (no `uuid` dep) — same recipe as
/// `scorer.rs::new_uuid_v4`. The content hash is the integrity anchor, not this id.
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
