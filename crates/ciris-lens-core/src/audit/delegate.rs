//! Audit-entry construction + canonical signing helper (CIRISLensCore#12).
//!
//! # Delegation path (three-step)
//!
//! ```text
//! TypedAuditEvent
//!   │
//!   ▼  build_entry_json()  (this module — pure Rust, no I/O)
//! AuditEntry JSON (entry_hash="", signature="")
//!   │
//!   ▼  engine.audit_canonicalize_for_hash(json) → bytes
//!   ▼  sha256(bytes) → entry_hash
//!   ▼  engine.audit_canonicalize_for_signing(json+hash) → bytes
//!   ▼  engine.local_sign(bytes) → Ed25519 sig (64 bytes)
//!   │
//!   ▼  engine.audit_record_entry(json+hash+sig)   (persist write)
//! ```
//!
//! Steps 2-5 are driven by the Python PyO3 layer in `crate::audit::pyo3`
//! (or the `LensAudit` Python class). This module owns ONLY the pure
//! Rust step 1 — building the initial `AuditEntry` JSON payload — plus
//! the `seal_entry` helper that wires in an `entry_hash` + `signature`
//! returned by the canonicalize/sign steps. Both helpers are pure and
//! fully unit-testable without an Engine.
//!
//! # Canonicalization discipline
//!
//! Lens-core NEVER re-implements the audit canonicalization rules. All
//! canonical bytes go through persist's `audit_canonicalize_for_hash`
//! and `audit_canonicalize_for_signing` Python methods — the same
//! Python-method-dispatch pattern proven in #11's capture path. This
//! mirrors the MISSION.md boundary: persist owns the canonicalizer;
//! consumers (lens-core, CIRISAgent, CIRISEdge) call it, never
//! re-implement it.
//!
//! # Cross-wheel delegation note (CIRISConformance)
//!
//! The full canonicalize→sign→audit_record_entry path crosses the
//! Python-method dispatch boundary (lens-core wheel + ciris_persist
//! wheel). This cannot be integration-tested in-repo — it requires two
//! separately-built wheels. This is a `CIRISConformance requires_audit_engine`
//! cell. The pure helpers in this module (build + seal) ARE tested;
//! only the Python dispatch step is a conformance cell.

use base64::Engine as B64Engine;
use chrono::{DateTime, Timelike, Utc};
use sha2::{Digest, Sha256};

use crate::audit::api::TypedAuditEvent;

/// An `AuditEntry` value built for the persist wire.
///
/// Not the same as `ciris_persist::audit::AuditEntry` — we build
/// a `serde_json::Value` directly to avoid coupling to the persist
/// crate's internal struct layout across major versions. The JSON
/// shape mirrors the persist struct exactly (field names match the
/// `serde` renames on `AuditEntry`).
///
/// Invariant: `entry_hash` and `signature` are empty strings until
/// the caller supplies them via [`seal_entry`].
pub struct AuditEntryDraft {
    /// JSON value with empty `entry_hash` and `signature`.
    pub json: serde_json::Value,
}

/// Truncate a UTC datetime to microsecond precision.
///
/// Mirrors `ciris_persist::audit::verify::truncate_to_micros`: persist's
/// audit columns are microsecond-precision (Postgres `TIMESTAMPTZ`, SQLite
/// text), so `recorded_at` MUST be rounded to microseconds **before** the
/// `entry_hash` is computed and the entry signed — otherwise the value the
/// caller hashed (nanosecond `Utc::now()`) differs from the microsecond
/// value persist re-reads, and `audit_verify_chain` reports
/// `EntryHashMismatch` on every row even though the write succeeded.
fn truncate_to_micros(dt: DateTime<Utc>) -> DateTime<Utc> {
    let micros = dt.nanosecond() / 1000;
    dt.with_nanosecond(micros * 1000).unwrap_or(dt)
}

/// Build the initial `AuditEntry` JSON for a typed audit event.
///
/// Returns an [`AuditEntryDraft`] with:
/// - `sequence_number` / `prev_hash` set to the chain head the caller
///   read from `engine.audit_next_chain_position(tenant_id)` — persist's
///   `record_entry` REQUIRES `sequence_number >= 1` and a 32-byte
///   `prev_hash` equal to the previous entry's `entry_hash` (the genesis
///   entry uses `sequence_number = 1` + 32 zero bytes). Persist does NOT
///   fill these on INSERT; supplying `0` / `""` is rejected (CIRISServer#93).
/// - `entry_hash = ""`  (to be filled by the caller after hashing)
/// - `signature = ""`   (to be filled by the caller after signing)
/// - `recorded_at` truncated to microseconds (see [`truncate_to_micros`]).
///
/// `prev_hash` is the raw 32-byte chain-head digest; it is encoded here as
/// base64-STANDARD to match persist's `AuditEntry` wire serde
/// (`serde_bytes_b64`), the same encoding [`stamp_entry_hash`] uses for
/// `entry_hash`. The caller hex-decodes the `prev_hash` returned by
/// `audit_next_chain_position` (which reports it as 64 hex chars) into these
/// raw bytes.
///
/// The caller MUST:
/// 1. `pos = engine.audit_next_chain_position(tenant_id)` →
///    `sequence_number` + `prev_hash`
/// 2. Call `engine.audit_canonicalize_for_hash(draft.json_str())`
/// 3. sha256 the returned bytes → fill `entry_hash`
/// 4. Call `engine.audit_canonicalize_for_signing(json_with_hash)`
/// 5. `engine.local_sign(bytes_from_step4)` → fill `signature`
/// 6. `engine.audit_record_entry(json_with_hash_and_sig)`
///
/// `actor_id` is the signing key's public-key base64 (the self-signed
/// identity model per persist v0.7.1 — `actor_id IS the pubkey`).
/// For the cohabitation path this is `engine.local_public_key_b64()`
/// (NOT `local_key_id()`, which returns the key_id label — persist
/// decodes `actor_id` as the Ed25519 verifying key for signature check).
pub fn build_entry_draft(
    event: &TypedAuditEvent,
    tenant_id: &str,
    actor_id: &str,
    entry_id: &str,
    recorded_at: DateTime<Utc>,
    sequence_number: i64,
    prev_hash: &[u8],
) -> AuditEntryDraft {
    let payload = event.to_payload();
    let prev_hash_b64 = base64::engine::general_purpose::STANDARD.encode(prev_hash);
    let json = serde_json::json!({
        "entry_id": entry_id,
        "sequence_number": sequence_number,
        "tenant_id": tenant_id,
        "actor_id": actor_id,
        "action_type": event.action_type_str(),
        "subject_kind": event.subject_kind(),
        "subject_id": event.subject_id(),
        "payload": payload,
        "prev_hash": prev_hash_b64,    // base64 of the chain-head digest
        "entry_hash": "",              // caller fills after canonicalize_for_hash
        "recorded_at": truncate_to_micros(recorded_at).to_rfc3339(),
        "signature": "",               // caller fills after signing
    });
    AuditEntryDraft { json }
}

impl AuditEntryDraft {
    /// Serialize to a compact JSON string suitable for the persist
    /// `audit_canonicalize_for_hash` / `audit_canonicalize_for_signing`
    /// / `audit_record_entry` calls.
    pub fn to_json_str(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.json)
    }
}

/// Stamp an `entry_hash` (base64-encoded SHA-256 of canonical bytes)
/// onto a draft entry JSON and return the updated JSON string.
///
/// `canonical_bytes` is the raw bytes returned by
/// `engine.audit_canonicalize_for_hash(draft_json_str)`. The
/// resulting JSON is ready to pass to
/// `engine.audit_canonicalize_for_signing`.
pub fn stamp_entry_hash(mut draft: serde_json::Value, canonical_bytes: &[u8]) -> serde_json::Value {
    let hash_b64 = base64::engine::general_purpose::STANDARD
        .encode(Sha256::digest(canonical_bytes).as_slice());
    // Replace the placeholder.
    if let Some(obj) = draft.as_object_mut() {
        obj.insert("entry_hash".into(), serde_json::Value::String(hash_b64));
    }
    draft
}

/// Stamp an Ed25519 `signature` (base64-STANDARD, padded) onto an
/// entry JSON that already has `entry_hash` set.
///
/// `sig_bytes` is the 64-byte Ed25519 signature returned by
/// `engine.local_sign(canonical_bytes_for_signing)`. The resulting
/// JSON is ready to pass to `engine.audit_record_entry`.
///
/// The encoding MUST be base64-STANDARD: persist's `audit_record_entry`
/// decodes the `signature` field through `verify_hybrid`, which uses the
/// STANDARD alphabet — a URL-safe (`-`/`_`) signature is rejected with
/// `base64 decode ed25519_sig: Invalid symbol` (CIRISServer#93, found at
/// the wheel boundary once the sequence_number gate was cleared).
pub fn stamp_signature(mut entry: serde_json::Value, sig_bytes: &[u8]) -> serde_json::Value {
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig_bytes);
    if let Some(obj) = entry.as_object_mut() {
        obj.insert("signature".into(), serde_json::Value::String(sig_b64));
    }
    entry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::api::{
        AuditedAction, ConsentEvent, ConsentEventType, IdentityChange, TypedAuditEvent,
        WisdomBasedDeferral,
    };
    use chrono::TimeZone;

    fn fixed_ts() -> DateTime<Utc> {
        Utc.timestamp_opt(1_718_000_000, 0).single().unwrap()
    }

    /// 32 zero bytes — the genesis chain head (sequence 1).
    const GENESIS_PREV: [u8; 32] = [0u8; 32];

    /// A non-genesis chain head (the previous entry's 32-byte entry_hash).
    fn some_prev() -> [u8; 32] {
        [0xABu8; 32]
    }

    /// Test helper: build a draft at the genesis chain head (seq 1, zero prev).
    fn build_genesis(
        event: &TypedAuditEvent,
        tenant_id: &str,
        actor_id: &str,
        entry_id: &str,
        recorded_at: DateTime<Utc>,
    ) -> AuditEntryDraft {
        build_entry_draft(
            event,
            tenant_id,
            actor_id,
            entry_id,
            recorded_at,
            1,
            &GENESIS_PREV,
        )
    }

    fn action_event() -> TypedAuditEvent {
        TypedAuditEvent::Action(AuditedAction {
            action_type: "speak".into(),
            thought_id: "th_001".into(),
            rationale: Some("testing".into()),
            handler: "speak_handler".into(),
            success: true,
            duration_ms: 55,
            recorded_at: fixed_ts(),
        })
    }

    // ── build_entry_draft structural checks ──────────────────────────

    #[test]
    fn draft_has_required_top_level_keys() {
        let ev = action_event();
        let draft = build_genesis(&ev, "tnt-1", "pubkey-b64", "entry-uuid-1", fixed_ts());
        let obj = draft.json.as_object().unwrap();
        for key in &[
            "entry_id",
            "sequence_number",
            "tenant_id",
            "actor_id",
            "action_type",
            "subject_kind",
            "subject_id",
            "payload",
            "prev_hash",
            "entry_hash",
            "recorded_at",
            "signature",
        ] {
            assert!(obj.contains_key(*key), "missing key: {key}");
        }
    }

    #[test]
    fn draft_entry_hash_and_signature_are_empty() {
        let ev = action_event();
        let draft = build_genesis(&ev, "tnt-1", "pk", "eid-1", fixed_ts());
        // entry_hash + signature stay empty (caller fills them); prev_hash and
        // sequence_number, by contrast, MUST be filled from the chain head —
        // they participate in the canonical bytes the entry_hash covers.
        assert_eq!(draft.json["entry_hash"], "");
        assert_eq!(draft.json["signature"], "");
    }

    // ── chain-head wiring (CIRISServer#93) ───────────────────────────

    #[test]
    fn genesis_draft_has_sequence_one_and_zero_prev_hash() {
        let ev = action_event();
        let draft = build_genesis(&ev, "tnt-1", "pk", "eid-1", fixed_ts());
        // persist's record_entry requires sequence_number >= 1 (the old draft
        // sent 0 and was rejected — this is the bug CIRISServer#93 reported).
        assert_eq!(draft.json["sequence_number"], 1);
        // The genesis prev_hash is 32 zero bytes, base64-STANDARD encoded to
        // match persist's serde_bytes_b64 wire shape (44 chars, all-zero data).
        let expected = base64::engine::general_purpose::STANDARD.encode(GENESIS_PREV);
        assert_eq!(draft.json["prev_hash"], expected);
        // Round-trips back to the 32 zero bytes persist's deserializer expects.
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(draft.json["prev_hash"].as_str().unwrap())
            .unwrap();
        assert_eq!(decoded, GENESIS_PREV.to_vec());
    }

    #[test]
    fn non_genesis_draft_carries_sequence_and_prev_hash() {
        let ev = action_event();
        let prev = some_prev();
        let draft = build_entry_draft(&ev, "tnt-1", "pk", "eid-2", fixed_ts(), 7, &prev);
        assert_eq!(draft.json["sequence_number"], 7);
        // prev_hash decodes back to the supplied 32-byte digest (the previous
        // entry's entry_hash), so persist's prev_hash==tail.entry_hash gate passes.
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(draft.json["prev_hash"].as_str().unwrap())
            .unwrap();
        assert_eq!(decoded, prev.to_vec());
    }

    #[test]
    fn recorded_at_is_truncated_to_microseconds() {
        // A timestamp with nanosecond precision below the microsecond floor.
        let ns = Utc
            .timestamp_opt(1_718_000_000, 123_456_789)
            .single()
            .unwrap();
        let ev = action_event();
        let draft = build_entry_draft(&ev, "t", "a", "e", ns, 1, &GENESIS_PREV);
        let recorded = draft.json["recorded_at"].as_str().unwrap();
        // The 789 nanosecond tail must be gone (Postgres TIMESTAMPTZ is µs);
        // otherwise the read-back hash diverges and verify_chain fails.
        assert!(
            !recorded.contains("123456789"),
            "recorded_at must be truncated to microseconds, got: {recorded}"
        );
        let parsed = DateTime::parse_from_rfc3339(recorded).unwrap();
        assert_eq!(parsed.timestamp_subsec_nanos(), 123_456_000);
    }

    #[test]
    fn draft_action_type_maps_correctly() {
        let ev = action_event();
        let draft = build_genesis(&ev, "t", "a", "e", fixed_ts());
        assert_eq!(draft.json["action_type"], "handler_action_speak");
        assert_eq!(draft.json["subject_kind"], "thought");
        assert_eq!(draft.json["subject_id"], "th_001");
    }

    #[test]
    fn draft_consent_event_action_type() {
        let ev = TypedAuditEvent::ConsentEvent(ConsentEvent {
            event_type: ConsentEventType::Grant,
            stream_id: "s1".into(),
            duration_days: Some(30),
            consent_role: "datum".into(),
            recorded_at: fixed_ts(),
        });
        let draft = build_genesis(&ev, "t", "a", "e", fixed_ts());
        assert_eq!(draft.json["action_type"], "consent_event");
        assert_eq!(draft.json["subject_kind"], "stream");
        assert_eq!(draft.json["subject_id"], "s1");
    }

    #[test]
    fn draft_wbd_action_type() {
        let ev = TypedAuditEvent::WisdomBasedDeferral(WisdomBasedDeferral {
            deferral_reason: "cap".into(),
            deferred_to: "human".into(),
            deferral_window_seconds: 3600,
            recorded_at: fixed_ts(),
        });
        let draft = build_genesis(&ev, "t", "a", "e", fixed_ts());
        assert_eq!(draft.json["action_type"], "wisdom_based_deferral");
    }

    #[test]
    fn draft_identity_change_action_type() {
        let ev = TypedAuditEvent::IdentityChange(IdentityChange {
            field: "agent_role".into(),
            old: "datum".into(),
            new: "ally".into(),
            operator_signature: "sig".into(),
            recorded_at: fixed_ts(),
        });
        let draft = build_genesis(&ev, "t", "a", "e", fixed_ts());
        assert_eq!(draft.json["action_type"], "identity_change");
        assert_eq!(draft.json["subject_kind"], "identity_field");
        assert_eq!(draft.json["subject_id"], "agent_role");
    }

    // ── stamp_entry_hash ─────────────────────────────────────────────

    #[test]
    fn stamp_entry_hash_replaces_placeholder() {
        let ev = action_event();
        let draft = build_genesis(&ev, "t", "a", "e", fixed_ts());
        let canonical = b"some canonical bytes";
        let stamped = stamp_entry_hash(draft.json, canonical);
        // entry_hash must now be a non-empty base64 string.
        let h = stamped["entry_hash"].as_str().unwrap();
        assert!(!h.is_empty(), "entry_hash must be non-empty after stamp");
        // Verify it's the SHA-256 of the canonical bytes (base64 STANDARD).
        let expected =
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(canonical).as_slice());
        assert_eq!(h, expected);
    }

    #[test]
    fn stamp_entry_hash_is_deterministic() {
        let ev = action_event();
        let draft1 = build_genesis(&ev, "t", "a", "e", fixed_ts());
        let draft2 = build_genesis(&ev, "t", "a", "e", fixed_ts());
        let canonical = b"deterministic input";
        let h1 = stamp_entry_hash(draft1.json, canonical)["entry_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        let h2 = stamp_entry_hash(draft2.json, canonical)["entry_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(h1, h2);
    }

    // ── stamp_signature ──────────────────────────────────────────────

    #[test]
    fn stamp_signature_replaces_placeholder() {
        let ev = action_event();
        let draft = build_genesis(&ev, "t", "a", "e", fixed_ts());
        let sig_bytes = [0xABu8; 64];
        let signed = stamp_signature(draft.json, &sig_bytes);
        let sig = signed["signature"].as_str().unwrap();
        assert!(!sig.is_empty());
        // Must be base64-STANDARD (persist's verify_hybrid decodes the audit
        // signature with the STANDARD alphabet; URL-safe `-`/`_` is rejected).
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(sig)
            .expect("must decode as base64-STANDARD");
        assert_eq!(decoded, sig_bytes.as_slice());
    }

    // ── to_json_str ──────────────────────────────────────────────────

    #[test]
    fn draft_serializes_to_valid_json() {
        let ev = action_event();
        let draft = build_genesis(&ev, "tnt", "pk", "eid", fixed_ts());
        let s = draft.to_json_str().expect("must serialize");
        let _: serde_json::Value = serde_json::from_str(&s).expect("must re-parse");
    }
}
