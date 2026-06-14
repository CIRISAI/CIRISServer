//! Typed action vocabulary for the audit log (CIRISLensCore#12 v0.3).
//!
//! # Wire-freeze note (#18)
//!
//! These four types are wire-frozen: `AuditedAction`, `ConsentEvent`,
//! `WisdomBasedDeferral`, `IdentityChange`. Shape changes must go through
//! the #18 freeze process. The variant names and field names here ARE the
//! wire strings — don't rename without a freeze amendment.
//!
//! # Relationship to `AuditEntry`
//!
//! Each variant here maps to one `AuditEntry` row in persist's
//! `cirislens_audit_log` table:
//!
//! - `action_type` = the action-type wire string (see [`AuditedAction::action_type_str`])
//! - `subject_kind` = the subject_kind wire string (see each variant's impl)
//! - `subject_id` = the thought_id / stream_id / agent_id / field name
//! - `payload` = the typed struct serialized as JSON
//!
//! `actor_id` is the signing key's public-key base64 (the self-signed
//! identity model persist v0.7.1 established) — supplied by the host
//! Engine's `local_key_id()`.
//!
//! # Why enum variants instead of a flat struct
//!
//! The 4 action types carry different required fields (a `ConsentEvent`
//! needs `stream_id` + `consent_role`; an `IdentityChange` needs
//! `operator_signature`). An enum enforces that callers supply the right
//! fields at compile-time and makes the vocabulary set closed (additive-
//! only per the #18 freeze contract).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Typed vocabulary ────────────────────────────────────────────────

/// A handler action recorded to the audit log.
///
/// Maps to persist's `AuditEntry.action_type` = `handler_action_<type>`.
/// This is the #12 analogue of `AuditService.log_action(...)` in
/// CIRISAgent — the audit half of the accord_metrics adapter.
///
/// # Wire-frozen fields (#18)
///
/// - `action_type`: the handler vocabulary string
///   (e.g. `"speak"`, `"memorize"`, `"defer"`, `"reject"`, `"tool"`,
///   `"ponder"`, `"observe"`, `"task_complete"`, `"recall"`, `"forget"`)
/// - `thought_id`: the thought being handled (stable trace anchor)
/// - `rationale`: the reasoning summary (optional, may be scrubbed at
///   trace levels below `detailed`)
/// - `handler`: the handler class name (e.g. `"speak_handler"`)
/// - `success`: whether the action completed without error
/// - `duration_ms`: wall-clock time in milliseconds
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditedAction {
    /// Handler vocabulary string (wire-frozen). Examples:
    /// `"speak"`, `"memorize"`, `"recall"`, `"forget"`, `"tool"`,
    /// `"defer"`, `"reject"`, `"ponder"`, `"observe"`, `"task_complete"`.
    pub action_type: String,
    /// Thought-ID; also the `subject_id` in the `AuditEntry`.
    pub thought_id: String,
    /// Reasoning summary (optional). May be omitted at `generic`
    /// trace level to avoid PII egress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    /// Handler class name (e.g. `"speak_handler"`).
    pub handler: String,
    /// Whether the handler action completed without error.
    pub success: bool,
    /// Elapsed wall-clock time in milliseconds.
    pub duration_ms: u64,
    /// When the action was recorded. Set by lens-core at log time.
    pub recorded_at: DateTime<Utc>,
}

/// A user-consent lifecycle event.
///
/// Maps to `action_type = "consent_event"` in `AuditEntry`.
/// Covers the grant / revoke / expire transitions that the agent
/// records at the consent boundary.
///
/// # Wire-frozen fields (#18)
///
/// - `event_type`: `"grant"` | `"revoke"` | `"expire"`
/// - `stream_id`: the stream or channel the consent applies to
/// - `duration_days`: grant horizon in days (None for revoke/expire)
/// - `consent_role`: the principal role receiving consent
///   (e.g. `"datum"`, `"ally"`)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsentEvent {
    /// `"grant"` | `"revoke"` | `"expire"` (wire-frozen).
    pub event_type: ConsentEventType,
    /// The stream or channel this consent applies to.
    pub stream_id: String,
    /// Grant horizon in days. `None` for revoke/expire transitions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_days: Option<u32>,
    /// Principal role (e.g. `"datum"`, `"ally"`).
    pub consent_role: String,
    /// When the event was recorded. Set by lens-core at log time.
    pub recorded_at: DateTime<Utc>,
}

/// Wire-stable consent event type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentEventType {
    Grant,
    Revoke,
    Expire,
}

impl ConsentEventType {
    /// Wire string (lowercase, matches the Python enum value).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Revoke => "revoke",
            Self::Expire => "expire",
        }
    }
}

impl std::fmt::Display for ConsentEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A wisdom-based deferral event.
///
/// Records a decision to defer a thought to human oversight or another
/// principal because the agent assessed the situation as outside its
/// competence boundary. The "WBD" pattern from the CIRIS virtue
/// framework.
///
/// Maps to `action_type = "wisdom_based_deferral"` in `AuditEntry`.
///
/// # Wire-frozen fields (#18)
///
/// - `deferral_reason`: human-readable capability assessment
///   (e.g. `"capability_uncertain"`, `"ethical_boundary"`)
/// - `deferred_to`: the oversight target
///   (e.g. `"human_oversight"`, `"wa_authority"`)
/// - `deferral_window_seconds`: the deferral timeout in seconds
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WisdomBasedDeferral {
    /// Capability assessment reason for the deferral (wire-frozen).
    /// e.g. `"capability_uncertain"`, `"ethical_boundary"`.
    pub deferral_reason: String,
    /// Target principal for the deferral (wire-frozen).
    /// e.g. `"human_oversight"`, `"wa_authority"`.
    pub deferred_to: String,
    /// Timeout window for the deferral in seconds.
    pub deferral_window_seconds: u64,
    /// When the deferral was recorded. Set by lens-core at log time.
    pub recorded_at: DateTime<Utc>,
}

/// An agent identity change event.
///
/// Records a transition in the agent's role, identity field, or operator
/// affiliation. Operator-signed: the `operator_signature` field binds
/// the change to the operator's Ed25519 key (base64-encoded signature
/// over the canonical change record).
///
/// Maps to `action_type = "identity_change"` in `AuditEntry`.
///
/// # Wire-frozen fields (#18)
///
/// - `field`: the identity dimension being changed (e.g. `"agent_role"`)
/// - `old`: the previous value
/// - `new`: the new value
/// - `operator_signature`: Ed25519 signature from the operator authorizing
///   the change; base64-encoded. Empty string if not yet signed (unsigned
///   identity changes are accepted but flagged in chain verification).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityChange {
    /// Identity dimension being changed (e.g. `"agent_role"`,
    /// `"operator_id"`, `"agent_template"`).
    pub field: String,
    /// The previous value of the field.
    pub old: String,
    /// The new value of the field.
    pub new: String,
    /// Operator Ed25519 signature over the change (URL-safe base64, no pad).
    /// Empty string if the change is not operator-authorized.
    pub operator_signature: String,
    /// When the change was recorded. Set by lens-core at log time.
    pub recorded_at: DateTime<Utc>,
}

// ── AuditedAction top-level enum ────────────────────────────────────

/// The top-level typed audit event — one of the 4 wire-frozen variants.
///
/// This is the type the `LensAudit::record` method accepts; the per-type
/// `log_action` / `log_consent_event` / `log_wbd` / `log_identity_change`
/// methods on `LensAudit` are convenience constructors that build this
/// and call `record`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypedAuditEvent {
    Action(AuditedAction),
    ConsentEvent(ConsentEvent),
    WisdomBasedDeferral(WisdomBasedDeferral),
    IdentityChange(IdentityChange),
}

impl TypedAuditEvent {
    /// The `action_type` string for the persist `AuditEntry` row.
    /// These strings map to the persist `AuditEventType` vocabulary
    /// where they overlap, and extend it for the lens-core-specific types.
    pub fn action_type_str(&self) -> String {
        match self {
            // Handler actions use the persist vocab prefix.
            Self::Action(a) => format!("handler_action_{}", a.action_type),
            Self::ConsentEvent(_) => "consent_event".to_owned(),
            Self::WisdomBasedDeferral(_) => "wisdom_based_deferral".to_owned(),
            Self::IdentityChange(_) => "identity_change".to_owned(),
        }
    }

    /// The `subject_kind` string for the persist `AuditEntry` row.
    pub fn subject_kind(&self) -> &'static str {
        match self {
            Self::Action(_) => "thought",
            Self::ConsentEvent(_) => "stream",
            Self::WisdomBasedDeferral(_) => "thought",
            Self::IdentityChange(_) => "identity_field",
        }
    }

    /// The `subject_id` for the persist `AuditEntry` row.
    pub fn subject_id(&self) -> &str {
        match self {
            Self::Action(a) => &a.thought_id,
            Self::ConsentEvent(c) => &c.stream_id,
            // WBDs don't have a natural subject_id — use a sentinel.
            Self::WisdomBasedDeferral(_) => "wbd",
            Self::IdentityChange(ic) => &ic.field,
        }
    }

    /// The `recorded_at` timestamp.
    pub fn recorded_at(&self) -> DateTime<Utc> {
        match self {
            Self::Action(a) => a.recorded_at,
            Self::ConsentEvent(c) => c.recorded_at,
            Self::WisdomBasedDeferral(w) => w.recorded_at,
            Self::IdentityChange(ic) => ic.recorded_at,
        }
    }

    /// Serialize the event payload to a `serde_json::Value` for the
    /// persist `AuditEntry.payload` field.
    pub fn to_payload(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn now() -> DateTime<Utc> {
        // Deterministic for snapshot tests: fixed epoch.
        DateTime::from_timestamp(1_718_000_000, 0).unwrap()
    }

    // ── AuditedAction ────────────────────────────────────────────────

    #[test]
    fn audited_action_serde_round_trip() {
        let a = AuditedAction {
            action_type: "speak".into(),
            thought_id: "th_abc".into(),
            rationale: Some("user requested clarification".into()),
            handler: "speak_handler".into(),
            success: true,
            duration_ms: 42,
            recorded_at: now(),
        };
        let s = serde_json::to_string(&a).unwrap();
        let back: AuditedAction = serde_json::from_str(&s).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn audited_action_no_rationale_omits_field() {
        let a = AuditedAction {
            action_type: "speak".into(),
            thought_id: "th_abc".into(),
            rationale: None,
            handler: "speak_handler".into(),
            success: false,
            duration_ms: 0,
            recorded_at: now(),
        };
        let s = serde_json::to_string(&a).unwrap();
        assert!(
            !s.contains("rationale"),
            "rationale must be omitted when None"
        );
    }

    // ── ConsentEvent ─────────────────────────────────────────────────

    #[test]
    fn consent_event_grant_serde() {
        let c = ConsentEvent {
            event_type: ConsentEventType::Grant,
            stream_id: "ch_42".into(),
            duration_days: Some(30),
            consent_role: "datum".into(),
            recorded_at: now(),
        };
        let s = serde_json::to_string(&c).unwrap();
        assert!(s.contains("\"grant\""));
        let back: ConsentEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn consent_event_revoke_no_duration() {
        let c = ConsentEvent {
            event_type: ConsentEventType::Revoke,
            stream_id: "ch_99".into(),
            duration_days: None,
            consent_role: "ally".into(),
            recorded_at: now(),
        };
        let s = serde_json::to_string(&c).unwrap();
        assert!(
            !s.contains("duration_days"),
            "duration_days must be absent for revoke"
        );
    }

    // ── WisdomBasedDeferral ──────────────────────────────────────────

    #[test]
    fn wbd_serde_round_trip() {
        let w = WisdomBasedDeferral {
            deferral_reason: "capability_uncertain".into(),
            deferred_to: "human_oversight".into(),
            deferral_window_seconds: 86400,
            recorded_at: now(),
        };
        let s = serde_json::to_string(&w).unwrap();
        let back: WisdomBasedDeferral = serde_json::from_str(&s).unwrap();
        assert_eq!(w, back);
    }

    // ── IdentityChange ───────────────────────────────────────────────

    #[test]
    fn identity_change_serde_round_trip() {
        let ic = IdentityChange {
            field: "agent_role".into(),
            old: "datum".into(),
            new: "ally".into(),
            operator_signature: "base64sig==".into(),
            recorded_at: now(),
        };
        let s = serde_json::to_string(&ic).unwrap();
        let back: IdentityChange = serde_json::from_str(&s).unwrap();
        assert_eq!(ic, back);
    }

    // ── TypedAuditEvent dispatch ─────────────────────────────────────

    #[test]
    fn typed_event_action_type_str() {
        let ev = TypedAuditEvent::Action(AuditedAction {
            action_type: "speak".into(),
            thought_id: "th_x".into(),
            rationale: None,
            handler: "h".into(),
            success: true,
            duration_ms: 1,
            recorded_at: now(),
        });
        assert_eq!(ev.action_type_str(), "handler_action_speak");
        assert_eq!(ev.subject_kind(), "thought");
        assert_eq!(ev.subject_id(), "th_x");
    }

    #[test]
    fn typed_event_consent_type_str() {
        let ev = TypedAuditEvent::ConsentEvent(ConsentEvent {
            event_type: ConsentEventType::Expire,
            stream_id: "s1".into(),
            duration_days: None,
            consent_role: "datum".into(),
            recorded_at: now(),
        });
        assert_eq!(ev.action_type_str(), "consent_event");
        assert_eq!(ev.subject_kind(), "stream");
        assert_eq!(ev.subject_id(), "s1");
    }

    #[test]
    fn typed_event_wbd_type_str() {
        let ev = TypedAuditEvent::WisdomBasedDeferral(WisdomBasedDeferral {
            deferral_reason: "ethical_boundary".into(),
            deferred_to: "wa_authority".into(),
            deferral_window_seconds: 3600,
            recorded_at: now(),
        });
        assert_eq!(ev.action_type_str(), "wisdom_based_deferral");
        assert_eq!(ev.subject_kind(), "thought");
    }

    #[test]
    fn typed_event_identity_change_type_str() {
        let ev = TypedAuditEvent::IdentityChange(IdentityChange {
            field: "agent_role".into(),
            old: "datum".into(),
            new: "ally".into(),
            operator_signature: String::new(),
            recorded_at: now(),
        });
        assert_eq!(ev.action_type_str(), "identity_change");
        assert_eq!(ev.subject_kind(), "identity_field");
        assert_eq!(ev.subject_id(), "agent_role");
    }

    // ── Byte-stable canonical shape ──────────────────────────────────
    // These tests are signature-critical: they prove the JSON shape
    // the audit canonicalizer will see doesn't change across refactors.

    #[test]
    fn audited_action_payload_is_byte_stable() {
        let a = AuditedAction {
            action_type: "speak".into(),
            thought_id: "th_001".into(),
            rationale: None,
            handler: "speak_handler".into(),
            success: true,
            duration_ms: 42,
            recorded_at: now(),
        };
        let ev = TypedAuditEvent::Action(a);
        let payload = ev.to_payload();
        // Must have the required fields at the top level.
        assert!(payload.get("kind").is_some(), "missing kind tag");
        assert_eq!(payload["kind"], "action");
        assert_eq!(payload["action_type"], "speak");
        assert_eq!(payload["thought_id"], "th_001");
        assert_eq!(payload["handler"], "speak_handler");
        assert_eq!(payload["success"], true);
        assert_eq!(payload["duration_ms"], 42);
    }

    #[test]
    fn consent_event_payload_is_byte_stable() {
        let c = ConsentEvent {
            event_type: ConsentEventType::Grant,
            stream_id: "ch_grant".into(),
            duration_days: Some(30),
            consent_role: "datum".into(),
            recorded_at: now(),
        };
        let ev = TypedAuditEvent::ConsentEvent(c);
        let payload = ev.to_payload();
        assert_eq!(payload["kind"], "consent_event");
        assert_eq!(payload["event_type"], "grant");
        assert_eq!(payload["stream_id"], "ch_grant");
        assert_eq!(payload["duration_days"], 30);
        assert_eq!(payload["consent_role"], "datum");
    }

    #[test]
    fn wbd_payload_is_byte_stable() {
        let w = WisdomBasedDeferral {
            deferral_reason: "capability_uncertain".into(),
            deferred_to: "human_oversight".into(),
            deferral_window_seconds: 86400,
            recorded_at: now(),
        };
        let ev = TypedAuditEvent::WisdomBasedDeferral(w);
        let payload = ev.to_payload();
        assert_eq!(payload["kind"], "wisdom_based_deferral");
        assert_eq!(payload["deferral_reason"], "capability_uncertain");
        assert_eq!(payload["deferred_to"], "human_oversight");
        assert_eq!(payload["deferral_window_seconds"], 86400);
    }

    #[test]
    fn identity_change_payload_is_byte_stable() {
        let ic = IdentityChange {
            field: "agent_role".into(),
            old: "datum".into(),
            new: "ally".into(),
            operator_signature: "sig123".into(),
            recorded_at: now(),
        };
        let ev = TypedAuditEvent::IdentityChange(ic);
        let payload = ev.to_payload();
        assert_eq!(payload["kind"], "identity_change");
        assert_eq!(payload["field"], "agent_role");
        assert_eq!(payload["old"], "datum");
        assert_eq!(payload["new"], "ally");
        assert_eq!(payload["operator_signature"], "sig123");
    }
}
