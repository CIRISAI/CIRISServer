//! Partial-trace assembly — the in-memory state machine that turns a
//! stream of component events into sealed [`CompleteTrace`]s
//! (CIRISLensCore#11 Cut 2).
//!
//! # Storage choice (design-fork C1)
//!
//! Active (in-flight) traces live in a process-local [`HashMap`] keyed
//! by `thought_id` — behavior-parity with the agent's legacy
//! `_active_traces` dict. **In-flight traces are lost on process
//! restart**; [`orphan_sweep`](PartialTraceStore::orphan_sweep) purges
//! stale incompletes, and a lost partial is a never-sealed (dropped)
//! trace. The restart-durable variant is tracked at
//! [#35](https://github.com/CIRISAI/CIRISLensCore/issues/35).
//!
//! # Attempt index
//!
//! Some event types fire many times per thought (`LLM_CALL`,
//! `CONSCIENCE_RESULT`, DMA bounce alternatives). Each component carries
//! a per-`(thought_id, event_type)` monotonic `attempt_index` so
//! downstream consumers have stable ordering; once-per-thought events
//! are always index `0`. Single-subscriber FIFO delivery from the
//! agent's `reasoning_event_stream` guarantees the increment order is
//! the broadcast order (FSD/TRACE_EVENT_LOG_PERSISTENCE.md §5.1).
//!
//! # Not in this cut
//!
//! Signing, canonical bytes, persistence, and fan-out are Cut 3/4. This
//! module is pure assembly — no `Engine`, no I/O, no wall-clock
//! (`orphan_sweep` takes `now` as a parameter, mirroring
//! `retention::plan_eviction`).

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};

use super::event::{ComponentType, ReasoningEventType};

/// The wire trace-schema version this assembler emits. 3.0.0 is the JCS
/// canonicalizer era (major ≥ 3 ⇒ RFC 8785; CIRISAgent 2.9.6 cutover).
/// Like 2.7.9, the 10-field canonical layout (9 envelope fields +
/// `deployment_profile`) is unchanged — only the canonicalizer flips.
/// [`CompleteTrace::deployment_profile`] remains part of the signed bytes
/// when present; `BatchEnvelope::from_json` does NOT require it at 3.0.0
/// (the strict-require gate is 2.7.9-only in persist v5.2.0).
pub const TRACE_SCHEMA_VERSION: &str = "3.0.0";

/// A single assembled component of a reasoning trace.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceComponent {
    /// The trace-component bucket (`observation` / `rationale` / …).
    pub component_type: ComponentType,
    /// The originating reasoning-event type.
    pub event_type: ReasoningEventType,
    /// RFC-3339 timestamp carried by the inbound event.
    pub timestamp: String,
    /// Per-`(thought_id, event_type)` monotonic occurrence index.
    pub attempt_index: u32,
    /// Opaque event payload (already PII-scrubbed by the agent before
    /// emission, or scrubbed at the FULL_TRACES persist boundary).
    pub data: Value,
    /// Denormalized from [`CompleteTrace::agent_id_hash`] onto every
    /// component (trace_schema_version 2.7.9, CIRISAgent#712 item 1).
    pub agent_id_hash: String,
}

impl TraceComponent {
    /// The component's `data` with `attempt_index` injected as a key —
    /// the agent's wire + signed-canonical shape
    /// (CIRISAgent `services.py:1698`
    /// `component_data["attempt_index"] = attempt_index`, set at capture).
    ///
    /// `attempt_index` is lens-core's authoritative *typed field*; on the
    /// wire and in the signed canonical bytes it lives **inside** `data`
    /// (even `0`, which `strip_empty` keeps — it is informative: confirms
    /// first occurrence). This is the single injection point shared by
    /// [`to_json`](Self::to_json) (wire) and
    /// [`build_canonical_envelope`](super::seal::build_canonical_envelope)
    /// (signed bytes) so the two can never drift.
    pub fn data_with_attempt_index(&self) -> Value {
        let mut map = match &self.data {
            Value::Object(m) => m.clone(),
            // The agent's component data is always a dict; a null/absent
            // payload becomes the minimal `{"attempt_index": N}` (matching
            // the agent, whose `_extract_component_data` always returns a
            // dict it then injects into). Non-object scalars are
            // out-of-contract and collapse to the same minimal dict.
            _ => Map::new(),
        };
        map.insert("attempt_index".into(), json!(self.attempt_index));
        Value::Object(map)
    }

    /// Wire JSON for this component — snake_case `component_type` +
    /// bare `event_type`, matching the agent's `to_dict` shape.
    /// `attempt_index` is carried **inside** `data` (not a sibling key),
    /// per the agent (`services.py:1698`); see
    /// [`data_with_attempt_index`](Self::data_with_attempt_index).
    pub fn to_json(&self) -> Value {
        json!({
            "component_type": self.component_type.as_wire_str(),
            "event_type": self.event_type.as_wire_str(),
            "timestamp": self.timestamp,
            "data": self.data_with_attempt_index(),
            "agent_id_hash": self.agent_id_hash,
        })
    }
}

/// A reasoning trace under assembly or sealed. Mirrors the agent's
/// `CompleteTrace` wire shape (FSD/TRACE_WIRE_FORMAT.md). Signature
/// fields stay `None` until Cut 3 seals it.
#[derive(Debug, Clone, PartialEq)]
pub struct CompleteTrace {
    pub trace_id: String,
    pub thought_id: String,
    pub task_id: Option<String>,
    pub agent_id_hash: String,
    /// RFC-3339; set from the trace's first event.
    pub started_at: String,
    /// RFC-3339; set when `ACTION_RESULT` seals the trace.
    pub completed_at: Option<String>,
    pub components: Vec<TraceComponent>,
    pub signature: Option<String>,
    pub signature_key_id: Option<String>,
    /// ML-DSA-65 (FIPS 204) signature half of the hybrid trace seal,
    /// STANDARD base64. Signed over the bound input `canonical ‖
    /// ed25519_sig` (the bound-hybrid construction persist's
    /// `verify_trace_hybrid` reconstructs). `None` until the hybrid seal
    /// stamps it; the trace-tier hard cut (CIRISPersist#225) rejects a
    /// classical-only trace at `VerifyMode::Full` admission.
    pub signature_ml_dsa_65: Option<String>,
    /// Producer's ML-DSA-65 public key, STANDARD base64 (1952 raw bytes).
    /// Rides the trace envelope because the `accord_public_keys`
    /// directory is Ed25519-only; bound into the hybrid verify. `None`
    /// together with [`signature_ml_dsa_65`](Self::signature_ml_dsa_65).
    pub pubkey_ml_dsa_65: Option<String>,
    /// Identifier of the ML-DSA-65 signing key (stored verbatim).
    pub pqc_key_id: Option<String>,
    pub trace_level: Option<String>,
    pub trace_schema_version: String,
    /// 6-field cohort-taxonomy block (2.7.9+). Required on the wire at
    /// schema 2.7.9; populated by the client from operator config /
    /// migration defaults (Cut 3/5).
    pub deployment_profile: Option<Value>,
}

impl CompleteTrace {
    /// Is this trace sealed (i.e. `ACTION_RESULT` has landed)?
    pub fn is_sealed(&self) -> bool {
        self.completed_at.is_some()
    }
}

/// What [`PartialTraceStore::capture`] did with an inbound event.
#[derive(Debug, Clone, PartialEq)]
pub enum CaptureOutcome {
    /// First event for this `thought_id` — a new active trace opened.
    Opened,
    /// Component appended to an existing active trace.
    Appended,
    /// `ACTION_RESULT` landed; the now-sealed trace is returned and
    /// removed from the active set, ready for the Cut 3 seal path.
    Sealed(Box<CompleteTrace>),
    /// The event-type string didn't parse to a known
    /// [`ReasoningEventType`] — a **typed rejection**, never a silent
    /// mis-component (the CIRISLens#13 fix). The caller logs + drops.
    UnknownEvent { raw: String },
}

/// In-memory partial-trace store. Not thread-safe by itself — the
/// `LensCore` handle wraps it in a lock (Cut 3); the assembly logic
/// here is deliberately synchronous + pure for unit-testability.
#[derive(Debug, Default)]
pub struct PartialTraceStore {
    /// Active traces keyed by `thought_id`.
    active: HashMap<String, CompleteTrace>,
    /// Next attempt index per `(thought_id, event_wire_str)`.
    attempt_counters: HashMap<(String, String), u32>,
}

/// One inbound component event from the agent's `reasoning_event_stream`.
/// The PyO3 surface (Cut 5) constructs this from the agent's event dict.
#[derive(Debug, Clone)]
pub struct InboundEvent {
    /// Raw event-type string (either `"THOUGHT_START"` or
    /// `"ReasoningEvent.THOUGHT_START"` form).
    pub event_type: String,
    pub thought_id: String,
    pub task_id: Option<String>,
    pub agent_id_hash: String,
    /// RFC-3339 timestamp.
    pub timestamp: String,
    /// Trace level (`GENERIC` / `DETAILED` / `FULL_TRACES`).
    pub trace_level: Option<String>,
    pub data: Value,
}

impl PartialTraceStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of in-flight (unsealed) traces.
    pub fn active_len(&self) -> usize {
        self.active.len()
    }

    /// Assemble one inbound event into its trace.
    ///
    /// - First event for a `thought_id` opens a new active trace
    ///   (`started_at` = the event timestamp); the `trace_id` is the
    ///   caller-provided value or derived from `thought_id` (Cut 3 sets
    ///   the canonical id policy).
    /// - `ACTION_RESULT` appends its `action` component, stamps
    ///   `completed_at`, removes the trace from the active set, and
    ///   returns it [`Sealed`](CaptureOutcome::Sealed).
    /// - An unparseable event type is returned
    ///   [`UnknownEvent`](CaptureOutcome::UnknownEvent) and nothing is
    ///   mutated.
    pub fn capture(&mut self, ev: InboundEvent, trace_id_for_new: &str) -> CaptureOutcome {
        let Some(event_type) = ReasoningEventType::parse(&ev.event_type) else {
            return CaptureOutcome::UnknownEvent { raw: ev.event_type };
        };

        // Attempt index: read-and-increment per (thought_id, event).
        let key = (ev.thought_id.clone(), event_type.as_wire_str().to_string());
        let attempt_index = {
            let slot = self.attempt_counters.entry(key).or_insert(0);
            let idx = *slot;
            *slot += 1;
            idx
        };

        let component = TraceComponent {
            component_type: event_type.component_type(),
            event_type,
            timestamp: ev.timestamp.clone(),
            attempt_index,
            data: ev.data,
            agent_id_hash: ev.agent_id_hash.clone(),
        };

        let opened = !self.active.contains_key(&ev.thought_id);
        let trace = self
            .active
            .entry(ev.thought_id.clone())
            .or_insert_with(|| CompleteTrace {
                trace_id: trace_id_for_new.to_string(),
                thought_id: ev.thought_id.clone(),
                task_id: ev.task_id.clone(),
                agent_id_hash: ev.agent_id_hash.clone(),
                started_at: ev.timestamp.clone(),
                completed_at: None,
                components: Vec::new(),
                signature: None,
                signature_key_id: None,
                signature_ml_dsa_65: None,
                pubkey_ml_dsa_65: None,
                pqc_key_id: None,
                trace_level: ev.trace_level.clone(),
                trace_schema_version: TRACE_SCHEMA_VERSION.to_string(),
                deployment_profile: None,
            });

        // Late-arriving task_id / trace_level fill in if the opening
        // event lacked them.
        if trace.task_id.is_none() {
            trace.task_id = ev.task_id;
        }
        if trace.trace_level.is_none() {
            trace.trace_level = ev.trace_level;
        }

        trace.components.push(component);

        if event_type.seals_trace() {
            trace.completed_at = Some(ev.timestamp);
            // Drop this thought's attempt counters — the trace is done.
            self.attempt_counters
                .retain(|(tid, _), _| tid != &ev.thought_id);
            let sealed = self
                .active
                .remove(&ev.thought_id)
                .expect("trace was just inserted/updated");
            return CaptureOutcome::Sealed(Box::new(sealed));
        }

        if opened {
            CaptureOutcome::Opened
        } else {
            CaptureOutcome::Appended
        }
    }

    /// Purge active traces whose `started_at` is older than
    /// `max_age_secs` before `now`. Returns the count purged. These are
    /// incomplete reasoning traces whose `ACTION_RESULT` never arrived
    /// (agent crash mid-thought, dropped event). `now` is injected for
    /// deterministic testing — no wall-clock here.
    pub fn orphan_sweep(&mut self, now: DateTime<Utc>, max_age_secs: i64) -> usize {
        let before = self.active.len();
        let purged_thoughts: Vec<String> = self
            .active
            .iter()
            .filter(|(_, t)| match DateTime::parse_from_rfc3339(&t.started_at) {
                Ok(started) => (now - started.with_timezone(&Utc)).num_seconds() > max_age_secs,
                // Unparseable started_at → treat as orphan (malformed,
                // can never seal correctly).
                Err(_) => true,
            })
            .map(|(tid, _)| tid.clone())
            .collect();

        for tid in &purged_thoughts {
            self.active.remove(tid);
            self.attempt_counters.retain(|(t, _), _| t != tid);
        }
        before - self.active.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(event_type: &str, thought: &str, ts: &str) -> InboundEvent {
        InboundEvent {
            event_type: event_type.to_string(),
            thought_id: thought.to_string(),
            task_id: Some("task-1".into()),
            agent_id_hash: "agenthash".into(),
            timestamp: ts.to_string(),
            trace_level: Some("FULL_TRACES".into()),
            data: json!({ "k": "v" }),
        }
    }

    #[test]
    fn first_event_opens_a_trace() {
        let mut s = PartialTraceStore::new();
        let out = s.capture(ev("THOUGHT_START", "t1", "2026-06-08T00:00:00Z"), "trace-1");
        assert_eq!(out, CaptureOutcome::Opened);
        assert_eq!(s.active_len(), 1);
    }

    #[test]
    fn subsequent_events_append() {
        let mut s = PartialTraceStore::new();
        s.capture(ev("THOUGHT_START", "t1", "2026-06-08T00:00:00Z"), "trace-1");
        let out = s.capture(ev("DMA_RESULTS", "t1", "2026-06-08T00:00:01Z"), "trace-1");
        assert_eq!(out, CaptureOutcome::Appended);
        assert_eq!(s.active_len(), 1);
    }

    #[test]
    fn action_result_seals_and_removes() {
        let mut s = PartialTraceStore::new();
        s.capture(ev("THOUGHT_START", "t1", "2026-06-08T00:00:00Z"), "trace-1");
        s.capture(ev("DMA_RESULTS", "t1", "2026-06-08T00:00:01Z"), "trace-1");
        let out = s.capture(ev("ACTION_RESULT", "t1", "2026-06-08T00:00:02Z"), "trace-1");
        match out {
            CaptureOutcome::Sealed(t) => {
                assert!(t.is_sealed());
                assert_eq!(t.completed_at.as_deref(), Some("2026-06-08T00:00:02Z"));
                assert_eq!(t.components.len(), 3); // start + dma + action
                assert_eq!(t.thought_id, "t1");
            }
            other => panic!("expected Sealed, got {other:?}"),
        }
        assert_eq!(s.active_len(), 0); // removed from active on seal
    }

    #[test]
    fn attempt_index_increments_per_repeated_event() {
        let mut s = PartialTraceStore::new();
        s.capture(ev("THOUGHT_START", "t1", "2026-06-08T00:00:00Z"), "trace-1");
        // Three LLM_CALLs in one thought → indices 0, 1, 2.
        s.capture(ev("LLM_CALL", "t1", "2026-06-08T00:00:01Z"), "trace-1");
        s.capture(ev("LLM_CALL", "t1", "2026-06-08T00:00:02Z"), "trace-1");
        s.capture(ev("LLM_CALL", "t1", "2026-06-08T00:00:03Z"), "trace-1");
        let sealed = match s.capture(ev("ACTION_RESULT", "t1", "2026-06-08T00:00:04Z"), "trace-1") {
            CaptureOutcome::Sealed(t) => t,
            other => panic!("expected Sealed, got {other:?}"),
        };
        let llm_indices: Vec<u32> = sealed
            .components
            .iter()
            .filter(|c| c.event_type == ReasoningEventType::LlmCall)
            .map(|c| c.attempt_index)
            .collect();
        assert_eq!(llm_indices, vec![0, 1, 2]);
        // THOUGHT_START (fires once) is always index 0.
        let start = sealed
            .components
            .iter()
            .find(|c| c.event_type == ReasoningEventType::ThoughtStart)
            .unwrap();
        assert_eq!(start.attempt_index, 0);
    }

    #[test]
    fn attempt_counters_are_per_thought() {
        let mut s = PartialTraceStore::new();
        s.capture(ev("THOUGHT_START", "t1", "2026-06-08T00:00:00Z"), "trace-1");
        s.capture(ev("THOUGHT_START", "t2", "2026-06-08T00:00:00Z"), "trace-2");
        s.capture(ev("LLM_CALL", "t1", "2026-06-08T00:00:01Z"), "trace-1");
        let sealed_t2 =
            match s.capture(ev("ACTION_RESULT", "t2", "2026-06-08T00:00:02Z"), "trace-2") {
                CaptureOutcome::Sealed(t) => t,
                other => panic!("expected Sealed, got {other:?}"),
            };
        // t2's first LLM_CALL would be index 0 — independent of t1's counter.
        // (No LLM_CALL on t2 here; assert the action is index 0.)
        let action = sealed_t2
            .components
            .iter()
            .find(|c| c.event_type == ReasoningEventType::ActionResult)
            .unwrap();
        assert_eq!(action.attempt_index, 0);
        assert_eq!(s.active_len(), 1); // t1 still in flight
    }

    #[test]
    fn unknown_event_is_typed_rejection_no_mutation() {
        let mut s = PartialTraceStore::new();
        let out = s.capture(ev("THOUGHT_STRT", "t1", "2026-06-08T00:00:00Z"), "trace-1");
        assert_eq!(
            out,
            CaptureOutcome::UnknownEvent {
                raw: "THOUGHT_STRT".into()
            }
        );
        assert_eq!(s.active_len(), 0); // nothing opened
    }

    #[test]
    fn orphan_sweep_purges_stale_unsealed() {
        let mut s = PartialTraceStore::new();
        s.capture(
            ev("THOUGHT_START", "old", "2026-06-08T00:00:00Z"),
            "trace-old",
        );
        s.capture(
            ev("THOUGHT_START", "new", "2026-06-08T01:00:00Z"),
            "trace-new",
        );
        // now = 01:00:30; max_age = 600s. "old" started 1h0m30s ago → purged;
        // "new" started 30s ago → kept.
        let now: DateTime<Utc> = "2026-06-08T01:00:30Z".parse().unwrap();
        let purged = s.orphan_sweep(now, 600);
        assert_eq!(purged, 1);
        assert_eq!(s.active_len(), 1);
    }

    #[test]
    fn orphan_sweep_purges_malformed_timestamp() {
        let mut s = PartialTraceStore::new();
        let mut bad = ev("THOUGHT_START", "bad", "not-a-timestamp");
        bad.timestamp = "not-a-timestamp".into();
        s.capture(bad, "trace-bad");
        let now: DateTime<Utc> = "2026-06-08T01:00:30Z".parse().unwrap();
        assert_eq!(s.orphan_sweep(now, 600), 1);
    }

    #[test]
    fn dual_wire_form_assembles_identically() {
        let mut s = PartialTraceStore::new();
        // Enum-qualified open form, bare seal form — must land in one trace.
        s.capture(
            ev("ReasoningEvent.THOUGHT_START", "t1", "2026-06-08T00:00:00Z"),
            "trace-1",
        );
        let out = s.capture(ev("ACTION_RESULT", "t1", "2026-06-08T00:00:01Z"), "trace-1");
        assert!(matches!(out, CaptureOutcome::Sealed(_)));
    }
}
