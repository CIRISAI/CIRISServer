//! Outbound batch assembly — wrapping signed [`CompleteTrace`]s into the
//! persist `BatchEnvelope` wire bytes (CIRISLensCore#11 Cut 5, layer 1).
//!
//! # Where this sits
//!
//! ```text
//! capture → assemble (partial) → seal+sign (seal) → BATCH (this) →
//!     engine.receive_and_persist(bytes)  +  edge outbound fan-out
//! ```
//!
//! This module owns only the **wire shape** — turning one or more sealed,
//! Ed25519-signed traces into the JSON bytes
//! `Engine::receive_and_persist` (and the edge outbound path) consume. It
//! is pure: no `Engine`, no I/O, no wall-clock.
//!
//! # persist owns the typed envelope; lens-core emits JSON
//!
//! persist's `schema::trace::CompleteTrace` is a *different shape* from
//! lens-core's capture-side [`CompleteTrace`] (typed `WireDateTime`,
//! typed event/component enums, `Map` data, typed `DeploymentProfile`,
//! extra skip-default `cohort_scope` fields). Per the MISSION boundary
//! ("lens-core never re-implements persist's wire/canonical rules"), we
//! do **not** hand-convert into persist's typed struct — we emit the wire
//! JSON and let persist deserialize + verify it, exactly as the relay
//! handler re-serializes an inbound batch to bytes. The wire shape is
//! validated by round-tripping through persist's real
//! `BatchEnvelope::from_json` + `verify_trace` (see the tests).
//!
//! # Provenance is an explicit input (CIRISAgent#870)
//!
//! `consent_timestamp` + `correlation_metadata` are batch-level
//! provenance whose *source of truth* (post-fold) is the shared persist
//! Engine's CEG consent object, with a config/env fallback during the
//! 2.7.9 interim. That sourcing is a separate layer; this builder takes
//! provenance as an explicit [`BatchProvenance`] input so the wire format
//! and the consent-resolution machinery stay decoupled.

use serde_json::{json, Map, Value};

use super::partial::CompleteTrace;
use super::seal;

/// Batch-level provenance stamped on every outbound `BatchEnvelope`.
///
/// Sourced upstream (CIRISAgent#870: the shared Engine's CEG consent
/// object first, config/env fallback in the 2.7.9 interim) and passed in
/// — this builder is agnostic to where the values came from.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchProvenance {
    /// Wall-clock the batch was emitted, RFC-3339. Caller-supplied (this
    /// module never reads the clock, mirroring `orphan_sweep(now)`).
    pub batch_timestamp: String,
    /// User-consent timestamp, RFC-3339. **Hard gate:** persist 422s a
    /// batch whose `consent_timestamp` is missing or empty
    /// (TRACE_WIRE_FORMAT.md §1). Post-fold this is the CEG grant's
    /// `asserted_at`; config/env in the interim.
    pub consent_timestamp: String,
    /// Privacy / bandwidth tier of the batch — one of `generic` /
    /// `detailed` / `full_traces` (persist's [`TraceLevel`] wire form,
    /// snake_case lowercase). Constant within a batch and equal to each
    /// event's `trace_level` (§7).
    ///
    /// [`TraceLevel`]: ciris_persist::schema::TraceLevel
    pub trace_level: String,
    /// Wire-format schema version (e.g. `"2.7.9"`); gated by persist's
    /// `SUPPORTED_VERSIONS`.
    pub trace_schema_version: String,
    /// Optional consent-gated correlation block (deployment profile +
    /// consented, region-fuzzed user location). Omitted from the wire
    /// when `None` (persist's `skip_serializing_if`).
    pub correlation_metadata: Option<Value>,
}

/// Why [`build_batch_bytes`] refused to build a batch.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum BatchBuildError {
    /// No traces supplied — persist rejects an empty `events` array
    /// (`MissingField("events")`), so we refuse early with a clearer
    /// error rather than emitting bytes that will 422.
    #[error("cannot build a batch with zero traces")]
    EmptyBatch,
    /// A trace was not sealed + signed before batching. Emitting an
    /// unsigned trace would fail verification downstream; this is a
    /// programming error in the capture→seal→batch ordering.
    #[error("trace {trace_id} is unsigned (seal + sign before batching)")]
    UnsignedTrace { trace_id: String },
    /// `serde_json` failed to serialize the assembled envelope (should
    /// not happen for well-formed input; surfaced for diagnostics).
    #[error("serialize batch: {0}")]
    Serialize(String),
}

/// The wire JSON for one signed trace — TRACE_WIRE_FORMAT.md §3, the
/// agent's `CompleteTrace.to_dict`.
///
/// This is the signed canonical envelope (the 9(+1) top-level fields,
/// `strip_empty`'d components carrying `attempt_index` inside `data`)
/// **plus** the two unsigned `signature` / `signature_key_id` fields.
/// The agent's `to_dict` strips only `data` while we reuse the
/// fully-`strip_empty`'d [`build_canonical_envelope`]; the two differ
/// only if a component's *wrapper* field (`component_type` / `event_type`
/// / `timestamp` / `agent_id_hash`) is itself empty — impossible for a
/// valid component — so the emitted bytes are identical for in-spec
/// traces. Reusing the canonical builder keeps the wire trace and the
/// signed bytes structurally locked: the component `data` persist
/// re-canonicalizes at verify time is the same `data` we signed.
///
/// [`build_canonical_envelope`]: super::seal::build_canonical_envelope
fn trace_to_wire_json(trace: &CompleteTrace) -> Value {
    let mut obj = match seal::build_canonical_envelope(trace) {
        Value::Object(m) => m,
        // build_canonical_envelope always returns a JSON object.
        _ => unreachable!("canonical envelope is always a JSON object"),
    };
    // signature + signature_key_id are NOT part of the signed bytes
    // (the canonical envelope excludes them); they ride on the wire so
    // verifiers can check the trace. Present as JSON null only if unset —
    // but build_batch_bytes refuses unsigned traces, so they're Some here.
    obj.insert("signature".into(), json!(trace.signature));
    obj.insert("signature_key_id".into(), json!(trace.signature_key_id));
    Value::Object(obj)
}

/// Build the outbound batch wire bytes for a set of sealed, signed
/// traces. Each trace MUST already carry a `signature` +
/// `signature_key_id` (via [`seal::sign_trace`]); an unsigned trace is a
/// programming error ([`BatchBuildError::UnsignedTrace`]).
///
/// The bytes are the persist `BatchEnvelope` wire form
/// (TRACE_WIRE_FORMAT.md §1-3): an `events` array of
/// `{event_type:"complete_trace", trace_level, trace}` items plus the
/// batch-level provenance. Hand these to
/// `Engine::receive_and_persist(&bytes, scrubber)` (local persist) and
/// the edge outbound dispatcher (federation fan-out).
pub fn build_batch_bytes(
    traces: &[CompleteTrace],
    provenance: &BatchProvenance,
) -> Result<Vec<u8>, BatchBuildError> {
    if traces.is_empty() {
        return Err(BatchBuildError::EmptyBatch);
    }

    let mut events = Vec::with_capacity(traces.len());
    for t in traces {
        if t.signature.is_none() || t.signature_key_id.is_none() {
            return Err(BatchBuildError::UnsignedTrace {
                trace_id: t.trace_id.clone(),
            });
        }
        // BatchEvent is #[serde(tag = "event_type", rename_all =
        // "snake_case")] → the discriminant rides as an "event_type"
        // sibling key. trace_level is carried per-event (§7 gating) equal
        // to the batch level.
        events.push(json!({
            "event_type": "complete_trace",
            "trace_level": provenance.trace_level,
            "trace": trace_to_wire_json(t),
        }));
    }

    let mut envelope = Map::new();
    envelope.insert("events".into(), Value::Array(events));
    envelope.insert("batch_timestamp".into(), json!(provenance.batch_timestamp));
    envelope.insert(
        "consent_timestamp".into(),
        json!(provenance.consent_timestamp),
    );
    envelope.insert("trace_level".into(), json!(provenance.trace_level));
    envelope.insert(
        "trace_schema_version".into(),
        json!(provenance.trace_schema_version),
    );
    // Omitted entirely when absent — matches persist's
    // skip_serializing_if on the typed field.
    if let Some(cm) = &provenance.correlation_metadata {
        envelope.insert("correlation_metadata".into(), cm.clone());
    }

    serde_json::to_vec(&Value::Object(envelope))
        .map_err(|e| BatchBuildError::Serialize(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::event::{ComponentType, ReasoningEventType};
    use crate::capture::partial::{CompleteTrace, TraceComponent, TRACE_SCHEMA_VERSION};

    fn component(
        event_type: ReasoningEventType,
        ct: ComponentType,
        ts: &str,
        attempt_index: u32,
        data: Value,
    ) -> TraceComponent {
        TraceComponent {
            component_type: ct,
            event_type,
            timestamp: ts.into(),
            attempt_index,
            data,
            agent_id_hash: "deadbeef".into(),
        }
    }

    /// A sealed 2.7.9 trace with the required `deployment_profile` block
    /// and a lowercase wire `trace_level` (so persist's typed
    /// `TraceLevel` / `DeploymentProfile` deserialize). Unsigned until the
    /// test signs it.
    fn sealed_279_trace() -> CompleteTrace {
        CompleteTrace {
            trace_id: "trace-1".into(),
            thought_id: "th_abc".into(),
            task_id: Some("task-1".into()),
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-23T12:00:00+00:00".into(),
            completed_at: Some("2026-04-23T12:00:02+00:00".into()),
            components: vec![
                component(
                    ReasoningEventType::ThoughtStart,
                    ComponentType::Observation,
                    "2026-04-23T12:00:00+00:00",
                    0,
                    json!({"k_eff": 0.9, "phase": "healthy"}),
                ),
                component(
                    ReasoningEventType::ActionResult,
                    ComponentType::Action,
                    "2026-04-23T12:00:02+00:00",
                    3,
                    json!({"action": "speak"}),
                ),
            ],
            signature: None,
            signature_key_id: None,
            trace_level: Some("generic".into()),
            trace_schema_version: TRACE_SCHEMA_VERSION.into(),
            deployment_profile: Some(json!({
                "agent_role": "ally",
                "agent_template": "ally-default",
                "deployment_domain": "general",
                "deployment_type": "production",
                "deployment_region": null,
                "deployment_trust_mode": "sovereign",
            })),
        }
    }

    fn provenance() -> BatchProvenance {
        BatchProvenance {
            batch_timestamp: "2026-04-23T12:00:05+00:00".into(),
            consent_timestamp: "2026-04-01T00:00:00+00:00".into(),
            trace_level: "generic".into(),
            trace_schema_version: "2.7.9".into(),
            correlation_metadata: None,
        }
    }

    #[test]
    fn empty_batch_is_refused() {
        assert_eq!(
            build_batch_bytes(&[], &provenance()),
            Err(BatchBuildError::EmptyBatch)
        );
    }

    #[test]
    fn unsigned_trace_is_refused() {
        let t = sealed_279_trace(); // not signed
        assert_eq!(
            build_batch_bytes(&[t], &provenance()),
            Err(BatchBuildError::UnsignedTrace {
                trace_id: "trace-1".into()
            })
        );
    }

    #[test]
    fn wire_trace_carries_signature_and_attempt_index_in_data() {
        // The wire trace = canonical envelope + signature fields, with
        // attempt_index inside each component's data (not a sibling key).
        let mut t = sealed_279_trace();
        t.signature = Some("AAAA".into());
        t.signature_key_id = Some("k".into());
        let wire = trace_to_wire_json(&t);
        assert_eq!(wire["signature"], "AAAA");
        assert_eq!(wire["signature_key_id"], "k");
        // attempt_index 3 lives inside the ACTION_RESULT component's data.
        let action = &wire["components"][1];
        assert_eq!(action["event_type"], "ACTION_RESULT");
        assert_eq!(action["data"]["attempt_index"], 3);
        assert_eq!(action["data"]["action"], "speak");
        assert!(action.get("attempt_index").is_none(), "no sibling key");
    }

    #[test]
    fn batch_parses_and_verifies_through_real_persist() {
        // THE Cut-5 wire proof, no DB/Engine needed: a trace lens-core
        // seals + signs + wraps round-trips through persist's REAL
        // BatchEnvelope::from_json (typed deserialize, catches any field /
        // enum / timestamp / deployment_profile drift) and then verifies
        // under persist's OWN verify_trace (the federation verifier).
        use ciris_persist::prelude::{LocalSigner, PythonJsonDumpsCanonicalizer};
        use ciris_persist::schema::{BatchEnvelope, BatchEvent};
        use ciris_persist::verify::verify_trace;
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();
        let signer = LocalSigner::from_parts(sk, "host-unified-key".into(), None, None);

        let mut trace = sealed_279_trace();
        seal::sign_trace(&signer, &mut trace).expect("sign");

        let bytes = build_batch_bytes(&[trace], &provenance()).expect("build batch");

        // persist's real typed deserializer + all its gates (schema
        // version supported, events non-empty, data depth, 2.7.9
        // deployment_profile required).
        let env =
            BatchEnvelope::from_json(&bytes).expect("persist must parse the lens-core-built batch");
        assert_eq!(env.events.len(), 1);

        let BatchEvent::CompleteTrace { trace: ptrace, .. } = &env.events[0];
        // persist's federation verifier accepts a lens-core-sealed trace.
        verify_trace(ptrace, &PythonJsonDumpsCanonicalizer, &vk)
            .expect("persist verify_trace must accept a lens-core-sealed trace");
    }

    #[test]
    fn tampering_a_batched_trace_fails_persist_verify() {
        // Negative control: mutate a signed field after wrapping → persist's
        // verify_trace must reject. Proves the round-trip proof above isn't
        // vacuously passing.
        use ciris_persist::prelude::{LocalSigner, PythonJsonDumpsCanonicalizer};
        use ciris_persist::schema::{BatchEnvelope, BatchEvent};
        use ciris_persist::verify::verify_trace;
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let signer = LocalSigner::from_parts(sk, "k".into(), None, None);

        let mut trace = sealed_279_trace();
        seal::sign_trace(&signer, &mut trace).expect("sign");
        // Tamper a signed field AFTER signing, BEFORE wrapping.
        trace.thought_id = "swapped".into();

        let bytes = build_batch_bytes(&[trace], &provenance()).expect("build batch");
        let env = BatchEnvelope::from_json(&bytes).expect("parses (shape is valid)");
        let BatchEvent::CompleteTrace { trace: ptrace, .. } = &env.events[0];
        assert!(
            verify_trace(ptrace, &PythonJsonDumpsCanonicalizer, &vk).is_err(),
            "tampered trace must fail persist verify"
        );
    }

    // ── CIRISLensCore#43.2: 3.0.0 / JCS round-trip proof ────────────────────

    /// A 3.0.0-stamped trace (the new default after the TRACE_SCHEMA_VERSION
    /// flip). The canonical field layout is identical to the 2.7.9 shape
    /// (9 envelope fields + optional `deployment_profile`), only the
    /// canonicalizer changes. deployment_profile is OPTIONAL at 3.0.0 per
    /// persist v5.2.0 `BatchEnvelope::from_json` (the strict-require gate
    /// is `"2.7.9"` only). We include it here anyway to prove it round-trips.
    fn sealed_300_trace() -> CompleteTrace {
        CompleteTrace {
            trace_id: "trace-300".into(),
            thought_id: "th_300".into(),
            task_id: Some("task-300".into()),
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-06-08T00:00:00+00:00".into(),
            completed_at: Some("2026-06-08T00:00:02+00:00".into()),
            components: vec![
                component(
                    ReasoningEventType::ThoughtStart,
                    ComponentType::Observation,
                    "2026-06-08T00:00:00+00:00",
                    0,
                    serde_json::json!({"thought": "hello JCS"}),
                ),
                component(
                    ReasoningEventType::ActionResult,
                    ComponentType::Action,
                    "2026-06-08T00:00:02+00:00",
                    0,
                    serde_json::json!({"action": "speak"}),
                ),
            ],
            signature: None,
            signature_key_id: None,
            trace_level: Some("generic".into()),
            trace_schema_version: "3.0.0".into(),
            deployment_profile: Some(serde_json::json!({
                "agent_role": "ally",
                "agent_template": "ally-default",
                "deployment_domain": "general",
                "deployment_type": "production",
                "deployment_region": null,
                "deployment_trust_mode": "sovereign",
            })),
        }
    }

    fn provenance_300() -> BatchProvenance {
        BatchProvenance {
            batch_timestamp: "2026-06-08T00:00:05+00:00".into(),
            consent_timestamp: "2026-04-01T00:00:00+00:00".into(),
            trace_level: "generic".into(),
            trace_schema_version: "3.0.0".into(),
            correlation_metadata: None,
        }
    }

    /// THE 3.0.0 / JCS wire proof (CIRISLensCore#43.2):
    ///
    /// A trace stamped `"3.0.0"` that lens-core seals + JCS-signs + wraps
    /// must round-trip through persist's `BatchEnvelope::from_json` AND
    /// verify under persist's `verify_trace` with `JcsCanonicalizer`.
    ///
    /// This proves the sign/verify JCS match: `canonical_bytes` dispatched
    /// to JCS (V2Jcs via `canon_version_for_trace_schema("3.0.0")`), and
    /// `verify_trace` — which uses the CALLER-SUPPLIED canonicalizer to
    /// canonicalize the already-dispatched canonical value — verifies
    /// correctly when given `JcsCanonicalizer`.
    #[test]
    fn batch_300_parses_and_verifies_through_real_persist_jcs() {
        use ciris_persist::prelude::LocalSigner;
        use ciris_persist::schema::{BatchEnvelope, BatchEvent};
        use ciris_persist::verify::canonical::JcsCanonicalizer;
        use ciris_persist::verify::verify_trace;
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[43u8; 32]);
        let vk = sk.verifying_key();
        let signer = LocalSigner::from_parts(sk, "jcs-host-key".into(), None, None);

        let mut trace = sealed_300_trace();
        seal::sign_trace(&signer, &mut trace).expect("sign 3.0.0");

        let bytes = build_batch_bytes(&[trace], &provenance_300()).expect("build 3.0.0 batch");

        // persist's real typed deserializer — 3.0.0 is in SUPPORTED_VERSIONS;
        // deployment_profile is NOT required at 3.0.0 (but present here).
        let env = BatchEnvelope::from_json(&bytes)
            .expect("persist must parse a lens-core-built 3.0.0 batch");
        assert_eq!(env.events.len(), 1);

        let BatchEvent::CompleteTrace { trace: ptrace, .. } = &env.events[0];
        // verify_trace dispatches field layout by schema version ("3.0.0" →
        // canonical_payload_value_v279), then calls the supplied canonicalizer
        // on the value. We supply JcsCanonicalizer to match the signing path.
        verify_trace(ptrace, &JcsCanonicalizer, &vk)
            .expect("persist verify_trace must accept a 3.0.0 JCS-signed lens-core trace");
    }

    /// Negative control for the 3.0.0 / JCS path (CIRISLensCore#43.2):
    ///
    /// A `"3.0.0"` trace JCS-signed by lens-core MUST FAIL `verify_trace`
    /// when the caller passes `PythonJsonDumpsCanonicalizer` (the old path).
    /// This proves the dispatch matters: the two canonicalizers produce
    /// different bytes on the canonical value, so the wrong one causes a
    /// `SignatureMismatch`. For a pure-ASCII trace the two canonicalizers
    /// agree — so we include a non-ASCII character in the data to guarantee
    /// divergence (the CIRISAgent#871 measured corpus: any non-Latin text
    /// or the ⚠️ emoji).
    #[test]
    fn batch_300_jcs_signed_fails_with_python_canonicalizer() {
        use ciris_persist::prelude::{LocalSigner, PythonJsonDumpsCanonicalizer};
        use ciris_persist::schema::{BatchEnvelope, BatchEvent};
        use ciris_persist::verify::verify_trace;
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[44u8; 32]);
        let vk = sk.verifying_key();
        let signer = LocalSigner::from_parts(sk, "jcs-neg-key".into(), None, None);

        // Non-ASCII in the data — triggers Python-vs-JCS divergence
        // (Python emits \\u26a0, JCS emits raw ⚠ UTF-8 bytes).
        let mut trace = sealed_300_trace();
        trace.components[0].data = serde_json::json!({"note": "⚠️ attestation"});
        seal::sign_trace(&signer, &mut trace).expect("sign 3.0.0");

        let bytes = build_batch_bytes(&[trace], &provenance_300()).expect("build batch");
        let env = BatchEnvelope::from_json(&bytes).expect("parses (shape valid)");
        let BatchEvent::CompleteTrace { trace: ptrace, .. } = &env.events[0];

        // 3.0.0 JCS-signed trace MUST NOT verify under PythonJsonDumps.
        assert!(
            verify_trace(ptrace, &PythonJsonDumpsCanonicalizer, &vk).is_err(),
            "3.0.0 JCS-signed trace must fail verify under PythonJsonDumpsCanonicalizer \
             (the dispatch mismatch mints invalid signatures on non-ASCII — CIRISAgent#871 trap)"
        );
    }
}
