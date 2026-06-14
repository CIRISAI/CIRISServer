//! Trace sealing — canonical signing-bytes construction for a sealed
//! [`CompleteTrace`] (CIRISLensCore#11 Cut 3, updated CIRISLensCore#43.2).
//!
//! # The signature-critical contract
//!
//! When `ACTION_RESULT` seals a trace, lens-core canonicalizes it,
//! **Ed25519**-signs the canonical bytes (via the host `Engine`'s
//! signing identity), and persists it. (Trace signing is Ed25519-only —
//! the hybrid Ed25519+ML-DSA-65 pair is the detection-event /
//! attestation surface, not traces.) The **canonical bytes must be
//! byte-identical** to what every federation verifier recomputes, or
//! the signature fails to verify. This module owns the canonical-
//! envelope *structure*; the byte serialization is delegated to
//! persist's **version-aware dispatch** — `canon_version_for_trace_schema`
//! + `canonicalizer_for` (CIRISPersist#171 / v4.6.0 / v4.15.0 #871).
//!
//! # JCS / 3.0.0 era (CIRISLensCore#43.2)
//!
//! `TRACE_SCHEMA_VERSION` is now `"3.0.0"` — the CIRISAgent 2.9.6 JCS
//! cutover. [`canonical_bytes`] dispatches by the trace's actual
//! `trace_schema_version` field:
//!
//! - `"2.7.x"` (major < 3) → `V1Python` → `PythonJsonDumpsCanonicalizer`
//!   (`json.dumps(sort_keys=True, separators=(",",":"))`), byte-identical
//!   to pre-cutover CIRISAgent output. Pre-cut rows in the corpus continue
//!   to verify under the legacy canonicalizer.
//! - `"3.0.0"` and later (major ≥ 3) → `V2Jcs` → `JcsCanonicalizer`
//!   (RFC 8785), the post-cutover canonicalization. **Stamping 3.0.0 and
//!   sealing with PythonJsonDumps mints signatures the verifier rejects on
//!   non-ASCII — the CIRISAgent#871 trap.** Both halves of the flip MUST
//!   land together; this module enforces that by dispatching through the
//!   same `canon_version_for_trace_schema` gate persist's verifier uses.
//!
//! The dispatch mirrors `ciris_persist::verify::ed25519::verify_trace`'s
//! *canonicalizer selection* exactly (same function, same gate), so
//! sign and verify are byte-identical by construction. Lens-core never
//! re-implements canonicalization rules (MISSION.md boundary;
//! CIRISPersist#7 lesson).
//!
//! # The 9(+1)-field canonical (FSD/TRACE_WIRE_FORMAT.md §8, post-
//! CIRISAgent#710)
//!
//! ```text
//! {
//!   trace_id, thought_id, task_id, agent_id_hash,
//!   started_at, completed_at, trace_level, trace_schema_version,
//!   components: [ strip_empty({agent_id_hash, component_type, data,
//!                              event_type, timestamp}), … ],
//!   deployment_profile?   // 2.7.9+ cohort block, present iff set
//! }
//! ```
//!
//! `strip_empty` (recursive) drops `null` / `""` / `[]` / `{}` — but
//! **keeps `0` and `false`** (valid values, CIRISAgent
//! `_strip_empty`). The per-component `agent_id_hash` is denormalized
//! from the trace envelope (2.7.9 / CIRISAgent#712 item 1).
//!
//! # This module
//!
//! The pure, signature-critical core: [`build_canonical_envelope`] /
//! [`canonical_bytes`] (the signed bytes) + [`apply_signature`] /
//! [`verify_trace_signature`] (Ed25519 stamp + the federation-verifier
//! algorithm). No Engine, no I/O — fully unit-tested incl. a sign→verify
//! round-trip. The thin async glue (`engine.local_sign(canonical_bytes)`
//! → `apply_signature` → `receive_and_persist`) lands with the Engine
//! integration (Cut 4).

use serde_json::{json, Map, Value};

use super::partial::CompleteTrace;

/// Recursively strip `null` / `""` / `[]` / `{}` from a JSON value,
/// matching CIRISAgent's `_strip_empty`. **`0` and `false` are kept** —
/// they are valid values, not "empty". Object keys whose stripped value
/// is empty are dropped; array elements that are `null` are dropped
/// (other empties survive inside arrays, mirroring the Python which only
/// filters `None` from lists).
pub fn strip_empty(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                let stripped = strip_empty(v);
                if !is_empty(&stripped) {
                    out.insert(k, stripped);
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(
            arr.into_iter()
                .filter(|v| !v.is_null())
                .map(strip_empty)
                .collect(),
        ),
        other => other,
    }
}

/// Is this value one of the four "empty" forms the agent strips
/// (`null` / `""` / `[]` / `{}`)? Numbers (incl. `0`) and booleans
/// (incl. `false`) are never empty.
fn is_empty(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

/// Build the canonical signing envelope for a sealed trace. Pure — no
/// Engine, no I/O. The returned [`Value`] is handed to persist's
/// `canonicalize_envelope_for_signing` (see [`canonical_bytes`]) for the
/// bytes; this function owns only the *shape*.
///
/// `task_id` / `completed_at` are emitted as JSON `null` when absent
/// (they are top-level envelope fields the verifier expects present;
/// `strip_empty` applies to the per-component payload, NOT the nine
/// top-level keys — matching the agent's `_build_canonical_message`
/// which strips only inside `components`).
pub fn build_canonical_envelope(trace: &CompleteTrace) -> Value {
    let components: Vec<Value> = trace
        .components
        .iter()
        .map(|c| {
            // Per-component 5-field shape, then strip_empty (so an empty
            // `data` / blank field drops out of the signed bytes exactly
            // as the agent emits).
            let agent_id_hash = if c.agent_id_hash.is_empty() {
                trace.agent_id_hash.clone()
            } else {
                c.agent_id_hash.clone()
            };
            strip_empty(json!({
                "agent_id_hash": agent_id_hash,
                "component_type": c.component_type.as_wire_str(),
                // attempt_index is injected INSIDE data (the agent's
                // signed-canonical shape, services.py:1698) — never a
                // sibling key. Shared single injection point with the wire
                // path so the two can't drift.
                "data": c.data_with_attempt_index(),
                "event_type": c.event_type.as_wire_str(),
                "timestamp": c.timestamp,
            }))
        })
        .collect();

    let mut envelope = Map::new();
    envelope.insert("trace_id".into(), json!(trace.trace_id));
    envelope.insert("thought_id".into(), json!(trace.thought_id));
    envelope.insert("task_id".into(), json!(trace.task_id)); // null when None
    envelope.insert("agent_id_hash".into(), json!(trace.agent_id_hash));
    envelope.insert("started_at".into(), json!(trace.started_at));
    envelope.insert("completed_at".into(), json!(trace.completed_at)); // null when unsealed
    envelope.insert("trace_level".into(), json!(trace.trace_level));
    envelope.insert(
        "trace_schema_version".into(),
        json!(trace.trace_schema_version),
    );
    envelope.insert("components".into(), Value::Array(components));
    // deployment_profile is present in the signed bytes iff the trace
    // carries it (2.7.9 cohort block; absent at 2.7.0).
    if let Some(dp) = &trace.deployment_profile {
        envelope.insert("deployment_profile".into(), dp.clone());
    }
    Value::Object(envelope)
}

/// Canonical signing bytes for a sealed trace: build the envelope, then
/// dispatch to persist's version-aware canonicalizer — the federation-wide
/// canonicalization authority.
///
/// Dispatches by `trace.trace_schema_version` via the same gate persist's
/// verifier uses (`canon_version_for_trace_schema` + `canonicalizer_for`),
/// so sign and verify are byte-identical by construction:
///
///   - major < 3 (e.g. `"2.7.9"`) → `V1Python` → `PythonJsonDumpsCanonicalizer`
///   - major ≥ 3 (e.g. `"3.0.0"`) → `V2Jcs` → `JcsCanonicalizer` (RFC 8785)
///
/// **Atomicity note:** stamping `"3.0.0"` and then calling this function seals
/// with JCS — the two halves of the flip always travel together. Calling with
/// a trace whose `trace_schema_version` is `"3.0.0"` but the old
/// `PythonJsonDumpsCanonicalizer` path would mint a signature the verifier
/// rejects (the CIRISAgent#871 trap); this dispatch prevents that.
///
/// The error is stringified to avoid coupling to persist's internal error enum.
pub fn canonical_bytes(trace: &CompleteTrace) -> Result<Vec<u8>, String> {
    use ciris_persist::verify::canonical::canonicalizer_for;
    use ciris_persist::verify::ed25519::canon_version_for_trace_schema;

    let envelope = build_canonical_envelope(trace);
    let canon_version = canon_version_for_trace_schema(&trace.trace_schema_version);
    let canonicalizer = canonicalizer_for(canon_version);
    canonicalizer
        .canonicalize_value(&envelope)
        .map_err(|e| format!("canonicalize trace: {e}"))
}

// ── Signature application + verification ────────────────────────────
//
// Trace signing is **Ed25519-only** over the canonical bytes (NOT a
// hybrid Ed25519+ML-DSA pair — that is the detection-event / attestation
// surface). The signature is stored URL-safe-base64-no-pad, the
// `signature_key_id` names the signing key. This mirrors CIRISAgent's
// `Ed25519TraceSigner.sign_trace` (`unified_key.sign_base64(message)`) +
// `verify_trace` (`Ed25519.verify(sig, message)`) exactly, so a trace
// lens-core seals verifies under the agent's verify path and vice-versa.

/// Encode an Ed25519 signature for the `CompleteTrace.signature` field:
/// URL-safe base64, no padding — the form CIRISAgent's `verify_trace`
/// decodes (it re-appends `==` before `urlsafe_b64decode`).
pub fn encode_signature(sig_bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig_bytes)
}

/// Stamp a computed signature onto a sealed trace. Pure — the caller
/// (the Engine-coupled `sign_trace`, Cut 3b glue) obtains `sig_bytes`
/// from `engine.local_sign(canonical_bytes(trace))` and the host's
/// signing `key_id`.
pub fn apply_signature(trace: &mut CompleteTrace, sig_bytes: &[u8], key_id: &str) {
    trace.signature = Some(encode_signature(sig_bytes));
    trace.signature_key_id = Some(key_id.to_string());
}

/// Verify a sealed trace's Ed25519 signature against `verifying_key`,
/// recomputing the canonical bytes (sign/verify can never drift — both
/// go through [`canonical_bytes`]). Returns `false` on any failure
/// (missing/garbled signature, canonicalization error, bad signature) —
/// the same fail-closed shape as CIRISAgent's `verify_trace`. This is
/// the federation-verifier algorithm; a trace lens-core seals must pass
/// it under the producer's public key.
pub fn verify_trace_signature(
    trace: &CompleteTrace,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> bool {
    use base64::Engine as _;
    use ed25519_dalek::Verifier;

    let Some(sig_b64) = &trace.signature else {
        return false;
    };
    let Ok(sig_raw) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig_b64) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_raw.as_slice()) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
    let Ok(message) = canonical_bytes(trace) else {
        return false;
    };
    verifying_key.verify(&message, &signature).is_ok()
}

/// Error sealing (signing) a trace.
#[derive(Debug, thiserror::Error)]
pub enum TraceSealError {
    /// The canonical envelope couldn't be serialized (shouldn't happen
    /// for a well-formed trace; surfaced for diagnostics).
    #[error("canonicalize: {0}")]
    Canonicalize(String),
    /// The host signer failed to produce the Ed25519 signature.
    #[error("sign: {0}")]
    Sign(#[from] ciris_persist::prelude::LocalSignerError),
}

/// Seal a trace: compute its canonical bytes, Ed25519-sign them with the
/// host's signing identity, and stamp the signature + `signature_key_id`
/// onto the trace. The signing half of the client-mode seal flow
/// (Cut 4). Synchronous — trace signing is Ed25519-only, and
/// `LocalSigner::sign_ed25519` is a hot-path sync call (the hybrid PQC
/// pair is the detection-event surface, not traces).
///
/// `signer` is the host's [`LocalSigner`] — in cohabitation it wraps the
/// agent's unified key arriving across the `Engine` boundary, so a trace
/// lens-core seals here is signed under the same identity (and verifies
/// under the same key) as one the agent would have signed itself. After
/// this returns `Ok`, the trace is ready for `receive_and_persist` +
/// upstream fan-out (the Engine/Edge integration that lands with the
/// `LensCore::client` surface).
pub fn sign_trace(
    signer: &ciris_persist::prelude::LocalSigner,
    trace: &mut CompleteTrace,
) -> Result<(), TraceSealError> {
    let bytes = canonical_bytes(trace).map_err(TraceSealError::Canonicalize)?;
    let sig = signer.sign_ed25519(&bytes)?;
    apply_signature(trace, &sig, signer.key_id());
    Ok(())
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
        data: Value,
    ) -> TraceComponent {
        TraceComponent {
            component_type: ct,
            event_type,
            timestamp: ts.into(),
            attempt_index: 0,
            data,
            agent_id_hash: "agenthash".into(),
        }
    }

    fn sealed_trace() -> CompleteTrace {
        CompleteTrace {
            trace_id: "trace-1".into(),
            thought_id: "t1".into(),
            task_id: Some("task-1".into()),
            agent_id_hash: "agenthash".into(),
            started_at: "2026-06-08T00:00:00Z".into(),
            completed_at: Some("2026-06-08T00:00:02Z".into()),
            components: vec![
                component(
                    ReasoningEventType::ThoughtStart,
                    ComponentType::Observation,
                    "2026-06-08T00:00:00Z",
                    json!({"thought": "hi"}),
                ),
                component(
                    ReasoningEventType::ActionResult,
                    ComponentType::Action,
                    "2026-06-08T00:00:02Z",
                    json!({"action": "SPEAK"}),
                ),
            ],
            signature: None,
            signature_key_id: None,
            trace_level: Some("FULL_TRACES".into()),
            trace_schema_version: TRACE_SCHEMA_VERSION.into(),
            deployment_profile: None,
        }
    }

    #[test]
    fn strip_empty_keeps_zero_and_false() {
        // The load-bearing subtlety: 0 and false are NOT empty.
        let v = json!({"a": 0, "b": false, "c": null, "d": "", "e": [], "f": {}, "g": "x"});
        let stripped = strip_empty(v);
        assert_eq!(stripped, json!({"a": 0, "b": false, "g": "x"}));
    }

    #[test]
    fn strip_empty_is_recursive() {
        let v = json!({"outer": {"keep": 1, "drop": "", "nested": {"empty": null}}});
        // inner `nested` becomes {} after its only key drops → then drops itself.
        assert_eq!(strip_empty(v), json!({"outer": {"keep": 1}}));
    }

    #[test]
    fn strip_empty_filters_null_from_arrays() {
        let v = json!({"xs": [1, null, 2, "", 0]});
        // Only null is filtered from arrays (matching the Python list comp);
        // "" and 0 survive inside the array.
        assert_eq!(strip_empty(v), json!({"xs": [1, 2, "", 0]}));
    }

    #[test]
    fn envelope_has_nine_top_level_fields_no_deployment_profile() {
        let env = build_canonical_envelope(&sealed_trace());
        let obj = env.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "agent_id_hash",
                "completed_at",
                "components",
                "started_at",
                "task_id",
                "thought_id",
                "trace_id",
                "trace_level",
                "trace_schema_version",
            ]
        );
    }

    #[test]
    fn deployment_profile_present_iff_set() {
        let mut t = sealed_trace();
        assert!(build_canonical_envelope(&t)
            .get("deployment_profile")
            .is_none());
        t.deployment_profile = Some(json!({"agent_role": "scout"}));
        assert_eq!(
            build_canonical_envelope(&t)["deployment_profile"],
            json!({"agent_role": "scout"})
        );
    }

    #[test]
    fn component_carries_five_field_shape_and_wire_strings() {
        let env = build_canonical_envelope(&sealed_trace());
        let comp0 = &env["components"][0];
        // component_type + event_type are the WIRE strings, not enum debug.
        assert_eq!(comp0["component_type"], "observation");
        assert_eq!(comp0["event_type"], "THOUGHT_START");
        assert_eq!(comp0["agent_id_hash"], "agenthash");
        assert_eq!(comp0["timestamp"], "2026-06-08T00:00:00Z");
        // attempt_index is injected INSIDE data (agent services.py:1698),
        // not a sibling key. The `component()` helper builds attempt_index 0.
        assert_eq!(comp0["data"], json!({"thought": "hi", "attempt_index": 0}));
    }

    #[test]
    fn component_agent_id_hash_falls_back_to_trace() {
        let mut t = sealed_trace();
        t.components[0].agent_id_hash = String::new(); // blank → denormalize from trace
        let env = build_canonical_envelope(&t);
        assert_eq!(env["components"][0]["agent_id_hash"], "agenthash");
    }

    #[test]
    fn task_id_and_completed_at_null_when_absent() {
        let mut t = sealed_trace();
        t.task_id = None;
        t.completed_at = None;
        let env = build_canonical_envelope(&t);
        // Top-level fields stay present as null (strip_empty applies only
        // inside components) — the verifier expects all nine keys.
        assert!(env.get("task_id").is_some());
        assert_eq!(env["task_id"], Value::Null);
        assert_eq!(env["completed_at"], Value::Null);
    }

    #[test]
    fn canonical_bytes_are_byte_exact_sorted_compact() {
        // Signature-critical: a 2.7.9-era trace routes through V1Python →
        // PythonJsonDumpsCanonicalizer (json.dumps sort_keys=True,
        // separators=(",",":")) — keeping pre-cut 2.7.x corpus rows
        // verifiable. Explicit "2.7.9" pins the dispatch path so this test
        // is not affected by the TRACE_SCHEMA_VERSION flip to "3.0.0".
        let t = CompleteTrace {
            trace_id: "tr".into(),
            thought_id: "th".into(),
            task_id: None,
            agent_id_hash: "ah".into(),
            started_at: "2026-06-08T00:00:00Z".into(),
            completed_at: Some("2026-06-08T00:00:01Z".into()),
            components: vec![TraceComponent {
                component_type: ComponentType::Action,
                event_type: ReasoningEventType::ActionResult,
                timestamp: "2026-06-08T00:00:01Z".into(),
                attempt_index: 0,
                data: json!({"k": "v"}),
                // Equal to the trace's hash (FSD §712: agents MUST emit equal).
                agent_id_hash: "ah".into(),
            }],
            signature: None,
            signature_key_id: None,
            trace_level: Some("GENERIC".into()),
            trace_schema_version: "2.7.9".into(), // V1Python path — explicit
            deployment_profile: None,
        };
        let bytes = canonical_bytes(&t).expect("canonicalize");
        let got = String::from_utf8(bytes).unwrap();
        // Sorted keys, compact separators. components sorted-keys-per-object.
        // attempt_index 0 is injected inside `data` (agent services.py:1698)
        // — sorts before "k". This is the 2.7.9 / PythonJsonDumps wire shape.
        let expected = concat!(
            r#"{"agent_id_hash":"ah","completed_at":"2026-06-08T00:00:01Z","#,
            r#""components":[{"agent_id_hash":"ah","component_type":"action","#,
            r#""data":{"attempt_index":0,"k":"v"},"event_type":"ACTION_RESULT","#,
            r#""timestamp":"2026-06-08T00:00:01Z"}],"started_at":"2026-06-08T00:00:00Z","#,
            r#""task_id":null,"thought_id":"th","trace_id":"tr","#,
            r#""trace_level":"GENERIC","trace_schema_version":"2.7.9"}"#
        );
        assert_eq!(got, expected);
    }

    #[test]
    fn encode_signature_is_urlsafe_no_pad() {
        // 64-byte Ed25519 sig → 86-char URL-safe base64, no '=' padding,
        // no '+'/'/' (the form the agent's verify_trace decodes).
        let sig = [0xFBu8; 64];
        let enc = encode_signature(&sig);
        assert_eq!(enc.len(), 86);
        assert!(!enc.contains('='));
        assert!(!enc.contains('+') && !enc.contains('/'));
    }

    #[test]
    fn sign_verify_round_trip_matches_agent_algorithm() {
        // The signature-critical end-to-end proof, no Engine needed:
        // Ed25519-sign canonical_bytes, stamp via apply_signature, and
        // verify_trace_signature (recompute canonical + Ed25519-verify)
        // passes — exactly CIRISAgent's sign_trace/verify_trace pair.
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[7u8; 32]); // deterministic, no rng
        let vk = sk.verifying_key();

        let mut t = sealed_trace();
        let msg = canonical_bytes(&t).expect("canonicalize");
        let sig = sk.sign(&msg);
        apply_signature(&mut t, &sig.to_bytes(), "agent-unified-key");

        assert_eq!(t.signature_key_id.as_deref(), Some("agent-unified-key"));
        assert!(
            verify_trace_signature(&t, &vk),
            "freshly signed trace must verify"
        );
    }

    #[test]
    fn tampering_any_signed_field_invalidates() {
        // Mutating ANY canonical field after signing must break verify —
        // that's the whole point of binding provenance into the bytes.
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let vk = sk.verifying_key();

        let mut t = sealed_trace();
        let sig = sk.sign(&canonical_bytes(&t).unwrap());
        apply_signature(&mut t, &sig.to_bytes(), "k");
        assert!(verify_trace_signature(&t, &vk));

        // Tamper the trace_id (a top-level signed field).
        let mut tampered = t.clone();
        tampered.trace_id = "swapped".into();
        assert!(!verify_trace_signature(&tampered, &vk));

        // Tamper a component's data (inside the signed components array).
        let mut tampered2 = t.clone();
        tampered2.components[0].data = json!({"thought": "EVIL"});
        assert!(!verify_trace_signature(&tampered2, &vk));

        // Wrong key fails too.
        let other = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        assert!(!verify_trace_signature(&t, &other));
    }

    #[test]
    fn sign_trace_with_real_persist_signer_round_trips() {
        // End-to-end: lens-core's sign_trace using the REAL persist
        // LocalSigner.sign_ed25519 produces a signature that
        // verify_trace_signature (= the agent's verify_trace algorithm)
        // accepts. Proves the Engine-sign glue, not just the algorithm.
        use ciris_persist::prelude::LocalSigner;
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();
        // from_parts: in-memory test signer over the same Ed25519 key
        // (no seed file, no PQC — traces are Ed25519-only).
        let signer = LocalSigner::from_parts(sk, "host-unified-key".into(), None, None);

        let mut t = sealed_trace();
        sign_trace(&signer, &mut t).expect("sign");

        assert_eq!(t.signature_key_id.as_deref(), Some("host-unified-key"));
        assert!(t.signature.is_some());
        assert!(
            verify_trace_signature(&t, &vk),
            "trace signed via persist LocalSigner must verify under the agent's algorithm"
        );
        // And tampering still breaks it post-real-sign.
        let mut tampered = t.clone();
        tampered.thought_id = "swapped".into();
        assert!(!verify_trace_signature(&tampered, &vk));
    }

    #[test]
    fn verify_fails_closed_on_missing_or_garbled_signature() {
        use ed25519_dalek::SigningKey;
        let vk = SigningKey::from_bytes(&[3u8; 32]).verifying_key();
        let mut t = sealed_trace();
        // No signature → false (not a panic).
        assert!(!verify_trace_signature(&t, &vk));
        // Non-base64 garbage → false.
        t.signature = Some("!!!not base64!!!".into());
        assert!(!verify_trace_signature(&t, &vk));
        // Right base64 but wrong length → false.
        t.signature = Some(encode_signature(&[0u8; 10]));
        assert!(!verify_trace_signature(&t, &vk));
    }

    // ── Cross-implementation parity harness (CIRISLensCore#11 Cut 5) ─────
    //
    // The hand-written `canonical_bytes_are_byte_exact_*` test above pins
    // one string we wrote by hand. This harness instead pins lens-core's
    // canonical bytes against the AGENT's REAL `_build_canonical_message`
    // output, captured on a battery of fixtures by
    // `tests/parity/generate_canonical_fixtures.py` and committed as
    // `tests/parity/canonical_fixtures.json`. It catches divergences a
    // hand-written string can't reach — `ensure_ascii` unicode escaping
    // (`café` → `café`), Python float repr (`-1.5e10` →
    // `-15000000000.0`), 0/false retention, empty-field stripping, and the
    // full event-type → component-type taxonomy — across the
    // serde_json/PythonJsonDumpsCanonicalizer boundary. Hermetic: CI runs
    // it against the committed JSON with NO agent checkout. Regenerate the
    // fixtures when the agent's §8 format moves; a fixtures diff IS the
    // wire-format change.

    #[derive(serde::Deserialize)]
    struct ParityFixture {
        name: String,
        trace: TraceSpec,
        expected_canonical: String,
    }

    #[derive(serde::Deserialize)]
    struct TraceSpec {
        trace_id: String,
        thought_id: String,
        task_id: Option<String>,
        agent_id_hash: String,
        started_at: String,
        completed_at: Option<String>,
        trace_level: Option<String>,
        trace_schema_version: String,
        deployment_profile: Option<Value>,
        components: Vec<CompSpec>,
    }

    #[derive(serde::Deserialize)]
    struct CompSpec {
        event_type: String,
        component_type: String,
        timestamp: String,
        agent_id_hash: String,
        attempt_index: u32,
        data: Value,
    }

    fn trace_from_spec(spec: TraceSpec) -> CompleteTrace {
        let components = spec
            .components
            .into_iter()
            .map(|c| {
                let event_type = ReasoningEventType::parse(&c.event_type)
                    .unwrap_or_else(|| panic!("fixture event_type {:?} must parse", c.event_type));
                // lens-core derives component_type from event_type; assert the
                // agent's explicit component_type agrees — this locks the
                // taxonomy mapping across both implementations.
                let derived = event_type.component_type();
                assert_eq!(
                    derived.as_wire_str(),
                    c.component_type,
                    "taxonomy drift: {} maps to {} in lens-core but the agent fixture says {}",
                    c.event_type,
                    derived.as_wire_str(),
                    c.component_type,
                );
                TraceComponent {
                    component_type: derived,
                    event_type,
                    timestamp: c.timestamp,
                    attempt_index: c.attempt_index,
                    data: c.data,
                    agent_id_hash: c.agent_id_hash,
                }
            })
            .collect();
        CompleteTrace {
            trace_id: spec.trace_id,
            thought_id: spec.thought_id,
            task_id: spec.task_id,
            agent_id_hash: spec.agent_id_hash,
            started_at: spec.started_at,
            completed_at: spec.completed_at,
            components,
            signature: None,
            signature_key_id: None,
            trace_level: spec.trace_level,
            trace_schema_version: spec.trace_schema_version,
            deployment_profile: spec.deployment_profile,
        }
    }

    #[test]
    fn canonical_bytes_match_agent_fixtures() {
        // Committed fixtures = the agent's real signed bytes. Embedded at
        // compile time so the test is hermetic (no agent checkout in CI).
        const FIXTURES: &str = include_str!("../../tests/parity/canonical_fixtures.json");
        let fixtures: Vec<ParityFixture> =
            serde_json::from_str(FIXTURES).expect("parity fixtures must deserialize");
        assert!(
            fixtures.len() >= 7,
            "expected the full fixture battery, got {}",
            fixtures.len()
        );

        for fixture in fixtures {
            let name = fixture.name.clone();
            let expected = fixture.expected_canonical.clone();
            let trace = trace_from_spec(fixture.trace);
            let bytes = canonical_bytes(&trace)
                .unwrap_or_else(|e| panic!("[{name}] canonicalize failed: {e}"));
            let got = String::from_utf8(bytes)
                .unwrap_or_else(|e| panic!("[{name}] canonical bytes not UTF-8: {e}"));
            assert_eq!(
                got, expected,
                "[{name}] lens-core canonical bytes diverge from the agent's signed bytes\n  \
                 lens: {got}\n  agent: {expected}"
            );
        }
    }

    // ── CIRISLensCore#43.2: JCS / 3.0.0 dispatch proofs ─────────────────

    /// Dispatch gate: `"2.7.9"` routes to PythonJsonDumps; `"3.0.0"` routes
    /// to JCS (RFC 8785). For ASCII-only payload the two canonicalizers
    /// produce identical bytes — divergence only appears on non-ASCII. This
    /// test asserts the routing itself (not the bytes) by confirming that a
    /// trace with non-ASCII content produces DIFFERENT bytes under the two
    /// schema versions, proving the dispatch gate is live.
    #[test]
    fn dispatch_routes_v1python_for_279_and_v2jcs_for_300() {
        // Non-ASCII in a component field triggers the Python-vs-JCS divergence.
        let mut t279 = CompleteTrace {
            trace_id: "tr".into(),
            thought_id: "th".into(),
            task_id: None,
            agent_id_hash: "ah".into(),
            started_at: "2026-06-08T00:00:00Z".into(),
            completed_at: Some("2026-06-08T00:00:01Z".into()),
            components: vec![TraceComponent {
                component_type: ComponentType::Action,
                event_type: ReasoningEventType::ActionResult,
                timestamp: "2026-06-08T00:00:01Z".into(),
                attempt_index: 0,
                // U+00E9 é — ASCII-only agent_id_hash but non-ASCII data
                // is enough to split Python (\\u00e9 escape) vs JCS (raw UTF-8).
                data: json!({"note": "caf\u{00e9}"}),
                agent_id_hash: "ah".into(),
            }],
            signature: None,
            signature_key_id: None,
            trace_level: Some("GENERIC".into()),
            trace_schema_version: "2.7.9".into(),
            deployment_profile: None,
        };
        let mut t300 = t279.clone();
        t300.trace_schema_version = "3.0.0".into();

        let bytes_279 = canonical_bytes(&t279).expect("canonicalize 2.7.9");
        let bytes_300 = canonical_bytes(&t300).expect("canonicalize 3.0.0");

        let s279 = String::from_utf8(bytes_279).unwrap();
        let s300 = String::from_utf8(bytes_300).unwrap();

        // Python emits \\u00e9 for é; JCS emits raw UTF-8 é.
        assert!(
            s279.contains("\\u00e9"),
            "2.7.9 path must use Python-compat (\\u00e9 escape), got: {s279}"
        );
        assert!(
            s300.contains('\u{00e9}') && !s300.contains("\\u00e9"),
            "3.0.0 path must use JCS (raw UTF-8 é, no escape), got: {s300}"
        );
        assert_ne!(
            s279, s300,
            "V1Python and V2Jcs must produce different bytes on non-ASCII"
        );

        // Baseline: ASCII-only traces produce IDENTICAL bytes under both paths
        // (the two canonicalizers agree on pure-ASCII — no false divergence).
        t279.components[0].data = json!({"note": "ascii only"});
        t300.components[0].data = json!({"note": "ascii only"});
        let ascii_279 = canonical_bytes(&t279).expect("ascii 2.7.9");
        let ascii_300 = canonical_bytes(&t300).expect("ascii 3.0.0");
        // Only trace_schema_version differs in the output — the data part is identical.
        let ascii_279_s = String::from_utf8(ascii_279).unwrap();
        let ascii_300_s = String::from_utf8(ascii_300).unwrap();
        // Both contain the same data encoding (no divergence on ASCII).
        assert!(ascii_279_s.contains("\"note\":\"ascii only\""));
        assert!(ascii_300_s.contains("\"note\":\"ascii only\""));
    }

    /// 3.0.0 sign→verify round-trip via [`verify_trace_signature`].
    ///
    /// A trace stamped `"3.0.0"`, signed via our dispatch-aware `canonical_bytes` +
    /// Ed25519, must verify under the same path. Proves the lens-core-internal JCS
    /// sign/verify match.
    #[test]
    fn sign_verify_round_trip_300_via_internal_verifier() {
        use ed25519_dalek::{Signer, SigningKey};

        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let vk = sk.verifying_key();

        let mut t = sealed_trace(); // TRACE_SCHEMA_VERSION = "3.0.0" after the flip
        assert_eq!(
            t.trace_schema_version, "3.0.0",
            "sealed_trace() must use the 3.0.0 TRACE_SCHEMA_VERSION default"
        );

        let msg = canonical_bytes(&t).expect("canonicalize 3.0.0");
        let sig = sk.sign(&msg);
        apply_signature(&mut t, &sig.to_bytes(), "jcs-test-key");

        assert!(
            verify_trace_signature(&t, &vk),
            "3.0.0 / JCS signed trace must verify under verify_trace_signature (same dispatch)"
        );

        // Tamper → must reject.
        let mut tampered = t.clone();
        tampered.trace_id = "evil".into();
        assert!(
            !verify_trace_signature(&tampered, &vk),
            "tampered 3.0.0 trace must not verify"
        );
    }
}
