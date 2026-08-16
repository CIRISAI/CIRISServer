//! **The scrubber the agent actually gets** (CIRISServer#418).
//!
//! `EgressScrubber` was wired into this crate's two Rust ingest paths in
//! 0.5.173. The agent uses neither: it constructs persist's `Engine` from
//! Python, and that constructor takes `scrubber: Option<callable>` defaulting to
//! `NullScrubber`. So the node scrubbed nothing on the path it actually receives
//! traces over, and persist v32.1.0 turned the standing warning into a refusal:
//!
//! ```text
//! RuntimeError: engine.receive_and_persist: ValueError:
//!   ('scrub_treatment_mismatch', 'label=full_traces treated_as=full_traces')
//! ```
//!
//! Ten occurrences in one staged QA run, zero traces persisted.
//!
//! Two `Engine` construction sites; 0.5.173 fixed one. The break carries NO
//! signature change anywhere — which is why comparing the API surface across the
//! bump came back clean, and why only running it caught this.
//!
//! These pin the contract [`ciris_server::scrub::scrub_envelope_json`] must meet
//! for persist's `PyCallableScrubber` to accept its output at all.

use ciris_server::scrub::scrub_envelope_json;

/// A minimal batch envelope at the given level, carrying one trace with a field
/// the scrub catalog redacts.
fn envelope(level: &str) -> String {
    serde_json::json!({
        "events": [{
            "event_type": "complete_trace",
            "trace_level": level,
            "trace": {
                "trace_id": "t-418-python-door",
                "thought_id": "th-1",
                "agent_id_hash": "agent-abc",
                "started_at": "2026-08-14T12:00:00Z",
                "completed_at": "2026-08-14T12:00:01Z",
                "trace_level": level,
                "trace_schema_version": "1.0.0",
                "cohort_scope": "federation",
                "signature": "",
                "signature_key_id": "test",
                "components": [{
                    "component_type": "observation",
                    "event_type": "thought_start",
                    "timestamp": "2026-08-14T12:00:00Z",
                    "data": {
                        "thought_content": "reach me at alice@example.com or 555-12-9999",
                    }
                }]
            }
        }],
        "batch_timestamp": "2026-08-14T12:00:00Z",
        "consent_timestamp": "2026-08-14T12:00:00Z",
        "trace_level": level,
        "trace_schema_version": "1.0.0",
    })
    .to_string()
}

/// **The level must come back exactly as it went in.**
///
/// persist re-reads the envelope after the callable returns and refuses any
/// scrubber that moved `trace_level`:
///
/// ```text
/// scrubber altered trace_level — rejected
/// ```
///
/// It then derives `applied_trace_level` from that unchanged envelope. So the
/// downgrade the Rust path performs — `FullTraces` without a model becomes
/// `Detailed`, label rewritten to match — is structurally unavailable here.
/// Performing it anyway would trade persist's documented refusal for a vaguer
/// one, on every batch.
#[test]
fn the_level_is_never_relabelled_on_the_python_path() {
    for level in ["generic", "detailed", "full_traces"] {
        let (out, _, _, _) = scrub_envelope_json(&envelope(level)).expect("scrub");
        let v: serde_json::Value = serde_json::from_str(&out).expect("json");

        assert_eq!(
            v["trace_level"], level,
            "batch trace_level was rewritten {level} -> {}. persist's PyCallableScrubber \
             rejects a callable that alters trace_level, so this turns every batch into \
             `scrubber altered trace_level — rejected`.",
            v["trace_level"]
        );
        assert_eq!(
            v["events"][0]["trace_level"], level,
            "the EVENT level was rewritten while the batch level held. §7 requires them \
             equal, so a half-applied downgrade fails the envelope's own consistency \
             check downstream — the failure mode that is hardest to read."
        );
    }
}

/// **`ner_ran` must be the truth, and must not be inferred from a count.**
///
/// It is the single fact persist's refusal turns on:
///
/// ```rust,ignore
/// if scrub_outcome.applied_trace_level == TraceLevel::FullTraces.as_str()
///     && !scrub_outcome.ner_ran
/// ```
///
/// persist's 2-tuple fallback reports `ner_ran: false` precisely because a
/// nonzero modified-count says fields changed, never that a named-entity pass
/// ran — treating one as the other would manufacture the evidence #690 exists to
/// demand. So this door must return the 4-tuple, and its third element must
/// track `ner::is_configured()` rather than the redaction count.
#[test]
fn ner_ran_tracks_the_model_not_the_edit_count() {
    let (_, modified, ner_ran, digest) =
        scrub_envelope_json(&envelope("full_traces")).expect("scrub");

    let configured = ciris_persist::pipeline::scrub::ner::is_configured();
    assert_eq!(
        ner_ran, configured,
        "ner_ran ({ner_ran}) disagrees with whether a model is loaded ({configured}). \
         This is the value persist's ScrubTreatmentMismatch turns on: claiming true \
         without a model asserts a treatment the content never received, and claiming \
         false with one refuses a batch that was properly scrubbed."
    );
    if !configured {
        assert!(
            !ner_ran,
            "no model is loaded, yet ner_ran is true — {modified} fields were modified, \
             and a modification count is not evidence of a named-entity pass."
        );
    }
    assert!(
        digest.is_none(),
        "a model digest was reported. persist exposes `ner::is_configured()` but nothing \
         identifying WHICH model answered, so there is no honest value here — and \
         inventing one defeats the field's purpose, which is telling a receiver what \
         instrument ran."
    );
}

/// **Content is actually redacted — the point of wiring anything at all.**
///
/// `NullScrubber` returns `fields_modified: 0` having touched nothing, and at
/// `detailed` (what production runs) persist accepts that batch. So the silent
/// failure was never the refusal — it was every `detailed` batch federating
/// unredacted while a warning scrolled past.
#[test]
fn detailed_actually_redacts_where_nullscrubber_passed_content_through() {
    let (out, modified, _, _) = scrub_envelope_json(&envelope("detailed")).expect("scrub");

    assert!(
        modified > 0,
        "nothing was redacted at `detailed`. That is NullScrubber's behaviour, and it is \
         accepted by persist — no refusal, no signal, content federated as written."
    );
    assert!(
        !out.contains("alice@example.com"),
        "the address survived the scrub. This is the leak the refusal drew attention to, \
         and the one that was live on every detailed batch:\n{out}"
    );
}
