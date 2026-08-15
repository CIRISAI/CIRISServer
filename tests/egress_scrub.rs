//! **Content is redacted before it can be sealed and federated.**
//!
//! Both ingest paths passed `NullScrubber`, and persist warned on every batch:
//!
//! ```text
//! NullScrubber used at non-GENERIC trace level — content not scrubbed
//! ```
//!
//! 26 of those in one day on the scout node, on a transport that had just begun
//! delivering. Those rows federate as signed CEG objects, so "not scrubbed" does
//! not stay local — and once a row is signed nothing downstream can redact it
//! without invalidating the signature that makes it admissible.
//!
//! The contract said an upstream egress filter had already run. Nothing verified
//! that, and on this node nothing implemented it. These tests are the
//! verification.

use ciris_persist::schema::{BatchEnvelope, BatchEvent, TraceLevel};
use ciris_persist::scrub::Scrubber;
use ciris_server::scrub::EgressScrubber;
use serde_json::json;

/// PII a real trace would carry, in fields the walker actually enters.
fn batch_at(level: &str) -> BatchEnvelope {
    let env = json!({
        "events": [{
            "event_type": "complete_trace",
            "trace_level": level,
            "trace": {
                "trace_id": "t-egress-scrub-1",
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
                        "thought_content":
                            "reach me at alice@example.com or 555-12-9999, host 10.0.0.7",
                    }
                }]
            }
        }],
        "batch_timestamp": "2026-08-14T12:00:00Z",
        "consent_timestamp": "2026-08-14T12:00:00Z",
        "trace_level": level,
        "trace_schema_version": "1.0.0",
    });
    serde_json::from_value(env).expect("fixture is a valid BatchEnvelope")
}

fn rendered(env: &BatchEnvelope) -> String {
    serde_json::to_string(env).expect("envelope serializes")
}

#[test]
fn detailed_content_is_redacted_before_it_can_federate() {
    let mut env = batch_at("detailed");
    assert!(
        rendered(&env).contains("alice@example.com"),
        "fixture must actually carry the PII it claims to — otherwise this test \
         passes by examining nothing"
    );

    let modified = EgressScrubber
        .scrub_batch(&mut env)
        .expect("detailed scrubs with regex + walker; no NER required");

    let out = rendered(&env);
    assert!(
        modified > 0,
        "scrub reported 0 fields modified on a trace carrying an email, an SSN \
         and an IP — the walker did not reach the content"
    );
    for pii in ["alice@example.com", "555-12-9999", "10.0.0.7"] {
        assert!(
            !out.contains(pii),
            "`{pii}` SURVIVED the egress scrub and would federate verbatim.\n\
             Scrubbed output: {out}"
        );
    }
}

/// GENERIC carries no content text by design, so the scrub is a no-op — and must
/// not mangle the batch on its way through.
#[test]
fn generic_passes_through_untouched() {
    let mut env = batch_at("generic");
    let before = rendered(&env);
    let modified = EgressScrubber
        .scrub_batch(&mut env)
        .expect("generic is a no-op");
    assert_eq!(modified, 0, "generic has no content to redact");
    assert_eq!(
        before,
        rendered(&env),
        "generic must round-trip byte-identical"
    );
}

/// **The `trace_level` a row carries must match the scrub it received.**
///
/// `full_traces` is opt-in, and the agents that opt in are the research ones.
/// Refusing their batches would take them dark because a model file is missing,
/// so a `full_traces` batch on a node without NER is scrubbed at `Detailed` and
/// **relabelled** `detailed`.
///
/// The relabelling is the load-bearing half. `trace_level` is the CLAIM about
/// what treatment the content got; leaving it at `full_traces` after a
/// regex-only pass would put rows in the corpus asserting a scrub they never
/// received, and every downstream reader trusting that label would be wrong.
/// Downgrading content without downgrading the claim is the same defect this
/// whole module exists to close.
///
/// Asserted in BOTH directions against the live NER state, so this test is
/// meaningful on a machine with a model and on CI without one.
#[test]
fn the_level_a_row_claims_matches_the_scrub_it_received() {
    let ner_available = ciris_persist::pipeline::scrub::ner::is_configured();
    let mut env = batch_at("full_traces");

    EgressScrubber
        .scrub_batch(&mut env)
        .expect("full_traces downgrades when NER is absent — it must never refuse");

    let expected = if ner_available {
        TraceLevel::FullTraces
    } else {
        TraceLevel::Detailed
    };
    assert_eq!(
        env.trace_level, expected,
        "NER available = {ner_available}, so the batch should carry {expected:?}. \
         A row labelled full_traces that never saw a NER pass is a false claim in \
         the corpus."
    );

    // The event-level copy must move with it: §7 gating compares the two, and a
    // downgrade that updated only the envelope would fail that check downstream.
    for ev in &env.events {
        let BatchEvent::CompleteTrace { trace_level, .. } = ev;
        assert_eq!(
            *trace_level, expected,
            "the per-event trace_level drifted from the batch's after downgrade"
        );
    }

    // Whichever path ran, the content is gone.
    let out = rendered(&env);
    for pii in ["alice@example.com", "555-12-9999", "10.0.0.7"] {
        assert!(!out.contains(pii), "`{pii}` survived the scrub\n{out}");
    }
}
