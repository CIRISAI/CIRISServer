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

use ciris_persist::schema::BatchEnvelope;
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

/// **The refusal is the feature.** Without NER compiled in, a `full_traces`
/// batch must be REJECTED, not scrubbed with regex alone.
///
/// persist's mission note is explicit: partial scrubbing is worse than none,
/// because it leaks the assumption that the rest *was* scrubbed. An Err here
/// fails the ingest, so nothing partially-scrubbed is ever persisted — where the
/// old `NullScrubber` passed the same batch through completely unredacted and
/// only logged a warning.
#[test]
fn full_traces_is_refused_rather_than_under_scrubbed() {
    let mut env = batch_at("full_traces");
    let before = rendered(&env);

    let result = EgressScrubber.scrub_batch(&mut env);

    assert!(
        result.is_err(),
        "full_traces was ACCEPTED without NER. Regex alone silently drops \
         multilingual entity coverage, and a batch that is partly scrubbed reads \
         downstream as fully scrubbed. It must refuse."
    );
    assert_eq!(
        before,
        rendered(&env),
        "a refused batch must be left untouched — a half-scrubbed envelope must \
         never be observable, even on the error path"
    );
}
