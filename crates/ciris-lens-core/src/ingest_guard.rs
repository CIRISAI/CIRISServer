//! Admission checks every trace-batch ingest path shares, run on the raw
//! batch bytes BEFORE `Engine::receive_and_persist`.
//!
//! One implementation for both doors a batch enters a node through: the HTTP
//! ingest route (`ciris-server`'s `ingest_http`) and the Reticulum opaque-event
//! relay ([`crate::role::LensCoreHandler`]). A check that lives on only one of
//! them is a check the other door walks around.
//!
//! # The mock-LLM refusal (CIRISAgent#1244)
//!
//! 1,499 traces produced by the agent's MOCK LLM (21,836 trace_events rows,
//! ~17% of the corpus) reached the production canonical between 2026-08-01
//! and 2026-09-18: the agent's exporter defaulted to the production endpoint
//! with no mock guard. Mock output is not evidence about any agent; it skews
//! capacity scoring, and the mock echoed whole prompts into structured fields.

use serde_json::Value;

/// The model name the agent's mock LLM reports on every call.
pub const MOCK_LLM_MODEL: &str = "mock-model";

/// The stable refusal token for a batch carrying a mock-LLM call. Permanent,
/// not retryable: a producer must stop.
pub const REFUSAL_MOCK_LLM: &str = "trace_mock_llm_refused";

/// The `event_type` of an LLM-call trace component (persist's
/// `ReasoningEventType::LlmCall`, serialized SCREAMING_SNAKE_CASE). Persist
/// reads the call's model from that component's `data.model`.
const LLM_CALL_EVENT: &str = "LLM_CALL";

/// Does this batch carry an LLM call made by the agent's mock LLM?
///
/// Only an **LLM-call component** counts: an object whose `event_type` is
/// `LLM_CALL` and whose `data.model` is exactly [`MOCK_LLM_MODEL`], which is
/// the field persist records as the call's model. Other components' `data` is
/// opaque and may legitimately mention the words, or even hold a
/// `{"model": "mock-model"}` of its own (tool or action metadata); that is not
/// a mock call and is admitted.
///
/// The fast path skips the parse when the bytes can't spell the model: no
/// literal `mock-model` and no JSON `\u` escape (an escape can encode any
/// character of the name, so its presence forces the parse). Unparseable bytes
/// return `false`; the persist pipeline refuses them as schema.
#[must_use]
pub fn batch_has_mock_llm_call(body: &[u8]) -> bool {
    if !contains(body, MOCK_LLM_MODEL.as_bytes()) && !contains(body, b"\\u") {
        return false;
    }
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    has_mock_llm_call(&v)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Walk ONLY the batch's trace components, `events[*].trace.components[*]`
/// (persist's `BatchEnvelope` -> `BatchEvent::CompleteTrace` ->
/// `CompleteTrace.components`). Component `data` and batch metadata are opaque
/// and never searched, so an object that merely looks like an LLM call inside
/// another component's payload is not one.
fn has_mock_llm_call(v: &Value) -> bool {
    let Some(events) = v.get("events").and_then(Value::as_array) else {
        return false;
    };
    events
        .iter()
        .filter_map(|e| e.get("trace")?.get("components")?.as_array())
        .flatten()
        .any(is_mock_llm_component)
}

fn is_mock_llm_component(c: &Value) -> bool {
    c.get("event_type").and_then(Value::as_str) == Some(LLM_CALL_EVENT)
        && c.get("data")
            .and_then(|d| d.get("model"))
            .and_then(Value::as_str)
            == Some(MOCK_LLM_MODEL)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A batch envelope holding one trace whose components are `components`.
    fn batch(components: &str) -> String {
        format!(
            r#"{{"events":[{{"event_type":"complete_trace","trace":{{"trace_id":"t1","components":[{components}]}}}}]}}"#
        )
    }

    fn call(model: &str) -> String {
        batch(&format!(
            r#"{{"event_type":"LLM_CALL","data":{{"model":"{model}"}}}}"#
        ))
    }

    #[test]
    fn a_mock_llm_call_is_refused_and_a_real_one_admitted() {
        assert!(batch_has_mock_llm_call(call("mock-model").as_bytes()));
        assert!(!batch_has_mock_llm_call(call("gpt-4o").as_bytes()));
    }

    #[test]
    fn an_escaped_spelling_of_the_mock_model_is_still_refused() {
        // JSON `\u002d` is '-' and `\u006d` is 'm': serde decodes both to
        // exactly "mock-model", while the raw bytes never spell it. Written
        // with an escaped backslash so the escape survives into the bytes.
        let escaped =
            batch("{\"event_type\":\"LLM_CALL\",\"data\":{\"model\":\"mock\\u002dmodel\"}}");
        assert!(
            !escaped.contains("mock-model"),
            "the bytes must not spell it"
        );
        assert!(batch_has_mock_llm_call(escaped.as_bytes()));
        let fully =
            batch("{\"event_type\":\"LLM_CALL\",\"data\":{\"model\":\"\\u006dock-model\"}}");
        assert!(!fully.contains("mock-model"));
        assert!(batch_has_mock_llm_call(fully.as_bytes()));
    }

    #[test]
    fn a_model_field_outside_an_llm_call_is_not_a_mock_call() {
        let tool = batch(
            r#"{"event_type":"ACTION_RESULT","data":{"model":"mock-model","note":"mock-model"}},
               {"event_type":"LLM_CALL","data":{"model":"gpt-4o"}}"#,
        );
        assert!(!batch_has_mock_llm_call(tool.as_bytes()));
    }

    #[test]
    fn an_llm_call_lookalike_inside_opaque_data_is_not_a_component() {
        // Codex on #753: a NON-LLM component whose payload embeds an object
        // shaped like a mock LLM call. Only the component list is searched.
        let nested = batch(
            r#"{"event_type":"ACTION_RESULT","data":{"result":{"event_type":"LLM_CALL","data":{"model":"mock-model"}}}}"#,
        );
        assert!(!batch_has_mock_llm_call(nested.as_bytes()));
        // And a lookalike in batch-level metadata is not one either.
        let meta = r#"{"correlation":{"event_type":"LLM_CALL","data":{"model":"mock-model"}},"events":[]}"#;
        assert!(!batch_has_mock_llm_call(meta.as_bytes()));
    }

    #[test]
    fn unparseable_bytes_are_left_to_persist() {
        assert!(!batch_has_mock_llm_call(b"not json mock-model"));
    }
}
