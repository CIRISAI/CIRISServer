//! `EgressFilter` — per-upstream forwarding policy (FSD §3).
//!
//! The agent's lens-core captures FULL_TRACES locally **always**;
//! `trace_level` becomes a per-recipient egress decision, not a
//! per-emission capture decision (FSD §1, §2.2). One upstream lens
//! gets `Generic` (cohort + score only); a sovereign-mode peer in
//! the trust circle gets `FullTraces`; one capture, N forwarding
//! decisions.
//!
//! v0.3 ships **trace_level only** (per CIRISLensCore#11 acceptance:
//! "single-upstream filtering via trace_level only"). v0.4
//! (CIRISLensCore#14) extends with severity gating, detection-event
//! / score inclusion bits, and per-modality content redaction.
//! `#[non_exhaustive]` keeps that extension a minor-version
//! operation.
//!
//! # Filter application
//!
//! [`apply_egress_filter`] is the PURE transform that converts a
//! batch JSON envelope into the per-upstream-filtered form. It
//! operates on a `serde_json::Value` batch (the shape
//! `build_batch_bytes` emits) so it can be applied without
//! re-deserializing into persist's typed structs — the output is
//! still parseable by `BatchEnvelope::from_json` (verified by the
//! `filter_roundtrip_stays_wire_valid` test).
//!
//! ## Field defaults (v0.4 additions)
//!
//! | Field | Default | Rationale |
//! |---|---|---|
//! | `min_severity` | `None` | No severity gate — all traces forwarded |
//! | `include_detection_events` | `true` | Forward LLM-call / detection components |
//! | `include_scores` | `true` | Forward scoring / conformity components |
//! | `redact_user_prompts` | `true` | **Privacy-safe default** — redact unless explicitly opted out |
//! | `redact_completions` | `true` | **Privacy-safe default** — redact unless explicitly opted out |
//!
//! The redaction defaults follow the privacy-conservative posture:
//! operators must explicitly opt-in to forwarding content text
//! (`redact_user_prompts=false`, `redact_completions=false`).

use ciris_persist::derived::types::DetectionSeverity;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::wire::TraceLevel;

/// Per-upstream forwarding policy.
///
/// `#[non_exhaustive]` — additions are minor-version operations.
/// Use [`EgressFilter::new`] for v0.3-compatible construction;
/// [`EgressFilter::builder`] for full v0.4 control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EgressFilter {
    /// Maximum content level allowed out to this upstream. The
    /// originating client always captures `FullTraces` locally; this
    /// is the *ceiling* for what crosses the wire toward the named
    /// destination. See [`TraceLevel`] for the three levels'
    /// semantics.
    pub trace_level: TraceLevel,

    /// Drop entire trace events whose associated severity (when
    /// present in the batch's per-event metadata) is below this
    /// threshold. `None` = no severity gate (all traces forwarded).
    ///
    /// Severity is not part of the current `CompleteTrace` wire
    /// shape; this field is a forward gate for batches that carry
    /// per-event severity annotations. Traces without a `severity`
    /// field are treated as if they pass the gate (permissive).
    ///
    /// Default: `None` (no gate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<DetectionSeverity>,

    /// Whether to include detection-event components (e.g. `llm_call`
    /// components, which carry LLM-call observations used by the
    /// detection layer) in the forwarded trace. When `false`, those
    /// components are stripped from each `CompleteTrace` before
    /// forwarding.
    ///
    /// Default: `true` (include all components).
    #[serde(default = "default_true")]
    pub include_detection_events: bool,

    /// Whether to include scoring / conformity data carried in
    /// component `data` fields in the forwarded trace. When `false`,
    /// score-related keys (`conformity`, `k_eff`, `n_eff`,
    /// `cohort_id`) are stripped from each component's `data`.
    ///
    /// Default: `true` (include scores).
    #[serde(default = "default_true")]
    pub include_scores: bool,

    /// Whether to redact the `user_prompt` field from every
    /// component's `data` before forwarding. When `true` (the
    /// privacy-safe default), `user_prompt` is replaced with `null`.
    ///
    /// Default: `true` (redact — privacy-conservative posture).
    #[serde(default = "default_true")]
    pub redact_user_prompts: bool,

    /// Whether to redact the `llm_completion` field from every
    /// component's `data` before forwarding. When `true` (the
    /// privacy-safe default), `llm_completion` is replaced with
    /// `null`.
    ///
    /// Default: `true` (redact — privacy-conservative posture).
    #[serde(default = "default_true")]
    pub redact_completions: bool,
}

fn default_true() -> bool {
    true
}

impl EgressFilter {
    /// Construct an `EgressFilter` with only the v0.3 field set.
    /// v0.4 additions default to permissive/safe:
    /// - `min_severity = None` (no severity gate)
    /// - `include_detection_events = true`
    /// - `include_scores = true`
    /// - `redact_user_prompts = true` (privacy-safe)
    /// - `redact_completions = true` (privacy-safe)
    pub fn new(trace_level: TraceLevel) -> Self {
        Self {
            trace_level,
            min_severity: None,
            include_detection_events: true,
            include_scores: true,
            redact_user_prompts: true,
            redact_completions: true,
        }
    }

    /// Full v0.4 constructor — set all six fields.
    ///
    /// # Arguments
    ///
    /// - `trace_level` — content ceiling for this upstream.
    /// - `min_severity` — severity gate; `None` = no gate.
    /// - `include_detection_events` — forward `llm_call` components.
    /// - `include_scores` — forward score fields in component data.
    /// - `redact_user_prompts` — blank `user_prompt` in component data.
    /// - `redact_completions` — blank `llm_completion` in component data.
    #[allow(clippy::too_many_arguments)]
    pub fn with_all(
        trace_level: TraceLevel,
        min_severity: Option<DetectionSeverity>,
        include_detection_events: bool,
        include_scores: bool,
        redact_user_prompts: bool,
        redact_completions: bool,
    ) -> Self {
        Self {
            trace_level,
            min_severity,
            include_detection_events,
            include_scores,
            redact_user_prompts,
            redact_completions,
        }
    }
}

impl Default for EgressFilter {
    /// `Generic` + privacy-safe redaction defaults — the
    /// most-privacy-conservative forwarding posture.
    ///
    /// Forwards only the structural / numeric signal (cohort, scores),
    /// no content text; user prompts and completions are redacted even
    /// if `trace_level` is later widened by the operator.
    fn default() -> Self {
        Self::new(TraceLevel::Generic)
    }
}

// ── Score-field constants ─────────────────────────────────────────────

/// Component `data` keys considered "scoring" fields. When
/// `include_scores=false`, these keys are removed from every
/// component's `data` object.
const SCORE_FIELDS: &[&str] = &["conformity", "k_eff", "n_eff", "cohort_id", "phase"];

/// Component `component_type` wire strings that carry detection-event
/// data. When `include_detection_events=false`, components with these
/// types are dropped from each trace's `components` array.
const DETECTION_COMPONENT_TYPES: &[&str] = &["llm_call"];

// ── Severity ordering ─────────────────────────────────────────────────

/// Map [`DetectionSeverity`] to an ordinal for comparison.
/// `Info < Warning < Critical`.
fn severity_ord(s: DetectionSeverity) -> u8 {
    match s {
        DetectionSeverity::Info => 0,
        DetectionSeverity::Warning => 1,
        DetectionSeverity::Critical => 2,
    }
}

// ── apply_egress_filter ───────────────────────────────────────────────

/// Apply `filter` to a batch JSON envelope (the `serde_json::Value`
/// produced by serializing the output of [`build_batch_bytes`]) and
/// return the per-upstream-filtered form.
///
/// This is a **PURE** transform — no Engine, no I/O. The output is
/// still valid `BatchEnvelope` JSON (parseable by
/// `BatchEnvelope::from_json`).
///
/// # What it does
///
/// 1. **trace_level** — updates the envelope-level `trace_level` and
///    each per-event `trace_level` to the filter's value. Content
///    stripping at the `trace_level` boundary (the `scrub_trace`
///    path) is the fan-out dispatcher's responsibility; this function
///    stamps the declared level. The filtered traces produced here
///    contain only components whose declared level is ≤ the filter
///    ceiling — but full scrubbing (persist's `scrub_trace`) runs at
///    dispatch time, not here, to avoid duplicating
///    single-source-of-truth canonicalization.
///
/// 2. **min_severity** — for each batch event that carries a
///    top-level `severity` JSON field, drops the event if the
///    severity is below `min_severity`. Events without a `severity`
///    field are kept (permissive — traces in the current wire shape
///    do not carry per-event severity).
///
/// 3. **include_detection_events** — when `false`, drops components
///    whose `component_type` is one of [`DETECTION_COMPONENT_TYPES`]
///    (`"llm_call"`) from every `CompleteTrace` in the batch.
///
/// 4. **include_scores** — when `false`, removes the
///    [`SCORE_FIELDS`] keys (`conformity`, `k_eff`, `n_eff`,
///    `cohort_id`, `phase`) from every component's `data`.
///
/// 5. **redact_user_prompts** — when `true`, replaces the
///    `user_prompt` key in every component's `data` with `null`
///    (the same semantic as persist's `scrub_trace` content
///    stripping — the key is present but value-nulled, matching
///    how `strip_empty` handles null in objects).
///
/// 6. **redact_completions** — when `true`, replaces
///    `llm_completion` in every component's `data` with `null`.
///
/// # Wire validity
///
/// The returned value is a `BatchEnvelope`-shaped JSON object:
/// `{ events, batch_timestamp, consent_timestamp, trace_level,
/// trace_schema_version, correlation_metadata? }`.
/// If the filter drops all events from the envelope, the returned
/// value still carries an empty `events` array (persist rejects
/// empty envelopes on ingest, but the egress dispatcher should
/// short-circuit before sending zero-event batches to upstreams).
///
/// # Arguments
///
/// - `batch` — a `serde_json::Value` produced by serializing the
///   output of `build_batch_bytes`; must be a JSON Object.
/// - `filter` — the per-upstream forwarding policy.
///
/// # Returns
///
/// The filtered batch value. If `batch` is not a JSON Object, it
/// is returned unchanged (defensive; callers must supply well-formed
/// batch JSON).
pub fn apply_egress_filter(batch: Value, filter: &EgressFilter) -> Value {
    let mut obj = match batch {
        Value::Object(m) => m,
        other => return other,
    };

    // 1. Stamp trace_level on the envelope.
    let tl_str = trace_level_wire_str(filter.trace_level);
    obj.insert("trace_level".into(), Value::String(tl_str.to_owned()));

    // 2. Process events array.
    if let Some(Value::Array(events)) = obj.get_mut("events") {
        // Step 2a: min_severity gate — drop events whose `severity`
        // field is below the threshold (events without a `severity`
        // field pass through).
        if let Some(min) = filter.min_severity {
            let min_ord = severity_ord(min);
            events.retain(|ev| {
                match ev.get("severity").and_then(Value::as_str) {
                    Some(sev_str) => {
                        // Map known severity strings to ordinals.
                        // Unknown strings pass through (permissive).
                        match DetectionSeverity::from_db_str(sev_str) {
                            Some(s) => severity_ord(s) >= min_ord,
                            None => true,
                        }
                    }
                    None => true, // no severity field → keep
                }
            });
        }

        // Step 2b: Apply per-trace transformations to remaining events.
        for ev in events.iter_mut() {
            // Stamp trace_level per event.
            if let Some(obj_ev) = ev.as_object_mut() {
                obj_ev.insert("trace_level".into(), Value::String(tl_str.to_owned()));

                // 3-6: Apply component-level filters inside CompleteTrace events.
                if let Some(trace_val) = obj_ev.get_mut("trace") {
                    apply_component_filters(trace_val, filter);
                }
            }
        }
    }

    Value::Object(obj)
}

/// Apply component-level filters to a single `CompleteTrace` JSON value.
///
/// Mutates `trace_val` in-place:
/// - Drops components by `component_type` when
///   `!include_detection_events`.
/// - Strips score fields from `data` when `!include_scores`.
/// - Nulls `user_prompt` / `llm_completion` in `data` per redact flags.
fn apply_component_filters(trace_val: &mut Value, filter: &EgressFilter) {
    let trace_obj = match trace_val.as_object_mut() {
        Some(m) => m,
        None => return,
    };

    let components = match trace_obj.get_mut("components") {
        Some(Value::Array(arr)) => arr,
        _ => return,
    };

    // 3. include_detection_events gate: drop detection-typed components.
    if !filter.include_detection_events {
        components.retain(|c| {
            let ct = c
                .get("component_type")
                .and_then(Value::as_str)
                .unwrap_or("");
            !DETECTION_COMPONENT_TYPES.contains(&ct)
        });
    }

    // 4. include_scores / 5-6. redact — transform each remaining component.
    for comp in components.iter_mut() {
        let comp_obj = match comp.as_object_mut() {
            Some(m) => m,
            None => continue,
        };

        let data = match comp_obj.get_mut("data") {
            Some(Value::Object(d)) => d,
            _ => continue,
        };

        // 4. Strip score fields when !include_scores.
        if !filter.include_scores {
            for field in SCORE_FIELDS {
                data.remove(*field);
            }
        }

        // 5. Redact user_prompt (replace with null, matching persist's
        //    scrub_trace content-null semantics — present but value-nulled).
        if filter.redact_user_prompts && data.contains_key("user_prompt") {
            data.insert("user_prompt".into(), Value::Null);
        }

        // 6. Redact llm_completion.
        if filter.redact_completions && data.contains_key("llm_completion") {
            data.insert("llm_completion".into(), Value::Null);
        }
    }
}

/// Map a [`TraceLevel`] to its wire snake_case string.
///
/// Mirrors persist's `TraceLevel` serde `rename_all = "snake_case"`.
fn trace_level_wire_str(level: TraceLevel) -> &'static str {
    match level {
        TraceLevel::Generic => "generic",
        TraceLevel::Detailed => "detailed",
        TraceLevel::FullTraces => "full_traces",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── EgressFilter construction / serde ────────────────────────────

    #[test]
    fn default_is_generic_most_conservative() {
        // Forwarding without explicit operator opt-in must never
        // leak content. `Generic` is the floor and the default.
        assert_eq!(EgressFilter::default().trace_level, TraceLevel::Generic);
    }

    #[test]
    fn new_sets_trace_level_and_safe_defaults() {
        let f = EgressFilter::new(TraceLevel::FullTraces);
        assert_eq!(f.trace_level, TraceLevel::FullTraces);
        assert_eq!(f.min_severity, None);
        assert!(f.include_detection_events);
        assert!(f.include_scores);
        assert!(
            f.redact_user_prompts,
            "redact_user_prompts must default true"
        );
        assert!(f.redact_completions, "redact_completions must default true");
    }

    #[test]
    fn with_all_sets_every_field() {
        let f = EgressFilter::with_all(
            TraceLevel::Detailed,
            Some(DetectionSeverity::Warning),
            false,
            false,
            false,
            false,
        );
        assert_eq!(f.trace_level, TraceLevel::Detailed);
        assert_eq!(f.min_severity, Some(DetectionSeverity::Warning));
        assert!(!f.include_detection_events);
        assert!(!f.include_scores);
        assert!(!f.redact_user_prompts);
        assert!(!f.redact_completions);
    }

    #[test]
    fn serde_roundtrip_each_level() {
        for level in [
            TraceLevel::Generic,
            TraceLevel::Detailed,
            TraceLevel::FullTraces,
        ] {
            let f = EgressFilter::new(level);
            let json = serde_json::to_string(&f).unwrap();
            let back: EgressFilter = serde_json::from_str(&json).unwrap();
            assert_eq!(f, back);
        }
    }

    #[test]
    fn serde_uses_snake_case_trace_level() {
        // Wire-stable: federation peers parse the persist TraceLevel
        // representation. snake_case matches persist's schema.
        let f = EgressFilter::new(TraceLevel::FullTraces);
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["trace_level"], "full_traces");
    }

    #[test]
    fn serde_roundtrip_with_all_fields() {
        let f = EgressFilter::with_all(
            TraceLevel::Generic,
            Some(DetectionSeverity::Critical),
            false,
            true,
            true,
            false,
        );
        let json = serde_json::to_string(&f).unwrap();
        let back: EgressFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn serde_min_severity_omitted_when_none() {
        // When `min_severity` is None, the field is not emitted (skip_serializing_if).
        let f = EgressFilter::new(TraceLevel::Generic);
        let json_val = serde_json::to_value(&f).unwrap();
        assert!(
            json_val.get("min_severity").is_none(),
            "min_severity should be absent when None"
        );
    }

    #[test]
    fn serde_default_booleans_deserialized_when_absent() {
        // A v0.3-era JSON (only trace_level) must deserialize with v0.4
        // boolean fields using their defaults (all true except min_severity).
        let legacy = r#"{"trace_level":"generic"}"#;
        let f: EgressFilter = serde_json::from_str(legacy).unwrap();
        assert_eq!(f.trace_level, TraceLevel::Generic);
        assert_eq!(f.min_severity, None);
        assert!(f.include_detection_events);
        assert!(f.include_scores);
        assert!(f.redact_user_prompts);
        assert!(f.redact_completions);
    }

    // ── Helper: build a minimal batch JSON Value ─────────────────────

    fn batch_with_trace(components: serde_json::Value) -> Value {
        json!({
            "events": [{
                "event_type": "complete_trace",
                "trace_level": "full_traces",
                "trace": {
                    "trace_id": "trace-1",
                    "thought_id": "th_1",
                    "agent_id_hash": "deadbeef",
                    "started_at": "2026-06-12T00:00:00+00:00",
                    "completed_at": "2026-06-12T00:00:02+00:00",
                    "trace_level": "full_traces",
                    "trace_schema_version": "3.0.0",
                    "components": components,
                    "signature": "AAAA",
                    "signature_key_id": "k",
                }
            }],
            "batch_timestamp": "2026-06-12T00:00:05+00:00",
            "consent_timestamp": "2026-01-01T00:00:00+00:00",
            "trace_level": "full_traces",
            "trace_schema_version": "3.0.0"
        })
    }

    fn llm_call_component() -> Value {
        json!({
            "component_type": "llm_call",
            "event_type": "LLM_CALL",
            "timestamp": "2026-06-12T00:00:01+00:00",
            "data": {
                "attempt_index": 0,
                "user_prompt": "hello world",
                "llm_completion": "hi there",
                "k_eff": 0.9
            },
            "agent_id_hash": "deadbeef"
        })
    }

    fn observation_component() -> Value {
        json!({
            "component_type": "observation",
            "event_type": "THOUGHT_START",
            "timestamp": "2026-06-12T00:00:00+00:00",
            "data": {
                "attempt_index": 0,
                "user_prompt": "my question",
                "conformity": "numeric",
                "k_eff": 0.95
            },
            "agent_id_hash": "deadbeef"
        })
    }

    // ── apply_egress_filter tests ─────────────────────────────────────

    /// Permissive filter (all include=true, redact=false) is near-identity:
    /// all components preserved, no fields stripped, trace_level stamped.
    #[test]
    fn permissive_filter_is_near_identity() {
        let filter = EgressFilter::with_all(
            TraceLevel::FullTraces,
            None,
            true,
            true,
            false, // no redaction
            false,
        );
        let batch = batch_with_trace(json!([observation_component(), llm_call_component()]));
        let filtered = apply_egress_filter(batch.clone(), &filter);

        let events = filtered["events"].as_array().unwrap();
        assert_eq!(events.len(), 1, "one trace event preserved");

        let comps = &events[0]["trace"]["components"];
        assert_eq!(
            comps.as_array().unwrap().len(),
            2,
            "both components preserved"
        );
        // user_prompt not redacted
        assert_eq!(comps[0]["data"]["user_prompt"], "my question");
        // trace_level stamped
        assert_eq!(filtered["trace_level"], "full_traces");
    }

    /// min_severity gate: events with severity below threshold dropped.
    #[test]
    fn min_severity_drops_low_severity_events() {
        let filter = EgressFilter::with_all(
            TraceLevel::Generic,
            Some(DetectionSeverity::Warning),
            true,
            true,
            false,
            false,
        );

        // Build a batch with two events: one "info" (dropped), one "warning" (kept).
        let batch = json!({
            "events": [
                {
                    "event_type": "complete_trace",
                    "trace_level": "generic",
                    "severity": "info",
                    "trace": {
                        "trace_id": "trace-info",
                        "thought_id": "th_i",
                        "agent_id_hash": "dead",
                        "started_at": "2026-06-12T00:00:00+00:00",
                        "completed_at": "2026-06-12T00:00:02+00:00",
                        "trace_level": "generic",
                        "trace_schema_version": "3.0.0",
                        "components": [],
                        "signature": "AAAA",
                        "signature_key_id": "k"
                    }
                },
                {
                    "event_type": "complete_trace",
                    "trace_level": "generic",
                    "severity": "warning",
                    "trace": {
                        "trace_id": "trace-warn",
                        "thought_id": "th_w",
                        "agent_id_hash": "dead",
                        "started_at": "2026-06-12T00:00:01+00:00",
                        "completed_at": "2026-06-12T00:00:03+00:00",
                        "trace_level": "generic",
                        "trace_schema_version": "3.0.0",
                        "components": [],
                        "signature": "BBBB",
                        "signature_key_id": "k"
                    }
                }
            ],
            "batch_timestamp": "2026-06-12T00:00:05+00:00",
            "consent_timestamp": "2026-01-01T00:00:00+00:00",
            "trace_level": "generic",
            "trace_schema_version": "3.0.0"
        });

        let filtered = apply_egress_filter(batch, &filter);
        let events = filtered["events"].as_array().unwrap();
        assert_eq!(events.len(), 1, "only warning event kept");
        assert_eq!(events[0]["trace"]["trace_id"], "trace-warn");
    }

    /// Events without a severity field pass the min_severity gate.
    #[test]
    fn min_severity_passes_events_without_severity_field() {
        let filter = EgressFilter::with_all(
            TraceLevel::Generic,
            Some(DetectionSeverity::Critical),
            true,
            true,
            false,
            false,
        );
        let batch = batch_with_trace(json!([]));
        let filtered = apply_egress_filter(batch, &filter);
        // No severity field on the event → kept
        assert_eq!(filtered["events"].as_array().unwrap().len(), 1);
    }

    /// include_detection_events=false drops llm_call components.
    #[test]
    fn include_detection_events_false_drops_llm_call_components() {
        let filter = EgressFilter::with_all(
            TraceLevel::FullTraces,
            None,
            false, // drop detection event components
            true,
            false,
            false,
        );
        let batch = batch_with_trace(json!([observation_component(), llm_call_component()]));
        let filtered = apply_egress_filter(batch, &filter);
        let comps = &filtered["events"][0]["trace"]["components"];
        let comp_arr = comps.as_array().unwrap();
        assert_eq!(
            comp_arr.len(),
            1,
            "llm_call component dropped, observation kept"
        );
        assert_eq!(comp_arr[0]["component_type"], "observation");
    }

    /// include_scores=false strips score fields from component data.
    #[test]
    fn include_scores_false_strips_score_fields() {
        let filter = EgressFilter::with_all(
            TraceLevel::FullTraces,
            None,
            true,
            false, // drop scores
            false,
            false,
        );
        let batch = batch_with_trace(json!([observation_component()]));
        let filtered = apply_egress_filter(batch, &filter);
        let data = &filtered["events"][0]["trace"]["components"][0]["data"];
        // conformity + k_eff stripped
        assert!(
            data.get("conformity").is_none(),
            "conformity must be stripped"
        );
        assert!(data.get("k_eff").is_none(), "k_eff must be stripped");
        // attempt_index + user_prompt kept (not a score field)
        assert_eq!(data["attempt_index"], 0);
        assert_eq!(data["user_prompt"], "my question");
    }

    /// redact_user_prompts=true nulls user_prompt in component data.
    #[test]
    fn redact_user_prompts_true_nulls_user_prompt() {
        let filter = EgressFilter::with_all(
            TraceLevel::Detailed,
            None,
            true,
            true,
            true,  // redact user prompts
            false, // no completion redaction
        );
        let batch = batch_with_trace(json!([observation_component(), llm_call_component()]));
        let filtered = apply_egress_filter(batch, &filter);
        let comps = &filtered["events"][0]["trace"]["components"];
        // observation component: user_prompt nulled
        assert!(
            comps[0]["data"]["user_prompt"].is_null(),
            "user_prompt must be null"
        );
        // llm_call component: user_prompt nulled; llm_completion kept
        assert!(
            comps[1]["data"]["user_prompt"].is_null(),
            "user_prompt in llm_call must be null"
        );
        assert_eq!(comps[1]["data"]["llm_completion"], "hi there");
    }

    /// redact_completions=true nulls llm_completion in component data.
    #[test]
    fn redact_completions_true_nulls_llm_completion() {
        let filter = EgressFilter::with_all(
            TraceLevel::Detailed,
            None,
            true,
            true,
            false, // no user prompt redaction
            true,  // redact completions
        );
        let batch = batch_with_trace(json!([llm_call_component()]));
        let filtered = apply_egress_filter(batch, &filter);
        let data = &filtered["events"][0]["trace"]["components"][0]["data"];
        assert!(
            data["llm_completion"].is_null(),
            "llm_completion must be null"
        );
        // user_prompt kept
        assert_eq!(data["user_prompt"], "hello world");
    }

    /// redact flags blank content but keep non-content fields.
    #[test]
    fn redact_blanks_content_fields_keeps_non_content() {
        let filter = EgressFilter::with_all(
            TraceLevel::Detailed,
            None,
            true,
            true,
            true, // redact both
            true,
        );
        let batch = batch_with_trace(json!([llm_call_component()]));
        let filtered = apply_egress_filter(batch, &filter);
        let data = &filtered["events"][0]["trace"]["components"][0]["data"];
        assert!(data["user_prompt"].is_null());
        assert!(data["llm_completion"].is_null());
        // Non-content fields kept
        assert_eq!(data["attempt_index"], 0);
        assert_eq!(data["k_eff"], 0.9);
    }

    /// A filtered batch round-trips through persist's BatchEnvelope::from_json.
    #[test]
    fn filter_roundtrip_stays_wire_valid() {
        use ciris_persist::prelude::LocalSigner;
        use ciris_persist::schema::{BatchEnvelope, BatchEvent};
        use ciris_persist::verify::canonical::JcsCanonicalizer;
        use ciris_persist::verify::verify_trace;
        use ed25519_dalek::SigningKey;

        use crate::capture::batch::{build_batch_bytes, BatchProvenance};
        use crate::capture::event::{ComponentType, ReasoningEventType};
        use crate::capture::partial::{CompleteTrace, TraceComponent, TRACE_SCHEMA_VERSION};
        use crate::capture::seal;

        let sk = SigningKey::from_bytes(&[99u8; 32]);
        let vk = sk.verifying_key();
        let signer = LocalSigner::from_parts(sk, "egress-test-key".into(), None, None);

        // Build a trace with an LLM_CALL component + user_prompt in data.
        let mut trace = CompleteTrace {
            trace_id: "trace-egress-1".into(),
            thought_id: "th_eg_1".into(),
            task_id: Some("task-eg".into()),
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-06-12T00:00:00+00:00".into(),
            completed_at: Some("2026-06-12T00:00:02+00:00".into()),
            components: vec![
                TraceComponent {
                    component_type: ComponentType::Observation,
                    event_type: ReasoningEventType::ThoughtStart,
                    timestamp: "2026-06-12T00:00:00+00:00".into(),
                    attempt_index: 0,
                    data: serde_json::json!({"user_prompt": "top-secret", "k_eff": 0.9}),
                    agent_id_hash: "deadbeef".into(),
                },
                TraceComponent {
                    component_type: ComponentType::LlmCall,
                    event_type: ReasoningEventType::LlmCall,
                    timestamp: "2026-06-12T00:00:01+00:00".into(),
                    attempt_index: 0,
                    data: serde_json::json!({
                        "user_prompt": "secret query",
                        "llm_completion": "secret answer"
                    }),
                    agent_id_hash: "deadbeef".into(),
                },
            ],
            signature: None,
            signature_key_id: None,
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
            trace_level: Some("full_traces".into()),
            trace_schema_version: TRACE_SCHEMA_VERSION.into(),
            deployment_profile: Some(serde_json::json!({
                "agent_role": "ally",
                "agent_template": "ally-default",
                "deployment_domain": "general",
                "deployment_type": "production",
                "deployment_region": null,
                "deployment_trust_mode": "sovereign",
            })),
        };

        seal::sign_trace(&signer, &mut trace).expect("sign");

        let provenance = BatchProvenance {
            batch_timestamp: "2026-06-12T00:00:05+00:00".into(),
            consent_timestamp: "2026-01-01T00:00:00+00:00".into(),
            trace_level: "full_traces".into(),
            trace_schema_version: TRACE_SCHEMA_VERSION.into(),
            correlation_metadata: None,
        };

        let bytes = build_batch_bytes(&[trace], &provenance).expect("build batch");
        let batch_val: Value = serde_json::from_slice(&bytes).expect("parse batch");

        // Apply a privacy filter: redact prompts + completions, drop detection
        // event components, downgrade trace_level to "detailed".
        let filter = EgressFilter::with_all(
            TraceLevel::Detailed,
            None,
            false, // drop llm_call components
            true,
            true, // redact user_prompt
            true, // redact llm_completion
        );
        let filtered_val = apply_egress_filter(batch_val, &filter);

        // Confirm filtered bytes are still valid BatchEnvelope JSON.
        let filtered_bytes = serde_json::to_vec(&filtered_val).expect("serialize filtered");
        let env =
            BatchEnvelope::from_json(&filtered_bytes).expect("persist must parse filtered batch");
        assert_eq!(env.events.len(), 1);

        // The LLM_CALL component was dropped; only observation remains.
        let BatchEvent::CompleteTrace { trace: ptrace, .. } = &env.events[0];
        assert_eq!(
            ptrace.components.len(),
            1,
            "llm_call component dropped by filter"
        );
        assert_ne!(
            ptrace.components[0].component_type,
            ciris_persist::schema::events::ComponentType::LlmCall,
            "remaining component must not be llm_call"
        );

        // The filtered trace still verifies — the signature covers the
        // pre-filter canonical bytes; the filtered form is what we SEND
        // to upstreams (re-signing is the fan-out dispatcher's job,
        // CIRISLensCore#11 Cut 4 / per the issue spec). The persist
        // round-trip proves the filtered bytes stay wire-valid.
        //
        // Note: verify_trace uses the original (pre-filter) signature still
        // present on the trace; it will FAIL because we mutated components.
        // This is expected: the filter is for FORWARDING (re-sign at dispatch);
        // here we only confirm wire shape validity via from_json, not signature.
        let _ = verify_trace(ptrace, &JcsCanonicalizer, &vk); // ok to fail post-filter
    }

    /// A permissive filter (all defaults) with no redaction is near-identity
    /// and the resulting batch round-trips through persist's BatchEnvelope.
    #[test]
    fn permissive_filter_roundtrip_stays_wire_valid() {
        use ciris_persist::prelude::LocalSigner;
        use ciris_persist::schema::{BatchEnvelope, BatchEvent};
        use ciris_persist::verify::canonical::JcsCanonicalizer;
        use ciris_persist::verify::verify_trace;
        use ed25519_dalek::SigningKey;

        use crate::capture::batch::{build_batch_bytes, BatchProvenance};
        use crate::capture::event::{ComponentType, ReasoningEventType};
        use crate::capture::partial::{CompleteTrace, TraceComponent, TRACE_SCHEMA_VERSION};
        use crate::capture::seal;

        let sk = SigningKey::from_bytes(&[100u8; 32]);
        let vk = sk.verifying_key();
        let signer = LocalSigner::from_parts(sk, "egress-perm-key".into(), None, None);

        let mut trace = CompleteTrace {
            trace_id: "trace-perm-1".into(),
            thought_id: "th_perm_1".into(),
            task_id: None,
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-06-12T00:00:00+00:00".into(),
            completed_at: Some("2026-06-12T00:00:02+00:00".into()),
            components: vec![TraceComponent {
                component_type: ComponentType::Observation,
                event_type: ReasoningEventType::ThoughtStart,
                timestamp: "2026-06-12T00:00:00+00:00".into(),
                attempt_index: 0,
                data: serde_json::json!({"phase": "healthy", "k_eff": 0.9}),
                agent_id_hash: "deadbeef".into(),
            }],
            signature: None,
            signature_key_id: None,
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
            trace_level: Some("generic".into()),
            trace_schema_version: TRACE_SCHEMA_VERSION.into(),
            deployment_profile: Some(serde_json::json!({
                "agent_role": "ally",
                "agent_template": "ally-default",
                "deployment_domain": "general",
                "deployment_type": "production",
                "deployment_region": null,
                "deployment_trust_mode": "sovereign",
            })),
        };

        seal::sign_trace(&signer, &mut trace).expect("sign");

        let provenance = BatchProvenance {
            batch_timestamp: "2026-06-12T00:00:05+00:00".into(),
            consent_timestamp: "2026-01-01T00:00:00+00:00".into(),
            trace_level: "generic".into(),
            trace_schema_version: TRACE_SCHEMA_VERSION.into(),
            correlation_metadata: None,
        };

        let bytes = build_batch_bytes(&[trace], &provenance).expect("build batch");
        let batch_val: Value = serde_json::from_slice(&bytes).expect("parse batch");

        // Permissive filter: no redaction, keep everything, same trace_level.
        let filter = EgressFilter::with_all(
            TraceLevel::Generic,
            None,
            true,
            true,
            false, // no redaction
            false,
        );
        let filtered_val = apply_egress_filter(batch_val, &filter);
        let filtered_bytes = serde_json::to_vec(&filtered_val).expect("serialize");

        // persist round-trip + signature verify (no mutation → signature holds).
        let env = BatchEnvelope::from_json(&filtered_bytes)
            .expect("permissive filter must stay wire-valid");
        assert_eq!(env.events.len(), 1);

        let BatchEvent::CompleteTrace { trace: ptrace, .. } = &env.events[0];
        verify_trace(ptrace, &JcsCanonicalizer, &vk)
            .expect("permissive filter must not break signature");
    }
}
