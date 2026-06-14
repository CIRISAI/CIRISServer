//! R3.1 — property tests for the scrubber.
//!
//! Four invariants from FSD §7.3:
//!   - **Idempotence**: `scrub(scrub(t)) == scrub(t)` for all `t`.
//!   - **No-text-no-change**: traces with no string fields pass through
//!     bytewise-identical.
//!   - **Generic invariance**: `scrub_generic(t) == t` always.
//!   - **Entity preservation**: redacted placeholders survive a second
//!     scrub pass.
//!
//! Uses `proptest` (already in dev-dependencies). Strategies generate
//! arbitrary JSON shapes including the field names that trigger
//! scrubbing, so the walker is exercised across realistic structures.
//!
//! These run on the default build — no NER feature required. The
//! detailed-level path is a regex-only deterministic transform; full
//! invariants hold there. Full-traces invariants additionally require
//! NER to be configured, tested via the `--features ner` test runner.

use proptest::prelude::*;
use serde_json::{Map, Value};

use super::{scrub_trace, TraceLevel};

// ────────────────────────────────────────────────────────────────────────────
// Strategies — generate trace-shaped JSON values for property checking.
// ────────────────────────────────────────────────────────────────────────────

/// Field names that trigger scrubbing — exercises the walker's matched-key path.
const SCRUBBABLE_FIELDS: &[&str] = &[
    "task_description",
    "thought_content",
    "action_rationale",
    "reasoning",
    "flags",
    "source_ids",
    "intervention_recommendation",
];

/// Field names the walker should leave alone.
const NON_SCRUBBABLE_FIELDS: &[&str] = &[
    "metadata",
    "agent_name",
    "trace_id",
    "score",
    "config",
];

/// Strategy: generate text that may contain entities the regex catches.
fn text_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // Plain text (most common)
        "[A-Za-z ]{0,80}",
        // With a year
        "[A-Za-z ]{0,30} (?:1[7-9][0-9]{2}|20[0-1][0-9]|202[0-3]) [A-Za-z ]{0,30}",
        // With an email
        "[A-Za-z ]{0,30}[a-z]{3,8}@[a-z]{3,8}\\.com[A-Za-z ]{0,30}",
        // With a year-bearing identifier
        "user_query_(?:1[7-9][0-9]{2}|20[0-1][0-9]|202[0-3])_topic",
        // Empty
        Just(String::new()),
        // Just whitespace
        Just("   ".to_string()),
    ]
}

/// Strategy: a leaf JSON value (string/number/bool/null).
fn leaf_strategy() -> impl Strategy<Value = Value> {
    prop_oneof![
        text_strategy().prop_map(Value::String),
        any::<i64>().prop_map(|n| Value::Number(n.into())),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ]
}

/// Strategy: a small JSON object with a mix of scrubbable and non-scrubbable
/// keys, leaf values up to 2 levels deep.
fn object_strategy() -> impl Strategy<Value = Value> {
    let leaf = leaf_strategy();
    let array = prop::collection::vec(leaf_strategy(), 0..4).prop_map(Value::Array);
    let inner = prop_oneof![leaf, array];
    let key_strategy = prop_oneof![
        prop::sample::select(SCRUBBABLE_FIELDS).prop_map(|s| s.to_string()),
        prop::sample::select(NON_SCRUBBABLE_FIELDS).prop_map(|s| s.to_string()),
    ];
    prop::collection::hash_map(key_strategy, inner, 0..6).prop_map(|m| {
        let mut obj = Map::new();
        for (k, v) in m {
            obj.insert(k, v);
        }
        Value::Object(obj)
    })
}

// ────────────────────────────────────────────────────────────────────────────
// Properties
// ────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_shrink_iters: 1000,
        ..ProptestConfig::default()
    })]

    /// Generic-level scrub is the identity. Pure pass-through; no text
    /// is touched regardless of contents.
    #[test]
    fn generic_invariance(trace in object_strategy()) {
        let scrubbed = scrub_trace(trace.clone(), TraceLevel::Generic).unwrap();
        prop_assert_eq!(scrubbed.value, trace);
    }

    /// Detailed-level scrub is idempotent: scrub(scrub(t)) == scrub(t).
    /// (Regex passes are deterministic; running them twice on the same
    /// input must produce the same output.)
    #[test]
    fn detailed_idempotent(trace in object_strategy()) {
        let once = scrub_trace(trace, TraceLevel::Detailed).unwrap();
        let twice = scrub_trace(once.value.clone(), TraceLevel::Detailed).unwrap();
        prop_assert_eq!(once.value, twice.value);
    }

    /// Entity preservation: once a placeholder appears in scrubbed text,
    /// a second scrub pass must not mangle it. `[YEAR]`, `[EMAIL]`, etc.
    /// must round-trip.
    #[test]
    fn placeholders_survive_resroub(trace in object_strategy()) {
        let scrubbed = scrub_trace(trace, TraceLevel::Detailed).unwrap();
        let serialized = serde_json::to_string(&scrubbed.value).unwrap();
        let placeholders = ["[YEAR]", "[EMAIL]", "[PHONE]", "[IDENTIFIER]"];
        for placeholder in placeholders {
            if serialized.contains(placeholder) {
                let resrubbed = scrub_trace(scrubbed.value.clone(), TraceLevel::Detailed)
                    .unwrap();
                let resrub_str = serde_json::to_string(&resrubbed.value).unwrap();
                prop_assert!(
                    resrub_str.contains(placeholder),
                    "placeholder {placeholder} did not survive a second scrub: {resrub_str}",
                );
            }
        }
    }

    /// No-text-no-change: traces with zero string-typed leaves under
    /// scrubbable keys pass through bytewise-identical (the walker
    /// doesn't allocate when there's nothing to do).
    #[test]
    fn no_text_no_change(
        trace in prop::collection::hash_map(
            "[a-z_]{1,12}",
            prop_oneof![any::<i64>().prop_map(|n| Value::Number(n.into())),
                        any::<bool>().prop_map(Value::Bool),
                        Just(Value::Null)],
            0..6
        )
    ) {
        let mut obj = Map::new();
        for (k, v) in trace {
            obj.insert(k, v);
        }
        let value = Value::Object(obj);
        let scrubbed = scrub_trace(value.clone(), TraceLevel::Detailed).unwrap();
        prop_assert_eq!(scrubbed.value, value);
    }

    /// Year-residue invariant always holds on detailed-level output.
    /// (The scrub_trace call would Err if it didn't.)
    #[test]
    fn year_residue_invariant(trace in object_strategy()) {
        let scrubbed = scrub_trace(trace, TraceLevel::Detailed).unwrap();
        // If we get here, the residue check passed.
        let serialized = serde_json::to_string(&scrubbed.value).unwrap();
        // Sanity: regex couldn't catch every possible year in non-ASCII,
        // but in our strategy text is all ASCII so any historical year
        // 1700-2023 must have been redacted.
        let bare_year = ::regex::Regex::new(
            r"\b(?:1[7-9]\d{2}|20[0-1]\d|202[0-3])\b"
        ).unwrap();
        prop_assert!(!bare_year.is_match(&serialized),
            "scrubbed output still contains a bare historical year: {serialized}");
    }
}
