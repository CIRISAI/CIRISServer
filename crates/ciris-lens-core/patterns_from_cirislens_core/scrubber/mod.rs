//! CIRIS Scrubbing v2 — multilingual NER + regex PII redaction.
//!
//! This module is the only path to persistence for trace text content.
//! See `FSD/CIRIS_SCRUBBING_V2.md` for the full spec.
//!
//! Invariant: no unscrubbed text reaches the storage layer. Trace handlers
//! must consume the returned `ScrubbedTrace` and never reference the input
//! after passing it to `scrub_trace`.

use serde_json::Value;
use thiserror::Error;

pub mod fields;
pub mod ner;
pub mod regex;
pub mod walker;

#[cfg(feature = "ner")]
pub mod distilbert_loader;

#[cfg(feature = "ner")]
pub mod xlm_r_loader;

#[cfg(feature = "ner-ort")]
pub mod ort_loader;

#[cfg(test)]
mod proptests;

pub use fields::SCRUB_FIELDS;

/// Trace privacy level — controls which scrub passes run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceLevel {
    /// Numeric scores only; no text to scrub. Pass-through.
    Generic,
    /// Identifiers + timestamps + structured metadata. Regex pass only.
    Detailed,
    /// Full reasoning text. NER + regex.
    FullTraces,
}

impl TraceLevel {
    pub fn from_str(s: &str) -> Result<Self, ScrubError> {
        match s {
            "generic" => Ok(Self::Generic),
            "detailed" => Ok(Self::Detailed),
            "full_traces" => Ok(Self::FullTraces),
            other => Err(ScrubError::InvalidLevel(other.to_string())),
        }
    }
}

/// Counts of redactions made. Per-trace metric for observability.
#[derive(Debug, Default, Clone)]
pub struct ScrubStats {
    /// NER entity replacements, by tag.
    pub entities_redacted: usize,
    /// Regex replacements, by pattern type. (sum across all patterns)
    pub regex_redactions: usize,
    /// Number of distinct string fields modified.
    pub fields_modified: usize,
    /// Maximum depth reached in the JSON walker.
    pub walker_max_depth: usize,
    /// True if NER pass actually ran (only on FullTraces).
    pub ner_ran: bool,
    /// Number of NER inputs served from the content cache (no model call).
    pub ner_cache_hits: usize,
    /// Number of NER inputs that missed the cache and went to the model.
    pub ner_cache_misses: usize,
}

/// Output of a successful scrub. Holds owned JSON; the input is consumed.
#[derive(Debug)]
pub struct ScrubbedTrace {
    pub value: Value,
    pub stats: ScrubStats,
    pub level: TraceLevel,
}

/// Errors that prevent scrubbing from completing. The contract: any error
/// here means the trace MUST be rejected — never persisted partially scrubbed.
#[derive(Debug, Error)]
pub enum ScrubError {
    #[error("invalid trace level: {0}")]
    InvalidLevel(String),
    #[error("NER inference failed: {0}")]
    NerFailed(String),
    #[error("walker recursion exceeded depth limit ({0})")]
    WalkerDepthExceeded(usize),
    #[error("year-residue check failed: redacted output still contains {0} historical-year matches")]
    YearResidue(usize),
    #[error("operator probe matched in scrubbed output (CIRISLENS_LEAK_PROBES)")]
    ProbeMatch,
    #[error("NER model not configured — full_traces cannot be scrubbed without it")]
    NerNotConfigured,
}

/// Scrub a trace. The input is consumed; only the returned `ScrubbedTrace`
/// may be passed to persistence.
///
/// Per the FSD invariant: any error path returns `Err`, never a partially-
/// scrubbed `Ok`. The caller must propagate the error; downstream storage
/// code must not have a path from `Err` to a write.
pub fn scrub_trace(trace: Value, level: TraceLevel) -> Result<ScrubbedTrace, ScrubError> {
    let mut stats = ScrubStats::default();

    let scrubbed_value = match level {
        TraceLevel::Generic => {
            // No-op: generic traces have no text to scrub.
            trace
        }
        TraceLevel::Detailed => {
            // Regex pass only.
            walker::walk(trace, &SCRUB_FIELDS, &mut stats, /* run_ner = */ false)?
        }
        TraceLevel::FullTraces => {
            // NER + regex on every string in matched subtrees.
            stats.ner_ran = ner::is_configured();
            if !stats.ner_ran {
                // Fail-loud: full_traces without NER would silently drop
                // multilingual entity coverage. Reject the trace.
                return Err(ScrubError::NerNotConfigured);
            }
            walker::walk(trace, &SCRUB_FIELDS, &mut stats, /* run_ner = */ true)?
        }
    };

    // Invariant check: no historical-year residue in redacted output.
    if let TraceLevel::Detailed | TraceLevel::FullTraces = level {
        let residue = regex::count_year_residue(&scrubbed_value);
        if residue > 0 {
            return Err(ScrubError::YearResidue(residue));
        }
        if regex::probe_match(&scrubbed_value) {
            return Err(ScrubError::ProbeMatch);
        }
    }

    Ok(ScrubbedTrace {
        value: scrubbed_value,
        stats,
        level,
    })
}

/// Scrub a batch of traces with one NER forward pass shared across the
/// whole batch. Significantly higher throughput than calling
/// [`scrub_trace`] in a loop when level=`FullTraces`; for other levels
/// it's just a per-trace regex pass.
pub fn scrub_traces_batch(
    traces: Vec<Value>,
    level: TraceLevel,
) -> Result<Vec<ScrubbedTrace>, ScrubError> {
    if traces.is_empty() {
        return Ok(Vec::new());
    }
    let mut stats = ScrubStats::default();

    let scrubbed_values: Vec<Value> = match level {
        TraceLevel::Generic => traces, // pass-through
        TraceLevel::Detailed => {
            walker::walk_batch(traces, &SCRUB_FIELDS, &mut stats, /* run_ner = */ false)?
        }
        TraceLevel::FullTraces => {
            stats.ner_ran = ner::is_configured();
            if !stats.ner_ran {
                return Err(ScrubError::NerNotConfigured);
            }
            walker::walk_batch(traces, &SCRUB_FIELDS, &mut stats, /* run_ner = */ true)?
        }
    };

    // Per-trace invariant check: residue / probe match. Reject the
    // whole batch if any single trace fails — an opt-in
    // partial-success mode is left for a future API once it has a
    // real-world need.
    if let TraceLevel::Detailed | TraceLevel::FullTraces = level {
        for v in &scrubbed_values {
            let residue = regex::count_year_residue(v);
            if residue > 0 {
                return Err(ScrubError::YearResidue(residue));
            }
            if regex::probe_match(v) {
                return Err(ScrubError::ProbeMatch);
            }
        }
    }

    Ok(scrubbed_values
        .into_iter()
        .map(|v| ScrubbedTrace {
            value: v,
            // Copy the aggregated stats into each ScrubbedTrace so the
            // caller can attribute them; per-trace breakdown is left
            // for a future ScrubStats refactor if the API needs it.
            stats: stats.clone(),
            level,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn generic_passes_through() {
        let trace = json!({"csdma": 0.95, "coh": 1.0});
        let out = scrub_trace(trace.clone(), TraceLevel::Generic).unwrap();
        assert_eq!(out.value, trace);
        assert!(!out.stats.ner_ran);
    }

    #[cfg(not(feature = "ner"))]
    #[test]
    fn full_traces_without_ner_rejects() {
        // Without the `ner` feature, `is_configured()` is hard-coded to
        // false; full_traces must fail loudly. Gated under `cfg(not(feature
        // = "ner"))` because under `--features ner` a cached model on disk
        // (e.g. `CIRISLENS_NER_MODEL_DIR` set, or HF cache populated)
        // legitimately makes the backend ready and this assertion would
        // misfire.
        let trace = json!({"task_description": "anything"});
        let result = scrub_trace(trace, TraceLevel::FullTraces);
        assert!(matches!(result, Err(ScrubError::NerNotConfigured)));
    }

    #[test]
    fn detailed_runs_regex_only() {
        let trace = json!({
            "task_description": "User email is alice@example.com from 1989"
        });
        let out = scrub_trace(trace, TraceLevel::Detailed).unwrap();
        let text = out.value["task_description"].as_str().unwrap();
        assert!(text.contains("[EMAIL]"));
        // Year regex should have caught 1989
        assert!(!text.contains("1989"));
    }

    #[test]
    fn invalid_level_string_rejected() {
        assert!(matches!(
            TraceLevel::from_str("not_a_level"),
            Err(ScrubError::InvalidLevel(_))
        ));
    }
}
