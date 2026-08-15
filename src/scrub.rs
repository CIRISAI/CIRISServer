//! **The egress scrub — content is redacted before it can federate.**
//!
//! # What this closes
//!
//! Both paths that put content into this node's corpus passed
//! [`NullScrubber`](ciris_persist::scrub::NullScrubber), and persist said so on
//! every batch:
//!
//! ```text
//! WARN ciris_persist::scrub: NullScrubber used at non-GENERIC trace level —
//!      content not scrubbed; wire a real Scrubber impl in production
//! ```
//!
//! 26 of those were observed on the scout node in one day, on a transport that
//! had just started delivering. The rows land in the corpus and then federate as
//! signed CEG objects — so unscrubbed content does not stay local.
//!
//! # Why HERE is egress
//!
//! A trace leaves this node as an already-signed row, replicated by edge's
//! anti-entropy rounds. **Nothing downstream of the signature can redact it** —
//! editing the bytes invalidates the signature that makes the row admissible at
//! all. So the last moment content can be scrubbed is before it is sealed, which
//! is this boundary: where content authored elsewhere becomes content this node
//! will federate.
//!
//! persist's own contract said the originating node's egress filter had already
//! run (`ingest_http`'s module doc, CIRISPersist#89). That is a precondition
//! nothing verified and, on this node, nothing implemented — the warning above
//! IS persist reporting that it cannot confirm it.
//!
//! # What it does at each level
//!
//! Levels come from persist's [`TraceLevel`], and the behaviour is persist's,
//! not ours — this type only routes a batch into
//! [`scrub_trace`](ciris_persist::pipeline::scrub::scrub_trace):
//!
//! | level | treatment |
//! |---|---|
//! | `Generic` | no-op — carries no content text by design |
//! | `Detailed` | walker + regex redaction over the field catalog |
//! | `FullTraces` | walker + regex + NER, and **REFUSES** when NER is absent |
//!
//! That refusal is deliberate upstream design, and we keep it: a `FullTraces`
//! batch scrubbed without NER would silently lose multilingual entity coverage,
//! and persist's mission note is explicit that partial scrubbing is worse than
//! none because it leaks the assumption that the rest *was* scrubbed. An `Err`
//! here fails the ingest and the batch is rejected — nothing partially-scrubbed
//! is ever persisted.
//!
//! # NER is a build decision, not a runtime one
//!
//! The NER backends live behind persist's `scrub-ner` / `scrub-ort` features
//! (Candle + tokenizers + hf-hub, or ORT). This build enables `scrub` only, so
//! `Detailed` is fully covered and `FullTraces` is refused rather than
//! under-scrubbed. Turning NER on is a wheel-size question measured against the
//! PyPI ceiling, and it belongs in the same commit as that measurement.

use ciris_persist::pipeline::scrub::scrub_trace;
use ciris_persist::schema::{BatchEnvelope, BatchEvent};
use ciris_persist::scrub::{ScrubError, Scrubber};

/// Routes each event in a batch through persist's scrub pipeline.
///
/// Stateless: the redaction policy, the field catalog and the level semantics
/// all live in persist, so this cannot drift from them.
#[derive(Debug, Default, Clone, Copy)]
pub struct EgressScrubber;

impl Scrubber for EgressScrubber {
    fn scrub_batch(&self, env: &mut BatchEnvelope) -> Result<usize, ScrubError> {
        let level = env.trace_level;
        let mut modified = 0usize;

        for event in env.events.iter_mut() {
            match event {
                BatchEvent::CompleteTrace { trace, .. } => {
                    // Round-trip through JSON because the pipeline walks values,
                    // not persist's typed structs. Failure to serialize is an
                    // Err, never a skip — a trace we cannot read is a trace we
                    // cannot claim to have scrubbed.
                    let as_value = serde_json::to_value(&*trace)?;
                    let scrubbed = scrub_trace(as_value, level)
                        .map_err(|e| ScrubError::External(e.to_string()))?;
                    modified += scrubbed.stats.fields_modified;
                    *trace = serde_json::from_value(scrubbed.value)?;
                }
            }
        }

        if modified > 0 {
            tracing::debug!(
                trace_level = ?level,
                fields_redacted = modified,
                events = env.events.len(),
                "egress scrub redacted content before it could be sealed and federated"
            );
        }
        Ok(modified)
    }
}
