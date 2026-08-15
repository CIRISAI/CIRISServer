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
//! | `FullTraces` | walker + regex + NER — **only if a model is loaded** |
//!
//! # `FullTraces` DOWNGRADES when NER is absent — it does not refuse
//!
//! `full_traces` is opt-in and the agents that opt in are exactly the ones doing
//! research. Refusing their batches would take them dark on a node whose only
//! fault is a missing model file, so a batch that asks for `FullTraces` on a
//! node without NER is scrubbed at `Detailed` and **the level is rewritten to
//! match**, loudly.
//!
//! Rewriting the level is the honest part. `trace_level` is the CLAIM about what
//! treatment the content received, so a trace that got the regex pass must say
//! `detailed` — otherwise the corpus carries rows labelled `full_traces` that
//! never saw a NER pass, and every downstream reader that trusts the label is
//! wrong. Downgrading the content without downgrading the claim would be the
//! same defect this module exists to close.
//!
//! # NER is a build decision AND a deployment one
//!
//! The backends live behind persist's `scrub-ner` / `scrub-ort` features
//! (measured: **+1.01 MiB** of binary, which fits the PyPI ceiling with ~6.8 MiB
//! to spare). The MODEL does not ship — XLM-R INT8 is ~280 MB, and persist
//! resolves it from `CIRISLENS_NER_MODEL_DIR` or an HF-Hub fetch. So the feature
//! being compiled in does not mean NER is available on any given node, which is
//! exactly why this is a runtime check and not a `#[cfg]`.

use ciris_persist::pipeline::scrub::{ner, scrub_trace};
use ciris_persist::schema::{BatchEnvelope, BatchEvent, TraceLevel};
use ciris_persist::scrub::{ScrubError, ScrubOutcome, Scrubber};

/// Routes each event in a batch through persist's scrub pipeline.
///
/// Stateless: the redaction policy, the field catalog and the level semantics
/// all live in persist, so this cannot drift from them.
#[derive(Debug, Default, Clone, Copy)]
pub struct EgressScrubber;

impl Scrubber for EgressScrubber {
    fn scrub_batch(&self, env: &mut BatchEnvelope) -> Result<ScrubOutcome, ScrubError> {
        // A node can be BUILT with NER and still not have a model, so ask at
        // runtime. `FullTraces` without a model becomes `Detailed`, content and
        // claim together.
        let ner_ran = ner::is_configured() && env.trace_level == TraceLevel::FullTraces;
        let level = match env.trace_level {
            TraceLevel::FullTraces if !ner::is_configured() => {
                tracing::warn!(
                    requested = "full_traces",
                    applied = "detailed",
                    "NO NER MODEL LOADED — this batch asked for full_traces and got the \
                     regex/walker pass only. Multilingual entity coverage is NOT applied, \
                     and the trace_level is being rewritten to `detailed` so the corpus \
                     does not carry rows claiming a scrub they never received. Stage a \
                     model (CIRISLENS_NER_MODEL_DIR) to restore full_traces."
                );
                TraceLevel::Detailed
            }
            other => other,
        };
        if level != env.trace_level {
            env.trace_level = level;
        }
        let mut modified = 0usize;

        for event in env.events.iter_mut() {
            match event {
                BatchEvent::CompleteTrace {
                    trace,
                    trace_level: event_level,
                } => {
                    // §7 gating requires the event's level to equal the batch's;
                    // a downgrade that updated only one of them would fail the
                    // envelope's own consistency check downstream.
                    *event_level = level;
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

        // v32.1.0 (CIRISPersist#690) — STATE what was done, do not merely count
        // it. `fields_modified: 0` is the honest output of both "NER ran and
        // found nothing" and "no scrubber ran", and a receiver enforcing
        // "properly scrubbed" has to tell those apart. persist binds this
        // statement into the signed scrub envelope, so it travels with the row.
        //
        // `applied_trace_level` is the level the content was ACTUALLY treated
        // at — already downgraded above when no model is loaded — so the
        // envelope agrees with the label rather than contradicting it.
        Ok(ScrubOutcome {
            fields_modified: modified,
            ner_ran,
            applied_trace_level: level.as_str().to_string(),
            // NOT KNOWABLE HERE. persist exposes `ner::is_configured()` but
            // nothing that identifies WHICH model answered, so there is no
            // honest value to put here — and inventing one would defeat the
            // field's purpose, which is telling a receiver what instrument ran.
            // Raised upstream rather than filled with a guess.
            scrubber_model_digest: None,
        })
    }
}
