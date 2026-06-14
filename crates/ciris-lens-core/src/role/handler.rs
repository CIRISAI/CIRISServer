//! `LensCoreHandler` — the Edge `Handler<AccordEventsBatch>` impl
//! that backs relay mode.
//!
//! Edge's verify pipeline authenticates an inbound envelope, then
//! dispatches the typed message to the registered handler. For
//! `AccordEventsBatch` (a batch of trace events), lens-core's relay
//! handler persists the batch to the host's shared persist `Engine`
//! and returns the per-batch insert counts as the ACK response.
//!
//! # Relay = pass-through scrubbing
//!
//! The handler calls `Engine::receive_and_persist` with
//! [`NullScrubber`] — relay mode does **not** re-scrub. Scrubbing is
//! the originating client node's egress-filter responsibility
//! (capture-locally / filter-on-egress); inter-node federation
//! traffic is post-egress-filter by contract. Re-scrubbing at a
//! relay is actively harmful: it demands NER models relays aren't
//! provisioned with, and divergent NER versions across relays would
//! store the same trace differently — trace-content drift across the
//! federation. A deployment that points agents *directly* at a relay
//! (a first-hop sink) is itself a privacy boundary and would need a
//! real scrubber; relay-from-federation does not. See CIRISPersist#89.
//!
//! # Double-verify
//!
//! `receive_and_persist` re-runs persist's `IngestPipeline` verify
//! step, but the batch already arrived Edge-verified
//! ([`HandlerContext::verify_outcome`]). The redundant
//! federation-directory lookup is tracked as CIRISPersist#91
//! (skip-verify relay fast-path), deferred — correctness is
//! unaffected, only a per-batch lookup is duplicated.

use std::sync::Arc;

use ciris_edge::{AccordEventsBatch, AccordEventsResponse, Handler, HandlerContext, HandlerError};
use ciris_persist::prelude::Engine;
use ciris_persist::scrub::NullScrubber;

/// Relay-mode inbound handler. Holds a shared handle to the host's
/// persist `Engine`; persists every verified [`AccordEventsBatch`] it
/// receives.
pub struct LensCoreHandler {
    engine: Arc<Engine>,
}

impl LensCoreHandler {
    /// Wrap the host `Engine`. The `Engine` is the CIRIS 3.0
    /// process-singleton — lens-core never constructs one; the host
    /// hands the `Arc` in via [`LensCore::relay`].
    ///
    /// [`LensCore::relay`]: crate::LensCore::relay
    pub fn new(engine: Arc<Engine>) -> Self {
        Self { engine }
    }
}

#[async_trait::async_trait]
impl Handler<AccordEventsBatch> for LensCoreHandler {
    async fn handle(
        &self,
        msg: AccordEventsBatch,
        ctx: HandlerContext,
    ) -> Result<AccordEventsResponse, HandlerError> {
        // `AccordEventsBatch` is `#[serde(transparent)]` over
        // `BatchEnvelope`; `receive_and_persist` wants raw bytes.
        // Re-serializing is safe — persist's IngestPipeline
        // canonicalizes before the signature check, so a serde
        // round-trip of the outer envelope is not byte-load-bearing.
        let bytes = serde_json::to_vec(&msg.0).map_err(|e| {
            HandlerError::SchemaInvalid(format!("re-serialize AccordEventsBatch: {e}"))
        })?;

        let summary = self
            .engine
            .receive_and_persist(&bytes, &NullScrubber)
            .await
            .map_err(|e| HandlerError::Persist(e.to_string()))?;

        tracing::debug!(
            peer = %ctx.signing_key_id,
            envelopes = summary.envelopes_processed,
            trace_events = summary.trace_events_inserted,
            llm_calls = summary.trace_llm_calls_inserted,
            deduplicated = summary.trace_events_conflicted,
            "relay persisted AccordEventsBatch",
        );

        // `BatchSummary` counts are `usize`; the wire response is
        // `u32`. Batch sizes are bounded well under u32::MAX by
        // persist's ingest limits — the cast is lossless in practice.
        Ok(AccordEventsResponse {
            trace_events_inserted: summary.trace_events_inserted as u32,
            trace_llm_calls_inserted: summary.trace_llm_calls_inserted as u32,
            deduplicated: summary.trace_events_conflicted as u32,
        })
    }
}
