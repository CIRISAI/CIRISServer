//! `LensCoreHandler` — the inbound **opaque-event subscriber** that
//! backs relay mode (edge v8.0.0 / CC 0.7 opaque wire vocabulary).
//!
//! Before edge 8.0 this was a typed `Handler<AccordEventsBatch>`. CC 0.7
//! (`WIRE_VOCABULARY.md` v1.0.1 §4) retired the `AccordEventsBatch`
//! Tier-1 variant and moved trace/telemetry batches to a **Tier-2 opaque
//! event** in CIRISPersist's `0x0005_*` steward range: the edge carries
//! the batch as opaque bytes and fans it out to per-`kind` subscribers,
//! agnostic to its meaning ("reach, not meaning", MISSION §1.3). The
//! payload IS the `BatchEnvelope` bytes the emitter published, so lens-core
//! feeds them straight into the host's verify-before-persist pipeline.
//!
//! **Semantic change (sanctioned by §4):** an opaque *event* is
//! fire-and-forget — there is no `AccordEventsResponse` ACK, so a mesh
//! emitter no longer gets per-batch insert counts back (the HTTP ingest
//! path in `ciris-server`'s `ingest_http` is unaffected and still reports
//! counts). Counts are logged locally at `debug`.
//!
//! # Relay = pass-through scrubbing
//!
//! The subscriber calls `Engine::receive_and_persist` with
//! [`NullScrubber`] — relay mode does **not** re-scrub. Scrubbing is the
//! originating client node's egress-filter responsibility; inter-node
//! federation traffic is post-egress-filter by contract. Re-scrubbing at a
//! relay is actively harmful (divergent NER → trace-content drift). See
//! CIRISPersist#89.
//!
//! # Double-verify
//!
//! `receive_and_persist` re-runs persist's `IngestPipeline` verify step,
//! but the batch already arrived Edge-verified. The redundant lookup is
//! CIRISPersist#91 (skip-verify relay fast-path), deferred — correctness
//! is unaffected.

use std::sync::Arc;

use ciris_edge::Edge;
use ciris_persist::prelude::Engine;
use ciris_persist::scrub::NullScrubber;

/// The opaque-event `kind` for trace/telemetry batches (the successor of
/// the retired `AccordEventsBatch`), in CIRISPersist's `0x0005_*` steward
/// range (`WIRE_VOCABULARY.md` v1.0.1 §3.1).
///
/// **PROVISIONAL (CIRISServer#128):** CIRISPersist has not yet published
/// its `WIRE_VOCABULARY_KINDS.md` allocation for this batch, and the
/// mesh-side emitter (CIRISAgent#904) has not yet migrated. This value must
/// be reconciled with the CIRISPersist steward allocation + the emitter
/// BEFORE any node emits trace batches over Reticulum. The **live**
/// trace-ingest path is HTTP (`ciris-server`'s `ingest_http`), which does
/// not use this `kind`, so this receiver has no live cross-node emitter to
/// be wire-incompatible with today.
pub const ACCORD_EVENTS_KIND: u32 = 0x0005_0001;

/// Relay-mode inbound subscriber. Holds a shared handle to the host's
/// persist `Engine`; persists every verified trace batch it receives.
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

    /// Persist one opaque trace-batch payload (the raw `BatchEnvelope`
    /// bytes). Fire-and-forget: errors are logged, never returned to the
    /// emitter (opaque events carry no response leg).
    async fn persist_batch(&self, sender_key_id: &str, payload: &[u8]) {
        match self
            .engine
            .receive_and_persist(payload, &NullScrubber)
            .await
        {
            Ok(summary) => tracing::debug!(
                peer = %sender_key_id,
                envelopes = summary.envelopes_processed,
                trace_events = summary.trace_events_inserted,
                llm_calls = summary.trace_llm_calls_inserted,
                deduplicated = summary.trace_events_conflicted,
                "relay persisted opaque trace batch (kind {:#010x})",
                ACCORD_EVENTS_KIND,
            ),
            Err(e) => tracing::warn!(
                peer = %sender_key_id,
                error = %e,
                "relay failed to persist opaque trace batch (kind {:#010x})",
                ACCORD_EVENTS_KIND,
            ),
        }
    }

    /// Register lens-core's trace-batch subscriber on `edge` and spawn the
    /// drain task that persists each event. Returns the subscriber id (drop
    /// it via `edge.unregister_opaque_subscriber` to stop, or let the task
    /// end when the edge shuts down and the receiver closes).
    ///
    /// Replaces the pre-8.0 `edge.register_handler::<AccordEventsBatch,_>` —
    /// `register_opaque_subscriber` is synchronous and infallible (it just
    /// inserts an mpsc sender), so callers no longer `.await?`.
    pub fn spawn_subscriber(engine: Arc<Engine>, edge: &Edge) -> u64 {
        let (sub_id, mut rx) = edge.register_opaque_subscriber(ACCORD_EVENTS_KIND);
        let handler = LensCoreHandler::new(engine);
        tokio::spawn(async move {
            // The receiver closes when the edge is dropped/shut down → the
            // loop ends and the task exits cleanly.
            while let Some((sender_key_id, _kind, payload)) = rx.recv().await {
                handler.persist_batch(&sender_key_id, &payload).await;
            }
        });
        sub_id
    }
}
