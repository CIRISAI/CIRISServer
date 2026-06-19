//! HTTP trace-ingest endpoint — the `listen+1` relay the runbook §3.4 promised
//! (CIRISServer trace-ingest break).
//!
//! ## Why this exists
//!
//! The agent's accord-metrics emitter (UA `CIRIS-AccordMetrics/1.0`) ships
//! signed trace batches over a plain HTTP `POST` to the legacy lens-python path
//! `/lens-api/api/v1/accord/events`. That lens-python service is decommissioned;
//! ciris-server today ingests ONLY over Reticulum (the RET relay,
//! `crates/ciris-lens-core/src/role/ret_relay.rs`). So production receives ZERO
//! traces — every emitter `POST` 404s. This module re-opens the HTTP pipe on the
//! read-API listener so the bridge forwards the legacy path unchanged.
//!
//! ## The wire shape IS already an `AccordEventsBatch`
//!
//! The emitter body is exactly the JSON `BatchEnvelope`
//! (`ciris_persist::schema::BatchEnvelope`) that `AccordEventsBatch`
//! (`#[serde(transparent)]` over `BatchEnvelope`) carries over Reticulum:
//!
//! ```json
//! { "events": [ { "event_type": "complete_trace",
//!                 "trace_level": "generic",
//!                 "trace": { ...CompleteTrace..., "signature": "...",
//!                            "signature_key_id": "..." } } ],
//!   "batch_timestamp": "...", "consent_timestamp": "...",
//!   "trace_level": "generic", "trace_schema_version": "..." }
//! ```
//!
//! So the HTTP handler does NOT adapt a foreign shape — it deserializes the
//! posted bytes straight into `BatchEnvelope` and feeds them to the SAME
//! verify-before-persist path the RET relay's `LensCoreHandler` uses:
//! `Engine::receive_and_persist(&bytes, &NullScrubber)` with the default
//! `VerifyMode::Full`.
//!
//! ## Verify-before-persist (NON-NEGOTIABLE — the security is the CEG signature)
//!
//! HTTP is just the pipe; trust is identical to the RET relay: the per-trace
//! hybrid (Ed25519 + ML-DSA-65) CEG signature IS the authentication, so the
//! route is unauthenticated exactly like the relay (`PeerAcl::AllowAll` ingest,
//! no bearer token). `receive_and_persist` runs persist's `IngestPipeline`
//! verify gate (schema parse → signature verify → scrub → insert) BEFORE any
//! row lands; an unsigned / tampered / unknown-key / classical-only batch is
//! rejected with a 4xx and NOTHING persists. We use the untrusted-input
//! `VerifyMode::Full` (NOT the relay-only `receive_and_persist_pre_verified`
//! skip-verify path) — a direct HTTP `POST` carries no Edge `verify_outcome`,
//! so persist MUST verify it itself.
//!
//! ## Scrubbing
//!
//! `NullScrubber`, matching the relay (`LensCoreHandler`): scrubbing is the
//! originating client node's egress-filter responsibility; the trace arrives
//! post-egress-filter by contract (CIRISPersist#89). A deployment that points
//! agents *directly* at this endpoint as a first-hop privacy boundary would
//! need a real scrubber — same caveat as the relay.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::ingest::IngestError;
use ciris_persist::prelude::Engine;
use ciris_persist::scrub::NullScrubber;
use serde::Serialize;

/// The LEGACY path the deployed emitter POSTs to (UA `CIRIS-AccordMetrics/1.0`).
/// Mounted verbatim so the Caddy bridge forwards it unchanged — zero rewrite.
pub const LEGACY_INGEST_PATH: &str = "/lens-api/api/v1/accord/events";

/// The clean canonical alias for new emitters / direct callers.
pub const CANONICAL_INGEST_PATH: &str = "/v1/ingest/accord-events";

/// Success body — the counts ingested (mirrors the RET relay's
/// `AccordEventsResponse` so an emitter sees identical accounting over either
/// transport).
#[derive(Debug, Serialize)]
struct IngestOk {
    /// `trace_events` rows that landed (excluding idempotent-dedup skips).
    trace_events_inserted: u32,
    /// `trace_llm_calls` rows that landed.
    trace_llm_calls_inserted: u32,
    /// Idempotent ON-CONFLICT dedup skips (anti gossip-loop / re-delivery).
    deduplicated: u32,
    /// CompleteTrace envelopes whose CEG signature verified.
    signatures_verified: u32,
}

/// Error body — a stable machine token (never raw payload bytes; AV-15).
#[derive(Debug, Serialize)]
struct IngestErr {
    /// The stable per-variant token (e.g. `verify_signature_mismatch`,
    /// `verify_hybrid_required`, `schema_missing_field`).
    error: &'static str,
    /// Optional closed-set detail (e.g. the missing field name).
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

/// Merge the HTTP trace-ingest routes onto the read-API listener.
///
/// Both the legacy path (so the bridge forwards unchanged) AND the canonical
/// alias resolve to the same handler. Returned router carries its own
/// `Arc<Engine>` state, so it composes via `.merge(...)` exactly like the auth
/// / safety routers in `compose.rs`.
pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route(LEGACY_INGEST_PATH, axum::routing::post(ingest))
        .route(CANONICAL_INGEST_PATH, axum::routing::post(ingest))
        .with_state(engine)
}

/// `POST <ingest path>` — deserialize-verify-persist, identical to the RET
/// relay handler. Returns `200` + the ingest counts, or a 4xx/5xx + a stable
/// error token. NEVER persists an unverified batch (verify-before-persist runs
/// inside `receive_and_persist`).
async fn ingest(State(engine): State<Arc<Engine>>, body: Bytes) -> Response {
    // The SAME call the RET relay's `LensCoreHandler::handle` makes — the raw
    // posted bytes ARE a `BatchEnvelope`/`AccordEventsBatch` JSON; persist's
    // IngestPipeline canonicalizes + verifies BEFORE persisting (VerifyMode::Full,
    // the untrusted-input default — a direct HTTP POST is NOT pre-verified).
    match engine.receive_and_persist(&body, &NullScrubber).await {
        Ok(summary) => {
            tracing::info!(
                envelopes = summary.envelopes_processed,
                trace_events = summary.trace_events_inserted,
                llm_calls = summary.trace_llm_calls_inserted,
                deduplicated = summary.trace_events_conflicted,
                signatures_verified = summary.signatures_verified,
                "HTTP ingest persisted AccordEventsBatch (verify-before-persist)",
            );
            // Cast usize -> u32: batch sizes are bounded well under u32::MAX by
            // persist's ingest limits (lossless in practice — same as the relay).
            (
                StatusCode::OK,
                Json(IngestOk {
                    trace_events_inserted: summary.trace_events_inserted as u32,
                    trace_llm_calls_inserted: summary.trace_llm_calls_inserted as u32,
                    deduplicated: summary.trace_events_conflicted as u32,
                    signatures_verified: summary.signatures_verified as u32,
                }),
            )
                .into_response()
        }
        Err(e) => {
            let status = ingest_status(&e);
            // AV-15: surface the stable token, never the verbose Display (which
            // could echo payload bytes). The Display goes to the tracing log only.
            tracing::warn!(error = %e, kind = e.kind(), %status, "HTTP ingest rejected");
            (
                status,
                Json(IngestErr {
                    error: e.kind(),
                    detail: e.detail(),
                }),
            )
                .into_response()
        }
    }
}

/// Map an [`IngestError`] to its HTTP status — the same per-layer mapping the
/// lens-python service used (documented on each `IngestError` variant):
///
/// - **verify** (signature mismatch / unknown key / malformed / hybrid-required
///   / hybrid-failed) → `401 Unauthorized` — the CEG signature IS the auth, so
///   a verify failure is an auth failure. THIS is the gate that rejects an
///   unsigned / tampered / classical-only batch.
/// - **schema** (malformed JSON, bad version, missing field, depth bomb) →
///   `422 Unprocessable Entity`.
/// - **scope** (cohort-scope admission refusal) → `403 Forbidden`.
/// - **store** (DB unreachable / IO) → `503 Service Unavailable`.
/// - **sign / scrub / pipeline-invariant** → `500 Internal Server Error`
///   (server-side faults, not the client's batch).
fn ingest_status(e: &IngestError) -> StatusCode {
    match e {
        IngestError::Verify(_) => StatusCode::UNAUTHORIZED,
        IngestError::Schema(_) => StatusCode::UNPROCESSABLE_ENTITY,
        IngestError::ScopeRefused(_) => StatusCode::FORBIDDEN,
        IngestError::Store(_) => StatusCode::SERVICE_UNAVAILABLE,
        IngestError::Sign(_) | IngestError::Scrub(_) | IngestError::PipelineInvariant { .. } => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_path_is_the_decommissioned_lens_python_path() {
        // The bridge forwards this verbatim — it MUST equal what the deployed
        // CIRIS-AccordMetrics/1.0 emitter POSTs (runbook §3.4 / MANIFEST.json).
        assert_eq!(LEGACY_INGEST_PATH, "/lens-api/api/v1/accord/events");
    }

    #[test]
    fn verify_failures_map_to_401() {
        // The signature gate — an unsigned / tampered / unknown-key / classical-
        // only batch surfaces as a Verify error → 401 (auth failure). This is the
        // wire-checkable "verify-before-persist" posture for the HTTP pipe.
        use ciris_persist::verify::Error as VerifyError;
        assert_eq!(
            ingest_status(&IngestError::Verify(VerifyError::SignatureMismatch)),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ingest_status(&IngestError::Verify(VerifyError::UnknownKey("k".into()))),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ingest_status(&IngestError::Verify(VerifyError::HybridRequired)),
            StatusCode::UNAUTHORIZED
        );
    }
}
