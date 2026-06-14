//! `capture/` — client/emit-path partial-trace assembly (CIRISLensCore#11).
//!
//! Replaces the **emit** half of CIRISAgent's `accord_metrics/
//! services.py` (~3000 LOC Python). The agent's `reasoning_event_stream`
//! subscriber feeds component events here; lens-core assembles partial
//! traces in memory, then on `ACTION_RESULT` seals + canonicalizes +
//! signs (via the host `Engine`'s `local_sign` / `local_pqc_sign`) +
//! persists (via `Engine::receive_and_persist`) + fans out to upstream
//! lenses through edge's outbound dispatcher.
//!
//! # Cut sequence (per the #11 design-decision comment)
//!
//! This module lands in reviewable cuts:
//!
//! - **Cut 1 (this commit) — [`event`] taxonomy.** The closed
//!   `ReasoningEventType` enum + `ComponentType` mapping: the
//!   compile-time wire contract that structurally prevents the
//!   CIRISAgent#757 / CIRISLens#13 drift incidents. No I/O, no Engine.
//! - **Cut 2 — partial-trace assembly.** In-memory store keyed by
//!   `thought_id` (design-fork C1; durable variant tracked at #35),
//!   `orphan_sweep`, the `CompleteTrace` shape + `to_dict`.
//! - **Cut 3 — seal path.** Canonical-message build +
//!   `local_sign`/`local_pqc_sign` + `receive_and_persist`. Verifies
//!   the v4 write-path admission gate (AV-45) admits self-authored
//!   traces.
//! - **Cut 4 — fan-out.** Enqueue to each `UpstreamLens` via edge's
//!   `outbound` dispatcher (design-fork A1).
//! - **Cut 5 — PyO3 surface + Python shim.** Flat `lens.capture_event`
//!   / `lens.flush` / `lens.orphan_sweep` (design-fork B1; sub-object
//!   form tracked at #36); the ~10-line `accord_metrics/__init__.py`
//!   shim; CIRISAgent `tests/adapters/accord_metrics/` parity.

pub mod batch;
pub mod client;
pub mod consent;
pub mod correlation;
pub mod event;
pub mod partial;
pub mod py_engine;
pub mod seal;

pub use batch::{build_batch_bytes, BatchBuildError, BatchProvenance};
pub use client::{
    sign_trace_via_hardware_signer, CaptureClient, CaptureEventOutcome, ClientError,
    PrepareSealOutcome, SealSignError, SealSummary,
};
pub use consent::{
    resolve_consent, resolve_consent_via_engine, resolve_grant, ConsentConfig, ConsentError,
    ConsentResolution, GrantState, CONSENT_DIMENSION,
};
pub use correlation::{fuzz_location_to_region, CorrelationMetadata};
pub use event::{ComponentType, ReasoningEventType};
pub use partial::{
    CaptureOutcome, CompleteTrace, InboundEvent, PartialTraceStore, TraceComponent,
    TRACE_SCHEMA_VERSION,
};
pub use seal::{build_canonical_envelope, canonical_bytes, strip_empty};
