//! Wire-contract — federation-public ABI for trace event types.
//!
//! Per `FSD/LENS_CORE_V0_5.md` §5 (Wire-contract freeze). The trace
//! event types lens-core consumes + emits are sourced from
//! `ciris_persist::schema::*` as a single-source-of-truth federation
//! contract. Lens-core re-exports them under `crate::wire::*` so
//! consumers (Rust rlib + Python via the v0.3 LensClient surface)
//! see a stable boundary even as persist's internal layout evolves.
//!
//! # Why re-export rather than redefine
//!
//! Persist v1.1.2+ already canonicalizes via
//! `ciris_persist::prelude::canonicalize_envelope_for_signing` (the
//! single-source-of-truth canonicalizer; CIRISPersist#7 lesson).
//! Re-defining the types in lens-core would diverge the wire format
//! the first time persist adds a field; re-exporting keeps the two
//! crates structurally locked.
//!
//! This is the same pattern `crate::extract::*` uses for the typed
//! `Features` struct (`pub use ciris_persist::pipeline::extract::*`).
//!
//! # Semver discipline (per FSD §5.1)
//!
//! Adding a field with serde default → **minor** (compatible).
//! Renaming or removing → **major**. Changing semantics → **major**.
//! Adding a new `ReasoningEventType` variant → minor (consumers MUST
//! accept unknown variants gracefully — persist v1.1.2's
//! `ReasoningEventType::Unknown(String)` is the forward-compat
//! sentinel; consumers downsample unknown to that variant rather
//! than rejecting the envelope).
//!
//! # PyO3 surface
//!
//! v0.2 ships **Rust-only**. Python consumers use the existing
//! JSON-dict path (today's accord_metrics shape). PyO3 `#[pyclass]`
//! thin-wrappers land in v0.3 alongside `LensClient` when the agent
//! actually constructs trace events from Python with type-safe
//! ergonomics.

// ── re-exports from persist's schema (federation-public ABI) ──

pub use ciris_persist::schema::envelope::{
    BatchEnvelope, BatchEvent, CorrelationMetadata, TraceLevel,
};

pub use ciris_persist::schema::trace::{CompleteTrace, DeploymentProfile, TraceComponent};

pub use ciris_persist::schema::events::{
    AuditAnchor, ComponentType, CostSummary, LlmCallStatus, LlmCallSummary, ReasoningEventType,
};

// ── Goal primitive (CIRISPersist#114, persist v2.10.0) ──
//
// CEG §5.5 + §11.2.1 — typed Goal across the federation, with M-1
// alignment as a structural construction-time invariant. Lens-core's
// F-3 detector family (CIRISLensCore#23 / #24 / #26 / #27) operates
// on the aggregate of declared goals; re-exporting here keeps the
// federation-public ABI for goal-shaped data centralized under
// `crate::wire::*`. M1Dimension is the closed enum that forces
// declarers to think within the Accord's M-1 framing rather than
// slap arbitrary rationale.
pub use ciris_persist::federation::goal::{
    DeliberationRef, Goal, GoalScope, GoalsFilter, M1Dimension, MetaGoalAlignment,
};

// ── lens-core's typed signer wrapper ──

pub mod signer;

pub use signer::Ed25519TraceSigner;

// ── canonical-bytes utility ──

/// Compute canonical bytes for signing a [`BatchEnvelope`] via
/// persist's single-source-of-truth canonicalizer.
///
/// Lens-core never re-implements canonicalization (CIRISPersist#7
/// lesson). Every consumer of the wire contract that needs signed
/// bytes routes through this function.
pub fn canonical_bytes(envelope: &BatchEnvelope) -> Result<Vec<u8>, CanonicalError> {
    let value =
        serde_json::to_value(envelope).map_err(|e| CanonicalError::Serialize(e.to_string()))?;
    ciris_persist::prelude::canonicalize_envelope_for_signing(&value)
        .map_err(|e| CanonicalError::Canonicalize(format!("{e}")))
}

/// Errors from [`canonical_bytes`].
#[derive(Debug, thiserror::Error)]
pub enum CanonicalError {
    /// Envelope couldn't be serialized to `serde_json::Value` —
    /// typically a non-serializable variant in `CorrelationMetadata`.
    #[error("serialize envelope: {0}")]
    Serialize(String),
    /// Persist's canonicalizer rejected the value — typically a
    /// schema-level shape violation. Shouldn't happen on well-formed
    /// `BatchEnvelope` instances; surfaced for diagnostics.
    #[error("canonicalize: {0}")]
    Canonicalize(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn re_export_accessibility() {
        // Compile-time check that the federation-public ABI is
        // reachable under `crate::wire::*` paths. If persist relocates
        // a type, this test breaks at the use line above and the
        // compiler tells us exactly which one.
        fn _accepts_batch_envelope(_e: &BatchEnvelope) {}
        fn _accepts_complete_trace(_t: &CompleteTrace) {}
        fn _accepts_trace_component(_c: &TraceComponent) {}
        fn _accepts_deployment_profile(_d: &DeploymentProfile) {}
        fn _accepts_goal(_g: &Goal) {}
        fn _accepts_meta_goal_alignment(_a: &MetaGoalAlignment) {}
        fn _accepts_m1_dimension(_d: M1Dimension) {}
        fn _accepts_goal_scope(_s: &GoalScope) {}
        fn _accepts_goals_filter(_f: &GoalsFilter) {}
        fn _accepts_trace_level(_l: TraceLevel) {}
        fn _accepts_reasoning_event_type(_e: &ReasoningEventType) {}
        fn _accepts_correlation_metadata(_m: &CorrelationMetadata) {}
        fn _accepts_component_type(_c: ComponentType) {}
    }
}
