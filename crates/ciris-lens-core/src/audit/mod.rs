//! `LensCore.audit` — typed action vocabulary + persist audit-log delegation
//! (CIRISLensCore#12 v0.3).
//!
//! # Module layout
//!
//! - [`api`] — wire-frozen typed vocabulary: `AuditedAction`, `ConsentEvent`,
//!   `WisdomBasedDeferral`, `IdentityChange`, `TypedAuditEvent`.
//! - [`delegate`] — pure Rust helpers: `build_entry_draft`, `stamp_entry_hash`,
//!   `stamp_signature`. No I/O; fully unit-tested without an Engine.
//! - [`pyo3`] — `LensAudit` PyO3 class: 4 `log_*` methods that drive the
//!   canonical+sign+record delegation path through the host Engine's Python methods.
//!
//! # Substrate composition
//!
//! | Need | Source |
//! |---|---|
//! | Hash-chained audit log storage | `engine.audit_record_entry(json)` (CIRISPersist v0.8.1) |
//! | Canonicalization for hash | `engine.audit_canonicalize_for_hash(json)` → bytes |
//! | Canonicalization for signing | `engine.audit_canonicalize_for_signing(json)` → bytes |
//! | Ed25519 signing | `engine.local_sign(bytes)` → 64-byte sig |
//! | Typed action enum | lens-core (`src/audit/api.rs`) |
//!
//! # Wire-freeze
//!
//! The 4 typed variants are wire-frozen per FSD §4.1 + #18 freeze.
//! Shape changes require a freeze amendment.

pub mod api;
pub mod delegate;

#[cfg(feature = "python")]
pub mod pyo3;

pub use api::{
    AuditedAction, ConsentEvent, ConsentEventType, IdentityChange, TypedAuditEvent,
    WisdomBasedDeferral,
};
