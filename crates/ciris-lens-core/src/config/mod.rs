//! Configuration types — pan-mode shared shapes (FSD §3 + §8).
//!
//! Three data types every `LensCore` mode (client / relay / node)
//! shares:
//!
//! - [`UpstreamLens`] — destination identity + per-upstream egress
//!   filter
//! - [`EgressFilter`] — what gets forwarded to a given upstream
//! - [`RetentionPolicy`] — local-store eviction bounds
//!
//! [`TraceLevel`] is **not** redefined here — it lives in persist
//! ([`ciris_persist::schema::envelope::TraceLevel`], re-exported as
//! [`crate::wire::TraceLevel`]) and is shared across the federation.
//! Lens-core consumes it; never redefines it (CIRISPersist#7 lesson).
//!
//! # Versioning posture
//!
//! All three structs are `#[non_exhaustive]`. v0.3 lands the minimum
//! field set (CIRISLensCore#11 single-upstream + trace_level only);
//! v0.4 (#13, #14) extends them — `EgressFilter` gains
//! `min_severity` + `include_detection_events` + `include_scores` +
//! `redact_user_prompts` + `redact_completions`; `RetentionPolicy`
//! grows enforcement (the shape ships in v0.3 so callers can already
//! configure for the v0.4 enforcement). Adding fields after a struct
//! is `#[non_exhaustive]` is a minor-version operation, not a break.

pub mod egress;
pub mod node;
pub mod retention;
pub mod upstream;

pub use egress::{apply_egress_filter, EgressFilter};
pub use node::{PeerAcl, ScoringConfig, UxConfig};
pub use retention::RetentionPolicy;
pub use upstream::UpstreamLens;
