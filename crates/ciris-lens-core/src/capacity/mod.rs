//! `capacity/` — CEG §5.5.4 Capacity-Score primitives.
//!
//! Per CEG `FSD/CEG/`'s §5.5.4, lens-core owns the Capacity-Score
//! factors that compose `𝒞_CIRIS = C · I_int · R · I_inc · S`:
//!
//! - `capacity:core_identity` (C)
//! - `capacity:integrity` (I_int)
//! - `capacity:resilience` (R)
//! - `capacity:incompleteness_awareness` (I_inc)
//! - `capacity:sustained_coherence` (S)
//! - `capacity:composite` (𝒞_CIRIS)
//!
//! # CEG §7.5 anti-Goodhart — structural enforcement
//!
//! `capacity:*` attestations are surfaced **about** an agent **by
//! other federation members**, never self-reports. CEG §7.5:
//! "`attesting_key_id` MUST NOT equal `attested_key_id`."
//!
//! This module's [`CapacityAttestation`] type enforces that at the
//! type system, not as a runtime validation hook. The struct has no
//! `Default` and no constructor that accepts matching key_ids — a
//! same-key attestation cannot exist as a value of the type. Same
//! shape as persist's [`Goal`](crate::wire::Goal) having
//! [`MetaGoalAlignment`](crate::wire::MetaGoalAlignment) as a
//! required field (CIRISPersist#114) — load-bearing invariants get
//! the type system, not best-effort validation.
//!
//! v0.4 ships the typed attestation primitive; v0.5 (CIRISLensCore
//! #25 / CEG §5.5.4) layers the five-factor calculation on top.

pub mod attestation;
pub mod score;

pub use attestation::{AntiGoodhartViolation, CapacityAttestation};
pub use score::{CapacityFactorError, CapacityFactors};
