//! `cohort/` module — declared + inferred routing; mismatch is itself
//! a detection signal (LC-AV-2 P0). See `MISSION.md` §2 cohort/.
//!
//! # Phase 1 design lock
//!
//! Cohort cells are the **6-tuple** of agent-declared
//! `deployment_profile` fields (CIRISAgent FSD `TRACE_WIRE_FORMAT.md`
//! §3.2, RATCHET-confirmed 2026-05-04):
//! `(agent_role, agent_template, deployment_domain, deployment_type,
//!   deployment_region, deployment_trust_mode)`.
//!
//! `deployment_resourcing` (§3.3, lens-computed) is NOT in the cohort
//! key. See `OPEN_QUESTIONS.md` OQ-10 closure for the lock-in history.
//!
//! `deployment_resourcing` (`TRACE_WIRE_FORMAT.md` §3.3) is NOT a
//! Phase 1 cohort axis. The continuous cost/tokens/model features
//! it derives from are P0 LC-AV-2 inputs; the categorical 4-band
//! tier is a research-grade analytic available via [`resourcing`]
//! for post-calibration use. See `OPEN_QUESTIONS.md` OQ-10 closure.

pub mod declared;
pub mod resourcing;

pub use declared::{cohort_cell, is_complete, missing_axes, parse_from_envelope};
