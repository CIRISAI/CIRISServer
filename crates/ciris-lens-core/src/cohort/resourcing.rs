//! Resourcing tier classification per `CIRISAgent/FSD/TRACE_WIRE_FORMAT.md`
//! §3.3.
//!
//! The closed value enum is normative; the threshold partition is
//! research-grade and RATCHET-calibrated. Phase 1 lens-core does NOT
//! use this on the hot-path cohort routing — the 6-tuple of agent-
//! declared `deployment_profile` fields is the v0.1.0 cohort key per
//! wire spec §3.2 (see `OPEN_QUESTIONS.md` OQ-10 closure). Resourcing
//! is the 7th cohort axis (wire spec §3.3, lens-computed), not in the
//! Phase 1 hot path. The classifier exists for derived analytics and
//! post-calibration use.

use crate::extract::Features;

/// 4-band resourcing tier per `TRACE_WIRE_FORMAT.md` §3.3.
/// Value enum is normative; threshold partition is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourcingTier {
    /// `< 50K tokens/trace AND < $0.01/action` (illustrative;
    /// thresholds RATCHET-calibrated, not normative).
    Scarcity,
    /// `50–150K tokens AND $0.01–0.05`.
    Constrained,
    /// `150–250K tokens AND $0.05–0.10`.
    Standard,
    /// `> 250K tokens OR > $0.10/action`.
    Abundance,
}

/// Threshold parameters for tier classification. Delivered via the
/// OQ-03 channel (RATCHET calibration); version-stamped per
/// `lens_core_version` for federation determinism (LC-AV-19).
///
/// Three cuts produce four bands. Each cut is `(tokens_upper_bound,
/// cost_upper_bound)`; values <= both bounds fall into the lower
/// tier, values exceeding either bound move up.
#[derive(Debug, Clone)]
pub struct ResourcingParams {
    pub cuts: [(u64, f64); 3],
}

/// Classify a trace's continuous cost+tokens features into the 4-band
/// tier. **NOT called by Phase 1 cohort routing** — available for
/// derived analytics consumers and post-calibration RATCHET use.
pub fn classify(_features: &Features, _params: &ResourcingParams) -> ResourcingTier {
    todo!("phase 1 — defer until RATCHET calibration delivers thresholds")
}
