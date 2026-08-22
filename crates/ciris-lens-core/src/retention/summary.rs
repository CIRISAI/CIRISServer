//! [`EvictionPlan`] and [`EvictionSummary`] — the eviction
//! intermediate-form and result types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// **Can the configured disk bound actually ACT?** (CIRISServer#476)
///
/// The disk bound is measured on one axis and enforced on another: it reads
/// `StorageSummary::total_disk_bytes` — the WHOLE database — while the only
/// levers this policy owns are `delete_traces_older_than` (trace_events) and
/// `archive_audit_range` (audit_log). When a store's mass is in neither class,
/// the cap can be exceeded by any margin and the planner will correctly decide
/// to do nothing, forever.
///
/// That was measured in production, not imagined: the ciris-status node
/// carried a 389 MB engine store — 52,125 `federation_attestations`, 52,160
/// `signed_wire_index`, 21,322 `attestation_subjects` — and ZERO trace rows.
/// Every hourly pass logged "the store is inside every configured bound
/// (steady state, not a fault)". Setting a disk cap would not have changed one
/// byte of that outcome, and the log line would have said the same thing.
///
/// A bound that cannot bite must SAY SO. This verdict is how the planner
/// reports the difference between "nothing needed evicting" and "the bytes are
/// somewhere I cannot reach", which are opposite conditions that used to share
/// a log line and a `0`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiskPressure {
    /// No `max_disk_gb` configured — the disk axis carries no bound at all.
    ///
    /// Also the DEFAULT: a summary constructed without a verdict claims NO
    /// BOUND rather than a healthy one. Defaulting to `Within` would invent
    /// reassurance out of an unset field, which is the failure this whole
    /// type exists to remove.
    #[default]
    Unbounded,
    /// Under the eviction trigger. The ordinary healthy state.
    Within { used_bytes: u64, cap_bytes: u64 },
    /// At/over the trigger, and the plan CAN act: a trace cutoff or an audit
    /// archive range was produced, so this pass will free bytes.
    Relieving { used_bytes: u64, cap_bytes: u64 },
    /// At/over the trigger, and NO configured lever reaches the bytes.
    ///
    /// The evictable classes are empty (or already fully drained), so the mass
    /// lives in tables this policy cannot touch — and no future pass changes
    /// that on its own. This is a FAULT: the operator asked for a bound the
    /// system cannot honour, and must hear about it.
    Unreachable {
        used_bytes: u64,
        cap_bytes: u64,
        /// Rows the levers CAN reach (trace_events + audit_log). Reported
        /// because it is almost always ~0 in this state, which is the
        /// diagnosis: the store is big and the reachable part is empty.
        evictable_rows: u64,
    },
}

impl DiskPressure {
    /// `true` when a configured bound is exceeded and unenforceable.
    #[must_use]
    pub fn is_unreachable(&self) -> bool {
        matches!(self, Self::Unreachable { .. })
    }

    /// `true` when the cap is at/over its trigger, actionable or not.
    #[must_use]
    pub fn is_over_trigger(&self) -> bool {
        matches!(self, Self::Relieving { .. } | Self::Unreachable { .. })
    }
}

/// What [`plan_eviction`](crate::retention::plan_eviction) decided
/// to do. Pure data; no I/O has happened yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvictionPlan {
    /// If `Some(ts)`, traces with `ts < this` are eligible for
    /// deletion via `Engine::delete_traces_older_than`. Combines
    /// `max_age_days` (always evaluated) with disk-pressure
    /// (`max_disk_gb` at ≥90% reached → push `ts` further toward
    /// `now` to free space).
    ///
    /// `None` = no trace eviction needed this pass.
    pub delete_traces_older_than: Option<DateTime<Utc>>,

    /// Per-call cap on rows deleted. Bounded to keep transactions
    /// small (Pi-class + Postgres both benefit). The executor loops
    /// until `delete_traces_older_than` returns < this (i.e. no
    /// more eligible rows), so a single call's cap doesn't bound
    /// total work — just per-statement work.
    pub trace_batch_size: usize,

    /// Whether the configured disk bound can actually act this pass — see
    /// [`DiskPressure`]. Carried on the PLAN (not re-derived by the driver)
    /// so the verdict a caller reports is the one the planner actually used.
    pub disk_pressure: DiskPressure,

    /// If `Some((from_ts, to_ts))`, audit-log entries with
    /// `recorded_at` in `[from_ts, to_ts)` are archived (and then
    /// truncated, preserving the chain) via
    /// `Engine::archive_audit_range`.
    ///
    /// `None` = no audit archival needed this pass.
    pub archive_audit_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
}

/// What [`execute_plan`](crate::retention::execute_plan) actually did
/// against the substrate. Returned from
/// [`evict_per_retention_policy`](crate::retention::
/// evict_per_retention_policy) for the caller to log / surface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvictionSummary {
    /// The disk-bound verdict this pass ran under — copied from the plan so a
    /// driver reports what the planner decided rather than recomputing it from
    /// a second reading of the store (two readers, one question: the drift this
    /// tree keeps paying for).
    pub disk_pressure: DiskPressure,

    /// Number of trace rows deleted across all batched calls.
    pub evicted_traces: usize,

    /// Number of audit-log rows archived (and truncated from live).
    pub archived_audit_entries: u64,

    /// Number of `archive_audit_range` calls that produced a non-
    /// empty archive blob. Useful for diagnostics — distinguishes
    /// "ran a no-op archive sweep" from "actually archived
    /// something."
    pub archived_audit_ranges: usize,

    /// Best-effort estimate of bytes freed from the live store.
    /// Computed from the pre/post `StorageSummary` deltas (so it
    /// includes index + TOAST shrink on Postgres but is `0` on
    /// SQLite where `dbstat` is typically not compiled in).
    pub freed_bytes_estimate: u64,
}
