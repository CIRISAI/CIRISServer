//! [`EvictionPlan`] and [`EvictionSummary`] — the eviction
//! intermediate-form and result types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
