//! Eviction planner + executor.
//!
//! See [`crate::retention`] module doc for the design rationale.

use chrono::{DateTime, Duration, Utc};
use ciris_persist::prelude::Engine;

use crate::config::RetentionPolicy;
use crate::retention::summary::{EvictionPlan, EvictionSummary};

/// Per-statement batch size when looping `delete_traces_older_than`.
/// Keeps transactions small — both Postgres + SQLite happier on
/// short statements, and the surrounding ingest/verify pipeline
/// doesn't get stalled by a single 10M-row delete.
pub const DEFAULT_TRACE_BATCH_SIZE: usize = 1_000;

/// Disk-pressure threshold — eviction triggers at this fraction of
/// `max_disk_gb` reached. FSD §8.2: "Soft cap; triggers eviction
/// once 90% reached."
const DISK_EVICTION_THRESHOLD: f64 = 0.9;

/// Errors from [`evict_per_retention_policy`] / [`execute_plan`].
#[derive(Debug, thiserror::Error)]
pub enum EvictionError {
    /// Persist's retention primitive surfaced an error
    /// (storage_summary read, delete_traces_older_than,
    /// archive_audit_range).
    #[error("persist retention: {0}")]
    Persist(String),
}

impl From<ciris_persist::retention::RetentionError> for EvictionError {
    fn from(e: ciris_persist::retention::RetentionError) -> Self {
        Self::Persist(e.to_string())
    }
}

/// Plan eviction from a storage snapshot + policy + clock.
///
/// Pure function. No I/O; trivially testable across the threshold
/// matrix without an `Engine`.
pub fn plan_eviction(
    summary: &ciris_persist::retention::StorageSummary,
    policy: &RetentionPolicy,
    now: DateTime<Utc>,
) -> EvictionPlan {
    let mut delete_traces_older_than: Option<DateTime<Utc>> = None;

    // Dimension 1 — global age.
    if let Some(max_age_days) = policy.max_age_days {
        let cutoff = now - Duration::days(max_age_days as i64);
        delete_traces_older_than = Some(cutoff);
    }

    // Dimension 2 — disk pressure. If `total_disk_bytes` is at or
    // above 90% of `max_disk_gb`, push the trace-eviction cutoff
    // toward `now` to free disk. For v0.4 the heuristic is simple:
    // *if disk-pressured, evict EVERYTHING older than the
    // newest-half of the trace window.* A more sophisticated policy
    // (evict-until-below-threshold loop with size estimation) is a
    // follow-up; this v0.4 slice picks a conservative cut that's
    // monotonic — never *less* aggressive than `max_age_days`.
    if let Some(max_disk_gb) = policy.max_disk_gb {
        let cap_bytes = max_disk_gb.saturating_mul(1_000_000_000) as f64;
        if (summary.total_disk_bytes as f64) >= cap_bytes * DISK_EVICTION_THRESHOLD {
            // Use the trace_events table's age midpoint as the cut.
            // If the table is empty or has a single row, no cut.
            if let (Some(oldest), Some(newest)) = (
                summary.trace_events.oldest_ts,
                summary.trace_events.newest_ts,
            ) {
                let midpoint = oldest + (newest - oldest) / 2;
                // Take the more-aggressive (more-recent) cutoff so
                // disk pressure tightens, never loosens, the global-
                // age cutoff.
                delete_traces_older_than = Some(match delete_traces_older_than {
                    Some(existing) => existing.max(midpoint),
                    None => midpoint,
                });
            }
        }
    }

    // Dimension 3 — audit-log archival via archive_audit_range.
    // Archives entries in `[oldest, now - max_age_days)`. The chain
    // anchor (returned in `ArchiveHandle`) preserves verifiability.
    let archive_audit_range = policy.audit_log_max_age_days.and_then(|days| {
        let cutoff = now - Duration::days(days as i64);
        summary
            .audit_log
            .oldest_ts
            .filter(|oldest| *oldest < cutoff)
            .map(|oldest| (oldest, cutoff))
    });

    // Dimensions deliberately not enforced in this v0.4 slice:
    // - per_level_max_age: trace_events has no per-level partition
    //   in persist (capture is always FullTraces; level is an
    //   egress-time concept). Needs a level-filtered delete primitive.
    // - detection_events_max_age_days: persist's
    //   delete_traces_older_than is scoped to `trace_events`, not
    //   the derived `detection_events` table. Needs a separate
    //   primitive.

    EvictionPlan {
        delete_traces_older_than,
        trace_batch_size: DEFAULT_TRACE_BATCH_SIZE,
        archive_audit_range,
    }
}

/// Execute a planned eviction against the substrate. Loops
/// `delete_traces_older_than` until it returns less than
/// `trace_batch_size` (i.e. no more eligible rows). Calls
/// `archive_audit_range` once.
pub async fn execute_plan(
    engine: &Engine,
    plan: EvictionPlan,
) -> Result<EvictionSummary, EvictionError> {
    let bytes_before = engine.storage_summary().await?.total_disk_bytes;

    let mut evicted_traces: usize = 0;

    if let Some(cutoff) = plan.delete_traces_older_than {
        loop {
            let deleted = engine
                .delete_traces_older_than(cutoff, plan.trace_batch_size)
                .await?;
            evicted_traces += deleted;
            if deleted < plan.trace_batch_size {
                // No more eligible rows; persist drained the window.
                break;
            }
        }
    }

    // Audit-log archival via `Engine::archive_audit_range` is
    // gated on the persist `cirisaudit` feature, which lens-core
    // does not yet propagate (Cargo.toml v0.4 follow-up). The plan
    // carries `archive_audit_range = Some(..)` whenever the policy
    // requires it; the executor records this as a planned-but-
    // not-yet-executed action in the summary so operators see the
    // policy is configured even before the feature is on.
    let archived_audit_entries: u64 = 0;
    let archived_audit_ranges: usize = 0;
    if plan.archive_audit_range.is_some() {
        tracing::debug!(
            "audit_log_max_age_days configured but lens-core not built with the cirisaudit \
             passthrough; archive_audit_range was planned but not executed this pass",
        );
    }

    let bytes_after = engine.storage_summary().await?.total_disk_bytes;

    let freed_bytes_estimate = bytes_before.saturating_sub(bytes_after);

    Ok(EvictionSummary {
        evicted_traces,
        archived_audit_entries,
        archived_audit_ranges,
        freed_bytes_estimate,
    })
}

/// Plan + execute in one call. The convenience entry point for
/// callers driving periodic eviction.
pub async fn evict_per_retention_policy(
    engine: &Engine,
    policy: &RetentionPolicy,
) -> Result<EvictionSummary, EvictionError> {
    let summary = engine.storage_summary().await?;
    let plan = plan_eviction(&summary, policy, Utc::now());
    execute_plan(engine, plan).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_persist::retention::{StorageSummary, TableUsage};

    fn t(s: &str) -> DateTime<Utc> {
        s.parse::<DateTime<Utc>>().unwrap()
    }

    fn empty_summary() -> StorageSummary {
        StorageSummary {
            trace_events: TableUsage::default(),
            trace_llm_calls: TableUsage::default(),
            detection_events: TableUsage::default(),
            audit_log: TableUsage::default(),
            edge_outbound_queue: TableUsage::default(),
            federation_keys: TableUsage::default(),
            total_disk_bytes: 0,
        }
    }

    fn populated_summary(
        oldest: DateTime<Utc>,
        newest: DateTime<Utc>,
        bytes: u64,
    ) -> StorageSummary {
        let mut s = empty_summary();
        s.trace_events = TableUsage {
            bytes,
            rows: 1000,
            oldest_ts: Some(oldest),
            newest_ts: Some(newest),
        };
        s.total_disk_bytes = bytes;
        s
    }

    #[test]
    fn empty_policy_plans_nothing() {
        let plan = plan_eviction(
            &empty_summary(),
            &RetentionPolicy::default(),
            t("2026-05-28T00:00:00Z"),
        );
        assert!(plan.delete_traces_older_than.is_none());
        assert!(plan.archive_audit_range.is_none());
    }

    #[test]
    fn max_age_days_sets_trace_cutoff() {
        let now = t("2026-05-28T00:00:00Z");
        let policy = RetentionPolicy {
            max_age_days: Some(7),
            ..RetentionPolicy::default()
        };
        let plan = plan_eviction(&empty_summary(), &policy, now);
        assert_eq!(
            plan.delete_traces_older_than,
            Some(t("2026-05-21T00:00:00Z"))
        );
    }

    #[test]
    fn disk_pressure_below_threshold_no_eviction() {
        // 40GB used out of 50GB cap = 80% — below 90% threshold.
        let policy = RetentionPolicy {
            max_disk_gb: Some(50),
            ..RetentionPolicy::default()
        };
        let summary = populated_summary(
            t("2026-04-01T00:00:00Z"),
            t("2026-05-28T00:00:00Z"),
            40 * 1_000_000_000,
        );
        let plan = plan_eviction(&summary, &policy, t("2026-05-28T00:00:00Z"));
        assert!(plan.delete_traces_older_than.is_none());
    }

    #[test]
    fn disk_pressure_above_threshold_evicts_to_midpoint() {
        // 46GB out of 50GB = 92% — above 90% threshold.
        let policy = RetentionPolicy {
            max_disk_gb: Some(50),
            ..RetentionPolicy::default()
        };
        let summary = populated_summary(
            t("2026-04-01T00:00:00Z"),
            t("2026-05-28T00:00:00Z"),
            46 * 1_000_000_000,
        );
        let plan = plan_eviction(&summary, &policy, t("2026-05-28T00:00:00Z"));
        // Midpoint between 04-01 and 05-28: roughly 2026-04-29.
        let cutoff = plan.delete_traces_older_than.expect("must evict");
        assert!(cutoff > t("2026-04-28T00:00:00Z"));
        assert!(cutoff < t("2026-04-30T00:00:00Z"));
    }

    #[test]
    fn disk_pressure_does_not_loosen_age_cutoff() {
        // max_age_days picks 7 days (cutoff = 2026-05-21).
        // Disk pressure midpoint would pick ~2026-04-29 (more
        // permissive — older cutoff = less eviction).
        // Result must be the MORE aggressive cutoff: 2026-05-21.
        let now = t("2026-05-28T00:00:00Z");
        let policy = RetentionPolicy {
            max_age_days: Some(7),
            max_disk_gb: Some(50),
            ..RetentionPolicy::default()
        };
        let summary = populated_summary(
            t("2026-04-01T00:00:00Z"),
            t("2026-05-28T00:00:00Z"),
            46 * 1_000_000_000,
        );
        let plan = plan_eviction(&summary, &policy, now);
        assert_eq!(
            plan.delete_traces_older_than,
            Some(t("2026-05-21T00:00:00Z")),
            "age cutoff (more aggressive) must win over disk midpoint",
        );
    }

    #[test]
    fn audit_log_archival_when_aged() {
        let now = t("2026-05-28T00:00:00Z");
        let policy = RetentionPolicy {
            audit_log_max_age_days: Some(30),
            ..RetentionPolicy::default()
        };
        let mut summary = empty_summary();
        summary.audit_log = TableUsage {
            bytes: 0,
            rows: 100,
            oldest_ts: Some(t("2026-01-01T00:00:00Z")),
            newest_ts: Some(t("2026-05-28T00:00:00Z")),
        };
        let plan = plan_eviction(&summary, &policy, now);
        let (from_ts, to_ts) = plan.archive_audit_range.expect("must archive");
        assert_eq!(from_ts, t("2026-01-01T00:00:00Z"));
        assert_eq!(to_ts, t("2026-04-28T00:00:00Z"));
    }

    #[test]
    fn audit_log_no_archival_when_all_recent() {
        // Audit log's oldest entry is newer than the cutoff — nothing
        // to archive.
        let now = t("2026-05-28T00:00:00Z");
        let policy = RetentionPolicy {
            audit_log_max_age_days: Some(30),
            ..RetentionPolicy::default()
        };
        let mut summary = empty_summary();
        summary.audit_log = TableUsage {
            bytes: 0,
            rows: 100,
            oldest_ts: Some(t("2026-05-25T00:00:00Z")),
            newest_ts: Some(t("2026-05-28T00:00:00Z")),
        };
        let plan = plan_eviction(&summary, &policy, now);
        assert!(plan.archive_audit_range.is_none());
    }

    #[test]
    fn batch_size_is_default() {
        let plan = plan_eviction(
            &empty_summary(),
            &RetentionPolicy::default(),
            t("2026-05-28T00:00:00Z"),
        );
        assert_eq!(plan.trace_batch_size, DEFAULT_TRACE_BATCH_SIZE);
    }
}
