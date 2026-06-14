//! v0.4 — `RetentionPolicy` enforcement (CIRISLensCore#13).
//!
//! Lens-core owns *policy* — the [`RetentionPolicy`](crate::config::
//! RetentionPolicy) config type shipped in v0.3 (1bd65e6). Persist
//! v2.7.0 (CIRISPersist#107) exposes the *primitives*:
//!
//! - `Engine::storage_summary()` — disk + row + age per table
//! - `Engine::delete_traces_older_than(ts, max_rows)` — batch-capped
//!   trace eviction
//! - `Engine::archive_audit_range(from, to)` — chain-preserving
//!   audit-log archival
//!
//! This module composes the two: reads the summary, projects the
//! policy onto an [`EvictionPlan`], executes it through the persist
//! primitives, returns an [`EvictionSummary`].
//!
//! # Planner / executor split
//!
//! The eviction logic is split:
//!
//! - [`plan_eviction`] — pure function over a `StorageSummary` + a
//!   `RetentionPolicy` + a `now` clock. Returns an [`EvictionPlan`].
//!   No I/O; trivially unit-testable across the threshold matrix.
//! - [`execute_plan`] — async; takes a `&Engine` + a plan; calls the
//!   persist primitives. Returns an [`EvictionSummary`].
//! - [`evict_per_retention_policy`] — the convenience entry point
//!   that wires them: `summary → plan → execute`.
//!
//! # What this v0.4 slice enforces
//!
//! | Policy field                       | v0.4 status                                |
//! |---                                 |---                                         |
//! | `max_age_days`                     | ✅ via `delete_traces_older_than`          |
//! | `max_disk_gb` (90% threshold)      | ✅ as oldest-first trace eviction           |
//! | `audit_log_max_age_days`           | ✅ via `archive_audit_range`               |
//! | `detection_events_max_age_days`    | ⏸ persist primitive not yet exposed       |
//! | `per_level_max_age`                | ⏸ trace_events has no per-level partition |
//!
//! The two ⏸ rows depend on follow-up persist surface (a level-
//! filtered delete + a detection_events delete primitive). The v0.4
//! ship is the three ✅ enforcements; ⏸ rows are silent no-ops with a
//! `tracing::debug!` note so operators see them as configured but
//! not yet acting.

pub mod eviction;
pub mod summary;

pub use eviction::{evict_per_retention_policy, execute_plan, plan_eviction, EvictionError};
pub use summary::{EvictionPlan, EvictionSummary};
