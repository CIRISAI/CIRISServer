//! `RetentionPolicy` — local-store eviction bounds (FSD §8).
//!
//! Lens-core owns the *policy*; persist exposes the deletion
//! primitives. The local trace + audit store evicts according to
//! the operator's configured disk budget + time bounds, with
//! per-trace_level age caps so FULL_TRACES can have shorter
//! retention than GENERIC (privacy posture).
//!
//! The shape ships in v0.3 so callers can already configure their
//! retention; **enforcement lands in v0.4** (CIRISLensCore#13) once
//! persist exposes `delete_traces_older_than` / `storage_summary` /
//! `archive_audit_range`. Constructing a `RetentionPolicy` in v0.3
//! is a no-op against the store but a non-op against the API
//! contract — once #13 lands, the same config drives enforcement
//! without a caller-side change.
//!
//! # Deviation from FSD §8 — `Option<u32>` for detection events
//!
//! FSD §8 typed `detection_events_max_age_days: u32` with the
//! documented default of "never (kept indefinitely)." `u32` has no
//! natural "never" sentinel. The sibling `audit_log_max_age_days`
//! is `Option<u32>` with the same "default: never" semantics; both
//! are unified to `Option<u32>` here. `None` = never. This is the
//! v0.5 FSD finalization intent.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::wire::TraceLevel;

/// Local-store retention configuration. None = no bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RetentionPolicy {
    /// Soft disk-usage cap for the local trace + audit store, in
    /// gigabytes. Eviction triggers once the store reaches ≈90% of
    /// this. `None` = no disk-pressure eviction (time-bound caps
    /// still apply).
    pub max_disk_gb: Option<u64>,

    /// Global age cap. Traces older than this auto-evict regardless
    /// of disk pressure. `None` = no global time bound.
    pub max_age_days: Option<u32>,

    /// Per-trace_level overrides. Keeps `FullTraces` short (privacy)
    /// while keeping `Generic` long (cohort-analysis utility).
    /// `None` (top-level) = every level inherits `max_age_days`.
    /// Any [`TraceLevel`] missing from the map inherits
    /// `max_age_days`.
    pub per_level_max_age: Option<HashMap<TraceLevel, u32>>,

    /// Detection-event retention. Signed federation evidence is
    /// typically kept far longer than the underlying traces (or
    /// forever). `None` = never expire.
    pub detection_events_max_age_days: Option<u32>,

    /// Audit-log retention. Hash chain MUST stay unbroken — eviction
    /// is "archive + truncate," never "delete." `None` = never
    /// expire (default; OQ-13 handles archival).
    pub audit_log_max_age_days: Option<u32>,
}

impl Default for RetentionPolicy {
    /// All-`None` policy — no eviction in any dimension. Pi-class
    /// deployments override `max_age_days`; production overrides
    /// `max_disk_gb` + `max_age_days`; sovereign-anchor leaves all
    /// `None`.
    fn default() -> Self {
        Self {
            max_disk_gb: None,
            max_age_days: None,
            per_level_max_age: None,
            detection_events_max_age_days: None,
            audit_log_max_age_days: None,
        }
    }
}

impl RetentionPolicy {
    /// Construct an indefinitely-retain policy. Same as `default()`;
    /// named ctor for sovereign-anchor deployment readability.
    pub fn indefinite() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_indefinite_retention() {
        let p = RetentionPolicy::default();
        assert_eq!(p.max_disk_gb, None);
        assert_eq!(p.max_age_days, None);
        assert!(p.per_level_max_age.is_none());
        assert_eq!(p.detection_events_max_age_days, None);
        assert_eq!(p.audit_log_max_age_days, None);
    }

    #[test]
    fn indefinite_ctor_equals_default() {
        assert_eq!(RetentionPolicy::indefinite(), RetentionPolicy::default());
    }

    #[test]
    fn serde_roundtrip_pi_class_config() {
        // Pi-class: 24h retention, no disk cap (small SSD assumed
        // adequate for 24h); detection events forever.
        let mut per_level = HashMap::new();
        per_level.insert(TraceLevel::FullTraces, 1);
        per_level.insert(TraceLevel::Detailed, 7);
        per_level.insert(TraceLevel::Generic, 90);

        let p = RetentionPolicy {
            max_disk_gb: None,
            max_age_days: Some(1),
            per_level_max_age: Some(per_level),
            detection_events_max_age_days: None,
            audit_log_max_age_days: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: RetentionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn serde_roundtrip_production_config() {
        // Production: 50GB cap, 90d global, FULL_TRACES 30d for
        // privacy posture; detection events forever; audit forever.
        let mut per_level = HashMap::new();
        per_level.insert(TraceLevel::FullTraces, 30);

        let p = RetentionPolicy {
            max_disk_gb: Some(50),
            max_age_days: Some(90),
            per_level_max_age: Some(per_level),
            detection_events_max_age_days: None,
            audit_log_max_age_days: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: RetentionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}
