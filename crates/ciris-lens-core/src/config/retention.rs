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

    // ── Bound setters (CIRISServer#348) ─────────────────────────────────────
    //
    // The struct is `#[non_exhaustive]`, so a caller in ANOTHER crate — e.g.
    // ciris-server's retention loop, which projects the node's `config:*`
    // knobs onto a policy — cannot use a struct literal and cannot use
    // `..Default::default()` either. The remaining shape is
    // `let mut p = default(); p.field = ..;`, which clippy rejects
    // (`field_reassign_with_default`), so the only lint-clean way to build a
    // bounded policy from outside was to not build one at all. These exist so
    // the policy type is CONSTRUCTIBLE by its consumers.
    //
    // Named setters rather than a positional `bounded(a, b, c)` ctor on
    // purpose: three `Option<integer>` bounds in a row is exactly the shape
    // where two arguments swap silently and the compiler agrees.

    /// Set the global trace age cap (`None` = no time bound).
    pub fn with_max_age_days(mut self, days: Option<u32>) -> Self {
        self.max_age_days = days;
        self
    }

    /// Set the soft disk-usage cap in GB (`None` = no disk-pressure eviction).
    pub fn with_max_disk_gb(mut self, gb: Option<u64>) -> Self {
        self.max_disk_gb = gb;
        self
    }

    /// Set the audit-log age cap (`None` = never archive).
    pub fn with_audit_log_max_age_days(mut self, days: Option<u32>) -> Self {
        self.audit_log_max_age_days = days;
        self
    }

    /// Whether this policy bounds ANYTHING. A policy that bounds nothing is a
    /// legitimate operator choice (the sovereign anchor keeps everything) and
    /// also the state in which the local store grows until the disk fills — so
    /// the retention loop reports it as its own named outcome rather than
    /// running a sweep that provably cannot act.
    ///
    /// Counts exactly the three ✅ rows of the [`crate::retention`]
    /// enforcement table. `per_level_max_age` and
    /// `detection_events_max_age_days` are the ⏸ rows — configured but with no
    /// enforcement path — and counting them would let a node report itself
    /// bounded while nothing whatsoever bounds it, which is the more dangerous
    /// of the two wrong answers.
    pub fn is_bounded(&self) -> bool {
        self.max_disk_gb.is_some()
            || self.max_age_days.is_some()
            || self.audit_log_max_age_days.is_some()
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
