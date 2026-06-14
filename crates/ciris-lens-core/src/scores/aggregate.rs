//! [`AgentScoreAggregate`] and the pure
//! [`compute_aggregate`] reduction.
//!
//! The aggregation is split out as a free function over
//! `&[DetectionEvent]` (not a method on the oracle) so it's
//! testable without any `Engine` — pure data in, pure data out.
//! The oracle's `for_agent_window` calls this after fetching.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use ciris_persist::derived::types::{ConformityVariant, DetectionEvent, DetectionSeverity};
use serde::{Deserialize, Serialize};

/// Time-window aggregate of an agent's scoring outcomes (FSD §4.6).
///
/// The agent's self-awareness loop reads this back after emitting
/// — counts of how many traces scored each conformity variant,
/// per-detector fire frequencies, severity distribution. The
/// shape is what `lens.scores.get_for_agent_window(...)` will
/// surface to Python once CIRISLensCore#11 lands the
/// `LensCore.client` ctor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentScoreAggregate {
    /// Inclusive window start.
    pub window_start: DateTime<Utc>,
    /// Inclusive window end (events with `ts > window_end` excluded).
    pub window_end: DateTime<Utc>,
    /// Total events counted across all conformity variants. NOT the
    /// distinct trace count — multiple events per trace (a manifold
    /// score + a declared/inferred-mismatch detection, say) count
    /// separately. Use `conformity_*` counts for per-decision
    /// breakdowns.
    pub traces_scored: u32,
    /// Events with [`ConformityVariant::Numeric`] — score was
    /// computable.
    pub conformity_numeric: u32,
    /// Events with [`ConformityVariant::Indeterminate`] — typed
    /// fail-secure (sample-size gate, ambiguous cohort, etc.). Never
    /// silently collapsed to a numeric.
    pub conformity_indeterminate: u32,
    /// Events with [`ConformityVariant::Unavailable`] — scoring
    /// machinery itself fell through (SLO breach, persist read
    /// failure, etc.).
    pub conformity_unavailable: u32,
    /// Per-detector fire count. Key is the `detector` field on
    /// `DetectionEvent`; value is the number of events with that
    /// detector in the window.
    pub detector_fire_counts: HashMap<String, u32>,
    /// Per-severity event count.
    pub severity_distribution: SeverityDistribution,
}

/// Per-severity event count. Three buckets matching
/// [`DetectionSeverity`]'s variants.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityDistribution {
    /// Diagnostic / observational. No alert action implied.
    pub info: u32,
    /// Notable; consumer policy may surface to operators.
    pub warning: u32,
    /// Federation-level evidence; consumers SHOULD react.
    pub critical: u32,
}

/// Reduce a slice of [`DetectionEvent`] to an
/// [`AgentScoreAggregate`] bounded by `[window_start, window_end]`.
///
/// Pure function. Events with `ts < window_start` or
/// `ts > window_end` are excluded (the caller already passed
/// `since = window_start` to the upstream filter; events past
/// `window_end` arrive when the EventFilter has no `until` field,
/// per persist v3.1.1 — the caller fetched "since" and we filter
/// "until" here).
///
/// If `detector_filter` is `Some`, events whose `detector` is not in
/// the filter set are excluded. `None` means no detector filter.
pub fn compute_aggregate(
    events: &[DetectionEvent],
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    detector_filter: Option<&[String]>,
    event_ts: impl Fn(&DetectionEvent) -> DateTime<Utc>,
) -> AgentScoreAggregate {
    let mut agg = AgentScoreAggregate {
        window_start,
        window_end,
        traces_scored: 0,
        conformity_numeric: 0,
        conformity_indeterminate: 0,
        conformity_unavailable: 0,
        detector_fire_counts: HashMap::new(),
        severity_distribution: SeverityDistribution::default(),
    };

    for event in events {
        let ts = event_ts(event);
        if ts < window_start || ts > window_end {
            continue;
        }
        if let Some(allowed) = detector_filter {
            if !allowed.iter().any(|d| d == &event.detector) {
                continue;
            }
        }

        agg.traces_scored += 1;
        match event.conformity_variant {
            ConformityVariant::Numeric => agg.conformity_numeric += 1,
            ConformityVariant::Indeterminate => agg.conformity_indeterminate += 1,
            ConformityVariant::Unavailable => agg.conformity_unavailable += 1,
        }
        match event.severity {
            DetectionSeverity::Info => agg.severity_distribution.info += 1,
            DetectionSeverity::Warning => agg.severity_distribution.warning += 1,
            DetectionSeverity::Critical => agg.severity_distribution.critical += 1,
        }
        *agg.detector_fire_counts
            .entry(event.detector.clone())
            .or_insert(0) += 1;
    }

    agg
}

/// Rank a [`DetectionSeverity`] for `min_severity` filtering.
/// `Info < Warning < Critical`. Used by [`crate::scores::oracle::
/// ScoresOracle::detector_history`].
pub fn severity_level(s: DetectionSeverity) -> u8 {
    match s {
        DetectionSeverity::Info => 0,
        DetectionSeverity::Warning => 1,
        DetectionSeverity::Critical => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        s.parse::<DateTime<Utc>>().unwrap()
    }

    fn make_event(
        detector: &str,
        severity: DetectionSeverity,
        conformity: ConformityVariant,
    ) -> DetectionEvent {
        DetectionEvent {
            detection_id: uuid::Uuid::nil(),
            trace_id: format!("trace-{detector}"),
            body_sha256: vec![0u8; 32],
            detector: detector.to_string(),
            severity,
            cohort_cell: serde_json::Value::Null,
            conformity_variant: conformity,
            conformity_payload: serde_json::Value::Null,
            lens_core_version: "test".into(),
            ratchet_calibration_version: 0,
            canonical_bytes: vec![],
            ed25519_sig: vec![0u8; 64],
            ml_dsa_65_sig: vec![0u8; 3309],
            signing_key_id: "test".into(),
            ts: t("2026-05-29T12:00:00Z"),
        }
    }

    /// Real callers pass `|e| e.ts`; tests use the same so the
    /// fixture's `ts` field drives window-boundary logic. The
    /// dedicated boundary test (`excludes_outside_window`) overrides
    /// per-event `ts` values to exercise the window filter.
    fn event_ts_field(e: &DetectionEvent) -> DateTime<Utc> {
        e.ts
    }

    #[test]
    fn empty_input_is_zero_aggregate() {
        let agg = compute_aggregate(
            &[],
            t("2026-05-29T00:00:00Z"),
            t("2026-05-30T00:00:00Z"),
            None,
            event_ts_field,
        );
        assert_eq!(agg.traces_scored, 0);
        assert_eq!(agg.conformity_numeric, 0);
        assert_eq!(agg.conformity_indeterminate, 0);
        assert_eq!(agg.conformity_unavailable, 0);
        assert!(agg.detector_fire_counts.is_empty());
        assert_eq!(agg.severity_distribution, SeverityDistribution::default());
    }

    #[test]
    fn counts_each_conformity_variant_independently() {
        let events = vec![
            make_event("d1", DetectionSeverity::Info, ConformityVariant::Numeric),
            make_event("d1", DetectionSeverity::Info, ConformityVariant::Numeric),
            make_event(
                "d2",
                DetectionSeverity::Warning,
                ConformityVariant::Indeterminate,
            ),
            make_event(
                "d3",
                DetectionSeverity::Critical,
                ConformityVariant::Unavailable,
            ),
        ];
        let agg = compute_aggregate(
            &events,
            t("2026-05-29T00:00:00Z"),
            t("2026-05-30T00:00:00Z"),
            None,
            event_ts_field,
        );
        assert_eq!(agg.traces_scored, 4);
        assert_eq!(agg.conformity_numeric, 2);
        assert_eq!(agg.conformity_indeterminate, 1);
        assert_eq!(agg.conformity_unavailable, 1);
    }

    #[test]
    fn detector_fire_counts_aggregate_by_token() {
        let events = vec![
            make_event("d1", DetectionSeverity::Info, ConformityVariant::Numeric),
            make_event("d1", DetectionSeverity::Info, ConformityVariant::Numeric),
            make_event("d1", DetectionSeverity::Info, ConformityVariant::Numeric),
            make_event("d2", DetectionSeverity::Info, ConformityVariant::Numeric),
        ];
        let agg = compute_aggregate(
            &events,
            t("2026-05-29T00:00:00Z"),
            t("2026-05-30T00:00:00Z"),
            None,
            event_ts_field,
        );
        assert_eq!(agg.detector_fire_counts.get("d1"), Some(&3));
        assert_eq!(agg.detector_fire_counts.get("d2"), Some(&1));
        assert_eq!(agg.detector_fire_counts.get("d3"), None);
    }

    #[test]
    fn severity_distribution_buckets_correctly() {
        let events = vec![
            make_event("d", DetectionSeverity::Info, ConformityVariant::Numeric),
            make_event("d", DetectionSeverity::Info, ConformityVariant::Numeric),
            make_event("d", DetectionSeverity::Warning, ConformityVariant::Numeric),
            make_event("d", DetectionSeverity::Critical, ConformityVariant::Numeric),
            make_event("d", DetectionSeverity::Critical, ConformityVariant::Numeric),
        ];
        let agg = compute_aggregate(
            &events,
            t("2026-05-29T00:00:00Z"),
            t("2026-05-30T00:00:00Z"),
            None,
            event_ts_field,
        );
        assert_eq!(agg.severity_distribution.info, 2);
        assert_eq!(agg.severity_distribution.warning, 1);
        assert_eq!(agg.severity_distribution.critical, 2);
    }

    #[test]
    fn detector_filter_excludes_others() {
        let events = vec![
            make_event("keep", DetectionSeverity::Info, ConformityVariant::Numeric),
            make_event("skip", DetectionSeverity::Info, ConformityVariant::Numeric),
            make_event("keep", DetectionSeverity::Info, ConformityVariant::Numeric),
        ];
        let filter = vec!["keep".to_string()];
        let agg = compute_aggregate(
            &events,
            t("2026-05-29T00:00:00Z"),
            t("2026-05-30T00:00:00Z"),
            Some(&filter),
            event_ts_field,
        );
        assert_eq!(agg.traces_scored, 2);
        assert_eq!(agg.detector_fire_counts.get("keep"), Some(&2));
        assert_eq!(agg.detector_fire_counts.get("skip"), None);
    }

    #[test]
    fn empty_detector_filter_excludes_everything() {
        // An empty allowlist means no detector is allowed — strict.
        let events = vec![make_event(
            "d",
            DetectionSeverity::Info,
            ConformityVariant::Numeric,
        )];
        let filter: Vec<String> = vec![];
        let agg = compute_aggregate(
            &events,
            t("2026-05-29T00:00:00Z"),
            t("2026-05-30T00:00:00Z"),
            Some(&filter),
            event_ts_field,
        );
        assert_eq!(agg.traces_scored, 0);
    }

    #[test]
    fn excludes_outside_window() {
        // EventFilter on persist's side carries `since` but no
        // `until` (v3.1.1) — `compute_aggregate` filters the upper
        // bound client-side. Test that boundary inclusivity matches
        // the doc: [window_start, window_end] inclusive on both ends.
        let mut before = make_event("a", DetectionSeverity::Info, ConformityVariant::Numeric);
        before.ts = t("2026-05-28T23:59:00Z");
        let mut in_window = make_event("b", DetectionSeverity::Info, ConformityVariant::Numeric);
        in_window.ts = t("2026-05-29T12:00:00Z");
        let mut after = make_event("c", DetectionSeverity::Info, ConformityVariant::Numeric);
        after.ts = t("2026-05-30T00:01:00Z");
        let events = vec![before, in_window, after];
        let agg = compute_aggregate(
            &events,
            t("2026-05-29T00:00:00Z"),
            t("2026-05-30T00:00:00Z"),
            None,
            event_ts_field,
        );
        assert_eq!(agg.traces_scored, 1);
        assert_eq!(agg.detector_fire_counts.get("b"), Some(&1));
    }

    #[test]
    fn severity_level_ranks_info_lt_warning_lt_critical() {
        assert!(
            severity_level(DetectionSeverity::Info) < severity_level(DetectionSeverity::Warning)
        );
        assert!(
            severity_level(DetectionSeverity::Warning)
                < severity_level(DetectionSeverity::Critical)
        );
    }

    #[test]
    fn serde_roundtrip_aggregate() {
        let agg = AgentScoreAggregate {
            window_start: t("2026-05-29T00:00:00Z"),
            window_end: t("2026-05-30T00:00:00Z"),
            traces_scored: 10,
            conformity_numeric: 7,
            conformity_indeterminate: 2,
            conformity_unavailable: 1,
            detector_fire_counts: [("manifold_conformity_outlier".to_string(), 5)]
                .into_iter()
                .collect(),
            severity_distribution: SeverityDistribution {
                info: 6,
                warning: 3,
                critical: 1,
            },
        };
        let json = serde_json::to_string(&agg).unwrap();
        let back: AgentScoreAggregate = serde_json::from_str(&json).unwrap();
        assert_eq!(agg, back);
    }
}
