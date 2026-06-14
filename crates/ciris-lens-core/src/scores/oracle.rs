//! [`ScoresOracle`] — async read facade over
//! `Engine::get_detection_events` (persist v2.13.0 / CIRISPersist
//! #113) implementing FSD `LENS_CORE_V0_5.md` §4.6's three patterns.

use chrono::{DateTime, Utc};
use ciris_persist::derived::types::{DetectionEvent, DetectionSeverity, EventFilter};
use ciris_persist::prelude::Engine;

use crate::scores::aggregate::{compute_aggregate, severity_level, AgentScoreAggregate};

/// Borrows an [`Engine`] and serves the FSD §4.6 read patterns.
/// Held by reference rather than owned — same shape lens-core
/// already uses for short-lived per-query borrows; the host
/// constructs the `Engine` once and lends it to read paths.
pub struct ScoresOracle<'a> {
    engine: &'a Engine,
}

impl<'a> ScoresOracle<'a> {
    /// Wrap an `Engine` borrow. The lifetime is the caller's; an
    /// oracle does not outlive the engine that constructed it.
    pub fn new(engine: &'a Engine) -> Self {
        Self { engine }
    }

    /// All detection events filed against `trace_id`. Empty `Vec`
    /// if none — that includes traces that never produced a
    /// detection event (`ConformityVariant::Numeric` no-flag traces
    /// don't always persist a row, depending on detector policy).
    pub async fn for_trace(&self, trace_id: &str) -> Result<Vec<DetectionEvent>, OracleError> {
        let filter = EventFilter {
            trace_id: Some(trace_id.to_string()),
            detector: None,
            since: None,
        };
        self.engine
            .get_detection_events(filter)
            .await
            .map_err(|e| OracleError::Persist(e.to_string()))
    }

    /// Reduce events in `[window_start, window_end]` to an
    /// [`AgentScoreAggregate`]. `detector_filter` (if provided)
    /// restricts to the named detectors only — `None` aggregates
    /// across all.
    ///
    /// Uses `compute_aggregate` under the hood for the reduction;
    /// the upper bound (`window_end`) is filtered client-side
    /// since persist's [`EventFilter`] carries only `since`.
    pub async fn for_agent_window(
        &self,
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
        detector_filter: Option<&[String]>,
    ) -> Result<AgentScoreAggregate, OracleError> {
        let filter = EventFilter {
            trace_id: None,
            detector: None,
            since: Some(window_start),
        };
        let events = self
            .engine
            .get_detection_events(filter)
            .await
            .map_err(|e| OracleError::Persist(e.to_string()))?;

        // Persist v3.1.1 surfaces `ts` on `DetectionEvent`, so the
        // client-side window-end bound is exact (the upstream
        // `since` filter handles the lower bound).
        let agg = compute_aggregate(&events, window_start, window_end, detector_filter, |e| e.ts);
        Ok(agg)
    }

    /// Detection events for one detector since `since`, filtered to
    /// at least the given severity. Persist returns the slice in its
    /// native order; the slice is returned as-is here. Callers
    /// wanting newest-first sort by `recorded_at` (when persist
    /// surfaces it — see [`for_agent_window`]'s doc) or by
    /// `detection_id` UUIDv7-style ordering once persist ships v7.
    pub async fn detector_history(
        &self,
        detector: &str,
        since: DateTime<Utc>,
        min_severity: DetectionSeverity,
    ) -> Result<Vec<DetectionEvent>, OracleError> {
        let filter = EventFilter {
            trace_id: None,
            detector: Some(detector.to_string()),
            since: Some(since),
        };
        let events = self
            .engine
            .get_detection_events(filter)
            .await
            .map_err(|e| OracleError::Persist(e.to_string()))?;

        let min = severity_level(min_severity);
        let filtered: Vec<DetectionEvent> = events
            .into_iter()
            .filter(|e| severity_level(e.severity) >= min)
            .collect();
        Ok(filtered)
    }
}

/// Errors from [`ScoresOracle`].
#[derive(Debug, thiserror::Error)]
pub enum OracleError {
    /// Persist's read returned an error — pool exhausted, query
    /// timeout, schema-out-of-date, etc.
    #[error("persist read: {0}")]
    Persist(String),
}
