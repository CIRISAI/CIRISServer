//! **The reading that asks itself** (CIRISServer#369 follow-on).
//!
//! # The half that was still missing
//!
//! `FSD/RCA_INGEST_REJECTION_2026-08-05.md` closes with a demand:
//!
//! > "nothing is happening" is the hardest condition to detect, because it has
//! > no positive signal to match on.
//!
//! CIRISServer#369 and #370 built the signal: [`crate::operator_surface`] bands
//! trace-plane liveness and the refusal rate, and `GET /v1/node/state` renders
//! both. But that surface is **pull**. This process runs seven periodic loops —
//! retention, the scorer, config reconcile, replication reconcile, federation
//! delivery, equivocation, mesh-config refresh — and not one of them asks *"is
//! the trace plane alive?"*. On 2026-08-04 a node running this exact build would
//! have held a correct red band that no one requested, which is the outage's own
//! shape moved up a level: the information exists and has no reader.
//!
//! So this loop is the reader. It computes the SAME two standings the surface
//! renders (one source, one answer — it re-derives nothing) and writes them to
//! the node log, where the routine soak check that eventually found the outage
//! was already looking.
//!
//! # Edge-triggered, because the RCA is about log volume nobody read
//!
//! The failure being cured is *"8,631 refusals a day visible only as log volume
//! nobody was reading."* A watch that logged its verdict every tick would
//! reproduce that defect while claiming to fix it — 96 lines a day saying the
//! same thing, which is how an operator learns to filter a source out.
//!
//! So it logs on **transition** — when the (trace-plane, ingest) standing pair
//! changes — plus one restatement per [`RESTATE_AFTER`] while the condition is
//! non-green, so a red that began last week is still on today's page. A green
//! run is one line at startup and then silence until something moves.
//!
//! [`decide`] is that whole policy as a pure function over an explicit clock, so
//! the discipline is testable without waiting on a timer. The loop below only
//! reads the substrate and calls it.
//!
//! # Cost
//!
//! Each tick is one [`Engine::storage_summary`] — six table aggregates plus two
//! SQLite `PRAGMA`s, of which this uses one, and `count(*)` is a scan on
//! Postgres over the node's largest table. That is why the cadence is
//! [`WATCH_CADENCE`] (15 minutes, 96 reads a day) and not seconds: the surface's
//! own docs warn that `storage_summary` is not a thing to poll hard, and a
//! watchdog that costs more than the condition it watches is its own incident.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ciris_persist::federation::node_state::StateBand;
use ciris_persist::prelude::Engine;

use crate::ingest_http::IngestRefusals;
use crate::operator_surface::{
    ingest_standing, trace_plane_standing, IngestStanding, TraceCorpus, TracePlaneStanding,
};

/// How often the watch takes a reading.
///
/// 15 minutes: fast enough that the yellow band ([`TRACE_GREEN_MAX_HOURS`] = 6 h)
/// is announced within a rounding error of when it opens, slow enough that the
/// `storage_summary` scan is 96 reads a day rather than 86,400.
///
/// [`TRACE_GREEN_MAX_HOURS`]: crate::operator_surface::TRACE_GREEN_MAX_HOURS
pub const WATCH_CADENCE: Duration = Duration::from_secs(15 * 60);

/// How long a *standing* condition goes unrestated before the watch says it
/// again.
///
/// Six hours: four lines a day for a genuinely stuck node, which is a report;
/// ninety-six would be a feed. The restatement exists because a transition-only
/// watch is silent about a red that began before today's log file, and the
/// operator reading today's log is the one who has to act.
pub const RESTATE_AFTER: chrono::Duration = chrono::Duration::hours(6);

/// One reading — the two standings the operator surface renders, and nothing
/// else. Deliberately NOT a band: the band is a judgement and this type is an
/// observation, and folding them would let this module answer a question
/// `operator_surface` already answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    /// CIRISServer#369 — has a trace been admitted lately.
    pub trace: TracePlaneStanding,
    /// CIRISServer#370 — is the admission gate working overtime.
    pub ingest: IngestStanding,
}

impl Reading {
    /// The worse of the two bands — what an operator's eye should be drawn to.
    #[must_use]
    pub fn band(self) -> StateBand {
        self.trace.band().worse(self.ingest.band())
    }

    /// The reading, from the two inputs the operator surface uses. Takes the
    /// SAME `Result`/`Option` shapes so an unreadable corpus and an unmounted
    /// ledger cannot be laundered into observations on the way in.
    #[must_use]
    pub fn of(
        corpus: Result<TraceCorpus, &str>,
        refusals: Option<&crate::ingest_http::IngestRefusalBundle>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            trace: trace_plane_standing(corpus, now),
            ingest: ingest_standing(refusals),
        }
    }
}

/// What the watch decided to do with a reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emit {
    /// The condition changed. Always announced, in either direction — a
    /// recovery is as much news as a fault, and a watch that only ever reports
    /// bad news gives an operator no way to confirm a fix landed.
    Changed,
    /// The condition is unchanged and non-green, and has gone unrestated for
    /// [`RESTATE_AFTER`].
    Restated,
}

/// The watch's memory. One value, so the policy below is a function of it and
/// the reading rather than of ambient state.
#[derive(Debug, Clone, Copy, Default)]
pub struct Watch {
    last: Option<Reading>,
    last_emitted_at: Option<DateTime<Utc>>,
}

impl Watch {
    /// A fresh watch that has never read anything.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last: None,
            last_emitted_at: None,
        }
    }

    /// **The whole policy.** Fold `reading` in and say whether to speak.
    ///
    /// - the FIRST reading always speaks, whatever it says. A node that comes up
    ///   already dark has no transition to observe, and silence there would mean
    ///   the watch is quietest in exactly the case it exists for;
    /// - a changed pair always speaks, in both directions;
    /// - an unchanged GREEN pair never speaks;
    /// - an unchanged non-green pair speaks once per [`RESTATE_AFTER`].
    pub fn observe(&mut self, reading: Reading, now: DateTime<Utc>) -> Option<Emit> {
        let emit = match self.last {
            None => Some(Emit::Changed),
            Some(prev) if prev != reading => Some(Emit::Changed),
            Some(_) if reading.band() == StateBand::Green => None,
            Some(_) => {
                let due = self
                    .last_emitted_at
                    .is_none_or(|t| now.signed_duration_since(t) >= RESTATE_AFTER);
                due.then_some(Emit::Restated)
            }
        };
        self.last = Some(reading);
        if emit.is_some() {
            self.last_emitted_at = Some(now);
        }
        emit
    }

    /// The last reading folded in, if any.
    #[must_use]
    pub const fn last(&self) -> Option<Reading> {
        self.last
    }
}

/// Write one reading to the node log at the level its band earns.
///
/// The level IS the band, so a log-level filter and the operator surface cannot
/// disagree about severity — `red` is `ERROR`, `yellow` is `WARN`, and `unknown`
/// is `WARN` rather than `INFO` because an uncomputed signal is not a healthy
/// one and this whole arc exists because an absence read as an absence of
/// problems.
fn say(reading: Reading, emit: Emit, corpus: Result<TraceCorpus, &str>) {
    let last_admitted = corpus.ok().and_then(|c| c.last_admitted_at);
    let rows = corpus.ok().map(|c| c.rows);
    let why = match emit {
        Emit::Changed => "changed",
        Emit::Restated => "unchanged (restated)",
    };
    match reading.band() {
        StateBand::Green => tracing::info!(
            trace_plane = reading.trace.as_str(),
            ingest = reading.ingest.as_str(),
            ?last_admitted,
            ?rows,
            why,
            "trace-plane watch: the plane this node exists to receive on is being fed"
        ),
        StateBand::Yellow | StateBand::Unknown => tracing::warn!(
            trace_plane = reading.trace.as_str(),
            ingest = reading.ingest.as_str(),
            ?last_admitted,
            ?rows,
            why,
            band = reading.band().as_str(),
            "trace-plane watch: {} / {} — GET /v1/node/state carries the full reading",
            reading.trace.message().0,
            reading.ingest.message().0,
        ),
        StateBand::Red => tracing::error!(
            trace_plane = reading.trace.as_str(),
            ingest = reading.ingest.as_str(),
            ?last_admitted,
            ?rows,
            why,
            "trace-plane watch: {} / {} — arrival is the one thing this node exists to do. \
             GET /v1/node/state carries the full reading, including WHO is being refused.",
            reading.trace.message().0,
            reading.ingest.message().0,
        ),
    }
}

/// Take ONE reading and log it if the policy says to. Returns what it emitted,
/// so a caller (and a test) can see the decision rather than infer it from a log.
pub async fn tick(
    watch: &mut Watch,
    engine: &Engine,
    refusals: Option<&IngestRefusals>,
    now: DateTime<Utc>,
) -> Option<Emit> {
    // The SAME aggregate the operator surface reads. A second implementation of
    // "when did a trace last arrive" is the two-lists-that-disagree defect on
    // the one signal this node's health hangs on.
    let corpus = crate::operator_surface::corpus_of(engine.storage_summary().await);
    let bundle = refusals.map(|r| r.snapshot_at(now));
    let reading = Reading::of(
        corpus.as_ref().copied().map_err(String::as_str),
        bundle.as_ref(),
        now,
    );
    let emit = watch.observe(reading, now);
    if let Some(emit) = emit {
        say(
            reading,
            emit,
            corpus.as_ref().copied().map_err(String::as_str),
        );
    }
    emit
}

/// Spawn the watch. Runs for the life of the process.
///
/// `refusals` is the SAME ledger the ingest route counts into
/// ([`crate::operator_surface::trace_plane_router`] mints it); `None` on a
/// composition with no HTTP ingest route, which reads `unreadable` and never a
/// clean zero.
pub fn spawn(engine: Arc<Engine>, refusals: Option<IngestRefusals>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut watch = Watch::new();
        let mut interval = tokio::time::interval(WATCH_CADENCE);
        // The default `Burst` behaviour would fire the missed ticks back to back
        // after a stall; `Delay` keeps the cadence a cadence.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            tick(&mut watch, &engine, refusals.as_ref(), Utc::now()).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s)
            .expect("rfc3339 fixture")
            .with_timezone(&Utc)
    }

    const fn reading(trace: TracePlaneStanding, ingest: IngestStanding) -> Reading {
        Reading { trace, ingest }
    }

    const LIVE: Reading = reading(TracePlaneStanding::Live, IngestStanding::Clean);
    const DARK: Reading = reading(TracePlaneStanding::Dark, IngestStanding::StuckProducer);

    /// A node that comes up ALREADY DARK has no transition to observe. If the
    /// watch waited for a change it would be silent in exactly the case it
    /// exists for — a restarted canonical whose producer is still broken.
    #[test]
    fn the_first_reading_always_speaks_even_when_nothing_has_changed_yet() {
        let mut w = Watch::new();
        assert_eq!(
            w.observe(DARK, at("2026-08-05T13:55:00Z")),
            Some(Emit::Changed),
            "a watch that only reports transitions is silent about a condition that predates it"
        );

        // ...and so does a green first reading, so a healthy start is on the
        // record too. An operator cannot tell "the watch says nothing" from
        // "the watch is not running" unless it says something once.
        let mut w = Watch::new();
        assert_eq!(
            w.observe(LIVE, at("2026-08-05T13:55:00Z")),
            Some(Emit::Changed)
        );
    }

    /// **The RCA's own defect, applied to the cure.** 8,631 correct refusals a
    /// day were invisible because they were log volume nobody read. A watch that
    /// restated a green verdict every 15 minutes would be 96 lines a day of the
    /// same sentence — and an operator who filters this source out has lost the
    /// red line too.
    #[test]
    fn a_steady_green_falls_silent_rather_than_becoming_log_volume() {
        let mut w = Watch::new();
        let t0 = at("2026-08-05T00:00:00Z");
        assert_eq!(w.observe(LIVE, t0), Some(Emit::Changed), "the first line");
        // A whole day of ticks at the real cadence.
        for i in 1..=96 {
            let now = t0 + chrono::Duration::minutes(15 * i);
            assert_eq!(
                w.observe(LIVE, now),
                None,
                "a healthy node must not narrate itself (tick {i})"
            );
        }
    }

    /// A RED that began before today's log file must still be on today's page,
    /// and at a rate that reads as a report rather than a feed.
    #[test]
    fn a_standing_red_is_restated_but_only_four_times_a_day() {
        let mut w = Watch::new();
        let t0 = at("2026-08-03T23:30:00Z");
        assert_eq!(w.observe(DARK, t0), Some(Emit::Changed));

        let mut emitted = 0;
        // 24 hours of ticks at the real cadence.
        for i in 1..=96 {
            let now = t0 + chrono::Duration::minutes(15 * i);
            if let Some(e) = w.observe(DARK, now) {
                assert_eq!(e, Emit::Restated, "an unchanged condition is not a change");
                emitted += 1;
            }
        }
        assert_eq!(
            emitted, 4,
            "six-hourly while it stands: four lines a day is a report, ninety-six is a feed and \
             a feed is what nobody read"
        );
    }

    /// **A recovery is news.** A watch that announced only faults leaves an
    /// operator who applied a fix with no way to see it land, and the next
    /// person reading the log cannot tell a resolved incident from an ongoing
    /// one.
    #[test]
    fn a_recovery_speaks_as_loudly_as_the_fault() {
        let mut w = Watch::new();
        let t0 = at("2026-08-03T23:30:00Z");
        w.observe(DARK, t0);
        assert_eq!(
            w.observe(LIVE, t0 + chrono::Duration::minutes(15)),
            Some(Emit::Changed),
            "the plane came back and the log must say so"
        );
        assert_eq!(w.last(), Some(LIVE));
    }

    /// The pair is the unit, not the band. `dark`+`stuck_producer` (a producer
    /// being correctly refused) and `dark`+`clean` (nothing reaching this node
    /// at all) are the same band and different incidents with different first
    /// steps — so a move between them is a change and must be spoken.
    #[test]
    fn a_change_of_cause_at_an_unchanged_band_still_speaks() {
        let mut w = Watch::new();
        let t0 = at("2026-08-05T13:55:00Z");
        w.observe(DARK, t0);
        let silent_pipe = reading(TracePlaneStanding::Dark, IngestStanding::Clean);
        assert_eq!(silent_pipe.band(), DARK.band(), "same band by construction");
        assert_eq!(
            w.observe(silent_pipe, t0 + chrono::Duration::minutes(15)),
            Some(Emit::Changed),
            "'a producer is being refused' and 'nothing is reaching this node' are different \
             incidents; a watch that keys on the band alone conflates them"
        );
    }

    /// An UNKNOWN is not a healthy quiet. A corpus that could not be read and a
    /// ledger that is not mounted are non-green, get restated, and are logged at
    /// WARN — the whole arc exists because an absence of output read as an
    /// absence of problems.
    #[test]
    fn an_unreadable_reading_is_non_green_and_does_not_fall_silent() {
        let blind = reading(TracePlaneStanding::Unreadable, IngestStanding::Unreadable);
        assert_eq!(blind.band(), StateBand::Unknown);
        assert_ne!(blind.band(), StateBand::Green);

        let mut w = Watch::new();
        let t0 = at("2026-08-05T13:55:00Z");
        w.observe(blind, t0);
        assert_eq!(
            w.observe(blind, t0 + RESTATE_AFTER),
            Some(Emit::Restated),
            "a node that could not ask itself must keep saying so"
        );
    }

    /// The watch re-derives NOTHING: its reading is the operator surface's two
    /// narrowings, called. A second implementation would be a second answer, and
    /// the log and the surface would eventually disagree about one node.
    #[test]
    fn the_reading_is_the_surfaces_own_and_not_a_second_opinion() {
        let now = at("2026-08-05T13:55:00Z");
        let corpus = TraceCorpus {
            last_admitted_at: Some(at("2026-08-03T23:30:00Z")),
            rows: 120_000,
        };
        let r = Reading::of(Ok(corpus), None, now);
        assert_eq!(r.trace, trace_plane_standing(Ok(corpus), now));
        assert_eq!(r.ingest, ingest_standing(None));
        assert_eq!(r.band(), StateBand::Red);
        // ...and an unreadable corpus arrives as unreadable, not as an empty one.
        assert_eq!(
            Reading::of(Err("sqlite: database is locked"), None, now).trace,
            TracePlaneStanding::Unreadable
        );
    }
}
