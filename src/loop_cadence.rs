//! Periodic-loop cadence: a fixed period, on a slot that no other loop shares.
//!
//! # Why this exists
//!
//! Every long-lived loop in the node used `tokio::time::interval(period)`.
//! Two consequences, both measured on the canonical in CIRISServer#575:
//!
//! 1. **They all start at boot**, so every loop's tick lands on the same
//!    instant at `t = 0` and again at every common multiple of their periods.
//!    The config reconciler and the replication reconciler both run at 30 s, so
//!    *every* tick of one landed on a tick of the other.
//! 2. **A collision is not free.** A tick's reads run inline-sync on the
//!    request-serving runtime and serialize on one connection mutex
//!    (CIRISPersist#829), so two loops reading at once is the node's own read
//!    API stalling: `GET /v1/identity` p50 went 1.1 ms → 780 ms inside a burst,
//!    ~700×, on 6.9% of wall time, with zero non-200s. Nothing fails; it hangs.
//!
//! Nothing here makes a tick cheaper, and nothing here lets two ticks read at
//! once — that is #829's half. This stops them from being scheduled together.
//!
//! # Slots, not hashes — and a fixed spacing, not a fraction
//!
//! [`LOOPS`] lists every periodic loop in the node, and **the order is the
//! allocation**: loop `i` sits `i × `[`SLOT_SPACING`] past the epoch.
//!
//! The spacing is a fixed duration rather than a fraction of each loop's
//! period, and that distinction is the whole correctness argument. A fraction
//! (`period × i / n`) spreads loops that share a period and silently *collides*
//! loops that do not: the 60 s scorer at slot 2 lands on `60 × 2 / 6 = 20 s`
//! and the 30 s delivery reconciler at slot 4 lands on `30 × 4 / 6 = 20 s`, so
//! against a shared epoch they coincide **exactly**, once a minute, forever
//! (Codex, PR #576).
//!
//! With a fixed spacing, two loops tick together only if
//! `(i − j) × SLOT_SPACING` is a multiple of `gcd(period_i, period_j)`. Every
//! cadence here defaults to a multiple of 30 s, so that gcd is at least 30 s
//! while `(i − j) × SLOT_SPACING` is at most 15 s — the separation is never
//! less than [`SLOT_SPACING`], at any of them.
//!
//! An operator who sets a cadence that shares no useful factor with the others
//! (7 s, say) can still produce occasional coincidences. That is a much smaller
//! claim than the one this replaced, and it is the honest one.
//!
//! An earlier version derived the phase by hashing the loop's name. It
//! looked deterministic and was — deterministically *clustered*: six hashed
//! points on a circle leave an expected smallest gap of about `period/n²`, and
//! the committed names put `federation_delivery` and `mesh_config_effect`
//! **1.54 s** apart, inside the 1–2 s burst width #575 measured. Hashing spreads
//! things on average; it does not spread six things. A list does.
//!
//! # One epoch
//!
//! Phases are only meaningful against a shared origin. Each loop anchoring at
//! its own `Instant::now()` would fold in the gap between one loop's
//! construction and the next — the loops are spawned across several seconds of
//! compose — so a 5 s slot separation could arrive as 3 s or 7 s. Every cadence
//! measures from [`epoch`], captured once per process.
//!
//! # No jitter
//!
//! Deadlines come from a fixed grid (`epoch + phase + n × period`), so a slow
//! tick never pushes the schedule later and two loops of equal period hold their
//! separation forever. There is no drift for jitter to break up, and jitter of
//! any useful size is larger than the gaps it would have to respect — the same
//! arithmetic that rules out hashed phases. Cross-period coincidences still
//! happen: a 30 s and a 3600 s loop share a tick instant once an hour by
//! definition. That is rare, bounded, and visible in the schedule, which is the
//! trade this file makes deliberately.

use std::time::Duration;

use tokio::time::{sleep_until, Instant};

/// Every periodic loop in the node. **The order is the phase allocation** — see
/// the module docs. `tests/loop_cadence_gate.rs` checks that this list and the
/// `Cadence::new` call sites in `src/` name exactly the same set, so neither can
/// drift from the other.
///
/// Adding a loop here moves the others' slots. That is intended: the invariant
/// is even spread, not a fixed offset for any one loop.
pub const LOOPS: [&str; 6] = [
    "config_reconcile",
    "replication_reconcile",
    "scorer",
    "retention",
    "federation_delivery",
    "mesh_config_effect",
];

/// The origin every cadence measures its phase from, captured once per process.
fn epoch() -> Instant {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// The gap between consecutive loop slots.
///
/// Wide enough to clear the 1-2 s bursts CIRISServer#575 measured, and narrow
/// enough that all of [`LOOPS`] fits well inside the shortest cadence the node
/// runs (`5 × 3 s = 15 s` against 30 s) — the margin is what keeps the
/// separation argument in the module docs true.
pub const SLOT_SPACING: Duration = Duration::from_secs(3);

/// This loop's offset into its period: slot `i` of [`LOOPS`] sits at
/// `i ×` [`SLOT_SPACING`], wrapped into the period.
///
/// The wrap only bites for a cadence shorter than `LOOPS.len() × SLOT_SPACING`,
/// which the node has none of; a 1 s cadence would put every loop back on
/// slot 0, and is documented rather than defended against.
///
/// An unregistered name gets slot 0 and warns rather than panicking. It is a
/// programming error the gate catches before it can ship, and slot 0 is what
/// every loop had before this module existed — so the failure mode is today's
/// behaviour, not a node that will not boot.
#[must_use]
pub fn phase_for(name: &str, period: Duration) -> Duration {
    match LOOPS.iter().position(|n| *n == name) {
        Some(slot) => {
            let offset = SLOT_SPACING * u32::try_from(slot).unwrap_or(0);
            if offset < period {
                offset
            } else {
                Duration::from_nanos((offset.as_nanos() % period.as_nanos().max(1)) as u64)
            }
        }
        None => {
            tracing::warn!(
                loop_name = name,
                "periodic loop is not registered in loop_cadence::LOOPS — it shares slot 0 \
                 with the first registered loop and can tick alongside it (CIRISServer#575); \
                 add it to that list"
            );
            Duration::ZERO
        }
    }
}

/// A periodic schedule on a slot no other loop shares. Construct one per loop;
/// call [`Cadence::tick`] where the loop used `interval.tick()`.
pub struct Cadence {
    name: &'static str,
    period: Duration,
    /// The grid origin: `base + n × period` is deadline `n`.
    base: Instant,
    /// Ordinal of the next deadline.
    seq: u64,
    /// Whether the immediate first tick has been taken.
    started: bool,
}

impl Cadence {
    /// A cadence named `name` with period `period`.
    ///
    /// `name` must appear in [`LOOPS`]; the gate enforces it.
    ///
    /// A zero period would make every deadline immediate and busy-spin, so it is
    /// clamped to one second. The callers already clamp their configured
    /// cadences; this is the backstop for the one that forgets.
    #[must_use]
    pub fn new(name: &'static str, period: Duration) -> Self {
        let period = if period.is_zero() {
            Duration::from_secs(1)
        } else {
            period
        };
        let mut c = Self {
            name,
            period,
            base: epoch() + phase_for(name, period),
            seq: 0,
            started: false,
        };
        c.seq = c.first_seq_after(Instant::now());
        c
    }

    /// The smallest ordinal whose deadline is strictly after `t`.
    ///
    /// Arithmetic, not a walk. `base` is the process epoch, so a loop
    /// constructed or retuned on a node that has been up for months is millions
    /// of periods along the grid; iterating to find the ordinal would run those
    /// millions of steps synchronously on a request-serving worker, and would
    /// get slower the longer the node stayed up (Codex, PR #576).
    fn first_seq_after(&self, t: Instant) -> u64 {
        if t <= self.base {
            return 0;
        }
        let elapsed = (t - self.base).as_nanos();
        let period = self.period.as_nanos().max(1);
        // deadline(n) > t  <=>  n > elapsed/period. An exact multiple lands ON
        // t, which is not "after", so it advances too.
        u64::try_from(elapsed / period + 1).unwrap_or(u64::MAX)
    }

    /// This loop's offset into its period.
    #[must_use]
    pub fn phase(&self) -> Duration {
        phase_for(self.name, self.period)
    }

    /// The absolute deadline for tick `n`.
    ///
    /// Nanosecond arithmetic rather than `Duration * u32`: against a
    /// process-lifetime epoch the ordinal outgrows `u32` on a short cadence.
    fn deadline(&self, n: u64) -> Instant {
        let nanos = u64::try_from(self.period.as_nanos())
            .unwrap_or(u64::MAX)
            .saturating_mul(n);
        self.base + Duration::from_nanos(nanos)
    }

    /// Wait for the next tick.
    ///
    /// The **first** call returns immediately, matching the immediate first tick
    /// of `tokio::time::interval` these loops were written against: a node that
    /// just booted should converge its config and its peers now, not a period
    /// from now.
    ///
    /// # Overrun
    ///
    /// If loop work ran past one or more deadlines, the first call after it
    /// returns **immediately** for the overdue tick and realigns to the grid,
    /// skipping the rest. That is `MissedTickBehavior::Skip`, which is what
    /// these loops had: a reconcile that has already fallen behind should retry
    /// at once, not sit idle for another cadence — precisely under load.
    ///
    /// # Cancellation
    ///
    /// Safe to drop. Every call site polls this inside `tokio::select!` against
    /// a config watch, a notify and a shutdown, so it is dropped often; the
    /// ordinal advances only *after* the sleep completes, so a losing race does
    /// not silently consume a deadline. Advancing first meant an unrelated
    /// config write could postpone the next pass by a full cadence, and a stream
    /// of them could postpone it indefinitely.
    pub async fn tick(&mut self) {
        if !self.started {
            self.started = true;
            return;
        }
        let now = Instant::now();
        let deadline = self.deadline(self.seq);
        if deadline <= now {
            // Overdue: take this tick now, then realign past anything else that
            // elapsed while the work ran.
            self.seq = self.first_seq_after(now);
            return;
        }
        sleep_until(deadline).await;
        // Realign from the clock, not `seq + 1`, and only here — see the
        // cancellation note.
        //
        // The runtime may not poll this future until well after `deadline`:
        // that is precisely what happens when the request-serving workers are
        // blocked on the database, which is the condition this whole module
        // exists for. Advancing by one would leave the NEXT ordinal already
        // overdue, so the following call would return at once and run two
        // passes back to back — the burst Skip exists to prevent (Codex,
        // PR #576).
        self.seq = self.first_seq_after(Instant::now());
    }

    /// Put the next deadline a **full period or more** from now, keeping the
    /// loop's slot.
    ///
    /// For a loop that has just slept out-of-band (a backoff pause) and must not
    /// have its next tick already due the moment it returns — the pause would
    /// otherwise buy nothing.
    pub fn reset(&mut self) {
        self.seq = self.first_seq_after(Instant::now() + self.period);
    }

    /// Adopt a new period, keeping the loop's slot.
    ///
    /// The next deadline lands on the new grid **within one new period**, so
    /// shortening 3600 s to 30 s takes effect in under 30 s rather than in the
    /// remainder of the old hour. (Unlike [`reset`](Self::reset), which is
    /// deliberately at least a period out.)
    pub fn retune(&mut self, period: Duration) {
        self.period = if period.is_zero() {
            Duration::from_secs(1)
        } else {
            period
        };
        self.base = epoch() + self.phase();
        self.seq = self.first_seq_after(Instant::now());
    }

    /// The period.
    #[must_use]
    pub fn period(&self) -> Duration {
        self.period
    }

    /// This cadence's name, for the loop's own startup log line.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The node's real default cadences. Every one is a multiple of 30 s,
    /// which is the premise the separation argument rests on — if a default
    /// changes to something coprime, this list changing is the reminder.
    const DEFAULT_PERIODS: [(&str, u64); 6] = [
        ("config_reconcile", 30),
        ("replication_reconcile", 30),
        ("scorer", 60),
        ("retention", 3600),
        ("federation_delivery", 30),
        ("mesh_config_effect", 60),
    ];

    /// The test that would have caught the fraction-based allocation: walk a
    /// day of real tick instants for the real periods and assert no two loops
    /// ever land on top of each other.
    ///
    /// The fraction put the 60 s scorer and the 30 s delivery reconciler both
    /// at 20 s, coinciding exactly once a minute (Codex, PR #576). Checking the
    /// spread *within* one period could never have seen it.
    #[test]
    fn no_two_loops_ever_tick_together_at_the_default_periods() {
        const DAY: u64 = 24 * 60 * 60;
        let ticks = |name: &str, period: u64| -> Vec<u64> {
            let phase = phase_for(name, Duration::from_secs(period)).as_secs();
            (0..)
                .map(|n| phase + n * period)
                .take_while(|t| *t <= DAY)
                .collect()
        };
        let all: Vec<(&str, Vec<u64>)> = DEFAULT_PERIODS
            .iter()
            .map(|(n, p)| (*n, ticks(n, *p)))
            .collect();
        let floor = SLOT_SPACING.as_secs();
        for (i, (a, ta)) in all.iter().enumerate() {
            for (b, tb) in all.iter().skip(i + 1) {
                let mut closest = u64::MAX;
                for x in ta {
                    // Both series are sorted; a linear scan of a day is cheap
                    // enough and obviously correct.
                    for y in tb {
                        closest = closest.min(x.abs_diff(*y));
                    }
                }
                assert!(
                    closest >= floor,
                    "{a} and {b} come within {closest}s of each other over a day; the slot \
                     spacing is {floor}s"
                );
            }
        }
    }

    #[test]
    fn slots_are_one_spacing_apart() {
        let p = Duration::from_secs(30);
        for (i, a) in LOOPS.iter().enumerate() {
            for b in LOOPS.iter().skip(i + 1) {
                assert_ne!(phase_for(a, p), phase_for(b, p), "{a} and {b} share a slot");
            }
        }
        assert_eq!(
            phase_for(LOOPS[1], p) - phase_for(LOOPS[0], p),
            SLOT_SPACING
        );
    }

    /// The premise of the separation argument: every slot fits inside the
    /// shortest cadence the node runs, so no phase has to wrap.
    #[test]
    fn every_slot_fits_inside_the_shortest_cadence() {
        let shortest = Duration::from_secs(
            DEFAULT_PERIODS
                .iter()
                .map(|(_, p)| *p)
                .min()
                .expect("periods"),
        );
        let widest = SLOT_SPACING * (LOOPS.len() as u32 - 1);
        assert!(
            widest < shortest,
            "the slots span {widest:?} but the shortest cadence is {shortest:?} — phases \
             would wrap and two loops could share one"
        );
    }

    #[test]
    fn the_two_thirty_second_reconcilers_do_not_share_a_slot() {
        let p = Duration::from_secs(30);
        assert_ne!(
            phase_for("config_reconcile", p),
            phase_for("replication_reconcile", p),
            "these two sharing a phase IS #575"
        );
    }

    #[test]
    fn an_unregistered_loop_falls_back_rather_than_panicking() {
        assert_eq!(
            phase_for("not_a_registered_loop", Duration::from_secs(30)),
            Duration::ZERO,
            "an unregistered name must degrade to today's behaviour, not kill the node"
        );
    }

    /// The first tick is immediate; from the first SCHEDULED tick onward the
    /// cadence holds.
    ///
    /// Note what is deliberately not asserted: that the first scheduled tick is
    /// a whole period away. The grid is anchored to the process epoch, not to
    /// this constructor, so the next grid point can be moments off — which is
    /// exactly why a loop that must not run at once (retention deleting during
    /// the boot storm, the scorer scoring an empty corpus) asks for the delay
    /// with `reset()` rather than assuming it. An earlier version of this test
    /// asserted the second tick waited and failed on a Windows runner that
    /// happened to construct just before a grid point (PR #576).
    #[tokio::test]
    async fn first_tick_is_immediate_and_the_cadence_holds_after_it() {
        let p = Duration::from_millis(120);
        let mut c = Cadence::new("config_reconcile", p);
        let t0 = std::time::Instant::now();
        c.tick().await;
        assert!(
            t0.elapsed() < p,
            "the first tick waited {:?} — a booting node reconciles now",
            t0.elapsed()
        );
        c.tick().await; // lands on the next grid point, however near
        let t1 = std::time::Instant::now();
        c.tick().await;
        let step = t1.elapsed();
        assert!(
            step > p / 2,
            "consecutive scheduled ticks were {step:?} apart; the period is {p:?}"
        );
    }

    /// Codex, PR #576: advancing the ordinal before the sleep completed made
    /// this cancellation-UNSAFE. Every call site polls it in `select!`, so a
    /// config write or a notify could silently consume a deadline and postpone
    /// the pass by a full cadence — repeatedly, indefinitely.
    #[tokio::test]
    async fn a_cancelled_tick_does_not_consume_its_deadline() {
        let p = Duration::from_millis(400);
        let mut c = Cadence::new("config_reconcile", p);
        c.tick().await; // immediate first
        for _ in 0..20 {
            tokio::select! {
                () = c.tick() => panic!("the tick should not have completed this fast"),
                () = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
        }
        // Twenty cancellations must not have eaten twenty deadlines: the next
        // real tick is still due within one period.
        let t0 = std::time::Instant::now();
        c.tick().await;
        assert!(
            t0.elapsed() <= p * 2,
            "after 20 cancelled polls the next tick took {:?} — deadlines were consumed \
             by the cancellations",
            t0.elapsed()
        );
    }

    /// Codex, PR #576: `MissedTickBehavior::Skip` returns the overdue tick
    /// IMMEDIATELY and skips only the rest. Waiting instead meant an already-slow
    /// reconcile idled another full cadence, precisely under load.
    #[tokio::test]
    async fn an_overdue_tick_fires_at_once_then_realigns() {
        let p = Duration::from_millis(80);
        let mut c = Cadence::new("config_reconcile", p);
        c.tick().await; // immediate first
        c.tick().await; // one scheduled tick
        tokio::time::sleep(p * 4).await; // the work overruns four periods
        let t0 = std::time::Instant::now();
        c.tick().await;
        assert!(
            t0.elapsed() < p / 2,
            "the overdue tick waited {:?} instead of firing at once",
            t0.elapsed()
        );
        // ...and does not then burst. Asserted over the next TWO ticks, not one:
        // realigning puts the next deadline somewhere in (0, p] — it can be
        // moments away, which is the grid working, not a burst. Two consecutive
        // scheduled ticks always span a whole period, and a catch-up burst
        // would have returned both at once.
        let t1 = std::time::Instant::now();
        c.tick().await;
        c.tick().await;
        assert!(
            t1.elapsed() >= p * 3 / 4,
            "two ticks after an overrun spanned {:?} — that is a catch-up burst",
            t1.elapsed()
        );
    }

    /// Codex, PR #576: `reset` set the ordinal to 1 while deadline 1 still
    /// carried the phase, so the wait was `phase + period` — 101 s for the
    /// 60 s scorer, 4,454 s for hourly retention.
    #[tokio::test]
    async fn reset_waits_at_least_one_period_and_not_much_more() {
        let p = Duration::from_millis(200);
        // A loop whose slot is late in the period is where the old bug was worst.
        let mut c = Cadence::new("mesh_config_effect", p);
        c.tick().await;
        c.reset();
        let t0 = std::time::Instant::now();
        c.tick().await;
        let waited = t0.elapsed();
        assert!(
            waited >= p,
            "reset must buy a full period; waited {waited:?} of {p:?}"
        );
        assert!(
            waited < p * 3,
            "reset waited {waited:?} — the phase is being added on top of the period again"
        );
    }

    /// Retune is the other half: the NEW cadence must take effect within one new
    /// period, not the remainder of the old one.
    #[tokio::test]
    async fn retune_takes_effect_within_one_new_period() {
        let mut c = Cadence::new("retention", Duration::from_secs(3600));
        c.tick().await;
        let short = Duration::from_millis(150);
        c.retune(short);
        assert_eq!(c.period(), short);
        let t0 = std::time::Instant::now();
        c.tick().await;
        assert!(
            t0.elapsed() <= short * 2,
            "after retuning 3600 s -> {short:?} the next tick took {:?}",
            t0.elapsed()
        );
    }
}
