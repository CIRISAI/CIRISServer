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
//! # Slots, not hashes
//!
//! [`LOOPS`] lists every periodic loop in the node, and **the order is the
//! allocation**: loop `i` of `n` sits `i/n` of the way through its period. Six
//! loops on a 30 s period are 5 s apart, by construction, at every period.
//!
//! The first version of this derived the phase by hashing the loop's name. It
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

/// This loop's offset into its period: slot `i` of [`LOOPS`] sits at `i/n`.
///
/// An unregistered name gets slot 0 and warns rather than panicking. It is a
/// programming error the gate catches before it can ship, and slot 0 is what
/// every loop had before this module existed — so the failure mode is today's
/// behaviour, not a node that will not boot.
#[must_use]
pub fn phase_for(name: &str, period: Duration) -> Duration {
    match LOOPS.iter().position(|n| *n == name) {
        Some(slot) => period * slot as u32 / LOOPS.len() as u32,
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
    fn first_seq_after(&self, t: Instant) -> u64 {
        let mut n = 0u64;
        // The grid starts at `base`, which is at most one period before now on
        // construction and is re-derived on retune, so this walks a bounded
        // number of steps in practice; the cap is belt and braces.
        while n < u64::MAX && self.deadline(n) <= t {
            n += 1;
        }
        n
    }

    /// This loop's offset into its period.
    #[must_use]
    pub fn phase(&self) -> Duration {
        phase_for(self.name, self.period)
    }

    /// The absolute deadline for tick `n`.
    fn deadline(&self, n: u64) -> Instant {
        self.base + self.period * u32::try_from(n.min(u64::from(u32::MAX))).unwrap_or(u32::MAX)
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
        // Only here — see the cancellation note.
        self.seq += 1;
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

    #[test]
    fn slots_are_evenly_spread_at_every_period() {
        for secs in [30u64, 60, 300, 3600] {
            let p = Duration::from_secs(secs);
            let phases: Vec<Duration> = LOOPS.iter().map(|n| phase_for(n, p)).collect();
            let slot = p / LOOPS.len() as u32;
            for (i, a) in phases.iter().enumerate() {
                for b in phases.iter().skip(i + 1) {
                    let gap = a.abs_diff(*b);
                    let gap = gap.min(p - gap);
                    assert!(
                        gap >= slot,
                        "two loops sit {gap:?} apart in a {p:?} period; the slot width is \
                         {slot:?} — hashed phases were what clustered (#575 review)"
                    );
                }
            }
        }
    }

    /// The gap must clear the burst width #575 measured (1–2 s), not merely be
    /// non-zero.
    #[test]
    fn the_slot_width_clears_a_burst() {
        let slot = Duration::from_secs(30) / LOOPS.len() as u32;
        assert!(
            slot >= Duration::from_secs(2),
            "slot width {slot:?} at the shortest period does not clear a 1-2 s burst"
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

    #[tokio::test]
    async fn first_tick_is_immediate_and_later_ticks_wait() {
        let p = Duration::from_millis(120);
        let mut c = Cadence::new("config_reconcile", p);
        let t0 = std::time::Instant::now();
        c.tick().await;
        assert!(
            t0.elapsed() < p,
            "the first tick waited {:?} — a booting node reconciles now",
            t0.elapsed()
        );
        c.tick().await;
        assert!(
            t0.elapsed() >= Duration::from_millis(20),
            "the second tick returned immediately — the schedule is not waiting"
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
        // ...and does not then burst: the next one waits for the grid.
        let t1 = std::time::Instant::now();
        c.tick().await;
        assert!(
            t1.elapsed() > p / 4,
            "the tick after an overrun fired in {:?} — that is a catch-up burst",
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
