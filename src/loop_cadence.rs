//! Periodic-loop cadence: a fixed average period that does **not** align with
//! the node's other periodic loops.
//!
//! # Why this exists
//!
//! Every long-lived loop in the node used `tokio::time::interval(period)`
//! directly. Two consequences, both measured on the canonical in
//! CIRISServer#575:
//!
//! 1. **They all start at boot**, so every loop's tick lands on the same
//!    instant at `t = 0` and again at every common multiple of their periods.
//!    The config reconciler and the replication reconciler both run at 30 s,
//!    so *every* tick of one landed on a tick of the other.
//! 2. **A collision is not free.** A tick's reads run inline-sync on the
//!    request-serving runtime and serialize on one connection mutex, so two
//!    loops reading at once is the node's own read API stalling: `GET
//!    /v1/identity` p50 went 1.1 ms → 780 ms inside a burst, ~700×, on 6.9% of
//!    wall time, with zero non-200s. Nothing fails; it hangs.
//!
//! Nothing here makes a tick cheaper, and nothing here lets two ticks read at
//! once — that is CIRISPersist#829 (sqlite reads run inline-sync on the caller's
//! runtime behind one connection mutex). This
//! makes the collisions **rare and non-repeating** instead of systematic.
//!
//! # What it does
//!
//! Each loop declares a name. From that name comes:
//!
//! * a **phase** — a fixed offset in `[0, period)`, so two loops of the same
//!   period sit at different points in it rather than on top of each other;
//! * a **per-tick jitter** of ±[`JITTER_NUM`]/[`JITTER_DEN`] of the period, so
//!   that if the two schedules do drift into each other (a tick that overruns
//!   re-anchors, which is what produced #575's observed ~1.2 s-per-cycle beat)
//!   they cannot *stay* there.
//!
//! Both are derived from the name by a fixed, documented hash, not from an
//! RNG. A loop's schedule is therefore identical on every boot and in every
//! test, on every platform and every Rust version — a random phase would make
//! this file's own tests flaky and would let two loops collide by chance for a
//! long run. Determinism is the point; unpredictability is not a goal here.
//!
//! The average period is preserved exactly: deadlines are computed from a fixed
//! anchor as `anchor + phase + n × period ± jitter(n)`, so a slow tick does not
//! push the schedule later (no drift accumulation), and a deadline already
//! passed is **skipped** rather than fired late — the same contract as
//! `MissedTickBehavior::Skip`, which is what these loops used before.

use std::time::Duration;

use tokio::time::{sleep_until, Instant};

/// Jitter as a fraction of the period: ±1/10.
///
/// Large enough to break a beat of a few seconds per cycle (#575 measured
/// ~1.2 s), small enough that a cadence an operator set to 30 s still means
/// 30 s. The average is exactly the period — the jitter is symmetric about the
/// deadline, not added to it.
const JITTER_NUM: u64 = 1;
const JITTER_DEN: u64 = 10;

/// FNV-1a, 64-bit. Fixed by this file rather than taken from `DefaultHasher`,
/// whose output std explicitly does not guarantee across Rust releases — a
/// phase that moved under the node's feet on a toolchain bump would be a
/// genuinely baffling thing to debug.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// SplitMix64 — one round, so successive tick ordinals of the same loop get
/// uncorrelated jitter instead of a ramp.
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// A periodic schedule that keeps its average period and stays out of its
/// siblings' way. Construct one per loop; call [`Cadence::tick`] where the loop
/// used `interval.tick()`.
pub struct Cadence {
    name: &'static str,
    period: Duration,
    seed: u64,
    anchor: Instant,
    /// Ordinal of the next deadline. Tick 0 is immediate (see [`Cadence::tick`]).
    seq: u64,
}

impl Cadence {
    /// A cadence named `name` with average period `period`.
    ///
    /// `name` must be unique per loop and stable across releases: it *is* the
    /// phase. Renaming a loop moves its slot, which is harmless but will show
    /// up as a one-time change in when it runs.
    ///
    /// A zero period would make every deadline immediate and busy-spin, so it
    /// is clamped to one second; the callers already clamp their configured
    /// cadences, and this is the backstop for the one that forgets.
    pub fn new(name: &'static str, period: Duration) -> Self {
        let period = if period.is_zero() {
            Duration::from_secs(1)
        } else {
            period
        };
        Self {
            name,
            period,
            seed: fnv1a(name.as_bytes()),
            anchor: Instant::now(),
            seq: 0,
        }
    }

    /// This loop's fixed offset into its period.
    pub fn phase(&self) -> Duration {
        let nanos = self.period.as_nanos() as u64;
        Duration::from_nanos(self.seed % nanos.max(1))
    }

    /// The jitter applied to tick `n`, in `[-period/10, +period/10]`.
    fn jitter(&self, n: u64) -> i64 {
        let span = (self.period.as_nanos() as u64 / JITTER_DEN) * JITTER_NUM;
        if span == 0 {
            return 0;
        }
        let r = splitmix64(self.seed ^ n);
        // Map into [-span, +span].
        (r % (2 * span + 1)) as i64 - span as i64
    }

    /// How long after the anchor tick `n` is due. Pure arithmetic on the name,
    /// the period and the ordinal — no clock — which is what the schedule tests
    /// assert on, so they can never flake on a slow machine.
    fn offset(&self, n: u64) -> Duration {
        let base = self.phase() + self.period * (n as u32);
        let j = self.jitter(n);
        if j >= 0 {
            base + Duration::from_nanos(j as u64)
        } else {
            base.saturating_sub(Duration::from_nanos(j.unsigned_abs()))
        }
    }

    /// The absolute deadline for tick `n`.
    fn deadline(&self, n: u64) -> Instant {
        self.anchor + self.offset(n)
    }

    /// Wait for the next tick.
    ///
    /// The **first** call returns immediately, matching the immediate first
    /// tick of `tokio::time::interval` that these loops were written against:
    /// a node that just booted should converge its config and its peers now,
    /// not up to a period from now. The phase applies from the second tick on,
    /// which is where the steady-state collisions were.
    ///
    /// A deadline that has already passed is skipped rather than fired late, so
    /// a tick that overruns its period does not produce a catch-up burst.
    pub async fn tick(&mut self) {
        if self.seq == 0 {
            self.seq = 1;
            return;
        }
        loop {
            let deadline = self.deadline(self.seq);
            self.seq += 1;
            if deadline > Instant::now() {
                sleep_until(deadline).await;
                return;
            }
            // Missed: skip it (MissedTickBehavior::Skip).
        }
    }

    /// Put the next deadline a full period from **now**, keeping the period.
    ///
    /// For a loop that has just slept out-of-band (a backoff pause) and must
    /// not have its next tick already due the moment it returns — the pause
    /// would otherwise buy nothing.
    pub fn reset(&mut self) {
        self.anchor = Instant::now();
        self.seq = 1;
    }

    /// Adopt a new period, keeping the loop's phase identity.
    ///
    /// Re-anchors to now, so the next deadline is one fresh period away rather
    /// than derived from an ordinal counted at the old period.
    pub fn retune(&mut self, period: Duration) {
        self.period = if period.is_zero() {
            Duration::from_secs(1)
        } else {
            period
        };
        self.reset();
    }

    /// The average period. The jitter is symmetric, so this is the real one.
    pub fn period(&self) -> Duration {
        self.period
    }

    /// This cadence's name, for the loop's own startup log line.
    pub fn name(&self) -> &'static str {
        self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phases_are_distinct_at_the_shared_thirty_second_period() {
        // The two loops CIRISServer#575 measured beating against each other.
        let p = Duration::from_secs(30);
        let a = Cadence::new("config_reconcile", p);
        let b = Cadence::new("replication_reconcile", p);
        assert_ne!(
            a.phase(),
            b.phase(),
            "the two 30 s reconcilers must not share a phase — that IS #575"
        );
        let gap = a.phase().abs_diff(b.phase());
        let gap = gap.min(p - gap);
        assert!(
            gap >= Duration::from_secs(2),
            "phases {:?} and {:?} are only {gap:?} apart; a tick is longer than that",
            a.phase(),
            b.phase()
        );
    }

    #[test]
    fn phase_is_stable_across_constructions() {
        let p = Duration::from_secs(30);
        assert_eq!(
            Cadence::new("config_reconcile", p).phase(),
            Cadence::new("config_reconcile", p).phase(),
            "a loop's phase must be the same on every boot"
        );
    }

    #[test]
    fn jitter_is_bounded_and_averages_out() {
        let p = Duration::from_secs(30);
        let c = Cadence::new("config_reconcile", p);
        let span = (p.as_nanos() as u64 / JITTER_DEN) as i64;
        let mut sum: i128 = 0;
        for n in 0..10_000u64 {
            let j = c.jitter(n);
            assert!(j.abs() <= span, "jitter {j} exceeds ±{span} ns");
            sum += j as i128;
        }
        let mean = (sum / 10_000).unsigned_abs() as u64;
        assert!(
            mean < (span as u64) / 10,
            "jitter mean {mean} ns should sit near zero, not shift the cadence"
        );
    }

    #[test]
    fn two_same_period_loops_do_not_lock_into_a_beat() {
        // #575's tell: the gap between the two loops' ticks changed by a
        // near-constant ~1.2 s per cycle, so collisions recurred on a
        // schedule. With per-tick jitter the gap must keep moving, and must
        // not spend long near zero.
        let p = Duration::from_secs(30);
        let a = Cadence::new("config_reconcile", p);
        let b = Cadence::new("replication_reconcile", p);
        let base = a.phase().as_nanos() as i64 - b.phase().as_nanos() as i64;
        let mut collisions = 0usize;
        // A collision = the two ticks land within a second of each other,
        // which is the width of a burst #575 measured.
        for n in 1..1_000u64 {
            let gap = (base + a.jitter(n) - b.jitter(n)).abs();
            if gap < Duration::from_secs(1).as_nanos() as i64 {
                collisions += 1;
            }
        }
        assert!(
            collisions < 50,
            "{collisions}/999 ticks collide — the phases are not separating the loops"
        );
    }

    #[test]
    fn consecutive_ticks_are_one_period_apart_on_average() {
        let p = Duration::from_secs(30);
        let c = Cadence::new("config_reconcile", p);
        let slack = p / JITTER_DEN as u32 * 2;
        let mut total = Duration::ZERO;
        for n in 1..1_000u64 {
            let step = c.offset(n + 1) - c.offset(n);
            assert!(
                step > p - slack && step < p + slack,
                "tick {n}→{} is {step:?} apart; the period is {p:?}",
                n + 1
            );
            total += step;
        }
        let mean = total / 999;
        let drift = mean.abs_diff(p);
        assert!(
            drift < p / 100,
            "mean step {mean:?} drifts {drift:?} from the {p:?} period — jitter must \
             not shift the cadence, only move each tick within it"
        );
    }

    #[test]
    fn the_schedule_does_not_accumulate_drift() {
        // Deadlines come from a fixed anchor, so tick 1000 is ~1000 periods
        // out no matter how long any individual tick took.
        let p = Duration::from_secs(30);
        let c = Cadence::new("replication_reconcile", p);
        let far = c.offset(1_000);
        let want = c.phase() + p * 1_000;
        assert!(
            far.abs_diff(want) <= p / JITTER_DEN as u32,
            "tick 1000 at {far:?} vs {want:?} — the anchor should not have moved"
        );
    }

    #[tokio::test]
    async fn first_tick_is_immediate_and_later_ticks_wait() {
        let p = Duration::from_millis(120);
        let mut c = Cadence::new("config_reconcile", p);
        let t0 = std::time::Instant::now();
        c.tick().await;
        // Generous: the assertion is "did not wait a period", not "was fast".
        // A loaded CI runner can take a while to schedule a thread, and this
        // test must not fail for that.
        assert!(
            t0.elapsed() < p,
            "the first tick waited {:?} — a booting node reconciles now, not a \
             period from now",
            t0.elapsed()
        );
        c.tick().await;
        assert!(
            t0.elapsed() >= Duration::from_millis(30),
            "the second tick returned immediately — the schedule is not waiting"
        );
    }

    #[tokio::test]
    async fn an_overrunning_tick_skips_rather_than_bursts() {
        let p = Duration::from_millis(60);
        let mut c = Cadence::new("config_reconcile", p);
        c.tick().await; // immediate
        c.tick().await;
        // A tick that runs several periods long.
        tokio::time::sleep(p * 5).await;
        let before = std::time::Instant::now();
        c.tick().await;
        // Skip semantics: the missed deadlines are dropped, so this waits for a
        // real future one rather than firing immediately five times over.
        // Generous by 3x for a loaded runner: the assertion is that the missed
        // deadlines were DROPPED, not that the wait was short. A catch-up burst
        // would have fired immediately, five times over.
        assert!(
            before.elapsed() <= p * 3,
            "after overrunning, the next tick waited {:?}",
            before.elapsed()
        );
    }

    #[tokio::test]
    async fn retune_takes_effect() {
        let mut c = Cadence::new("config_reconcile", Duration::from_secs(30));
        assert_ne!(c.phase(), Duration::ZERO);
        c.tick().await;
        c.retune(Duration::from_millis(80));
        assert_eq!(c.period(), Duration::from_millis(80));
        let t0 = std::time::Instant::now();
        c.tick().await;
        assert!(
            t0.elapsed() < Duration::from_secs(1),
            "retune to 80 ms still waited {:?}",
            t0.elapsed()
        );
    }
}
