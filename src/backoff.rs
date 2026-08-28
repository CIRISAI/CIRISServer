//! **Retry backoff** — decay a failing operation instead of running it flat out.
//!
//! Measured on the canonical in one 30-minute window, every retry in the mesh ran
//! at full cadence regardless of outcome:
//!
//! ```text
//! attestation refusals   2,253   four keys, none of them ever going to succeed
//! Key refusals              55   ONE row, one content_hash, refused every time
//! ```
//!
//! Those refusals are the senders' bugs. The *uniform* retry is what turns four
//! defects into thousands of log lines an hour on a node already at ~91% CPU, and
//! it is ours.
//!
//! # Why reset-on-success is the load-bearing half
//!
//! A backoff that only grows is a throttle: one transient failure permanently
//! slows a healthy peer. A backoff that never grows is what we have today. The
//! useful behaviour is the pair — double on failure, and drop straight back to the
//! floor the moment the operation works, so a peer that recovers is not still
//! being punished for a blip five minutes ago.
//!
//! # Not a substitute for terminal-refusal classification
//!
//! Backoff makes a permanently-refused row cheap; it does not make it stop.
//! `conflicting_version` will be refused on attempt 56 for the reason it was
//! refused on attempt 1, and only the sender learning that the verdict is terminal
//! ends it (CIRISEdge#544). This bounds the cost meanwhile.

use std::time::Duration;

/// Exponential backoff with a floor, a ceiling, and reset-on-success.
#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    max: Duration,
    current: Duration,
    consecutive_failures: u32,
}

impl Backoff {
    /// Build a backoff that starts at `base` and doubles to at most `max`.
    ///
    /// A `max` below `base` is raised to `base` rather than inverting the range.
    #[must_use]
    pub fn new(base: Duration, max: Duration) -> Self {
        let max = max.max(base);
        Self {
            base,
            max,
            current: base,
            consecutive_failures: 0,
        }
    }

    /// Record a failure and return how long to wait before the next attempt.
    pub fn fail(&mut self) -> Duration {
        let wait = self.current;
        self.current = (self.current * 2).min(self.max);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        wait
    }

    /// Record a success — the next failure starts again from the floor.
    pub fn succeed(&mut self) {
        self.current = self.base;
        self.consecutive_failures = 0;
    }

    /// Consecutive failures since the last success.
    #[must_use]
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// The delay the next `fail()` would return, without recording anything.
    #[must_use]
    pub fn peek(&self) -> Duration {
        self.current
    }

    /// Whether the ceiling has been reached — worth saying out loud in a log,
    /// because "backing off at the maximum" is a different operational state from
    /// "retrying briskly".
    #[must_use]
    pub fn at_ceiling(&self) -> bool {
        self.current >= self.max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn doubles_from_the_floor_and_stops_at_the_ceiling() {
        let mut b = Backoff::new(ms(100), ms(800));
        assert_eq!(b.fail(), ms(100));
        assert_eq!(b.fail(), ms(200));
        assert_eq!(b.fail(), ms(400));
        assert_eq!(b.fail(), ms(800));
        assert_eq!(b.fail(), ms(800), "clamped, not unbounded");
        assert!(b.at_ceiling());
    }

    #[test]
    fn success_returns_to_the_floor() {
        // The half that stops a backoff becoming a throttle: one blip must not
        // permanently slow a peer that has since recovered.
        let mut b = Backoff::new(ms(100), ms(8000));
        for _ in 0..5 {
            b.fail();
        }
        assert!(b.peek() > ms(100));
        b.succeed();
        assert_eq!(b.peek(), ms(100));
        assert_eq!(b.consecutive_failures(), 0);
        assert_eq!(b.fail(), ms(100), "next failure starts over");
    }

    #[test]
    fn counts_consecutive_failures_not_total() {
        let mut b = Backoff::new(ms(1), ms(10));
        b.fail();
        b.fail();
        assert_eq!(b.consecutive_failures(), 2);
        b.succeed();
        b.fail();
        assert_eq!(b.consecutive_failures(), 1);
    }

    #[test]
    fn an_inverted_range_does_not_invert_the_backoff() {
        let mut b = Backoff::new(ms(500), ms(100));
        assert_eq!(b.fail(), ms(500));
        assert_eq!(
            b.fail(),
            ms(500),
            "ceiling raised to the floor, never below it"
        );
    }

    #[test]
    fn a_long_outage_cannot_overflow_the_delay() {
        // 2,253 failures in 30 minutes is a real observed rate; the doubling must
        // saturate rather than wrap.
        let mut b = Backoff::new(ms(100), Duration::from_secs(300));
        for _ in 0..10_000 {
            b.fail();
        }
        assert_eq!(b.peek(), Duration::from_secs(300));
        assert!(b.consecutive_failures() >= 10_000);
    }

    #[test]
    fn peek_does_not_advance() {
        let mut b = Backoff::new(ms(100), ms(800));
        assert_eq!(b.peek(), ms(100));
        assert_eq!(b.peek(), ms(100));
        assert_eq!(b.fail(), ms(100));
        assert_eq!(b.peek(), ms(200));
    }
}
