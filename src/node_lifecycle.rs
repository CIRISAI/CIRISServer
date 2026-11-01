//! **The node sleeps with its phone** (steward 2026-11-01: "we limit our
//! background listener to the clean minimum listener as designed";
//! CIRISServer#24, #530).
//!
//! A phone OS gives a backgrounded app seconds, not minutes, and then
//! suspends or kills it. Android: a service started from the background may
//! not enter the foreground
//! (<https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start>),
//! a `dataSync` foreground service is stopped after its time limit
//! (<https://developer.android.com/develop/background-work/services/fgs/timeout>),
//! and Doze cuts the network without warning
//! (<https://developer.android.com/training/monitoring-device-state/doze-standby>).
//! iOS suspends a backgrounded app and kills one that holds work past its
//! background task's expiration
//! (<https://developer.apple.com/documentation/backgroundtasks>). Both
//! platforms agree on the shape: **no persistent background work; a push
//! wakes the app, the app pulls, the app sleeps.**
//!
//! So the embedding host tells the node where it is:
//!
//! - [`enter_background`] — every periodic loop (`loop_cadence::Cadence`)
//!   stops at its NEXT tick, and the call waits — up to the host's deadline —
//!   for the passes already running to finish, so nothing is mid-write when
//!   the OS suspends the process. It reports whether they drained.
//! - [`enter_foreground`] — the loops resume at once. Every one of them is
//!   overdue after a sleep, so each runs its catch-up pass immediately (the
//!   `Cadence` overrun rule), on its own slot.
//!
//! The host calls `enter_background` from its lifecycle callback (Android
//! `onStop` / iOS `sceneDidEnterBackground`) inside the time the OS grants —
//! on iOS, inside `beginBackgroundTask` and ending it when this returns
//! (<https://developer.apple.com/documentation/uikit/uiapplication/beginbackgroundtask(withname:expirationhandler:)>).
//!
//! Scope: this pauses the SERVER's loops. Edge's transport (its links and
//! replication rounds) sleeps through edge's own `suspend` / `resume`, which
//! this module calls once edge ships them; until then [`BackgroundReport`]
//! says so rather than claiming the transport is quiet.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use tokio::sync::watch;

/// Where the host says the node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The app is in use: every loop runs on its cadence.
    Foreground,
    /// The app is backgrounded: no loop starts a new pass.
    Background,
}

impl Phase {
    /// The word the host and the log read.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Foreground => "foreground",
            Self::Background => "background",
        }
    }
}

fn phase_tx() -> &'static watch::Sender<Phase> {
    static TX: OnceLock<watch::Sender<Phase>> = OnceLock::new();
    TX.get_or_init(|| watch::channel(Phase::Foreground).0)
}

/// Loops between a tick and their next call to `tick` — i.e. mid-pass.
static IN_PASS: AtomicUsize = AtomicUsize::new(0);

/// The current phase.
#[must_use]
pub fn phase() -> Phase {
    *phase_tx().borrow()
}

/// Wait until the node is in the foreground. Returns at once when it is.
pub async fn foreground() {
    let mut rx = phase_tx().subscribe();
    let _ = rx.wait_for(|p| *p == Phase::Foreground).await;
}

/// Held by a loop for the length of one pass (from a tick returning to the
/// loop's next `tick` call). Counts the loop as in flight.
pub struct PassGuard(());

impl PassGuard {
    pub(crate) fn begin() -> Self {
        IN_PASS.fetch_add(1, Ordering::SeqCst);
        Self(())
    }
}

impl Drop for PassGuard {
    fn drop(&mut self) {
        IN_PASS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Loops currently mid-pass.
#[must_use]
pub fn in_pass() -> usize {
    IN_PASS.load(Ordering::SeqCst)
}

/// What [`enter_background`] did, for the host and the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackgroundReport {
    /// Every in-flight pass finished inside the deadline.
    pub drained: bool,
    /// Passes still running when the call returned (0 when drained).
    pub still_in_pass: usize,
    /// How long the call waited.
    pub waited: Duration,
    /// Edge's transport was suspended too. `false` until edge ships `suspend`.
    pub transport_suspended: bool,
}

/// Background the node: no loop starts a new pass, and the call waits up to
/// `deadline` for the passes already running to finish. Idempotent.
///
/// Blocking (a short poll), so the host can call it from its lifecycle
/// callback with the interpreter lock released; it runs no tokio itself.
#[must_use]
pub fn enter_background(deadline: Duration) -> BackgroundReport {
    let was = phase_tx().send_replace(Phase::Background);
    let start = Instant::now();
    while in_pass() > 0 && start.elapsed() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let report = BackgroundReport {
        drained: in_pass() == 0,
        still_in_pass: in_pass(),
        waited: start.elapsed(),
        // TODO(edge suspend/resume — agreed 2026-11-01 with edge and agent):
        // call edge's `suspend(remaining deadline)` here and report its result.
        transport_suspended: false,
    };
    if report.drained {
        tracing::info!(
            was = was.as_str(),
            waited_ms = report.waited.as_millis() as u64,
            "LIFECYCLE background — every periodic loop is paused at its next tick and no \
             pass is running; edge's transport is not suspended yet (edge suspend pending)"
        );
    } else {
        tracing::warn!(
            was = was.as_str(),
            still_in_pass = report.still_in_pass,
            deadline_ms = deadline.as_millis() as u64,
            "LIFECYCLE background — the deadline passed with passes still running; they \
             finish if the OS lets the process run, and no new pass starts"
        );
    }
    report
}

/// Foreground the node: every paused loop resumes and runs its overdue pass at
/// once. Idempotent.
pub fn enter_foreground() {
    let was = phase_tx().send_replace(Phase::Foreground);
    // TODO(edge suspend/resume): call edge's `resume()` here.
    tracing::info!(
        was = was.as_str(),
        "LIFECYCLE foreground — every periodic loop resumes and runs its catch-up pass now"
    );
}
