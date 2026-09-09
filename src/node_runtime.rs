//! **The node's tokio runtime, with a worker floor** (CIRISServer#446 / #501).
//!
//! # Why a floor
//!
//! A default runtime sizes itself to core count, so a 2-vCPU host gets TWO
//! workers — a two-slot budget for the accept loop, replication, the scorer and
//! every request at once. One blocking task and HTTP becomes unschedulable: the
//! socket stays LISTEN, `Recv-Q` climbs as the kernel completes handshakes, and
//! userspace never calls `accept()`. That is #501, observed on the canonical with
//! one worker pegged at 99.9% and five threads idle.
//!
//! # Why it lives here rather than in `main.rs`
//!
//! Because the binary is not the deployment that needed it most. `main.rs` is one
//! of THREE runtime construction sites; the other two are `rt_block_on` and
//! `rt_block_on_reentrant`, which host `serve_with_python_adapter` — the embedded
//! agent/fold topology, running on exactly the small hosts this floor exists for.
//! A floor applied only to the standalone binary would have left the agent-carrying
//! node with two workers while the fix reported success (Codex, PR #502).
//!
//! One builder, every serving path.
//!
//! # Why a CAP as well as a floor (CIRISServer#577)
//!
//! The floor answers a 2-vCPU server. The opposite problem is an embedded fold
//! on a phone: the Python entry points bring up several multi-thread runtimes
//! and each one sized itself to `available_parallelism()`, so an 8-core handset
//! got tens of native worker threads for a single-user workload that is mostly
//! idle. Thread count is the multiplier in every allocator's per-thread cache —
//! glibc's arenas, Scudo's TSD on Android, libmalloc's magazines on iOS — and
//! unlike `M_ARENA_MAX` (CIRISServer#552) it is a lever that exists on all of
//! them.
//!
//! So the host may set the count: [`set_worker_override`] (from the
//! `worker_threads=` argument of the Python entry points) or
//! `CIRIS_RUNTIME_WORKERS`. An embedded host knows things this library cannot,
//! which is the same argument that made the listen address configurable
//! (CIRISServer#303).
//!
//! **The floor still wins.** A request for one or two workers resolves to
//! [`MIN_WORKER_THREADS`], because a serving node with two workers is #501 —
//! and the fold serves an API too. What the knob removes is the multiplication
//! by core count, which is where the threads actually came from: four runtimes
//! at the floor is a fraction of four runtimes at `available_parallelism()`.

/// Never fewer than this many workers, whatever the host reports.
pub const MIN_WORKER_THREADS: usize = 4;

/// The env var an embedded host can set instead of passing `worker_threads=`.
///
/// Distinct from `TOKIO_WORKER_THREADS`, which is tokio's own and tunes any
/// tokio program on the box; this one names THIS library's runtimes, which is
/// what an agent embedding the fold wants to reach.
pub const WORKERS_ENV: &str = "CIRIS_RUNTIME_WORKERS";

/// Set by the host through the Python entry points. `0` means unset — a real
/// request of zero is meaningless and would resolve to the floor anyway.
static WORKER_OVERRIDE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Ask every runtime this library builds from here on for `n` workers.
///
/// Called by `serve_with_python_adapter` / `start_federation_delivery` before
/// they build anything. Runtimes already built keep the size they were built
/// with — tokio cannot resize a live runtime — so a host setting this after the
/// serve is under way changes nothing, which is why the entry points take it as
/// an argument rather than leaving it to a later call.
///
/// `None` clears it, restoring the detected default.
pub fn set_worker_override(n: Option<usize>) {
    WORKER_OVERRIDE.store(n.unwrap_or(0), std::sync::atomic::Ordering::Relaxed);
}

/// The override currently in force, if any.
#[must_use]
pub fn worker_override() -> Option<usize> {
    match WORKER_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed) {
        0 => None,
        n => Some(n),
    }
}

/// The worker count for a node runtime.
#[must_use]
pub fn worker_threads() -> usize {
    // Precedence: what the embedding host asked for, then this library's env
    // var, then tokio's own.
    //
    // `#[tokio::main]` honoured TOKIO_WORKER_THREADS; building by hand drops it
    // unless we read it, which would ignore a deliberately-tuned deployment.
    let requested = resolve_requested(
        worker_override(),
        parse_env(WORKERS_ENV),
        parse_env("TOKIO_WORKER_THREADS"),
    );
    let detected = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(MIN_WORKER_THREADS);
    resolve_workers(requested, detected)
}

/// Which of the three inputs wins, with all three passed in.
///
/// Separated for the same reason as [`resolve_workers`]: precedence that can
/// only be tested by setting environment variables is precedence tested once,
/// serially, or not at all.
///
/// The host's explicit argument beats this library's env var, which beats
/// tokio's — most specific first. A deployment that sets `TOKIO_WORKER_THREADS`
/// for every tokio program on the box should not override the one value an
/// embedding host passed for this library in particular.
#[must_use]
pub const fn resolve_requested(
    host: Option<usize>,
    ciris_env: Option<usize>,
    tokio_env: Option<usize>,
) -> Option<usize> {
    match (host, ciris_env, tokio_env) {
        (Some(n), _, _) => Some(n),
        (None, Some(n), _) => Some(n),
        (None, None, other) => other,
    }
}

fn parse_env(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
}

/// The decision itself, with both inputs passed in.
///
/// Separated so it can be tested without an ambient `TOKIO_WORKER_THREADS` or a
/// particular core count deciding the outcome — a test that reads its environment
/// fails on someone's machine for reasons unrelated to the code.
///
/// The floor applies to an override BELOW it: asking for one worker on a 2-vCPU
/// host is how #501 happened, and honouring that would reintroduce the outage by
/// configuration.
#[must_use]
pub const fn resolve_workers(requested: Option<usize>, detected: usize) -> usize {
    let want = match requested {
        Some(n) => n,
        None => detected,
    };
    if want > MIN_WORKER_THREADS {
        want
    } else {
        MIN_WORKER_THREADS
    }
}

/// Build a multi-thread runtime with the floor applied.
///
/// # Errors
/// Propagates the tokio builder's IO error.
pub fn build(thread_name: &str) -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads())
        .enable_all()
        .thread_name(thread_name.to_owned())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 2-vCPU host must not get a 2-slot runtime, where one blocking task leaves
    /// HTTP unschedulable (CIRISServer#446, hit in #501).
    #[test]
    fn a_small_host_still_gets_the_floor() {
        assert_eq!(resolve_workers(None, 1), MIN_WORKER_THREADS);
        assert_eq!(resolve_workers(None, 2), MIN_WORKER_THREADS);
    }

    /// It is a FLOOR, not a cap — a 32-core canonical must still get 32, or fixing
    /// the small host throttles the large one.
    #[test]
    fn the_floor_never_caps_a_large_host() {
        assert_eq!(resolve_workers(None, 32), 32);
    }

    /// #577: an embedded host caps the runtimes it brings up. The cap must
    /// reach the decision — that is the whole ask.
    #[test]
    fn an_embedded_host_can_cap_below_the_detected_core_count() {
        // 8-core handset, host asks for 4.
        assert_eq!(resolve_workers(Some(4), 8), 4);
        // 32-core box, host asks for 4: honoured, not raised back to 32.
        assert_eq!(resolve_workers(Some(4), 32), 4);
    }

    /// ...but not below the #501 floor. The fold serves an API too, so a
    /// two-worker request is the outage that floor exists for, whoever asks.
    #[test]
    fn the_floor_wins_over_a_hosts_cap() {
        assert_eq!(resolve_workers(Some(2), 8), MIN_WORKER_THREADS);
        assert_eq!(resolve_workers(Some(1), 8), MIN_WORKER_THREADS);
    }

    /// Most specific wins: the host's argument, then this library's env var,
    /// then tokio's.
    #[test]
    fn the_hosts_argument_beats_both_env_vars() {
        assert_eq!(resolve_requested(Some(4), Some(8), Some(16)), Some(4));
        assert_eq!(resolve_requested(None, Some(8), Some(16)), Some(8));
        assert_eq!(resolve_requested(None, None, Some(16)), Some(16));
        assert_eq!(resolve_requested(None, None, None), None);
    }

    /// The override is a process-global because the runtimes it sizes are built
    /// from several call sites; round-trip it and put it back.
    #[test]
    fn the_override_round_trips() {
        let restore = worker_override();
        set_worker_override(Some(6));
        assert_eq!(worker_override(), Some(6));
        set_worker_override(None);
        assert_eq!(worker_override(), None, "None must clear, not store zero");
        set_worker_override(restore);
    }

    /// A deliberate high override is honoured even above the detected core count:
    /// an operator asking for more knows something the host report does not say.
    #[test]
    fn a_high_override_is_honoured() {
        assert_eq!(resolve_workers(Some(16), 2), 16);
    }

    /// …but an override BELOW the floor is still floored.
    #[test]
    fn an_override_cannot_go_under_the_floor() {
        assert_eq!(resolve_workers(Some(1), 2), MIN_WORKER_THREADS);
    }

    /// Every serving path gets a floored runtime, not just the binary.
    #[test]
    fn the_builder_applies_the_floor() {
        let rt = build("test-node").expect("build runtime");
        assert!(worker_threads() >= MIN_WORKER_THREADS);
        drop(rt);
    }
}
