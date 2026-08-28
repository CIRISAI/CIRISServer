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

/// Never fewer than this many workers, whatever the host reports.
pub const MIN_WORKER_THREADS: usize = 4;

/// The worker count for a node runtime.
#[must_use]
pub fn worker_threads() -> usize {
    // `#[tokio::main]` honoured TOKIO_WORKER_THREADS; building by hand drops it
    // unless we read it, which would CAP a deliberately-tuned deployment.
    let requested = std::env::var("TOKIO_WORKER_THREADS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0);
    let detected = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(MIN_WORKER_THREADS);
    resolve_workers(requested, detected)
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
