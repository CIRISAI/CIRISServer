//! WHY THE PRODUCTION CANONICAL SEGFAULTED ON 0.5.218 (2026-10-01 21:19Z), and
//! what stops it without waiting for an edge release.
//!
//! Edge's replication scheduler does this, once per coordinator per round
//! (`ciris_edge::replication::scheduler`, unchanged since at least v31):
//!
//! ```ignore
//! let span = tracing::info_span!("anti_entropy_round", ..);
//! let _enter = span.enter();          // a THREAD-LOCAL guard …
//! round_gate.enter(..).await;         // … held across an await
//! ```
//!
//! `enter()` pushes the span onto the CURRENT THREAD's stack. At the await the
//! task yields but the span stays on that worker's stack, so the next task the
//! worker polls creates its own span as a CHILD of it. When the first task
//! resumes on another worker its guard pops nothing there. Every worker's
//! stack only grows; every new round span is one deeper than the last. The
//! canonical reached a depth of ~9,500 and a 678 KB log line, and the
//! subscriber's walk of that chain overflowed a worker stack (exit 139).
//! The same leak has a second outcome, which this test found: a span that
//! CLOSES while still on another worker's stack makes the next span created
//! there panic ("tried to clone … no span exists with that ID"), which kills
//! that coordinator's task without a log line.
//!
//! This test reproduces the shape with the scheduler's own idiom and proves
//! the mitigation the server installs in its subscriber
//! (`ciris_server::span_leak_guard`): with that one callsite DISABLED,
//! `enter()` is a no-op and nothing nests, while every event from the same
//! module still logs.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::EnvFilter;

/// Records the deepest span chain any event was emitted under, and how many
/// events it saw.
#[derive(Clone, Default)]
struct Depth {
    max: Arc<AtomicUsize>,
    events: Arc<AtomicUsize>,
}

impl<S> Layer<S> for Depth
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        self.events.fetch_add(1, Ordering::Relaxed);
        let depth = ctx.event_scope(event).map_or(0, |s| s.count());
        self.max.fetch_max(depth, Ordering::Relaxed);
    }
}

/// The scheduler's idiom: a span guard held across awaits, many coordinators,
/// a multi-thread runtime. The module path ends as edge's does, so the
/// server's guard recognises the callsite.
mod replication {
    pub mod scheduler {
        pub async fn coordinator(rounds: usize) {
            for _ in 0..rounds {
                let span = tracing::info_span!("anti_entropy_round", peer = "p", kind = "k");
                let _enter = span.enter();
                tokio::task::yield_now().await;
                tokio::time::sleep(std::time::Duration::from_micros(200)).await;
                tracing::warn!("coordinator error during round");
                tracing::info!("an INFO line from the same module");
            }
        }
    }
}

/// Returns (deepest chain, events delivered, coordinator tasks that panicked).
fn run(guarded: bool) -> (usize, usize, usize) {
    let depth = Depth::default();
    // The server's stack in miniature: the env filter, then (when `guarded`)
    // the server's own guard layer, then the sinks.
    let guard = guarded.then(ciris_server::span_leak_guard::layer);
    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::new("info"))
        .with(guard)
        .with(depth.clone());
    // A dispatcher scoped to this run, set on every worker thread.
    let dispatch = tracing::Dispatch::new(subscriber);
    let on_worker = dispatch.clone();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_time()
        .on_thread_start(move || {
            // Leak the guard: the worker keeps this dispatcher for life.
            std::mem::forget(tracing::dispatcher::set_default(&on_worker));
        })
        .build()
        .expect("runtime");
    let _main = tracing::dispatcher::set_default(&dispatch);
    let panicked = rt.block_on(async {
        let mut tasks = Vec::new();
        for _ in 0..42 {
            tasks.push(tokio::spawn(replication::scheduler::coordinator(40)));
        }
        let mut panicked = 0;
        for t in tasks {
            if t.await.is_err() {
                panicked += 1;
            }
        }
        panicked
    });
    (
        depth.max.load(Ordering::Relaxed),
        depth.events.load(Ordering::Relaxed),
        panicked,
    )
}

#[test]
fn a_guard_held_across_an_await_nests_or_kills_the_coordinator() {
    // Quiet the expected panics of the premise run.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let (max, _events, panicked) = run(false);
    std::panic::set_hook(hook);
    assert!(
        max > 1 || panicked > 0,
        "premise: with the span enabled the idiom either nests rounds inside each other \
         (deepest chain {max}) or panics a coordinator on a span that closed while still on a \
         worker's stack ({panicked} task(s)). If this reads 1 and 0 the idiom stopped leaking \
         and the mitigation can go"
    );
}

#[test]
fn the_servers_guard_stops_it_and_keeps_every_event() {
    let (max, events, panicked) = run(true);
    assert_eq!(panicked, 0, "no coordinator dies");
    assert_eq!(
        events,
        42 * 40 * 2,
        "every WARN and INFO event from the module still logs — only the span is disabled"
    );
    assert_eq!(max, 0, "a disabled span is never entered, so nothing nests");
}

#[test]
fn the_guard_names_edges_callsite_and_nothing_else() {
    use ciris_server::span_leak_guard::{LEAKING_SPAN, LEAKING_SPAN_MODULE};
    assert_eq!(LEAKING_SPAN, "anti_entropy_round");
    assert!("ciris_edge::replication::scheduler".ends_with(LEAKING_SPAN_MODULE));
}
