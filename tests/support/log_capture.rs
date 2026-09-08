//! In-process log capture — so a test can assert on what a pass SAID, not only
//! on what it returned.
//!
//! ## Why this exists
//!
//! "The steady state must not be an alarm" is a property of the LOG LINE, not of
//! any return value. 0.5.152's scorer returned perfectly correct outcomes while
//! WARNing about them 24,500 times a day; every assertion on its return values
//! stayed green throughout. The only way to gate that class is to look at the
//! emitted event's level.
//!
//! Scoped to one future via [`tracing::instrument::WithSubscriber`] rather than a
//! global default: integration tests in one binary run concurrently on separate
//! threads, and a global capture would interleave two tests' events into each
//! other's assertions.
//!
//! NB: files under `tests/support/` are not auto-compiled as test binaries; each
//! suite pulls this in with an explicit `#[path]` (same shape as
//! `tests/release_gates/support.rs`).

#![allow(dead_code)]

use std::future::Future;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;

/// One captured `tracing` event.
#[derive(Clone, Debug)]
pub struct CapturedEvent {
    pub level: Level,
    pub target: String,
    pub message: String,
}

impl CapturedEvent {
    /// Whether an operator would read this as something demanding attention.
    ///
    /// Written as an explicit match rather than `level <= Level::WARN`:
    /// `tracing::Level`'s `Ord` is by VERBOSITY (`TRACE > DEBUG > INFO > WARN >
    /// ERROR`), which reads backwards at a glance and is exactly the kind of
    /// inverted comparison that silently passes a test it was meant to fail.
    pub fn is_alarm(&self) -> bool {
        matches!(self.level, Level::WARN | Level::ERROR)
    }
}

/// The events one captured future emitted.
#[derive(Clone, Default)]
pub struct Log(Arc<Mutex<Vec<CapturedEvent>>>);

impl Log {
    pub fn events(&self) -> Vec<CapturedEvent> {
        self.0.lock().expect("log capture mutex").clone()
    }

    /// Every event an operator would read as demanding attention.
    pub fn alarms(&self) -> Vec<CapturedEvent> {
        self.events().into_iter().filter(|e| e.is_alarm()).collect()
    }

    /// Events at exactly `level` — used to prove a pass was AUDIBLE, i.e. that
    /// "no alarm" was achieved by saying the right thing rather than by saying
    /// nothing at all (a silent pass and a dead loop look identical from
    /// outside; that is CIRISServer#315).
    pub fn at(&self, level: Level) -> Vec<CapturedEvent> {
        self.events()
            .into_iter()
            .filter(|e| e.level == level)
            .collect()
    }

    /// Human-readable dump for assertion messages.
    /// Render, but NEVER to the empty string.
    ///
    /// A CI failure (0.5.182 adopt) printed this into an assertion message and
    /// produced nothing at all, so the report read as "the healthy line was
    /// missing from the log" when what actually happened was "no events were
    /// captured". Those are different worlds with different fixes — the first
    /// is a scorer bug, the second is this harness not seeing the events —
    /// and an empty render collapses them into the more alarming one.
    ///
    /// `capture` attaches its subscriber to the FUTURE, so anything the code
    /// under test `tokio::spawn`s emits into the global dispatcher instead and
    /// is invisible here. That is scheduling-dependent, which is why it showed
    /// up on a loaded CI runner and never locally.
    pub fn render_or_explain(&self) -> String {
        let n = self.events().len();
        if n == 0 {
            return "(NO EVENTS CAPTURED AT ALL — this is a capture failure, not a \
                    missing log line. `capture` subscribes the future it wraps; work the \
                    code under test spawns onto other tasks emits into the global \
                    dispatcher and never reaches this Log.)"
                .to_string();
        }
        format!("{n} event(s) captured:\n{}", self.render())
    }

    pub fn render(&self) -> String {
        self.events()
            .iter()
            .map(|e| format!("  [{}] {}: {}", e.level, e.target, e.message))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// The ONE process-global layer. It never filters (`Interest::always()` for
/// every callsite) and routes each event to the capture that is active for
/// the current TASK, dropping it when there is none.
struct RoutingLayer;

tokio::task_local! {
    /// The capture a task is running under, if any.
    static CURRENT: Log;
}

impl<S: Subscriber> Layer<S> for RoutingLayer {
    fn register_callsite(
        &self,
        _meta: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::always()
    }
    fn enabled(&self, _meta: &tracing::Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        true
    }
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        struct MessageVisitor<'a>(&'a mut String);
        impl Visit for MessageVisitor<'_> {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0.push_str(&format!("{value:?}"));
                }
            }
        }
        // No active capture on this task: not our event.
        let _ = CURRENT.try_with(|log| {
            let mut message = String::new();
            event.record(&mut MessageVisitor(&mut message));
            log.0
                .lock()
                .expect("log capture mutex")
                .push(CapturedEvent {
                    level: *event.metadata().level(),
                    target: event.metadata().target().to_string(),
                    message,
                });
        });
    }
}

/// Install the routing layer as the process-global default, once.
///
/// # Why GLOBAL, and not a scoped `with_subscriber` (CIRISServer#542)
///
/// The first version wrapped the future in `with_subscriber(registry + layer)`
/// — a SCOPED dispatcher, installed per poll. Three CI runs (and 1 in 4 local
/// runs, once looked for) captured NOTHING for a pass whose INFO line is
/// emitted inline, and the reason is in `tracing-core`, not in the code under
/// test: a callsite's `Interest` is cached process-wide, and when exactly one
/// scoped dispatcher is alive (`Dispatchers::has_just_one`), it is recomputed
/// from *the registering thread's* current default. A sibling test's
/// `tokio::spawn`ed retention loop hits `run_pass`'s callsites first, on a
/// worker thread whose default is the global (or nothing), and caches them
/// `never`; the scoped capture on this thread is then never consulted, because
/// the `tracing::info!` macro returns before it asks. Forcing a rebuild from
/// this thread makes it worse for the same reason. A global default that is
/// always interested ends the question: interest is `always` from any thread,
/// and WHERE an event goes is decided here, per task, at dispatch time.
fn install_global() {
    use std::sync::OnceLock;
    static INSTALLED: OnceLock<bool> = OnceLock::new();
    let ours = *INSTALLED.get_or_init(|| {
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(RoutingLayer))
            .is_ok()
    });
    assert!(
        ours,
        "log_capture: another global tracing subscriber was installed before the first \
         capture in this process, so captured events cannot be routed. Tests in a binary \
         that uses `log_capture::capture` must not install their own global subscriber."
    );
}

pub async fn capture<F: Future>(fut: F) -> (F::Output, Log) {
    install_global();
    let log = Log::default();
    let out = CURRENT.scope(log.clone(), fut).await;
    (out, log)
}
