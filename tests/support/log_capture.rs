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
use tracing::instrument::WithSubscriber;
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
    pub fn render(&self) -> String {
        self.events()
            .iter()
            .map(|e| format!("  [{}] {}: {}", e.level, e.target, e.message))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

struct CaptureLayer(Log);

impl<S: Subscriber> Layer<S> for CaptureLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        struct MessageVisitor<'a>(&'a mut String);
        impl Visit for MessageVisitor<'_> {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                // The formatted `message` is the operator-facing text; the
                // structured fields are deliberately ignored so an assertion on
                // wording cannot be satisfied by a field that happens to
                // contain it.
                if field.name() == "message" {
                    self.0.push_str(&format!("{value:?}"));
                }
            }
        }
        let mut message = String::new();
        event.record(&mut MessageVisitor(&mut message));
        self.0
             .0
            .lock()
            .expect("log capture mutex")
            .push(CapturedEvent {
                level: *event.metadata().level(),
                target: event.metadata().target().to_string(),
                message,
            });
    }
}

/// Run `fut` with every `tracing` event it emits captured, returning its output
/// alongside the [`Log`].
pub async fn capture<F: Future>(fut: F) -> (F::Output, Log) {
    let log = Log::default();
    let subscriber = tracing_subscriber::registry().with(CaptureLayer(log.clone()));
    let out = fut.with_subscriber(subscriber).await;
    (out, log)
}
