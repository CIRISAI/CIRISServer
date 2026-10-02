//! One span this process refuses to open: edge's `anti_entropy_round`.
//!
//! Edge's replication scheduler holds a span GUARD across awaits
//! (`let _enter = span.enter(); round_gate.enter(..).await; …`, in
//! `ciris_edge::replication::scheduler`, once per coordinator per round).
//! `enter()` is thread-local, so at the await the span stays on that worker's
//! stack and the next task polled there opens its span as a child of it. The
//! chain only grows. On the production canonical under 0.5.218 it reached a
//! depth of ~9,500 within hours — a 678 KB log line, ~0.5 MB/s of log — and the
//! subscriber's walk of the chain overflowed a worker stack: SIGSEGV, exit 139
//! (2026-10-01 21:19Z). The same leak can also panic a coordinator task
//! outright when a span closes while still on another worker's stack.
//!
//! The cure is edge's: `.instrument(span)` instead of a held guard. Until an
//! edge release carries it, this layer DISABLES that one callsite. A disabled
//! span is never entered, so nothing leaks; the scheduler's events still log,
//! and its WARN lines already name the peer and kind in their own fields.
//!
//! Delete this module when the pinned edge no longer holds a guard across an
//! await in its scheduler. `tests/a_span_guard_held_across_an_await_nests.rs`
//! is the witness for both halves.

use tracing::Metadata;
use tracing_subscriber::Layer;

/// The span's name, as edge spells it.
pub const LEAKING_SPAN: &str = "anti_entropy_round";
/// The module that opens it. Matched as a suffix so the witness test can
/// reproduce the idiom under its own crate name.
pub const LEAKING_SPAN_MODULE: &str = "replication::scheduler";

/// Is this callsite the span whose guard is held across an await?
pub fn is_leaking_round_span(meta: &Metadata<'_>) -> bool {
    meta.is_span() && meta.name() == LEAKING_SPAN && meta.target().ends_with(LEAKING_SPAN_MODULE)
}

/// A global layer that disables that callsite and nothing else.
pub fn layer<S>() -> impl Layer<S>
where
    S: tracing::Subscriber,
{
    tracing_subscriber::filter::filter_fn(|meta| !is_leaking_round_span(meta))
}
