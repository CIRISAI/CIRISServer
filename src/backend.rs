//! **The one door to the storage backend — and the reason there is one.**
//!
//! persist enforces backend parity with TRAITS. Every capability is a `*Service`
//! trait implemented by `SqliteBackend`, `PostgresBackend` and `MemoryBackend`
//! alike, so adding a method is a compile error in every backend that has not
//! implemented it. Parity is a type error, not a discipline.
//!
//! A consumer only loses that guarantee by reaching PAST the trait for a
//! concrete backend — `engine.sqlite_backend()` — which is exactly what this
//! crate did in 30 places. The cost was not theoretical:
//!
//! - `src/safety/{watchlist,named,moderation,age,infohazard}.rs` — twelve sites.
//!   Every one of them silently returned "no directory" on a PostgreSQL node, so
//!   watchlists, named-entity promotion, moderation duties, age assurance and
//!   infohazard flags were **exempt on postgres**. Not degraded — absent, and
//!   quiet about it.
//! - `src/auth/store.rs` — auth itself, which killed the process at boot
//!   (CIRISServer#397) rather than failing quietly. That one was loud only by
//!   luck: `bootstrap_if_needed`'s `Err` arm fails the boot deliberately.
//! - `src/scorer.rs` — the capacity scorer, observed failing on **every cadence**
//!   on the postgres scout node: 21 ticks, 21 failures, no capacity attestations
//!   ever emitted.
//!
//! ## Which door to use
//!
//! **Most reads and writes already have a backend-agnostic accessor and need
//! nothing from this module.** Prefer them, in this order:
//!
//! 1. `engine.federation_directory()` → `Arc<dyn FederationDirectory>`. The big
//!    one: ~200 methods, every backend, no `Option`. Twelve safety sites and five
//!    auth sites moved here verbatim — the migration DELETED a failure path each
//!    time, because the directory is always present.
//! 2. `Engine`'s own thin dispatch methods (`list_attestations`, …), which exist
//!    so "co-resident Rust consumers don't `match` on the backend themselves".
//!
//! This module exists only for the surfaces where persist declares a trait that
//! every backend implements but exposes **no accessor** for it. Today that is
//! [`ReadEngine`](ciris_persist::ceg::ReadEngine) — five methods, implemented by
//! sqlite, postgres AND memory, reachable through no `Engine` method at all. So
//! `sqlite_backend()` was the only door, and the SQLite-only gate was forced
//! rather than chosen.
//!
//! ## Why an enum and not `dyn`
//!
//! `ReadEngine`'s methods return `impl Future`, so the trait is not
//! dyn-compatible — the same constraint that shaped `auth::store`'s
//! `AuthCertBackend`. An enum has the better property anyway: **a third backend
//! is a compile error here**, rather than a runtime `None` in production.
//!
//! ## Upstream
//!
//! The durable fix is persist exposing `ReadEngine` the way it already exposes
//! `federation_directory()` — a dispatch over its own `BackendDispatch`. This
//! module is the local stand-in until then, and is deliberately small so it
//! deletes cleanly.

use ciris_persist::ceg::{Error, TraceCursor, TraceListPage};
use ciris_persist::prelude::{CallerScope, Engine, TraceFilter};

/// Page trace summaries on whichever backend this Engine actually has.
///
/// The scoring corpus read. Before this existed the scorer asked for SQLite by
/// name and returned `Err("capacity scorer requires a SQLite-backed Engine")` on
/// every pass of every postgres node — so those nodes never scored an agent and
/// never emitted a `capacity:*` attestation, while the node itself looked
/// healthy.
pub async fn list_trace_summaries(
    engine: &Engine,
    filter: TraceFilter,
    cursor: Option<TraceCursor>,
    limit: i64,
    scope: CallerScope,
) -> Result<TraceListPage, Error> {
    use ciris_persist::prelude::ReadEngine as _;

    // persist's `postgres` feature is enabled ONLY on Linux (Cargo.toml
    // `[target.'cfg(target_os = "linux")'.dependencies]`), so `PostgresBackend`
    // does not exist elsewhere and neither may this arm.
    #[cfg(target_os = "linux")]
    if let Some(pg) = engine.postgres_backend() {
        return pg.list_trace_summaries(filter, cursor, limit, scope).await;
    }
    if let Some(sq) = engine.sqlite_backend() {
        return sq.list_trace_summaries(filter, cursor, limit, scope).await;
    }
    Err(Error::Backend(
        "this Engine has no read-capable backend (expected SQLite or PostgreSQL) — \
         trace reads, and therefore capacity scoring, are unavailable on this node"
            .to_string(),
    ))
}
