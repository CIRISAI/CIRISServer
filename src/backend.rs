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
use std::sync::Arc;

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

/// Exact distinct-trace count for a filter — the receipt's number
/// ([`crate::trace_receipt`]). Same one door as
/// [`list_trace_summaries`]: asking a backend by name here is how a postgres
/// node came to answer `Err` on every scorer pass.
pub async fn count_traces(
    engine: &Engine,
    filter: TraceFilter,
    scope: CallerScope,
) -> Result<i64, Error> {
    use ciris_persist::prelude::ReadEngine as _;

    #[cfg(target_os = "linux")]
    if let Some(pg) = engine.postgres_backend() {
        return pg.count_traces(filter, scope).await;
    }
    if let Some(sq) = engine.sqlite_backend() {
        return sq.count_traces(filter, scope).await;
    }
    Err(Error::Backend(
        "this Engine has no read-capable backend (expected SQLite or PostgreSQL) — \
         trace counts are unavailable on this node"
            .to_string(),
    ))
}

/// One trace summary by id, or `None` — the receipt's "do you hold THIS one"
/// ([`crate::trace_receipt`]). Same door as the other two.
pub async fn get_trace_summary(
    engine: &Engine,
    trace_id: &str,
    scope: CallerScope,
) -> Result<Option<ciris_persist::prelude::TraceSummary>, Error> {
    use ciris_persist::prelude::ReadEngine as _;

    #[cfg(target_os = "linux")]
    if let Some(pg) = engine.postgres_backend() {
        return pg.get_trace_summary(trace_id, scope).await;
    }
    if let Some(sq) = engine.sqlite_backend() {
        return sq.get_trace_summary(trace_id, scope).await;
    }
    Err(Error::Backend(
        "this Engine has no read-capable backend (expected SQLite or PostgreSQL) — \
         trace lookups are unavailable on this node"
            .to_string(),
    ))
}

/// This node's content-KEM occurrence for `owner_key_id`, provisioned through
/// edge's `provision_engine_occurrence` — which needs
/// `FederationDirectory + BlobStorage` (the content-KEM identity lives on the
/// blob side), and `Engine::federation_directory()` is only the former. The
/// concrete-backend reach lives here, behind the one door, like every other
/// (`tests/backend_parity.rs`). Returns `(me, how)`: the occurrence key and
/// `created` / `already_current` / `migrated`. See
/// `contacts_chat::ensure_owner_content_occurrence` for why the keys are the
/// engine's and not the keystore's (CIRISServer#596).
pub async fn provision_engine_occurrence(
    engine: &Arc<Engine>,
    owner_key_id: &str,
) -> Result<(String, &'static str), String> {
    #[cfg(target_os = "linux")]
    if let Some(pg) = engine.postgres_backend() {
        return provision_with(engine, &**pg, owner_key_id).await;
    }
    if let Some(sq) = engine.sqlite_backend() {
        return provision_with(engine, &**sq, owner_key_id).await;
    }
    Err("this Engine has no read-capable backend (expected SQLite or PostgreSQL)".into())
}

async fn provision_with<B>(
    engine: &Engine,
    backend: &B,
    owner_key_id: &str,
) -> Result<(String, &'static str), String>
where
    B: ciris_persist::federation::FederationDirectory
        + ciris_persist::federation::blobs::BlobStorage,
{
    use ciris_edge::content_occurrence::{provision_engine_occurrence, Provisioned};
    use ciris_persist::federation::types::device_class::SERVER;
    let (me, outcome) = provision_engine_occurrence(engine, backend, owner_key_id, SERVER).await?;
    match outcome {
        Provisioned::Created => Ok((me, "created")),
        Provisioned::AlreadyCurrent => Ok((me, "already_current")),
        // A node that provisioned under 0.5.207: the row under `me` carries the
        // SelfEncKeys pubkeys, and the helper refuses to overwrite a drifted
        // row — an operator decides which keys are authoritative. Here the
        // decision is made: that row went through the local door and never
        // replicated, and every grant wrapped to it is unopenable by anyone,
        // so replacing it loses nothing. Overwrite it once through the local
        // door with the content-KEM pubkeys (the upsert holds because the
        // row's signature is NULL), then provision again — it reads
        // `AlreadyCurrent` and heals the row onto the plane.
        Provisioned::Drifted => {
            let kem = backend
                .load_or_init_content_kem_identity()
                .await
                .map_err(|e| format!("load the content-KEM identity: {e}"))?;
            let enc = ciris_persist::federation::EncryptionPubkeys {
                x25519_base64: kem.x25519_pubkey_b64,
                ml_kem_768_base64: kem.ml_kem_768_pubkey_b64,
            };
            backend
                .put_identity_occurrence_local(
                    ciris_persist::federation::types::IdentityOccurrence {
                        identity_key_id: owner_key_id.to_owned(),
                        occurrence_key_id: me.clone(),
                        device_class: SERVER.to_owned(),
                        hardware_attestation: None,
                        asserted_at: chrono::Utc::now(),
                        valid_until: None,
                        encryption_pubkeys: Some(enc),
                        transport_binding: None,
                        persist_row_hash: String::new(),
                    },
                )
                .await
                .map_err(|e| format!("overwrite the drifted 0.5.207 occurrence {me}: {e}"))?;
            let (me2, again) =
                provision_engine_occurrence(engine, backend, owner_key_id, SERVER).await?;
            tracing::info!(
                identity = %owner_key_id,
                occurrence = %me2,
                ?again,
                "content occurrence migrated from 0.5.207's SelfEncKeys pubkeys to the \
                 content-KEM identity (CIRISServer#596)"
            );
            Ok((me2, "migrated"))
        }
    }
}

/// Spawn edge's blob puller over this Engine's read-capable backend and build
/// the revocation wiring for the replication runtime (edge v25.0.0,
/// CIRISServer#602 items 5–6). Returns `(None, None)` when the Engine has no
/// SQLite/PostgreSQL backend to store blobs in, or no shared Edge handle yet —
/// the runtime then runs as it did on v24, with no pulls.
pub async fn spawn_blob_puller(
    engine: &Arc<Engine>,
    local_key_id: &str,
) -> (
    Option<ciris_edge::blob_swarm::PullSink>,
    Option<ciris_edge::replication::RevocationWiring>,
) {
    #[cfg(target_os = "linux")]
    if let Some(pg) = engine.postgres_backend() {
        return spawn_puller_with(engine, Arc::clone(pg), local_key_id);
    }
    if let Some(sq) = engine.sqlite_backend() {
        return spawn_puller_with(engine, Arc::clone(sq), local_key_id);
    }
    tracing::warn!(
        "blob puller NOT spawned — this Engine has no read-capable backend; blobs will not \
         be pulled on this node (edge v25.0.0, CIRISServer#602)"
    );
    (None, None)
}

fn spawn_puller_with<B>(
    engine: &Arc<Engine>,
    backend: Arc<B>,
    local_key_id: &str,
) -> (
    Option<ciris_edge::blob_swarm::PullSink>,
    Option<ciris_edge::replication::RevocationWiring>,
)
where
    B: ciris_persist::federation::blobs::BlobStorage
        + ciris_persist::federation::FederationDirectory
        + Send
        + Sync
        + 'static,
{
    use ciris_edge::blob_swarm::store_gate::{ConsentDisposition, OperatorStoreConsent};
    use ciris_edge::blob_swarm::{BlobPuller, PullConfig, RevocationRegister};
    use ciris_edge::replication::RevocationWiring;

    let edge_arc: Arc<ciris_edge::Edge> = match ciris_edge::current_edge() {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "blob puller NOT spawned — no shared Edge handle yet");
            return (None, None);
        }
    };
    let config = PullConfig {
        consent: OperatorStoreConsent {
            own: ConsentDisposition::Announce,
            family: ConsentDisposition::Announce,
            community: ConsentDisposition::Announce,
            commons: ConsentDisposition::Decline,
        },
        ..PullConfig::default()
    };
    let (sink, _puller) = BlobPuller::spawn(
        edge_arc,
        (**engine).clone(),
        Arc::clone(&backend),
        engine.federation_directory(),
        local_key_id,
        config,
    );
    let register = Arc::new(RevocationRegister::new(1024, 256));
    let evictor: Arc<dyn ciris_edge::blob_swarm::BlobEvictor> = backend;
    tracing::info!(
        local_key_id,
        "blob puller spawned — community/family/own content is held and announced, the \
         commons declined; revocation register armed (edge v25.0.0)"
    );
    (
        Some(sink),
        Some(RevocationWiring {
            register,
            evictor: Some(evictor),
        }),
    )
}

/// This engine's content-KEM pubkeys (the identity persist mints and seals
/// itself, CIRISPersist#848) — what a signed occurrence carries as
/// `encryption_pubkeys` so a far node's DEK cascade can wrap to it. `None` when
/// the Engine has no read-capable backend.
pub async fn content_kem_pubkeys(
    engine: &Arc<Engine>,
) -> Result<Option<ciris_persist::federation::EncryptionPubkeys>, String> {
    use ciris_persist::federation::blobs::BlobStorage;
    let kem = {
        #[cfg(target_os = "linux")]
        if let Some(pg) = engine.postgres_backend() {
            return pg
                .load_or_init_content_kem_identity()
                .await
                .map(|k| {
                    Some(ciris_persist::federation::EncryptionPubkeys {
                        x25519_base64: k.x25519_pubkey_b64,
                        ml_kem_768_base64: k.ml_kem_768_pubkey_b64,
                    })
                })
                .map_err(|e| format!("load the content-KEM identity: {e}"));
        }
        match engine.sqlite_backend() {
            Some(sq) => sq
                .load_or_init_content_kem_identity()
                .await
                .map_err(|e| format!("load the content-KEM identity: {e}"))?,
            None => return Ok(None),
        }
    };
    Ok(Some(ciris_persist::federation::EncryptionPubkeys {
        x25519_base64: kem.x25519_pubkey_b64,
        ml_kem_768_base64: kem.ml_kem_768_pubkey_b64,
    }))
}
