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
/// The server's [`BlobChunkSource`]: persist's gated peer-serve door for the
/// bytes, and the blob's SCOPE answered from the row that references it.
///
/// `PersistBlobChunkSource::chunk_scope` is left `None` upstream on purpose —
/// persist's blob columns carry a cohort scope but not the MLS group id the
/// scope-native gate keys on, and edge refuses to guess. On a node that armed
/// scope-native addressing (this one, `compose::build_edge`) `None` means every
/// inbound `BlobChunkFetch` is `WITHHELD on scope admission — blob scope could
/// not be determined` (0.5.213, the last rung under `arrived`): the bytes are
/// held, the requester arrived on the room's own derived address, and the
/// responder cannot say which room the bytes belong to.
///
/// The row knows. Every blob-backed body is referenced by an attestation whose
/// pointer names `community_key_id` and `tier`, and edge's
/// [`BlobMeaning::project`] is the ONE projection from that row to a
/// [`ContentScope`] — the same one the PULLER runs to route the fetch. Serving
/// through it means the two sides agree on the scope by construction; a
/// second spelling here would be the axis-fusion this arc kept finding.
///
/// [`BlobChunkSource`]: ciris_edge::blob_swarm::BlobChunkSource
/// [`BlobMeaning::project`]: ciris_edge::blob_swarm::BlobMeaning::project
/// [`ContentScope`]: ciris_edge::blob_swarm::ContentScope
pub(crate) struct ServerBlobChunkSource {
    inner: ciris_edge::blob_swarm::PersistBlobChunkSource,
    directory: Arc<dyn ciris_persist::federation::FederationDirectory>,
    /// The blob store itself, for the community-DEK epoch binding — the
    /// `(community, minter, epoch)` a sealed blob belongs to (persist #848 §17).
    /// `None` only on a non-SQLite engine, where the meaning path still answers.
    blobs: Option<Arc<ciris_persist::store::sqlite::SqliteBackend>>,
}

impl ServerBlobChunkSource {
    pub(crate) fn new(engine: &Engine) -> Self {
        Self {
            inner: ciris_edge::blob_swarm::PersistBlobChunkSource::new(Engine::clone(engine))
                .with_revocations(Some(revocation_register())),
            directory: engine.federation_directory(),
            blobs: engine.sqlite_backend().cloned(),
        }
    }
}

#[async_trait::async_trait]
impl ciris_edge::blob_swarm::BlobChunkSource for ServerBlobChunkSource {
    async fn read_chunk(
        &self,
        blob_sha256: [u8; 32],
        chunk_sha256: [u8; 32],
        requesting_peer_key_id: &str,
    ) -> Result<Option<Vec<u8>>, ciris_edge::blob_swarm::ChunkSourceRefusal> {
        self.inner
            .read_chunk(blob_sha256, chunk_sha256, requesting_peer_key_id)
            .await
    }

    /// Two readers, one answer, in this order:
    ///
    /// 1. **The bytes' own key identity.** A community-DEK blob carries its
    ///    `(community, minter, epoch)` binding in persist (`community_dek_blob_
    ///    epoch`, #848 §17) — a fact about which DEK sealed the bytes, present
    ///    even when the referencing row is not held here. It projects to the
    ///    SAME `ContentScope::Group { Cohort { community }, community }` the
    ///    puller's `BlobMeaning` builds for a community pointer, spelled once
    ///    there and copied here by shape, not by hand: a different group id on
    ///    the serve side is a fetch that arrives on the right address and is
    ///    refused as the wrong room.
    /// 2. **A referencing row.** For a plaintext or self/family blob the
    ///    binding table is silent; any attestation whose `evidence_refs`
    ///    cites the sha projects through `BlobMeaning` (a `holds_bytes` claim
    ///    is possession, not meaning, and `project` refuses it itself).
    ///
    /// `None` means the serve is WITHHELD on a scope-native node — the right
    /// posture for bytes nothing this node holds can place in a room.
    /// Declared, so a scope-native build is admitted (edge v27.0.0,
    /// CIRISEdge#640): `chunk_scope` below answers from the blob's own
    /// community-DEK binding and, failing that, a referencing row — never
    /// `None` for bytes this node can place in a room.
    fn answers_scope(&self) -> bool {
        true
    }

    async fn chunk_scope(
        &self,
        blob_sha256: [u8; 32],
    ) -> Option<ciris_edge::blob_swarm::ContentScope> {
        use ciris_persist::federation::BlobStorage;
        let sha_hex = hex::encode(blob_sha256);
        if let Some(blobs) = self.blobs.as_ref() {
            match blobs.community_dek_blob_epoch(&blob_sha256).await {
                Ok(Some((community, _minter, epoch))) => {
                    tracing::debug!(
                        blob = %sha_hex,
                        community = %community,
                        epoch,
                        "blob chunk source: scope from the bytes' community-DEK binding"
                    );
                    return Some(ciris_edge::blob_swarm::ContentScope::Group {
                        scope: ciris_edge::cohort_scope::CohortScope::Cohort {
                            cohort_id: community.clone(),
                        },
                        group_id: community,
                    });
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(
                    blob = %sha_hex,
                    error = %e,
                    "blob chunk source: the community-DEK binding could not be read"
                ),
            }
        }
        let rows = match self.directory.attestations_binding_content(&sha_hex).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(
                    blob = %sha_hex,
                    error = %e,
                    "blob chunk source: the rows referencing this blob could not be read — \
                     scope undeterminable, the serve will be withheld"
                );
                return None;
            }
        };
        for row in &rows {
            if let Ok(meaning) = ciris_edge::blob_swarm::BlobMeaning::project(row, &blob_sha256) {
                return Some(meaning.scope().clone());
            }
        }
        tracing::warn!(
            blob = %sha_hex,
            referencing_rows = rows.len(),
            "blob chunk source: no community-DEK binding and no referencing row projects a \
             scope for this blob — scope undeterminable, the serve will be withheld (a \
             holds_bytes claim alone is possession, not meaning)"
        );
        None
    }
}

/// The process-wide serve/apply revocation register (CIRISEdge#606). Built on
/// first use; the edge's blob-chunk source is wired at `Edge::builder()` time,
/// before the puller exists, so both reach it through this accessor.
pub(crate) fn revocation_register() -> Arc<ciris_edge::blob_swarm::RevocationRegister> {
    static REGISTER: std::sync::OnceLock<Arc<ciris_edge::blob_swarm::RevocationRegister>> =
        std::sync::OnceLock::new();
    Arc::clone(
        REGISTER
            .get_or_init(|| Arc::new(ciris_edge::blob_swarm::RevocationRegister::new(1024, 256))),
    )
}

pub async fn spawn_blob_puller(
    engine: &Arc<Engine>,
    edge: Arc<ciris_edge::Edge>,
    local_key_id: &str,
) -> (
    Option<ciris_edge::blob_swarm::PullSink>,
    Option<ciris_edge::replication::RevocationWiring>,
) {
    #[cfg(target_os = "linux")]
    if let Some(pg) = engine.postgres_backend() {
        return spawn_puller_with(engine, edge, Arc::clone(pg), local_key_id);
    }
    if let Some(sq) = engine.sqlite_backend() {
        return spawn_puller_with(engine, edge, Arc::clone(sq), local_key_id);
    }
    tracing::warn!(
        "blob puller NOT spawned — this Engine has no read-capable backend; blobs will not \
         be pulled on this node (edge v25.0.0, CIRISServer#602)"
    );
    (None, None)
}

fn spawn_puller_with<B>(
    engine: &Arc<Engine>,
    edge: Arc<ciris_edge::Edge>,
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
    use ciris_edge::blob_swarm::{BlobPuller, PullConfig};
    use ciris_edge::replication::RevocationWiring;

    // The Edge compose holds — never the process-global handle. The standalone
    // binary builds its own `Arc<Edge>` and never publishes the global (only the
    // #221 embedded fold does), so a global lookup failed on every standalone
    // node — the canonical's first boot on 0.5.211 logged "blob puller NOT
    // spawned — no shared Edge handle yet" (CIRISServer#604). The gate
    // `tests/blob_puller_uses_compose_edge.rs` scrapes this fn for the lookup.
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
        edge,
        (**engine).clone(),
        Arc::clone(&backend),
        engine.federation_directory(),
        local_key_id,
        config,
    );
    // ONE register per process: the apply path writes withdrawals here and the
    // serve door (`PersistBlobChunkSource::with_revocations`, wired in
    // `compose::build_edge`) reads it. Two registers would let a withdrawn blob
    // keep being served — CIRISEdge#606's exact defect, one Arc away.
    let register = revocation_register();
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
