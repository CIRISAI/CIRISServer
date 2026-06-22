//! CIRISServer#11 — wire CIRISEdge's holonomic-tier
//! [`FountainSwarmRuntime`] into the node.
//!
//! The swarm runtime is the v6.3.0 quartet's *holonomic* layer: a
//! publisher that advertises the fountain content this node currently
//! holds (as signed `FountainHoldingClaim` envelopes shipped to the
//! replication/consent cohort) and a converger that acts on the
//! *peers'* claims — tier-evicting or hard-deleting locally-held
//! symbols once a content unit is sufficiently replicated across the
//! cohort (the §19 rarity heuristic). The converger's INBOUND path is
//! already handled by edge: `Edge::run`'s dispatch routes verified
//! `MessageType::FountainHoldingClaim` envelopes into the installed
//! runtime's `register_observed_claim` (CIRISEdge#184). So *installing*
//! the runtime before `edge.run()` is sufficient — there is no inbound
//! path to wire here.
//!
//! This module supplies the three persist-backed trait adapters the
//! runtime needs and an [`install_swarm_runtime`] entry point that
//! mirrors the existing `setup_peer_replication` wiring shape in
//! `compose.rs` (get the live Reticulum transport, build the runtime,
//! install it on the Edge — all BEFORE `edge.run()` consumes the Edge).
//!
//! ## Honest activation
//!
//! The publisher lists *real* holdings from persist
//! ([`Engine::list_held_fountain_content`]). On a node that holds no
//! fountain content yet (the common case today) the list is empty —
//! that is correct, not theater: the node simply has nothing to
//! advertise, while the converger still acts on whatever claims peers
//! send. No synthetic "active" claims are injected.

use std::sync::Arc;

use ciris_edge::swarm::persist_fountain_evict::{
    FountainEvictError, FountainEvictHardDelete, FountainHoldingsSource, FountainTierEvict,
    HeldFountainContent,
};
use ciris_edge::swarm::{FountainSwarmRuntime, SwarmRuntimeConfig};
use ciris_edge::Edge;
use ciris_persist::fountain::FountainTier;
use ciris_persist::prelude::Engine;

use crate::config::ServerConfig;

/// Map a persist [`FountainHeldMeta`](ciris_persist::fountain::FountainHeldMeta)
/// onto edge's [`HeldFountainContent`].
///
/// **WRINKLE 1**: persist exposes `held_symbols` as a *count*, not the
/// per-symbol id list, so we synthesize contiguous ids
/// `(0..held_symbols)`. This is the only mapping available from the
/// current persist surface; a future persist cut may expose the real
/// `symbol_id`s (CIRISPersist#227 follow-on), at which point this
/// should thread them through instead.
fn map_held(meta: &ciris_persist::fountain::FountainHeldMeta) -> HeldFountainContent {
    HeldFountainContent {
        content_id: meta.content_id.clone(),
        corpus_kind: meta.corpus_kind.clone(),
        // count-as-contiguous-ids — persist exposes no per-symbol ids.
        symbol_ids: (0..meta.held_symbols).collect(),
    }
}

/// Parse the edge `FountainTierEvict` string tier label onto persist's
/// [`FountainTier`] enum.
///
/// Edge's converger emits `"t1"` for the gentlest row-freeing eviction
/// (its comment: "DiskPressure::Warn-equivalent — the gentlest step
/// that actually frees symbol rows"). Persist has no `T1`; its
/// `Warn`-equivalent is [`FountainTier::T2`] (keep `n_source`, drop
/// repair), so `"t1"` maps to `T2`. Unknown labels default to `T2` —
/// the gentlest tier that still frees rows — and are logged; defaulting
/// conservative (least destructive that honors the eject intent) avoids
/// an over-eager hard drop on a label this node doesn't recognize.
fn parse_tier(tier: &str) -> FountainTier {
    match tier {
        "full" => FountainTier::Full,
        // "t1" (edge's Warn-equivalent gentlest evict) and "t2" both
        // map to persist T2: keep n_source, drop repair symbols.
        "t1" | "t2" => FountainTier::T2,
        "t3" => FountainTier::T3,
        "t4" => FountainTier::T4,
        "t5" => FountainTier::T5,
        other => {
            tracing::warn!(
                tier = %other,
                "swarm tier-evict: unrecognized tier label — defaulting to T2 (gentlest \
                 row-freeing tier)"
            );
            FountainTier::T2
        }
    }
}

/// Persist-backed [`FountainHoldingsSource`]: the publisher's
/// "what fountain content am I holding?" view, filtered to this node's
/// publisher key (`cfg.key_id`).
struct EngineHoldingsSource {
    engine: Arc<Engine>,
    publisher_key_id: String,
}

#[async_trait::async_trait]
impl FountainHoldingsSource for EngineHoldingsSource {
    async fn list_held_fountain_content(
        &self,
    ) -> Result<Vec<HeldFountainContent>, FountainEvictError> {
        let held = self
            .engine
            .list_held_fountain_content(&self.publisher_key_id)
            .await
            .map_err(|e| FountainEvictError::HardDeleteFailed(e.to_string()))?;
        Ok(held.iter().map(map_held).collect())
    }
}

/// Persist-backed [`FountainTierEvict`]: tier-eviction sibling of the
/// hard-delete path. Async, matching persist's async eviction API.
struct EngineTierEvict {
    engine: Arc<Engine>,
}

#[async_trait::async_trait]
impl FountainTierEvict for EngineTierEvict {
    async fn evict_fountain_content_to_tier(
        &self,
        content_id: &str,
        corpus_kind: &str,
        tier: &str,
    ) -> Result<(), FountainEvictError> {
        let tier = parse_tier(tier);
        self.engine
            .evict_fountain_content_to_tier(content_id, corpus_kind, tier)
            .await
            .map(|_evicted| ())
            .map_err(|e| FountainEvictError::HardDeleteFailed(e.to_string()))
    }
}

/// Persist-backed [`FountainEvictHardDelete`]: the §8.1.11.3 N5
/// terminal hard-delete primitive.
///
/// **WRINKLE 2**: the edge trait method is **sync** but persist's
/// `evict_fountain_content_hard_delete` is **async**. We bridge with a
/// captured [`tokio::runtime::Handle`] + `block_in_place` +
/// `handle.block_on(..)`. This is the safe option here: the converger
/// invokes this method from inside an `async fn` running on a tokio
/// *worker thread* of the server's multi-thread runtime (see
/// `FountainSwarmRuntime`'s converger task — the hard-delete call sits
/// directly in the async dispatch body). `block_in_place` is exactly
/// for that case: it tells the runtime this worker is about to block so
/// the scheduler can compensate, then `block_on` drives the persist
/// future to completion. (`block_in_place` requires the multi-thread
/// runtime, which the server always uses.)
struct EngineHardDelete {
    engine: Arc<Engine>,
    handle: tokio::runtime::Handle,
}

impl FountainEvictHardDelete for EngineHardDelete {
    fn evict_fountain_content_hard_delete(
        &self,
        content_id: &str,
        corpus_kind: &str,
    ) -> Result<(), FountainEvictError> {
        let engine = Arc::clone(&self.engine);
        let content_id = content_id.to_string();
        let corpus_kind = corpus_kind.to_string();
        let handle = self.handle.clone();
        // Bridge sync→async: block_in_place + block_on. Safe because the
        // converger calls this from a multi-thread-runtime worker thread
        // (an async dispatch body), never from inside a single-thread
        // runtime or a nested block_on.
        tokio::task::block_in_place(move || {
            handle.block_on(async move {
                engine
                    .evict_fountain_content_hard_delete(&content_id, &corpus_kind)
                    .await
                    .map(|_dropped| ())
                    .map_err(|e| FountainEvictError::HardDeleteFailed(e.to_string()))
            })
        })
    }
}

/// Wire the holonomic-tier [`FountainSwarmRuntime`] into the shared
/// `Edge`, mirroring `setup_peer_replication`.
///
/// MUST run BEFORE `edge.run()` consumes the Edge:
/// `install_swarm_runtime` registers the runtime into the Edge's
/// inbound dispatch (so verified peer `FountainHoldingClaim` envelopes
/// reach the converger), and `reticulum_transport()` must be cloned off
/// the live Edge. Returns `None` (a no-op) when there is no Reticulum
/// transport — same as the replication wiring; without a transport the
/// publisher has no cohort to ship claims to.
///
/// The returned handle must be bound by the caller so the runtime's
/// publisher/converger tasks are not dropped.
pub async fn install_swarm_runtime(
    engine: &Arc<Engine>,
    edge: &Edge,
    cfg: &ServerConfig,
) -> Option<Arc<FountainSwarmRuntime>> {
    let Some(transport) = edge.reticulum_transport() else {
        tracing::warn!(
            "Edge has no Reticulum transport — holonomic swarm runtime not started (no cohort to \
             publish FountainHoldingClaims to)"
        );
        return None;
    };

    let holdings: Arc<dyn FountainHoldingsSource> = Arc::new(EngineHoldingsSource {
        engine: Arc::clone(engine),
        publisher_key_id: cfg.key_id.clone(),
    });
    let tier_evict: Arc<dyn FountainTierEvict> = Arc::new(EngineTierEvict {
        engine: Arc::clone(engine),
    });
    let hard_delete: Arc<dyn FountainEvictHardDelete + Send + Sync> = Arc::new(EngineHardDelete {
        engine: Arc::clone(engine),
        // Captured at construction; the converger runs on this runtime.
        handle: tokio::runtime::Handle::current(),
    });

    // Cohort = the node's current replication/consent peers (the same
    // source the ReplicationRuntime converges to). A static snapshot
    // resolved once at boot is fine for v6.3.0: the swarm cohort is the
    // consented federation, which today changes only via the owner-gated
    // peering API (a node restart re-resolves it). A future cut can swap
    // this for a live closure over the consent CEG to match the
    // replication reconciler's hot-add — comment kept so it's an
    // explicit, honest snapshot, not an oversight.
    let cohort_peers: Vec<String> =
        match crate::peer::replication_peers_from_consent(engine, &cfg.key_id).await {
            Ok(peers) => peers,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "swarm cohort: failed to resolve consent peers at boot — starting with an \
                     empty cohort (publisher ships no claims until restart re-resolves it)"
                );
                Vec::new()
            }
        };
    let cohort: Arc<dyn Fn() -> Vec<String> + Send + Sync> = {
        let snapshot = cohort_peers.clone();
        Arc::new(move || snapshot.clone())
    };

    let runtime = FountainSwarmRuntime::start(
        SwarmRuntimeConfig::default(),
        holdings,
        tier_evict,
        hard_delete,
        transport as Arc<dyn ciris_edge::transport::Transport>,
        cohort,
        cfg.key_id.clone(),
        None,
    );
    let runtime = Arc::new(runtime);

    // Set-once install: routes verified inbound FountainHoldingClaim
    // envelopes into the runtime's converger (CIRISEdge#184).
    edge.install_swarm_runtime(Arc::clone(&runtime));

    tracing::info!(
        cohort_peers = cohort_peers.len(),
        "holonomic swarm runtime started + installed on the shared Edge (publisher advertises \
         held fountain content; converger acts on peers' claims via edge dispatch)"
    );
    Some(runtime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_held_uses_contiguous_symbol_ids() {
        let meta = ciris_persist::fountain::FountainHeldMeta {
            content_id: "c1".to_string(),
            corpus_kind: "fountain-corpus".to_string(),
            pqc_key_id: "pk1".to_string(),
            original_content_length: 1024,
            n_source: 8,
            k_repair: 4,
            min_viable_symbols: 6,
            symbol_size: 256,
            held_symbols: 5,
            recoverable: false,
            admitted_at: "2026-06-21T00:00:00Z".to_string(),
        };
        let mapped = map_held(&meta);
        assert_eq!(mapped.content_id, "c1");
        assert_eq!(mapped.corpus_kind, "fountain-corpus");
        // held_symbols (a count) → contiguous ids 0..5.
        assert_eq!(mapped.symbol_ids, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn map_held_zero_symbols_yields_empty() {
        let meta = ciris_persist::fountain::FountainHeldMeta {
            content_id: "c2".to_string(),
            corpus_kind: "fountain-corpus".to_string(),
            pqc_key_id: "pk1".to_string(),
            original_content_length: 0,
            n_source: 1,
            k_repair: 0,
            min_viable_symbols: 1,
            symbol_size: 1,
            held_symbols: 0,
            recoverable: false,
            admitted_at: "2026-06-21T00:00:00Z".to_string(),
        };
        assert!(map_held(&meta).symbol_ids.is_empty());
    }

    #[test]
    fn empty_holdings_map_to_empty_vec() {
        // The publisher's "I hold nothing" path (the common case today):
        // an empty persist list maps to an empty Vec — no synthetic claims.
        let metas: Vec<ciris_persist::fountain::FountainHeldMeta> = Vec::new();
        let mapped: Vec<HeldFountainContent> = metas.iter().map(map_held).collect();
        assert!(mapped.is_empty());
    }

    #[test]
    fn parse_tier_maps_all_labels() {
        assert_eq!(parse_tier("full"), FountainTier::Full);
        // edge's "t1" gentlest-evict label → persist T2.
        assert_eq!(parse_tier("t1"), FountainTier::T2);
        assert_eq!(parse_tier("t2"), FountainTier::T2);
        assert_eq!(parse_tier("t3"), FountainTier::T3);
        assert_eq!(parse_tier("t4"), FountainTier::T4);
        assert_eq!(parse_tier("t5"), FountainTier::T5);
        // unknown → conservative gentlest row-freeing tier.
        assert_eq!(parse_tier("nonsense"), FountainTier::T2);
    }
}
