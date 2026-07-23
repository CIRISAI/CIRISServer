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
    FountainEvictError, FountainHoldingsSource, HeldFountainContent,
};
use ciris_edge::swarm::{FountainSwarmRuntime, SwarmRuntimeConfig};
use ciris_edge::Edge;
use ciris_persist::prelude::Engine;

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

// NB (edge v7.0.0 / persist v10): the `FountainTierEvict` + `FountainEvictHardDelete`
// adapter traits were dropped — `FederationDirectory` now carries
// `evict_fountain_content_to_tier` + `evict_fountain_content_hard_delete` directly,
// so the runtime takes the engine's `Arc<dyn FederationDirectory>` (same shape as
// `ReplicationRuntime`) and these two persist-backed shims are no longer needed.
// `FountainHoldingsSource` (the publisher's holdings view) is still adapter-supplied.

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
) -> Option<Arc<FountainSwarmRuntime>> {
    let Some(transport) = edge.reticulum_transport() else {
        tracing::warn!(
            "Edge has no Reticulum transport — holonomic swarm runtime not started (no cohort to \
             publish FountainHoldingClaims to)"
        );
        return None;
    };

    // ── Single composition (the CIRISServer#312 discipline, hunt-dual-owner F3).
    // `edge.install_swarm_runtime` is a SET-ONCE install, but this runtime used to
    // live in the serve stack frame and be rebuilt on every compose::serve — so a
    // fold clean-restart (#276) left the edge's inbound-claim routing pointed at
    // the FIRST (torn-down) runtime while a SECOND publisher advertised on the
    // shared transport. One runtime per process, same idiom as the
    // ReplicationRuntime: the first serve composes, later serves receive it.
    static SWARM: tokio::sync::OnceCell<Arc<FountainSwarmRuntime>> =
        tokio::sync::OnceCell::const_new();
    if let Some(existing) = SWARM.get() {
        tracing::info!(
            "holonomic swarm runtime already composed — reusing the held runtime (single \
             composition; the edge's set-once claim routing already points at it)"
        );
        return Some(Arc::clone(existing));
    }

    // ONE identity (#312): the publisher / consent-read / runtime identity is the
    // edge's SIGNER key — never the config alias. Reading the consent cohort by
    // the alias yields an EMPTY cohort in the embedded fold (the alias authored
    // nothing), which is the exact #312 failure this plane inherited.
    let node_key_id = edge.signer_key_id().to_string();

    let holdings: Arc<dyn FountainHoldingsSource> = Arc::new(EngineHoldingsSource {
        engine: Arc::clone(engine),
        publisher_key_id: node_key_id.clone(),
    });
    // edge v7.0.0: tier-evict + hard-delete are now methods on the persist
    // FederationDirectory the runtime holds — no per-trait shims.
    let directory = engine.federation_directory();

    // Cohort = the node's current replication/consent peers (the same
    // source the ReplicationRuntime converges to). A static snapshot
    // resolved once at boot is fine for v6.3.0: the swarm cohort is the
    // consented federation, which today changes only via the owner-gated
    // peering API (a node restart re-resolves it). A future cut can swap
    // this for a live closure over the consent CEG to match the
    // replication reconciler's hot-add — comment kept so it's an
    // explicit, honest snapshot, not an oversight.
    let cohort_peers: Vec<String> =
        match crate::peer::replication_peers_from_consent(engine, &node_key_id).await {
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
        directory,
        transport as Arc<dyn ciris_edge::transport::Transport>,
        cohort,
        node_key_id,
        None,
    );
    let runtime = Arc::new(runtime);
    // Publish for later serves BEFORE the set-once edge install, so a concurrent
    // second serve reuses this runtime rather than racing a doomed install.
    let runtime = if SWARM.set(Arc::clone(&runtime)).is_ok() {
        runtime
    } else {
        // Lost the composition race — adopt the winner's runtime (its
        // publisher/converger are the live ones; ours drops unreferenced,
        // its tasks never having been installed on the edge).
        let held = SWARM.get().expect("set failed ⇒ already initialized");
        tracing::info!(
            "holonomic swarm runtime: lost the composition race — adopting the winner's runtime"
        );
        return Some(Arc::clone(held));
    };

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
            content_bytes: 1280,
            cohort_scope: Some("federation".to_string()),
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
            content_bytes: 0,
            cohort_scope: None,
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

    // (edge v7.0.0) `parse_tier_maps_all_labels` retired — the string-tier→
    // FountainTier mapping moved into persist's FederationDirectory, which the
    // runtime now calls directly; the server no longer owns that translation.
}
