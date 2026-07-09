//! Agent-embedded federation-delivery controller (CIRISServer#205, subsuming
//! #204).
//!
//! # The gap this closes
//!
//! A *compose* node (ciris-server's own boot, [`crate::compose::serve`]) drives
//! federation delivery to the canonical mesh from a stack of controllers wired at
//! boot: [`crate::compose::start_replication_runtime`] (the `ReplicationRuntime`
//! over the shared Reticulum transport), [`crate::replication_reconcile::spawn`]
//! (the consent-topology reconcile loop) and [`crate::compose::spawn_announce_logger`]
//! (RNS rooting visibility). The AGENT embeds an Edge via `init_edge_runtime`
//! (edge's pyo3 ctor) but never runs any of that — so on the agent side the CEG
//! trace chain seals + signs locally but **nothing is delivered to Node A**: the
//! replication runtime is never started, no `consent:replication` topology is
//! authored for the baked canonical peer, and the rooting exchange is invisible.
//!
//! # The one entry the agent calls
//!
//! [`run_federation_delivery`] grabs the in-process embedded handles
//! (`ciris_persist::…::current_rust_engine()` + `ciris_edge::current_edge()`,
//! installed by the persist/edge pyo3 ctors) and, IN-PROCESS:
//!
//!   1. Reads the baked canonical record's `transport_hints`
//!      ([`Engine::canonical_bootstrap_hints`]) → the canonical `key_id`s (the
//!      replication targets) + their dialable ip addresses (logged; see the
//!      dial-set caveat below — subsumes #204).
//!   2. Authors this node's directed `consent:replication` grant AT each admitted
//!      canonical peer ([`crate::peer::emit_replication_consent`], idempotent) so
//!      the reconcile loop keeps the canonical in the desired topology.
//!   3. Starts the ONE `ReplicationRuntime` over the shared transport, seeding the
//!      canonical key_ids as `extra_targets`
//!      ([`crate::compose::start_replication_runtime`] — the SAME core the compose
//!      boot path uses) and installs the inbound replication routing.
//!   4. Spawns the consent-topology reconcile loop
//!      ([`crate::replication_reconcile::reconcile_once`] on `cadence_seconds`).
//!   5. Spawns the announce logger over `edge.events()` so RNS rooting is visible.
//!
//! The runtime + its scheduler tasks + the reconcile loop are held for the process
//! lifetime in a process static ([`hold`]), so a Python caller dropping the return
//! value never tears delivery down.
//!
//! # Post-boot ordering (the CIRISServer#205 caveat, verified against edge v9.2.0)
//!
//! Compose's own comment says `install_replication_routing` "MUST run BEFORE
//! `edge.run()`". On the AGENT path the Edge is ALREADY running. This is
//! nevertheless safe: `Edge::run` clones the `Arc<OnceLock>` replication registry
//! and reads it LIVE per inbound frame (`replication_registry.get()` inside the
//! run loop), so a post-boot `install_replication_routing` populates the SAME
//! `OnceLock` the running loop holds and is observed on the next inbound frame.
//! Starting the `ReplicationRuntime` and cloning `reticulum_transport()` are both
//! `&self` accessors on the live Edge — safe at any time.
//!
//! **The one thing that is genuinely build-time-only** is the transport's TCP
//! bootstrap **dial** set: `ReticulumTransport` seeds `add_tcp_client(bootstrap_peers)`
//! at build time and exposes NO runtime add-peer. So this controller CANNOT dial a
//! *new* address that was not in the edge's `bootstrap_peers` at
//! `init_edge_runtime` time. It reads + logs the canonical ip hints (subsuming
//! #204's read), and delivery reaches Node A once the canonical address is present
//! in the edge's init `bootstrap_peers` OR the peer is reachable via an announce
//! over a shared interface. Seeding that dial at init is the agent-side half of
//! #204 (CIRISAgent#896) — this controller drives everything ELSE end to end.

use std::sync::Arc;
#[cfg(feature = "python")]
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result};
use ciris_edge::replication::ReplicationRuntime;
use ciris_edge::Edge;
use ciris_persist::prelude::Engine;
use tokio::sync::watch;

/// A started delivery controller. Holding this keeps the `ReplicationRuntime`
/// scheduler + the reconcile-loop task alive; dropping it drops the strong
/// runtime `Arc` and signals the reconcile loop to stop. In the wheel it is
/// stashed in the [`hold`] process static so a Python caller need not retain it.
pub struct DeliveryController {
    /// The live replication runtime (the reconcile loop mutates its peer set).
    pub runtime: Arc<ReplicationRuntime>,
    /// The canonical `key_id`s seeded as replication targets (for observability).
    pub canonical_targets: Vec<String>,
    /// Shutdown signal for the reconcile loop.
    reconcile_shutdown: watch::Sender<bool>,
    /// The reconcile-loop task handle (held so the task is not detached-and-lost).
    _reconcile_join: tokio::task::JoinHandle<()>,
}

impl Drop for DeliveryController {
    fn drop(&mut self) {
        let _ = self.reconcile_shutdown.send(true);
    }
}

/// Process-global hold for the started controller + the runtime that drives its
/// spawned tasks. The `tokio::runtime::Runtime` MUST be held here: the controller
/// starts the `ReplicationRuntime` scheduler + the reconcile loop via
/// `tokio::spawn` onto this runtime, and those tasks stop the instant the runtime
/// is dropped. Holding it in a `static` gives the delivery machinery the process
/// lifetime (mirrors compose retaining the `Arc<ReplicationRuntime>` for the
/// node's lifetime).
///
/// Gated on `python`: the only entry that installs into it ([`start_and_hold`])
/// grabs the persist pyo3 engine static, which exists only in the wheel build.
#[cfg(feature = "python")]
static HELD: OnceLock<(tokio::runtime::Runtime, Arc<DeliveryController>)> = OnceLock::new();

/// Whether [`start_and_hold`] has already installed a controller in this process.
#[cfg(feature = "python")]
pub fn is_started() -> bool {
    HELD.get().is_some()
}

/// Stash the driving runtime + controller for the process lifetime. First call
/// wins (delivery is started exactly once per process — a second start would spin
/// up a duplicate `ReplicationRuntime` on the one transport). Returns the seeded
/// canonical-target count of whichever controller is now held.
#[cfg(feature = "python")]
fn hold(rt: tokio::runtime::Runtime, controller: Arc<DeliveryController>) -> usize {
    match HELD.set((rt, controller)) {
        Ok(()) => HELD
            .get()
            .map(|(_, c)| c.canonical_targets.len())
            .unwrap_or(0),
        Err((rt, _dupe)) => {
            // Lost the race / a second call: drop the freshly-built runtime (its
            // Drop shuts down the just-spawned duplicate tasks) and report the
            // already-held controller's target count.
            drop(rt);
            HELD.get()
                .map(|(_, c)| c.canonical_targets.len())
                .unwrap_or(0)
        }
    }
}

/// Grab the in-process embedded handles installed by the persist/edge pyo3 ctors,
/// build a dedicated multi-thread runtime, start the delivery controller on it,
/// and hold both for the process lifetime. Returns the number of admitted
/// canonical replication targets seeded. Idempotent per process: a second call is
/// a no-op that returns the already-held target count.
///
/// This is the entry the wheel's `#[pyfunction] start_federation_delivery` calls.
/// It creates its OWN runtime (rather than borrowing the agent's) so the
/// controller's task lifetimes are explicit and owned here — the same
/// single-runtime shape compose uses, just held in a `static` instead of a stack
/// frame. Gated on `python`: `current_rust_engine()` lives in persist's pyo3 FFI
/// surface, which only compiles into the wheel.
#[cfg(feature = "python")]
pub fn start_and_hold(cadence_seconds: Option<u64>, announce_logger: bool) -> Result<usize> {
    if is_started() {
        tracing::info!("federation delivery already started in this process — no-op");
        return Ok(HELD
            .get()
            .map(|(_, c)| c.canonical_targets.len())
            .unwrap_or(0));
    }

    // The in-process embedded handles: persist's engine static (pyo3) + edge's
    // downstream `current_edge()` accessor (CIRISEdge#289). A clear error (not a
    // panic) if the agent calls this before its engine/edge are up.
    let engine: Arc<Engine> = ciris_persist::ffi::pyo3::current_rust_engine().context(
        "federation delivery: no in-process persist Engine (current_rust_engine() is None) — call \
         after the embedded engine is initialized",
    )?;
    let edge: Arc<Edge> = ciris_edge::current_edge().map_err(|e| {
        anyhow::anyhow!(
            "federation delivery: no in-process embedded Edge (current_edge() failed: {e}) — call \
             after init_edge_runtime()"
        )
    })?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ciris-fed-delivery")
        .build()
        .context("build federation-delivery runtime")?;
    let controller = rt.block_on(run_federation_delivery(
        engine,
        edge,
        cadence_seconds,
        announce_logger,
    ))?;
    let controller = Arc::new(controller);
    Ok(hold(rt, controller))
}

/// The default reconcile cadence, matching the compose default
/// ([`crate::config_reconcile::DEFAULT_REPLICATION_RECONCILE_SECS`]).
pub const DEFAULT_DELIVERY_CADENCE_SECS: u64 =
    crate::config_reconcile::DEFAULT_REPLICATION_RECONCILE_SECS;

/// Bring up the delivery controller against the given in-process embedded engine +
/// edge. Must be `await`ed on the runtime that will own the spawned tasks (see
/// [`start_and_hold`]). Returns the assembled [`DeliveryController`] — the caller
/// is responsible for holding it. Takes the handles as params (rather than reading
/// the persist pyo3 static) so the whole controller compiles + is checked in the
/// default (non-`python`) build; the wheel wrapper [`start_and_hold`] supplies the
/// process singletons.
pub async fn run_federation_delivery(
    engine: Arc<Engine>,
    edge: Arc<Edge>,
    cadence_seconds: Option<u64>,
    announce_logger: bool,
) -> Result<DeliveryController> {
    let node_key_id = edge.signer_key_id().to_string();

    // 2. Read the baked canonical record(s): key_ids (replication targets) + ip
    //    hints (dial addresses — logged; see the dial-set caveat in the module
    //    doc). Subsumes #204's read of the transport_hints.
    let hints = engine
        .canonical_bootstrap_hints()
        .await
        .map_err(|e| anyhow::anyhow!("read canonical bootstrap hints: {e}"))?;
    let canonical_key_ids = distinct_canonical_key_ids(&hints);
    let dial_addrs = crate::compose::ip_addrs_from_hints(&hints);
    tracing::info!(
        node_key_id = %node_key_id,
        canonical_targets = ?canonical_key_ids,
        dial_addrs = ?dial_addrs,
        "federation delivery: seeding from the baked canonical record(s) (transport dial set is \
         fixed at init — see #204; delivery reaches Node A once the address is in the edge's init \
         bootstrap_peers or reachable via an announce)"
    );

    // 3. Author this node's directed consent:replication grant at each ADMITTED
    //    canonical peer (idempotent) so the reconcile loop keeps it in the desired
    //    topology. An unadmitted canonical (no federation_keys row) is skipped with
    //    a warn — the baked genesis record is admitted, so this normally emits.
    let directory = engine.federation_directory();
    let mut admitted_targets: Vec<String> = Vec::with_capacity(canonical_key_ids.len());
    for canonical in &canonical_key_ids {
        match directory.lookup_public_key(canonical).await {
            Ok(Some(_)) => {
                match crate::peer::emit_replication_consent(
                    &engine,
                    &node_key_id,
                    canonical,
                    crate::peer::DEFAULT_GRANT_ATTESTATION_PREFIXES,
                )
                .await
                {
                    Ok(grant) => {
                        tracing::info!(
                            canonical = %canonical,
                            freshly_emitted = grant.freshly_emitted,
                            "federation delivery: consent:replication grant authored at canonical peer"
                        );
                        admitted_targets.push(canonical.clone());
                    }
                    Err(e) => tracing::warn!(
                        canonical = %canonical,
                        error = %e,
                        "federation delivery: emit consent:replication for canonical failed — skipping"
                    ),
                }
            }
            Ok(None) => tracing::warn!(
                canonical = %canonical,
                "federation delivery: baked canonical key is NOT an admitted federation_keys row — \
                 skipping (nothing to route/verify)"
            ),
            Err(e) => tracing::warn!(
                canonical = %canonical,
                error = %e,
                "federation delivery: directory lookup for canonical failed — skipping"
            ),
        }
    }

    // 4. Start the ONE ReplicationRuntime over the shared transport, seeding the
    //    admitted canonical key_ids as extra_targets (belt-and-suspenders alongside
    //    the consent grant above). Reuses the EXACT compose core.
    let runtime = crate::compose::start_replication_runtime(
        &engine,
        &edge,
        &node_key_id,
        &admitted_targets,
    )
    .await?
    .context(
        "federation delivery: the embedded Edge has no Reticulum transport — cannot deliver (boot \
         the edge with disable_reticulum=false)",
    )?;

    // 5. Announce logger — RNS rooting visibility over the edge's event bus.
    if announce_logger {
        crate::compose::spawn_announce_logger(edge.events());
        tracing::info!("federation delivery: announce logger subscribed to the edge event bus");
    }

    // 6. The reconcile loop — converge the live runtime to the corpus's
    //    consent:replication topology on a cadence tick. Uses `reconcile_once`
    //    directly (this controller has no ResolvedConfig watch; the cadence is the
    //    fixed `cadence_seconds` param, defaulting to the compose default).
    let cadence = Duration::from_secs(
        cadence_seconds
            .unwrap_or(DEFAULT_DELIVERY_CADENCE_SECS)
            .max(1),
    );
    let (reconcile_shutdown, mut shutdown_rx) = watch::channel(false);
    let reconcile_engine = Arc::clone(&engine);
    let reconcile_runtime = Arc::clone(&runtime);
    let reconcile_node_key = node_key_id.clone();
    let reconcile_join = tokio::spawn(async move {
        let mut interval = tokio::time::interval(cadence);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            cadence_secs = cadence.as_secs(),
            "federation-delivery reconcile loop started (consent:replication topology → set_peers)"
        );
        let mut last_logged: Option<usize> = None;
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        tracing::info!("federation-delivery reconcile loop shutting down");
                        return;
                    }
                    continue;
                }
            }
            match crate::replication_reconcile::reconcile_once(
                &reconcile_engine,
                &reconcile_node_key,
                &reconcile_runtime,
            )
            .await
            {
                Ok(count) => {
                    if last_logged != Some(count) {
                        tracing::info!(
                            consent_peers = count,
                            "federation delivery converged to {count} consent peers",
                        );
                        last_logged = Some(count);
                    }
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    "federation-delivery reconcile tick failed — skipping"
                ),
            }
        }
    });

    tracing::info!(
        canonical_targets = admitted_targets.len(),
        "federation delivery controller started (embedded edge now drives replication + rooting to \
         the canonical mesh)"
    );

    Ok(DeliveryController {
        runtime,
        canonical_targets: admitted_targets,
        reconcile_shutdown,
        _reconcile_join: reconcile_join,
    })
}

/// The distinct canonical `key_id`s carried by the `(key_id, TransportHint)` pairs
/// [`Engine::canonical_bootstrap_hints`] returns — the replication targets. Order
/// is preserved by first appearance; duplicates (a canonical with multiple hints)
/// collapse to one. Pure so it is unit-testable without an engine.
pub(crate) fn distinct_canonical_key_ids(
    hints: &[(String, ciris_persist::federation::types::TransportHint)],
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (key_id, _hint) in hints {
        if !out.iter().any(|k| k == key_id) {
            out.push(key_id.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_persist::federation::types::TransportHint;

    fn hint(dest: &str, kind: &str) -> TransportHint {
        TransportHint {
            destination: dest.to_string(),
            kind: kind.to_string(),
        }
    }

    #[test]
    fn distinct_key_ids_dedupes_multi_hint_canonical() {
        // One canonical with two hints (ip + reticulum) + a second canonical.
        let hints = vec![
            ("canon-1".to_string(), hint("108.61.242.236:4243", "ip")),
            ("canon-1".to_string(), hint("abcd", "reticulum")),
            ("canon-2".to_string(), hint("10.0.0.1:4243", "ip")),
        ];
        let ids = distinct_canonical_key_ids(&hints);
        assert_eq!(ids, vec!["canon-1".to_string(), "canon-2".to_string()]);
    }

    #[test]
    fn distinct_key_ids_empty_on_no_hints() {
        assert!(distinct_canonical_key_ids(&[]).is_empty());
    }

    #[test]
    fn build_replication_peers_two_coordinators_per_target() {
        use ciris_edge::replication::EnvelopeKind;
        // The delivery controller hands the admitted canonical targets to the SAME
        // peer-assembly the compose boot path uses: exactly Attestation + Key per
        // target, in target order.
        let desired = vec!["canon-1".to_string(), "peer-b".to_string()];
        let peers = crate::compose::build_replication_peers(&desired);
        assert_eq!(peers.len(), 4);
        assert_eq!(peers[0].peer_key_id, "canon-1");
        assert!(matches!(peers[0].kind, EnvelopeKind::Attestation));
        assert!(matches!(peers[1].kind, EnvelopeKind::Key));
        assert_eq!(peers[2].peer_key_id, "peer-b");
        assert!(matches!(peers[2].kind, EnvelopeKind::Attestation));
        assert!(matches!(peers[3].kind, EnvelopeKind::Key));
    }

    #[test]
    fn build_replication_peers_empty_target_set() {
        assert!(crate::compose::build_replication_peers(&[]).is_empty());
    }
}
