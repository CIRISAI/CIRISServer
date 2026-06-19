//! The **CEG-driven replication reconciler** — the controller loop that converges
//! the live [`ReplicationRuntime`] to the desired topology recorded in the corpus.
//!
//! ## Architecture rule (load-bearing)
//!
//! **The API never touches the runtime — it writes CEG; the runtime is
//! CEG-driven.** `POST /v1/federation/peering` (see [`crate::federation_admin`])
//! only ever writes a `consent:replication:v1` object to the corpus and nudges
//! this loop via a [`tokio::sync::Notify`]. The `consent:replication` objects in
//! the corpus ARE the desired replication topology
//! ([`crate::peer::replication_peers_from_consent`]); this loop is the single
//! place that mutates the runtime registry to match them.
//!
//! ## What converges (fully runtime — no restart)
//!
//! Each reconcile computes the desired peer set (admitted `consent:replication`
//! subjects) and hands it to [`ReplicationRuntime::set_peers`], which
//! diff-converges the runtime's **live Initiator set** (adds first, then removes):
//!
//!   - **newly consented** → an active **Initiator** coordinator is spawned at
//!     runtime (scheduler-driven active pull begins immediately — no restart).
//!   - **consent gone** → the matching Initiator's scheduled rounds stop and its
//!     inbound routing is deregistered.
//!
//! This uses edge v5.1.0's runtime peer-control API; the interim
//! "active pull only after restart" gap (**CIRISEdge#173**) is resolved.
//!
//! The loop is robust: a directory read error logs + skips the tick and never
//! panics the controller.

use std::sync::Arc;

use ciris_edge::replication::{EnvelopeKind, ReplicationPeer, ReplicationRuntime};
use ciris_persist::prelude::Engine;
use tokio::sync::{watch, Notify};

use crate::config_reconcile::ResolvedConfig;

/// Run **one** reconcile pass: converge the runtime's live `Attestation`-kind
/// **Initiator** set to the admitted `consent:replication` subjects in the corpus.
/// Factored out of the loop so tests can drive a single deterministic step
/// ([`crate::replication_reconcile::reconcile_once`]).
///
/// - `desired` = [`crate::peer::replication_peers_from_consent`] **filtered to
///   peers whose key is admitted in the directory** (we cannot replicate with an
///   unknown key — an unadmitted consent subject is skipped + warned).
/// - hand `desired` to [`ReplicationRuntime::set_peers`], which diff-converges the
///   live Initiator coordinators (adds first, then removes). Newly consented peers
///   begin active pull immediately; revoked peers stop — all at runtime, no
///   restart (edge v5.1.0, CIRISEdge#173 resolved).
///
/// A directory read error returns `Err` (the caller logs + skips the tick); this
/// fn itself never panics.
pub async fn reconcile_once(
    engine: &Arc<Engine>,
    node_key_id: &str,
    runtime: &Arc<ReplicationRuntime>,
) -> anyhow::Result<()> {
    // Desired topology from the corpus (the consent objects ARE the topology).
    let consented = crate::peer::replication_peers_from_consent(engine, node_key_id).await?;

    // Admission filter: only peers whose key is a verified federation_keys row
    // can be replicated with (the runtime would have no key to route/verify).
    // EnvelopeKind::Attestation carries BOTH directions (capacity:* out,
    // health:liveness in).
    let directory = engine.federation_directory();
    let mut desired: Vec<ReplicationPeer> = Vec::with_capacity(consented.len());
    for peer in consented {
        match directory.lookup_public_key(&peer).await {
            Ok(Some(_)) => desired.push(ReplicationPeer {
                peer_key_id: peer,
                kind: EnvelopeKind::Attestation,
            }),
            Ok(None) => tracing::warn!(
                peer_key_id = %peer,
                "consent:replication observed for an UNADMITTED peer key — skipping reconcile for \
                 it (register the peer's self-signed key first via POST /v1/federation/peering)"
            ),
            Err(e) => tracing::warn!(
                peer_key_id = %peer,
                error = %e,
                "directory lookup for a consent peer failed — skipping it this tick"
            ),
        }
    }

    // Diff-converge the live Initiator set to the desired consent peers. Adds
    // become active Initiators (scheduler-driven pull) at runtime; removals stop
    // their rounds + drop inbound routing — all without a restart.
    let count = desired.len();
    if let Err(e) = runtime.set_peers(desired).await {
        // The runtime's scheduler has stopped (shutdown) — surface so the caller
        // logs + skips; the controller never panics.
        anyhow::bail!("replication set_peers failed to converge: {e}");
    }

    tracing::info!(
        consent_peers = count,
        "replication converged to {count} consent peers",
    );

    Ok(())
}

/// Spawn the reconcile controller loop. Returns the task handle (held by the
/// caller for the node's lifetime). The loop ticks on the configured cadence, on
/// an explicit `notify` nudge (the peering API fires this after writing CEG so
/// convergence is prompt), and exits when `shutdown` flips to `true`.
///
/// **HOT cadence (Server 0.5 Phase 2):** the reconcile period is sourced from the
/// live resolved-config snapshot (`config_rx`, `replication.reconcile_secs`) —
/// previously `CIRIS_SERVER_REPLICATION_RECONCILE_SECS` env. The interval is
/// rebuilt when the cadence changes, so a `POST /v1/config` retunes it on the next
/// tick with no restart.
pub fn spawn(
    engine: Arc<Engine>,
    node_key_id: String,
    runtime: Arc<ReplicationRuntime>,
    notify: Arc<Notify>,
    config_rx: watch::Receiver<ResolvedConfig>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut period = config_rx.borrow().replication_reconcile_interval();
        let mut interval = tokio::time::interval(period);
        // Skip missed ticks rather than burst-catch-up if a reconcile runs long.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            period_secs = period.as_secs(),
            "CEG-driven replication reconciler started (consent objects are the topology; \
             API writes CEG, this loop converges the live runtime via set_peers — no restart, \
             CIRISEdge#173 resolved; cadence from config:* replication.reconcile_secs)"
        );

        // An initial reconcile is already implied by the first immediate
        // interval.tick(); no extra pass needed.
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = notify.notified() => {
                    tracing::debug!("reconcile nudged (CEG changed) — reconciling now");
                }
                changed = shutdown.changed() => {
                    // Sender dropped (Err) or flipped to true → exit.
                    if changed.is_err() || *shutdown.borrow() {
                        tracing::info!("replication reconciler shutting down");
                        return;
                    }
                    continue;
                }
            }

            // Hot cadence: rebuild the interval if replication.reconcile_secs changed.
            let live_period = config_rx.borrow().replication_reconcile_interval();
            if live_period != period {
                period = live_period;
                interval = tokio::time::interval(period);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                interval.tick().await; // consume the immediate tick
                tracing::info!(
                    period_secs = period.as_secs(),
                    "replication reconcile cadence retuned from config:* (hot)"
                );
            }

            if let Err(e) = reconcile_once(&engine, &node_key_id, &runtime).await {
                // Never panic the controller on a transient directory read error.
                tracing::warn!(error = %e, "replication reconcile tick failed — skipping");
            }
        }
    })
}
