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
//! ## What converges (and the honest interim gap)
//!
//! Each reconcile diffs the desired peer set (admitted `consent:replication`
//! subjects) against the runtime's currently-registered `Attestation`-kind peers:
//!
//!   - **newly consented** → [`ReplicationRuntime::register_peer`], which hot-adds
//!     a **Responder** (inbound routing). Inbound replication from that peer works
//!     immediately. ACTIVE INITIATION (the scheduler-driven pull) is derived from
//!     CEG only at boot today, so a runtime-added peer begins active pull after
//!     the next node restart, until the runtime Initiator-add lands
//!     (**CIRISEdge#173**).
//!   - **consent gone** → [`ReplicationRegistry::deregister`] for the
//!     `Attestation` kind.
//!
//! The loop is robust: a directory read error logs + skips the tick and never
//! panics the controller.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use ciris_edge::replication::{EnvelopeKind, ReplicationRuntime};
use ciris_persist::prelude::Engine;
use tokio::sync::{watch, Notify};

/// Default reconcile cadence (seconds) when `CIRIS_SERVER_REPLICATION_RECONCILE_SECS`
/// is unset / unparsable.
const DEFAULT_RECONCILE_SECS: u64 = 30;

/// The reconcile cadence, from `CIRIS_SERVER_REPLICATION_RECONCILE_SECS`
/// (default [`DEFAULT_RECONCILE_SECS`]). A `0` or unparsable value falls back to
/// the default (a zero-period interval would busy-spin).
fn reconcile_interval() -> Duration {
    let secs = std::env::var("CIRIS_SERVER_REPLICATION_RECONCILE_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(DEFAULT_RECONCILE_SECS);
    Duration::from_secs(secs)
}

/// Run **one** reconcile pass: converge the runtime's registered
/// `Attestation`-kind peers to the admitted `consent:replication` subjects in the
/// corpus. Factored out of the loop so tests can drive a single deterministic
/// step ([`crate::replication_reconcile::reconcile_once`]).
///
/// - `desired` = [`crate::peer::replication_peers_from_consent`] **filtered to
///   peers whose key is admitted in the directory** (we cannot replicate with an
///   unknown key — an unadmitted consent subject is skipped + warned).
/// - `current` = the runtime registry's `Attestation`-kind keys.
/// - register the `desired − current`; deregister the `current − desired`.
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
    let directory = engine.federation_directory();
    let mut desired: HashSet<String> = HashSet::new();
    for peer in consented {
        match directory.lookup_public_key(&peer).await {
            Ok(Some(_)) => {
                desired.insert(peer);
            }
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

    // Current Attestation-kind registrations on the live runtime.
    let current: HashSet<String> = runtime
        .registry()
        .registered_keys()
        .await
        .into_iter()
        .filter(|(_, kind)| *kind == EnvelopeKind::Attestation)
        .map(|(peer, _)| peer)
        .collect();

    // desired − current → register for inbound (Responder hot-add).
    for peer in desired.difference(&current) {
        runtime
            .register_peer(peer.clone(), EnvelopeKind::Attestation)
            .await;
        tracing::info!(
            peer_key_id = %peer,
            "consent:replication for {peer} observed → registered for inbound. Active initiation \
             begins after next restart until runtime Initiator-add lands (CIRISEdge#173).",
        );
    }

    // current − desired → consent revoked / gone → deregister.
    for peer in current.difference(&desired) {
        runtime
            .registry()
            .deregister(peer, EnvelopeKind::Attestation)
            .await;
        tracing::info!(
            peer_key_id = %peer,
            "consent:replication for {peer} revoked → deregistered.",
        );
    }

    Ok(())
}

/// Spawn the reconcile controller loop. Returns the task handle (held by the
/// caller for the node's lifetime). The loop ticks on the configured cadence, on
/// an explicit `notify` nudge (the peering API fires this after writing CEG so
/// convergence is prompt), and exits when `shutdown` flips to `true`.
pub fn spawn(
    engine: Arc<Engine>,
    node_key_id: String,
    runtime: Arc<ReplicationRuntime>,
    notify: Arc<Notify>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let period = reconcile_interval();
        let mut interval = tokio::time::interval(period);
        // Skip missed ticks rather than burst-catch-up if a reconcile runs long.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            period_secs = period.as_secs(),
            "CEG-driven replication reconciler started (consent objects are the topology; \
             API writes CEG, this loop converges; runtime Initiator-add pending CIRISEdge#173)"
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

            if let Err(e) = reconcile_once(&engine, &node_key_id, &runtime).await {
                // Never panic the controller on a transient directory read error.
                tracing::warn!(error = %e, "replication reconcile tick failed — skipping");
            }
        }
    })
}
