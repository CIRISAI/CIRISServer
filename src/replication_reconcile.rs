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
///
/// Returns the number of converged consent peers so the controller loop can log
/// at INFO only on a genuine change (and `debug!` otherwise — a steady count
/// every cadence is noise on an idle node).
pub async fn reconcile_once(
    engine: &Arc<Engine>,
    node_key_id: &str,
    runtime: &Arc<ReplicationRuntime>,
) -> anyhow::Result<usize> {
    // ── The #530 REPAIR motion (persist v21.12.0) ───────────────────────────
    // `promote_consented_backlog` is auto-fired at its own chokepoints, but it
    // pages `WHERE tier = 'local'` — so a row that already reached
    // `(cohort_scope = self|family, tier = federation)` is excluded from it BY
    // CONSTRUCTION and no cadence of re-running ever revisits it. Such a row is
    // past the tier gate, covered by a live grant, and still never offered.
    // persist ships the second motion (`repair_stranded_scope_backlog`) but
    // deliberately does NOT call it from the promote sweep, and nothing else
    // called it either — leaving the (a)+(c) pair with only (a) wired.
    //
    // This loop is the right home: it is already the "converge the live runtime
    // to the CEG" tick, and the repair is safe to run unconditionally —
    // strictly WIDENING (a grant whose audience is itself suppressed means the
    // row's invisibility MATCHES consent, so it is skipped, never narrowed),
    // scoped to rows covered by a live grant, and a PURE placement correction
    // (already federation-tier ⇒ no tier flip, no re-signing; `cohort_scope`
    // lives outside the signed envelope so the scrub signature stays valid).
    // Self-limiting like its sibling: a repaired row leaves the stranded set.
    //
    // Ordering matters — repair BEFORE computing the desired peer set, so a row
    // corrected on this tick is offerable on this tick rather than the next.
    match engine.repair_stranded_scope_backlog().await {
        Ok(report) => {
            if report.rescoped > 0 || report.skipped > 0 {
                tracing::info!(
                    rescoped = report.rescoped,
                    skipped = report.skipped,
                    "CIRISPersist#530 repair sweep: re-scoped {} stranded \
                     (self|family, federation) row(s) to their covering grant's audience — \
                     these were past the tier gate but never offered (the offer filter keys \
                     on cohort_scope)",
                    report.rescoped,
                );
            }
        }
        // Never fail the tick on the repair motion: the peer-set convergence
        // below is the loop's primary duty and must still run.
        Err(e) => tracing::warn!(
            error = %e,
            "CIRISPersist#530 repair sweep failed this tick — stranded rows (if any) stay \
             unofferable until the next tick; peer convergence continues"
        ),
    }

    // ── The #227 CONSENT-DECAY sweep (CIRISServer#337) ──────────────────────
    // The second of the pair #337 asked for, and the one that was still
    // uncalled: `repair_stranded_scope_backlog` above landed; this did not.
    //
    // It is the TIME-driven twin of the disk-pressure sweeper. A content unit
    // admitted under a TEMPORARY (14-day) or pattern (90-day) consent class is
    // supposed to shed symbols down its tier schedule as that window elapses —
    // that decay IS the consent, and it is what makes "temporary" mean anything
    // to the person who granted it. Nothing drives that clock but this call, so
    // until now every unit stayed at Full tier indefinitely: the schedule was
    // computed, tested, and never once advanced on a live node. An expiry that
    // no clock enforces is not an expiry.
    //
    // Disk-INDEPENDENT by design (no watermark, no free-bytes gate) — the
    // promise was made in days, not in bytes, so a node with plenty of disk must
    // still honour it. Safe to run unconditionally: idempotent (the eviction
    // only removes symbols down to a keep-count, so re-running at the same
    // instant evicts nothing further), fail-safe for units that declare no decay
    // class (left untouched — silence is not consent to delete), and manifests
    // are never touched (the always-retained provenance).
    //
    // This loop is the right home for the same reason the repair sweep is: it is
    // already the tick that converges the node to what consent says, and the
    // decay schedule is consent with a clock on it.
    match engine.sweep_consent_decay_once(chrono::Utc::now()).await {
        Ok(report) => {
            // Only speak when the clock actually moved something. A node holding
            // no fountain content — still the common case — would otherwise log
            // an identical zero every cadence forever, and the one pass that
            // DOES decay something would be indistinguishable from it.
            if report.content_decayed > 0 || report.symbols_evicted > 0 {
                tracing::info!(
                    content_scanned = report.content_scanned,
                    content_with_decay_class = report.content_with_decay_class,
                    content_decayed = report.content_decayed,
                    symbols_evicted = report.symbols_evicted,
                    "CIRISPersist#227 consent-decay sweep: {} content unit(s) crossed a decay \
                     breakpoint and shed {} symbol(s) — the TEMPORARY/pattern consent windows \
                     are being honoured on the clock, not just at admission",
                    report.content_decayed,
                    report.symbols_evicted,
                );
            }
        }
        // Never fail the tick on the decay sweep, for the same reason as the
        // repair above: peer convergence is this loop's primary duty. A missed
        // sweep costs latency on a decay boundary, and the next tick re-derives
        // the target tier from the wall clock — nothing is lost by skipping one.
        Err(e) => tracing::warn!(
            error = %e,
            "CIRISPersist#227 consent-decay sweep failed this tick — content past a decay \
             breakpoint keeps its symbols until the next tick; peer convergence continues"
        ),
    }

    // Desired topology from the corpus (the consent objects ARE the topology).
    let consented = crate::peer::replication_peers_from_consent(engine, node_key_id).await?;

    // ── CC 4.1.4 (CIRISServer#159) — the withdraws-arbitrage countermeasure ──
    // Consent is granted once; behavior is continuous. A peer that was clean at
    // peering time can turn into a `withdraws`-arbitrager afterwards (spray
    // aggressive attestations, retract whatever fails to stick, never `recants`,
    // never pay the epistemic-error price — see `crate::withdraws_arbitrage`). The
    // window is ROLLING, so this tick re-judges every consent peer in BOTH
    // directions: an attester that crosses the threshold stops being pulled from
    // on the next tick, and one that mends its ways (or simply ages out) is
    // re-admitted with no operator action. This is consumer policy — we refuse to
    // CONSUME the arbitrager's corpus. Substrate admission of any individual
    // `withdraws` is untouched (CC 2.4.1.1 MUST-admit).
    let policy = crate::withdraws_arbitrage::load_policy(engine).await;
    let now = chrono::Utc::now();

    // Admission filter: only peers whose key is a verified federation_keys row
    // can be replicated with (the runtime would have no key to route/verify).
    // EnvelopeKind::Attestation carries BOTH directions (capacity:* out,
    // health:liveness in).
    let directory = engine.federation_directory();
    let mut desired: Vec<ReplicationPeer> = Vec::with_capacity(consented.len() * 4);
    for peer in consented {
        // Fail closed: an over-threshold attester — or one whose behavioral ledger
        // we cannot read at all — is dropped from the desired set this tick.
        if let Err(refusal) = crate::withdraws_arbitrage::enforce(engine, &peer, policy, now).await
        {
            tracing::warn!(
                peer_key_id = %peer,
                refusal = %refusal,
                "CC 4.1.4 withdraws-arbitrage: consent peer REFUSED — not replicating from it \
                 this tick (consumer-policy downweight to zero; the consent CEG is untouched \
                 and the peer is re-admitted automatically once its in-window ratio recovers)"
            );
            continue;
        }
        match directory.lookup_public_key(&peer).await {
            Ok(Some(_)) => {
                // ALL THREE planes per admitted peer (mirrors compose::build_replication_peers):
                //  - Attestation: capacity:* out, health:liveness in (as before).
                //  - Key (#144, CIRISEdge#257): the KEY-PLANE anti-entropy. Paired
                //    with the runtime's `key_selector` (publishes the node's OWN
                //    record — KERI publish-own), this converges a node's scrub-signed
                //    accord-anchored record to its consent peers so they can ROOT it.
                //  - IdentityOccurrence (CIRISEdge#305): the KEX plane — the occurrence
                //    carries the content-tier `encryption_pubkeys`. Paired with the
                //    runtime's `occurrence_selector` (publish-own), this converges the
                //    node's enc keys to peers so they can SEAL to it (and pulls peers'
                //    enc keys in). Without it a hot-added peer roots but never KEXes.
                desired.push(ReplicationPeer {
                    peer_key_id: peer.clone(),
                    kind: EnvelopeKind::Attestation,
                });
                desired.push(ReplicationPeer {
                    peer_key_id: peer.clone(),
                    kind: EnvelopeKind::Key,
                });
                desired.push(ReplicationPeer {
                    peer_key_id: peer.clone(),
                    kind: EnvelopeKind::IdentityOccurrence,
                });
                //  - TransportDestination (CIRISEdge#406): paired with the publish-own
                //    self_provider, offers this node's OWN SIGNED transport-dest so a
                //    peer receives it and can satisfy its #393 item-2 PQ attribution
                //    gate. Without a round for this kind the signed TD is published
                //    locally but never transferred (the item-2 dead end).
                desired.push(ReplicationPeer {
                    peer_key_id: peer,
                    kind: EnvelopeKind::TransportDestination,
                });
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

    // Diff-converge the live Initiator set to the desired consent peers. Adds
    // become active Initiators (scheduler-driven pull) at runtime; removals stop
    // their rounds + drop inbound routing — all without a restart.
    // `desired` holds THREE coordinators per peer (Attestation + Key +
    // IdentityOccurrence); the reported count is distinct consent peers.
    let count = desired.len() / 3;
    if let Err(e) = runtime.set_peers(desired).await {
        // The runtime's scheduler has stopped (shutdown) — surface so the caller
        // logs + skips; the controller never panics.
        anyhow::bail!("replication set_peers failed to converge: {e}");
    }

    // Steady-state per-tick detail (the controller loop logs the INFO line only
    // when this count actually changes, so an idle node doesn't spam INFO).
    tracing::debug!(
        consent_peers = count,
        "replication reconcile tick: converged to {count} consent peers",
    );

    Ok(count)
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
        //
        // Only log the converged-peers INFO line when the count CHANGES from the
        // previous cycle (e.g. 0→2, 2→0); a steady count logs at debug! inside
        // reconcile_once so an idle node doesn't spam INFO every cadence.
        let mut last_logged: Option<usize> = None;
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

            match reconcile_once(&engine, &node_key_id, &runtime).await {
                Ok(count) => {
                    // INFO only on a genuine transition; otherwise the per-tick
                    // detail already went to debug! inside reconcile_once.
                    if last_logged != Some(count) {
                        tracing::info!(
                            consent_peers = count,
                            "replication converged to {count} consent peers",
                        );
                        last_logged = Some(count);
                    }
                }
                Err(e) => {
                    // Never panic the controller on a transient directory read error.
                    tracing::warn!(error = %e, "replication reconcile tick failed — skipping");
                }
            }
        }
    })
}
