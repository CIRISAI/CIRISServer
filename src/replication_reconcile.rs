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

use ciris_edge::replication::{ReplicationPeer, ReplicationRuntime};
use ciris_persist::prelude::Engine;
use tokio::sync::{watch, Notify};

use crate::config_reconcile::ResolvedConfig;

/// Say WHICH rows the consent sweep reported `awaiting_actor` for, and what
/// each one means — because the count alone was wrong three ways at once.
///
/// The sweep's candidates are federation-tier rows at an undiscoverable scope
/// (`self` / `family`, CC 5.2) with no `supersedes` by their own attester. On
/// every claimed node that set contains the OWNER-BINDING setup-complete wrote
/// at `self`, and it stays in the set after a successful announce, because the
/// announce widens by emitting a fresh federation-scope `delegates_to` rather
/// than a `supersedes` — deliberately: persist's `owner_of` folds `delegates_to`
/// rows only, and a peer holds nothing but the widening, so a `supersedes`
/// widening of the binding would resolve the node to NO owner at every peer
/// (CIRISPersist#807 — CLOSED by persist v41.1.0, adopted in 0.5.199: a settled
/// owner-binding is no longer offered as a candidate, so the "announced" case
/// below should now be empty; it stays as the reading for any older substrate
/// and as the guard if the candidate ever comes back). So the binding's
/// candidacy is not a stuck row:
///
/// * announced — the federation copy exists; the candidate is persist's
///   bookkeeping, and this logs it at DEBUG;
/// * not announced — P2P-only by the owner's choice (the wizard's opt-out);
///   INFO, naming the route that widens it;
/// * anything else — genuinely waiting on a signer this node does not hold;
///   WARN, the only case that was ever a fault.
///
/// Read-only: it pages the same candidate list the sweep pages and writes
/// nothing. Bounded to one page so a pathological corpus cannot turn a log
/// line into a scan.
async fn explain_awaiting_actor(engine: &Engine, node_key_id: &str, awaiting: u64) {
    use ciris_persist::federation::admission::is_owner_binding_envelope;
    use ciris_persist::federation::types::{attestation_type, cohort_scope};

    let dir = engine.federation_directory();
    let candidates = match dir.list_widening_candidates(None, 64).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(
                awaiting_actor = awaiting,
                error = %e,
                "{awaiting} row(s) await their author's signer and this node could not read \
                 which — the widening-candidate page failed"
            );
            return;
        }
    };
    let mut unexplained = 0u64;
    for row in &candidates {
        if !is_owner_binding_envelope(&row.attestation_envelope) {
            unexplained += 1;
            tracing::warn!(
                attestation_id = %row.attestation_id,
                attester = %row.attesting_key_id,
                attested = %row.attested_key_id,
                cohort_scope = %row.cohort_scope,
                "row awaits its author's signer and will NOT move on its own — the sweep \
                 re-authors nobody's claim. If the author is a REMOTE key this is correct \
                 and the row waits for that node. If the author is THIS node's owner, the \
                 crossing was handed no actor (or one keyed for `attest::emit`, whose \
                 `key_id` is already derived and so derives twice against `custody_for`) — \
                 see `identity::hardware_user_crossing_signer`"
            );
            continue;
        }
        // The owner-binding. Is there a federation-scope `delegates_to` by the
        // same owner onto the same node — i.e. has the owner announced?
        let announced = dir
            .list_attestations_for(&row.attested_key_id)
            .await
            .unwrap_or_default()
            .iter()
            .any(|a| {
                a.attestation_type == attestation_type::DELEGATES_TO
                    && a.attesting_key_id == row.attesting_key_id
                    && a.cohort_scope == cohort_scope::FEDERATION
                    && is_owner_binding_envelope(&a.attestation_envelope)
            });
        let ours = row.attested_key_id == node_key_id;
        if announced {
            tracing::debug!(
                attestation_id = %row.attestation_id,
                owner = %row.attesting_key_id,
                node = %row.attested_key_id,
                "owner-binding listed as a widening candidate although the owner has \
                 ANNOUNCED (a federation-scope delegates_to by the same owner exists). \
                 Nothing to do: the announce widens by a fresh delegates_to because \
                 owner_of folds delegates_to only. persist v41.1.0 stopped offering a \
                 settled binding (CIRISPersist#807) — seeing this line on v41.1.0+ means \
                 the candidate came back; say so upstream"
            );
        } else if ours {
            tracing::info!(
                attestation_id = %row.attestation_id,
                owner = %row.attesting_key_id,
                "this node's owner-binding is held at cohort_scope `self` only: the owner \
                 has NOT announced, so this node is P2P-only by choice — it can dial and \
                 be dialled, and no peer can place it in a community audience. \
                 POST /v1/federation/announce widens it (the wizard's default)"
            );
        } else {
            tracing::info!(
                attestation_id = %row.attestation_id,
                owner = %row.attesting_key_id,
                node = %row.attested_key_id,
                "a peer's owner-binding at cohort_scope `self` is held here without a \
                 federation copy — their owner has not announced; the row waits for them"
            );
        }
    }
    if candidates.len() as u64 >= 64 && awaiting > candidates.len() as u64 {
        tracing::warn!(
            awaiting_actor = awaiting,
            shown = candidates.len(),
            "more rows await their author's signer than one page shows"
        );
    }
    let _ = unexplained;
}

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
    // ── The #530 REPAIR motion (persist v39.0.0) ───────────────────────────
    // Was `repair_stranded_scope_backlog`, which persist shipped but never
    // called, leaving the (a)+(c) pair with only (a) wired — this loop was its
    // only caller. v39.0.0 DELETED it and re-cut `promote_consented_backlog`
    // over the two crossing verbs, so the motion is now that sweep's second
    // pass: rows already in the mesh at an undiscoverable scope with no widening
    // yet (`list_widening_candidates`) — the sealed-before-grant case #530
    // found — are widened by a `supersedes` the ACTOR signs.
    //
    // That is a real change in what the repair DOES, and it is the point of
    // v39. The old motion re-scoped a row in place, which was safe only because
    // `cohort_scope` sat outside the signed envelope; the new one leaves the
    // actor's row untouched and writes a second row at the wider audience. A
    // row whose actor this node does not hold now WAITS (`awaiting_actor`)
    // instead of being silently re-authored by the fabric.
    //
    // Still the right home, and for the original reason: this is already the
    // "converge the live runtime to the CEG" tick, and running it here — BEFORE
    // the desired peer set is computed — makes a row corrected on this tick
    // offerable on this tick rather than the next. The sweep is idempotent and
    // self-limiting; persist also auto-fires it at its own chokepoints, so this
    // call is the cadence, not the only trigger.
    match engine.promote_consented_backlog().await {
        Ok(report) => {
            if report.promoted > 0 || report.widened > 0 || report.awaiting_actor > 0 {
                tracing::info!(
                    promoted = report.promoted,
                    widened = report.widened,
                    awaiting_actor = report.awaiting_actor,
                    skipped = report.skipped,
                    "CIRISPersist#530 consent sweep: {} row(s) entered the mesh, {} widened to \
                     their covering grant's audience; {} await their actor's signer (a row this \
                     node did not author is not re-authored by it)",
                    report.promoted,
                    report.widened,
                    report.awaiting_actor,
                );
            }
            if report.awaiting_actor > 0 {
                // AN `Ok` THAT DID NOTHING, on a cadence. These rows are counted
                // every tick and moved by none of them: the sweep will not
                // re-author another key's claim, which is the v39 correction
                // itself, so nothing here converges with time. Named row by row,
                // because "stuck" was three different situations and the count
                // alone read as a fault on every announced node in the mesh.
                explain_awaiting_actor(engine, node_key_id, report.awaiting_actor).await;
            }
        }
        // Never fail the tick on the repair motion: the peer-set convergence
        // below is the loop's primary duty and must still run.
        Err(e) => tracing::warn!(
            error = %e,
            "CIRISPersist#530 consent sweep failed this tick — stranded rows (if any) stay \
             unofferable until the next tick; peer convergence continues. This sweep is \
             what carries a locally-authored row from `self` to the audience its \
             covering grant names, so while it is failing, rows accumulate that this \
             node can read and no peer can: the symptom downstream is a plane that \
             looks healthy locally and delivers nothing"
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

    // ── CIRISServer#472 — heal person-subject grants onto their bound nodes ──
    //
    // A contact grant emitted BEFORE the contact's owner-binding replicated here
    // falls back to the PERSON-subject form — recorded intent the wire cannot
    // route (a person's key has no transport binding; edge matches send-set
    // recipients by exact key). The binding arrives on its own anti-entropy
    // schedule, so add-time resolution is a race by construction. This tick is
    // the natural healer: it already owns consent-vs-transport reconciliation
    // and re-runs on a timer, and `ensure_contact_consent_covers` is idempotent
    // — one no-op read per tick once coverage stands. The person-subject grant
    // remains live as the recorded intent; what heals is that the same coverage
    // now ALSO names a subject the wire can serve. (The class fix — the
    // send-set resolving persons itself — is CIRISPersist#764; this healer
    // becomes a no-op the day it ships.)
    match crate::peer::live_consent_grants(engine, node_key_id).await {
        Ok(grants) => {
            for (subject, prefixes) in grants {
                if prefixes.is_empty() {
                    continue;
                }
                match crate::peer::bound_nodes_of(engine, &subject).await {
                    // A subject with bound nodes is a PERSON (nodes own nothing);
                    // ensure the same prefixes are live on each routable node.
                    Ok(nodes) if !nodes.is_empty() => {
                        if let Err(e) = crate::peer::ensure_contact_consent_covers(
                            engine,
                            node_key_id,
                            &subject,
                            &prefixes,
                        )
                        .await
                        {
                            tracing::warn!(
                                subject = %subject,
                                error = %e,
                                "CIRISServer#472 consent healer: could not widen coverage onto                                  the contact's bound node this tick — retrying next tick"
                            );
                        }
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(
                        subject = %subject,
                        error = %e,
                        "CIRISServer#472 consent healer: bound-node resolution failed this tick"
                    ),
                }
            }
        }
        // Never fail the tick: peer convergence is this loop's primary duty.
        Err(e) => tracing::warn!(
            error = %e,
            "CIRISServer#472 consent healer: could not read the live grant set this tick"
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
    let mut admitted_peers: usize = 0;
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
                // EVERY plane per admitted peer — from the ONE list that
                // defines them (`compose::build_replication_peers`), not a
                // hand-maintained copy of it.
                //
                // This used to restate the kinds inline, and the restatement had
                // already drifted: its own comment said "ALL THREE planes" while
                // listing four, and the community plane added beside it would
                // have made that five in one file and three in the other. Two
                // lists that must agree about what replicates is the shape this
                // tree keeps paying for — a peer hot-added HERE would silently
                // converge fewer planes than one added at boot, and nothing
                // would fail until someone noticed a room that never arrived.
                //
                // The per-plane rationale lives at the definition site.
                desired.extend(crate::compose::build_replication_peers(
                    std::slice::from_ref(&peer),
                ));
                admitted_peers += 1;
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
    // COUNT PEERS, NOT COORDINATORS. The old `desired.len() / 3` baked a
    // plane count into a denominator two files away from the plane list — it
    // was already stale at four planes and reported 2x peers at six. The
    // admitted-peer counter cannot drift with the fan-out.
    let count = admitted_peers;
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

            // The node's own health, on the cadence that is already running.
            //
            // Deliberately BEFORE the reconcile call and outside its result:
            // the counters describe the rounds edge already ran, so they are
            // just as readable on a tick whose reconcile is about to fail — and
            // a tick that fails is exactly when an operator wants them. Reading
            // them here rather than spawning a fourth loop also means the
            // degradation window is the reconcile cadence, which is the same
            // clock the operator surface's peer counts move on.
            //
            // `current_edge()` is fallible by design (a fold with no edge in
            // process). Absent edge raises nothing: this loop reports what edge
            // measured, and has no standing to invent a verdict when there is
            // nothing to measure with.
            match ciris_edge::current_edge() {
                // `last_logged` carries the converged peer count from the
                // previous tick — the topology evidence the degradation module
                // cannot obtain for itself. ZERO peers means there is nobody to
                // fail to converge WITH, which is what lets an operator recover
                // by removing the failing relationship; without it, the alarm
                // they just fixed would stand forever (PR #483 review).
                Ok(e) => crate::degradation::report_edge_metrics_with_topology(
                    &e.metrics().snapshot(),
                    last_logged,
                ),
                Err(e) => tracing::debug!(
                    error = %e,
                    "no in-process edge to read round counters from this tick —                      network degradation not evaluated (not the same as 'healthy')"
                ),
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
