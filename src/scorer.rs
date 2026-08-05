//! Capacity scorer — the score→emit pipeline (CIRISServer federation Round 1,
//! deliverable 2).
//!
//! A **periodic task** (spawned from [`crate::compose::serve`], NEVER in the
//! ingest hot path) that, per agent with ingested traces in the local corpus:
//!
//!   1. enumerates the agent's trace summaries over a window (the lens feature
//!      matrix — `ReadEngine::list_trace_summaries`, the same surface the read
//!      API serves);
//!   2. builds the per-trace feature matrix (rows = traces, cols = the lens
//!      constraint dims), standardizes columns to Z, computes the covariance
//!      eigenspectrum, and derives **N_eff** — a faithful port of CIRISLens
//!      `scripts/measure_n_eff.py:141-186` (see [`n_eff`]);
//!   3. feeds `n_eff` into [`scoring::capacity::capacity`] for the
//!      `sustained_coherence` factor (the CEG §5.5.4 S factor — "long-window
//!      N_eff + manifold-conformity stability", the one factor N_eff *is*);
//!   4. assembles a FEDERATION-tier `capacity:*` `scores` [`Attestation`]
//!      (attesting = Node A's key, attested = the agent's key — anti-Goodhart
//!      enforced by [`CapacityAttestation::new`]), hybrid-signs it, and
//!      `put_attestation`s it to Node A's OWN corpus.
//!
//! The emit recipe is modeled line-for-line on CIRISStatus `src/ceg.rs:182`
//! (`emit_liveness`): JCS-canonicalize the envelope → `hex(SHA-256)` →
//! `Engine::sign_hybrid` → assemble the federation-tier row → `put_attestation`.
//!
//! ## Gate semantics (documented choice)
//!
//! `capacity(n_eff, gate, target)` returns `0.0` when `n_eff <= gate` (the
//! LC-AV-18 sample-size gate). We **emit the 0.0 row anyway** when an agent has
//! at least one trace: a federation-visible "we observed this agent but do not
//! yet have enough independent constraint to vouch" signal is itself useful
//! consumer telemetry (and it is honest — a *missing* row is indistinguishable
//! from "never observed"). An agent with **zero** ingested traces is skipped
//! entirely (nothing to attest about).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::watch;

use ciris_lens_core::capacity::CapacityAttestation;
use ciris_lens_core::scoring;
use ciris_persist::federation::envelope::paths;
/// The four stances persist's ONE canonical scoped-consent fold can return.
/// Named here rather than path-qualified at the match arm so the gate reads as
/// the four-way question it is — and so a fifth stance CC might add would fail
/// to compile at the arm rather than fold silently into "declined".
use ciris_persist::federation::hard_case::ConsentState;
use ciris_persist::federation::types::cohort_scope;
use ciris_persist::federation::EmitAttestationInput;
use ciris_persist::prelude::{CallerScope, Engine, ReadEngine, TraceFilter, TraceSummary};

use crate::key_standing;

pub mod n_eff;

/// CEG `scores` attestation type — the shared constant, not a local copy.
use ciris_persist::federation::types::attestation_type::SCORES as ATTESTATION_TYPE_SCORES;

/// The capacity leaf this scorer emits. **Versioned** (`:v1`) to satisfy
/// persist's `DimensionAdmissionPolicy { require_version_segment: true }`. We
/// emit `sustained_coherence` — the CEG §5.5.4 **S** factor — because that is
/// the single capacity factor N_eff directly measures ("long-window N_eff +
/// manifold-conformity stability"). The other four factors (C / I_int / R /
/// I_inc) need signals this scorer does not yet derive; emitting only S is the
/// honest scope (the composite product would otherwise be fabricated).
const CAPACITY_DIMENSION: &str = "capacity:sustained_coherence:v1";

/// Periodic-scorer configuration. Cadence + window + gates are sourced from the
/// resolved `config:*` snapshot ([`crate::config_reconcile::ResolvedConfig`]) —
/// HOT: the scorer re-reads the live snapshot each cycle, so a `POST /v1/config`
/// retunes the next pass with no restart. See [`ScorerConfig::from_resolved`].
#[derive(Debug, Clone)]
pub struct ScorerConfig {
    /// How often the scorer runs.
    pub cadence: Duration,
    /// Max trace summaries pulled per agent per pass (the N_eff window cap —
    /// the `--n` cap in measure_n_eff.py).
    pub window: i64,
    /// LC-AV-18 sample-size gate. Below this effective N the cohort is not
    /// trustworthy for scoring; `capacity()` returns 0.
    pub sample_size_gate: u32,
    /// Saturation point — `n_eff >= target_n_eff` → capacity 1.0. A RATCHET
    /// calibration parameter; passed explicitly (calibration-bundle wiring is
    /// CIRISPersist#18, future).
    pub target_n_eff: f64,
}

impl Default for ScorerConfig {
    fn default() -> Self {
        ScorerConfig {
            // ONE source for this number. This used to be a second literal
            // (3600) beside `config_reconcile::DEFAULT_SCORER_CADENCE_SECS` —
            // two copies of one default, maintained separately, which is the
            // class that shipped ["capacity:"] against a harness passing
            // ["trace:","capacity:"] and cost a week. Reference it.
            cadence: Duration::from_secs(crate::config_reconcile::DEFAULT_SCORER_CADENCE_SECS),
            // The measure_n_eff.py default window cap.
            window: 500,
            // measure_n_eff.py refuses fewer than 20 surviving rows; mirror that
            // as the gate so a thin corpus reports 0 capacity rather than noise.
            sample_size_gate: 20,
            // A modest saturation target for an early federation. RATCHET owns
            // the real value; the band is linear in [gate, target].
            target_n_eff: 8.0,
        }
    }
}

impl ScorerConfig {
    /// Project the resolved `config:*` snapshot onto a [`ScorerConfig`] — the
    /// Server 0.5 Phase 2 source of the scorer knobs (the `CIRIS_SERVER_SCORER_*`
    /// env reads are deleted). The snapshot already validated each value against
    /// its baked default during [`crate::config_reconcile::resolve`].
    pub fn from_resolved(r: &crate::config_reconcile::ResolvedConfig) -> Self {
        let mut cfg = ScorerConfig {
            cadence: r.scorer_cadence(),
            window: r.scorer_window,
            sample_size_gate: r.scorer_sample_gate,
            target_n_eff: r.scorer_target_n_eff,
        };
        // TEST-ANCHOR-FENCED knob overrides (mesh-repro traceflow E2E,
        // CIRISServer#315 / CIRISAgent#924): a harness canonical has no owner
        // session to PUT config:v1 knobs, and the E2E must not wait out the
        // 3600s production cadence. Honored ONLY under CIRIS_TESTING_MODE —
        // the same fence as the announce-cadence override in compose.rs; a
        // production node never reads these.
        if std::env::var("CIRIS_TESTING_MODE").as_deref() == Ok("true") {
            if let Some(secs) = std::env::var("CIRIS_TEST_SCORER_CADENCE_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
            {
                cfg.cadence = std::time::Duration::from_secs(secs.max(1));
            }
            if let Some(gate) = std::env::var("CIRIS_TEST_SCORER_SAMPLE_GATE")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
            {
                cfg.sample_size_gate = gate;
            }
        }
        cfg
    }
}

/// Spawn the periodic capacity scorer onto the current Tokio runtime. Returns
/// the join handle; the task runs until the runtime drops it (the node's
/// lifetime). The first pass runs after one `cadence` tick (lets the corpus
/// accumulate traces post-boot).
///
/// **HOT config (Server 0.5 Phase 2):** `config_rx` is the live resolved-config
/// snapshot. Each cycle reads `*config_rx.borrow()` for the current
/// [`ScorerConfig`], so a `POST /v1/config` that retunes `scorer.*` applies on the
/// next pass with NO restart. The sleep period itself tracks the live
/// `scorer.cadence_secs`: we recompute the interval whenever the cadence changes.
pub fn spawn(
    engine: Arc<Engine>,
    mut config_rx: watch::Receiver<crate::config_reconcile::ResolvedConfig>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // ONE identity (#312/#315): the producer named INSIDE the capacity
        // envelope must be the same identity `emit_attestation_self` stamps as
        // the attester — the ENGINE signer's derived key, never a config alias
        // (in the embedded fold they differ, and an alias here would make the
        // envelope's producer disagree with the row's own attester).
        let node_key_id = match engine.local_derived_key_id().await {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "capacity scorer: cannot resolve the node identity — scorer NOT running"
                );
                return;
            }
        };
        // ── RUNTIME-TOPOLOGY PROBE (#315 field diagnosis) ────────────────────
        // On-device the tick loop never fired while the config-watch branch
        // stayed alive — the signature of a task whose TIMER wakeups are dead
        // (future deadlines need a driven time driver; watch wakeups and
        // already-elapsed deadlines do not). Make the topology and timer
        // health OBVIOUS in one glance: name the thread + runtime flavor this
        // task actually landed on, then prove (or disprove) its timer with a
        // 2s heartbeat BEFORE entering the loop. If the spawn line appears but
        // the heartbeat never does, this task's runtime cannot deliver future
        // timer deadlines — case closed, no theorizing.
        let flavor = format!("{:?}", tokio::runtime::Handle::current().runtime_flavor());
        tracing::info!(
            thread = %std::thread::current().name().unwrap_or("<unnamed>"),
            thread_id = ?std::thread::current().id(),
            runtime_flavor = %flavor,
            "capacity scorer task STARTED — timer heartbeat (2s) next; if no \
             heartbeat line follows, THIS runtime's time driver is not delivering"
        );
        let hb = std::time::Instant::now();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        tracing::info!(
            elapsed_ms = hb.elapsed().as_millis() as u64,
            "capacity scorer timer heartbeat OK — time driver delivers on this \
             runtime; tick loop is live"
        );
        // Track the cadence so we can rebuild the interval when it changes HOT.
        let mut cadence = ScorerConfig::from_resolved(&config_rx.borrow()).cadence;
        let mut tick = tokio::time::interval(cadence);
        // The first immediate tick fires at once; skip it so we don't score an
        // empty just-booted corpus.
        tick.tick().await;
        loop {
            // CIRISServer#315 ask 2: select on the CONFIG WATCH as well as the
            // tick, so a hot knob write re-arms the timer IMMEDIATELY instead of
            // waiting out an in-flight full-cadence sleep (under the 3600s
            // default, a mobile session ended long before a knob change was even
            // noticed).
            tokio::select! {
                _ = tick.tick() => {
                    // Every tick is AUDIBLE (#315: never a silent zero) — this
                    // line firing at the configured cadence is the proof the
                    // timer path works end-to-end on this deployment.
                    tracing::info!(
                        cadence_secs = cadence.as_secs(),
                        "capacity scorer TICK — running pass"
                    );
                    // Read the LIVE snapshot per cycle — cadence/window/gate/target.
                    let cfg = ScorerConfig::from_resolved(&config_rx.borrow());
                    if cfg.cadence != cadence {
                        cadence = cfg.cadence;
                        tick = tokio::time::interval(cadence);
                        tick.tick().await;
                        tracing::info!(
                            cadence_secs = cadence.as_secs(),
                            "capacity scorer cadence retuned from config:* (hot)"
                        );
                    }
                    if let Err(e) = run_pass(&engine, &node_key_id, &cfg).await {
                        tracing::warn!(
                            error = %e,
                            "capacity scorer pass failed (will retry next cadence)"
                        );
                    }
                }
                changed = config_rx.changed() => {
                    if changed.is_err() {
                        // Config sender dropped — the serve stack is tearing down.
                        break;
                    }
                    let cfg = ScorerConfig::from_resolved(&config_rx.borrow());
                    if cfg.cadence != cadence {
                        cadence = cfg.cadence;
                        tick = tokio::time::interval(cadence);
                        // Consume the interval's immediate first tick: the NEXT
                        // pass runs one (new) cadence from NOW — so shortening
                        // 3600s -> 30s takes effect in 30s, not in the remainder
                        // of the old hour.
                        tick.tick().await;
                        tracing::info!(
                            cadence_secs = cadence.as_secs(),
                            "capacity scorer cadence retuned from config:* (hot, mid-sleep re-arm)"
                        );
                    }
                }
            }
        }
    })
}

/// Run one full scoring pass over every agent with traces in the corpus.
/// Public so the integration test can drive a single deterministic pass without
/// waiting on the timer. Returns the number of `capacity:*` attestations emitted.
pub async fn run_pass(engine: &Engine, node_key_id: &str, cfg: &ScorerConfig) -> Result<usize> {
    let backend = engine
        .sqlite_backend()
        .context("capacity scorer requires a SQLite-backed Engine")?
        .clone();

    // Enumerate the agents present in the corpus by their agent_id_hash (the
    // AV-9 per-agent key on every trace summary). We page the unfiltered trace
    // window once and group — the read surface has no distinct-agent primitive.
    let page = backend
        .list_trace_summaries(
            TraceFilter::default(),
            None,
            cfg.window,
            CallerScope::Unauthenticated,
        )
        .await
        .map_err(|e| anyhow::anyhow!("list trace summaries: {e}"))?;

    // Group summaries by agent_id_hash → that agent's feature rows.
    let mut by_agent: std::collections::BTreeMap<String, Vec<&TraceSummary>> =
        std::collections::BTreeMap::new();
    for s in &page.items {
        by_agent.entry(s.agent_id_hash.clone()).or_default().push(s);
    }

    let n_summaries = page.items.len();
    let n_agents = by_agent.len();
    let mut empty_matrix_agents = 0usize;
    let mut unchanged_agents = 0usize;
    let mut not_consented_agents = 0usize;
    // CIRISServer#351 — counted SEPARATELY from `not_consented_agents`, and
    // deliberately absent from `accounted` below: an unreadable consent fold
    // must never help a zero-emission pass read as a healthy steady state.
    let mut consent_unreadable_agents = 0usize;
    // CIRISServer#374 — the same rule one plane over. A capacity-history read
    // that FAILED is not "nothing stands", so it may not help a zero-emission
    // pass read as a healthy steady state either.
    let mut standing_unreadable_agents = 0usize;
    let mut unregistered_agents = 0usize;
    let mut emitted = 0usize;
    for (agent_id_hash, traces) in by_agent {
        // Attest ABOUT the agent's REGISTERED federation key_id (persist v20.1.0 /
        // CIRISPersist#498): `TraceSummary.agent_key_id` is the `signing_key_id`
        // resolved from `federation_keys` at verify time, so it is guaranteed to
        // satisfy `federation_attestations.attested_key_id`'s FK AND to differ
        // from the scorer's own key (anti-Goodhart). The AV-9 `agent_id_hash` was
        // NEVER an FK-resolvable identity — attesting about it FK-failed on every
        // real fold DB. When `agent_key_id` is absent (an unverified/legacy trace
        // with no resolvable emitter identity) we CANNOT attest — skip LOUDLY
        // rather than silently (no-silent-caps): a swallowed skip is exactly how
        // the whole plane read as green while emitting nothing.
        let Some(attested_key_id) = traces.iter().find_map(|t| t.agent_key_id.clone()) else {
            unregistered_agents += 1;
            tracing::warn!(
                agent_id_hash = %agent_id_hash,
                n_traces = traces.len(),
                "capacity scorer: no registered agent_key_id on these traces (unverified/legacy \
                 emitter) — cannot attest capacity about an unregistered subject; skipping"
            );
            continue;
        };

        match score_and_emit(engine, node_key_id, &attested_key_id, &traces, cfg).await {
            Ok(ScoreOutcome::Emitted) => emitted += 1,
            // Unchanged is the STEADY STATE on a healthy node, not a problem.
            // Counted separately so the pass line distinguishes "nothing to say"
            // from "nothing to say it with".
            // Declining to be scored is a permanent, legitimate choice. Count
            // it; do not alarm on it.
            Ok(ScoreOutcome::NotConsented { stance }) => {
                not_consented_agents += 1;
                tracing::debug!(
                    agent = %attested_key_id,
                    ?stance,
                    "capacity scorer: no live CC#46 `analyze` consent from this subject — \
                     skipping (an allowed choice, not a fault)"
                );
            }
            // The subject's answer could not be READ (CIRISServer#351). Not the
            // arm above: that one is the gate working. This one is the gate
            // blind, and CC 3.4.5 makes `capacity:*` the only family whose
            // admission turns on a consent read at all — so a failed read stops
            // the whole family. Per-agent at DEBUG (the 24,500-lines-a-day
            // lesson), aggregated into the pass line at WARN.
            Ok(ScoreOutcome::ConsentUnreadable { error }) => {
                consent_unreadable_agents += 1;
                tracing::debug!(
                    agent = %attested_key_id,
                    %error,
                    "capacity scorer: the CC#46 `analyze` consent fold FAILED TO READ for this \
                     subject — this is NOT a decline; see the pass line"
                );
            }
            // The capacity history could not be READ (CIRISServer#374). Not the
            // `Unchanged` arm below — that one is the coalescing working, this
            // one is the coalescing BLIND. Held out of `accounted` for the same
            // reason as the arm above: the pass authored nothing because it
            // could not tell whether it needed to, which is not a state this
            // node is allowed to sit in quietly.
            Ok(ScoreOutcome::StandingUnreadable { error }) => {
                standing_unreadable_agents += 1;
                tracing::debug!(
                    agent = %attested_key_id,
                    %error,
                    "capacity scorer: the standing-rows read FAILED for this subject — this is \
                     NOT \"nothing stands\"; nothing was authored because we cannot tell whether \
                     we already did; see the pass line"
                );
            }
            Ok(ScoreOutcome::Unchanged {
                standing_since,
                bucket_secs,
            }) => {
                unchanged_agents += 1;
                tracing::debug!(
                    agent = %attested_key_id,
                    %standing_since,
                    bucket_secs,
                    "capacity scorer: score unchanged and already standing — not re-authoring"
                );
            }
            Ok(ScoreOutcome::NoFeatureRows) => {
                // Scored-but-not-emitted: the agent had trace summaries but NO
                // usable feature rows (feature_matrix empty). Visible per-agent so
                // the window/feature-extraction semantics are never a silent zero.
                empty_matrix_agents += 1;
                // Under CIRIS_TESTING_MODE the per-agent skip is promoted to
                // INFO so harness E2Es (mesh-repro traceflow) see WHY an agent
                // was skipped without RUST_LOG=debug on the whole crate.
                if std::env::var("CIRIS_TESTING_MODE").as_deref() == Ok("true") {
                    tracing::info!(
                        agent = %attested_key_id,
                        n_traces = traces.len(),
                        "capacity scorer: agent scored zero usable feature rows (skipped) [testing-mode verbose]"
                    );
                } else {
                    tracing::debug!(
                        agent = %attested_key_id,
                        n_traces = traces.len(),
                        "capacity scorer: agent scored zero usable feature rows (skipped)"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    agent = %attested_key_id,
                    error = %e,
                    "capacity scoring failed for agent (skipping)",
                );
            }
        }
    }
    // The one line that decides the two field readings (CIRISServer#315):
    //   n_summaries=0            → no traces in the window the scorer reads.
    //   n_summaries>0, emitted=0 → traces present but every agent's feature
    //                              matrix was empty (window/feature semantics).
    //   emitted>0                → capacity rows authored → replication ships them.
    if emitted == 0 {
        // A ZERO MUST NAME ITS OWN CAUSE.
        //
        // The previous version reported `n_summaries=0` and left the reader to
        // guess which of three narrowings produced it. On the production
        // canonical that cost a night: 56 trace_events sat in the corpus, all
        // `cohort_scope=federation`, grouping cleanly into 4 trace_ids when the
        // scorer's own query was run by hand — and the scorer logged
        // `n_summaries=0` on every pass. Scope, projection and filter were each
        // excluded by measurement, one at a time, from the outside.
        //
        // So the zero path now probes the plane BELOW its own read and reports
        // the narrowing, turning "no traces in scope" from a conclusion into a
        // measurement. The three states are distinguishable at a glance:
        //
        //   raw_trace_events == 0            → nothing arrived. Delivery problem,
        //                                      upstream of the scorer entirely.
        //   raw > 0, n_summaries == 0        → THE READ IS NARROWING. Rows are in
        //                                      the corpus and the summary read
        //                                      cannot see them — scope gate,
        //                                      filter, or backend handle.
        //   n_summaries > 0, emitted == 0    → feature semantics (empty matrices,
        //                                      the sample gate, or CC#46 consent).
        //
        // This is the same inversion asked of the substrate in CIRISEdge#433 and
        // CIRISPersist#565: an absence is an event, and the instrument that
        // reports it must say which branch produced it.
        let raw_trace_events = backend
            .list_trace_summaries(
                TraceFilter::default(),
                None,
                cfg.window,
                CallerScope::Unauthenticated,
            )
            .await
            .map(|p| p.items.len())
            .unwrap_or(usize::MAX);
        let narrowing = if consent_unreadable_agents > 0 {
            // FIRST, ahead of every corpus narrowing below: the traces arrived
            // and were read fine; what failed is the CC#46 gate's own input.
            // Reporting this as "feature semantics" would send the reader to the
            // trace plane for a fault in the consent plane (CIRISServer#351).
            "THE CONSENT FOLD FAILED TO READ — this is NOT a subject declining. CC 3.4.5              makes `capacity:*` the one family gated on a consent read, so a failed read stops              the family. Check the federation directory backend handle, then                `resolve_scoped_consent` for the (attester, subject, `analyze`) triple"
        } else if standing_unreadable_agents > 0 {
            // Also ahead of the corpus narrowings, and for the same reason: the
            // traces arrived and were read fine. What failed is the read of what
            // this node has ALREADY said (CIRISServer#374).
            "THE STANDING-ROWS READ FAILED — this is NOT \"nothing stands\". The scorer suppresses              rather than author a row whose signed `asserted_at` would be derived from the read              that just failed. Check `list_attestations` (capacity:* about the subject) and              `revocations_for` on the attesting keys"
        } else if raw_trace_events == usize::MAX {
            "read FAILED — the summary read itself errored; the scorer cannot see the corpus"
        } else if raw_trace_events == 0 {
            "nothing arrived — the corpus has no traces this scorer can read (delivery, not scoring)"
        } else if n_summaries == 0 {
            "THE READ IS NARROWING — rows exist in the corpus but this pass saw none.              Compare the scope gate (Unauthenticated admits affiliations/species/biosphere/             federation), the filter, and whether this backend handle is the one replication              writes through"
        } else {
            "feature semantics — summaries present but no capacity authored (empty matrices,              the sample gate, or CC#46 analyze consent)"
        };
        // Coalescing changed what a zero MEANS, and this instrument predates it.
        //
        // Before 0.5.152 every pass authored a row, so `emitted == 0` could only
        // be a fault and the WARN above was right to shout. Now the steady state
        // on a perfectly healthy node is zero emissions — every score already
        // stands, asserted within its bucket, and there is nothing new to say.
        // Left alone this would WARN "feature semantics" once a minute forever,
        // and an operator would correctly learn to ignore it. An alarm that
        // fires on the happy path trains people to miss the real one.
        //
        // So account for the agents first: if every agent this pass is either
        // already-standing, feature-less, or unregistered, the zero is EXPLAINED
        // and it is not a fault.
        //
        // `consent_unreadable_agents` is NOT in this sum, and that omission is
        // the fix (CIRISServer#351). An outcome only accounts for a zero if it
        // is a state the system is legitimately allowed to be in; a consent fold
        // that cannot be read is not one, so it can never make a zero look
        // healthy. Before the split it did exactly that twice over — it counted
        // as `not_consented_agents`, which both entered this sum AND satisfies
        // the `|| not_consented_agents > 0` trigger, so a total failure of the
        // consent read logged INFO "steady state, not a fault" for every agent
        // in the corpus.
        //
        // `standing_unreadable_agents` is out of the sum for the identical
        // reason (CIRISServer#374), and its collapse was the same one aimed at
        // the OTHER trigger: an unreadable capacity-history read used to look
        // like "nothing stands", so the scorer re-authored — and once the row
        // landed, the next pass counted it as `unchanged_agents`, which is the
        // first of the two `|| ` triggers here. A blind coalescer therefore
        // wrote a row a minute AND reported itself as the steady state.
        let accounted =
            unchanged_agents + not_consented_agents + empty_matrix_agents + unregistered_agents;
        if consent_unreadable_agents > 0 {
            // Its own line, ahead of the generic zero WARN, because the MESSAGE
            // is what an operator reads: "the agents do not account for it" sends
            // them to the trace plane, and the trace plane is fine — the traces
            // arrived, the read saw them, and the CC#46 gate's own input is what
            // went missing. The `narrowing` field says the same thing; a fact
            // that only exists in a structured field is a fact most readers of a
            // log line do not have.
            tracing::warn!(
                n_summaries,
                n_agents,
                unchanged_agents,
                not_consented_agents,
                consent_unreadable_agents,
                standing_unreadable_agents,
                empty_matrix_agents,
                unregistered_agents,
                window = cfg.window,
                raw_trace_events,
                narrowing,
                "capacity scorer pass emitted ZERO because the CC#46 `analyze` consent fold \
                 FAILED TO READ — these subjects did NOT decline, their answer is unreadable, \
                 and capacity:* is the one family CC 3.4.5 gates on that read"
            );
        } else if standing_unreadable_agents > 0 {
            // Its own line, ahead of the quiet branch, for the CIRISServer#351
            // reason applied to CIRISServer#374's plane: the generic zero WARN
            // sends the reader to the trace plane, and the trace plane is fine.
            // What failed is the read of what this node has ALREADY said.
            tracing::warn!(
                n_summaries,
                n_agents,
                unchanged_agents,
                not_consented_agents,
                consent_unreadable_agents,
                standing_unreadable_agents,
                empty_matrix_agents,
                unregistered_agents,
                window = cfg.window,
                raw_trace_events,
                narrowing,
                "capacity scorer pass emitted ZERO because the STANDING-ROWS READ FAILED — this \
                 is NOT \"nothing stands\"; the scorer cannot tell whether it has already \
                 authored these scores, so it authored none"
            );
        } else if (unchanged_agents > 0 || not_consented_agents > 0) && accounted >= n_agents {
            tracing::info!(
                n_summaries,
                n_agents,
                unchanged_agents,
                not_consented_agents,
                consent_unreadable_agents,
                standing_unreadable_agents,
                empty_matrix_agents,
                unregistered_agents,
                "capacity scorer pass authored nothing — every score already stands within its \
                 coalescing bucket (steady state, not a fault)"
            );
        } else {
            tracing::warn!(
                n_summaries,
                n_agents,
                unchanged_agents,
                not_consented_agents,
                consent_unreadable_agents,
                standing_unreadable_agents,
                empty_matrix_agents,
                unregistered_agents,
                window = cfg.window,
                raw_trace_events,
                sample_size_gate = cfg.sample_size_gate,
                narrowing,
                "capacity scorer pass emitted ZERO and the agents do not account for it — see \
                 `narrowing` for which plane stopped it"
            );
        }
    } else if consent_unreadable_agents > 0 {
        // A PARTIAL consent-fold failure is still a failure (CIRISServer#351).
        // `emitted > 0` says some subjects' answers were readable; it says
        // nothing about the ones whose were not, and folding those into the
        // "pass complete" INFO is how a gate degrades silently — the majority
        // path stays green while the gate goes blind for a subset.
        tracing::warn!(
            n_summaries,
            n_agents,
            emitted,
            unchanged_agents,
            not_consented_agents,
            consent_unreadable_agents,
            standing_unreadable_agents,
            unregistered_agents,
            "capacity scorer pass authored rows BUT the CC#46 `analyze` consent fold failed to \
             read for some subjects — those are NOT declines and were not scored"
        );
    } else if standing_unreadable_agents > 0 {
        // A PARTIAL standing-read failure is still a failure, same as above.
        // `emitted > 0` says the capacity history was readable for SOME
        // subjects; the ones it was not readable for were skipped, and folding
        // them into the "pass complete" INFO is how a coalescer goes blind for a
        // subset while the majority path stays green (CIRISServer#374).
        tracing::warn!(
            n_summaries,
            n_agents,
            emitted,
            unchanged_agents,
            not_consented_agents,
            consent_unreadable_agents,
            standing_unreadable_agents,
            unregistered_agents,
            "capacity scorer pass authored rows BUT the standing-rows read failed for some \
             subjects — that is NOT \"nothing stands\", and those subjects were not scored"
        );
    } else {
        tracing::info!(
            n_summaries,
            n_agents,
            emitted,
            unchanged_agents,
            not_consented_agents,
            consent_unreadable_agents,
            standing_unreadable_agents,
            unregistered_agents,
            "capacity scorer pass complete (capacity attestations authored → replication)"
        );
    }
    Ok(emitted)
}

// ── Re-assertion coalescing (CIRISPersist#519 item 2a-iii) ──────────────────

/// The base bucket the assertion instant is floored to — the **hourly floor**.
///
/// # Why a bucket at all
///
/// The scorer runs every [`config_reconcile::DEFAULT_SCORER_CADENCE_SECS`] (60s)
/// so a CHANGED score is visible within a minute. That is a detection property
/// and it is worth keeping. But 0.5.151 authored a new signed row on every pass:
/// 12 rows, 12 attestation_ids, 12 distinct content hashes in 12 minutes, all
/// asserting `score 0.0, sample_size 3` — identical measurements differing only
/// in `asserted_at`, which is inside the signed envelope. Against a 7-day
/// `valid_until` that is ~10,000 simultaneously-live rows per agent per
/// dimension, all saying the same thing.
///
/// Persist named the cure and we had not adopted it. `freshness.rs`:
///
/// > a producer SHOULD round `fresh_as_of` to a bucket boundary before emitting,
/// > so repeated touches within the same bucket dedupe on the wire (identical
/// > `fresh_as_of` ⇒ identical signed envelope ⇒ identical content hash)
///
/// Flooring the instant makes repeated identical measurements produce
/// byte-identical envelopes, which is what makes them recognisable as the same
/// assertion rather than a stream of new ones.
const SCORE_COALESCE_BASE: i64 = 3600;

/// The widest the bucket may attenuate to for a score that will not move.
///
/// Bounded by the validity window, not by taste: at 24h against a 7-day
/// `valid_until` a live score is re-asserted seven times before it could expire.
/// A bucket approaching the window would let a still-true score age out silently,
/// and "stopped being true" and "stopped being measured" would become the same
/// observation — the confirmed-vs-unverified ambiguity this codebase keeps
/// paying for.
const SCORE_COALESCE_MAX: i64 = 86_400;

/// Attenuate the bucket by how long this exact score has already held.
///
/// Stateless BY CONSTRUCTION — derived from the stored rows, never from a cache.
/// A process restart, a replica, and a backfill all compute the same width from
/// the same corpus, so there is no local state to diverge from the graph. (A
/// cached "last emitted" would be a second source of truth for a question the
/// rows already answer.)
///
/// Widening is safe in the direction it moves: `merge_floor` is a monotonic max,
/// so a coarser floor can never roll an assertion backwards.
fn coalesce_bucket(unchanged_for: chrono::Duration) -> chrono::Duration {
    let secs = match unchanged_for.num_hours() {
        h if h >= 24 => SCORE_COALESCE_MAX,
        h if h >= 6 => 6 * SCORE_COALESCE_BASE,
        _ => SCORE_COALESCE_BASE,
    };
    chrono::Duration::seconds(secs)
}

/// Page size for the capacity-plane read. Bounds the scan; the working set for
/// one subject's capacity history is far smaller.
const CAPACITY_READ_LIMIT: i64 = 512;

/// This subject's live `capacity:*` rows, filtered IN THE QUERY.
///
/// # Why (CIRISServer#343)
///
/// `standing_assertion` and `unchanged_for` were each doing
/// `list_attestations_for(subject)` — every attestation about that subject —
/// and then filtering by dimension in Rust. Two full scans per agent per
/// 60-second pass. On a canonical with twenty agents that is forty scans a
/// minute, growing with every row anyone ever writes about anyone.
///
/// I added both of those helpers one cut before writing this, while fixing a
/// different unbounded-growth defect. The measured instance was elsewhere
/// (`graph_config`, 9,824 rows scanned fifteen times to read twelve values,
/// a 152-second boot phase) — but the shape was the same, and the reason it
/// went unnoticed in review is that `list_attestations_for(x)` reads as a
/// narrow query. It is not; the narrowing is the caller's `.filter()`.
///
/// # `revoked_after` (CIRISServer#355 / CIRISPersist#570 ask 4)
///
/// A row whose attester's statements are revoked from an instant covering it
/// does not count as live here, and the reason is a live attack rather than
/// tidiness. Everything downstream of this read is a SUPPRESSION decision: if
/// the corpus already carries this score in this bucket, the scorer authors
/// nothing ([`ScoreOutcome::Unchanged`]), and [`unchanged_for`] widens the
/// coalescing bucket the longer the score has apparently held. So a single
/// forged `capacity:*` row from a compromised key can silence honest scoring
/// of that subject for a day — no error, no warning, a perfectly healthy-
/// looking "unchanged". Honouring the bound is what makes the forged row stop
/// counting while the key's pre-compromise measurements keep doing so.
///
/// A revocation read that fails must never return the rows unfiltered — that
/// is the direction the attack above needs. It returns `Err`, which suppresses;
/// see [`StandingRows`] for why suppressing is safe on BOTH axes and an empty
/// set was safe on only one.
///
/// `Err` carries the backend's own message and means **the read failed**. It is
/// deliberately outside [`StandingRows`] rather than a fourth variant of it, for
/// the reason spelled out on that type.
async fn live_capacity_rows(
    engine: &Engine,
    attested_key_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<StandingRows, String> {
    use ciris_persist::ceg::list::federation::AttestationFilter;

    let mut filter = AttestationFilter::default();
    filter.attested_key_id = Some(attested_key_id.to_owned());
    filter.attestation_type = Some(ATTESTATION_TYPE_SCORES.to_owned());
    // Prefix derived from the dimension constant, never a second literal.
    filter.dimension_prefixes = vec![CAPACITY_DIMENSION
        .split_once(':')
        .map(|(fam, _)| format!("{fam}:"))
        .unwrap_or_else(|| CAPACITY_DIMENSION.to_owned())];

    let page = match engine
        .list_attestations(
            filter,
            None,
            CAPACITY_READ_LIMIT,
            ciris_persist::prelude::CallerScope::Unauthenticated,
        )
        .await
    {
        Ok(page) => page,
        Err(e) => return Err(format!("list_attestations(capacity): {e}")),
    };
    // How many rows the corpus holds ABOUT this subject in this family, before
    // any liveness filter. This is the number that separates "this subject has
    // never been scored" from "rows exist and none of them stand".
    let read = page.items.len();
    let rows: Vec<ciris_persist::federation::Attestation> = page
        .items
        .into_iter()
        .filter(|a| {
            ciris_persist::federation::admission::envelope_dimension(&a.attestation_envelope)
                .is_some_and(|d| d == CAPACITY_DIMENSION)
        })
        .filter(|a| a.expires_at.is_none_or(|exp| exp > now))
        .collect();

    // `revoked_after` — one `revocations_for` per DISTINCT attester in the
    // page (in the steady state that is one key, this node's), never per row.
    let held =
        match key_standing::HeldRevocations::for_keys(engine, key_standing::attesting_keys(&rows))
            .await
        {
            Ok(held) => held,
            Err(e) => return Err(format!("revocations_for(attesters): {e}")),
        };
    let live: Vec<ciris_persist::federation::Attestation> = if held.is_empty() {
        rows
    } else {
        rows.into_iter()
            .filter(|a| {
                let fold = held.statement_standing(a, now);
                if fold.standing.is_suspect() {
                    key_standing::warn_suspect("scorer", a, &fold);
                    return false;
                }
                true
            })
            .collect()
    };

    // THREE ZEROES — every one of them a real answer, because the absence of an
    // answer left through `Err` above and cannot arrive here.
    Ok(if !live.is_empty() {
        StandingRows::Standing(live)
    } else if read == 0 {
        StandingRows::NeverScored
    } else {
        StandingRows::NoneStanding { read }
    })
}

/// What the standing-rows read actually returned — **the three zeroes kept
/// apart** (CIRISServer#374).
///
/// This was `Vec<Attestation>`, and every failure inside
/// [`live_capacity_rows`] returned `Vec::new()`. So "the standing-rows read
/// FAILED" was reported to both callers as "nothing stands", which is the same
/// swallow CIRISServer#351 fixed one function down in this module: a failed
/// read wearing the costume of a real answer.
///
/// # Why an empty vec was not harmless
///
/// Both callers turn this read into a WRITE decision, and both degrade in the
/// same direction:
///
/// - [`standing_assertion`] reads "nothing stands", so the scorer re-authors a
///   row it may already have written — defeating the coalescing that took
///   production capacity rows from ~900/day to 21. Nothing downstream catches
///   it: `attestation_emit::assemble_and_put` stamps a fresh
///   `uuid::Uuid::new_v4()` on every emit, so persist has no content-level
///   dedupe and THIS suppression is the only thing standing between a failed
///   read and a new permanent row. Measured, not assumed: with the read broken
///   and the arm folded back to fail-open, the corpus went 1 → 2 rows on a pass
///   whose score had not moved at all.
/// - [`unchanged_for`] reads a zero-length run, so [`coalesce_bucket`] hands
///   back the BASE (hourly) bucket instead of the attenuated one. A score that
///   has held for a day is bucketed at 24h, so the fallback both narrows the
///   bucket — up to 24 authorings a day per subject rather than one — and puts
///   a DIFFERENT floored `asserted_at` inside the signed envelope than the row
///   already standing carries. The failure does not merely lose a suppression,
///   it re-creates the growth the suppression exists to stop.
///
/// # The zeroes
///
/// - [`Standing`](StandingRows::Standing) — rows stand. Never empty.
/// - [`NoneStanding`](StandingRows::NoneStanding) — the corpus holds
///   `capacity:*` rows about this subject and NONE of them are live: expired,
///   or their attester's statements revoked over them. A real, informative
///   zero — it is exactly what the CIRISServer#355 revocation filter is FOR.
/// - [`NeverScored`](StandingRows::NeverScored) — the corpus holds no
///   `capacity:*` row about this subject at all. A cold subject; the first pass
///   of every agent's life sees this.
///
/// `NoneStanding` and `NeverScored` both proceed to author, and deliberately:
/// they are the same DECISION reached from different facts, and collapsing them
/// would leave the log unable to say whether a re-emission followed a
/// revocation or a cold start. That is the distinction the previous shape
/// destroyed for all three at once.
///
/// # Why "unreadable" is NOT a variant here
///
/// It is the `Err` of [`live_capacity_rows`], because a failed read is not a
/// fourth kind of answer — it is the absence of one, and that is exactly the
/// distinction this type exists to hold. The module already answers this
/// question this way one gate up: `resolve_scoped_consent` returns
/// `Result<ConsentState, _>`, and `score_and_emit` splits it three ways with
/// the unreadable case in `Err`. Two shapes for one question is how the axes get
/// fused in the first place.
///
/// It is also the difference between a defect that is *detectable* and one that
/// is *unrepresentable*. An earlier draft of this fix made `Unreadable` a fourth
/// variant whose `rows()` returned `&[]`, with a doc comment claiming "the type
/// is what enforces it: a caller who ignores the arm cannot reach the rows
/// without saying so." That claim was false. Dropping the early return compiled
/// silently, `standing.rows()` handed back `&[]`, and the function walked
/// straight back into the original bug — a failed read reported as "nothing
/// stands" — with every test still green. With the failure in `Err`, there is no
/// `StandingRows` value to call `rows()` on until the error has been discharged,
/// so the silent form of that regression no longer compiles.
#[derive(Debug)]
enum StandingRows {
    /// Live `capacity:*` rows about this subject. Non-empty by construction.
    Standing(Vec<ciris_persist::federation::Attestation>),
    /// Rows exist about this subject; none are live. `read` is how many were
    /// seen before the liveness filters, so the log can say how many stopped.
    NoneStanding { read: usize },
    /// No `capacity:*` row about this subject exists at all.
    NeverScored,
}

impl StandingRows {
    /// The live rows, as a slice — empty for both real zeroes.
    ///
    /// Every value of this type is an answer, so an empty slice here always
    /// means "nothing stands" and never "we could not tell". That is a property
    /// of the type, not of the caller's discipline: see the note on the type
    /// about why the unreadable case is `Err` rather than a variant.
    fn rows(&self) -> &[ciris_persist::federation::Attestation] {
        match self {
            Self::Standing(rows) => rows,
            _ => &[],
        }
    }

    /// For [`NoneStanding`](StandingRows::NoneStanding) only: how many rows
    /// existed about this subject and STOPPED counting (expired, or their
    /// attester's statements revoked over them).
    ///
    /// `None` on every other arm rather than `0`. This number is a fact about
    /// that one zero; handing the other arms a count would put two questions
    /// ("how many rows are live?" / "how many rows stopped?") on one name, which
    /// is the class of defect this whole type exists to undo.
    fn stopped(&self) -> Option<usize> {
        match self {
            Self::NoneStanding { read } => Some(*read),
            _ => None,
        }
    }

    /// The one-word fact for a log line: which of the three answers this was.
    fn kind(&self) -> &'static str {
        match self {
            Self::Standing(_) => "standing",
            Self::NoneStanding { .. } => "none_standing",
            Self::NeverScored => "never_scored",
        }
    }
}

/// The already-standing assertion for `(subject, capacity dimension)`, if the
/// corpus already says exactly this.
///
/// Returns `Some(prev_asserted_at)` when a live row already carries this score
/// with an assertion instant at or after `bucket_start` — i.e. we have already
/// said this, in this bucket, and saying it again would add a signed row
/// carrying no new information.
///
/// Compares the row's OWN stored `asserted_at` and `weight` rather than
/// recomputing persist's canonical hash. Reproducing the canonicalization here
/// would be a second implementation of persist's content-addressing, and a
/// divergence would fail SILENTLY — the check would simply never match and the
/// duplication would return, green. The stored fields cannot drift from
/// themselves.
///
/// A PURE fold over rows the caller has already read and already decided about
/// (CIRISServer#374). It used to issue its own [`live_capacity_rows`] call, as
/// did [`unchanged_for`] — so one pass read the same subject's capacity history
/// twice, at two instants, and derived the coalescing bucket from one corpus and
/// the standing check from the other. Reading once removes both the second scan
/// and that skew, and it is what lets the ONE read failure be handled in ONE
/// place instead of being swallowed identically in two.
fn standing_assertion(
    rows: &[ciris_persist::federation::Attestation],
    score: f64,
    bucket_start: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    rows.iter()
        // Same measurement: the band we would author, already authored.
        .filter(|a| a.weight.is_some_and(|w| (w - score).abs() < f64::EPSILON))
        .map(|a| a.asserted_at)
        .filter(|t| *t >= bucket_start)
        .max()
}

/// How long this score has held unbroken, for [`coalesce_bucket`].
///
/// The span from the OLDEST live row still carrying this score to now. A score
/// that just changed has no such run and gets the base bucket, so a moving score
/// is never coarsened — attenuation only ever slows down the restatement of
/// something that is not moving.
///
/// Pure, for the reasons on [`standing_assertion`]. Note what the zero return
/// means here and why it must never be reachable from a failed read: zero run
/// ⇒ base bucket ⇒ a floored `asserted_at` that differs from the standing row's
/// ⇒ a different content hash ⇒ a genuinely new signed row. "I could not read
/// the history" and "the score just changed" produce the same number and
/// opposite truths.
fn unchanged_for(
    rows: &[ciris_persist::federation::Attestation],
    score: f64,
    now: chrono::DateTime<chrono::Utc>,
) -> chrono::Duration {
    rows.iter()
        .filter(|a| a.weight.is_some_and(|w| (w - score).abs() < f64::EPSILON))
        .map(|a| a.asserted_at)
        .min()
        .map(|oldest| now - oldest)
        .unwrap_or_else(chrono::Duration::zero)
}

/// How long a capacity assertion stays live once made.
const SCORE_VALIDITY_DAYS: i64 = 7;

/// The `(asserted_at, valid_until)` pair one emission should carry.
///
/// Extracted so the CALL SITE is testable, not just persist's pure function
/// underneath it. The first version of these tests asserted that
/// `coalesce_touch_ts` floors — which was never in doubt — and a mutation adding
/// `+ bucket` at the call site sailed through every one of them. A test that
/// exercises the dependency instead of the code under test is the same shape as
/// a harness supplying the value production defaults.
///
/// Both instants derive from the COALESCED one. Deriving `valid_until` from raw
/// `now` would leave it varying every pass, the envelope would differ anyway,
/// and the coalescing would be real and entirely ineffective.
fn coalesced_assertion(
    now: chrono::DateTime<chrono::Utc>,
    bucket: chrono::Duration,
) -> (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) {
    let asserted_at = ciris_persist::federation::freshness::coalesce_touch_ts(now, bucket);
    (
        asserted_at,
        asserted_at + chrono::Duration::days(SCORE_VALIDITY_DAYS),
    )
}

/// What one agent's scoring pass actually did.
///
/// This was a `bool`, and coalescing gave the `false` arm a SECOND meaning:
/// "no usable feature rows" and "unchanged, deliberately not re-authored" are
/// opposite conditions — one is a gap in the data, the other is the system
/// working — and they were about to share a return value, a counter, and a log
/// line reading "agent scored zero usable feature rows". On a healthy node with
/// stable scores that line would have been printed for every agent, every pass.
///
/// One name answering two questions is the defect class this codebase has paid
/// for repeatedly (`root` meaning both signing holder and trust root;
/// `carries_infra_serve` asking about one scope of four). Naming the outcomes
/// costs one enum.
#[derive(Debug)]
enum ScoreOutcome {
    /// A new capacity row was authored.
    Emitted,
    /// The agent had trace summaries but no usable feature rows — a real gap in
    /// the corpus, worth surfacing per-agent.
    NoFeatureRows,
    /// The subject has not granted this attester the `analyze` scope, so
    /// CIRISConstitution#46 forbids a `capacity:*` claim about them.
    ///
    /// A PERMANENT, LEGITIMATE state — declining to be scored is an allowed
    /// choice, not a fault — and therefore never an error. It was one: persist
    /// refused at `put_attestation` and the refusal surfaced as `Err`, so every
    /// unconsented agent produced a WARN on every pass. Measured on the
    /// production canonical: 17 of 20 agents, 51 WARN lines every three minutes,
    /// roughly 24,500 a day, none of them actionable. An alarm that fires on a
    /// legitimate steady state trains people to ignore the log.
    ///
    /// Carries the stance persist's fold actually returned, so the log can name
    /// WHICH refusal it was: a subject who never spoke (`Unspecified`), one who
    /// spoke and withdrew (`Revoked`), and one whose grant ran out (`Expired`)
    /// are three different facts, and only the middle one is someone changing
    /// their mind.
    NotConsented { stance: ConsentState },
    /// **The consent fold could not be READ** (CIRISServer#351).
    ///
    /// NOT [`ScoreOutcome::NotConsented`]. "The subject declined" and "we could
    /// not ask the subject" are opposite facts: the first is the gate working,
    /// the second is the gate's only input missing. CC 3.4.5 leaves `capacity:*`
    /// as the ONE family whose admission turns on a consent read — the ruling
    /// keeps this gate and gates nothing else on a subject's say-so — so a
    /// consent read that FAILS is that whole gate failing, not a quiet no.
    ///
    /// They shared an arm. `resolve_scoped_consent` returns
    /// `Result<ConsentState, _>` and the gate asked `!matches!(stance,
    /// Ok(Granted))`, folding every backend error into the one outcome this
    /// module declares must never alarm — while `not_consented_agents > 0` is
    /// itself one of the two conditions that promote a zero-emission pass to
    /// INFO *"steady state, not a fault"*. So a corpus-wide failure of the
    /// consent read reported, once a minute, that every agent had declined and
    /// all was well: `FSD/RCA_TRACE_PLANE_2026-07-31.md`'s shape landing on the
    /// one gate CC 3.4.5 kept.
    ///
    /// Deliberately NOT an `Err`: the per-agent `Err` arm WARNs once per agent
    /// per pass, which is the 24,500-lines-a-day failure the arm above records.
    /// This is counted, named in the pass line, and — the load-bearing half —
    /// excluded from the set of outcomes that can account for a zero.
    ConsentUnreadable { error: String },
    /// **The standing-rows read could not be READ** (CIRISServer#374).
    ///
    /// The same shape as [`ScoreOutcome::ConsentUnreadable`], one plane over:
    /// [`live_capacity_rows`] swallowed every backend failure into an empty
    /// `Vec`, so "I could not read what already stands" arrived at both callers
    /// as "nothing stands". See [`StandingRows`] for what that costs.
    ///
    /// # Why this SUPPRESSES the write rather than proceeding
    ///
    /// The instinct is that re-authoring is harmless — the row would be
    /// identical, and a capacity score is worth having. Both halves are wrong,
    /// and the second is the load-bearing one.
    ///
    /// 1. **"Identical" would not save us even if it were true.** Persist
    ///    stamps a fresh `uuid::Uuid::new_v4()` on every emit and does not
    ///    dedupe by content, so a re-authored row is a NEW permanent row no
    ///    matter how identical its envelope is. This suppression is the entire
    ///    mechanism. Measured against the real backend: fail-open on a broken
    ///    read took the corpus 1 → 2 on a pass whose score had not moved.
    ///    And it is not identical anyway — `asserted_at` is inside the signed
    ///    envelope, floored to a bucket derived from [`unchanged_for`], i.e.
    ///    from the read that just failed; with no history the bucket falls back
    ///    to the hourly base, so a score that has held for a day gets a
    ///    different floored instant than the row already standing.
    /// 2. **The content is derived from the failed read.** Not just the
    ///    decision to write — the value of a signed field. Authoring here mints
    ///    a permanent, replicating, hybrid-signed row whose own `asserted_at`
    ///    is a fallback for data we did not have. That is CIRISPersist#541's
    ///    shape (a row corrupt BY CONSTRUCTION because a field was rewritten
    ///    from something other than the truth it claims to carry).
    /// 3. **The cost is asymmetric and the recovery is cheap.** Suppressing
    ///    costs one cadence — 60 seconds — and the next pass re-measures from
    ///    the same trace window. Authoring costs a row that cannot be deleted,
    ///    only superseded, and that replicates to every consenting peer.
    /// 4. **Fail-open is safe on ONE axis; suppression is safe on BOTH.** The
    ///    fail-open reasoning in [`live_capacity_rows`]'s own doc comment is
    ///    correct on the axis it was written for: a forged row must not silence
    ///    honest scoring, so a revocation read that fails must not return rows
    ///    unfiltered. Suppression satisfies that too — NOT writing can never
    ///    admit a forged suppression, and the forged row keeps being refused on
    ///    the next readable pass. Only the write-amplification axis
    ///    distinguishes them, and on that axis fail-open is the defect. One
    ///    function's failure mode was answering two questions and had only ever
    ///    been checked against one.
    ///
    /// The liveness objection — a sustained read failure lets the standing
    /// score expire after `SCORE_VALIDITY_DAYS` — is real and is answered by
    /// the counter, not by the write: a `list_attestations` that fails for days
    /// has broken far more of this node than the scorer, and it now WARNs with
    /// its own `narrowing` line every pass instead of quietly authoring rows.
    StandingUnreadable { error: String },
    /// The score is unchanged and already stands, asserted within the current
    /// coalescing bucket. Nothing to say; saying it anyway would cost a
    /// permanent, replicated row carrying no new information.
    Unchanged {
        standing_since: chrono::DateTime<chrono::Utc>,
        bucket_secs: i64,
    },
}

/// Score one agent and emit its `capacity:sustained_coherence:v1` attestation.
/// See [`ScoreOutcome`] for what the arms mean — they are NOT interchangeable
/// "did not emit" cases.
async fn score_and_emit(
    engine: &Engine,
    node_key_id: &str,
    attested_key_id: &str,
    traces: &[&TraceSummary],
    cfg: &ScorerConfig,
) -> Result<ScoreOutcome> {
    // Build the feature matrix (rows = traces, cols = lens constraint dims).
    let matrix = n_eff::feature_matrix(traces);
    if matrix.is_empty() {
        return Ok(ScoreOutcome::NoFeatureRows);
    }

    // Faithful N_eff port — participation ratio (measure_n_eff.py n_eff_pr).
    let derivation = n_eff::n_eff(&matrix);
    let n_eff_pr = derivation.n_eff_pr;

    // Feed N_eff into the [0,1] capacity band.
    let score = scoring::capacity::capacity(n_eff_pr, cfg.sample_size_gate, cfg.target_n_eff);

    // Anti-Goodhart: attesting (Node A) MUST differ from attested (the agent).
    // Self-attestation would be rejected here, never reaching put_attestation.
    let anti_goodhart = CapacityAttestation::new(node_key_id, attested_key_id)
        .context("capacity attestation violates CEG §7.5 anti-Goodhart")?;

    let now = chrono::Utc::now();

    // ── CIRISConstitution#46, asked BEFORE the work ─────────────────────────
    //
    // persist enforces this at put_attestation; asking first is not a second
    // implementation of the rule, it is the same canonical fold
    // (`resolve_scoped_consent`) consulted early. Two things follow: an
    // unconsented subject costs no hybrid signature, and — the reason this
    // exists — declining is reported as the ordinary state it is rather than as
    // a refused write.
    // THREE ZEROES, NOT ONE (CIRISServer#351). `resolve_scoped_consent` returns
    // `Result<ConsentState, _>`, so "did the subject permit this?" has three
    // possible answers and the gate must not fold two of them together:
    //   Ok(Granted)   → proceed.
    //   Ok(_ )        → the subject declined. Legitimate, permanent, never an
    //                   alarm — and the stance says WHICH decline it was.
    //   Err(_)        → the subject's answer is UNREADABLE. The gate has no
    //                   input; this is a fault, and it is the fault that used to
    //                   be indistinguishable from the line above.
    // Fail-closed is preserved in every arm — nothing is emitted unless the fold
    // returns `Granted`. What changes is what the instrument SAYS about the two
    // ways it can fail to.
    let stance = engine
        .federation_directory()
        .resolve_scoped_consent(
            node_key_id,
            attested_key_id,
            ciris_persist::federation::admission::ANALYZE_CONSENT_SCOPE,
            None,
            now,
        )
        .await;
    match stance {
        Ok(ConsentState::Granted) => {}
        Ok(declined) => return Ok(ScoreOutcome::NotConsented { stance: declined }),
        Err(e) => {
            return Ok(ScoreOutcome::ConsentUnreadable {
                error: e.to_string(),
            })
        }
    }

    // ── What already stands, read ONCE (CIRISServer#374) ────────────────────
    //
    // Read AFTER the consent gate, deliberately: a subject who declined is a
    // decline whatever the corpus says, so asking the corpus first would let a
    // capacity-plane read failure be reported about a subject whose answer was
    // "no" — the same category error one plane over. It also means an
    // unconsented subject costs no capacity scan, matching the comment above.
    //
    // ONE read feeds BOTH derivations. They used to issue one each, so the
    // bucket came from one corpus and the standing check from another, and each
    // swallowed its own failure into an empty vec independently.
    //
    // Split exactly like the consent gate above, and for the same reason:
    //   Ok(rows) → a real answer about what stands (which of the three zeroes it
    //              was is a fact for the log, not for the decision).
    //   Err(_)   → NO answer. FAIL CLOSED. The argument is on
    //              `ScoreOutcome::StandingUnreadable`; the short form is that
    //              the row we would author carries an `asserted_at` derived from
    //              the read that just failed, so "author it anyway, it would be
    //              identical" is false precisely when it matters.
    let standing = match live_capacity_rows(engine, attested_key_id, now).await {
        Ok(standing) => standing,
        Err(error) => return Ok(ScoreOutcome::StandingUnreadable { error }),
    };

    // ── Coalesce the assertion instant (CIRISPersist#519 item 2a-iii) ────────
    //
    // FLOOR, never ceiling or round-to-nearest. Persist's `coalesce_touch_ts`
    // spells out why, and the reason inverts the usual instinct: this is a LOWER
    // bound, so rounding UP could assert an instant past the real `now()` and
    // trip the future-skew guard on a legitimate, just-unlucky emission.
    // Flooring can only make the assertion more conservative, never less true.
    // (An upper bound like `valid_until` would round the other way, for exactly
    // the same reason — same operation, opposite direction, because the bound
    // points the other way.)
    let bucket = coalesce_bucket(unchanged_for(standing.rows(), score, now));
    let (asserted_at, valid_until) = coalesced_assertion(now, bucket);
    // Derive validity from the COALESCED instant, not from raw `now`. Deriving
    // it from `now` would leave `valid_until` varying every pass and the envelope
    // would differ anyway — the coalescing would be real and completely
    // ineffective, which is the worst of both.

    // Already said this, in this bucket? Then there is nothing new to assert,
    // and a signed row carrying no new information is pure cost: it is permanent,
    // it replicates, and it dilutes the corpus a reader has to fold.
    if let Some(prev) = standing_assertion(standing.rows(), score, asserted_at) {
        tracing::debug!(
            attested = %attested_key_id,
            score,
            bucket_secs = bucket.num_seconds(),
            standing_since = %prev,
            "capacity unchanged within the coalescing bucket — not re-authoring"
        );
        return Ok(ScoreOutcome::Unchanged {
            standing_since: prev,
            bucket_secs: bucket.num_seconds(),
        });
    }

    // The CEG `scores` envelope — the JCS canonical-signing payload (the same
    // shape ciris-status / lens-core emit; dimension is the versioned leaf).
    let envelope = serde_json::json!({
        (paths::DIMENSION): CAPACITY_DIMENSION,
        "attestation_type": ATTESTATION_TYPE_SCORES,
        "attesting_key_id": anti_goodhart.attesting(),
        "attested_key_id": anti_goodhart.attested(),
        "score": score,
        "n_eff_pr": n_eff_pr,
        "n_eff_h": derivation.n_eff_h,
        "sample_size": matrix.len(),
        "feature_dim": derivation.feature_dim,
        "sample_size_gate": cfg.sample_size_gate,
        "target_n_eff": cfg.target_n_eff,
        "asserted_at": asserted_at.to_rfc3339(),
        "valid_until": valid_until.to_rfc3339(),
        "cohort_scope": cohort_scope::FEDERATION,
    });

    // ── Emit (CIRISPersist#252/#253 collapse) ────────────────────────────────
    // The hand-rolled canonicalize→hash→hybrid-sign→assemble→put recipe is now
    // `Engine::emit_attestation_self`: it signs with the engine's OWN composed
    // (hardware-hybrid) signer and derives the attester/scrub as the node's #247
    // DERIVED federation key_id (the ENGINE signer's id — NOT cfg.key_id, which
    // `node_key_id` here — wire-preserving). `weight = Some(score)` (the v9.4.0
    // #252 surface) keeps the capacity band on the row so the replication trust
    // model reads the real score, not the `1.0` default.
    let mut input = EmitAttestationInput::with_envelope(
        ATTESTATION_TYPE_SCORES,
        ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope)?,
        // capacity:* is a REPUTATIONAL claim about an agent, federation-visible
        // by design (the whole point is that peers read it).
        cohort_scope::FEDERATION,
    );
    input.attested_key_id = Some(attested_key_id.to_owned());
    input.subject_key_ids = vec![attested_key_id.to_owned()];
    input.weight = Some(score);
    input.expires_at = Some(valid_until);
    engine
        .emit_attestation_self(input)
        .await
        .map_err(|e| anyhow::anyhow!("emit_attestation_self(capacity): {e}"))?;

    tracing::info!(
        attested = %attested_key_id,
        n_eff_pr,
        score,
        samples = matrix.len(),
        dim = derivation.feature_dim,
        // WHICH zero preceded this write. `never_scored` is a cold subject's
        // first row; `none_standing` means rows exist and stopped counting
        // (expired, or CIRISServer#355 revoked-over); `standing` means live rows
        // exist but none carries this score in this bucket — the score MOVED.
        // Three different reasons to author, and the swallowed read used to make
        // all three look like the first.
        standing = standing.kind(),
        standing_stopped = ?standing.stopped(),
        "emitted capacity:sustained_coherence:v1 attestation",
    );
    Ok(ScoreOutcome::Emitted)
}

#[cfg(test)]
mod outcome_accounting_tests {
    /// **A legitimate steady state must never be an alarm.**
    ///
    /// Every arm of [`super::ScoreOutcome`] that names a state the system is
    /// ALLOWED to be in must be counted into the zero-path accounting, or the
    /// pass WARNs that "the agents do not account for" a zero it can perfectly
    /// well account for. The two arms that are not such a state —
    /// `ConsentUnreadable` and `StandingUnreadable` — are held out by
    /// [`an_unreadable_consent_fold_never_accounts_for_a_zero`] and
    /// [`an_unreadable_standing_read_never_accounts_for_a_zero`], which are the
    /// other half of this rule and not exceptions to it.
    ///
    /// Measured before this was fixed: 17 of 20 agents on the production
    /// canonical had not granted CC#46 `analyze` consent — a permanent, allowed
    /// choice — and each produced a WARN on every 60s pass. 51 lines every three
    /// minutes, ~24,500 a day, none actionable. The zero was fully explained the
    /// whole time; nothing was counting the explanation.
    ///
    /// This asserts the SOURCE, because the condition is a property of the
    /// accounting expression rather than of any value it produces.
    #[test]
    fn every_non_emitting_outcome_is_counted_into_the_accounting() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/scorer.rs"),
        )
        .expect("readable");
        let code = src.split("#[cfg(test)]").next().expect("code");
        let accounted = code
            .split_once("let accounted =")
            .expect("the zero-path accounting must exist")
            .1
            .split(';')
            .next()
            .unwrap_or("");
        for counter in [
            "unchanged_agents",
            "not_consented_agents",
            "empty_matrix_agents",
            "unregistered_agents",
        ] {
            assert!(
                accounted.contains(counter),
                "`{counter}` is not in the zero-path accounting, so a pass explained entirely by \
                 it still WARNs. Every non-emitting outcome is a reason the zero is EXPLAINED; \
                 an alarm that fires on an explained zero is noise, and noise is how a real one \
                 gets missed.\naccounting: {accounted}"
            );
        }
    }

    /// **An unreadable consent fold never accounts for a zero** — the inverse
    /// of the rule above, and the CIRISServer#351 fix (CC 3.4.5).
    ///
    /// CC 3.4.5 ratifies consent-before-scoring for `capacity:*` and for nothing
    /// else: it is the ONE family whose admission turns on reading a subject's
    /// answer. So the answer being UNREADABLE is not one of the states this pass
    /// is allowed to sit in, and it must not be able to make a zero-emission
    /// pass read as healthy.
    ///
    /// Before the split it could, twice over. `Err(_)` from
    /// `resolve_scoped_consent` folded into `NotConsented`, which (a) entered
    /// `accounted` and (b) is itself one of the two triggers for the INFO
    /// *"steady state, not a fault"* line. A corpus-wide failure of the consent
    /// read therefore printed, once a minute, that every agent had declined and
    /// all was well — an instrument reporting its own blindness as the subjects'
    /// choice, which is the `FSD/RCA_TRACE_PLANE_2026-07-31.md` shape landing on
    /// the one gate the ruling kept.
    ///
    /// Source-asserted for the same reason as the test above: both conditions
    /// are properties of expressions, not of any value they produce.
    #[test]
    fn an_unreadable_consent_fold_never_accounts_for_a_zero() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/scorer.rs"),
        )
        .expect("readable");
        let code = src.split("#[cfg(test)]").next().expect("code");
        let (_, after) = code
            .split_once("let accounted =")
            .expect("the zero-path accounting must exist");
        let accounted = after.split(';').next().unwrap_or("");
        assert!(
            !accounted.contains("consent_unreadable_agents"),
            "`consent_unreadable_agents` is in the zero-path accounting, so a pass whose \
             consent fold failed for EVERY agent counts as fully explained. \"The subject \
             declined\" and \"we could not read the subject's answer\" are opposite facts; \
             only the first accounts for a zero.\naccounting: {accounted}"
        );

        // …and it must be DECIDED BEFORE the quiet branch, not merely left out
        // of the sum: a single readable decline plus N unreadable folds would
        // otherwise still satisfy `unchanged || not_consented` and log INFO.
        // Everything between the accounting and the first `tracing::info!` is
        // the guard the quiet line sits behind.
        let before_the_quiet_line = after
            .split_once("tracing::info!")
            .map(|(guard, _)| guard)
            .unwrap_or("");
        assert!(
            before_the_quiet_line.contains("consent_unreadable_agents > 0"),
            "nothing between the zero-path accounting and the INFO \"steady state, not a \
             fault\" line tests `consent_unreadable_agents`, so one readable decline is enough \
             to let an otherwise-blind pass report itself healthy.\nguard: \
             {before_the_quiet_line}"
        );
    }

    /// **An unreadable standing-rows read never accounts for a zero**
    /// (CIRISServer#374) — the same rule as above, one plane over.
    ///
    /// `live_capacity_rows` swallowed every backend failure into `Vec::new()`,
    /// so "the capacity history could not be read" reached both of its callers
    /// as "nothing stands". That is not a state this node is allowed to sit in,
    /// and it is worse than it looks in the zero-path accounting: the swallow
    /// made the scorer AUTHOR a row (it could not see the one already there),
    /// and on the next pass that row counted as `unchanged_agents` — the first
    /// of the two triggers for the INFO *"steady state, not a fault"* line. A
    /// blind coalescer therefore wrote a permanent row a minute while reporting
    /// itself as the steady state, which is how ~900 rows/day happened.
    ///
    /// Source-asserted, like its two neighbours, because the condition is a
    /// property of an expression rather than of any value it produces.
    #[test]
    fn an_unreadable_standing_read_never_accounts_for_a_zero() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/scorer.rs"),
        )
        .expect("readable");
        let code = src.split("#[cfg(test)]").next().expect("code");
        let (_, after) = code
            .split_once("let accounted =")
            .expect("the zero-path accounting must exist");
        let accounted = after.split(';').next().unwrap_or("");
        assert!(
            !accounted.contains("standing_unreadable_agents"),
            "`standing_unreadable_agents` is in the zero-path accounting, so a pass whose \
             capacity-history read failed for EVERY agent counts as fully explained. \"Nothing \
             stands\" and \"we could not read what stands\" are opposite facts; only the first \
             accounts for a zero.\naccounting: {accounted}"
        );

        // …and DECIDED BEFORE the quiet branch, not merely left out of the sum.
        let before_the_quiet_line = after
            .split_once("tracing::info!")
            .map(|(guard, _)| guard)
            .unwrap_or("");
        assert!(
            before_the_quiet_line.contains("standing_unreadable_agents > 0"),
            "nothing between the zero-path accounting and the INFO \"steady state, not a \
             fault\" line tests `standing_unreadable_agents`, so one genuinely-unchanged \
             subject is enough to let a pass with a blind coalescer report itself \
             healthy.\nguard: {before_the_quiet_line}"
        );
    }

    /// **The CC#46 consent gate is asked BEFORE the standing-rows read**
    /// (CIRISServer#374).
    ///
    /// A subject who declined is a decline whatever the corpus says. Asking the
    /// corpus first would report a capacity-plane read failure about a subject
    /// whose answer was "no" — the #351 category error, committed by the fix for
    /// it — and would make an unconsented subject pay for a scan the gate is
    /// about to render pointless.
    ///
    /// Source-asserted because the property IS a source ordering, and this is
    /// the form of that assertion which can fail: move the read above the gate
    /// and the two offsets swap. (`find` takes the first occurrence of each, so
    /// the earliest mention of either is what is compared.)
    ///
    /// # What used to be here, and why it is gone
    ///
    /// This test also asserted that `score_and_emit` "returns
    /// `StandingUnreadable` before reaching `emit_attestation_self`" — by
    /// checking that the *string* `ScoreOutcome::StandingUnreadable` occurred
    /// somewhere in the source ahead of the emit. **That assertion could not
    /// fail.** Mutation D — hang the early return off the wrong arm, so an
    /// unreadable read falls through and authors — leaves the string exactly
    /// where it was, and the gate stayed green over the restored bug.
    ///
    /// It is not replaced by a stricter source scan, because the property is not
    /// a source property. It has two better owners now:
    ///
    /// - the TYPE, which no longer admits the silent form of the regression at
    ///   all (see [`StandingRows`]); and
    /// - `an_unreadable_standing_read_is_not_nothing_standing` in
    ///   `tests/capacity_scorer.rs`, which breaks the read against a real
    ///   backend and counts the rows in the corpus — measuring the suppression
    ///   rather than looking for a name. Its own justification for being
    ///   source-asserted ("no return value distinguishes suppressed from would
    ///   have suppressed") was simply untrue: `run_pass` returns the emitted
    ///   count, and the corpus is countable.
    #[test]
    fn the_consent_gate_is_asked_before_the_standing_rows_read() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/scorer.rs"),
        )
        .expect("readable");
        let code = src.split("#[cfg(test)]").next().expect("code");
        let body = code
            .split_once("async fn score_and_emit")
            .expect("score_and_emit must exist")
            .1;
        let consent_at = body
            .find("resolve_scoped_consent")
            .expect("the CC#46 gate must exist");
        let standing_at = body
            .find("live_capacity_rows")
            .expect("the standing-rows read must exist");
        assert!(
            consent_at < standing_at,
            "the standing-rows read runs BEFORE the CC#46 consent gate, so a subject who \
             declined can be reported as a capacity-plane read failure — and an unconsented \
             subject pays for a capacity scan the gate is about to make pointless"
        );
    }
}

#[cfg(test)]
mod coalescing_tests {
    use super::*;
    use ciris_persist::federation::freshness::coalesce_touch_ts;

    fn t(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s).unwrap().into()
    }

    /// **Flooring, never ceiling** — the safety property, and the one whose
    /// reasoning inverts the instinct.
    ///
    /// `asserted_at` is a temporal LOWER bound. Rounding up (or to nearest)
    /// could push it past the real `now()` and trip the future-skew guard on a
    /// legitimate, just-unlucky emission. Flooring can only make the assertion
    /// more conservative, never less true. An upper bound like `valid_until`
    /// would round the OTHER way for the same reason.
    #[test]
    fn the_coalesced_instant_never_moves_into_the_future() {
        let bucket = chrono::Duration::seconds(SCORE_COALESCE_BASE);
        // Exercise the CALL SITE, not persist's pure function underneath it.
        for iso in [
            "2026-08-01T17:00:00Z",
            "2026-08-01T17:42:25Z",
            "2026-08-01T17:59:59Z",
        ] {
            let now = t(iso);
            let (asserted, valid_until) = coalesced_assertion(now, bucket);
            assert!(
                asserted <= now,
                "{iso}: the emit path asserts liveness at {asserted}, AFTER now. A lower bound \
                 may only ever understate; the future-skew guard refuses this."
            );
            assert_eq!(
                valid_until,
                asserted + chrono::Duration::days(SCORE_VALIDITY_DAYS),
                "{iso}: validity must derive from the COALESCED instant. Derived from raw now it \
                 varies every pass, the envelope differs anyway, and the coalescing does nothing."
            );
        }
        for iso in [
            "2026-08-01T17:00:00Z", // exactly on a boundary
            "2026-08-01T17:00:01Z", // just after
            "2026-08-01T17:59:59Z", // just before the next
            "2026-08-01T17:42:25Z", // the observed production instant
        ] {
            let now = t(iso);
            let coalesced = coalesce_touch_ts(now, bucket);
            assert!(
                coalesced <= now,
                "{iso}: coalescing moved the assertion FORWARD to {coalesced}. For a lower bound \
                 that asserts liveness we did not have, and the future-skew guard refuses it."
            );
            assert!(
                now - coalesced < bucket,
                "{iso}: coalescing dropped more than a full bucket ({coalesced}) — the assertion \
                 would be needlessly stale"
            );
        }
    }

    /// The dedup property this exists for: two passes inside one bucket, same
    /// score, must produce the SAME assertion instant — which is what makes the
    /// signed envelopes identical rather than merely similar.
    #[test]
    fn passes_within_one_bucket_share_an_assertion_instant() {
        let bucket = chrono::Duration::seconds(SCORE_COALESCE_BASE);
        // The eleven observed production passes, 17:32:25 .. 17:42:25.
        let instants: Vec<_> = (32..=42)
            .map(|m| t(&format!("2026-08-01T17:{m:02}:25Z")))
            .map(|n| coalesce_touch_ts(n, bucket))
            .collect();
        assert!(
            instants.windows(2).all(|w| w[0] == w[1]),
            "eleven passes inside one hour produced {} distinct instants — each one is a distinct \
             signed envelope, a distinct content hash, and a permanent row. That is exactly the \
             0.5.151 behaviour this replaces.",
            instants
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
    }

    /// Attenuation only ever slows the restatement of something that is NOT
    /// moving. A score that just changed must get the base bucket, so a moving
    /// score is never coarsened.
    #[test]
    fn attenuation_is_monotonic_and_a_fresh_score_is_never_coarsened() {
        let base = coalesce_bucket(chrono::Duration::zero());
        assert_eq!(
            base.num_seconds(),
            SCORE_COALESCE_BASE,
            "a score with no unbroken run must get the base bucket — otherwise a score that just \
             moved would be restated more slowly than one that never moves"
        );
        let widths: Vec<i64> = [0i64, 1, 5, 6, 12, 23, 24, 72, 24 * 30]
            .iter()
            .map(|h| coalesce_bucket(chrono::Duration::hours(*h)).num_seconds())
            .collect();
        assert!(
            widths.windows(2).all(|w| w[0] <= w[1]),
            "attenuation must be monotonic in the unchanged run: {widths:?}"
        );
        assert_eq!(
            *widths.last().unwrap(),
            SCORE_COALESCE_MAX,
            "a very old unchanged score must saturate at the cap, not keep widening"
        );
    }

    /// **The cap is bounded by the validity window, not by taste.**
    ///
    /// A bucket approaching `valid_until` would let a still-true score age out
    /// silently, and "stopped being true" and "stopped being measured" would
    /// become the same observation from outside. That is the confirmed-vs-
    /// unverified ambiguity the trace-plane RCA is about, and it is worse here
    /// because the row is what peers read.
    #[test]
    fn the_widest_bucket_re_asserts_well_inside_the_validity_window() {
        let validity = chrono::Duration::days(7).num_seconds();
        let re_assertions = validity / SCORE_COALESCE_MAX;
        assert!(
            re_assertions >= 4,
            "at the widest bucket a live score is re-asserted only {re_assertions}x before it \
             expires. Fewer than a handful and one missed pass silently ages out a score that is \
             still true. Narrow SCORE_COALESCE_MAX or widen the validity — deliberately, together."
        );
    }
}
