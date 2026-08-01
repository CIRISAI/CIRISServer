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
use ciris_persist::federation::types::cohort_scope;
use ciris_persist::federation::EmitAttestationInput;
use ciris_persist::prelude::{CallerScope, Engine, ReadEngine, TraceFilter, TraceSummary};

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
            // Hourly — long enough that the score→emit pass is negligible load,
            // short enough that a fresh corpus produces a capacity row promptly.
            cadence: Duration::from_secs(3600),
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
            Ok(true) => emitted += 1,
            Ok(false) => {
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
        let narrowing = if raw_trace_events == usize::MAX {
            "read FAILED — the summary read itself errored; the scorer cannot see the corpus"
        } else if raw_trace_events == 0 {
            "nothing arrived — the corpus has no traces this scorer can read (delivery, not scoring)"
        } else if n_summaries == 0 {
            "THE READ IS NARROWING — rows exist in the corpus but this pass saw none.              Compare the scope gate (Unauthenticated admits affiliations/species/biosphere/             federation), the filter, and whether this backend handle is the one replication              writes through"
        } else {
            "feature semantics — summaries present but no capacity authored (empty matrices,              the sample gate, or CC#46 analyze consent)"
        };
        tracing::warn!(
            n_summaries,
            n_agents,
            empty_matrix_agents,
            unregistered_agents,
            window = cfg.window,
            raw_trace_events,
            sample_size_gate = cfg.sample_size_gate,
            narrowing,
            "capacity scorer pass emitted ZERO — see `narrowing` for which plane stopped it"
        );
    } else {
        tracing::info!(
            n_summaries,
            n_agents,
            emitted,
            unregistered_agents,
            "capacity scorer pass complete (capacity attestations authored → replication)"
        );
    }
    Ok(emitted)
}

/// Score one agent and emit its `capacity:sustained_coherence:v1` attestation.
/// Returns `Ok(true)` if a row was emitted, `Ok(false)` if the agent had no
/// usable feature rows (skipped).
async fn score_and_emit(
    engine: &Engine,
    node_key_id: &str,
    attested_key_id: &str,
    traces: &[&TraceSummary],
    cfg: &ScorerConfig,
) -> Result<bool> {
    // Build the feature matrix (rows = traces, cols = lens constraint dims).
    let matrix = n_eff::feature_matrix(traces);
    if matrix.is_empty() {
        return Ok(false); // no feature rows for this agent
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
    let valid_until = now + chrono::Duration::days(7);

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
        "asserted_at": now.to_rfc3339(),
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
        "emitted capacity:sustained_coherence:v1 attestation",
    );
    Ok(true)
}
