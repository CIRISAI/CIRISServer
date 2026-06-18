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
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use sha2::{Digest, Sha256};

use ciris_lens_core::capacity::CapacityAttestation;
use ciris_lens_core::scoring;
use ciris_persist::federation::types::{attestation_tier, Attestation, SignedAttestation};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{CallerScope, Engine, ReadEngine, TraceFilter, TraceSummary};
// The CEG PRODUCE canonicalizer (V2/JCS). persist v9.0.0's federation-tier
// ingest gate (CC 5.3.2.4.3.1) re-canonicalizes the emitted attestation envelope
// through THIS function and Strict-hybrid-verifies the result, so the scorer MUST
// sign over the SAME `ceg_produce_canonicalize` bytes (matching peer.rs /
// build_self_key_record) — the legacy `canonicalize_envelope_for_signing`
// (PythonJsonDumps strip form) produces different bytes and the gate rejects it.
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

pub mod n_eff;

/// CEG `scores` attestation type (matches
/// `ciris_persist::federation::types::attestation_type::SCORES`).
const ATTESTATION_TYPE_SCORES: &str = "scores";

/// The capacity leaf this scorer emits. **Versioned** (`:v1`) to satisfy
/// persist's `DimensionAdmissionPolicy { require_version_segment: true }`. We
/// emit `sustained_coherence` — the CEG §5.5.4 **S** factor — because that is
/// the single capacity factor N_eff directly measures ("long-window N_eff +
/// manifold-conformity stability"). The other four factors (C / I_int / R /
/// I_inc) need signals this scorer does not yet derive; emitting only S is the
/// honest scope (the composite product would otherwise be fabricated).
const CAPACITY_DIMENSION: &str = "capacity:sustained_coherence:v1";

/// Periodic-scorer configuration. Cadence + window are env-driven with sane
/// defaults; see [`ScorerConfig::from_env`].
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
    /// Build from the environment over the defaults. Every field is optional.
    ///
    /// - `CIRIS_SERVER_SCORER_CADENCE_SECS`
    /// - `CIRIS_SERVER_SCORER_WINDOW`
    /// - `CIRIS_SERVER_SCORER_SAMPLE_GATE`
    /// - `CIRIS_SERVER_SCORER_TARGET_N_EFF`
    pub fn from_env() -> Self {
        let d = ScorerConfig::default();
        let cadence = std::env::var("CIRIS_SERVER_SCORER_CADENCE_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|s| *s > 0)
            .map(Duration::from_secs)
            .unwrap_or(d.cadence);
        let window = std::env::var("CIRIS_SERVER_SCORER_WINDOW")
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok())
            .filter(|w| (1..=10_000).contains(w))
            .unwrap_or(d.window);
        let sample_size_gate = std::env::var("CIRIS_SERVER_SCORER_SAMPLE_GATE")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(d.sample_size_gate);
        let target_n_eff = std::env::var("CIRIS_SERVER_SCORER_TARGET_N_EFF")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|t| t.is_finite() && *t > 0.0)
            .unwrap_or(d.target_n_eff);
        ScorerConfig {
            cadence,
            window,
            sample_size_gate,
            target_n_eff,
        }
    }
}

/// Spawn the periodic capacity scorer onto the current Tokio runtime. Returns
/// the join handle; the task runs until the runtime drops it (the node's
/// lifetime). The first pass runs after one `cadence` tick (lets the corpus
/// accumulate traces post-boot).
pub fn spawn(
    engine: Arc<Engine>,
    node_key_id: String,
    cfg: ScorerConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(cfg.cadence);
        // The first immediate tick fires at once; skip it so we don't score an
        // empty just-booted corpus.
        tick.tick().await;
        loop {
            tick.tick().await;
            if let Err(e) = run_pass(&engine, &node_key_id, &cfg).await {
                tracing::warn!(error = %e, "capacity scorer pass failed (will retry next cadence)");
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

    let mut emitted = 0usize;
    for (agent_id_hash, traces) in by_agent {
        // The attested key is the agent's federation identity. The only
        // substrate-stable per-agent identifier on a trace summary is
        // `agent_id_hash` (the AV-9 dedup-key prefix), which is exactly what
        // `put_attestation`'s FK + identity lookup resolves against — so we
        // attest ABOUT the agent_id_hash. (A future agent_name→key_id mapping
        // could substitute a human-readable key_id; until that mapping is
        // substrate-backed, the hash is the honest, FK-resolvable subject.)
        let attested_key_id = agent_id_hash.clone();

        match score_and_emit(
            engine,
            backend.as_ref(),
            node_key_id,
            &attested_key_id,
            &traces,
            cfg,
        )
        .await
        {
            Ok(true) => emitted += 1,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(
                    agent = %attested_key_id,
                    error = %e,
                    "capacity scoring failed for agent (skipping)",
                );
            }
        }
    }
    Ok(emitted)
}

/// Score one agent and emit its `capacity:sustained_coherence:v1` attestation.
/// Returns `Ok(true)` if a row was emitted, `Ok(false)` if the agent had no
/// usable feature rows (skipped).
async fn score_and_emit(
    engine: &Engine,
    directory: &dyn FederationDirectory,
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
        "dimension": CAPACITY_DIMENSION,
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
        "cohort_scope": "federation",
    });

    // ── Emit recipe — modeled on CIRISStatus ceg.rs:182 (emit_liveness) ──────
    // 1. CEG PRODUCE-canonical bytes (V2/JCS — the signing basis, CEG §0.9; the
    //    SAME form persist v9.0.0's federation-tier ingest gate re-derives).
    let canonical = ceg_produce_canonicalize(&envelope)
        .map_err(|e| anyhow::anyhow!("canonicalize capacity envelope: {e}"))?;
    // 2. original_content_hash = hex(SHA-256(canonical)).
    let original_content_hash = hex::encode(Sha256::digest(&canonical));
    // 3. Hybrid sign (Ed25519 + ML-DSA-65) over the canonical bytes.
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .context("hybrid-sign capacity envelope")?;
    let classical_b64 = B64.encode(&sig.classical.signature);
    let pqc_b64 = B64.encode(&sig.pqc.signature);

    // 4. Assemble the FEDERATION-tier row.
    let attestation = Attestation {
        attestation_id: new_uuid_v4(),
        attesting_key_id: node_key_id.to_owned(),
        attested_key_id: attested_key_id.to_owned(),
        attestation_type: ATTESTATION_TYPE_SCORES.to_owned(),
        weight: Some(score),
        asserted_at: now,
        expires_at: Some(valid_until),
        attestation_envelope: envelope,
        original_content_hash,
        scrub_signature_classical: classical_b64,
        scrub_signature_pqc: Some(pqc_b64),
        scrub_key_id: node_key_id.to_owned(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(), // server-computed on insert
        subject_key_ids: vec![attested_key_id.to_owned()],
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_owned(),
        tier: attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
    };

    directory
        .put_attestation(SignedAttestation { attestation })
        .await
        .map_err(|e| anyhow::anyhow!("put_attestation(capacity): {e}"))?;

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

/// Minimal RFC-4122 v4 row id (no `uuid` dep) — mirrors ceg.rs's `uuid_v4`. The
/// content hash is the integrity anchor, not this id.
fn new_uuid_v4() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let t = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default() as u64;
    let a = t ^ (n.rotate_left(17));
    let b = t.rotate_left(31) ^ n;
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (a >> 32) as u32,
        (a >> 16) as u16,
        (a as u16) & 0x0fff,
        ((b >> 48) as u16 & 0x3fff) | 0x8000,
        b & 0xffff_ffff_ffff,
    )
}
