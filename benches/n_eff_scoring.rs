//! N_eff capacity-scoring microbench — the lens constraint eigenspectrum pipeline
//! (CIRISServer scorer, src/scorer/n_eff.rs).
//!
//! Measures the CPU cost of the `capacity:sustained_coherence:v1` computation:
//! the feature-matrix build + Jacobi eigendecomposition + participation-ratio
//! derivation that feeds the scorer's per-cycle attestation. This is the
//! `measure_n_eff.py` Rust port — fully CI-runnable (no network, no database,
//! pure arithmetic over synthetic feature matrices).
//!
//! ## Bench groups
//!
//! 1. `n_eff_matrix_build` — build the feature matrix from synthetic TraceSummary
//!    structs (the "feature_matrix" step in the scorer). Sizes N=50/100/500.
//!
//! 2. `n_eff_compute` — run [`n_eff`] (Jacobi eigendecomposition + PR/entropy
//!    derivation) over an already-built dense matrix. Sizes N=20/100/500.
//!
//! 3. `n_eff_e2e` — end-to-end: synthetic TraceSummary slice → feature matrix
//!    → N_eff. Sizes N=50/500.
//!
//! Run: `cargo bench --bench n_eff_scoring`
//!
//! The reported time/iter is the per-agent per-cadence-tick CPU cost. At N=500
//! (the window cap) this is an upper bound; at N=50 (a few hours of live mesh
//! traces on a lightly loaded node) it is the typical observed cost.
//!
//! These numbers are MEASURED (CI-runnable, no live mesh required) and are
//! promoted in the scoreboard JSON under `substrate.n_eff_scoring_per_agent`.

#![allow(clippy::doc_lazy_continuation)]

use chrono::Utc;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use ciris_persist::prelude::TraceSummary;
use ciris_persist::schema::TraceLevel;
use ciris_server::scorer::n_eff::{feature_matrix, n_eff, FEATURE_DIM};

// ── Synthetic trace factory ────────────────────────────────────────────────────

/// Build a synthetic [`TraceSummary`] carrying the 11 fields [`feature_row`]
/// reads, leaving all other fields at sensible zero/None values. Uses a
/// deterministic seed from `idx` so the matrix is non-degenerate (not all
/// constant columns) — eigendecomposition exercises the real code path.
fn synthetic_trace(idx: usize) -> TraceSummary {
    // Mix two independent patterns so consecutive traces are NOT identical
    // (constant columns → zero eigenvalues → n_eff = 0, the degenerate case;
    // we want a realistic non-degenerate corpus).
    let pattern_a = (idx % 3) != 0;
    let pattern_b = (idx % 7) < 4;

    let now = Utc::now();
    TraceSummary {
        trace_id: format!("bench-trace-{idx}"),
        thought_id: format!("bench-thought-{idx}"),
        task_id: None,
        agent_id_hash: "bench-agent".to_string(),
        agent_name: None,
        agent_role: None,
        deployment_domain: None,
        deployment_type: None,
        started_at: now,
        completed_at: now,
        trace_level: TraceLevel::Generic,
        schema_version: "6".to_string(),
        signature_verified: true,
        cognitive_state: None,
        thought_type: None,
        thought_depth: None,
        // The 11 fields n_eff::feature_row reads:
        csdma_plausibility_score: Some(0.5 + (((idx * 37 + 11) % 41) as f64) / 100.0),
        dsdma_domain_alignment: Some(0.3 + (((idx * 17 + 7) % 70) as f64) / 100.0),
        dsdma_domain: None,
        idma_k_eff: Some(1.0 + ((idx * 13 % 7) as f64)),
        idma_correlation_risk: Some(0.1 + (((idx * 23) % 50) as f64) / 100.0),
        idma_fragility_flag: Some(idx % 5 == 0),
        idma_phase: None,
        conscience_passed: Some(pattern_a),
        action_was_overridden: Some(idx % 10 == 0),
        entropy_passed: Some(pattern_b),
        coherence_passed: Some(pattern_a || pattern_b),
        optimization_veto_passed: Some(true),
        epistemic_humility_passed: Some(pattern_b),
        selected_action: None,
        action_success: None,
        llm_calls: None,
        tokens_total: None,
        cost_usd: None,
    }
}

/// Pre-build the feature matrix (the `feature_matrix` step already done, so
/// `n_eff_compute` can bench the eigendecomposition in isolation).
fn build_matrix(n: usize) -> Vec<[Option<f64>; FEATURE_DIM]> {
    let traces: Vec<TraceSummary> = (0..n).map(synthetic_trace).collect();
    let refs: Vec<&TraceSummary> = traces.iter().collect();
    feature_matrix(&refs)
}

// ── 1. Feature-matrix build ────────────────────────────────────────────────────

fn bench_matrix_build(c: &mut Criterion) {
    let mut g = c.benchmark_group("n_eff_matrix_build");
    for &n in &[50usize, 100, 500] {
        g.throughput(Throughput::Elements(n as u64));
        g.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let traces: Vec<TraceSummary> = (0..n).map(synthetic_trace).collect();
            b.iter(|| {
                let refs: Vec<&TraceSummary> = traces.iter().collect();
                black_box(feature_matrix(black_box(&refs)))
            });
        });
    }
    g.finish();
}

// ── 2. N_eff computation (eigendecomposition) ─────────────────────────────────

fn bench_n_eff_compute(c: &mut Criterion) {
    let mut g = c.benchmark_group("n_eff_compute");
    for &n in &[20usize, 100, 500] {
        g.throughput(Throughput::Elements(n as u64));
        g.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let matrix = build_matrix(n);
            b.iter(|| black_box(n_eff(black_box(&matrix))));
        });
    }
    g.finish();
}

// ── 3. End-to-end: traces → feature matrix → N_eff ───────────────────────────

fn bench_n_eff_e2e(c: &mut Criterion) {
    let mut g = c.benchmark_group("n_eff_e2e");
    for &n in &[50usize, 500] {
        g.throughput(Throughput::Elements(n as u64));
        g.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let traces: Vec<TraceSummary> = (0..n).map(synthetic_trace).collect();
            b.iter(|| {
                let refs: Vec<&TraceSummary> = traces.iter().collect();
                let mat = feature_matrix(black_box(&refs));
                black_box(n_eff(&mat))
            });
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_matrix_build,
    bench_n_eff_compute,
    bench_n_eff_e2e
);
criterion_main!(benches);
