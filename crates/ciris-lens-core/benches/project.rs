//! `project` — `crate::extract::projection::project(&Features) ->
//! [f64; 16]`, the 16-feature CRC projection on the science-layer
//! hot path (one call per trace).
//!
//! Each detection-event pipeline runs this once. Throughput sets the
//! ceiling on per-trace scoring rate; allocations would compound to
//! GC pressure under load.
//!
//! # Expected curve
//!
//! Constant in component_blobs population size — `project` is a fixed
//! sequence of 16 path-lookups + atomic-typed extractions; an O(n)
//! curve in blob count would mean the function started iterating where
//! it should be indexing.

#![allow(
    clippy::pedantic,
    clippy::needless_pass_by_value,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss
)]

use std::collections::HashMap;

use ciris_lens_core::extract::project;
use ciris_persist::pipeline::extract::Features;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::json;

/// Build a `Features` struct populated with the three core blobs
/// `project` reads (`dma_results`, `idma_result`, `conscience_result`)
/// plus an arbitrary number of unused blobs to pad the HashMap.
fn make_features(noise_blob_count: usize) -> Features {
    let mut component_blobs = HashMap::new();

    // The three blobs `project` actually reads.
    component_blobs.insert(
        "dma_results".to_string(),
        json!({
            "csdma": { "plausibility_score": 0.873 },
            "dsdma": { "domain_alignment": 0.812 },
        }),
    );
    component_blobs.insert(
        "idma_result".to_string(),
        json!({ "k_eff": 2.5, "correlation_risk": 0.18 }),
    );
    component_blobs.insert(
        "conscience_result".to_string(),
        json!({
            "coherence_level": 0.92,
            "entropy_level": 0.41,
            "entropy_score": 0.7,
            "coherence_score": 0.85,
            "optimization_veto_entropy_ratio": 0.55,
            "epistemic_humility_certainty": 0.78,
            "conscience_passed": true,
            "entropy_passed": true,
            "coherence_passed": true,
            "optimization_veto_passed": false,
            "epistemic_humility_passed": true,
            "action_was_overridden": false,
        }),
    );

    // Noise blobs `project` should NOT read — pads the HashMap to
    // verify the projection is O(1) in blob count.
    for i in 0..noise_blob_count {
        component_blobs.insert(format!("noise_blob_{i}"), json!({ "ignored": true }));
    }

    Features {
        declared: Default::default(),
        step_timestamps: Default::default(),
        observation_weights: Default::default(),
        models_used: vec![],
        component_blobs,
        cost_estimate: 0.0,
        total_tokens: 0,
        model_class: Default::default(),
    }
}

fn bench_project(c: &mut Criterion) {
    // Sweep noise-blob count geometrically. A flat curve confirms the
    // projection indexes (not iterates); a rising curve would surface
    // an accidental linear sweep.
    let sizes = [0usize, 8, 64, 512, 4_096];
    let mut group = c.benchmark_group("project");
    for size in sizes {
        let features = make_features(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &features, |b, f| {
            b.iter(|| project(black_box(f)))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_project);
criterion_main!(benches);
