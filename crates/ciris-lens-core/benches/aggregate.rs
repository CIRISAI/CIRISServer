//! `aggregate` — `crate::scores::compute_aggregate(...)`, the pure
//! reduction over a slice of `DetectionEvent`s that produces an
//! `AgentScoreAggregate` (FSD §4.6).
//!
//! Sets the ceiling on the agent-side score read path's response
//! time: every `lens.scores.get_for_agent_window(...)` call lands
//! here after persist's read.
//!
//! # Expected curve
//!
//! Linear in event count — a single pass over the slice, plus a
//! HashMap insert per unique detector. A super-linear curve would
//! mean someone added a sort or a quadratic comparison in the loop.

#![allow(
    clippy::pedantic,
    clippy::needless_pass_by_value,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss
)]

use chrono::{DateTime, Utc};
use ciris_lens_core::scores::compute_aggregate;
use ciris_persist::derived::types::{ConformityVariant, DetectionEvent, DetectionSeverity};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn t(s: &str) -> DateTime<Utc> {
    s.parse::<DateTime<Utc>>().unwrap()
}

fn make_event(i: usize) -> DetectionEvent {
    // Rotate through three detectors so the per-detector HashMap
    // has realistic cardinality; rotate through three severities
    // + three conformity variants so the bucket arithmetic gets
    // exercised across paths.
    let detector_idx = i % 3;
    let severity_idx = i % 3;
    let conformity_idx = i % 3;

    let detector = match detector_idx {
        0 => "manifold_conformity_outlier",
        1 => "cohort_declared_inferred_mismatch",
        _ => "unconsented_external_probe",
    };
    let severity = match severity_idx {
        0 => DetectionSeverity::Info,
        1 => DetectionSeverity::Warning,
        _ => DetectionSeverity::Critical,
    };
    let conformity = match conformity_idx {
        0 => ConformityVariant::Numeric,
        1 => ConformityVariant::Indeterminate,
        _ => ConformityVariant::Unavailable,
    };

    DetectionEvent {
        detection_id: uuid::Uuid::nil(),
        trace_id: format!("bench-trace-{i}"),
        body_sha256: vec![0u8; 32],
        detector: detector.to_string(),
        severity,
        cohort_cell: serde_json::Value::Null,
        conformity_variant: conformity,
        conformity_payload: serde_json::Value::Null,
        lens_core_version: "bench".into(),
        ratchet_calibration_version: 0,
        canonical_bytes: vec![],
        ed25519_sig: vec![0u8; 64],
        ml_dsa_65_sig: vec![0u8; 3309],
        signing_key_id: "bench".into(),
        ts: t("2026-06-05T12:00:00Z"),
    }
}

fn bench_aggregate(c: &mut Criterion) {
    // Event-count sweep — what realistic windows look like. Pi-class
    // 24h: ≈ 1k events; production-class 24h: ≈ 100k.
    let sizes = [100usize, 1_000, 10_000, 100_000];
    let mut group = c.benchmark_group("aggregate");
    for size in sizes {
        let events: Vec<DetectionEvent> = (0..size).map(make_event).collect();
        let window_start = t("2026-06-05T00:00:00Z");
        let window_end = t("2026-06-06T00:00:00Z");

        // Throughput in elements/sec — criterion reports elements/sec
        // when given Throughput::Elements; lets the curve show
        // events-aggregated-per-second directly.
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &events, |b, evs| {
            b.iter(|| compute_aggregate(black_box(evs), window_start, window_end, None, |e| e.ts));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_aggregate);
criterion_main!(benches);
