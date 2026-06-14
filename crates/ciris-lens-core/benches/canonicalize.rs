//! `canonicalize` — `ciris_persist::prelude::canonicalize_envelope_for_signing`
//! over a synthesized envelope `serde_json::Value`, swept geometrically
//! across body size (docs/BENCHMARKS.md).
//!
//! Lens-core's signing hot path canonicalizes the envelope once per
//! detection event via `crate::wire::canonical_bytes(&BatchEnvelope)`
//! which calls `serde_json::to_value(envelope)` then this function.
//! The `to_value` step is constant per envelope shape; the
//! `canonicalize_envelope_for_signing` step is what scales with body
//! size — so benching the underlying primitive directly gives the
//! same shape-of-curve information without having to construct a
//! schema-current `BatchEnvelope` (the typed struct shifts across
//! persist minor versions; the underlying `Value` interface is
//! stable).
//!
//! # Expected curve (per BENCHMARKS.md "Reading the curves")
//!
//! Linear in body size — persist's canonicalizer writes the bytes
//! verbatim plus a fixed-size domain-separated frame. Non-linear ⇒
//! canonicalization started re-serializing the body (AV-5 regression,
//! CIRISPersist#7 trap).

#![allow(
    clippy::pedantic,
    clippy::needless_pass_by_value,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::items_after_statements,
    clippy::needless_raw_string_hashes
)]

use ciris_persist::prelude::canonicalize_envelope_for_signing;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde_json::json;

/// Build an envelope-shaped `serde_json::Value` whose payload field
/// is approximately the requested byte size. The shape is whatever
/// `canonicalize_envelope_for_signing` accepts; we deliberately use
/// `Value` not `BatchEnvelope` so the bench is decoupled from the
/// typed schema (which moves across persist minor versions).
fn make_envelope(body_size: usize) -> serde_json::Value {
    // Surrounding envelope JSON adds ≈ 200 bytes; pad to land near
    // the requested total size.
    let payload_size = body_size.saturating_sub(200);
    let filler = "x".repeat(payload_size);

    json!({
        "events": [],
        "batch_timestamp": "2026-06-05T12:00:00Z",
        "consent_timestamp": "2026-06-05T12:00:00Z",
        "trace_level": "generic",
        "trace_schema_version": "2.7.legacy",
        "filler_for_body_size_sweep": filler,
    })
}

fn bench_canonicalize(c: &mut Criterion) {
    // Sweep body size geometrically — same shape persist + edge bench
    // their canonical paths against. Picks up linearity violations
    // visually across the curve, not from a single fixed-size sample.
    let sizes = [256usize, 1_024, 4_096, 16_384, 65_536, 262_144];
    let mut group = c.benchmark_group("canonicalize");
    for size in sizes {
        let envelope = make_envelope(size);
        // Account each iteration as the *envelope bytes processed*.
        // criterion's Throughput::Bytes lets the report give MB/s.
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &envelope, |b, env| {
            b.iter(|| canonicalize_envelope_for_signing(black_box(env)))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_canonicalize);
criterion_main!(benches);
