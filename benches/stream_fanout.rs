//! Sustained multi-stream seal throughput — the publisher-side CPU cost of a
//! large room, MEASURED in a real loop instead of divided out of a single-op
//! microbench.
//!
//! The capability page / FSD §4 claim "2,000 blob streams ≈ 6-10% of one core"
//! was arithmetic: single `seal_av_inner` cost × stream count. This bench seals
//! `N` distinct blob streams for one 30 fps frame-tick in a sustained loop, so
//! the reported time/iter includes allocator pressure, cache behaviour, and
//! nonce derivation at scale — i.e. the true aggregate, not a per-op ideal.
//!
//! Read the result as core-fraction: `time_per_iter × 30 fps` = seconds of CPU
//! spent per wall-second to keep `N` streams sealed at 30 fps. At N=2,000 that
//! quotient is the honest "% of a core" the page should quote.
//!
//! In-memory only — there is no egress here; the real-world ceiling is donated
//! uplink (FSD §2-§3), not this CPU number. Run: `cargo bench --bench stream_fanout`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use ciris_edge::transport::realtime_av::{
    seal_av_inner, ChunkLayer, ChunkSeq, Epoch, EpochDek, StreamId, CODEC_OPAQUE,
};

const BLOB: usize = 208; // ~50 kbps blinking-dot blob @30fps frame

fn dek() -> EpochDek {
    EpochDek::from_bytes([0x3c; 32])
}

/// Distinct stream id per publisher so nonce derivation can't be hoisted.
fn stream_id(i: usize) -> StreamId {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&(i as u64).to_le_bytes());
    StreamId(b)
}

/// Seal one 30fps frame-tick across `n` distinct blob streams.
fn seal_tick(n: usize, frame: &[u8], dek: &EpochDek, seq: u64) -> usize {
    for i in 0..n {
        let sealed = seal_av_inner(
            frame,
            dek,
            stream_id(i),
            Epoch(1),
            ChunkSeq(seq),
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .expect("inner seal");
        black_box(&sealed);
    }
    n
}

fn bench_stream_fanout(c: &mut Criterion) {
    let frame: Vec<u8> = (0..BLOB as u32).map(|i| (i * 7 % 251) as u8).collect();
    let dek = dek();

    let mut g = c.benchmark_group("stream_fanout_seal_tick");
    // One iteration = sealing all N streams once (one 30fps frame-tick).
    for &n in &[500usize, 1000, 2000] {
        g.throughput(Throughput::Elements(n as u64));
        g.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let mut seq = 0u64;
            b.iter(|| {
                seq = seq.wrapping_add(1);
                black_box(seal_tick(n, &frame, &dek, seq))
            });
        });
    }
    g.finish();
}

criterion_group!(benches, bench_stream_fanout);
criterion_main!(benches);
