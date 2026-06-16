//! Multi-tier ALM relay chain — the cost of forwarding a sealed A/V chunk through
//! a tree of peer relays, now that CIRISEdge#149 ships the relay outer-open
//! primitive (`open_av_outer`, edge v4.2.0). Each interior hop opens the inbound
//! per-link outer AEAD and re-seals for its downstream link **without ever
//! touching the epoch DEK** — so the inner E2E ciphertext survives arbitrarily
//! many hops (publisher → relay → relay → … → viewer).
//!
//! This is the CIRISServer side of the 2,000-stream / multi-tier scale picture
//! (FSD/PQC_AV_STREAMING_BENCH.md §3–§4): a 2,000-room is a 3–4-tier ALM tree, so
//! the load-bearing per-frame cost is one relay hop × depth. The correctness
//! invariant (inner bytes survive the chain) is gated in `tests/alm_chain.rs`.
//! Run: `cargo bench --bench alm_chain`.
#![allow(clippy::doc_lazy_continuation)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use ciris_edge::transport::realtime_av::{
    open_av_chunk, open_av_outer, seal_av_inner, seal_av_outer, ChunkLayer, ChunkSeq, Epoch,
    EpochDek, SealedAvChunk, StreamId, CODEC_OPAQUE,
};

const BLOB: usize = 208; // ~50 kbps blinking-dot blob @30fps
const FULL: usize = 16 * 1024; // typical 720p inter-frame

fn stream() -> StreamId {
    StreamId([0x7a; 32])
}
fn dek() -> EpochDek {
    EpochDek::from_bytes([0x3c; 32])
}

/// `tiers` relay hops ⇒ `tiers+1` per-link outer keys/ids (publisher→t1, …, tN→viewer).
fn keys_links(tiers: usize) -> (Vec<[u8; 32]>, Vec<Vec<u8>>) {
    let keys = (0..=tiers).map(|i| [0x40 + i as u8; 32]).collect();
    let links = (0..=tiers)
        .map(|i| format!("alm-hop-{i:02}").into_bytes())
        .collect();
    (keys, links)
}

/// Publisher seals once; the chunk traverses `keys.len()-1` relay hops (each an
/// `open_av_outer` + `seal_av_outer`); returns the final wire the viewer opens.
fn relay_chain(
    frame: &[u8],
    dek: &EpochDek,
    keys: &[[u8; 32]],
    links: &[Vec<u8>],
    seq: u64,
) -> SealedAvChunk {
    let inner = seal_av_inner(
        frame,
        dek,
        stream(),
        Epoch(1),
        ChunkSeq(seq),
        CODEC_OPAQUE,
        ChunkLayer::BASE,
    )
    .expect("inner seal");
    let mut sealed = seal_av_outer(&inner, &keys[0], &links[0], seq).expect("outer seal");
    for i in 1..keys.len() {
        let recovered =
            open_av_outer(&sealed, &keys[i - 1], &links[i - 1], seq).expect("relay open");
        sealed = seal_av_outer(&recovered, &keys[i], &links[i], seq).expect("relay reseal");
    }
    sealed
}

// ── 1. One relay hop: open inbound outer + re-seal outbound (the per-tier cost) ─
fn bench_chain_hop(c: &mut Criterion) {
    let mut g = c.benchmark_group("alm_chain_hop");
    for &size in &[BLOB, FULL] {
        let frame = vec![0xABu8; size];
        let dek = dek();
        let (keys, links) = keys_links(1);
        let inner = seal_av_inner(
            &frame,
            &dek,
            stream(),
            Epoch(1),
            ChunkSeq(1),
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .expect("inner");
        let inbound = seal_av_outer(&inner, &keys[0], &links[0], 1).expect("inbound");
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(size), &inbound, |b, inbound| {
            b.iter(|| {
                let rec = open_av_outer(black_box(inbound), &keys[0], &links[0], 1).expect("open");
                black_box(seal_av_outer(&rec, &keys[1], &links[1], 1).expect("reseal"))
            });
        });
    }
    g.finish();
}

// ── 2. End-to-end through 1/2/3/4 tiers (a 2,000-room is 3–4 tiers) ───────────
fn bench_chain_e2e(c: &mut Criterion) {
    let frame = vec![0xABu8; BLOB];
    let dek = dek();
    let mut g = c.benchmark_group("alm_chain_e2e_blob");
    for &tiers in &[1usize, 2, 3, 4] {
        let (keys, links) = keys_links(tiers);
        let last = keys.len() - 1;
        g.bench_with_input(BenchmarkId::new("tiers", tiers), &tiers, |b, _| {
            let mut seq = 0u64;
            b.iter(|| {
                seq += 1;
                let sealed = relay_chain(black_box(&frame), &dek, &keys, &links, seq);
                black_box(
                    open_av_chunk(&sealed, &keys[last], &links[last], seq, &dek)
                        .expect("viewer open"),
                )
            });
        });
    }
    g.finish();
}

criterion_group!(benches, bench_chain_hop, bench_chain_e2e);
criterion_main!(benches);
