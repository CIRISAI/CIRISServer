//! PQC realtime A/V streaming — end-to-end benchmark (CIRISEdge#62 realtime_av
//! profile, CEG 0.13 §10.5.8). Run: `cargo bench --bench pqc_av_streaming`.
//!
//! Measures the actual per-frame and per-link cost a CIRIS fabric node pays to
//! ship group video/voice over the **hybrid-PQC two-layer crypto** the edge
//! realtime mesh defines:
//!
//! ```text
//! wire = OuterAEAD( transit_key, OuterNonce,
//!           InnerAEAD( epoch_dek, InnerNonce, frame_plaintext ) )
//! ```
//!
//! - **Inner** (AES-256-GCM under the per-`(stream,epoch)` DEK) — end-to-end:
//!   relays/SFUs never see plaintext. Identical across the whole mesh for a
//!   given `(stream,epoch,chunk_seq)` (deterministic nonce).
//! - **Outer** (AES-256-GCM under the per-Link transit key) — hop authenticity
//!   + replay binding. The transit key is the output of the **hybrid
//!   X25519+ML-KEM-768 KEX** (`federation_session`, CIRISEdge#54) — that handshake
//!   is the post-quantum half, amortized per peer-link, benched in `pqc_kex`.
//!
//! ## What's measured
//!
//! 1. `av_frame_e2e`     — full per-frame round-trip (seal → wire codec → open)
//!                          across realistic A/V frame sizes. The hot loop.
//! 2. `av_frame_halves`  — seal-only vs open-only at one size (sender/receiver split).
//! 3. `pqc_kex`          — hybrid vs classical KEX initiate+respond (per-link, amortized).
//! 4. `av_mesh_fanout`   — per-frame SENDER cost for a room of N, two ways:
//!                          `naive` (current API: N× full seal) vs `shared_inner`
//!                          (1× inner-seal reused across the mesh + N× outer-seal).
//!                          Quantifies the optimization headroom for large rooms.
//! 5. `av_fanout_plan`   — the entitled∧reachable fan-out planner over N peers.
//!
//! Derived metrics (fps ceiling, max mesh size at 30 fps) are computed from these
//! in the run report, not here.
#![allow(clippy::doc_lazy_continuation, clippy::doc_overindented_list_items)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use ciris_crypto::{aes_gcm, ml_kem, x25519};
use ciris_edge::reachability::{AttemptOutcome, ReachabilityTracker};
use ciris_edge::transport::federation_session::{
    FederationSession, KexAlgorithm, OwnKexKeys, PeerKexPubkeys,
};
use ciris_edge::transport::realtime_av::{
    derive_inner_nonce, derive_outer_nonce, open_av_chunk, seal_av_chunk, ChunkSeq, Epoch,
    EpochDek, MeshParticipant, RealtimeFanout, StreamId, REALTIME_MIN_RATIO,
};
use ciris_edge::transport::TransportId;

/// Realistic A/V frame sizes (codec output, pre-seal):
///   320 B  — Opus voice frame (~20 ms @ 128 kbps)
///   4 KiB  — low-motion 720p inter-frame (VP9/AV1)
///   16 KiB — typical 720p inter-frame
///   64 KiB — 1080p inter-frame / 720p keyframe
///   256 KiB— 1080p keyframe
const FRAME_SIZES: &[usize] = &[320, 4 * 1024, 16 * 1024, 64 * 1024, 256 * 1024];

const TRANSIT_KEY: [u8; 32] = [0x11; 32];
const LINK_ID: &[u8] = b"rns-link-bench-0001";

fn stream() -> StreamId {
    StreamId([0x7a; 32])
}
fn dek() -> EpochDek {
    EpochDek::from_bytes([0x3c; 32])
}

// ── 1. Per-frame end-to-end (one participant link) ───────────────────────────
fn bench_frame_e2e(c: &mut Criterion) {
    let mut g = c.benchmark_group("av_frame_e2e");
    for &size in FRAME_SIZES {
        let frame = vec![0xABu8; size];
        let dek = dek();
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(size), &frame, |b, frame| {
            let mut seq = 0u64;
            b.iter(|| {
                seq += 1;
                // Sender: two-layer seal → on-wire bytes.
                let sealed = seal_av_chunk(
                    black_box(frame),
                    &TRANSIT_KEY,
                    LINK_ID,
                    seq,
                    &dek,
                    stream(),
                    Epoch(1),
                    ChunkSeq(seq),
                )
                .expect("seal");
                let wire = sealed.to_bytes();
                // Receiver: parse wire → two-layer open → plaintext.
                let parsed = ciris_edge::transport::realtime_av::SealedAvChunk::from_bytes(&wire)
                    .expect("parse");
                let opened =
                    open_av_chunk(&parsed, &TRANSIT_KEY, LINK_ID, seq, &dek).expect("open");
                black_box(opened)
            });
        });
    }
    g.finish();
}

// ── 2. Sender vs receiver split at a representative size ──────────────────────
fn bench_frame_halves(c: &mut Criterion) {
    const SIZE: usize = 64 * 1024;
    let frame = vec![0xABu8; SIZE];
    let dek = dek();

    let mut g = c.benchmark_group("av_frame_halves");
    g.throughput(Throughput::Bytes(SIZE as u64));

    g.bench_function("seal_64KiB", |b| {
        let mut seq = 0u64;
        b.iter(|| {
            seq += 1;
            black_box(
                seal_av_chunk(
                    black_box(&frame),
                    &TRANSIT_KEY,
                    LINK_ID,
                    seq,
                    &dek,
                    stream(),
                    Epoch(1),
                    ChunkSeq(seq),
                )
                .expect("seal"),
            )
        });
    });

    // Pre-seal a chunk so open() is measured in isolation.
    let pre = seal_av_chunk(
        &frame,
        &TRANSIT_KEY,
        LINK_ID,
        7,
        &dek,
        stream(),
        Epoch(1),
        ChunkSeq(7),
    )
    .expect("pre-seal");
    g.bench_function("open_64KiB", |b| {
        b.iter(|| {
            black_box(open_av_chunk(black_box(&pre), &TRANSIT_KEY, LINK_ID, 7, &dek).expect("open"))
        });
    });

    g.finish();
}

// ── 3. The post-quantum half: hybrid vs classical KEX (per-link, amortized) ──
fn bench_pqc_kex(c: &mut Criterion) {
    // Responder long-term-ish KEX keys (generated once, outside the loop).
    let (x_priv, x_pub) = x25519::generate_ephemeral_keypair().expect("x25519");
    let (mlkem_priv, mlkem_pub) = ml_kem::generate_keypair().expect("ml-kem");
    let own_hybrid = OwnKexKeys {
        x25519_priv: x_priv,
        mlkem768_priv: Some(mlkem_priv.clone()),
        mlkem768_pub: Some(mlkem_pub.clone()),
    };
    let peer_hybrid = PeerKexPubkeys {
        x25519_pub: x_pub,
        mlkem768_pub: Some(mlkem_pub.clone()),
    };
    let peer_classical = PeerKexPubkeys {
        x25519_pub: x_pub,
        mlkem768_pub: None,
    };
    let own_classical = OwnKexKeys {
        x25519_priv: x_priv,
        mlkem768_priv: None,
        mlkem768_pub: None,
    };

    let mut g = c.benchmark_group("pqc_kex");

    // Hybrid X25519 + ML-KEM-768 — the harvest-now-decrypt-later-resistant path.
    g.bench_function("hybrid_initiate", |b| {
        b.iter(|| {
            black_box(
                FederationSession::initiate(black_box(&peer_hybrid), KexAlgorithm::Hybrid)
                    .expect("hybrid initiate"),
            )
        });
    });
    let (hybrid_msg, _k) =
        FederationSession::initiate(&peer_hybrid, KexAlgorithm::Hybrid).expect("hybrid initiate");
    g.bench_function("hybrid_respond", |b| {
        b.iter(|| {
            black_box(
                FederationSession::respond(black_box(&own_hybrid), black_box(&hybrid_msg))
                    .expect("hybrid respond"),
            )
        });
    });

    // Classical X25519-only — the fallback, for overhead comparison.
    g.bench_function("classical_initiate", |b| {
        b.iter(|| {
            black_box(
                FederationSession::initiate(black_box(&peer_classical), KexAlgorithm::Classical)
                    .expect("classical initiate"),
            )
        });
    });
    let (classical_msg, _k) = FederationSession::initiate(&peer_classical, KexAlgorithm::Classical)
        .expect("classical initiate");
    g.bench_function("classical_respond", |b| {
        b.iter(|| {
            black_box(
                FederationSession::respond(black_box(&own_classical), black_box(&classical_msg))
                    .expect("classical respond"),
            )
        });
    });

    g.finish();
}

// ── 4. Per-frame mesh fan-out: current API vs shared-inner optimization ───────
//
// The sender ships one frame to N participants. Inner seal (E2E DEK) is IDENTICAL
// across the mesh for a given (stream,epoch,chunk_seq); only the outer (per-Link)
// seal differs. The current `seal_av_chunk` re-does BOTH per participant. This
// bench measures that vs an inner-once / outer-N path to size the headroom that
// the Phase 1.x SFU/large-room surface can claim.
fn bench_mesh_fanout(c: &mut Criterion) {
    const SIZE: usize = 16 * 1024; // typical 720p inter-frame
    let frame = vec![0xABu8; SIZE];
    let dek = dek();
    let mesh_sizes = [2usize, 8, 50]; // 50 = the realtime mesh cap before SFU crossover

    let mut g = c.benchmark_group("av_mesh_fanout");
    for &n in &mesh_sizes {
        // Distinct per-Link ids (outer nonce binds to link_id).
        let links: Vec<Vec<u8>> = (0..n)
            .map(|i| format!("link-{i:04}").into_bytes())
            .collect();
        g.throughput(Throughput::Bytes(SIZE as u64)); // one logical frame, regardless of N

        // Current API: full two-layer seal per participant.
        g.bench_with_input(BenchmarkId::new("naive", n), &n, |b, _| {
            let mut seq = 0u64;
            b.iter(|| {
                seq += 1;
                for link in &links {
                    black_box(
                        seal_av_chunk(
                            black_box(&frame),
                            &TRANSIT_KEY,
                            link,
                            seq,
                            &dek,
                            stream(),
                            Epoch(1),
                            ChunkSeq(seq),
                        )
                        .expect("seal"),
                    );
                }
            });
        });

        // Optimization: inner-seal once (shared E2E ciphertext), outer-seal per Link.
        // Mirrors seal_av_chunk's internals (same nonces, same AEAD).
        g.bench_with_input(BenchmarkId::new("shared_inner", n), &n, |b, _| {
            let mut seq = 0u64;
            b.iter(|| {
                seq += 1;
                let inner_nonce = derive_inner_nonce(stream(), Epoch(1), ChunkSeq(seq));
                let inner = aes_gcm::encrypt(dek.as_bytes(), &inner_nonce, black_box(&frame))
                    .expect("inner seal");
                for link in &links {
                    let outer_nonce = derive_outer_nonce(link, seq);
                    black_box(
                        aes_gcm::encrypt(&TRANSIT_KEY, &outer_nonce, &inner).expect("outer seal"),
                    );
                }
            });
        });
    }
    g.finish();
}

// ── 5. Fan-out planner: entitled∧reachable filter cost ────────────────────────
fn bench_fanout_plan(c: &mut Criterion) {
    const N: usize = 50;
    let transport_id = TransportId("reticulum");
    let tracker = ReachabilityTracker::new(60);
    let participants: Vec<MeshParticipant> = (0..N)
        .map(|i| {
            let id = format!("peer-{i:04}");
            // Mark ~80% reachable so the filter does real work.
            for k in 0..10 {
                let outcome = if k < 8 {
                    AttemptOutcome::SendSuccess
                } else {
                    AttemptOutcome::SendFailure {
                        error_class: "timeout".into(),
                    }
                };
                tracker.record_attempt(&id, transport_id, outcome);
            }
            MeshParticipant {
                peer_key_id: id,
                link_id: format!("link-{i:04}").into_bytes(),
            }
        })
        .collect();

    c.bench_function("av_fanout_plan_50", |b| {
        b.iter(|| {
            black_box(RealtimeFanout::plan(
                black_box(&participants),
                &tracker,
                transport_id,
                REALTIME_MIN_RATIO,
            ))
        });
    });
}

criterion_group!(
    benches,
    bench_frame_e2e,
    bench_frame_halves,
    bench_pqc_kex,
    bench_mesh_fanout,
    bench_fanout_plan
);
criterion_main!(benches);
