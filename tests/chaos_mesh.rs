//! Chaos / resilience proofs for the realtime mesh — the guarantees the UX is
//! built against (FSD/PQC_AV_STREAMING_BENCH.md §4; the bench page's "Guaranteed
//! mesh characteristics"):
//!
//!  1. **Stream path-redundancy (proven).** A publisher's inner E2E chunk reaches
//!     a viewer over multiple disjoint relay paths (the ALM primary +
//!     `MAX_BACKUPS=2` backups). Any *surviving* path yields the identical
//!     plaintext — kill all but one and the stream continues. Shown at the
//!     crypto/transport layer with `open_av_outer` (CIRISEdge#149): the inner
//!     ciphertext is path-independent, only the outer per-link layer differs.
//!  2. **Survival floor (model).** Content is fountain-split into H=30 holders,
//!     any N=20 reconstruct. Losing up to H−N=10 holders (33%) still leaves ≥N →
//!     content survives. The combinatorial backbone of the binomial survival curve
//!     (scale_model v0.7).

use ciris_edge::transport::realtime_av::{
    open_av_chunk, open_av_outer, seal_av_inner, seal_av_outer, ChunkLayer, ChunkSeq, Epoch,
    EpochDek, InnerSealed, SealedAvChunk, StreamId, CODEC_OPAQUE,
};

fn stream() -> StreamId {
    StreamId([0x7a; 32])
}

fn publish(frame: &[u8], dek: &EpochDek, seq: u64) -> InnerSealed {
    seal_av_inner(
        frame,
        dek,
        stream(),
        Epoch(1),
        ChunkSeq(seq),
        CODEC_OPAQUE,
        ChunkLayer::BASE,
    )
    .expect("inner seal")
}

/// One independent relay PATH of `tiers` hops, salted by `path` so its per-link
/// keys/ids are disjoint from every other path. Returns the final wire + the
/// viewer's (transit key, link id) for that path.
fn path_deliver(
    inner: &InnerSealed,
    tiers: usize,
    path: u8,
    seq: u64,
) -> (SealedAvChunk, [u8; 32], Vec<u8>) {
    let keys: Vec<[u8; 32]> = (0..=tiers)
        .map(|i| [path.wrapping_mul(0x10) + i as u8 + 1; 32])
        .collect();
    let links: Vec<Vec<u8>> = (0..=tiers)
        .map(|i| format!("p{path}-hop-{i}").into_bytes())
        .collect();
    let mut sealed = seal_av_outer(inner, &keys[0], &links[0], seq).expect("publisher outer");
    for i in 1..keys.len() {
        let rec = open_av_outer(&sealed, &keys[i - 1], &links[i - 1], seq).expect("relay open");
        sealed = seal_av_outer(&rec, &keys[i], &links[i], seq).expect("relay reseal");
    }
    let last = keys.len() - 1;
    (sealed, keys[last], links[last].clone())
}

#[test]
fn stream_survives_loss_of_all_but_one_path() {
    let frame: Vec<u8> = (0..208u32).map(|i| (i * 7 % 251) as u8).collect();
    let dek = EpochDek::from_bytes([0x3c; 32]);
    let inner = publish(&frame, &dek, 1);

    // Primary + 2 backups (MAX_BACKUPS=2), disjoint paths at different depths.
    let paths = [
        path_deliver(&inner, 2, 0, 1),
        path_deliver(&inner, 3, 1, 1),
        path_deliver(&inner, 4, 2, 1),
    ];

    // Every path independently delivers the identical plaintext.
    for (i, (sealed, key, link)) in paths.iter().enumerate() {
        let opened =
            open_av_chunk(sealed, key, link, 1, &dek).unwrap_or_else(|e| panic!("path {i}: {e:?}"));
        assert_eq!(opened, frame, "path {i} must deliver identical plaintext");
    }

    // "Kill" the primary and the first backup; only the last backup survives →
    // the stream continues, identical bytes, no re-publish.
    let (sealed, key, link) = &paths[2];
    assert_eq!(
        open_av_chunk(sealed, key, link, 1, &dek).expect("survivor decodes"),
        frame,
        "stream must survive on the last remaining path"
    );
}

#[test]
fn content_survives_one_third_holder_loss() {
    // Fountain policy (scale_model v0.7): H holders, N reconstruct threshold.
    const H: usize = 30;
    const N: usize = 20;
    // RaptorQ property (MODEL): any subset of ≥ N of the H symbols reconstructs.
    let survives = |killed: usize| (H - killed) >= N;

    for killed in 0..=(H - N) {
        assert!(
            survives(killed),
            "content must survive {killed} holder losses"
        );
    }
    assert!(
        !survives(H - N + 1),
        "below N symbols, reconstruction is impossible"
    );
    assert_eq!(H - N, 10, "33% holder-loss tolerance at H=30/N=20");
}
