//! CIRISEdge#149 invariant gate: the inner E2E ciphertext survives an arbitrary
//! multi-tier ALM relay chain. Each relay hop opens the inbound per-link outer
//! AEAD (`open_av_outer`) and re-seals for its downstream link — **never touching
//! the epoch DEK** — so a publisher's plaintext is recovered byte-identical at the
//! viewer after N relay→relay hops. This is the correctness backbone of the
//! multi-tier scale claim (FSD/PQC_AV_STREAMING_BENCH.md §4); the cost is in
//! `benches/alm_chain.rs`.

use ciris_edge::transport::realtime_av::{
    open_av_chunk, open_av_outer, seal_av_inner, seal_av_outer, ChunkLayer, ChunkSeq, Epoch,
    EpochDek, StreamId, CODEC_OPAQUE,
};

#[test]
fn inner_e2e_survives_relay_chain() {
    let frame: Vec<u8> = (0..208u32).map(|i| (i % 251) as u8).collect();
    let dek = EpochDek::from_bytes([0x3c; 32]);
    let stream = StreamId([0x7a; 32]);

    for tiers in 1..=5 {
        // `tiers` relay hops ⇒ tiers+1 per-link outer keys (publisher→…→viewer).
        let keys: Vec<[u8; 32]> = (0..=tiers).map(|i| [0x40 + i as u8; 32]).collect();
        let links: Vec<Vec<u8>> = (0..=tiers)
            .map(|i| format!("hop-{i}").into_bytes())
            .collect();

        let inner = seal_av_inner(
            &frame,
            &dek,
            stream,
            Epoch(1),
            ChunkSeq(1),
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .expect("inner seal");
        let mut sealed = seal_av_outer(&inner, &keys[0], &links[0], 1).expect("publisher outer");

        // Each interior relay opens its inbound outer + re-seals downstream.
        for i in 1..keys.len() {
            let recovered =
                open_av_outer(&sealed, &keys[i - 1], &links[i - 1], 1).expect("relay outer-open");
            sealed = seal_av_outer(&recovered, &keys[i], &links[i], 1).expect("relay reseal");
        }

        let last = keys.len() - 1;
        let opened =
            open_av_chunk(&sealed, &keys[last], &links[last], 1, &dek).expect("viewer open");
        assert_eq!(
            opened, frame,
            "E2E plaintext corrupted after {tiers} relay hops"
        );
    }
}

#[test]
fn wrong_outer_key_at_a_hop_fails_closed() {
    // A relay with the wrong inbound transit key cannot recover the chunk — the
    // outer AEAD fails closed (no silent passthrough of garbage downstream).
    let frame = vec![0xABu8; 208];
    let dek = EpochDek::from_bytes([0x3c; 32]);
    let stream = StreamId([0x7a; 32]);
    let inner = seal_av_inner(
        &frame,
        &dek,
        stream,
        Epoch(1),
        ChunkSeq(1),
        CODEC_OPAQUE,
        ChunkLayer::BASE,
    )
    .expect("inner");
    let sealed = seal_av_outer(&inner, &[0x40; 32], b"hop-0", 1).expect("outer");
    assert!(
        open_av_outer(&sealed, &[0x99; 32], b"hop-0", 1).is_err(),
        "outer-open with the wrong transit key must fail, not pass garbage"
    );
}
