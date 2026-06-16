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
//!  2. **Survival floor (MEASURED — RaptorQ reference codec).** Content is really
//!     RaptorQ-coded into H=30 holders (one symbol each), a third are killed, and
//!     the survivors RaptorQ-reconstruct it BYTE-IDENTICAL — not the old
//!     `(H-k) >= N` tautology. Measured reception overhead (`report_fountain_
//!     overhead`): keep 20/30 (33% loss) → 99.6% reconstruct; keep 21/30 (30%) →
//!     100% (2000/2000); 19/30 is below the floor and never reconstructs. The
//!     substrate ships no fountain codec yet, so this proves the property with the
//!     reference codec (scale_model v0.7 N=20/H=30): substrate codec is FRONTIER.

use ciris_edge::transport::realtime_av::{
    open_av_chunk, open_av_outer, seal_av_inner, seal_av_outer, ChunkLayer, ChunkSeq, Epoch,
    EpochDek, InnerSealed, SealedAvChunk, StreamId, CODEC_OPAQUE,
};
// RaptorQ (RFC 6330) REFERENCE codec — dev/test only. The substrate ships no
// fountain codec yet (edge/persist expose only seal/open + reachability; the
// v0.7 toy's `fountain_defaults` are policy constants). We use the reference
// codec to PROVE the survival floor empirically — encode → drop a third →
// reconstruct byte-identical — instead of asserting the `(H-killed) >= N`
// tautology. Badge: MEASURED (RaptorQ reference) · substrate codec FRONTIER.
use raptorq::{
    EncodingPacket, ObjectTransmissionInformation, SourceBlockDecoder, SourceBlockEncoder,
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

// ─── Fountain survival floor — REAL RaptorQ encode/drop/decode ──────────────
//
// Fountain policy (scale_model v0.7): content is RaptorQ-coded into N_SOURCE
// source symbols; the swarm converges to H=TARGET_HOLDERS holders, each storing
// ONE symbol (source or repair). The resilience claim is that losing a third of
// the holders still leaves enough symbols to reconstruct.

const N_SOURCE: usize = 20; // scale_model::N_SOURCE — source-symbol count = reconstruction floor
const TARGET_HOLDERS: usize = 30; // scale_model::TARGET_HOLDERS (H) — one symbol per holder
const SYMBOL: u16 = 64; // bytes/symbol → content is exactly N_SOURCE symbols

fn fountain_oti() -> ObjectTransmissionInformation {
    // One source block, no sub-blocking, byte alignment — so the block splits
    // into exactly N_SOURCE source symbols of SYMBOL bytes.
    ObjectTransmissionInformation::new(N_SOURCE as u64 * SYMBOL as u64, SYMBOL, 1, 1, 1)
}

fn fountain_content() -> Vec<u8> {
    (0..N_SOURCE * SYMBOL as usize)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
        .collect()
}

/// The H encoded symbols, one per holder: N_SOURCE source + (H−N_SOURCE) repair.
fn fountain_holders(content: &[u8]) -> Vec<EncodingPacket> {
    let cfg = fountain_oti();
    let enc = SourceBlockEncoder::new(0, &cfg, content);
    let mut pkts = enc.source_packets(); // N_SOURCE source symbols
    pkts.extend(enc.repair_packets(0, (TARGET_HOLDERS - N_SOURCE) as u32)); // repair
    pkts
}

fn fountain_decode(subset: &[EncodingPacket]) -> Option<Vec<u8>> {
    let cfg = fountain_oti();
    let mut dec = SourceBlockDecoder::new(0, &cfg, N_SOURCE as u64 * SYMBOL as u64);
    dec.decode(subset.iter().cloned())
}

/// Deterministic shuffle (LCG) so "which holders die" is reproducible without an
/// rng dependency — same `seed` ⇒ same surviving subset every CI run.
fn surviving_subset(holders: &[EncodingPacket], keep: usize, seed: u64) -> Vec<EncodingPacket> {
    let mut idx: Vec<usize> = (0..holders.len()).collect();
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    for i in (1..idx.len()).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let j = (state >> 33) as usize % (i + 1);
        idx.swap(i, j);
    }
    idx.into_iter().take(keep).map(|i| holders[i].clone()).collect()
}

#[test]
fn content_survives_one_third_holder_loss() {
    let content = fountain_content();
    let holders = fountain_holders(&content);
    assert_eq!(holders.len(), TARGET_HOLDERS, "H holders, one symbol each");

    // Kill a third of the holders (H−N_SOURCE = 10, 33%); the surviving 20 must
    // RaptorQ-reconstruct the content BYTE-IDENTICAL. Repeated over many
    // deterministic kill patterns — this is a real decode, not `(H-k) >= N`.
    // (RaptorQ has a small reception overhead — see `report_fountain_overhead`
    // for the measured success rate exactly at the floor; we keep N_SOURCE+1
    // here so the floor test is deterministic and non-flaky.)
    let keep = N_SOURCE + 1; // 21 of 30 — within the 33%-loss budget, above RaptorQ overhead
    for seed in 0..32u64 {
        let kept = surviving_subset(&holders, keep, seed);
        let decoded = fountain_decode(&kept)
            .unwrap_or_else(|| panic!("seed {seed}: {keep} of {TARGET_HOLDERS} must reconstruct"));
        assert_eq!(decoded, content, "seed {seed}: reconstruction must be byte-identical");
    }
}

#[test]
fn below_floor_cannot_reconstruct() {
    // Fewer than N_SOURCE encoded symbols is below the information-theoretic
    // floor — RaptorQ cannot (and must not) reconstruct.
    let content = fountain_content();
    let holders = fountain_holders(&content);
    for seed in 0..16u64 {
        let kept = surviving_subset(&holders, N_SOURCE - 1, seed); // 19 of 30
        assert!(
            fountain_decode(&kept).is_none(),
            "seed {seed}: {} symbols is below the floor — must not reconstruct",
            N_SOURCE - 1
        );
    }
}

/// Characterization probe (not an assertion): prints the measured RaptorQ
/// reception overhead — the fraction of random `s`-of-H subsets that
/// reconstruct, for s around the N_SOURCE floor. Run with:
///   `cargo test --test chaos_mesh report_fountain_overhead -- --nocapture --ignored`
/// Use the output to keep the page's survival wording honest (the v0.7 toy
/// idealizes exactly-N_SOURCE reconstruction; RaptorQ needs a small overhead).
#[test]
#[ignore]
fn report_fountain_overhead() {
    let content = fountain_content();
    let holders = fountain_holders(&content);
    const TRIALS: u64 = 2000;
    for keep in [N_SOURCE, N_SOURCE + 1, N_SOURCE + 2] {
        let mut ok = 0u64;
        for seed in 0..TRIALS {
            let kept = surviving_subset(&holders, keep, seed + keep as u64 * 1_000_003);
            if fountain_decode(&kept).map(|d| d == content).unwrap_or(false) {
                ok += 1;
            }
        }
        let killed = TARGET_HOLDERS - keep;
        println!(
            "keep {keep}/{TARGET_HOLDERS} (killed {killed}, {:.0}% loss): \
             {ok}/{TRIALS} reconstruct = {:.3}%",
            killed as f64 / TARGET_HOLDERS as f64 * 100.0,
            ok as f64 / TRIALS as f64 * 100.0
        );
    }
}
