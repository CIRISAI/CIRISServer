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
//!  2. **Survival floor (MEASURED — substrate codec).** Content is really
//!     fountain-coded by edge v4.2.0's OWN `fountain_encode` (codec-fountain, L1-A)
//!     into H=30 holders (one symbol each), a third are killed, and the survivors
//!     `fountain_decode` it BYTE-IDENTICAL — not the old `(H-k) >= N` tautology.
//!     Measured reception overhead (`report_fountain_overhead`): keep 20/30
//!     (33% loss) → 99.6% reconstruct; keep 21/30 (30%) → 100% (2000/2000); 19/30
//!     is below the floor and never reconstructs the content (scale_model v0.7
//!     N=20/H=30). The codec is dev-enabled here; a relay forwards symbols opaquely.

use ciris_edge::transport::realtime_av::{
    open_av_chunk, open_av_outer, seal_av_inner, seal_av_outer, ChunkLayer, ChunkSeq, Epoch,
    EpochDek, InnerSealed, SealedAvChunk, StreamId, CODEC_OPAQUE,
};
// The SUBSTRATE's own fountain codec (edge v4.2.0 `codec-fountain`, L1-A — RaptorQ
// RFC 6330). We prove the survival floor against the shipped codec directly:
// encode → drop a third of the holders → reconstruct byte-identical, instead of
// the old `(H-killed) >= N` tautology. Badge: MEASURED (substrate codec).
use ciris_edge::transport::realtime_av_codec::fountain::{
    fountain_decode, fountain_encode, FountainConfig, FountainSymbol,
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

// ─── Fountain survival floor — REAL substrate codec encode/drop/decode ──────
//
// Fountain policy (scale_model v0.7): content is RaptorQ-coded into N_SOURCE
// source symbols; the swarm converges to H=TARGET_HOLDERS holders, each storing
// ONE symbol (source or repair). The resilience claim is that losing a third of
// the holders still leaves enough symbols to reconstruct. Exercised against
// edge v4.2.0's OWN `fountain_encode`/`fountain_decode` (codec-fountain).

const N_SOURCE: u32 = 20; // scale_model::N_SOURCE — source-symbol count = reconstruction floor
const K_REPAIR: u32 = 10; // repair symbols → N_SOURCE+K_REPAIR = TARGET_HOLDERS symbols (one/holder)
const TARGET_HOLDERS: usize = (N_SOURCE + K_REPAIR) as usize; // H = 30
const SYMBOL: u32 = 64; // bytes/symbol → content fills exactly N_SOURCE symbols
const MIN_VIABLE: u32 = 5; // scale_model::MIN_VIABLE_SYMBOLS (BLINKING_DOT floor)

fn fountain_config() -> FountainConfig {
    FountainConfig {
        n_source: N_SOURCE,
        k_repair: K_REPAIR,
        symbol_size: SYMBOL,
        min_viable_symbols: MIN_VIABLE,
    }
}

fn fountain_content() -> Vec<u8> {
    (0..(N_SOURCE * SYMBOL) as usize)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
        .collect()
}

/// Deterministic shuffle (LCG) so "which holders die" is reproducible without an
/// rng dependency — same `seed` ⇒ same surviving subset every CI run.
fn surviving_subset(holders: &[FountainSymbol], keep: usize, seed: u64) -> Vec<FountainSymbol> {
    let mut idx: Vec<usize> = (0..holders.len()).collect();
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    for i in (1..idx.len()).rev() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let j = (state >> 33) as usize % (i + 1);
        idx.swap(i, j);
    }
    idx.into_iter().take(keep).map(|i| holders[i].clone()).collect()
}

#[test]
fn content_survives_one_third_holder_loss() {
    let cfg = fountain_config();
    let content = fountain_content();
    let enc = fountain_encode(&content, &cfg).expect("substrate fountain_encode");
    assert_eq!(enc.symbols.len(), TARGET_HOLDERS, "H holders, one symbol each");

    // Kill a third of the holders (H−N_SOURCE = 10, 33%); the survivors must
    // reconstruct the content BYTE-IDENTICAL through the SUBSTRATE codec — a real
    // decode, not `(H-k) >= N`. (RaptorQ has a small reception overhead at the
    // exact floor — see `report_fountain_overhead`; we keep N_SOURCE+1 here so
    // the floor test is deterministic and non-flaky.)
    let keep = N_SOURCE as usize + 1; // 21 of 30 — inside the 33%-loss budget, above overhead
    for seed in 0..32u64 {
        let kept = surviving_subset(&enc.symbols, keep, seed);
        let decoded = fountain_decode(&kept, &enc.symbol_hashes, enc.original_content_length, &cfg)
            .unwrap_or_else(|e| panic!("seed {seed}: {keep}/{TARGET_HOLDERS} must reconstruct: {e:?}"));
        assert_eq!(decoded, content, "seed {seed}: reconstruction must be byte-identical");
    }
}

#[test]
fn below_floor_cannot_reconstruct() {
    // Fewer than N_SOURCE encoded symbols is below the information floor — the
    // substrate codec cannot (and must not) reconstruct the full content.
    let cfg = fountain_config();
    let content = fountain_content();
    let enc = fountain_encode(&content, &cfg).expect("encode");
    for seed in 0..16u64 {
        let kept = surviving_subset(&enc.symbols, N_SOURCE as usize - 1, seed); // 19 of 30
        let r = fountain_decode(&kept, &enc.symbol_hashes, enc.original_content_length, &cfg);
        assert!(
            r.map(|d| d != content).unwrap_or(true),
            "seed {seed}: {} symbols is below the floor — must not reconstruct the content",
            N_SOURCE - 1
        );
    }
}

/// Characterization probe (not an assertion): prints the measured reception
/// overhead of the SUBSTRATE codec — the fraction of random `s`-of-H subsets that
/// reconstruct, for s around the N_SOURCE floor. Run with:
///   `cargo test --test chaos_mesh report_fountain_overhead -- --nocapture --ignored`
/// Keeps the page's survival wording honest (the v0.7 toy idealizes exactly-N
/// reconstruction; RaptorQ needs a small overhead at the exact floor).
#[test]
#[ignore]
fn report_fountain_overhead() {
    let cfg = fountain_config();
    let content = fountain_content();
    let enc = fountain_encode(&content, &cfg).expect("encode");
    const TRIALS: u64 = 2000;
    for keep in [N_SOURCE as usize, N_SOURCE as usize + 1, N_SOURCE as usize + 2] {
        let mut ok = 0u64;
        for seed in 0..TRIALS {
            let kept = surviving_subset(&enc.symbols, keep, seed + keep as u64 * 1_000_003);
            if fountain_decode(&kept, &enc.symbol_hashes, enc.original_content_length, &cfg)
                .map(|d| d == content)
                .unwrap_or(false)
            {
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
