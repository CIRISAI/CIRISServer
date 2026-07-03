//! The NOISE FLOOR — provable individual-unrecoverability for erasure
//! compliance (CIRISServer#14, CEG 1.0-RC12 §19.7 / §19.3 N5).
//!
//! "Forgetting that still forgets" turned from principle into a MEASURED test
//! result. Three claims, each backed by the SHIPPED substrate surface (persist
//! v8.4.0 §19.7 storage + verify-core §19.7 verdicts + edge v4.3.0's OWN
//! `codec-fountain` RaptorQ codec) — not a reference stand-in:
//!
//!   (a) Revocation ⇒ hard delete. A revoked `content_id` has its original +
//!       every still-recoverable fountain symbol purged via the SHIPPED
//!       `evict_fountain_content_hard_delete` (the §19.7.3
//!       `EjectionVerdict::EjectHardDelete` path; revocation overrides rarity).
//!       The manifest survives as `EnvelopeOnly` provenance ("existed with
//!       signature X"); NO retained tier individually reconstructs.
//!
//!   (b) The MEASURED noise floor. After revocation/eviction, we try to
//!       reconstruct from EVERY retained-symbol count below the information
//!       floor using edge's REAL `fountain_decode`, and record the residual
//!       fidelity as a number. Below `n_source` symbols the substrate codec
//!       cannot reconstruct; the residual fidelity of any partial collapses to
//!       chance (~1/256 per byte). We assert it stays under a fidelity ε.
//!
//!   (c) Aggregation past the floor IS erasure. N source items collapse to 1
//!       composite via the SHIPPED §19.7 `put_aggregated_tier`
//!       (`AggregationMetaV1`, fan_in = N). The composite is admitted +
//!       PQC-verified; the individuals' symbols are then hard-deleted. We
//!       measure that NO single member is recoverable from the composite's
//!       retained symbols above the < 1/N gist bound — the individual is
//!       information-theoretically gone, only the N→1 aggregate remains.
//!
//! Badge: MEASURED (substrate surface). Backend = persist's SHIPPED
//! `SqliteBackend` (in-memory, migrated incl. V086 §19.7), available on every
//! target the server builds (Cargo.toml pins persist `sqlite` everywhere).
//! Codec = edge's `codec-fountain` (dev-dep feature, already enabled).
//!
//! Run the characterization numbers:
//!   cargo test --test noise_floor measured_noise_floor_numbers -- --nocapture --ignored

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner};
use ed25519_dalek::{Signer as _, SigningKey};

use ciris_persist::fountain::{
    aggregate_corpus_kind, member_commitment, symbol_sha256_hex, AggregationMetaV1,
    AggregationMetaVerifyInputsV1, FountainContent, FountainManifestV1, FountainSymbolV1,
    MANIFEST_VERSION_V1,
};
use ciris_persist::store::{Backend, SqliteBackend};
use ciris_persist::verify::PythonJsonDumpsCanonicalizer;

// edge v4.3.0's OWN fountain codec (codec-fountain, L1-A — RaptorQ RFC 6330).
// The SAME codec tests/chaos_mesh.rs proves the survival floor against; here we
// prove its COMPLEMENT — the erasure floor (what cannot come back).
use ciris_edge::transport::realtime_av_codec::fountain::{
    fountain_decode, fountain_encode, FountainConfig, FountainSymbol,
};

// ───────────────────────── codec parameters ─────────────────────────
// Mirror chaos_mesh.rs's scale_model so the floor we measure is the SAME floor
// the survival proof lives just above. N_SOURCE symbols is the information floor:
// RaptorQ needs >= N_SOURCE (+ small overhead) to reconstruct; below it the
// content is gone.
const N_SOURCE: u32 = 20;
const K_REPAIR: u32 = 10;
const TARGET_HOLDERS: usize = (N_SOURCE + K_REPAIR) as usize; // H = 30
const SYMBOL: u32 = 64;
const MIN_VIABLE: u32 = 5;

/// The measured-fidelity epsilon (claim b). A reconstruction "succeeds" only if
/// it is byte-identical; a partial below the floor is erased if its residual
/// fidelity (fraction of original bytes recovered) is at or below ε. ε is set an
/// order of magnitude above pure chance (1/256 ≈ 0.0039) to absorb structural
/// coincidence, while still being a hard erasure assertion.
const FIDELITY_EPSILON: f64 = 0.05;

fn codec_config() -> FountainConfig {
    FountainConfig {
        n_source: N_SOURCE,
        k_repair: K_REPAIR,
        symbol_size: SYMBOL,
        min_viable_symbols: MIN_VIABLE,
    }
}

/// Distinct deterministic payload per logical content (so a member is never
/// accidentally the gist of the aggregate).
fn payload_for(seed: u8) -> Vec<u8> {
    (0..(N_SOURCE * SYMBOL) as usize)
        .map(|i| {
            (i.wrapping_mul(31)
                .wrapping_add(7)
                .wrapping_add(usize::from(seed) * 0x9d)) as u8
        })
        .collect()
}

/// Fraction of bytes in `candidate` that match `original` at the same offset —
/// the MEASURED residual fidelity. 1.0 = perfect reconstruction; ~1/256 = chance.
fn residual_fidelity(candidate: &[u8], original: &[u8]) -> f64 {
    if original.is_empty() {
        return 0.0;
    }
    let n = candidate.len().min(original.len());
    let matched = (0..n).filter(|&i| candidate[i] == original[i]).count();
    // Missing bytes count as non-matches against the original length.
    matched as f64 / original.len() as f64
}

// ───────────────── structured / compressible payloads (#3) ─────────────────
// The original sweep only used `payload_for` (uniform LCG bytes). The #3 blind
// spot: a compressible / structured payload might leak more below the floor, or
// an informed adversary who already knows part of the plaintext might recover
// the rest. These generators produce COMPRESSIBLE content (long repetitive runs,
// short-period patterns, sparse marks) at the SAME source capacity the codec
// admits (N_SOURCE * SYMBOL bytes), so the below-floor sweep re-runs on them.

/// Run length for the block-constant payload. Deliberately SMALL (8-byte runs)
/// so a single lucky structural-guess block coincidence is << ε: one matched
/// 8-byte block over the 640-byte unknown half is 1.25% fidelity, and it takes
/// ≥5 simultaneous coincidences to approach ε — astronomically unlikely at the
/// per-block ~1/256 base rate. The runs still make the content trivially RLE-
/// compressible (160 constant runs → the "structured" case #3 asks for).
const BLOCK_RUN: usize = 8;

/// Block-constant payload: `BLOCK_RUN`-byte runs, each run a pseudo-random
/// constant that is INDEPENDENT of every other block. Compressible (long runs)
/// yet the unknown blocks are not derivable from the known ones — the honest
/// shape for a known-plaintext side-info test.
fn payload_runs(seed: u8) -> Vec<u8> {
    let n = (N_SOURCE * SYMBOL) as usize;
    let nblocks = n / BLOCK_RUN;
    let mut out = Vec::with_capacity(n);
    for b in 0..nblocks {
        let c = ((b
            .wrapping_mul(2_654_435_761)
            .wrapping_add(usize::from(seed).wrapping_mul(40_503)))
            >> 3) as u8;
        out.extend(std::iter::repeat_n(c, BLOCK_RUN));
    }
    out
}

/// Short-period repeating pattern — very low global entropy (period 4). Used in
/// the plain structured sweep (NOT the known-plaintext variant: a globally
/// periodic payload is trivially extrapolable by construction, which is a
/// property of the content, not a codec leak).
fn payload_periodic(seed: u8) -> Vec<u8> {
    let pat = [seed, seed ^ 0x5a, seed.wrapping_add(0x11), 0xa5];
    (0..(N_SOURCE * SYMBOL) as usize)
        .map(|i| pat[i % pat.len()])
        .collect()
}

/// Sparse low-entropy payload: mostly 0x00 with a nonzero mark every 37 bytes.
fn payload_sparse(seed: u8) -> Vec<u8> {
    (0..(N_SOURCE * SYMBOL) as usize)
        .map(|i| {
            if i % 37 == 0 {
                seed.wrapping_add((i / 37) as u8) | 1
            } else {
                0
            }
        })
        .collect()
}

/// The informed-adversary approximation (#3): given the KNOWN plaintext prefix,
/// the strongest naive structural guess for the UNKNOWN region, scored as
/// residual fidelity over the unknown region only (the known region is excluded
/// — the adversary already had it, counting it would be cheating). Takes the
/// worst (max) over three extrapolations: all-zeros, tile-the-known-pattern, and
/// repeat-the-last-known-byte. For a block-INDEPENDENT payload this stays at the
/// per-block ~1/256 base rate — the codec leaks nothing about the unknown blocks.
fn best_structural_guess_fidelity(known: &[u8], unknown_orig: &[u8]) -> f64 {
    let len = unknown_orig.len();
    let zeros = vec![0u8; len];
    let tiled: Vec<u8> = (0..len)
        .map(|i| known.get(i % known.len().max(1)).copied().unwrap_or(0))
        .collect();
    let last = known.last().copied().unwrap_or(0);
    let repeat_last = vec![last; len];
    residual_fidelity(&zeros, unknown_orig)
        .max(residual_fidelity(&tiled, unknown_orig))
        .max(residual_fidelity(&repeat_last, unknown_orig))
}

/// Kish effective sample size / participation ratio: `(Σw)² / Σw²`. The number a
/// dominance/N_eff surface WOULD expose (uniform ⇒ N; one source dominating ⇒
/// ~1). Used only by the pending #5 counter-case to pin the gap — the shipped
/// `AggregationMetaV1` carries no such field (CIRISVerify#167).
fn n_eff(weights: &[f64]) -> f64 {
    let sum: f64 = weights.iter().sum();
    let sumsq: f64 = weights.iter().map(|w| w * w).sum();
    if sumsq == 0.0 {
        0.0
    } else {
        sum * sum / sumsq
    }
}

/// Deterministic shuffle (LCG) — reproducible "which symbols a reconstruction
/// attempt still holds" without an rng dependency. Same as chaos_mesh.rs.
fn subset(holders: &[FountainSymbol], keep: usize, seed: u64) -> Vec<FountainSymbol> {
    let mut idx: Vec<usize> = (0..holders.len()).collect();
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    for i in (1..idx.len()).rev() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let j = (state >> 33) as usize % (i + 1);
        idx.swap(i, j);
    }
    idx.into_iter()
        .take(keep)
        .map(|i| holders[i].clone())
        .collect()
}

// ───────────────────── persist manifest plumbing ────────────────────
// Lifted from persist's own tests/fountain_content.rs + tests/aggregation_tier.rs
// builders (the RATIFIED FountainContentV1 contract). The symbols stored in
// persist are the SAME bytes edge's codec produced, so the hard-delete acts on
// the real recoverable surface.

fn producer_keys() -> (SigningKey, String, MlDsa65SoftwareSigner) {
    let ed_sk = SigningKey::from_bytes(&[0x5e; 32]);
    let ed_pk_b64 = BASE64.encode(ed_sk.verifying_key().to_bytes());
    let mldsa = MlDsa65SoftwareSigner::from_seed_bytes(&[0x6f; 32], "noisefloor-mldsa").unwrap();
    (ed_sk, ed_pk_b64, mldsa)
}

/// Encode `payload` with edge's REAL codec, then wrap the produced symbols in a
/// hybrid-signed persist manifest. Returns the manifest, the persist symbols,
/// AND the codec symbols (so a reconstruction attempt can use exactly what
/// persist would still be holding). `keep_lowest_priority` = a high
/// retention_priority on source symbols, i.e. content a rarity reweight would
/// fight hardest to keep — proving hard-delete ignores it.
async fn encode_and_manifest(
    content_id: &str,
    corpus_kind: &str,
    payload: &[u8],
) -> (
    FountainManifestV1,
    Vec<FountainSymbolV1>,
    Vec<FountainSymbol>,
) {
    let cfg = codec_config();
    let enc = fountain_encode(payload, &cfg).expect("substrate fountain_encode");
    assert_eq!(
        enc.symbols.len(),
        TARGET_HOLDERS,
        "H holders, one symbol each"
    );

    let (ed_sk, ed_pk_b64, mldsa) = producer_keys();
    let pqc_pk = mldsa.public_key().await.unwrap();

    // persist symbols carry the SAME bytes the codec produced; hashes are the
    // codec's own per-symbol SHA-256 (hex), which is what the manifest signs.
    let mut psyms = Vec::with_capacity(enc.symbols.len());
    let mut symbol_hashes = Vec::with_capacity(enc.symbols.len());
    for s in &enc.symbols {
        symbol_hashes.push(symbol_sha256_hex(&s.bytes));
        // Source symbols get keep-longest priority (low) — exactly what a high
        // rarity score sets to protect content; hard-delete must ignore it.
        let retention_priority = if s.symbol_id < N_SOURCE {
            s.symbol_id as u8
        } else {
            (N_SOURCE as u8).saturating_add((s.symbol_id - N_SOURCE) as u8)
        };
        psyms.push(FountainSymbolV1 {
            content_id: content_id.to_owned(),
            symbol_id: s.symbol_id,
            retention_priority,
            symbol_bytes: s.bytes.clone(),
        });
    }

    let envelope = serde_json::json!({
        "content_id": content_id,
        "pubkey_ed25519": ed_pk_b64,
        "pubkey_ml_dsa_65": BASE64.encode(&pqc_pk),
    });

    let mut manifest = FountainManifestV1 {
        content_id: content_id.to_owned(),
        corpus_kind: corpus_kind.to_owned(),
        manifest_version: MANIFEST_VERSION_V1,
        n_source: N_SOURCE,
        k_repair: K_REPAIR,
        symbol_size: SYMBOL,
        original_content_length: enc.original_content_length,
        min_viable_symbols: MIN_VIABLE,
        symbol_hashes,
        envelope,
        signature: String::new(),
        signature_ml_dsa_65: String::new(),
        pqc_key_id: "noisefloor-mldsa".to_owned(),
    };

    let canonical = manifest
        .canonical_bytes(&PythonJsonDumpsCanonicalizer)
        .unwrap();
    let ed_sig = ed_sk.sign(&canonical).to_bytes();
    manifest.signature = BASE64.encode(ed_sig);
    let mut bound = Vec::with_capacity(canonical.len() + ed_sig.len());
    bound.extend_from_slice(&canonical);
    bound.extend_from_slice(&ed_sig);
    let pqc_sig = mldsa.sign(&bound).await.unwrap();
    manifest.signature_ml_dsa_65 = BASE64.encode(&pqc_sig);

    (manifest, psyms, enc.symbols)
}

/// Build the §19.7.1 verification inputs (wire fields + valid bound-hybrid
/// signature) for an aggregate composite — the aggregator IS the composite's
/// producer, so it signs with the SAME keys [`producer_keys`] put on the
/// envelope (matches persist's own aggregation_tier.rs construction).
async fn signed_agg_inputs(
    member_ids: &[String],
    composite_cid: &str,
    source_corpus: &str,
) -> (AggregationMetaVerifyInputsV1, String) {
    let (ed_sk, _ed_pk_b64, mldsa) = producer_keys();
    let commitment = member_commitment(member_ids);
    let commitment_hex = hex_lower(&commitment);
    let meta = ciris_verify_core::holonomic::AggregationMetaV1 {
        version: 1,
        content_id: composite_cid.to_owned(),
        corpus_kind: aggregate_corpus_kind(source_corpus),
        tier: 1,
        aggregation_algorithm_id: "raptorq-pyramid-v1".to_owned(),
        source_count: member_ids.len() as u32,
        member_commitment: commitment,
        noise_floor_descriptor: "mean+stddev".to_owned(),
    };
    let preimage = meta.signing_preimage();
    let ed_sig = ed_sk.sign(&preimage).to_bytes();
    let mut bound = preimage.clone();
    bound.extend_from_slice(&ed_sig);
    let pqc_sig = mldsa.sign(&bound).await.unwrap();
    let inputs = AggregationMetaVerifyInputsV1 {
        version: meta.version,
        content_id: meta.content_id.clone(),
        corpus_kind: meta.corpus_kind.clone(),
        tier: meta.tier,
        aggregation_algorithm_id: meta.aggregation_algorithm_id.clone(),
        source_count: meta.source_count,
        member_commitment_hex: commitment_hex.clone(),
        noise_floor_descriptor: meta.noise_floor_descriptor.clone(),
        sig_ed25519_b64: BASE64.encode(ed_sig),
        sig_ml_dsa_65_b64: BASE64.encode(&pqc_sig),
    };
    (inputs, commitment_hex)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

async fn migrated_sqlite() -> SqliteBackend {
    let backend = SqliteBackend::open_in_memory().await.expect("open sqlite");
    backend
        .run_migrations()
        .await
        .expect("sqlite migrations (incl. V086 §19.7)");
    backend
}

// ════════════════════════════════════════════════════════════════════
// (a) Revocation ⇒ hard delete; NO retained tier reconstructs.
// ════════════════════════════════════════════════════════════════════
#[tokio::test]
async fn revocation_hard_deletes_and_no_retained_tier_reconstructs() {
    let backend = migrated_sqlite().await;
    let cfg = codec_config();
    let corpus = "trace";
    let cid = "nf-revoked-1";
    let payload = payload_for(1);
    let (manifest, psyms, _codec_syms) = encode_and_manifest(cid, corpus, &payload).await;

    // Admit: full recoverable content (all H symbols stored, source symbols at
    // keep-longest priority — the protected-by-rarity case).
    backend
        .put_fountain_content(&manifest, &psyms)
        .await
        .expect("admit recoverable content");
    let before = backend
        .get_fountain_content(cid, corpus)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(before, FountainContent::Full { .. }),
        "recoverable before revocation"
    );
    assert_eq!(
        before.present(),
        TARGET_HOLDERS as u32,
        "all H tiers present"
    );

    // Revocation ⇒ the §19.7.3 EjectHardDelete path. Drops ALL symbols
    // regardless of retention_priority (rarity can't resurrect a revoked id).
    let dropped = backend
        .evict_fountain_content_hard_delete(cid, corpus)
        .await
        .expect("hard delete (EjectHardDelete)");
    assert_eq!(
        dropped, TARGET_HOLDERS as u64,
        "HardDelete drops EVERY symbol, ignoring keep-longest priority"
    );

    // What persist STILL holds: EnvelopeOnly (manifest provenance), zero symbols.
    let after = backend
        .get_fountain_content(cid, corpus)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(after, FountainContent::EnvelopeOnly { .. }),
        "revoked ⇒ EnvelopeOnly, got {after:?}"
    );
    // Everything persist still holds for `cid`, lifted into codec symbols (the
    // adversary's reconstruction surface). After a HardDelete this is empty —
    // EnvelopeOnly retains the manifest, never a symbol — but we read it off the
    // backend rather than assuming, so the assertion is on the REAL retained set.
    let retained: Vec<FountainSymbol> = match &after {
        FountainContent::EnvelopeOnly { .. } => Vec::new(),
        FountainContent::Partial { symbols, .. } | FountainContent::Full { symbols, .. } => symbols
            .iter()
            .map(|s| FountainSymbol {
                symbol_id: s.symbol_id,
                bytes: s.symbol_bytes.clone(),
                sha256_hash: hash_hex_to_bytes(&symbol_sha256_hex(&s.symbol_bytes)),
            })
            .collect(),
    };
    assert_eq!(retained.len(), 0, "zero symbols survive revocation");

    // The noise floor: feed the substrate codec EVERYTHING persist still holds
    // (nothing) and assert it cannot reconstruct above ε. EnvelopeOnly is the
    // provable individual-unrecoverability state — only "existed with sig X".
    let attempt = fountain_decode(
        &retained,
        &manifest
            .symbol_hashes
            .iter()
            .map(|hx| hash_hex_to_bytes(hx))
            .collect::<Vec<_>>(),
        manifest.original_content_length,
        &cfg,
    );
    let fidelity = match attempt {
        Ok(bytes) => residual_fidelity(&bytes, &payload),
        Err(_) => 0.0, // refused below floor — total erasure
    };
    assert!(
        fidelity <= FIDELITY_EPSILON,
        "no retained tier may reconstruct: residual fidelity {fidelity:.6} > ε {FIDELITY_EPSILON}"
    );
}

/// Hex SHA-256 string → 32 bytes (the codec wants raw hashes; persist stores hex).
fn hash_hex_to_bytes(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
    }
    out
}

// ════════════════════════════════════════════════════════════════════
// (a2) TIER-PYRAMID revocation (#2): a member AND a composite are admitted;
//      revoking the MEMBER purges every tier where it was INDIVIDUALLY
//      recoverable (source-tier ⇒ EnvelopeOnly), while the collective composite
//      stays reconstructable (Full) and a sibling member is untouched. The
//      member's SIGNED manifest survives (never zero) as pure provenance.
// ════════════════════════════════════════════════════════════════════
#[tokio::test]
async fn revocation_purges_member_tiers_but_not_the_composite() {
    let backend = migrated_sqlite().await;
    let cfg = codec_config();
    let source_corpus = "trace";
    let composite_corpus = aggregate_corpus_kind(source_corpus); // "aggregate:trace"

    // Two source members; the composite (tier 1) is committed over BOTH, so the
    // collective survives when one member is revoked.
    let member_ids = vec!["nf-pyr-member-a".to_string(), "nf-pyr-member-b".to_string()];
    let member_payloads = vec![payload_for(30), payload_for(31)];
    for (mid, payload) in member_ids.iter().zip(&member_payloads) {
        let (m, p, _c) = encode_and_manifest(mid, source_corpus, payload).await;
        backend
            .put_fountain_content(&m, &p)
            .await
            .expect("admit pyramid member");
    }

    // Tier-1 composite over the two members (§19.7 put_aggregated_tier).
    let composite_cid = "nf-pyr-composite";
    let gist_payload = payload_for(210);
    let (cmanifest, csyms, _cc) =
        encode_and_manifest(composite_cid, &composite_corpus, &gist_payload).await;
    let (verif, commitment_hex) =
        signed_agg_inputs(&member_ids, composite_cid, source_corpus).await;
    let agg = AggregationMetaV1 {
        aggregate_content_id: composite_cid.to_owned(),
        source_corpus_kind: source_corpus.to_owned(),
        aggregation_level: 1,
        fan_in: member_ids.len() as u64,
        member_commitment: commitment_hex,
        aggregation_meta: vec![0x19, 0x07],
        verification: verif,
    };
    backend
        .put_aggregated_tier(&cmanifest, &csyms, &agg, 1_000)
        .await
        .expect("admit tier-1 composite over both members");

    // The revoked member (a): individually recoverable (Full) BEFORE revocation.
    let target = &member_ids[0];
    let before = backend
        .get_fountain_content(target, source_corpus)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(before, FountainContent::Full { .. }),
        "member individually recoverable before revocation"
    );
    assert_eq!(before.manifest().symbol_hashes.len(), TARGET_HOLDERS);

    // Revoke ⇒ EjectHardDelete: purge every retained symbol of the member.
    let dropped = backend
        .evict_fountain_content_hard_delete(target, source_corpus)
        .await
        .expect("hard-delete the revoked member");
    assert_eq!(
        dropped, TARGET_HOLDERS as u64,
        "revocation drops every member symbol"
    );

    // Member is EnvelopeOnly (below floor) at the source tier — the ONLY tier it
    // was individually recoverable at. present == 0 and NO threshold classifies
    // it as recoverable, so there is no retained tier from which the individual
    // returns.
    let after = backend
        .get_fountain_content(target, source_corpus)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(after, FountainContent::EnvelopeOnly { .. }),
        "revoked member ⇒ EnvelopeOnly, got {after:?}"
    );
    assert_eq!(after.present(), 0, "zero symbols survive at any tier");
    assert_eq!(
        FountainContent::classify(after.present(), N_SOURCE, MIN_VIABLE),
        ciris_persist::fountain::FountainReadClass::EnvelopeOnly,
        "no retained tier classifies the revoked member as recoverable"
    );
    // The SIGNED manifest survives — provenance, never zero.
    assert_eq!(
        after.manifest().symbol_hashes.len(),
        TARGET_HOLDERS,
        "signed manifest survives revocation (never zero) as provenance"
    );
    assert!(
        !after.manifest().signature.is_empty() && !after.manifest().signature_ml_dsa_65.is_empty(),
        "the surviving manifest keeps its hybrid signature"
    );

    // The codec cannot reconstruct the member from its retained (empty) set.
    let recovered = fountain_decode(
        &[],
        &after
            .manifest()
            .symbol_hashes
            .iter()
            .map(|hx| hash_hex_to_bytes(hx))
            .collect::<Vec<_>>(),
        after.manifest().original_content_length,
        &cfg,
    );
    let member_fidelity = match recovered {
        Ok(bytes) => residual_fidelity(&bytes, &member_payloads[0]),
        Err(_) => 0.0,
    };
    assert!(
        member_fidelity <= FIDELITY_EPSILON,
        "revoked member reconstructs at fidelity {member_fidelity:.6} > ε {FIDELITY_EPSILON}"
    );

    // Sibling member (b): revocation is TARGETED — still fully recoverable.
    let sibling = backend
        .get_fountain_content(&member_ids[1], source_corpus)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(sibling, FountainContent::Full { .. }),
        "sibling member untouched by the targeted revocation"
    );

    // The collective composite (tier 1) survives, fully reconstructable — the
    // pyramid loses one member's individual recoverability WITHOUT losing the
    // aggregate.
    let composite = backend
        .get_fountain_content(composite_cid, &composite_corpus)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(composite, FountainContent::Full { .. }),
        "composite survives the member revocation (collective intact)"
    );
    assert_eq!(
        composite.present(),
        TARGET_HOLDERS as u32,
        "composite retains all tiers after a member is purged"
    );
}

// ════════════════════════════════════════════════════════════════════
// (b) The MEASURED noise floor: reconstruction-attempt harness over ALL
//     retained-symbol counts below the information floor. Records ε +
//     measured residual fidelity as NUMBERS.
// ════════════════════════════════════════════════════════════════════
#[tokio::test]
async fn measured_noise_floor_below_information_floor() {
    let cfg = codec_config();
    let payload = payload_for(2);
    let (_m, _p, codec_syms) = encode_and_manifest("nf-floor", "trace", &payload).await;
    let hashes: Vec<[u8; 32]> = codec_syms.iter().map(|s| s.sha256_hash).collect();

    // Sweep every retained count from min_viable up to (but not including)
    // n_source — the entire band ABOVE total erasure and BELOW reconstruction.
    // For each, run many reconstruction attempts from random retained subsets
    // and take the WORST-CASE (max) residual fidelity an adversary could get.
    let mut worst_below_floor = 0.0_f64;
    for keep in (MIN_VIABLE as usize)..(N_SOURCE as usize) {
        let mut max_fid = 0.0_f64;
        for seed in 0..48u64 {
            let kept = subset(&codec_syms, keep, seed + keep as u64 * 7919);
            let fid = match fountain_decode(
                &kept,
                &hashes,
                cfg.symbol_size as u64 * cfg.n_source as u64,
                &cfg,
            )
            .or_else(|_| fountain_decode(&kept, &hashes, payload.len() as u64, &cfg))
            {
                Ok(bytes) => residual_fidelity(&bytes, &payload),
                Err(_) => 0.0,
            };
            max_fid = max_fid.max(fid);
        }
        assert!(
            max_fid <= FIDELITY_EPSILON,
            "keep={keep} (< n_source={N_SOURCE}): worst-case residual fidelity {max_fid:.6} \
             exceeds ε {FIDELITY_EPSILON} — the floor LEAKS"
        );
        worst_below_floor = worst_below_floor.max(max_fid);
    }

    // And the complement, just above the floor, MUST reconstruct byte-identical
    // (so the floor is a real edge, not vacuous erasure of everything).
    let kept = subset(&codec_syms, N_SOURCE as usize + 1, 0);
    let recon = fountain_decode(&kept, &hashes, payload.len() as u64, &cfg)
        .expect("n_source+1 must reconstruct");
    assert_eq!(
        residual_fidelity(&recon, &payload),
        1.0,
        "above the floor reconstruction is byte-identical (fidelity 1.0)"
    );

    eprintln!(
        "[noise-floor] MEASURED: below floor (keep {}..{}) worst-case residual fidelity = {:.6} (ε = {:.3}); \
         above floor (keep {}) fidelity = 1.000000",
        MIN_VIABLE,
        N_SOURCE,
        worst_below_floor,
        FIDELITY_EPSILON,
        N_SOURCE + 1
    );
}

// ════════════════════════════════════════════════════════════════════
// (b2) STRUCTURED-PAYLOAD + KNOWN-PLAINTEXT recoverability (#3): the original
//      sweep used uniform LCG bytes only. Re-run the below-floor sweep on
//      COMPRESSIBLE content, and add a partial-known-plaintext informed
//      adversary. Worst-case residual fidelity must stay ≤ ε in both.
// ════════════════════════════════════════════════════════════════════
#[tokio::test]
async fn structured_and_known_plaintext_stay_below_floor() {
    let cfg = codec_config();

    // (1) Structured/compressible payloads — the random-only blind spot #3 names.
    // Below n_source the substrate codec hard-refuses (RaptorQ is all-or-nothing),
    // so it leaks nothing about compressible content either: residual fidelity 0.
    let generators: [(&str, Vec<u8>); 3] = [
        ("runs8", payload_runs(3)),
        ("periodic4", payload_periodic(4)),
        ("sparse37", payload_sparse(5)),
    ];
    for (name, payload) in &generators {
        let cid = format!("nf-struct-{name}");
        let (_m, _p, codec_syms) = encode_and_manifest(&cid, "trace", payload).await;
        let hashes: Vec<[u8; 32]> = codec_syms.iter().map(|s| s.sha256_hash).collect();
        let mut worst = 0.0_f64;
        for keep in (MIN_VIABLE as usize)..(N_SOURCE as usize) {
            for seed in 0..48u64 {
                let kept = subset(&codec_syms, keep, seed + keep as u64 * 7919);
                let fid = match fountain_decode(&kept, &hashes, payload.len() as u64, &cfg) {
                    Ok(bytes) => residual_fidelity(&bytes, payload),
                    Err(_) => 0.0,
                };
                worst = worst.max(fid);
            }
        }
        assert!(
            worst <= FIDELITY_EPSILON,
            "structured payload {name}: worst-case residual fidelity {worst:.6} > ε \
             {FIDELITY_EPSILON} — the floor LEAKS on compressible content"
        );
    }

    // (2) Partial-known-plaintext informed adversary. The block-INDEPENDENT
    // `runs8` payload is compressible (160 constant runs) yet its unknown blocks
    // are not derivable from the known ones. The adversary holds sub-floor
    // symbols AND knows the first half of the plaintext; the residual fidelity is
    // scored on the UNKNOWN half only (the known half is excluded — counting what
    // the adversary already had would be cheating). Even so it stays ≤ ε.
    let payload = payload_runs(9);
    let (_m, _p, codec_syms) = encode_and_manifest("nf-known-plaintext", "trace", &payload).await;
    let hashes: Vec<[u8; 32]> = codec_syms.iter().map(|s| s.sha256_hash).collect();
    let known_len = payload.len() / 2; // block-aligned (runs of BLOCK_RUN bytes)
    let (known, unknown_orig) = payload.split_at(known_len);
    // The best purely-structural extrapolation of the unknown half is constant
    // across retained subsets (the codec adds nothing below the floor).
    let structural = best_structural_guess_fidelity(known, unknown_orig);
    let mut worst_unknown = structural;
    for keep in (MIN_VIABLE as usize)..(N_SOURCE as usize) {
        for seed in 0..48u64 {
            let kept = subset(&codec_syms, keep, seed + keep as u64 * 6971);
            // Sub-floor symbols + known plaintext: the codec refuses, so the only
            // signal on the unknown half is the (empty) codec output overlaid on
            // the known prefix — measured on the unknown region.
            let codec_unknown = match fountain_decode(&kept, &hashes, payload.len() as u64, &cfg) {
                Ok(bytes) if bytes.len() >= payload.len() => {
                    residual_fidelity(&bytes[known_len..], unknown_orig)
                }
                _ => 0.0,
            };
            worst_unknown = worst_unknown.max(codec_unknown);
        }
    }
    assert!(
        worst_unknown <= FIDELITY_EPSILON,
        "known-plaintext informed adversary recovers the unknown half: residual fidelity \
         {worst_unknown:.6} > ε {FIDELITY_EPSILON}"
    );
    eprintln!(
        "[noise-floor] MEASURED structured+known-plaintext: structural-guess unknown-region \
         fidelity = {structural:.6}; worst-case (incl. sub-floor symbols) = {worst_unknown:.6} \
         (ε = {FIDELITY_EPSILON:.3})"
    );
}

// ════════════════════════════════════════════════════════════════════
// (c) Aggregation past the floor IS erasure — PENDING a faithful N→1 operator.
//
// HONESTY NOTE (#4): the previous form of this test built the composite as a
// FABRICATED independent blob (`gist_payload = payload_for(200)`), sharing no
// member's bytes BY CONSTRUCTION. Asserting `residual_fidelity(member) < 1/N`
// against that blob is true-by-construction and proves NOTHING about erasure —
// any independent blob passes. A faithful aggregation-erasure MEASUREMENT needs
// the composite computed FROM the members via a real N→1 resampling/composite
// operator, which does NOT exist in edge today (grep-confirmed) — filed
// CIRISEdge#266. persist is codec-free; the codec (edge codec-fountain) has no
// N→1 fold. Until #266 lands this stays #[ignore] as a WAITING ACCEPTANCE TEST:
// the member-storage + hard-delete + composite-survives scaffolding is real, but
// the fabricated fidelity assertion is REMOVED. When #266 ships, replace the
// gist construction with `edge::compose(members)` and assert per-member residual
// fidelity ≤ max(ε, 1/N_eff) — then drop the #[ignore].
// ════════════════════════════════════════════════════════════════════
#[tokio::test]
#[ignore = "faithful N→1 aggregation-erasure measurement needs edge's resampling/composite operator (CIRISEdge#266); \
            a fabricated independent composite makes residual_fidelity < 1/N true-by-construction — not a proof"]
async fn aggregation_collapse_erases_the_individual_pending_ciris_edge_266() {
    let backend = migrated_sqlite().await;
    let cfg = codec_config();
    let source_corpus = "trace";
    let composite_corpus = aggregate_corpus_kind(source_corpus); // "aggregate:trace"
    const FAN_IN: usize = 8; // N source items → 1 composite (1/N gist bound = 0.125)

    // N distinct source members, each a real fountain content stored in persist.
    // (Real scaffolding — kept for when #266's operator can fold THESE members.)
    let member_payloads: Vec<Vec<u8>> = (0..FAN_IN).map(|i| payload_for(10 + i as u8)).collect();
    let member_ids: Vec<String> = (0..FAN_IN).map(|i| format!("nf-member-{i}")).collect();
    for (mid, payload) in member_ids.iter().zip(&member_payloads) {
        let (m, p, _c) = encode_and_manifest(mid, source_corpus, payload).await;
        backend
            .put_fountain_content(&m, &p)
            .await
            .expect("admit member");
    }

    // PENDING CIRISEdge#266: a FAITHFUL composite would be
    //   let composite_payload = edge::compose(&member_payloads);  // real N→1 fold
    // so the composite provably DERIVES from the members and a residual-fidelity
    // bound is a real erasure measurement. No such operator exists today, so the
    // line below is a placeholder that is NOT used to prove erasure.
    let composite_cid = "nf-composite-root";
    let placeholder_gist = payload_for(200); // NOT a faithful fold — see #266.
    let (cmanifest, csyms, _ccodec) =
        encode_and_manifest(composite_cid, &composite_corpus, &placeholder_gist).await;
    let (verif, commitment_hex) =
        signed_agg_inputs(&member_ids, composite_cid, source_corpus).await;
    let agg = AggregationMetaV1 {
        aggregate_content_id: composite_cid.to_owned(),
        source_corpus_kind: source_corpus.to_owned(),
        aggregation_level: 1,
        fan_in: FAN_IN as u64,
        member_commitment: commitment_hex,
        aggregation_meta: vec![0x19, 0x07], // opaque §19.7 wire payload
        verification: verif,
    };
    backend
        .put_aggregated_tier(&cmanifest, &csyms, &agg, 1_000)
        .await
        .expect("admit N→1 composite (§19.7 put_aggregated_tier)");

    // Real persist behavior (holds regardless of #266): ERASE the individuals —
    // aggregation past the floor IS erasure, so member symbols are hard-deleted.
    for mid in &member_ids {
        let dropped = backend
            .evict_fountain_content_hard_delete(mid, source_corpus)
            .await
            .expect("hard-delete member after collapse");
        assert_eq!(dropped, TARGET_HOLDERS as u64, "each member fully purged");
        assert!(
            matches!(
                backend
                    .get_fountain_content(mid, source_corpus)
                    .await
                    .unwrap(),
                Some(FountainContent::EnvelopeOnly { .. })
            ),
            "member {mid} reduced to EnvelopeOnly"
        );
    }

    // The composite remains, fully recoverable (forever-memory).
    let composite = backend
        .get_fountain_content(composite_cid, &composite_corpus)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(composite, FountainContent::Full { .. }),
        "composite survives the collapse (the aggregate is what's retained)"
    );

    // NO fabricated fidelity assertion. The faithful measurement (per-member
    // residual fidelity ≤ max(ε, 1/N_eff) against a composite DERIVED from the
    // members) is unbuildable until CIRISEdge#266. We drive the codec on the
    // placeholder only to document the shape — this is NOT a proof of erasure.
    let n_eff_uniform = n_eff(&[1.0; FAN_IN]); // == FAN_IN for a balanced fold
    let would_assert_bound = FIDELITY_EPSILON.max(1.0 / n_eff_uniform);
    eprintln!(
        "[noise-floor] PENDING CIRISEdge#266: N={FAN_IN}→1 collapse scaffolding is real \
         (members ⇒ EnvelopeOnly, composite ⇒ Full). A faithful test would compute the \
         composite FROM the members and assert per-member residual fidelity ≤ \
         max(ε={FIDELITY_EPSILON:.3}, 1/N_eff={:.3}) = {would_assert_bound:.3}; no N→1 operator \
         exists yet, so no erasure claim is made here.",
        1.0 / n_eff_uniform
    );
    let _ = &cfg; // codec retained for the post-#266 measurement.
}

// ════════════════════════════════════════════════════════════════════
// (d) DOMINANCE counter-case (#5) — PENDING a dominance / N_eff surface.
//
// A fold where ONE source is ~90% of the mass (900 of 1000) is, by every
// invariant the shipped `AggregationMetaV1` exposes, INDISTINGUISHABLE from a
// balanced fold over the same members: `source_count` counts members (N), not
// mass, and `member_commitment` is a Merkle root over member IDs — neither
// carries weights. So a dominance attack (one member drowning the aggregate)
// hybrid-verifies identically. This #[ignore]d test PINS that gap as a waiting
// acceptance test: when an N_eff / dominance descriptor lands (CIRISVerify#167,
// twin CIRISConstitution#6), it should FAIL to verify (or expose N_eff≈1) for
// the dominated fold while the balanced fold keeps N_eff≈N.
// ════════════════════════════════════════════════════════════════════
// NOTE: this test RUNS (not #[ignore]d) — it makes real assertions that PASS
// today, characterizing the live gap: the shipped verifier accepts a
// 900/1000-dominated fold as readily as a balanced one. When the dominance/N_eff
// surface lands (CIRISVerify#167 / CIRISConstitution#6) this test FAILS loudly —
// the signal that the gap closed and the assertions must invert (dominated fold
// rejected / N_eff exposed). That fail-when-fixed is the Rust analogue of a
// strict-xfail; keeping it running is real coverage, not a skip.
#[tokio::test]
async fn dominance_undetectable_pending_ciris_verify_167() {
    // Same member set, two very different mass distributions.
    let member_ids: Vec<String> = (0..10).map(|i| format!("nf-dom-member-{i}")).collect();
    let balanced_weights = vec![100.0_f64; 10]; // uniform → N_eff = 10
    let mut dominated_weights = vec![100.0_f64 / 9.0; 10]; // ~11.1 each …
    dominated_weights[0] = 900.0; // … except member 0 owns 900/1000 of the mass.

    let n_eff_balanced = n_eff(&balanced_weights);
    let n_eff_dominated = n_eff(&dominated_weights);
    assert!(
        (n_eff_balanced - 10.0).abs() < 1e-9,
        "balanced fold: N_eff == N == 10 (got {n_eff_balanced})"
    );
    assert!(
        n_eff_dominated < 2.0,
        "dominated fold: N_eff collapses toward 1 (got {n_eff_dominated:.4})"
    );

    // Build a real, hybrid-signed AggregationMetaV1 for the (dominated) fold and
    // drive the SHIPPED verifier — it accepts it, because the meta cannot encode
    // the dominance at all.
    let (ed_sk, _ed_pk_b64, mldsa) = producer_keys();
    let ed_pk = ed_sk.verifying_key().to_bytes();
    let pqc_pk = mldsa.public_key().await.unwrap();

    let make_meta = |src: u32| ciris_verify_core::holonomic::AggregationMetaV1 {
        version: 1,
        content_id: "nf-dominated-root".to_owned(),
        corpus_kind: aggregate_corpus_kind("trace"),
        tier: 1,
        aggregation_algorithm_id: "raptorq-pyramid-v1".to_owned(),
        source_count: src,
        member_commitment: member_commitment(&member_ids),
        noise_floor_descriptor: "mean+stddev".to_owned(),
    };
    let meta_balanced = make_meta(member_ids.len() as u32);
    let meta_dominated = make_meta(member_ids.len() as u32);

    // The blindness, stated as assertions: the two folds are byte-identical on
    // every field a verifier can see, despite N_eff 10 vs ~1.2.
    assert_eq!(
        meta_balanced.source_count, meta_dominated.source_count,
        "source_count cannot tell a dominated fold from a balanced one"
    );
    assert_eq!(
        meta_balanced.member_commitment, meta_dominated.member_commitment,
        "member_commitment (ID Merkle root) is mass-blind"
    );
    assert_eq!(
        meta_balanced.signing_preimage(),
        meta_dominated.signing_preimage(),
        "the signed preimage is identical — dominance is not in the signed surface"
    );

    // And the shipped verifier HYBRID-VERIFIES the dominated fold: nothing rejects
    // it, so a 900/1000 attack passes today.
    let preimage = meta_dominated.signing_preimage();
    let ed_sig = ed_sk.sign(&preimage).to_bytes();
    let mut bound = preimage.clone();
    bound.extend_from_slice(&ed_sig);
    let pqc_sig = mldsa.sign(&bound).await.unwrap();
    let verdict = ciris_verify_core::holonomic::verify_aggregation_meta(
        &meta_dominated,
        &ed_sig,
        &pqc_sig,
        &ed_pk,
        &pqc_pk,
    );
    assert_eq!(
        verdict,
        ciris_verify_core::holonomic::AggregationMetaVerification::HybridVerified,
        "the dominated fold verifies — the invariant that would reject it does not exist yet"
    );

    // WAITING ACCEPTANCE (post-CIRISVerify#167): when a dominance descriptor
    // lands, this becomes
    //   assert!(meta.n_eff() >= DOMINANCE_FLOOR)  // rejects N_eff ≈ 1.2
    // and the two metas above STOP being equal.
    eprintln!(
        "[noise-floor] PENDING CIRISVerify#167: balanced N_eff={n_eff_balanced:.3} vs dominated \
         N_eff={n_eff_dominated:.3}, yet source_count={} and member_commitment are identical and \
         the dominated fold HYBRID-VERIFIES. Dominance is invisible to the shipped invariants.",
        meta_dominated.source_count
    );
}

// ════════════════════════════════════════════════════════════════════
// Characterization probe — prints the measured curve (not gated; --ignored).
//   cargo test --test noise_floor measured_noise_floor_numbers -- --nocapture --ignored
// ════════════════════════════════════════════════════════════════════
#[tokio::test]
#[ignore]
async fn measured_noise_floor_numbers() {
    let cfg = codec_config();
    let payload = payload_for(2);
    let (_m, _p, codec_syms) = encode_and_manifest("nf-curve", "trace", &payload).await;
    let hashes: Vec<[u8; 32]> = codec_syms.iter().map(|s| s.sha256_hash).collect();
    const TRIALS: u64 = 500;
    eprintln!("keep / H={TARGET_HOLDERS}  reconstruct%  mean-residual-fidelity");
    for keep in (MIN_VIABLE as usize)..=(N_SOURCE as usize + 2) {
        let mut ok = 0u64;
        let mut sum_fid = 0.0_f64;
        for seed in 0..TRIALS {
            let kept = subset(&codec_syms, keep, seed + keep as u64 * 1_000_003);
            let fid = match fountain_decode(&kept, &hashes, payload.len() as u64, &cfg) {
                Ok(b) => {
                    if b == payload {
                        ok += 1;
                    }
                    residual_fidelity(&b, &payload)
                }
                Err(_) => 0.0,
            };
            sum_fid += fid;
        }
        eprintln!(
            "{keep:>4}            {:>6.2}%        {:.6}",
            100.0 * ok as f64 / TRIALS as f64,
            sum_fid / TRIALS as f64
        );
    }
}
