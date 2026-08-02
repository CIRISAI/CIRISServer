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
    // §19.7.1.3 (verify v10 / CIRISVerify#191, CC 6.1.2.1.2 R9): the mass Merkle
    // root is over `(member_id, mass)` leaves. This fixture is a BALANCED fold —
    // every member carries equal mass — which is what makes `n_eff == N` honest.
    let masses: Vec<(String, u64)> = member_ids.iter().map(|id| (id.clone(), 1u64)).collect();
    let mass_root = ciris_verify_core::holonomic::mass_commitment(&masses);
    let meta = ciris_verify_core::holonomic::AggregationMetaV1 {
        // v10 §19.7.1.3 (CIRISVerify#191): version-3 carries a SIGNED
        // `max_source_multiplicity` + `mass_commitment`. This is a FLAG-DAY cut —
        // a v1/v2 tier lacks the surface and fails CLOSED at
        // `passes_multiplicity_gate` (no deprecation window) — so the fixture must
        // move to v3 to stay admissible. (v2 added the signed n_eff dominance
        // surface, §19.7.1.2 / #167; v1 had neither and fails both gates.)
        version: 3,
        content_id: composite_cid.to_owned(),
        corpus_kind: aggregate_corpus_kind(source_corpus),
        tier: 1,
        aggregation_algorithm_id: "raptorq-pyramid-v1".to_owned(),
        source_count: member_ids.len() as u32,
        // Balanced fold of N equal-mass members ⇒ n_eff == N (signed, v2+), which
        // clears `passes_dominance_gate` for any min_ratio ≤ 1.
        n_eff: member_ids.len() as u32,
        // The R9 residual the mass-based n_eff cannot see: 900 near-DUPLICATE
        // contents folded as 900 distinct members at equal mass yield an honest
        // n_eff == 1000, yet the composite blur IS the data subject. Here the
        // members are genuinely DISTINCT contents, so the largest
        // content-similarity cluster is a single member ⇒ multiplicity 1, and
        // `passes_multiplicity_gate` (max_source_multiplicity * n_min <=
        // source_count) clears for any n_min <= N.
        max_source_multiplicity: 1,
        member_commitment: commitment,
        noise_floor_descriptor: "mean+stddev".to_owned(),
        mass_commitment: mass_root,
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
        n_eff: meta.n_eff,
        max_source_multiplicity: meta.max_source_multiplicity,
        member_commitment_hex: commitment_hex.clone(),
        mass_commitment_hex: hex_lower(&meta.mass_commitment),
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
// operator. That operator NOW EXISTS: `aggregate_symbols`, in the pinned edge at
// `src/transport/realtime_av_codec/fountain.rs:429`, shipped in v9.0.0.
//
// This comment previously read "does NOT exist in edge today (grep-confirmed)"
// and cited CIRISEdge#266 as the blocker. That was true when written and false
// for many releases after, and the evidence language ("grep-confirmed") is what
// made it costly: a triager reads it, concludes the test is correctly waiting on
// upstream, and moves on. It is not blocked. It is UNWRITTEN.
//
// That is this repository's signature defect — a claim that outruns its
// measurement — living inside the suite that measures that defect. See
// CONTRIBUTING.md §"a design doc is not an implementation".
//
// So this stays #[ignore] as a WAITING ACCEPTANCE TEST, but waiting on US:
// the member-storage + hard-delete + composite-survives scaffolding is real, but
// the fabricated fidelity assertion is REMOVED. When #266 ships, replace the
// gist construction with `edge::compose(members)` and assert per-member residual
// fidelity ≤ max(ε, 1/N_eff) — then drop the #[ignore].
// ════════════════════════════════════════════════════════════════════
#[tokio::test]
#[ignore = "UNWRITTEN, NOT BLOCKED: edge's N→1 operator (aggregate_symbols, \
            realtime_av_codec/fountain.rs) has shipped since v9.0.0. What is missing is this test \
            calling it — a fabricated independent composite makes residual_fidelity < 1/N \
            true-by-construction, which is not a proof. See CIRISServer#239"]
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
// (d) DOMINANCE + MULTIPLICITY are REJECTED — the v3 hard fork (CIRISVerify#167
//     + #191, CC 6.1.2 / 6.1.2.1.2 R9; CIRISServer#239).
//
// This test used to be the INVERSE: it characterized the gap, asserting that a
// 900/1000-dominated fold hybrid-verifies exactly like a balanced one because
// `AggregationMetaV1` could not encode mass at all. It was meant to "fail loudly
// when the surface lands" — but it pinned `version: 1`, which is blind BY
// CONSTRUCTION, so the tripwire could never fire no matter what shipped. That is
// the stale-tripwire defect (#239): a test that can only ever pass is not a test.
//
// The surface has now landed and we are HARD-FORKED onto version 3 — no v1/v2
// producer, no flag-day window, no legacy tolerance (the mesh is still seeding,
// so there is nothing to be backward-compatible WITH). So the assertions invert
// into a positive pin of the two gates:
//
//   * DOMINANCE (§19.7.1.2, v2+): one member owning 900/1000 of the MASS collapses
//     n_eff → ~1.2, and `passes_dominance_gate` rejects it.
//   * MULTIPLICITY (§19.7.1.3, v3, the R9 residual): 900 NEAR-DUPLICATE contents
//     folded as 900 *distinct members at equal mass* are mass-honest — n_eff == N
//     exactly, so the dominance gate is blind to them — yet the composite blur IS
//     the data subject. Only `max_source_multiplicity` sees it. This is the case
//     n_eff provably cannot catch, and it is why v3 exists.
// ════════════════════════════════════════════════════════════════════
#[tokio::test]
async fn dominance_and_multiplicity_are_rejected_on_v3() {
    use ciris_verify_core::holonomic::{
        effective_source_count, mass_commitment, passes_dominance_gate, passes_multiplicity_gate,
        verify_aggregation_meta, AggregationMetaV1, AggregationMetaVerification,
        MASS_FIXED_POINT_SCALE,
    };

    const N: usize = 10;
    let member_ids: Vec<String> = (0..N).map(|i| format!("nf-dom-member-{i}")).collect();

    // Two mass distributions over the SAME members.
    let balanced_masses = vec![100.0_f64; N]; // uniform      → n_eff == N
    let mut dominated_masses = vec![100.0_f64 / 9.0; N]; // ~11.1 each …
    dominated_masses[0] = 900.0; // … except member 0 owns 900/1000 of the mass.

    let n_eff_balanced = effective_source_count(&balanced_masses);
    let n_eff_dominated = effective_source_count(&dominated_masses);
    assert_eq!(n_eff_balanced, N as u32, "balanced fold ⇒ n_eff == N");
    assert!(
        n_eff_dominated <= 1,
        "900/1000 dominated fold ⇒ n_eff collapses toward 1 (got {n_eff_dominated})"
    );

    let fixed = |m: f64| (m * MASS_FIXED_POINT_SCALE).round() as u64;
    let mass_root = |masses: &[f64]| {
        let leaves: Vec<(String, u64)> = member_ids
            .iter()
            .cloned()
            .zip(masses.iter().map(|m| fixed(*m)))
            .collect();
        mass_commitment(&leaves)
    };

    // `multiplicity` = size of the largest content-similarity cluster. Distinct
    // contents ⇒ 1. The R9 case below fabricates 900 near-duplicates ⇒ 900.
    let make_meta = |n_eff: u32, multiplicity: u32, masses: &[f64], src: u32| AggregationMetaV1 {
        version: 3, // HARD FORK — v1/v2 are not produced and fail closed.
        content_id: "nf-dominated-root".to_owned(),
        corpus_kind: aggregate_corpus_kind("trace"),
        tier: 1,
        aggregation_algorithm_id: "raptorq-pyramid-v1".to_owned(),
        source_count: src,
        n_eff,
        max_source_multiplicity: multiplicity,
        member_commitment: member_commitment(&member_ids),
        noise_floor_descriptor: "mean+stddev".to_owned(),
        mass_commitment: mass_root(masses),
    };

    let meta_balanced = make_meta(n_eff_balanced, 1, &balanced_masses, N as u32);
    let meta_dominated = make_meta(n_eff_dominated, 1, &dominated_masses, N as u32);

    // The OLD test asserted these were byte-identical (dominance invisible). At v3
    // they MUST differ — the mass distribution is now inside the SIGNED surface.
    assert_ne!(
        meta_balanced.signing_preimage(),
        meta_dominated.signing_preimage(),
        "at v3 the signed preimage carries n_eff + mass_commitment, so a dominated \
         fold can no longer forge the balanced fold's signature surface"
    );
    assert_ne!(
        meta_balanced.mass_commitment, meta_dominated.mass_commitment,
        "the mass Merkle root makes a lying n_eff mechanically provable from held members"
    );

    // ── Gate 1: DOMINANCE ────────────────────────────────────────────────────
    // Consume the CEG-PINNED floors from the ENFORCING path — persist's
    // `verify_for_admission` gates admission with exactly these. A local `0.5`
    // literal here would only pin our own copy of the number and would silently
    // diverge if the substrate retuned the floor; the point of the test is to pin
    // what the admission gate actually enforces.
    use ciris_persist::fountain::aggregation::{DEFAULT_MULTIPLICITY_N_MIN, MIN_DOMINANCE_RATIO};
    const MIN_RATIO: f64 = MIN_DOMINANCE_RATIO;
    assert!(
        passes_dominance_gate(&meta_balanced, MIN_RATIO),
        "a balanced fold must be ADMITTED"
    );
    assert!(
        !passes_dominance_gate(&meta_dominated, MIN_RATIO),
        "the 900/1000 dominated fold must be REJECTED — this is the assertion the \
         old characterization test was waiting to invert"
    );

    // ── Gate 2: MULTIPLICITY — the R9 residual n_eff CANNOT see ──────────────
    // 1000 members, equal mass, but 900 of them are NEAR-DUPLICATE contents filed
    // under distinct ids. n_eff is mass-based, so it reports a perfectly honest
    // 1000 and the dominance gate happily admits. Only the content-similarity
    // multiplicity exposes that the composite is really ~1 subject.
    const R9_N: u32 = 1000;
    const R9_DUPES: u32 = 900;
    let r9_masses = vec![1.0_f64; R9_N as usize];
    let r9_n_eff = effective_source_count(&r9_masses);
    assert_eq!(
        r9_n_eff, R9_N,
        "R9: equal-mass near-duplicates are MASS-honest — n_eff == N exactly"
    );
    let r9 = AggregationMetaV1 {
        version: 3,
        source_count: R9_N,
        n_eff: r9_n_eff,
        max_source_multiplicity: R9_DUPES,
        ..make_meta(r9_n_eff, R9_DUPES, &balanced_masses, R9_N)
    };
    const N_MIN: u32 = DEFAULT_MULTIPLICITY_N_MIN; // the pinned floor, not a local guess
    assert!(
        passes_dominance_gate(&r9, MIN_RATIO),
        "the dominance gate is BLIND to R9 (n_eff == N) — this is exactly why the \
         multiplicity surface had to exist; if this ever fails, the premise moved"
    );
    assert!(
        !passes_multiplicity_gate(&r9, N_MIN),
        "R9 MUST be rejected: 900 near-duplicates behind 1000 distinct ids means the \
         composite blur IS the data subject (max_source_multiplicity * n_min > source_count)"
    );
    let r9_clean = AggregationMetaV1 {
        max_source_multiplicity: 1,
        ..r9.clone()
    };
    assert!(
        passes_multiplicity_gate(&r9_clean, N_MIN),
        "the same fold over genuinely distinct contents must be ADMITTED"
    );

    // ── The hard fork: v1/v2 fail CLOSED, no legacy tolerance ────────────────
    for stale in [1u32, 2u32] {
        let old = AggregationMetaV1 {
            version: stale,
            ..meta_balanced.clone()
        };
        assert!(
            !passes_multiplicity_gate(&old, N_MIN),
            "v{stale} lacks the multiplicity surface and MUST fail closed — the mesh is \
             still seeding, so there is no legacy producer to grandfather"
        );
    }
    assert!(
        !passes_dominance_gate(
            &AggregationMetaV1 {
                version: 1,
                ..meta_balanced.clone()
            },
            MIN_RATIO
        ),
        "v1 has no signed n_eff and MUST fail the dominance gate closed"
    );

    // ── And the signed v3 meta still HYBRID-VERIFIES end to end ──────────────
    let (ed_sk, _ed_pk_b64, mldsa) = producer_keys();
    let ed_pk = ed_sk.verifying_key().to_bytes();
    let pqc_pk = mldsa.public_key().await.unwrap();
    let preimage = meta_balanced.signing_preimage();
    let ed_sig = ed_sk.sign(&preimage).to_bytes();
    let mut bound = preimage.clone();
    bound.extend_from_slice(&ed_sig);
    let pqc_sig = mldsa.sign(&bound).await.unwrap();
    assert_eq!(
        verify_aggregation_meta(&meta_balanced, &ed_sig, &pqc_sig, &ed_pk, &pqc_pk),
        AggregationMetaVerification::HybridVerified,
        "a well-formed v3 balanced fold verifies; the GATES (not the signature) are \
         what reject dominance and multiplicity"
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
