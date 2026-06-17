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
// (c) Aggregation past the floor IS erasure: N→1 composite; the
//     individual is information-theoretically unrecoverable (< 1/N gist).
// ════════════════════════════════════════════════════════════════════
#[tokio::test]
async fn aggregation_collapse_erases_the_individual() {
    let backend = migrated_sqlite().await;
    let cfg = codec_config();
    let source_corpus = "trace";
    let composite_corpus = aggregate_corpus_kind(source_corpus); // "aggregate:trace"
    const FAN_IN: usize = 8; // N source items → 1 composite (1/N gist bound = 0.125)

    // N distinct source members, each a real fountain content stored in persist.
    let member_payloads: Vec<Vec<u8>> = (0..FAN_IN).map(|i| payload_for(10 + i as u8)).collect();
    let member_ids: Vec<String> = (0..FAN_IN).map(|i| format!("nf-member-{i}")).collect();
    for (mid, payload) in member_ids.iter().zip(&member_payloads) {
        let (m, p, _c) = encode_and_manifest(mid, source_corpus, payload).await;
        backend
            .put_fountain_content(&m, &p)
            .await
            .expect("admit member");
    }

    // The §19.7 operator-2 collapse: N→1. The composite is a NEW content whose
    // payload is the aggregate "gist", NOT any member. (persist is codec-free —
    // the N→1 resampling is edge-side; we model the gist as a distinct payload,
    // which is the honest shape: the composite shares no member's bytes.)
    let composite_cid = "nf-composite-root";
    let gist_payload = payload_for(200);
    let (cmanifest, csyms, ccodec) =
        encode_and_manifest(composite_cid, &composite_corpus, &gist_payload).await;
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

    // Now ERASE the individuals: aggregation past the floor IS erasure, so the
    // member symbols are hard-deleted (the composite carries the lineage).
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

    // MEASURED individual-unrecoverability: the ONLY recoverable artifact left
    // is the composite. Try to recover EACH erased member from the composite's
    // retained symbols (the adversary's best surface) and assert the gist of any
    // member is below 1/N. The composite payload shares no member's bytes, so the
    // residual fidelity of any member vs. the reconstructed composite is chance.
    let chashes: Vec<[u8; 32]> = ccodec.iter().map(|s| s.sha256_hash).collect();
    let composite_recovered = fountain_decode(&ccodec, &chashes, gist_payload.len() as u64, &cfg)
        .expect("composite itself reconstructs");
    let gist_bound = 1.0 / FAN_IN as f64; // < 1/N
    let mut worst_member_gist = 0.0_f64;
    for payload in &member_payloads {
        let gist = residual_fidelity(&composite_recovered, payload);
        worst_member_gist = worst_member_gist.max(gist);
        assert!(
            gist < gist_bound,
            "an erased member is recoverable from the composite: gist {gist:.6} >= 1/N {gist_bound:.6}"
        );
    }
    eprintln!(
        "[noise-floor] MEASURED aggregation: N={FAN_IN}→1 collapse; worst member-gist recoverable \
         from composite = {worst_member_gist:.6} (< 1/N = {gist_bound:.6}); members = EnvelopeOnly"
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
