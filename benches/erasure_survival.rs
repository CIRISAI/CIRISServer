//! **Erasure survival — EMPIRICAL, against the real substrate codec.**
//!
//! This replaces the old analytical `survival_curve` (binomial `P(Binom(H,q) ≥ N)`)
//! with a MEASURED reconstruction rate: a real blob is fountain-coded by edge's OWN
//! `fountain_encode` (codec-fountain, RaptorQ RFC 6330) into `H = N_SOURCE + K_REPAIR`
//! holders (one symbol each), then at each availability tier `q` we drop holders by an
//! independent Bernoulli(q) coin per holder, hand the survivors to the real
//! `fountain_decode`, and count how many of `TRIALS` independent trials reconstruct the
//! content BYTE-IDENTICAL. The reported `p_reconstruct` is `ok / TRIALS` — an empirical
//! frequency, not a model.
//!
//! It is a `harness = false` bench (no criterion timing — survival is a *rate*, not a
//! latency) that writes its results to `target/erasure_survival.json`. The `scoreboard`
//! subcommand reads that sidecar and folds the empirical curve into `bench_results.json`
//! under `erasure.survival`; if the sidecar is absent the scoreboard GATES the tier
//! honestly ("erasure survival not benched"). The codec is dev-only (a relay forwards
//! sealed symbols opaquely and never encodes/decodes), so this lives in a bench where
//! `codec-fountain` is on, not in the shipped library.
//!
//! Run: `cargo bench --bench erasure_survival`

use std::io::Write as _;
use std::path::PathBuf;

use ciris_edge::transport::realtime_av_codec::fountain::{
    fountain_decode, fountain_encode, FountainConfig, FountainSymbol,
};

// Fountain policy (scale_model v0.7): content is RaptorQ-coded into N_SOURCE source
// symbols (= the reconstruction floor); the swarm converges to H = N_SOURCE + K_REPAIR
// holders, each storing ONE symbol. The same constants chaos_mesh.rs proves against.
const N_SOURCE: u32 = 20;
const K_REPAIR: u32 = 10;
const TARGET_HOLDERS: usize = (N_SOURCE + K_REPAIR) as usize; // H = 30
const SYMBOL: u32 = 64; // bytes/symbol — content fills exactly N_SOURCE symbols
const MIN_VIABLE: u32 = 5; // BLINKING_DOT floor

/// Independent reconstruction trials per availability tier. 4,000 gives a
/// per-tier standard error of ≤0.8 pp at p≈0.5 — tight enough to publish.
const TRIALS: u64 = 4_000;

/// Availability tiers `(q, label)`: probability an individual holder is online when
/// reconstruction is attempted. Matches the operator scale grid (datacenter →
/// battlefield mesh).
const Q_TIERS: &[(f64, &str)] = &[
    (0.95, "datacenter"),
    (0.90, "typical wifi"),
    (0.85, "medium churn (design target)"),
    (0.80, "high churn"),
    (0.70, "battlefield mesh"),
];

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

/// SplitMix64 — a tiny, dependency-free PRNG so "which holders are online this trial"
/// is reproducible (same `seed` ⇒ same survivor set every CI run) and uniform.
struct SplitMix64(u64);
impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform f64 in [0, 1).
    fn next_f64(&mut self) -> f64 {
        // 53-bit mantissa.
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Drop each holder independently with probability `1 - q` (a Bernoulli(q) online
/// coin per holder), returning the survivors that would be reachable this trial.
fn survivors(holders: &[FountainSymbol], q: f64, rng: &mut SplitMix64) -> Vec<FountainSymbol> {
    holders
        .iter()
        .filter(|_| rng.next_f64() < q)
        .cloned()
        .collect()
}

struct TierResult {
    q: f64,
    label: &'static str,
    p_reconstruct: f64,
    trials: u64,
    mean_survivors: f64,
}

fn main() {
    let cfg = fountain_config();
    let content = fountain_content();
    let enc = fountain_encode(&content, &cfg).expect("substrate fountain_encode");
    assert_eq!(
        enc.symbols.len(),
        TARGET_HOLDERS,
        "H holders, one symbol each"
    );

    println!(
        "erasure_survival — REAL RaptorQ codec (edge codec-fountain): N_SOURCE={N_SOURCE} \
         K_REPAIR={K_REPAIR} H={TARGET_HOLDERS}, {TRIALS} trials/tier"
    );

    let mut results = Vec::new();
    for &(q, label) in Q_TIERS {
        // Per-tier deterministic stream, decorrelated across tiers.
        let mut rng = SplitMix64(0xC0FF_EE00 ^ (q.to_bits()));
        let mut ok = 0u64;
        let mut total_survivors = 0u64;
        for _ in 0..TRIALS {
            let kept = survivors(&enc.symbols, q, &mut rng);
            total_survivors += kept.len() as u64;
            // A real decode through the substrate codec. Below MIN_VIABLE the codec
            // hard-refuses (Err) → counts as a failed reconstruction, honestly.
            let decoded =
                fountain_decode(&kept, &enc.symbol_hashes, enc.original_content_length, &cfg);
            if decoded.map(|d| d == content).unwrap_or(false) {
                ok += 1;
            }
        }
        let p = ok as f64 / TRIALS as f64;
        let mean_surv = total_survivors as f64 / TRIALS as f64;
        println!(
            "  q={q:.2} ({label:<26}) : {ok}/{TRIALS} reconstruct = {:.3}%  \
             (mean {mean_surv:.1}/{TARGET_HOLDERS} holders online)",
            p * 100.0
        );
        results.push(TierResult {
            q,
            label,
            p_reconstruct: p,
            trials: TRIALS,
            mean_survivors: mean_surv,
        });
    }

    write_sidecar(&results);
}

/// Emit the empirical curve to `target/erasure_survival.json` for the scoreboard to
/// fold in. Hand-rolled JSON (no serde dep in a bench) — small + stable.
fn write_sidecar(results: &[TierResult]) {
    let out = sidecar_path();
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str("  \"schema\": \"ciris-server/erasure-survival/1\",\n");
    s.push_str("  \"codec\": \"ciris_edge codec-fountain (RaptorQ RFC 6330)\",\n");
    s.push_str(&format!(
        "  \"n_source\": {N_SOURCE},\n  \"k_repair\": {K_REPAIR},\n  \"holders\": {TARGET_HOLDERS},\n  \"min_viable_symbols\": {MIN_VIABLE},\n"
    ));
    s.push_str("  \"survival\": [\n");
    for (i, r) in results.iter().enumerate() {
        let comma = if i + 1 < results.len() { "," } else { "" };
        s.push_str(&format!(
            "    {{\"q\": {:.2}, \"label\": \"{}\", \"p_reconstruct\": {:.6}, \"trials\": {}, \"mean_survivors\": {:.3}}}{}\n",
            r.q, r.label, r.p_reconstruct, r.trials, r.mean_survivors, comma
        ));
    }
    s.push_str("  ]\n}\n");

    if let Some(parent) = out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::File::create(&out) {
        Ok(mut f) => {
            let _ = f.write_all(s.as_bytes());
            println!("wrote {}", out.display());
        }
        Err(e) => eprintln!("WARN: could not write {}: {e}", out.display()),
    }
}

/// `<CARGO_TARGET_DIR or ./target>/erasure_survival.json`.
fn sidecar_path() -> PathBuf {
    let base = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target"));
    base.join("erasure_survival.json")
}
