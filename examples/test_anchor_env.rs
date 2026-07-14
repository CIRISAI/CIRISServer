//! HARNESS generator (CIRISServer#258 / CIRISPersist#451) — derive the FULL
//! test-anchor env block from `CIRIS_TEST_TRUST_ROOT_SEED`, so
//! `harness/mesh-repro/docker-compose.yml` carries a self-consistent SW trust
//! root: anchor pubkeys (Ed25519 + ML-DSA-65) AND the real self-scrub signature
//! pair over persist's pinned synthesized envelope
//! (`JCS({"key_id":"test-accord-holder-0","test_anchor":true})`, sign_bound) —
//! the #451 contract that makes the seeded terminus scrub-VERIFYING so
//! persist's own `root_binding` Confirms through it.
//!
//! Run:  CIRIS_TEST_TRUST_ROOT_SEED=<b64 32B> \
//!       cargo run --release --example test_anchor_env
//!
//! Deterministic per seed except the ML-DSA signature (hedged/randomized) —
//! any emitted signature verifies, so regenerate-and-paste is always safe.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer, PqcSigner as _};
    use ciris_verify_core::self_at_login::{HybridSigningIdentity, SelfSigner as _};

    let seed_b64 = std::env::var("CIRIS_TEST_TRUST_ROOT_SEED")
        .map_err(|_| "set CIRIS_TEST_TRUST_ROOT_SEED (base64 of exactly 32 bytes)")?;
    let ed_seed: [u8; 32] = B64
        .decode(seed_b64.trim())?
        .try_into()
        .map_err(|_| "seed must decode to exactly 32 bytes")?;

    // SAME derivation as src/test_bless.rs — one env seeds the whole hybrid root.
    let ml_seed: [u8; 32] = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"ciris-test-trust-root/mldsa/v1");
        h.update(ed_seed);
        h.finalize().into()
    };
    let ed = Ed25519Signer::from_seed(&ed_seed)?;
    let mldsa = MlDsa65Signer::from_seed(&ml_seed)?;
    let ed_pub = B64.encode(ed.public_key()?);
    let ml_pub = B64.encode(mldsa.public_key()?);

    // persist v17.2.0's PINNED synthesized envelope for holder slot 0 —
    // byte-identical canonicalization (JCS) to what the genesis seed verifies.
    let root = HybridSigningIdentity::new("test-accord-holder-0".to_string(), ed, mldsa);
    let envelope = serde_json::json!({ "key_id": "test-accord-holder-0", "test_anchor": true });
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)?;
    let rt = tokio::runtime::Builder::new_current_thread().build()?;
    let (scrub_ed, scrub_pqc) = rt.block_on(root.sign_bound(&canonical))?;

    println!("# test-anchor env block (paste into harness/mesh-repro/docker-compose.yml)");
    println!("CIRIS_TESTING_MODE: \"true\"");
    println!("CIRIS_TEST_TRUST_ROOT: \"{ed_pub}\"");
    println!("CIRIS_TEST_TRUST_ROOT_PQC: \"{ml_pub}\"");
    println!("CIRIS_TEST_TRUST_ROOT_SCRUB: \"{scrub_ed}\"");
    println!("CIRIS_TEST_TRUST_ROOT_SCRUB_PQC: \"{scrub_pqc}\"");
    println!("CIRIS_TEST_TRUST_ROOT_SEED: \"{}\"", seed_b64.trim());
    Ok(())
}
