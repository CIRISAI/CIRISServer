//! **Signature overhead — classical vs hybrid, MEASURED on the real substrate primitive.**
//!
//! The production provenance signature on every CEG object / trace is HYBRID:
//! Ed25519 + ML-DSA-65 (the `ciris_crypto::HybridSigner` path the substrate signs with —
//! `pqc_sig = Sign_PQC(data ‖ classical_sig)`, stripping-resistant). This bench measures
//! the per-operation **sign + verify** latency of one signed event on two paths against
//! the SAME small payload (a 64 B event/trace digest), using the substrate's REAL
//! primitives — no hand-rolled crypto:
//!
//!   1. `classical` — `Ed25519Signer::sign` + `Ed25519Verifier::verify` (classical only).
//!   2. `hybrid`    — `HybridSigner::sign` + `HybridVerifier::verify` (Ed25519 + ML-DSA-65,
//!      the production provenance signature).
//!
//! The scoreboard reads the two criterion medians and reports
//! `signature_overhead.overhead_pct = (hybrid − classical) / classical × 100` — a real,
//! defensible "+N%" for the page's "post-quantum provenance costs only N% more" line.
//!
//! Run: `cargo bench --bench sig_overhead`

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use ciris_crypto::{
    ClassicalSigner as _, ClassicalVerifier as _, Ed25519Signer, Ed25519Verifier, HybridSigner,
    HybridVerifier, MlDsa65Signer, MlDsa65Verifier,
};

/// A 64-byte payload standing in for a signed event/trace digest (the unit the
/// provenance signature actually covers per object).
fn payload() -> Vec<u8> {
    (0..64u32)
        .map(|i| (i.wrapping_mul(37) ^ 0x5A) as u8)
        .collect()
}

fn bench_sig(c: &mut Criterion) {
    let data = payload();

    // ── classical: Ed25519-only sign + verify ────────────────────────────────
    let ed_signer = Ed25519Signer::from_seed(&[0x11u8; 32]).expect("ed25519 seed");
    let ed_pk = ed_signer.public_key().expect("ed pk");
    let ed_verifier = Ed25519Verifier::new();

    let mut g = c.benchmark_group("signature");
    g.throughput(Throughput::Elements(1)); // one signed event per iteration

    g.bench_function("classical_sign_verify", |b| {
        b.iter(|| {
            let sig = ed_signer.sign(black_box(&data)).expect("ed sign");
            let ok = ed_verifier
                .verify(black_box(&ed_pk), black_box(&data), black_box(&sig))
                .expect("ed verify");
            assert!(ok);
            black_box(ok)
        });
    });

    // ── hybrid: Ed25519 + ML-DSA-65 sign + verify (production provenance) ─────
    // Fresh signer/verifier pair built from the SAME substrate primitives the
    // production hybrid-signing path composes.
    let h_signer = HybridSigner::new(
        Ed25519Signer::from_seed(&[0x22u8; 32]).expect("ed25519 seed"),
        MlDsa65Signer::from_seed(&[0x33u8; 32]).expect("ml-dsa seed"),
    )
    .expect("hybrid signer");
    let h_verifier = HybridVerifier::new(Ed25519Verifier::new(), MlDsa65Verifier::new());

    g.bench_function("hybrid_sign_verify", |b| {
        b.iter(|| {
            let sig = h_signer.sign(black_box(&data)).expect("hybrid sign");
            let ok = h_verifier
                .verify(black_box(&data), black_box(&sig))
                .expect("hybrid verify");
            assert!(ok);
            black_box(ok)
        });
    });

    g.finish();
}

criterion_group!(benches, bench_sig);
criterion_main!(benches);
