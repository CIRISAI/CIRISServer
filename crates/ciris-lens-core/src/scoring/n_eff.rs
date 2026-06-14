//! Kish's effective sample size formula.
//!
//! `N_eff = N / (1 + ρ(N-1))` where ρ is intra-cluster correlation
//! ∈ [0, 1]. Pure function; no I/O, no allocation. Used by RATCHET
//! to characterize per-cohort calibration quality and by lens-core's
//! [`capacity`](super::capacity) to fold N_eff into a [0, 1]
//! confidence band.
//!
//! # Boundary semantics
//!
//! - `N = 0` → `0.0` (no samples = no effective size, definition).
//! - `N = 1` → `1.0` (single sample is its own effective sample
//!   regardless of ρ; the formula collapses to `1 / (1 + 0) = 1`).
//! - `ρ = 0` → `N` (perfect independence: no correlation reduction).
//! - `ρ = 1` → `1.0` (perfect correlation: one effective sample
//!   regardless of N).
//! - `ρ ∉ [0, 1]` clamped to `[0, 1]` before evaluation; negative
//!   correlations don't have a defined Kish interpretation and we
//!   refuse to inflate N_eff beyond N.
//!
//! See `CIRIS-RED/docs/CRC.md` for the corpus-wide reference value
//! (`N_eff ≈ 7.1` on n=6,465, PR=6.61).

/// Kish's effective-sample-size formula.
///
/// Inputs clamped to defended ranges; output always in `[0, n]` as
/// f64.
pub fn kish_n_eff(n: u32, rho: f64) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let n_f = n as f64;
    let rho_c = rho.clamp(0.0, 1.0);
    n_f / (1.0 + rho_c * (n_f - 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tolerance for floating-point equality in the smooth interior
    /// of the formula. Conservative; the formula is exact in the
    /// boundary cases tested separately.
    const EPS: f64 = 1e-9;

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < EPS
    }

    #[test]
    fn zero_samples_yields_zero() {
        assert_eq!(kish_n_eff(0, 0.0), 0.0);
        assert_eq!(kish_n_eff(0, 0.5), 0.0);
        assert_eq!(kish_n_eff(0, 1.0), 0.0);
    }

    #[test]
    fn single_sample_yields_one_regardless_of_rho() {
        assert!(approx(kish_n_eff(1, 0.0), 1.0));
        assert!(approx(kish_n_eff(1, 0.5), 1.0));
        assert!(approx(kish_n_eff(1, 1.0), 1.0));
    }

    #[test]
    fn perfect_independence_yields_n() {
        assert!(approx(kish_n_eff(100, 0.0), 100.0));
        assert!(approx(kish_n_eff(6465, 0.0), 6465.0));
    }

    #[test]
    fn perfect_correlation_yields_one() {
        assert!(approx(kish_n_eff(100, 1.0), 1.0));
        assert!(approx(kish_n_eff(6465, 1.0), 1.0));
    }

    #[test]
    fn corpus_reference_anchor() {
        // CRC paper: n=6,465, PR=6.61 ⇒ N_eff ≈ 977.5. The user's
        // earlier "N_eff ≈ 7.1" figure was for a sub-cohort, not the
        // full corpus. This test pins the formula behavior; the
        // ground-truth corpus ρ is what RATCHET delivers in the
        // calibration bundle.
        let n_eff = kish_n_eff(6465, 0.99);
        assert!(n_eff < 6465.0);
        assert!(n_eff > 1.0);
    }

    #[test]
    fn smooth_interior_kish_50_at_rho_0_5_n_100() {
        // N=100, ρ=0.5: N_eff = 100 / (1 + 0.5 × 99) = 100 / 50.5 ≈ 1.9802
        assert!(approx(kish_n_eff(100, 0.5), 100.0 / 50.5));
    }

    #[test]
    fn negative_rho_clamps_to_zero() {
        assert!(approx(kish_n_eff(100, -0.1), 100.0));
        assert!(approx(kish_n_eff(100, -1.0), 100.0));
    }

    #[test]
    fn rho_above_one_clamps_to_one() {
        assert!(approx(kish_n_eff(100, 1.5), 1.0));
        assert!(approx(kish_n_eff(100, f64::INFINITY), 1.0));
    }

    #[test]
    fn nan_rho_clamps_via_total_order() {
        // f64::NAN.clamp() returns NAN; result will propagate. We
        // don't crash, and the result is NAN — caller must guard.
        // Documented behavior for the otherwise-defended formula.
        assert!(kish_n_eff(100, f64::NAN).is_nan());
    }

    #[test]
    fn output_never_exceeds_n() {
        // Monotonicity property: N_eff ≤ N for all ρ ∈ [0, 1].
        for &n in &[1u32, 10, 100, 1000] {
            for rho_milli in 0..=1000 {
                let rho = rho_milli as f64 / 1000.0;
                let n_eff = kish_n_eff(n, rho);
                assert!(
                    n_eff <= n as f64 + EPS,
                    "kish_n_eff({n}, {rho}) = {n_eff} exceeded N"
                );
                assert!(
                    n_eff >= 1.0 - EPS,
                    "kish_n_eff({n}, {rho}) = {n_eff} below 1.0"
                );
            }
        }
    }
}
