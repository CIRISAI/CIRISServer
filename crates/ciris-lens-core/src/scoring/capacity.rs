//! Capacity — federation-confidence band [0, 1] derived from N_eff
//! and the per-cohort sample-size gate.
//!
//! ```text
//!                              n_eff
//!   capacity = clamp01( ─────────────────── )
//!                       target_n_eff - gate
//!   shifted so n_eff ≤ gate → 0 and n_eff ≥ target → 1
//! ```
//!
//! # Semantics
//!
//! - `n_eff ≤ gate` → `0.0`. Below the LC-AV-18 sample-size gate the
//!   cohort isn't trustworthy for scoring; capacity reports zero
//!   confidence. (Assembly returns
//!   `Indeterminate::SampleSizeBelowGate` for the trace itself; the
//!   capacity number is consumer telemetry, not the gate decision.)
//! - `n_eff ≥ target_n_eff` → `1.0`. Saturated — the federation has
//!   enough independent observations that scoring is at full
//!   confidence.
//! - In between: linear interpolation.
//! - `target_n_eff ≤ gate` → degenerate; returns `1.0` if
//!   `n_eff > gate`, `0.0` otherwise. Documented as caller's
//!   responsibility to pass `target_n_eff > gate`.
//!
//! `target_n_eff` is a RATCHET calibration parameter; for v0.1.0
//! callers pass it explicitly. Future versions read it from the
//! calibration bundle (CIRISPersist#18
//! `calibration_bundles.target_n_eff` if/when added).

/// Linear capacity band in `[0, 1]`.
pub fn capacity(n_eff: f64, sample_size_gate: u32, target_n_eff: f64) -> f64 {
    let gate_f = sample_size_gate as f64;
    if n_eff <= gate_f {
        return 0.0;
    }
    if n_eff >= target_n_eff {
        return 1.0;
    }
    // Guard against degenerate target ≤ gate; falls to the
    // "n_eff > gate" branch above when target_n_eff ≤ gate, so this
    // subtraction is non-zero by the time we reach it.
    let span = target_n_eff - gate_f;
    if span <= 0.0 {
        // Degenerate: target ≤ gate. Caller bug, but we choose a
        // defined output rather than NaN — favor "we have at least
        // gate samples" → 1.0.
        return 1.0;
    }
    ((n_eff - gate_f) / span).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 1e-9;

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < EPS
    }

    #[test]
    fn zero_n_eff_is_zero_capacity() {
        assert_eq!(capacity(0.0, 30, 100.0), 0.0);
    }

    #[test]
    fn at_gate_is_zero_capacity() {
        // Boundary: equal-to-gate is still "below" by the strict <=
        // check. LC-AV-18 wants fail-secure at the boundary.
        assert_eq!(capacity(30.0, 30, 100.0), 0.0);
    }

    #[test]
    fn at_target_is_full_capacity() {
        assert_eq!(capacity(100.0, 30, 100.0), 1.0);
    }

    #[test]
    fn above_target_saturates_at_one() {
        assert_eq!(capacity(500.0, 30, 100.0), 1.0);
        assert_eq!(capacity(f64::INFINITY, 30, 100.0), 1.0);
    }

    #[test]
    fn midpoint_is_half_capacity() {
        // gate=30, target=130, n_eff=80 → (80-30)/(130-30) = 0.5
        assert!(approx(capacity(80.0, 30, 130.0), 0.5));
    }

    #[test]
    fn quarter_point_is_quarter_capacity() {
        // gate=0, target=100, n_eff=25 → 0.25
        assert!(approx(capacity(25.0, 0, 100.0), 0.25));
    }

    #[test]
    fn degenerate_target_le_gate_returns_one_when_above_gate() {
        // Caller bug: target ≤ gate. Documented to return 1.0
        // when n_eff > gate (rather than NaN from divide-by-zero or
        // negative).
        assert_eq!(capacity(50.0, 30, 30.0), 1.0);
        assert_eq!(capacity(50.0, 30, 20.0), 1.0);
    }

    #[test]
    fn degenerate_target_le_gate_returns_zero_when_at_or_below_gate() {
        assert_eq!(capacity(30.0, 30, 20.0), 0.0);
        assert_eq!(capacity(0.0, 30, 20.0), 0.0);
    }

    #[test]
    fn output_in_unit_interval_for_random_inputs() {
        for n_milli in 0..=2000 {
            let n_eff = n_milli as f64 / 10.0; // 0 .. 200
            let c = capacity(n_eff, 30, 100.0);
            assert!(
                (0.0..=1.0).contains(&c),
                "capacity({n_eff}, 30, 100.0) = {c} outside [0, 1]"
            );
        }
    }
}
