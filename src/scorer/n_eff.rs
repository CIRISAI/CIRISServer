//! N_eff — effective independent participatory constraints.
//!
//! A faithful Rust port of CIRISLens `scripts/measure_n_eff.py:141-186`
//! (`compute_n_eff`). The pipeline:
//!
//! 1. Build the per-trace feature matrix over a window (rows = traces, cols =
//!    the lens constraint dims — [`FEATURE_DIM`] columns, drawn from the same
//!    `trace_context` fields measure_n_eff.py reads, here surfaced on persist's
//!    [`TraceSummary`]).
//! 2. Impute column-mean for missing optional gates, drop zero-variance columns,
//!    and standardize the rest to Z (z-score, `ddof=1`).
//! 3. Covariance `C = cov(Z, rowvar=False)`. Symmetric eigendecomposition
//!    (`eigh`), eigenvalues clipped to `>= 0`.
//! 4. `n_eff_pr = (Σλ)² / Σ(λ²)` (participation ratio) and
//!    `n_eff_h = exp(-Σ p·ln(p+1e-30))`, `p = λ/Σλ` (entropy perplexity).
//!
//! ## Which measure feeds `capacity()`
//!
//! The scorer feeds **`n_eff_pr`** (participation ratio) into
//! `scoring::capacity::capacity`. measure_n_eff.py reports both and notes PR
//! "penalizes variance concentration more aggressively" — the conservative
//! choice for an anti-Sybil independence claim (a near-degenerate spectrum is
//! pushed toward 1, not flattered). `scoring/calibration.rs` does not specify a
//! preference, so we take the conservative measure. `n_eff_h` is computed and
//! carried in the attestation envelope as corroborating telemetry.
//!
//! ## Eigensolver
//!
//! No linalg crate (nalgebra/ndarray) is in the dependency graph, and the
//! covariance matrix is tiny (at most [`FEATURE_DIM`]² = a few hundred
//! entries). We use the **classic cyclic Jacobi eigenvalue algorithm** for real
//! symmetric matrices — pure Rust, exact for the symmetric covariance, no new
//! dependency. (`numpy.linalg.eigh` is LAPACK's symmetric tridiagonal QR; Jacobi
//! converges to the same eigenvalues — only the eigenvalue *spectrum* feeds
//! N_eff, and both measures are eigenvector-free, so Jacobi vs QR is
//! numerically equivalent for our purpose.)

use ciris_persist::prelude::TraceSummary;

/// The lens constraint-vector dimension — the columns of the feature matrix.
/// A subset of measure_n_eff.py's 17-col vector: exactly the columns persist's
/// [`TraceSummary`] denormalizes (the others — `entropy_level`, `coherence_score`,
/// etc. — are not surfaced on the summary row; absent dims simply lower the
/// dimensionality, which N_eff handles correctly).
pub const FEATURE_DIM: usize = 11;

/// Extract the [`FEATURE_DIM`]-wide feature row for one trace summary. Missing
/// numeric scores map to `None` → imputed later; missing boolean gates map to a
/// neutral midpoint sentinel that the impute step treats as "missing".
fn feature_row(t: &TraceSummary) -> [Option<f64>; FEATURE_DIM] {
    // measure_n_eff.py CASE-maps each boolean gate to {0,1}; absent → NULL.
    let b = |o: Option<bool>| o.map(|v| if v { 1.0 } else { 0.0 });
    [
        t.csdma_plausibility_score,
        t.dsdma_domain_alignment,
        t.idma_k_eff,
        t.idma_correlation_risk,
        b(t.idma_fragility_flag),
        b(t.conscience_passed),
        b(t.action_was_overridden),
        b(t.entropy_passed),
        b(t.coherence_passed),
        b(t.optimization_veto_passed),
        b(t.epistemic_humility_passed),
    ]
}

/// Build the per-agent feature matrix (rows = traces, cols = constraint dims).
/// Mirrors measure_n_eff.py's null discipline: drop rows where the two
/// most-essential features (`csdma_plausibility_score`, `idma_k_eff`) are both
/// missing — a row with no DMA signal carries no constraint information. The
/// remaining `None`s are imputed to column means in [`n_eff`].
pub fn feature_matrix(traces: &[&TraceSummary]) -> Vec<[Option<f64>; FEATURE_DIM]> {
    traces
        .iter()
        .map(|t| feature_row(t))
        .filter(|row| {
            // measure_n_eff.py: df.dropna(subset=["csdma_plausibility_score",
            // "idma_k_eff"]). We keep the row if EITHER essential feature is
            // present (a slightly more permissive — but honest — filter for the
            // summary surface, which may carry only one DMA family).
            row[0].is_some() || row[2].is_some()
        })
        .collect()
}

/// The N_eff derivation result — both measures + the realized feature
/// dimensionality (post zero-variance-column drop).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NEff {
    /// Participation ratio: `(Σλ)² / Σλ²`. The measure fed into `capacity()`.
    pub n_eff_pr: f64,
    /// Entropy perplexity: `exp(-Σ p·ln(p+1e-30))`, `p = λ/Σλ`. Telemetry.
    pub n_eff_h: f64,
    /// Number of non-degenerate feature columns the spectrum was computed over.
    pub feature_dim: usize,
}

/// Compute N_eff from a feature matrix (faithful port of
/// measure_n_eff.py:compute_n_eff). Returns `n_eff_pr = n_eff_h = 0.0` for a
/// matrix that collapses to zero usable columns (degenerate corpus → no
/// effective constraint, which `capacity()` correctly floors to 0).
// Symmetric-matrix covariance assembly cross-indexes `cov[i][j]` / `cov[j][i]`
// and row[i]·row[j]; the explicit index loops are the clearest expression and an
// iterator rewrite would obscure the math (clippy::needless_range_loop).
#[allow(clippy::needless_range_loop)]
pub fn n_eff(matrix: &[[Option<f64>; FEATURE_DIM]]) -> NEff {
    let n = matrix.len();
    if n == 0 {
        return NEff {
            n_eff_pr: 0.0,
            n_eff_h: 0.0,
            feature_dim: 0,
        };
    }

    // ── Impute column means over present values (df.fillna(df.mean())) ────────
    let mut col_sum = [0.0f64; FEATURE_DIM];
    let mut col_cnt = [0usize; FEATURE_DIM];
    for row in matrix {
        for c in 0..FEATURE_DIM {
            if let Some(v) = row[c] {
                if v.is_finite() {
                    col_sum[c] += v;
                    col_cnt[c] += 1;
                }
            }
        }
    }
    let col_mean: [f64; FEATURE_DIM] = std::array::from_fn(|c| {
        if col_cnt[c] > 0 {
            col_sum[c] / col_cnt[c] as f64
        } else {
            0.0
        }
    });

    // Dense imputed matrix.
    let dense: Vec<[f64; FEATURE_DIM]> = matrix
        .iter()
        .map(|row| std::array::from_fn(|c| row[c].filter(|v| v.is_finite()).unwrap_or(col_mean[c])))
        .collect();

    // ── Standardize: keep only columns with std > 1e-9 (sigma > 1e-9 mask) ────
    let n_f = n as f64;
    let mut mu = [0.0f64; FEATURE_DIM];
    for row in &dense {
        for c in 0..FEATURE_DIM {
            mu[c] += row[c];
        }
    }
    for m in mu.iter_mut() {
        *m /= n_f;
    }
    // Sample std (ddof=1, matching numpy std(ddof=1)).
    let mut var = [0.0f64; FEATURE_DIM];
    for row in &dense {
        for c in 0..FEATURE_DIM {
            let d = row[c] - mu[c];
            var[c] += d * d;
        }
    }
    let denom = if n > 1 { (n - 1) as f64 } else { 1.0 };
    let sigma: [f64; FEATURE_DIM] = std::array::from_fn(|c| (var[c] / denom).sqrt());

    let keep: Vec<usize> = (0..FEATURE_DIM).filter(|&c| sigma[c] > 1e-9).collect();
    let k = keep.len();
    if k == 0 {
        // All columns constant → no variance, no effective constraint.
        return NEff {
            n_eff_pr: 0.0,
            n_eff_h: 0.0,
            feature_dim: 0,
        };
    }

    // Z-scored matrix over kept columns.
    let z: Vec<Vec<f64>> = dense
        .iter()
        .map(|row| keep.iter().map(|&c| (row[c] - mu[c]) / sigma[c]).collect())
        .collect();

    // ── Covariance C = cov(Z, rowvar=False) — k×k, ddof=1 ────────────────────
    // Z columns are already zero-mean (within float), so cov_ij = Σ z_i z_j / (n-1).
    let mut cov = vec![vec![0.0f64; k]; k];
    for row in &z {
        for i in 0..k {
            for j in i..k {
                cov[i][j] += row[i] * row[j];
            }
        }
    }
    for i in 0..k {
        for j in i..k {
            let v = cov[i][j] / denom;
            cov[i][j] = v;
            cov[j][i] = v;
        }
    }

    // ── Symmetric eigendecomposition (eigh) → eigenvalues, clipped >= 0 ───────
    let mut eigvals = jacobi_eigenvalues(cov);
    for e in eigvals.iter_mut() {
        if *e < 0.0 {
            *e = 0.0; // np.clip(eigvals, 0, None)
        }
    }

    // ── Participation ratio + entropy perplexity ─────────────────────────────
    let total: f64 = eigvals.iter().sum();
    if total <= 0.0 {
        return NEff {
            n_eff_pr: 0.0,
            n_eff_h: 0.0,
            feature_dim: k,
        };
    }
    let sum_sq: f64 = eigvals.iter().map(|l| l * l).sum();
    let n_eff_pr = if sum_sq > 0.0 {
        (total * total) / sum_sq
    } else {
        0.0
    };
    let n_eff_h = {
        // p = λ/Σλ; H = -Σ p·ln(p + 1e-30); n_eff_h = exp(H).
        let h: f64 = eigvals
            .iter()
            .map(|&l| {
                let p = l / total;
                p * (p + 1e-30).ln()
            })
            .sum();
        (-h).exp()
    };

    NEff {
        n_eff_pr,
        n_eff_h,
        feature_dim: k,
    }
}

/// Eigenvalues of a real symmetric matrix via the classic cyclic Jacobi
/// rotation algorithm. Returns the diagonal after convergence (the eigenvalues,
/// unordered — order is irrelevant to both N_eff measures). The matrix is
/// consumed (rotated in place).
// Jacobi rotation cross-indexes rows/cols p and q symmetrically (`a[i][p]` /
// `a[p][i]`); index loops are the standard, clearest form (clippy::needless_range_loop).
#[allow(clippy::needless_range_loop)]
fn jacobi_eigenvalues(mut a: Vec<Vec<f64>>) -> Vec<f64> {
    let n = a.len();
    if n == 0 {
        return Vec::new();
    }
    if n == 1 {
        return vec![a[0][0]];
    }

    // Frobenius-norm of the off-diagonal — the convergence target.
    let off = |m: &[Vec<f64>]| -> f64 {
        let mut s = 0.0;
        for i in 0..n {
            for j in (i + 1)..n {
                s += 2.0 * m[i][j] * m[i][j];
            }
        }
        s.sqrt()
    };

    // Tolerance scaled to the matrix magnitude; cap sweeps so a pathological
    // input can never spin forever.
    let scale: f64 = a.iter().flat_map(|r| r.iter()).map(|v| v.abs()).sum();
    let tol = 1e-12 * scale.max(1.0);
    let max_sweeps = 100;

    for _ in 0..max_sweeps {
        if off(&a) <= tol {
            break;
        }
        for p in 0..n {
            for q in (p + 1)..n {
                let apq = a[p][q];
                if apq.abs() <= f64::EPSILON {
                    continue;
                }
                let app = a[p][p];
                let aqq = a[q][q];
                // Jacobi rotation angle (Golub & Van Loan, Alg. 8.4.1).
                let theta = (aqq - app) / (2.0 * apq);
                let t = theta.signum() / (theta.abs() + (theta * theta + 1.0).sqrt());
                let c = 1.0 / (t * t + 1.0).sqrt();
                let s = t * c;

                // Apply the rotation to rows/cols p and q.
                for i in 0..n {
                    if i != p && i != q {
                        let aip = a[i][p];
                        let aiq = a[i][q];
                        a[i][p] = c * aip - s * aiq;
                        a[p][i] = a[i][p];
                        a[i][q] = s * aip + c * aiq;
                        a[q][i] = a[i][q];
                    }
                }
                a[p][p] = c * c * app - 2.0 * s * c * apq + s * s * aqq;
                a[q][q] = s * s * app + 2.0 * s * c * apq + c * c * aqq;
                a[p][q] = 0.0;
                a[q][p] = 0.0;
            }
        }
    }

    (0..n).map(|i| a[i][i]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 1e-6;

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < EPS
    }

    #[test]
    fn jacobi_diagonal_matrix_returns_diagonal() {
        let m = vec![vec![3.0, 0.0], vec![0.0, 5.0]];
        let mut ev = jacobi_eigenvalues(m);
        ev.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert!(approx(ev[0], 3.0));
        assert!(approx(ev[1], 5.0));
    }

    #[test]
    fn jacobi_known_2x2() {
        // [[2,1],[1,2]] has eigenvalues 1 and 3.
        let m = vec![vec![2.0, 1.0], vec![1.0, 2.0]];
        let mut ev = jacobi_eigenvalues(m);
        ev.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert!(approx(ev[0], 1.0), "got {ev:?}");
        assert!(approx(ev[1], 3.0), "got {ev:?}");
    }

    #[test]
    fn jacobi_trace_invariant_3x3() {
        // Sum of eigenvalues == trace (a Jacobi-rotation invariant).
        let m = vec![
            vec![4.0, 1.0, 0.5],
            vec![1.0, 3.0, 0.2],
            vec![0.5, 0.2, 2.0],
        ];
        let trace: f64 = (0..3).map(|i| m[i][i]).sum();
        let ev = jacobi_eigenvalues(m);
        let sum: f64 = ev.iter().sum();
        assert!(approx(sum, trace), "eig sum {sum} != trace {trace}");
    }

    /// Independent (orthogonal) features → spectrum near-uniform → N_eff near
    /// the feature dimension (the participation ratio's whole point).
    #[test]
    fn independent_features_give_high_n_eff() {
        // 4 features, each an independent ±1 pattern across 8 rows.
        let rows = [
            [1.0, 1.0, 1.0, 1.0],
            [-1.0, 1.0, -1.0, 1.0],
            [1.0, -1.0, -1.0, 1.0],
            [-1.0, -1.0, 1.0, 1.0],
            [1.0, 1.0, -1.0, -1.0],
            [-1.0, 1.0, 1.0, -1.0],
            [1.0, -1.0, 1.0, -1.0],
            [-1.0, -1.0, -1.0, -1.0],
        ];
        let matrix: Vec<[Option<f64>; FEATURE_DIM]> = rows
            .iter()
            .map(|r| {
                let mut row = [None; FEATURE_DIM];
                for (c, v) in r.iter().enumerate() {
                    row[c] = Some(*v);
                }
                row
            })
            .collect();
        let res = n_eff(&matrix);
        // Orthogonal columns → equal eigenvalues → PR == dim (4).
        assert!(
            res.n_eff_pr > 3.5,
            "orthogonal 4-feature corpus should have n_eff_pr≈4, got {}",
            res.n_eff_pr
        );
        assert_eq!(res.feature_dim, 4);
    }

    /// Perfectly correlated features → one effective dimension → N_eff ≈ 1.
    #[test]
    fn correlated_features_give_low_n_eff() {
        let matrix: Vec<[Option<f64>; FEATURE_DIM]> = (0..30)
            .map(|i| {
                let v = (i as f64) * 0.1;
                let mut row = [None; FEATURE_DIM];
                // Three columns that are exact scalar multiples → rank 1.
                row[0] = Some(v);
                row[1] = Some(2.0 * v);
                row[2] = Some(-v);
                row
            })
            .collect();
        let res = n_eff(&matrix);
        assert!(
            res.n_eff_pr < 1.5,
            "rank-1 corpus should have n_eff_pr≈1, got {}",
            res.n_eff_pr
        );
    }

    #[test]
    fn empty_matrix_is_zero() {
        let res = n_eff(&[]);
        assert_eq!(res.n_eff_pr, 0.0);
        assert_eq!(res.n_eff_h, 0.0);
    }

    #[test]
    fn constant_columns_yield_zero_n_eff() {
        // Every column constant → zero variance → no effective constraint.
        let matrix: Vec<[Option<f64>; FEATURE_DIM]> = (0..25)
            .map(|_| {
                let mut row = [None; FEATURE_DIM];
                row[0] = Some(0.5);
                row[2] = Some(0.5);
                row
            })
            .collect();
        let res = n_eff(&matrix);
        assert_eq!(res.n_eff_pr, 0.0, "constant corpus must floor n_eff to 0");
    }
}
