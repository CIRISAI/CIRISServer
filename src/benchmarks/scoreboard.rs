//! The scoreboard data model + the storage-tier calculator.
//!
//! All storage-tier numbers derive from a [`FountainPolicy`] and the binomial
//! survival math; the modeled curve this produces matches the scale_model v0.7
//! targets in CIRISServer#13 (asserted in the tests). The "measured" fields are
//! `Option` overlays a live node fills from observed holders / real per-peer
//! availability `q`; left `None` they yield a pure modeled scoreboard for CI.

use serde::Serialize;

/// Fountain replication policy. `n` = symbols required to reconstruct (content is
/// split into `n` symbols, each ~`1/n` of the content); `h` = distinct holders
/// (one symbol each); `k` = fountain repair parameter. Reference default is the
/// CIRISRegistry#86 §R-policy point at q≈0.85.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct FountainPolicy {
    pub n: u32,
    pub k: u32,
    pub h: u32,
}

impl FountainPolicy {
    /// The v0.7 / #86 reference: N=20, K=6, H=30 → 1.5× overhead at q≈0.85.
    pub const REFERENCE: FountainPolicy = FountainPolicy { n: 20, k: 6, h: 30 };

    /// Distinct-holder replication overhead `H/N` (target 1.5×).
    pub fn overhead(&self) -> f64 {
        self.h as f64 / self.n as f64
    }

    /// Per-peer symbol load as a fraction of content size (`1/N`, target 5%).
    pub fn per_peer_load_frac(&self) -> f64 {
        1.0 / self.n as f64
    }

    /// Active-ejection threshold (CEG §19.3 `should_eject_above_target`): trim
    /// kicks in above `H × 1.15` (e.g. 34.5 for H=30).
    pub fn eject_threshold(&self) -> f64 {
        self.h as f64 * 1.15
    }

    /// Federation distinct-content capacity (bytes) for a given total disk:
    /// `total_disk / overhead` (vs `/N` for whole-copy replication — a ~3.3× win).
    pub fn capacity_bytes(&self, total_disk_bytes: f64) -> f64 {
        total_disk_bytes / self.overhead()
    }

    /// Reconstruction survival probability `P(Binomial(h, q) ≥ n)` for a given
    /// per-peer availability `q` and holder count `h` (defaults to policy `h`).
    pub fn survival(&self, q: f64, holders: u32) -> f64 {
        binomial_survival(holders, self.n, q)
    }
}

/// `P(X ≥ n)` for `X ~ Binomial(h, q)`, computed in log-space (stable for the
/// H≈20–40 range the policy uses).
fn binomial_survival(h: u32, n: u32, q: f64) -> f64 {
    if n == 0 {
        return 1.0;
    }
    if n > h {
        return 0.0;
    }
    let q = q.clamp(0.0, 1.0);
    if q == 0.0 {
        return 0.0;
    }
    if q == 1.0 {
        return 1.0;
    }
    let (lq, l1q) = (q.ln(), (1.0 - q).ln());
    let mut sum = 0.0;
    for k in n..=h {
        let log_pmf = ln_choose(h, k) + (k as f64) * lq + ((h - k) as f64) * l1q;
        sum += log_pmf.exp();
    }
    sum.clamp(0.0, 1.0)
}

fn ln_choose(h: u32, k: u32) -> f64 {
    ln_factorial(h) - ln_factorial(k) - ln_factorial(h - k)
}

fn ln_factorial(n: u32) -> f64 {
    (2..=n).map(|i| (i as f64).ln()).sum()
}

/// A modeled target with its alarm band and an optional live measurement.
#[derive(Debug, Clone, Serialize)]
pub struct MetricTarget {
    pub modeled: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alarm_high: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alarm_low: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measured: Option<f64>,
}

impl MetricTarget {
    fn new(modeled: f64, alarm_low: Option<f64>, alarm_high: Option<f64>) -> Self {
        MetricTarget {
            modeled,
            alarm_high,
            alarm_low,
            measured: None,
        }
    }
    /// True when a live measurement has breached its alarm band.
    pub fn alarming(&self) -> bool {
        match self.measured {
            None => false,
            Some(m) => {
                self.alarm_high.is_some_and(|hi| m > hi) || self.alarm_low.is_some_and(|lo| m < lo)
            }
        }
    }
}

/// One point on the survival curve `q → P(reconstruct)`.
#[derive(Debug, Clone, Serialize)]
pub struct SurvivalPoint {
    pub q: f64,
    pub label: &'static str,
    pub p_reconstruct: f64,
}

/// One holographic degradation tier (capacity grows under pressure as holders shed
/// toward the `min_viable=5` floor).
#[derive(Debug, Clone, Serialize)]
pub struct DegradationTier {
    pub tier: &'static str,
    pub holders: u32,
    pub overhead_multiplier: f64,
}

/// The storage-tier scoreboard (CIRISServer#13).
#[derive(Debug, Clone, Serialize)]
pub struct StorageTier {
    pub replication_overhead: MetricTarget,
    pub per_peer_load_frac: MetricTarget,
    pub eject_threshold_holders: f64,
    /// Survival floor (≥99% alarm) and target (≥99.95% at the design q).
    pub survival_floor: f64,
    pub survival_target: f64,
    pub design_q: f64,
    /// Modeled survival curve — reproduced from the binomial, not hard-coded.
    pub survival_curve: Vec<SurvivalPoint>,
    /// Live survival recomputed from measured `q` + observed holders (if running).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measured_survival: Option<f64>,
    pub degradation_tiers: Vec<DegradationTier>,
}

/// A tier we can't ground yet — emitted so the scoreboard is honest about scope
/// rather than fabricating numbers (the "toy numbers" #12 removes).
#[derive(Debug, Clone, Serialize)]
pub struct GatedTier {
    pub status: &'static str,
    pub gated_on: &'static str,
    pub metrics: Vec<&'static str>,
}

/// The full operator scoreboard.
#[derive(Debug, Clone, Serialize)]
pub struct Scoreboard {
    pub schema: &'static str,
    pub policy: FountainPolicy,
    pub storage: StorageTier,
    pub substrate: GatedTier,
    pub holonomic: GatedTier,
}

/// The standard per-peer availability grid the v0.7 model reports against.
const Q_GRID: &[(f64, &str)] = &[
    (0.95, "datacenter"),
    (0.90, "typical wifi"),
    (0.85, "medium churn (design target)"),
    (0.80, "high churn"),
    (0.70, "battlefield mesh"),
];

impl Scoreboard {
    /// Build the modeled scoreboard for a policy (no live measurements). The
    /// storage tier is fully grounded; substrate/holonomic are honest stubs.
    pub fn modeled(policy: FountainPolicy) -> Self {
        let survival_curve = Q_GRID
            .iter()
            .map(|&(q, label)| SurvivalPoint {
                q,
                label,
                p_reconstruct: policy.survival(q, policy.h),
            })
            .collect();

        // Holographic degradation tiers (holders → overhead multiplier), shedding
        // toward min_viable=5.
        let degradation_tiers = vec![
            DegradationTier {
                tier: "none",
                holders: policy.h,
                overhead_multiplier: policy.overhead(),
            },
            DegradationTier {
                tier: "warn",
                holders: policy.n,
                overhead_multiplier: 1.0,
            },
            DegradationTier {
                tier: "crit",
                holders: 14,
                overhead_multiplier: 0.7,
            },
            DegradationTier {
                tier: "stop",
                holders: 5,
                overhead_multiplier: 0.25,
            },
            DegradationTier {
                tier: "host-at-risk",
                holders: 0,
                overhead_multiplier: 0.0,
            },
        ];

        let storage = StorageTier {
            replication_overhead: MetricTarget::new(policy.overhead(), Some(1.0), Some(2.0)),
            per_peer_load_frac: MetricTarget::new(policy.per_peer_load_frac(), None, Some(0.10)),
            eject_threshold_holders: policy.eject_threshold(),
            survival_floor: 0.99,
            survival_target: 0.9995,
            design_q: 0.85,
            survival_curve,
            measured_survival: None,
            degradation_tiers,
        };

        Scoreboard {
            schema: "ciris-server/holonomic-scoreboard/1",
            policy,
            storage,
            substrate: GatedTier {
                status: "gated",
                gated_on: "edge v4.1.1 NETWORK_CAPACITY_MODEL.md + benches (CIRISEdge PR#147)",
                metrics: vec![
                    "aead_throughput_per_core",
                    "alm_tree_depth_vs_n",
                    "mls_commit_barrier",
                    "cold_join_burst_latency",
                ],
            },
            holonomic: GatedTier {
                status: "gated",
                gated_on: "fountain/holonomic API wiring (CIRISServer#11) + CIRISRegistry#88 composite model",
                metrics: vec![
                    "wholeness_witness_reconciliation",
                    "alm_topology_compute",
                    "recursive_trust_bootstrap_walk",
                    "swarm_rarity_convergence",
                ],
            },
        }
    }

    /// Overlay a live measurement: observed median holder count + measured per-peer
    /// availability `q`. Recomputes overhead and the survival probability against
    /// the floor (the early-warning signal before content becomes unreconstructable).
    pub fn with_measurement(mut self, observed_holders: u32, measured_q: f64) -> Self {
        self.storage.replication_overhead.measured =
            Some(observed_holders as f64 / self.policy.n as f64);
        self.storage.measured_survival = Some(self.policy.survival(measured_q, observed_holders));
        self
    }

    /// True if any grounded metric is in an alarm state (drives operator alerts).
    pub fn alarming(&self) -> bool {
        self.storage.replication_overhead.alarming()
            || self.storage.per_peer_load_frac.alarming()
            || self
                .storage
                .measured_survival
                .is_some_and(|s| s < self.storage.survival_floor)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("scoreboard serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    #[test]
    fn overhead_and_load_match_v07_targets() {
        let p = FountainPolicy::REFERENCE;
        assert!(approx(p.overhead(), 1.5, 1e-9), "overhead {}", p.overhead());
        assert!(approx(p.per_peer_load_frac(), 0.05, 1e-9));
        assert!(approx(p.eject_threshold(), 34.5, 1e-9));
        // Capacity: fountain overhead 1.5× vs whole-copy ~5× (the replication
        // factor for equivalent durability) → 3.3× more distinct content carried.
        const WHOLE_COPY_OVERHEAD: f64 = 5.0;
        assert!(approx(WHOLE_COPY_OVERHEAD / p.overhead(), 3.333, 0.01));
    }

    #[test]
    fn survival_curve_reproduces_v07_model() {
        // The load-bearing check: our binomial reproduces the scale_model v0.7
        // table at H=30 / N=20 (CIRISServer#13), proving "modeled" is first-principles.
        let p = FountainPolicy::REFERENCE;
        assert!(
            p.survival(0.95, 30) >= 0.9999,
            "q=0.95 -> {}",
            p.survival(0.95, 30)
        );
        assert!(
            approx(p.survival(0.90, 30), 0.9999, 0.0005),
            "q=0.90 -> {}",
            p.survival(0.90, 30)
        );
        assert!(
            approx(p.survival(0.85, 30), 0.997, 0.003),
            "q=0.85 -> {}",
            p.survival(0.85, 30)
        );
        assert!(
            approx(p.survival(0.80, 30), 0.974, 0.006),
            "q=0.80 -> {}",
            p.survival(0.80, 30)
        );
        assert!(
            approx(p.survival(0.70, 30), 0.730, 0.02),
            "q=0.70 -> {}",
            p.survival(0.70, 30)
        );
    }

    #[test]
    fn survival_floor_alarm_fires() {
        // At q=0.85 the design target holds; if holders erode (e.g. to 22) under
        // high churn the live survival should drop and the alarm should fire.
        let board = Scoreboard::modeled(FountainPolicy::REFERENCE);
        assert!(!board.alarming(), "modeled-only board must not alarm");
        let degraded = Scoreboard::modeled(FountainPolicy::REFERENCE).with_measurement(22, 0.70);
        assert!(
            degraded.storage.measured_survival.unwrap() < 0.99,
            "eroded holders @ high churn must dip under the 99% floor: {:?}",
            degraded.storage.measured_survival
        );
        assert!(degraded.alarming(), "survival under floor must alarm");
    }

    #[test]
    fn over_replication_alarms() {
        // > 2.0× distinct holders = wasted disk → alarm.
        let board = Scoreboard::modeled(FountainPolicy::REFERENCE).with_measurement(45, 0.85);
        assert!(
            board.storage.replication_overhead.alarming(),
            "45/20 = 2.25x must alarm high"
        );
    }

    #[test]
    fn json_emits() {
        let j = Scoreboard::modeled(FountainPolicy::REFERENCE).to_json();
        assert!(j.contains("holonomic-scoreboard/1"));
        assert!(j.contains("survival_curve"));
        assert!(j.contains("gated"));
    }
}
