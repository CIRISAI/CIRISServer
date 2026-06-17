//! Operator-facing **holonomic federation scoreboard** (CIRISServer#12/#13).
//!
//! CIRISServer is the fabric node that *runs* the holonomic substrate, so it is
//! where the modeled scale numbers meet reality. This module emits a JSON
//! scoreboard of **measured vs modeled** for each capacity/survival metric, so an
//! operator catches drift (over-replication, survival-floor erosion, convergence
//! stalls) on a live swarm — and a CI run can assert the model against a synthetic
//! federation.
//!
//! What's IMPLEMENTED here (fully grounded — the math is self-contained and the
//! targets come from the scale_model **v0.7** fountain update, CIRISNodeCore#40):
//!   - the **storage tier** — replication overhead, per-peer load, federation
//!     capacity, the **survival floor** (`P(Binomial(H, q) ≥ N)`), the active-
//!     ejection threshold, and the holographic degradation tiers. The survival
//!     calculator REPRODUCES the v0.7 modeled table from first principles (see
//!     the tests), which is exactly what makes "measured vs modeled" trustworthy.
//!
//! What's MEASURED through the fabric (the **substrate tier**, when criterion
//! results are supplied via `scoreboard --criterion-dir target/criterion`): four
//! metrics derived straight from this repo's criterion benches, each carrying its
//! source group/id for provenance —
//!   - `aead_throughput_per_core` ← `av_frame_halves/open` (receiver open-only).
//!   - `alm_tree_depth_vs_n` ← `alm_chain_hop` (per-hop × the FSD §3 4-tier depth).
//!   - `replication_ingest_per_sec` ← `replication_ingest/ingest_new`.
//!   - `stream_fanout_core_frac` ← `stream_fanout_seal_tick` (N=2,000 × 30 fps).
//! With no criterion dir supplied these stay `None` and the tier reads as gated
//! (so non-bench `scoreboard` runs and the unit tests stay all-modeled).
//!
//! What's STILL STUBBED (gated — would be invented numbers otherwise, the very
//! "toy numbers" #12 removes):
//!   - the substrate remainder `mls_commit_barrier` + `cold_join_burst_latency` —
//!     no MLS-commit or cold-join-latency bench exists yet.
//!   - the **holonomic tier** (WholenessWitness, ALM-topology compute, trust
//!     bootstrap, swarm-rarity convergence) — gated on wiring the fountain/
//!     holonomic APIs (CIRISServer#11) + **CIRISRegistry#88**'s composite model
//!     that grounds the targets.

mod scoreboard;

pub use scoreboard::{
    DegradationTier, FountainPolicy, GatedTier, MeasuredMetric, MetricTarget, Scoreboard,
    StorageTier, SubstrateTier, SurvivalPoint,
};
