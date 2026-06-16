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
//! What's STUBBED (gated — would be invented numbers otherwise, the very "toy
//! numbers" #12 removes):
//!   - the **substrate tier** (AEAD/MLS/ALM) — gated on edge **v4.1.1**'s
//!     `NETWORK_CAPACITY_MODEL.md` + benches (CIRISEdge PR#147).
//!   - the **holonomic tier** (WholenessWitness, ALM-topology compute, trust
//!     bootstrap, swarm-rarity convergence) — gated on wiring the fountain/
//!     holonomic APIs (CIRISServer#11) + **CIRISRegistry#88**'s composite model
//!     that grounds the targets.

mod scoreboard;

pub use scoreboard::{
    DegradationTier, FountainPolicy, MetricTarget, Scoreboard, StorageTier, SurvivalPoint,
};
