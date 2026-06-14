//! `scores/` — agent-side score read path (CIRISLensCore#19,
//! FSD `LENS_CORE_V0_5.md` §4.6).
//!
//! Closes the agent's self-awareness loop:
//!
//! ```text
//!   agent emits ─► lens-core scores ─► persist stores
//!                                            │
//!                                            ▼
//!                                    lens.scores.* reads
//!                                            │
//!                                            ▼
//!                                   agent reacts (post-decision
//!                                   reflection / what-am-I-doing
//!                                   inspection)
//! ```
//!
//! Before this module, an agent's emit-side trace shape was the
//! only feedback the substrate provided about its own behavior.
//! With [`ScoresOracle`], the agent reads back the detection
//! events filed against its trace IDs, the windowed aggregate of
//! its scoring outcomes, and the recent fire history of any
//! detector — and decides whether to defer, change posture, or
//! log additional context.
//!
//! # What this module owns
//!
//! - The pure-function aggregation
//!   ([`compute_aggregate`](aggregate::compute_aggregate)) that
//!   reduces a `Vec<DetectionEvent>` to an [`AgentScoreAggregate`]
//! - The async [`ScoresOracle`] wrapping
//!   [`Engine::get_detection_events`](ciris_persist::prelude::
//!   Engine::get_detection_events) — persist v2.13.0
//!   (CIRISPersist#113), shipped against the lens-core ask
//!
//! # What lives elsewhere
//!
//! - [`Score`](crate::scoring::Score) (the *write*-side score
//!   constructed in `pipeline::lifecycle`) — symmetrically related
//!   but distinct type; read-side `DetectionEvent` rows have
//!   `lens_core_version: String`, write-side `Score` has
//!   `&'static str`. Read returns the raw events; the caller does
//!   the on-demand reconstruction if they want a `Score`-shaped
//!   view.
//! - Storage and the `EventFilter` shape — persist owns them
//!
//! # PyO3 surface
//!
//! NOT in this commit. The FSD `lens.scores.*` Python namespace
//! depends on the `LensCore.client(...)` ctor (CIRISLensCore#11)
//! since it's reachable as `lens.scores.*` on a client handle.
//! When that ctor lands, this Rust core wraps with a thin
//! `#[pyclass]` layer.

pub mod aggregate;
pub mod oracle;

pub use aggregate::{compute_aggregate, AgentScoreAggregate, SeverityDistribution};
pub use oracle::{OracleError, ScoresOracle};
