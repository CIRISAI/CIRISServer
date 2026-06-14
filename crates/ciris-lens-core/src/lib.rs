//! `ciris-lens-core` — science-layer runtime for the CIRIS federation.
//!
//! Routes traces to cohorts, scores conformity to the alignment
//! manifold, signs detection events. Folds into the agent post-PoB
//! §3.1 (becomes a library every CIRIS peer links rather than a
//! service the federation depends on).
//!
//! # Per-trace lifecycle
//!
//! ```text
//! Edge (verified) ──► Persist (scrub + classify + extract) ──► LensCore::process
//!                                                                    │
//!                                                                    ├── pipeline::lifecycle
//!                                                                    │       │
//!                                                                    │       ├── cohort     (declared + inferred routing)
//!                                                                    │       ├── detector   (5 ratchet detectors + manifold)
//!                                                                    │       ├── scoring    (capacity, N_eff, conformity)
//!                                                                    │       └── signing    (via persist.local_sign)
//!                                                                    │
//!                                                                    └─► Persist (signed event lands in audit chain)
//! ```
//!
//! Scrubbing + classification + feature extraction live in
//! `ciris-persist v0.6.0+` (CIRISPersist#19). Lens-core re-exports
//! the typed `Features` via [`extract`] for backward call-site
//! compatibility; the actual transform runs server-side inside
//! `Engine.receive_and_persist`.
//!
//! # Mission alignment
//!
//! See `MISSION.md` at the repo root for M-1 alignment per module.
//! Brief summary:
//!
//! - **cohort**: route declared + inferred; mismatch is detection (LC-AV-2 P0)
//! - **detector**: layered defense across 5 ratchet detectors + manifold
//! - **scoring**: ManifoldConformity enum (Numeric/Indeterminate/Unavailable);
//!   never silently elevated (LC-AV-18 P0; LC-AV-11 P0)
//! - **signing**: every detection event is federation evidence
//!
//! # Threat model
//!
//! 21 LC-AVs in `docs/THREAT_MODEL.md`. P0 must-have-at-v0.1.0:
//!
//! - LC-AV-2: declared-vs-inferred cohort mismatch detection
//! - LC-AV-11: bounded queue; `score_unavailable` on SLO breach
//! - LC-AV-18: insufficient sample → `indeterminate`, not numeric
//!
//! # Boundaries
//!
//! - **Verify is implicit.** Edge owns verify-via-persist before any
//!   byte reaches lens-core. Lens-core does NOT re-verify; it consumes
//!   `VerifiedTrace` from edge and trusts the type-system attestation.
//! - **Storage is implicit.** Persist owns trace_events + trace_llm_calls.
//!   Lens-core holds an `Engine` handle, calls `engine.local_sign` for
//!   detection events, never opens its own DB connection.
//! - **Canonicalization is implicit.** `engine.canonicalize_envelope`
//!   only — lens-core never re-implements canonicalization rules.
//!   CIRISPersist#7 lesson holds.

// Unsafe is forbidden in lens-core's own code. PyO3 macro-generated
// FFI shims legitimately require unsafe; loosen the gate when the
// `python` feature is on. Without `python`, the crate is unsafe-free.
#![cfg_attr(not(feature = "python"), forbid(unsafe_code))]
#![warn(clippy::all)]

// Module skeleton — implementation lands when the Phase 1 work
// kicks off. Each module's mission is documented in MISSION.md §2;
// this file just declares the scope.

pub mod audit;
pub mod canonical;
pub mod capacity;
pub mod capture;
pub mod cohort;
pub mod config;
pub mod detector;
pub mod extract;
pub mod ffi;
pub mod observability;
pub mod pipeline;
pub mod retention;
pub mod role;
pub mod scores;
pub mod scoring;
pub mod signing;
pub mod wire;

// Public re-exports — the API surface the host (lens-deployed-product
// today; agent post-fold) consumes. Stable across patch versions;
// changes require a deprecation window.

pub use audit::{
    AuditedAction, ConsentEvent, ConsentEventType, IdentityChange, TypedAuditEvent,
    WisdomBasedDeferral,
};
pub use canonical::{
    ceg_egress::{
        build_state_publication, DetectionAttestation, LensStatePublication,
        LENS_STATE_PUBLICATION_TYPE,
    },
    CanonicalPeerEnrollment, EnrollmentError, CIRIS_CANONICAL_COMMUNITY_KEY_ID,
};
pub use capacity::{
    AntiGoodhartViolation, CapacityAttestation, CapacityFactorError, CapacityFactors,
};
pub use config::{
    apply_egress_filter, EgressFilter, PeerAcl, RetentionPolicy, ScoringConfig, UpstreamLens,
    UxConfig,
};
pub use detector::CoherenceRatchetDetector;
pub use pipeline::lifecycle::{LensCore, Outcome};
pub use retention::{evict_per_retention_policy, EvictionError, EvictionPlan, EvictionSummary};
pub use role::{
    CalibrationBundleResponse, LensCoreHandler, LensQueryError, ManifoldAggregateResponse,
    NodeError, NodeHandle, RelayError, RelayHandle, RetRelayHandle, ScoreListResponse,
    ScoreResponse,
};
pub use scores::{AgentScoreAggregate, OracleError, ScoresOracle, SeverityDistribution};
pub use scoring::result::{ManifoldConformity, Score};
