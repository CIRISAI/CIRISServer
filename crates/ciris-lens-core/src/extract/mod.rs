//! `extract/` module — re-exports the typed extraction primitives
//! from `ciris_persist::pipeline::extract`. Persist owns the
//! wire-to-storage boundary (CIRISPersist#19, persist v0.6.0). The
//! typed `Features` struct + extractor live there; lens-core
//! consumes via rlib re-export so call sites across
//! `cohort/`, `scoring/`, `pipeline/` don't see the move.
//!
//! Persist's `extract` Cargo feature is enabled on our dep
//! declaration; it pulls `classify` + `scrub` transitively but NOT
//! the heavy NER deps (`scrub-ner` / `scrub-ort` stay off).
//! Lens-core's binary is regex-only weight; the real scrubbing
//! happens server-side during `Engine.receive_and_persist`.

pub use ciris_persist::pipeline::extract::{
    extract_features, DeclaredCohortAxes, Features, ModelClass, ObservationWeights, StepTimestamps,
};

pub mod projection;

pub use projection::{project, PROJECTION_DIM, PROJECTION_VERSION};
