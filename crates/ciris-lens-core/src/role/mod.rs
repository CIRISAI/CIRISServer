//! `role/` — lens-core's deployment-mode runtimes (FSD §3).
//!
//! Lens-core runs in one of four modes. v0.2 ships **relay** (HTTP);
//! v1.0 adds the **RET-native relay** (Reticulum canonical wire):
//!
//! - **client** (v0.3) — co-located with a CIRISAgent; captures the
//!   agent's own traces locally and filters on egress.
//! - **relay** (v0.2, [`relay`]) — store-and-forward federation
//!   transit over HTTP (documented fallback transport per MISSION.md §2).
//!   Accepts verified [`AccordEventsBatch`] traffic from peers over Edge,
//!   persists it to the host's shared persist `Engine`, and is itself a
//!   key-addressable Edge endpoint.
//! - **ret_relay** (v1.0, [`ret_relay`] — CIRISLensCore#34) — the
//!   canonical-wire variant of relay mode: same handler, same persist
//!   cohabitation, but wired over a Reticulum transport (Leviculum
//!   stack). `LensCore::ret_relay` is the `LensCore::relay` analogue for
//!   Reticulum-native deployments.
//! - **node** (v0.4 — CIRISLensCore#15) — relay behavior plus the frozen
//!   public read API (`/lens/api/v1/*`) community lens viewers consume.
//!   Federation-anchor deployments (`safety.ciris.ai`-class) run node mode.
//!
//! [`AccordEventsBatch`]: ciris_edge::AccordEventsBatch
//!
//! # What relay mode delivers
//!
//! Before this module, lens-core could *sign as* a key (its signed
//! detection events carry `signing_key_id`, verifiable via
//! `verify_hybrid_via_directory`) but could not *receive at* one —
//! it had no Edge listener. [`LensCore::relay`] opens that listener
//! over HTTP; [`LensCore::ret_relay`] opens it over Reticulum.
//!
//! [`LensCore::relay`]: crate::LensCore::relay
//! [`LensCore::ret_relay`]: crate::LensCore::ret_relay
//!
//! # What node mode adds
//!
//! Node mode wraps relay mode and adds an axum HTTP server exposing
//! seven read endpoints over [`ScoresOracle`]. The read data already
//! exists in persist; node mode exposes it at frozen public URLs.
//! No business logic lives in the API layer beyond pagination + auth.
//!
//! [`ScoresOracle`]: crate::scores::ScoresOracle
//!
//! # Substrate boundaries
//!
//! Both relay modes compose — they write ~zero substrate code:
//!
//! - **Directory + queue** — the host `Engine`'s existing
//!   `SqliteBackend`, shared (cohabitation: one connection pool, not
//!   a second opened from the same db_path). `SqliteBackend`
//!   satisfies Edge's `VerifyDirectory` + `OutboundHandle` via Edge's
//!   blanket impls over persist's `FederationDirectory` /
//!   `OutboundQueue`.
//! - **Ingest** — persist's `Engine::receive_and_persist`
//!   (CIRISPersist#89), called with `&NullScrubber` (see
//!   [`handler`]).
//! - **Transport-signing identity** — loaded via
//!   `LocalSigner::from_keyring_seed_dir` (same as HTTP relay).

pub mod handler;
pub mod node;
pub mod relay;
pub mod ret_relay;

pub use handler::LensCoreHandler;
pub use node::{
    CalibrationBundleResponse, LensQueryError, ManifoldAggregateResponse, NodeError, NodeHandle,
    ScoreListResponse, ScoreResponse,
};
pub use relay::{RelayError, RelayHandle};
pub use ret_relay::RetRelayHandle;
