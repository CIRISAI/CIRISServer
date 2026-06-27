//! The substrate **safety foundation** (CIRISServer#20) — moderation +
//! child-safety as first-class fabric primitives, built AHEAD of any media /
//! social content feature.
//!
//! FSDs: `FSD/MODERATION_CHILD_SAFETY.md` (the spine — moderation is a delegable
//! DUTY, not a role; the §A named-moderator existence invariant; the §B
//! anti-predator audit), `FSD/WATCHLIST_DETECTION.md` (opt-in per-group
//! content watchlist), `FSD/SAFETY_LANDSCAPE.md` (the honest comparative
//! framing). Wire spec: the CIRIS Constitution §4.5.x (moderate / takedown /
//! review duties; CC 4.5.4 named-moderator invariant + merit auto-promotion;
//! CC 4.5.7 watchlist; CC 4.5.3 takedown) + part_3 namespace (`age_assurance:*`,
//! `moderation:*`, `watchlist:*`, `hard_case:*`).
//!
//! ## What is COMPOSED from persist v9.0.0 (not re-implemented)
//!
//! persist v9.0.0 (CIRISPersist#233 / CEG RC25-RC27 §11.10/§11.11) ships the
//! moderation duty-admission machinery; this module COMPOSES it rather than
//! re-deriving the rule:
//!
//! - `federation::admission::DELEGATION_SCOPE_{MODERATE,TAKEDOWN,REVIEW}` — the
//!   three enforced duty-scope tokens (the §4.5.x agency-class scopes).
//! - `federation::admission::is_named_moderator` — the CC 4.5.4 predicate
//!   (owner-bound authority root, zero-hop or via a live `moderate`-scoped
//!   `delegates_to` chain).
//! - `federation::admission::check_moderation_admission` — the §11.10 admit-iff
//!   gate (as-self duty-holder OR a live scoped delegation chain; absence never
//!   admits — fail-secure).
//! - `federation::admission::duty_holders_for_community` /
//!   `duty_holders_from_signed_subjects` — the duty-holder set resolution.
//! - `federation::admission::is_steward_bound` — the CC 3.2 owner-binding leaf
//!   (the moderator must root in an accountable human).
//!
//! ## What is BUILT server-side (the genuine gaps — flagged for upstream)
//!
//! - **age-assurance** ([`age`]) — `age_assurance:{level}` is NOT a substrate
//!   dimension (only the AVMSD takedown age-gate composition ships). Built
//!   fabric-side over generic `scores` with a fixed dimension name (the §4.2
//!   workaround pattern; no new primitive). Upstream-ask: canonicalize the
//!   dimension + the `self < provider:* < government:*` ordering.
//! - **the named-moderator EXISTENCE gate + merit auto-promotion** ([`named`]) —
//!   persist ships the per-key `is_named_moderator` predicate; the *group-level
//!   existence invariant* (CC 4.5.4: a group can only operate while ≥1 live
//!   `moderate`-holder exists; fail-secure + merit auto-promotion ranking) is
//!   composed ON TOP of it here. Upstream-ask: a persist admission precondition
//!   wiring this into community admission + a `hard_case:community_unmoderated`
//!   reserved reason.
//! - **watchlist config** ([`watchlist`]) — `watchlist:{id}` is NOT a substrate
//!   dimension; the opt-in enable is a config attestation (the `consent.rs`
//!   recipe) gated on `moderate`/`takedown`. The MATCHER fires at the
//!   publish/share seam, which is NodeCore content — DEFERRED (see below).
//! - **moderation-event emit** ([`moderation`]) — the `moderation:*` `scores`
//!   emit + `moderation_track_record:*` read composition.
//!
//! ## What is BUILT NOW vs DEFERRED to the NodeCore content seam
//!
//! BUILT NOW (this is the foundation that must exist before content lands):
//! the delegation-spine admission, the age-gate, the named-moderator existence
//! invariant + auto-promotion, the watchlist CONFIG + duty/authority gate +
//! the hook point, the moderation-event emit, and the `/v1/safety/*` routers.
//!
//! DEFERRED to the NodeCore content integration (flagged, not silently missing):
//! the actual perceptual-hash MATCHER + `takedown_notice{PerceptualHashCsam}`
//! auto-fire. The matcher fires at `put_blob_signing` ingress — that seam is
//! NodeCore content. The operator provisions the licensed hash DB (IWF / NCMEC /
//! PhotoDNA are access-gated and NEVER shippable — `FSD/WATCHLIST_DETECTION.md`
//! §7). [`watchlist::on_publish`] is the hook the matcher plugs into.
//!
//! ## Honesty discipline (load-bearing — kept TRUE in code, not just docs)
//!
//! - Private (`self`/`family`, E2EE-equivalent) content CSAM detection is NOT
//!   solved and is never represented as solved (the CC 8.3.2 /
//!   SAFETY_LANDSCAPE structural limit — the watchlist cannot reach content that
//!   never crosses the share boundary). See [`watchlist`] for where detection
//!   CAN run.
//! - The named-moderator invariant FAILS SECURE: no nameable moderator ⇒ the
//!   group MUST NOT federate (better no group than an unmoderated one). See
//!   [`named::existence_verdict`].
//! - The watchlist is opt-in / per-group / NEVER global (no bulk surveillance).
//! - IWF / NCMEC hashes are operator-provisioned, never shipped.
//! - Age misdeclaration NEVER fires slashing: it routes to the
//!   `moderation:age_assurance_misdeclaration` adjudication path. See
//!   [`age::MISDECLARATION_ALLEGATION`].

use std::sync::Arc;

use ciris_persist::prelude::{Engine, HybridPolicy};

pub mod age;
pub mod moderation;
pub mod named;
pub mod watchlist;

/// Merge the full `/v1/safety/*` router surface onto the read-API listener.
///
/// Mirrors `compose.rs`'s existing `.merge(...)` chain for the auth routers; the
/// client safety cards drive these (owner / `moderate`-gated as appropriate):
///
/// - `POST /v1/safety/age-assurance` — set the caller's self-declared age level.
/// - `GET  /v1/safety/age-assurance/:key_id` — read an identity's age level.
/// - `GET  /v1/safety/status` — the aggregate safety status (age + moderation).
/// - `POST /v1/safety/moderation` — file a `moderate`/`takedown`/`review`
///   action (admitted iff the signer holds the duty or a live delegated chain).
/// - `GET  /v1/safety/named-moderator/:community_key_id` — the CC 4.5.4
///   existence-invariant status of a community (operating / quiesced).
/// - `POST /v1/safety/watchlist` — enable/disable a per-group watchlist
///   (`moderate`-gated; CSAM additionally `takedown`-gated).
pub fn router(engine: Arc<Engine>, policy: HybridPolicy) -> axum::Router {
    age::router(Arc::clone(&engine), policy)
        .merge(moderation::router(Arc::clone(&engine), policy))
        .merge(named::router(Arc::clone(&engine)))
        .merge(watchlist::router(Arc::clone(&engine), policy))
}
