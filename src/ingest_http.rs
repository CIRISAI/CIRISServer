//! HTTP trace-ingest endpoint — the `listen+1` relay the runbook §3.4 promised
//! (CIRISServer trace-ingest break).
//!
//! ## Why this exists
//!
//! The agent's accord-metrics emitter (UA `CIRIS-AccordMetrics/1.0`) ships
//! signed trace batches over a plain HTTP `POST` to the legacy lens-python path
//! `/lens-api/api/v1/accord/events`. That lens-python service is decommissioned;
//! ciris-server today ingests ONLY over Reticulum (the RET relay,
//! `crates/ciris-lens-core/src/role/ret_relay.rs`). So production receives ZERO
//! traces — every emitter `POST` 404s. This module re-opens the HTTP pipe on the
//! read-API listener so the bridge forwards the legacy path unchanged.
//!
//! ## The wire shape IS already an `AccordEventsBatch`
//!
//! The emitter body is exactly the JSON `BatchEnvelope`
//! (`ciris_persist::schema::BatchEnvelope`) that `AccordEventsBatch`
//! (`#[serde(transparent)]` over `BatchEnvelope`) carries over Reticulum:
//!
//! ```json
//! { "events": [ { "event_type": "complete_trace",
//!                 "trace_level": "generic",
//!                 "trace": { ...CompleteTrace..., "signature": "...",
//!                            "signature_key_id": "..." } } ],
//!   "batch_timestamp": "...", "consent_timestamp": "...",
//!   "trace_level": "generic", "trace_schema_version": "..." }
//! ```
//!
//! So the HTTP handler does NOT adapt a foreign shape — it deserializes the
//! posted bytes straight into `BatchEnvelope` and feeds them to the SAME
//! verify-before-persist path the RET relay's `LensCoreHandler` uses:
//! `Engine::receive_and_persist(&bytes, &NullScrubber)` with the default
//! `VerifyMode::Full`.
//!
//! ## Verify-before-persist (NON-NEGOTIABLE — the security is the CEG signature)
//!
//! HTTP is just the pipe; trust is identical to the RET relay: the per-trace
//! hybrid (Ed25519 + ML-DSA-65) CEG signature IS the authentication, so the
//! route is unauthenticated exactly like the relay (`PeerAcl::AllowAll` ingest,
//! no bearer token). `receive_and_persist` runs persist's `IngestPipeline`
//! verify gate (schema parse → signature verify → scrub → insert) BEFORE any
//! row lands; an unsigned / tampered / unknown-key / classical-only batch is
//! rejected with a 4xx and NOTHING persists. We use the untrusted-input
//! `VerifyMode::Full` (NOT the relay-only `receive_and_persist_pre_verified`
//! skip-verify path) — a direct HTTP `POST` carries no Edge `verify_outcome`,
//! so persist MUST verify it itself.
//!
//! ## Scrubbing
//!
//! [`EgressScrubber`](crate::scrub::EgressScrubber) — persist's walker + regex
//! redaction, run BEFORE the row is sealed.
//!
//! This used to pass `NullScrubber` on the reasoning that scrubbing is the
//! originating client node's egress-filter responsibility and the trace arrives
//! post-egress-filter by contract (CIRISPersist#89). That contract was a
//! precondition **nothing verified and, on this node, nothing implemented** —
//! there was no egress filter in this crate at all. persist said so on every
//! batch (`NullScrubber used at non-GENERIC trace level`), 26 times in one day
//! on the scout node, and the caveat about "a deployment that points agents
//! directly at this endpoint" described the actual deployment.
//!
//! It has to happen here because a trace leaves as a SIGNED row replicated by
//! anti-entropy rounds: nothing downstream of the signature can redact it
//! without invalidating the signature that makes it admissible. This boundary is
//! the last moment content can be scrubbed, so it is egress in the only sense
//! that matters.
//!
//! `full_traces` is REFUSED rather than under-scrubbed when NER is not compiled
//! in — see `crate::scrub`. Gated by `tests/egress_scrub.rs`.
//!
//! ## CIRISServer#370 — a refusal is counted, not only logged
//!
//! Until the 2026-08-05 soak this handler `tracing::warn!`ed a rejection and
//! kept nothing. `FSD/RCA_INGEST_REJECTION_2026-08-05.md`: a misconfigured
//! producer was refused **8,631 times a day for 71 hours** and the only trace of
//! it was log volume nobody was reading. Every individual refusal was CORRECT —
//! which is exactly why the aggregate had no reader.
//!
//! [`IngestRefusals`] is that reader's data: a bounded, process-local ledger of
//! recent refusals carrying **who** was refused, not merely how many. It counts;
//! it renders no verdict. The banding lives in
//! [`crate::operator_surface`], the module whose job is naming, exactly as
//! edge's `EdgeMetrics` counts and this repo bands.
//!
//! ## `feature.trace_replication` — the mesh-config consumer (CIRISServer#365)
//!
//! This route is the trace plane's INBOUND leg in this build, and it is the
//! heaviest plane a congested canonical carries. A subscribed trust root that
//! sets `feature.trace_replication = 0` on persist's `mesh_config` plane pauses
//! it: a batch is refused **before verification**, with its own stable token,
//! and NOTHING is persisted. Rows already held are untouched.
//!
//! The value is read live off [`crate::mesh_config_effect`], which re-folds on a
//! cadence — so a relief takes effect without a restart and, more importantly,
//! **stops** taking effect when its TTL closes without anyone filing anything.
//!
//! Two limits, stated rather than implied:
//!
//! - it gates the INBOUND leg only; the outbound replication offer filter is
//!   edge's (CIRISEdge#440) and is not reachable from this process;
//! - it fails OPEN. A plane that cannot be read leaves the relay accepting, the
//!   owner default. An ingest path that fail-closed on a directory blip would
//!   turn a transient substrate error into a silent trace outage, which is
//!   exactly the 71-hour failure `FSD/RCA_INGEST_REJECTION_2026-08-05.md`
//!   documents.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::scrub::EgressScrubber;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use ciris_persist::ingest::IngestError;
use ciris_persist::prelude::Engine;
use ciris_persist::verify::Error as VerifyError;
use serde::Serialize;

use crate::mesh_config_effect::{MeshConfigEffect, PlaneAdmission};
use crate::{classify_key_id, KeyIdNamespace};

/// The LEGACY path the deployed emitter POSTs to (UA `CIRIS-AccordMetrics/1.0`).
/// Mounted verbatim so the Caddy bridge forwards it unchanged — zero rewrite.
pub const LEGACY_INGEST_PATH: &str = "/lens-api/api/v1/accord/events";

/// The clean canonical alias for new emitters / direct callers.
pub const CANONICAL_INGEST_PATH: &str = "/v1/ingest/accord-events";

/// Success body — the counts ingested (mirrors the RET relay's
/// `AccordEventsResponse` so an emitter sees identical accounting over either
/// transport).
#[derive(Debug, Serialize)]
struct IngestOk {
    /// `trace_events` rows that landed (excluding idempotent-dedup skips).
    trace_events_inserted: u32,
    /// `trace_llm_calls` rows that landed.
    trace_llm_calls_inserted: u32,
    /// Idempotent ON-CONFLICT dedup skips (anti gossip-loop / re-delivery).
    deduplicated: u32,
    /// CompleteTrace envelopes whose CEG signature verified.
    signatures_verified: u32,
}

/// Error body — a stable machine token (never raw payload bytes; AV-15).
#[derive(Debug, Serialize)]
struct IngestErr {
    /// The stable per-variant token (e.g. `verify_signature_mismatch`,
    /// `verify_hybrid_required`, `schema_missing_field`).
    error: &'static str,
    /// Optional closed-set detail (e.g. the missing field name).
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    /// Which **derivation namespace** the refused signer id belongs to, present
    /// only on a directory miss (RCA 2026-08-05 fix 6 — see
    /// [`refused_key_namespace`]).
    ///
    /// A separate field rather than a second meaning for `detail`: `detail`
    /// answers *"what was wrong with the payload"* and this answers *"which of
    /// your identities did you sign with"*. Folding them would be the very
    /// one-field-two-axes shape CIRISServer#371 exists to retire, committed in
    /// the response body of the fix for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id_namespace: Option<&'static str>,
}

// ─────────────────────────────────────────────────────────────────────────────
// CIRISServer#370 — the refusal ledger.
// ─────────────────────────────────────────────────────────────────────────────

/// The window every rate on [`IngestRefusalBundle`] is measured over, in
/// seconds. One hour: long enough that a single stale client cannot look
/// sustained, short enough that a reading taken now describes now.
///
/// Carried onto the wire beside every count, so a reader never has to know this
/// constant to interpret the number beside it.
pub const REFUSAL_WINDOW_SECS: i64 = 3_600;

/// Hard cap on remembered refusal events, independent of the window. Bounds the
/// ledger's memory against exactly the flood it exists to detect: at the
/// incident's ~6/min this holds ~11 hours, and at 6/sec it still holds ~11
/// minutes. While it is biting, [`IngestRefusalBundle::window_truncated`] says
/// so and every window count becomes a FLOOR rather than a fact — an
/// under-report that announces itself is usable; a silent one is not.
pub const REFUSAL_EVENT_CAP: usize = 4_096;

/// How many refused signer ids the bundle names, worst first.
pub const REFUSAL_TOP_N: usize = 5;

/// Max stored length of a refused signer id.
///
/// The id is **attacker-controlled bytes off an unauthenticated POST** — that is
/// what "unregistered signer" means — so it is truncated before it is ever
/// stored or rendered. AV-15: the id is a closed-vocabulary-shaped identifier,
/// never payload; truncation bounds it anyway.
pub const REFUSAL_SIGNER_ID_MAX: usize = 128;

/// One refused POST, as the ledger remembers it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Refusal {
    at: DateTime<Utc>,
    /// persist's own stable error token (`verify_unknown_key`, …). Never a
    /// label of ours — the same discipline the carriage counters follow.
    kind: &'static str,
    /// The signer the refusal names, when the refusal names one at all. Most
    /// do not: only an unknown-key rejection carries an identity, because
    /// that is the only refusal that got far enough to read one.
    signer: Option<String>,
}

/// The ledger's mutable half.
#[derive(Debug)]
struct Ledger {
    started_at: DateTime<Utc>,
    accepted_total: u64,
    refused_total: u64,
    events: VecDeque<Refusal>,
    /// When the cap last evicted an event that was still inside the window.
    ///
    /// An INSTANT rather than a running total, because
    /// [`IngestRefusalBundle::window_truncated`] is a statement about the window
    /// being displayed and a total is a statement about the process. An eviction
    /// at `T` dropped an event whose own instant lay somewhere in
    /// `[T - window, T]`, so it can only still belong to the window ending now
    /// if `T` itself is inside that window. A count here would latch the flag on
    /// for the life of the process: a node that weathered a flood and recovered
    /// would go on declaring its counts a FLOOR forever — true about an hour
    /// that has already scrolled off, false about the one on screen.
    last_capped_at: Option<DateTime<Utc>>,
}

/// CIRISServer#370 — **a bounded, process-local ledger of ingest refusals.**
///
/// A cheap `Arc` clone, like edge's `EdgeMetrics`: the router holds one and the
/// operator surface holds the same one. Cloning it clones the handle, not the
/// counts.
///
/// # What it deliberately does NOT do
///
/// It renders no verdict. `clean` / `background` / `stuck_producer` are
/// [`crate::operator_surface`]'s tokens, computed from this bundle — one source,
/// one answer, which is the rule that keeps two lists from disagreeing.
///
/// # Volatility, stated
///
/// Every field is **process-local and cumulative since this process started**.
/// It resets on restart, differs between processes serving one node, and is
/// stored nowhere. It belongs in the operator surface's `volatility.process_local`
/// list beside the carriage counters, and it is put there.
#[derive(Debug, Clone)]
pub struct IngestRefusals {
    inner: Arc<Mutex<Ledger>>,
}

impl Default for IngestRefusals {
    fn default() -> Self {
        Self::new()
    }
}

impl IngestRefusals {
    /// A fresh ledger, starting now.
    #[must_use]
    pub fn new() -> Self {
        Self::started_at(Utc::now())
    }

    /// A fresh ledger with a pinned start instant. Tests use this so a rate over
    /// a window is a function of injected time and not of how fast the suite
    /// ran.
    #[must_use]
    pub fn started_at(now: DateTime<Utc>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Ledger {
                started_at: now,
                accepted_total: 0,
                refused_total: 0,
                events: VecDeque::new(),
                last_capped_at: None,
            })),
        }
    }

    /// Record an accepted batch.
    ///
    /// Counting the ACCEPTS is what lets a zero refusal count name its own
    /// cause: without it, "nothing was refused" and "nothing was ever offered"
    /// are the same reading. The replication plane spent a release proving the
    /// point from the other side — it counted refusals and nothing else, so its
    /// `clean` arm was three facts wearing one token until CIRISEdge#457 gave it
    /// this counter's equivalent (see
    /// [`crate::operator_surface::ReceiveStanding`]).
    pub fn observe_accept(&self) {
        self.observe_accept_at(Utc::now());
    }

    /// [`Self::observe_accept`] at a pinned instant.
    pub fn observe_accept_at(&self, _now: DateTime<Utc>) {
        if let Ok(mut l) = self.inner.lock() {
            l.accepted_total = l.accepted_total.saturating_add(1);
        }
    }

    /// Record a refusal, reading its stable token and (when the refusal names
    /// one) its signer id straight off persist's typed error.
    pub fn observe_refusal(&self, e: &IngestError) {
        self.observe_refusal_at(Utc::now(), e);
    }

    /// [`Self::observe_refusal`] at a pinned instant.
    pub fn observe_refusal_at(&self, now: DateTime<Utc>, e: &IngestError) {
        let signer = refused_signer(e).map(|s| truncate_id(s).to_owned());
        self.record(now, e.kind(), signer);
    }

    fn record(&self, now: DateTime<Utc>, kind: &'static str, signer: Option<String>) {
        let Ok(mut l) = self.inner.lock() else { return };
        l.refused_total = l.refused_total.saturating_add(1);
        l.events.push_back(Refusal {
            at: now,
            kind,
            signer,
        });
        prune(&mut l, now);
    }

    /// The reading, as of `now`.
    #[must_use]
    pub fn snapshot_at(&self, now: DateTime<Utc>) -> IngestRefusalBundle {
        let Ok(mut l) = self.inner.lock() else {
            // A poisoned lock is "could not read", and the ONLY honest answer
            // is the one the surface renders `unreadable`. Returning a zeroed
            // bundle here would manufacture a clean reading out of a failure —
            // the false-clean the RCA's third instrument failure is about.
            return IngestRefusalBundle::unreadable(now);
        };
        let floor = prune(&mut l, now);

        let mut by_kind: BTreeMap<&'static str, u64> = BTreeMap::new();
        let mut by_signer: HashMap<&str, u64> = HashMap::new();
        let mut unattributed: u64 = 0;
        for ev in &l.events {
            *by_kind.entry(ev.kind).or_insert(0) += 1;
            match ev.signer.as_deref() {
                Some(s) => *by_signer.entry(s).or_insert(0) += 1,
                None => unattributed += 1,
            }
        }
        let mut top: Vec<(String, u64)> = by_signer
            .iter()
            .map(|(s, n)| ((*s).to_owned(), *n))
            .collect();
        // Worst first, then by id so the list is stable between two reads that
        // saw the same counts.
        top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        top.truncate(REFUSAL_TOP_N);

        IngestRefusalBundle {
            readable: true,
            observed_since: l.started_at,
            as_of: now,
            window_seconds: REFUSAL_WINDOW_SECS,
            accepted_total: l.accepted_total,
            refused_total: l.refused_total,
            refusals_in_window: l.events.len() as u64,
            distinct_signers_in_window: by_signer.len(),
            unattributed_in_window: unattributed,
            top_signers: top,
            by_kind_in_window: by_kind,
            // Truncation of THIS window, not of any window this process ever
            // showed. See [`Ledger::last_capped_at`].
            window_truncated: l.last_capped_at.is_some_and(|t| t >= floor),
        }
    }

    /// The reading, as of now.
    #[must_use]
    pub fn snapshot(&self) -> IngestRefusalBundle {
        self.snapshot_at(Utc::now())
    }
}

/// Drop everything older than the window, then everything over the cap, and
/// return the window floor the caller needs to interpret `last_capped_at`.
fn prune(l: &mut Ledger, now: DateTime<Utc>) -> DateTime<Utc> {
    let floor = now - Duration::seconds(REFUSAL_WINDOW_SECS);
    while l.events.front().is_some_and(|e| e.at < floor) {
        l.events.pop_front();
    }
    while l.events.len() > REFUSAL_EVENT_CAP {
        l.events.pop_front();
        l.last_capped_at = Some(now);
    }
    floor
}

/// Truncate an attacker-supplied id on a char boundary.
fn truncate_id(s: &str) -> &str {
    if s.len() <= REFUSAL_SIGNER_ID_MAX {
        return s;
    }
    let mut end = REFUSAL_SIGNER_ID_MAX;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// The signer id a refusal names, or `None` when the refusal names none.
///
/// **Exhaustive with no catch-all, on both enums**, so a substrate bump that
/// adds an error variant carrying an identity is a compile error here rather
/// than a signer that silently stops being counted. That is the same guard
/// `WithholdClass::of` uses over edge's taxonomy, and it is the only one that
/// survives a version bump.
///
/// Only `UnknownKey` carries an id today, and that is not an accident: it is the
/// one rejection that got far enough to READ an identity before refusing it.
/// Everything else failed before there was a name to record — which is why
/// `distinct_signers == 0` alongside a large refusal count is a real, distinct
/// state and not an arithmetic accident.
fn refused_signer(e: &IngestError) -> Option<&str> {
    match e {
        IngestError::Verify(v) => match v {
            VerifyError::UnknownKey(id) => Some(id.as_str()),
            VerifyError::SignatureMismatch
            | VerifyError::Canonicalization(_)
            | VerifyError::InvalidSignature(_)
            | VerifyError::Internal(_)
            | VerifyError::UnsupportedSchemaVersion(_)
            | VerifyError::HybridRequired
            | VerifyError::HybridVerify(_) => None,
        },
        IngestError::Schema(_)
        | IngestError::Scrub(_)
        | IngestError::Store(_)
        | IngestError::Sign(_)
        | IngestError::ScopeRefused(_)
        | IngestError::PipelineInvariant { .. } => None,
    }
}

/// CIRISServer#370 — one read of [`IngestRefusals`]. Counts only; the standing
/// is [`crate::operator_surface`]'s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestRefusalBundle {
    /// `false` only when the ledger itself could not be read (a poisoned lock).
    /// **Not** "nothing was refused" — the surface renders it `unreadable`, and
    /// the two must never collapse.
    pub readable: bool,
    /// When this ledger started counting — i.e. when this process started.
    pub observed_since: DateTime<Utc>,
    /// The instant the window was measured against.
    pub as_of: DateTime<Utc>,
    /// The window every `*_in_window` field covers. See [`REFUSAL_WINDOW_SECS`].
    pub window_seconds: i64,
    /// Batches accepted since this process started.
    pub accepted_total: u64,
    /// Batches refused since this process started (uncapped, unwindowed).
    pub refused_total: u64,
    /// Batches refused inside the window.
    pub refusals_in_window: u64,
    /// Refusals in the window that named no signer at all. Their existence is
    /// why `distinct_signers_in_window == 0` is a state and not an impossibility.
    pub unattributed_in_window: u64,
    /// **The load-bearing dimension.** Distinct signer ids among the refusals in
    /// the window. The same rate from two identities and from eight thousand are
    /// opposite conditions — a stuck producer and a Sybil probe — and the count
    /// alone cannot tell them apart.
    pub distinct_signers_in_window: usize,
    /// The most-refused signer ids in the window, worst first, capped at
    /// [`REFUSAL_TOP_N`].
    pub top_signers: Vec<(String, u64)>,
    /// Refusals in the window, by persist's own stable error token.
    pub by_kind_in_window: BTreeMap<&'static str, u64>,
    /// [`REFUSAL_EVENT_CAP`] evicted events that could still belong to **this**
    /// window ⇒ every window count above is a FLOOR.
    ///
    /// It falls back to `false` once the truncation itself has aged out, which
    /// is the point: a node that weathered a flood and recovered reports
    /// accurate counts again rather than disclaiming them forever.
    pub window_truncated: bool,
}

impl IngestRefusalBundle {
    /// **The one bundle that is not a statement about what was refused.**
    ///
    /// Every count on it is zero and NONE of those zeroes means "nothing was
    /// refused" — [`Self::readable`] is `false`, and the operator surface is
    /// required to read that flag before it reads a single count. Returning
    /// this shape rather than an error keeps the reading uniform; the flag is
    /// what keeps it honest.
    ///
    /// `pub(crate)` so the surface's own gate can construct the arm it must
    /// handle. A poisoned lock is not reachable on demand from a test that
    /// asserts on the RENDERING, and an unhandled arm nobody can construct is
    /// an unhandled arm nobody tests.
    pub(crate) fn unreadable(now: DateTime<Utc>) -> Self {
        Self {
            readable: false,
            observed_since: now,
            as_of: now,
            window_seconds: REFUSAL_WINDOW_SECS,
            accepted_total: 0,
            refused_total: 0,
            refusals_in_window: 0,
            unattributed_in_window: 0,
            distinct_signers_in_window: 0,
            top_signers: Vec::new(),
            by_kind_in_window: BTreeMap::new(),
            window_truncated: false,
        }
    }
}

/// The router's state: the engine plus the refusal ledger the handler writes to.
#[derive(Clone)]
struct IngestState {
    engine: Arc<Engine>,
    /// CIRISServer#370 — the refusal ledger this handler counts into.
    refusals: IngestRefusals,
    /// CIRISServer#365 — the live `mesh_config` reading gating this plane.
    mesh_config: MeshConfigEffect,
}

/// The stable refusal token a paused trace plane answers with. Distinct from
/// every [`IngestError`] kind on purpose: *"I refuse your batch"* and *"I am
/// not taking any batches right now"* are different answers, and an emitter
/// that cannot tell them apart will either retry a permanent failure forever or
/// give up on a temporary one.
pub const REFUSAL_TRACE_PLANE_PAUSED: &str = "trace_replication_paused";

/// Merge the HTTP trace-ingest routes onto the read-API listener.
///
/// Both the legacy path (so the bridge forwards unchanged) AND the canonical
/// alias resolve to the same handler. Returned router carries its own state, so
/// it composes via `.merge(...)` exactly like the auth / safety routers in
/// `compose.rs`.
///
/// `refusals` is the ledger this handler counts into (CIRISServer#370). Pass the
/// SAME handle to [`crate::operator_surface::router`] — a second ledger would be
/// a second answer to one question.
///
/// `mesh_config` is the live reading of persist's `mesh_config` plane
/// (CIRISServer#365). A composition that runs no plane passes
/// [`MeshConfigEffect::unwired`], which reads every key as unreadable and
/// leaves this relay accepting — the parameter is REQUIRED rather than
/// defaulted so a new host has to decide, instead of silently inheriting an
/// ungated route.
pub fn router(
    engine: Arc<Engine>,
    refusals: IngestRefusals,
    mesh_config: MeshConfigEffect,
) -> Router {
    publish(&refusals);
    Router::new()
        .route(LEGACY_INGEST_PATH, axum::routing::post(ingest))
        .route(CANONICAL_INGEST_PATH, axum::routing::post(ingest))
        .with_state(IngestState {
            engine,
            refusals,
            mesh_config,
        })
}

/// The ledger this process's ingest route counts into, for readers that are not
/// holding the router's state — specifically the in-process fold accessor
/// [`crate::operator_surface::node_state_json`], which reaches process statics
/// exactly as [`crate::federation_delivery::held`] does.
///
/// `None` when no ingest route has been mounted in this process, which is the
/// honest input to an `unreadable` ingest reading: there is no gate here to have
/// refused anything.
static HELD: Mutex<Option<IngestRefusals>> = Mutex::new(None);

/// Publish the ledger for [`held`]. Called by [`router`], the one chokepoint
/// where a process acquires an ingest gate.
fn publish(refusals: &IngestRefusals) {
    if let Ok(mut h) = HELD.lock() {
        *h = Some(refusals.clone());
    }
}

/// The process's ingest refusal ledger, if it has one.
#[must_use]
pub fn held() -> Option<IngestRefusals> {
    HELD.lock().ok().and_then(|h| h.clone())
}

/// `POST <ingest path>` — deserialize-verify-persist, identical to the RET
/// relay handler. Returns `200` + the ingest counts, or a 4xx/5xx + a stable
/// error token. NEVER persists an unverified batch (verify-before-persist runs
/// inside `receive_and_persist`).
async fn ingest(State(st): State<IngestState>, body: Bytes) -> Response {
    // ── `feature.trace_replication` (CIRISServer#365) ───────────────────────
    // BEFORE the body is even parsed: a paused plane must cost this node
    // nothing, and refusing after verification would spend the ML-DSA-65 work
    // the relief was filed to avoid.
    if st.mesh_config.trace_plane() == PlaneAdmission::Paused {
        tracing::warn!(
            bytes = body.len(),
            "HTTP ingest REFUSED: a subscribed trust root has paused the trace plane \
             (mesh_config feature.trace_replication = 0). Nothing was parsed, verified or \
             persisted; rows already held are untouched. The relief carries a TTL and lifts \
             itself."
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(IngestErr {
                error: REFUSAL_TRACE_PLANE_PAUSED,
                detail: Some(
                    "A subscribed trust root has paused trace replication on this node via the \
                     mesh_config plane (feature.trace_replication = 0). This is temporary and \
                     TTL-bounded; retry later. GET /v1/mesh-config shows the row, its author \
                     and its countdown."
                        .to_string(),
                ),
                // CIRISServer#371: a paused plane says NOTHING about which key
                // namespace the producer signed under — the body was never even
                // parsed. Claiming one here would send an honest producer
                // chasing a key problem it does not have.
                key_id_namespace: None,
            }),
        )
            .into_response();
    }
    let engine = st.engine;
    // The SAME call the RET relay's `LensCoreHandler::handle` makes — the raw
    // posted bytes ARE a `BatchEnvelope`/`AccordEventsBatch` JSON; persist's
    // IngestPipeline canonicalizes + verifies BEFORE persisting (VerifyMode::Full,
    // the untrusted-input default — a direct HTTP POST is NOT pre-verified).
    match engine.receive_and_persist(&body, &EgressScrubber).await {
        Ok(summary) => {
            st.refusals.observe_accept();
            tracing::info!(
                envelopes = summary.envelopes_processed,
                trace_events = summary.trace_events_inserted,
                llm_calls = summary.trace_llm_calls_inserted,
                deduplicated = summary.trace_events_conflicted,
                signatures_verified = summary.signatures_verified,
                "HTTP ingest persisted AccordEventsBatch (verify-before-persist)",
            );
            // Cast usize -> u32: batch sizes are bounded well under u32::MAX by
            // persist's ingest limits (lossless in practice — same as the relay).
            (
                StatusCode::OK,
                Json(IngestOk {
                    trace_events_inserted: summary.trace_events_inserted as u32,
                    trace_llm_calls_inserted: summary.trace_llm_calls_inserted as u32,
                    deduplicated: summary.trace_events_conflicted as u32,
                    signatures_verified: summary.signatures_verified as u32,
                }),
            )
                .into_response()
        }
        Err(e) => {
            let status = ingest_status(&e);
            // CIRISServer#370 — COUNT the refusal, do not only log it. A refusal
            // that exists solely as a WARN line is a refusal with no reader, and
            // 8,631 of those a day for 71 hours is what the 2026-08-05 soak found.
            st.refusals.observe_refusal(&e);
            // CIRISServer#371 — the body carries `key_id_namespace`, so a producer
            // that signed from the wrong derivation is TOLD that, rather than
            // receiving the single token `verify_unknown_key` and having to guess.
            let body = ingest_error_body(&e);
            // AV-15: surface the stable token, never the verbose Display (which
            // could echo payload bytes). The Display goes to the tracing log only.
            tracing::warn!(
                error = %e,
                kind = e.kind(),
                key_id_namespace = ?body.key_id_namespace,
                %status,
                "HTTP ingest rejected"
            );
            (status, Json(body)).into_response()
        }
    }
}

/// Map an [`IngestError`] to its HTTP status — the same per-layer mapping the
/// lens-python service used (documented on each `IngestError` variant):
///
/// - **verify** (signature mismatch / unknown key / malformed / hybrid-required
///   / hybrid-failed) → `401 Unauthorized` — the CEG signature IS the auth, so
///   a verify failure is an auth failure. THIS is the gate that rejects an
///   unsigned / tampered / classical-only batch.
/// - **schema** (malformed JSON, bad version, missing field, depth bomb) →
///   `422 Unprocessable Entity`.
/// - **scope** (cohort-scope admission refusal) → `403 Forbidden`.
/// - **store** (DB unreachable / IO) → `503 Service Unavailable`.
/// - **sign / scrub / pipeline-invariant** → `500 Internal Server Error`
///   (server-side faults, not the client's batch).
fn ingest_status(e: &IngestError) -> StatusCode {
    match e {
        IngestError::Verify(_) => StatusCode::UNAUTHORIZED,
        IngestError::Schema(_) => StatusCode::UNPROCESSABLE_ENTITY,
        IngestError::ScopeRefused(_) => StatusCode::FORBIDDEN,
        IngestError::Store(_) => StatusCode::SERVICE_UNAVAILABLE,
        IngestError::Sign(_) | IngestError::Scrub(_) | IngestError::PipelineInvariant { .. } => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// Which **derivation namespace** the signer id in a refused batch belongs to —
/// `None` when the refusal was not a directory miss.
///
/// # Why the 401 has to say this (RCA 2026-08-05 fix 6)
///
/// On 2026-08-02 a producer began signing with `agent-55fe8d181727` — the
/// agent-credits namespace, not [`FederationKeyId`](crate::FederationKeyId).
/// persist refused it correctly, logged a genuinely excellent diagnostic naming
/// the byte length and a sample of the directory it looked in — **in this
/// server's log.** What the producer received was one token,
/// `verify_unknown_key`, which is true of a typo, a revoked key, a key not yet
/// registered, and a key from the wrong derivation entirely. Those need four
/// different fixes, and only the producer can apply any of them.
///
/// So the namespace rides the response. It is a closed-set token
/// ([`KeyIdNamespace::as_str`]) and never the offending value — AV-15 holds; the
/// value stays in the log.
///
/// `verify_unknown_key` and `unrecognized` together still mean "not registered
/// here", which is the honest answer for a key that IS derive_key_id-shaped:
/// this node cannot tell a typo from a pending registration, and guessing would
/// be the same class of error one level up.
///
/// # The match is exhaustive on purpose
///
/// `UnknownKey` is the only verify variant that carries a signer id today. A
/// wildcard arm would answer `None` for a *future* persist variant that carries
/// one — silently, and in the direction of saying less. The exhaustive arm makes
/// that a compile error at the next substrate bump, which is the same
/// registry-of-record discipline the CEG replication chokepoint uses.
fn refused_key_namespace(e: &IngestError) -> Option<KeyIdNamespace> {
    use ciris_persist::verify::Error as VerifyError;

    let IngestError::Verify(verify) = e else {
        return None;
    };
    match verify {
        VerifyError::UnknownKey(key_id) => Some(classify_key_id(key_id)),
        // None of these say anything about a derivation namespace: a signature
        // mismatch, a malformed encoding, a missing PQC half and a canonicalizer
        // bug are all conditions a correctly-namespaced id reaches.
        VerifyError::SignatureMismatch
        | VerifyError::Canonicalization(_)
        | VerifyError::InvalidSignature(_)
        | VerifyError::Internal(_)
        | VerifyError::UnsupportedSchemaVersion(_)
        | VerifyError::HybridRequired
        | VerifyError::HybridVerify(_) => None,
    }
}

/// The refusal body the producer receives — the ONE construction, so the test
/// below pins what the handler actually sends rather than a copy of it.
fn ingest_error_body(e: &IngestError) -> IngestErr {
    IngestErr {
        error: e.kind(),
        detail: e.detail(),
        key_id_namespace: refused_key_namespace(e).map(KeyIdNamespace::as_str),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_path_is_the_decommissioned_lens_python_path() {
        // The bridge forwards this verbatim — it MUST equal what the deployed
        // CIRIS-AccordMetrics/1.0 emitter POSTs (runbook §3.4 / MANIFEST.json).
        assert_eq!(LEGACY_INGEST_PATH, "/lens-api/api/v1/accord/events");
    }

    // ── CIRISServer#370 — the refusal ledger ────────────────────────────────

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s)
            .expect("rfc3339 fixture")
            .with_timezone(&Utc)
    }

    fn unknown_key(id: &str) -> IngestError {
        IngestError::Verify(VerifyError::UnknownKey(id.to_owned()))
    }

    /// The ledger records WHO, not merely how many — the dimension that
    /// separates a stuck producer from a Sybil probe at an identical rate.
    #[test]
    fn the_ledger_counts_who_was_refused_and_not_only_how_many() {
        let t0 = at("2026-08-05T13:00:00Z");
        let l = IngestRefusals::started_at(t0);
        // The incident's real ratio: 4,317 vs 4,314, scaled.
        for i in 0..40 {
            l.observe_refusal_at(t0, &unknown_key("agent-55fe8d181727"));
            if i < 39 {
                l.observe_refusal_at(t0, &unknown_key("agent-1ee871dcf31b"));
            }
        }
        l.observe_accept_at(t0);
        let b = l.snapshot_at(t0 + Duration::minutes(1));

        assert_eq!(b.refusals_in_window, 79);
        assert_eq!(b.refused_total, 79);
        assert_eq!(b.accepted_total, 1);
        assert_eq!(b.distinct_signers_in_window, 2);
        assert_eq!(b.unattributed_in_window, 0);
        // Worst first — the list an operator reads top-down.
        assert_eq!(
            b.top_signers,
            vec![
                ("agent-55fe8d181727".to_owned(), 40),
                ("agent-1ee871dcf31b".to_owned(), 39),
            ]
        );
        // persist's OWN stable token, carried — never a label of ours.
        assert_eq!(b.by_kind_in_window.get("verify_unknown_key"), Some(&79));
        assert!(b.readable);
        assert!(!b.window_truncated);
    }

    /// Only a refusal that got far enough to READ an identity can name one.
    /// Everything else is genuinely unattributable — which is why zero distinct
    /// signers beside a large count is a real state and not an arithmetic
    /// accident.
    #[test]
    fn only_an_unknown_key_refusal_names_a_signer() {
        assert_eq!(
            refused_signer(&unknown_key("agent-55fe8d181727")),
            Some("agent-55fe8d181727")
        );
        for e in [
            IngestError::Verify(VerifyError::SignatureMismatch),
            IngestError::Verify(VerifyError::HybridRequired),
            IngestError::Verify(VerifyError::HybridVerify("bad pqc".into())),
            IngestError::Verify(VerifyError::InvalidSignature("b64".into())),
            IngestError::Sign("keyring locked".into()),
        ] {
            assert_eq!(
                refused_signer(&e),
                None,
                "{} refused before there was an identity to record",
                e.kind()
            );
        }

        // A refusal that names nobody still COUNTS, under its own token.
        let t0 = at("2026-08-05T13:00:00Z");
        let l = IngestRefusals::started_at(t0);
        l.observe_refusal_at(t0, &IngestError::Verify(VerifyError::HybridRequired));
        let b = l.snapshot_at(t0 + Duration::seconds(1));
        assert_eq!(b.refusals_in_window, 1);
        assert_eq!(b.distinct_signers_in_window, 0);
        assert_eq!(b.unattributed_in_window, 1);
        assert_eq!(b.by_kind_in_window.get("verify_hybrid_required"), Some(&1));
    }

    /// The window is a window: an old flood does not keep a recovered node red,
    /// and the whole-process totals still carry the history.
    #[test]
    fn refusals_age_out_of_the_window_but_not_out_of_the_totals() {
        let t0 = at("2026-08-05T00:00:00Z");
        let l = IngestRefusals::started_at(t0);
        for _ in 0..100 {
            l.observe_refusal_at(t0, &unknown_key("agent-55fe8d181727"));
        }
        // Inside the window.
        let b = l.snapshot_at(t0 + Duration::seconds(REFUSAL_WINDOW_SECS - 1));
        assert_eq!(b.refusals_in_window, 100);
        // One second past it.
        let b = l.snapshot_at(t0 + Duration::seconds(REFUSAL_WINDOW_SECS + 1));
        assert_eq!(b.refusals_in_window, 0);
        assert_eq!(b.distinct_signers_in_window, 0);
        assert_eq!(
            b.refused_total, 100,
            "the window emptied; the process total must not, or a recovered node reads as one \
             that never refused anything"
        );
    }

    /// A flood past the cap under-reports, and SAYS SO. An under-report that
    /// announces itself is usable; a silent one is the false clean again.
    #[test]
    fn a_flood_past_the_cap_reports_a_floor_and_declares_it() {
        let t0 = at("2026-08-05T13:00:00Z");
        let l = IngestRefusals::started_at(t0);
        for i in 0..(REFUSAL_EVENT_CAP + 50) {
            l.observe_refusal_at(t0 + Duration::milliseconds(i as i64), &unknown_key("a"));
        }
        let b = l.snapshot_at(t0 + Duration::minutes(1));
        assert_eq!(b.refusals_in_window as usize, REFUSAL_EVENT_CAP);
        assert!(
            b.window_truncated,
            "a truncated window must declare itself — every count above it is a floor"
        );
        assert_eq!(b.refused_total as usize, REFUSAL_EVENT_CAP + 50);

        // ...and the disclaimer is about THIS window, not about the process.
        // The evictions happened seconds after t0, so a window whose floor has
        // moved past them contains nothing they could have belonged to and its
        // counts are exact again.
        let edge = l.snapshot_at(t0 + Duration::seconds(REFUSAL_WINDOW_SECS));
        assert!(
            edge.window_truncated,
            "the floor still stands while the truncation is inside the window"
        );
        let later =
            l.snapshot_at(t0 + Duration::seconds(REFUSAL_WINDOW_SECS) + Duration::minutes(1));
        assert_eq!(later.refusals_in_window, 0);
        assert!(
            !later.window_truncated,
            "a latched flag would leave a node that weathered a flood and recovered disclaiming \
             accurate counts for the life of the process — true about an hour that has already \
             scrolled off, false about the one being displayed"
        );
        assert_eq!(
            later.refused_total as usize,
            REFUSAL_EVENT_CAP + 50,
            "the window emptied; the process total must not"
        );
    }

    /// A POISONED LOCK IS NOT A CLEAN LEDGER.
    ///
    /// This is the RCA's third and most expensive instrument failure in its
    /// smallest form: a check that could not run, whose no-output reads as
    /// no-problem. The ledger answers a failed read with `readable: false`, and
    /// every count on that bundle is a placeholder rather than an observation.
    #[test]
    fn a_poisoned_ledger_reads_unreadable_and_not_as_a_clean_zero() {
        let t0 = at("2026-08-05T13:00:00Z");
        let l = IngestRefusals::started_at(t0);
        for _ in 0..99 {
            l.observe_refusal_at(t0, &unknown_key("agent-55fe8d181727"));
        }
        assert!(l.snapshot_at(t0).readable, "healthy before the poisoning");

        // Poison it for real: panic while holding the lock.
        let poisoned = l.clone();
        let _ = std::thread::spawn(move || {
            let _g = poisoned.inner.lock().expect("lock");
            panic!("poison the ledger");
        })
        .join();

        let b = l.snapshot_at(t0);
        assert!(
            !b.readable,
            "a ledger that could not be read must SAY so, not answer with zeroes"
        );
        assert_eq!(
            b.refusals_in_window, 0,
            "the placeholder counts are zero — which is exactly why `readable` has to be checked \
             before any of them is believed"
        );
        assert_eq!(b.refused_total, 0);
        assert!(b.top_signers.is_empty());
    }

    /// The signer id is attacker-controlled bytes off an unauthenticated POST.
    #[test]
    fn an_oversized_signer_id_is_truncated_before_it_is_stored() {
        let long = "ß".repeat(500);
        let t0 = at("2026-08-05T13:00:00Z");
        let l = IngestRefusals::started_at(t0);
        l.observe_refusal_at(t0, &unknown_key(&long));
        let b = l.snapshot_at(t0 + Duration::seconds(1));
        let (id, _) = &b.top_signers[0];
        assert!(
            id.len() <= REFUSAL_SIGNER_ID_MAX,
            "stored {} bytes from an unauthenticated POST",
            id.len()
        );
        assert!(long.starts_with(id.as_str()), "truncation must be a prefix");
    }

    #[test]
    fn verify_failures_map_to_401() {
        // The signature gate — an unsigned / tampered / unknown-key / classical-
        // only batch surfaces as a Verify error → 401 (auth failure). This is the
        // wire-checkable "verify-before-persist" posture for the HTTP pipe.
        use ciris_persist::verify::Error as VerifyError;
        assert_eq!(
            ingest_status(&IngestError::Verify(VerifyError::SignatureMismatch)),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ingest_status(&IngestError::Verify(VerifyError::UnknownKey("k".into()))),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ingest_status(&IngestError::Verify(VerifyError::HybridRequired)),
            StatusCode::UNAUTHORIZED
        );
    }

    /// The 2026-08-05 refusal, as the producer now receives it.
    ///
    /// The status is unchanged (401 — the admission gate was always right); what
    /// changed is that the body distinguishes *"you signed with your credits
    /// identity"* from *"we do not have your federation key"*. Those are the two
    /// conditions the flood conflated for 71 hours.
    #[test]
    fn an_unknown_key_refusal_names_the_derivation_namespace() {
        use ciris_persist::verify::Error as VerifyError;

        // The exact id from the RCA (4,317 rejections / 24h).
        let credits = IngestError::Verify(VerifyError::UnknownKey("agent-55fe8d181727".into()));
        assert_eq!(ingest_status(&credits), StatusCode::UNAUTHORIZED);
        assert_eq!(
            refused_key_namespace(&credits).map(KeyIdNamespace::as_str),
            Some("agent_credits"),
        );

        // A well-formed federation id that simply is not registered here reads
        // as its own namespace — "unknown key", not "wrong namespace". Merging
        // the two would send every honest new peer chasing the producer fix.
        let unregistered = IngestError::Verify(VerifyError::UnknownKey(
            "ciris-agent-bootstrap-25uzoxtlro".into(),
        ));
        assert_eq!(
            refused_key_namespace(&unregistered).map(KeyIdNamespace::as_str),
            Some("federation_derive_key_id"),
        );

        // A keystore alias (CIRISServer#118's shape) is neither.
        let alias = IngestError::Verify(VerifyError::UnknownKey("ciris-client".into()));
        assert_eq!(
            refused_key_namespace(&alias).map(KeyIdNamespace::as_str),
            Some("unrecognized"),
        );

        // A refusal that is NOT a directory miss must not claim a namespace —
        // a signature mismatch says nothing about which derivation was used.
        assert!(
            refused_key_namespace(&IngestError::Verify(VerifyError::SignatureMismatch)).is_none()
        );
        assert!(refused_key_namespace(&IngestError::Verify(VerifyError::HybridRequired)).is_none());
        assert!(
            refused_key_namespace(&IngestError::Verify(VerifyError::HybridVerify(
                "pqc_len".into()
            )))
            .is_none()
        );
    }

    /// The namespace must reach the **wire**, not merely the classifier.
    ///
    /// `refused_key_namespace` being right buys nothing if the handler drops the
    /// value on the way out — that is the shape of a gate that passes while the
    /// producer still receives one uninformative token. So this asserts on the
    /// serialized body, built by the same `ingest_error_body` the handler sends.
    #[test]
    fn the_serialized_refusal_body_carries_the_namespace() {
        use ciris_persist::verify::Error as VerifyError;

        let credits = IngestError::Verify(VerifyError::UnknownKey("agent-55fe8d181727".into()));
        let json = serde_json::to_value(ingest_error_body(&credits)).expect("serialize");
        assert_eq!(json["error"], "verify_unknown_key");
        assert_eq!(
            json["key_id_namespace"], "agent_credits",
            "the producer's only actionable field must be ON the response: {json}"
        );

        // AV-15: the offending value never rides the body — it stays in the log.
        assert!(
            !json.to_string().contains("agent-55fe8d181727"),
            "the refused key id must not be echoed back: {json}"
        );

        // A non-directory-miss refusal omits the field entirely rather than
        // sending a null or a guess.
        let mismatch = IngestError::Verify(VerifyError::SignatureMismatch);
        let json = serde_json::to_value(ingest_error_body(&mismatch)).expect("serialize");
        assert_eq!(json["error"], "verify_signature_mismatch");
        assert!(
            json.get("key_id_namespace").is_none(),
            "a signature mismatch carries no namespace information: {json}"
        );
    }
}
