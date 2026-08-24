//! CIRISServer#356 — **the operator surface: one read that answers "how is this
//! node?"**
//!
//! The material for this answer already existed and nothing called it. Two
//! sources, and they **compose rather than overlap**:
//!
//! | source | question it answers |
//! |---|---|
//! | persist [`resolve_node_state`](ciris_persist::federation::node_state::resolve_node_state) | *how is this node* — trust root, drill freshness, key standing, quarantine, consent SLA, peer quota |
//! | edge [`EdgeMetricsBundle`](ciris_edge::observability::EdgeMetricsBundle) | *did anything move, and if not, what stopped it* — the withhold ledger, apply refusals |
//! | persist [`storage_summary`](ciris_persist::prelude::Engine::storage_summary) | **CIRISServer#369** — *is the trace plane alive* — when a trace was last admitted, banded |
//! | [`IngestRefusals`](crate::ingest_http::IngestRefusals) | **CIRISServer#370** — *is the admission gate working overtime* — the refusal rate and WHO is being refused |
//!
//! **Draw from both. Re-derive neither.** Every band under `node` is persist's
//! own [`StateBand`], carried verbatim; every count under `carriage` / `receive`
//! is edge's own counter, carried verbatim. This module folds, names, and
//! localizes. It computes no verdict either source already computes — two lists
//! that disagree is the #541 shape, and the cure is to have one list.
//!
//! # A gauge, not a gate
//!
//! Nothing here may be gated on, and this module inherits that rule from
//! persist's `node_state` doc verbatim: a red drill band does not make a root
//! invalid, and `TrustRootVerdict::valid` does not consult it. The headline is
//! the colour of a tile, not the input to a decision.
//!
//! # Distinct zeroes — the discipline that matters most
//!
//! This repo has hit the collapsed-zero defect three times independently
//! (`ScoreOutcome`, `RetentionOutcome`, and edge's own withhold ledger). The
//! rule every field below obeys:
//!
//! > **`0` on an idle node and `0` on a withholding node must not render the
//! > same. "Nothing to report" and "could not read" must not render the same.**
//!
//! Concretely, the zeroes this surface separates by TOKEN (not merely by band):
//!
//! - [`CarriageStanding`] — `unreadable` / `not_exercised` / `idle` / `moving` /
//!   `withholding`. An empty withhold ledger is *three different facts*
//!   depending on whether the counters could be read at all, whether a
//!   replication round has ever finished, and whether anything was served.
//! - [`ReceiveStanding`] — `unreadable` / `not_exercised` / `idle` / `converged` /
//!   `applying` / `refusing`, for the same reason on the other direction. The
//!   middle three were ONE token (`clean`) until CIRISEdge#457 gave the receive
//!   plane an accepted-applies counter: "nothing was offered to us", "everything
//!   offered was a row we already held" and "rows arrived and changed state here"
//!   are three facts that all report zero refusals.
//! - `trust_root.drill` — persist bands a NEVER-drilled root and a 200-day-stale
//!   root identically `Red` **on purpose** (its doc says the distinction is
//!   carried by `last_drill_at` being `None`). So this surface reads that field
//!   and emits `never_drilled` vs `stale`: two tokens, one band.
//! - `peer_quota` — `no_quota` / `not_exercised` / `clean`, because
//!   `slot_denials: 0` on a fresh process is untested, not healthy (persist
//!   already bands this `unknown`; this surface names WHICH unknown).
//! - `consent_sla` — `none_overdue` vs `unreadable`. `Some(0)` and `None` are
//!   different facts and persist keeps them apart; so does this.
//! - [`TracePlaneStanding`] — `unreadable` / `never_admitted` / `future_dated` /
//!   `live` / `quiet` / `dark`. **CIRISServer#369.** A corpus that could not be
//!   read and a corpus that holds nothing are not the same fact, and neither is
//!   the same as a plane that admitted its last trace two days ago.
//! - [`IngestStanding`] — `unreadable` / `not_exercised` / `clean` /
//!   `unattributed` / `background` / `stuck_producer`. **CIRISServer#370**, and
//!   the one INVERSE case on this surface: a large number of individually
//!   correct outcomes must name its cause too.
//! - Each SOURCE, whole: a missing source is `unavailable` with a reason, never
//!   an absent key and never a healthy default.
//!
//! # The 2026-08-05 incident, and what it added here
//!
//! `FSD/RCA_INGEST_REJECTION_2026-08-05.md`: traces stopped arriving on the
//! production canonical at `2026-08-03T23:30` and nobody knew for two days. The
//! producer signed, the server verified, the admission gate refused **8,631
//! times a day** with a precise diagnostic, and every layer was RIGHT. Nothing
//! turned "nothing is arriving" into a signal.
//!
//! Two readings close that, and they are complementary rather than redundant —
//! read together they distinguish the three ways a plane goes dark:
//!
//! | `trace_plane` | `ingest` | what it means |
//! |---|---|---|
//! | `dark` | `stuck_producer` | **the 2026-08-05 condition** — a producer is being correctly refused and cannot self-correct |
//! | `dark` | `clean` / `not_exercised` | nothing is even reaching this node: routing, the bridge, or the producer stopped |
//! | `live` | `stuck_producer` | one producer is broken while others still land — the 33-hour overlap window nobody was watching |
//!
//! # Strings are `{id, text}`, never sentences
//!
//! Every operator-facing string is a localizable pair — a stable `id` plus its
//! English source — the same shape [`crate::peer::consent_disclosure_json`]
//! emits. A UI resolves the id and falls back to `text`, marked as a fallback.
//! Handing a UI a pre-formatted sentence makes the surface English-only
//! forever.
//!
//! # What is volatile, stated rather than discovered
//!
//! Two different kinds of volatility ride this payload and they are not the
//! same kind:
//!
//! - `volatility.clock_dependent` — persist's own list, verbatim: bands that
//!   move on elapsed time alone, with no state change and no new row.
//! - `volatility.process_local` — the carriage/receive counters, which are
//!   cumulative since THIS process started, reset on restart, differ between
//!   processes serving one node, and are stored nowhere.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};

use ciris_edge::observability::{EdgeMetricsBundle, WithholdReason, RECENT_WITHHOLDS_CAP};
use ciris_persist::federation::node_state::{NodeState, StateBand, TrustRootStanding};
use ciris_persist::federation::quarantine::QuarantineState;
use ciris_persist::federation::register::KeyStatementStanding;
use ciris_persist::federation::trust_root::DrillFreshness;
use ciris_persist::prelude::Engine;

use crate::ingest_http::IngestRefusalBundle;

use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::{resolve_bearer, SessionCaller};

/// The locale every `text` field below is written in. A consumer that resolves
/// every `id` needs none of them; one that falls back needs to know what it is
/// falling back TO, so it can mark it rather than present English as if it were
/// the reader's language.
pub const SOURCE_LOCALE: &str = "en";

/// A localizable string: a stable id plus its English source.
type Msg = (&'static str, &'static str);

/// Render a [`Msg`] as the `{id, text}` pair the wire carries.
fn msg((id, text): Msg) -> Value {
    json!({ "id": id, "text": text })
}

// ─────────────────────────────────────────────────────────────────────────────
// The carriage (serve) half — edge's withhold ledger, folded.
// ─────────────────────────────────────────────────────────────────────────────

/// CIRISServer#356 — **why a withhold happened, at the granularity an operator
/// acts on.**
///
/// Edge's [`WithholdReason`] is a closed, per-BRANCH taxonomy — one variant per
/// code branch, deliberately not a disjunction. That is the right granularity
/// for a counter and the wrong one for a headline: eleven reasons do not sort
/// themselves into "I must fix this" and "this is my configuration working".
///
/// The three classes here come from edge's OWN per-variant prose, which already
/// draws the line ("working as designed" / "a wiring fault, not a policy
/// decision" / "transient, not a trust verdict" / "near-impossible — which is
/// exactly why it must speak if it ever fires"). This is a rendering of that
/// distinction, not a second opinion about it.
///
/// [`Self::of`] matches [`WithholdReason`] **exhaustively with no catch-all**,
/// so a new edge variant is a compile error here rather than a silent default.
/// That is the only guard that survives a substrate bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WithholdClass {
    /// A decision this node made on purpose: consent scope, a serve capability
    /// the peer does not hold, a producer's own recipient restriction. Nothing
    /// is broken; the configuration is what it is.
    Policy,
    /// A read or a wiring step failed and the serve path failed CLOSED. The
    /// withhold is not a verdict about the peer — edge is explicit that
    /// reporting a transient read failure as a confident statement about the
    /// peer "sends the operator looking in the wrong place".
    Fault,
    /// A row this node holds could not be served at all — it would not
    /// serialize, its persist row hash would not decode, or advertised bytes
    /// were unfetchable. A defect in local state, not a policy.
    Integrity,
}

impl WithholdClass {
    /// The stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Fault => "fault",
            Self::Integrity => "integrity",
        }
    }

    /// Every class, worst last.
    pub const ALL: &'static [Self] = &[Self::Policy, Self::Fault, Self::Integrity];

    /// The band a withhold of this class renders as.
    ///
    /// # Policy is YELLOW, and that was the hard call
    ///
    /// A node whose consent scope legitimately excludes some peer will sit at
    /// yellow indefinitely, and 0.5.153 is the standing warning about that: an
    /// instrument that fires on the healthy steady state trains people to
    /// ignore it. Two things make yellow right here anyway.
    ///
    /// First, this is a **pull gauge, not a log line** — nothing emits once a
    /// minute, so there is no alarm to habituate to; there is only the colour of
    /// a tile the operator chose to look at.
    ///
    /// Second, and decisively: *a policy withhold is exactly what an operator
    /// hunting a dark plane is looking for.* `ServeCapabilityMissing` is a
    /// policy verdict AND the documented reason a fleet that has not
    /// re-genesised with an `infra:serve`-blessed canonical sees no traces move
    /// at all (CIRISPersist#480). Rendering that green because the code did what
    /// it was configured to do would hide the single most valuable reading on
    /// this surface — which is the #356 defect, restated.
    ///
    /// Yellow is persist's *"warrants attention but not action"*, and that is
    /// the honest reading: look, understand, and change the configuration if it
    /// is not what you meant. It is not a fault, and it is never a gate.
    #[must_use]
    pub const fn band(self) -> StateBand {
        match self {
            Self::Policy => StateBand::Yellow,
            Self::Fault | Self::Integrity => StateBand::Red,
        }
    }

    /// Classify one of edge's withhold reasons. **Exhaustive by construction.**
    #[must_use]
    pub const fn of(reason: WithholdReason) -> Self {
        match reason {
            // "working as designed" / a policy verdict about the recipient.
            WithholdReason::RecipientNotInSendSet
            | WithholdReason::ServeCapabilityMissing
            | WithholdReason::ServeCapabilityNotRooted
            | WithholdReason::RecipientCapabilityRestriction
            // edge v15.19.0 (CIRISEdge#440). Both are decisions somebody MADE,
            // not failures: a subscribed trust root paused the plane via
            // mesh_config, or an operator quarantined the author here. They
            // belong beside the other deliberate withholds — Yellow, "change the
            // configuration, not the code" — and NOT with the fail-closed reads
            // below, because reading them as a fault would send an operator
            // hunting for a defect in a mesh doing exactly what it was told.
            | WithholdReason::ConfigPaused
            | WithholdReason::QuarantinedAuthor
            // edge v18.0.0 (CIRISEdge#499 workstream F) — the accord relay gate.
            // These two are DECISIONS, not failures. CC 4.2.1: "a node that
            // never trusted the accord … is simply not reached", and a key that
            // names a root it holds no live seat on is not authoritative just
            // for naming it. An operator seeing either should look at the trust
            // edge or the roster, not hunt for a defect.
            | WithholdReason::AccordRelayNoTrustEdge
            | WithholdReason::AccordRelaySignerNotSeated
            // persist's classifier says the row is simply not on the accord
            // family — a determination, not a failure to make one.
            | WithholdReason::AccordRelayObjectNotAccord
            // edge v18.0.0 (CIRISEdge#499) — scope-native addressing. Each of
            // these is the scope gate REACHING A VERDICT: the blob's scope does
            // not admit the arrival scope, the request came in on an address
            // derived from another group's MLS exporter_secret (the
            // cross-group probe the design exists to refuse), or the peer is
            // not in the record's own roster. Refusing is the feature.
            | WithholdReason::BlobArrivalScopeInsufficient
            | WithholdReason::BlobArrivalGroupMismatch
            | WithholdReason::HoldingScopePeerNotInRoster
            // #169 LXMF — operator posture and advertised limits. Not a
            // propagation node; not holding mail for that destination; a
            // transient ID parked for someone else (the cross-recipient
            // mailbox probe per-destination scoping exists to catch); a stamp
            // below the cost this node ADVERTISES; a peer-sync form
            // leviculum-lxmf deliberately does not implement; a ceiling that
            // refused carriage before doing work; a full mailbox refusing
            // rather than silently evicting; and a parked message evicted at
            // its retention window — the bounded-retention promise being KEPT.
            // An operator who sees these should change configuration if they
            // meant something else, and otherwise leave them alone.
            | WithholdReason::LxmfPropagationDisabled
            | WithholdReason::LxmfDestinationNotServed
            | WithholdReason::LxmfMailboxScopeMismatch
            | WithholdReason::LxmfStampBelowCost
            | WithholdReason::LxmfPeerSyncUnsupported
            | WithholdReason::LxmfFrameOversized
            | WithholdReason::LxmfMailboxFull
            | WithholdReason::LxmfRetentionExpired => Self::Policy,
            // Fail-closed on a failed read, or a missing local wiring input.
            WithholdReason::LocalIdentityMissing
            | WithholdReason::SendSetUnresolved
            | WithholdReason::ServeCapabilityReadError
            | WithholdReason::TrustRootWalkError
            // A quarantine read that FAILED is not a quarantine that said no —
            // could-not-ask versus a verdict, the distinction this surface exists
            // to keep. Fail-closed, and Red: the node withheld without knowing
            // whether it had to.
            | WithholdReason::QuarantineReadError
            // "I CANNOT JUDGE" — kept apart from the two accord VERDICTS below,
            // which is the distinction CIRISPersist#713 wrote a mutation to
            // protect: an unjudgeable root reported as an unseated signer is an
            // admission of ignorance dressed as an accusation. Roster
            // unresolvable = go sync the family record; unresolved = the check
            // never ran (a wiring/timing fact, fail-closed). Both are things to
            // go fix, so Fault — the band the other read failures already use.
            | WithholdReason::AccordRelayRosterUnresolvable
            | WithholdReason::AccordRelayUnresolved
            // CIRISEdge#499 / CIRISPersist#744 — every one of these is the node
            // being UNABLE to decide, which is categorically different from
            // deciding no. Scope undeterminable; an audience KIND with no
            // peer-set mechanism on this plane; the gate armed with no
            // FederationDirectory wired; the authority walk erroring; the
            // recipient set answering "I cannot judge"; and the recipient read
            // returning Err. All of them are something to go wire or go fix.
            | WithholdReason::BlobScopeUndeterminable
            | WithholdReason::HoldingScopeUndeterminable
            | WithholdReason::HoldingScopeProjectionUnsupported
            | WithholdReason::HoldingScopeDirectoryMissing
            | WithholdReason::HoldingScopeAuthorityUnresolved
            | WithholdReason::HoldingScopeRecipientSetUnresolved
            | WithholdReason::HoldingScopeRecipientReadError
            // The requester's identity did not resolve, so there is no
            // destination to scope a mailbox to. Fail-closed and Red: the node
            // withheld without being able to establish who was asking.
            | WithholdReason::LxmfRequesterUnidentified => Self::Fault,
            // Local state that cannot be put on the wire at all.
            WithholdReason::EnvelopeUnfetchable
            | WithholdReason::RowNotSerializable
            | WithholdReason::RowHashUndecodable
            // The ROW is the problem, which is what Integrity means here.
            // Unreadable = it does not deserialize into persist's row type, so
            // there is nothing to hand the relay verb. MirrorUnbound = the
            // RowMirror is absent (a pre-#643 unstamped row) or DIVERGES, so
            // the typed columns assert nothing and persist's
            // `check_row_column_binding` refuses it.
            //
            // Edge keeps those two apart deliberately and we preserve it: a
            // DIVERGENCE is a security event (a relay rewriting a signed row's
            // identity, verb, signer or subject while the signature still
            // verifies), while a missing mirror is a producer-vintage problem.
            // Same band, different findings — the band carries the operator's
            // urgency, not the diagnosis.
            | WithholdReason::AccordRelayObjectUnreadable
            | WithholdReason::AccordRelayMirrorUnbound
            // CIRISPersist#733 — the accord_root contract, and both arms are
            // properties of the ARTIFACT. Unnamed: the row is on the accord
            // family and nothing in it names the accord it acts under, so it
            // asserts authority it never identifies. Disagrees: ONE ARTIFACT
            // ASSERTING TWO ACCORDS — the signed key and the drill-dimension
            // rule name different roots, which persist refuses outright rather
            // than silently preferring either, because the problem is not
            // which to pick.
            | WithholdReason::AccordRelayObjectRootUnnamed
            | WithholdReason::AccordRelayObjectRootDisagrees
            // A private roster declared at Public cohort scope is a
            // self-contradictory holding, not a policy choice.
            | WithholdReason::HoldingScopePublicGroup
            // The bytes do not decode as the wire this endpoint speaks.
            | WithholdReason::LxmfWireUnparseable => Self::Integrity,
        }
    }

    /// The operator-facing explanation.
    #[must_use]
    pub const fn message(self) -> Msg {
        match self {
            Self::Policy => (
                "operator.withhold_class.policy",
                "A decision this node made on purpose — consent scope, a serve capability the \
                 peer does not hold, or the producer's own restriction. Working as configured: \
                 change the configuration, not the code.",
            ),
            Self::Fault => (
                "operator.withhold_class.fault",
                "A read or a wiring step failed and the serve path failed closed. This is NOT a \
                 verdict about the peer — it is this node's fault to fix.",
            ),
            Self::Integrity => (
                "operator.withhold_class.integrity",
                "A row this node holds could not be served at all: it would not serialize, its \
                 stored hash would not decode, or advertised bytes were unfetchable. A defect in \
                 local state, not a policy.",
            ),
        }
    }
}

/// CIRISServer#356 — **what an empty withhold ledger MEANS.**
///
/// The ledger's own zero is three different facts and edge cannot tell them
/// apart from inside a counter. This is the narrowing, and it is drawn entirely
/// from other counters in the SAME bundle — never re-derived from a second
/// source that could disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarriageStanding {
    /// The counters could not be read at all (no live Edge in this process).
    /// **Not** "nothing was withheld" — "we could not ask".
    Unreadable,
    /// The counters were read and NO replication round has reached a terminal
    /// state on this process, so no serving-path gate has ever run. A zero here
    /// is UNTESTED, in exactly the sense persist bands a fresh peer quota
    /// `unknown` rather than green.
    NotExercised,
    /// Rounds finished; this node served nothing and withheld nothing. It had
    /// nothing its peers still needed. A real, healthy state — and a different
    /// one from [`Self::Moving`].
    Idle,
    /// Rounds finished, rows were served, nothing was withheld.
    Moving,
    /// At least one serving-path gate declined to serve a row it held. The
    /// reason axis says which branch; the ring says to whom.
    Withholding,
}

impl CarriageStanding {
    /// The stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::NotExercised => "not_exercised",
            Self::Idle => "idle",
            Self::Moving => "moving",
            Self::Withholding => "withholding",
        }
    }

    /// Every variant — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::Unreadable,
        Self::NotExercised,
        Self::Idle,
        Self::Moving,
        Self::Withholding,
    ];

    /// The operator-facing explanation.
    #[must_use]
    pub const fn message(self) -> Msg {
        match self {
            Self::Unreadable => (
                "operator.carriage.unreadable",
                "This node's carriage counters could not be read, so nothing here is a statement \
                 about what it served. This is not 'nothing was withheld' — it is 'we could not \
                 ask'.",
            ),
            Self::NotExercised => (
                "operator.carriage.not_exercised",
                "No replication round has finished on this process, so no serving-path gate has \
                 ever run and the withhold ledger has never been written to. The zero is \
                 untested, not clean.",
            ),
            Self::Idle => (
                "operator.carriage.idle",
                "Replication rounds finished, and this node served nothing and withheld nothing: \
                 it had nothing its peers still needed.",
            ),
            Self::Moving => (
                "operator.carriage.moving",
                "This node served rows to its peers and withheld none.",
            ),
            Self::Withholding => (
                "operator.carriage.withholding",
                "This node declined to serve rows it held. `withholds_by_reason` names the branch \
                 that declined and `recent_withholds` names to whom — an idle node reports \
                 neither.",
            ),
        }
    }
}

/// CIRISServer#356 — **what a zero apply-refusal count MEANS.**
///
/// # CIRISEdge#457 — the `clean` arm split three ways
///
/// Until edge v15.20.1 this enum had a single healthy arm, `clean`, and it was
/// overloaded: edge booked `ApplyOutcome::Refused` and booked neither `Admitted`
/// nor `Duplicate`, so *nothing was offered to us*, *everything offered applied*
/// and *everything offered was a row we already held* all produced the same
/// reading. That is the collapsed zero this module exists to prevent, sitting in
/// the module's own enum, and it survived because the counter that would have
/// separated the arms did not exist to be read.
///
/// It exists now — `replication_applied_total` and `replication_duplicate_total`,
/// booked at the same #425 apply choke as the refusals — so the three are three
/// tokens. They deliberately mirror [`CarriageStanding`]'s arms on the other
/// direction: `idle` is "nothing moved and nothing was owed", and the arm above
/// it names what moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveStanding {
    /// The counters could not be read at all. **Not** "nothing was refused" —
    /// "we could not ask".
    Unreadable,
    /// No replication round has finished on this process, so nothing has been
    /// offered to the apply path. Untested, not clean.
    NotExercised,
    /// Rounds finished and the apply path was never reached: no row was applied,
    /// none was a duplicate, none was refused. Our peers offered us nothing.
    ///
    /// The receive mirror of [`CarriageStanding::Idle`], and a REAL state — but
    /// not the same fact as [`Self::Converged`], where rows were offered and
    /// every one was already held.
    Idle,
    /// Rows were offered and every one was a row this node already held
    /// (`ApplyOutcome::Duplicate`): nothing was refused and nothing changed
    /// state. The healthy steady state of anti-entropy, and the arm that used to
    /// be indistinguishable from having been offered nothing at all.
    Converged,
    /// Rows were offered, at least one was ADMITTED and changed local state, and
    /// none was refused. The reading that `clean` could never assert.
    Applying,
    /// At least one offered row was refused. Outranks every arm above it: a node
    /// that applied fifty rows and refused one is `refusing`, and the counts
    /// beside the token say which of those two numbers is the large one.
    Refusing,
}

impl ReceiveStanding {
    /// The stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::NotExercised => "not_exercised",
            Self::Idle => "idle",
            Self::Converged => "converged",
            Self::Applying => "applying",
            Self::Refusing => "refusing",
        }
    }

    /// Every variant — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::Unreadable,
        Self::NotExercised,
        Self::Idle,
        Self::Converged,
        Self::Applying,
        Self::Refusing,
    ];

    /// The band. `unreadable` and `not_exercised` are both `unknown`, and
    /// `idle` / `converged` / `applying` are all `green` — and each is a
    /// DIFFERENT TOKEN on its shared band, which is the whole discipline: a band
    /// never replaces a token, it only accompanies one.
    #[must_use]
    pub const fn band(self) -> StateBand {
        match self {
            Self::Unreadable | Self::NotExercised => StateBand::Unknown,
            Self::Idle | Self::Converged | Self::Applying => StateBand::Green,
            Self::Refusing => StateBand::Red,
        }
    }

    /// The operator-facing explanation.
    #[must_use]
    pub const fn message(self) -> Msg {
        match self {
            Self::Unreadable => (
                "operator.receive.unreadable",
                "This node's apply counters could not be read, so nothing here is a statement \
                 about what it accepted. This is not 'nothing was refused' — it is 'we could not \
                 ask'.",
            ),
            Self::NotExercised => (
                "operator.receive.not_exercised",
                "No replication round has finished on this process, so nothing has been offered \
                 to this node's apply path. The zero is untested, not clean.",
            ),
            Self::Idle => (
                "operator.receive.idle",
                "Replication rounds finished and no peer offered this node a single row: nothing \
                 was applied, nothing was already held, nothing was refused. Its peers had \
                 nothing for it, which is not the same fact as having applied everything they \
                 sent.",
            ),
            Self::Converged => (
                "operator.receive.converged",
                "Peers offered rows and this node already held every one of them, so nothing \
                 changed state and nothing was refused. This is anti-entropy at rest — traffic \
                 is arriving and there is nothing left to learn from it.",
            ),
            Self::Applying => (
                "operator.receive.applying",
                "Rows a peer offered were admitted here and changed this node's state, and none \
                 was refused. `applied_by_kind` names the planes that moved; `duplicate_total` \
                 beside it counts the offered rows this node already held.",
            ),
            Self::Refusing => (
                "operator.receive.refusing",
                "This node refused rows its peers offered. `apply_refusals_by_kind` names the \
                 plane; `key_apply_refusals_by_reason` names the policy token that refused a key.",
            ),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CIRISServer#369 — the trace plane's own liveness.
// ─────────────────────────────────────────────────────────────────────────────

/// Upper bound (hours) of the **green** trace-plane band: a plane that admitted
/// a trace inside this window is being fed.
///
/// Modelled on persist's [`DRILL_GREEN_MAX_DAYS`](ciris_persist::federation::trust_root::DRILL_GREEN_MAX_DAYS),
/// which bands exactly this shape for the trust root — *when did this last
/// happen, and is that long enough ago to worry?* — and carried onto the wire
/// beside the band, so a reader never has to know this constant to interpret the
/// colour beside it.
pub const TRACE_GREEN_MAX_HOURS: i64 = 6;

/// Upper bound (hours) of the **yellow** trace-plane band. At or beyond this the
/// plane reads RED.
///
/// The 2026-08-05 incident is the calibration: the last trace was admitted at
/// `2026-08-03T23:30` and a human first looked at `2026-08-05T13:55`, 38 hours
/// later. At 24 h this signal is RED for the last fourteen of those hours and
/// YELLOW for the thirty-two before that — which is the whole ask, since the RCA
/// names a 33-hour window in which one producer was already being refused while
/// another still succeeded and nothing compared the two.
pub const TRACE_YELLOW_MAX_HOURS: i64 = 24;

/// Tolerance before a newest-row timestamp in the FUTURE is called out rather
/// than banded. Ordinary NTP skew between a producer and this node is seconds;
/// five minutes is well outside it and well inside the green band.
pub const TRACE_FUTURE_TOLERANCE_MINUTES: i64 = 5;

/// CIRISServer#369 — **has this node admitted a trace lately, and if not, is
/// that a fault or an unread instrument?**
///
/// The node exists to receive traces. Before this reading it had a scorer
/// reporting `n_summaries`, a retention loop, an equivocation detector and four
/// distinct carriage zeroes — and nothing at all that said *"no trace has been
/// admitted in 48 hours."* Arrival was the one thing unwatched, and on
/// 2026-08-03 it stopped for two days with every layer reporting success.
///
/// # Six tokens on four bands
///
/// The band is the judgement; the token is the cause. `unreadable` and
/// `never_admitted` share the `unknown` band and are DIFFERENT FACTS — "we could
/// not ask the corpus" is not "the corpus is empty", and collapsing them is the
/// precise failure the RCA's third instrument failure describes (a grep that
/// matched nothing read as a node with nothing wrong).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TracePlaneStanding {
    /// The corpus could not be read at all. **Not** "nothing has been admitted".
    Unreadable,
    /// The corpus was read and holds no trace at all: nothing has EVER been
    /// admitted here.
    ///
    /// Bands `unknown`, not `red`, and the difference from persist's
    /// never-drilled arm is deliberate. A root always has a mint instant, so
    /// "never drilled" is always a real omission; an empty trace corpus is the
    /// ordinary state of every node between provisioning and its first batch. A
    /// signal that fires red on the healthy steady state trains people to
    /// ignore it — the standing 0.5.153 warning this module already cites — and
    /// an instrument nobody reads is what the RCA is about. `unknown` is
    /// non-green, is named individually in the surface's `unknown` list, and
    /// therefore cannot render as health.
    NeverAdmitted,
    /// The newest row in the corpus is stamped in the FUTURE by more than
    /// [`TRACE_FUTURE_TOLERANCE_MINUTES`].
    ///
    /// A statement about a clock, not about the plane — and it has to be its own
    /// token because it otherwise defeats the whole instrument silently: a
    /// producer stamping tomorrow pins this reading green forever, which is a
    /// dead plane wearing a healthy colour.
    FutureDated,
    /// A trace was admitted inside [`TRACE_GREEN_MAX_HOURS`].
    Live,
    /// Quiet longer than expected, but plausibly idle.
    Quiet,
    /// **Nothing admitted in [`TRACE_YELLOW_MAX_HOURS`] or more.** The 2026-08-05
    /// condition.
    Dark,
}

impl TracePlaneStanding {
    /// The stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::NeverAdmitted => "never_admitted",
            Self::FutureDated => "future_dated",
            Self::Live => "live",
            Self::Quiet => "quiet",
            Self::Dark => "dark",
        }
    }

    /// Every variant — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::Unreadable,
        Self::NeverAdmitted,
        Self::FutureDated,
        Self::Live,
        Self::Quiet,
        Self::Dark,
    ];

    /// The band. Three tokens sit on `unknown` and they are three different
    /// facts — a band never replaces a token.
    #[must_use]
    pub const fn band(self) -> StateBand {
        match self {
            Self::Unreadable | Self::NeverAdmitted | Self::FutureDated => StateBand::Unknown,
            Self::Live => StateBand::Green,
            Self::Quiet => StateBand::Yellow,
            Self::Dark => StateBand::Red,
        }
    }

    /// The operator-facing explanation.
    #[must_use]
    pub const fn message(self) -> Msg {
        match self {
            Self::Unreadable => (
                "operator.trace_plane.unreadable",
                "This node's trace corpus could not be read, so nothing here is a statement about \
                 what it has admitted. This is not 'no trace has arrived' — it is 'we could not \
                 ask'.",
            ),
            Self::NeverAdmitted => (
                "operator.trace_plane.never_admitted",
                "The corpus was read and holds no trace at all: nothing has ever been admitted on \
                 this node. There is no arrival instant to band, so this is an untested zero, not \
                 a healthy one — and on a node that has been serving for a while it is the same \
                 condition as a dark plane.",
            ),
            Self::FutureDated => (
                "operator.trace_plane.future_dated",
                "The newest trace in the corpus is stamped in the FUTURE. The timestamp is the \
                 producer's own broadcast clock, so this is a statement about that clock — and it \
                 is called out rather than banded because a future-dated row pins this reading \
                 green indefinitely and would hide a plane that has actually stopped.",
            ),
            Self::Live => (
                "operator.trace_plane.live",
                "A trace was admitted recently: the plane this node exists to receive on is being \
                 fed.",
            ),
            Self::Quiet => (
                "operator.trace_plane.quiet",
                "No trace has been admitted for longer than expected, but not yet long enough to \
                 call the plane dark. A genuinely idle node reads this way; so does the first \
                 half of a producer outage.",
            ),
            Self::Dark => (
                "operator.trace_plane.dark",
                "NOTHING HAS BEEN ADMITTED FOR LONGER THAN THIS NODE'S RED THRESHOLD. Arrival is \
                 the single thing this node exists to do. Read the `ingest` reading beside this: a \
                 dark plane with a sustained refusal rate is a producer being correctly rejected, \
                 and a dark plane with no refusals at all means nothing is even reaching this \
                 node.",
            ),
        }
    }
}

/// What the corpus read returned. Carrying the row count beside the instant is
/// free — it comes out of the same aggregate — and it is what makes
/// `never_admitted` checkable rather than inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceCorpus {
    /// `MAX(trace_events.ts)`, or `None` on an empty corpus.
    pub last_admitted_at: Option<DateTime<Utc>>,
    /// `COUNT(*)` over `trace_events`.
    pub rows: u64,
}

/// **CIRISServer#446 — what this node is CARRYING**, from persist's own aggregate.
///
/// # Free information that was being thrown away
///
/// [`corpus_and_store`] already reads `Engine::storage_summary` on every call and
/// keeps two fields of one table. The aggregate answers for SIX tables plus the
/// whole-database byte count, and the other five were discarded — so the cost
/// was already being paid and the answer already computed. This carries it out.
///
/// # Why it is persist's numbers verbatim
///
/// Persist owns this measurement and exposes it; edge owns the carriage
/// counters and exposes those. This module's rule is draw from both, re-derive
/// neither — so nothing here counts a row. A hand-rolled `SELECT count(*)`
/// would be a second implementation of a number the store already computes, and
/// two lists that disagree is the #541 shape.
///
/// # What it deliberately does NOT include
///
/// The SQLite WAL — 218 MiB against a 1.26 GB store on the production canonical
/// — is absent because `total_disk_bytes` is `page_count * page_size`, which
/// does not count it, and persist exposes no reader for it. Stat-ing the file
/// from here would mean this module guessing persist's on-disk layout: a second
/// implementation of "how big is the store", which is the exact thing the rule
/// above forbids. Asked for in CIRISPersist#768 instead.
///
/// Likewise absent: the attestation family. `StorageSummary` has no
/// `TableUsage` for `federation_attestations` at all, which is why an operator
/// could not see the 194.8 MiB that dominates this node's read path without
/// opening the database by hand (CIRISPersist#767).
#[derive(Debug, Clone, PartialEq)]
pub struct StoreFootprint {
    /// Whole-database bytes as persist reports them: `pg_database_size` on
    /// Postgres, `page_count * page_size` on SQLite (WAL excluded — see above).
    pub total_disk_bytes: u64,
    /// `(table name, rows)` for every table the aggregate answers for, in a
    /// stable order. Rows only: per-table BYTES are `0` on SQLite unless
    /// `dbstat` is compiled in, and reporting a zero that means "not measured"
    /// beside zeros that mean "empty" is the collapsed-zero defect this file
    /// spends a section warning about.
    pub tables: Vec<(&'static str, u64)>,
}

impl StoreFootprint {
    fn from_summary(s: &ciris_persist::retention::StorageSummary) -> Self {
        Self {
            total_disk_bytes: s.total_disk_bytes,
            tables: vec![
                ("trace_events", s.trace_events.rows),
                ("trace_llm_calls", s.trace_llm_calls.rows),
                ("detection_events", s.detection_events.rows),
                ("audit_log", s.audit_log.rows),
                ("edge_outbound_queue", s.edge_outbound_queue.rows),
                ("federation_keys", s.federation_keys.rows),
            ],
        }
    }

    fn to_json(&self) -> Value {
        let tables: serde_json::Map<String, Value> = self
            .tables
            .iter()
            .map(|(name, rows)| ((*name).to_string(), serde_json::json!({ "rows": rows })))
            .collect();
        serde_json::json!({
            "total_disk_bytes": self.total_disk_bytes,
            "tables": tables,
            // Named absences. An operator reading this must be able to tell
            // "measured and small" from "not measured at all" WITHOUT knowing
            // which tables persist's aggregate happens to cover.
            // Message PAIRS, not bare strings (codex review, PR #483). These
            // are stable operator-facing sentences on a surface that advertises
            // `source_locale`, so a client in any other language had no key to
            // resolve and could only print English. Backend error DETAIL stays
            // a bare string — that is genuinely opaque and per-incident — but a
            // fixed explanation is not.
            //
            // Their ids are enumerated in the guard's `KNOWN_UNLOCALIZED` until
            // the bundles carry them (#484): a resolvable key that is not yet
            // translated is strictly better than prose with no key at all,
            // because the client can start resolving it the moment it lands.
            "not_measured": {
                "wal_bytes": msg(STORE_WAL_NOT_MEASURED),
                "federation_attestations": msg(STORE_ATTESTATIONS_NOT_MEASURED),
                "per_table_bytes": msg(STORE_PER_TABLE_BYTES_NOT_MEASURED),
            },
        })
    }
}

/// Band the trace plane.
///
/// `Result` rather than `Option` on the input for the reason this whole module
/// uses `Result`: a corpus that could not be read must carry that fact, and
/// `Option` would erase it into the empty-corpus arm — the one collapse #369
/// explicitly forbids.
#[must_use]
pub fn trace_plane_standing(
    corpus: Result<TraceCorpus, &str>,
    now: DateTime<Utc>,
) -> TracePlaneStanding {
    let Ok(c) = corpus else {
        return TracePlaneStanding::Unreadable;
    };
    let Some(last) = c.last_admitted_at else {
        return TracePlaneStanding::NeverAdmitted;
    };
    let age = now.signed_duration_since(last);
    if age < -chrono::Duration::minutes(TRACE_FUTURE_TOLERANCE_MINUTES) {
        return TracePlaneStanding::FutureDated;
    }
    if age < chrono::Duration::hours(TRACE_GREEN_MAX_HOURS) {
        TracePlaneStanding::Live
    } else if age < chrono::Duration::hours(TRACE_YELLOW_MAX_HOURS) {
        TracePlaneStanding::Quiet
    } else {
        TracePlaneStanding::Dark
    }
}

/// The producer of the trace-plane half, named on the wire.
const TRACE_SOURCE: &str = "ciris_persist::Engine::storage_summary().trace_events";

const TRACE_UNAVAILABLE: Msg = (
    "operator.source.trace_corpus.unavailable",
    "This node's trace corpus could not be read, so nothing here describes what it has admitted. \
     Absence of arrivals from an unread corpus is not absence of arrivals.",
);

/// The limit of the trace-plane reading, carried IN the payload — the same
/// discipline [`RECEIVE_DECIDED_DENOMINATOR`] follows, so a consumer that
/// renders the struct without reading this source still shows it.
pub const TRACE_PRODUCER_ASSERTED_TS: Msg = (
    "operator.trace_plane.producer_asserted_ts",
    "`last_admitted_at` is MAX(trace_events.admitted_at) — when THIS node last accepted a trace, \
     on its own clock (CIRISPersist#606, persist v32.1.0). It is no longer the producer's \
     assertion, so a peer with a skewed clock can no longer move this node's liveness reading. \
     `None` on a corpus whose rows all predate the admission column: that reads as \
     `never_admitted`, which is honest — this node cannot say when it last accepted one — and \
     deliberately NOT a fallback to the producer's timestamp, which would reinstate the very \
     coupling this replaced. A far-future row is still called out as `future_dated`.",
);

/// The trace-plane half as it appears on the wire.
fn trace_plane_json(corpus: Result<&TraceCorpus, &String>, now: DateTime<Utc>) -> Value {
    let standing = trace_plane_standing(corpus.copied().map_err(std::string::String::as_str), now);
    let mut out = Map::new();
    out.insert("band".into(), json!(standing.band().as_str()));
    out.insert("standing".into(), json!(standing.as_str()));
    out.insert("explains".into(), msg(standing.message()));
    out.insert("source".into(), json!(TRACE_SOURCE));
    out.insert("note".into(), msg(TRACE_PRODUCER_ASSERTED_TS));
    // The thresholds ride WITH the band. A band whose edges are only in the
    // source is a datum again: the reader cannot tell whether `quiet` means six
    // hours or six days without leaving the payload.
    out.insert(
        "bands".into(),
        json!({
            "green_max_hours": TRACE_GREEN_MAX_HOURS,
            "yellow_max_hours": TRACE_YELLOW_MAX_HOURS,
            "future_tolerance_minutes": TRACE_FUTURE_TOLERANCE_MINUTES,
        }),
    );

    let c = match corpus {
        Ok(c) => c,
        Err(detail) => {
            out.insert("unavailable".into(), msg(TRACE_UNAVAILABLE));
            out.insert("detail".into(), json!(detail));
            return Value::Object(out);
        }
    };
    out.insert("last_admitted_at".into(), json!(c.last_admitted_at));
    out.insert(
        "age_seconds".into(),
        c.last_admitted_at.map_or(Value::Null, |t| {
            json!(now.signed_duration_since(t).num_seconds())
        }),
    );
    out.insert("rows".into(), json!(c.rows));
    Value::Object(out)
}

/// What the receive plane's denominator counts, carried IN the payload rather
/// than only in these docs — the same discipline persist's `PEER_QUOTA_NOTE`
/// uses, so a consumer that renders the struct without reading the source still
/// shows it.
///
/// **CIRISEdge#457 closed the gap this slot used to describe.** The old note here
/// said the substrate counted refusals and not accepted applies, so `clean` could
/// not separate "everything offered was applied" from "nothing was offered". Edge
/// v15.20.1 books `replication_applied_total` and `replication_duplicate_total` at
/// the same #425 choke as the refusals, so that separation is now
/// [`ReceiveStanding::Applying`] / [`ReceiveStanding::Converged`] /
/// [`ReceiveStanding::Idle`] and the caveat is gone rather than softened — a stale
/// caveat tells a reader not to trust a number that is now trustworthy.
///
/// What remains is not a limit on the standing but a fact about the denominator,
/// and it is stated because a total that silently excludes a class is the same
/// defect one level down: edge counts `ApplyOutcome::Deserialize` NOWHERE, on
/// purpose — undecodable bytes are wire corruption, not a policy decision, and
/// folding them into a per-kind apply count would conflate the two.
///
/// The message TEXT is localized across 29 bundles — extend the docs here, not the
/// string, unless you are re-translating.
pub const RECEIVE_DECIDED_DENOMINATOR: Msg = (
    "operator.receive.decided_denominator",
    "`decided_total` is every row a peer offered that reached an apply decision here: applied \
     plus duplicate plus refused. Bytes this node could not decode reach no decision and are \
     counted nowhere, so they are missing from this total rather than folded into it.",
);

/// The carriage/receive/ingest counters' volatility, stated in the payload.
pub const PROCESS_LOCAL_NOTE: Msg = (
    "operator.volatility.process_local",
    "The carriage, receive and ingest counters are process-local and cumulative since this \
     process started. They reset on restart, differ between processes serving one node, and are \
     stored nowhere. They are a gauge of this process, not a ledger of this node.",
);

/// Which fields [`PROCESS_LOCAL_NOTE`] governs.
pub const PROCESS_LOCAL_FIELDS: &[&str] = &["carriage", "receive", "ingest"];

/// The trace plane's volatility, which is a DIFFERENT kind from either of the
/// two already named.
///
/// It is not persist's clock-dependent list (that list is persist's own and this
/// module carries it verbatim), and it is not a process-local counter (the
/// corpus is durable and survives restart). It is a band computed here, over a
/// stored instant, against the read clock — so it moves on elapsed time alone,
/// with no state change and no new row.
///
/// That is not a caveat, it is the mechanism: a plane that stops being fed walks
/// green → yellow → red by itself, which is what makes it a detector rather than
/// a datum an operator has to already suspect something to go read.
pub const CLOCK_DEPENDENT_LOCAL_NOTE: Msg = (
    "operator.volatility.clock_dependent_local",
    "This band is computed on THIS node from a stored instant against the read clock, so it moves \
     on elapsed time alone — no state change, no new row. A node that stops admitting traces \
     walks green to yellow to red on its own, which is the point: it goes red without anyone \
     asking it to.",
);

/// Which fields [`CLOCK_DEPENDENT_LOCAL_NOTE`] governs.
pub const CLOCK_DEPENDENT_LOCAL_FIELDS: &[&str] = &["trace_plane"];

// ─────────────────────────────────────────────────────────────────────────────
// CIRISServer#370 — the ingest refusal rate as its own reading.
// ─────────────────────────────────────────────────────────────────────────────

/// Refusals inside the window at or above which the rate stops being churn.
///
/// One a minute, sustained for the whole window. The 2026-08-05 producer ran at
/// ~6/min for 71 hours unbroken; a stale client retrying on a backoff does not
/// reach this.
pub const INGEST_SUSTAINED_MIN: u64 = 60;

/// Distinct refused signers at or below which the identity set is STABLE — a
/// small fixed set of producers stuck in a loop, rather than churn.
///
/// The incident had exactly two. The threshold is what separates the two
/// opposite conditions that share one counter: 8,631 refusals a day from two
/// identities is a misconfigured client that cannot self-correct; the same rate
/// from eight thousand is a Sybil probe. Different responses, identical rate.
pub const INGEST_STABLE_SIGNER_MAX: usize = 8;

/// CIRISServer#370 — **what a rate of CORRECT refusals means.**
///
/// The inverse of this surface's distinct-zeroes rule. That rule says a zero
/// must name its own cause; this says **a large number of individually-correct
/// outcomes must also name its cause**, because "the gate is working" and "the
/// gate is working overtime because something upstream is broken" are different
/// conditions wearing the same success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestStanding {
    /// The ledger could not be read at all — this process has no HTTP ingest
    /// route mounted, or the ledger's lock was poisoned. **Not** "nothing was
    /// refused".
    Unreadable,
    /// The ledger was read and NOTHING has been offered to this path on this
    /// process: no accept, no refusal. The zero is untested, in exactly the
    /// sense [`CarriageStanding::NotExercised`] is.
    ///
    /// This arm exists because the ledger counts ACCEPTS as well as refusals, so
    /// "everything offered was admitted" and "nothing was offered" never had to
    /// share a reading here. The replication plane spent one release unable to
    /// make the same distinction for want of that counter — see
    /// [`ReceiveStanding`], where CIRISEdge#457 finally supplied it.
    NotExercised,
    /// Offers were made and none was refused inside the window.
    Clean,
    /// Refusals inside the window, and every one of them named NO signer:
    /// malformed batches, bad signatures, unsupported schema versions — refusals
    /// that failed before there was an identity to record.
    ///
    /// **This is the zero that must not collapse.** `distinct_signers == 0`
    /// trivially satisfies "a small, stable identity set", so a stuck-producer
    /// test written as `distinct <= MAX` alone reports a stuck producer that
    /// does not exist and names nobody — an unactionable red. It is also not
    /// clean and not ordinary churn. Its own token, checked first.
    Unattributed,
    /// Refusals, but not sustained, or sustained across a wide identity set:
    /// ordinary background of probes, stale clients and churn.
    ///
    /// Read `distinct_signers` before dismissing it — a *wide* set at a *high*
    /// rate is a probe, not churn, and it renders here because the RCA's
    /// remedy for it is investigation rather than a phone call to one producer.
    Background,
    /// **Sustained refusals from a small, stable identity set.** Someone is
    /// stuck in a retry loop and cannot self-correct. Every refusal is correct
    /// and the condition is still a fault — someone else's, which is why it
    /// needs a reader here and gets none from the gate that is doing its job.
    StuckProducer,
}

impl IngestStanding {
    /// The stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::NotExercised => "not_exercised",
            Self::Clean => "clean",
            Self::Unattributed => "unattributed",
            Self::Background => "background",
            Self::StuckProducer => "stuck_producer",
        }
    }

    /// Every variant — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::Unreadable,
        Self::NotExercised,
        Self::Clean,
        Self::Unattributed,
        Self::Background,
        Self::StuckProducer,
    ];

    /// The band.
    ///
    /// `stuck_producer` is RED even though this node did nothing wrong: the band
    /// answers "does someone need to act", and someone does. `background` is
    /// yellow for the same reason `WithholdClass::Policy` is — a pull gauge has
    /// no alarm to habituate to, and a refusal rate is what an operator hunting
    /// a dark plane is looking for.
    #[must_use]
    pub const fn band(self) -> StateBand {
        match self {
            Self::Unreadable | Self::NotExercised => StateBand::Unknown,
            Self::Clean => StateBand::Green,
            Self::Unattributed | Self::Background => StateBand::Yellow,
            Self::StuckProducer => StateBand::Red,
        }
    }

    /// The operator-facing explanation.
    #[must_use]
    pub const fn message(self) -> Msg {
        match self {
            Self::Unreadable => (
                "operator.ingest.unreadable",
                "This node's ingest refusal ledger could not be read, so nothing here is a \
                 statement about what it refused. This is not 'nothing was refused' — it is 'we \
                 could not ask'.",
            ),
            Self::NotExercised => (
                "operator.ingest.not_exercised",
                "Nothing has been offered to the HTTP ingest path on this process — no batch \
                 accepted and none refused. The zero is untested, not clean.",
            ),
            Self::Clean => (
                "operator.ingest.clean",
                "Batches were offered to the HTTP ingest path and none was refused inside the \
                 window. `refused_total` beside this is the whole-process count: a clean window \
                 on a process that refused earlier is a recovery, not an absence.",
            ),
            Self::Unattributed => (
                "operator.ingest.unattributed",
                "Batches were refused and NOT ONE named a signer: they failed before there was an \
                 identity to record — malformed bytes, a bad signature, an unsupported schema \
                 version. There is no producer to call, and this is deliberately not reported as \
                 a stuck producer: zero distinct signers is not a small stable identity set.",
            ),
            Self::Background => (
                "operator.ingest.background",
                "Refusals are present but not sustained from a stable identity set: ordinary \
                 probes, stale clients and churn. Read `distinct_signers` and \
                 `unattributed_in_window` before dismissing it — a HIGH rate spread across a WIDE \
                 identity set is a probe, and a HIGH rate that named almost nobody is malformed \
                 traffic with a stale client mixed into it. Neither is churn, and neither has one \
                 producer to go fix, which is why they read here rather than as a stuck producer.",
            ),
            Self::StuckProducer => (
                "operator.ingest.stuck_producer",
                "A SUSTAINED rate of refusals from a SMALL, STABLE set of signers: a producer is \
                 stuck in a retry loop and cannot self-correct. Every one of these refusals is \
                 correct — the gate is working — which is exactly why the aggregate needs its own \
                 reading. `top_signers` names who to go fix.",
            ),
        }
    }
}

/// Narrow an ingest refusal count to its cause. Every input comes from the SAME
/// bundle — one source, one answer.
///
/// **The order of the arms is load-bearing.** `unattributed` is tested BEFORE
/// the stable-set test, because `distinct_signers == 0` satisfies
/// `<= INGEST_STABLE_SIGNER_MAX` and would otherwise report a stuck producer
/// whose `top_signers` list is empty.
///
/// **And both halves of the stuck-producer test read one population.** The rate
/// is measured over the ATTRIBUTED refusals, not over the window, because the
/// identity set is drawn from the attributed refusals too — mixing the axes lets
/// unattributable volume carry a named producer over the bar it never reached on
/// its own.
#[must_use]
pub fn ingest_standing(bundle: Option<&IngestRefusalBundle>) -> IngestStanding {
    let Some(b) = bundle else {
        return IngestStanding::Unreadable;
    };
    if !b.readable {
        return IngestStanding::Unreadable;
    }
    if b.refusals_in_window == 0 {
        // Nothing offered at all — the untested zero, distinct from a clean one.
        if b.accepted_total == 0 && b.refused_total == 0 {
            return IngestStanding::NotExercised;
        }
        return IngestStanding::Clean;
    }
    if b.distinct_signers_in_window == 0 {
        return IngestStanding::Unattributed;
    }
    // BOTH halves of the stuck-producer test read the SAME population: the
    // refusals that actually named a signer. Testing the rate against the whole
    // window while testing the identity set against the attributed slice is one
    // number answering two questions — 399 malformed bodies beside one stale
    // client would clear a `>= SUSTAINED_MIN` bar the stale client contributed
    // one event to, and `top_signers` would then name the wrong party as the
    // thing to go fix. Naming the wrong producer is worse than naming none.
    let attributed = b
        .refusals_in_window
        .saturating_sub(b.unattributed_in_window);
    if attributed >= INGEST_SUSTAINED_MIN
        && b.distinct_signers_in_window <= INGEST_STABLE_SIGNER_MAX
    {
        return IngestStanding::StuckProducer;
    }
    IngestStanding::Background
}

/// The producer of the ingest half, named on the wire.
const INGEST_SOURCE: &str = "ciris_server::ingest_http::IngestRefusals::snapshot";

const INGEST_UNAVAILABLE: Msg = (
    "operator.source.ingest_refusals.unavailable",
    "This node's ingest refusal ledger could not be read, so nothing here describes what the \
     admission gate refused. A gate with no reader is what let 8,631 correct refusals a day run \
     unnoticed for 71 hours.",
);

/// The scope limit of the ingest reading, carried IN the payload.
pub const INGEST_HTTP_PATH_ONLY: Msg = (
    "operator.ingest.http_path_only",
    "This reading covers the HTTP ingest path only. A batch that arrives over the Reticulum relay \
     is verified by the same persist gate but is not counted here, so a clean ingest reading is \
     not a statement about every way a trace can be offered to this node.",
);

/// The ingest half as it appears on the wire.
fn ingest_json(bundle: Option<&IngestRefusalBundle>) -> Value {
    let standing = ingest_standing(bundle);
    let mut out = Map::new();
    out.insert("band".into(), json!(standing.band().as_str()));
    out.insert("standing".into(), json!(standing.as_str()));
    out.insert("explains".into(), msg(standing.message()));
    out.insert("source".into(), json!(INGEST_SOURCE));
    out.insert("note".into(), msg(INGEST_HTTP_PATH_ONLY));
    // The thresholds ride WITH the token, for the same reason the trace bands do.
    out.insert(
        "thresholds".into(),
        json!({
            "sustained_min_refusals_in_window": INGEST_SUSTAINED_MIN,
            "stable_signer_max": INGEST_STABLE_SIGNER_MAX,
            "top_signers_cap": crate::ingest_http::REFUSAL_TOP_N,
        }),
    );

    let Some(b) = bundle.filter(|b| b.readable) else {
        out.insert("unavailable".into(), msg(INGEST_UNAVAILABLE));
        return Value::Object(out);
    };

    out.insert("observed_since".into(), json!(b.observed_since));
    out.insert("window_seconds".into(), json!(b.window_seconds));
    out.insert("refusals_in_window".into(), json!(b.refusals_in_window));
    // The rate, spelled out, so the reading is a rate rather than a count the
    // reader has to divide by a window they also have to find.
    out.insert(
        "refusals_per_hour".into(),
        json!(if b.window_seconds > 0 {
            (b.refusals_in_window as f64) * 3600.0 / (b.window_seconds as f64)
        } else {
            0.0
        }),
    );
    out.insert(
        "distinct_signers".into(),
        json!(b.distinct_signers_in_window),
    );
    out.insert(
        "unattributed_in_window".into(),
        json!(b.unattributed_in_window),
    );
    out.insert(
        "top_signers".into(),
        Value::Array(
            b.top_signers
                .iter()
                .map(|(id, n)| json!({ "signer_id": id, "refusals": n }))
                .collect(),
        ),
    );
    out.insert("by_kind".into(), json!(b.by_kind_in_window));
    out.insert("accepted_total".into(), json!(b.accepted_total));
    out.insert("refused_total".into(), json!(b.refused_total));
    // A truncated window under-reports, and says so: the counts above become a
    // floor. Silence here would be the one thing worse than the under-report.
    out.insert("window_truncated".into(), json!(b.window_truncated));
    Value::Object(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// The two sources.
// ─────────────────────────────────────────────────────────────────────────────

/// The two composed sources, each either present or unavailable-with-a-reason.
///
/// Modelled as `Result` rather than `Option` on purpose: a missing source must
/// carry WHY it is missing, because "could not read" and "nothing to report" are
/// the pair this whole surface exists to keep apart.
pub struct Sources<'a> {
    /// persist's node-state fold, or the error text that stopped it.
    pub node: Result<&'a NodeState, String>,
    /// edge's metrics bundle, or the error text that stopped it.
    pub edge: Result<&'a EdgeMetricsBundle, String>,
    /// CIRISServer#369 — the trace corpus aggregate, or the error text that
    /// stopped it. A read failure MUST arrive here as `Err`, never as an empty
    /// corpus: "we could not ask" and "nothing has ever arrived" are the pair
    /// this reading exists to keep apart.
    pub trace: Result<&'a TraceCorpus, String>,
    /// CIRISServer#446 — what this node is carrying, from the SAME
    /// `storage_summary` read the trace band uses. `Err` when that read failed,
    /// for the same reason `trace` is: could-not-ask and nothing-there must not
    /// render alike.
    pub store: Result<&'a StoreFootprint, String>,
    /// CIRISServer#370 — this process's ingest refusal ledger, or `None` on a
    /// node with no HTTP ingest route mounted. Rendered `unreadable`, never as a
    /// clean zero.
    pub ingest: Option<&'a IngestRefusalBundle>,
}

/// The producer of each half, named on the wire so an operator chasing a value
/// knows which repo computes it.
/// CIRISServer#446 — the store footprint's producer. The SAME
/// `storage_summary` read as [`TRACE_SOURCE`], named separately because the two
/// readings can be asked about independently even though one call answers both.
/// CIRISServer#446 — the store footprint's NAMED ABSENCES, as message pairs.
///
/// A surface that silently omitted the largest table on the node would teach
/// its reader the node is small; these say so out loud, and say it in a shape a
/// non-English client can localize.
const STORE_WAL_NOT_MEASURED: Msg = (
    "operator.store.wal_bytes_not_measured",
    "The write-ahead log is excluded from this total: `total_disk_bytes` is page_count times \
     page_size, and persist exposes no reader for the WAL. On a busy node the WAL can be a \
     large fraction of what the disk actually holds.",
);

const STORE_ATTESTATIONS_NOT_MEASURED: Msg = (
    "operator.store.federation_attestations_not_measured",
    "The federation attestation table has no per-table line here: persist's storage summary \
     carries no reading for it. Its bytes ARE inside `total_disk_bytes`, which is the whole \
     database — what is missing is the ATTRIBUTION. On this node it is routinely the largest \
     table, so a large total may be almost entirely this one table and nothing here would \
     say so.",
);

const STORE_PER_TABLE_BYTES_NOT_MEASURED: Msg = (
    "operator.store.per_table_bytes_not_measured",
    "Per-table BYTES read as 0 on SQLite builds without dbstat, so row counts are reported \
     instead. A zero here means the size was not measured, never that the table is empty.",
);

const STORE_SOURCE: &str = "ciris_persist::Engine::storage_summary()";
const NODE_SOURCE: &str = "ciris_persist::federation::node_state::resolve_node_state";
const EDGE_SOURCE: &str = "ciris_edge::observability::EdgeMetrics::snapshot";

const NODE_UNAVAILABLE: Msg = (
    "operator.source.node_state.unavailable",
    "This node's state signals could not be read from the substrate, so nothing here describes \
     its trust root, key standing, quarantine, consent SLA or peer quota. Absence of bad news \
     from an unread source is not good news.",
);

const EDGE_UNAVAILABLE: Msg = (
    "operator.source.edge_metrics.unavailable",
    "This node's carriage counters could not be read, so nothing here describes what it served, \
     withheld, or refused to apply.",
);

// ─────────────────────────────────────────────────────────────────────────────
// Folding.
// ─────────────────────────────────────────────────────────────────────────────

/// Sum a counter map. **The ONE predicate that decides whether a counter has
/// anything in it**, used by the standing narrowings and by the rendered
/// `*_total` fields alike.
///
/// `is_empty()` would have been the obvious test and is subtly the wrong one: a
/// present key holding zero would make a standing say `withholding` while the
/// total beside it said `0`. Two answers to one question, in a payload whose
/// entire purpose is that there is only ever one.
fn total<K>(map: &std::collections::HashMap<K, u64>) -> u64 {
    map.values().sum()
}

/// Narrow an empty (or non-empty) withhold ledger to its cause. Every input
/// comes from the SAME bundle — one source, one answer.
#[must_use]
pub fn carriage_standing(bundle: Option<&EdgeMetricsBundle>) -> CarriageStanding {
    let Some(b) = bundle else {
        return CarriageStanding::Unreadable;
    };
    if total(&b.withholds_by_reason) > 0 {
        return CarriageStanding::Withholding;
    }
    // No terminal round ⇒ no serving-path gate has run ⇒ the ledger's zero has
    // never been written to. (Edge documents this map as empty until the
    // runtime is started with a live metrics handle, so this arm also covers an
    // unwired runtime — both are honestly "not exercised".)
    if total(&b.replication_round_outcomes_total) == 0 {
        return CarriageStanding::NotExercised;
    }
    if total(&b.replication_envelopes_served_total) == 0 {
        CarriageStanding::Idle
    } else {
        CarriageStanding::Moving
    }
}

/// The carriage band. `withholding` takes the band of its WORST class, so a
/// node withholding only by consent policy reads yellow and a node withholding
/// on a failed read reads red — they are not the same event.
#[must_use]
pub fn carriage_band(standing: CarriageStanding, worst_class: Option<WithholdClass>) -> StateBand {
    match standing {
        CarriageStanding::Unreadable | CarriageStanding::NotExercised => StateBand::Unknown,
        CarriageStanding::Idle | CarriageStanding::Moving => StateBand::Green,
        // `Withholding` and `worst_withhold_class` ask the same question of the
        // same map through the same `total` predicate, so `None` here is
        // unreachable. It bands RED rather than green anyway: a withhold whose
        // class we somehow lost is not a healthy withhold.
        CarriageStanding::Withholding => worst_class.map_or(StateBand::Red, WithholdClass::band),
    }
}

/// Narrow a zero apply-refusal count to its cause. **The ONE derivation of this
/// question in this repo** — `federation_delivery::round_diagnostics_json` and
/// `GET /v1/federation/metrics` both call this rather than re-deriving it, because
/// #377 was two readers of one bundle, one right and one wrong.
///
/// Every input comes from the SAME bundle — one source, one answer — and reaches
/// it through [`total`], so a present-but-zero key can never make a standing
/// disagree with the count rendered beside it.
#[must_use]
pub fn receive_standing(bundle: Option<&EdgeMetricsBundle>) -> ReceiveStanding {
    let Some(b) = bundle else {
        return ReceiveStanding::Unreadable;
    };
    // A refusal outranks every healthy arm: it is the only one that is a fault,
    // and a node that applied fifty rows and refused one still refused one.
    if total(&b.apply_refusals_by_kind) > 0 || total(&b.key_apply_refusals_by_reason) > 0 {
        return ReceiveStanding::Refusing;
    }
    // No terminal round ⇒ the apply path has never been asked anything ⇒ every
    // zero below is UNTESTED rather than clean. Same predicate as the carriage
    // half, for the same reason.
    if total(&b.replication_round_outcomes_total) == 0 {
        return ReceiveStanding::NotExercised;
    }
    // CIRISEdge#457 — the three arms that were one. Order matters: an admit is
    // the loudest fact of the three (local state changed), a duplicate says
    // traffic arrived and taught us nothing, and only the absence of BOTH means
    // the apply path was never handed a row.
    if total(&b.replication_applied_total) > 0 {
        return ReceiveStanding::Applying;
    }
    if total(&b.replication_duplicate_total) > 0 {
        return ReceiveStanding::Converged;
    }
    ReceiveStanding::Idle
}

/// Every row a peer offered that reached an apply DECISION — applied, duplicate
/// or refused, summed. The denominator [`RECEIVE_DECIDED_DENOMINATOR`] describes,
/// computed once here so no caller invents a second definition of "offered".
///
/// `ApplyOutcome::Deserialize` is deliberately absent — edge books it nowhere,
/// and a total that quietly absorbed undecodable bytes would report wire
/// corruption as a policy outcome.
#[must_use]
pub fn receive_decided_total(bundle: &EdgeMetricsBundle) -> u64 {
    total(&bundle.replication_applied_total)
        + total(&bundle.replication_duplicate_total)
        + total(&bundle.apply_refusals_by_kind)
}

/// The worst withhold class present in the ledger, or `None` when it is empty.
#[must_use]
pub fn worst_withhold_class(bundle: &EdgeMetricsBundle) -> Option<WithholdClass> {
    bundle
        .withholds_by_reason
        .iter()
        .filter(|(_, n)| **n > 0)
        .map(|(r, _)| WithholdClass::of(*r))
        .max()
}

/// The carriage half as it appears on the wire.
fn carriage_json(bundle: Option<&EdgeMetricsBundle>) -> Value {
    let standing = carriage_standing(bundle);
    let worst = bundle.and_then(worst_withhold_class);
    let band = carriage_band(standing, worst);

    let mut out = Map::new();
    out.insert("band".into(), json!(band.as_str()));
    out.insert("standing".into(), json!(standing.as_str()));
    out.insert("explains".into(), msg(standing.message()));

    let Some(b) = bundle else {
        out.insert("source".into(), json!(EDGE_SOURCE));
        out.insert("unavailable".into(), msg(EDGE_UNAVAILABLE));
        return Value::Object(out);
    };

    // Per-reason counts, keyed on EDGE's stable label — never a label of ours.
    let mut by_reason = Map::new();
    let mut by_class: std::collections::BTreeMap<&'static str, u64> = WithholdClass::ALL
        .iter()
        .map(|c| (c.as_str(), 0u64))
        .collect();
    let mut withholds_total: u64 = 0;
    for (reason, n) in &b.withholds_by_reason {
        by_reason.insert(reason.as_str().into(), json!(n));
        *by_class
            .entry(WithholdClass::of(*reason).as_str())
            .or_insert(0) += n;
        withholds_total += n;
    }

    let recent: Vec<Value> = b
        .recent_withholds
        .iter()
        .map(|w| {
            json!({
                "reason": w.reason.as_str(),
                "class": WithholdClass::of(w.reason).as_str(),
                "peer_key_id": w.peer_key_id,
                "detail": w.detail,
            })
        })
        .collect();

    let mut served = Map::new();
    let mut served_total: u64 = 0;
    for (kind, n) in &b.replication_envelopes_served_total {
        served.insert(kind.as_wire_str().into(), json!(n));
        served_total += n;
    }

    let mut rounds = Map::new();
    let mut rounds_total: u64 = 0;
    for (outcome, n) in &b.replication_round_outcomes_total {
        rounds.insert(outcome.as_str().into(), json!(n));
        rounds_total += n;
    }

    out.insert("source".into(), json!(EDGE_SOURCE));
    out.insert(
        "worst_withhold_class".into(),
        worst.map_or(Value::Null, |c| json!(c.as_str())),
    );
    out.insert(
        "class_explains".into(),
        Value::Array(
            WithholdClass::ALL
                .iter()
                .map(|c| {
                    json!({
                        "class": c.as_str(),
                        "band": c.band().as_str(),
                        "count": by_class.get(c.as_str()).copied().unwrap_or(0),
                        "message": msg(c.message()),
                    })
                })
                .collect(),
        ),
    );
    out.insert("withholds_total".into(), json!(withholds_total));
    out.insert("withholds_by_reason".into(), Value::Object(by_reason));
    out.insert("withholds_by_class".into(), json!(by_class));
    out.insert("recent_withholds".into(), Value::Array(recent));
    out.insert("recent_withholds_cap".into(), json!(RECENT_WITHHOLDS_CAP));
    out.insert("served_total".into(), json!(served_total));
    out.insert("served_by_kind".into(), Value::Object(served));
    out.insert("rounds_total".into(), json!(rounds_total));
    out.insert("rounds_by_outcome".into(), Value::Object(rounds));
    out.insert(
        "inbound_backpressure_drops".into(),
        json!(b.replication_inbound_backpressure_drops),
    );
    Value::Object(out)
}

/// The receive half as it appears on the wire.
fn receive_json(bundle: Option<&EdgeMetricsBundle>) -> Value {
    let standing = receive_standing(bundle);
    let mut out = Map::new();
    out.insert("band".into(), json!(standing.band().as_str()));
    out.insert("standing".into(), json!(standing.as_str()));
    out.insert("explains".into(), msg(standing.message()));
    out.insert("source".into(), json!(EDGE_SOURCE));
    out.insert("note".into(), msg(RECEIVE_DECIDED_DENOMINATOR));

    let Some(b) = bundle else {
        out.insert("unavailable".into(), msg(EDGE_UNAVAILABLE));
        return Value::Object(out);
    };

    let mut by_kind = Map::new();
    let mut refusals_total: u64 = 0;
    for (kind, n) in &b.apply_refusals_by_kind {
        by_kind.insert(kind.as_wire_str().into(), json!(n));
        refusals_total += n;
    }
    let mut by_reason = Map::new();
    for (token, n) in &b.key_apply_refusals_by_reason {
        by_reason.insert(token.clone(), json!(n));
    }
    // CIRISEdge#457 — the two accepted-apply axes, rendered through edge's own
    // `as_wire_str` so the kind token here is the kind token on the wire (one
    // vocabulary, never a hand-mirrored copy — SRV-1/#322). They are separate
    // maps because an admit and a duplicate are separate facts: collapsing them
    // would re-create, one level down, exactly the overload #457 removed.
    let mut applied_by_kind = Map::new();
    let mut applied_total: u64 = 0;
    for (kind, n) in &b.replication_applied_total {
        applied_by_kind.insert(kind.as_wire_str().into(), json!(n));
        applied_total += n;
    }
    let mut duplicate_by_kind = Map::new();
    let mut duplicate_total: u64 = 0;
    for (kind, n) in &b.replication_duplicate_total {
        duplicate_by_kind.insert(kind.as_wire_str().into(), json!(n));
        duplicate_total += n;
    }
    out.insert("applied_total".into(), json!(applied_total));
    out.insert("applied_by_kind".into(), Value::Object(applied_by_kind));
    out.insert("duplicate_total".into(), json!(duplicate_total));
    out.insert("duplicate_by_kind".into(), Value::Object(duplicate_by_kind));
    out.insert("apply_refusals_total".into(), json!(refusals_total));
    out.insert("apply_refusals_by_kind".into(), Value::Object(by_kind));
    out.insert(
        "key_apply_refusals_by_reason".into(),
        Value::Object(by_reason),
    );
    // The denominators. `decided_total` says how many rows the three counts
    // above divide up; `rounds_total` says whether this node was ever asked at
    // all, which is what makes a `decided_total` of 0 readable rather than bare.
    out.insert("decided_total".into(), json!(receive_decided_total(b)));
    out.insert(
        "rounds_total".into(),
        json!(total(&b.replication_round_outcomes_total)),
    );
    Value::Object(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// The persist half: persist's tokens, given sentences. No band is recomputed.
// ─────────────────────────────────────────────────────────────────────────────

/// One `(signal, token, band, message)` row explaining a persist signal.
///
/// The `band` is persist's, carried; only the `token` narrowing and the
/// `message` are this module's. Every match below is exhaustive over a persist
/// enum, so a new substrate variant is a compile error here.
fn explain(signal: &str, token: &str, band: StateBand, m: Msg) -> Value {
    json!({
        "signal": signal,
        "token": token,
        "band": band.as_str(),
        "message": msg(m),
    })
}

const fn trust_root_message(s: TrustRootStanding) -> Msg {
    match s {
        TrustRootStanding::Valid => (
            "operator.trust_root.valid",
            "This node roots to a trust root that checks out in full: a live trust edge, a \
             self-declaring charter with a recovery commitment, and no halt latched.",
        ),
        TrustRootStanding::NoSelfKey => (
            "operator.trust_root.no_self_key",
            "The host never declared this node's own key id, so nothing self-scoped could be \
             walked. This is a statement about the reader, not about the node: declare the key \
             at startup and every self-scoped signal below becomes answerable.",
        ),
        TrustRootStanding::NoTrustEdges => (
            "operator.trust_root.no_trust_edges",
            "This node declared itself and holds no live trust edge to any root: it roots to \
             nothing. A known bad, not a missing reading.",
        ),
        TrustRootStanding::NoValidRoot => (
            "operator.trust_root.no_valid_root",
            "This node trusts one or more roots and none of them validates. The per-leg verdict \
             beside this names which leg failed.",
        ),
        TrustRootStanding::Unreadable => (
            "operator.trust_root.unreadable",
            "The trust-root walk could not be read. An unreadable directory is not an untrusted \
             one — do not read this as a rootless node.",
        ),
    }
}

/// The drill narrowing. Persist bands NEVER-drilled and long-stale identically
/// `Red` **on purpose**, and its doc says the distinction is carried by
/// `last_drill_at` being `None` rather than by a fourth variant. So this reads
/// that field and issues two tokens on the one band — which is exactly the
/// "a band never replaces a token" rule applied to the sharpest signal #356
/// names.
fn drill_narrowing(freshness: Option<DrillFreshness>, last_drill_at: bool) -> (&'static str, Msg) {
    match freshness {
        None => (
            "no_root_walked",
            (
                "operator.drill.no_root_walked",
                "No trust root was walked, so there is nothing to be undrilled about. This is not \
                 a stale drill — there is no drill subject.",
            ),
        ),
        Some(DrillFreshness::Green) => (
            "green",
            (
                "operator.drill.green",
                "This node's trust root proved its kill switch within the last 90 days.",
            ),
        ),
        Some(DrillFreshness::Yellow) => (
            "yellow",
            (
                "operator.drill.yellow",
                "This node's trust root last proved its kill switch between 90 and 180 days ago.",
            ),
        ),
        Some(DrillFreshness::Red) if !last_drill_at => (
            "never_drilled",
            (
                "operator.drill.never_drilled",
                "This node's trust root has NEVER proved its kill switch. It shares the red band \
                 with a long-abandoned root, and the absent last-drill instant beside it is the \
                 difference. The root still serves: drill freshness is a trust signal, never a \
                 gate.",
            ),
        ),
        Some(DrillFreshness::Red) => (
            "stale",
            (
                "operator.drill.stale",
                "This node's trust root last proved its kill switch more than 180 days ago. It \
                 still serves: drill freshness is a trust signal, never a gate.",
            ),
        ),
    }
}

const fn key_statement_message(s: Option<KeyStatementStanding>) -> Msg {
    match s {
        None => (
            "operator.key_statements.unreadable",
            "This node's key standing could not be computed. That is not 'stands' — an unasked \
             question has no answer.",
        ),
        Some(KeyStatementStanding::Stands) => (
            "operator.key_statements.stands",
            "No revocation this node holds covers a statement made right now.",
        ),
        Some(KeyStatementStanding::SuspectAfterBound) => (
            "operator.key_statements.suspect_after_bound",
            "A history-BOUNDED revocation covers a statement made right now: this key is \
             de-admitted as of now, and its honest past still stands. That bound is materially \
             better than an unbounded revocation and does not read the same.",
        ),
        Some(KeyStatementStanding::SuspectUnbounded) => (
            "operator.key_statements.suspect_unbounded",
            "An UNBOUNDED revocation covers this key, so everything it ever said is in doubt — \
             the revocation declined to say otherwise.",
        ),
    }
}

const fn quarantine_message(s: Option<QuarantineState>) -> Msg {
    match s {
        None => (
            "operator.quarantine.unreadable",
            "The quarantine state could not be read. That is not 'not quarantined'.",
        ),
        Some(QuarantineState::NotQuarantined) => (
            "operator.quarantine.not_quarantined",
            "No quarantine marker about this node's key has ever taken effect here.",
        ),
        Some(QuarantineState::Released) => (
            "operator.quarantine.released",
            "This node's key was withheld and then released. It serves now, and it did not \
             always — a different fact from never having been withheld.",
        ),
        Some(QuarantineState::Withheld) => (
            "operator.quarantine.withheld",
            "This node's key is withheld from serving by a quarantine marker.",
        ),
    }
}

const fn consent_sla_message(overdue: Option<usize>) -> Msg {
    match overdue {
        None => (
            "operator.consent_sla.unreadable",
            "The consent-SLA backlog could not be read. That is not 'nothing overdue'.",
        ),
        Some(0) => (
            "operator.consent_sla.none_overdue",
            "Every consent revocation this node promised to promote is inside its SLA window.",
        ),
        Some(_) => (
            "operator.consent_sla.overdue",
            "This node is LATE promoting consent revocations it committed to. The sampled \
             attestation ids beside this are the handles that clear the condition.",
        ),
    }
}

/// CIRISServer#356 — **which of the peer-quota zeroes this is.**
///
/// persist already bands a fresh quota `unknown` rather than green; what it does
/// not do is say WHICH unknown, and "this backend holds no quota" and "this
/// process has never charged a peer write" call for different actions. Narrowed
/// from the observation persist already carries — the band is persist's and is
/// not recomputed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerQuotaCause {
    /// This backend exposes no quota at all.
    NoQuota,
    /// A quota exists and no peer write has been charged against it.
    NotExercised,
    /// Exercised, and the slot-denial arithmetic still holds.
    Clean,
    /// Slot denials were recorded — the derivation no longer holds.
    Denials,
}

impl PeerQuotaCause {
    /// The stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoQuota => "no_quota",
            Self::NotExercised => "not_exercised",
            Self::Clean => "clean",
            Self::Denials => "denials",
        }
    }

    /// Every variant — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::NoQuota,
        Self::NotExercised,
        Self::Clean,
        Self::Denials,
    ];

    /// Read the cause off the observation persist carries.
    #[must_use]
    pub fn of(state: &NodeState) -> Self {
        // Borrowed, not moved: the observation stopped being `Copy` at persist
        // v38.0.0. Reading a cause off a state must never consume it — every
        // other reader here takes `&NodeState` for the same reason.
        match &state.peer_quota.observation {
            None => Self::NoQuota,
            Some(o) if o.slot_denials > 0 => Self::Denials,
            Some(o) if o.tracked_peers == 0 => Self::NotExercised,
            Some(_) => Self::Clean,
        }
    }

    /// The operator-facing explanation.
    #[must_use]
    pub const fn message(self) -> Msg {
        match self {
            Self::NoQuota => (
                "operator.peer_quota.no_quota",
                "This backend holds no peer-write quota, so the tripwire reports nothing. That is \
                 not a clean reading.",
            ),
            Self::NotExercised => (
                "operator.peer_quota.not_exercised",
                "No peer write has been charged against the quota on this process, so its zero is \
                 untested rather than clean.",
            ),
            Self::Clean => (
                "operator.peer_quota.clean",
                "The peer-write quota has been exercised and its slot-denial arithmetic still \
                 holds.",
            ),
            Self::Denials => (
                "operator.peer_quota.denials",
                "The peer-write quota recorded slot denials. The tracked-peers cap derivation no \
                 longer holds in this build.",
            ),
        }
    }
}

/// Every persist signal, given a token and a sentence. Bands are persist's.
fn node_explains(state: &NodeState) -> Vec<Value> {
    let (drill_token, drill_msg) = drill_narrowing(
        state.trust_root.drill_freshness,
        state.trust_root.last_drill_at.is_some(),
    );
    let quota = PeerQuotaCause::of(state);
    vec![
        explain(
            "trust_root",
            state.trust_root.standing.as_str(),
            state.trust_root.band,
            trust_root_message(state.trust_root.standing),
        ),
        explain(
            "trust_root.drill",
            drill_token,
            state.trust_root.drill_band,
            drill_msg,
        ),
        explain(
            "key_statements",
            state
                .key_statements
                .standing
                .map_or("unreadable", |s| s.as_str()),
            state.key_statements.band,
            key_statement_message(state.key_statements.standing),
        ),
        explain(
            "quarantine",
            state.quarantine.state.map_or("unreadable", |s| s.as_str()),
            state.quarantine.band,
            quarantine_message(state.quarantine.state),
        ),
        explain(
            "consent_sla",
            match state.consent_sla.overdue {
                None => "unreadable",
                Some(0) => "none_overdue",
                Some(_) => "overdue",
            },
            state.consent_sla.band,
            consent_sla_message(state.consent_sla.overdue),
        ),
        explain(
            "peer_quota",
            quota.as_str(),
            state.peer_quota.band,
            quota.message(),
        ),
    ]
}

const fn headline(band: StateBand) -> Msg {
    match band {
        StateBand::Green => (
            "operator.headline.green",
            "Every signal this node can compute reads healthy.",
        ),
        StateBand::Yellow => (
            "operator.headline.yellow",
            "This node is serving, and something here warrants a look.",
        ),
        StateBand::Unknown => (
            "operator.headline.unknown",
            "One or more signals could not be computed. Read the unknown list — an uncomputed \
             signal is not a healthy one.",
        ),
        StateBand::Red => (
            "operator.headline.red",
            "At least one signal reads unhealthy. Read the unknown list too: a red headline \
             ranks above an unknown and can otherwise hide one behind it.",
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The composed view.
// ─────────────────────────────────────────────────────────────────────────────

/// CIRISServer#356 — **fold both sources into one operator-readable value.**
///
/// Pure: no I/O, no clock read (`as_of` is the caller's, so it matches the
/// instant persist banded against). That is what lets every zero-case be pinned
/// by a unit test with no engine and no transport.
#[must_use]
pub fn compose(sources: Sources<'_>, as_of: DateTime<Utc>) -> Value {
    let node = sources.node.as_ref().ok().copied();
    let edge = sources.edge.as_ref().ok().copied();

    let carriage = carriage_json(edge);
    let receive = receive_json(edge);
    let trace_plane = trace_plane_json(sources.trace.as_ref().copied(), as_of);
    let ingest = ingest_json(sources.ingest);

    // Bands. persist's own roll-up is carried, never recomputed; the two edge
    // halves contribute theirs.
    let node_band = node.map_or(StateBand::Unknown, |s| s.band);
    // Re-read the band this module just WROTE into each half rather than
    // recomputing it: a roll-up computed from a second evaluation is the
    // two-lists-that-disagree shape at the smallest possible scale.
    let carriage_band_v = carriage
        .get("band")
        .and_then(Value::as_str)
        .map_or(StateBand::Unknown, band_of);
    let receive_band_v = receive
        .get("band")
        .and_then(Value::as_str)
        .map_or(StateBand::Unknown, band_of);
    let trace_band_v = trace_plane
        .get("band")
        .and_then(Value::as_str)
        .map_or(StateBand::Unknown, band_of);
    let ingest_band_v = ingest
        .get("band")
        .and_then(Value::as_str)
        .map_or(StateBand::Unknown, band_of);
    let band = node_band
        .worse(carriage_band_v)
        .worse(receive_band_v)
        .worse(trace_band_v)
        .worse(ingest_band_v);

    // Every unknown, named individually. A roll-up may not swallow one — a
    // known red outranks an unknown, so without this list the unknown vanishes.
    let mut unknown: Vec<String> = Vec::new();
    match node {
        None => unknown.push("node".into()),
        Some(s) => unknown.extend(s.unknown.iter().map(|u| format!("node.{u}"))),
    }
    if carriage_band_v == StateBand::Unknown {
        unknown.push("carriage".into());
    }
    if receive_band_v == StateBand::Unknown {
        unknown.push("receive".into());
    }
    if trace_band_v == StateBand::Unknown {
        unknown.push("trace_plane".into());
    }
    if ingest_band_v == StateBand::Unknown {
        unknown.push("ingest".into());
    }
    // An unreadable store is an unknown like any other. Reported in
    // `store.unreadable` but absent from `unknown`, it was invisible to every
    // consumer that scans the one list built to name what this payload could
    // not answer.
    if sources.store.is_err() {
        unknown.push("store".into());
    }

    let composed_from: Vec<&str> = [
        node.map(|_| "node_state"),
        edge.map(|_| "edge_metrics"),
        sources.trace.as_ref().ok().map(|_| "trace_corpus"),
        // CIRISServer#446 (codex review, PR #483). The store block was emitted
        // without appearing in ANY of the three bookkeeping mechanisms, so the
        // payload said it was not composed from the store while `store` carried
        // measured data — and a consumer keying on `composed_from` could not
        // see a reading that was right there.
        sources.store.as_ref().ok().map(|_| "store_footprint"),
        // A ledger that is HELD but could not be READ contributed nothing, so
        // it is not composed from — the same `readable` test `present` below
        // applies. Listing it here off `is_some()` alone would put the two
        // fields in the one payload at odds: composed from a source the very
        // next key calls absent.
        sources
            .ingest
            .filter(|b| b.readable)
            .map(|_| "ingest_refusals"),
    ]
    .into_iter()
    .flatten()
    .collect();

    let mut node_source = Map::new();
    node_source.insert("produced_by".into(), json!(NODE_SOURCE));
    node_source.insert("present".into(), json!(node.is_some()));
    if let Err(detail) = &sources.node {
        node_source.insert("unavailable".into(), msg(NODE_UNAVAILABLE));
        node_source.insert("detail".into(), json!(detail));
    }
    let mut edge_source = Map::new();
    edge_source.insert("produced_by".into(), json!(EDGE_SOURCE));
    edge_source.insert("present".into(), json!(edge.is_some()));
    if let Err(detail) = &sources.edge {
        edge_source.insert("unavailable".into(), msg(EDGE_UNAVAILABLE));
        edge_source.insert("detail".into(), json!(detail));
    }
    let mut trace_source = Map::new();
    trace_source.insert("produced_by".into(), json!(TRACE_SOURCE));
    trace_source.insert("present".into(), json!(sources.trace.is_ok()));
    if let Err(detail) = &sources.trace {
        trace_source.insert("unavailable".into(), msg(TRACE_UNAVAILABLE));
        trace_source.insert("detail".into(), json!(detail));
    }
    let mut store_source = Map::new();
    store_source.insert("produced_by".into(), json!(STORE_SOURCE));
    store_source.insert("present".into(), json!(sources.store.is_ok()));
    if let Err(detail) = &sources.store {
        // `present: false` + `detail`, and DELIBERATELY no localized
        // `unavailable` Msg like its siblings carry.
        //
        // A `Msg` is an (id, text) pair that the localization guard scrapes and
        // then requires in en.json and all 29 locales. Adding one here would
        // mean either inventing 29 translations or shipping a key the guard
        // reports as uncovered — and the store's failure reason is the SAME
        // `storage_summary` error the trace half already renders, so the
        // information is not lost, only the translated framing.
        //
        // Named rather than left to look like an oversight; it belongs with the
        // structured-params work in CIRISServer#484, where these strings get
        // localized properly instead of one at a time.
        store_source.insert("detail".into(), json!(detail));
    }
    let mut ingest_source = Map::new();
    ingest_source.insert("produced_by".into(), json!(INGEST_SOURCE));
    ingest_source.insert(
        "present".into(),
        json!(sources.ingest.is_some_and(|b| b.readable)),
    );
    if !sources.ingest.is_some_and(|b| b.readable) {
        ingest_source.insert("unavailable".into(), msg(INGEST_UNAVAILABLE));
    }

    json!({
        "as_of": as_of,
        "source_locale": SOURCE_LOCALE,
        "band": band.as_str(),
        "headline": msg(headline(band)),
        "unknown": unknown,
        "composed_from": composed_from,
        "sources": {
            "node_state": node_source,
            "edge_metrics": edge_source,
            "trace_corpus": trace_source,
            "store_footprint": store_source,
            "ingest_refusals": ingest_source,
        },
        "node": node,
        "node_explains": node.map(node_explains),
        "carriage": carriage,
        "receive": receive,
        // CIRISServer#369 — the one thing this node exists to do, watched.
        "trace_plane": trace_plane,
        // CIRISServer#370 — a rate of CORRECT refusals, read as the fault
        // report about someone else that it is.
        "ingest": ingest,
        // CIRISServer#446 — HOW BIG IS THIS NODE. persist's own aggregate,
        // carried out instead of discarded: the same read the trace band
        // already pays for answers for six tables and the whole-database byte
        // count. A read failure is `unreadable` with the reason, never an empty
        // store — the distinct-zeroes rule this file is built on.
        "store": match sources.store {
            Ok(f) => f.to_json(),
            Err(ref e) => json!({ "unreadable": e }),
        },
        "volatility": {
            // persist's own list, verbatim — bands that move on elapsed time
            // alone, with no state change and no new row.
            "clock_dependent": node.map(|s| s.clock_dependent.clone()).unwrap_or_default(),
            // The same shape, computed HERE rather than by persist. Kept out of
            // the list above so persist's stays verbatim and the two cannot be
            // mistaken for one list with two authors.
            "clock_dependent_local": {
                "fields": CLOCK_DEPENDENT_LOCAL_FIELDS,
                "note": msg(CLOCK_DEPENDENT_LOCAL_NOTE),
            },
            "process_local": {
                "fields": PROCESS_LOCAL_FIELDS,
                "note": msg(PROCESS_LOCAL_NOTE),
            },
        },
    })
}

/// Parse a band token back into persist's [`StateBand`]. Used only to re-read
/// the band this module just wrote into the carriage/receive halves, so the
/// roll-up and the rendered field cannot disagree.
fn band_of(token: &str) -> StateBand {
    StateBand::ALL
        .iter()
        .copied()
        .find(|b| b.as_str() == token)
        .unwrap_or(StateBand::Unknown)
}

// ─────────────────────────────────────────────────────────────────────────────
// The live read.
// ─────────────────────────────────────────────────────────────────────────────

/// Options for [`operator_state`], mirroring persist's
/// [`NodeStateOptions`](ciris_persist::federation::node_state::NodeStateOptions)
/// so the two cannot drift on defaults.
#[derive(Debug, Clone, Default)]
pub struct OperatorStateOptions {
    /// This node's own federation key id. `None` falls through to persist's
    /// `no_self_key` arm, which is `unknown` on every self-scoped signal.
    pub self_key_id: Option<String>,
    /// Pin the trust-root walk to ONE root instead of enumerating this node's
    /// own trust edges.
    pub root_key_id: Option<String>,
    /// The read-time instant. `None` ⇒ now.
    pub now: Option<DateTime<Utc>>,
    /// The consent-promotion SLA window in seconds. `None` ⇒ persist's 24 h.
    pub sla_seconds: Option<u64>,
}

/// CIRISServer#356 — **the live composed read.** Writes nothing, on every arm:
/// persist's fold uses the read-only overdue query by construction, and the
/// edge half is a counter clone. A dashboard may poll this at any rate.
///
/// `metrics` is a `Result` and not an `Option` on purpose: an absent edge must
/// carry the reason it is absent all the way onto the wire. `Option` would
/// erase it, and "the carriage counters are missing" with no cause is the
/// silent half of the very defect this surface exists to close.
pub async fn operator_state(
    engine: &Engine,
    metrics: Result<&ciris_edge::observability::EdgeMetrics, String>,
    refusals: Option<&crate::ingest_http::IngestRefusals>,
    opts: &OperatorStateOptions,
) -> Value {
    use ciris_persist::federation::node_state::{resolve_node_state, NodeStateOptions};

    let now = opts.now.unwrap_or_else(Utc::now);
    let directory = engine.federation_directory();
    let node = resolve_node_state(
        &*directory,
        NodeStateOptions {
            self_key_id: opts.self_key_id.as_deref(),
            root_key_id: opts.root_key_id.as_deref(),
            now,
            sla: std::time::Duration::from_secs(opts.sla_seconds.unwrap_or(86_400)),
        },
    )
    .await;

    let (trace, store) = corpus_and_store(engine).await;
    let bundle = metrics.map(ciris_edge::observability::EdgeMetrics::snapshot);
    let refusals = refusals.map(|r| r.snapshot_at(now));
    compose(
        Sources {
            node: node.as_ref().map_err(std::string::ToString::to_string),
            edge: bundle.as_ref().map_err(Clone::clone),
            trace: trace.as_ref().map_err(Clone::clone),
            store: store.as_ref().map_err(Clone::clone),
            ingest: refusals.as_ref(),
        },
        now,
    )
}

/// CIRISServer#369 / #446 — **one `storage_summary` read, BOTH readings**: the
/// trace band behind `last_admitted_at` and the store footprint.
///
/// `Engine::storage_summary` is persist's OWN aggregate, and the trace-plane
/// half of it is a pushed-down `SELECT count(*), MIN(ts), MAX(ts)` on both
/// backends. That is why it is the reader used here rather than any
/// list-and-fold: the answer is computed by the store, no row is materialized,
/// and — decisively — there is no second implementation of "when did a trace
/// last arrive" that could disagree with persist's own. A hand-rolled scan would
/// be the two-lists-that-disagree shape (#541) applied to the one signal this
/// node's health hangs on. The footprint half obeys the same rule for the same
/// reason: every byte and row count below is persist's, and nothing here counts.
///
/// # What it costs, stated because the surface invites polling
///
/// `storage_summary` answers for SIX tables, so a read is six of those
/// aggregates plus (on SQLite) two `PRAGMA`s. Every one is read-only, which is
/// what `polling_the_surface_writes_nothing` pins, but `count(*)` is a scan on
/// Postgres and the trace table is the largest on the node. That is an
/// acceptable price for having one implementation instead of two; it is NOT a
/// licence to poll this route at seconds' cadence, and it is written down here
/// rather than discovered later.
///
/// **Which is exactly why this is one call and not two.** #446 wanted a second
/// reading from the same aggregate. Asking twice would double a cost this
/// surface invites callers to pay on a poll, and would let the two answers
/// describe different instants — a footprint from one moment beside a corpus
/// from another, with nothing on the wire to say so.
///
/// A read failure comes back as `Err` on BOTH halves, and the caller must keep
/// them `Err`: [`TracePlaneStanding::Unreadable`] and
/// [`TracePlaneStanding::NeverAdmitted`] are different facts, and #369's whole
/// ask is that they never render alike.
async fn corpus_and_store(
    engine: &Engine,
) -> (Result<TraceCorpus, String>, Result<StoreFootprint, String>) {
    match engine.storage_summary().await {
        Ok(summary) => {
            let store = StoreFootprint::from_summary(&summary);
            (corpus_of(Ok(summary)), Ok(store))
        }
        Err(e) => {
            let msg = format!("read the trace corpus aggregate: {e}");
            (Err(msg.clone()), Err(msg))
        }
    }
}

/// The pure half of [`corpus_and_store`]: pick the trace-plane fields out of
/// persist's aggregate, and **keep a failure a failure.**
///
/// Split out from the `await` for one reason: this `map_err` is the single line
/// standing between #369 and the defect it exists to prevent. Fold the error
/// into an empty corpus here and the surface reports `never_admitted` on a node
/// whose database it could not open — a failed read rendering as a fact about
/// the node. Behind an `await` it is untestable and therefore ungated; in front
/// of one it is neither.
/// `pub(crate)` so [`crate::trace_plane_watch`] reads the corpus through the
/// SAME projection this surface does. A watch with its own field selection would
/// be a second answer to "when did a trace last arrive", and the log and the
/// surface would eventually disagree about one node.
pub(crate) fn corpus_of(
    summary: Result<
        ciris_persist::retention::StorageSummary,
        ciris_persist::retention::RetentionError,
    >,
) -> Result<TraceCorpus, String> {
    summary
        .map(|s| TraceCorpus {
            // v32.1.0 (CIRISPersist#606) — THIS node's admission instant, not
            // the producer's assertion. `newest_ts` is MAX(component timestamp)
            // from inside the signed CompleteTrace, so banding liveness on it
            // derived "arrival stopped" from a number supplied by the party that
            // stopped arriving: a slow producer clock pinned the plane dark
            // while it was being actively fed, a fast one pinned it green
            // through any silence. The caveat this surface used to carry
            // (TRACE_PRODUCER_ASSERTED_TS) is now retired rather than explained.
            last_admitted_at: s.trace_events.newest_admitted_at,
            rows: s.trace_events.rows,
        })
        .map_err(|e| format!("read the trace corpus aggregate: {e}"))
}

/// The reason the edge half is missing on a node composed without a transport.
pub const NO_EDGE_IN_PROCESS: &str =
    "no live Edge in this process — the carriage counters live on the Edge runtime, and a node \
     with no transport has never had one";

/// CIRISServer#356 — **the fold's accessor.** `ciris_server.node_state()` calls
/// this; see the pymethod docs for the contract.
///
/// Reaches the in-process persist engine + edge statics and the held delivery
/// runtime, exactly as [`crate::federation_delivery::analyze_consent_stance`]
/// does — the fold has ONE runtime and every in-process entry must use it (a
/// second `Runtime::new()` around the embedded Engine is the persist
/// dual-runtime rule, and the reentrancy panic that cost the fold-boot saga).
///
/// A MISSING EDGE IS NOT AN ERROR. An agent whose persist engine is up and
/// whose edge is not yet initialized gets the persist half plus an `unavailable`
/// edge half naming why — which is the reading that tells it what to do next.
/// Raising there would hand the fold nothing at exactly the moment it has a
/// question.
#[cfg(feature = "python")]
pub fn node_state_json(opts: &OperatorStateOptions) -> anyhow::Result<String> {
    use anyhow::Context as _;

    let engine: Arc<Engine> = ciris_persist::ffi::pyo3::current_rust_engine()
        .context("node_state: no in-process persist Engine")?;
    let (rt, _controller) = crate::federation_delivery::held()
        .context("node_state: federation delivery not started")?;
    let metrics = ciris_edge::current_edge()
        .map(|e| e.metrics())
        .map_err(|e| format!("{NO_EDGE_IN_PROCESS} (current_edge(): {e})"));
    // Same rule as the edge half: a fold with no HTTP ingest route mounted has
    // no gate to have refused anything, so the reading is `unreadable` and never
    // a clean zero.
    let refusals = crate::ingest_http::held();
    let view = rt.block_on(operator_state(
        &engine,
        metrics.as_ref().map_err(Clone::clone),
        refusals.as_ref(),
        opts,
    ));
    serde_json::to_string(&view).context("node_state: serialize")
}

// ─────────────────────────────────────────────────────────────────────────────
// The HTTP route.
// ─────────────────────────────────────────────────────────────────────────────

/// `GET /v1/node/state` — the composed operator surface.
pub const ROUTE: &str = "/v1/node/state";

#[derive(Clone)]
struct OperatorState {
    engine: Arc<Engine>,
    /// THIS node's federation `key_id` — the `self_key_id` persist's self-scoped
    /// signals are asked about. Passing it is what turns four `no_self_key`
    /// unknowns into real readings.
    node_key_id: String,
    /// The live edge's counter bag, or `None` when this node runs with no
    /// transport. `None` is rendered as `unavailable`, never as a clean zero.
    metrics: Option<ciris_edge::observability::EdgeMetrics>,
    /// The SAME ledger `ingest_http`'s route counts into, or `None` on a node
    /// with no HTTP ingest route. `None` renders `unreadable`.
    refusals: Option<crate::ingest_http::IngestRefusals>,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

/// Owner-authority gate, same spine as
/// [`crate::federation_admin`]: `SYSTEM_ADMIN` AND `FullAccess`, so neither a
/// role-permission drift nor a permission-only check can widen it.
async fn require_owner(st: &OperatorState, headers: &HeaderMap) -> Result<SessionCaller, Response> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "missing bearer session token",
        ));
    };
    match resolve_bearer(&st.engine, token).await {
        Ok(Some(caller))
            if caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) =>
        {
            Ok(caller)
        }
        Ok(Some(_)) => Err(err(
            StatusCode::FORBIDDEN,
            "the node operator surface requires the owner (SYSTEM_ADMIN) role",
        )),
        Ok(None) => Err(err(StatusCode::UNAUTHORIZED, "invalid or expired session")),
        Err(e) => Err(err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}"))),
    }
}

/// Query parameters — every one optional, every one a pass-through to persist.
#[derive(Debug, serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct StateQuery {
    /// Override the node's own key id for this read.
    self_key_id: Option<String>,
    /// Pin the trust-root walk to one root.
    root_key_id: Option<String>,
    /// RFC 3339. Pin the instant every clock-dependent band is a function of.
    now: Option<String>,
    /// The consent-promotion SLA window.
    sla_seconds: Option<u64>,
}

/// `GET /v1/node/state` (OWNER) — **how is this node?**
///
/// Owner-gated on the same three legs the rest of the owner surface uses: the
/// node must have a responsible party (owner-binding), the caller must hold an
/// owner session, and a DELEGATED caller must hold the `read_node_state` verb.
/// A read rather than a write, but not a public one: it names this node's peers
/// in the withhold ring, its overdue consent handles, and its quarantine
/// grounds.
async fn get_state(
    State(st): State<OperatorState>,
    headers: HeaderMap,
    Query(q): Query<StateQuery>,
) -> Response {
    if crate::auth::gate::require_owner_bound(&st.engine, &st.node_key_id)
        .await
        .is_err()
    {
        return err(
            StatusCode::FORBIDDEN,
            "this node has no responsible party (owner-binding) — the operator surface is \
             refused. Claim ownership first via POST /v1/setup/root.",
        );
    }
    match require_owner(&st, &headers).await {
        Ok(caller) => {
            if let Some(resp) = crate::auth::gate::require_verb(
                &caller,
                crate::auth::gate::CapabilityVerb::ReadNodeState,
            ) {
                return resp;
            }
        }
        Err(resp) => return resp,
    }

    let now = match q.now.as_deref() {
        None => None,
        Some(s) => match DateTime::parse_from_rfc3339(s) {
            Ok(t) => Some(t.with_timezone(&Utc)),
            Err(e) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    format!("bad `now` (RFC 3339): {e}"),
                )
            }
        },
    };
    let opts = OperatorStateOptions {
        // Default to THIS node — the whole surface is self-scoped, and leaving
        // it unset would report four `no_self_key` unknowns about a node that
        // knows perfectly well who it is.
        self_key_id: Some(q.self_key_id.unwrap_or_else(|| st.node_key_id.clone())),
        root_key_id: q.root_key_id,
        now,
        sla_seconds: q.sla_seconds,
    };
    let view = operator_state(
        &st.engine,
        st.metrics
            .as_ref()
            .ok_or_else(|| NO_EDGE_IN_PROCESS.to_owned()),
        st.refusals.as_ref(),
        &opts,
    )
    .await;
    (StatusCode::OK, Json(json!({ "data": view }))).into_response()
}

/// Mount `GET /v1/node/state`.
///
/// `metrics` is the live [`ciris_edge::observability::EdgeMetrics`] handle
/// (a cheap `Arc` clone off `Edge::metrics()`), or `None` on a node running
/// with no transport — in which case the carriage/receive halves render
/// `unavailable` rather than a clean zero.
///
/// `refusals` is the SAME [`crate::ingest_http::IngestRefusals`] handle passed to
/// [`crate::ingest_http::router`] (CIRISServer#370). A second ledger would be a
/// second answer to one question; `None` renders `unreadable`, never a clean
/// zero.
pub fn router(
    engine: Arc<Engine>,
    node_key_id: String,
    metrics: Option<ciris_edge::observability::EdgeMetrics>,
    refusals: Option<crate::ingest_http::IngestRefusals>,
) -> Router {
    Router::new()
        .route(ROUTE, axum::routing::get(get_state))
        .with_state(OperatorState {
            engine,
            node_key_id,
            metrics,
            refusals,
        })
}

/// **The trace plane's two halves, over ONE ledger** — the route that ADMITS
/// ([`crate::ingest_http::router`]) merged with the route that READS
/// ([`router`]), sharing a single [`crate::ingest_http::IngestRefusals`] handle
/// that this function mints and no caller can substitute.
///
/// # Why a composition function and not two merges
///
/// #370's whole reading rests on one sentence that used to live only in a
/// comment at the composition root: *"pass the SAME ledger to both."* A
/// composition that minted a second one would compile, serve, and pass every
/// test in this repo — the ingest route would count into a ledger nobody reads
/// while the operator surface reported a permanently `not_exercised` gate on a
/// node being flooded. That is the 2026-08-05 failure exactly: every component
/// correct, the composite silently dead, and no one owning the join.
///
/// The parameters here are the ones a HOST legitimately varies (which engine,
/// which node, whether there is an edge, which mesh-config plane). The ledger is
/// not among them, because there is no correct second answer to *"where does
/// this process record its refusals"* — so the type no longer offers one.
///
/// `metrics` is the live edge counter handle, or `None` on a node with no
/// transport (rendered `unavailable`, never a clean zero). `mesh_config` is the
/// live `mesh_config` reading gating the inbound trace plane (CIRISServer#365);
/// a composition running no plane passes
/// [`MeshConfigEffect::unwired`](crate::mesh_config_effect::MeshConfigEffect::unwired).
pub fn trace_plane_router(
    engine: Arc<Engine>,
    node_key_id: String,
    metrics: Option<ciris_edge::observability::EdgeMetrics>,
    mesh_config: crate::mesh_config_effect::MeshConfigEffect,
) -> Router {
    // THE one ledger. Minted here, handed to both halves, reachable by no other
    // route — `ingest_http::router` also publishes it to the process static the
    // in-process fold reads (`ingest_http::held`).
    let refusals = crate::ingest_http::IngestRefusals::new();
    router(
        Arc::clone(&engine),
        node_key_id,
        metrics,
        Some(refusals.clone()),
    )
    .merge(crate::ingest_http::router(engine, refusals, mesh_config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_edge::observability::{EdgeMetrics, RoundOutcome};
    use ciris_edge::replication::protocol::EnvelopeKind;

    /// A bundle from a live-but-idle process: rounds finished, nothing served,
    /// nothing withheld.
    fn idle() -> EdgeMetricsBundle {
        let m = EdgeMetrics::new();
        m.inc_round_outcome(RoundOutcome::Completed);
        m.snapshot()
    }

    /// A bundle from a process that has never run a round.
    fn fresh() -> EdgeMetricsBundle {
        EdgeMetrics::new().snapshot()
    }

    /// A bundle from a node that IS withholding, on `reason`.
    fn withholding(reason: WithholdReason) -> EdgeMetricsBundle {
        let m = EdgeMetrics::new();
        m.inc_round_outcome(RoundOutcome::Completed);
        m.inc_withhold(reason, "peer-1", "legA");
        m.snapshot()
    }

    #[test]
    fn withhold_class_covers_every_edge_reason_and_keeps_policy_apart_from_fault() {
        // The classification must be TOTAL over edge's taxonomy — the match in
        // `WithholdClass::of` has no catch-all, so this asserts the mapping
        // rather than the totality (the compiler asserts the totality).
        assert_eq!(
            WithholdClass::of(WithholdReason::RecipientNotInSendSet),
            WithholdClass::Policy,
            "consent working as designed is a policy withhold, not a fault"
        );
        assert_eq!(
            WithholdClass::of(WithholdReason::SendSetUnresolved),
            WithholdClass::Fault,
            "a failed send-set READ is not a statement that the peer is unconsented — \
             collapsing it into the policy class is the #425 Exhibit C defect exactly"
        );
        assert_eq!(
            WithholdClass::of(WithholdReason::ServeCapabilityMissing),
            WithholdClass::Policy
        );
        assert_eq!(
            WithholdClass::of(WithholdReason::ServeCapabilityReadError),
            WithholdClass::Fault
        );
        assert_eq!(
            WithholdClass::of(WithholdReason::RowHashUndecodable),
            WithholdClass::Integrity
        );
        // The two bands differ, so the two classes cannot render alike.
        assert_ne!(
            WithholdClass::Policy.band(),
            WithholdClass::Fault.band(),
            "a withhold this node chose and a withhold it suffered must not share a band"
        );
        assert_eq!(WithholdClass::Policy.band(), StateBand::Yellow);
        assert_eq!(WithholdClass::Integrity.band(), StateBand::Red);
    }

    #[test]
    fn carriage_zero_names_its_own_cause() {
        // THE defect this surface exists to prevent: three different facts, all
        // of which produce `withholds_total: 0`.
        assert_eq!(carriage_standing(None), CarriageStanding::Unreadable);
        assert_eq!(
            carriage_standing(Some(&fresh())),
            CarriageStanding::NotExercised
        );
        assert_eq!(carriage_standing(Some(&idle())), CarriageStanding::Idle);

        // ...and they do not share a token.
        let tokens: std::collections::HashSet<&str> =
            CarriageStanding::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(tokens.len(), CarriageStanding::ALL.len());

        // The three zero-arms: two unknown, one green — and the two unknowns
        // are DIFFERENT TOKENS on the one band. A band never replaces a token.
        assert_eq!(
            carriage_band(CarriageStanding::Unreadable, None),
            StateBand::Unknown
        );
        assert_eq!(
            carriage_band(CarriageStanding::NotExercised, None),
            StateBand::Unknown
        );
        assert_ne!(
            CarriageStanding::Unreadable.as_str(),
            CarriageStanding::NotExercised.as_str(),
            "'could not read' and 'nothing to report' must not render the same"
        );
        assert_eq!(
            carriage_band(CarriageStanding::Idle, None),
            StateBand::Green
        );
    }

    #[test]
    fn an_idle_node_and_a_withholding_node_do_not_render_the_same() {
        // The #433 property, carried up to the operator surface. Both nodes
        // served ZERO rows; only one of them chose to.
        let idle_v = carriage_json(Some(&idle()));
        let holding = withholding(WithholdReason::RecipientNotInSendSet);
        let holding_v = carriage_json(Some(&holding));

        assert_eq!(idle_v["served_total"], json!(0));
        assert_eq!(holding_v["served_total"], json!(0));
        assert_ne!(
            idle_v["standing"], holding_v["standing"],
            "identical zero carriage, different cause — the tokens must differ"
        );
        assert_eq!(idle_v["standing"], json!("idle"));
        assert_eq!(holding_v["standing"], json!("withholding"));
        assert_eq!(idle_v["withholds_total"], json!(0));
        assert_eq!(holding_v["withholds_total"], json!(1));
        assert_eq!(idle_v["band"], json!("green"));
        assert_eq!(holding_v["band"], json!("yellow"));
        assert_ne!(idle_v["explains"], holding_v["explains"]);

        // A FAULT-class withhold outranks a policy one, on the same count.
        let faulted = withholding(WithholdReason::TrustRootWalkError);
        let faulted_v = carriage_json(Some(&faulted));
        assert_eq!(faulted_v["withholds_total"], json!(1));
        assert_eq!(faulted_v["band"], json!("red"));
        assert_eq!(faulted_v["worst_withhold_class"], json!("fault"));

        // …and a node that MOVED rows is its own token again, green like idle
        // but not the same reading. `envelopes_sent_total` never saw these —
        // the replication plane's own counter is the one that does (#433).
        let m = EdgeMetrics::new();
        m.inc_round_outcome(RoundOutcome::Completed);
        m.inc_replication_served(EnvelopeKind::Attestation);
        let moving_v = carriage_json(Some(&m.snapshot()));
        assert_eq!(moving_v["standing"], json!("moving"));
        assert_eq!(moving_v["band"], json!("green"));
        assert_eq!(moving_v["served_total"], json!(1));
        assert_eq!(moving_v["served_by_kind"]["attestation"], json!(1));
        assert_ne!(
            moving_v["standing"], idle_v["standing"],
            "'we carried rows' and 'we had none to carry' are both green and \
             are not the same fact"
        );
    }

    /// A bundle from a node that APPLIED `n` rows of `kind` (edge's real
    /// `ApplyOutcome::Admitted` counter, CIRISEdge#457).
    fn applying(kind: EnvelopeKind, n: u64) -> EdgeMetricsBundle {
        let m = EdgeMetrics::new();
        m.inc_round_outcome(RoundOutcome::Completed);
        for _ in 0..n {
            m.inc_applied(kind);
        }
        m.snapshot()
    }

    /// A bundle from a node offered `n` rows of `kind` it ALREADY HELD.
    fn converged(kind: EnvelopeKind, n: u64) -> EdgeMetricsBundle {
        let m = EdgeMetrics::new();
        m.inc_round_outcome(RoundOutcome::Completed);
        for _ in 0..n {
            m.inc_duplicate(kind);
        }
        m.snapshot()
    }

    #[test]
    fn receive_zero_names_its_own_cause() {
        assert_eq!(receive_standing(None), ReceiveStanding::Unreadable);
        assert_eq!(
            receive_standing(Some(&fresh())),
            ReceiveStanding::NotExercised
        );
        assert_eq!(receive_standing(Some(&idle())), ReceiveStanding::Idle);

        let m = EdgeMetrics::new();
        m.inc_round_outcome(RoundOutcome::Completed);
        m.inc_apply_refusal_kind(EnvelopeKind::Key);
        m.inc_key_apply_refusal("pubkey_swap");
        let refusing = m.snapshot();
        assert_eq!(receive_standing(Some(&refusing)), ReceiveStanding::Refusing);

        assert_eq!(ReceiveStanding::Unreadable.band(), StateBand::Unknown);
        assert_eq!(ReceiveStanding::NotExercised.band(), StateBand::Unknown);
        assert_eq!(ReceiveStanding::Idle.band(), StateBand::Green);
        assert_eq!(ReceiveStanding::Converged.band(), StateBand::Green);
        assert_eq!(ReceiveStanding::Applying.band(), StateBand::Green);
        assert_eq!(ReceiveStanding::Refusing.band(), StateBand::Red);
        let tokens: std::collections::HashSet<&str> =
            ReceiveStanding::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(tokens.len(), ReceiveStanding::ALL.len());

        // The idle reading carries its denominators IN the payload.
        let v = receive_json(Some(&idle()));
        assert_eq!(v["note"]["id"], json!(RECEIVE_DECIDED_DENOMINATOR.0));
        assert_eq!(v["apply_refusals_total"], json!(0));
        assert_eq!(v["decided_total"], json!(0));
        assert_eq!(
            v["rounds_total"],
            json!(1),
            "a decided_total of 0 is only readable beside the count of rounds that \
             could have produced one"
        );
        // ...and the refusing one names the plane AND the policy token.
        let v = receive_json(Some(&refusing));
        assert_eq!(v["apply_refusals_by_kind"]["key"], json!(1));
        assert_eq!(v["key_apply_refusals_by_reason"]["pubkey_swap"], json!(1));
    }

    /// **CIRISEdge#457, the property the counter was filed for.** Three nodes,
    /// all reporting zero refusals, in three different conditions. Before the
    /// accepted-apply counters existed they were one token (`clean`) and one
    /// sentence; a `clean` node that had applied every row a peer sent and a
    /// `clean` node that had never been handed one were literally the same
    /// payload.
    #[test]
    fn nothing_offered_all_applied_and_all_duplicates_do_not_render_the_same() {
        let nothing = receive_json(Some(&idle()));
        let all_applied = receive_json(Some(&applying(EnvelopeKind::Attestation, 15)));
        let all_held = receive_json(Some(&converged(EnvelopeKind::Attestation, 15)));

        // All three are honestly zero-refusal and honestly green...
        for v in [&nothing, &all_applied, &all_held] {
            assert_eq!(v["apply_refusals_total"], json!(0));
            assert_eq!(v["band"], json!("green"));
        }
        // ...and no two of them share a token or a sentence.
        let tokens: std::collections::HashSet<&str> = [&nothing, &all_applied, &all_held]
            .iter()
            .map(|v| v["standing"].as_str().expect("standing"))
            .collect();
        assert_eq!(
            tokens.len(),
            3,
            "identical zero refusals, three different causes — the tokens must differ: \
             {tokens:?}"
        );
        assert_eq!(nothing["standing"], json!("idle"));
        assert_eq!(all_applied["standing"], json!("applying"));
        assert_eq!(all_held["standing"], json!("converged"));
        let sentences: std::collections::HashSet<&str> = [&nothing, &all_applied, &all_held]
            .iter()
            .map(|v| v["explains"]["id"].as_str().expect("explains id"))
            .collect();
        assert_eq!(sentences.len(), 3, "each arm needs its own sentence");

        // Every count sits beside its denominator, and the denominator SEPARATES
        // the arms rather than reading 0 for all three.
        assert_eq!(nothing["decided_total"], json!(0));
        assert_eq!(all_applied["decided_total"], json!(15));
        assert_eq!(all_held["decided_total"], json!(15));
        assert_eq!(all_applied["applied_total"], json!(15));
        assert_eq!(all_applied["applied_by_kind"]["attestation"], json!(15));
        assert_eq!(all_applied["duplicate_total"], json!(0));
        assert_eq!(all_held["duplicate_total"], json!(15));
        assert_eq!(all_held["duplicate_by_kind"]["attestation"], json!(15));
        assert_eq!(
            all_held["applied_total"],
            json!(0),
            "a duplicate is not an apply: it books the duplicate axis and only that one"
        );
    }

    /// A node that applied most of what it was offered and refused one row is
    /// `refusing` — and the counts beside the token say which number is large.
    /// Before #457 the `refusing` arm could report only the refusals, so
    /// "refused one of fifty" and "refused the only row it was ever offered"
    /// were the same reading.
    #[test]
    fn a_mostly_applying_node_that_refused_one_row_still_reads_refusing() {
        let m = EdgeMetrics::new();
        m.inc_round_outcome(RoundOutcome::Completed);
        for _ in 0..49 {
            m.inc_applied(EnvelopeKind::Attestation);
        }
        m.inc_apply_refusal_kind(EnvelopeKind::Key);
        let mostly = m.snapshot();

        assert_eq!(receive_standing(Some(&mostly)), ReceiveStanding::Refusing);
        let v = receive_json(Some(&mostly));
        assert_eq!(v["standing"], json!("refusing"));
        assert_eq!(v["band"], json!("red"));
        assert_eq!(v["applied_total"], json!(49));
        assert_eq!(v["apply_refusals_total"], json!(1));
        assert_eq!(
            v["decided_total"],
            json!(50),
            "the denominator is what makes 1 refusal readable as 1-in-50 rather \
             than as everything this node was ever offered"
        );

        // The same single refusal, with nothing applied beside it, is the OTHER
        // condition and the payload distinguishes them on the counts.
        let m = EdgeMetrics::new();
        m.inc_round_outcome(RoundOutcome::Completed);
        m.inc_apply_refusal_kind(EnvelopeKind::Key);
        let only = receive_json(Some(&m.snapshot()));
        assert_eq!(only["standing"], json!("refusing"));
        assert_eq!(only["apply_refusals_total"], json!(1));
        assert_ne!(
            only["decided_total"], v["decided_total"],
            "one refusal out of one and one out of fifty must not read the same"
        );
    }

    /// The denominator excludes what edge excludes, and says so on the wire.
    /// `ApplyOutcome::Deserialize` is booked by no counter in the bundle, so a
    /// `decided_total` that claimed to be "everything offered" would be a total
    /// silently missing a class — the same defect one level down.
    #[test]
    fn the_decided_denominator_is_the_sum_of_the_three_booked_outcomes() {
        let m = EdgeMetrics::new();
        m.inc_round_outcome(RoundOutcome::Completed);
        m.inc_applied(EnvelopeKind::Key);
        m.inc_applied(EnvelopeKind::Attestation);
        m.inc_duplicate(EnvelopeKind::Attestation);
        m.inc_apply_refusal_kind(EnvelopeKind::Key);
        // The Key plane's typed token axis mirrors a refusal ALREADY counted on
        // the kind axis (edge books both for one refused key), so it must not be
        // summed into the denominator a second time.
        m.inc_key_apply_refusal("pubkey_swap");
        let b = m.snapshot();

        assert_eq!(receive_decided_total(&b), 4);
        let v = receive_json(Some(&b));
        assert_eq!(v["decided_total"], json!(4));
        assert_eq!(v["applied_total"], json!(2));
        assert_eq!(v["duplicate_total"], json!(1));
        assert_eq!(v["apply_refusals_total"], json!(1));
        assert_eq!(v["key_apply_refusals_by_reason"]["pubkey_swap"], json!(1));
        assert_eq!(
            v["decided_total"].as_u64().expect("decided_total"),
            v["applied_total"].as_u64().expect("applied")
                + v["duplicate_total"].as_u64().expect("duplicate")
                + v["apply_refusals_total"].as_u64().expect("refusals"),
            "the denominator must be the sum of exactly the three rendered axes — \
             double-counting the Key token axis would inflate it by every refused key"
        );
    }

    #[test]
    fn every_message_is_an_id_text_pair_never_a_bare_sentence() {
        let v = carriage_json(Some(&withholding(WithholdReason::RowNotSerializable)));
        let explains = &v["explains"];
        assert!(explains["id"].is_string(), "{explains}");
        assert!(explains["text"].is_string(), "{explains}");
        for c in v["class_explains"].as_array().expect("class_explains") {
            assert!(c["message"]["id"].is_string());
            assert!(c["message"]["text"].is_string());
        }
        // Every id in the closed sets is unique and namespaced.
        let mut ids: Vec<&str> = Vec::new();
        ids.extend(CarriageStanding::ALL.iter().map(|s| s.message().0));
        ids.extend(ReceiveStanding::ALL.iter().map(|s| s.message().0));
        ids.extend(WithholdClass::ALL.iter().map(|c| c.message().0));
        ids.extend(PeerQuotaCause::ALL.iter().map(|c| c.message().0));
        ids.extend(StateBand::ALL.iter().map(|b| headline(*b).0));
        ids.extend(
            TrustRootStanding::ALL
                .iter()
                .map(|s| trust_root_message(*s).0),
        );
        ids.extend(
            [
                None,
                Some(KeyStatementStanding::Stands),
                Some(KeyStatementStanding::SuspectAfterBound),
                Some(KeyStatementStanding::SuspectUnbounded),
            ]
            .into_iter()
            .map(|s| key_statement_message(s).0),
        );
        ids.extend(
            [
                None,
                Some(QuarantineState::NotQuarantined),
                Some(QuarantineState::Released),
                Some(QuarantineState::Withheld),
            ]
            .into_iter()
            .map(|s| quarantine_message(s).0),
        );
        ids.extend(
            [None, Some(0usize), Some(3)]
                .into_iter()
                .map(|o| consent_sla_message(o).0),
        );
        ids.extend(
            [
                (None, false),
                (Some(DrillFreshness::Green), true),
                (Some(DrillFreshness::Yellow), true),
                (Some(DrillFreshness::Red), false),
                (Some(DrillFreshness::Red), true),
            ]
            .into_iter()
            .map(|(f, d)| drill_narrowing(f, d).1 .0),
        );
        ids.push(RECEIVE_DECIDED_DENOMINATOR.0);
        ids.push(PROCESS_LOCAL_NOTE.0);
        ids.push(NODE_UNAVAILABLE.0);
        ids.push(EDGE_UNAVAILABLE.0);
        let unique: std::collections::HashSet<&&str> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "duplicate message id: {ids:?}");
        for id in ids {
            assert!(id.starts_with("operator."), "{id} is not namespaced");
        }
    }

    #[test]
    fn a_never_drilled_root_and_a_stale_one_share_a_band_and_not_a_token() {
        // persist bands both RED on purpose and says so: the distinction is
        // carried by `last_drill_at` being None rather than by a fourth
        // variant. A surface that renders only the band therefore DESTROYS a
        // distinction the substrate deliberately preserved — "this root has
        // never been drilled" and "this root was drilled 200 days ago" are the
        // two ends of #356's sharpest signal.
        let (never, never_msg) = drill_narrowing(Some(DrillFreshness::Red), false);
        let (stale, stale_msg) = drill_narrowing(Some(DrillFreshness::Red), true);
        assert_eq!(never, "never_drilled");
        assert_eq!(stale, "stale");
        assert_ne!(never, stale, "one band, two facts — the tokens must differ");
        assert_ne!(never_msg.0, stale_msg.0);

        // ...and neither is the third zero: no root walked at all.
        let (none, none_msg) = drill_narrowing(None, false);
        assert_eq!(none, "no_root_walked");
        assert_ne!(none_msg.0, never_msg.0);
        // The green/yellow arms are unambiguous and keep their own tokens.
        assert_eq!(
            drill_narrowing(Some(DrillFreshness::Green), true).0,
            "green"
        );
        assert_eq!(
            drill_narrowing(Some(DrillFreshness::Yellow), true).0,
            "yellow"
        );
        let tokens: std::collections::HashSet<&str> = [
            drill_narrowing(None, false).0,
            drill_narrowing(Some(DrillFreshness::Green), true).0,
            drill_narrowing(Some(DrillFreshness::Yellow), true).0,
            never,
            stale,
        ]
        .into_iter()
        .collect();
        assert_eq!(tokens.len(), 5, "a drill token collapsed: {tokens:?}");
    }

    #[test]
    fn the_peer_quota_zeroes_do_not_share_a_token() {
        // persist bands a fresh quota `unknown` rather than green; this names
        // WHICH unknown, because "this backend has no quota" and "no peer write
        // has been charged yet" are different things to do about.
        let tokens: std::collections::HashSet<&str> =
            PeerQuotaCause::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(tokens.len(), PeerQuotaCause::ALL.len());
        let ids: std::collections::HashSet<&str> =
            PeerQuotaCause::ALL.iter().map(|c| c.message().0).collect();
        assert_eq!(ids.len(), PeerQuotaCause::ALL.len());
        assert_ne!(
            PeerQuotaCause::NoQuota.as_str(),
            PeerQuotaCause::NotExercised.as_str(),
        );
    }

    #[test]
    fn band_token_round_trips_through_persists_closed_set() {
        for b in StateBand::ALL {
            assert_eq!(band_of(b.as_str()), *b);
        }
        // An unrecognised token is UNKNOWN, never green.
        assert_eq!(band_of("nonsense"), StateBand::Unknown);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CIRISServer#369 — the trace plane.
    // ─────────────────────────────────────────────────────────────────────────

    /// The incident clock, so every assertion below is a function of injected
    /// time rather than of when the suite ran.
    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s)
            .expect("rfc3339 fixture")
            .with_timezone(&Utc)
    }

    fn corpus(last: Option<&str>, rows: u64) -> TraceCorpus {
        TraceCorpus {
            last_admitted_at: last.map(at),
            rows,
        }
    }

    /// **THE TEST THAT MATTERS MOST.** `FSD/RCA_INGEST_REJECTION_2026-08-05.md`:
    /// the last trace was admitted at `2026-08-03T23:30`, the condition was
    /// found at `2026-08-05T13:55`, and nothing in between turned "nothing is
    /// arriving" into a signal.
    ///
    /// The gate is not "does a stale corpus read red" — it is that a stale
    /// corpus and an UNREADABLE one do not read the same. An instrument that
    /// cannot tell the incident from a node it merely failed to ask would not
    /// have caught this: the RCA's third and most expensive instrument failure
    /// is exactly a check whose no-output read as no-problem.
    #[test]
    fn the_2026_08_05_incident_reads_red_and_an_unreadable_corpus_does_not() {
        // The real instants, unrounded.
        let last_admitted = "2026-08-03T23:30:00Z";
        let found_at = at("2026-08-05T13:55:00Z");

        let incident = trace_plane_standing(Ok(corpus(Some(last_admitted), 120_000)), found_at);
        assert_eq!(
            incident,
            TracePlaneStanding::Dark,
            "a plane whose newest trace is 38 hours old is the 2026-08-05 condition and must be \
             DARK"
        );
        assert_eq!(incident.band(), StateBand::Red);

        // The RCA's own wording — "a plane that has admitted nothing for two
        // days must be RED" — at exactly two days.
        let two_days = trace_plane_standing(
            Ok(corpus(Some(last_admitted), 120_000)),
            at("2026-08-05T23:30:00Z"),
        );
        assert_eq!(two_days, TracePlaneStanding::Dark);
        assert_eq!(two_days.band(), StateBand::Red);

        // A node that could not READ the corpus. Same absence of arrivals in
        // the payload, categorically different fact.
        let unreadable = trace_plane_standing(Err("sqlite: database is locked"), found_at);
        assert_eq!(unreadable, TracePlaneStanding::Unreadable);
        assert_eq!(unreadable.band(), StateBand::Unknown);

        // THE discrimination. Neither the token nor the band may collapse.
        assert_ne!(
            incident, unreadable,
            "the incident and an unread corpus must not be the same value"
        );
        assert_ne!(
            incident.band(),
            unreadable.band(),
            "a dark plane is a known bad; an unread corpus is an unasked question. Same display, \
             no detection."
        );
        assert_ne!(incident.message().0, unreadable.message().0);

        // ...and neither is a healthy quiet node. This is the third value the
        // gate has to keep apart: a node that admitted a trace an hour ago is
        // GREEN, and if the incident could not be told from THAT, the reading
        // would have been silent on 2026-08-04 exactly as the node was.
        let healthy =
            trace_plane_standing(Ok(corpus(Some("2026-08-05T13:00:00Z"), 120_000)), found_at);
        assert_eq!(healthy, TracePlaneStanding::Live);
        assert_eq!(healthy.band(), StateBand::Green);
        assert_ne!(healthy.band(), incident.band());
        assert_ne!(healthy.band(), unreadable.band());

        // WOULD IT HAVE FIRED ON 2026-08-04? The plane went silent at
        // 2026-08-03T23:30. Walk the clock forward and pin when each band
        // starts, because "it eventually goes red" is not a detection claim.
        assert_eq!(
            trace_plane_standing(
                Ok(corpus(Some(last_admitted), 120_000)),
                at("2026-08-04T05:29:00Z")
            ),
            TracePlaneStanding::Live,
            "still inside the green window at +5h59m"
        );
        assert_eq!(
            trace_plane_standing(
                Ok(corpus(Some(last_admitted), 120_000)),
                at("2026-08-04T05:31:00Z")
            ),
            TracePlaneStanding::Quiet,
            "yellow from +6h — 2026-08-04, the morning after"
        );
        assert_eq!(
            trace_plane_standing(
                Ok(corpus(Some(last_admitted), 120_000)),
                at("2026-08-04T23:31:00Z")
            ),
            TracePlaneStanding::Dark,
            "RED from +24h, which is 2026-08-04 — fourteen hours before a human looked"
        );
    }

    /// A FAILED CORPUS READ MUST STAY A FAILURE all the way from persist's
    /// error to the surface's token. This is the one line where #369 could be
    /// undone silently: folding the error into an empty corpus would report
    /// `never_admitted` — a confident statement about a node whose database
    /// could not be opened.
    #[test]
    fn a_failed_corpus_read_never_becomes_an_empty_corpus() {
        use ciris_persist::retention::{RetentionError, StorageSummary, TableUsage};

        let err = corpus_of(Err(RetentionError::Backend(
            "sqlite: database is locked".into(),
        )));
        assert!(
            err.is_err(),
            "a backend failure must not be mapped to a corpus"
        );
        assert!(
            err.as_ref()
                .unwrap_err()
                .contains("sqlite: database is locked"),
            "the reason must survive to the wire: {err:?}"
        );
        assert_eq!(
            trace_plane_standing(
                err.as_ref().map(|c| *c).map_err(String::as_str),
                at("2026-08-05T13:55:00Z")
            ),
            TracePlaneStanding::Unreadable
        );

        // ...and the happy path picks the trace-plane fields, not another
        // table's. `trace_llm_calls` is deliberately populated with a DIFFERENT
        // instant here: a field-selection slip would otherwise be invisible.
        let last = at("2026-08-03T23:30:00Z");
        let summary = StorageSummary {
            trace_events: TableUsage {
                bytes: 0,
                rows: 120_000,
                oldest_ts: Some(at("2026-01-01T00:00:00Z")),
                newest_ts: Some(last),
                newest_admitted_at: Some(last),
            },
            trace_llm_calls: TableUsage {
                bytes: 0,
                rows: 7,
                oldest_ts: None,
                newest_ts: Some(at("2026-08-05T13:00:00Z")),
                newest_admitted_at: Some(at("2026-08-05T13:00:00Z")),
            },
            detection_events: TableUsage::default(),
            audit_log: TableUsage::default(),
            edge_outbound_queue: TableUsage::default(),
            federation_keys: TableUsage::default(),
            total_disk_bytes: 101 * 1024 * 1024,
        };
        let ok = corpus_of(Ok(summary)).expect("a readable summary is a readable corpus");
        assert_eq!(
            ok.last_admitted_at,
            Some(last),
            "the reading must come from trace_events, not from a neighbouring table"
        );
        assert_eq!(ok.rows, 120_000);
        assert_eq!(
            trace_plane_standing(Ok(ok), at("2026-08-05T13:55:00Z")),
            TracePlaneStanding::Dark
        );
    }

    #[test]
    fn the_trace_plane_zeroes_do_not_share_a_token() {
        let now = at("2026-08-05T13:55:00Z");

        // Three ways to have no recent arrival, three tokens, two bands.
        let unreadable = trace_plane_standing(Err("backend down"), now);
        let never = trace_plane_standing(Ok(corpus(None, 0)), now);
        let dark = trace_plane_standing(Ok(corpus(Some("2026-08-03T23:30:00Z"), 9)), now);
        assert_eq!(unreadable, TracePlaneStanding::Unreadable);
        assert_eq!(never, TracePlaneStanding::NeverAdmitted);
        assert_eq!(dark, TracePlaneStanding::Dark);
        assert_ne!(
            unreadable.as_str(),
            never.as_str(),
            "'could not read the corpus' and 'the corpus is empty' must not render the same"
        );
        assert_ne!(never.as_str(), dark.as_str());
        // The two unknowns share a band and NOT a token — a band never replaces
        // a token, the rule the drill narrowing already enforces.
        assert_eq!(unreadable.band(), StateBand::Unknown);
        assert_eq!(never.band(), StateBand::Unknown);
        assert_ne!(never.band(), dark.band());

        // A fresh node's empty corpus is UNKNOWN and never GREEN: an untested
        // zero is not a healthy one.
        assert_ne!(never.band(), StateBand::Green);

        // Every token and every message id is distinct across the closed set.
        let tokens: std::collections::HashSet<&str> =
            TracePlaneStanding::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(tokens.len(), TracePlaneStanding::ALL.len());
        let ids: std::collections::HashSet<&str> = TracePlaneStanding::ALL
            .iter()
            .map(|s| s.message().0)
            .collect();
        assert_eq!(ids.len(), TracePlaneStanding::ALL.len());
    }

    #[test]
    fn a_future_dated_corpus_is_called_out_rather_than_banded_green() {
        let now = at("2026-08-05T13:55:00Z");
        // Ordinary skew stays green — the reading must not flap on NTP jitter.
        assert_eq!(
            trace_plane_standing(Ok(corpus(Some("2026-08-05T13:56:00Z"), 5)), now),
            TracePlaneStanding::Live
        );
        // A producer stamping tomorrow would otherwise pin this green forever,
        // which is a dead plane wearing a healthy colour.
        let skewed = trace_plane_standing(Ok(corpus(Some("2026-08-06T13:55:00Z"), 5)), now);
        assert_eq!(skewed, TracePlaneStanding::FutureDated);
        assert_ne!(
            skewed.band(),
            StateBand::Green,
            "a future-dated newest row is a statement about a clock, not evidence of arrival"
        );
        assert_eq!(skewed.band(), StateBand::Unknown);
    }

    #[test]
    fn the_trace_plane_band_edges_are_the_documented_ones() {
        let last = at("2026-08-01T00:00:00Z");
        let c = TraceCorpus {
            last_admitted_at: Some(last),
            rows: 1,
        };
        let g = chrono::Duration::hours(TRACE_GREEN_MAX_HOURS);
        let y = chrono::Duration::hours(TRACE_YELLOW_MAX_HOURS);
        assert_eq!(
            trace_plane_standing(Ok(c), last + g - chrono::Duration::seconds(1)),
            TracePlaneStanding::Live
        );
        assert_eq!(
            trace_plane_standing(Ok(c), last + g),
            TracePlaneStanding::Quiet,
            "the green edge is EXCLUSIVE, matching persist's DrillFreshness::of"
        );
        assert_eq!(
            trace_plane_standing(Ok(c), last + y - chrono::Duration::seconds(1)),
            TracePlaneStanding::Quiet
        );
        assert_eq!(
            trace_plane_standing(Ok(c), last + y),
            TracePlaneStanding::Dark
        );

        // The thresholds ride ON the wire. A band whose edges live only in the
        // source is a datum again — the reader cannot tell six hours from six
        // days without leaving the payload.
        let v = trace_plane_json(Ok(&c), last + y);
        assert_eq!(v["bands"]["green_max_hours"], json!(TRACE_GREEN_MAX_HOURS));
        assert_eq!(
            v["bands"]["yellow_max_hours"],
            json!(TRACE_YELLOW_MAX_HOURS)
        );
        assert_eq!(v["band"], json!("red"));
        assert_eq!(v["standing"], json!("dark"));
        assert_eq!(v["age_seconds"], json!(y.num_seconds()));
        assert_eq!(v["note"]["id"], json!(TRACE_PRODUCER_ASSERTED_TS.0));

        // The unreadable arm carries the REASON, not merely the absence.
        let err = "sqlite: database is locked".to_owned();
        let v = trace_plane_json(Err(&err), last);
        assert_eq!(v["standing"], json!("unreadable"));
        assert_eq!(v["band"], json!("unknown"));
        assert_eq!(v["detail"], json!(err));
        assert!(
            v.get("last_admitted_at").is_none(),
            "an unread corpus must not render a last_admitted_at at all — a null there would be \
             indistinguishable from an empty corpus"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CIRISServer#370 — the ingest refusal reading.
    // ─────────────────────────────────────────────────────────────────────────

    use crate::ingest_http::IngestRefusals;
    use ciris_persist::ingest::IngestError;
    use ciris_persist::verify::Error as VerifyError;

    /// A ledger fed `n` unknown-key refusals spread over `signers`, plus
    /// `unattributed` refusals that name nobody.
    fn ledger(
        n: usize,
        signers: &[&str],
        unattributed: usize,
        accepts: usize,
    ) -> IngestRefusalBundle {
        let t0 = at("2026-08-05T13:00:00Z");
        let l = IngestRefusals::started_at(t0);
        for _ in 0..accepts {
            l.observe_accept_at(t0);
        }
        for i in 0..n {
            let who = signers[i % signers.len()];
            l.observe_refusal_at(
                t0 + chrono::Duration::milliseconds(i as i64),
                &IngestError::Verify(VerifyError::UnknownKey(who.to_owned())),
            );
        }
        for i in 0..unattributed {
            l.observe_refusal_at(
                t0 + chrono::Duration::milliseconds(i as i64),
                &IngestError::Verify(VerifyError::HybridRequired),
            );
        }
        l.snapshot_at(t0 + chrono::Duration::minutes(1))
    }

    /// **THE ZERO-DISTINCTIONS GATE.** `distinct_signers == 0` trivially
    /// satisfies "a small, stable identity set", so a stuck-producer test
    /// written as `distinct <= MAX` alone reports a stuck producer that does not
    /// exist and names nobody. It is also not clean and not ordinary churn.
    #[test]
    fn zero_distinct_signers_is_its_own_reading_and_never_a_stuck_producer() {
        // A sustained flood in which NOT ONE refusal named a signer: every one
        // failed before there was an identity to record.
        let b = ledger(0, &[], 400, 0);
        assert_eq!(b.refusals_in_window, 400);
        assert_eq!(b.distinct_signers_in_window, 0);
        assert_eq!(b.unattributed_in_window, 400);
        assert!(
            b.refusals_in_window >= INGEST_SUSTAINED_MIN
                && b.distinct_signers_in_window <= INGEST_STABLE_SIGNER_MAX,
            "the fixture must actually satisfy the naive stuck-producer predicate, or this test \
             proves nothing"
        );
        let standing = ingest_standing(Some(&b));
        assert_eq!(
            standing,
            IngestStanding::Unattributed,
            "a sustained flood that names NOBODY must not be reported as a stuck producer — \
             there is no producer to go fix and `top_signers` would be empty"
        );
        assert_ne!(standing, IngestStanding::StuckProducer);
        assert_ne!(standing, IngestStanding::Clean);
        assert!(
            ingest_json(Some(&b))["top_signers"]
                .as_array()
                .expect("top_signers")
                .is_empty(),
            "the reading that names nobody must render nobody"
        );
    }

    /// The RCA's own numbers: 8,631 refusals a day from two identities is a
    /// stuck producer; the same rate from thousands is a probe. **Opposite
    /// responses, identical counter** — which is why the distinct-signer
    /// dimension is load-bearing and not decoration.
    #[test]
    fn the_same_refusal_rate_from_two_identities_and_from_thousands_do_not_render_the_same() {
        // 360/h ≈ the incident's 6/min, from the two real key ids.
        let stuck = ledger(360, &["agent-55fe8d181727", "agent-1ee871dcf31b"], 0, 0);
        // The SAME count, spread across a wide identity set.
        let wide_ids: Vec<String> = (0..360).map(|i| format!("probe-{i:04}")).collect();
        let wide_refs: Vec<&str> = wide_ids.iter().map(String::as_str).collect();
        let probe = ledger(360, &wide_refs, 0, 0);

        assert_eq!(
            stuck.refusals_in_window, probe.refusals_in_window,
            "the two fixtures MUST have identical counts, or this proves nothing about the \
             counter being insufficient"
        );
        assert_eq!(stuck.distinct_signers_in_window, 2);
        assert_eq!(probe.distinct_signers_in_window, 360);

        assert_eq!(ingest_standing(Some(&stuck)), IngestStanding::StuckProducer);
        assert_eq!(ingest_standing(Some(&probe)), IngestStanding::Background);
        assert_ne!(
            ingest_standing(Some(&stuck)).as_str(),
            ingest_standing(Some(&probe)).as_str(),
            "one counter, two opposite conditions — the identity dimension is what separates them"
        );
        assert_eq!(
            IngestStanding::StuckProducer.band(),
            StateBand::Red,
            "a producer that cannot self-correct is actionable, even though every refusal was \
             correct"
        );
        assert_ne!(
            IngestStanding::StuckProducer.band(),
            IngestStanding::Background.band()
        );

        // ...and the stuck reading NAMES who to go fix, worst first.
        let v = ingest_json(Some(&stuck));
        assert_eq!(v["standing"], json!("stuck_producer"));
        assert_eq!(v["distinct_signers"], json!(2));
        assert_eq!(v["refusals_in_window"], json!(360));
        let top = v["top_signers"].as_array().expect("top_signers");
        assert_eq!(top.len(), 2);
        let named: std::collections::HashSet<&str> = top
            .iter()
            .map(|t| t["signer_id"].as_str().expect("signer_id"))
            .collect();
        assert!(named.contains("agent-55fe8d181727"), "{v}");
        assert!(named.contains("agent-1ee871dcf31b"), "{v}");
        // The probe's list is CAPPED — naming 360 ids on a gauge is not a
        // reading, and the distinct count beside it carries the width.
        let v = ingest_json(Some(&probe));
        assert_eq!(
            v["top_signers"].as_array().expect("top_signers").len(),
            crate::ingest_http::REFUSAL_TOP_N
        );
        assert_eq!(v["distinct_signers"], json!(360));
    }

    #[test]
    fn ingest_zero_names_its_own_cause() {
        // Four readings that all report zero refusals in the window.
        assert_eq!(ingest_standing(None), IngestStanding::Unreadable);
        assert_eq!(
            ingest_standing(Some(&ledger(0, &[], 0, 0))),
            IngestStanding::NotExercised,
            "nothing offered at all is an UNTESTED zero, not a clean one"
        );
        assert_eq!(
            ingest_standing(Some(&ledger(0, &[], 0, 12))),
            IngestStanding::Clean,
            "batches were offered and admitted — counting the ACCEPTS is what makes this \
             distinguishable from 'nothing was offered'"
        );

        // ...and they do not share a token or a message.
        let tokens: std::collections::HashSet<&str> =
            IngestStanding::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(tokens.len(), IngestStanding::ALL.len());
        let ids: std::collections::HashSet<&str> =
            IngestStanding::ALL.iter().map(|s| s.message().0).collect();
        assert_eq!(ids.len(), IngestStanding::ALL.len());
        assert_ne!(
            IngestStanding::Unreadable.as_str(),
            IngestStanding::NotExercised.as_str(),
            "'we could not ask the ledger' and 'nothing was ever offered' must not render alike"
        );
        assert_eq!(IngestStanding::Unreadable.band(), StateBand::Unknown);
        assert_eq!(IngestStanding::NotExercised.band(), StateBand::Unknown);
        assert_eq!(IngestStanding::Clean.band(), StateBand::Green);

        // The unreadable arm renders NO counts at all. A zero there would be
        // a manufactured clean reading — the RCA's false clean, in JSON.
        let v = ingest_json(None);
        assert_eq!(v["standing"], json!("unreadable"));
        assert!(v.get("refusals_in_window").is_none(), "{v}");
        assert_eq!(v["unavailable"]["id"], json!(INGEST_UNAVAILABLE.0));

        // ...and the OTHER way to be unreadable: a ledger that IS present and
        // whose lock could not be taken. It arrives as a bundle full of zeroes
        // carrying `readable: false`, and the surface must read that flag
        // BEFORE it reads a single count — otherwise a failed read renders
        // exactly like a node that was offered nothing, which is the RCA's
        // false clean.
        let poisoned = IngestRefusalBundle::unreadable(at("2026-08-05T13:55:00Z"));
        assert_eq!(poisoned.refusals_in_window, 0);
        assert_eq!(poisoned.accepted_total, 0);
        assert_eq!(poisoned.refused_total, 0);
        assert_eq!(
            ingest_standing(Some(&poisoned)),
            IngestStanding::Unreadable,
            "a bundle whose every count is a placeholder must NOT be narrowed by those counts — \
             `not_exercised` here would be a statement about a node derived from a failed read"
        );
        let v = ingest_json(Some(&poisoned));
        assert_eq!(v["standing"], json!("unreadable"));
        assert_eq!(v["band"], json!("unknown"));
        assert!(
            v.get("refusals_in_window").is_none(),
            "the placeholder zeroes must not reach the wire at all: {v}"
        );
        assert!(v.get("accepted_total").is_none(), "{v}");
        assert_eq!(v["unavailable"]["id"], json!(INGEST_UNAVAILABLE.0));

        // ...and the whole-payload accounting agrees with itself about it. A
        // ledger that is HELD but could not be READ contributed nothing, so it
        // must not appear in `composed_from` while `present` calls it absent —
        // one payload cannot answer the same question two ways.
        let composed = compose(
            Sources {
                node: Err("no node state in this fixture".into()),
                edge: Err("no edge in this fixture".into()),
                trace: Err("sqlite: database is locked".into()),
                store: Err("not exercised by this case".to_string()),
                ingest: Some(&poisoned),
            },
            at("2026-08-05T13:55:00Z"),
        );
        assert_eq!(
            composed["sources"]["ingest_refusals"]["present"],
            json!(false)
        );
        assert!(
            !composed["composed_from"]
                .as_array()
                .expect("composed_from")
                .contains(&json!("ingest_refusals")),
            "an unread ledger composed nothing: {composed}"
        );
        assert!(
            composed["unknown"]
                .as_array()
                .expect("unknown")
                .contains(&json!("ingest")),
            "{composed}"
        );
    }

    #[test]
    fn a_low_refusal_rate_is_background_and_does_not_cry_stuck_producer() {
        // Two identities, but nowhere near sustained: a stale client, not a
        // stuck one. An instrument that fires on this trains people to ignore it.
        let quiet = ledger(3, &["agent-55fe8d181727", "agent-1ee871dcf31b"], 0, 40);
        assert!(quiet.refusals_in_window < INGEST_SUSTAINED_MIN);
        assert_eq!(ingest_standing(Some(&quiet)), IngestStanding::Background);
        assert_eq!(IngestStanding::Background.band(), StateBand::Yellow);
    }

    /// **UNATTRIBUTABLE VOLUME MUST NOT CARRY A NAMED PRODUCER OVER THE BAR.**
    ///
    /// A scanner posting malformed bodies produces refusals that name nobody. If
    /// the sustained-rate test counted the whole window while the identity test
    /// counted only the attributed slice, one stale client with a single
    /// unknown-key refusal would ride 399 malformed ones into `stuck_producer` —
    /// and `top_signers` would then name that client as the thing to go fix,
    /// against a rate it contributed 1/400th of.
    ///
    /// Naming the wrong producer is worse than naming none: it is an actionable
    /// reading pointing at the wrong party, and the party it points at is the
    /// one whose logs will show nothing wrong.
    #[test]
    fn a_flood_that_names_nobody_does_not_make_a_stuck_producer_of_one_stale_client() {
        // 399 refusals that failed before there was an identity to record, plus
        // ONE that named a signer.
        let mixed = ledger(1, &["agent-55fe8d181727"], 399, 0);
        assert_eq!(mixed.refusals_in_window, 400);
        assert_eq!(mixed.unattributed_in_window, 399);
        assert_eq!(mixed.distinct_signers_in_window, 1);
        assert!(
            mixed.refusals_in_window >= INGEST_SUSTAINED_MIN
                && mixed.distinct_signers_in_window <= INGEST_STABLE_SIGNER_MAX,
            "the fixture must satisfy the AXIS-MIXED predicate, or this test proves nothing"
        );

        assert_eq!(
            ingest_standing(Some(&mixed)),
            IngestStanding::Background,
            "the named signer was refused ONCE — the volume is unattributable and there is no \
             producer stuck in a retry loop"
        );

        // The same one signer, now actually sustained on its own, IS stuck —
        // so the discrimination is about the attributed rate and not about the
        // presence of unattributed noise beside it.
        let really_stuck = ledger(120, &["agent-55fe8d181727"], 399, 0);
        assert_eq!(really_stuck.unattributed_in_window, 399);
        assert_eq!(
            ingest_standing(Some(&really_stuck)),
            IngestStanding::StuckProducer,
            "unattributed noise beside a genuinely sustained producer must not SUPPRESS the \
             reading either"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The composed view.
    // ─────────────────────────────────────────────────────────────────────────

    /// The whole 2026-08-05 shape in ONE read, and the two neighbouring shapes
    /// it must not be confused with. `trace_plane` says the plane is dead;
    /// `ingest` says why. Neither alone distinguishes "a producer is being
    /// correctly refused" from "nothing is reaching this node at all".
    #[test]
    fn the_incident_and_a_silent_pipe_are_both_dark_and_are_not_the_same_read() {
        let now = at("2026-08-05T13:55:00Z");
        let dark = corpus(Some("2026-08-03T23:30:00Z"), 120_000);
        let stuck = ledger(360, &["agent-55fe8d181727", "agent-1ee871dcf31b"], 0, 4);
        let silent = ledger(0, &[], 0, 0);

        let incident = compose(
            Sources {
                node: Err("no node state in this fixture".into()),
                edge: Err("no edge in this fixture".into()),
                trace: Ok(&dark),
                store: Err("not exercised by this case".to_string()),
                ingest: Some(&stuck),
            },
            now,
        );
        let pipe = compose(
            Sources {
                node: Err("no node state in this fixture".into()),
                edge: Err("no edge in this fixture".into()),
                trace: Ok(&dark),
                store: Err("not exercised by this case".to_string()),
                ingest: Some(&silent),
            },
            now,
        );

        // Both planes are dark, and that reading is identical...
        assert_eq!(incident["trace_plane"]["standing"], json!("dark"));
        assert_eq!(pipe["trace_plane"]["standing"], json!("dark"));
        assert_eq!(incident["trace_plane"], pipe["trace_plane"]);
        // ...and the CAUSE is not.
        assert_eq!(incident["ingest"]["standing"], json!("stuck_producer"));
        assert_eq!(pipe["ingest"]["standing"], json!("not_exercised"));
        assert_ne!(
            incident["ingest"]["standing"], pipe["ingest"]["standing"],
            "a dark plane with a stuck producer and a dark plane with nothing arriving are \
             different faults with different owners"
        );

        // The roll-up carries the worst of them, and neither reading is hidden.
        assert_eq!(incident["band"], json!("red"));

        // **A DARK PLANE MUST REDDEN THE HEADLINE BY ITSELF.** With a clean
        // ingest and no other source readable, the trace plane is the ONLY
        // contributor that can be red — so if it does not reach the roll-up, a
        // node whose whole purpose has stopped reports `unknown` and an
        // operator scanning headlines walks past it. That is #369 restated as
        // arithmetic.
        let clean = ledger(0, &[], 0, 20);
        let alone = compose(
            Sources {
                node: Err("no node state in this fixture".into()),
                edge: Err("no edge in this fixture".into()),
                trace: Ok(&dark),
                store: Err("not exercised by this case".to_string()),
                ingest: Some(&clean),
            },
            now,
        );
        assert_eq!(alone["ingest"]["band"], json!("green"));
        assert_eq!(
            alone["band"],
            json!("red"),
            "the trace plane must be able to turn the headline red on its own: {alone}"
        );
        assert!(
            incident["composed_from"]
                .as_array()
                .expect("composed_from")
                .contains(&json!("trace_corpus")),
            "{incident}"
        );
        // The silent-pipe read has an UNKNOWN ingest, and an unknown is named
        // individually so a red headline cannot hide it.
        let unknown = pipe["unknown"].as_array().expect("unknown");
        assert!(unknown.contains(&json!("ingest")), "{pipe}");

        // An unreadable corpus is a THIRD read, and it is not either of these.
        let blind = compose(
            Sources {
                node: Err("no node state in this fixture".into()),
                edge: Err("no edge in this fixture".into()),
                trace: Err("sqlite: database is locked".into()),
                store: Err("not exercised by this case".to_string()),
                ingest: Some(&stuck),
            },
            now,
        );
        assert_eq!(blind["trace_plane"]["standing"], json!("unreadable"));
        assert_ne!(
            blind["trace_plane"]["standing"],
            incident["trace_plane"]["standing"]
        );
        assert!(
            blind["unknown"]
                .as_array()
                .expect("unknown")
                .contains(&json!("trace_plane")),
            "an unread corpus must be NAMED as an unknown, not merely banded: {blind}"
        );
        assert_eq!(
            blind["sources"]["trace_corpus"]["present"],
            json!(false),
            "{blind}"
        );
    }

    /// Both new readings are localizable pairs, their ids are unique against
    /// every OTHER id on the surface, and both are declared in the volatility
    /// section under the right kind.
    #[test]
    fn the_new_readings_are_localizable_and_declare_their_own_volatility() {
        let now = at("2026-08-05T13:55:00Z");
        let dark = corpus(Some("2026-08-03T23:30:00Z"), 120_000);
        let stuck = ledger(360, &["agent-55fe8d181727", "agent-1ee871dcf31b"], 0, 4);

        for v in [trace_plane_json(Ok(&dark), now), ingest_json(Some(&stuck))] {
            assert!(v["explains"]["id"].is_string(), "{v}");
            assert!(v["explains"]["text"].is_string(), "{v}");
            assert!(v["note"]["id"].is_string(), "{v}");
            assert!(v["note"]["text"].is_string(), "{v}");
        }

        let mut ids: Vec<&str> = Vec::new();
        ids.extend(TracePlaneStanding::ALL.iter().map(|s| s.message().0));
        ids.extend(IngestStanding::ALL.iter().map(|s| s.message().0));
        // ...against the ids that were already here.
        ids.extend(CarriageStanding::ALL.iter().map(|s| s.message().0));
        ids.extend(ReceiveStanding::ALL.iter().map(|s| s.message().0));
        ids.extend(WithholdClass::ALL.iter().map(|c| c.message().0));
        ids.extend(PeerQuotaCause::ALL.iter().map(|c| c.message().0));
        ids.push(TRACE_PRODUCER_ASSERTED_TS.0);
        ids.push(TRACE_UNAVAILABLE.0);
        ids.push(INGEST_HTTP_PATH_ONLY.0);
        ids.push(INGEST_UNAVAILABLE.0);
        ids.push(CLOCK_DEPENDENT_LOCAL_NOTE.0);
        ids.push(PROCESS_LOCAL_NOTE.0);
        let unique: std::collections::HashSet<&&str> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "duplicate message id: {ids:?}");
        for id in ids {
            assert!(id.starts_with("operator."), "{id} is not namespaced");
        }

        // The volatility declaration: the ingest counters are process-local
        // (they reset on restart), and the trace band is clock-dependent but
        // computed HERE — not on persist's verbatim list.
        let v = compose(
            Sources {
                node: Err("no node state in this fixture".into()),
                edge: Err("no edge in this fixture".into()),
                trace: Ok(&dark),
                store: Err("not exercised by this case".to_string()),
                ingest: Some(&stuck),
            },
            now,
        );
        assert!(
            PROCESS_LOCAL_FIELDS.contains(&"ingest"),
            "a process-local counter that does not declare itself is the field an operator will \
             read as durable node state"
        );
        assert_eq!(
            v["volatility"]["process_local"]["fields"],
            json!(PROCESS_LOCAL_FIELDS)
        );
        assert_eq!(
            v["volatility"]["clock_dependent_local"]["fields"],
            json!(["trace_plane"])
        );
        // persist's own list stays persist's — the trace plane must NOT have
        // been folded into it, or the payload would claim persist computes a
        // band this module computes.
        assert!(
            !v["volatility"]["clock_dependent"]
                .as_array()
                .expect("clock_dependent")
                .contains(&json!("trace_plane")),
            "{v}"
        );
    }
}
