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
//! - [`ReceiveStanding`] — `unreadable` / `not_exercised` / `clean` / `refusing`,
//!   for the same reason on the other direction.
//! - `trust_root.drill` — persist bands a NEVER-drilled root and a 200-day-stale
//!   root identically `Red` **on purpose** (its doc says the distinction is
//!   carried by `last_drill_at` being `None`). So this surface reads that field
//!   and emits `never_drilled` vs `stale`: two tokens, one band.
//! - `peer_quota` — `no_quota` / `not_exercised` / `clean`, because
//!   `slot_denials: 0` on a fresh process is untested, not healthy (persist
//!   already bands this `unknown`; this surface names WHICH unknown).
//! - `consent_sla` — `none_overdue` vs `unreadable`. `Some(0)` and `None` are
//!   different facts and persist keeps them apart; so does this.
//! - Each SOURCE, whole: a missing source is `unavailable` with a reason, never
//!   an absent key and never a healthy default.
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
            | WithholdReason::RecipientCapabilityRestriction => Self::Policy,
            // Fail-closed on a failed read, or a missing local wiring input.
            WithholdReason::LocalIdentityMissing
            | WithholdReason::SendSetUnresolved
            | WithholdReason::ServeCapabilityReadError
            | WithholdReason::TrustRootWalkError => Self::Fault,
            // Local state that cannot be put on the wire at all.
            WithholdReason::EnvelopeUnfetchable
            | WithholdReason::RowNotSerializable
            | WithholdReason::RowHashUndecodable => Self::Integrity,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveStanding {
    /// The counters could not be read at all.
    Unreadable,
    /// No replication round has finished on this process, so nothing has been
    /// offered to the apply path. Untested, not clean.
    NotExercised,
    /// Rounds finished and no offered row was refused. See
    /// [`RECEIVE_NO_ACCEPTED_COUNTER`] for what this reading still cannot
    /// separate — the edge bundle counts refusals, not accepted applies.
    Clean,
    /// At least one offered row was refused.
    Refusing,
}

impl ReceiveStanding {
    /// The stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::NotExercised => "not_exercised",
            Self::Clean => "clean",
            Self::Refusing => "refusing",
        }
    }

    /// Every variant — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::Unreadable,
        Self::NotExercised,
        Self::Clean,
        Self::Refusing,
    ];

    /// The band. `unreadable` and `not_exercised` are both `unknown` — and they
    /// are DIFFERENT TOKENS on that one band, which is the whole discipline: a
    /// band never replaces a token, it only accompanies one.
    #[must_use]
    pub const fn band(self) -> StateBand {
        match self {
            Self::Unreadable | Self::NotExercised => StateBand::Unknown,
            Self::Clean => StateBand::Green,
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
            Self::Clean => (
                "operator.receive.clean",
                "No row a peer offered has been refused on this process.",
            ),
            Self::Refusing => (
                "operator.receive.refusing",
                "This node refused rows its peers offered. `apply_refusals_by_kind` names the \
                 plane; `key_apply_refusals_by_reason` names the policy token that refused a key.",
            ),
        }
    }
}

/// The limit of a clean receive reading, carried IN the payload rather than
/// only in these docs — the same discipline persist's `PEER_QUOTA_NOTE` uses,
/// so a consumer that renders the struct without reading the source still shows
/// it.
pub const RECEIVE_NO_ACCEPTED_COUNTER: Msg = (
    "operator.receive.no_accepted_counter",
    "The substrate counts apply REFUSALS, not accepted applies. A clean reading therefore cannot \
     separate 'everything offered was applied' from 'nothing was offered' — read `rounds_total` \
     and the peer's own surface to tell those apart.",
);

/// The carriage/receive counters' volatility, stated in the payload.
pub const PROCESS_LOCAL_NOTE: Msg = (
    "operator.volatility.process_local",
    "The carriage and receive counters are process-local and cumulative since this process \
     started. They reset on restart, differ between processes serving one node, and are stored \
     nowhere. They are a gauge of this process, not a ledger of this node.",
);

/// Which fields [`PROCESS_LOCAL_NOTE`] governs.
pub const PROCESS_LOCAL_FIELDS: &[&str] = &["carriage", "receive"];

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
}

/// The producer of each half, named on the wire so an operator chasing a value
/// knows which repo computes it.
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

/// Narrow a zero apply-refusal count to its cause.
#[must_use]
pub fn receive_standing(bundle: Option<&EdgeMetricsBundle>) -> ReceiveStanding {
    let Some(b) = bundle else {
        return ReceiveStanding::Unreadable;
    };
    if total(&b.apply_refusals_by_kind) > 0 || total(&b.key_apply_refusals_by_reason) > 0 {
        return ReceiveStanding::Refusing;
    }
    if total(&b.replication_round_outcomes_total) == 0 {
        return ReceiveStanding::NotExercised;
    }
    ReceiveStanding::Clean
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
    out.insert("note".into(), msg(RECEIVE_NO_ACCEPTED_COUNTER));

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
    out.insert("apply_refusals_total".into(), json!(refusals_total));
    out.insert("apply_refusals_by_kind".into(), Value::Object(by_kind));
    out.insert(
        "key_apply_refusals_by_reason".into(),
        Value::Object(by_reason),
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
        match state.peer_quota.observation {
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
    let band = node_band.worse(carriage_band_v).worse(receive_band_v);

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

    let composed_from: Vec<&str> = [node.map(|_| "node_state"), edge.map(|_| "edge_metrics")]
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

    json!({
        "as_of": as_of,
        "source_locale": SOURCE_LOCALE,
        "band": band.as_str(),
        "headline": msg(headline(band)),
        "unknown": unknown,
        "composed_from": composed_from,
        "sources": { "node_state": node_source, "edge_metrics": edge_source },
        "node": node,
        "node_explains": node.map(node_explains),
        "carriage": carriage,
        "receive": receive,
        "volatility": {
            // persist's own list, verbatim — bands that move on elapsed time
            // alone, with no state change and no new row.
            "clock_dependent": node.map(|s| s.clock_dependent.clone()).unwrap_or_default(),
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

    let bundle = metrics.map(ciris_edge::observability::EdgeMetrics::snapshot);
    compose(
        Sources {
            node: node.as_ref().map_err(std::string::ToString::to_string),
            edge: bundle.as_ref().map_err(Clone::clone),
        },
        now,
    )
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
    let view = rt.block_on(operator_state(
        &engine,
        metrics.as_ref().map_err(Clone::clone),
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
pub fn router(
    engine: Arc<Engine>,
    node_key_id: String,
    metrics: Option<ciris_edge::observability::EdgeMetrics>,
) -> Router {
    Router::new()
        .route(ROUTE, axum::routing::get(get_state))
        .with_state(OperatorState {
            engine,
            node_key_id,
            metrics,
        })
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

    #[test]
    fn receive_zero_names_its_own_cause() {
        assert_eq!(receive_standing(None), ReceiveStanding::Unreadable);
        assert_eq!(
            receive_standing(Some(&fresh())),
            ReceiveStanding::NotExercised
        );
        assert_eq!(receive_standing(Some(&idle())), ReceiveStanding::Clean);

        let m = EdgeMetrics::new();
        m.inc_round_outcome(RoundOutcome::Completed);
        m.inc_apply_refusal_kind(EnvelopeKind::Key);
        m.inc_key_apply_refusal("pubkey_swap");
        let refusing = m.snapshot();
        assert_eq!(receive_standing(Some(&refusing)), ReceiveStanding::Refusing);

        assert_eq!(ReceiveStanding::Unreadable.band(), StateBand::Unknown);
        assert_eq!(ReceiveStanding::NotExercised.band(), StateBand::Unknown);
        assert_eq!(ReceiveStanding::Clean.band(), StateBand::Green);
        assert_eq!(ReceiveStanding::Refusing.band(), StateBand::Red);
        let tokens: std::collections::HashSet<&str> =
            ReceiveStanding::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(tokens.len(), ReceiveStanding::ALL.len());

        // The clean reading carries its own limit IN the payload.
        let v = receive_json(Some(&idle()));
        assert_eq!(v["note"]["id"], json!(RECEIVE_NO_ACCEPTED_COUNTER.0));
        assert_eq!(v["apply_refusals_total"], json!(0));
        // ...and the refusing one names the plane AND the policy token.
        let v = receive_json(Some(&refusing));
        assert_eq!(v["apply_refusals_by_kind"]["key"], json!(1));
        assert_eq!(v["key_apply_refusals_by_reason"]["pubkey_swap"], json!(1));
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
        ids.push(RECEIVE_NO_ACCEPTED_COUNTER.0);
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
}
