//! **The commons surface** (CIRISServer#367, adoption debt #361) — the routes
//! that let a community raise, see, escalate and dismiss an objection on
//! persist's [`reverse_quorum`] plane.
//!
//! ```text
//! GET  /v1/commons/standing      read     the fold's live answer about ONE action
//! POST /v1/commons/objections    1-of-N   raise the brake
//! POST /v1/commons/ballots       1 sig    answer a question the duty-holders left open
//! POST /v1/commons/dismissals    m-of-n   lift a brake
//! ```
//!
//! # Why this surface and not one more `/v1/admin/*` route
//!
//! Consent protects the private plane **structurally**: no signed directed
//! grant, no delivery. The commons — federation-scoped, publicly readable rows
//! — gets nothing from that, because in the commons everyone has already
//! consented to look (FSD §1). Communities are meant to police themselves, and
//! [`reverse_quorum`] is the mechanism. `/v1/admin/*` is authority acting **on**
//! the commons; this is the commons acting on itself, so it is its own surface
//! with its own paths.
//!
//! Every primitive called here shipped in persist v25.0.0 / v26.0.0 against
//! issues this repo filed, and had **zero callers here** — #361's seventh and
//! last. An unbuilt plane refuses; a plane with no consumer *confirms*.
//!
//! # The asymmetry is persist's, and this module encodes NONE of it
//!
//! > **1-of-N to protect, m-of-n to undo.**
//!
//! One objection raises the brake; `m` distinct roster members dismiss it;
//! silence is its own arm; after the steward deadline the escalated threshold
//! counts **respondents, not the roster**; and
//! [`ESCALATION_RESPONDENT_FLOOR`] is an absolute floor no policy string can
//! lower. Every one of those numbers is decided by
//! [`resolve_reverse_quorum`] and rendered here verbatim. **There is no
//! threshold arithmetic in this file** — no `m`, no strict majority, no window
//! comparison, no respondent count. A second implementation of a rule is a
//! second answer that can disagree with the first, which is this repo's
//! dominant defect class ("one name, two axes"), and it is exactly the
//! discipline that kept [`crate::mesh_config_surface`] free of a durability
//! predicate.
//!
//! `tests/commons_surface.rs::property_2_*` scans this module's own source for
//! that arithmetic, so the claim is checked rather than asserted.
//!
//! # Distinct zeroes are the point, not a nicety
//!
//! [`CommonsStanding`] separates **eight** facts that all render as "nothing is
//! stopping this action": the plane could not be read, the action is not a row
//! this node holds, the cohort does not resolve here, the cohort declares no
//! reverse-quorum policy, nobody objected, somebody objected and the window is
//! open, the window closed under the threshold, and the action is reversed.
//! This repo has arrived at that discipline five times, and on 2026-08-05 a
//! trace plane sat dark for 71 hours partly because a zero could not be told
//! from an absence (`FSD/RCA_INGEST_REJECTION_2026-08-05.md`). *A `0` because
//! nobody spoke and a `0` because nothing could be read must not render the
//! same.*
//!
//! The escalation axis keeps its own zeroes because persist keeps them:
//! [`StewardTierStanding`] is a SEPARATE enum from [`ReverseQuorumStanding`],
//! and `Silent` / `Overruled` / `NoDutyHolders` are three different diagnoses
//! of the same escalation. They are passed through by
//! [`StewardTierStanding::as_str`] and never collapsed.
//!
//! # Gating, and the axis it is NOT on
//!
//! Reads take the delegatable [`CapabilityVerb::ReadNodeState`] — an owner may
//! hand a monitoring agent "watch what this commons is deciding". Writes take
//! the never-delegatable [`CapabilityVerb::Wipe`], as
//! [`crate::admin_ops`] and [`crate::mesh_config_surface`] do.
//!
//! That is deliberately **not** a threshold. The session gate answers *may this
//! bearer speak with this node's federation key*; the reverse quorum answers
//! *how many members does this act take*. Two questions, two mechanisms —
//! fusing them is how a surface ends up re-pricing a substrate rule. The
//! substrate still prices an objection at one member and a dismissal at m-of-n,
//! whatever this node's session policy is.
//!
//! # Operator-facing strings
//!
//! Every human-readable string is a `{id, text}` pair, like
//! [`crate::peer::consent_disclosure_json`]. Refusal tokens come from persist's
//! own [`ObjectionRefusalReason::as_str`] and the message ids are DERIVED from
//! them, so the localizable id set cannot drift from the token set and no
//! variant list is written down here.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[cfg(doc)]
use ciris_persist::federation::reverse_quorum::StewardTierStanding;
use ciris_persist::federation::reverse_quorum::{
    ballot_envelope, dismissal_envelope, objection_envelope, record_objection,
    record_objection_ballot, record_objection_dismissal, resolve_reverse_quorum, DismissalDecision,
    ObjectionEscalation, ObjectionOutcome, ReverseQuorumFold, ReverseQuorumStanding,
    DIMENSION_DISMISSAL, DIMENSION_OBJECTION, DIMENSION_OVERRULED, DIMENSION_UPHELD,
    ESCALATION_RESPONDENT_FLOOR, OBJECTION_THRESHOLD,
};
use ciris_persist::federation::types::{attestation_type, cohort_scope, Attestation, ScrubSig};
use ciris_persist::federation::Cohort;
use ciris_persist::prelude::Engine;

use crate::auth::gate::CapabilityVerb;
use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::{resolve_bearer, SessionCaller};

// ═══════════════════════════════════════════════════════════════════════════
//  Routes + vocabulary
// ═══════════════════════════════════════════════════════════════════════════

/// `GET` — the reverse quorum's live answer about one commons action.
pub const ROUTE_STANDING: &str = "/v1/commons/standing";
/// `POST` — raise an objection. One member is enough.
pub const ROUTE_OBJECT: &str = "/v1/commons/objections";
/// `POST` — cast an upholding / overruling ballot on an objection.
pub const ROUTE_BALLOT: &str = "/v1/commons/ballots";
/// `POST` — dismiss an objection. Costs the cohort's m-of-n.
pub const ROUTE_DISMISS: &str = "/v1/commons/dismissals";

/// The locale the `text` half of every `{id, text}` pair is written in.
pub const SOURCE_LOCALE: &str = "en";

/// A localizable string: a stable id plus its English source.
fn m(id: &str, text: &str) -> Value {
    json!({ "id": id, "text": text })
}

fn err(code: StatusCode, token: &str, id: &str, text: String) -> Response {
    (
        code,
        Json(json!({
            "refused": true,
            "refusal": token,
            "source_locale": SOURCE_LOCALE,
            "message": m(id, &text),
        })),
    )
        .into_response()
}

fn refusal(code: StatusCode, token: &str, id: &str, text: &str) -> Response {
    err(code, token, id, text.to_owned())
}

// ═══════════════════════════════════════════════════════════════════════════
//  State + gates
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone)]
struct CommonsState {
    engine: Arc<Engine>,
    /// THIS node's federation `key_id` — the member whose voice every write
    /// here carries, and the node whose owner-binding the serve floor checks.
    node_key_id: String,
}

/// Owner-authority gate — the [`crate::federation_admin`] spine verbatim:
/// `resolve_bearer → SessionCaller → SYSTEM_ADMIN + FullAccess`, both, so
/// neither a role-permission drift nor a permission-only check can widen who
/// may speak with this node's key in someone's commons.
async fn require_owner(st: &CommonsState, headers: &HeaderMap) -> Result<SessionCaller, Response> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return Err(refusal(
            StatusCode::UNAUTHORIZED,
            "session_absent",
            "commons_surface.refusal.session_absent",
            "No session token was presented. The commons surface is owner-only.",
        ));
    };
    match resolve_bearer(&st.engine, token).await {
        Ok(Some(caller))
            if caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) =>
        {
            Ok(caller)
        }
        Ok(Some(_)) => Err(refusal(
            StatusCode::FORBIDDEN,
            "not_owner",
            "commons_surface.refusal.not_owner",
            "The commons surface requires the owner (SYSTEM_ADMIN) role.",
        )),
        Ok(None) => Err(refusal(
            StatusCode::UNAUTHORIZED,
            "session_invalid",
            "commons_surface.refusal.session_invalid",
            "That session is invalid or expired.",
        )),
        Err(e) => Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "commons_surface.refusal.store_unavailable",
            format!("The substrate could not be read: {e}"),
        )),
    }
}

/// The gate stack: serve-only floor → owner session → the capability verb.
///
/// See the module doc for why the verb layer is not, and must not become, a
/// second threshold.
async fn gate(
    st: &CommonsState,
    headers: &HeaderMap,
    verb: CapabilityVerb,
) -> Result<(), Response> {
    if crate::auth::gate::require_owner_bound(&st.engine, &st.node_key_id)
        .await
        .is_err()
    {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "node_unowned",
            "commons_surface.refusal.node_unowned",
            "This node has no responsible party (owner-binding), so it neither reads nor speaks \
             in anyone's commons on their behalf. Claim ownership first.",
        ));
    }
    let caller = require_owner(st, headers).await?;
    if let Some(resp) = crate::auth::gate::require_verb(&caller, verb) {
        return Err(resp);
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
//  Distinct zeroes — the standing
// ═══════════════════════════════════════════════════════════════════════════

/// **What a quiet commons MEANS.** Eight facts that all look like "nothing is
/// stopping this action", separated by token.
///
/// Four of them are zeroes and none shares a value with another:
/// [`Self::Unreadable`] (we could not read the objections),
/// [`Self::ActionUnknown`] (there is no such row here to object to),
/// [`Self::CohortUnknown`] (that group does not resolve on this node), and
/// [`Self::NotGoverned`] (this community has no reverse-quorum policy). A fifth
/// — [`Self::Quiet`] — is the honest *"no objection has been raised"*, which is
/// a statement about a plane that WAS read.
///
/// Derived by [`Self::of`] as a pure PROJECTION of persist's
/// [`ReverseQuorumStanding`] plus `distinct_objectors`. No threshold is
/// compared here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonsStanding {
    /// The plane could not be read — the substrate refused a read, so the
    /// objections are **unknown**, not absent.
    Unreadable,
    /// The named action is not an attestation this node holds. Nothing can be
    /// objected to and nothing can be folded.
    ActionUnknown,
    /// The named `(cohort, cohort_key_id)` does not resolve to a group this
    /// node holds, so there is no roster and no declaration to read.
    CohortUnknown,
    /// The cohort resolves and declares no `reverse_quorum:*` protocol. This
    /// commons has not adopted the plane at all — which is NOT "nobody
    /// objected".
    NotGoverned,
    /// Governed, read cleanly, and **zero** objections counted. The window may
    /// still be open — `window_open` and `window_closes_at` say which.
    Quiet,
    /// Governed; at least one objection counted; the window is still OPEN and
    /// the reversal threshold is not met. The action stands FOR NOW.
    Objected,
    /// Governed; at least one objection counted; the window CLOSED under the
    /// threshold. The action was objected to and survived.
    Stood,
    /// The reversal threshold is met. Every node holding these rows folds to
    /// this same answer.
    Reversed,
}

impl CommonsStanding {
    /// The stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::ActionUnknown => "action_unknown",
            Self::CohortUnknown => "cohort_unknown",
            Self::NotGoverned => "not_governed",
            Self::Quiet => "quiet",
            Self::Objected => "objected",
            Self::Stood => "stood",
            Self::Reversed => "reversed",
        }
    }

    /// Every variant, in declaration order — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::Unreadable,
        Self::ActionUnknown,
        Self::CohortUnknown,
        Self::NotGoverned,
        Self::Quiet,
        Self::Objected,
        Self::Stood,
        Self::Reversed,
    ];

    /// The operator-facing explanation.
    #[must_use]
    fn message(self) -> Value {
        match self {
            Self::Unreadable => m(
                "commons_surface.standing.unreadable",
                "The objection plane could not be read here. This is NOT a statement that nobody \
                 objected — the objections are unknown, not absent.",
            ),
            Self::ActionUnknown => m(
                "commons_surface.standing.action_unknown",
                "This node holds no such action. An objection names a row, and there is no row \
                 here to name.",
            ),
            Self::CohortUnknown => m(
                "commons_surface.standing.cohort_unknown",
                "That cohort does not resolve on this node, so it has no roster and no \
                 declaration this node can read. Authority must come from local verified state.",
            ),
            Self::NotGoverned => m(
                "commons_surface.standing.not_governed",
                "This community declares no reverse-quorum policy, so the objection plane does \
                 not apply to its commons at all. That is different from nobody having objected.",
            ),
            Self::Quiet => m(
                "commons_surface.standing.quiet",
                "The plane was read and no objection has been raised against this action.",
            ),
            Self::Objected => m(
                "commons_surface.standing.objected",
                "At least one member has objected and the window is still open. The action \
                 stands for now; one more objection may be all it takes.",
            ),
            Self::Stood => m(
                "commons_surface.standing.stood",
                "The window closed below the reversal threshold. This action was objected to and \
                 stands.",
            ),
            Self::Reversed => m(
                "commons_surface.standing.reversed",
                "Enough distinct members objected inside the window. Every node holding these \
                 rows folds to this same answer, with no coordination.",
            ),
        }
    }

    /// Read the standing off persist's fold. **A pure projection** — the only
    /// inputs are the substrate's own `standing` arm and its own objector
    /// count, never a threshold recomputed here.
    ///
    /// `None` is the unreadable arm and is the only way to reach it: an error
    /// must never arrive here as an empty fold.
    #[must_use]
    fn of(fold: Option<&ReverseQuorumFold>) -> Self {
        let Some(f) = fold else {
            return Self::Unreadable;
        };
        match (f.standing, f.distinct_objectors) {
            (ReverseQuorumStanding::NotGoverned, _) => Self::NotGoverned,
            (ReverseQuorumStanding::Reversed, _) => Self::Reversed,
            (ReverseQuorumStanding::WindowOpen | ReverseQuorumStanding::Stood, 0) => Self::Quiet,
            (ReverseQuorumStanding::WindowOpen, _) => Self::Objected,
            (ReverseQuorumStanding::Stood, _) => Self::Stood,
        }
    }
}

/// **Did the question ever reach the commons, and what came back?**
///
/// A SEPARATE axis from [`CommonsStanding`] because persist keeps it separate:
/// [`StewardTierStanding`] answers *did the people carrying the duty answer?*
/// and [`ReverseQuorumStanding`] answers *does the action stand?*. Fusing them
/// would put "the action stands" and "nobody looked" in one value, which is the
/// whole of what CIRISPersist#591 exists to prevent.
///
/// Four arms, three of which are zeroes with different causes: nothing to
/// escalate, the deadline has not passed, escalation is open, and the tier was
/// never declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationStanding {
    /// The cohort's `consensus_protocol` declares no `+escalate:` tier. There
    /// is no deadline to be silent past and no escalated pool — every policy
    /// string written before persist v26.0.0 means exactly this.
    NotAdopted,
    /// A tier IS declared and there is no live objection to escalate. Nobody
    /// was silent, because nothing was asked.
    NothingToEscalate,
    /// A tier is declared, objections are live, and NO objection has escalation
    /// open: the duty-holders may still answer, or they upheld in time. The
    /// healthy in-progress state — deliberately not a zero.
    Awaiting,
    /// At least one objection's escalation is OPEN — the duty-holders were
    /// silent, overruled, or there were none. The commons may act on its own
    /// silence, priced against the respondents rather than the roster.
    Open,
}

impl EscalationStanding {
    /// The stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAdopted => "not_adopted",
            Self::NothingToEscalate => "nothing_to_escalate",
            Self::Awaiting => "awaiting",
            Self::Open => "open",
        }
    }

    /// Every variant, in declaration order — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::NotAdopted,
        Self::NothingToEscalate,
        Self::Awaiting,
        Self::Open,
    ];

    #[must_use]
    fn message(self) -> Value {
        match self {
            Self::NotAdopted => m(
                "commons_surface.escalation.not_adopted",
                "This community declared no steward tier, so there is no moderator deadline and \
                 no escalation. Silence changes nothing here.",
            ),
            Self::NothingToEscalate => m(
                "commons_surface.escalation.nothing_to_escalate",
                "A steward tier is declared and no live objection is waiting on it. Nobody was \
                 silent, because nothing was asked.",
            ),
            Self::Awaiting => m(
                "commons_surface.escalation.awaiting",
                "The appointed moderators may still answer, or they have already ruled in time. \
                 Escalation has not opened.",
            ),
            Self::Open => m(
                "commons_surface.escalation.open",
                "The duty-holders did not answer in time, and the decision has passed to those \
                 who did. The threshold now counts RESPONDENTS rather than the whole roster — \
                 which is what lets a quiet community still resolve — floored so that \
                 'reachable' never degrades to 'one person decides'.",
            ),
        }
    }

    /// Read it off persist's own per-objection records. **The open test is
    /// [`StewardTierStanding::escalates`] — persist's one predicate** — never
    /// a re-match of its arms here.
    #[must_use]
    fn of(fold: &ReverseQuorumFold) -> Self {
        if fold.steward_deadline.is_none() {
            return Self::NotAdopted;
        }
        if fold.escalation.is_empty() {
            return Self::NothingToEscalate;
        }
        if fold.escalation.iter().any(|e| e.steward.escalates()) {
            Self::Open
        } else {
            Self::Awaiting
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Rendering — persist's numbers, this node's ids
// ═══════════════════════════════════════════════════════════════════════════

/// One objection's steward / escalation record, rendered.
///
/// Every number is persist's. The two enum tokens are persist's `as_str`
/// verbatim and their message ids are DERIVED from those tokens, so the id set
/// cannot drift from the token set and no arm list is written down here.
fn escalation_json(e: &ObjectionEscalation) -> Value {
    json!({
        "objection_id": e.objection_id,
        "steward": e.steward.as_str(),
        "steward_message": m(
            &format!("commons_surface.steward.{}", e.steward.as_str()),
            "The steward tier's answer on this objection. The token names which of the six \
             arms; the substrate owns that vocabulary.",
        ),
        "escalation_open": e.steward.escalates(),
        "outcome": e.outcome.as_str(),
        "outcome_message": m(
            &format!("commons_surface.outcome.{}", e.outcome.as_str()),
            "What the commons said once it was asked. The token names which of the four arms; \
             the substrate owns that vocabulary.",
        ),
        "duty_holders": e.duty_holders,
        "steward_ruling_required": e.steward_ruling_required,
        // THE property #591 is about: the escalated denominator is the people
        // who answered, not the roster.
        "respondents": e.respondents,
        "required": e.required,
        "uphold_ballots": e.uphold_ballots,
        "overrule_ballots": e.overrule_ballots,
        "counted_ballot_ids": e.counted_ballot_ids,
    })
}

/// The full standing response over one action.
fn standing_json(
    fold: Option<&ReverseQuorumFold>,
    cohort: Cohort,
    cohort_key_id: &str,
    action_id: &str,
    action: Option<&Attestation>,
    now: DateTime<Utc>,
    forced: Option<CommonsStanding>,
) -> Value {
    let standing = forced.unwrap_or_else(|| CommonsStanding::of(fold));
    let mut out = json!({
        "source_locale": SOURCE_LOCALE,
        "generated_at": now.to_rfc3339(),
        "cohort": cohort.as_str(),
        "cohort_key_id": cohort_key_id,
        "action_id": action_id,
        "standing": standing.as_str(),
        "standing_message": standing.message(),
        // The asymmetry, named on every response so a UI never has to infer it.
        "objection_threshold": OBJECTION_THRESHOLD,
        "escalation_respondent_floor": ESCALATION_RESPONDENT_FLOOR,
        "asymmetry_message": m(
            "commons_surface.asymmetry",
            "One member raises the brake; the cohort must agree to lift it. Raising protection \
             is unconditional and costs one signature; undoing somebody else's costs the \
             cohort's own threshold, and the escalated undo can never fall below an absolute \
             floor no policy string may lower.",
        ),
        "dimensions": {
            "objection": DIMENSION_OBJECTION,
            "dismissal": DIMENSION_DISMISSAL,
            "uphold": DIMENSION_UPHELD,
            "overrule": DIMENSION_OVERRULED,
        },
    });
    if let Some(a) = action {
        out["action_author"] = json!(a.attesting_key_id);
        out["action_asserted_at"] = json!(a.asserted_at.to_rfc3339());
    }
    match fold {
        // The unreadable / absent arms carry NO counts. A null is the honest
        // answer; a zero would be a claim nobody made.
        None => {
            out["fold"] = Value::Null;
            out["escalation"] = Value::Null;
        }
        Some(f) => {
            out["fold"] = json!({
                "substrate_standing": match f.standing {
                    ReverseQuorumStanding::NotGoverned => "not_governed",
                    ReverseQuorumStanding::WindowOpen => "window_open",
                    ReverseQuorumStanding::Stood => "stood",
                    ReverseQuorumStanding::Reversed => "reversed",
                },
                "policy": f.policy,
                "distinct_objectors": f.distinct_objectors,
                "required": f.required,
                "roster_size": f.roster_size,
                "window_opens_at": f.window_opens_at.to_rfc3339(),
                "window_closes_at": f.window_closes_at.to_rfc3339(),
                "window_open": f.window_open,
                "counted_objection_ids": f.counted_objection_ids,
                "dismissed_objection_ids": f.dismissed_objection_ids,
                "escalated_dismissed_objection_ids": f.escalated_dismissed_objection_ids,
            });
            let esc = EscalationStanding::of(f);
            out["escalation"] = json!({
                "standing": esc.as_str(),
                "standing_message": esc.message(),
                "steward_deadline": f.steward_deadline.map(|d| d.to_rfc3339()),
                "objections": f.escalation.iter().map(escalation_json).collect::<Vec<_>>(),
            });
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════
//  GET /v1/commons/standing
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StandingQuery {
    /// `family` / `community` / `affiliations`. Parsed through persist's own
    /// [`Cohort::from_token`], never a match here.
    cohort: String,
    cohort_key_id: String,
    /// The commons action being judged.
    action_id: String,
    /// Read-time instant. Every window in the fold is compared against it, so a
    /// caller may ask what the commons said (or will say) at any instant.
    now: Option<String>,
}

fn parse_now(raw: Option<&str>) -> Result<DateTime<Utc>, String> {
    match raw {
        None => Ok(Utc::now()),
        Some(s) => DateTime::parse_from_rfc3339(s)
            .map(|t| t.with_timezone(&Utc))
            .map_err(|e| format!("`now` must be RFC 3339: {e}")),
    }
}

/// Parse the cohort token through persist's own parser. `self` is admitted by
/// [`Cohort::from_token`] and refused HERE with its own token, because the
/// `self` cohort has no roster to be a quorum over — its members are one
/// identity's devices — so it has no commons to police. persist's
/// `parse_cohort` refuses it at the fold, and this refusal exists so the caller
/// gets a reason rather than an empty roster.
#[allow(clippy::result_large_err)] // mirrors the rest of the module's Result<_, Response> helpers
fn parse_cohort(raw: &str) -> Result<Cohort, Response> {
    match Cohort::from_token(raw.trim()) {
        Ok(Cohort::SelfId) => Err(refusal(
            StatusCode::BAD_REQUEST,
            "cohort_not_a_commons",
            "commons_surface.refusal.cohort_not_a_commons",
            "The `self` cohort has no roster to be a quorum over — its members are one \
             identity's own devices — so it has no commons to police.",
        )),
        Ok(c) => Ok(c),
        Err(bad) => Err(err(
            StatusCode::BAD_REQUEST,
            "cohort_unrecognized",
            "commons_surface.refusal.cohort_unrecognized",
            format!("`{bad}` is not a rostered cohort."),
        )),
    }
}

/// Resolve the action row every call names.
///
/// `Ok(None)` is "this node does not hold it" — the [`CommonsStanding::ActionUnknown`]
/// zero — and is deliberately different from `Err`, which is
/// [`CommonsStanding::Unreadable`].
async fn load_action(engine: &Engine, action_id: &str) -> Result<Option<Attestation>, String> {
    engine
        .federation_directory()
        .get_attestation(action_id.trim())
        .await
        .map_err(|e| format!("{e}"))
}

async fn get_standing(
    State(st): State<CommonsState>,
    headers: HeaderMap,
    Query(q): Query<StandingQuery>,
) -> Response {
    if let Err(resp) = gate(&st, &headers, CapabilityVerb::ReadNodeState).await {
        return resp;
    }
    let cohort = match parse_cohort(&q.cohort) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let now = match parse_now(q.now.as_deref()) {
        Ok(n) => n,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "commons_surface.refusal.bad_now",
                e,
            )
        }
    };
    let key = q.cohort_key_id.trim();
    let action_id = q.action_id.trim();

    let render = |fold: Option<&ReverseQuorumFold>,
                  action: Option<&Attestation>,
                  forced: Option<CommonsStanding>| {
        standing_json(fold, cohort, key, action_id, action, now, forced)
    };

    // (1) The action. Absent and unreadable are two different answers.
    let action = match load_action(&st.engine, action_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(render(None, None, Some(CommonsStanding::ActionUnknown))),
            )
                .into_response()
        }
        Err(e) => {
            let mut body = render(None, None, Some(CommonsStanding::Unreadable));
            body["error"] = json!(e);
            return (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response();
        }
    };

    // (2) Does the cohort resolve here at all? `resolve_reverse_quorum` folds an
    //     unresolvable group to `NotGoverned` with an empty roster, which would
    //     render "this community has no reverse-quorum policy" for a community
    //     this node has never heard of. Two facts, two tokens.
    match st
        .engine
        .federation_directory()
        .lookup_group(cohort, key)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(render(
                    None,
                    Some(&action),
                    Some(CommonsStanding::CohortUnknown),
                )),
            )
                .into_response()
        }
        Err(e) => {
            let mut body = render(None, Some(&action), Some(CommonsStanding::Unreadable));
            body["error"] = json!(format!("{e}"));
            return (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response();
        }
    }

    // (3) The fold. Persist decides everything from here down.
    let dir = st.engine.federation_directory();
    match resolve_reverse_quorum(&*dir, cohort, key, &action, now).await {
        Ok(fold) => (
            StatusCode::OK,
            Json(render(Some(&fold), Some(&action), None)),
        )
            .into_response(),
        Err(e) => {
            let mut body = render(None, Some(&action), Some(CommonsStanding::Unreadable));
            body["error"] = json!(format!("{e}"));
            (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  The three write doors
// ═══════════════════════════════════════════════════════════════════════════

/// Fields every write on this plane carries.
#[derive(Debug, Clone, Deserialize)]
struct CommonsWriteBase {
    cohort: String,
    cohort_key_id: String,
    /// The commons action this row is about.
    action_id: String,
    /// **MANDATORY.** Free text: WHY. Recorded, never interpreted — persist
    /// does not adjudicate why somebody objected, and neither does this.
    grounds: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ObjectionRequest {
    #[serde(flatten)]
    base: CommonsWriteBase,
}

#[derive(Debug, Clone, Deserialize)]
struct BallotRequest {
    #[serde(flatten)]
    base: CommonsWriteBase,
    /// The objection this ballot is cast on.
    objection_id: String,
    /// `true` — *this objection stands*; `false` — *it does not*.
    upholds: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct DismissalRequest {
    #[serde(flatten)]
    base: CommonsWriteBase,
    /// The objection being dismissed.
    objection_id: String,
    /// Co-signatures over the SAME canonical envelope. **What they are worth is
    /// counted by the substrate**; this module counts nothing.
    #[serde(default)]
    additional_scrubs: Vec<ScrubSig>,
    /// Return the STAMPED canonical envelope and its `payload_sha256` WITHOUT
    /// signing or submitting, so co-signers can produce `additional_scrubs` over
    /// exactly the bytes the submission will carry. The m-of-n is unreachable
    /// without it.
    #[serde(default)]
    dry_run: bool,
    /// The `envelope` a [`Self::dry_run`] returned, echoed back verbatim.
    ///
    /// REQUIRED for a co-signed submission, and the reason is arithmetic: the
    /// emit stamp mints the row id and the instant AT STAMP TIME, so a second
    /// stamp produces different bytes and every co-signature made over the first
    /// verifies against nothing. persist re-verifies base and additional scrubs
    /// alike over the stored envelope, so the node's own scrub would count and
    /// the co-signers' would not — an m-of-n silently counting one, which is the
    /// quorum failing OPEN on the operator.
    ///
    /// Echoing it back is the only way the two calls can agree on one document.
    /// It is not trusted: the submission rebuilds what it WOULD have stamped and
    /// refuses anything whose claim differs (see the handler).
    #[serde(default)]
    stamped_envelope: Option<Value>,
}

/// Refuse a blank required string.
fn require_nonblank(
    v: &str,
    token: &'static str,
    id: &'static str,
    text: &'static str,
) -> Option<Response> {
    if v.trim().is_empty() {
        Some(refusal(StatusCode::BAD_REQUEST, token, id, text))
    } else {
        None
    }
}

/// The resolved preconditions every write shares.
struct WriteContext {
    cohort: Cohort,
    /// The action's author — the `attested_key_id` every row on this plane must
    /// carry, or persist refuses it `not_filed_against_actor`: the fold looks
    /// for these rows under the ACTOR, so a row filed elsewhere would be
    /// stored, durable, and permanently inert.
    actor: String,
}

/// Check the shared fields and resolve the action. **No threshold and no
/// authority decision is made here** — those are the substrate's, at its own
/// doors. What this does is refuse a request that names nothing at all, so the
/// operator gets a localizable reason instead of a row assembled around a
/// dangling id.
async fn check_base(
    engine: &Arc<Engine>,
    base: &CommonsWriteBase,
) -> Result<WriteContext, Response> {
    let cohort = parse_cohort(&base.cohort)?;
    for (v, token, id, text) in [
        (
            &base.cohort_key_id,
            "cohort_absent",
            "commons_surface.refusal.cohort_absent",
            "cohort_key_id is required: it names whose roster and whose declaration govern the \
             count.",
        ),
        (
            &base.action_id,
            "action_absent",
            "commons_surface.refusal.action_absent",
            "action_id is required. An objection names a row in the commons; one that names \
             nothing can never be counted.",
        ),
        (
            &base.grounds,
            "grounds_absent",
            "commons_surface.refusal.grounds_absent",
            "grounds is required. An objection raised for no recorded reason is \
             indistinguishable from one raised for a bad one — and grounds are recorded, never \
             interpreted.",
        ),
    ] {
        if let Some(r) = require_nonblank(v, token, id, text) {
            return Err(r);
        }
    }
    match load_action(engine, &base.action_id).await {
        Ok(Some(a)) => Ok(WriteContext {
            cohort,
            actor: a.attesting_key_id,
        }),
        Ok(None) => Err(refusal(
            StatusCode::NOT_FOUND,
            "action_unknown",
            "commons_surface.refusal.action_unknown",
            "This node holds no such action, so a row naming it would be filed where no fold \
             will ever count it. The substrate refuses the same case at its own door.",
        )),
        Err(e) => Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "commons_surface.refusal.store_unavailable",
            format!("The substrate could not be read: {e}"),
        )),
    }
}

/// `sha256(JCS(envelope))` — the exact bytes a co-signer must sign.
fn payload_sha256(envelope: &Value) -> Result<String, String> {
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(envelope)
        .map_err(|e| format!("canonicalize commons row: {e}"))?;
    Ok(hex::encode(Sha256::digest(&canonical)))
}

/// Assemble + hybrid-sign one row on this plane.
///
/// The envelope always comes from persist's own builder, so producer and fold
/// cannot disagree about where a reference lives. `attested_key_id` is the
/// ACTOR, which is what makes the row findable by the fold's
/// `list_attestations_for(actor)` read.
/// Stamp a commons envelope — mint its id, instant and column mirror — WITHOUT
/// signing it.
///
/// Split out of [`build_row`] because the co-signed path needs the stamped bytes
/// BEFORE anyone signs: the dry run advertises them, the co-signers sign them,
/// and the submission assembles over the same ones. A second stamp would mint a
/// different id and instant (CIRISPersist#598/#643), and persist re-verifies base
/// AND additional scrubs over the stored envelope — so co-signatures made over a
/// bare envelope verify against nothing while the node's own still counts. That
/// is an m-of-n silently counting one, which is the quorum failing OPEN.
async fn stamp_for(
    engine: &Arc<Engine>,
    envelope: Value,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<crate::attest::Emit, String> {
    let key_id = engine
        .local_derived_key_id()
        .await
        .map_err(|e| format!("derive acting key_id: {e}"))?;
    crate::attest::Emit::stamp_at(
        &key_id,
        crate::attest::Spec::new(attestation_type::SCORES, cohort_scope::FEDERATION, envelope)
            // A commons row is ABOUT the actor and names no subject: it scores
            // conduct, and `subject_key_ids` would hand the scored party revocation
            // authority over the score (the CIRISPersist#519 exhibit-G2 shape).
            .attested_to(actor),
        now,
    )
    .map_err(|e| format!("stamp commons row: {e}"))
}

/// Sign and assemble a commons row from `envelope`.
///
/// When the envelope is ALREADY stamped — the co-signed path echoing back what
/// the dry run returned — it is ADOPTED rather than re-stamped, so the bytes the
/// co-signers signed are the bytes the row carries. An unstamped envelope is
/// stamped here, which is right for the uncontested single-signer path.
async fn build_row_from(
    engine: &Arc<Engine>,
    envelope: Value,
    actor: &str,
    additional_scrubs: Vec<ScrubSig>,
    now: DateTime<Utc>,
) -> Result<Attestation, String> {
    let already_stamped = envelope
        .get(ciris_persist::federation::envelope::paths::ROW)
        .is_some();
    let stamped = if already_stamped {
        crate::attest::Emit::adopt(&envelope).map_err(|e| format!("adopt commons row: {e}"))?
    } else {
        stamp_for(engine, envelope, actor, now).await?
    };

    let sig = engine
        .sign_hybrid(stamped.canonical())
        .await
        .map_err(|e| format!("hybrid-sign commons row: {e}"))?;
    let mut row = stamped
        .assemble(sig)
        .map_err(|e| format!("assemble commons row: {e}"))?;
    row.additional_scrubs = additional_scrubs;
    Ok(row)
}

/// **Render the substrate's outcome. Nothing is decided here.**
///
/// The refusal token is [`ObjectionRefusalReason::as_str`] verbatim — persist
/// owns that vocabulary and it is append-only — and the message id is DERIVED
/// from it, so the localizable id set cannot drift from the token set and no
/// variant list is written down.
///
/// [`ObjectionRefusalReason::as_str`]: ciris_persist::federation::reverse_quorum::ObjectionRefusalReason::as_str
fn outcome_response(
    outcome: ObjectionOutcome,
    admitted_message: Value,
    mut body: serde_json::Map<String, Value>,
) -> Response {
    match outcome.refusal() {
        None => {
            body.insert("admitted".into(), json!(true));
            body.insert("message".into(), admitted_message);
            (StatusCode::OK, Json(Value::Object(body))).into_response()
        }
        Some(reason) => {
            let token = reason.as_str();
            body.insert("refused".into(), json!(true));
            body.insert("refusal".into(), json!(token));
            body.insert(
                "message".into(),
                m(
                    &format!("commons_surface.refusal.{token}"),
                    &format!(
                        "The substrate refused this row at the {token} gate. The refusal token \
                         names which rule; the substrate owns that vocabulary."
                    ),
                ),
            );
            (StatusCode::CONFLICT, Json(Value::Object(body))).into_response()
        }
    }
}

fn sign_failed(e: String) -> Response {
    err(
        StatusCode::SERVICE_UNAVAILABLE,
        "sign_failed",
        "commons_surface.refusal.sign_failed",
        e,
    )
}

fn store_unavailable(e: String) -> Response {
    err(
        StatusCode::SERVICE_UNAVAILABLE,
        "store_unavailable",
        "commons_surface.refusal.store_unavailable",
        format!("The substrate could not be written: {e}"),
    )
}

// ─── raise ──────────────────────────────────────────────────────────────────

async fn post_objection(
    State(st): State<CommonsState>,
    headers: HeaderMap,
    Json(req): Json<ObjectionRequest>,
) -> Response {
    if let Err(resp) = gate(&st, &headers, CapabilityVerb::Wipe).await {
        return resp;
    }
    let ctx = match check_base(&st.engine, &req.base).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let envelope = objection_envelope(
        ctx.cohort,
        req.base.cohort_key_id.trim(),
        req.base.action_id.trim(),
        req.base.grounds.trim(),
    );
    let now = Utc::now();
    let row = match build_row_from(&st.engine, envelope, &ctx.actor, Vec::new(), now).await {
        Ok(r) => r,
        Err(e) => return sign_failed(e),
    };
    let dir = st.engine.federation_directory();
    let outcome = match record_objection(&*dir, &row).await {
        Ok(o) => o,
        Err(e) => return store_unavailable(format!("{e}")),
    };
    let mut body = serde_json::Map::new();
    body.insert("source_locale".into(), json!(SOURCE_LOCALE));
    body.insert("objection_id".into(), json!(row.attestation_id));
    body.insert("action_id".into(), json!(req.base.action_id.trim()));
    body.insert("objector".into(), json!(row.attesting_key_id));
    body.insert("threshold".into(), json!(OBJECTION_THRESHOLD));
    outcome_response(
        outcome,
        m(
            "commons_surface.objection.admitted",
            "The objection is on the record. It is a MARKER, not a command: nothing was changed \
             by its arrival, and it replicates on the ordinary attestation plane so a peer that \
             was partitioned during the window still counts it when it arrives. One member is \
             enough to raise it; lifting it costs the cohort's own threshold.",
        ),
        body,
    )
}

// ─── ballot ─────────────────────────────────────────────────────────────────

async fn post_ballot(
    State(st): State<CommonsState>,
    headers: HeaderMap,
    Json(req): Json<BallotRequest>,
) -> Response {
    if let Err(resp) = gate(&st, &headers, CapabilityVerb::Wipe).await {
        return resp;
    }
    let ctx = match check_base(&st.engine, &req.base).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    if let Some(r) = require_nonblank(
        &req.objection_id,
        "objection_absent",
        "commons_surface.refusal.objection_absent",
        "objection_id is required: a ballot answers a question about ONE objection.",
    ) {
        return r;
    }
    let envelope = ballot_envelope(
        ctx.cohort,
        req.base.cohort_key_id.trim(),
        req.base.action_id.trim(),
        req.objection_id.trim(),
        req.upholds,
        req.base.grounds.trim(),
    );
    let now = Utc::now();
    let row = match build_row_from(&st.engine, envelope, &ctx.actor, Vec::new(), now).await {
        Ok(r) => r,
        Err(e) => return sign_failed(e),
    };
    let dir = st.engine.federation_directory();
    let outcome = match record_objection_ballot(&*dir, &row).await {
        Ok(o) => o,
        Err(e) => return store_unavailable(format!("{e}")),
    };
    let mut body = serde_json::Map::new();
    body.insert("source_locale".into(), json!(SOURCE_LOCALE));
    body.insert("ballot_id".into(), json!(row.attestation_id));
    body.insert("objection_id".into(), json!(req.objection_id.trim()));
    body.insert("upholds".into(), json!(req.upholds));
    body.insert("voter".into(), json!(row.attesting_key_id));
    outcome_response(
        outcome,
        m(
            "commons_surface.ballot.admitted",
            "The ballot is on the record. It has NO force on its own: its price is paid at read \
             time against a denominator that does not exist yet when it is cast — whether the \
             pool ever reaches the escalated threshold depends on who else answers. A member may \
             change their mind; the latest ballot governs.",
        ),
        body,
    )
}

// ─── dismiss ────────────────────────────────────────────────────────────────

async fn post_dismissal(
    State(st): State<CommonsState>,
    headers: HeaderMap,
    Json(req): Json<DismissalRequest>,
) -> Response {
    if let Err(resp) = gate(&st, &headers, CapabilityVerb::Wipe).await {
        return resp;
    }
    let ctx = match check_base(&st.engine, &req.base).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    if let Some(r) = require_nonblank(
        &req.objection_id,
        "objection_absent",
        "commons_surface.refusal.objection_absent",
        "objection_id is required: a dismissal lifts ONE named objection.",
    ) {
        return r;
    }
    let envelope = dismissal_envelope(
        ctx.cohort,
        req.base.cohort_key_id.trim(),
        req.base.action_id.trim(),
        req.objection_id.trim(),
        req.base.grounds.trim(),
    );
    if req.dry_run {
        // STAMP, then advertise. The bytes a co-signer must sign are the bytes
        // the row will carry, and since CIRISPersist#598/#643 those include the
        // row's own id, its instant and the seven-column mirror — all minted by
        // the stamp. Advertising the BARE envelope here is what made every
        // co-signature verify against a document that never existed.
        let stamped = match stamp_for(&st.engine, envelope, &ctx.actor, Utc::now()).await {
            Ok(v) => v,
            Err(e) => return sign_failed(e),
        };
        let stamped_envelope = stamped.envelope();
        let sha = match payload_sha256(&stamped_envelope) {
            Ok(s) => s,
            Err(e) => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "canonicalize_failed",
                    "commons_surface.refusal.canonicalize_failed",
                    e,
                )
            }
        };
        return (
            StatusCode::OK,
            Json(json!({
                "source_locale": SOURCE_LOCALE,
                "dry_run": true,
                "envelope": stamped_envelope,
                "payload_sha256": sha,
                "message": m(
                    "commons_surface.dry_run",
                    "Nothing was signed and nothing was submitted. These are the exact canonical \
                     bytes each co-signer must sign for their scrub to count on the real \
                     submission — the m-of-n is over these bytes and no others. Send this \
                     `envelope` back verbatim as `stamped_envelope` with the submission: a second \
                     stamp would mint a different row id and instant, and every co-signature \
                     would then verify against nothing.",
                ),
            })),
        )
            .into_response();
    }

    // A CO-SIGNED submission must carry the stamped envelope the co-signers
    // actually signed. Rebuild what we WOULD have stamped and refuse anything
    // whose claim differs — the echo is a transport for the stamp, never a way to
    // choose what the row says.
    let echoed =
        match req.stamped_envelope.as_ref() {
            Some(e) if !req.additional_scrubs.is_empty() => {
                if crate::attest::claim_view(e) != crate::attest::claim_view(&envelope) {
                    return err(
                        StatusCode::CONFLICT,
                        "stamped_envelope_mismatch",
                        "commons_surface.refusal.stamped_envelope_mismatch",
                        "the echoed `stamped_envelope` does not describe the dismissal in this \
                     request. Re-run the dry run for THESE fields and have the co-signers sign \
                     what it returns."
                            .to_string(),
                    );
                }
                Some(e.clone())
            }
            // No co-signers: nothing was signed elsewhere, so there is nothing to
            // agree with and a fresh stamp is correct. An echoed envelope with no
            // scrubs is harmless but pointless — ignored rather than refused.
            Some(_) => None,
            None if req.additional_scrubs.is_empty() => None,
            None => return err(
                StatusCode::BAD_REQUEST,
                "stamped_envelope_required",
                "commons_surface.refusal.stamped_envelope_required",
                "co-signatures were supplied without the `stamped_envelope` they were made over. \
                 Run the dry run, have the co-signers sign the `envelope` it returns, and send \
                 that envelope back with their scrubs — otherwise their signatures cover bytes \
                 this submission does not carry and the quorum silently counts one."
                    .to_string(),
            ),
        };

    let now = Utc::now();
    let row = match build_row_from(
        &st.engine,
        echoed.unwrap_or(envelope),
        &ctx.actor,
        req.additional_scrubs,
        now,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return sign_failed(e),
    };
    let dir = st.engine.federation_directory();
    let decision: DismissalDecision = match record_objection_dismissal(&*dir, &row).await {
        Ok(d) => d,
        Err(e) => return store_unavailable(format!("{e}")),
    };
    let mut body = serde_json::Map::new();
    body.insert("source_locale".into(), json!(SOURCE_LOCALE));
    body.insert("dismissal_id".into(), json!(row.attestation_id));
    body.insert("objection_id".into(), json!(req.objection_id.trim()));
    // The hash of the envelope the ROW carries — which since the stamp is the
    // same document the co-signers signed. Hashing a separately-built envelope
    // here is how the advertised preimage and the stored one came apart.
    body.insert(
        "payload_sha256".into(),
        json!(payload_sha256(&row.attestation_envelope).unwrap_or_default()),
    );
    // The m-of-n evidence, on BOTH arms — a refusal names its shortfall and an
    // admission names what it cleared. persist's numbers, verbatim.
    body.insert(
        "quorum".into(),
        json!({
            "counted": decision.quorum.counted,
            "required": decision.quorum.required,
            "roster_size": decision.quorum.roster_size,
        }),
    );
    outcome_response(
        decision.outcome,
        m(
            "commons_surface.dismissal.admitted",
            "The objection is lifted for the count. The threshold is re-derived from this node's \
             own roster on every later read, so a dismissal that stops clearing a grown roster \
             stops suppressing — and the protection it removed comes back.",
        ),
        body,
    )
}

// ═══════════════════════════════════════════════════════════════════════════
//  Router
// ═══════════════════════════════════════════════════════════════════════════

/// Mount the commons surface. `node_key_id` is THIS node's federation key id —
/// the member whose voice every write here carries.
pub fn router(engine: Arc<Engine>, node_key_id: String) -> Router {
    Router::new()
        .route(ROUTE_STANDING, axum::routing::get(get_standing))
        .route(ROUTE_OBJECT, axum::routing::post(post_objection))
        .route(ROUTE_BALLOT, axum::routing::post(post_ballot))
        .route(ROUTE_DISMISS, axum::routing::post(post_dismissal))
        .with_state(CommonsState {
            engine,
            node_key_id,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_persist::federation::reverse_quorum::{
        EscalationOutcome, ObjectionRefusalReason, StewardTierStanding,
    };
    use std::collections::BTreeSet;

    fn ts(s: &str) -> DateTime<Utc> {
        s.parse().expect("rfc3339")
    }

    const T0: &str = "2026-08-05T12:00:00Z";

    fn fold(standing: ReverseQuorumStanding, objectors: usize) -> ReverseQuorumFold {
        ReverseQuorumFold {
            standing,
            policy: Some("reverse_quorum:2/5:3600".into()),
            distinct_objectors: objectors,
            required: 2,
            roster_size: 5,
            window_opens_at: ts(T0),
            window_closes_at: ts(T0),
            window_open: false,
            counted_objection_ids: Vec::new(),
            dismissed_objection_ids: Vec::new(),
            steward_deadline: None,
            escalation: Vec::new(),
            escalated_dismissed_objection_ids: Vec::new(),
        }
    }

    /// The four facts the issue names, plus the two absences, all separable.
    #[test]
    fn every_zero_names_its_own_cause() {
        assert_eq!(CommonsStanding::of(None), CommonsStanding::Unreadable);
        assert_eq!(
            CommonsStanding::of(Some(&fold(ReverseQuorumStanding::NotGoverned, 0))),
            CommonsStanding::NotGoverned
        );
        assert_eq!(
            CommonsStanding::of(Some(&fold(ReverseQuorumStanding::WindowOpen, 0))),
            CommonsStanding::Quiet
        );
        assert_eq!(
            CommonsStanding::of(Some(&fold(ReverseQuorumStanding::Stood, 0))),
            CommonsStanding::Quiet
        );
        assert_eq!(
            CommonsStanding::of(Some(&fold(ReverseQuorumStanding::WindowOpen, 1))),
            CommonsStanding::Objected
        );
        assert_eq!(
            CommonsStanding::of(Some(&fold(ReverseQuorumStanding::Stood, 1))),
            CommonsStanding::Stood
        );
        assert_eq!(
            CommonsStanding::of(Some(&fold(ReverseQuorumStanding::Reversed, 2))),
            CommonsStanding::Reversed
        );

        // Every token in both closed sets is distinct, and so is every message
        // id — two facts sharing a sentence is the same defect as two facts
        // sharing a token.
        for (n, tokens) in [
            (
                CommonsStanding::ALL.len(),
                CommonsStanding::ALL
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<BTreeSet<_>>(),
            ),
            (
                EscalationStanding::ALL.len(),
                EscalationStanding::ALL
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<BTreeSet<_>>(),
            ),
        ] {
            assert_eq!(tokens.len(), n, "duplicate standing token");
        }
        let ids: BTreeSet<String> = CommonsStanding::ALL
            .iter()
            .map(|s| s.message()["id"].as_str().expect("id").to_owned())
            .collect();
        assert_eq!(ids.len(), CommonsStanding::ALL.len());
        let esc_ids: BTreeSet<String> = EscalationStanding::ALL
            .iter()
            .map(|s| s.message()["id"].as_str().expect("id").to_owned())
            .collect();
        assert_eq!(esc_ids.len(), EscalationStanding::ALL.len());
    }

    /// The escalation axis is persist's, read through persist's own
    /// `escalates()` predicate — including all THREE of its zeroes.
    #[test]
    fn escalation_standing_reads_persists_predicate() {
        let mut f = fold(ReverseQuorumStanding::WindowOpen, 1);
        assert_eq!(EscalationStanding::of(&f), EscalationStanding::NotAdopted);

        f.steward_deadline = Some(ts(T0));
        assert_eq!(
            EscalationStanding::of(&f),
            EscalationStanding::NothingToEscalate
        );

        let rec = |steward: StewardTierStanding| ObjectionEscalation {
            objection_id: "o1".into(),
            steward,
            outcome: EscalationOutcome::Unresolved,
            duty_holders: 1,
            steward_ruling_required: 1,
            respondents: 0,
            required: ESCALATION_RESPONDENT_FLOOR,
            uphold_ballots: 0,
            overrule_ballots: 0,
            counted_ballot_ids: Vec::new(),
        };

        for quiet in [StewardTierStanding::Awaiting, StewardTierStanding::Upheld] {
            f.escalation = vec![rec(quiet)];
            assert_eq!(
                EscalationStanding::of(&f),
                EscalationStanding::Awaiting,
                "{quiet} must not open escalation"
            );
        }
        // THE THREE ZEROES. Each opens escalation, each keeps its own token.
        for open in [
            StewardTierStanding::Silent,
            StewardTierStanding::Overruled,
            StewardTierStanding::NoDutyHolders,
        ] {
            f.escalation = vec![rec(open)];
            assert_eq!(
                EscalationStanding::of(&f),
                EscalationStanding::Open,
                "{open} must open escalation"
            );
        }
        let tokens: BTreeSet<&str> = [
            StewardTierStanding::Silent,
            StewardTierStanding::Overruled,
            StewardTierStanding::NoDutyHolders,
        ]
        .iter()
        .map(StewardTierStanding::as_str)
        .collect();
        assert_eq!(tokens.len(), 3, "the three zeroes must not share a token");
    }

    /// The unreadable and absent arms carry NO counts. A `0` where the answer
    /// is "unknown" is the RCA's defect in miniature.
    #[test]
    fn an_unknown_plane_reports_no_numbers() {
        for forced in [
            CommonsStanding::Unreadable,
            CommonsStanding::ActionUnknown,
            CommonsStanding::CohortUnknown,
        ] {
            let v = standing_json(
                None,
                Cohort::Community,
                "c1",
                "a1",
                None,
                ts(T0),
                Some(forced),
            );
            assert_eq!(v["standing"], json!(forced.as_str()));
            assert_eq!(v["fold"], Value::Null, "{forced:?} must carry no counts");
            assert_eq!(v["escalation"], Value::Null);
        }
    }

    /// Every refusal token persist can return gets a distinct message id, with
    /// no arm list written down here.
    #[test]
    fn refusal_ids_are_derived_from_persists_closed_set() {
        let ids: BTreeSet<String> = ObjectionRefusalReason::ALL
            .iter()
            .map(|r| {
                let resp = outcome_response(
                    ObjectionOutcome::Refused { reason: *r },
                    m("x", "x"),
                    serde_json::Map::new(),
                );
                assert_eq!(resp.status(), StatusCode::CONFLICT);
                format!("commons_surface.refusal.{}", r.as_str())
            })
            .collect();
        assert_eq!(ids.len(), ObjectionRefusalReason::ALL.len());
    }
}
