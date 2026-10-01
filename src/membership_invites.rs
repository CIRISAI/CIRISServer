//! **Nobody joins without their own consent — the invite flow** (0.5.218;
//! the maintainer's ruling of 2026-09-30, CIRISConstitution#133, persist
//! v52.0.0 / CIRISPersist#955, edge v38.0.0's `membership` module;
//! `FSD/MEMBERSHIP_INVITES.md`).
//!
//! Until 0.5.218 every roster-growing door added a member on the EXISTING
//! members' authority alone, and from the ruling until this cut every such
//! door answered 409 `membership.consent_required` ("refuse, don't hold").
//! This module is what replaces the refusal: the three signed rows of
//! persist's flow, driven over HTTP.
//!
//! ```text
//! inviter's node                    invitee's node                 group
//! POST …/{families,communities}/{id}/invites
//!   membership:proposal:v1 ───────▶ GET /v1/self/invites
//!   (the inviter's PERSON signs)    POST /v1/self/invites/{p}/accept
//!                                     membership:acceptance:v1 ──▶ (replicates back)
//!   the WIDENING ◀─────────────────────────────────────────────── the inviter's node
//!   (founder_only: on arrival, by edge's bridge with this node's
//!    `membership_widener`, or here when a member lists the invites;
//!    a quorum group: envelope → cosign → assemble, an `add`)
//! ```
//!
//! # Where each rule lives (and where it does not)
//!
//! The ADMISSION rule is persist's, every word of it: a growth needs the
//! member's live acceptance of a live proposal (`check_growth_accepted`, on the
//! local door AND the replicated apply), a decline is terminal, expiry is
//! judged on the two signed instants, a founding record seats only its
//! signers, a supersede never adds. The ROWS are edge's (`membership::propose`,
//! `reply`, `widen_on_acceptance` — built through persist's own builders, so the
//! wire shape cannot drift). This module keeps NEITHER. It decides only HTTP
//! things: who may ask (the owner's session, never a delegate, for anything
//! that signs), which group the caller may see, and how a refusal is NAMED —
//! persist's eight rule tokens map one-to-one onto stable `membership.*`
//! reason ids in [`refused`], and nothing here re-derives a verdict persist
//! would give (the mirrored-rule class: one rule, one implementation).
//!
//! # Whose key signs what
//!
//! - The PROPOSAL is the inviter's person (`OwnerSignerCapsule::edge_signer`):
//!   persist checks "a founder proposes under `founder_only`" against the
//!   proposer's identity.
//! - The ACCEPTANCE / DECLINE is the invitee's person. persist would admit a
//!   device acting for them (`signer_acts_for`); the person's own pen is used
//!   because the acceptance is the person's consent, the same reason a consent
//!   grant is authored by the human (`consent-is-authored-by-the-human`).
//! - The WIDENING is a founder's PERSON key — the roster's consensus counts raw
//!   seat keys, so a device acting for the founder does not count. That is why
//!   `compose` installs the owner's person pen as the bridge's
//!   `membership_widener`, and why [`widen_held_acceptances`] takes the
//!   caller's capsule, never the node signer.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::Serialize;

use ciris_edge::membership::{
    self as em, GroupScope, MembershipError, MembershipWidener, ACCEPTANCE_DIMENSION,
    DECLINE_DIMENSION, PROPOSAL_DIMENSION,
};
use ciris_persist::federation::types::{attestation_type, Attestation};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::Engine;

use crate::family_api::{owner_caller, GateRefusal, OwnerCaller};
use crate::owner_signer_capsule::{self, OwnerSignerCapsule};

/// How long an invitation lives when the inviter does not say: two weeks.
/// persist bounds it at 30 days (`MEMBERSHIP_PROPOSAL_MAX_TTL_SECS`); a
/// longer ask is refused by name here rather than clamped, so a client never
/// shows an expiry the row does not carry.
pub const DEFAULT_INVITE_DAYS: i64 = 14;

/// Every `state` an invitation can be in, as [`InviteView::state`] reports it.
pub const INVITE_STATES: &[&str] = &[
    STATE_PENDING,
    STATE_ACCEPTED,
    STATE_JOINED,
    STATE_DECLINED,
    STATE_EXPIRED,
    STATE_WITHDRAWN,
];
/// Sent; the invitee has not answered and it is live.
pub const STATE_PENDING: &str = "pending";
/// The invitee accepted; the group has not seated them yet (under a quorum
/// protocol: "accepted, awaiting the group" — persist FSD §4).
pub const STATE_ACCEPTED: &str = "accepted";
/// Accepted AND active in the group's roster now.
pub const STATE_JOINED: &str = "joined";
/// The invitee declined. Terminal for this invitation.
pub const STATE_DECLINED: &str = "declined";
/// Lapsed unanswered. Terminal; inviting again is a new invitation.
pub const STATE_EXPIRED: &str = "expired";
/// The inviter withdrew it before an answer. Terminal.
pub const STATE_WITHDRAWN: &str = "withdrawn";

// ─── Refusals ───────────────────────────────────────────────────────────────
//
// One function per id, a string-literal id beside a one-sentence English text
// (the localization guard reads the pair, and an id must carry exactly one
// sentence). No id is ever built with `format!`.

fn refuse(code: StatusCode, id: &'static str, text: &'static str, detail: String) -> Response {
    (
        code,
        Json(serde_json::json!({ "error": text, "reason_id": id, "detail": detail })),
    )
        .into_response()
}

pub(crate) fn invite_not_found(detail: String) -> Response {
    refuse(
        StatusCode::NOT_FOUND,
        "membership.invite_not_found",
        "That invitation isn't here. It may not have arrived yet, or it was never sent to you.",
        detail,
    )
}

fn not_the_invitee(detail: String) -> Response {
    refuse(
        StatusCode::FORBIDDEN,
        "membership.not_the_invitee",
        "Only the person who was invited can answer an invitation.",
        detail,
    )
}

pub(crate) fn not_the_proposer(detail: String) -> Response {
    refuse(
        StatusCode::FORBIDDEN,
        "membership.not_the_proposer",
        "Only the person who sent an invitation can withdraw it.",
        detail,
    )
}

pub(crate) fn bad_expiry(detail: String) -> Response {
    refuse(
        StatusCode::BAD_REQUEST,
        "membership.bad_expiry",
        "An invitation lasts between one and thirty days.",
        detail,
    )
}

pub(crate) fn invite_closed(detail: String) -> Response {
    refuse(
        StatusCode::CONFLICT,
        "membership.invite_closed",
        "That invitation is no longer open, so it can't be withdrawn.",
        detail,
    )
}

fn store_unavailable(detail: String) -> Response {
    refuse(
        StatusCode::SERVICE_UNAVAILABLE,
        "membership.store_unavailable",
        "The node could not read or write its membership records. Nothing was changed.",
        detail,
    )
}

fn signer_unavailable(detail: String) -> Response {
    refuse(
        StatusCode::FORBIDDEN,
        "membership.signer_unavailable",
        "Your identity could not be opened to sign this answer.",
        detail,
    )
}

fn session_required(code: StatusCode) -> Response {
    refuse(
        code,
        "membership.owner_session_required",
        "Invitations are answered by this node's owner. Sign in as the owner.",
        String::new(),
    )
}

fn delegate_may_not_answer() -> Response {
    refuse(
        StatusCode::FORBIDDEN,
        "membership.delegate_may_not_answer",
        "A delegated session can see invitations but can't answer them. Your answer is signed with your own key.",
        String::new(),
    )
}

/// **persist's refusal, named.** The eight rule tokens of CIRISPersist#955,
/// verbatim from edge's [`MembershipError::Refused`], each onto ONE stable
/// id. Retryable rules (`*_unresolved`) are 409s a client may retry; the rest
/// are terminal for that invitation. `detail` is the substrate's own sentence.
pub(crate) fn refused(e: &MembershipError) -> Response {
    let detail = e.to_string();
    match e {
        MembershipError::Refused { rule, .. } => match *rule {
            em::RULE_ACCEPTANCE_UNRESOLVED => refuse(
                StatusCode::CONFLICT,
                "membership.awaiting_acceptance",
                "They haven't accepted the invitation yet, so they can't join.",
                detail,
            ),
            em::RULE_PROPOSAL_UNRESOLVED => refuse(
                StatusCode::CONFLICT,
                "membership.invite_not_here_yet",
                "That invitation hasn't reached this device yet. Try again shortly.",
                detail,
            ),
            em::RULE_DECLINED => refuse(
                StatusCode::CONFLICT,
                "membership.declined",
                "They declined the invitation, so they can't be added under it.",
                detail,
            ),
            em::RULE_PROPOSAL_EXPIRED => refuse(
                StatusCode::GONE,
                "membership.invite_expired",
                "That invitation has expired. Send a new one.",
                detail,
            ),
            em::RULE_ACCEPTANCE_MISMATCH => refuse(
                StatusCode::FORBIDDEN,
                "membership.acceptance_mismatch",
                "That answer doesn't match the invitation it names.",
                detail,
            ),
            em::RULE_REPLY_CONFLICT => refuse(
                StatusCode::CONFLICT,
                "membership.already_answered",
                "That invitation was already answered the other way.",
                detail,
            ),
            em::RULE_FOUNDING_MEMBER_UNSIGNED => founding_member_unsigned(detail),
            em::RULE_SUPERSEDE_CANNOT_ADD => refuse(
                StatusCode::CONFLICT,
                "membership.supersede_cannot_add",
                "A change to the group's record can't add anyone. New members join by invitation.",
                detail,
            ),
            _ => membership_refused(detail),
        },
        MembershipError::NotAProposal(_) => invite_not_found(detail),
        MembershipError::Other(_) => membership_refused(detail),
    }
}

/// A founding roster names someone who did not sign it (persist Q1: signing
/// the founding record IS consent). Shared with the create routes, which
/// refuse the same thing BEFORE writing anything.
pub(crate) fn founding_member_unsigned(detail: String) -> Response {
    refuse(
        StatusCode::CONFLICT,
        "membership.founding_member_unsigned",
        "A group is founded by you alone. Invite the others once it exists.",
        detail,
    )
}

/// Any other refusal of a membership row (a proposer without standing, a
/// dissolved group, a malformed row) — persist's sentence in `detail`.
fn membership_refused(detail: String) -> Response {
    refuse(
        StatusCode::CONFLICT,
        "membership.refused",
        "The group's rules refused that membership change.",
        detail,
    )
}

/// persist's typed consent refusal out of a roster door (`add_member`,
/// `put_*_membership_widening`), as [`refused`] names it; `None` for any
/// other error, which the caller keeps naming its own way.
pub(crate) fn persist_refusal(e: &ciris_persist::federation::Error) -> Option<Response> {
    match e {
        ciris_persist::federation::Error::MembershipAcceptanceRefused {
            group_key_id,
            member_key_id,
            rule,
        } => Some(refused(&MembershipError::Refused {
            group_key_id: group_key_id.clone(),
            member_key_id: member_key_id.clone(),
            rule,
        })),
        _ => None,
    }
}

// ─── The rows, read back ────────────────────────────────────────────────────

/// One invitation into a group, as the group's members see it.
#[derive(Debug, Clone, Serialize)]
pub struct InviteView {
    pub proposal_id: String,
    pub invitee_key_id: String,
    pub role: Option<String>,
    pub proposer_key_id: String,
    pub proposed_at: String,
    pub expires_at: Option<String>,
    /// One of [`INVITE_STATES`].
    pub state: &'static str,
    /// The acceptance or decline row, when there is one.
    pub reply_id: Option<String>,
}

fn dimension_of(row: &Attestation) -> Option<&str> {
    em::dimension_of(row)
}

fn envelope_str<'a>(row: &'a Attestation, member: &str) -> Option<&'a str> {
    row.attestation_envelope
        .get(member)
        .and_then(serde_json::Value::as_str)
}

/// The group a membership row is placed at (`family_key_id` /
/// `community_key_id`, edge's [`GroupScope::target_member`]).
pub(crate) fn group_of(row: &Attestation, scope: GroupScope) -> Option<&str> {
    envelope_str(row, scope.target_member())
}

/// Every proposal held here that invites someone into `group`, oldest first.
///
/// persist keeps no index of proposals by group (the read arm it ships is by
/// INVITEE, which edge's `pending_proposals_for` walks), so this pages the
/// node's attestation log the way that helper does. A node holds the
/// proposals of the groups it is in plus the ones addressed to its owner, so
/// the walk is bounded by what this node already stores.
async fn proposals_into(
    dir: &dyn FederationDirectory,
    scope: GroupScope,
    group: &str,
) -> Result<Vec<Attestation>, String> {
    const PAGE: u32 = 512;
    let mut out = Vec::new();
    let mut since = None;
    loop {
        let page = dir
            .list_attestations_since(since.clone(), PAGE)
            .await
            .map_err(|e| format!("list_attestations_since: {e:#}"))?;
        let full = page.len() == PAGE as usize;
        since = page
            .last()
            .map(ciris_persist::federation::types::ServedAttestation::resume_pair);
        for served in page {
            let p = served.attestation;
            if dimension_of(&p) == Some(PROPOSAL_DIMENSION)
                && GroupScope::of_row(&p) == Some(scope)
                && group_of(&p, scope) == Some(group)
            {
                out.push(p);
            }
        }
        if !full {
            break;
        }
    }
    out.sort_by_key(|p| p.asserted_at);
    Ok(out)
}

/// **Who a pair room is waiting for** — the invitee of the newest proposal
/// into `room` that does not name `me`. Since edge v38 a pair room is founded
/// by its opener alone and the other person joins by accepting, so between
/// the two steps the FOLD names one person; the other is named only by the
/// invitation. `None` when nothing invites anyone into it.
pub(crate) async fn pending_pair_invitee(
    dir: &dyn FederationDirectory,
    room: &str,
    me: &str,
) -> Option<String> {
    proposals_into(dir, GroupScope::Community, room)
        .await
        .ok()?
        .into_iter()
        .rev()
        .filter_map(|p| p.subject_key_ids.first().cloned())
        .find(|k| k != me)
}

/// The invitee's replies to `proposal_id`: (acceptance, decline).
async fn replies_to(
    dir: &dyn FederationDirectory,
    invitee: &str,
    proposal_id: &str,
) -> Result<(Option<Attestation>, Option<Attestation>), String> {
    let mut accepted = None;
    let mut declined = None;
    for r in dir
        .list_attestations_for(invitee)
        .await
        .map_err(|e| format!("list_attestations_for({invitee}): {e:#}"))?
    {
        if envelope_str(
            &r,
            ciris_persist::federation::envelope::paths::REFERENCES_ATTESTATION_ID,
        ) != Some(proposal_id)
        {
            continue;
        }
        match dimension_of(&r) {
            Some(ACCEPTANCE_DIMENSION) => accepted = Some(r),
            Some(DECLINE_DIMENSION) => declined = Some(r),
            _ => {}
        }
    }
    Ok((accepted, declined))
}

/// Has the proposer withdrawn `proposal_id` (a `withdraws` naming it)?
async fn withdrawn(dir: &dyn FederationDirectory, proposal_id: &str) -> Result<bool, String> {
    Ok(dir
        .list_attestations_referencing(proposal_id)
        .await
        .map_err(|e| format!("list_attestations_referencing({proposal_id}): {e:#}"))?
        .iter()
        .any(|r| r.attestation_type == attestation_type::WITHDRAWS))
}

/// **Every invitation into `group`, with its state** — `active` is the group's
/// roster by the fold (the caller's own read), so "joined" is a fact about the
/// roster and never inferred from the acceptance alone.
pub(crate) async fn group_invites(
    dir: &dyn FederationDirectory,
    scope: GroupScope,
    group: &str,
    active: &HashSet<String>,
) -> Result<Vec<(InviteView, Option<Attestation>)>, String> {
    let now = chrono::Utc::now();
    let mut out = Vec::new();
    for p in proposals_into(dir, scope, group).await? {
        let Some(invitee) = p.subject_key_ids.first().cloned() else {
            continue;
        };
        let (accepted, declined) = replies_to(dir, &invitee, &p.attestation_id).await?;
        // An acceptance SIGNED after the proposal lapsed seats nobody: persist
        // judges expiry on the two signed instants (`asserted_at` against
        // `expires_at`), never on a reader's clock, and so does this view.
        let accepted_in_time = accepted
            .as_ref()
            .is_some_and(|a| p.expires_at.is_none_or(|t| a.asserted_at <= t));
        let state = if active.contains(&invitee) && accepted.is_some() {
            STATE_JOINED
        } else if accepted_in_time {
            STATE_ACCEPTED
        } else if accepted.is_some() {
            STATE_EXPIRED
        } else if declined.is_some() {
            STATE_DECLINED
        } else if withdrawn(dir, &p.attestation_id).await? {
            STATE_WITHDRAWN
        } else if p.expires_at.is_some_and(|t| t <= now) {
            STATE_EXPIRED
        } else {
            STATE_PENDING
        };
        let reply_id = accepted
            .as_ref()
            .or(declined.as_ref())
            .map(|r| r.attestation_id.clone());
        out.push((
            InviteView {
                proposal_id: p.attestation_id.clone(),
                invitee_key_id: invitee,
                role: envelope_str(&p, "role").map(str::to_owned),
                proposer_key_id: p.attesting_key_id.clone(),
                proposed_at: p.asserted_at.to_rfc3339(),
                expires_at: p.expires_at.map(|t| t.to_rfc3339()),
                state,
                reply_id,
            },
            accepted,
        ));
    }
    Ok(out)
}

/// **Seat every accepted, unseated invitee of `group`** — the widening edge's
/// bridge performs on an acceptance's arrival, re-attempted here for the
/// window the bridge cannot cover (a node claimed after its replication
/// runtime started has no widener until restart — see `compose`'s
/// `membership_widener` block) and for an acceptance that arrived before its
/// proposal did. Same edge call ([`em::widen_on_acceptance`]), same
/// idempotence (an active member is `AlreadyMember`, nothing written).
///
/// Only a single-signature widening is attempted: under a quorum protocol
/// persist refuses it (the group's M-of-N lives on the growth row), and the
/// group seats the member through `…/changes/{envelope,cosign,assemble}` with
/// `action: add`. Those refusals are logged at debug and left for the quorum.
///
/// Returns the members this call seated.
pub(crate) async fn widen_held_acceptances(
    dir: &dyn FederationDirectory,
    invites: &[(InviteView, Option<Attestation>)],
    widener: &MembershipWidener,
) -> Vec<String> {
    let mut seated = Vec::new();
    for (view, acceptance) in invites {
        let (STATE_ACCEPTED, Some(acceptance)) = (view.state, acceptance) else {
            continue;
        };
        match em::widen_on_acceptance(dir, acceptance, widener).await {
            Ok(em::WidenOutcome::Widened { member_key_id, .. }) => {
                tracing::info!(
                    member = %member_key_id,
                    proposal = %view.proposal_id,
                    "membership: an accepted invitee seated (CIRISPersist#955)"
                );
                seated.push(member_key_id);
            }
            Ok(other) => tracing::debug!(
                proposal = %view.proposal_id, outcome = ?other,
                "membership: nothing to widen for this acceptance here"
            ),
            Err(e) => tracing::debug!(
                proposal = %view.proposal_id,
                rule = e.rule().unwrap_or("-"),
                error = %e,
                "membership: the single-signature widening was refused — under a quorum \
                 protocol the group seats the member through the change flow"
            ),
        }
    }
    if !seated.is_empty() {
        let _ = crate::compose::kick_replication("membership: accepted invitees seated");
    }
    seated
}

/// The invitation's `expires_at` from a client's `expires_in_days`.
#[allow(clippy::result_large_err)]
pub(crate) fn expiry(days: Option<i64>) -> Result<chrono::DateTime<chrono::Utc>, Response> {
    let days = days.unwrap_or(DEFAULT_INVITE_DAYS);
    let max_days = em::MEMBERSHIP_PROPOSAL_MAX_TTL_SECS / 86_400;
    if !(1..=max_days).contains(&days) {
        return Err(bad_expiry(format!(
            "expires_in_days {days} is outside 1..={max_days} (persist bounds a proposal at \
             {} s)",
            em::MEMBERSHIP_PROPOSAL_MAX_TTL_SECS
        )));
    }
    // A minute inside the bound: persist judges `expires_at − asserted_at`
    // against the row's own stamp, which is taken a moment after this.
    let bound = chrono::Duration::days(days).min(
        chrono::Duration::seconds(em::MEMBERSHIP_PROPOSAL_MAX_TTL_SECS)
            - chrono::Duration::minutes(1),
    );
    Ok(chrono::Utc::now() + bound)
}

/// The 202 an invitation answers with — `state: "invited"`, so no caller
/// mistakes an invitation for a membership (FSD §3).
pub(crate) fn invited(
    scope: GroupScope,
    group: &str,
    proposal: &Attestation,
    invitee: &str,
    role: Option<&str>,
) -> Response {
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "state": "invited",
            "proposal_id": proposal.attestation_id,
            "group_kind": kind_token(scope),
            "group_id": group,
            "invitee_key_id": invitee,
            "role": role,
            "expires_at": proposal.expires_at.map(|t| t.to_rfc3339()),
        })),
    )
        .into_response()
}

fn kind_token(scope: GroupScope) -> &'static str {
    match scope {
        GroupScope::Family => "family",
        GroupScope::Community => "community",
    }
}

/// Withdraw a pending invitation: a `withdraws` of the proposal signed by its
/// proposer (persist rule 1 — a row is withdrawn by its own attester), which
/// persist reads as expiring it. The CALLER must be the proposer.
pub(crate) async fn withdraw(
    dir: &dyn FederationDirectory,
    scope: GroupScope,
    group: &str,
    proposal_id: &str,
    capsule: &OwnerSignerCapsule,
) -> Response {
    let proposal = match dir.get_attestation(proposal_id).await {
        Ok(Some(p))
            if dimension_of(&p) == Some(PROPOSAL_DIMENSION)
                && group_of(&p, scope) == Some(group) =>
        {
            p
        }
        Ok(_) => {
            return invite_not_found(format!("{proposal_id} is not an invitation into {group}"))
        }
        Err(e) => return store_unavailable(format!("get_attestation: {e:#}")),
    };
    if proposal.attesting_key_id != capsule.edge_signer().key_id {
        return not_the_proposer(format!(
            "{proposal_id} was proposed by {}",
            proposal.attesting_key_id
        ));
    }
    let invitee = proposal
        .subject_key_ids
        .first()
        .cloned()
        .unwrap_or_default();
    match replies_to(dir, &invitee, proposal_id).await {
        Ok((None, None)) => {}
        Ok(_) => return invite_closed(format!("{proposal_id} was already answered")),
        Err(e) => return store_unavailable(e),
    }
    match withdrawn(dir, proposal_id).await {
        Ok(false) => {}
        Ok(true) => return invite_closed(format!("{proposal_id} was already withdrawn")),
        Err(e) => return store_unavailable(e),
    }
    let row = match ciris_edge::replication::attestation_bind::withdraws_attestation(
        &proposal,
        "invitation withdrawn",
        chrono::Utc::now(),
        capsule.edge_signer(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return signer_unavailable(e),
    };
    if let Err(e) = dir
        .put_attestation_authored(ciris_persist::federation::SignedAttestation {
            attestation: row.clone(),
        })
        .await
    {
        return membership_refused(format!("withdraw {proposal_id}: {e:#}"));
    }
    let _ = crate::compose::kick_replication("membership: invitation withdrawn");
    Json(serde_json::json!({
        "state": STATE_WITHDRAWN,
        "proposal_id": proposal_id,
        "withdrawal_id": row.attestation_id,
    }))
    .into_response()
}

// ─── The invitee's side: /v1/self/invites ───────────────────────────────────

#[derive(Clone)]
struct InboxState {
    engine: Arc<Engine>,
    user_seed_dir: std::path::PathBuf,
}

#[allow(clippy::result_large_err)]
fn gate(r: Result<OwnerCaller, GateRefusal>) -> Result<OwnerCaller, Response> {
    r.map_err(|e| match e {
        GateRefusal::NoSession => session_required(StatusCode::UNAUTHORIZED),
        GateRefusal::NotOwner | GateRefusal::Unowned => session_required(StatusCode::FORBIDDEN),
        GateRefusal::Delegated => delegate_may_not_answer(),
        GateRefusal::Store(d) => store_unavailable(d),
    })
}

async fn group_name(
    dir: &dyn FederationDirectory,
    scope: GroupScope,
    group: &str,
) -> Option<String> {
    match scope {
        GroupScope::Family => dir
            .lookup_family(group)
            .await
            .ok()
            .flatten()
            .map(|f| f.family_name),
        GroupScope::Community => dir
            .lookup_community(group)
            .await
            .ok()
            .flatten()
            .map(|c| c.community_name),
    }
}

/// `GET /v1/self/invites` — the inbox: every live invitation held here that
/// names this node's owner and that they have not answered, across families,
/// communities and pair rooms (edge's `pending_proposals_for`). A delegate may
/// read it; only the owner answers.
async fn inbox(State(st): State<InboxState>, headers: HeaderMap) -> Response {
    let caller = match gate(owner_caller(&st.engine, &headers, true).await) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let dir = st.engine.federation_directory();
    let pending = match em::pending_proposals_for(dir.as_ref(), &caller.owner_key_id).await {
        Ok(p) => p,
        Err(e) => return store_unavailable(e.to_string()),
    };
    let mut invites = Vec::with_capacity(pending.len());
    for p in pending {
        // Edge's inbox drops answered and lapsed proposals; a WITHDRAWN one
        // (the proposer's `withdraws`, which persist reads as expiring it) is
        // dropped here, so the invitee is never offered what is gone.
        match withdrawn(dir.as_ref(), &p.proposal.attestation_id).await {
            Ok(false) => {}
            Ok(true) => continue,
            Err(e) => return store_unavailable(e),
        }
        invites.push(serde_json::json!({
            "proposal_id": p.proposal.attestation_id,
            "group_kind": kind_token(p.scope),
            "group_id": p.group_key_id,
            "group_name": group_name(dir.as_ref(), p.scope, &p.group_key_id).await,
            "is_pair_room": p.group_key_id.starts_with(ciris_edge::chat::PAIR_COMMUNITY_PREFIX),
            "role": p.role,
            "proposer_key_id": p.proposal.attesting_key_id,
            "proposed_at": p.proposal.asserted_at.to_rfc3339(),
            "expires_at": p.expires_at.to_rfc3339(),
        }));
    }
    Json(serde_json::json!({
        "invitee_key_id": caller.owner_key_id,
        "invites": invites,
    }))
    .into_response()
}

async fn answer(st: InboxState, headers: HeaderMap, proposal_id: String, accept: bool) -> Response {
    let caller = match gate(owner_caller(&st.engine, &headers, false).await) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let dir = st.engine.federation_directory();
    let proposal = match dir.get_attestation(&proposal_id).await {
        Ok(Some(p)) if dimension_of(&p) == Some(PROPOSAL_DIMENSION) => p,
        Ok(_) => return invite_not_found(format!("{proposal_id} is not an invitation held here")),
        Err(e) => return store_unavailable(format!("get_attestation: {e:#}")),
    };
    if proposal.subject_key_ids.first().map(String::as_str) != Some(caller.owner_key_id.as_str()) {
        return not_the_invitee(format!(
            "{proposal_id} invites {:?}, not this node's owner",
            proposal.subject_key_ids.first()
        ));
    }
    // Do not ask the person to sign an answer to an invitation that has
    // visibly lapsed or been withdrawn. This is not the admission rule —
    // persist judges the signed instants wherever the rows land — only a
    // refusal to author a row that can no longer seat anyone, named by the
    // same id persist's rule maps to.
    let lapsed = proposal.expires_at.is_some_and(|t| t <= chrono::Utc::now());
    let pulled = match withdrawn(dir.as_ref(), &proposal_id).await {
        Ok(w) => w,
        Err(e) => return store_unavailable(e),
    };
    if lapsed || pulled {
        let group = GroupScope::of_row(&proposal)
            .and_then(|s| group_of(&proposal, s))
            .unwrap_or_default()
            .to_owned();
        return refused(&MembershipError::Refused {
            group_key_id: group,
            member_key_id: caller.owner_key_id.clone(),
            rule: em::RULE_PROPOSAL_EXPIRED,
        });
    }
    let capsule = match owner_signer_capsule::acquire(
        &st.engine,
        Some(&caller.bearer),
        &caller.owner_key_id,
        st.user_seed_dir.clone(),
    )
    .await
    {
        Ok(c) => c,
        Err(owner_signer_capsule::CapsuleRefusal::Delegated) => return delegate_may_not_answer(),
        Err(e) => return signer_unavailable(e.to_string()),
    };
    let reply = match em::reply(dir.as_ref(), &proposal_id, accept, capsule.edge_signer()).await {
        Ok(r) => r,
        Err(e) => return refused(&e),
    };
    let _ = crate::compose::kick_replication(if accept {
        "membership: invitation accepted"
    } else {
        "membership: invitation declined"
    });
    let scope = GroupScope::of_row(&proposal);
    tracing::info!(
        proposal = %proposal_id,
        accepted = accept,
        "membership: the invitee answered with their own signature (CIRISPersist#955)"
    );
    Json(serde_json::json!({
        "state": if accept { STATE_ACCEPTED } else { STATE_DECLINED },
        "proposal_id": proposal_id,
        "reply_id": reply.attestation_id,
        "group_kind": scope.map(kind_token),
        "group_id": scope.and_then(|s| group_of(&proposal, s)),
        // Accepting is consent, not membership: the group seats the member
        // (founder_only: the proposer's node on the acceptance's arrival; a
        // quorum group: when M of N sign the add).
        "awaiting": accept.then_some("the group's widening"),
    }))
    .into_response()
}

async fn accept(
    State(st): State<InboxState>,
    headers: HeaderMap,
    Path(proposal_id): Path<String>,
) -> Response {
    answer(st, headers, proposal_id, true).await
}

async fn decline(
    State(st): State<InboxState>,
    headers: HeaderMap,
    Path(proposal_id): Path<String>,
) -> Response {
    answer(st, headers, proposal_id, false).await
}

/// The invitee's routes (FSD §3). The group-side routes live with their group
/// (`family_api`, `communities`), where membership of the group is decided.
pub fn router(engine: Arc<Engine>, user_seed_dir: std::path::PathBuf) -> Router {
    use axum::routing::{get, post};
    Router::new()
        .route("/v1/self/invites", get(inbox))
        .route("/v1/self/invites/{proposal_id}/accept", post(accept))
        .route("/v1/self/invites/{proposal_id}/decline", post(decline))
        .with_state(InboxState {
            engine,
            user_seed_dir,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// persist's eight rule tokens each land on their OWN `membership.*` id —
    /// none falls through to the catch-all, and no two share one.
    #[tokio::test]
    async fn every_persist_rule_has_its_own_id() {
        let mut seen = HashSet::new();
        for rule in [
            em::RULE_ACCEPTANCE_UNRESOLVED,
            em::RULE_PROPOSAL_UNRESOLVED,
            em::RULE_DECLINED,
            em::RULE_PROPOSAL_EXPIRED,
            em::RULE_ACCEPTANCE_MISMATCH,
            em::RULE_REPLY_CONFLICT,
            em::RULE_FOUNDING_MEMBER_UNSIGNED,
            em::RULE_SUPERSEDE_CANNOT_ADD,
        ] {
            let r = refused(&MembershipError::Refused {
                group_key_id: "g".into(),
                member_key_id: "k".into(),
                rule,
            });
            let body = axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .expect("body");
            let v: serde_json::Value = serde_json::from_slice(&body).expect("json");
            let id = v["reason_id"].as_str().expect("reason_id").to_owned();
            assert!(id.starts_with("membership."), "{rule} -> {id}");
            assert_ne!(
                id, "membership.refused",
                "{rule} fell through to the catch-all"
            );
            assert!(seen.insert(id.clone()), "{rule} shares {id}");
        }
    }

    #[test]
    fn an_expiry_outside_persists_bound_is_refused_by_name() {
        assert!(expiry(Some(0)).is_err());
        assert!(expiry(Some(31)).is_err());
        let t = expiry(Some(30)).expect("thirty days is inside the bound");
        assert!(
            (t - chrono::Utc::now()).num_seconds() < em::MEMBERSHIP_PROPOSAL_MAX_TTL_SECS,
            "the stamp leaves room for the row's own asserted_at"
        );
        assert!(expiry(None).is_ok());
    }
}
