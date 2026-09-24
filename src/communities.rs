//! **Communities and affiliations — N-member rooms** (CIRISServer#594,
//! `FSD/ROSTER_AND_DRIVE_CRUD.md` §4).
//!
//! The pair room (`POST /v1/chat`) is a two-person `Community` whose id is
//! derived from the pair. This module is everything wider: a room founded by
//! the caller with any number of members, grown and shrunk on persist v48's
//! two roster planes, governed by the room's own declared
//! `consensus_protocol`, and read back through the one roster fold.
//!
//! | route | what it moves | the substrate door |
//! |---|---|---|
//! | `POST /v1/communities` | a `Community` record, owner-signed | `put_community` (`chat::signed_community`) |
//! | `GET /v1/communities` | the rooms the caller is ACTIVE in (pair rooms included) | fold over `list_communities_for_member` ∪ the widening plane |
//! | `GET /v1/communities/{id}` | record + effective roster + roles + appointed moderators | `effective_roster`, `appointed_moderators_of` |
//! | `POST /v1/communities/{id}/members` | a `CommunityMembershipWidening` | `put_community_membership_widening` |
//! | `DELETE /v1/communities/{id}/members/{key_id}` | a `CommunityMembershipRevocation` (rotates the DEK) | `put_community_membership_revocation` |
//! | `POST /v1/communities/{id}/members/{key_id}/role` | a widening carrying the new role | `put_community_membership_widening` |
//! | `POST /v1/communities/{id}/leave` | the caller's own revocation | `put_community_membership_revocation` |
//! | `DELETE /v1/communities/{id}` | a revocation of every active member | `put_community_membership_revocation` × N |
//! | `POST /v1/communities/{id}/changes/{envelope,cosign,assemble}` | the two-phase quorum flow | `build_membership_change_envelope`, `verify_membership_quorum` |
//!
//! # The rules this module keeps (FSD §1)
//!
//! * **The human signs.** Every record and every roster row is signed with the
//!   owner's fed-ID pen (`owner_signer_capsule::acquire`), never the node key.
//!   The pair room's record stays node-signed (`contacts_chat::start_chat`):
//!   its bytes are derived identically by both ends, and changing its signer
//!   would change nothing a reader can check while risking a roster fork.
//! * **Delegates never author roster changes** — every write names
//!   `CapabilityVerb::ChatAuthor`, which is on the never-delegatable list:
//!   a roster row signed under the owner's key outlives any delegation that
//!   asked for it. Reads name `ChatRead`, as the transcript does.
//! * **The roster is the FOLD.** Membership is `effective_roster` (record ∪
//!   widenings − revocations, latest event wins, a removal wins a tie). This
//!   module never reads `community.members` for a decision;
//!   `tests/no_raw_roster_reads.rs` fails the build if anything in `src/` does.
//! * **Governance is the room's own declared rule** — see [`Protocol`] and
//!   [`tally`]. Leaving is always your own act and never subject to it.
//! * **A non-member cannot find out a room is there**: every read and write
//!   answers `community.not_found` (404) for a room the caller is not active
//!   in, exactly as for a room that does not exist.
//!
//! # What persist does NOT enforce for us (CIRISPersist#908)
//!
//! The replicated widening and revocation doors verify the SIGNATURE, not the
//! signer's standing in the room. So the protocol is enforced HERE, before any
//! row this server authors is written; a row a peer authors is admitted by
//! persist alone until #908 lands.
//!
//! # What a widened member cannot do yet (CIRISPersist#907)
//!
//! persist's caller admission (`build_caller_admission` →
//! `list_communities_for_member_active`) walks the RECORD's members and
//! ignores the widening plane, so a member added through
//! `POST /v1/communities/{id}/members` is listed, shown and sealed to by the
//! fold — and still refused by the message read gate (`chat.not_a_member`).
//! The route is built anyway; `tests/community_crud.rs` pins the gap as an
//! ignored red test named for #907.
//!
//! This file deliberately allows `clippy::result_large_err`: its helpers
//! return the finished refusal `Response` as their error, the same shape the
//! rest of the chat surface uses, so a refusal is decided exactly once.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use ciris_edge::chat::{CHAT_ATTESTATION_PREFIX, PAIR_COMMUNITY_PREFIX};
use ciris_persist::federation::admission::{self, MEMBER_ROLE_FOUNDER};
use ciris_persist::federation::cohort::Cohort;
use ciris_persist::federation::types::{
    cohort_scope, consensus_protocol, Community, CommunityMember, CommunityMembershipWidening,
    SignedCommunityMembershipWidening,
};
use ciris_persist::federation::FederationDirectory;
use ciris_verify_core::threshold::{ThresholdError, ThresholdMember, ThresholdSignature};

use crate::auth::gate::CapabilityVerb;
use crate::auth::refusal::{refuse, refuse_with};
use crate::contacts_chat::{
    active_roster, bearer_of, ensure_owner_content_occurrence, require_owner, require_verb,
    ChatState, Owner,
};
use crate::owner_signer_capsule::OwnerSignerCapsule;

/// The `policy_blob` member that carries a room's audience tier — persist's
/// own documented home for the `cohort_scope` membership label
/// (`Community::policy_blob`, §8.1.13.3).
const TIER_POLICY_FIELD: &str = "cohort_scope";

/// The role word a client sends for an ordinary member. Stored as NO role on
/// the roster (persist's reading of `role: None`), so the two spellings of
/// "plain member" cannot diverge.
const MEMBER_ROLE_MEMBER: &str = "member";

/// Longest room name accepted. The name rides inside the signed record, and a
/// record is replicated to every member's node.
const MAX_NAME_CHARS: usize = 200;

/// Page ceiling for `GET /v1/communities` (FSD §1 rule 8: every list route
/// carries a resume cursor).
const MAX_LIST_LIMIT: usize = 500;
const DEFAULT_LIST_LIMIT: usize = 100;

/// Page size when walking the widening plane for rooms the caller was ADDED
/// to — persist indexes the record's members, not the widening plane's.
const WIDENING_SCAN_PAGE: u32 = 500;

// ─── Vocabulary ─────────────────────────────────────────────────────────────

/// A room's audience tier (FSD §4): `community`, or `affiliations` — the same
/// machinery at `Cohort::Affiliations`, whose version chain persist keeps
/// under its own discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    Community,
    Affiliations,
}

impl Tier {
    fn parse(s: &str) -> Option<Self> {
        match s {
            cohort_scope::COMMUNITY => Some(Self::Community),
            cohort_scope::AFFILIATIONS => Some(Self::Affiliations),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Community => cohort_scope::COMMUNITY,
            Self::Affiliations => cohort_scope::AFFILIATIONS,
        }
    }

    fn cohort(self) -> Cohort {
        match self {
            Self::Community => Cohort::Community,
            Self::Affiliations => Cohort::Affiliations,
        }
    }

    /// Read off the record's policy blob. Absent or anything else is
    /// `community` — the tier every pair room and every pre-#594 room has.
    fn of(record: &Community) -> Self {
        match record
            .policy_blob
            .as_ref()
            .and_then(|b| b.get(TIER_POLICY_FIELD))
            .and_then(serde_json::Value::as_str)
        {
            Some(cohort_scope::AFFILIATIONS) => Self::Affiliations,
            _ => Self::Community,
        }
    }
}

/// The room's declared governance rule, parsed. Only the four forms this
/// server can EVALUATE are accepted at create; a room that arrives from a peer
/// declaring `weighted:*` / `custom:*` can be read but not changed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    /// One active founder's signature (or, for a plain-member add/remove, an
    /// appointed moderator's).
    FounderOnly,
    /// Every active member (a removal does not wait on its own target).
    Unanimous,
    /// A strict majority of the active members.
    Majority,
    /// `quorum:M/N`, verified by persist's `verify_membership_quorum`.
    Quorum { m: usize, n: usize },
}

impl Protocol {
    fn parse(s: &str) -> Option<Self> {
        match s {
            consensus_protocol::FOUNDER_ONLY => Some(Self::FounderOnly),
            consensus_protocol::UNANIMOUS => Some(Self::Unanimous),
            consensus_protocol::MAJORITY => Some(Self::Majority),
            other => {
                let (m, n) = other
                    .strip_prefix(consensus_protocol::QUORUM_PREFIX)?
                    .split_once('/')?;
                let (m, n): (usize, usize) = (m.parse().ok()?, n.parse().ok()?);
                // Strict majority (`2M > N`), the only quorum verify admits:
                // a 1/2 room has two disjoint quorums.
                (m >= 1 && m <= n && m.checked_mul(2)? > n).then_some(Self::Quorum { m, n })
            }
        }
    }
}

fn strict_majority(n: usize) -> usize {
    n / 2 + 1
}

fn kind_of(community_id: &str) -> &'static str {
    if community_id.starts_with(PAIR_COMMUNITY_PREFIX) {
        "pair"
    } else {
        "room"
    }
}

/// Persist stores instants at millisecond resolution; a signature over finer
/// digits is a signature over bytes the row never carries.
fn to_ms(t: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(t.timestamp_millis()).unwrap_or(t)
}

/// `member` and an absent role are the same fact on the roster.
fn normalize_role(role: Option<&str>) -> Option<String> {
    match role.map(str::trim) {
        None | Some("") | Some(MEMBER_ROLE_MEMBER) => None,
        Some(r) => Some(r.to_owned()),
    }
}

fn role_token(role: Option<&str>) -> &str {
    role.unwrap_or(MEMBER_ROLE_MEMBER)
}

// ─── Refusals — one function per id, so one id is one sentence ──────────────

fn store_unavailable(what: impl std::fmt::Display) -> Response {
    refuse(
        StatusCode::SERVICE_UNAVAILABLE,
        "community.store_unavailable",
        format!("the directory could not be read or written: {what}"),
    )
}

fn not_found(community_id: &str) -> Response {
    // The SAME answer for "does not exist" and "you are not in it": a
    // non-member must not learn a room is there (FSD §3 "hidden, not refused").
    refuse(
        StatusCode::NOT_FOUND,
        "community.not_found",
        format!("no community {community_id:?} that you are an active member of"),
    )
}

fn malformed(detail: impl std::fmt::Display) -> Response {
    refuse(
        StatusCode::BAD_REQUEST,
        "community.malformed_body",
        format!("the request body is not what this route takes: {detail}"),
    )
}

fn not_authorized(protocol: &str, detail: impl std::fmt::Display) -> Response {
    refuse(
        StatusCode::FORBIDDEN,
        "community.not_authorized",
        format!("this room's consensus protocol ({protocol}) is not satisfied: {detail}"),
    )
}

fn not_a_member(key_id: &str) -> Response {
    refuse(
        StatusCode::CONFLICT,
        "community.not_a_member",
        format!("{key_id:?} is not an active member of this room"),
    )
}

fn already_member(key_id: &str) -> Response {
    refuse(
        StatusCode::CONFLICT,
        "community.already_member",
        format!("{key_id:?} is already an active member of this room"),
    )
}

fn last_founder(key_id: &str) -> Response {
    refuse(
        StatusCode::CONFLICT,
        "community.last_founder",
        format!(
            "{key_id:?} is the room's last founder and the room has other members — \
             appoint another founder first (POST …/members/{{key_id}}/role), or dissolve the room"
        ),
    )
}

fn pair_room_fixed(community_id: &str) -> Response {
    refuse(
        StatusCode::CONFLICT,
        "community.pair_room_fixed",
        format!(
            "{community_id:?} is a two-person room whose id is derived from the pair — its \
             roster IS its identity and cannot change. Open a room (POST /v1/communities) to \
             talk with more people"
        ),
    )
}

fn write_failed(detail: impl std::fmt::Display) -> Response {
    refuse(
        StatusCode::INTERNAL_SERVER_ERROR,
        "community.write_failed",
        format!("the roster change could not be written: {detail}"),
    )
}

fn change_stale(detail: impl std::fmt::Display) -> Response {
    refuse(
        StatusCode::CONFLICT,
        "community.change_stale",
        format!(
            "this change envelope no longer describes the room — its roster, roles or \
             protocol moved since it was built ({detail}). Build a fresh one with \
             POST …/changes/envelope"
        ),
    )
}

// ─── Gates ──────────────────────────────────────────────────────────────────

/// Every WRITE: an owner session, never a delegate (the verb is on the
/// never-list — checked before any existence read so a delegate learns
/// nothing), and the declared-conformance gate a federation-wire write needs.
async fn write_preamble(st: &ChatState, headers: &HeaderMap) -> Result<Owner, Response> {
    let owner = require_owner(st, headers).await?;
    if let Some(r) = require_verb(
        &owner,
        CapabilityVerb::ChatAuthor,
        "community.delegate_may_not_author",
    ) {
        return Err(r);
    }
    if let Some(r) = crate::conformance::require_op(&st.engine, CapabilityVerb::ChatCreate).await {
        return Err(r);
    }
    Ok(owner)
}

/// Every READ: an owner session, or a delegate granted `chat_read`.
async fn read_preamble(st: &ChatState, headers: &HeaderMap) -> Result<Owner, Response> {
    let owner = require_owner(st, headers).await?;
    if let Some(r) = require_verb(
        &owner,
        CapabilityVerb::ChatRead,
        "community.delegation_denied",
    ) {
        return Err(r);
    }
    Ok(owner)
}

/// The owner's fed-ID pen for this request — the person signs every roster row.
async fn pen(
    st: &ChatState,
    headers: &HeaderMap,
    owner: &Owner,
) -> Result<OwnerSignerCapsule, Response> {
    crate::owner_signer_capsule::acquire(
        &st.engine,
        bearer_of(headers),
        &owner.key_id,
        st.user_seed_dir.clone(),
    )
    .await
    .map_err(|e| {
        refuse(
            StatusCode::FORBIDDEN,
            "community.author_signer_unavailable",
            format!(
                "a room's roster is signed by the person who changes it, and this node cannot \
                 wield that identity right now: {e}"
            ),
        )
    })
}

/// The member must be a CONTACT whose live grant covers `chat:` — the same
/// rule `POST /v1/chat` applies (`contacts_chat::start_chat`), for the same
/// reason: a member this node does not replicate chat to is in a room whose
/// messages never reach them.
async fn require_contact(st: &ChatState, owner: &Owner, key_id: &str) -> Result<(), Response> {
    match crate::peer::contact_grant_prefixes(&st.engine, &owner.node_key_id, key_id).await {
        Ok(Some(prefixes)) if prefixes.iter().any(|p| p == CHAT_ATTESTATION_PREFIX) => Ok(()),
        Ok(Some(prefixes)) => Err(refuse(
            StatusCode::FORBIDDEN,
            "community.not_a_contact",
            format!(
                "{key_id:?} is a consent peer but its live grant does not cover \
                 {CHAT_ATTESTATION_PREFIX:?} (it covers {prefixes:?}) — POST /v1/contacts to widen it"
            ),
        )),
        Ok(None) => Err(refuse(
            StatusCode::FORBIDDEN,
            "community.not_a_contact",
            format!("{key_id:?} is not a contact — POST /v1/contacts first"),
        )),
        Err(e) => Err(store_unavailable(format!("consent peer set: {e:#}"))),
    }
}

// ─── The room, as the fold sees it ──────────────────────────────────────────

/// A room: its record (identity, name, protocol, tier) and its ACTIVE roster
/// by the fold. The record's own `members` is never consulted for membership.
struct Room {
    record: Community,
    roster: Vec<CommunityMember>,
    tier: Tier,
}

impl Room {
    fn id(&self) -> &str {
        &self.record.community_key_id
    }

    fn is_pair(&self) -> bool {
        self.id().starts_with(PAIR_COMMUNITY_PREFIX)
    }

    fn member(&self, key_id: &str) -> Option<&CommunityMember> {
        self.roster.iter().find(|m| m.key_id == key_id)
    }

    fn is_founder(&self, key_id: &str) -> bool {
        self.member(key_id)
            .is_some_and(|m| m.role.as_deref() == Some(MEMBER_ROLE_FOUNDER))
    }

    fn founders(&self) -> Vec<String> {
        self.roster
            .iter()
            .filter(|m| m.role.as_deref() == Some(MEMBER_ROLE_FOUNDER))
            .map(|m| m.key_id.clone())
            .collect()
    }

    /// Would removing (or demoting) `key_id` leave a room with members and no
    /// founder? A founderless room has no authority root, so under
    /// `founder_only` nobody could ever change it again and no named moderator
    /// exists (CC 4.5.4) — the reason edge refuses to BUILD one.
    fn orphans_if_gone(&self, key_id: &str) -> bool {
        self.is_founder(key_id) && self.founders().len() == 1 && self.roster.len() > 1
    }
}

async fn load_room(st: &ChatState, community_id: &str) -> Result<Option<Room>, Response> {
    let dir = st.engine.federation_directory();
    let Some(record) = dir
        .lookup_community(community_id)
        .await
        .map_err(|e| store_unavailable(format!("lookup_community: {e:#}")))?
    else {
        return Ok(None);
    };
    let roster = active_roster(&*dir, &record)
        .await
        .map_err(store_unavailable)?;
    let tier = Tier::of(&record);
    Ok(Some(Room {
        record,
        roster,
        tier,
    }))
}

/// The room, or `community.not_found` — for a room that does not exist AND for
/// one the caller is not active in.
async fn load_room_as_member(
    st: &ChatState,
    owner: &Owner,
    community_id: &str,
) -> Result<Room, Response> {
    match load_room(st, community_id).await? {
        Some(room) if room.member(&owner.key_id).is_some() => Ok(room),
        _ => Err(not_found(community_id)),
    }
}

/// The next roster instant for `room`: now, at persist's resolution, and
/// strictly after every event already on either plane. The fold orders by
/// `effective_at` and a removal wins a tie — so a re-add in the same
/// millisecond as a removal would be written and silently lose. The revocation
/// door refuses a future-dated instant, so this waits for the clock rather
/// than stepping past it.
async fn next_event_instant(
    dir: &dyn FederationDirectory,
    room: &str,
) -> Result<chrono::DateTime<chrono::Utc>, String> {
    let widenings = dir
        .list_community_membership_widenings_for(room)
        .await
        .map_err(|e| format!("list widenings: {e:#}"))?;
    let revocations = dir
        .list_community_membership_revocations_for(room)
        .await
        .map_err(|e| format!("list revocations: {e:#}"))?;
    let latest = widenings
        .iter()
        .map(|w| w.effective_at)
        .chain(revocations.iter().map(|r| r.effective_at))
        .max();
    for _ in 0..20 {
        let now = to_ms(chrono::Utc::now());
        match latest {
            Some(l) if now <= l => {
                let wait = (l - now).num_milliseconds().clamp(0, 100) as u64 + 1;
                tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
            }
            _ => return Ok(now),
        }
    }
    Err(format!(
        "the room's latest roster event ({latest:?}) is dated in the future — a peer's clock \
         is ahead; the next change can be written once that instant has passed"
    ))
}

// ─── The change, as a signed envelope ───────────────────────────────────────

/// One roster change. `leave` is not here: leaving is always your own act and
/// is never put to a quorum (FSD §1 rule 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum ChangeOp {
    /// Widen the roster by one member.
    Add {
        key_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        role: Option<String>,
    },
    /// Remove a member (a revocation, which rotates the room's DEK).
    Remove { key_id: String },
    /// Change a member's role.
    Role { key_id: String, role: String },
    /// Remove every member: the room's terminal act.
    Dissolve,
}

impl ChangeOp {
    /// Canonical form: roles normalized, key ids trimmed — so the envelope
    /// two members sign is the same bytes whatever spelling a client sent.
    fn normalized(self) -> Self {
        match self {
            Self::Add { key_id, role } => Self::Add {
                key_id: key_id.trim().to_owned(),
                role: normalize_role(role.as_deref()),
            },
            Self::Remove { key_id } => Self::Remove {
                key_id: key_id.trim().to_owned(),
            },
            Self::Role { key_id, role } => Self::Role {
                key_id: key_id.trim().to_owned(),
                role: normalize_role(Some(&role)).unwrap_or_else(|| MEMBER_ROLE_MEMBER.to_owned()),
            },
            Self::Dissolve => Self::Dissolve,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Add { .. } => "add",
            Self::Remove { .. } => "remove",
            Self::Role { .. } => "role",
            Self::Dissolve => "dissolve",
        }
    }

    /// Does this change touch only non-founder seats? The one case an
    /// appointed moderator's signature authorizes under `founder_only`.
    fn touches_only_plain_members(&self, room: &Room) -> bool {
        match self {
            Self::Add { role, .. } => role.as_deref() != Some(MEMBER_ROLE_FOUNDER),
            Self::Remove { key_id } => !room.is_founder(key_id),
            Self::Role { .. } | Self::Dissolve => false,
        }
    }

    /// The target of a removal, which a unanimous room does not wait on.
    fn removal_target(&self) -> Option<&str> {
        match self {
            Self::Remove { key_id } => Some(key_id),
            _ => None,
        }
    }
}

/// The roster after `op`, as `(key_id, role)`.
fn roster_after(room: &Room, op: &ChangeOp) -> Vec<(String, Option<String>)> {
    let mut out: Vec<(String, Option<String>)> = room
        .roster
        .iter()
        .map(|m| (m.key_id.clone(), m.role.clone()))
        .collect();
    match op {
        ChangeOp::Add { key_id, role } => out.push((key_id.clone(), role.clone())),
        ChangeOp::Remove { key_id } => out.retain(|(k, _)| k != key_id),
        ChangeOp::Role { key_id, role } => {
            for (k, r) in &mut out {
                if k == key_id {
                    *r = normalize_role(Some(role));
                }
            }
        }
        ChangeOp::Dissolve => out.clear(),
    }
    out
}

fn roster_json(roster: &[(String, Option<String>)]) -> serde_json::Value {
    serde_json::Value::Array(
        roster
            .iter()
            .map(|(k, r)| serde_json::json!({ "key_id": k, "role": role_token(r.as_deref()) }))
            .collect(),
    )
}

/// The canonical change envelope: persist's own membership-change payload
/// (`build_membership_change_envelope` — the prior roster BY THE FOLD, the new
/// roster, the protocol, and the `supersedes.prior_member_key_ids`
/// anti-replay binding verify checks) plus a `community_change` member naming
/// the op and binding the prior and new ROLES, which persist's payload does
/// not carry. Every signer signs the JCS bytes of the whole object.
async fn build_change(
    st: &ChatState,
    room: &Room,
    op: &ChangeOp,
) -> Result<serde_json::Value, Response> {
    let new_roster = roster_after(room, op);
    let new_ids: Vec<String> = new_roster.iter().map(|(k, _)| k.clone()).collect();
    // A quorum room's `quorum:M/N` names its roster size, and verify refuses a
    // payload whose N is not the new member count — so a change that moves the
    // count takes persist's strict-majority default for the new N. Anything
    // else carries the room's own protocol through unchanged.
    let protocol = match Protocol::parse(&room.record.consensus_protocol) {
        Some(Protocol::Quorum { n, .. })
            if n != new_ids.len() && !matches!(op, ChangeOp::Dissolve) =>
        {
            None
        }
        _ => Some(room.record.consensus_protocol.clone()),
    };
    let mut env = st
        .engine
        .federation_directory()
        .build_membership_change_envelope(
            room.tier.cohort(),
            room.id(),
            &new_ids,
            false,
            protocol.as_deref(),
        )
        .await
        .map_err(|e| store_unavailable(format!("build_membership_change_envelope: {e:#}")))?;
    let prior: Vec<(String, Option<String>)> = room
        .roster
        .iter()
        .map(|m| (m.key_id.clone(), m.role.clone()))
        .collect();
    if let Some(obj) = env.as_object_mut() {
        obj.insert(
            "community_change".to_owned(),
            serde_json::json!({
                "op": op,
                "tier": room.tier.as_str(),
                "prior_roster": roster_json(&prior),
                "new_roster": roster_json(&new_roster),
            }),
        );
    }
    Ok(env)
}

fn signing_bytes(env: &serde_json::Value) -> Result<Vec<u8>, Response> {
    ciris_verify_core::jcs::canonicalize(env)
        .map_err(|e| write_failed(format!("canonicalize the change envelope: {e}")))
}

/// The caller's own cosignature over the envelope — bound hybrid (ML-DSA-65
/// over `bytes ‖ ed25519_sig`), the shape verify's threshold primitive counts.
async fn sign_change(
    pen: &OwnerSignerCapsule,
    env: &serde_json::Value,
) -> Result<ThresholdSignature, Response> {
    let bytes = signing_bytes(env)?;
    let (ed, pqc) =
        ciris_edge::identity::sign_bound_hybrid(pen.edge_signer(), &bytes, "community change")
            .await
            .map_err(write_failed)?;
    Ok(ThresholdSignature {
        member_id: pen.key_id().to_owned(),
        ed25519_signature_base64: ed,
        mldsa65_signature_base64: pqc,
    })
}

/// A submitted envelope, checked against the room AS IT IS NOW: rebuilt from
/// its own `op` and compared whole. Anything that moved — a member, a role,
/// the protocol — makes it stale; this is the anti-replay binding for the
/// parts persist's `supersedes` block does not cover (roles, the op itself).
async fn check_envelope_current(
    st: &ChatState,
    room: &Room,
    env: &serde_json::Value,
) -> Result<ChangeOp, Response> {
    let op: ChangeOp = env
        .get("community_change")
        .and_then(|c| c.get("op"))
        .cloned()
        .ok_or_else(|| malformed("change_envelope.community_change.op is missing"))
        .and_then(|v| serde_json::from_value(v).map_err(|e| malformed(format!("op: {e}"))))?;
    if env.get("family_key_id").and_then(serde_json::Value::as_str) != Some(room.id()) {
        return Err(change_stale("it names a different room"));
    }
    let expected = build_change(st, room, &op).await?;
    if &expected != env {
        return Err(change_stale("the rebuilt envelope differs"));
    }
    Ok(op)
}

/// How far the signatures on a change get toward the room's protocol.
struct Tally {
    valid: usize,
    required: usize,
    eligible: BTreeSet<String>,
    protocol: String,
}

impl Tally {
    fn met(&self) -> bool {
        self.valid >= self.required
    }
}

/// **Who may authorize `op` in `room`, and how many of them signed.**
///
/// | protocol | eligible signers | required |
/// |---|---|---|
/// | `founder_only` | active founders (+ appointed `moderate` duty holders, for a plain-member add/remove) | 1 |
/// | `unanimous` | every active member except a removal's own target | all of them |
/// | `majority` | every active member | strict majority |
/// | `quorum:M/N` | every active member | M (persist re-verifies on apply) |
///
/// Counted by verify's `verify_threshold_signatures` over the eligible
/// members' REGISTERED hybrid pubkeys: distinct signers only, both halves
/// required, a signature by anyone not eligible silently not counted.
async fn tally(
    st: &ChatState,
    room: &Room,
    op: &ChangeOp,
    env: &serde_json::Value,
    signatures: &[ThresholdSignature],
) -> Result<Tally, Response> {
    let dir = st.engine.federation_directory();
    let protocol_str = room.record.consensus_protocol.clone();
    let Some(protocol) = Protocol::parse(&protocol_str) else {
        return Err(not_authorized(
            &protocol_str,
            "this server evaluates founder_only, unanimous, majority and quorum:M/N only",
        ));
    };
    let everyone: BTreeSet<String> = room.roster.iter().map(|m| m.key_id.clone()).collect();
    let (eligible, required): (BTreeSet<String>, usize) = match protocol {
        Protocol::FounderOnly => {
            let mut e: BTreeSet<String> = room.founders().into_iter().collect();
            if op.touches_only_plain_members(room) {
                // An APPOINTED roster-duty holder: a founder-rooted,
                // `moderate`-scoped `delegates_to` chain (persist's
                // `appointed_moderators_of`, CIRISPersist#591) — not the
                // widened "anyone who could appoint" set.
                let appointed = admission::appointed_moderators_of(
                    dir.as_ref(),
                    room.id(),
                    admission::DELEGATION_SCOPE_MODERATE,
                )
                .await
                .map_err(|e| store_unavailable(format!("appointed_moderators_of: {e:#}")))?;
                e.extend(appointed.into_iter().filter(|k| everyone.contains(k)));
            }
            (e, 1)
        }
        Protocol::Unanimous => {
            let e: BTreeSet<String> = everyone
                .iter()
                .filter(|k| Some(k.as_str()) != op.removal_target())
                .cloned()
                .collect();
            let n = e.len();
            (e, n)
        }
        Protocol::Majority => {
            let n = strict_majority(everyone.len());
            (everyone.clone(), n)
        }
        Protocol::Quorum { m, n } => {
            let required = if n == everyone.len() {
                m
            } else {
                strict_majority(everyone.len())
            };
            (everyone.clone(), required)
        }
    };
    let mut members: Vec<ThresholdMember> = Vec::with_capacity(eligible.len());
    for k in &eligible {
        if let Some(rec) = dir
            .lookup_public_key(k)
            .await
            .map_err(|e| store_unavailable(format!("lookup_public_key({k}): {e:#}")))?
        {
            members.push(ThresholdMember {
                member_id: rec.key_id,
                ed25519_public_key_base64: rec.pubkey_ed25519_base64,
                mldsa65_public_key_base64: rec.pubkey_ml_dsa_65_base64,
                role: None,
            });
        }
    }
    let bytes = signing_bytes(env)?;
    let valid = if members.is_empty() {
        0
    } else {
        match ciris_verify_core::threshold::verify_threshold_signatures(
            &bytes, &members, signatures, 1,
        ) {
            Ok(v) => v,
            Err(ThresholdError::Insufficient { valid, .. }) => valid,
            Err(e) => return Err(not_authorized(&protocol_str, format!("{e:?}"))),
        }
    };
    Ok(Tally {
        valid,
        required: required.max(1),
        eligible,
        protocol: protocol_str,
    })
}

// ─── Applying an authorized change ──────────────────────────────────────────

/// Write one widening through persist's REPLICATED door. Not the local
/// `add_community_member`: that door no-ops when the member is already active
/// at the instant (so a role change could never be written), and after a
/// quorum re-baseline it would see the member on the new record and write
/// nothing a peer can fold. The protocol was enforced before this is reached
/// (the door itself checks only the signature — CIRISPersist#908).
async fn put_widening(
    dir: &dyn FederationDirectory,
    room: &str,
    member_key_id: &str,
    role: Option<&str>,
    at: chrono::DateTime<chrono::Utc>,
    pen: &OwnerSignerCapsule,
) -> Result<(), String> {
    let (member, spec) = ciris_edge::community_roster::community_membership_widening(
        dir,
        room,
        member_key_id,
        role,
        at,
        pen.edge_signer(),
    )
    .await?;
    dir.put_community_membership_widening(SignedCommunityMembershipWidening {
        community_membership_widening: CommunityMembershipWidening {
            community_key_id: room.to_owned(),
            member_key_id: member.key_id,
            joined_at: member.joined_at,
            effective_at: member.joined_at,
            role: member.role,
            persist_row_hash: String::new(),
        },
        authority_key_id: spec.authority_key_id,
        scrub_signature_classical: spec.scrub_signature_classical,
        scrub_signature_pqc: spec.scrub_signature_pqc,
    })
    .await
    .map_err(|e| format!("put_community_membership_widening: {e:#}"))
}

/// Write one revocation through persist's door (rotates the room's DEK in the
/// same transaction). Direct, not edge's `revoke_community_member`: that helper
/// skips the write when the fold already lacks the member, which after a
/// quorum re-baseline is every removal — and the peers, who hold the old
/// record, would never learn of it.
async fn put_revocation(
    dir: &dyn FederationDirectory,
    room: &str,
    member_key_id: &str,
    at: chrono::DateTime<chrono::Utc>,
    reason: &str,
    pen: &OwnerSignerCapsule,
) -> Result<(), String> {
    let signed = ciris_edge::community_roster::community_membership_revocation(
        room,
        member_key_id,
        at,
        Some(reason),
        &[],
        pen.edge_signer(),
    )
    .await?;
    dir.put_community_membership_revocation(signed)
        .await
        .map_err(|e| format!("put_community_membership_revocation: {e:#}"))
}

/// A `quorum:M/N` room's change goes through persist's own quorum door FIRST:
/// `supersede_{community,affiliations}_with_quorum` runs
/// `verify_membership_quorum` over the envelope and the cosignatures and
/// re-baselines the record to the new roster and protocol. Without the
/// re-baseline the record's `quorum:M/N` would keep naming the OLD size, and
/// verify refuses a prior envelope whose N is not its member count — the
/// room's second size-changing change could never be authorized.
async fn quorum_rebaseline(
    st: &ChatState,
    room: &Room,
    op: &ChangeOp,
    env: &serde_json::Value,
    signatures: &[ThresholdSignature],
    pen: &OwnerSignerCapsule,
) -> Result<(), Response> {
    let protocol = env
        .get("consensus_protocol")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(&room.record.consensus_protocol)
        .to_owned();
    let now = to_ms(chrono::Utc::now());
    let members: Vec<(String, Option<String>)> = roster_after(room, op);
    let joined: BTreeMap<&str, chrono::DateTime<chrono::Utc>> = room
        .roster
        .iter()
        .map(|m| (m.key_id.as_str(), m.joined_at))
        .collect();
    let new_record = Community {
        community_key_id: room.record.community_key_id.clone(),
        community_name: room.record.community_name.clone(),
        members: members
            .iter()
            .map(|(k, r)| CommunityMember {
                key_id: k.clone(),
                joined_at: joined.get(k.as_str()).copied().unwrap_or(now),
                role: r.clone(),
            })
            .collect(),
        founded_at: room.record.founded_at,
        consensus_protocol: protocol.clone(),
        policy_blob: room.record.policy_blob.clone(),
        persist_row_hash: String::new(),
    };
    let signed = ciris_edge::chat::signed_community(new_record, pen.edge_signer())
        .await
        .map_err(write_failed)?;
    let dir = st.engine.federation_directory();
    let out = match room.tier {
        Tier::Community => {
            dir.supersede_community_with_quorum(signed, env.clone(), signatures.to_vec())
                .await
        }
        Tier::Affiliations => {
            dir.supersede_affiliations_with_quorum(signed, env.clone(), signatures.to_vec())
                .await
        }
    };
    out.map(|_| ()).map_err(|e| {
        not_authorized(
            &room.record.consensus_protocol,
            format!("persist's verify_membership_quorum refused the change: {e:#}"),
        )
    })
}

/// Apply an AUTHORIZED change, signed by the caller's pen. Returns the room's
/// roster after the change, by the fold.
async fn apply_change(
    st: &ChatState,
    room: &Room,
    op: &ChangeOp,
    env: &serde_json::Value,
    signatures: &[ThresholdSignature],
    pen: &OwnerSignerCapsule,
) -> Result<Vec<CommunityMember>, Response> {
    if matches!(
        Protocol::parse(&room.record.consensus_protocol),
        Some(Protocol::Quorum { .. })
    ) && !matches!(op, ChangeOp::Dissolve)
    {
        quorum_rebaseline(st, room, op, env, signatures, pen).await?;
    }
    let dir = st.engine.federation_directory();
    let at = next_event_instant(dir.as_ref(), room.id())
        .await
        .map_err(write_failed)?;
    match op {
        ChangeOp::Add { key_id, role } => {
            put_widening(dir.as_ref(), room.id(), key_id, role.as_deref(), at, pen)
                .await
                .map_err(write_failed)?;
        }
        ChangeOp::Role { key_id, role } => {
            put_widening(
                dir.as_ref(),
                room.id(),
                key_id,
                normalize_role(Some(role)).as_deref(),
                at,
                pen,
            )
            .await
            .map_err(write_failed)?;
        }
        ChangeOp::Remove { key_id } => {
            put_revocation(dir.as_ref(), room.id(), key_id, at, "removed", pen)
                .await
                .map_err(write_failed)?;
        }
        ChangeOp::Dissolve => {
            // Everyone else first, the signer last: every revocation is
            // written by a member who is still active when it is written.
            let mut order: Vec<&str> = room
                .roster
                .iter()
                .map(|m| m.key_id.as_str())
                .filter(|k| *k != pen.key_id())
                .collect();
            if room.member(pen.key_id()).is_some() {
                order.push(pen.key_id());
            }
            for (i, k) in order.iter().enumerate() {
                let at = if i == 0 {
                    at
                } else {
                    next_event_instant(dir.as_ref(), room.id())
                        .await
                        .map_err(write_failed)?
                };
                put_revocation(dir.as_ref(), room.id(), k, at, "dissolved", pen)
                    .await
                    .map_err(write_failed)?;
            }
        }
    }
    crate::compose::kick_replication("community roster changed");
    tracing::info!(
        room = %room.id(),
        op = op.name(),
        author = %pen.key_id(),
        "communities: roster change applied — rows signed by the owner's fed-ID"
    );
    let record = dir
        .lookup_community(room.id())
        .await
        .map_err(|e| store_unavailable(format!("lookup_community: {e:#}")))?
        .ok_or_else(|| not_found(room.id()))?;
    active_roster(&*dir, &record)
        .await
        .map_err(store_unavailable)
}

/// The preconditions of `op` that do not depend on who signs it.
async fn precheck(
    st: &ChatState,
    owner: &Owner,
    room: &Room,
    op: &ChangeOp,
) -> Result<(), Response> {
    if room.is_pair() {
        return Err(pair_room_fixed(room.id()));
    }
    match op {
        ChangeOp::Add { key_id, .. } => {
            if key_id.is_empty() {
                return Err(malformed("key_id must be a non-empty federation key id"));
            }
            if room.member(key_id).is_some() {
                return Err(already_member(key_id));
            }
            require_contact(st, owner, key_id).await?;
        }
        ChangeOp::Remove { key_id } => {
            if room.member(key_id).is_none() {
                return Err(not_a_member(key_id));
            }
            if room.orphans_if_gone(key_id) {
                return Err(last_founder(key_id));
            }
        }
        ChangeOp::Role { key_id, role } => {
            if room.member(key_id).is_none() {
                return Err(not_a_member(key_id));
            }
            if role.as_str() != MEMBER_ROLE_FOUNDER && room.orphans_if_gone(key_id) {
                return Err(last_founder(key_id));
            }
        }
        ChangeOp::Dissolve => {}
    }
    Ok(())
}

fn member_json(m: &CommunityMember) -> serde_json::Value {
    serde_json::json!({
        "key_id": m.key_id,
        "role": role_token(m.role.as_deref()),
        "joined_at": m.joined_at.to_rfc3339(),
    })
}

fn applied(room: &Room, op: &ChangeOp, roster: &[CommunityMember]) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "community_id": room.id(),
            "op": op.name(),
            "applied": true,
            "members": roster.iter().map(member_json).collect::<Vec<_>>(),
        })),
    )
        .into_response()
}

/// A direct roster route: the caller's own signature is the only one offered.
/// Enough under `founder_only` (for a founder) and in any room where one
/// signature meets the protocol; otherwise the answer is
/// `community.quorum_pending` WITH the envelope and the caller's signature, so
/// the client can collect the rest through `…/changes/cosign` and finish with
/// `…/changes/assemble`.
async fn direct_change(
    st: &ChatState,
    headers: &HeaderMap,
    owner: &Owner,
    room: Room,
    op: ChangeOp,
) -> Response {
    if let Err(r) = precheck(st, owner, &room, &op).await {
        return r;
    }
    let pen = match pen(st, headers, owner).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let env = match build_change(st, &room, &op).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let mine = match sign_change(&pen, &env).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let sigs = vec![mine];
    let t = match tally(st, &room, &op, &env, &sigs).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if !t.eligible.contains(&owner.key_id) {
        return not_authorized(
            &t.protocol,
            format!(
                "{:?} cannot authorize a {} here — the eligible signers are {:?}",
                owner.key_id,
                op.name(),
                t.eligible
            ),
        );
    }
    if !t.met() {
        return quorum_pending(&t, &env, &sigs);
    }
    match apply_change(st, &room, &op, &env, &sigs, &pen).await {
        Ok(roster) => applied(&room, &op, &roster),
        Err(r) => r,
    }
}

fn quorum_pending(t: &Tally, env: &serde_json::Value, sigs: &[ThresholdSignature]) -> Response {
    use base64::Engine as _;
    let bytes = ciris_verify_core::jcs::canonicalize(env).unwrap_or_default();
    refuse_with(
        StatusCode::CONFLICT,
        "community.quorum_pending",
        format!(
            "{} of {} required signature(s) under {} — collect the rest with \
             POST …/changes/cosign on each signer's node, then POST …/changes/assemble",
            t.valid, t.required, t.protocol
        ),
        serde_json::json!({
            "change_envelope": env,
            "signing_bytes_base64": base64::engine::general_purpose::STANDARD.encode(bytes),
            "signatures": sigs,
            "valid": t.valid,
            "required": t.required,
            "eligible_signers": t.eligible,
            "consensus_protocol": t.protocol,
        }),
    )
}

// ─── Routes ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CreateRequest {
    name: String,
    #[serde(default)]
    members: Vec<String>,
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    consensus_protocol: Option<String>,
}

/// `POST /v1/communities` — found a room. The caller is its founder; each
/// initial member must be a contact whose grant covers `chat:`. A member named
/// at CREATE is on the record, which every reader — persist's admission
/// included — sees; a member added later is on the widening plane.
async fn create_community(
    State(st): State<ChatState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let owner = match write_preamble(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let req: CreateRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return malformed(format!(
                "expected {{\"name\": \"…\", \"members\"?: […]}}: {e}"
            ))
        }
    };
    let name = req.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return refuse(
            StatusCode::BAD_REQUEST,
            "community.name_empty",
            format!("a room needs a name of 1 to {MAX_NAME_CHARS} characters"),
        );
    }
    let tier = match req.tier.as_deref().map(str::trim) {
        None | Some("") => Tier::Community,
        Some(t) => match Tier::parse(t) {
            Some(t) => t,
            None => {
                return refuse(
                    StatusCode::BAD_REQUEST,
                    "community.bad_tier",
                    format!("tier {t:?} is not one of \"community\", \"affiliations\""),
                )
            }
        },
    };
    let mut members: Vec<String> = Vec::new();
    for m in &req.members {
        let m = m.trim();
        if m.is_empty() {
            return malformed("members must be non-empty federation key ids");
        }
        if m != owner.key_id && !members.iter().any(|x| x == m) {
            members.push(m.to_owned());
        }
    }
    let protocol = req
        .consensus_protocol
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .unwrap_or(consensus_protocol::FOUNDER_ONLY)
        .to_owned();
    match Protocol::parse(&protocol) {
        Some(Protocol::Quorum { n, .. }) if n != members.len() + 1 => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "community.bad_consensus_protocol",
                format!(
                    "{protocol:?} names {n} member(s) but the room is founded with {} — a \
                     quorum's N is its roster size",
                    members.len() + 1
                ),
            )
        }
        Some(_) => {}
        None => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "community.bad_consensus_protocol",
                format!(
                    "{protocol:?} is not one of founder_only, unanimous, majority, quorum:M/N \
                     (a strict majority, 2M > N)"
                ),
            )
        }
    }
    for m in &members {
        if let Err(r) = require_contact(&st, &owner, m).await {
            return r;
        }
    }
    let pen = match pen(&st, &headers, &owner).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let community_id = ciris_edge::chat::new_room_community_key_id();
    let founded_at = to_ms(chrono::Utc::now());
    let mut roster: Vec<(&str, Option<&str>)> =
        vec![(owner.key_id.as_str(), Some(MEMBER_ROLE_FOUNDER))];
    roster.extend(members.iter().map(|m| (m.as_str(), None)));
    let mut record =
        match ciris_edge::chat::community(&community_id, &name, &roster, &protocol, founded_at) {
            Ok(r) => r,
            Err(e) => return malformed(e),
        };
    if tier == Tier::Affiliations {
        record.policy_blob = Some(serde_json::json!({ TIER_POLICY_FIELD: tier.as_str() }));
    }
    let signed = match ciris_edge::chat::signed_community(record, pen.edge_signer()).await {
        Ok(s) => s,
        Err(e) => return write_failed(e),
    };
    let dir = st.engine.federation_directory();
    if let Err(e) = dir.put_community(signed).await {
        return write_failed(format!("put_community: {e:#}"));
    }
    ensure_owner_content_occurrence(&st, &owner.key_id).await;
    crate::compose::kick_replication("community room founded");
    let Ok(Some(room)) = load_room(&st, &community_id).await else {
        return store_unavailable("the room was written and could not be read back");
    };
    tracing::info!(
        room = %community_id,
        founder = %owner.key_id,
        members = room.roster.len(),
        tier = tier.as_str(),
        protocol = %protocol,
        "communities: room founded — record signed by the owner's fed-ID"
    );
    (
        StatusCode::CREATED,
        Json(room_json(&st, &room, &owner, false).await),
    )
        .into_response()
}

/// The room as the client renders it. `detail` adds the appointed moderators
/// and the plane counts.
async fn room_json(st: &ChatState, room: &Room, owner: &Owner, detail: bool) -> serde_json::Value {
    let mut roles: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for m in &room.roster {
        roles
            .entry(role_token(m.role.as_deref()))
            .or_default()
            .push(m.key_id.as_str());
    }
    let mut v = serde_json::json!({
        "community_id": room.id(),
        "name": room.record.community_name,
        "kind": kind_of(room.id()),
        "tier": room.tier.as_str(),
        // The row envelope's visibility (FSD §1 rule 8): a room's messages are
        // placed at the `community` tier; an affiliations room's label rides
        // the record, and edge v31's chat producer places its rows at the
        // community tier too (no affiliations placement exists in `ScopeRoom`).
        "cohort_scope": room.tier.as_str(),
        "consensus_protocol": room.record.consensus_protocol,
        "founded_at": room.record.founded_at.to_rfc3339(),
        "member_count": room.roster.len(),
        "my_role": room.member(&owner.key_id).map(|m| role_token(m.role.as_deref())),
        "members": room.roster.iter().map(member_json).collect::<Vec<_>>(),
        "roles": roles,
    });
    if detail {
        let dir = st.engine.federation_directory();
        let moderators = admission::appointed_moderators_of(
            dir.as_ref(),
            room.id(),
            admission::DELEGATION_SCOPE_MODERATE,
        )
        .await
        .unwrap_or_default();
        let widenings = dir
            .list_community_membership_widenings_for(room.id())
            .await
            .map(|w| w.len())
            .unwrap_or(0);
        let revocations = dir
            .list_community_membership_revocations_for(room.id())
            .await
            .map(|r| r.len())
            .unwrap_or(0);
        if let Some(obj) = v.as_object_mut() {
            obj.insert("moderators".to_owned(), serde_json::json!(moderators));
            obj.insert("widenings".to_owned(), serde_json::json!(widenings));
            obj.insert("revocations".to_owned(), serde_json::json!(revocations));
        }
    }
    v
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    after: Option<String>,
}

/// `GET /v1/communities` — every room the caller is ACTIVE in, pair rooms
/// included, by the fold. Candidates are the rooms whose RECORD names the
/// caller (persist's index) plus the rooms whose WIDENING plane does (persist
/// indexes no widening by member, so the plane is walked) — then each is
/// judged by the fold, so a removed member's room drops out and an added
/// member's room appears.
async fn list_communities(
    State(st): State<ChatState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Response {
    let owner = match read_preamble(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let dir = st.engine.federation_directory();
    let mut ids: BTreeSet<String> = match dir.list_communities_for_member(&owner.key_id).await {
        Ok(v) => v.into_iter().map(|c| c.community_key_id).collect(),
        Err(e) => return store_unavailable(format!("list_communities_for_member: {e:#}")),
    };
    let mut cursor = None;
    loop {
        let page = match dir
            .list_signed_community_membership_widenings_since(cursor.clone(), WIDENING_SCAN_PAGE)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                return store_unavailable(format!(
                    "list_signed_community_membership_widenings_since: {e:#}"
                ))
            }
        };
        for w in &page {
            let row = &w.widening.community_membership_widening;
            if row.member_key_id == owner.key_id {
                ids.insert(row.community_key_id.clone());
            }
        }
        if page.len() < WIDENING_SCAN_PAGE as usize {
            break;
        }
        cursor = page.last().map(|p| p.resume_pair());
    }
    let limit = q
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let mut out: Vec<serde_json::Value> = Vec::new();
    let mut resume: Option<String> = None;
    for id in ids
        .iter()
        .filter(|id| q.after.as_deref().is_none_or(|a| id.as_str() > a))
    {
        let room = match load_room(&st, id).await {
            Ok(Some(r)) => r,
            Ok(None) => continue,
            Err(r) => return r,
        };
        if room.member(&owner.key_id).is_none() {
            continue;
        }
        if out.len() == limit {
            resume = out
                .last()
                .and_then(|v| v["community_id"].as_str())
                .map(str::to_owned);
            break;
        }
        out.push(room_json(&st, &room, &owner, false).await);
    }
    let total = out.len();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "communities": out,
            "total": total,
            "resume": resume,
        })),
    )
        .into_response()
}

/// `GET /v1/communities/{id}` — record + effective roster + roles + appointed
/// moderators. `community.not_found` for a non-member.
async fn read_community(
    State(st): State<ChatState>,
    headers: HeaderMap,
    Path(community_id): Path<String>,
) -> Response {
    let owner = match read_preamble(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    match load_room_as_member(&st, &owner, &community_id).await {
        Ok(room) => (
            StatusCode::OK,
            Json(room_json(&st, &room, &owner, true).await),
        )
            .into_response(),
        Err(r) => r,
    }
}

#[derive(Debug, Deserialize)]
struct AddMemberRequest {
    key_id: String,
    #[serde(default)]
    role: Option<String>,
}

/// `POST /v1/communities/{id}/members` — widen the roster by one.
async fn add_member(
    State(st): State<ChatState>,
    headers: HeaderMap,
    Path(community_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let owner = match write_preamble(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let room = match load_room_as_member(&st, &owner, &community_id).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let req: AddMemberRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return malformed(format!(
                "expected {{\"key_id\": \"…\", \"role\"?: \"…\"}}: {e}"
            ))
        }
    };
    let op = ChangeOp::Add {
        key_id: req.key_id,
        role: req.role,
    }
    .normalized();
    direct_change(&st, &headers, &owner, room, op).await
}

/// `DELETE /v1/communities/{id}/members/{key_id}` — remove a member. Naming
/// yourself is leaving, which is never put to a quorum.
async fn remove_member(
    State(st): State<ChatState>,
    headers: HeaderMap,
    Path((community_id, key_id)): Path<(String, String)>,
) -> Response {
    let owner = match write_preamble(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let room = match load_room_as_member(&st, &owner, &community_id).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    if key_id.trim() == owner.key_id {
        return leave_room(&st, &headers, &owner, room).await;
    }
    let op = ChangeOp::Remove { key_id }.normalized();
    direct_change(&st, &headers, &owner, room, op).await
}

#[derive(Debug, Deserialize)]
struct RoleRequest {
    role: String,
}

/// `POST /v1/communities/{id}/members/{key_id}/role` — change a member's role.
/// Moderation stays a delegable DUTY (`delegates_to`), not a role; this is the
/// roster's `founder` / `member` / operator-defined word.
async fn change_role(
    State(st): State<ChatState>,
    headers: HeaderMap,
    Path((community_id, key_id)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Response {
    let owner = match write_preamble(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let room = match load_room_as_member(&st, &owner, &community_id).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let req: RoleRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return malformed(format!("expected {{\"role\": \"…\"}}: {e}")),
    };
    if req.role.trim().is_empty() {
        return malformed("role must be a non-empty word (founder, member, …)");
    }
    let op = ChangeOp::Role {
        key_id,
        role: req.role,
    }
    .normalized();
    direct_change(&st, &headers, &owner, room, op).await
}

/// `POST /v1/communities/{id}/leave` — remove yourself. Always your own act,
/// never put to a quorum; the last founder of a room with other members must
/// hand the role on first.
async fn leave_community(
    State(st): State<ChatState>,
    headers: HeaderMap,
    Path(community_id): Path<String>,
) -> Response {
    let owner = match write_preamble(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let room = match load_room_as_member(&st, &owner, &community_id).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    leave_room(&st, &headers, &owner, room).await
}

async fn leave_room(st: &ChatState, headers: &HeaderMap, owner: &Owner, room: Room) -> Response {
    if room.is_pair() {
        return pair_room_fixed(room.id());
    }
    if room.orphans_if_gone(&owner.key_id) {
        return last_founder(&owner.key_id);
    }
    let pen = match pen(st, headers, owner).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let dir = st.engine.federation_directory();
    let at = match next_event_instant(dir.as_ref(), room.id()).await {
        Ok(t) => t,
        Err(e) => return write_failed(e),
    };
    if let Err(e) = put_revocation(dir.as_ref(), room.id(), &owner.key_id, at, "left", &pen).await {
        return write_failed(e);
    }
    crate::compose::kick_replication("community member left");
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "community_id": room.id(),
            "op": "leave",
            "applied": true,
            "key_id": owner.key_id,
        })),
    )
        .into_response()
}

/// `DELETE /v1/communities/{id}` — dissolve: every active member revoked, the
/// room's DEK rotated on each, and nobody left who can change it.
///
/// Expressed on the revocation plane rather than as a terminal record
/// supersede, for two reasons at these pins: verify's membership-change
/// envelope refuses an empty roster (`quorum:M/0` is malformed —
/// `accord_genesis::quorum_threshold_from_envelope`), and a rewritten record
/// is a roster fork at every peer, while revocations replicate as their own
/// kind and every node folds them to the same empty room.
async fn dissolve_community(
    State(st): State<ChatState>,
    headers: HeaderMap,
    Path(community_id): Path<String>,
) -> Response {
    let owner = match write_preamble(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let room = match load_room_as_member(&st, &owner, &community_id).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    direct_change(&st, &headers, &owner, room, ChangeOp::Dissolve).await
}

/// `POST /v1/communities/{id}/changes/envelope` `{op, key_id?, role?}` — build
/// the change for a quorum, pre-signed by the caller. Every other signer runs
/// `…/changes/cosign` on their OWN node (the signature is theirs, made by their
/// pen) and the caller finishes with `…/changes/assemble`.
async fn change_envelope(
    State(st): State<ChatState>,
    headers: HeaderMap,
    Path(community_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let owner = match write_preamble(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let room = match load_room_as_member(&st, &owner, &community_id).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let op: ChangeOp = match serde_json::from_slice::<ChangeOp>(&body) {
        Ok(op) => op.normalized(),
        Err(e) => {
            return malformed(format!(
                "expected {{\"op\": \"add\"|\"remove\"|\"role\"|\"dissolve\", \"key_id\"?, \"role\"?}}: {e}"
            ))
        }
    };
    if let Err(r) = precheck(&st, &owner, &room, &op).await {
        return r;
    }
    let pen = match pen(&st, &headers, &owner).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let env = match build_change(&st, &room, &op).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let mine = match sign_change(&pen, &env).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let t = match tally(&st, &room, &op, &env, std::slice::from_ref(&mine)).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    use base64::Engine as _;
    let bytes = match signing_bytes(&env) {
        Ok(b) => b,
        Err(r) => return r,
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "community_id": room.id(),
            "change_envelope": env,
            "signing_bytes_base64": base64::engine::general_purpose::STANDARD.encode(bytes),
            "signatures": [mine],
            "valid": t.valid,
            "required": t.required,
            "eligible_signers": t.eligible,
            "consensus_protocol": t.protocol,
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct CosignRequest {
    change_envelope: serde_json::Value,
}

/// `POST /v1/communities/{id}/changes/cosign` `{change_envelope}` — this
/// node's OWNER signs a change someone else built, after checking it still
/// describes the room as this node folds it. Stateless: it returns the
/// signature, it stores nothing.
async fn change_cosign(
    State(st): State<ChatState>,
    headers: HeaderMap,
    Path(community_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let owner = match write_preamble(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let room = match load_room_as_member(&st, &owner, &community_id).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let req: CosignRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return malformed(format!("expected {{\"change_envelope\": {{…}}}}: {e}")),
    };
    let op = match check_envelope_current(&st, &room, &req.change_envelope).await {
        Ok(op) => op,
        Err(r) => return r,
    };
    let pen = match pen(&st, &headers, &owner).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let sig = match sign_change(&pen, &req.change_envelope).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "community_id": room.id(),
            "op": op.name(),
            "signature": sig,
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct AssembleRequest {
    change_envelope: serde_json::Value,
    #[serde(default)]
    signatures: Vec<ThresholdSignature>,
}

/// `POST /v1/communities/{id}/changes/assemble` `{change_envelope,
/// signatures}` — count the signatures against the room's protocol and, when
/// met, apply the change signed by the caller's pen.
async fn change_assemble(
    State(st): State<ChatState>,
    headers: HeaderMap,
    Path(community_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let owner = match write_preamble(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let room = match load_room_as_member(&st, &owner, &community_id).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let req: AssembleRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return malformed(format!(
                "expected {{\"change_envelope\": {{…}}, \"signatures\": […]}}: {e}"
            ))
        }
    };
    let op = match check_envelope_current(&st, &room, &req.change_envelope).await {
        Ok(op) => op,
        Err(r) => return r,
    };
    if let Err(r) = precheck(&st, &owner, &room, &op).await {
        return r;
    }
    let t = match tally(&st, &room, &op, &req.change_envelope, &req.signatures).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if t.valid == 0 {
        return not_authorized(
            &t.protocol,
            format!(
                "none of the {} signature(s) is a valid signature by an eligible signer ({:?})",
                req.signatures.len(),
                t.eligible
            ),
        );
    }
    if !t.met() {
        return quorum_pending(&t, &req.change_envelope, &req.signatures);
    }
    let pen = match pen(&st, &headers, &owner).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    match apply_change(&st, &room, &op, &req.change_envelope, &req.signatures, &pen).await {
        Ok(roster) => applied(&room, &op, &roster),
        Err(r) => r,
    }
}

/// The community routes, merged into the chat router (same state, same owner
/// gate, same signer) — see `contacts_chat::router`.
pub(crate) fn routes() -> Router<ChatState> {
    use axum::routing::{delete, get, post};
    Router::new()
        .route(
            "/v1/communities",
            get(list_communities).post(create_community),
        )
        .route(
            "/v1/communities/{community_id}",
            get(read_community).delete(dissolve_community),
        )
        .route("/v1/communities/{community_id}/members", post(add_member))
        .route(
            "/v1/communities/{community_id}/members/{key_id}",
            delete(remove_member),
        )
        .route(
            "/v1/communities/{community_id}/members/{key_id}/role",
            post(change_role),
        )
        .route(
            "/v1/communities/{community_id}/leave",
            post(leave_community),
        )
        .route(
            "/v1/communities/{community_id}/changes/envelope",
            post(change_envelope),
        )
        .route(
            "/v1/communities/{community_id}/changes/cosign",
            post(change_cosign),
        )
        .route(
            "/v1/communities/{community_id}/changes/assemble",
            post(change_assemble),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocols_parse_only_what_can_be_evaluated() {
        assert_eq!(Protocol::parse("founder_only"), Some(Protocol::FounderOnly));
        assert_eq!(Protocol::parse("unanimous"), Some(Protocol::Unanimous));
        assert_eq!(Protocol::parse("majority"), Some(Protocol::Majority));
        assert_eq!(
            Protocol::parse("quorum:2/3"),
            Some(Protocol::Quorum { m: 2, n: 3 })
        );
        // Split-brain and nonsense shapes are refused.
        for bad in [
            "quorum:1/2",
            "quorum:0/1",
            "quorum:4/3",
            "weighted:x",
            "custom:y",
            "",
        ] {
            assert_eq!(Protocol::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn member_and_no_role_are_one_fact() {
        assert_eq!(normalize_role(Some("member")), None);
        assert_eq!(normalize_role(Some(" ")), None);
        assert_eq!(normalize_role(None), None);
        assert_eq!(normalize_role(Some("founder")).as_deref(), Some("founder"));
    }

    #[test]
    fn the_op_round_trips_through_the_envelope_member() {
        let op = ChangeOp::Add {
            key_id: "k".into(),
            role: None,
        };
        let v = serde_json::to_value(&op).unwrap();
        assert_eq!(v, serde_json::json!({"op": "add", "key_id": "k"}));
        assert_eq!(serde_json::from_value::<ChangeOp>(v).unwrap(), op);
        assert_eq!(
            serde_json::to_value(ChangeOp::Dissolve).unwrap(),
            serde_json::json!({"op": "dissolve"})
        );
    }
}
