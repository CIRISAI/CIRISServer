//! **A room's moderation decisions, applied where its content is read**
//! (CC 4.5.5; steward ruling 2026-10-30).
//!
//! CC 4.5.5 has two layers. Anyone may LABEL anything, and a label is a filter
//! a viewer opts into. Acting on the ROOM's behalf takes a duty: a `moderate`
//! holder's `content_class:{class}` flag gates the item for every member, the
//! item's author may file a `reconsideration:{grounds}` against it, and a
//! `review` holder rules on that. This module is the read side of the duty
//! layer, used by every reader of room content — the chat transcript, the room
//! drive's listing and its file reads — so one fold answers all three.
//!
//! **Who is believed is decided here, on read.** `content_class:` is open
//! vocabulary at persist's write door (CC 3.3.12), so a flag row proves only
//! that someone wrote it. One counts for the room iff its attester
//! `is_named_moderator(attester, room, moderate)` — the same predicate
//! persist's §11.10 gate and `viewer_duties` use. A label from anyone else is
//! not the room's decision and is not applied. A ruling counts iff its attester
//! holds `review`; persist already refuses any other at admission, and the
//! read re-checks rather than trusting that every row arrived through it.
//!
//! **A flag withholds; it does not delete.** Removal is `takedown`. A flagged
//! item is listed with its [`ModerationView`], and its body or bytes open only
//! for a viewer whose own `consent:state:granted {scope: view, content_class}`
//! names it ([`reveal`]) — the same consent fold `/v1/safety/reveal` reads.
//!
//! A directory read that fails is an error, never "not flagged": on a
//! child-safety gate, "we could not check" must not render as "nothing here".

use std::collections::HashMap;

use ciris_persist::federation::admission;
use ciris_persist::federation::consent::consent_dimension;
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::types::{attestation_type, cohort_scope};
use ciris_persist::federation::{Attestation, FederationDirectory};
use ciris_persist::prelude::Engine;
use serde::Serialize;

use crate::attestation_reads::AllAttestations as _;
use crate::safety::infohazard::ContentFlag;

/// The scope token persist's `resolve_scoped_consent` matches a view consent on.
const VIEW_SCOPE: &str = "view";

/// Where a reconsideration of the live flag stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reconsideration {
    /// Filed by the author (or a review holder), not yet ruled on.
    Filed,
    /// A review holder ruled; the flag stands.
    Upheld,
    /// A review holder ruled for part of it; the flag stands.
    Partial,
    /// A review holder reversed the flag; the item is no longer withheld.
    Reversed,
}

/// **What the room decided about one item, as this viewer sees it.** Absent
/// from an item nobody with the duty has ever flagged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModerationView {
    /// `infohazard` | `reported` — the class a moderator flagged it as.
    /// `None` once the flag was cleared or reversed; the history fields stay.
    pub flag: Option<&'static str>,
    /// The item the flag names — this row, or an earlier version of a
    /// message. What a reveal consents to.
    pub item_attestation_id: String,
    /// The moderator's flag row — what a reconsideration targets.
    pub flag_attestation_id: String,
    /// Who flagged it: a holder of the room's `moderate` duty.
    pub flagged_by: String,
    /// Whether the body or bytes are withheld from THIS viewer right now:
    /// flagged and not revealed.
    pub withheld: bool,
    /// This viewer consented to view it (`POST …/reveal`).
    pub revealed: bool,
    /// Where an appeal of the flag stands, if one was filed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconsideration: Option<Reconsideration>,
    /// The filing row, for a ruling to name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconsideration_attestation_id: Option<String>,
}

/// Duty answers memoised for one read: a transcript of many messages from a
/// few moderators costs a few walks, not one per row.
#[derive(Default)]
pub struct DutyCache(HashMap<(String, &'static str), bool>);

impl DutyCache {
    async fn holds(
        &mut self,
        dir: &dyn FederationDirectory,
        who: &str,
        room: &str,
        duty: &'static str,
    ) -> Result<bool, String> {
        if let Some(hit) = self.0.get(&(who.to_owned(), duty)) {
            return Ok(*hit);
        }
        let held = admission::is_named_moderator(dir, who, room, duty)
            .await
            .map_err(|e| format!("is_named_moderator({who}, {room}, {duty}): {e}"))?;
        self.0.insert((who.to_owned(), duty), held);
        Ok(held)
    }
}

fn dimension(row: &Attestation) -> Option<&str> {
    row.attestation_envelope
        .get(paths::DIMENSION)
        .and_then(serde_json::Value::as_str)
}

fn names_room(row: &Attestation, room: &str) -> bool {
    row.attestation_envelope
        .get("community_id")
        .and_then(serde_json::Value::as_str)
        == Some(room)
}

fn flag_class(dimension: &str) -> Option<ContentFlag> {
    let tail = dimension.strip_prefix("content_class:")?;
    ContentFlag::from_token(tail.split(':').next()?)
}

fn references(row: &Attestation) -> Option<&str> {
    row.attestation_envelope
        .get(paths::REFERENCES_ATTESTATION_ID)
        .and_then(serde_json::Value::as_str)
}

/// **The room's decision about `target_id`, for `viewer`.** `Ok(None)` when no
/// holder of the room's `moderate` duty ever flagged it.
///
/// THE SHAPE: every row of the duty layer is ABOUT the item's author —
/// `attested_key_id` and `subject_key_ids` name them, which is what gives the
/// author standing to appeal (CC 4.5.5) — and names the item, or the flag
/// under appeal, by `references_attestation_id`. An attestation id is not a
/// key, so it cannot be a row's `attested_key_id`; and persist has no lookup
/// of `scores` rows by reference. So the fold reads the author's rows once and
/// filters them by what they reference.
///
/// # Errors
/// A directory read failed. Never folded into "not flagged".
pub async fn view_of(
    engine: &Engine,
    duties: &mut DutyCache,
    room: &str,
    target_id: &str,
    author: &str,
    viewer: &str,
) -> Result<Option<ModerationView>, String> {
    let dir = engine.federation_directory();
    let rows = dir
        .attestations_to_all(author)
        .await
        .map_err(|e| format!("read moderation rows about {author}: {e}"))?;

    // THE FLAG: per class, the newest row from a `moderate` holder of THIS
    // room. A cleared flag (`withdrawn: true`) is the newest row saying so.
    let mut newest: HashMap<&'static str, &Attestation> = HashMap::new();
    for row in &rows {
        if row.attestation_type != attestation_type::SCORES
            || !names_room(row, room)
            || references(row) != Some(target_id)
        {
            continue;
        }
        let Some(class) = dimension(row).and_then(flag_class) else {
            continue;
        };
        if row.expires_at.is_some_and(|t| t <= chrono::Utc::now()) {
            continue;
        }
        if !duties
            .holds(
                dir.as_ref(),
                &row.attesting_key_id,
                room,
                admission::DELEGATION_SCOPE_MODERATE,
            )
            .await?
        {
            continue;
        }
        let slot = newest.entry(class.as_str()).or_insert(row);
        if row.asserted_at > slot.asserted_at {
            *slot = row;
        }
    }
    // The more severe class leads when both were ever flagged.
    let Some(flag_row) = [ContentFlag::Infohazard, ContentFlag::Reported]
        .iter()
        .find_map(|c| newest.get(c.as_str()).copied())
    else {
        return Ok(None);
    };
    let class = dimension(flag_row)
        .and_then(flag_class)
        .unwrap_or(ContentFlag::Reported);
    let cleared = flag_row
        .attestation_envelope
        .get("withdrawn")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    // THE APPEAL: the newest filing against this flag row, and the newest
    // ruling from a `review` holder after it.
    let mut filing: Option<&Attestation> = None;
    let mut ruling: Option<(&Attestation, String)> = None;
    for row in &rows {
        if row.attestation_type != attestation_type::SCORES
            || !dimension(row)
                .is_some_and(|d| d.starts_with(admission::RECONSIDERATION_DIMENSION_PREFIX))
            || references(row) != Some(flag_row.attestation_id.as_str())
        {
            continue;
        }
        match row
            .attestation_envelope
            .get(admission::RECONSIDERATION_OUTCOME_MEMBER)
            .and_then(serde_json::Value::as_str)
        {
            None => {
                if filing.is_none_or(|f| row.asserted_at > f.asserted_at) {
                    filing = Some(row);
                }
            }
            Some(outcome) => {
                if !duties
                    .holds(
                        dir.as_ref(),
                        &row.attesting_key_id,
                        room,
                        admission::DELEGATION_SCOPE_REVIEW,
                    )
                    .await?
                {
                    continue;
                }
                if ruling
                    .as_ref()
                    .is_none_or(|(r, _)| row.asserted_at > r.asserted_at)
                {
                    ruling = Some((row, outcome.to_owned()));
                }
            }
        }
    }
    let reconsideration = match (filing, &ruling) {
        (Some(f), Some((r, outcome))) if r.asserted_at >= f.asserted_at => {
            Some(match outcome.as_str() {
                "reversed" => Reconsideration::Reversed,
                "partial" => Reconsideration::Partial,
                // An outcome this build does not know does not lift a flag.
                _ => Reconsideration::Upheld,
            })
        }
        (Some(_), _) => Some(Reconsideration::Filed),
        // A ruling with no filing on this node yet: the ruling still binds.
        (None, Some((_, outcome))) if outcome == "reversed" => Some(Reconsideration::Reversed),
        (None, Some(_)) => Some(Reconsideration::Upheld),
        (None, None) => None,
    };
    let live = !cleared && reconsideration != Some(Reconsideration::Reversed);
    let revealed = live && has_view_consent(engine, viewer, target_id, class).await?;
    Ok(Some(ModerationView {
        flag: live.then_some(class.as_str()),
        item_attestation_id: target_id.to_owned(),
        flag_attestation_id: flag_row.attestation_id.clone(),
        flagged_by: flag_row.attesting_key_id.clone(),
        withheld: live && !revealed,
        revealed,
        reconsideration,
        reconsideration_attestation_id: filing.map(|f| f.attestation_id.clone()),
    }))
}

/// Has `viewer` consented to view `target_id` flagged as `class`?
///
/// PER ITEM, which persist's `resolve_scoped_consent` cannot say: it keys a
/// view consent on a KEY (the author), so consenting to one flagged message
/// would open every message that author was ever flagged for. The viewer's own
/// consent rows are about the viewer and name the item by reference; the
/// newest one naming this item and class decides, and only `granted` opens.
async fn has_view_consent(
    engine: &Engine,
    viewer: &str,
    target_id: &str,
    class: ContentFlag,
) -> Result<bool, String> {
    let rows = engine
        .federation_directory()
        .attestations_to_all(viewer)
        .await
        .map_err(|e| format!("read {viewer}'s view consents: {e}"))?;
    let newest = rows
        .iter()
        .filter(|r| {
            r.attesting_key_id == viewer
                && r.attestation_type == attestation_type::SCORES
                && references(r) == Some(target_id)
                && dimension(r).is_some_and(|d| d.starts_with(consent_dimension::STATE_PREFIX))
                && r.attestation_envelope
                    .get("scope")
                    .and_then(serde_json::Value::as_str)
                    == Some(VIEW_SCOPE)
                && r.attestation_envelope
                    .get("content_class")
                    .and_then(serde_json::Value::as_str)
                    == Some(class.as_str())
        })
        .max_by_key(|r| r.asserted_at);
    Ok(newest
        .and_then(dimension)
        .is_some_and(|d| d.starts_with(consent_dimension::STATE_GRANTED_PREFIX)))
}

/// **The viewer's consent to view a flagged item** — their own signed
/// `consent:state:granted {scope: view, content_class}` naming it by
/// `references_attestation_id` (see [`has_view_consent`]), at
/// `self` scope: whether someone chose to look is theirs, and it never
/// leaves their devices. Returns the consent row's id.
///
/// # Errors
/// The row could not be signed or admitted.
pub async fn reveal(
    engine: &Engine,
    viewer: &ciris_persist::prelude::LocalSigner,
    target_id: &str,
    class: ContentFlag,
) -> Result<String, String> {
    let spec = crate::attest::Spec::new(
        attestation_type::SCORES,
        cohort_scope::SELF,
        serde_json::json!({
            (paths::DIMENSION): format!("{}:v1", consent_dimension::STATE_GRANTED_PREFIX),
            "scope": VIEW_SCOPE,
            "content_class": class.as_str(),
            (paths::REFERENCES_ATTESTATION_ID): target_id,
        }),
    )
    .about(viewer.key_id());
    crate::attest::emit(engine, crate::attest::KeySigner::Local(viewer), spec)
        .await
        .map_err(|e| format!("{e:#}"))
}
