//! **A room's takedown: the moderator removes a message's or a file's bytes**
//! (CC 4.5.3, CC 4.5.5; Eric, 2026-11-11: "the last piece to make rooms safe").
//!
//! A flag ([`crate::room_moderation`]) withholds an item until each viewer
//! chooses to see it. A takedown removes it: the item's BYTES (a message's
//! body, a file's content) stop being served at once, by every holder, with no
//! reveal, and are hard-deleted when the basis's counter-notice window closes.
//! The row itself — who wrote it, when — stays: a duty-holder's takedown
//! reaches the bytes plane only (CC 4.5.3; persist `takedown_tombstone`).
//!
//! **One basis here: `community_standards`** (a 30-day withhold, then delete).
//! The legal and immediate-removal bases are not a room moderator's to file
//! from a chat menu.
//!
//! **Three halves, all persist's rules, none re-implemented:**
//!
//! - [`take_down`] — the moderator's act. A `takedown_notice:{basis}:v1` row
//!   signed by the moderator's own pen, admitted only if persist finds them
//!   holding the `takedown` duty over the content (or authoring it); then
//!   `Engine::takedown_tombstone` withholds the bytes on THIS node.
//! - [`sweep`] — every OTHER member's node. The notice row replicates like any
//!   signed row; this node finds the notices about its rooms' members and
//!   applies each through the same `Engine::takedown_tombstone`, which re-asks
//!   the duty against THIS node's own state and is idempotent on the notice.
//!   Edge carries no purge plane yet, so this is how a takedown reaches every
//!   member. Then, once a notice's window has closed, `purge_finalize`.
//! - [`view_of`] — what a reader is told: taken down, by whom, under which
//!   basis, and the appeal's standing. Whether the bytes are withheld is
//!   persist's answer at read (`purge_withheld`), never a stored flag.
//!
//! **Appeals** of a takedown are `reconsideration:{grounds}` rows naming the
//! notice row, at `community` scope naming the room — where persist's
//! `takedown_reversal` looks — filed by the item's author, ruled by a `review`
//! holder. A `reversed` ruling inside the window lifts the withholding.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use ciris_persist::federation::admission;
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::takedown_tombstone::{TakedownNotice, NOTICE_DIMENSION_PREFIX};
use ciris_persist::federation::types::{attestation_type, cohort_scope};
use ciris_persist::federation::{Attestation, FederationDirectory};
use ciris_persist::prelude::{Engine, LocalSigner};
use serde::Serialize;

/// The one basis a room moderator files under.
pub const BASIS: &str = "community_standards";

/// How long a notice row lives. It must outlast the basis's window (30 days)
/// and any appeal inside it.
const NOTICE_LIFETIME: chrono::Duration = chrono::Duration::days(365);

/// The jurisdiction a room's own standards are filed under when the moderator
/// names none: ISO 3166's user-assigned "unknown or unspecified".
pub const DEFAULT_JURISDICTION: &str = "ZZ";

/// The content sha256 (lowercase hex) of a room item: a message's body
/// pointer, or a file's pointer. `None` for an inline-sealed message (no
/// separate bytes to take down) or a row that is not an item of `room`.
#[must_use]
pub fn content_sha_of(row: &Attestation, room: &str) -> Option<String> {
    if let Some(m) = ciris_edge::chat::ChatMessage::from_row(row, room) {
        return match m.body {
            ciris_edge::chat::Body::Pointer(p) => Some(p.content_sha256),
            _ => None,
        };
    }
    let scope = ciris_edge::scope_room::ScopeRoom::community(room);
    ciris_edge::files::belongs_to(&scope, row).map(|f| f.pointer.content_sha256)
}

/// Where an appeal of a takedown stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Appeal {
    /// Filed, not yet ruled on.
    Filed,
    /// A reviewer ruled; the takedown stands.
    Upheld,
    /// A reviewer ruled for part of it; the takedown stands.
    Partial,
    /// A reviewer reversed it.
    Reversed,
}

/// **What the room did to one item's bytes**, as a reader is told it (CC
/// 4.5.5: the person named sees that a record about them exists, its kind,
/// its consequence and who answers for it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TakedownView {
    /// The notice row: what an appeal names.
    pub notice_attestation_id: String,
    /// Who took it down.
    pub taken_down_by: String,
    /// The basis (`community_standards`).
    pub legal_basis: String,
    /// When.
    pub asserted_at: chrono::DateTime<chrono::Utc>,
    /// The bytes are withheld on this node right now (persist's answer).
    pub withheld: bool,
    /// Where an appeal stands, if one was filed or ruled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appeal: Option<Appeal>,
    /// The filing, for a ruling to answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appeal_attestation_id: Option<String>,
}

fn dimension(row: &Attestation) -> Option<&str> {
    row.attestation_envelope
        .get(paths::DIMENSION)
        .and_then(serde_json::Value::as_str)
}

fn str_member<'a>(row: &'a Attestation, k: &str) -> Option<&'a str> {
    row.attestation_envelope
        .get(k)
        .and_then(serde_json::Value::as_str)
}

/// The takedown notices about `author`, newest first.
async fn notices_about(
    dir: &dyn FederationDirectory,
    author: &str,
) -> Result<Vec<Attestation>, String> {
    use ciris_persist::federation::attestation_query::{AttestationQuery, FOLD_PAGE};
    let mut out = Vec::new();
    let mut pages = AttestationQuery::to(author, FOLD_PAGE)
        .dimension_prefix(NOTICE_DIMENSION_PREFIX)
        .pages();
    while let Some(rows) = pages
        .next(dir)
        .await
        .map_err(|e| format!("read takedown notices about {author}: {e:#}"))?
    {
        out.extend(rows);
    }
    out.retain(|r| r.attestation_type == attestation_type::SCORES);
    out.sort_by_key(|r| std::cmp::Reverse(r.asserted_at));
    Ok(out)
}

/// **The moderator's takedown** of one item's bytes. `signer` is the
/// moderator's own pen; persist admits the notice only if it holds the
/// `takedown` duty over the content (or wrote it). Returns the notice row's
/// id. Idempotent in effect: a second notice for the same bytes tombstones
/// nothing new.
///
/// # Errors
/// The notice was refused (persist's token in the message) or could not be
/// applied here.
#[allow(clippy::too_many_arguments)] // the item, its room, its author and the act's words
pub async fn take_down(
    engine: &Engine,
    signer: &LocalSigner,
    room: &str,
    item_id: &str,
    author: &str,
    content_sha256: &str,
    claim_text: &str,
    jurisdiction: &str,
) -> Result<String, String> {
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({
        (paths::DIMENSION): ciris_persist::federation::takedown_tombstone::notice_dimension(BASIS),
        "subject_kind": ciris_persist::federation::takedown_tombstone::TAKEDOWN_NOTICE_SUBJECT_KIND,
        "legal_basis": BASIS,
        "claimant_key_id": signer.key_id(),
        "content_sha256": content_sha256,
        "jurisdiction": jurisdiction,
        "good_faith_statement":
            "I moderate this room and remove this under its community standards in good faith.",
        "claim_text": claim_text,
        "score": -1.0,
        "community_id": room,
        (paths::REFERENCES_ATTESTATION_ID): item_id,
    });
    let spec = crate::attest::Spec::new(
        attestation_type::SCORES,
        // FEDERATION, as a flag is (AV-84): it replicates to the room's
        // members, whose servers apply it (`sweep`).
        cohort_scope::FEDERATION,
        envelope,
    )
    // ABOUT the author, never naming them a subject: a subject may withdraw a
    // row, and a takedown is not the author's to withdraw. Their standing to
    // appeal is the content's (persist reads the content's binding).
    .attested_to(author)
    .expiring(Some(now + NOTICE_LIFETIME));
    let notice_id = crate::attest::emit(engine, crate::attest::KeySigner::Local(signer), spec)
        .await
        .map_err(|e| format!("{e:#}"))?;
    apply(engine, &notice_id).await?;
    Ok(notice_id)
}

/// Apply one held notice row on THIS node: persist re-verifies it and re-asks
/// the duty against this node's state. Idempotent.
async fn apply(engine: &Engine, notice_attestation_id: &str) -> Result<(), String> {
    let dir = engine.federation_directory();
    let row = dir
        .get_attestation(notice_attestation_id)
        .await
        .map_err(|e| format!("read notice {notice_attestation_id}: {e:#}"))?
        .ok_or_else(|| format!("notice {notice_attestation_id} is not held here"))?;
    let notice = TakedownNotice::of_row(&row).map_err(|e| format!("{e:#}"))?;
    let report = engine
        .takedown_tombstone(&notice)
        .await
        .map_err(|e| format!("{e:#}"))?;
    remember(report.notice_id.clone(), report.settles_at);
    if report.tombstoned {
        tracing::info!(
            notice = notice_attestation_id,
            content = %report.content_sha256,
            by = %report.signer,
            settles_at = ?report.settles_at,
            "takedown: the bytes are withheld on this node (CC 4.5.3)"
        );
    }
    Ok(())
}

/// The purge headers this process applied, with when each may be finalized.
fn applied(
) -> &'static Mutex<std::collections::HashMap<String, Option<chrono::DateTime<chrono::Utc>>>> {
    static A: OnceLock<
        Mutex<std::collections::HashMap<String, Option<chrono::DateTime<chrono::Utc>>>>,
    > = OnceLock::new();
    A.get_or_init(Default::default)
}

fn remember(purge_id: String, settles_at: Option<chrono::DateTime<chrono::Utc>>) {
    applied()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .entry(purge_id)
        .or_insert(settles_at);
}

/// What a sweep did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepReport {
    /// Notices seen about this node's rooms' members.
    pub seen: usize,
    /// Notices applied without error this pass (idempotent).
    pub applied: usize,
    /// Notices refused or not yet applicable (retried next pass).
    pub waiting: usize,
    /// Purges hard-deleted this pass.
    pub finalized: usize,
}

/// **Every member's node applies the room's takedowns** (see the module
/// docs). For each room this node's owner is in, the notices about each
/// member are applied; a refused one (the content's row or the moderator's
/// appointment not here yet) waits for the next pass. Then every purge whose
/// window closed is finalized.
///
/// # Errors
/// The directory could not be read.
pub async fn sweep(engine: &Engine, node_key_id: &str) -> Result<SweepReport, String> {
    let dir = engine.federation_directory();
    let mut report = SweepReport::default();
    let Some(owner) = admission::owner_of(dir.as_ref(), node_key_id)
        .await
        .map_err(|e| format!("owner_of: {e:#}"))?
    else {
        return Ok(report);
    };
    let rooms = dir
        .list_communities_for_member(&owner)
        .await
        .map_err(|e| format!("list_communities_for_member: {e:#}"))?;
    let mut authors = HashSet::new();
    for room in &rooms {
        for m in dir
            .active_community_members(&room.community_key_id)
            .await
            .map_err(|e| format!("active_community_members: {e:#}"))?
        {
            authors.insert(m.key_id);
        }
    }
    let mut done = HashSet::new();
    for author in &authors {
        for row in notices_about(dir.as_ref(), author).await? {
            if !done.insert(row.attestation_id.clone()) {
                continue;
            }
            report.seen += 1;
            match apply(engine, &row.attestation_id).await {
                Ok(()) => report.applied += 1,
                Err(e) => {
                    report.waiting += 1;
                    tracing::debug!(
                        notice = %row.attestation_id,
                        error = %e,
                        "takedown: not applied on this node yet — retried next pass"
                    );
                }
            }
        }
    }
    let now = chrono::Utc::now();
    let due: Vec<String> = applied()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|(_, s)| s.is_some_and(|t| t <= now))
        .map(|(id, _)| id.clone())
        .collect();
    for purge_id in due {
        match engine.purge_finalize(&purge_id).await {
            Ok(_) => {
                report.finalized += 1;
                applied()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&purge_id);
                tracing::info!(purge = %purge_id, "takedown: window closed, bytes hard-deleted");
            }
            Err(e) => tracing::warn!(
                purge = %purge_id,
                error = %format!("{e:#}"),
                "takedown: the hard delete could not run — retried next pass"
            ),
        }
    }
    Ok(report)
}

/// One listing's notice reads, per author: a transcript or a drive listing
/// asks once per author, not once per item.
#[derive(Default)]
pub struct NoticeCache(std::collections::HashMap<String, std::sync::Arc<Vec<Attestation>>>);

impl NoticeCache {
    async fn about(
        &mut self,
        dir: &dyn FederationDirectory,
        author: &str,
    ) -> Result<std::sync::Arc<Vec<Attestation>>, String> {
        if let Some(hit) = self.0.get(author) {
            return Ok(hit.clone());
        }
        let rows = std::sync::Arc::new(notices_about(dir, author).await?);
        self.0.insert(author.to_owned(), rows.clone());
        Ok(rows)
    }
}

/// **What the room did to one item's bytes**, for a reader: the newest notice
/// about `author` naming `content_sha256` in `room` whose signer persist
/// would admit, and the appeal's standing. `None` when nobody took it down.
///
/// # Errors
/// A directory read failed. Never folded into "not taken down".
pub async fn view_of(
    engine: &Engine,
    cache: &mut NoticeCache,
    room: &str,
    author: &str,
    content_sha256: &str,
) -> Result<Option<TakedownView>, String> {
    let dir = engine.federation_directory();
    let notices = cache.about(dir.as_ref(), author).await?;
    let Some(notice) = notices.iter().find(|r| {
        str_member(r, "content_sha256") == Some(content_sha256)
            && str_member(r, "community_id") == Some(room)
            && dimension(r).is_some_and(|d| d.starts_with(NOTICE_DIMENSION_PREFIX))
    }) else {
        return Ok(None);
    };
    let sha: [u8; 32] = hex::decode(content_sha256)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("content sha {content_sha256:?} is not 32 bytes of hex"))?;
    let withheld = ciris_persist::federation::steward_purge::purge_withheld(dir.as_ref(), &sha)
        .await
        .map_err(|e| format!("purge_withheld: {e:#}"))?
        .is_some();
    // THE APPEAL: where persist's reversal looks — community scope, this room.
    let rows = match dir
        .list_targeted_by_dimension_prefix(
            &[cohort_scope::COMMUNITY],
            room,
            admission::RECONSIDERATION_DIMENSION_PREFIX,
        )
        .await
    {
        Ok(r) => r,
        Err(ciris_persist::federation::Error::Unsupported { .. }) => Vec::new(),
        Err(e) => return Err(format!("read the room's appeals: {e:#}")),
    };
    let mut filing: Option<&Attestation> = None;
    let mut ruling: Option<(&Attestation, &str)> = None;
    for r in &rows {
        if str_member(r, paths::REFERENCES_ATTESTATION_ID) != Some(notice.attestation_id.as_str()) {
            continue;
        }
        match str_member(r, admission::RECONSIDERATION_OUTCOME_MEMBER) {
            None => {
                if filing.is_none_or(|f| r.asserted_at > f.asserted_at) {
                    filing = Some(r);
                }
            }
            Some(o) => {
                if ruling.is_none_or(|(x, _)| r.asserted_at > x.asserted_at) {
                    ruling = Some((r, o));
                }
            }
        }
    }
    let appeal = match (filing, ruling) {
        (_, Some((_, "reversed"))) => Some(Appeal::Reversed),
        (Some(f), Some((r, o))) if r.asserted_at >= f.asserted_at => Some(if o == "partial" {
            Appeal::Partial
        } else {
            Appeal::Upheld
        }),
        (Some(_), _) => Some(Appeal::Filed),
        (None, Some((_, "partial"))) => Some(Appeal::Partial),
        (None, Some(_)) => Some(Appeal::Upheld),
        (None, None) => None,
    };
    Ok(Some(TakedownView {
        notice_attestation_id: notice.attestation_id.clone(),
        taken_down_by: notice.attesting_key_id.clone(),
        legal_basis: str_member(notice, "legal_basis")
            .unwrap_or(BASIS)
            .to_owned(),
        asserted_at: notice.asserted_at,
        withheld,
        appeal,
        appeal_attestation_id: filing.map(|f| f.attestation_id.clone()),
    }))
}
