//! **A pair room the person asked for — kept on disk** (0.5.218, edge v38 /
//! persist v52, CIRISPersist#955).
//!
//! Since edge v38 a pair room joins in two steps: the CREATOR (the smaller
//! fed-ID, `chat::PairRole`) founds it alone and proposes the other person;
//! the JOINER accepts. When the joiner's person calls `POST /v1/chat` for a
//! contact before the creator's invitation has reached their node, there is
//! nothing to accept yet — so the request is recorded here, and the
//! invitation is accepted when it lands (on the next read of the room, or the
//! compose loop's membership sweep).
//!
//! # Why this is consent, and the only thing it is consent to
//!
//! The maintainer's ruling (2026-09-30, CIRISConstitution#133): nobody joins a
//! family or community without their OWN consent, and a contact grant is not
//! it. Ruled on this path the same day: *the person's own `POST /v1/chat` for
//! that contact IS their act of consent to that pair room.* So an intent
//! records exactly that act — `{pair_id, contact_person, asked_at}` — and
//! [`advance`] accepts an invitation ONLY when it matches a recorded intent on
//! all three counts: the invitation is into that `pair_id`, it invites THIS
//! node's person, and its proposer resolves (`admission_identity_for_writer`)
//! to that `contact_person`. **Nothing else is ever auto-accepted** — not an
//! invitation into another room, not one from another person into the same
//! derived id, not a family or community invitation. Those wait in
//! `GET /v1/self/invites` for the person.
//!
//! # Why on disk, and the lifecycle
//!
//! Process memory forgot the request on a restart, and the person's act would
//! silently have to be repeated. The file mirrors `mls-claims.json`
//! (`mls_state`): one small JSON file in the node's user-seed directory,
//! written (temp + rename) BEFORE anything depends on it — `POST /v1/chat`
//! refuses rather than answer `awaiting_invitation` over an intent it could
//! not keep — and fallible by name. An intent is REMOVED once the room seats
//! this person, once the matching invitation is declined, expired or
//! withdrawn, or after [`MAX_AGE_DAYS`] (persist's longest proposal life) with
//! no invitation at all. It is not secret: it names two public fed-IDs.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use ciris_edge::membership::{self as em, GroupScope};
use ciris_persist::federation::FederationDirectory;

/// The sidecar's file name, in the node's user-seed directory.
pub const PAIR_INTENTS_FILE: &str = "pair-intents.json";

/// An intent no invitation answered in this long is dropped: persist bounds a
/// proposal's life at 30 days, so nothing older can still be answered.
pub const MAX_AGE_DAYS: i64 = 30;

/// One request: this node's person asked to open `pair_id` with
/// `contact_person`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairIntent {
    pub pair_id: String,
    pub contact_person: String,
    pub asked_at: chrono::DateTime<chrono::Utc>,
}

fn path_in(seed_dir: &Path) -> PathBuf {
    seed_dir.join(PAIR_INTENTS_FILE)
}

/// Every recorded intent. An unreadable file is logged and read as none —
/// nothing is auto-accepted on a guess.
pub fn read(seed_dir: &Path) -> Vec<PairIntent> {
    let path = path_in(seed_dir);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!(path = %path.display(), error = %e, "pair intents unreadable — nothing is auto-accepted until the person asks again");
            Vec::new()
        }),
        Err(_) => Vec::new(),
    }
}

fn write(seed_dir: &Path, intents: &[PairIntent]) -> Result<(), String> {
    let path = path_in(seed_dir);
    if intents.is_empty() {
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("remove pair intents at {}: {e}", path.display())),
        };
    }
    let bytes = serde_json::to_vec(intents).map_err(|e| format!("encode pair intents: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)
        .and_then(|()| std::fs::rename(&tmp, &path))
        .map_err(|e| format!("write pair intents at {}: {e}", path.display()))
}

/// Record that this node's person asked to open `pair_id` with
/// `contact_person`. Idempotent (the FIRST `asked_at` is kept). An `Err`
/// means the intent is not durable and the caller must not promise it.
pub fn record(seed_dir: &Path, pair_id: &str, contact_person: &str) -> Result<(), String> {
    let mut intents = read(seed_dir);
    if intents
        .iter()
        .any(|i| i.pair_id == pair_id && i.contact_person == contact_person)
    {
        return Ok(());
    }
    intents.push(PairIntent {
        pair_id: pair_id.to_owned(),
        contact_person: contact_person.to_owned(),
        asked_at: chrono::Utc::now(),
    });
    write(seed_dir, &intents)
}

/// Drop every intent for `pair_id`.
pub fn forget(seed_dir: &Path, pair_id: &str) -> Result<(), String> {
    let mut intents = read(seed_dir);
    let before = intents.len();
    intents.retain(|i| i.pair_id != pair_id);
    if intents.len() == before {
        return Ok(());
    }
    write(seed_dir, &intents)
}

fn drop_intent(seed_dir: &Path, pair_id: &str, why: &str) {
    match forget(seed_dir, pair_id) {
        Ok(()) => tracing::info!(pair_id, why, "pair intent removed"),
        Err(e) => tracing::warn!(pair_id, why, error = %e, "pair intent could not be removed"),
    }
}

/// **Act on every recorded intent** for `me` (this node's person): accept a
/// MATCHING invitation (see the module docs — into that pair, for `me`, from
/// that contact's person), signed by `signer` (`me`'s person or a device
/// acting for them, which persist admits for a reply); remove the intent once
/// `me` is seated, once the matching invitation is declined / expired /
/// withdrawn, or once it is older than [`MAX_AGE_DAYS`]. Returns the rooms
/// whose invitation it accepted.
pub async fn advance(
    dir: &dyn FederationDirectory,
    seed_dir: &Path,
    me: &str,
    signer: &ciris_edge::identity::LocalSigner,
) -> Vec<String> {
    let now = chrono::Utc::now();
    let mut accepted = Vec::new();
    for intent in read(seed_dir) {
        if now.signed_duration_since(intent.asked_at) > chrono::Duration::days(MAX_AGE_DAYS) {
            drop_intent(
                seed_dir,
                &intent.pair_id,
                "no invitation within a proposal's life",
            );
            continue;
        }
        // An intent that does not name this pair's derived id for `me` is
        // not this person's request (a hand-edited or foreign file).
        if ciris_edge::chat::pair_community_key_id(me, &intent.contact_person) != intent.pair_id {
            drop_intent(seed_dir, &intent.pair_id, "not this person's pair");
            continue;
        }
        let active: std::collections::HashSet<String> = dir
            .active_community_members(&intent.pair_id)
            .await
            .map(|v| v.into_iter().map(|m| m.key_id).collect())
            .unwrap_or_default();
        if active.contains(me) {
            drop_intent(seed_dir, &intent.pair_id, "seated");
            continue;
        }
        let Ok(invites) = crate::membership_invites::group_invites(
            dir,
            GroupScope::Community,
            &intent.pair_id,
            &active,
        )
        .await
        else {
            continue;
        };
        let mut matching = Vec::new();
        for (view, _) in &invites {
            if view.invitee_key_id != me {
                continue;
            }
            let proposer = ciris_persist::federation::admission::admission_identity_for_writer(
                dir,
                &view.proposer_key_id,
            )
            .await
            .unwrap_or_default();
            if proposer == intent.contact_person {
                matching.push(view.clone());
            }
        }
        if let Some(pending) = matching
            .iter()
            .rev()
            .find(|v| v.state == crate::membership_invites::STATE_PENDING)
        {
            match em::reply(dir, &pending.proposal_id, true, signer).await {
                Ok(_) => {
                    tracing::info!(
                        pair_id = %intent.pair_id, contact = %intent.contact_person,
                        "pair room: accepted the invitation the person asked for (their POST /v1/chat)"
                    );
                    let _ = crate::compose::kick_replication("pair room invitation accepted");
                    accepted.push(intent.pair_id.clone());
                }
                Err(e) => {
                    tracing::debug!(pair_id = %intent.pair_id, error = %e, "pair intent: not accepted yet")
                }
            }
            continue;
        }
        let answered_in_time = matching
            .iter()
            .any(|v| v.state == crate::membership_invites::STATE_ACCEPTED);
        let closed = matching.iter().any(|v| {
            [
                crate::membership_invites::STATE_DECLINED,
                crate::membership_invites::STATE_EXPIRED,
                crate::membership_invites::STATE_WITHDRAWN,
            ]
            .contains(&v.state)
        });
        if closed && !answered_in_time {
            drop_intent(
                seed_dir,
                &intent.pair_id,
                "the invitation was declined, expired or withdrawn",
            );
        }
    }
    accepted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_intent_survives_a_reread_and_is_removed_by_name() {
        let dir = std::env::temp_dir().join(format!(
            "pair-intents-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        record(&dir, "chat:pair:v1:x", "bob").expect("record");
        record(&dir, "chat:pair:v1:x", "bob").expect("idempotent");
        record(&dir, "chat:pair:v1:y", "carol").expect("second");
        let got = read(&dir);
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(dir.join(PAIR_INTENTS_FILE).exists(), "durable on disk");
        forget(&dir, "chat:pair:v1:x").expect("forget");
        assert_eq!(read(&dir).len(), 1);
        forget(&dir, "chat:pair:v1:y").expect("forget the last");
        assert!(
            !dir.join(PAIR_INTENTS_FILE).exists(),
            "no file once none remain"
        );
    }
}
