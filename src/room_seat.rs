//! **A newcomer gets the room's key when they are seated** (0.5.247; CC C559,
//! persist 61.4.0 `Engine::seat_community_member`, CIRISServer#874).
//!
//! Before 0.5.247 a member seated in a room could read nothing written before
//! their seat until some member wrote again: the room's epoch keys reach a
//! member only through a seal's `key_grant` emission. Persist's seat door gives
//! the newcomer this node's current epoch key at the seat, with no content
//! write (or rotates first, when a removal made a rotation due). Every minter
//! in the room seats the newcomer into its own epoch; a node that has minted
//! nothing there is skipped, and its first seal grants everyone anyway.
//!
//! The server calls the door whenever a room's roster may have gained someone:
//! - a roster row LANDED by replication or by an edge write (edge's
//!   decision-row signal, `RosterLanded`, and the `MembershipReply` an edge
//!   widener seats from);
//! - a widening this server wrote itself ([`roster_changed`] at each write).
//!
//! A room with a member still owed (their device not known here yet) is
//! passed again on the pair-room driver's 30 s tick until it is not.
//!
//! One worker, coalesced per room. A (room, member) pair is remembered once
//! the door answered for it (granted, nothing owed, or no minter here), so a busy room
//! folds its roster once per change, not once per member per change. Persist's
//! door is idempotent besides: a second seat writes nothing.

use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use ciris_persist::Engine;
use tokio::sync::mpsc;

/// How long a burst of roster changes is gathered before one pass.
const COALESCE: std::time::Duration = std::time::Duration::from_millis(250);

/// The worker's word for "pass the owed and the owner's rooms" ([`sweep`]):
/// no room id is empty.
const SWEEP: &str = "";

/// Rooms with a member the door could not yet answer for.
fn owed() -> &'static Mutex<BTreeSet<String>> {
    static O: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    O.get_or_init(Default::default)
}

fn sender() -> &'static OnceLock<mpsc::UnboundedSender<String>> {
    static TX: OnceLock<mpsc::UnboundedSender<String>> = OnceLock::new();
    &TX
}

/// (engine, room, member) pairs the door already answered for. The engine is
/// named by address: one per process in production, several in a test.
fn seated() -> &'static Mutex<HashSet<(usize, String, String)>> {
    static S: OnceLock<Mutex<HashSet<(usize, String, String)>>> = OnceLock::new();
    S.get_or_init(Default::default)
}

/// `room`'s roster may have gained someone: seat them (asynchronously). A
/// no-op before [`start`] ran.
pub(crate) fn roster_changed(room: &str) {
    if let Some(tx) = sender().get() {
        let _ = tx.send(room.to_owned());
    }
}

/// Start the seat worker over `engine`, and listen to `runtime`'s decision
/// rows when there is one. Once per process; later calls do nothing.
pub(crate) fn start(
    engine: &Arc<Engine>,
    runtime: Option<&Arc<ciris_edge::replication::ReplicationRuntime>>,
) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    if sender().set(tx).is_err() {
        return;
    }
    if let Some(runtime) = runtime {
        let mut rows = runtime.bridge().subscribe_decision_rows();
        handle.spawn(async move {
            use ciris_edge::decision_rows::DecisionRowKind as K;
            use tokio::sync::broadcast::error::RecvError;
            loop {
                match rows.recv().await {
                    Ok(r) => {
                        if matches!(r.kind, K::RosterLanded | K::MembershipReply) {
                            if let Some(room) = r.scope_id.as_deref() {
                                roster_changed(room);
                            }
                        }
                    }
                    // Missed events: a later change in the same room re-folds
                    // its whole roster, so nothing is lost for good.
                    Err(RecvError::Lagged(n)) => {
                        tracing::debug!(missed = n, "room seat: decision rows lagged");
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        });
    }
    let engine = Arc::clone(engine);
    handle.spawn(async move {
        while let Some(first) = rx.recv().await {
            tokio::time::sleep(COALESCE).await;
            let mut asked = vec![first];
            while let Ok(r) = rx.try_recv() {
                asked.push(r);
            }
            let mut rooms = BTreeSet::new();
            for r in asked {
                if r == SWEEP {
                    rooms.extend(std::mem::take(
                        &mut *owed()
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                    ));
                    // Every room this node's owner sits in: a seat that
                    // replicated here raised no signal on one node of the
                    // native ladder. Answered members cost a memo lookup.
                    rooms.extend(owner_rooms(&engine).await);
                } else {
                    rooms.insert(r);
                }
            }
            for room in rooms {
                seat_room(&engine, &room).await;
            }
        }
    });
}

/// Pass again every room with a member still owed, and every room this node's
/// owner sits in. Called on the pair-room driver's tick (30 s): the cadence
/// registry has no slot for a fifteenth periodic loop (`loop_cadence`).
pub(crate) fn sweep() {
    if let Some(tx) = sender().get() {
        let _ = tx.send(SWEEP.to_owned());
    }
}

/// The community rooms this node's owner is a member of (none before a claim).
async fn owner_rooms(engine: &Engine) -> Vec<String> {
    let dir = engine.federation_directory();
    let Ok(node) = crate::backend::content_occurrence_key_id(engine).await else {
        return Vec::new();
    };
    let Ok(Some(owner)) = ciris_persist::federation::admission::owner_of(dir.as_ref(), &node).await
    else {
        return Vec::new();
    };
    dir.list_communities_for_member(&owner)
        .await
        .map(|cs| cs.into_iter().map(|c| c.community_key_id).collect())
        .unwrap_or_default()
}

/// Seat every member of `room` this process has not yet seated. Returns the
/// devices (occurrence keys) this node granted its epoch key to.
pub async fn seat_room(engine: &Engine, room: &str) -> Vec<String> {
    let dir = engine.federation_directory();
    let record = match dir.lookup_community(room).await {
        Ok(Some(r)) => r,
        Ok(None) => return Vec::new(),
        Err(e) => {
            tracing::debug!(room, error = %format!("{e:#}"), "room seat: room unreadable");
            return Vec::new();
        }
    };
    let roster = match crate::contacts_chat::active_roster(&*dir, &record).await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(room, error = %e, "room seat: roster unreadable");
            return Vec::new();
        }
    };
    let mut granted = Vec::new();
    for member in roster {
        let key = (
            std::ptr::from_ref(engine) as usize,
            room.to_owned(),
            member.key_id.clone(),
        );
        if seated()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&key)
        {
            continue;
        }
        match engine.seat_community_member(room, &member.key_id).await {
            Ok(out) => {
                let r = &out.seat;
                tracing::debug!(room, member = %member.key_id, report = ?r, "room seat");
                // Done once the door answered for a member whose device this
                // node knows (an empty answer for a member with no device
                // here yet is not "nothing owed": their occurrence row often
                // lands after their seat). Not done while the member is not
                // on persist's authorized roster yet, or a device was
                // excluded for want of keys. Owed rooms are passed again.
                let known = r.skipped == Some("not_a_minter")
                    || dir
                        .list_identity_occurrences_for(&member.key_id)
                        .await
                        .is_ok_and(|os| os.iter().any(|o| o.encryption_pubkeys.is_some()));
                let done = r.skipped != Some("not_a_member") && r.excluded.is_empty() && known;
                if !done {
                    owed()
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(room.to_owned());
                }
                // The door grants every live member device the epoch lacks,
                // not only the seated member's: report each device once.
                if !r.granted.is_empty() {
                    tracing::info!(
                        room,
                        member = %member.key_id,
                        epoch = ?r.epoch,
                        minted = r.minted,
                        devices = r.granted.len(),
                        excluded = r.excluded.len(),
                        "room seat: members' devices hold this node's room key (CC C559)"
                    );
                    granted.extend(r.granted.iter().cloned());
                }
                if done {
                    seated()
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(key);
                }
            }
            Err(e) => tracing::warn!(
                room,
                member = %member.key_id,
                error = %format!("{e:#}"),
                "room seat: the seat door failed; the next roster change retries"
            ),
        }
    }
    if !granted.is_empty() {
        crate::compose::wrote_rows("room seat: key grants");
    }
    granted
}
