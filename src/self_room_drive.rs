//! **The self room's driver** — the last rung under "my stuff on my other
//! devices" (CIRISServer#622 / CIRISEdge#646, `FSD/CONTENT_TRANSFER.md` §6.3).
//!
//! # Why a driver exists at all
//!
//! A community room is created by a person inviting another. A self room has
//! nobody to invite: it must appear the moment an identity owns a second
//! device, with no human act. And if both devices create one, they derive
//! different exporter secrets and address each other at destinations nobody
//! registered — correct by every local check and dark on the wire, which is the
//! shape this whole arc exists to remove.
//!
//! So edge owns the RULE and this owns the IO, the same split as
//! [`ScopeLifecycle`](ciris_edge::scope_lifecycle::ScopeLifecycle):
//! [`self_room::roster`] says who belongs (the directory's answer),
//! [`self_room::snapshot`] says what the lifecycle installs (the MLS tree's),
//! and [`self_room::decide`] says what this node should do about the
//! difference. Nothing here decides; every branch below performs one named
//! action and says what it did.
//!
//! # The bootstrap needs no room
//!
//! KeyPackage, Welcome and Commit are ordinary `self`-placed rows, so they
//! reach the identity's other nodes over the ROW plane — which since persist
//! v46.3.0 / edge v29.3.0 carries a `self` row to the owner's own nodes with no
//! grant between them (`send_set_for`, CC 3.2/3.3.6: an owner consenting to
//! their own node is a category error, so membership is a cryptographic fact
//! instead). Only the BYTES need the room. There is no chicken-and-egg.
//!
//! # What this does not do yet
//!
//! The MLS group is held in memory for the life of the process, exactly as the
//! chat rooms are. A restart therefore re-derives: `decide` sees no held room,
//! creates one, meets the other device's live claim as a `rival`, and
//! `Abandon`s in its favour — convergent, but churn. Durable group state is
//! CIRISServer#623 and belongs to every room at once, not to this one.

use std::sync::Arc;

use ciris_edge::identity::LocalSigner;
use ciris_edge::mls::cohort_group::CohortKeyMaterial;
use ciris_edge::mls::{CohortGroup, CommitClaim};
use ciris_edge::scope_lifecycle::ScopeLifecycle;
use ciris_edge::scope_room::ScopeRoom;
use ciris_edge::self_room::{self, HeldRoom, SelfRoomAction};
use ciris_persist::prelude::Engine;

/// What one tick did — named, because a ladder reads these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfRoomTick {
    /// No owner binding yet: nothing to be a self-collective of.
    NoOwner,
    /// The owner's roster does not contain this node. The owner-binding is
    /// wrong; never derive a room from a roster we are not in.
    NotInRoster,
    /// One device. Correct and complete — a self room of one has nobody to
    /// address, and this ends the moment a second device announces.
    SoleDevice,
    /// This node created the room and is now its committer.
    Created { members: usize },
    /// Our KeyPackage is published; the creator adds us when it reads it.
    PublishedKeyPackage,
    /// The creator's Welcome arrived and we are IN the room.
    Joined { members: usize },
    /// Devices admitted to the tree this tick.
    Added(usize),
    /// Devices removed from the tree this tick (forward secrecy: first).
    Removed(usize),
    /// Another node's claim wins; ours is dropped and we join from theirs.
    Abandoned,
    /// Converged — the tree matches the directory.
    Idle,
    /// The tick could not complete. The string names the rung, not the symptom.
    Failed(String),
}

/// The room this node holds, with the claim it was created under.
///
/// THE CLAIM IS STORED, NOT REBUILT. `decide` settles a two-room contest by
/// comparing our claim to a rival's, and `first_rival` reads rivals off their
/// SIGNED commit rows — stable, dated values. Rebuilding ours with
/// `Utc::now()` on every tick made it perpetually the youngest, so a rival
/// always won and this node always abandoned; with both nodes doing that, both
/// drop their group and neither room survives. The winner has to be decided by
/// a value that does not move (Codex, CIRISServer#628).
#[derive(Clone)]
pub struct HeldGroup {
    pub group: Arc<CohortGroup>,
    pub claim: CommitClaim,
}

/// Everything the driver needs, resolved once at compose.
pub struct SelfRoomState {
    pub engine: Arc<Engine>,
    pub node_signer: Arc<LocalSigner>,
    pub user_seed_dir: std::path::PathBuf,
    pub lifecycle: Option<Arc<ScopeLifecycle>>,
    /// The live group **and the claim it was created under**, held across
    /// ticks — see the module note on durability.
    pub held: Arc<tokio::sync::Mutex<Option<HeldGroup>>>,
    /// Our KeyPackage material while we wait to be added.
    pub pending: Arc<tokio::sync::Mutex<Option<CohortKeyMaterial>>>,
}

impl SelfRoomState {
    /// The MLS state store for this identity's room. In-process for now (see
    /// the module note) — one provider per room id, as chat does.
    fn store(room_id: &str) -> Result<ciris_edge::mls::ScopeStateProvider, String> {
        Ok(ciris_edge::mls::ScopeStateProvider::new(Arc::new(
            ciris_persist::encrypted_kv::XChaChaKvStore::open_in_memory(room_id.as_bytes())
                .map_err(|e| format!("open the self room's MLS store: {e}"))?,
        )))
    }
}

/// One tick of the self-room drive. Idempotent: every branch is safe to run
/// again, because `decide` re-reads the world each time.
pub async fn drive_once(st: &SelfRoomState) -> SelfRoomTick {
    let dir = st.engine.federation_directory();
    let node_key = match st.engine.local_derived_key_id().await {
        Ok(k) => k,
        Err(e) => return SelfRoomTick::Failed(format!("resolve this node's key: {e}")),
    };
    let owner = match st.engine.owner_of(&node_key).await {
        Ok(Some(o)) => o,
        Ok(None) => return SelfRoomTick::NoOwner,
        Err(e) => return SelfRoomTick::Failed(format!("resolve this node's owner: {e}")),
    };

    // THE OWNER MUST BE A KEM TARGET ON THIS NODE, or self content has nobody
    // to be wrapped to. `files::publish` at `self` resolves recipients from the
    // owner's ACTIVE OCCURRENCES WITH CONTENT-KEM KEYS, and a node that has
    // only ever been claimed has none: the provisioning door was reachable from
    // a chat route and nowhere else, so a node whose person never chatted
    // refused every self write as `ReadableByNobody` — correctly, and with
    // nothing to point at. Measured on the selffiles ladder: the only
    // occurrence row was the node's own singleton.
    //
    // It belongs here because this is the tick that makes this node a member of
    // the owner's self-collective, and an occurrence with no KEM keys is a
    // membership the cascade cannot use. Idempotent (`created` /
    // `already_current` / `migrated`), so every tick is safe.
    match crate::backend::provision_engine_occurrence(&st.engine, &owner).await {
        Ok((occ, how)) if how != "already_current" => tracing::info!(
            owner = %owner, occurrence = %occ, how,
            "self room: this node is now a content-KEM occurrence of its owner — self bytes \
             can be wrapped to it"
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(
            owner = %owner, error = %e,
            "self room: could not provision this node as a content-KEM occurrence of its \
             owner — self writes will refuse as readable-by-nobody until it exists"
        ),
    }

    // WHO BELONGS: the directory's answer, in NODES (CC 4.4.3.2.4.1(b) — an
    // occurrence is a grant target, never a replication endpoint).
    let lens = ciris_edge::contact::PersistLens::new(&*dir);
    let roster = self_room::roster(&owner, &lens).await;
    let room = self_room::room(&owner);
    let room_id = room.content_group_id().to_owned();

    // WHAT WE HOLD: the live tree, if this process has one.
    let held_group = st.held.lock().await.clone();
    let held = match &held_group {
        Some(h) => Some(HeldRoom {
            // The STORED claim — see `HeldGroup`. Not `Utc::now()`.
            claim: h.claim.clone(),
            members: h.group.member_key_ids().await,
        }),
        None => None,
    };

    // A RIVAL: another node's commit claim for this same identity. Read from
    // the rows, because that is where a contest is visible to both sides.
    let rival = first_rival(&*dir, &roster, &node_key, &room_id).await;

    let action = self_room::decide(&node_key, &roster, held.as_ref(), rival.as_ref());
    // The DECISION, before the work it implies. A tick reports what it DID; if
    // the doing wedges there is no report at all, and the difference between
    // "converged and quiet" and "stuck forever" is invisible. This line is the
    // difference, and it is cheap: DEBUG, one line, off in normal operation.
    tracing::debug!(
        ?action,
        roster = roster.len(),
        held = held.is_some(),
        rival = rival.is_some(),
        "self room: decided"
    );
    match action {
        SelfRoomAction::NotInRoster => SelfRoomTick::NotInRoster,
        SelfRoomAction::SoleDevice => SelfRoomTick::SoleDevice,
        SelfRoomAction::Idle => {
            if let Some(h) = held_group {
                install_or_advance(st, &room, &owner, &h.group).await;
            }
            if let Some(l) = &st.lifecycle {
                l.seal_due(std::time::Instant::now());
            }
            SelfRoomTick::Idle
        }
        SelfRoomAction::PublishKeyPackage => {
            // THE WELCOME IS THE POINT OF THE KEYPACKAGE. The first cut
            // returned early forever once `pending` was set, so nothing ever
            // consumed the creator's Welcome and a second device published a
            // KeyPackage it could never act on — it stayed outside the room
            // while reporting success every tick (Codex, CIRISServer#628).
            // Look first, publish only if there is nothing to join.
            match join_if_welcomed(st, &room, &roster, &node_key, rival.as_ref()).await {
                Ok(Some(members)) => SelfRoomTick::Joined { members },
                Ok(None) => match publish_key_package(st, &room, &node_key).await {
                    Ok(()) => SelfRoomTick::PublishedKeyPackage,
                    Err(e) => SelfRoomTick::Failed(e),
                },
                Err(e) => SelfRoomTick::Failed(e),
            }
        }
        SelfRoomAction::Create => match create_room(st, &room, &owner, &node_key).await {
            Ok(n) => SelfRoomTick::Created { members: n },
            Err(e) => SelfRoomTick::Failed(e),
        },
        SelfRoomAction::Add(nodes) => match add_members(st, &room, &owner, &nodes).await {
            Ok(n) => SelfRoomTick::Added(n),
            Err(e) => SelfRoomTick::Failed(e),
        },
        SelfRoomAction::Remove(nodes) => match remove_members(st, &room, &owner, &nodes).await {
            Ok(n) => SelfRoomTick::Removed(n),
            Err(e) => SelfRoomTick::Failed(e),
        },
        SelfRoomAction::Abandon { in_favour_of } => {
            // Drop ours and wait for their Welcome. Dropping FIRST is the
            // point: a room about to be abandoned must not be addressed, or we
            // register destinations at a group that is going away.
            //
            // AND RETIRE ITS ADDRESSES. Clearing `held` drops this driver's
            // reference and nothing else — the snapshot installed in the
            // scope-address table survives it, so the node keeps LISTENING on
            // the derived address of a group it has just conceded, and keeps
            // advertising it to peers. `leave` retires every live epoch of the
            // group, which is exactly what abandoning means and is the one
            // moment no address of it should survive (Codex, CIRISServer#628).
            if let Some(life) = &st.lifecycle {
                let out = life.leave(&room.scope(), &room.table_group_id());
                if out.unretired > 0 {
                    tracing::warn!(
                        room = %room, retired = out.sealed, unretired = out.unretired,
                        "self room: abandoned the room but could not retire every address — \
                         this node still answers for a group it has left"
                    );
                } else {
                    tracing::info!(
                        room = %room, retired = out.sealed,
                        "self room: retired the abandoned room's addresses"
                    );
                }
            }
            *st.held.lock().await = None;
            tracing::info!(
                owner = %owner,
                winner = %in_favour_of.committer_key_id(),
                "self room: abandoning our claim — another of this identity's nodes holds the \
                 older claim, and two rooms would derive two secrets and address nobody"
            );
            SelfRoomTick::Abandoned
        }
    }
}

/// The oldest rival claim among the identity's other nodes, if any.
async fn first_rival(
    dir: &dyn ciris_persist::federation::FederationDirectory,
    roster: &[String],
    own: &str,
    room_id: &str,
) -> Option<CommitClaim> {
    let mut best: Option<CommitClaim> = None;
    for node in roster.iter().filter(|n| n.as_str() != own) {
        if let Ok(commits) = ciris_edge::chat::commits_from(dir, node, room_id).await {
            for (_, claim) in commits {
                if best.as_ref().is_none_or(|b| claim.wins_over(b)) {
                    best = Some(claim);
                }
            }
        }
    }
    best
}

/// Open the owner's pen — the actor a `self` row is crossed as.
///
/// Authorized by the node's OWNER BINDING, not by a session: this is a loop,
/// and `acquire`'s first line refuses a caller-less request (`NotSignedIn`).
/// Passing `bearer: None` here is how every owner-authored arm of this drive
/// refused on every tick while `Create` — the one arm that signs as the node —
/// succeeded, so a node created its self room and never admitted its second
/// device. See `owner_signer_capsule::for_owned_node`.
async fn owner_pen(
    st: &SelfRoomState,
    owner: &str,
) -> Result<crate::owner_signer_capsule::OwnerSignerCapsule, String> {
    let _ = owner; // the binding names the owner; we do not take the caller's word for it
    crate::owner_signer_capsule::for_owned_node(&st.engine, &st.node_signer.key_id)
        .await
        .map_err(|e| {
            format!(
                "the self room is keyed to the person who owns these devices, and this node \
                 cannot wield that identity: {e:?}"
            )
        })
}

/// **Join from a creator's Welcome, if one has arrived.**
///
/// `Ok(Some(members))` — we are in the room. `Ok(None)` — nothing to join yet,
/// so the caller publishes (or re-publishes) a KeyPackage.
///
/// The material is TAKEN before the join and is NOT restored on failure — it
/// cannot be: `CohortGroup::join` consumes it and `CohortKeyMaterial` is not
/// `Clone`. That is the right shape anyway. A Welcome is sealed to one
/// KeyPackage, so material that failed to consume one is spent; clearing
/// `pending` makes the next tick MINT AND REPUBLISH a fresh KeyPackage, which
/// is a recovery, where hoarding the dead material would retry the same
/// failure forever.
///
/// The claim stored is the CREATOR's, not a fresh one — we are adopting their
/// room, so their claim is the one that must win any later contest. Dating it
/// `now()` here would make this node's copy of the room look younger than the
/// room itself and invite it to abandon what it just joined.
async fn join_if_welcomed(
    st: &SelfRoomState,
    room: &ScopeRoom,
    roster: &[String],
    own: &str,
    rival: Option<&CommitClaim>,
) -> Result<Option<usize>, String> {
    if st.held.lock().await.is_some() {
        return Ok(None);
    }
    if st.pending.lock().await.is_none() {
        return Ok(None);
    }
    let dir = st.engine.federation_directory();
    let room_id = room.content_group_id();
    for node in roster.iter().filter(|n| n.as_str() != own) {
        let Some((welcome, _epoch)) = ciris_edge::chat::welcome_from(&*dir, node, room_id)
            .await
            .map_err(|e| format!("read {node}'s Welcome: {e}"))?
        else {
            continue;
        };
        let Some(material) = st.pending.lock().await.take() else {
            return Ok(None);
        };
        let store = SelfRoomState::store(room_id)?;
        match ciris_edge::mls::cohort_group::CohortGroup::join(
            store, room_id, material, &welcome, 16,
        )
        .await
        {
            Ok(group) => {
                let group = Arc::new(group);
                let members = group.member_key_ids().await.len();
                let claim = rival
                    .cloned()
                    .unwrap_or_else(|| CommitClaim::new(chrono::Utc::now(), node.clone()));
                *st.held.lock().await = Some(HeldGroup {
                    group: Arc::clone(&group),
                    claim,
                });
                install_or_advance(st, room, room.content_group_id(), &group).await;
                tracing::info!(
                    room = %room, from = %node, members,
                    "self room JOINED — this device is in its person's room"
                );
                return Ok(Some(members));
            }
            Err(e) => {
                // `pending` is already None (taken above), so the next tick
                // mints a fresh KeyPackage and republishes. See the note on
                // this function for why that beats keeping the spent material.
                return Err(format!(
                    "join {node}'s self room: {e} — republishing a fresh KeyPackage next tick"
                ));
            }
        }
    }
    Ok(None)
}

async fn publish_key_package(
    st: &SelfRoomState,
    room: &ScopeRoom,
    node_key: &str,
) -> Result<(), String> {
    use ciris_edge::mls::cohort_group::{key_package_to_bytes, mint_cohort_key_material};
    let mut pending = st.pending.lock().await;
    if pending.is_some() {
        // Published already; the creator adds us when it reads the row.
        return Ok(());
    }
    let (material, kp) =
        mint_cohort_key_material(node_key).map_err(|e| format!("mint key material: {e}"))?;
    let kp_bytes = key_package_to_bytes(kp).map_err(|e| format!("KeyPackage bytes: {e}"))?;
    let owner = room.content_group_id();
    let capsule = owner_pen(st, owner).await?;
    // ATTESTED BY THE NODE, NOT THE PERSON — and this is the whole reason a
    // second device could not join. `chat::key_package_from(dir, node, room)`
    // resolves through `rows_in_room` → `list_attestations_by(node)`: it asks
    // for rows THAT NODE ATTESTED. Those helpers were written for a chat room,
    // where a participant IS a person and their rows carry their own key. A
    // SELF room's participants are NODES while the person is one owner, so
    // signing the handshake with the owner's pen made every lookup by node
    // return None: the creator held the joiner's KeyPackage and could not
    // find it, added nobody, and the room stayed at one member forever while
    // every row crossed correctly. Rows plural, one attester, two axes — the
    // person/node fusion again.
    //
    // The node is also the RIGHT signer on the merits: a KeyPackage is a
    // device announcing its own MLS leaf (FSD/CONTENT_TRANSFER.md §5.3 R5,
    // "the room installed in the scope table — NODES, not persons"), and
    // edge's own `files::publish` builds its row from `signers.node`. The
    // owner's pen stays as the crossing ACTOR below, which is what carries the
    // person's authority for the placement.
    let row = ciris_edge::chat::key_package_attestation(
        &st.node_signer,
        room.content_group_id(),
        &kp_bytes,
        chrono::Utc::now(),
    )
    .await?;
    crate::contacts_chat::share_in(
        &*st.engine.federation_directory(),
        row,
        room,
        ciris_edge::replication::attestation_bind::Signers {
            node: &st.node_signer,
            actor: Some(capsule.edge_signer()),
        },
    )
    .await?;
    *pending = Some(material);
    Ok(())
}

async fn create_room(
    st: &SelfRoomState,
    room: &ScopeRoom,
    owner: &str,
    node_key: &str,
) -> Result<usize, String> {
    let group = CohortGroup::create(
        SelfRoomState::store(room.content_group_id())?,
        room.content_group_id(),
        node_key,
        16,
    )
    .await
    .map_err(|e| format!("create the self room: {e}"))?;
    let group = Arc::new(group);
    let members = group.member_key_ids().await.len();
    *st.held.lock().await = Some(HeldGroup {
        group: Arc::clone(&group),
        // Dated ONCE, here, when the room actually came into being.
        claim: CommitClaim::new(chrono::Utc::now(), node_key.to_owned()),
    });
    install_or_advance(st, room, owner, &group).await;
    tracing::info!(
        owner = %owner,
        room = %room,
        "self room CREATED — this node is its committer; other devices join from the \
         Welcome their KeyPackage earns"
    );
    Ok(members)
}

/// Undo an add whose rows could not be placed, so the next tick retries.
///
/// The tree is mutated by `add_member` BEFORE the Welcome exists to place, so
/// a failure after it leaves a member `decide` counts as present and therefore
/// never re-adds. Removing restores `in the tree ⇒ was welcomed`.
///
/// A failed rollback is WARNed, not returned: the caller is already returning
/// the placement error, and replacing it with the rollback's would name the
/// second problem and hide the first. This is the one state the drive cannot
/// repair by itself — the tree holds a member that was never welcomed — so it
/// says so in those words.
async fn rollback_add(group: &Arc<CohortGroup>, node: &str, cause: &str) {
    match group.remove_member(node).await {
        Ok(_) => tracing::warn!(
            %node, %cause,
            "self room: placing the add's rows failed — removed the device from the tree \
             again so the next tick can retry it cleanly"
        ),
        Err(e) => tracing::warn!(
            %node, %cause, error = %e,
            "self room: the add's rows could not be placed AND the member could not be \
             rolled back — the tree now holds a device that was never welcomed, and \
             `decide` will report Idle rather than retrying it"
        ),
    }
}

async fn add_members(
    st: &SelfRoomState,
    room: &ScopeRoom,
    owner: &str,
    nodes: &[String],
) -> Result<usize, String> {
    let Some(group) = st.held.lock().await.clone().map(|h| h.group) else {
        return Err("add without a held room — decide() and the tree disagree".into());
    };
    let dir = st.engine.federation_directory();
    let capsule = owner_pen(st, owner).await?;
    let mut added = 0usize;
    for node in nodes {
        // An add waits on the newcomer's KeyPackage, which is an asynchronous
        // arrival on another node. Missing is not an error: the next tick asks
        // again (and a removal never waits behind it — `decide` orders that).
        let Some(kp_bytes) =
            ciris_edge::chat::key_package_from(&*dir, node, room.content_group_id())
                .await
                .map_err(|e| format!("read {node}'s KeyPackage: {e}"))?
        else {
            continue;
        };
        let kp = ciris_edge::mls::cohort_group::key_package_from_bytes(&kp_bytes)
            .map_err(|e| format!("{node}'s KeyPackage: {e}"))?;
        // STEP LOGGING, because an add is rare (once per new device) and its
        // steps are the ones that can block: an MLS commit, then two
        // placements. A tick that stops between them used to leave no trace at
        // all — the loop simply never reported again.
        tracing::info!(%node, room = %room, "self room: adding a device — KeyPackage read");
        let commit = group
            .add_member(node, kp)
            .await
            .map_err(|e| format!("add {node}: {e}"))?;
        let welcome = commit
            .welcome()
            .ok_or_else(|| format!("adding {node} produced no Welcome"))?
            .to_vec();
        let epoch = commit.epoch();
        // Same axis: the joiner reads this with
        // `welcome_from(dir, <creator's NODE key>, room)`.
        let welcome_row = ciris_edge::chat::welcome_attestation(
            &st.node_signer,
            node,
            &welcome,
            epoch,
            chrono::Utc::now(),
        )
        .await?;
        tracing::info!(%node, epoch, "self room: committed the add; placing the Welcome");
        // FROM HERE THE TREE IS ALREADY MUTATED, and that is the hazard: if a
        // placement fails (or the watchdog cancels this tick), the next
        // `decide` sees the device present in `mine.members`, returns `Idle`,
        // and the Welcome it never received is never retried — the device sits
        // outside a room that believes it is inside (Codex, CIRISServer#628).
        //
        // So a placement failure ROLLS THE MEMBER BACK OUT, restoring the
        // invariant `in the tree ⇒ was welcomed` and letting the next tick
        // re-add cleanly. A rollback that itself fails is the one state we
        // cannot repair here, so it is WARNed by name rather than folded into
        // the returned error, which would name only the first failure.
        if let Err(e) = cross(st, room, welcome_row, &capsule).await {
            rollback_add(&group, node, &e).await;
            return Err(e);
        }
        // Same axis: `commits_from(dir, <node>, room_id)` in `first_rival`
        // below already reads commits BY NODE — these two must agree or a
        // node cannot even see its own rival.
        let commit_row = ciris_edge::chat::commit_attestation_in(
            &st.node_signer,
            room.content_group_id(),
            &commit,
        )
        .await?;
        if let Err(e) = cross(st, room, commit_row, &capsule).await {
            rollback_add(&group, node, &e).await;
            return Err(e);
        }
        tracing::info!(%node, epoch, "self room: device ADDED — Welcome and Commit placed");
        added += 1;
    }
    if added > 0 {
        install_or_advance(st, room, owner, &group).await;
    }
    Ok(added)
}

async fn remove_members(
    st: &SelfRoomState,
    room: &ScopeRoom,
    owner: &str,
    nodes: &[String],
) -> Result<usize, String> {
    let Some(group) = st.held.lock().await.clone().map(|h| h.group) else {
        return Err("remove without a held room — decide() and the tree disagree".into());
    };
    let capsule = owner_pen(st, owner).await?;
    let mut removed = 0usize;
    for node in nodes {
        let commit = group
            .remove_member(node)
            .await
            .map_err(|e| format!("remove {node}: {e}"))?;
        // Node-attested like every other handshake row — a removal Commit is
        // read back by `commits_from(dir, <node>, room_id)` exactly as an add's
        // is. See the note in `publish_key_package`.
        let row = ciris_edge::chat::commit_attestation_in(
            &st.node_signer,
            room.content_group_id(),
            &commit,
        )
        .await?;
        cross(st, room, row, &capsule).await?;
        removed += 1;
    }
    if removed > 0 {
        install_or_advance(st, room, owner, &group).await;
    }
    Ok(removed)
}

async fn cross(
    st: &SelfRoomState,
    room: &ScopeRoom,
    row: ciris_persist::federation::types::Attestation,
    capsule: &crate::owner_signer_capsule::OwnerSignerCapsule,
) -> Result<(), String> {
    crate::contacts_chat::share_in(
        &*st.engine.federation_directory(),
        row,
        room,
        ciris_edge::replication::attestation_bind::Signers {
            node: &st.node_signer,
            actor: Some(capsule.edge_signer()),
        },
    )
    .await
    .map(|_| ())
}

/// Put the room's derived addresses where the byte path can find them —
/// install the first time, advance when the epoch moved, refresh when the
/// roster resolved late at the same epoch (CIRISEdge#648).
async fn install_or_advance(
    st: &SelfRoomState,
    room: &ScopeRoom,
    owner: &str,
    group: &CohortGroup,
) {
    let Some(life) = &st.lifecycle else {
        tracing::debug!(
            room = %room,
            "self room: scope-native addressing is not armed on this node, so the room's \
             bytes have no derived destinations — rows still cross"
        );
        return;
    };
    let snap = match self_room::snapshot(group, owner).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(room = %room, error = %e, "self room: snapshot failed");
            return;
        }
    };
    let scope = room.scope();
    let verb = match life.table().live_epochs(&scope, &snap.group_id) {
        None => "install",
        Some(le) if le.current == snap.epoch || le.next == Some(snap.epoch) => "refresh",
        Some(_) => "advance",
    };
    let out = match verb {
        "install" => life.install(&scope, &snap),
        "advance" => life.advance(&scope, &snap, std::time::Instant::now()),
        _ => life.refresh_members(&scope, &snap),
    };
    match out {
        Ok(o) => tracing::info!(
            room = %room, verb, epoch = o.epoch, derived = o.derived,
            members = ?snap.members,
            "self room addresses in the scope-address table — this node listens on its own \
             derived address and dials its other devices'"
        ),
        Err(e) => tracing::warn!(
            room = %room, verb, error = %e,
            "self room: the scope-address table refused the room — self blobs will read \
             blob_holder_not_in_group until it is installed"
        ),
    }
}
