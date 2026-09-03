//! **Contacts + user chat** — the owner-facing surface over the substrate that
//! was already there.
//!
//! Nothing here is a new plane. Every object this module writes is a CEG object
//! persist already types, and every read is a persist reader:
//!
//! | route | the CEG object it moves | the persist primitive |
//! |---|---|---|
//! | `GET /v1/contacts` | `consent:replication:v1` grants, revocation-folded | [`crate::peer::live_consent_grants`] → `list_live_consent_grants_by` |
//! | `POST /v1/contacts` | one `consent:replication:v1` grant | [`crate::peer::ensure_replication_consent_covers`] |
//! | `POST /v1/chat` | a 2-member [`Community`] | `Engine::put_community_self_signed` |
//! | `POST /v1/chat/{id}/messages` | a `chat:message:v1` `scores` attestation | `attestation_upsert_local` + `attestation_promote(community)` |
//! | `GET /v1/chat/{id}/messages` | the same rows, read back | `active_community_members` + `list_attestations_by` |
//!
//! # Why a contact IS a replication-consent grant
//!
//! The client's `ContactsScreen` already renders `GET /v1/federation/peers`
//! (`LocalPeerState`), so the *display* substrate was never in question. The
//! question was what "add" writes. A contact is not an annotation and not a
//! table: it is the statement *"this node consents to replicate to that key"* —
//! which is exactly `consent:replication:v1`, and exactly the edge that makes a
//! chat message actually reach the other side. So `POST /v1/contacts` ENSURES that
//! grant covers `chat:` — emitting it, or widening a narrower standing one by
//! superseding it (PR #464 P1: an already-peered key holds a
//! `capacity:`/`trace:`-only grant, and a plain emit was a silent no-op against
//! it).
//!
//! And a CONTACT is specifically a peer whose live grant covers `chat:` — not
//! every consent peer. Both read sites (`GET /v1/contacts` and the guard on
//! `POST /v1/chat`) check the prefix, because an ordinarily-federated peer is
//! someone this node replicates to and CANNOT message: offering them as a
//! contact opens a room whose messages never leave. The fold that decides
//! liveness is persist's (`list_live_consent_grants_by`), so un-contacting stays
//! the ordinary CEG withdraw of the grant row, with no second code path.
//!
//! # Every route names a capability verb
//!
//! `resolve_bearer` hands a `dgrant:` token the owner's role AND `FullAccess`
//! together with the delegate's action constraints, so a role-only gate accepts
//! an announce-only delegate. The constraints are only enforced where a route
//! NAMES its verb — a route with no verb is a route with no enforcement — so all
//! five name one: `ChatRead` (both reads), `Peer` (add contact — it emits the
//! same object `POST /v1/federation/peering` does), `ChatCreate` (open a room),
//! and `ChatAuthor` (send), which is on the server never-list.
//!
//! The rows are then projected through [`crate::federation_peers::peer_projection`]
//! — the SAME `LocalPeerState` shape the contacts screen already binds to — so a
//! contact renders with the identical card, plus the contact-only fields.
//!
//! # Why a chat is a community, and where its name comes from
//!
//! `cohort_scope: community` is persist's visibility tier for exactly this: a
//! cohort-filtered audience that is neither `self` (invisible) nor `federation`
//! (public). The cohort itself is a [`Community`] row, and both sides must land
//! on the SAME one without talking first — so the id is DERIVED, not minted:
//!
//! ```text
//! chat:pair:v1:<sha256(lo ‖ "\n" ‖ hi)>      lo,hi = the two key_ids, sorted
//! ```
//!
//! Persist ships no such convention (checked: no pair/dyad derivation anywhere in
//! `federation/`), so this module owns it — [`pair_community_key_id`] — and both
//! ends compute it from public inputs alone. `founded_at` is derived too (the
//! later `valid_from` of the two member key records) rather than read from a
//! clock, so the two nodes author byte-identical roster content; only the
//! authority signature differs, because each node signs as itself.
//!
//! # The three substrate rules that shaped the message row
//!
//! These are persist's, verified against its gates rather than assumed:
//!
//! 1. **A community is not an admissible attested subject.**
//!    `check_attested_subject_admission` accepts a registered `federation_keys`
//!    row or a constitutional FAMILY — and nothing else. So `attested_key_id`
//!    CANNOT be the `community_key_id`; the community binding rides the ENVELOPE
//!    (`community_id`), exactly as `safety::moderation` already does.
//! 2. **A community-scoped row may name no party but its own producer.**
//!    `check_promotion_cohort_standing` refuses a `family`/`community` promotion
//!    unless `attested_key_id == attesting_key_id` and every `subject_key_ids`
//!    entry is the producer. So "both members hold revocation rights" is not
//!    expressible on this row — persist refuses it as
//!    `CohortStandingRefusal::NamedSubject`. The author alone withdraws/recants
//!    their own message, which is the CEG rule anyway.
//! 3. **`cohort_scope` is a closed 7-value vocabulary**, not a cohort id. The
//!    row is placed at the `community` TIER; which community is envelope data.
//!
//! # The read gate is the substrate's, not ours
//!
//! [`CallerScope::admits`] is persist's own §4.3 predicate. The caller's
//! admission set is built by `build_caller_admission` — resolved from the
//! directory (occurrence → identity → ACTIVE communities, revocations folded),
//! never caller-asserted (AV-44). `GET /v1/chat/{id}/messages` asks it one
//! question — `admits(community, <community_id>)` — and a non-member is refused
//! even when they are this node's own owner. Authority over the node is not
//! membership in a cohort, and that is the whole point of the tier.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use ciris_persist::federation::admission;
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::precedence;
use ciris_persist::federation::types::{attestation_type, cohort_scope, Attestation};
use ciris_persist::prelude::{CallerScope, Engine};

use crate::attestation_crossing;
use crate::auth::refusal::refuse;
use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::{resolve_bearer, SessionCaller};

// ─── Vocabulary ─────────────────────────────────────────────────────────────

// ── THE CHAT VOCABULARY IS EDGE'S, RE-EXPORTED (CIRISServer#524) ────────────
//
// Every one of these was spelled here as a `const` of its own, and the copies
// drifted exactly where a copy always drifts — at the member nobody re-reads.
// Edge says `community_key_id`; this file said `community_id`. The two agreed
// for as long as nothing compared them, and the moment edge v19.0.0 added a
// per-recipient CC 5.2 audience gate the rows stopped being served: the wire
// had two names for one field and only one of them was edge's.
//
// It survived our own tests because `is_message_for` asks persist's
// `admission::envelope_cohort_target`, and BOTH spellings are in
// `COHORT_TARGET_ENVELOPE_FIELDS` — so the reader resolved either while the
// writer emitted the wrong one. A gate that accepts both names cannot tell you
// that you are writing the wrong one.
//
// `pub use`, not re-declaration: a rename in edge is now a compile error here
// instead of a silent divergence on the wire.
pub use ciris_edge::chat::{
    pair_community_key_id, CHAT_ATTESTATION_PREFIX, CHAT_MESSAGE_DIMENSION, FIELD_BODY,
    FIELD_COMMUNITY_ID, FIELD_CONTENT_TYPE, FIELD_ON_BEHALF_OF, PAIR_COMMUNITY_PREFIX,
};

/// What an omitted `content_type` means.
const DEFAULT_CONTENT_TYPE: &str = "text/plain";

/// Message-body ceiling. Persist's own cap is the 1 MiB
/// `MAX_ATTESTATION_ENVELOPE_BYTES` over the CANONICAL envelope; refusing far
/// below it here means a client gets a typed `chat.message_too_large` instead of
/// an opaque substrate `EnvelopeTooLarge` after the row was already built.
const MAX_MESSAGE_BYTES: usize = 16 * 1024;

// ─── State + refusal helpers ────────────────────────────────────────────────

#[derive(Clone)]
struct ChatState {
    engine: Arc<Engine>,
    /// The node's owner-seed location — what [`crate::owner_signer_capsule`]
    /// needs to re-open the responsible party's fed-ID under a live owner
    /// session. A chat row is signed by the PERSON, so the route has to be able
    /// to reach their signer; the capsule is the gate that decides whether it may.
    user_seed_dir: std::path::PathBuf,
    /// Live MLS state per room — see [`RoomState`].
    rooms: Arc<tokio::sync::Mutex<std::collections::HashMap<String, RoomState>>>,
    /// THIS NODE's edge signer — the room record's authority.
    ///
    /// Edge's chat surface takes `ciris_edge::identity::LocalSigner`, which is
    /// edge's own type and not persist's; the node's is built once at boot from
    /// the same sealed federation key the Engine holds, plus its ML-DSA-65 half,
    /// because from edge v20.0.0 there is no classical-only signing path
    /// anywhere in the chat plane.
    node_signer: Arc<ciris_edge::identity::LocalSigner>,
}

/// Where a room's MLS handshake has got to on THIS node.
///
/// The conversation key is derived from a live `CohortGroup` (`RoomKey::of`), and
/// the group is built by a two-row handshake OVER the room: the joiner publishes
/// a `chat:key_package:v1`, the creator answers with a `chat:welcome:v1`. Which
/// side we are is decided from the two fed-IDs alone — `PairRole::of` is
/// order-free, so neither end has to be told and there is nothing to coordinate.
///
/// It is a state machine and not a single `CohortGroup` because the joiner mints
/// its key material BEFORE the creator's Welcome exists, and the very same
/// material is what `CohortGroup::join` consumes when the Welcome lands. Dropping
/// it between the two requests would mint a second KeyPackage the creator never
/// admitted, and the join would fail against a group that had added the first.
enum RoomState {
    /// Joiner: our KeyPackage is published; this is the material the Welcome
    /// will be joined with.
    AwaitingWelcome(ciris_edge::mls::cohort_group::CohortKeyMaterial),
    /// Both roles, once the handshake completes.
    Keyed(Arc<ciris_edge::mls::CohortGroup>),
}

/// Put a row and place it in the room — the ONE way this module writes chat.
///
/// Authored `self` and signed at write by the HUMAN, entered over the same bytes
/// with the node's co-scrub, then widened to `community` by the owner's own
/// `supersedes`. Two rows; the peer receives the second. Copied from edge's own
/// `share_in_room` (`src/bin/edge_node.rs`) rather than re-derived, because the
/// ordering — store, then `share` — is what makes the crossing act on bytes that
/// already exist.
async fn share_in_room(
    dir: &dyn ciris_persist::federation::FederationDirectory,
    row: Attestation,
    room: &str,
    signers: ciris_edge::replication::attestation_bind::Signers<'_>,
) -> Result<String, String> {
    use ciris_edge::replication::attestation_bind::{share, CrossingBasis, Shared, With};
    dir.put_attestation(ciris_persist::federation::SignedAttestation {
        attestation: row.clone(),
    })
    .await
    .map_err(|e| format!("put {}: {e}", row.attestation_id))?;
    let crossing = share(
        dir,
        &row,
        With::Community {
            community_key_id: room.to_owned(),
        },
        CrossingBasis::ProducerAuthority,
        signers,
    )
    .await?;
    match crossing.shared {
        // The PLACED row's id — the widening, which is what the room reads.
        Shared::Placed { attestation_id } | Shared::AlreadyThere { attestation_id } => {
            Ok(attestation_id)
        }
        Shared::AwaitingActor {
            attestation_id,
            age_ms,
        } => Err(format!(
            "the row {attestation_id} waits for its author's signer ({age_ms} ms) — \
             a chat row is signed by the person, and this node does not hold that key"
        )),
    }
}

/// Advance this room's MLS handshake as far as the rows on disk allow, and
/// return the conversation key once it is complete.
///
/// `Ok(None)` is NOT a failure: it means the counterpart's handshake row has not
/// replicated yet. That is the self-resolving stall in edge's ladder vocabulary
/// — the caller should say "not keyed yet" and let the mesh converge, never
/// retry in a loop and never alarm a person.
///
/// Deliberately driven off the DIRECTORY rather than a wait: these run inside an
/// HTTP request, and blocking one on mesh convergence turns a chat send into a
/// timeout. Edge's `sync_and_await` is the right tool for a background driver
/// and the wrong one here.
async fn room_key(
    st: &ChatState,
    me: &str,
    peer: &str,
    author: &ciris_edge::identity::LocalSigner,
) -> Result<Option<ciris_edge::chat::RoomKey>, String> {
    use ciris_edge::chat::{self, PairRole, RoomKey};
    use ciris_edge::mls::cohort_group::{
        key_package_from_bytes, key_package_to_bytes, mint_cohort_key_material,
    };
    use ciris_edge::mls::{CohortGroup, ScopeStateProvider};
    use ciris_persist::encrypted_kv::XChaChaKvStore;

    let room = pair_community_key_id(me, peer);
    let dir = st.engine.federation_directory();
    let mut rooms = st.rooms.lock().await;

    if let Some(RoomState::Keyed(group)) = rooms.get(&room) {
        return RoomKey::of(group).await.map(Some);
    }

    // The MLS store is keyed by the room and lives for the process. State that
    // outlives a restart is a separate concern (the group can be rebuilt from the
    // handshake rows, which are durable CEG); what must NOT happen is two rooms
    // sharing one store.
    let store = ScopeStateProvider::new(Arc::new(
        XChaChaKvStore::open_in_memory(room.as_bytes())
            .map_err(|e| format!("open the room's MLS store: {e}"))?,
    ));

    match PairRole::of(me, peer) {
        PairRole::Creator => {
            let Some(kp_bytes) = chat::key_package_from(&*dir, peer, &room).await? else {
                return Ok(None); // the joiner has not published theirs yet
            };
            let group = CohortGroup::create(store, &room, me, 16)
                .await
                .map_err(|e| format!("CohortGroup::create: {e}"))?;
            let kp = key_package_from_bytes(&kp_bytes).map_err(|e| format!("KeyPackage: {e}"))?;
            let commit = group
                .add_member(peer, kp)
                .await
                .map_err(|e| format!("add_member: {e}"))?;
            let epoch = commit.epoch();
            let welcome = commit
                .welcome()
                .ok_or("add_member produced no Welcome")?
                .to_vec();
            let row = chat::welcome_attestation(author, peer, &welcome, epoch, chrono::Utc::now())
                .await?;
            share_in_room(
                &*dir,
                row,
                &room,
                ciris_edge::replication::attestation_bind::Signers {
                    node: &st.node_signer,
                    actor: Some(author),
                },
            )
            .await?;
            let key = RoomKey::of(&group).await?;
            rooms.insert(room, RoomState::Keyed(Arc::new(group)));
            Ok(Some(key))
        }
        PairRole::Joiner => {
            let material = match rooms.remove(&room) {
                Some(RoomState::AwaitingWelcome(m)) => m,
                _ => {
                    // Publish our half once, then wait for the Welcome.
                    let (material, kp) = mint_cohort_key_material(me)
                        .map_err(|e| format!("mint_cohort_key_material: {e}"))?;
                    let kp_bytes =
                        key_package_to_bytes(kp).map_err(|e| format!("KeyPackage: {e}"))?;
                    let row =
                        chat::key_package_attestation(author, peer, &kp_bytes, chrono::Utc::now())
                            .await?;
                    share_in_room(
                        &*dir,
                        row,
                        &room,
                        ciris_edge::replication::attestation_bind::Signers {
                            node: &st.node_signer,
                            actor: Some(author),
                        },
                    )
                    .await?;
                    material
                }
            };
            let Some((welcome, _epoch)) = chat::welcome_from(&*dir, peer, &room).await? else {
                rooms.insert(room, RoomState::AwaitingWelcome(material));
                return Ok(None); // the creator has not answered yet
            };
            let group = CohortGroup::join(store, &room, material, &welcome, 16)
                .await
                .map_err(|e| format!("CohortGroup::join: {e}"))?;
            let key = RoomKey::of(&group).await?;
            rooms.insert(room, RoomState::Keyed(Arc::new(group)));
            Ok(Some(key))
        }
    }
}

/// The owner-authority context every route here runs under: WHICH node, and
/// WHICH human is responsible for it. The owner's key is the chat identity —
/// messages are authored by the person, not by the box.
struct Owner {
    /// This node's #247 DERIVED federation key_id.
    node_key_id: String,
    /// The responsible party's federation identity key (the fedID) —
    /// `auth::gate::require_owner_bound`'s return, not a caller-supplied value.
    key_id: String,
    /// The verified session. Carried because the OWNER-vs-DELEGATE distinction
    /// is invisible in the role (`resolve_bearer` hands a `dgrant:` token the
    /// owner's role AND `FullAccess` by design), so only `caller.actor` can tell
    /// them apart — and one route here may not be exercised by a delegate at
    /// all. See [`CapabilityVerb::ChatAuthor`].
    caller: SessionCaller,
}

/// Owner-authority gate for this surface: a `SYSTEM_ADMIN` session on an
/// owner-BOUND node, resolving the responsible party's key. The predicate is the
/// same one `federation_peers::require_owner_session` +
/// `auth::gate::require_owner_bound` apply to the peer sideband writes; the
/// difference is that every refusal here carries a typed `reason_id`
/// (CIRISServer#389), because this surface is one a client localizes.
async fn require_owner(st: &ChatState, headers: &HeaderMap) -> Result<Owner, Response> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return Err(refuse(
            StatusCode::UNAUTHORIZED,
            "auth.owner_gate.missing_bearer",
            "missing bearer session token",
        ));
    };
    let caller = match resolve_bearer(&st.engine, token).await {
        Ok(Some(caller))
            if caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) =>
        {
            caller
        }
        Ok(Some(_)) => {
            return Err(refuse(
                StatusCode::FORBIDDEN,
                "auth.owner_gate.not_owner",
                "contacts and chat are owner (SYSTEM_ADMIN) surfaces",
            ))
        }
        Ok(None) => {
            return Err(refuse(
                StatusCode::UNAUTHORIZED,
                "auth.owner_gate.invalid_session",
                "invalid or expired session",
            ))
        }
        Err(e) => {
            return Err(refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.owner_gate.store_unavailable",
                format!("session store: {e}"),
            ))
        }
    };
    let node_key_id = crate::self_identity::resolve(&st.engine, "contacts_chat")
        .await
        .map_err(|e| {
            refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.owner_gate.no_self_identity",
                format!("{} ({e})", crate::self_identity::MESSAGE_TEXT),
            )
        })?;
    // The serve-only floor (CC 3.2 / CC 1.13.5): an owner-UNBOUND node has no
    // responsible party, so it has no chat identity to author as either.
    let key_id = crate::auth::gate::require_owner_bound(&st.engine, &node_key_id)
        .await
        .map_err(|()| {
            refuse(
                StatusCode::FORBIDDEN,
                "auth.owner_gate.node_unowned",
                "this node has no responsible party (owner-binding) — contacts and chat \
                 are refused (CC 3.2 / CC 1.13.5). Claim ownership first via POST /v1/setup/root.",
            )
        })?;
    Ok(Owner {
        node_key_id,
        key_id,
        caller,
    })
}

/// Render a delegation refusal in THIS surface's `{error, reason_id}` shape.
///
/// The RULE is single-sourced in [`crate::auth::gate::authorize_delegated`] —
/// this only chooses how to say it. `auth::gate::deny_response` emits the
/// `delegation_denied` envelope `admin_ops` and the peering routes use; this
/// surface's contract is `{error, reason_id}` and clients bind localization keys
/// against it (see `auth::refusal`'s own note that the two are deliberately
/// different contracts). Two renderings of one rule, never two rules.
fn require_verb(
    owner: &Owner,
    verb: crate::auth::gate::CapabilityVerb,
    reason_id: &'static str,
) -> Option<Response> {
    crate::auth::gate::authorize_delegated(&owner.caller, verb)
        .err()
        .map(|deny| refuse(StatusCode::FORBIDDEN, reason_id, deny.detail))
}

// ─── The pair room ──────────────────────────────────────────────────────────
//
// The id itself is `chat::pair_community_key_id`, re-exported above. The note
// that used to live here explained a derivation this file no longer owns; edge
// states it, and both ends of a room now read the same sentence.

// ─── GET /v1/contacts ───────────────────────────────────────────────────────

/// `GET /v1/contacts` → `{ "contacts": [Contact…], "total": N }`.
///
/// A `Contact` is a `LocalPeerState` (the shape the client's contacts screen
/// already binds) with four contact-only members added:
/// `contact: true`, `chat_community_id`, `chat_started`, `occurrence_key_ids`.
async fn list_contacts(State(st): State<ChatState>, headers: HeaderMap) -> Response {
    let owner = match require_owner(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    if let Some(resp) = require_verb(
        &owner,
        crate::auth::gate::CapabilityVerb::ChatRead,
        "contacts.delegation_denied",
    ) {
        return resp;
    }
    // Persist's revocation-FOLDED consent peer set, WITH what each grant covers.
    // A withdrawn grant is already gone here, so un-contacting needs no second
    // code path — and the `chat:` filter below is why this reads prefixes rather
    // than bare peer ids.
    let grants = match crate::peer::live_consent_grants(&st.engine, &owner.node_key_id).await {
        Ok(g) => g,
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "contacts.store_unavailable",
                format!("consent peer set: {e}"),
            )
        }
    };
    // A CONTACT is a peer this node can actually MESSAGE, not merely one it
    // replicates to. An ordinarily-federated peer carries the default
    // `capacity:`/`trace:` grant and no `chat:`; listing them would offer the
    // human a conversation that silently never leaves this node.
    //
    // #472 — a routable grant names the contact's NODE, but the contact IS the
    // PERSON: each chat-covering subject resolves through persist's owner_of
    // (the withdraws-aware owner-binding fold) back to the human it speaks
    // for. A person-subject grant (legacy, or the unclaimed-contact fallback)
    // stays as-is; two grants resolving to one person are ONE contact.
    let mut peer_ids: Vec<String> = Vec::new();
    for (subject, prefixes) in grants {
        if !prefixes.iter().any(|p| p == CHAT_ATTESTATION_PREFIX) {
            continue;
        }
        let person = match st.engine.owner_of(&subject).await {
            Ok(Some(owner_key)) => owner_key,
            Ok(None) => subject,
            Err(e) => {
                return refuse(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "contacts.store_unavailable",
                    format!("owner_of({subject}): {e}"),
                )
            }
        };
        if !peer_ids.contains(&person) {
            peer_ids.push(person);
        }
    }
    let directory = st.engine.federation_directory();
    let mut contacts = Vec::with_capacity(peer_ids.len());
    for key_id in peer_ids {
        // The SAME projection `GET /v1/federation/peers` serves, resolved one
        // key at a time — see `peer_projection`'s doc for why the bulk listing
        // cannot answer for a `user` identity.
        let card =
            match crate::federation_peers::peer_projection(Arc::clone(&st.engine), &key_id).await {
                Ok(card) => card,
                Err(e) => {
                    return refuse(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "contacts.store_unavailable",
                        format!("peer projection: {e}"),
                    )
                }
            };
        // A contact this node has consented to but whose key it can no longer
        // project (a de-admitted key with the grant still standing) is STILL a
        // contact: report it with what is known rather than dropping it, which
        // would make a live grant invisible to the human who authored it.
        let mut card = card.unwrap_or_else(|| {
            serde_json::json!({
                "key_id": key_id,
                "canonical": false,
                "trust": "unknown",
            })
        });
        let community_id = pair_community_key_id(&owner.key_id, &key_id);
        let chat_started = matches!(directory.lookup_community(&community_id).await, Ok(Some(_)));
        let occurrence_key_ids: Vec<String> = directory
            .list_identity_occurrences_active(&key_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|o| o.occurrence_key_id)
            .collect();
        if let Some(obj) = card.as_object_mut() {
            obj.insert("contact".into(), serde_json::json!(true));
            obj.insert("chat_community_id".into(), serde_json::json!(community_id));
            obj.insert("chat_started".into(), serde_json::json!(chat_started));
            obj.insert(
                "occurrence_key_ids".into(),
                serde_json::json!(occurrence_key_ids),
            );
        }
        contacts.push(card);
    }
    let total = contacts.len();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "contacts": contacts, "total": total })),
    )
        .into_response()
}

// ─── POST /v1/contacts ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AddContactRequest {
    /// The contact's federation identity key (their fedID).
    key_id: String,
}

#[derive(Debug, Serialize)]
struct AddContactResponse {
    key_id: String,
    /// The `consent:replication:v1` grant row that IS the contact relationship.
    consent_attestation_id: String,
    /// `false` when the standing grant already covered every required prefix —
    /// the true no-op. `true` when a grant row was written, whether it was the
    /// first grant for this peer or a widening one.
    freshly_emitted: bool,
    /// The narrower grant this call superseded, when it widened one (PR #464
    /// P1: an already-peered key holds a `capacity:`/`trace:`-only grant).
    /// `null` on a first grant or a no-op.
    #[serde(skip_serializing_if = "Option::is_none")]
    superseded_attestation_id: Option<String>,
    /// The prefix set the live grant now covers. `chat:` being present is what
    /// makes this contact's messages eligible to replicate to them.
    consent_prefixes: Vec<String>,
    /// The contact's ACTIVE identity occurrences, resolved from the directory.
    occurrence_key_ids: Vec<String>,
    /// The community id a chat with this contact will converge on.
    chat_community_id: String,
}

/// `POST /v1/contacts` — add a contact by fedID.
///
/// The fedID must already be a key this node's federation directory holds: a
/// contact is a consent statement ABOUT a known key, and consenting to replicate
/// to a key with no provenance is how an announce bookmark becomes an authority.
/// Admission of a new key is a separate, deliberate act
/// (`POST /v1/federation/peering`), and keeping the two apart is the point.
async fn add_contact(
    State(st): State<ChatState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let owner = match require_owner(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    // `POST /v1/contacts` emits the SAME `consent:replication:v1` grant
    // `POST /v1/federation/peering` does, so it MUST answer to the same verb.
    // Without this a delegate an owner had explicitly denied `peer` could author
    // the identical object through the contacts door — a gate is only as narrow
    // as its widest route.
    if let Some(resp) = require_verb(
        &owner,
        crate::auth::gate::CapabilityVerb::Peer,
        "contacts.delegation_denied",
    ) {
        return resp;
    }
    let req: AddContactRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "contacts.malformed_body",
                format!("expected {{\"key_id\": \"…\"}}: {e}"),
            )
        }
    };
    let key_id = req.key_id.trim().to_owned();
    if key_id.is_empty() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "contacts.malformed_body",
            "key_id must be a non-empty federation key id",
        );
    }
    if key_id == owner.key_id || key_id == owner.node_key_id {
        return refuse(
            StatusCode::BAD_REQUEST,
            "contacts.self_contact",
            "refusing to add this node's own identity as a contact",
        );
    }
    let directory = st.engine.federation_directory();
    match directory.lookup_public_key(&key_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return refuse(
                StatusCode::NOT_FOUND,
                "contacts.unknown_fed_id",
                format!(
                    "{key_id:?} is not in this node's federation directory — admit the key \
                     first (POST /v1/federation/peering); an announced-but-unadmitted \
                     bookmark carries no provenance and cannot be consented to"
                ),
            )
        }
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "contacts.store_unavailable",
                format!("directory lookup: {e}"),
            )
        }
    }
    // Resolve their identity occurrences — the devices this contact actually
    // speaks from. Reported, never required: a peer NODE legitimately has none,
    // and refusing on absence would make node contacts unaddable.
    let occurrence_key_ids: Vec<String> = directory
        .list_identity_occurrences_active(&key_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|o| o.occurrence_key_id)
        .collect();

    // THE contact object — ENSURED, not merely emitted (PR #464 P1).
    //
    // `emit_replication_consent` alone was wrong here in the one case that
    // matters most: a peer this node had already FEDERATED with holds a grant
    // covering `capacity:`/`trace:` only, and that function's guard matches on
    // (subject, dimension) without ever comparing prefixes — so adding an
    // already-peered key as a contact returned success while `chat:` rows
    // stayed ineligible to replicate to them. The people you know best were
    // exactly the people you could not message.
    //
    // `ensure_contact_consent_covers` asks BOTH questions the guard did not:
    // does the LIVE grant cover `chat:`, and does it name a subject the WIRE
    // can route (#472 — the contact's bound NODE, resolved through persist's
    // own withdraws-aware nodes_stewarded_by; an unclaimed contact falls back
    // to the person-subject grant as recorded intent).
    let mut prefixes = crate::peer::default_attestation_prefixes();
    prefixes.push(CHAT_ATTESTATION_PREFIX.to_owned());
    let (grant, _covered_subjects) = match crate::peer::ensure_contact_consent_covers(
        &st.engine,
        &owner.node_key_id,
        &key_id,
        &prefixes,
    )
    .await
    {
        Ok(g) => g,
        Err(e) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "contacts.consent_emit_failed",
                format!(
                    "ensure consent:replication:v1 grant covers {CHAT_ATTESTATION_PREFIX}: {e}"
                ),
            )
        }
    };
    let chat_community_id = pair_community_key_id(&owner.key_id, &key_id);
    (
        StatusCode::OK,
        Json(AddContactResponse {
            key_id,
            consent_attestation_id: grant.attestation_id,
            freshly_emitted: grant.freshly_emitted,
            superseded_attestation_id: grant.superseded_attestation_id,
            consent_prefixes: grant.prefixes,
            occurrence_key_ids,
            chat_community_id,
        }),
    )
        .into_response()
}

// ─── POST /v1/chat ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct StartChatRequest {
    /// The contact to chat with.
    key_id: String,
}

#[derive(Debug, Serialize)]
struct StartChatResponse {
    community_id: String,
    community_name: String,
    member_key_ids: Vec<String>,
    /// The visibility tier the chat's messages are placed at — always
    /// `community`. Named in the response so a client never has to infer it.
    cohort_scope: &'static str,
    /// `false` when the community already existed (the call is idempotent).
    freshly_created: bool,
}

/// `POST /v1/chat` — get-or-create the two-member community for
/// `(owner, contact)`.
///
/// Convergent by construction: the id is derived ([`pair_community_key_id`]) and
/// the roster content is derived (sorted members, `founded_at` = the later of
/// the two key records' `valid_from`), so both ends author the same row from
/// public inputs. Idempotent by lookup: persist's `put_community` is a plain
/// INSERT that errors on a PK collision, so the existing row is returned rather
/// than re-authored.
async fn start_chat(
    State(st): State<ChatState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let owner = match require_owner(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    if let Some(resp) = require_verb(
        &owner,
        crate::auth::gate::CapabilityVerb::ChatCreate,
        "chat.delegation_denied",
    ) {
        return resp;
    }
    // The DECLARED-conformance gate, beside the delegation gate: ChatCreate is
    // [Producer, Substrate] in conformance::required_profiles, and a
    // declaration is only real if something REFUSES when it is absent — a node
    // whose config:node.conformance_profiles does not claim those roles must
    // not author a federation-wire Community. Same idiom as peering's gate.
    if let Some(resp) =
        crate::conformance::require_op(&st.engine, crate::auth::gate::CapabilityVerb::ChatCreate)
            .await
    {
        return resp;
    }
    let req: StartChatRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "chat.malformed_body",
                format!("expected {{\"key_id\": \"…\"}}: {e}"),
            )
        }
    };
    let key_id = req.key_id.trim().to_owned();
    if key_id.is_empty() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "chat.malformed_body",
            "key_id must be a non-empty federation key id",
        );
    }
    if key_id == owner.key_id {
        return refuse(
            StatusCode::BAD_REQUEST,
            "chat.self_chat",
            "refusing to open a two-member chat with yourself",
        );
    }
    let directory = st.engine.federation_directory();

    // The peer must be a CONTACT — meaning the LIVE grant covers `chat:`, not
    // merely that a grant exists. Being federated with someone is not the same as
    // being able to message them: an ordinarily-peered key carries `capacity:`/
    // `trace:` only, and accepting it here opens a room whose messages are stored
    // locally and never become eligible to replicate — a one-way plane that looks
    // like a working conversation from this side, which is the worst way for it
    // to fail.
    match crate::peer::contact_grant_prefixes(&st.engine, &owner.node_key_id, &key_id).await {
        Ok(Some(prefixes)) if prefixes.iter().any(|p| p == CHAT_ATTESTATION_PREFIX) => {}
        Ok(Some(prefixes)) => {
            return refuse(
                StatusCode::FORBIDDEN,
                "chat.not_a_contact",
                format!(
                    "{key_id:?} is a consent peer but its live grant does not cover \
                     {CHAT_ATTESTATION_PREFIX:?} (it covers {prefixes:?}) — POST /v1/contacts \
                     to widen it"
                ),
            )
        }
        Ok(None) => {
            return refuse(
                StatusCode::FORBIDDEN,
                "chat.not_a_contact",
                format!("{key_id:?} is not a contact — POST /v1/contacts first"),
            )
        }
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "chat.store_unavailable",
                format!("consent peer set: {e}"),
            )
        }
    }

    let community_id = pair_community_key_id(&owner.key_id, &key_id);
    let mut expected_members = vec![owner.key_id.clone(), key_id.clone()];
    expected_members.sort();
    match directory.lookup_community(&community_id).await {
        Ok(Some(existing)) => {
            // THE ROSTER IS PART OF THE IDENTITY. The pair id is derivable by
            // anyone, so a peer can pre-replicate a community under it carrying
            // the pair PLUS an extra member — and a front door that accepts any
            // row at the derived id would open that room, with every subsequent
            // community-scoped message readable by the stowaway. Same sorted-
            // member equality the insert-race arm applies: a room at this id
            // that is not EXACTLY this pair is a conflict, not a chat.
            let mut existing_members: Vec<String> =
                existing.members.iter().map(|m| m.key_id.clone()).collect();
            existing_members.sort();
            if existing_members != expected_members {
                return refuse(
                    StatusCode::CONFLICT,
                    "chat.community_shape_conflict",
                    format!(
                        "a community already exists under the derived pair id but its                          roster is not this pair ({} member(s), expected 2) — refusing                          to open it as this chat",
                        existing_members.len()
                    ),
                );
            }
            return (
                StatusCode::OK,
                Json(StartChatResponse {
                    community_id: existing.community_key_id,
                    community_name: existing.community_name,
                    member_key_ids: existing_members,
                    cohort_scope: cohort_scope::COMMUNITY,
                    freshly_created: false,
                }),
            )
                .into_response();
        }
        Ok(None) => {}
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "chat.store_unavailable",
                format!("lookup_community: {e}"),
            )
        }
    }

    // `founded_at` is DERIVED, not read from a clock: the later `valid_from` of
    // the two member key records. A community cannot predate its members, and a
    // derived instant is the same on both nodes — a `Utc::now()` here would make
    // the two ends author rows that differ in a signed field.
    let mut founded_at = None;
    for member in [&owner.key_id, &key_id] {
        match directory.lookup_public_key(member).await {
            Ok(Some(rec)) => {
                founded_at = Some(match founded_at {
                    Some(prev) if prev > rec.valid_from => prev,
                    _ => rec.valid_from,
                });
            }
            Ok(None) => {
                return refuse(
                    StatusCode::NOT_FOUND,
                    "chat.unknown_fed_id",
                    format!("{member:?} is not in this node's federation directory"),
                )
            }
            Err(e) => {
                return refuse(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "chat.store_unavailable",
                    format!("directory lookup: {e}"),
                )
            }
        }
    }
    let Some(founded_at) = founded_at else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "chat.store_unavailable",
            "could not resolve either member's key record",
        );
    };

    let member_key_ids = expected_members;
    // ── THE ROOM RECORD IS EDGE'S (CIRISServer#524) ─────────────────────────
    //
    // This built the `Community` by hand, and the roster it produced differed
    // from edge's in the one way that matters: both members carried
    // `role: None`. Edge names both people `founder` outright, and says why —
    // CC 4.5.4 / §11.11, no unmoderated federated space: "persist refuses to
    // federate any content keyed on a community that has no live named
    // moderator, and a named moderator exists iff the community has a
    // steward-bound AUTHORITY root". A pair room is two equals, so the record
    // makes each an authority root BY CONSTRUCTION rather than by the accident
    // of a protocol setting.
    //
    // `community_name` was a second copy too — a sorted `"{a} <-> {b}"`, the
    // same string edge formats — and it sits INSIDE `Community::signing_envelope`,
    // so a drift there would have been two different signed records under one id.
    //
    // Edge's own note: "Everything that opens a pair room — the mesh harness,
    // the tests, a consumer — builds it here, so the roster shape cannot drift
    // between them." We were the consumer that drifted.
    let signed = match ciris_edge::chat::signed_pair_community(
        &owner.key_id,
        &key_id,
        founded_at,
        &st.node_signer,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "chat.store_unavailable",
                format!("signed_pair_community: {e}"),
            )
        }
    };
    // Signed by edge over `Community::signing_envelope()` — the JCS field-set
    // gate verifies exactly those bytes, which is why the record is never
    // hand-rolled on either side of the room.
    // The name the record actually carries — read off the signed room rather
    // than re-derived, so the response cannot describe a room differently from
    // the bytes that were stored.
    let community_name = signed.community.community_name.clone();
    if let Err(e) = st.engine.federation_directory().put_community(signed).await {
        // A LOST RACE IS A SUCCESS SOMEONE ELSE ALREADY HAD. Two concurrent
        // POSTs (double-tap, client retry, two devices) can both observe
        // `lookup_community` returning None above; one insert wins and the
        // other lands here on the primary-key conflict.
        //
        // persist v38.2.0 NARROWED when this arm fires: an IDENTICAL re-put is
        // now an Ok no-op at the door (first-accepted authority signature
        // preserved), so the ordinary race never errors at all. What still
        // reaches here is the typed Conflict for DIFFERING content under the
        // id — a roster-fork signal — plus any backend that predates the
        // verdict semantics. The roster-equality re-read below is exactly the
        // fork discriminator: matching roster → idempotent success;
        // differing → the 500 carries the substrate's own Conflict message. The room the loser
        // asked for EXISTS — reporting 500 would break the route's advertised
        // idempotency exactly on the inputs where idempotency matters. So on
        // failure, re-read the derived id: if the room is there with the same
        // convergent identity, this call is the second arrival, not an error.
        // A re-read that finds nothing (or a different shape) is a REAL
        // failure and keeps the 500 with the original error.
        if let Ok(Some(existing)) = directory.lookup_community(&community_id).await {
            let mut existing_members: Vec<String> =
                existing.members.iter().map(|m| m.key_id.clone()).collect();
            existing_members.sort();
            if existing_members == member_key_ids {
                return (
                    StatusCode::OK,
                    Json(StartChatResponse {
                        community_id: existing.community_key_id,
                        community_name: existing.community_name,
                        member_key_ids: existing_members,
                        cohort_scope: cohort_scope::COMMUNITY,
                        freshly_created: false,
                    }),
                )
                    .into_response();
            }
        }
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "chat.community_create_failed",
            format!("put_community: {e}"),
        );
    }
    (
        StatusCode::OK,
        Json(StartChatResponse {
            community_id: community_id.clone(),
            community_name,
            member_key_ids,
            cohort_scope: cohort_scope::COMMUNITY,
            freshly_created: true,
        }),
    )
        .into_response()
}

// ─── The message row ────────────────────────────────────────────────────────

/// One chat message, projected for the client with its CEG identity intact.
///
/// This is deliberately NOT a bespoke `{from, text, at}` shape. The client
/// renders each message with the SAME hamburger component it uses on every other
/// attestation card, and that component needs the object's CEG identity —
/// `attestation_id` (what Supersede / Withdraw / Recant target),
/// `attesting_key_id` (who may), `cohort_scope` (who can see it), and the folded
/// `status`. A message shape that hid those would be a second, weaker object
/// model for rows that are ordinary attestations.
#[derive(Debug, Serialize)]
struct ChatMessage {
    attestation_id: String,
    attesting_key_id: String,
    attested_key_id: String,
    attestation_type: String,
    subject_key_ids: Vec<String>,
    cohort_scope: String,
    community_id: String,
    /// `live` | `superseded` | `withdrawn` | `recanted` — the SAME vocabulary
    /// `memory_api`'s CEG projection uses, so one hamburger drives both.
    status: &'static str,
    /// The composer row that produced a non-`live` status, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    status_attestation_id: Option<String>,
    body: String,
    content_type: String,
    /// RFC3339. The transcript is ordered by this, ascending.
    asserted_at: String,
    /// **WHO WROTE IT** — read from the envelope's `on_behalf_of_key_id`, never
    /// from `attesting_key_id`. The node attests and signs; the human authors.
    /// A client that read the attester would name the box instead of the person,
    /// on its own messages and the far side's alike.
    author: String,
    /// `true` when this node's owner is the AUTHOR (same source as `author`).
    mine: bool,
}

/// Is this row a chat message in `community_id`?
///
/// TWO shapes, since persist v39.0.0. A message is written as a `scores` row at
/// `self` and then WIDENED into the community by a `supersedes` its author
/// signs, so the row the community can actually read is the widening. The `self`
/// original never appears here at all — it is structurally undiscoverable
/// (CC 5.2) — which is why matching only `scores` returned an empty list.
fn is_message_for(row: &Attestation, community_id: &str) -> bool {
    (row.attestation_type == attestation_type::SCORES
        || (row.attestation_type == attestation_type::SUPERSEDES && attestation_crossing::is_placement_widening(row)))
        && row.cohort_scope == cohort_scope::COMMUNITY
        && row
            .attestation_envelope
            .get(paths::DIMENSION)
            .and_then(|v| v.as_str())
            == Some(CHAT_MESSAGE_DIMENSION)
        // ASK PERSIST WHICH COHORT THE ROW NAMES, do not match a field name.
        // The row this node writes names it `community_id`, but `widen_audience`
        // re-emits the cohort target under the canonical member for the audience
        // — `community_key_id` — so a reader hand-matching the first spelling
        // finds nothing on the very row the community is supposed to read. Both
        // spellings are `COHORT_TARGET_ENVELOPE_FIELDS`; this is persist's own
        // accessor over them.
        && admission::envelope_cohort_target(&row.attestation_envelope)
            .ok()
            .flatten()
            == Some(community_id)
}

/// The `live`/`superseded`/`withdrawn`/`recanted` token for a composer type.
fn status_token(attestation_type_str: &str) -> &'static str {
    match attestation_type_str {
        attestation_type::RECANTS => "recanted",
        attestation_type::WITHDRAWS => "withdrawn",
        attestation_type::SUPERSEDES => "superseded",
        _ => "live",
    }
}

/// Fold the structural composers targeting `message_id` into one status.
///
/// Per CEG §6.1 rule 4 cross-attester chains are evaluated INDEPENDENTLY, so the
/// rows are grouped by attester and `precedence_winner` picks each group's
/// winner; the reported status is the highest-ranked winner across groups.
/// `composer_rank` is persist's — the rank order (recants > withdraws >
/// supersedes) is not restated here.
fn fold_status<'a>(composers: Option<&'a Vec<&'a Attestation>>) -> (&'static str, Option<String>) {
    let Some(composers) = composers else {
        return ("live", None);
    };
    let mut by_attester: HashMap<&str, Vec<&Attestation>> = HashMap::new();
    for c in composers {
        by_attester
            .entry(c.attesting_key_id.as_str())
            .or_default()
            .push(c);
    }
    let mut best: Option<&Attestation> = None;
    for group in by_attester.values() {
        let Some(winner) = precedence::precedence_winner(group) else {
            continue;
        };
        let better = match best {
            None => true,
            Some(b) => {
                precedence::composer_rank(&winner.attestation_type)
                    > precedence::composer_rank(&b.attestation_type)
            }
        };
        if better {
            best = Some(winner);
        }
    }
    match best {
        Some(w) => (
            status_token(&w.attestation_type),
            Some(w.attestation_id.clone()),
        ),
        None => ("live", None),
    }
}

// ─── POST /v1/chat/{community_id}/messages ──────────────────────────────────

#[derive(Debug, Deserialize)]
struct SendMessageRequest {
    body: String,
    #[serde(default)]
    content_type: Option<String>,
}

/// Resolve the caller's substrate-built scope. `build_caller_admission` is the
/// SOLE constructor for a `CallerAdmission` (AV-44) — the admission set is
/// resolved from the directory, never asserted by the caller.
async fn caller_scope(engine: &Engine, identity_key_id: &str) -> Result<CallerScope, String> {
    let admission =
        ciris_persist::scope::build_caller_admission(engine, &identity_key_id.to_owned())
            .await
            .map_err(|e| e.to_string())?;
    Ok(CallerScope::Authenticated { admission })
}

/// The membership question, asked of persist's own §4.3 predicate.
async fn require_member(st: &ChatState, owner: &Owner, community_id: &str) -> Result<(), Response> {
    let directory = st.engine.federation_directory();
    match directory.lookup_community(community_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(refuse(
                StatusCode::NOT_FOUND,
                "chat.unknown_community",
                format!("no community {community_id:?} on this node"),
            ))
        }
        Err(e) => {
            return Err(refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "chat.store_unavailable",
                format!("lookup_community: {e}"),
            ))
        }
    }
    let scope = caller_scope(&st.engine, &owner.key_id).await.map_err(|e| {
        refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "chat.store_unavailable",
            format!("build_caller_admission: {e}"),
        )
    })?;
    if !scope.admits(cohort_scope::COMMUNITY, community_id) {
        // The contextual-integrity line. Owning the node is not membership in
        // the cohort, and the tier means nothing if this arm is skipped.
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "chat.not_a_member",
            format!(
                "{:?} is not an active member of community {community_id:?} — \
                 community-scoped content is cohort-filtered, not owner-readable",
                owner.key_id
            ),
        ));
    }
    Ok(())
}

/// `POST /v1/chat/{community_id}/messages` — send.
///
/// The row: a `scores` attestation on `chat:message:v1`, authored by the OWNER's
/// identity key (the human wrote it, not the box), placed at the `community`
/// tier. `attested_key_id` and `subject_key_ids` name the producer and nobody
/// else — persist's `check_promotion_cohort_standing` refuses any other shape at
/// this tier (see the module docs).
async fn send_message(
    State(st): State<ChatState>,
    headers: HeaderMap,
    Path(community_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let owner = match require_owner(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    // NEVER-DELEGATABLE (see `CapabilityVerb::ChatAuthor`). Checked AHEAD of the
    // membership read because it is a pure function of the session: a delegate
    // must not learn whether a community exists from the shape of its refusal.
    if let Some(resp) = require_verb(
        &owner,
        crate::auth::gate::CapabilityVerb::ChatAuthor,
        "chat.delegate_may_not_author",
    ) {
        return resp;
    }
    // Declared-conformance gate (see start_chat's for the reasoning) — still
    // AHEAD of the membership read: this too is a pure function of the node's
    // own declaration and must not leak community existence.
    if let Some(resp) =
        crate::conformance::require_op(&st.engine, crate::auth::gate::CapabilityVerb::ChatAuthor)
            .await
    {
        return resp;
    }
    if let Err(r) = require_member(&st, &owner, &community_id).await {
        return r;
    }
    let req: SendMessageRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "chat.malformed_body",
                format!("expected {{\"body\": \"…\"}}: {e}"),
            )
        }
    };
    if req.body.trim().is_empty() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "chat.empty_message",
            "a message body must carry at least one non-whitespace character",
        );
    }
    if req.body.len() > MAX_MESSAGE_BYTES {
        return refuse(
            StatusCode::PAYLOAD_TOO_LARGE,
            "chat.message_too_large",
            format!(
                "message body is {} bytes; the ceiling is {MAX_MESSAGE_BYTES}",
                req.body.len()
            ),
        );
    }
    let content_type = req
        .content_type
        .as_deref()
        .map_or(DEFAULT_CONTENT_TYPE, str::trim)
        .to_owned();

    // Envelope KEYS come from persist's exported constants where persist owns
    // them (`paths::DIMENSION`); the three message members are server
    // vocabulary persist types no constant for.
    //
    // No `asserted_at` here (CIRISServer#402 / CIRISPersist#598): the local
    // The OTHER member — the room is a pair, so the peer is the member that is
    // not the owner. Read off the community record rather than re-derived: the
    // roster is what the audience gate serves against, so the peer we address
    // must be the peer the room says it has.
    let contact_key_id = match st
        .engine
        .federation_directory()
        .lookup_community(&community_id)
        .await
    {
        Ok(Some(c)) => {
            match c
                .members
                .iter()
                .map(|m| m.key_id.clone())
                .find(|k| *k != owner.key_id)
            {
                Some(peer) => peer,
                None => {
                    return refuse(
                        StatusCode::CONFLICT,
                        "chat.not_a_pair_room",
                        "this room has no second member — a pair chat addresses exactly one \
                         other person, and `chat_message_attestation` derives the room from \
                         the two fed-IDs",
                    )
                }
            }
        }
        Ok(None) => {
            return refuse(
                StatusCode::NOT_FOUND,
                "chat.unknown_community",
                format!("no community {community_id:?} on this node"),
            )
        }
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "chat.store_unavailable",
                format!("lookup_community: {e}"),
            )
        }
    };
    // Edge's row carries a body and no content type — the community tier is
    // sealed text. Refusing an unsupported type is honest; accepting it and
    // dropping it would tell the client something was stored that was not.
    if content_type != DEFAULT_CONTENT_TYPE {
        return refuse(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "chat.unsupported_content_type",
            format!(
                "the sealed community tier carries text only; got {content_type:?}, want \
                 {DEFAULT_CONTENT_TYPE:?}"
            ),
        );
    }
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);

    // ── THE MESSAGE IS EDGE'S ROW, SEALED, SIGNED BY THE PERSON ─────────────
    //
    // This built a plaintext `scores` row attested by the NODE and pushed it
    // through persist's crossing directly. Three things were wrong with that,
    // and only the wire could tell:
    //
    //   * the body was PLAINTEXT. From edge v20.0.0 the community tier is
    //     encrypted, always — "there is no plaintext producer";
    //   * the row was attested by the node, so the author rode in an envelope
    //     member instead of in the signature, and a reader had to trust the box
    //     about whose words these were;
    //   * it was placed by calling persist, which skips the audience gate edge
    //     applies per recipient — the row existed and was never served.
    //
    // Now: the OWNER signs at write, the body is sealed under the room's record
    // secret, and `share` enters the mesh over those bytes (node co-scrub) and
    // widens to the room with the owner's own `supersedes`.
    let capsule = match crate::owner_signer_capsule::acquire(
        &st.engine,
        bearer,
        &owner.key_id,
        st.user_seed_dir.clone(),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            return refuse(
                StatusCode::FORBIDDEN,
                "chat.author_signer_unavailable",
                format!(
                    "a chat message is signed by the person who wrote it, and this node \
                     cannot wield that identity right now: {e:?}"
                ),
            )
        }
    };
    let author = capsule.edge_signer();

    // The conversation key. `None` is the self-resolving stall: the peer's half
    // of the MLS handshake has not replicated yet. Say so plainly — the mesh
    // converges on its own, and a client that retries in a loop is the wrong
    // answer (edge's `LadderStall` vocabulary, §3 of its integration guide).
    let key = match room_key(&st, &owner.key_id, &contact_key_id, author).await {
        Ok(Some(k)) => k,
        Ok(None) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "chat.room_not_keyed_yet",
                "the room's key exchange has not completed — the other side's handshake \
                 row has not arrived yet. This converges on its own; try again shortly.",
            )
        }
        Err(e) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "chat.room_key_failed",
                format!("derive the room key: {e}"),
            )
        }
    };

    let row = match ciris_edge::chat::chat_message_attestation(
        author,
        &contact_key_id,
        &req.body,
        chrono::Utc::now(),
        &key,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "chat.emit_failed",
                format!("chat_message_attestation: {e}"),
            )
        }
    };
    let attestation_id = match share_in_room(
        &*st.engine.federation_directory(),
        row,
        &community_id,
        ciris_edge::replication::attestation_bind::Signers {
            node: &st.node_signer,
            actor: Some(author),
        },
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "chat.emit_failed",
                format!("share the message with the room: {e}"),
            )
        }
    };
    let message = match load_message(&st, &community_id, &attestation_id, &owner).await {
        Ok(Some(m)) => m,
        Ok(None) | Err(_) => {
            // The row landed; only the read-back projection did not. Say so
            // rather than reporting a failed send.
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "attestation_id": attestation_id,
                    "community_id": community_id,
                    "cohort_scope": cohort_scope::COMMUNITY,
                    "message": serde_json::Value::Null,
                })),
            )
                .into_response();
        }
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "attestation_id": attestation_id,
            "community_id": community_id,
            "cohort_scope": cohort_scope::COMMUNITY,
            "message": message,
        })),
    )
        .into_response()
}

// ─── GET /v1/chat/{community_id}/messages ───────────────────────────────────

/// Collect the community's transcript: every chat row authored by an ACTIVE
/// member, plus the structural composers that revise them.
///
/// Anchored on the ROSTER, not on the caller — a member reads the same
/// transcript regardless of who is asking, which is what makes the membership
/// gate the only thing standing between a non-member and the content.
async fn collect_messages(
    st: &ChatState,
    community_id: &str,
    owner: &Owner,
) -> Result<Vec<ChatMessage>, String> {
    let directory = st.engine.federation_directory();
    let members = directory
        .active_community_members(community_id)
        .await
        .map_err(|e| format!("active_community_members: {e}"))?;
    // ── WHOSE ROWS TO SCAN ──────────────────────────────────────────────────
    //
    // Messages are attested by NODES, not by members (the node signs on its
    // owner's behalf — see `send_message`), so scanning the roster alone finds
    // nothing. The nodes to scan are the ones the members are bound to, and each
    // member's own `delegates_to(member -> node)` owner-binding NAMES them — a
    // federation-tier row that replicates, so the far side's node is resolvable
    // here exactly as ours is.
    //
    // That binding arrives in the SAME scan the roster already needs, so this
    // costs no extra read: walk each member once, keep their chat rows, and
    // collect the node ids their bindings point at.
    let mut rows: Vec<Attestation> = Vec::new();
    let mut node_key_ids: Vec<String> = vec![owner.node_key_id.clone()];
    // (member, binding attestation_id, bound node) — kept so the AUTHOR claim can
    // be validated against the binding's FOLDED status below, not its mere
    // existence: a withdrawn binding must not keep authenticating claims.
    let mut binding_edges: Vec<(String, String, String)> = Vec::new();
    for member in &members {
        let authored = directory
            .list_attestations_by(&member.key_id)
            .await
            .map_err(|e| format!("list_attestations_by({}): {e}", member.key_id))?;
        for row in &authored {
            if row.attestation_type == attestation_type::DELEGATES_TO
                && ciris_persist::federation::admission::is_owner_binding_envelope(
                    &row.attestation_envelope,
                )
            {
                binding_edges.push((
                    member.key_id.clone(),
                    row.attestation_id.clone(),
                    row.attested_key_id.clone(),
                ));
                if !node_key_ids.contains(&row.attested_key_id) {
                    node_key_ids.push(row.attested_key_id.clone());
                }
            }
        }
        // A member's own rows are still scanned: pre-attribution messages, and
        // the signer-explicit ones a future substrate lets them author directly,
        // are attested by the human. Both shapes read back through one path.
        rows.extend(authored);
    }
    for node in &node_key_ids {
        let authored = directory
            .list_attestations_by(node)
            .await
            .map_err(|e| format!("list_attestations_by({node}): {e}"))?;
        rows.extend(authored);
    }
    // One row can arrive twice (a member IS scanned, and so is their node);
    // dedup on the row identity rather than trusting the walk not to overlap.
    rows.sort_by(|a, b| a.attestation_id.cmp(&b.attestation_id));
    rows.dedup_by(|a, b| a.attestation_id == b.attestation_id);
    // Composers first, so a message's status is available when it is projected.
    let mut composers: HashMap<String, Vec<&Attestation>> = HashMap::new();
    for row in &rows {
        if !precedence::is_structural_composer(&row.attestation_type) {
            continue;
        }
        // A widening is a `supersedes` that places the row, not one that ends
        // it. Folding it as a composer would report every message as superseded
        // by its own arrival in the community.
        if attestation_crossing::is_placement_widening(row) {
            continue;
        }
        if let Some(target) =
            precedence::references_attestation_id_from_envelope(&row.attestation_envelope)
        {
            composers.entry(target.to_owned()).or_default().push(row);
        }
    }
    // WHICH HUMAN EACH NODE MAY SPEAK FOR — from the LIVE owner-bindings only.
    // The `on_behalf_of_key_id` member is producer-asserted: any admitted node
    // can sign a valid community row whose envelope claims OUR owner as author,
    // and a projection that trusts the claim renders the forgery as
    // `mine: true`. The claim is honored only when the attesting node's live
    // binding names the claimed member — the same chain the design says a
    // verifier walks, actually walked.
    let mut bound_member_of: HashMap<&str, &str> = HashMap::new();
    for (member, binding_id, node) in &binding_edges {
        if fold_status(composers.get(binding_id)).0 == "live" {
            bound_member_of.insert(node.as_str(), member.as_str());
        }
    }
    let mut out: Vec<ChatMessage> = Vec::new();
    for row in &rows {
        if !is_message_for(row, community_id) {
            continue;
        }
        let (status, status_attestation_id) = fold_status(composers.get(&row.attestation_id));
        // The author: the envelope's claim, VALIDATED against the attesting
        // node's live owner-binding. Three shapes:
        //   * claim matches the binding — the human, as designed;
        //   * NO claim — pre-attribution or signer-explicit row; the attester
        //     is the least-wrong answer available (documented fallback);
        //   * claim does NOT match — a forgery or an unresolvable binding, and
        //     the projection reports the WIRE TRUTH (the attesting node), never
        //     the claim. `mine` derives from author, so a forged claim can no
        //     longer render as the local owner's own words.
        let claimed = row
            .attestation_envelope
            .get(FIELD_ON_BEHALF_OF)
            .and_then(|v| v.as_str());
        let author = match claimed {
            Some(c)
                if bound_member_of.get(row.attesting_key_id.as_str()) == Some(&c)
                    || c == row.attesting_key_id.as_str() =>
            {
                c.to_owned()
            }
            Some(c) => {
                tracing::warn!(
                    attestation_id = %row.attestation_id,
                    attesting_key_id = %row.attesting_key_id,
                    claimed_author = %c,
                    "chat: on_behalf_of claim does not match the attesting node's                      live owner-binding — projecting the attester, not the claim"
                );
                row.attesting_key_id.clone()
            }
            None => row.attesting_key_id.clone(),
        };
        out.push(ChatMessage {
            attestation_id: row.attestation_id.clone(),
            attesting_key_id: row.attesting_key_id.clone(),
            attested_key_id: row.attested_key_id.clone(),
            // THE CLAIM'S TYPE, NOT THE PLACEMENT'S. A chat message is a
            // `scores` claim; since persist v39.0.0 the row the community reads
            // is the `supersedes` that WIDENED it into the community, which is
            // how it got here and not what it is. Reporting `supersedes` would
            // tell every client that every message replaced something, and
            // `is_message_for` above has already established this row is a
            // `chat:message:v1` claim — which is emitted as `scores`, always.
            attestation_type: if attestation_crossing::is_placement_widening(row) {
                attestation_type::SCORES.to_owned()
            } else {
                row.attestation_type.clone()
            },
            subject_key_ids: row.subject_key_ids.clone(),
            cohort_scope: row.cohort_scope.clone(),
            community_id: community_id.to_owned(),
            status,
            status_attestation_id,
            body: row
                .attestation_envelope
                .get(FIELD_BODY)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
            content_type: row
                .attestation_envelope
                .get(FIELD_CONTENT_TYPE)
                .and_then(|v| v.as_str())
                .unwrap_or(DEFAULT_CONTENT_TYPE)
                .to_owned(),
            asserted_at: row.asserted_at.to_rfc3339(),
            author: author.clone(),
            mine: author == owner.key_id,
        });
    }
    // Newest LAST — a transcript reads down the page. `asserted_at` can tie
    // (the substrate truncates to its own resolution), so `attestation_id` is
    // the stable tie-break; without it two messages sent in the same instant
    // would swap places between reads.
    out.sort_by(|a, b| {
        a.asserted_at
            .cmp(&b.asserted_at)
            .then_with(|| a.attestation_id.cmp(&b.attestation_id))
    });
    Ok(out)
}

/// Read one message back after a send (the response body's `message`).
async fn load_message(
    st: &ChatState,
    community_id: &str,
    attestation_id: &str,
    owner: &Owner,
) -> Result<Option<ChatMessage>, String> {
    Ok(collect_messages(st, community_id, owner)
        .await?
        .into_iter()
        .find(|m| m.attestation_id == attestation_id))
}

/// `GET /v1/chat/{community_id}/messages` → `{ "community_id", "messages": […],
/// "total" }`, oldest first.
async fn list_messages(
    State(st): State<ChatState>,
    headers: HeaderMap,
    Path(community_id): Path<String>,
) -> Response {
    let owner = match require_owner(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    if let Some(resp) = require_verb(
        &owner,
        crate::auth::gate::CapabilityVerb::ChatRead,
        "chat.delegation_denied",
    ) {
        return resp;
    }
    if let Err(r) = require_member(&st, &owner, &community_id).await {
        return r;
    }
    match collect_messages(&st, &community_id, &owner).await {
        Ok(messages) => {
            let total = messages.len();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "community_id": community_id,
                    "cohort_scope": cohort_scope::COMMUNITY,
                    "messages": messages,
                    "total": total,
                })),
            )
                .into_response()
        }
        Err(e) => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "chat.store_unavailable",
            format!("read transcript: {e}"),
        ),
    }
}

// ─── Router ─────────────────────────────────────────────────────────────────

/// The contacts + chat router. Takes no key id: the node's own federation
/// key_id and the responsible party's are BOTH resolved from the engine at
/// request time (CIRISServer#372 Level 2 — with no parameter there is no second
/// value to mismatch).
///
/// `node_signer` is the one thing that cannot be resolved from the engine: edge
/// signs with its OWN `LocalSigner` type, and the Engine holds persist's. It is
/// the same sealed federation key either way — built once at boot, from the same
/// classical and ML-DSA-65 halves the edge transport signer wraps.
pub fn router(
    engine: Arc<Engine>,
    node_signer: Arc<ciris_edge::identity::LocalSigner>,
    user_seed_dir: std::path::PathBuf,
) -> Router {
    let state = ChatState {
        engine,
        user_seed_dir,
        rooms: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        node_signer,
    };
    Router::new()
        .route(
            "/v1/contacts",
            axum::routing::get(list_contacts).post(add_contact),
        )
        .route("/v1/chat", axum::routing::post(start_chat))
        .route(
            "/v1/chat/{community_id}/messages",
            axum::routing::get(list_messages).post(send_message),
        )
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derived id is order-free — the two ends dial the same room without
    /// agreeing on who initiated.
    #[test]
    fn pair_id_is_order_free() {
        assert_eq!(
            pair_community_key_id("alice", "bob"),
            pair_community_key_id("bob", "alice")
        );
    }

    /// The separator is load bearing: without it `("ab","c")` and `("a","bc")`
    /// hash the same bytes and two unrelated pairs share one room.
    #[test]
    fn pair_id_does_not_collide_across_split_points() {
        assert_ne!(
            pair_community_key_id("ab", "c"),
            pair_community_key_id("a", "bc")
        );
    }

    #[test]
    fn pair_id_carries_its_prefix() {
        let id = pair_community_key_id("a", "b");
        assert!(id.starts_with(PAIR_COMMUNITY_PREFIX), "{id}");
        assert_eq!(id.len(), PAIR_COMMUNITY_PREFIX.len() + 64);
    }

    // The room's NAME is edge's now — `chat::pair_community` formats it from
    // the same sorted pair, and it rides inside `Community::signing_envelope`,
    // so the property this used to assert is pinned where the string is built
    // rather than beside a copy of it.
}
