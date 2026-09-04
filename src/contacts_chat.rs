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
    .map_err(|e| {
        tracing::error!(
            attestation_id = %row.attestation_id,
            attester = %row.attesting_key_id,
            cohort_scope = %row.cohort_scope,
            error = %e,
            "chat: the LOCAL put refused the row, so nothing was placed. The local \
             door verifies the row's hybrid signature against the ATTESTER's \
             registered pubkeys — so the usual cause is an attester whose key is \
             not in `federation_keys`, or one registered with different pubkeys \
             than the signer that just signed. Check `get_public_key(attester)` \
             and that the author's fed-ID was minted with the seed this node holds"
        );
        format!("put {}: {e}", row.attestation_id)
    })?;
    let crossing = share(
        dir,
        &row,
        With::Community {
            community_key_id: room.to_owned(),
        },
        CrossingBasis::ProducerAuthority,
        signers,
    )
    .await
    .map_err(|e| {
        tracing::error!(
            attestation_id = %row.attestation_id,
            attester = %row.attesting_key_id,
            room = %room,
            error = %e,
            "chat: the row was stored but NOT placed in the room. `share` runs \
             `enter_mesh` (tier crossing over the same bytes) then \
             `widen_audience` (a `supersedes` the ACTOR signs at the room's \
             scope). `CustodyIsNotTheActor` means the actor's \
             `derived_key_id()` does not equal the row's `attesting_key_id` — \
             see `identity::hardware_user_crossing_signer`, since a signer built \
             for `attest::emit` carries the already-derived id and derives twice \
             here. `check_promotion_cohort_standing` means the community \
             placement names a party other than its producer"
        );
        e
    })?;
    match crossing.shared {
        // The PLACED row's id — the widening, which is what the room reads.
        Shared::Placed { attestation_id } | Shared::AlreadyThere { attestation_id } => {
            Ok(attestation_id)
        }
        Shared::AwaitingActor {
            attestation_id,
            age_ms,
        } => {
            tracing::warn!(
                attestation_id = %attestation_id,
                attester = %row.attesting_key_id,
                room = %room,
                age_ms,
                "chat: the row is WAITING for its author's signature and has not \
                 been placed — an `Ok` that did nothing. `custody_for` will sign \
                 as the node only for a row this node attested; for anyone \
                 else's row it needs that key's own signer. Nothing more happens \
                 on its own: either the author signs it, or it sits. If this is \
                 a row this node SHOULD be able to place, the actor passed to \
                 `share` was `None` or was keyed the wrong way"
            );
            Err(format!(
                "the row {attestation_id} waits for its author's signer ({age_ms} ms) — \
             a chat row is signed by the person, and this node does not hold that key"
            ))
        }
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
/// ── WHAT AN ENTRY IS, ON TWO AXES ───────────────────────────────────────────
///
/// Chat rooms and agent conversations are ONE client surface, so they are one
/// schema. The temptation is a single flat `role` — `self | other_human |
/// my_agent | other_agent | system | error` — and it does not survive contact
/// with a channel that has more than two people in it, because it fuses two
/// independent questions:
///
///   * **What kind of entry is this?** Someone spoke, or the room narrated, or
///     something failed. Viewer-independent — the same for every member.
///   * **Who wrote it, and what are they to ME?** Viewer-DEPENDENT: the same row
///     is "my agent" to its owner and "someone's agent" to everyone else, and
///     these rows are CEG objects replicated verbatim to every member.
///
/// Fusing them means `other_human` collapses fifty distinct people into one
/// label — the client still needs the author key to draw a name — and it gives
/// two names to one row depending on who is looking, in a transcript that is
/// byte-identical for all of them.
///
/// This is the split Matrix makes (`sender` + event `type`/`msgtype`, with "is it
/// me" computed client-side) and the one the `system|user|assistant` role triple
/// does not — that triple is fine for one person talking to one model and has no
/// way to say WHICH user or WHICH agent, which is exactly what a channel needs.
///
/// So: [`EntryKind`] answers the first, `author` + `author_kind` the second, and
/// `relation` is the derived viewer-relative convenience, marked as such.
///
/// | asked for | this schema |
/// |---|---|
/// | self | `kind=message`, `relation=self` |
/// | other human | `kind=message`, `author_kind=person`, `relation=other` |
/// | my agent | `kind=message`, `author_kind=agent`, `relation=own_agent` |
/// | other agent | `kind=message`, `author_kind=agent`, `relation=other` |
/// | system | `kind=system` + a `message_id` naming WHICH note |
/// | error | `kind=error` + a `message_id` naming WHICH failure |
///
/// The last two carry a `message_id` rather than being bare categories, because
/// "system" is not a thing a user can read — "Request to join chat sent" is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A participant said something.
    Message,
    /// The room narrating itself: handshake progress, membership changes.
    System,
    /// A failure the user has to see, in the place it happened.
    Error,
}

impl EntryKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::System => "system",
            Self::Error => "error",
        }
    }
}

/// What the AUTHOR is — edge's vocabulary, not a second one of ours.
/// `person` consents, `agent` is owned by a person and cannot consent for them,
/// `node` is the box. `unknown` is honest: resolution genuinely stalls while a
/// key body is in flight, and guessing "person" there would put a stranger's
/// name on an agent's words.
fn author_kind_str(kind: &ciris_edge::contact::IdentityKind) -> &'static str {
    use ciris_edge::contact::IdentityKind;
    match kind {
        IdentityKind::Person => "person",
        IdentityKind::Agent => "agent",
        IdentityKind::Node => "node",
        IdentityKind::Other(_) => "other",
    }
}

/// The moderation duties `who` holds in `community_id`, memoised per transcript.
///
/// Three calls to persist's CC 4.5.4 predicate, one per duty scope. Memoised
/// because a busy channel has few authors and many messages, and the predicate
/// walks a delegation chain each time.
///
/// A read error is NOT a duty. `is_named_moderator` is already fail-closed on
/// anything it cannot establish; a transport-level failure here is treated the
/// same way, because the alternative — showing a moderator badge on a directory
/// error — puts authority on screen that nothing verified.
async fn duties_of(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    cache: &mut HashMap<String, Vec<&'static str>>,
    who: &str,
    community_id: &str,
) -> Vec<&'static str> {
    use ciris_persist::federation::admission;
    if let Some(hit) = cache.get(who) {
        return hit.clone();
    }
    let mut held: Vec<&'static str> = Vec::new();
    for duty in [
        admission::DELEGATION_SCOPE_MODERATE,
        admission::DELEGATION_SCOPE_TAKEDOWN,
        admission::DELEGATION_SCOPE_REVIEW,
    ] {
        if admission::is_named_moderator(directory, who, community_id, duty)
            .await
            .unwrap_or(false)
        {
            held.push(duty);
        }
    }
    cache.insert(who.to_owned(), held.clone());
    held
}

/// `(author_kind, relation)` for one author, memoised per transcript.
///
/// Both come from ONE `contact::resolve`: `resolved_from` says what the author
/// is, `fed_id` says whose it is. We do not walk ownership ourselves — that walk
/// has an asymmetric ambiguous-node rule that exists for security reasons, and a
/// second copy of it is a second answer.
async fn author_facts(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    cache: &mut HashMap<String, (&'static str, &'static str)>,
    author: &str,
    owner_key_id: &str,
) -> (&'static str, &'static str) {
    if let Some(hit) = cache.get(author) {
        return *hit;
    }
    let lens = ciris_edge::contact::PersistLens::new(directory);
    let facts = match ciris_edge::contact::resolve(&lens, author).await {
        Ok(subject) => {
            let relation = if author == owner_key_id {
                "self"
            } else if subject.fed_id == owner_key_id {
                // An agent or node this node's owner owns — their words, but not
                // them. A channel draws this differently from both.
                "own_agent"
            } else {
                "other"
            };
            (author_kind_str(&subject.resolved_from), relation)
        }
        // NOT an error: the directory has not converged on this key yet. Saying
        // `unknown` is better than defaulting to `person`, which would put a
        // human's framing on an agent's message.
        Err(_) => (
            "unknown",
            if author == owner_key_id {
                "self"
            } else {
                "other"
            },
        ),
    };
    cache.insert(author.to_owned(), facts);
    facts
}

/// A transcript that cannot be read YET — 200, with the reason in the history.
///
/// The shape is the ordinary transcript shape plus a `handshake` object, so a
/// client renders it the same way it renders messages: the note goes in the
/// conversation, in order, where "Request to join chat sent" belongs. No new
/// screen, no error dialog, and nothing for the client to invent.
///
/// `message_id` is what a localized client looks up; `message` is the English it
/// renders until the bundle carries that id (CIRISClient#36). Both are here on
/// purpose — a client that only had the id would show a blank line for exactly
/// the users least able to guess what happened.
fn transcript_pending(community_id: &str, state: RoomHandshake) -> axum::response::Response {
    let (message_id, note) = state.note();
    // A SYSTEM ENTRY IN THE TRANSCRIPT, not a sibling object. Chat rooms and
    // agent conversations are one client surface, so the note arrives the same
    // way a message does and renders in the history in order — "Request to join
    // chat sent" sits where it happened. A parallel `handshake` field would have
    // made every client build a second rendering path for the same sentence.
    let entry = ChatMessage {
        // Synthetic, and deliberately not an attestation id: no row was signed.
        // A client keys off this for dedup; it must not look like something the
        // room could supersede or withdraw.
        attestation_id: format!("system:{message_id}"),
        attestation_type: attestation_type::SCORES.to_string(),
        attesting_key_id: String::new(),
        attested_key_id: String::new(),
        subject_key_ids: Vec::new(),
        cohort_scope: cohort_scope::COMMUNITY.to_string(),
        community_id: community_id.to_string(),
        status: "live",
        status_attestation_id: None,
        body: Some(note.to_string()),
        unopened_reason: None,
        content_type: DEFAULT_CONTENT_TYPE,
        asserted_at: chrono::Utc::now().to_rfc3339(),
        author: String::new(),
        mine: false,
        kind: EntryKind::System.as_str(),
        author_kind: "none",
        relation: "none",
        author_role: None,
        author_duties: Vec::new(),
        message_id: Some(message_id),
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "community_id": community_id,
            "cohort_scope": cohort_scope::COMMUNITY,
            "messages": vec![entry],
            // `total` counts what people SAID. A system note is the room talking
            // about itself, and counting it would make an unstarted conversation
            // report one message.
            "total": 0,
            "ready": state.is_ready(),
            // The client's cue to WAIT rather than offer a retry button: both
            // waiting states resolve when the peer's row replicates, and a human
            // pressing retry changes nothing about that.
            "converges_on_its_own": state.converges_on_its_own(),
        })),
    )
        .into_response()
}

/// ── THE ROOM'S HANDSHAKE, AS ONE TABLE ──────────────────────────────────────
///
/// A pair room is end-to-end encrypted, so nobody can speak into it until BOTH
/// halves of the MLS handshake exist: the joiner publishes a KeyPackage, the
/// creator answers with a Welcome. Both are ordinary `chat:` rows that have to
/// REPLICATE, so the room spends real time — sometimes minutes — in a state that
/// is neither broken nor ready.
///
/// That state used to reach the user as `503 chat.room_not_keyed_yet`, one
/// sentence for every case, on a surface with no way to say "waiting for Bob".
/// It is a conversation, and a conversation can say what it is doing.
///
/// | state | what is true | who acts next | the user sees |
/// |---|---|---|---|
/// | [`Ready`](RoomHandshake::Ready) | both halves landed; the group key exists | nobody | nothing — messages just work |
/// | [`AwaitingPeer`](RoomHandshake::AwaitingPeer) | we CREATED the room; the peer has never opened it | the peer | "Waiting for them to join this chat" |
/// | [`JoinRequested`](RoomHandshake::JoinRequested) | we are the joiner; our KeyPackage is published | the peer's node | "Request to join chat sent" |
/// | [`NoAuthorSigner`](RoomHandshake::NoAuthorSigner) | no fed-ID in hand to sign the handshake | the caller | "This device can't act as you yet" |
///
/// The roles are not negotiated: `PairRole::of` gives the lexicographically
/// smaller fed-ID the creator's role, so which of the two middle states a node is
/// in is a pure function of the two ids.
///
/// ONE TABLE, THREE CONSUMERS — the log line, the refusal, and the transcript's
/// system note all read [`RoomHandshake::note`]. They said three different things
/// before, and only the log said anything useful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomHandshake {
    /// Keyed. Messages send and open.
    Ready,
    /// We are the CREATOR and the joiner's KeyPackage has not arrived.
    AwaitingPeer,
    /// We are the JOINER; our KeyPackage is out and the Welcome has not returned.
    JoinRequested,
    /// No signer to author our half with — a delegate reading, or an owner whose
    /// fed-ID this node cannot open.
    NoAuthorSigner,
}

impl RoomHandshake {
    /// `(reason_id, English)`. The id is what a client localizes; the English is
    /// what it renders until the bundle carries that id (CIRISClient#36).
    ///
    /// These are CHAT-HISTORY notes, not errors: they belong in the transcript
    /// beside the messages, in the same voice, because from the user's side
    /// "waiting for them to join" IS the state of the conversation.
    #[must_use]
    pub fn note(self) -> (&'static str, &'static str) {
        match self {
            Self::Ready => ("chat.state.ready", "End-to-end encrypted."),
            Self::AwaitingPeer => (
                "chat.state.awaiting_peer",
                "Waiting for them to join this chat. They will see your invitation \
                 when their device next syncs, and your messages will send once they do.",
            ),
            Self::JoinRequested => (
                "chat.state.join_requested",
                "Request to join chat sent. Waiting for them to let you in — this \
                 completes on its own once their device answers.",
            ),
            Self::NoAuthorSigner => (
                "chat.state.no_author_signer",
                "This device cannot act as you yet, so it cannot join the chat's key \
                 exchange. Create or unlock your federation ID to continue.",
            ),
        }
    }

    /// Is the room usable?
    #[must_use]
    pub fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Does this resolve WITHOUT anyone doing anything? Both waiting states do —
    /// which is why they are notes and not errors, and why a client that retries
    /// in a loop is the wrong answer.
    #[must_use]
    pub fn converges_on_its_own(self) -> bool {
        matches!(self, Self::AwaitingPeer | Self::JoinRequested)
    }
}

async fn room_key(
    st: &ChatState,
    me: &str,
    peer: &str,
    author: Option<&ciris_edge::identity::LocalSigner>,
) -> Result<(Option<ciris_edge::chat::RoomKey>, RoomHandshake), String> {
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
        return RoomKey::of(group)
            .await
            .map(|k| (Some(k), RoomHandshake::Ready));
    }
    // ADVANCING the handshake needs the person's signer; READING a room whose
    // handshake already finished does not. A delegate granted `chat_read` holds
    // no fed-ID and never will — requiring one to read would revoke a permission
    // the owner deliberately granted, on a technicality of key derivation.
    let Some(author) = author else {
        tracing::debug!(
            room = %room,
            me = %me,
            peer = %peer,
            "chat: no author signer in hand, so the room cannot be keyed on this \
             call. This is the READ path for a delegate with no fed-ID of its \
             own — expected, and it means the delegate can only read a room some \
             earlier call already keyed. If the OWNER sees this, their fed-ID \
             could not be opened: check the seed dir, the `.backend` marker and \
             the `active_user_alias` pointer"
        );
        return Ok((None, RoomHandshake::NoAuthorSigner));
    };

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
                // the joiner has not published theirs yet
                tracing::info!(
                    room = %room,
                    creator = %me,
                    joiner = %peer,
                    "chat: room not keyed — WE ARE THE CREATOR and the joiner's \
                     KeyPackage has not arrived. The joiner publishes it on their \
                     first `POST /v1/chat` or send, and it must then REPLICATE to \
                     this node: it is a `chat:` row at the room's community scope, \
                     so it rides the same consent grant as a message. If it never \
                     arrives, look at the joiner's withholds for this room before \
                     looking here — nothing on this node can complete the \
                     handshake alone"
                );
                return Ok((None, RoomHandshake::AwaitingPeer));
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
            Ok((Some(key), RoomHandshake::Ready))
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
                // the creator has not answered yet
                tracing::info!(
                    room = %room,
                    joiner = %me,
                    creator = %peer,
                    "chat: room not keyed — WE ARE THE JOINER, our KeyPackage is \
                     published, and the creator's Welcome has not arrived. The \
                     creator answers when it next reads the room, so this \
                     converges on its own IF our KeyPackage reached them. Check \
                     that first: it is a `chat:` row at the room's community \
                     scope and rides the consent grant. `PairRole::of` gives the \
                     lexicographically smaller fed-ID the creator's role, so the \
                     roles are fixed by the two ids and never negotiated"
                );
                rooms.insert(room, RoomState::AwaitingWelcome(material));
                return Ok((None, RoomHandshake::JoinRequested));
            };
            let group = CohortGroup::join(store, &room, material, &welcome, 16)
                .await
                .map_err(|e| format!("CohortGroup::join: {e}"))?;
            let key = RoomKey::of(&group).await?;
            rooms.insert(room, RoomState::Keyed(Arc::new(group)));
            Ok((Some(key), RoomHandshake::Ready))
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
    // PERSON. EDGE RESOLVES THAT, we do not: `contact::resolve` takes any
    // identifier (fedID, nodeID, agentID) and lands on the same `Subject`, so a
    // node-subject grant and a person-subject grant fold to one contact without
    // this module knowing which it held.
    //
    // This walked persist's `owner_of` itself. Never again: the reverse and
    // forward owner walks handle an ambiguous node ASYMMETRICALLY on purpose
    // (the reverse walk skips it, so one poisoned node cannot make its owner's
    // every grant unroutable; the forward walk fails closed when asked about
    // that node directly), and both directions are security-relevant. Two
    // spellings of "who owns this key" are two answers that can disagree, in
    // precisely the place where disagreement is an impersonation.
    let directory = st.engine.federation_directory();
    let lens = ciris_edge::contact::PersistLens::new(&*directory);
    let mut peer_ids: Vec<String> = Vec::new();
    for (subject, prefixes) in grants {
        if !prefixes.iter().any(|p| p == CHAT_ATTESTATION_PREFIX) {
            continue;
        }
        let person = match ciris_edge::contact::resolve(&lens, &subject).await {
            Ok(resolved) => resolved.fed_id,
            // A STALL IS NOT AN ERROR, and a live grant must not vanish from the
            // list because the directory has not converged on its subject yet.
            // `NotYetDiscovered` fixes itself — edge queues the key fetch — so
            // the grant is reported under the id it names until it does.
            Err(stall) => {
                tracing::info!(
                    subject = %subject,
                    stall = ?stall,
                    "contacts: a chat-covering grant's subject does not resolve to a \
                     person yet, so it is listed under the key the grant names. This \
                     is the directory not having converged, not a broken grant — it \
                     resolves itself once the subject's key body arrives"
                );
                subject
            }
        };
        if !peer_ids.contains(&person) {
            peer_ids.push(person);
        }
    }
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
    // The default already carries `chat:` — it IS edge's `DEFAULT_CONSENT_PREFIXES`
    // now — so the explicit push this used to do was covering for a divergence
    // that no longer exists. Re-adding it would be the restated list again, one
    // element at a time.
    let prefixes = crate::peer::default_attestation_prefixes();
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
    /// `None` when the row could not be opened — see `unopened_reason`. A
    /// message that cannot be read is NOT the same as one that says nothing, and
    /// collapsing them onto `""` would render a locked row as an empty bubble.
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    /// Why the body did not open, from edge (`Body::Unopened`): a row sealed at
    /// an epoch this member no longer holds, a ciphertext lifted from another
    /// room, or a row carrying no seal at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    unopened_reason: Option<String>,
    /// Always [`DEFAULT_CONTENT_TYPE`]. Edge's `ChatMessage` does not model a
    /// content type because the sealed community tier carries text and nothing
    /// else — `chat_message_attestation` takes a `&str` body — and `send_message`
    /// refuses anything else outright. It is still reported, because dropping a
    /// field every existing client reads would be an API break to say something
    /// the API already guarantees.
    content_type: &'static str,
    /// RFC3339. The transcript is ordered by this, ascending.
    asserted_at: String,
    /// **WHO WROTE IT**, from `ChatMessage::author_key_id` — edge's own answer.
    ///
    /// In v20.0.0 that field could not be trusted: it read the envelope's
    /// `on_behalf_of_key_id` and fell back to the attester only when the member
    /// was absent, so a member of the room — who signs its own envelope — could
    /// name ANY key there, including this node's owner, and the row rendered as
    /// the owner's own words with `mine: true`. Edge sealed the body to
    /// `attesting_key_id` while attributing the text to the claim, so the two
    /// disagreed by construction. This projected `attesting_key_id` directly to
    /// stay out of the way of it (CIRISEdge#564).
    ///
    /// v20.1.0 closed it at the source: `from_row` no longer reads authorship
    /// out of any envelope member, the raw value is surfaced as
    /// `on_behalf_of_claim` — plainly a claim — and ONLY `messages_in_room`
    /// promotes it, after `owner_of(attester)` proves a live owner binding backs
    /// it. So the field is the attester unless a node is legitimately speaking
    /// for its own owner, and reading it is once again the right thing.
    ///
    /// We do not call `messages_in_room` itself: it drops every row referenced
    /// by another, which is right for a plain transcript but would silently
    /// DELETE a withdrawn message instead of rendering it as `withdrawn`, and
    /// this surface reports a status with the same vocabulary `memory_api`'s CEG
    /// projection uses. The promotion that helper performs is therefore not
    /// applied here — a node-attested row is attributed to the node.
    author: String,
    /// `true` when this node's owner is the AUTHOR (same source as `author`).
    ///
    /// Kept, and it is exactly `relation == "self"`. Viewer-DEPENDENT, like
    /// `relation`: the row it describes is replicated byte-identically to every
    /// member, and this field is this node's reading of it.
    mine: bool,
    /// `message` | `system` | `error` — see [`EntryKind`]. Viewer-independent.
    kind: &'static str,
    /// What the author IS: `person` | `agent` | `node` | `other` | `unknown`.
    /// Viewer-independent, and the field a channel needs in order to draw an
    /// agent differently from the human who owns it.
    author_kind: &'static str,
    /// The author's relationship to THIS node's owner: `self` | `own_agent` |
    /// `other` | `none`. Viewer-DEPENDENT and derived — a convenience so a client
    /// need not walk ownership itself, never a property of the row.
    relation: &'static str,
    /// The author's role ON THE ROSTER, verbatim: `founder` | `member` |
    /// operator-defined. Viewer-independent, and **not** the moderation signal —
    /// see `author_duties`. Passed through rather than interpreted, because
    /// persist documents the vocabulary as open.
    #[serde(skip_serializing_if = "Option::is_none")]
    author_role: Option<String>,
    /// **The moderation signal**: which duties this author actually holds in
    /// THIS community — any of `moderate` / `takedown` / `review`.
    ///
    /// Moderation is a delegable DUTY, not a role (CC §4.5.x; `FSD/
    /// MODERATION_CHILD_SAFETY.md` says so in its first line). A founder or
    /// steward appoints a moderator by authoring a scoped `delegates_to`, and
    /// §11.11 merit auto-promotion emits that same shape — so a member with no
    /// special roster role can hold real moderation authority, and reading
    /// `author_role == "founder"` would show them as an ordinary member while
    /// they moderate.
    ///
    /// Answered by persist's `admission::is_named_moderator`, which is the CC
    /// 4.5.4 predicate: a live scope-bearing chain from a STEWARD-BOUND member of
    /// the community's authority set, with ⊆-attenuation, `sub_delegation`-gated
    /// deputization, depth ≤ 5, and no `withdraws`-revoked edge — fail-closed on
    /// anything it cannot establish. Not a walk this module could reproduce, and
    /// not one it should: `src/safety/named.rs` composes the same predicate, and
    /// two answers to "may they moderate" is the disagreement that matters.
    ///
    /// A founder is admitted zero-hop, so a pair room's two members both come
    /// back with the full set.
    author_duties: Vec<&'static str>,
    /// For `system` and `error` entries: the localization key naming WHICH note
    /// this is. A client looks it up; `body` carries the English fallback so a
    /// bundle that has not caught up yet renders a sentence rather than a blank.
    #[serde(skip_serializing_if = "Option::is_none")]
    message_id: Option<&'static str>,
}

/// ONE id, ONE sentence. Two sites refuse with `chat.not_a_pair_room`, and they
/// had drifted into two different English texts — which means at least one
/// endpoint renders a sentence it does not say in every language that bundle
/// covers. `tools/check_server_localization.py`'s `server-id-single-valued`
/// check is what caught it; a shared const is what stops it recurring, since a
/// second copy cannot drift from a name.
const NOT_A_PAIR_ROOM: &str =
    "this room has no second member — a pair chat addresses exactly one other person";

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
                        NOT_A_PAIR_ROOM,
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
    let key = match room_key(&st, &owner.key_id, &contact_key_id, Some(author)).await {
        Ok((Some(k), _)) => k,
        Ok((None, state)) => {
            // THE STATE, NOT A GENERIC STALL. Same table the transcript renders,
            // so the note the sender sees here is the note already sitting in
            // their chat history — one sentence, not two descriptions of one
            // situation that a client would have to reconcile.
            let (reason_id, note) = state.note();
            tracing::info!(
                room = %pair_community_key_id(&owner.key_id, &contact_key_id),
                state = ?state,
                converges_on_its_own = state.converges_on_its_own(),
                "chat: send refused — the room's handshake is not complete"
            );
            return refuse(StatusCode::SERVICE_UNAVAILABLE, reason_id, note);
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
    let message = match load_message(&st, &community_id, &attestation_id, &owner, &key).await {
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
    key: &ciris_edge::chat::RoomKey,
) -> Result<Vec<ChatMessage>, String> {
    let directory = st.engine.federation_directory();
    let members = directory
        .active_community_members(community_id)
        .await
        .map_err(|e| format!("active_community_members: {e}"))?;

    // ── THE BODY IS OPENED BY EDGE, NOT READ BY US ──────────────────────────
    //
    // This walked the rows itself and copied `body` straight into the response.
    // That was correct while the tier was plaintext and became a live defect the
    // moment `send_message` started sealing: from edge v20.0.0 `FIELD_BODY` is
    // base64 XChaCha20-Poly1305 ciphertext, so every transcript this route
    // served was unreadable — and served without the `sealed` header a client
    // would need to even try. `ChatMessage::from_row` is edge's opener; it
    // reads the seal, derives the per-row key from the room secret, and returns
    // `Body::Unopened { reason }` rather than guessing when it cannot.
    //
    // THREE THINGS WENT WITH IT, all dead rather than merely duplicated:
    //
    //  * the `node_key_ids` scan. Rows are attested by the HUMAN now
    //    (`chat_message_attestation(author, ..)`), so walking the node's own
    //    attestations found nothing a member walk did not.
    //  * the `binding_edges` / `bound_member_of` owner-binding walk — ~50 lines
    //    that existed to check a producer-asserted `on_behalf_of_key_id` against
    //    a live binding. Edge documents that member as "Pre-v39 attribution
    //    member. Read, never written", and `chat_message_attestation` does not
    //    emit it, so the check always fell through to the attester. The author
    //    is the ATTESTER now, verified by the signature rather than by us
    //    re-deriving trust in a claim.
    //  * `is_message_for`. `from_row` answers the same question — right room,
    //    right dimension — against edge's own vocabulary.
    let mut rows: Vec<Attestation> = Vec::new();
    for member in &members {
        let mut by = directory
            .list_attestations_by(&member.key_id)
            .await
            .map_err(|e| format!("list_attestations_by({}): {e}", member.key_id))?;
        rows.append(&mut by);
    }
    rows.sort_by(|a, b| a.attestation_id.cmp(&b.attestation_id));
    rows.dedup_by(|a, b| a.attestation_id == b.attestation_id);

    // Composers first, so a message's status is available when it is projected.
    // A placement widening is NOT a status change — see `is_placement_widening`.
    let mut composers: HashMap<String, Vec<&Attestation>> = HashMap::new();
    for row in &rows {
        if !precedence::is_structural_composer(&row.attestation_type)
            || attestation_crossing::is_placement_widening(row)
        {
            continue;
        }
        if let Some(target) =
            precedence::references_attestation_id_from_envelope(&row.attestation_envelope)
        {
            composers.entry(target.to_owned()).or_default().push(row);
        }
    }

    let mut out: Vec<ChatMessage> = Vec::new();
    let mut who_cache: HashMap<String, (&'static str, &'static str)> = HashMap::new();
    // The roster's roles, from the membership rows already read above. No extra
    // query: this is the same list the transcript is anchored on.
    let mut duty_cache: HashMap<String, Vec<&'static str>> = HashMap::new();
    let roles: HashMap<&str, Option<String>> = members
        .iter()
        .map(|m| (m.key_id.as_str(), m.role.clone()))
        .collect();
    // Counters, so an empty transcript says WHICH step emptied it. Every one of
    // these has been the answer at least once: no members (roster never
    // replicated), rows but none at community scope (the widening never ran),
    // rows in the room that would not open (sealed at an epoch this member does
    // not hold).
    let mut not_community = 0usize;
    let mut not_this_room = 0usize;
    for row in &rows {
        // THE PLACED ROW ONLY. A message the owner sent exists twice on their own
        // node — the `self` original they signed, and the `community` widening
        // that carries it to the room — and `from_row` opens either, because both
        // name the room. The far side only ever receives the widening, so showing
        // both here would render every one of your own messages twice, and only
        // to you. The room's transcript is what the room can see.
        if row.cohort_scope != cohort_scope::COMMUNITY {
            not_community += 1;
            continue;
        }
        // Edge decides whether this row belongs to the room AND opens it.
        let Some(opened) = ciris_edge::chat::ChatMessage::from_row(row, community_id, key) else {
            not_this_room += 1;
            continue;
        };
        let who = author_facts(
            &*directory,
            &mut who_cache,
            &opened.author_key_id,
            &owner.key_id,
        )
        .await;
        let (status, status_attestation_id) = fold_status(composers.get(&row.attestation_id));
        let (body, unopened_reason) = match opened.body {
            ciris_edge::chat::Body::Text(text) => (Some(text), None),
            ciris_edge::chat::Body::Unopened { reason } => (None, Some(reason)),
        };
        out.push(ChatMessage {
            attestation_id: row.attestation_id.clone(),
            attesting_key_id: row.attesting_key_id.clone(),
            attested_key_id: row.attested_key_id.clone(),
            // THE CLAIM'S TYPE, NOT THE PLACEMENT'S — a widening is how the row
            // reached the room, not what it is.
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
            body,
            unopened_reason,
            content_type: DEFAULT_CONTENT_TYPE,
            asserted_at: opened.asserted_at.to_rfc3339(),
            // WHOSE WORDS — edge's, off the row's own attester. It is no longer
            // a claim this projection has to weigh: the person signed the row.
            // EDGE DECIDES, and from v20.1.0 it decides correctly.
            mine: opened.author_key_id == owner.key_id,
            kind: EntryKind::Message.as_str(),
            // ONE resolve per distinct author, cached for this transcript. Edge
            // answers both halves at once: `resolved_from` is what the author IS,
            // and `fed_id` is the person behind it — so an agent's message is
            // attributed to the agent AND placed relative to its owner without a
            // second walk. A stall leaves it `unknown`, which is the truth.
            author_kind: who.0,
            relation: who.1,
            author_role: roles.get(opened.author_key_id.as_str()).cloned().flatten(),
            author_duties: duties_of(
                &*directory,
                &mut duty_cache,
                &opened.author_key_id,
                community_id,
            )
            .await,
            message_id: None,
            author: opened.author_key_id,
        });
    }
    out.sort_by(|a, b| {
        a.asserted_at
            .cmp(&b.asserted_at)
            .then_with(|| a.attestation_id.cmp(&b.attestation_id))
    });

    // ONE LINE THAT EXPLAINS AN EMPTY TRANSCRIPT. Every count here has been the
    // answer to "why is the room blank" at least once, and each points somewhere
    // different — which is the whole reason they are counted separately rather
    // than summed.
    let unopened = out.iter().filter(|m| m.body.is_none()).count();
    if out.is_empty() || unopened > 0 {
        tracing::warn!(
            room = %community_id,
            members = members.len(),
            rows_by_members = rows.len(),
            skipped_not_community_scope = not_community,
            skipped_other_room = not_this_room,
            projected = out.len(),
            unopened,
            "chat: the transcript is empty or partly unreadable — read the counts \
             left to right, the first surprising one is the answer. members=0: \
             the community row never replicated here, so nothing is anchored \
             (check the roster plane, not the message). rows_by_members=0: the \
             members are known but none of their rows are on this node — a \
             DELIVERY problem, look at the sender's withholds. \
             skipped_not_community_scope>0 with projected=0: the rows exist but \
             sit at `self`, so `widen_audience` never placed them and only this \
             node can see them. skipped_other_room>0: rows carry a different \
             `community_key_id` than the one asked for — the two sides derived \
             different room ids. unopened>0: the rows arrived and belong here but \
             the seal will not open, which is an MLS epoch this member does not \
             hold (a row sealed before we joined, or sealed under edge v19's key \
             derivation, which v20 deliberately cannot read)"
        );
    } else {
        tracing::debug!(
            room = %community_id,
            members = members.len(),
            projected = out.len(),
            "chat: transcript assembled"
        );
    }
    Ok(out)
}

/// The other person in a pair room. Split out of [`room_context`] because a
/// `chat_read` delegate needs it and must not be made to acquire the owner's
/// capsule to get it.
async fn other_member(
    st: &ChatState,
    owner: &Owner,
    community_id: &str,
) -> Result<String, Response> {
    match st
        .engine
        .federation_directory()
        .lookup_community(community_id)
        .await
    {
        Ok(Some(c)) => match c
            .members
            .iter()
            .map(|m| m.key_id.clone())
            .find(|k| *k != owner.key_id)
        {
            Some(peer) => Ok(peer),
            None => Err(refuse(
                StatusCode::CONFLICT,
                "chat.not_a_pair_room",
                NOT_A_PAIR_ROOM,
            )),
        },
        Ok(None) => Err(refuse(
            StatusCode::NOT_FOUND,
            "chat.unknown_community",
            format!("no community {community_id:?} on this node"),
        )),
        Err(e) => Err(refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "chat.store_unavailable",
            format!("lookup_community: {e}"),
        )),
    }
}

/// The owner's signer plus the other member — the preamble a route needs when it
/// must ADVANCE the handshake or AUTHOR a row.
async fn room_context(
    st: &ChatState,
    headers: &HeaderMap,
    owner: &Owner,
    community_id: &str,
) -> Result<Option<(crate::owner_signer_capsule::OwnerSignerCapsule, String)>, Response> {
    let peer = other_member(st, owner, community_id).await?;
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
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
            return Err(refuse(
                StatusCode::FORBIDDEN,
                "chat.author_signer_unavailable",
                format!(
                    "a chat room is keyed to the people in it, and this node cannot wield \
                     that identity right now: {e:?}"
                ),
            ))
        }
    };
    Ok(Some((capsule, peer)))
}

async fn load_message(
    st: &ChatState,
    community_id: &str,
    attestation_id: &str,
    owner: &Owner,
    key: &ciris_edge::chat::RoomKey,
) -> Result<Option<ChatMessage>, String> {
    Ok(collect_messages(st, community_id, owner, key)
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
    let peer = match other_member(&st, &owner, &community_id).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    // The transcript is CIPHERTEXT on the wire; opening it needs the room key.
    //
    // Try the key WITHOUT the owner's signer first. A room whose handshake has
    // finished is readable by anyone the owner let read it — including a
    // `chat_read` delegate, which holds no fed-ID and could never acquire the
    // capsule. Only ADVANCING an unfinished handshake needs the person, and a
    // delegate cannot do that anyway; for them the honest answer is the same
    // "not keyed yet" the owner would get, not a permission error.
    let key = 'key: {
        match room_key(&st, &owner.key_id, &peer, None).await {
            Ok((Some(k), _)) => break 'key k,
            // NOT KEYED — and that is a 200, not an error. The room exists, the
            // conversation has simply not finished starting, and the transcript
            // says so in its own voice. A 503 here made every client invent its
            // own wording for a state the server can name exactly, and gave the
            // user a failure where the truth is "waiting for them".
            Ok((None, first)) => {
                // One attempt to ADVANCE the handshake with the owner's signer:
                // reading needs no fed-ID, authoring our half does. A delegate
                // reaches neither, and gets the same note the owner would.
                if let Ok(Some((capsule, _))) =
                    room_context(&st, &headers, &owner, &community_id).await
                {
                    match room_key(&st, &owner.key_id, &peer, Some(capsule.edge_signer())).await {
                        Ok((Some(k), _)) => break 'key k,
                        Ok((None, state)) => return transcript_pending(&community_id, state),
                        Err(e) => {
                            return refuse(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "chat.room_key_failed",
                                format!("derive the room key: {e}"),
                            )
                        }
                    }
                }
                return transcript_pending(&community_id, first);
            }
            Err(e) => {
                return refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "chat.room_key_failed",
                    format!("derive the room key: {e}"),
                )
            }
        }
    };
    match collect_messages(&st, &community_id, &owner, &key).await {
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
