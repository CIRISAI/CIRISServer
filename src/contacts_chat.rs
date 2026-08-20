//! **Contacts + user chat** — the owner-facing surface over the substrate that
//! was already there.
//!
//! Nothing here is a new plane. Every object this module writes is a CEG object
//! persist already types, and every read is a persist reader:
//!
//! | route | the CEG object it moves | the persist primitive |
//! |---|---|---|
//! | `GET /v1/contacts` | `consent:replication:v1` grants, revocation-folded | [`crate::peer::replication_peers_from_consent`] → `list_consent_peers` |
//! | `POST /v1/contacts` | one `consent:replication:v1` grant | [`crate::peer::emit_replication_consent`] |
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
//! chat message actually reach the other side. So `POST /v1/contacts` emits that
//! grant (idempotent), and `GET /v1/contacts` reads
//! [`crate::peer::replication_peers_from_consent`] — persist's
//! `list_consent_peers` projection, which has the `withdraws`/`supersedes` fold
//! ALREADY applied. Un-contacting is therefore the ordinary CEG withdraw of the
//! grant row, with no second code path to keep in step.
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
use sha2::{Digest, Sha256};

use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::precedence;
use ciris_persist::federation::types::{
    attestation_type, cohort_scope, Attestation, Community, CommunityMember, LocalAttestationInput,
};
use ciris_persist::prelude::{CallerScope, Engine};

use crate::auth::refusal::refuse;
use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::resolve_bearer;

// ─── Vocabulary ─────────────────────────────────────────────────────────────

/// The `scores` dimension every chat message carries. Versioned because
/// persist's `require_version_segment` demands a `:vN` segment on every `scores`
/// dimension, and prefixed `chat:` because that prefix is NOT reserved by
/// `default_reserved_prefix_rules` — an ordinary `user` identity may emit it.
pub const CHAT_MESSAGE_DIMENSION: &str = "chat:message:v1";

/// The replication-consent namespace prefix a contact grant must cover for chat
/// messages to actually federate to the contact.
pub const CHAT_ATTESTATION_PREFIX: &str = "chat:";

/// The derived-id prefix for a two-party chat community. See the module docs.
pub const PAIR_COMMUNITY_PREFIX: &str = "chat:pair:v1:";

/// `unanimous` — the honest `consensus_protocol` for a two-party community
/// (persist's `check_consensus_protocol_form` accepts it as a canonical form).
const PAIR_CONSENSUS_PROTOCOL: &str = "unanimous";

/// Envelope member naming the community a message belongs to. NOT an
/// `envelope::paths` constant — persist types no cohort-target field (see
/// `check_promotion_cohort_standing`'s own note that "the row has no field to
/// name one"), so this is server vocabulary, spelled the same way
/// `safety::moderation` already spells it.
const FIELD_COMMUNITY_ID: &str = "community_id";
/// Envelope member carrying the message text.
const FIELD_BODY: &str = "body";
/// Envelope member carrying the body's media type.
const FIELD_CONTENT_TYPE: &str = "content_type";
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
    match resolve_bearer(&st.engine, token).await {
        Ok(Some(caller))
            if caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) => {}
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
    }
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
    })
}

// ─── The derived pair-community id ──────────────────────────────────────────

/// **The convergent name for a two-party chat.**
///
/// `sha256` over the two `key_id`s sorted ascending and joined by a newline,
/// under [`PAIR_COMMUNITY_PREFIX`]. Both properties are load bearing:
///
/// - **Sorted** so `pair(a, b) == pair(b, a)` — the two ends dial the same
///   community without agreeing on who initiated.
/// - **Separator-joined** so `("ab", "c")` and `("a", "bc")` cannot collide;
///   `key_id`s carry no newline, so the concatenation is unambiguous.
///
/// Persist has no such convention of its own (searched: nothing in
/// `federation/` derives a pair id), so this is the server's, stated once.
#[must_use]
pub fn pair_community_key_id(a: &str, b: &str) -> String {
    let mut pair = [a, b];
    pair.sort_unstable();
    let mut h = Sha256::new();
    h.update(pair[0].as_bytes());
    h.update(b"\n");
    h.update(pair[1].as_bytes());
    format!("{PAIR_COMMUNITY_PREFIX}{}", hex::encode(h.finalize()))
}

/// The community's display name, derived from the same sorted pair so both ends
/// author identical roster content.
fn pair_community_name(a: &str, b: &str) -> String {
    let mut pair = [a, b];
    pair.sort_unstable();
    format!("{} <-> {}", pair[0], pair[1])
}

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
    // Persist's revocation-FOLDED consent peer set — a withdrawn grant is
    // already gone here, so un-contacting needs no second code path.
    let peer_ids =
        match crate::peer::replication_peers_from_consent(&st.engine, &owner.node_key_id).await {
            Ok(p) => p,
            Err(e) => {
                return refuse(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "contacts.store_unavailable",
                    format!("consent peer set: {e}"),
                )
            }
        };
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
    /// `false` when the grant already stood (the call is idempotent).
    freshly_emitted: bool,
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

    // THE contact object. Idempotent: an existing grant is returned, not
    // re-emitted.
    let mut prefixes = crate::peer::default_attestation_prefixes();
    prefixes.push(CHAT_ATTESTATION_PREFIX.to_owned());
    let grant = match crate::peer::emit_replication_consent(
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
                format!("emit consent:replication:v1 grant: {e}"),
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

    // The contact must be a CONTACT, not merely a known key: a chat community
    // whose messages this node has not consented to replicate to the other
    // member is a room nothing ever leaves.
    match crate::peer::replication_peers_from_consent(&st.engine, &owner.node_key_id).await {
        Ok(peers) if peers.iter().any(|p| p == &key_id) => {}
        Ok(_) => {
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
    match directory.lookup_community(&community_id).await {
        Ok(Some(existing)) => {
            return (
                StatusCode::OK,
                Json(StartChatResponse {
                    community_id: existing.community_key_id,
                    community_name: existing.community_name,
                    member_key_ids: existing.members.into_iter().map(|m| m.key_id).collect(),
                    cohort_scope: cohort_scope::COMMUNITY,
                    freshly_created: false,
                }),
            )
                .into_response()
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

    let mut member_key_ids = vec![owner.key_id.clone(), key_id.clone()];
    member_key_ids.sort();
    let community = Community {
        community_key_id: community_id.clone(),
        community_name: pair_community_name(&owner.key_id, &key_id),
        members: member_key_ids
            .iter()
            .map(|k| CommunityMember {
                key_id: k.clone(),
                joined_at: founded_at,
                role: None,
            })
            .collect(),
        founded_at,
        consensus_protocol: PAIR_CONSENSUS_PROTOCOL.to_owned(),
        policy_blob: None,
        // Server-computed by `put_community`.
        persist_row_hash: String::new(),
    };
    // Authored + hybrid-signed by THIS node through persist's own builder —
    // never a hand-rolled `SignedCommunity`, because the JCS field-set gate
    // verifies the signature over `Community::signing_envelope()` exactly.
    if let Err(e) = st.engine.put_community_self_signed(community).await {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "chat.community_create_failed",
            format!("put_community_self_signed: {e}"),
        );
    }
    (
        StatusCode::OK,
        Json(StartChatResponse {
            community_id: community_id.clone(),
            community_name: pair_community_name(&owner.key_id, &key_id),
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
    /// `true` when this node's owner authored the message.
    mine: bool,
}

/// Is this row a chat message in `community_id`?
fn is_message_for(row: &Attestation, community_id: &str) -> bool {
    row.attestation_type == attestation_type::SCORES
        && row.cohort_scope == cohort_scope::COMMUNITY
        && row
            .attestation_envelope
            .get(paths::DIMENSION)
            .and_then(|v| v.as_str())
            == Some(CHAT_MESSAGE_DIMENSION)
        && row
            .attestation_envelope
            .get(FIELD_COMMUNITY_ID)
            .and_then(|v| v.as_str())
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
    // write stamps it once, at the substrate's own resolution.
    let envelope = serde_json::json!({
        (paths::DIMENSION): CHAT_MESSAGE_DIMENSION,
        FIELD_COMMUNITY_ID: community_id,
        FIELD_BODY: req.body,
        FIELD_CONTENT_TYPE: content_type,
        // A `scores` row carries a score; the magnitude is not load bearing for
        // a message, and a positive constant is the honest "this was said".
        "score": 1.0,
    });
    let envelope_core =
        match ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope) {
            Ok(e) => e,
            Err(e) => {
                return refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "chat.emit_failed",
                    format!("build message envelope: {e}"),
                )
            }
        };
    let input = LocalAttestationInput {
        attestation_id: None,
        attesting_key_id: owner.key_id.clone(),
        // Producer-only, at BOTH of these fields — `check_promotion_cohort_standing`
        // refuses a `community` placement that names any other party.
        attested_key_id: Some(owner.key_id.clone()),
        attestation_type: attestation_type::SCORES.to_owned(),
        weight: None,
        expires_at: None,
        attestation_envelope: envelope_core,
        subject_key_ids: vec![owner.key_id.clone()],
        // Staged `self`, then PLACED at `community` by the promote below — the
        // same two-step `safety::moderation` uses. Signature is deferred to the
        // promote (persist v13 #171).
        cohort_scope: cohort_scope::SELF.to_owned(),
        scrub_signature_classical: None,
        scrub_signature_pqc: None,
    };
    let attestation_id = match st
        .engine
        .federation_directory()
        .attestation_upsert_local(input)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "chat.emit_failed",
                format!("attestation_upsert_local(chat:message:v1): {e}"),
            )
        }
    };
    // Place it at the community tier: federation TIER (so it replicates to the
    // other member) with `community` PLACEMENT (so only the cohort sees it).
    if let Err(e) = st
        .engine
        .attestation_promote(&attestation_id, cohort_scope::COMMUNITY)
        .await
    {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "chat.emit_failed",
            format!("attestation_promote(community): {e}"),
        );
    }
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
    let mut rows: Vec<Attestation> = Vec::new();
    for member in &members {
        let mut authored = directory
            .list_attestations_by(&member.key_id)
            .await
            .map_err(|e| format!("list_attestations_by({}): {e}", member.key_id))?;
        rows.append(&mut authored);
    }
    // Composers first, so a message's status is available when it is projected.
    let mut composers: HashMap<String, Vec<&Attestation>> = HashMap::new();
    for row in &rows {
        if !precedence::is_structural_composer(&row.attestation_type) {
            continue;
        }
        if let Some(target) =
            precedence::references_attestation_id_from_envelope(&row.attestation_envelope)
        {
            composers.entry(target.to_owned()).or_default().push(row);
        }
    }
    let mut out: Vec<ChatMessage> = Vec::new();
    for row in &rows {
        if !is_message_for(row, community_id) {
            continue;
        }
        let (status, status_attestation_id) = fold_status(composers.get(&row.attestation_id));
        out.push(ChatMessage {
            attestation_id: row.attestation_id.clone(),
            attesting_key_id: row.attesting_key_id.clone(),
            attested_key_id: row.attested_key_id.clone(),
            attestation_type: row.attestation_type.clone(),
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
            mine: row.attesting_key_id == owner.key_id,
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
pub fn router(engine: Arc<Engine>) -> Router {
    let state = ChatState { engine };
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

    /// The community name is derived from the same sorted pair, so both ends
    /// author identical roster content.
    #[test]
    fn pair_name_is_order_free() {
        assert_eq!(pair_community_name("b", "a"), pair_community_name("a", "b"));
    }
}
