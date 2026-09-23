//! **Files at every cohort, and the drive that lists them** — one door for
//! self, family and community (CIRISServer#622 / #615, edge v29.5.0
//! `FSD/CONTENT_TRANSFER.md` §6.7–§6.9).
//!
//! # One door, three cohorts
//!
//! A file is bytes sealed at a room's tier plus a row citing them. Which room
//! decides everything else — the seal's group, the row's cohort target, who the
//! row crosses to — and edge's [`ScopeRoom`] answers all of those from one
//! value, so nothing here spells a group id or picks an audience by hand. That
//! is deliberate: the alternative is three near-copies of one rule, which is
//! how the cohorts drift apart.
//!
//! # What the drive shows that a file listing does not
//!
//! `row held, bytes absent` is a FIRST-CLASS state, not an error. A self file
//! written on the laptop is a row on the phone long before its bytes are
//! pulled, and the honest answer for the phone's drive is "on another device" —
//! distinct from "this key does not open it", which is a grant problem with a
//! different remedy. `UnopenedReason::NotFetched` and `NotGranted` are separate
//! variants for exactly that reason, and this surface keeps them separate.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use ciris_edge::files::{self, FileWrite};

/// What a note IS on the wire: a text file in the self room. One constant, so
/// the writer and the reader cannot disagree about which files are notes.
const NOTE_MEDIA_TYPE: &str = "text/plain; charset=utf-8";
use ciris_edge::scope_room::ScopeRoom;
use ciris_persist::prelude::Engine;

/// The cohort a write names. Spelled as a closed set at the door so an
/// unknown token is a 400 with a list, not a silently-wrong audience.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Cohort {
    /// This identity's own devices.
    #[serde(rename = "self")]
    SelfCollective,
    /// A family the owner belongs to (`family_id` required).
    Family,
    /// A community room (`room_id` required).
    Community,
}

#[derive(Debug, Deserialize)]
pub struct FileWriteRequest {
    pub cohort: Cohort,
    /// The family or community id. Omitted for `self` — the room IS the owner.
    #[serde(default)]
    pub room_id: Option<String>,
    /// Base64 bytes. Inline only for now (edge caps at 1 MiB and says so).
    pub bytes_base64: String,
    pub media_type: String,
    #[serde(default)]
    pub filename: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FileWriteResponse {
    pub attestation_id: String,
    pub cohort: String,
    pub room: String,
    pub tier: String,
    /// **False means the file reached nobody.** It is local-tier, and persist's
    /// E5 invariant keeps local-tier rows out of every federation stream — so
    /// it is invisible to other devices AND to this drive. Reported, never
    /// implied by a 200.
    pub crossed: bool,
    /// Occurrences that could not be granted. Non-empty is partial
    /// readability: those keys will read `not_granted`.
    pub excluded: Vec<String>,
    pub granted: usize,
}

#[derive(Debug, Serialize)]
pub struct DriveEntry {
    pub attestation_id: String,
    pub author_key_id: String,
    pub asserted_at: String,
    pub filename: Option<String>,
    pub media_type: Option<String>,
    /// `here` when the bytes open on this node, else the reason they do not.
    pub bytes: String,
    /// The plain-words version of `bytes`, for a client that renders state.
    pub detail: String,
}

#[derive(Debug, Deserialize)]
pub struct DriveQuery {
    #[serde(default)]
    pub cohort: Option<String>,
    #[serde(default)]
    pub room_id: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

#[derive(Clone)]
pub struct DriveState {
    pub engine: Arc<Engine>,
    pub node_signer: Arc<ciris_edge::identity::LocalSigner>,
    pub user_seed_dir: std::path::PathBuf,
}

fn refuse(code: StatusCode, error: &str, detail: String) -> Response {
    (
        code,
        Json(serde_json::json!({ "error": error, "detail": detail })),
    )
        .into_response()
}

/// Resolve the room a request names, refusing a missing id by name rather than
/// defaulting to something the caller did not ask for.
#[allow(clippy::result_large_err)] // the Err IS an axum Response; boxing it would
                                   // only move the allocation and make every call site unwrap a Box to return it.
fn room_for(cohort: Cohort, room_id: Option<&str>, owner: &str) -> Result<ScopeRoom, Response> {
    match cohort {
        Cohort::SelfCollective => Ok(ciris_edge::self_room::room(owner)),
        Cohort::Family => room_id.map(ScopeRoom::family).ok_or_else(|| {
            refuse(
                StatusCode::BAD_REQUEST,
                "drive.room_required",
                "a family write must name `room_id` (the family's key id) — there is no \
                 default family, and guessing one would place bytes in a cohort nobody chose"
                    .into(),
            )
        }),
        Cohort::Community => room_id.map(ScopeRoom::community).ok_or_else(|| {
            refuse(
                StatusCode::BAD_REQUEST,
                "drive.room_required",
                "a community write must name `room_id` (the community's key id)".into(),
            )
        }),
    }
}

fn store(engine: &Arc<Engine>) -> ciris_edge::group_content::PersistGroupContentStore {
    ciris_edge::group_content::PersistGroupContentStore::new(
        (**engine).clone(),
        engine.federation_directory(),
    )
}

/// Make sure the OWNER is a content-KEM target on this node before a write.
///
/// A self/family write resolves its recipients from the owner's active
/// occurrences that carry content-KEM keys. A freshly claimed node has none —
/// only its own singleton — so `files::publish` refuses the write as
/// `ReadableByNobody`: correct, and useless to the person who just asked to
/// save a file. The self-room drive provisions this on its cadence, but a
/// FIRST write must not have to wait for a background tick; the chat route has
/// ensured the same thing inline since 0.5.207 for exactly this reason.
///
/// Idempotent. A failure is logged and not fatal: the publish below will refuse
/// by name, which is a better error than this one could invent.
async fn ensure_owner_is_a_kem_target(st: &DriveState, owner_key_id: &str) {
    match crate::backend::provision_engine_occurrence(&st.engine, owner_key_id).await {
        Ok((occurrence, how)) if how != "already_current" => tracing::info!(
            owner = %owner_key_id, %occurrence, how,
            "drive: provisioned this node as a content-KEM occurrence of its owner so the \
             write below has somebody to be wrapped to"
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(
            owner = %owner_key_id, error = %e,
            "drive: could not provision this node as a content-KEM occurrence of its owner — \
             a self or family write will refuse as readable-by-nobody"
        ),
    }
}

/// `POST /v1/files` — write a file at a chosen cohort.
async fn write_file(
    State(st): State<DriveState>,
    headers: HeaderMap,
    Json(req): Json<FileWriteRequest>,
) -> Response {
    let Some(owner) = crate::drive_auth::owner(&st, &headers).await else {
        return refuse(
            StatusCode::FORBIDDEN,
            "drive.owner_session_required",
            "writing a file is an act of the person who owns this node".into(),
        );
    };
    let room = match room_for(req.cohort, req.room_id.as_deref(), &owner.key_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    ensure_owner_is_a_kem_target(&st, &owner.key_id).await;
    let bytes = match base64_decode(&req.bytes_base64) {
        Ok(b) => b,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, "drive.bad_base64", e),
    };
    let capsule = match crate::owner_signer_capsule::acquire(
        &st.engine,
        bearer(&headers),
        &owner.key_id,
        st.user_seed_dir.clone(),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            return refuse(
                StatusCode::FORBIDDEN,
                "drive.author_signer_unavailable",
                format!(
                "a file is authored by the person, and this node cannot wield that identity: {e:?}"
            ),
            )
        }
    };
    let dir = st.engine.federation_directory();
    let content = store(&st.engine);
    let published = match files::publish(
        &*dir,
        &content,
        ciris_edge::replication::attestation_bind::Signers {
            node: &st.node_signer,
            actor: Some(capsule.edge_signer()),
        },
        &FileWrite {
            room: &room,
            bytes: &bytes,
            media_type: &req.media_type,
            filename: req.filename.as_deref(),
            asserted_at: chrono::Utc::now(),
        },
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return file_error(&e, &room),
    };
    // The row is written; make it cross now rather than on the next cadence.
    crate::compose::kick_replication("file published in a cohort room");
    if !published.crossed {
        tracing::warn!(
            room = %room,
            attestation_id = %published.row.attestation_id,
            "drive: the file was written but did NOT cross — it is local-tier, which persist's \
             E5 invariant keeps out of every federation stream, so no other device and not \
             even this node's own drive will list it. It parks only when the crossing awaits \
             an actor signature"
        );
    }
    if !published.excluded.is_empty() {
        tracing::warn!(
            room = %room,
            excluded = ?published.excluded,
            "drive: the file is only PARTIALLY readable — these occurrences hold no grant and \
             will read not_granted"
        );
    }
    (
        StatusCode::OK,
        Json(FileWriteResponse {
            attestation_id: published.row.attestation_id.clone(),
            cohort: room.row_scope_token().to_owned(),
            room: room.to_string(),
            tier: format!("{:?}", published.tier),
            crossed: published.crossed,
            excluded: published.excluded.clone(),
            granted: published.granted.len(),
        }),
    )
        .into_response()
}

/// `GET /v1/drive` — everything this identity can reach, with the bytes' state
/// named per row.
async fn read_drive(
    State(st): State<DriveState>,
    headers: HeaderMap,
    Query(q): Query<DriveQuery>,
) -> Response {
    let Some(owner) = crate::drive_auth::owner(&st, &headers).await else {
        return refuse(
            StatusCode::FORBIDDEN,
            "drive.owner_session_required",
            "a drive is one person's view of their own reach".into(),
        );
    };
    let cohort = match q.cohort.as_deref() {
        None | Some("self") => Cohort::SelfCollective,
        Some("family") => Cohort::Family,
        Some("community") => Cohort::Community,
        Some(other) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "drive.unknown_cohort",
                format!("unknown cohort {other:?} — use self | family | community"),
            )
        }
    };
    let room = match room_for(cohort, q.room_id.as_deref(), &owner.key_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let dir = st.engine.federation_directory();
    let rows = match files::in_room(&*dir, &room, q.limit).await {
        Ok(r) => r,
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "drive.listing_failed",
                format!("list {room}: {e}"),
            )
        }
    };
    let content = store(&st.engine);
    let viewer = match st.engine.local_derived_key_id().await {
        Ok(v) => v,
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "drive.no_node_key",
                format!("resolve this node's key: {e}"),
            )
        }
    };
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let (bytes, detail) = match row.open(&content, &viewer).await {
            Ok(_) => ("here".to_owned(), "the bytes are on this device".to_owned()),
            Err(reason) => unopened(&reason),
        };
        out.push(DriveEntry {
            attestation_id: row.attestation_id.clone(),
            author_key_id: row.attesting_key_id.clone(),
            asserted_at: row.asserted_at.to_rfc3339(),
            filename: row.filename.clone(),
            media_type: row.media_type.clone(),
            bytes,
            detail,
        });
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "cohort": room.row_scope_token(),
            "room": room.to_string(),
            "entries": out,
        })),
    )
        .into_response()
}

/// `GET /v1/files/{attestation_id}` — the bytes, or the reason they are not
/// here yet.
async fn read_file(
    State(st): State<DriveState>,
    headers: HeaderMap,
    Path(attestation_id): Path<String>,
    Query(q): Query<DriveQuery>,
) -> Response {
    let Some(owner) = crate::drive_auth::owner(&st, &headers).await else {
        return refuse(
            StatusCode::FORBIDDEN,
            "drive.owner_session_required",
            "reading a file is an act of the person who owns this node".into(),
        );
    };
    // Named, not defaulted. A `_ => Community` arm here sent a typo'd cohort
    // looking in a community room and reported `not_in_room` — a refusal about
    // the ROW for a mistake in the QUESTION, which is the hardest kind to read
    // from the client side. The write and list doors both name it; so does this.
    let cohort = match q.cohort.as_deref() {
        None | Some("self") => Cohort::SelfCollective,
        Some("family") => Cohort::Family,
        Some("community") => Cohort::Community,
        Some(other) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "drive.unknown_cohort",
                format!("unknown cohort {other:?} — use self | family | community"),
            )
        }
    };
    let room = match room_for(cohort, q.room_id.as_deref(), &owner.key_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let dir = st.engine.federation_directory();
    let rows = files::in_room(&*dir, &room, 500).await.unwrap_or_default();
    let Some(row) = rows
        .into_iter()
        .find(|r| r.attestation_id == attestation_id)
    else {
        return refuse(
            StatusCode::NOT_FOUND,
            "drive.not_in_room",
            format!("{attestation_id} is not a file row in {room}"),
        );
    };
    let content = store(&st.engine);
    let viewer = match st.engine.local_derived_key_id().await {
        Ok(v) => v,
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "drive.no_node_key",
                format!("resolve this node's key: {e}"),
            )
        }
    };
    match row.open(&content, &viewer).await {
        Ok(bytes) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "attestation_id": row.attestation_id,
                "media_type": row.media_type,
                "filename": row.filename,
                "bytes_base64": base64_encode(&bytes),
            })),
        )
            .into_response(),
        Err(reason) => {
            let (state, detail) = unopened(&reason);
            // NOT an error status for `not_fetched`: the row is legitimately
            // here and the bytes legitimately are not. 409 says "ask again",
            // which is the truth, where 404 would say "this does not exist".
            let code = if state == "not_fetched" {
                StatusCode::CONFLICT
            } else {
                StatusCode::FORBIDDEN
            };
            refuse(code, &format!("drive.{state}"), detail)
        }
    }
}

/// The two states a client must tell apart, in its words.
fn unopened(reason: &ciris_edge::chat::UnopenedReason) -> (String, String) {
    let s = format!("{reason:?}");
    if s.contains("NotFetched") {
        (
            "not_fetched".to_owned(),
            "on another device — the row is here, its bytes have not been pulled yet".to_owned(),
        )
    } else if s.contains("NotGranted") {
        (
            "not_granted".to_owned(),
            "this device's key does not open it — it holds no grant for these bytes".to_owned(),
        )
    } else {
        ("unopened".to_owned(), s)
    }
}

fn file_error(e: &files::FileError, room: &ScopeRoom) -> Response {
    use files::FileError as F;
    let (code, tag, detail) = match e {
        F::TooLargeForInline { size, cap } => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "drive.too_large",
            format!(
                "{size} bytes exceeds the {cap}-byte inline cap — the chunk-DAG door is not \
                 open yet (CIRISEdge#633)"
            ),
        ),
        F::ReadableByNobody { .. } => (
            StatusCode::CONFLICT,
            "drive.readable_by_nobody",
            format!(
                "nothing in {room} could be granted these bytes, so the write was refused \
                 rather than sealing something no one can open"
            ),
        ),
        other => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "drive.publish_failed",
            format!("{other:?}"),
        ),
    };
    refuse(code, tag, detail)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| format!("bytes_base64 is not base64: {e}"))
}

fn base64_encode(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

// ─────────────────────────────────────────────────────────────────────────────
// NOTES — self-chat as a note-taking mechanism
// ─────────────────────────────────────────────────────────────────────────────
//
// A note is a chat message in the SELF room: same row shape, same sealed body,
// same crossing — the only difference is the room, and therefore the audience.
// That is the whole design. Writing a note is talking to yourself across your
// own devices, so it needs no new object: the self room already means "this
// identity's devices", the body is already sealed to the room's tier, and the
// row already crosses `With::MyDevices`.
//
// It also gets the properties for free that a bespoke notes table would have
// had to re-earn: a note is a CEG row with an author and a time, it is
// invisible to the substrate (CC 5.2 — no holder claim is emitted for self),
// and it reaches a new device through the same retroactive re-grant as
// everything else the owner holds.

#[derive(Debug, Deserialize)]
pub struct NoteWrite {
    pub body: String,
}

#[derive(Debug, Serialize)]
pub struct Note {
    pub attestation_id: String,
    pub asserted_at: String,
    pub author_key_id: String,
    /// The note, when this device can open it; `None` with `state` saying why.
    pub body: Option<String>,
    pub state: String,
    pub detail: String,
}

/// `POST /v1/notes` — write a note to yourself.
async fn write_note(
    State(st): State<DriveState>,
    headers: HeaderMap,
    Json(req): Json<NoteWrite>,
) -> Response {
    let Some(owner) = crate::drive_auth::owner(&st, &headers).await else {
        return refuse(
            StatusCode::FORBIDDEN,
            "notes.owner_session_required",
            "a note is written by the person whose devices these are".into(),
        );
    };
    if req.body.trim().is_empty() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "notes.empty",
            "a note with no body is not a note".into(),
        );
    }
    let room = ciris_edge::self_room::room(&owner.key_id);
    ensure_owner_is_a_kem_target(&st, &owner.key_id).await;
    let capsule = match crate::owner_signer_capsule::acquire(
        &st.engine,
        bearer(&headers),
        &owner.key_id,
        st.user_seed_dir.clone(),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            return refuse(
                StatusCode::FORBIDDEN,
                "notes.author_signer_unavailable",
                format!("a note is authored by the person: {e:?}"),
            )
        }
    };
    let dir = st.engine.federation_directory();
    let content = store(&st.engine);
    // A NOTE IS A SELF-SCOPED TEXT FILE, through the same door as every other
    // file. The first cut authored it with `chat_message_attestation_in`, and
    // persist refused the seal by name: that builder stamps `cohort_scope:
    // community` and hands persist the room id as a `community_key_id`, so a
    // self room came back as `unknown community_key_id`. The refusal was right
    // — the community-DEK path is not the self tier. `files::publish` seals at
    // the ROOM's tier (a per-write DEK for self) and fills persist's group slot
    // with the OWNER, which is what a self note is.
    let published = match files::publish(
        &*dir,
        &content,
        ciris_edge::replication::attestation_bind::Signers {
            node: &st.node_signer,
            actor: Some(capsule.edge_signer()),
        },
        &FileWrite {
            room: &room,
            bytes: req.body.as_bytes(),
            media_type: NOTE_MEDIA_TYPE,
            filename: None,
            asserted_at: chrono::Utc::now(),
        },
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return file_error(&e, &room),
    };
    crate::compose::kick_replication("note written in the self room");
    if !published.crossed {
        tracing::warn!(
            attestation_id = %published.row.attestation_id,
            "notes: the note was written but did NOT cross — it is local-tier, so this \
             person's other devices will never see it"
        );
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "attestation_id": published.row.attestation_id,
            "room": room.to_string(),
            "cohort": room.row_scope_token(),
            "crossed": published.crossed,
        })),
    )
        .into_response()
}

/// `GET /v1/notes` — your notes, newest last, with unopened ones named.
async fn read_notes(
    State(st): State<DriveState>,
    headers: HeaderMap,
    Query(q): Query<DriveQuery>,
) -> Response {
    let Some(owner) = crate::drive_auth::owner(&st, &headers).await else {
        return refuse(
            StatusCode::FORBIDDEN,
            "notes.owner_session_required",
            "notes are one person's".into(),
        );
    };
    let room = ciris_edge::self_room::room(&owner.key_id);
    let dir = st.engine.federation_directory();
    let rows = match files::in_room(&*dir, &room, q.limit).await {
        Ok(r) => r,
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "notes.listing_failed",
                format!("read your self room: {e}"),
            )
        }
    };
    let content = store(&st.engine);
    let viewer = match st.engine.local_derived_key_id().await {
        Ok(v) => v,
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "notes.no_node_key",
                format!("resolve this node's key: {e}"),
            )
        }
    };
    let mut out: Vec<Note> = Vec::new();
    for row in rows {
        // A note is an UNNAMED text row in this room. Both conditions, because
        // both are what `write_note` stamps: `text/plain` and `filename: None`.
        // The media type alone is not enough — `POST /v1/files` can put a named
        // `.txt` in the same room, and a notes list that swallowed it would
        // report somebody's uploaded file as something they had written. A
        // photo in this room is excluded by the type; a named text file is
        // excluded by the name, and nothing here guesses.
        let is_text = row
            .media_type
            .as_deref()
            .is_some_and(|m| m.starts_with("text/plain"));
        if !is_text || row.filename.is_some() {
            continue;
        }
        let (body, state, detail) = match row.open(&content, &viewer).await {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(text) => (
                    Some(text),
                    "open".to_owned(),
                    "readable on this device".to_owned(),
                ),
                Err(_) => (
                    None,
                    "unreadable".to_owned(),
                    "the bytes opened but are not UTF-8 text".to_owned(),
                ),
            },
            Err(reason) => {
                let (s, d) = unopened(&reason);
                (None, s, d)
            }
        };
        out.push(Note {
            attestation_id: row.attestation_id.clone(),
            asserted_at: row.asserted_at.to_rfc3339(),
            author_key_id: row.attesting_key_id.clone(),
            body,
            state,
            detail,
        });
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "room": room.to_string(), "notes": out })),
    )
        .into_response()
}

pub fn router(
    engine: Arc<Engine>,
    node_signer: Arc<ciris_edge::identity::LocalSigner>,
    user_seed_dir: std::path::PathBuf,
) -> Router {
    let state = DriveState {
        engine,
        node_signer,
        user_seed_dir,
    };
    Router::new()
        .route("/v1/files", axum::routing::post(write_file))
        .route("/v1/drive", axum::routing::get(read_drive))
        .route("/v1/files/{attestation_id}", axum::routing::get(read_file))
        .route("/v1/notes", axum::routing::get(read_notes).post(write_note))
        .with_state(state)
}
