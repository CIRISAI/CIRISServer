//! **Files at every cohort, and the drive that lists them** — one door for
//! self, family and community (CIRISServer#622 / #615, edge v29.5.0
//! `FSD/CONTENT_TRANSFER.md` §6.7–§6.9), and since 0.5.216 the whole CRUD
//! surface over them (`FSD/ROSTER_AND_DRIVE_CRUD.md` §5).
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
//!
//! # Changing a file is a new claim; deleting one is a `withdraws`
//!
//! Nothing here edits a row. Replace, rename and move each PUBLISH a new row and
//! then WITHDRAW the old one (edge's `withdraws_attestation`, the CC 2.4.1
//! composer); delete is the withdrawal alone. Persist then refuses every read of
//! bytes whose every binding row is withdrawn (CC 2.3 at the bytes plane,
//! `BlobError::Withdrawn`), and the local copy is evicted (`Engine::evict_blob`)
//! once nothing live binds it. A rename binds the SAME bytes under the new row,
//! so its bytes stay live and are never evicted.
//!
//! # Who may change a file
//!
//! The row's author, and "author" is read off the row: `files::publish` signs
//! every file row with THIS NODE's key (`Signers::node`), and a `withdraws` is
//! admitted for rule 1 — the target's own attester. So this node can retract
//! exactly the rows it wrote; a file its owner wrote on another device is
//! withdrawn from that device. See `require_author`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use ciris_edge::files::{self, FileWrite};
use ciris_edge::scope_room::ScopeRoom;
use ciris_persist::federation::{Attestation, BlobError};
use ciris_persist::prelude::Engine;

/// What a note IS on the wire: a text file in the self room. One constant, so
/// the writer and the reader cannot disagree about which files are notes.
const NOTE_MEDIA_TYPE: &str = "text/plain; charset=utf-8";

/// **The largest file this node writes or reads whole: persist's chunk-DAG
/// whole-read cap (64 MiB).**
///
/// One number for both directions, on purpose. An upload above it would seal
/// fine (edge seals anything above 1 MiB as a chunk DAG) but could then never be
/// opened by the JSON read, `GET /v1/files/{id}`, or by `move`, which all read
/// whole — so the node would accept bytes it cannot give back the same way. A
/// file received from a peer above it is still served, by `?raw=1` with `Range`.
pub const WHOLE_READ_CAP: usize =
    ciris_persist::federation::chunk_dag_cascade::DAG_WHOLE_READ_CAP_BYTES as usize;

/// The request-body ceiling for the upload routes: the cap, as base64 (the JSON
/// form inflates by 4/3), plus 1 MiB for the form's other members and multipart
/// framing. Applied to `POST /v1/files` and `PUT /v1/files/{id}` ONLY — every
/// other route keeps axum's 2 MB default, which is the right size for JSON.
pub const UPLOAD_BODY_LIMIT: usize = WHOLE_READ_CAP.div_ceil(3) * 4 + 1024 * 1024;

/// The most rows one `GET /v1/drive` page returns. A bigger `limit` is clamped,
/// not refused: a client asking for "everything" gets a page and a `resume`.
pub const MAX_PAGE: usize = 500;

/// The envelope member a rename row carries, naming the row it replaces.
///
/// A signed member, not a CEG `supersedes`: edge's file door offers no
/// supersedes input, and persist's only supersedes builder
/// (`crossing::build_widening`) changes `cohort_scope` and nothing else. The
/// old row is WITHDRAWN, which is what retires it; this member is the lineage a
/// client renders ("renamed from …"). `FSD/ROSTER_AND_DRIVE_CRUD.md` §5 records
/// the gap.
pub const FIELD_REPLACES: &str = "replaces_attestation_id";

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

impl Cohort {
    fn parse(token: Option<&str>) -> Result<Self, String> {
        match token {
            None | Some("self") => Ok(Self::SelfCollective),
            Some("family") => Ok(Self::Family),
            Some("community") => Ok(Self::Community),
            Some(other) => Err(format!(
                "unknown cohort {other:?} — use self | family | community"
            )),
        }
    }
}

/// The JSON upload form. `multipart/form-data` carries the same members as
/// form fields, with the bytes in a part named `file`.
#[derive(Debug, Deserialize)]
pub struct FileWriteRequest {
    #[serde(default)]
    pub cohort: Option<Cohort>,
    /// The family or community id. Omitted for `self` — the room IS the owner.
    #[serde(default)]
    pub room_id: Option<String>,
    /// Base64 bytes, up to [`WHOLE_READ_CAP`] decoded. Edge seals anything
    /// above its 1 MiB envelope bound as a chunk DAG (CIRISEdge#633); for a
    /// large file prefer `multipart/form-data`, which skips the 4/3 inflation.
    pub bytes_base64: String,
    #[serde(default)]
    pub media_type: Option<String>,
    #[serde(default)]
    pub filename: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FileWriteResponse {
    pub attestation_id: String,
    /// Whether the room has a derived destination. `crossed: true` with
    /// `addressed: false` means the ROW reached the audience and the BYTES
    /// cannot be fetched — two different facts, reported separately.
    pub addressed: bool,
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
    /// The row this write retired, for `PUT` / `move` / `rename`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaces: Option<String>,
    /// Every row id withdrawn by this call (the listed row and the prior rows
    /// its widening superseded). Empty for a plain upload.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub withdrawn: Vec<String>,
}

/// The PLAINTEXT digest of an opened file, as lowercase hex SHA-256
/// (CIRISServer#641; CC 5.3.2.5 "verify the full SHA-256 before handing bytes
/// to any renderer"). This node opened the seal, so it can state the digest of
/// what it hands over; the edge pointer's `content_sha256` is the AT-REST hash
/// (the sealed blob or the chunk manifest) and never matches decrypted bytes.
/// A digest SIGNED into the row itself needs edge's file row to carry it
/// (CIRISEdge#638).
fn plaintext_digest(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// RFC 9530 `Repr-Digest` for a whole representation.
fn repr_digest(bytes: &[u8]) -> Option<HeaderValue> {
    use sha2::{Digest as _, Sha256};
    HeaderValue::from_str(&format!(
        "sha-256=:{}:",
        base64_encode(&Sha256::digest(bytes))
    ))
    .ok()
}

/// The byte-state tokens, one word per fact, shared by every drive surface
/// (`GET /v1/drive` `bytes`, `GET /v1/notes` `state`, the `drive.*` refusal
/// ids). CIRISServer#644: a second surface picked a second word (`open`) for
/// `here`, and a client correctly read the unknown word as "not here". A new
/// surface adds to THIS list, never its own.
pub const BYTE_STATE_HERE: &str = "here";
pub const BYTE_STATES: &[&str] = &[
    BYTE_STATE_HERE,
    "not_fetched",
    "not_granted",
    "withdrawn",
    "evicted",
    "seal_mismatch",
    "unopened",
];

#[derive(Debug, Serialize)]
pub struct DriveEntry {
    /// The cohort this row was listed from (`self` | `family` | `community`).
    pub cohort: String,
    /// The room id to pass back to `GET /v1/files/{id}`.
    pub room_id: String,
    pub attestation_id: String,
    pub author_key_id: String,
    pub asserted_at: String,
    pub filename: Option<String>,
    pub media_type: Option<String>,
    /// `here` when the bytes open on this node, else the reason they do not:
    /// `not_fetched`, `not_granted`, `evicted`, `withdrawn`, or a substrate
    /// fault's kind.
    pub bytes: String,
    /// The plain-words version of `bytes`, for a client that renders state.
    pub detail: String,
    /// The plaintext size, when this node can tell it without opening the
    /// bytes (`None` while they are not here or not granted).
    pub size: Option<u64>,
    /// `true` only on a row a `withdraws` retired — listed at all only under
    /// `include_withdrawn=true`.
    pub withdrawn: bool,
    /// The row this one replaced (rename lineage), when it carries one.
    pub replaces: Option<String>,
    /// The row's CEG envelope (CSD-006 / CIRISServer#616): who it is about,
    /// who signed it, who can see it, what it is.
    pub envelope: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct DriveQuery {
    #[serde(default)]
    pub cohort: Option<String>,
    #[serde(default)]
    pub room_id: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// The `resume` a previous page returned.
    #[serde(default)]
    pub after: Option<String>,
    /// List withdrawn rows too (marked `withdrawn: true`). Off by default: a
    /// withdrawn file is gone from the person's drive.
    #[serde(default)]
    pub include_withdrawn: Option<String>,
}

/// The query every per-file route takes: which room the id lives in.
#[derive(Debug, Deserialize)]
pub struct FileQuery {
    #[serde(default)]
    pub cohort: Option<String>,
    #[serde(default)]
    pub room_id: Option<String>,
    /// `raw=1` answers the BYTES (with `Content-Type`, `Content-Disposition`
    /// and `Range`) instead of the JSON form.
    #[serde(default)]
    pub raw: Option<String>,
}

fn default_limit() -> usize {
    100
}

fn truthy(v: Option<&str>) -> bool {
    matches!(v, Some("1") | Some("true") | Some("yes"))
}

#[derive(Clone)]
pub struct DriveState {
    pub engine: Arc<Engine>,
    pub node_signer: Arc<ciris_edge::identity::LocalSigner>,
    pub user_seed_dir: std::path::PathBuf,
    /// The scope-address plane, so a write can SAY when the room it is sealing
    /// into has no derived destination. See `addressed_or_warn`.
    pub scope_lifecycle: Option<Arc<ciris_edge::scope_lifecycle::ScopeLifecycle>>,
}

/// `{error, reason_id, detail}` — the refusal shape every route here answers
/// (`FSD/ROSTER_AND_DRIVE_CRUD.md` §1 rule 6). `reason_id` IS the localization
/// id; `error` carries the same value for clients written before 0.5.216.
/// [`refuse`] with extra top-level fields (e.g. `declared` / `sniffed` on a
/// format mismatch) — named so the localization guard sees the id it emits.
fn refuse_with(
    code: StatusCode,
    error: &str,
    detail: String,
    extra: serde_json::Value,
) -> Response {
    let mut body = serde_json::json!({ "error": error, "reason_id": error, "detail": detail });
    if let (Some(b), Some(x)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in x {
            b.insert(k.clone(), v.clone());
        }
    }
    (code, Json(body)).into_response()
}

fn refuse(code: StatusCode, error: &str, detail: String) -> Response {
    (
        code,
        Json(serde_json::json!({ "error": error, "reason_id": error, "detail": detail })),
    )
        .into_response()
}

// ─── The session gate, per plane ────────────────────────────────────────────

fn drive_no_session() -> Response {
    refuse(
        StatusCode::FORBIDDEN,
        "drive.owner_session_required",
        "a drive is one person's view of their own reach, and reading or writing in it is that person's own act".into(),
    )
}

fn notes_no_session() -> Response {
    refuse(
        StatusCode::FORBIDDEN,
        "notes.owner_session_required",
        "notes are one person's, and writing or reading them is that person's own act".into(),
    )
}

/// The owner, for a route that WRITES a file row. A delegated session is named
/// as such (`drive.delegate_may_not_author`) rather than folded into "no
/// session": the delegate IS signed in, and the remedy is the owner acting,
/// not signing in again.
#[allow(clippy::result_large_err)] // the Err IS an axum Response
async fn drive_author(
    st: &DriveState,
    headers: &HeaderMap,
) -> Result<crate::drive_auth::DriveOwner, Response> {
    match crate::drive_auth::owner_checked(st, headers).await {
        Ok(o) => Ok(o),
        Err(crate::drive_auth::OwnerRefusal::Delegated) => Err(refuse(
            StatusCode::FORBIDDEN,
            "drive.delegate_may_not_author",
            "a delegate may not write, change or withdraw a file: the row is signed into the \
             graph as the owner's own act, and a delegation that ends cannot un-sign it"
                .into(),
        )),
        Err(crate::drive_auth::OwnerRefusal::NoOwnerSession) => Err(drive_no_session()),
    }
}

/// [`drive_author`] for the notes plane.
#[allow(clippy::result_large_err)] // the Err IS an axum Response
async fn notes_author(
    st: &DriveState,
    headers: &HeaderMap,
) -> Result<crate::drive_auth::DriveOwner, Response> {
    match crate::drive_auth::owner_checked(st, headers).await {
        Ok(o) => Ok(o),
        Err(crate::drive_auth::OwnerRefusal::Delegated) => Err(refuse(
            StatusCode::FORBIDDEN,
            "notes.delegate_may_not_author",
            "a delegate may not write, change or withdraw a note: it is signed into the graph \
             as the owner's own words, and a delegation that ends cannot un-sign them"
                .into(),
        )),
        Err(crate::drive_auth::OwnerRefusal::NoOwnerSession) => Err(notes_no_session()),
    }
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
                "drive.family_id_required",
                "a family write must name `room_id` (the family's key id) — there is no \
                 default family, and guessing one would place bytes in a cohort nobody chose"
                    .into(),
            )
        }),
        Cohort::Community => room_id.map(ScopeRoom::community).ok_or_else(|| {
            refuse(
                StatusCode::BAD_REQUEST,
                "drive.community_id_required",
                "a community write must name `room_id` (the community's key id)".into(),
            )
        }),
    }
}

/// The room a per-file route's query names, membership-checked. Named, not
/// defaulted: a `_ => Community` arm once sent a typo'd cohort looking in a
/// community room and reported `not_in_room` — a refusal about the ROW for a
/// mistake in the QUESTION.
#[allow(clippy::result_large_err)] // the Err IS an axum Response
async fn room_from_query(
    st: &DriveState,
    owner: &str,
    q: &FileQuery,
) -> Result<(Cohort, ScopeRoom), Response> {
    let cohort = Cohort::parse(q.cohort.as_deref())
        .map_err(|e| refuse(StatusCode::BAD_REQUEST, "drive.unknown_cohort", e))?;
    let room = room_for(cohort, q.room_id.as_deref(), owner)?;
    require_cohort_member(st, owner, cohort, &room).await?;
    Ok((cohort, room))
}

/// **The id a caller can actually read the file back by.**
///
/// A crossing that WIDENS is two rows: the authored one (`self`, local tier —
/// the producer's own copy) and the `supersedes` row placed at the wider
/// audience, which has a NEW id. Edge says so in as many words on
/// `Shared::Placed`: "After a widening this is the NEW `supersedes` row's id,
/// not the one passed in."
///
/// Returning `published.row.attestation_id` therefore handed the caller an id
/// that names a row nobody else has. Measured on the chat ladder: `POST
/// /v1/files {cohort:"community"}` answered `file-f9d37acb…` while the row that
/// crossed was `e0d4dcdc-…`; reading back by the answered id was
/// `404 drive.not_in_room` on the recipient's node AND on the author's own,
/// because `file-f9d37acb…` is only the `self`-scoped copy. A client that
/// stores what the write returns could never open its own file.
///
/// `self` writes were unaffected — nothing widens — which is exactly why the
/// self-file ladder was green over this same code. One cohort exercised the
/// widening and the other did not.
fn readable_id(published: &files::PublishedFile) -> &str {
    placed_or(&published.shared, &published.row.attestation_id)
}

/// [`readable_id`] for any crossing: the placed row's id, or — when the
/// crossing parked awaiting its actor — the authored row, the only row there
/// is. `crossed: false` already tells the caller it reached nobody.
fn placed_or<'a>(
    shared: &'a ciris_edge::replication::attestation_bind::Shared,
    authored: &'a str,
) -> &'a str {
    use ciris_edge::replication::attestation_bind::Shared;
    match shared {
        Shared::Placed { attestation_id } | Shared::AlreadyThere { attestation_id } => {
            attestation_id
        }
        Shared::AwaitingActor { .. } => authored,
    }
}

/// **Does this owner belong to the cohort they named?** (Codex, CIRISServer#628)
///
/// `self` needs no check — the room IS the owner, and `room_for` derived it
/// from their own key rather than from anything they sent.
///
/// `family` / `community` do, and this was missing. A `room_id` is a
/// caller-supplied string, `files::in_room` (before edge v30) took no caller
/// identity and could not enforce membership itself, and a node that relays for a mesh holds
/// rows for cohorts its owner is not in. Without this, an authenticated owner
/// could name ANY locally-known room and read back filenames, authors,
/// timestamps and byte-availability from it — the metadata, even where the
/// bytes stay sealed. Owning the machine is not membership in the cohort;
/// that is the whole contextual-integrity line, and persist's §4.3 predicate
/// is where it is drawn for chat already (`contacts_chat::require_member`).
///
/// Applied to every family/community door: the write, the listing, the direct
/// read, and every change route — including a `move`'s TARGET.
#[allow(clippy::result_large_err)] // the Err IS an axum Response
async fn require_cohort_member(
    st: &DriveState,
    owner: &str,
    cohort: Cohort,
    room: &ScopeRoom,
) -> Result<(), Response> {
    let scope_token = match cohort {
        Cohort::SelfCollective => return Ok(()),
        Cohort::Family => ciris_persist::federation::types::cohort_scope::FAMILY,
        Cohort::Community => ciris_persist::federation::types::cohort_scope::COMMUNITY,
    };
    let group = room.content_group_id();
    let admission =
        match ciris_persist::scope::build_caller_admission(&st.engine, &owner.to_owned()).await {
            Ok(a) => a,
            Err(e) => {
                return Err(refuse(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "drive.store_unavailable",
                    format!("build_caller_admission: {e:#}"),
                ))
            }
        };
    let scope = ciris_persist::prelude::CallerScope::Authenticated { admission };
    // persist v47 (#893/#897): membership is the ROW's room against the caller's
    // rooms — `cohort_target`; `target` is only read on the self arm.
    if scope.admits(scope_token, owner, Some(group), None) {
        return Ok(());
    }
    Err(refuse(
        StatusCode::FORBIDDEN,
        "drive.not_a_member",
        format!(
            "this identity is not a member of {scope_token} {group:?} — owning the node that \
             relays a cohort's rows is not membership in it, and the listing would disclose \
             its filenames, authors and timestamps"
        ),
    ))
}

/// **Is this room actually addressable?** (Codex, CIRISServer#628)
///
/// A file can cross — the ROW is placed, `crossed: true` — while its BYTES
/// have nowhere to be fetched from, because no derived destination for the
/// room is installed in the scope-address table. The chat flow installs one
/// when it keys a room, which is exactly what masked this: the harness chats
/// first. A community reached without that flow, or reached after a restart,
/// seals a file whose bytes no recipient can pull.
///
/// This reports rather than repairs, and the distinction is deliberate.
/// INSTALLING a room needs its live MLS group, which lives in the chat
/// module's registry; reaching across for it here would put two owners on the
/// scope plane. What this does do is refuse to let the response say "crossed"
/// and mean "reachable" — `addressed` is its own field, and a `false` is
/// WARNed with the room named. The repair belongs with whoever owns the
/// group registry; tracked on CIRISServer#622.
fn addressed_or_warn(st: &DriveState, room: &ScopeRoom, cohort: Cohort) -> bool {
    if matches!(cohort, Cohort::SelfCollective) {
        // The self room's driver installs its own addresses each tick.
        return true;
    }
    let Some(life) = st.scope_lifecycle.as_ref() else {
        return false;
    };
    let installed = life
        .table()
        .live_epochs(&room.scope(), &room.table_group_id())
        .is_some();
    if !installed {
        tracing::warn!(
            room = %room,
            "drive: this room has NO derived destination in the scope-address table, so the \
             file's bytes cannot be fetched by anyone even though the row crosses. The room \
             is addressed when it is keyed (the chat flow does it); a community reached \
             without that, or after a restart, seals bytes nobody can pull"
        );
    }
    installed
}

/// Every room this identity can reach: their own devices, plus each family and
/// community persist's admission places them in.
///
/// Read off `CallerAdmission` rather than enumerated here, so the drive can
/// never list a cohort the caller is not admitted to — the same predicate
/// `require_cohort_member` applies to a NAMED room, applied to the unnamed
/// case by construction instead of by a second check that could drift.
#[allow(clippy::result_large_err)] // the Err IS an axum Response
async fn everything_reachable(
    st: &DriveState,
    owner: &str,
) -> Result<Vec<(Cohort, ScopeRoom)>, Response> {
    let mut out = vec![(Cohort::SelfCollective, ciris_edge::self_room::room(owner))];
    let admission =
        match ciris_persist::scope::build_caller_admission(&st.engine, &owner.to_owned()).await {
            Ok(a) => a,
            Err(e) => {
                return Err(refuse(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "drive.store_unavailable",
                    format!("build_caller_admission: {e:#}"),
                ))
            }
        };
    for fam in &admission.family_key_ids {
        out.push((Cohort::Family, ScopeRoom::family(fam.as_str())));
    }
    for com in &admission.community_key_ids {
        out.push((Cohort::Community, ScopeRoom::community(com.as_str())));
    }
    Ok(out)
}

fn store(engine: &Arc<Engine>) -> ciris_edge::group_content::PersistGroupContentStore {
    ciris_edge::group_content::PersistGroupContentStore::new(
        (**engine).clone(),
        engine.federation_directory(),
    )
}

/// **The key every file is opened AS** — the one this node's content-KEM
/// occurrence was provisioned under. See
/// [`crate::backend::content_occurrence_key_id`]: on an actor/node split that
/// is the WIRE node key, not `engine.local_derived_key_id()`, and opening as
/// the latter asked for a grant nothing was ever wrapped to.
async fn viewer_key(st: &DriveState) -> Result<String, String> {
    crate::backend::content_occurrence_key_id(&st.engine).await
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

// ─── Upload bodies: JSON or multipart ──────────────────────────────────────

/// One upload, whichever form carried it.
#[derive(Debug, Default)]
struct Upload {
    cohort: Option<String>,
    room_id: Option<String>,
    bytes: Vec<u8>,
    media_type: Option<String>,
    filename: Option<String>,
}

/// `drive.too_large` — the one sentence for "bigger than this node takes whole".
fn too_large(size: usize) -> Response {
    refuse(
        StatusCode::PAYLOAD_TOO_LARGE,
        "drive.too_large",
        format!(
            "{size} bytes exceeds this node's {WHOLE_READ_CAP}-byte file cap — the chunk-DAG \
             whole-read cap, above which a file could be stored but never read back whole"
        ),
    )
}

/// Parse an upload body: `application/json` ([`FileWriteRequest`]) or
/// `multipart/form-data` (fields `cohort`, `room_id`, `media_type`,
/// `filename`, and the bytes in a part named `file` — whose own filename and
/// `Content-Type` are used when the fields are absent).
#[allow(clippy::result_large_err)] // the Err IS an axum Response
fn parse_upload(
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Upload, Response> {
    let body = body.map_err(|rej| {
        if rej.status() == StatusCode::PAYLOAD_TOO_LARGE {
            too_large(UPLOAD_BODY_LIMIT)
        } else {
            bad_body(format!("read the request body: {rej}"))
        }
    })?;
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");
    let upload = if ct
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("multipart/form-data")
    {
        let boundary = multipart::boundary(ct).ok_or_else(|| {
            bad_body("multipart/form-data without a `boundary` parameter".to_owned())
        })?;
        let parts = multipart::parse(&body, &boundary).map_err(bad_body)?;
        let mut up = Upload::default();
        let mut saw_file = false;
        for p in parts {
            let text = || String::from_utf8(p.data.clone()).ok();
            match p.name.as_str() {
                "file" | "bytes" => {
                    saw_file = true;
                    if up.filename.is_none() {
                        up.filename = p.filename.clone();
                    }
                    if up.media_type.is_none() {
                        up.media_type = p.content_type.clone();
                    }
                    up.bytes = p.data;
                }
                "cohort" => up.cohort = text(),
                "room_id" => up.room_id = text(),
                // Explicit fields win over the part's own headers.
                "media_type" => up.media_type = text(),
                "filename" => up.filename = text(),
                _ => {}
            }
        }
        if !saw_file {
            return Err(bad_body(
                "multipart/form-data upload has no part named `file`".to_owned(),
            ));
        }
        up
    } else {
        let req: FileWriteRequest = serde_json::from_slice(&body)
            .map_err(|e| bad_body(format!("not a file-write JSON body: {e}")))?;
        let bytes = base64_decode(&req.bytes_base64)
            .map_err(|e| refuse(StatusCode::BAD_REQUEST, "drive.bad_base64", e))?;
        Upload {
            cohort: req.cohort.map(|c| {
                match c {
                    Cohort::SelfCollective => "self",
                    Cohort::Family => "family",
                    Cohort::Community => "community",
                }
                .to_owned()
            }),
            room_id: req.room_id,
            bytes,
            media_type: req.media_type,
            filename: req.filename,
        }
    };
    if upload.bytes.len() > WHOLE_READ_CAP {
        return Err(too_large(upload.bytes.len()));
    }
    Ok(upload)
}

fn bad_body(detail: String) -> Response {
    refuse(StatusCode::BAD_REQUEST, "drive.bad_body", detail)
}

/// A minimal `multipart/form-data` reader (RFC 7578) — enough for one upload
/// form, with no new dependency. Bounded by the route's body limit, so the
/// whole body is already in memory; this only slices it.
mod multipart {
    pub struct Part {
        pub name: String,
        pub filename: Option<String>,
        pub content_type: Option<String>,
        pub data: Vec<u8>,
    }

    /// The `boundary` parameter of a `multipart/form-data` content type.
    pub fn boundary(content_type: &str) -> Option<String> {
        content_type.split(';').skip(1).find_map(|param| {
            let (k, v) = param.split_once('=')?;
            if k.trim().eq_ignore_ascii_case("boundary") {
                let v = v.trim().trim_matches('"');
                (!v.is_empty()).then(|| v.to_owned())
            } else {
                None
            }
        })
    }

    fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
        if needle.is_empty() || from > hay.len() {
            return None;
        }
        hay[from..]
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|p| p + from)
    }

    /// A `Content-Disposition` parameter, quotes stripped.
    fn disposition_param(value: &str, key: &str) -> Option<String> {
        value.split(';').skip(1).find_map(|param| {
            let (k, v) = param.split_once('=')?;
            k.trim()
                .eq_ignore_ascii_case(key)
                .then(|| v.trim().trim_matches('"').to_owned())
        })
    }

    pub fn parse(body: &[u8], boundary: &str) -> Result<Vec<Part>, String> {
        let delim = format!("--{boundary}").into_bytes();
        let next_delim = format!("\r\n--{boundary}").into_bytes();
        let mut at = find(body, &delim, 0)
            .ok_or_else(|| "multipart body does not contain its boundary".to_owned())?
            + delim.len();
        let mut parts = Vec::new();
        loop {
            // After a delimiter: `--` closes the body, CRLF opens a part.
            if body[at..].starts_with(b"--") {
                return Ok(parts);
            }
            if !body[at..].starts_with(b"\r\n") {
                return Err("malformed multipart delimiter line".to_owned());
            }
            at += 2;
            let head_end = find(body, b"\r\n\r\n", at)
                .ok_or_else(|| "multipart part has no header terminator".to_owned())?;
            let head = std::str::from_utf8(&body[at..head_end])
                .map_err(|_| "multipart part headers are not UTF-8".to_owned())?;
            let (mut name, mut filename, mut content_type) = (None, None, None);
            for line in head.split("\r\n") {
                let Some((k, v)) = line.split_once(':') else {
                    continue;
                };
                if k.trim().eq_ignore_ascii_case("content-disposition") {
                    name = disposition_param(v, "name");
                    filename = disposition_param(v, "filename");
                } else if k.trim().eq_ignore_ascii_case("content-type") {
                    content_type = Some(v.trim().to_owned());
                }
            }
            let data_start = head_end + 4;
            let data_end = find(body, &next_delim, data_start)
                .ok_or_else(|| "multipart part is not closed by its boundary".to_owned())?;
            parts.push(Part {
                name: name.ok_or_else(|| "multipart part has no `name`".to_owned())?,
                filename,
                content_type,
                data: body[data_start..data_end].to_vec(),
            });
            at = data_end + next_delim.len();
        }
    }
}

// ─── Publishing, finding, and withdrawing rows ─────────────────────────────

/// Which plane a shared helper is speaking for — the ids differ, the act does not.
#[derive(Clone, Copy)]
enum Plane {
    Drive,
    Notes,
}

/// The owner's pen, or the refusal naming why this node cannot wield it.
#[allow(clippy::result_large_err)] // the Err IS an axum Response
async fn author_capsule(
    st: &DriveState,
    headers: &HeaderMap,
    owner_key_id: &str,
    plane: Plane,
) -> Result<crate::owner_signer_capsule::OwnerSignerCapsule, Response> {
    crate::owner_signer_capsule::acquire(
        &st.engine,
        bearer(headers),
        owner_key_id,
        st.user_seed_dir.clone(),
    )
    .await
    .map_err(|e| match plane {
        Plane::Drive => refuse(
            StatusCode::FORBIDDEN,
            "drive.author_signer_unavailable",
            format!(
                "a file is authored by the person, and this node cannot wield that identity: {e}"
            ),
        ),
        Plane::Notes => refuse(
            StatusCode::FORBIDDEN,
            "notes.author_signer_unavailable",
            format!("a note is authored by the person: {e}"),
        ),
    })
}

/// A new file row in `room`: seal, author, cross — edge's one door
/// (`files::publish`), with this server's reporting around it.
#[allow(clippy::result_large_err)] // the Err IS an axum Response
#[allow(clippy::too_many_arguments)]
async fn publish_into(
    st: &DriveState,
    headers: &HeaderMap,
    owner_key_id: &str,
    cohort: Cohort,
    room: &ScopeRoom,
    bytes: &[u8],
    media_type: &str,
    filename: Option<&str>,
    plane: Plane,
) -> Result<(files::PublishedFile, bool), Response> {
    // THE WRITE GATE (CIRISServer#642, CC 3.3.13 / CC 5.3.2.6): the node is the
    // first consumer of these bytes, and every peer inherits what this row
    // says they are. The declared type must be an RFC 6838 essence the leading
    // bytes agree with, and the name is display-only (RFC 6266 §4.3) — no path,
    // no control or bidi characters. Every write door comes through here.
    let essence = match crate::media_gate::check_format(media_type, bytes) {
        Ok(e) => e,
        Err(crate::media_gate::TypeRefusal::BadEssence(d)) => {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "drive.bad_media_type",
                format!("{d:?} is not an RFC 6838 media type (type/subtype)"),
            ))
        }
        Err(crate::media_gate::TypeRefusal::Mismatch { declared, sniffed }) => {
            return Err(refuse_with(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "drive.format_mismatch",
                format!(
                    "declared {declared}, but the bytes are {sniffed} — a file must be what it \
                     says it is (CC 5.3.2.6)"
                ),
                serde_json::json!({ "declared": declared, "sniffed": sniffed }),
            ))
        }
    };
    let clean_name = match filename {
        None => None,
        Some(raw) => match crate::media_gate::sanitize_filename(raw) {
            Some((n, _)) => Some(n),
            None => {
                return Err(refuse(
                    StatusCode::BAD_REQUEST,
                    "drive.bad_filename",
                    "nothing displayable is left of that filename once path components and \
                     control / bidi characters are removed (RFC 6266 §4.3)"
                        .into(),
                ))
            }
        },
    };
    let media_type = essence.as_str();
    let filename = clean_name.as_deref();
    ensure_owner_is_a_kem_target(st, owner_key_id).await;
    let addressed = addressed_or_warn(st, room, cohort);
    let capsule = author_capsule(st, headers, owner_key_id, plane).await?;
    let dir = st.engine.federation_directory();
    let content = store(&st.engine);
    let published = files::publish(
        &*dir,
        &content,
        ciris_edge::replication::attestation_bind::Signers {
            node: &st.node_signer,
            actor: Some(capsule.edge_signer()),
        },
        &FileWrite {
            room,
            bytes,
            media_type,
            filename,
            asserted_at: chrono::Utc::now(),
        },
    )
    .await
    .map_err(|e| file_error(&e, room))?;
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
    Ok((published, addressed))
}

fn write_response(
    published: &files::PublishedFile,
    addressed: bool,
    room: &ScopeRoom,
    replaces: Option<String>,
    withdrawn: Vec<String>,
) -> FileWriteResponse {
    FileWriteResponse {
        attestation_id: readable_id(published).to_owned(),
        addressed,
        cohort: room.row_scope_token().to_owned(),
        room: room.to_string(),
        tier: format!("{:?}", published.tier),
        crossed: published.crossed,
        excluded: published.excluded.clone(),
        granted: published.granted.len(),
        replaces,
        withdrawn,
    }
}

/// One file row as a route found it: edge's reading of it, and the row itself.
struct Found {
    file: files::FileRow,
    row: Attestation,
    /// The `withdraws` that retired it, if one did.
    withdrawn_by: Option<String>,
}

/// Find `attestation_id` among `room`'s file rows, as `owner` sees them.
///
/// Through edge's GATED reader (`files::in_room`, persist's §4.3 predicate in
/// the same query), walking `resume` until the row or the end of the room — so
/// a valid id past the first page is found, not reported missing (Codex,
/// CIRISServer#628). Withdrawn rows are FOUND (persist's `list_attestations`
/// does not apply the lifecycle axis), and reported as such by the caller.
#[allow(clippy::result_large_err)] // the Err IS an axum Response
async fn find_file(
    st: &DriveState,
    owner: &str,
    room: &ScopeRoom,
    attestation_id: &str,
    plane: Plane,
) -> Result<Found, Response> {
    let listing_failed = |e: String| match plane {
        Plane::Drive => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "drive.listing_failed",
            format!("list {room}: {e}"),
        ),
        Plane::Notes => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "notes.listing_failed",
            format!("read your self room: {e}"),
        ),
    };
    let mut after = None;
    loop {
        // NOT an empty room on error (Codex, CIRISServer#628): a directory or
        // store outage is "ask again shortly", never "your file is gone".
        let page = files::in_room(&st.engine, room, owner, usize::MAX, after)
            .await
            .map_err(|e| listing_failed(format!("{e:#}")))?;
        if let Some(file) = page
            .files
            .into_iter()
            .find(|r| r.attestation_id == attestation_id)
        {
            let dir = st.engine.federation_directory();
            let row = dir
                .get_attestation(attestation_id)
                .await
                .map_err(|e| listing_failed(format!("read row {attestation_id}: {e:#}")))?
                .ok_or_else(|| listing_failed(format!("row {attestation_id} vanished")))?;
            let withdrawn_by = withdrawn_by(st, attestation_id)
                .await
                .map_err(listing_failed)?;
            return Ok(Found {
                file,
                row,
                withdrawn_by,
            });
        }
        match page.resume {
            Some(c) => after = Some(c),
            None => {
                return Err(match plane {
                    Plane::Drive => refuse(
                        StatusCode::NOT_FOUND,
                        "drive.not_in_room",
                        format!("{attestation_id} is not a file row in {room}"),
                    ),
                    Plane::Notes => refuse(
                        StatusCode::NOT_FOUND,
                        "notes.not_found",
                        format!("{attestation_id} is not one of your notes"),
                    ),
                })
            }
        }
    }
}

/// **Has a `withdraws` retired this row?** The id of the one that did.
///
/// Re-derives each retraction's authority NOW with persist's own
/// `check_withdraws_admission`, never trusting the stored rule — the same
/// discipline `blob_tombstone::binding_state` applies at the bytes plane, one
/// row instead of every row binding a sha. (Persist's per-row fold,
/// `retiring_composer`, is private; this is its withdraws arm, and the only
/// predicate it contains is persist's.) A `withdraws` whose authority does not
/// re-derive retires nothing — replication must not become a remote delete.
async fn withdrawn_by(st: &DriveState, attestation_id: &str) -> Result<Option<String>, String> {
    use ciris_persist::federation::types::attestation_type::WITHDRAWS;
    let dir = st.engine.federation_directory();
    let refs = dir
        .list_attestations_referencing(attestation_id)
        .await
        .map_err(|e| format!("composers naming {attestation_id}: {e:#}"))?;
    for g in refs {
        if g.attestation_type != WITHDRAWS {
            continue;
        }
        match ciris_persist::federation::admission::check_withdraws_admission(&*dir, &g).await {
            Ok(Some(_)) => return Ok(Some(g.attestation_id)),
            Ok(None) | Err(ciris_persist::federation::Error::WithdrawsNotAdmitted { .. }) => {}
            Err(e) => return Err(format!("re-derive {}: {e:#}", g.attestation_id)),
        }
    }
    Ok(None)
}

/// **Only the author changes a file.** See the module docs: the author is the
/// row's attester, and this node can sign a rule-1 `withdraws` for exactly the
/// rows its own key attested.
#[allow(clippy::result_large_err)] // the Err IS an axum Response
fn require_author(st: &DriveState, row: &Attestation) -> Result<(), Response> {
    if row.attesting_key_id == st.node_signer.key_id {
        return Ok(());
    }
    Err(refuse(
        StatusCode::FORBIDDEN,
        "drive.not_author",
        format!(
            "only the author may change or withdraw a file, and this row was written by {} — \
             a change is a new claim only its author can sign. A file you wrote on another of \
             your devices is changed from that device",
            row.attesting_key_id
        ),
    ))
}

/// The pointer's at-rest sha, as bytes.
fn sha_of(file: &files::FileRow) -> Option<[u8; 32]> {
    hex::decode(&file.pointer.content_sha256)
        .ok()
        .and_then(|v| v.try_into().ok())
}

/// What `withdraw_rows` did.
struct Withdrawal {
    withdrawn: Vec<String>,
    evicted: bool,
}

/// **Withdraw a file row, and the rows its widening superseded.**
///
/// A cohort file is two rows (see [`readable_id`]): the authored `self` row
/// and the `supersedes` placed at the room. Persist refuses a read of bytes
/// only when EVERY row binding them is retired (`blob_tombstone`), so the
/// listed row alone is not enough — the chain it supersedes, back to the
/// authored row, is withdrawn with it. Each by edge's own producer
/// (`withdraws_attestation`, persist's envelope builder, bound-hybrid signed)
/// with this node's key: rule 1, the attester's own retraction.
///
/// Then, if nothing live binds the bytes any more, the local copy goes
/// (`Engine::evict_blob`, which first retracts this node's `holds_bytes`
/// claims). A rename's bytes stay bound by the new row, so they are kept.
async fn withdraw_rows(
    st: &DriveState,
    listed: &Attestation,
    file: &files::FileRow,
    reason: &str,
) -> Result<Withdrawal, String> {
    use ciris_persist::federation::types::attestation_type::SUPERSEDES;
    let dir = st.engine.federation_directory();
    let mut chain = vec![listed.clone()];
    let mut cur = listed.clone();
    // Bounded: a widening chain is one hop per audience step, and there are
    // four audiences a file row can be widened through.
    while cur.attestation_type == SUPERSEDES && chain.len() < 8 {
        let Some(prior_id) =
            ciris_persist::federation::precedence::references_attestation_id_from_envelope(
                &cur.attestation_envelope,
            )
            .map(str::to_owned)
        else {
            break;
        };
        let Some(prior) = dir
            .get_attestation(&prior_id)
            .await
            .map_err(|e| format!("read prior {prior_id}: {e:#}"))?
        else {
            break;
        };
        if prior.attesting_key_id != st.node_signer.key_id {
            break;
        }
        chain.push(prior.clone());
        cur = prior;
    }
    let now = chrono::Utc::now();
    let mut withdrawn = Vec::new();
    for row in &chain {
        if withdrawn_by(st, &row.attestation_id).await?.is_some() {
            continue;
        }
        let w = ciris_edge::replication::attestation_bind::withdraws_attestation(
            row,
            reason,
            now,
            &st.node_signer,
        )
        .await
        .map_err(|e| format!("build withdraws for {}: {e}", row.attestation_id))?;
        dir.put_attestation_authored(ciris_persist::federation::SignedAttestation {
            attestation: w,
        })
        .await
        .map_err(|e| format!("admit withdraws for {}: {e:#}", row.attestation_id))?;
        withdrawn.push(row.attestation_id.clone());
    }
    crate::compose::kick_replication("file row withdrawn");

    let mut evicted = false;
    if let Some(sha) = sha_of(file) {
        use ciris_persist::federation::blob_tombstone::{binding_state, BindingState};
        match binding_state(&*dir, &sha).await {
            Ok(BindingState::Withdrawn { .. }) => match st.engine.evict_blob(&sha, now).await {
                Ok(report) => evicted = report.blob_deleted,
                // Not fatal: the rows are withdrawn and persist already refuses
                // every read of these bytes (CC 2.3). The copy is swept later.
                Err(e) => tracing::warn!(
                    sha = %file.pointer.content_sha256, error = %e,
                    "drive: the file is withdrawn but its local copy could not be evicted \
                     now — reads are refused regardless; the sweep will retry"
                ),
            },
            Ok(BindingState::Live) | Ok(BindingState::Unbound) => {}
            Err(e) => tracing::warn!(
                sha = %file.pointer.content_sha256, error = %e,
                "drive: could not fold the bytes' binding state after a withdrawal — the \
                 local copy is kept until the sweep decides"
            ),
        }
    }
    Ok(Withdrawal { withdrawn, evicted })
}

fn withdraw_failed(detail: String) -> Response {
    refuse(
        StatusCode::INTERNAL_SERVER_ERROR,
        "drive.withdraw_failed",
        detail,
    )
}

/// **A rename: a new row over the SAME bytes.**
///
/// No re-seal and no re-upload: the new row cites the old pointer. That is only
/// possible because the seal's associated data is `(author, asserted_at,
/// field)` read off the ROW (`group_content::aad_for_open`), so the new row
/// carries the old row's author and instant verbatim — the claim's instant,
/// exactly as a widening carries it (persist v40.0.0) — and the bytes open
/// under it. Everything else is `files::publish`'s row shape: the file
/// dimension, the pointer under `content`, the room's cohort target, the sha
/// cited in `evidence_refs`, authored at `self` / local tier for the crossing
/// to place.
///
/// Built here because edge's file door takes BYTES, not a pointer (upstream
/// ask: a `files::republish(pointer, ..)`); the row shape above is edge's, and
/// `rename_keeps_the_blob_and_the_bytes_open` in `tests/drive_crud.rs` is what
/// fails if the two drift.
async fn rename_row(
    author: &ciris_edge::identity::LocalSigner,
    room: &ScopeRoom,
    old: &files::FileRow,
    filename: &str,
    replaces: &str,
) -> Result<Attestation, String> {
    use ciris_edge::replication::attestation_bind::{
        bind_attestation_envelope, render_signed_instant, AttestationColumns,
    };
    use ciris_persist::federation::types::{attestation_tier, cohort_scope};
    use sha2::{Digest as _, Sha256};

    let author_key_id = author.key_id.as_str();
    let asserted_at = old.asserted_at;
    let mut envelope = serde_json::json!({
        (ciris_persist::federation::envelope::paths::DIMENSION): files::FILE_DIMENSION,
        (ciris_edge::chat::FIELD_CONTENT): old.pointer,
        (files::FIELD_FILENAME): filename,
        (FIELD_REPLACES): replaces,
        "evidence_refs": [old.pointer.content_sha256],
    });
    if let Some(field) = room.cohort_target_field() {
        envelope[field] = serde_json::json!(room.content_group_id());
    }
    let attestation_id = {
        let mut h = Sha256::new();
        h.update(files::FILE_DIMENSION.as_bytes());
        h.update(b"\0rename\0");
        h.update(room.table_group_id().as_bytes());
        h.update(author_key_id.as_bytes());
        h.update(render_signed_instant(asserted_at).as_bytes());
        h.update(
            ciris_persist::prelude::ceg_produce_canonicalize(&envelope)
                .map_err(|e| format!("canonicalize: {e}"))?,
        );
        format!("file-{}", &hex::encode(h.finalize())[..32])
    };
    let subjects = vec![author_key_id.to_owned()];
    bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: author_key_id,
            attestation_type: "scores",
            attested_key_id: author_key_id,
            subject_key_ids: &subjects,
            cohort_scope: cohort_scope::SELF,
            weight: None,
        },
    );
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope)
        .map_err(|e| format!("canonicalize: {e}"))?;
    let digest = Sha256::digest(&canonical);
    let (sig_classical, sig_pqc) =
        ciris_edge::identity::sign_bound_hybrid(author, &canonical, files::FILE_DIMENSION).await?;
    Ok(Attestation {
        attestation_id,
        attesting_key_id: author_key_id.to_owned(),
        attested_key_id: author_key_id.to_owned(),
        attestation_type: "scores".to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig_classical,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: author_key_id.to_owned(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: subjects,
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::SELF.to_owned(),
        tier: attestation_tier::LOCAL.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    })
}

// ─── Byte state: typed, never parsed out of a Debug string ─────────────────

/// Where a row's bytes stand on this node.
enum ByteState {
    /// Authorized, not withdrawn, held. `size` is the PLAINTEXT length.
    Here { size: Option<u64> },
    /// Not openable here, and why — a state token and its plain words.
    Absent { state: &'static str, detail: String },
}

/// The plain words for a state token. One sentence per state, so the drive,
/// the metadata route and the refusals say the same thing.
fn state_detail(state: &str) -> &'static str {
    match state {
        "not_fetched" => "on another device — the row is here, its bytes have not been pulled yet",
        "not_granted" => "this device's key does not open it — it holds no grant for these bytes",
        "withdrawn" => "withdrawn by its author — the bytes are no longer served anywhere",
        "evicted" => "these bytes were swept from this node and cannot be read here again",
        "seal_mismatch" => "the bytes did not open under this row — the row and the bytes disagree",
        _ => "the bytes could not be opened on this node",
    }
}

/// A typed persist refusal → the drive's state token. Every arm is a VARIANT,
/// never a message: a reword upstream cannot move a file between states.
fn blob_state(e: &BlobError) -> ByteState {
    let state = match e {
        BlobError::NotHeld { .. } => "not_fetched",
        BlobError::NotGranted { .. } | BlobError::NotPartyTo { .. } => "not_granted",
        BlobError::Withdrawn { .. } => "withdrawn",
        BlobError::Evicted { .. } => "evicted",
        BlobError::SealDidNotOpen { .. } => "seal_mismatch",
        _ => "substrate",
    };
    ByteState::Absent {
        state,
        detail: if state == "substrate" {
            format!("{}: {e}", state_detail(state))
        } else {
            state_detail(state).to_owned()
        },
    }
}

/// Edge's typed reason → the same tokens, through `UnopenedReason::kind()` (the
/// arm's stable label), never its `Debug` rendering. Edge maps persist's
/// `Withdrawn` into `substrate` (CIRISEdge `group_content/persist_store.rs`
/// `map_err`'s catch-all), which is why every read here checks the ROW's
/// withdrawal BEFORE it opens anything.
fn unopened(reason: &ciris_edge::chat::UnopenedReason) -> ByteState {
    let state = reason.kind();
    ByteState::Absent {
        state,
        detail: match state {
            "not_fetched" | "not_granted" | "evicted" | "seal_mismatch" => {
                state_detail(state).to_owned()
            }
            _ => format!("{}: {reason}", state_detail(state)),
        },
    }
}

/// The associated data the bytes were sealed under, rebuilt from the ROW with
/// edge's own `aad_for_open` — `None` at the plaintext tier, which persist
/// refuses AAD against (the same rule `PersistGroupContentStore::open` applies).
fn aad_for(file: &files::FileRow) -> Option<Vec<u8>> {
    use ciris_persist::federation::types::cohort_scope::CryptoTier;
    match file.pointer.tier {
        CryptoTier::Plaintext => None,
        CryptoTier::InvisibleEncrypted | CryptoTier::CommunityDek => Some(
            ciris_edge::group_content::aad_for_open(&ciris_edge::group_content::OpenRequest {
                pointer: &file.pointer,
                author_key_id: &file.attesting_key_id,
                asserted_at: file.asserted_at,
                viewer_key_id: "",
            }),
        ),
    }
}

/// **Byte state WITHOUT opening the bytes.**
///
/// The drive used to `open` — decrypt in full — every listed file to report
/// "here". Persist offers no public "may this viewer read, without reading"
/// door (its `authorize_viewer_by_tier` is `pub(crate)`), so this asks the one
/// public door that runs that predicate and then stops before the body: a
/// RANGE read starting past any possible end. Persist's range door authorizes
/// by tier, refuses a withdrawn sha, and then answers `RangeNotSatisfiable`
/// naming the PLAINTEXT size — from the row's columns for an inline blob (no
/// decryption at all) and from the manifest for a chunk DAG (one small open,
/// never a chunk). So one call yields presence, grant, withdrawal AND size.
async fn probe(st: &DriveState, file: &files::FileRow, viewer: &str) -> ByteState {
    let Some(sha) = sha_of(file) else {
        return ByteState::Absent {
            state: "malformed_row",
            detail: format!(
                "{}: the row's pointer is not a sha-256",
                state_detail("malformed_row")
            ),
        };
    };
    let aad = aad_for(file);
    let past_the_end = u64::MAX - 1;
    match st
        .engine
        .read_blob_range_as(&sha, viewer, past_the_end, past_the_end, aad.as_deref())
        .await
    {
        Err(BlobError::RangeNotSatisfiable { size, .. }) => ByteState::Here { size: Some(size) },
        Ok(_) => ByteState::Here { size: None },
        Err(e) => blob_state(&e),
    }
}

/// The refusal for a byte state — status and id chosen TOGETHER, both literal
/// (the localization guard reads ids from an emitter's argument position; an
/// id assembled from the token would be invisible to it).
fn refuse_state(state: &str, detail: String) -> Response {
    match state {
        // NOT an error status for `not_fetched`: the row is legitimately here
        // and the bytes legitimately are not. 409 says "ask again".
        "not_fetched" => refuse(StatusCode::CONFLICT, "drive.not_fetched", detail),
        "not_granted" => refuse(StatusCode::FORBIDDEN, "drive.not_granted", detail),
        "withdrawn" => refuse(StatusCode::GONE, "drive.withdrawn", detail),
        "evicted" => refuse(StatusCode::GONE, "drive.evicted", detail),
        "seal_mismatch" => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "drive.seal_mismatch",
            detail,
        ),
        _ => refuse(StatusCode::INTERNAL_SERVER_ERROR, "drive.unopened", detail),
    }
}

fn row_withdrawn_refusal(withdraws_id: &str) -> Response {
    refuse_state(
        "withdrawn",
        format!("{} ({withdraws_id})", state_detail("withdrawn")),
    )
}

fn too_large_for_whole_read(size: u64) -> Response {
    refuse(
        StatusCode::PAYLOAD_TOO_LARGE,
        "drive.too_large_for_whole_read",
        format!(
            "this file is {size} bytes, above the {WHOLE_READ_CAP}-byte whole-read cap — read \
             it with `?raw=1` and an HTTP `Range` header"
        ),
    )
}

/// The whole plaintext, after the state and size checks a whole read owes.
#[allow(clippy::result_large_err)] // the Err IS an axum Response
async fn open_whole(
    st: &DriveState,
    found: &Found,
    viewer: &str,
) -> Result<(Vec<u8>, Option<u64>), Response> {
    if let Some(w) = &found.withdrawn_by {
        return Err(row_withdrawn_refusal(w));
    }
    let size = match probe(st, &found.file, viewer).await {
        ByteState::Here { size } => size,
        ByteState::Absent { state, detail } => return Err(refuse_state(state, detail)),
    };
    if let Some(n) = size.filter(|n| *n > WHOLE_READ_CAP as u64) {
        return Err(too_large_for_whole_read(n));
    }
    let content = store(&st.engine);
    match found.file.open(&content, viewer).await {
        Ok(b) => Ok((b, size)),
        Err(reason) => match unopened(&reason) {
            ByteState::Absent { state, detail } => Err(refuse_state(state, detail)),
            ByteState::Here { .. } => unreachable!("unopened always answers Absent"),
        },
    }
}

/// The row's CEG envelope, as a client's receipt sheet renders it (CSD-006,
/// CIRISServer#616): who it is about, who signed it, who can see it, what it
/// is. Read off the row, never inferred. A file row rides the producer's own
/// authority, not a consent grant, so `consent_scope` is whatever the row
/// declares — `null` for every row edge's file door writes today.
fn envelope_of(row: &Attestation) -> serde_json::Value {
    let env = &row.attestation_envelope;
    let target = ["family_key_id", "community_key_id"]
        .iter()
        .find_map(|k| env.get(*k).and_then(serde_json::Value::as_str));
    serde_json::json!({
        "attestation_id": row.attestation_id,
        "attestation_type": row.attestation_type,
        "attesting_key_id": row.attesting_key_id,
        "attested_key_id": row.attested_key_id,
        "subject_key_ids": row.subject_key_ids,
        "cohort_scope": row.cohort_scope,
        "cohort_target": target,
        (ciris_persist::federation::envelope::paths::DIMENSION): ciris_persist::federation::admission::envelope_dimension(env),
        "tier": row.tier,
        "consent_scope": env.get("consent_scope"),
        "asserted_at": row.asserted_at.to_rfc3339(),
    })
}

fn replaces_of(row: &Attestation) -> Option<String> {
    row.attestation_envelope
        .get(FIELD_REPLACES)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

// ─── Routes ────────────────────────────────────────────────────────────────

/// `POST /v1/files` — write a file at a chosen cohort. JSON or multipart.
async fn write_file(
    State(st): State<DriveState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let owner = match drive_author(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    // DECLARED-CONFORMANCE GATE, ahead of the membership read (Codex,
    // CIRISServer#628). A file published into a cohort room is a
    // federation-wire production exactly as a chat message is, so a node
    // declared consumer-only must not author one — `contacts_chat` gates its
    // author door on the same verb, and a producer that skipped it would make
    // the declaration a statement the node does not keep.
    //
    // ORDER IS LOAD-BEARING, for the same reason it is in chat: this is a pure
    // function of the node's OWN declaration, so answering it first cannot
    // leak whether a cohort exists here, where the membership check below
    // necessarily touches the directory.
    if let Some(resp) =
        crate::conformance::require_op(&st.engine, crate::auth::gate::CapabilityVerb::ChatAuthor)
            .await
    {
        return resp;
    }
    let up = match parse_upload(&headers, body) {
        Ok(u) => u,
        Err(e) => return e,
    };
    let Some(cohort_token) = up.cohort.as_deref() else {
        return bad_body(
            "an upload must name its `cohort` (self | family | community) — there is no default \
             audience for a file"
                .to_owned(),
        );
    };
    let cohort = match Cohort::parse(Some(cohort_token)) {
        Ok(c) => c,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, "drive.unknown_cohort", e),
    };
    let room = match room_for(cohort, up.room_id.as_deref(), &owner.key_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if let Err(e) = require_cohort_member(&st, &owner.key_id, cohort, &room).await {
        return e;
    }
    let media_type = up
        .media_type
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    match publish_into(
        &st,
        &headers,
        &owner.key_id,
        cohort,
        &room,
        &up.bytes,
        &media_type,
        up.filename.as_deref(),
        Plane::Drive,
    )
    .await
    {
        Ok((published, addressed)) => (
            StatusCode::OK,
            Json(write_response(&published, addressed, &room, None, vec![])),
        )
            .into_response(),
        Err(e) => e,
    }
}

/// The drive's resume cursor: which room, and where in it. Opaque to clients
/// (base64url JSON); the persist cursor inside is persist's own, never minted
/// here — a cursor this server built would be a second spelling of persist's
/// ordering.
#[derive(Debug, Serialize, Deserialize)]
struct DriveCursor {
    room: String,
    #[serde(default)]
    at: Option<ciris_persist::ceg::AttestationCursor>,
}

fn room_key(room: &ScopeRoom) -> String {
    format!("{}:{}", room.row_scope_token(), room.content_group_id())
}

fn encode_cursor(c: &DriveCursor) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(c).unwrap_or_default())
}

fn decode_cursor(s: &str) -> Option<DriveCursor> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim())
        .ok()?;
    serde_json::from_slice(&raw).ok()
}

/// `GET /v1/drive` — everything this identity can reach, with the bytes' state
/// named per row, a page at a time.
async fn read_drive(
    State(st): State<DriveState>,
    headers: HeaderMap,
    Query(q): Query<DriveQuery>,
) -> Response {
    let Some(owner) = crate::drive_auth::owner(&st, &headers).await else {
        return drive_no_session();
    };
    // NO FILTER MEANS THE WHOLE DRIVE. This route is "everything this identity
    // can reach", and converting an absent `cohort` to `self` made it "your
    // own devices" while still calling itself a drive — every family and
    // community file silently missing, with a 200 (Codex, CIRISServer#628).
    // The cohorts are not guessed: they are the ones persist's own admission
    // says this caller is in, so the listing cannot reach past membership.
    let rooms: Vec<(Cohort, ScopeRoom)> = match q.cohort.as_deref() {
        Some("self") => vec![(
            Cohort::SelfCollective,
            ciris_edge::self_room::room(&owner.key_id),
        )],
        Some("family") | Some("community") => {
            let cohort = if q.cohort.as_deref() == Some("family") {
                Cohort::Family
            } else {
                Cohort::Community
            };
            let room = match room_for(cohort, q.room_id.as_deref(), &owner.key_id) {
                Ok(r) => r,
                Err(e) => return e,
            };
            if let Err(e) = require_cohort_member(&st, &owner.key_id, cohort, &room).await {
                return e;
            }
            vec![(cohort, room)]
        }
        Some(other) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "drive.unknown_cohort",
                format!("unknown cohort {other:?} — use self | family | community"),
            )
        }
        None => match everything_reachable(&st, &owner.key_id).await {
            Ok(v) => v,
            Err(e) => return e,
        },
    };
    let include_withdrawn = truthy(q.include_withdrawn.as_deref());
    // CLAMPED, not refused: "everything" is a page and a `resume`.
    let limit = q.limit.clamp(1, MAX_PAGE);
    // Where to start: the room the cursor names, at the cursor's place in it.
    let (start, mut start_at) =
        match q.after.as_deref() {
            None => (0, None),
            Some(s) => {
                let Some(c) = decode_cursor(s) else {
                    return refuse(
                        StatusCode::BAD_REQUEST,
                        "drive.bad_cursor",
                        "`after` is not a cursor this drive issued — pass back a page's `resume` \
                     verbatim"
                            .into(),
                    );
                };
                match rooms.iter().position(|(_, r)| room_key(r) == c.room) {
                    Some(i) => (i, c.at),
                    None => return refuse(
                        StatusCode::BAD_REQUEST,
                        "drive.bad_cursor",
                        "`after` is not a cursor this drive issued — pass back a page's `resume` \
                         verbatim"
                            .into(),
                    ),
                }
            }
        };
    // THE LIMIT IS A BUDGET ACROSS THE WHOLE DRIVE, not per room (Codex,
    // CIRISServer#628) — and it counts rows READ, withdrawn ones included, so
    // the work per page is bounded even when most of a room is withdrawn.
    let mut rows: Vec<(String, String, files::FileRow)> = Vec::new();
    let mut read = 0usize;
    let mut resume: Option<DriveCursor> = None;
    for (idx, (_, room)) in rooms.iter().enumerate().skip(start) {
        let remaining = limit.saturating_sub(read);
        if remaining == 0 {
            resume = Some(DriveCursor {
                room: room_key(room),
                at: None,
            });
            break;
        }
        let after = if idx == start { start_at.take() } else { None };
        // edge v30 (CIRISEdge#656/#657): the drive read is persist's GATED
        // reader door — the caller is named and the substrate composes the
        // §4.3 predicate in the same query; a page, not an iterator.
        match files::in_room(&st.engine, room, &owner.key_id, remaining, after).await {
            Ok(page) => {
                read += page.files.len();
                rows.extend(page.files.into_iter().map(|row| {
                    (
                        room.row_scope_token().to_owned(),
                        room.content_group_id().to_owned(),
                        row,
                    )
                }));
                if let Some(c) = page.resume {
                    resume = Some(DriveCursor {
                        room: room_key(room),
                        at: Some(c),
                    });
                    break;
                }
            }
            Err(e) => {
                return refuse(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "drive.listing_failed",
                    format!("list {room}: {e:#}"),
                )
            }
        }
    }
    let viewer = match viewer_key(&st).await {
        Ok(v) => v,
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "drive.no_node_key",
                format!("resolve this node's key: {e}"),
            )
        }
    };
    let dir = st.engine.federation_directory();
    let mut out = Vec::with_capacity(rows.len());
    for (cohort, room_id, file) in rows {
        let withdrawn = match withdrawn_by(&st, &file.attestation_id).await {
            Ok(w) => w,
            Err(e) => {
                return refuse(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "drive.listing_failed",
                    format!("list {room_id}: {e}"),
                )
            }
        };
        if withdrawn.is_some() && !include_withdrawn {
            continue;
        }
        // Presence, grant and size WITHOUT decrypting the file — see `probe`.
        let (bytes, detail, size) = if withdrawn.is_some() {
            (
                "withdrawn".to_owned(),
                state_detail("withdrawn").to_owned(),
                None,
            )
        } else {
            match probe(&st, &file, &viewer).await {
                ByteState::Here { size } => (
                    BYTE_STATE_HERE.to_owned(),
                    "the bytes are on this device".to_owned(),
                    size,
                ),
                ByteState::Absent { state, detail } => (state.to_owned(), detail, None),
            }
        };
        let row = dir
            .get_attestation(&file.attestation_id)
            .await
            .ok()
            .flatten();
        out.push(DriveEntry {
            // THE ROOM THIS ROW CAME FROM. An unfiltered drive concatenates
            // several rooms, and `GET /v1/files/{id}` needs the right `cohort`
            // and `room_id` or it defaults to `self` and misses (Codex,
            // CIRISServer#628).
            cohort,
            room_id,
            attestation_id: file.attestation_id.clone(),
            author_key_id: file.attesting_key_id.clone(),
            asserted_at: file.asserted_at.to_rfc3339(),
            filename: file.filename.clone(),
            media_type: file.media_type.clone(),
            bytes,
            detail,
            size,
            withdrawn: withdrawn.is_some(),
            replaces: row.as_ref().and_then(replaces_of),
            envelope: row
                .as_ref()
                .map(envelope_of)
                .unwrap_or(serde_json::Value::Null),
        });
    }
    // The ROOMS listed, not "the room" — an unfiltered drive spans several, and
    // reporting one would name whichever happened to be first.
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "rooms": rooms
                .iter()
                .map(|(_, r)| serde_json::json!({
                    "cohort": r.row_scope_token(),
                    "room": r.to_string(),
                }))
                .collect::<Vec<_>>(),
            "entries": out,
            "limit": limit,
            // `null` means the drive is exhausted; anything else is passed back
            // as `after` for the next page.
            "resume": resume.as_ref().map(encode_cursor),
        })),
    )
        .into_response()
}

/// `GET /v1/files/{attestation_id}/meta` — everything about a file except its
/// bytes, without opening them.
async fn file_meta(
    State(st): State<DriveState>,
    headers: HeaderMap,
    Path(attestation_id): Path<String>,
    Query(q): Query<FileQuery>,
) -> Response {
    let Some(owner) = crate::drive_auth::owner(&st, &headers).await else {
        return drive_no_session();
    };
    let (_, room) = match room_from_query(&st, &owner.key_id, &q).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    let found = match find_file(&st, &owner.key_id, &room, &attestation_id, Plane::Drive).await {
        Ok(f) => f,
        Err(e) => return e,
    };
    let viewer = match viewer_key(&st).await {
        Ok(v) => v,
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "drive.no_node_key",
                format!("resolve this node's key: {e}"),
            )
        }
    };
    let (bytes, detail, size) = if found.withdrawn_by.is_some() {
        (
            "withdrawn".to_owned(),
            state_detail("withdrawn").to_owned(),
            None,
        )
    } else {
        match probe(&st, &found.file, &viewer).await {
            ByteState::Here { size } => (
                BYTE_STATE_HERE.to_owned(),
                "the bytes are on this device".to_owned(),
                size,
            ),
            ByteState::Absent { state, detail } => (state.to_owned(), detail, None),
        }
    };
    // The plaintext digest costs a whole read, so it is computed only here and
    // on open — never per listed row — and only when the bytes are here.
    let content_digest = if bytes == BYTE_STATE_HERE {
        match open_whole(&st, &found, &viewer).await {
            Ok((plain, _)) => Some(plaintext_digest(&plain)),
            Err(_) => None,
        }
    } else {
        None
    };
    // HOLDER CLAIMS: CC 5.2 — `self` / `family` bytes are never advertised, so
    // the substrate records no holder there and the count is not a count of
    // devices. Said as such (`holder_claims_recorded: false`) rather than a
    // bare 0 a client would render as "nobody has it".
    let recorded =
        room.row_scope_token() == ciris_persist::federation::types::cohort_scope::COMMUNITY;
    let devices_holding = match (recorded, sha_of(&found.file)) {
        (true, Some(sha)) => crate::backend::blob_holder_count(&st.engine, &sha)
            .await
            .ok(),
        _ => None,
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "attestation_id": found.file.attestation_id,
            "cohort": room.row_scope_token(),
            "room_id": room.content_group_id(),
            "filename": found.file.filename,
            "media_type": found.file.media_type,
            "author_key_id": found.file.attesting_key_id,
            "asserted_at": found.file.asserted_at.to_rfc3339(),
            "size": size,
            "bytes": bytes,
            "detail": detail,
            // The PLAINTEXT digest, when the bytes open here (CIRISServer#641).
            "content_digest": content_digest,
            "content_digest_alg": "sha-256",
            // The AT-REST hash of the sealed blob / chunk manifest — NOT a digest
            // of the file's bytes; a client must not verify plaintext against it.
            "at_rest_sha256": found.file.pointer.content_sha256,
            // Deprecated name for `at_rest_sha256`, kept for 0.5.216 readers.
            "content_sha256": found.file.pointer.content_sha256,
            "chunked": found.file.pointer.stream_id.is_some(),
            "tier": format!("{:?}", found.file.pointer.tier),
            "withdrawn": found.withdrawn_by.is_some(),
            "withdrawn_by": found.withdrawn_by,
            "replaces": replaces_of(&found.row),
            "devices_holding": devices_holding,
            "holder_claims_recorded": recorded,
            "envelope": envelope_of(&found.row),
        })),
    )
        .into_response()
}

/// A single `Range: bytes=…` request, resolved against the plaintext size.
enum RangeAsk {
    /// No usable Range header: serve the whole file.
    Whole,
    /// Serve `[start, end]` inclusive.
    Part(u64, u64),
    /// RFC 9110 §14.4: 416.
    Unsatisfiable,
}

/// RFC 9110 §14.1.2, one range. A multi-range or malformed header is IGNORED
/// (the whole representation is served), which the RFC permits; a range past
/// the end is 416. A satisfiable range longer than [`WHOLE_READ_CAP`] is
/// SHORTENED to it — a 206's `Content-Range` names what was actually sent, and
/// every range client continues from there.
fn parse_range(h: Option<&str>, total: u64) -> RangeAsk {
    let Some(spec) = h.and_then(|v| v.trim().strip_prefix("bytes=")) else {
        return RangeAsk::Whole;
    };
    if spec.contains(',') {
        return RangeAsk::Whole;
    }
    let Some((a, b)) = spec.split_once('-') else {
        return RangeAsk::Whole;
    };
    let (a, b) = (a.trim(), b.trim());
    let (start, end) = if a.is_empty() {
        // Suffix: the last `n` bytes.
        let Ok(n) = b.parse::<u64>() else {
            return RangeAsk::Whole;
        };
        if n == 0 || total == 0 {
            return RangeAsk::Unsatisfiable;
        }
        (total.saturating_sub(n), total - 1)
    } else {
        let Ok(s) = a.parse::<u64>() else {
            return RangeAsk::Whole;
        };
        let e = if b.is_empty() {
            u64::MAX
        } else {
            match b.parse::<u64>() {
                Ok(e) if e >= s => e,
                _ => return RangeAsk::Whole,
            }
        };
        if s >= total {
            return RangeAsk::Unsatisfiable;
        }
        (s, e.min(total - 1))
    };
    let cap = WHOLE_READ_CAP as u64;
    RangeAsk::Part(start, end.min(start.saturating_add(cap - 1)))
}

/// `Content-Disposition: attachment` with the file's name — an ASCII fallback
/// (`filename=`) and the exact UTF-8 name (`filename*=`, RFC 6266 / 5987).
fn content_disposition(filename: Option<&str>) -> HeaderValue {
    let Some(name) = filename.filter(|n| !n.trim().is_empty()) else {
        return HeaderValue::from_static("attachment");
    };
    let ascii: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() && c != '"' && c != '\\' || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let v = format!(
        "attachment; filename=\"{ascii}\"; filename*=UTF-8''{}",
        urlencoding::encode(name)
    );
    HeaderValue::from_str(&v).unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

/// `GET /v1/files/{attestation_id}` — the bytes, or the reason they are not
/// here. JSON by default; `?raw=1` answers the bytes themselves, with `Range`.
async fn read_file(
    State(st): State<DriveState>,
    headers: HeaderMap,
    Path(attestation_id): Path<String>,
    Query(q): Query<FileQuery>,
) -> Response {
    let Some(owner) = crate::drive_auth::owner(&st, &headers).await else {
        return drive_no_session();
    };
    let (_, room) = match room_from_query(&st, &owner.key_id, &q).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    let found = match find_file(&st, &owner.key_id, &room, &attestation_id, Plane::Drive).await {
        Ok(f) => f,
        Err(e) => return e,
    };
    let viewer = match viewer_key(&st).await {
        Ok(v) => v,
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "drive.no_node_key",
                format!("resolve this node's key: {e}"),
            )
        }
    };
    if !truthy(q.raw.as_deref()) {
        return match open_whole(&st, &found, &viewer).await {
            Ok((bytes, _)) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "attestation_id": found.file.attestation_id,
                    "media_type": found.file.media_type,
                    "filename": found.file.filename,
                    "size": bytes.len(),
                    "content_digest": plaintext_digest(&bytes),
                    "content_digest_alg": "sha-256",
                    "bytes_base64": base64_encode(&bytes),
                })),
            )
                .into_response(),
            Err(e) => e,
        };
    }
    // RAW: the bytes, typed and named, whole or by range.
    if let Some(w) = &found.withdrawn_by {
        return row_withdrawn_refusal(w);
    }
    let size = match probe(&st, &found.file, &viewer).await {
        ByteState::Here { size } => size,
        ByteState::Absent { state, detail } => return refuse_state(state, detail),
    };
    let media = found
        .file
        .media_type
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&media)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        content_disposition(found.file.filename.as_deref()),
    );
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    let range_header = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
    let ask = match (range_header, size) {
        (None, _) => RangeAsk::Whole,
        (Some(r), Some(total)) => parse_range(Some(r), total),
        // Size unknown (persist answered the probe with bytes): serve whole.
        (Some(_), None) => RangeAsk::Whole,
    };
    match ask {
        RangeAsk::Whole => match open_whole(&st, &found, &viewer).await {
            Ok((bytes, _)) => {
                if let Some(v) = repr_digest(&bytes) {
                    h.insert(header::HeaderName::from_static("repr-digest"), v);
                }
                (StatusCode::OK, h, bytes).into_response()
            }
            Err(e) => e,
        },
        RangeAsk::Unsatisfiable => {
            let total = size.unwrap_or(0);
            let mut resp = refuse(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "drive.range_not_satisfiable",
                format!("the requested range is outside this {total}-byte file"),
            );
            if let Ok(v) = HeaderValue::from_str(&format!("bytes */{total}")) {
                resp.headers_mut().insert(header::CONTENT_RANGE, v);
            }
            resp
        }
        RangeAsk::Part(start, end) => {
            let Some(sha) = sha_of(&found.file) else {
                return refuse_state("malformed_row", state_detail("malformed_row").to_owned());
            };
            let aad = aad_for(&found.file);
            match st
                .engine
                .read_blob_range_as(&sha, &viewer, start, end, aad.as_deref())
                .await
            {
                Ok(bytes) => {
                    let sent_end = start + (bytes.len() as u64).saturating_sub(1);
                    if let Ok(v) = HeaderValue::from_str(&format!(
                        "bytes {start}-{sent_end}/{}",
                        size.unwrap_or(0)
                    )) {
                        h.insert(header::CONTENT_RANGE, v);
                    }
                    (StatusCode::PARTIAL_CONTENT, h, bytes).into_response()
                }
                Err(e) => match blob_state(&e) {
                    ByteState::Absent { state, detail } => refuse_state(state, detail),
                    ByteState::Here { .. } => unreachable!("blob_state always answers Absent"),
                },
            }
        }
    }
}

/// `PUT /v1/files/{attestation_id}` — replace a file's bytes. Author only.
/// Publishes the new row, THEN withdraws the old one, so a failure between the
/// two leaves both rather than neither.
async fn replace_file(
    State(st): State<DriveState>,
    headers: HeaderMap,
    Path(attestation_id): Path<String>,
    Query(q): Query<FileQuery>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let owner = match drive_author(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    if let Some(resp) =
        crate::conformance::require_op(&st.engine, crate::auth::gate::CapabilityVerb::ChatAuthor)
            .await
    {
        return resp;
    }
    let (cohort, room) = match room_from_query(&st, &owner.key_id, &q).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    let found = match find_file(&st, &owner.key_id, &room, &attestation_id, Plane::Drive).await {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Err(e) = require_author(&st, &found.row) {
        return e;
    }
    if let Some(w) = &found.withdrawn_by {
        return row_withdrawn_refusal(w);
    }
    let up = match parse_upload(&headers, body) {
        Ok(u) => u,
        Err(e) => return e,
    };
    // Unnamed members keep the old file's: a replace changes the BYTES.
    let media_type = up
        .media_type
        .clone()
        .or_else(|| found.file.media_type.clone())
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    let filename = up.filename.clone().or_else(|| found.file.filename.clone());
    let (published, addressed) = match publish_into(
        &st,
        &headers,
        &owner.key_id,
        cohort,
        &room,
        &up.bytes,
        &media_type,
        filename.as_deref(),
        Plane::Drive,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return e,
    };
    let w = match withdraw_rows(&st, &found.row, &found.file, "replaced by its author").await {
        Ok(w) => w,
        Err(e) => return withdraw_failed(e),
    };
    tracing::info!(
        old = %attestation_id, new = %readable_id(&published), evicted = w.evicted,
        "drive: file replaced — new row published, old rows withdrawn"
    );
    (
        StatusCode::OK,
        Json(write_response(
            &published,
            addressed,
            &room,
            Some(attestation_id),
            w.withdrawn,
        )),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct RenameRequest {
    pub filename: String,
}

/// `POST /v1/files/{attestation_id}/rename` — a new row over the SAME bytes
/// (no re-upload, no re-seal), then the old row withdrawn. Author only.
async fn rename_file(
    State(st): State<DriveState>,
    headers: HeaderMap,
    Path(attestation_id): Path<String>,
    Query(q): Query<FileQuery>,
    body: Result<Json<RenameRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let owner = match drive_author(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    if let Some(resp) =
        crate::conformance::require_op(&st.engine, crate::auth::gate::CapabilityVerb::ChatAuthor)
            .await
    {
        return resp;
    }
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => return bad_body(format!("not a rename body: {e}")),
    };
    let filename = req.filename.trim();
    if filename.is_empty() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "drive.filename_empty",
            "a rename needs a name — an empty filename would leave the file unnamed rather \
             than renamed"
                .into(),
        );
    }
    // Same display-only rule as the write gate (CIRISServer#642).
    let Some((clean, _)) = crate::media_gate::sanitize_filename(filename) else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "drive.bad_filename",
            "nothing displayable is left of that filename once path components and control / \
             bidi characters are removed (RFC 6266 §4.3)"
                .into(),
        );
    };
    let filename = clean.as_str();
    let (_, room) = match room_from_query(&st, &owner.key_id, &q).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    let found = match find_file(&st, &owner.key_id, &room, &attestation_id, Plane::Drive).await {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Err(e) = require_author(&st, &found.row) {
        return e;
    }
    if let Some(w) = &found.withdrawn_by {
        return row_withdrawn_refusal(w);
    }
    let row = match rename_row(
        &st.node_signer,
        &room,
        &found.file,
        filename,
        &attestation_id,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "drive.publish_failed",
                format!("build the renamed row: {e}"),
            )
        }
    };
    let dir = st.engine.federation_directory();
    if let Err(e) = dir
        .put_attestation_authored(ciris_persist::federation::SignedAttestation {
            attestation: row.clone(),
        })
        .await
    {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "drive.publish_failed",
            format!("author the renamed row: {e:#}"),
        );
    }
    let crossing = match ciris_edge::replication::attestation_bind::share(
        &*dir,
        &row,
        room.widen_to(),
        ciris_edge::replication::attestation_bind::CrossingBasis::ProducerAuthority,
        ciris_edge::replication::attestation_bind::Signers {
            node: &st.node_signer,
            actor: None,
        },
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "drive.publish_failed",
                format!("cross the renamed row into {room}: {e}"),
            )
        }
    };
    crate::compose::kick_replication("file renamed");
    let new_id = placed_or(&crossing.shared, &row.attestation_id).to_owned();
    let w = match withdraw_rows(&st, &found.row, &found.file, "renamed by its author").await {
        Ok(w) => w,
        Err(e) => return withdraw_failed(e),
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "attestation_id": new_id,
            "replaces": attestation_id,
            "filename": filename,
            "content_sha256": found.file.pointer.content_sha256,
            "cohort": room.row_scope_token(),
            "room": room.to_string(),
            "crossed": !matches!(
                crossing.shared,
                ciris_edge::replication::attestation_bind::Shared::AwaitingActor { .. }
            ),
            "withdrawn": w.withdrawn,
        })),
    )
        .into_response()
}

/// `DELETE /v1/files/{attestation_id}` — withdraw a file. Author only
/// (subject take-back is FSD §7). Persist then refuses every read of the bytes
/// (CC 2.3), the local copy is evicted, and holders drop it on their next pass.
async fn withdraw_file(
    State(st): State<DriveState>,
    headers: HeaderMap,
    Path(attestation_id): Path<String>,
    Query(q): Query<FileQuery>,
) -> Response {
    let owner = match drive_author(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    if let Some(resp) =
        crate::conformance::require_op(&st.engine, crate::auth::gate::CapabilityVerb::ChatAuthor)
            .await
    {
        return resp;
    }
    let (_, room) = match room_from_query(&st, &owner.key_id, &q).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    let found = match find_file(&st, &owner.key_id, &room, &attestation_id, Plane::Drive).await {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Err(e) = require_author(&st, &found.row) {
        return e;
    }
    if let Some(w) = &found.withdrawn_by {
        return row_withdrawn_refusal(w);
    }
    match withdraw_rows(&st, &found.row, &found.file, "withdrawn by its author").await {
        Ok(w) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "attestation_id": attestation_id,
                "withdrawn": w.withdrawn,
                "evicted": w.evicted,
            })),
        )
            .into_response(),
        Err(e) => withdraw_failed(e),
    }
}

#[derive(Debug, Deserialize)]
pub struct MoveRequest {
    pub cohort: String,
    #[serde(default)]
    pub room_id: Option<String>,
    /// Keep the source row (a copy / "share to") instead of withdrawing it.
    #[serde(default)]
    pub keep_source: bool,
}

/// `POST /v1/files/{attestation_id}/move` — reseal at the target room's tier,
/// publish there, and (unless `keep_source`) withdraw the source. "Going out
/// asks": this call IS the ask. Author only, and a member of the target.
async fn move_file(
    State(st): State<DriveState>,
    headers: HeaderMap,
    Path(attestation_id): Path<String>,
    Query(q): Query<FileQuery>,
    body: Result<Json<MoveRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let owner = match drive_author(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    if let Some(resp) =
        crate::conformance::require_op(&st.engine, crate::auth::gate::CapabilityVerb::ChatAuthor)
            .await
    {
        return resp;
    }
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => return bad_body(format!("not a move body: {e}")),
    };
    // The TARGET, parsed before anything is read: a bad target is a 400 about
    // the question, whatever the source turns out to be.
    let target_cohort = match Cohort::parse(Some(req.cohort.as_str())) {
        Ok(c) => c,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, "drive.bad_move_target", e),
    };
    if !matches!(target_cohort, Cohort::SelfCollective) && req.room_id.is_none() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "drive.bad_move_target",
            format!(
                "a move to a {} must name its `room_id` — there is no default circle to move a \
                 file into",
                req.cohort
            ),
        );
    }
    let (_, source) = match room_from_query(&st, &owner.key_id, &q).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    let target = match room_for(target_cohort, req.room_id.as_deref(), &owner.key_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if target == source {
        return refuse(
            StatusCode::CONFLICT,
            "drive.same_room",
            "the file is already in that room — a move needs a different circle".into(),
        );
    }
    if let Err(e) = require_cohort_member(&st, &owner.key_id, target_cohort, &target).await {
        return e;
    }
    let found = match find_file(&st, &owner.key_id, &source, &attestation_id, Plane::Drive).await {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Err(e) = require_author(&st, &found.row) {
        return e;
    }
    let viewer = match viewer_key(&st).await {
        Ok(v) => v,
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "drive.no_node_key",
                format!("resolve this node's key: {e}"),
            )
        }
    };
    // A RESEAL, not a re-pointer: the target room's tier and group decide the
    // seal (a community DEK is not a self wrap), so the bytes are opened here
    // and sealed again there.
    let (bytes, _) = match open_whole(&st, &found, &viewer).await {
        Ok(b) => b,
        Err(e) => return e,
    };
    let media_type = found
        .file
        .media_type
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    let (published, addressed) = match publish_into(
        &st,
        &headers,
        &owner.key_id,
        target_cohort,
        &target,
        &bytes,
        &media_type,
        found.file.filename.as_deref(),
        Plane::Drive,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return e,
    };
    let withdrawn = if req.keep_source {
        Vec::new()
    } else {
        match withdraw_rows(&st, &found.row, &found.file, "moved by its author").await {
            Ok(w) => w.withdrawn,
            Err(e) => return withdraw_failed(e),
        }
    };
    (
        StatusCode::OK,
        Json(write_response(
            &published,
            addressed,
            &target,
            (!req.keep_source).then_some(attestation_id),
            withdrawn,
        )),
    )
        .into_response()
}

fn file_error(e: &files::FileError, room: &ScopeRoom) -> Response {
    use files::FileError as F;
    match e {
        // Unreachable from `files::publish` since CIRISEdge#633 (it seals above
        // the 1 MiB envelope bound as a chunk DAG). Kept, under the same id as
        // this node's own cap, for a store that implements only `seal`.
        F::TooLargeForInline { size, .. } => too_large(*size),
        F::ReadableByNobody { .. } => refuse(
            StatusCode::CONFLICT,
            "drive.readable_by_nobody",
            format!(
                "nothing in {room} could be granted these bytes, so the write was refused \
                 rather than sealing something no one can open"
            ),
        ),
        other => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "drive.publish_failed",
            format!("{other}"),
        ),
    }
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
// everything else the owner holds. Editing one is the same replace-and-withdraw
// as a file; deleting one is the same withdrawal.

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
    /// One of [`BYTE_STATES`] — the SAME words `GET /v1/drive` uses for the same
    /// fact (CIRISServer#644: notes said `open` where the drive said `here`) —
    /// plus `unreadable`, the one note-only fact: the bytes opened and are not
    /// UTF-8 text.
    pub state: String,
    pub detail: String,
}

/// A note is an UNNAMED text row in the self room. Both conditions, because
/// both are what `write_note` stamps: `text/plain` and `filename: None`. The
/// media type alone is not enough — `POST /v1/files` can put a named `.txt` in
/// the same room, and a notes list that swallowed it would report somebody's
/// uploaded file as something they had written.
fn is_note(file: &files::FileRow) -> bool {
    file.media_type
        .as_deref()
        .is_some_and(|m| m.starts_with("text/plain"))
        && file.filename.is_none()
}

#[allow(clippy::result_large_err)] // the Err IS an axum Response
fn require_note_body(body: &str) -> Result<(), Response> {
    if body.trim().is_empty() {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "notes.empty",
            "a note with no body is not a note".into(),
        ));
    }
    Ok(())
}

/// Publish a note's text into the self room. See `write_note` for why a note
/// is a file and not a chat row.
#[allow(clippy::result_large_err)] // the Err IS an axum Response
async fn publish_note(
    st: &DriveState,
    headers: &HeaderMap,
    owner_key_id: &str,
    body: &str,
) -> Result<(files::PublishedFile, ScopeRoom), Response> {
    let room = ciris_edge::self_room::room(owner_key_id);
    // A NOTE IS A SELF-SCOPED TEXT FILE, through the same door as every other
    // file. The first cut authored it with `chat_message_attestation_in`, and
    // persist refused the seal by name: that builder stamps `cohort_scope:
    // community` and hands persist the room id as a `community_key_id`, so a
    // self room came back as `unknown community_key_id`. The refusal was right
    // — the community-DEK path is not the self tier. `files::publish` seals at
    // the ROOM's tier (a per-write DEK for self) and fills persist's group slot
    // with the OWNER, which is what a self note is.
    let (published, _) = publish_into(
        st,
        headers,
        owner_key_id,
        Cohort::SelfCollective,
        &room,
        body.as_bytes(),
        NOTE_MEDIA_TYPE,
        None,
        Plane::Notes,
    )
    .await?;
    if !published.crossed {
        tracing::warn!(
            attestation_id = %published.row.attestation_id,
            "notes: the note was written but did NOT cross — it is local-tier, so this \
             person's other devices will never see it"
        );
    }
    Ok((published, room))
}

/// `POST /v1/notes` — write a note to yourself.
async fn write_note(
    State(st): State<DriveState>,
    headers: HeaderMap,
    Json(req): Json<NoteWrite>,
) -> Response {
    let owner = match notes_author(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    if let Err(e) = require_note_body(&req.body) {
        return e;
    }
    // DECLARED-CONFORMANCE GATE — see `write_file`.
    if let Some(resp) =
        crate::conformance::require_op(&st.engine, crate::auth::gate::CapabilityVerb::ChatAuthor)
            .await
    {
        return resp;
    }
    let (published, room) = match publish_note(&st, &headers, &owner.key_id, &req.body).await {
        Ok(p) => p,
        Err(e) => return e,
    };
    crate::compose::kick_replication("note written in the self room");
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "attestation_id": readable_id(&published),
            "room": room.to_string(),
            "cohort": room.row_scope_token(),
            "crossed": published.crossed,
        })),
    )
        .into_response()
}

/// The note `attestation_id` in the owner's self room, author-checked — or
/// `notes.not_found` for anything that is not one of their live notes.
#[allow(clippy::result_large_err)] // the Err IS an axum Response
async fn find_own_note(
    st: &DriveState,
    owner_key_id: &str,
    attestation_id: &str,
) -> Result<Found, Response> {
    let room = ciris_edge::self_room::room(owner_key_id);
    let found = find_file(st, owner_key_id, &room, attestation_id, Plane::Notes).await?;
    // A withdrawn note, or a file that is not a note, is not one of your notes.
    if !is_note(&found.file) || found.withdrawn_by.is_some() {
        return Err(refuse(
            StatusCode::NOT_FOUND,
            "notes.not_found",
            format!("{attestation_id} is not one of your notes"),
        ));
    }
    require_author(st, &found.row)?;
    Ok(found)
}

/// `PUT /v1/notes/{attestation_id}` — edit a note: the new text is a new note
/// row, and the old one is withdrawn.
async fn update_note(
    State(st): State<DriveState>,
    headers: HeaderMap,
    Path(attestation_id): Path<String>,
    body: Result<Json<NoteWrite>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let owner = match notes_author(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => return bad_body(format!("not a note body: {e}")),
    };
    if let Err(e) = require_note_body(&req.body) {
        return e;
    }
    if let Some(resp) =
        crate::conformance::require_op(&st.engine, crate::auth::gate::CapabilityVerb::ChatAuthor)
            .await
    {
        return resp;
    }
    let found = match find_own_note(&st, &owner.key_id, &attestation_id).await {
        Ok(f) => f,
        Err(e) => return e,
    };
    let (published, room) = match publish_note(&st, &headers, &owner.key_id, &req.body).await {
        Ok(p) => p,
        Err(e) => return e,
    };
    let w = match withdraw_rows(&st, &found.row, &found.file, "edited by its author").await {
        Ok(w) => w,
        Err(e) => return withdraw_failed(e),
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "attestation_id": readable_id(&published),
            "replaces": attestation_id,
            "room": room.to_string(),
            "cohort": room.row_scope_token(),
            "crossed": published.crossed,
            "withdrawn": w.withdrawn,
        })),
    )
        .into_response()
}

/// `DELETE /v1/notes/{attestation_id}` — withdraw a note.
async fn withdraw_note(
    State(st): State<DriveState>,
    headers: HeaderMap,
    Path(attestation_id): Path<String>,
) -> Response {
    let owner = match notes_author(&st, &headers).await {
        Ok(o) => o,
        Err(r) => return r,
    };
    if let Some(resp) =
        crate::conformance::require_op(&st.engine, crate::auth::gate::CapabilityVerb::ChatAuthor)
            .await
    {
        return resp;
    }
    let found = match find_own_note(&st, &owner.key_id, &attestation_id).await {
        Ok(f) => f,
        Err(e) => return e,
    };
    match withdraw_rows(&st, &found.row, &found.file, "withdrawn by its author").await {
        Ok(w) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "attestation_id": attestation_id,
                "withdrawn": w.withdrawn,
                "evicted": w.evicted,
            })),
        )
            .into_response(),
        Err(e) => withdraw_failed(e),
    }
}

/// `GET /v1/notes` — your notes, newest first, with unopened ones named and
/// withdrawn ones gone.
async fn read_notes(
    State(st): State<DriveState>,
    headers: HeaderMap,
    Query(q): Query<DriveQuery>,
) -> Response {
    let Some(owner) = crate::drive_auth::owner(&st, &headers).await else {
        return notes_no_session();
    };
    let room = ciris_edge::self_room::room(&owner.key_id);
    let limit = q.limit.clamp(1, MAX_PAGE);
    let viewer = match viewer_key(&st).await {
        Ok(v) => v,
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "notes.no_node_key",
                format!("resolve this node's key: {e}"),
            )
        }
    };
    let content = store(&st.engine);
    // THE LIMIT COUNTS NOTES, NOT ROWS (Codex, CIRISServer#628). A limit on the
    // room's rows bounds every FILE in the self room — photos, named uploads,
    // anything — and the note filter runs after, so enough non-note rows at the
    // head of the window and a person's notes simply vanish. Walk the room
    // (edge bounds each walk, `resume` continues it) and stop once `limit`
    // NOTES are collected.
    let mut out: Vec<Note> = Vec::new();
    let mut after = None;
    'rooms: loop {
        let page = match files::in_room(&st.engine, &room, &owner.key_id, usize::MAX, after).await {
            Ok(p) => p,
            Err(e) => {
                return refuse(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "notes.listing_failed",
                    format!("read your self room: {e:#}"),
                )
            }
        };
        for row in page.files {
            if out.len() >= limit {
                break 'rooms;
            }
            if !is_note(&row) {
                continue;
            }
            match withdrawn_by(&st, &row.attestation_id).await {
                Ok(None) => {}
                Ok(Some(_)) => continue,
                Err(e) => {
                    return refuse(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "notes.listing_failed",
                        format!("read your self room: {e}"),
                    )
                }
            }
            let (body, state, detail) = match row.open(&content, &viewer).await {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(text) => (
                        Some(text),
                        BYTE_STATE_HERE.to_owned(),
                        "readable on this device".to_owned(),
                    ),
                    Err(_) => (
                        None,
                        "unreadable".to_owned(),
                        "the bytes opened but are not UTF-8 text".to_owned(),
                    ),
                },
                Err(reason) => match unopened(&reason) {
                    ByteState::Absent { state, detail } => (None, state.to_owned(), detail),
                    ByteState::Here { .. } => unreachable!("unopened always answers Absent"),
                },
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
        match page.resume {
            Some(c) => after = Some(c),
            None => break,
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "room": room.to_string(), "notes": out })),
    )
        .into_response()
}

/// `GET /v1/media/policy` — this node's media render policy (CIRISServer#643),
/// published ahead of the ingest pipeline (#614). See [`crate::media_gate::policy`].
async fn media_policy() -> Response {
    (StatusCode::OK, Json(crate::media_gate::policy())).into_response()
}

pub fn router(
    engine: Arc<Engine>,
    node_signer: Arc<ciris_edge::identity::LocalSigner>,
    user_seed_dir: std::path::PathBuf,
    // CIRISEdge#499 — the same plane the chat router is given. The drive does
    // not INSTALL rooms (that needs the group registry) but it must be able to
    // say whether one is addressed, or a write reports `crossed` for bytes
    // nobody can fetch.
    scope_lifecycle: Option<Arc<ciris_edge::scope_lifecycle::ScopeLifecycle>>,
) -> Router {
    let state = DriveState {
        engine,
        node_signer,
        user_seed_dir,
        scope_lifecycle,
    };
    // THE UPLOAD ROUTES ONLY carry the raised body limit. axum's 2 MB default
    // stands everywhere else; before 0.5.216 it stood HERE too, so the largest
    // file anyone could upload was ~1.5 MB of base64 while the comment on the
    // form said edge capped at 1 MiB — two stale numbers, neither the real one.
    let upload_limit = DefaultBodyLimit::max(UPLOAD_BODY_LIMIT);
    use axum::routing::{get, post, put};
    Router::new()
        .route("/v1/files", post(write_file).layer(upload_limit))
        .route("/v1/drive", get(read_drive))
        // Public: a node's render policy is what its clients need BEFORE they
        // hold a session, and it discloses nothing about anyone (#643).
        .route("/v1/media/policy", get(media_policy))
        .route(
            "/v1/files/{attestation_id}",
            get(read_file)
                .put(replace_file)
                .delete(withdraw_file)
                .layer(upload_limit),
        )
        .route("/v1/files/{attestation_id}/meta", get(file_meta))
        .route("/v1/files/{attestation_id}/rename", post(rename_file))
        .route("/v1/files/{attestation_id}/move", post(move_file))
        .route("/v1/notes", get(read_notes).post(write_note))
        .route(
            "/v1/notes/{attestation_id}",
            put(update_note).delete(withdraw_note),
        )
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_upload_limit_admits_a_capped_file_in_either_form() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 3 * 1024]);
        assert!(b64.len() <= 4 * 1024);
        assert!(UPLOAD_BODY_LIMIT > WHOLE_READ_CAP.div_ceil(3) * 4);
        assert_eq!(WHOLE_READ_CAP, 64 * 1024 * 1024);
    }

    #[test]
    fn a_range_is_resolved_against_the_plaintext_size() {
        assert!(matches!(parse_range(None, 10), RangeAsk::Whole));
        assert!(matches!(
            parse_range(Some("bytes=2-4"), 10),
            RangeAsk::Part(2, 4)
        ));
        assert!(matches!(
            parse_range(Some("bytes=5-"), 10),
            RangeAsk::Part(5, 9)
        ));
        assert!(matches!(
            parse_range(Some("bytes=-3"), 10),
            RangeAsk::Part(7, 9)
        ));
        assert!(matches!(
            parse_range(Some("bytes=8-100"), 10),
            RangeAsk::Part(8, 9)
        ));
        assert!(matches!(
            parse_range(Some("bytes=10-"), 10),
            RangeAsk::Unsatisfiable
        ));
        assert!(matches!(
            parse_range(Some("bytes=-0"), 10),
            RangeAsk::Unsatisfiable
        ));
        // Ignored, per RFC 9110: multi-range and malformed.
        assert!(matches!(
            parse_range(Some("bytes=0-1,4-5"), 10),
            RangeAsk::Whole
        ));
        assert!(matches!(
            parse_range(Some("bytes=5-2"), 10),
            RangeAsk::Whole
        ));
        assert!(matches!(
            parse_range(Some("items=0-1"), 10),
            RangeAsk::Whole
        ));
    }

    #[test]
    fn multipart_reads_the_file_part_and_the_fields() {
        let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"cohort\"\r\n\r\nself\r\n\
--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"boat.jpg\"\r\n\
Content-Type: image/jpeg\r\n\r\n\x00\x01\r\n\x02\r\n--XyZ--\r\n";
        assert_eq!(
            multipart::boundary("multipart/form-data; boundary=XyZ").as_deref(),
            Some("XyZ")
        );
        assert_eq!(
            multipart::boundary("multipart/form-data; boundary=\"XyZ\"").as_deref(),
            Some("XyZ")
        );
        let parts = multipart::parse(body, "XyZ").expect("parse");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].name, "cohort");
        assert_eq!(parts[0].data, b"self");
        assert_eq!(parts[1].name, "file");
        assert_eq!(parts[1].filename.as_deref(), Some("boat.jpg"));
        assert_eq!(parts[1].content_type.as_deref(), Some("image/jpeg"));
        // CRLF INSIDE the bytes survives: only CRLF + delimiter ends a part.
        assert_eq!(parts[1].data, b"\x00\x01\r\n\x02");
        assert!(multipart::parse(b"no boundary here", "XyZ").is_err());
    }

    #[test]
    fn content_disposition_names_the_file_in_both_forms() {
        let v = content_disposition(Some("Mira's \"boat\" — 1.jpg"));
        let s = v.to_str().expect("ascii header");
        assert!(s.starts_with("attachment; filename=\""));
        assert!(s.contains("filename*=UTF-8''"));
        assert!(
            !s.contains("\"boat\""),
            "a quote inside the name is escaped: {s}"
        );
        assert_eq!(content_disposition(None), "attachment");
    }
}
