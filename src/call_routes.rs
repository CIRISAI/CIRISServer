//! **Calls in a room, as the member** (CIRISServer#859, 0.5.246).
//!
//! The production call surface the client builds against (CIRISClient
//! `FSD/CSD/CSD-134-calls.md`, PR #287). The QA routes (`crate::qa_call`) stay as
//! the harness door; these join AS THE PERSON, carry the client's own encoded
//! frames, and refuse in words.
//!
//! - `POST /v1/chat/{room}/call` `{video?, relay?}`: join. `relay` defaults to
//!   **false** in 0.5.246: member relays shed and strand listeners on edge
//!   v44/v45 (evidence/av/av_mesh.jsonl), so calls run full mesh, which edge
//!   keeps for up to 9 members by design, until edge 45.1 passes the relay gate.
//! - `DELETE /v1/chat/{room}/call`: leave. The call goes on for the others.
//! - `GET /v1/chat/{room}/call`: is there a call, who is in it, and the two
//!   things a joiner is told before publishing (`room_may_keep`,
//!   `visible_to_watcher`).
//! - `WS /v1/chat/{room}/call/frames`: frames both ways in the v1 layout
//!   ([`crate::call_frames`]) as binary messages, and call events as JSON text
//!   messages. Closing the socket leaves the call.
//! - `POST /v1/chat/{room}/call/layers` `{member, policy}`: what THIS device
//!   receives from `member`. v1 filters on arrival (saves decode and render, not
//!   network); edge 45.1 adds the request to the publisher and this route will
//!   send it, with the same contract.
//!
//! Every route is the owner's session, like chat. The person's own pen signs
//! the attendance row (`join_call_as`), never the node.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use ciris_edge::transport::av_call::{Call, CallError, CallEvent, CallOptions, Frame};
use ciris_edge::transport::realtime_av::{ChunkLayer, ReceiverLayerPolicy};
use ciris_edge::Edge;
use ciris_persist::prelude::Engine;

use crate::auth::refusal::refuse_with;
use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::resolve_bearer;
use crate::call_frames::{self, Incoming};

/// The capability word the client's Call action waits for (`chat:call`).
pub const FEATURE: &str = "chat:call";

/// "Live" when a member's attendance row is this recent, or this node is in it.
const LIVE_WINDOW_SECS: i64 = 60;

#[derive(Clone)]
struct CallState {
    engine: Arc<Engine>,
    edge: Arc<Edge>,
}

/// One joined call on this node: the call itself, its two take-once streams
/// (taken by the frames socket), and the receive caps the layers route set.
struct Joined {
    call: tokio::sync::Mutex<Option<Call>>,
    frames: StdMutex<
        Option<tokio::sync::mpsc::Receiver<ciris_edge::transport::av_call::ReceivedFrame>>,
    >,
    events: StdMutex<Option<tokio::sync::mpsc::Receiver<CallEvent>>>,
    caps: StdMutex<HashMap<String, ReceiverLayerPolicy>>,
    video: bool,
}

/// Single-use frames-socket tickets: a browser cannot put a bearer header on a
/// WebSocket, and the session token must never go in a URL. The join (an
/// authenticated POST) hands one out; the socket spends it within 30 s.
const TICKET_TTL: std::time::Duration = std::time::Duration::from_secs(30);

fn tickets() -> &'static StdMutex<HashMap<String, (String, std::time::Instant)>> {
    static T: OnceLock<StdMutex<HashMap<String, (String, std::time::Instant)>>> = OnceLock::new();
    T.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn issue_ticket(room: &str) -> String {
    let mut b = [0u8; 32];
    ciris_crypto::random::fill(&mut b).expect("CSPRNG for a call ticket");
    let t = hex::encode(b);
    let mut m = tickets()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    m.retain(|_, (_, at)| at.elapsed() < TICKET_TTL);
    m.insert(t.clone(), (room.to_owned(), std::time::Instant::now()));
    t
}

/// Spend a ticket: true once, for its own room, inside its window.
fn spend_ticket(ticket: &str, room: &str) -> bool {
    let mut m = tickets()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match m.remove(ticket) {
        Some((r, at)) => r == room && at.elapsed() < TICKET_TTL,
        None => false,
    }
}

/// A browser's `Origin` must be this node's own host; a native client sends none.
fn origin_ok(headers: &HeaderMap) -> bool {
    let Some(origin) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    else {
        return true;
    };
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let origin_host = origin.split("://").nth(1).unwrap_or(origin);
    !host.is_empty() && origin_host.eq_ignore_ascii_case(host)
}

/// The person a call member's NODE belongs to (its live owner-binding), for the
/// socket's events: frames name the node (a stream is a device), and the client
/// groups a person's devices under them without keeping a second copy of the
/// roster. Cached 60 s when found, 5 s when not yet bound.
type PersonCache = StdMutex<HashMap<String, (Option<String>, std::time::Instant)>>;

async fn person_of(engine: &Engine, node: &str) -> Option<String> {
    static C: OnceLock<PersonCache> = OnceLock::new();
    let cache = C.get_or_init(|| StdMutex::new(HashMap::new()));
    if let Some((p, at)) = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(node)
        .cloned()
    {
        let ttl = if p.is_some() { 60 } else { 5 };
        if at.elapsed() < std::time::Duration::from_secs(ttl) {
            return p;
        }
    }
    let p = ciris_persist::federation::admission::owner_of(
        engine.federation_directory().as_ref(),
        node,
    )
    .await
    .ok()
    .flatten();
    cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(node.to_owned(), (p.clone(), std::time::Instant::now()));
    p
}

async fn people_of(engine: &Engine, members: &[String]) -> serde_json::Value {
    let mut out = Vec::new();
    // Attendance rows are authored by the PERSON (`join_call_as`), so an attendee
    // with no owner-binding of its own is already the person; a node that
    // attended (the QA door) resolves to its owner.
    for m in members {
        let person = person_of(engine, m).await.unwrap_or_else(|| m.clone());
        out.push(json!({ "member": m, "person": person }));
    }
    serde_json::Value::Array(out)
}

/// Add `person` beside `member` on an event that names one.
async fn with_person(engine: &Engine, mut v: serde_json::Value) -> serde_json::Value {
    if let Some(m) = v
        .get("member")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
    {
        let p = person_of(engine, &m).await;
        v["person"] = json!(p);
    }
    v
}

fn joined() -> &'static StdMutex<HashMap<String, Arc<Joined>>> {
    static J: OnceLock<StdMutex<HashMap<String, Arc<Joined>>>> = OnceLock::new();
    J.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn current(room: &str) -> Option<Arc<Joined>> {
    joined()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(room)
        .cloned()
}

fn forget(room: &str) -> Option<Arc<Joined>> {
    joined()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(room)
}

/// The owner's session, as chat requires.
async fn require_owner(st: &CallState, headers: &HeaderMap) -> Result<(), Response> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return Err(refuse_with(
            StatusCode::UNAUTHORIZED,
            "call.session_absent",
            "Sign in to join a call.",
            json!({}),
        ));
    };
    match resolve_bearer(&st.engine, token).await {
        Ok(Some(c))
            if c.role == UserRole::SystemAdmin
                && c.permissions.contains(&Permission::FullAccess) =>
        {
            Ok(())
        }
        Ok(Some(_)) => Err(refuse_with(
            StatusCode::FORBIDDEN,
            "call.not_owner",
            "Only this device's owner can join calls from it.",
            json!({}),
        )),
        Ok(None) => Err(refuse_with(
            StatusCode::UNAUTHORIZED,
            "call.session_absent",
            "Sign in to join a call.",
            json!({}),
        )),
        Err(e) => Err(refuse_with(
            StatusCode::SERVICE_UNAVAILABLE,
            "call.plumbing",
            "Calls aren't available on this device right now.",
            json!({ "detail": format!("{e:#}") }),
        )),
    }
}

/// A call refusal, in words. One id per thing a person can do something about.
fn refuse_call(e: &CallError) -> Response {
    let detail = json!({ "detail": e.to_string() });
    match e {
        CallError::NotARoomMember { .. } | CallError::ConsentMissing { .. } => refuse_with(
            StatusCode::FORBIDDEN,
            "call.not_a_member",
            "You're not a member of this room yet, so you can't join its call.",
            detail,
        ),
        CallError::AnonymousMode => refuse_with(
            StatusCode::FORBIDDEN,
            "call.anonymous_mode",
            "Calls aren't available while this device is anonymous.",
            detail,
        ),
        CallError::FrameTooLarge { .. } => refuse_with(
            StatusCode::PAYLOAD_TOO_LARGE,
            "call.frame_over_budget",
            "That frame is too big for this call.",
            detail,
        ),
        CallError::CallEnded(_) => refuse_with(
            StatusCode::CONFLICT,
            "call.ended",
            "That call has already ended.",
            detail,
        ),
        _ => refuse_with(
            StatusCode::SERVICE_UNAVAILABLE,
            "call.plumbing",
            "Calls aren't available on this device right now.",
            detail,
        ),
    }
}

#[derive(Deserialize, Default)]
struct JoinBody {
    #[serde(default)]
    video: bool,
    /// Off by default in 0.5.246 (see the module note).
    #[serde(default)]
    relay: bool,
}

async fn join(
    State(st): State<CallState>,
    headers: HeaderMap,
    Path(room): Path<String>,
    body: Option<Json<JoinBody>>,
) -> Response {
    if let Err(r) = require_owner(&st, &headers).await {
        return r;
    }
    let body = body.map(|Json(b)| b).unwrap_or_default();
    if let Some(j) = current(&room) {
        let guard = j.call.lock().await;
        if let Some(c) = guard.as_ref() {
            return (
                StatusCode::OK,
                Json(join_view(&st.engine, &room, c, j.video, true).await),
            )
                .into_response();
        }
    }
    let node = crate::node_key::wire_identity()
        .map(str::to_owned)
        .unwrap_or_default();
    let actor = match crate::owner_signer_capsule::for_owned_node(&st.engine, &node).await {
        Ok(capsule) => Some(Arc::clone(capsule.edge_signer())),
        Err(e) => {
            return refuse_with(
                StatusCode::FORBIDDEN,
                "call.owner_pen_unavailable",
                "This device can't sign for you, so it can't join a call as you.",
                json!({ "detail": format!("{e:?}") }),
            )
        }
    };
    let opts = CallOptions {
        relay: body.relay,
        ..CallOptions::default()
    };
    let mut call = match st.edge.join_call_as(&room, opts, actor).await {
        Ok(c) => c,
        Err(e) => return refuse_call(&e),
    };
    let frames = call.frames();
    let events = call.events();
    let view = join_view(&st.engine, &room, &call, body.video, false).await;
    joined()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(
            room.clone(),
            Arc::new(Joined {
                call: tokio::sync::Mutex::new(Some(call)),
                frames: StdMutex::new(frames),
                events: StdMutex::new(events),
                caps: StdMutex::new(HashMap::new()),
                video: body.video,
            }),
        );
    tracing::info!(room = %room, relay = body.relay, video = body.video, "call: joined as the member");
    (StatusCode::OK, Json(view)).into_response()
}

async fn join_view(
    engine: &Engine,
    room: &str,
    call: &Call,
    video: bool,
    already: bool,
) -> serde_json::Value {
    let attendees = call.attendees().await;
    let people = people_of(engine, &attendees).await;
    json!({
        "room": room,
        "already_joined": already,
        "call_id": format!("{:?}", call.id()),
        "stream_id": hex::encode(call.stream().0),
        "epoch": call.epoch().await.0,
        "video": video,
        "frame_budget_bytes": call.chunk_plaintext_budget(),
        "service_tier": format!("{:?}", call.service_tier()),
        "attendees": attendees,
        "attendee_people": people,
        "legs": call.legs(),
        "frames_socket": format!("/v1/chat/{room}/call/frames"),
        // Browsers: open the socket with `?ticket=<this>` (single use, 30 s).
        "frames_ticket": issue_ticket(room),
    })
}

async fn leave(
    State(st): State<CallState>,
    headers: HeaderMap,
    Path(room): Path<String>,
) -> Response {
    if let Err(r) = require_owner(&st, &headers).await {
        return r;
    }
    match leave_room(&room, "left").await {
        Some(summary) => (StatusCode::OK, Json(summary)).into_response(),
        None => (
            StatusCode::OK,
            Json(json!({ "room": room, "left": "not_in_call" })),
        )
            .into_response(),
    }
}

/// Leave this node's call in `room`, if any. `why` is what the others are told
/// (`left`, `backgrounded`, `lost`).
pub async fn leave_room(room: &str, why: &str) -> Option<serde_json::Value> {
    let j = forget(room)?;
    let call = j.call.lock().await.take()?;
    let stream = hex::encode(call.stream().0);
    let summary = call.leave().await.ok();
    tracing::info!(room, why, "call: left");
    Some(json!({
        "room": room,
        "left": why,
        "stream_id": stream,
        "summary": summary.map(|s| format!("{s:?}")),
    }))
}

fn runtime() -> &'static OnceLock<tokio::runtime::Handle> {
    static H: OnceLock<tokio::runtime::Handle> = OnceLock::new();
    &H
}

/// `enter_background`'s first step, from the host's (non-runtime) thread: leave
/// every joined call as `backgrounded`, within `deadline`. Returns how many.
pub fn leave_all_blocking(deadline: std::time::Duration) -> usize {
    let any = !joined()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_empty();
    let Some(handle) = runtime().get() else {
        return 0;
    };
    if !any || tokio::runtime::Handle::try_current().is_ok() {
        return 0;
    }
    handle
        .block_on(async { tokio::time::timeout(deadline, leave_all("backgrounded")).await })
        .unwrap_or(0)
}

/// Leave every call this node is in. The host's `enter_background` path calls
/// it, so the others see `left: backgrounded` rather than a stall (CSD-134).
pub async fn leave_all(why: &str) -> usize {
    let rooms: Vec<String> = joined()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .keys()
        .cloned()
        .collect();
    let mut n = 0;
    for room in rooms {
        if leave_room(&room, why).await.is_some() {
            n += 1;
        }
    }
    n
}

async fn state(
    State(st): State<CallState>,
    headers: HeaderMap,
    Path(room): Path<String>,
) -> Response {
    if let Err(r) = require_owner(&st, &headers).await {
        return r;
    }
    let mine = match current(&room) {
        Some(j) => {
            let g = j.call.lock().await;
            match g.as_ref() {
                Some(c) => Some(json!({
                    "attendee_people": people_of(&st.engine, &c.attendees().await).await,
                    "stream_id": hex::encode(c.stream().0),
                    "state": format!("{:?}", c.state()),
                    "frame_budget_bytes": c.chunk_plaintext_budget(),
                    "service_tier": format!("{:?}", c.service_tier()),
                    "attendees": c.attendees().await,
                    "legs": c.legs(),
                    "video": j.video,
                })),
                None => None,
            }
        }
        None => None,
    };
    // Who else is in a call here, from the room's attendance rows.
    let rows = st
        .engine
        .federation_directory()
        .list_targeted_by_dimension_prefix(
            &[ciris_persist::federation::types::cohort_scope::COMMUNITY],
            &room,
            ciris_edge::chat::CALL_DIMENSION,
        )
        .await
        .unwrap_or_default();
    let now = chrono::Utc::now();
    let recent: Vec<&ciris_persist::federation::Attestation> = rows
        .iter()
        .filter(|r| (now - r.asserted_at).num_seconds() <= LIVE_WINDOW_SECS)
        .collect();
    let mut seen: Vec<String> = recent
        .iter()
        .flat_map(|r| {
            if r.subject_key_ids.is_empty() {
                vec![r.attesting_key_id.clone()]
            } else {
                r.subject_key_ids.clone()
            }
        })
        .collect();
    seen.sort();
    seen.dedup();
    (
        StatusCode::OK,
        Json(json!({
            "room": room,
            "live": mine.is_some() || !recent.is_empty(),
            "joined": mine,
            "recent_attendees": seen,
            // Told before a person publishes (CSD-134 §2). Streams are live only
            // until CIRISPersist#1067, so nothing in this room can be kept yet.
            "room_may_keep": {
                "allowed": false,
                "reason_id": "call.room_may_keep.not_yet",
                "says": "Calls aren't saved. Nobody in this room can keep a recording yet.",
            },
            // Calls do not ride the hidden connections (FSD/PRIVACY_MODES.md).
            "visible_to_watcher": {
                "visible": true,
                "reason_id": "call.visible_to_watcher.visible",
                "says": "Someone watching your network can see that you're on a call, not what's said.",
            },
            "save_state": "not_saved",
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct LayersBody {
    member: String,
    policy: serde_json::Value,
}

fn policy_of(v: &serde_json::Value) -> Option<ReceiverLayerPolicy> {
    if v.as_str() == Some("audio_only") {
        return Some(ReceiverLayerPolicy {
            max_spatial: 0,
            max_temporal: 0,
            max_quality: 0,
        });
    }
    let n = |k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_u64)
            .and_then(|x| u8::try_from(x).ok())
    };
    Some(ReceiverLayerPolicy {
        max_spatial: n("max_spatial")?,
        max_temporal: n("max_temporal")?,
        max_quality: n("max_quality")?,
    })
}

async fn layers(
    State(st): State<CallState>,
    headers: HeaderMap,
    Path(room): Path<String>,
    Json(b): Json<LayersBody>,
) -> Response {
    if let Err(r) = require_owner(&st, &headers).await {
        return r;
    }
    let Some(j) = current(&room) else {
        return refuse_with(
            StatusCode::CONFLICT,
            "call.not_joined",
            "Join the call first.",
            json!({}),
        );
    };
    let Some(policy) = policy_of(&b.policy) else {
        return refuse_with(
            StatusCode::BAD_REQUEST,
            "call.bad_layer_policy",
            "That quality setting isn't one this device understands.",
            json!({ "expected": "{max_spatial,max_temporal,max_quality} or \"audio_only\"" }),
        );
    };
    j.caps
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(b.member.clone(), policy);
    (
        StatusCode::OK,
        Json(json!({
            "member": b.member,
            "policy": {"max_spatial": policy.max_spatial, "max_temporal": policy.max_temporal,
                       "max_quality": policy.max_quality},
            // v1: filtered on arrival. edge 45.1 sends it to the publisher.
            "applied": "receive_filter",
            "saves": "decode and render on this device, not network",
        })),
    )
        .into_response()
}

fn admits(policy: Option<&ReceiverLayerPolicy>, layer: ChunkLayer) -> bool {
    policy.is_none_or(|p| {
        layer.spatial <= p.max_spatial
            && layer.temporal <= p.max_temporal
            && layer.quality <= p.max_quality
    })
}

fn event_json(e: &CallEvent) -> serde_json::Value {
    match e {
        CallEvent::AttendeeJoined { key_id } | CallEvent::MemberJoined { key_id } => {
            json!({ "type": "attendee_joined", "member": key_id })
        }
        CallEvent::MemberLeft { key_id } => {
            json!({ "type": "attendee_left", "member": key_id, "left": "left" })
        }
        CallEvent::EpochRolled { .. } => {
            json!({ "type": "epoch_rolled", "detail": format!("{e:?}") })
        }
        CallEvent::LoadTier { .. } => json!({ "type": "tier_changed", "detail": format!("{e:?}") }),
        CallEvent::KeepRefused { .. } => {
            json!({ "type": "keep_refused", "reason_id": "call.keep_refused" })
        }
        CallEvent::Stranded { .. } => json!({ "type": "stranded", "detail": format!("{e:?}") }),
        other => json!({ "type": "event", "detail": format!("{other:?}") }),
    }
}

#[derive(Deserialize, Default)]
struct SocketQuery {
    #[serde(default)]
    ticket: Option<String>,
}

async fn frames_socket(
    State(st): State<CallState>,
    headers: HeaderMap,
    Path(room): Path<String>,
    axum::extract::Query(q): axum::extract::Query<SocketQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    if !origin_ok(&headers) {
        return refuse_with(
            StatusCode::FORBIDDEN,
            "call.cross_origin",
            "This call can only be opened from this device's own page.",
            json!({}),
        );
    }
    let ticketed = q.ticket.as_deref().is_some_and(|t| spend_ticket(t, &room));
    if !ticketed {
        if let Err(r) = require_owner(&st, &headers).await {
            return r;
        }
    }
    let Some(j) = current(&room) else {
        return refuse_with(
            StatusCode::CONFLICT,
            "call.not_joined",
            "Join the call first.",
            json!({}),
        );
    };
    let frames = j
        .frames
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let events = j
        .events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let (Some(frames), Some(events)) = (frames, events) else {
        return refuse_with(
            StatusCode::CONFLICT,
            "call.socket_already_open",
            "This call already has a frames connection open.",
            json!({}),
        );
    };
    let engine = Arc::clone(&st.engine);
    ws.on_upgrade(move |socket| pump(socket, engine, room, j, frames, events))
}

async fn pump(
    socket: WebSocket,
    engine: Arc<Engine>,
    room: String,
    j: Arc<Joined>,
    mut frames: tokio::sync::mpsc::Receiver<ciris_edge::transport::av_call::ReceivedFrame>,
    mut events: tokio::sync::mpsc::Receiver<CallEvent>,
) {
    use futures_util::{SinkExt, StreamExt};
    let (mut tx, mut rx) = socket.split();
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Message>(256);

    // Node → client: frames (binary) and events (text), on one writer.
    let writer = tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if tx.send(m).await.is_err() {
                break;
            }
        }
    });
    let jf = Arc::clone(&j);
    let out_f = out_tx.clone();
    let frame_task = tokio::spawn(async move {
        while let Some(f) = frames.recv().await {
            let layer = f.layer;
            let cap = jf
                .caps
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&f.publisher)
                .copied();
            if !admits(cap.as_ref(), layer) {
                continue;
            }
            let incoming = Incoming {
                codec_id: f.codec_id,
                layer: (layer.spatial, layer.temporal, layer.quality),
                publisher: f.publisher.clone(),
                stream_id: f.stream.0,
                epoch: f.epoch.0,
                chunk_seq: f.chunk_seq.0,
                payload: f.bytes,
            };
            if let Ok(bytes) = call_frames::encode_incoming(&incoming) {
                if out_f.send(Message::Binary(bytes.into())).await.is_err() {
                    break;
                }
            }
        }
    });
    let out_e = out_tx.clone();
    let eng_e = Arc::clone(&engine);
    let event_task = tokio::spawn(async move {
        while let Some(e) = events.recv().await {
            let text = with_person(&eng_e, event_json(&e)).await.to_string();
            if out_e.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
    });

    // Readiness and leavers, from the call's own state (edge v44 has no
    // "attendee left" event): `ready {frame_budget_bytes}` once a leg is up and
    // again when the budget changes; `attendee_left {left: "lost"}` when a
    // member's leg has been gone for 5 s (edge's Down bound at depth 0; a failover can
    // take a leg for over 2 s). A client publishes only after `ready`.
    let jw = Arc::clone(&j);
    let out_w = out_tx.clone();
    let eng_w = Arc::clone(&engine);
    let watch_task = tokio::spawn(async move {
        let mut last_budget: Option<usize> = None;
        let mut legs_seen: HashMap<String, Option<std::time::Instant>> = HashMap::new();
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let (budget, legs) = {
                let g = jw.call.lock().await;
                match g.as_ref() {
                    Some(c) => (c.chunk_plaintext_budget(), c.legs()),
                    None => break,
                }
            };
            if budget.is_some() && budget != last_budget {
                last_budget = budget;
                // `fragmenting`: whether the node splits a frame over the budget
                // (edge 45.1) or refuses it (v44). The client switches on THIS.
                let m = json!({ "type": "ready", "frame_budget_bytes": budget,
                                "fragmenting": false });
                if out_w
                    .send(Message::Text(m.to_string().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            for l in &legs {
                legs_seen.insert(l.clone(), None);
            }
            let now = std::time::Instant::now();
            let mut gone = Vec::new();
            for (k, since) in &mut legs_seen {
                if legs.contains(k) {
                    continue;
                }
                match since {
                    None => *since = Some(now),
                    Some(t) if now.duration_since(*t) >= std::time::Duration::from_secs(5) => {
                        gone.push(k.clone());
                    }
                    Some(_) => {}
                }
            }
            for k in gone {
                legs_seen.remove(&k);
                let m = with_person(
                    &eng_w,
                    json!({ "type": "attendee_left", "member": k, "left": "lost" }),
                )
                .await;
                if out_w
                    .send(Message::Text(m.to_string().into()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    });

    // Client → node: publish each frame, refusing in a text event.
    let mut why = "lost";
    while let Some(msg) = rx.next().await {
        let bytes = match msg {
            Ok(Message::Binary(b)) => b,
            Ok(Message::Close(_)) => {
                why = "left";
                break;
            }
            Ok(_) => continue,
            Err(_) => break,
        };
        let refusal = match call_frames::decode_outgoing(&bytes) {
            Err(e) => Some(json!({ "type": "publish_refused", "reason": e.token() })),
            Ok(f) => {
                let mut guard = j.call.lock().await;
                match guard.as_mut() {
                    None => break,
                    Some(call) => {
                        let budget = call.chunk_plaintext_budget();
                        let frame = Frame {
                            codec_id: f.codec_id,
                            layer: ChunkLayer {
                                spatial: f.layer.0,
                                temporal: f.layer.1,
                                quality: f.layer.2,
                            },
                            bytes: f.payload,
                        };
                        match call.publish(frame).await {
                            Ok(_) => None,
                            Err(CallError::FrameTooLarge { .. }) => Some(json!({
                                "type": "publish_refused", "reason": "over_budget", "budget": budget })),
                            Err(e) => Some(json!({
                                "type": "publish_refused", "reason": "call_error", "detail": e.to_string() })),
                        }
                    }
                }
            }
        };
        if let Some(r) = refusal {
            let _ = out_tx.send(Message::Text(r.to_string().into())).await;
        }
    }
    // The socket closed: this device has left (CSD-134: a remote client's
    // socket close ends its stream).
    frame_task.abort();
    event_task.abort();
    watch_task.abort();
    drop(out_tx);
    let _ = writer.await;
    let _ = leave_room(&room, why).await;
}

/// `POST`/`DELETE /v1/chat/{room}/call/share`: a member's screen or window share,
/// a second stream that replaces nothing (CC; edge 45.1 `Call::add_stream`). Until
/// that pin it is refused by name, so the client tells "not on this node yet" from
/// a missing route. The contract is agreed (CSD-134): POST answers
/// `{stream_id, frames_ticket, frame_budget_bytes}`; the share's outgoing frames go
/// on `WS …/call/share/frames`, which also sends `ready`; receivers get
/// `share_started` / `share_stopped` (with `person`) on their main socket.
async fn share(
    State(st): State<CallState>,
    headers: HeaderMap,
    Path(_room): Path<String>,
) -> Response {
    if let Err(r) = require_owner(&st, &headers).await {
        return r;
    }
    refuse_with(
        StatusCode::NOT_IMPLEMENTED,
        "call.share_unavailable",
        "Sharing your screen isn't available on this node yet.",
        json!({ "needs": "edge 45.1 (Call::add_stream)" }),
    )
}

/// The member call routes. Mounted on every node; each route is the owner's.
pub fn router(engine: Arc<Engine>, edge: Arc<Edge>) -> Router {
    if let Ok(h) = tokio::runtime::Handle::try_current() {
        let _ = runtime().set(h);
    }
    Router::new()
        .route(
            "/v1/chat/{room}/call",
            axum::routing::post(join).delete(leave).get(state),
        )
        .route(
            "/v1/chat/{room}/call/frames",
            axum::routing::get(frames_socket),
        )
        .route("/v1/chat/{room}/call/layers", axum::routing::post(layers))
        .route(
            "/v1/chat/{room}/call/share",
            axum::routing::post(share).delete(share),
        )
        .with_state(CallState { engine, edge })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audio_only_admits_only_the_base_layer() {
        let p = policy_of(&json!("audio_only")).unwrap();
        assert!(admits(
            Some(&p),
            ChunkLayer {
                spatial: 0,
                temporal: 0,
                quality: 0
            }
        ));
        assert!(!admits(
            Some(&p),
            ChunkLayer {
                spatial: 1,
                temporal: 0,
                quality: 0
            }
        ));
        assert!(
            admits(
                None,
                ChunkLayer {
                    spatial: 3,
                    temporal: 3,
                    quality: 3
                }
            ),
            "no cap, no filter"
        );
    }

    #[test]
    fn a_policy_names_all_three_layers_or_is_refused() {
        assert!(
            policy_of(&json!({"max_spatial": 1, "max_temporal": 2, "max_quality": 0})).is_some()
        );
        assert!(policy_of(&json!({"max_spatial": 1})).is_none());
        assert!(
            policy_of(&json!({"max_spatial": 300, "max_temporal": 0, "max_quality": 0})).is_none()
        );
    }

    #[test]
    fn a_ticket_is_spent_once_and_only_for_its_room() {
        let t = issue_ticket("room-a");
        assert!(!spend_ticket(&t, "room-b"), "another room");
        let t = issue_ticket("room-a");
        assert!(spend_ticket(&t, "room-a"));
        assert!(!spend_ticket(&t, "room-a"), "single use");
        assert!(!spend_ticket("not-a-ticket", "room-a"));
    }

    #[test]
    fn a_browser_must_come_from_this_node() {
        let mut h = HeaderMap::new();
        assert!(origin_ok(&h), "a native client sends no Origin");
        h.insert(axum::http::header::HOST, "127.0.0.1:4243".parse().unwrap());
        h.insert(
            axum::http::header::ORIGIN,
            "http://127.0.0.1:4243".parse().unwrap(),
        );
        assert!(origin_ok(&h));
        h.insert(
            axum::http::header::ORIGIN,
            "https://evil.example".parse().unwrap(),
        );
        assert!(!origin_ok(&h));
    }

    #[test]
    fn events_carry_a_type_and_the_member_and_no_name() {
        let v = event_json(&CallEvent::MemberLeft { key_id: "k".into() });
        assert_eq!(v["type"], "attendee_left");
        assert_eq!(v["member"], "k");
        assert_eq!(v["left"], "left");
        assert!(v.get("name").is_none() && v.get("display_name").is_none());
    }
}
