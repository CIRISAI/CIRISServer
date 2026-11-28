//! **Calls in a room, as the member** (CIRISServer#859, 0.5.246).
//!
//! The production call surface the client builds against (CIRISClient
//! `FSD/CSD/CSD-134-calls.md`, PR #287). The QA routes (`crate::qa_call`) stay as
//! the harness door; these join AS THE PERSON, carry the client's own encoded
//! frames, and refuse in words.
//!
//! - `POST /v1/chat/{room}/call` `{video?, relay?}`: join. `relay` omitted is
//!   the node's choice ([`relay_default`]): never on a serve seat (edge refuses
//!   to relay call media there anyway), never on a phone build, and **on** for
//!   any other member node ([`RELAY_DEFAULT_MEMBER`]; the av_mesh relay matrix on
//!   edge 45.2.0 is its release gate, evidence/av/av_mesh.jsonl). A client on a
//!   metered network sends `relay: false`; on an unmetered phone, `relay: true`.
//! - `POST /v1/chat/{room}/call/relay` `{relay}`: start or stop relaying others'
//!   streams live (edge `Call::set_relay`); answers the relay status.
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

use ciris_edge::transport::av_call::{
    Call, CallError, CallEvent, CallOptions, CallState as EdgeCallState, EndCause, Frame,
};
use ciris_edge::transport::av_chunk_auth::SignedEnd;
use ciris_edge::transport::media_path::PathKind;
use ciris_edge::transport::realtime_av::{ChunkLayer, ReceiverLayerPolicy, StreamId};
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

/// What a call event is a state OF: two events with one key are two states of
/// the same thing, and only the later one is worth telling a client that has
/// not read the first. Streams are keyed by STREAM, not member: a member has a
/// camera stream and a screen share, and losing the share's end would leave it
/// on screen. `None`: a one-off notice, kept in order.
fn event_key(e: &CallEvent) -> Option<(u8, String, [u8; 32])> {
    const NO: [u8; 32] = [0; 32];
    match e {
        CallEvent::RelayStatus { .. } => Some((1, String::new(), NO)),
        CallEvent::LoadTier { .. } => Some((2, String::new(), NO)),
        CallEvent::MediaPathFailed { member, .. } | CallEvent::MediaPathRestored { member, .. } => {
            Some((3, member.clone(), NO))
        }
        CallEvent::StreamAdded {
            publisher, stream, ..
        }
        | CallEvent::StreamEnded {
            publisher, stream, ..
        } => Some((4, publisher.clone(), stream.0)),
        CallEvent::VideoUnavailable { publisher, .. } | CallEvent::VideoRestored { publisher } => {
            Some((5, publisher.clone(), NO))
        }
        CallEvent::AttendeeJoined { key_id } | CallEvent::AttendeeLeft { key_id, .. } => {
            Some((6, key_id.clone(), NO))
        }
        CallEvent::MemberJoined { key_id } | CallEvent::MemberLeft { key_id } => {
            Some((7, key_id.clone(), NO))
        }
        _ => None,
    }
}

/// The most one-off notices kept for a client that is not reading.
const MAX_WAITING_NOTICES: usize = 256;

/// The call's events, read from edge from the moment of the join by a task that
/// never waits on the client. Edge's channel holds 64 and DROPS what does not
/// fit (edge 2026-11-25), and the frames socket's writer waits on a slow or
/// backgrounded client, and nothing read at all before a socket opened, so a
/// `StreamEnded` could be lost after its `StreamAdded` was shown.
#[derive(Default)]
struct EventBox {
    waiting: StdMutex<std::collections::VecDeque<CallEvent>>,
    arrived: tokio::sync::Notify,
    closed: std::sync::atomic::AtomicBool,
}

impl EventBox {
    /// Start reading `events` into a new box.
    fn read(mut events: tokio::sync::mpsc::Receiver<CallEvent>) -> Arc<Self> {
        let b = Arc::new(Self::default());
        let me = Arc::clone(&b);
        tokio::spawn(async move {
            while let Some(e) = events.recv().await {
                me.put(e);
            }
            me.closed.store(true, std::sync::atomic::Ordering::Release);
            me.arrived.notify_one();
        });
        b
    }

    fn put(&self, e: CallEvent) {
        let key = event_key(&e);
        let mut q = self
            .waiting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match key {
            Some(_) => q.retain(|w| event_key(w) != key),
            None => {
                if q.iter().filter(|w| event_key(w).is_none()).count() >= MAX_WAITING_NOTICES {
                    if let Some(i) = q.iter().position(|w| event_key(w).is_none()) {
                        q.remove(i);
                    }
                }
            }
        }
        q.push_back(e);
        drop(q);
        self.arrived.notify_one();
    }

    /// The next event; `None` once the call's events have ended and all are read.
    async fn next(&self) -> Option<CallEvent> {
        loop {
            let closed = self.closed.load(std::sync::atomic::Ordering::Acquire);
            let e = self
                .waiting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front();
            if e.is_some() {
                return e;
            }
            if closed {
                return None;
            }
            self.arrived.notified().await;
        }
    }
}

/// One joined call on this node: the call itself, its frames and its events
/// (each taken once, by the frames socket), and the receive caps the layers
/// route set.
struct Joined {
    call: tokio::sync::Mutex<Option<Call>>,
    frames: StdMutex<
        Option<tokio::sync::mpsc::Receiver<ciris_edge::transport::av_call::ReceivedFrame>>,
    >,
    events: StdMutex<Option<Arc<EventBox>>>,
    caps: StdMutex<HashMap<String, ReceiverLayerPolicy>>,
    video: bool,
    /// Whether video and screen share may be published now: the call has at
    /// most [`VIDEO_MAX_PEOPLE`] people (see [`video_allowed`]).
    video_ok: std::sync::atomic::AtomicBool,
    /// This device's live screen or window share, a second own stream
    /// (`Call::add_stream`), while one is up.
    share: StdMutex<Option<StreamId>>,
    /// Non-zero once [`hold_to_call_size`] found the call too big: the people
    /// it counted.
    full: std::sync::atomic::AtomicUsize,
    /// Ringing's notices for this caller's socket (`ringing`, `declined`,
    /// `no_answer`; `call_ring`), sent by the watch loop.
    ring_notices: StdMutex<Vec<serde_json::Value>>,
}

/// Queue a ringing notice for this node's call socket in `room`.
pub fn notify_caller(room: &str, v: serde_json::Value) {
    if let Some(j) = current(room) {
        j.ring_notices
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(v);
    }
}

/// The attendees of this node's call in `room`, or `None` when it is in no
/// call there.
pub async fn attendees_of(room: &str) -> Option<Vec<String>> {
    let j = current(room)?;
    let g = j.call.lock().await;
    Some(g.as_ref()?.attendees().await)
}

/// The person a node belongs to (cached), for ringing.
pub async fn person_of_node(engine: &Engine, node: &str) -> Option<String> {
    person_of(engine, node).await
}

/// **Video only between two people, on edge v45.0.0** (Eric, 2026-11-10: "Yes
/// enforce it, above 2 drop to audio only"). v45.0.0 has no keyframe request
/// and fans a keyframe out unpaced to every receiver, so room video freezes
/// under ordinary loss; a two-person call has no fan-out. Audio is allowed at
/// any size. Counted in PEOPLE (distinct persons; one person's phone and
/// laptop are one), in the CALL, not the room. Above it, the frames socket
/// refuses non-audio frames (`publish_refused {reason: "video_two_people_only"}`)
/// and a `video_allowed` event says so; back at two, video may resume (the
/// client resumes it if the person's camera is still on). Lifted at edge v45.1.
pub const VIDEO_MAX_PEOPLE: usize = 2;

/// The people in `call`: its attendees' persons, and this node's own person.
async fn people_in_call(engine: &Engine, call: &Call) -> usize {
    let mut people = std::collections::BTreeSet::new();
    for m in call.attendees().await {
        people.insert(person_of(engine, &m).await.unwrap_or(m));
    }
    if let Some(node) = crate::node_key::wire_identity() {
        people.insert(
            person_of(engine, node)
                .await
                .unwrap_or_else(|| node.to_owned()),
        );
    }
    people.len()
}

/// Whether video may be published in a call of `people` people.
#[must_use]
pub const fn video_allowed(people: usize) -> bool {
    people <= VIDEO_MAX_PEOPLE
}

/// **A call holds at most four people on edge 45.2.0** (Eric 2026-11-25:
/// "limit it to 4 and tag"). The av_mesh matrix on edge 45.2.0 met every bar
/// at four members (250 and 300 kbit/s) and failed at six: under a capped
/// uplink six members heard 0.69-0.82 of the capped publisher and links were
/// torn down, and one six-member call never formed (evidence/av/av_mesh.jsonl;
/// edge's 45.2.1 work list). A room still seats six: the limit is on who is IN
/// THE CALL, counted in people like [`VIDEO_MAX_PEOPLE`] (one person's phone
/// and laptop are one).
pub const CALL_MAX_PEOPLE: usize = 4;

/// Whether a call of `people` (this device's person included) is within
/// [`CALL_MAX_PEOPLE`].
#[must_use]
pub const fn call_has_room(people: usize) -> bool {
    people <= CALL_MAX_PEOPLE
}

/// How long after its own join a node checks that it did not make the call too
/// big. Attendance is learned from legs and stream bindings as they arrive, so
/// a joiner cannot know the count at the moment it joins; within this window a
/// node that finds more than [`CALL_MAX_PEOPLE`] people leaves, and the
/// members who were there first never do. Two people joining the same full
/// call in the same seconds may both be turned away; joining again works.
pub const CALL_FULL_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);

/// The `call_ended` a node sends before it leaves a call it made too big.
#[must_use]
pub fn call_full_json(people: usize) -> serde_json::Value {
    json!({ "type": "call_ended", "ended": "call_full", "reason_id": "call.full",
            "max_people": CALL_MAX_PEOPLE, "people": people })
}

/// The server's own end for a call that rang [`crate::call_ring::RING_TIMEOUT`]
/// with nobody joining: the node leaves it, and the socket says so in words.
pub fn no_answer_ended_json() -> serde_json::Value {
    json!({ "type": "call_ended", "ended": "no_answer", "reason_id": "call.no_answer" })
}

/// Watch a call this node just joined for [`CALL_FULL_WINDOW`]: if it holds
/// more than [`CALL_MAX_PEOPLE`] people, tell the socket (it sends
/// [`call_full_json`] and closes) and leave.
async fn hold_to_call_size(engine: Arc<Engine>, room: String, mine: Arc<Joined>) {
    let until = tokio::time::Instant::now() + CALL_FULL_WINDOW;
    while tokio::time::Instant::now() < until {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        match current(&room) {
            Some(j) if Arc::ptr_eq(&j, &mine) => {}
            _ => return,
        }
        let people = {
            let g = mine.call.lock().await;
            match g.as_ref() {
                Some(c) => people_in_call(&engine, c).await,
                None => return,
            }
        };
        if !call_has_room(people) {
            mine.full
                .store(people, std::sync::atomic::Ordering::Release);
            tracing::info!(room = %room, people, max = CALL_MAX_PEOPLE,
                "call: full; this device joined last and leaves");
            // Give the socket's watch a tick to say why before the call goes.
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            if matches!(current(&room), Some(j) if Arc::ptr_eq(&j, &mine)) {
                let _ = leave_room(&room, "left").await;
            }
            return;
        }
    }
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

/// The other people of `room` and their nodes, as this node holds them. Room
/// members are PERSON keys (people join rooms, not nodes); a member that is a
/// node (the QA door) stands for its owner. This node and its own person are
/// left out. A person with no node held here has an empty list.
pub async fn room_people(engine: &Engine, room: &str) -> Vec<(String, Vec<String>)> {
    let Some(me) = crate::node_key::wire_identity().map(str::to_owned) else {
        return Vec::new();
    };
    let members = match crate::mls_state::groups_for(&me).open_existing(room).await {
        Ok(Some(g)) => g.member_key_ids().await,
        _ => return Vec::new(),
    };
    let my_person = person_of(engine, &me).await;
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for m in members {
        let owner = person_of(engine, &m).await;
        let person = owner.clone().unwrap_or_else(|| m.clone());
        if m == me || my_person.as_deref() == Some(person.as_str()) {
            continue;
        }
        let mut nodes = crate::peer::bound_nodes_of(engine, &person)
            .await
            .unwrap_or_default();
        if owner.is_some() && !nodes.contains(&m) {
            nodes.push(m.clone());
        }
        nodes.retain(|n| *n != me);
        match out.iter_mut().find(|(p, _)| *p == person) {
            Some((_, ns)) => {
                for n in nodes {
                    if !ns.contains(&n) {
                        ns.push(n);
                    }
                }
            }
            None => out.push((person, nodes)),
        }
    }
    out
}

/// Whether each other person in `room` can be heard from, as THIS node sees
/// it: a warning for "you are calling someone whose device is offline", never
/// a refusal. One entry per person: `{member, person, nodes, in_call,
/// last_heard_ms_ago, reachable_now}` (`member` = `person`, the room member's
/// key). `last_heard_ms_ago` is the newest row held here that the person or
/// one of their nodes signed (null: none held). `reachable_now` is edge's
/// live reach reading (CIRISEdge 45.3 `peer_reach`); until the node runs on
/// it, null = unknown.
pub async fn reach_view(engine: &Engine, room: &str, attendees: &[String]) -> serde_json::Value {
    let now = chrono::Utc::now();
    let mut out = Vec::new();
    for (person, nodes) in room_people(engine, room).await {
        let heard = crate::contacts_chat::last_heard_from(engine, &person, &nodes).await;
        let ago = heard.map(|at| u64::try_from((now - at).num_milliseconds()).unwrap_or(0));
        let in_call = attendees.contains(&person) || nodes.iter().any(|n| attendees.contains(n));
        out.push(json!({
            "member": person,
            "person": person,
            "nodes": nodes,
            "in_call": in_call,
            "last_heard_ms_ago": ago,
            "reachable_now": serde_json::Value::Null,
        }));
    }
    json!({ "view": "this_node", "members": out })
}

/// How long after the socket opens, with no `ready`, `connecting` is sent again.
pub const CONNECTING_AGAIN_AFTER: std::time::Duration = std::time::Duration::from_secs(20);

/// `{type: connecting, members, since_ms, reach}`: `members` are the room's
/// other people (who the call waits on), `since_ms` the unix ms the socket
/// opened.
async fn connecting_json(
    engine: &Engine,
    room: &str,
    attendees: &[String],
    since_ms: i64,
) -> serde_json::Value {
    connecting_from(reach_view(engine, room, attendees).await, since_ms)
}

fn connecting_from(reach: serde_json::Value, since_ms: i64) -> serde_json::Value {
    let members: Vec<serde_json::Value> = reach["members"]
        .as_array()
        .map(|a| a.iter().map(|m| m["member"].clone()).collect())
        .unwrap_or_default();
    json!({ "type": "connecting", "members": members, "since_ms": since_ms, "reach": reach })
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
    if let Some(t) = v
        .get("through")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
    {
        v["through_person"] = json!(person_of(engine, &t).await);
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
            json!({ "detail": e.to_string(), "token": "onion_anonymous_no_media" }),
        ),
        // Edge 45.2.0: calls ride unshaped links, so a device set to shaped
        // links only starts, joins and accepts no call. Direct links stay.
        CallError::ShapedOnly => refuse_with(
            StatusCode::FORBIDDEN,
            "call.shaped_only",
            "Calls aren't available while this device is set to \"Always hide when I talk\".",
            json!({ "detail": e.to_string(), "token": "shaped_only_no_media" }),
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
    /// Omitted: the node decides ([`relay_default`]). A client on a metered
    /// network sends `false` unless the person opted in; a phone must say
    /// `true` to relay.
    #[serde(default)]
    relay: Option<bool>,
    /// How opening this call alerts the room: `open`, `notify` or `ring`
    /// (`call_ring::Alert`). Omitted: ring a room of at most
    /// [`CALL_MAX_PEOPLE`] people, notify a bigger one. Only the opener's
    /// counts; joining a live call alerts nobody.
    #[serde(default)]
    alert: Option<String>,
}

/// The codecs a video stream (a camera, or a share) is bound to: AV1 under
/// 0x01, H.264 under 0x04 and Opus under 0xFF, the ids every client handles
/// (tests/vectors/call_frames_v1.json). A map naming a video class makes edge
/// FRAME the stream: a frame over the chunk budget is split into marked
/// fragments and rejoined at each receiver. With no map (0.5.246-0.5.253) a
/// video frame had to fit one chunk, a few hundred bytes, so a real camera's
/// frames were refused `over_budget`.
fn video_codecs() -> Option<ciris_edge::transport::av_chunk_auth::CodecMap> {
    use ciris_edge::transport::av_chunk_auth::{CodecMap, CodecToken};
    CodecMap::new([CodecToken::Av1, CodecToken::H264, CodecToken::Opus]).ok()
}

/// Whether a member node relays others' call streams when its client did not
/// say (Eric 2026-11-22: on by default, phones on mobile or metered data opt
/// in). The release gate for `true` is the av_mesh relay matrix (N=4/6 x
/// 250/300 kbit) on edge 45.2.0; flipping it changes no wire shape.
pub const RELAY_DEFAULT_MEMBER: bool = true;

/// A phone build. It cannot tell here whether its network is metered, so a
/// client that says nothing (every client before the `relay` field) is taken
/// as not opted in: the client sends `relay: true` on an unmetered network.
pub const PHONE: bool = cfg!(any(target_os = "android", target_os = "ios"));

/// The relay choice for a join with no `relay`: never on a serve seat (edge
/// 45.2.0 refuses to relay call media there whatever it is told), never on a
/// phone that did not say.
pub const fn relay_default(serve_seat: bool, phone: bool) -> bool {
    !serve_seat && !phone && RELAY_DEFAULT_MEMBER
}

/// Whether this node is a serve seat (a canonical): it takes no call media.
/// Unknown counts as one, so a node that cannot tell never offers to relay.
async fn is_serve_seat(engine: &Engine) -> bool {
    match crate::node_key::wire_identity() {
        Some(me) => engine.is_canonical(me).await.unwrap_or(true),
        None => true,
    }
}

/// The distinct people `children` belong to; an unbound node is its own.
async fn people_count(engine: &Engine, children: &[String]) -> usize {
    let mut people = std::collections::HashSet::new();
    for c in children {
        people.insert(person_of(engine, c).await.unwrap_or_else(|| c.clone()));
    }
    people.len()
}

/// The relay status a client shows ("relaying for N people"): `relaying_for`
/// counts PEOPLE, mapped from edge's child nodes; `relaying_for_nodes` is
/// edge's own count.
async fn relay_view(engine: &Engine, call: &Call, serve_seat: bool) -> serde_json::Value {
    let (relaying, nodes) = call.relay_status();
    let children: Vec<String> = call.relayed_to().into_iter().map(|r| r.child).collect();
    json!({
        "relaying": relaying,
        "relaying_for": people_count(engine, &children).await,
        "relaying_for_nodes": nodes,
        "serve_seat": serve_seat,
    })
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
    let asked_alert = match body.alert.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(w) => match crate::call_ring::Alert::parse(w) {
            Some(a) => Some(a),
            None => {
                return refuse_with(
                    StatusCode::BAD_REQUEST,
                    "call.alert_unknown",
                    "That isn't a way of letting the room know about a call.",
                    json!({ "accepted": ["open", "notify", "ring"] }),
                )
            }
        },
    };
    let serve_seat = is_serve_seat(&st.engine).await;
    let relay = !serve_seat
        && body
            .relay
            .unwrap_or_else(|| relay_default(serve_seat, PHONE));
    let opts = CallOptions {
        relay,
        // Audio-only stays unframed (one Opus packet per chunk).
        codecs: if body.video { video_codecs() } else { None },
        ..CallOptions::default()
    };
    let mut call = match st.edge.join_call_as(&room, opts, actor).await {
        Ok(c) => c,
        Err(e) => return refuse_call(&e),
    };
    let frames = call.frames();
    let events = call.events().map(EventBox::read);
    let people_now = people_in_call(&st.engine, &call).await;
    if !call_has_room(people_now) {
        let _ = call.leave_with(SignedEnd::Left).await;
        return refuse_with(
            StatusCode::CONFLICT,
            "call.full",
            "This call already has 4 people, the most a call can have.",
            json!({ "max_people": CALL_MAX_PEOPLE, "people": people_now - 1 }),
        );
    }
    let video_ok = video_allowed(people_now);
    let mut view = join_view(&st.engine, &room, &call, body.video, false).await;
    // Ringing (`call_ring`): this device answering a ring stops it ringing
    // here; a call nobody else is in yet rings the room.
    crate::call_ring::answered_here(&room);
    // Attendance rows are authored by the PERSON, so "nobody else is in it"
    // means no attendee but this node or its own person.
    let me = crate::node_key::wire_identity().unwrap_or_default();
    let my_person = person_of(&st.engine, me).await;
    let first = call
        .attendees()
        .await
        .iter()
        .all(|m| m == me || my_person.as_deref() == Some(m.as_str()));
    let call_id = hex::encode(call.id().0);
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
                video_ok: std::sync::atomic::AtomicBool::new(video_ok),
                share: StdMutex::new(None),
                full: std::sync::atomic::AtomicUsize::new(0),
                ring_notices: StdMutex::new(Vec::new()),
            }),
        );
    // The alert mode: the opener's choice, or the room's size.
    let alert = if first {
        let in_room = room_people(&st.engine, &room).await.len() + 1;
        let a = asked_alert.unwrap_or_else(|| crate::call_ring::Alert::default_for(in_room));
        crate::call_ring::start(
            Arc::clone(&st.edge),
            Arc::clone(&st.engine),
            room.clone(),
            call_id,
            body.video,
            a,
        );
        Some(a.token())
    } else {
        None
    };
    // null: this device joined a call already live, and alerted nobody.
    view["alert"] = json!(alert);
    if let Some(mine) = current(&room) {
        tokio::spawn(hold_to_call_size(
            Arc::clone(&st.engine),
            room.clone(),
            mine,
        ));
    }
    tracing::info!(room = %room, relay, serve_seat, video = body.video, "call: joined as the member");
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
    let video_ok = video_allowed(people_in_call(engine, call).await);
    json!({
        // Video and screen share may be sent now (VIDEO_MAX_PEOPLE).
        "video_allowed": video_ok,
        "video_max_people": VIDEO_MAX_PEOPLE,
        "room": room,
        "already_joined": already,
        "call_id": hex::encode(call.id().0),
        "stream_id": hex::encode(call.stream().0),
        "epoch": call.epoch().await.0,
        "video": video,
        // null until a leg is up; the socket's `ready` carries it then.
        "frame_budget_bytes": call.chunk_plaintext_budget(),
        "service_tier": call.service_tier().token(),
        "state": state_view(&call.state()),
        "attendees": attendees,
        "attendee_people": people,
        "reach": reach_view(engine, room, &attendees).await,
        "legs": call.legs(),
        "relay": relay_view(engine, call, is_serve_seat(engine).await).await,
        "frames_socket": format!("/v1/chat/{room}/call/frames"),
        // Browsers: open the socket with `?ticket=<this>` (single use, 30 s).
        "frames_ticket": issue_ticket(room),
    })
}

#[derive(serde::Deserialize, Default)]
struct LeaveQuery {
    #[serde(default)]
    left: Option<String>,
}

/// The reasons a client may give for leaving. `lost` is never given: it is what
/// the node says when a leg vanished without one.
fn leave_reason(q: Option<&str>) -> Option<&'static str> {
    match q.map(str::trim) {
        None | Some("" | "left") => Some("left"),
        Some("backgrounded") => Some("backgrounded"),
        Some(_) => None,
    }
}

/// `DELETE /v1/chat/{room}/call?left=left|backgrounded`. The reason is what the
/// others are told (CSD-134). On edge v44 it reaches only this node's log and
/// answer; edge v45's `leave_with` signs it into the end of this node's stream,
/// so the others' `attendee_left` carries it.
async fn leave(
    State(st): State<CallState>,
    headers: HeaderMap,
    Path(room): Path<String>,
    axum::extract::Query(q): axum::extract::Query<LeaveQuery>,
) -> Response {
    if let Err(r) = require_owner(&st, &headers).await {
        return r;
    }
    let Some(why) = leave_reason(q.left.as_deref()) else {
        return refuse_with(
            StatusCode::BAD_REQUEST,
            "call.leave_reason_unknown",
            "That isn't a reason for leaving a call.",
            json!({ "accepted": ["left", "backgrounded"] }),
        );
    };
    match leave_room(&room, why).await {
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
    let summary = call.leave_with(signed_end(why)).await.ok();
    tracing::info!(room, why, "call: left");
    Some(json!({
        "room": room,
        "left": why,
        "stream_id": stream,
        "summary": summary.map(|s| format!("{s:?}")),
    }))
}

/// The signed end a leave carries. `lost` is this node's word for a device
/// whose socket vanished; the node itself is still here and ends the stream,
/// so the others are told `left`.
fn signed_end(why: &str) -> SignedEnd {
    match why {
        "backgrounded" => SignedEnd::Backgrounded,
        _ => SignedEnd::Left,
    }
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
                    "reach": reach_view(&st.engine, &room, &c.attendees().await).await,
                    "stream_id": hex::encode(c.stream().0),
                    "state": state_view(&c.state()),
                    "frame_budget_bytes": c.chunk_plaintext_budget(),
                    "service_tier": c.service_tier().token(),
                    "attendees": c.attendees().await,
                    "legs": c.legs(),
                    "relay": relay_view(&st.engine, c, is_serve_seat(&st.engine).await).await,
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
struct RelayBody {
    relay: bool,
}

/// `POST /v1/chat/{room}/call/relay` `{relay}`: relay others' streams or stop,
/// live. A serve seat stays off (edge's rule) and says `serve_seat: true`.
async fn set_relay(
    State(st): State<CallState>,
    headers: HeaderMap,
    Path(room): Path<String>,
    Json(body): Json<RelayBody>,
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
    let g = j.call.lock().await;
    let Some(c) = g.as_ref() else {
        return refuse_with(
            StatusCode::CONFLICT,
            "call.not_joined",
            "Join the call first.",
            json!({}),
        );
    };
    let serve_seat = is_serve_seat(&st.engine).await;
    c.set_relay(body.relay && !serve_seat).await;
    tracing::info!(room = %room, relay = body.relay, serve_seat, "call: relay set");
    let mut v = relay_view(&st.engine, c, serve_seat).await;
    v["room"] = json!(room);
    (StatusCode::OK, Json(v)).into_response()
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
        // The room dropped a member: it is out of the call too.
        CallEvent::MemberLeft { key_id } => {
            json!({ "type": "attendee_left", "member": key_id, "left": "removed" })
        }
        CallEvent::AttendeeLeft {
            key_id,
            stream,
            cause,
            truncated,
        } => json!({
            "type": "attendee_left",
            "member": key_id,
            "stream_id": hex::encode(stream.0),
            "left": cause.token(),
            "truncated": truncated,
        }),
        CallEvent::StreamAdded {
            publisher,
            stream,
            kind,
        } => json!({
            "type": "stream_added",
            "member": publisher,
            "stream_id": hex::encode(stream.0),
            // CC rc18: 0 media, 1 share; an unknown value renders as media.
            "kind": if *kind == 1 { "share" } else { "media" },
        }),
        CallEvent::StreamEnded {
            publisher,
            stream,
            cause,
            truncated,
        } => json!({
            "type": "stream_ended",
            "member": publisher,
            "stream_id": hex::encode(stream.0),
            "ended": cause.token(),
            "truncated": truncated,
        }),
        CallEvent::StreamReplaced {
            publisher,
            old,
            new,
        } => json!({
            "type": "stream_replaced",
            "member": publisher,
            "old_stream_id": hex::encode(old.0),
            "new_stream_id": hex::encode(new.0),
        }),
        CallEvent::VideoUnavailable { publisher, reason } => json!({
            "type": "video_unavailable",
            "member": publisher,
            "reason_id": format!("call.{reason}"),
        }),
        CallEvent::VideoRestored { publisher } => {
            json!({ "type": "video_restored", "member": publisher })
        }
        CallEvent::EpochRolled { to, .. } => json!({ "type": "epoch_rolled", "epoch": to }),
        CallEvent::LoadTier { tier } => json!({ "type": "tier_changed", "tier": tier }),
        CallEvent::KeepRefused { .. } => {
            json!({ "type": "keep_refused", "reason_id": "call.keep_refused" })
        }
        CallEvent::Stranded { epoch, reason } => {
            json!({ "type": "stranded", "epoch": epoch, "reason": reason })
        }
        // Edge 45.2.0 (docs/calls_relay_tokens.md): `relaying_for` is edge's
        // NODE count here; the socket replaces it with people (`relay_view`).
        CallEvent::RelayStatus {
            relaying,
            relaying_for,
        } => json!({
            "type": "relay_status",
            "relaying": relaying,
            "relaying_for": relaying_for,
            "relaying_for_nodes": relaying_for,
            "serve_seat": false,
        }),
        // `through` is a node key id (the attendee `member` id space);
        // `through_person` is filled by `with_person`.
        CallEvent::MediaPathRestored {
            member,
            via,
            through,
        } => json!({
            "type": "media_path_restored",
            "member": member,
            "via": via.token(),
            "direct": *via != PathKind::PeerRelay,
            "through": through,
            "through_person": serde_json::Value::Null,
        }),
        // The person sees the real reason (Eric 2026-11-21): `cause` and
        // `relay` pass through verbatim, each with its copy key; the rest is
        // the "?" panel's, in edge's serde form.
        CallEvent::MediaPathFailed {
            member,
            cause,
            retryable,
            retry_after_s,
            detail,
            tried,
            local_nat,
            peer_nat,
            relay,
        } => json!({
            "type": "media_path_failed",
            "member": member,
            "cause": cause.token(),
            "reason_id": format!("call.media_path_failed.{}", cause.token()),
            "retryable": retryable,
            "retry_after_s": retry_after_s,
            "relay": relay.token(),
            "relay_reason_id": format!("call.relay_standing.{}", relay.token()),
            "diag": {
                "detail": detail.map(|d| d.token()),
                "tried": tried,
                "local_nat": local_nat,
                "peer_nat": peer_nat,
            },
        }),
        other => json!({ "type": "event", "detail": format!("{other:?}") }),
    }
}

/// The token and copy key of a call's end (edge `EndCause`). A media refusal
/// mid-call keeps the join refusal's copy (edge: "the same copy as the
/// refusal"); `call.ended` is the CONFLICT string, so ends are `call.end.*`.
pub fn end_ids(cause: &EndCause) -> (&'static str, &'static str) {
    match cause {
        EndCause::HungUp => ("hung_up", "call.end.hung_up"),
        EndCause::Revoked => ("revoked", "call.end.revoked"),
        EndCause::Expired => ("expired", "call.end.expired"),
        EndCause::MediaRefused { token } => (
            token,
            if *token == "shaped_only_no_media" {
                "call.shaped_only"
            } else {
                "call.anonymous_mode"
            },
        ),
    }
}

/// The `call_ended` socket event.
/// A call's state as tokens: `{state: "live"}`, `{state: "degraded", epoch,
/// reason}` or `{state: "ended", ended, reason_id}` (the `call_ended` ids).
pub fn state_view(state: &EdgeCallState) -> serde_json::Value {
    match state {
        EdgeCallState::Live => json!({ "state": "live" }),
        EdgeCallState::Degraded { epoch, reason } => {
            json!({ "state": "degraded", "epoch": epoch, "reason": reason })
        }
        EdgeCallState::Ended(cause) => {
            let (token, id) = end_ids(cause);
            json!({ "state": "ended", "ended": token, "reason_id": id })
        }
    }
}

pub fn ended_json(cause: &EndCause) -> serde_json::Value {
    let (token, id) = end_ids(cause);
    json!({ "type": "call_ended", "ended": token, "reason_id": id })
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
    events: Arc<EventBox>,
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
                // Edge v45: the publisher's signed source time (the lip-sync
                // clock) and, on a framed stream, the per-class frame counter.
                source_ts_ms: f.source_ts_ms,
                frame_seq: f.frame_seq,
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
    let je = Arc::clone(&j);
    let event_task = tokio::spawn(async move {
        let serve_seat = is_serve_seat(&eng_e).await;
        // The shares this socket has announced, so their end is a
        // `share_stopped` too (CSD-134).
        let mut shares: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        while let Some(e) = events.next().await {
            let mut out = vec![event_json(&e)];
            if matches!(e, CallEvent::RelayStatus { .. }) {
                let g = je.call.lock().await;
                if let Some(c) = g.as_ref() {
                    let mut v = relay_view(&eng_e, c, serve_seat).await;
                    v["type"] = json!("relay_status");
                    out[0] = v;
                }
            }
            match &e {
                CallEvent::StreamAdded {
                    publisher, stream, ..
                } if share_kind(&e) => {
                    shares.insert(stream.0);
                    out.push(json!({ "type": "share_started", "member": publisher,
                                     "stream_id": hex::encode(stream.0) }));
                }
                CallEvent::StreamEnded {
                    publisher, stream, ..
                } if shares.remove(&stream.0) => {
                    out.push(json!({ "type": "share_stopped", "member": publisher,
                                     "stream_id": hex::encode(stream.0) }));
                }
                _ => {}
            }
            for v in out {
                let text = with_person(&eng_e, v).await.to_string();
                if out_e.send(Message::Text(text.into())).await.is_err() {
                    return;
                }
            }
        }
    });

    // Readiness and leavers, from the call's own state (edge v44 has no
    // "attendee left" event): `ready {frame_budget_bytes}` once a leg is up and
    // again when the budget changes; `attendee_left {left: "lost"}` when a
    // member's leg has been gone for 5 s (edge's Down bound at depth 0; a failover can
    // take a leg for over 2 s). A client publishes only after `ready`.
    //
    // `connecting {members, since_ms, reach}` when the socket opens, and once
    // more if no `ready` has come CONNECTING_AGAIN_AFTER later: who the call is
    // waiting on and whether this node has heard from them (`reach_view`), so
    // a client can say "Francesco's device hasn't been seen since…" instead of
    // ringing silently. A warning; the call carries on.
    let jw = Arc::clone(&j);
    let out_w = out_tx.clone();
    let eng_w = Arc::clone(&engine);
    let room_w = room.clone();
    let watch_task = tokio::spawn(async move {
        let since_ms = chrono::Utc::now().timestamp_millis();
        let opened = std::time::Instant::now();
        let mut connecting_sent: u8 = 0;
        let mut last_budget: Option<usize> = None;
        let mut legs_seen: HashMap<String, Option<std::time::Instant>> = HashMap::new();
        let mut last_video: Option<bool> = None;
        let mut tick: u32 = 0;
        loop {
            let due = match connecting_sent {
                0 => true,
                1 => last_budget.is_none() && opened.elapsed() >= CONNECTING_AGAIN_AFTER,
                _ => false,
            };
            if due {
                connecting_sent += 1;
                let attendees = {
                    let g = jw.call.lock().await;
                    match g.as_ref() {
                        Some(c) => c.attendees().await,
                        None => break,
                    }
                };
                let m = connecting_json(&eng_w, &room_w, &attendees, since_ms).await;
                if out_w
                    .send(Message::Text(m.to_string().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let notices: Vec<serde_json::Value> = std::mem::take(
                &mut *jw
                    .ring_notices
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            let mut gone = false;
            for v in notices {
                let text = with_person(&eng_w, v).await.to_string();
                if out_w.send(Message::Text(text.into())).await.is_err() {
                    gone = true;
                    break;
                }
            }
            if gone {
                break;
            }
            // Once a second: how many people are in the call (VIDEO_MAX_PEOPLE).
            if tick % 4 == 0 {
                let people = {
                    let g = jw.call.lock().await;
                    match g.as_ref() {
                        Some(c) => people_in_call(&eng_w, c).await,
                        None => break,
                    }
                };
                let ok = video_allowed(people);
                jw.video_ok.store(ok, std::sync::atomic::Ordering::Relaxed);
                if last_video != Some(ok) {
                    last_video = Some(ok);
                    let m = json!({ "type": "video_allowed", "allowed": ok, "people": people,
                                    "max_people": VIDEO_MAX_PEOPLE,
                                    "reason_id": "call.video_two_people_only" });
                    if out_w
                        .send(Message::Text(m.to_string().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
            tick = tick.wrapping_add(1);
            let (budget, legs, ended) = {
                let g = jw.call.lock().await;
                match g.as_ref() {
                    Some(c) => (
                        c.chunk_plaintext_budget(),
                        c.legs(),
                        match c.state() {
                            EdgeCallState::Ended(cause) => Some(cause),
                            _ => None,
                        },
                    ),
                    None => break,
                }
            };
            // The call is over the four-person limit and this device joined last
            // (`hold_to_call_size`): say so, close, and the call is left.
            let full = jw.full.load(std::sync::atomic::Ordering::Acquire);
            if full > 0 {
                let _ = out_w
                    .send(Message::Text(call_full_json(full).to_string().into()))
                    .await;
                let _ = out_w
                    .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                        code: axum::extract::ws::close_code::NORMAL,
                        reason: "call_full".into(),
                    })))
                    .await;
                break;
            }
            // Edge 45.2.0: the call ended under the socket (this device turned
            // shaped-only or anonymous, left the room, or was hung up): say
            // why, then close with the bare token as the close reason.
            if let Some(cause) = ended {
                let (token, _) = end_ids(&cause);
                let _ = out_w
                    .send(Message::Text(ended_json(&cause).to_string().into()))
                    .await;
                let _ = out_w
                    .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                        code: axum::extract::ws::close_code::NORMAL,
                        reason: token.into(),
                    })))
                    .await;
                break;
            }
            if budget.is_some() && budget != last_budget {
                last_budget = budget;
                // `fragmenting`: whether the node splits a frame over the budget
                // (a video join: its stream is bound to `video_codecs`) or refuses it
                // (audio only). The client switches on THIS.
                let m = json!({ "type": "ready", "frame_budget_bytes": budget,
                                "fragmenting": jw.video });
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
            Ok(f)
                if f.codec_id != call_frames::CODEC_OPAQUE
                    && !j.video_ok.load(std::sync::atomic::Ordering::Relaxed) =>
            {
                Some(
                    json!({ "type": "publish_refused", "reason": "video_two_people_only",
                             "reason_id": "call.video_two_people_only",
                             "max_people": VIDEO_MAX_PEOPLE }),
                )
            }
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

/// True for a `stream_added` whose signed kind is a share (CC rc18: 1).
fn share_kind(e: &CallEvent) -> bool {
    matches!(e, CallEvent::StreamAdded { kind, .. } if *kind == ciris_edge::transport::av_chunk_auth::STREAM_KIND_SHARE)
}

/// The ticket room of a share's frames socket: apart from the call's own, so
/// one ticket never opens the other socket.
fn share_ticket_room(room: &str) -> String {
    format!("{room}#share")
}

/// `POST /v1/chat/{room}/call/share`: share this device's screen, a window or
/// an app, as a SECOND stream that replaces nothing (CSD-134; CC rc17: a share
/// is a second stream with no `replaces`; edge v45 `Call::add_stream`). The
/// camera and microphone keep their own stream.
///
/// Answers `{stream_id, frames_ticket, frame_budget_bytes, kind: "share"}`.
/// The share's frames go on `WS …/call/share/frames` (binary, the same
/// frame format as the call's socket), which sends `ready` first. Every other
/// member's main socket sees `stream_added {kind: "share"}` and
/// `share_started {member, person, stream_id}`; a stop is `stream_ended` and
/// `share_stopped`. A share is video, so it keeps the call's two-person rule
/// (`call.video_two_people_only`). One share per device at a time
/// (`call.share_already_live`, 409, naming the live one).
async fn share(
    State(st): State<CallState>,
    headers: HeaderMap,
    Path(room): Path<String>,
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
    if !j.video_ok.load(std::sync::atomic::Ordering::Relaxed) {
        return refuse_with(
            StatusCode::CONFLICT,
            "call.video_two_people_only",
            "Video and screen sharing work in calls between two people for now. This call has more, \
             so it's voice only. If your camera is on, it starts sending again when the call is back \
             to two.",
            json!({ "max_people": VIDEO_MAX_PEOPLE }),
        );
    }
    if let Some(live) = *j
        .share
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        return refuse_with(
            StatusCode::CONFLICT,
            "call.share_already_live",
            "You're already sharing your screen.",
            json!({ "stream_id": hex::encode(live.0) }),
        );
    }
    let (stream, budget) = {
        let g = j.call.lock().await;
        let Some(call) = g.as_ref() else {
            return refuse_with(
                StatusCode::CONFLICT,
                "call.not_joined",
                "Join the call first.",
                json!({}),
            );
        };
        match call.add_stream(video_codecs()).await {
            Ok(s) => (s, call.chunk_plaintext_budget()),
            Err(e) => {
                tracing::warn!(room = %room, error = %e, "call: the share stream was refused");
                return refuse_with(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "call.share_unavailable",
                    "Sharing your screen isn't available on this node yet.",
                    json!({ "detail": e.to_string() }),
                );
            }
        }
    };
    *j.share
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(stream);
    tracing::info!(room = %room, stream = %hex::encode(stream.0), "call: share started");
    (
        StatusCode::OK,
        Json(json!({
            "room": room,
            "kind": "share",
            "stream_id": hex::encode(stream.0),
            "frames_ticket": issue_ticket(&share_ticket_room(&room)),
            "frame_budget_bytes": budget,
        })),
    )
        .into_response()
}

/// End this device's share: `end_stream`, signed, so every member sees
/// `stream_ended` and `share_stopped`. `None` when there was none.
async fn stop_share(j: &Joined) -> Option<StreamId> {
    let live = j
        .share
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()?;
    let g = j.call.lock().await;
    if let Some(call) = g.as_ref() {
        if let Err(e) = call.end_stream(live).await {
            tracing::warn!(error = %e, "call: ending the share stream failed");
        }
    }
    Some(live)
}

/// `DELETE /v1/chat/{room}/call/share`: stop sharing. The call goes on.
async fn unshare(
    State(st): State<CallState>,
    headers: HeaderMap,
    Path(room): Path<String>,
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
    match stop_share(&j).await {
        Some(s) => (
            StatusCode::OK,
            Json(json!({ "room": room, "stopped": hex::encode(s.0) })),
        )
            .into_response(),
        None => refuse_with(
            StatusCode::CONFLICT,
            "call.no_share",
            "You aren't sharing your screen.",
            json!({}),
        ),
    }
}

/// `WS /v1/chat/{room}/call/share/frames?ticket=…`: the share's outgoing
/// frames, binary, in the call socket's frame format. Sends `ready
/// {frame_budget_bytes}` first and `publish_refused` on a frame it could not
/// send. Closing the socket stops the share.
async fn share_socket(
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
    let ticketed = q
        .ticket
        .as_deref()
        .is_some_and(|t| spend_ticket(t, &share_ticket_room(&room)));
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
    let Some(stream) = *j
        .share
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    else {
        return refuse_with(
            StatusCode::CONFLICT,
            "call.no_share",
            "You aren't sharing your screen.",
            json!({}),
        );
    };
    ws.on_upgrade(move |socket| share_pump(socket, room, j, stream))
}

async fn share_pump(socket: WebSocket, room: String, j: Arc<Joined>, stream: StreamId) {
    use futures_util::{SinkExt, StreamExt};
    let (mut tx, mut rx) = socket.split();
    let budget = {
        let g = j.call.lock().await;
        g.as_ref().and_then(|c| c.chunk_plaintext_budget())
    };
    let ready = json!({ "type": "ready", "kind": "share", "stream_id": hex::encode(stream.0),
                        "frame_budget_bytes": budget, "fragmenting": true });
    if tx
        .send(Message::Text(ready.to_string().into()))
        .await
        .is_err()
    {
        let _ = stop_share(&j).await;
        return;
    }
    while let Some(msg) = rx.next().await {
        let bytes = match msg {
            Ok(Message::Binary(b)) => b,
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => continue,
        };
        // The share was stopped by DELETE, or replaced: this socket is done.
        if *j
            .share
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            != Some(stream)
        {
            break;
        }
        let refusal = match call_frames::decode_outgoing(&bytes) {
            Err(e) => Some(json!({ "type": "publish_refused", "reason": e.token() })),
            Ok(_) if !j.video_ok.load(std::sync::atomic::Ordering::Relaxed) => Some(
                json!({ "type": "publish_refused", "reason": "video_two_people_only",
                         "reason_id": "call.video_two_people_only",
                         "max_people": VIDEO_MAX_PEOPLE }),
            ),
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
                        match call.publish_on(stream, frame).await {
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
            if tx.send(Message::Text(r.to_string().into())).await.is_err() {
                break;
            }
        }
    }
    // The socket closed: the share ends, the call goes on (if this socket
    // still owned the live share).
    let still_ours = *j
        .share
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        == Some(stream);
    if still_ours {
        let _ = stop_share(&j).await;
        tracing::info!(room = %room, "call: share stopped (its socket closed)");
    }
}

/// The member call routes. Mounted on every node; each route is the owner's.
pub fn router(engine: Arc<Engine>, edge: Arc<Edge>) -> Router {
    if let Ok(h) = tokio::runtime::Handle::try_current() {
        let _ = runtime().set(h);
    }
    // Ringing's receiver (`call_ring`): rings, ends and declines from the
    // room's other member nodes.
    crate::call_ring::register(&edge, Arc::clone(&engine));
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
        .route("/v1/chat/{room}/call/relay", axum::routing::post(set_relay))
        .route(
            "/v1/chat/{room}/call/share",
            axum::routing::post(share).delete(unshare),
        )
        .route(
            "/v1/chat/{room}/call/share/frames",
            axum::routing::get(share_socket),
        )
        .route("/v1/chat/{room}/call/decline", axum::routing::post(decline))
        .route("/v1/calls/ringing", axum::routing::get(ringing_now))
        .route("/v1/calls/events", axum::routing::get(ring_events))
        .with_state(CallState { engine, edge })
}

#[derive(Deserialize, Default)]
struct DeclineBody {
    #[serde(default)]
    reason: Option<String>,
}

/// `POST /v1/chat/{room}/call/decline {reason: declined|busy}`: decline the
/// ring this device is hearing in `room` (`call_ring`).
async fn decline(
    State(st): State<CallState>,
    headers: HeaderMap,
    Path(room): Path<String>,
    body: Option<Json<DeclineBody>>,
) -> Response {
    if let Err(r) = require_owner(&st, &headers).await {
        return r;
    }
    let reason = body
        .and_then(|Json(b)| b.reason)
        .unwrap_or_else(|| "declined".to_owned());
    if !crate::call_ring::DECLINE_REASONS.contains(&reason.as_str()) {
        return refuse_with(
            StatusCode::BAD_REQUEST,
            "call.decline_reason_unknown",
            "That isn't a reason for declining a call.",
            json!({ "accepted": crate::call_ring::DECLINE_REASONS }),
        );
    }
    match crate::call_ring::decline(&st.edge, &room, &reason).await {
        Some(v) => (StatusCode::OK, Json(v)).into_response(),
        None => (
            StatusCode::OK,
            Json(json!({ "room": room, "declined": "not_ringing" })),
        )
            .into_response(),
    }
}

/// `GET /v1/calls/ringing`: the rings live on this device now.
async fn ringing_now(State(st): State<CallState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_owner(&st, &headers).await {
        return r;
    }
    (
        StatusCode::OK,
        Json(crate::call_ring::live(&st.engine).await),
    )
        .into_response()
}

/// `GET /v1/calls/events`: SSE of `call_ringing` and `call_ring_ended`. Opens
/// with the rings live now (`event: ringing_now`), since a broadcast does not
/// replay; a lagged reader is told to fetch `GET /v1/calls/ringing`.
async fn ring_events(State(st): State<CallState>, headers: HeaderMap) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_util::StreamExt;
    if let Err(r) = require_owner(&st, &headers).await {
        return r;
    }
    let now = crate::call_ring::live(&st.engine).await;
    let first = futures_util::stream::once(async move {
        Event::default().event("ringing_now").data(now.to_string())
    });
    let rx = crate::call_ring::subscribe();
    let live = futures_util::stream::unfold(rx, |mut rx| async move {
        let e = match rx.recv().await {
            Ok(v) => {
                let ty = v["type"].as_str().unwrap_or("call").to_owned();
                Event::default().event(ty).data(v.to_string())
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => Event::default()
                .event("resync")
                .data(json!({ "fetch": "/v1/calls/ringing" }).to_string()),
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
        };
        Some((e, rx))
    });
    Sse::new(first.chain(live).map(Ok::<Event, std::convert::Infallible>))
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_is_two_people_and_audio_any() {
        assert!(video_allowed(1));
        assert!(video_allowed(2));
        assert!(!video_allowed(3), "above two the call drops to audio only");
        assert!(!video_allowed(10));
    }

    #[test]
    fn a_client_names_left_or_backgrounded_and_never_lost() {
        assert_eq!(leave_reason(None), Some("left"));
        assert_eq!(leave_reason(Some("")), Some("left"));
        assert_eq!(leave_reason(Some("left")), Some("left"));
        assert_eq!(leave_reason(Some("backgrounded")), Some("backgrounded"));
        assert_eq!(leave_reason(Some("lost")), None, "lost is the node's word");
        assert_eq!(leave_reason(Some("bogus")), None);
    }

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
        assert_eq!(v["left"], "removed");
        assert!(v.get("name").is_none() && v.get("display_name").is_none());
    }

    #[test]
    fn a_leave_carries_its_signed_cause_and_stream() {
        use ciris_edge::transport::av_call::LeaveCause;
        use ciris_edge::transport::realtime_av::StreamId;
        let v = event_json(&CallEvent::AttendeeLeft {
            key_id: "k".into(),
            stream: StreamId([7; 32]),
            cause: LeaveCause::Backgrounded,
            truncated: false,
        });
        assert_eq!(v["type"], "attendee_left");
        assert_eq!(v["left"], "backgrounded");
        assert_eq!(v["stream_id"], hex::encode([7u8; 32]));
        let v = event_json(&CallEvent::StreamAdded {
            publisher: "k".into(),
            stream: StreamId([1; 32]),
            kind: 9,
        });
        assert_eq!(v["kind"], "media", "an unknown kind renders as media");
        let v = event_json(&CallEvent::StreamEnded {
            publisher: "k".into(),
            stream: StreamId([1; 32]),
            cause: LeaveCause::Ended,
            truncated: true,
        });
        assert_eq!(
            (v["type"].as_str(), v["ended"].as_str()),
            (Some("stream_ended"), Some("ended"))
        );
        assert_eq!(v["truncated"], true);
    }

    /// Every event the socket builds from an edge `CallEvent` has the same
    /// keys as its example in the golden vectors the client pins (`person` is
    /// added later, by `with_person`).
    #[test]
    fn socket_events_match_the_golden_vectors() {
        use ciris_edge::transport::av_call::LeaveCause;
        use ciris_edge::transport::realtime_av::StreamId;
        use std::collections::BTreeSet;
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/call_frames_v1.json"
        ))
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let examples = v["events"]["examples"].as_array().unwrap().clone();
        let keys = |o: &serde_json::Value| -> BTreeSet<String> {
            o.as_object()
                .unwrap()
                .keys()
                .filter(|k| *k != "person")
                .cloned()
                .collect()
        };
        let s = StreamId([1; 32]);
        let built = [
            CallEvent::AttendeeJoined { key_id: "k".into() },
            CallEvent::MemberLeft { key_id: "k".into() },
            CallEvent::AttendeeLeft {
                key_id: "k".into(),
                stream: s,
                cause: LeaveCause::Left,
                truncated: false,
            },
            CallEvent::StreamAdded {
                publisher: "k".into(),
                stream: s,
                kind: 0,
            },
            CallEvent::StreamEnded {
                publisher: "k".into(),
                stream: s,
                cause: LeaveCause::Ended,
                truncated: false,
            },
            CallEvent::StreamReplaced {
                publisher: "k".into(),
                old: s,
                new: StreamId([2; 32]),
            },
            CallEvent::EpochRolled { from: 1, to: 2 },
            CallEvent::LoadTier { tier: 1 },
            CallEvent::KeepRefused {
                epoch: 1,
                reason: "x",
            },
            CallEvent::Stranded {
                epoch: 1,
                reason: "x".into(),
            },
            CallEvent::VideoUnavailable {
                publisher: "k".into(),
                reason: "relay_canonical_audio_only",
            },
            CallEvent::VideoRestored {
                publisher: "k".into(),
            },
            CallEvent::RelayStatus {
                relaying: true,
                relaying_for: 3,
            },
            CallEvent::MediaPathRestored {
                member: "k".into(),
                via: PathKind::PeerRelay,
                through: Some("b".into()),
            },
            CallEvent::MediaPathFailed {
                member: "k".into(),
                cause: ciris_edge::transport::media_path::MediaPathCause::NoMemberCouldRelay,
                retryable: true,
                retry_after_s: None,
                detail: None,
                tried: Vec::new(),
                local_nat: ciris_edge::transport::media_path::NatReport::unknown(chrono::Utc::now()),
                peer_nat: None,
                relay: ciris_edge::transport::media_path::RelayStanding::NoneAvailable,
            },
        ];
        for e in &built {
            let out = event_json(e);
            let ty = out["type"].as_str().unwrap();
            assert!(
                examples
                    .iter()
                    .any(|x| x["type"] == ty && keys(x) == keys(&out)),
                "{ty}: socket keys {:?} match no vector example",
                keys(&out)
            );
        }
    }

    #[test]
    fn only_backgrounded_is_signed_as_backgrounded() {
        assert_eq!(signed_end("backgrounded"), SignedEnd::Backgrounded);
        assert_eq!(signed_end("left"), SignedEnd::Left);
        assert_eq!(signed_end("lost"), SignedEnd::Left);
    }

    /// The call's state, tier and the `connecting` event are tokens and
    /// shapes the client pins, never Rust Debug strings.
    #[test]
    fn call_state_and_connecting_are_tokens() {
        assert_eq!(state_view(&EdgeCallState::Live), json!({ "state": "live" }));
        let d = state_view(&EdgeCallState::Degraded {
            epoch: 3,
            reason: "r".into(),
        });
        assert_eq!(d, json!({ "state": "degraded", "epoch": 3, "reason": "r" }));
        let e = state_view(&EdgeCallState::Ended(EndCause::HungUp));
        assert_eq!(
            e,
            json!({ "state": "ended", "ended": "hung_up", "reason_id": "call.end.hung_up" })
        );
        assert_eq!(ciris_edge::ServiceTier::FullOps.token(), "load_tier:0");

        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/call_frames_v1.json"
        ))
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let pinned = v["events"]["examples"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["type"] == "connecting")
            .unwrap()
            .clone();
        let built = connecting_from(pinned["reach"].clone(), 1_795_000_000_000);
        assert_eq!(
            built, pinned,
            "the server builds the pinned connecting event"
        );
    }

    /// Every way a call ends has its token and copy key, and the vectors the
    /// client pins say the same (`call.ended` stays the CONFLICT string).
    #[test]
    fn a_call_end_names_its_token_and_copy() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/call_frames_v1.json"
        ))
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let pinned = v["events"]["call_ended_values"]
            .as_object()
            .unwrap()
            .clone();
        let causes = [
            EndCause::HungUp,
            EndCause::Revoked,
            EndCause::Expired,
            EndCause::MediaRefused {
                token: "shaped_only_no_media",
            },
            EndCause::MediaRefused {
                token: "onion_anonymous_no_media",
            },
        ];
        // Edge's causes plus the server's own: a call over the four-person
        // limit, and a call that rang with nobody answering.
        assert_eq!(pinned.len(), causes.len() + 2);
        let full = call_full_json(5);
        assert_eq!(pinned[full["ended"].as_str().unwrap()], full["reason_id"]);
        let none = no_answer_ended_json();
        assert_eq!(pinned[none["ended"].as_str().unwrap()], none["reason_id"]);
        for c in &causes {
            let out = ended_json(c);
            assert_eq!(out["type"], "call_ended");
            let token = out["ended"].as_str().unwrap();
            assert_eq!(pinned[token], out["reason_id"], "{token}");
            assert_ne!(out["reason_id"], "call.ended");
        }
    }

    /// Four people may be in a call, a fifth may not (Eric 2026-11-25).
    #[test]
    fn a_call_holds_four_people() {
        assert!(call_has_room(1));
        assert!(call_has_room(CALL_MAX_PEOPLE));
        assert!(!call_has_room(CALL_MAX_PEOPLE + 1));
        assert_eq!(CALL_MAX_PEOPLE, 4);
        let v = call_full_json(5);
        assert_eq!(v["type"], "call_ended");
        assert_eq!(v["reason_id"], "call.full");
        assert_eq!(v["max_people"], 4);
    }

    /// A client that reads nothing loses no state: edge's channel is emptied
    /// (64 is its size, 200 events pass through), a share's end is told though
    /// the member's camera stream ended and began around it, and the status is
    /// the latest one.
    #[tokio::test]
    async fn events_are_read_though_no_client_reads_and_the_last_state_survives() {
        let added = |s: u8| CallEvent::StreamAdded {
            publisher: "m".into(),
            stream: StreamId([s; 32]),
            kind: 0,
        };
        let ended = |s: u8| CallEvent::StreamEnded {
            publisher: "m".into(),
            stream: StreamId([s; 32]),
            cause: ciris_edge::transport::av_call::LeaveCause::Left,
            truncated: false,
        };
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let b = EventBox::read(rx);
        for e in [added(1), added(2)] {
            tx.send(e).await.unwrap();
        }
        let first = b.next().await.expect("the camera");
        assert!(matches!(first, CallEvent::StreamAdded { stream, .. } if stream.0 == [1; 32]));
        let second = b.next().await.expect("the share");
        assert!(matches!(second, CallEvent::StreamAdded { stream, .. } if stream.0 == [2; 32]));
        // The client stops reading here. Every send below completes only if
        // the box keeps reading.
        for n in 0..200u16 {
            let e = CallEvent::RelayStatus {
                relaying: true,
                relaying_for: n,
            };
            tokio::time::timeout(std::time::Duration::from_secs(5), tx.send(e))
                .await
                .expect("the box reads though nobody reads it")
                .unwrap();
        }
        tx.send(ended(2)).await.unwrap();
        tx.send(ended(1)).await.unwrap();
        tx.send(added(3)).await.unwrap();
        drop(tx);
        let mut seen = Vec::new();
        while let Some(e) = b.next().await {
            seen.push(e);
        }
        let status: Vec<u16> = seen
            .iter()
            .filter_map(|e| match e {
                CallEvent::RelayStatus { relaying_for, .. } => Some(*relaying_for),
                _ => None,
            })
            .collect();
        assert_eq!(status.last(), Some(&199), "the latest status is told last");
        let ends: Vec<u8> = seen
            .iter()
            .filter_map(|e| match e {
                CallEvent::StreamEnded { stream, .. } => Some(stream.0[0]),
                _ => None,
            })
            .collect();
        assert_eq!(ends, vec![2, 1], "each stream's end is told");
        assert!(seen
            .iter()
            .any(|e| matches!(e, CallEvent::StreamAdded { stream, .. } if stream.0 == [3; 32])));
    }

    /// One-off notices are bounded; they never push out a state.
    #[test]
    fn unread_notices_are_bounded_and_never_push_out_a_state() {
        let b = EventBox::default();
        b.put(CallEvent::AttendeeJoined { key_id: "a".into() });
        for n in 0..(MAX_WAITING_NOTICES as u64 + 50) {
            b.put(CallEvent::EpochRolled { from: n, to: n + 1 });
        }
        b.put(CallEvent::AttendeeLeft {
            key_id: "a".into(),
            stream: StreamId([1; 32]),
            cause: ciris_edge::transport::av_call::LeaveCause::Left,
            truncated: false,
        });
        let q = b.waiting.lock().unwrap();
        assert_eq!(q.len(), MAX_WAITING_NOTICES + 1);
        assert!(matches!(q.back(), Some(CallEvent::AttendeeLeft { .. })));
        assert!(!q
            .iter()
            .any(|e| matches!(e, CallEvent::AttendeeJoined { .. })));
    }

    /// A serve seat and a phone that did not say never relay; any other member
    /// node relays by default (Eric 2026-11-22).
    #[test]
    fn a_serve_seat_never_relays_by_default() {
        assert!(!relay_default(true, false));
        assert!(!relay_default(true, true));
        assert!(!relay_default(false, true));
        assert!(relay_default(false, false));
    }

    /// A path event's member and `through` share the attendee id space, and
    /// `direct` is every technique but a member relay.
    #[test]
    fn a_restored_path_says_direct_or_through_whom() {
        for k in PathKind::ALL {
            let out = event_json(&CallEvent::MediaPathRestored {
                member: "k".into(),
                via: *k,
                through: (*k == PathKind::PeerRelay).then(|| "b".to_owned()),
            });
            assert_eq!(out["via"], k.token());
            assert_eq!(out["direct"], *k != PathKind::PeerRelay);
        }
    }
}
