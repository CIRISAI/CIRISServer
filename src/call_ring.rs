//! **Ringing** (0.5.255; Eric 2026-11-27 "yes on all"): when someone starts a
//! call in a room with no call live, every other member's node is told, and
//! the person's app rings while it is running.
//!
//! Ringing is **transient call control, never a row** (the Constitution's
//! reading, 2026-11-27): nothing folds over a ring, a decline or a timeout, and
//! a stored record of who declined whom would be a social record nobody asked
//! for. So:
//! 1. it goes only to members of the room, and a receiver refuses a ring from a
//!    key that is not in that room's group (a ring never tells a non-member a
//!    room or a call exists);
//! 2. it rides edge's opaque request/response (Ephemeral class: signed,
//!    sealed, nothing queued or replicated, an in-memory replay window), never
//!    `send_opaque_event` (durable: a ring a day late);
//! 3. no node persists it: an incoming ring lives in this process's memory
//!    until it ends, and a "missed call" is the device's own local state;
//! 4. a receiver rate bounds how often one key can ring this node;
//! 5. a decline's reason is the closed pair `declined | busy`.
//!
//! The wire (kind [`RING_KIND`], JSON bytes, `v: 1`):
//! * `ring {room, call_id, video, since_ms}` caller → each member node;
//!   answered `200 {state: "ringing"}`, `403` not a member, `429` too often.
//! * `end {room, call_id, why, joined_by?}` caller → each member node, when
//!   the ring is over: `answered` (someone joined; `joined_by` is the attendee,
//!   a person key),
//!   `cancelled` (the caller left), `timeout` ([`RING_TIMEOUT`]). A receiver
//!   whose own person joined from another device reports `answered_elsewhere`.
//! * `decline {room, call_id, reason}` callee → the caller's node.
//!
//! Locally, `GET /v1/calls/events` (SSE, the owner's session) carries
//! `call_ringing {room, call_id, by: {member, person}, video, since_ms}` and
//! `call_ring_ended {room, call_id, why}`; `GET /v1/calls/ringing` lists the
//! rings live now (an SSE does not replay); `POST /v1/chat/{room}/call/decline
//! {reason}` declines. The caller's frames socket gets `ringing {members}`,
//! `declined {member, person, reason}` and `no_answer`, and the call is left
//! when nobody joined within [`RING_TIMEOUT`].
//!
//! Limits on edge 45.2.1: a ring is not yet classed ahead of media (45.3 sends
//! unclassed control first); a cold dial costs a path seek; a node with no
//! path now is told nothing (the caller sees `unreachable`); a backgrounded
//! phone is not woken (push-to-wake, CIRISServer#24).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use ciris_edge::messages::OpaqueResponse;
use ciris_edge::Edge;
use ciris_persist::prelude::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// The server's opaque kind for ringing (its own range: 1 mesh control, 2
/// device join).
pub const RING_KIND: u32 = 0x0000_0003;
/// How long a call rings before the caller is told `no_answer` and the call
/// is left.
pub const RING_TIMEOUT: Duration = Duration::from_secs(45);
/// A receiver drops a ring it heard no end for after this long (the caller's
/// node went away mid-ring).
pub const RING_STALE_AFTER: Duration = Duration::from_secs(60);
/// One send's bound: a ring that has not reached a node in this long is
/// `unreachable` to the caller.
pub const SEND_TIMEOUT_MS: u64 = 8_000;
/// At most this many rings from one key per [`RATE_WINDOW`].
pub const RATE_MAX: usize = 6;
/// The receiver rate's window.
pub const RATE_WINDOW: Duration = Duration::from_secs(60);

/// The decline reasons a client may give.
pub const DECLINE_REASONS: [&str; 2] = ["declined", "busy"];
/// Why a ring ended, as the callee's events say it.
pub const END_WHYS: [&str; 5] = [
    "answered",
    "answered_elsewhere",
    "declined",
    "cancelled",
    "timeout",
];

/// One ring message on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Wire {
    Ring {
        v: u8,
        room: String,
        call_id: String,
        video: bool,
        since_ms: i64,
    },
    End {
        v: u8,
        room: String,
        call_id: String,
        why: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        joined_by: Option<String>,
    },
    Decline {
        v: u8,
        room: String,
        call_id: String,
        reason: String,
    },
}

impl Wire {
    fn room(&self) -> &str {
        match self {
            Self::Ring { room, .. } | Self::End { room, .. } | Self::Decline { room, .. } => room,
        }
    }
}

/// A ring this node is hearing now.
#[derive(Debug, Clone)]
struct Incoming {
    call_id: String,
    caller: String,
    video: bool,
    since_ms: i64,
    heard: Instant,
}

fn incoming() -> &'static StdMutex<HashMap<String, Incoming>> {
    static I: OnceLock<StdMutex<HashMap<String, Incoming>>> = OnceLock::new();
    I.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn bus() -> &'static tokio::sync::broadcast::Sender<serde_json::Value> {
    static B: OnceLock<tokio::sync::broadcast::Sender<serde_json::Value>> = OnceLock::new();
    B.get_or_init(|| tokio::sync::broadcast::channel(64).0)
}

/// Subscribe to this node's ring events (`call_ringing`, `call_ring_ended`).
pub fn subscribe() -> tokio::sync::broadcast::Receiver<serde_json::Value> {
    bus().subscribe()
}

fn publish(v: serde_json::Value) {
    let _ = bus().send(v);
}

fn lock<T>(m: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The receiver rate: may `sender` ring now? Records the ring when it may.
fn rate_ok(sender: &str, now: Instant) -> bool {
    static R: OnceLock<StdMutex<HashMap<String, VecDeque<Instant>>>> = OnceLock::new();
    let mut r = lock(R.get_or_init(|| StdMutex::new(HashMap::new())));
    let q = r.entry(sender.to_owned()).or_default();
    while q
        .front()
        .is_some_and(|t| now.duration_since(*t) >= RATE_WINDOW)
    {
        q.pop_front();
    }
    if q.len() >= RATE_MAX {
        return false;
    }
    q.push_back(now);
    true
}

fn ringing_json(room: &str, i: &Incoming, person: Option<&str>) -> serde_json::Value {
    json!({
        "type": "call_ringing",
        "room": room,
        "call_id": i.call_id,
        "by": { "member": i.caller, "person": person },
        "video": i.video,
        "since_ms": i.since_ms,
    })
}

fn ended_json(room: &str, call_id: &str, why: &str) -> serde_json::Value {
    json!({ "type": "call_ring_ended", "room": room, "call_id": call_id, "why": why })
}

/// End this node's incoming ring in `room` (if it is `call_id`, or any when
/// `None`) and say why. Returns the ring it ended.
fn end_incoming(room: &str, call_id: Option<&str>, why: &str) -> Option<Incoming> {
    let mut map = lock(incoming());
    let hit = map
        .get(room)
        .is_some_and(|i| call_id.is_none_or(|c| c == i.call_id));
    let gone = if hit { map.remove(room) } else { None };
    drop(map);
    if let Some(i) = &gone {
        publish(ended_json(room, &i.call_id, why));
    }
    gone
}

/// The rings live on this node now, for a client that (re)connects.
pub async fn live(engine: &Engine) -> serde_json::Value {
    let now = Instant::now();
    let rings: Vec<(String, Incoming)> = {
        let mut map = lock(incoming());
        map.retain(|_, i| now.duration_since(i.heard) < RING_STALE_AFTER);
        map.iter().map(|(r, i)| (r.clone(), i.clone())).collect()
    };
    let mut out = Vec::new();
    for (room, i) in rings {
        let person = crate::call_routes::person_of_node(engine, &i.caller).await;
        out.push(ringing_json(&room, &i, person.as_deref()));
    }
    json!({ "ringing": out })
}

/// This node's own call in `room` was answered here: stop ringing it.
pub fn answered_here(room: &str) {
    let _ = end_incoming(room, None, "answered");
}

// ─── the receiver ────────────────────────────────────────────────────────────

fn respond(status: u16, body: serde_json::Value) -> OpaqueResponse {
    OpaqueResponse {
        kind: RING_KIND,
        status,
        payload: body.to_string().into_bytes(),
    }
}

/// Whether `key` is in `room`'s group as this node holds it.
async fn in_room(engine: &Engine, room: &str, node: &str) -> bool {
    let Some(me) = crate::node_key::wire_identity() else {
        return false;
    };
    let members = match crate::mls_state::groups_for(me).open_existing(room).await {
        Ok(Some(g)) => g.member_key_ids().await,
        _ => return false,
    };
    // Members are PERSON keys; the sender is a node speaking for its owner.
    if members.iter().any(|m| m == node) {
        return true;
    }
    match crate::call_routes::person_of_node(engine, node).await {
        Some(p) => members.contains(&p),
        None => false,
    }
}

/// Handle one inbound ring message from `sender` (a node key, edge-verified).
pub async fn handle(engine: &Engine, sender: &str, payload: &[u8]) -> OpaqueResponse {
    let Ok(msg) = serde_json::from_slice::<Wire>(payload) else {
        return respond(400, json!({ "error": "ring.malformed" }));
    };
    if !in_room(engine, msg.room(), sender).await {
        // Said the same way whether the room exists here or not.
        return respond(403, json!({ "error": "ring.not_a_member" }));
    }
    match msg {
        Wire::Ring {
            room,
            call_id,
            video,
            since_ms,
            ..
        } => {
            if !rate_ok(sender, Instant::now()) {
                return respond(429, json!({ "error": "ring.too_often" }));
            }
            // Already in this room's call (two people joined at once, each
            // seeing an empty call): nothing to ring.
            if crate::call_routes::attendees_of(&room).await.is_some() {
                return respond(200, json!({ "state": "in_call" }));
            }
            let i = Incoming {
                call_id,
                caller: sender.to_owned(),
                video,
                since_ms,
                heard: Instant::now(),
            };
            let fresh = {
                let mut map = lock(incoming());
                let same = map
                    .get(&room)
                    .is_some_and(|o| o.call_id == i.call_id && o.caller == i.caller);
                map.insert(room.clone(), i.clone());
                !same
            };
            if fresh {
                let person = crate::call_routes::person_of_node(engine, sender).await;
                publish(ringing_json(&room, &i, person.as_deref()));
                tokio::spawn(expire(room, i.call_id.clone()));
            }
            respond(200, json!({ "state": "ringing" }))
        }
        Wire::End {
            room,
            call_id,
            why,
            joined_by,
            ..
        } => {
            let why = match (why.as_str(), joined_by) {
                ("answered", Some(j)) => {
                    let me = crate::node_key::wire_identity().unwrap_or_default();
                    let mine = crate::call_routes::person_of_node(engine, me).await;
                    let theirs = crate::call_routes::person_of_node(engine, &j).await;
                    // `joined_by` is an attendee: a PERSON key, or a node.
                    if j == me
                        || mine.as_deref() == Some(j.as_str())
                        || (mine.is_some() && mine == theirs)
                    {
                        "answered_elsewhere"
                    } else {
                        "answered"
                    }
                }
                (w, _) if END_WHYS.contains(&w) => END_WHYS
                    .iter()
                    .find(|x| **x == w)
                    .copied()
                    .unwrap_or("cancelled"),
                _ => "cancelled",
            };
            let _ = end_incoming(&room, Some(&call_id), why);
            respond(200, json!({ "state": "ended" }))
        }
        Wire::Decline {
            room,
            call_id,
            reason,
            ..
        } => {
            let reason = if DECLINE_REASONS.contains(&reason.as_str()) {
                reason
            } else {
                "declined".to_owned()
            };
            outgoing_declined(engine, &room, &call_id, sender, &reason).await;
            respond(200, json!({ "state": "noted" }))
        }
    }
}

/// Drop a ring this node never heard the end of.
async fn expire(room: String, call_id: String) {
    tokio::time::sleep(RING_STALE_AFTER).await;
    let _ = end_incoming(&room, Some(&call_id), "timeout");
}

/// Register the receiver on the node's edge.
pub fn register(edge: &Edge, engine: Arc<Engine>) {
    edge.register_opaque_handler(RING_KIND, move |sender, payload| {
        let engine = Arc::clone(&engine);
        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current()
                .block_on(async move { handle(&engine, &sender, &payload).await })
        })
    });
}

// ─── the caller ──────────────────────────────────────────────────────────────

/// A ring this node is making: who it rang and how each answered.
#[derive(Debug, Default)]
struct Outgoing {
    call_id: String,
    /// member node → `ringing | in_call | busy | declined | unreachable | refused`.
    targets: HashMap<String, &'static str>,
    over: bool,
}

fn outgoing() -> &'static StdMutex<HashMap<String, Outgoing>> {
    static O: OnceLock<StdMutex<HashMap<String, Outgoing>>> = OnceLock::new();
    O.get_or_init(|| StdMutex::new(HashMap::new()))
}

async fn send(edge: &Edge, to: &str, msg: &Wire) -> Result<OpaqueResponse, String> {
    let bytes = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
    edge.send_opaque_request(to, RING_KIND, bytes, SEND_TIMEOUT_MS)
        .await
        .map_err(|e| e.to_string())
}

/// The nodes to ring in `room`: every other person's nodes (never this
/// person's own other devices; `call_routes::room_people`).
async fn targets(engine: &Engine, room: &str) -> Vec<String> {
    crate::call_routes::room_people(engine, room)
        .await
        .into_iter()
        .flat_map(|(_, nodes)| nodes)
        .collect()
}

async fn members_view(engine: &Engine, room: &str) -> serde_json::Value {
    let rows: Vec<(String, &'static str)> = lock(outgoing())
        .get(room)
        .map(|o| o.targets.iter().map(|(k, v)| (k.clone(), *v)).collect())
        .unwrap_or_default();
    let mut out = Vec::new();
    for (m, state) in rows {
        let person = crate::call_routes::person_of_node(engine, &m).await;
        out.push(json!({ "member": m, "person": person, "state": state }));
    }
    serde_json::Value::Array(out)
}

fn in_call_answer(payload: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(payload).is_ok_and(|v| v["state"] == "in_call")
}

/// Start ringing the room for this node's new call. The call's own attendee
/// list decides "answered"; the caller leaving decides "cancelled".
pub fn start(edge: Arc<Edge>, engine: Arc<Engine>, room: String, call_id: String, video: bool) {
    tokio::spawn(async move {
        let to = targets(&engine, &room).await;
        if to.is_empty() {
            return;
        }
        {
            let mut map = lock(outgoing());
            map.insert(
                room.clone(),
                Outgoing {
                    call_id: call_id.clone(),
                    targets: to.iter().map(|m| (m.clone(), "ringing")).collect(),
                    over: false,
                },
            );
        }
        let since_ms = chrono::Utc::now().timestamp_millis();
        let ring = Wire::Ring {
            v: 1,
            room: room.clone(),
            call_id: call_id.clone(),
            video,
            since_ms,
        };
        let sends = to.iter().map(|m| {
            let edge = Arc::clone(&edge);
            let ring = ring.clone();
            let m = m.clone();
            async move {
                let r = send(&edge, &m, &ring).await;
                (m, r)
            }
        });
        for (m, r) in futures_util::future::join_all(sends).await {
            let state: &'static str = match &r {
                Ok(resp) if resp.status == 200 && in_call_answer(&resp.payload) => "in_call",
                Ok(resp) if resp.status == 200 => "ringing",
                Ok(_) => "refused",
                Err(_) => "unreachable",
            };
            tracing::info!(room = %room, member = %m, state, "call: rang a member");
            if let Some(o) = lock(outgoing()).get_mut(&room) {
                if o.call_id == call_id && o.targets.get(&m) == Some(&"ringing") {
                    o.targets.insert(m.clone(), state);
                }
            }
        }
        let view = members_view(&engine, &room).await;
        crate::call_routes::notify_caller(&room, json!({ "type": "ringing", "members": view }));
        watch(edge, engine, room, call_id).await;
    });
}

/// Every second until the ring is over: answered, cancelled, all declined, or
/// timed out.
async fn watch(edge: Arc<Edge>, engine: Arc<Engine>, room: String, call_id: String) {
    let started = Instant::now();
    let me = crate::node_key::wire_identity()
        .unwrap_or_default()
        .to_owned();
    // Attendees are PERSON keys (attendance is authored by the person): this
    // caller's own person is not an answer.
    let my_person = crate::call_routes::person_of_node(&engine, &me).await;
    let (why, joined_by) = loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let over = lock(outgoing())
            .get(&room)
            .is_none_or(|o| o.call_id != call_id || o.over);
        if over {
            return;
        }
        match crate::call_routes::attendees_of(&room).await {
            None => break ("cancelled", None),
            Some(a) => {
                if let Some(j) = a
                    .into_iter()
                    .find(|m| *m != me && my_person.as_deref() != Some(m.as_str()))
                {
                    break ("answered", Some(j));
                }
            }
        }
        let (still, any_declined) = lock(outgoing()).get(&room).map_or((false, false), |o| {
            (
                o.targets.values().any(|s| *s == "ringing"),
                o.targets.values().any(|s| *s == "declined" || *s == "busy"),
            )
        });
        if !still {
            // Nobody is still being rung. If someone declined or is busy, the
            // caller heard each `declined`, and hears `no_answer` once; if they
            // were only unreachable, in the call already or refused, the
            // `ringing` list said so and the call simply waits.
            if any_declined {
                crate::call_routes::notify_caller(
                    &room,
                    json!({ "type": "no_answer", "why": "declined" }),
                );
            }
            break ("cancelled", None);
        }
        if started.elapsed() >= RING_TIMEOUT {
            crate::call_routes::notify_caller(
                &room,
                json!({ "type": "no_answer", "why": "timeout" }),
            );
            // Then the call's end in words (`call_ended` ended=no_answer):
            // the node leaves it, so the socket closes after this.
            crate::call_routes::notify_caller(&room, crate::call_routes::no_answer_ended_json());
            // Let the socket's watch loop (250 ms) send both before the call goes.
            tokio::time::sleep(Duration::from_millis(600)).await;
            let _ = crate::call_routes::leave_room(&room, "left").await;
            break ("timeout", None);
        }
    };
    let rung: Vec<String> = {
        let mut map = lock(outgoing());
        let Some(o) = map.get_mut(&room) else {
            return;
        };
        o.over = true;
        let r = o
            .targets
            .iter()
            .filter(|(_, s)| **s == "ringing")
            .map(|(k, _)| k.clone())
            .collect();
        map.remove(&room);
        r
    };
    let end = Wire::End {
        v: 1,
        room: room.clone(),
        call_id: call_id.clone(),
        why: why.to_owned(),
        joined_by,
    };
    let sends = rung.iter().map(|m| {
        let edge = Arc::clone(&edge);
        let end = end.clone();
        let m = m.clone();
        async move {
            let _ = send(&edge, &m, &end).await;
        }
    });
    futures_util::future::join_all(sends).await;
    tracing::info!(room = %room, why, "call: ringing over");
}

/// A member declined this node's ring.
async fn outgoing_declined(engine: &Engine, room: &str, call_id: &str, from: &str, reason: &str) {
    let hit = {
        let mut map = lock(outgoing());
        match map.get_mut(room) {
            Some(o) if o.call_id == call_id && o.targets.contains_key(from) => {
                let s: &'static str = if reason == "busy" { "busy" } else { "declined" };
                o.targets.insert(from.to_owned(), s);
                true
            }
            _ => false,
        }
    };
    if hit {
        let person = crate::call_routes::person_of_node(engine, from).await;
        crate::call_routes::notify_caller(
            room,
            json!({ "type": "declined", "member": from, "person": person, "reason": reason }),
        );
    }
}

/// Decline the ring this node is hearing in `room`: tell the caller, and stop
/// ringing here. `None` when nothing is ringing in that room.
pub async fn decline(edge: &Edge, room: &str, reason: &str) -> Option<serde_json::Value> {
    let i = end_incoming(room, None, "declined")?;
    let msg = Wire::Decline {
        v: 1,
        room: room.to_owned(),
        call_id: i.call_id.clone(),
        reason: reason.to_owned(),
    };
    let told = send(edge, &i.caller, &msg).await.is_ok();
    Some(json!({ "room": room, "call_id": i.call_id, "reason": reason, "caller_told": told }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wire_is_tagged_and_versioned() {
        let r = Wire::Ring {
            v: 1,
            room: "r".into(),
            call_id: "c".into(),
            video: true,
            since_ms: 5,
        };
        let s = serde_json::to_value(&r).unwrap();
        assert_eq!(
            s,
            json!({"op":"ring","v":1,"room":"r","call_id":"c","video":true,"since_ms":5})
        );
        let e: Wire = serde_json::from_value(
            json!({"op":"end","v":1,"room":"r","call_id":"c","why":"timeout"}),
        )
        .unwrap();
        assert_eq!(e.room(), "r");
        assert!(serde_json::from_value::<Wire>(json!({"op":"spam","v":1})).is_err());
    }

    #[test]
    fn one_key_rings_at_most_six_times_a_minute() {
        let t0 = Instant::now();
        for _ in 0..RATE_MAX {
            assert!(rate_ok("rate-test-key", t0));
        }
        assert!(
            !rate_ok("rate-test-key", t0),
            "the seventh ring in a minute is refused"
        );
        assert!(rate_ok("rate-test-other", t0), "the rate is per key");
        assert!(
            rate_ok("rate-test-key", t0 + RATE_WINDOW),
            "and a minute later it may ring again"
        );
    }

    #[tokio::test]
    async fn a_ring_ends_once_and_says_why() {
        let mut rx = subscribe();
        lock(incoming()).insert(
            "ring-test-room".into(),
            Incoming {
                call_id: "c1".into(),
                caller: "k".into(),
                video: false,
                since_ms: 1,
                heard: Instant::now(),
            },
        );
        assert!(end_incoming("ring-test-room", Some("other-call"), "cancelled").is_none());
        assert!(end_incoming("ring-test-room", Some("c1"), "cancelled").is_some());
        assert!(end_incoming("ring-test-room", Some("c1"), "cancelled").is_none());
        let v = rx.recv().await.unwrap();
        assert_eq!(v, ended_json("ring-test-room", "c1", "cancelled"));
    }
}
