//! **QA call routes**: a minimal A/V test surface over edge's call API
//! (`Edge::join_call`, edge v44.1, `FSD/AV_CALL_API.md`), so a cross-NAT A/V
//! step can be run against a real node over HTTP (steward 2026-11-08, for
//! 0.5.245).
//!
//! **Gated twice.** The routes are mounted only when `CIRIS_QA_CALLS=1` is set
//! on the node; without it they are not there (404), so a production node
//! carries no test-stream surface. Mounted, every route needs the node owner's
//! session (SYSTEM_ADMIN + FullAccess, the same spine as `admin_ops`).
//!
//! The stream is GENERATED: frames at a stated rate and size, each carrying
//! its sequence number and the sender's wall-clock send time in its first 16
//! bytes, so the receiving node can count them and estimate one-way delay
//! (across machines that delay includes clock skew; it is a test reading).
//!
//! - `POST /v1/qa/call/start  {room, relay?}` joins `room`'s call as this node.
//! - `POST /v1/qa/call/stream {room, rate_hz, frame_bytes, seconds}` publishes.
//! - `GET  /v1/qa/call/stats?room=` reads the call's counters.
//! - `POST /v1/qa/call/stop   {room}` leaves and returns the final counters.
//!
//! Not a UI surface: errors carry a program token and edge's error text, no
//! localized message ids.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::Deserialize;

use ciris_edge::transport::av_call::{Call, CallOptions, Frame, LegOutcome};
use ciris_edge::Edge;
use ciris_persist::prelude::Engine;

use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::resolve_bearer;

/// The env switch that mounts the routes.
pub const ENV_QA_CALLS: &str = "CIRIS_QA_CALLS";
/// Longest stream one request may run.
const MAX_STREAM_SECS: u64 = 300;
/// Highest frame rate one request may ask for.
const MAX_RATE_HZ: u32 = 120;
/// The frame header: seq (8) + sender's unix ms (8).
const HEADER: usize = 16;
/// Delay samples kept per call.
const MAX_SAMPLES: usize = 8192;
/// Events kept per call.
const MAX_EVENTS: usize = 64;

/// Whether the QA call routes are mounted on this node.
#[must_use]
pub fn enabled() -> bool {
    std::env::var(ENV_QA_CALLS).is_ok_and(|v| v.trim() == "1")
}

#[derive(Clone)]
struct QaState {
    engine: Arc<Engine>,
    edge: Arc<Edge>,
}

#[derive(Default)]
struct Counters {
    frames_sent: AtomicU64,
    publish_refused: AtomicU64,
    leg_delivered: AtomicU64,
    leg_congested: AtomicU64,
    leg_too_large: AtomicU64,
    leg_filtered: AtomicU64,
    leg_gone: AtomicU64,
    leg_failed: AtomicU64,
    frames_received: AtomicU64,
    bytes_received: AtomicU64,
}

struct Slot {
    call: tokio::sync::Mutex<Option<Call>>,
    counters: Counters,
    delays_ms: StdMutex<Vec<u64>>,
    /// Per publisher: frames heard and their delays (the 0.5.246 room test reads
    /// each stream on its own, not one sum across the room).
    by_publisher: StdMutex<std::collections::BTreeMap<String, (u64, Vec<u64>)>>,
    events: StdMutex<Vec<String>>,
    last_publish_error: StdMutex<Option<String>>,
    started: Instant,
    streaming: std::sync::atomic::AtomicBool,
}

fn calls() -> &'static StdMutex<HashMap<String, Arc<Slot>>> {
    static CALLS: OnceLock<StdMutex<HashMap<String, Arc<Slot>>>> = OnceLock::new();
    CALLS.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn slot(room: &str) -> Option<Arc<Slot>> {
    calls()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(room)
        .cloned()
}

fn now_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

fn fail(code: StatusCode, token: &str, detail: impl std::fmt::Display) -> Response {
    (
        code,
        Json(serde_json::json!({
            "refused": true,
            "refusal": token,
            "detail": detail.to_string(),
        })),
    )
        .into_response()
}

/// Owner gate: the same spine as `admin_ops::require_owner`.
async fn require_owner(st: &QaState, headers: &HeaderMap) -> Result<(), Response> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return Err(fail(
            StatusCode::UNAUTHORIZED,
            "session_absent",
            "the QA call routes are owner-only",
        ));
    };
    match resolve_bearer(&st.engine, token).await {
        Ok(Some(c))
            if c.role == UserRole::SystemAdmin
                && c.permissions.contains(&Permission::FullAccess) =>
        {
            Ok(())
        }
        Ok(Some(_)) => Err(fail(
            StatusCode::FORBIDDEN,
            "not_owner",
            "the QA call routes need the owner (SYSTEM_ADMIN) role",
        )),
        Ok(None) => Err(fail(
            StatusCode::UNAUTHORIZED,
            "session_invalid",
            "the session token did not resolve",
        )),
        Err(e) => Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "session_unresolvable",
            format!("{e:#}"),
        )),
    }
}

#[derive(Deserialize)]
struct StartBody {
    room: String,
    #[serde(default)]
    relay: bool,
}

async fn start(
    State(st): State<QaState>,
    headers: HeaderMap,
    Json(b): Json<StartBody>,
) -> Response {
    if let Err(r) = require_owner(&st, &headers).await {
        return r;
    }
    if slot(&b.room).is_some() {
        return fail(StatusCode::CONFLICT, "call_already_joined", &b.room);
    }
    let opts = CallOptions {
        relay: b.relay,
        ..CallOptions::default()
    };
    let mut call = match st.edge.join_call(&b.room, opts).await {
        Ok(c) => c,
        Err(e) => return fail(StatusCode::UNPROCESSABLE_ENTITY, "join_refused", e),
    };
    let slot = Arc::new(Slot {
        call: tokio::sync::Mutex::new(None),
        counters: Counters::default(),
        delays_ms: StdMutex::new(Vec::new()),
        by_publisher: StdMutex::new(std::collections::BTreeMap::new()),
        events: StdMutex::new(Vec::new()),
        last_publish_error: StdMutex::new(None),
        started: Instant::now(),
        streaming: std::sync::atomic::AtomicBool::new(false),
    });
    // Drain what the other members publish: count it and read its send time.
    // Ends when the call ends (the sender side of the channel drops).
    if let Some(mut frames) = call.frames() {
        let s = Arc::clone(&slot);
        tokio::spawn(async move {
            while let Some(f) = frames.recv().await {
                s.counters.frames_received.fetch_add(1, Ordering::Relaxed);
                s.counters
                    .bytes_received
                    .fetch_add(f.bytes.len() as u64, Ordering::Relaxed);
                let delay = (f.bytes.len() >= HEADER).then(|| {
                    let mut sent = [0u8; 8];
                    sent.copy_from_slice(&f.bytes[8..16]);
                    now_ms().saturating_sub(u64::from_be_bytes(sent))
                });
                if let Some(delay) = delay {
                    let mut d = s
                        .delays_ms
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if d.len() < MAX_SAMPLES {
                        d.push(delay);
                    }
                }
                let mut by = s
                    .by_publisher
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let entry = by.entry(f.publisher.clone()).or_default();
                entry.0 += 1;
                if let Some(delay) = delay {
                    if entry.1.len() < MAX_SAMPLES {
                        entry.1.push(delay);
                    }
                }
            }
        });
    }
    if let Some(mut events) = call.events() {
        let s = Arc::clone(&slot);
        tokio::spawn(async move {
            while let Some(e) = events.recv().await {
                let mut v = s
                    .events
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if v.len() < MAX_EVENTS {
                    v.push(format!("{e:?}"));
                }
            }
        });
    }
    let legs = call.legs();
    let budget = call.chunk_plaintext_budget();
    *slot.call.lock().await = Some(call);
    calls()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(b.room.clone(), slot);
    tracing::info!(room = %b.room, legs = legs.len(), "qa call: joined");
    Json(serde_json::json!({
        "room": b.room,
        "joined": true,
        "legs": legs,
        "frame_budget_bytes": budget,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct StreamBody {
    room: String,
    rate_hz: u32,
    frame_bytes: usize,
    seconds: u64,
}

async fn stream(
    State(st): State<QaState>,
    headers: HeaderMap,
    Json(b): Json<StreamBody>,
) -> Response {
    if let Err(r) = require_owner(&st, &headers).await {
        return r;
    }
    let Some(slot) = slot(&b.room) else {
        return fail(StatusCode::NOT_FOUND, "no_call", &b.room);
    };
    if b.rate_hz == 0 || b.rate_hz > MAX_RATE_HZ {
        return fail(
            StatusCode::BAD_REQUEST,
            "bad_rate",
            format!("rate_hz must be 1..={MAX_RATE_HZ}"),
        );
    }
    if b.seconds == 0 || b.seconds > MAX_STREAM_SECS {
        return fail(
            StatusCode::BAD_REQUEST,
            "bad_duration",
            format!("seconds must be 1..={MAX_STREAM_SECS}"),
        );
    }
    if b.frame_bytes < HEADER {
        return fail(
            StatusCode::BAD_REQUEST,
            "bad_frame_size",
            format!("frame_bytes must be at least {HEADER}"),
        );
    }
    if slot.streaming.swap(true, Ordering::AcqRel) {
        return fail(StatusCode::CONFLICT, "already_streaming", &b.room);
    }
    let total = u64::from(b.rate_hz) * b.seconds;
    let period = Duration::from_secs(1) / b.rate_hz;
    let s = Arc::clone(&slot);
    let size = b.frame_bytes;
    tokio::spawn(async move {
        let t0 = tokio::time::Instant::now();
        // A bounded run: `total` frames, each at its own slot, never a
        // standing ticker.
        for i in 0..total {
            tokio::time::sleep_until(t0 + period * u32::try_from(i).unwrap_or(u32::MAX)).await;
            let mut bytes = vec![0u8; size];
            bytes[..8].copy_from_slice(&i.to_be_bytes());
            bytes[8..16].copy_from_slice(&now_ms().to_be_bytes());
            let mut guard = s.call.lock().await;
            let Some(call) = guard.as_mut() else { break };
            match call.publish(Frame::opaque(bytes)).await {
                Ok(report) => {
                    s.counters.frames_sent.fetch_add(1, Ordering::Relaxed);
                    for (_, o) in &report.legs {
                        let c = match o {
                            LegOutcome::Delivered => &s.counters.leg_delivered,
                            LegOutcome::Congested => &s.counters.leg_congested,
                            LegOutcome::TooLarge => &s.counters.leg_too_large,
                            LegOutcome::FilteredByPolicy => &s.counters.leg_filtered,
                            LegOutcome::Gone => &s.counters.leg_gone,
                            LegOutcome::Failed(_) => &s.counters.leg_failed,
                        };
                        c.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    s.counters.publish_refused.fetch_add(1, Ordering::Relaxed);
                    *s.last_publish_error
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(format!("{e}"));
                }
            }
        }
        s.streaming.store(false, Ordering::Release);
    });
    Json(serde_json::json!({
        "room": b.room,
        "streaming": true,
        "frames": total,
        "rate_hz": b.rate_hz,
        "frame_bytes": size,
    }))
    .into_response()
}

fn percentile(sorted: &[u64], p: f64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let i = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted.get(i).copied()
}

fn by_publisher_json(slot: &Slot) -> serde_json::Value {
    let by = slot
        .by_publisher
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut out = serde_json::Map::new();
    for (publisher, (frames, delays)) in by.iter() {
        let mut d = delays.clone();
        d.sort_unstable();
        out.insert(
            publisher.clone(),
            serde_json::json!({
                "frames": frames,
                "delay_ms_p50": percentile(&d, 0.5),
                "delay_ms_p95": percentile(&d, 0.95),
            }),
        );
    }
    serde_json::Value::Object(out)
}

async fn stats_of(slot: &Slot) -> serde_json::Value {
    let c = &slot.counters;
    let mut delays = slot
        .delays_ms
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    delays.sort_unstable();
    let guard = slot.call.lock().await;
    let call_view = guard.as_ref().map(|call| {
        let reorder = call.reorder_counts();
        let alm = call.alm_counts();
        let auth = call.chunk_auth_counts();
        // How each heard stream reaches this node: straight from its
        // publisher, or through another member relaying it (the ALM's parent).
        let streams: Vec<_> = call
            .alm_parents()
            .into_iter()
            .map(|p| {
                let leg = match (&p.publisher, &p.primary) {
                    (_, None) => "none",
                    (Some(publ), Some(prim)) if publ == prim => "direct",
                    (None, Some(_)) => "unknown",
                    _ => "member_relay",
                };
                serde_json::json!({
                    "publisher": p.publisher,
                    "leg": leg,
                    "primary": p.primary,
                    "standby": p.standby,
                    "parent_changes": p.parent_changes,
                })
            })
            .collect();
        serde_json::json!({
            "state": format!("{:?}", call.state()),
            "service_tier": format!("{:?}", call.service_tier()),
            "legs": call.legs(),
            "frame_budget_bytes": call.chunk_plaintext_budget(),
            "streams": streams,
            "reorder": {
                "released": reorder.released,
                "skipped": reorder.skipped,
                "duplicates": reorder.duplicates,
                "expired_late": reorder.late,
            },
            "chunk_auth": {
                "verified": auth.verified,
                "forged": auth.forged,
                "unbound": auth.unbound,
                "bindings_installed": auth.bindings_installed,
                "bindings_refused": auth.bindings_refused,
            },
            "alm": {
                "stale_dropped": alm.stale_dropped,
                "forwarded": alm.forwarded,
                "legs_shed_to_base": alm.legs_shed_to_base,
                "admitted": alm.admitted,
                "shed": alm.shed,
                "refused": alm.refused,
            },
        })
    });
    drop(guard);
    serde_json::json!({
        "elapsed_s": slot.started.elapsed().as_secs(),
        "streaming": slot.streaming.load(Ordering::Acquire),
        "sent": {
            "frames": c.frames_sent.load(Ordering::Relaxed),
            "publish_refused": c.publish_refused.load(Ordering::Relaxed),
            "last_publish_error": slot.last_publish_error.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone(),
            "legs": {
                "delivered": c.leg_delivered.load(Ordering::Relaxed),
                "congested": c.leg_congested.load(Ordering::Relaxed),
                "too_large": c.leg_too_large.load(Ordering::Relaxed),
                "filtered": c.leg_filtered.load(Ordering::Relaxed),
                "gone": c.leg_gone.load(Ordering::Relaxed),
                "failed": c.leg_failed.load(Ordering::Relaxed),
            },
        },
        "received": {
            "frames": c.frames_received.load(Ordering::Relaxed),
            "bytes": c.bytes_received.load(Ordering::Relaxed),
            "delay_ms_p50": percentile(&delays, 0.5),
            "delay_ms_p95": percentile(&delays, 0.95),
            "delay_ms_max": delays.last(),
            "by_publisher": by_publisher_json(slot),
        },
        "call": call_view,
        "events": slot.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone(),
    })
}

#[derive(Deserialize)]
struct RoomQuery {
    room: String,
}

async fn stats(
    State(st): State<QaState>,
    headers: HeaderMap,
    Query(q): Query<RoomQuery>,
) -> Response {
    if let Err(r) = require_owner(&st, &headers).await {
        return r;
    }
    let Some(slot) = slot(&q.room) else {
        return fail(StatusCode::NOT_FOUND, "no_call", &q.room);
    };
    let mut v = stats_of(&slot).await;
    v["room"] = serde_json::json!(q.room);
    Json(v).into_response()
}

async fn stop(State(st): State<QaState>, headers: HeaderMap, Json(b): Json<RoomQuery>) -> Response {
    if let Err(r) = require_owner(&st, &headers).await {
        return r;
    }
    let Some(slot) = slot(&b.room) else {
        return fail(StatusCode::NOT_FOUND, "no_call", &b.room);
    };
    let mut v = stats_of(&slot).await;
    let call = slot.call.lock().await.take();
    calls()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&b.room);
    let summary = match call {
        Some(c) => match c.leave().await {
            Ok(s) => serde_json::json!({
                "frames_published": s.frames_published,
                "frames_received": s.frames_received,
                "frames_skipped": s.frames_skipped,
                "duplicates": s.duplicates,
                "epochs": s.epochs,
            }),
            Err(e) => serde_json::json!({ "leave_error": e.to_string() }),
        },
        None => serde_json::Value::Null,
    };
    v["room"] = serde_json::json!(b.room);
    v["summary"] = summary;
    tracing::info!(room = %b.room, "qa call: left");
    Json(v).into_response()
}

// ─── Echo (0.5.246): one client leg can call ONE node ───────────────────────
//
// `POST /v1/qa/call/echo {room}` joins `room`'s call as this node's OWNER (the
// person, like a member) and republishes every frame it hears, codec_id,
// layer and bytes unchanged, so the five-platform runner proves mic → node →
// speaker and camera → node → tile with no second device. A republished frame's
// publisher is the echo node's person. `POST /v1/qa/call/echo/stop {room}`.

struct Echo {
    task: tokio::task::JoinHandle<()>,
    echoed: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

fn echoes() -> &'static StdMutex<HashMap<String, Echo>> {
    static E: OnceLock<StdMutex<HashMap<String, Echo>>> = OnceLock::new();
    E.get_or_init(|| StdMutex::new(HashMap::new()))
}

async fn echo_start(
    State(st): State<QaState>,
    headers: HeaderMap,
    Json(b): Json<RoomQuery>,
) -> Response {
    if let Err(r) = require_owner(&st, &headers).await {
        return r;
    }
    let room = b.room;
    if echoes()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains_key(&room)
    {
        return fail(StatusCode::CONFLICT, "echo_already_running", &room);
    }
    let node = crate::node_key::wire_identity()
        .map(str::to_owned)
        .unwrap_or_default();
    let actor = match crate::owner_signer_capsule::for_owned_node(&st.engine, &node).await {
        Ok(c) => Some(Arc::clone(c.edge_signer())),
        Err(e) => {
            return fail(
                StatusCode::FORBIDDEN,
                "owner_pen_unavailable",
                format!("{e:?}"),
            )
        }
    };
    let mut call = match st
        .edge
        .join_call_as(&room, CallOptions::default(), actor)
        .await
    {
        Ok(c) => c,
        Err(e) => return fail(StatusCode::UNPROCESSABLE_ENTITY, "join_refused", e),
    };
    let Some(mut frames) = call.frames() else {
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "frames_taken", &room);
    };
    let echoed = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicU64::new(0));
    let (e2, d2) = (Arc::clone(&echoed), Arc::clone(&dropped));
    let task = tokio::spawn(async move {
        while let Some(f) = frames.recv().await {
            let frame = Frame {
                codec_id: f.codec_id,
                layer: f.layer,
                bytes: f.bytes,
            };
            match call.publish(frame).await {
                Ok(_) => e2.fetch_add(1, Ordering::Relaxed),
                Err(_) => d2.fetch_add(1, Ordering::Relaxed),
            };
        }
        let _ = call.leave().await;
    });
    echoes()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(
            room.clone(),
            Echo {
                task,
                echoed,
                dropped,
            },
        );
    tracing::info!(room = %room, "qa call: ECHO joined as the owner; republishing every frame heard");
    (
        StatusCode::OK,
        Json(serde_json::json!({ "room": room, "echo": "running" })),
    )
        .into_response()
}

async fn echo_stop(
    State(st): State<QaState>,
    headers: HeaderMap,
    Json(b): Json<RoomQuery>,
) -> Response {
    if let Err(r) = require_owner(&st, &headers).await {
        return r;
    }
    let Some(e) = echoes()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&b.room)
    else {
        return fail(StatusCode::NOT_FOUND, "echo_not_running", &b.room);
    };
    e.task.abort();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "room": b.room,
            "echoed": e.echoed.load(Ordering::Relaxed),
            "dropped": e.dropped.load(Ordering::Relaxed),
        })),
    )
        .into_response()
}

/// The QA call routes, or an empty router when `CIRIS_QA_CALLS` is not `1`.
pub fn router(engine: Arc<Engine>, edge: Arc<Edge>) -> Router {
    if !enabled() {
        return Router::new();
    }
    tracing::warn!(
        "QA call routes MOUNTED ({ENV_QA_CALLS}=1): /v1/qa/call/{{start,stream,stats,stop}}, \
         owner-only. A production node does not set this"
    );
    Router::new()
        .route("/v1/qa/call/start", axum::routing::post(start))
        .route("/v1/qa/call/stream", axum::routing::post(stream))
        .route("/v1/qa/call/stats", axum::routing::get(stats))
        .route("/v1/qa/call/stop", axum::routing::post(stop))
        .route("/v1/qa/call/echo", axum::routing::post(echo_start))
        .route("/v1/qa/call/echo/stop", axum::routing::post(echo_stop))
        .with_state(QaState { engine, edge })
}
