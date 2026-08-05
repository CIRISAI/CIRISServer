//! **The agent-compat federation edge surface** (CIRISServer#261) — the four
//! `/v1/federation/*` routes the CIRISAgent wave-2 DRY purge deletes from
//! Python that need the LIVE `Arc<Edge>` (not just the persist directory):
//!
//!   - `GET  /v1/federation/identity` — signer_key_id + edge crate version +
//!     local peer counts + advertised capabilities (`identity.py`).
//!   - `GET  /v1/federation/metrics` — the Edge metrics snapshot, projected
//!     into the SAME family-keyed maps the Edge PyO3 `metrics_snapshot()`
//!     produced (`metrics.py`).
//!   - `POST /v1/federation/content/{content_id}` — content-addressed fetch
//!     from a named peer via `Edge::fetch_content` (`content.py`).
//!   - `GET  /v1/federation/events/{channel}` — the SSE bridge over the edge
//!     event bus, one channel per Edge `subscribe_*` stream (`events.py` +
//!     `federation_sse_bridge.py`).
//!
//! The deleted agent route files ARE the wire spec: every response shape,
//! error envelope, and SSE frame name below mirrors them field-for-field
//! (the vendored KMP client — `CIRISApiClient.kt` federation surface +
//! `FederationEventStream.kt` — consumes these shapes). Success bodies ride
//! the agent's `SuccessResponse` envelope (`{"data": <T>}`); the client's
//! `decodeFederationEnvelope` unwraps it (and tolerates bare bodies, but we
//! match the agent exactly).
//!
//! ## Auth posture
//!
//! `identity` / `metrics` / `events` are unauthenticated — the agent gated
//! them OBSERVER+ (its lowest tier), and the node's read surface has no
//! observer tier; they carry non-sensitive operational telemetry, same
//! posture as the peers list ([`crate::federation_peers`]) and `/v1/health`.
//! `content` POST stays owner-gated (the agent required SYSTEM_ADMIN — it
//! commands a network fetch on the node's behalf), via the SAME session gate
//! the peers sideband PUTs share ([`crate::federation_peers::require_owner_session`]).
//!
//! ## Why a sibling module (not more of `federation_peers.rs`)
//!
//! These four routes need the live `Arc<Edge>` in state; the peers surface is
//! persist-only (and its integration test stands up an Engine WITHOUT an
//! Edge). Splitting keeps the peers router testable with no transport.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use futures_util::StreamExt;
use serde::Deserialize;

use ciris_edge::events::{EventSeverity, NetworkEvent};
use ciris_edge::{ContentResult, Edge, VerifiedEnvelopeSnapshot};
use ciris_persist::prelude::Engine;

use crate::federation_peers::require_owner_session;

/// The federation-surface capability list — the agent's fixed literal
/// (`identity.py::_FEDERATION_CAPABILITIES`), bumped in lock-step with the
/// actual served routes. All five are live here.
const FEDERATION_CAPABILITIES: &[&str] = &[
    "sas",
    "fetch_content",
    "metrics",
    "subscribe_events",
    "inline_text",
];

/// The valid event channels — the agent's `VALID_CHANNELS`
/// (`federation_events.py`), one per Edge `subscribe_*` stream.
const VALID_CHANNELS: &[&str] = &[
    "announces",
    "feed",
    "interface_events",
    "link_events",
    "path_events",
    "resource_events",
    "all",
];

/// SSE heartbeat cadence — the agent bridge's 30 s comment cadence
/// (`federation_sse_bridge.py::HEARTBEAT_INTERVAL_SECONDS`; the client's
/// stall guard fires at 60 s of silence, so this must stay well under it).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct SurfaceState {
    engine: Arc<Engine>,
    /// The ONE shared edge runtime (compose builds/reuses it before mounting).
    edge: Arc<Edge>,
}

/// How the peer counts on `GET /v1/federation/identity` were arrived at.
///
/// **Three states, not one counter** (the 2026-08-05 RCA's second instrument
/// finding). "Zero peers", "the store could not be read" and "this node cannot
/// resolve its own identity so there is no `self` to count peers OF" are
/// different conditions that used to render as the same `0`.
const COUNTS_MEASURED: &str = "measured";
/// The peer store could not be read; the counts are not evidence.
const COUNTS_STORE_UNAVAILABLE: &str = "store_unavailable";

fn err(code: StatusCode, error: &str) -> Response {
    (code, Json(serde_json::json!({ "error": error }))).into_response()
}

// ─── GET /v1/federation/identity ─────────────────────────────────────────────

/// `GET /v1/federation/identity` → `{ "data": { signer_key_id, crate_version,
/// peer_count_total, peer_count_canonical, capabilities } }` — the agent's
/// `FederationIdentityResponse`, polled by the client home tab ("your
/// federation address is X").
///
/// A peer-count store error degrades to zero counts rather than failing the
/// whole call — the agent did the same when its seeder wasn't wired ("we
/// still have a working Edge identity to return") — but the degradation is now
/// **named**: `peer_counts_standing` distinguishes a measured zero from an
/// unreadable store from an unresolvable self (CIRISServer#372 / the
/// 2026-08-05 RCA). A zero that cannot say why it is zero is not evidence.
///
/// The node's own key id — the `self` the peers are counted relative to — is
/// resolved from the engine (CIRISServer#372 Level 2), not threaded in from
/// `cfg.key_id`. It was documented as `== edge.signer_key_id()`; asking the
/// engine makes that an identity rather than an assertion.
async fn get_identity(State(st): State<SurfaceState>) -> Response {
    let (total, canonical, standing) =
        match crate::self_identity::resolve(&st.engine, "federation_surface").await {
            Err(_) => (0, 0, crate::self_identity::REFUSAL_TOKEN),
            Ok(self_key_id) => {
                match crate::federation_peers::peer_counts(&st.engine, &self_key_id).await {
                    Ok((t, c)) => (t, c, COUNTS_MEASURED),
                    Err(e) => {
                        tracing::debug!("peer counts unavailable for federation identity: {e}");
                        (0, 0, COUNTS_STORE_UNAVAILABLE)
                    }
                }
            }
        };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": {
                "signer_key_id": st.edge.signer_key_id(),
                "crate_version": ciris_edge::version::VERSION,
                "peer_count_total": total,
                "peer_count_canonical": canonical,
                "peer_counts_standing": standing,
                "capabilities": FEDERATION_CAPABILITIES,
            }
        })),
    )
        .into_response()
}

// ─── GET /v1/federation/metrics ──────────────────────────────────────────────

/// `GET /v1/federation/metrics` → `{ "data": FederationMetricsResponse }`.
///
/// Projects [`ciris_edge::observability::EdgeMetricsBundle`] into the SAME
/// family-keyed string maps the Edge PyO3 `metrics_snapshot()` produced —
/// including the exact key formatting the client round-trips on:
///
///   - `envelopes_{sent,received}_total`: `MessageType` Debug repr
///     ("InlineText", "FederationAnnouncement", …).
///   - `send_failures_total`: `"<transport>:<cause>"`.
///   - `verify_failures_total` / `durable_queue_depth`: the enums' stable
///     snake-case `as_str` labels.
///   - `transport_bytes_{in,out}_total`: the transport id string.
///   - `peer_reachability_ratio`: `"<peer_key>:<medium>"`.
///
/// Like the PyO3 surface, the live reachability tracker is mirrored into the
/// gauge BEFORE snapshotting so pollers see current ratios.
///
/// `inline_text_subscriber_count`: the agent sourced this from a PyO3-layer
/// subscriber registry that doesn't exist server-side; the closest live
/// diagnostic is the verified-feed broadcast receiver count (which the SSE
/// `feed` channel below subscribes through), so that is what's served.
async fn get_metrics(State(st): State<SurfaceState>) -> Response {
    // Mirror the live reachability tracker into the gauge before snapshotting
    // — consumers expect the gauge to be current (PyO3 parity).
    let reach_snap = st.edge.reachability_tracker().snapshot_all();
    let m = st.edge.metrics();
    for entry in &reach_snap {
        m.set_peer_reachability(&entry.peer_key_id, entry.transport_id.0, entry.ratio());
    }
    let bundle = m.snapshot();

    let debug_keyed = |map: &std::collections::HashMap<ciris_edge::messages::MessageType, u64>| {
        map.iter()
            .map(|(k, v)| (format!("{k:?}"), serde_json::json!(v)))
            .collect::<serde_json::Map<_, _>>()
    };
    let envelopes_sent = debug_keyed(&bundle.envelopes_sent_total);
    let envelopes_received = debug_keyed(&bundle.envelopes_received_total);
    let send_failures: serde_json::Map<_, _> = bundle
        .send_failures_total
        .iter()
        .map(|((t, c), v)| (format!("{}:{c}", t.0), serde_json::json!(v)))
        .collect();
    let verify_failures: serde_json::Map<_, _> = bundle
        .verify_failures_total
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), serde_json::json!(v)))
        .collect();
    let durable_depth: serde_json::Map<_, _> = bundle
        .durable_queue_depth
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), serde_json::json!(v)))
        .collect();
    let bytes_in: serde_json::Map<_, _> = bundle
        .transport_bytes_in_total
        .iter()
        .map(|(k, v)| (k.0.to_string(), serde_json::json!(v)))
        .collect();
    let bytes_out: serde_json::Map<_, _> = bundle
        .transport_bytes_out_total
        .iter()
        .map(|(k, v)| (k.0.to_string(), serde_json::json!(v)))
        .collect();
    let reachability: serde_json::Map<_, _> = bundle
        .peer_reachability_ratio
        .iter()
        .map(|((peer, medium), v)| (format!("{peer}:{medium}"), serde_json::json!(v)))
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": {
                "envelopes_sent_total": envelopes_sent,
                "envelopes_received_total": envelopes_received,
                "send_failures_total": send_failures,
                "verify_failures_total": verify_failures,
                "durable_queue_depth": durable_depth,
                "transport_bytes_in_total": bytes_in,
                "transport_bytes_out_total": bytes_out,
                "peer_reachability_ratio": reachability,
                "inline_text_subscriber_count": st.edge.verified_feed_subscriber_count(),
            }
        })),
    )
        .into_response()
}

// ─── POST /v1/federation/content/{content_id} ────────────────────────────────

/// Body — the agent's `FederationContentFetchRequest` (`extra="forbid"` ⇒
/// `deny_unknown_fields`; `timeout_ms` defaults 30 s, clamped 1 ms..5 min).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentFetchRequest {
    peer_key_id: String,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

fn default_timeout_ms() -> u64 {
    30_000
}

/// `POST /v1/federation/content/{content_id}` (OWNER) — fetch content
/// addressed by SHA-256 from a named peer. Mirrors `content.py`:
///
///   - 400 `INVALID_CONTENT_ID` — path segment isn't 64-char hex.
///   - 404 `CONTENT_MISS` `{content_id, peer_key_id, reason}` — the peer
///     reported the bytes unavailable (typed `MissReason` string).
///   - 503 `FETCH_FAILED` `{detail}` — timeout / transport failure /
///     unexpected fetch result kind.
///   - 200 `{ "data": { content_id, content_type: null, payload_base64,
///     size_bytes, fetched_at } }` — the SHA-256 integrity invariant
///     (`sha256(decode(payload_base64)) == content_id`) is enforced by
///     Edge's dispatch-side ContentBody gate before the bytes reach us.
///
/// `ContentResult::External` (the multimedia blob pointer, post-dates the
/// agent contract) surfaces as `FETCH_FAILED` — same as the agent's
/// "unknown fetch_content kind" arm; a typed external-pointer response is
/// future contract work, not a silent shape change.
async fn fetch_content(
    State(st): State<SurfaceState>,
    Path(content_id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner_session(&st.engine, &headers).await {
        return resp;
    }
    let sha: Option<[u8; 32]> = (content_id.len() == 64)
        .then(|| hex::decode(&content_id).ok())
        .flatten()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
    let Some(sha) = sha else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "INVALID_CONTENT_ID",
                "detail": "content_id must be a 64-character hex SHA-256 digest.",
            })),
        )
            .into_response();
    };
    let req: ContentFetchRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    if req.peer_key_id.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "peer_key_id must not be empty");
    }
    if !(1..=300_000).contains(&req.timeout_ms) {
        return err(
            StatusCode::BAD_REQUEST,
            "timeout_ms must be in 1..=300000 (1ms..5min)",
        );
    }

    match st
        .edge
        .fetch_content(&req.peer_key_id, sha, Duration::from_millis(req.timeout_ms))
        .await
    {
        Ok(ContentResult::Bytes(bytes)) => {
            use base64::engine::general_purpose::STANDARD as BASE64;
            use base64::Engine as _;
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "data": {
                        "content_id": content_id,
                        "content_type": serde_json::Value::Null,
                        "payload_base64": BASE64.encode(&bytes),
                        "size_bytes": bytes.len(),
                        "fetched_at": chrono::Utc::now().to_rfc3339(),
                    }
                })),
            )
                .into_response()
        }
        Ok(ContentResult::ContentMiss { reason }) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "CONTENT_MISS",
                "content_id": content_id,
                "peer_key_id": req.peer_key_id,
                "reason": reason,
            })),
        )
            .into_response(),
        Ok(other) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "FETCH_FAILED",
                "detail": format!(
                    "Edge returned an unhandled fetch_content result kind: {}",
                    match other {
                        ContentResult::External { .. } => "external",
                        _ => "unknown",
                    }
                ),
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "FETCH_FAILED",
                "detail": format!("{e}"),
            })),
        )
            .into_response(),
    }
}

// ─── GET /v1/federation/events/{channel} — the SSE bridge ───────────────────

/// One live subscription — either a network-event channel or the verified
/// feed. Unifies the two broadcast receiver types behind one `recv` that
/// yields the `(event_type, payload)` pair the envelope needs.
enum ChannelRx {
    Net(tokio::sync::broadcast::Receiver<NetworkEvent>),
    Feed(tokio::sync::broadcast::Receiver<VerifiedEnvelopeSnapshot>),
}

impl ChannelRx {
    async fn recv(
        &mut self,
    ) -> Result<(String, serde_json::Value), tokio::sync::broadcast::error::RecvError> {
        match self {
            ChannelRx::Net(rx) => rx.recv().await.map(|ev| {
                let payload = network_event_payload(&ev);
                (format!("{:?}", ev.kind), payload)
            }),
            ChannelRx::Feed(rx) => rx.recv().await.map(|snap| {
                let message_type = format!("{:?}", snap.envelope.message_type);
                let payload = serde_json::json!({
                    "message_type": message_type,
                    "signing_key_id": snap.envelope.signing_key_id,
                    "destination_key_id": snap.envelope.destination_key_id,
                    "body_sha256_prefix": hex::encode(&snap.body_sha256[..4]),
                    "transport_id": snap.transport_id.0,
                    "received_at_ms": snap.received_at.timestamp_millis(),
                });
                (message_type, payload)
            }),
        }
    }
}

/// Project a [`NetworkEvent`] into the JSON payload the agent bridge shipped —
/// the PyO3 `network_event_to_pydict` key set, with the bytes fields
/// hex-encoded (the envelope schema documents `identity_hash?` / `app_data?` /
/// `link_id?` as hex; the Python bridge's `default=str` byte handling was the
/// one place its wire form was mushy, so hex is the honest canonical form).
fn network_event_payload(ev: &NetworkEvent) -> serde_json::Value {
    let sev = match ev.severity {
        EventSeverity::Info => "info",
        EventSeverity::Warning => "warning",
        EventSeverity::Error => "error",
    };
    serde_json::json!({
        "at": ev.at.to_rfc3339(),
        "kind": format!("{:?}", ev.kind),
        "severity": sev,
        "message": ev.message,
        "peer_key_id": ev.peer_key_id,
        "transport_id": ev.transport_id,
        "aspect": ev.aspect,
        "identity_hash": ev.identity_hash.as_deref().map(hex::encode),
        "app_data": ev.app_data.as_deref().map(hex::encode),
        "rssi_dbm": ev.rssi_dbm,
        "snr_db": ev.snr_db,
        "link_id": ev.link_id.as_deref().map(hex::encode),
        "destination_hash": ev.destination_hash.as_deref().map(hex::encode),
        "hops": ev.hops,
        "resource_kind": ev.resource_kind,
        "measurement": ev.measurement,
        "unit": ev.unit,
        "lagged_count": ev.lagged_count,
    })
}

/// Build one `federation_event` SSE frame: the agent's
/// `FederationEventEnvelope` (`event_id` UUID4 for client-side dedup,
/// `channel`, `timestamp`, `event_type`, channel-specific `payload`), with
/// the SSE `id:` line set to the envelope's `event_id`.
fn federation_event_frame(channel: &str, event_type: String, payload: serde_json::Value) -> Event {
    let event_id = uuid::Uuid::new_v4().to_string();
    let envelope = serde_json::json!({
        "event_id": event_id,
        "channel": channel,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "event_type": event_type,
        "payload": payload,
    });
    Event::default()
        .id(event_id)
        .event("federation_event")
        .data(envelope.to_string())
}

/// `GET /v1/federation/events/{channel}` — the SSE stream over the edge event
/// bus (the deleted `events.py` + `federation_sse_bridge.py` contract).
///
/// Frame vocabulary (all `data:` payloads JSON; names are what the client's
/// `FederationEventStream.parseFrame` switches on):
///
///   - `connected`        — one-shot on connect (`{status, channel, timestamp}`).
///   - `resume-notice`    — one-shot iff `Last-Event-ID` was sent: Edge
///     broadcast channels don't replay, so the client is told to resync its
///     snapshot from a non-streaming endpoint.
///   - `federation_event` — one per Edge emission (see
///     [`federation_event_frame`]).
///   - `error`            — terminal: the receiver LAGGED past the bounded
///     broadcast channel (the agent's producer surfaced the same condition
///     as `EDGE_PRODUCER_ERROR` and ended the stream; the client reconnects).
///   - `stream-closed`    — terminal: the bus sender dropped (edge shutdown).
///
/// Plus `: heartbeat` SSE comments every 30 s of idle (axum `KeepAlive` —
/// carriers don't idle-kill the socket, and the client's 60 s stall guard
/// stays fed).
///
/// Backpressure is the broadcast channel's own bounded drop-oldest (a lagged
/// consumer errors and reconnects) — same "live status now, not perfect
/// replay" bias as the agent bridge's drop-oldest queue.
async fn events_stream(
    State(st): State<SurfaceState>,
    Path(channel): Path<String>,
    headers: HeaderMap,
) -> Response {
    let bus = st.edge.events();
    let rx = match channel.as_str() {
        "announces" => ChannelRx::Net(bus.subscribe_announces()),
        "feed" => ChannelRx::Feed(st.edge.subscribe_verified_feed()),
        "interface_events" => ChannelRx::Net(bus.subscribe_interfaces()),
        "link_events" => ChannelRx::Net(bus.subscribe_links()),
        "path_events" => ChannelRx::Net(bus.subscribe_paths()),
        "resource_events" => ChannelRx::Net(bus.subscribe_resources()),
        "all" => ChannelRx::Net(bus.subscribe_all()),
        // 400 not 404 — the route exists; the channel name is wrong. The body
        // is the agent's `FederationEventErrorEnvelope`.
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "UNKNOWN_CHANNEL",
                    "detail": format!(
                        "Channel '{channel}' is not a recognized federation event channel. \
                         Valid channels: {}.",
                        VALID_CHANNELS.join(", ")
                    ),
                    "valid_channels": VALID_CHANNELS,
                })),
            )
                .into_response()
        }
    };

    // Preamble frames: connected (always) + resume-notice (iff Last-Event-ID).
    let mut preamble = vec![Event::default().event("connected").data(
        serde_json::json!({
            "status": "connected",
            "channel": channel,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        })
        .to_string(),
    )];
    if let Some(last_event_id) = headers
        .get("Last-Event-ID")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    {
        preamble.push(
            Event::default().event("resume-notice").data(
                serde_json::json!({
                    "requested_last_event_id": last_event_id,
                    "replay_supported": false,
                    "detail": "Edge subscription channels do not support replay; starting from \
                               live tail. Client should resync any cached snapshot via a \
                               non-streaming endpoint.",
                })
                .to_string(),
            ),
        );
    }

    // Live tail: unfold over the receiver. A terminal frame (lagged / closed)
    // is yielded ONCE with the receiver dropped, then the stream ends.
    let live_channel = channel.clone();
    let live = futures_util::stream::unfold(Some(rx), move |state| {
        let channel = live_channel.clone();
        async move {
            let mut rx = state?;
            match rx.recv().await {
                Ok((event_type, payload)) => Some((
                    federation_event_frame(&channel, event_type, payload),
                    Some(rx),
                )),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => Some((
                    Event::default().event("error").data(
                        serde_json::json!({
                            "error": "EDGE_PRODUCER_ERROR",
                            "detail": format!("event subscription lagged by {n} events"),
                        })
                        .to_string(),
                    ),
                    None,
                )),
                Err(tokio::sync::broadcast::error::RecvError::Closed) => Some((
                    Event::default().event("stream-closed").data(
                        serde_json::json!({
                            "channel": channel,
                            "reason": "edge_subscription_drained",
                        })
                        .to_string(),
                    ),
                    None,
                )),
            }
        }
    });

    let stream = futures_util::stream::iter(preamble)
        .chain(live)
        .map(Ok::<Event, std::convert::Infallible>);

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(HEARTBEAT_INTERVAL)
                .text("heartbeat"),
        )
        .into_response()
}

/// The agent-compat federation edge-surface router (#261). `edge` is the ONE
/// shared edge runtime — mounted right after [`crate::federation_peers::router`]
/// in [`crate::compose`].
///
/// **It takes no key id** (CIRISServer#372 Level 2): the node's own derived
/// federation `key_id` is resolved from the engine at request time.
pub fn router(engine: Arc<Engine>, edge: Arc<Edge>) -> Router {
    let state = SurfaceState { engine, edge };
    Router::new()
        .route("/v1/federation/identity", axum::routing::get(get_identity))
        .route("/v1/federation/metrics", axum::routing::get(get_metrics))
        .route(
            "/v1/federation/content/{content_id}",
            axum::routing::post(fetch_content),
        )
        .route(
            "/v1/federation/events/{channel}",
            axum::routing::get(events_stream),
        )
        .with_state(state)
}
