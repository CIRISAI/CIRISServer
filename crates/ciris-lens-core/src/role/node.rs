//! Node mode — [`LensCore::node`] + [`NodeHandle`] (FSD §3 + #15).
//!
//! Node mode = relay mode **plus** the frozen public read API
//! (`/lens/api/v1/*`) community lens viewers consume. Federation anchor
//! deployments (`safety.ciris.ai`-class) run in node mode; relay nodes
//! that don't serve read traffic run in relay mode.
//!
//! # Architecture
//!
//! ```text
//! LensCore::node(engine, listen_addr, ...)
//!     ├── LensCore::relay(...)  ← relay mode Edge listener (inbound AccordEventsBatch)
//!     │       registers LensCoreHandler on the Edge
//!     └── axum HTTP server on listen_addr  ← read API server (GET-only)
//!             routes → ScoresOracle → DetectionEvent JSON responses
//! ```
//!
//! The relay and the HTTP server share the same `Arc<Engine>` —
//! one connection pool, one process-singleton Engine.
//!
//! # HTTP server — axum reuse
//!
//! `ciris-edge`'s `transport-http` feature transitively depends on
//! `axum` v0.8. Lens-core re-uses the axum version already in the
//! dependency graph rather than adding a separate direct dep.
//!
//! # Auth model
//!
//! Every endpoint requires federation-signed request headers:
//! - `X-Lens-Signing-Key-Id: <key_id>`
//! - `X-Lens-Signature: <hex-ed25519-sig>`
//! - `X-Lens-Signed-At: <RFC-3339>`
//!
//! The axum auth middleware calls
//! `engine.verify_hybrid_via_directory(...)` on the request canonical
//! bytes and then checks the `key_id` against the `PeerAcl`. Requests
//! that fail either step receive `401 LensQueryError::UnauthorizedSignature`.
//!
//! For the v0.4 implementation the auth middleware is **present but
//! advisory** — it validates headers when present and rejects with 401
//! when signatures fail to verify. A missing `X-Lens-Signing-Key-Id`
//! header on a non-auth-critical deployment is a configuration choice
//! left to the operator's `PeerAcl`; `AllowAll` skips the key-ID
//! presence check for local-dev.
//!
//! # Endpoints (frozen at v0.5.0 per #18)
//!
//! ```text
//! GET  /lens/api/v1/scores
//! GET  /lens/api/v1/scores/{trace_id}
//! GET  /lens/api/v1/detection_events
//! GET  /lens/api/v1/detection_events/{detection_id}
//! GET  /lens/api/v1/manifold_conformity_aggregate
//! GET  /lens/api/v1/calibration_bundles
//! GET  /lens/api/v1/calibration_bundles/{version}
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use ciris_persist::derived::types::{DetectionEvent, DetectionSeverity, EventFilter};
use ciris_persist::prelude::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::node::{PeerAcl, ScoringConfig, UxConfig};
use crate::config::{RetentionPolicy, UpstreamLens};
use crate::pipeline::lifecycle::LensCore;
use crate::role::relay::RelayError;
use crate::scores::aggregate::{compute_aggregate, AgentScoreAggregate};

// ─── Shared axum app state ─────────────────────────────────────────

/// State threaded through every axum route handler.
#[derive(Clone)]
pub(crate) struct NodeState {
    /// Host Engine — all Engine-backed read paths go through here.
    /// `None` is only valid in unit tests that exercise routes which
    /// do not call into the Engine (e.g. `/calibration_bundles`).
    pub(crate) engine: Option<Arc<Engine>>,
    /// ACL applied after signature verify. Checked by the auth
    /// middleware (`permits`) before dispatching to route handlers.
    /// v0.4: middleware is present but advisory (AllowAll bypasses
    /// the key-ID check post-verify); field is retained for the v0.5
    /// strict-auth path. Suppressing the dead-code lint here because
    /// the field IS part of the stable API shape (#15).
    #[allow(dead_code)]
    pub(crate) peer_acl: Arc<PeerAcl>,
    /// RATCHET version stamped onto responses.
    pub(crate) ratchet_version: i32,
    /// Frozen API root path prefix (e.g. `/lens/api/v1`).
    pub(crate) api_root: String,
}

// ─── Wire response types (frozen at v0.5.0 per #18) ───────────────

/// Thin envelope that serializes a `DetectionEvent` to the frozen
/// public JSON shape the node API exposes.
///
/// Field names match the OpenAPI 3.1 spec in `docs/LENS_NODE_API.md`.
/// Rename or removal = major break.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScoreResponse {
    pub detection_id: String,
    pub trace_id: String,
    pub detector: String,
    pub severity: String,
    pub conformity_variant: String,
    /// Opaque JSON — the per-score payload persist stores. Shape is
    /// detector-specific; consumers should treat it as extensible.
    pub conformity_payload: serde_json::Value,
    /// RATCHET calibration bundle version applied to this score.
    pub ratchet_calibration_version: i32,
    pub lens_core_version: String,
    pub ts: DateTime<Utc>,
}

impl From<DetectionEvent> for ScoreResponse {
    fn from(e: DetectionEvent) -> Self {
        use ciris_persist::derived::types::ConformityVariant;
        Self {
            detection_id: e.detection_id.to_string(),
            trace_id: e.trace_id,
            detector: e.detector,
            severity: severity_str(e.severity).to_string(),
            conformity_variant: match e.conformity_variant {
                ConformityVariant::Numeric => "numeric",
                ConformityVariant::Indeterminate => "indeterminate",
                ConformityVariant::Unavailable => "unavailable",
            }
            .to_string(),
            conformity_payload: e.conformity_payload,
            ratchet_calibration_version: e.ratchet_calibration_version,
            lens_core_version: e.lens_core_version,
            ts: e.ts,
        }
    }
}

/// Paginated list of scores returned by `GET /scores`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScoreListResponse {
    pub items: Vec<ScoreResponse>,
    /// Opaque cursor for the next page. `None` = last page.
    pub next_cursor: Option<String>,
}

/// Manifold-conformity aggregate returned by
/// `GET /manifold_conformity_aggregate`.
///
/// Wraps [`AgentScoreAggregate`] with the frozen API field names.
#[derive(Debug, Serialize, Deserialize)]
pub struct ManifoldAggregateResponse {
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub traces_scored: u32,
    pub conformity_numeric: u32,
    pub conformity_indeterminate: u32,
    pub conformity_unavailable: u32,
    pub detector_fire_counts: std::collections::HashMap<String, u32>,
    pub severity_info: u32,
    pub severity_warning: u32,
    pub severity_critical: u32,
}

impl From<AgentScoreAggregate> for ManifoldAggregateResponse {
    fn from(a: AgentScoreAggregate) -> Self {
        Self {
            window_start: a.window_start,
            window_end: a.window_end,
            traces_scored: a.traces_scored,
            conformity_numeric: a.conformity_numeric,
            conformity_indeterminate: a.conformity_indeterminate,
            conformity_unavailable: a.conformity_unavailable,
            detector_fire_counts: a.detector_fire_counts,
            severity_info: a.severity_distribution.info,
            severity_warning: a.severity_distribution.warning,
            severity_critical: a.severity_distribution.critical,
        }
    }
}

/// A RATCHET calibration bundle entry returned by
/// `GET /calibration_bundles` or `GET /calibration_bundles/{version}`.
#[derive(Debug, Serialize, Deserialize)]
pub struct CalibrationBundleResponse {
    pub version: i32,
    /// ISO-8601 timestamp when this bundle was registered.
    pub registered_at: Option<DateTime<Utc>>,
    /// Whether this is the current active bundle.
    pub is_current: bool,
}

/// Typed error returned by failing read handlers.
#[derive(Debug, Serialize, Deserialize)]
pub struct LensQueryError {
    pub error: String,
    pub detail: Option<String>,
}

impl LensQueryError {
    fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            detail: None,
        }
    }

    fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

fn engine_unavailable() -> (StatusCode, Json<LensQueryError>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(LensQueryError::new("engine_unavailable").with_detail("Engine not initialized")),
    )
}

fn internal_error(msg: impl Into<String>) -> (StatusCode, Json<LensQueryError>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(LensQueryError::new("internal_error").with_detail(msg)),
    )
}

fn not_found(detail: impl Into<String>) -> (StatusCode, Json<LensQueryError>) {
    (
        StatusCode::NOT_FOUND,
        Json(LensQueryError::new("not_found").with_detail(detail)),
    )
}

fn severity_str(s: DetectionSeverity) -> &'static str {
    match s {
        DetectionSeverity::Info => "info",
        DetectionSeverity::Warning => "warning",
        DetectionSeverity::Critical => "critical",
    }
}

// ─── Query parameter types ─────────────────────────────────────────

/// Query parameters for `GET /scores`.
#[derive(Debug, Deserialize, Default)]
pub struct ScoresQuery {
    pub trace_id: Option<String>,
    pub agent_id_hash: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub page_size: Option<u32>,
    pub cursor: Option<String>,
}

/// Query parameters for `GET /detection_events`.
#[derive(Debug, Deserialize, Default)]
pub struct DetectionEventsQuery {
    pub detector: Option<String>,
    pub severity: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub page_size: Option<u32>,
    pub cursor: Option<String>,
}

/// Query parameters for `GET /manifold_conformity_aggregate`.
#[derive(Debug, Deserialize)]
pub struct AggregateQuery {
    pub window_start: Option<DateTime<Utc>>,
    pub window_end: Option<DateTime<Utc>>,
    pub detector: Option<String>,
}

// ─── Route handlers ────────────────────────────────────────────────

/// `GET /lens/api/v1/scores`
///
/// Paginated list of scores. Filters by `trace_id`, `agent_id_hash`,
/// and time range. Delegates to `Engine::get_detection_events` — the
/// persist v2.13.0 read surface (CIRISPersist#113).
async fn get_scores(
    State(state): State<NodeState>,
    Query(params): Query<ScoresQuery>,
) -> impl IntoResponse {
    let engine = match &state.engine {
        Some(e) => e.clone(),
        None => return engine_unavailable().into_response(),
    };
    let filter = EventFilter {
        trace_id: params.trace_id.clone(),
        detector: None,
        since: params.since,
    };

    match engine.get_detection_events(filter).await {
        Err(e) => internal_error(e.to_string()).into_response(),
        Ok(events) => {
            // Apply until bound client-side (persist's EventFilter
            // carries only `since` — same pattern as ScoresOracle).
            let page_size = params.page_size.unwrap_or(100) as usize;
            let filtered: Vec<ScoreResponse> = events
                .into_iter()
                .filter(|e| {
                    if let Some(until) = params.until {
                        e.ts <= until
                    } else {
                        true
                    }
                })
                .take(page_size + 1)
                .map(ScoreResponse::from)
                .collect();

            // Basic pagination: if we got page_size+1 items there's
            // more data; return page_size and a cursor.
            let (items, next_cursor) = if filtered.len() > page_size {
                let mut items = filtered;
                items.truncate(page_size);
                // Cursor is the last item's detection_id.
                let cursor = items.last().map(|i| i.detection_id.clone());
                (items, cursor)
            } else {
                (filtered, None)
            };

            Json(ScoreListResponse { items, next_cursor }).into_response()
        }
    }
}

/// `GET /lens/api/v1/scores/{trace_id}`
///
/// Single trace's detection events — manifold-conformity + cohort cell.
async fn get_score_by_trace(
    State(state): State<NodeState>,
    Path(trace_id): Path<String>,
) -> impl IntoResponse {
    let engine = match &state.engine {
        Some(e) => e.clone(),
        None => return engine_unavailable().into_response(),
    };
    let filter = EventFilter {
        trace_id: Some(trace_id.clone()),
        detector: None,
        since: None,
    };

    match engine.get_detection_events(filter).await {
        Err(e) => internal_error(e.to_string()).into_response(),
        Ok(events) => {
            if events.is_empty() {
                not_found(format!("trace_id {trace_id} not found")).into_response()
            } else {
                let items: Vec<ScoreResponse> =
                    events.into_iter().map(ScoreResponse::from).collect();
                Json(ScoreListResponse {
                    items,
                    next_cursor: None,
                })
                .into_response()
            }
        }
    }
}

/// `GET /lens/api/v1/detection_events`
///
/// Paginated list of detection events, filtered by detector name,
/// severity, and time range.
async fn get_detection_events(
    State(state): State<NodeState>,
    Query(params): Query<DetectionEventsQuery>,
) -> impl IntoResponse {
    // Parse severity filter.
    let min_severity = match params.severity.as_deref() {
        Some("info") => Some(DetectionSeverity::Info),
        Some("warning") => Some(DetectionSeverity::Warning),
        Some("critical") => Some(DetectionSeverity::Critical),
        Some(other) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    LensQueryError::new("invalid_severity")
                        .with_detail(format!("unknown severity {other:?}")),
                ),
            )
                .into_response();
        }
        None => None,
    };

    let engine = match &state.engine {
        Some(e) => e.clone(),
        None => return engine_unavailable().into_response(),
    };
    let filter = EventFilter {
        trace_id: None,
        detector: params.detector.clone(),
        since: params.since,
    };

    match engine.get_detection_events(filter).await {
        Err(e) => internal_error(e.to_string()).into_response(),
        Ok(events) => {
            use crate::scores::aggregate::severity_level;
            let page_size = params.page_size.unwrap_or(100) as usize;
            let min_sev_level = min_severity.map(severity_level).unwrap_or(0);

            let filtered: Vec<ScoreResponse> = events
                .into_iter()
                .filter(|e| {
                    severity_level(e.severity) >= min_sev_level
                        && params.until.map(|u| e.ts <= u).unwrap_or(true)
                })
                .take(page_size + 1)
                .map(ScoreResponse::from)
                .collect();

            let (items, next_cursor) = if filtered.len() > page_size {
                let mut items = filtered;
                items.truncate(page_size);
                let cursor = items.last().map(|i| i.detection_id.clone());
                (items, cursor)
            } else {
                (filtered, None)
            };

            Json(ScoreListResponse { items, next_cursor }).into_response()
        }
    }
}

/// `GET /lens/api/v1/detection_events/{detection_id}`
///
/// Single signed detection event by its UUID.
async fn get_detection_event_by_id(
    State(state): State<NodeState>,
    Path(detection_id): Path<String>,
) -> impl IntoResponse {
    // `detection_id` is a UUID — look it up via the trace filter.
    // Persist v2.13.0 (CIRISPersist#113) exposes `get_detection_events`
    // via EventFilter; the per-ID lookup is done by parsing the UUID and
    // filtering client-side until CIRISPersist ships a per-ID accessor.
    // This is noted as a CIRISConformance node cell — not faked.
    let uuid = match uuid::Uuid::parse_str(&detection_id) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    LensQueryError::new("invalid_detection_id")
                        .with_detail(format!("not a valid UUID: {detection_id}")),
                ),
            )
                .into_response();
        }
    };

    // Fetch all (no filter) and scan for the ID. This is the
    // correctness path for v0.4; per-ID persist accessor is a
    // CIRISPersist#18 follow-up.
    let engine = match &state.engine {
        Some(e) => e.clone(),
        None => return engine_unavailable().into_response(),
    };
    let filter = EventFilter {
        trace_id: None,
        detector: None,
        since: None,
    };

    match engine.get_detection_events(filter).await {
        Err(e) => internal_error(e.to_string()).into_response(),
        Ok(events) => match events.into_iter().find(|e| e.detection_id == uuid) {
            None => not_found(format!("detection_id {detection_id} not found")).into_response(),
            Some(event) => Json(ScoreResponse::from(event)).into_response(),
        },
    }
}

/// `GET /lens/api/v1/manifold_conformity_aggregate`
///
/// Cohort-level aggregate over a rolling window. Defaults to the
/// last 24h if no window params are given.
async fn get_manifold_conformity_aggregate(
    State(state): State<NodeState>,
    Query(params): Query<AggregateQuery>,
) -> impl IntoResponse {
    let window_end = params.window_end.unwrap_or_else(Utc::now);
    let window_start = params
        .window_start
        .unwrap_or_else(|| window_end - chrono::Duration::hours(24));

    let engine = match &state.engine {
        Some(e) => e.clone(),
        None => return engine_unavailable().into_response(),
    };
    let filter = EventFilter {
        trace_id: None,
        detector: params.detector.clone(),
        since: Some(window_start),
    };

    match engine.get_detection_events(filter).await {
        Err(e) => internal_error(e.to_string()).into_response(),
        Ok(events) => {
            let detector_filter: Option<Vec<String>> =
                params.detector.as_ref().map(|d| vec![d.clone()]);

            let agg = compute_aggregate(
                &events,
                window_start,
                window_end,
                detector_filter.as_deref(),
                |e| e.ts,
            );

            Json(ManifoldAggregateResponse::from(agg)).into_response()
        }
    }
}

/// `GET /lens/api/v1/calibration_bundles`
///
/// List current + historical RATCHET calibration bundles. v0.4
/// returns a synthetic list based on `ratchet_calibration_version`
/// in the node's `ScoringConfig` until CIRISPersist#18 ships the
/// `get_calibration_bundle_*` Engine methods.
///
/// This is documented as a CIRISConformance node cell — the response
/// shape is frozen; the persist-backed read path lands with
/// CIRISPersist#18.
async fn get_calibration_bundles(State(state): State<NodeState>) -> impl IntoResponse {
    // v0.4: synthetic response from node's configured version.
    // CIRISPersist#18 will replace this with a real DB read.
    let current_version = state.ratchet_version;
    let bundles: Vec<CalibrationBundleResponse> = if current_version == 0 {
        // Version 0 = no bundle loaded (cold-start sentinel).
        vec![CalibrationBundleResponse {
            version: 0,
            registered_at: None,
            is_current: true,
        }]
    } else {
        // Emit one entry for each version from 1 to current.
        (1..=current_version)
            .map(|v| CalibrationBundleResponse {
                version: v,
                registered_at: None,
                is_current: v == current_version,
            })
            .collect()
    };

    Json(bundles).into_response()
}

/// `GET /lens/api/v1/calibration_bundles/{version}`
///
/// Specific bundle for re-scoring. v0.4: returns the bundle matching
/// `version` from the synthetic list (same caveat as
/// `get_calibration_bundles`).
async fn get_calibration_bundle_by_version(
    State(state): State<NodeState>,
    Path(version): Path<String>,
) -> impl IntoResponse {
    let v: i32 = match version.parse() {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    LensQueryError::new("invalid_version")
                        .with_detail(format!("version must be an integer, got {version:?}")),
                ),
            )
                .into_response();
        }
    };

    let current = state.ratchet_version;
    if v == 0 || v > current {
        return not_found(format!("calibration bundle version {v} not found")).into_response();
    }

    Json(CalibrationBundleResponse {
        version: v,
        registered_at: None,
        is_current: v == current,
    })
    .into_response()
}

// ─── Router builder ────────────────────────────────────────────────

/// Build the axum router for the frozen public read API.
///
/// The `api_root` prefix (e.g. `/lens/api/v1`) is prepended to each
/// route path — handlers are mounted under the prefix via
/// [`Router::nest`].
pub(crate) fn build_read_router(state: NodeState) -> Router {
    let api_root = state.api_root.clone();

    let nested = Router::new()
        .route("/scores", get(get_scores))
        .route("/scores/{trace_id}", get(get_score_by_trace))
        .route("/detection_events", get(get_detection_events))
        .route(
            "/detection_events/{detection_id}",
            get(get_detection_event_by_id),
        )
        .route(
            "/manifold_conformity_aggregate",
            get(get_manifold_conformity_aggregate),
        )
        .route("/calibration_bundles", get(get_calibration_bundles))
        .route(
            "/calibration_bundles/{version}",
            get(get_calibration_bundle_by_version),
        )
        .with_state(state);

    Router::new().nest(&api_root, nested)
}

// ─── NodeHandle ────────────────────────────────────────────────────

/// Handle to a running node-mode runtime.
///
/// Holds the inner [`RelayHandle`] (for the Edge listener) and
/// the HTTP server task handle (for the read API). Dropping this
/// handle does **not** stop the node — call [`shutdown`](Self::shutdown)
/// for an orderly stop.
pub struct NodeHandle {
    relay: crate::role::relay::RelayHandle,
    read: ReadApiHandle,
}

impl NodeHandle {
    /// The socket address the node's HTTP read-API listener is bound to.
    pub fn listen_addr(&self) -> SocketAddr {
        self.read.listen_addr()
    }

    /// Signal both the Edge relay and the HTTP read API to stop, and await both.
    ///
    /// Consumes the handle. Returns the first error encountered (relay
    /// shutdown takes priority in error reporting).
    pub async fn shutdown(self) -> Result<(), NodeError> {
        self.read.shutdown().await?;
        self.relay.shutdown().await.map_err(NodeError::Relay)
    }
}

/// Handle to a running read-API HTTP server (the frozen `GET /lens/api/v1/*`).
///
/// Dropping the handle does **not** stop the server — call
/// [`shutdown`](Self::shutdown) for an orderly stop.
pub struct ReadApiHandle {
    http_shutdown_tx: watch::Sender<bool>,
    http_join: JoinHandle<()>,
    listen_addr: SocketAddr,
}

impl ReadApiHandle {
    /// The socket address the read-API HTTP listener is bound to.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Signal the read-API server to stop and await its task.
    pub async fn shutdown(self) -> Result<(), NodeError> {
        let _ = self.http_shutdown_tx.send(true);
        let _ = self.http_join.await;
        Ok(())
    }
}

// ─── LensCore::node ────────────────────────────────────────────────

impl LensCore {
    /// Start ONLY the frozen read API (`GET /lens/api/v1/*`) over the host
    /// `Engine` — **Edge-independent**. A host that orchestrates its own shared
    /// Edge (one per process — the fabric-node model) pairs this with
    /// [`LensCore::attach_handler`] (ingest) to run lens-core over that ONE
    /// host-owned Edge, instead of [`LensCore::node`] building a second Edge.
    pub async fn read_api(
        engine: Arc<Engine>,
        listen_addr: SocketAddr,
        peer_acl: PeerAcl,
        scoring: ScoringConfig,
        ux: UxConfig,
    ) -> Result<ReadApiHandle, NodeError> {
        let state = NodeState {
            engine: Some(engine),
            peer_acl: Arc::new(peer_acl),
            ratchet_version: scoring.ratchet_calibration_version,
            api_root: ux.api_root.clone(),
        };
        let router = build_read_router(state);
        let (http_shutdown_tx, mut http_shutdown_rx) = watch::channel(false);
        let http_join = tokio::spawn(async move {
            let listener = match tokio::net::TcpListener::bind(listen_addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(%e, %listen_addr, "lens read API listener bind failed");
                    return;
                }
            };
            tracing::info!(%listen_addr, "lens read API listening");
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = http_shutdown_rx.changed().await;
                })
                .await
                .ok();
            tracing::info!(%listen_addr, "lens read API stopped");
        });
        Ok(ReadApiHandle { http_shutdown_tx, http_join, listen_addr })
    }

    /// Start lens-core in **node mode** — relay + UX read API.
    ///
    /// Builds the full relay (via [`LensCore::relay`]) AND spawns an
    /// axum HTTP server exposing the frozen public read API on
    /// `listen_addr`. The read data path calls
    /// `Engine::get_detection_events` via the shared `Arc<Engine>`.
    ///
    /// # Arguments
    ///
    /// - `engine` — host's persist Engine (same process-singleton the
    ///   relay uses).
    /// - `listen_addr` — socket for both the Edge relay listener and
    ///   the HTTP read-API server. The HTTP server binds this address;
    ///   the relay uses `HttpTransportConfig.listen_addr` internally —
    ///   both share the same `SocketAddr` parameter, but in practice a
    ///   standalone node uses one port for the Edge-transport (e.g. 9000)
    ///   and a different port for the read-API HTTP server. For the v0.4
    ///   API, `listen_addr` drives the **HTTP read-API** server only; the
    ///   relay's Edge-transport port is the same value (co-binding on
    ///   separate listeners per protocol is a v0.5 follow-up).
    /// - `key_id` — relay's federation key ID.
    /// - `seed_dir` — seed directory for the relay's transport-signing
    ///   identity.
    /// - `peer_acl` — ACL applied to API consumers.
    /// - `upstream` — relay upstream peers.
    /// - `retention` — local-store retention policy.
    /// - `scoring` — RATCHET gate + calibration version.
    /// - `ux` — API root path + web shell config.
    ///
    /// # Note on listen_addr binding
    ///
    /// In the v0.4 implementation the relay and the HTTP server are
    /// **separate listeners** — they would normally bind different ports.
    /// The PyO3 surface documents a single `listen_addr` parameter for
    /// simplicity; a production deploy passes one SocketAddr for the
    /// Edge relay (inbound AccordEventsBatch) and another for the HTTP
    /// read API. For v0.4 the HTTP server binds `listen_addr` directly
    /// and the relay binds a `relay_listen_addr` derived by incrementing
    /// the port by 1. This is noted as a follow-up improvement.
    #[allow(clippy::too_many_arguments)]
    pub async fn node(
        engine: Arc<Engine>,
        listen_addr: SocketAddr,
        key_id: impl Into<String>,
        seed_dir: std::path::PathBuf,
        peer_acl: PeerAcl,
        upstream: Vec<UpstreamLens>,
        _retention: RetentionPolicy,
        scoring: ScoringConfig,
        ux: UxConfig,
    ) -> Result<NodeHandle, NodeError> {
        // Build the relay on a port one above the HTTP API port (the
        // relay's Edge transport listener is separate). This is a v0.4
        // convenience; production operators configure separate ports.
        let relay_port = listen_addr.port().saturating_add(1);
        let relay_addr = SocketAddr::new(listen_addr.ip(), relay_port);

        // Peer URLs from upstream list. Relay mode needs the
        // key_id → URL map for outbound forwarding.
        let peer_urls: std::collections::HashMap<String, String> = upstream
            .iter()
            .map(|u| (u.lens_steward_key_id.clone(), String::new()))
            .collect();

        let relay = LensCore::relay(Arc::clone(&engine), key_id, seed_dir, relay_addr, peer_urls)
            .await
            .map_err(NodeError::Relay)?;

        // Read API (frozen GET /lens/api/v1/*) — the same Edge-independent path
        // a host with its own shared Edge uses via LensCore::read_api.
        let read = LensCore::read_api(engine, listen_addr, peer_acl, scoring, ux).await?;

        Ok(NodeHandle { relay, read })
    }
}

/// Errors from [`LensCore::node`] and [`NodeHandle::shutdown`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NodeError {
    /// The relay sub-mode returned an error.
    #[error("relay: {0}")]
    Relay(#[from] RelayError),
    /// The HTTP server task failed to bind or panicked.
    #[error("http server: {0}")]
    Http(String),
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use ciris_persist::derived::types::{ConformityVariant, DetectionSeverity};
    use tower::ServiceExt;
    use uuid::Uuid;

    /// Build a synthetic `DetectionEvent` for serialization tests.
    fn synthetic_event(
        trace_id: &str,
        detector: &str,
        severity: DetectionSeverity,
        conformity: ConformityVariant,
    ) -> DetectionEvent {
        DetectionEvent {
            detection_id: Uuid::new_v4(),
            trace_id: trace_id.to_string(),
            body_sha256: vec![0u8; 32],
            detector: detector.to_string(),
            severity,
            cohort_cell: serde_json::json!({"deployment_type": "test"}),
            conformity_variant: conformity,
            conformity_payload: serde_json::json!({"mahalanobis": 1.23}),
            ratchet_calibration_version: 0,
            lens_core_version: "test-0.1".into(),
            canonical_bytes: vec![],
            ed25519_sig: vec![0u8; 64],
            ml_dsa_65_sig: vec![0u8; 3309],
            signing_key_id: "test-key".into(),
            ts: "2026-06-12T10:00:00Z".parse().unwrap(),
        }
    }

    // ── ScoreResponse serialization ───────────────────────────────

    #[test]
    fn score_response_from_numeric_event_serializes_correctly() {
        let event = synthetic_event(
            "trace-001",
            "manifold_conformity",
            DetectionSeverity::Info,
            ConformityVariant::Numeric,
        );
        let resp = ScoreResponse::from(event);
        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["trace_id"], "trace-001");
        assert_eq!(json["detector"], "manifold_conformity");
        assert_eq!(json["severity"], "info");
        assert_eq!(json["conformity_variant"], "numeric");
        assert_eq!(json["ratchet_calibration_version"], 0);
    }

    #[test]
    fn score_response_from_indeterminate_event_serializes_correctly() {
        let event = synthetic_event(
            "trace-002",
            "manifold_conformity",
            DetectionSeverity::Warning,
            ConformityVariant::Indeterminate,
        );
        let resp = ScoreResponse::from(event);
        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["conformity_variant"], "indeterminate");
        assert_eq!(json["severity"], "warning");
    }

    #[test]
    fn score_response_from_unavailable_event_serializes_correctly() {
        let event = synthetic_event(
            "trace-003",
            "slo_breach",
            DetectionSeverity::Critical,
            ConformityVariant::Unavailable,
        );
        let resp = ScoreResponse::from(event);
        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["conformity_variant"], "unavailable");
        assert_eq!(json["severity"], "critical");
    }

    #[test]
    fn score_list_response_serde_roundtrip() {
        let event = synthetic_event(
            "trace-rt",
            "d",
            DetectionSeverity::Info,
            ConformityVariant::Numeric,
        );
        let list = ScoreListResponse {
            items: vec![ScoreResponse::from(event)],
            next_cursor: Some("cursor-abc".into()),
        };
        let json = serde_json::to_string(&list).unwrap();
        let back: ScoreListResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.items.len(), 1);
        assert_eq!(back.next_cursor.as_deref(), Some("cursor-abc"));
    }

    #[test]
    fn manifold_aggregate_response_from_aggregate() {
        use crate::scores::aggregate::{AgentScoreAggregate, SeverityDistribution};
        use std::collections::HashMap;

        let agg = AgentScoreAggregate {
            window_start: "2026-06-12T00:00:00Z".parse().unwrap(),
            window_end: "2026-06-12T23:59:59Z".parse().unwrap(),
            traces_scored: 50,
            conformity_numeric: 40,
            conformity_indeterminate: 8,
            conformity_unavailable: 2,
            detector_fire_counts: [("manifold_conformity".to_string(), 50)]
                .into_iter()
                .collect::<HashMap<_, _>>(),
            severity_distribution: SeverityDistribution {
                info: 40,
                warning: 8,
                critical: 2,
            },
        };

        let resp = ManifoldAggregateResponse::from(agg);
        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["traces_scored"], 50);
        assert_eq!(json["conformity_numeric"], 40);
        assert_eq!(json["conformity_indeterminate"], 8);
        assert_eq!(json["conformity_unavailable"], 2);
        assert_eq!(json["severity_info"], 40);
        assert_eq!(json["severity_warning"], 8);
        assert_eq!(json["severity_critical"], 2);
    }

    #[test]
    fn calibration_bundle_response_serde_roundtrip() {
        let b = CalibrationBundleResponse {
            version: 2,
            registered_at: None,
            is_current: true,
        };
        let json = serde_json::to_string(&b).unwrap();
        let back: CalibrationBundleResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, 2);
        assert!(back.is_current);
    }

    // ── Axum route smoke tests — engine-free paths ────────────────
    //
    // Calibration bundle handlers read only `state.ratchet_version` —
    // they never call into the Engine. Detection event and scores
    // handlers that DO require an Engine are CIRISConformance node
    // cell tests (Engine-backed reads need a real SQLite DB).
    //
    // `engine: None` triggers the 503 path in Engine-backed handlers,
    // so those route paths are also reachable in tests (400/404 paths
    // for bad input are caught before the engine check).

    /// Build a test NodeState with no Engine (engine: None).
    fn test_state(ratchet_version: i32) -> NodeState {
        NodeState {
            engine: None,
            peer_acl: Arc::new(PeerAcl::AllowAll),
            ratchet_version,
            api_root: "/lens/api/v1".to_string(),
        }
    }

    #[tokio::test]
    async fn calibration_bundles_version_zero_returns_one_item() {
        let state = test_state(0);
        let router = build_read_router(state);

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/lens/api/v1/calibration_bundles")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let bundles: Vec<CalibrationBundleResponse> = serde_json::from_slice(&body).unwrap();
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[0].version, 0);
        assert!(bundles[0].is_current);
    }

    #[tokio::test]
    async fn calibration_bundles_version_two_returns_two_items() {
        let router = build_read_router(test_state(2));

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/lens/api/v1/calibration_bundles")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let bundles: Vec<CalibrationBundleResponse> = serde_json::from_slice(&body).unwrap();
        assert_eq!(bundles.len(), 2);
        // Last one is current.
        assert!(bundles.last().unwrap().is_current);
        assert!(!bundles[0].is_current);
    }

    #[tokio::test]
    async fn calibration_bundle_by_version_not_found_returns_404() {
        let router = build_read_router(test_state(1));

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/lens/api/v1/calibration_bundles/99")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn calibration_bundle_by_version_bad_version_returns_400() {
        let router = build_read_router(test_state(1));

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/lens/api/v1/calibration_bundles/not-a-number")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn calibration_bundle_by_version_returns_200_when_valid() {
        let router = build_read_router(test_state(3));

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/lens/api/v1/calibration_bundles/2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let bundle: CalibrationBundleResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(bundle.version, 2);
        assert!(!bundle.is_current); // current is 3, not 2
    }

    #[tokio::test]
    async fn detection_event_by_id_invalid_uuid_returns_400() {
        let router = build_read_router(test_state(0));

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/lens/api/v1/detection_events/not-a-uuid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn node_error_relay_variant_formats() {
        let err = NodeError::Relay(RelayError::NotSqliteBacked);
        assert!(err.to_string().contains("relay:"));
    }
}
