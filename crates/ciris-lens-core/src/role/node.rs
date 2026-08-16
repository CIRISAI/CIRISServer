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
//! The read API reuses the substrate's existing federation
//! request-auth contract — the SAME hybrid Ed25519 + ML-DSA-65
//! scheme `ciris-persist`'s secrets server uses (no new crypto
//! primitive is invented here). Requests carry these headers:
//! - `x-ciris-signing-key-id: <federation_keys.key_id>`
//! - `x-ciris-signature-ed25519: <base64-ed25519-sig>`
//! - `x-ciris-signature-ml-dsa-65: <base64-ml-dsa-65-sig>` (optional;
//!   required under `HybridPolicy::Strict`)
//!
//! The **canonical bytes are the request BODY**. These are GET
//! requests, so the body is empty and canonicalizes as `b""` — this
//! matches persist's contract, which signs the body and explicitly
//! handles the empty-body case. Read clients (KMP / portal) MUST
//! therefore sign the empty-body request with these `x-ciris-*`
//! headers for the authenticated path to succeed.
//!
//! The [`require_federation_signature`] middleware enforces this:
//!
//! - `PeerAcl::AllowAll` → **open passthrough** (the documented
//!   local-dev / open posture). No signature is required.
//! - any other `PeerAcl` (a real ACL = production posture) →
//!   1. missing `x-ciris-signing-key-id` / `x-ciris-signature-ed25519`
//!      → `401 LensQueryError::UnauthorizedSignature`;
//!   2. no `engine` to source the federation directory → `503`;
//!   3. hybrid verify (`verify_hybrid_via_directory` over the empty
//!      body, with the configured [`HybridPolicy`], default
//!      [`HybridPolicy::Strict`]) fails → `401`;
//!   4. `key_id` not permitted by the `PeerAcl` → `403`;
//!   5. otherwise the request passes through to the handler.
//!
//! `HybridPolicy::Strict` is the project's hard-cut, and as of 0.5.175 it
//! is the ONLY posture: both Ed25519 and ML-DSA-65 are required, and the
//! policy is passed as a literal at the verify call rather than carried in
//! a field, so there is no knob an operator or a future caller could turn.
//!
//! It was previously a `NodeState` field with a `with_hybrid_policy`
//! setter for "operators mid-PQC-rollout". That setter had ZERO callers,
//! no config path, and an `#[allow(dead_code)]` keeping it quiet — a
//! downgrade affordance surviving on an allow. CIRISEdge#481 retired the
//! same shape on the KEX side after finding a responder that accepted
//! spoofed classical handshakes; the mesh is pre-release and fully
//! PQC-provisioned, so the rollout posture it existed for has no user.
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
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use ciris_persist::derived::types::{DetectionEvent, DetectionSeverity, EventFilter};
use ciris_persist::prelude::{verify_hybrid_via_directory, Engine, HybridPolicy};
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
    /// ACL applied after signature verify. The
    /// [`require_federation_signature`] middleware checks `permits`
    /// (step 4) once the hybrid signature verifies. `AllowAll` is the
    /// open / local-dev passthrough: the middleware skips verification
    /// entirely. Any other variant is the production posture and gates
    /// every read on a valid federation-signed request.
    pub(crate) peer_acl: Arc<PeerAcl>,
    /// RATCHET version stamped onto responses.
    pub(crate) ratchet_version: i32,
    /// Frozen API root path prefix (e.g. `/lens/api/v1`).
    pub(crate) api_root: String,
    /// **How much of a row this node is willing to serve right now**
    /// (CIRISServer#365). Supplied by the composing host and re-invoked
    /// PER REQUEST, so a backpressure relief that arrives — or whose
    /// TTL closes — is observed with no restart. `None` = the host
    /// wires no such policy and every row is served whole, which is
    /// what this API did before the knob existed.
    pub(crate) fidelity: Option<ServeFidelityProvider>,
}

impl NodeState {
    /// What fidelity to serve this request at. `None` provider ⇒
    /// [`RowFidelity::Full`] — the pre-knob behaviour, and the one an
    /// unreadable policy must also produce (the host decides that; this
    /// crate never guesses at a plane it does not read).
    fn row_fidelity(&self) -> RowFidelity {
        self.fidelity.as_ref().map_or(RowFidelity::Full, |f| f())
    }
}

/// **How much of a row the read API serves.**
///
/// The consumer half of `mesh_config`'s `backpressure.summary_only`
/// (CIRISServer#365 / `FSD/MESH_CONFIG_AND_ADMIN_OPS.md`: *"trace
/// serving — serve summaries, not raw traces"*). A congested node
/// under a trust root's relief keeps answering — the row's identity,
/// detector, severity, calibration version and timestamp still cross —
/// and stops shipping the opaque per-score payload, which is the bulk.
///
/// Two states named rather than a bare `bool`, because a `bool` three
/// modules from its definition says nothing about which way `true`
/// points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowFidelity {
    /// Whole rows, opaque payload included. The default, and what every
    /// pre-0.5.156 node serves.
    #[default]
    Full,
    /// Summary fields only; `conformity_payload` is withheld and the
    /// response says so.
    SummaryOnly,
}

impl RowFidelity {
    /// Serde skip predicate: the marker is ABSENT on a full response, so
    /// the frozen v0.5.0 wire shape is byte-identical in the normal case
    /// and the marker's presence always means something.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        matches!(self, Self::Full)
    }
}

/// A live read of [`RowFidelity`], supplied by the composing host and
/// invoked once per request.
///
/// Lens-core deliberately owns no mesh-config plane: it is handed a
/// verdict, not a corpus. The host that DOES own the plane
/// (`ciris_server::mesh_config_effect`) folds it, decides what an
/// unreadable plane means, and hands the answer down.
pub type ServeFidelityProvider = Arc<dyn Fn() -> RowFidelity + Send + Sync>;

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
    ///
    /// **`null` is two different facts**, which is why
    /// [`Self::row_fidelity`] rides beside it: a detector that emitted
    /// nothing, and a node under backpressure that DECLINED to ship what
    /// it has. Read the fidelity marker before concluding the former.
    pub conformity_payload: serde_json::Value,
    /// RATCHET calibration bundle version applied to this score.
    pub ratchet_calibration_version: i32,
    pub lens_core_version: String,
    pub ts: DateTime<Utc>,
    /// `summary_only` when this row was thinned by a backpressure
    /// relief (CIRISServer#365); **absent** otherwise, so the frozen
    /// v0.5.0 shape is byte-identical on the normal path and the
    /// marker's presence always carries information.
    #[serde(default, skip_serializing_if = "RowFidelity::is_full")]
    pub row_fidelity: RowFidelity,
}

impl ScoreResponse {
    /// Thin this row to its summary: drop the opaque per-score payload —
    /// the bulk of the row — and MARK that it was dropped.
    ///
    /// Everything that identifies the finding survives (`detection_id`,
    /// `trace_id`, `detector`, `severity`, `conformity_variant`,
    /// `ratchet_calibration_version`, `ts`), so a viewer under relief
    /// still learns THAT something fired and can come back for the
    /// payload when the relief lifts.
    #[must_use]
    fn into_summary(mut self) -> Self {
        self.conformity_payload = serde_json::Value::Null;
        self.row_fidelity = RowFidelity::SummaryOnly;
        self
    }

    /// Project at the requested fidelity. One function so the four
    /// row-serving handlers cannot disagree about what a summary is.
    #[must_use]
    fn at(self, fidelity: RowFidelity) -> Self {
        match fidelity {
            RowFidelity::Full => self,
            RowFidelity::SummaryOnly => self.into_summary(),
        }
    }
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
            row_fidelity: RowFidelity::Full,
        }
    }
}

/// Paginated list of scores returned by `GET /scores`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScoreListResponse {
    pub items: Vec<ScoreResponse>,
    /// Opaque cursor for the next page. `None` = last page.
    pub next_cursor: Option<String>,
    /// `summary_only` when this page was served under a backpressure
    /// relief; absent otherwise. Carried on the ENVELOPE as well as on
    /// each item so an **empty** page under relief is still
    /// distinguishable from an empty page on a healthy node — the same
    /// zero, two causes.
    #[serde(default, skip_serializing_if = "RowFidelity::is_full")]
    pub row_fidelity: RowFidelity,
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

fn unauthorized_signature(detail: impl Into<String>) -> (StatusCode, Json<LensQueryError>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(LensQueryError::new("unauthorized_signature").with_detail(detail)),
    )
}

fn forbidden_key(detail: impl Into<String>) -> (StatusCode, Json<LensQueryError>) {
    (
        StatusCode::FORBIDDEN,
        Json(LensQueryError::new("forbidden").with_detail(detail)),
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

    let fidelity = state.row_fidelity();
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
                .map(|r| r.at(fidelity))
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

            Json(ScoreListResponse {
                items,
                next_cursor,
                row_fidelity: fidelity,
            })
            .into_response()
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

    let fidelity = state.row_fidelity();
    match engine.get_detection_events(filter).await {
        Err(e) => internal_error(e.to_string()).into_response(),
        Ok(events) => {
            if events.is_empty() {
                not_found(format!("trace_id {trace_id} not found")).into_response()
            } else {
                let items: Vec<ScoreResponse> = events
                    .into_iter()
                    .map(ScoreResponse::from)
                    .map(|r| r.at(fidelity))
                    .collect();
                Json(ScoreListResponse {
                    items,
                    next_cursor: None,
                    row_fidelity: fidelity,
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

    let fidelity = state.row_fidelity();
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
                .map(|r| r.at(fidelity))
                .collect();

            let (items, next_cursor) = if filtered.len() > page_size {
                let mut items = filtered;
                items.truncate(page_size);
                let cursor = items.last().map(|i| i.detection_id.clone());
                (items, cursor)
            } else {
                (filtered, None)
            };

            Json(ScoreListResponse {
                items,
                next_cursor,
                row_fidelity: fidelity,
            })
            .into_response()
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

    let fidelity = state.row_fidelity();
    match engine.get_detection_events(filter).await {
        Err(e) => internal_error(e.to_string()).into_response(),
        Ok(events) => match events.into_iter().find(|e| e.detection_id == uuid) {
            None => not_found(format!("detection_id {detection_id} not found")).into_response(),
            Some(event) => Json(ScoreResponse::from(event).at(fidelity)).into_response(),
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

// ─── Auth middleware ───────────────────────────────────────────────

/// Header carrying the caller's `federation_keys.key_id`.
/// Mirrors `ciris_persist::server::secrets::HEADER_KEY_ID`.
const HEADER_KEY_ID: &str = "x-ciris-signing-key-id";
/// Header carrying the base64 Ed25519 signature over the request body.
const HEADER_ED25519: &str = "x-ciris-signature-ed25519";
/// Header carrying the base64 ML-DSA-65 signature over the request
/// body. REQUIRED — verification is `HybridPolicy::Strict` with no
/// alternative, so a request without this header is refused.
const HEADER_ML_DSA_65: &str = "x-ciris-signature-ml-dsa-65";

/// Federation-signed-request auth gate for the frozen read API.
///
/// Reuses the substrate's hybrid request-auth contract verbatim (the
/// `x-ciris-*` headers + `verify_hybrid_via_directory`) — no new
/// crypto primitive. See the module-level "Auth model" section for the
/// full behavior. Middleware order + status codes:
///
/// 1. `PeerAcl::AllowAll` → passthrough (open / local-dev).
/// 2. missing `x-ciris-signing-key-id` / `x-ciris-signature-ed25519`
///    → `401`.
/// 3. `engine` is `None` (no federation directory source) → `503`.
/// 4. hybrid verify over the (empty) body fails → `401`.
/// 5. `key_id` not permitted by the ACL → `403`.
/// 6. otherwise → pass through to the handler.
async fn require_federation_signature(
    State(state): State<NodeState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // 1. AllowAll → open passthrough (documented local-dev posture).
    if matches!(state.peer_acl.as_ref(), PeerAcl::AllowAll) {
        return next.run(request).await;
    }

    // 2. Extract the mandatory signature headers.
    let key_id = match headers.get(HEADER_KEY_ID).and_then(|v| v.to_str().ok()) {
        Some(k) => k.to_owned(),
        None => {
            return unauthorized_signature(format!("missing {HEADER_KEY_ID} header"))
                .into_response()
        }
    };
    let ed25519 = match headers.get(HEADER_ED25519).and_then(|v| v.to_str().ok()) {
        Some(s) => s.to_owned(),
        None => {
            return unauthorized_signature(format!("missing {HEADER_ED25519} header"))
                .into_response()
        }
    };
    let ml_dsa_65 = headers
        .get(HEADER_ML_DSA_65)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());

    // 3. Require an Engine to source the federation directory.
    let engine = match &state.engine {
        Some(e) => e.clone(),
        None => return engine_unavailable().into_response(),
    };

    // 4. Hybrid-verify over the request BODY. These are GET requests,
    //    so the canonical bytes are empty (`b""`) — matches persist's
    //    contract, which signs the body and handles the empty case.
    //
    //    `verify_hybrid_via_directory` is generic over a *Sized*
    //    `F: FederationDirectory`, so we hand it the concrete
    //    SqliteBackend handle (`&SqliteBackend`) rather than the
    //    `Arc<dyn FederationDirectory>` `engine.federation_directory()`
    //    returns (a `dyn` value is unsized and won't satisfy the
    //    implicit `Sized` bound). lens-core is `sqlite`-featured and
    //    the relay already reads `engine.sqlite_backend()` for the
    //    shared directory — this is the same handle.
    let directory = match engine.sqlite_backend() {
        Some(b) => b.clone(),
        None => return engine_unavailable().into_response(),
    };
    let outcome = verify_hybrid_via_directory(
        &*directory,
        b"",
        &key_id,
        &ed25519,
        ml_dsa_65.as_deref(),
        // HARD-CODED, not a field: see the module doc. There is no
        // classical-only path and no knob that could create one.
        HybridPolicy::Strict,
        None,
    )
    .await;
    if let Err(e) = outcome {
        tracing::warn!(
            error = %e,
            key_id = %key_id,
            "lens read API rejected: signature verification failed"
        );
        return unauthorized_signature(format!("signature verification failed: {e}"))
            .into_response();
    }

    // 5. ACL check on the verified key_id.
    if !state.peer_acl.permits(&key_id) {
        tracing::warn!(key_id = %key_id, "lens read API rejected: key not permitted by ACL");
        return forbidden_key(format!("key {key_id} not permitted")).into_response();
    }

    // 6. Pass through.
    next.run(request).await
}

// ─── Router builder ────────────────────────────────────────────────

/// Build the axum router for the frozen public read API.
///
/// The `api_root` prefix (e.g. `/lens/api/v1`) is prepended to each
/// route path — handlers are mounted under the prefix via
/// [`Router::nest`]. The [`require_federation_signature`] auth gate is
/// layered onto the nested router (so every `GET /lens/api/v1/*` route
/// is gated before dispatch).
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
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_federation_signature,
        ))
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
        Self::read_api_with_extra(engine, listen_addr, peer_acl, scoring, ux, Router::new()).await
    }

    /// Like [`Self::read_api`], but merges `extra` routes onto the same HTTP
    /// listener — so the composing host (CIRISServer) can serve its own
    /// fabric-node surface (e.g. `GET /v1/identity`) on the same port as the
    /// frozen `GET /lens/api/v1/*` read API. The lens routes win on conflict
    /// (merge order); `extra` should use non-`/lens/api/v1` paths.
    ///
    /// Serves every row WHOLE. A host that wants the read API to thin its rows
    /// under backpressure passes a provider to
    /// [`Self::read_api_with_extra_at_fidelity`].
    pub async fn read_api_with_extra(
        engine: Arc<Engine>,
        listen_addr: SocketAddr,
        peer_acl: PeerAcl,
        scoring: ScoringConfig,
        ux: UxConfig,
        extra: Router,
    ) -> Result<ReadApiHandle, NodeError> {
        Self::read_api_with_extra_at_fidelity(
            engine,
            listen_addr,
            peer_acl,
            scoring,
            ux,
            extra,
            None,
        )
        .await
    }

    /// [`Self::read_api_with_extra`] plus the **serve-fidelity policy**
    /// (CIRISServer#365): a host-supplied provider, invoked once per request,
    /// that says whether this node is currently willing to ship whole rows or
    /// only their summaries.
    ///
    /// This is the consumer half of `mesh_config`'s
    /// `backpressure.summary_only`. Lens-core reads no mesh-config plane of its
    /// own — the host folds it (most-restrictive across trust roots, TTL
    /// applied), decides what an unreadable plane means, and hands down a
    /// verdict. `None` = no policy, every row whole, the pre-0.5.156 behaviour.
    #[allow(clippy::too_many_arguments)]
    pub async fn read_api_with_extra_at_fidelity(
        engine: Arc<Engine>,
        listen_addr: SocketAddr,
        peer_acl: PeerAcl,
        scoring: ScoringConfig,
        ux: UxConfig,
        extra: Router,
        fidelity: Option<ServeFidelityProvider>,
    ) -> Result<ReadApiHandle, NodeError> {
        let state = NodeState {
            engine: Some(engine),
            peer_acl: Arc::new(peer_acl),
            // Hard-cut PQC default. Operators mid-rollout can swap to
            ratchet_version: scoring.ratchet_calibration_version,
            api_root: ux.api_root.clone(),
            fidelity,
        };
        let router = extra.merge(build_read_router(state));
        let (http_shutdown_tx, mut http_shutdown_rx) = watch::channel(false);
        // Bind SYNCHRONOUSLY, before spawning the accept loop (CIRISServer#279).
        // The old shape bound inside the spawned task and swallowed the error
        // into a log line — the caller got a "successful" handle with NO
        // listener behind it, and on a platform where that log line never
        // became bytes the node ran forever with the read API silently absent.
        // Now a bind failure is the CALLER's error (compose fails loudly with
        // the real reason, e.g. AddrInUse), and a returned handle GUARANTEES
        // the port is bound — the kernel accepts connections from this line on
        // even before the accept loop polls.
        let listener = tokio::net::TcpListener::bind(listen_addr)
            .await
            .map_err(|e| NodeError::Http(format!("bind {listen_addr}: {e}")))?;
        let http_join = tokio::spawn(async move {
            tracing::info!(%listen_addr, "lens read API listening");
            // Attach per-connection peer info so downstream routers can extract
            // `ConnectInfo<SocketAddr>` (used by ciris-server's loopback guard to
            // restrict setup/apex routes to localhost). Harmless for routes that
            // don't read it.
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = http_shutdown_rx.changed().await;
            })
            .await
            .ok();
            tracing::info!(%listen_addr, "lens read API stopped");
        });
        Ok(ReadApiHandle {
            http_shutdown_tx,
            http_join,
            listen_addr,
        })
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
            row_fidelity: RowFidelity::Full,
        };
        let json = serde_json::to_string(&list).unwrap();
        // The frozen v0.5.0 shape is unchanged on the full path: the
        // fidelity marker is skipped, so a pre-0.5.156 reader sees the
        // same bytes it always did.
        assert!(!json.contains("row_fidelity"), "{json}");
        let back: ScoreListResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.items.len(), 1);
        assert_eq!(back.next_cursor.as_deref(), Some("cursor-abc"));
        assert_eq!(back.row_fidelity, RowFidelity::Full);
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

    /// Build a test NodeState with no Engine (engine: None) and the
    /// open `AllowAll` posture (auth passthrough).
    fn test_state(ratchet_version: i32) -> NodeState {
        NodeState {
            engine: None,
            peer_acl: Arc::new(PeerAcl::AllowAll),
            ratchet_version,
            api_root: "/lens/api/v1".to_string(),
            fidelity: None,
        }
    }

    /// Build a test NodeState with a non-empty `AllowList` ACL — the
    /// production posture that the auth gate enforces. `engine: None`
    /// here exercises the middleware order: missing-header rejection
    /// (401) happens BEFORE the engine check (503).
    fn test_state_acl(ratchet_version: i32) -> NodeState {
        NodeState {
            engine: None,
            peer_acl: Arc::new(PeerAcl::AllowList(vec!["allowed-key".to_string()])),
            ratchet_version,
            api_root: "/lens/api/v1".to_string(),
            fidelity: None,
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

    // ── Federation-signed-request auth gate ───────────────────────
    //
    // Prove the door is CLOSED. Middleware order (see
    // `require_federation_signature`):
    //   1. AllowAll                → passthrough (no signature needed)
    //   2. missing key-id/ed25519  → 401
    //   3. engine: None            → 503
    //   4. hybrid verify fails     → 401
    //   5. key_id not in ACL       → 403
    // The missing-header (401) check runs BEFORE the engine check, so
    // `engine: None` + AllowList still yields 401 for a header-less
    // request. The bad-signature (401) check runs AFTER the engine
    // check, so that test supplies a real in-memory Engine whose
    // directory has no matching key → `verify_unknown_key` → 401.

    /// AllowAll posture: a header-less GET passes the auth gate
    /// (returns NOT 401 — here a 503 from `engine: None`, never 401).
    #[tokio::test]
    async fn allow_all_passes_through_without_signature() {
        let router = build_read_router(test_state(0));
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/lens/api/v1/scores")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Passed the gate: engine: None → 503 (NOT 401). The point is
        // the auth middleware did not reject the unsigned request.
        assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Configured ACL posture: a request with NO auth headers is
    /// rejected with 401 before the engine is even consulted.
    #[tokio::test]
    async fn configured_acl_rejects_missing_signature() {
        let router = build_read_router(test_state_acl(0));
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/lens/api/v1/scores")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let err: LensQueryError = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.error, "unauthorized_signature");
    }

    /// Configured ACL posture: a request with a key-id + garbage
    /// Ed25519 signature is rejected with 401 (the directory has no
    /// such key → `verify_unknown_key`, so hybrid verify fails).
    #[tokio::test]
    async fn configured_acl_rejects_bad_signature() {
        use ciris_persist::prelude::{Engine, LocalSigner};
        use ed25519_dalek::SigningKey;

        // In-memory Engine with an EMPTY federation directory — no key
        // is registered, so verify_hybrid_via_directory returns
        // `verify_unknown_key`. Deterministic; no real crypto needed.
        let signing_key = SigningKey::from_bytes(&[0x11u8; 32]);
        let signer = Arc::new(LocalSigner::from_parts(
            signing_key,
            "unused-engine-signer".to_string(),
            None,
            None,
        ));
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory Engine");

        let state = NodeState {
            engine: Some(Arc::new(engine)),
            peer_acl: Arc::new(PeerAcl::AllowList(vec!["allowed-key".to_string()])),
            ratchet_version: 0,
            api_root: "/lens/api/v1".to_string(),
            fidelity: None,
        };
        let router = build_read_router(state);

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/lens/api/v1/scores")
                    .header(HEADER_KEY_ID, "allowed-key")
                    .header(HEADER_ED25519, "bm90LWEtcmVhbC1zaWduYXR1cmU=")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let err: LensQueryError = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.error, "unauthorized_signature");
    }

    // ═══════════════════════════════════════════════════════════════
    //  `backpressure.summary_only` — the serve path (CIRISServer#365)
    // ═══════════════════════════════════════════════════════════════
    //
    // The bug being fixed is a config that is READ and IGNORED, so a
    // test that asserts the provider was consulted proves nothing. What
    // these prove is that the SAME stored row comes back whole under
    // `Full` and thinned under `SummaryOnly`, over the real router.

    /// An in-memory Engine holding one detection event with a non-empty
    /// opaque `conformity_payload` — the part a summary withholds.
    async fn engine_with_one_score(trace_id: &str) -> Arc<ciris_persist::prelude::Engine> {
        use ciris_persist::derived::DerivedSchema;
        use ciris_persist::prelude::{Engine, LocalSigner};
        use ed25519_dalek::SigningKey;

        let signer = Arc::new(LocalSigner::from_parts(
            SigningKey::from_bytes(&[0x5Au8; 32]),
            "fidelity-engine-signer".to_string(),
            None,
            None,
        ));
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory Engine");
        let mut event = synthetic_event(
            trace_id,
            "manifold_conformity_outlier",
            DetectionSeverity::Warning,
            ConformityVariant::Numeric,
        );
        // The storage CHECKs want real-length signature bytes.
        event.canonical_bytes = b"canon".to_vec();
        engine
            .sqlite_backend()
            .expect("sqlite backend")
            .put_detection_event(event)
            .await
            .expect("seed one detection event");
        Arc::new(engine)
    }

    fn state_at(engine: Arc<ciris_persist::prelude::Engine>, fidelity: RowFidelity) -> NodeState {
        NodeState {
            engine: Some(engine),
            peer_acl: Arc::new(PeerAcl::AllowAll),
            ratchet_version: 0,
            api_root: "/lens/api/v1".to_string(),
            fidelity: Some(Arc::new(move || fidelity)),
        }
    }

    async fn get_json(state: NodeState, uri: &str) -> serde_json::Value {
        let resp = build_read_router(state)
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "GET {uri}");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).expect("json body")
    }

    #[tokio::test]
    async fn a_backpressure_relief_thins_the_rows_this_node_serves() {
        let engine = engine_with_one_score("tr-fidelity-1").await;

        // ── Full: the whole row, and NO marker (the frozen v0.5.0 shape
        //    is byte-identical on the normal path).
        let full = get_json(
            state_at(Arc::clone(&engine), RowFidelity::Full),
            "/lens/api/v1/scores",
        )
        .await;
        assert_eq!(full["items"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            full["items"][0]["conformity_payload"]["mahalanobis"],
            serde_json::json!(1.23),
            "a full response must carry the opaque per-score payload: {full}"
        );
        assert!(
            full.get("row_fidelity").is_none() && full["items"][0].get("row_fidelity").is_none(),
            "the fidelity marker must be ABSENT on a full response, so its presence always \
             means something: {full}"
        );

        // ── SummaryOnly: the SAME stored row, thinned — and marked.
        let summary = get_json(
            state_at(Arc::clone(&engine), RowFidelity::SummaryOnly),
            "/lens/api/v1/scores",
        )
        .await;
        assert_eq!(
            summary["items"].as_array().map(Vec::len),
            Some(1),
            "a relief thins rows; it does not stop answering: {summary}"
        );
        assert_eq!(
            summary["items"][0]["conformity_payload"],
            serde_json::Value::Null,
            "the opaque payload — the bulk of the row — must be withheld: {summary}"
        );
        // The finding still crosses: a viewer under relief learns THAT
        // something fired and can come back for the payload later.
        assert_eq!(
            summary["items"][0]["trace_id"],
            full["items"][0]["trace_id"]
        );
        assert_eq!(
            summary["items"][0]["detector"],
            full["items"][0]["detector"]
        );
        assert_eq!(
            summary["items"][0]["severity"],
            full["items"][0]["severity"]
        );
        assert_eq!(summary["items"][0]["ts"], full["items"][0]["ts"]);
        // `null` because a detector emitted nothing and `null` because
        // this node declined to ship it are DIFFERENT facts.
        assert_eq!(
            summary["items"][0]["row_fidelity"],
            serde_json::json!("summary_only"),
            "a withheld payload must say it was withheld: {summary}"
        );
        assert_eq!(
            summary["row_fidelity"],
            serde_json::json!("summary_only"),
            "the ENVELOPE carries the marker too, so an EMPTY page under relief is still \
             distinguishable from an empty page on a healthy node: {summary}"
        );
    }

    #[tokio::test]
    async fn every_row_serving_route_honours_the_relief() {
        // Four handlers project rows; all four must go through the one
        // projection, or the relief leaks out of whichever was missed.
        let engine = engine_with_one_score("tr-fidelity-2").await;
        let id = {
            let full = get_json(
                state_at(Arc::clone(&engine), RowFidelity::Full),
                "/lens/api/v1/scores",
            )
            .await;
            full["items"][0]["detection_id"]
                .as_str()
                .expect("detection_id")
                .to_string()
        };

        for uri in [
            "/lens/api/v1/scores".to_string(),
            "/lens/api/v1/scores/tr-fidelity-2".to_string(),
            "/lens/api/v1/detection_events".to_string(),
        ] {
            let v = get_json(
                state_at(Arc::clone(&engine), RowFidelity::SummaryOnly),
                &uri,
            )
            .await;
            assert_eq!(
                v["items"][0]["conformity_payload"],
                serde_json::Value::Null,
                "{uri} leaked the opaque payload under a backpressure relief: {v}"
            );
        }

        // The single-row route answers a BARE ScoreResponse, so its
        // marker rides on the item itself.
        let one = get_json(
            state_at(engine, RowFidelity::SummaryOnly),
            &format!("/lens/api/v1/detection_events/{id}"),
        )
        .await;
        assert_eq!(one["conformity_payload"], serde_json::Value::Null, "{one}");
        assert_eq!(
            one["row_fidelity"],
            serde_json::json!("summary_only"),
            "{one}"
        );
    }

    #[tokio::test]
    async fn no_policy_means_whole_rows() {
        // A host that wires no fidelity provider gets exactly what this
        // API served before the knob existed — including the absent
        // marker, so no consumer sees a shape change.
        let engine = engine_with_one_score("tr-fidelity-3").await;
        let state = NodeState {
            engine: Some(engine),
            peer_acl: Arc::new(PeerAcl::AllowAll),
            ratchet_version: 0,
            api_root: "/lens/api/v1".to_string(),
            fidelity: None,
        };
        let v = get_json(state, "/lens/api/v1/scores").await;
        assert_eq!(
            v["items"][0]["conformity_payload"]["mahalanobis"],
            serde_json::json!(1.23)
        );
        assert!(v.get("row_fidelity").is_none(), "{v}");
    }
}
