//! **Memory READ surface** — agent-compat endpoints for the CIRIS desktop/mobile
//! Memory + GraphMemory cards (`GET /v1/memory/stats`, `GET /v1/memory/timeline`,
//! `POST /v1/memory/query`, `GET /v1/memory/{node_id}`,
//! `GET /v1/memory/{node_id}/edges`).
//!
//! ## Why these routes exist
//!
//! The desktop/mobile client's Memory card calls `getMemoryStats` and
//! `getMemoryTimeline`; its GraphMemory card calls `getGraphData` (which fetches
//! `/v1/memory/timeline?include_edges=true`). On the Python agent these are served
//! by `LocalGraphMemoryService`. In server mode the same data lives in persist's
//! `cirisgraph_nodes` / `cirisgraph_edges` tables (V013 migration). This module
//! exposes it on the SAME wire contract the client expects, so both cards work
//! unchanged.
//!
//! ## Wire contract (mirrors the agent's OpenAPI)
//!
//! - `GET /v1/memory/stats` → `{ "data": MemoryStats }` where `MemoryStats`:
//!   `{ total_nodes, nodes_by_type, nodes_by_scope, recent_nodes_24h,
//!      oldest_node_date?, newest_node_date? }`.
//!
//! - `GET /v1/memory/timeline?hours=<n>&scope=<s>&type=<t>&include_edges=<bool>
//!                            &include_metrics=<bool>` →
//!   `{ "data": TimelineResponse }` where `TimelineResponse`:
//!   `{ memories: [GraphNode…], edges: [GraphEdge…], start_time, end_time,
//!      total }`.
//!   When `include_metrics=false` (the client default), `tsdb_data` nodes are
//!   excluded. When `include_edges=true`, edges between the returned nodes are
//!   batch-fetched and included.
//!
//! - `POST /v1/memory/query` (JSON body: `QueryRequest`) →
//!   `{ "data": [GraphNode…] }`.  Supports `scope`, `type`, `query` (text
//!   search on `attributes->>'content'`), `since`, `until`, and `limit`.
//!
//! - `GET /v1/memory/{node_id}` → `{ "data": GraphNode }` (404 if not found;
//!   searches all four scopes until the first hit).
//!
//! - `GET /v1/memory/{node_id}/edges` → `{ "data": [GraphEdge…] }` (both
//!   incoming + outgoing, all four scopes unioned).
//!
//! ## Data source
//!
//! Reads directly from the SQLite backend's `cirisgraph_nodes` and
//! `cirisgraph_edges` tables via `ciris_persist::graph::sqlite::SqliteGraphBackend`
//! (the same backend the SQLite `Engine` owns). The `Engine::sqlite_backend()`
//! accessor returns `Option<&Arc<SqliteBackend>>`; `SqliteBackend::conn_handle()`
//! returns the `Arc<Mutex<Connection>>` that `SqliteGraphBackend::new` takes.
//! This avoids a second connection and re-uses the migrated DB.
//!
//! ## Scope fan-out
//!
//! The `GraphService` trait requires a specific scope on every read (AV-47 in
//! persist's threat model). For endpoints that do not specify a scope (node
//! look-up by ID, edge look-up, timeline without scope filter) this module fans
//! out across all four scopes (`Local`, `Identity`, `Environment`, `Community`)
//! and unions the results, deduplicated by `node_id`.
//!
//! ## Fields null/stubbed in server mode
//!
//! - `GraphNode.consent_stream` — always `null` (no consent object attached to
//!   raw graph rows; the CEG owns consent separately).
//! - `GraphNode.expires_at` — always `null` (retention enforced by the
//!   eviction sweeper, not a per-row TTL field in the graph schema).
//! - `GraphEdge.attributes.created_at` / `.context` — mapped from the raw row's
//!   `created_at` / empty respectively.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use ciris_persist::graph::sqlite::SqliteGraphBackend;
use ciris_persist::graph::types::{EdgeDirection, GraphScope, NodeFilter};
use ciris_persist::graph::GraphService;
use ciris_persist::prelude::Engine;

// ── State ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct MemState {
    graph: Arc<SqliteGraphBackend>,
}

fn err(code: StatusCode, error: &str) -> Response {
    (code, Json(serde_json::json!({ "error": error }))).into_response()
}

// ── Wire types (mirrors the OpenAPI generated client) ─────────────────────────

/// `GraphNode` in the agent wire format.
#[derive(Debug, Serialize)]
struct WireNode {
    id: String,
    #[serde(rename = "type")]
    node_type: String,
    scope: String,
    attributes: serde_json::Value,
    version: Option<i32>,
    updated_by: Option<String>,
    updated_at: Option<String>,
    consent_stream: Option<serde_json::Value>,
    expires_at: Option<serde_json::Value>,
}

/// `GraphEdge` in the agent wire format.
#[derive(Debug, Serialize)]
struct WireEdge {
    source: String,
    target: String,
    relationship: String,
    scope: String,
    weight: Option<f64>,
    attributes: WireEdgeAttributes,
}

#[derive(Debug, Serialize)]
struct WireEdgeAttributes {
    created_at: Option<String>,
    context: Option<String>,
}

/// `MemoryStats` in the agent wire format.
#[derive(Debug, Serialize)]
struct WireStats {
    total_nodes: u64,
    nodes_by_type: HashMap<String, u64>,
    nodes_by_scope: HashMap<String, u64>,
    recent_nodes_24h: u64,
    oldest_node_date: Option<String>,
    newest_node_date: Option<String>,
}

/// `TimelineResponse` in the agent wire format.
#[derive(Debug, Serialize)]
struct WireTimeline {
    memories: Vec<WireNode>,
    edges: Vec<WireEdge>,
    start_time: Option<String>,
    end_time: Option<String>,
    total: usize,
    buckets: Option<serde_json::Value>,
}

// ── Persist type projections ──────────────────────────────────────────────────

fn scope_to_str(s: &GraphScope) -> &'static str {
    match s {
        GraphScope::Local => "local",
        GraphScope::Identity => "identity",
        GraphScope::Environment => "environment",
        GraphScope::Community => "community",
    }
}

fn parse_scope(s: &str) -> Option<GraphScope> {
    match s.to_ascii_uppercase().as_str() {
        "LOCAL" => Some(GraphScope::Local),
        "IDENTITY" => Some(GraphScope::Identity),
        "ENVIRONMENT" => Some(GraphScope::Environment),
        "COMMUNITY" => Some(GraphScope::Community),
        _ => None,
    }
}

fn to_wire_node(n: ciris_persist::graph::types::GraphNode) -> WireNode {
    WireNode {
        id: n.node_id,
        node_type: n.node_type,
        scope: scope_to_str(&n.scope).to_owned(),
        attributes: n.attributes,
        version: Some(n.version),
        updated_by: Some(n.updated_by),
        updated_at: Some(n.updated_at.to_rfc3339()),
        consent_stream: None,
        expires_at: None,
    }
}

fn to_wire_edge(e: ciris_persist::graph::types::GraphEdge) -> WireEdge {
    WireEdge {
        source: e.source_node_id,
        target: e.target_node_id,
        relationship: e.relationship,
        scope: scope_to_str(&e.scope).to_owned(),
        weight: e.weight,
        attributes: WireEdgeAttributes {
            created_at: Some(e.created_at.to_rfc3339()),
            context: None,
        },
    }
}

const ALL_SCOPES: &[GraphScope] = &[
    GraphScope::Local,
    GraphScope::Identity,
    GraphScope::Environment,
    GraphScope::Community,
];

// ── Query-param shapes ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
struct TimelineParams {
    hours: Option<i64>,
    scope: Option<String>,
    #[serde(rename = "type")]
    node_type: Option<String>,
    include_edges: Option<bool>,
    include_metrics: Option<bool>,
}

/// JSON body for `POST /v1/memory/query`.
#[derive(Debug, Deserialize, Default)]
struct QueryBody {
    node_id: Option<String>,
    #[serde(rename = "type")]
    node_type: Option<String>,
    query: Option<String>,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    scope: Option<String>,
    limit: Option<i64>,
    /// Pagination offset — accepted in the body for wire-compat but not yet
    /// applied (cursor-based paging is the substrate's model; offset paging
    /// over the full timeline is prohibitively expensive server-side).
    #[serde(default)]
    #[allow(dead_code)]
    offset: Option<i64>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// `GET /v1/memory/stats` — node counts, type histogram, scope histogram,
/// 24h recency count, oldest/newest date.
async fn get_stats(State(st): State<MemState>) -> Response {
    let now = Utc::now();
    let cutoff_24h = now - chrono::Duration::hours(24);

    let mut total_nodes: u64 = 0;
    let mut nodes_by_type: HashMap<String, u64> = HashMap::new();
    let mut nodes_by_scope: HashMap<String, u64> = HashMap::new();
    let mut recent_24h: u64 = 0;
    let mut oldest: Option<DateTime<Utc>> = None;
    let mut newest: Option<DateTime<Utc>> = None;

    for &scope in ALL_SCOPES {
        // Total count per scope.
        let filter = NodeFilter {
            scope: Some(scope),
            ..Default::default()
        };
        let count = match st.graph.count_nodes(filter).await {
            Ok(c) => c,
            Err(_) => continue,
        };
        if count == 0 {
            continue;
        }
        let scope_str = scope_to_str(&scope).to_owned();
        *nodes_by_scope.entry(scope_str).or_insert(0) += count;
        total_nodes += count;

        // Type histogram.
        if let Ok(by_type) = st.graph.count_nodes_by_type(scope).await {
            for (t, c) in by_type {
                *nodes_by_type.entry(t).or_insert(0) += c;
            }
        }

        // Recent 24h count (page the first large batch and count updated_at > cutoff).
        let filter_recent = NodeFilter {
            scope: Some(scope),
            updated_after: Some(cutoff_24h),
            ..Default::default()
        };
        if let Ok(c) = st.graph.count_nodes(filter_recent).await {
            recent_24h += c;
        }

        // Oldest / newest: fetch the first page (up to 1000) sorted newest-first,
        // then track the trailing (oldest) updated_at from the last fetched row.
        // This is a heuristic — a full scan would be expensive and the counts are
        // already correct; the dates are informational dashboard metadata.
        let filter_page = NodeFilter {
            scope: Some(scope),
            ..Default::default()
        };
        if let Ok(page) = st.graph.query_nodes(filter_page, None, 1000).await {
            for node in &page.items {
                let ts = node.updated_at;
                newest = Some(newest.map_or(ts, |n: DateTime<Utc>| n.max(ts)));
                oldest = Some(oldest.map_or(ts, |o: DateTime<Utc>| o.min(ts)));
            }
        }
    }

    let stats = WireStats {
        total_nodes,
        nodes_by_type,
        nodes_by_scope,
        recent_nodes_24h: recent_24h,
        oldest_node_date: oldest.map(|t| t.to_rfc3339()),
        newest_node_date: newest.map(|t| t.to_rfc3339()),
    };
    (StatusCode::OK, Json(serde_json::json!({ "data": stats }))).into_response()
}

/// `GET /v1/memory/timeline` — newest-first, time-windowed, optionally scoped
/// and type-filtered. `include_edges=true` batch-fetches edges between returned
/// nodes; `include_metrics=false` (the client default) suppresses `tsdb_data`.
async fn get_timeline(
    State(st): State<MemState>,
    Query(params): Query<TimelineParams>,
) -> Response {
    let hours = params.hours.unwrap_or(24).max(1);
    let include_edges = params.include_edges.unwrap_or(false);
    let include_metrics = params.include_metrics.unwrap_or(true);

    let now = Utc::now();
    let start = now - chrono::Duration::hours(hours);

    let scopes: Vec<GraphScope> = if let Some(ref s) = params.scope {
        match parse_scope(s) {
            Some(sc) => vec![sc],
            None => return err(StatusCode::BAD_REQUEST, "unknown scope"),
        }
    } else {
        ALL_SCOPES.to_vec()
    };

    let type_filter = params.node_type.clone();
    let mut all_nodes: Vec<WireNode> = Vec::new();
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    for scope in scopes {
        let filter = NodeFilter {
            scope: Some(scope),
            node_type: type_filter.clone(),
            updated_after: Some(start),
            ..Default::default()
        };
        match st.graph.query_nodes(filter, None, 500).await {
            Ok(page) => {
                for node in page.items {
                    // `include_metrics=false` suppresses tsdb_data nodes.
                    if !include_metrics && node.node_type == "tsdb_data" {
                        continue;
                    }
                    if seen_ids.insert(node.node_id.clone()) {
                        all_nodes.push(to_wire_node(node));
                    }
                }
            }
            Err(_) => continue,
        }
    }

    // Newest-first (already newest-first per scope from query_nodes; re-sort union).
    all_nodes.sort_by(|a, b| {
        b.updated_at
            .as_deref()
            .unwrap_or("")
            .cmp(a.updated_at.as_deref().unwrap_or(""))
    });

    let total = all_nodes.len();

    // Batch-fetch edges if requested.
    let edges: Vec<WireEdge> = if include_edges {
        let mut edge_vec: Vec<WireEdge> = Vec::new();
        let mut seen_edge_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        for node in &all_nodes {
            let node_scope = parse_scope(&node.scope).unwrap_or(GraphScope::Local);
            if let Ok(raw_edges) = st
                .graph
                .get_edges_for_node(&node.id, node_scope, EdgeDirection::Both, None)
                .await
            {
                for e in raw_edges {
                    // Only include edges whose source AND target are in our result set.
                    if seen_ids.contains(&e.source_node_id)
                        && seen_ids.contains(&e.target_node_id)
                        && seen_edge_ids.insert(e.edge_id.clone())
                    {
                        edge_vec.push(to_wire_edge(e));
                    }
                }
            }
        }
        edge_vec
    } else {
        vec![]
    };

    let timeline = WireTimeline {
        memories: all_nodes,
        edges,
        start_time: Some(start.to_rfc3339()),
        end_time: Some(now.to_rfc3339()),
        total,
        buckets: None,
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({ "data": timeline })),
    )
        .into_response()
}

/// `POST /v1/memory/query` — flexible recall (by type, scope, text, time window).
async fn query_memory(State(st): State<MemState>, Json(body): Json<QueryBody>) -> Response {
    // If node_id is provided, do a direct point-lookup across all scopes.
    if let Some(ref node_id) = body.node_id {
        let mut found: Option<WireNode> = None;
        for &scope in ALL_SCOPES {
            match st.graph.get_node(node_id, scope).await {
                Ok(Some(n)) => {
                    found = Some(to_wire_node(n));
                    break;
                }
                Ok(None) => continue,
                Err(_) => continue,
            }
        }
        let results: Vec<WireNode> = found.into_iter().collect();
        return (StatusCode::OK, Json(serde_json::json!({ "data": results }))).into_response();
    }

    let limit = body.limit.unwrap_or(20).clamp(1, 500);

    let scopes: Vec<GraphScope> = if let Some(ref s) = body.scope {
        match parse_scope(s) {
            Some(sc) => vec![sc],
            None => return err(StatusCode::BAD_REQUEST, "unknown scope"),
        }
    } else {
        ALL_SCOPES.to_vec()
    };

    let mut all_nodes: Vec<WireNode> = Vec::new();
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    for scope in scopes {
        // Build attribute-containment filter for text search if provided.
        // The agent stores content under `attributes->>'content'`; we use
        // the JSONB-containment index for a prefix match by injecting the
        // text as the `content` value. This is approximate (exact-string
        // containment, not full-text), matching the agent's simple LIKE
        // fallback for server mode.
        let attrs_contains: Option<serde_json::Value> = body
            .query
            .as_ref()
            .map(|q| serde_json::json!({ "content": q }));

        let filter = NodeFilter {
            scope: Some(scope),
            node_type: body.node_type.clone(),
            attributes_contains: attrs_contains,
            updated_after: body.since,
            updated_before: body.until,
            ..Default::default()
        };
        match st.graph.query_nodes(filter, None, limit).await {
            Ok(page) => {
                for node in page.items {
                    if seen_ids.insert(node.node_id.clone()) {
                        all_nodes.push(to_wire_node(node));
                        if all_nodes.len() >= limit as usize {
                            break;
                        }
                    }
                }
            }
            Err(_) => continue,
        }
        if all_nodes.len() >= limit as usize {
            break;
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "data": all_nodes })),
    )
        .into_response()
}

/// `GET /v1/memory/{node_id}` — point-lookup across all scopes (first hit wins).
async fn get_node(State(st): State<MemState>, Path(node_id): Path<String>) -> Response {
    for &scope in ALL_SCOPES {
        match st.graph.get_node(&node_id, scope).await {
            Ok(Some(n)) => {
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({ "data": to_wire_node(n) })),
                )
                    .into_response();
            }
            Ok(None) => continue,
            Err(e) => {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &format!("graph store: {e}"),
                );
            }
        }
    }
    err(StatusCode::NOT_FOUND, "node not found")
}

/// `GET /v1/memory/{node_id}/edges` — both directions, all scopes, union'd.
async fn get_node_edges(State(st): State<MemState>, Path(node_id): Path<String>) -> Response {
    let mut edges: Vec<WireEdge> = Vec::new();
    let mut seen_edge_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    for &scope in ALL_SCOPES {
        match st
            .graph
            .get_edges_for_node(&node_id, scope, EdgeDirection::Both, None)
            .await
        {
            Ok(raw) => {
                for e in raw {
                    if seen_edge_ids.insert(e.edge_id.clone()) {
                        edges.push(to_wire_edge(e));
                    }
                }
            }
            Err(_) => continue,
        }
    }

    (StatusCode::OK, Json(serde_json::json!({ "data": edges }))).into_response()
}

// ── Router ────────────────────────────────────────────────────────────────────

/// The memory READ router. Requires a SQLite-backed Engine (no-op graceful
/// degradation if the engine is Postgres-only or has no SQLite backend — the
/// routes return 503 rather than panic).
pub fn router(engine: Arc<Engine>) -> Router {
    // Build the graph backend from the Engine's SQLite connection handle.
    // Engine::sqlite_backend() returns None on a Postgres-only node; in
    // that case we still mount the routes but they 503 on every call.
    let maybe_graph: Option<Arc<SqliteGraphBackend>> = engine
        .sqlite_backend()
        .map(|sq| Arc::new(SqliteGraphBackend::new(sq.conn_handle())));

    if let Some(graph) = maybe_graph {
        let state = MemState { graph };
        Router::new()
            .route("/v1/memory/stats", axum::routing::get(get_stats))
            .route("/v1/memory/timeline", axum::routing::get(get_timeline))
            .route("/v1/memory/query", axum::routing::post(query_memory))
            .route("/v1/memory/{node_id}", axum::routing::get(get_node))
            .route(
                "/v1/memory/{node_id}/edges",
                axum::routing::get(get_node_edges),
            )
            .with_state(state)
    } else {
        // Postgres-only node — mount stub routes that return 503.
        Router::new()
            .route(
                "/v1/memory/stats",
                axum::routing::get(|| async {
                    err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "memory API requires SQLite backend",
                    )
                }),
            )
            .route(
                "/v1/memory/timeline",
                axum::routing::get(|| async {
                    err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "memory API requires SQLite backend",
                    )
                }),
            )
            .route(
                "/v1/memory/query",
                axum::routing::post(|| async {
                    err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "memory API requires SQLite backend",
                    )
                }),
            )
            .route(
                "/v1/memory/{node_id}",
                axum::routing::get(|| async {
                    err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "memory API requires SQLite backend",
                    )
                }),
            )
            .route(
                "/v1/memory/{node_id}/edges",
                axum::routing::get(|| async {
                    err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "memory API requires SQLite backend",
                    )
                }),
            )
    }
}
