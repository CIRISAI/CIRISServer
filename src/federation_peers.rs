//! **`GET /v1/federation/peers`** + **`GET /v1/federation/peers/{key_id}`** —
//! the agent-compat federation-peers READ surface (CIRISServer Network card).
//!
//! The CIRIS desktop/mobile client's Network card lists the node's known
//! federation peers. On the Python agent this is served by
//! `FederationPeerListResponse` / `FederationPeerDetailResponse`; in server
//! mode the same data lives in persist's `federation_directory`
//! (`federation_keys` rows). This module exposes it on the SAME wire contract
//! the client expects (`LocalPeerState`), so the card works unchanged.
//!
//! ## Wire contract (mirrors the agent)
//!
//!   - `GET /v1/federation/peers` → `{ "peers": [LocalPeerState…], "total": N }`
//!     (bare object — the client's `decodeFederationEnvelope` tolerates either a
//!     `{data:…}` wrapper or the bare body; the bare body is simplest).
//!   - `GET /v1/federation/peers/{key_id}` →
//!     `{ "peer": LocalPeerState, "reachability": null }` (the client tolerates a
//!     null `reachability` — server mode holds no Edge transport stats).
//!
//! `LocalPeerState` JSON: `key_id`, `pubkey_ed25519_base64`, `canonical` (bool),
//! `trust` ("trusted"|…), `first_seen` (RFC3339), `appearance` / `alias_override`
//! / `notes` / `last_seen` (all null in server mode — no per-peer sideband state
//! is persisted here yet).
//!
//! ## Data source
//!
//! Modeled on [`crate::accord::list_holders`]: it reads
//! `engine.federation_directory().list_keys_by_identity_type(…)`. The
//! `FederationDirectory` trait has no "all keys" enumerator, so this UNIONs the
//! peer-relevant identity types (nodes, stewards, agents, accord holders, wise
//! authorities, partners, witnesses) and de-dups by `key_id`. Each
//! [`ciris_persist::federation::types::KeyRecord`] maps to a `LocalPeerState`:
//!
//!   - `key_id` / `pubkey_ed25519_base64`  ← record fields verbatim.
//!   - `canonical`  ← `identity_type == "node"` OR `key_id` begins
//!     `ciris-canonical` (a known canonical-mesh identity).
//!   - `trust`  ← `"trusted"` (a directory row is an admitted key).
//!   - `first_seen`  ← record `valid_from` (RFC3339).
//!   - `appearance`/`alias_override`/`notes`/`last_seen`  ← null.
//!
//! The node's OWN self key is excluded from the list.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::Serialize;

use ciris_persist::federation::types::{identity_type, KeyRecord};
use ciris_persist::prelude::Engine;

/// The peer-relevant `identity_type`s the directory is queried across (the
/// trait has no list-all method, so we union these). Ordered most-canonical
/// first; de-dup by `key_id` keeps the first sighting.
const PEER_IDENTITY_TYPES: &[&str] = &[
    identity_type::NODE,
    identity_type::STEWARD,
    identity_type::WISE_AUTHORITY,
    identity_type::ACCORD_HOLDER,
    identity_type::PARTNER,
    identity_type::WITNESS,
    identity_type::AGENT,
];

#[derive(Clone)]
struct PeersState {
    engine: Arc<Engine>,
    /// The node's own derived federation `key_id` — excluded from the peer list.
    self_key_id: String,
}

fn err(code: StatusCode, error: &str) -> Response {
    (code, Json(serde_json::json!({ "error": error }))).into_response()
}

/// The client-facing `LocalPeerState` (server-mode projection of a `KeyRecord`).
#[derive(Debug, Serialize)]
struct LocalPeerState {
    key_id: String,
    pubkey_ed25519_base64: String,
    canonical: bool,
    /// One of "trusted"|"untrusted"|"blocked"|"unknown". A directory row is an
    /// admitted key ⇒ "trusted".
    trust: &'static str,
    /// RFC3339 — the record's `valid_from`.
    first_seen: String,
    // Per-peer user sideband — not persisted in server mode (always null).
    appearance: Option<serde_json::Value>,
    alias_override: Option<String>,
    notes: Option<String>,
    last_seen: Option<String>,
}

/// `true` if the key is a known canonical-mesh identity (a node row, or a
/// `ciris-canonical*` key_id). Heuristic — sufficient for the card's badge.
fn is_canonical(rec: &KeyRecord) -> bool {
    rec.identity_type == identity_type::NODE || rec.key_id.starts_with("ciris-canonical")
}

fn to_peer(rec: KeyRecord) -> LocalPeerState {
    let canonical = is_canonical(&rec);
    LocalPeerState {
        key_id: rec.key_id,
        pubkey_ed25519_base64: rec.pubkey_ed25519_base64,
        canonical,
        trust: "trusted",
        first_seen: rec.valid_from.to_rfc3339(),
        appearance: None,
        alias_override: None,
        notes: None,
        last_seen: None,
    }
}

/// Collect every peer-relevant directory key (union of [`PEER_IDENTITY_TYPES`]),
/// de-duped by `key_id`, EXCLUDING the node's own self key.
async fn collect_peers(st: &PeersState) -> Result<Vec<LocalPeerState>, Response> {
    let dir = st.engine.federation_directory();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut peers: Vec<LocalPeerState> = Vec::new();
    for ty in PEER_IDENTITY_TYPES {
        let rows = dir
            .list_keys_by_identity_type(ty)
            .await
            .map_err(|e| err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")))?;
        for rec in rows {
            if rec.key_id == st.self_key_id {
                continue; // exclude self
            }
            if !seen.insert(rec.key_id.clone()) {
                continue; // already collected under an earlier identity_type
            }
            peers.push(to_peer(rec));
        }
    }
    Ok(peers)
}

/// `GET /v1/federation/peers` → `{ "peers": [LocalPeerState…], "total": N }`.
async fn list_peers(State(st): State<PeersState>) -> Response {
    match collect_peers(&st).await {
        Ok(peers) => {
            let total = peers.len();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "peers": peers, "total": total })),
            )
                .into_response()
        }
        Err(resp) => resp,
    }
}

/// `GET /v1/federation/peers/{key_id}` →
/// `{ "peer": LocalPeerState, "reachability": null }` (404 if unknown).
async fn get_peer(State(st): State<PeersState>, Path(key_id): Path<String>) -> Response {
    let rec = match st
        .engine
        .federation_directory()
        .lookup_public_key(&key_id)
        .await
    {
        Ok(Some(rec)) => rec,
        Ok(None) => return err(StatusCode::NOT_FOUND, "peer not found"),
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")),
    };
    let peer = to_peer(rec);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "peer": peer, "reachability": serde_json::Value::Null })),
    )
        .into_response()
}

/// The federation-peers read router. `self_key_id` is the node's own derived
/// federation `key_id` (excluded from the listing).
pub fn router(engine: Arc<Engine>, self_key_id: String) -> Router {
    let state = PeersState {
        engine,
        self_key_id,
    };
    Router::new()
        .route("/v1/federation/peers", axum::routing::get(list_peers))
        .route(
            "/v1/federation/peers/{key_id}",
            axum::routing::get(get_peer),
        )
        .with_state(state)
}
