//! **`/v1/federation/peers*`** — the agent-compat federation-peers surface
//! (CIRISServer Network card): the READ half (list + detail) plus, since
//! CIRISServer#261, the per-peer WRITE SIDEBAND (trust / appearance / SAS
//! verification) the CIRISAgent wave-2 DRY purge deletes from Python.
//!
//! The CIRIS desktop/mobile client's Network card lists the node's known
//! federation peers. On the Python agent this was served by
//! `FederationPeerListResponse` / `FederationPeerDetailResponse` +
//! `routes/federation/{peers,sas}.py`; in server mode the same data lives in
//! persist's `federation_directory` (`federation_keys` rows). This module
//! exposes it on the SAME wire contract the client expects (`LocalPeerState`),
//! so the card works unchanged. The deleted agent route files ARE the wire
//! spec — shapes below mirror them field-for-field.
//!
//! ## Wire contract (mirrors the agent)
//!
//!   - `GET /v1/federation/peers` → `{ "peers": [LocalPeerState…], "total": N }`
//!     (bare object — the client's `decodeFederationEnvelope` tolerates either a
//!     `{data:…}` wrapper or the bare body; the bare body is simplest).
//!   - `GET /v1/federation/peers/{key_id}` →
//!     `{ "peer": LocalPeerState, "reachability": null }` (the client tolerates a
//!     null `reachability` — server mode holds no Edge transport stats).
//!   - `PUT /v1/federation/peers/{key_id}/trust` (OWNER) — body
//!     `{ "trust": "trusted"|"untrusted"|"blocked"|"unknown" }` → `{ "data":
//!     LocalPeerState }` (the agent's `SuccessResponse(data=updated)` envelope;
//!     the client's `decodeFederationEnvelope` unwraps `data`).
//!   - `PUT /v1/federation/peers/{key_id}/appearance` (OWNER) — body
//!     `{ "appearance": { "icon"?, "fg_color"?, "bg_color"? } }` → same envelope.
//!   - `GET /v1/federation/peers/{key_id}/sas` → `{ "data": { "key_id",
//!     "words": [5 BIP39 words], "digits": "6 digits" } }` — the Signal-style
//!     Short Authentication String, derived EXACTLY as the agent's Edge PyO3
//!     `peer_sas` does (`ciris_edge::sas`, protocol constant
//!     `ciris-edge::peer-sas::v1`), so both sides of a call read the same words.
//!   - `PUT /v1/federation/peers/{key_id}/sas` (OWNER) — body
//!     `{ "verified": bool }` records the out-of-band SAS comparison outcome
//!     (the "SAS verification state" leg of CIRISServer#261; the agent had no
//!     PUT — this is the server-native completion of the T-E5 "promote after
//!     SAS verification" flow). Responds `{ "data": { "key_id", "verified",
//!     "verified_at" } }`.
//!
//! `LocalPeerState` JSON: `key_id`, `pubkey_ed25519_base64`, `canonical` (bool),
//! `trust` ("trusted"|…), `first_seen` (RFC3339), `appearance` / `alias_override`
//! / `notes` / `last_seen`. The sideband fields default to null until the owner
//! writes them (below); `last_seen` stays null in server mode (presence is a
//! property of attempted contact — no Edge transport stats are projected here).
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
//!   - `canonical`  ← the `identity_type` set contains `canonical` (the
//!     authoritative `admission::is_canonical` predicate — earned via
//!     anchor-scrub, not guessed from role/key_id).
//!   - `trust`  ← the owner's sideband override if one exists, else `"trusted"`
//!     (a directory row is an admitted key).
//!   - `first_seen`  ← record `valid_from` (RFC3339).
//!   - `appearance`  ← the owner's sideband annotation (Sideband convention:
//!     appearance is a LOCAL-user annotation, never trusted from the wire).
//!
//! ## Sideband persistence (#261)
//!
//! Per-peer user sideband (trust override, appearance, SAS verification) is
//! persisted through [`crate::graph_config`] — one signed `config:v1` CEG row
//! per peer under `federation.peer_sideband.<key_id>` (a `Dict` value). This
//! deliberately reuses the config-as-CEG store instead of a bespoke table:
//! the rows are owner-authored node-local annotations (exactly config's
//! shape), they survive reseed/replication like any CEG object, and the
//! latest-wins fold gives us update semantics for free. The PUTs are gated
//! the SAME two ways `/v1/config` writes are (serve-only floor + owner
//! session); reads stay unauthenticated like the rest of this read surface.
//!
//! The node's OWN self key is excluded from the list.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use ciris_persist::federation::types::{identity_type, KeyRecord};
use ciris_persist::prelude::Engine;

use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::{resolve_bearer, SessionCaller};
use crate::graph_config::{self, ConfigScope, ConfigValue};

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

/// The agent's 404 body for a sideband write on an unknown peer — mirrors
/// `routes/federation/peers.py`'s `PEER_NOT_FOUND` envelope verbatim
/// (`{"error", "key_id", "detail"}`), so a client that pattern-matches the
/// agent shape keeps working against the node.
fn peer_not_found(key_id: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "PEER_NOT_FOUND",
            "key_id": key_id,
            "detail": format!("peer {key_id:?} is not in the federation directory"),
        })),
    )
        .into_response()
}

// ─── Owner gate (#261) — IDENTICAL posture to /v1/config writes ─────────────
//
// The per-peer sideband PUTs are owner-authority acts on the node's local
// annotation store, so they are gated the SAME two ways a config write is
// (see [`crate::config_api`], which itself mirrors [`crate::federation_admin`]):
//
//   1. the serve-only floor ([`crate::auth::gate::require_owner_bound`]): an
//      owner-UNBOUND node refuses every sideband write (no responsible party
//      to root the authority in), and
//   2. the SYSTEM_ADMIN (owner) session gate (`resolve_bearer` →
//      `SessionCaller` → role+permission), matching the agent's
//      `require_system_admin` dependency on the deleted `peers.py` routes.

/// Owner-authority session gate — requires the `SYSTEM_ADMIN` (owner) role AND
/// [`Permission::FullAccess`]. Returns the verified caller, or a `401`/`403`/
/// `503` response to short-circuit. `pub(crate)` so the sibling agent-compat
/// surface ([`crate::federation_surface`]) shares ONE gate implementation.
pub(crate) async fn require_owner_session(
    engine: &Arc<Engine>,
    headers: &HeaderMap,
) -> Result<SessionCaller, Response> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "missing bearer session token",
        ));
    };
    match resolve_bearer(engine, token).await {
        Ok(Some(caller))
            if caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) =>
        {
            Ok(caller)
        }
        Ok(Some(_)) => Err(err(
            StatusCode::FORBIDDEN,
            "federation peer sideband writes require the owner (SYSTEM_ADMIN) role",
        )),
        Ok(None) => Err(err(StatusCode::UNAUTHORIZED, "invalid or expired session")),
        Err(e) => Err(err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}"))),
    }
}

/// The serve-only-floor gate (CC 3.2 / CC 1.13.5) — an owner-UNBOUND node
/// refuses every sideband write. Mirrors the config handler's check.
async fn require_owner_bound(st: &PeersState) -> Result<(), Response> {
    if crate::auth::gate::require_owner_bound(&st.engine, &st.self_key_id)
        .await
        .is_err()
    {
        return Err(err(
            StatusCode::FORBIDDEN,
            "this node has no responsible party (owner-binding) — peer sideband writes \
             refused (CC 3.2 / CC 1.13.5). Claim ownership first via POST /v1/setup/root.",
        ));
    }
    Ok(())
}

// ─── Per-peer sideband store (#261) — config-as-CEG, one Dict row per peer ──

/// Config-key prefix for the per-peer sideband rows. One key per peer:
/// `federation.peer_sideband.<key_id>` → [`PeerSideband`] as a `Dict` value.
const SIDEBAND_KEY_PREFIX: &str = "federation.peer_sideband.";

/// The per-peer user sideband — the owner's LOCAL annotations on a peer.
/// Persisted as one `config:v1` Dict row per peer (see module doc). All
/// fields optional so a partial write (trust only, appearance only, SAS
/// only) round-trips without clobbering siblings — the PUT handlers do a
/// read-modify-write on the whole struct.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PeerSideband {
    /// Trust override: "trusted"|"untrusted"|"blocked"|"unknown" (the
    /// agent's `PeerTrustState` vocabulary, locked to Edge's `EdgePeerTrust`).
    #[serde(skip_serializing_if = "Option::is_none")]
    trust: Option<String>,
    /// The `(icon, fg_color, bg_color)` appearance tuple — local UI sugar.
    #[serde(skip_serializing_if = "Option::is_none")]
    appearance: Option<PeerAppearance>,
    /// Whether the owner has confirmed the SAS words out-of-band.
    #[serde(skip_serializing_if = "Option::is_none")]
    sas_verified: Option<bool>,
    /// RFC3339 timestamp of the most recent SAS verification write.
    #[serde(skip_serializing_if = "Option::is_none")]
    sas_verified_at: Option<String>,
}

/// The agent's `PeerAppearance` (canonical_peer.py) — `extra="forbid"` there,
/// so `deny_unknown_fields` here keeps the two ends equally strict.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerAppearance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    icon: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fg_color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bg_color: Option<String>,
}

fn sideband_config_key(key_id: &str) -> String {
    format!("{SIDEBAND_KEY_PREFIX}{key_id}")
}

/// Read the sideband row for one peer (None if never written / tombstoned).
async fn load_sideband(st: &PeersState, key_id: &str) -> Result<Option<PeerSideband>, Response> {
    let entry = graph_config::get_config(&st.engine, &st.self_key_id, &sideband_config_key(key_id))
        .await
        .map_err(|e| err(StatusCode::SERVICE_UNAVAILABLE, &format!("sideband: {e}")))?;
    Ok(entry.and_then(|e| {
        serde_json::to_value(&e.value)
            .ok()
            .and_then(|v| serde_json::from_value::<PeerSideband>(v).ok())
    }))
}

/// Read ALL peers' sideband rows in one prefix-scan (for the list overlay).
/// Best-effort: a store error degrades to "no overlay" rather than failing the
/// whole peer list — the directory rows are the load-bearing data.
async fn load_all_sidebands(st: &PeersState) -> HashMap<String, PeerSideband> {
    let mut out = HashMap::new();
    match graph_config::list_configs(&st.engine, &st.self_key_id, Some(SIDEBAND_KEY_PREFIX)).await {
        Ok(map) => {
            for (key, entry) in map {
                let Some(peer_key_id) = key.strip_prefix(SIDEBAND_KEY_PREFIX) else {
                    continue;
                };
                if let Some(sb) = serde_json::to_value(&entry.value)
                    .ok()
                    .and_then(|v| serde_json::from_value::<PeerSideband>(v).ok())
                {
                    out.insert(peer_key_id.to_string(), sb);
                }
            }
        }
        Err(e) => {
            tracing::warn!("peer sideband prefix-scan failed (serving bare rows): {e}");
        }
    }
    out
}

/// Write the sideband row for one peer (signed `config:v1`, latest-wins).
async fn store_sideband(
    st: &PeersState,
    key_id: &str,
    sideband: &PeerSideband,
    updated_by: &str,
) -> Result<(), Response> {
    let value = match serde_json::to_value(sideband) {
        Ok(serde_json::Value::Object(map)) => ConfigValue::Dict(map),
        _ => {
            return Err(err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "sideband serialization failed",
            ))
        }
    };
    graph_config::set_config(
        &st.engine,
        &st.self_key_id,
        &sideband_config_key(key_id),
        value,
        updated_by,
        ConfigScope::Local,
    )
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("sideband: {e}")))?;
    Ok(())
}

/// The client-facing `LocalPeerState` (server-mode projection of a `KeyRecord`).
#[derive(Debug, Serialize)]
struct LocalPeerState {
    key_id: String,
    pubkey_ed25519_base64: String,
    /// The ML-DSA-65 half (present on a hybrid-complete row; `None` on a legacy
    /// bookmark). Projected so the accord admit-node card can auto-fill BOTH of a
    /// selected owned node's pubkeys from the local directory — no manual paste.
    #[serde(skip_serializing_if = "Option::is_none")]
    pubkey_ml_dsa_65_base64: Option<String>,
    canonical: bool,
    /// One of "trusted"|"untrusted"|"blocked"|"unknown". A directory row is an
    /// admitted key ⇒ "trusted", unless the owner wrote a sideband override.
    trust: String,
    /// RFC3339 — the record's `valid_from`.
    first_seen: String,
    // Per-peer user sideband (#261) — overlaid from the config-as-CEG rows
    // when present; null until the owner writes them.
    appearance: Option<PeerAppearance>,
    alias_override: Option<String>,
    notes: Option<String>,
    last_seen: Option<String>,
}

/// `true` if the key is a canonical / founding bootstrap server — the
/// AUTHORITATIVE predicate `ciris_persist::federation::admission::is_canonical`
/// uses: its `identity_type` set contains `identity_type::CANONICAL` (a row can
/// carry `canonical` only by earning it via anchor-scrub, since the write gate is
/// the enforcement point). We already hold the row, so we apply the substrate's
/// set-membership predicate directly instead of the old node-role/key_id-prefix
/// heuristic (which false-positived every peer node).
fn is_canonical(rec: &KeyRecord) -> bool {
    identity_type::set_contains(&rec.identity_type, identity_type::CANONICAL)
}

fn to_peer(rec: KeyRecord, sideband: Option<&PeerSideband>) -> LocalPeerState {
    let canonical = is_canonical(&rec);
    LocalPeerState {
        key_id: rec.key_id,
        pubkey_ed25519_base64: rec.pubkey_ed25519_base64,
        pubkey_ml_dsa_65_base64: rec.pubkey_ml_dsa_65_base64,
        canonical,
        trust: sideband
            .and_then(|s| s.trust.clone())
            .unwrap_or_else(|| "trusted".to_string()),
        first_seen: rec.valid_from.to_rfc3339(),
        appearance: sideband.and_then(|s| s.appearance.clone()),
        alias_override: None,
        notes: None,
        last_seen: None,
    }
}

/// Collect every peer-relevant directory key (union of [`PEER_IDENTITY_TYPES`]),
/// de-duped by `key_id`, EXCLUDING the node's own self key. The owner's
/// sideband rows are overlaid per peer (trust override + appearance).
async fn collect_peers(st: &PeersState) -> Result<Vec<LocalPeerState>, Response> {
    let sidebands = load_all_sidebands(st).await;
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
            let sideband = sidebands.get(&rec.key_id);
            peers.push(to_peer(rec, sideband));
        }
    }
    Ok(peers)
}

/// The `(total, canonical)` peer counts — the federation-identity projection's
/// two counters (CIRISServer#261: `GET /v1/federation/identity` mirrors the
/// agent's `peer_count_total` / `peer_count_canonical`, which the agent sourced
/// from its `BootstrapPeerSeeder`; in server mode the federation directory IS
/// the peer set). `pub(crate)` for [`crate::federation_surface`].
pub(crate) async fn peer_counts(
    engine: &Arc<Engine>,
    self_key_id: &str,
) -> Result<(usize, usize), String> {
    let dir = engine.federation_directory();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut canonical = 0usize;
    for ty in PEER_IDENTITY_TYPES {
        let rows = dir
            .list_keys_by_identity_type(ty)
            .await
            .map_err(|e| format!("store: {e}"))?;
        for rec in rows {
            if rec.key_id == self_key_id {
                continue;
            }
            if !seen.insert(rec.key_id.clone()) {
                continue;
            }
            if is_canonical(&rec) {
                canonical += 1;
            }
        }
    }
    Ok((seen.len(), canonical))
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
    let sideband = match load_sideband(&st, &key_id).await {
        Ok(sb) => sb,
        Err(resp) => return resp,
    };
    let peer = to_peer(rec, sideband.as_ref());
    (
        StatusCode::OK,
        Json(serde_json::json!({ "peer": peer, "reachability": serde_json::Value::Null })),
    )
        .into_response()
}

// ─── The #261 write sideband: trust / appearance / SAS ──────────────────────

/// The agent's `PeerTrustState` wire vocabulary — locked to Edge's
/// `EdgePeerTrust` enum; don't extend without an Edge counterpart.
const TRUST_VOCAB: &[&str] = &["trusted", "untrusted", "blocked", "unknown"];

/// Body for `PUT /v1/federation/peers/{key_id}/trust` — the agent's
/// `FederationPeerTrustUpdateRequest` (`extra="forbid"` ⇒ `deny_unknown_fields`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustUpdateRequest {
    trust: String,
}

/// Body for `PUT /v1/federation/peers/{key_id}/appearance` — the agent's
/// `FederationPeerAppearanceUpdateRequest`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppearanceUpdateRequest {
    appearance: PeerAppearance,
}

/// Body for `PUT /v1/federation/peers/{key_id}/sas` — server-native (#261);
/// records the operator's out-of-band SAS word comparison outcome.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SasUpdateRequest {
    verified: bool,
}

/// Shared prologue for the three sideband PUTs: gates (serve-only floor +
/// owner session), then the peer-existence check. Returns the caller and the
/// peer's directory row.
async fn sideband_put_prologue(
    st: &PeersState,
    headers: &HeaderMap,
    key_id: &str,
) -> Result<(SessionCaller, KeyRecord), Response> {
    require_owner_bound(st).await?;
    let caller = require_owner_session(&st.engine, headers).await?;
    let rec = st
        .engine
        .federation_directory()
        .lookup_public_key(key_id)
        .await
        .map_err(|e| err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")))?
        .ok_or_else(|| peer_not_found(key_id))?;
    Ok((caller, rec))
}

/// `PUT /v1/federation/peers/{key_id}/trust` (OWNER) → `{ "data":
/// LocalPeerState }` with the new trust applied. 404 `PEER_NOT_FOUND` for a
/// key not in the directory — same as the agent's seeder-miss.
async fn set_peer_trust(
    State(st): State<PeersState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let (caller, rec) = match sideband_put_prologue(&st, &headers, &key_id).await {
        Ok(x) => x,
        Err(resp) => return resp,
    };
    let req: TrustUpdateRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    if !TRUST_VOCAB.contains(&req.trust.as_str()) {
        return err(
            StatusCode::BAD_REQUEST,
            &format!(
                "trust must be one of {}: got {:?}",
                TRUST_VOCAB.join("|"),
                req.trust
            ),
        );
    }
    let mut sideband = match load_sideband(&st, &key_id).await {
        Ok(sb) => sb.unwrap_or_default(),
        Err(resp) => return resp,
    };
    sideband.trust = Some(req.trust);
    if let Err(resp) = store_sideband(&st, &key_id, &sideband, &caller.wa_id).await {
        return resp;
    }
    let peer = to_peer(rec, Some(&sideband));
    (StatusCode::OK, Json(serde_json::json!({ "data": peer }))).into_response()
}

/// `PUT /v1/federation/peers/{key_id}/appearance` (OWNER) → `{ "data":
/// LocalPeerState }` with the new appearance applied.
async fn set_peer_appearance(
    State(st): State<PeersState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let (caller, rec) = match sideband_put_prologue(&st, &headers, &key_id).await {
        Ok(x) => x,
        Err(resp) => return resp,
    };
    let req: AppearanceUpdateRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    let mut sideband = match load_sideband(&st, &key_id).await {
        Ok(sb) => sb.unwrap_or_default(),
        Err(resp) => return resp,
    };
    sideband.appearance = Some(req.appearance);
    if let Err(resp) = store_sideband(&st, &key_id, &sideband, &caller.wa_id).await {
        return resp;
    }
    let peer = to_peer(rec, Some(&sideband));
    (StatusCode::OK, Json(serde_json::json!({ "data": peer }))).into_response()
}

/// `PUT /v1/federation/peers/{key_id}/sas` (OWNER) — record the out-of-band
/// SAS verification outcome → `{ "data": { "key_id", "verified",
/// "verified_at" } }`. `verified_at` stamps a `true` write and clears on
/// `false` (an un-verify resets the record, it doesn't preserve a stale
/// timestamp).
async fn set_peer_sas(
    State(st): State<PeersState>,
    Path(key_id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let (caller, _rec) = match sideband_put_prologue(&st, &headers, &key_id).await {
        Ok(x) => x,
        Err(resp) => return resp,
    };
    let req: SasUpdateRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    let mut sideband = match load_sideband(&st, &key_id).await {
        Ok(sb) => sb.unwrap_or_default(),
        Err(resp) => return resp,
    };
    sideband.sas_verified = Some(req.verified);
    sideband.sas_verified_at = req.verified.then(|| chrono::Utc::now().to_rfc3339());
    if let Err(resp) = store_sideband(&st, &key_id, &sideband, &caller.wa_id).await {
        return resp;
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": {
                "key_id": key_id,
                "verified": sideband.sas_verified,
                "verified_at": sideband.sas_verified_at,
            }
        })),
    )
        .into_response()
}

/// `GET /v1/federation/peers/{key_id}/sas` → `{ "data": { "key_id", "words",
/// "digits", … } }` — the Signal-style Short Authentication String for
/// verifying the peer key out-of-band (the deleted agent `sas.py` contract).
///
/// Derivation is EXACTLY the agent's: `ciris_edge::sas` over the sorted
/// `(local_pub, peer_pub)` tuple + the `ciris-edge::peer-sas::v1` protocol
/// constant — a pure function, so the agent-served and node-served words for
/// the same key pair are IDENTICAL (both operators read the same 5 words / 6
/// digits regardless of which surface they poll). The local pubkey is the
/// node's federation Ed25519 (the engine's composed signer — the same key
/// `Edge.signer()` wraps on the agent path).
///
/// Unauthenticated like the other peers reads (the agent gated OBSERVER+; the
/// node's read surface has no observer tier — both pubkeys are public data
/// and the SAS is a pure function of them).
///
/// Extra fields `verified`/`verified_at` surface the PUT-recorded sideband
/// state; the client's kotlinx `ignoreUnknownKeys=true` tolerates them.
async fn get_peer_sas(State(st): State<PeersState>, Path(key_id): Path<String>) -> Response {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;

    // Peer pubkey — a directory miss is the agent's 404 `PEER_SAS_UNAVAILABLE`.
    let rec =
        match st
            .engine
            .federation_directory()
            .lookup_public_key(&key_id)
            .await
        {
            Ok(Some(rec)) => rec,
            Ok(None) => return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "PEER_SAS_UNAVAILABLE",
                    "key_id": key_id,
                    "detail": format!("peer key_id not found in federation directory: {key_id:?}"),
                })),
            )
                .into_response(),
            Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")),
        };
    let peer_pub: [u8; 32] = match BASE64
        .decode(&rec.pubkey_ed25519_base64)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
    {
        Some(pk) => pk,
        None => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "peer pubkey is not a 32-byte Ed25519 key",
            )
        }
    };

    // Local pubkey — the node's composed federation signer (Ed25519 half).
    let local_pub: [u8; 32] = match st.engine.signer().public_key().await {
        Ok(b) => match <[u8; 32]>::try_from(b.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "local pubkey must be 32 bytes for SAS derivation",
                )
            }
        },
        Err(e) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!("local signer public_key: {e}"),
            )
        }
    };

    let words = match ciris_edge::sas::peer_sas_words(
        &local_pub,
        &peer_pub,
        ciris_edge::sas::DEFAULT_SAS_WORDS,
    ) {
        Ok(w) => w,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("peer_sas: {e}")),
    };
    let digits = match ciris_edge::sas::peer_sas_digits(
        &local_pub,
        &peer_pub,
        ciris_edge::sas::DEFAULT_SAS_DIGITS,
    ) {
        Ok(d) => d,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("peer_sas_digits: {e}"),
            )
        }
    };

    let sideband = load_sideband(&st, &key_id).await.ok().flatten();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": {
                "key_id": key_id,
                "words": words,
                "digits": digits,
                "verified": sideband.as_ref().and_then(|s| s.sas_verified),
                "verified_at": sideband.as_ref().and_then(|s| s.sas_verified_at.clone()),
            }
        })),
    )
        .into_response()
}

/// TEST-ANCHOR-ONLY (CIRISServer#258) — serve THIS node's own **directory row**
/// as a registrable `SignedKeyRecord` (`{"record": {...}}`), i.e. the
/// test-root-BLESSED record after `test_bless` upgraded it — unlike
/// `/v1/federation/self-key-record`, which serves the boot-time SELF-SIGNED
/// record. The harness agent fetches this to admit the harness canonical
/// (whose blessed row carries `canonical,node` + the dial hint) into its own
/// directory, standing in for the baked genesis the test override skips.
/// Compile-fenced with the rest of the harness surface; never in prod.
#[cfg(feature = "test-anchor")]
async fn test_blessed_self_record(State(st): State<PeersState>) -> Response {
    let rec = match st
        .engine
        .federation_directory()
        .lookup_public_key(&st.self_key_id)
        .await
    {
        Ok(Some(rec)) => rec,
        Ok(None) => return err(StatusCode::NOT_FOUND, "self record not in directory"),
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")),
    };
    (StatusCode::OK, Json(serde_json::json!({ "record": rec }))).into_response()
}

/// TEST-ANCHOR-ONLY (CIRISServer#258) — admit a peer's `SignedKeyRecord` into
/// THIS node's federation directory, unauthenticated. Stands in for the
/// owner-gated claim/peering flows a production mesh admits agents through, so
/// the harness canonical can ATTRIBUTE the agent's inbound round envelopes
/// (without a directory row the source_key_id resolves to None, the frame is
/// dropped pre-dispatch — the #317 class — and every anti-entropy round times
/// out awaiting the reply). The record still passes the FULL untouched
/// admission gates (`register_federation_key`: Strict hybrid self-scrub
/// verify, hardware-class chokepoint, role gates) — only the CALLER auth is
/// waived, and only in a test-anchor build.
#[cfg(feature = "test-anchor")]
async fn test_admit_peer(
    State(st): State<PeersState>,
    Json(signed): Json<serde_json::Value>,
) -> Response {
    use ciris_verify_core::federation_self_record::{produce_scrubbed_key_record, ScrubTarget};

    let rec: ciris_persist::federation::SignedKeyRecord = match serde_json::from_value(signed) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("SignedKeyRecord: {e}")),
    };
    let key_id = rec.record.key_id.clone();

    // BLESS-then-register — the harness mirror of the prod admit-node ceremony
    // (accord_provision.rs: an accord holder scrub-signs the node's record).
    // A merely self-signed row admits but roots only ADVISORY
    // (`rooting_not_rooted_at_steward`): the provenance chain must terminate at
    // an accord holder for the announce to root, and without Rooted provenance
    // the inbound round envelopes stay unattributed → the round times out.
    // Scrubbing with the SW test root (terminus `test-accord-holder-0`, in the
    // swapped anchor) makes the peer root exactly as an A1-admitted node does.
    let blessed = {
        let Some(ml) = rec.record.pubkey_ml_dsa_65_base64.clone() else {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "peer record has no ML-DSA-65 pubkey — cannot scrub-sign",
            );
        };
        let test_root = match crate::test_bless::mint_test_root() {
            Ok(r) => r,
            Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &format!("test root: {e}")),
        };
        let target = ScrubTarget {
            key_id: key_id.clone(),
            pubkey_ed25519_base64: rec.record.pubkey_ed25519_base64.clone(),
            pubkey_ml_dsa_65_base64: ml,
            identity_type: rec.record.identity_type.clone(),
            roles: Vec::new(),
        };
        let valid_from = chrono::Utc::now().to_rfc3339();
        let scrubbed = match produce_scrubbed_key_record(&test_root, target, &valid_from, &[]).await
        {
            Ok(s) => s,
            Err(e) => {
                return err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &format!("test-root scrub-sign of {key_id}: {e}"),
                )
            }
        };
        match serde_json::to_value(&scrubbed).ok().and_then(|v| {
            serde_json::from_value::<ciris_persist::federation::SignedKeyRecord>(v).ok()
        }) {
            Some(p) => p,
            None => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "scrubbed record bridge failed",
                )
            }
        }
    };
    let blessed_json = serde_json::to_value(&blessed).unwrap_or_default();

    match crate::hardware_attestation::register_attested_federation_key(&st.engine, blessed).await {
        Ok(()) => {
            tracing::warn!(
                peer = %key_id,
                "TEST-ANCHOR: peer BLESSED (SW test-root scrub) + admitted via unauthenticated \
                 test-admit-peer (harness only) — announce will root as Rooted provenance"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({ "admitted": key_id, "blessed": true, "record": blessed_json })),
            )
                .into_response()
        }
        Err(ciris_persist::federation::Error::Conflict(_)) => (
            StatusCode::OK,
            Json(serde_json::json!({ "admitted": key_id, "blessed": true, "conflict": true })),
        )
            .into_response(),
        Err(e) => err(StatusCode::UNPROCESSABLE_ENTITY, &format!("admission: {e}")),
    }
}

/// The federation-peers read router. `self_key_id` is the node's own derived
/// federation `key_id` (excluded from the listing).
pub fn router(engine: Arc<Engine>, self_key_id: String) -> Router {
    let state = PeersState {
        engine,
        self_key_id,
    };
    let router = Router::new()
        .route("/v1/federation/peers", axum::routing::get(list_peers))
        .route(
            "/v1/federation/peers/{key_id}",
            axum::routing::get(get_peer),
        )
        // The #261 write sideband + SAS (see module doc): owner-gated PUTs,
        // unauthenticated SAS read — the routes the agent wave-2 purge deletes.
        .route(
            "/v1/federation/peers/{key_id}/trust",
            axum::routing::put(set_peer_trust),
        )
        .route(
            "/v1/federation/peers/{key_id}/appearance",
            axum::routing::put(set_peer_appearance),
        )
        .route(
            "/v1/federation/peers/{key_id}/sas",
            axum::routing::get(get_peer_sas).put(set_peer_sas),
        );
    #[cfg(feature = "test-anchor")]
    let router = router
        .route(
            "/v1/federation/test-blessed-self-record",
            axum::routing::get(test_blessed_self_record),
        )
        .route(
            "/v1/federation/test-admit-peer",
            axum::routing::post(test_admit_peer),
        );
    router.with_state(state)
}
