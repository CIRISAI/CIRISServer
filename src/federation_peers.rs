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
}

fn err(code: StatusCode, error: &str) -> Response {
    (code, Json(serde_json::json!({ "error": error }))).into_response()
}

/// The node's own derived federation `key_id` — the key excluded from the peer
/// list, the node whose owner-binding gates the sideband writes, and the
/// granter of the reciprocal consent below.
///
/// **Resolved from the engine, never accepted as a parameter**
/// (CIRISServer#372 Level 2). This module already knew the difference: the
/// test-anchor admit path derived it explicitly and warned in a comment that
/// "passing `st.self_key_id` (the composed `cfg.key_id`) risks a mismatch that
/// would make the idempotency read miss and the grant land under the wrong
/// granter". With no parameter left there is no second value to mismatch.
async fn self_key_id(st: &PeersState) -> Result<String, Response> {
    crate::self_identity::resolve(&st.engine, "federation_peers")
        .await
        .map_err(|e| {
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!("{} ({e})", crate::self_identity::MESSAGE_TEXT),
            )
        })
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
    let self_key_id = self_key_id(st).await?;
    if crate::auth::gate::require_owner_bound(&st.engine, &self_key_id)
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
    let entry = graph_config::get_config(&st.engine, &sideband_config_key(key_id))
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
    match graph_config::list_configs(&st.engine, Some(SIDEBAND_KEY_PREFIX)).await {
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

/// `true` if the key is a canonical / founding bootstrap server, **and the quorum
/// has not withdrawn that role**.
///
/// # This was a second opinion, and it disagreed with the first
///
/// It read set-membership alone and its doc called that "the AUTHORITATIVE
/// predicate `admission::is_canonical` uses". That was true at persist v13.0.0.
/// v13.1.0 (CIRISPersist#377) superseded it: `Engine::is_canonical` now resolves
/// through `is_canonical_effective`, which is set-membership AND
/// `lookup_canonical_withdrawal(key_id).is_none()` — in persist's words, "a
/// WITHDRAWN canonical reads false (the raw set-membership still carries the role
/// token, but the quorum revoked it)".
///
/// So one node answered this two ways depending which surface you asked:
/// `accord_provision` already calls the tombstone-aware `engine.is_canonical`,
/// while this rendered `"canonical": true` for a key the accord had de-canonicalised
/// — on `GET /v1/federation/peers`, the surface an operator would check the
/// withdrawal ON, and in the canonical tally beside it. The withdraw plane is live
/// here (`list_canonical_withdrawals`, `supersede_canonical`), so this was not
/// hypothetical: a successful de-canonicalisation looked like a failed one.
///
/// It takes the directory now because the answer is not in the row.
async fn is_canonical(
    dir: &dyn ciris_persist::federation::FederationDirectory,
    rec: &KeyRecord,
) -> bool {
    if !identity_type::set_contains(&rec.identity_type, identity_type::CANONICAL) {
        return false;
    }
    // A read failure is NOT "not canonical" — that would silently demote every
    // canonical peer during a store outage. Fall back to the role token and let
    // the outage surface elsewhere, rather than inventing a de-canonicalisation.
    match dir.lookup_canonical_withdrawal(&rec.key_id).await {
        Ok(w) => w.is_none(),
        Err(e) => {
            tracing::warn!(
                key_id = %rec.key_id, error = %e,
                "could not read the canonical-withdrawal tombstone — reporting the role token as \
                 carried. A withdrawn canonical may read `true` until the store answers again"
            );
            true
        }
    }
}

async fn to_peer(
    dir: &dyn ciris_persist::federation::FederationDirectory,
    rec: KeyRecord,
    sideband: Option<&PeerSideband>,
) -> LocalPeerState {
    let canonical = is_canonical(dir, &rec).await;
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
    let self_key_id = self_key_id(st).await?;
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
            if rec.key_id == self_key_id {
                continue; // exclude self
            }
            if !seen.insert(rec.key_id.clone()) {
                continue; // already collected under an earlier identity_type
            }
            let sideband = sidebands.get(&rec.key_id);
            peers.push(to_peer(dir.as_ref(), rec, sideband).await);
        }
    }

    // ── Announced-but-not-admitted peers (CIRISServer#289) ──────────────────
    //
    // edge has been WRITING these rows all along — `reticulum.rs record_announced_peer`,
    // whose own comment names `GET /v1/federation/peers` as the intended consumer
    // (CIRISEdge#362) — and nothing here ever read them. A node you have heard
    // announce, but never admitted, was invisible in the peer list.
    //
    // These are NOT keys. The rows carry no provenance and must never reach a
    // verification path; they project as `canonical=false, trust="unknown"`,
    // which is the honest rendering of "heard, not vouched for".
    //
    // `to_peer` is deliberately BYPASSED: it resolves trust and canonicality
    // from the directory, and these keys are by definition absent from it.
    match dir.list_announced_peers().await {
        Ok(rows) => {
            for a in rows {
                if a.key_id == self_key_id || !seen.insert(a.key_id.clone()) {
                    // An admitted key wins: it has provenance, this row has none.
                    continue;
                }
                let sideband = sidebands.get(&a.key_id);
                peers.push(LocalPeerState {
                    key_id: a.key_id,
                    pubkey_ed25519_base64: a.pubkey_ed25519_base64,
                    pubkey_ml_dsa_65_base64: a.pubkey_ml_dsa_65_base64,
                    canonical: false,
                    // "unknown" is the DEFAULT, not a constant: an owner who has
                    // explicitly marked this key (say `blocked`) means it, and a
                    // bookmark is exactly where that matters most.
                    trust: sideband
                        .and_then(|s| s.trust.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    first_seen: a.first_seen_at.to_rfc3339(),
                    appearance: sideband.and_then(|s| s.appearance.clone()),
                    alias_override: None,
                    notes: None,
                    // The liveness signal an admitted row does not carry.
                    last_seen: Some(a.last_seen_at.to_rfc3339()),
                });
            }
        }
        // NOT the 503 the loop above uses. The trait default is
        // `Error::Unsupported`, so mapping this to SERVICE_UNAVAILABLE would take
        // the ENTIRE peers endpoint down on any backend without the table — a
        // strictly worse outcome than the omission this fixes.
        Err(e) => {
            tracing::warn!(
                error = %e,
                "announced-peer bookmarks unavailable — listing admitted peers only. \
                 Peers this node has heard announce but not admitted will not appear."
            );
        }
    }

    Ok(peers)
}

/// The `(total, canonical)` peer counts — the federation-identity projection's
/// two counters (CIRISServer#261: `GET /v1/federation/identity` mirrors the
/// agent's `peer_count_total` / `peer_count_canonical`, which the agent sourced
/// from its `BootstrapPeerSeeder`; in server mode the federation directory IS
/// the peer set). `pub(crate)` for [`crate::federation_surface`].
///
/// # These count ADMITTED keys only, and deliberately so (CIRISServer#289)
///
/// `GET /v1/federation/peers` now also lists announced-but-not-admitted
/// bookmarks, so its array is LONGER than `peer_count_total`. That divergence is
/// chosen, not overlooked.
///
/// A count is an authority statement — "this node has N peers" — and an announce
/// is unverified hearsay: anyone can emit one, so counting them would let a
/// stranger inflate a number the UI presents as standing. The list can afford to
/// show them because every bookmark renders `canonical=false, trust="unknown"`
/// beside its own liveness; a bare integer carries no such qualifier.
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
            if is_canonical(dir.as_ref(), &rec).await {
                canonical += 1;
            }
        }
    }
    Ok((seen.len(), canonical))
}

/// **One key, projected as a `LocalPeerState`** — for the contacts surface
/// ([`crate::contacts_chat`]).
///
/// Contacts render on the peer card the client already binds, so the contacts
/// route must serve the SAME projection this module serves rather than a second
/// one that starts identical and drifts. Returns the JSON rather than the
/// private struct so the shape stays owned HERE: a caller may add contact-only
/// members to the object, but cannot fork the peer half of it.
///
/// # Why per-key, and not [`collect_peers`]
///
/// [`PEER_IDENTITY_TYPES`] — the union `GET /v1/federation/peers` walks — does
/// **not** include [`identity_type::USER`]. That is correct for the peers
/// endpoint (a human is not a peer of this node, and `peer_counts` reads the
/// same list, so a human on it would inflate `peer_count_total`), and it means a
/// human contact is INVISIBLE to the bulk listing. A contact is a key this node
/// has already consented to by `key_id`, so resolving it directly is both
/// cheaper and the only way a `user` identity projects at all.
///
/// `Ok(None)` iff the key is not in the federation directory.
pub(crate) async fn peer_projection(
    engine: Arc<Engine>,
    key_id: &str,
) -> Result<Option<serde_json::Value>, String> {
    let st = PeersState { engine };
    let dir = st.engine.federation_directory();
    let Some(rec) = dir
        .lookup_public_key(key_id)
        .await
        .map_err(|e| format!("lookup_public_key({key_id}): {e}"))?
    else {
        return Ok(None);
    };
    // The owner's local annotations, overlaid by the same `to_peer` that serves
    // the peers endpoint — so trust overrides and appearance follow a key onto
    // its contact card without a second overlay implementation.
    let sideband = load_sideband(&st, key_id)
        .await
        // The internal form is a ready `Response`; the contacts route re-types
        // the failure under its own `reason_id`, so only the status crosses.
        .map_err(|resp| format!("peer sideband refused ({})", resp.status()))?;
    let peer = to_peer(dir.as_ref(), rec, sideband.as_ref()).await;
    serde_json::to_value(&peer)
        .map(Some)
        .map_err(|e| format!("serialize LocalPeerState({key_id}): {e}"))
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
    let peer = to_peer(
        st.engine.federation_directory().as_ref(),
        rec,
        sideband.as_ref(),
    )
    .await;
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
    let peer = to_peer(
        st.engine.federation_directory().as_ref(),
        rec,
        Some(&sideband),
    )
    .await;
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
    let peer = to_peer(
        st.engine.federation_directory().as_ref(),
        rec,
        Some(&sideband),
    )
    .await;
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
    let self_key_id = match self_key_id(&st).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let rec = match st
        .engine
        .federation_directory()
        .lookup_public_key(&self_key_id)
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
        let scrubbed =
            match produce_scrubbed_key_record(&test_root, target, &valid_from, None, &[]).await {
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

    // Admit the peer (bless-then-register). BOTH `Ok` and a benign `Conflict`
    // mean the peer is now an admitted `federation_keys` row; only a hard error
    // aborts. We fall through to the reciprocal-consent step in either case.
    let conflict =
        match crate::hardware_attestation::register_attested_federation_key(&st.engine, blessed)
            .await
        {
            Ok(()) => {
                tracing::warn!(
                    peer = %key_id,
                    "TEST-ANCHOR: peer BLESSED (SW test-root scrub) + admitted via unauthenticated \
                     test-admit-peer (harness only) — announce will root as Rooted provenance"
                );
                false
            }
            Err(ciris_persist::federation::Error::Conflict(_)) => true,
            Err(e) => return err(StatusCode::UNPROCESSABLE_ENTITY, &format!("admission: {e}")),
        };

    // ── Reciprocal replication consent (CIRISEdge#396 item 1) ────────────────
    // Consent is DIRECTIONAL. Edge's `resolve_attestation_recipient` funnels the
    // WHOLE attestation plane through `list_consent_peers(local)` (persist's E7
    // projection, `local` == THIS node): a peer absent from the sender's own
    // send-set has *every* attestation withheld, fail-closed (proven by edge's
    // `consent_membership_fan_out_bound`). The agent authoring a grant that names
    // the canonical only opens agent→canonical; nothing crosses canonical→agent —
    // including the leg-B candidate `delegates_to(root → canonical, infra:serve)`
    // the agent's `capability_roots_to_trusted_root` walk needs — until the
    // canonical authors the RECIPROCAL grant naming the agent. The bare agent mints
    // its side via the `author_federation_consent` FFI at boot; the canonical never
    // runs that path, so we mint its side HERE, at the same test-anchor admit door.
    //
    // PREFIX SET — security-critical, kept MINIMAL. The row that must cross is the
    // leg-B candidate `delegates_to(root → self, infra:serve)`, dimension
    // `self:delegates_to:v1` (`delegates_to_envelope` stamps it; verified). It is
    // minted at `cohort_scope: federation`, so it is already federation-tier and
    // crosses on send-set MEMBERSHIP alone — this grant's job is to put the peer in
    // the set. We carry the single narrow trust-graph prefix `self:delegates_to:`
    // (a `consent_grammar::covers` `starts_with` of that dimension) and NOTHING more:
    //   • NOT `trace:` — `promote_consented_backlog` walks EVERY local-tier row (not
    //     just our own) and promotes any dimension our egress grants `covers`. A
    //     `trace:`-covering grant would promote a co-resident load agent's replicated
    //     -in local-tier trace rows to federation, leaking agent B's traces to agent A
    //     under `docker-compose.load.yml` (N agents / one canonical). Cross-agent leak.
    //   • NOT `capacity:` / `default_attestation_prefixes()` — it would satisfy the
    //     non-vacuous-prefix guard (peer enters the send-set) while covering nothing
    //     the trust graph needs: the plane opens, the row still doesn't promote, and
    //     the failure looks identical to today. A silent-false trap.
    // If `self:delegates_to:` alone proves insufficient at runtime, the fix is to
    // report the refused dimension — NOT to widen the set speculatively.
    //
    // TESTING-MODE FENCE. Even in a test-anchor build this auto-grant fires ONLY
    // under `CIRIS_TESTING_MODE=true`, mirroring the agent's `author_consent_testing`
    // posture: production consent is exclusively the owner-gated
    // `POST /v1/federation/consent`. A self-attested admission proves key custody,
    // not authorization to replicate — so auto-consent stays a fixture behavior.
    if std::env::var("CIRIS_TESTING_MODE").ok().as_deref() != Some("true") {
        tracing::warn!(
            peer = %key_id,
            "TEST-ANCHOR: peer admitted but CIRIS_TESTING_MODE!=true — NOT auto-authoring the \
             reciprocal consent:replication grant (production consent is the owner-gated \
             POST /v1/federation/consent); this node's plane toward the peer stays closed"
        );
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "admitted": key_id,
                "blessed": true,
                "conflict": conflict,
                "reciprocal_consent": serde_json::Value::Null,
                "record": if conflict { serde_json::Value::Null } else { blessed_json },
            })),
        )
            .into_response();
    }

    // `node_key_id` MUST be `engine.local_derived_key_id()` — the EXACT #247-derived
    // attester `emit_attestation_self` stamps AND the value edge resolves its
    // `local_key_id` send-set against. This used to warn that passing
    // `st.self_key_id` (the composed `cfg.key_id`) risks a mismatch; since
    // CIRISServer#372 Level 2 there IS no `st.self_key_id` to pass, and every
    // route on this surface reads the same [`self_key_id`] the way this one
    // always did.
    let node_key_id = match self_key_id(&st).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // The single narrow trust-graph prefix — see the block comment above.
    let consent_prefixes = ["self:delegates_to:".to_string()];
    let consent = match crate::peer::emit_replication_consent(
        &st.engine,
        &node_key_id,
        &key_id,
        &consent_prefixes,
    )
    .await
    {
        Ok(g) => g,
        // Loud, not silent: without this grant the canonical's whole attestation
        // plane toward the agent stays dark, so surface the failure to the harness
        // (which retries the admit) rather than 200-ing a half-open peering.
        Err(e) => {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("reciprocal replication consent for {key_id}: {e}"),
            )
        }
    };

    // Assert on the PROJECTION, not the row (CIRISEdge#425 silent-false class). A
    // `consent:replication:v1` attestation can EXIST yet be invisible to edge if its
    // `consent_peer_set` projection was not maintained — edge reads the projection
    // (`list_consent_peers`), never the raw table. `emit_replication_consent` uses
    // `emit_attestation_self`, whose write maintains the projection transactionally,
    // so this should always hold; we verify it anyway because a missing projection is
    // exactly the failure that reads as "consented" in the table and darkens the
    // plane. Read-back through the SAME projection edge resolves the send-set from.
    // THE PROJECTION ITSELF, not the routable-node view of it.
    //
    // This called `replication_peers_from_consent`, which is the projection PLUS
    // a person→node resolution: a PERSON subject is replaced by the nodes bound
    // to them. So verifying a person's grant against it asked "does this person
    // appear in a list of nodes", which they never can — and the failure was
    // reported as "the consent_peer_set projection did not take", sending the
    // reader to a projection that was in fact perfectly correct.
    //
    // One name answering two questions: the consent SUBJECTS, and the nodes we
    // would dial. Edge reads the subjects here (`list_consent_peers`, then its
    // own `send_set.contains(peer) || owned_nodes.contains(peer)`), so the
    // subjects are what this must read back.
    //
    // It bit exactly where it hurts most: the owner-key admit between two mesh
    // nodes names the peer's OWNER, and an owner is a person, so the step that
    // teaches one node about another's owner failed 500 every time — and the
    // harness fell back to a test-only admit that hid it.
    match st
        .engine
        .federation_directory()
        .list_consent_peers(&node_key_id)
        .await
    {
        Ok(peers) if peers.iter().any(|p| p == &key_id) => {
            tracing::warn!(
                peer = %key_id,
                grant = %consent.attestation_id,
                freshly_emitted = consent.freshly_emitted,
                "TEST-ANCHOR: canonical RECIPROCAL consent:replication VERIFIED in the \
                 list_consent_peers projection (CIRISEdge#396 item 1) — the peer is now in this \
                 node's attestation send-set, so its leg-B delegates_to(root→self, infra:serve) \
                 candidate can cross (prefix self:delegates_to: only; no trace: promotion)"
            );
        }
        Ok(_) => {
            // The grant emitted but the projection does NOT list the peer — the
            // silent-false class made loud. Fail the admit so the harness sees it.
            tracing::error!(
                peer = %key_id,
                grant = %consent.attestation_id,
                "TEST-ANCHOR: reciprocal consent:replication row emitted but the peer is ABSENT \
                 from list_consent_peers(self) — the consent_peer_set projection did not take; \
                 edge will still withhold the plane (CIRISEdge#425 silent-false)"
            );
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "reciprocal consent grant {} for {key_id} is not in the list_consent_peers \
                     projection — plane would stay dark",
                    consent.attestation_id
                ),
            );
        }
        Err(e) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!("reciprocal consent: verify list_consent_peers projection: {e}"),
            )
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "admitted": key_id,
            "blessed": true,
            "conflict": conflict,
            "reciprocal_consent": consent.attestation_id,
            "consent_freshly_emitted": consent.freshly_emitted,
            "consent_projection_verified": true,
            // `record` preserved on a fresh admit (harness compat); null on a
            // conflict re-admit, where the stored row is the authority.
            "record": if conflict { serde_json::Value::Null } else { blessed_json },
        })),
    )
        .into_response()
}

/// The federation-peers read router.
///
/// **It takes no key id** (CIRISServer#372 Level 2): the node's own derived
/// federation `key_id` (the one excluded from the listing) is resolved from the
/// engine at request time — see [`self_key_id`].
pub fn router(engine: Arc<Engine>) -> Router {
    let state = PeersState { engine };
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
