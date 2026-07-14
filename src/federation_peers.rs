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
//!   - `canonical`  ← the `identity_type` set contains `canonical` (the
//!     authoritative `admission::is_canonical` predicate — earned via
//!     anchor-scrub, not guessed from role/key_id).
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
    /// The ML-DSA-65 half (present on a hybrid-complete row; `None` on a legacy
    /// bookmark). Projected so the accord admit-node card can auto-fill BOTH of a
    /// selected owned node's pubkeys from the local directory — no manual paste.
    #[serde(skip_serializing_if = "Option::is_none")]
    pubkey_ml_dsa_65_base64: Option<String>,
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

fn to_peer(rec: KeyRecord) -> LocalPeerState {
    let canonical = is_canonical(&rec);
    LocalPeerState {
        key_id: rec.key_id,
        pubkey_ed25519_base64: rec.pubkey_ed25519_base64,
        pubkey_ml_dsa_65_base64: rec.pubkey_ml_dsa_65_base64,
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
