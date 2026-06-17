//! ROOT-user bootstrap + first-time-setup — the founder-becomes-SYSTEM_ADMIN flow
//! (CIRISServer#19).
//!
//! A faithful port of the agent's three-part ROOT story onto the `wa_cert`
//! substrate:
//!
//! 1. **Baked trust-anchor** — `bootstrap_if_needed` ([`service.py:bootstrap_if_needed`])
//!    loads a baked ROOT public-key seed on first boot when no ROOT WA exists and
//!    stores it as the federation root-of-trust. The PRIVATE key is held OFFLINE by
//!    the founder; the seed carries only the public anchor (the agent's
//!    `seed/root_pub.json`). It then ensures a SYSTEM WA exists as a CHILD of root
//!    (the agent's `_create_system_wa_certificate(root.wa_id)`).
//!
//! 2. **Auto-mint** — `auto_mint_root_if_needed` ([`routes/auth.py:_auto_mint_system_admin_if_needed`]):
//!    when an admin-eligible principal authenticates and holds no ROOT WaCert, mint
//!    it as a ROOT WaCert (the agent's `mint_wise_authority(role=ROOT)`), so the
//!    founder's identity resolves to `UserRole::SystemAdmin`.
//!
//! 3. **First-run claim** — `POST /v1/setup/root`: the literal first-time-setup
//!    flow for a FRESH node with NO baked seed. The first identity to present a
//!    valid `x-ciris-*` signature claims ROOT; once a ROOT exists the route is
//!    closed (409). This is the only path that needs no offline private key — the
//!    founder claims the node they just stood up.
//!
//! Why this makes `POST /v1/federation/peering` reachable: that route is gated by
//! [`federation_admin::require_owner`] on `UserRole::SystemAdmin` + `FullAccess`.
//! `WaRole::Root → UserRole::SystemAdmin` ([`roles::UserRole::from_wa_role`]), so
//! any of the three paths above gives the founder a ROOT WaCert whose session
//! resolves to the owner role — closing the owner-claim gap that blocked peering.
//!
//! ## wa_cert vs the agent's WACertificate
//!
//! The persist `WaCert` row CAN express everything this port needs: `role: Root`,
//! `parent_wa_id` + `parent_signature` (so the SYSTEM WA really is child-of-root),
//! `scopes: ["*"]`, `token_type: standard`, `active`. The one shape difference is
//! cosmetic: the agent's `root_pub.json` carries `scopes_json` (a JSON STRING) and
//! `active: 1` (an INT); persist's `WaCert` carries `scopes` (a JSON VALUE) and
//! `active: bool`. [`RootSeed`] deserializes the agent's exact on-disk shape and
//! converts, so an operator can drop the agent's `seed/root_pub.json` in verbatim.

use std::path::Path;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::prelude::{Engine, HybridPolicy};
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};
use serde::{Deserialize, Serialize};

use super::store;
use super::verify::{self, VerifyError};

/// Env: a filesystem path to a `root_pub.json`-shaped seed (the agent's shape).
pub const ENV_SEED_PATH: &str = "CIRIS_ROOT_SEED_PATH";
/// Env: the ROOT public key (base64/base64url Ed25519) — the seed-less inline form.
pub const ENV_ROOT_PUBKEY: &str = "CIRIS_ROOT_PUBKEY";
/// Env: the ROOT `wa_id` paired with [`ENV_ROOT_PUBKEY`].
pub const ENV_ROOT_WA_ID: &str = "CIRIS_ROOT_WA_ID";
/// Env: the ROOT identity `key_id` an auto-mint binds to (the founder's federation key).
pub const ENV_ROOT_KEY_ID: &str = "CIRIS_ROOT_KEY_ID";
/// Env: a comma-separated allowlist of admin-eligible `key_id`s (auto-mint gate).
pub const ENV_ADMIN_KEY_IDS: &str = "CIRIS_ADMIN_KEY_IDS";

/// The agent's `seed/root_pub.json` on-disk shape. Field-compatible with the
/// agent so its seed file drops in verbatim:
/// `scopes_json` is a JSON STRING (`"[\"*\"]"`), `active` is `0|1`, `created` is an
/// RFC-3339 instant (trailing `Z` accepted). All but `wa_id`/`name`/`role`/`pubkey`
/// are optional with agent-faithful defaults.
#[derive(Debug, Clone, Deserialize)]
pub struct RootSeed {
    /// The ROOT WA identifier (e.g. `wa-2025-06-14-ROOT00`).
    pub wa_id: String,
    /// Human-readable name (the agent bakes `"ciris_root"`).
    pub name: String,
    /// Role token — MUST be `root` for a trust anchor (rejected otherwise).
    #[serde(default = "default_role_token")]
    pub role: String,
    /// Base64/base64url Ed25519 public key — the offline-held founder anchor.
    pub pubkey: String,
    /// JWT kid (the agent bakes `"wa-jwt-root00"`).
    #[serde(default)]
    pub jwt_kid: Option<String>,
    /// Scopes as a JSON STRING (`"[\"*\"]"`) — the agent's `_json` column shape.
    #[serde(default)]
    pub scopes_json: Option<String>,
    /// RFC-3339 creation instant (`Z` or `+00:00`). Defaults to now if absent.
    #[serde(default)]
    pub created: Option<String>,
    /// Active flag as an INT (`0|1`) — the agent's SQLite shape. Defaults to active.
    #[serde(default = "default_active_int")]
    pub active: i64,
    /// Token-type token. The agent bakes `"standard"`.
    #[serde(default)]
    pub token_type: Option<String>,
}

fn default_role_token() -> String {
    "root".to_string()
}
fn default_active_int() -> i64 {
    1
}

/// How a bootstrap attempt resolved (for logging + the test assertions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapOutcome {
    /// A ROOT WaCert already existed — no-op (idempotent re-run).
    AlreadyBootstrapped,
    /// A baked seed was loaded and a ROOT WaCert was stored.
    SeededRoot,
    /// No ROOT and no seed configured — first-run root-claim is available.
    NoSeedAvailable,
}

/// Errors a bootstrap can surface (kept distinct from a clean no-op).
#[derive(Debug)]
pub enum BootstrapError {
    /// The seed file could not be read.
    Io(std::io::Error),
    /// The seed JSON was malformed.
    Parse(serde_json::Error),
    /// The seed declared a non-root role (a trust anchor MUST be root).
    NotRoot(String),
    /// A substrate store call failed.
    Store(store::StoreError),
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootstrapError::Io(e) => write!(f, "read root seed: {e}"),
            BootstrapError::Parse(e) => write!(f, "parse root seed: {e}"),
            BootstrapError::NotRoot(r) => write!(f, "root seed declares role {r:?}, not \"root\""),
            BootstrapError::Store(e) => write!(f, "store: {e}"),
        }
    }
}
impl std::error::Error for BootstrapError {}

impl From<store::StoreError> for BootstrapError {
    fn from(e: store::StoreError) -> Self {
        BootstrapError::Store(e)
    }
}

/// Parse `scopes_json` (a JSON STRING) into a JSON array, defaulting to `["*"]`
/// (the agent's root scope: full authority). A malformed string falls back to
/// `["*"]` rather than failing the trust-anchor load.
fn scopes_value(scopes_json: Option<&str>) -> serde_json::Value {
    match scopes_json {
        Some(s) => serde_json::from_str::<serde_json::Value>(s)
            .ok()
            .filter(|v| v.is_array())
            .unwrap_or_else(|| serde_json::json!(["*"])),
        None => serde_json::json!(["*"]),
    }
}

/// Parse the agent's `created` string (trailing `Z` → `+00:00`, as the agent
/// rewrites it) into a UTC instant. Falls back to `now` if absent/unparseable.
fn parse_created(created: Option<&str>) -> chrono::DateTime<chrono::Utc> {
    let Some(raw) = created else {
        return chrono::Utc::now();
    };
    let normalized = if let Some(stripped) = raw.strip_suffix('Z') {
        format!("{stripped}+00:00")
    } else {
        raw.to_string()
    };
    chrono::DateTime::parse_from_rfc3339(&normalized)
        .map(|t| t.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now())
}

/// Build a ROOT [`WaCert`] from a parsed seed (the trust-anchor row). `role` is
/// pinned to [`WaRole::Root`]; `token_type` to [`TokenType::Standard`]; `scopes`
/// to the seed's set (default `["*"]`). The pubkey is stored verbatim — it is the
/// founder's OFFLINE-held anchor, never a private key.
fn root_cert_from_seed(seed: &RootSeed) -> Result<WaCert, BootstrapError> {
    if seed.role != "root" {
        return Err(BootstrapError::NotRoot(seed.role.clone()));
    }
    let created = parse_created(seed.created.as_deref());
    Ok(WaCert {
        wa_id: seed.wa_id.clone(),
        name: seed.name.clone(),
        role: WaRole::Root,
        pubkey: seed.pubkey.clone(),
        jwt_kid: seed
            .jwt_kid
            .clone()
            .unwrap_or_else(|| format!("{}-jwt", seed.wa_id)),
        password_hash: None,
        api_key_hash: None,
        oauth_provider: None,
        oauth_external_id: None,
        oauth_links: None,
        veilid_id: None,
        auto_minted: false,
        parent_wa_id: None,
        parent_signature: None,
        scopes: scopes_value(seed.scopes_json.as_deref()),
        custom_permissions: None,
        adapter_id: None,
        adapter_name: None,
        adapter_metadata: None,
        token_type: TokenType::Standard,
        created,
        last_login: None,
        active: seed.active != 0,
    })
}

/// Resolve a [`RootSeed`] from the configured env surface, mirroring the agent's
/// "load the baked seed" step:
///
/// 1. `CIRIS_ROOT_SEED_PATH` → a `root_pub.json`-shaped file (agent verbatim);
/// 2. else `CIRIS_ROOT_PUBKEY` + `CIRIS_ROOT_WA_ID` → an inline anchor;
/// 3. else `None` (no seed; first-run root-claim is available).
fn load_seed_from_env() -> Result<Option<RootSeed>, BootstrapError> {
    if let Ok(path) = std::env::var(ENV_SEED_PATH) {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return load_seed_file(Path::new(trimmed)).map(Some);
        }
    }
    if let (Ok(pubkey), Ok(wa_id)) = (
        std::env::var(ENV_ROOT_PUBKEY),
        std::env::var(ENV_ROOT_WA_ID),
    ) {
        if !pubkey.trim().is_empty() && !wa_id.trim().is_empty() {
            return Ok(Some(RootSeed {
                wa_id: wa_id.trim().to_string(),
                name: "ciris_root".to_string(),
                role: "root".to_string(),
                pubkey: pubkey.trim().to_string(),
                jwt_kid: None,
                scopes_json: None,
                created: None,
                active: 1,
                token_type: None,
            }));
        }
    }
    Ok(None)
}

/// Read + parse a `root_pub.json`-shaped seed file (the agent's shape).
pub fn load_seed_file(path: &Path) -> Result<RootSeed, BootstrapError> {
    let content = std::fs::read_to_string(path).map_err(BootstrapError::Io)?;
    serde_json::from_str(&content).map_err(BootstrapError::Parse)
}

/// **`bootstrap_if_needed`** — the startup ROOT bootstrap (port of
/// `service.py:bootstrap_if_needed`).
///
/// If a ROOT WaCert already exists, this is a no-op ([`BootstrapOutcome::AlreadyBootstrapped`])
/// — idempotent across reboots, exactly like the agent's `has_root` short-circuit.
/// Otherwise it resolves a seed from the env surface ([`load_seed_from_env`]) and,
/// if present, stores it as the ROOT trust anchor + ensures a SYSTEM WA exists as a
/// CHILD of root. With no seed it logs and returns [`BootstrapOutcome::NoSeedAvailable`]
/// (no panic) — the first-run `POST /v1/setup/root` claim remains available.
pub async fn bootstrap_if_needed(engine: &Engine) -> Result<BootstrapOutcome, BootstrapError> {
    // `list_by_role` returns only ACTIVE certs — mirrors the agent's `has_root`.
    let existing = store::list_by_role(engine, WaRole::Root, 1).await?;
    if !existing.is_empty() {
        tracing::debug!("root WA already present — bootstrap is a no-op (idempotent)");
        return Ok(BootstrapOutcome::AlreadyBootstrapped);
    }

    let Some(seed) = load_seed_from_env()? else {
        tracing::info!(
            "no root seed ({ENV_SEED_PATH} / {ENV_ROOT_PUBKEY}+{ENV_ROOT_WA_ID}); \
             first-run root-claim available at POST /v1/setup/root"
        );
        return Ok(BootstrapOutcome::NoSeedAvailable);
    };

    let cert = root_cert_from_seed(&seed)?;
    let root_wa_id = cert.wa_id.clone();
    store::upsert(engine, cert).await?;
    tracing::info!(wa_id = %root_wa_id, "loaded baked ROOT WA trust anchor (offline-held private key)");

    // Ensure a SYSTEM WA exists as a CHILD of root (the agent's
    // `_create_system_wa_certificate(root.wa_id)`). The substrate CAN express the
    // child-of-root link via `parent_wa_id` (self-FK) + `parent_signature`.
    ensure_system_wa(engine, &root_wa_id).await?;

    Ok(BootstrapOutcome::SeededRoot)
}

/// Ensure the SYSTEM WA exists as a child of `root_wa_id` (port of
/// `_create_system_wa_certificate`). Idempotent: a present SYSTEM WA is a no-op.
///
/// Faithfulness note: the agent's `_create_system_wa_certificate` MINTS a fresh
/// keypair for the system WA and signs the parent link with the system key. Here
/// the fabric stores the parent linkage (`parent_wa_id = root`) but does NOT mint
/// a signing keypair — the substrate row carries no private material and the
/// fabric is the single token issuer (sessions, not per-WA JWTs), so a system
/// signing key has no consumer on this side yet. The CHILD-OF-ROOT relationship
/// IS expressed; the keypair-mint is the one piece deferred (it lights up when the
/// node slice that signs as SYSTEM lands). The SYSTEM WA rides `WaRole::Authority`
/// (it is not the root-of-trust itself).
async fn ensure_system_wa(engine: &Engine, root_wa_id: &str) -> Result<(), BootstrapError> {
    let system_wa_id = "wa-system-00";
    if store::get(engine, system_wa_id).await?.is_some() {
        return Ok(());
    }
    let now = chrono::Utc::now();
    let cert = WaCert {
        wa_id: system_wa_id.to_string(),
        name: "ciris_system".to_string(),
        role: WaRole::Authority,
        // The substrate requires a non-empty pubkey. No keypair is minted on this
        // side (see the doc comment) — a deterministic placeholder marks the row as
        // keyless (the fabric is the single token issuer; this WA has no per-WA JWT).
        pubkey: format!("system-of:{root_wa_id}"),
        jwt_kid: "wa-jwt-system00".to_string(),
        password_hash: None,
        api_key_hash: None,
        oauth_provider: None,
        oauth_external_id: None,
        oauth_links: None,
        veilid_id: None,
        auto_minted: true,
        parent_wa_id: Some(root_wa_id.to_string()),
        // No keypair is minted on this side (see the doc comment) → no signature.
        parent_signature: None,
        scopes: serde_json::json!(["*"]),
        custom_permissions: None,
        adapter_id: None,
        adapter_name: None,
        adapter_metadata: None,
        token_type: TokenType::Standard,
        created: now,
        last_login: None,
        active: true,
    };
    store::upsert(engine, cert).await?;
    tracing::info!(parent = %root_wa_id, "ensured SYSTEM WA as child of root");
    Ok(())
}

/// True if `key_id` is admin-eligible: it matches the configured root identity
/// (`CIRIS_ROOT_KEY_ID`) OR appears in the `CIRIS_ADMIN_KEY_IDS` allowlist
/// (comma-separated). This is the fabric analogue of the agent's
/// `oauth_user.role == SYSTEM_ADMIN` eligibility check — on the federation side an
/// identity's eligibility is operator-declared, not OAuth-email-derived.
pub fn is_admin_eligible(key_id: &str) -> bool {
    if let Ok(root) = std::env::var(ENV_ROOT_KEY_ID) {
        if root.trim() == key_id {
            return true;
        }
    }
    if let Ok(list) = std::env::var(ENV_ADMIN_KEY_IDS) {
        return list
            .split(',')
            .map(str::trim)
            .any(|k| !k.is_empty() && k == key_id);
    }
    false
}

/// **`auto_mint_root_if_needed`** — port of `routes/auth.py:_auto_mint_system_admin_if_needed`.
///
/// When `is_admin_eligible` and the identity holds NO active ROOT WaCert, mint
/// (upsert) a ROOT WaCert bound to `identity_key_id` so the founder's identity
/// resolves to `UserRole::SystemAdmin` (the agent's `mint_wise_authority(role=ROOT)`).
/// Idempotent: an existing ROOT bound to this identity is a no-op. Returns `true`
/// iff a fresh ROOT WaCert was minted. Never panics — a store failure is surfaced
/// as `Err` and the caller (a login path) logs + continues (the agent's
/// `except: warn(...); user can mint manually`).
pub async fn auto_mint_root_if_needed(
    engine: &Engine,
    identity_key_id: &str,
    is_admin: bool,
) -> Result<bool, store::StoreError> {
    if !is_admin {
        return Ok(false);
    }
    let wa_id = root_wa_id_for_identity(identity_key_id);
    // Already minted (active ROOT bound to this identity) ⇒ no-op.
    if let Some(existing) = store::get(engine, &wa_id).await? {
        if existing.role == WaRole::Root && existing.active {
            return Ok(false);
        }
    }
    let now = chrono::Utc::now();
    let cert = WaCert {
        wa_id: wa_id.clone(),
        name: format!("root:{identity_key_id}"),
        role: WaRole::Root,
        // The founder's federation key IS the pubkey/anchor for this ROOT cert.
        pubkey: identity_key_id.to_string(),
        jwt_kid: format!("{wa_id}-jwt"),
        password_hash: None,
        api_key_hash: None,
        oauth_provider: None,
        oauth_external_id: None,
        oauth_links: None,
        veilid_id: None,
        auto_minted: true,
        parent_wa_id: None,
        parent_signature: None,
        scopes: serde_json::json!(["*"]),
        custom_permissions: None,
        adapter_id: None,
        adapter_name: None,
        adapter_metadata: None,
        token_type: TokenType::Standard,
        created: now,
        last_login: Some(now),
        active: true,
    };
    store::upsert(engine, cert).await?;
    tracing::info!(
        identity = %identity_key_id,
        wa_id = %wa_id,
        "auto-minted admin-eligible identity as ROOT WaCert (founder → SYSTEM_ADMIN)"
    );
    Ok(true)
}

/// The deterministic ROOT `wa_id` an identity's auto-mint / first-run claim binds
/// to. Deterministic so the mint is idempotent across logins (re-deriving the same
/// id) — the agent keys its mint on `oauth_user.user_id` the same way.
fn root_wa_id_for_identity(identity_key_id: &str) -> String {
    format!("wa-root-{identity_key_id}")
}

// ─── POST /v1/setup/root — the first-run root-claim route ────────────────────

#[derive(Clone)]
struct SetupState {
    engine: Arc<Engine>,
    policy: HybridPolicy,
    /// THIS node's federation `key_id` — the identity the supplied NodeCode must
    /// pin (the out-of-band bootstrap handle, CEG §0.10).
    node_key_id: String,
    /// THIS node's raw Ed25519 pubkey (base64) — the second half of the NodeCode
    /// identity pin.
    node_pubkey_ed25519_base64: String,
}

/// The first-run ROOT-claim request body — the NodeCode identity-pin (CEG §0.10).
///
/// The founder MUST prove they reached the INTENDED node (the one whose NodeCode
/// they hold out-of-band) by supplying that node's identity. Either form is
/// accepted: the full `CIRIS-V1-...` `node_code` string (decoded server-side), OR
/// the decoded `key_id` + `pubkey_ed25519_base64` pair directly. The handler
/// verifies the pin matches THIS node's actual steward identity before admitting
/// the claim — defeating a spoof where the founder is tricked into claiming a
/// different node. The request body is ALSO the signed payload (the existing
/// `x-ciris-*` hybrid signature covers it), so the pin is signature-bound.
#[derive(Debug, Deserialize, Default)]
struct SetupRootRequest {
    /// The node's full `CIRIS-V1-...` NodeCode string (dashes/whitespace/case
    /// tolerated). When present it is decoded and takes precedence.
    #[serde(default)]
    node_code: Option<String>,
    /// The node's federation `key_id` (the decoded pin half), when not supplying
    /// the full `node_code`.
    #[serde(default)]
    key_id: Option<String>,
    /// The node's raw Ed25519 pubkey (base64) — the other decoded pin half.
    #[serde(default)]
    pubkey_ed25519_base64: Option<String>,
}

#[derive(Debug, Serialize)]
struct SetupRootResponse {
    /// The ROOT `wa_id` that was claimed.
    wa_id: String,
    /// The claiming federation identity (`key_id`).
    identity_key_id: String,
    /// The bridged API role (`SYSTEM_ADMIN`).
    role: String,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// Verify the NodeCode identity-pin in the signed claim body matches THIS node's
/// steward identity (CEG §0.10). Accepts either the full `node_code` string or the
/// decoded `key_id` + `pubkey_ed25519_base64` pair. Returns `None` on a match;
/// `Some(response)` (a `400` to short-circuit) when the pin is absent,
/// undecodable, or names a different node.
fn verify_node_code_pin(st: &SetupState, body: &[u8]) -> Option<Response> {
    let req: SetupRootRequest = if body.is_empty() {
        SetupRootRequest::default()
    } else {
        match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => {
                return Some(err(
                    StatusCode::BAD_REQUEST,
                    format!("setup/root body is not valid JSON: {e}"),
                ))
            }
        }
    };

    // Resolve the (key_id, pubkey) pin from the request: prefer the full NodeCode.
    let (claim_key_id, claim_pubkey) = if let Some(code) = req.node_code.as_deref() {
        match crate::nodecode::decode(code) {
            Ok(nc) => (nc.key_id, nc.pubkey_ed25519_base64),
            Err(e) => {
                return Some(err(
                    StatusCode::BAD_REQUEST,
                    format!("supplied NodeCode is undecodable: {e}"),
                ))
            }
        }
    } else if let (Some(k), Some(p)) = (req.key_id.as_deref(), req.pubkey_ed25519_base64.as_deref())
    {
        (k.to_string(), p.to_string())
    } else {
        return Some(err(
            StatusCode::BAD_REQUEST,
            "first-run ROOT claim must pin this node's identity: supply `node_code` \
             (CIRIS-V1-...) or `key_id` + `pubkey_ed25519_base64`",
        ));
    };

    if claim_key_id != st.node_key_id || claim_pubkey != st.node_pubkey_ed25519_base64 {
        return Some(err(
            StatusCode::BAD_REQUEST,
            "supplied NodeCode does not match this node's identity — \
             you may have reached the wrong node",
        ));
    }
    None
}

/// `POST /v1/setup/root` — first-time-setup ROOT claim for a FRESH node with no
/// baked seed.
///
/// # Security model — three independent gates
///
/// 1. **First-run only** — allowed ONLY when no ROOT WaCert exists; after a ROOT
///    exists the route returns `409 Conflict` (no silent re-claim).
/// 2. **Signature** — the caller proves control of a federation identity via the
///    `x-ciris-*` hybrid signature over the request body (the same verifier
///    self-login uses, default [`HybridPolicy::Strict`]); that identity is bound
///    as the ROOT WaCert. This is the CLAIM AUTHORITY.
/// 3. **NodeCode identity-pin (CEG §0.10)** — the claim MUST carry THIS node's
///    own NodeCode (or its decoded `key_id` + `pubkey_ed25519_base64`), and the
///    handler verifies it matches the node's actual steward identity before
///    admitting the claim. The NodeCode is the OUT-OF-BAND bootstrap handle the
///    operator reads off the node and hands to the founder's app; pinning it
///    proves the founder reached the INTENDED node — not a spoof that intercepted
///    the claim. The pin rides inside the signed body, so it is signature-bound.
///
/// First-run + signature is the claim authority; the NodeCode pin is which node
/// is being claimed. This is the path that needs NO offline private key: the
/// founder claims the node they just stood up (and proved they reached),
/// becoming `SYSTEM_ADMIN`.
async fn setup_root(
    State(st): State<SetupState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // (1) Closed once a ROOT exists — checked FIRST so an unsigned probe against an
    //     already-claimed node still gets the clear 409 (no re-claim).
    match store::list_by_role(&st.engine, WaRole::Root, 1).await {
        Ok(v) if !v.is_empty() => {
            return err(
                StatusCode::CONFLICT,
                "root already claimed; first-run setup is closed",
            )
        }
        Ok(_) => {}
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    }

    // (2) Verify the claimant controls a federation identity (hybrid signature).
    let caller = match verify::verify_request(&st.engine, &headers, &body, st.policy).await {
        Ok(c) => c,
        Err(VerifyError::MissingHeader(h)) => {
            return err(StatusCode::UNAUTHORIZED, format!("missing {h}"))
        }
        Err(VerifyError::NoDirectory) => {
            return err(StatusCode::SERVICE_UNAVAILABLE, "no federation directory")
        }
        Err(VerifyError::SignatureInvalid(e)) => {
            return err(
                StatusCode::UNAUTHORIZED,
                format!("signature verification failed: {e}"),
            )
        }
    };

    // (2b) NodeCode identity-pin (CEG §0.10): the claim must carry THIS node's own
    //      identity (the out-of-band bootstrap handle), proving the founder reached
    //      the intended node. The pin rides inside the signed body, so it is
    //      signature-bound. A claim with no pin, an undecodable NodeCode, or a pin
    //      that names a DIFFERENT node is rejected (400) — closing the spoof where
    //      a founder is tricked into claiming an attacker's node.
    if let Some(resp) = verify_node_code_pin(&st, &body) {
        return resp;
    }

    // (3) Bind this identity as ROOT (race-narrowed: re-check + claim).
    if let Ok(v) = store::list_by_role(&st.engine, WaRole::Root, 1).await {
        if !v.is_empty() {
            return err(
                StatusCode::CONFLICT,
                "root already claimed; first-run setup is closed",
            );
        }
    }
    let wa_id = root_wa_id_for_identity(&caller.key_id);
    let now = chrono::Utc::now();
    let cert = WaCert {
        wa_id: wa_id.clone(),
        name: format!("root:{}", caller.key_id),
        role: WaRole::Root,
        pubkey: caller.key_id.clone(),
        jwt_kid: format!("{wa_id}-jwt"),
        password_hash: None,
        api_key_hash: None,
        oauth_provider: None,
        oauth_external_id: None,
        oauth_links: None,
        veilid_id: None,
        auto_minted: false,
        parent_wa_id: None,
        parent_signature: None,
        scopes: serde_json::json!(["*"]),
        custom_permissions: None,
        adapter_id: None,
        adapter_name: None,
        adapter_metadata: None,
        token_type: TokenType::Standard,
        created: now,
        last_login: Some(now),
        active: true,
    };
    match store::upsert(&st.engine, cert).await {
        Ok(()) => {
            tracing::info!(
                identity = %caller.key_id,
                wa_id = %wa_id,
                "first-run ROOT claim: identity bound as ROOT (founder → SYSTEM_ADMIN)"
            );
            (
                StatusCode::CREATED,
                Json(SetupRootResponse {
                    wa_id,
                    identity_key_id: caller.key_id,
                    role: super::roles::UserRole::SystemAdmin.as_str().to_string(),
                }),
            )
                .into_response()
        }
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    }
}

/// The first-run setup router — merge onto the read-API listener beside the other
/// auth routers. Federation-signed; default [`HybridPolicy::Strict`].
///
/// `node_key_id` + `node_pubkey_ed25519_base64` are THIS node's steward identity
/// (the same `key_id` + raw Ed25519 pubkey carried on its NodeCode, CEG §0.10);
/// the first-run claim is identity-pinned to them (see [`setup_root`]).
pub fn router(
    engine: Arc<Engine>,
    policy: HybridPolicy,
    node_key_id: String,
    node_pubkey_ed25519_base64: String,
) -> Router {
    Router::new()
        .route("/v1/setup/root", axum::routing::post(setup_root))
        .with_state(SetupState {
            engine,
            policy,
            node_key_id,
            node_pubkey_ed25519_base64,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_seed_shape_deserializes() {
        // The agent's seed/root_pub.json verbatim.
        let json = r#"{
            "wa_id": "wa-2025-06-14-ROOT00",
            "name": "ciris_root",
            "role": "root",
            "pubkey": "QK0ZQ9FhWKMtP8YL3wXU_n0cmqYyV3HoDi-AIJgSHi0",
            "jwt_kid": "wa-jwt-root00",
            "scopes_json": "[\"*\"]",
            "created": "2025-06-16T20:55:42.680865Z",
            "active": 1,
            "token_type": "standard"
        }"#;
        let seed: RootSeed = serde_json::from_str(json).unwrap();
        assert_eq!(seed.wa_id, "wa-2025-06-14-ROOT00");
        assert_eq!(seed.role, "root");
        assert_eq!(seed.active, 1);
        let cert = root_cert_from_seed(&seed).unwrap();
        assert_eq!(cert.role, WaRole::Root);
        assert_eq!(cert.token_type, TokenType::Standard);
        assert!(cert.active);
        assert_eq!(cert.scopes, serde_json::json!(["*"]));
        // Trailing-Z timestamp parses (the agent rewrites Z → +00:00).
        assert_eq!(cert.created.format("%Y-%m-%d").to_string(), "2025-06-16");
    }

    #[test]
    fn non_root_seed_is_rejected() {
        let seed = RootSeed {
            wa_id: "wa-x".into(),
            name: "x".into(),
            role: "authority".into(),
            pubkey: "pk".into(),
            jwt_kid: None,
            scopes_json: None,
            created: None,
            active: 1,
            token_type: None,
        };
        assert!(matches!(
            root_cert_from_seed(&seed),
            Err(BootstrapError::NotRoot(_))
        ));
    }

    #[test]
    fn scopes_default_to_star() {
        assert_eq!(scopes_value(None), serde_json::json!(["*"]));
        assert_eq!(scopes_value(Some("[\"a\"]")), serde_json::json!(["a"]));
        // Malformed string falls back to ["*"] rather than failing the load.
        assert_eq!(scopes_value(Some("not json")), serde_json::json!(["*"]));
    }

    #[test]
    fn root_wa_id_is_deterministic_per_identity() {
        assert_eq!(
            root_wa_id_for_identity("ciris-founder"),
            root_wa_id_for_identity("ciris-founder")
        );
        assert_ne!(root_wa_id_for_identity("a"), root_wa_id_for_identity("b"));
    }
}
