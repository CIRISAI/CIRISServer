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
//!    flow for a FRESH node with NO baked seed, claimed by a FRESH founder whose
//!    key is NOT yet in this node's `federation_keys` directory. The founder
//!    presents their OWN hybrid pubkeys in the body and proves control of them by
//!    hybrid-signing the body (self-attested proof-of-possession, verified against
//!    the SUPPLIED pubkeys under `Strict` — NOT the directory). The handler then
//!    registers the founder's key (admitting it thereafter) and binds ROOT to it.
//!    The claim is NodeCode-pinned (the founder proves they reached the intended
//!    node) and first-run-only — once a ROOT exists the route is closed (409). This
//!    is the only path that needs no offline private key AND no prior directory
//!    registration — the founder claims the node they just stood up.
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
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{verify_hybrid, Engine, HybridPolicy};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::store;
use super::verify;

/// Env: an OPTIONAL filesystem path the one-time claim PIN is ALSO written to on a
/// fresh (unclaimed) boot, for headless ops that cannot scrape the console log. The
/// default is console/log ONLY — the PIN is the operator-presence secret and is
/// NEVER served over any HTTP route. When set, the PIN file is written `0600` and
/// the operator is responsible for removing it after the claim.
pub const ENV_CLAIM_PIN_FILE: &str = "CIRIS_CLAIM_PIN_FILE";

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

// ─── One-time CLAIM PIN — the operator-presence secret (console-only) ─────────

/// Crockford base32 alphabet (excludes I, L, O, U to stay operator-typable —
/// no visual confusion with 1/0 and no accidental words).
const CLAIM_PIN_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Number of PIN characters (rendered as two dash-separated groups of 4).
const CLAIM_PIN_LEN: usize = 8;

/// Generate a cryptographically-random, operator-typable one-time claim PIN —
/// [`CLAIM_PIN_LEN`] Crockford-base32 chars rendered `XXXX-XXXX`.
///
/// This is the **operator-presence secret** that gates the first-run ownership
/// claim. It closes the hole that the NodeCode alone is a PUBLIC, freely-shareable
/// handle (served by `GET /v1/federation/node-code`): knowing the NodeCode is not
/// enough — the claimant must ALSO present this PIN, which is printed ONLY to the
/// node's console/log on a fresh boot and NEVER exposed via any HTTP route.
///
/// Sourced from `getrandom` (the OS CSPRNG). Rejection-free: the alphabet is
/// exactly 32 chars, so each random byte maps to one symbol via a 5-bit mask with
/// zero modulo bias.
pub fn generate_claim_pin() -> String {
    let mut bytes = [0u8; CLAIM_PIN_LEN];
    getrandom::fill(&mut bytes).expect("OS CSPRNG (getrandom) for the one-time claim PIN");
    let mut chars: Vec<char> = bytes
        .iter()
        .map(|b| CLAIM_PIN_ALPHABET[(b & 0x1F) as usize] as char)
        .collect();
    // Render as two dash-separated groups of 4 (XXXX-XXXX) for typability.
    chars.insert(4, '-');
    chars.into_iter().collect()
}

/// Print the unmissable "OWNERSHIP UNCLAIMED" banner at startup — the NodeCode (a
/// PUBLIC handle) PLUS the one-time claim PIN (the console-only operator-presence
/// secret). Optionally ALSO writes the PIN to [`ENV_CLAIM_PIN_FILE`] (`0600`) for
/// headless ops. The PIN is NEVER served over HTTP.
pub fn announce_ownership_unclaimed(node_code: &str, claim_pin: &str) {
    tracing::warn!(
        "\n\
         ╔══════════════════════════════════════════════════════════════════════╗\n\
         ║  OWNERSHIP UNCLAIMED — this node has no ROOT owner yet.               ║\n\
         ║                                                                      ║\n\
         ║  To claim ownership (POST /v1/setup/root), present BOTH:             ║\n\
         ║                                                                      ║\n\
         ║    NodeCode : {node_code}\n\
         ║    CLAIM PIN: {claim_pin}   (one-time; console-only — NEVER over HTTP)\n\
         ║                                                                      ║\n\
         ║  The NodeCode is a PUBLIC handle (GET /v1/federation/node-code).     ║\n\
         ║  The PIN is the operator-presence secret: it is printed ONLY here    ║\n\
         ║  and is consumed on the first successful claim.                      ║\n\
         ╚══════════════════════════════════════════════════════════════════════╝"
    );

    // Optional headless-ops sink: write the PIN to a 0600 file when configured.
    if let Ok(path) = std::env::var(ENV_CLAIM_PIN_FILE) {
        let path = path.trim();
        if !path.is_empty() {
            match std::fs::write(path, format!("{claim_pin}\n")) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ =
                            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
                    }
                    tracing::info!(pin_file = %path, "one-time claim PIN ALSO written to file (0600; remove after claim)");
                }
                Err(e) => {
                    tracing::warn!(pin_file = %path, error = %e, "could not write claim PIN file (PIN remains available on the console)")
                }
            }
        }
    }
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
    /// The one-time claim PIN minted on a fresh (unclaimed) boot — the
    /// operator-presence secret. `Some(pin)` while unclaimed-and-armed; set to
    /// `None` once a ROOT exists at boot (already claimed → no PIN), or CLEARED on
    /// the first successful claim (consume-once; no replay). Held behind a `Mutex`
    /// so the claim handler can take it. NEVER reachable via any HTTP route.
    claim_pin: Arc<Mutex<Option<String>>>,
}

/// The FRESH founder's self-attested hybrid identity (the claimant's OWN keys).
///
/// A fresh founder's key is NOT yet in this node's `federation_keys` directory, so
/// the claim cannot be verified directory-side. Instead the founder presents their
/// own public keys here and proves control of them by hybrid-signing the request
/// body (proof-of-possession). The handler verifies the `x-ciris-*` signature
/// AGAINST THESE pubkeys (not the directory), then registers this key in
/// `federation_keys` (self-attested admission) so the founder becomes a real
/// federation identity, and binds ROOT to `key_id`.
#[derive(Debug, Deserialize, Clone)]
struct Founder {
    /// The founder's federation `key_id` — the identity ROOT is bound to. The
    /// `x-ciris-signing-key-id` header MUST equal this value.
    key_id: String,
    /// The founder's raw Ed25519 public key (base64-standard, 32 bytes).
    ed25519_pubkey_b64: String,
    /// The founder's raw ML-DSA-65 public key (base64-standard, 1952 bytes).
    ml_dsa_65_pubkey_b64: String,
}

/// The first-run ROOT-claim request body — the NodeCode identity-pin (CEG §0.10)
/// PLUS the self-attested founder identity.
///
/// The founder MUST prove they reached the INTENDED node (the one whose NodeCode
/// they hold out-of-band) by supplying that node's identity. Either form is
/// accepted: the full `CIRIS-V1-...` `node_code` string (decoded server-side), OR
/// the decoded `key_id` + `pubkey_ed25519_base64` pair directly. The handler
/// verifies the pin matches THIS node's actual steward identity before admitting
/// the claim — defeating a spoof where the founder is tricked into claiming a
/// different node. The request body is ALSO the signed payload (the `x-ciris-*`
/// hybrid signature covers it), so both the pin AND the founder pubkeys are
/// signature-bound.
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
    /// The fresh founder's self-attested hybrid identity (the claimant's OWN keys).
    /// REQUIRED: the claim is verified against these pubkeys (proof-of-possession),
    /// NOT the federation directory.
    #[serde(default)]
    founder: Option<Founder>,
    /// The cohort scope the responsible party claims this node under — one of
    /// `self` / `family` / `community` (CC 4.4.3.4.1 cohort scopes). REQUIRED:
    /// it records the membership-standing tier the owner-binding covers. Rides
    /// inside the signed body, so it is signature-bound. Validated against the
    /// closed set; anything else → `400`.
    #[serde(default)]
    cohort_scope: Option<String>,
    /// OPTIONAL explicit infra scope set for the owner-binding (CC 4.4.3.5 —
    /// `infra:*` ONLY). When absent the canonical
    /// [`ownership::OWNER_BINDING_INFRA_SCOPES`] set is used. Any `agency:*` (or
    /// legacy agency) scope here is REJECTED (CC 1.13.5): a node delegation
    /// literally cannot carry agency.
    #[serde(default)]
    infra_scopes: Option<Vec<String>>,
    /// The one-time CLAIM PIN printed to THIS node's console/log on a fresh boot —
    /// the operator-presence secret (CONSOLE-ONLY; never served over HTTP). It is
    /// verified (constant-time) against the boot PIN before ROOT is bound, and
    /// consumed on success. It rides INSIDE the signed body, so it is
    /// signature-bound (it cannot be stripped/swapped without breaking the hybrid
    /// PoP signature). REQUIRED.
    #[serde(default)]
    claim_pin: Option<String>,
}

#[derive(Debug, Serialize)]
struct SetupRootResponse {
    /// The ROOT `wa_id` that was claimed.
    wa_id: String,
    /// The claiming federation identity (`key_id`) — the RESPONSIBLE PARTY (a
    /// `user`-role identity), NOT a bare node.
    identity_key_id: String,
    /// The bridged API role (`SYSTEM_ADMIN`), derived from the owner-binding.
    role: String,
    /// The cohort scope the node was claimed under (`self` / `family` /
    /// `community`).
    cohort_scope: String,
    /// The owner-binding `delegates_to(user → node, infra:*)` attestation id (the
    /// CC 3.2 responsible-party binding that was emitted).
    owner_binding_attestation_id: String,
}

/// The closed set of cohort scopes a node may be claimed under (CC 4.4.3.4.1).
const COHORT_SCOPES: &[&str] = &["self", "family", "community"];

/// Validate the claimed cohort scope against [`COHORT_SCOPES`]. Returns the
/// normalized (trimmed) value, or `Err(response)` (a `400`) when absent/invalid.
/// The error is boxed (`result_large_err`) — an axum `Response` is large and
/// this is the cold/reject path.
fn validate_cohort_scope(req: &SetupRootRequest) -> Result<String, Box<Response>> {
    let Some(raw) = req.cohort_scope.as_deref() else {
        return Err(Box::new(err(
            StatusCode::BAD_REQUEST,
            "first-run ROOT claim must carry `cohort_scope` (one of self|family|community)",
        )));
    };
    let v = raw.trim();
    if COHORT_SCOPES.contains(&v) {
        Ok(v.to_string())
    } else {
        Err(Box::new(err(
            StatusCode::BAD_REQUEST,
            format!("invalid cohort_scope {v:?} — must be one of self|family|community"),
        )))
    }
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// Verify the NodeCode identity-pin in the signed claim body matches THIS node's
/// steward identity (CEG §0.10). Accepts either the full `node_code` string or the
/// decoded `key_id` + `pubkey_ed25519_base64` pair. Returns `None` on a match;
/// `Some(response)` (a `400` to short-circuit) when the pin is absent,
/// undecodable, or names a different node.
fn verify_node_code_pin(st: &SetupState, req: &SetupRootRequest) -> Option<Response> {
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

/// Verify the one-time CLAIM PIN in the signed claim body against the boot PIN
/// held in [`SetupState`], using a CONSTANT-TIME comparison (no early-return on
/// first-byte mismatch, no length-leaking shortcut beyond the unavoidable
/// length-equality flag). Returns `None` on a match; `Some(401)` when the PIN is
/// absent, when no boot PIN is armed (already-claimed / mis-bootstrapped node), or
/// when it does not match. The PIN is the operator-presence secret: it is printed
/// ONLY to the console and is NEVER served over any HTTP route.
fn verify_claim_pin(st: &SetupState, req: &SetupRootRequest) -> Option<Response> {
    // The armed boot PIN. A missing/cleared PIN means the route must not admit a
    // claim (node already claimed at boot, or PIN already consumed) → reject.
    let armed = match st.claim_pin.lock() {
        Ok(g) => g.clone(),
        Err(_) => None,
    };
    let Some(expected) = armed else {
        return Some(err(
            StatusCode::UNAUTHORIZED,
            "this node is not armed for a first-run claim (no one-time PIN) — \
             ownership may already be claimed",
        ));
    };

    let Some(supplied) = req.claim_pin.as_deref() else {
        return Some(err(
            StatusCode::UNAUTHORIZED,
            "first-run ROOT claim must carry `claim_pin` (the one-time PIN printed \
             on this node's console at boot)",
        ));
    };

    // Constant-time equality over the raw bytes. `subtle::ConstantTimeEq` requires
    // equal-length slices to compare byte-by-byte; a length difference is folded in
    // WITHOUT an early return so the path does not short-circuit on first mismatch.
    let a = supplied.as_bytes();
    let b = expected.as_bytes();
    let len_ok = a.len() == b.len();
    // Pad/truncate the supplied bytes to the expected length so `ct_eq` always runs
    // over `expected.len()` bytes (a mismatched length still does full work, then
    // the `len_ok` flag forces the result false).
    let mut padded = vec![0u8; b.len()];
    for (i, slot) in padded.iter_mut().enumerate() {
        *slot = if i < a.len() { a[i] } else { 0 };
    }
    let bytes_eq: bool = padded.ct_eq(b).into();
    if len_ok && bytes_eq {
        return None;
    }
    Some(err(StatusCode::UNAUTHORIZED, "invalid one-time claim PIN"))
}

/// `POST /v1/setup/root` — first-time-setup ROOT claim for a FRESH node with no
/// baked seed.
///
/// # The responsible-party model (CC 4.4.3.5 + CC 3.2 + CC 1.13.5)
///
/// A fabric node is `node`-role and MUST NOT have agency ("infrastructure must
/// not have agency", CC 1.13.5). This claim therefore establishes a RESPONSIBLE
/// PARTY, not an agency partnership:
///
///   - the claimant is the **responsible user** — registered as `identity_type
///     "user"` (CC 3.2: ownership roots in an accountable human);
///   - on success the handler emits the structural owner-binding
///     `delegates_to(user → THIS node, infra:*)`
///     ([`ownership::emit_owner_binding`]) — `infra:*` scopes ONLY;
///   - it records the chosen `cohort_scope` (self|family|community); and
///   - the ROOT WaCert / `SYSTEM_ADMIN` is the *derived* API-role view of that
///     same responsible party.
///
/// Any `agency:*` (or legacy agency) scope in the claim is REJECTED (`400`) — a
/// node delegation literally cannot carry agency (the CC 1.13.5 wire-checkable
/// invariant). The AGENT's joint-agency partnership (`agency:*` +
/// `consent:partnership_grant/accept`) stays in the agent, NOT here.
///
/// # Security model — four independent gates
///
/// 0. **One-time CLAIM PIN (operator-presence)** — the claim MUST carry the
///    `claim_pin` printed to THIS node's console/log on a fresh boot, verified
///    CONSTANT-TIME against the boot PIN held in [`SetupState`]. The PIN is NEVER
///    served over any HTTP route, so it proves the claimant has operator-level
///    access to the node's console — closing the hole that the NodeCode alone is a
///    PUBLIC, freely-shareable handle. A wrong/missing PIN → `401` (no ROOT). On
///    success the PIN is CONSUMED (cleared from state) so it cannot be replayed.
///    The PIN rides inside the signed body, so it is signature-bound.
/// 1. **First-run only** — allowed ONLY when no ROOT WaCert exists; after a ROOT
///    exists the route returns `409 Conflict` (no silent re-claim).
/// 2. **NodeCode identity-pin (CEG §0.10)** — the claim MUST carry THIS node's
///    own NodeCode (or its decoded `key_id` + `pubkey_ed25519_base64`), and the
///    handler verifies it matches the node's actual steward identity before
///    admitting the claim. The NodeCode is the OUT-OF-BAND bootstrap handle the
///    operator reads off the node and hands to the founder's app; pinning it
///    proves the founder reached the INTENDED node — not a spoof that intercepted
///    the claim. The pin rides inside the signed body, so it is signature-bound.
/// 3. **Self-attested hybrid proof-of-possession** — a FRESH founder's key is NOT
///    yet in this node's `federation_keys` directory, so the claim is NOT verified
///    directory-side ([`verify::verify_request`]/`verify_hybrid_via_directory`).
///    Instead the founder presents their OWN pubkeys in the `founder` object and
///    proves control by hybrid-signing the request body. The handler verifies the
///    `x-ciris-*` signature AGAINST THOSE pubkeys ([`verify_hybrid`],
///    [`HybridPolicy::Strict`] — both Ed25519 + ML-DSA-65 REQUIRED, no
///    classical-only path). This is the CLAIM AUTHORITY (proof-of-possession).
/// 4. The founder's key is then REGISTERED in `federation_keys` via the canonical
///    self-attested admission gate
///    ([`Engine::register_federation_key`](ciris_persist::Engine::register_federation_key)
///    → `verify_key_registration`, `scrub_key_id == key_id`), so the founder
///    becomes a real federation identity admitted thereafter. ROOT is then bound to
///    `founder.key_id`.
///
/// # Wire contract (the parallel client matches this exactly)
///
/// `POST /v1/setup/root`, headers:
/// - `x-ciris-signing-key-id`: MUST equal `founder.key_id`
/// - `x-ciris-signature-ed25519`: base64 Ed25519 over the EXACT serialized body bytes
/// - `x-ciris-signature-ml-dsa-65`: base64 ML-DSA-65 over the EXACT serialized body bytes
///
/// body (JSON):
/// ```json
/// {
///   "node_code": "CIRIS-V1-...",
///   "founder": {
///     "key_id": "...",
///     "ed25519_pubkey_b64": "...",
///     "ml_dsa_65_pubkey_b64": "..."
///   },
///   "claim_pin": "XXXX-XXXX"
/// }
/// ```
/// `claim_pin` is the one-time PIN printed to the node's console on a fresh boot
/// (console-only; NEVER served over HTTP). It is inside the signed body, so the
/// signature binds it.
/// (`node_code` may instead be supplied as the decoded `key_id` +
/// `pubkey_ed25519_base64` pair at the top level — the node-pin half, distinct
/// from the `founder` object.) The signature MUST cover the body bytes verbatim.
///
/// This is the path that needs NO offline private key and NO prior directory
/// registration: the founder claims the node they just stood up (and proved they
/// reached), self-attesting their fresh identity, becoming `SYSTEM_ADMIN`.
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

    // Parse the signed body once (the pin + the founder identity both ride here).
    let req: SetupRootRequest = if body.is_empty() {
        SetupRootRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    format!("setup/root body is not valid JSON: {e}"),
                )
            }
        }
    };

    // (2) NodeCode identity-pin (CEG §0.10): the claim must carry THIS node's own
    //     identity (the out-of-band bootstrap handle), proving the founder reached
    //     the intended node. The pin rides inside the signed body, so it is
    //     signature-bound. A claim with no pin, an undecodable NodeCode, or a pin
    //     that names a DIFFERENT node is rejected (400) — closing the spoof where a
    //     founder is tricked into claiming an attacker's node.
    if let Some(resp) = verify_node_code_pin(&st, &req) {
        return resp;
    }

    // (0/operator-presence) One-time CLAIM PIN. The claim must carry the PIN that
    //     was printed to THIS node's console/log on a fresh boot — verified
    //     CONSTANT-TIME against the boot PIN. The PIN is NEVER served over HTTP, so
    //     possessing it proves operator-level console access, closing the hole that
    //     the NodeCode alone is a freely-shareable PUBLIC handle. A wrong/missing
    //     PIN → 401 (no ROOT minted). The PIN is signature-bound (inside the signed
    //     body). It is NOT consumed here — only on a fully-successful claim below.
    if let Some(resp) = verify_claim_pin(&st, &req) {
        return resp;
    }

    // (3) Self-attested hybrid proof-of-possession. A FRESH founder is not in the
    //     directory, so we verify the body signature against the founder's OWN
    //     pubkeys (NOT the directory) under Strict policy (both sigs required).
    let Some(founder) = req.founder.clone() else {
        return err(
            StatusCode::BAD_REQUEST,
            "first-run ROOT claim must carry a `founder` object \
             { key_id, ed25519_pubkey_b64, ml_dsa_65_pubkey_b64 }",
        );
    };

    // (responsible-party model — CC 4.4.3.5 + CC 3.2 + CC 1.13.5)
    // The claimant is the RESPONSIBLE PARTY, not an agency partner. Two
    // body-level gates before we spend a signature verify:
    //   (b) the cohort scope (self|family|community) the node is claimed under, and
    //   (CC 1.13.5) REFUSE any agency:* (or legacy agency) scope in the claim — a
    //       node delegation literally cannot carry agency. The owner-binding is
    //       infra:* ONLY.
    let cohort_scope = match validate_cohort_scope(&req) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let infra_scopes: Vec<String> = match req.infra_scopes.clone() {
        Some(s) => s,
        None => super::ownership::OWNER_BINDING_INFRA_SCOPES
            .iter()
            .map(|s| s.to_string())
            .collect(),
    };
    if !super::ownership::scopes_are_infra_only(&infra_scopes) {
        return err(
            StatusCode::BAD_REQUEST,
            "first-run ROOT claim carries a non-infra (agency:* or legacy-agency) scope — \
             a node delegation MUST be infra:* ONLY (CC 1.13.5); agency stays in the agent",
        );
    }

    let signing_key_id = match header_str(&headers, verify::HEADER_KEY_ID) {
        Some(v) => v,
        None => {
            return err(
                StatusCode::UNAUTHORIZED,
                format!("missing {}", verify::HEADER_KEY_ID),
            )
        }
    };
    // The signing identity MUST be the founder identity (no third-party claim).
    if signing_key_id != founder.key_id {
        return err(
            StatusCode::UNAUTHORIZED,
            format!(
                "{} ({signing_key_id}) does not match founder.key_id ({})",
                verify::HEADER_KEY_ID,
                founder.key_id
            ),
        );
    }
    let ed25519_sig = match header_str(&headers, verify::HEADER_ED25519) {
        Some(v) => v,
        None => {
            return err(
                StatusCode::UNAUTHORIZED,
                format!("missing {}", verify::HEADER_ED25519),
            )
        }
    };
    let ml_dsa_65_sig = match header_str(&headers, verify::HEADER_ML_DSA_65) {
        Some(v) => v,
        None => {
            return err(
                StatusCode::UNAUTHORIZED,
                format!("missing {} (Strict requires it)", verify::HEADER_ML_DSA_65),
            )
        }
    };

    // Verify the hybrid signature over the EXACT body bytes against the founder's
    // PROVIDED pubkeys — proof-of-possession, not a directory lookup. Uses the
    // node's configured policy (production default [`HybridPolicy::Strict`]: both
    // Ed25519 + ML-DSA-65 required; no classical-only path). The ML-DSA-65 header
    // is required above regardless, so a Strict node never downgrades.
    if let Err(e) = verify_hybrid(
        &body,
        &ed25519_sig,
        Some(&ml_dsa_65_sig),
        &founder.ed25519_pubkey_b64,
        Some(&founder.ml_dsa_65_pubkey_b64),
        st.policy,
        None,
    ) {
        return err(
            StatusCode::UNAUTHORIZED,
            format!("self-attested signature verification failed: {e}"),
        );
    }

    // (4) Register the founder's key in federation_keys via the canonical
    //     self-attested admission gate (scrub_key_id == key_id). The founder
    //     becomes a real federation identity admitted thereafter.
    if let Err(e) = register_founder_key(&st.engine, &founder, &ed25519_sig, &ml_dsa_65_sig).await {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("register founder federation key: {e}"),
        );
    }

    // (5) Bind this identity as ROOT (race-narrowed: re-check + claim).
    if let Ok(v) = store::list_by_role(&st.engine, WaRole::Root, 1).await {
        if !v.is_empty() {
            return err(
                StatusCode::CONFLICT,
                "root already claimed; first-run setup is closed",
            );
        }
    }
    let wa_id = root_wa_id_for_identity(&founder.key_id);
    let now = chrono::Utc::now();
    let cert = WaCert {
        wa_id: wa_id.clone(),
        name: format!("root:{}", founder.key_id),
        role: WaRole::Root,
        pubkey: founder.key_id.clone(),
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
            // (responsible-party model, CC 3.2) Emit the owner-binding
            // delegates_to(responsible_user → THIS node, infra:*). This is the
            // STRUCTURAL artifact that binds the node UNDER the user's authority
            // with NO agency (CC 1.13.5); the ROOT WaCert / SystemAdmin above is
            // the derived API-role view of the SAME responsible party. The scope
            // set was already proven infra-only (the agency reject gate ran on the
            // body). A failure here is fatal to the claim's CC-meaning, so surface
            // it (the ROOT cert exists but is owner-unbound — we report 500 so the
            // operator re-drives rather than silently leaving a half-bound node).
            let owner_binding_attestation_id = match super::ownership::emit_owner_binding(
                &st.engine,
                &founder.key_id,
                &st.node_key_id,
                &infra_scopes,
            )
            .await
            {
                Ok(id) => id,
                Err(e) => {
                    return err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("ROOT bound but owner-binding emit failed: {e}"),
                    )
                }
            };

            // Consume the one-time PIN: clear it so it can never be replayed. (The
            // route is also 409-closed now that a ROOT exists — this is defence in
            // depth + makes the consumed-once invariant directly assertable.)
            if let Ok(mut guard) = st.claim_pin.lock() {
                *guard = None;
            }
            tracing::info!(
                identity = %founder.key_id,
                wa_id = %wa_id,
                cohort_scope = %cohort_scope,
                owner_binding = %owner_binding_attestation_id,
                "first-run ROOT claim: responsible user registered + owner-binding \
                 delegates_to(user → node, infra:*) emitted; ROOT/SYSTEM_ADMIN derived; \
                 one-time claim PIN consumed (CC 3.2 / CC 1.13.5)"
            );
            (
                StatusCode::CREATED,
                Json(SetupRootResponse {
                    wa_id,
                    identity_key_id: founder.key_id,
                    role: super::roles::UserRole::SystemAdmin.as_str().to_string(),
                    cohort_scope,
                    owner_binding_attestation_id,
                }),
            )
                .into_response()
        }
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    }
}

/// Read a header as a `String` (UTF-8). `None` if absent or non-UTF-8.
fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Register the fresh founder's hybrid key in `federation_keys` so it is admitted
/// thereafter (the founder becomes a real federation identity).
///
/// ## Why `put_public_key`, not `register_federation_key`
///
/// The canonical admission gate
/// ([`Engine::register_federation_key`](ciris_persist::Engine::register_federation_key)
/// → `verify_key_registration`) verifies a scrub-signature over the canonical
/// `registration_envelope` — bytes DISTINCT from the request body. Requiring that
/// would force the founder's client to produce a SECOND signature (over the
/// envelope) on top of the body signature, complicating the wire contract.
///
/// The proof-of-possession is already established by the handler's step-3
/// [`verify_hybrid`] (Strict, both sigs) over the request body against THESE same
/// pubkeys — cryptographically equivalent authority to the envelope scrub-check,
/// just over the body. So we record the proven identity directly via
/// [`put_public_key`](ciris_persist::federation::FederationDirectory::put_public_key),
/// which keeps its own `algorithm == hybrid` + `accord_holder` attestation gates
/// (a `user` row needs no attestation). The `scrub_*` fields are populated for
/// row-shape completeness (a self-attested envelope + the body signatures); they
/// are NOT re-verified by `put_public_key`.
///
/// **The claimant is the RESPONSIBLE PARTY (CC 3.2): a `user`-role identity, NOT
/// a steward.** Ownership roots in an accountable human; the node binds UNDER the
/// user's authority via a later `delegates_to(user → node, infra:*)`. We register
/// the founder's key as `identity_type "user"` (corrected from the prior
/// "steward") so [`ownership::is_owner_bound`]'s granter-is-user check resolves.
async fn register_founder_key(
    engine: &Engine,
    founder: &Founder,
    ed25519_body_sig_b64: &str,
    ml_dsa_65_body_sig_b64: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": founder.key_id });
    let canonical = ceg_produce_canonicalize(&envelope)?;
    let record = KeyRecord {
        key_id: founder.key_id.clone(),
        pubkey_ed25519_base64: founder.ed25519_pubkey_b64.clone(),
        pubkey_ml_dsa_65_base64: Some(founder.ml_dsa_65_pubkey_b64.clone()),
        algorithm: algorithm::HYBRID.into(),
        // CC 3.2: the responsible party is a `user`-role identity (free-form
        // TEXT per CC 3.4.7.1). The substrate ships an `identity_type::USER`
        // constant; we use it (not STEWARD).
        identity_type: identity_type::USER.into(),
        identity_ref: founder.key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        // The founder's body signatures, recorded as scrub material for row-shape
        // completeness. PoP was already verified over the body in handler step 3.
        scrub_signature_classical: ed25519_body_sig_b64.to_string(),
        scrub_signature_pqc: Some(ml_dsa_65_body_sig_b64.to_string()),
        scrub_key_id: founder.key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await?;
    Ok(())
}

/// The first-run setup router — merge onto the read-API listener beside the other
/// auth routers. Federation-signed; default [`HybridPolicy::Strict`].
///
/// `node_key_id` + `node_pubkey_ed25519_base64` are THIS node's steward identity
/// (the same `key_id` + raw Ed25519 pubkey carried on its NodeCode, CEG §0.10);
/// the first-run claim is identity-pinned to them (see [`setup_root`]).
///
/// `claim_pin` is the one-time operator-presence secret: `Some(pin)` arms the
/// route for a fresh (unclaimed) node — the boot path mints it via
/// [`generate_claim_pin`], prints it via [`announce_ownership_unclaimed`], and the
/// claim is gated on it (constant-time, consumed on success). `None` (an
/// already-claimed node) leaves the route un-armed — every claim attempt is `401`
/// (and `409` once the first-run check sees the existing ROOT). The PIN is held in
/// state ONLY; it is NEVER served over any HTTP route.
pub fn router(
    engine: Arc<Engine>,
    policy: HybridPolicy,
    node_key_id: String,
    node_pubkey_ed25519_base64: String,
    claim_pin: Option<String>,
) -> Router {
    Router::new()
        .route("/v1/setup/root", axum::routing::post(setup_root))
        .with_state(SetupState {
            engine,
            policy,
            node_key_id,
            node_pubkey_ed25519_base64,
            claim_pin: Arc::new(Mutex::new(claim_pin)),
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
