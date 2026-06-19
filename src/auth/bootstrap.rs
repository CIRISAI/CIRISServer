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
//! 3. **First-run claim** — `POST /v1/setup/root` (1-phase, SUBSTRATE-NATIVE):
//!    the literal first-time-setup flow for a FRESH node with NO baked seed. The
//!    claiming party is itself a node running the full substrate (JCS + hybrid
//!    signing), so it has ALREADY built + JCS-canonicalized + hybrid-SIGNED the
//!    `delegates_to(responsible user → THIS node, infra:*)` owner-binding with the
//!    USER's key. The body carries that complete
//!    [`SignedOwnerBinding`](super::ownership::SignedOwnerBinding); this handler
//!    verifies it (Strict, against the user's SUPPLIED pubkeys), registers the
//!    user's key (`identity_type "user"`), persists the genuinely user-signed
//!    `delegates_to`, and binds ROOT to the user — in ONE round-trip (no
//!    `/finalize`, no server-returned bytes-to-sign; the canonicalization +
//!    signing happen in the substrate on the CLAIMING side, never in any app). The
//!    claim is NodeCode-pinned (the claimant proves they reached the intended
//!    node) + claim-PIN-gated (operator presence) and first-run-only — once a ROOT
//!    exists the route is closed (409). The claiming side is driven by
//!    [`crate::claim_remote`] (`POST /v1/setup/claim-remote` on the LOCAL node).
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

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::prelude::{Engine, HybridPolicy};
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::store;

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
    /// A baked seed was loaded and a ROOT WaCert was stored. **Server 0.5: never
    /// produced on the boot path** (which always takes the no-seed claim route);
    /// retained for an explicit seed-import tool ([`root_cert_from_seed`]).
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
///
/// **Server 0.5: a pub utility for an explicit seed-import tool, NOT the boot
/// path** (which always takes the no-seed claim route). See [`load_seed_file`].
pub fn root_cert_from_seed(seed: &RootSeed) -> Result<WaCert, BootstrapError> {
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

/// Read + parse a `root_pub.json`-shaped seed file (the agent's shape).
///
/// **Server 0.5 (zero env): NOT called at boot.** A fresh node has no baked root —
/// it trusts `ciris-canonical` (per the constitution) and the founder claims ROOT
/// via the first-run `POST /v1/setup/root` (NodeCode + one-time PIN) flow. This
/// parser is retained as a pub utility (and for the seed-shape unit tests) so an
/// out-of-band tool can still read the agent's seed shape; the boot path no longer
/// pre-seeds a root from env or file.
pub fn load_seed_file(path: &Path) -> Result<RootSeed, BootstrapError> {
    let content = std::fs::read_to_string(path).map_err(BootstrapError::Io)?;
    serde_json::from_str(&content).map_err(BootstrapError::Parse)
}

/// Build a SYSTEM WA child-of-root row from a seeded ROOT (port of
/// `_create_system_wa_certificate`). Retained as a pub utility for an explicit
/// seed-import tool; **not called on the zero-env boot path** (which always takes
/// the no-seed claim route). See [`load_seed_file`].
pub fn system_wa_cert(root_wa_id: &str) -> WaCert {
    let now = chrono::Utc::now();
    WaCert {
        wa_id: "wa-system-00".to_string(),
        name: "ciris_system".to_string(),
        role: WaRole::Authority,
        // The substrate requires a non-empty pubkey. No keypair is minted on this
        // side — a deterministic placeholder marks the row as keyless (the fabric
        // is the single token issuer; this WA has no per-WA JWT).
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
    }
}

/// **`bootstrap_if_needed`** — the startup ROOT bootstrap.
///
/// **Server 0.5 (zero env): always the no-seed (claim) path.** The prior env-seed
/// pre-seed branch (`CIRIS_ROOT_SEED_PATH` / `CIRIS_ROOT_PUBKEY`+`CIRIS_ROOT_WA_ID`)
/// is DELETED. The behavior is now:
///   - if a ROOT WaCert already exists → no-op
///     ([`BootstrapOutcome::AlreadyBootstrapped`]), idempotent across reboots
///     (the agent's `has_root` short-circuit);
///   - otherwise → [`BootstrapOutcome::NoSeedAvailable`] (a clean no-op): the
///     node trusts `ciris-canonical` and the founder claims ROOT via the first-run
///     `POST /v1/setup/root` (NodeCode + one-time PIN) flow.
///
/// The serve-only-until-owned floor + the `require_owner_bound` gate are UNCHANGED
/// — this function only stopped pre-seeding a root from env.
pub async fn bootstrap_if_needed(engine: &Engine) -> Result<BootstrapOutcome, BootstrapError> {
    // `list_by_role` returns only ACTIVE certs — mirrors the agent's `has_root`.
    let existing = store::list_by_role(engine, WaRole::Root, 1).await?;
    if !existing.is_empty() {
        tracing::debug!("root WA already present — bootstrap is a no-op (idempotent)");
        return Ok(BootstrapOutcome::AlreadyBootstrapped);
    }

    tracing::info!(
        "no ROOT owner — first-run root-claim available at POST /v1/setup/root \
         (NodeCode + one-time PIN); the node trusts ciris-canonical until claimed (Server 0.5)"
    );
    Ok(BootstrapOutcome::NoSeedAvailable)
}

/// True if `key_id` is admin-eligible: it appears in `admin_key_ids` (the
/// operator-declared allowlist). This is the fabric analogue of the agent's
/// `oauth_user.role == SYSTEM_ADMIN` eligibility check — on the federation side an
/// identity's eligibility is operator-declared, not OAuth-email-derived.
///
/// **Server 0.5 (zero env):** the allowlist is no longer read from
/// `CIRIS_ADMIN_KEY_IDS` / `CIRIS_ROOT_KEY_ID`. It is resolved at boot from the
/// `auth.admin_key_ids` config:* object and threaded into the self-login router as
/// state, then passed here.
pub fn is_admin_eligible(key_id: &str, admin_key_ids: &[String]) -> bool {
    admin_key_ids
        .iter()
        .map(|k| k.trim())
        .any(|k| !k.is_empty() && k == key_id)
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
/// secret). When `pin_file` is `Some`, ALSO writes the PIN to that path (`0600`)
/// for headless ops (Server 0.5: the conventional `home/claim_pin` path, NOT an
/// env). The PIN is NEVER served over HTTP.
pub fn announce_ownership_unclaimed(node_code: &str, claim_pin: &str, pin_file: Option<PathBuf>) {
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

    // Optional headless-ops sink: write the PIN to a 0600 file when a path is
    // supplied (the conventional `home/claim_pin`; Server 0.5 — not env).
    if let Some(path) = pin_file {
        match std::fs::write(&path, format!("{claim_pin}\n")) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                }
                tracing::info!(pin_file = %path.display(), "one-time claim PIN ALSO written to file (0600; remove after claim)");
            }
            Err(e) => {
                tracing::warn!(pin_file = %path.display(), error = %e, "could not write claim PIN file (PIN remains available on the console)")
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

/// The 1-phase first-run ROOT-claim request body — the NodeCode identity-pin
/// (CEG §0.10) PLUS a COMPLETE, already-user-signed owner-binding.
///
/// The claim is SUBSTRATE-NATIVE and 1-phase: the claiming party is itself a node
/// running the full substrate, so it has already built + JCS-canonicalized +
/// hybrid-SIGNED the `delegates_to(user → THIS node, infra:*)` owner-binding with
/// the responsible USER's key ([`ownership::build_signed_owner_binding`]). This
/// body carries that complete [`SignedOwnerBinding`](ownership::SignedOwnerBinding);
/// the handler verifies + persists it ([`ownership::apply_signed_owner_binding`])
/// and binds ROOT — no second round-trip, no server-returned bytes-to-sign.
///
/// The claimant MUST prove they reached the INTENDED node (the one whose NodeCode
/// they hold out-of-band) by supplying that node's identity. Either form is
/// accepted: the full `CIRIS-V1-...` `node_code` string (decoded server-side), OR
/// the decoded `key_id` + `pubkey_ed25519_base64` pair directly.
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
    /// The cohort scope the responsible party claims this node under — one of
    /// `self` / `family` / `community` (CC 4.4.3.4.1 cohort scopes). REQUIRED:
    /// it records the membership-standing tier the owner-binding covers.
    /// Validated against the closed set; anything else → `400`.
    #[serde(default)]
    cohort_scope: Option<String>,
    /// The COMPLETE, already-user-signed owner-binding — the
    /// `delegates_to(user → THIS node, infra:*)` envelope + the user's hybrid
    /// signatures + the user's `key_id` + pubkeys
    /// ([`ownership::SignedOwnerBinding`]). REQUIRED: the claim is verified +
    /// persisted directly from it (the receiver never canonicalizes/signs on the
    /// user's behalf — the claiming node already did, in its substrate).
    #[serde(default)]
    owner_binding: Option<super::ownership::SignedOwnerBinding>,
    /// The one-time CLAIM PIN printed to THIS node's console/log on a fresh boot —
    /// the operator-presence secret (CONSOLE-ONLY; never served over HTTP). It is
    /// verified (constant-time) against the boot PIN before ROOT is bound, and
    /// consumed on success. REQUIRED.
    #[serde(default)]
    claim_pin: Option<String>,
}

/// The 1-phase `POST /v1/setup/root` response — ROOT bound + the USER-SIGNED
/// owner-binding persisted.
#[derive(Debug, Serialize)]
struct SetupRootResponse {
    /// The ROOT `wa_id` that was claimed.
    wa_id: String,
    /// The claiming federation identity (`key_id`) — the RESPONSIBLE PARTY.
    identity_key_id: String,
    /// The cohort scope the node was claimed under (`self` / `family` /
    /// `community`).
    cohort_scope: String,
    /// The bridged API role (`SYSTEM_ADMIN`), derived from the owner-binding.
    role: String,
    /// The USER-SIGNED owner-binding `delegates_to(user → node, infra:*)`
    /// attestation id (the CC 3.2 responsible-party binding that was persisted).
    owner_binding_attestation_id: String,
}

/// The closed set of cohort scopes a node may be claimed under (CC 4.4.3.4.1).
/// The 3-value restriction is intentional (a narrower subset of the persist
/// `cohort_scope` vocabulary).
const COHORT_SCOPES: &[&str] = &[
    ciris_persist::federation::types::cohort_scope::SELF,
    ciris_persist::federation::types::cohort_scope::FAMILY,
    ciris_persist::federation::types::cohort_scope::COMMUNITY,
];

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
/// baked seed. **1-phase + SUBSTRATE-NATIVE.**
///
/// # The responsible-party model (CC 4.4.3.5 + CC 3.2 + CC 1.13.5)
///
/// A fabric node is `node`-role and MUST NOT have agency ("infrastructure must
/// not have agency", CC 1.13.5). This claim establishes a RESPONSIBLE PARTY (a
/// `user`-role identity), not an agency partnership.
///
/// # 1-phase claim — the client is itself a node (it HAS JCS)
///
/// The claiming party runs the full substrate, so it has ALREADY built +
/// JCS-canonicalized + hybrid-SIGNED the `delegates_to(user → THIS node, infra:*)`
/// owner-binding with the responsible USER's key
/// ([`ownership::build_signed_owner_binding`]). The body carries that COMPLETE
/// [`SignedOwnerBinding`](super::ownership::SignedOwnerBinding) — the envelope +
/// the user's hybrid signatures + the user's `key_id` + pubkeys. This handler
/// verifies + persists it ([`ownership::apply_signed_owner_binding`]) and binds
/// ROOT in ONE round-trip. There is NO server-returned bytes-to-sign and NO
/// `/finalize` — the canonicalization + signing happened in the substrate on the
/// CLAIMING side, never in any app.
///
/// Any `agency:*` (or legacy agency) scope in the owner-binding is REJECTED
/// (`400`) — a node delegation literally cannot carry agency (the CC 1.13.5
/// wire-checkable invariant). The AGENT's joint-agency partnership stays in the
/// agent, NOT here.
///
/// # Security model — independent gates
///
/// 1. **First-run only** — allowed ONLY when no ROOT WaCert exists; after a ROOT
///    exists the route returns `409 Conflict` (no silent re-claim).
/// 2. **NodeCode identity-pin (CEG §0.10)** — the claim MUST carry THIS node's
///    own NodeCode (or its decoded `key_id` + `pubkey_ed25519_base64`), verified
///    against the node's actual steward identity — proving the claimant reached
///    the INTENDED node, not a spoof.
/// 3. **One-time CLAIM PIN (operator-presence)** — the claim MUST carry the
///    `claim_pin` printed to THIS node's console on a fresh boot, verified
///    CONSTANT-TIME against the boot PIN. The PIN is NEVER served over HTTP, so it
///    proves operator-level console access. Consumed on a fully-successful claim.
/// 4. **User-signed owner-binding (the claim authority)** — the
///    [`SignedOwnerBinding`](super::ownership::SignedOwnerBinding) is validated +
///    its USER hybrid signature verified over the JCS-canonical bytes of its
///    envelope against the user's SUPPLIED pubkeys (Strict). The user's key is
///    then registered (`identity_type "user"`) and the GENUINELY USER-SIGNED
///    `delegates_to` is persisted ([`ownership::apply_signed_owner_binding`]).
///    Then ROOT is bound to the responsible user → `SYSTEM_ADMIN`.
///
/// # Wire contract
///
/// `POST /v1/setup/root`, body (JSON):
/// ```json
/// {
///   "node_code": "CIRIS-V1-...",
///   "cohort_scope": "self|family|community",
///   "claim_pin": "XXXX-XXXX",
///   "owner_binding": {
///     "envelope": { ...the delegates_to(user -> node, infra:*) envelope... },
///     "attesting_key_id": "<the responsible user key_id>",
///     "ed25519_pubkey_b64": "...",
///     "ml_dsa_65_pubkey_b64": "...",
///     "ed25519_sig_b64": "<user sig over JCS(envelope)>",
///     "ml_dsa_65_sig_b64": "<user sig over JCS(envelope)>"
///   }
/// }
/// ```
/// No `x-ciris-*` headers: the proof is the user's hybrid signature INSIDE the
/// owner-binding (over the envelope's canonical bytes), verified against the
/// user's supplied pubkeys. (`node_code` may instead be supplied as the decoded
/// `key_id` + `pubkey_ed25519_base64` pair at the top level.)
///
/// Response (`201 Created`): `{ wa_id, identity_key_id, cohort_scope, role,
/// owner_binding_attestation_id }`.
async fn setup_root(State(st): State<SetupState>, body: axum::body::Bytes) -> Response {
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
    //     identity, proving the claimant reached the intended node.
    if let Some(resp) = verify_node_code_pin(&st, &req) {
        return resp;
    }

    // (3) One-time CLAIM PIN (operator-presence). Constant-time vs the boot PIN.
    //     NOT consumed here — only on a fully-successful claim below.
    if let Some(resp) = verify_claim_pin(&st, &req) {
        return resp;
    }

    // The cohort scope (self|family|community) the node is claimed under.
    let cohort_scope = match validate_cohort_scope(&req) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };

    // (4) The COMPLETE, already-user-signed owner-binding. The claiming node built
    //     + canonicalized + hybrid-signed it in ITS substrate; we only verify +
    //     persist it here (no canonicalize/sign on the user's behalf).
    let Some(owner_binding) = req.owner_binding.as_ref() else {
        return err(
            StatusCode::BAD_REQUEST,
            "first-run ROOT claim must carry a complete `owner_binding` \
             (the user-signed delegates_to: envelope + signatures + key_id + pubkeys)",
        );
    };

    // Validate + verify (Strict hybrid against the user's supplied pubkeys) +
    // register the user as identity_type "user" + persist the GENUINELY USER-SIGNED
    // delegates_to(user -> THIS node, infra:*). All crypto in the substrate.
    let applied = match super::ownership::apply_signed_owner_binding(
        &st.engine,
        &st.node_key_id,
        st.policy,
        owner_binding,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            // Map the substrate error to the right HTTP status.
            let code = match e {
                super::ownership::OwnershipError::AgencyScopeRefused
                | super::ownership::OwnershipError::Validation(_)
                | super::ownership::OwnershipError::Canonicalize(_) => StatusCode::BAD_REQUEST,
                super::ownership::OwnershipError::Verify(_) => StatusCode::UNAUTHORIZED,
                super::ownership::OwnershipError::Sign(_)
                | super::ownership::OwnershipError::Persist(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return err(code, format!("owner-binding rejected: {e}"));
        }
    };

    // (5) Bind this responsible user as ROOT (race-narrowed: re-check + claim).
    if let Ok(v) = store::list_by_role(&st.engine, WaRole::Root, 1).await {
        if !v.is_empty() {
            return err(
                StatusCode::CONFLICT,
                "root already claimed; first-run setup is closed",
            );
        }
    }
    let identity_key_id = applied.responsible_user_key_id;
    let wa_id = root_wa_id_for_identity(&identity_key_id);
    let now = chrono::Utc::now();
    let cert = WaCert {
        wa_id: wa_id.clone(),
        name: format!("root:{identity_key_id}"),
        role: WaRole::Root,
        pubkey: identity_key_id.clone(),
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
            // Consume the one-time PIN (no replay; route is also 409-closed now).
            if let Ok(mut guard) = st.claim_pin.lock() {
                *guard = None;
            }
            tracing::info!(
                identity = %identity_key_id,
                wa_id = %wa_id,
                node_key_id = %st.node_key_id,
                cohort_scope = %cohort_scope,
                owner_binding = %applied.attestation_id,
                "first-run ROOT claim (1-phase, substrate-native): USER-SIGNED \
                 owner-binding persisted; ROOT/SYSTEM_ADMIN bound to the responsible \
                 user; one-time claim PIN consumed (CC 3.2 / CC 1.13.5)"
            );
            (
                StatusCode::CREATED,
                Json(SetupRootResponse {
                    wa_id,
                    identity_key_id,
                    cohort_scope,
                    role: super::roles::UserRole::SystemAdmin.as_str().to_string(),
                    owner_binding_attestation_id: applied.attestation_id,
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
///
/// `claim_pin` is the one-time operator-presence secret: `Some(pin)` arms the
/// route for a fresh (unclaimed) node — the boot path mints it via
/// [`generate_claim_pin`], prints it via [`announce_ownership_unclaimed`], and the
/// claim is gated on it (constant-time, consumed on success). `None` (an
/// already-claimed node) leaves the route un-armed — every claim attempt is `401`
/// (and `409` once the first-run check sees the existing ROOT). The PIN is held in
/// state ONLY; it is NEVER served over any HTTP route.
///
/// 1-phase: there is a single `POST /v1/setup/root` route — no `/finalize` (the
/// client is itself a node and signs the owner-binding in its own substrate).
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
