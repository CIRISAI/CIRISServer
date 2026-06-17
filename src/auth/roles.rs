//! The role + permission model (CIRISServer#9).
//!
//! TWO complementary taxonomies, both authoritative:
//!
//! 1. [`Role`] — the **CEG role-set** (§7.0.1: `identity_type` is a SET, so a key
//!    may hold several). The federation-native model + the §9 infra/agency
//!    reserved-scope split. This is how the fabric reasons about identities.
//! 2. [`UserRole`] + [`Permission`] + [`permissions_for`] — the **agent's API
//!    role hierarchy** (`OBSERVER < ADMIN < AUTHORITY < SYSTEM_ADMIN`, plus the
//!    `SERVICE_ACCOUNT` peer). Preserved VERBATIM so the agent's API clients keep
//!    working when they hit the fabric — this is the API-compatibility contract.
//!
//! The bridge: `wa_cert.role` (`root|authority|observer`, persist [`WaRole`]) →
//! [`UserRole`] (`ROOT→SYSTEM_ADMIN`, `AUTHORITY→AUTHORITY`, `OBSERVER→OBSERVER`).

use ciris_persist::wa_cert::WaRole;

// ─── The CEG role-set (federation-native) ───────────────────────────────────

/// A federation role. A key's `identity_type` is a SET of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// An accountable human identity.
    User,
    /// Infrastructure (a fabric node) — never agency-bearing (§1.3).
    Node,
    /// An autonomous AI delegate (a brain) — the only AI actor.
    Agent,
    /// A founder member of an infrastructure community (e.g. ciris-canonical).
    Steward,
    /// A transparency-log co-signer (`transparency_log:cosigned:*`).
    Witness,
    /// A Humanity-Accord holder (the one constitutional asymmetry, §9).
    AccordHolder,
}

impl Role {
    /// The canonical `identity_type` token.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Node => "node",
            Role::Agent => "agent",
            Role::Steward => "steward",
            Role::Witness => "witness",
            Role::AccordHolder => "accord_holder",
        }
    }

    /// Parse a canonical `identity_type` token.
    pub fn from_token(s: &str) -> Option<Role> {
        Some(match s {
            "user" => Role::User,
            "node" => Role::Node,
            "agent" => Role::Agent,
            "steward" => Role::Steward,
            "witness" => Role::Witness,
            "accord_holder" => Role::AccordHolder,
            _ => return None,
        })
    }
}

/// The §9 reserved-scope split that cryptographically enforces "infra must not
/// have agency": a server/node binding may hold only [`INFRA`] scopes; the
/// agency scopes are brain-only ([`AGENCY`]). Self-at-login's `app` occurrence
/// gets agency; a bare server binding does not.
pub mod scope {
    /// Non-agency scopes a user→node ("partnership-without-agency") binding gets.
    pub const INFRA: &[&str] = &[
        "network_presence",
        "join_communities",
        "serve",
        "store",
        "attest",
        "transport",
    ];
    /// Agency scopes only a brain (agent) may hold (§8.1.12.7 user→agent set).
    pub const AGENCY: &[&str] = &["act_on_behalf", "message_io", "reason", "decide"];
}

// ─── The agent's API role hierarchy (client-compatibility contract) ─────────

/// The agent's API role (`schemas/api/auth.py` `UserRole`). Preserved verbatim
/// so existing agent clients keep working against the fabric.
///
/// Hierarchy: `OBSERVER < ADMIN < AUTHORITY < SYSTEM_ADMIN`. `SERVICE_ACCOUNT`
/// is a peer of `ADMIN` (system ops, not in the human escalation ladder).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserRole {
    /// Read-only + send messages.
    Observer,
    /// + management (config, runtime, tasks…).
    Admin,
    /// + deferral resolution, guidance, permission grants.
    Authority,
    /// + full access, emergency shutdown, sensitive config.
    SystemAdmin,
    /// Machine-to-machine system ops (peer of Admin).
    ServiceAccount,
}

impl UserRole {
    /// Numeric escalation level (higher = more authority). `SERVICE_ACCOUNT`
    /// shares level 2 with `ADMIN`.
    pub fn level(self) -> u8 {
        match self {
            UserRole::Observer => 1,
            UserRole::Admin => 2,
            UserRole::ServiceAccount => 2,
            UserRole::Authority => 3,
            UserRole::SystemAdmin => 4,
        }
    }

    /// True if `self` satisfies a `required` role (escalation check). A
    /// `SERVICE_ACCOUNT` only satisfies `SERVICE_ACCOUNT` or lower-level human
    /// roles by level, never `AUTHORITY`/`SYSTEM_ADMIN`.
    pub fn satisfies(self, required: UserRole) -> bool {
        self.level() >= required.level()
    }

    /// Canonical wire token (`"OBSERVER"`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            UserRole::Observer => "OBSERVER",
            UserRole::Admin => "ADMIN",
            UserRole::Authority => "AUTHORITY",
            UserRole::SystemAdmin => "SYSTEM_ADMIN",
            UserRole::ServiceAccount => "SERVICE_ACCOUNT",
        }
    }

    /// Parse a wire token.
    pub fn from_str_token(s: &str) -> Option<UserRole> {
        Some(match s {
            "OBSERVER" => UserRole::Observer,
            "ADMIN" => UserRole::Admin,
            "AUTHORITY" => UserRole::Authority,
            "SYSTEM_ADMIN" => UserRole::SystemAdmin,
            "SERVICE_ACCOUNT" => UserRole::ServiceAccount,
            _ => return None,
        })
    }

    /// Bridge from the persist `wa_cert.role` (`WaRole`) to the API role.
    /// `ROOT → SYSTEM_ADMIN`, `AUTHORITY → AUTHORITY`, `OBSERVER → OBSERVER`
    /// (the agent's `WARole → APIRole` map).
    pub fn from_wa_role(role: WaRole) -> UserRole {
        match role {
            WaRole::Root => UserRole::SystemAdmin,
            WaRole::Authority => UserRole::Authority,
            WaRole::Observer => UserRole::Observer,
        }
    }
}

/// The agent's `Permission` enum (`schemas/api/auth.py`). Preserved verbatim for
/// client compatibility. The string value is the wire form clients check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    // Observer
    ViewMessages,
    ViewTelemetry,
    ViewReasoning,
    ViewConfig,
    ViewMemory,
    ViewAudit,
    ViewTools,
    ViewLogs,
    SendMessages,
    // Admin
    ManageConfig,
    RuntimeControl,
    ManageIncidents,
    ManageTasks,
    ManageFilters,
    TriggerAnalysis,
    // Authority
    ResolveDeferrals,
    ProvideGuidance,
    GrantPermissions,
    ManageUserPermissions,
    // System Admin
    FullAccess,
    EmergencyShutdown,
    ManageSensitiveConfig,
}

impl Permission {
    /// The permissions held by `OBSERVER` (the base read-only + send set).
    const OBSERVER: &'static [Permission] = &[
        Permission::ViewMessages,
        Permission::ViewTelemetry,
        Permission::ViewReasoning,
        Permission::ViewConfig,
        Permission::ViewMemory,
        Permission::ViewAudit,
        Permission::ViewTools,
        Permission::ViewLogs,
        Permission::SendMessages,
    ];
    /// The permissions `ADMIN` adds on top of `OBSERVER`.
    const ADMIN_EXTRA: &'static [Permission] = &[
        Permission::ManageConfig,
        Permission::RuntimeControl,
        Permission::ManageIncidents,
        Permission::ManageTasks,
        Permission::ManageFilters,
        Permission::TriggerAnalysis,
    ];
    /// The permissions `AUTHORITY` adds on top of `ADMIN`.
    const AUTHORITY_EXTRA: &'static [Permission] = &[
        Permission::ResolveDeferrals,
        Permission::ProvideGuidance,
        Permission::GrantPermissions,
        Permission::ManageUserPermissions,
    ];
    /// The permissions `SYSTEM_ADMIN` adds on top of `AUTHORITY`.
    const SYSTEM_ADMIN_EXTRA: &'static [Permission] = &[
        Permission::FullAccess,
        Permission::EmergencyShutdown,
        Permission::ManageSensitiveConfig,
    ];
}

/// The `ROLE_PERMISSIONS` map (`schemas/api/auth.py`). Returns the full effective
/// permission set for `role` (cumulative up the hierarchy).
pub fn permissions_for(role: UserRole) -> Vec<Permission> {
    let mut perms: Vec<Permission> = Permission::OBSERVER.to_vec();
    match role {
        UserRole::Observer => {}
        UserRole::ServiceAccount => {
            // System-ops peer of Admin: telemetry/config/runtime/tools/logs/send.
            return vec![
                Permission::ViewTelemetry,
                Permission::ViewConfig,
                Permission::RuntimeControl,
                Permission::ViewTools,
                Permission::ViewLogs,
                Permission::SendMessages,
            ];
        }
        UserRole::Admin => perms.extend_from_slice(Permission::ADMIN_EXTRA),
        UserRole::Authority => {
            perms.extend_from_slice(Permission::ADMIN_EXTRA);
            perms.extend_from_slice(Permission::AUTHORITY_EXTRA);
        }
        UserRole::SystemAdmin => {
            perms.extend_from_slice(Permission::ADMIN_EXTRA);
            perms.extend_from_slice(Permission::AUTHORITY_EXTRA);
            perms.extend_from_slice(Permission::SYSTEM_ADMIN_EXTRA);
        }
    }
    perms
}

/// True if `role` holds `perm` (effective set membership).
pub fn role_has(role: UserRole, perm: Permission) -> bool {
    permissions_for(role).contains(&perm)
}

// ─── Root-authority helpers (mint / root-signature) — scaffolded ────────────

/// Map an API role back to the persist `wa_cert.role` for minting.
pub fn user_role_to_wa_role(role: UserRole) -> WaRole {
    match role {
        UserRole::SystemAdmin => WaRole::Root,
        UserRole::Authority => WaRole::Authority,
        // Admin / ServiceAccount / Observer all map to the observer wa_cert role
        // (the API-role distinction is carried by `scopes` / `custom_permissions`,
        // not the 3-value WA role vocabulary).
        _ => WaRole::Observer,
    }
}

/// The agent's ROOT mint message: `MINT_WA:{user_id}:{wa_role}:{timestamp}`
/// (`wa_role` is the lowercase persist token, `timestamp` an ISO-8601 instant).
pub fn root_mint_message(user_id: &str, wa_role: WaRole, timestamp: &str) -> String {
    format!("MINT_WA:{user_id}:{}:{timestamp}", wa_role.as_sql_str())
}

/// The timestamp-free fallback message (`MINT_WA:{user_id}:{wa_role}`) the agent
/// also accepts for signatures produced by its offline signing script.
fn root_mint_message_no_ts(user_id: &str, wa_role: WaRole) -> String {
    format!("MINT_WA:{user_id}:{}", wa_role.as_sql_str())
}

/// Decode the agent's `root_pub.json` `pubkey` field (base64url, MAY be missing
/// padding — the agent re-pads with `"=" * (4 - len % 4)`) into a verifying key.
fn parse_root_pubkey(pubkey_b64url: &str) -> Option<ed25519_dalek::VerifyingKey> {
    use base64::Engine as _;
    // base64url WITH padding tolerated; the URL_SAFE engine here is forgiving of
    // already-padded input, and we re-pad to a multiple of 4 to mirror the agent.
    let mut s = pubkey_b64url.to_string();
    let rem = s.len() % 4;
    if rem != 0 {
        s.push_str(&"=".repeat(4 - rem));
    }
    let bytes = base64::engine::general_purpose::URL_SAFE.decode(&s).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr).ok()
}

/// Render a UTC instant the way Python's `datetime.isoformat()` does for a
/// tz-aware UTC datetime: `YYYY-MM-DDTHH:MM:SS+00:00`, with `.ffffff` inserted
/// ONLY when microseconds are non-zero. The agent signs/verifies against this
/// exact string, so byte-for-byte parity matters.
fn python_isoformat(t: chrono::DateTime<chrono::Utc>) -> String {
    use chrono::Timelike as _;
    let micros = t.nanosecond() / 1_000;
    if micros == 0 {
        t.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()
    } else {
        format!("{}.{:06}+00:00", t.format("%Y-%m-%dT%H:%M:%S"), micros)
    }
}

/// The ROOT public key the fabric pins as its mint trust root. Matches the
/// agent's `seed/root_pub.json` shape (the `pubkey` field is the only one the
/// verify reads).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RootPubKey {
    /// Base64url-encoded Ed25519 public key.
    pub pubkey: String,
}

impl RootPubKey {
    /// Load the pinned ROOT pubkey from a `root_pub.json`-shaped file (the fabric
    /// identity dir's equivalent of the agent's `seed/root_pub.json`).
    pub fn load(path: &std::path::Path) -> std::io::Result<RootPubKey> {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// Verify a ROOT mint signature — byte-compatible port of
/// `auth_service.verify_root_signature`.
///
/// The agent Ed25519-verifies `signature` (base64 OR base64url) against the
/// pinned ROOT pubkey over the message `MINT_WA:{user_id}:{wa_role}:{timestamp}`,
/// trying every whole-minute ISO timestamp in the **last 60 minutes** (its
/// skew-tolerance window), then a timestamp-free fallback
/// (`MINT_WA:{user_id}:{wa_role}`) for offline-signed mints. Any decode/verify
/// failure across all candidates → `false` (the agent's `except: continue` /
/// `return False`).
///
/// `now` is injected for deterministic testing; production callers pass
/// `chrono::Utc::now()`.
pub fn verify_root_signature(
    root_pubkey_b64url: &str,
    user_id: &str,
    wa_role: WaRole,
    signature: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    use base64::Engine as _;
    use ed25519_dalek::Verifier as _;

    let Some(vk) = parse_root_pubkey(root_pubkey_b64url) else {
        return false;
    };

    // Decode the signature both ways the agent accepts; gather the candidates.
    let mut sig_candidates: Vec<ed25519_dalek::Signature> = Vec::new();
    // standard base64
    if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(signature) {
        if let Ok(sig) = ed25519_dalek::Signature::from_slice(&b) {
            sig_candidates.push(sig);
        }
    }
    // url-safe base64 (re-padded, as the agent does)
    {
        let mut s = signature.to_string();
        let rem = s.len() % 4;
        if rem != 0 {
            s.push_str(&"=".repeat(4 - rem));
        }
        if let Ok(b) = base64::engine::general_purpose::URL_SAFE.decode(&s) {
            if let Ok(sig) = ed25519_dalek::Signature::from_slice(&b) {
                sig_candidates.push(sig);
            }
        }
    }
    if sig_candidates.is_empty() {
        return false;
    }

    let try_msg = |msg: &str| -> bool {
        sig_candidates
            .iter()
            .any(|sig| vk.verify(msg.as_bytes(), sig).is_ok())
    };

    // Timestamped messages over the last 60 minutes (the agent's window). The
    // agent builds each candidate as `(now - minutes_ago).isoformat()`, so the
    // wire form must match Python's `datetime.isoformat()` EXACTLY: it omits the
    // fractional part entirely when microseconds == 0, else renders 6 digits;
    // a UTC offset is `+00:00`. We reproduce both cases.
    for minutes_ago in 0..60i64 {
        let t = now - chrono::Duration::minutes(minutes_ago);
        let timestamp = python_isoformat(t);
        if try_msg(&root_mint_message(user_id, wa_role, &timestamp)) {
            return true;
        }
    }

    // Timestamp-free fallback (offline signing script).
    try_msg(&root_mint_message_no_ts(user_id, wa_role))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hierarchy_escalates() {
        assert!(UserRole::SystemAdmin.satisfies(UserRole::Authority));
        assert!(UserRole::Authority.satisfies(UserRole::Admin));
        assert!(UserRole::Admin.satisfies(UserRole::Observer));
        assert!(!UserRole::Observer.satisfies(UserRole::Admin));
        // SERVICE_ACCOUNT (level 2) does not reach AUTHORITY (level 3).
        assert!(!UserRole::ServiceAccount.satisfies(UserRole::Authority));
    }

    #[test]
    fn permission_map_is_cumulative() {
        let obs = permissions_for(UserRole::Observer);
        let adm = permissions_for(UserRole::Admin);
        let auth = permissions_for(UserRole::Authority);
        let sa = permissions_for(UserRole::SystemAdmin);
        assert_eq!(obs.len(), 9);
        assert_eq!(adm.len(), 15);
        assert_eq!(auth.len(), 19);
        assert_eq!(sa.len(), 22);
        // SYSTEM_ADMIN has the apex permissions; OBSERVER does not.
        assert!(role_has(UserRole::SystemAdmin, Permission::EmergencyShutdown));
        assert!(!role_has(UserRole::Observer, Permission::EmergencyShutdown));
        assert!(role_has(UserRole::Observer, Permission::SendMessages));
    }

    #[test]
    fn wa_role_bridges_to_api_role() {
        assert_eq!(UserRole::from_wa_role(WaRole::Root), UserRole::SystemAdmin);
        assert_eq!(
            UserRole::from_wa_role(WaRole::Authority),
            UserRole::Authority
        );
        assert_eq!(UserRole::from_wa_role(WaRole::Observer), UserRole::Observer);
    }

    #[test]
    fn python_isoformat_matches_cpython() {
        use chrono::TimeZone as _;
        // Whole second ⇒ no fractional part (CPython drops it).
        let t = chrono::Utc.with_ymd_and_hms(2026, 6, 16, 12, 30, 0).unwrap();
        assert_eq!(python_isoformat(t), "2026-06-16T12:30:00+00:00");
        // Non-zero microseconds ⇒ 6-digit fraction.
        let t2 = chrono::Utc
            .with_ymd_and_hms(2026, 6, 16, 12, 30, 0)
            .unwrap()
            + chrono::Duration::microseconds(123456);
        assert_eq!(python_isoformat(t2), "2026-06-16T12:30:00.123456+00:00");
    }

    /// Vectors produced by the AGENT'S OWN ed25519 path
    /// (`cryptography.ed25519`, seed = `bytes(range(32))`). The no-timestamp
    /// message is the deterministic offline-signing path the agent accepts.
    #[test]
    fn verify_root_signature_no_timestamp_vector() {
        let pub_b64url = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
        let sig_b64 = "9yo4Wmwi/RmNKWHYZ+02G6gcw6hOXaAJ0f8vcNX/VhwnNBZUMZMioV6XthLZuWg1EIFV3APz36REHN0MKPa+Dw==";
        let now = chrono::Utc::now();
        assert!(
            verify_root_signature(pub_b64url, "user-123", WaRole::Root, sig_b64, now),
            "must verify the agent's no-timestamp MINT_WA signature"
        );
        // Wrong user_id ⇒ fail.
        assert!(!verify_root_signature(
            pub_b64url, "user-999", WaRole::Root, sig_b64, now
        ));
    }

    /// The timestamped path: the agent's signing-time `isoformat()` must fall
    /// within our 60-minute reconstruction window. Signed at `now - 0min`.
    #[test]
    fn verify_root_signature_timestamped_vector() {
        use chrono::TimeZone as _;
        let pub_b64url = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
        let sig_b64url =
            "_7z2AZRdkLfnIDtt251Fse2l7brJO_69GIWxCMZvxo8-UavTnjjXWNw0oTnGgh26fSzxO8flTBp2sHXH3HHrBA";
        // Signed against timestamp 2026-06-16T12:30:00+00:00; verify with a `now`
        // 5 minutes later so the candidate lands inside the [now-60min, now] sweep.
        let now = chrono::Utc.with_ymd_and_hms(2026, 6, 16, 12, 35, 0).unwrap();
        assert!(
            verify_root_signature(pub_b64url, "user-123", WaRole::Root, sig_b64url, now),
            "must verify the agent's timestamped MINT_WA signature within the window"
        );
        // Outside the window (signed >60min ago) ⇒ fail.
        let too_late = chrono::Utc.with_ymd_and_hms(2026, 6, 16, 14, 0, 0).unwrap();
        assert!(!verify_root_signature(
            pub_b64url, "user-123", WaRole::Root, sig_b64url, too_late
        ));
    }
}
