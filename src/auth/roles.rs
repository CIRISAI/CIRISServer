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

/// Verify a ROOT mint signature (port of `auth_service.verify_root_signature`).
///
/// The agent verified an Ed25519 signature over `MINT_WA:{user_id}:{wa_role}:
/// {timestamp}` against a pinned `root_pub.json`. In the fabric the trust root is
/// the fabric's own federation identity, so the pinned key source is a policy
/// decision (fabric signing pubkey vs. an explicit `root_pub.json`).
///
/// TODO(CIRISServer#9): wire the Ed25519 verify against the pinned ROOT pubkey
/// (load from the fabric identity dir) with the agent's ±60-minute timestamp
/// skew tolerance. Scaffolded: the message construction is fixed here so the
/// verify is a drop-in.
pub fn root_mint_message(user_id: &str, wa_role: WaRole, timestamp: &str) -> String {
    format!("MINT_WA:{user_id}:{}:{timestamp}", wa_role.as_sql_str())
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
}
