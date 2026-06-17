#![allow(dead_code)] // scaffold surface — wired by the next auth slices (registry-fold #2 + agent migration).

//! The one role model — the CEG role-set (§7.0.1: `identity_type` is a SET, so a
//! key may hold several roles). Replaces the agent's `WARole → APIRole + 17
//! perms` taxonomy and the registry's `SystemRole/OrgRole`.

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
