//! The owner-binding gate (CIRISServer#9) — the CIRISServer authz floor.
//! CEG has the primitives but does not mandate it (filed as the optional
//! normative rule in CIRISRegistry#83).
//!
//! **TRUST ≠ JOIN. SERVE ≠ OWN.** A node may *trust + serve* an infrastructure
//! community (relay/store/transport/serve reads — e.g. the shipped
//! ciris-canonical pin) with **no owner**. It may *join* (become a member: share
//! the DEK, count in consensus) a **non-infrastructure** community, and may
//! perform owner-only operations (e.g. federation peering), only after a
//! **RESPONSIBLE PARTY is bound** to it — a `user`-role identity holding a live
//! `delegates_to(user → node, infra:*)` owner-binding (CC 3.2 / CC 4.4.3.5).
//! Non-infra membership + cross-node data flow are authority acts, which §1.5 /
//! §7.0.1 require to root in an accountable human — never a bare node.
//!
//! **The serve-only floor (the principle this gate enforces).** An UNOWNED node
//! refuses every owner-op and serves cleartext federation data from the
//! **canonical root ONLY** — it relays/serves but does not author cross-node
//! consent, join non-infra groups, or otherwise act with the standing of an
//! owned member. [`is_steward_bound`] is the producer of the `owner_bound` bit;
//! [`require_owner_bound`] is the operational gate.

use ciris_persist::prelude::Engine;

pub use crate::auth::ownership::is_steward_bound;
use crate::auth::session::SessionCaller;

// ─── Delegation authorization (CIRISServer delegation-constraints) ────────────
//
// A delegated caller (`SessionCaller.actor.is_some()`) wields the owner's role,
// but the owner may BOUND it with a `DelegationConstraints` (action allow/deny +
// goal; duration rides the edge expiry). This is the enforcement seam:
// `authorize_delegated` is called at every owner-gated op, keyed by a
// non-defaultable [`CapabilityVerb`] so a new endpoint can't silently skip it.

/// The capability a request exercises — one per class of owner-gated op. The verb
/// is the unit the owner's action allow/deny-list and the server never-list match
/// on (`as_str`). Non-`Default` on purpose: every gated handler must name its verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityVerb {
    /// Claim a REMOTE node on the owner's behalf (`POST /v1/setup/claim-remote`).
    ClaimRemote,
    /// Promote + announce a node to the federation (`POST /v1/federation/announce`).
    Announce,
    /// Establish cross-node replication peering (`POST /v1/federation/peering`).
    Peer,
    /// Write a config:* object (`PUT`/`DELETE /v1/config/{key}`).
    ConfigWrite,
    /// Set a subject's age band (`POST /v1/self/age`).
    SetAge,
    /// Relay a signed control op to an owned remote (`POST /v1/mesh/relay`).
    MeshRelay,
    /// Issue / approve a delegation (`/v1/auth/device/{delegate,approve}`). NEVER
    /// delegatable — a delegate must not mint further delegations (no re-delegation).
    Delegate,
    /// Wipe / reset node data (`/v1/system/data/*`). NEVER delegatable.
    Wipe,
    /// Accord kill-switch / halt (`/v1/accord/*` custody ops). NEVER delegatable.
    AccordHalt,
}

impl CapabilityVerb {
    /// The stable wire token the owner's allow/deny-list matches on.
    pub fn as_str(self) -> &'static str {
        match self {
            CapabilityVerb::ClaimRemote => "claim_remote",
            CapabilityVerb::Announce => "announce",
            CapabilityVerb::Peer => "peer",
            CapabilityVerb::ConfigWrite => "config_write",
            CapabilityVerb::SetAge => "set_age",
            CapabilityVerb::MeshRelay => "mesh_relay",
            CapabilityVerb::Delegate => "delegate",
            CapabilityVerb::Wipe => "wipe",
            CapabilityVerb::AccordHalt => "accord_halt",
        }
    }

    /// Verbs NO delegate may ever exercise, regardless of the grant's allow-list —
    /// the server floor (re-delegation, data wipe, the humanity-accord kill-switch).
    /// These stay the owner's alone; a delegated bearer is refused unconditionally.
    pub fn never_delegatable(self) -> bool {
        matches!(
            self,
            CapabilityVerb::Delegate | CapabilityVerb::Wipe | CapabilityVerb::AccordHalt
        )
    }
}

/// Why a delegated call was refused — serialized into the `403` body so the actor
/// sees exactly which rule blocked it (and the goal it was granted for).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DenyReason {
    /// The rule that denied: `never_list` | `action_deny` | `action_allow`.
    pub denied_by: &'static str,
    /// The verb that was attempted.
    pub verb: &'static str,
    /// The delegation's goal, when set (context for the human reading the log).
    pub goal: Option<String>,
    /// Human-readable detail.
    pub detail: String,
}

/// **The delegation-constraint gate.** Call at every owner-gated op AFTER the
/// role/owner check, naming the [`CapabilityVerb`] being exercised.
///
/// - A NON-delegated caller (`actor.is_none()` — the owner acting directly) is
///   always `Ok`: constraints bound *delegates*, not the owner.
/// - A delegated caller is refused if the verb is on the server never-list, on the
///   grant's action deny-list, or absent from a set action allow-list. Check order
///   is never → deny → allow (deny beats allow; a missing allow-list = all verbs).
pub fn authorize_delegated(caller: &SessionCaller, verb: CapabilityVerb) -> Result<(), DenyReason> {
    // The owner acting directly is unconstrained by delegation bounds.
    if caller.actor.is_none() {
        return Ok(());
    }
    // Server floor: some verbs are never delegatable, whatever the grant says.
    if verb.never_delegatable() {
        return Err(DenyReason {
            denied_by: "never_list",
            verb: verb.as_str(),
            goal: caller.constraints.as_ref().and_then(|c| c.goal.clone()),
            detail: format!(
                "'{}' can never be performed by a delegate — it stays the owner's alone",
                verb.as_str()
            ),
        });
    }
    let Some(constraints) = &caller.constraints else {
        // Delegated but no constraints recorded ⇒ unconstrained (legacy full grant).
        return Ok(());
    };
    let v = verb.as_str();
    // Deny-list wins over everything below.
    if constraints.actions_deny.iter().any(|a| a == v) {
        return Err(DenyReason {
            denied_by: "action_deny",
            verb: v,
            goal: constraints.goal.clone(),
            detail: format!("'{v}' is on this delegation's deny-list"),
        });
    }
    // A SET allow-list must contain the verb; an absent allow-list = all permitted.
    if let Some(allow) = &constraints.actions_allow {
        if !allow.iter().any(|a| a == v) {
            return Err(DenyReason {
                denied_by: "action_allow",
                verb: v,
                goal: constraints.goal.clone(),
                detail: format!("'{v}' is not in this delegation's allowed actions"),
            });
        }
    }
    Ok(())
}

/// The community class for the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommunityKind {
    /// `cohort_subkind: infrastructure` — trust roots (ciris-canonical /
    /// governance). Joinable with no owner; the trust root is maximally
    /// inspectable.
    Infrastructure,
    /// Any other community (family / community / affiliations).
    Other,
}

/// May this node be **admitted as a member** of a community of `kind`, given
/// whether an accountable owner (responsible party) is bound to it? (Trust +
/// serve is always allowed and is NOT gated here — this governs *membership*
/// only.)
pub fn may_join(kind: CommunityKind, owner_bound: bool) -> bool {
    match kind {
        CommunityKind::Infrastructure => true,
        CommunityKind::Other => owner_bound,
    }
}

/// Resolve whether `node_key_id` has a responsible party bound (the producer of
/// the `owner_bound` bit), then apply [`may_join`]. A node with no live
/// `delegates_to(user → node, infra:*)` owner-binding may join only
/// infrastructure communities.
pub async fn may_join_resolved(engine: &Engine, node_key_id: &str, kind: CommunityKind) -> bool {
    let owner_bound = is_steward_bound(engine, node_key_id).await.is_some();
    may_join(kind, owner_bound)
}

/// **The serve-only-floor gate.** `Ok(responsible_user_key_id)` iff a live
/// owner-binding exists; `Err(())` for an UNOWNED node (it must refuse the
/// owner-op and fall back to serving cleartext from the canonical root only).
///
/// This is the operational producer of `owner_bound` for owner-requiring
/// routes (e.g. `POST /v1/federation/peering`): an unowned node refuses
/// owner-ops, period — independent of any session/role the caller presents.
pub async fn require_owner_bound(engine: &Engine, node_key_id: &str) -> Result<String, ()> {
    is_steward_bound(engine, node_key_id).await.ok_or(())
}

/// Render a [`DenyReason`] as the structured `403` a delegated caller receives.
/// Kept here (not in each handler) so every gated op rejects with the same shape.
pub fn deny_response(reason: DenyReason) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "error": "delegation_denied",
            "denied_by": reason.denied_by,
            "verb": reason.verb,
            "goal": reason.goal,
            "detail": reason.detail,
        })),
    )
        .into_response()
}

/// Convenience: run [`authorize_delegated`] and, on denial, return the ready `403`
/// [`deny_response`] to `return` from the handler. `None` when the caller may
/// proceed. (`Option`, not `Result`, so the large `Response` isn't a `result_large_err`.)
#[must_use]
pub fn require_verb(
    caller: &SessionCaller,
    verb: CapabilityVerb,
) -> Option<axum::response::Response> {
    authorize_delegated(caller, verb).err().map(deny_response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::roles::{permissions_for, UserRole};
    use crate::auth::session::DelegationConstraints;

    /// Build a SessionCaller: `actor=Some` ⇒ delegated (constraints apply).
    fn caller(actor: Option<&str>, constraints: Option<DelegationConstraints>) -> SessionCaller {
        SessionCaller {
            wa_id: "wa-owner".into(),
            name: actor.unwrap_or("owner").into(),
            role: UserRole::SystemAdmin,
            permissions: permissions_for(UserRole::SystemAdmin),
            constraints,
            actor: actor.map(str::to_string),
        }
    }

    #[test]
    fn non_delegated_owner_is_unconstrained() {
        // The owner acting directly passes every verb, incl. never-list ones.
        let c = caller(None, None);
        assert!(authorize_delegated(&c, CapabilityVerb::Announce).is_ok());
        assert!(authorize_delegated(&c, CapabilityVerb::Wipe).is_ok());
    }

    #[test]
    fn delegated_default_allows_non_never_verbs() {
        // A delegated grant with no constraints = legacy full grant (all but never).
        let c = caller(Some("agent-1"), Some(DelegationConstraints::default()));
        assert!(authorize_delegated(&c, CapabilityVerb::Announce).is_ok());
        assert!(authorize_delegated(&c, CapabilityVerb::Peer).is_ok());
    }

    #[test]
    fn never_list_blocks_even_the_default_grant() {
        let c = caller(Some("agent-1"), Some(DelegationConstraints::default()));
        let d = authorize_delegated(&c, CapabilityVerb::Delegate).unwrap_err();
        assert_eq!(d.denied_by, "never_list");
        assert!(authorize_delegated(&c, CapabilityVerb::Wipe).is_err());
    }

    #[test]
    fn allow_list_admits_only_listed_verbs() {
        let c = caller(
            Some("agent-1"),
            Some(DelegationConstraints {
                actions_allow: Some(vec!["announce".into()]),
                ..Default::default()
            }),
        );
        assert!(authorize_delegated(&c, CapabilityVerb::Announce).is_ok());
        let d = authorize_delegated(&c, CapabilityVerb::Peer).unwrap_err();
        assert_eq!(d.denied_by, "action_allow");
    }

    #[test]
    fn deny_list_overrides_allow() {
        let c = caller(
            Some("agent-1"),
            Some(DelegationConstraints {
                actions_allow: Some(vec!["announce".into(), "peer".into()]),
                actions_deny: vec!["peer".into()],
                ..Default::default()
            }),
        );
        assert!(authorize_delegated(&c, CapabilityVerb::Announce).is_ok());
        let d = authorize_delegated(&c, CapabilityVerb::Peer).unwrap_err();
        assert_eq!(d.denied_by, "action_deny");
    }

    #[test]
    fn tighten_only_never_widens_authority() {
        // Existing: announce-only. Approver tries to ADD "peer" to the allow-list →
        // the intersection keeps it announce-only (cannot widen).
        let existing = DelegationConstraints {
            actions_allow: Some(vec!["announce".into()]),
            ..Default::default()
        };
        let approver = DelegationConstraints {
            actions_allow: Some(vec!["announce".into(), "peer".into()]),
            ..Default::default()
        };
        let eff = existing.tightened_with(&approver);
        assert_eq!(
            eff.actions_allow,
            Some(vec!["announce".into()]),
            "intersection narrows"
        );

        // Approver adds a deny → it sticks (union of denials).
        let approver2 = DelegationConstraints {
            actions_deny: vec!["set_age".into()],
            goal: Some("mesh seed".into()),
            ..Default::default()
        };
        let eff2 = existing.tightened_with(&approver2);
        assert_eq!(
            eff2.actions_deny,
            vec!["set_age".to_string()],
            "deny union applied"
        );
        assert_eq!(
            eff2.goal.as_deref(),
            Some("mesh seed"),
            "approver sets the goal"
        );

        // An unconstrained existing + a restricting approver ⇒ the restriction.
        let eff3 = DelegationConstraints::default().tightened_with(&existing);
        assert_eq!(
            eff3.actions_allow,
            Some(vec!["announce".into()]),
            "approver narrows an open grant"
        );
    }

    #[test]
    fn infra_joinable_without_owner_other_is_not() {
        assert!(may_join(CommunityKind::Infrastructure, false));
        assert!(may_join(CommunityKind::Infrastructure, true));
        assert!(!may_join(CommunityKind::Other, false));
        assert!(may_join(CommunityKind::Other, true));
    }
}
