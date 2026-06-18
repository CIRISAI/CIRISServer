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
//! owned member. [`is_owner_bound`] is the producer of the `owner_bound` bit;
//! [`require_owner_bound`] is the operational gate.

use ciris_persist::prelude::Engine;

pub use crate::auth::ownership::is_owner_bound;

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
    let owner_bound = is_owner_bound(engine, node_key_id).await.is_some();
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
    is_owner_bound(engine, node_key_id).await.ok_or(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infra_joinable_without_owner_other_is_not() {
        assert!(may_join(CommunityKind::Infrastructure, false));
        assert!(may_join(CommunityKind::Infrastructure, true));
        assert!(!may_join(CommunityKind::Other, false));
        assert!(may_join(CommunityKind::Other, true));
    }
}
