#![allow(dead_code)] // scaffold surface — wired by the next auth slices (registry-fold #2 + agent migration).

//! The owner-binding gate (CIRISServer#9) — the NEW CIRISServer authz rule.
//! CEG has the primitives but does not mandate it (filed as the optional
//! normative rule in CIRISRegistry#83).
//!
//! **TRUST ≠ JOIN.** A node may *trust + serve* an infrastructure community
//! (relay/store/transport/serve reads — e.g. the shipped ciris-canonical pin)
//! with **no owner**. It may *join* (become a member: share the DEK, count in
//! consensus) a **non-infrastructure** community only after a **user is bound**
//! (via self-at-login: `identity_occurrence` + `delegates_to`). Non-infra
//! membership is an authority act, which §1.5/§7.0.1 require to root in an
//! accountable human — never a bare node.

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
/// whether an accountable owner is bound to it? (Trust + serve is always
/// allowed and is NOT gated here — this governs *membership* only.)
pub fn may_join(kind: CommunityKind, owner_bound: bool) -> bool {
    match kind {
        CommunityKind::Infrastructure => true,
        CommunityKind::Other => owner_bound,
    }
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
