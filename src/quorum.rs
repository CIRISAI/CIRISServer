//! The `ciris-canonical` 2-of-3 founder-quorum — the steward-key replacement.
//!
//! The old federation trust root was a single **shared vaulted steward key**
//! (registry-us and registry-eu held one secret). That is retired: authority is
//! now an **entrenched M-of-N founder-quorum** over the three `ciris-canonical`
//! per-node keys (the three fabric nodes' own keys). A node gains a *vote*, never
//! a *verdict* (MISSION §1.5; CEG §8.1.13.1.1 founder-subset eval).
//!
//! This module is shared infrastructure: the registry slice uses it for the
//! trust root at Server 0.5, but the construction + verification live here (over
//! the verify v5.4.0 `infrastructure_community` + `threshold` primitives) so the
//! fold is mechanical. See FSD/REGISTRY_FOLD_DERISK.md.

use anyhow::{Context, Result};
use ciris_verify_core::infrastructure_community::{
    infrastructure_community_signing_bytes, InfrastructureCommunity, InfrastructureConstraint,
};
use ciris_verify_core::threshold::{
    verify_quorum_policy, QuorumPolicy, Role, ThresholdMember, ThresholdSignature,
};

/// The canonical trust-root community id consumers re-root their pin to
/// (replacing the steward-key fingerprint). Matches the lens slice's
/// `CIRIS_CANONICAL_COMMUNITY_KEY_ID`.
pub const CANONICAL_COMMUNITY_KEY_ID: &str = "ciris-canonical";

/// The entrenched consensus protocol for the canonical trust root.
pub const CANONICAL_CONSENSUS_PROTOCOL: &str = "quorum:2/3";

/// Build the `ciris-canonical` infrastructure community (the trust root) from its
/// founder members — an entrenched 2-of-3 founder-quorum over the three canonical
/// per-node keys. `is_trust_root_conformant()` holds by construction.
pub fn canonical_community(founders: Vec<ThresholdMember>) -> InfrastructureCommunity {
    InfrastructureCommunity {
        schema_version: 1,
        community_key_id: CANONICAL_COMMUNITY_KEY_ID.to_string(),
        community_name: "CIRIS Canonical Services".to_string(),
        cohort_subkind: "infrastructure".to_string(),
        infrastructure_constraint: InfrastructureConstraint {
            service_class: "canonical".to_string(),
            admission_quorum_basis: "founders".to_string(),
        },
        members: founders,
        consensus_protocol: CANONICAL_CONSENSUS_PROTOCOL.to_string(),
        consensus_protocol_entrenched: true,
    }
}

/// Verify a founder-quorum signature set over `bytes` against `community`'s
/// declared `consensus_protocol` (e.g. 2-of-3). The m-of-n that supersedes the
/// single steward key: non-founder / wrong-role signatures don't count
/// (anti-Sybil), and the declared N must equal the founder roster.
pub fn verify_canonical_quorum(
    community: &InfrastructureCommunity,
    bytes: &[u8],
    signatures: &[ThresholdSignature],
) -> Result<usize> {
    let policy = QuorumPolicy::parse(&community.consensus_protocol).with_context(|| {
        format!("invalid consensus_protocol {:?}", community.consensus_protocol)
    })?;
    verify_quorum_policy(bytes, &community.members, signatures, policy)
        .map_err(|e| anyhow::anyhow!("founder-quorum verify failed: {e}"))
}

/// The canonical-bytes a founder signs / a verifier checks for this community
/// (domain-separated; member-order-independent).
pub fn community_signing_bytes(community: &InfrastructureCommunity) -> Vec<u8> {
    infrastructure_community_signing_bytes(community)
}

/// A founder member from its base64 Ed25519 pubkey (+ optional ML-DSA-65 for the
/// hybrid half). `role = Founder` so it counts toward the founder-quorum.
pub fn founder_member(
    member_id: impl Into<String>,
    ed25519_public_key_base64: impl Into<String>,
    mldsa65_public_key_base64: Option<String>,
) -> ThresholdMember {
    ThresholdMember {
        member_id: member_id.into(),
        ed25519_public_key_base64: ed25519_public_key_base64.into(),
        mldsa65_public_key_base64,
        role: Some(Role::Founder),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn founders() -> Vec<ThresholdMember> {
        vec![
            founder_member("lens", "AAAA", None),
            founder_member("registry-us", "BBBB", None),
            founder_member("registry-eu", "CCCC", None),
        ]
    }

    #[test]
    fn canonical_community_is_a_conformant_entrenched_2of3_trust_root() {
        let c = canonical_community(founders());
        assert!(c.is_trust_root_conformant(), "must be a conformant trust root");
        assert_eq!(c.community_key_id, CANONICAL_COMMUNITY_KEY_ID);
        assert!(c.consensus_protocol_entrenched);
        assert_eq!(c.infrastructure_constraint.admission_quorum_basis, "founders");

        let p = QuorumPolicy::parse(&c.consensus_protocol).expect("parse consensus_protocol");
        assert_eq!((p.m, p.n), (2, 3), "2-of-3");

        // Domain-separated signing bytes are produced + stable across member order.
        let mut reordered = founders();
        reordered.reverse();
        let c2 = canonical_community(reordered);
        assert!(!community_signing_bytes(&c).is_empty());
        assert_eq!(
            community_signing_bytes(&c),
            community_signing_bytes(&c2),
            "signing bytes must be member-order-independent"
        );
    }

    #[test]
    fn empty_signature_set_does_not_meet_quorum() {
        let c = canonical_community(founders());
        let bytes = community_signing_bytes(&c);
        // No signatures → cannot reach 2-of-3 (verify returns an error).
        assert!(verify_canonical_quorum(&c, &bytes, &[]).is_err());
    }
}
