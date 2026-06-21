//! **Generic CEWP family operations** over persist's family CEG DX
//! (`federation_families` + the §11.7.1 membership-revocation forward-secrecy
//! primitive). This layer is deliberately **NOT accord-aware** — it is the reusable
//! "a group of trusted identity keys, with a consensus protocol" primitive that any
//! CEWP family (a household, an org, …) uses. The HUMANITY_ACCORD kill-switch is
//! ONE specialization layered on top of it (see [`crate::accord`]).
//!
//! ## The model (persist-native)
//! - A family is a `federation_families` row keyed by `family_key_id` (which MUST
//!   be a registered `federation_keys` identity — the FK).
//! - The **live roster** is always [`active_members`] = the admitted roster MINUS
//!   the effective membership revocations (`active_family_members`). Reads compose
//!   the append-only revocation table, so membership is forward-secret.
//! - A member **SWAP** ([`swap_member`]) is therefore `revoke_member` + `add_member`:
//!   the leaving seat goes inactive, the incoming key activates, and the active
//!   roster size is preserved — no extra seat is ever added.
//!
//! Authorization of a mutation (who may create a family / add / revoke / swap) is
//! the CALLER's concern (the family's `consensus_protocol`), not this module's —
//! these are the mechanism, the policy lives in the specialization.

use ciris_persist::federation::cohort::Cohort;
use ciris_persist::federation::types::{
    Family, FamilyMember, FamilyMembershipRevocation, SignedFamily,
    SignedFamilyMembershipRevocation,
};
use ciris_persist::federation::Error as FedError;
use ciris_persist::prelude::Engine;
use ciris_verify_core::threshold::ThresholdMember;

/// Resolving a family roster to its pinned pubkeys can fail two ways.
#[derive(Debug)]
pub enum RosterError {
    /// A persist store fault.
    Store(FedError),
    /// A live member has no `federation_keys` row (roster references a key that was
    /// never registered / was removed) — fail-closed for a threshold set.
    UnregisteredMember(String),
}

impl std::fmt::Display for RosterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RosterError::Store(e) => write!(f, "store: {e}"),
            RosterError::UnregisteredMember(k) => {
                write!(f, "family member {k} has no registered federation key")
            }
        }
    }
}

/// Create / entrench a family. `family.family_key_id` MUST already be a registered
/// `federation_keys` identity (the FK). Idempotent on `family_key_id`. persist
/// admits on value-validation (closed-set + `consensus_protocol` canonical form).
pub async fn create_family(engine: &Engine, family: Family) -> Result<(), FedError> {
    engine
        .federation_directory()
        .put_family(SignedFamily { family })
        .await
}

/// Fetch a family by `family_key_id` (full admitted record, no revocation filter).
pub async fn lookup(engine: &Engine, family_key_id: &str) -> Result<Option<Family>, FedError> {
    engine
        .federation_directory()
        .lookup_family(family_key_id)
        .await
}

/// Add one identity to a family roster (idempotent on `member.key_id` — an existing
/// member is a no-op returning `Ok(false)`). The family must exist.
pub async fn add_member(
    engine: &Engine,
    family_key_id: &str,
    member: FamilyMember,
) -> Result<bool, FedError> {
    engine
        .federation_directory()
        .add_family_member(family_key_id, member)
        .await
}

/// The **LIVE roster** — admitted members MINUS effective revocations. This is the
/// authoritative "who is currently in the family" set.
pub async fn active_members(
    engine: &Engine,
    family_key_id: &str,
) -> Result<Vec<FamilyMember>, FedError> {
    engine
        .federation_directory()
        .active_family_members(family_key_id)
        .await
}

/// Record a membership removal (append-only; the active reads filter against it).
pub async fn revoke_member(
    engine: &Engine,
    revocation: FamilyMembershipRevocation,
) -> Result<(), FedError> {
    engine
        .federation_directory()
        .put_family_membership_revocation(SignedFamilyMembershipRevocation {
            family_membership_revocation: revocation,
        })
        .await
}

/// **Swap one seat**: revoke `revocation.removed_identity_key_id`, then add
/// `incoming`. The active roster stays the same size — the incoming key takes the
/// leaving key's place. (The CALLER authorizes this per the family's
/// `consensus_protocol`; e.g. the accord requires a 2/3 quorum.)
pub async fn swap_member(
    engine: &Engine,
    family_key_id: &str,
    revocation: FamilyMembershipRevocation,
    incoming: FamilyMember,
) -> Result<(), FedError> {
    revoke_member(engine, revocation).await?;
    add_member(engine, family_key_id, incoming).await?;
    Ok(())
}

/// Resolve a family's LIVE roster to verify [`ThresholdMember`]s — each member's
/// pinned Ed25519 + ML-DSA-65 pubkeys from `federation_keys`. The generic
/// "threshold set" view of any family whose members are federation identities; the
/// accord kill-switch resolves its quorum set through exactly this. Fail-closed: a
/// live member with no registered key is a [`RosterError::UnregisteredMember`].
pub async fn active_threshold_roster(
    engine: &Engine,
    family_key_id: &str,
) -> Result<Vec<ThresholdMember>, RosterError> {
    let dir = engine.federation_directory();
    // A not-yet-created family is an EMPTY roster, not an error (persist's
    // active_member_keys errors InvalidArgument on an unknown family).
    if dir
        .lookup_family(family_key_id)
        .await
        .map_err(RosterError::Store)?
        .is_none()
    {
        return Ok(Vec::new());
    }
    // Substrate-native (CIRISPersist#249 G1): persist resolves the LIVE roster →
    // pinned hybrid KeyRecords in one call, with its own broken-roster guard
    // (refuses to undercount a quorum). No hand-rolled per-member lookup.
    let keys = dir
        .active_member_keys(Cohort::Family, family_key_id)
        .await
        .map_err(RosterError::Store)?;
    Ok(keys
        .into_iter()
        .map(|rec| ThresholdMember {
            member_id: rec.key_id,
            ed25519_public_key_base64: rec.pubkey_ed25519_base64,
            mldsa65_public_key_base64: rec.pubkey_ml_dsa_65_base64,
            // Role is only consulted by founder-quorum verifiers (genesis);
            // invocation verification matches by member_id, so None is correct.
            role: None,
        })
        .collect())
}
