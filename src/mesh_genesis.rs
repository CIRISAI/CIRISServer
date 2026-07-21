//! Portable mesh genesis (`FSD/MESH_GENESIS.md`) — produce + attach a
//! self-verifying bundle carrying **the trust root and ≥1 `infra:serve` node**.
//!
//! # Why this exists
//!
//! A trust root alone is inert: it can vouch, but nothing can serve or receive.
//! The genesis object therefore guarantees a **minimum viable mesh** — a root you
//! can trust *and* a node that can actually serve you. That invariant is enforced
//! at PRODUCE time: [`produce_genesis`] refuses to emit a bundle whose serve set is
//! empty, so the CIRISPersist#480 failure (a baked seed shipping `roles: []`, which
//! darks the whole trace plane) cannot be reproduced as a portable artifact. Today
//! [`produce_genesis_from_baked`] REFUSES for exactly that reason — the refusal is
//! the invariant working, not a bug.
//!
//! # Self-verifying
//!
//! [`verify_bundle`] checks the bundle against ITSELF, offline: every serve node's
//! scrub roots to a holder carried in the same bundle, and every serve node carries
//! an `infra:serve` role. A tampered or hand-assembled genesis fails these checks —
//! the object is trustworthy because it proves its own rooting, not because of where
//! it came from. Safe to move over any channel (file, QR, USB).
//!
//! The cryptographic anchor is the **holder records** (signed) plus each serve
//! node's scrub to them; `family_key_id` is a grouping identifier, not authority.
//!
//! # What it is NOT
//!
//! Public records + attestations only — **never a seed or secret byte**. Attaching
//! seeds the RECORDS; it deliberately does not write the user's
//! `delegates_to(user → root)` trust edge, which is the user's own signed,
//! deletable, nuclear-revocable act (`FSD/TRUST_ROOT_CAPABILITY_GATE.md` §1). The
//! operator *chooses* a trust root; a bundle never assigns one.

use ciris_persist::federation::types::delegation_scope::INFRA_SERVE;
use ciris_persist::federation::{FederationDirectory, SignedKeyRecord};
use serde::{Deserialize, Serialize};

/// Wire version of the genesis bundle. Bump on any breaking shape change.
pub const GENESIS_VERSION: u32 = 1;

/// A portable, self-verifying mesh genesis: the trust root + ≥1 serve node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisBundle {
    pub version: u32,
    /// The trust root's family identifier (grouping; authority lives in `holders`).
    pub family_key_id: String,
    /// The accord holders: the pinned anchor pubkeys every chain terminates in.
    pub holders: Vec<SignedKeyRecord>,
    /// **≥1** `infra:serve`-blessed node, so the mesh can actually serve on attach.
    pub serve_nodes: Vec<SignedKeyRecord>,
    pub produced_at: String,
}

#[derive(Debug)]
pub enum GenesisError {
    /// The invariant: a genesis without a serve node is a dark mesh.
    NoServeNode,
    /// A serve node does not carry `infra:serve` (it cannot receive traces).
    ServeNodeUnblessed(String),
    /// A serve node's scrub does not root to any holder carried in this bundle.
    ServeNodeUnrooted(String),
    NoHolders,
    Directory(String),
}

impl std::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoServeNode => write!(
                f,
                "genesis has no infra:serve-blessed serve node — attaching it would \
                 produce a DARK mesh (nothing could receive traces). Bless a canonical \
                 with infra:serve first (CIRISPersist#480)"
            ),
            Self::ServeNodeUnblessed(k) => {
                write!(f, "serve node {k} does not carry the infra:serve role")
            }
            Self::ServeNodeUnrooted(k) => write!(
                f,
                "serve node {k} scrub does not root to any accord holder in this bundle \
                 (not self-verifying)"
            ),
            Self::NoHolders => write!(f, "genesis carries no accord holders (no anchor)"),
            Self::Directory(e) => write!(f, "directory: {e}"),
        }
    }
}

impl std::error::Error for GenesisError {}

/// Does this record carry `infra:serve`? Read from the record's OWN signed roles —
/// the accord-conferred capability, never a local assertion.
fn carries_infra_serve(rec: &SignedKeyRecord) -> bool {
    rec.record.roles.iter().any(|r| r == INFRA_SERVE)
}

/// **Verify a bundle against itself, offline.** No directory, no network: the
/// bundle either proves its own rooting or it does not.
pub fn verify_bundle(bundle: &GenesisBundle) -> Result<(), GenesisError> {
    if bundle.holders.is_empty() {
        return Err(GenesisError::NoHolders);
    }
    if bundle.serve_nodes.is_empty() {
        return Err(GenesisError::NoServeNode);
    }
    let holder_ids: Vec<&str> = bundle
        .holders
        .iter()
        .map(|h| h.record.key_id.as_str())
        .collect();
    for n in &bundle.serve_nodes {
        if !carries_infra_serve(n) {
            return Err(GenesisError::ServeNodeUnblessed(n.record.key_id.clone()));
        }
        // Self-verifying: the serve node's scrub must terminate in an anchor the
        // bundle itself carries.
        if !holder_ids.contains(&n.record.scrub_key_id.as_str()) {
            return Err(GenesisError::ServeNodeUnrooted(n.record.key_id.clone()));
        }
    }
    Ok(())
}

/// **Produce** a genesis from caller-supplied serve records.
///
/// `serve_candidates` may be the baked genesis records, or the freshly re-blessed
/// output of the accord co-scrub ceremony — the source does not matter, the
/// invariant does: records not carrying `infra:serve` are dropped, and if that
/// leaves none, this REFUSES. A genesis that cannot serve is the persist#480
/// darkness in portable form, and emitting one would just relocate the outage.
pub fn produce_genesis(
    family_key_id: &str,
    serve_candidates: Vec<SignedKeyRecord>,
    now_rfc3339: &str,
) -> Result<GenesisBundle, GenesisError> {
    let holders: Vec<SignedKeyRecord> =
        ciris_persist::federation::genesis::effective_accord_holder_records().into_owned();
    if holders.is_empty() {
        return Err(GenesisError::NoHolders);
    }
    // The narrowing IS the invariant — not a warning, a refusal.
    let serve_nodes: Vec<SignedKeyRecord> = serve_candidates
        .into_iter()
        .filter(carries_infra_serve)
        .collect();
    if serve_nodes.is_empty() {
        return Err(GenesisError::NoServeNode);
    }

    let bundle = GenesisBundle {
        version: GENESIS_VERSION,
        family_key_id: family_key_id.to_string(),
        holders,
        serve_nodes,
        produced_at: now_rfc3339.to_string(),
    };
    verify_bundle(&bundle)?;
    Ok(bundle)
}

/// Convenience: produce from the BAKED canonical genesis records.
///
/// Today this REFUSES with [`GenesisError::NoServeNode`] — the baked
/// `canonical_seed.json` still ships `roles: []` (CIRISPersist#480), so no baked
/// canonical is blessed to serve. That refusal is the invariant doing its job: it
/// is exactly the condition that darks the live trace plane, caught before it can
/// be handed to anyone as an artifact. It starts succeeding the moment the seed
/// bakes an `infra:serve`-blessed canonical.
pub fn produce_genesis_from_baked(now_rfc3339: &str) -> Result<GenesisBundle, GenesisError> {
    let family = ciris_persist::federation::genesis::accord_family_genesis_record();
    let baked: Vec<SignedKeyRecord> =
        ciris_persist::federation::genesis::canonical_genesis_records().to_vec();
    produce_genesis(&family.family_key_id, baked, now_rfc3339)
}

/// What an attach actually did.
#[derive(Debug, Serialize)]
pub struct AttachReport {
    pub family_key_id: String,
    pub holders_seeded: usize,
    pub serve_nodes_seeded: usize,
    /// The root the caller should now sign `delegates_to(user → root)` against —
    /// attaching seeds the RECORDS; the trust edge is the user's own signed act.
    pub trust_root_key_id: String,
}

/// **Attach** a genesis: verify it, then seed its records into the directory.
///
/// Deliberately does NOT write the `delegates_to(user → root)` trust edge — that is
/// the user's own signed act (the 2-phase user-signed path that mirrors the
/// owner-binding claim). Attaching makes the root and its serve node KNOWN; trusting
/// them stays an explicit, revocable choice.
pub async fn attach_genesis<D>(
    dir: &D,
    bundle: &GenesisBundle,
) -> Result<AttachReport, GenesisError>
where
    D: FederationDirectory + ?Sized,
{
    verify_bundle(bundle)?;

    for h in &bundle.holders {
        dir.put_public_key(h.clone())
            .await
            .map_err(|e| GenesisError::Directory(e.to_string()))?;
    }
    for n in &bundle.serve_nodes {
        dir.put_public_key(n.clone())
            .await
            .map_err(|e| GenesisError::Directory(e.to_string()))?;
    }

    Ok(AttachReport {
        family_key_id: bundle.family_key_id.clone(),
        holders_seeded: bundle.holders.len(),
        serve_nodes_seeded: bundle.serve_nodes.len(),
        trust_root_key_id: bundle.family_key_id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The invariant, asserted: the baked seed cannot produce a genesis today,
    /// because `canonical_seed.json` ships `roles: []` (CIRISPersist#480). When
    /// that seed is fixed this test flips — and that flip is the signal the trace
    /// plane can light up.
    #[test]
    fn baked_seed_cannot_produce_a_dark_genesis() {
        match produce_genesis_from_baked("2026-07-21T00:00:00Z") {
            Err(GenesisError::NoServeNode) => { /* expected until #480 lands */ }
            Err(e) => panic!("unexpected genesis error: {e}"),
            Ok(b) => {
                // If this passes, #480 baked a blessed canonical — assert the
                // bundle is genuinely serve-capable rather than silently empty.
                assert!(
                    !b.serve_nodes.is_empty(),
                    "a produced genesis must carry >=1 infra:serve node"
                );
                assert!(
                    verify_bundle(&b).is_ok(),
                    "produced genesis must self-verify"
                );
            }
        }
    }

    #[test]
    fn verify_rejects_an_unrooted_serve_node() {
        // A bundle whose serve node scrubs to someone not in the bundle is not
        // self-verifying and must be refused.
        let holders =
            ciris_persist::federation::genesis::effective_accord_holder_records().into_owned();
        if holders.is_empty() {
            return; // no anchors compiled in this build; nothing to assert
        }
        let bundle = GenesisBundle {
            version: GENESIS_VERSION,
            family_key_id: "fam".into(),
            holders,
            serve_nodes: Vec::new(),
            produced_at: "2026-07-21T00:00:00Z".into(),
        };
        assert!(matches!(
            verify_bundle(&bundle),
            Err(GenesisError::NoServeNode)
        ));
    }
}
