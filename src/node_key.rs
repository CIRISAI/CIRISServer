//! # The node key is its OWN key (CC 3.4.7.3, CIRISConstitution#95)
//!
//! ## What was wrong
//!
//! A node's substrate identity — the Reticulum transport identity, `self_key_id`,
//! the de-admission self — was whatever key the host process handed us. When
//! CIRISServer runs standalone that is a `node`-typed key and everything is
//! correct. When CIRISAgent **embeds** us, it is the agent's own bootstrap key,
//! and it is `identity_type = agent`.
//!
//! Observed in production, one key answering two questions:
//!
//! ```text
//! key_id         ciris-agent-bootstrap-mplbdbzbed
//! identity_type  agent
//!
//! de-admission gate ARMED — self_key_id=ciris-agent-bootstrap-mplbdbzbed
//! Reticulum transport identity: … key_id=ciris-agent-bootstrap-mplbdbzbed
//! ```
//!
//! `register_self_key` *tried* to register that id as `node` and could not:
//! `register_federation_key` is `ON CONFLICT DO NOTHING`, so the agent's
//! pre-existing `agent` row was sticky and our attempt was a silent no-op. The
//! node never had an identity of its own; it borrowed the brain's.
//!
//! ## Why a second KEY and not a second ROLE
//!
//! `identity_type` is a set, so `{node, agent}` is expressible — and it is
//! exactly the loophole. persist's agency gate constrains a recipient that
//! resolves to a **node-only** identity; a `{node,agent}` hybrid passes it. Fusing
//! the roles onto one key does not merely blur the distinction, it **switches off
//! the rule that enforces it**.
//!
//! CC 3.4.7.3 Clause A therefore makes `node` non-cohabitable with `agent` and
//! with `user`. Infrastructure-ness is exclusive: a key is substrate or actor,
//! never both.
//!
//! ## The shape
//!
//! Exactly the move [`crate::compose::substrate_persist_signer`] already makes
//! for reserved-prefix authority, for the same reason — one authority per key:
//!
//! | key | alias | identity_type | signs |
//! |---|---|---|---|
//! | actor (host-supplied) | `<alias>` | `agent` / `user` | traces, brain ops, authorship |
//! | **node** | `<alias>-node` | `node` | transport, replication, serve, de-admission |
//! | substrate | `<alias>-substrate` | `substrate_persist` | reserved-prefix rows |
//!
//! The actor key is **never modified**. Its registration envelope binds
//! `identity_type = agent` inside the signed bytes (CIRISPersist#659), so
//! re-typing it would mean re-minting a signed envelope through an accord-holder
//! scrub — the expensive path — and would retroactively make every historical
//! trace node-authored. Minting a fresh node key touches no signature at all.
//!
//! ## Ownership follows the node, not the brain
//!
//! The owner-binding names the NODE (`purpose = responsible_for`, `infra:*`-only
//! scope, and an explicit `node_key_id` field). Under the fused key it pointed at
//! the actor. [`plan_owner_binding_move`] reports the re-issue that puts it on the
//! node key; the agent↔node relation itself needs no edge, because CC 3.4.7.3
//! Clause D derives it: an agent may act through a node iff the node's single
//! owner appears in the agent's steward set.

use anyhow::{Context, Result};
use ciris_keyring::{HardwareSigner, MlDsa65SoftwareSigner, PqcSigner, SealedEd25519Signer};
use ciris_persist::federation::types::identity_type;
use ciris_persist::federation::FederationDirectory;
use std::sync::Arc;

/// The keystore-alias suffix for the node's own key. Parallel to `-substrate`.
pub const NODE_ALIAS_SUFFIX: &str = "-node";

/// What a key is allowed to be, once we look at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityVerdict {
    /// `node` and nothing that conflicts — usable as the substrate identity.
    SubstrateOnly,
    /// Carries `agent` or `user`. An actor. MUST NOT be a node identity.
    Actor { roles: Vec<String> },
    /// Carries `node` AND an actor role — the CC 3.4.7.3 Clause A violation, and
    /// the one that silently disables the agency gate.
    Fused { roles: Vec<String> },
    /// No row for this key_id in the directory.
    Unregistered,
}

impl IdentityVerdict {
    /// May this key serve as the node's substrate identity?
    #[must_use]
    pub fn usable_as_node(&self) -> bool {
        matches!(self, Self::SubstrateOnly)
    }
}

/// Split an `identity_type` cell into its role set.
///
/// persist stores the set comma-joined (CC 3.4.7.1: `agent,lenscore_detector`),
/// so membership is a split-and-compare, never `==`. A scalar is the singleton.
#[must_use]
pub fn roles_of(cell: &str) -> Vec<String> {
    cell.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The actor roles — the ones CC 3.4.7.3 Clause A forbids beside `node`.
#[must_use]
pub fn is_actor_role(role: &str) -> bool {
    role == identity_type::AGENT || role == identity_type::USER
}

/// Classify a key_id against the directory.
///
/// # Errors
/// Propagates a directory read failure. An unreadable directory is NOT reported
/// as `Unregistered` — "we could not look" and "it is not there" are different
/// states and must not share a value.
pub async fn classify(dir: &dyn FederationDirectory, key_id: &str) -> Result<IdentityVerdict> {
    let Some(rec) = dir.lookup_public_key(key_id).await? else {
        return Ok(IdentityVerdict::Unregistered);
    };
    let roles = roles_of(&rec.identity_type);
    let has_node = roles.iter().any(|r| r == identity_type::NODE);
    let actors: Vec<String> = roles.iter().filter(|r| is_actor_role(r)).cloned().collect();
    Ok(match (has_node, actors.is_empty()) {
        (true, false) => IdentityVerdict::Fused { roles },
        (false, false) => IdentityVerdict::Actor { roles },
        _ => IdentityVerdict::SubstrateOnly,
    })
}

/// The keystore alias the node's own key lives under, given the host's alias.
#[must_use]
pub fn node_alias(keystore_alias: &str) -> String {
    // Idempotent: a host that already passes `<x>-node` does not get `<x>-node-node`.
    if keystore_alias.ends_with(NODE_ALIAS_SUFFIX) {
        return keystore_alias.to_owned();
    }
    format!("{keystore_alias}{NODE_ALIAS_SUFFIX}")
}

/// What must move when a fused key is split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerBindingMove {
    /// The human who owns the node.
    pub owner_key_id: String,
    /// Where the binding points today (the fused key).
    pub from_key_id: String,
    /// Where it must point (the node key).
    pub to_key_id: String,
}

/// Plan the owner-binding re-issue for a split.
///
/// Returns `None` when the node has no owner — which is NOT an error here: an
/// unowned node is a real, common state (a node claims ownership later via
/// `POST /v1/setup/root`), and reporting it as a failure would block boot on a
/// condition the operator is expected to resolve at their leisure.
///
/// It IS load-bearing downstream, though: CC 3.4.7.3 Clause D is fail-closed, so
/// an unowned node cannot answer `may_act_through` at all.
///
/// # Errors
/// Propagates directory read failures.
pub async fn plan_owner_binding_move(
    dir: &dyn FederationDirectory,
    fused_key_id: &str,
    node_key_id: &str,
) -> Result<Option<OwnerBindingMove>> {
    let owner = ciris_persist::federation::admission::owner_of(dir, fused_key_id).await?;
    Ok(owner.map(|owner_key_id| OwnerBindingMove {
        owner_key_id,
        from_key_id: fused_key_id.to_owned(),
        to_key_id: node_key_id.to_owned(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_comma_joined_cell_is_a_set() {
        assert_eq!(roles_of("canonical,node"), vec!["canonical", "node"]);
        assert_eq!(roles_of("agent"), vec!["agent"]);
        assert_eq!(roles_of(" agent , node "), vec!["agent", "node"]);
        assert!(roles_of("").is_empty());
    }

    /// The whole point of Clause A: `{node,agent}` is the composition that
    /// switches the agency gate OFF, so it must classify as its own verdict and
    /// never as either half.
    #[test]
    fn a_fused_key_is_neither_substrate_nor_merely_an_actor() {
        let fused = IdentityVerdict::Fused {
            roles: roles_of("node,agent"),
        };
        assert!(!fused.usable_as_node());
        assert_ne!(
            fused,
            IdentityVerdict::Actor {
                roles: roles_of("node,agent")
            }
        );
    }

    #[test]
    fn only_a_pure_substrate_key_may_be_the_node() {
        assert!(IdentityVerdict::SubstrateOnly.usable_as_node());
        assert!(!IdentityVerdict::Actor {
            roles: vec!["agent".into()]
        }
        .usable_as_node());
        assert!(!IdentityVerdict::Unregistered.usable_as_node());
    }

    #[test]
    fn user_is_an_actor_role_too() {
        assert!(is_actor_role("agent"));
        assert!(is_actor_role("user"));
        assert!(!is_actor_role("node"));
        assert!(!is_actor_role("substrate_persist"));
        // The CC 3.4.7.1 worked example stays conformant — the carve-out is at
        // the actor/substrate axis, not at "two roles".
        assert!(!is_actor_role("lenscore_detector"));
        assert!(!is_actor_role("witness"));
    }

    #[test]
    fn the_node_alias_is_idempotent() {
        assert_eq!(
            node_alias("ciris-agent-bootstrap"),
            "ciris-agent-bootstrap-node"
        );
        assert_eq!(
            node_alias("ciris-agent-bootstrap-node"),
            "ciris-agent-bootstrap-node"
        );
    }
}

/// Mint (or re-open) the node's OWN hybrid signer under `<alias>-node`.
///
/// Byte-for-byte the shape of [`crate::compose::substrate_persist_signer`],
/// because it is the same move for the same reason: an authority the host key
/// may not hold gets its own key rather than another role on a shared one.
/// Sealed Ed25519 + a software ML-DSA-65 seed, both open-or-mint, so the
/// identity is stable across restarts.
///
/// # Errors
/// Keystore open/mint failure, seed IO, or signer composition failure.
pub async fn node_signer(
    keystore_alias: &str,
    identity_dir: &std::path::Path,
) -> Result<(
    Arc<ciris_persist::prelude::LocalSigner>,
    ciris_verify_core::self_at_login::HardwareRootedIdentity,
)> {
    let alias = node_alias(keystore_alias);

    let ed: Arc<dyn HardwareSigner> = Arc::from(
        SealedEd25519Signer::open_or_create(alias.clone(), identity_dir.to_path_buf(), None)
            .map(|s| Box::new(s) as Box<dyn HardwareSigner>)
            .map_err(|e| anyhow::anyhow!("open-or-mint node Ed25519 signer: {e}"))?,
    );

    let pqc_alias = format!("{alias}-pqc");
    let pqc_path = identity_dir.join("node_ml_dsa_65.seed");
    let pqc = if pqc_path.exists() {
        MlDsa65SoftwareSigner::from_seed_file(&pqc_path, pqc_alias.clone())
            .map_err(|e| anyhow::anyhow!("adopt node ML-DSA-65 seed: {e}"))?
    } else {
        let mut seed = [0u8; 32];
        ciris_crypto::random::fill(&mut seed)
            .map_err(|e| anyhow::anyhow!("mint node ML-DSA-65 seed: {e}"))?;
        std::fs::write(&pqc_path, seed).with_context(|| format!("write {}", pqc_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&pqc_path, std::fs::Permissions::from_mode(0o600));
        }
        MlDsa65SoftwareSigner::from_seed_bytes(&seed, pqc_alias.clone())
            .map_err(|e| anyhow::anyhow!("load minted node ML-DSA-65 seed: {e}"))?
    };
    let pqc: Arc<dyn PqcSigner> = Arc::new(pqc);

    let signer = Arc::new(
        ciris_persist::prelude::LocalSigner::from_hardware_parts(
            ed.clone(),
            alias.clone(),
            Some(pqc.clone()),
            Some(pqc_alias),
        )
        .await
        .map_err(|e| anyhow::anyhow!("compose node LocalSigner: {e}"))?,
    );
    let identity = ciris_verify_core::self_at_login::HardwareRootedIdentity::new(
        signer.derived_key_id(),
        ed,
        pqc,
    )
    .map_err(|e| anyhow::anyhow!("build node self-signer identity: {e}"))?;
    Ok((signer, identity))
}

/// Register the node's own key as `identity_type = node`.
///
/// Self-signed proof-of-possession through the canonical
/// `register_federation_key` gate — the same fail-secure hybrid-verify the host
/// key and the substrate key both take. Idempotent: a matching row is `Ok`, and a
/// benign `Conflict` (the row is already there) is `Ok`.
///
/// The envelope is verify's RICH producer, so it binds `key_id` + BOTH pubkeys +
/// `identity_type` (CIRISPersist#659). That matters more here than anywhere: this
/// key's whole purpose is to assert `node` and nothing else, and an envelope that
/// did not NAME `node` would stand for any record it was pasted onto.
///
/// # Errors
/// Producer, bridge, or a non-conflict registration failure.
pub async fn register_node_key(
    engine: &ciris_persist::prelude::Engine,
    identity: &ciris_verify_core::self_at_login::HardwareRootedIdentity,
) -> Result<String> {
    use ciris_persist::federation::{Error as FederationError, SignedKeyRecord};
    use ciris_verify_core::federation_self_record::produce_self_key_record;

    let valid_from = chrono::Utc::now().to_rfc3339();
    let v_rec = produce_self_key_record(identity, identity_type::NODE, &valid_from, &[])
        .await
        .map_err(|e| anyhow::anyhow!("produce node self key record: {e}"))?;
    let signed: SignedKeyRecord = serde_json::from_value(serde_json::to_value(&v_rec)?)
        .map_err(|e| anyhow::anyhow!("bridge verify→persist node SignedKeyRecord: {e}"))?;
    let key_id = signed.record.key_id.clone();

    match engine.register_federation_key(signed).await {
        Ok(()) => {
            tracing::info!(node_key_id = %key_id, "node key registered (identity_type=node)");
        }
        Err(FederationError::Conflict(_)) => {
            tracing::debug!(node_key_id = %key_id, "node key already registered — idempotent");
        }
        Err(e) => return Err(anyhow::anyhow!("register node key {key_id}: {e}")),
    }
    Ok(key_id)
}

/// **The structural gate: resolve the key this node will BE, and refuse an actor.**
///
/// Called at boot with whatever `key_id` the host configured. Three outcomes,
/// and the middle one is the whole point:
///
/// - the configured key is `node`-only ⇒ use it (CIRISServer standalone; nothing
///   changes for an operator who was already correct);
/// - the configured key is an ACTOR or is FUSED ⇒ the node mints and uses its own
///   `<alias>-node` key instead, and says so loudly. The actor key is left
///   untouched — it keeps its type, its signatures, and every row it authored;
/// - the configured key is unregistered ⇒ the node registers it as `node`
///   itself, which is the pre-existing first-boot path.
///
/// Returns the key_id the node will operate as.
///
/// # Why this cannot be a warning
///
/// A node running on an actor key is not cosmetically wrong. Its transport
/// identity, its `self_key_id` and its de-admission self all name a key that
/// holds agency, and CC 3.4.7.3 Clause A exists because a key holding both is the
/// composition that switches the agency gate off. Continuing on it would keep the
/// property nominally true and actually unenforced — the state this whole change
/// exists to end.
///
/// # Errors
/// Directory read failure, or mint/registration failure for the node key.
pub async fn resolve_node_identity(
    engine: &ciris_persist::prelude::Engine,
    configured_key_id: &str,
    keystore_alias: &str,
    identity_dir: &std::path::Path,
) -> Result<NodeIdentityResolution> {
    let dir = engine.federation_directory();
    let verdict = classify(dir.as_ref(), configured_key_id).await?;

    match &verdict {
        IdentityVerdict::SubstrateOnly | IdentityVerdict::Unregistered => {
            Ok(NodeIdentityResolution {
                node_key_id: configured_key_id.to_owned(),
                split_from: None,
                verdict,
            })
        }
        IdentityVerdict::Actor { roles } | IdentityVerdict::Fused { roles } => {
            let (_signer, identity) = node_signer(keystore_alias, identity_dir).await?;
            let node_key_id = register_node_key(engine, &identity).await?;
            tracing::warn!(
                configured_key_id = %configured_key_id,
                configured_roles = ?roles,
                node_key_id = %node_key_id,
                "the configured key is an ACTOR, so it is not this node's identity. Minted and \
                 registered a separate node key (CC 3.4.7.3 Clause A: `node` is non-cohabitable \
                 with `agent`/`user`). The actor key is UNCHANGED and keeps everything it \
                 authored. The node's owner-binding must be re-issued onto the node key — see \
                 `plan_owner_binding_move`."
            );
            Ok(NodeIdentityResolution {
                node_key_id,
                split_from: Some(configured_key_id.to_owned()),
                verdict,
            })
        }
    }
}

/// What [`resolve_node_identity`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentityResolution {
    /// The key this node operates as.
    pub node_key_id: String,
    /// `Some` when the configured key was an actor and a node key was minted —
    /// i.e. this boot performed a split.
    pub split_from: Option<String>,
    /// How the configured key classified.
    pub verdict: IdentityVerdict,
}

impl NodeIdentityResolution {
    /// Did this boot split an actor key away from the node identity?
    #[must_use]
    pub fn did_split(&self) -> bool {
        self.split_from.is_some()
    }
}
