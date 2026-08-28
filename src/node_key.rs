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
    /// Registered, but carries neither `node` nor an actor role —
    /// `substrate_persist`, `witness`, `canonical`, `steward`, or an empty set.
    ///
    /// Not usable as the node identity (it does not say `node`) and not usable as
    /// an actor (it says nothing this split recognises as one). Folding it into
    /// either neighbour is what let a `witness` key pass the readiness gate as a
    /// brain.
    OtherInfrastructure { roles: Vec<String> },
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
        (true, true) => IdentityVerdict::SubstrateOnly,
        // NEITHER `node` nor an actor role: `substrate_persist`, `witness`,
        // `canonical`, `steward`, an empty set… (Codex P2 on #489).
        //
        // This used to fall into `SubstrateOnly`, which made the readiness gate
        // accept a `witness` key as the brain's actor identity — `is_actor_role`
        // explicitly rejects those, so the gate passed while every downstream
        // agency and authorship check operated on a key that is neither.
        //
        // It is its own verdict because it is genuinely a third thing: not the
        // node, not an actor, and not unknown. Distinct-zeroes again.
        (false, true) => IdentityVerdict::OtherInfrastructure { roles },
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
    fn an_unclaimed_node_with_a_brain_waits() {
        assert_eq!(
            gate_for(Some("agent-k"), true),
            StartupGate::WaitingForClaim {
                actor_key_id: "agent-k".into()
            }
        );
    }

    #[test]
    fn an_unclaimed_node_with_no_brain_starts_anyway() {
        // A substrate node has nothing to attribute, and one that refused to
        // federate until claimed could never carry the mesh it exists to serve.
        assert_eq!(gate_for(None, true), StartupGate::Ready);
    }

    #[test]
    fn a_claimed_node_with_a_brain_starts() {
        assert_eq!(gate_for(Some("agent-k"), false), StartupGate::Ready);
    }

    #[test]
    fn the_gate_holds_only_on_the_conjunction() {
        // Both halves are required: neither an owner alone nor a brain alone holds
        // the node. Pinned because dropping either turns a targeted hold into
        // either a no-op or a mesh-wide outage on unclaimed substrate nodes.
        assert_eq!(gate_for(None, false), StartupGate::Ready);
        assert!(matches!(
            gate_for(Some("a"), true),
            StartupGate::WaitingForClaim { .. }
        ));
    }

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
                signer: None,
            })
        }
        // All three are "the configured key is not this node": an actor, a fused
        // key, or some other infrastructure role that simply does not say `node`.
        // Each gets its own node key; none of them is mutated.
        IdentityVerdict::Actor { roles }
        | IdentityVerdict::Fused { roles }
        | IdentityVerdict::OtherInfrastructure { roles } => {
            let (signer, identity) = node_signer(keystore_alias, identity_dir).await?;
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
                signer: Some(signer),
            })
        }
    }
}

/// What [`resolve_node_identity`] decided.
// No `PartialEq`/`Eq`: a `LocalSigner` has no meaningful equality, and deriving
// one over a key would invite comparing signers instead of key ids.
#[derive(Clone)]
pub struct NodeIdentityResolution {
    /// The key this node operates as.
    pub node_key_id: String,
    /// `Some` when the configured key was an actor and a node key was minted —
    /// i.e. this boot performed a split.
    pub split_from: Option<String>,
    /// How the configured key classified.
    pub verdict: IdentityVerdict,
    /// The node key's signer, present exactly when a split happened. Needed to
    /// author rows AS the node while the engine signs as the actor.
    pub signer: Option<std::sync::Arc<ciris_persist::prelude::LocalSigner>>,
}

impl NodeIdentityResolution {
    /// Did this boot split an actor key away from the node identity?
    #[must_use]
    pub fn did_split(&self) -> bool {
        self.split_from.is_some()
    }
}

/// **Move the owner-binding from the actor key onto the node key — unattended.**
///
/// The split itself needs no operator, and neither does this. A node that has
/// been claimed already HOLDS its owner's fed-ID: claiming is what put the seed
/// at `<seed_dir>/<owner>.ed25519.seed`, and installing the app is the claim. So
/// the same key that authored the original binding is available to author the
/// corrected one, and asking a human to re-state ownership they already
/// established would be ceremony, not security.
///
/// What this authors is deliberately the narrowest possible act: **the same
/// owner, the same `infra:*` scope set, the same cohort — pointed at the node's
/// own key instead of the actor's.** No new authority is created. If the owner
/// resolved from the actor binding is not the owner this node holds a signer
/// for, nothing is written.
///
/// Idempotent: if `owner_of(node_key)` already resolves, there is nothing to do.
///
/// # Errors
/// Directory reads, binding construction, or the apply. A failure here leaves
/// the node unowned and therefore fail-closed under CC 3.4.7.3 Clause D — which
/// is the correct outcome for "we could not establish who owns this", and why
/// this returns the error rather than swallowing it.
pub async fn move_owner_binding_to_node_key(
    engine: &ciris_persist::prelude::Engine,
    owner_signer: &ciris_persist::prelude::LocalSigner,
    actor_key_id: &str,
    node_key_id: &str,
) -> Result<Option<OwnerBindingMove>> {
    use ciris_persist::federation::admission::owner_of;

    let dir = engine.federation_directory();

    // Already owned ⇒ nothing to move. Checked FIRST so a re-boot after a
    // successful migration is a cheap no-op rather than a re-emit.
    if owner_of(dir.as_ref(), node_key_id).await?.is_some() {
        return Ok(None);
    }

    let Some(owner_key_id) = owner_of(dir.as_ref(), actor_key_id).await? else {
        // The actor key is not owned either, so there is no binding to move and
        // nothing to infer. Not an error: an unclaimed node is a real state.
        return Ok(None);
    };

    // The signer must BE that owner. Anything else would be this node asserting
    // an ownership claim on behalf of a party whose key it does not hold.
    if owner_signer.key_id() != owner_key_id {
        anyhow::bail!(
            "refusing to move the owner-binding: the actor key is owned by {owner_key_id:?} \
             but this node holds a signer for {:?}. Moving it would mean authoring an \
             ownership claim as a party whose key we do not have.",
            owner_signer.key_id()
        );
    }

    let infra_scopes: Vec<String> = crate::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let cohort = ciris_persist::federation::types::cohort_scope::SELF;

    let binding = crate::auth::ownership::build_signed_owner_binding(
        owner_signer,
        node_key_id,
        &infra_scopes,
        cohort,
    )
    .await
    .map_err(|e| anyhow::anyhow!("build owner-binding for the node key: {e}"))?;

    crate::auth::ownership::apply_signed_owner_binding(
        engine,
        node_key_id,
        cohort,
        ciris_persist::prelude::HybridPolicy::Strict,
        &binding,
    )
    .await
    .map_err(|e| anyhow::anyhow!("apply owner-binding for the node key: {e}"))?;

    tracing::info!(
        owner_key_id = %owner_key_id,
        from_key_id = %actor_key_id,
        to_key_id = %node_key_id,
        "owner-binding moved onto the node key — the same owner, the same infra scopes, \
         a different subject. `owner_of(node)` now resolves, so CC 3.4.7.3 Clause D can be \
         answered for agents acting through this node."
    );
    Ok(Some(OwnerBindingMove {
        owner_key_id,
        from_key_id: actor_key_id.to_owned(),
        to_key_id: node_key_id.to_owned(),
    }))
}

/// **Re-author the actor's replication consent as the node.**
///
/// The half CIRISServer#312 makes mandatory: `compose` reads the topology by ONE
/// identity, so when that becomes the node key every grant the actor authored
/// goes invisible — zero peers, zero envelopes, fully green transport, no error.
///
/// Authored with the node's OWN signer via
/// [`crate::peer::ConsentGrantOptions::author_signer`], so this works with the
/// engine still signing as the actor (CIRISServer#221 keeps one engine in the
/// embedded fold). Self-attestation is preserved — the signature really is the
/// node's — which is the property CEG 1.0-RC29 §5.6.8.15 protects.
///
/// Returns the peers moved THIS pass; empty on a second boot.
///
/// # Errors
/// Directory reads, or a grant emission that is not a benign duplicate.
pub async fn reauthor_consent_as_node(
    engine: &std::sync::Arc<ciris_persist::prelude::Engine>,
    node_signer: std::sync::Arc<ciris_persist::prelude::LocalSigner>,
    actor_key_id: &str,
    node_key_id: &str,
) -> Result<Vec<String>> {
    let grants = engine
        .federation_directory()
        .list_live_consent_grants_by(actor_key_id)
        .await
        .map_err(|e| anyhow::anyhow!("list live consent grants by {actor_key_id}: {e}"))?;
    if grants.is_empty() {
        return Ok(Vec::new());
    }
    // Read ONCE before the loop so the skip set cannot drift as we write into it.
    let already: std::collections::BTreeSet<String> =
        crate::peer::replication_peers_from_consent(engine, node_key_id)
            .await?
            .into_iter()
            .collect();

    let mut moved = Vec::new();
    for grant in &grants {
        let Some(peer) = grant.subject_key_ids.first().cloned() else {
            continue;
        };
        if already.contains(&peer) {
            continue;
        }
        // **Carry the POLICY, never the defaults** (Codex P1 on #489).
        //
        // The first version rebuilt each grant from `ConsentGrantOptions::default()`
        // plus the global default prefixes, keeping only the peer id. An operator
        // grant with a narrowed prefix set, an expiry, an audience or a restriction
        // would have come back UNRESTRICTED — the migration authorizing data the
        // owner never consented to share. Widening consent silently is the worst
        // outcome available here, so the original policy is read off the live row
        // and reproduced.
        let (opts, prefixes) = policy_of(grant, &node_signer)?;
        crate::peer::emit_replication_consent_with_policy(
            engine,
            node_key_id,
            &peer,
            &prefixes,
            &opts,
        )
        .await
        .map_err(|e| anyhow::anyhow!("re-author consent {node_key_id} -> {peer}: {e}"))?;
        moved.push(peer);
    }
    if !moved.is_empty() {
        tracing::info!(
            from_key_id = %actor_key_id,
            to_key_id = %node_key_id,
            peers = ?moved,
            "consent re-authored as the node key, policy preserved — the replication \
             topology now resolves for the identity that reads it (CIRISServer#312)"
        );
    }
    Ok(moved)
}

/// Every payload member `emit_replication_consent_with_policy` can reproduce.
/// A grant carrying anything else is REFUSED rather than migrated with that
/// member dropped — see [`policy_of`].
const REPRODUCIBLE_PAYLOAD_MEMBERS: &[&str] = &[
    "grants",
    "direction",
    "kinds",
    "attestation_prefixes",
    "principle",
    "audience",
    "restrictions",
    "purpose",
    "valid_until",
];

/// Read a live grant's policy back into the options that reproduce it.
///
/// **Fail-closed on anything unrecognised.** A payload member this build cannot
/// carry means the re-authored grant would differ from the one the operator
/// authored, in a direction nobody reviewed. Refusing leaves the node's topology
/// unmigrated and visible; dropping the member silently widens a consent grant,
/// which is the failure this function exists to prevent.
fn policy_of(
    grant: &ciris_persist::federation::types::Attestation,
    node_signer: &std::sync::Arc<ciris_persist::prelude::LocalSigner>,
) -> Result<(crate::peer::ConsentGrantOptions, Vec<String>)> {
    let payload = grant
        .attestation_envelope
        .get("payload")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "consent grant {} carries no payload object — refusing to re-author a \
                 grant whose policy cannot be read",
                grant.attestation_id
            )
        })?;

    let unknown: Vec<&str> = payload
        .keys()
        .map(String::as_str)
        .filter(|k| !REPRODUCIBLE_PAYLOAD_MEMBERS.contains(k))
        .collect();
    anyhow::ensure!(
        unknown.is_empty(),
        "consent grant {} carries payload member(s) {unknown:?} this build cannot \
         reproduce. Refusing to re-author it: migrating with those dropped would \
         author a grant the owner never made, and a widened consent is worse than an \
         unmigrated one. Extend REPRODUCIBLE_PAYLOAD_MEMBERS (and the options it maps \
         to) rather than relaxing this check.",
        grant.attestation_id
    );

    let strs = |k: &str| -> Option<Vec<String>> {
        payload.get(k)?.as_array().map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
    };
    let s =
        |k: &str| -> Option<String> { payload.get(k).and_then(|v| v.as_str()).map(str::to_owned) };

    let prefixes = strs("attestation_prefixes").unwrap_or_default();
    anyhow::ensure!(
        !prefixes.is_empty(),
        "consent grant {} declares no attestation prefixes — refusing rather than \
         substituting the defaults, which is exactly how a narrowed grant becomes a \
         broad one",
        grant.attestation_id
    );

    let restrictions = match payload.get("restrictions") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| {
            anyhow::anyhow!(
                "consent grant {} has restrictions this build cannot parse ({e}) — \
                 refusing rather than re-authoring without them",
                grant.attestation_id
            )
        })?,
    };
    let valid_until = match payload.get("valid_until") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(
            v.as_str()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|t| t.with_timezone(&chrono::Utc))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "consent grant {} has an unparseable valid_until — refusing \
                         rather than re-authoring WITHOUT an expiry the owner set",
                        grant.attestation_id
                    )
                })?,
        ),
    };

    Ok((
        crate::peer::ConsentGrantOptions {
            author_signer: Some(node_signer.clone()),
            audience: s("audience"),
            valid_until,
            restrictions,
            kinds: strs("kinds"),
            direction: s("direction"),
            principle: s("principle"),
            purpose: s("purpose"),
        },
        prefixes,
    ))
}

/// **Provision the node identity — mint + register, ahead of edge init.**
///
/// The ordering the split needs and did not have. CIRISEdge#541 gives
/// `init_edge_runtime` a `use_node_identity` flag which resolves the node key by
/// `open_existing` and REFUSES if it is absent — correct, because a key edge
/// minted would be registered by no directory and owner-bound by nobody
/// (CIRISAgent#1009's shape). But in the embedded fold edge inits BEFORE
/// CIRISServer's compose folds on, so on a first boot the key it needs does not
/// exist yet and the flag would refuse forever.
///
/// Softening edge's refusal would be the wrong cure — it puts the node-identity
/// lifecycle in the party that does not own it. So the mint moves EARLIER
/// instead: the host calls this after building its engine and before edge init.
///
/// Both halves are minted here, and they are separate files on purpose:
/// `<alias>-node` sealed Ed25519, and **`node_ml_dsa_65.seed`** — NOT the
/// engine's `ml_dsa_65.seed`. Handing the node key the actor's PQC half would
/// split the classical axis only, hybrid-sign with the wrong post-quantum key,
/// and report green throughout.
///
/// Idempotent: `node_signer` is open-or-mint and registration treats a matching
/// row as `Ok`, so every boot after the first is a no-op.
///
/// Returns the registered node `key_id`.
///
/// # Errors
/// Keystore/seed IO, or a registration failure that is not a benign conflict.
/// **Register an agent's ACTOR key as an occurrence, minting nothing.**
///
/// This is the cure for the refusal storm the `Unregistered` arm below used to
/// merely announce: an actor key that never reached `federation_keys` has every
/// row it authors refused at every peer, and the peer's log is not one the agent's
/// operator can read. Measured on the canonical in one 30-minute window: **1,943
/// refusals** reading `attesting_key_id … does not exist in federation_keys`,
/// from four keys, retried without backoff.
///
/// # Why this needs no new key material
///
/// The actor key is the ENGINE's own identity — the one `emit_attestation_self`
/// already signs with, and the one [`crate::attest::KeySigner::key_id`] derives.
/// The node key is the newly-minted half of the split; the actor keeps the
/// pre-existing keypair. So registering it is a proof-of-possession the node can
/// already produce, and [`crate::attest::register_key`] reads both pubkeys off a
/// live probe signature rather than a re-opened seed that might have diverged.
///
/// # Occurrences are INDEPENDENT by default
///
/// `root_identity_key_id` is `None` for every agent but one, and that default is
/// load-bearing rather than a shortcut. Production holds nine `echo-core` keys,
/// nine `datum`, eight `echo-speculative` — all deliberately unlinked, because an
/// agent is hard-bound to the node that hosts it and separate occurrences are
/// separate selves. `None` therefore binds the occurrence to ITSELF, reproducing
/// exactly what the mesh already does (all 200 occurrence rows on the canonical
/// are self-referential).
///
/// Passing `Some(root)` is for the genuine multi-occurrence agent — scout is the
/// only one — where several occurrences ARE one self and `signer_acts_for` should
/// treat any active one as acting for it. That path has never run in production
/// (zero non-self-referential rows exist), so it is exercised by test here rather
/// than trusted.
///
/// Idempotent: registration treats a matching row as success, and binding an
/// occurrence that already exists is a no-op.
///
/// # Errors
/// If the engine does not hold `actor_key_id` (we cannot prove possession of a key
/// we do not have), or if registration or binding fails.
pub async fn register_actor_occurrence(
    engine: &ciris_persist::prelude::Engine,
    actor_key_id: &str,
    root_identity_key_id: Option<&str>,
) -> Result<()> {
    use ciris_persist::federation::types::{device_class, identity_type};

    let signer = crate::attest::KeySigner::Engine(engine);
    let derived = signer
        .key_id()
        .await
        .map_err(|e| anyhow::anyhow!("resolve this engine's derived actor key_id: {e}"))?;

    // The honest boundary. We can self-register the key this node HOLDS; we cannot
    // manufacture a proof of possession for someone else's. Bailing here is
    // correct in a way the old blanket bail was not: it fires only when the caller
    // named a key we genuinely cannot speak for.
    if derived != actor_key_id {
        anyhow::bail!(
            "cannot register actor key {actor_key_id:?}: this engine signs as {derived:?}, so it              holds no proof of possession for it. An agent is hard-bound to its node — the actor              key must be the one this node's engine signs with."
        );
    }

    crate::attest::register_key(
        engine,
        crate::attest::KeySigner::Engine(engine),
        actor_key_id,
        identity_type::AGENT,
        serde_json::Value::Null,
    )
    .await
    .map_err(|e| anyhow::anyhow!("register actor key {actor_key_id}: {e}"))?;

    let identity_key_id = root_identity_key_id.unwrap_or(actor_key_id);
    crate::auth::occurrence::bind_occurrence_core(
        engine,
        identity_key_id,
        actor_key_id,
        device_class::AGENT,
        None,
        None,
        None,
    )
    .await
    .map_err(|e| anyhow::anyhow!("bind actor occurrence {actor_key_id}: {e}"))?;

    tracing::info!(
        actor_key_id = %actor_key_id,
        identity_key_id = %identity_key_id,
        independent = root_identity_key_id.is_none(),
        "actor key registered and bound as an agent occurrence"
    );
    Ok(())
}

pub async fn provision_node_identity(
    engine: &ciris_persist::prelude::Engine,
    keystore_alias: &str,
    identity_dir: &std::path::Path,
    actor_key_id: Option<&str>,
) -> Result<String> {
    let (_signer, identity) = node_signer(keystore_alias, identity_dir).await?;
    let key_id = register_node_key(engine, &identity).await?;

    // ── The readiness gate: edge must not start on a half-provisioned identity ──
    //
    // Verified by READING THE DIRECTORY BACK, not by trusting the register call
    // above. `register_federation_key` treats a benign Conflict as Ok, which is
    // exactly how a node once ran for months on a key that never said `node` —
    // the write reported success and the row said something else.
    let dir = engine.federation_directory();
    match classify(dir.as_ref(), &key_id).await? {
        IdentityVerdict::SubstrateOnly => {}
        other => anyhow::bail!(
            "node identity NOT provisioned: {key_id:?} classifies as {other:?}, not a \
             pure `node`. Edge must not start on this — the transport identity is the \
             key that walks the lightnet door (bootstrap kinds are exempt from \
             `Rooted ∧ owns_key` and attributed by the link's identity), and CC 3.4.7.3 \
             Clause A exists because a key carrying both roles makes persist's agency \
             gate stop firing."
        ),
    }

    // An agent-carrying node owes its ACTOR key too: the brain signs authorship
    // with it, and an unregistered attester has every row refused
    // (`attesting_key_id … does not exist in federation_keys` — 3,404 refusals on
    // one key in production). Checked here so the failure lands at provisioning,
    // in front of whoever is starting the node, rather than as a refusal storm at
    // a peer whose logs they cannot read.
    if let Some(actor) = actor_key_id {
        match classify(dir.as_ref(), actor).await? {
            IdentityVerdict::Actor { .. } => {}
            // Absent ⇒ REGISTER it, do not refuse to start. An unregistered actor
            // key is a first boot, exactly as it is for the node key a few hundred
            // lines up (`resolve_node_identity` registers rather than bails on the
            // same verdict). Refusing here only moved the agent team's failure from
            // "a silent storm at a peer" to "your node will not boot" — better to
            // read, but still a precondition we gave them no way to satisfy.
            IdentityVerdict::Unregistered => {
                tracing::info!(
                    actor_key_id = %actor,
                    "actor key is unregistered — registering it (first boot for this agent \
                     occurrence)"
                );
                register_actor_occurrence(engine, actor, None).await?;
                // Re-READ, do not trust the write: registration treats a benign
                // conflict as success, which is exactly how a node once ran for
                // months on a key whose row said something other than what the
                // write reported.
                match classify(dir.as_ref(), actor).await? {
                    IdentityVerdict::Actor { .. } => {}
                    other => anyhow::bail!(
                        "node identity NOT provisioned: registered actor key {actor:?} reads back \
                         as {other:?}, not an actor."
                    ),
                }
            }
            other => anyhow::bail!(
                "node identity NOT provisioned: the actor key {actor:?} classifies as \
                 {other:?}. An agent-carrying node needs a key that IS an actor — a \
                 `node`-typed or fused key here is the fusion this split removes."
            ),
        }
        // Recorded only after the key is known-good, so the startup gate can never
        // hold a node on the strength of an actor key we just refused.
        set_actor_identity(actor);
    }

    // NOT gated: the owner-binding. A fresh node has no owner until someone
    // completes OAuth and claims it, and that is what first-run is FOR. Requiring
    // a human here would mean a node cannot start its transport until it is
    // claimed — and the claim path reaches edge only through a fire-and-forget
    // `pull_owner_testimony` whose own comment says the response "must not wait on
    // a peer being reachable". Gating would make that permanently dead on first
    // run and deadlock any future claim path that does want a peer.
    //
    // The defect still closes: the lightnet door is walked by a `node`-typed key
    // from the first packet, claimed or not. Ownership is a separate readiness
    // question, answered by `owner_of` at the point that needs it — fail-closed,
    // per CC 3.4.7.3 Clause D.
    // Record the wire identity HERE, not only in compose.
    //
    // `federation_delivery::start_and_hold` arms the de-admission gate on the
    // EMBEDDED path and never runs `serve_with_adapter`, so a wire identity set
    // only in compose would be unset there and the gate would arm the ACTOR —
    // the node advertising an identity a sanction can name while being
    // un-de-admittable through it. Provisioning is the earliest point the node
    // key is known and it runs on every path that reaches edge, which makes it
    // the right place. compose sets the same value later; first-writer-wins.
    set_wire_identity(&key_id);

    tracing::info!(
        node_key_id = %key_id,
        alias = %node_alias(keystore_alias),
        actor_key_id = actor_key_id.unwrap_or("<none — not agent-carrying>"),
        "node identity provisioned and VERIFIED (CC 3.4.7.3) — minted, registered and \
         read back ahead of edge init, so `use_node_identity` resolves it by \
         open_existing (CIRISEdge#541). Ownership is deliberately not gated here."
    );
    Ok(key_id)
}

// ─── The WIRE identity — one binding, read by every transport-plane caller ────

/// The key this node presents ON THE WIRE, once resolved at boot.
///
/// Set by [`resolve_node_identity`]; read by the transport-plane callers that
/// must agree with edge's Reticulum identity. A `OnceLock` rather than a
/// threaded parameter because the callers are reached from two entry points
/// (`compose::serve_with_adapter` and `federation_delivery::start_and_hold`) and
/// a parameter added to one of them is exactly how these drift apart.
///
/// # Why this exists at all
///
/// CIRISEdge#541's review found three defects from ONE root cause: a single
/// binding serving several jobs that coincided only while the transport identity
/// and the actor were the same key. Under the split they are not, and the same
/// shape existed here — `publish_self_transport_destination` bound `cfg.key_id`
/// (the ACTOR's derived id) to edge's `local_named_dest_hash()` (the NODE's
/// destination under `use_node_identity`), so a peer evaluating CIRISEdge#393
/// item 2 would find the signed route naming a key that is not the one it is
/// talking to, and never root. `arm_peer_deadmission_gate` had the twin: it armed
/// the ACTOR as the de-admission self, so this node would advertise an identity a
/// sanction can name while being un-de-admittable through it.
///
/// Both are the same mistake in the same direction — reaching for "the node's
/// key" and getting whichever key happened to be at hand.
static WIRE_IDENTITY: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Record the wire identity. First writer wins; a second call with a DIFFERENT
/// value is a bug worth shouting about rather than silently ignoring.
/// The ACTOR key this node carries, when it carries a brain at all.
///
/// Separate from [`wire_identity`] because they are different keys on exactly the
/// node that matters here: an agent-carrying node operates as its `node` key and
/// authors brain work under its `agent` key, and CC 3.4.7.3 Clause A exists to
/// keep them apart.
static ACTOR_IDENTITY: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Record that this node carries a brain, under `key_id`.
pub fn set_actor_identity(key_id: &str) {
    if let Err(existing) = ACTOR_IDENTITY.set(key_id.to_owned()) {
        if existing != key_id {
            tracing::error!(
                already = %ACTOR_IDENTITY.get().map(String::as_str).unwrap_or("<unset>"),
                attempted = %key_id,
                "actor identity RESET attempted with a different key — authorship would be \
                 split across two agent identities. The first value stands."
            );
        }
    }
}

/// The actor key this node carries, or `None` on a node with no brain.
#[must_use]
pub fn actor_identity() -> Option<&'static str> {
    ACTOR_IDENTITY.get().map(String::as_str)
}

/// Whether this node may begin joining the mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupGate {
    /// Nothing is owed — start.
    Ready,
    /// This node carries a brain and nobody owns it yet.
    WaitingForClaim {
        /// The actor key whose work would otherwise be unattributable.
        actor_key_id: String,
    },
}

/// **Hold an agent-carrying node at "waiting for claim" until someone owns it.**
///
/// An agent acts *through* a node on behalf of a human: `may_act_through(agent,
/// node)` requires an owner, and CC 3.4.7.3 Clause D is fail-closed, so an unowned
/// node cannot answer it at all. Joining the mesh first means publishing brain work
/// no owner stands behind — every row unattributable at the moment it is authored,
/// which is not a state a peer can repair later.
///
/// This reuses the first-run machinery rather than inventing a second notion of
/// "unclaimed": [`crate::auth::bootstrap::is_first_run`] is the same predicate the
/// claim routes gate themselves on, so the node is waiting on exactly the condition
/// `POST /v1/setup/root` clears, and the PIN + NodeCode banner an operator already
/// sees at `claim_pin` is already the instruction for how to clear it.
///
/// Deliberately does NOT gate a node with no brain. A plain node has nothing to
/// attribute, and a substrate node that refused to federate until claimed could
/// never serve the mesh it is there to carry.
///
/// `is_first_run` fails CLOSED (a directory error reads as NOT first-run), so an
/// unreadable directory lets the node start rather than stranding it unreachable —
/// the same direction the claim routes chose.
pub async fn startup_gate(engine: &ciris_persist::prelude::Engine) -> StartupGate {
    let unclaimed = crate::auth::bootstrap::is_first_run(engine).await;
    gate_for(actor_identity(), unclaimed)
}

/// The decision itself, separated from where its two inputs come from.
///
/// `actor_identity` is a process-global `OnceLock` and "first run" needs a live
/// engine, so a gate that read both directly could only ever be exercised in one
/// state per test process — and the three states are exactly what needs pinning.
#[must_use]
pub fn gate_for(actor: Option<&str>, unclaimed: bool) -> StartupGate {
    match (actor, unclaimed) {
        (Some(actor_key_id), true) => StartupGate::WaitingForClaim {
            actor_key_id: actor_key_id.to_owned(),
        },
        _ => StartupGate::Ready,
    }
}

pub fn set_wire_identity(key_id: &str) {
    if let Err(existing) = WIRE_IDENTITY.set(key_id.to_owned()) {
        if existing != key_id {
            tracing::error!(
                already = %WIRE_IDENTITY.get().map(String::as_str).unwrap_or("<unset>"),
                attempted = %key_id,
                "wire identity RESET attempted with a different key — the transport plane \
                 would be split across two identities. The first value stands; this is a \
                 bug in boot ordering, not a recoverable condition."
            );
        }
    }
}

/// The wire identity, or `None` before boot has resolved it.
///
/// Callers on the transport plane MUST prefer this over `cfg.key_id` or
/// `engine.local_derived_key_id()`: those are the ACTOR on a split node, and
/// using them publishes routes and arms sanctions against a key that is not the
/// one on the link.
#[must_use]
pub fn wire_identity() -> Option<&'static str> {
    WIRE_IDENTITY.get().map(String::as_str)
}
