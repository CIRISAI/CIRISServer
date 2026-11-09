//! **The registry slice is conferred, not configured** (CIRISServer#537,
//! CIRISRegistry#62).
//!
//! The fold of `ciris-registry-core` into this server hangs on one ordering
//! constraint: *no server converts to a canonical node until it can serve
//! registry capabilities under the granted role*. So "may serve the registry
//! surface" has to be something the node EVALUATES, never something an operator
//! asserts.
//!
//! ## The gate
//!
//! [`registry_slice_conferred`] walks persist's
//! `capability_roots_to_trusted_root(dir, me, me, infra:attest)`. Both key ids
//! are this node's on purpose: the question is *"do I hold this capability, from
//! a root I MYSELF accept?"*. The second half is the operator's un-trust lever:
//! withdraw the `trust:accepts` edge and the walk returns `None`, and the slice
//! goes dark with nothing special-cased. The walk covers all three conferral
//! planes persist knows (a `delegates_to` grant, the accord co-scrub on the key
//! record, a family-quorum grant), so the production canonical's
//! `genesis-grant:ciris-canonical-1-*` (all four charter verbs) confers it with
//! no charter amendment.
//!
//! No charter amendment is needed because the verbs exist: registry's work is
//! attestation-shaped and rides `infra:attest`, which every serve node holds the
//! moment the accord blesses it ([`crate::final_genesis::SERVE_NODE_ROLES`]).
//!
//! ## Infrastructure does not vote; the owner sets the config
//!
//! Steward ruling 2026-09-22 (CIRISServer#537): only the accord family is a
//! quorum, and a canonical node's OWNER sets its configuration. That splits the
//! two inputs cleanly:
//!
//! - **The conferral** is the accord's. Nothing on this node can widen it.
//! - **The opt-out** is the owner's: the signed, owner-gated `config:*` key
//!   [`KEY_REGISTRY_SLICE`] set to `false` keeps a conferred node from serving.
//!   It can only narrow. `true`, or absent, defers to the conferral.
//!
//! `ServerConfig::slices.registry` survives as the embedder's compile-time
//! opt-out with the same one-way semantics; it defaults to `true`, because
//! defaulting it to `false` made the conferral unreachable on every node.
//!
//! ## Why this is not part of `Capabilities`
//!
//! `Capabilities::detect` runs BEFORE the Engine opens (a pre-corpus structural
//! gate). A delegation-graph walk needs the corpus, so this gate is necessarily
//! post-corpus and runs at slice-composition time.
//!
//! ## What a withheld slice means
//!
//! `Ok(None)` from the walk is a steady state, not an error: a node that was
//! never blessed simply does not serve the authority slice. Only a failure to
//! EVALUATE is an error, and composition treats it fail-secure (withheld) rather
//! than failing the boot.

use std::sync::Arc;

use anyhow::Result;
use ciris_persist::federation::trust_root::{
    capability_roots_to_trusted_root, TrustedGrant, INFRA_ATTEST_SCOPE,
};
use ciris_persist::prelude::Engine;

/// The owner's opt-out: a signed `config:*` boolean. `false` withholds the
/// registry slice from a node the accord conferred it on; `true` or absent
/// defers to the conferral. It never confers.
pub const KEY_REGISTRY_SLICE: &str = "slices.registry";

/// Why the slice is, or is not, served on this node. Composition logs it once
/// at boot; later increments read it to decide which routes to mount.
#[derive(Debug, Clone)]
pub enum RegistrySlice {
    /// The accord conferred `infra:attest` from a root this node accepts, and
    /// neither opt-out is set.
    Conferred(TrustedGrant),
    /// No accord-conferred `infra:attest` from a root this node accepts. The
    /// ordinary state of every node that has not been blessed.
    NotConferred,
    /// The embedder compiled the slice out (`ServerConfig::slices.registry`).
    DisabledByEmbedder,
    /// The owner's signed [`KEY_REGISTRY_SLICE`] is `false`. Carries whether the
    /// accord had conferred it, so the log says what the owner declined.
    DeclinedByOwner {
        /// Whether the walk resolved; `None` when it could not be evaluated.
        was_conferred: Option<bool>,
    },
    /// The walk or the owner's config could not be evaluated. Withheld: an
    /// undetermined conferral is not a conferral.
    Undetermined(String),
}

impl RegistrySlice {
    /// Does this node serve the registry slice?
    pub fn serves(&self) -> bool {
        matches!(self, RegistrySlice::Conferred(_))
    }

    /// The grant that confers it, when it is conferred.
    pub fn grant(&self) -> Option<&TrustedGrant> {
        match self {
            RegistrySlice::Conferred(g) => Some(g),
            _ => None,
        }
    }
}

/// Does `subject_key_id` hold `infra:attest` from a root `user_key_id` accepts?
///
/// The general form of the walk, for a test or a surface that reports on a
/// PEER's standing. The gate on this node is [`registry_slice_conferred`],
/// which asks it about itself on both sides.
pub async fn infra_attest_conferral(
    engine: &Arc<Engine>,
    user_key_id: &str,
    subject_key_id: &str,
) -> Result<Option<TrustedGrant>> {
    let directory = engine.federation_directory();
    capability_roots_to_trusted_root(
        directory.as_ref(),
        user_key_id,
        subject_key_id,
        INFRA_ATTEST_SCOPE,
    )
    .await
    .map_err(|e| anyhow::anyhow!("evaluate the registry-slice capability walk: {e:#}"))
}

/// Is THIS node conferred the authority slice? See the module docs.
pub async fn registry_slice_conferred(
    engine: &Arc<Engine>,
    node_key_id: &str,
) -> Result<Option<TrustedGrant>> {
    infra_attest_conferral(engine, node_key_id, node_key_id).await
}

/// The owner's opt-out: `Ok(true)` iff the owner's signed [`KEY_REGISTRY_SLICE`]
/// is `false`. A value that is not a boolean is treated as a decline, loudly: a
/// node that cannot read what its owner said serves less, never more.
pub async fn owner_declined(engine: &Arc<Engine>) -> Result<bool> {
    match crate::graph_config::get_config(engine, KEY_REGISTRY_SLICE).await? {
        None => Ok(false),
        Some(entry) => match entry.value.as_bool() {
            Some(enabled) => Ok(!enabled),
            None => {
                tracing::error!(
                    key = KEY_REGISTRY_SLICE,
                    updated_by = %entry.updated_by,
                    "the owner's registry-slice setting is not a boolean — read as a DECLINE \
                     (it can only narrow the slice, so an unreadable value narrows it)"
                );
                Ok(true)
            }
        },
    }
}

/// Resolve whether this node serves the registry slice. Never fails: every
/// evaluation error resolves to [`RegistrySlice::Undetermined`], which serves
/// nothing.
pub async fn resolve(
    engine: &Arc<Engine>,
    node_key_id: &str,
    embedder_enabled: bool,
) -> RegistrySlice {
    if !embedder_enabled {
        return RegistrySlice::DisabledByEmbedder;
    }
    let conferral = registry_slice_conferred(engine, node_key_id).await;
    match owner_declined(engine).await {
        Ok(true) => {
            return RegistrySlice::DeclinedByOwner {
                was_conferred: conferral.as_ref().ok().map(Option::is_some),
            }
        }
        Ok(false) => {}
        Err(e) => {
            return RegistrySlice::Undetermined(format!(
                "read the owner's {KEY_REGISTRY_SLICE} config: {e:#}"
            ))
        }
    }
    match conferral {
        Ok(Some(grant)) => RegistrySlice::Conferred(grant),
        Ok(None) => RegistrySlice::NotConferred,
        Err(e) => RegistrySlice::Undetermined(format!("{e:#}")),
    }
}

/// Log the resolution once, at boot, in words an operator can act on.
pub fn log_resolution(slice: &RegistrySlice, node_key_id: &str) {
    match slice {
        RegistrySlice::Conferred(grant) => tracing::info!(
            node = %node_key_id,
            root = %grant.root_key_id,
            grant = %grant.grant_attestation_id,
            plane = ?grant.conferral_plane,
            scope = INFRA_ATTEST_SCOPE,
            "registry slice CONFERRED by the trust root — this node serves the registry \
             surfaces composed so far (CIRISServer#537)"
        ),
        RegistrySlice::NotConferred => tracing::info!(
            node = %node_key_id,
            scope = INFRA_ATTEST_SCOPE,
            "registry slice WITHHELD — this node holds no accord-conferred infra:attest from a \
             trust root it accepts. Normal for an unblessed node: the slice is conferred by the \
             accord, never configured"
        ),
        RegistrySlice::DisabledByEmbedder => tracing::info!(
            node = %node_key_id,
            "registry slice DISABLED by the embedder (ServerConfig::slices.registry = false)"
        ),
        RegistrySlice::DeclinedByOwner { was_conferred } => tracing::warn!(
            node = %node_key_id,
            key = KEY_REGISTRY_SLICE,
            was_conferred = ?was_conferred,
            "registry slice DECLINED by the node's owner (config {KEY_REGISTRY_SLICE} = false)"
        ),
        RegistrySlice::Undetermined(why) => tracing::warn!(
            node = %node_key_id,
            error = %why,
            "registry slice WITHHELD — the conferral could not be evaluated, and an undetermined \
             conferral is not a conferral"
        ),
    }
}
