//! **An owner who announced stays announced across the 0.5.189 split.**
//!
//! Eric × Francesco, 2026-10-23: chat never started. The canonical held
//! `francesco → <agent key>` at federation scope and nothing naming his NODE key.
//! His install had announced while the binding named the agent key; a later boot
//! split a node key off it and moved the binding there at `self` (the scope every
//! binding is born at). A self-scoped binding reaches only the owner's own devices,
//! so the canonical never rooted his node at its steward, and Eric's node found
//! "no node" for him (`peer_nodes=0`).
//!
//! The boot step under test is `node_key::follow_owner_across_split`: move, then
//! carry the announce. On 0.5.234 compose ran the move alone and these fail.

use std::sync::Arc;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::cohort_scope;
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use ed25519_dalek::SigningKey;

use ciris_server::attest::{register_key, KeySigner};
use ciris_server::auth::ownership::{
    announced_nodes_of, apply_signed_owner_binding, build_signed_owner_binding,
    owner_binding_is_federation_scoped, promote_owner_binding_to_federation,
    OWNER_BINDING_INFRA_SCOPES,
};
use ciris_server::node_key::follow_owner_across_split;

fn id_of(alias: &str, seed: u8) -> String {
    let ed = SigningKey::from_bytes(&[seed; 32]);
    ciris_verify_core::fedcode::derive_key_id(alias, ed.verifying_key().as_bytes())
}

fn pen_as(seed: u8, key_id: &str) -> LocalSigner {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x5A; 32], format!("{key_id}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        SigningKey::from_bytes(&[seed; 32]),
        key_id.to_owned(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    )
}

/// A ≤0.5.188-claimed home at its split: the engine on the actor key, owned by
/// `owner` (announced when `announced`), and a fresh node key nobody owns yet.
async fn split_home(owner: &LocalSigner, announced: bool) -> (Arc<Engine>, String, String) {
    let actor = id_of("ciris-agent-bootstrap-fz", 0x11);
    let engine = Arc::new(
        Engine::with_signer(
            Arc::new(pen_as(0x11, "ciris-agent-bootstrap-fz")),
            "sqlite::memory:",
        )
        .await
        .expect("engine"),
    );
    register_key(
        &engine,
        KeySigner::Engine(&engine),
        &actor,
        "agent",
        serde_json::Value::Null,
    )
    .await
    .unwrap();
    let node = id_of("ciris-node-bootstrap-fz", 0x22);
    register_key(
        &engine,
        KeySigner::Local(&pen_as(0x22, &node)),
        &node,
        "node",
        serde_json::Value::Null,
    )
    .await
    .unwrap();
    let scopes: Vec<String> = OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let binding = build_signed_owner_binding(owner, &actor, &scopes, cohort_scope::SELF)
        .await
        .unwrap();
    apply_signed_owner_binding(
        &engine,
        &actor,
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &binding,
    )
    .await
    .expect("the owner claims the actor key");
    if announced {
        promote_owner_binding_to_federation(&engine, owner, &actor)
            .await
            .expect("the owner announces (the ≤0.5.188 wizard's step)");
        assert!(owner_binding_is_federation_scoped(&engine, &actor).await);
    }
    (engine, actor, node)
}

#[tokio::test]
async fn a_split_from_an_announced_actor_ends_with_a_federation_owner_binding_on_the_node_key() {
    let owner = pen_as(0x33, &id_of("francesco", 0x33));
    let (engine, actor, node) = split_home(&owner, true).await;

    let (moved, announced) = follow_owner_across_split(&engine, &owner, &actor, &node)
        .await
        .expect("the boot step");
    assert!(moved.is_some(), "the binding moved onto the node key");
    assert!(announced.is_some(), "and was re-announced");
    assert!(
        owner_binding_is_federation_scoped(&engine, &node).await,
        "a federation-scope delegates_to owner → node key: what peers and the canonical read"
    );
    assert!(
        announced_nodes_of(&engine, owner.key_id())
            .await
            .unwrap()
            .contains(&node),
        "the owner's announced nodes include the node key"
    );

    // Every boot runs it; once carried, nothing more is owed.
    let again = follow_owner_across_split(&engine, &owner, &actor, &node)
        .await
        .unwrap();
    assert!(again.0.is_none() && again.1.is_none(), "{again:?}");
}

/// Francesco's actual state: the move already happened on an earlier boot (at
/// `self`), so the next boot finds the node owned. It must still heal.
#[tokio::test]
async fn an_already_split_home_heals_on_its_next_boot() {
    let owner = pen_as(0x33, &id_of("francesco", 0x33));
    let (engine, actor, node) = split_home(&owner, true).await;
    ciris_server::node_key::move_owner_binding_to_node_key(&engine, &owner, &actor, &node)
        .await
        .unwrap()
        .expect("0.5.234's move, at self");
    assert!(
        !owner_binding_is_federation_scoped(&engine, &node).await,
        "the defect: the moved binding is self-scoped"
    );

    let (moved, announced) = follow_owner_across_split(&engine, &owner, &actor, &node)
        .await
        .unwrap();
    assert!(moved.is_none(), "already owned: nothing to move");
    assert!(announced.is_some(), "but the announce is carried");
    assert!(owner_binding_is_federation_scoped(&engine, &node).await);
}

/// An owner who never announced is not announced on their behalf.
#[tokio::test]
async fn a_split_from_a_private_actor_stays_private() {
    let owner = pen_as(0x33, &id_of("francesco", 0x33));
    let (engine, actor, node) = split_home(&owner, false).await;
    let (moved, announced) = follow_owner_across_split(&engine, &owner, &actor, &node)
        .await
        .unwrap();
    assert!(moved.is_some());
    assert!(
        announced.is_none(),
        "never announced, so nothing is carried"
    );
    assert!(!owner_binding_is_federation_scoped(&engine, &node).await);
}
