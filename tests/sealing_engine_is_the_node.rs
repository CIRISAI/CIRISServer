//! **On a split home the NODE seals, never the agent** (Eric, 2026-10-28).
//!
//! The five-platform gate of 2026-10-28 reached a Ready room on both sides,
//! sent, and the joiner never opened the message: the room's epoch was minted
//! and its key-grant set signed by the ENGINE, which on a split home is the
//! agent, and the joiner refused it (`signer_not_active_member`) — an agent's
//! tie to its person is a `self` row no peer receives. The holding claim for
//! the body was the agent's too, and was withheld (NoHolders). The sealing
//! engine and the chat plane's node signer are the held node key; persist's
//! announcing check refuses any engine whose LocalSigner does not derive the
//! same id as its composed signer, so the ids are what this pins.

use std::sync::Arc;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;

fn id_of(alias: &str, seed: u8) -> String {
    let ed = SigningKey::from_bytes(&[seed; 32]);
    ciris_verify_core::fedcode::derive_key_id(alias, ed.verifying_key().as_bytes())
}

fn pen_as(seed: u8, alias: &str) -> LocalSigner {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x5A; 32], format!("{alias}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        SigningKey::from_bytes(&[seed; 32]),
        alias.to_owned(),
        Some(pqc),
        Some(format!("{alias}-pqc")),
    )
}

#[tokio::test]
async fn the_sealing_engine_and_the_chat_signer_are_the_node_on_a_split_home() {
    let engine = Engine::with_signer(
        Arc::new(pen_as(0x13, "qa-runner-ciris-agent-seal")),
        "sqlite::memory:",
    )
    .await
    .expect("engine on the agent key");
    let agent = engine.local_derived_key_id().await.unwrap();

    // No split: the engine is the node, and seals as itself.
    assert_eq!(
        ciris_server::node_key::sealing_engine(&engine)
            .local_derived_key_id()
            .await
            .unwrap(),
        agent
    );
    assert!(ciris_server::node_key::held_node_edge_signer().is_none());

    // The split: the node's pen held by ALIAS, as `node_signer` builds it.
    let node = id_of("ciris-node-bootstrap-seal", 0x23);
    ciris_server::node_key::set_node_signer(
        Arc::new(pen_as(0x23, "ciris-node-bootstrap-seal")),
        String::new(),
    );
    let sealing = ciris_server::node_key::sealing_engine(&engine);
    assert_eq!(
        sealing.local_derived_key_id().await.unwrap(),
        node,
        "the sealing engine mints and claims as the node"
    );
    assert_ne!(node, agent);
    let chat = ciris_server::node_key::held_node_edge_signer().expect("node edge signer");
    assert_eq!(
        chat.key_id, node,
        "the chat plane's node signer is the node"
    );

    // Same substrate: a row the sealing engine writes is the engine's to read.
    assert_eq!(
        sealing.federation_directory().node_key_id(),
        engine.federation_directory().node_key_id()
    );
}
