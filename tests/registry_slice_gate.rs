//! CIRISServer#537 phase 1 — the registry slice is conferred by the accord,
//! declinable by the owner, and never configured on (`src/registry_slice.rs`).
//!
//! The regression these pin first is a boot outage, not a feature:
//! `compose_registry` was a `todo!()` reachable only because a config bool
//! defaulted to `false`. Every resolution here must RETURN, on blessed and
//! unblessed nodes alike.

use std::sync::Arc;

use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_server::graph_config::{set_config, ConfigScope, ConfigValue};
use ciris_server::registry_slice::{
    registry_slice_conferred, resolve, RegistrySlice, KEY_REGISTRY_SLICE,
};
use ed25519_dalek::SigningKey;

async fn engine(seed: u8, name: &str) -> (Arc<Engine>, String) {
    let pqc = Arc::new(
        ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(
            &[seed ^ 0x5A; 32],
            format!("{name}-pqc"),
        )
        .expect("ML-DSA-65 seed"),
    );
    let engine = Arc::new(
        Engine::with_signer(
            Arc::new(LocalSigner::from_parts(
                SigningKey::from_bytes(&[seed; 32]),
                name.to_string(),
                Some(pqc),
                Some(format!("{name}-pqc")),
            )),
            "sqlite::memory:",
        )
        .await
        .expect("engine"),
    );
    let node = engine.local_derived_key_id().await.expect("node key id");
    ciris_server::attest::register_key(
        &engine,
        ciris_server::attest::KeySigner::Engine(&engine),
        &node,
        ciris_persist::federation::types::identity_type::NODE,
        serde_json::Value::Null,
    )
    .await
    .expect("register the node key, as boot does before any config write");
    (engine, node)
}

/// An unblessed node resolves the walk to `Ok(None)` — a steady state, not a
/// fault — and composition resolves it to `NotConferred`, which serves nothing.
#[tokio::test]
async fn an_unblessed_node_is_not_conferred_and_does_not_fail_its_boot() {
    let (engine, node) = engine(0xB1, "unblessed-node").await;
    assert!(
        matches!(registry_slice_conferred(&engine, &node).await, Ok(None)),
        "an unblessed node must resolve to Ok(None): Err would fail the boot of a node \
         whose only \"problem\" is that it was never blessed"
    );
    let slice = resolve(&engine, &node, true).await;
    assert!(matches!(slice, RegistrySlice::NotConferred), "{slice:?}");
    assert!(!slice.serves());
}

/// The embedder's flag can only take the slice away.
#[tokio::test]
async fn the_embedder_flag_only_declines() {
    let (engine, node) = engine(0xB2, "embedder-off").await;
    let slice = resolve(&engine, &node, false).await;
    assert!(
        matches!(slice, RegistrySlice::DisabledByEmbedder),
        "{slice:?}"
    );
    assert!(!slice.serves());
}

/// The owner's signed config can decline the slice. Setting it to `true` on an
/// unblessed node confers nothing: config narrows, it never widens.
#[tokio::test]
async fn the_owner_config_declines_and_never_confers() {
    let (engine, node) = engine(0xB3, "owner-config").await;

    set_config(
        &engine,
        KEY_REGISTRY_SLICE,
        ConfigValue::Bool(true),
        &node,
        ConfigScope::default(),
    )
    .await
    .expect("owner writes true");
    let slice = resolve(&engine, &node, true).await;
    assert!(
        matches!(slice, RegistrySlice::NotConferred),
        "`true` must defer to the conferral, not stand in for it: {slice:?}"
    );

    set_config(
        &engine,
        KEY_REGISTRY_SLICE,
        ConfigValue::Bool(false),
        &node,
        ConfigScope::default(),
    )
    .await
    .expect("owner writes false");
    let slice = resolve(&engine, &node, true).await;
    assert!(
        matches!(
            slice,
            RegistrySlice::DeclinedByOwner {
                was_conferred: Some(false)
            }
        ),
        "{slice:?}"
    );

    // A value that is not a boolean narrows: the node cannot tell what its owner
    // meant, so it serves less.
    set_config(
        &engine,
        KEY_REGISTRY_SLICE,
        ConfigValue::Str("yes".into()),
        &node,
        ConfigScope::default(),
    )
    .await
    .expect("owner writes a string");
    let slice = resolve(&engine, &node, true).await;
    assert!(
        matches!(slice, RegistrySlice::DeclinedByOwner { .. }),
        "{slice:?}"
    );
}

/// The production shape confers it. Once a node accepts the baked accord root,
/// the bundle's serve-node grant (all four charter verbs) confers `infra:attest`
/// on the seated canonical — with no charter amendment — while this node, which
/// the bundle does not seat, still holds nothing. Asking about a peer is the
/// same walk the gate runs on itself.
///
/// Production bake only: under `test-anchor` the trust anchor is the software
/// test root, and the seated canonical is not the production one.
#[cfg(not(feature = "test-anchor"))]
#[tokio::test]
async fn the_baked_serve_node_grant_confers_the_slice_on_the_seated_canonical() {
    use ciris_server::registry_slice::infra_attest_conferral;
    let (engine, node) = engine(0xB4, "accepting-node").await;
    let baked = ciris_persist::federation::genesis::canonical_genesis_bundle();
    ciris_server::mesh_genesis::accept_trust_root(&engine, baked)
        .await
        .expect("accept the baked root");

    let seated = baked
        .serve_nodes
        .first()
        .expect("the final genesis seats at least one serve node")
        .record
        .key_id
        .clone();
    let grant = infra_attest_conferral(&engine, &node, &seated)
        .await
        .expect("the walk evaluates")
        .unwrap_or_else(|| {
            panic!("the baked grant must confer infra:attest on the seated canonical {seated}")
        });
    assert_eq!(
        grant.root_key_id,
        ciris_server::mesh_genesis::charter_root_key_id(baked).expect("the bake has a charter"),
        "the conferral roots in the accord charter: {grant:?}"
    );

    assert!(
        registry_slice_conferred(&engine, &node)
            .await
            .expect("evaluates")
            .is_none(),
        "a node the bundle does not seat holds no infra:attest, whatever root it accepts"
    );
}
