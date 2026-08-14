//! CEG → memory-graph projection (CIRISServer#127++) — `memory_api::seed_ceg_graph`
//! turns persist's rich CEG state into a contextual graph the client's Graph page
//! renders as a mesh of AttestationCards. Drives the projection against an in-memory
//! hybrid-signed Engine (the SAME setup `tests/config_reconcile.rs` uses), proving:
//!
//!   - a fresh seeded node yields MANY graph nodes (not just `node/identity`), with
//!     the config:* values projected as `config` nodes wired by `has_config` edges;
//!   - every projected node carries the CEG-object identity the client op menu needs
//!     (`kind`, `subject`, `status`);
//!   - the projection is idempotent (a second run neither dups nor errors).

use std::sync::Arc;

use ed25519_dalek::SigningKey;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::identity_type;
use ciris_persist::graph::sqlite::SqliteGraphBackend;
use ciris_persist::graph::types::{EdgeDirection, GraphScope, NodeFilter};
use ciris_persist::graph::GraphService;
use ciris_persist::prelude::{Engine, LocalSigner};

use ciris_server::graph_config::{self, ConfigScope, ConfigValue};
use ciris_server::memory_api;

const NODE_KEY_ID: &str = "ciris-server";

async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    let engine = Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("Engine::with_signer (sqlite::memory:) must succeed");
    Arc::new(engine)
}

async fn node_key_id(engine: &Engine) -> String {
    engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id")
}

async fn register_self(engine: &Engine) {
    let key_id = node_key_id(engine).await;
    // Through the ONE door (CIRISServer#402): the registration envelope now BINDS
    // ITS SUBJECT. The hand-rolled `{"key_id": …}` shape named neither the
    // identity type nor either pubkey, and persist v31 refuses it — an envelope
    // that does not name its subject stands for any record it is pasted onto
    // (CIRISPersist#659).
    ciris_server::attest::register_key(
        engine,
        ciris_server::attest::KeySigner::Engine(engine),
        &key_id,
        identity_type::NODE,
        serde_json::Value::Null,
    )
    .await
    .expect("register node key via admission gate");
}

async fn set(engine: &Arc<Engine>, key: &str, value: ConfigValue) {
    // Post-#315 the config plane resolves its identity internally.
    graph_config::set_config(engine, key, value, "owner", ConfigScope::Local)
        .await
        .unwrap_or_else(|e| panic!("set_config {key}: {e}"));
}

fn graph(engine: &Engine) -> SqliteGraphBackend {
    SqliteGraphBackend::new(
        engine
            .sqlite_backend()
            .expect("sqlite backend")
            .conn_handle(),
    )
}

async fn total_nodes(g: &SqliteGraphBackend) -> u64 {
    let mut n = 0;
    for scope in [
        GraphScope::Local,
        GraphScope::Identity,
        GraphScope::Environment,
        GraphScope::Community,
    ] {
        n += g
            .count_nodes(NodeFilter {
                scope: Some(scope),
                ..Default::default()
            })
            .await
            .unwrap_or(0);
    }
    n
}

/// A fresh seeded node projects MANY nodes with config nodes + `has_config` edges.
#[tokio::test]
async fn seed_ceg_graph_projects_a_rich_graph() {
    let engine = node().await;
    register_self(&engine).await;
    let nk = node_key_id(&engine).await;

    // A handful of config:* objects (the projection turns each into a `config` node).
    set(&engine, "scorer.window", ConfigValue::I64(500)).await;
    set(&engine, "replication.reconcile_secs", ConfigValue::I64(30)).await;
    set(&engine, "mode", ConfigValue::Str("server".into())).await;

    // Seed identity + CEG projection (the two boot calls, in order).
    memory_api::seed_identity_graph(&engine, "node").await;
    memory_api::seed_ceg_graph(&engine).await;

    let g = graph(&engine);

    // CIRISServer#372 Level 2 — the identity WRITTEN INTO THE GRAPH is the id
    // the engine signs as. `NODE_KEY_ID` here is the keystore ALIAS; the derived
    // id is `<alias>-<fingerprint>`, so this assertion fails if the seed ever
    // goes back to writing a label.
    let id_node = g
        .get_node("node/identity", GraphScope::Identity)
        .await
        .expect("identity node read")
        .expect("node/identity must exist");
    assert_eq!(
        id_node.attributes["key_id"], nk,
        "node/identity must carry the ENGINE-derived key id, not a label"
    );
    assert_ne!(
        id_node.attributes["key_id"], NODE_KEY_ID,
        "node/identity must NOT carry the bare keystore alias"
    );
    assert_eq!(id_node.updated_by, nk, "updated_by must be the derived id");

    // Well beyond the single `node/identity` node the old seed produced.
    let n = total_nodes(&g).await;
    assert!(
        n > 1,
        "projection must yield more than the lone identity node, got {n}"
    );

    // The identity node exists and has outgoing edges (owner-binding / has_config).
    let self_edges = g
        .get_edges_for_node(
            "node/identity",
            GraphScope::Identity,
            EdgeDirection::Both,
            None,
        )
        .await
        .expect("edges for node/identity");
    assert!(
        !self_edges.is_empty(),
        "node/identity must have edges after the CEG projection"
    );

    // Each config:* value became a `config` node carrying the client op-menu metadata.
    for key in ["scorer.window", "replication.reconcile_secs", "mode"] {
        let cid = format!("config/{key}");
        let cfg_node = g
            .get_node(&cid, GraphScope::Identity)
            .await
            .expect("config node read")
            .unwrap_or_else(|| panic!("config node {cid} must exist"));
        assert_eq!(cfg_node.attributes["kind"], "config");
        assert_eq!(cfg_node.attributes["subject"], key);
        assert_eq!(cfg_node.attributes["status"], "live");

        // …wired to the node by a `has_config` edge.
        let edges = g
            .get_edges_for_node(&cid, GraphScope::Identity, EdgeDirection::Incoming, None)
            .await
            .expect("config edges");
        assert!(
            edges
                .iter()
                .any(|e| e.relationship == "has_config" && e.source_node_id == "node/identity"),
            "config node {cid} must have a has_config edge from node/identity"
        );
    }
}

/// The projection is idempotent — a second run neither errors nor changes the count.
#[tokio::test]
async fn seed_ceg_graph_is_idempotent() {
    let engine = node().await;
    register_self(&engine).await;
    set(&engine, "scorer.window", ConfigValue::I64(500)).await;

    memory_api::seed_identity_graph(&engine, "node").await;
    memory_api::seed_ceg_graph(&engine).await;
    let g = graph(&engine);
    let first = total_nodes(&g).await;

    // Re-run: must not dup nodes or error.
    memory_api::seed_ceg_graph(&engine).await;
    let second = total_nodes(&g).await;

    assert_eq!(first, second, "re-seed must be idempotent (no dup nodes)");
}
