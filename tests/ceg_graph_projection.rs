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

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
use ciris_persist::graph::sqlite::SqliteGraphBackend;
use ciris_persist::graph::types::{EdgeDirection, GraphScope, NodeFilter};
use ciris_persist::graph::GraphService;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

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
    let now = chrono::Utc::now();
    let key_id = node_key_id(engine).await;
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize self envelope");
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .expect("self hybrid sign");
    let record = KeyRecord {
        key_id: key_id.clone(),
        pubkey_ed25519_base64: BASE64.encode(&sig.classical.public_key),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(&sig.pqc.public_key)),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::NODE.into(),
        identity_ref: key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .register_federation_key(SignedKeyRecord { record })
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
    memory_api::seed_identity_graph(&engine, &nk, "node").await;
    memory_api::seed_ceg_graph(&engine, &nk).await;

    let g = graph(&engine);

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
    let nk = node_key_id(&engine).await;
    set(&engine, "scorer.window", ConfigValue::I64(500)).await;

    memory_api::seed_identity_graph(&engine, &nk, "node").await;
    memory_api::seed_ceg_graph(&engine, &nk).await;
    let g = graph(&engine);
    let first = total_nodes(&g).await;

    // Re-run: must not dup nodes or error.
    memory_api::seed_ceg_graph(&engine, &nk).await;
    let second = total_nodes(&g).await;

    assert_eq!(first, second, "re-seed must be idempotent (no dup nodes)");
}
