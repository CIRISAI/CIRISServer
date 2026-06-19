//! Config-as-CEG (Server 0.5 Phase 1) — the signed GraphConfig store over the
//! CEG. Drives [`ciris_server::graph_config`] directly against an in-memory
//! hybrid-signed Engine (the SAME setup `tests/peer_replication.rs` uses), proving
//! the round-trip, version-chaining, latest-wins, prefix-listing, and
//! revoke-reads-as-absent behaviors.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{
    algorithm, attestation_tier, attestation_type, identity_type, Attestation, KeyRecord,
    SignedAttestation, SignedKeyRecord,
};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

use ciris_server::graph_config::{self, CONFIG_DIMENSION};
use ciris_server::{ConfigScope, ConfigValue};

const NODE_KEY_ID: &str = "ciris-server";

/// Stand up the node: in-memory substrate keyed by a HYBRID node-identity signer
/// (Ed25519 + ML-DSA-65 software seed) so `sign_hybrid` (the config write) works.
/// Mirrors `tests/peer_replication.rs::node_a`.
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

/// Register the node's own steward key (the `put_attestation` attesting-key FK
/// precondition for any self-attested write). Mirrors
/// `tests/peer_replication.rs::register_self`.
async fn register_self(engine: &Engine) {
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": NODE_KEY_ID });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize self envelope");
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .expect("self hybrid sign");
    let record = KeyRecord {
        key_id: NODE_KEY_ID.to_string(),
        pubkey_ed25519_base64: BASE64.encode(&sig.classical.public_key),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(&sig.pqc.public_key)),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::STEWARD.into(),
        identity_ref: NODE_KEY_ID.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: NODE_KEY_ID.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .register_federation_key(SignedKeyRecord { record })
        .await
        .expect("register node steward key via admission gate");
}

/// Each `ConfigValue` variant round-trips through set_config → get_config.
#[tokio::test]
async fn each_value_variant_round_trips() {
    let engine = node().await;
    register_self(&engine).await;

    let cases: Vec<(&str, ConfigValue)> = vec![
        ("k.str", ConfigValue::Str("hello".to_string())),
        ("k.i64", ConfigValue::I64(-42)),
        ("k.f64", ConfigValue::F64(1.5)),
        ("k.bool", ConfigValue::Bool(true)),
        (
            "k.list",
            ConfigValue::List(vec![
                serde_json::json!(1),
                serde_json::json!("two"),
                serde_json::json!(true),
            ]),
        ),
        ("k.dict", {
            let mut m = serde_json::Map::new();
            m.insert("a".to_string(), serde_json::json!(1));
            m.insert("b".to_string(), serde_json::json!("x"));
            ConfigValue::Dict(m)
        }),
    ];

    for (key, value) in &cases {
        let written = graph_config::set_config(
            &engine,
            NODE_KEY_ID,
            key,
            value.clone(),
            "owner-user",
            ConfigScope::Local,
        )
        .await
        .expect("set_config");
        assert_eq!(written.version, 1, "first write is version 1");
        assert_eq!(
            written.previous_version, None,
            "first write has no previous"
        );

        let read = graph_config::get_config(&engine, NODE_KEY_ID, key)
            .await
            .expect("get_config")
            .expect("key present after write");
        assert_eq!(
            &read.value, value,
            "value for {key} must round-trip exactly"
        );
        assert_eq!(read.updated_by, "owner-user");
        assert_eq!(read.scope, ConfigScope::Local);
    }

    // Typed accessors.
    assert_eq!(
        graph_config::get_str(&engine, NODE_KEY_ID, "k.str")
            .await
            .unwrap(),
        Some("hello".to_string())
    );
    assert_eq!(
        graph_config::get_i64(&engine, NODE_KEY_ID, "k.i64")
            .await
            .unwrap(),
        Some(-42)
    );
    assert_eq!(
        graph_config::get_f64(&engine, NODE_KEY_ID, "k.f64")
            .await
            .unwrap(),
        Some(1.5)
    );
    assert_eq!(
        graph_config::get_bool(&engine, NODE_KEY_ID, "k.bool")
            .await
            .unwrap(),
        Some(true)
    );
}

/// set_config twice on the same key → version increments, previous_version
/// chains, get_config returns the latest.
#[tokio::test]
async fn set_twice_increments_version_and_chains_previous() {
    let engine = node().await;
    register_self(&engine).await;

    let v1 = graph_config::set_config(
        &engine,
        NODE_KEY_ID,
        "tunable.x",
        ConfigValue::I64(1),
        "owner",
        ConfigScope::Local,
    )
    .await
    .expect("first set");
    assert_eq!(v1.version, 1);
    assert_eq!(v1.previous_version, None);

    let v2 = graph_config::set_config(
        &engine,
        NODE_KEY_ID,
        "tunable.x",
        ConfigValue::I64(2),
        "owner",
        ConfigScope::Local,
    )
    .await
    .expect("second set");
    assert_eq!(v2.version, 2, "second write increments the version");
    assert!(
        v2.previous_version.is_some(),
        "second write chains previous_version to the prior row id"
    );

    let latest = graph_config::get_config(&engine, NODE_KEY_ID, "tunable.x")
        .await
        .expect("get_config")
        .expect("key present");
    assert_eq!(latest.version, 2, "get returns the highest version");
    assert_eq!(
        latest.value,
        ConfigValue::I64(2),
        "get returns the latest value (latest-wins)"
    );
    assert_eq!(latest.previous_version, v2.previous_version);
}

/// list_configs(prefix) returns the latest-per-key filtered by prefix.
#[tokio::test]
async fn list_configs_returns_latest_per_key_filtered_by_prefix() {
    let engine = node().await;
    register_self(&engine).await;

    // Two keys under "replication.", one outside.
    graph_config::set_config(
        &engine,
        NODE_KEY_ID,
        "replication.reconcile_secs",
        ConfigValue::I64(30),
        "owner",
        ConfigScope::Local,
    )
    .await
    .unwrap();
    // Overwrite the first key — list must show the latest.
    graph_config::set_config(
        &engine,
        NODE_KEY_ID,
        "replication.reconcile_secs",
        ConfigValue::I64(60),
        "owner",
        ConfigScope::Local,
    )
    .await
    .unwrap();
    graph_config::set_config(
        &engine,
        NODE_KEY_ID,
        "replication.max_peers",
        ConfigValue::I64(8),
        "owner",
        ConfigScope::Local,
    )
    .await
    .unwrap();
    graph_config::set_config(
        &engine,
        NODE_KEY_ID,
        "safety.age_gate",
        ConfigValue::Bool(true),
        "owner",
        ConfigScope::Identity,
    )
    .await
    .unwrap();

    let filtered = graph_config::list_configs(&engine, NODE_KEY_ID, Some("replication."))
        .await
        .expect("list_configs(prefix)");
    assert_eq!(
        filtered.len(),
        2,
        "exactly the two replication.* keys (latest-per-key)"
    );
    assert_eq!(
        filtered.get("replication.reconcile_secs").unwrap().value,
        ConfigValue::I64(60),
        "list shows the LATEST value for an overwritten key"
    );
    assert_eq!(
        filtered.get("replication.reconcile_secs").unwrap().version,
        2
    );
    assert!(filtered.contains_key("replication.max_peers"));
    assert!(
        !filtered.contains_key("safety.age_gate"),
        "prefix filter excludes non-matching keys"
    );

    // No prefix → all three distinct keys.
    let all = graph_config::list_configs(&engine, NODE_KEY_ID, None)
        .await
        .expect("list_configs(None)");
    assert_eq!(all.len(), 3, "all distinct keys, latest-per-key");
}

/// A recanted (RECANTS) config row reads as absent (revocation honored).
#[tokio::test]
async fn recanted_key_reads_as_absent() {
    let engine = node().await;
    register_self(&engine).await;

    let written = graph_config::set_config(
        &engine,
        NODE_KEY_ID,
        "ephemeral.flag",
        ConfigValue::Bool(true),
        "owner",
        ConfigScope::Local,
    )
    .await
    .expect("set_config");

    // Present before recant.
    assert!(
        graph_config::get_config(&engine, NODE_KEY_ID, "ephemeral.flag")
            .await
            .unwrap()
            .is_some(),
        "key present before recant"
    );

    // Emit a RECANTS by the node targeting the config row's attestation_id.
    recant_row(&engine, &written_row_id(&engine, "ephemeral.flag").await).await;
    // (written.version sanity)
    assert_eq!(written.version, 1);

    let after = graph_config::get_config(&engine, NODE_KEY_ID, "ephemeral.flag")
        .await
        .expect("get_config after recant");
    assert!(after.is_none(), "a recanted key MUST read as absent");

    // And it drops out of the listing too.
    let listed = graph_config::list_configs(&engine, NODE_KEY_ID, None)
        .await
        .unwrap();
    assert!(
        !listed.contains_key("ephemeral.flag"),
        "recanted key is excluded from list_configs"
    );
}

/// Find the substrate `attestation_id` of the latest config row for a key (by
/// reading the raw directory rows the store wrote).
async fn written_row_id(engine: &Arc<Engine>, key: &str) -> String {
    let rows = engine
        .federation_directory()
        .list_attestations_by(NODE_KEY_ID)
        .await
        .expect("list attestations by node");
    rows.into_iter()
        .filter(|a| {
            a.attestation_type == attestation_type::SCORES
                && a.attestation_envelope
                    .get("dimension")
                    .and_then(|d| d.as_str())
                    == Some(CONFIG_DIMENSION)
                && a.attestation_envelope.get("key").and_then(|k| k.as_str()) == Some(key)
        })
        .max_by_key(|a| {
            a.attestation_envelope
                .get("version")
                .and_then(|v| v.as_u64())
        })
        .map(|a| a.attestation_id)
        .expect("config row for key present")
}

/// Emit a node-authored RECANTS attestation targeting `target_attestation_id`
/// (subject_key_ids carries the row id) — the revocation shape `config_key_revoked`
/// recognizes.
async fn recant_row(engine: &Arc<Engine>, target_attestation_id: &str) {
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({
        "dimension": "config:v1",
        "attesting_key_id": NODE_KEY_ID,
        "recants": target_attestation_id,
        "asserted_at": now.to_rfc3339(),
    });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize recant");
    let original_content_hash = hex::encode(Sha256::digest(&canonical));
    let sig = engine.sign_hybrid(&canonical).await.expect("sign recant");

    let attestation = Attestation {
        attestation_id: format!("recant-{target_attestation_id}"),
        attesting_key_id: NODE_KEY_ID.to_string(),
        attested_key_id: NODE_KEY_ID.to_string(),
        attestation_type: attestation_type::RECANTS.to_string(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash,
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: NODE_KEY_ID.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: vec![target_attestation_id.to_string()],
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
    };
    engine
        .federation_directory()
        .put_attestation(SignedAttestation { attestation })
        .await
        .expect("put recant attestation");
}
