//! Config reconciler (Server 0.5 Phase 2) — `config_reconcile::resolve` reads the
//! migrated runtime-tunable knobs from the corpus's signed `config:*` objects,
//! falling back to the baked default per absent key. Drives [`resolve`] directly
//! against an in-memory hybrid-signed Engine (the SAME setup
//! `tests/graph_config.rs` uses), proving:
//!
//!   - an EMPTY corpus resolves to the baked defaults ([`ResolvedConfig::default`]);
//!   - a `set_config` override is reflected per key (transport.node, scorer.*,
//!     replication.reconcile_secs, mode);
//!   - a wrong-typed / out-of-range value falls back to the default per key.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

use ciris_server::config_reconcile::{self, ResolvedConfig};
use ciris_server::graph_config::{self, ConfigScope, ConfigValue};

const NODE_KEY_ID: &str = "ciris-server";

/// Stand up the node: in-memory substrate keyed by a HYBRID node-identity signer
/// (Ed25519 + ML-DSA-65 software seed) so `sign_hybrid` (the config write) works.
/// Mirrors `tests/graph_config.rs::node`.
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

/// The node's #247 DERIVED federation key_id — what `set_config` /
/// `config_reconcile::resolve` (and `compose::register_self_key`) use in prod
/// (`cfg.key_id`), and what `Engine::emit_attestation_self` attests under. The
/// bare `NODE_KEY_ID` const is the keystore ALIAS, not the wire key_id.
async fn node_key_id(engine: &Engine) -> String {
    engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id")
}

/// Register the node's own steward key (the `put_attestation` attesting-key FK
/// precondition for any self-attested write). Mirrors `tests/graph_config.rs`.
/// Registers under the DERIVED key_id so `emit_attestation_self` (which attests
/// under `local_derived_key_id()`) resolves the FK + signature-verify.
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
        identity_type: identity_type::STEWARD.into(),
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
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .register_federation_key(SignedKeyRecord { record })
        .await
        .expect("register node steward key via admission gate");
}

async fn set(engine: &Arc<Engine>, key: &str, value: ConfigValue) {
    let nk = node_key_id(engine).await;
    graph_config::set_config(engine, &nk, key, value, "owner", ConfigScope::Local)
        .await
        .unwrap_or_else(|e| panic!("set_config {key}: {e}"));
}

/// An EMPTY corpus resolves to the baked defaults.
#[tokio::test]
async fn resolve_empty_corpus_is_baked_defaults() {
    let engine = node().await;
    register_self(&engine).await;

    let resolved = config_reconcile::resolve(&engine, &node_key_id(&engine).await).await;
    assert_eq!(
        resolved,
        ResolvedConfig::default(),
        "empty corpus must resolve to the baked defaults"
    );

    // Spot-check the documented defaults explicitly.
    assert!(resolved.transport_node);
    assert!(resolved.store_and_forward);
    assert_eq!(resolved.scorer_cadence_secs, 3600);
    assert_eq!(resolved.scorer_window, 500);
    assert_eq!(resolved.scorer_sample_gate, 20);
    assert_eq!(resolved.scorer_target_n_eff, 8.0);
    assert_eq!(resolved.replication_reconcile_secs, 30);
    assert_eq!(resolved.mode, "server");
}

/// Per-key overrides written as `config:*` objects are reflected by `resolve()`.
#[tokio::test]
async fn resolve_reflects_overrides_per_key() {
    let engine = node().await;
    register_self(&engine).await;

    set(
        &engine,
        config_reconcile::KEY_SCORER_CADENCE_SECS,
        ConfigValue::I64(7),
    )
    .await;
    set(
        &engine,
        config_reconcile::KEY_SCORER_WINDOW,
        ConfigValue::I64(123),
    )
    .await;
    set(
        &engine,
        config_reconcile::KEY_SCORER_SAMPLE_GATE,
        ConfigValue::I64(5),
    )
    .await;
    set(
        &engine,
        config_reconcile::KEY_SCORER_TARGET_N_EFF,
        ConfigValue::F64(12.5),
    )
    .await;
    set(
        &engine,
        config_reconcile::KEY_TRANSPORT_NODE,
        ConfigValue::Bool(false),
    )
    .await;
    set(
        &engine,
        config_reconcile::KEY_STORE_AND_FORWARD,
        ConfigValue::Bool(false),
    )
    .await;
    set(
        &engine,
        config_reconcile::KEY_REPLICATION_RECONCILE_SECS,
        ConfigValue::I64(90),
    )
    .await;
    set(
        &engine,
        config_reconcile::KEY_MODE,
        ConfigValue::Str("client".to_string()),
    )
    .await;

    let r = config_reconcile::resolve(&engine, &node_key_id(&engine).await).await;
    assert_eq!(r.scorer_cadence_secs, 7, "scorer.cadence_secs override");
    assert_eq!(r.scorer_window, 123);
    assert_eq!(r.scorer_sample_gate, 5);
    assert_eq!(r.scorer_target_n_eff, 12.5);
    assert!(!r.transport_node, "transport.node override");
    assert!(!r.store_and_forward, "store_and_forward override");
    assert_eq!(r.replication_reconcile_secs, 90);
    assert_eq!(r.mode, "client");

    // The HOT-path derived durations reflect the override.
    assert_eq!(r.scorer_cadence().as_secs(), 7);
    assert_eq!(r.replication_reconcile_interval().as_secs(), 90);
}

/// A wrong-typed or out-of-range value falls back to that key's baked default
/// (a malformed row must never wedge resolution).
#[tokio::test]
async fn resolve_falls_back_on_bad_value_per_key() {
    let engine = node().await;
    register_self(&engine).await;

    // scorer.cadence_secs as a string (wrong type) → default; out-of-range window
    // (> 10_000) → default; non-positive replication secs → default.
    set(
        &engine,
        config_reconcile::KEY_SCORER_CADENCE_SECS,
        ConfigValue::Str("not-a-number".to_string()),
    )
    .await;
    set(
        &engine,
        config_reconcile::KEY_SCORER_WINDOW,
        ConfigValue::I64(999_999),
    )
    .await;
    set(
        &engine,
        config_reconcile::KEY_REPLICATION_RECONCILE_SECS,
        ConfigValue::I64(0),
    )
    .await;
    set(
        &engine,
        config_reconcile::KEY_MODE,
        ConfigValue::Str("   ".to_string()),
    )
    .await;

    let r = config_reconcile::resolve(&engine, &node_key_id(&engine).await).await;
    let d = ResolvedConfig::default();
    assert_eq!(
        r.scorer_cadence_secs, d.scorer_cadence_secs,
        "wrong-typed cadence falls back to default"
    );
    assert_eq!(
        r.scorer_window, d.scorer_window,
        "out-of-range window falls back to default"
    );
    assert_eq!(
        r.replication_reconcile_secs, d.replication_reconcile_secs,
        "non-positive reconcile secs falls back to default"
    );
    assert_eq!(r.mode, d.mode, "blank mode falls back to default");
}
