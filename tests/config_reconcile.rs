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

use ed25519_dalek::SigningKey;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::identity_type;
use ciris_persist::prelude::{Engine, LocalSigner};

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
        identity_type::STEWARD,
        serde_json::Value::Null,
    )
    .await
    .expect("register node steward key via admission gate");
}

async fn set(engine: &Arc<Engine>, key: &str, value: ConfigValue) {
    // Post-#315: the config plane resolves its identity INTERNALLY from the
    // engine signer — this test used to derive-and-pass the same id explicitly,
    // which is exactly why it round-tripped while production callers (passing
    // the config alias) read {} over their own writes.
    graph_config::set_config(engine, key, value, "owner", ConfigScope::Local)
        .await
        .unwrap_or_else(|e| panic!("set_config {key}: {e}"));
}

/// An EMPTY corpus resolves to the baked defaults.
#[tokio::test]
async fn resolve_empty_corpus_is_baked_defaults() {
    let engine = node().await;
    register_self(&engine).await;

    let resolved = config_reconcile::resolve(&engine).await;
    assert_eq!(
        resolved,
        ResolvedConfig::default(),
        "empty corpus must resolve to the baked defaults"
    );

    // Spot-check the documented defaults explicitly.
    assert!(resolved.transport_node);
    assert!(resolved.store_and_forward);
    // Against the CONSTANT, not a frozen copy of it — this literal was a THIRD
    // copy of the cadence default (config_reconcile, scorer.rs, here), and a
    // spot-check that restates the value it checks can only ever agree with it.
    assert_eq!(
        resolved.scorer_cadence_secs,
        ciris_server::config_reconcile::DEFAULT_SCORER_CADENCE_SECS
    );
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

    let r = config_reconcile::resolve(&engine).await;
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

    let r = config_reconcile::resolve(&engine).await;
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
