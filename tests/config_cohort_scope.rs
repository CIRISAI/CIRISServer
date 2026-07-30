//! CIRISServer#324 gate — every `config:v1` row this node writes MUST carry
//! `cohort_scope = "self"`, NOT `"federation"`.
//!
//! ## Why this is a two-assertion gate
//!
//! There are TWO `cohort_scope` values on a config write and they must agree:
//!
//!   1. the STORED, typed `Attestation::cohort_scope` column — the value persist's
//!      admission, `cohort_scope::suppresses_holds_bytes` (`SELF | FAMILY`), the
//!      at-rest DEK cascade, and the federation-directory projection actually read.
//!      This is sourced from `EmitAttestationInput::cohort_scope`
//!      (`emit_attestation_assemble`), which `set_config` now sets to `SELF`.
//!   2. the envelope's inline `cohort_scope` JSON field (`graph_config::
//!      config_envelope`), which rides the signed canonical basis and is what an
//!      envelope-reading consumer sees.
//!
//! Before #324, (1) was `federation` (the `with_envelope` default, never
//! overridden) and (2) was `federation` (hardcoded). Fixing only the envelope
//! (the manifest's original one-line prescription) would leave (1) — the
//! load-bearing column — at `federation`, so this gate asserts BOTH. If either
//! regresses, config rows become directory-advertised + cohort-replicable again.
//!
//! Keys covered include the three the manifest names explicitly
//! (`auth.admin_key_ids`, `net.bootstrap_peers`, `federation.peer_sideband.<peer>`)
//! — the last is the owner's node-local peer annotation, the one key that could
//! plausibly be argued into a wider tier; the gate pins it to `self` too, because
//! config-class content is uniformly self-state (CC 4.4.3.4.3).
//!
//! Engine setup mirrors `tests/graph_config.rs` (an in-memory hybrid-signed node).

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{
    algorithm, attestation_type, cohort_scope, identity_type, Attestation, KeyRecord,
    SignedKeyRecord,
};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

use ciris_server::graph_config::{self, CONFIG_DIMENSION};
use ciris_server::{ConfigScope, ConfigValue};

const NODE_KEY_ID: &str = "ciris-server";

/// In-memory substrate keyed by a HYBRID node-identity signer (Ed25519 +
/// ML-DSA-65 software seed) — the `set_config` write path needs `sign_hybrid`.
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

/// Register the node's own steward key (the `put_attestation` attesting-key FK
/// precondition for any self-attested write).
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
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .register_federation_key(SignedKeyRecord { record })
        .await
        .expect("register node steward key via admission gate");
}

/// The latest raw stored `config:v1` [`Attestation`] this node wrote for `key`.
async fn latest_config_row(engine: &Arc<Engine>, key: &str) -> Attestation {
    let nk = node_key_id(engine).await;
    let rows = engine
        .federation_directory()
        .list_attestations_by(&nk)
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
        .expect("config row for key present")
}

/// Every config key — including the manifest-named ones and the owner's per-peer
/// sideband annotation — is written at `cohort_scope::SELF`, in BOTH the stored
/// typed column and the signed envelope. This is the #324 regression gate.
#[tokio::test]
async fn every_config_key_is_self_scoped() {
    let engine = node().await;
    register_self(&engine).await;

    // (key, value) pairs — a representative runtime knob plus the three keys the
    // FSD manifest names as currently mis-scoped; peer_sideband last (the one key
    // that could be argued into a wider tier — pinned to `self` too).
    let cases: Vec<(&str, ConfigValue)> = vec![
        ("scorer.cadence_secs", ConfigValue::I64(3600)),
        (
            "auth.admin_key_ids",
            ConfigValue::List(vec![serde_json::json!("some-admin-key")]),
        ),
        (
            "net.bootstrap_peers",
            ConfigValue::List(vec![serde_json::json!("198.51.100.7:4242")]),
        ),
        ("federation.peer_sideband.peer-key-abc", {
            let mut m = serde_json::Map::new();
            m.insert("trust".to_string(), serde_json::json!("trusted"));
            ConfigValue::Dict(m)
        }),
    ];

    for (key, value) in &cases {
        graph_config::set_config(&engine, key, value.clone(), "owner", ConfigScope::Local)
            .await
            .unwrap_or_else(|e| panic!("set_config({key}) must succeed: {e}"));

        let row = latest_config_row(&engine, key).await;

        // (1) The STORED, typed column — the load-bearing value persist reads.
        assert_eq!(
            row.cohort_scope,
            cohort_scope::SELF,
            "config key {key:?}: stored Attestation.cohort_scope MUST be `self` \
             (got {:?}) — a `federation` row is directory-advertised + \
             cohort-replicable (CIRISServer#324)",
            row.cohort_scope
        );

        // (2) The signed envelope's inline field — must agree, no divergence.
        assert_eq!(
            row.attestation_envelope
                .get("cohort_scope")
                .and_then(|v| v.as_str()),
            Some(cohort_scope::SELF),
            "config key {key:?}: envelope cohort_scope JSON field MUST be `self`"
        );

        // Belt-and-suspenders: `self` is one of the two scopes persist's
        // structural-invisibility predicate protects.
        assert!(
            cohort_scope::suppresses_holds_bytes(&row.cohort_scope),
            "config key {key:?}: cohort_scope {:?} must be suppresses_holds_bytes-protected",
            row.cohort_scope
        );
    }
}
