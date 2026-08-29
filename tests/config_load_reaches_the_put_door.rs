//! **The `config:load` self-attestation, through a REAL put door.**
//!
//! Every unit test in `load_shed` passed while two defects made the row
//! unadmittable in production (Codex, PR #504):
//!
//! 1. the dimension carried no `:vN` segment, so persist's
//!    `DimensionAdmissionPolicy` refused it (`MissingVersionSegment`, T3);
//! 2. on a split node the row was stamped as the node and signed by the ACTOR,
//!    so the signature failed verification against the node's registered key.
//!
//! Neither is visible to a test that stops at the `Spec`. Both are invisible in
//! production too — the observer logs "attestation failed" once a minute and
//! nothing ever reaches a peer, which is the failure mode this file exists to
//! make loud. The rule it encodes: **a producer is not tested until its row has
//! been through `put_attestation`.**

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord};
use ciris_persist::federation::SignedKeyRecord;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::sync::Arc;

fn seed(label: &str, n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    let d = Sha256::digest(format!("{label}:{n}").as_bytes());
    s.copy_from_slice(&d);
    s
}

fn signer_for(key_id: &str) -> LocalSigner {
    let ed = SigningKey::from_bytes(&seed(key_id, 1));
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&seed(key_id, 2), format!("{key_id}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        ed,
        key_id.to_string(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    )
}

async fn register(engine: &Engine, signer: &LocalSigner, key_id: &str, ident: &str) {
    let mut envelope = serde_json::json!({ "key_id": key_id });
    let probe = signer.sign_hybrid(b"probe").await.expect("probe");
    let ed_pub = B64.encode(&probe.classical.public_key);
    let pqc_pub = B64.encode(&probe.pqc.public_key);
    ciris_persist::federation::admission::bind_subject_into_envelope(
        &mut envelope,
        key_id,
        ident,
        &ed_pub,
        Some(&pqc_pub),
    )
    .expect("bind subject (#659)");
    let canonical =
        ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope).expect("canon");
    let sig = signer.sign_hybrid(&canonical).await.expect("sign");
    let now = chrono::Utc::now();
    engine
        .register_federation_key(SignedKeyRecord {
            record: KeyRecord {
                key_id: key_id.to_string(),
                pubkey_ed25519_base64: ed_pub,
                pubkey_ml_dsa_65_base64: Some(pqc_pub),
                algorithm: algorithm::HYBRID.into(),
                identity_type: ident.to_string(),
                identity_ref: key_id.to_string(),
                valid_from: now,
                valid_until: None,
                registration_envelope: envelope,
                original_content_hash: hex::encode(Sha256::digest(&canonical)),
                scrub_signature_classical: B64.encode(&sig.classical.signature),
                scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
                scrub_key_id: key_id.to_string(),
                scrub_timestamp: now,
                pqc_completed_at: Some(now),
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .unwrap_or_else(|e| panic!("register {key_id}: {e}"));
}

async fn engine_for(key_id: &str) -> Arc<Engine> {
    Arc::new(
        Engine::with_signer(Arc::new(signer_for(key_id)), "sqlite::memory:")
            .await
            .expect("Engine::with_signer(sqlite::memory:)"),
    )
}

/// **The unsplit node: engine key IS the node key, engine is the right pen.**
///
/// This is the standalone binary and the wheel's bare-agent path. Admission must
/// accept the row — which is what catches a missing `:vN`, a malformed envelope,
/// or any other rule the `Spec` alone cannot see.
#[tokio::test]
async fn an_unsplit_node_emits_a_config_load_row_that_admission_accepts() {
    const NODE: &str = "unsplit-node";
    let engine = engine_for(NODE).await;
    register(&engine, &signer_for(NODE), NODE, identity_type::NODE).await;

    let id =
        ciris_server::load_shed::emit(&engine, &ciris_server::load_shed::NodePen::Engine, NODE)
            .await
            .expect("config:load must be ADMITTED, not merely built");
    assert!(!id.is_empty());

    let rows = engine
        .federation_directory()
        .list_attestations_for(NODE)
        .await
        .expect("read back");
    let row = rows
        .iter()
        .find(|r| {
            r.attestation_envelope
                .get("dimension")
                .and_then(serde_json::Value::as_str)
                == Some(ciris_server::load_shed::DIMENSION)
        })
        .expect("the config:load row is in the store");

    // Signed by the node itself — CC 3.4.5 self-or-owner, on the wire.
    assert_eq!(row.scrub_key_id, NODE);
    assert_eq!(row.attesting_key_id, NODE);
    // And it expires. A row without this is a permanent declaration.
    assert!(
        row.expires_at.is_some(),
        "the row must carry the expiry that bounds the node's standing"
    );
}

/// **The split node: the node's own pen, not the engine's.**
///
/// The engine signs as the ACTOR while `wire_identity()` is the minted node key.
/// Signing with the engine here produces a row stamped as the node and signed by
/// the actor — admission rejects it against the node's registered public key.
/// This is the topology the feature exists for, and the one where the local unit
/// tests were fully green while nothing could ever be admitted.
#[tokio::test]
async fn a_split_node_signs_as_the_node_and_admission_accepts_it() {
    const ACTOR: &str = "split-actor";
    const NODE: &str = "split-node";
    // The engine's identity is the ACTOR — the agent-carrying shape.
    let engine = engine_for(ACTOR).await;
    register(&engine, &signer_for(ACTOR), ACTOR, identity_type::AGENT).await;
    register(&engine, &signer_for(NODE), NODE, identity_type::NODE).await;

    let node_pen = ciris_server::load_shed::NodePen::Node(Arc::new(signer_for(NODE)));
    let id = ciris_server::load_shed::emit(&engine, &node_pen, NODE)
        .await
        .expect("a split node must author config:load with the NODE's pen");
    assert!(!id.is_empty());

    let rows = engine
        .federation_directory()
        .list_attestations_for(NODE)
        .await
        .expect("read back");
    let row = rows
        .iter()
        .find(|r| {
            r.attestation_envelope
                .get("dimension")
                .and_then(serde_json::Value::as_str)
                == Some(ciris_server::load_shed::DIMENSION)
        })
        .expect("the config:load row is in the store");

    assert_eq!(
        row.scrub_key_id, NODE,
        "signed by the NODE — an actor-signed row fails verification against the node's key"
    );
    assert_ne!(row.scrub_key_id, ACTOR, "the engine's pen must not appear");
}

/// **A peer must be able to COMPOSE a verdict from it.**
///
/// Admission is not the last gate. `compose_policy::Composer::screen` refuses an
/// envelope with no `confidence` (`MalformedEnvelope("confidence")`) and does NOT
/// default it — so a row could be admitted, replicated, and still contribute
/// nothing to the verdict a peer would use to stop offering work (Codex, PR #504).
/// The whole point of replicating this is that a peer can act on it, so the
/// producer is checked against the consumer.
#[tokio::test]
async fn a_peer_can_screen_the_row_it_receives() {
    const NODE: &str = "screenable-node";
    let engine = engine_for(NODE).await;
    register(&engine, &signer_for(NODE), NODE, identity_type::NODE).await;

    ciris_server::load_shed::emit(&engine, &ciris_server::load_shed::NodePen::Engine, NODE)
        .await
        .expect("admitted");

    let rows = engine
        .federation_directory()
        .list_attestations_for(NODE)
        .await
        .expect("read back");
    let row = rows
        .iter()
        .find(|r| {
            r.attestation_envelope
                .get("dimension")
                .and_then(serde_json::Value::as_str)
                == Some(ciris_server::load_shed::DIMENSION)
        })
        .expect("row present");

    // The two fields a consumer's screen requires, present and well-formed.
    let conf = row
        .attestation_envelope
        .get("confidence")
        .and_then(serde_json::Value::as_f64)
        .expect("confidence — Composer::screen refuses the envelope without it");
    assert!(
        (0.0..=1.0).contains(&conf),
        "confidence in range, got {conf}"
    );
    assert!(row
        .attestation_envelope
        .get("score")
        .and_then(serde_json::Value::as_f64)
        .is_some());
}

/// **The regression that would have shipped: an unversioned dimension.**
///
/// Asserts the rule directly against persist rather than trusting our constant,
/// so this fails if persist tightens `DimensionAdmissionPolicy` further — the
/// producer-obligation half of CC 3.4.7 checked against the substrate half.
#[tokio::test]
async fn an_unversioned_config_dimension_is_refused_at_admission() {
    const NODE: &str = "unversioned-node";
    let engine = engine_for(NODE).await;
    register(&engine, &signer_for(NODE), NODE, identity_type::NODE).await;

    // The exact shape the first cut emitted: `config:load`, no `:vN`.
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(180);
    let mut spec = ciris_server::load_shed::spec(NODE, expires_at);
    spec.envelope["dimension"] = serde_json::json!("config:load");

    let row = ciris_server::attest::Emit::stamp(NODE, spec)
        .expect("stamp")
        .sign_and_assemble(ciris_server::attest::KeySigner::Engine(&engine))
        .await
        .expect("sign");
    let err = ciris_server::attest::put(&engine, row)
        .await
        .expect_err("persist MUST refuse a scores dimension with no version segment");
    let msg = err.to_string();
    assert!(
        msg.contains("version") || msg.contains("dimension"),
        "the refusal should name the dimension rule, got: {msg}"
    );
}
