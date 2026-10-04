//! **Un-trusting a root withdraws EVERY live acceptance of it** (Codex on
//! CIRISServer#725). An upgraded node holds its pre-v53 acceptance edge AND
//! the labelled one written beside it; persist's `trusted_roots_of` counts
//! either, so `DELETE /v1/trust-root/{root}` withdrawing only the first one it
//! found left the root trusted. Two live acceptances, one delete, none left.
//!
//! Production roster (the baked genesis is what the node accepts).
#![cfg(not(feature = "test-anchor"))]

use std::sync::Arc;

use ciris_persist::federation::types::{attestation_type, cohort_scope};
use ciris_persist::federation::EmitAttestationInput;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;

async fn trusts(engine: &Engine, node: &str, root: &str) -> bool {
    ciris_persist::federation::trust_root::trusted_roots_of(
        engine.federation_directory().as_ref(),
        node,
        chrono::Utc::now(),
    )
    .await
    .expect("trusted_roots_of")
    .iter()
    .any(|r| r == root)
}

#[tokio::test]
async fn two_live_acceptances_one_withdrawal_none_left() {
    // A hybrid signer: a federation-tier emit needs both halves.
    let pqc = Arc::new(
        ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(
            &[0x5b; 32],
            "withdraw-every-acceptance-pqc".to_string(),
        )
        .expect("ML-DSA-65 seed"),
    );
    let engine = Arc::new(
        Engine::with_signer(
            Arc::new(LocalSigner::from_parts(
                SigningKey::from_bytes(&[0x5a; 32]),
                "withdraw-every-acceptance".to_string(),
                Some(pqc),
                Some("withdraw-every-acceptance-pqc".to_string()),
            )),
            "sqlite::memory:",
        )
        .await
        .expect("engine"),
    );
    let bundle = ciris_persist::federation::genesis::canonical_genesis_bundle();
    let root = ciris_server::mesh_genesis::charter_root_key_id(bundle).expect("the baked root");
    let node = engine.local_derived_key_id().await.expect("node key id");
    // The node registers through the one door, as boot does.
    ciris_server::attest::register_key(
        &engine,
        ciris_server::attest::KeySigner::Engine(&engine),
        &node,
        ciris_persist::federation::types::identity_type::NODE,
        serde_json::Value::Null,
    )
    .await
    .expect("register the node key");

    // One acceptance through the server's own door...
    ciris_server::mesh_genesis::accept_trust_root(&engine, bundle)
        .await
        .expect("accept the baked root")
        .expect("the baked root's head is held, so the acceptance is written");
    // ...and a second live one beside it, as an upgraded node holds.
    let mut envelope = engine
        .trust_acceptance_envelope(&root, &["infra:attest", "infra:serve"])
        .await
        .expect("acceptance envelope");
    envelope["references_attestation_id"] =
        serde_json::Value::String(format!("trust-edge:{node}:{root}:second"));
    let mut input = EmitAttestationInput::with_envelope(
        attestation_type::DELEGATES_TO,
        ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope).unwrap(),
        cohort_scope::FEDERATION,
    );
    input.attested_key_id = Some(root.clone());
    engine
        .emit_attestation_self(input)
        .await
        .expect("a second live acceptance");
    let live = engine
        .federation_directory()
        .list_attestations_by(&node)
        .await
        .unwrap()
        .into_iter()
        .filter(|a| {
            a.attested_key_id == root && a.attestation_type == attestation_type::DELEGATES_TO
        })
        .count();
    assert!(
        live >= 2,
        "premise: two acceptance edges are held, got {live}"
    );
    assert!(
        trusts(&engine, &node, &root).await,
        "premise: the root is trusted"
    );

    assert!(
        ciris_server::mesh_genesis::withdraw_trust_acceptance(&engine, &root)
            .await
            .expect("withdraw"),
        "something was withdrawn"
    );
    assert!(
        !trusts(&engine, &node, &root).await,
        "after one un-trust the root must not be trusted through the other acceptance"
    );
    assert!(
        !ciris_server::mesh_genesis::withdraw_trust_acceptance(&engine, &root)
            .await
            .expect("withdraw again"),
        "nothing live is left to withdraw"
    );
}
