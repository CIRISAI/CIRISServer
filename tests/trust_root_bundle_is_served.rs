//! **`GET /v1/trust-root/bundle`** (`FSD/FINAL_GENESIS.md` §3 item 8): the
//! genesis bundle this node runs on, in the registry's shape, public.
//! Production roster: the baked bundle.
#![cfg(not(feature = "test-anchor"))]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use tower::ServiceExt;

async fn get_bundle(app: axum::Router) -> (StatusCode, serde_json::Value) {
    // No ConnectInfo: a remote reader, not loopback.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/trust-root/bundle")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 16 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    (status, body)
}

#[tokio::test]
async fn the_bake_is_served_only_when_trusted_and_importable() {
    let pqc = Arc::new(
        ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(
            &[0x63; 32],
            "bundle-serve-node-pqc".to_string(),
        )
        .expect("ML-DSA-65 seed"),
    );
    let engine = Arc::new(
        Engine::with_signer(
            Arc::new(LocalSigner::from_parts(
                SigningKey::from_bytes(&[0x62; 32]),
                "bundle-serve-node".to_string(),
                Some(pqc),
                Some("bundle-serve-node-pqc".to_string()),
            )),
            "sqlite::memory:",
        )
        .await
        .expect("engine"),
    );
    let node = engine.local_derived_key_id().await.expect("node key id");
    let app = || ciris_server::trust_root_api::public_router(Arc::clone(&engine), node.clone());

    // Not yet trusting the bake's root: it serves nothing.
    let (status, body) = get_bundle(app()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        body["reason_id"], "trust_root.bundle_not_in_force",
        "{body}"
    );

    // Boot's stage 1: register, accept the baked root.
    ciris_server::attest::register_key(
        &engine,
        ciris_server::attest::KeySigner::Engine(&engine),
        &node,
        ciris_persist::federation::types::identity_type::NODE,
        serde_json::Value::Null,
    )
    .await
    .expect("register the node key");
    let baked = ciris_persist::federation::genesis::canonical_genesis_bundle();
    ciris_server::mesh_genesis::accept_trust_root(&engine, baked)
        .await
        .expect("accept the baked root");

    // Trusted now, and the bake (persist v53.1.1: the final genesis) is
    // labelled — it is served in the registry's shape, `community` included.
    assert!(
        ciris_server::mesh_genesis::unlabelled_trust_row(baked).is_none(),
        "premise: the final genesis's trust rows are labelled"
    );
    let (status, body) = get_bundle(app()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["bundle"], serde_json::to_value(baked).unwrap());
    assert_eq!(
        body["bundle_fingerprint"],
        ciris_server::mesh_genesis::fingerprint(baked).unwrap()
    );
    assert_eq!(body["charter_root_key_id"], "humanity-accord");
    assert_eq!(body["served_by"], serde_json::json!(node));
    assert_eq!(
        body["community"]["community"]["community_key_id"], "ciris-canonical",
        "the ciris-canonical birth rides beside the bundle: {}",
        body["community"]
    );
}

/// A labelled charter does not carry legacy grants through the import gate:
/// every trust-job row must be labelled (Codex on CIRISServer#725).
#[test]
fn an_unlabelled_grant_is_named_even_beside_a_labelled_charter() {
    // The July bundle (unlabelled throughout): label its charter only.
    let mut bundle: ciris_server::mesh_genesis::GenesisBundle =
        serde_json::from_str(include_str!("fixtures/genesis_2026-07-31_unlabelled.json"))
            .expect("the July bundle parses");
    // Label the charter, leave the grants as minted (unlabelled).
    for a in &mut bundle.attestations {
        if a.attestation.attestation_id == "genesis-charter" {
            a.attestation.attestation_envelope["dimension"] =
                serde_json::json!(ciris_persist::federation::trust_root::TRUST_CHARTER_DIMENSION);
        }
    }
    assert!(ciris_server::mesh_genesis::bundle_charter_is_labelled(
        &bundle
    ));
    let named = ciris_server::mesh_genesis::unlabelled_trust_row(&bundle)
        .expect("the legacy grant is named");
    assert!(named.starts_with("genesis-grant:"), "{named}");
}
