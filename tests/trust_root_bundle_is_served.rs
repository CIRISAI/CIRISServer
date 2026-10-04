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

#[tokio::test]
async fn the_baked_bundle_is_served_in_the_registry_shape() {
    let engine = Arc::new(
        Engine::with_signer(
            Arc::new(LocalSigner::from_parts(
                SigningKey::from_bytes(&[0x62; 32]),
                "bundle-serve-node".to_string(),
                None,
                None,
            )),
            "sqlite::memory:",
        )
        .await
        .expect("engine"),
    );
    // No ConnectInfo: a remote reader, not loopback.
    let app = ciris_server::trust_root_api::public_router(engine, "bundle-serve-node".into());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/trust-root/bundle")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 16 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let baked = ciris_persist::federation::genesis::canonical_genesis_bundle();
    assert_eq!(body["bundle"], serde_json::to_value(baked).unwrap());
    assert_eq!(
        body["bundle_fingerprint"],
        ciris_server::mesh_genesis::fingerprint(baked).unwrap()
    );
    assert_eq!(body["charter_root_key_id"], "humanity-accord");
    assert_eq!(body["served_by"], "bundle-serve-node");
    assert!(
        body.get("community").is_some(),
        "community is present (null on a pre-v3 bake)"
    );
}

/// A labelled charter does not carry legacy grants through the import gate:
/// every trust-job row must be labelled (Codex on CIRISServer#725).
#[test]
fn an_unlabelled_grant_is_named_even_beside_a_labelled_charter() {
    let mut bundle = ciris_persist::federation::genesis::canonical_genesis_bundle().clone();
    // Label the charter, leave the grants as baked (unlabelled).
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
