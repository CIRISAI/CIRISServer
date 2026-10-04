//! **An old portable bundle is refused at import, by name** (persist v53,
//! CC 3.2 T4a "bundle only"; FSD/FINAL_GENESIS.md §3 item 6).
//!
//! A bundle minted before the trust-root rows carried their job labels still
//! VERIFIES — its signatures are real — but outside the one pinned genesis its
//! unlabelled charter installs as no charter, so the root would read as
//! imported and never be valid. The import route refuses it with
//! `trust_root.bundle_unlabelled` and installs nothing.
//!
//! The specimen is the real one: persist's baked production bundle, minted at
//! the 2026-07 ceremony with an unlabelled charter. Production roster only
//! (a test-anchor build swaps the roster, and the bundle would not verify).
#![cfg(not(feature = "test-anchor"))]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use tower::ServiceExt;

#[tokio::test]
async fn the_baked_pre_v53_bundle_verifies_but_is_refused_as_unlabelled() {
    let bundle = ciris_persist::federation::genesis::canonical_genesis_bundle();
    let ours: ciris_server::mesh_genesis::GenesisBundle =
        serde_json::from_value(serde_json::to_value(bundle).unwrap()).unwrap();
    assert!(
        ciris_server::mesh_genesis::verify_bundle(&ours).is_ok(),
        "premise: the old bundle's signatures verify"
    );
    assert!(
        !ciris_server::mesh_genesis::bundle_charter_is_labelled(&ours),
        "premise: its charter carries no trust:charter:v1 label"
    );

    let engine = Arc::new(
        Engine::with_signer(
            Arc::new(LocalSigner::from_parts(
                SigningKey::from_bytes(&[0x61; 32]),
                "import-test-node".to_string(),
                None,
                None,
            )),
            "sqlite::memory:",
        )
        .await
        .expect("engine"),
    );
    let app = ciris_server::trust_root_api::router(engine, "import-test-node".to_string());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/trust-root/import")
                .header("content-type", "application/json")
                // The import is the operator's own act: loopback only.
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    40_000,
                ))))
                .body(Body::from(
                    serde_json::json!({ "bundle": serde_json::to_value(bundle).unwrap() })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let raw = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&raw)
        .unwrap_or_else(|_| panic!("{status}: {}", String::from_utf8_lossy(&raw)));
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["reason_id"], "trust_root.bundle_unlabelled", "{body}");
}
