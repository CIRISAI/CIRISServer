//! CIRISRegistry#62 / CIRISServer#537 — the registry slice's public reads are
//! served by `ciris-registry-core`'s fold router over THIS node's Engine.
//!
//! What this pins is the composition, not the handler (registry tests the
//! handler). Two things could silently break it:
//!
//! 1. **A second substrate rev.** `fold::router` takes `Arc<Engine>`. If
//!    registry-core ever resolves a different `ciris-persist` than this crate,
//!    the two `Engine` types stop being the same type and this file stops
//!    compiling — which is the point: the failure is a build error here, not a
//!    duplicate substrate discovered in production.
//! 2. **The wrapper growing authority.** The bundle is self-authenticating
//!    (it carries its own accord `authorizations`). An outer
//!    `response_signature` would prove only that the relay said so, which is
//!    what `/v1/steward-key` used to prove and why it was retired
//!    (CIRISRegistry#133).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ciris_persist::prelude::Engine;
use tower::ServiceExt;

async fn engine() -> Arc<Engine> {
    use ciris_keyring::MlDsa65SoftwareSigner;
    use ciris_persist::prelude::LocalSigner;
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xC2; 32], "ciris-server-pqc".to_string())
            .expect("pqc seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        ed25519_dalek::SigningKey::from_bytes(&[0xC1; 32]),
        "fold-test-node".to_string(),
        Some(pqc),
        Some("ciris-server-pqc".to_string()),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine"),
    )
}

async fn get(path: &str) -> (StatusCode, serde_json::Value) {
    let app = ciris_registry_core::fold::router(engine().await, "fold-test-node".to_string());
    let r = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .expect("route answers");
    let status = r.status();
    let bytes = axum::body::to_bytes(r.into_body(), 4 << 20)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn the_trust_root_bundle_is_served_over_this_nodes_engine() {
    let (status, body) = get("/v1/trust-root/bundle").await;
    assert_eq!(status, StatusCode::OK);
    let bundle = &body["bundle"];
    assert!(
        bundle["authorizations"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "the bundle must carry its accord authorizations — they are what make it \
         self-authenticating"
    );
    assert!(
        bundle["holders"].as_array().is_some_and(|a| !a.is_empty()),
        "a consumer re-derives the quorum from the holder roster"
    );
    assert_eq!(body["served_by"]["node_key_id"], "fold-test-node");
}

#[tokio::test]
async fn the_outer_envelope_claims_no_authority() {
    let (_, body) = get("/v1/trust-root/bundle").await;
    let outer = body.as_object().expect("object");
    for forbidden in ["response_signature", "signature_mode", "hardware_class"] {
        assert!(
            !outer.contains_key(forbidden),
            "`{forbidden}` on the outer envelope would prove only that the relay said so \
             (CIRISRegistry#133)"
        );
    }
}

/// An unaccepted root is reported as such. A node relaying the bundle has not
/// thereby accepted it; `accepts_this_root` is the operator's own edge.
#[tokio::test]
async fn a_node_that_has_not_accepted_the_root_says_so() {
    let (_, body) = get("/v1/trust-root/bundle").await;
    assert_eq!(body["served_by"]["accepts_this_root"], false);
}

/// The retired path still answers, with the bundle rather than a self-assertion.
#[tokio::test]
async fn steward_key_serves_the_same_bundle() {
    let (status, body) = get("/v1/steward-key").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["bundle"]["authorizations"].is_array());
    assert!(body.get("stewards").is_none());
}
