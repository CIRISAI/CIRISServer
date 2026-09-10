//! **The capacity read route answers** — CIRISServer#580.
//!
//! The defect was not a wrong value; it was a missing surface. Every capacity
//! route a client tried returned **404** against a real 0.5.204 while the
//! scorer was writing `capacity:*` rows into the corpus, so a client card built
//! on them could only render a permanent "warming up" placeholder — a screen
//! that says "not yet" about a build where the answer would never come.
//!
//! So the thing worth pinning is the one that was broken: **this route is
//! mounted and answers**, on the same router in node mode and agent mode. The
//! projection's rules are unit-tested next to the code in
//! `src/capacity_read.rs`; this is about the surface existing at all.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use tower::ServiceExt as _;

const NODE_KEY_ID: &str = "ciris-node-bootstrap-capread";

async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xC1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xC2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine"),
    )
}

fn cfg() -> ciris_server::config::ServerConfig {
    ciris_server::config::ServerConfig::from_home(
        std::env::temp_dir().join(format!("capread-{}", std::process::id())),
        NODE_KEY_ID.to_string(),
    )
    .expect("config")
}

async fn get(uri: &str) -> (StatusCode, serde_json::Value) {
    let router = ciris_server::system_data::router(node().await, cfg());
    let resp = router
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body");
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// THE regression: `GET /v1/my-data/capacity` was a 404.
#[tokio::test]
async fn the_capacity_route_is_mounted_and_does_not_404() {
    let (status, _) = get("/v1/my-data/capacity").await;
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "the capacity read route is missing again — this is CIRISServer#580"
    );
    assert!(
        status.is_success(),
        "the capacity route answered {status}, which a client renders as the same \
         dead card a 404 did"
    );
}

/// A node that has never federated must still ANSWER — with a shape the page
/// can render and a reason in words. A 500 here reads to a client exactly like
/// the 404 did.
#[tokio::test]
async fn a_node_with_no_registered_key_answers_with_a_reason_not_an_error() {
    let (status, body) = get("/v1/my-data/capacity").await;
    assert!(status.is_success(), "answered {status}");
    let data = &body["data"];
    assert!(data.is_object(), "the page needs a data object, got {body}");
    // Either it resolved a key and reported (possibly empty) subjects, or it
    // said in words why it could not. What it may never do is answer nothing.
    let explained = data.get("unavailable").and_then(|v| v.as_str()).is_some();
    let reported = data.get("subjects").map(|s| s.is_array()).unwrap_or(false);
    assert!(
        explained || reported,
        "neither a subject list nor a stated reason: {data}"
    );
}
