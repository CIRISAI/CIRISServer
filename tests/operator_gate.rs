//! What a node's operator reads answers the node's own host and its owner, and
//! nobody else. The read API binds `0.0.0.0` by default, so a route with no check
//! of its own is open to the network; these once were.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Router;
use ciris_persist::prelude::Engine;
use tower::ServiceExt as _;

async fn app() -> Router {
    let ed = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let pqc =
        ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&[8u8; 32], "gate-pqc".to_string())
            .expect("ML-DSA-65 seed");
    let signer = ciris_persist::prelude::LocalSigner::from_parts(
        ed,
        "operator-gate-node".to_string(),
        Some(Arc::new(pqc)),
        Some("gate-pqc".to_string()),
    );
    let engine = Arc::new(
        Engine::with_signer(Arc::new(signer), "sqlite::memory:")
            .await
            .expect("engine"),
    );
    let logs = std::env::temp_dir().join(format!("ciris-operator-gate-{}", std::process::id()));
    std::fs::create_dir_all(&logs).expect("log dir");
    ciris_server::telemetry_logs::router(Arc::clone(&engine), logs)
        .merge(ciris_server::memory_api::router(engine))
}

async fn get(app: &Router, path: &str, from: Option<[u8; 4]>) -> StatusCode {
    let mut b = Request::builder().method("GET").uri(path);
    if let Some(ip) = from {
        b = b.extension(ConnectInfo(SocketAddr::from((ip, 40_000))));
    }
    let req = b.body(Body::empty()).expect("request");
    app.clone().oneshot(req).await.expect("oneshot").status()
}

#[tokio::test]
async fn the_operator_routes_refuse_the_network_and_answer_the_host() {
    let app = app().await;
    for path in [
        "/v1/telemetry/logs",
        "/v1/memory/timeline",
        "/v1/memory/stats",
    ] {
        assert_eq!(
            get(&app, path, Some([203, 0, 113, 9])).await,
            StatusCode::UNAUTHORIZED,
            "{path} answered a stranger on the network"
        );
        assert_eq!(
            get(&app, path, None).await,
            StatusCode::UNAUTHORIZED,
            "{path}: an address we can't establish is not the host"
        );
        assert_ne!(
            get(&app, path, Some([127, 0, 0, 1])).await,
            StatusCode::UNAUTHORIZED,
            "{path} refused the node's own host"
        );
    }
}

/// Liveness stays public, and only liveness: status, version and the conformance
/// fingerprint CC 2.6.4 publishes. The host's pressure moves with its real activity.
#[tokio::test]
async fn public_health_says_it_is_alive_and_keeps_the_rest() {
    let app = ciris_server::health::router();
    let read = |from: [u8; 4]| {
        let app = app.clone();
        async move {
            let req = Request::builder()
                .method("GET")
                .uri("/v1/health")
                .extension(ConnectInfo(SocketAddr::from((from, 40_000))))
                .body(Body::empty())
                .expect("request");
            let resp = app.oneshot(req).await.expect("oneshot");
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .expect("body");
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("json")
        }
    };
    let stranger = read([203, 0, 113, 9]).await;
    assert!(stranger["data"]["resources"].is_null(), "{stranger}");
    assert!(stranger["data"]["version"].is_string());
    assert!(stranger["data"]["conformance"].is_object());
    let host = read([127, 0, 0, 1]).await;
    assert!(host["data"]["resources"].is_object(), "the host keeps it");
}
