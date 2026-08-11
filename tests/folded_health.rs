//! **One port must answer both meanings** (CIRISServer#390).
//!
//! A folded deployment serves the node and the brain on one port, and the
//! universal client decides node-vs-agent from `/v1/system/health`: AGENT iff
//! `cognitive_state` is present or the service map is non-empty
//! (`clientModeFrom` in the vendored KMP client).
//!
//! Health is a SUBSTRATE path — the node answers it natively and never proxies
//! it — so on the folded port a full agent reported as a bare NODE, and the
//! client hid the 22 cognitive services of the agent it was connected to.
//! Pointing the client at the brain's own port does not help: that port 404s the
//! node's surface. Neither port served both meanings.
//!
//! These tests drive the REAL router against a REAL upstream, because the
//! failure was never in the merge logic — it was that nobody asked the brain at
//! all. A unit test over a merge function would have passed the whole time.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

/// Serve a fake brain on a loopback port and return its base URL.
async fn spawn_brain(body: serde_json::Value) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/v1/system/health",
        axum::routing::get(move || {
            let b = body.clone();
            async move { axum::Json(b) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a brain port");
    let addr = listener.local_addr().expect("addr");
    let h = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), h)
}

async fn get_health(router: axum::Router) -> serde_json::Value {
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/v1/system/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// A BARE node: no brain, no cognitive_state — and it says so explicitly rather
/// than by omission.
#[tokio::test]
async fn a_bare_node_reports_no_agent_and_no_cognitive_state() {
    let v = get_health(ciris_server::health::router()).await;
    assert_eq!(v["data"]["status"], "ok");
    assert_eq!(v["data"]["role"], "fabric-node");
    assert!(
        v["data"]["cognitive_state"].is_null(),
        "a bare node must not claim a cognitive state: {v}"
    );
    assert_eq!(v["data"]["agent"]["folded"], false);
    assert_eq!(v["data"]["agent"]["reachable"], false);
}

/// **The bug, closed.** A folded brain's `cognitive_state` and service map reach
/// the client through the NODE's port, so `clientModeFrom` resolves AGENT.
#[tokio::test]
async fn a_folded_brain_enriches_the_nodes_own_health() {
    let (base, h) = spawn_brain(serde_json::json!({
        "data": {
            "status": "ok",
            "cognitive_state": "WORK",
            "services": { "llm": "ok", "memory": "ok" },
        }
    }))
    .await;

    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;

    // The agent half arrived...
    assert_eq!(
        v["data"]["cognitive_state"], "WORK",
        "the folded brain's cognitive_state must reach the client on the NODE's port: {v}"
    );
    assert_eq!(v["data"]["services"]["llm"], "ok");
    assert_eq!(v["data"]["agent"]["folded"], true);
    assert_eq!(v["data"]["agent"]["reachable"], true);

    // ...and the NODE's own half survived. Proxying this path wholesale would
    // have answered the agent question and silently lost node liveness — the
    // endpoint has to be the union, not a redirect.
    assert_eq!(v["data"]["status"], "ok");
    assert_eq!(v["data"]["role"], "fabric-node");
    assert!(
        v["data"]["conformance"].is_object(),
        "the node's own conformance block must survive the merge: {v}"
    );
    h.abort();
}

/// THREE STATES, NOT TWO. A brain that is attached but not answering is NOT the
/// same as no brain — and before this both rendered as a bare node, which is
/// exactly the failure. The node stays up and says which case it is.
#[tokio::test]
async fn an_unreachable_brain_is_distinguished_from_no_brain() {
    // A port nobody is listening on: bind then drop, so the address is dead.
    let dead = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let a = l.local_addr().expect("addr");
        drop(l);
        format!("http://{a}")
    };

    let v = get_health(ciris_server::health::router_with_brain(Some(dead))).await;

    // The node's own liveness is UNAFFECTED — a dead brain must not take the
    // node's health answer down with it.
    assert_eq!(v["data"]["status"], "ok");
    assert!(v["data"]["cognitive_state"].is_null());

    // And the distinction is on the wire: attached, but not answering.
    assert_eq!(
        v["data"]["agent"]["folded"], true,
        "a configured brain is FOLDED even when it is not answering: {v}"
    );
    assert_eq!(
        v["data"]["agent"]["reachable"], false,
        "…and unreachable, which is a different fact from 'there is no brain'"
    );
}

/// A brain that answers a BARE object rather than the `{"data":{…}}` envelope
/// still contributes. Being strict here would reintroduce the same outcome —
/// a real agent rendered as a bare node — over a shape difference.
#[tokio::test]
async fn a_brain_answering_without_the_data_envelope_still_contributes() {
    let (base, h) = spawn_brain(serde_json::json!({
        "status": "ok",
        "cognitive_state": "DREAM",
    }))
    .await;
    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;
    assert_eq!(v["data"]["cognitive_state"], "DREAM", "{v}");
    assert_eq!(v["data"]["agent"]["reachable"], true);
    h.abort();
}
