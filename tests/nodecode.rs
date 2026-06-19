//! NodeCode bootstrap-handle integration (CEG §0.10).
//!
//! Proves `GET /v1/federation/node-code` serves a `CIRIS-V1-...` code that
//! decodes back to THIS node's `key_id` + Ed25519 pubkey, in both the dashed and
//! QR forms — the public, unauthenticated bootstrap handle an operator reads off
//! the node and hands to a founder's app.
//!
//! The codec round-trip / CRC / version / dash-case tolerance unit tests live in
//! `src/nodecode.rs`; the wrong-node-pin + first-run-only ROOT-claim tests live
//! in `tests/root_bootstrap.rs`. This file proves the HTTP node-code endpoint.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use ciris_server::federation_nodecode::{self, build_node_code, render_response_json};
use ciris_server::nodecode::{self, NodeCode};

const NODE_KEY_ID: &str = "ciris-server";

/// Serve the node-code router on an ephemeral port; return its base URL.
async fn serve(response_json: String) -> (String, tokio::task::JoinHandle<()>) {
    let app = federation_nodecode::router(response_json);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn node_code_endpoint_decodes_to_this_nodes_identity() {
    // The node's own identity: key_id + a fixed 32-byte Ed25519 pubkey.
    let pubkey = BASE64.encode([0x11u8; 32]);
    let nc = build_node_code(NODE_KEY_ID, &pubkey, None, None);
    let json = render_response_json(&nc).expect("render node-code response");
    let (base, _h) = serve(json).await;
    let client = reqwest::Client::new();

    // Unauthenticated GET (the code is a public bootstrap handle).
    let resp = client
        .get(format!("{base}/v1/federation/node-code"))
        .send()
        .await
        .expect("GET node-code");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("node-code json");

    assert_eq!(body["key_id"], NODE_KEY_ID);

    // The dashed `code` decodes to this node's key_id + pubkey.
    let code = body["code"].as_str().expect("code field");
    assert!(code.starts_with("CIRIS-V1-"));
    let decoded = nodecode::decode(code).expect("decode served code");
    assert_eq!(decoded.key_id, NODE_KEY_ID);
    assert_eq!(decoded.pubkey_ed25519_base64, pubkey);

    // The QR payload decodes to the SAME identity (no dashes after the prefix).
    let qr = body["qr_payload"].as_str().expect("qr_payload field");
    assert!(qr.starts_with("CIRIS-V1-"));
    assert!(!qr["CIRIS-V1-".len()..].contains('-'));
    let decoded_qr = nodecode::decode(qr).expect("decode served qr");
    assert_eq!(decoded_qr, decoded);
}

#[tokio::test]
async fn node_code_endpoint_carries_hints_when_configured() {
    // A node code with both hints set round-trips through the served response.
    let pubkey = BASE64.encode([0x22u8; 32]);
    let nc = NodeCode {
        key_id: NODE_KEY_ID.into(),
        pubkey_ed25519_base64: pubkey.clone(),
        transport_hint: Some("https://node.example.org:4243".into()),
        alias_hint: Some("Founder Node".into()),
    };
    let json = render_response_json(&nc).expect("render");
    let (base, _h) = serve(json).await;
    let client = reqwest::Client::new();

    let body: serde_json::Value = client
        .get(format!("{base}/v1/federation/node-code"))
        .send()
        .await
        .expect("GET node-code")
        .json()
        .await
        .expect("json");

    // alias_hint is surfaced at the top level (the agent's response shape).
    assert_eq!(body["alias_hint"], "Founder Node");
    let decoded = nodecode::decode(body["code"].as_str().unwrap()).expect("decode");
    assert_eq!(
        decoded.transport_hint.as_deref(),
        Some("https://node.example.org:4243")
    );
    assert_eq!(decoded.alias_hint.as_deref(), Some("Founder Node"));
}
