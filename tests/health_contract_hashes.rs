//! `/v1/health` contract-hash surface (CIRISServer#323 / SRV-2).
//!
//! persist's docs for `ENVELOPE_VOCABULARY_SHA256` / `TRACE_SUMMARY_EXTRACTION_SHA256`
//! already claim "CIRISServer serves the hash on /v1/health, consumers assert it".
//! This drives the real health router IN-PROCESS (`tower::ServiceExt::oneshot`) and
//! proves the HTTP surface makes that claim TRUE: the endpoint returns a
//! `conformance.contract_hashes` object whose values ARE persist's pinned contract
//! hashes, beside the unchanged, still-top-level `wire_vocabulary_sha256` key — on
//! every health route (`/v1/health`, `/v1/system/health`, the LB-facing `/health`).
//!
//! Scope: the SERVING surface only. The cross-repo RATIFIED pin gate is the
//! contract-drift `tests/` suite; the linked-substrate self-consistency witness runs
//! at boot (`conformance::assert_contract_hashes_pinned`, which `health::router()`
//! fires — so building the router below also exercises it).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _; // for `oneshot`

use ciris_server::conformance;
use ciris_server::health;

async fn get_json(path: &str) -> (StatusCode, serde_json::Value) {
    let app = health::router();
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .expect("build request");
    let resp = app.oneshot(req).await.expect("router oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("collect body");
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// The four persist-pinned contract hashes the health surface must publish, paired
/// with persist's exported const — the values the endpoint MUST echo verbatim.
fn expected() -> [(&'static str, &'static str); 4] {
    [
        (
            "envelope_vocabulary_sha256",
            ciris_persist::federation::envelope::ENVELOPE_VOCABULARY_SHA256,
        ),
        (
            "trace_summary_extraction_sha256",
            ciris_persist::trace_summary_contract::TRACE_SUMMARY_EXTRACTION_SHA256,
        ),
        (
            "consent_grammar_sha256",
            ciris_persist::federation::consent_grammar::CONSENT_GRAMMAR_HASH,
        ),
        (
            "transform_algebra_sha256",
            ciris_persist::federation::transform::TRANSFORM_ALGEBRA_HASH,
        ),
    ]
}

fn assert_conformance_block(conf: &serde_json::Value) {
    // The published key is unchanged and STILL top-level (ADD, don't rename).
    assert_eq!(
        conf["wire_vocabulary_sha256"],
        serde_json::Value::String(conformance::wire_vocabulary_sha256()),
        "wire_vocabulary_sha256 must stay at its published path, unchanged"
    );
    let ch = &conf["contract_hashes"];
    assert!(
        ch.is_object(),
        "conformance.contract_hashes must be an object"
    );
    for (key, pinned) in expected() {
        assert_eq!(
            ch[key],
            serde_json::Value::String(pinned.to_string()),
            "conformance.contract_hashes.{key} must equal persist's pinned hash"
        );
    }
    // Exactly the pinned set — no accidental extras or omissions on the wire surface.
    assert_eq!(
        ch.as_object().map(|m| m.len()),
        Some(expected().len()),
        "contract_hashes must carry exactly the pinned set"
    );
}

#[tokio::test]
async fn v1_health_serves_contract_hashes() {
    let (status, body) = get_json("/v1/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_conformance_block(&body["data"]["conformance"]);
}

#[tokio::test]
async fn system_health_serves_contract_hashes() {
    // The agent inherits + enriches this endpoint; the SERVER base must carry it.
    let (status, body) = get_json("/v1/system/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_conformance_block(&body["data"]["conformance"]);
}

#[tokio::test]
async fn plain_health_serves_contract_hashes() {
    // The LB-facing liveness route carries the same build-conformance block.
    let (status, body) = get_json("/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_conformance_block(&body["conformance"]);
}

/// The values SERVED are exactly what `conformance::contract_hashes()` builds —
/// guards the endpoint and the builder against silently diverging.
#[tokio::test]
async fn served_hashes_match_the_builder() {
    let (_, body) = get_json("/v1/health").await;
    assert_eq!(
        body["data"]["conformance"]["contract_hashes"],
        conformance::contract_hashes()
    );
}
