//! HTTP trace-ingest endpoint — the `listen+1` relay runbook §3.4 promised
//! (CIRISServer trace-ingest break).
//!
//! ## What this proves
//!
//! The agent's `CIRIS-AccordMetrics/1.0` emitter POSTs a SIGNED
//! `AccordEventsBatch` JSON to the legacy lens-python path
//! `/lens-api/api/v1/accord/events`. That path 404s today (lens-python is
//! decommissioned; ciris-server ingests only over Reticulum). This test drives
//! `crate::ingest_http::router` — the new HTTP endpoint mounted on the read-API
//! listener — IN-PROCESS via `tower::ServiceExt::oneshot`, and asserts:
//!
//!   1. **A signed batch POSTed to the LEGACY path persists** — `200` + the
//!      ingest counts, and the trace is in the corpus (proven by an idempotent
//!      re-POST registering a dedup conflict — dedup only fires against a row
//!      that actually landed).
//!   2. **The canonical alias `POST /v1/ingest/accord-events` behaves identically.**
//!   3. **A TAMPERED batch is REJECTED** — `401`, and NOTHING persists (the
//!      verify-before-persist gate inside `Engine::receive_and_persist` is real,
//!      not a rubber stamp; the CEG signature IS the auth, identical to the RET
//!      relay's `LensCoreHandler` posture).
//!   4. **An UNKNOWN-KEY batch is REJECTED** — `401`, nothing persists.
//!
//! The fixture (a hybrid-signed `CompleteTrace` wrapped in a `BatchEnvelope`) is
//! the SAME shape `tests/replication.rs` uses — exactly what the emitter ships
//! and what `AccordEventsBatch` carries over Reticulum.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _; // for `oneshot`

use ciris_persist::federation::types::{algorithm, identity_type};
use ciris_persist::federation::{FederationDirectory as _, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::schema::{
    CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion, TraceComponent, TraceLevel,
};
use ciris_persist::verify::canonical::Canonicalizer;
use ciris_persist::verify::{ed25519::canonical_payload_value, PythonJsonDumpsCanonicalizer};

use ciris_server::ingest_http::{self, CANONICAL_INGEST_PATH, LEGACY_INGEST_PATH};

// ── A fabric node: one independent in-memory Engine + its node-identity signer ──
// Mirrors `tests/replication.rs::node` — production `compose::build_engine`
// minus the hardware seal.
async fn node(node_seed: u8, node_key_id: &str) -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[node_seed; 32]);
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        node_key_id.to_string(),
        None,
        None,
    ));
    let engine = Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("Engine::with_signer (sqlite::memory:) must succeed");
    Arc::new(engine)
}

/// Cross-register an agent's Ed25519 verifying key so `VerifyMode::Full` (the
/// default `receive_and_persist` path the HTTP handler uses) can resolve a trace
/// signed under `key_id`. The founder-quorum door does this in prod.
async fn cross_register(engine: &Engine, key_id: &str, agent_sk: &SigningKey) {
    let pubkey_b64 = BASE64.encode(agent_sk.verifying_key().to_bytes());
    let now = Utc::now();
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: pubkey_b64.clone(),
        pubkey_ml_dsa_65_base64: None,
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::AGENT.into(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": key_id }),
        original_content_hash: "deadbeef".into(),
        scrub_signature_classical: pubkey_b64,
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .sqlite_backend()
        .expect("sqlite backend present")
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("cross-register agent key in federation directory");
}

/// Build the exact wire bytes the `CIRIS-AccordMetrics/1.0` emitter ships: a
/// single FULL-HYBRID-signed `CompleteTrace` wrapped in a `BatchEnvelope` JSON
/// (= `AccordEventsBatch`). Lifted from `tests/replication.rs::build_batch_bytes`.
fn build_batch_bytes(agent_sk: &SigningKey, key_id: &str, trace_id: &str) -> Vec<u8> {
    let mut data = serde_json::Map::new();
    data.insert("seq".into(), serde_json::json!(0));
    let component = TraceComponent {
        component_type: ComponentType::Conscience,
        event_type: ReasoningEventType::ConscienceResult,
        timestamp: "2026-06-14T00:00:00Z".parse().unwrap(),
        data,
        agent_id_hash: None,
    };

    let mut trace = CompleteTrace {
        trace_id: trace_id.into(),
        thought_id: trace_id.into(),
        task_id: Some("task-http-ingest".into()),
        agent_id_hash: "cafebabe".into(),
        started_at: "2026-06-14T00:00:00Z".parse().unwrap(),
        completed_at: "2026-06-14T00:01:00Z".parse().unwrap(),
        trace_level: TraceLevel::Generic,
        trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
        components: vec![component],
        deployment_profile: None,
        cohort_scope: "federation".into(),
        cohort_target_id: None,
        signature: String::new(),
        signature_key_id: key_id.into(),
        signature_ml_dsa_65: None,
        pubkey_ml_dsa_65: None,
        pqc_key_id: None,
    };

    // Hard cut (persist v7.2.0 #225): VerifyMode::Full rejects classical-only.
    // Sign FULL HYBRID — Ed25519 over canon, ML-DSA-65 over (canon ‖ ed25519_sig).
    let payload = canonical_payload_value(&trace);
    let canon = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&payload)
        .expect("canonicalize trace payload");
    let ed_sig = agent_sk.sign(&canon).to_bytes();
    let mut bound = Vec::with_capacity(canon.len() + ed_sig.len());
    bound.extend_from_slice(&canon);
    bound.extend_from_slice(&ed_sig);
    let mldsa = ciris_crypto::MlDsa65Signer::from_seed(&[0x77u8; 32]).expect("ml-dsa seed");
    use ciris_crypto::PqcSigner as _;
    trace.signature = BASE64.encode(ed_sig);
    trace.signature_ml_dsa_65 = Some(BASE64.encode(mldsa.sign(&bound).expect("ml-dsa sign")));
    trace.pubkey_ml_dsa_65 = Some(BASE64.encode(mldsa.public_key().expect("ml-dsa pk")));
    trace.pqc_key_id = Some("test-mldsa".into());

    let envelope = serde_json::json!({
        "events": [{
            "event_type": "complete_trace",
            "trace_level": "generic",
            "trace": serde_json::to_value(&trace).expect("serialize trace"),
        }],
        "batch_timestamp": "2026-06-14T00:00:00Z",
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
    });
    envelope.to_string().into_bytes()
}

/// POST `body` to `path` on the ingest router; return (status, parsed JSON body).
async fn post(engine: Arc<Engine>, path: &str, body: Vec<u8>) -> (StatusCode, serde_json::Value) {
    let app = ingest_http::router(engine);
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        // The deployed emitter's User-Agent — documents that the bridge forwards
        // this verbatim (the route does not gate on it; the signature is the auth).
        .header("user-agent", "CIRIS-AccordMetrics/1.0")
        .body(Body::from(body))
        .expect("build request");
    let resp = app.oneshot(req).await.expect("router oneshot");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

const AGENT_KEY_ID: &str = "agent-alpha";

#[tokio::test]
async fn signed_batch_posted_to_legacy_path_persists() {
    let engine = node(0xA0, "node-a").await;
    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    cross_register(&engine, AGENT_KEY_ID, &agent_sk).await;

    let bytes = build_batch_bytes(&agent_sk, AGENT_KEY_ID, "trace-http-0001");

    // 1. POST to the LEGACY path the emitter targets → 200 + counts.
    let (status, body) = post(Arc::clone(&engine), LEGACY_INGEST_PATH, bytes.clone()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "signed batch on the legacy path must persist, got {status}: {body}"
    );
    assert_eq!(
        body["trace_events_inserted"].as_u64(),
        Some(1),
        "exactly one trace_event must land: {body}"
    );
    assert_eq!(
        body["signatures_verified"].as_u64(),
        Some(1),
        "the CEG signature must verify (verify-before-persist): {body}"
    );
    assert_eq!(
        body["deduplicated"].as_u64(),
        Some(0),
        "first delivery is not a dedup: {body}"
    );

    // The trace is in the corpus — proven by an idempotent re-POST: dedup only
    // fires against a row that ACTUALLY landed (content-addressed merge).
    let (status2, body2) = post(Arc::clone(&engine), LEGACY_INGEST_PATH, bytes).await;
    assert_eq!(
        status2,
        StatusCode::OK,
        "re-delivery must not error: {body2}"
    );
    assert_eq!(
        body2["trace_events_inserted"].as_u64(),
        Some(0),
        "re-delivery must NOT double-insert (idempotent merge): {body2}"
    );
    assert_eq!(
        body2["deduplicated"].as_u64(),
        Some(1),
        "re-delivery must register as a dedup conflict (proves the row is in the corpus): {body2}"
    );
}

#[tokio::test]
async fn signed_batch_posted_to_canonical_alias_persists() {
    let engine = node(0xA1, "node-a").await;
    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    cross_register(&engine, AGENT_KEY_ID, &agent_sk).await;

    let bytes = build_batch_bytes(&agent_sk, AGENT_KEY_ID, "trace-http-canon-0001");
    let (status, body) = post(engine, CANONICAL_INGEST_PATH, bytes).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the canonical alias must behave identically to the legacy path, got {status}: {body}"
    );
    assert_eq!(body["trace_events_inserted"].as_u64(), Some(1), "{body}");
    assert_eq!(body["signatures_verified"].as_u64(), Some(1), "{body}");
}

#[tokio::test]
async fn tampered_batch_is_rejected_and_nothing_persists() {
    let engine = node(0xA2, "node-a").await;
    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    cross_register(&engine, AGENT_KEY_ID, &agent_sk).await;

    let trace_id = "trace-http-tampered-0001";
    let mut bytes = build_batch_bytes(&agent_sk, AGENT_KEY_ID, trace_id);

    // Tamper the SIGNED content AFTER signing: flip the agent_id_hash inside the
    // trace so the canonical bytes no longer match the signature. The envelope is
    // still well-formed JSON (so it parses) but the signature is now invalid.
    let s = String::from_utf8(bytes).expect("utf8");
    let s = s.replace("cafebabe", "deadc0de");
    bytes = s.into_bytes();

    let (status, body) = post(Arc::clone(&engine), LEGACY_INGEST_PATH, bytes).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a tampered batch must be rejected 401 (signature is the auth), got {status}: {body}"
    );
    assert!(
        body["error"].as_str().unwrap_or("").starts_with("verify_"),
        "rejection must be a verify failure: {body}"
    );

    // NOTHING persisted: a fresh re-POST of the SAME tampered bytes is rejected
    // the same way (a persisted row would change nothing here, but a clean
    // legitimate batch for the same trace_id must still be insertable — proving
    // no partial/unsigned row was written under that trace_id).
    let clean = build_batch_bytes(&agent_sk, AGENT_KEY_ID, trace_id);
    let (status_clean, body_clean) = post(engine, LEGACY_INGEST_PATH, clean).await;
    assert_eq!(
        status_clean,
        StatusCode::OK,
        "a clean batch for the same trace_id must insert (no tampered row blocked it): \
         {status_clean}: {body_clean}"
    );
    assert_eq!(
        body_clean["trace_events_inserted"].as_u64(),
        Some(1),
        "the clean trace must be the FIRST insert for this trace_id — the tampered POST \
         persisted nothing: {body_clean}"
    );
    assert_eq!(
        body_clean["deduplicated"].as_u64(),
        Some(0),
        "no prior (tampered) row exists to dedup against: {body_clean}"
    );
}

#[tokio::test]
async fn unknown_key_batch_is_rejected() {
    // Engine that does NOT cross-register the agent key — VerifyMode::Full rejects
    // an unknown-key trace outright (the founder-quorum admission gate is real).
    let engine = node(0xC0, "node-c").await;
    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    // (no cross_register)

    let bytes = build_batch_bytes(&agent_sk, AGENT_KEY_ID, "trace-http-unknown-0001");
    let (status, body) = post(engine, LEGACY_INGEST_PATH, bytes).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a batch signed under an unadmitted key must be rejected 401, got {status}: {body}"
    );
    assert_eq!(
        body["error"].as_str(),
        Some("verify_unknown_key"),
        "rejection must be an unknown-key verify failure: {body}"
    );
}
