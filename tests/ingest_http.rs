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
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
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
    post_counted(engine, &ingest_http::IngestRefusals::new(), path, body).await
}

/// [`post`] against an explicit refusal ledger (CIRISServer#370), so a test can
/// read what the gate counted.
async fn post_counted(
    engine: Arc<Engine>,
    refusals: &ingest_http::IngestRefusals,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    let app = ingest_http::router(engine, refusals.clone());
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

// ─────────────────────────────────────────────────────────────────────────────
// CIRISServer#369 + #370 — THE 2026-08-05 INCIDENT, REPRODUCED END TO END.
// ─────────────────────────────────────────────────────────────────────────────

/// **The test that decides whether this work was worth doing.**
///
/// `FSD/RCA_INGEST_REJECTION_2026-08-05.md`: a producer signed with an identity
/// from the wrong derivation namespace, the canonical refused it 8,631 times a
/// day for 71 hours, the last trace was admitted at `2026-08-03T23:30`, and the
/// mesh was dead for two days with every layer reporting success.
///
/// This drives the REAL routes — the real verify-before-persist gate, the real
/// corpus, the real refusal ledger — and asserts that one read of the operator
/// surface would have said so:
///
/// 1. a good producer's trace lands, and the plane reads green;
/// 2. 48 hours later, with nothing new admitted, the SAME corpus reads **red**;
/// 3. the two real incident key ids are refused 401 by the gate — correctly —
///    and the surface reads **`stuck_producer`** and NAMES them;
/// 4. and a node that cannot READ the corpus reads `unknown`, which is not the
///    same value as (2). An instrument that cannot tell the incident from a node
///    it merely failed to ask would not have caught this.
#[tokio::test]
async fn the_2026_08_05_incident_would_have_fired_on_the_operator_surface() {
    use ciris_server::operator_surface::{self, OperatorStateOptions};

    // The two identities from the RCA, verbatim. `agent-{hash[:12]}` is the
    // agent-credits key id — a DIFFERENT namespace from the federation key id,
    // so neither exists in `federation_keys` and the gate is right to refuse.
    const STUCK: [&str; 2] = ["agent-55fe8d181727", "agent-1ee871dcf31b"];
    const GOOD: &str = "ciris-agent-bootstrap-25uzoxtlro";

    let engine = node(0xD0, "node-canonical-1").await;
    let refusals = ingest_http::IngestRefusals::new();

    // ── (1) A good producer lands a trace through the real gate ─────────────
    let good_sk = SigningKey::from_bytes(&[0x21; 32]);
    cross_register(&engine, GOOD, &good_sk).await;
    let bytes = build_batch_bytes(&good_sk, GOOD, "trace-live-0001");
    let (status, body) =
        post_counted(Arc::clone(&engine), &refusals, LEGACY_INGEST_PATH, bytes).await;
    assert_eq!(status, StatusCode::OK, "the good producer must land: {body}");

    // The instant the corpus now reports as its newest arrival. Read from
    // persist's own aggregate — the same reader the surface uses — so the clock
    // below is anchored to the row that actually landed.
    let last_admitted = engine
        .storage_summary()
        .await
        .expect("storage summary")
        .trace_events
        .newest_ts
        .expect("a trace landed, so the corpus has a newest instant");

    let opts = |now: chrono::DateTime<Utc>| OperatorStateOptions {
        self_key_id: Some("node-canonical-1".to_owned()),
        root_key_id: None,
        now: Some(now),
        sla_seconds: None,
    };

    // ── The plane is GREEN while it is being fed ────────────────────────────
    let live = operator_surface::operator_state(
        &engine,
        Err("no edge in this fixture".to_owned()),
        Some(&refusals),
        &opts(last_admitted + chrono::Duration::minutes(5)),
    )
    .await;
    assert_eq!(
        live["trace_plane"]["standing"],
        serde_json::json!("live"),
        "a plane that admitted a trace five minutes ago is being fed: {}",
        live["trace_plane"]
    );
    assert_eq!(live["trace_plane"]["band"], serde_json::json!("green"));
    // ...and the gate counted the ACCEPT, which is the only thing that lets
    // this read `clean` rather than `not_exercised`. Without it, "everything
    // offered was admitted" and "nothing was ever offered" collapse — the exact
    // limitation `RECEIVE_NO_ACCEPTED_COUNTER` documents on the replication
    // plane, and the one this plane does not have to inherit.
    assert_eq!(
        live["ingest"]["accepted_total"],
        serde_json::json!(1),
        "the real route must count what it admitted: {}",
        live["ingest"]
    );
    assert_eq!(
        live["ingest"]["standing"],
        serde_json::json!("clean"),
        "a gate that has admitted a batch and refused none is CLEAN, not untested: {}",
        live["ingest"]
    );

    // ── (3) The stuck producer: correct 401s, at a sustained rate ───────────
    let stuck_sk = SigningKey::from_bytes(&[0x31; 32]);
    for i in 0..60 {
        let who = STUCK[i % STUCK.len()];
        let bytes = build_batch_bytes(&stuck_sk, who, &format!("trace-stuck-{i:04}"));
        let (status, body) =
            post_counted(Arc::clone(&engine), &refusals, LEGACY_INGEST_PATH, bytes).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the gate is RIGHT to refuse an unregistered signer: {body}"
        );
        assert_eq!(body["error"].as_str(), Some("verify_unknown_key"));
    }

    // ── (2) 48 hours later, with nothing new admitted ───────────────────────
    let found_at = last_admitted + chrono::Duration::hours(48);
    let dark = operator_surface::operator_state(
        &engine,
        Err("no edge in this fixture".to_owned()),
        Some(&refusals),
        &opts(found_at),
    )
    .await;

    assert_eq!(
        dark["trace_plane"]["standing"],
        serde_json::json!("dark"),
        "NOTHING has been admitted for 48 hours — this is the whole condition: {}",
        dark["trace_plane"]
    );
    assert_eq!(
        dark["trace_plane"]["band"],
        serde_json::json!("red"),
        "a plane that admitted nothing in two days must be RED, not absent from the display"
    );
    assert_eq!(
        dark["trace_plane"]["last_admitted_at"],
        serde_json::json!(last_admitted),
        "the reading must name WHEN, not only that it is late"
    );
    assert_eq!(dark["band"], serde_json::json!("red"), "{dark}");

    // ── ...and the ingest reading says WHY, and who to go fix ───────────────
    assert_eq!(
        dark["ingest"]["standing"],
        serde_json::json!("stuck_producer"),
        "60 correct refusals from two stable identities is a fault report about someone else: {}",
        dark["ingest"]
    );
    assert_eq!(dark["ingest"]["band"], serde_json::json!("red"));
    assert_eq!(dark["ingest"]["distinct_signers"], serde_json::json!(2));
    let named: std::collections::HashSet<&str> = dark["ingest"]["top_signers"]
        .as_array()
        .expect("top_signers")
        .iter()
        .map(|t| t["signer_id"].as_str().expect("signer_id"))
        .collect();
    for who in STUCK {
        assert!(
            named.contains(who),
            "the reading must NAME the stuck producer — that is what makes it actionable: {}",
            dark["ingest"]
        );
    }
    assert_eq!(
        dark["ingest"]["by_kind"]["verify_unknown_key"],
        serde_json::json!(60),
        "persist's own stable token, carried: {}",
        dark["ingest"]
    );

    // ── (4) The unreadable arm is NOT the same value ────────────────────────
    //
    // Composed directly, because the only honest way to produce it is a corpus
    // read that failed. If this rendered like (2), the surface could not tell
    // the incident from a node it simply failed to ask — the RCA's third and
    // most expensive instrument failure, in a different costume.
    let bundle = refusals.snapshot_at(found_at);
    let blind = operator_surface::compose(
        operator_surface::Sources {
            node: Err("not read in this fixture".to_owned()),
            edge: Err("no edge in this fixture".to_owned()),
            trace: Err("sqlite: database is locked".to_owned()),
            ingest: Some(&bundle),
        },
        found_at,
    );
    assert_eq!(
        blind["trace_plane"]["standing"],
        serde_json::json!("unreadable")
    );
    assert_ne!(
        blind["trace_plane"]["standing"],
        dark["trace_plane"]["standing"],
        "'we could not ask the corpus' and 'the corpus has admitted nothing for two days' must \
         never be the same reading"
    );
    assert_ne!(
        blind["trace_plane"]["band"],
        dark["trace_plane"]["band"],
        "an unasked question is not a known bad"
    );
    assert!(
        blind["unknown"]
            .as_array()
            .expect("unknown")
            .contains(&serde_json::json!("trace_plane")),
        "an unread corpus must be NAMED as an unknown so a red headline cannot hide it: {blind}"
    );

    // ── The healthy-quiet control ───────────────────────────────────────────
    //
    // If the gate cannot tell the incident from a node that is simply being fed,
    // it would have been silent on 2026-08-04 exactly as the node was.
    assert_ne!(
        live["trace_plane"]["band"],
        dark["trace_plane"]["band"],
        "a fed plane and a dead one must not share a band"
    );
    assert_ne!(live["trace_plane"]["band"], blind["trace_plane"]["band"]);
}
