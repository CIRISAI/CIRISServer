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
//!   5. **The refusal NAMES the derivation namespace** (CIRISServer#371 / RCA
//!      2026-08-05 fix 6) — an agent-credits id comes back `agent_credits`, a
//!      bare label comes back `unrecognized`, and neither echoes the value.
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
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use tower::ServiceExt as _; // for `oneshot`

use ciris_persist::federation::types::{algorithm, identity_type};
use ciris_persist::federation::{FederationDirectory as _, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};

use ciris_server::ingest_http::{
    self, CANONICAL_INGEST_PATH, LEGACY_INGEST_PATH, REFUSAL_TRACE_PLANE_PAUSED,
};
use ciris_server::mesh_config_effect::{EffectiveMeshConfig, MeshConfigEffect};

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

/// The exact wire bytes the `CIRIS-AccordMetrics/1.0` emitter ships: a single
/// FULL-HYBRID-signed `CompleteTrace` wrapped in a `BatchEnvelope` JSON (=
/// `AccordEventsBatch`).
///
/// The construction lives in `tests/support/accord_batch.rs` so this file and
/// `tests/trace_plane_release_gate.rs` cannot disagree about what the producer
/// actually sends — two fixtures for one wire shape is the two-lists-that-
/// -disagree defect applied to the evidence rather than the code.
#[path = "support/accord_batch.rs"]
mod accord_batch;
use accord_batch::build_batch_bytes;

/// POST `body` to `path` on the ingest router with the trace plane OPEN (the
/// owner default, and what an unreadable mesh-config plane also produces).
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
    post_full(engine, refusals, MeshConfigEffect::unwired(), path, body).await
}

/// [`post`] under a given mesh-config reading (CIRISServer#365).
async fn post_under(
    engine: Arc<Engine>,
    mesh_config: MeshConfigEffect,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    post_full(
        engine,
        &ingest_http::IngestRefusals::new(),
        mesh_config,
        path,
        body,
    )
    .await
}

/// The one composition both helpers route through — a second router build would
/// be a second answer to "how is this route wired".
async fn post_full(
    engine: Arc<Engine>,
    refusals: &ingest_http::IngestRefusals,
    mesh_config: MeshConfigEffect,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    let app = ingest_http::router(engine, refusals.clone(), mesh_config);
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
    // `agent-alpha` is neither derivation — a bare label, the CIRISServer#118
    // shape. Naming it `agent_credits` would send the producer chasing the wrong
    // fix, so the refusal says only what it can prove.
    assert_eq!(
        body["key_id_namespace"].as_str(),
        Some("unrecognized"),
        "{body}"
    );
}

/// **The 2026-08-05 incident, end to end** (RCA fix 6, CIRISServer#371).
///
/// The producer held a real Ed25519 key and signed correctly — it just named
/// itself with its **agent-credits** identity, `agent-{sha256(pubkey)[:12]}`,
/// which is not a federation identity. canonical-server-1 refused it 8,631 times
/// a day for 71 hours and the only thing the producer ever received back was the
/// token `verify_unknown_key` — equally true of a typo, a revoked key, a pending
/// registration, and this. Four different fixes; one word.
///
/// This drives the real router, the real `receive_and_persist` verify gate and
/// the real response body, so it fails if ANY link drops the namespace — which
/// the unit tests in `src/ingest_http.rs` cannot tell you.
#[tokio::test]
async fn the_credits_namespace_incident_is_refused_by_name() {
    // The exact id from FSD/RCA_INGEST_REJECTION_2026-08-05.md (4,317/24h).
    const CREDITS_KEY_ID: &str = "agent-55fe8d181727";

    let engine = node(0xC1, "node-c").await;
    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    // No cross_register — exactly the production condition: the credits id is
    // not in `federation_keys`, because it never could be.

    let bytes = build_batch_bytes(&agent_sk, CREDITS_KEY_ID, "trace-http-credits-0001");
    let (status, body) = post(engine, LEGACY_INGEST_PATH, bytes).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the admission gate was always right and must not soften: {status}: {body}"
    );
    assert_eq!(body["error"].as_str(), Some("verify_unknown_key"), "{body}");
    assert_eq!(
        body["key_id_namespace"].as_str(),
        Some("agent_credits"),
        "the producer is the only party who can fix this, and the namespace is \
         the only thing that tells them what to fix: {body}"
    );
    // AV-15: the refused value itself never rides the response.
    assert!(
        !body.to_string().contains(CREDITS_KEY_ID),
        "the offending key id belongs in the log, not the body: {body}"
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
    assert_eq!(
        status,
        StatusCode::OK,
        "the good producer must land: {body}"
    );

    // The instant the corpus now reports as its newest arrival. Read from
    // persist's own aggregate — the same reader the surface uses — so the clock
    // below is anchored to the row that actually landed.
    let last_admitted = engine
        .storage_summary()
        .await
        .expect("storage summary")
        .trace_events
        // v32.1.0 (CIRISPersist#606) — read the SAME field the surface bands on.
        // This used to read `newest_ts` (the producer's assertion) while the
        // surface now uses this node's admission instant, so the test's `now`
        // sat days behind the real admission and the plane read `future_dated`.
        // A test that derives its clock from a different field than the code
        // under test is measuring something else.
        .newest_admitted_at
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
    // offered was admitted" and "nothing was ever offered" collapse — which is
    // precisely what happened on the replication plane, whose `clean` arm carried
    // that collapse until CIRISEdge#457 gave it an accepted-applies counter of
    // its own (see `ReceiveStanding::Applying` / `Converged` / `Idle`).
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
    // Read the refusal ledger FIRST, and near the refusals.
    //
    // `snapshot_at(now)` PRUNES: it drops every event older than `now - 1h` from
    // the ledger in place. So reading the surface at `+48h` (below) does not
    // merely report a stale window — it DESTROYS the 60 refusals, and any later
    // read sees an empty ledger and says `clean`.
    //
    // Two bands, two clocks, and an order that matters: the trace plane is
    // banded 48h after this node's last admission, the ingest ledger over a
    // rolling hour. This only held before v32.1.0 because `last_admitted` was
    // the PRODUCER's fixture timestamp, so `+48h` landed near the refusals by
    // accident; now that it is this node's real admission instant
    // (CIRISPersist#606) the accident is gone.
    let ledger = operator_surface::operator_state(
        &engine,
        Err("no edge in this fixture".to_owned()),
        Some(&refusals),
        &opts(last_admitted + chrono::Duration::minutes(5)),
    )
    .await;

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
        ledger["ingest"]["standing"],
        serde_json::json!("stuck_producer"),
        "60 correct refusals from two stable identities is a fault report about someone else: {}",
        ledger["ingest"]
    );
    assert_eq!(ledger["ingest"]["band"], serde_json::json!("red"));
    assert_eq!(ledger["ingest"]["distinct_signers"], serde_json::json!(2));
    let named: std::collections::HashSet<&str> = ledger["ingest"]["top_signers"]
        .as_array()
        .expect("top_signers")
        .iter()
        .map(|t| t["signer_id"].as_str().expect("signer_id"))
        .collect();
    for who in STUCK {
        assert!(
            named.contains(who),
            "the reading must NAME the stuck producer — that is what makes it actionable: {}",
            ledger["ingest"]
        );
    }
    assert_eq!(
        ledger["ingest"]["by_kind"]["verify_unknown_key"],
        serde_json::json!(60),
        "persist's own stable token, carried: {}",
        ledger["ingest"]
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
        blind["trace_plane"]["standing"], dark["trace_plane"]["standing"],
        "'we could not ask the corpus' and 'the corpus has admitted nothing for two days' must \
         never be the same reading"
    );
    assert_ne!(
        blind["trace_plane"]["band"], dark["trace_plane"]["band"],
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
        live["trace_plane"]["band"], dark["trace_plane"]["band"],
        "a fed plane and a dead one must not share a band"
    );
    assert_ne!(live["trace_plane"]["band"], blind["trace_plane"]["band"]);
}

// ═══════════════════════════════════════════════════════════════════════════
//  `feature.trace_replication` — the mesh-config consumer (CIRISServer#365)
// ═══════════════════════════════════════════════════════════════════════════
//
// #365: the mesh_config plane was operable and NOT effective — nine keys, and
// this repo had a caller for none. An operator could pause the trace plane,
// watch the row admit, watch it fold most-restrictive across roots, watch its
// TTL count down, and **nothing changed.**
//
// So the test that matters is not "the value was read". A test asserting
// `effective == 0` passes against the broken code, because the broken code
// folded correctly and ignored the answer. What must be proven is that the
// SAME batch that persists with the plane open is REFUSED with the plane
// paused, and that nothing lands.

const PAUSE_ROOT: &str = "ingest-pause-root";

/// A mesh-config reading in which a subscribed trust root has paused the trace
/// plane. Built through persist's OWN envelope producer and persist's OWN pure
/// fold — the same two functions production folds with, so this fixture cannot
/// encode a rule the substrate does not.
fn trace_plane_paused() -> MeshConfigEffect {
    use ciris_persist::federation::mesh_config::{fold_mesh_config, mesh_config_envelope};
    use ciris_persist::federation::types::{attestation_tier, attestation_type, cohort_scope};
    use ciris_persist::federation::{MeshConfigBaseline, MeshConfigForm, MeshConfigKey};

    let now = Utc::now();
    let key = MeshConfigKey::FeatureTraceReplication;
    let row = ciris_persist::federation::types::Attestation {
        attestation_id: "mesh-config-pause-row".into(),
        attesting_key_id: "root-holder".into(),
        attested_key_id: PAUSE_ROOT.into(),
        attestation_type: attestation_type::SCORES.to_string(),
        weight: None,
        asserted_at: now - chrono::Duration::minutes(1),
        expires_at: None,
        attestation_envelope: mesh_config_envelope(
            key,
            // 0 = off = LESS flow: a relief, admissible under relieve-never-expand.
            0,
            PAUSE_ROOT,
            MeshConfigForm::Emergency,
            Some(now + chrono::Duration::hours(4)),
            "delegation-ingest-pause",
            None,
            "canonical is congested; shed the heaviest inbound plane",
        ),
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: "root-holder".into(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    };
    MeshConfigEffect::pinned(EffectiveMeshConfig::folded(fold_mesh_config(
        "node-under-relief",
        &MeshConfigBaseline::owner_defaults(),
        &[PAUSE_ROOT.to_string()],
        &[row],
        now,
    )))
}

#[tokio::test]
async fn a_paused_trace_plane_refuses_a_batch_that_would_otherwise_persist() {
    let engine = node(0xB0, "node-b").await;
    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    cross_register(&engine, AGENT_KEY_ID, &agent_sk).await;

    let trace_id = "trace-http-paused-0001";
    let bytes = build_batch_bytes(&agent_sk, AGENT_KEY_ID, trace_id);

    // ── The plane is PAUSED: the batch is refused. ──────────────────────────
    let (status, body) = post_under(
        Arc::clone(&engine),
        trace_plane_paused(),
        LEGACY_INGEST_PATH,
        bytes.clone(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a paused trace plane must refuse the batch, got {status}: {body}"
    );
    assert_eq!(
        body["error"].as_str(),
        Some(REFUSAL_TRACE_PLANE_PAUSED),
        "the refusal must carry its OWN token — 'I refuse your batch' and 'I am not taking \
         batches' are different answers to an emitter: {body}"
    );

    // ── And NOTHING landed. ─────────────────────────────────────────────────
    // The same bytes, now with the plane open, insert as the FIRST row for this
    // trace_id (`deduplicated: 0`). Dedup fires only against a row that actually
    // landed, so a zero here is proof the refused POST persisted nothing — the
    // same evidence shape the tampered-batch test uses.
    let (status_open, body_open) =
        post(Arc::clone(&engine), LEGACY_INGEST_PATH, bytes.clone()).await;
    assert_eq!(
        status_open,
        StatusCode::OK,
        "the SAME batch must persist once the plane is open — otherwise this test proves \
         nothing about the gate: {status_open}: {body_open}"
    );
    assert_eq!(
        body_open["trace_events_inserted"].as_u64(),
        Some(1),
        "the open-plane POST must be the FIRST insert for this trace_id: {body_open}"
    );
    assert_eq!(
        body_open["deduplicated"].as_u64(),
        Some(0),
        "no prior row exists to dedup against — the refused POST wrote nothing: {body_open}"
    );

    // ── The gate is not path-specific. ──────────────────────────────────────
    let (status_alias, body_alias) =
        post_under(engine, trace_plane_paused(), CANONICAL_INGEST_PATH, bytes).await;
    assert_eq!(
        status_alias,
        StatusCode::SERVICE_UNAVAILABLE,
        "the canonical alias must be gated identically: {status_alias}: {body_alias}"
    );
}

#[tokio::test]
async fn an_unreadable_mesh_config_plane_leaves_the_relay_accepting() {
    // The fail-OPEN choice, pinned. A directory read error must not become a
    // silent trace outage: that is the 71-hour failure
    // FSD/RCA_INGEST_REJECTION_2026-08-05.md documents, and fail-closed ingest
    // is how you would build it on purpose.
    let engine = node(0xB1, "node-b").await;
    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    cross_register(&engine, AGENT_KEY_ID, &agent_sk).await;

    let bytes = build_batch_bytes(&agent_sk, AGENT_KEY_ID, "trace-http-unreadable-0001");
    let unreadable =
        MeshConfigEffect::pinned(EffectiveMeshConfig::unreadable("directory unavailable"));
    let (status, body) = post_under(engine, unreadable, LEGACY_INGEST_PATH, bytes).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unreadable mesh-config plane must leave ingest ACCEPTING (the owner default), \
         got {status}: {body}"
    );
    assert_eq!(body["trace_events_inserted"].as_u64(), Some(1), "{body}");
}
