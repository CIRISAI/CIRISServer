//! **The receipt says what the canonical HOLDS, and unknown is not zero.**
//!
//! Two engines: a "canonical" that has admitted some of an agent's traces and a
//! "producer" that authored more of them. The canonical door is served on a real
//! socket; the producer's receipt asks it over HTTP the way a node would, and
//! the numbers must come back as `authored / held / lag` — with an unreachable
//! canonical reading `held: null`, never `held: 0` (CIRISServer#487 was answered
//! by a database query because no surface said this; a surface that said "0"
//! when it meant "could not ask" would be worse than none).
//!
//! The key, trace-batch and engine helpers are the capacity scorer's
//! (`tests/capacity_scorer.rs`), copied rather than shared: that file is the
//! scorer's fixture and this one should not move when it does.

#[path = "support/fixture_pqc.rs"]
mod fixture_pqc;

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type};
use ciris_persist::federation::{KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::schema::{
    CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion, TraceComponent, TraceLevel,
};
use ciris_persist::scrub::NullScrubber;
use ciris_persist::verify::canonical::Canonicalizer;
use ciris_persist::verify::{ed25519::canonical_payload_value, PythonJsonDumpsCanonicalizer};

use ciris_server::trace_receipt::{self, CanonicalRead, UrlSource};

const AGENT_KEY_ID: &str = "agent-receipt";
const AGENT_ID_HASH: &str = "agent-receipt-hash";

fn agent_identity() -> (LocalSigner, String) {
    let signer = LocalSigner::from_parts(
        SigningKey::from_bytes(&[0x11; 32]),
        AGENT_KEY_ID.to_string(),
        Some(Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&[0x12; 32], format!("{AGENT_KEY_ID}-pqc"))
                .expect("agent ml-dsa"),
        ) as Arc<dyn ciris_keyring::PqcSigner>),
        Some(format!("{AGENT_KEY_ID}-pqc")),
    );
    let key_id = signer.derived_key_id();
    (signer, key_id)
}

fn agent_pqc_pubkey_b64() -> String {
    use ciris_crypto::PqcSigner as _;
    BASE64.encode(
        ciris_crypto::MlDsa65Signer::from_seed(&[0x12; 32])
            .expect("agent ml-dsa seed")
            .public_key()
            .expect("agent ml-dsa pk"),
    )
}

/// One in-memory node keyed by a hybrid software signer, with the agent's key
/// registered so its signed batches admit.
async fn node(seed: u8, node_key_id: &str) -> Arc<Engine> {
    use ciris_keyring::PqcSigner as _;
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let ed_pub_b64 = BASE64.encode(signing_key.verifying_key().to_bytes());
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(
            &[seed.wrapping_add(1); 32],
            format!("{node_key_id}-pqc"),
        )
        .expect("node ML-DSA-65 seed"),
    );
    let mldsa_pub_b64 = BASE64.encode(pqc.public_key().await.expect("node ML-DSA-65 pubkey"));
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        node_key_id.to_string(),
        Some(pqc),
        Some(format!("{node_key_id}-pqc")),
    ));
    let engine = Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer (sqlite::memory:)"),
    );
    let derived = engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id");
    register_key_hybrid(
        &engine,
        &derived,
        &ed_pub_b64,
        Some(&mldsa_pub_b64),
        identity_type::NODE,
    )
    .await;
    let (_, agent_key_id) = agent_identity();
    let agent_pub_b64 = BASE64.encode(
        SigningKey::from_bytes(&[0x11; 32])
            .verifying_key()
            .to_bytes(),
    );
    register_key_hybrid(
        &engine,
        &agent_key_id,
        &agent_pub_b64,
        Some(&agent_pqc_pubkey_b64()),
        identity_type::AGENT,
    )
    .await;
    engine
}

async fn register_key_hybrid(
    engine: &Engine,
    key_id: &str,
    ed_pubkey_b64: &str,
    ml_dsa_65_pubkey_b64: Option<&str>,
    id_type: &str,
) {
    use ciris_persist::federation::FederationDirectory as _;
    let now = chrono::Utc::now();
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: ed_pubkey_b64.to_string(),
        pubkey_ml_dsa_65_base64: ml_dsa_65_pubkey_b64.map(str::to_string),
        algorithm: algorithm::HYBRID.into(),
        identity_type: id_type.to_string(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": key_id }),
        original_content_hash: "deadbeef".into(),
        scrub_signature_classical: ed_pubkey_b64.to_string(),
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
        .expect("register key in federation directory");
    fixture_pqc::register(engine).await;
}

/// One signed `CompleteTrace` batch; `idx` names the trace (`trace-rcpt-NNNN`)
/// and spaces `started_at` so newest-first ordering is decided by time, not by
/// id.
fn build_trace_batch(agent_key_id: &str, agent_sk: &SigningKey, idx: usize) -> Vec<u8> {
    let mldsa = fixture_pqc::signer();
    // RFC 3339 text: the wire types (`WireDateTime`) parse from it, and the
    // field they land in decides the type.
    let ts = |secs: usize| -> String {
        (chrono::DateTime::parse_from_rfc3339("2026-06-14T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
            + chrono::Duration::seconds(secs as i64))
        .to_rfc3339()
    };
    let component =
        |event_type, at: usize, data: serde_json::Map<String, serde_json::Value>| TraceComponent {
            component_type: ComponentType::Rationale,
            event_type,
            timestamp: ts(at).parse().unwrap(),
            data,
            agent_id_hash: None,
        };
    let mut dma = serde_json::Map::new();
    dma.insert("csdma_plausibility_score".into(), serde_json::json!(0.7));
    dma.insert("dsdma_domain_alignment".into(), serde_json::json!(0.6));
    let mut idma = serde_json::Map::new();
    idma.insert("idma_k_eff".into(), serde_json::json!(1.5));
    idma.insert("idma_correlation_risk".into(), serde_json::json!(0.2));

    let trace_id = format!("trace-rcpt-{idx:04}");
    let mut trace = CompleteTrace {
        trace_id: trace_id.clone(),
        thought_id: trace_id.clone(),
        task_id: Some("task-rcpt".into()),
        agent_id_hash: AGENT_ID_HASH.into(),
        started_at: ts(idx * 60).parse().unwrap(),
        completed_at: ts(idx * 60 + 30).parse().unwrap(),
        trace_level: TraceLevel::Generic,
        trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
        components: vec![
            component(ReasoningEventType::DmaResults, idx * 60, dma),
            component(ReasoningEventType::IdmaResult, idx * 60 + 1, idma),
        ],
        deployment_profile: None,
        cohort_scope: "federation".into(),
        cohort_target_id: None,
        signature: String::new(),
        signature_key_id: agent_key_id.into(),
        signature_ml_dsa_65: None,
        pubkey_ml_dsa_65: None,
        pqc_key_id: None,
    };
    let payload = canonical_payload_value(&trace);
    let canon = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&payload)
        .expect("canonicalize trace payload");
    let ed_sig = agent_sk.sign(&canon).to_bytes();
    let mut bound = Vec::with_capacity(canon.len() + ed_sig.len());
    bound.extend_from_slice(&canon);
    bound.extend_from_slice(&ed_sig);
    use ciris_crypto::PqcSigner as _;
    trace.signature = BASE64.encode(ed_sig);
    trace.signature_ml_dsa_65 = Some(BASE64.encode(mldsa.sign(&bound).expect("ml-dsa sign")));
    trace.pubkey_ml_dsa_65 = Some(BASE64.encode(mldsa.public_key().expect("ml-dsa pk")));
    trace.pqc_key_id = Some(fixture_pqc::KEY_ID.into());

    serde_json::json!({
        "events": [{
            "event_type": "complete_trace",
            "trace_level": "generic",
            "trace": serde_json::to_value(&trace).expect("serialize trace"),
        }],
        "batch_timestamp": "2026-06-14T00:00:00Z",
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
    })
    .to_string()
    .into_bytes()
}

/// Admit traces `0..n` into `engine` as the agent.
async fn admit(engine: &Engine, n: usize) {
    let (_, agent_key_id) = agent_identity();
    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    let mut inserted = 0usize;
    for i in 0..n {
        let bytes = build_trace_batch(&agent_key_id, &agent_sk, i);
        let summary = engine
            .receive_and_persist(&bytes, &NullScrubber)
            .await
            .expect("ingest synthetic trace");
        inserted += summary.trace_events_inserted;
    }
    assert!(
        inserted >= n,
        "expected at least {n} trace events admitted, got {inserted}"
    );
}

/// Serve the canonical door on an ephemeral port; returns its base URL.
async fn serve_canonical(engine: Arc<Engine>) -> (String, tokio::task::JoinHandle<()>) {
    let app = trace_receipt::router(engine);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

// ─── the canonical door ─────────────────────────────────────────────────────

#[tokio::test]
async fn the_canonical_counts_one_agents_traces_and_names_the_newest() {
    let canonical = node(0xA1, "node-canonical").await;
    admit(&canonical, 5).await;
    let (base, _h) = serve_canonical(Arc::clone(&canonical)).await;
    let client = reqwest::Client::new();

    let json: serde_json::Value = client
        .get(format!("{base}{}", trace_receipt::RECEIPT_ROUTE))
        .query(&[("agent_id_hash", AGENT_ID_HASH)])
        .send()
        .await
        .expect("GET receipt")
        .json()
        .await
        .expect("receipt json");
    let data = &json["data"];
    assert_eq!(data["agent_id_hash"], AGENT_ID_HASH);
    assert_eq!(
        data["traces"], 5,
        "five distinct traces were admitted: {json}"
    );
    assert_eq!(
        data["newest"]["trace_id"], "trace-rcpt-0004",
        "newest is the latest started_at, not the first id: {json}"
    );

    // A hash nobody has written under: zero and NO newest — and that is an
    // answer, distinct from the 503 an unreadable store would give.
    let json: serde_json::Value = client
        .get(format!("{base}{}", trace_receipt::RECEIPT_ROUTE))
        .query(&[("agent_id_hash", "nobody")])
        .send()
        .await
        .expect("GET receipt for unknown hash")
        .json()
        .await
        .expect("json");
    assert_eq!(json["data"]["traces"], 0);
    assert!(json["data"]["newest"].is_null(), "{json}");

    // The hash is required: the door answers about ONE agent, never the corpus.
    let resp = client
        .get(format!("{base}{}", trace_receipt::RECEIPT_ROUTE))
        .send()
        .await
        .expect("GET receipt without a hash");
    assert_eq!(resp.status(), 400);
}

// ─── the producer's receipt ─────────────────────────────────────────────────

#[tokio::test]
async fn the_producer_reads_authored_against_held_and_reports_the_lag() {
    let canonical = node(0xA1, "node-canonical").await;
    admit(&canonical, 5).await;
    let (base, _h) = serve_canonical(Arc::clone(&canonical)).await;

    let producer = node(0xB1, "node-producer").await;
    admit(&producer, 7).await;

    let view = trace_receipt::delivery_receipt(
        &producer,
        vec![CanonicalRead {
            key_id: Some("ciris-canonical-stub".into()),
            url: base.clone(),
            url_source: UrlSource::Config,
        }],
    )
    .await;

    let agents = view["agents"].as_array().expect("agents");
    assert_eq!(agents.len(), 1, "one agent authored here: {view}");
    assert_eq!(agents[0]["agent_id_hash"], AGENT_ID_HASH);
    assert_eq!(agents[0]["authored"], 7);
    assert_eq!(agents[0]["newest_authored"]["trace_id"], "trace-rcpt-0006");

    let c = &view["canonicals"][0];
    assert_eq!(c["url"], base);
    assert_eq!(c["reachable"], true, "{view}");
    let a = &c["agents"][0];
    assert_eq!(a["held"], 5, "the canonical's own count, not ours: {view}");
    assert_eq!(a["lag"], 2, "seven authored, five held: {view}");
    assert_eq!(a["shipped"], true);
    assert_eq!(a["newest_held"]["trace_id"], "trace-rcpt-0004");
    assert_eq!(
        a["newest_matches"], false,
        "the newest thing we made is not the newest thing they hold: {view}"
    );

    let v = &view["verdict"];
    assert_eq!(v["any_canonical_reachable"], true);
    assert_eq!(v["shipped_to_every_reachable_canonical"], false);
    assert_eq!(v["worst_lag"], 2);
    assert!(
        view["hint"]
            .as_str()
            .unwrap_or_default()
            .contains("not held by a canonical"),
        "the hint names the lag: {view}"
    );
}

#[tokio::test]
async fn an_unreachable_canonical_reads_unknown_not_zero() {
    let producer = node(0xB1, "node-producer").await;
    admit(&producer, 3).await;

    // A port nothing listens on.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = l.local_addr().expect("addr");
        drop(l);
        format!("http://{addr}")
    };
    let view = trace_receipt::delivery_receipt(
        &producer,
        vec![CanonicalRead {
            key_id: Some("ciris-canonical-dead".into()),
            url: dead.clone(),
            url_source: UrlSource::DerivedFromIpHint,
        }],
    )
    .await;

    let c = &view["canonicals"][0];
    assert_eq!(c["reachable"], false, "{view}");
    assert_eq!(c["url"], dead, "the URL it tried is in the answer: {view}");
    assert_eq!(c["url_source"], "derived_from_ip_hint");
    assert!(
        c["error"].as_str().is_some_and(|e| e.contains(&dead)),
        "{view}"
    );
    let a = &c["agents"][0];
    assert_eq!(a["authored"], 3);
    assert!(a["held"].is_null(), "unknown is not zero: {view}");
    assert!(a["lag"].is_null(), "{view}");
    assert!(a["shipped"].is_null(), "{view}");

    let v = &view["verdict"];
    assert_eq!(v["any_canonical_reachable"], false);
    assert!(
        v["shipped_to_every_reachable_canonical"].is_null(),
        "{view}"
    );
    assert!(v["worst_lag"].is_null(), "{view}");
    assert!(
        view["hint"]
            .as_str()
            .unwrap_or_default()
            .contains("UNKNOWN"),
        "{view}"
    );
}

#[tokio::test]
async fn a_node_with_no_canonical_and_no_traces_says_so_in_that_order() {
    let producer = node(0xB1, "node-producer").await;
    let view = trace_receipt::delivery_receipt(&producer, Vec::new()).await;
    assert!(
        view["agents"].as_array().is_some_and(Vec::is_empty),
        "{view}"
    );
    assert!(
        view["canonicals"].as_array().is_some_and(Vec::is_empty),
        "{view}"
    );
    assert!(
        view["hint"]
            .as_str()
            .unwrap_or_default()
            .contains("no canonical read URL"),
        "no canonical is the first thing to say — a receipt with nobody to ask is not \
         'nothing authored': {view}"
    );
}

#[tokio::test]
async fn canonical_reads_derive_the_read_api_from_an_ip_hint_unless_configured() {
    // A stock node's baked record carries the canonical's Reticulum `ip` hint
    // and nothing else, so the read URL is derived — and says so.
    let producer = node(0xB1, "node-producer").await;
    let reads = trace_receipt::canonical_reads(&producer).await;
    for r in &reads {
        assert_eq!(r.url_source, UrlSource::DerivedFromIpHint, "{r:?}");
        assert!(
            r.url.starts_with("http://")
                && r.url
                    .ends_with(&format!(":{}", trace_receipt::READ_API_PORT)),
            "derived from the ip hint with the read-API port: {r:?}"
        );
        assert!(r.key_id.is_some(), "a baked canonical is named: {r:?}");
    }
}
