//! **The receipt says what the canonical HOLDS — signed, bound to the ask —
//! and unknown is not zero.**
//!
//! Two engines: a "canonical" that has admitted some of an agent's traces and a
//! "producer" that authored more of them. The canonical door is served on a real
//! socket; the producer's receipt asks it over HTTP the way a node would,
//! verifies the answer against the canonical's REGISTERED key in the producer's
//! own directory, and checks the signed answer is the answer to ITS question.
//! The verdict is whether the newest trace the producer authored is held —
//! asked by id — not whether the counts line up.
//!
//! Pinned here, one test each:
//!   * count + newest for one agent, the by-id check, and the echoed nonce;
//!   * "authored here" is the SIGNER, not the store — a canonical asking itself
//!     finds nothing, a node whose key signed the traces finds them, and paging
//!     past newer foreign rows still finds them (or says it stopped);
//!   * a signed receipt from a registered canonical VERIFIES; a tampered one
//!     reads `failed`, an unsigned one `unavailable`, both with `held: null`;
//!   * a VALID receipt replayed for a different ask reads `failed`;
//!   * a receipt signed by a registered key that is not the named canonical is
//!     not its receipt;
//!   * a body over the receipt limit is refused before it is buffered;
//!   * an unreachable canonical reads unknown, not zero;
//!   * the verdict covers canonicals that ANSWERED — one dead or one
//!     unverifiable beside one live does not turn "delivered" into "not";
//!   * a roster that could not be read is a STORE fault, not "no canonical".
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

use ciris_server::trace_receipt::{self, CanonicalRead, CanonicalRoster, UrlSource};

/// An agent: a hybrid software signer (Ed25519 seed `ed`, ML-DSA seed `pqc`)
/// and the AV-9 hash its traces carry.
struct Agent {
    alias: &'static str,
    hash: &'static str,
    ed: u8,
    pqc: u8,
}

const AGENT_A: Agent = Agent {
    alias: "agent-receipt",
    hash: "agent-receipt-hash",
    ed: 0x11,
    pqc: 0x12,
};
/// Another agent entirely — its rows are FOREIGN to a node signing as A.
const AGENT_B: Agent = Agent {
    alias: "agent-other",
    hash: "agent-other-hash",
    ed: 0x21,
    pqc: 0x22,
};

impl Agent {
    fn sk(&self) -> SigningKey {
        SigningKey::from_bytes(&[self.ed; 32])
    }
    /// The signer and its DERIVED key id — the id its traces carry as
    /// `signature_key_id`, and the id a node whose engine signs as this agent
    /// reports as `local_derived_key_id()`.
    fn signer(&self) -> (Arc<LocalSigner>, String) {
        let signer = Arc::new(LocalSigner::from_parts(
            self.sk(),
            self.alias.to_string(),
            Some(Arc::new(
                MlDsa65SoftwareSigner::from_seed_bytes(
                    &[self.pqc; 32],
                    format!("{}-pqc", self.alias),
                )
                .expect("agent ml-dsa"),
            ) as Arc<dyn ciris_keyring::PqcSigner>),
            Some(format!("{}-pqc", self.alias)),
        ));
        let key_id = signer.derived_key_id();
        (signer, key_id)
    }
    fn pubkeys_b64(&self) -> (String, String) {
        use ciris_crypto::PqcSigner as _;
        let ed = BASE64.encode(self.sk().verifying_key().to_bytes());
        let pqc = BASE64.encode(
            ciris_crypto::MlDsa65Signer::from_seed(&[self.pqc; 32])
                .expect("agent ml-dsa seed")
                .public_key()
                .expect("agent ml-dsa pk"),
        );
        (ed, pqc)
    }
}

/// A node: its engine, its derived key id, and its two pubkeys (base64) so
/// ANOTHER node can register it and verify what it signs.
struct Node {
    engine: Arc<Engine>,
    key_id: String,
    ed_pub_b64: String,
    mldsa_pub_b64: String,
}

/// One in-memory node keyed by its OWN hybrid software signer (seeded from
/// `seed`), with both agents' keys registered so their signed batches admit.
async fn node(seed: u8, alias: &str) -> Node {
    use ciris_keyring::PqcSigner as _;
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let ed_pub_b64 = BASE64.encode(signing_key.verifying_key().to_bytes());
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed.wrapping_add(1); 32], format!("{alias}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let mldsa_pub_b64 = BASE64.encode(pqc.public_key().await.expect("node ML-DSA-65 pubkey"));
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        alias.to_string(),
        Some(pqc),
        Some(format!("{alias}-pqc")),
    ));
    let engine = Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer (sqlite::memory:)"),
    );
    let key_id = engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id");
    register_key_hybrid(
        &engine,
        &key_id,
        &ed_pub_b64,
        Some(&mldsa_pub_b64),
        identity_type::NODE,
    )
    .await;
    register_agent(&engine, &AGENT_A).await;
    register_agent(&engine, &AGENT_B).await;
    Node {
        engine,
        key_id,
        ed_pub_b64,
        mldsa_pub_b64,
    }
}

/// A node whose engine signs AS AN AGENT — the embedded-agent shape, where the
/// process's own federation key is the one on its traces.
async fn node_signing_as(agent: &Agent) -> Arc<Engine> {
    let (signer, _) = agent.signer();
    let engine = Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer (sqlite::memory:)"),
    );
    register_agent(&engine, &AGENT_A).await;
    register_agent(&engine, &AGENT_B).await;
    engine
}

async fn register_agent(engine: &Engine, agent: &Agent) {
    let (_, key_id) = agent.signer();
    let (ed, pqc) = agent.pubkeys_b64();
    register_key_hybrid(engine, &key_id, &ed, Some(&pqc), identity_type::AGENT).await;
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

/// Make the producer able to VERIFY the canonical: its key, registered here.
async fn trust(producer: &Engine, canonical: &Node) {
    register_key_hybrid(
        producer,
        &canonical.key_id,
        &canonical.ed_pub_b64,
        Some(&canonical.mldsa_pub_b64),
        identity_type::NODE,
    )
    .await;
}

/// One signed `CompleteTrace` batch by `agent`; `idx` names the trace
/// (`trace-rcpt-NNNN`) and spaces `started_at` so newest-first ordering is
/// decided by time, not by id.
fn build_trace_batch(agent: &Agent, idx: usize) -> Vec<u8> {
    let (_, agent_key_id) = agent.signer();
    let agent_sk = agent.sk();
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
        agent_id_hash: agent.hash.into(),
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
        signature_key_id: agent_key_id,
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

/// Admit the named traces into `engine` as `agent`.
async fn admit(engine: &Engine, agent: &Agent, ids: impl IntoIterator<Item = usize>) {
    for i in ids {
        engine
            .receive_and_persist(&build_trace_batch(agent, i), &NullScrubber)
            .await
            .expect("ingest synthetic trace");
    }
}

/// Serve a router on an ephemeral port; returns its base URL.
async fn serve(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

fn read(url: String, key_id: &str) -> CanonicalRead {
    CanonicalRead {
        key_id: key_id.to_string(),
        url,
        url_source: UrlSource::Config,
    }
}

fn roster(reads: Vec<CanonicalRead>) -> Result<CanonicalRoster, String> {
    Ok(CanonicalRoster {
        reads,
        refused: Vec::new(),
    })
}

/// A "canonical" that serves a FIXED body at the receipt route — for the
/// forged, unsigned, replayed and oversized cases.
fn stub(body: serde_json::Value) -> axum::Router {
    axum::Router::new().route(
        trace_receipt::RECEIPT_ROUTE,
        axum::routing::get(move || {
            let body = body.clone();
            async move { axum::Json(body) }
        }),
    )
}

/// GET a real receipt from `base` for `hash` (+ optional trace id), with a
/// nonce of our choosing.
async fn get_receipt(
    base: &str,
    hash: &str,
    trace_id: Option<&str>,
    nonce: &str,
) -> reqwest::Response {
    let mut q = vec![("agent_id_hash", hash), ("nonce", nonce)];
    if let Some(t) = trace_id {
        q.push(("trace_id", t));
    }
    reqwest::Client::new()
        .get(format!("{base}{}", trace_receipt::RECEIPT_ROUTE))
        .query(&q)
        .send()
        .await
        .expect("GET receipt")
}

// ─── the canonical door ─────────────────────────────────────────────────────

#[tokio::test]
async fn the_canonical_counts_one_agents_traces_names_the_newest_answers_by_id_and_echoes_the_nonce(
) {
    let canonical = node(0xA1, "node-canonical").await;
    admit(&canonical.engine, &AGENT_A, 0..5).await;
    let (base, _h) = serve(trace_receipt::router(Arc::clone(&canonical.engine))).await;

    let json: serde_json::Value = get_receipt(&base, AGENT_A.hash, None, "n-1")
        .await
        .json()
        .await
        .expect("receipt json");
    let data = &json["data"];
    assert_eq!(data["agent_id_hash"], AGENT_A.hash);
    assert_eq!(
        data["traces"], 5,
        "five distinct traces were admitted: {json}"
    );
    assert_eq!(
        data["newest"]["trace_id"], "trace-rcpt-0004",
        "newest is the latest started_at, not the first id: {json}"
    );
    assert!(
        data.get("holds_trace").is_none(),
        "nothing asked by id: {json}"
    );
    assert_eq!(
        data["nonce"], "n-1",
        "the nonce is echoed INSIDE the signed data: {json}"
    );
    assert_eq!(
        json["signature"]["manifest"]["signer_key_id"], canonical.key_id,
        "the receipt is signed by the canonical's own node key: {json}"
    );

    // By id: held for THIS agent, or not.
    let json: serde_json::Value = get_receipt(&base, AGENT_A.hash, Some("trace-rcpt-0002"), "n")
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(json["data"]["holds_trace"], true, "{json}");
    let json: serde_json::Value = get_receipt(&base, AGENT_A.hash, Some("trace-rcpt-0099"), "n")
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(json["data"]["holds_trace"], false, "{json}");
    // A held id under ANOTHER agent's hash is not that agent's trace.
    let json: serde_json::Value = get_receipt(&base, AGENT_B.hash, Some("trace-rcpt-0002"), "n")
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(json["data"]["holds_trace"], false, "{json}");
    assert_eq!(json["data"]["traces"], 0);

    // A hash nobody has written under: zero and NO newest — and that is an
    // answer, distinct from the 503 an unreadable store would give.
    let json: serde_json::Value = get_receipt(&base, "nobody", None, "n")
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(json["data"]["traces"], 0);
    assert!(json["data"]["newest"].is_null(), "{json}");

    // The hash is required: the door answers about ONE agent, never the corpus.
    let resp = reqwest::Client::new()
        .get(format!("{base}{}", trace_receipt::RECEIPT_ROUTE))
        .send()
        .await
        .expect("GET receipt without a hash");
    assert_eq!(resp.status(), 400);
}

// ─── "authored here" is the signer, not the store ───────────────────────────

#[tokio::test]
async fn authored_here_is_decided_by_the_signing_key_not_by_what_the_store_holds() {
    // A canonical asking itself: holds five of the agent's traces, signed by
    // the AGENT's key, not its own. Authored here: none.
    let canonical = node(0xA1, "node-canonical").await;
    admit(&canonical.engine, &AGENT_A, 0..5).await;
    let (mine, d) = trace_receipt::authored_here(&canonical.engine, None)
        .await
        .expect("read");
    assert!(
        mine.is_empty(),
        "a node reports only traces ITS key signed; these are the agent's: {mine:?}"
    );
    assert_eq!(d.mode, "signing_key");
    assert_eq!(d.rows_scanned, 5);
    assert!(!d.truncated);

    // The embedded-agent shape: the engine signs as the agent, so the traces'
    // signing key IS this node's own key. Authored here: all of them.
    let producer = node_signing_as(&AGENT_A).await;
    admit(&producer, &AGENT_A, 0..3).await;
    let (mine, _) = trace_receipt::authored_here(&producer, None)
        .await
        .expect("read");
    assert_eq!(mine.len(), 1, "{mine:?}");
    assert_eq!(mine[0].agent_id_hash, AGENT_A.hash);
    assert_eq!(mine[0].authored, 3);
    assert_eq!(
        mine[0]
            .newest_authored
            .as_ref()
            .map(|n| n.trace_id.as_str()),
        Some("trace-rcpt-0002")
    );

    // Naming the hash skips discovery entirely — the embedded agent knows its
    // own — and works on a node whose key signed nothing.
    let (mine, d) = trace_receipt::authored_here(&canonical.engine, Some(AGENT_A.hash))
        .await
        .expect("read");
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].authored, 5);
    assert_eq!(d.mode, "explicit");
    assert_eq!(d.rows_scanned, 0);
}

#[tokio::test]
async fn discovery_pages_past_newer_foreign_rows_and_says_when_it_stopped_early() {
    // A node signing as A holds four of A's rows and, NEWER than all of them,
    // six of B's (replicated). A first page of two is all B.
    let producer = node_signing_as(&AGENT_A).await;
    admit(&producer, &AGENT_A, 0..4).await;
    admit(&producer, &AGENT_B, 10..16).await;

    // Paging on: A is found behind B's rows.
    let (mine, d) = trace_receipt::authored_here_with(&producer, None, 2, 1_000)
        .await
        .expect("read");
    assert_eq!(mine.len(), 1, "{mine:?}");
    assert_eq!(mine[0].agent_id_hash, AGENT_A.hash);
    assert_eq!(mine[0].authored, 4);
    assert_eq!(d.rows_scanned, 10);
    assert!(!d.truncated);

    // Capped before A's rows: nothing found — and the scan SAYS it stopped,
    // which is the difference between "nothing authored" and "did not look".
    let (mine, d) = trace_receipt::authored_here_with(&producer, None, 2, 4)
        .await
        .expect("read");
    assert!(mine.is_empty(), "{mine:?}");
    assert!(d.truncated, "{d:?}");
    assert_eq!(d.rows_scanned, 4);
}

// ─── the producer's receipt ─────────────────────────────────────────────────

#[tokio::test]
async fn the_producer_verifies_the_receipt_and_asks_whether_its_newest_trace_is_held() {
    let canonical = node(0xA1, "node-canonical").await;
    admit(&canonical.engine, &AGENT_A, 0..5).await;
    let (base, _h) = serve(trace_receipt::router(Arc::clone(&canonical.engine))).await;

    let producer = node(0xB1, "node-producer").await;
    trust(&producer.engine, &canonical).await;
    admit(&producer.engine, &AGENT_A, 0..7).await;

    let view = trace_receipt::delivery_receipt(
        &producer.engine,
        roster(vec![read(base.clone(), &canonical.key_id)]),
        Some(AGENT_A.hash),
    )
    .await;

    let agents = view["agents"].as_array().expect("agents");
    assert_eq!(agents.len(), 1, "{view}");
    assert_eq!(agents[0]["authored"], 7);
    assert_eq!(agents[0]["newest_authored"]["trace_id"], "trace-rcpt-0006");

    let c = &view["canonicals"][0];
    assert_eq!(c["reachable"], true, "{view}");
    let a = &c["agents"][0];
    assert_eq!(a["verification"], "verified", "{view}");
    assert_eq!(a["held"], 5, "the canonical's own count: {view}");
    assert_eq!(a["count_gap"], 2, "context, not verdict: {view}");
    assert_eq!(a["shipped_any"], true);
    assert_eq!(
        a["newest_authored_held"], false,
        "trace-rcpt-0006 was never admitted there — THE answer: {view}"
    );
    assert_eq!(a["newest_held"]["trace_id"], "trace-rcpt-0004");
    assert_eq!(a["newest_matches"], false);

    let v = &view["verdict"];
    assert_eq!(v["canonicals_answered"], 1);
    assert_eq!(v["canonicals_unverified"], 0);
    assert_eq!(v["canonicals_unreachable"], 0);
    assert_eq!(
        v["newest_authored_held_by_every_answering_canonical"],
        false
    );
    assert!(
        view["hint"]
            .as_str()
            .unwrap_or_default()
            .contains("does NOT hold the newest trace"),
        "{view}"
    );

    // Now the canonical catches up: the two it was missing land. The counts
    // would have read "delivered" as soon as they matched; identity says it
    // now, because THE trace is there.
    admit(&canonical.engine, &AGENT_A, 5..7).await;
    let view = trace_receipt::delivery_receipt(
        &producer.engine,
        roster(vec![read(base, &canonical.key_id)]),
        Some(AGENT_A.hash),
    )
    .await;
    let a = &view["canonicals"][0]["agents"][0];
    assert_eq!(a["newest_authored_held"], true, "{view}");
    assert_eq!(a["newest_matches"], true, "{view}");
    assert_eq!(
        view["verdict"]["newest_authored_held_by_every_answering_canonical"], true,
        "{view}"
    );
    assert!(
        view["hint"]
            .as_str()
            .unwrap_or_default()
            .contains("the plane delivered"),
        "{view}"
    );
}

#[tokio::test]
async fn counts_alone_never_say_delivered() {
    // The canonical holds MORE of this agent's traces than the producer has
    // (history from earlier runs; the producer pruned). Counts say "held ≥
    // authored"; the newest authored trace is still not there.
    let canonical = node(0xA1, "node-canonical").await;
    admit(&canonical.engine, &AGENT_A, 0..5).await;
    let (base, _h) = serve(trace_receipt::router(Arc::clone(&canonical.engine))).await;

    let producer = node(0xB1, "node-producer").await;
    trust(&producer.engine, &canonical).await;
    admit(&producer.engine, &AGENT_A, [7, 8]).await;

    let view = trace_receipt::delivery_receipt(
        &producer.engine,
        roster(vec![read(base, &canonical.key_id)]),
        Some(AGENT_A.hash),
    )
    .await;
    let a = &view["canonicals"][0]["agents"][0];
    assert_eq!(a["authored"], 2);
    assert_eq!(a["held"], 5);
    assert_eq!(a["count_gap"], 0, "counts say nothing is missing: {view}");
    assert_eq!(
        a["newest_authored_held"], false,
        "identity says trace-rcpt-0008 never arrived: {view}"
    );
    assert_eq!(
        view["verdict"]["newest_authored_held_by_every_answering_canonical"], false,
        "{view}"
    );
}

#[tokio::test]
async fn a_forged_receipt_reads_failed_and_an_unsigned_one_unavailable_both_with_held_null() {
    let canonical = node(0xA1, "node-canonical").await;
    admit(&canonical.engine, &AGENT_A, 0..5).await;
    let (real, _h) = serve(trace_receipt::router(Arc::clone(&canonical.engine))).await;

    let producer = node(0xB1, "node-producer").await;
    trust(&producer.engine, &canonical).await;
    admit(&producer.engine, &AGENT_A, 0..2).await;

    // Take a real, signed receipt and change the number.
    let mut forged: serde_json::Value =
        get_receipt(&real, AGENT_A.hash, Some("trace-rcpt-0001"), "x")
            .await
            .json()
            .await
            .expect("json");
    assert_eq!(forged["data"]["traces"], 5);
    forged["data"]["traces"] = serde_json::json!(500);
    let (forged_url, _h2) = serve(stub(forged.clone())).await;

    // And one that simply carries no signature at all.
    let mut unsigned = forged.clone();
    unsigned["data"]["traces"] = serde_json::json!(5);
    unsigned.as_object_mut().unwrap().remove("signature");
    let (unsigned_url, _h3) = serve(stub(unsigned)).await;

    let view = trace_receipt::delivery_receipt(
        &producer.engine,
        roster(vec![
            read(forged_url, &canonical.key_id),
            read(unsigned_url, &canonical.key_id),
        ]),
        Some(AGENT_A.hash),
    )
    .await;

    let f = &view["canonicals"][0];
    assert_eq!(f["reachable"], true, "{view}");
    assert_eq!(f["agents"][0]["verification"], "failed", "{view}");
    assert!(
        f["agents"][0]["held"].is_null(),
        "a forged count is not a count: {view}"
    );
    assert!(
        f["error"]
            .as_str()
            .is_some_and(|e| e.contains("does not verify")),
        "{view}"
    );

    let u = &view["canonicals"][1];
    assert_eq!(u["reachable"], true, "{view}");
    assert_eq!(u["agents"][0]["verification"], "unavailable", "{view}");
    assert!(u["agents"][0]["held"].is_null(), "{view}");
    assert!(
        u["error"]
            .as_str()
            .is_some_and(|e| e.contains("no signature")),
        "{view}"
    );

    let v = &view["verdict"];
    assert_eq!(
        v["canonicals_answered"], 0,
        "neither said anything usable: {view}"
    );
    assert_eq!(v["canonicals_unverified"], 2, "{view}");
    assert!(
        v["newest_authored_held_by_every_answering_canonical"].is_null(),
        "{view}"
    );
    assert!(
        view["hint"]
            .as_str()
            .unwrap_or_default()
            .contains("could verify"),
        "{view}"
    );
}

#[tokio::test]
async fn a_valid_receipt_replayed_for_a_different_ask_is_refused() {
    let canonical = node(0xA1, "node-canonical").await;
    admit(&canonical.engine, &AGENT_A, 0..5).await;
    let (real, _h) = serve(trace_receipt::router(Arc::clone(&canonical.engine))).await;

    let producer = node(0xB1, "node-producer").await;
    trust(&producer.engine, &canonical).await;
    admit(&producer.engine, &AGENT_A, 0..3).await; // newest: trace-rcpt-0002

    // A perfectly valid signed receipt — for trace-rcpt-0001 under nonce
    // "old", saying it IS held. An on-path party serves exactly that when the
    // producer asks about trace-rcpt-0002.
    let replay: serde_json::Value =
        get_receipt(&real, AGENT_A.hash, Some("trace-rcpt-0001"), "old")
            .await
            .json()
            .await
            .expect("json");
    assert_eq!(replay["data"]["holds_trace"], true);
    let (replay_url, _h2) = serve(stub(replay)).await;

    let view = trace_receipt::delivery_receipt(
        &producer.engine,
        roster(vec![read(replay_url, &canonical.key_id)]),
        Some(AGENT_A.hash),
    )
    .await;
    let c = &view["canonicals"][0];
    assert_eq!(c["reachable"], true, "{view}");
    assert_eq!(c["agents"][0]["verification"], "failed", "{view}");
    assert!(
        c["agents"][0]["newest_authored_held"].is_null(),
        "the replayed `holds_trace: true` must NOT become 'delivered': {view}"
    );
    assert!(
        c["error"].as_str().is_some_and(|e| e.contains("replayed")),
        "{view}"
    );
    assert!(
        view["verdict"]["newest_authored_held_by_every_answering_canonical"].is_null(),
        "{view}"
    );
}

#[tokio::test]
async fn a_receipt_signed_by_someone_other_than_the_named_canonical_is_not_its_receipt() {
    // A registered, honest node — that is not the canonical the producer
    // asked for — serves receipts. Its signature verifies; it is still the
    // wrong signer.
    let impostor = node(0xC1, "node-impostor").await;
    admit(&impostor.engine, &AGENT_A, 0..5).await;
    let (url, _h) = serve(trace_receipt::router(Arc::clone(&impostor.engine))).await;

    let producer = node(0xB1, "node-producer").await;
    trust(&producer.engine, &impostor).await;
    admit(&producer.engine, &AGENT_A, 0..2).await;

    let view = trace_receipt::delivery_receipt(
        &producer.engine,
        roster(vec![read(url, "ciris-canonical-1-d7bdeu223k")]),
        Some(AGENT_A.hash),
    )
    .await;
    let c = &view["canonicals"][0];
    assert_eq!(c["agents"][0]["verification"], "failed", "{view}");
    assert!(c["agents"][0]["held"].is_null(), "{view}");
    assert!(
        c["error"]
            .as_str()
            .is_some_and(|e| e.contains("not its receipt")),
        "{view}"
    );
}

#[tokio::test]
async fn a_body_over_the_receipt_limit_is_refused_before_it_is_buffered() {
    let producer = node(0xB1, "node-producer").await;
    admit(&producer.engine, &AGENT_A, 0..1).await;
    let pad = "x".repeat(trace_receipt::MAX_RECEIPT_BYTES + 1024);
    let (big_url, _h) = serve(stub(serde_json::json!({ "data": {}, "pad": pad }))).await;

    let view = trace_receipt::delivery_receipt(
        &producer.engine,
        roster(vec![read(big_url, "whoever")]),
        Some(AGENT_A.hash),
    )
    .await;
    let c = &view["canonicals"][0];
    assert_eq!(c["agents"][0]["verification"], "unavailable", "{view}");
    assert!(c["agents"][0]["held"].is_null(), "{view}");
    assert!(
        c["error"]
            .as_str()
            .is_some_and(|e| e.contains("receipt limit")),
        "{view}"
    );
}

#[tokio::test]
async fn an_unreachable_or_unverifiable_canonical_reads_unknown_and_does_not_poison_the_verdict() {
    let canonical = node(0xA1, "node-canonical").await;
    admit(&canonical.engine, &AGENT_A, 0..3).await;
    let (live, _h) = serve(trace_receipt::router(Arc::clone(&canonical.engine))).await;

    let producer = node(0xB1, "node-producer").await;
    trust(&producer.engine, &canonical).await;
    admit(&producer.engine, &AGENT_A, 0..3).await;

    // A port nothing listens on…
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = l.local_addr().expect("addr");
        drop(l);
        format!("http://{addr}")
    };
    // …and one that answers, unsigned.
    let (unsigned_url, _h2) = serve(stub(serde_json::json!({ "data": {
        "agent_id_hash": AGENT_A.hash, "traces": 3, "newest": null,
        "read_at": chrono::Utc::now(),
    }})))
    .await;

    let view = trace_receipt::delivery_receipt(
        &producer.engine,
        roster(vec![
            CanonicalRead {
                key_id: "ciris-canonical-dead".into(),
                url: dead.clone(),
                url_source: UrlSource::DerivedFromIpHint,
            },
            read(unsigned_url, &canonical.key_id),
            read(live, &canonical.key_id),
        ]),
        Some(AGENT_A.hash),
    )
    .await;

    let d = &view["canonicals"][0];
    assert_eq!(d["reachable"], false, "{view}");
    assert_eq!(d["url"], dead, "the URL it tried is in the answer: {view}");
    assert_eq!(d["url_source"], "derived_from_ip_hint");
    assert!(
        d["error"].as_str().is_some_and(|e| e.contains(&dead)),
        "{view}"
    );
    assert!(
        d["agents"][0]["held"].is_null(),
        "unknown is not zero: {view}"
    );
    assert!(d["agents"][0]["newest_authored_held"].is_null(), "{view}");

    let u = &view["canonicals"][1];
    assert_eq!(u["reachable"], true, "{view}");
    assert_eq!(u["agents"][0]["verification"], "unavailable", "{view}");

    // The live one answered and holds the newest trace: delivered THERE, and
    // the other two are counted apart rather than folded into "not delivered".
    let l = &view["canonicals"][2];
    assert_eq!(l["agents"][0]["newest_authored_held"], true, "{view}");
    let v = &view["verdict"];
    assert_eq!(v["canonicals_answered"], 1);
    assert_eq!(v["canonicals_unverified"], 1);
    assert_eq!(v["canonicals_unreachable"], 1);
    assert_eq!(
        v["newest_authored_held_by_every_answering_canonical"], true,
        "{view}"
    );
    let hint = view["hint"].as_str().unwrap_or_default();
    assert!(
        hint.contains("the plane delivered")
            && hint.contains("1 canonical(s) did not answer")
            && hint.contains("1 canonical(s) answered but could not be verified"),
        "{view}"
    );
}

#[tokio::test]
async fn a_roster_that_could_not_be_read_is_a_store_fault_not_a_missing_canonical() {
    let producer = node(0xB1, "node-producer").await;
    admit(&producer.engine, &AGENT_A, 0..1).await;
    let view = trace_receipt::delivery_receipt(
        &producer.engine,
        Err("read the baked canonical records: disk on fire".into()),
        Some(AGENT_A.hash),
    )
    .await;
    assert_eq!(
        view["canonical_roster"]["error"], "read the baked canonical records: disk on fire",
        "{view}"
    );
    assert!(
        view["hint"]
            .as_str()
            .unwrap_or_default()
            .contains("STORE fault"),
        "{view}"
    );
    assert!(
        view["canonicals"].as_array().is_some_and(Vec::is_empty),
        "{view}"
    );

    // And a config whose every entry was refused says THAT, not "no canonical".
    let view = trace_receipt::delivery_receipt(
        &producer.engine,
        Ok(CanonicalRoster {
            reads: Vec::new(),
            refused: vec!["`http://x:4243`: no key id".into()],
        }),
        Some(AGENT_A.hash),
    )
    .await;
    assert_eq!(
        view["canonical_roster"]["refused"][0],
        "`http://x:4243`: no key id"
    );
    assert!(
        view["hint"]
            .as_str()
            .unwrap_or_default()
            .contains("was refused"),
        "{view}"
    );
}

#[tokio::test]
async fn a_node_with_no_canonical_and_no_traces_says_so_in_that_order() {
    let producer = node(0xB1, "node-producer").await;
    let view = trace_receipt::delivery_receipt(&producer.engine, roster(Vec::new()), None).await;
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
    // and nothing else, so the read URL is derived — and says so — and every
    // baked canonical is named by key.
    let producer = node(0xB1, "node-producer").await;
    let roster = trace_receipt::canonical_reads(&producer.engine)
        .await
        .expect("the directory reads");
    assert!(roster.refused.is_empty());
    for r in &roster.reads {
        assert_eq!(r.url_source, UrlSource::DerivedFromIpHint, "{r:?}");
        assert!(
            r.url.starts_with("http://")
                && r.url
                    .ends_with(&format!(":{}", trace_receipt::READ_API_PORT)),
            "derived from the ip hint with the read-API port: {r:?}"
        );
        assert!(!r.key_id.is_empty(), "a baked canonical is named: {r:?}");
    }
}
