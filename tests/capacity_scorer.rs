//! End-to-end proof of the capacity score→emit pipeline (CIRISServer
//! federation Round 1, deliverable 3).
//!
//! The spine: ingest a batch of synthetic-but-realistic traces for one agent
//! into a node's corpus → register Node A's own steward key + the agent key
//! (the `put_attestation` FK precondition) → run a single deterministic scorer
//! pass → assert a `capacity:sustained_coherence:v1` `scores` attestation now
//! exists in Node A's corpus, with:
//!   - attesting = Node A's key,
//!   - attested  = the agent's key (anti-Goodhart: attesting != attested),
//!   - federation tier,
//!   - a plausible, N_eff-derived score in [0, 1].
//!
//! The traces carry varied DMA / IDMA / CONSCIENCE component payloads so the
//! per-trace feature matrix has real (non-degenerate) covariance structure —
//! the N_eff derivation is exercised on real ingested feature vectors read back
//! through persist's `TraceSummary` surface, not on synthetic in-memory vectors.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, attestation_tier, identity_type};
use ciris_persist::federation::{FederationDirectory as _, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::schema::{
    CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion, TraceComponent, TraceLevel,
};
use ciris_persist::scrub::NullScrubber;
use ciris_persist::verify::canonical::Canonicalizer;
use ciris_persist::verify::{ed25519::canonical_payload_value, PythonJsonDumpsCanonicalizer};

use ciris_server::scorer::{self, ScorerConfig};

const NODE_KEY_ID: &str = "node-a";
const AGENT_KEY_ID: &str = "agent-alpha";
/// The agent's AV-9 identity hash on its traces — the subject the scorer
/// attests about (and the key_id we register so the FK resolves).
const AGENT_ID_HASH: &str = "agent-alpha";

/// Stand up Node A: its own in-memory substrate, keyed by a HYBRID node-identity
/// signer (Ed25519 + ML-DSA-65 software seed) — the scorer hybrid-signs, so the
/// node's `sign_hybrid` must have a PQC half (production wires this via the
/// keyring; here we use a deterministic software seed).
async fn node_a() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node-a ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    let engine = Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("Engine::with_signer (sqlite::memory:) must succeed");
    Arc::new(engine)
}

/// Register a peer/agent verifying key into the directory so (a) trace verify
/// resolves it and (b) `put_attestation`'s attested-key FK resolves it. Mirrors
/// `replication.rs::cross_register`.
async fn register_key(engine: &Engine, key_id: &str, ed_pubkey_b64: &str, id_type: &str) {
    let now = chrono::Utc::now();
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: ed_pubkey_b64.to_string(),
        pubkey_ml_dsa_65_base64: None,
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
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .sqlite_backend()
        .expect("sqlite backend present")
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register key in federation directory");
}

/// Build one signed `CompleteTrace` wire batch carrying DMA / IDMA / CONSCIENCE
/// component payloads. The `idx` perturbs the feature values so the per-agent
/// feature matrix has real covariance structure (not a rank-0 constant block).
fn build_trace_batch(
    agent_sk: &SigningKey,
    mldsa: &ciris_crypto::MlDsa65Signer,
    idx: usize,
) -> Vec<u8> {
    let f = idx as f64;
    // Three correlated-but-varied DMA signals + two semi-independent conscience
    // gates → a spectrum with a few effective dimensions.
    let csdma = 0.5 + 0.3 * ((f * 0.7).sin());
    let dsdma = 0.5 + 0.25 * ((f * 0.9).cos());
    let k_eff = 1.0 + (f % 5.0) * 0.4;
    let corr_risk = 0.1 + 0.2 * ((f * 1.3).sin()).abs();
    let conscience_passed = idx % 4 != 0; // mostly pass, periodic fail
    let overridden = idx % 7 == 0;
    let entropy_passed = idx % 3 != 0;
    let coherence_passed = idx % 5 != 0;

    // component_type is an organizational tag; persist's summary extraction keys
    // the feature columns on `event_type` (DMA_RESULTS / IDMA_RESULT /
    // CONSCIENCE_RESULT), so Rationale is fine for the DMA-family components.
    let dma = TraceComponent {
        component_type: ComponentType::Rationale,
        event_type: ReasoningEventType::DmaResults,
        timestamp: "2026-06-14T00:00:00Z".parse().unwrap(),
        data: {
            let mut m = serde_json::Map::new();
            m.insert("csdma_plausibility_score".into(), serde_json::json!(csdma));
            m.insert("dsdma_domain_alignment".into(), serde_json::json!(dsdma));
            m
        },
        agent_id_hash: None,
    };
    let idma = TraceComponent {
        component_type: ComponentType::Rationale,
        event_type: ReasoningEventType::IdmaResult,
        timestamp: "2026-06-14T00:00:01Z".parse().unwrap(),
        data: {
            let mut m = serde_json::Map::new();
            m.insert("idma_k_eff".into(), serde_json::json!(k_eff));
            m.insert("idma_correlation_risk".into(), serde_json::json!(corr_risk));
            m
        },
        agent_id_hash: None,
    };
    let conscience = TraceComponent {
        component_type: ComponentType::Conscience,
        event_type: ReasoningEventType::ConscienceResult,
        timestamp: "2026-06-14T00:00:02Z".parse().unwrap(),
        data: {
            let mut m = serde_json::Map::new();
            m.insert(
                "conscience_passed".into(),
                serde_json::json!(conscience_passed),
            );
            m.insert(
                "action_was_overridden".into(),
                serde_json::json!(overridden),
            );
            m.insert("entropy_passed".into(), serde_json::json!(entropy_passed));
            m.insert(
                "coherence_passed".into(),
                serde_json::json!(coherence_passed),
            );
            m
        },
        agent_id_hash: None,
    };

    let trace_id = format!("trace-cap-{idx:04}");
    let mut trace = CompleteTrace {
        trace_id: trace_id.clone(),
        thought_id: trace_id.clone(),
        task_id: Some("task-cap".into()),
        agent_id_hash: AGENT_ID_HASH.into(),
        started_at: "2026-06-14T00:00:00Z".parse().unwrap(),
        completed_at: "2026-06-14T00:01:00Z".parse().unwrap(),
        trace_level: TraceLevel::Generic,
        trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
        components: vec![dma, idma, conscience],
        deployment_profile: None,
        cohort_scope: "federation".into(),
        cohort_target_id: None,
        signature: String::new(),
        signature_key_id: AGENT_KEY_ID.into(),
        signature_ml_dsa_65: None,
        pubkey_ml_dsa_65: None,
        pqc_key_id: None,
    };

    // Sign FULL HYBRID (VerifyMode::Full rejects classical-only).
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

#[tokio::test]
async fn capacity_scorer_emits_n_eff_derived_attestation_end_to_end() {
    let node = node_a().await;
    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    let agent_pub_b64 = BASE64.encode(agent_sk.verifying_key().to_bytes());
    let mldsa = ciris_crypto::MlDsa65Signer::from_seed(&[0x77u8; 32]).expect("ml-dsa seed");

    // ── Precondition: both the attesting (Node A) and attested (agent) keys
    //    must exist as federation_keys rows for put_attestation's FK. Node A's
    //    own key is registered by compose::register_self_key in production; here
    //    we register both directly. The agent key is also the trace-verify key. ─
    register_key(
        &node,
        NODE_KEY_ID,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "steward",
    )
    .await;
    register_key(&node, AGENT_KEY_ID, &agent_pub_b64, identity_type::AGENT).await;

    // ── Ingest a batch of synthetic-but-realistic traces for the agent ───────
    const N_TRACES: usize = 30;
    let mut inserted = 0usize;
    for i in 0..N_TRACES {
        let bytes = build_trace_batch(&agent_sk, &mldsa, i);
        let summary = node
            .receive_and_persist(&bytes, &NullScrubber)
            .await
            .expect("ingest synthetic trace");
        inserted += summary.trace_events_inserted;
    }
    assert!(
        inserted >= N_TRACES,
        "expected at least {N_TRACES} trace events ingested, got {inserted}"
    );

    // ── Run one deterministic scorer pass (low gate so the 30-trace corpus
    //    clears it; target 8 keeps the band meaningful). ──────────────────────
    let cfg = ScorerConfig {
        cadence: std::time::Duration::from_secs(3600),
        window: 500,
        sample_size_gate: 2,
        target_n_eff: 8.0,
    };
    let emitted = scorer::run_pass(&node, NODE_KEY_ID, &cfg)
        .await
        .expect("scorer pass must succeed");
    assert_eq!(emitted, 1, "exactly one agent should be scored + emitted");

    // ── Assert: a capacity:* attestation now exists, attesting=Node A,
    //    attested=agent, federation tier, plausible N_eff-derived score. ───────
    let attestations = node
        .federation_directory()
        .list_attestations_for(AGENT_KEY_ID)
        .await
        .expect("list attestations for the agent");
    assert_eq!(
        attestations.len(),
        1,
        "exactly one capacity attestation should target the agent"
    );
    let att = &attestations[0];

    assert_eq!(
        att.attesting_key_id, NODE_KEY_ID,
        "attesting must be Node A"
    );
    assert_eq!(
        att.attested_key_id, AGENT_KEY_ID,
        "attested must be the agent"
    );
    assert_ne!(
        att.attesting_key_id, att.attested_key_id,
        "anti-Goodhart: attesting != attested (CEG §7.5)"
    );
    assert_eq!(att.attestation_type, "scores");
    assert_eq!(
        att.tier,
        attestation_tier::FEDERATION,
        "must be federation-tier"
    );
    assert_eq!(att.cohort_scope, "federation");

    // Envelope carries the versioned capacity leaf + the N_eff derivation.
    let env = &att.attestation_envelope;
    assert_eq!(
        env["dimension"], "capacity:sustained_coherence:v1",
        "versioned capacity leaf"
    );
    let n_eff_pr = env["n_eff_pr"].as_f64().expect("n_eff_pr present");
    assert!(
        n_eff_pr > 1.0,
        "varied multi-DMA corpus should have >1 effective dimension, got n_eff_pr={n_eff_pr}"
    );
    let score = att.weight.expect("weight (capacity score) present");
    assert!(
        (0.0..=1.0).contains(&score),
        "capacity score must be in [0,1], got {score}"
    );
    assert!(
        score > 0.0,
        "n_eff above the sample gate should yield a positive capacity, got {score}"
    );
    // The envelope score field mirrors the row weight.
    assert!((env["score"].as_f64().unwrap() - score).abs() < 1e-12);

    // The hybrid signature components are populated (PQC-complete row).
    assert!(!att.scrub_signature_classical.is_empty());
    assert!(att
        .scrub_signature_pqc
        .as_ref()
        .is_some_and(|s| !s.is_empty()));
}
