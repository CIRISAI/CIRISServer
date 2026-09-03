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

#[path = "support/fixture_pqc.rs"]
mod fixture_pqc;

#[path = "support/log_capture.rs"]
mod log_capture;
#[path = "support/revocation.rs"]
mod revocation;

/// **CIRISConstitution#46 (persist v22.0.0) — CONSENT BEFORE SCORING.**
///
/// v22 inverts the RC2 default for `capacity:*`: a federation-tier capacity claim
/// about subject S by attester P is REFUSED unless a live `analyze`-scoped consent
/// from S covers P. Persist's framing: *"were you permitted to compute and publish
/// this about me?"* — CC 3.4.5 previously let any registered key score any third
/// party, which on a deliberately-cheap bootstrap means anyone.
///
/// The claim is the edge `P → S`; the consent is the **REVERSE** edge `S → P`.
/// So the SUBJECT authors this, naming the attester as `attested_key_id`, with the
/// envelope naming scope `analyze`. Resolved by `resolve_scoped_consent`, which
/// reads federation-tier rows only — hence the promote.
///
/// Vocabulary is single-sourced from persist (`paths::DIMENSION`,
/// `STATE_GRANTED_PREFIX`, `ANALYZE_CONSENT_SCOPE`); a hand-mirrored literal
/// compiles and skews the wire.
async fn grant_analyze_consent(engine: &Engine, subject: &str, attester: &str) {
    use ciris_persist::federation::admission::ANALYZE_CONSENT_SCOPE;
    use ciris_persist::federation::consent::consent_dimension;
    use ciris_persist::federation::envelope::paths;
    use ciris_persist::federation::types::{cohort_scope, LocalAttestationInput};

    let envelope = serde_json::json!({
        (paths::DIMENSION): format!("{}:v1", consent_dimension::STATE_GRANTED_PREFIX),
        "scope": ANALYZE_CONSENT_SCOPE,
    });
    let core = ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope)
        .expect("analyze-consent envelope");
    let id = engine
        .federation_directory()
        .attestation_upsert_local(LocalAttestationInput {
            attestation_id: None,
            attesting_key_id: subject.to_string(),
            attested_key_id: Some(attester.to_string()),
            attestation_type: "consent".to_string(),
            weight: None,
            expires_at: None,
            attestation_envelope: core,
            // Empty on purpose: `subject_key_ids` confers revocation authority, and
            // the subject already holds it as producer. Naming the attester would
            // give the scorer a say over the consent that authorizes it.
            subject_key_ids: Vec::new(),
            cohort_scope: cohort_scope::SELF.to_string(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        })
        .await
        .expect("seed analyze consent");
    // `resolve_scoped_consent` reads via `list_attestations_for`, which is
    // federation-tier only — a local row would be invisible and the gate would
    // still refuse.
    engine
        .attestation_promote(&id, cohort_scope::FEDERATION)
        .await
        .expect("promote analyze consent to federation tier");
}

const NODE_KEY_ID: &str = "node-a";
const AGENT_KEY_ID: &str = "agent-alpha";
/// The agent's AV-9 identity hash on its traces — the subject the scorer
/// attests about (and the key_id we register so the FK resolves).
const AGENT_ID_HASH: &str = "agent-alpha";

/// Stand up Node A: its own in-memory substrate, keyed by a HYBRID node-identity
/// signer (Ed25519 + ML-DSA-65 software seed) — the scorer hybrid-signs, so the
/// node's `sign_hybrid` must have a PQC half (production wires this via the
/// keyring; here we use a deterministic software seed). Returns its REAL hybrid
/// public keys (Ed25519 + ML-DSA-65, base64): persist v9.0.0 (CC 5.3.2.4.3.1)
/// verifies the federation-tier hybrid signature at `put_attestation` against the
/// registered key, so the scorer's own emit only admits if NODE_KEY_ID is
/// registered with the SAME pubkeys its signer holds — these are them.
async fn node_a_with_keys() -> (Arc<Engine>, String, String) {
    use ciris_keyring::PqcSigner as _;
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    let ed_pub_b64 = BASE64.encode(signing_key.verifying_key().to_bytes());
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node-a ML-DSA-65 seed"),
    );
    let mldsa_pub_b64 = BASE64.encode(pqc.public_key().await.expect("node-a ML-DSA-65 pubkey"));
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    let engine = Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("Engine::with_signer (sqlite::memory:) must succeed");
    (Arc::new(engine), ed_pub_b64, mldsa_pub_b64)
}

/// Register a peer/agent verifying key into the directory so (a) trace verify
/// resolves it and (b) `put_attestation`'s attested-key FK resolves it. Mirrors
/// `replication.rs::cross_register`.
async fn register_key(engine: &Engine, key_id: &str, ed_pubkey_b64: &str, id_type: &str) {
    register_key_hybrid(engine, key_id, ed_pubkey_b64, None, id_type).await;
}

/// Register a key, optionally with its ML-DSA-65 pubkey. The federation-tier
/// ingest gate (persist v9.0.0) resolves `scrub_key_id`'s pubkeys here to verify
/// an emitted attestation's hybrid signature, so an attesting node MUST be
/// registered with its real ML-DSA-65 half (`Some(...)`) for its own emits to
/// admit. (The attested agent key is FK-only here — never the attester — so it
/// may register without a PQC half.)
async fn register_key_hybrid(
    engine: &Engine,
    key_id: &str,
    ed_pubkey_b64: &str,
    ml_dsa_65_pubkey_b64: Option<&str>,
    id_type: &str,
) {
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
    trace.pqc_key_id = Some(fixture_pqc::KEY_ID.into());

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
    let (node, node_ed_pub_b64, node_mldsa_pub_b64) = node_a_with_keys().await;
    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    let agent_pub_b64 = BASE64.encode(agent_sk.verifying_key().to_bytes());
    let mldsa = fixture_pqc::signer();

    // ── Precondition: both the attesting (Node A) and attested (agent) keys
    //    must exist as federation_keys rows for put_attestation's FK. Node A's
    //    own key is registered by compose::register_self_key in production; here
    //    we register both directly. The agent key is also the trace-verify key.
    //    persist v9.0.0 (CC 5.3.2.4.3.1) verifies the scorer's emitted
    //    federation-tier hybrid signature against NODE_KEY_ID's registered
    //    pubkeys, so Node A must register its REAL Ed25519 + ML-DSA-65 halves
    //    (its `node` identity_type — CC 1.13.5), not a placeholder. ────────────
    // v0.5.14 (#45 collapse): the scorer now emits via Engine::emit_attestation_self,
    // which attests under the node's #247 DERIVED federation key_id
    // (local_derived_key_id() = derive_key_id(alias, pubkey)) — exactly what
    // compose::register_self_key registers in prod. Register under the derived id
    // (not the bare alias) so the emit FK + signature-verify resolve.
    let node_key_id = node
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id");
    register_key_hybrid(
        &node,
        &node_key_id,
        &node_ed_pub_b64,
        Some(&node_mldsa_pub_b64),
        identity_type::NODE,
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
    // CC#46: without the subject's `analyze` consent the scorer authors NOTHING
    // (and the refusal is a WARN naming the missing scope, not a panic) — so this
    // grant is part of the fixture's contract now, not incidental setup.
    // The attester is the node's #247 DERIVED federation key_id — what
    // `emit_attestation_self` stamps and what is registered above — NOT the bare
    // `NODE_KEY_ID` alias. Consenting to the alias would leave the real attester
    // unconsented and the gate would still refuse (the 0.5.138 derived-vs-alias
    // identity-fork class, in miniature).
    grant_analyze_consent(&node, AGENT_KEY_ID, &node_key_id).await;

    let emitted = scorer::run_pass(&node, &node_key_id, &cfg)
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
        att.attesting_key_id, node_key_id,
        "attesting must be Node A (its derived federation key_id)"
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

// ─── `revoked_after` on the capacity plane (CIRISServer#355) ─────────────────

/// **A revoked key's post-bound `capacity:*` row must not suppress honest
/// scoring** (CIRISServer#355 / CIRISPersist#570 ask 4).
///
/// Everything downstream of `scorer::live_capacity_rows` is a SUPPRESSION
/// decision: if a live row already carries this score in this coalescing
/// bucket, the pass authors nothing, and `unchanged_for` widens the bucket the
/// longer the score has apparently held. So a single row from a compromised key
/// can silence honest scoring of a subject for up to a day — with no error, no
/// warning, and a perfectly healthy-looking "unchanged".
///
/// The gate drives the real pass three times:
///
///   1. cold corpus → emits (the baseline);
///   2. immediately again → emits NOTHING, because the row it just wrote stands
///      (this is the suppression the attack borrows);
///   3. after a revocation of the authoring key bounded BEFORE that row's
///      signed instant → emits again, because the standing row stopped
///      standing.
///
/// Step 2 is load-bearing: without it, step 3 proves nothing — a pass that
/// always emits would satisfy step 3 for the wrong reason.
#[tokio::test]
async fn a_post_bound_capacity_row_stops_suppressing_the_scorer() {
    use ciris_keyring::PqcSigner as _;

    let (node, node_ed_pub_b64, node_mldsa_pub_b64) = node_a_with_keys().await;
    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    let agent_pub_b64 = BASE64.encode(agent_sk.verifying_key().to_bytes());
    let mldsa = fixture_pqc::signer();

    let node_key_id = node
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id");
    register_key_hybrid(
        &node,
        &node_key_id,
        &node_ed_pub_b64,
        Some(&node_mldsa_pub_b64),
        identity_type::NODE,
    )
    .await;
    register_key(&node, AGENT_KEY_ID, &agent_pub_b64, identity_type::AGENT).await;

    for i in 0..30usize {
        node.receive_and_persist(&build_trace_batch(&agent_sk, &mldsa, i), &NullScrubber)
            .await
            .expect("ingest synthetic trace");
    }
    grant_analyze_consent(&node, AGENT_KEY_ID, &node_key_id).await;

    let cfg = ScorerConfig {
        cadence: std::time::Duration::from_secs(3600),
        window: 500,
        sample_size_gate: 2,
        target_n_eff: 8.0,
    };

    // (1) baseline — the pass authors the subject's capacity row.
    assert_eq!(
        scorer::run_pass(&node, &node_key_id, &cfg)
            .await
            .expect("first pass"),
        1,
        "cold corpus: the scorer must author one capacity row"
    );

    // The signed instant of the row that now stands. NOT `asserted_at` (the
    // unsigned write column) — the scorer floors the ENVELOPE instant to an
    // hour bucket, so the two differ by up to an hour and only one of them is
    // what a bound is compared against.
    let standing = node
        .federation_directory()
        .list_attestations_for(AGENT_KEY_ID)
        .await
        .expect("read the standing capacity row")
        .into_iter()
        .find(|a| a.attestation_type == "scores")
        .expect("one capacity row");
    let signed_at: chrono::DateTime<chrono::Utc> = standing.attestation_envelope["asserted_at"]
        .as_str()
        .expect("signed asserted_at")
        .parse()
        .expect("rfc3339");

    // (2) the suppression is real — nothing new to say, so nothing is said.
    assert_eq!(
        scorer::run_pass(&node, &node_key_id, &cfg)
            .await
            .expect("second pass"),
        0,
        "the score is unchanged inside the bucket, so the standing row suppresses re-emission \
         — this is the behaviour a forged row borrows"
    );

    // (3) revoke the authoring key from an instant BEFORE that row was signed.
    let authority = {
        let signing_key = SigningKey::from_bytes(&[0xD1; 32]);
        let pqc = Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&[0xD2; 32], "revocation-authority-pqc")
                .expect("authority ML-DSA-65 seed"),
        );
        let ed_pub = BASE64.encode(signing_key.verifying_key().to_bytes());
        let mldsa_pub = BASE64.encode(pqc.public_key().await.expect("authority pubkey"));
        register_key_hybrid(
            &node,
            "revocation-authority",
            &ed_pub,
            Some(&mldsa_pub),
            identity_type::STEWARD,
        )
        .await;
        LocalSigner::from_parts(
            signing_key,
            "revocation-authority".to_string(),
            Some(pqc),
            Some("revocation-authority-pqc".to_string()),
        )
    };
    revocation::revoke(
        &node,
        &authority,
        &node_key_id,
        chrono::Utc::now(),
        Some(signed_at - chrono::Duration::seconds(1)),
    )
    .await;

    // (4) the standing row no longer stands, so the honest measurement is made
    // and published again.
    assert_eq!(
        scorer::run_pass(&node, &node_key_id, &cfg)
            .await
            .expect("third pass"),
        1,
        "a capacity row whose author's statements are revoked from an earlier instant must \
         not count as a standing assertion — otherwise one forged row silences the scorer"
    );
}

// ── CIRISServer#351 — "the subject declined" is not "we could not ask" ───────
//
// CC 3.4.5 ratifies consent-before-scoring and scopes it to `capacity:*` alone:
// the artifact-integrity and adversarial-detector families stay ungated ("a
// forger never consents to verification"; an adversary must not be able to opt
// out of `rollback_detected`). That ruling makes this scorer's `analyze`-consent
// check the ONE place in the server where a subject's own answer decides whether
// a row about them may exist — so an instrument that cannot tell that answer
// from its own failure to read it is a hole in the only gate the ruling kept.

/// Stand up Node A on a **file-backed** sqlite DB, so a second connection can
/// reach the same tables. `sqlite::memory:` is private to the engine's own
/// connection — the same reason `tests/audit_chain.rs` uses a file DSN.
///
/// Otherwise identical to [`node_a_with_keys`]: the scorer hybrid-signs, so the
/// node signer needs a real ML-DSA-65 half, and the returned pubkeys are the
/// ones that must be registered for its own emits to admit.
async fn node_a_on_disk(db_path: &str) -> (Arc<Engine>, String, String) {
    use ciris_keyring::PqcSigner as _;
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    let ed_pub_b64 = BASE64.encode(signing_key.verifying_key().to_bytes());
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node-a ML-DSA-65 seed"),
    );
    let mldsa_pub_b64 = BASE64.encode(pqc.public_key().await.expect("node-a ML-DSA-65 pubkey"));
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    // DSN: persist strips `sqlite:///` INCLUDING the leading slash, so an
    // absolute path is glued onto the scheme (→ `sqlite:////abs/path`).
    let engine = Engine::with_signer(signer, &format!("sqlite:///{db_path}"))
        .await
        .expect("Engine::with_signer (file-backed sqlite)");
    (Arc::new(engine), ed_pub_b64, mldsa_pub_b64)
}

/// Rename `federation_attestations` on a SECOND connection to the engine's own
/// DB file, so persist's `resolve_scoped_consent` — which reads that table
/// through `list_attestations_for` — returns `Err` instead of a stance.
///
/// This is the only honest way to produce the condition. The fold is persist's
/// canonical one and the server deliberately does not re-implement it (a second
/// implementation of a rule is a second answer that can disagree), so the error
/// has to come from the real backend rather than from a stubbed trait. Renaming
/// rather than dropping keeps the corpus intact, which is what lets the same
/// test put it back and prove the pass goes quiet again.
fn set_consent_fold_readable(db_path: &std::path::Path, readable: bool) {
    let conn = rusqlite::Connection::open(db_path).expect("open fault-injection connection");
    conn.busy_timeout(std::time::Duration::from_secs(30))
        .expect("busy_timeout");
    let sql = if readable {
        "ALTER TABLE federation_attestations_hidden RENAME TO federation_attestations"
    } else {
        "ALTER TABLE federation_attestations RENAME TO federation_attestations_hidden"
    };
    conn.execute_batch(sql)
        .expect("rename federation_attestations");
}

/// **An unreadable consent fold must not report itself as the subject's choice.**
///
/// The three zeroes this pass has to keep apart:
///
/// | fact | rows authored | what an operator must read |
/// |---|---|---|
/// | the subject granted `analyze` | one | routine |
/// | the subject declined | none | routine, permanent, **never an alarm** |
/// | the subject's answer is unreadable | none | **a fault** |
///
/// Before CIRISServer#351 the third collapsed into the second:
/// `resolve_scoped_consent` returns `Result<ConsentState, _>` and the gate asked
/// `!matches!(stance, Ok(Granted))`, so every backend error became "declined" —
/// and because `not_consented_agents > 0` is one of the two triggers for the
/// INFO *"steady state, not a fault"* pass line, a corpus-wide failure of the
/// consent read printed, once a minute, that every agent had declined and all
/// was well.
///
/// Asserted on the LOG, not on a return value, because both readings return
/// `Ok(0)`: the difference between them exists only in what the pass said.
#[tokio::test]
async fn an_unreadable_consent_fold_is_not_a_decline() {
    let dir = std::env::temp_dir().join(format!("ciris-351-consent-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let db_path = dir.join("node-a.db");
    let (node, node_ed_pub_b64, node_mldsa_pub_b64) =
        node_a_on_disk(&db_path.to_string_lossy()).await;

    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    let agent_pub_b64 = BASE64.encode(agent_sk.verifying_key().to_bytes());
    let mldsa = fixture_pqc::signer();
    let node_key_id = node
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id");
    register_key_hybrid(
        &node,
        &node_key_id,
        &node_ed_pub_b64,
        Some(&node_mldsa_pub_b64),
        identity_type::NODE,
    )
    .await;
    register_key(&node, AGENT_KEY_ID, &agent_pub_b64, identity_type::AGENT).await;
    for i in 0..30usize {
        node.receive_and_persist(&build_trace_batch(&agent_sk, &mldsa, i), &NullScrubber)
            .await
            .expect("ingest synthetic trace");
    }
    grant_analyze_consent(&node, AGENT_KEY_ID, &node_key_id).await;

    let cfg = ScorerConfig {
        cadence: std::time::Duration::from_secs(3600),
        window: 500,
        sample_size_gate: 2,
        target_n_eff: 8.0,
    };

    // (1) GREEN — the subject consented, the fold is readable, a row is
    //     authored, and the pass says nothing alarming.
    let (emitted, log) = log_capture::capture(scorer::run_pass(&node, &node_key_id, &cfg)).await;
    assert_eq!(
        emitted.expect("consented pass"),
        1,
        "a consented subject with a full trace window must be scored"
    );
    assert!(
        log.alarms().is_empty(),
        "the consented path must not alarm:\n{}",
        log.render_or_explain()
    );

    // (2) BREAK the gate's only input. Nothing about the subject's answer has
    //     changed — the grant is still in the corpus, untouched.
    set_consent_fold_readable(&db_path, false);

    let (emitted, log) = log_capture::capture(scorer::run_pass(&node, &node_key_id, &cfg)).await;
    assert_eq!(
        emitted.expect("the pass itself must survive an unreadable fold"),
        0,
        "fail-closed: an unreadable consent answer authors nothing"
    );

    // The load-bearing assertions. `Ok(0)` is also what a corpus of declining
    // subjects returns, so the only place the difference can live is the log.
    let alarms = log.alarms();
    assert!(
        !alarms.is_empty(),
        "an unreadable CC#46 consent fold was reported with NO alarm at all — the gate went \
         blind and the pass read as routine.\n{}",
        log.render_or_explain()
    );
    assert!(
        alarms
            .iter()
            .any(|e| e.message.contains("consent fold") && e.message.contains("FAILED TO READ")),
        "no alarm names the CONSENT FOLD as what failed. The reader has to be sent to the \
         consent plane, not the trace plane — the traces arrived and were read fine.\n{}",
        log.render_or_explain()
    );
    assert!(
        log.events()
            .iter()
            .all(|e| !e.message.contains("steady state, not a fault")),
        "the pass reported a blind consent gate as a healthy steady state — the exact \
         collapse CIRISServer#351 is about.\n{}",
        log.render_or_explain()
    );
    assert!(
        log.events()
            .iter()
            .any(|e| e.message.contains("NOT a decline")),
        "the per-agent line must say the subject did not decline: \"no consent\" and \"no \
         answer\" are opposite facts about the subject.\n{}",
        log.render_or_explain()
    );

    // (3) RESTORE — same corpus, same subject, same grant. The fold is readable
    //     again, the score already stands, and the pass goes quiet. Without this
    //     leg the test would pass equally well against a scorer that alarms
    //     unconditionally.
    set_consent_fold_readable(&db_path, true);

    let (emitted, log) = log_capture::capture(scorer::run_pass(&node, &node_key_id, &cfg)).await;
    assert_eq!(
        emitted.expect("restored pass"),
        0,
        "the score is unchanged inside its coalescing bucket, so nothing new is authored"
    );
    assert!(
        log.alarms().is_empty(),
        "with the fold readable again the pass must be quiet — an alarm that never clears is \
         the same instrument failure pointed the other way:\n{}",
        log.render_or_explain()
    );
    assert!(
        log.events()
            .iter()
            .any(|e| e.message.contains("steady state, not a fault")),
        "the restored pass must be AUDIBLE about being healthy, not merely silent — a silent \
         pass and a dead loop look identical from outside (CIRISServer#315).\n{}",
        log.render_or_explain()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ── CIRISServer#374 — "nothing stands" is not "we could not read what stands" ─
//
// The same defect class as #351 above, one plane over and one function down.
// `scorer::live_capacity_rows` swallowed every backend failure into an empty
// `Vec`, so a failed capacity-history read arrived at both of its callers as the
// affirmative answer "no rows stand". Both callers turn that into a WRITE
// decision:
//
//   - `standing_assertion` re-authors a row it may already have written;
//   - `unchanged_for` returns a zero-length run, so `coalesce_bucket` falls back
//     to the HOURLY base instead of the attenuated bucket — and `asserted_at` is
//     inside the signed envelope, so the fallback instant gives a different
//     content hash and a genuinely new permanent row.
//
// That is the growth coalescing exists to stop (production capacity rows: ~900 a
// day → 21), reappearing silently whenever a read fails.

/// How many `scores` rows the corpus holds about the agent.
///
/// The behavioural half of this gate. A fail-open scorer and a fail-closed one
/// both return `Ok(0)` for the pass and both look plausible in a log; the corpus
/// is where they differ, and it is the thing the swallow actually damaged.
async fn capacity_rows(engine: &Engine) -> usize {
    engine
        .federation_directory()
        .list_attestations_for(AGENT_KEY_ID)
        .await
        .expect("read the agent's attestations")
        .into_iter()
        .filter(|a| a.attestation_type == "scores")
        .count()
}

/// Rename `federation_revocations` on a SECOND connection to the engine's own DB
/// file, so `HeldRevocations::for_keys` — the `revocations_for` leg inside
/// `live_capacity_rows` — returns `Err`.
///
/// # Why this table and not `federation_attestations`
///
/// It is the one fault that isolates the leg under test. `resolve_scoped_consent`
/// and `list_attestations` both read `federation_attestations`, so hiding that
/// table breaks the CC#46 gate first and the pass reports `ConsentUnreadable` —
/// the #351 outcome, correctly, since that gate is asked first. Hiding
/// `federation_revocations` leaves the consent fold and the attestation page
/// perfectly readable and fails ONLY the revocation read inside
/// `live_capacity_rows`, which is precisely the swallow this test is about.
///
/// Renaming rather than dropping keeps the rows, which is what lets the same
/// test put the table back and prove the pass goes quiet again.
fn set_revocation_read_readable(db_path: &std::path::Path, readable: bool) {
    let conn = rusqlite::Connection::open(db_path).expect("open fault-injection connection");
    conn.busy_timeout(std::time::Duration::from_secs(30))
        .expect("busy_timeout");
    let sql = if readable {
        "ALTER TABLE federation_revocations_hidden RENAME TO federation_revocations"
    } else {
        "ALTER TABLE federation_revocations RENAME TO federation_revocations_hidden"
    };
    conn.execute_batch(sql)
        .expect("rename federation_revocations");
}

/// **An unreadable standing-rows read must not report itself as "nothing
/// stands", and must not author.**
///
/// The three zeroes this read has to keep apart, and the fourth thing that is
/// not a zero at all:
///
/// | fact | rows authored | what an operator must read |
/// |---|---|---|
/// | live rows carry this score in this bucket | none | routine (`Unchanged`) |
/// | rows exist about the subject and none stand | one | routine (`none_standing`) |
/// | the subject has never been scored | one | routine (`never_scored`) |
/// | the read FAILED | **none** | **a fault** |
///
/// Leg 2 is the load-bearing one and it asserts BOTH halves of the fix:
///
///   - **the pass alarms** and names the standing-rows read (the instrument), and
///   - **the corpus does not grow** (the behaviour). The second is what the
///     swallow actually cost: a fail-open re-author would have left the returned
///     count and the log looking almost identical while adding a permanent,
///     replicating row on every pass.
///
/// Leg 3 restores the table and requires the pass to go quiet AND stay audible,
/// so the test cannot be satisfied by a scorer that alarms unconditionally.
#[tokio::test]
async fn an_unreadable_standing_read_is_not_nothing_standing() {
    let dir = std::env::temp_dir().join(format!("ciris-374-standing-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let db_path = dir.join("node-a.db");
    let (node, node_ed_pub_b64, node_mldsa_pub_b64) =
        node_a_on_disk(&db_path.to_string_lossy()).await;

    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    let agent_pub_b64 = BASE64.encode(agent_sk.verifying_key().to_bytes());
    let mldsa = fixture_pqc::signer();
    let node_key_id = node
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id");
    register_key_hybrid(
        &node,
        &node_key_id,
        &node_ed_pub_b64,
        Some(&node_mldsa_pub_b64),
        identity_type::NODE,
    )
    .await;
    register_key(&node, AGENT_KEY_ID, &agent_pub_b64, identity_type::AGENT).await;
    for i in 0..30usize {
        node.receive_and_persist(&build_trace_batch(&agent_sk, &mldsa, i), &NullScrubber)
            .await
            .expect("ingest synthetic trace");
    }
    grant_analyze_consent(&node, AGENT_KEY_ID, &node_key_id).await;

    let cfg = ScorerConfig {
        cadence: std::time::Duration::from_secs(3600),
        window: 500,
        sample_size_gate: 2,
        target_n_eff: 8.0,
    };

    // (1) GREEN — cold corpus, the read works, one row is authored, nothing
    //     alarms. This is `never_scored`: the first pass of a subject's life.
    let (emitted, log) = log_capture::capture(scorer::run_pass(&node, &node_key_id, &cfg)).await;
    assert_eq!(
        emitted.expect("cold pass"),
        1,
        "a consented subject with a full trace window and no history must be scored"
    );
    assert!(
        log.alarms().is_empty(),
        "the cold path must not alarm:\n{}",
        log.render_or_explain()
    );
    let rows_after_cold = capacity_rows(&node).await;
    assert_eq!(rows_after_cold, 1, "exactly one capacity row after leg 1");

    // (2) BREAK the standing-rows read. Nothing about the corpus has changed:
    //     the consent grant stands, the traces stand, and the capacity row
    //     written in leg 1 is still there — the scorer just cannot see it.
    set_revocation_read_readable(&db_path, false);

    let (emitted, log) = log_capture::capture(scorer::run_pass(&node, &node_key_id, &cfg)).await;
    assert_eq!(
        emitted.expect("the pass itself must survive an unreadable standing read"),
        0,
        "FAIL CLOSED: when the scorer cannot tell whether it has already authored this score, \
         it must not author. The row it would write carries an `asserted_at` derived from the \
         read that just failed, so \"it would be identical anyway\" is false exactly here."
    );

    // The behavioural half — this is what the swallow COST.
    assert_eq!(
        capacity_rows(&node).await,
        rows_after_cold,
        "a failed standing-rows read grew the corpus. That is the whole defect: an empty vec \
         reads as \"nothing stands\", the scorer re-authors, and because `unchanged_for` also \
         came back empty the assertion instant falls back to the hourly base bucket — a \
         different signed instant, a different content hash, a genuinely new permanent row."
    );

    // The instrument half. `Ok(0)` is also what a fully-coalesced healthy pass
    // returns, so the difference between them exists only in what the pass said.
    let alarms = log.alarms();
    assert!(
        !alarms.is_empty(),
        "an unreadable standing-rows read was reported with NO alarm at all — the coalescer \
         went blind and the pass read as routine.\n{}",
        log.render_or_explain()
    );
    assert!(
        alarms
            .iter()
            .any(|e| e.message.contains("STANDING-ROWS READ FAILED")),
        "no alarm names the STANDING-ROWS READ as what failed. The reader must be sent to the \
         capacity plane, not the trace plane — the traces arrived and were read fine.\n{}",
        log.render_or_explain()
    );
    assert!(
        log.events()
            .iter()
            .all(|e| !e.message.contains("steady state, not a fault")),
        "the pass reported a blind coalescer as a healthy steady state — the exact collapse \
         CIRISServer#374 is about.\n{}",
        log.render_or_explain()
    );
    assert!(
        log.events()
            .iter()
            .any(|e| e.message.contains("NOT \"nothing stands\"")),
        "the per-agent line must say this was not an empty corpus: \"no rows stand\" and \"the \
         rows could not be read\" are opposite facts.\n{}",
        log.render_or_explain()
    );

    // (3) RESTORE — same corpus, same subject, same grant, same score. The read
    //     works again, the leg-1 row stands inside its bucket, and the pass goes
    //     quiet. Without this leg the test would pass against a scorer that
    //     alarms unconditionally.
    set_revocation_read_readable(&db_path, true);

    let (emitted, log) = log_capture::capture(scorer::run_pass(&node, &node_key_id, &cfg)).await;
    assert_eq!(
        emitted.expect("restored pass"),
        0,
        "the score is unchanged inside its coalescing bucket, so nothing new is authored"
    );
    assert_eq!(
        capacity_rows(&node).await,
        rows_after_cold,
        "the restored pass must not author either — the leg-1 row is visible again and stands"
    );
    assert!(
        log.alarms().is_empty(),
        "with the read working again the pass must be quiet — an alarm that never clears is \
         the same instrument failure pointed the other way:\n{}",
        log.render_or_explain()
    );
    assert!(
        log.events()
            .iter()
            .any(|e| e.message.contains("steady state, not a fault")),
        "the restored pass must be AUDIBLE about being healthy, not merely silent — a silent \
         pass and a dead loop look identical from outside (CIRISServer#315).\n{}",
        log.render_or_explain()
    );

    let _ = std::fs::remove_dir_all(&dir);
}
