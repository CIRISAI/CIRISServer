//! CHARACTERIZATION PIN — the capacity self-revocation defect (CIRISServer T6
//! Item 1 / CIRISPersist#519 exhibit G2). This test asserts a KNOWN-WRONG live
//! behavior on purpose so the eventual fix is DETECTED, not a behavior we endorse.
//!
//! ## The defect
//!
//! `src/scorer.rs` sets `input.subject_key_ids = vec![attested_key_id]` on every
//! `capacity:*` emit. Persist's `resolve_withdraws_admission_rule` (admission.rs)
//! **rule 2** admits a `withdraws` from any `issuer ∈ subject_key_ids`. Net effect:
//! the SCORED agent can self-revoke its own unflattering capacity score. CC 3.4.5's
//! anti-Goodhart wall blocks self-EMISSION (persist `CapacitySelfEmissionRejected`,
//! and `CapacityAttestation::new` server-side) but NOT self-REVOCATION.
//!
//! ## Why it stays a persist-court fix (assessed against persist v21.10.0)
//!
//! The naïve server fix — stop populating `subject_key_ids` — WOULD BREAK subject-
//! keyed score reads: `attestation_subjects.subject_key_id` is the per-element
//! projection of `subject_key_ids` (persist `list_attestation_log`'s `s.subject_key_id`
//! seek + the memory twin's `subject_key_id` filter both match against it). The
//! singular read predicate and the plural revocation vector are the SAME field, so
//! decoupling them (or making withdraws rule 2 dimension-aware) requires a persist
//! change. persist v21.10.0 ships NO per-family revocation policy: `recipient_revoke`
//! appears only in the namespace-superset MANIFEST (zero `.rs` enforcement) and
//! `resolve_withdraws_admission_rule` is dimension-blind. So the server changes
//! NOTHING here — this pin documents the live behavior.
//!
//! ## What trips this pin (either court)
//!
//! - SERVER fix (scorer stops populating `subject_key_ids`): the first assertion
//!   fails — the manifest's prescribed cure ("capacity:* should NOT populate
//!   subject_key_ids").
//! - PERSIST fix (withdraws rule 2 becomes dimension-aware for `capacity:*`): the
//!   second assertion fails — the subject is no longer admitted (rule 2).
//!
//! When it fails, the fixer should REPLACE the `assert`s here with the corrected
//! expectation (subject self-revocation DENIED for a capacity row).

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::admission::resolve_withdraws_admission_rule;
use ciris_persist::federation::types::{algorithm, identity_type};
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

/// **CIRISConstitution#46 (persist v22.0.0) — CONSENT BEFORE SCORING.** The
/// subject must grant the attester the `analyze` scope or `capacity:*` emission is
/// refused, so this is now part of the fixture's contract rather than incidental
/// setup: without it the scorer authors nothing and this pin's *setup* fails long
/// before it can characterise the revocation behaviour it exists to pin.
///
/// The claim is `P → S`; the consent is the REVERSE edge `S → P`, so the SUBJECT
/// authors it naming the attester. Federation-tier (via promote) because
/// `resolve_scoped_consent` reads through `list_attestations_for`, which is
/// tier-filtered. Vocabulary single-sourced from persist, never hand-mirrored.
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
            subject_key_ids: Vec::new(),
            cohort_scope: cohort_scope::SELF.to_string(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        })
        .await
        .expect("seed analyze consent");
    engine
        .attestation_promote(&id, cohort_scope::FEDERATION)
        .await
        .expect("promote analyze consent to federation tier");
}

const AGENT_ID_HASH: &str = "agent-alpha";

/// Node A: in-memory substrate keyed by a hybrid node-identity signer (Ed25519 +
/// ML-DSA-65 software seed). Returns its real hybrid pubkeys (base64) so the
/// scorer's federation-tier emit admits. Mirrors `tests/capacity_scorer.rs`.
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

async fn register_key(engine: &Engine, key_id: &str, ed_pubkey_b64: &str, id_type: &str) {
    register_key_hybrid(engine, key_id, ed_pubkey_b64, None, id_type).await;
}

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
}

/// One signed `CompleteTrace` batch with varied DMA/IDMA/CONSCIENCE payloads so the
/// per-agent feature matrix has real covariance structure. Copied from
/// `tests/capacity_scorer.rs::build_trace_batch`.
fn build_trace_batch(
    agent_sk: &SigningKey,
    mldsa: &ciris_crypto::MlDsa65Signer,
    idx: usize,
) -> Vec<u8> {
    let f = idx as f64;
    let csdma = 0.5 + 0.3 * ((f * 0.7).sin());
    let dsdma = 0.5 + 0.25 * ((f * 0.9).cos());
    let k_eff = 1.0 + (f % 5.0) * 0.4;
    let corr_risk = 0.1 + 0.2 * ((f * 1.3).sin()).abs();
    let conscience_passed = idx % 4 != 0;
    let overridden = idx % 7 == 0;
    let entropy_passed = idx % 3 != 0;
    let coherence_passed = idx % 5 != 0;

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
async fn scored_agent_is_refused_self_revocation_of_its_capacity_score() {
    let (node, node_ed_pub_b64, node_mldsa_pub_b64) = node_a_with_keys().await;
    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    let agent_pub_b64 = BASE64.encode(agent_sk.verifying_key().to_bytes());
    let mldsa = ciris_crypto::MlDsa65Signer::from_seed(&[0x77u8; 32]).expect("ml-dsa seed");

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

    // Ingest a scorable corpus for the agent.
    const N_TRACES: usize = 30;
    for i in 0..N_TRACES {
        let bytes = build_trace_batch(&agent_sk, &mldsa, i);
        node.receive_and_persist(&bytes, &NullScrubber)
            .await
            .expect("ingest synthetic trace");
    }

    // Run the REAL scorer (the code under characterization).
    let cfg = ScorerConfig {
        cadence: std::time::Duration::from_secs(3600),
        window: 500,
        sample_size_gate: 2,
        target_n_eff: 8.0,
    };
    // CC#46 — the attester is the node's DERIVED key id (what emit_attestation_self
    // stamps and what is registered), not the bare NODE_KEY_ID alias.
    grant_analyze_consent(&node, AGENT_KEY_ID, &node_key_id).await;

    let emitted = scorer::run_pass(&node, &node_key_id, &cfg)
        .await
        .expect("scorer pass must succeed");
    assert_eq!(emitted, 1, "exactly one agent scored + emitted");

    let dir = node.sqlite_backend().expect("sqlite backend present");
    let attestations = dir
        .list_attestations_for(AGENT_KEY_ID)
        .await
        .expect("list attestations for the agent");
    assert_eq!(attestations.len(), 1, "exactly one capacity row");
    let att = &attestations[0];
    assert_eq!(att.attestation_type, "scores");
    assert_eq!(att.attested_key_id, AGENT_KEY_ID);
    assert_ne!(
        att.attesting_key_id, att.attested_key_id,
        "anti-Goodhart on emission holds (attesting != attested)"
    );

    // ── PIN 1 (SERVER contribution) ─────────────────────────────────────────
    // The scorer populates `subject_key_ids` with the SCORED agent's key — the
    // field withdraws rule 2 keys off. The manifest's prescribed server cure is
    // to STOP doing this (see `data_subject` note: "capacity:* should NOT
    // populate subject_key_ids"); when that lands, this assertion trips.
    assert_eq!(
        att.subject_key_ids,
        vec![AGENT_KEY_ID.to_string()],
        "KNOWN DEFECT: scorer puts the scored agent in subject_key_ids — the \
         withdraws rule-2 self-revocation vector. STILL CORRECT to populate: it is \
         legitimate data-subject NAMING (the singular `attestation_subjects.subject_key_id` \
         read predicate is its per-element projection). persist v21.12.0 fixed this in the \
         right court by making the withdraws rule dimension-aware — see PIN 2"
    );

    // ── PIN 2 (PERSIST consequence) — INVERTED, the fix LANDED ──────────────
    // persist v21.12.0 (CIRISPersist#528, exhibit G2 of #519) shipped the
    // dimension-aware withdraws policy. The scored agent (a mere SUBJECT of a
    // `capacity:*` row) is now REFUSED: CC 3.4.5's anti-Goodhart wall applies to
    // retraction as well as emission, so an agent can no longer score itself
    // "un-down" by withdrawing an unflattering score.
    //
    // This assertion was written INVERTED-ON-PURPOSE while the defect was live
    // (it asserted rule 2 was admitted, and tripped the moment the fix arrived —
    // which is exactly how this cut discovered v21.12.0 had closed it). Do NOT
    // "repair" it back: if this ever admits again, the anti-Goodhart wall has
    // been re-opened on the retraction side.
    let refusal = resolve_withdraws_admission_rule(dir.as_ref(), AGENT_KEY_ID, att)
        .await
        .expect_err(
            "REGRESSION: the scored agent must NOT be admitted to withdraw its own \
             capacity score (CIRISPersist#528 / CC 3.4.5 anti-Goodhart applies to \
             retraction, not just emission). If this succeeds, per-family revocation \
             policy has regressed to the dimension-blind rules",
        );
    assert_eq!(
        refusal.kind(),
        "federation_withdraws_not_admitted",
        "the refusal must be the withdraws-authority gate specifically, not an \
         incidental error (got: {refusal})"
    );

    // The node (attester) may of course revoke its own attestation — rule 1. This
    // is CORRECT and must survive any fix (attester + quorum keep revocation).
    let attester_rule = resolve_withdraws_admission_rule(dir.as_ref(), &node_key_id, att)
        .await
        .expect("the attester (node) may always revoke its own row");
    assert_eq!(
        attester_rule, 1,
        "attester self-revocation is rule 1 (correct)"
    );
}
