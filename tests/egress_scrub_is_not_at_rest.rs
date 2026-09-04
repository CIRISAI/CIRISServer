//! **A node's own record is never scrubbed; only what ships is** (persist
//! v33.0.0 / CIRISPersist#705 / CIRISServer#418).
//!
//! # Why this file exists at all
//!
//! The v33 change is **compiler-invisible** — persist's own inventory measured
//! it at +191/−21 lines inside function bodies with *zero* signature change. So
//! the entire adopt of the release we most wanted produces a green build, a
//! green clippy and a green suite whether or not the behaviour actually moved.
//! Nothing in this repo would have noticed the difference.
//!
//! Server wrote that lesson into its own source after being burned by exactly
//! this class, and persist's adopt map repeats it: *validation must be a
//! behavioural witness*.
//!
//! # What changed
//!
//! Before v33, `receive_and_persist` scrubbed the ingest envelope **in place**.
//! But that call is how an agent captures **its own** traces, so the original
//! was redacted before it was ever stored and the unscrubbed record existed
//! nowhere. Server wired a real scrubber, watched self-scoped content change
//! under it, reverted, and held the pin — which is what produced #418.
//!
//! v33 splits it at the privacy boundary:
//!
//! | artifact | treatment | role |
//! |---|---|---|
//! | the stored `trace_events` rows | **untouched** | the record |
//! | the minted attestation | **scrubbed** | the only thing that ships |
//!
//! # The assertion has to be the DISAGREEMENT
//!
//! This is the part worth being careful about. Persist's changelog states it:
//!
//! > Either assertion alone passes on a no-op scrubber or on the old
//! > both-scrubbed behaviour; only the pair distinguishes this fix.
//!
//! - "the stored row still has the PII" **alone** passes trivially against a
//!   `NullScrubber` — it proves nothing about egress.
//! - "the attestation lacks the PII" **alone** passes against the OLD
//!   both-scrubbed behaviour — the artifact this test exists to distinguish.
//!
//! Only asserting both against **one** ingest of **one** batch separates v33
//! from both of its neighbours, so that is what the test below does.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::Utc;
use ciris_persist::federation::types::{algorithm, identity_type};
use ciris_persist::federation::{FederationDirectory as _, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::schema::{
    CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion, TraceComponent, TraceLevel,
};
use ciris_persist::verify::canonical::Canonicalizer;
use ciris_persist::verify::{ed25519::canonical_payload_value, PythonJsonDumpsCanonicalizer};
use ciris_server::scrub::EgressScrubber;
use ed25519_dalek::{Signer as _, SigningKey};

/// The PII the walker+regex pass at `detailed` actually redacts. Distinct
/// literals so a failure names WHICH one leaked, rather than "content differs".
const EMAIL: &str = "alice.reallyunique@example.com";
const SSN: &str = "555-12-9999";

const TRACE_ID: &str = "t-egress-not-at-rest-1";
const AGENT_KEY: &str = "agent-egress-witness";

async fn node() -> Arc<Engine> {
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0x5Au8; 32]),
        "node-egress-witness".to_string(),
        None,
        None,
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine"),
    )
}

/// Cross-register the agent key so `VerifyMode::Full` — the real
/// `receive_and_persist` path — can resolve the trace's signature.
async fn cross_register(engine: &Engine, key_id: &str, sk: &SigningKey, mldsa_pk: &str) {
    let now = Utc::now();
    let pubkey_b64 = BASE64.encode(sk.verifying_key().to_bytes());
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: pubkey_b64.clone(),
        pubkey_ml_dsa_65_base64: Some(mldsa_pk.to_string()),
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
        .expect("cross-register the agent key");
}

/// A hybrid-signed `detailed` batch carrying PII in a field the walker enters.
///
/// `detailed` on purpose, not `full_traces`: the walker+regex pass is
/// deterministic and safe by construction, so this test does not depend on
/// whether an NER model is staged. A `full_traces` batch without one is REFUSED
/// by persist (#690), which would test the refusal rather than the split.
fn build_batch_bytes() -> Vec<u8> {
    let mut data = serde_json::Map::new();
    data.insert(
        "thought_content".into(),
        serde_json::json!(format!("reach me at {EMAIL} or {SSN}")),
    );
    let component = TraceComponent {
        component_type: ComponentType::Observation,
        event_type: ReasoningEventType::ThoughtStart,
        timestamp: "2026-06-14T00:00:00Z".parse().unwrap(),
        data,
        agent_id_hash: None,
    };

    let mut trace = CompleteTrace {
        trace_id: TRACE_ID.into(),
        thought_id: TRACE_ID.into(),
        task_id: Some("task-egress".into()),
        agent_id_hash: "cafebabe".into(),
        started_at: "2026-06-14T00:00:00Z".parse().unwrap(),
        completed_at: "2026-06-14T00:01:00Z".parse().unwrap(),
        trace_level: TraceLevel::Detailed,
        trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
        components: vec![component],
        deployment_profile: None,
        // SELF-scoped: the node's own record, which is precisely the case #418
        // was filed about — the content that was being destroyed at rest.
        cohort_scope: "self".into(),
        cohort_target_id: None,
        signature: String::new(),
        signature_key_id: AGENT_KEY.into(),
        signature_ml_dsa_65: None,
        pubkey_ml_dsa_65: None,
        pqc_key_id: None,
    };

    let payload = canonical_payload_value(&trace);
    let canon = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&payload)
        .expect("canonicalize");
    let sk = SigningKey::from_bytes(&[0x33u8; 32]);
    let ed_sig = sk.sign(&canon).to_bytes();
    let mut bound = Vec::with_capacity(canon.len() + ed_sig.len());
    bound.extend_from_slice(&canon);
    bound.extend_from_slice(&ed_sig);
    let mldsa = ciris_crypto::MlDsa65Signer::from_seed(&[0x44u8; 32]).expect("ml-dsa seed");
    use ciris_crypto::PqcSigner as _;
    trace.signature = BASE64.encode(ed_sig);
    trace.signature_ml_dsa_65 = Some(BASE64.encode(mldsa.sign(&bound).expect("sign")));
    trace.pubkey_ml_dsa_65 = Some(BASE64.encode(mldsa.public_key().expect("pk")));
    // This file signs with its OWN ML-DSA key (seed 0x44) and registers that
    // pubkey on `AGENT_KEY`'s own record, so the key id it names is that record
    // — one identity holding both halves, the shape a production hybrid key
    // record has. It does not use the shared `fixture_pqc` identity, which
    // exists for the fixtures that sign with the common seed.
    trace.pqc_key_id = Some(AGENT_KEY.into());

    serde_json::json!({
        "events": [{
            "event_type": "complete_trace",
            "trace_level": "detailed",
            "trace": serde_json::to_value(&trace).expect("serialize"),
        }],
        "batch_timestamp": "2026-06-14T00:00:00Z",
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "detailed",
        "trace_schema_version": "2.7.0",
    })
    .to_string()
    .into_bytes()
}

/// Every stored `trace_events` row's component payload, read straight out of
/// sqlite — the record as it actually rests on disk, not as any API renders it.
/// Every stored `trace_events` row, ALL columns, straight out of sqlite — the
/// record as it actually rests on disk, not as any API renders it.
///
/// Reads columns generically rather than naming one: which column holds the
/// component payload is persist's schema detail, and a test that hard-codes it
/// breaks on an unrelated migration while proving nothing extra. What this
/// witness needs is only "does the content survive anywhere in the row".
fn stored_rows_text(engine: &Engine) -> String {
    let handle = engine
        .sqlite_backend()
        .expect("sqlite-backed in this test")
        .conn_handle();
    let conn = handle.lock();
    let mut stmt = conn
        .prepare("SELECT * FROM trace_events")
        .expect("trace_events is the projection table v33 leaves untouched");
    let ncols = stmt.column_count();
    let rows: Vec<String> = stmt
        .query_map([], |r| {
            let mut cells = Vec::with_capacity(ncols);
            for i in 0..ncols {
                // Every column as text; a non-text column simply contributes
                // nothing to the content search, which is correct.
                cells.push(r.get::<_, String>(i).unwrap_or_default());
            }
            Ok(cells.join("\u{1}"))
        })
        .expect("query trace_events")
        .filter_map(Result::ok)
        .collect();
    assert!(
        !rows.is_empty(),
        "the batch must have produced trace_events rows, or neither half of \
         this witness is testing anything"
    );
    rows.join("\n")
}

#[tokio::test]
async fn the_record_keeps_its_content_and_only_the_attestation_is_scrubbed() {
    let engine = node().await;
    let mldsa = ciris_crypto::MlDsa65Signer::from_seed(&[0x44u8; 32]).expect("ml-dsa seed");
    use ciris_crypto::PqcSigner as _;
    let mldsa_pk = BASE64.encode(mldsa.public_key().expect("pk"));
    cross_register(
        &engine,
        AGENT_KEY,
        &SigningKey::from_bytes(&[0x33u8; 32]),
        &mldsa_pk,
    )
    .await;

    // ONE ingest, through the REAL scrubber this node wires in production
    // (`ingest_http.rs` passes exactly this). Both halves below read the
    // artifacts of this single call — that is what makes them a pair rather
    // than two independent facts.
    let summary = engine
        .receive_and_persist(&build_batch_bytes(), &EgressScrubber)
        .await
        .expect(
            "a detailed batch with a real scrubber must be ACCEPTED — v33 \
                 moved the #690 refusal onto publication, not storage",
        );
    assert!(
        summary.trace_events_inserted > 0,
        "the record must have been stored: {summary:?}"
    );

    // ── HALF 1: the RECORD is intact ────────────────────────────────────────
    // Pre-v33 this is where the content was destroyed: the scrubber ran on the
    // ingest envelope in place, so the node's own unredacted trace existed
    // nowhere afterwards. This half fails against the old behaviour.
    let stored = stored_rows_text(&engine);
    assert!(
        stored.contains(EMAIL),
        "the node's OWN record must keep its content — scrubbing at rest is what \
         CIRISServer#418 was filed about. `{EMAIL}` is absent from the stored \
         rows:\n{stored}"
    );
    assert!(
        stored.contains(SSN),
        "same for `{SSN}` — a partial redaction at rest is still redaction at \
         rest:\n{stored}"
    );

    // ── HALF 2: what SHIPS is scrubbed ──────────────────────────────────────
    // The attestation embeds the whole trace and is the wire object; the
    // trace_events rows are a local projection that never replicates. So this
    // is the artifact the privacy guarantee actually rides on. This half fails
    // if a scrubber was never wired at all.
    // Fetched by persist's DETERMINISTIC trace-attestation id rather than by
    // listing. The list readers are two axes — `list_attestations_by` is the
    // ATTESTER, `list_attestations_for` is the SUBJECT — and this mint attests
    // under the trace's verified producer key while being about the trace. The
    // id depends on neither, so it cannot silently return an empty set because
    // the wrong axis was asked. (Written after `_for` returned nothing and the
    // vacuity guard below caught it.)
    let att_id = ciris_persist::ingest::trace_attestation_id(TRACE_ID);
    let minted_att = engine
        .sqlite_backend()
        .expect("sqlite backend present")
        .get_attestation(&att_id)
        .await
        .expect("get_attestation")
        .expect("the ingest must have minted a trace attestation for this trace");
    let minted = serde_json::to_string(&minted_att).expect("serialize attestation");
    assert!(
        minted.contains(TRACE_ID),
        "half 2 must be reading the attestation for THIS trace, or it proves \
         nothing about the batch half 1 just inspected:\n{minted}"
    );
    assert!(
        !minted.contains(EMAIL),
        "the PUBLISHABLE artifact must be redacted — `{EMAIL}` reached the \
         attestation, which is the object that federates:\n{minted}"
    );
    assert!(
        !minted.contains(SSN),
        "`{SSN}` reached the attestation:\n{minted}"
    );
}
