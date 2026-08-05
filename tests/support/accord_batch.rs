//! **The wire bytes the `CIRIS-AccordMetrics/1.0` emitter ships** — a
//! FULL-HYBRID-signed `CompleteTrace` wrapped in a `BatchEnvelope` JSON (=
//! `AccordEventsBatch`), byte-shaped exactly as the deployed producer POSTs it.
//!
//! Shared rather than copied, on purpose. Two test files that each build "the
//! emitter's batch" are two answers to what the wire shape IS, and the first
//! substrate bump that changes one and not the other leaves a green suite over a
//! fixture production no longer sends. Same rule the source side follows for
//! envelope vocabulary.
//!
//! [`build_batch_bytes_at`] takes the component instant because
//! `trace_events.ts` — the column persist's `storage_summary` folds into
//! `newest_ts`, and therefore the column the trace-plane liveness band
//! (CIRISServer#369) reads — IS this timestamp. A fixture that hard-codes it
//! cannot prove the band *moves* when a newer trace lands.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as _, SigningKey};

use ciris_persist::schema::{
    CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion, TraceComponent, TraceLevel,
};
use ciris_persist::verify::canonical::Canonicalizer;
use ciris_persist::verify::{ed25519::canonical_payload_value, PythonJsonDumpsCanonicalizer};

/// The instant the original fixture pinned, kept so callers that do not care
/// about the clock read exactly as they did before.
const DEFAULT_STARTED_AT: &str = "2026-06-14T00:00:00Z";
const DEFAULT_COMPLETED_AT: &str = "2026-06-14T00:01:00Z";

/// The emitter's batch, at the fixture's original fixed instants.
#[allow(dead_code)] // used by tests/ingest_http.rs, not by every consumer
pub fn build_batch_bytes(agent_sk: &SigningKey, key_id: &str, trace_id: &str) -> Vec<u8> {
    build_batch_bytes_at(
        agent_sk,
        key_id,
        trace_id,
        DateTime::parse_from_rfc3339(DEFAULT_COMPLETED_AT)
            .expect("default completed_at")
            .with_timezone(&Utc),
    )
}

/// `ts` as the wire bytes a producer actually sends. `WireDateTime` preserves
/// the wire form byte-exactly (persist AV-4) because the CEG signature is over
/// those bytes — so the fixture has to commit to one rendering, and seconds-
/// precision-with-`Z` is what the emitter ships.
fn wire(ts: DateTime<Utc>) -> ciris_persist::schema::WireDateTime {
    ciris_persist::schema::WireDateTime::from_wire(
        ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    )
    .expect("rfc3339 wire instant")
}

/// The emitter's batch with the component stamped at `ts`.
///
/// `ts` lands in `trace_events.ts`, which is what `storage_summary().
/// trace_events.newest_ts` reports and what the operator surface bands as
/// `last_admitted_at`. It is the PRODUCER's own broadcast clock — that is not an
/// accident of this fixture, it is the documented limit of the reading
/// (`operator.trace_plane.producer_asserted_ts`).
#[allow(dead_code)]
pub fn build_batch_bytes_at(
    agent_sk: &SigningKey,
    key_id: &str,
    trace_id: &str,
    ts: DateTime<Utc>,
) -> Vec<u8> {
    let mut data = serde_json::Map::new();
    data.insert("seq".into(), serde_json::json!(0));
    let component = TraceComponent {
        component_type: ComponentType::Conscience,
        event_type: ReasoningEventType::ConscienceResult,
        timestamp: wire(ts),
        data,
        agent_id_hash: None,
    };

    let mut trace = CompleteTrace {
        trace_id: trace_id.into(),
        thought_id: trace_id.into(),
        task_id: Some("task-http-ingest".into()),
        agent_id_hash: "cafebabe".into(),
        started_at: DEFAULT_STARTED_AT.parse().expect("started_at"),
        completed_at: wire(ts),
        trace_level: TraceLevel::Generic,
        trace_schema_version: SchemaVersion::parse("2.7.0").expect("schema version"),
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
        "batch_timestamp": DEFAULT_STARTED_AT,
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
    });
    envelope.to_string().into_bytes()
}
