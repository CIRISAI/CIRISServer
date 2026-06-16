//! Replication / corpus-ingest throughput — the receive side of CEG-RC5
//! replication (the spine `tests/replication.rs` proves correct). Measures
//! `Engine::receive_and_persist`: signature verify (Ed25519) → decompose →
//! persist with a **5-tuple `ON CONFLICT DO NOTHING`** dedup (NOT a content-hash
//! lookup — the dedup key is `(agent_id_hash, trace_id, thought_id, event_type,
//! attempt_index[, ts])`). Run: `cargo bench --bench replication_ingest`.
//!
//! Both run against ONE shared in-memory Engine (not a fresh backend per
//! iteration), so the dedup path is exercised for real:
//! - `ingest_new`   — a fresh signed trace each iteration (a new envelope from a
//!   peer). "Replication speed" — traces/sec a node absorbs.
//! - `ingest_dedup` — re-delivering an already-seen trace (anti gossip-loop:
//!   verify → decompose → insert rejected at the unique index).
//!
//! THE FINDING: `ingest_dedup` is only marginally cheaper than `ingest_new` —
//! because **verify runs BEFORE the dedup insert**, a re-delivery still pays full
//! Ed25519 verification. So a replay / gossip flood is bounded by **verify
//! throughput**, not a cheap hash reject. This is deliberate (verify-before-
//! mutation, MISSION §3 — reordering dedup ahead of verify is an AV-9 suppression
//! oracle: the dedup tuple is attacker-controllable). The scale levers are the
//! pre-verified relay path (`VerifyMode::TrustPreVerified` gated on an Edge
//! `verify_outcome`) and batch verification (CIRISPersist#225) — NOT dedup-first.

use std::sync::Arc;
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use ed25519_dalek::{Signer as _, SigningKey};

use ciris_persist::federation::types::{algorithm, identity_type};
use ciris_persist::federation::{FederationDirectory as _, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::schema::{
    CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion, TraceComponent, TraceLevel,
};
use ciris_persist::scrub::NullScrubber;

const KEY_ID: &str = "bench-agent";

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

async fn engine_with_key(agent_sk: &SigningKey) -> Arc<Engine> {
    let node = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xA0; 32]),
        "bench-node".to_string(),
        None,
        None,
    ));
    let engine = Arc::new(
        Engine::with_signer(node, "sqlite::memory:")
            .await
            .expect("engine"),
    );
    // Register the agent key so VerifyMode::Full resolves the trace signature.
    let pubkey_b64 = BASE64.encode(agent_sk.verifying_key().to_bytes());
    let now = chrono::Utc::now();
    let record = KeyRecord {
        key_id: KEY_ID.into(),
        pubkey_ed25519_base64: pubkey_b64.clone(),
        pubkey_ml_dsa_65_base64: None,
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::AGENT.into(),
        identity_ref: KEY_ID.into(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": KEY_ID }),
        original_content_hash: "deadbeef".into(),
        scrub_signature_classical: pubkey_b64,
        scrub_signature_pqc: None,
        scrub_key_id: KEY_ID.into(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .sqlite_backend()
        .expect("sqlite")
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register key");
    engine
}

fn batch_bytes(agent_sk: &SigningKey, trace_id: &str) -> Vec<u8> {
    use ciris_persist::verify::canonical::Canonicalizer;
    use ciris_persist::verify::{ed25519::canonical_payload_value, PythonJsonDumpsCanonicalizer};
    let mut data = serde_json::Map::new();
    data.insert("seq".into(), serde_json::json!(0));
    let mut trace = CompleteTrace {
        trace_id: trace_id.into(),
        thought_id: trace_id.into(),
        task_id: Some("bench".into()),
        agent_id_hash: "cafebabe".into(),
        started_at: "2026-06-15T00:00:00Z".parse().unwrap(),
        completed_at: "2026-06-15T00:01:00Z".parse().unwrap(),
        trace_level: TraceLevel::Generic,
        trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
        components: vec![TraceComponent {
            component_type: ComponentType::Conscience,
            event_type: ReasoningEventType::ConscienceResult,
            timestamp: "2026-06-15T00:00:00Z".parse().unwrap(),
            data,
            agent_id_hash: None,
        }],
        deployment_profile: None,
        cohort_scope: "federation".into(),
        cohort_target_id: None,
        signature: String::new(),
        signature_key_id: KEY_ID.into(),
        // Hybrid half (persist v7.2.0 #225) — filled below.
        signature_ml_dsa_65: None,
        pubkey_ml_dsa_65: None,
        pqc_key_id: None,
    };
    let canon = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&canonical_payload_value(&trace))
        .unwrap();
    // Hard cut (CIRISPersist v7.2.0 #225): VerifyMode::Full rejects classical-only
    // per-trace sigs. Sign FULL HYBRID — Ed25519 over `canon`, ML-DSA-65 over
    // `canon ‖ ed25519_sig` (the bound input; ciris-crypto HybridSigner contract).
    // The ML-DSA pubkey rides the trace envelope (the verifier reads it there, not
    // from the KeyRecord). Sync ciris_crypto signer → no async in the setup closure.
    use ciris_crypto::{MlDsa65Signer, PqcSigner as _};
    let ed_sig = agent_sk.sign(&canon).to_bytes();
    let mut bound = Vec::with_capacity(canon.len() + ed_sig.len());
    bound.extend_from_slice(&canon);
    bound.extend_from_slice(&ed_sig);
    let mldsa = MlDsa65Signer::from_seed(&[0x77u8; 32]).expect("ml-dsa seed");
    trace.signature = BASE64.encode(ed_sig);
    trace.signature_ml_dsa_65 = Some(BASE64.encode(mldsa.sign(&bound).expect("ml-dsa sign")));
    trace.pubkey_ml_dsa_65 = Some(BASE64.encode(mldsa.public_key().expect("ml-dsa pk")));
    trace.pqc_key_id = Some("bench-mldsa".into());
    serde_json::json!({
        "events": [{ "event_type": "complete_trace", "trace_level": "generic",
                     "trace": serde_json::to_value(&trace).unwrap() }],
        "batch_timestamp": "2026-06-15T00:00:00Z",
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
    })
    .to_string()
    .into_bytes()
}

fn bench_ingest(c: &mut Criterion) {
    let _ = SystemTime::now(); // (no-op; keeps import honest if trimmed)
    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    let runtime = rt();
    let engine = runtime.block_on(engine_with_key(&agent_sk));

    let mut g = c.benchmark_group("replication_ingest");
    g.throughput(Throughput::Elements(1)); // one trace per iteration

    // New-trace insert path (a fresh envelope from a peer) = replication speed.
    g.bench_function("ingest_new", |b| {
        let mut n = 0u64;
        b.to_async(&runtime).iter_batched(
            || {
                n += 1;
                batch_bytes(&agent_sk, &format!("repl-{n:08}"))
            },
            |bytes| {
                let engine = Arc::clone(&engine);
                async move {
                    engine
                        .receive_and_persist(&bytes, &NullScrubber)
                        .await
                        .expect("ingest")
                }
            },
            BatchSize::SmallInput,
        );
    });

    // Re-delivery of an already-seen trace (anti gossip-loop dedup path).
    let dup = batch_bytes(&agent_sk, "repl-dup-fixed");
    runtime.block_on(async {
        engine
            .receive_and_persist(&dup, &NullScrubber)
            .await
            .expect("seed dup");
    });
    g.bench_function("ingest_dedup", |b| {
        b.to_async(&runtime).iter(|| {
            let engine = Arc::clone(&engine);
            let bytes = dup.clone();
            async move {
                engine
                    .receive_and_persist(&bytes, &NullScrubber)
                    .await
                    .expect("dedup")
            }
        });
    });

    g.finish();
}

criterion_group!(benches, bench_ingest);
criterion_main!(benches);
