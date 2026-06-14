//! Two-node CEG-RC5 replication spine — the de-risk test (CIRISServer#1;
//! FSD/REGISTRY_FOLD_DERISK.md §3). The user's ask: "lens needs the same
//! peer-to-peer replication per CEG RC5 as registry needs to replace Spock, so
//! test that."
//!
//! ## What this proves (and what it deliberately does NOT)
//!
//! The replication invariant CIRISServer owns is: **a CEG-signed corpus
//! envelope produced under node A's federation key, delivered to an
//! *independent* node B, verifies against the cross-registered key and persists
//! idempotently** — content-addressed dedup (CEG §10.1.6 idempotent merge for
//! keys/attestations/occurrences) is what prevents anti-entropy gossip loops.
//! This test exercises that spine across two independent `Engine`s on the
//! frozen triple (persist v6.8.1 / edge v3.5.0 / verify v5.4.0).
//!
//! The **transport hop itself** (Reticulum/HTTP framing, announce, durable
//! queue) is covered by edge's own round-trip tests. The inbound handler that
//! `Edge::run` dispatches to — `LensCore::attach_handler` → the lens handler —
//! calls exactly `Engine::receive_and_persist(&bytes, &NullScrubber)` (see
//! `crates/ciris-lens-core/src/role/handler.rs`). So feeding the wire bytes to
//! node B's `receive_and_persist` faithfully simulates the receive-side of the
//! app plane without standing up two Reticulum stacks in-process.
//!
//! The **anti-entropy Responder** (the registry-grade `ReplicationRuntime`
//! plane) cannot be driven end-to-end in-process yet: `Edge::run` owns the
//! `Transport::listen` loop and there is no hook to feed inbound replication
//! frames into `ReplicationRegistry::route_inbound_bytes`. Filed upstream as
//! **CIRISEdge#119** (`Edge::install_replication_routing`). Until it lands, this
//! test pins the persistence + verify + idempotent-merge spine both planes
//! deliver into.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};

use ciris_persist::federation::types::{algorithm, identity_type};
use ciris_persist::federation::{FederationDirectory as _, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::schema::{
    CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion, TraceComponent, TraceLevel,
};
use ciris_persist::scrub::NullScrubber;
use ciris_persist::verify::canonical::Canonicalizer;
use ciris_persist::verify::{ed25519::canonical_payload_value, PythonJsonDumpsCanonicalizer};

// ── A fabric node: one independent in-memory Engine + its node-identity signer ──

/// Stand up an independent node — its own SQLite-in-memory substrate, keyed by
/// its own node-identity `LocalSigner` (distinct from the agent key that signs
/// traces). Mirrors what `compose::build_engine` does in production, minus the
/// hardware seal.
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

/// Cross-register a peer's Ed25519 verifying key into this node's federation
/// directory so `VerifyMode::Full` can resolve a trace signed under `key_id`.
/// This is the "cross-registered keys" precondition for cross-region trust
/// (the founder-quorum admission door publishes these in production —
/// `src/quorum.rs`).
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
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .sqlite_backend()
        .expect("sqlite backend present")
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("cross-register peer key in federation directory");
}

/// Build the CEG wire bytes for a corpus batch: a single signed `CompleteTrace`
/// wrapped in a `BatchEnvelope` JSON — exactly what `AccordEventsBatch` carries
/// over the wire and what `Engine::receive_and_persist` consumes. (Same shape as
/// the persist QA harness fixture.)
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
        task_id: Some("task-repl".into()),
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
    };

    // Sign the canonicalized payload — the same canonicalization verify re-runs.
    let payload = canonical_payload_value(&trace);
    let canon = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&payload)
        .expect("canonicalize trace payload");
    trace.signature = BASE64.encode(agent_sk.sign(&canon).to_bytes());

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

/// The full spine: origin persists + verifies; an independent peer that trusts
/// the origin's key replicates + verifies the SAME envelope; re-delivery is an
/// idempotent no-op (anti gossip-loop); a peer that does NOT trust the key still
/// stores but cannot verify (proving the verify gate is real, not a rubber stamp).
#[tokio::test]
async fn signed_batch_replicates_and_verifies_across_independent_nodes() {
    // Agent (trace author) key — the federation identity the corpus is signed under.
    const AGENT_KEY_ID: &str = "agent-alpha";
    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);

    // Three independent fabric nodes, each its own substrate + node identity.
    let node_a = node(0xA0, "node-a").await; // origin
    let node_b = node(0xB0, "node-b").await; // trusting peer (replication target)
    let node_c = node(0xC0, "node-c").await; // peer that does NOT trust the agent key

    // A and B cross-register the agent key (founder-quorum admission, in prod).
    // C deliberately does not.
    cross_register(&node_a, AGENT_KEY_ID, &agent_sk).await;
    cross_register(&node_b, AGENT_KEY_ID, &agent_sk).await;

    let bytes = build_batch_bytes(&agent_sk, AGENT_KEY_ID, "trace-repl-0001");

    // ── Origin (node A): ingest + verify ─────────────────────────────────────
    let a = node_a
        .receive_and_persist(&bytes, &NullScrubber)
        .await
        .expect("origin ingest must succeed");
    assert!(
        a.trace_events_inserted > 0,
        "origin must persist the trace, inserted={}",
        a.trace_events_inserted
    );
    assert_eq!(
        a.signatures_verified, 1,
        "origin must verify the trace signature (key registered)"
    );

    // ── Replication hop (node B): the SAME wire bytes the app-plane inbound
    //    handler would feed to receive_and_persist ────────────────────────────
    let b = node_b
        .receive_and_persist(&bytes, &NullScrubber)
        .await
        .expect("peer ingest of replicated envelope must succeed");
    assert!(
        b.trace_events_inserted > 0,
        "peer B must persist the replicated trace, inserted={}",
        b.trace_events_inserted
    );
    assert_eq!(
        b.signatures_verified, 1,
        "peer B must verify the replicated trace against the cross-registered key"
    );

    // ── Anti gossip-loop: re-deliver to B → content-addressed idempotent merge ─
    let b2 = node_b
        .receive_and_persist(&bytes, &NullScrubber)
        .await
        .expect("re-delivery must not error");
    assert_eq!(
        b2.trace_events_inserted, 0,
        "re-delivered envelope must NOT double-insert (idempotent merge)"
    );
    assert!(
        b2.trace_events_conflicted > 0,
        "re-delivery must register as a dedup conflict, conflicted={}",
        b2.trace_events_conflicted
    );

    // ── Verify is real: node C REJECTS the envelope (agent key not admitted) ──
    // On the v6.8.1 triple, VerifyMode::Full rejects an unknown-key trace outright
    // (Err UnknownKey) rather than persisting it unverified — a stronger gate. A
    // node only replicates corpus signed under a key its directory trusts (in
    // prod: admitted via the founder-quorum door, src/quorum.rs).
    let c = node_c.receive_and_persist(&bytes, &NullScrubber).await;
    let err = c.expect_err("peer C must REJECT a trace signed under an unregistered key");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("UnknownKey"),
        "rejection must be an unknown-key verify failure, got: {msg}"
    );
}
