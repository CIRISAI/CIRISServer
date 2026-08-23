//! The **retention / eviction control loop** (CIRISServer#348) — proof that the
//! eviction stack lens-core has shipped since v0.4 now has a caller, and that the
//! caller behaves on the happy path.
//!
//! Three properties, in the order they can fail:
//!
//!   1. **The loop actually runs the primitives.** Ingest traces older than the
//!      configured cap, spawn the real controller loop, and watch the rows leave
//!      the store. Not "a pass returns the right enum" — the SPAWNED TASK, on its
//!      own cadence, driving `evict_per_retention_policy` into persist. That is
//!      the exact link that was missing: everything downstream of it was already
//!      written, tested, and green.
//!
//!   2. **The steady state is not an alarm.** A node inside its bounds evicts
//!      nothing on every pass forever. That pass must be AUDIBLE (a dead loop and
//!      a quiet one are indistinguishable — CIRISServer#315) and must not WARN
//!      (0.5.152 shipped a WARN on the scorer's happy path and 0.5.153 removed
//!      it; ~24,500 unactionable lines a day is how an operator learns to stop
//!      reading the log).
//!
//!   3. **An unbounded policy says so.** "Nothing to evict" and "nothing will
//!      ever be evicted" are opposite conditions and must not share a line.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use tokio::sync::watch;
use tracing::Level;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type};
use ciris_persist::federation::{FederationDirectory as _, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::schema::{
    CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion, TraceComponent, TraceLevel,
    WireDateTime,
};
use ciris_persist::scrub::NullScrubber;
use ciris_persist::verify::canonical::Canonicalizer;
use ciris_persist::verify::{ed25519::canonical_payload_value, PythonJsonDumpsCanonicalizer};

use ciris_server::config_reconcile::ResolvedConfig;
use ciris_server::retention_loop::{self, RetentionConfig, RetentionOutcome};

#[path = "support/log_capture.rs"]
mod log_capture;

const NODE_KEY_ID: &str = "node-retention";
const AGENT_KEY_ID: &str = "agent-retention";

// ── Substrate (mirrors tests/capacity_scorer.rs) ─────────────────────────────

async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node ML-DSA-65 seed"),
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

/// Register the agent's verifying key so trace verify resolves it at ingest.
async fn register_agent_key(engine: &Engine, ed_pubkey_b64: &str) {
    let now = chrono::Utc::now();
    let record = KeyRecord {
        key_id: AGENT_KEY_ID.to_string(),
        pubkey_ed25519_base64: ed_pubkey_b64.to_string(),
        pubkey_ml_dsa_65_base64: None,
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::AGENT.to_string(),
        identity_ref: AGENT_KEY_ID.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": AGENT_KEY_ID }),
        original_content_hash: "deadbeef".into(),
        scrub_signature_classical: ed_pubkey_b64.to_string(),
        scrub_signature_pqc: None,
        scrub_key_id: AGENT_KEY_ID.to_string(),
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
        .expect("register agent key in federation directory");
}

/// One signed `CompleteTrace` wire batch, stamped at `at`. The timestamp is the
/// point of the whole fixture — it is what the age cutoff decides on — so it is
/// a parameter rather than a constant buried in the builder.
fn trace_batch(
    agent_sk: &SigningKey,
    mldsa: &ciris_crypto::MlDsa65Signer,
    idx: usize,
    at: chrono::DateTime<chrono::Utc>,
) -> Vec<u8> {
    // The wire type keeps the ORIGINAL string alongside the parsed instant
    // (canonicalization signs the bytes, not the value), so the fixture has to
    // go through it rather than handing over a `DateTime`.
    let wire_at = WireDateTime::from_wire(at.to_rfc3339()).expect("rfc3339");
    let component = TraceComponent {
        component_type: ComponentType::Rationale,
        event_type: ReasoningEventType::DmaResults,
        timestamp: wire_at.clone(),
        data: {
            let mut m = serde_json::Map::new();
            m.insert(
                "csdma_plausibility_score".into(),
                serde_json::json!(0.5 + (idx as f64) * 0.01),
            );
            m
        },
        agent_id_hash: None,
    };
    let trace_id = format!("trace-retention-{idx:04}");
    let mut trace = CompleteTrace {
        trace_id: trace_id.clone(),
        thought_id: trace_id.clone(),
        task_id: Some("task-retention".into()),
        agent_id_hash: AGENT_KEY_ID.into(),
        started_at: wire_at.clone(),
        completed_at: wire_at,
        trace_level: TraceLevel::Generic,
        trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
        components: vec![component],
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

    serde_json::json!({
        "events": [{
            "event_type": "complete_trace",
            "trace_level": "generic",
            "trace": serde_json::to_value(&trace).expect("serialize trace"),
        }],
        "batch_timestamp": at.to_rfc3339(),
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
    })
    .to_string()
    .into_bytes()
}

/// Ingest `n` traces stamped `age_days` in the past. Returns the trace-event row
/// count persist reports afterwards.
async fn ingest_aged_traces(engine: &Engine, n: usize, age_days: i64) -> u64 {
    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    register_agent_key(engine, &BASE64.encode(agent_sk.verifying_key().to_bytes())).await;
    let mldsa = ciris_crypto::MlDsa65Signer::from_seed(&[0x77u8; 32]).expect("ml-dsa seed");
    let at = chrono::Utc::now() - chrono::Duration::days(age_days);
    for i in 0..n {
        engine
            .receive_and_persist(&trace_batch(&agent_sk, &mldsa, i, at), &NullScrubber)
            .await
            .expect("ingest synthetic trace");
    }
    trace_rows(engine).await
}

async fn trace_rows(engine: &Engine) -> u64 {
    engine
        .storage_summary()
        .await
        .expect("storage_summary")
        .trace_events
        .rows
}

/// A resolved config with the retention knobs set and everything else baked.
fn retention_config(cadence_secs: u64, max_age_days: u32) -> ResolvedConfig {
    ResolvedConfig {
        retention_cadence_secs: cadence_secs,
        retention_max_age_days: max_age_days,
        ..ResolvedConfig::default()
    }
}

// ── 1. The loop actually runs the primitives ─────────────────────────────────

/// **THE gate for CIRISServer#348.**
///
/// Not `run_pass` — the SPAWNED LOOP. Everything below the spawn was already
/// written and green before this cut; the defect was that `spawn` did not exist
/// and nothing called `evict_per_retention_policy`. So the assertion has to span
/// exactly that gap: start the controller, touch nothing else, and watch rows
/// leave the store on their own.
#[tokio::test]
async fn the_spawned_loop_evicts_aged_traces_on_its_cadence() {
    let engine = node().await;
    const N: usize = 5;
    let before = ingest_aged_traces(&engine, N, 3).await;
    assert!(
        before >= N as u64,
        "fixture: expected at least {N} aged trace rows, got {before}"
    );

    // 1s cadence, 1-day cap: the ingested traces are 3 days old, so the very
    // first tick must find them.
    let (config_tx, config_rx) = watch::channel(retention_config(1, 1));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let join = retention_loop::spawn(Arc::clone(&engine), config_rx, shutdown_rx);

    // Poll rather than sleep-a-fixed-amount: the assertion is "the loop gets
    // there", and a fixed sleep would encode a guess about scheduling as if it
    // were the property under test.
    let mut remaining = before;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        remaining = trace_rows(&engine).await;
        if remaining == 0 {
            break;
        }
    }
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
    drop(config_tx);

    assert_eq!(
        remaining, 0,
        "the spawned retention loop left {remaining} of {before} aged trace rows in the store \
         after 10s at a 1s cadence with a 1-day cap. Either the loop is not running its pass, or \
         the pass is not reaching lens-core's eviction stack — which is precisely the state \
         CIRISServer#348 describes: the primitives ship, correct and tested, with no caller."
    );
}

// ── 2. The steady state is not an alarm ──────────────────────────────────────

/// A bounded node with nothing old enough to evict: the pass must SPEAK (INFO)
/// and must not ALARM.
///
/// Both halves matter and they fail in opposite directions. Drop the INFO and a
/// stopped loop becomes indistinguishable from a working one. Raise it to WARN
/// and every healthy node cries wolf hourly — which is not a hypothetical here,
/// it is what 0.5.152 shipped on the scorer.
#[tokio::test]
async fn a_pass_with_nothing_to_evict_is_audible_and_not_an_alarm() {
    let engine = node().await;
    // Fresh traces: inside the 90-day default bound, so nothing is eligible.
    ingest_aged_traces(&engine, 3, 0).await;
    let cfg = RetentionConfig::from_resolved(&ResolvedConfig::default());

    let (outcome, log) = log_capture::capture(retention_loop::run_pass(&engine, &cfg)).await;
    let outcome = outcome.expect("a pass over a healthy store must not error");

    assert!(
        matches!(outcome, RetentionOutcome::WithinBounds { .. }),
        "a bounded store with nothing aged out must report WithinBounds, got {outcome:?}"
    );
    assert!(!outcome.is_fault(), "{outcome:?} must not be a fault");
    assert!(
        log.alarms().is_empty(),
        "the STEADY STATE raised {} alarm(s). An alarm on the happy path fires on every healthy \
         node on every cadence, and the operator who learns to skip it is the one who misses the \
         real one — 0.5.152, fixed in 0.5.153.\n{}",
        log.alarms().len(),
        log.render()
    );
    assert!(
        !log.at(Level::INFO).is_empty(),
        "the pass emitted no INFO line, so a node whose retention loop has DIED looks exactly \
         like one whose store is healthy. Silence is not a report.\n{}",
        log.render()
    );
}

/// The other zero. An unbounded policy evicts nothing for a completely different
/// reason, and must not be reported as a healthy sweep — but it is a legitimate
/// operator choice (a sovereign archive keeps everything), so it is still INFO.
#[tokio::test]
async fn an_unbounded_policy_names_itself_without_alarming() {
    let engine = node().await;
    let cfg = RetentionConfig::from_resolved(&retention_config(3600, 0));
    assert!(
        !cfg.policy.is_bounded(),
        "fixture: retention.max_age_days = 0 must resolve to an unbounded policy"
    );

    let (outcome, log) = log_capture::capture(retention_loop::run_pass(&engine, &cfg)).await;
    let outcome = outcome.expect("an unbounded pass must not error");

    assert_eq!(
        outcome,
        RetentionOutcome::Unbounded,
        "an unbounded policy must be its OWN outcome. Folded into WithinBounds, a node that will \
         grow until the disk fills reports the same line as one that is comfortably inside its \
         bounds — and the two are opposite conditions."
    );
    assert!(!outcome.is_fault());
    assert!(
        log.alarms().is_empty(),
        "declining to bound the store is an allowed choice, not a fault.\n{}",
        log.render()
    );
    assert!(
        !log.at(Level::INFO).is_empty(),
        "an unbounded node must still say so once a cadence — it is the one zero that is worth \
         acting on.\n{}",
        log.render()
    );
}

// ── 3. An evicting pass reports what it removed ──────────────────────────────

/// The acting path, driven deterministically through `run_pass`: the outcome
/// must carry the count, and doing the job it was configured to do is still not
/// an alarm.
#[tokio::test]
async fn an_evicting_pass_reports_the_count_and_is_not_an_alarm() {
    let engine = node().await;
    const N: usize = 4;
    let before = ingest_aged_traces(&engine, N, 3).await;
    let cfg = RetentionConfig::from_resolved(&retention_config(3600, 1));

    let (outcome, log) = log_capture::capture(retention_loop::run_pass(&engine, &cfg)).await;
    let outcome = outcome.expect("an evicting pass must not error");

    match outcome {
        RetentionOutcome::Evicted {
            evicted_traces: n, ..
        } => assert_eq!(
            n as u64, before,
            "the outcome must carry the real count — it is the only signal that the pass did \
             work, since `freed_bytes_estimate` is routinely 0 on SQLite (deleted pages go on \
             the freelist and PRAGMA page_count does not fall without a VACUUM)"
        ),
        other => panic!("{N} traces 3 days old under a 1-day cap must evict, got {other:?}"),
    }
    assert!(
        log.alarms().is_empty(),
        "eviction performing exactly its configured duty is not a fault.\n{}",
        log.render()
    );
    assert_eq!(
        trace_rows(&engine).await,
        0,
        "the aged rows must actually be gone from the store"
    );
}

/// **Exactly one outcome is a fault, and it is the one where a bound cannot
/// bite** (CIRISServer#476).
///
/// The enum's doc used to promise `is_fault()` was constant `false` — a guard
/// against someone adding alarm to a happy path. #476 found a state that arm
/// list could not express: a configured disk cap, EXCEEDED, with no lever that
/// reaches the bytes. Production reported that as "steady state, not a fault"
/// every hour while the store grew.
///
/// This pins both halves of the corrected invariant, because a fault that
/// spreads to the healthy arms is just as useless as one that never fires.
#[test]
fn only_an_unenforceable_bound_is_a_fault() {
    use ciris_server::retention_loop::RetentionOutcome;

    assert!(
        !RetentionOutcome::Unbounded.is_fault(),
        "an operator who configured no bound made a choice, not a mistake"
    );
    assert!(!RetentionOutcome::WithinBounds {
        trace_rows: 96_265,
        oldest_trace: None,
        total_disk_bytes: 1_264_021_504,
    }
    .is_fault());
    assert!(!RetentionOutcome::Evicted {
        evicted_traces: 1_000,
        archived_audit_entries: 0,
        freed_bytes_estimate: 0,
        total_disk_bytes: 1_000_000,
    }
    .is_fault());

    // The measured shape: 389 MB over a 1 GB cap's trigger, nothing reachable.
    assert!(
        RetentionOutcome::BoundUnenforceable {
            used_bytes: 2_000_000_000,
            cap_bytes: 1_000_000_000,
            evictable_rows: 0,
        }
        .is_fault(),
        "a configured bound that cannot act MUST alarm — silence here is what \
         let ciris-status pass its cap unnoticed"
    );
}

// ── 5. The alarm reaches health, and comes back down ─────────────────────────

/// The degradation registry is a PROCESS-GLOBAL and libtest runs these cases in
/// parallel threads of one process, so one case's `raise` lands inside another's
/// window. Caught by construction here rather than by a flake: both cases below
/// raise the SAME code and then assert it is gone, which is exactly the pair
/// that interleaves into a false failure. `src/degradation.rs` carries the same
/// lock for the same reason, and `oauth_state_matrix.rs` records the first time
/// this repo paid for a leaked global.
static REGISTRY_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// **A retention fault must be visible where someone is looking**, and a
/// recovered node must stop shouting (CIRISServer#446).
///
/// The ERROR line `run_pass` emits goes to a log nobody tails. The half that
/// matters for an operator on a phone is `GET /v1/node/health`, and the half
/// that matters for whether they ever trust it again is that a fixed node
/// clears. A warning that only ever goes up is one people learn to skip — the
/// same silence #476 set out to fix, approached from the other side.
///
/// Driven through the real `run_pass` rather than by calling `clear` directly,
/// because the defect this guards against is a future arm that returns early
/// and skips the clear.
#[tokio::test]
async fn a_healthy_pass_takes_a_standing_retention_alarm_down() {
    let _registry = REGISTRY_LOCK.lock().await;
    // Start from a known state for THIS code specifically — `reset_for_test`
    // is deliberately not public, so a test clears exactly what it asserts on
    // rather than being handed a lever that empties a live node's health.
    ciris_server::degradation::clear("retention.bound_unenforceable");
    let engine = node().await;
    ingest_aged_traces(&engine, 3, 0).await;

    // Pretend a previous pass found the bound unenforceable.
    ciris_server::degradation::raise(ciris_server::degradation::Warning::error(
        "retention.bound_unenforceable",
        "a bound from a previous pass that has since been fixed",
    ));
    assert!(
        ciris_server::degradation::degraded_mode(),
        "fixture: the node must start this test degraded"
    );

    let cfg = RetentionConfig::from_resolved(&ResolvedConfig::default());
    let outcome = retention_loop::run_pass(&engine, &cfg)
        .await
        .expect("a healthy pass must not error");
    assert!(!outcome.is_fault(), "fixture: {outcome:?} must be healthy");

    let standing: Vec<String> = ciris_server::degradation::snapshot()
        .into_iter()
        .map(|w| w.code)
        .collect();
    assert!(
        !standing.contains(&"retention.bound_unenforceable".to_string()),
        "the store is inside every bound and the node is STILL reporting an unenforceable \
         cap. A stale alarm is worse than no alarm: it trains the operator to ignore the \
         real one. Standing: {standing:?}"
    );
}

/// The unbounded arm returns EARLY, before the store is even read — so it needs
/// its own clear, and this is the test that would catch its absence.
///
/// Clearing here is not reassurance. An unbounded store still grows and the
/// INFO line says so; it is refusing to leave standing a claim ("the configured
/// bound cannot bite") that stops being true the moment there is no configured
/// bound.
#[tokio::test]
async fn the_early_unbounded_return_also_clears() {
    let _registry = REGISTRY_LOCK.lock().await;
    // Start from a known state for THIS code specifically — `reset_for_test`
    // is deliberately not public, so a test clears exactly what it asserts on
    // rather than being handed a lever that empties a live node's health.
    ciris_server::degradation::clear("retention.bound_unenforceable");
    let engine = node().await;
    ciris_server::degradation::raise(ciris_server::degradation::Warning::error(
        "retention.bound_unenforceable",
        "raised while a cap was configured; the operator has since removed it",
    ));

    let cfg = RetentionConfig::from_resolved(&retention_config(3600, 0));
    let outcome = retention_loop::run_pass(&engine, &cfg)
        .await
        .expect("an unbounded pass must not error");
    assert_eq!(outcome, RetentionOutcome::Unbounded, "fixture");

    let standing: Vec<String> = ciris_server::degradation::snapshot()
        .into_iter()
        .map(|w| w.code)
        .collect();
    assert!(
        !standing.contains(&"retention.bound_unenforceable".to_string()),
        "the unbounded path returns before the sweep and skipped the clear, so removing a \
         cap leaves the node permanently degraded. Standing: {standing:?}"
    );
}
