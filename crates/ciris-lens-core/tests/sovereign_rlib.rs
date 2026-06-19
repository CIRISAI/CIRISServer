//! CIRISLensCore#17 — Sovereign-mode rlib-parity rehearsal.
//!
//! **Gate:** proves that the lens-core rlib surface (`CaptureClient` + its
//! typed dependencies) works end-to-end from Rust with NO `python` feature
//! (`pyo3` dep absent). The PoB §3.1 fold links lens-core as an rlib and
//! constructs `LensCore::client(...)` directly from Rust; this test
//! rehearses that path at its current (v0.4.x) CaptureClient level.
//!
//! # What this proves (FSD LENS_CORE_V0_5 §7)
//!
//! 1. `Engine::with_signer` + `"sqlite::memory:"` — in-memory substrate
//!    round-trip, no file I/O, no Python.
//! 2. `CaptureClient::new(...)` via the typed Rust constructor — all nine
//!    parameters, no `PyO3` wrapper.
//! 3. `capture_event(THOUGHT_START)` → `Opened`.
//! 4. `capture_event(ACTION_RESULT)` → `SealedAndPersisted { trace_id,
//!    summary }` with `summary.trace_events_inserted > 0`.
//! 5. `signatures_verified` finding — documented below.
//! 6. `orphan_sweep(now, 3600)` → `0` (trace sealed, no orphans).
//! 7. Consent gate: `consent_timestamp = None` → `ConsentBlocked { reason:
//!    "no_consent" }` from the rlib path.
//!
//! # signatures_verified finding (#17)
//!
//! `Engine::receive_and_persist` runs `VerifyMode::Full`, which calls
//! `FederationDirectory::lookup_public_key(signing_key_id)` to verify the
//! trace signature. `Engine::with_signer(signer, "sqlite::memory:")` does
//! NOT auto-register the signer's public key in the `federation_keys`
//! table — the Engine uses that signer for *scrub-envelope* signing, not as
//! a known federation peer.
//!
//! Consequence: when the trace is signed under key `"sovereign-rlib-key"` and
//! that key_id is absent from `federation_keys`, `lookup_public_key` returns
//! `None` → the ingest pipeline treats it as `UnknownKey` → the trace is
//! persisted (rows land) but `signatures_verified = 0`.
//!
//! This test registers the key via
//! `FederationDirectory::put_public_key(SignedKeyRecord{...})` on the
//! SQLite backend BEFORE calling `capture_event`, so `signatures_verified`
//! is `1` and is asserted as such.
//!
//! # #17 rlib-ergonomics gap finding
//!
//! No gaps found. Every type the sovereign path needs is public and
//! re-exported:
//! - `ciris_lens_core::capture::{CaptureClient, CaptureEventOutcome,
//!   ConsentConfig, InboundEvent}` — all `pub` via `capture/mod.rs`.
//! - `ciris_persist::prelude::{Engine, LocalSigner}` — `pub` in persist's
//!   prelude re-export.
//! - `ciris_persist::scrub::NullScrubber` — `pub` in persist's scrub module.
//! - `ciris_persist::federation::{FederationDirectory, KeyRecord,
//!   SignedKeyRecord}` — `pub` re-exports in persist's federation module.
//! - `ed25519_dalek::SigningKey` — a normal dependency, `pub`.
//!
//! # Sovereign `cargo test` invocation
//!
//! ```bash
//! cargo test --test sovereign_rlib
//! ```
//!
//! The `python` feature is NOT enabled. The `sqlite` feature is inherited
//! from `ciris-persist`'s transitive feature set (persist is declared with
//! `features = ["extract", "sqlite"]` in lens-core's `Cargo.toml`), so
//! `Engine::with_signer` + `engine.sqlite_backend()` are both available
//! without any explicit `--features` flag on the integration test invocation.
//! `cargo build --no-default-features` confirms the rlib compiles cleanly
//! with no PyO3 dep.

use std::sync::Arc;

use chrono::Utc;
use ed25519_dalek::SigningKey;
use serde_json::json;

use ciris_lens_core::capture::{CaptureClient, CaptureEventOutcome, ConsentConfig, InboundEvent};
use ciris_persist::federation::types::{algorithm, identity_type};
use ciris_persist::federation::{FederationDirectory as _, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::scrub::NullScrubber;

// ── Helper: deterministic signer ────────────────────────────────────────────

fn test_signer(seed: u8, key_id: &str) -> Arc<LocalSigner> {
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    // Configure the ML-DSA-65 (PQC) half so the Engine can hybrid-sign
    // traces. persist's trace-tier hard cut (CIRISPersist#225,
    // VerifyMode::Full → verify_trace_hybrid under HybridPolicy::Strict)
    // REJECTS a classical-only trace at admission, so a sovereign client
    // that means to persist MUST carry an ML-DSA-65 identity. Deterministic
    // seed for reproducibility.
    let pqc_signer = ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(
        &[seed.wrapping_add(1); 32],
        format!("{key_id}-pqc"),
    )
    .expect("ml-dsa seed length checked");
    Arc::new(LocalSigner::from_parts(
        signing_key,
        key_id.to_string(),
        Some(Arc::new(pqc_signer) as Arc<dyn ciris_keyring::PqcSigner>),
        Some(format!("{key_id}-pqc")),
    ))
}

// ── Helper: 2.7.9 deployment profile ────────────────────────────────────────

fn deployment_profile() -> serde_json::Value {
    json!({
        "agent_role": "ally",
        "agent_template": "ally-default",
        "deployment_domain": "general",
        "deployment_type": "production",
        "deployment_region": null,
        "deployment_trust_mode": "sovereign",
    })
}

// ── Helper: InboundEvent ──────────────────────────────────────────────────────

fn inbound(event_type: &str, thought_id: &str, ts: &str) -> InboundEvent {
    InboundEvent {
        event_type: event_type.into(),
        thought_id: thought_id.into(),
        task_id: Some("task-sovereign-1".into()),
        agent_id_hash: "deadbeef".into(),
        timestamp: ts.into(),
        trace_level: Some("generic".into()),
        data: json!({ "sovereign_rlib": true }),
    }
}

// ── register_key_in_directory ────────────────────────────────────────────────

/// Register an Ed25519 public key (from a `LocalSigner`) into the Engine's
/// SQLite `federation_keys` table so `VerifyMode::Full` can resolve it.
///
/// Uses the public `FederationDirectory::put_public_key` API — no raw SQL,
/// no `rusqlite` dep in lens-core. The `scrub_signature_classical` field
/// accepts any non-empty base64 string (persist's write path stores it; the
/// read-side verify for scrub-envelopes is a separate flow).
///
/// `LocalSigner::public_key_b64()` is the public accessor for the Ed25519
/// verifying key. `LocalSigner::signing_key()` is `pub(crate)` and is NOT
/// accessible from integration tests — this is an **rlib ergonomics gap**
/// documented as a #17 finding: there is no public API to obtain the raw
/// `[u8; 32]` signing-key seed from a `LocalSigner`, only the public
/// `public_key_b64()` string accessor. For registration purposes
/// `public_key_b64()` is sufficient.
async fn register_key_in_directory(engine: &Engine, signer: &LocalSigner) {
    let pubkey_b64 = signer.public_key_b64();
    let key_id = signer.key_id().to_owned();
    let now = Utc::now();

    let record = KeyRecord {
        key_id: key_id.clone(),
        pubkey_ed25519_base64: pubkey_b64.clone(),
        pubkey_ml_dsa_65_base64: None,
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::AGENT.into(),
        identity_ref: key_id.clone(),
        valid_from: now,
        valid_until: None,
        // Bootstrap self-signed pattern: registration_envelope carries
        // the key_id; original_content_hash + scrub fields are minimal
        // valid placeholders (persist stores them; scrub-sig verification
        // runs separately from trace-sig verification).
        registration_envelope: json!({ "key_id": key_id }),
        original_content_hash: "deadbeef".into(),
        scrub_signature_classical: pubkey_b64, // non-empty base64
        scrub_signature_pqc: None,
        scrub_key_id: key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(), // server-computed on write
        roles: Vec::new(),
        attestation_evidence: None,
    };

    let sq = engine
        .sqlite_backend()
        .expect("sqlite backend must be present");
    sq.put_public_key(SignedKeyRecord { record })
        .await
        .expect("register key in federation directory");
}

// ── Test 1: sovereign_rlib_end_to_end ────────────────────────────────────────
//
// Full end-to-end happy-path:
//  - THOUGHT_START → Opened
//  - ACTION_RESULT → SealedAndPersisted (trace_events_inserted > 0,
//    signatures_verified == 1 because we pre-register the key)
//  - orphan_sweep → 0 (trace sealed, not orphaned)

#[tokio::test]
async fn sovereign_rlib_end_to_end() {
    let signer = test_signer(0xAB, "sovereign-rlib-key");
    let engine = Engine::with_signer(signer.clone(), "sqlite::memory:")
        .await
        .expect("Engine::with_signer must succeed with in-memory SQLite");
    let engine = Arc::new(engine);

    // Register the signing key so VerifyMode::Full resolves it and
    // signatures_verified == 1 (not 0). See module-level doc for the
    // signatures_verified finding.
    register_key_in_directory(&engine, &signer).await;

    // Construct CaptureClient via the pure-Rust rlib API — no PyO3.
    //
    // CaptureClient::new signature (verified from src/capture/client.rs):
    //   fn new(
    //       engine: Arc<Engine>,
    //       scrubber: Arc<dyn Scrubber + Send + Sync>,
    //       trace_level: String,
    //       trace_schema_version: String,
    //       correlation: Option<CorrelationMetadata>,
    //       consent_attesting_key_id: Option<String>,
    //       consent_config: ConsentConfig,
    //       deployment_profile: Option<serde_json::Value>,
    //       local_copy_dir: Option<PathBuf>,
    //   ) -> Self
    let client = CaptureClient::new(
        engine.clone(),
        Arc::new(NullScrubber),
        "generic".into(), // trace_level
        "2.7.9".into(),   // trace_schema_version
        None,             // correlation
        None,             // consent_attesting_key_id (2.9.6 interim path)
        ConsentConfig {
            consent_timestamp: Some("2026-01-01T00:00:00Z".into()),
        },
        Some(deployment_profile()), // deployment_profile (required at 2.7.9)
        None,                       // local_copy_dir
    );

    // Step 1: THOUGHT_START → Opened
    let out = client
        .capture_event(inbound(
            "THOUGHT_START",
            "thought-sovereign-1",
            "2026-06-01T00:00:00Z",
        ))
        .await
        .expect("capture_event THOUGHT_START must not error");

    assert!(
        matches!(out, CaptureEventOutcome::Opened),
        "THOUGHT_START must yield Opened, got: {out:?}",
    );

    // Step 2: ACTION_RESULT → SealedAndPersisted
    let out = client
        .capture_event(inbound(
            "ACTION_RESULT",
            "thought-sovereign-1",
            "2026-06-01T00:00:02Z",
        ))
        .await
        .expect("capture_event ACTION_RESULT must not error");

    let (trace_id, summary) = match out {
        CaptureEventOutcome::SealedAndPersisted { trace_id, summary } => (trace_id, summary),
        other => panic!("ACTION_RESULT must yield SealedAndPersisted, got: {other:?}"),
    };

    assert_eq!(
        trace_id, "thought-sovereign-1",
        "trace_id must match thought_id"
    );
    assert!(
        summary.trace_events_inserted > 0,
        "trace_events_inserted must be > 0, got {}",
        summary.trace_events_inserted,
    );

    // Step 3: signatures_verified finding.
    //
    // Because we pre-registered the signing key via put_public_key above,
    // VerifyMode::Full resolves the key and verifies the Ed25519 trace
    // signature → signatures_verified == 1.
    //
    // If this assertion starts failing (== 0), it means the key registration
    // step is broken or the Engine's trace-signing key_id doesn't match
    // the registered key_id — investigate register_key_in_directory().
    assert_eq!(
        summary.signatures_verified, 1,
        "signatures_verified must be 1 (key pre-registered in federation_directory); \
         if 0, the federation directory did not find the key — check key_id match \
         between LocalSigner::key_id() and the registered KeyRecord.key_id",
    );

    // Step 4: orphan_sweep → 0 (trace was sealed, no in-flight orphans)
    let purged = client.orphan_sweep(Utc::now(), 3600).await;
    assert_eq!(
        purged, 0,
        "orphan_sweep must return 0 after the only trace was sealed",
    );
}

// ── Test 2: sovereign_rlib_consent_gate ──────────────────────────────────────
//
// Proves the consent gate works via the rlib path:
// consent_attesting_key_id=None + consent_config{consent_timestamp:None}
// → capture_event on a sealing (ACTION_RESULT) event
// → ConsentBlocked { reason: "no_consent" }
//
// No emission; no persist. The rlib consent gate enforces privacy even
// without Python.

#[tokio::test]
async fn sovereign_rlib_consent_gate() {
    let signer = test_signer(0xCD, "sovereign-consent-key");
    let engine = Engine::with_signer(signer.clone(), "sqlite::memory:")
        .await
        .expect("Engine::with_signer must succeed");
    let engine = Arc::new(engine);

    // Client with no consent configured — both attesting key and
    // config timestamp are absent.
    let client = CaptureClient::new(
        engine.clone(),
        Arc::new(NullScrubber),
        "generic".into(),
        "2.7.9".into(),
        None,
        None, // consent_attesting_key_id = None (config-only path)
        ConsentConfig {
            consent_timestamp: None, // no consent configured
        },
        Some(deployment_profile()),
        None,
    );

    // Open a trace first (THOUGHT_START → Opened; consent not checked until seal)
    let open_out = client
        .capture_event(inbound(
            "THOUGHT_START",
            "thought-no-consent",
            "2026-06-01T00:00:00Z",
        ))
        .await
        .expect("THOUGHT_START must not error even without consent");
    assert!(
        matches!(open_out, CaptureEventOutcome::Opened),
        "THOUGHT_START must open a trace, got: {open_out:?}",
    );

    // ACTION_RESULT seals → consent gate fires → ConsentBlocked
    let seal_out = client
        .capture_event(inbound(
            "ACTION_RESULT",
            "thought-no-consent",
            "2026-06-01T00:00:02Z",
        ))
        .await
        .expect("capture_event must not error even when consent is blocked");

    match seal_out {
        CaptureEventOutcome::ConsentBlocked { reason } => {
            assert_eq!(
                reason, "no_consent",
                "reason must be 'no_consent' when no consent is configured",
            );
        }
        other => panic!("expected ConsentBlocked {{ reason: \"no_consent\" }}, got: {other:?}",),
    }
}
