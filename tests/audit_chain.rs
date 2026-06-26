//! CIRISServer#110 conformance gate: the audit-log hash chain, clean + tampered
//! (D02/D23). The Rust-side equivalent of the agent's Python `test_320` that drives
//! `LensAudit` → `audit_verify_chain` — modeled on the `tests/alm_chain.rs` idiom:
//! drive the REAL pinned persist/verify crates Rust-to-Rust, assert the positive
//! (a clean chain verifies end-to-end), AND prove the negative (a single mutated
//! row must fail closed). The fail-closed half is the load-bearing property:
//! tamper-evidence is worthless if a corrupted row can pass `verify_chain`.
//!
//! Threat-model anchors (CIRISPersist THREAT_MODEL §4): AV-49 (record_entry
//! re-derives `entry_hash` and refuses a mismatched insert) + AV-50 (verify_chain
//! walks the chain end-to-end and surfaces the first break with a typed reason).
//!
//! What it proves against the pinned triple (edge v7.0.12 / persist v10.2.2 /
//! verify v7.5.0):
//!   1. GENESIS shape — a fresh tenant's `next_chain_position` is
//!      `(1, GENESIS_PREV_HASH)`; the first recorded entry carries seq==1 + the
//!      all-zero genesis prev_hash.
//!   2. CLEAN — record N>=3 self-signed entries chained via `next_chain_position`;
//!      `verify_chain(tenant, 1, None)` returns `ChainVerifyOutcome::Ok` and walked
//!      all N.
//!   3. TAMPER — mutate one STORED entry's payload (a raw second SQLite connection
//!      to the engine's file DB — record_entry validates + rejects, so a broken row
//!      can only be planted out-of-band, exactly as persist's own internal tamper
//!      test does) and assert `verify_chain` now reports
//!      `Break { reason: EntryHashMismatch, at_sequence: <the mutated seq> }`.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::audit::types::ChainBreakReason;
use ciris_persist::audit::verify::{
    canonical_bytes_for_entry, compute_entry_hash, truncate_to_micros,
};
use ciris_persist::audit::{AuditEntry, AuditService, ChainVerifyOutcome, GENESIS_PREV_HASH};
use ciris_persist::prelude::{Engine, LocalSigner};

const NODE_KEY_ID: &str = "audit-chain-node";

/// Build an in-process ciris-server [`Engine`] with a SOFTWARE hybrid signer over a
/// **file-backed** SQLite DB (mirrors `examples/qa_runner/common.rs::node()` minus
/// the node-self registration the audit surface doesn't need). A file DSN — not
/// `sqlite::memory:` — is mandatory: the tamper step opens a SECOND connection to
/// the same file, and an in-memory DB is private to the engine's own connection.
async fn engine_at(db_path: &str) -> Arc<Engine> {
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
    // DSN: persist strips the `sqlite:///` prefix INCLUDING the leading slash,
    // so an absolute path needs the `sqlite:///` scheme glued directly onto the
    // already-leading-`/` path (→ `sqlite:////abs/path`), which strips back to
    // the absolute `/abs/path`.
    Arc::new(
        Engine::with_signer(signer, &format!("sqlite:///{db_path}"))
            .await
            .expect("Engine::with_signer (file-backed sqlite)"),
    )
}

/// Build + self-sign one audit entry (actor_id IS the Ed25519 pubkey, the v0.7.1
/// self-signed identity model). Exactly the recipe persist's own internal test
/// (`engine.rs::audit_service_sqlite_round_trip`) uses:
///   1. `recorded_at` truncated to µs (Postgres TIMESTAMPTZ precision — a non-µs
///      timestamp would hash-mismatch on the post-storage round-trip).
///   2. `entry_hash` = sha256 of canonical(entry with entry_hash+signature zeroed).
///   3. `signature` = Ed25519 over canonical(entry minus the `signature` field) —
///      which INCLUDES the resolved `entry_hash`, binding the sig to chain position.
fn build_and_sign(
    key: &SigningKey,
    tenant: &str,
    sequence_number: i64,
    prev_hash: Vec<u8>,
    seq_marker: i64,
) -> AuditEntry {
    let mut entry = AuditEntry {
        entry_id: uuid::Uuid::new_v4().to_string(),
        sequence_number,
        tenant_id: tenant.to_owned(),
        actor_id: BASE64.encode(key.verifying_key().to_bytes()),
        action_type: "handler_action_task_complete".into(),
        subject_kind: "task".into(),
        subject_id: format!("subj-{seq_marker}"),
        payload: serde_json::json!({ "seq": seq_marker }),
        prev_hash,
        entry_hash: vec![],
        recorded_at: truncate_to_micros(chrono::Utc::now()),
        signature: String::new(),
    };
    entry.entry_hash = compute_entry_hash(&entry)
        .expect("compute entry_hash")
        .to_vec();
    let canonical = canonical_bytes_for_entry(&entry).expect("canonical bytes for signing");
    entry.signature = BASE64.encode(key.sign(&canonical).to_bytes());
    entry
}

/// Record `n` chained entries under `tenant`, sequencing each off the live
/// `next_chain_position` head (>=1, genesis prev_hash for the first). Returns the
/// `(sequence_number, prev_hash)` the FIRST (genesis) entry was built with so the
/// caller can assert the genesis shape.
async fn record_chain(
    audit: &Arc<ciris_persist::audit::sqlite::SqliteAuditBackend>,
    key: &SigningKey,
    tenant: &str,
    n: i64,
) -> (i64, Vec<u8>) {
    let mut genesis_shape = None;
    for marker in 1..=n {
        let pos = audit
            .next_chain_position(tenant)
            .await
            .expect("next_chain_position");
        if marker == 1 {
            genesis_shape = Some((pos.next_sequence_number, pos.prev_hash.to_vec()));
        }
        let entry = build_and_sign(
            key,
            tenant,
            pos.next_sequence_number,
            pos.prev_hash.to_vec(),
            marker,
        );
        audit.record_entry(entry).await.expect("record_entry");
    }
    genesis_shape.expect("at least one entry recorded")
}

#[tokio::test]
async fn audit_chain_verifies_clean_and_fails_on_tamper() {
    let dir = std::env::temp_dir().join(format!("ciris-audit-chain-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let db_path = dir.join("audit.db");
    let db_path_str = db_path.to_string_lossy().into_owned();

    let engine = engine_at(&db_path_str).await;
    // The `sqlite` backend is the one this conformance build pins (Cargo.toml
    // persist features include `sqlite`); destructure to the concrete backend so
    // we can call the `AuditService` trait methods (the dispatch enum is the
    // object-safe wrapper, not itself an `AuditService`).
    let audit = match engine.audit_service() {
        ciris_persist::AuditDispatch::Sqlite(b) => b,
        #[allow(unreachable_patterns)]
        _ => panic!("expected the sqlite audit backend for this gate"),
    };

    let actor = SigningKey::from_bytes(&[0xC3; 32]);
    let tenant = format!("audit-chain-{}", uuid::Uuid::new_v4().simple());
    const N: i64 = 4;

    // ── 1. record the chain + assert the GENESIS shape ───────────────────────
    let (genesis_seq, genesis_prev) = record_chain(&audit, &actor, &tenant, N).await;
    assert_eq!(genesis_seq, 1, "genesis sequence_number is 1");
    assert_eq!(
        genesis_prev,
        GENESIS_PREV_HASH.to_vec(),
        "genesis prev_hash is the all-zero sentinel"
    );

    // ── 2. CLEAN: verify_chain walks all N and reports Ok ────────────────────
    let clean = audit
        .verify_chain(&tenant, 1, None)
        .await
        .expect("verify_chain (clean)");
    assert_eq!(
        clean.outcome,
        ChainVerifyOutcome::Ok,
        "a clean chain must verify; got {:?}",
        clean.outcome
    );
    assert_eq!(
        clean.entries_walked, N as usize,
        "verify_chain must walk every recorded entry"
    );

    // ── 3. TAMPER: corrupt one STORED row, assert verify FAILS closed ────────
    // record_entry re-derives entry_hash + rejects a mismatch (AV-49), so a
    // tampered row cannot be inserted through the trait — it must be planted
    // out-of-band, exactly as persist's own internal tamper test does. We open
    // a SECOND rusqlite connection to the engine's file DB and UPDATE the
    // payload of seq 2; the stored entry_hash no longer matches the canonical
    // bytes, so the chain walk surfaces EntryHashMismatch at that sequence.
    const TAMPERED_SEQ: i64 = 2;
    {
        let conn = rusqlite::Connection::open(&db_path).expect("open tamper connection");
        // WAL is the engine's journal mode; share it + a busy timeout so the
        // write commits against the live DB the engine reads back.
        conn.busy_timeout(std::time::Duration::from_secs(30))
            .expect("busy_timeout");
        let updated = conn
            .execute(
                "UPDATE cirislens_audit_log SET payload = ?1 \
                 WHERE tenant_id = ?2 AND sequence_number = ?3",
                rusqlite::params![
                    serde_json::to_string(&serde_json::json!({ "TAMPERED": true })).unwrap(),
                    &tenant,
                    TAMPERED_SEQ,
                ],
            )
            .expect("tamper UPDATE");
        assert_eq!(updated, 1, "exactly one row tampered");
    }

    let tampered = audit
        .verify_chain(&tenant, 1, None)
        .await
        .expect("verify_chain (tampered)");
    match tampered.outcome {
        ChainVerifyOutcome::Break {
            at_sequence,
            reason,
            ..
        } => {
            assert_eq!(
                at_sequence, TAMPERED_SEQ,
                "the break must land on the mutated entry"
            );
            assert_eq!(
                reason,
                ChainBreakReason::EntryHashMismatch,
                "a mutated payload must surface as EntryHashMismatch"
            );
        }
        ChainVerifyOutcome::Ok => {
            panic!("FAIL-CLOSED VIOLATED: verify_chain returned Ok over a tampered row")
        }
    }

    drop(engine);
    let _ = std::fs::remove_dir_all(&dir);
}
