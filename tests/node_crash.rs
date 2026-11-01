//! **Crash scenarios the embedded node must survive** (steward 2026-11-01:
//! "we test for this scenario and any other common crash scenarios on ios and
//! android"). Each test here is a scenario a phone's OS inflicts on the node,
//! run against the real persist engine on a real file:
//!
//! 1. **Killed mid-write.** Android kills a backgrounded process under memory
//!    pressure with no callback
//!    (<https://developer.android.com/topic/performance/memory-management>);
//!    iOS jetsam does the same
//!    (<https://developer.apple.com/documentation/xcode/identifying-high-memory-use-with-jetsam-event-reports>).
//!    A child process writes in a loop and is SIGKILLed; the database must
//!    reopen intact with every acknowledged write present.
//! 2. **Restart from disk.** The OS relaunches the app (Android's sticky
//!    restart, an iOS background launch): a fresh engine on the same file sees
//!    what the last one committed.
//! 3. **The database cannot be opened.** On iOS, a file under data protection is
//!    unreadable while the device is locked, and a background launch can happen
//!    then (<https://developer.apple.com/documentation/uikit/protecting-the-user-s-privacy/encrypting-your-app-s-files>).
//!    Opening must fail with an error, never panic, and never replace the file.
//!
//! Backgrounding mid-pass is `tests/node_lifecycle.rs`. These are written to
//! run unchanged on the Android emulator and the iOS simulator
//! (`.github/workflows/mobile-node-lanes.yml`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord};
use ciris_persist::federation::SignedKeyRecord;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

const NODE_ALIAS: &str = "ciris-node-that-crashes";
/// Set in the child's environment: the directory it writes into.
const CHILD_DIR: &str = "CIRIS_CRASH_CHILD_DIR";

fn seed(label: &str, n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&Sha256::digest(format!("{label}:{n}").as_bytes())[..32]);
    s
}

fn signer_for(alias: &str) -> LocalSigner {
    let ed = SigningKey::from_bytes(&seed(alias, 1));
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&seed(alias, 2), format!("{alias}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        ed,
        alias.to_string(),
        Some(pqc),
        Some(format!("{alias}-pqc")),
    )
}

async fn register(engine: &Engine, signer: &LocalSigner, key_id: &str, ident: &str) {
    let mut envelope = serde_json::json!({ "key_id": key_id });
    let probe = signer.sign_hybrid(b"probe").await.expect("probe");
    let ed_pub = B64.encode(&probe.classical.public_key);
    let pqc_pub = B64.encode(&probe.pqc.public_key);
    ciris_persist::federation::admission::bind_subject_into_envelope(
        &mut envelope,
        key_id,
        ident,
        &ed_pub,
        Some(&pqc_pub),
        None,
    )
    .expect("bind subject (#659)");
    let canonical =
        ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope).expect("canon");
    let sig = signer.sign_hybrid(&canonical).await.expect("sign");
    let now = chrono::Utc::now();
    engine
        .register_federation_key(SignedKeyRecord {
            record: KeyRecord {
                key_id: key_id.to_string(),
                pubkey_ed25519_base64: ed_pub,
                pubkey_ml_dsa_65_base64: Some(pqc_pub),
                algorithm: algorithm::HYBRID.into(),
                identity_type: ident.to_string(),
                identity_ref: key_id.to_string(),
                valid_from: now,
                valid_until: None,
                registration_envelope: envelope,
                original_content_hash: hex::encode(Sha256::digest(&canonical)),
                scrub_signature_classical: B64.encode(&sig.classical.signature),
                scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
                scrub_key_id: key_id.to_string(),
                scrub_timestamp: now,
                pqc_completed_at: Some(now),
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .unwrap_or_else(|e| panic!("register {key_id}: {e}"));
}

/// A fresh directory per test: pid AND a counter, because the tests of one
/// binary run in parallel threads of one process. Removed on drop.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("ciris-node-crash-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp dir");
        Self(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Register a fresh key named `label-<fingerprint>` (CC 2.6.8: a key id ends
/// in its own key's fingerprint). Returns the registered id.
async fn register_fresh(engine: &Engine, label: &str) -> String {
    let signer = signer_for(label);
    let probe = signer.sign_hybrid(b"probe").await.expect("probe");
    let fp = ciris_persist::federation::register::key_id_fingerprint(
        &B64.encode(&probe.classical.public_key),
    )
    .expect("fingerprint");
    let key_id = format!("{label}-{fp}");
    register(engine, &signer, &key_id, identity_type::NODE).await;
    key_id
}

fn dsn(path: &std::path::Path) -> String {
    format!("sqlite:///{}", path.display())
}

async fn open(path: &std::path::Path) -> Result<Arc<Engine>, String> {
    Engine::with_signer(Arc::new(signer_for(NODE_ALIAS)), &dsn(path))
        .await
        .map(Arc::new)
        .map_err(|e| format!("{e:#}"))
}

fn keys_on_disk(path: &std::path::Path) -> i64 {
    let c = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open read-only");
    c.query_row(
        "SELECT count(*) FROM federation_keys WHERE key_id LIKE 'crash-key-%'",
        [],
        |r| r.get(0),
    )
    .expect("count")
}

fn integrity_ok(path: &std::path::Path) -> String {
    let c = rusqlite::Connection::open(path).expect("open");
    c.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
        .expect("integrity_check")
}

/// The child half of scenario 1: write key records forever, recording after
/// each acknowledged write how many have landed. Runs only when the parent
/// re-executes this binary with [`CHILD_DIR`] set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "the child of a_node_killed_mid_write_reopens_with_every_acknowledged_write"]
async fn crash_child_writer() {
    let Some(dir) = std::env::var_os(CHILD_DIR) else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let engine = open(&dir.join("node.db")).await.expect("child opens");
    for n in 0u32.. {
        register_fresh(&engine, &format!("crash-key-{n}")).await;
        std::fs::write(dir.join("acked"), (n + 1).to_string()).expect("ack");
    }
}

#[test]
fn a_node_killed_mid_write_reopens_with_every_acknowledged_write() {
    let dir = TempDir::new();
    let mut child = std::process::Command::new(std::env::current_exe().expect("exe"))
        .args(["--ignored", "--exact", "crash_child_writer", "--nocapture"])
        .env(CHILD_DIR, dir.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn the writer");
    let acked = || -> u64 {
        std::fs::read_to_string(dir.path().join("acked"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };
    let start = Instant::now();
    while acked() < 25 {
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "the writer acknowledged only {} writes in 120 s",
            acked()
        );
        assert!(
            child.try_wait().expect("poll").is_none(),
            "the writer exited early"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    // SIGKILL: no destructor, no flush, no callback — what the OS does.
    child.kill().expect("kill -9");
    let _ = child.wait();
    let acknowledged = acked();

    let db = dir.path().join("node.db");
    assert_eq!(
        integrity_ok(&db),
        "ok",
        "the database is intact after the kill"
    );
    let rows = keys_on_disk(&db);
    assert!(
        u64::try_from(rows).unwrap_or(0) >= acknowledged,
        "every acknowledged write survives the kill: {rows} on disk < {acknowledged} acknowledged"
    );
    // And the node itself opens on it.
    let rt = tokio::runtime::Runtime::new().expect("rt");
    rt.block_on(async {
        open(&db).await.expect("the engine reopens after the kill");
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_node_reads_what_the_last_one_committed() {
    let dir = TempDir::new();
    let db = dir.path().join("node.db");
    let key_id = {
        let engine = open(&db).await.expect("first life");
        register_fresh(&engine, "crash-key-restart").await
    };
    let engine = open(&db).await.expect("second life");
    let found = engine
        .federation_directory()
        .lookup_public_key(&key_id)
        .await
        .expect("lookup");
    assert!(
        found.is_some(),
        "the second life sees the first life's write"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unopenable_database_is_refused_never_replaced() {
    let dir = TempDir::new();
    // What a protected, locked file looks like to the process: bytes it cannot
    // read as a database. Opening must say so and leave them alone.
    let db = dir.path().join("node.db");
    let garbage = vec![0x5Au8; 64 * 1024];
    std::fs::write(&db, &garbage).expect("write");
    let r = open(&db).await;
    assert!(r.is_err(), "an unreadable database is refused, not opened");
    assert_eq!(
        std::fs::read(&db).expect("read back"),
        garbage,
        "the refused file is left byte-for-byte as it was"
    );

    // A file the process may not read at all (the locked-device case on unix).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let locked = dir.path().join("locked.db");
        {
            let e = open(&locked).await.expect("create");
            drop(e);
        }
        let before = std::fs::read(&locked).expect("read");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        // root reads anything; the check only means something when we cannot.
        if std::fs::File::open(&locked).is_err() {
            assert!(open(&locked).await.is_err(), "a locked database is refused");
        }
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(
            std::fs::read(&locked).expect("read"),
            before,
            "and left unchanged"
        );
    }
}
