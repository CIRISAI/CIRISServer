//! **A dedicated home means a dedicated post-quantum half** (CIRISServer#621).
//!
//! `--home` isolates the database, config, logs and the Ed25519 seed. It did not
//! isolate the ML-DSA-65 half: `create_federation_identity` seals that itself,
//! into the global `keys_dir()`, with no parameter for where (CIRISVerify#285).
//! A fresh mint therefore wrote globally, `sealed_keys_dir_for` found that
//! marker and kept using it, and two homes minting under the same alias shared
//! one file — so the promise an operator reads into `--home` was not true of the
//! half that makes the identity hybrid.
//!
//! `relocate_sealed_pqc_into_home` is what the server can do without that
//! parameter. The property under test is not "files moved" but **the identity
//! survived the move**: the seed IS the identity, and a relocation that quietly
//! re-minted would swap the PQC half for one no peer can verify, destroying the
//! original in the process (CIRISVerify#134). So every case here checks the
//! public key, not the file list.

use ciris_keyring::sealed_mldsa65::SealedMlDsa65Signer;
use ciris_keyring::PqcSigner as _;

/// A unique temp dir per case. pid ALONE is not isolation — cargo runs a file's
/// tests in parallel threads of ONE process, so every case would share it; the
/// counter is what separates them (CIRISServer, the keyring `.blob.tmp` race).
fn tmp(tag: &str) -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ciris-seal-home-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Seal a half under `alias` in `dir` from a known seed, and return its pubkey.
async fn seal(dir: &std::path::Path, alias: &str, seed: &[u8; 32]) -> Vec<u8> {
    std::fs::create_dir_all(dir).expect("create key store");
    let signer = SealedMlDsa65Signer::open_or_create(alias, dir, Some(seed))
        .expect("the deliberate first seal");
    signer.public_key().await.expect("public key")
}

fn home_keys(seed_dir: &std::path::Path) -> std::path::PathBuf {
    seed_dir
        .parent()
        .expect("seed dir has a parent")
        .join("keys")
}

/// The half moves, and it is the SAME key on the other side.
#[tokio::test]
async fn the_half_moves_and_stays_the_same_key() {
    let root = tmp("move");
    let seed_dir = root.join("identity").join("user");
    std::fs::create_dir_all(&seed_dir).expect("seed dir");
    let legacy = root.join("global-keys");
    // A distinctive alias per test process: the key store is keyed by alias and
    // a fixed one would collide between parallel runs.
    let alias = format!("relocate-{}-{}", std::process::id(), line!());

    let before = seal(&legacy, &alias, &[7u8; 32]).await;

    let landed =
        ciris_server::identity::relocate_sealed_pqc_into_home(&seed_dir, &alias, &legacy).await;

    assert_eq!(
        landed,
        home_keys(&seed_dir),
        "a mint into the global store must end up in THIS home's key store — that is the \
         whole point of --home for the post-quantum half"
    );
    let reopened = SealedMlDsa65Signer::open_existing(&alias, &landed)
        .expect("the relocated half must OPEN — load-only, never re-minting");
    assert_eq!(
        reopened.public_key().await.expect("public key"),
        before,
        "THE IDENTITY MUST SURVIVE THE MOVE. A different public key here means the half was \
         re-minted rather than relocated, which silently replaces a live identity with one \
         no peer can verify (CIRISVerify#134)."
    );
    assert!(
        SealedMlDsa65Signer::open_existing(&alias, &legacy).is_err(),
        "the global original must be GONE once the copy is proven — leaving it means two \
         homes under this alias still find it, which is the sharing this fixes"
    );
}

/// Nothing to move is not a failure, and must not disturb what is already home.
#[tokio::test]
async fn a_half_already_in_this_home_is_left_alone() {
    let root = tmp("athome");
    let seed_dir = root.join("identity").join("user");
    std::fs::create_dir_all(&seed_dir).expect("seed dir");
    let legacy = root.join("global-keys");
    std::fs::create_dir_all(&legacy).expect("legacy dir");
    let alias = format!("athome-{}-{}", std::process::id(), line!());

    let home = home_keys(&seed_dir);
    let before = seal(&home, &alias, &[9u8; 32]).await;

    let landed =
        ciris_server::identity::relocate_sealed_pqc_into_home(&seed_dir, &alias, &legacy).await;

    assert_eq!(
        landed, home,
        "an already-home half resolves to the home store"
    );
    assert_eq!(
        SealedMlDsa65Signer::open_existing(&alias, &home)
            .expect("still there")
            .public_key()
            .await
            .expect("public key"),
        before,
        "a no-op must be a NO-OP: re-sealing what is already here would mint a second half \
         for a live identity"
    );
}

/// A relocation that CANNOT COMPLETE leaves the original working.
///
/// The dangerous outcome is not "the move failed" — it is a move that removed
/// the original after putting down something that does not open. So this drives
/// a genuine failure (the home key store cannot be created: a FILE sits where
/// the directory must go) and asserts the global original is untouched and
/// still opens to the key it always had.
///
/// Note what this case is NOT: pre-placing a different half in the home store
/// would trip the "already home" short-circuit, and the relocation would return
/// before copying anything. That version of this test passed without ever
/// exercising a failure — a fixture whose hazards cancel proves nothing.
#[tokio::test]
async fn a_relocation_that_cannot_complete_leaves_the_original_working() {
    let root = tmp("blocked");
    let seed_dir = root.join("identity").join("user");
    std::fs::create_dir_all(&seed_dir).expect("seed dir");
    let legacy = root.join("global-keys");
    let alias = format!("blocked-{}-{}", std::process::id(), line!());

    let before = seal(&legacy, &alias, &[3u8; 32]).await;

    // A file where `<home>/identity/keys` must be: `create_dir_all` fails, so
    // the copy never starts. Works regardless of who the test runs as, unlike
    // a permission bit.
    let home = home_keys(&seed_dir);
    std::fs::write(&home, b"not a directory").expect("place the blocker");

    let landed =
        ciris_server::identity::relocate_sealed_pqc_into_home(&seed_dir, &alias, &legacy).await;

    assert_eq!(
        landed, legacy,
        "a relocation that could not complete must resolve to the store the half is \
         ACTUALLY in, or every later re-open looks in an empty directory"
    );
    assert_eq!(
        SealedMlDsa65Signer::open_existing(&alias, &legacy)
            .expect("the original must survive a failed relocation")
            .public_key()
            .await
            .expect("public key"),
        before,
        "the global original was modified or removed on a path that never proved a copy"
    );
}
