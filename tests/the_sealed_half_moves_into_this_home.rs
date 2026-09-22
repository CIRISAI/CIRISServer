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

/// The three cases, decided from the two directories and nothing else.
///
/// This is the whole safety argument in one assertion: after
/// `create_federation_identity` has run you cannot tell a half it minted from
/// one that was already there, because `open_or_create` does not say which it
/// did. Everything below depends on this being decided FIRST.
#[test]
fn the_plan_is_decided_from_what_is_on_disk_before_the_mint() {
    use ciris_server::identity::{plan_sealed_half, SealedHalfPlan};
    let root = tmp("plan");
    let seed_dir = root.join("identity").join("user");
    std::fs::create_dir_all(&seed_dir).expect("seed dir");
    let legacy = root.join("global-keys");
    std::fs::create_dir_all(&legacy).expect("legacy dir");
    let alias = "planned";

    assert_eq!(
        plan_sealed_half(&seed_dir, alias, &legacy),
        SealedHalfPlan::CreatorWillMint,
        "nothing sealed anywhere: what the creator mints belongs to this mint"
    );

    std::fs::write(legacy.join(format!("{alias}.mldsa65.seed.blob")), b"x").expect("legacy blob");
    assert_eq!(
        plan_sealed_half(&seed_dir, alias, &legacy),
        SealedHalfPlan::LeaveLegacy,
        "a half in the global store that this home does not have predates home scoping — \
         another home may resolve through it, so it is NOT ours to move"
    );

    std::fs::create_dir_all(home_keys(&seed_dir)).expect("home dir");
    std::fs::write(
        home_keys(&seed_dir).join(format!("{alias}.mldsa65.seed.blob")),
        b"y",
    )
    .expect("home blob");
    assert_eq!(
        plan_sealed_half(&seed_dir, alias, &legacy),
        SealedHalfPlan::ReuseHome,
        "this home already holds it: the creator must be handed OUR key, not left to mint a \
         second one"
    );

    // The degenerate shape: a seed dir whose sibling `keys` IS the global store,
    // which is what an un-homed node looks like. `home_keys_dir` derives
    // `<parent>/keys`, so the two coincide only when the global store is that
    // directory — nothing to decide, and nothing to move.
    let unhomed_root = tmp("unhomed");
    let unhomed_seed = unhomed_root.join("user");
    let unhomed_keys = unhomed_root.join("keys");
    std::fs::create_dir_all(&unhomed_seed).expect("seed dir");
    std::fs::create_dir_all(&unhomed_keys).expect("keys dir");
    assert_eq!(
        plan_sealed_half(&unhomed_seed, alias, &unhomed_keys),
        SealedHalfPlan::NotApplicable,
        "home and global being the same directory is nothing to decide"
    );
}

/// The half this mint created moves, and it is the SAME key on the other side.
#[tokio::test]
async fn the_half_moves_and_stays_the_same_key() {
    use ciris_server::identity::SealedHalfPlan;
    let root = tmp("move");
    let seed_dir = root.join("identity").join("user");
    std::fs::create_dir_all(&seed_dir).expect("seed dir");
    let legacy = root.join("global-keys");
    let alias = format!("relocate-{}-{}", std::process::id(), line!());

    // The order the real call site follows: plan (nothing anywhere), then the
    // creator seals globally, then settle.
    let before = seal(&legacy, &alias, &[7u8; 32]).await;

    let landed = ciris_server::identity::relocate_sealed_pqc_into_home(
        &seed_dir,
        &alias,
        &legacy,
        SealedHalfPlan::CreatorWillMint,
    )
    .await;

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

/// **A half that predates home scoping is never moved.**
///
/// The dangerous case, and the reason the plan exists. An identity created
/// before home scoping lives in the global store and its home resolves through
/// it. A SECOND `--home` minting the same alias makes
/// `create_federation_identity` OPEN that half rather than mint one — and a
/// relocation that could not tell the difference would move it and delete the
/// original, leaving the first home with neither a local nor a global half and
/// an established identity that can no longer sign.
#[tokio::test]
async fn a_legacy_half_another_home_may_use_is_never_moved() {
    use ciris_server::identity::{plan_sealed_half, SealedHalfPlan};
    let root = tmp("legacy");
    let seed_dir = root.join("identity").join("user");
    std::fs::create_dir_all(&seed_dir).expect("seed dir");
    let legacy = root.join("global-keys");
    let alias = format!("prehome-{}-{}", std::process::id(), line!());

    let established = seal(&legacy, &alias, &[11u8; 32]).await;
    let plan = plan_sealed_half(&seed_dir, &alias, &legacy);
    assert_eq!(
        plan,
        SealedHalfPlan::LeaveLegacy,
        "the fixture must be the legacy case"
    );

    let landed =
        ciris_server::identity::relocate_sealed_pqc_into_home(&seed_dir, &alias, &legacy, plan)
            .await;

    assert_eq!(
        landed, legacy,
        "the resolution must keep pointing at the store the half is actually in"
    );
    assert_eq!(
        SealedMlDsa65Signer::open_existing(&alias, &legacy)
            .expect("THE OTHER HOME'S IDENTITY MUST STILL OPEN")
            .public_key()
            .await
            .expect("public key"),
        established,
        "the pre-home-scoping half was moved or altered — the home that was resolving \
         through it can no longer sign, which is worse than never isolating it"
    );
    assert!(
        !home_keys(&seed_dir)
            .join(format!("{alias}.mldsa65.seed.blob"))
            .exists(),
        "nothing may be copied into this home either: a second copy of a live PQC half is \
         the duplication the occurrence model exists to prevent"
    );
}

/// **A retried provision reuses this home's half, and takes the staging down.**
///
/// `POST /v1/self/identity` is documented as repeatable. Once the first call has
/// relocated the half into this home, the global store is empty — so a second
/// call would have the creator mint a FRESH global half, build the CEG object
/// and fedcode from it, and leave the response and every later signer
/// resolution using the old home key: an identity that disagrees with itself.
/// Staging the home half for the creator is what keeps the operation idempotent.
#[tokio::test]
async fn a_retried_mint_reuses_this_homes_half() {
    use ciris_server::identity::{plan_sealed_half, stage_home_half_into, SealedHalfPlan};
    let root = tmp("retry");
    let seed_dir = root.join("identity").join("user");
    std::fs::create_dir_all(&seed_dir).expect("seed dir");
    let legacy = root.join("global-keys");
    std::fs::create_dir_all(&legacy).expect("legacy dir");
    let alias = format!("retried-{}-{}", std::process::id(), line!());

    let home = home_keys(&seed_dir);
    let ours = seal(&home, &alias, &[13u8; 32]).await;

    let plan = plan_sealed_half(&seed_dir, &alias, &legacy);
    assert_eq!(plan, SealedHalfPlan::ReuseHome);
    let staged = stage_home_half_into(&seed_dir, &alias, &legacy);
    assert!(
        !staged.is_empty(),
        "the staging must actually put files there"
    );
    // What the creator would do with the staging present: open it, not mint.
    assert_eq!(
        SealedMlDsa65Signer::open_existing(&alias, &legacy)
            .expect("the staged copy must open — that is what makes the creator reuse it")
            .public_key()
            .await
            .expect("public key"),
        ours,
        "the staged copy must be OUR key, or the creator records one we cannot sign with"
    );

    let landed =
        ciris_server::identity::relocate_sealed_pqc_into_home(&seed_dir, &alias, &legacy, plan)
            .await;

    assert_eq!(landed, home, "the home copy is the one that stays");
    assert_eq!(
        SealedMlDsa65Signer::open_existing(&alias, &home)
            .expect("this home's half must be untouched")
            .public_key()
            .await
            .expect("public key"),
        ours,
        "a retry must not change the key this home signs with"
    );
    assert!(
        SealedMlDsa65Signer::open_existing(&alias, &legacy).is_err(),
        "the staging was scaffolding — leaving it in the global store re-creates the sharing \
         this whole change removes"
    );
}

/// A relocation that CANNOT COMPLETE leaves the original working.
///
/// The dangerous outcome is not "the move failed" — it is a move that removed
/// the original after putting down something that does not open. So this drives
/// a genuine failure (the home key store cannot be created: a FILE sits where
/// the directory must go) and asserts the global original is untouched and
/// still opens to the key it always had.
#[tokio::test]
async fn a_relocation_that_cannot_complete_leaves_the_original_working() {
    use ciris_server::identity::SealedHalfPlan;
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

    let landed = ciris_server::identity::relocate_sealed_pqc_into_home(
        &seed_dir,
        &alias,
        &legacy,
        SealedHalfPlan::CreatorWillMint,
    )
    .await;

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
