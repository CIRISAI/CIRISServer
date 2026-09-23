//! **A dedicated home seals its own post-quantum half** (CIRISServer#621,
//! CIRISVerify#285 — verify v16.1.0).
//!
//! `--home` isolated the database, config, logs and the Ed25519 seed. It did
//! not isolate the ML-DSA-65 half: `create_federation_identity` sealed that
//! into the process-global `keys_dir()` with no parameter for where, so two
//! homes minting the same alias shared one file. verify v16.1.0 added
//! `create_federation_identity_in(keys_dir, …)`; the server now mints through
//! it with `<home>/identity/keys`, after `preflight_keys_dir` has proved the
//! directory usable.
//!
//! An earlier cut worked around the missing parameter by RELOCATING the
//! globally-sealed half into the home after the fact — copy, prove by public
//! key, delete. That machinery is gone. These are the properties that replace
//! it, asserted on the real mint rather than on file moves.
//!
//! # Which of these actually distinguishes the two implementations
//!
//! Measured, by running this file against the pre-collapse code:
//!
//! * `an_unusable_home_key_store_is_refused_up_front` — **FAILS there.** The
//!   old path sealed globally and then merely declined to relocate, so a home
//!   that cannot hold keys still produced an identity. This is the witness for
//!   the change.
//! * the other two **pass on both.** That is not a weak test, it is what the
//!   relocation was FOR: it left the same end state (half in the home, global
//!   original deleted; a retry reused the staged copy). The transient — bytes
//!   written to a directory this home does not own — is not observable after
//!   the fact, so they pin properties that must keep holding rather than
//!   proving the collapse.

use ciris_server::identity::{mint_user_identity, ActiveAlias, UserIdentityBackend};

/// A unique home per case: pid AND a counter — cargo runs a file's tests in
/// parallel threads of one process, so pid alone would collide.
fn home(tag: &str) -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ciris-home-x-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("identity").join("user")).expect("seed dir");
    dir
}

fn sealed_half_in(dir: &std::path::Path, alias: &str) -> bool {
    dir.join(format!("{alias}.mldsa65.seed.blob")).exists()
        || dir.join(format!("{alias}.master.key")).exists()
        || dir.join(format!("{alias}.tpmplugin_seal")).exists()
}

/// THE PROPERTY: a mint into a home seals into THAT home, and nowhere else.
#[tokio::test]
async fn a_home_mint_seals_its_pqc_half_into_the_home_and_not_the_global_store() {
    let root = home("seal");
    let seed_dir = root.join("identity").join("user");
    let alias = format!("home-x-{}-{}", std::process::id(), line!());

    let minted = mint_user_identity(
        UserIdentityBackend::Software,
        &alias,
        Some("Home X"),
        seed_dir.clone(),
        ActiveAlias::Adopt,
    )
    .await
    .expect("mint into a dedicated home");
    assert!(
        minted.key_id.starts_with(&format!("{alias}-")),
        "derived key_id expected, got {}",
        minted.key_id
    );

    let home_keys = root.join("identity").join("keys");
    assert!(
        sealed_half_in(&home_keys, &alias),
        "the ML-DSA-65 half must be sealed in THIS home's key store ({}) — that is the whole \
         point of --home for the post-quantum half",
        home_keys.display()
    );
    let global = ciris_verify_core::ceg_outbox::keys_dir();
    assert!(
        !sealed_half_in(&global, &alias),
        "nothing for this alias may land in the process-global key store ({}) — two homes \
         minting the same alias would share it, which is the defect this closes",
        global.display()
    );
}

/// A retried mint in the same home OPENS the same half; it does not mint a
/// second one under the alias (the identity that disagreed with itself).
#[tokio::test]
async fn a_retried_home_mint_reuses_the_same_key() {
    let root = home("retry");
    let seed_dir = root.join("identity").join("user");
    let alias = format!("home-retry-{}-{}", std::process::id(), line!());

    let first = mint_user_identity(
        UserIdentityBackend::Software,
        &alias,
        Some("Home X"),
        seed_dir.clone(),
        ActiveAlias::Adopt,
    )
    .await
    .expect("first mint");
    let second = mint_user_identity(
        UserIdentityBackend::Software,
        &alias,
        Some("Home X"),
        seed_dir.clone(),
        ActiveAlias::Adopt,
    )
    .await
    .expect("retried mint must be a no-op open, not a failure");
    assert_eq!(
        first.key_id, second.key_id,
        "a retry must resolve to the SAME identity — a different key_id means the retry \
         minted a second half under the alias"
    );
}

/// A home whose key path cannot be a directory is refused BEFORE anything
/// irreversible — the preflight, not a failure three steps later.
#[tokio::test]
async fn an_unusable_home_key_store_is_refused_up_front() {
    let root = home("blocked");
    let seed_dir = root.join("identity").join("user");
    let alias = format!("home-blocked-{}-{}", std::process::id(), line!());
    // A FILE where `<home>/identity/keys` must be a directory.
    std::fs::write(root.join("identity").join("keys"), b"not a directory").expect("blocker");

    let err = mint_user_identity(
        UserIdentityBackend::Software,
        &alias,
        Some("Home X"),
        seed_dir.clone(),
        ActiveAlias::Adopt,
    )
    .await
    .expect_err("a home whose key store cannot be created must refuse the mint");
    let text = format!("{err:#}");
    assert!(
        text.contains("key store") || text.contains("keys_dir"),
        "the refusal must name the key store, got: {text}"
    );
    let global = ciris_verify_core::ceg_outbox::keys_dir();
    assert!(
        !sealed_half_in(&global, &alias),
        "a refused home mint must not fall back to sealing globally"
    );
    // AND NOTHING IRREVERSIBLE RAN. `open_user_signer` writes an Ed25519 seed,
    // creates a platform seal, and with provisioning can program a PIV slot —
    // so the preflight must precede it, not merely precede the PQC seal. An
    // earlier revision of this collapse preflighted afterwards and left exactly
    // these artifacts behind for a home that never had a usable key store.
    let leftovers: Vec<String> = std::fs::read_dir(&seed_dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with(&alias))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        leftovers.is_empty(),
        "a refused mint must leave no key material for {alias} in the seed dir, found: \
         {leftovers:?}"
    );
}

/// **An identity that predates home scoping is REUSED, never replaced.**
///
/// Its Ed25519 half sits in `seed_dir` while its ML-DSA half exists only in the
/// global store. Minting against an empty home directory would have
/// `open_or_create` mint a SECOND post-quantum half under the same alias and
/// derived id; the replacement then wins the home-first resolve and the identity
/// stops producing signatures its directory record and peers accept — the
/// CIRISVerify#134 hazard. The resolver is what prevents it, so this asserts the
/// resolver's decision directly, with both stores injected (no `CIRIS_HOME`,
/// which is process-global and races every other test in the binary).
#[test]
fn a_legacy_half_is_chosen_over_an_empty_home_store() {
    let root = home("legacy");
    let seed_dir = root.join("identity").join("user");
    let legacy = root.join("global-keys");
    std::fs::create_dir_all(&legacy).expect("legacy dir");
    let alias = "predates-home-scoping";

    // Nothing anywhere: a NEW identity is home-scoped.
    assert_eq!(
        ciris_server::identity::sealed_keys_dir_in(&seed_dir, alias, &legacy),
        root.join("identity").join("keys"),
        "a fresh alias must mint into THIS home — that is the isolation this cut buys"
    );

    // The half exists only in the global store: mint there, opening it.
    std::fs::write(legacy.join(format!("{alias}.mldsa65.seed.blob")), b"x").expect("legacy half");
    assert_eq!(
        ciris_server::identity::sealed_keys_dir_in(&seed_dir, alias, &legacy),
        legacy,
        "an alias whose ML-DSA half lives in the global store must be OPENED there, not \
         re-minted into an empty home store under the same id (CIRISVerify#134)"
    );
}
