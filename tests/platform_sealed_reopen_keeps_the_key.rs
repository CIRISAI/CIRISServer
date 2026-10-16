//! **Re-opening a platform-sealed owner key must never archive it**
//! (Eric's desktop, 2026-10-08 → found 2026-10-16).
//!
//! The owner's fed-ID `mooreericnyc-ubnr7f7uxe` was minted with backend
//! `platform-sealed` on a machine where the TPM plugin was not usable, so the
//! keyring degraded to ENCRYPTED SOFTWARE storage: `{alias}.master.key` +
//! `{alias}.ed25519.seed.blob`. Weeks later the TPM plugin became usable in the
//! same process (`libciris_tpm_plugin.so` beside the agent; the user is in the
//! `tss` group). The next RE-OPEN of that key (`get_user_identity_signer`,
//! which the server's `open_user_signer(create = false)` uses for every owner
//! act) constructed the TPM plugin storage, which found no seal, minted a fresh
//! TPM master, witnessed that as "the higher-tier mint landed", and archived
//! the live software key to `*.superseded-pre-v8`. It never wrote a seed into
//! the new tier, so every open since fails `Key not found: ed25519.seed`: the
//! node is owned by a key it can no longer wield (CIRISServer#783).
//!
//! This test replays that on a temp dir: a software-fallback seed, then the
//! exact re-open. It needs a usable TPM + the plugin (`CIRIS_TPM_PLUGIN` or the
//! loader path); without one the re-open stays on software and the test says so.
use std::path::PathBuf;

use ciris_keyring::storage::{SecureBlobStorage, SoftwareSecureBlobStorage};
use ciris_keyring::user_identity::{get_user_identity_signer, SigningBackend, UserIdentityConfig};
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_server::key_tier;

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "ciris-reopen-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn names(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn canary_the_keyring_factory_still_supersedes_a_software_key_on_reopen() {
    let dir = tmp("owner");
    let alias = "repro-owner";

    // 1. What `platform-sealed` wrote when the TPM was NOT usable: the keyring's
    //    software tier, under the same key id the sealed Ed25519 signer uses.
    {
        let sw = SoftwareSecureBlobStorage::new(alias, &dir).unwrap();
        sw.store("ed25519.seed", &[7u8; 32]).unwrap();
    }
    let before = names(&dir);
    assert!(
        before.iter().any(|n| n.ends_with(".blob")),
        "software fallback written: {before:?}"
    );

    // 2. The server's re-open of an existing owner key (create = false).
    let cfg = UserIdentityConfig {
        key_id: alias.to_string(),
        seed_dir: dir.clone(),
        backend: SigningBackend::PlatformSealed,
    };
    let opened = get_user_identity_signer(&cfg);
    let after = names(&dir);
    eprintln!(
        "before={before:?}\nafter={after:?}\nopen={:?}",
        opened.as_ref().err()
    );

    let tpm_tier_appeared = after.iter().any(|n| n.ends_with(".tpmplugin_seal"));
    if !tpm_tier_appeared {
        // No TPM plugin here, so the canary has nothing to observe. Not asserting
        // the keyring's own re-open succeeds: on macOS the platform factory picks
        // the keychain/Secure Enclave tier and cannot see software-tier files at
        // all (KeyNotFound) — the same stranding, by another route, which is why
        // the server opens software-tier keys through `key_tier` (tested above).
        eprintln!(
            "no usable TPM plugin in this process — canary not applicable (keyring open: {:?})",
            opened.as_ref().err()
        );
        return;
    }
    // CANARY. The keyring (verify v20.1.0, f4ea1a2) still supersedes a software
    // key on a mere re-open — that is why `ciris_server::key_tier` exists. When
    // this assertion fails, upstream fixed it: retire the workaround's re-open
    // routing (keep the heal for homes already damaged) and delete this canary.
    let archived: Vec<&String> = after
        .iter()
        .filter(|n| n.ends_with("superseded-pre-v8"))
        .collect();
    assert!(
        !archived.is_empty() && opened.is_err(),
        "UPSTREAM FIXED: the keyring re-open no longer supersedes ({after:?}, {:?}) — retire key_tier's routing",
        opened.err()
    );
}

fn tpm_plugin_usable() -> bool {
    // Probe on a scratch alias: does the platform factory pick the plugin tier here?
    let d = tmp("probe");
    let _ = ciris_keyring::create_platform_storage("probe", &d);
    d.join("probe.tpmplugin_seal").exists()
}

fn software_key(dir: &std::path::Path, alias: &str, ed: [u8; 32], ml: [u8; 32]) {
    let sw = SoftwareSecureBlobStorage::new(alias, dir).unwrap();
    sw.store("ed25519.seed", &ed).unwrap();
    sw.store("mldsa65.seed", &ml).unwrap();
}

async fn ed_pub(s: &dyn HardwareSigner) -> Vec<u8> {
    s.public_key().await.unwrap()
}

async fn ml_pub(s: &dyn PqcSigner) -> Vec<u8> {
    s.public_key().await.unwrap()
}

/// The FIX, with a TPM present: the server's re-open (`key_tier`) leaves a
/// software-tier key where it is and opens it — both halves, same public keys.
#[tokio::test]
async fn the_servers_reopen_keeps_a_software_tier_key_when_a_tpm_appears() {
    let dir = tmp("fix");
    let alias = "fixed-owner";
    software_key(&dir, alias, [9u8; 32], [11u8; 32]);
    let ed = key_tier::ed25519_open_existing(alias, &dir).expect("Ed25519 re-open");
    let ml = key_tier::mldsa65_open_existing(alias, &dir).expect("ML-DSA re-open");
    let after = names(&dir);
    assert!(
        !after.iter().any(|n| n.ends_with("superseded-pre-v8")),
        "nothing archived: {after:?}"
    );
    assert!(
        !after.iter().any(|n| n.ends_with(".tpmplugin_seal")),
        "no TPM master minted on a re-open: {after:?}"
    );
    let want_ed = Ed25519SoftwareSigner::from_bytes(&[9u8; 32], alias).unwrap();
    let want_ml = MlDsa65SoftwareSigner::from_seed_bytes(&[11u8; 32], alias).unwrap();
    assert_eq!(
        ed_pub(&*ed).await,
        ed_pub(&want_ed).await,
        "the same Ed25519 key"
    );
    assert_eq!(
        ml_pub(&*ml).await,
        ml_pub(&want_ml).await,
        "the same ML-DSA-65 key"
    );
    // And open-or-create on an existing software key is an open, not a mint.
    let again = key_tier::ed25519_open_or_create(alias, &dir).expect("open-or-create");
    assert_eq!(ed_pub(&*again).await, ed_pub(&want_ed).await);
    eprintln!("tpm plugin usable in this process: {}", tpm_plugin_usable());
}

/// The HEAL: Eric's on-disk state exactly — the software pair archived to
/// `*.superseded-pre-v8` beside a plugin seal that holds NO blob. The re-open
/// restores the archived key (the TPM tier was empty, so it is the only key),
/// keeps the seal aside, and opens the ORIGINAL key. No TPM needed.
#[tokio::test]
async fn a_key_superseded_into_an_empty_tpm_tier_is_restored_and_opens() {
    let dir = tmp("heal");
    let alias = "eric-shape";
    software_key(&dir, alias, [5u8; 32], [6u8; 32]);
    for n in names(&dir) {
        std::fs::rename(dir.join(&n), dir.join(format!("{n}.superseded-pre-v8"))).unwrap();
    }
    std::fs::write(
        dir.join(format!("{alias}.tpmplugin_seal")),
        b"sealed master, no blobs",
    )
    .unwrap();
    let broken = names(&dir);

    let ed = key_tier::ed25519_open_existing(alias, &dir).expect("healed Ed25519 re-open");
    let ml = key_tier::mldsa65_open_existing(alias, &dir).expect("healed ML-DSA re-open");
    let healed = names(&dir);
    eprintln!("broken={broken:?}\nhealed={healed:?}");
    assert!(
        healed.contains(&format!("{alias}.master.key")),
        "software master restored: {healed:?}"
    );
    assert!(
        healed.contains(&format!("{alias}.ed25519.seed.blob")),
        "Ed25519 blob restored"
    );
    assert!(
        healed
            .iter()
            .any(|n| n.starts_with(&format!("{alias}.tpmplugin_seal.orphaned-"))),
        "empty seal kept aside, not deleted"
    );
    assert!(
        !healed.contains(&format!("{alias}.tpmplugin_seal")),
        "the live seal name is free"
    );
    let want_ed = Ed25519SoftwareSigner::from_bytes(&[5u8; 32], alias).unwrap();
    let want_ml = MlDsa65SoftwareSigner::from_seed_bytes(&[6u8; 32], alias).unwrap();
    assert_eq!(
        ed_pub(&*ed).await,
        ed_pub(&want_ed).await,
        "the ORIGINAL Ed25519 key opens"
    );
    assert_eq!(
        ml_pub(&*ml).await,
        ml_pub(&want_ml).await,
        "the ORIGINAL ML-DSA key opens"
    );
}

/// The heal NEVER fires when the TPM tier holds a key: a seal WITH a blob is the
/// live key, and an archived software pair beside it stays archived.
#[tokio::test]
async fn a_tpm_tier_that_holds_a_key_is_never_overridden_by_the_archive() {
    let dir = tmp("noheal");
    let alias = "live-tpm";
    software_key(&dir, alias, [1u8; 32], [2u8; 32]);
    for n in names(&dir) {
        std::fs::rename(dir.join(&n), dir.join(format!("{n}.superseded-pre-v8"))).unwrap();
    }
    std::fs::write(dir.join(format!("{alias}.tpmplugin_seal")), b"seal").unwrap();
    std::fs::write(
        dir.join(format!("{alias}.ed25519_seed.tpmp_blob")),
        b"live tpm key",
    )
    .unwrap();
    let restored = key_tier::heal_orphaned_supersession(alias, &dir);
    assert!(restored.is_empty(), "nothing restored over a live TPM key");
    assert!(dir.join(format!("{alias}.tpmplugin_seal")).exists());
    assert!(!dir.join(format!("{alias}.master.key")).exists());
}

/// Operator probe, not CI: point `CIRIS_HEAL_PROBE_SEED_DIR` / `_KEYS_DIR` at a
/// COPY of a damaged home and `_ALIAS` / `_EXPECT_KEY_ID` at the owner, and this
/// heals the copy and asserts the opened key derives the registered owner id.
#[tokio::test]
#[ignore]
async fn probe_heal_a_copied_home() {
    let seed_dir = PathBuf::from(std::env::var("CIRIS_HEAL_PROBE_SEED_DIR").unwrap());
    let keys_dir = PathBuf::from(std::env::var("CIRIS_HEAL_PROBE_KEYS_DIR").unwrap());
    let alias = std::env::var("CIRIS_HEAL_PROBE_ALIAS").unwrap();
    let expect = std::env::var("CIRIS_HEAL_PROBE_EXPECT_KEY_ID").unwrap();
    eprintln!("before seed_dir={:?}", names(&seed_dir));
    let ed = key_tier::ed25519_open_existing(&alias, &seed_dir).expect("Ed25519 opens after heal");
    let ml = key_tier::mldsa65_open_existing(&alias, &keys_dir).expect("ML-DSA opens");
    eprintln!(
        "after seed_dir={:?}\nafter keys_dir={:?}",
        names(&seed_dir),
        names(&keys_dir)
    );
    let derived = ciris_verify_core::fedcode::derive_key_id(&alias, &ed_pub(&*ed).await);
    eprintln!(
        "derived={derived} expect={expect} mldsa_pub_len={}",
        ml_pub(&*ml).await.len()
    );
    assert_eq!(derived, expect, "the healed key IS the registered owner");
}
