//! **A partial reset starts a new node; it never signs on with half an
//! identity** (0.5.249; CIRISAgent 2.22.1's five-platform run, windows,
//! 2026-11-15).
//!
//! A device reset on Windows could not delete the files the running node held
//! open: it removed `node_alias` and `ml_dsa_65.seed` but left the keystore
//! files of the node's alias. The next boot minted a fresh ML-DSA-65 seed
//! beside the surviving Ed25519 key, under the same key id, and the canonical
//! refused it as `pubkey_swap`. Two guards now stand in that path: the boot
//! sets a lone Ed25519 key aside and mints a whole new pair, and registering a
//! key whose id this store already holds with another pair is refused, not
//! taken for "already registered".

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::{HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::prelude::{Engine, LocalSigner};
use std::sync::Arc;

/// The home's identity dir after a BARE boot: the node alias recorded, its
/// Ed25519 key on disk, the engine's ML-DSA seed, and the node key registered
/// in `engine`'s directory with exactly that pair.
async fn bare_booted_home(dir: &std::path::Path, alias: &str, engine: &Engine) -> (String, String) {
    std::fs::create_dir_all(dir).expect("identity dir");
    std::fs::write(dir.join(ciris_server::node_key::NODE_ALIAS_FILE), alias).expect("alias");
    let ed: Arc<dyn HardwareSigner> = Arc::from(
        ciris_server::key_tier::ed25519_open_or_create(alias, dir).expect("node Ed25519"),
    );
    let seed = [0x4Du8; 32];
    std::fs::write(dir.join("ml_dsa_65.seed"), seed).expect("engine seed");
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&seed, format!("{alias}-pqc")).expect("pqc"),
    );
    let signer = LocalSigner::from_hardware_parts(
        ed.clone(),
        alias.to_owned(),
        Some(pqc.clone()),
        Some(format!("{alias}-pqc")),
    )
    .await
    .expect("signer");
    let identity = ciris_verify_core::self_at_login::HardwareRootedIdentity::new(
        signer.derived_key_id(),
        ed,
        pqc.clone(),
    )
    .expect("identity");
    let (key_id, _) = ciris_server::node_key::register_node_key_with_record(engine, &identity)
        .await
        .expect("the bare boot registers its node key");
    let pqc_pub = B64.encode(pqc.public_key().await.expect("pqc pub"));
    (key_id, pqc_pub)
}

/// A fresh identity dir for ONE test: pid plus the test's own name, since
/// parallel test threads share a pid.
fn scratch(test: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "split-pair-{}-{test}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&d);
    d.join("identity")
}

async fn store() -> Arc<Engine> {
    let signer = LocalSigner::from_hardware_parts(
        Arc::new(
            ciris_keyring::Ed25519SoftwareSigner::from_bytes(&[0x21; 32], "store-host")
                .expect("host"),
        ),
        "store-host".into(),
        Some(Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&[0x22; 32], "store-host-pqc".to_string())
                .expect("host pqc"),
        )),
        Some("store-host-pqc".to_string()),
    )
    .await
    .expect("host signer");
    Arc::new(
        Engine::with_signer(Arc::new(signer), "sqlite::memory:")
            .await
            .expect("engine"),
    )
}

#[test]
fn a_key_that_lost_its_pqc_half_is_set_aside_not_signed_with() {
    let dir = scratch("half");
    std::fs::create_dir_all(&dir).expect("dir");
    let alias = "cirisserver-testhost-node";
    let _ = ciris_server::key_tier::ed25519_open_or_create(alias, &dir).expect("the old key");
    if ciris_server::key_tier::on_disk_tier(alias, &dir)
        == ciris_server::key_tier::OnDiskTier::Absent
    {
        eprintln!(
            "this host keeps keys outside the identity dir; the file-tier case is untestable here"
        );
        return;
    }
    // The partial reset: the PQC seed is gone, the Ed25519 key is not.
    let moved = ciris_server::node_key::set_aside_half_identity(alias, &dir).expect("set aside");
    assert!(!moved.is_empty(), "the surviving key files are moved");
    assert!(
        moved
            .iter()
            .all(|p| p.to_string_lossy().contains(".pubkey_swap-")),
        "kept aside under a name that says why, never deleted: {moved:?}"
    );
    assert!(
        ciris_server::key_tier::ed25519_open_existing(alias, &dir).is_err(),
        "the alias no longer opens the half identity, so the boot mints a whole new pair"
    );
}

#[test]
fn a_whole_identity_is_left_alone() {
    let dir = scratch("whole");
    std::fs::create_dir_all(&dir).expect("dir");
    let alias = "cirisserver-testhost-node";
    let _ = ciris_server::key_tier::ed25519_open_or_create(alias, &dir).expect("key");
    std::fs::write(dir.join("ml_dsa_65.seed"), [0x11u8; 32]).expect("pqc seed");
    let moved = ciris_server::node_key::set_aside_half_identity(alias, &dir).expect("noop");
    assert!(moved.is_empty(), "both halves present: nothing moves");
    assert!(ciris_server::key_tier::ed25519_open_existing(alias, &dir).is_ok());
    // And a home with no key at all is a first boot, not a partial reset.
    let fresh = scratch("fresh");
    std::fs::create_dir_all(&fresh).expect("dir");
    assert!(
        ciris_server::node_key::set_aside_half_identity(alias, &fresh)
            .expect("noop")
            .is_empty()
    );
}

#[tokio::test]
async fn registering_a_second_pair_under_a_held_id_is_refused() {
    let dir = scratch("second");
    let engine = store().await;
    let alias = "cirisserver-testhost-node";
    let (key_id, _registered) = bare_booted_home(&dir, alias, &engine).await;
    // The same Ed25519 key (so the same id) with a different ML-DSA-65 half.
    let ed: Arc<dyn HardwareSigner> =
        Arc::from(ciris_server::key_tier::ed25519_open_existing(alias, &dir).expect("same key"));
    let other: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0x5Au8; 32], format!("{alias}-pqc")).expect("pqc"),
    );
    let signer = LocalSigner::from_hardware_parts(
        ed.clone(),
        alias.to_owned(),
        Some(other.clone()),
        Some(format!("{alias}-pqc")),
    )
    .await
    .expect("signer");
    assert_eq!(
        signer.derived_key_id(),
        key_id,
        "the id fingerprints the Ed25519 half only"
    );
    let swapped = ciris_verify_core::self_at_login::HardwareRootedIdentity::new(
        signer.derived_key_id(),
        ed,
        other,
    )
    .expect("identity");
    let err = ciris_server::node_key::register_node_key_with_record(&engine, &swapped)
        .await
        .expect_err("a second pair under a held id is refused");
    assert!(format!("{err:#}").contains("pubkey_swap"), "{err:#}");
}
