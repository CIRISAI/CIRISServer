//! **A home that boots bare, then with an agent, stays ONE node with ONE key
//! pair** (0.5.248; CIRISAgent 2.22.0's five-platform run, linux and windows,
//! 2026-11-14).
//!
//! The run's harness boots a home bare first (no `--key-id`, the "no AI" leg)
//! and then with the agent's key (the "add AI" leg). The bare boot's engine
//! identity is the home-picked node key, registered with the engine's ML-DSA-65
//! seed (`ml_dsa_65.seed`). The agent boot splits: the configured key is an
//! actor, so the recorded node alias is adopted as the NODE key. Before this
//! fix `node_signer` paired that kept Ed25519 key with a freshly minted
//! `node_ml_dsa_65.seed`, so the same key id (it fingerprints the Ed25519 half
//! only) carried a second PQC half. The canonical refused it as `pubkey_swap`
//! (first record wins) and every row the node signed after that failed its
//! scrub check: no key exchange, no traces, no contact add.

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

/// The ML-DSA-65 public key of the seed the node signs with.
async fn node_pqc_pub(dir: &std::path::Path) -> String {
    let s =
        MlDsa65SoftwareSigner::from_seed_file(dir.join("node_ml_dsa_65.seed"), "probe".to_string())
            .expect("node seed");
    B64.encode(s.public_key().await.expect("pqc pub"))
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

#[tokio::test]
async fn the_agent_boot_keeps_the_pair_the_bare_boot_registered() {
    let dir = scratch("keeps");
    let engine = store().await;
    let alias = "cirisserver-testhost-node";
    let (key_id, registered_pqc) = bare_booted_home(&dir, alias, &engine).await;

    // The agent boot: the configured key is the actor's; the node alias is the
    // recorded one. With the directory the node keeps its registered pair.
    let (signer, identity) = ciris_server::node_key::node_signer(
        "qa-runner-ciris-agent",
        &dir,
        Some(engine.federation_directory().as_ref()),
    )
    .await
    .expect("node signer");
    assert_eq!(
        signer.derived_key_id(),
        key_id,
        "the same node, the same id"
    );
    let _ = identity;
    let pqc_now = node_pqc_pub(&dir).await;
    assert_eq!(
        pqc_now, registered_pqc,
        "the node key keeps the ML-DSA-65 half it registered with (no pubkey_swap)"
    );
    assert!(
        dir.join("node_ml_dsa_65.seed").exists(),
        "the adopted seed is recorded as the node's own"
    );
    // Registering again is the idempotent no-op it always was.
    ciris_server::node_key::register_node_key_with_record(&engine, &identity)
        .await
        .expect("re-registering the same pair is a no-op");
}

#[tokio::test]
async fn without_the_store_the_old_path_mints_a_second_pqc_half() {
    // The defect, kept visible: no directory, no adoption, a fresh seed under
    // the same id.
    let dir = scratch("old");
    let engine = store().await;
    let alias = "cirisserver-testhost-node";
    let (key_id, registered_pqc) = bare_booted_home(&dir, alias, &engine).await;
    let (signer, _identity) =
        ciris_server::node_key::node_signer("qa-runner-ciris-agent", &dir, None)
            .await
            .expect("node signer");
    assert_eq!(signer.derived_key_id(), key_id);
    let pqc_now = node_pqc_pub(&dir).await;
    assert_ne!(
        pqc_now, registered_pqc,
        "a second PQC half under the same id"
    );
}

#[tokio::test]
async fn a_registered_pair_no_seed_here_matches_is_refused_not_re_minted() {
    let dir = scratch("refused");
    let engine = store().await;
    let alias = "cirisserver-testhost-node";
    bare_booted_home(&dir, alias, &engine).await;
    // The engine seed has since changed (another identity took the file).
    std::fs::write(dir.join("ml_dsa_65.seed"), [0x7Eu8; 32]).expect("replace seed");
    let err = ciris_server::node_key::node_signer(
        "qa-runner-ciris-agent",
        &dir,
        Some(engine.federation_directory().as_ref()),
    )
    .await
    .err()
    .expect("refused");
    assert!(format!("{err:#}").contains("pubkey_swap"), "{err:#}");
    assert!(!dir.join("node_ml_dsa_65.seed").exists(), "nothing minted");
}

#[tokio::test]
async fn a_home_the_broken_split_already_re_keyed_heals_on_its_next_boot() {
    // 0.5.246–0.5.247 left this home with a fresh node seed under the
    // registered id. The next boot restores the registered half and keeps the
    // other seed aside.
    let dir = scratch("heal");
    let engine = store().await;
    let alias = "cirisserver-testhost-node";
    let (key_id, registered_pqc) = bare_booted_home(&dir, alias, &engine).await;
    let _ = ciris_server::node_key::node_signer("qa-runner-ciris-agent", &dir, None)
        .await
        .expect("the broken split");
    assert_ne!(
        node_pqc_pub(&dir).await,
        registered_pqc,
        "broken as shipped"
    );
    let (signer, _) = ciris_server::node_key::node_signer(
        "qa-runner-ciris-agent",
        &dir,
        Some(engine.federation_directory().as_ref()),
    )
    .await
    .expect("the next boot");
    assert_eq!(signer.derived_key_id(), key_id);
    assert_eq!(
        node_pqc_pub(&dir).await,
        registered_pqc,
        "the registered half is back"
    );
    assert!(
        dir.join("node_ml_dsa_65.seed.pubkey_swap").exists(),
        "the stray seed is kept, never deleted"
    );
}
