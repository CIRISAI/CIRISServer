//! **Portable software identity occurrence** (CIRISServer — bootstrap) — the
//! owner's deliberate, labeled trade-off: a fresh *software* hybrid keyset that the
//! local primary authorizes as an occurrence of the same self, written to a chosen
//! directory (a USB key), so a second device is recognized as "him".
//!
//! This is the proof the owner asked for. It exercises the crate-internal path the
//! `POST /v1/self/occurrence/portable` + `POST /v1/self/associate` handlers drive
//! (software keys only — NO hardware):
//!
//!   1. Mint a software primary as the "self" + register it.
//!   2. Mint a portable software keyset into `target_dir` and BIND it as an
//!      occurrence of that self via `bind_occurrence_core` (the exact three-effect
//!      sequence the owner-gated handler runs). Assert
//!      `signer_acts_for(new_software_key, self) == true` AND the seed files exist.
//!   3. Install (associate) the portable keyset from a SECOND seed dir and assert
//!      that device's re-opened signer resolves to the SAME self (its `key_id()` is
//!      the portable occurrence key, which is an active occurrence of the self).

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::types::{algorithm, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};

use ciris_server::auth::occurrence::bind_occurrence_core;
use ciris_server::auth::verify::signer_acts_for;

const NODE_KEY_ID: &str = "ciris-server-portable-test";

/// A unique temp dir per test/tag.
fn tmp(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "ciris-portable-occ-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// Stand up THIS node — an in-memory hybrid substrate (mirrors tests/occurrence.rs).
async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xB1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xB2; 32], format!("{NODE_KEY_ID}-pqc"))
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

/// Register a `federation_keys` row for the self's primary so `signer_acts_for`
/// resolves it (the self root acts for itself trivially; we register so the row
/// exists, mirroring the occurrence-test fixture).
async fn register_self_key(engine: &Engine, key_id: &str) {
    let ed = SigningKey::from_bytes(&[0x10; 32]);
    let mldsa = MlDsa65SoftwareSigner::from_seed_bytes(&[0x11; 32], format!("{key_id}-pqc"))
        .expect("self ML-DSA-65 seed");
    let now = chrono::Utc::now();
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: BASE64.encode(ed.verifying_key().to_bytes()),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(mldsa.public_key().await.unwrap())),
        algorithm: algorithm::HYBRID.into(),
        identity_type: "user".to_string(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": key_id }),
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register self key");
}

#[tokio::test]
async fn portable_software_keyset_becomes_a_primary_authorized_occurrence_of_the_self() {
    // The verify outbox + the ML-DSA seal root must live somewhere writable + unique
    // per run (the portable mint produces a self-record; the install re-seals).
    let home = tmp("home");
    let data = tmp("data");
    std::env::set_var("CIRIS_HOME", &home);
    std::env::set_var("CIRIS_DATA_DIR", &data);

    let engine = node().await;

    // (1) The owner's self — a software primary, registered in the directory.
    let self_key = "owner-self-root";
    register_self_key(&engine, self_key).await;
    assert!(
        signer_acts_for(&engine, self_key, self_key).await,
        "the self root acts for itself"
    );

    // (2) Mint a PORTABLE software keyset into the chosen USB dir, keyed by a stable
    //     alias (so re-opening it on another device reproduces the same key_id).
    let usb = tmp("usb");
    let portable_alias = "owner-portable-1";
    let keyset = ciris_server::identity::mint_portable_software_occurrence(&usb, portable_alias)
        .await
        .expect("mint portable software occurrence");
    assert_eq!(keyset.identity_type, "user");
    assert_eq!(keyset.alias, portable_alias);
    assert!(
        keyset.fedcode.starts_with("CIRIS-V2-"),
        "got fedcode {}",
        keyset.fedcode
    );

    // BOTH seed halves + the marker landed on the USB dir, keyed by the alias (the
    // proof it is portable).
    let ed_seed = usb.join(format!("{portable_alias}.ed25519.seed"));
    let ml_seed = usb.join(format!("{portable_alias}.mldsa65.seed"));
    let marker = usb.join(format!("{portable_alias}.backend"));
    assert!(ed_seed.exists(), "ed25519 seed must exist at {ed_seed:?}");
    assert!(ml_seed.exists(), "ml-dsa-65 seed must exist at {ml_seed:?}");
    assert!(marker.exists(), "backend marker must exist at {marker:?}");
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap().trim(),
        "software",
        "the marker honestly records the software custody tier"
    );

    // The portable key is NOT yet an occurrence of the self.
    assert!(
        !signer_acts_for(&engine, &keyset.key_id, self_key).await,
        "before the bind the portable key does not act for the self"
    );

    // (3) THE security-critical bind — register the fresh software key + make it an
    //     ACTIVE occurrence of the owner's self. This is the exact core the
    //     owner-gated handler runs (authorized there by the owner session + the
    //     locally-held primary). The self-signed PoP record admits the fresh key.
    let outcome = bind_occurrence_core(
        &engine,
        self_key,
        &keyset.key_id,
        "laptop",
        None,
        None,
        Some(keyset.key_record.clone()),
    )
    .await
    .expect("bind portable key as an occurrence of the self");
    assert!(
        outcome.key_freshly_registered,
        "the portable key was admitted via its self-signed PoP record"
    );

    // THE PROOF the owner asked for: the new software key now acts AS the self.
    assert!(
        signer_acts_for(&engine, &keyset.key_id, self_key).await,
        "after the bind the portable software key MUST act for the self"
    );

    // (4) ASSOCIATE: install the portable keyset into a SECOND seed dir (a fresh
    //     device) under a local alias, then re-open the signer and assert it
    //     resolves to the portable occurrence key — i.e. this device now signs as
    //     that occurrence of the SAME self.
    let device2_seed = tmp("device2-seed");
    // The discovered alias drives the install (mirrors the associate handler).
    let discovered = ciris_server::identity::find_portable_alias(&usb)
        .expect("discover the portable alias in the USB dir");
    assert_eq!(discovered, portable_alias);
    let installed =
        ciris_server::identity::install_portable_software_keyset(&usb, &discovered, &device2_seed)
            .expect("install (associate) the portable keyset onto device 2");
    assert!(
        installed.iter().any(|f| f.contains("ed25519.seed")),
        "the ed25519 seed was installed: {installed:?}"
    );
    assert!(
        device2_seed
            .join(format!("{portable_alias}.ed25519.seed"))
            .exists(),
        "device 2 holds the ed25519 seed under the alias"
    );

    // Re-open device 2's user signer the SAME way the node resolves it
    // (`hardware_user_local_signer(Software, alias, seed_dir)`). Its key_id() must
    // be the portable occurrence key — so device 2 IS recognized as the same self.
    let device2_signer = ciris_server::identity::hardware_user_local_signer(
        ciris_server::identity::UserIdentityBackend::Software,
        portable_alias,
        device2_seed.clone(),
    )
    .await
    .expect("re-open device 2's associated user signer");
    assert_eq!(
        device2_signer.key_id(),
        keyset.key_id,
        "device 2's signer resolves to the portable occurrence key"
    );
    assert!(
        signer_acts_for(&engine, device2_signer.key_id(), self_key).await,
        "device 2's signer acts for the SAME self (it is an active occurrence)"
    );

    // Cleanup.
    std::env::remove_var("CIRIS_HOME");
    std::env::remove_var("CIRIS_DATA_DIR");
    for d in [&home, &data, &usb, &device2_seed] {
        let _ = std::fs::remove_dir_all(d);
    }
}
