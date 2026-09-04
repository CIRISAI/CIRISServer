//! **The test-anchor block in `docker-compose.yml` must root under THIS repo's
//! pins** — checked in about a second, not fifteen minutes into a mesh run.
//!
//! The six `CIRIS_TEST_TRUST_ROOT*` values are one synthetic trust root: anchor
//! pubkeys, and a self-scrub signature pair over the terminus row's
//! `registration_envelope`. persist BUILDS that envelope
//! (`genesis::test_anchor_registration_envelope`) and pastes the env-supplied
//! scrub onto the row it seeds; verify then checks the scrub over the STORED
//! bytes. So the scrub only verifies under the persist/verify pair it was
//! minted against — bump a pin that changes the envelope and every node in the
//! harness roots `Advisory`, the Attestation plane goes dark, and the trace
//! ladder reads `arrive=0` with nothing in the logs but a token.
//!
//! That happened. The block was byte-identical to what our generator printed —
//! and the generator was the stale copy, signing a two-key literal persist had
//! outgrown. CIRISEdge hit the mirror image two days earlier by transcribing
//! OUR block (CIRISEdge 82d8650). Three copies of one minter; one drifted.
//!
//! This is not a generator. It runs persist's real `root_binding` — the walk the
//! canonical runs when the agent announces — against a directory seeded exactly
//! as a harness node seeds one, and asserts the terminus CONFIRMS. When it fails
//! it prints persist's `detail`, which names the link and quotes verify. The
//! block itself is minted by the substrate's generator (CIRISPersist#805 asks
//! persist to ship it); until then CIRISEdge's `tests/anchor_block_generate.rs`
//! mints the identical bytes ONLY while it pins the same persist + verify as
//! this repo — Ed25519 is deterministic, so compare `SCRUB` to know.
#![cfg(feature = "test-anchor")]

use std::collections::BTreeMap;

fn compose_block() -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/harness/mesh-repro/docker-compose.yml"
    ))
    .expect("read harness/mesh-repro/docker-compose.yml");
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some((k, v)) = t.split_once(": \"") {
            if k.starts_with("CIRIS_TEST") && v.ends_with('"') {
                out.insert(k.to_owned(), v.trim_end_matches('"').to_owned());
            }
        }
    }
    out
}

#[tokio::test]
async fn the_compose_anchor_block_roots_under_this_repos_pins() {
    use ciris_persist::federation::rooting::{root_binding, RootingVerdict};

    let block = compose_block();
    for k in [
        "CIRIS_TESTING_MODE",
        "CIRIS_TEST_TRUST_ROOT",
        "CIRIS_TEST_TRUST_ROOT_PQC",
        "CIRIS_TEST_TRUST_ROOT_SCRUB",
        "CIRIS_TEST_TRUST_ROOT_SCRUB_PQC",
        "CIRIS_TEST_TRUST_ROOT_SEED",
    ] {
        let v = block
            .get(k)
            .unwrap_or_else(|| panic!("{k} missing from the compose block — all six are required"));
        // An override from the caller wins, so the mutation check below can hand
        // in a stale scrub without editing the file.
        if std::env::var(k).is_err() {
            std::env::set_var(k, v);
        }
    }

    // Open the engine the way a harness node does: migrations run, and the
    // genesis accord holders are seeded from `effective_accord_holder_records`,
    // which resolves to persist's SYNTHETIC test-anchor rows while the block is
    // armed — carrying the env-supplied scrub. Nothing is hand-seeded here, so
    // this is the row the canonical actually holds.
    let pqc = std::sync::Arc::new(
        ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(
            &[0x51; 32],
            "pin-node-pqc".to_string(),
        )
        .expect("ML-DSA-65 seed"),
    );
    let signer = std::sync::Arc::new(ciris_persist::prelude::LocalSigner::from_parts(
        ed25519_dalek::SigningKey::from_bytes(&[0x50; 32]),
        "pin-node".to_string(),
        Some(pqc),
        Some("pin-node-pqc".to_string()),
    ));
    let engine = ciris_persist::prelude::Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("in-memory engine");
    let dir = engine.federation_directory();
    let terminus = dir
        .lookup_public_key("test-accord-holder-0")
        .await
        .expect("lookup terminus")
        .expect("the engine seeds test-accord-holder-0 while the block is armed");

    // The walk the canonical runs when a peer announces.
    match root_binding(&*dir, &terminus.key_id, &terminus.pubkey_ed25519_base64).await {
        RootingVerdict::Confirmed { .. } => {}
        RootingVerdict::Rejected { rejection } => panic!(
            "the compose anchor block does NOT root under this repo's pins: {} — {rejection:?}\n\
             The scrub in harness/mesh-repro/docker-compose.yml was minted against a \
             different persist/verify pair. Re-mint it against the pins in Cargo.lock \
             (see this file's header for where the generator lives) and paste all six \
             values; the anchor pubkeys and SEED will not change, the two SCRUB values will.",
            rejection.kind()
        ),
    }
}
