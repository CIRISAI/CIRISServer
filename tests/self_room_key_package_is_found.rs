//! **A self room's KeyPackage, once shared, is found by the lookup the creator
//! uses** (0.5.218, the self-files ladder's `tick=Added(0)`).
//!
//! On the CI ladder the creator (node-a) HELD two `chat:key_package:v1` rows
//! attested by the joiner (node-c) — counted in its own sqlite — and still
//! added nobody for fifteen minutes: `chat::key_package_from(dir, node-c,
//! room)` returned `None`. This runs the same three steps in-process on one
//! engine: build the row the way `self_room_drive::publish_key_package` does,
//! share it into the self room the way `contacts_chat::share_in` does, then
//! read it the way `add_members` does. Every intermediate state is printed, so
//! a red names the step.

use std::sync::Arc;

#[allow(dead_code)]
mod support {
    include!("support/drive_fixture.rs");
}
use support::*;

#[tokio::test]
async fn a_shared_self_room_key_package_is_found_by_the_creators_lookup() {
    use ciris_edge::replication::attestation_bind::{share, CrossingBasis, Signers};
    use ciris_persist::federation::SignedAttestation;

    init_tracing();
    let engine = node_engine().await;
    let node = register_self(&engine).await;
    let owner = OwnerIdentity::mint().await;
    bind_owner(&engine, &owner, &node).await;
    let signer = node_edge_signer(&engine).await;
    let dir = engine.federation_directory();

    let room = ciris_edge::self_room::room(&owner.key_id);
    let room_id = room.content_group_id().to_owned();
    let row = ciris_edge::chat::key_package_attestation_in(
        &signer,
        &room,
        b"key-package-bytes",
        chrono::Utc::now(),
    )
    .await
    .expect("build the KeyPackage row");
    eprintln!(
        "BUILT id={} scope={} tier={} envelope_keys={:?}",
        row.attestation_id,
        row.cohort_scope,
        row.tier,
        row.attestation_envelope
            .as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>())
    );
    dir.put_attestation_authored(SignedAttestation {
        attestation: row.clone(),
    })
    .await
    .expect("local put");

    let before = ciris_edge::chat::key_package_from(&*dir, &node, &room_id)
        .await
        .expect("lookup");
    eprintln!("LOOKUP before share: {}", before.is_some());

    let crossing = share(
        &*dir,
        &row,
        room.widen_to(),
        CrossingBasis::ProducerAuthority,
        Signers {
            node: &signer,
            actor: None,
        },
    )
    .await;
    eprintln!("SHARE: {crossing:?}");

    for a in dir.list_attestations_by(&node).await.expect("list") {
        eprintln!(
            "ROW id={} scope={} tier={} refs={:?} target={:?} has_bytes={}",
            a.attestation_id,
            a.cohort_scope,
            a.tier,
            a.attestation_envelope.get("references_attestation_id"),
            ciris_persist::federation::admission::envelope_cohort_target(&a.attestation_envelope),
            a.attestation_envelope.get("mls_bytes").is_some(),
        );
    }

    let after = ciris_edge::chat::key_package_from(&*dir, &node, &room_id)
        .await
        .expect("lookup");
    assert_eq!(
        after.as_deref(),
        Some(&b"key-package-bytes"[..]),
        "the creator's lookup does not find the joiner's KeyPackage after the share"
    );
    let _ = Arc::clone(&engine);
}
