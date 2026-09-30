//! **A canonical relays the devices people announced** (CC 5.4.6,
//! CIRISConstitution#111; CIRISServer#655) — in process, against edge's own
//! advertise path.
//!
//! The native harness measured the fault (`harness/native/topologies/
//! selffiles.yaml`): person `one` owns D1 and D2, both announced; X peers D1
//! and the canonical C; X's public roster read of `one` lists ONE device. C
//! holds D2's key record and occurrence and offers neither, because the three
//! `SelfOwn` planes advertise only the node's self-publish set.
//!
//! This file drives the fix where it bites — `DirectoryStateAdapter::
//! local_refs(kind)` toward an UNCONSENTED peer, the exact call the responder
//! makes once per round — with the SAME selector compose installs
//! (`announced_relay::selector_for_sets` over `announced_relay_sets`). The
//! assertions are on content hashes, computed the way edge advertises them
//! (`sha256(serde_json::to_vec(row))`), so "offered" means the ref a peer's
//! Diff would actually want:
//!
//! 1. **The fault, reproduced**: with no selector, C offers X none of D2's rows.
//! 2. **The cure**: with the relay, C offers X D2's key record, its occurrence,
//!    and the owner's key record (without which X must refuse both).
//! 3. **The privacy negatives**: D3 — the same person's node, NOT announced —
//!    is in no relayed set and C offers X neither its key nor its occurrence;
//!    the person key is never an occurrence subject; and C's own rows are still
//!    offered (the answer replaces the self set, so it must contain it).
//!
//! The planes the relay must never touch — routes (`TransportDestination`),
//! consent grants and every self-scoped row (the Attestation plane) — are
//! pinned by the unit tests in `src/announced_relay.rs`
//! (`routes_and_every_other_plane_are_never_relayed`), because the selector
//! answers `None` for them before any row is read.
//!
//! `multi_thread` is load-bearing: `DirectoryStateAdapter` bridges edge's sync
//! trait to persist via `block_in_place`.

use std::collections::HashSet;
use std::sync::Arc;

use ciris_edge::replication::{
    DirectoryStateAdapter, EnvelopeKind, FederationDirectoryReplicationBridge, StateProvider,
};
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{cohort_scope, identity_type};
use ciris_persist::federation::SignedKeyRecord;
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use ciris_server::announced_relay::{announced_relay_sets, selector_for_sets, RelaySets};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

#[allow(dead_code)] // one fixture, several binaries: each uses a different subset
mod support {
    include!("support/drive_fixture.rs");
}
use support::*;

/// A device's substrate, keyed by its own hybrid signer.
async fn device_engine(alias: &str, ed: u8, pqc: u8) -> Arc<Engine> {
    let pqc_signer = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[pqc; 32], format!("{alias}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[ed; 32]),
        alias.to_string(),
        Some(pqc_signer),
        Some(format!("{alias}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine"),
    )
}

fn infra_scopes() -> Vec<String> {
    ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// The owner-binding at `self` — a node the person claimed and did NOT
/// announce (what `claim-remote` records before any announce).
async fn bind_unannounced(engine: &Engine, owner: &OwnerIdentity, node: &str) {
    let binding = ciris_server::auth::ownership::build_signed_owner_binding(
        &owner.signer().await,
        node,
        &infra_scopes(),
        cohort_scope::SELF,
    )
    .await
    .expect("build a self-scoped owner-binding");
    ciris_server::auth::ownership::apply_signed_owner_binding(
        engine,
        node,
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &binding,
    )
    .await
    .expect("record the unannounced owner-binding");
}

/// Register the owner's user key alone — `bind_owner` without the binding.
async fn register_owner_key(engine: &Engine, owner: &OwnerIdentity) {
    use ciris_persist::federation::types::{algorithm, KeyRecord};
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": owner.key_id });
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .expect("canonicalize owner envelope");
    let record = KeyRecord {
        key_id: owner.key_id.clone(),
        pubkey_ed25519_base64: owner.pubkey_ed25519_base64.clone(),
        pubkey_ml_dsa_65_base64: Some(owner.pubkey_ml_dsa_65_base64.clone()),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::USER.into(),
        identity_ref: owner.key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: owner.key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register the owner's user key");
}

/// The signed occurrence `device` provisioned for `owner`, as replication
/// would carry it.
async fn signed_occurrence_of(
    device: &Engine,
    owner: &str,
    occurrence: &str,
) -> ciris_persist::federation::SignedIdentityOccurrence {
    device
        .federation_directory()
        .list_signed_identity_occurrences_for(owner)
        .await
        .expect("signed occurrences")
        .into_iter()
        .find(|o| o.identity_occurrence.occurrence_key_id == occurrence)
        .expect("the provisioned occurrence rides the signed plane")
}

fn hash_of<T: serde::Serialize>(row: &T) -> [u8; 32] {
    Sha256::digest(serde_json::to_vec(row).expect("serialize row")).into()
}

/// The content hash edge advertises for `key_id`'s key record on `engine`.
async fn key_hash(engine: &Engine, key_id: &str) -> [u8; 32] {
    let served = engine
        .federation_directory()
        .list_signed_key_records_since(None, 10_000)
        .await
        .expect("key records");
    let rec = served
        .into_iter()
        .find(|s| s.record.key_id == key_id)
        .unwrap_or_else(|| panic!("{key_id} is held here"));
    hash_of(&SignedKeyRecord { record: rec.record })
}

/// The content hash edge advertises for the occurrence `occurrence` on `engine`.
async fn occurrence_hash(engine: &Engine, occurrence: &str) -> [u8; 32] {
    let served = engine
        .federation_directory()
        .list_signed_identity_occurrences_since(None, 10_000)
        .await
        .expect("occurrences");
    let row = served
        .into_iter()
        .find(|s| s.occurrence.identity_occurrence.occurrence_key_id == occurrence)
        .unwrap_or_else(|| panic!("occurrence {occurrence} is held here"));
    hash_of(&row.occurrence)
}

async fn offered(
    bridge: Arc<FederationDirectoryReplicationBridge>,
    peer: &str,
    kind: EnvelopeKind,
) -> HashSet<[u8; 32]> {
    DirectoryStateAdapter::new(bridge)
        .with_peer(peer.to_owned())
        .local_refs(kind)
        .await
        .into_iter()
        .map(|r| r.envelope_hash)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_canonical_offers_an_announced_device_to_a_stranger_and_never_an_unannounced_one() {
    init_tracing();
    let one = OwnerIdentity::mint().await;

    // D2 — announced (the owner-binding is at `federation`). Its occurrence
    // is provisioned on D2 itself and carried to C signed, as on the wire.
    let d2 = device_engine("relay-d2", 0xD1, 0xD2).await;
    let d2_key = register_self(&d2).await;
    bind_owner(&d2, &one, &d2_key).await;
    let (d2_occ, _) = ciris_server::backend::provision_engine_occurrence(&d2, &one.key_id)
        .await
        .expect("D2 provisions its occurrence");

    // D3 — the SAME person's node, claimed and NOT announced.
    let d3 = device_engine("relay-d3", 0xE1, 0xE2).await;
    let d3_key = register_self(&d3).await;
    register_owner_key(&d3, &one).await;
    bind_unannounced(&d3, &one, &d3_key).await;
    let (d3_occ, _) = ciris_server::backend::provision_engine_occurrence(&d3, &one.key_id)
        .await
        .expect("D3 provisions its occurrence");

    // C — the canonical. It holds what replication brought it: both devices'
    // keys, the owner's key, both owner-bindings at their own scopes, both
    // signed occurrences.
    let c = node_engine().await;
    let c_key = register_self(&c).await;
    seed_key(&c, &d2_key, 0xD1, 0xD2, identity_type::NODE).await;
    seed_key(&c, &d3_key, 0xE1, 0xE2, identity_type::NODE).await;
    bind_owner(&c, &one, &d2_key).await; // owner key + the ANNOUNCED binding
    bind_unannounced(&c, &one, &d3_key).await;
    for (dev, occ) in [(&d2, &d2_occ), (&d3, &d3_occ)] {
        c.federation_directory()
            .put_identity_occurrence(signed_occurrence_of(dev, &one.key_id, occ).await)
            .await
            .expect("C admits the device's signed occurrence");
    }

    // The relay sets C computes — the announced device and its owner, nothing
    // else.
    let sets = announced_relay_sets(&c).await.expect("relay sets");
    assert_eq!(
        sets,
        RelaySets {
            announced_nodes: vec![d2_key.clone()],
            owners: vec![one.key_id.clone()],
        },
        "exactly the announced device and its owner"
    );

    let x = "x-another-persons-node-never-consented";
    let own = vec![c_key.clone()];
    let bridge = |relay: Option<RelaySets>| {
        let own_for_provider = own.clone();
        Arc::new(
            FederationDirectoryReplicationBridge::new(c.federation_directory(), Arc::new(Vec::new))
                .with_local_key_id(Some(c_key.clone()))
                .with_self_provider(Some(Arc::new(move || own_for_provider.clone())))
                .with_kind_publish_selector(Some(selector_for_sets(own.clone(), relay))),
        )
    };

    let d2_key_h = key_hash(&c, &d2_key).await;
    let one_key_h = key_hash(&c, &one.key_id).await;
    let d3_key_h = key_hash(&c, &d3_key).await;
    let c_key_h = key_hash(&c, &c_key).await;
    let d2_occ_h = occurrence_hash(&c, &d2_occ).await;
    let d3_occ_h = occurrence_hash(&c, &d3_occ).await;

    // 1. THE FAULT: not a relay → C offers X its own record and nothing of
    //    one's.
    let keys = offered(bridge(None), x, EnvelopeKind::Key).await;
    assert!(
        keys.contains(&c_key_h),
        "C always offers its own key record"
    );
    assert!(
        !keys.contains(&d2_key_h) && !keys.contains(&one_key_h),
        "precondition: without the relay C withholds the announced device (the measured fault)"
    );
    let occs = offered(bridge(None), x, EnvelopeKind::IdentityOccurrence).await;
    assert!(
        !occs.contains(&d2_occ_h),
        "precondition: no relayed occurrence"
    );

    // 2. THE CURE: the relay offers the announced device, its occurrence, and
    //    the owner's key record — to a peer nothing consents to.
    let keys = offered(bridge(Some(sets.clone())), x, EnvelopeKind::Key).await;
    assert!(
        keys.contains(&c_key_h),
        "the relay still offers C's own record"
    );
    assert!(
        keys.contains(&d2_key_h),
        "the announced device's key is relayed"
    );
    assert!(keys.contains(&one_key_h), "its owner's key is relayed");
    let occs = offered(
        bridge(Some(sets.clone())),
        x,
        EnvelopeKind::IdentityOccurrence,
    )
    .await;
    assert!(
        occs.contains(&d2_occ_h),
        "the announced device's occurrence is relayed (and passes CIRISEdge#682's announce gate)"
    );

    // 3. THE NEGATIVES: the unannounced node is in no relayed set.
    assert!(
        !sets.announced_nodes.contains(&d3_key) && !sets.owners.contains(&d3_key),
        "an unannounced node is never in the relay sets"
    );
    assert!(
        !keys.contains(&d3_key_h),
        "C never relays an unannounced node's key record"
    );
    assert!(
        !occs.contains(&d3_occ_h),
        "C never relays an unannounced node's occurrence"
    );
}

/// The predicate for "the canonical": a node relays only when it holds
/// `infra:serve` from a root it trusts. A fresh node does not; the same node
/// after the root-side legs and its own acceptance does.
#[cfg(feature = "test-anchor")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_node_holding_infra_serve_from_a_trusted_root_relays() {
    init_tracing();
    let c = node_engine().await;
    let c_key = register_self(&c).await;
    let own = vec![c_key.clone()];
    assert!(
        !ciris_server::announced_relay::serves_infrastructure(&c, &own).await,
        "an ordinary node is not a relay"
    );

    let root = "relay-test-root";
    ciris_persist::federation::operational::test_support::establish_trust_root_side(
        c.federation_directory().as_ref(),
        root,
        &c_key,
        "infra:serve",
    )
    .await
    .expect("root-side trust legs: delegates_to(root -> C, infra:serve)");
    let core = ciris_persist::federation::envelope::EnvelopeCore::from_value(
        serde_json::json!({ "scope": ["infra:attest", "infra:serve"] }),
    )
    .expect("trust edge envelope");
    let mut accept = ciris_persist::federation::EmitAttestationInput::with_envelope(
        ciris_persist::federation::types::attestation_type::DELEGATES_TO,
        core,
        cohort_scope::FEDERATION,
    );
    accept.attested_key_id = Some(root.to_string());
    accept.subject_key_ids = vec![root.to_string()];
    c.emit_attestation_self(accept)
        .await
        .expect("C accepts the root");

    assert!(
        ciris_server::announced_relay::serves_infrastructure(&c, &own).await,
        "a node holding infra:serve from a root it accepts is a relay"
    );
}
