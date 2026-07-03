//! TRUE end-to-end QA gate for the genesis-mesh SEED via the KEY PLANE
//! (deploy-with-confidence). Complements `mesh_seed_e2e.rs` (which covers the
//! relay/trace Attestation path); this proves the admit-node → rooting loop for
//! **key records** across TWO independent engines, driving the REAL edge
//! replication bridge (no mocks of our own logic):
//!
//!   1. **Seed** — the baked HUMANITY_ACCORD anchor (A1) is present on BOTH nodes
//!      (persist v12.0.2 first-boot seed, simulated here by registering A1).
//!   2. **Producer** (CIRISServer#150 / CIRISPersist#351) — node A holds its
//!      boot-time SELF-signed own row, then `Engine::adopt_scrub_upgrade` upgrades
//!      it IN PLACE to the A1-scrubbed (anchored) record.
//!   3. **Publish-own** (CIRISEdge#257 / edge v8.6.x) — A's replication bridge with
//!      the Key-plane `key_selector` = A's own key_id advertises A's OWN anchored
//!      record over `EnvelopeKind::Key` (`list_envelope_refs` + `fetch_envelope_bytes`).
//!   4. **Receive** — node B applies those exact wire bytes via the bridge
//!      (`apply_envelope_bytes`) — the receive side of anti-entropy.
//!   5. **Root** — B now ROOTS A at the accord anchor (`root_binding_anchored`),
//!      which it could NOT do before receiving A's record.
//!
//! The Reticulum transport hop + the scheduler cadence are edge's own tested
//! concerns; this gate proves OUR composition (producer + publish-set selection +
//! apply + root) end-to-end and deterministically, with software keys.

use std::sync::Arc;

use base64::Engine as _;

use ciris_edge::replication::{
    BridgeConfig, CohortProvider, EnvelopeKind, FederationDirectoryReplicationBridge,
    ReplicationDirectory,
};
use ciris_persist::federation::rooting::{root_binding_anchored, RootingVerdict};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::federation::SignedKeyRecord as PersistSignedKeyRecord;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::store::sqlite::SqliteBackend;

use ciris_verify_core::federation_self_record::{
    produce_scrubbed_key_record, produce_self_key_record, ScrubTarget, SignedKeyRecord,
};
use ciris_verify_core::self_at_login::HybridSigningIdentity;

use ciris_keyring::MlDsa65SoftwareSigner;
use ed25519_dalek::SigningKey;

/// A fresh in-memory sqlite Engine with a distinct signer seed.
async fn engine(seed: u8, alias: &str) -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0xFF; 32], format!("{alias}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        alias.to_string(),
        Some(pqc),
        Some(format!("{alias}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer (sqlite::memory:)"),
    )
}

fn to_persist(v: &SignedKeyRecord) -> PersistSignedKeyRecord {
    serde_json::from_value(serde_json::to_value(v).expect("serialize verify record"))
        .expect("deserialize into persist record")
}

fn ed32(b64: &str) -> [u8; 32] {
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("b64 ed25519")
        .try_into()
        .expect("32-byte ed25519")
}

async fn roots(backend: &SqliteBackend, key_id: &str, ed_b64: &str, anchor: &[[u8; 32]]) -> bool {
    matches!(
        root_binding_anchored(backend, key_id, ed_b64, anchor).await,
        RootingVerdict::Confirmed { .. }
    )
}

#[tokio::test]
async fn admit_node_seed_replicates_and_peer_roots_end_to_end() {
    let node_a_key = "canonical-node-a-test";
    let node_b_key = "canonical-node-b-test";

    let engine_a = engine(0xA0, node_a_key).await;
    let engine_b = engine(0xB0, node_b_key).await;
    let now = chrono::Utc::now().to_rfc3339();

    // (1) SEED — A1, the baked HUMANITY_ACCORD anchor, present on BOTH nodes.
    let a1 = HybridSigningIdentity::generate("humanity-accord-a1-test").expect("gen A1");
    let a1_anchor = produce_self_key_record(&a1, "steward,accord_holder", &now)
        .await
        .expect("A1 anchor");
    let a1_ed = ed32(&a1_anchor.record.pubkey_ed25519_base64);
    for e in [&engine_a, &engine_b] {
        e.register_federation_key(to_persist(&a1_anchor))
            .await
            .expect("seed A1 anchor");
    }

    // Node A's identity + its BOOT-time SELF-signed own row (what register_self_key
    // writes) in A's directory.
    let node_a = HybridSigningIdentity::generate(node_a_key).expect("gen node A");
    let a_self = produce_self_key_record(&node_a, "node", &now)
        .await
        .expect("A self record");
    let a_ed_b64 = a_self.record.pubkey_ed25519_base64.clone();
    let a_mldsa_b64 = a_self
        .record
        .pubkey_ml_dsa_65_base64
        .clone()
        .expect("A ml_dsa");
    engine_a
        .register_federation_key(to_persist(&a_self))
        .await
        .expect("A self-signed own row");

    let anchor_set = [a1_ed];

    // Precondition: B cannot root A (it has never seen A's record).
    assert!(
        !roots(
            engine_b.sqlite_backend().unwrap().as_ref(),
            node_a_key,
            &a_ed_b64,
            &anchor_set
        )
        .await,
        "precondition: B must NOT root A before receiving A's record"
    );

    // (2) PRODUCER — A1 scrub-signs A; A adopts the upgrade onto its OWN row.
    let a_scrubbed = produce_scrubbed_key_record(
        &a1,
        ScrubTarget {
            key_id: node_a_key.to_string(),
            pubkey_ed25519_base64: a_ed_b64.clone(),
            pubkey_ml_dsa_65_base64: a_mldsa_b64,
            identity_type: "node".to_string(),
        },
        &now,
    )
    .await
    .expect("A1 scrub-signs A");
    engine_a
        .adopt_scrub_upgrade(to_persist(&a_scrubbed))
        .await
        .expect("A adopts the scrub upgrade onto its own row");

    // A's own row roots LOCALLY now — the producer worked.
    assert!(
        roots(
            engine_a.sqlite_backend().unwrap().as_ref(),
            node_a_key,
            &a_ed_b64,
            &anchor_set
        )
        .await,
        "A's own row must root locally after adopt"
    );

    // (3) PUBLISH-OWN — A's bridge with the Key-plane selector = A's own key_id.
    let a_dir: Arc<dyn FederationDirectory> = engine_a.federation_directory();
    let cohort_a: CohortProvider = Arc::new(move || vec![node_b_key.to_string()]);
    let key_sel: CohortProvider = Arc::new(move || vec![node_a_key.to_string()]);
    let a_bridge =
        FederationDirectoryReplicationBridge::with_config(a_dir, cohort_a, BridgeConfig::default())
            .with_key_selector(Some(key_sel));

    let refs = a_bridge.list_envelope_refs(EnvelopeKind::Key).await;
    assert_eq!(
        refs.len(),
        1,
        "A publishes exactly its OWN record on the Key plane (selector-scoped), got {refs:?}"
    );
    let bytes = a_bridge
        .fetch_envelope_bytes(EnvelopeKind::Key, &refs[0].envelope_hash)
        .await
        .expect("A serves its own record bytes");

    // (4) RECEIVE — B applies the exact wire bytes via its bridge (anti-entropy RX).
    let b_dir: Arc<dyn FederationDirectory> = engine_b.federation_directory();
    let b_bridge = FederationDirectoryReplicationBridge::with_config(
        b_dir,
        Arc::new(move || vec![node_a_key.to_string()]),
        BridgeConfig::default(),
    );
    let admitted = b_bridge
        .apply_envelope_bytes(EnvelopeKind::Key, &bytes)
        .await;
    assert!(
        admitted,
        "B must admit A's anchored record (validates against seeded A1)"
    );

    // (5) ROOT — B now roots A at the accord anchor. THE SEED CLOSED.
    assert!(
        roots(
            engine_b.sqlite_backend().unwrap().as_ref(),
            node_a_key,
            &a_ed_b64,
            &anchor_set
        )
        .await,
        "after receiving A's anchored record, B MUST root A — the mesh seed is complete"
    );

    // Negative: B still won't root A under a WRONG anchor set (the gate bites).
    assert!(
        !roots(
            engine_b.sqlite_backend().unwrap().as_ref(),
            node_a_key,
            &a_ed_b64,
            &[[0x11u8; 32]]
        )
        .await,
        "B must NOT root A when A1 is not the pinned anchor"
    );
}
