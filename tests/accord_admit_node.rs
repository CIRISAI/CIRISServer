//! QA gate for the accord **admit-node** op (CIRISServer#140 / CIRISVerify#162,
//! the v12.0 genesis-mesh "centipede tail").
//!
//! An accord holder (A1) admits a node to the trust root by **scrub-signing** its
//! registration ([`produce_scrubbed_key_record`]). This gate proves the produced
//! records are ROCK-SOLID against the substrate — emulating the accord-genesis QA
//! harness (software signers + register + verify; the hardware YubiKey+USB path is
//! operator-validated, so here A1 is a software [`HybridSigningIdentity`]):
//!
//!  1. A1's self-signed `steward,accord_holder` **anchor** record + the A1-scrubbed
//!     node record both survive persist's STRICT `register_federation_key` gate
//!     (byte-safety: the scrub-signature verifies over the canonical
//!     `registration_envelope` persist recomputes — the CIRISPersist#345 trap).
//!  2. The scrubbed node **ROOTS** at the accord anchor via `root_binding_anchored`
//!     (chain `node → A1`, A1's ed25519 pubkey ∈ the trusted anchor).
//!  3. Negative: with A1 NOT in the anchor set, it is rejected — the anchor gate bites.

use std::sync::Arc;

use base64::Engine as _;

use ciris_persist::federation::rooting::{root_binding_anchored, RootingVerdict};
use ciris_persist::federation::SignedKeyRecord as PersistSignedKeyRecord;
use ciris_persist::prelude::{Engine, LocalSigner};

use ciris_verify_core::federation_self_record::{
    produce_scrubbed_key_record, produce_self_key_record, ScrubTarget, SignedKeyRecord,
};
use ciris_verify_core::self_at_login::HybridSigningIdentity;

use ciris_keyring::MlDsa65SoftwareSigner;
use ed25519_dalek::SigningKey;

/// A fresh in-memory sqlite Engine (federation directory only — no genesis recording
/// needed for this gate).
async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0x5A; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0x5B; 32], "admit-node-qa-pqc".to_string())
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        "admit-node-qa".to_string(),
        Some(pqc),
        Some("admit-node-qa-pqc".to_string()),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer (sqlite::memory:)"),
    )
}

/// The verify producer returns verify's `SignedKeyRecord`; persist admits its own
/// (serde-compatible) shape. Round-trip through JSON — the same bridge the server's
/// accord anchor-mint uses (`serde_json::to_value(&v_rec)`).
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

#[tokio::test]
async fn admit_node_scrubbed_record_roots_at_accord_anchor() {
    let engine = node().await;
    let now = chrono::Utc::now().to_rfc3339();

    // A1 — a software stand-in for the portable YubiKey+USB holder (a `SelfSigner`).
    let a1 = HybridSigningIdentity::generate("humanity-accord-a1-test").expect("gen A1");

    // (1) A1's self-signed `steward,accord_holder` anchor → register (the rooting
    //     terminus persist bakes; here we admit it through the strict gate).
    let anchor = produce_self_key_record(&a1, "steward,accord_holder", &now)
        .await
        .expect("A1 self-signed anchor");
    let a1_ed_b64 = anchor.record.pubkey_ed25519_base64.clone();
    engine
        .register_federation_key(to_persist(&anchor))
        .await
        .expect("register A1 anchor (strict gate)");

    // The target node identity (its published hybrid pubkeys — what the operator
    // hands the holder from the node's self-key-record).
    let target = HybridSigningIdentity::generate("canonical-server-1-test").expect("gen target");
    let target_self = produce_self_key_record(&target, "node", &now)
        .await
        .expect("target self record");
    let target_ed_b64 = target_self.record.pubkey_ed25519_base64.clone();
    let target_mldsa_b64 = target_self
        .record
        .pubkey_ml_dsa_65_base64
        .clone()
        .expect("target ml_dsa pubkey");

    // (2) A1 scrub-signs the target's registration (the admit-node op).
    let scrubbed = produce_scrubbed_key_record(
        &a1,
        ScrubTarget {
            key_id: "canonical-server-1-test".to_string(),
            pubkey_ed25519_base64: target_ed_b64.clone(),
            pubkey_ml_dsa_65_base64: target_mldsa_b64,
            identity_type: "node".to_string(),
        },
        &now,
    )
    .await
    .expect("A1 scrub-signs the target");

    // The record's identity is the TARGET's; the scrub is the HOLDER's.
    assert_eq!(scrubbed.record.key_id, "canonical-server-1-test");
    assert_eq!(
        scrubbed.record.scrub_key_id,
        a1.key_id(),
        "scrubbed by A1, NOT self-signed"
    );

    // Byte-safety: the scrub-signature must verify over the canonical envelope
    // persist recomputes — the strict gate accepts it (would reject on any drift).
    engine
        .register_federation_key(to_persist(&scrubbed))
        .await
        .expect("register scrubbed node (strict gate — proves byte-safety)");

    // (3) The node ROOTS: chain `canonical-server-1-test → A1`, A1 ∈ the anchor.
    let backend = engine.sqlite_backend().expect("sqlite backend");
    let anchor_set = [ed32(&a1_ed_b64)];
    let verdict = root_binding_anchored(
        backend.as_ref(),
        "canonical-server-1-test",
        &target_ed_b64,
        &anchor_set,
    )
    .await;
    assert!(
        matches!(verdict, RootingVerdict::Confirmed { .. }),
        "scrubbed node must ROOT at the accord anchor, got {verdict:?}"
    );

    // (4) Negative — a DIFFERENT anchor set: the chain terminates at a real
    //     steward/accord_holder shape whose pubkey is NOT pinned ⇒ rejected.
    let wrong_anchor = [[0x11u8; 32]];
    let verdict_wrong = root_binding_anchored(
        backend.as_ref(),
        "canonical-server-1-test",
        &target_ed_b64,
        &wrong_anchor,
    )
    .await;
    assert!(
        !matches!(verdict_wrong, RootingVerdict::Confirmed { .. }),
        "must NOT root when A1 is not a pinned anchor, got {verdict_wrong:?}"
    );
}

/// The PRODUCER path (CIRISServer#150 / CIRISPersist#351): a node that already
/// holds its boot-time **self-signed** own-key row upgrades that row IN PLACE to
/// the accord-holder-scrubbed record via `Engine::adopt_scrub_upgrade` (the old
/// `register_federation_key` is `ON CONFLICT DO NOTHING` and would have left the
/// self-signed row). After the upgrade the row ROOTS at the anchor, and a second
/// apply is idempotent — exactly what admit-node relies on to publish an anchored
/// record over the Key plane.
#[tokio::test]
async fn adopt_scrub_upgrade_promotes_self_signed_own_row_and_roots() {
    use ciris_persist::federation::register::AdoptScrubOutcome;

    let engine = node().await;
    let now = chrono::Utc::now().to_rfc3339();

    let a1 = HybridSigningIdentity::generate("humanity-accord-a1-test").expect("gen A1");
    let anchor = produce_self_key_record(&a1, "steward,accord_holder", &now)
        .await
        .expect("A1 anchor");
    let a1_ed_b64 = anchor.record.pubkey_ed25519_base64.clone();
    engine
        .register_federation_key(to_persist(&anchor))
        .await
        .expect("register A1 anchor");

    // The node's boot-time state: its OWN row, SELF-signed.
    let target = HybridSigningIdentity::generate("canonical-server-1-test").expect("gen target");
    let target_self = produce_self_key_record(&target, "node", &now)
        .await
        .expect("target self record");
    let target_ed_b64 = target_self.record.pubkey_ed25519_base64.clone();
    let target_mldsa_b64 = target_self
        .record
        .pubkey_ml_dsa_65_base64
        .clone()
        .expect("target ml_dsa");
    engine
        .register_federation_key(to_persist(&target_self))
        .await
        .expect("register target SELF-signed own row");

    // Precondition: a self-signed row does NOT root.
    let backend = engine.sqlite_backend().expect("sqlite backend");
    let anchor_set = [ed32(&a1_ed_b64)];
    assert!(
        !matches!(
            root_binding_anchored(
                backend.as_ref(),
                "canonical-server-1-test",
                &target_ed_b64,
                &anchor_set
            )
            .await,
            RootingVerdict::Confirmed { .. }
        ),
        "precondition: the self-signed own row must NOT root yet"
    );

    // A1 scrub-signs the target, and the node ADOPTS the upgrade onto its own row.
    let scrubbed = produce_scrubbed_key_record(
        &a1,
        ScrubTarget {
            key_id: "canonical-server-1-test".to_string(),
            pubkey_ed25519_base64: target_ed_b64.clone(),
            pubkey_ml_dsa_65_base64: target_mldsa_b64,
            identity_type: "node".to_string(),
        },
        &now,
    )
    .await
    .expect("A1 scrub-signs target");

    let outcome = engine
        .adopt_scrub_upgrade(to_persist(&scrubbed))
        .await
        .expect("adopt_scrub_upgrade must succeed on a self-signed own row");
    assert!(
        matches!(outcome, AdoptScrubOutcome::Upgraded),
        "first adopt upgrades the self-signed row, got {outcome:?}"
    );

    // Now the SAME key_id ROOTS — the Key plane would publish an anchored record.
    assert!(
        matches!(
            root_binding_anchored(
                backend.as_ref(),
                "canonical-server-1-test",
                &target_ed_b64,
                &anchor_set
            )
            .await,
            RootingVerdict::Confirmed { .. }
        ),
        "after adopt the own row must ROOT at the accord anchor"
    );

    // Idempotent: re-applying the same outbox record is a no-op (second boot).
    let again = engine
        .adopt_scrub_upgrade(to_persist(&scrubbed))
        .await
        .expect("re-adopt must not error");
    assert!(
        matches!(again, AdoptScrubOutcome::AlreadyAdopted),
        "second adopt is idempotent, got {again:?}"
    );
}
