//! CIRISServer#606 — heal a pre-#659 owner registration record through
//! persist's same-key rebind door (v44.7.0, CIRISPersist#864).
//!
//! The production canonical held one `user` registration whose envelope was
//! `{"key_id": …}` and nothing else (2026-07-02, before persist required the
//! subject binding). Every verify v15.2.0 peer refused it at admission, and
//! because that user stewards nine nodes the record rode the first identity
//! round to every new peer. Persist's key door refused a re-registration
//! (`Conflict: different content`), so the holder could not repair it until
//! the rebind door existed. This pins the server half:
//!
//! 1. an UNBOUND self-signed owner record is refused by a fresh peer engine;
//! 2. `rebind_owner_key_record`, holding the owner's pen, rebinds it in place
//!    (same key, pubkeys, identity_type, valid_from) — and reports `Rebound`;
//! 3. the rebound record now admits on the peer;
//! 4. a second call is `Bound` and writes nothing; a bound record from the
//!    start is `Bound` on the first call;
//! 5. a pen that does not hold the owner's pubkeys is refused before any write.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::admission::verify_envelope_binds_subject;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

use ciris_server::auth::ownership::{rebind_owner_key_record, OwnerKeyRecordState};

fn seed(label: &str, n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&Sha256::digest(format!("{label}:{n}").as_bytes())[..32]);
    s
}

fn signer_for(alias: &str) -> LocalSigner {
    let ed = SigningKey::from_bytes(&seed(alias, 1));
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&seed(alias, 2), format!("{alias}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        ed,
        alias.to_string(),
        Some(pqc),
        Some(format!("{alias}-pqc")),
    )
}

/// A self-signed registration record for `signer`. `bound` = the envelope
/// binds its subject (#659); `false` = the pre-#659 `{key_id}`-only shape.
async fn record_for(signer: &LocalSigner, ident: &str, bound: bool) -> SignedKeyRecord {
    let key_id = signer.derived_key_id();
    let probe = signer.sign_hybrid(b"probe").await.expect("probe");
    let ed_pub = B64.encode(&probe.classical.public_key);
    let pqc_pub = B64.encode(&probe.pqc.public_key);
    let mut envelope = serde_json::json!({ "key_id": key_id });
    if bound {
        ciris_persist::federation::admission::bind_subject_into_envelope(
            &mut envelope,
            &key_id,
            ident,
            &ed_pub,
            Some(&pqc_pub),
            None,
        )
        .expect("bind subject");
    }
    let canonical = ceg_produce_canonicalize(&envelope).expect("canon");
    let sig = signer.sign_hybrid(&canonical).await.expect("sign");
    let now = chrono::Utc::now();
    SignedKeyRecord {
        record: KeyRecord {
            key_id: key_id.clone(),
            pubkey_ed25519_base64: ed_pub,
            pubkey_ml_dsa_65_base64: Some(pqc_pub),
            algorithm: algorithm::HYBRID.into(),
            identity_type: ident.to_string(),
            identity_ref: key_id.clone(),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(Sha256::digest(&canonical)),
            scrub_signature_classical: B64.encode(&sig.classical.signature),
            scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
            scrub_key_id: key_id,
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        },
    }
}

async fn engine_as(alias: &str) -> Arc<Engine> {
    Arc::new(
        Engine::with_signer(Arc::new(signer_for(alias)), "sqlite::memory:")
            .await
            .expect("engine"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unbound_owner_record_is_rebound_in_place_and_then_admits_on_a_peer() {
    let node = engine_as("node-for-the-rebind-test").await;
    let owner = signer_for("owner-with-a-pre-659-record");
    let owner_id = owner.derived_key_id();

    // ── 1. the pre-#659 row, exactly as the canonical held it ────────────
    let unbound = record_for(&owner, identity_type::USER, false).await;
    node.federation_directory()
        .put_public_key(unbound.clone())
        .await
        .expect("the bypass door stores an unbound row, as 2026-07 did");
    let stored = node
        .federation_directory()
        .lookup_public_key(&owner_id)
        .await
        .expect("lookup")
        .expect("stored");
    assert!(
        verify_envelope_binds_subject(&stored).is_err(),
        "fixture: the stored record must be UNBOUND"
    );
    let peer = engine_as("a-fresh-peer-on-verify-15-2").await;
    let refused = peer.apply_replicated_key_record(unbound.clone()).await;
    assert!(
        !matches!(
            refused,
            Ok(ciris_persist::federation::register::ReplicatedKeyOutcome::Inserted)
        ),
        "a fresh peer must REFUSE the unbound record — that is the four-run \
         `held 0` (CIRISAgent#1178): {refused:?}"
    );

    // ── 2. the heal, with the owner's own pen ─────────────────────────────
    let state = rebind_owner_key_record(&node, &owner)
        .await
        .expect("rebind runs");
    assert_eq!(state, OwnerKeyRecordState::Rebound);
    let healed = node
        .federation_directory()
        .lookup_public_key(&owner_id)
        .await
        .expect("lookup")
        .expect("still stored");
    assert!(
        verify_envelope_binds_subject(&healed).is_ok(),
        "the record now binds its subject"
    );
    assert_eq!(healed.key_id, stored.key_id);
    assert_eq!(healed.pubkey_ed25519_base64, stored.pubkey_ed25519_base64);
    assert_eq!(
        healed.pubkey_ml_dsa_65_base64,
        stored.pubkey_ml_dsa_65_base64
    );
    assert_eq!(healed.identity_type, stored.identity_type);
    assert_eq!(healed.identity_ref, stored.identity_ref);
    assert_eq!(
        healed.valid_from, stored.valid_from,
        "a rebind changes the claim's binding, never what it claims (persist rule 3)"
    );
    assert_ne!(healed.original_content_hash, stored.original_content_hash);
    assert_eq!(healed.scrub_key_id, owner_id, "self-signed by the holder");

    // ── 3. the rebound record admits on the peer ──────────────────────────
    let admitted = peer
        .apply_replicated_key_record(SignedKeyRecord {
            record: healed.clone(),
        })
        .await
        .expect("peer applies");
    assert!(
        matches!(
            admitted,
            ciris_persist::federation::register::ReplicatedKeyOutcome::Inserted
        ),
        "a verify v15.2.0 peer admits the rebound record: {admitted:?}"
    );

    // ── 4. idempotent; a bound-from-birth record is Bound on the first call ─
    assert_eq!(
        rebind_owner_key_record(&node, &owner)
            .await
            .expect("second call"),
        OwnerKeyRecordState::Bound
    );
    let modern = signer_for("owner-registered-after-659");
    node.register_federation_key(record_for(&modern, identity_type::USER, true).await)
        .await
        .expect("a bound record registers through the gate");
    assert_eq!(
        rebind_owner_key_record(&node, &modern)
            .await
            .expect("bound owner"),
        OwnerKeyRecordState::Bound,
        "nothing to heal; nothing written"
    );

    // ── 5. the wrong pen is refused before any write ─────────────────────
    let stranger = signer_for("owner-with-a-pre-659-record-but-a-different-seed-x");
    let other_unbound_owner = signer_for("second-unbound-owner");
    node.federation_directory()
        .put_public_key(record_for(&other_unbound_owner, identity_type::USER, false).await)
        .await
        .expect("a second unbound row");
    let absent = rebind_owner_key_record(&node, &stranger)
        .await
        .expect("no row for a stranger");
    assert_eq!(
        absent,
        OwnerKeyRecordState::Absent,
        "a pen with no record heals nothing"
    );
    let still_unbound = node
        .federation_directory()
        .lookup_public_key(&other_unbound_owner.derived_key_id())
        .await
        .expect("lookup")
        .expect("row");
    assert!(
        verify_envelope_binds_subject(&still_unbound).is_err(),
        "no other owner's record was touched"
    );
}
