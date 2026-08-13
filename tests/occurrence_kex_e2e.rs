//! End-to-end proof of the **signed occurrence-KEX plane** (occurrence-KEX arc:
//! CIRISVerify#183 → CIRISPersist#418 → CIRISEdge#305/#307 → CIRISServer#227).
//!
//! The 0.5.99 predecessor of this test proved the replication mechanics but baked in
//! the two assumptions the arc closed: it derived enc keys from a RAW seed in the test
//! body (the custody gap) and published an UNSIGNED occurrence (the authenticity gap).
//! This version validates the assumptions, not just the mechanism:
//!
//!   1. **Custody path** — B's enc pubkeys come from `SelfEncKeys` (keyring), opened
//!      by alias over a SEALED seed. No raw seed and no private half appears anywhere
//!      in the publish or decrypt paths of this test.
//!   2. **Signed publish** — B's self-occurrence envelope (with the REQUIRED
//!      `transport_destination` member + `encryption_pubkeys`) is signed by B's own
//!      hybrid identity via `produce_signed_identity_occurrence` and admitted through
//!      persist's ONE fail-secure gate (`put_identity_occurrence` →
//!      `verify_signed_identity_occurrence`: hybrid sig over JCS, dest-hash recompute,
//!      C4 key separation, signer_acts_for).
//!   3. **Adversarial** — Mallory (a registered, unrelated key — i.e. a compromised
//!      consented peer) signs an occurrence claiming B's identity with HER enc keys:
//!      REJECTED at the gate. An unsigned/tampered envelope: REJECTED.
//!   4. **Byte-exact signed replication** — the edge bridge (publish-own
//!      `occurrence_selector`) advertises B's occurrence from
//!      `list_signed_identity_occurrences_for` (the v14.1.0 signed re-read), one
//!      anti-entropy hop carries the SAME signed tuple to A, and A's gate re-verifies
//!      the SAME signature before admitting.
//!   5. **Rotation** — a re-assert with newer `asserted_at` supersedes (last-signed-
//!      wins); a stale replay of the old signed tuple is a no-op.
//!   6. **Seal round-trip** — A initiates a hybrid session to B's RESOLVED pubkeys;
//!      B recomputes the identical session key via `SelfEncKeys::kex_respond` —
//!      decrypt INSIDE custody, no private key material in the test body.
//!
//! Trusted-local rows (`put_identity_occurrence_local`, the device-bind path) are also
//! asserted NOT to signed-replicate — you can only replicate what was signed-put.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;

use ciris_edge::replication::{
    CohortProvider, EnvelopeKind, FederationDirectoryReplicationBridge, ReplicationDirectory,
};
use ciris_edge::transport::federation_session::{FederationSession, KexAlgorithm, PeerKexPubkeys};
use ciris_keyring::self_enc_keys::SelfEncKeys;
use ciris_keyring::{MlDsa65SoftwareSigner, SealedEd25519Signer};
use ciris_persist::federation::types::{
    identity_type, IdentityOccurrence, OccurrenceTransportBinding, SignedIdentityOccurrence,
};
use ciris_persist::federation::{EncryptionPubkeys, FederationDirectory};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_verify_core::transport_binding::{
    compute_destination_hash, produce_signed_identity_occurrence,
};

const NODE_A_KEY_ID: &str = "kex-node-a";
const NODE_B_KEY_ID: &str = "kex-node-b";
const MALLORY_KEY_ID: &str = "kex-mallory";
/// B's Ed25519 base seed. Used EXACTLY ONCE outside custody: at fixture mint time to
/// seal it into the keyring (`SealedEd25519Signer::adopt`) — the legitimate mint-time
/// raw-seed touch. Everything after goes through `SelfEncKeys` by alias.
const NODE_B_ED_SEED: [u8; 32] = [0xB0; 32];
const NODE_B_ML_SEED: [u8; 32] = [0xB1; 32];
const MALLORY_ED_SEED: [u8; 32] = [0xE1; 32];
const MALLORY_ML_SEED: [u8; 32] = [0xE2; 32];

async fn engine(key_id: &str, ed_seed: [u8; 32], ml_seed: [u8; 32]) -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&ml_seed, format!("{key_id}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&ed_seed),
        key_id.to_string(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer(sqlite::memory:)"),
    )
}

/// Admit a hybrid software node identity through the ONE key door
/// (CIRISServer#402), which writes a registration envelope that BINDS ITS SUBJECT
/// — key_id, identity_type and both pubkeys. The `{"key_id": …}` envelope this
/// fixture used to hand-roll vouched for none of the rest, so its signature stood
/// for any record it was pasted onto, and persist v31 refuses it
/// (CIRISPersist#659).
async fn register_node(engine: &Engine, key_id: &str, ed_seed: &[u8; 32], ml_seed: &[u8; 32]) {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(ml_seed, format!("{key_id}-pqc"))
            .expect("ML-DSA seed"),
    );
    let signer = LocalSigner::from_parts(
        SigningKey::from_bytes(ed_seed),
        key_id.to_string(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    );
    ciris_server::attest::register_key(
        engine,
        ciris_server::attest::KeySigner::Local(&signer),
        key_id,
        identity_type::NODE,
        serde_json::Value::Null,
    )
    .await
    .unwrap_or_else(|e| panic!("register {key_id}: {e}"));
}

/// A hybrid `SelfSigner` over software seeds (the portable-mint pattern) — used to
/// SIGN occurrence envelopes in the test (B legitimately; Mallory adversarially).
fn hybrid_identity(
    key_id: &str,
    ed_seed: &[u8; 32],
    ml_seed: &[u8; 32],
) -> ciris_verify_core::self_at_login::HybridSigningIdentity {
    use ciris_crypto::{Ed25519Signer, MlDsa65Signer};
    let ed = Ed25519Signer::from_seed(ed_seed).expect("ed signer");
    let mldsa = MlDsa65Signer::from_seed(ml_seed).expect("mldsa signer");
    ciris_verify_core::self_at_login::HybridSigningIdentity::new(key_id.to_string(), ed, mldsa)
}

fn directory_of(engine: &Arc<Engine>) -> Arc<dyn FederationDirectory> {
    engine
        .sqlite_backend()
        .expect("sqlite-backed engine")
        .clone()
}

fn selector(key_id: &str) -> CohortProvider {
    let k = key_id.to_string();
    Arc::new(move || vec![k.clone()])
}

/// Build the signed self-occurrence (envelope + typed row) for `identity`, carrying
/// `enc` as the content-KEM half and a derivation-consistent transport binding
/// (dest-hash recomputed by the gate per §5.6.8.8.1.1; transport-x25519 ≠ content
/// x25519 satisfies C4).
async fn signed_self_occurrence(
    key_id: &str,
    signer: &ciris_verify_core::self_at_login::HybridSigningIdentity,
    enc: &EncryptionPubkeys,
    transport_x: [u8; 32],
    transport_ed: [u8; 32],
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> SignedIdentityOccurrence {
    let app = "ciris";
    let aspects = vec!["edge".to_string()];
    let dest_hash =
        compute_destination_hash(app, &aspects, &transport_x, &transport_ed).expect("dest hash");
    let tb_env = serde_json::json!({
        "reticulum_x25519_pubkey": BASE64.encode(transport_x),
        "reticulum_ed25519_pubkey": BASE64.encode(transport_ed),
        "destination_hash": BASE64.encode(dest_hash),
        "app_name": app,
        "aspects": aspects,
    });
    let envelope = serde_json::json!({
        "identity_key_id": key_id,
        "occurrence_key_id": key_id,
        "transport_destination": tb_env,
        "encryption_pubkeys": {
            "x25519_base64": enc.x25519_base64,
            "ml_kem_768_base64": enc.ml_kem_768_base64,
        },
        "asserted_at": asserted_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    let (signed_envelope, signature) = produce_signed_identity_occurrence(signer, envelope)
        .await
        .expect("produce signed occurrence");
    SignedIdentityOccurrence {
        identity_occurrence: IdentityOccurrence {
            identity_key_id: key_id.to_string(),
            occurrence_key_id: key_id.to_string(),
            device_class: "agent".to_string(),
            hardware_attestation: None,
            asserted_at,
            valid_until: None,
            encryption_pubkeys: Some(enc.clone()),
            transport_binding: Some(OccurrenceTransportBinding {
                reticulum_x25519_pubkey_base64: BASE64.encode(transport_x),
                reticulum_ed25519_pubkey_base64: BASE64.encode(transport_ed),
                destination_hash_base64: BASE64.encode(dest_hash),
                app_name: app.to_string(),
                aspects: vec!["edge".to_string()],
            }),
            persist_row_hash: String::new(),
        },
        attesting_key_id: key_id.to_string(),
        signed_envelope,
        signature,
    }
}

#[tokio::test]
async fn signed_occurrence_custody_replication_and_seal() {
    // ── Engines: A (must SEAL to B), B (the sealable peer). B's + Mallory's keys are
    //    registered on both (the gate resolves the ATTESTING key from the directory).
    let engine_a = engine(NODE_A_KEY_ID, [0xA0; 32], [0xA2; 32]).await;
    let engine_b = engine(NODE_B_KEY_ID, NODE_B_ED_SEED, NODE_B_ML_SEED).await;
    for (key_id, ed_seed, ml_seed) in [
        (NODE_B_KEY_ID, &NODE_B_ED_SEED, &NODE_B_ML_SEED),
        (MALLORY_KEY_ID, &MALLORY_ED_SEED, &MALLORY_ML_SEED),
    ] {
        register_node(&engine_b, key_id, ed_seed, ml_seed).await;
        register_node(&engine_a, key_id, ed_seed, ml_seed).await;
    }
    let dir_a = directory_of(&engine_a);
    let dir_b = directory_of(&engine_b);

    // ── (1) CUSTODY: seal B's seed into the keyring (mint-time), then obtain the enc
    //    pubkeys BY ALIAS via SelfEncKeys — no raw derive in the publish path.
    let custody_dir = std::env::temp_dir().join(format!(
        "ciris-occ-kex-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&custody_dir).expect("custody dir");
    SealedEd25519Signer::adopt(NODE_B_KEY_ID, custody_dir.clone(), &NODE_B_ED_SEED)
        .expect("seal B's seed (mint-time)");
    let b_custody =
        SelfEncKeys::open(NODE_B_KEY_ID, custody_dir.clone()).expect("SelfEncKeys::open by alias");
    let b_enc_out = b_custody.enc_pubkeys().expect("enc pubkeys from custody");
    let b_enc = EncryptionPubkeys {
        x25519_base64: b_enc_out.x25519_base64.clone(),
        ml_kem_768_base64: b_enc_out.ml_kem_768_base64.clone(),
    };

    // ── (2) SIGNED SELF-PUBLISH on B (what compose::publish_self_identity_occurrence
    //    does at boot), through the ONE fail-secure gate.
    let b_signer = hybrid_identity(NODE_B_KEY_ID, &NODE_B_ED_SEED, &NODE_B_ML_SEED);
    let t0 = chrono::Utc::now();
    let b_occ =
        signed_self_occurrence(NODE_B_KEY_ID, &b_signer, &b_enc, [0x02; 32], [0x01; 32], t0).await;
    dir_b
        .put_identity_occurrence(b_occ)
        .await
        .expect("B's signed self-occurrence admitted");

    // ── (3) ADVERSARIAL: Mallory (registered, unrelated — a compromised consented
    //    peer) signs an occurrence claiming B's identity with HER enc keys → the gate
    //    MUST reject (signer_acts_for). This is the content-MITM the arc closes.
    let mallory_signer = hybrid_identity(MALLORY_KEY_ID, &MALLORY_ED_SEED, &MALLORY_ML_SEED);
    let mallory_enc = ciris_server::identity::derive_self_enc_pubkeys(&MALLORY_ED_SEED)
        .expect("mallory enc keys");
    let mut forged = signed_self_occurrence(
        NODE_B_KEY_ID,   // claims B's identity...
        &mallory_signer, // ...but Mallory signs
        &mallory_enc,
        [0x04; 32],
        [0x05; 32],
        chrono::Utc::now(),
    )
    .await;
    forged.attesting_key_id = MALLORY_KEY_ID.to_string();
    assert!(
        dir_a.put_identity_occurrence(forged).await.is_err(),
        "a forged occurrence (valid Mallory signature, B's identity) MUST be rejected \
         (signer is neither the identity nor an active occurrence of it)"
    );
    // Tampered envelope (signature over different bytes) → rejected as inauthentic.
    let mut tampered = signed_self_occurrence(
        NODE_B_KEY_ID,
        &b_signer,
        &b_enc,
        [0x02; 32],
        [0x01; 32],
        chrono::Utc::now(),
    )
    .await;
    tampered.signed_envelope["encryption_pubkeys"]["x25519_base64"] =
        serde_json::json!(mallory_enc.x25519_base64);
    tampered.identity_occurrence.encryption_pubkeys = Some(mallory_enc.clone());
    assert!(
        dir_a.put_identity_occurrence(tampered).await.is_err(),
        "a tampered envelope (enc keys swapped after signing) MUST be rejected"
    );

    // ── (4) BYTE-EXACT SIGNED REPLICATION: the bridge's publish-own selector reads
    //    the SIGNED tuple (v14.1.0 list_signed_identity_occurrences_for), one
    //    anti-entropy hop carries it to A, and A's gate RE-VERIFIES the signature.
    let bridge_b =
        FederationDirectoryReplicationBridge::new(Arc::clone(&dir_b), Arc::new(Vec::new))
            .with_self_provider(Some(selector(NODE_B_KEY_ID)));
    let refs = bridge_b
        .list_envelope_refs(EnvelopeKind::IdentityOccurrence)
        .await;
    assert_eq!(
        refs.len(),
        1,
        "B advertises its OWN signed occurrence (#305)"
    );
    let bytes = bridge_b
        .fetch_envelope_bytes(EnvelopeKind::IdentityOccurrence, &refs[0].envelope_hash)
        .await
        .expect("fetch signed occurrence bytes");
    let bridge_a =
        FederationDirectoryReplicationBridge::new(Arc::clone(&dir_a), Arc::new(Vec::new));
    let outcome = bridge_a
        .apply_envelope_bytes(EnvelopeKind::IdentityOccurrence, &bytes, None)
        .await;
    assert!(
        outcome.is_admitted(),
        "A verifies + admits B's replicated SIGNED occurrence (got {outcome:?})"
    );
    let resolved = dir_a
        .resolve_encryption_keys(NODE_B_KEY_ID)
        .await
        .expect("resolve ok")
        .expect("B's enc keys resolve on A after signed replication");
    assert_eq!(resolved.x25519_base64, b_enc.x25519_base64);
    assert_eq!(resolved.ml_kem_768_base64, b_enc.ml_kem_768_base64);

    // Trusted-local rows must NOT signed-replicate: a local (device-bind-style) row on
    // B is invisible to the signed re-read the wire uses.
    dir_b
        .put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: NODE_B_KEY_ID.to_string(),
            occurrence_key_id: MALLORY_KEY_ID.to_string(), // any bound device key
            device_class: "laptop".to_string(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("trusted-local bind");
    let refs_after = bridge_b
        .list_envelope_refs(EnvelopeKind::IdentityOccurrence)
        .await;
    assert_eq!(
        refs_after.len(),
        1,
        "trusted-local rows are EXCLUDED from signed replication (only signed-put rides)"
    );

    // ── (5) ROTATION: B re-asserts with NEW enc keys + newer asserted_at → supersedes
    //    on A; a stale replay of the ORIGINAL signed tuple does NOT reinstate it.
    let b_enc2 = ciris_server::identity::derive_self_enc_pubkeys(&[0xB2; 32])
        .expect("rotated enc keys (fixture)");
    let t1 = t0 + chrono::Duration::seconds(5);
    let b_occ2 = signed_self_occurrence(
        NODE_B_KEY_ID,
        &b_signer,
        &b_enc2,
        [0x02; 32],
        [0x01; 32],
        t1,
    )
    .await;
    dir_a
        .put_identity_occurrence(b_occ2)
        .await
        .expect("rotated re-assert admitted (last-signed-wins)");
    let after_rotate = dir_a
        .resolve_encryption_keys(NODE_B_KEY_ID)
        .await
        .expect("resolve ok")
        .expect("still resolvable");
    assert_eq!(
        after_rotate.x25519_base64, b_enc2.x25519_base64,
        "rotation superseded the enc keys"
    );
    // Stale replay: re-apply the ORIGINAL replicated bytes → safe no-op.
    let _ = bridge_a
        .apply_envelope_bytes(EnvelopeKind::IdentityOccurrence, &bytes, None)
        .await;
    let after_replay = dir_a
        .resolve_encryption_keys(NODE_B_KEY_ID)
        .await
        .expect("resolve ok")
        .expect("still resolvable");
    assert_eq!(
        after_replay.x25519_base64, b_enc2.x25519_base64,
        "a stale signed replay must NOT roll back the rotated keys (anti-first-writer)"
    );

    // ── (6) SEAL ROUND-TRIP, decrypt INSIDE CUSTODY: A initiates to B's ORIGINAL
    //    resolved pubkeys (the custody-derived set from step 1); B recomputes the
    //    SAME session key via SelfEncKeys::kex_respond — no private half in the test.
    let peer = PeerKexPubkeys {
        x25519_pub: BASE64
            .decode(&b_enc.x25519_base64)
            .expect("x b64")
            .try_into()
            .expect("x 32B"),
        mlkem768_pub: Some(BASE64.decode(&b_enc.ml_kem_768_base64).expect("mlkem b64")),
    };
    let (handshake, sender_key) =
        FederationSession::initiate(&peer, KexAlgorithm::Hybrid).expect("A seals to B");
    let handshake_json = match &handshake {
        ciris_edge::transport::federation_session::SessionHandshakeMsg::Hybrid(m) => {
            serde_json::to_vec(m).expect("handshake json")
        }
        ciris_edge::transport::federation_session::SessionHandshakeMsg::Classical(m) => {
            serde_json::to_vec(m).expect("handshake json")
        }
    };
    let recipient_key = b_custody
        .kex_respond(&handshake_json)
        .expect("B opens INSIDE custody (SelfEncKeys::kex_respond)");
    assert_eq!(
        sender_key.as_bytes(),
        &recipient_key,
        "session keys match — sealed content to B opens inside B's custody"
    );
}
