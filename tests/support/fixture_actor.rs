//! An **actor**: a signer that can put its own claim into the mesh.
//!
//! ## Why fixtures need one since persist v39.0.0
//!
//! `attestation_promote` used to re-sign every promoted row with THIS NODE's
//! key, so a fixture could write a row attested by any string it liked and the
//! node would sign it into the federation tier. That is the defect v39 removed:
//! the fabric was becoming the author of claims it was only carrying.
//!
//! Now custody is decided by the row (`Engine::custody_for`):
//!
//! | row | signer in hand | custody |
//! |---|---|---|
//! | unsigned, attested by this node | — | this node signs as the actor |
//! | unsigned, attested by another key | that key's signer | the actor signs now |
//! | unsigned, attested by another key | none | **`AwaitingActor`** — it waits |
//!
//! A fixture that seeds an unsigned row under some other key and hands over no
//! signer lands in the third row: the crossing returns `Ok`, nothing reaches the
//! federation tier, and the test fails later and further away — as an empty list
//! or a zero count — with nothing naming the cause. So a fixture that wants a
//! row IN the mesh under a key that is not the node's must hold that key.
//!
//! ## What this gives it
//!
//! A hybrid signer (v19.0.0 refuses a signer without its ML-DSA-65 half) whose
//! key record is registered under its DERIVED id with BOTH pubkeys — the shape
//! `custody_for` matches on and the put door verifies against. Callers use
//! [`Actor::key_id`] as `attesting_key_id` and pass [`Actor::signer`] as the
//! actor, and the two agree by construction.
#![allow(dead_code)] // each consumer uses a different part of this surface

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;

use ciris_persist::federation::types::algorithm;
use ciris_persist::federation::{FederationDirectory as _, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};

/// A registered hybrid signer, and the key id its rows are attested under.
pub struct Actor {
    signer: Arc<LocalSigner>,
    key_id: String,
    seed: u8,
}

impl Actor {
    /// The DERIVED key id (`<alias>-<fingerprint>`), which is what a row's
    /// `attesting_key_id` must be for this actor's signer to be accepted as its
    /// custody. Not the alias: `custody_for` compares against
    /// `LocalSigner::derived_key_id`, and an alias would be refused as "the
    /// signer is not the attester" (CIRISPersist#247).
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Pass to `enter_mesh_at` / `enter_mesh` / `widen_audience` as `actor`.
    #[must_use]
    pub fn signer(&self) -> &LocalSigner {
        &self.signer
    }

    /// The SAME Ed25519 key the signer holds, for fixtures that sign raw bytes
    /// themselves (a trace's `signature`, say) rather than through
    /// `LocalSigner`. Handing back a second, unrelated key here would produce
    /// signatures that verify against nothing this actor registered.
    #[must_use]
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&[self.seed; 32])
    }

    /// The ML-DSA-65 half, likewise — same seed rule as [`Self::signing_key`].
    #[must_use]
    pub fn pqc_signer(&self) -> ciris_crypto::MlDsa65Signer {
        ciris_crypto::MlDsa65Signer::from_seed(&[self.seed.wrapping_add(1); 32])
            .expect("ml-dsa seed")
    }
}

/// Mint a hybrid signer for `alias` and register it in the federation directory.
///
/// `seed` distinguishes actors: it seeds BOTH halves, so two actors never share
/// a key. (Sharing the PQC half would make two identities one to anything that
/// checks it.)
pub async fn actor(engine: &Engine, alias: &str, seed: u8, id_type: &str) -> Actor {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let ed_pub_b64 = BASE64.encode(sk.verifying_key().to_bytes());
    let pqc =
        ciris_crypto::MlDsa65Signer::from_seed(&[seed.wrapping_add(1); 32]).expect("ml-dsa seed");
    let pqc_pub_b64 = {
        use ciris_crypto::PqcSigner as _;
        BASE64.encode(pqc.public_key().expect("ml-dsa pk"))
    };
    let pqc_key_id = format!("{alias}-pqc");
    let signer = Arc::new(LocalSigner::from_parts(
        sk,
        alias.to_string(),
        Some(Arc::new(pqc) as Arc<dyn ciris_keyring::PqcSigner>),
        Some(pqc_key_id.clone()),
    ));
    let key_id = signer.derived_key_id();
    let now = chrono::Utc::now();

    // BOTH halves on ONE record, under the derived id. The classical half is
    // what `custody_for` resolves and the put door verifies the base scrub
    // against; the ML-DSA half is what persist v38.8.0 (#789) resolves the
    // hybrid signature against, refusing rather than trusting the pubkey the
    // payload carries.
    let record = KeyRecord {
        key_id: key_id.clone(),
        pubkey_ed25519_base64: ed_pub_b64.clone(),
        pubkey_ml_dsa_65_base64: Some(pqc_pub_b64),
        algorithm: algorithm::HYBRID.into(),
        identity_type: id_type.to_string(),
        identity_ref: key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": key_id }),
        original_content_hash: "deadbeef".into(),
        scrub_signature_classical: ed_pub_b64,
        scrub_signature_pqc: None,
        scrub_key_id: key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .sqlite_backend()
        .expect("sqlite backend present")
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register the fixture actor in the federation directory");

    Actor {
        signer,
        key_id,
        seed,
    }
}
