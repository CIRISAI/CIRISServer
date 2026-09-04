//! The ML-DSA-65 identity every hybrid-signing test fixture in this repo signs
//! with, spelled ONCE.
//!
//! ## Why this file exists
//!
//! Persist v38.8.0 (#789) resolves a hybrid payload's `pqc_key_id` against the
//! federation directory and refuses when the record it finds carries no
//! `pubkey_ml_dsa_65_base64`:
//!
//! ```text
//! UnknownKey("pqc_key_id test-mldsa has no ML-DSA-65 pubkey in the federation
//!             directory — refusing rather than falling back to the pubkey the
//!             payload nominates (#789)")
//! ```
//!
//! It will not fall back to the pubkey the payload itself carries, which is the
//! whole point of the rule: a payload that both signs and supplies the key it is
//! checked against proves nothing. That turned the seed below from a private
//! detail of seven separate signing fixtures into a shared IDENTITY — one that
//! must be registered wherever it is used, or `VerifyMode::Full` answers
//! `verify_unknown_key`.
//!
//! Seven test files had each re-spelled the seed and the key id inline. Two
//! spellings of a seed are two identities that still compile, so they live here
//! instead, and callers ask for them.
#![allow(dead_code)] // each consumer uses a different part of this surface

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;

use ciris_persist::federation::types::{algorithm, identity_type};
use ciris_persist::federation::{FederationDirectory as _, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::Engine;

/// The key id the fixtures put in `trace.pqc_key_id`.
pub const KEY_ID: &str = "test-mldsa";

const SEED: [u8; 32] = [0x77u8; 32];

/// The Ed25519 half of the [`KEY_ID`] record, and the instant it is valid from.
///
/// The directory has no PQC-only record shape, but this key id is resolved only
/// for its ML-DSA half, so the classical half is filler — FIXED filler, and the
/// timestamp is fixed for the same reason. The directory refuses a second write
/// of an existing key id whose content differs (`Conflict`), and [`register`] is
/// called once per producer in tests that have several. Deriving this from the
/// calling producer's key, or stamping it with `Utc::now()`, makes every
/// registration a different row and the second producer collides with the first.
const RECORD_SEED: [u8; 32] = [0x78u8; 32];
const VALID_FROM: &str = "2020-01-01T00:00:00Z";

/// The signer the fixtures sign the PQC half with.
pub fn signer() -> ciris_crypto::MlDsa65Signer {
    ciris_crypto::MlDsa65Signer::from_seed(&SEED).expect("ml-dsa seed")
}

/// The public half to register under [`KEY_ID`], base64 as the directory stores
/// it.
pub fn pubkey_b64() -> String {
    use ciris_crypto::PqcSigner as _;
    BASE64.encode(signer().public_key().expect("ml-dsa pk"))
}

/// Put the [`KEY_ID`] record so a batch signed by [`signer`] verifies.
///
/// Idempotent by construction: the row is byte-identical on every call, so a
/// test with several producers may call this once per producer.
///
/// This is a row of its OWN rather than a PQC half filled in on each producer's
/// record, so that a test which counts directory rows sees one extra row total
/// instead of one per producer — and so that two producers are never handed the
/// same PQC pubkey, which would make them one identity to anything checking.
pub async fn register(engine: &Engine) {
    let ed_b64 = BASE64.encode(
        SigningKey::from_bytes(&RECORD_SEED)
            .verifying_key()
            .to_bytes(),
    );
    let at = VALID_FROM.parse().expect("pqc valid_from");
    let record = KeyRecord {
        key_id: KEY_ID.to_string(),
        pubkey_ed25519_base64: ed_b64.clone(),
        pubkey_ml_dsa_65_base64: Some(pubkey_b64()),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::AGENT.to_string(),
        identity_ref: KEY_ID.to_string(),
        valid_from: at,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": KEY_ID }),
        original_content_hash: "deadbeef".into(),
        scrub_signature_classical: ed_b64,
        scrub_signature_pqc: None,
        scrub_key_id: KEY_ID.to_string(),
        scrub_timestamp: at,
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
        .expect("register the fixture ML-DSA-65 key in the federation directory");
}
