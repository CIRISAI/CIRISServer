//! Seed a REAL, admitted revocation — with or without the CIRISPersist#570
//! `revoked_after` history bound.
//!
//! Shared because two suites need it (`revoked_after_enforcement`, which gates
//! four read paths, and `capacity_scorer`, which gates the fifth on top of its
//! own trace-ingest fixture) and a second copy of the fixture is how two gates
//! end up testing two different things while reading identically.
//!
//! The bound is written into the SIGNED envelope as well as the typed field
//! because persist refuses any other shape (`check_revocation_bound`: a typed
//! bound with no envelope bound is not a lenient revocation, it is a forged
//! one). Building the fixture the only way the substrate accepts is what keeps
//! these gates about ENFORCEMENT rather than about a row someone hand-wrote.
//!
//! NB: files under `tests/support/` are not auto-compiled as test binaries; each
//! suite pulls this in with an explicit `#[path]`.

#![allow(dead_code)]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use ciris_persist::federation::types::{Revocation, SignedRevocation};
use ciris_persist::federation::verify_coord::region;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

/// Persist a hybrid-signed revocation of `revoked_key_id`, effective at
/// `effective_at`, optionally bounded at `revoked_after`.
///
/// `revoking` must already be registered with the pubkeys it signs with —
/// persist re-verifies the revocation against the directory
/// (`verify_revocation_admission`), so an unregistered or mismatched signer is
/// refused rather than stored.
pub async fn revoke(
    engine: &Engine,
    revoking: &LocalSigner,
    revoked_key_id: &str,
    effective_at: DateTime<Utc>,
    revoked_after: Option<DateTime<Utc>>,
) {
    let mut envelope = serde_json::json!({
        "revoked_key_id": revoked_key_id,
        "revoking_key_id": revoking.key_id(),
        "revoked_at": effective_at.to_rfc3339(),
        "effective_at": effective_at.to_rfc3339(),
    });
    if let Some(b) = revoked_after {
        envelope["revoked_after"] = serde_json::Value::String(b.to_rfc3339());
    }
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize revocation envelope");
    let sig = revoking
        .sign_hybrid(&canonical)
        .await
        .expect("hybrid-sign the revocation");
    let now = Utc::now();
    let row = Revocation {
        revocation_id: format!("rev-{revoked_key_id}"),
        revoked_key_id: revoked_key_id.to_string(),
        revoking_key_id: revoking.key_id().to_string(),
        reason: None,
        revoked_at: effective_at,
        effective_at,
        revocation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: revoking.key_id().to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        observed_region: region::US.to_string(),
        revoked_after,
        persist_row_hash: String::new(),
    };
    engine
        .federation_directory()
        .put_revocation(SignedRevocation { revocation: row })
        .await
        .expect("put_revocation (the bound must be admitted by check_revocation_bound)");
}
