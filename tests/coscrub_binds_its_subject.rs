//! **Our anchor's scrub is never added to a record we did not bind first.**
//!
//! CIRISVerify#252, adopted per CIRISServer#399 (server-specific §2).
//!
//! `/v1/accord/ci-key/cosign` and the canonical cosign flow both take a
//! CALLER-SUPPLIED `SignedKeyRecord` and append this node's anchor scrub to it.
//! That is the privilege-transfer shape verify found:
//!
//! `key_id`, `identity_type` and the pubkeys are sibling fields living OUTSIDE
//! `registration_envelope`, while the authority evidence — the roles and the
//! anchor scrub-signatures — is verified AGAINST that envelope. Unbound, the two
//! halves may describe different keys. A caller wraps a sibling `key_id` naming
//! the key you pinned around a genuinely accord-co-scrubbed envelope for some
//! OTHER key that carries `infra:attest`. It passes an identity comparison, a
//! role read, and a real ≥2-anchor quorum — every check that exists — and then
//! this endpoint adds our anchor's signature, blessing a key nobody blessed.
//!
//! Our own producers build both halves coherently, so the gate only ever refuses
//! a record we did not author. That is precisely the caller-supplied case, which
//! is why it belongs at the door rather than in the producer.
//!
//! This pins the PROPERTY (an unbound record is refused) rather than the call
//! site, so moving the check does not silently delete it.

use ciris_verify_core::federation_self_record::KeyRecord;

/// A record whose signed envelope is about a DIFFERENT subject than its sibling
/// fields claim — the attack shape, built by hand.
fn relabelled_record() -> KeyRecord {
    let mut rec: KeyRecord = serde_json::from_value(serde_json::json!({
        "key_id": "the-key-you-pinned",
        "identity_type": "node",
        "identity_ref": "the-key-you-pinned",
        "pubkey_ed25519_base64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "algorithm": "ed25519",
        "valid_from": "2026-08-15T00:00:00Z",
        "registration_envelope": {
            // The signed half is about somebody else entirely.
            "key_id": "some-other-key-that-carries-infra-attest",
            "identity_type": "node",
            "roles": ["infra:attest"],
        },
        "original_content_hash": "",
        "scrub_signature_classical": "",
        "scrub_key_id": "anchor-a",
        "scrub_timestamp": "2026-08-15T00:00:00Z",
        "persist_row_hash": "",
        "pubkey_ml_dsa_65_base64": null,
    }))
    .expect("fixture parses as a KeyRecord");
    // Belt and braces: the fixture must actually carry the divergence it claims.
    assert_ne!(
        rec.key_id,
        rec.registration_envelope
            .get("key_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        "fixture must have sibling and envelope naming DIFFERENT subjects — \
         otherwise this test passes by examining nothing"
    );
    rec.valid_until = None;
    rec
}

#[test]
fn a_record_whose_envelope_names_another_subject_is_refused() {
    let rec = relabelled_record();
    assert!(
        rec.check_subject_binding().is_err(),
        "a record whose signed envelope is about `{}` while its sibling fields claim \
         `{}` was ACCEPTED. Co-scrubbing it would add this node's anchor signature to \
         a blessing of a key nobody blessed.",
        rec.registration_envelope
            .get("key_id")
            .and_then(|v| v.as_str())
            .unwrap_or("<none>"),
        rec.key_id,
    );
}

/// The gate must be reachable from the co-scrub doors, not merely exist.
///
/// Asserted against the source because the endpoints need a live YubiKey and an
/// accord roster to drive end-to-end — a check that cannot run in CI is a check
/// that silently stops running. Both caller-supplied sites are covered.
#[test]
fn both_caller_supplied_coscrub_paths_call_the_gate() {
    let src = include_str!("../src/accord_provision.rs");
    let calls = src.matches("check_subject_binding()").count();
    assert!(
        calls >= 2,
        "expected the binding gate at BOTH caller-supplied co-scrub sites \
         (cosign_canonical_impl and the batch partials loop); found {calls}. \
         A caller-supplied SignedKeyRecord must be bound to its envelope before \
         this node's anchor signs anything about it (CIRISVerify#252)."
    );
}
