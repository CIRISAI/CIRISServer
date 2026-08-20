//! **The self identity-occurrence envelope satisfies verify's own projection**
//! (CIRISServer#454).
//!
//! # What went wrong
//!
//! `publish_self_identity_occurrence` built a signed envelope carrying
//! `identity_key_id`, `occurrence_key_id`, `transport_destination`,
//! `encryption_pubkeys` and `asserted_at` — but NOT `attesting_key_id`. That
//! value was set as a top-level field on `SignedIdentityOccurrence` instead, so
//! the signature never covered it.
//!
//! `ciris_verify_core` has required it INSIDE the signed bytes since v13.1.0.
//! Every publish was refused with:
//!
//! ```text
//! transport binding: signed bytes do not carry `attesting_key_id` — refusing,
//! an absent binding is skippable by omission
//! ```
//!
//! …and the node then logged "peers cannot seal to this node until it is
//! admitted". Both the canonical and the status node were in that state.
//!
//! # Why it survived so long
//!
//! Nothing failed. The node booted, served HTTP, answered its health check and
//! replicated — it simply never published the row that lets peers seal to it.
//! The only symptom was one WARN per boot among thousands of lines. That is the
//! same silent-consequence shape as CIRISServer#365 (nine `mesh_config` keys,
//! zero consumers): operable, and not EFFECTIVE.
//!
//! It also predates the substrate jump. verify v13.1.0 introduced the
//! requirement and we were on v13.3.1 before 0.5.182, so this was NOT a
//! regression from adopting v18.2.0 — it had been failing on every boot since
//! whichever cut first pinned v13.1.0+.
//!
//! # Why the gate is shaped this way
//!
//! It asserts our envelope against `TransportBinding::subject_binding()` —
//! VERIFY'S OWN projection, which is exactly what it is exposed for. A test
//! that hand-listed the required keys would be a second reading of the rule,
//! and would keep passing the day verify adds a third requirement. This one
//! fails.

use ciris_verify_core::transport_binding::{
    EncryptionPubkeys, TransportBinding, TransportBindingSignature, TransportDestination,
};

/// THE PRODUCTION BUILDER, called — not re-implemented.
///
/// This is the entire point of the fix. A fixture that rebuilt the envelope here
/// would be a third copy of the rule, and the second copy is what let this
/// defect live: `occurrence_kex_e2e` had a correct one beside a wrong producer
/// and passed.
fn envelope_as_production_builds_it(key_id: &str) -> serde_json::Value {
    let td = serde_json::json!({
        "reticulum_x25519_pubkey": "eA==",
        "reticulum_ed25519_pubkey": "ZA==",
        "destination_hash": "aA==",
        "app_name": "ciris",
        "aspects": ["edge"],
    });
    ciris_server::test_support_self_occurrence_envelope(
        key_id,
        &td,
        "eA==",
        "bQ==",
        chrono::Utc::now(),
    )
}

/// **Verify's projection must find every member it requires.**
///
/// This is the assertion that would have caught the defect on the day it
/// shipped, and it fails against the pre-fix envelope.
#[test]
fn the_signed_envelope_satisfies_verifys_subject_binding() {
    let key_id = "ciris-canonical-1-d7bdeu223k";
    let envelope = envelope_as_production_builds_it(key_id);

    let binding = TransportBinding {
        attesting_key_id: key_id.to_string(),
        signed_envelope: envelope.clone(),
        // NOTE the field names differ from the ENVELOPE keys by design:
        // verify's struct is `*_base64`, and `subject_binding()` maps it to the
        // unsuffixed envelope keys. Building the struct directly (rather than
        // deserializing the envelope into it) is what keeps that mapping under
        // verify's control instead of ours.
        transport_destination: TransportDestination {
            reticulum_x25519_pubkey_base64: "eA==".to_string(),
            reticulum_ed25519_pubkey_base64: "ZA==".to_string(),
            destination_hash_base64: "aA==".to_string(),
            app_name: "ciris".to_string(),
            aspects: vec!["edge".to_string()],
        },
        encryption_pubkeys: Some(EncryptionPubkeys {
            x25519_base64: "eA==".to_string(),
            ml_kem_768_base64: "bQ==".to_string(),
        }),
        // The signature bytes are irrelevant here — this gate is about the
        // PROJECTION, i.e. which members the signed object must carry. A real
        // signature would test the crypto, which `occurrence_kex_e2e` already
        // does.
        signature: TransportBindingSignature {
            ed25519_signature_base64: String::new(),
            mldsa65_signature_base64: None,
        },
    };

    // VERIFY'S OWN projection, not a hand-written list of keys.
    let projection = binding.subject_binding();
    let verdict = projection.check("transport binding", &envelope);

    assert!(
        verdict.is_ok(),
        "the envelope this node signs does not satisfy verify's subject binding, \
         so every self identity-occurrence publish is refused and peers cannot \
         seal to this node: {verdict:?}"
    );
}

/// **Production goes through the shared builder, and the builder signs the key.**
///
/// Two assertions because there are two ways to reintroduce the defect: the
/// producer stops calling the shared builder (and grows its own again), or the
/// builder stops emitting the key.
///
/// This gate fired on its own author. The first version grepped the producer's
/// body for `"attesting_key_id": key_id`, which was correct until the literal
/// moved INTO the shared builder during the same fix — at which point it went
/// red on a refactor that improved things. Kept, and re-pointed, because a gate
/// that notices its subject moved is doing its job.
#[test]
fn production_uses_the_shared_builder_and_the_builder_signs_the_key() {
    let compose = include_str!("../src/compose.rs");

    let start = compose
        .find("async fn publish_self_identity_occurrence")
        .expect("the producer must exist");
    let body = &compose[start..(start + 6000).min(compose.len())];
    assert!(
        body.contains("self_occurrence_envelope("),
        "publish_self_identity_occurrence no longer calls the shared envelope \
         builder. A second copy of the envelope is exactly how CIRISServer#454 \
         happened: the e2e test's copy was correct and the producer's was not, \
         so everything passed while every boot was refused."
    );

    let b = compose
        .find("pub(crate) fn self_occurrence_envelope")
        .expect("the shared builder must exist");
    let builder = &compose[b..(b + 2000).min(compose.len())];
    assert!(
        builder.contains("\"attesting_key_id\": key_id"),
        "the shared builder no longer puts `attesting_key_id` INSIDE the signed \
         envelope. Setting it as a top-level field on SignedIdentityOccurrence is \
         NOT equivalent — the signature does not cover it, and verify refuses: \
         \"signed bytes do not carry `attesting_key_id` — an absent binding is \
         skippable by omission\". The node still boots, serves and passes its \
         health check; it just silently stops being sealable."
    );
}
