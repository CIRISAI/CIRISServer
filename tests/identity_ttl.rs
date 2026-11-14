//! **A harness node's identity rows carry a stated end** (0.5.247; steward
//! ruling 2026-11-13). With `CIRIS_NODE_IDENTITY_TTL_S` set, the node key
//! record and the owner-binding this process signs are admitted carrying an
//! end `ttl` from now, so a CI node leaves nothing live on the canonical after
//! its run. Every other suite runs with the variable unset, which pins the
//! production half: no end, rows exactly as before.
//!
//! ONE test in this binary: the end is fixed once per process, at first use.

#[path = "support/owned_node.rs"]
mod owned_node;

use ciris_server::attestation_reads::AllAttestations as _;
use owned_node::Person;

#[tokio::test]
async fn a_harness_nodes_key_and_owner_binding_lapse_at_the_stated_end() {
    // Before anything this process signs.
    std::env::set_var(ciris_server::identity_ttl::ENV, "86400");
    let before = chrono::Utc::now();
    let alice = Person::new("ttl").await;
    let after = chrono::Utc::now();
    let dir = alice.engine.federation_directory();

    // The node key record, admitted with the end signed into its envelope.
    let rec = dir
        .lookup_public_key(&alice.node_key_id)
        .await
        .expect("lookup")
        .expect("the node key is registered");
    let end = rec.valid_until.expect("a harness node key carries an end");
    let day = chrono::Duration::days(1);
    assert!(
        end >= before + day - chrono::Duration::seconds(1) && end <= after + day,
        "the end is a day from now: {end}"
    );
    assert_eq!(
        rec.registration_envelope
            .get("valid_until")
            .and_then(serde_json::Value::as_str)
            .map(|s| chrono::DateTime::parse_from_rfc3339(s).expect("rfc3339")),
        Some(end.fixed_offset()),
        "the end is SIGNED, in the envelope, not only a column beside it"
    );

    // The owner-binding the claim wrote, admitted with the same end.
    let bindings: Vec<_> = dir
        .attestations_to_all(&alice.node_key_id)
        .await
        .expect("rows")
        .into_iter()
        .filter(|r| {
            r.attestation_envelope
                .get("delegation_purpose")
                .and_then(serde_json::Value::as_str)
                == Some(ciris_server::auth::ownership::OWNER_BINDING_PURPOSE)
        })
        .collect();
    assert!(!bindings.is_empty(), "the claim wrote an owner-binding");
    for b in &bindings {
        assert_eq!(
            b.expires_at,
            Some(end),
            "the binding lapses with the key: {b:?}"
        );
    }

    // An identity occurrence signed with the same end in its envelope (the
    // shape `publish_self_identity_occurrence` writes at boot) is admitted, and
    // the typed row carries the end.
    let owner = alice.owner.signer().await;
    let enc = ciris_server::identity::derive_self_enc_pubkeys(&[0x5A; 32]).expect("enc keys");
    let asserted_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .expect("now, to the millisecond");
    let until = ciris_server::identity_ttl::valid_until_str().expect("the end, as signed");
    let envelope = serde_json::json!({
        "attesting_key_id": alice.key(),
        "identity_key_id": alice.key(),
        "occurrence_key_id": alice.node_key_id,
        "device_class": "laptop",
        "encryption_pubkeys": {
            "x25519_base64": enc.x25519_base64,
            "ml_kem_768_base64": enc.ml_kem_768_base64,
        },
        "asserted_at": asserted_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "valid_until": until,
        "hardware_attestation": serde_json::Value::Null,
    });
    let (signed_envelope, signature) =
        ciris_verify_core::transport_binding::produce_signed_identity_occurrence(
            &ciris_persist::signing::LocalSelfSigner::new(&owner),
            envelope,
        )
        .await
        .expect("sign the occurrence");
    dir.put_identity_occurrence(ciris_persist::federation::SignedIdentityOccurrence {
        identity_occurrence: ciris_persist::federation::types::IdentityOccurrence {
            identity_key_id: alice.key().to_owned(),
            occurrence_key_id: alice.node_key_id.clone(),
            device_class: "laptop".to_owned(),
            hardware_attestation: None,
            asserted_at,
            valid_until: Some(end),
            encryption_pubkeys: Some(enc),
            transport_binding: None,
            persist_row_hash: String::new(),
        },
        attesting_key_id: alice.key().to_owned(),
        signed_envelope,
        signature,
    })
    .await
    .expect("an occurrence with a signed end is admitted");
    let held = dir
        .list_identity_occurrences_for(alice.key())
        .await
        .expect("occurrences")
        .into_iter()
        .find(|o| o.occurrence_key_id == alice.node_key_id)
        .expect("held");
    assert_eq!(held.valid_until, Some(end));
}
