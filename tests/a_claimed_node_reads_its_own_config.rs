//! **A claimed node can read — and renew — its own `config:*` rows.**
//! (CIRISServer#624 → CIRISPersist#888, fixed in persist v46.3.1)
//!
//! # What broke
//!
//! On 0.5.213 a first-run node announced once was fine and 500'd on the second
//! announce. The 500 was a symptom: on a CLAIMED node `GET /v1/config` read `{}`
//! over rows that demonstrably existed and were stamped exactly as CC 3.1.9 /
//! 3.4.5 prescribe (`attesting = attested = node`, `cohort_scope: self`). An
//! empty read means no leaf head, so `set_config` opened the leaf with `scores`
//! a second time, and persist's (correct) duplicate-live-row guard refused it.
//!
//! Why the read was empty: persist's read-side `self` gate compared the caller's
//! RESOLVED identity against the row's RAW target. Since persist#873 a claimed
//! node resolves to its owner, so `target(node) == identity(owner)` was false
//! and every `self` row a node emits about itself vanished — for the node too.
//! Before #873 the node resolved to itself and nobody noticed.
//!
//! # What this pins
//!
//! The rows never change between the two halves of this test. Only the node's
//! resolution does — a claim moves it from singleton to principal. The read
//! must survive that. This is the server-side twin of persist's I141.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
use ciris_persist::federation::IdentityOccurrence;
use ciris_persist::prelude::{Engine, LocalSigner};

use ciris_server::graph_config;
use ciris_server::{ConfigScope, ConfigValue};

const NODE_ALIAS: &str = "claimed-config-node";

/// Same node shape as `tests/graph_config.rs`: hybrid signer, in-memory sqlite.
async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xC1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xC2; 32], format!("{NODE_ALIAS}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_ALIAS.to_string(),
        Some(pqc),
        Some(format!("{NODE_ALIAS}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer (sqlite::memory:)"),
    )
}

async fn node_key_id(engine: &Engine) -> String {
    engine
        .local_derived_key_id()
        .await
        .expect("derived node key_id")
}

/// The node's own key, through the admission door (as `tests/graph_config.rs`).
async fn register_self(engine: &Engine) {
    let key_id = node_key_id(engine).await;
    ciris_server::attest::register_key(
        engine,
        ciris_server::attest::KeySigner::Engine(engine),
        &key_id,
        identity_type::STEWARD,
        serde_json::Value::Null,
    )
    .await
    .expect("register node steward key");
}

/// THE CLAIM, reduced to the one row the read gate resolves through: the
/// owner's login anchor `identity_occurrence { identity = owner, occurrence =
/// node }` (what `anchor_agent_to_owner` writes at claim, 0.5.211). After it,
/// `active_identity_for_occurrence(node) == owner` — the node is a principal's
/// occurrence, no longer its own singleton (persist FSD/OCCURRENCE_PRINCIPAL §2).
async fn claim(engine: &Engine, node: &str) -> String {
    let owner_ed = SigningKey::from_bytes(&[0xD1; 32]);
    let owner_pqc = MlDsa65SoftwareSigner::from_seed_bytes(&[0xD2; 32], "owner-pqc".to_string())
        .expect("owner ML-DSA-65 seed");
    let owner = "owner-of-claimed-config-node".to_string();
    let now = chrono::Utc::now();
    // The owner's key record, admitted directly (no PoP at this door — the
    // occurrence/device_grant fixtures do the same).
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord {
            record: KeyRecord {
                key_id: owner.clone(),
                pubkey_ed25519_base64: BASE64.encode(owner_ed.verifying_key().to_bytes()),
                pubkey_ml_dsa_65_base64: Some(
                    BASE64.encode(owner_pqc.public_key().await.expect("owner pqc pub")),
                ),
                algorithm: algorithm::HYBRID.into(),
                identity_type: identity_type::USER.to_string(),
                identity_ref: owner.clone(),
                valid_from: now,
                valid_until: None,
                registration_envelope: serde_json::json!({ "key_id": owner }),
                original_content_hash: String::new(),
                scrub_signature_classical: String::new(),
                scrub_signature_pqc: None,
                scrub_key_id: owner.clone(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .expect("register the owner's key");
    engine
        .federation_directory()
        .put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: owner.clone(),
            occurrence_key_id: node.to_string(),
            device_class: "server".into(),
            hardware_attestation: None,
            asserted_at: now,
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("anchor the node as the owner's occurrence");
    owner
}

#[tokio::test]
async fn a_claimed_node_reads_and_renews_its_own_config() {
    let engine = node().await;
    register_self(&engine).await;
    let node = node_key_id(&engine).await;

    // Unclaimed: write, read back. This half passes on every persist.
    let v1 = graph_config::set_config(
        &engine,
        "net.announce_ownership",
        ConfigValue::Bool(true),
        "owner",
        ConfigScope::default(),
    )
    .await
    .expect("first write opens the leaf");
    assert_eq!(v1.version, 1);
    graph_config::invalidate_engine(&engine);
    assert!(
        graph_config::get_config(&engine, "net.announce_ownership")
            .await
            .expect("read")
            .is_some(),
        "an UNCLAIMED node must read its own config — if this fails the fixture is wrong, \
         not the gate"
    );

    // THE CLAIM. Nothing about the rows changes from here on.
    let owner = claim(&engine, &node).await;
    graph_config::invalidate_engine(&engine);

    // Rung 1 — the read. Empty here is CIRISServer#624's `GET /v1/config → {}`.
    let read = graph_config::get_config(&engine, "net.announce_ownership")
        .await
        .expect("read after claim");
    assert!(
        read.is_some(),
        "a CLAIMED node cannot read its own `config:*` rows. The rows are unchanged and \
         per CC 3.1.9 / 3.4.5 (attester = attested = node, cohort_scope self); what moved \
         is the node's resolution — it is now an occurrence of {owner}, and persist's \
         read-side `self` gate compared that RESOLVED identity to the row's RAW target \
         (CIRISPersist#888; fixed v46.3.1: the gate admits the caller's self-collective)."
    );

    // Rung 2 — the renewal. A second write must find the leaf head and renew
    // with `supersedes`; opening the leaf again with `scores` is what persist's
    // duplicate-live-row guard refuses — the announce 500.
    let v2 = graph_config::set_config(
        &engine,
        "net.announce_ownership",
        ConfigValue::Bool(true),
        "owner",
        ConfigScope::default(),
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "a CLAIMED node cannot RENEW its own config: {e:#}\n\nThis is the second \
             `POST /v1/federation/announce` 500 (CIRISServer#624): the read above found no \
             leaf head, so the write opened the leaf with `scores` again and persist's \
             CC 3.4.5.1 guard correctly refused a second live row."
        )
    });
    assert_eq!(v2.version, 2, "the renewal must chain, not restart");
    assert!(
        v2.previous_version.is_some(),
        "a renewal names the head it supersedes — `None` means it opened the leaf again"
    );
}
