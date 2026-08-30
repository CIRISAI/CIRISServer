//! **`GET /v1/identity` — asserted through the PRODUCTION assembly, not a literal.**
//!
//! The first version of this file built the expected JSON by hand and asserted the
//! literal contained what it had just inserted. It referenced `local_identity_json`
//! once, in a doc comment, and never called it — so it would have passed if
//! production omitted, renamed or mispopulated every field (Codex, PR #508). It
//! did pass, while 0.5.195 shipped a real defect on this exact surface.
//!
//! A test that cannot fail is worse than no test: it occupies the slot where a real
//! one would go. These call `local_identity_json` and assert on what it returns.
//!
//! # The defect these now pin
//!
//! `local_identity_aggregate` sources signing and content-KEM pubkeys from the
//! ENGINE's signer — the ACTOR on a split node. 0.5.195 overrode `key_id` with the
//! node key and left the pubkeys, so the id and the key material disagreed. A
//! consumer verifying a fingerprint, or sealing to that identity, would use the
//! wrong key. Worse than the mislabelling it set out to fix.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord};
use ciris_persist::federation::SignedKeyRecord;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::sync::Arc;

fn seed(label: &str, n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&Sha256::digest(format!("{label}:{n}").as_bytes()));
    s
}

fn signer_for(key_id: &str) -> LocalSigner {
    let ed = SigningKey::from_bytes(&seed(key_id, 1));
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&seed(key_id, 2), format!("{key_id}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        ed,
        key_id.to_string(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    )
}

async fn register(engine: &Engine, signer: &LocalSigner, key_id: &str, ident: &str) {
    let mut envelope = serde_json::json!({ "key_id": key_id });
    let probe = signer.sign_hybrid(b"probe").await.expect("probe");
    let ed_pub = B64.encode(&probe.classical.public_key);
    let pqc_pub = B64.encode(&probe.pqc.public_key);
    ciris_persist::federation::admission::bind_subject_into_envelope(
        &mut envelope,
        key_id,
        ident,
        &ed_pub,
        Some(&pqc_pub),
    )
    .expect("bind subject");
    let canonical =
        ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope).expect("canon");
    let sig = signer.sign_hybrid(&canonical).await.expect("sign");
    let now = chrono::Utc::now();
    engine
        .register_federation_key(SignedKeyRecord {
            record: KeyRecord {
                key_id: key_id.to_string(),
                pubkey_ed25519_base64: ed_pub,
                pubkey_ml_dsa_65_base64: Some(pqc_pub),
                algorithm: algorithm::HYBRID.into(),
                identity_type: ident.to_string(),
                identity_ref: key_id.to_string(),
                valid_from: now,
                valid_until: None,
                registration_envelope: envelope,
                original_content_hash: hex::encode(Sha256::digest(&canonical)),
                scrub_signature_classical: B64.encode(&sig.classical.signature),
                scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
                scrub_key_id: key_id.to_string(),
                scrub_timestamp: now,
                pqc_completed_at: Some(now),
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .unwrap_or_else(|e| panic!("register {key_id}: {e}"));
}

async fn engine_for(key_id: &str) -> Arc<Engine> {
    Arc::new(
        Engine::with_signer(Arc::new(signer_for(key_id)), "sqlite::memory:")
            .await
            .expect("engine"),
    )
}

/// Run the real assembly and parse what it produced.
async fn payload(
    engine: &Engine,
    node_key_id: &str,
    actor_key_id: Option<&str>,
) -> serde_json::Value {
    let json = ciris_server::local_identity_json(engine, None, node_key_id, actor_key_id)
        .await
        .expect("assemble /v1/identity");
    serde_json::from_str(&json).expect("valid JSON")
}

/// **The 0.5.195 regression, pinned.** `key_id` must agree with the key material
/// beside it. The aggregate's pubkeys come from the ENGINE's signer, so `key_id`
/// must be the engine's — never overwritten with the node's, which would leave a
/// consumer verifying a fingerprint against the wrong key.
#[tokio::test]
async fn the_key_id_agrees_with_the_key_material_beside_it() {
    const ACTOR: &str = "split-actor";
    const NODE: &str = "split-node";
    let engine = engine_for(ACTOR).await;
    register(&engine, &signer_for(ACTOR), ACTOR, identity_type::AGENT).await;
    register(&engine, &signer_for(NODE), NODE, identity_type::NODE).await;

    let v = payload(&engine, NODE, Some(ACTOR)).await;

    let engine_derived = engine
        .local_derived_key_id()
        .await
        .expect("engine derived key_id");
    assert_eq!(
        v["key_id"], engine_derived,
        "key_id must name the identity whose pubkeys this aggregate carries"
    );
    assert_ne!(
        v["key_id"], NODE,
        "relabelling the aggregate with the node key while its pubkeys stay the \
         actor's is the 0.5.195 defect"
    );
}

/// The node identity is STATED beside the aggregate rather than written over it.
#[tokio::test]
async fn the_node_key_is_its_own_field() {
    const ACTOR: &str = "split-actor-2";
    const NODE: &str = "split-node-2";
    let engine = engine_for(ACTOR).await;
    register(&engine, &signer_for(ACTOR), ACTOR, identity_type::AGENT).await;
    register(&engine, &signer_for(NODE), NODE, identity_type::NODE).await;

    let v = payload(&engine, NODE, Some(ACTOR)).await;
    assert_eq!(v["node_key_id"], NODE);
    assert_eq!(v["actor_key_id"], ACTOR);
    assert_ne!(
        v["node_key_id"], v["actor_key_id"],
        "on a split node these are different keys and both must be readable"
    );
}

/// **CIRISServer#507.** The kind is READ from the directory — not guessed from the
/// name, which is the sealed-keystore alias the host chose.
#[tokio::test]
async fn the_kind_is_read_from_the_directory_not_the_name() {
    // Agent-SHAPED name, registered as a node: a name-based guess gets this
    // backwards, which is why the field exists.
    const NODE: &str = "ciris-agent-bootstrap-abc123";
    let engine = engine_for("host").await;
    register(&engine, &signer_for(NODE), NODE, identity_type::NODE).await;

    let v = payload(&engine, NODE, None).await;
    assert_eq!(
        v["identity_type"],
        identity_type::NODE,
        "the registered kind governs, not the alias"
    );
}

/// An unregistered node key reports `identity_type: null` — never a default.
/// "Not in the directory" and "is a node" are different facts.
#[tokio::test]
async fn an_unresolvable_kind_is_null_and_not_defaulted() {
    let engine = engine_for("host2").await;
    let v = payload(&engine, "never-registered", None).await;
    assert!(
        v["identity_type"].is_null(),
        "an unread kind must not render as a real one: {}",
        v["identity_type"]
    );
}

/// A node with no agent says so with `null` rather than omitting the field —
/// omission is indistinguishable from a server too old to answer.
#[tokio::test]
async fn a_node_with_no_agent_says_null_rather_than_omitting() {
    const NODE: &str = "plain-node";
    let engine = engine_for(NODE).await;
    register(&engine, &signer_for(NODE), NODE, identity_type::NODE).await;

    let v = payload(&engine, NODE, None).await;
    assert!(
        v.as_object().expect("object").contains_key("actor_key_id"),
        "the field must always be present"
    );
    assert!(v["actor_key_id"].is_null());
}
