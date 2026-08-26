//! # A node's identity is its own key — CC 3.4.7.3 Clause A, against a live substrate
//!
//! The unit tests beside `node_key` prove the classifier. These prove the thing
//! that actually failed in production: what happens when a real directory already
//! holds an actor-typed row under the key_id the node was told to be.
//!
//! Observed, before this change:
//!
//! ```text
//! key_id         ciris-agent-bootstrap-mplbdbzbed
//! identity_type  agent
//! self_key_id=ciris-agent-bootstrap-mplbdbzbed          ← the node, on the brain's key
//! ```
//!
//! `register_self_key` had tried to register that id as `node` and could not.
//! persist REFUSES it correctly — `Conflict: already exists with different
//! content` — and the swallow is on OUR side: `compose::register_self_key` maps
//! that Conflict to `Ok(())` at debug level, under a comment that accurately
//! says "a differing row already holds this key_id" and then calls it benign.
//!
//! Benign is right for the case it was written for (re-registering an identical
//! trust-root row). It is exactly wrong for this one, where the differing row is
//! an ACTOR row and the node proceeds believing it registered as `node`.
//!
//! **The first test here reproduces that**, because a fix whose failure mode was
//! never demonstrated is a fix nobody can check.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord};
use ciris_persist::federation::SignedKeyRecord;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_server::node_key::{classify, node_alias, IdentityVerdict};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::sync::Arc;

fn seed(label: &str, n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    let h = Sha256::digest(format!("{label}:{n}").as_bytes());
    s.copy_from_slice(&h[..32]);
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

/// Register through the canonical gate with a subject-binding envelope (#659).
async fn register(engine: &Engine, signer: &LocalSigner, key_id: &str, ident: &str) {
    let mut envelope = serde_json::json!({ "key_id": key_id });
    let probe = signer.sign_hybrid(b"probe").await.expect("probe sign");
    let ed_pub = B64.encode(&probe.classical.public_key);
    let pqc_pub = B64.encode(&probe.pqc.public_key);
    ciris_persist::federation::admission::bind_subject_into_envelope(
        &mut envelope,
        key_id,
        ident,
        &ed_pub,
        Some(&pqc_pub),
    )
    .expect("bind subject (#659)");
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .expect("canonicalize");
    let sig = signer.sign_hybrid(&canonical).await.expect("sign");
    let now = chrono::Utc::now();
    let record = KeyRecord {
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
    };
    engine
        .register_federation_key(SignedKeyRecord { record })
        .await
        .unwrap_or_else(|e| panic!("register {key_id}: {e}"));
}

/// `register`, but hands back the substrate's verdict instead of panicking.
async fn try_register(
    engine: &Engine,
    signer: &LocalSigner,
    key_id: &str,
    ident: &str,
) -> Result<(), ciris_persist::federation::Error> {
    let mut envelope = serde_json::json!({ "key_id": key_id });
    let probe = signer.sign_hybrid(b"probe").await.expect("probe sign");
    let ed_pub = B64.encode(&probe.classical.public_key);
    let pqc_pub = B64.encode(&probe.pqc.public_key);
    ciris_persist::federation::admission::bind_subject_into_envelope(
        &mut envelope,
        key_id,
        ident,
        &ed_pub,
        Some(&pqc_pub),
    )
    .expect("bind subject (#659)");
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .expect("canonicalize");
    let sig = signer.sign_hybrid(&canonical).await.expect("sign");
    let now = chrono::Utc::now();
    let record = KeyRecord {
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
    };
    engine
        .register_federation_key(SignedKeyRecord { record })
        .await
}

async fn engine_for(key_id: &str) -> Arc<Engine> {
    Arc::new(
        Engine::with_signer(Arc::new(signer_for(key_id)), "sqlite::memory:")
            .await
            .expect("Engine::with_signer(sqlite::memory:)"),
    )
}

const AGENT_KEY: &str = "ciris-agent-bootstrap-mplbdbzbed";

/// **The production defect, reproduced.** persist refuses the re-registration
/// with a typed `Conflict`; the row stays `agent`. What made this invisible is
/// that `compose::register_self_key` maps that Conflict to `Ok(())` — so the
/// node proceeded on a key that never said `node`.
///
/// This test pins BOTH halves: persist must refuse, and the refusal must name a
/// differing row rather than reporting success.
#[tokio::test]
async fn re_registering_an_actor_key_as_node_is_refused_and_changes_nothing() {
    let engine = engine_for(AGENT_KEY).await;
    let signer = signer_for(AGENT_KEY);
    register(&engine, &signer, AGENT_KEY, identity_type::AGENT).await;

    // Exactly what `register_self_key` does: same id, asserting `node`.
    let outcome = try_register(&engine, &signer, AGENT_KEY, identity_type::NODE).await;
    let err = outcome.expect_err(
        "persist must REFUSE a differing row for an occupied key_id — if this ever \
         succeeds, re-registration became destructive and the actor key's history \
         is at risk",
    );
    assert!(
        matches!(err, ciris_persist::federation::Error::Conflict(_)),
        "expected a typed Conflict, got {err:?} — consumers key on the variant, and \
         `register_self_key` branches on exactly this one"
    );

    let dir = engine.federation_directory();
    let row = dir
        .lookup_public_key(AGENT_KEY)
        .await
        .expect("directory read")
        .expect("row present");
    assert_eq!(
        row.identity_type,
        identity_type::AGENT,
        "the second registration returned Ok and the row is STILL `agent` — this is \
         ON CONFLICT DO NOTHING, and it is why a node could operate for months on a \
         key that never said `node`. If this ever fails, persist changed the \
         re-registration semantics and `resolve_node_identity` should be revisited."
    );
    assert_eq!(
        classify(dir.as_ref(), AGENT_KEY).await.expect("classify"),
        IdentityVerdict::Actor {
            roles: vec![identity_type::AGENT.to_string()]
        },
        "and the classifier must call it what it is"
    );
}

/// A `node`-only key classifies as usable — the standalone CIRISServer path,
/// which must not change.
#[tokio::test]
async fn a_node_only_key_is_usable_as_the_node_identity() {
    const NODE_KEY: &str = "ciris-server-node-only";
    let engine = engine_for(NODE_KEY).await;
    register(
        &engine,
        &signer_for(NODE_KEY),
        NODE_KEY,
        identity_type::NODE,
    )
    .await;
    let v = classify(engine.federation_directory().as_ref(), NODE_KEY)
        .await
        .expect("classify");
    assert_eq!(v, IdentityVerdict::SubstrateOnly);
    assert!(v.usable_as_node());
}

/// **The loophole, demonstrated at the substrate.** `{node,agent}` registers
/// happily — persist accepts the row — and it is precisely the composition that
/// makes the agency gate stop constraining the key. The classifier must call it
/// `Fused` and must NOT call it usable.
#[tokio::test]
async fn a_fused_node_agent_key_registers_and_must_still_be_refused() {
    const FUSED: &str = "fused-node-agent";
    let engine = engine_for(FUSED).await;
    register(&engine, &signer_for(FUSED), FUSED, "node,agent").await;

    let v = classify(engine.federation_directory().as_ref(), FUSED)
        .await
        .expect("classify");
    assert!(
        matches!(v, IdentityVerdict::Fused { .. }),
        "expected Fused, got {v:?} — a `{{node,agent}}` key is not merely an actor and \
         not merely substrate; it is the CC 3.4.7.3 Clause A violation, and collapsing \
         it into either neighbour loses the reason the clause exists"
    );
    assert!(
        !v.usable_as_node(),
        "a fused key must never be adopted as the node identity — persist's agency gate \
         constrains only a NODE-ONLY recipient, so operating as this key would leave \
         'infrastructure must not have agency' nominally true and actually unenforced"
    );
}

/// An unregistered key is not an actor and not substrate — it is unknown, and
/// unknown must be its own value. (Distinct-zeroes: "no row" and "a row saying
/// node" are different facts and a boot path branches differently on each.)
#[tokio::test]
async fn an_unregistered_key_is_its_own_verdict() {
    let engine = engine_for("nobody").await;
    let v = classify(engine.federation_directory().as_ref(), "never-registered")
        .await
        .expect("classify");
    assert_eq!(v, IdentityVerdict::Unregistered);
    assert!(!v.usable_as_node());
}

/// The node alias is derived, stable, and never collides with the actor's.
#[test]
fn the_node_alias_is_distinct_from_the_actor_alias() {
    assert_ne!(node_alias("ciris-agent-bootstrap"), "ciris-agent-bootstrap");
    assert_eq!(
        node_alias("ciris-agent-bootstrap"),
        "ciris-agent-bootstrap-node"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  The owner-binding follows the node key, unattended
// ═══════════════════════════════════════════════════════════════════════════

/// An unclaimed node has no binding to move, and that is not an error — an
/// unclaimed node is an ordinary state, not a failure.
#[tokio::test]
async fn nothing_to_move_when_the_actor_key_is_unowned() {
    let engine = engine_for(AGENT_KEY).await;
    let signer = signer_for(AGENT_KEY);
    register(&engine, &signer, AGENT_KEY, identity_type::AGENT).await;

    let moved = ciris_server::node_key::move_owner_binding_to_node_key(
        &engine,
        &signer,
        AGENT_KEY,
        "some-node-key",
    )
    .await
    .expect("an unowned actor key is not an error");
    assert!(moved.is_none(), "no binding exists, so nothing moves");
}

/// **The refusal that matters.** If the node holds a signer for someone OTHER
/// than the actor key's owner, moving the binding would mean authoring an
/// ownership claim as a party whose key we do not have. That must fail loudly
/// rather than write a binding signed by the wrong person.
#[tokio::test]
async fn refuses_to_move_a_binding_it_cannot_legitimately_author() {
    const OWNER: &str = "the-real-owner";
    const IMPOSTOR: &str = "some-other-user";
    let engine = engine_for(AGENT_KEY).await;

    register(
        &engine,
        &signer_for(AGENT_KEY),
        AGENT_KEY,
        identity_type::AGENT,
    )
    .await;
    register(&engine, &signer_for(OWNER), OWNER, identity_type::USER).await;
    register(
        &engine,
        &signer_for(IMPOSTOR),
        IMPOSTOR,
        identity_type::USER,
    )
    .await;

    // The real owner claims the actor key.
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let cohort = ciris_persist::federation::types::cohort_scope::SELF;
    let binding = ciris_server::auth::ownership::build_signed_owner_binding(
        &signer_for(OWNER),
        AGENT_KEY,
        &scopes,
        cohort,
    )
    .await
    .expect("build the original owner-binding");
    ciris_server::auth::ownership::apply_signed_owner_binding(
        &engine,
        AGENT_KEY,
        cohort,
        ciris_persist::prelude::HybridPolicy::Strict,
        &binding,
    )
    .await
    .expect("apply the original owner-binding");

    // Now attempt the move holding the WRONG signer.
    let err = ciris_server::node_key::move_owner_binding_to_node_key(
        &engine,
        &signer_for(IMPOSTOR),
        AGENT_KEY,
        "node-key-for-this-node",
    )
    .await
    .expect_err(
        "a node holding a signer for someone other than the owner must NOT author an \
         ownership claim — the whole point of moving the binding is that it stays the \
         SAME owner's claim",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("refusing to move the owner-binding"),
        "the refusal must name itself, got: {msg}"
    );
}
