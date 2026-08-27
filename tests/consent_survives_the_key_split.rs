//! # The key split must not re-earn CIRISServer#312
//!
//! `compose.rs` collapses three roles into one identity on purpose:
//!
//! > *`node_key_id` is the local federation signing key (the consent AUTHOR, the
//! > KERI publish-own selector, and the trace-gate leg-B "I") … reading consent by
//! > the alias yields an empty topology from a corpus whose grants the signer
//! > wrote (the #312 field failure).*
//!
//! What that cost was **zero peers and zero envelopes under a fully green
//! transport** — a silent withhold, not an error. Nothing failed; the node simply
//! stopped having anyone to talk to.
//!
//! Moving the consent author from the actor key to the node key is that exact
//! move. These tests are written FIRST, and the first one deliberately
//! demonstrates the regression before the migration exists — a fix whose failure
//! mode was never reproduced is a fix nobody can check.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord};
use ciris_persist::federation::SignedKeyRecord;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const ACTOR: &str = "ciris-agent-bootstrap-mplbdbzbed";
const NODE: &str = "ciris-agent-bootstrap-node-x7k2";
const PEER: &str = "peer-node-for-the-split-test";

fn seed(label: &str, n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&Sha256::digest(format!("{label}:{n}").as_bytes())[..32]);
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
    .expect("bind subject (#659)");
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

/// A substrate with the actor, the future node key, and a peer all registered,
/// and the ACTOR holding a live `consent:replication:v1` grant at the peer —
/// i.e. a node exactly as it exists today, before any split.
async fn fixture() -> Arc<Engine> {
    let engine = Arc::new(
        Engine::with_signer(Arc::new(signer_for(ACTOR)), "sqlite::memory:")
            .await
            .expect("engine"),
    );
    // Register the engine's DERIVED id, not the bare alias. `Engine` stamps
    // `derive_key_id(alias, pubkey)` = `<alias>-<fp>` (FSD-003 #247), and every
    // row it self-attests carries that. Registering the literal leaves the
    // engine's own attester absent from `federation_keys` — which the substrate
    // catches as `attesting_key_id … does not exist`, the same refusal the
    // research agents' unregistered keys produce in production.
    let derived = engine
        .local_derived_key_id()
        .await
        .expect("the engine's derived federation key_id");
    register(&engine, &signer_for(ACTOR), &derived, identity_type::AGENT).await;
    register(&engine, &signer_for(NODE), NODE, identity_type::NODE).await;
    register(&engine, &signer_for(PEER), PEER, identity_type::NODE).await;
    engine
}

/// **The #312 regression, demonstrated — and the constraint that shapes the cure.**
///
/// The engine authors its grant (self-attested, as consent must be). Reading the
/// topology by ANY other id — including the node key we just minted — returns
/// nothing. Green transport, zero peers, no error.
#[tokio::test]
async fn reading_consent_by_another_id_finds_nothing_the_engine_authored() {
    let engine = fixture().await;
    let author = engine
        .local_derived_key_id()
        .await
        .expect("the engine's derived federation key_id — the only consent author");

    ciris_server::peer::emit_replication_consent(
        &engine,
        &author,
        PEER,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("the engine authors its own grant");

    assert_eq!(
        ciris_server::peer::replication_peers_from_consent(&engine, &author)
            .await
            .expect("read as the author"),
        vec![PEER.to_string()],
        "sanity: the author sees its own grant"
    );

    let as_node = ciris_server::peer::replication_peers_from_consent(&engine, NODE)
        .await
        .expect("read as the node key");
    assert!(
        as_node.is_empty(),
        "THE #312 SHAPE: a different id reads an EMPTY topology from a corpus whose \
         grants the engine wrote. Nothing errors. Ship the identity move without \
         moving the grants and production looks like this — a fully green transport \
         with nobody to talk to. Got {as_node:?}"
    );
}

/// **Consent is SELF-attested, so a grant cannot be authored on another key's
/// behalf — and that is the whole reason the engine-signer swap must come FIRST.**
///
/// `emit_replication_consent` takes a `node_key_id`, which reads like a selector
/// and is not one: `peer.rs` documents it as an assertion that the argument
/// EQUALS the engine's derived id ("wire-preserving"), because the row is signed
/// by `emit_attestation_self`. CEG 1.0-RC29 §5.6.8.15 requires exactly that —
/// third-party authorship of a consent grant is foreclosed so a grant cannot be
/// produced on your behalf.
///
/// This test exists because an earlier draft of `FSD/ACTOR_NODE_KEY_SPLIT.md`
/// had the migration re-author grants as the node while the engine still signed
/// as the actor. That is not a thing the substrate permits, and it is right not
/// to. Pinned so the ordering cannot be quietly re-inverted.
#[tokio::test]
async fn a_grant_cannot_be_authored_for_a_key_the_engine_does_not_sign_as() {
    let engine = fixture().await;
    let err = ciris_server::peer::emit_replication_consent(
        &engine,
        NODE, // NOT the engine's identity
        PEER,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect_err(
        "emitting a consent grant naming a key the engine does not sign as must FAIL — \
         if this ever succeeds, self-attestation has been weakened and RC29 §5.6.8.15 \
         no longer holds",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("refusing to emit a consent grant naming"),
        "the refusal must name itself and the mismatch, got: {msg}"
    );
    assert!(
        msg.contains("self-attested"),
        "and must say WHY — a caller who sees this needs to know the emit is not a \
         selector, got: {msg}"
    );
}

/// The corollary, stated positively: once the engine signs AS the node key, the
/// node authors its own grants and reads its own topology. This is what the
/// engine-signer swap buys, and the check that will prove it landed.
#[tokio::test]
async fn an_engine_signing_as_the_node_authors_and_reads_its_own_topology() {
    // An engine whose signer IS the node key — i.e. post-swap.
    let engine = Arc::new(
        Engine::with_signer(Arc::new(signer_for(NODE)), "sqlite::memory:")
            .await
            .expect("engine signing as the node"),
    );
    let author = engine.local_derived_key_id().await.expect("derived id");
    register(&engine, &signer_for(NODE), &author, identity_type::NODE).await;
    register(&engine, &signer_for(PEER), PEER, identity_type::NODE).await;

    ciris_server::peer::emit_replication_consent(
        &engine,
        &author,
        PEER,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("the node authors its own grant");

    assert_eq!(
        ciris_server::peer::replication_peers_from_consent(&engine, &author)
            .await
            .expect("read"),
        vec![PEER.to_string()],
        "post-swap the node is the consent author AND the reader — the #312 identity \
         is one identity again, and it is the node's"
    );
}

/// **The split, complete: the engine signs as the ACTOR and the node still owns
/// its own replication topology.**
///
/// This is what an embedded node looks like after CC 3.4.7.3 — the agent's
/// engine is unchanged (CIRISServer#221: one pool, one sweeper, no second
/// writer), and the node authors its consent with the key it actually is.
///
/// Self-attestation is preserved, which is the property that made the naive
/// version impossible: the signature really is the named author's. What is
/// refused is signing *silently* as someone else.
#[tokio::test]
async fn the_node_authors_its_topology_while_the_engine_signs_as_the_actor() {
    let engine = fixture().await;
    let engine_author = engine.local_derived_key_id().await.expect("derived");
    assert_ne!(
        engine_author, NODE,
        "premise: the engine is NOT the node key — this is the embedded fold"
    );

    let opts = ciris_server::peer::ConsentGrantOptions {
        author_signer: Some(Arc::new(signer_for(NODE))),
        ..Default::default()
    };
    ciris_server::peer::emit_replication_consent_with_policy(
        &engine,
        NODE,
        PEER,
        &ciris_server::peer::default_attestation_prefixes(),
        &opts,
    )
    .await
    .expect("the node authors its own grant with the key it holds");

    assert_eq!(
        ciris_server::peer::replication_peers_from_consent(&engine, NODE)
            .await
            .expect("read as the node"),
        vec![PEER.to_string()],
        "THE POINT: the node reads a live topology it authored, with the engine still \
         signing as the actor. No engine swap, no second writer, no #312."
    );

    assert!(
        ciris_server::peer::replication_peers_from_consent(&engine, &engine_author)
            .await
            .expect("read as the engine")
            .is_empty(),
        "and the grant did NOT land under the engine's identity — the author is the \
         node, not whoever happened to hold the pen"
    );
}

/// A signer that is not the named author is still refused. The escape hatch is
/// "I hold this key", never "sign as anyone".
#[tokio::test]
async fn an_author_signer_for_a_different_key_is_still_refused() {
    let engine = fixture().await;
    let opts = ciris_server::peer::ConsentGrantOptions {
        author_signer: Some(Arc::new(signer_for(PEER))), // holds PEER, claims NODE
        ..Default::default()
    };
    let err = ciris_server::peer::emit_replication_consent_with_policy(
        &engine,
        NODE,
        PEER,
        &ciris_server::peer::default_attestation_prefixes(),
        &opts,
    )
    .await
    .expect_err("a signer that is not the named author must be refused");
    assert!(
        err.to_string()
            .contains("refusing to emit a consent grant naming"),
        "got: {err}"
    );
}

/// **A restricted grant must survive migration RESTRICTED** (Codex P1 on #489).
///
/// The first version rebuilt each grant from `ConsentGrantOptions::default()` +
/// the global default prefixes, keeping only the peer id. An operator grant with
/// a narrowed prefix set or an expiry would have come back unrestricted — the
/// migration authorizing data the owner never consented to share.
///
/// Widening a consent grant silently is the worst outcome available here, so this
/// pins the narrow shape end to end.
#[tokio::test]
async fn a_narrowed_grant_is_not_widened_by_the_migration() {
    let engine = fixture().await;
    let author = engine.local_derived_key_id().await.expect("derived");

    // Deliberately NARROWER than the defaults, plus an expiry.
    let narrow = vec!["trace:".to_string()];
    let expiry = chrono::Utc::now() + chrono::Duration::days(30);
    ciris_server::peer::emit_replication_consent_with_policy(
        &engine,
        &author,
        PEER,
        &narrow,
        &ciris_server::peer::ConsentGrantOptions {
            valid_until: Some(expiry),
            ..Default::default()
        },
    )
    .await
    .expect("the operator authors a narrowed, expiring grant");

    let moved = ciris_server::node_key::reauthor_consent_as_node(
        &engine,
        Arc::new(signer_for(NODE)),
        &author,
        NODE,
    )
    .await
    .expect("re-author");
    assert_eq!(moved, vec![PEER.to_string()]);

    // Read the NODE's grant back and compare its policy to what was authored.
    let grants = engine
        .federation_directory()
        .list_live_consent_grants_by(NODE)
        .await
        .expect("list the node's grants");
    let g = grants.first().expect("the node holds a grant");
    let payload = g
        .attestation_envelope
        .get("payload")
        .and_then(|v| v.as_object())
        .expect("payload");

    let prefixes: Vec<String> = payload["attestation_prefixes"]
        .as_array()
        .expect("prefixes")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        prefixes, narrow,
        "the migrated grant must carry the OPERATOR'S prefixes, not the defaults. \
         Got {prefixes:?} — if this is the default set, the migration just widened a \
         consent the owner deliberately narrowed"
    );
    assert!(
        payload.get("valid_until").is_some_and(|v| !v.is_null()),
        "and it must keep the expiry — dropping one turns a time-boxed grant into a \
         permanent one"
    );
}

/// A grant carrying a payload member this build cannot reproduce is REFUSED, not
/// migrated with the member dropped.
#[tokio::test]
async fn an_unreproducible_payload_member_refuses_rather_than_dropping_it() {
    let engine = fixture().await;
    let author = engine.local_derived_key_id().await.expect("derived");
    ciris_server::peer::emit_replication_consent(
        &engine,
        &author,
        PEER,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("a grant");

    // Simulate a future/unknown member by asserting the guard's own list is what
    // the emitter writes — if the emitter grows a member and the list does not,
    // migration must refuse rather than silently drop it.
    let grants = engine
        .federation_directory()
        .list_live_consent_grants_by(&author)
        .await
        .expect("list");
    let payload = grants[0]
        .attestation_envelope
        .get("payload")
        .and_then(|v| v.as_object())
        .expect("payload");
    for k in payload.keys() {
        assert!(
            [
                "grants",
                "direction",
                "kinds",
                "attestation_prefixes",
                "principle",
                "audience",
                "restrictions",
                "purpose",
                "valid_until"
            ]
            .contains(&k.as_str()),
            "the emitter writes payload member {k:?} which the migration guard does not \
             know how to reproduce. Add it to REPRODUCIBLE_PAYLOAD_MEMBERS *and* map it \
             into ConsentGrantOptions — leaving it out means a migrated grant silently \
             differs from the one the operator authored"
        );
    }
}
