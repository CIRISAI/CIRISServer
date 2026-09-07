//! # A split node signs its consent as itself (CIRISServer#563)
//!
//! The Android run-without-AI leg (CIRISAgent#1149) died at boot with:
//!
//! ```text
//! re-author consent ciris-node-bootstrap-4w7a7jm6j5 -> ciris-canonical-1-…:
//! refusing to emit a consent grant naming "ciris-node-bootstrap-4w7a7jm6j5":
//! this engine signs as "ciris-agent-bootstrap-lbylhuoe7f" …
//! ```
//!
//! The engine signs as the ACTOR (the agent's alias, on purpose — passing the
//! node alias is #380's two-identities refusal). Boot mints or adopts the NODE
//! key through `node_key::node_signer`, whose `LocalSigner::key_id()` is the
//! keystore ALIAS while the node is registered as `derived_key_id()`. The
//! consent guard compared the alias to the derived id, so the boot re-author
//! that moves the actor's grants onto the node — the cure for CIRISServer#312 —
//! refused every grant it was asked to move. `tests/consent_survives_the_key_split.rs`
//! registered its node under a bare label and never saw it.
//!
//! This binary drives the PRODUCTION objects: a sealed keystore in a scratch
//! identity dir, `resolve_node_identity`'s split, `register_node_key`'s id, and
//! the re-author — then the runtime emit path with no explicit signer, which on
//! a split node must author as the node through the pen the process holds.
//!
//! One test, two phases, because the held node signer is process-wide.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord};
use ciris_persist::federation::SignedKeyRecord;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// The actor: the agent's own bootstrap alias, as the app passes it.
const ACTOR_ALIAS: &str = "ciris-agent-bootstrap";
const PEER: &str = "ciris-canonical-1-for-the-split-test";
const PEER_2: &str = "a-second-peer-consented-at-runtime";
const PEER_3: &str = "a-third-peer-named-through-the-actor";

fn seed(label: &str, n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&Sha256::digest(format!("{label}:{n}").as_bytes())[..32]);
    s
}

fn signer_for(alias: &str) -> LocalSigner {
    let ed = SigningKey::from_bytes(&seed(alias, 1));
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&seed(alias, 2), format!("{alias}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        ed,
        alias.to_string(),
        Some(pqc),
        Some(format!("{alias}-pqc")),
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
        None,
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

fn scratch_identity_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ciris-563-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::create_dir_all(&dir).expect("scratch identity dir");
    dir
}

#[tokio::test]
async fn the_split_node_reauthors_at_boot_and_authors_at_runtime_as_itself() {
    // The engine signs as the ACTOR — the embedded fold and the headless boot alike.
    let engine = Arc::new(
        Engine::with_signer(Arc::new(signer_for(ACTOR_ALIAS)), "sqlite::memory:")
            .await
            .expect("engine signing as the actor"),
    );
    let actor = engine
        .local_derived_key_id()
        .await
        .expect("actor derived id");
    register(
        &engine,
        &signer_for(ACTOR_ALIAS),
        &actor,
        identity_type::AGENT,
    )
    .await;
    register(&engine, &signer_for(PEER), PEER, identity_type::NODE).await;
    register(&engine, &signer_for(PEER_2), PEER_2, identity_type::NODE).await;
    register(&engine, &signer_for(PEER_3), PEER_3, identity_type::NODE).await;

    // ── Before the split: the wizard peers with the canonical. The engine is the
    //    only pen, so the grant is the ACTOR'S — the state every agent-hosted node
    //    is in after first setup.
    ciris_server::peer::emit_replication_consent(
        &engine,
        &actor,
        PEER,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("the actor authors the wizard-time grant");

    // ── The boot split, with the production objects: a sealed node keystore in
    //    the identity dir, the node key registered under its DERIVED id.
    let identity_dir = scratch_identity_dir();
    let resolution =
        ciris_server::node_key::resolve_node_identity(&engine, &actor, ACTOR_ALIAS, &identity_dir)
            .await
            .expect("resolve the node identity");
    assert!(resolution.did_split(), "an actor-configured key splits");
    let node = resolution.node_key_id.clone();
    let node_signer = resolution
        .signer
        .clone()
        .expect("the split holds the node's signer");
    assert_ne!(
        node_signer.key_id(),
        node.as_str(),
        "premise: the node signer names its key by ALIAS ({:?}) while the node is \
         registered as the DERIVED id ({node:?}) — the two conventions the guard must \
         both recognise",
        node_signer.key_id()
    );
    assert_eq!(node_signer.derived_key_id(), node);

    // ── Phase 1: the boot re-author — the exact call that crashed the Android node.
    let moved = ciris_server::node_key::reauthor_consent_as_node(
        &engine,
        node_signer.clone(),
        &actor,
        &node,
    )
    .await
    .expect("the boot re-author must move the actor's grant onto the node key (#563)");
    assert_eq!(moved, vec![PEER.to_string()]);
    assert_eq!(
        ciris_server::peer::replication_peers_from_consent(&engine, &node)
            .await
            .expect("read as the node"),
        vec![PEER.to_string()],
        "the node reads the topology it now authors — no #312 under a healthy transport"
    );
    let again = ciris_server::node_key::reauthor_consent_as_node(
        &engine,
        node_signer.clone(),
        &actor,
        &node,
    )
    .await
    .expect("second boot");
    assert!(again.is_empty(), "a second boot moves nothing: {again:?}");

    // ── Phase 2: a runtime emit on the split node — `POST /v1/federation/peers`,
    //    the edge's consent callback, the coverage top-up — names the NODE and
    //    passes no signer. The engine still signs as the actor; the pen the
    //    process holds for the node key authors it.
    assert!(
        ciris_server::node_key::held_node_signer().is_some(),
        "the split records the node's signer for the process"
    );
    ciris_server::peer::emit_replication_consent(
        &engine,
        &node,
        PEER_2,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("a runtime emit naming the node authors as the node through the held signer");
    let mut peers = ciris_server::peer::replication_peers_from_consent(&engine, &node)
        .await
        .expect("read as the node");
    peers.sort();
    let mut want = vec![PEER.to_string(), PEER_2.to_string()];
    want.sort();
    assert_eq!(peers, want);
    assert!(
        ciris_server::peer::replication_peers_from_consent(&engine, &actor)
            .await
            .expect("read as the actor")
            .iter()
            .all(|p| p != PEER_2),
        "the runtime grant did NOT land under the actor"
    );

    // ── Phase 3: a caller that names the ACTOR — the contacts surface's
    //    `self_identity::resolve`, the admin router's configured key — means
    //    "this node". It is normalised to the node, not refused and not authored
    //    under the actor (Codex P1 on #564).
    ciris_server::peer::emit_replication_consent(
        &engine,
        &actor,
        PEER_3,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("a grant named for the actor on a split node is authored as the node");
    assert!(
        ciris_server::peer::replication_peers_from_consent(&engine, &node)
            .await
            .expect("read as the node")
            .contains(&PEER_3.to_string()),
        "the node reads the grant the actor-naming caller asked for"
    );
    assert!(
        !ciris_server::peer::replication_peers_from_consent(&engine, &actor)
            .await
            .expect("read as the actor")
            .contains(&PEER_3.to_string()),
        "and it did NOT land under the actor"
    );

    // ── Phase 4: widening coverage (adding a contact) supersedes the node's
    //    standing grant with a row the NODE signs — same attester as the grant
    //    it retires (Codex P2 on #564). Named for the actor, like the contacts
    //    surface does.
    let defaults = ciris_server::peer::default_attestation_prefixes();
    let extra = ["hard_case:", "location:", "capacity:", "trace:"]
        .into_iter()
        .find(|p| !defaults.iter().any(|d| d == p))
        .expect("a prefix outside the default set, so the widening is real")
        .to_string();
    let coverage = ciris_server::peer::ensure_replication_consent_covers(
        &engine,
        &actor,
        PEER,
        std::slice::from_ref(&extra),
    )
    .await
    .expect("widen the node's grant");
    assert!(coverage.freshly_emitted, "a new, wider grant was written");
    assert!(
        coverage.superseded_attestation_id.is_some(),
        "the supersedes composer succeeded — the corpus says the narrower grant is retired"
    );
    let rows = engine
        .federation_directory()
        .list_attestations_by(&node)
        .await
        .expect("the node's rows");
    let supersedes: Vec<_> = rows
        .iter()
        .filter(|a| {
            a.attestation_type == ciris_persist::federation::types::attestation_type::SUPERSEDES
        })
        .collect();
    assert_eq!(
        supersedes.len(),
        1,
        "exactly one supersedes row, authored by the node"
    );
    assert_eq!(
        supersedes[0]
            .attestation_envelope
            .get(ciris_persist::federation::envelope::paths::REFERENCES_ATTESTATION_ID)
            .and_then(|v| v.as_str()),
        coverage.superseded_attestation_id.as_deref(),
        "and it retires the grant the coverage call says it retired"
    );
    assert!(
        ciris_server::peer::replication_peers_from_consent(&engine, &node)
            .await
            .expect("read as the node")
            .contains(&PEER.to_string()),
        "consent to the peer is never momentarily absent across the widening"
    );

    // ── Phase 5: the CC#46 `analyze` grant is the NODE's consent to be scored,
    //    signed with the node's pen, and it must RESOLVE (Codex P1 on #564).
    let analyze = ciris_server::peer::emit_analyze_consent(&engine, &actor, PEER)
        .await
        .expect("the analyze grant authors as the node and resolves");
    assert!(analyze.is_some(), "a fresh analyze grant was written");
    let resolved = engine
        .federation_directory()
        .resolve_scoped_consent(
            PEER,
            &node,
            ciris_persist::federation::admission::ANALYZE_CONSENT_SCOPE,
            None,
            chrono::Utc::now(),
        )
        .await
        .expect("resolve");
    assert!(
        matches!(
            resolved,
            ciris_persist::federation::hard_case::ConsentState::Granted
        ),
        "the peer may now score THIS NODE (the node key, not the actor): {resolved:?}"
    );
    assert!(
        ciris_server::peer::emit_analyze_consent(&engine, &actor, PEER)
            .await
            .expect("idempotent")
            .is_none(),
        "a second call finds the resolved stance and writes nothing"
    );

    // ── And the guard still refuses a pen that is not the node's.
    let err = ciris_server::peer::emit_replication_consent_with_policy(
        &engine,
        &node,
        "yet-another-peer",
        &ciris_server::peer::default_attestation_prefixes(),
        &ciris_server::peer::ConsentGrantOptions {
            author_signer: Some(Arc::new(signer_for(PEER))),
            ..Default::default()
        },
    )
    .await
    .expect_err("an explicit signer that does not hold the node key is refused");
    assert!(err
        .to_string()
        .contains("refusing to emit a consent grant naming"));

    let _ = std::fs::remove_dir_all(&identity_dir);
}
