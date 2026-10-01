//! **A claimed node finds the peers its owner consented to** — the receive-axis
//! pull (CIRISServer#601, the peer-read half).
//!
//! Production logs, every claimed node: `receive-axis pull found NO PEERS`. The
//! pull read its peers with `list_consent_peers(node)` — grants the MACHINE
//! authored. After the claim, consent is authored by the OWNER (#599: consent is
//! by humans) and names the machine through `for_key_id`, so the machine-authored
//! set is empty on exactly the nodes that have an owner to pull testimony for.
//!
//! This pins the by-principals read the pull now uses, folded over every key the
//! node is (a split install passes the ACTOR, while the consent names the NODE).

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

const NODE: &str = "ciris-node-for-the-receive-axis-test";
const PEER: &str = "ciris-canonical-the-owner-consented-to";
const ACTOR: &str = "agent-actor-key-on-a-split-install";
const PREFIXES: &[&str] = &["trace:", "capacity:"];

fn scratch_seed_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ciris-receive-axis-{}-{}-{}",
        std::process::id(),
        tag,
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("scratch seed dir");
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_claimed_node_finds_the_peers_its_owner_consented_to() {
    ciris_server::peer::set_owner_authored_consent(true);
    let node_signer = Arc::new(signer_for(NODE));
    let engine = Arc::new(
        Engine::with_signer(node_signer.clone(), "sqlite::memory:")
            .await
            .expect("engine signing as the node"),
    );
    let node = engine
        .local_derived_key_id()
        .await
        .expect("the node's derived key_id");
    register(&engine, &node_signer, &node, identity_type::NODE).await;
    register(&engine, &signer_for(PEER), PEER, identity_type::NODE).await;

    // Unclaimed: nothing to pull FOR, and nothing to ask.
    let own = ciris_server::receive_axis::own_keys(&node);
    assert_eq!(own.first().map(String::as_str), Some(node.as_str()));
    assert_eq!(
        ciris_server::receive_axis::owner_of_any(&engine, &own).await,
        None
    );

    // ── the claim, the way the wizard does it ──
    let seed_dir = scratch_seed_dir("owner");
    let alias = format!("ra-owner-{}", std::process::id());
    let minted = ciris_server::identity::mint_user_identity(
        ciris_server::identity::UserIdentityBackend::Software,
        &alias,
        Some("Receive Axis Owner"),
        seed_dir.clone(),
        ciris_server::identity::ActiveAlias::Adopt,
    )
    .await
    .expect("mint the owner's fed-ID");
    let owner = minted.key_id.clone();
    let owner_signer = ciris_server::identity::hardware_user_signers(
        ciris_server::identity::UserIdentityBackend::Software,
        &alias,
        seed_dir.clone(),
    )
    .await
    .expect("re-open the owner's fed-ID")
    .0;
    register(&engine, &owner_signer, &owner, identity_type::USER).await;
    ciris_server::node_key::set_user_seed_dir(seed_dir.clone(), alias.clone());
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    ciris_server::auth::ownership::emit_steward_binding(&engine, &owner_signer, &node, &scopes)
        .await
        .expect("the owner claims the node");

    // ── consent, authored by the OWNER (the claimed shape) ──
    ciris_server::peer::emit_replication_consent(&engine, &node, PEER, PREFIXES)
        .await
        .expect("consent authored as the owner");
    let by_owner = engine
        .federation_directory()
        .list_live_consent_grants_by(&owner)
        .await
        .expect("grants by the owner");
    assert!(
        by_owner
            .iter()
            .any(|g| g.subject_key_ids.first().map(String::as_str) == Some(PEER)),
        "precondition: the grant is the OWNER's, not the machine's"
    );

    // The read the pull USED to make: machine-authored grants only. On a claimed
    // node it is empty — which is the production "NO PEERS".
    let machine_only = engine
        .federation_directory()
        .list_consent_peers(&node)
        .await
        .expect("machine-authored consent peers");
    assert!(
        !machine_only.iter().any(|p| p == PEER),
        "the old read must not find the owner's grant, or this test pins nothing: \
         {machine_only:?}"
    );

    // The read the pull makes NOW.
    assert_eq!(
        ciris_server::receive_axis::owner_of_any(&engine, &own)
            .await
            .as_deref(),
        Some(owner.as_str()),
        "the claimed node has an owner to pull testimony for"
    );
    assert_eq!(
        ciris_server::receive_axis::peers_to_ask(&engine, &own).await,
        vec![PEER.to_string()],
        "a claimed node finds the peer its owner consented to (CIRISServer#601)"
    );

    // A split install: the caller passes the ACTOR (the edge signer); the
    // owner-binding and the consent name the NODE. Folded over both, the owner
    // and the peer are still found, and no own key is ever a peer.
    let split = vec![ACTOR.to_string(), node.clone()];
    assert_eq!(
        ciris_server::receive_axis::owner_of_any(&engine, &split)
            .await
            .as_deref(),
        Some(owner.as_str()),
        "the owner is found through the node key when the caller names the actor"
    );
    assert_eq!(
        ciris_server::receive_axis::peers_to_ask(&engine, &split).await,
        vec![PEER.to_string()],
        "the peer is found through the node key when the caller names the actor"
    );
    assert_eq!(
        ciris_server::receive_axis::peers_to_ask(&engine, &[ACTOR.to_string()]).await,
        Vec::<String>::new(),
        "keyed on the actor ALONE nothing is found — why the read must fold"
    );

    let _ = std::fs::remove_dir_all(&seed_dir);
}
