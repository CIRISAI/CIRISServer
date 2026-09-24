//! CIRISServer#632 — a HUMAN's consent grant names the MACHINE they are bound
//! to in `for_key_id`, never themselves.
//!
//! The chat ladder went red at `room:node-a` (`POST /v1/chat` 403
//! `chat.not_a_contact`) right after `POST /v1/contacts` returned 200 (2026-09-24,
//! CI and locally, deterministic). The person-contact grant was stored with
//! `for_key_id = <the owner>` while every node-peer grant carried the node key,
//! and `live_consent_grants_for_machine(node)` keeps only grants whose
//! `for_key_id == node` — so the node could not see the grant it had just
//! authored.
//!
//! Mechanism: `ensure_replication_consent_covers` shadows `node_key_id` with
//! `author.key_id` (the owner) and its widen/emit path re-resolves the author
//! with `requested = owner`; `bound_own_key_for` took `requested` first, and
//! persist's `steward_bindings_of` clause 1 says a `user`-role key steward-binds
//! ITSELF, so the human "was bound to" their own key. Identity is not a binding
//! to a machine. The author's own key is never a candidate now.
//!
//! This pins the whole surface the ladder crossed, in-process, on an UNSPLIT
//! owned node (the chat ladder's shape) with a production-shaped pen:
//!
//! 1. `POST /v1/contacts`' door (`ensure_contact_consent_covers`) for a PERSON,
//!    then `POST /v1/chat`'s read (`contact_grant_prefixes`) finds it covering
//!    `chat:` — the exact pair that broke;
//! 2. the grant's envelope `for_key_id` IS the node key, on the owner path
//!    (`consent_author(node)`), on the owner path re-entered with the owner's
//!    own key as `requested` (the widen shape), and on the explicit-pen path;
//! 3. `consent_peers_by_principals(node)` — the fold every runtime read uses —
//!    resolves the person.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord};
use ciris_persist::federation::SignedKeyRecord;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

const NODE_ALIAS: &str = "ciris-node-a-for-the-persons-grant-test";
const PERSON: &str = "ciris-node-b-user-the-other-person";
const NODE_PEER: &str = "ciris-node-b-the-other-persons-node";

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

fn for_key_id_of(engine_row: &ciris_persist::federation::types::Attestation) -> Option<String> {
    ciris_persist::federation::consent_by_humans::for_key_id_of(&engine_row.attestation_envelope)
        .map(str::to_owned)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_persons_contact_grant_names_the_node_and_the_node_can_read_it() {
    // ── an UNSPLIT owned node: engine key == node key (the chat ladder's shape) ──
    let engine = Arc::new(
        Engine::with_signer(Arc::new(signer_for(NODE_ALIAS)), "sqlite::memory:")
            .await
            .expect("engine signing as the node"),
    );
    let node = engine
        .local_derived_key_id()
        .await
        .expect("node derived id");
    register(&engine, &signer_for(NODE_ALIAS), &node, identity_type::NODE).await;
    register(&engine, &signer_for(PERSON), PERSON, identity_type::USER).await;
    register(
        &engine,
        &signer_for(NODE_PEER),
        NODE_PEER,
        identity_type::NODE,
    )
    .await;

    // ── the owner, with a PRODUCTION-SHAPED pen (key_id = the derived id) ──
    let seed_dir = std::env::temp_dir().join(format!(
        "ciris-632-persons-grant-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    std::fs::create_dir_all(&seed_dir).expect("owner seed dir");
    let alias = format!("persons-grant-owner-{}", std::process::id());
    let minted = ciris_server::identity::mint_user_identity(
        ciris_server::identity::UserIdentityBackend::Software,
        &alias,
        Some("Persons Grant Owner"),
        seed_dir.clone(),
        ciris_server::identity::ActiveAlias::Adopt,
    )
    .await
    .expect("mint the owner");
    let owner = minted.key_id.clone();
    let owner_signer = ciris_server::identity::hardware_user_signers(
        ciris_server::identity::UserIdentityBackend::Software,
        &alias,
        seed_dir.clone(),
    )
    .await
    .expect("re-open the owner")
    .0;
    assert_eq!(
        owner_signer.key_id(),
        owner,
        "production pen: named by the derived id"
    );
    register(&engine, &owner_signer, &owner, identity_type::USER).await;
    ciris_server::node_key::set_user_seed_dir(seed_dir.clone(), alias.clone());
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    ciris_server::auth::ownership::emit_steward_binding(&engine, &owner_signer, &node, &scopes)
        .await
        .expect("the human claims the node");
    assert!(
        engine
            .steward_bindings_of(&node)
            .await
            .expect("stewards of the node")
            .contains(&owner),
        "premise: the owner steward-binds the node"
    );
    assert!(
        engine
            .steward_bindings_of(&owner)
            .await
            .expect("stewards of the owner")
            .contains(&owner),
        "premise (persist clause 1): a user-role key steward-binds ITSELF — the fact that \
         made the author's own key look 'bound to' and broke the grant"
    );

    // ── 1. POST /v1/contacts' door, then POST /v1/chat's read ─────────────────
    let prefixes = ["capacity:", "chat:", "self:delegates_to:", "trace:"];
    let (coverage, subjects) =
        ciris_server::peer::ensure_contact_consent_covers(&engine, &node, PERSON, &prefixes)
            .await
            .expect("the human's contact grant is authored");
    assert!(
        coverage.freshly_emitted,
        "a fresh grant for a fresh contact"
    );
    assert_eq!(
        subjects,
        vec![PERSON.to_string()],
        "no bound nodes yet: the person is the subject"
    );
    let read = ciris_server::peer::contact_grant_prefixes(&engine, &node, PERSON)
        .await
        .expect("the room-create read runs")
        .expect(
            "POST /v1/chat's read finds the grant POST /v1/contacts just authored — \
             `None` here is the 403 `chat.not_a_contact` the ladder measured",
        );
    assert!(
        read.iter().any(|p| p == "chat:"),
        "and it covers chat: ({read:?})"
    );

    // ── 2. the envelope names the NODE, on every author path ──────────────────
    let by_owner = engine
        .federation_directory()
        .list_live_consent_grants_by(&owner)
        .await
        .expect("grants by the owner");
    let row = by_owner
        .iter()
        .find(|g| g.subject_key_ids.iter().any(|s| s == PERSON))
        .expect("the person-contact grant is the human's");
    assert_eq!(
        for_key_id_of(row).as_deref(),
        Some(node.as_str()),
        "for_key_id is the MACHINE the human is bound to, not the human"
    );
    let owner_path = ciris_server::peer::consent_author(&engine, &node, None)
        .await
        .expect("owner path, requested = node");
    assert_eq!(owner_path.key_id, owner);
    assert_eq!(owner_path.for_key_id.as_deref(), Some(node.as_str()));
    let widen_shape = ciris_server::peer::consent_author(&engine, &owner, None)
        .await
        .expect("owner path re-entered with the owner's own key as requested (the widen shape)");
    assert_eq!(widen_shape.key_id, owner);
    assert_eq!(
        widen_shape.for_key_id.as_deref(),
        Some(node.as_str()),
        "requested == the human: still names the node, never the human"
    );
    let explicit =
        ciris_server::peer::consent_author(&engine, &owner, Some(Arc::new(owner_signer)))
            .await
            .expect("explicit pen naming itself");
    assert_eq!(
        explicit.for_key_id.as_deref(),
        Some(node.as_str()),
        "an explicit human pen names the node it is bound to"
    );

    // ── 3. the runtime fold resolves the person for the node ──────────────────
    let peers = engine
        .consent_peers_by_principals(&node)
        .await
        .expect("by-principals read for the node");
    assert!(
        peers.contains(&PERSON.to_string()),
        "the node's consent peers: {peers:?}"
    );

    // A node peer still gets the same answer (the path that never broke).
    ciris_server::peer::ensure_contact_consent_covers(&engine, &node, NODE_PEER, &prefixes)
        .await
        .expect("node-peer grant");
    let read = ciris_server::peer::contact_grant_prefixes(&engine, &node, NODE_PEER)
        .await
        .expect("read")
        .expect("found");
    assert!(read.iter().any(|p| p == "chat:"));

    let _ = std::fs::remove_dir_all(&seed_dir);
}
