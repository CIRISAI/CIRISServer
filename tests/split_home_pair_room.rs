//! **A pair room is founded by the PERSON, never by their machine's key.**
//!
//! The five-platform run of 2026-10-27, after the contact ladder went green:
//! every creator `POST /v1/chat` answered 500 `chat.community_create_failed`,
//! `membership … refused (membership_founding_member_unsigned)`. The chat routes
//! signed the founding record with the ENGINE's key, which on a split home (an
//! agent embedding the node, 0.5.189 and later) is the AGENT key. An agent is
//! its own self and carries no owner-binding, so persist could not lift that
//! signer to the founder. Membership — founding, proposal, acceptance, a
//! joiner's intent — is the person's act, so the routes now sign it with the
//! owner's own pen (`contacts_chat::membership_pen`); in production the user's
//! signing key is always available.

use std::sync::Arc;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::engine::{SelfAtLoginInput, SelfAtLoginOccurrence};
use ciris_persist::federation::types::{cohort_scope, device_class};
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use ed25519_dalek::SigningKey;

use ciris_server::attest::{register_key, KeySigner};
use ciris_server::auth::ownership::{
    apply_signed_owner_binding, build_signed_owner_binding, OWNER_BINDING_INFRA_SCOPES,
};

fn id_of(alias: &str, seed: u8) -> String {
    let ed = SigningKey::from_bytes(&[seed; 32]);
    ciris_verify_core::fedcode::derive_key_id(alias, ed.verifying_key().as_bytes())
}

fn pen_as(seed: u8, key_id: &str) -> LocalSigner {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x5A; 32], format!("{key_id}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        SigningKey::from_bytes(&[seed; 32]),
        key_id.to_owned(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    )
}

/// An edge signer for the same key.
fn edge_of(pen: LocalSigner, key_id: &str) -> ciris_edge::identity::LocalSigner {
    let pen = Arc::new(pen);
    ciris_edge::identity::LocalSigner::new(
        key_id,
        Arc::new(ciris_persist::signing::LocalSignerHardwareAdapter::new(
            Arc::clone(&pen),
        )),
        pen.pqc_signer(),
    )
}

#[tokio::test]
async fn a_split_home_founds_its_pair_room_with_the_persons_key_not_the_agent_key() {
    // The split home: engine on the agent key, the owner bound to the node key,
    // the agent an occurrence of its human (the first-run claim's three rows).
    let owner_id = id_of("owner-pair-split", 0x35);
    let owner = pen_as(0x35, &owner_id);
    let agent = id_of("qa-runner-ciris-agent-split", 0x13);
    let engine = Arc::new(
        Engine::with_signer(
            Arc::new(pen_as(0x13, "qa-runner-ciris-agent-split")),
            "sqlite::memory:",
        )
        .await
        .expect("engine on the agent key"),
    );
    register_key(
        &engine,
        KeySigner::Engine(&engine),
        &agent,
        "agent",
        serde_json::Value::Null,
    )
    .await
    .expect("agent key");
    let node = id_of("ciris-node-bootstrap-pairsplit", 0x23);
    let node_pen = pen_as(0x23, &node);
    register_key(
        &engine,
        KeySigner::Local(&node_pen),
        &node,
        "node",
        serde_json::Value::Null,
    )
    .await
    .expect("node key");
    register_key(
        &engine,
        KeySigner::Local(&owner),
        &owner_id,
        "user",
        serde_json::Value::Null,
    )
    .await
    .expect("owner key");
    let scopes: Vec<String> = OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let binding = build_signed_owner_binding(&owner, &node, &scopes, cohort_scope::SELF)
        .await
        .unwrap();
    apply_signed_owner_binding(
        &engine,
        &node,
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &binding,
    )
    .await
    .expect("the owner claims the node");
    let enc = ciris_server::backend::content_kem_pubkeys(&engine)
        .await
        .expect("content KEM keys");
    engine
        .self_at_login(SelfAtLoginInput {
            identity_key_id: owner_id.clone(),
            identity_signer: Some(Arc::new(pen_as(0x35, "owner-pair-split"))),
            app: SelfAtLoginOccurrence {
                occurrence_key_id: node.clone(),
                device_class: ciris_server::backend::host_device_class().to_owned(),
                hardware_attestation: None,
                encryption_pubkeys: enc.clone(),
                transport_destinations: Vec::new(),
            },
            agent: SelfAtLoginOccurrence {
                occurrence_key_id: agent.clone(),
                device_class: device_class::AGENT.to_owned(),
                hardware_attestation: None,
                encryption_pubkeys: enc,
                transport_destinations: Vec::new(),
            },
            bilateral_pair_id: format!("fold:{owner_id}:{agent}"),
            delegation_scope: None,
        })
        .await
        .expect("the agent becomes an occurrence of its human");

    // The contact, as the add left them: their key is held here.
    let peer_id = id_of("peer-pair-split", 0x45);
    register_key(
        &engine,
        KeySigner::Local(&pen_as(0x45, &peer_id)),
        &peer_id,
        "user",
        serde_json::Value::Null,
    )
    .await
    .expect("peer key");

    let dir = engine.federation_directory();
    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::days(7);

    // The engine's key (what the routes used): the founder did not sign it.
    let agent_signer = edge_of(pen_as(0x13, &agent), &agent);
    let refused =
        ciris_edge::chat::open_pair_room(&*dir, &owner_id, &peer_id, now, expires, &agent_signer)
            .await
            .expect_err("an agent key does not act for its owner");
    assert!(
        refused.contains("membership_founding_member_unsigned"),
        "the production refusal: {refused}"
    );

    // The person's own pen (what the chat routes sign membership with): an
    // invitation is the person's act, and their signing key is always held.
    let owner_signer = edge_of(pen_as(0x35, &owner_id), &owner_id);
    let opened =
        ciris_edge::chat::open_pair_room(&*dir, &owner_id, &peer_id, now, expires, &owner_signer)
            .await
            .expect("the person founds their own room");
    assert!(opened.founded, "this call founded the room");
    assert!(opened.proposal.is_some(), "and invited the peer");

    // The invitation must be deliverable to the invitee's NODE (2026-10-27:
    // the joiner never listed it). The peer announced one node; this side
    // holds its key and the peer's owner-binding to it, as #907 left it.
    let peer_node = id_of("ciris-node-bootstrap-peersplit", 0x46);
    let peer_node_pen = pen_as(0x46, &peer_node);
    register_key(
        &engine,
        KeySigner::Local(&peer_node_pen),
        &peer_node,
        "node",
        serde_json::Value::Null,
    )
    .await
    .expect("peer node key");
    let peer_pen = pen_as(0x45, &peer_id);
    let peer_binding =
        build_signed_owner_binding(&peer_pen, &peer_node, &scopes, cohort_scope::SELF)
            .await
            .unwrap();
    apply_signed_owner_binding(
        &engine,
        &peer_node,
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &peer_binding,
    )
    .await
    .expect("the peer's owner-binding is held here");
    // The invitee's own login ceremony, as their node publishes it and this
    // side pulls it with their records (#907): their node and agent are
    // occurrences of the invitee. Production holds these; the first version of
    // this test did not, and saw Yes where production saw NotInAudience.
    let peer_agent = id_of("qa-runner-ciris-agent-peersplit", 0x47);
    register_key(
        &engine,
        KeySigner::Local(&pen_as(0x47, &peer_agent)),
        &peer_agent,
        "agent",
        serde_json::Value::Null,
    )
    .await
    .expect("peer agent key");
    let enc2 = ciris_server::backend::content_kem_pubkeys(&engine)
        .await
        .expect("content KEM keys");
    let peer_login = engine
        .self_at_login(SelfAtLoginInput {
            identity_key_id: peer_id.clone(),
            identity_signer: Some(Arc::new(pen_as(0x45, "peer-pair-split"))),
            app: SelfAtLoginOccurrence {
                occurrence_key_id: peer_node.clone(),
                device_class: ciris_server::backend::host_device_class().to_owned(),
                hardware_attestation: None,
                encryption_pubkeys: enc2.clone(),
                transport_destinations: Vec::new(),
            },
            agent: SelfAtLoginOccurrence {
                occurrence_key_id: peer_agent.clone(),
                device_class: device_class::AGENT.to_owned(),
                hardware_attestation: None,
                encryption_pubkeys: enc2,
                transport_destinations: Vec::new(),
            },
            bilateral_pair_id: format!("fold:{peer_id}:{peer_agent}"),
            delegation_scope: None,
        })
        .await;
    eprintln!(
        "peer login ceremony at the creator: {:?}",
        peer_login.as_ref().map(|_| "ok")
    );
    // The invitee's node agrees, in its own hand, to be their device — what a
    // split home publishes since 0.5.241 (`node_key::publish_node_occurrence`).
    // With it the node resolves to the invitee as an AGREED device on any peer,
    // with or without persist's owner-binding fallback.
    {
        use ciris_persist::engine::BackendDispatch;
        // Named by ALIAS, as the held node signer is: its derived id is the node key.
        let node_signer = Arc::new(pen_as(0x46, "ciris-node-bootstrap-peersplit"));
        match engine.backend() {
            BackendDispatch::Sqlite(b) => {
                ciris_persist::federation::key_grant::publish_self_occurrence_with_local_signer(
                    b.as_ref(),
                    &node_signer,
                    &peer_id,
                    ciris_server::backend::host_device_class(),
                    None,
                )
                .await
                .expect("the invitee's node agrees to be their device");
            }
            #[allow(unreachable_patterns)]
            _ => unreachable!("in-memory sqlite"),
        }
    }
    // What a peer receives is the CURRENT signed row for the pair, and it is
    // last-signed-wins: published after the ceremony, it is the node's own.
    let current_signer = |rows: Vec<ciris_persist::federation::SignedIdentityOccurrence>| {
        rows.into_iter()
            .find(|r| r.identity_occurrence.occurrence_key_id == peer_node)
            .map(|r| r.attesting_key_id)
    };
    assert_eq!(
        current_signer(
            dir.list_signed_identity_occurrences_for(&peer_id)
                .await
                .unwrap()
        )
        .as_deref(),
        Some(peer_node.as_str()),
        "after the ceremony, the node's agreement is the current row peers receive"
    );
    let active = dir
        .active_identities_for_occurrence(&peer_node)
        .await
        .unwrap();
    assert!(
        active.contains(&peer_id),
        "the agreed occurrence resolves the invitee's node to the invitee: {active:?}"
    );
    let occs = dir
        .list_identity_occurrences_by_occurrence_key(&peer_node)
        .await
        .unwrap();
    eprintln!(
        "peer node: active identities={active:?} occurrence rows={:?}",
        occs.iter()
            .map(|o| (o.identity_key_id.clone(), o.device_class.clone()))
            .collect::<Vec<_>>()
    );
    let proposal = opened.proposal.expect("proposal");
    let principals = ciris_persist::federation::self_collective::principals_of(&*dir, &peer_node)
        .await
        .unwrap();
    let verdict =
        ciris_persist::federation::replication_audience::may_receive(&*dir, &peer_node, &proposal)
            .await
            .unwrap();
    eprintln!(
        "proposal subject={:?} scope={} attester={} tier={} | peer node principals={principals:?} | verdict={verdict:?}",
        proposal.subject_key_ids, proposal.cohort_scope, proposal.attesting_key_id, proposal.tier
    );
    assert!(
        verdict.allowed(),
        "the invitation reaches the invitee's node: {verdict:?}"
    );

    // The room's own record and its roster rows (the group plane) must reach
    // the live invitee's node too, or the joiner never learns it is seated and
    // never publishes its KeyPackage (2026-10-28: `membership-plane row
    // withheld — the recipient is neither a member's node, a live invitee's
    // node …` toward the joiner, every round).
    let group_verdict = ciris_persist::federation::replication_audience::may_receive_group_plane(
        &*dir,
        &peer_node,
        cohort_scope::COMMUNITY,
        &opened.room,
        None,
    )
    .await
    .unwrap();
    eprintln!("group plane verdict for the invitee's node: {group_verdict:?}");
    assert!(
        group_verdict.allowed(),
        "the room record reaches the live invitee's node: {group_verdict:?}"
    );
}
