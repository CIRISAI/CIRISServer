//! **An agent's deferral, the Wise Authority's answer, and the identity
//! amendment it authorises** (CIRISAgent#1316; CC rc10 3.1.9.4 / 3.1.5; T7's
//! `agent.deferral.*` and `agent.identity.amended`).
//!
//! On a live substrate: the agent's node (engine on the agent's key), owned by a
//! human whose pen is the seated WA (Eric, 2026-10-22: the owner is the seated
//! WA for their own agent).

use std::sync::Arc;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::cohort_scope;
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use ed25519_dalek::SigningKey;

use ciris_server::agent_deferral::{
    emit_deferral_request, emit_deferral_response, emit_identity_amendment, sign_deferral_response,
    AgentRowError, DeferralRequest, DEFERRAL_APPROVED, DEFERRAL_REJECTED, DEFERRAL_REQUEST,
    IDENTITY_AMENDMENT, ROOM_FIELD,
};
use ciris_server::attest::{self, register_key, KeySigner, Spec};
use ciris_server::auth::ownership::{
    apply_signed_owner_binding, build_signed_owner_binding, OWNER_BINDING_INFRA_SCOPES,
};

fn id_of(alias: &str, seed: u8) -> String {
    let ed = SigningKey::from_bytes(&[seed; 32]);
    ciris_verify_core::fedcode::derive_key_id(alias, ed.verifying_key().as_bytes())
}

/// A pen for `alias` from `seed`, named by its registered id.
fn pen(alias: &str, seed: u8) -> LocalSigner {
    pen_as(seed, &id_of(alias, seed))
}

/// The same key named `key_id` — by its ALIAS for an engine, which derives its
/// own registered id from it.
fn pen_as(seed: u8, key_id: &str) -> LocalSigner {
    let key_id = key_id.to_owned();
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x5A; 32], format!("{key_id}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        SigningKey::from_bytes(&[seed; 32]),
        key_id.clone(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    )
}

const DIGEST: &str = "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233";

/// The agent's node, owned by `owner`. Returns (engine, agent key).
async fn owned_agent(owner: &LocalSigner) -> (Arc<Engine>, String) {
    let agent = id_of("ciris-agent-t7", 0x11);
    let engine = Arc::new(
        Engine::with_signer(Arc::new(pen_as(0x11, "ciris-agent-t7")), "sqlite::memory:")
            .await
            .expect("engine"),
    );
    register_key(
        &engine,
        KeySigner::Engine(&engine),
        &agent,
        "node",
        serde_json::Value::Null,
    )
    .await
    .expect("register the node's key");
    let scopes: Vec<String> = OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let binding = build_signed_owner_binding(owner, &agent, &scopes, cohort_scope::SELF)
        .await
        .unwrap();
    apply_signed_owner_binding(
        &engine,
        &agent,
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &binding,
    )
    .await
    .expect("the owner claims the node");
    (engine, agent)
}

fn request(room: Option<&str>) -> DeferralRequest {
    DeferralRequest {
        deferral_id: "def-1".into(),
        task_id: "task-1".into(),
        thought_id: "thought-1".into(),
        reason_digest: DIGEST.into(),
        domain_hint: Some("ethics".into()),
        room_id: room.map(str::to_owned),
    }
}

async fn row(engine: &Engine, id: &str) -> ciris_persist::federation::types::Attestation {
    engine
        .federation_directory()
        .get_attestation(id)
        .await
        .unwrap()
        .expect("stored")
}

#[tokio::test]
async fn the_deferral_round_trip_ends_in_an_amendment_citing_the_approval() {
    let owner = pen("owner-fedid", 0x33);
    let (engine, agent) = owned_agent(&owner).await;
    let room = ciris_edge::chat::pair_community_key_id(&agent, owner.key_id());

    // 1. The agent defers, in its room with the owner.
    let req_id = emit_deferral_request(&engine, &agent, &request(Some(&room)))
        .await
        .expect("the agent's occurrence key signs the request");
    let req = row(&engine, &req_id).await;
    assert_eq!(req.attestation_envelope["dimension"], DEFERRAL_REQUEST);
    assert_eq!(req.attesting_key_id, agent, "the occurrence key signs");
    assert_eq!(
        req.attested_key_id, agent,
        "about the agent's identity (its own self here)"
    );
    assert_eq!(req.attestation_envelope["deferral_id"], "def-1");
    assert_eq!(req.attestation_envelope["reason_digest"], DIGEST);
    assert_eq!(req.attestation_envelope[ROOM_FIELD], room.as_str());

    // 2. The owner — the seated WA — approves, with their own pen.
    let resp_id = sign_deferral_response(&engine, &owner, &req_id, true)
        .await
        .expect("the WA answers");
    let resp = row(&engine, &resp_id).await;
    assert_eq!(resp.attestation_envelope["dimension"], DEFERRAL_APPROVED);
    assert_eq!(
        resp.attesting_key_id,
        owner.key_id(),
        "the WA's own key signs"
    );
    assert_eq!(resp.attested_key_id, agent);
    assert_eq!(
        resp.attestation_envelope["references_attestation_id"],
        req_id.as_str()
    );
    assert_eq!(
        resp.attestation_envelope[ROOM_FIELD],
        room.as_str(),
        "same room"
    );

    // 3. The agent applies the amendment, citing the approval.
    let amend_id = emit_identity_amendment(&engine, &agent, DIGEST, &resp_id, &req_id)
        .await
        .expect("an approved response authorises the amendment");
    let amend = row(&engine, &amend_id).await;
    assert_eq!(amend.attestation_envelope["dimension"], IDENTITY_AMENDMENT);
    assert_eq!(amend.attesting_key_id, agent);
    assert_eq!(amend.attested_key_id, agent);
    assert_eq!(amend.attestation_envelope["amendment_digest"], DIGEST);
    assert_eq!(
        amend.attestation_envelope["authorized_by"],
        resp_id.as_str()
    );
    assert_eq!(
        amend.attestation_envelope["evidence_refs"][0],
        resp_id.as_str()
    );
    assert_eq!(
        amend.attestation_envelope[ROOM_FIELD],
        room.as_str(),
        "same room"
    );
}

#[tokio::test]
async fn a_rejected_answer_does_not_authorise_an_amendment() {
    let owner = pen("owner-fedid", 0x33);
    let (engine, agent) = owned_agent(&owner).await;
    let req_id = emit_deferral_request(&engine, &agent, &request(None))
        .await
        .unwrap();
    let resp_id = sign_deferral_response(&engine, &owner, &req_id, false)
        .await
        .unwrap();
    assert_eq!(
        row(&engine, &resp_id).await.attestation_envelope["dimension"],
        DEFERRAL_REJECTED
    );
    let err = emit_identity_amendment(&engine, &agent, DIGEST, &resp_id, &req_id)
        .await
        .expect_err("a rejection authorises nothing");
    assert!(matches!(err, AgentRowError::Unauthorized(_)), "{err}");
    assert_eq!(err.reason_id(), "identity_amendment_unauthorized");
}

#[tokio::test]
async fn an_approval_from_someone_not_seated_is_unauthorized() {
    let owner = pen("owner-fedid", 0x33);
    let stranger = pen("stranger", 0x44);
    let (engine, agent) = owned_agent(&owner).await;
    register_key(
        &engine,
        KeySigner::Local(&stranger),
        stranger.key_id(),
        "user",
        serde_json::Value::Null,
    )
    .await
    .unwrap();
    let req_id = emit_deferral_request(&engine, &agent, &request(None))
        .await
        .unwrap();
    let resp_id = sign_deferral_response(&engine, &stranger, &req_id, true)
        .await
        .expect("anyone can sign a row; admission of the AMENDMENT is the gate");
    let err = emit_identity_amendment(&engine, &agent, DIGEST, &resp_id, &req_id)
        .await
        .expect_err("not the seated WA");
    assert!(matches!(err, AgentRowError::Unauthorized(_)), "{err}");
}

#[tokio::test]
async fn an_approval_about_another_agent_is_unauthorized() {
    let owner = pen("owner-fedid", 0x33);
    let (engine, agent) = owned_agent(&owner).await;
    let other_pen = pen("ciris-agent-other", 0x55);
    let other = other_pen.key_id().to_string();
    register_key(
        &engine,
        KeySigner::Local(&other_pen),
        &other,
        "agent",
        serde_json::Value::Null,
    )
    .await
    .unwrap();
    let req_id = emit_deferral_request(&engine, &agent, &request(None))
        .await
        .unwrap();
    let resp_id = attest::emit(
        &engine,
        KeySigner::Local(&owner),
        Spec::new(
            "scores",
            cohort_scope::SELF,
            serde_json::json!({ "dimension": DEFERRAL_APPROVED, "references_attestation_id": req_id }),
        )
        .weighing(Some(1.0))
        .attested_to(&other),
    )
    .await
    .expect("the owner approves something for another agent");
    let err = emit_identity_amendment(&engine, &agent, DIGEST, &resp_id, &req_id)
        .await
        .expect_err("about another agent");
    assert!(matches!(err, AgentRowError::Unauthorized(_)), "{err}");
}

#[tokio::test]
async fn an_unknown_response_is_unauthorized_and_inputs_are_checked() {
    let owner = pen("owner-fedid", 0x33);
    let (engine, agent) = owned_agent(&owner).await;
    let err = emit_identity_amendment(&engine, &agent, DIGEST, "no-such-row", "no-such-req")
        .await
        .expect_err("nothing admitted");
    assert!(matches!(err, AgentRowError::Unauthorized(_)), "{err}");

    let bad = emit_identity_amendment(&engine, &agent, "ABC", "x", "y")
        .await
        .unwrap_err();
    assert!(matches!(bad, AgentRowError::BadInput(_)), "{bad}");
    let mut r = request(None);
    r.reason_digest = "not-hex".into();
    assert!(matches!(
        emit_deferral_request(&engine, &agent, &r)
            .await
            .unwrap_err(),
        AgentRowError::BadInput(_)
    ));
    let bad_room = emit_deferral_request(&engine, &agent, &request(Some("family:xyz")))
        .await
        .unwrap_err();
    assert!(matches!(bad_room, AgentRowError::BadInput(_)), "{bad_room}");
}

#[tokio::test]
async fn the_response_door_refuses_before_opening_any_pen() {
    let owner = pen("owner-fedid", 0x33);
    let (engine, agent) = owned_agent(&owner).await;
    let seed = std::env::temp_dir().join("ciris-1316-no-seed");
    // Unknown deferral: refused before the session is even read.
    let unknown = emit_deferral_response(&engine, None, "u", seed.clone(), "nope", true)
        .await
        .unwrap_err();
    assert_eq!(unknown.reason_id(), "deferral.unknown_request");
    // No session.
    let req_id = emit_deferral_request(&engine, &agent, &request(None))
        .await
        .unwrap();
    let anon = emit_deferral_response(&engine, None, "u", seed, &req_id, true)
        .await
        .unwrap_err();
    assert_eq!(anon.reason_id(), "deferral.not_signed_in");
}

/// `owner_record` states the founding ROOT's record in the forms the agent
/// parses: `role` is persist's `WaRole` serde form ("root"), `user_role` the
/// session role, `auth_type` the cert's token type, and nothing is invented.
#[tokio::test]
async fn the_owner_record_states_the_founding_root_without_inventing_fields() {
    use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};
    let owner = pen("owner-fedid", 0x33);
    let (engine, agent) = owned_agent(&owner).await;
    assert!(
        ciris_server::auth::session::owner_record(&engine, &agent)
            .await
            .unwrap()
            .is_none(),
        "no ROOT, no record"
    );
    let created = chrono::Utc::now();
    ciris_server::auth::store::upsert(
        &engine,
        WaCert {
            wa_id: "wa-root-owner".into(),
            name: "Owner Person".into(),
            role: WaRole::Root,
            pubkey: owner.key_id().into(),
            jwt_kid: "kid-owner".into(),
            password_hash: Some("hash".into()),
            api_key_hash: None,
            oauth_provider: None,
            oauth_external_id: None,
            oauth_links: None,
            veilid_id: None,
            auto_minted: false,
            parent_wa_id: None,
            parent_signature: None,
            scopes: serde_json::json!([]),
            custom_permissions: None,
            adapter_id: None,
            adapter_name: None,
            adapter_metadata: None,
            token_type: TokenType::Standard,
            created,
            last_login: None,
            active: true,
        },
    )
    .await
    .unwrap();
    let rec = ciris_server::auth::session::owner_record(&engine, &agent)
        .await
        .unwrap()
        .expect("a ROOT exists");
    assert_eq!(rec["wa_id"], "wa-root-owner");
    assert_eq!(rec["name"], "Owner Person");
    assert_eq!(rec["role"], "root", "persist's WaRole serde form");
    assert_eq!(rec["user_role"], "SYSTEM_ADMIN");
    assert_eq!(rec["auth_type"], "standard");
    assert_eq!(rec["has_password"], true);
    assert_eq!(rec["owner_key_id"], owner.key_id(), "owner_of(node)");
    assert!(rec["oauth_provider"].is_null());
    assert!(rec["created_at"]
        .as_str()
        .unwrap()
        .starts_with(&created.format("%Y-%m-%d").to_string()));
}

#[tokio::test]
async fn a_request_with_no_room_lands_in_the_agent_owner_pair_room() {
    let owner = pen("owner-fedid", 0x33);
    let (engine, agent) = owned_agent(&owner).await;
    let req_id = emit_deferral_request(&engine, &agent, &request(None))
        .await
        .unwrap();
    assert_eq!(
        row(&engine, &req_id).await.attestation_envelope[ROOM_FIELD],
        ciris_edge::chat::pair_community_key_id(&agent, owner.key_id()).as_str(),
        "the pair room of the agent and its owner"
    );
}

/// An approval for deferral A does not authorise an amendment asked under B,
/// and one approval authorises one amendment.
#[tokio::test]
async fn an_amendment_is_bound_to_its_deferral_and_used_once() {
    let owner = pen("owner-fedid", 0x33);
    let (engine, agent) = owned_agent(&owner).await;
    let req_a = emit_deferral_request(&engine, &agent, &request(None))
        .await
        .unwrap();
    let mut b = request(None);
    b.deferral_id = "def-2".into();
    let req_b = emit_deferral_request(&engine, &agent, &b).await.unwrap();
    let approves_a = sign_deferral_response(&engine, &owner, &req_a, true)
        .await
        .unwrap();

    let crossed = emit_identity_amendment(&engine, &agent, DIGEST, &approves_a, &req_b)
        .await
        .expect_err("A's approval cannot authorise B's amendment");
    assert!(
        matches!(crossed, AgentRowError::Unauthorized(_)),
        "{crossed}"
    );

    emit_identity_amendment(&engine, &agent, DIGEST, &approves_a, &req_a)
        .await
        .expect("A's approval authorises A's amendment");
    let again = emit_identity_amendment(&engine, &agent, DIGEST, &approves_a, &req_a)
        .await
        .expect_err("once");
    assert_eq!(again.reason_id(), "deferral.response_already_used");
}

#[tokio::test]
async fn deferral_rows_reads_the_chain_back_by_id() {
    let owner = pen("owner-fedid", 0x33);
    let (engine, agent) = owned_agent(&owner).await;
    let req = emit_deferral_request(&engine, &agent, &request(None))
        .await
        .unwrap();
    let resp = sign_deferral_response(&engine, &owner, &req, true)
        .await
        .unwrap();
    let amend = emit_identity_amendment(&engine, &agent, DIGEST, &resp, &req)
        .await
        .unwrap();
    let rows = ciris_server::agent_deferral::deferral_rows(
        &engine,
        &[req.clone(), resp.clone(), amend.clone(), "missing".into()],
    )
    .await
    .unwrap();
    let types: Vec<Option<&str>> = rows
        .iter()
        .map(|r| {
            r.as_ref()
                .and_then(ciris_server::agent_deferral::dimension_of)
        })
        .collect();
    assert_eq!(
        types,
        vec![
            Some(DEFERRAL_REQUEST),
            Some(DEFERRAL_APPROVED),
            Some(IDENTITY_AMENDMENT),
            None
        ]
    );
    assert_eq!(rows[1].as_ref().unwrap().attesting_key_id, owner.key_id());
}

/// **A split home** — every home claimed on 0.5.189 or later: the engine signs as
/// the AGENT key, the owner-binding names a separate NODE key, and the agent is
/// tied to its human only as an OCCURRENCE (`self:delegates_to:agent_occurrence:v1`
/// from the login ceremony), never by an owner-binding of its own. So the
/// amendment's attester (the agent key) has no `owner_of`; its owner is reached
/// through the node. Persist v60.1's #1120 gate admits this shape through the
/// occurrence anchor (CIRISPersist PR #1135, witness I1368); this is Server's
/// side of the same shape, run on every adoption.
#[tokio::test]
async fn a_split_home_amendment_is_authorised_by_the_nodes_owner() {
    use ciris_persist::engine::{SelfAtLoginInput, SelfAtLoginOccurrence};
    use ciris_persist::federation::admission::owner_of;
    use ciris_persist::federation::types::device_class;

    let owner = pen("owner-fedid-split", 0x34);
    let agent = id_of("ciris-agent-bootstrap-split", 0x12);
    let engine = Arc::new(
        Engine::with_signer(
            Arc::new(pen_as(0x12, "ciris-agent-bootstrap-split")),
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
    .expect("the agent key registers");
    let node = id_of("ciris-node-bootstrap-split", 0x22);
    register_key(
        &engine,
        KeySigner::Local(&pen_as(0x22, &node)),
        &node,
        "node",
        serde_json::Value::Null,
    )
    .await
    .expect("the node key registers");
    register_key(
        &engine,
        KeySigner::Local(&owner),
        owner.key_id(),
        "user",
        serde_json::Value::Null,
    )
    .await
    .expect("the owner registers");

    // The owner-binding names the NODE (the first-run claim's shape).
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

    // The login ceremony anchors the agent as an occurrence of its human
    // (`node_key::anchor_agent_to_owner`'s call, with the owner's pen).
    let enc = ciris_server::backend::content_kem_pubkeys(&engine)
        .await
        .expect("content KEM keys");
    engine
        .self_at_login(SelfAtLoginInput {
            identity_key_id: owner.key_id().to_owned(),
            // Named by its ALIAS: the ceremony derives the registered id from it,
            // as the hardware login signer does in production.
            identity_signer: Some(Arc::new(pen_as(0x34, "owner-fedid-split"))),
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
            bilateral_pair_id: format!("fold:{}:{agent}", owner.key_id()),
            delegation_scope: None,
        })
        .await
        .expect("the agent becomes an occurrence of its human");

    let dir = engine.federation_directory();
    assert_eq!(
        owner_of(dir.as_ref(), &agent).await.unwrap(),
        None,
        "precondition: the agent key carries no owner-binding of its own"
    );
    assert_eq!(
        owner_of(dir.as_ref(), &node).await.unwrap().as_deref(),
        Some(owner.key_id()),
        "precondition: the node's owner is the human"
    );

    let req_id = emit_deferral_request(&engine, &node, &request(None))
        .await
        .expect("the agent defers");
    let resp_id = sign_deferral_response(&engine, &owner, &req_id, true)
        .await
        .expect("the owner, the seated WA, approves");
    let amend_id = emit_identity_amendment(&engine, &node, DIGEST, &resp_id, &req_id)
        .await
        .expect("the node's owner authorises an amendment the agent key signs");
    let amend = row(&engine, &amend_id).await;
    assert_eq!(amend.attestation_envelope["dimension"], IDENTITY_AMENDMENT);
    assert_eq!(
        amend.attesting_key_id, agent,
        "the agent key signs, not the node"
    );
    assert_eq!(
        amend.attestation_envelope["authorized_by"],
        resp_id.as_str()
    );
}
