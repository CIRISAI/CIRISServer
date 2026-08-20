//! **Contacts + user chat, end to end over the real router.**
//!
//! Drives [`ciris_server::contacts_chat::router`] on a bound TCP listener
//! against an in-memory substrate, so the full HTTP + owner-auth stack runs and
//! nothing under test is stubbed. Four questions, in the order the flow asks
//! them:
//!
//! 1. **Add a contact by fedID** writes the `consent:replication:v1` grant that
//!    IS the contact relationship, resolves the contact's identity occurrences,
//!    and is idempotent. The contact then appears in `GET /v1/contacts` on the
//!    peer card shape the client already renders.
//! 2. **Chat creation converges.** The community id is DERIVED from the pair, so
//!    the test recomputes it independently — in both argument orders — and
//!    demands the route's answer match. A room both ends can only reach by
//!    agreeing first is not a room.
//! 3. **Send + list round-trips**, and the listed message carries its CEG
//!    identity: `attestation_id`, `attesting_key_id`, `cohort_scope`, and the
//!    folded `status`. The client reuses its attestation hamburger on each
//!    message, so a shape that hid those would be a second, weaker object model.
//! 4. **A non-member cannot read the community's messages** — and this is the
//!    one that matters. The community in that test holds a REAL message; the
//!    caller is the node's own OWNER; the refusal comes from persist's own §4.3
//!    predicate. Owning the box is not membership in the cohort, and if that
//!    arm ever goes quiet the `community` tier means nothing.
//!
//! Test 4 is paired with a control (`the_owner_reads_their_own_community`) for
//! the reason the whole file exists: a refusal test that passes because the
//! fixture never worked proves nothing.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::types::{
    algorithm, attestation_type, cohort_scope, identity_type, IdentityOccurrence, KeyRecord,
    LocalAttestationInput, SignedKeyRecord,
};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};

use ciris_server::auth::store;
use ciris_server::contacts_chat::{self, pair_community_key_id};

const NODE_KEY_ID: &str = "ciris-server";
const OWNER_USER_KEY_ID: &str = "ciris-owner-user";
const OWNER_ED_SEED: [u8; 32] = [0xF1; 32];
const OWNER_PQC_SEED: [u8; 32] = [0xF2; 32];

/// The contact the owner chats with.
const CONTACT_KEY_ID: &str = "bob-v1";
/// The contact's phone — proves the occurrence resolution is real.
const CONTACT_OCCURRENCE_KEY_ID: &str = "bob-v1-phone";
/// Two strangers whose community the owner is deliberately NOT in.
const STRANGER_A_KEY_ID: &str = "carol-v1";
const STRANGER_B_KEY_ID: &str = "dave-v1";

// ─── Fixture ────────────────────────────────────────────────────────────────

/// This node: an in-memory substrate keyed by a HYBRID node-identity signer, so
/// `sign_hybrid` (the community self-signature + the promote reseal) works.
async fn node() -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xA1; 32]),
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine"),
    )
}

/// The node's #247 DERIVED federation key_id — what `self_identity::resolve`
/// returns and what the consent grants are authored under.
async fn node_key_id(engine: &Engine) -> String {
    engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id")
}

/// Register this node's own steward key through the canonical admission gate
/// (the `put_attestation` attesting-key FK precondition).
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
    .expect("register node steward key via admission gate");
}

/// Seed a `user`-role key straight into the directory. The routes under test
/// require the row to EXIST; key-admission coverage lives in
/// `tests/federation_admin.rs`.
async fn seed_user_key(engine: &Engine, key_id: &str, ed_seed: u8, pqc_seed: u8) {
    let ed = SigningKey::from_bytes(&[ed_seed; 32]);
    let mldsa = MlDsa65SoftwareSigner::from_seed_bytes(&[pqc_seed; 32], format!("{key_id}-pqc"))
        .expect("ML-DSA-65 seed");
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize registration");
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: BASE64.encode(ed.verifying_key().to_bytes()),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(mldsa.public_key().await.expect("ml-dsa pk"))),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::USER.into(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
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
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .unwrap_or_else(|e| panic!("seed user key {key_id}: {e}"));
}

fn owner_user_signer() -> LocalSigner {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&OWNER_PQC_SEED, format!("{OWNER_USER_KEY_ID}-pqc"))
            .expect("owner ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        SigningKey::from_bytes(&OWNER_ED_SEED),
        OWNER_USER_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{OWNER_USER_KEY_ID}-pqc")),
    )
}

/// Bind the responsible party — the serve-only floor refuses every route here on
/// an owner-UNBOUND node, and the owner's key IS the chat identity.
async fn bind_owner(engine: &Engine) {
    let owner_ed_pub = BASE64.encode(
        SigningKey::from_bytes(&OWNER_ED_SEED)
            .verifying_key()
            .to_bytes(),
    );
    let owner_mldsa_pub = {
        let pqc = MlDsa65SoftwareSigner::from_seed_bytes(
            &OWNER_PQC_SEED,
            format!("{OWNER_USER_KEY_ID}-pqc"),
        )
        .expect("owner ML-DSA-65 seed");
        BASE64.encode(pqc.public_key().await.expect("owner ML-DSA-65 pubkey"))
    };
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": OWNER_USER_KEY_ID });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize owner envelope");
    let record = KeyRecord {
        key_id: OWNER_USER_KEY_ID.to_string(),
        pubkey_ed25519_base64: owner_ed_pub,
        pubkey_ml_dsa_65_base64: Some(owner_mldsa_pub),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::USER.into(),
        identity_ref: OWNER_USER_KEY_ID.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: OWNER_USER_KEY_ID.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register responsible-party user key");

    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let node = node_key_id(engine).await;
    ciris_server::auth::ownership::emit_steward_binding(
        engine,
        &owner_user_signer(),
        &node,
        &scopes,
    )
    .await
    .expect("emit owner-binding delegates_to(user -> node, infra:*)");
}

/// Bind a device to `CONTACT_KEY_ID` so `POST /v1/contacts` has a real
/// occurrence to resolve (an empty array would let the resolution be a no-op and
/// still pass). The occurrence key is FK'd to `federation_keys`, so it is a
/// registered key in its own right — as a real device key is.
async fn seed_contact_occurrence(engine: &Engine) {
    seed_user_key(engine, CONTACT_OCCURRENCE_KEY_ID, 0xB2, 0xB3).await;
    engine
        .federation_directory()
        .put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: CONTACT_KEY_ID.to_string(),
            occurrence_key_id: CONTACT_OCCURRENCE_KEY_ID.to_string(),
            device_class: "phone".to_string(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("bind the contact's phone occurrence");
}

/// Mint an active `wa_cert` + a bound session bearer token.
async fn mint_session(engine: &Engine, wa_id: &str, role: WaRole) -> String {
    let now = chrono::Utc::now();
    let cert = WaCert {
        wa_id: wa_id.to_string(),
        name: wa_id.to_string(),
        role,
        pubkey: BASE64.encode([0u8; 32]),
        jwt_kid: format!("kid-{wa_id}"),
        password_hash: None,
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
        token_type: TokenType::Session,
        created: now,
        last_login: None,
        active: true,
    };
    store::upsert(engine, cert).await.expect("mint wa_cert");
    ciris_server::auth::session::test_support_issue_session_token(wa_id)
}

/// Serve the contacts+chat router on an ephemeral port.
async fn serve(engine: Arc<Engine>) -> (String, tokio::task::JoinHandle<()>) {
    let app = contacts_chat::router(engine);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// The whole fixture: a claimed node, a registered contact with a device, and an
/// owner session.
async fn fixture() -> (Arc<Engine>, String, String, tokio::task::JoinHandle<()>) {
    let engine = node().await;
    register_self(&engine).await;
    bind_owner(&engine).await;
    seed_user_key(&engine, CONTACT_KEY_ID, 0xB0, 0xB1).await;
    seed_user_key(&engine, STRANGER_A_KEY_ID, 0xC0, 0xC1).await;
    seed_user_key(&engine, STRANGER_B_KEY_ID, 0xD0, 0xD1).await;
    seed_contact_occurrence(&engine).await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, handle) = serve(Arc::clone(&engine)).await;
    (engine, base, owner, handle)
}

/// `POST /v1/contacts` + `POST /v1/chat` in one step — the precondition for the
/// message tests.
async fn open_chat(client: &reqwest::Client, base: &str, owner: &str) -> String {
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts");
    assert_eq!(resp.status(), 200, "add contact: {:?}", resp.text().await);
    let resp = client
        .post(format!("{base}/v1/chat"))
        .bearer_auth(owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/chat");
    assert_eq!(resp.status(), 200, "start chat: {:?}", resp.text().await);
    let json: serde_json::Value = resp.json().await.expect("start chat json");
    json["community_id"]
        .as_str()
        .expect("community_id")
        .to_string()
}

// ─── 1. Add a contact by fedID ──────────────────────────────────────────────

#[tokio::test]
async fn add_contact_writes_the_consent_grant_and_resolves_occurrences() {
    let (engine, base, owner, _h) = fixture().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts");
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.expect("add contact json");
    assert_eq!(json["key_id"], CONTACT_KEY_ID);
    assert!(
        json["consent_attestation_id"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "the contact relationship IS the consent grant — its id must come back: {json}"
    );
    assert_eq!(json["freshly_emitted"], true);
    assert_eq!(
        json["occurrence_key_ids"],
        serde_json::json!([CONTACT_OCCURRENCE_KEY_ID]),
        "the contact's identity occurrence must be resolved from the directory"
    );

    // The grant is a real `consent:replication:v1` row this node authored, and
    // persist's revocation-folded projection can see it.
    let node = node_key_id(&engine).await;
    let peers = ciris_server::peer::replication_peers_from_consent(&engine, &node)
        .await
        .expect("consent peer set");
    assert!(
        peers.iter().any(|p| p == CONTACT_KEY_ID),
        "the contact must land in the consent peer set: {peers:?}"
    );

    // Idempotent: a second add returns the SAME grant, freshly_emitted false.
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts (again)");
    assert_eq!(resp.status(), 200);
    let again: serde_json::Value = resp.json().await.expect("re-add json");
    assert_eq!(again["freshly_emitted"], false);
    assert_eq!(
        again["consent_attestation_id"],
        json["consent_attestation_id"]
    );

    // And it renders in the list, on the peer card the client already binds.
    let resp = client
        .get(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET /v1/contacts");
    assert_eq!(resp.status(), 200);
    let list: serde_json::Value = resp.json().await.expect("contacts json");
    assert_eq!(list["total"], 1);
    let row = &list["contacts"][0];
    assert_eq!(row["key_id"], CONTACT_KEY_ID);
    assert_eq!(row["contact"], true);
    assert_eq!(row["chat_started"], false, "no chat opened yet");
    assert_eq!(
        row["chat_community_id"],
        serde_json::json!(pair_community_key_id(OWNER_USER_KEY_ID, CONTACT_KEY_ID))
    );
    assert!(
        row["pubkey_ed25519_base64"].is_string(),
        "a contact card must carry the peer projection's fields: {row}"
    );
}

#[tokio::test]
async fn an_unknown_fed_id_is_refused_with_a_typed_reason() {
    let (_engine, base, owner, _h) = fixture().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": "nobody-v1" }))
        .send()
        .await
        .expect("POST /v1/contacts");
    assert_eq!(resp.status(), 404);
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["reason_id"], "contacts.unknown_fed_id");
}

// ─── 2. Chat creation converges ─────────────────────────────────────────────

#[tokio::test]
async fn chat_creation_is_convergent_and_idempotent_for_a_pair() {
    let (engine, base, owner, _h) = fixture().await;
    let client = reqwest::Client::new();
    let community_id = open_chat(&client, &base, &owner).await;

    // THE convergence property: the id is derived from public inputs alone, so
    // the other end computes the same one without ever talking to this node —
    // in either argument order.
    assert_eq!(
        community_id,
        pair_community_key_id(OWNER_USER_KEY_ID, CONTACT_KEY_ID)
    );
    assert_eq!(
        community_id,
        pair_community_key_id(CONTACT_KEY_ID, OWNER_USER_KEY_ID),
        "a room the two ends can only reach by agreeing who initiated is not a room"
    );

    // The row is a real 2-member persist Community.
    let community = engine
        .federation_directory()
        .lookup_community(&community_id)
        .await
        .expect("lookup_community")
        .expect("the community must exist after POST /v1/chat");
    let mut members: Vec<String> = community.members.iter().map(|m| m.key_id.clone()).collect();
    members.sort();
    let mut expected = vec![OWNER_USER_KEY_ID.to_string(), CONTACT_KEY_ID.to_string()];
    expected.sort();
    assert_eq!(members, expected);

    // Idempotent: a second start returns the same room, not a second one.
    let resp = client
        .post(format!("{base}/v1/chat"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/chat (again)");
    assert_eq!(resp.status(), 200);
    let again: serde_json::Value = resp.json().await.expect("start chat json");
    assert_eq!(again["community_id"], serde_json::json!(community_id));
    assert_eq!(again["freshly_created"], false);
    assert_eq!(again["cohort_scope"], cohort_scope::COMMUNITY);
}

#[tokio::test]
async fn a_chat_with_a_non_contact_is_refused() {
    let (_engine, base, owner, _h) = fixture().await;
    let client = reqwest::Client::new();
    // STRANGER_A is a registered key but was never added as a contact — so this
    // node has consented to replicate nothing to them, and a room whose messages
    // never leave is not a chat.
    let resp = client
        .post(format!("{base}/v1/chat"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": STRANGER_A_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/chat");
    assert_eq!(resp.status(), 403);
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["reason_id"], "chat.not_a_contact");
}

// ─── 3. Send + list round-trips, with the CEG identity intact ───────────────

#[tokio::test]
async fn send_and_list_round_trip_carries_the_hamburger_fields() {
    let (_engine, base, owner, _h) = fixture().await;
    let client = reqwest::Client::new();
    let community_id = open_chat(&client, &base, &owner).await;

    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "first" }))
        .send()
        .await
        .expect("POST message");
    assert_eq!(resp.status(), 200, "send: {:?}", resp.text().await);
    let sent: serde_json::Value = resp.json().await.expect("send json");
    let first_id = sent["attestation_id"]
        .as_str()
        .expect("attestation_id")
        .to_string();
    assert_eq!(sent["cohort_scope"], cohort_scope::COMMUNITY);

    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "second", "content_type": "text/plain" }))
        .send()
        .await
        .expect("POST message 2");
    assert_eq!(resp.status(), 200);

    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET messages");
    assert_eq!(resp.status(), 200);
    let list: serde_json::Value = resp.json().await.expect("messages json");
    assert_eq!(list["total"], 2, "both messages must come back: {list}");
    let messages = list["messages"].as_array().expect("messages array");

    // NEWEST LAST — a transcript reads down the page.
    assert_eq!(messages[0]["body"], "first");
    assert_eq!(messages[1]["body"], "second");

    // THE HAMBURGER FIELDS. The client renders each message with the same
    // attestation card it uses everywhere else; a bespoke `{from,text,at}` would
    // have hidden every one of these.
    let m = &messages[0];
    assert_eq!(m["attestation_id"], serde_json::json!(first_id));
    assert_eq!(m["attesting_key_id"], OWNER_USER_KEY_ID);
    assert_eq!(m["attested_key_id"], OWNER_USER_KEY_ID);
    assert_eq!(m["attestation_type"], attestation_type::SCORES);
    assert_eq!(m["cohort_scope"], cohort_scope::COMMUNITY);
    assert_eq!(m["community_id"], serde_json::json!(community_id));
    assert_eq!(m["status"], "live");
    assert_eq!(m["subject_key_ids"], serde_json::json!([OWNER_USER_KEY_ID]));
    assert_eq!(m["content_type"], "text/plain");
    assert_eq!(m["mine"], true);
    assert!(m["asserted_at"].is_string());
}

#[tokio::test]
async fn a_withdrawn_message_reads_back_as_withdrawn() {
    let (engine, base, owner, _h) = fixture().await;
    let client = reqwest::Client::new();
    let community_id = open_chat(&client, &base, &owner).await;

    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "oops" }))
        .send()
        .await
        .expect("POST message");
    assert_eq!(resp.status(), 200);
    let sent: serde_json::Value = resp.json().await.expect("send json");
    let message_id = sent["attestation_id"]
        .as_str()
        .expect("attestation_id")
        .to_string();

    // The author withdraws it — the ordinary CEG composer, emitted the same way
    // the route emits the message it targets.
    withdraw_own_message(&engine, &message_id).await;

    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET messages");
    let list: serde_json::Value = resp.json().await.expect("messages json");
    let m = &list["messages"][0];
    assert_eq!(
        m["status"], "withdrawn",
        "the read must fold the composer, not report the raw row: {list}"
    );
    assert!(m["status_attestation_id"].is_string());
}

// ─── 4. THE contextual-integrity line ───────────────────────────────────────

/// A community of two strangers, authored by this node (as a replicated row
/// would be), holding a real message. The owner is deliberately not on it.
async fn strangers_community(engine: &Engine) -> String {
    use ciris_persist::federation::types::{Community, CommunityMember};
    let community_id = pair_community_key_id(STRANGER_A_KEY_ID, STRANGER_B_KEY_ID);
    let now = chrono::Utc::now();
    engine
        .put_community_self_signed(Community {
            community_key_id: community_id.clone(),
            community_name: format!("{STRANGER_A_KEY_ID} <-> {STRANGER_B_KEY_ID}"),
            members: [STRANGER_A_KEY_ID, STRANGER_B_KEY_ID]
                .iter()
                .map(|k| CommunityMember {
                    key_id: (*k).to_string(),
                    joined_at: now,
                    role: None,
                })
                .collect(),
            founded_at: now,
            consensus_protocol: "unanimous".to_string(),
            policy_blob: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("author the strangers' community");
    community_id
}

/// Emit a chat message into `community_id` authored by `author` — the same row
/// shape `POST /v1/chat/{id}/messages` writes, so the withheld content is real
/// content and not an empty transcript.
async fn seed_message(engine: &Engine, author: &str, community_id: &str, body: &str) -> String {
    let envelope = serde_json::json!({
        (paths::DIMENSION): contacts_chat::CHAT_MESSAGE_DIMENSION,
        "community_id": community_id,
        "body": body,
        "content_type": "text/plain",
        "score": 1.0,
    });
    let input = LocalAttestationInput {
        attestation_id: None,
        attesting_key_id: author.to_string(),
        attested_key_id: Some(author.to_string()),
        attestation_type: attestation_type::SCORES.to_string(),
        weight: None,
        expires_at: None,
        attestation_envelope: ciris_persist::federation::envelope::EnvelopeCore::from_value(
            envelope,
        )
        .expect("envelope"),
        subject_key_ids: vec![author.to_string()],
        cohort_scope: cohort_scope::SELF.to_string(),
        scrub_signature_classical: None,
        scrub_signature_pqc: None,
    };
    let id = engine
        .federation_directory()
        .attestation_upsert_local(input)
        .await
        .expect("upsert seeded chat message");
    engine
        .attestation_promote(&id, cohort_scope::COMMUNITY)
        .await
        .expect("promote seeded chat message to the community tier");
    id
}

/// The owner's `withdraws` composer over one of their own messages.
///
/// **This one cannot be signature-deferred.** `is_subject_side_revocation`
/// classifies a `withdraws` whose attester is in its own `subject_key_ids` as a
/// TRANSIT revocation (§10.1.3 / AV-61), and the local door then demands a
/// bound-hybrid signature that verifies against the attester's REGISTERED
/// pubkeys before it will store the row. So the withdraw is signed here with the
/// owner's own key — which is exactly the constraint the client faces: the
/// server can stage a message on the owner's behalf, but only the holder of the
/// owner's key can retract one.
async fn withdraw_own_message(engine: &Engine, target_attestation_id: &str) {
    use ciris_persist::federation::admission::truncate_to_substrate_resolution;
    use ciris_persist::federation::envelope::{EnvelopeCore, RowMirror};

    let envelope = serde_json::json!({
        (paths::DIMENSION): contacts_chat::CHAT_MESSAGE_DIMENSION,
        (paths::REFERENCES_ATTESTATION_ID): target_attestation_id,
    });
    let mut core = EnvelopeCore::from_value(envelope).expect("withdraw envelope");
    // A transit row is NOT stamped by the local door (the door stamps only
    // durable rows — it must not mutate bytes a signature already covers), so
    // the producer carries the #643 mirror and the #598 instant itself. That
    // makes the row's identity and its seven typed columns part of the signed
    // bytes, which is the whole point: a relay cannot rewrite `subject_key_ids`
    // out from under a signature that still verifies.
    let attestation_id = ciris_server::ids::new_id();
    core.asserted_at = Some(truncate_to_substrate_resolution(chrono::Utc::now()).to_rfc3339());
    core.row = Some(RowMirror {
        attestation_id: attestation_id.clone(),
        attesting_key_id: OWNER_USER_KEY_ID.to_string(),
        attestation_type: attestation_type::WITHDRAWS.to_string(),
        attested_key_id: OWNER_USER_KEY_ID.to_string(),
        subject_key_ids: vec![OWNER_USER_KEY_ID.to_string()],
        cohort_scope: cohort_scope::SELF.to_string(),
        weight: None,
    });
    // Sign the envelope AS THE DOOR WILL SEE IT — `EnvelopeCore::to_value` is
    // what `verify_envelope_hybrid_signature` recanonicalizes, so signing any
    // other rendering of the same JSON would verify against different bytes.
    let canonical = ceg_produce_canonicalize(&core.to_value()).expect("canonicalize withdraw");
    let sig = owner_user_signer()
        .sign_hybrid(&canonical)
        .await
        .expect("owner hybrid-signs their own withdraw");
    let input = LocalAttestationInput {
        attestation_id: Some(attestation_id),
        attesting_key_id: OWNER_USER_KEY_ID.to_string(),
        attested_key_id: Some(OWNER_USER_KEY_ID.to_string()),
        attestation_type: attestation_type::WITHDRAWS.to_string(),
        weight: None,
        expires_at: None,
        attestation_envelope: core,
        subject_key_ids: vec![OWNER_USER_KEY_ID.to_string()],
        cohort_scope: cohort_scope::SELF.to_string(),
        scrub_signature_classical: Some(BASE64.encode(&sig.classical.signature)),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
    };
    let id = engine
        .federation_directory()
        .attestation_upsert_local(input)
        .await
        .expect("upsert withdraws");
    engine
        .attestation_promote(&id, cohort_scope::COMMUNITY)
        .await
        .expect("promote withdraws");
}

/// **The test that matters.** The node's OWNER — the highest authority this
/// process answers to — asks for a community they are not a member of, and the
/// substrate's own §4.3 predicate refuses. If this ever returns 200, the
/// `community` tier is decorative.
#[tokio::test]
async fn a_non_member_cannot_read_the_communitys_messages() {
    let (engine, base, owner, _h) = fixture().await;
    let community_id = strangers_community(&engine).await;
    let secret = "the strangers' private message";
    seed_message(&engine, STRANGER_A_KEY_ID, &community_id, secret).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET messages");
    assert_eq!(
        resp.status(),
        403,
        "owning the node is not membership in the cohort"
    );
    let body = resp.text().await.expect("refusal body");
    let json: serde_json::Value = serde_json::from_str(&body).expect("refusal json");
    assert_eq!(json["reason_id"], "chat.not_a_member");
    assert!(
        !body.contains(secret),
        "the refusal must not leak the content it is withholding: {body}"
    );

    // And the write side refuses too — a non-member cannot speak into the room
    // either.
    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "let me in" }))
        .send()
        .await
        .expect("POST message");
    assert_eq!(resp.status(), 403);
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["reason_id"], "chat.not_a_member");
}

/// **The control.** Without it the refusal above could pass because the fixture
/// never worked — an unclaimed node, an unregistered key, a community that was
/// never written all produce the same 403 for reasons having nothing to do with
/// membership.
#[tokio::test]
async fn the_owner_reads_their_own_community() {
    let (engine, base, owner, _h) = fixture().await;
    let client = reqwest::Client::new();
    let community_id = open_chat(&client, &base, &owner).await;
    // The SAME seeding path the withheld community used, so the two tests differ
    // in exactly one variable: whether the caller is on the roster.
    seed_message(&engine, OWNER_USER_KEY_ID, &community_id, "hello").await;

    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET messages");
    assert_eq!(resp.status(), 200);
    let list: serde_json::Value = resp.json().await.expect("messages json");
    assert_eq!(list["total"], 1);
    assert_eq!(list["messages"][0]["body"], "hello");
}

#[tokio::test]
async fn an_unknown_community_is_a_404_not_a_403() {
    let (_engine, base, owner, _h) = fixture().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/v1/chat/chat:pair:v1:deadbeef/messages"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET messages");
    assert_eq!(resp.status(), 404);
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["reason_id"], "chat.unknown_community");
}

// ─── The gates ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn every_route_refuses_without_an_owner_session() {
    let (engine, base, owner, _h) = fixture().await;
    let client = reqwest::Client::new();
    let community_id = open_chat(&client, &base, &owner).await;
    let observer = mint_session(&engine, "wa-observer", WaRole::Observer).await;

    for (method, path) in [
        ("GET", "/v1/contacts".to_string()),
        ("POST", "/v1/contacts".to_string()),
        ("POST", "/v1/chat".to_string()),
        ("GET", format!("/v1/chat/{community_id}/messages")),
        ("POST", format!("/v1/chat/{community_id}/messages")),
    ] {
        let url = format!("{base}{path}");
        let build = |c: &reqwest::Client| match method {
            "GET" => c.get(&url),
            _ => c
                .post(&url)
                .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID, "body": "x" })),
        };
        // No bearer at all.
        let resp = build(&client).send().await.expect("no-session request");
        assert_eq!(resp.status(), 401, "{method} {path} without a session");
        let json: serde_json::Value = resp.json().await.expect("refusal json");
        assert_eq!(json["reason_id"], "auth.owner_gate.missing_bearer");

        // A real session that is not the owner.
        let resp = build(&client)
            .bearer_auth(&observer)
            .send()
            .await
            .expect("observer request");
        assert_eq!(resp.status(), 403, "{method} {path} as a non-owner");
        let json: serde_json::Value = resp.json().await.expect("refusal json");
        assert_eq!(json["reason_id"], "auth.owner_gate.not_owner");
    }
}
