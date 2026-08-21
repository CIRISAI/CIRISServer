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

use ciris_server::auth::session::DelegationConstraints;
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

/// `GET /v1/contacts` as the owner, decoded.
async fn contacts_list(client: &reqwest::Client, base: &str, owner: &str) -> serde_json::Value {
    let resp = client
        .get(format!("{base}/v1/contacts"))
        .bearer_auth(owner)
        .send()
        .await
        .expect("GET /v1/contacts");
    assert_eq!(resp.status(), 200);
    resp.json().await.expect("contacts json")
}

/// The revocation-FOLDED live grants this node holds for `peer` — persist's
/// `list_live_consent_grants_by` filtered to the peer. This is the read that
/// decides what actually replicates, so it is the read the widening tests
/// assert on: the HTTP response says what the server BELIEVES, this says what
/// the corpus holds.
async fn live_grants_for(
    engine: &Engine,
    node: &str,
    peer: &str,
) -> Vec<ciris_persist::federation::types::Attestation> {
    engine
        .federation_directory()
        .list_live_consent_grants_by(node)
        .await
        .expect("list_live_consent_grants_by")
        .into_iter()
        .filter(|a| a.subject_key_ids.iter().any(|s| s == peer))
        .collect()
}

/// The prefix set the single live grant covers, sorted. Panics if the peer has
/// no live grant — an absent grant and an empty one are different facts and the
/// tests must not collapse them onto `vec![]`.
async fn live_grant_prefixes(engine: &Engine, node: &str, peer: &str) -> Vec<String> {
    let live = live_grants_for(engine, node, peer).await;
    assert_eq!(
        live.len(),
        1,
        "expected exactly one live consent grant for {peer}, found {}",
        live.len()
    );
    let mut prefixes: Vec<String> = live[0].attestation_envelope["payload"]["attestation_prefixes"]
        .as_array()
        .expect("attestation_prefixes array")
        .iter()
        .map(|v| v.as_str().expect("prefix string").to_owned())
        .collect();
    prefixes.sort();
    prefixes
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

/// **THE PR #464 P1 REGRESSION.** Federate with a peer the ordinary way FIRST —
/// which leaves a standing `consent:replication:v1` grant covering `capacity:` /
/// `trace:` and nothing else — and only then add them as a contact.
///
/// This is the case the old code got wrong, and it got it wrong in the direction
/// that hides: `emit_replication_consent`'s guard matched on (subject, dimension)
/// and returned the first hit without ever comparing prefixes, so `POST
/// /v1/contacts` answered 200 while `chat:` stayed uncovered. The contacts who
/// had peered first — the ones you actually know — were exactly the ones you
/// could not message. Nothing 404s, nothing 403s; the messages simply never
/// become eligible to replicate.
///
/// So the assertion is on the EFFECTIVE folded grant, not on the response: read
/// `list_live_consent_grants_by` back and demand `chat:` is in the payload of the
/// one grant that survives the fold.
#[tokio::test]
async fn adding_an_already_peered_key_widens_its_narrow_consent_grant() {
    let (engine, base, owner, _h) = fixture().await;
    let node = node_key_id(&engine).await;

    // Ordinary federation peering: the boot/peering default prefix set.
    let peered = ciris_server::peer::emit_replication_consent(
        &engine,
        &node,
        CONTACT_KEY_ID,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("pre-existing federation peering grant");
    assert!(peered.freshly_emitted);
    assert_eq!(
        live_grant_prefixes(&engine, &node, CONTACT_KEY_ID).await,
        vec!["capacity:".to_string(), "trace:".to_string()],
        "the fixture must actually start NARROW, or this test proves nothing"
    );

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts");
    let status = resp.status();
    let body = resp.text().await.expect("add contact body");
    assert_eq!(status, 200, "add contact: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("add contact json");
    assert_eq!(
        json["superseded_attestation_id"],
        serde_json::json!(peered.attestation_id),
        "the widening must NAME the narrower grant it retires: {json}"
    );
    assert_eq!(json["freshly_emitted"], true);
    assert_ne!(
        json["consent_attestation_id"],
        serde_json::json!(peered.attestation_id)
    );

    // THE assertion: the EFFECTIVE folded grant covers chat:, and it is the ONLY
    // live grant for this peer.
    assert_eq!(
        live_grant_prefixes(&engine, &node, CONTACT_KEY_ID).await,
        vec![
            "capacity:".to_string(),
            "chat:".to_string(),
            "trace:".to_string()
        ],
        "the widened grant must carry the UNION — dropping capacity:/trace: would \
         trade one dead plane for two"
    );
    let live = live_grants_for(&engine, &node, CONTACT_KEY_ID).await;
    assert_eq!(live.len(), 1, "exactly one grant may be live for a peer");
    assert_eq!(live[0].attestation_id, json["consent_attestation_id"]);

    // The contact is still a contact — a widening must not drop the peer out of
    // the revocation-folded set on its way through.
    let peers = ciris_server::peer::replication_peers_from_consent(&engine, &node)
        .await
        .expect("consent peer set");
    assert!(peers.iter().any(|p| p == CONTACT_KEY_ID), "{peers:?}");

    // And a SECOND add is now a true no-op: nothing written, nothing superseded.
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts (again)");
    assert_eq!(resp.status(), 200);
    let again: serde_json::Value = resp.json().await.expect("re-add json");
    assert_eq!(
        again["freshly_emitted"], false,
        "second add must be a no-op: {again}"
    );
    assert!(again["superseded_attestation_id"].is_null());
    assert_eq!(
        again["consent_attestation_id"],
        json["consent_attestation_id"]
    );
    assert_eq!(
        live_grants_for(&engine, &node, CONTACT_KEY_ID).await.len(),
        1,
        "a no-op must not append a grant"
    );
}

/// A widening PRESERVES the operator's policy on every axis but prefixes. An
/// owner who narrowed the audience or time-boxed the grant through
/// `POST /v1/federation/consent` must not have that reverted by someone adding a
/// contact — a silent policy reset is the same class of defect as the silent
/// no-op, just pointing the other way.
#[tokio::test]
async fn widening_preserves_the_standing_grants_policy() {
    let (engine, base, owner, _h) = fixture().await;
    let node = node_key_id(&engine).await;
    let opts = ciris_server::peer::ConsentGrantOptions {
        audience: Some(cohort_scope::SPECIES.to_string()),
        principle: Some("analyze".to_string()),
        purpose: Some("a purpose the owner wrote down".to_string()),
        ..Default::default()
    };
    ciris_server::peer::emit_replication_consent_with_policy(
        &engine,
        &node,
        CONTACT_KEY_ID,
        &["trace:"],
        &opts,
    )
    .await
    .expect("owner-policy grant");

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts");
    let status = resp.status();
    let body = resp.text().await.expect("add contact body");
    assert_eq!(status, 200, "add contact: {body}");

    let live = live_grants_for(&engine, &node, CONTACT_KEY_ID).await;
    assert_eq!(live.len(), 1);
    let payload = &live[0].attestation_envelope["payload"];
    assert_eq!(payload["audience"], cohort_scope::SPECIES);
    assert_eq!(payload["principle"], "analyze");
    assert_eq!(payload["purpose"], "a purpose the owner wrote down");
    // The prefix axis DID move — that is the point of the call — to the union of
    // the standing `trace:` and what `add_contact` requires. Every other axis
    // above is unchanged, which is the property this test exists for.
    assert_eq!(
        payload["attestation_prefixes"],
        serde_json::json!(["capacity:", "chat:", "trace:"]),
        "the union must be sorted + deduped so the JCS bytes are stable"
    );
}

/// Withdraw a consent grant the way the CEG says to: a `withdraws` composer over
/// the grant's `attestation_id`, authored by the grant's own author (this node).
///
/// Built through persist's OWN `withdraws_attestation_envelope` rather than a
/// hand-rolled object — the same builder `admin_ops::emit_about_peer` uses — so
/// the test cannot pass against an envelope shape production never writes. Note
/// it emits no `dimension`, which is the same rule the widening composer obeys.
///
/// `subject_key_ids` stays EMPTY on purpose: the node is the grant's PRODUCER,
/// not its subject, so this is not a §10.1.3 subject-side revocation and needs
/// no bound-hybrid signature. A withdraw naming itself as subject would.
async fn withdraw_consent_grant(engine: &Engine, peer: &str, grant_attestation_id: &str) {
    let envelope = ciris_persist::federation::withdraws_attestation_envelope(
        grant_attestation_id,
        attestation_type::SCORES,
    );
    let core = ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope)
        .expect("withdraws envelope");
    let mut input = ciris_persist::federation::EmitAttestationInput::with_envelope(
        attestation_type::WITHDRAWS,
        core,
        cohort_scope::FEDERATION.to_string(),
    );
    input.attested_key_id = Some(peer.to_string());
    engine
        .emit_attestation_self(input)
        .await
        .expect("withdraw the consent grant");
}

/// **REVOCATION MUST BE FREE.** The guard that decides whether a grant already
/// stands used to scan `list_attestations_by`, which folds nothing — so a
/// WITHDRAWN grant still answered "already present", and `emit_replication_consent`
/// returned success having written nothing. Withdrawing consent to a peer
/// permanently poisoned re-consenting to them: every later peering call was a
/// silent no-op with no live grant behind it.
///
/// A revocation that costs you the ability to ever re-consent is one nobody can
/// afford to exercise, which makes it not a revocation at all. This pins the
/// primitive directly — `emit_replication_consent`, the call peering and boot
/// make — rather than only the route on top of it.
#[tokio::test]
async fn emit_replication_consent_re_grants_after_a_withdraw() {
    let (engine, _base, _owner, _h) = fixture().await;
    let node = node_key_id(&engine).await;

    let first = ciris_server::peer::emit_replication_consent(
        &engine,
        &node,
        CONTACT_KEY_ID,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("first grant");
    assert!(first.freshly_emitted);
    assert_eq!(
        live_grants_for(&engine, &node, CONTACT_KEY_ID).await.len(),
        1
    );

    withdraw_consent_grant(&engine, CONTACT_KEY_ID, &first.attestation_id).await;

    // The withdraw must actually have landed, or the re-grant below proves
    // nothing about the fold.
    assert!(
        live_grants_for(&engine, &node, CONTACT_KEY_ID)
            .await
            .is_empty(),
        "the withdraw must clear the live grant"
    );
    let peers = ciris_server::peer::replication_peers_from_consent(&engine, &node)
        .await
        .expect("consent peer set");
    assert!(!peers.iter().any(|p| p == CONTACT_KEY_ID), "{peers:?}");

    // RE-CONSENT. Under the old guard this returned freshly_emitted:false and
    // wrote nothing, leaving the peer permanently unreachable.
    let second = ciris_server::peer::emit_replication_consent(
        &engine,
        &node,
        CONTACT_KEY_ID,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("re-grant after withdraw");
    assert!(
        second.freshly_emitted,
        "re-consenting after a withdraw must write a real grant, not report the withdrawn one"
    );
    assert_ne!(second.attestation_id, first.attestation_id);
    let live = live_grants_for(&engine, &node, CONTACT_KEY_ID).await;
    assert_eq!(live.len(), 1, "exactly one live grant after re-consent");
    assert_eq!(live[0].attestation_id, second.attestation_id);
    let peers = ciris_server::peer::replication_peers_from_consent(&engine, &node)
        .await
        .expect("consent peer set");
    assert!(
        peers.iter().any(|p| p == CONTACT_KEY_ID),
        "the peer must be replicable again: {peers:?}"
    );
}

/// The same property through the CONTACTS route: un-contact someone, then add
/// them back. The user-visible shape of the defect above — "I removed them and
/// now I can't add them again", with the UI reporting success every time.
#[tokio::test]
async fn re_adding_an_un_contacted_person_restores_a_live_grant() {
    let (engine, base, owner, _h) = fixture().await;
    let node = node_key_id(&engine).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts");
    assert_eq!(resp.status(), 200);
    let first: serde_json::Value = resp.json().await.expect("add contact json");
    let first_id = first["consent_attestation_id"]
        .as_str()
        .expect("id")
        .to_string();

    // Un-contact: the ordinary CEG withdraw of the grant row, which is what the
    // module doc promises un-contacting IS.
    withdraw_consent_grant(&engine, CONTACT_KEY_ID, &first_id).await;
    let listed = contacts_list(&client, &base, &owner).await;
    assert_eq!(
        listed["total"], 0,
        "a withdrawn contact must leave the list: {listed}"
    );

    // Add them back.
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts (re-add)");
    let status = resp.status();
    let body = resp.text().await.expect("re-add body");
    assert_eq!(status, 200, "re-add: {body}");
    let second: serde_json::Value = serde_json::from_str(&body).expect("re-add json");
    assert_eq!(
        second["freshly_emitted"], true,
        "re-add must write a grant: {second}"
    );
    assert_ne!(
        second["consent_attestation_id"],
        serde_json::json!(first_id)
    );
    assert!(
        second["superseded_attestation_id"].is_null(),
        "a re-grant is not a widening — there was nothing live to supersede"
    );
    assert_eq!(
        live_grant_prefixes(&engine, &node, CONTACT_KEY_ID).await,
        vec![
            "capacity:".to_string(),
            "chat:".to_string(),
            "trace:".to_string()
        ]
    );
    let listed = contacts_list(&client, &base, &owner).await;
    assert_eq!(listed["total"], 1, "the contact must be back: {listed}");
    assert_eq!(listed["contacts"][0]["key_id"], CONTACT_KEY_ID);
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
    let (engine, base, owner, _h) = fixture().await;
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
    let node = node_key_id(&engine).await;
    let m = &messages[0];
    assert_eq!(m["attestation_id"], serde_json::json!(first_id));
    // THE NODE ATTESTS, THE HUMAN AUTHORS — two fields, two questions. A card
    // that read `attesting_key_id` as the sender would label every message with
    // the box it passed through.
    assert_eq!(m["attesting_key_id"], serde_json::json!(node));
    assert_eq!(m["attested_key_id"], serde_json::json!(node));
    assert_eq!(m["author"], OWNER_USER_KEY_ID);
    assert_eq!(m["attestation_type"], attestation_type::SCORES);
    assert_eq!(m["cohort_scope"], cohort_scope::COMMUNITY);
    assert_eq!(m["community_id"], serde_json::json!(community_id));
    assert_eq!(m["status"], "live");
    assert_eq!(m["subject_key_ids"], serde_json::json!([node]));
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
    // NODE-attested, AUTHOR-attributed — the shape `send_message` writes.
    let node = node_key_id(engine).await;
    let envelope = serde_json::json!({
        (paths::DIMENSION): contacts_chat::CHAT_MESSAGE_DIMENSION,
        "community_id": community_id,
        "on_behalf_of_key_id": author,
        "body": body,
        "content_type": "text/plain",
        "score": 1.0,
    });
    let input = LocalAttestationInput {
        attestation_id: None,
        attesting_key_id: node.clone(),
        attested_key_id: Some(node.clone()),
        attestation_type: attestation_type::SCORES.to_string(),
        weight: None,
        expires_at: None,
        attestation_envelope: ciris_persist::federation::envelope::EnvelopeCore::from_value(
            envelope,
        )
        .expect("envelope"),
        subject_key_ids: vec![node],
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
    // Same shape as the message it retracts: NODE-attested, node-signed,
    // owner-attributed. The owner exercises revocation THROUGH the node, which is
    // consistent with the route being owner-gated and `ChatAuthor` never
    // delegatable — and unlike the earlier owner-signed form, this one actually
    // reaches the far side, which is the whole point of a retraction.
    let node = node_key_id(engine).await;
    let envelope = serde_json::json!({
        (paths::DIMENSION): contacts_chat::CHAT_MESSAGE_DIMENSION,
        (paths::REFERENCES_ATTESTATION_ID): target_attestation_id,
    });
    let input = LocalAttestationInput {
        attestation_id: None,
        attesting_key_id: node.clone(),
        attested_key_id: Some(node.clone()),
        attestation_type: attestation_type::WITHDRAWS.to_string(),
        weight: None,
        expires_at: None,
        attestation_envelope: ciris_persist::federation::envelope::EnvelopeCore::from_value(
            envelope,
        )
        .expect("withdraw envelope"),
        // EMPTY, and load-bearing: `is_subject_side_revocation` classifies a
        // `withdraws` whose attester is among its own subjects as a §10.1.3
        // TRANSIT revocation, which the local door then demands a bound-hybrid
        // signature for. Naming nobody keeps it an ordinary durable row — and
        // matches persist's own `consent_peer_set` fixture composer.
        subject_key_ids: Vec::new(),
        cohort_scope: cohort_scope::SELF.to_string(),
        scrub_signature_classical: None,
        scrub_signature_pqc: None,
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

// ─── The delegate ruling, and the substrate pin under it ────────────────────

/// Mint a DELEGATED bearer — the `dgrant:` token a device-grant issues after the
/// owner approves. It carries the owner's role AND `FullAccess` by design, so the
/// owner gate cannot tell it from the owner; only `caller.actor` can.
///
/// The bearer alone is not the authority: `resolve_bearer` RE-CHECKS the signed
/// `delegates_to(owner -> actor)` edge in the graph on every use (so revoking the
/// delegation kills the token immediately), which is why this emits the real edge
/// first rather than only registering the in-memory grant.
async fn mint_delegated_token(engine: &Engine, owner_wa_id: &str, client_id: &str) -> String {
    // The durable, owner-signed act-on-behalf edge — built through persist's own
    // envelope helper and the user-signed emit path device_grant's approve uses.
    ciris_server::auth::ownership::emit_signed_attestation(
        engine,
        &owner_user_signer(),
        attestation_type::DELEGATES_TO,
        client_id,
        ciris_persist::federation::delegates_to_envelope(
            client_id,
            &[DELEGATED_SCOPE.to_string()],
            false,
        ),
        None,
    )
    .await
    .expect("emit delegates_to(owner -> actor)");
    mint_delegated_token_inner(owner_wa_id, client_id, DelegationConstraints::default())
}

/// The same, with an owner-set ALLOW-LIST — the case codex named: a delegate
/// granted one verb and reaching for the others.
async fn mint_constrained_delegated_token(
    engine: &Engine,
    owner_wa_id: &str,
    client_id: &str,
    allow: &[&str],
) -> String {
    ciris_server::auth::ownership::emit_signed_attestation(
        engine,
        &owner_user_signer(),
        attestation_type::DELEGATES_TO,
        client_id,
        ciris_persist::federation::delegates_to_envelope(
            client_id,
            &[DELEGATED_SCOPE.to_string()],
            false,
        ),
        None,
    )
    .await
    .expect("emit delegates_to(owner -> actor)");
    mint_delegated_token_inner(
        owner_wa_id,
        client_id,
        DelegationConstraints {
            actions_allow: Some(allow.iter().map(|s| (*s).to_string()).collect()),
            ..Default::default()
        },
    )
}

const DELEGATED_SCOPE: &str = "owner:act-on-behalf";

fn mint_delegated_token_inner(
    owner_wa_id: &str,
    client_id: &str,
    constraints: DelegationConstraints,
) -> String {
    use ciris_server::auth::session::DelegatedGrant;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    ciris_server::auth::session::register_delegated_grant(DelegatedGrant {
        owner_wa_id: owner_wa_id.to_string(),
        owner_role: ciris_server::auth::roles::UserRole::SystemAdmin,
        owner_key_id: OWNER_USER_KEY_ID.to_string(),
        client_id: client_id.to_string(),
        scope: DELEGATED_SCOPE.to_string(),
        expires_at: now + 600,
        issued_at: now,
        purpose: Some("a monitoring agent".to_string()),
        attestation_id: None,
        constraints,
    })
}

/// **A DELEGATE MAY NOT AUTHOR A MESSAGE.** The ruling, pinned.
///
/// The gate passes delegates by design, so this has to be decided rather than
/// inherited, and the code decides it: the node holds only the OWNER's key, so
/// signing as the delegate is not possible — and signing as the OWNER from a
/// delegated session mints a signature that OUTLIVES the delegation. Withdrawing
/// the `delegates_to` edge cannot retract bytes already signed under the owner's
/// key, so the message would stand as the owner's own words forever. That is the
/// class CIRISServer#342's capsule doc names, which is why `ChatAuthor` sits on
/// `never_delegatable` beside re-delegation, wipe and the accord kill-switch.
///
/// READS stay open to a delegate: reading is bounded by the delegation's life,
/// and the cohort gate still applies underneath.
#[tokio::test]
async fn a_delegate_may_not_author_a_message_but_may_read() {
    let (_engine, base, owner, _h) = fixture().await;
    let client = reqwest::Client::new();
    let community_id = open_chat(&client, &base, &owner).await;
    let delegated = mint_delegated_token(&_engine, "wa-owner", CONTACT_KEY_ID).await;

    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&delegated)
        .json(&serde_json::json!({ "body": "signed as whom, exactly?" }))
        .send()
        .await
        .expect("POST message as a delegate");
    assert_eq!(
        resp.status(),
        403,
        "a delegate must not author under the owner's key"
    );
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["reason_id"], "chat.delegate_may_not_author");

    // The same bearer READS fine — the refusal is about signing, not about trust.
    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&delegated)
        .send()
        .await
        .expect("GET messages as a delegate");
    assert_eq!(
        resp.status(),
        200,
        "a delegate may read what it may not author"
    );
}

/// **EVERY OWNER-GATED ROUTE ANSWERS TO A VERB.** The other half of the
/// delegation hole: `resolve_bearer` hands a `dgrant:` token the owner's role AND
/// `FullAccess` together with the delegate's constraints, so the role check
/// cannot see the bounds. They bind only where a route NAMES its verb — a route
/// with no verb is a route with no enforcement — and none of these five named one
/// until now.
///
/// The grant here allows `announce` and nothing else, which is the shape codex
/// described: a delegate provisioned for one job reaching every other surface on
/// the node. All five must refuse, and each must say which contract refused it.
#[tokio::test]
async fn an_announce_only_delegate_reaches_no_contacts_or_chat_route() {
    let (engine, base, owner, _h) = fixture().await;
    let client = reqwest::Client::new();
    let community_id = open_chat(&client, &base, &owner).await;
    let delegated =
        mint_constrained_delegated_token(&engine, "wa-owner", CONTACT_KEY_ID, &["announce"]).await;

    for (method, path, reason) in [
        (
            "GET",
            "/v1/contacts".to_string(),
            "contacts.delegation_denied",
        ),
        (
            "POST",
            "/v1/contacts".to_string(),
            "contacts.delegation_denied",
        ),
        ("POST", "/v1/chat".to_string(), "chat.delegation_denied"),
        (
            "GET",
            format!("/v1/chat/{community_id}/messages"),
            "chat.delegation_denied",
        ),
        (
            "POST",
            format!("/v1/chat/{community_id}/messages"),
            "chat.delegate_may_not_author",
        ),
    ] {
        let url = format!("{base}{path}");
        let req = match method {
            "GET" => client.get(&url),
            _ => client
                .post(&url)
                .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID, "body": "x" })),
        };
        let resp = req
            .bearer_auth(&delegated)
            .send()
            .await
            .expect("constrained delegate request");
        assert_eq!(
            resp.status(),
            403,
            "{method} {path} must refuse a delegate outside its allow-list"
        );
        let json: serde_json::Value = resp.json().await.expect("refusal json");
        assert_eq!(json["reason_id"], reason, "{method} {path}");
    }
}

/// A delegate granted the READ verb may read, and still may not SEND. The two
/// powers are separate verbs precisely so an owner can hand over one of them;
/// without this, "gate everything" and "gate the right things" look identical.
#[tokio::test]
async fn a_read_granted_delegate_reads_but_still_cannot_send() {
    let (engine, base, owner, _h) = fixture().await;
    let client = reqwest::Client::new();
    let community_id = open_chat(&client, &base, &owner).await;
    let delegated =
        mint_constrained_delegated_token(&engine, "wa-owner", CONTACT_KEY_ID, &["chat_read"]).await;

    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&delegated)
        .send()
        .await
        .expect("GET messages");
    assert_eq!(
        resp.status(),
        200,
        "an explicitly read-granted delegate may read"
    );

    // `chat_author` is on the SERVER never-list, so even naming it in the
    // allow-list would not help — but here it simply is not granted.
    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&delegated)
        .json(&serde_json::json!({ "body": "not mine to send" }))
        .send()
        .await
        .expect("POST message");
    assert_eq!(resp.status(), 403);
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["reason_id"], "chat.delegate_may_not_author");
}

/// **A FEDERATED PEER IS NOT A CONTACT.** The accept-side mirror of the widening
/// fix: `POST /v1/contacts` widens a narrow grant on the SEND side, but the guard
/// on `POST /v1/chat` accepted any consent peer — so an ordinarily-federated key
/// carrying only `capacity:`/`trace:` could have a room opened with it and
/// messages accepted locally, while `chat:` stayed ineligible to replicate.
///
/// A one-way plane is worse than a closed one: it looks like a working
/// conversation from this side and arrives nowhere.
#[tokio::test]
async fn an_ordinarily_federated_peer_is_not_a_contact() {
    let (engine, base, owner, _h) = fixture().await;
    let node = node_key_id(&engine).await;
    // Ordinary federation peering — capacity:/trace: only, never a contact.
    ciris_server::peer::emit_replication_consent(
        &engine,
        &node,
        CONTACT_KEY_ID,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("federation peering grant");
    let client = reqwest::Client::new();

    // NOT listed: offering them would promise a conversation that never leaves.
    let listed = contacts_list(&client, &base, &owner).await;
    assert_eq!(
        listed["total"], 0,
        "a peer whose grant does not cover chat: is not a contact: {listed}"
    );

    // NOT accepted, and the refusal NAMES the missing prefix rather than saying
    // only "not a contact" — the operator needs to know it is a coverage gap and
    // not an unknown key.
    let resp = client
        .post(format!("{base}/v1/chat"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/chat");
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.expect("refusal body");
    assert!(body.contains("chat.not_a_contact"), "{body}");
    assert!(
        body.contains("chat:"),
        "the refusal must name the missing prefix: {body}"
    );

    // Adding them as a contact widens the grant, and BOTH doors then accept.
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts");
    assert_eq!(resp.status(), 200);
    let listed = contacts_list(&client, &base, &owner).await;
    assert_eq!(
        listed["total"], 1,
        "widening makes them a contact: {listed}"
    );
    let resp = client
        .post(format!("{base}/v1/chat"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/chat");
    assert_eq!(resp.status(), 200, "the room opens once chat: is covered");
}

/// **THE BOUNDARY GATE — the pin, flipped.**
///
/// Its predecessor asserted this FAILED, and named exactly what would flip it.
/// This is that flip: the row a send writes is now attested and signed by the
/// same key, so persist's own `verify_row_hybrid_signature` — the gate the far
/// node runs on ingest — accepts it. Two live nodes observed the old row refused
/// with "Classical signature verification failed: Ed25519" while node-authored
/// rows landed beside it; this asserts the difference is gone.
///
/// It runs the REAL gate against the REAL directory rather than re-deriving what
/// verification ought to mean, so it cannot pass by agreeing with itself.
#[tokio::test]
async fn a_chat_message_verifies_at_the_persist_boundary() {
    use ciris_persist::federation::tier_ingest::verify_row_hybrid_signature;

    let (engine, base, owner, _h) = fixture().await;
    let client = reqwest::Client::new();
    let community_id = open_chat(&client, &base, &owner).await;
    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "does this cross the wire?" }))
        .send()
        .await
        .expect("POST message");
    assert_eq!(resp.status(), 200);
    let sent: serde_json::Value = resp.json().await.expect("send json");
    let id = sent["attestation_id"].as_str().expect("attestation_id");

    let node = node_key_id(&engine).await;
    let directory = engine.federation_directory();
    let row = directory
        .list_attestations_by(&node)
        .await
        .expect("list_attestations_by")
        .into_iter()
        .find(|a| a.attestation_id == id)
        .expect("the stored message row");

    // Signer == attester: the property the far side's gate actually turns on.
    assert_eq!(row.attesting_key_id, node);
    assert_eq!(
        row.scrub_key_id, row.attesting_key_id,
        "the split that made every cross-node ingest refuse must be gone"
    );
    verify_row_hybrid_signature(directory.as_ref(), &row)
        .await
        .expect("the far node's own ingest gate must accept this row");
}

/// **THE ATTRIBUTION HALF.** Delivery and authorship are two properties and the
/// pin above only holds one of them — a row could verify perfectly while having
/// quietly lost the human whose words it carries. That failure would be
/// invisible: everything green, every message signed, every message attributed
/// to a box.
///
/// So this asserts the other half, and asserts it INSIDE the signed bytes: the
/// envelope names the owner, the projection reads the author from THERE (not
/// from the attester), and the live owner-binding the node acts under actually
/// exists.
#[tokio::test]
async fn the_message_names_its_human_author_inside_the_signed_envelope() {
    let (engine, base, owner, _h) = fixture().await;
    let client = reqwest::Client::new();
    let community_id = open_chat(&client, &base, &owner).await;
    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "my words, the node's signature" }))
        .send()
        .await
        .expect("POST message");
    assert_eq!(resp.status(), 200);
    let sent: serde_json::Value = resp.json().await.expect("send json");
    let id = sent["attestation_id"].as_str().expect("attestation_id");

    let node = node_key_id(&engine).await;
    let row = engine
        .federation_directory()
        .list_attestations_by(&node)
        .await
        .expect("list_attestations_by")
        .into_iter()
        .find(|a| a.attestation_id == id)
        .expect("the stored message row");

    // IN THE ENVELOPE — covered by the signature the far side verifies, so a
    // relay cannot rewrite the author while the row still checks out.
    assert_eq!(
        row.attestation_envelope["on_behalf_of_key_id"],
        serde_json::json!(OWNER_USER_KEY_ID),
        "the signed envelope must name the human: {:?}",
        row.attestation_envelope
    );
    assert_ne!(
        row.attesting_key_id, OWNER_USER_KEY_ID,
        "the node attests — if this ever equals the owner the signer-explicit \
         upgrade has landed, and `author` should come from the attester again"
    );

    // THE AUTHORITY IT ACTS UNDER is live and resolvable — not the node's say-so.
    // `is_steward_bound` is withdraws-aware, so this is the same read that would
    // stop being true the moment the owner revoked the binding.
    assert_eq!(
        ciris_server::auth::ownership::is_steward_bound(&engine, &node).await,
        Some(OWNER_USER_KEY_ID.to_string()),
        "a node authoring on its owner's behalf must hold a LIVE owner-binding"
    );

    // AND THE PROJECTION READS THE ENVELOPE, not the attester.
    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET messages");
    let list: serde_json::Value = resp.json().await.expect("messages json");
    let m = &list["messages"][0];
    assert_eq!(m["author"], OWNER_USER_KEY_ID, "author is the human: {m}");
    assert_eq!(
        m["attesting_key_id"],
        serde_json::json!(node),
        "attester is the node"
    );
    assert_eq!(
        m["mine"], true,
        "`mine` follows the author, not the attester"
    );
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

/// **Two concurrent `POST /v1/chat` for the same pair both succeed** — the
/// advertised idempotency must hold exactly on the inputs where it matters:
/// a double tap, a client retry, two devices. Both requests can observe
/// `lookup_community == None` before either insert lands; the loser hits the
/// primary-key conflict, and before the race arm it surfaced that as a 500 for
/// a room that EXISTS.
///
/// The race is scheduler-dependent, so this is a PROPERTY test: many rounds of
/// truly concurrent pairs on fresh state, asserting the contract — never a
/// 5xx, both bodies name the same convergent room, and at most one arrival
/// claims `freshly_created`. Rounds where the race does not interleave pass
/// trivially; a round where it does would have failed before the fix.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_chat_creation_is_an_idempotent_success() {
    for round in 0..12 {
        let (_engine, base, owner, _h) = fixture().await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/v1/contacts"))
            .bearer_auth(&owner)
            .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
            .send()
            .await
            .expect("POST /v1/contacts");
        assert_eq!(resp.status(), 200, "round {round}: add contact");

        let post = |c: reqwest::Client, b: String, o: String| async move {
            c.post(format!("{b}/v1/chat"))
                .bearer_auth(&o)
                .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
                .send()
                .await
                .expect("POST /v1/chat")
        };
        let (a, b) = tokio::join!(
            post(client.clone(), base.clone(), owner.clone()),
            post(client.clone(), base.clone(), owner.clone())
        );
        let (sa, sb) = (a.status(), b.status());
        let ja: serde_json::Value = a.json().await.expect("json a");
        let jb: serde_json::Value = b.json().await.expect("json b");
        assert!(
            sa == 200 && sb == 200,
            "round {round}: a concurrent chat creation must be an idempotent \
             success, got {sa}/{sb}: {ja} / {jb}"
        );
        assert_eq!(ja["community_id"], jb["community_id"], "round {round}");
        assert!(
            !(ja["freshly_created"] == true && jb["freshly_created"] == true),
            "round {round}: both arrivals claim to have created the room — the \
             loser must report freshly_created=false"
        );
    }
}

// ─── The author claim is validated, not trusted ─────────────────────────────

/// Seed a NODE-role key: a steward-binding's target must be a node —
/// `delegates_to` onto a user-role key is guardianship-only (CC 3.2, the
/// refusal this test first hit), so the contact's node must carry
/// `identity_type::NODE` exactly as a real node registration does.
async fn seed_node_key(engine: &Engine, key_id: &str, ed_seed: u8, pqc_seed: u8) {
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
        identity_type: identity_type::NODE.into(),
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
        .unwrap_or_else(|e| panic!("seed node key {key_id}: {e}"));
}

/// Build a signer for `CONTACT_KEY_ID` from the same seeds the fixture
/// registered its pubkeys under, so a binding it emits verifies as the real
/// contact's act.
fn contact_signer() -> LocalSigner {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xB1; 32], format!("{CONTACT_KEY_ID}-pqc"))
            .expect("contact ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xB0; 32]),
        CONTACT_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{CONTACT_KEY_ID}-pqc")),
    )
}

/// **A forged `on_behalf_of_key_id` cannot render as the local owner's words**
/// (codex, contacts_chat.rs:1303).
///
/// The envelope member is producer-asserted: any node inside the transcript's
/// scan set can sign a valid community row whose envelope claims OUR owner as
/// author. The projection now honors the claim only when the attesting node's
/// LIVE owner-binding names the claimed member. Three assertions, one run:
/// the forgery projects the WIRE TRUTH (the forging node) and never `mine`;
/// the same forger's row claiming its OWN bound member projects that member
/// (the positive case that makes the far side's legitimate messages work);
/// and the owner's genuine message still projects the owner.
#[tokio::test]
async fn a_forged_author_claim_projects_the_attester_never_the_owner() {
    let (engine, base, owner, _h) = fixture().await;
    let client = reqwest::Client::new();
    let community_id = open_chat(&client, &base, &owner).await;

    // A genuine message from the owner, as a control.
    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "genuine" }))
        .send()
        .await
        .expect("send genuine");
    assert_eq!(resp.status(), 200);

    // The contact's node: a real key the CONTACT's own live owner-binding
    // names — which puts it in the transcript's scan set, exactly the position
    // the attack requires.
    const EVIL_NODE: &str = "contact-node-1";
    seed_node_key(&engine, EVIL_NODE, 0xE0, 0xE1).await;
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    ciris_server::auth::ownership::emit_steward_binding(
        &engine,
        &contact_signer(),
        EVIL_NODE,
        &scopes,
    )
    .await
    .expect("bind contact -> its node");

    // The forgery: attested by the contact's node, claiming OUR owner.
    let forged =
        seed_message_attested_by(&engine, EVIL_NODE, OWNER_USER_KEY_ID, &community_id).await;
    // The far side's legitimate shape: same node, claiming ITS bound member.
    let legit = seed_message_attested_by(&engine, EVIL_NODE, CONTACT_KEY_ID, &community_id).await;

    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET messages");
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.expect("messages json");
    let msgs = json["messages"].as_array().expect("messages array");

    let find = |id: &str| {
        msgs.iter()
            .find(|m| m["attestation_id"] == id)
            .unwrap_or_else(|| panic!("row {id} missing from transcript"))
    };
    let f = find(&forged);
    assert_eq!(
        f["author"], EVIL_NODE,
        "a claim the attesting node's binding does not back must project the \
         WIRE TRUTH, not the claim: {f}"
    );
    assert_eq!(
        f["mine"], false,
        "a forged claim must never render as the local owner's own words: {f}"
    );
    let l = find(&legit);
    assert_eq!(
        l["author"], CONTACT_KEY_ID,
        "the same node claiming its OWN bound member is the legitimate far-side \
         shape and must project the member: {l}"
    );
    let genuine = msgs
        .iter()
        .find(|m| m["body"] == "genuine")
        .expect("genuine message");
    assert_eq!(genuine["author"], OWNER_USER_KEY_ID);
    assert_eq!(genuine["mine"], true);
}

/// A message row attested by `node`, claiming `author` — the wire shape a
/// FOREIGN node's row arrives in (raw put, community scope, no promote step:
/// a replicated row lands already at its tier).
async fn seed_message_attested_by(
    engine: &Engine,
    node: &str,
    author: &str,
    community_id: &str,
) -> String {
    let envelope = serde_json::json!({
        (paths::DIMENSION): contacts_chat::CHAT_MESSAGE_DIMENSION,
        "community_id": community_id,
        "on_behalf_of_key_id": author,
        "body": format!("as {author}"),
        "content_type": "text/plain",
        "score": 1.0,
    });
    let input = LocalAttestationInput {
        attestation_id: None,
        attesting_key_id: node.to_string(),
        attested_key_id: Some(node.to_string()),
        attestation_type: attestation_type::SCORES.to_string(),
        weight: None,
        expires_at: None,
        attestation_envelope: ciris_persist::federation::envelope::EnvelopeCore::from_value(
            envelope,
        )
        .expect("envelope"),
        subject_key_ids: vec![node.to_string()],
        cohort_scope: cohort_scope::SELF.to_string(),
        scrub_signature_classical: None,
        scrub_signature_pqc: None,
    };
    let id = engine
        .federation_directory()
        .attestation_upsert_local(input)
        .await
        .expect("upsert foreign-shaped chat message");
    engine
        .attestation_promote(&id, cohort_scope::COMMUNITY)
        .await
        .expect("promote to community tier");
    id
}

/// **A pre-planted room under the derived pair id is a conflict, not a chat**
/// (codex, contacts_chat.rs:702).
///
/// The pair id is derivable by anyone, so a peer can replicate a community
/// under it carrying the pair PLUS a stowaway. The front door now applies the
/// same sorted-member equality the insert-race arm uses — and the refusal
/// leaks nothing about who is on the poisoned roster.
#[tokio::test]
async fn a_poisoned_roster_under_the_pair_id_is_refused() {
    use ciris_persist::federation::types::{Community, CommunityMember};
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

    let community_id = pair_community_key_id(OWNER_USER_KEY_ID, CONTACT_KEY_ID);
    let now = chrono::Utc::now();
    engine
        .put_community_self_signed(Community {
            community_key_id: community_id.clone(),
            community_name: "poisoned".to_string(),
            members: [OWNER_USER_KEY_ID, CONTACT_KEY_ID, STRANGER_A_KEY_ID]
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
        .expect("pre-plant the poisoned room");

    let resp = client
        .post(format!("{base}/v1/chat"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/chat");
    assert_eq!(resp.status(), 409, "a wrong-roster room must refuse");
    let body = resp.text().await.expect("refusal body");
    let json: serde_json::Value = serde_json::from_str(&body).expect("refusal json");
    assert_eq!(json["reason_id"], "chat.community_shape_conflict");
    assert!(
        !body.contains(STRANGER_A_KEY_ID),
        "the refusal must not leak who is on the poisoned roster: {body}"
    );
}

/// **Both chat WRITE handlers call the declared-conformance gate** (codex,
/// contacts_chat.rs:633). ChatCreate/ChatAuthor declare [Producer, Substrate]
/// in `conformance::required_profiles`, and a declaration is only real if
/// something REFUSES when it is absent — the profiles were declared (the
/// exhaustive match forced it) while neither write handler enforced them, so a
/// node whose config omitted CCP/CCS still authored federation-wire rows.
/// Source-scoped to each handler's body, the owner_signer_capsule lesson: a
/// whole-file grep also matches the comment that explains the rule.
#[test]
fn both_chat_write_handlers_enforce_declared_conformance() {
    let src = include_str!("../src/contacts_chat.rs");
    for handler in ["async fn start_chat(", "async fn send_message("] {
        let start = src
            .find(handler)
            .unwrap_or_else(|| panic!("{handler} must exist"));
        let body = &src[start..(start + 6000).min(src.len())];
        assert!(
            body.contains("conformance::require_op"),
            "{handler} no longer calls the declared-conformance gate — a node \
             whose config:node.conformance_profiles does not claim \
             [Producer, Substrate] would author federation-wire chat rows it \
             explicitly does not claim the roles for"
        );
    }
}
