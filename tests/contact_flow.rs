//! **Adding a contact by QR code or pasted string, across two nodes**
//! (CIRISServer#673), and **taking consent back** (CIRISServer#657).
//!
//! Two [`Person`]s are two separate engines, as in production: Alice's node
//! serves her contact code, and Bob's node resolves it through the real
//! `POST /v1/contacts` door. Nothing moves between them except what the test
//! carries explicitly — the code itself, and (for the directory path) the rows
//! an announce replicates. That separation is the point: a single shared
//! database would let the directory answer for the code.
//!
//! The code's contract, by the maintainer's rulings (2026-09-25):
//!
//! * it carries the person's fed-ID key and the commitment to its ML-DSA-65
//!   half, and — by the person's choice — some of their ANNOUNCED nodes, each
//!   with its transport key. Announce is per node; an unannounced node never
//!   rides a code;
//! * with nodes, Bob resolves Alice with NO directory (edge's
//!   `ReadyFromCode`, `source: "direct"`);
//! * with none (`?nodes=none`), it is still a valid code and Bob resolves Alice
//!   through the public directory (`source: "federation"`).

#[path = "support/owned_node.rs"]
mod owned_node;

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde_json::json;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{attestation_type, identity_type};
use ciris_persist::prelude::LocalSigner;
use ciris_verify_core::fedcode;

use owned_node::{assert_refused, Person};

// ─── Fixture ────────────────────────────────────────────────────────────────

/// The contacts surface over `p`'s node, beside the self-device routes.
///
/// The edge signer is the room record's authority and is not exercised by the
/// contact doors; a throwaway software key under the node's id stands in.
fn contacts_router(p: &Person) -> axum::Router {
    let classical: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(
        ciris_keyring::Ed25519SoftwareSigner::from_bytes(&[0x5A; 32], "contact-flow-edge")
            .expect("edge classical"),
    );
    let pqc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0x5B; 32], "contact-flow-edge-pqc".to_string())
            .expect("edge pqc"),
    );
    let signer = Arc::new(ciris_edge::identity::LocalSigner::new(
        p.node_key_id.clone(),
        classical,
        Some(pqc),
    ));
    ciris_server::contacts_chat::router(
        Arc::clone(&p.engine),
        signer,
        p.owner.seed_dir.clone(),
        None,
        None,
    )
    .merge(p.router())
}

/// A live reticulum route for `node` on `p`'s directory, carrying a transport
/// Ed25519 derived from `tag` — what compose publishes at boot. Returns the
/// transport key (base64).
async fn publish_transport(p: &Person, node: &str, tag: u8) -> String {
    let ed = SigningKey::from_bytes(&[tag; 32]);
    let transport = BASE64.encode(ed.verifying_key().to_bytes());
    p.engine
        .federation_directory()
        .put_transport_destination(&ciris_persist::federation::TransportDestination {
            occurrence_key_id: node.to_owned(),
            transport_kind: "reticulum".to_owned(),
            destination: hex::encode([tag; 16]),
            asserted_at: chrono::Utc::now(),
            last_seen_at: None,
            transport_ed25519_pubkey_base64: Some(transport.clone()),
            transport_x25519_pubkey_base64: Some(BASE64.encode([tag.wrapping_add(1); 32])),
            binding_provenance: Default::default(),
            epoch: 0,
            retired_at: None,
        })
        .await
        .expect("publish a transport route");
    transport
}

/// Another machine `p` owns, owner-bound at FEDERATION (`announced`) or at
/// `self` (not announced).
async fn another_node(p: &Person, tag: u8, announced: bool) -> String {
    let key_id = format!("{}-node-{tag}", p.name);
    let pqc =
        MlDsa65SoftwareSigner::from_seed_bytes(&[tag.wrapping_add(1); 32], format!("{key_id}-pqc"))
            .expect("ML-DSA seed");
    let signer = LocalSigner::from_parts(
        SigningKey::from_bytes(&[tag; 32]),
        key_id.clone(),
        Some(Arc::new(pqc) as Arc<dyn ciris_keyring::PqcSigner>),
        Some(format!("{key_id}-pqc")),
    );
    ciris_server::attest::register_key(
        &p.engine,
        ciris_server::attest::KeySigner::Local(&signer),
        &key_id,
        identity_type::NODE,
        serde_json::Value::Null,
    )
    .await
    .expect("register the node");
    if announced {
        let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
            .iter()
            .map(|s| s.to_string())
            .collect();
        ciris_server::auth::ownership::emit_steward_binding(
            &p.engine,
            &p.owner.signer().await,
            &key_id,
            &scopes,
        )
        .await
        .expect("owner-bind at federation");
    } else {
        owned_node::bind_self_scoped(&p.engine, &p.owner.signer().await, &key_id).await;
    }
    key_id
}

/// What an ANNOUNCE puts in front of a peer: the owner's key, the node's key,
/// and the federation-scope owner-binding — carried onto `to` through the same
/// persist doors a replication apply uses.
async fn carry_announce(from: &Person, to: &Person) {
    to.knows(from).await;
    let src = from.engine.federation_directory();
    let dst = to.engine.federation_directory();
    let node = src
        .lookup_public_key(&from.node_key_id)
        .await
        .expect("lookup")
        .expect("the node key");
    dst.put_public_key(ciris_persist::federation::SignedKeyRecord { record: node })
        .await
        .expect("carry the node key");
    let rows = src
        .list_attestations_by(from.key())
        .await
        .expect("the owner's rows");
    let mut carried = 0;
    for row in rows {
        if row.attestation_type == attestation_type::DELEGATES_TO
            && row.attested_key_id == from.node_key_id
            && row.cohort_scope == ciris_persist::federation::types::cohort_scope::FEDERATION
        {
            dst.put_attestation(ciris_persist::federation::SignedAttestation { attestation: row })
                .await
                .expect("carry the federation owner-binding");
            carried += 1;
        }
    }
    assert!(carried > 0, "precondition: an announced binding to carry");
}

async fn contact_code(p: &Person, query: &str) -> (u16, serde_json::Value) {
    let (st, v) = p
        .as_owner("GET", &format!("/v1/self/contact-code{query}"), None)
        .await;
    (st.as_u16(), v)
}

fn included(v: &serde_json::Value) -> Vec<String> {
    v["included_nodes"]
        .as_array()
        .expect("included_nodes")
        .iter()
        .map(|n| n["key_id"].as_str().expect("key_id").to_owned())
        .collect()
}

fn available(v: &serde_json::Value) -> Vec<String> {
    v["available_nodes"]
        .as_array()
        .expect("available_nodes")
        .iter()
        .map(|n| n["node_key_id"].as_str().expect("node_key_id").to_owned())
        .collect()
}

async fn add_contact(p: &Person, key_or_code: &str) -> (u16, serde_json::Value) {
    let bearer = p.bearer.clone();
    let (st, v) = p
        .call_on(
            contacts_router(p),
            "POST",
            "/v1/contacts",
            Some(&bearer),
            Some(json!({ "key_id": key_or_code })),
        )
        .await;
    (st.as_u16(), v)
}

// ─── #673: the code ─────────────────────────────────────────────────────────

/// The whole flow the maintainer asked for: a code read off node A, pasted into
/// `POST /v1/contacts` on node B, resolves through the CODE (`ReadyFromCode`,
/// `source: "direct"`) into a contact whose person is A's owner. B holds A's
/// owner key (a Key Pull answered) but NOT A's ownership graph — so the
/// directory alone could not have produced this answer.
#[tokio::test]
async fn a_code_from_node_a_resolves_on_node_b_without_the_directory() {
    let alice = Person::new("cc-alice").await;
    let transport = publish_transport(&alice, &alice.node_key_id, 0x31).await;

    let (st, v) = contact_code(&alice, "").await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["key_id"], alice.key());
    assert_eq!(included(&v), vec![alice.node_key_id.clone()], "{v}");
    assert_eq!(v["reachable_without_directory"], true);

    // Verify's own decoder reads what the route encoded.
    let code = v["code"].as_str().expect("code").to_owned();
    assert!(code.starts_with("CIRIS-V3-"), "{code}");
    let decoded = fedcode::decode(&code).expect("decode the code");
    assert_eq!(decoded.kind, fedcode::FedKind::User);
    assert_eq!(decoded.key_id, alice.key());
    assert_eq!(
        decoded.pubkey_ed25519_base64,
        alice.owner.pubkey_ed25519_base64
    );
    assert_eq!(decoded.owned_nodes.len(), 1);
    assert_eq!(decoded.owned_nodes[0].key_id, alice.node_key_id);
    assert_eq!(
        decoded.owned_nodes[0].transport_pubkey_ed25519_base64,
        transport
    );
    let pqc = BASE64
        .decode(&alice.owner.pubkey_ml_dsa_65_base64)
        .expect("pqc b64");
    fedcode::verify_pulled_ml_dsa_65_pubkey(&decoded, &pqc)
        .expect("the code commits to the owner's ML-DSA-65 half");
    // The QR payload IS the same code, ungrouped.
    let qr = v["qr_payload"].as_str().expect("qr_payload");
    assert_eq!(fedcode::decode(qr).expect("decode the QR form"), decoded);
    assert_eq!(qr.replace('-', ""), code.replace('-', ""));

    // A node that does not hold Alice's key yet reaches the CODE path and asks
    // the mesh for the key body — there is no mesh in-process, so it says so.
    let carol = Person::new("cc-carol").await;
    let (st, v) = add_contact(&carol, &code).await;
    assert_eq!(
        (st, v["reason_id"].as_str()),
        (503, Some("contacts.key_pull_unavailable")),
        "{v}"
    );

    // Bob holds Alice's key record and nothing else of hers.
    let bob = Person::new("cc-bob").await;
    bob.knows(&alice).await;
    let (st, v) = add_contact(&bob, &code).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["source"], "direct", "resolved by the code: {v}");
    assert_eq!(
        v["key_id"],
        alice.key(),
        "the contact is Alice, the person: {v}"
    );
    // Pasting the QR form is the same contact, idempotently.
    let (st, again) = add_contact(&bob, qr).await;
    assert_eq!(st, 200, "{again}");
    assert_eq!(again["key_id"], alice.key());
    assert_eq!(again["consent_attestation_id"], v["consent_attestation_id"]);
}

/// The person chooses: every announced node by default, exactly the named ones,
/// or none — and an unannounced (or foreign) node can never be named. The
/// mixed owner: A (this node) and C announced, B not.
#[tokio::test]
async fn the_person_chooses_which_announced_nodes_the_code_carries() {
    let alice = Person::new("cc-mix").await;
    let node_a = alice.node_key_id.clone();
    let node_b = another_node(&alice, 0x62, false).await;
    let node_c = another_node(&alice, 0x64, true).await;
    for (n, tag) in [(&node_a, 0x41), (&node_b, 0x42), (&node_c, 0x43)] {
        publish_transport(&alice, n, tag).await;
    }
    let mut announced = vec![node_a.clone(), node_c.clone()];
    announced.sort();

    // Default: all ANNOUNCED nodes — never B.
    let (st, v) = contact_code(&alice, "").await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(available(&v), announced, "B is not offered: {v}");
    assert_eq!(included(&v), announced, "{v}");
    let decoded = fedcode::decode(v["code"].as_str().expect("code")).expect("decode");
    let mut carried: Vec<String> = decoded
        .owned_nodes
        .iter()
        .map(|n| n.key_id.clone())
        .collect();
    carried.sort();
    assert_eq!(carried, announced);
    let this = v["available_nodes"]
        .as_array()
        .expect("available")
        .iter()
        .find(|n| n["node_key_id"] == node_a.as_str())
        .expect("A offered");
    assert_eq!(this["announced"], true);
    assert_eq!(this["this_node"], true);

    // A chosen subset: exactly C.
    let (st, v) = contact_code(&alice, &format!("?nodes={node_c}")).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(included(&v), vec![node_c.clone()], "{v}");
    assert_eq!(available(&v), announced, "the choice is still offered: {v}");

    // Naming the unannounced node refuses, by name, listing it.
    let r = alice
        .as_owner(
            "GET",
            &format!("/v1/self/contact-code?nodes={node_a},{node_b}"),
            None,
        )
        .await;
    assert_refused(&r, 400, "self.node_not_announced");
    assert_eq!(r.1["detail"], node_b.as_str(), "{}", r.1);
    // …and so does a node that is not hers at all.
    let r = alice
        .as_owner(
            "GET",
            "/v1/self/contact-code?nodes=someone-elses-node",
            None,
        )
        .await;
    assert_refused(&r, 400, "self.node_not_announced");

    // None: a valid code with no nodes.
    let (st, v) = contact_code(&alice, "?nodes=none").await;
    assert_eq!(st, 200, "{v}");
    assert!(included(&v).is_empty(), "{v}");
    assert_eq!(v["reachable_without_directory"], false);
    let decoded = fedcode::decode(v["code"].as_str().expect("code")).expect("decode");
    assert!(decoded.owned_nodes.is_empty());
    assert_eq!(decoded.key_id, alice.key());
    assert!(
        decoded.ml_dsa_65_pubkey_sha256.is_some(),
        "a node-less code still commits to the PQC half"
    );
}

/// A code with no nodes resolves through the PUBLIC DIRECTORY: Bob holds what
/// Alice's announce put in front of peers (her key, her node's key, the
/// federation owner-binding), and the contact lands as `source: "federation"`
/// — the lightnet path, no embedded node needed.
#[tokio::test]
async fn a_node_less_code_resolves_through_the_directory() {
    let alice = Person::new("cc-dir").await;
    publish_transport(&alice, &alice.node_key_id, 0x51).await;
    let (st, v) = contact_code(&alice, "?nodes=none").await;
    assert_eq!(st, 200, "{v}");
    let code = v["code"].as_str().expect("code").to_owned();

    let bob = Person::new("cc-dir-bob").await;
    carry_announce(&alice, &bob).await;
    let (st, v) = add_contact(&bob, &code).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(
        v["source"], "federation",
        "resolved through the directory: {v}"
    );
    assert_eq!(v["key_id"], alice.key(), "{v}");
}

/// An owner who announced nothing still has a code — their key, no nodes — and
/// is offered nothing to include.
#[tokio::test]
async fn an_owner_with_no_announced_node_gets_a_node_less_code() {
    let alice = Person::new_unannounced("cc-quiet").await;
    publish_transport(&alice, &alice.node_key_id, 0x71).await;
    let (st, v) = contact_code(&alice, "").await;
    assert_eq!(st, 200, "{v}");
    assert!(available(&v).is_empty(), "{v}");
    assert!(included(&v).is_empty(), "{v}");
    let decoded = fedcode::decode(v["code"].as_str().expect("code")).expect("decode");
    assert_eq!(decoded.key_id, alice.key());
    assert!(decoded.owned_nodes.is_empty());
    // Naming this (unannounced) node is refused.
    let r = alice
        .as_owner(
            "GET",
            &format!("/v1/self/contact-code?nodes={}", alice.node_key_id),
            None,
        )
        .await;
    assert_refused(&r, 400, "self.node_not_announced");
}

#[tokio::test]
async fn only_the_owner_reads_the_contact_code() {
    let alice = Person::new("cc-gate").await;
    let r = alice.call("GET", "/v1/self/contact-code", None, None).await;
    assert_refused(&r, 401, "self.owner_session_required");
    let guest = alice.stranger_session().await;
    let r = alice
        .call("GET", "/v1/self/contact-code", Some(&guest), None)
        .await;
    assert_refused(&r, 403, "self.owner_session_required");
}

// ─── #657: taking consent back ──────────────────────────────────────────────

/// Alice consents to replicate to Bob — authored with HER pen, as an owned
/// node's consent is. Returns the grant's id.
async fn owner_grant(alice: &Person, bob: &Person) -> String {
    alice.knows(bob).await;
    let opts = ciris_server::peer::ConsentGrantOptions {
        author_signer: Some(Arc::new(alice.owner.signer().await)),
        ..Default::default()
    };
    let grant = ciris_server::peer::emit_replication_consent_with_policy(
        &alice.engine,
        alice.key(),
        bob.key(),
        &ciris_server::peer::default_attestation_prefixes(),
        &opts,
    )
    .await
    .expect("the owner consents");
    assert!(grant.freshly_emitted);
    grant.attestation_id
}

async fn live_grant_ids(p: &Person) -> Vec<String> {
    ciris_server::peer::live_consent_grants_for_machine(&p.engine, &p.node_key_id)
        .await
        .expect("live grants")
        .into_iter()
        .map(|g| g.attestation_id)
        .collect()
}

async fn owner_call(
    p: &Person,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let bearer = p.bearer.clone();
    p.call_on(contacts_router(p), method, path, Some(&bearer), body)
        .await
}

#[tokio::test]
async fn un_contacting_withdraws_the_owners_grant_with_the_owners_pen() {
    let alice = Person::new("uc-alice").await;
    let bob = Person::new("uc-bob").await;
    let grant = owner_grant(&alice, &bob).await;
    assert!(live_grant_ids(&alice).await.contains(&grant));

    let (st, v) = owner_call(
        &alice,
        "DELETE",
        &format!("/v1/contacts/{}", bob.key()),
        None,
    )
    .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(v["contact"], false, "{v}");
    let withdrawn = v["withdrawn"].as_array().expect("withdrawn");
    assert_eq!(withdrawn.len(), 1, "{v}");
    assert_eq!(withdrawn[0]["grant"], grant.as_str());

    // persist's fold, not the route, is the witness.
    assert!(!live_grant_ids(&alice).await.contains(&grant));
    // The withdraws is ALICE's row, never the node's.
    let wid = withdrawn[0]["withdraws"].as_str().expect("id");
    let row = alice
        .engine
        .federation_directory()
        .list_attestations_by(alice.key())
        .await
        .expect("rows")
        .into_iter()
        .find(|a| a.attestation_id == wid)
        .expect("the withdraws row, authored by the owner");
    assert_eq!(row.attestation_type, attestation_type::WITHDRAWS);
    assert_eq!(row.attesting_key_id, alice.key());

    // Nothing left to withdraw.
    let r = owner_call(
        &alice,
        "DELETE",
        &format!("/v1/contacts/{}", bob.key()),
        None,
    )
    .await;
    assert_refused(&r, 404, "contacts.not_a_contact");
    // And the person can be re-added: revocation is free.
    let (st, v) = add_contact(&alice, bob.key()).await;
    assert_eq!(st, 200, "re-adding after a withdraw works: {v}");
}

#[tokio::test]
async fn a_grant_is_revoked_by_id() {
    let alice = Person::new("rv-alice").await;
    let bob = Person::new("rv-bob").await;
    let grant = owner_grant(&alice, &bob).await;

    let (st, v) = owner_call(
        &alice,
        "POST",
        "/v1/federation/peering/revoke",
        Some(json!({ "attestation_id": grant })),
    )
    .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(v["attestation_id"], grant.as_str());
    assert_eq!(v["peer_key_ids"], json!([bob.key()]));
    assert!(!live_grant_ids(&alice).await.contains(&grant));

    let r = owner_call(
        &alice,
        "POST",
        "/v1/federation/peering/revoke",
        Some(json!({ "attestation_id": grant })),
    )
    .await;
    assert_refused(&r, 404, "consent.grant_not_live");
    let r = owner_call(
        &alice,
        "POST",
        "/v1/federation/peering/revoke",
        Some(json!({ "attestation_id": "no-such-grant" })),
    )
    .await;
    assert_refused(&r, 404, "consent.grant_not_live");
    let r = owner_call(
        &alice,
        "POST",
        "/v1/federation/peering/revoke",
        Some(json!({ "nope": 1 })),
    )
    .await;
    assert_refused(&r, 400, "consent.malformed_body");
}

/// A grant the MACHINE authored (the provisional pre-claim row) is not the
/// owner's to withdraw here, and the node will not withdraw it as itself: both
/// doors refuse it by name and write nothing.
#[tokio::test]
async fn a_machine_authored_grant_is_refused_by_name() {
    let alice = Person::new("ma-alice").await;
    let bob = Person::new("ma-bob").await;
    alice.knows(&bob).await;
    let grant = ciris_server::peer::emit_replication_consent(
        &alice.engine,
        &alice.node_key_id,
        bob.key(),
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("a machine-authored grant");
    let row = alice
        .engine
        .federation_directory()
        .get_attestation(&grant.attestation_id)
        .await
        .expect("read")
        .expect("the grant");
    assert_eq!(
        row.attesting_key_id, alice.node_key_id,
        "precondition: machine-authored"
    );

    let r = owner_call(
        &alice,
        "DELETE",
        &format!("/v1/contacts/{}", bob.key()),
        None,
    )
    .await;
    assert_refused(&r, 409, "consent.grant_not_owner_authored");
    let r = owner_call(
        &alice,
        "POST",
        "/v1/federation/peering/revoke",
        Some(json!({ "attestation_id": grant.attestation_id })),
    )
    .await;
    assert_refused(&r, 409, "consent.grant_not_owner_authored");
    assert!(live_grant_ids(&alice).await.contains(&grant.attestation_id));
}

/// Only the owner's own session withdraws — never a stranger, never a delegate
/// (the withdrawal is signed with the owner's key and outlives any delegation).
#[tokio::test]
async fn only_the_owner_withdraws_consent() {
    let alice = Person::new("ow-alice").await;
    let bob = Person::new("ow-bob").await;
    let grant = owner_grant(&alice, &bob).await;
    let path = format!("/v1/contacts/{}", bob.key());

    let r = alice
        .call_on(contacts_router(&alice), "DELETE", &path, None, None)
        .await;
    assert_eq!(r.0.as_u16(), 401, "{}", r.1);
    let guest = alice.stranger_session().await;
    let r = alice
        .call_on(contacts_router(&alice), "DELETE", &path, Some(&guest), None)
        .await;
    assert_eq!(r.0.as_u16(), 403, "{}", r.1);
    let delegated = alice.delegated_session().await;
    let r = alice
        .call_on(
            contacts_router(&alice),
            "DELETE",
            &path,
            Some(&delegated),
            None,
        )
        .await;
    assert_eq!(r.0.as_u16(), 403, "{}", r.1);
    assert!(
        matches!(
            r.1["reason_id"].as_str(),
            Some("contacts.delegation_denied" | "consent.delegate_may_not_withdraw")
        ),
        "{}",
        r.1
    );
    assert!(
        live_grant_ids(&alice).await.contains(&grant),
        "nothing withdrawn"
    );
}
