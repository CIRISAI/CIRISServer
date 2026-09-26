//! **The owner's own devices** (`FSD/ROSTER_AND_DRIVE_CRUD.md` §2), over the
//! real router: releasing a node, relabelling a device key, and the occurrence
//! list's `revoked` / `include_revoked`.
//!
//! A release is the OWNER's signed `withdraws` of their owner-binding, so the
//! witness is persist's own projection: `nodes_owned_by(owner)` lists the node
//! before and not after. The node you are talking to needs `force_self`, and
//! once released it answers its former owner's session as an unowned node.

#[path = "support/owned_node.rs"]
mod owned_node;

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde_json::json;

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::admission::{nodes_owned_by, owner_of};
use ciris_persist::federation::types::{
    attestation_type, identity_type, IdentityOccurrence, IdentityOccurrenceRevocation,
};
use ciris_persist::prelude::LocalSigner;

use owned_node::{assert_refused, user_record, Person};

async fn owned(p: &Person) -> Vec<String> {
    nodes_owned_by(p.engine.federation_directory().as_ref(), p.key())
        .await
        .expect("nodes_owned_by")
}

/// A second machine the same person owns: a registered NODE key and the
/// owner-binding `delegates_to(owner → node)` signed with the owner's pen.
async fn second_node(p: &Person, tag: u8) -> String {
    let key_id = format!("second-node-{tag}");
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
    .expect("register the second node");
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
    .expect("owner-bind the second node");
    key_id
}

#[tokio::test]
async fn the_owner_releases_another_of_their_nodes() {
    let alice = Person::new("rel-a").await;
    let n2 = second_node(&alice, 0xE0).await;
    let before = owned(&alice).await;
    assert!(before.contains(&n2), "precondition: {before:?}");
    assert!(before.contains(&alice.node_key_id), "{before:?}");

    let (st, v) = alice
        .as_owner("POST", &format!("/v1/self/nodes/{n2}/release"), None)
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(v["released"], true);
    assert_eq!(v["released_self"], false);
    let withdrawn = v["withdrawn"].as_array().expect("withdrawn");
    assert_eq!(withdrawn.len(), 1, "one owner-binding, one withdraws: {v}");

    // The witness is persist's, not the route's.
    let after = owned(&alice).await;
    assert!(!after.contains(&n2), "released node still owned: {after:?}");
    assert!(
        after.contains(&alice.node_key_id),
        "this node untouched: {after:?}"
    );
    assert_eq!(
        owner_of(alice.engine.federation_directory().as_ref(), &n2)
            .await
            .expect("owner_of"),
        None
    );
    // The withdraws is the OWNER's row, not the machine's.
    let wid = withdrawn[0]["withdraws"].as_str().expect("id");
    let row = alice
        .engine
        .federation_directory()
        .list_attestations_by(alice.key())
        .await
        .expect("rows")
        .into_iter()
        .find(|a| a.attestation_id == wid)
        .expect("the withdraws row");
    assert_eq!(row.attestation_type, attestation_type::WITHDRAWS);
    assert_eq!(row.attesting_key_id, alice.key());

    // Released is released: the same call again is not yours to make.
    let r = alice
        .as_owner("POST", &format!("/v1/self/nodes/{n2}/release"), None)
        .await;
    assert_refused(&r, 403, "self.not_your_node");
}

#[tokio::test]
async fn a_node_that_is_not_yours_is_refused_by_one_id() {
    let alice = Person::new("rel-b").await;
    let bob = Person::new("rel-c").await;
    // Bob's machine, even when Alice's node can see whose it is.
    let r = alice
        .as_owner(
            "POST",
            &format!("/v1/self/nodes/{}/release", bob.node_key_id),
            None,
        )
        .await;
    assert_refused(&r, 403, "self.not_your_node");
    // A key nobody has heard of.
    let r = alice
        .as_owner("POST", "/v1/self/nodes/no-such-node/release", None)
        .await;
    assert_refused(&r, 403, "self.not_your_node");
    // Bob's node never lost its owner.
    assert!(owned(&bob).await.contains(&bob.node_key_id));
}

#[tokio::test]
async fn releasing_the_node_you_are_talking_to_needs_force() {
    let alice = Person::new("rel-d").await;
    let path = format!("/v1/self/nodes/{}/release", alice.node_key_id);
    let r = alice.as_owner("POST", &path, None).await;
    assert_refused(&r, 409, "self.release_self_requires_force");
    let r = alice
        .as_owner("POST", &path, Some(json!({ "force_self": false })))
        .await;
    assert_refused(&r, 409, "self.release_self_requires_force");
    assert!(owned(&alice).await.contains(&alice.node_key_id));

    let (st, v) = alice
        .as_owner("POST", &path, Some(json!({ "force_self": true })))
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(v["released_self"], true);
    assert!(!owned(&alice).await.contains(&alice.node_key_id));
    // The node is unowned now: its former owner's session holds no authority
    // here (Clause D fail-closed).
    let r = alice.as_owner("GET", "/v1/families", None).await;
    assert_refused(&r, 403, "family.owner_session_required");
    let r = alice
        .as_owner("POST", &path, Some(json!({ "force_self": true })))
        .await;
    assert_refused(&r, 403, "self.owner_session_required");
}

#[tokio::test]
async fn only_the_owner_themself_may_release() {
    let alice = Person::new("rel-e").await;
    let n2 = second_node(&alice, 0xE4).await;
    let path = format!("/v1/self/nodes/{n2}/release");
    let r = alice.call("POST", &path, None, None).await;
    assert_refused(&r, 401, "self.owner_session_required");
    let guest = alice.stranger_session().await;
    let r = alice.call("POST", &path, Some(&guest), None).await;
    assert_refused(&r, 403, "self.owner_session_required");
    let delegated = alice.delegated_session().await;
    let r = alice.call("POST", &path, Some(&delegated), None).await;
    assert_refused(&r, 403, "self.delegate_may_not_author");
    assert!(owned(&alice).await.contains(&n2), "nothing was released");
}

// ─── Device labels and the occurrence list ──────────────────────────────────

/// Bind a registered device key to `p`'s self (the trusted-local door the
/// occurrence route's core uses).
async fn device(p: &Person, tag: u8) -> String {
    let key_id = format!("{}-phone-{tag}", p.owner.alias);
    let ed = SigningKey::from_bytes(&[tag; 32]);
    let pqc =
        MlDsa65SoftwareSigner::from_seed_bytes(&[tag.wrapping_add(1); 32], format!("{key_id}-pqc"))
            .expect("ML-DSA seed");
    let rec = user_record(
        &key_id,
        &BASE64.encode(ed.verifying_key().to_bytes()),
        &BASE64.encode(pqc.public_key().await.expect("pk")),
    );
    let dir = p.engine.federation_directory();
    dir.put_public_key(rec)
        .await
        .expect("register the device key");
    dir.put_identity_occurrence_local(IdentityOccurrence {
        identity_key_id: p.key().to_owned(),
        occurrence_key_id: key_id.clone(),
        device_class: "phone".to_owned(),
        hardware_attestation: None,
        asserted_at: chrono::Utc::now(),
        valid_until: None,
        encryption_pubkeys: None,
        transport_binding: None,
        persist_row_hash: String::new(),
    })
    .await
    .expect("bind the device");
    key_id
}

fn find<'a>(list: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    list["occurrences"]
        .as_array()?
        .iter()
        .find(|o| o["occurrence_key_id"] == key)
}

#[tokio::test]
async fn a_device_is_relabelled_and_only_its_owner_reads_the_label() {
    let alice = Person::new("lbl-a").await;
    let phone = device(&alice, 0xD0).await;

    let r = alice
        .as_owner(
            "POST",
            "/v1/self/occurrence/label",
            Some(json!({ "occurrence_key_id": phone, "label": "   " })),
        )
        .await;
    assert_refused(&r, 400, "self.label_empty");
    let r = alice
        .as_owner(
            "POST",
            "/v1/self/occurrence/label",
            Some(json!({ "occurrence_key_id": "not-my-phone", "label": "x" })),
        )
        .await;
    assert_refused(&r, 404, "self.not_your_device");
    let delegated = alice.delegated_session().await;
    let r = alice
        .call(
            "POST",
            "/v1/self/occurrence/label",
            Some(&delegated),
            Some(json!({ "occurrence_key_id": phone, "label": "x" })),
        )
        .await;
    assert_refused(&r, 403, "self.delegate_may_not_author");

    let (st, first) = alice
        .as_owner(
            "POST",
            "/v1/self/occurrence/label",
            Some(json!({ "occurrence_key_id": phone, "label": "Pixel" })),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{first}");
    assert!(
        first["supersedes"].is_null(),
        "the first label opens the leaf"
    );
    let (st, second) = alice
        .as_owner(
            "POST",
            "/v1/self/occurrence/label",
            Some(json!({ "occurrence_key_id": phone, "label": "Pixel 9" })),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{second}");
    assert_eq!(
        second["supersedes"], first["attestation_id"],
        "a relabel supersedes the previous head"
    );

    let list = format!("/v1/self/occurrences?identity_key_id={}", alice.key());
    let (st, v) = alice.as_owner("GET", &list, None).await;
    assert_eq!(st.as_u16(), 200, "{v}");
    let o = find(&v, &phone).expect("the phone is listed");
    assert_eq!(o["label"], "Pixel 9", "the newest label wins: {v}");
    assert_eq!(o["revoked"], false);
    // Unauthenticated: the phone is not an announced node, so it is not public
    // at all (CIRISServer#655).
    let (st, v) = alice.call("GET", &list, None, None).await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert!(find(&v, &phone).is_none(), "{v}");
    // This (announced) node IS public — and its label is not: the name a person
    // gave a device is never public, whatever the device.
    let node = provision_node_occurrence(&alice).await;
    let (st, v) = alice
        .as_owner(
            "POST",
            "/v1/self/occurrence/label",
            Some(json!({ "occurrence_key_id": node, "label": "Home server" })),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    let (_, v) = alice.as_owner("GET", &list, None).await;
    assert_eq!(find(&v, &node).expect("listed")["label"], "Home server");
    let (_, v) = alice.call("GET", &list, None, None).await;
    let o = find(&v, &node).expect("the announced node is public");
    assert!(
        o["label"].is_null(),
        "no label without the owner's session: {v}"
    );
}

#[tokio::test]
async fn the_occurrence_list_shows_revoked_devices_on_request() {
    let alice = Person::new("occ-a").await;
    let kept = device(&alice, 0xC0).await;
    let lost = device(&alice, 0xC4).await;
    // UNtruncated, as `POST /v1/self/occurrence/revoke` writes it: the fold
    // revokes only when `effective_at >= asserted_at`, and the device was bound
    // with a nanosecond `asserted_at` a moment ago — a millisecond-truncated
    // instant can land BEFORE it and revoke nothing.
    let now = chrono::Utc::now();
    alice
        .engine
        .federation_directory()
        .put_identity_occurrence_revocation_local(IdentityOccurrenceRevocation {
            identity_key_id: alice.key().to_owned(),
            occurrence_key_id: lost.clone(),
            revoked_at: now,
            effective_at: now,
            reason: Some("lost".into()),
            witness_set: vec![kept.clone()],
            persist_row_hash: String::new(),
        })
        .await
        .expect("revoke the lost phone");

    let base = format!("/v1/self/occurrences?identity_key_id={}", alice.key());
    let (_, v) = alice.as_owner("GET", &base, None).await;
    assert!(find(&v, &kept).is_some(), "{v}");
    assert!(
        find(&v, &lost).is_none(),
        "revoked devices are hidden by default: {v}"
    );

    let (_, v) = alice
        .as_owner("GET", &format!("{base}&include_revoked=true"), None)
        .await;
    assert_eq!(find(&v, &kept).expect("kept")["revoked"], false, "{v}");
    assert_eq!(find(&v, &lost).expect("lost")["revoked"], true, "{v}");
}

// ─── Who may read the roster (CIRISServer#655) ──────────────────────────────
//
// The maintainer's ruling (2026-09-25): the roster is public — people must be
// contactable — but not EXPOSED. Announce is PER NODE (each node's wizard asks),
// and the public roster is exactly the devices the person chose to announce,
// that people can contact them through. A stranger sees only occurrences that
// ARE announced nodes; an owner with none announced is indistinguishable from
// an identity nobody has heard of. The owner's own session sees everything.

/// Widen `p`'s owner-binding on THIS node to federation — what `POST
/// /v1/federation/announce` does, with the owner's own pen.
async fn announce(p: &Person) {
    ciris_server::auth::ownership::promote_owner_binding_to_federation(
        &p.engine,
        &p.owner.signer().await,
        &p.node_key_id,
    )
    .await
    .expect("promote the owner-binding to federation");
}

/// This node's own occurrence of `p`'s self (its content occurrence, which
/// edge provisions under the engine key). Returns the occurrence key — THIS
/// node's key.
async fn provision_node_occurrence(p: &Person) -> String {
    let (occ, _how) = ciris_server::backend::provision_engine_occurrence(&p.engine, p.key())
        .await
        .expect("provision the node's content occurrence");
    assert_eq!(
        occ, p.node_key_id,
        "precondition: the occurrence IS this node"
    );
    occ
}

/// A second machine `p` owns that `p` did NOT announce: a registered node key,
/// a SELF-scoped owner-binding, and an occurrence of `p`'s self under it.
async fn unannounced_second_node(p: &Person, tag: u8) -> String {
    let key_id = format!("quiet-node-{tag}");
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
    .expect("register the quiet node");
    owned_node::bind_self_scoped(&p.engine, &p.owner.signer().await, &key_id).await;
    p.engine
        .federation_directory()
        .put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: p.key().to_owned(),
            occurrence_key_id: key_id.clone(),
            device_class: "server".to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("bind the quiet node as an occurrence");
    assert!(owned(p).await.contains(&key_id), "precondition: owned");
    key_id
}

fn listed(v: &serde_json::Value) -> Vec<String> {
    v["occurrences"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|o| o["occurrence_key_id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn an_unannounced_roster_is_the_owners_alone() {
    let alice = Person::new_unannounced("occ-priv").await;
    let phone = device(&alice, 0xA0).await;
    let node_occ = provision_node_occurrence(&alice).await;
    let path = format!("/v1/self/occurrences?identity_key_id={}", alice.key());

    // The owner sees everything, labelled as the owner's view.
    let (st, v) = alice.as_owner("GET", &path, None).await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(v["audience"], "owner", "{v}");
    let mine = listed(&v);
    assert!(mine.contains(&phone) && mine.contains(&node_occ), "{v}");

    // No session, a stranger's session: nothing — not even this node, because
    // Alice did not announce it.
    let (st, anon) = alice.call("GET", &path, None, None).await;
    assert_eq!(st.as_u16(), 200, "{anon}");
    assert!(listed(&anon).is_empty(), "{anon}");
    let guest = alice.stranger_session().await;
    let (_, v) = alice.call("GET", &path, Some(&guest), None).await;
    assert!(listed(&v).is_empty(), "{v}");
    let (_, v) = alice
        .call("GET", &format!("{path}&include_revoked=true"), None, None)
        .await;
    assert!(listed(&v).is_empty(), "include_revoked widens nothing: {v}");

    // THE SAME ANSWER as for an identity nobody has heard of — the read does
    // not reveal that Alice exists.
    let (st, unknown) = alice
        .call(
            "GET",
            "/v1/self/occurrences?identity_key_id=nobody-v1-aaaaaaaaaa",
            None,
            None,
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{unknown}");
    let strip = |mut v: serde_json::Value| {
        v.as_object_mut().expect("object").remove("identity_key_id");
        v
    };
    assert_eq!(strip(anon), strip(unknown));

    // Announcing THIS node makes exactly this node public.
    announce(&alice).await;
    let (_, v) = alice.call("GET", &path, None, None).await;
    assert_eq!(listed(&v), vec![node_occ], "{v}");
}

/// The mixed case: node A announced, node B not. A stranger sees A's
/// occurrence and never B's — nor the phone, which is no node at all.
#[tokio::test]
async fn only_the_announced_nodes_are_public() {
    let alice = Person::new("occ-mixed").await; // node A: announced
    let phone = device(&alice, 0xA4).await;
    let node_a = provision_node_occurrence(&alice).await;
    let node_b = unannounced_second_node(&alice, 0xB6).await;
    let path = format!("/v1/self/occurrences?identity_key_id={}", alice.key());

    let (st, v) = alice.call("GET", &path, None, None).await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(v["audience"], "public", "{v}");
    assert_eq!(
        listed(&v),
        vec![node_a.clone()],
        "only the announced node: {v}"
    );
    let (_, v) = alice
        .call("GET", &format!("{path}&include_revoked=true"), None, None)
        .await;
    assert_eq!(listed(&v), vec![node_a.clone()], "{v}");

    // The owner still sees all three.
    let (_, v) = alice.as_owner("GET", &path, None).await;
    let mine = listed(&v);
    for k in [&phone, &node_a, &node_b] {
        assert!(mine.contains(k), "{k} missing from the owner's view: {v}");
    }
}
