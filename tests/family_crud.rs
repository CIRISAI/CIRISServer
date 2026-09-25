//! **Households, end to end over the real router** (CIRISServer#627,
//! `FSD/ROSTER_AND_DRIVE_CRUD.md` §3).
//!
//! Every person is a whole node ([`owned_node::Person`]): their own substrate,
//! their own minted fed-ID, their own owner session. A family row reaches
//! another person's node the way replication carries it — the SIGNED row,
//! re-admitted through persist's own door — so a member acting on their own
//! node is acting on what their node actually holds.
//!
//! What is pinned here, per FSD §6:
//! - every route's happy path, and every refusal id the surface emits;
//! - the policy matrix: founder / member / outsider / delegate (and no session,
//!   and a session that is not the owner's);
//! - `founder_only` in single calls, and a `quorum:2/3` family through
//!   envelope → cosign (on each member's OWN node) → assemble;
//! - leave (and that a departure written on the leaver's node reaches the
//!   founder's), the last-founder rule, dissolve, and that a non-member cannot
//!   even learn the family exists.

#[path = "support/owned_node.rs"]
mod owned_node;

use owned_node::{assert_refused, Person};
use serde_json::json;

fn members(v: &serde_json::Value) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = v["members"]
        .as_array()
        .unwrap_or_else(|| panic!("no members in {v}"))
        .iter()
        .map(|m| {
            (
                m["key_id"].as_str().expect("key_id").to_owned(),
                m["role"].as_str().expect("role").to_owned(),
            )
        })
        .collect();
    out.sort();
    out
}

fn sorted(mut v: Vec<(String, String)>) -> Vec<(String, String)> {
    v.sort();
    v
}

fn pair(p: &Person, role: &str) -> (String, String) {
    (p.key().to_owned(), role.to_owned())
}

/// Everyone registers everyone's key, as Key rounds would.
async fn acquainted(people: &[&Person]) {
    for a in people {
        for b in people {
            if a.key() != b.key() {
                a.knows(b).await;
            }
        }
    }
}

async fn create(p: &Person, body: serde_json::Value) -> String {
    let (st, v) = p.as_owner("POST", "/v1/families", Some(body)).await;
    assert_eq!(st.as_u16(), 201, "create: {v}");
    v["family_id"].as_str().expect("family_id").to_owned()
}

// ─── founder_only: the one-call household ───────────────────────────────────

#[tokio::test]
async fn a_founder_only_household_through_its_whole_life() {
    let alice = Person::new("alice").await;
    let bob = Person::new("bob").await;
    let carol = Person::new("carol").await;
    acquainted(&[&alice, &bob, &carol]).await;

    // ── create: the caller is the founder, founder_only is the default ──────
    let (st, v) = alice
        .as_owner(
            "POST",
            "/v1/families",
            Some(json!({ "name": "  Moore household " })),
        )
        .await;
    assert_eq!(st.as_u16(), 201, "{v}");
    let id = v["family_id"].as_str().expect("id").to_owned();
    assert!(id.starts_with("family:v1:"), "{id}");
    assert_eq!(v["name"], "Moore household");
    assert_eq!(v["consensus_protocol"], "founder_only");
    assert_eq!(members(&v), vec![pair(&alice, "founder")]);
    assert_eq!(v["my_role"], "founder");
    // The row's envelope: the human signed it, at family audience.
    assert_eq!(v["envelope"]["attester"], alice.key());
    assert_eq!(v["envelope"]["cohort_scope"], "family");
    assert_eq!(v["envelope"]["subject"], id.as_str());
    // … and it is on persist's SIGNED (replicable) read surface.
    let signed = alice
        .engine
        .federation_directory()
        .list_signed_families_since(None, u32::MAX)
        .await
        .expect("signed families");
    let row = signed
        .iter()
        .find(|s| s.family.family.family_key_id == id)
        .expect("the household is served on the signed surface — put_family, not put_family_local");
    assert_eq!(row.family.authority_key_id, alice.key());

    // ── create refusals ─────────────────────────────────────────────────────
    let r = alice
        .as_owner("POST", "/v1/families", Some(json!({ "name": "   " })))
        .await;
    assert_refused(&r, 400, "family.name_empty");
    let r = alice
        .as_owner(
            "POST",
            "/v1/families",
            Some(json!({ "name": "x", "consensus_protocol": "quorum:2/3" })),
        )
        .await;
    assert_refused(&r, 400, "family.bad_consensus_protocol");
    let r = alice
        .as_owner(
            "POST",
            "/v1/families",
            Some(json!({ "name": "x", "consensus_protocol": "weighted:rubric" })),
        )
        .await;
    assert_refused(&r, 400, "family.bad_consensus_protocol");
    let r = alice
        .as_owner(
            "POST",
            "/v1/families",
            Some(json!({ "name": "x", "members": ["nobody-registered-this"] })),
        )
        .await;
    assert_refused(&r, 400, "family.unknown_member_key");
    let r = alice
        .as_owner(
            "POST",
            "/v1/families",
            Some(json!({ "name": "x", "members": [alice.key()] })),
        )
        .await;
    assert_refused(&r, 409, "family.already_member");
    let r = alice
        .as_owner("POST", "/v1/families", Some(json!({ "nom": "x" })))
        .await;
    assert_refused(&r, 400, "family.bad_request");

    // ── list + read ─────────────────────────────────────────────────────────
    let (st, v) = alice.as_owner("GET", "/v1/families", None).await;
    assert_eq!(st.as_u16(), 200, "{v}");
    let fams = v["families"].as_array().expect("families");
    assert_eq!(fams.len(), 1, "{v}");
    assert_eq!(fams[0]["family_id"], id.as_str());
    assert!(fams[0]["envelope"]["attester"].is_string());
    assert!(v["resume"].is_null());
    let (st, v) = alice
        .as_owner("GET", &format!("/v1/families/{id}"), None)
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    let r = alice
        .as_owner("GET", "/v1/families/family:v1:does-not-exist", None)
        .await;
    assert_refused(&r, 404, "family.not_found");

    // ── add ─────────────────────────────────────────────────────────────────
    let r = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/members"),
            Some(json!({ "key_id": "nobody-registered-this" })),
        )
        .await;
    assert_refused(&r, 400, "family.unknown_member_key");
    let r = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/members"),
            Some(json!({ "key_id": bob.key(), "role": "" })),
        )
        .await;
    assert_refused(&r, 400, "family.bad_role");
    let (st, v) = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/members"),
            Some(json!({ "key_id": bob.key() })),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(
        members(&v),
        sorted(vec![pair(&alice, "founder"), pair(&bob, "member")])
    );
    assert!(
        v["dek_rewrap"].is_object() && v["dek_rewrap"].get("error").is_none(),
        "the DEK cascade ran for the newcomer: {v}"
    );
    let r = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/members"),
            Some(json!({ "key_id": bob.key() })),
        )
        .await;
    assert_refused(&r, 409, "family.already_member");

    // ── Bob's node receives the household; Bob is a MEMBER there ────────────
    bob.receive_families_from(&alice).await;
    let (st, v) = bob
        .as_owner("GET", &format!("/v1/families/{id}"), None)
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(v["my_role"], "member");
    let (_, v) = bob.as_owner("GET", "/v1/families", None).await;
    assert_eq!(v["families"].as_array().map(Vec::len), Some(1), "{v}");

    // ── the policy matrix: a MEMBER may not govern a founder_only family ────
    let r = bob
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/members"),
            Some(json!({ "key_id": carol.key() })),
        )
        .await;
    assert_refused(&r, 403, "family.not_authorized");
    let r = bob
        .as_owner(
            "DELETE",
            &format!("/v1/families/{id}/members/{}", alice.key()),
            None,
        )
        .await;
    assert_refused(&r, 403, "family.not_authorized");
    let r = bob
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/members/{}/role", bob.key()),
            Some(json!({ "role": "founder" })),
        )
        .await;
    assert_refused(&r, 403, "family.not_authorized");
    let r = bob
        .as_owner("DELETE", &format!("/v1/families/{id}"), None)
        .await;
    assert_refused(&r, 403, "family.not_authorized");

    // ── an OUTSIDER holding the row cannot find out it exists ───────────────
    carol.receive_families_from(&alice).await;
    assert!(
        carol
            .engine
            .federation_directory()
            .lookup_family(&id)
            .await
            .expect("lookup")
            .is_some(),
        "precondition: Carol's node HOLDS the family row"
    );
    for (method, path, body) in [
        ("GET", format!("/v1/families/{id}"), None),
        (
            "POST",
            format!("/v1/families/{id}/members"),
            Some(json!({ "key_id": carol.key() })),
        ),
        ("POST", format!("/v1/families/{id}/leave"), None),
        ("DELETE", format!("/v1/families/{id}"), None),
        (
            "POST",
            format!("/v1/families/{id}/members/{}/role", alice.key()),
            Some(json!({ "role": "member" })),
        ),
    ] {
        let r = carol.as_owner(method, &path, body).await;
        assert_refused(&r, 404, "family.not_found");
    }
    let (_, v) = carol.as_owner("GET", "/v1/families", None).await;
    assert_eq!(v["families"].as_array().map(Vec::len), Some(0), "{v}");

    // ── a DELEGATE may read, never author; no session / a guest: refused ────
    let delegated = alice.delegated_session().await;
    let r = alice
        .call(
            "POST",
            &format!("/v1/families/{id}/members"),
            Some(&delegated),
            Some(json!({ "key_id": carol.key() })),
        )
        .await;
    assert_refused(&r, 403, "family.delegate_may_not_author");
    let (st, v) = alice
        .call("GET", &format!("/v1/families/{id}"), Some(&delegated), None)
        .await;
    assert_eq!(st.as_u16(), 200, "a delegate reads: {v}");
    let r = alice.call("GET", "/v1/families", None, None).await;
    assert_refused(&r, 401, "family.owner_session_required");
    let guest = alice.stranger_session().await;
    let r = alice.call("GET", "/v1/families", Some(&guest), None).await;
    assert_refused(&r, 403, "family.owner_session_required");

    // ── the LAST FOUNDER may not leave, be removed, or step down ────────────
    let r = alice
        .as_owner("POST", &format!("/v1/families/{id}/leave"), None)
        .await;
    assert_refused(&r, 409, "family.last_founder");
    let r = alice
        .as_owner(
            "DELETE",
            &format!("/v1/families/{id}/members/{}", alice.key()),
            None,
        )
        .await;
    assert_refused(&r, 409, "family.last_founder");
    let r = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/members/{}/role", alice.key()),
            Some(json!({ "role": "member" })),
        )
        .await;
    assert_refused(&r, 409, "family.last_founder");

    // ── change role ─────────────────────────────────────────────────────────
    let r = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/members/{}/role", carol.key()),
            Some(json!({ "role": "member" })),
        )
        .await;
    assert_refused(&r, 404, "family.not_a_member");
    let r = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/members/{}/role", bob.key()),
            Some(json!({ "role": "" })),
        )
        .await;
    assert_refused(&r, 400, "family.bad_role");
    let (st, v) = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/members/{}/role", bob.key()),
            Some(json!({ "role": "guardian" })),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(
        members(&v),
        sorted(vec![pair(&alice, "founder"), pair(&bob, "guardian")])
    );

    // ── remove, and a removal is permanent at this pin ──────────────────────
    let (st, v) = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/members"),
            Some(json!({ "key_id": carol.key() })),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    let (st, v) = alice
        .as_owner(
            "DELETE",
            &format!("/v1/families/{id}/members/{}", carol.key()),
            None,
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(v["removed"], carol.key());
    assert!(
        !members(&v).iter().any(|(k, _)| k == carol.key()),
        "the removed member is out of the FOLD: {v}"
    );
    let r = alice
        .as_owner(
            "DELETE",
            &format!("/v1/families/{id}/members/{}", carol.key()),
            None,
        )
        .await;
    assert_refused(&r, 404, "family.not_a_member");
    let r = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/members"),
            Some(json!({ "key_id": carol.key() })),
        )
        .await;
    assert_refused(&r, 409, "family.readd_unsupported");

    // ── Bob LEAVES on his own node; the departure reaches Alice's ───────────
    let (st, v) = bob
        .as_owner("POST", &format!("/v1/families/{id}/leave"), None)
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(v["left"], true);
    let r = bob
        .as_owner("GET", &format!("/v1/families/{id}"), None)
        .await;
    assert_refused(&r, 404, "family.not_found");
    alice.receive_families_from(&bob).await;
    let (_, v) = alice
        .as_owner("GET", &format!("/v1/families/{id}"), None)
        .await;
    assert_eq!(
        members(&v),
        vec![pair(&alice, "founder")],
        "Bob's signed departure, carried from his node, is in Alice's fold: {v}"
    );

    // ── the envelope flow is for quorum families only ───────────────────────
    let r = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/changes/envelope"),
            Some(json!({ "action": "dissolve" })),
        )
        .await;
    assert_refused(&r, 400, "family.bad_consensus_protocol");

    // ── dissolve ────────────────────────────────────────────────────────────
    let (st, v) = alice
        .as_owner("DELETE", &format!("/v1/families/{id}"), None)
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(v["dissolved"], true);
    let r = alice
        .as_owner("GET", &format!("/v1/families/{id}"), None)
        .await;
    assert_refused(&r, 404, "family.not_found");
    let (_, v) = alice.as_owner("GET", "/v1/families", None).await;
    assert_eq!(v["families"].as_array().map(Vec::len), Some(0), "{v}");
    let record = alice
        .engine
        .federation_directory()
        .lookup_family(&id)
        .await
        .expect("lookup")
        .expect("the dissolved record stays, as history");
    assert!(
        record.members.is_empty(),
        "terminal supersede to an empty roster"
    );
}

/// The sole member of a household may simply leave it — the last-founder rule
/// protects OTHER members from a founderless family, and there are none.
#[tokio::test]
async fn the_only_member_may_leave() {
    let alice = Person::new("solo").await;
    let id = create(&alice, json!({ "name": "just me" })).await;
    let (st, v) = alice
        .as_owner("POST", &format!("/v1/families/{id}/leave"), None)
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    let r = alice
        .as_owner("GET", &format!("/v1/families/{id}"), None)
        .await;
    assert_refused(&r, 404, "family.not_found");
}

/// A second founder frees the first to go.
#[tokio::test]
async fn a_founder_may_leave_once_another_founder_remains() {
    let alice = Person::new("fa").await;
    let bob = Person::new("fb").await;
    acquainted(&[&alice, &bob]).await;
    let id = create(&alice, json!({ "name": "two founders" })).await;
    let (st, v) = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/members"),
            Some(json!({ "key_id": bob.key(), "role": "founder" })),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    let (st, v) = alice
        .as_owner("POST", &format!("/v1/families/{id}/leave"), None)
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    bob.receive_families_from(&alice).await;
    let (st, v) = bob
        .as_owner("GET", &format!("/v1/families/{id}"), None)
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(members(&v), vec![pair(&bob, "founder")]);
}

/// Pagination: `limit` + `resume` walk the caller's families in id order.
#[tokio::test]
async fn the_family_list_pages() {
    let alice = Person::new("pager").await;
    for n in 0..3 {
        create(&alice, json!({ "name": format!("f{n}") })).await;
    }
    let (_, first) = alice.as_owner("GET", "/v1/families?limit=2", None).await;
    assert_eq!(
        first["families"].as_array().map(Vec::len),
        Some(2),
        "{first}"
    );
    let resume = first["resume"]
        .as_str()
        .expect("a resume cursor")
        .to_owned();
    let (_, rest) = alice
        .as_owner("GET", &format!("/v1/families?limit=2&after={resume}"), None)
        .await;
    assert_eq!(rest["families"].as_array().map(Vec::len), Some(1), "{rest}");
    assert!(rest["resume"].is_null());
}

// ─── quorum:2/3 — envelope → cosign → assemble ──────────────────────────────

/// A `quorum:2/3` household of Alice (founder), Bob and Carol, held by all
/// three nodes.
async fn quorum_family(alice: &Person, bob: &Person, carol: &Person) -> String {
    let id = create(
        alice,
        json!({
            "name": "the trio",
            "members": [bob.key(), carol.key()],
            "consensus_protocol": "quorum:2/3",
        }),
    )
    .await;
    bob.receive_families_from(alice).await;
    carol.receive_families_from(alice).await;
    id
}

async fn envelope(p: &Person, id: &str, body: serde_json::Value) -> serde_json::Value {
    let (st, v) = p
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/changes/envelope"),
            Some(body),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "envelope: {v}");
    v["change_envelope"].clone()
}

async fn cosign(
    p: &Person,
    id: &str,
    env: &serde_json::Value,
    sigs: &serde_json::Value,
) -> serde_json::Value {
    let (st, v) = p
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/changes/cosign"),
            Some(json!({ "change_envelope": env, "signatures": sigs })),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "cosign by {}: {v}", p.name);
    v
}

async fn assemble(
    p: &Person,
    id: &str,
    env: &serde_json::Value,
    sigs: &serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    p.as_owner(
        "POST",
        &format!("/v1/families/{id}/changes/assemble"),
        Some(json!({ "change_envelope": env, "signatures": sigs })),
    )
    .await
}

#[tokio::test]
async fn a_quorum_family_adds_through_envelope_cosign_assemble() {
    let alice = Person::new("qa").await;
    let bob = Person::new("qb").await;
    let carol = Person::new("qc").await;
    let dave = Person::new("qd").await;
    acquainted(&[&alice, &bob, &carol, &dave]).await;
    let id = quorum_family(&alice, &bob, &carol).await;

    // One call is not enough for a quorum family — it says where to go.
    let r = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/members"),
            Some(json!({ "key_id": dave.key() })),
        )
        .await;
    assert_refused(&r, 409, "family.quorum_pending");
    let r = alice
        .as_owner("DELETE", &format!("/v1/families/{id}"), None)
        .await;
    assert_refused(&r, 409, "family.quorum_pending");

    // Envelope refusals.
    let r = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/changes/envelope"),
            Some(json!({ "action": "add", "key_id": bob.key() })),
        )
        .await;
    assert_refused(&r, 409, "family.already_member");
    let r = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/changes/envelope"),
            Some(json!({ "action": "add", "key_id": dave.key(), "consensus_protocol": "quorum:2/4" })),
        )
        .await;
    assert_refused(&r, 400, "family.bad_consensus_protocol");
    let r = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/changes/envelope"),
            Some(json!({ "action": "sell" })),
        )
        .await;
    assert_refused(&r, 400, "family.bad_request");

    // ── the envelope, built by the founder ──────────────────────────────────
    let env = envelope(
        &alice,
        &id,
        json!({ "action": "add", "key_id": dave.key() }),
    )
    .await;
    assert_eq!(
        env["consensus_protocol"], "quorum:3/4",
        "N follows the roster"
    );

    // ── Alice cosigns on HER node: 1 of 2, not yet met ──────────────────────
    let v = cosign(&alice, &id, &env, &json!([])).await;
    assert_eq!(v["required_signatures"], 2);
    assert_eq!(v["quorum_met"], false);
    let one = v["signatures"].clone();
    let r = assemble(&alice, &id, &env, &one).await;
    assert_refused(&r, 409, "family.quorum_pending");

    // ── an OUTSIDER cannot cosign — they cannot see the family at all ───────
    dave.receive_families_from(&alice).await;
    let r = dave
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/changes/cosign"),
            Some(json!({ "change_envelope": env, "signatures": one })),
        )
        .await;
    assert_refused(&r, 404, "family.not_found");

    // ── … and an outsider's signature does not count toward the quorum ──────
    let dave_sig = {
        let bytes = ciris_verify_core::jcs::canonicalize(&env).expect("jcs");
        let s = dave.owner.signer().await;
        let sig = s.sign_hybrid(&bytes).await.expect("sign");
        use base64::Engine as _;
        let b = base64::engine::general_purpose::STANDARD;
        json!({
            "member_id": dave.key(),
            "ed25519_signature_base64": b.encode(&sig.classical.signature),
            "mldsa65_signature_base64": b.encode(&sig.pqc.signature),
        })
    };
    let mut with_outsider = one.as_array().expect("sigs").clone();
    with_outsider.push(dave_sig);
    let (st, v) = assemble(&alice, &id, &env, &json!(with_outsider)).await;
    assert!(
        matches!(st.as_u16(), 403 | 409),
        "an outsider's signature must not complete the quorum: {st} {v}"
    );
    assert!(
        matches!(
            v["reason_id"].as_str(),
            Some("family.quorum_pending" | "family.not_authorized")
        ),
        "{v}"
    );

    // ── Bob cosigns on HIS node, adding to Alice's: 2 of 2, met ─────────────
    let v = cosign(&bob, &id, &env, &one).await;
    assert_eq!(v["quorum_met"], true, "{v}");
    let two = v["signatures"].clone();

    // ── any member assembles ────────────────────────────────────────────────
    let (st, v) = assemble(&alice, &id, &env, &two).await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(v["action"], "add");
    assert_eq!(v["consensus_protocol"], "quorum:3/4");
    assert_eq!(
        members(&v),
        sorted(vec![
            pair(&alice, "founder"),
            pair(&bob, "member"),
            pair(&carol, "member"),
            pair(&dave, "member"),
        ])
    );
    assert!(v["dek_rewrap"].is_object(), "{v}");

    // ── the same envelope cannot be applied twice (the record moved) ────────
    let r = assemble(&alice, &id, &env, &two).await;
    assert_refused(&r, 409, "family.bad_change");
    // … and a cosign against a node still holding the OLD record is refused
    // by name rather than signed: Bob's node never received the supersede
    // (FSD §3.5 — a grown family record does not replicate at this pin).
    let r = bob
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/changes/cosign"),
            Some(json!({ "change_envelope": envelope(&alice, &id, json!({ "action": "dissolve" })).await })),
        )
        .await;
    assert_refused(&r, 409, "family.bad_change");
}

#[tokio::test]
async fn a_quorum_family_removes_changes_a_role_and_lets_a_member_leave() {
    let alice = Person::new("ra").await;
    let bob = Person::new("rb").await;
    let carol = Person::new("rc").await;
    acquainted(&[&alice, &bob, &carol]).await;

    // ── remove Carol with Alice + Bob ───────────────────────────────────────
    let id = quorum_family(&alice, &bob, &carol).await;
    let r = alice
        .as_owner(
            "POST",
            &format!("/v1/families/{id}/changes/envelope"),
            Some(json!({ "action": "remove", "key_id": alice.key() })),
        )
        .await;
    assert_refused(&r, 409, "family.last_founder");
    let env = envelope(
        &alice,
        &id,
        json!({ "action": "remove", "key_id": carol.key() }),
    )
    .await;
    assert_eq!(env["consensus_protocol"], "quorum:2/2");
    let a = cosign(&alice, &id, &env, &json!([])).await;
    let ab = cosign(&bob, &id, &env, &a["signatures"]).await;
    let (st, v) = assemble(&bob, &id, &env, &ab["signatures"]).await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(v["removed"], carol.key());
    // Bob assembled on BOB's node; the removal row crosses to Carol's.
    carol.receive_families_from(&bob).await;
    let r = carol
        .as_owner("GET", &format!("/v1/families/{id}"), None)
        .await;
    assert_refused(&r, 404, "family.not_found");

    // ── a role change with Alice + Carol, on a fresh family ────────────────
    let id = quorum_family(&alice, &bob, &carol).await;
    let env = envelope(
        &alice,
        &id,
        json!({ "action": "role", "key_id": bob.key(), "role": "founder" }),
    )
    .await;
    let a = cosign(&alice, &id, &env, &json!([])).await;
    let ac = cosign(&carol, &id, &env, &a["signatures"]).await;
    let (st, v) = assemble(&alice, &id, &env, &ac["signatures"]).await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(
        v["consensus_protocol"], "quorum:2/3",
        "same roster, same rule"
    );
    assert_eq!(
        members(&v),
        sorted(vec![
            pair(&alice, "founder"),
            pair(&bob, "founder"),
            pair(&carol, "member"),
        ])
    );

    // ── leaving needs no quorum, and keeps N matching the roster ────────────
    let (st, v) = carol
        .as_owner("POST", &format!("/v1/families/{id}/leave"), None)
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    alice.receive_families_from(&carol).await;
    let (_, v) = alice
        .as_owner("GET", &format!("/v1/families/{id}"), None)
        .await;
    assert!(
        !members(&v).iter().any(|(k, _)| k == carol.key()),
        "Carol's departure crossed: {v}"
    );
}

#[tokio::test]
async fn a_quorum_family_dissolves_only_with_its_quorum() {
    let alice = Person::new("da").await;
    let bob = Person::new("db").await;
    let carol = Person::new("dc").await;
    acquainted(&[&alice, &bob, &carol]).await;
    let id = quorum_family(&alice, &bob, &carol).await;

    let env = envelope(&alice, &id, json!({ "action": "dissolve" })).await;
    let a = cosign(&alice, &id, &env, &json!([])).await;
    let r = assemble(&alice, &id, &env, &a["signatures"]).await;
    assert_refused(&r, 409, "family.quorum_pending");
    let ac = cosign(&carol, &id, &env, &a["signatures"]).await;
    assert_eq!(ac["quorum_met"], true);
    let (st, v) = assemble(&alice, &id, &env, &ac["signatures"]).await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(v["dissolved"], true);
    let r = alice
        .as_owner("GET", &format!("/v1/families/{id}"), None)
        .await;
    assert_refused(&r, 404, "family.not_found");
    // The removals replicate: Bob's node learns the family is gone for him too.
    bob.receive_families_from(&alice).await;
    let r = bob
        .as_owner("GET", &format!("/v1/families/{id}"), None)
        .await;
    assert_refused(&r, 404, "family.not_found");
}

/// `majority` / `unanimous` are accepted as aliases and stored in the one form
/// verify's membership-change gate counts.
#[tokio::test]
async fn declared_majority_and_unanimous_are_stored_as_quorum() {
    let alice = Person::new("ma").await;
    let bob = Person::new("mb").await;
    let carol = Person::new("mc").await;
    acquainted(&[&alice, &bob, &carol]).await;
    for (declared, stored) in [("majority", "quorum:2/3"), ("unanimous", "quorum:3/3")] {
        let (st, v) = alice
            .as_owner(
                "POST",
                "/v1/families",
                Some(json!({
                    "name": declared,
                    "members": [bob.key(), carol.key()],
                    "consensus_protocol": declared,
                })),
            )
            .await;
        assert_eq!(st.as_u16(), 201, "{v}");
        assert_eq!(v["consensus_protocol"], stored);
    }
}
