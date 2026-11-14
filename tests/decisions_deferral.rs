//! **An agent's deferral is on its owner's decisions queue** (0.5.247; Eric
//! 2026-11-13). The seated Wise Authority on a node is its owner, so a
//! `deferral:request:v1` the node's agent signed lists as a `deferral`
//! decision on `GET /v1/self/decisions`, and answering it signs
//! `deferral:response:{approved|rejected}:v1` with the owner's own pen. Before
//! 0.5.247 the queue listed only seat approvals, and the owner's client had to
//! find a deferral in the room.

#[path = "support/owned_node.rs"]
mod owned_node;

use ciris_server::agent_deferral::{
    deferral_rows, dimension_of, emit_deferral_request, DeferralRequest, DEFERRAL_APPROVED,
};
use owned_node::Person;
use serde_json::json;
use std::sync::Arc;

/// The decisions routes (merged into the chat router) over `p`'s node. The
/// edge signer is not exercised by the decisions doors; a throwaway software
/// key under the node's id stands in, as in `contact_flow.rs`.
fn decisions_router(p: &Person) -> axum::Router {
    let classical: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(
        ciris_keyring::Ed25519SoftwareSigner::from_bytes(&[0x6A; 32], "decisions-edge")
            .expect("edge classical"),
    );
    let pqc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(
        ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(
            &[0x6B; 32],
            "decisions-edge-pqc".to_string(),
        )
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
}

async fn as_owner(
    p: &Person,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> (axum::http::StatusCode, serde_json::Value) {
    p.call_on(
        decisions_router(p),
        method,
        path,
        Some(&p.bearer.clone()),
        body,
    )
    .await
}

const DIGEST: &str = "a3f1c2d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9a";

fn deferrals(v: &serde_json::Value) -> Vec<serde_json::Value> {
    v["decisions"]
        .as_array()
        .expect("decisions")
        .iter()
        .filter(|d| d["kind"] == "deferral")
        .cloned()
        .collect()
}

#[tokio::test]
async fn the_owner_answers_their_agents_deferral_from_the_decisions_queue() {
    let alice = Person::new("defer-q").await;
    let room = "chat:room:v1:00000000000000000000000000000d3f";
    let req = DeferralRequest {
        deferral_id: "def-q1".into(),
        task_id: "task-q1".into(),
        thought_id: "thought-q1".into(),
        reason_digest: DIGEST.into(),
        domain_hint: Some("legal".into()),
        room_id: Some(room.into()),
    };
    let request_id = emit_deferral_request(&alice.engine, &alice.node_key_id, &req)
        .await
        .expect("the agent defers");

    // On the owner's queue, with the hint and the room.
    let (s, v) = as_owner(&alice, "GET", "/v1/self/decisions", None).await;
    assert_eq!(s.as_u16(), 200, "{v}");
    let open = deferrals(&v);
    assert_eq!(open.len(), 1, "{v}");
    let d = &open[0];
    assert_eq!(d["decision_id"], format!("deferral:{request_id}"));
    assert_eq!(d["domain_hint"], "legal");
    assert_eq!(d["circle"], room);
    assert_eq!(d["deferral_id"], "def-q1");
    // The circle filter keeps it in its room.
    let (_, v) = as_owner(
        &alice,
        "GET",
        &format!("/v1/self/decisions?circle={room}"),
        None,
    )
    .await;
    assert_eq!(deferrals(&v).len(), 1, "{v}");
    let (_, v) = as_owner(
        &alice,
        "GET",
        "/v1/self/decisions?circle=chat:room:v1:elsewhere",
        None,
    )
    .await;
    assert!(deferrals(&v).is_empty(), "{v}");

    // The owner approves: a response row, signed by the owner, citing it.
    let did = d["decision_id"].as_str().expect("id").to_owned();
    let (s, v) = as_owner(
        &alice,
        "POST",
        &format!("/v1/self/decisions/{did}/answer"),
        Some(json!({ "answer": "approve" })),
    )
    .await;
    assert_eq!(
        (s.as_u16(), v["state"].as_str()),
        (200, Some("applied")),
        "{v}"
    );
    let response_id = v["response_attestation_id"]
        .as_str()
        .expect("response id")
        .to_owned();
    let rows = deferral_rows(&alice.engine, &[response_id])
        .await
        .expect("read back");
    let resp = rows[0].as_ref().expect("the response is admitted");
    assert_eq!(dimension_of(resp), Some(DEFERRAL_APPROVED));
    assert_eq!(resp.attesting_key_id, alice.key(), "signed by the owner");

    // Answered: off the queue, and a second answer finds nothing open.
    let (_, v) = as_owner(&alice, "GET", "/v1/self/decisions", None).await;
    assert!(deferrals(&v).is_empty(), "{v}");
    let (s, v) = as_owner(
        &alice,
        "POST",
        &format!("/v1/self/decisions/{did}/answer"),
        Some(json!({ "answer": "decline" })),
    )
    .await;
    assert_eq!(
        (s.as_u16(), v["reason_id"].as_str()),
        (404, Some("decisions.not_found")),
        "{v}"
    );
}
