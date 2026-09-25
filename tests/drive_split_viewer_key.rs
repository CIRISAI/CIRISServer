//! **A split node opens its own files** (`FSD/ROSTER_AND_DRIVE_CRUD.md` §5,
//! CIRISServer 0.5.216).
//!
//! On an actor/node SPLIT install (CC 3.4.7.3 Clause A,
//! `FSD/ACTOR_NODE_KEY_SPLIT.md`) compose mints a NODE key, moves the
//! owner-binding onto it and registers it as the process's wire identity, while
//! `engine.local_derived_key_id()` keeps answering the ACTOR key. The content-KEM
//! occurrence is provisioned under the key the binding names — the wire node key
//! (`backend::provision_with`) — so every seal's grant is wrapped to THAT id.
//!
//! The drive opened files as `engine.local_derived_key_id()`. On a split node
//! that is a key no grant was ever wrapped to, so every file the node wrote read
//! `not_granted` on the node that wrote it. Both sides now ask one function,
//! `backend::content_occurrence_key_id`.
//!
//! Its own binary because the wire identity is a process-global `OnceLock`: a
//! single-identity test sharing this process would silently run split-shaped.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_persist::federation::types::identity_type;
use ciris_persist::wa_cert::WaRole;

#[allow(dead_code)] // one fixture, two binaries: each uses a different subset
mod support {
    include!("support/drive_fixture.rs");
}
use support::*;

#[tokio::test]
async fn a_split_node_opens_the_files_it_wrote() {
    init_tracing();
    let engine = node_engine().await;
    let actor_key = register_self(&engine).await;

    // THE SPLIT: a separate node key, registered as a NODE, is the wire identity
    // and the key the owner-binding names.
    let node_key = format!("ciris-node-split-{}", std::process::id());
    seed_key(&engine, &node_key, 0x6A, 0x6B, identity_type::NODE).await;
    ciris_server::node_key::set_wire_identity(&node_key);
    assert_ne!(node_key, actor_key, "the fixture must actually be split");

    // PRODUCTION'S SEQUENCE: the claim bound the owner to the ACTOR (the
    // engine's key, before the split), then boot's split MOVED the binding onto
    // the node key through `node_key::move_owner_binding_to_node_key` — the
    // real function, so the fixture cannot drift from what a split node holds.
    let owner_id = OwnerIdentity::mint().await;
    bind_owner(&engine, &owner_id, &actor_key).await;
    let moved = ciris_server::node_key::move_owner_binding_to_node_key(
        &engine,
        &owner_id.signer().await,
        &actor_key,
        &node_key,
    )
    .await
    .expect("move the owner-binding onto the node key");
    assert!(moved.is_some(), "the split must move the binding");
    let owner = mint_session(&engine, "wa-split-owner", WaRole::Root).await;
    // Files are authored by the engine's (actor) signer — what compose hands
    // `drive::router` as `chat_node_signer`.
    let base = serve_drive(
        Arc::clone(&engine),
        node_edge_signer(&engine).await,
        owner_id.seed_dir.clone(),
    )
    .await;
    let client = reqwest::Client::new();

    assert_eq!(
        ciris_server::backend::content_occurrence_key_id(&engine)
            .await
            .expect("viewer key"),
        node_key,
        "on a split install files are opened as the WIRE node key — the key the \
         content occurrence is provisioned under"
    );

    let body = b"written on a split node".to_vec();
    let (s, v) = status_json(
        client
            .post(format!("{base}/v1/files"))
            .bearer_auth(&owner)
            .json(&serde_json::json!({
                "cohort": "self",
                "bytes_base64": BASE64.encode(&body),
                "media_type": "text/plain",
                "filename": "split.txt",
            }))
            .send()
            .await
            .expect("POST /v1/files"),
    )
    .await;
    assert_eq!(s, 200, "a split node writes a file: {v}");
    let id = v["attestation_id"].as_str().expect("id").to_owned();

    // THE FIX: the node that wrote it opens it.
    let (s, drive) = status_json(
        client
            .get(format!("{base}/v1/drive?cohort=self"))
            .bearer_auth(&owner)
            .send()
            .await
            .expect("GET /v1/drive"),
    )
    .await;
    assert_eq!(s, 200, "{drive}");
    let entry = drive["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|e| e["attestation_id"] == id.as_str())
        .unwrap_or_else(|| panic!("the file is listed: {drive}"))
        .clone();
    assert_eq!(
        entry["bytes"], "here",
        "a split node must open its own file — `not_granted` here is the pre-0.5.216 \
         viewer key: {entry}"
    );
    let (s, v) = status_json(
        client
            .get(format!("{base}/v1/files/{id}"))
            .bearer_auth(&owner)
            .send()
            .await
            .expect("GET file"),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(
        BASE64
            .decode(v["bytes_base64"].as_str().expect("bytes"))
            .expect("base64"),
        body
    );

    // THE CONTROL: opened as the ACTOR key — what the drive used to pass — the
    // same row does NOT open. Without this, the assertion above could be green
    // because every key opens everything.
    let room = ciris_edge::self_room::room(&owner_id.key_id);
    let page = ciris_edge::files::in_room(&engine, &room, &owner_id.key_id, 50, None)
        .await
        .expect("list the self room");
    let row = page
        .files
        .iter()
        .find(|f| f.attestation_id == id)
        .expect("the row is in the room");
    let store = ciris_edge::group_content::PersistGroupContentStore::new(
        (*engine).clone(),
        engine.federation_directory(),
    );
    let as_actor = row.open(&store, &actor_key).await;
    assert!(
        matches!(
            as_actor,
            Err(ciris_edge::chat::UnopenedReason::NotGranted { .. })
        ),
        "the actor key holds no grant on a split node — which is exactly why the drive \
         must not open as it: {as_actor:?}"
    );
    assert_eq!(
        row.open(&store, &node_key)
            .await
            .expect("opens as the node key"),
        body
    );
}
