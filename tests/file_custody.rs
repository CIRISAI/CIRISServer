//! **Where each file is — the custody view** (0.5.218, `FSD/FILE_CUSTODY.md`).
//!
//! Two devices of ONE person, in process, with nothing under test stubbed: the
//! real drive router on each, real engines, the owner's minted fed-ID, and the
//! second device's crossing carried the way replication carries it (its node
//! key, the owner's binding onto it, its SIGNED content occurrence).
//!
//! The receipt is edge's own: the second device SIGNS it with
//! `receipts::sign_receipt` and EMITS it with `receipts::emit_receipt_row` —
//! exactly what `on_dag_pulled` does after a DAG pull stores the chunks — and
//! the first device ADMITS it with `receipts::admit_and_count`, the replication
//! bridge's own call. What is not run here is the pull itself (the blob swarm
//! over a transport); the native harness's `custody` relation
//! (`harness/native/topologies/selffiles.yaml`, CSD-107) asserts the whole
//! path on a real mesh.
//!
//! Pinned:
//! 1. a > 1 MiB self file written on A, receipted by B → A's custody lists
//!    both devices, B `received` with the file's chunk count, A `here`,
//!    `devices_total == 2`; the drive row carries `{devices_total: 2,
//!    received_on: 1}`;
//! 2. an inline file answers `receipts_supported: false` with its reason id;
//! 3. every refusal is the byte read's refusal, status AND id — no session, a
//!    cohort the caller is not in, a row that is not there, and (on B, which
//!    holds the row and not the bytes) `not_fetched`; and persist's custody
//!    door itself refuses a viewer key that cannot open the bytes.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{cohort_scope, identity_type};
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use ciris_persist::wa_cert::WaRole;
use ed25519_dalek::SigningKey;

#[allow(dead_code)] // one fixture, several binaries: each uses a different subset
mod support {
    include!("support/drive_fixture.rs");
}
use support::*;

async fn other_engine(alias: &str, ed: u8, pqc: u8) -> Arc<Engine> {
    let pqc_signer = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[pqc; 32], format!("{alias}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[ed; 32]),
        alias.to_string(),
        Some(pqc_signer),
        Some(format!("{alias}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine"),
    )
}

/// The owner-binding claim-remote records LOCALLY for the other device.
async fn record_claim_locally(engine: &Engine, owner: &OwnerIdentity, node: &str) {
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let binding = ciris_server::auth::ownership::build_signed_owner_binding(
        &owner.signer().await,
        node,
        &scopes,
        cohort_scope::SELF,
    )
    .await
    .expect("build the claim's owner-binding");
    ciris_server::auth::ownership::apply_signed_owner_binding(
        engine,
        node,
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &binding,
    )
    .await
    .expect("record the other device's owner-binding locally");
}

/// Bytes the write gate reads as an honest `application/octet-stream`.
fn blob(n: usize) -> Vec<u8> {
    let mut v = b"\x00CIRIS-custody\x00".to_vec();
    v.extend((0..n.saturating_sub(v.len())).map(|i| ((i * 31 + i / 251) % 256) as u8));
    v
}

async fn upload(
    client: &reqwest::Client,
    base: &str,
    bearer: &str,
    bytes: &[u8],
    name: &str,
) -> String {
    let (s, v) = status_json(
        client
            .post(format!("{base}/v1/files"))
            .bearer_auth(bearer)
            .json(&serde_json::json!({
                "cohort": "self",
                "bytes_base64": BASE64.encode(bytes),
                "media_type": "application/octet-stream",
                "filename": name,
            }))
            .send()
            .await
            .expect("POST /v1/files"),
    )
    .await;
    assert_eq!(s, 200, "upload {name}: {v}");
    v["attestation_id"].as_str().expect("id").to_owned()
}

async fn get(
    client: &reqwest::Client,
    base: &str,
    bearer: Option<&str>,
    path: &str,
) -> (u16, serde_json::Value) {
    let mut req = client.get(format!("{base}{path}"));
    if let Some(b) = bearer {
        req = req.bearer_auth(b);
    }
    status_json(req.send().await.expect("GET")).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_author_device_names_the_device_that_received_the_file() {
    init_tracing();
    let client = reqwest::Client::new();

    // DEVICE A — owned, serving the drive.
    let first = node_engine().await;
    let owner = OwnerIdentity::mint().await;
    let first_key = register_self(&first).await;
    bind_owner(&first, &owner, &first_key).await;
    let bearer = mint_session(&first, "wa-custody-first", WaRole::Root).await;
    let base = serve_drive(
        Arc::clone(&first),
        node_edge_signer(&first).await,
        owner.seed_dir.clone(),
    )
    .await;

    // DEVICE B — same owner; its crossing onto A as replication carries it,
    // BEFORE the write, so the file is wrapped to it (`can_open`).
    let second = other_engine("ciris-custody-second", 0xC1, 0xC2).await;
    let second_key = register_self(&second).await;
    bind_owner(&second, &owner, &second_key).await;
    let (occurrence, _) =
        ciris_server::backend::provision_engine_occurrence(&second, &owner.key_id)
            .await
            .expect("the second device provisions its occurrence");
    seed_key(&first, &second_key, 0xC1, 0xC2, identity_type::NODE).await;
    record_claim_locally(&first, &owner, &second_key).await;
    let signed = second
        .federation_directory()
        .list_signed_identity_occurrences_for(&owner.key_id)
        .await
        .expect("the second device's signed occurrences")
        .into_iter()
        .find(|o| o.identity_occurrence.occurrence_key_id == occurrence)
        .expect("the provisioned occurrence rides the signed plane");
    first
        .federation_directory()
        .put_identity_occurrence(signed)
        .await
        .expect("A admits B's occurrence");

    // A > 1 MiB self file (a chunk DAG, so a stream and an STH) and an inline one.
    let big = blob(2 * 1024 * 1024 + 3);
    let big_id = upload(&client, &base, &bearer, &big, "big.bin").await;
    let small_id = upload(&client, &base, &bearer, &blob(4096), "small.bin").await;

    // BEFORE any receipt: B is listed, `unknown`, and can open.
    let (s, before) = get(
        &client,
        &base,
        Some(&bearer),
        &format!("/v1/files/{big_id}/custody?cohort=self"),
    )
    .await;
    assert_eq!(s, 200, "{before}");
    assert_eq!(before["devices_total"], 2, "{before}");
    assert_eq!(before["receipts_supported"], true, "{before}");
    let b_before = before["devices"]
        .as_array()
        .expect("devices")
        .iter()
        .find(|d| d["node_key_id"] == second_key.as_str())
        .unwrap_or_else(|| panic!("B is one of the person's devices: {before}"))
        .clone();
    assert_eq!(b_before["holds"], "unknown", "{before}");
    assert_eq!(b_before["can_open"], true, "B was wrapped to: {before}");

    // B RECEIPTS the file: edge's receive-side functions, as `on_dag_pulled`
    // runs them after a stored pull …
    let row = first
        .federation_directory()
        .get_attestation(&big_id)
        .await
        .expect("read")
        .expect("the file row");
    let claim = ciris_edge::receipts::StreamSthClaim::from_row(&row)
        .expect("a chunk-DAG file row carries its stream's STH");
    let receipt = ciris_edge::receipts::sign_receipt(
        &second,
        &second_key,
        &claim.stream_id,
        ciris_edge::receipts::FILE_STREAM_EPOCH,
        claim.root().expect("root"),
        claim.tree_size,
    )
    .await
    .expect("B signs the receipt");
    let receipt_row_id = ciris_edge::receipts::emit_receipt_row(&second, &row, &receipt)
        .await
        .expect("B emits the receipt row at the file's cohort");
    let receipt_row = second
        .federation_directory()
        .get_attestation(&receipt_row_id)
        .await
        .expect("read")
        .expect("the receipt row");
    // … and A ADMITS it, the replication bridge's own call.
    let log =
        ciris_edge::receipts::stream_log_of(&first).expect("a SQLite engine has a stream log");
    let directory = first.federation_directory();
    ciris_edge::receipts::admit_and_count(
        &*log,
        &*directory,
        &receipt_row,
        &ciris_edge::receipts::ReceiptLedger::new(),
        None,
    )
    .await
    .expect("A admits B's receipt");

    // 1. A's custody: both devices, B received, A here.
    let (s, v) = get(
        &client,
        &base,
        Some(&bearer),
        &format!("/v1/files/{big_id}/custody?cohort=self"),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["devices_total"], 2, "{v}");
    assert_eq!(v["held_here"], true, "{v}");
    assert_eq!(v["this_device_is_author"], true, "{v}");
    assert_eq!(
        v["copies_observable"], false,
        "self copies are uncountable by design: {v}"
    );
    let devices = v["devices"].as_array().expect("devices");
    let a = devices
        .iter()
        .find(|d| d["this_device"] == true)
        .unwrap_or_else(|| panic!("this device is listed: {v}"));
    assert_eq!(a["node_key_id"], first_key.as_str(), "{v}");
    assert_eq!(a["holds"], "here", "{v}");
    let b = devices
        .iter()
        .find(|d| d["node_key_id"] == second_key.as_str())
        .unwrap_or_else(|| panic!("B is listed: {v}"));
    assert_eq!(b["holds"], "received", "{v}");
    assert_eq!(b["received"]["k"], claim.tree_size, "{v}");
    assert!(claim.tree_size >= 2, "a 2 MiB file is several chunks: {v}");
    let why: Vec<&str> = v["why"]
        .as_array()
        .expect("why")
        .iter()
        .filter_map(|w| w["reason_id"].as_str())
        .collect();
    for id in [
        "custody.copies_unobservable_by_design",
        "custody.receipt_is_delivery_not_holding",
    ] {
        assert!(why.contains(&id), "{id} in {why:?}");
    }
    assert!(
        v["receipts_from_other_keys"]
            .as_array()
            .is_some_and(|r| r.is_empty()),
        "{v}"
    );

    // 2. The inline file says why it has no receipt.
    let (s, v) = get(
        &client,
        &base,
        Some(&bearer),
        &format!("/v1/files/{small_id}/custody?cohort=self"),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["receipts_supported"], false, "{v}");
    assert_eq!(
        v["receipts_unsupported_reason"], "custody.inline_no_receipt",
        "{v}"
    );
    assert!(
        v["why"].as_array().is_some_and(|w| w
            .iter()
            .any(|x| x["reason_id"] == "custody.inline_no_receipt")),
        "{v}"
    );
    assert_eq!(v["devices_total"], 2, "{v}");

    // The drive's compact summary, per row.
    let (s, drive) = get(&client, &base, Some(&bearer), "/v1/drive?cohort=self").await;
    assert_eq!(s, 200, "{drive}");
    let entry = |id: &str| {
        drive["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .find(|e| e["attestation_id"] == id)
            .unwrap_or_else(|| panic!("{id} listed: {drive}"))
            .clone()
    };
    assert_eq!(
        entry(&big_id)["custody"],
        serde_json::json!({"devices_total": 2, "received_on": 1}),
        "{drive}"
    );
    assert_eq!(
        entry(&small_id)["custody"],
        serde_json::json!({"devices_total": 2, "received_on": null}),
        "{drive}"
    );

    // 3. REFUSED EXACTLY AS THE BYTE READ REFUSES — status and id.
    let same = |label: &str, read: (u16, serde_json::Value), custody: (u16, serde_json::Value)| {
        assert_ne!(custody.0, 200, "{label}: custody answered {}", custody.1);
        assert_eq!(
            (custody.0, custody.1["reason_id"].clone()),
            (read.0, read.1["reason_id"].clone()),
            "{label}: the custody view refuses as the byte read does — read {} / custody {}",
            read.1,
            custody.1
        );
    };
    for (label, bearer, q) in [
        ("no session", None, "cohort=self"),
        (
            "not a member",
            Some(bearer.as_str()),
            "cohort=family&room_id=not-my-family",
        ),
        ("unknown cohort", Some(bearer.as_str()), "cohort=everyone"),
    ] {
        same(
            label,
            get(&client, &base, bearer, &format!("/v1/files/{big_id}?{q}")).await,
            get(
                &client,
                &base,
                bearer,
                &format!("/v1/files/{big_id}/custody?{q}"),
            )
            .await,
        );
    }
    same(
        "not in the room",
        get(
            &client,
            &base,
            Some(&bearer),
            "/v1/files/no-such-file?cohort=self",
        )
        .await,
        get(
            &client,
            &base,
            Some(&bearer),
            "/v1/files/no-such-file/custody?cohort=self",
        )
        .await,
    );

    // The substrate door itself: a viewer key that cannot open the bytes learns
    // nothing — not the access list, not the copies.
    let file = ciris_edge::files::FileRow::from_row(&row).expect("a file row");
    let store = ciris_edge::group_content::PersistGroupContentStore::new(
        (*first).clone(),
        first.federation_directory(),
    );
    match file.custody(&store, "a-stranger-with-no-grant").await {
        Err(reason) => assert_eq!(reason.kind(), "not_granted", "{reason}"),
        Ok(c) => panic!("a stranger's viewer key read the custody view: {c:?}"),
    }

    // B holds the ROW, not the bytes: the custody view is B's byte read's 409.
    seed_key(&second, &first_key, 0xA1, 0xA2, identity_type::NODE).await;
    record_claim_locally(&second, &owner, &first_key).await;
    second
        .federation_directory()
        .put_attestation(ciris_persist::federation::SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("B admits the file row");
    let bearer2 = mint_session(&second, "wa-custody-second", WaRole::Root).await;
    let base2 = serve_drive(
        Arc::clone(&second),
        edge_signer_for(&second_key, 0xC1, 0xC2),
        owner.seed_dir.clone(),
    )
    .await;
    let read = get(
        &client,
        &base2,
        Some(&bearer2),
        &format!("/v1/files/{big_id}?cohort=self&raw=1"),
    )
    .await;
    let custody = get(
        &client,
        &base2,
        Some(&bearer2),
        &format!("/v1/files/{big_id}/custody?cohort=self"),
    )
    .await;
    same("row here, bytes not", read, custody);
}
