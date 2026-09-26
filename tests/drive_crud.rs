//! **The drive's CRUD surface, end to end over the real router**
//! (`FSD/ROSTER_AND_DRIVE_CRUD.md` §5, CIRISServer 0.5.216).
//!
//! Every route, its happy path, every refusal id it can answer, and the policy
//! matrix — owner / author, non-author, non-member, delegate, no session. The
//! fixture (`tests/support/drive_fixture.rs`) stubs nothing: the owner's pen is
//! minted onto disk, the node's key is hybrid, the substrate is persist's
//! sqlite, and the router is `drive::router` on a real listener.
//!
//! What each test pins, in one line:
//!
//! * uploads — JSON and `multipart/form-data`, above axum's 2 MB default (the
//!   limit is raised on the upload routes only);
//! * the drive — `resume` pages, `limit` clamped at 500, envelope per row, byte
//!   state and size WITHOUT a whole read;
//! * metadata, the JSON read, `?raw=1` with `Content-Type` /
//!   `Content-Disposition`, and HTTP `Range` (inside one chunk, across chunk
//!   boundaries, suffix, unsatisfiable);
//! * withdraw → every read is `410 drive.withdrawn`, the listing hides it, the
//!   local copy is evicted;
//! * rename keeps the blob (same sha, bytes still open) and retires the old id;
//! * replace publishes new bytes and retires the old id;
//! * move reseals at the target room and withdraws the source (or keeps it);
//! * notes: edit and delete through the same machinery.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_persist::federation::types::{identity_type, Community, CommunityMember};
use ciris_persist::prelude::Engine;
use ciris_persist::wa_cert::WaRole;

#[allow(dead_code)] // one fixture, two binaries: each uses a different subset
mod support {
    include!("support/drive_fixture.rs");
}
use support::*;

const OWNER_WA: &str = "wa-drive-owner";

struct Fx {
    engine: Arc<Engine>,
    base: String,
    owner: String,
    owner_id: OwnerIdentity,
    node_key: String,
    client: reqwest::Client,
}

async fn fixture() -> Fx {
    init_tracing();
    let engine = node_engine().await;
    let owner_id = OwnerIdentity::mint().await;
    let node_key = register_self(&engine).await;
    bind_owner(&engine, &owner_id, &node_key).await;
    let owner = mint_session(&engine, OWNER_WA, WaRole::Root).await;
    let signer = node_edge_signer(&engine).await;
    let base = serve_drive(Arc::clone(&engine), signer, owner_id.seed_dir.clone()).await;
    Fx {
        engine,
        base,
        owner,
        owner_id,
        node_key,
        client: reqwest::Client::new(),
    }
}

impl Fx {
    /// `POST /v1/files` (JSON) at `self`; returns the readable id.
    async fn upload_self(&self, bytes: &[u8], filename: Option<&str>, media: &str) -> String {
        let (s, v) = status_json(
            self.client
                .post(format!("{}/v1/files", self.base))
                .bearer_auth(&self.owner)
                .json(&serde_json::json!({
                    "cohort": "self",
                    "bytes_base64": BASE64.encode(bytes),
                    "media_type": media,
                    "filename": filename,
                }))
                .send()
                .await
                .expect("POST /v1/files"),
        )
        .await;
        assert_eq!(s, 200, "upload: {v}");
        assert_eq!(v["crossed"], true, "a self file must cross: {v}");
        v["attestation_id"].as_str().expect("id").to_owned()
    }

    async fn get(&self, path: &str) -> (u16, serde_json::Value) {
        status_json(
            self.client
                .get(format!("{}{path}", self.base))
                .bearer_auth(&self.owner)
                .send()
                .await
                .expect("GET"),
        )
        .await
    }

    async fn delete(&self, path: &str) -> (u16, serde_json::Value) {
        status_json(
            self.client
                .delete(format!("{}{path}", self.base))
                .bearer_auth(&self.owner)
                .send()
                .await
                .expect("DELETE"),
        )
        .await
    }

    async fn post(&self, path: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
        status_json(
            self.client
                .post(format!("{}{path}", self.base))
                .bearer_auth(&self.owner)
                .json(&body)
                .send()
                .await
                .expect("POST"),
        )
        .await
    }

    async fn put(&self, path: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
        status_json(
            self.client
                .put(format!("{}{path}", self.base))
                .bearer_auth(&self.owner)
                .json(&body)
                .send()
                .await
                .expect("PUT"),
        )
        .await
    }

    /// The bytes of a file through the JSON read.
    async fn read_bytes(&self, id: &str, query: &str) -> Vec<u8> {
        let (s, v) = self.get(&format!("/v1/files/{id}?{query}")).await;
        assert_eq!(s, 200, "read {id}: {v}");
        BASE64
            .decode(v["bytes_base64"].as_str().expect("bytes_base64"))
            .expect("base64")
    }

    /// A community the OWNER founded (and so a member of), plus `others`.
    async fn owners_community(&self, name: &str, others: &[&str]) -> String {
        let id = format!("community-{name}-{}", std::process::id());
        let now = chrono::Utc::now();
        self.engine
            .put_community_self_signed(Community {
                community_key_id: id.clone(),
                community_name: name.to_owned(),
                members: founded_by(&self.owner_id.key_id, others, now),
                founded_at: now,
                consensus_protocol: "founder_only".to_string(),
                policy_blob: None,
                persist_row_hash: String::new(),
            })
            .await
            .expect("author the owner's community");
        id
    }

    /// A community of strangers the owner is NOT in.
    async fn strangers_community(&self) -> String {
        seed_key(&self.engine, "carol-drive", 0xC0, 0xC1, identity_type::USER).await;
        seed_key(&self.engine, "dave-drive", 0xD0, 0xD1, identity_type::USER).await;
        let id = format!("community-strangers-{}", std::process::id());
        let now = chrono::Utc::now();
        self.engine
            .put_community_self_signed(Community {
                community_key_id: id.clone(),
                community_name: "strangers".to_owned(),
                members: ["carol-drive", "dave-drive"]
                    .iter()
                    .map(|k| CommunityMember {
                        key_id: (*k).to_string(),
                        joined_at: now,
                        role: None,
                    })
                    .collect(),
                founded_at: now,
                consensus_protocol: "founder_only".to_string(),
                policy_blob: None,
                persist_row_hash: String::new(),
            })
            .await
            .expect("author the strangers' community");
        id
    }
}

/// A roster FOUNDED by the owner — the steward-bound authority root persist
/// requires before a community federates at all (CC 4.5.4: a room with no live
/// `moderate`-duty holder must not federate; a `founder_only` room's authority
/// is its founders).
fn founded_by(
    owner: &str,
    others: &[&str],
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<CommunityMember> {
    std::iter::once(CommunityMember {
        key_id: owner.to_owned(),
        joined_at: now,
        role: Some("founder".to_owned()),
    })
    .chain(others.iter().map(|k| CommunityMember {
        key_id: (*k).to_owned(),
        joined_at: now,
        role: None,
    }))
    .collect()
}

fn reason(v: &serde_json::Value) -> &str {
    v["reason_id"].as_str().unwrap_or("<none>")
}

/// A hand-built `multipart/form-data` body — the wire shape a browser's
/// `FormData` sends, CRLFs and all.
fn multipart_body(boundary: &str, fields: &[(&str, &str)], file: (&str, &str, &[u8])) -> Vec<u8> {
    let mut b = Vec::new();
    for (k, v) in fields {
        b.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n")
                .as_bytes(),
        );
    }
    let (name, ct, data) = file;
    b.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\
             Content-Type: {ct}\r\n\r\n"
        )
        .as_bytes(),
    );
    b.extend_from_slice(data);
    b.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    b
}

/// Deterministic, non-repeating-ish bytes, so a range slice is checkable.
fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + i / 251) % 256) as u8).collect()
}

// ─── Upload, list, metadata, read ──────────────────────────────────────────

/// JSON and multipart uploads both land, the multipart one ABOVE axum's 2 MB
/// default body limit (and above edge's 1 MiB envelope bound, so it is sealed
/// as a chunk DAG). The drive lists both with byte state, size and envelope;
/// the metadata route agrees; the JSON read and `?raw=1` return the bytes.
#[tokio::test]
async fn uploads_list_meta_and_read_round_trip() {
    let fx = fixture().await;
    let small = b"hello, drive".to_vec();
    let small_id = fx
        .upload_self(&small, Some("hello.txt"), "text/plain")
        .await;

    let big = pattern(3 * 1024 * 1024 + 17);
    let boundary = "drive-crud-boundary-7f3a";
    let body = multipart_body(
        boundary,
        &[("cohort", "self")],
        ("boat.bin", "application/x-boat", &big),
    );
    let (s, v) = status_json(
        fx.client
            .post(format!("{}/v1/files", fx.base))
            .bearer_auth(&fx.owner)
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(body)
            .send()
            .await
            .expect("multipart POST"),
    )
    .await;
    assert_eq!(s, 200, "a 3 MiB multipart upload must be admitted: {v}");
    let big_id = v["attestation_id"].as_str().expect("id").to_owned();

    // THE DRIVE: both rows, state `here`, size known WITHOUT a whole read,
    // and each row's envelope.
    let (s, drive) = fx.get("/v1/drive?cohort=self").await;
    assert_eq!(s, 200, "{drive}");
    let entries = drive["entries"].as_array().expect("entries");
    let entry = |id: &str| {
        entries
            .iter()
            .find(|e| e["attestation_id"] == id)
            .unwrap_or_else(|| panic!("{id} missing from the drive: {drive}"))
            .clone()
    };
    let e_small = entry(&small_id);
    assert_eq!(e_small["bytes"], "here", "{e_small}");
    assert_eq!(e_small["size"], small.len() as u64, "{e_small}");
    assert_eq!(e_small["filename"], "hello.txt");
    assert_eq!(e_small["withdrawn"], false);
    let env = &e_small["envelope"];
    assert_eq!(env["attestation_id"], small_id.as_str());
    assert_eq!(env["attesting_key_id"], fx.node_key.as_str());
    assert_eq!(env["cohort_scope"], "self");
    assert_eq!(env["dimension"], "file:v1");
    assert!(env["subject_key_ids"].is_array(), "{env}");
    assert!(env.get("consent_scope").is_some(), "{env}");
    let e_big = entry(&big_id);
    assert_eq!(e_big["bytes"], "here", "{e_big}");
    assert_eq!(e_big["size"], big.len() as u64, "{e_big}");
    assert_eq!(e_big["media_type"], "application/x-boat");
    assert_eq!(e_big["filename"], "boat.bin");
    assert!(drive["resume"].is_null(), "two rows fit one page: {drive}");

    // METADATA.
    let (s, meta) = fx.get(&format!("/v1/files/{big_id}/meta")).await;
    assert_eq!(s, 200, "{meta}");
    assert_eq!(meta["size"], big.len() as u64);
    assert_eq!(meta["bytes"], "here");
    assert_eq!(meta["chunked"], true, "above 1 MiB is a chunk DAG: {meta}");
    assert_eq!(meta["filename"], "boat.bin");
    assert_eq!(meta["withdrawn"], false);
    assert_eq!(
        meta["holder_claims_recorded"], false,
        "CC 5.2: no holder claim exists at self"
    );
    assert!(meta["devices_holding"].is_null(), "{meta}");
    assert_eq!(meta["envelope"]["dimension"], "file:v1");

    // THE JSON READ and THE RAW READ.
    assert_eq!(fx.read_bytes(&small_id, "").await, small);
    assert_eq!(fx.read_bytes(&big_id, "cohort=self").await, big);
    let resp = fx
        .client
        .get(format!("{}/v1/files/{small_id}?raw=1", fx.base))
        .bearer_auth(&fx.owner)
        .send()
        .await
        .expect("raw GET");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "text/plain");
    let cd = resp.headers()["content-disposition"]
        .to_str()
        .expect("ascii")
        .to_owned();
    assert!(
        cd.contains("attachment") && cd.contains("hello.txt"),
        "{cd}"
    );
    assert_eq!(resp.headers()["accept-ranges"], "bytes");
    assert_eq!(resp.bytes().await.expect("body").to_vec(), small);
}

/// HTTP `Range` on `?raw=1` — through persist's `read_blob_range_as`, inside
/// an inline blob, ACROSS the 256 KiB chunk boundaries of a DAG, as a suffix,
/// and past the end (416 `drive.range_not_satisfiable`).
#[tokio::test]
async fn range_reads_serve_the_asked_slice() {
    let fx = fixture().await;
    let small = pattern(1000);
    let small_id = fx
        .upload_self(&small, Some("s.bin"), "application/octet-stream")
        .await;
    let big = pattern(2 * 1024 * 1024 + 5);
    let big_id = fx
        .upload_self(&big, Some("b.bin"), "application/octet-stream")
        .await;

    let range = |id: String, r: &'static str| {
        let client = fx.client.clone();
        let url = format!("{}/v1/files/{id}?raw=1", fx.base);
        let owner = fx.owner.clone();
        async move {
            client
                .get(url)
                .bearer_auth(owner)
                .header("range", r)
                .send()
                .await
                .expect("range GET")
        }
    };

    let resp = range(small_id.clone(), "bytes=10-19").await;
    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers()["content-range"], "bytes 10-19/1000");
    assert_eq!(resp.bytes().await.unwrap().to_vec(), small[10..20].to_vec());

    let resp = range(small_id.clone(), "bytes=-5").await;
    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers()["content-range"], "bytes 995-999/1000");
    assert_eq!(resp.bytes().await.unwrap().to_vec(), small[995..].to_vec());

    // Across a chunk boundary (256 KiB = 262144).
    let resp = range(big_id.clone(), "bytes=262100-262200").await;
    assert_eq!(resp.status(), 206);
    assert_eq!(
        resp.headers()["content-range"],
        format!("bytes 262100-262200/{}", big.len()).as_str()
    );
    assert_eq!(
        resp.bytes().await.unwrap().to_vec(),
        big[262_100..=262_200].to_vec()
    );
    // Open-ended to the end.
    let resp = range(big_id.clone(), "bytes=2097150-").await;
    assert_eq!(resp.status(), 206);
    assert_eq!(
        resp.bytes().await.unwrap().to_vec(),
        big[2_097_150..].to_vec()
    );

    let resp = range(small_id.clone(), "bytes=5000-").await;
    assert_eq!(resp.status(), 416);
    assert_eq!(resp.headers()["content-range"], "bytes */1000");
    let (_, v) = status_json(resp).await;
    assert_eq!(reason(&v), "drive.range_not_satisfiable");
}

/// `resume` pages the drive: every row exactly once, `null` at the end — and
/// `limit` is clamped to 500, not refused.
#[tokio::test]
async fn the_drive_pages_by_resume() {
    let fx = fixture().await;
    let mut ids = Vec::new();
    for i in 0..5 {
        ids.push(
            fx.upload_self(
                format!("file {i}").as_bytes(),
                Some(&format!("f{i}.txt")),
                "text/plain",
            )
            .await,
        );
    }
    let mut seen = Vec::new();
    let mut after: Option<String> = None;
    let mut pages = 0;
    loop {
        let q = match &after {
            None => "/v1/drive?cohort=self&limit=2".to_owned(),
            Some(a) => format!("/v1/drive?cohort=self&limit=2&after={a}"),
        };
        let (s, v) = fx.get(&q).await;
        assert_eq!(s, 200, "{v}");
        pages += 1;
        for e in v["entries"].as_array().unwrap() {
            seen.push(e["attestation_id"].as_str().unwrap().to_owned());
        }
        match v["resume"].as_str() {
            Some(r) => after = Some(r.to_owned()),
            None => break,
        }
        assert!(pages < 10, "resume never reached the end");
    }
    assert!(
        pages >= 3,
        "5 rows at limit=2 is at least 3 pages, got {pages}"
    );
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), seen.len(), "a row was listed twice: {seen:?}");
    for id in &ids {
        assert!(seen.contains(id), "{id} never listed: {seen:?}");
    }

    let (_, v) = fx.get("/v1/drive?cohort=self&limit=100000").await;
    assert_eq!(v["limit"], 500, "clamped, not refused: {v}");
    let (s, v) = fx.get("/v1/drive?cohort=self&after=not-a-cursor").await;
    assert_eq!((s, reason(&v)), (400, "drive.bad_cursor"));
}

// ─── Withdraw, rename, replace ─────────────────────────────────────────────

/// DELETE withdraws: every read of the file is then 410 `drive.withdrawn`, the
/// drive hides it (and shows it under `include_withdrawn=true`), the metadata
/// route says so, the local copy is evicted, and a second DELETE is 410.
#[tokio::test]
async fn withdraw_then_read_is_gone() {
    let fx = fixture().await;
    let keep = fx
        .upload_self(b"keep me", Some("keep.txt"), "text/plain")
        .await;
    let id = fx
        .upload_self(b"take me back", Some("gone.txt"), "text/plain")
        .await;

    let (s, v) = fx.delete(&format!("/v1/files/{id}")).await;
    assert_eq!(s, 200, "{v}");
    assert!(
        v["withdrawn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w == id.as_str()),
        "{v}"
    );
    assert_eq!(v["evicted"], true, "nothing live binds the bytes: {v}");

    let (s, v) = fx.get(&format!("/v1/files/{id}")).await;
    assert_eq!((s, reason(&v)), (410, "drive.withdrawn"), "{v}");
    let (s, v) = fx.get(&format!("/v1/files/{id}?raw=1")).await;
    assert_eq!((s, reason(&v)), (410, "drive.withdrawn"), "{v}");
    let (s, v) = fx.delete(&format!("/v1/files/{id}")).await;
    assert_eq!((s, reason(&v)), (410, "drive.withdrawn"), "{v}");

    let (_, drive) = fx.get("/v1/drive?cohort=self").await;
    let listed: Vec<&str> = drive["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["attestation_id"].as_str().unwrap())
        .collect();
    assert!(
        !listed.contains(&id.as_str()),
        "a withdrawn file is gone: {drive}"
    );
    assert!(listed.contains(&keep.as_str()), "{drive}");

    let (_, drive) = fx.get("/v1/drive?cohort=self&include_withdrawn=true").await;
    let row = drive["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["attestation_id"] == id.as_str())
        .unwrap_or_else(|| panic!("include_withdrawn lists it: {drive}"))
        .clone();
    assert_eq!(row["withdrawn"], true);
    assert_eq!(row["bytes"], "withdrawn");

    let (s, meta) = fx.get(&format!("/v1/files/{id}/meta")).await;
    assert_eq!(s, 200, "{meta}");
    assert_eq!(meta["withdrawn"], true);
    assert!(meta["withdrawn_by"].is_string(), "{meta}");

    // The file that was not withdrawn is untouched.
    assert_eq!(fx.read_bytes(&keep, "").await, b"keep me");
}

/// Rename is a new row over the SAME bytes: the sha is unchanged, the bytes
/// still open under the new id, the old id is 410, and the new row says which
/// one it replaced. An empty name is `drive.filename_empty`.
#[tokio::test]
async fn rename_keeps_the_blob_and_the_bytes_open() {
    let fx = fixture().await;
    let id = fx
        .upload_self(b"the same bytes", Some("before.txt"), "text/plain")
        .await;
    let (_, before) = fx.get(&format!("/v1/files/{id}/meta")).await;

    let (s, v) = fx
        .post(
            &format!("/v1/files/{id}/rename"),
            serde_json::json!({ "filename": "  " }),
        )
        .await;
    assert_eq!((s, reason(&v)), (400, "drive.filename_empty"), "{v}");

    let (s, v) = fx
        .post(
            &format!("/v1/files/{id}/rename"),
            serde_json::json!({ "filename": "after.txt" }),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let new_id = v["attestation_id"].as_str().unwrap().to_owned();
    assert_ne!(new_id, id);
    assert_eq!(v["replaces"], id.as_str());
    assert_eq!(v["crossed"], true, "{v}");

    let (s, after) = fx.get(&format!("/v1/files/{new_id}/meta")).await;
    assert_eq!(s, 200, "{after}");
    assert_eq!(after["filename"], "after.txt");
    assert_eq!(
        after["content_sha256"], before["content_sha256"],
        "a rename must not re-upload: same sha"
    );
    assert_eq!(after["replaces"], id.as_str());
    assert_eq!(after["bytes"], "here", "the bytes stay live: {after}");
    assert_eq!(fx.read_bytes(&new_id, "").await, b"the same bytes");

    let (s, v) = fx.get(&format!("/v1/files/{id}")).await;
    assert_eq!((s, reason(&v)), (410, "drive.withdrawn"), "{v}");
    let (_, drive) = fx.get("/v1/drive?cohort=self").await;
    let names: Vec<&str> = drive["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["filename"].as_str())
        .collect();
    assert_eq!(names, vec!["after.txt"], "{drive}");
}

/// PUT replaces the bytes: a new id with the new bytes, the old name kept when
/// none is given, the old id 410.
#[tokio::test]
async fn replace_publishes_new_bytes_and_retires_the_old() {
    let fx = fixture().await;
    let id = fx
        .upload_self(b"version one", Some("doc.txt"), "text/plain")
        .await;
    let (s, v) = fx
        .put(
            &format!("/v1/files/{id}"),
            serde_json::json!({ "bytes_base64": BASE64.encode(b"version two") }),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let new_id = v["attestation_id"].as_str().unwrap().to_owned();
    assert_ne!(new_id, id);
    assert_eq!(v["replaces"], id.as_str());
    assert!(
        v["withdrawn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w == id.as_str()),
        "{v}"
    );
    assert_eq!(fx.read_bytes(&new_id, "").await, b"version two");
    let (_, meta) = fx.get(&format!("/v1/files/{new_id}/meta")).await;
    assert_eq!(meta["filename"], "doc.txt", "the old name is kept: {meta}");
    assert_eq!(meta["media_type"], "text/plain");
    let (s, v) = fx.get(&format!("/v1/files/{id}")).await;
    assert_eq!((s, reason(&v)), (410, "drive.withdrawn"), "{v}");
    // Replacing a withdrawn file is 410 too — there is nothing to replace.
    let (s, v) = fx
        .put(
            &format!("/v1/files/{id}"),
            serde_json::json!({ "bytes_base64": BASE64.encode(b"three") }),
        )
        .await;
    assert_eq!((s, reason(&v)), (410, "drive.withdrawn"), "{v}");
}

// ─── Move ──────────────────────────────────────────────────────────────────

/// Move reseals at the TARGET room: the file reads back from the community
/// with the same bytes, and the self copy is withdrawn — unless `keep_source`.
/// Plus every move refusal: same room, bad target, and a target the owner is
/// not a member of.
#[tokio::test]
async fn move_reseals_at_the_target_room() {
    let fx = fixture().await;
    let community = fx.owners_community("circle", &[]).await;
    let strangers = fx.strangers_community().await;
    let id = fx
        .upload_self(b"going out asks", Some("post.txt"), "text/plain")
        .await;

    let (s, v) = fx
        .post(
            &format!("/v1/files/{id}/move"),
            serde_json::json!({ "cohort": "self" }),
        )
        .await;
    assert_eq!((s, reason(&v)), (409, "drive.same_room"), "{v}");
    let (s, v) = fx
        .post(
            &format!("/v1/files/{id}/move"),
            serde_json::json!({ "cohort": "galaxy" }),
        )
        .await;
    assert_eq!((s, reason(&v)), (400, "drive.bad_move_target"), "{v}");
    let (s, v) = fx
        .post(
            &format!("/v1/files/{id}/move"),
            serde_json::json!({ "cohort": "community" }),
        )
        .await;
    assert_eq!((s, reason(&v)), (400, "drive.bad_move_target"), "{v}");
    let (s, v) = fx
        .post(
            &format!("/v1/files/{id}/move"),
            serde_json::json!({ "cohort": "community", "room_id": strangers }),
        )
        .await;
    assert_eq!((s, reason(&v)), (403, "drive.not_a_member"), "{v}");

    // A COPY first: keep_source leaves the self row live.
    let (s, v) = fx
        .post(
            &format!("/v1/files/{id}/move"),
            serde_json::json!({ "cohort": "community", "room_id": community, "keep_source": true }),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["cohort"], "community");
    let copy_id = v["attestation_id"].as_str().unwrap().to_owned();
    assert_eq!(fx.read_bytes(&id, "").await, b"going out asks");
    assert_eq!(
        fx.read_bytes(&copy_id, &format!("cohort=community&room_id={community}"))
            .await,
        b"going out asks"
    );
    let (_, meta) = fx
        .get(&format!(
            "/v1/files/{copy_id}/meta?cohort=community&room_id={community}"
        ))
        .await;
    assert_eq!(
        meta["tier"], "CommunityDek",
        "resealed at the room's tier: {meta}"
    );
    assert_eq!(meta["holder_claims_recorded"], true, "{meta}");

    // Then a real MOVE of the copy back… no: of the original, into the room.
    let (s, v) = fx
        .post(
            &format!("/v1/files/{id}/move"),
            serde_json::json!({ "cohort": "community", "room_id": community }),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["replaces"], id.as_str());
    let (s, v) = fx.get(&format!("/v1/files/{id}")).await;
    assert_eq!(
        (s, reason(&v)),
        (410, "drive.withdrawn"),
        "the source is withdrawn: {v}"
    );

    // The community listing shows the moved file, and the drive's unfiltered
    // view reaches the community room.
    let (s, drive) = fx
        .get(&format!("/v1/drive?cohort=community&room_id={community}"))
        .await;
    assert_eq!(s, 200, "{drive}");
    assert_eq!(drive["entries"].as_array().unwrap().len(), 2, "{drive}");
    let (s, all) = fx.get("/v1/drive").await;
    assert_eq!(s, 200, "{all}");
    assert!(
        all["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["cohort"] == "community" && e["room_id"] == community.as_str()),
        "{all}"
    );
}

// ─── The policy matrix ─────────────────────────────────────────────────────

/// No session, a delegate, a non-member, a non-author — each refused by name
/// on every route it reaches.
#[tokio::test]
async fn the_policy_matrix() {
    let fx = fixture().await;
    let id = fx
        .upload_self(b"mine", Some("mine.txt"), "text/plain")
        .await;
    let strangers = fx.strangers_community().await;

    // NO SESSION: every route, read or write.
    let anon = reqwest::Client::new();
    for (method, path) in [
        ("GET", "/v1/drive".to_owned()),
        ("GET", format!("/v1/files/{id}")),
        ("GET", format!("/v1/files/{id}/meta")),
        ("POST", "/v1/files".to_owned()),
        ("PUT", format!("/v1/files/{id}")),
        ("DELETE", format!("/v1/files/{id}")),
        ("POST", format!("/v1/files/{id}/rename")),
        ("POST", format!("/v1/files/{id}/move")),
    ] {
        let url = format!("{}{path}", fx.base);
        let req = match method {
            "GET" => anon.get(url),
            "POST" => anon.post(url).json(&serde_json::json!({})),
            "PUT" => anon.put(url).json(&serde_json::json!({})),
            _ => anon.delete(url),
        };
        let (s, v) = status_json(req.send().await.expect("anon")).await;
        assert_eq!(
            (s, reason(&v)),
            (403, "drive.owner_session_required"),
            "{method} {path}: {v}"
        );
    }

    // A DELEGATE: signed in, acting for the owner — reads are the owner's
    // alone, and every write is refused as the delegate's, by name.
    let delegate = mint_delegated_token(&fx.engine, &fx.owner_id, OWNER_WA, "helper-agent").await;
    let as_delegate = |method: &'static str, path: String, body: serde_json::Value| {
        let client = fx.client.clone();
        let url = format!("{}{path}", fx.base);
        let token = delegate.clone();
        async move {
            let req = match method {
                "GET" => client.get(url),
                "POST" => client.post(url).json(&body),
                "PUT" => client.put(url).json(&body),
                _ => client.delete(url),
            };
            status_json(req.bearer_auth(token).send().await.expect("delegate")).await
        }
    };
    let (s, v) = as_delegate("GET", "/v1/drive".into(), serde_json::json!({})).await;
    assert_eq!(
        (s, reason(&v)),
        (403, "drive.owner_session_required"),
        "{v}"
    );
    for (method, path, body) in [
        (
            "POST",
            "/v1/files".to_owned(),
            serde_json::json!({ "cohort": "self", "bytes_base64": "aGk=" }),
        ),
        (
            "PUT",
            format!("/v1/files/{id}"),
            serde_json::json!({ "bytes_base64": "aGk=" }),
        ),
        ("DELETE", format!("/v1/files/{id}"), serde_json::json!({})),
        (
            "POST",
            format!("/v1/files/{id}/rename"),
            serde_json::json!({ "filename": "x" }),
        ),
        (
            "POST",
            format!("/v1/files/{id}/move"),
            serde_json::json!({ "cohort": "self" }),
        ),
    ] {
        let (s, v) = as_delegate(method, path.clone(), body).await;
        assert_eq!(
            (s, reason(&v)),
            (403, "drive.delegate_may_not_author"),
            "{method} {path}: {v}"
        );
    }
    let (s, v) = as_delegate(
        "POST",
        "/v1/notes".into(),
        serde_json::json!({ "body": "hi" }),
    )
    .await;
    assert_eq!(
        (s, reason(&v)),
        (403, "notes.delegate_may_not_author"),
        "{v}"
    );

    // A NON-MEMBER: the owner names a community they are not in.
    for path in [
        format!("/v1/drive?cohort=community&room_id={strangers}"),
        format!("/v1/files/{id}?cohort=community&room_id={strangers}"),
        format!("/v1/files/{id}/meta?cohort=community&room_id={strangers}"),
    ] {
        let (s, v) = fx.get(&path).await;
        assert_eq!((s, reason(&v)), (403, "drive.not_a_member"), "{path}: {v}");
    }
    let (s, v) = fx
        .post(
            "/v1/files",
            serde_json::json!({ "cohort": "community", "room_id": strangers, "bytes_base64": "aGk=" }),
        )
        .await;
    assert_eq!((s, reason(&v)), (403, "drive.not_a_member"), "{v}");
    let (s, v) = fx
        .delete(&format!(
            "/v1/files/{id}?cohort=community&room_id={strangers}"
        ))
        .await;
    assert_eq!((s, reason(&v)), (403, "drive.not_a_member"), "{v}");

    // Unknown ids, unknown cohorts, bad bodies.
    let (s, v) = fx.get("/v1/files/file-nope").await;
    assert_eq!((s, reason(&v)), (404, "drive.not_in_room"), "{v}");
    let (s, v) = fx.get(&format!("/v1/files/{id}?cohort=galaxy")).await;
    assert_eq!((s, reason(&v)), (400, "drive.unknown_cohort"), "{v}");
    let (s, v) = fx
        .post("/v1/files", serde_json::json!({ "bytes_base64": "aGk=" }))
        .await;
    assert_eq!((s, reason(&v)), (400, "drive.bad_body"), "no cohort: {v}");
    let (s, v) = fx
        .post(
            "/v1/files",
            serde_json::json!({ "cohort": "self", "bytes_base64": "%%%" }),
        )
        .await;
    assert_eq!((s, reason(&v)), (400, "drive.bad_base64"), "{v}");
    let (s, v) = fx
        .post(
            "/v1/files",
            serde_json::json!({ "cohort": "family", "bytes_base64": "aGk=" }),
        )
        .await;
    assert_eq!((s, reason(&v)), (400, "drive.family_id_required"), "{v}");
}

/// **Only the author changes a file.** A member of the owner's community who
/// is not this node writes a file there; the owner can READ it (membership),
/// and every change route refuses `drive.not_author`.
#[tokio::test]
async fn a_non_author_cannot_change_a_file() {
    let fx = fixture().await;
    // Erin: a registered hybrid identity, a member of the room, publishing
    // through edge's own file door with her own key.
    let erin = "erin-drive";
    seed_key(&fx.engine, erin, 0xE0, 0xE1, identity_type::USER).await;
    let community = fx.owners_community("shared", &[erin]).await;
    // The owner's content occurrence on this node — what the room's DEK is
    // wrapped to, so erin's file is readable by somebody.
    ciris_server::backend::provision_engine_occurrence(&fx.engine, &fx.owner_id.key_id)
        .await
        .expect("provision the owner's content occurrence");
    let erin_signer = edge_signer_for(erin, 0xE0, 0xE1);
    let room = ciris_edge::scope_room::ScopeRoom::community(community.clone());
    let store = ciris_edge::group_content::PersistGroupContentStore::new(
        (*fx.engine).clone(),
        fx.engine.federation_directory(),
    );
    let published = ciris_edge::files::publish(
        &*fx.engine.federation_directory(),
        &store,
        ciris_edge::replication::attestation_bind::Signers {
            node: &erin_signer,
            actor: None,
        },
        &ciris_edge::files::FileWrite {
            room: &room,
            bytes: b"erin's words",
            media_type: "text/plain",
            filename: Some("erin.txt"),
            asserted_at: chrono::Utc::now(),
        },
    )
    .await
    .expect("erin publishes into the room");
    let erins = match &published.shared {
        ciris_edge::replication::attestation_bind::Shared::Placed { attestation_id }
        | ciris_edge::replication::attestation_bind::Shared::AlreadyThere { attestation_id } => {
            attestation_id.clone()
        }
        other => panic!("erin's file did not cross: {other:?}"),
    };
    let q = format!("cohort=community&room_id={community}");

    let (s, meta) = fx.get(&format!("/v1/files/{erins}/meta?{q}")).await;
    assert_eq!(s, 200, "the owner can see a member's file: {meta}");
    assert_eq!(meta["author_key_id"], erin);

    for (method, path, body) in [
        (
            "PUT",
            format!("/v1/files/{erins}?{q}"),
            serde_json::json!({ "bytes_base64": "aGk=" }),
        ),
        (
            "DELETE",
            format!("/v1/files/{erins}?{q}"),
            serde_json::json!({}),
        ),
        (
            "POST",
            format!("/v1/files/{erins}/rename?{q}"),
            serde_json::json!({ "filename": "mine-now.txt" }),
        ),
        (
            "POST",
            format!("/v1/files/{erins}/move?{q}"),
            serde_json::json!({ "cohort": "self" }),
        ),
    ] {
        let url = format!("{}{path}", fx.base);
        let req = match method {
            "PUT" => fx.client.put(url).json(&body),
            "POST" => fx.client.post(url).json(&body),
            _ => fx.client.delete(url),
        };
        let (s, v) = status_json(req.bearer_auth(&fx.owner).send().await.expect("req")).await;
        assert_eq!(
            (s, reason(&v)),
            (403, "drive.not_author"),
            "{method} {path}: {v}"
        );
    }
    // And the file is untouched.
    let (_, meta) = fx.get(&format!("/v1/files/{erins}/meta?{q}")).await;
    assert_eq!(meta["withdrawn"], false, "{meta}");
}

/// An upload above the cap is refused by name (`drive.too_large`), not by
/// axum's plain-text length error.
#[tokio::test]
async fn an_upload_above_the_cap_is_too_large() {
    let fx = fixture().await;
    let body = vec![b'a'; ciris_server::drive::UPLOAD_BODY_LIMIT + 1];
    let (s, v) = status_json(
        fx.client
            .post(format!("{}/v1/files", fx.base))
            .bearer_auth(&fx.owner)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .expect("oversized POST"),
    )
    .await;
    assert_eq!((s, reason(&v)), (413, "drive.too_large"), "{v}");
    // Other routes keep axum's default: a 3 MB rename body is refused.
    let (s, _) = status_json(
        fx.client
            .post(format!("{}/v1/files/x/rename", fx.base))
            .bearer_auth(&fx.owner)
            .header("content-type", "application/json")
            .body(vec![b' '; 3 * 1024 * 1024])
            .send()
            .await
            .expect("big rename"),
    )
    .await;
    assert_eq!(s, 400, "the raised limit is the upload routes' only");
}

/// A file above the whole-read cap (only reachable from a peer — this node's
/// own upload cap is the same number) is `413 drive.too_large_for_whole_read`
/// on the JSON read, and still served by `Range`.
#[tokio::test]
async fn a_file_above_the_whole_read_cap_is_read_by_range() {
    let fx = fixture().await;
    // Straight through edge's door, as a peer's file arrives: the HTTP upload
    // would refuse it (drive.too_large) before it was ever sealed.
    let owner_room = ciris_edge::self_room::room(&fx.owner_id.key_id);
    ciris_server::backend::provision_engine_occurrence(&fx.engine, &fx.owner_id.key_id)
        .await
        .expect("provision the content occurrence");
    let big = vec![7u8; ciris_server::drive::WHOLE_READ_CAP + 3];
    let store = ciris_edge::group_content::PersistGroupContentStore::new(
        (*fx.engine).clone(),
        fx.engine.federation_directory(),
    );
    let node = node_edge_signer(&fx.engine).await;
    let published = ciris_edge::files::publish(
        &*fx.engine.federation_directory(),
        &store,
        ciris_edge::replication::attestation_bind::Signers {
            node: &node,
            actor: None,
        },
        &ciris_edge::files::FileWrite {
            room: &owner_room,
            bytes: &big,
            media_type: "video/mp4",
            filename: Some("long.mp4"),
            asserted_at: chrono::Utc::now(),
        },
    )
    .await
    .expect("seal a file above the whole-read cap");
    let id = published.row.attestation_id.clone();
    let (s, v) = fx.get(&format!("/v1/files/{id}")).await;
    assert_eq!(
        (s, reason(&v)),
        (413, "drive.too_large_for_whole_read"),
        "{v}"
    );
    let (s, v) = fx.get(&format!("/v1/files/{id}?raw=1")).await;
    assert_eq!(
        (s, reason(&v)),
        (413, "drive.too_large_for_whole_read"),
        "{v}"
    );
    let resp = fx
        .client
        .get(format!("{}/v1/files/{id}?raw=1", fx.base))
        .bearer_auth(&fx.owner)
        .header("range", "bytes=-4")
        .send()
        .await
        .expect("range GET");
    assert_eq!(resp.status(), 206);
    assert_eq!(resp.bytes().await.unwrap().to_vec(), vec![7u8; 4]);
    let (_, meta) = fx.get(&format!("/v1/files/{id}/meta")).await;
    assert_eq!(meta["size"], big.len() as u64, "{meta}");
}

// ─── Notes ─────────────────────────────────────────────────────────────────

/// Notes edit and delete through the same machinery: an edit is a new note and
/// a withdrawn old one; a delete is a withdrawal; a file that is not a note is
/// `notes.not_found`.
#[tokio::test]
async fn notes_edit_and_delete() {
    let fx = fixture().await;
    let (s, v) = fx
        .post("/v1/notes", serde_json::json!({ "body": "first draft" }))
        .await;
    assert_eq!(s, 200, "{v}");
    let note = v["attestation_id"].as_str().unwrap().to_owned();
    let other = fx
        .post("/v1/notes", serde_json::json!({ "body": "keep" }))
        .await
        .1["attestation_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let (s, v) = fx
        .put(
            &format!("/v1/notes/{note}"),
            serde_json::json!({ "body": "  " }),
        )
        .await;
    assert_eq!((s, reason(&v)), (400, "notes.empty"), "{v}");
    let (s, v) = fx
        .put(
            &format!("/v1/notes/{note}"),
            serde_json::json!({ "body": "second draft" }),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let edited = v["attestation_id"].as_str().unwrap().to_owned();
    assert_eq!(v["replaces"], note.as_str());

    let (_, list) = fx.get("/v1/notes").await;
    let bodies: Vec<&str> = list["notes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|n| n["body"].as_str())
        .collect();
    assert!(bodies.contains(&"second draft"), "{list}");
    assert!(bodies.contains(&"keep"), "{list}");
    assert!(
        !bodies.contains(&"first draft"),
        "the edited note is gone: {list}"
    );

    let (s, v) = fx.delete(&format!("/v1/notes/{edited}")).await;
    assert_eq!(s, 200, "{v}");
    let (_, list) = fx.get("/v1/notes").await;
    let ids: Vec<&str> = list["notes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["attestation_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![other.as_str()], "{list}");

    // Gone, and not-a-note, are both notes.not_found.
    let (s, v) = fx.delete(&format!("/v1/notes/{edited}")).await;
    assert_eq!((s, reason(&v)), (404, "notes.not_found"), "{v}");
    let file = fx
        .upload_self(b"a named file", Some("n.txt"), "text/plain")
        .await;
    let (s, v) = fx
        .put(
            &format!("/v1/notes/{file}"),
            serde_json::json!({ "body": "x" }),
        )
        .await;
    assert_eq!((s, reason(&v)), (404, "notes.not_found"), "{v}");
    let (s, v) = fx.delete("/v1/notes/file-nope").await;
    assert_eq!((s, reason(&v)), (404, "notes.not_found"), "{v}");
}

// ─── 0.5.217: the write gate, one byte-state vocabulary, digests, policy ────

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// CIRISServer#642 — a file must be what it says it is, and its name is
/// display-only. Every refusal id, and the cleanup that is not a refusal.
#[tokio::test]
async fn the_write_gate_refuses_a_lie_and_cleans_a_name() {
    let fx = fixture().await;
    let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F'];
    let post = |media: &str, name: Option<&str>, bytes: &[u8]| {
        let mut body = serde_json::json!({
            "cohort": "self", "bytes_base64": b64(bytes), "media_type": media,
        });
        if let Some(n) = name {
            body["filename"] = serde_json::json!(n);
        }
        body
    };

    // Not an RFC 6838 essence.
    let (s, v) = fx.post("/v1/files", post("jpeg", None, &jpeg)).await;
    assert_eq!((s, reason(&v)), (400, "drive.bad_media_type"), "{v}");

    // JPEG bytes declared PNG: 415, naming both.
    let (s, v) = fx.post("/v1/files", post("image/png", None, &jpeg)).await;
    assert_eq!((s, reason(&v)), (415, "drive.format_mismatch"), "{v}");
    assert_eq!(v["declared"], "image/png");
    assert_eq!(v["sniffed"], "image/jpeg");

    // An executable declared as a PDF.
    let (s, v) = fx
        .post(
            "/v1/files",
            post("application/pdf", None, b"MZ\x90\x00\x03"),
        )
        .await;
    assert_eq!((s, reason(&v)), (415, "drive.format_mismatch"), "{v}");

    // Binary declared as text.
    let (s, v) = fx
        .post("/v1/files", post("text/plain", None, b"a\0b"))
        .await;
    assert_eq!((s, reason(&v)), (415, "drive.format_mismatch"), "{v}");

    // A name that is nothing but a bidi override.
    let (s, v) = fx
        .post("/v1/files", post("text/plain", Some("\u{202E}"), b"hi"))
        .await;
    assert_eq!((s, reason(&v)), (400, "drive.bad_filename"), "{v}");

    // Honest: a JPEG declared JPEG (case and parameters normalised), with a
    // bidi-spoofed, path-carrying name that is CLEANED, not refused.
    let (s, v) = fx
        .post(
            "/v1/files",
            post(
                "Image/JPEG; q=1",
                Some("../x/invoice\u{202E}gpj.exe"),
                &jpeg,
            ),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let id = v["attestation_id"].as_str().expect("id").to_owned();
    let (_, drive) = fx.get("/v1/drive?cohort=self").await;
    let row = drive["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|e| e["attestation_id"] == id.as_str())
        .expect("listed");
    assert_eq!(row["filename"], "invoicegpj.exe", "path and bidi removed");
    assert_eq!(
        row["media_type"], "image/jpeg",
        "the stored type is the essence"
    );

    // Rename runs the same cleanup.
    let (s, v) = fx
        .post(
            &format!("/v1/files/{id}/rename?cohort=self"),
            serde_json::json!({ "filename": "a/b/\u{200B}new\u{202E}.jpg" }),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let renamed = v["attestation_id"].as_str().expect("new id").to_owned();
    let (_, meta) = fx
        .get(&format!("/v1/files/{renamed}/meta?cohort=self"))
        .await;
    assert_eq!(meta["filename"], "new.jpg", "{meta}");
}

/// CIRISServer#641 — the node states the PLAINTEXT digest of what it hands
/// over (CC 5.3.2.5), on open and on meta, and names the at-rest hash for what
/// it is. CIRISServer#644 — notes use the drive's word for the same fact.
#[tokio::test]
async fn digests_are_of_the_plaintext_and_notes_say_here() {
    use sha2::{Digest as _, Sha256};
    let fx = fixture().await;
    let text = b"verify me before you render me".to_vec();
    let want = hex::encode(Sha256::digest(&text));
    let id = fx.upload_self(&text, Some("v.txt"), "text/plain").await;

    let (s, v) = fx.get(&format!("/v1/files/{id}?cohort=self")).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["content_digest"], want.as_str());
    assert_eq!(v["content_digest_alg"], "sha-256");
    assert_eq!(v["size"], text.len());

    let (s, meta) = fx.get(&format!("/v1/files/{id}/meta?cohort=self")).await;
    assert_eq!(s, 200, "{meta}");
    assert_eq!(meta["content_digest"], want.as_str());
    assert_ne!(
        meta["at_rest_sha256"],
        want.as_str(),
        "the at-rest hash is of the SEALED blob, never the plaintext"
    );

    let raw = fx
        .client
        .get(format!("{}/v1/files/{id}?cohort=self&raw=1", fx.base))
        .bearer_auth(&fx.owner)
        .send()
        .await
        .expect("raw GET");
    let rd = raw
        .headers()
        .get("repr-digest")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .expect("Repr-Digest on a whole raw read");
    assert_eq!(rd, format!("sha-256=:{}:", b64(&Sha256::digest(&text))));

    let (s, _) = fx
        .post("/v1/notes", serde_json::json!({ "body": "a note" }))
        .await;
    assert_eq!(s, 200);
    let (_, notes) = fx.get("/v1/notes").await;
    let states: Vec<&str> = notes["notes"]
        .as_array()
        .expect("notes")
        .iter()
        .filter_map(|n| n["state"].as_str())
        .collect();
    assert!(
        !states.is_empty() && states.iter().all(|s| *s == "here"),
        "a readable note says `here`, like the drive: {states:?}"
    );
}

/// CIRISServer#643 — the policy is public and says no rendition will come.
#[tokio::test]
async fn the_media_policy_is_published() {
    let fx = fixture().await;
    let resp = fx
        .client
        .get(format!("{}/v1/media/policy", fx.base))
        .send()
        .await
        .expect("policy GET without a session");
    assert_eq!(resp.status().as_u16(), 200);
    let v: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(v["renditions"], false);
    assert_eq!(v["tier_a"]["image/jpeg"]["max_pixels"], 33_000_000);
    assert!(v["tier_b_convert_at_sender"]
        .as_array()
        .expect("tier b")
        .iter()
        .any(|t| t == "image/heic"));
}

/// Run the ladder's transfer-corpus generator (`harness/mesh-repro/lib/
/// media_corpus.py`) into a fresh directory and return its manifest. ONE
/// corpus for both proofs: this test (the write gate, the seal, the chunk
/// path and the read, on every CI platform) and the self-files ladder (the
/// crossing to a second device). A Rust copy of the fixtures would be a
/// second list that drifts from the first.
fn transfer_corpus() -> (std::path::PathBuf, Vec<serde_json::Value>) {
    let dir = std::env::temp_dir().join(format!(
        "ciris-corpus-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("harness/mesh-repro/lib/media_corpus.py");
    // `python3` on Linux and macOS; Windows runners ship `python`. A runner with
    // neither fails here, loudly — a corpus test that skips is a test of nothing.
    let ran = ["python3", "python"].iter().find_map(|py| {
        std::process::Command::new(py)
            .arg(&script)
            .arg(&dir)
            .output()
            .ok()
            .filter(|o| o.status.success())
    });
    assert!(
        ran.is_some(),
        "could not run {} with python3 or python",
        script.display()
    );
    let manifest: Vec<serde_json::Value> = serde_json::from_str(
        &std::fs::read_to_string(dir.join("manifest.json")).expect("corpus manifest"),
    )
    .expect("manifest is JSON");
    (dir, manifest)
}

/// **Every type the node supports, at every size class, round-trips
/// byte-identical** (0.5.218; the maintainer's bar: "file transfer 100%
/// predictable and reliable across platforms and file types we support").
///
/// Each corpus file is uploaded through the real write gate and read back
/// raw: same bytes (SHA-256 against the generator's), the declared type
/// returned as `Content-Type`, the drive listing it `here` with its size and
/// name, and the JSON read's `content_digest` the plaintext's. The corpus
/// covers the media policy's tiers A, B and C, a zip container and the honest
/// `application/octet-stream`, and the sizes either side of the 1 MiB inline
/// boundary plus a 24 MiB chunk DAG. This runs on Linux, macOS and Windows in
/// CI; the self-files ladder carries the same corpus to a second device.
#[tokio::test]
async fn every_supported_type_round_trips_byte_identical() {
    use sha2::{Digest, Sha256};
    let fx = fixture().await;
    let (dir, manifest) = transfer_corpus();
    assert!(
        manifest.len() >= 20,
        "the corpus shrank: {}",
        manifest.len()
    );

    // EVERY failure, not the first: one refused type must not hide another.
    let mut failures: Vec<String> = Vec::new();
    let mut ids: Vec<(serde_json::Value, String)> = Vec::new();
    for row in &manifest {
        let name = row["name"].as_str().expect("name");
        let media = row["media_type"].as_str().expect("media_type");
        let filename = row["filename"].as_str().expect("filename");
        let bytes = std::fs::read(dir.join(name)).expect("corpus file");
        let (s, v) = status_json(
            fx.client
                .post(format!("{}/v1/files", fx.base))
                .bearer_auth(&fx.owner)
                .json(&serde_json::json!({
                    "cohort": "self",
                    "bytes_base64": BASE64.encode(&bytes),
                    "media_type": media,
                    "filename": filename,
                }))
                .send()
                .await
                .expect("POST /v1/files"),
        )
        .await;
        // A KNOWN_DEFECTS row (lib/media_corpus.py) must fail as its issue says,
        // and a pass is red too: the upstream fix landed and the mark must go.
        if let Some(issue) = row["known_defect"].as_str() {
            if s == 200 {
                failures.push(format!(
                    "{name}: marked KNOWN DEFECT ({issue}) but it now uploads — the fix landed; \
                     remove it from KNOWN_DEFECTS in harness/mesh-repro/lib/media_corpus.py"
                ));
            }
            continue;
        }
        match v["attestation_id"].as_str() {
            Some(id) if s == 200 => ids.push((row.clone(), id.to_owned())),
            _ => failures.push(format!(
                "{name} ({media}, {} bytes): upload {s} {}",
                bytes.len(),
                v["reason_id"]
            )),
        }
    }

    let (s, drive) = fx.get("/v1/drive?cohort=self&limit=500").await;
    assert_eq!(s, 200, "{drive}");
    let entries = drive["entries"].as_array().expect("entries").clone();

    for (row, id) in &ids {
        let name = row["name"].as_str().unwrap();
        let want_sha = row["sha256"].as_str().unwrap();
        let media = row["media_type"].as_str().unwrap();
        let resp = fx
            .client
            .get(format!("{}/v1/files/{id}?cohort=self&raw=1", fx.base))
            .bearer_auth(&fx.owner)
            .send()
            .await
            .expect("raw GET");
        let status = resp.status().as_u16();
        let ctype = resp
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let got = resp.bytes().await.expect("body");
        if status != 200 {
            failures.push(format!("{name}: raw read {status}"));
            continue;
        }
        if ctype != media {
            failures.push(format!(
                "{name}: Content-Type {ctype:?}, declared {media:?}"
            ));
        }
        let sha = hex::encode(Sha256::digest(&got));
        if sha != want_sha {
            failures.push(format!(
                "{name} ({media}): {} bytes back, digest differs from the bytes written",
                got.len()
            ));
        }
        match entries.iter().find(|e| e["attestation_id"] == id.as_str()) {
            None => failures.push(format!("{name}: missing from the drive")),
            Some(e) => {
                for (k, want) in [
                    ("bytes", serde_json::json!("here")),
                    ("size", row["size"].clone()),
                    ("media_type", serde_json::json!(media)),
                    ("filename", row["filename"].clone()),
                ] {
                    if e[k] != want {
                        failures.push(format!("{name}: drive {k} = {}, want {want}", e[k]));
                    }
                }
            }
        }
        if row["size"].as_u64().unwrap() <= 2 * 1024 * 1024 {
            let (s, v) = fx.get(&format!("/v1/files/{id}?cohort=self")).await;
            if s != 200 || v["content_digest"] != want_sha {
                failures.push(format!(
                    "{name}: JSON read {s}, content_digest {}",
                    v["content_digest"]
                ));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        failures.is_empty(),
        "{} of {} corpus files did not round-trip:\n  {}",
        failures.len(),
        manifest.len(),
        failures.join("\n  ")
    );
}
