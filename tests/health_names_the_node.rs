//! **A held port can be asked who holds it** (CIRISServer#410).
//!
//! The incident: an embedded-fold restart found the read-API port already
//! answering, and the operator could not tell their own node's previous
//! process from a foreign CIRIS node from a non-CIRIS squatter — every case
//! surfaced as the same opaque `Address already in use`. Every health route
//! now carries a `node` block naming the answering process; these tests pin
//! the properties a port probe relies on.
//!
//! PROCESS-GLOBAL STATE DISCIPLINE: `node_identity` is a process-wide static
//! shared by every test in this binary. Exactly ONE test here calls `stamp()`
//! (the lifecycle test), so its pre-stamp assertions see the genuinely fresh
//! state, and no other test asserts a specific `standing`. Adding a second
//! `stamp()` caller to this file would break that ordering-independence —
//! don't.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _; // for `oneshot`

use ciris_server::health;
use ciris_server::node_identity;

async fn get_json(path: &str) -> serde_json::Value {
    let app = health::router();
    let resp = app
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("collect body");
    serde_json::from_slice(&bytes).expect("json")
}

/// The `node` block for `path`, wherever that route carries it (`/health` is a
/// bare object; the `/v1` routes wrap it in the `{"data":{…}}` envelope).
async fn node_block(path: &str) -> serde_json::Value {
    let body = get_json(path).await;
    body.get("node")
        .or_else(|| body.get("data").and_then(|d| d.get("node")))
        .cloned()
        .unwrap_or_else(|| panic!("{path} must carry a `node` block: {body}"))
}

/// The axis-fusion guard: `local_json()` (the in-process superset) and
/// `wire_json()` (the served block) are two readers of ONE fact and must
/// agree on every shared field. Called at BOTH lifecycle states below, so
/// neither rendering can drift alone.
fn assert_accessor_agrees_with_wire() {
    let wire = node_identity::wire_json();
    let local: serde_json::Value =
        serde_json::from_str(&node_identity::local_json()).expect("local_json parses");
    for field in ["standing", "instance_id", "started_at", "key_id", "home_id"] {
        assert_eq!(
            wire[field], local[field],
            "local_json and wire_json must agree on `{field}` — two readers of \
             one fact must not be able to disagree"
        );
    }
}

/// Every health route names the answering process: a probe must not need to
/// know which of the three routes the listener serves best.
#[tokio::test]
async fn every_health_route_carries_the_node_block() {
    for path in ["/health", "/v1/health", "/v1/system/health"] {
        let node = node_block(path).await;
        assert!(
            node["instance_id"].is_string(),
            "{path} must name the instance: {node}"
        );
        assert!(
            node["started_at"].is_string(),
            "{path} must date the instance: {node}"
        );
        let standing = node["standing"].as_str().unwrap_or_default();
        assert!(
            standing == "identified" || standing == "unresolved",
            "{path}: standing must be one of the two NAMED states, got: {node}"
        );
    }
}

/// One process, one name: two reads agree, and the name is well-formed enough
/// to match against the boot log line (v4 UUID) and to order against another
/// holder's claim (RFC3339 started_at).
#[tokio::test]
async fn the_instance_id_is_stable_and_well_formed() {
    let a = node_block("/health").await;
    let b = node_block("/v1/health").await;
    assert_eq!(
        a["instance_id"], b["instance_id"],
        "two reads must name the SAME instance"
    );
    assert_eq!(a["started_at"], b["started_at"]);
    assert_v4_uuid(a["instance_id"].as_str().expect("instance_id is a string"));
    let started = a["started_at"].as_str().expect("started_at is a string");
    chrono::DateTime::parse_from_rfc3339(started)
        .unwrap_or_else(|e| panic!("started_at must parse as RFC3339 ({started}): {e}"));
}

/// Shape-level v4 check (8-4-4-4-12 lowercase hex, version nibble `4`,
/// RFC 4122 variant) — asserted without a uuid parser so the test pins the
/// WIRE form, not a library's tolerance.
fn assert_v4_uuid(id: &str) {
    let chars: Vec<char> = id.chars().collect();
    assert_eq!(chars.len(), 36, "uuid wire length: {id}");
    for (i, c) in chars.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => assert_eq!(*c, '-', "hyphen at {i}: {id}"),
            _ => assert!(
                c.is_ascii_hexdigit() && !c.is_ascii_uppercase(),
                "lowercase hex at {i}: {id}"
            ),
        }
    }
    assert_eq!(chars[14], '4', "version nibble must say v4: {id}");
    assert!(
        matches!(chars[19], '8' | '9' | 'a' | 'b'),
        "RFC 4122 variant nibble: {id}"
    );
}

/// The full lifecycle in ONE test because the state is process-global.
///
/// BEFORE `stamp()`: the node still names its instance — "I can't name myself
/// yet" must never collapse into "no answer"; that is the whole point of a
/// NAMED `unresolved` standing (the distinct-zeroes discipline).
///
/// AFTER `stamp()`: identified, the key echoes, `home_id` is a fingerprint and
/// never any part of the path (the read API binds 0.0.0.0 and the home path
/// carries the OS username) — and the in-process accessor agrees with the wire
/// at every step.
#[tokio::test]
async fn an_unresolved_node_still_names_its_instance_and_a_stamp_identifies_it() {
    // ── BEFORE stamp(): the sole stamp() caller in this binary is below, so
    //    this reads the genuinely fresh process state. ──────────────────────
    let node = node_block("/health").await;
    assert_eq!(
        node["standing"], "unresolved",
        "before compose derives the key, the state is NAMED, not absent: {node}"
    );
    assert!(
        node["key_id"].is_null(),
        "unresolved renders key_id as an EXPLICIT null: {node}"
    );
    assert!(node["home_id"].is_null());
    assert!(
        node["instance_id"].is_string(),
        "an unresolved node must STILL name its instance — 'cannot answer' is \
         not 'no answer': {node}"
    );
    assert_accessor_agrees_with_wire();

    // ── stamp() — what compose does the moment the one key_id exists. The
    //    home path is deliberately hex-alphabet: if home_id were ever derived
    //    by slicing or inlining the path, the substring assertions below
    //    could not pass by accident. ─────────────────────────────────────────
    let home = std::path::Path::new("/tmp/deadbeef00c0ffee/ciris-home-410");
    node_identity::stamp("test-node-key-410", home);

    let node = node_block("/v1/health").await;
    assert_eq!(node["standing"], "identified");
    assert_eq!(
        node["key_id"], "test-node-key-410",
        "the stamped key_id must echo on the wire: {node}"
    );
    let home_id = node["home_id"]
        .as_str()
        .expect("home_id present once identified");
    assert_eq!(
        home_id.len(),
        16,
        "home_id is a 16-hex fingerprint: {home_id}"
    );
    assert!(
        home_id.chars().all(|c| c.is_ascii_hexdigit()),
        "home_id is hex: {home_id}"
    );
    // THE PRIVACY ASSERTION: the fingerprint is not a slice of the path, and
    // the path appears NOWHERE in the wire block.
    assert!(
        !home.to_string_lossy().contains(home_id),
        "home_id must be a hash of the path, never a substring of it: {home_id}"
    );
    let wire_text = serde_json::to_string(&node).expect("serialize wire block");
    assert!(
        !wire_text.contains("deadbeef00c0ffee") && !wire_text.contains("ciris-home-410"),
        "the home PATH must never ride the wire (it leaks the OS username on \
         0.0.0.0): {wire_text}"
    );
    assert_accessor_agrees_with_wire();

    // The LOCAL accessor is the superset — the process owner may see the full
    // path, the pid and the bound addr; the wire may not.
    let local: serde_json::Value =
        serde_json::from_str(&node_identity::local_json()).expect("local_json parses");
    // Compared against the SAME absolutization the stamp performs, not against
    // the literal above: `stamp` resolves the path so the fingerprint cannot
    // vary with the process's cwd, and on Windows that turns `/tmp/...` into
    // `D:\tmp\...`. Re-stating the POSIX spelling here asserted the test
    // host's path syntax rather than the property — and failed the whole
    // windows leg of CI on exactly that.
    let expected_home = std::path::absolute(home)
        .unwrap_or_else(|_| home.to_path_buf())
        .display()
        .to_string();
    assert_eq!(
        local["home"], expected_home,
        "the local accessor exposes the RESOLVED home path in full — that is \
         the whole difference between it and the wire block"
    );
    assert!(local["pid"].is_u64(), "local carries the pid: {local}");
}

/// The four-way port-holder verdict, exhaustively — and the property that
/// matters most: a MISSING `node` block is `unverifiable`, NEVER `match`.
/// "The port did not answer the question" must not read as "the port is us" —
/// that guess is how an operator kills the wrong process.
#[test]
fn a_missing_node_block_is_unverifiable_never_a_match() {
    use ciris_server::node_identity::{port_holder_verdict, PortHolderVerdict as V};
    let ours_id = "11111111-2222-4333-8444-555555555555";
    let ours_key = Some("key-ours");

    // match: the same instance answered — we probed our own listener.
    let same = serde_json::json!({"node": {"instance_id": ours_id, "key_id": "key-ours"}});
    assert_eq!(
        port_holder_verdict(ours_id, ours_key, Some(&same)),
        V::Match
    );
    // …and the `data`-enveloped shape (`/v1/*`) reads the same way.
    let entoure =
        serde_json::json!({"data": {"node": {"instance_id": ours_id, "key_id": "key-ours"}}});
    assert_eq!(
        port_holder_verdict(ours_id, ours_key, Some(&entoure)),
        V::Match
    );

    // mismatch_same_key: OUR node identity in a DIFFERENT process — the stale
    // prior serve this whole feature exists to name.
    let stale =
        serde_json::json!({"node": {"instance_id": "another-process", "key_id": "key-ours"}});
    assert_eq!(
        port_holder_verdict(ours_id, ours_key, Some(&stale)),
        V::MismatchSameKey
    );

    // mismatch_foreign: someone else's CIRIS node.
    let foreign =
        serde_json::json!({"node": {"instance_id": "another-process", "key_id": "key-theirs"}});
    assert_eq!(
        port_holder_verdict(ours_id, ours_key, Some(&foreign)),
        V::MismatchForeign
    );

    // unverifiable — every "cannot answer" shape, none of which may collapse:
    // nothing parseable answered at all;
    assert_eq!(
        port_holder_verdict(ours_id, ours_key, None),
        V::Unverifiable
    );
    // an answer with NO node block (a pre-#410 node, or not a CIRIS node);
    let no_block = serde_json::json!({"status": "ok"});
    assert_eq!(
        port_holder_verdict(ours_id, ours_key, Some(&no_block)),
        V::Unverifiable
    );
    // a different instance whose key is unresolved: the mismatch is known but
    // the same-key/foreign split is NOT — refusing to guess it is the point;
    let unresolved =
        serde_json::json!({"node": {"instance_id": "another-process", "key_id": null}});
    assert_eq!(
        port_holder_verdict(ours_id, ours_key, Some(&unresolved)),
        V::Unverifiable
    );
    // and symmetrically when WE are the side that cannot name a key yet.
    assert_eq!(
        port_holder_verdict(ours_id, None, Some(&foreign)),
        V::Unverifiable
    );
}
