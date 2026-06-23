//! STAGE 2 gate — nodes A & B upgraded to the 0.5.35 SUBSTRATE. Probes each node's
//! **`/v1/health`** (`{"data":{"version":…}}`) and asserts the EMBEDDED ciris-server
//! version ≥ 0.5.35. RED until both bridge nodes are redeployed on the new floor.
//!   CIRIS_GATE_NODE_A=https://node-a… CIRIS_GATE_NODE_B=https://node-b… \
//!     cargo test --test release_gates -- --include-ignored stage2
//!
//! WHY `/v1/health`.`data.version` and not plain `/health`: a node may wrap
//! ciris-server in an adapter (CIRISStatus = ciris-server + StatusAdapter) whose
//! OWN `/health` reports the WRAPPER's package version (e.g. status 0.3.x), not the
//! substrate. The StatusAdapter does NOT override `/v1/health`, so it passes through
//! to ciris-server's `server_health()` which reports ciris-server's own
//! `CARGO_PKG_VERSION` — the embedded substrate version. That is the floor signal
//! this gate must measure, uniformly across a bare node (A) and a wrapped node (B).

use crate::support::{blocked, http_get, node_url};

const MIN_VERSION: (u32, u32, u32) = (0, 5, 36);

fn parse_semver(v: &str) -> Option<(u32, u32, u32)> {
    let core = v.trim().trim_start_matches('v');
    let core = core.split(['-', '+']).next()?;
    let mut it = core.split('.');
    Some((
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    ))
}

fn assert_node_on_floor(which: &str) {
    let Some(base) = node_url(which) else {
        blocked(
            &format!("2 (node {which})"),
            &format!("set CIRIS_GATE_NODE_{which}=<base-url> then redeploy that node on 0.5.35"),
        );
    };
    let url = format!("{}/v1/health", base.trim_end_matches('/'));
    let (status, body) = match http_get(&url) {
        Ok(r) => r,
        Err(e) => blocked(
            &format!("2 (node {which})"),
            &format!("{url} unreachable: {e}"),
        ),
    };
    assert_eq!(status, 200, "{url} returned {status}, expected 200");
    let v: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("{url} body not JSON: {e}"));
    // `/v1/health` is the `{"data":{…}}` envelope; the embedded ciris-server version
    // is `data.version` (tolerate a bare `version` too, for a raw probe).
    let ver = v
        .get("data")
        .and_then(|d| d.get("version"))
        .or_else(|| v.get("version"))
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("{url} has no data.version field"));
    let parsed = parse_semver(ver).unwrap_or_else(|| panic!("unparseable version {ver}"));
    assert!(
        parsed >= MIN_VERSION,
        "node {which} is {ver}, must be ≥ 0.5.35 (upgrade not yet deployed)"
    );
}

#[test]
#[ignore = "release gate (external fact): RED until node A is redeployed on 0.5.35; run with --include-ignored"]
fn gate2_node_a_upgraded() {
    assert_node_on_floor("A");
}

#[test]
#[ignore = "release gate (external fact): RED until node B is redeployed on 0.5.35; run with --include-ignored"]
fn gate2_node_b_upgraded() {
    assert_node_on_floor("B");
}
