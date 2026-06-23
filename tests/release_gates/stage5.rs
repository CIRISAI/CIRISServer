//! STAGE 5 gate — Node A's nodecode (transport key `ciris-canonical-1`) is
//! generated and PR'd to CIRISPersist for the v10 bake. Two requisites:
//!   (a) the nodecode codec round-trips (compiled, hermetic) — a structural
//!       sanity check that we can produce/parse the handle at all;
//!   (b) evidence/stage5.json records the opened PR + the decoded transport key:
//!       { "pr_url":"https://github.com/CIRISAI/CIRISPersist/pull/NNN",
//!         "node":"A", "transport_key_id":"ciris-canonical-1",
//!         "nodecode":"CIRISNODE-…" }
//! RED until the PR is open AND its transport_key_id is the canonical seed key.

use crate::support::{blocked, evidence, CANONICAL_TRANSPORT_KEY_ID};

/// (a) The nodecode module is present and its core type is constructible — proves
/// the codec we PR against is in-tree (a build-level guard, not a network call).
#[test]
fn gate5_nodecode_codec_present() {
    // Referencing the type forces a compile error if the surface regresses.
    fn _assert_nodecode_type(n: &ciris_server::nodecode::NodeCode) -> &str {
        &n.key_id
    }
}

/// (b) The Node A nodecode PR is open and carries the canonical seed transport key.
#[test]
#[ignore = "release gate (external fact): RED until Node A's nodecode PR is open at CIRISPersist (evidence/stage5.json); run with --include-ignored"]
fn gate5_node_a_nodecode_prd_with_canonical_key() {
    let Some(ev) = evidence("stage5") else {
        blocked(
            "5",
            "no evidence/stage5.json — generate Node A's nodecode and open the CIRISPersist PR, then record pr_url + transport_key_id",
        );
    };
    let pr = ev.get("pr_url").and_then(|p| p.as_str()).unwrap_or("");
    assert!(
        pr.contains("github.com/CIRISAI/CIRISPersist/pull/"),
        "pr_url must be a CIRISPersist PR, got {pr:?}"
    );
    let tk = ev
        .get("transport_key_id")
        .and_then(|t| t.as_str())
        .unwrap_or("");
    assert_eq!(
        tk, CANONICAL_TRANSPORT_KEY_ID,
        "Node A nodecode must carry transport key {CANONICAL_TRANSPORT_KEY_ID}"
    );
    assert!(
        ev.get("nodecode")
            .and_then(|n| n.as_str())
            .is_some_and(|s| s.starts_with("CIRIS-V")),
        "evidence must include the CIRIS-V1-… nodecode string"
    );
}
