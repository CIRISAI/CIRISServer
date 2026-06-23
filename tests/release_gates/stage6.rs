//! STAGE 6 gate — CIRISPersist baked v10 WITH Node A as the canonical seed.
//! Pin gate (persist tag is a v10.x) + evidence that Node A is in the baked set.
//! Drop tests/release_gates/evidence/stage6.json:
//!   { "persist_release":"v10.0.0", "node_a_baked":true,
//!     "baked_set":["ciris-canonical-1", …] }
//! RED until persist v10 ships and we re-pin to it.

use crate::support::{
    blocked, cargo_pin, evidence, CANONICAL_TRANSPORT_KEY_ID, TARGET_PERSIST_V10,
};

#[test]
#[ignore = "release gate (external fact): RED until CIRISPersist v10 ships and we re-pin; run with --include-ignored"]
fn gate6_persist_pinned_to_v10() {
    let pin = cargo_pin("ciris-persist").expect("persist pin present");
    assert!(
        pin.starts_with(TARGET_PERSIST_V10),
        "persist is pinned to {pin}, must be {TARGET_PERSIST_V10}.x (the Node-A bake)"
    );
}

#[test]
#[ignore = "release gate (external fact): RED until persist v10 bakes Node A (evidence/stage6.json); run with --include-ignored"]
fn gate6_node_a_in_baked_set() {
    let Some(ev) = evidence("stage6") else {
        blocked(
            "6",
            "no evidence/stage6.json — awaiting CIRISPersist v10 baking Node A into the canonical set",
        );
    };
    assert_eq!(
        ev.get("node_a_baked").and_then(|b| b.as_bool()),
        Some(true),
        "Node A must be baked into persist v10"
    );
    let baked = ev
        .get("baked_set")
        .and_then(|s| s.as_array())
        .unwrap_or_else(|| blocked("6", "evidence baked_set[] missing"));
    assert!(
        baked
            .iter()
            .any(|v| v.as_str() == Some(CANONICAL_TRANSPORT_KEY_ID)),
        "the baked canonical set must contain {CANONICAL_TRANSPORT_KEY_ID}"
    );
}
