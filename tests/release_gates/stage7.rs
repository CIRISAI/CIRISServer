//! STAGE 7 gate — 0.5.36 (verify v7.2 + persist v10) is cut AND CIRISAgent has
//! adopted it. Pin gate (persist v10 + verify still v7.2) + adoption evidence.
//! Drop tests/release_gates/evidence/stage7.json:
//!   { "server_release":"0.5.36",
//!     "agent_adopted":true, "agent_report":"https://github.com/CIRISAI/CIRISAgent/…",
//!     "agent_floor":{ "verify":"v7.2.0", "persist":"v10.0.0" } }
//! RED until the agent reports adoption of the two-baked-root floor.

use crate::support::{blocked, cargo_pin, evidence, TARGET_PERSIST_V10, TARGET_VERIFY};

#[test]
#[ignore = "release gate (external fact): RED until the 0.5.36 cut re-pins persist to v10; run with --include-ignored"]
fn gate7_floor_is_verify7_persist10() {
    let verify = cargo_pin("ciris-verify-core").expect("verify pin");
    let persist = cargo_pin("ciris-persist").expect("persist pin");
    assert_eq!(
        verify, TARGET_VERIFY,
        "verify must still be {TARGET_VERIFY}"
    );
    assert!(
        persist.starts_with(TARGET_PERSIST_V10),
        "persist must be {TARGET_PERSIST_V10}.x for the agent-adoption cut, got {persist}"
    );
}

#[test]
#[ignore = "release gate (external fact): RED until CIRISAgent reports adoption of 0.5.36 (evidence/stage7.json); run with --include-ignored"]
fn gate7_agent_reports_adoption() {
    let Some(ev) = evidence("stage7") else {
        blocked(
            "7",
            "no evidence/stage7.json — awaiting CIRISAgent adoption of 0.5.36 (verify7 + persist10)",
        );
    };
    assert_eq!(
        ev.get("agent_adopted").and_then(|b| b.as_bool()),
        Some(true),
        "CIRISAgent must report adoption"
    );
    let floor = ev
        .get("agent_floor")
        .unwrap_or_else(|| blocked("7", "evidence agent_floor missing"));
    assert_eq!(
        floor.get("verify").and_then(|v| v.as_str()),
        Some(TARGET_VERIFY),
        "agent's adopted verify floor must be {TARGET_VERIFY}"
    );
    assert!(
        floor
            .get("persist")
            .and_then(|p| p.as_str())
            .is_some_and(|p| p.starts_with(TARGET_PERSIST_V10)),
        "agent's adopted persist floor must be {TARGET_PERSIST_V10}.x"
    );
}
