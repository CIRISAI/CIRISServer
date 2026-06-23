//! STAGE 8 gate — the final cut: CIRISAgent has shipped 2.9.7 AND CIRISServer 0.6
//! (+registry) is ready. Composite: agent-2.9.7 evidence + the registry module is
//! actually present in-tree (0.6's defining feature — bootstraps the canonical
//! mesh). Drop tests/release_gates/evidence/stage8.json:
//!   { "agent_release":"2.9.7", "agent_adopted":true }
//! RED until the agent cuts 2.9.7 AND src/registry.rs (the +registry surface)
//! exists. This is the gate that authorizes the 0.6 tag.

use std::path::PathBuf;

use crate::support::{blocked, evidence};

#[test]
#[ignore = "release gate (external fact): RED until CIRISAgent ships 2.9.7 (evidence/stage8.json); run with --include-ignored"]
fn gate8_agent_2_9_7_shipped() {
    let Some(ev) = evidence("stage8") else {
        blocked(
            "8",
            "no evidence/stage8.json — awaiting CIRISAgent 2.9.7 release report",
        );
    };
    assert_eq!(
        ev.get("agent_release").and_then(|r| r.as_str()),
        Some("2.9.7"),
        "agent_release must be 2.9.7"
    );
    assert_eq!(
        ev.get("agent_adopted").and_then(|b| b.as_bool()),
        Some(true),
        "agent must confirm adoption"
    );
}

/// 0.6's defining surface — the registry that bootstraps the canonical mesh — must
/// exist before 0.6 can tag. While we hold on 0.5.X this file is absent → RED.
#[test]
#[ignore = "release gate (0.6 surface): RED until src/registry.rs (the +registry mesh bootstrap) is built; run with --include-ignored"]
fn gate8_registry_surface_present() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let has_registry = src.join("registry.rs").exists() || src.join("registry").is_dir();
    assert!(
        has_registry,
        "src/registry.rs absent — the +registry surface (0.6) is not built yet; \
         0.6 must NOT tag until the canonical-mesh registry exists"
    );
}
