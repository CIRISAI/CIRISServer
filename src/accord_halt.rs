//! **HUMANITY_ACCORD operational halt** (CIRISServer#41, CC 4.2.1 / 4.2.3 / §9.2.1)
//! — the disk-latched *full halt* that makes the 2-of-3 kill-switch enforceable at
//! the fabric-node layer, not merely verifiable.
//!
//! A verified 2-of-3 `CONSTITUTIONAL` invocation is "kill-switch authority; full
//! halt" (CC 4.2.1) and explicitly **"not a recoverable pause"** (CC 4.2.3). When
//! a node honors one it:
//!
//!   1. replicates the halt to **all known peers FIRST** (so the kill propagates
//!      mesh-wide even as nodes go dark — see [`crate::accord`]);
//!   2. writes a **halt latch** file to disk ([`latch_halt`]); and
//!   3. terminates — fail-secure, degrading to *not operating*, never escalating.
//!
//! The latch is the load-bearing mechanic: [`check_halt_gate`] runs at the very
//! top of boot and **refuses to start** while the latch exists. Only a manual
//! removal of the latch clears it — the out-of-band human act that a valid
//! `accord:lifecycle:active` re-activation authorizes (CC 4.2.1 §69). No operator,
//! steward, or Wise Authority restart can override it (CC 4.2 §157); the authority
//! lives outside the federation by design.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The halt-latch filename, written under the node `home`. Presence == halted.
pub const HALT_LATCH_FILE: &str = "HUMANITY_ACCORD_HALT";

/// The process exit code a node uses after latching an accord halt (a sentinel an
/// operator / supervisor can recognize as "halted by HUMANITY_ACCORD", distinct
/// from a crash). Non-zero so a naive `restart=on-failure` does NOT silently
/// resurrect it — and the latch gate blocks the restart regardless.
pub const HALT_EXIT_CODE: i32 = 42;

/// What gets recorded in the latch for the operator + audit (the invocation that
/// halted the node, re-verifiable against the cold-start holder roster).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaltRecord {
    pub invocation_kind: String,
    pub invocation_id: String,
    /// The registered holder `key_id`s whose cosignatures met the 2-of-3.
    pub valid_signers: Vec<String>,
    pub quorum_threshold: usize,
    /// RFC-3339 instant the halt was latched.
    pub latched_at: String,
}

/// The latch path under a node `home`.
#[must_use]
pub fn halt_latch_path(home: &Path) -> PathBuf {
    home.join(HALT_LATCH_FILE)
}

/// **Startup gate** — refuse to boot while the halt latch exists. Fail-secure:
/// presence is the gate (an unreadable-but-present latch still blocks). Returns a
/// loud, actionable error that the boot path propagates (the node does not start).
pub fn check_halt_gate(home: &Path) -> anyhow::Result<()> {
    let path = halt_latch_path(home);
    if !path.exists() {
        return Ok(());
    }
    let detail = std::fs::read_to_string(&path).unwrap_or_default();
    anyhow::bail!(
        "HUMANITY_ACCORD HALT IN EFFECT — refusing to start.\n\n\
         A 2-of-3 accord CONSTITUTIONAL halt has been honored by this node \
         (CC 4.2.1: kill-switch authority, full halt). This is NOT a recoverable \
         pause (CC 4.2.3): the node stays down until humanity re-activates the \
         accord (accord:lifecycle:active). No operator, steward, or Wise Authority \
         restart can override it.\n\n\
         Halt latch: {path}\n{detail}\n\n\
         The constitutional way back is a verified 2-of-3 accord:lifecycle:active that \
         includes >=1 of the ORIGINAL (genesis) holders:\n    \
         ciris-server accord reactivate --home <home> --proof <proof.json>\n\n\
         (Break-glass only, NON-conformant — an operator override the accord does not \
         authorize: rm {path})\n",
        path = path.display(),
    );
}

/// Latch the halt to disk (idempotent overwrite). Called AFTER the verified halt
/// has been replicated to peers (replicate-before-halt). A write failure is
/// returned so the caller can still proceed to terminate (fail-secure).
pub fn latch_halt(home: &Path, record: &HaltRecord) -> anyhow::Result<PathBuf> {
    let path = halt_latch_path(home);
    let body = serde_json::to_string_pretty(record).unwrap_or_else(|_| format!("{record:?}"));
    std::fs::write(&path, body)
        .map_err(|e| anyhow::anyhow!("write halt latch {}: {e}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_passes_when_no_latch_and_blocks_once_latched() {
        let dir = std::env::temp_dir().join(format!("accord-halt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let _ = std::fs::remove_file(halt_latch_path(&dir));

        // No latch ⇒ boot allowed.
        assert!(check_halt_gate(&dir).is_ok());

        // Latch ⇒ boot refused, and the error names the manual-removal path.
        let rec = HaltRecord {
            invocation_kind: "CONSTITUTIONAL".into(),
            invocation_id: "halt-001".into(),
            valid_signers: vec!["accord-holder-a".into(), "accord-holder-b".into()],
            quorum_threshold: 2,
            latched_at: "2026-06-20T00:00:00.000Z".into(),
        };
        let path = latch_halt(&dir, &rec).unwrap();
        assert!(path.exists());
        let err = check_halt_gate(&dir).unwrap_err().to_string();
        assert!(err.contains("HALT IN EFFECT"), "got: {err}");
        assert!(
            err.contains(&path.display().to_string()),
            "must name the latch path"
        );

        // Manual removal clears the gate.
        std::fs::remove_file(&path).unwrap();
        assert!(check_halt_gate(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
