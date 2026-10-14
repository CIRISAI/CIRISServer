//! **The node's halt predicate** (CC 4.2.1.1 as amended by
//! CIRISConstitution#146, rc7; `FSD/CONSTITUTIONAL_HALT.md` §3–4).
//!
//! One predicate, [`in_effect`], read from the latch ([`crate::accord_halt`])
//! on every call with the fuse computed for THIS instant. It has exactly ONE
//! reader: the agent's act gate, which reads `GET /v1/accord/halt-status`
//! before every effectful act (CC 1.13.6; the served read is this predicate
//! plus the record, computed in `crate::accord::halt_status`).
//!
//! No data door reads it. A halt is an AGENT PAUSE with zero data disruption
//! by construction: trace ingest, local capture, relay replication, files,
//! roster, consent and every serving read do their ordinary work while a halt
//! stands. 0.5.225 installed this predicate into the HTTP ingest, the relay's
//! `persist_batch` and both capture paths and refused them 423
//! `accord_halt_in_effect`; 0.5.226 removed every one of those readers (CC on
//! re-pin 17): a refused act's terminal `ACTION_RESULT` travels those very
//! paths to the record, and a door that refuses it makes the pause erase its
//! own evidence. `tests/halt_gate.rs` pins that no file outside this module
//! and `compose.rs` names the predicate, so adding a reader to a data door is
//! a red test (the L3 mutant for "zero data disruption").
//!
//! It is ABSOLUTE where it is read: there is no caller, role, tier or flag
//! that reads past it (CC 4.2.1.3 "no operator tier reaches a constitutional
//! halt"); it ends only as the latch ends. It is not cached: the latch is one
//! small file and the act cadence is the bound CC sets on a reader.

use std::path::PathBuf;
use std::sync::OnceLock;

/// The stable refusal token the AGENT's act gate records when it refuses an
/// act under a halt (its `ACTION_RESULT` names the halt's `invocation_id`).
/// No node door emits it since 0.5.226; it is kept here so the served status
/// and the agent agree on one word.
pub const REFUSAL_HALT_IN_EFFECT: &str = "accord_halt_in_effect";

static HOME: OnceLock<PathBuf> = OnceLock::new();

/// Install the node home the latch lives under. Called once at compose; a
/// second call is a no-op.
pub fn install(home: PathBuf) {
    let _ = HOME.set(home);
}

/// Has compose installed the predicate? Serving the halt status without it
/// is not conformant; compose asserts this right after installing.
#[must_use]
pub fn is_installed() -> bool {
    HOME.get().is_some()
}

/// Is a constitutional halt in effect on this node at this instant?
///
/// `false` when no home is installed (unit tests, no-home contexts). An
/// UNREADABLE latch reads as in effect: a predicate that cannot read the
/// thing it reports fails closed (a missed halt is the one unrecoverable
/// failure, CC 4.2.6), and the served read names the error for the operator.
#[must_use]
pub fn in_effect() -> bool {
    let Some(home) = HOME.get() else {
        return false;
    };
    match crate::accord_halt::read_halt_latch(home) {
        Ok(Some(rec)) => rec.in_effect_at(chrono::Utc::now()),
        Ok(None) => false,
        Err(e) => {
            tracing::error!(
                error = %format!("{e:#}"),
                "halt predicate: the latch is present but UNREADABLE — failing closed"
            );
            true
        }
    }
}

/// The standing latch, for a reader that wants to name the halt it stands under.
#[must_use]
pub fn standing() -> Option<crate::accord_halt::HaltRecord> {
    let home = HOME.get()?;
    crate::accord_halt::read_halt_latch(home)
        .ok()
        .flatten()
        .filter(|r| r.in_effect_at(chrono::Utc::now()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_predicate_is_open_until_installed_then_reads_the_latch_for_this_instant() {
        // One process-wide OnceLock, so this test is the one that installs.
        assert!(!in_effect());
        let dir = std::env::temp_dir().join(format!(
            "halt-gate-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        install(dir.clone());
        assert!(is_installed());
        assert!(!in_effect(), "no latch, no halt");
        let rec = crate::accord_halt::HaltRecord::new(
            "constitutional".into(),
            "halt-gate-001".into(),
            vec!["A1".into()],
            1,
            chrono::Utc::now().to_rfc3339(),
            Some("node".into()),
            Some("ab".repeat(32)),
        );
        crate::accord_halt::latch_halt(&dir, &rec).unwrap();
        assert!(in_effect(), "a fresh latch is in effect");
        assert_eq!(
            standing().map(|r| r.invocation_id).as_deref(),
            Some("halt-gate-001")
        );
        // A lapsed latch is history, not a halt.
        let lapsed = rec.clone().with_fuse(1);
        let mut lapsed = lapsed;
        lapsed.received_at = Some("2026-01-01T00:00:00Z".into());
        crate::accord_halt::latch_halt(&dir, &lapsed).unwrap();
        assert!(!in_effect());
        // An unreadable latch fails CLOSED.
        std::fs::write(crate::accord_halt::halt_latch_path(&dir), b"not json").unwrap();
        assert!(in_effect(), "unreadable ⇒ in effect (fail closed)");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
