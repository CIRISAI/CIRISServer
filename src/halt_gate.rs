//! **The node's one absolute halt gate** (CC 4.2.1.1 as amended by
//! CIRISConstitution#146, rc7; `FSD/CONSTITUTIONAL_HALT.md` §3–4).
//!
//! One predicate, [`in_effect`], read from the latch
//! ([`crate::accord_halt`]) on every call with the fuse computed for THIS
//! instant, and installed into every door an agent's reasoning or act crosses:
//!
//! - the HTTP trace ingest (`crate::ingest_http`), 423 with
//!   [`REFUSAL_HALT_IN_EFFECT`];
//! - lens-core's relay and local capture doors, through
//!   [`ciris_lens_core::halt_gate::set_halt_gate`];
//! - the agent's own act gate, which reads `GET /v1/accord/halt-status`
//!   before every effectful act (CC 1.13.6; the served read is this predicate
//!   plus the record).
//!
//! It is ABSOLUTE: there is no caller, role, tier or flag that reads past it
//! (CC 4.2.1.3 "no operator tier reaches a constitutional halt"); it ends only
//! as the latch ends. It is not cached: the latch is one small file and the
//! act cadence is the bound CC sets on a reader, so every call reads it.
//! Nothing on the SERVING side reads it (rc7: zero data disruption).

use std::path::PathBuf;
use std::sync::OnceLock;

pub use ciris_lens_core::halt_gate::REFUSAL_HALT_IN_EFFECT;

static HOME: OnceLock<PathBuf> = OnceLock::new();

/// Install the node home the latch lives under, and hand lens-core the same
/// predicate so its doors ask the same question. Called once at compose;
/// a second call is a no-op.
pub fn install(home: PathBuf) {
    let _ = HOME.set(home);
    let _ = ciris_lens_core::halt_gate::set_halt_gate(in_effect);
}

/// Has compose installed the gate? Serving agents without it is not
/// conformant; compose asserts this right after installing.
#[must_use]
pub fn is_installed() -> bool {
    HOME.get().is_some() && ciris_lens_core::halt_gate::is_installed()
}

/// Is a constitutional halt in effect on this node at this instant?
///
/// `false` when no home is installed (unit tests, no-home contexts). An
/// UNREADABLE latch reads as in effect: a gate that cannot read the thing it
/// gates fails closed (a missed halt is the one unrecoverable failure, CC
/// 4.2.6), and the served read names the error for the operator.
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
                "halt gate: the latch is present but UNREADABLE — failing closed"
            );
            true
        }
    }
}

/// The standing latch, for a door that wants to name the halt it refused under.
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
    fn the_gate_is_open_until_installed_and_lens_core_sees_the_same_answer() {
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
        assert!(!ciris_lens_core::halt_gate::halted());
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
        assert!(
            ciris_lens_core::halt_gate::halted(),
            "lens-core's doors ask the same predicate"
        );
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
