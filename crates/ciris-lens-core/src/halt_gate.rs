//! The host's **constitutional-halt gate**, as lens-core sees it (CC 4.2.1.1,
//! rc7, CIRISConstitution#146; CIRISServer `FSD/CONSTITUTIONAL_HALT.md`).
//!
//! The HOST (the node) owns the latch and decides whether a halt is in effect
//! at this instant; lens-core only asks. Every door through which an agent's
//! reasoning reaches persistence — the HTTP ingest (the host's), the relay's
//! opaque trace batches ([`crate::role::LensCoreHandler`]) and the local
//! capture ([`crate::capture::CaptureClient`]) — asks it before admitting
//! anything. A door that does not ask is a door around the halt.
//!
//! Until a host installs the gate it answers "not halted": lens-core alone has
//! no accord. The server installs it at compose, and a source-scan test on the
//! server side proves the installer is called (a hook left unset is the
//! 6-release class the server already paid for once).

use std::sync::OnceLock;

/// The stable refusal token every door emits while the halt is in effect.
pub const REFUSAL_HALT_IN_EFFECT: &str = "accord_halt_in_effect";

static GATE: OnceLock<fn() -> bool> = OnceLock::new();

/// Install the host's predicate. `true` means a constitutional halt is in
/// effect on this node RIGHT NOW (the host computes the fuse on every call).
/// Returns `false` if a gate was already installed (the first one stands).
pub fn set_halt_gate(gate: fn() -> bool) -> bool {
    GATE.set(gate).is_ok()
}

/// Is a constitutional halt in effect on this node? `false` until a host
/// installs the gate.
#[must_use]
pub fn halted() -> bool {
    GATE.get().is_some_and(|g| g())
}

/// Has a host installed the gate at all? A deployment that serves agents with
/// no gate installed is not conformant; the server's compose asserts this.
#[must_use]
pub fn is_installed() -> bool {
    GATE.get().is_some()
}
