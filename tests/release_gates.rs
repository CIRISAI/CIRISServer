//! RELEASE-GATE QA SUITE — the verify-7 → persist-10 → 0.6 countdown, as code.
//!
//! One module per stage of the release plan. Every gate FAILS (red) until its
//! stage's requisite is cleared in the mesh, and turns GREEN the moment reality
//! satisfies it. Run the whole suite before executing each step:
//!
//!     cargo test --test release_gates
//!
//! Software keys + file/HTTP probes throughout — no YubiKey, no operator needed
//! to RUN the suite (only to CLEAR the external-fact gates by deploying nodes,
//! merging PRs, or dropping an evidence file under tests/release_gates/evidence/).
//!
//! NB: an integration-test file is its own crate root, so a bare `mod stageN;`
//! would resolve to `tests/stageN.rs` (and each such top-level file would also
//! compile as a STRAY separate test binary). We keep the modules in the
//! `release_gates/` subdir — files there are NOT auto-compiled as binaries — and
//! point at them with explicit `#[path]`. One binary, no strays.

#[path = "release_gates/support.rs"]
mod support;

#[path = "release_gates/stage1.rs"]
mod stage1; // adopt verify7.2/persist9.11/edge6.4 + bake kill-switch + #268 path
#[path = "release_gates/stage2.rs"]
mod stage2; // nodes A & B upgraded to 0.5.35 (probe /health)
#[path = "release_gates/stage3.rs"]
mod stage3; // owner delegates → I claim dgrant token → config write (software)
#[path = "release_gates/stage4.rs"]
mod stage4; // ciris-scores served on A & B (evidence)
#[path = "release_gates/stage5.rs"]
mod stage5; // Node A nodecode (transport key ciris-canonical-1) + PR evidence
#[path = "release_gates/stage6.rs"]
mod stage6; // persist bakes v10 with Node A
#[path = "release_gates/stage7.rs"]
mod stage7; // cut 0.5.36 (verify7 + persist10) + agent adoption evidence
#[path = "release_gates/stage8.rs"]
mod stage8; // agent 2.9.7 + registry present → cut 0.6
