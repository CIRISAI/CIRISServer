//! # The release gates — what CIRISServer 0.5 preserves
//!
//! ```text
//! cargo test --test release_gates                     # the whole live ladder
//! cargo test --test release_gates -- --include-ignored # + the two RED-BY-DESIGN gates
//! ```
//!
//! 0.5.156 is intended as the last 0.5 release; 0.6 is the registry fold. This
//! suite answers one question — **is it safe to tag?** — and it answers it from
//! the tree, with no network, no peer, no YubiKey and no operator in the loop.
//!
//! ## What this replaced, and why
//!
//! The previous ladder was a countdown written for 0.5.35: eight numbered stages
//! stepping through "adopt verify 7.2", "node A upgraded to 0.5.35", "persist v10
//! ships and we re-pin", "the agent reports adoption of 0.5.36". Nineteen tests,
//! **ten `#[ignore]`d** against `evidence/stageN.json` files an operator was meant
//! to write. None was ever written; the directory held only `.tsv`. Run with
//! `--include-ignored`, eight failed — against conditions twenty releases stale.
//!
//! So the suite that was supposed to say "safe to release" measured a plan from
//! months ago, had no gate at all for the thing this release is for, and its most
//! important rungs defaulted to silence — which read as fine.
//!
//! That is this cut's own defect class turned on the instrument: **a check whose
//! scope does not cover what it claims.** Five separate checks in this repo turned
//! out unable to fail this week. This one mostly did not run.
//!
//! ## The rule
//!
//! **Hermetic, runnable, LOCAL invariants first.** Where an external fact really
//! is the gate it stays, but as a small, clearly separated minority in
//! [`boundary`], and its absence reads **BLOCKED, never as a pass**. A gate that
//! cannot be evaluated must never be indistinguishable from one that passed.
//!
//! ## The shape
//!
//! | module | rungs |
//! |---|---|
//! | [`ladder`] | the registry of what 0.5 preserves, + the ratchets that keep this ladder from rotting the way the last one did |
//! | [`substrate`] | the pins are at target and move together; the envelope vocabulary is the one we adopted |
//! | [`trust_root`] | genesis baked, kill switch 2-of-3, canonical seed is a ceremony bundle, custody floor still refuses software |
//! | [`planes`] | trace flow (HTTP ingest **and** over a replication round), trace-plane liveness alarms, KEX, both consents, signed-row integrity, replication-by-consent, identity derived, erasure floor |
//! | [`surfaces`] | distinct zeroes, localization reachable |
//! | [`boundary`] | the 0.6 registry gate and the one external probe — RED BY DESIGN, watched live |
//!
//! ## Two things worth knowing before reading a failure
//!
//! **Anchored rungs assert the proof is installed and armed, not that it passes.**
//! Where an invariant is already proven in this repo, the rung names the covering
//! file and test functions rather than re-implementing them — a forked proof
//! drifts from the thing it covers. Whether those tests pass is answered by CI
//! running them. What an anchored rung catches is a proof deleted, renamed,
//! quietly stripped of its `#[test]` attribute, `#[ignore]`d, or sitting behind a
//! feature no CI step passes to `cargo test` — which is how coverage actually
//! disappears.
//!
//! **Two trace-flow rungs, on purpose.** HTTP ingest proves a trace posted to a
//! node lands on THAT node; the replication round proves one crosses to a peer.
//! They are different claims over different code, and they became two rungs
//! because for most of this cut the second was RED (CIRISEdge#455, then
//! CIRISPersist#610) while the first was green — folding them would have let the
//! working half vouch for the broken one. Both are live as of persist v30.1.0 /
//! edge v15.18.3, and they stay two rungs: the reason they must not be folded
//! does not go away when both are passing, it just stops being visible.
//!
//! NB: an integration-test file is its own crate root, so a bare `mod x;` would
//! resolve to `tests/x.rs` (and each such top-level file would ALSO compile as a
//! stray separate test binary). The modules live in `release_gates/` — files there
//! are not auto-compiled as binaries — and are pointed at with explicit `#[path]`.
//! One binary, no strays.

#[path = "release_gates/ladder.rs"]
mod ladder;

#[path = "release_gates/substrate.rs"]
mod substrate;

#[path = "release_gates/trust_root.rs"]
mod trust_root;

#[path = "release_gates/planes.rs"]
mod planes;

#[path = "release_gates/surfaces.rs"]
mod surfaces;

#[path = "release_gates/boundary.rs"]
mod boundary;

#[path = "release_gates/ffi_symbols.rs"]
mod ffi_symbols;

#[path = "release_gates/workflows.rs"]
mod workflows;
