//! **The operator-surface rungs** — what a human reads off this node, and the two
//! ways that reading lies.
//!
//! Both failures here are the same shape from opposite ends: a surface that
//! cannot distinguish "we could not ask" from "the answer is none", and a string
//! that reaches the reader as a raw token because the id was written in a form
//! the loader can never resolve.

use crate::ladder::{assert_proven, DISTINCT_ZEROES, LOCALIZATION_REACHABLE};

/// Could-not-ask ≠ nothing-there, on every surface that shows a zero.
///
/// Every instance of this class in this repo has been found the same way: the
/// collapsed reading was GREEN and wrong. `not_exercised` folded into `idle` made
/// an untested node read healthy; the federation-identity fallback answered
/// `200 {"peer_count_total": 0}` with confidence it had not earned. A zero that
/// does not name its own cause is not data.
#[test]
fn gate_distinct_zeroes() {
    assert_proven(&DISTINCT_ZEROES);
}

/// Every message id resolves under the loader's REAL semantics.
///
/// `LocalizationManager.resolveKey` splits the key on `.` and walks nested
/// objects — there is no top-level exact-match fallback. So a flat dotted key is
/// dead for every reader in every language, English included, and it is dead
/// identically in all four committed bundles, which is why mirror-parity checks
/// see nothing wrong.
///
/// The bundle checker cannot catch it either: its `flatten()` maps a flat dotted
/// key and a nested path to the SAME string, so a key the loader can never
/// resolve satisfies the guard. That is this cut's defect class stated exactly —
/// a check whose scope does not cover what it claims — which is why the rung
/// anchors on the SHAPE predicate (`no key at any depth contains a dot`) and on
/// that predicate's own two mutation proofs, rather than on the flattened view.
///
/// The rung deliberately does NOT claim every emitted id has a bundle entry.
/// Ids with no entry degrade as designed — the wire carries `{id, text}` and the
/// English source ships in the payload — so absence is a localization-coverage
/// ratchet, not a release blocker. Reachability is the release blocker: a
/// DEFINED-but-unreachable id is worse than an absent one, because every bundle
/// agrees and the lookup still returns null.
#[test]
fn gate_localization_reachable() {
    assert_proven(&LOCALIZATION_REACHABLE);
}
