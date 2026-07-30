//! CIRISServer#327 §5 — the GATE for the in-crate field-conformance harness.
//!
//! The harness itself — the two tables ([`SERVER_FIELD_CONFORMANCE`] +
//! [`DEFERRED_PENDING_PLANE`]), the value-checks, the [`server_field_conformance`]
//! entry the shared CIRISConformance harness (CIRISConformance#83) drives against
//! the real wheel, and the [`server_evidence_rows`] generator — lives in
//! `ciris_server::field_conformance` (promoted there so it ships in the wheel like
//! edge's and persist's, not stranded in `tests/`).
//!
//! THIS file holds the `#[test]`s that keep that table honest against persist's LIVE
//! `field_processor_matrix()`:
//! - [`every_server_tagged_field_is_accounted_for`] — a new server-tagged field with
//!   NO check and NO deferral is a BUILD FAILURE (the CIRISServer#315
//!   carried-but-unprocessed dead-plane class the program exists to kill);
//! - [`evidence_tsv_matches_emitted`] — the vendored `evidence/CIRISServer.cc_impl.tsv`
//!   must equal what [`server_evidence_rows`] emits, so the evidence registry can
//!   never drift from the code it attests;
//! - [`checked_and_deferred_exactly_partition_server_fields`] — checked ∪ deferred
//!   equals the server-owned matrix rows EXACTLY, disjoint, no dups;
//! - [`server_field_conformance_passes`] / [`every_covered_field_has_evidence_anchor`]
//!   / [`no_conformance_entry_is_stale`] — the value checks pass and every entry is
//!   anchored and still server-owned upstream.
//!
//! They live in the gate file (not beside the harness) on purpose: they depend on
//! persist's vendored manifest, so a persist pin bump that moves the server surface
//! reds the build HERE — the completeness discipline is a test failure, not a silent
//! recompile.

use ciris_server::field_conformance::{
    server_evidence_rows, server_field_conformance, DEFERRED_PENDING_PLANE,
    SERVER_FIELD_CONFORMANCE,
};

/// Every server check passes — the value semantics hold in the pinned wheels.
#[test]
fn server_field_conformance_passes() {
    if let Err(v) = server_field_conformance() {
        panic!("server field conformance violations: {v:#?}");
    }
}

/// THE KEYSTONE (CIRISServer#327 §5): every field persist's live
/// `field_processor_matrix` tags `owner_component ⊇ server` is ACCOUNTED FOR —
/// either a [`SERVER_FIELD_CONFORMANCE`] check or a [`DEFERRED_PENDING_PLANE`] row.
/// A new server-tagged field persist ships that the server has not categorized
/// fails THIS test — the carried-but-unprocessed dead-plane (CIRISServer#315) is a
/// build failure, exactly as #327 §5 requires. (The manifest is byte-identical to
/// the vendored `FSD/namespace_supersets.json`, so this iterates the SAME pinned
/// table every repo generates from.)
#[test]
fn every_server_tagged_field_is_accounted_for() {
    use ciris_persist::federation::namespace::supersets::field_processor_matrix;
    use std::collections::HashSet;

    let accounted: HashSet<&str> = SERVER_FIELD_CONFORMANCE
        .iter()
        .map(|c| c.field)
        .chain(DEFERRED_PENDING_PLANE.iter().map(|(f, _)| *f))
        .collect();

    let mut gaps = Vec::new();
    for row in field_processor_matrix() {
        let server_owned = row.owner_component.split('/').any(|c| c == "server");
        if server_owned && !accounted.contains(row.field.as_str()) {
            gaps.push(row.field.clone());
        }
    }
    assert!(
        gaps.is_empty(),
        "server-tagged manifest fields with NO conformance check and NO deferral \
         (carried-but-unprocessed, CIRISServer#315) — add each to SERVER_FIELD_CONFORMANCE \
         or DEFERRED_PENDING_PLANE with a reason: {gaps:#?}"
    );
}

/// CIRISServer#327 §5 — the vendored `evidence/CIRISServer.cc_impl.tsv` (what the
/// Constitution's `check_evidence.py` consumes) is EXACTLY what the live code emits
/// from [`SERVER_FIELD_CONFORMANCE`]. A processor rename, a version bump, or a
/// hand-edit to the TSV that diverges from the tested table is a BUILD failure —
/// the evidence registry can never drift from the code it attests.
#[test]
fn evidence_tsv_matches_emitted() {
    let vendored: Vec<&str> = include_str!("../evidence/CIRISServer.cc_impl.tsv")
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .collect();
    let emitted = server_evidence_rows();
    assert_eq!(
        vendored,
        emitted.iter().map(String::as_str).collect::<Vec<_>>(),
        "evidence/CIRISServer.cc_impl.tsv drifted from SERVER_FIELD_CONFORMANCE — \
         regenerate it from server_evidence_rows() (CIRISServer#327 §5)"
    );
}

/// Every covered field carries a real, non-empty evidence anchor (a `path#symbol`
/// keyed to a `CLM-nsproc-*` claim and a CC section). Not merely present — the
/// anchor names the LIVE processor the check exercises.
#[test]
fn every_covered_field_has_evidence_anchor() {
    for c in SERVER_FIELD_CONFORMANCE {
        assert!(!c.property.is_empty(), "{}: empty property", c.field);
        assert!(!c.cc.is_empty(), "{}: empty cc section", c.field);
        assert!(
            c.clm.starts_with("CLM-nsproc-"),
            "{}: clm {:?} is not a CLM-nsproc-* claim",
            c.field,
            c.clm
        );
        assert!(
            c.evidence.contains('#'),
            "{}: evidence {:?} carries no path#symbol anchor",
            c.field,
            c.evidence
        );
    }
}

/// No stale entries: every field the server claims to process/defer is STILL a
/// server-owned row in persist's matrix (so a persist rename/removal surfaces here,
/// not as a silently-dead server check).
#[test]
fn no_conformance_entry_is_stale() {
    use ciris_persist::federation::namespace::supersets::field_processor_matrix;
    use std::collections::HashSet;

    let server_owned: HashSet<&str> = field_processor_matrix()
        .iter()
        .filter(|r| r.owner_component.split('/').any(|c| c == "server"))
        .map(|r| r.field.as_str())
        .collect();

    let mut stale = Vec::new();
    for f in SERVER_FIELD_CONFORMANCE
        .iter()
        .map(|c| c.field)
        .chain(DEFERRED_PENDING_PLANE.iter().map(|(f, _)| *f))
    {
        if !server_owned.contains(f) {
            stale.push(f);
        }
    }
    assert!(
        stale.is_empty(),
        "conformance entries no longer server-owned in persist's matrix (rename/removal?): {stale:#?}"
    );
}

/// CIRISServer#327 §5 — the PARTITION invariant made mechanical: the checked set and
/// the deferred set EXACTLY partition persist's server-owned matrix rows. A field is
/// EITHER value-checked OR deferred-with-reason — never both, never neither, no
/// duplicates. This is the arithmetic the handoff block records (server-owned = N =
/// checked + deferred); deriving N from the LIVE matrix rather than hardcoding it
/// means a persist pin bump that changes the server surface forces a re-partition
/// here instead of drifting silently. Strictly stronger than
/// [`every_server_tagged_field_is_accounted_for`] (⊇) +
/// [`no_conformance_entry_is_stale`] (⊆) combined, plus the disjointness the two
/// named gates do not check.
#[test]
fn checked_and_deferred_exactly_partition_server_fields() {
    use ciris_persist::federation::namespace::supersets::field_processor_matrix;
    use std::collections::HashSet;

    let checked: Vec<&str> = SERVER_FIELD_CONFORMANCE.iter().map(|c| c.field).collect();
    let deferred: Vec<&str> = DEFERRED_PENDING_PLANE.iter().map(|(f, _)| *f).collect();
    let checked_set: HashSet<&str> = checked.iter().copied().collect();
    let deferred_set: HashSet<&str> = deferred.iter().copied().collect();

    // No field appears twice within either list …
    assert_eq!(
        checked.len(),
        checked_set.len(),
        "duplicate field in SERVER_FIELD_CONFORMANCE"
    );
    assert_eq!(
        deferred.len(),
        deferred_set.len(),
        "duplicate field in DEFERRED_PENDING_PLANE"
    );
    // … and no field is BOTH checked and deferred (the "never both" half the two
    // named gates cannot see — a field checked here must have had its deferral line
    // deleted, per the handoff block's coupling note).
    let both: Vec<&&str> = checked_set.intersection(&deferred_set).collect();
    assert!(
        both.is_empty(),
        "fields both value-checked AND deferred (a field is EITHER processed OR deferred): {both:#?}"
    );

    // checked ∪ deferred EXACTLY equals persist's server-owned matrix fields — never
    // neither (a real #315 gap), never an extra (a stale entry).
    let server_owned: HashSet<&str> = field_processor_matrix()
        .iter()
        .filter(|r| r.owner_component.split('/').any(|c| c == "server"))
        .map(|r| r.field.as_str())
        .collect();
    let accounted: HashSet<&str> = checked_set.union(&deferred_set).copied().collect();
    assert_eq!(
        accounted, server_owned,
        "checked ∪ deferred must equal persist's server-owned matrix fields exactly"
    );

    // The count the handoff block pins (checked + deferred = server-owned), derived
    // from the live matrix so a persist bump that moves it reds HERE, loudly.
    assert_eq!(
        SERVER_FIELD_CONFORMANCE.len() + DEFERRED_PENDING_PLANE.len(),
        server_owned.len(),
        "partition arithmetic drifted: {} checked + {} deferred must equal {} server-owned fields",
        SERVER_FIELD_CONFORMANCE.len(),
        DEFERRED_PENDING_PLANE.len(),
        server_owned.len(),
    );
}
