//! Registry-of-Record cross-repo drift gate (`FSD/CEG_REPLICATION_MODEL.md` §4.2;
//! CIRISPersist#502 / CIRISEdge#393 / CIRISServer#319 + #320).
//!
//! The mechanistic CEG-admission model splits the replication contract across two
//! repos, each of which exports its half as a hashed manifest — the same
//! by-construction discipline as [`ciris_edge::WIRE_VOCABULARY_HASH`]
//! (see `wire_vocabulary_gate.rs`):
//!
//! - **persist** owns the APPLY authority: the per-`EnvelopeKind` admission +
//!   projection policy, hashed as `REPLICATION_POLICY_HASH`.
//! - **edge** owns the RESPONDER half: the advertise-projection + serve-gate
//!   policy, hashed as `SERVE_ADVERTISE_POLICY_HASH`.
//!
//! The server is the consumer of both, so it pins BOTH here. A change to either
//! policy (e.g. silently un-gating the `trace:*` serve path from
//! `capability:infra:serve` to public) flips a hash → this build fails → the
//! change cannot ship silently across the triple. Re-pinning is a deliberate,
//! reviewed act that travels with the substrate bump.

/// persist v21 (`ciris_persist::federation::replication_policy`) — the 14-kind
/// APPLY (admission + projection) policy hash.
const RATIFIED_REPLICATION_POLICY_HASH: &str =
    "351912ead0aab4847f40d2b54a7a326546c37d43507deb38ea24d6094d29d63b";

/// edge v16.0.0 (`ciris_edge::replication::serve_policy`) — the serve/advertise
/// (responder) policy hash. Witnesses the load-bearing E3 fact: `trace:*`
/// attestations serve ONLY to `capability:infra:serve` recipients; every other
/// kind serves public.
///
/// # Re-pinned twice, and BOTH times the serve gate was verified unmoved
///
/// v15.22.0 (#462) added the `receive` column — the RECEIVE axis. v16.0.0 (the
/// persist v31 subject-binding reset) changed one value INSIDE that column: the
/// Attestation plane's G2 carve went from naming a mechanism
/// (`consent-gated scores … persist consent_gated_claim`) to naming a
/// PREDICATE — `attestation_type == scores AND !is_subject_retainable(dimension)`.
///
/// That is a strict improvement and worth understanding rather than waving
/// through. persist's `is_subject_retainable` is an explicit list, not a
/// string-match over manifest prose, with a test
/// (`manifest_self_emission_families_are_all_retainable`) that fails the build
/// when the manifest gains a self-emission family the list does not name — "the
/// manifest is the alarm, not the authority". And it is consulted ONLY on the
/// data-subject axis: a score I AUTHORED stays mine to recover.
///
/// **What was verified before accepting each new value:** the
/// `(advertise, serve)` match block hashes BYTE-IDENTICAL across v15.21.8,
/// v15.22.0 and v16.0.0 (`f43c9736…` all three). So both re-pins are column
/// changes, not serve-rule relaxations. A hash gate exists to force that reading;
/// taking the number on trust would make it decoration.
const RATIFIED_SERVE_ADVERTISE_POLICY_HASH: &str =
    "6f683311627689221d886f4245ac7b9fa6715e6f1e135855f52fa7800fb7cda5";

#[test]
fn persist_replication_policy_hash_pinned() {
    assert_eq!(
        ciris_persist::federation::replication_policy::REPLICATION_POLICY_HASH,
        RATIFIED_REPLICATION_POLICY_HASH,
        "persist's replication ADMISSION/PROJECTION policy drifted — a change to \
         which signed CEG claim gates (or which projections fan out for) any of \
         the 14 EnvelopeKinds. Reconcile FSD/CEG_REPLICATION_MODEL.md §4 and \
         re-pin only as a reviewed act (CIRISPersist#502).",
    );
}

#[test]
fn edge_serve_advertise_policy_hash_pinned() {
    assert_eq!(
        ciris_edge::replication::serve_policy::SERVE_ADVERTISE_POLICY_HASH,
        RATIFIED_SERVE_ADVERTISE_POLICY_HASH,
        "edge's SERVE/ADVERTISE policy drifted — a change to which peers may be \
         served (or advertised) which kinds. Guards the E3 trace-confidentiality \
         invariant (trace:* → capability:infra:serve only). Reconcile \
         FSD/CEG_REPLICATION_MODEL.md §4.2/§4.3 and re-pin only as a reviewed act \
         (CIRISEdge#393).",
    );
}
