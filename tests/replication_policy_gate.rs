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

/// edge v15.22.0 (`ciris_edge::replication::serve_policy`) — the serve/advertise
/// (responder) policy hash. Witnesses the load-bearing E3 fact: `trace:*`
/// attestations serve ONLY to `capability:infra:serve` recipients; every other
/// kind serves public.
///
/// # Re-pinned for CIRISEdge#462 — the RECEIVE axis
///
/// The manifest gained a third column, `receive`: whether a kind answers a
/// subject-scoped pull, and under what rule. That is the axis this server filed
/// as missing — the want-generator that let a fedID recover its own testimony
/// after claiming a fresh node.
///
/// **What was reviewed before re-pinning**, because a hash bump is exactly the
/// act this gate exists to make deliberate:
///
/// - The `(advertise, serve)` match arms are BYTE-IDENTICAL across v15.21.8 and
///   v15.22.0 (verified by hashing that block in both checkouts). The E3 gate did
///   not move; the hash changed because a column was ADDED, not because a serve
///   rule was relaxed. That distinction is the whole point of reading the diff
///   rather than accepting the new value.
/// - The new column is fail-closed in the right direction: the five replicated
///   kinds are `subject_pull … subject-only`, and every other kind is `none` —
///   pullable is the exception, not the default.
/// - The Attestation plane sweeps BOTH testimonial axes
///   (`data_subject+sender`), which is the author/subject split this server
///   argued for, with a `consent-gated scores` carve on the `data_subject` axis
///   for the G2 capacity self-revocation hazard — the one case this server
///   flagged as must-not-auto-pull.
const RATIFIED_SERVE_ADVERTISE_POLICY_HASH: &str =
    "049e71ef208d24266fe366b8eaed365a467cadd3aadd8856c8ed917c90bced33";

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
