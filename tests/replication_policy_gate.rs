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

/// edge v14 (`ciris_edge::replication::serve_policy`) — the serve/advertise
/// (responder) policy hash. Witnesses the load-bearing E3 fact: `trace:*`
/// attestations serve ONLY to `capability:infra:serve` recipients; every other
/// kind serves public.
const RATIFIED_SERVE_ADVERTISE_POLICY_HASH: &str =
    "79f5c63a4e4945995f9beba6f3746c380e0bee3fe805866ebfaff34ac6d7c9ff";

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
