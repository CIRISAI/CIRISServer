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
//!
//! # v31.1.0 re-pin — the 15th wire kind (reviewed 2026-08-14)
//!
//! Both hashes moved for ONE coherent addition, verified by diffing persist
//! v31.0.0 → v31.1.0 rather than by trusting the bump:
//!
//! `EnvelopeKind::AccordQuorumEvidence` joins the wire vocabulary (14 → 15),
//! admitted by `QuorumFromOwnDirectory` + `StewardRosterFromDirectory`, and
//! projecting to a new `RoleWithdrawals` plane. `consent_grammar` places it on
//! the `StructuralPlane`.
//!
//! That is CIRISPersist#662's fix, and it is the replicate-evidence rule made
//! concrete: `federation_role_withdrawals` rows carry NO signature columns, so
//! shipping them would be a derived verdict asking the receiver to trust the
//! sender. Instead the SIGNED accord quorum evidence travels and each receiver
//! re-derives the withdrawal from its own directory.
//!
//! Impact on this server: none that changes behaviour. We never name an
//! `EnvelopeKind` variant in `src/` (only edge's re-export, in a test), so the
//! new kind cannot break an exhaustive match, and we neither produce nor consume
//! `AccordQuorumEvidence`. What it does mean is that a node will now SEE this
//! kind on the wire, which is the point — it is how a de-canonicalisation
//! reaches us at all.

/// persist v21 (`ciris_persist::federation::replication_policy`) — the 15-kind
/// APPLY (admission + projection) policy hash.
const RATIFIED_REPLICATION_POLICY_HASH: &str =
    "3af30bccf437679ecccba325e2db055824b4721eeac069fc30a38d7a0723bbef";

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
/// ## v16.3.0 re-pin — the 15th kind, and why it is not a serve relaxation
///
/// `6f683311…` → `328d73b0…`, read before accepting (CIRISEdge#474).
///
/// The diff against v16.1.0 adds exactly ONE arm to each of the two match
/// blocks, for the new `EnvelopeKind::AccordQuorumEvidence`:
///
/// | axis | value |
/// |---|---|
/// | advertise | `cursor:evidence_at` — the dedicated cursor path, not the content-hash Summary/Diff/Fetch flow |
/// | serve | `public` — a `FederationOnly`-tier bundle, no capability gate |
/// | receive | `cursor_pull:evidence_at; re-tally admit` |
///
/// **`trace:*` is untouched**, which is the invariant this gate exists for: E3
/// trace-confidentiality (`trace:*` → `capability:infra:serve` only). No
/// existing kind's advertise scope or serve gate moved; the hash changed because
/// the match blocks gained a fifteenth arm.
///
/// The one value worth pausing on is `serve = "public"` — an ungated serve is
/// normally exactly what this gate is here to catch. It is acceptable because
/// the RECEIVE side does not trust it: `apply_replicated_accord_evidence`
/// **re-tallies the quorum against the receiver's own roster** rather than
/// accepting the sender's verdict, and the value is deliberately kept out of the
/// `subject_pull:*` namespace so it cannot be mistaken for a subject-scoped read.
/// Serving a bundle anyone may verify for themselves is not a disclosure.
const RATIFIED_SERVE_ADVERTISE_POLICY_HASH: &str =
    "328d73b0a6a5c7e2d1272b81e245ecceeca1d837dd08b0415105e1661ff4a699";

#[test]
fn persist_replication_policy_hash_pinned() {
    assert_eq!(
        ciris_persist::federation::replication_policy::REPLICATION_POLICY_HASH,
        RATIFIED_REPLICATION_POLICY_HASH,
        "persist's replication ADMISSION/PROJECTION policy drifted — a change to \
         which signed CEG claim gates (or which projections fan out for) any of \
         the 15 EnvelopeKinds. Reconcile FSD/CEG_REPLICATION_MODEL.md §4 and \
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
