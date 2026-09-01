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
/// ## v18.2.0 re-pin — the manifest stopped lying, and that is the whole change
///
/// `328d73b0…` → `20499cab…f22d74` (CIRISServer#451).
///
/// Edge's own account: the manifest now states the TRUE constant projections for
/// five planes. **No serve behaviour moved** — the code always served those
/// planes that way; the manifest previously described them wrongly, so the hash
/// changed when the description was corrected to match the behaviour.
///
/// That is the one re-pin shape this gate should accept most readily and read
/// most carefully, because "the manifest was wrong" is also what a genuine
/// relaxation would look like if someone edited the manifest to match a change
/// they had already made. What separates them is direction: here the DESCRIPTION
/// moved toward the code. `trace:*` remains `capability:infra:serve` only — the
/// E3 trace-confidentiality invariant this gate exists for is untouched, which
/// is the property to re-check on every re-pin rather than the hash itself.
///
/// Mirroring this also clears the 6 cohabitation conformance jobs that have been
/// red on server-skew since v16.3.0.
/// ## v18.12.1 re-pin — the RECEIVE axis widens on four already-public planes
///
/// `20499cab…` → `e54c5677…5a6fe71681710dbf25` (CIRISServer#522, CIRISEdge#552/#556).
///
/// One cell. `Key`, `IdentityOccurrence`, `TransportDestination` and
/// `IdentityOccurrenceRevocation` move from
/// `subject_pull:data_subject; subject-only` to
/// `subject_pull:data_subject+any_attributed; public envelope`.
///
/// **Disclosure-neutral, and the direction is the point.** Those four planes
/// already serve `public` on the ADVERTISE axis — public signed envelopes, no
/// capability gate, already reachable through ordinary anti-entropy. `subject-only`
/// was making them *un-addressable, not undisclosed*: `Pull` is the only verb that
/// names a record by identifier, every other read is content-hash addressed, and a
/// node cannot compute the hash of a record it has never held. Under the hash-first
/// directory (CIRISEdge#552) a signer's `Key` became permanently unfetchable — and
/// with it every row that key signed, **revocations included**. That is a kill
/// order that does not land. The widening restores addressability for records the
/// federation already discloses; an UNATTRIBUTED requester is still served nothing.
///
/// **The property to re-check, per this gate's own rule, is not the hash.**
/// `Attestation` is unchanged and keeps `subject-only`: its serve cell is
/// conditional per ROW — `trace:*` rides `capability:infra:serve`, plus the per-row
/// G2 scores carve — so a per-plane widening there would conflate a per-record gate
/// with a per-plane one. E3's closure is therefore intact: `trace:*` still serves
/// only to `capability:infra:serve` recipients, which is the load-bearing fact this
/// gate witnesses.
///
/// Note the hash in CIRISServer#522's opening text (`e8216fec…`) is STALE — it
/// moved again when #552/#553/#554 landed on top of #556. The current value is
/// CIRISServer#524 §7's, pinned here.
const RATIFIED_SERVE_ADVERTISE_POLICY_HASH: &str =
    "e54c56775e8d56442f9fdbaa0346397cdc169e7cc6237f5a6fe71681710dbf25";

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
