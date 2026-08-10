//! The release ladder itself — **what CIRISServer 0.5 preserves**, as a registry,
//! plus the machinery every rung is built from.
//!
//! # Why this file replaced a stage ladder
//!
//! The ladder this supersedes was a countdown: eight numbered stages, each one a
//! step in the verify-7 → persist-10 → 0.6 plan of 0.5.35. Ten of its nineteen
//! tests were `#[ignore]`d pending `evidence/stageN.json` files a human was
//! supposed to remember to write. Nobody ever wrote one; the directory held only
//! `.tsv`. So the ten gates that carried the load defaulted to **silence**, and
//! silence read as fine. Run with `--include-ignored`, eight of them failed —
//! against conditions ("node A upgraded to 0.5.35", "persist v10 ships and we
//! re-pin") that had been overtaken by twenty releases.
//!
//! That is the defect this whole cut has been chasing, applied to the instrument
//! itself: **a check whose scope does not cover what it claims.** A suite that is
//! supposed to say "safe to release" was measuring a plan from months ago, and
//! had no gate at all for the thing this release is for.
//!
//! # The rule this ladder is built on
//!
//! **Hermetic, runnable, LOCAL invariants first.** A gate must be evaluable by
//! `cargo test --test release_gates` on a machine with no network, no peer, no
//! YubiKey and no operator. Where an external fact genuinely is the gate it stays
//! — but as a small, clearly separated minority in `boundary.rs`, and its absence
//! reads **BLOCKED**, never as a pass.
//!
//! # Two kinds of rung, and the honest scope of each
//!
//! 1. **Direct rungs** exercise the invariant here: they call the substrate, read
//!    the pinned vocabulary, or read the tree. What they assert, they prove.
//! 2. **Anchored rungs** assert that the *proof* of an invariant still exists and
//!    still runs — the covering test file is present, the named test functions are
//!    present, and each one still carries a `#[test]`/`#[tokio::test]` attribute.
//!    They deliberately do **not** re-implement the proof: re-implementing it
//!    forks it, and a forked proof drifts from the thing it covers.
//!
//!    The honest scope of an anchored rung is therefore: *the instrument for this
//!    invariant is still installed and still armed.* Whether it **passes** is
//!    answered by CI running the suite it names. An anchored rung fails when a
//!    proof is deleted, renamed, or quietly de-attributed into a dead helper —
//!    which is exactly how coverage disappears in practice.
//!
//! [`gate0_no_anchored_proof_is_an_empty_instrument`] closes the remaining hole in
//! that scope. A proof file behind `#![cfg(feature = "…")]` compiles to ZERO tests
//! without the feature and reports `test result: ok. 0 passed`, so such a file is
//! anchorable **only if a CI step actually runs it with that feature** — the gate
//! checks `.github/workflows/` for one. Compilation coverage is not execution
//! coverage, and this repo has now been caught by that distinction twice:
//! CIRISServer#373 (a bare `cargo test` tests the ROOT PACKAGE only, so a
//! workspace member's 364 tests never ran) and the eleven `test-anchor` tests that
//! were compiled by `clippy --all-targets --features test-anchor` and executed by
//! nothing. Both times the gap was in CI's SELECTION, not in any assertion.
//! [`DARK_TEST_FILES`] is the standing count of that debt.

#![allow(dead_code)]

use std::path::PathBuf;

// ─────────────────────────────────────────────────────────────────────────────
// Registry types
// ─────────────────────────────────────────────────────────────────────────────

/// One covering proof: a file in the tree, and the test functions in it that
/// carry the invariant. Paths are relative to the crate root, so a proof may
/// live in `tests/` (integration) or `src/` (unit) — several of the sharpest
/// discrimination proofs in this repo are `src/` unit tests.
pub struct Proof {
    pub file: &'static str,
    pub tests: &'static [&'static str],
}

/// One rung of the ladder: a thing 0.5 preserves, what shipping without it would
/// mean, and where the proof lives.
pub struct Invariant {
    /// Stable slug, used in failure text and in the duplicate check.
    pub id: &'static str,
    /// What 0.5 preserves, in one line.
    pub preserves: &'static str,
    /// **What is now unsafe to ship, and why.** This is the sentence someone
    /// reads at 2am deciding whether to tag; it must name the consequence, not
    /// the assertion.
    pub unsafe_to_ship: &'static str,
    /// The covering proofs. An empty slice is not permitted — see
    /// [`gate0_every_rung_names_a_proof_and_a_consequence`].
    pub proofs: &'static [Proof],
}

// ─────────────────────────────────────────────────────────────────────────────
// The rungs — what 0.5 preserves
// ─────────────────────────────────────────────────────────────────────────────

pub const TRACE_FLOW_INGEST: Invariant = Invariant {
    id: "trace-flow-ingest",
    preserves: "A signed trace batch posted over HTTP verifies, persists, and is \
                visible in the corpus — and a tampered or unknown-key batch persists nothing.",
    unsafe_to_ship: "The node's ONE job is to admit traces. Without this proof a cut can ship a \
                     server that accepts nothing (the 2026-08-03 outage: 8,631 correct refusals a \
                     day for 71 hours) or, worse, accepts a batch it did not verify. The tamper \
                     and unknown-key arms are the half that must stay: an ingest path that \
                     admits everything also 'works'.",
    proofs: &[
        Proof {
            file: "tests/ingest_http.rs",
            tests: &[
                "signed_batch_posted_to_legacy_path_persists",
                "signed_batch_posted_to_canonical_alias_persists",
                "tampered_batch_is_rejected_and_nothing_persists",
                "unknown_key_batch_is_rejected",
                "the_credits_namespace_incident_is_refused_by_name",
            ],
        },
        Proof {
            file: "tests/replication.rs",
            tests: &["signed_batch_replicates_and_verifies_across_independent_nodes"],
        },
    ],
};

pub const TRACE_FLOW_REPLICATION: Invariant = Invariant {
    id: "trace-flow-replication",
    preserves: "An agent-shaped node's sealed, consent-scoped `trace:*` reaches a \
                canonical-shaped node over a REAL anti-entropy round — and with no consent \
                grant, the same producer offers nothing.",
    unsafe_to_ship: "Peer replication is the plane the mesh is made of; HTTP ingest covers only \
                     the one node you posted to. Every predicate in this arc was found the same \
                     expensive way — a mesh run surfaced one silent gate, it got fixed, the next \
                     run surfaced the next — because nothing on this side ever drove an actual \
                     ROUND, and every defect lived in the seam between our surfaces and the \
                     substrate's. Shipping without this instrument means the next one is found by \
                     a peer operator whose plane went quiet, on a node they cannot debug.",
    // Behind `--features test-anchor` — conferring `infra:serve` is an ACCORD act
    // and the signing helpers that can perform a genuine 2-of-3 co-scrub live
    // behind that feature. Anchorable ONLY because ci.yml runs
    // `cargo test --features test-anchor --test trace_round_e2e --test trust_root_qa`;
    // `assert_proven` re-derives that from `.github/workflows/` rather than
    // trusting this comment, and refuses the anchor if the step ever goes away.
    // Without the feature this file compiles to ZERO tests and prints
    // `test result: ok. 0 passed` — a green line for an empty instrument, which
    // is what it was for as long as CI only CLIPPY'd the surface.
    proofs: &[Proof {
        file: "tests/trace_round_e2e.rs",
        tests: &[
            "agent_trace_reaches_canonical_over_a_real_round",
            // The negative is named here as well as under REPLICATION_BY_CONSENT,
            // deliberately: an arrival proof that could be satisfied by a widened
            // send gate would prove the wrong thing. The positive is only worth
            // what the negative costs it.
            "without_a_grant_the_producer_offers_nothing",
        ],
    }],
};

pub const TRACE_PLANE_LIVENESS: Invariant = Invariant {
    id: "trace-plane-liveness",
    preserves: "The trace plane has a reader: dark for two days is RED, a sustained rate of \
                CORRECT refusals from a small stable signer set is `stuck_producer`, and an \
                unreadable corpus is neither.",
    unsafe_to_ship: "This is the instrument whose absence cost the 2026-08-05 RCA. Every \
                     individual link was right and the composite was dead: arrival is the one \
                     thing this node exists to do and was the one thing unwatched. Shipping \
                     without it ships a node that can go dark for days while every gauge on it \
                     reads healthy — and a rate of correct refusals, which is a fault report \
                     about SOMEONE ELSE, stays invisible.",
    proofs: &[
        Proof {
            file: "tests/ingest_http.rs",
            tests: &["the_2026_08_05_incident_would_have_fired_on_the_operator_surface"],
        },
        Proof {
            file: "tests/trace_plane_release_gate.rs",
            tests: &[
                "a_second_arrival_moves_the_band_and_a_dark_plane_goes_green_again",
                "the_outage_shape_reads_stuck_producer_at_every_hour_of_its_71",
                "the_33_hour_overlap_window_reads_live_and_stuck_at_once",
                "the_watch_says_it_out_loud_and_then_stops_saying_it",
            ],
        },
        // The discrimination proofs — the readings that must NOT collapse into
        // one another — are `src/` unit tests, and they are worth more here than
        // the integration test: they are what stops `dark`, `unknown` and
        // `stuck_producer` becoming one grey "no data" tile.
        Proof {
            file: "src/operator_surface.rs",
            tests: &[
                "the_2026_08_05_incident_reads_red_and_an_unreadable_corpus_does_not",
                "the_same_refusal_rate_from_two_identities_and_from_thousands_do_not_render_the_same",
                "zero_distinct_signers_is_its_own_reading_and_never_a_stuck_producer",
                "a_flood_that_names_nobody_does_not_make_a_stuck_producer_of_one_stale_client",
                "the_incident_and_a_silent_pipe_are_both_dark_and_are_not_the_same_read",
            ],
        },
    ],
};

pub const KEX: Invariant = Invariant {
    id: "kex",
    preserves: "Federation session key exchange is hybrid and fails CLOSED — a tampered or \
                dropped ML-KEM ciphertext yields no session, and hybrid-required refuses a \
                classical-only peer. Occurrence KEX seals the same way.",
    unsafe_to_ship: "A KEX that fails OPEN downgrades every federation session to classical \
                     silently, and the failure is invisible from both ends because the session \
                     still establishes. Post-quantum custody is one of the two reasons the \
                     substrate is pinned as hard as it is; a cut that loses the fail-closed arms \
                     keeps the ceremony and loses the property.",
    proofs: &[
        Proof {
            file: "tests/federation_session_kex.rs",
            tests: &[
                "hybrid_handshake_derives_identical_session_key",
                "tampered_mlkem_ciphertext_fails_closed",
                "dropped_mlkem_ciphertext_fails_closed",
                "hybrid_required_rejects_classical_only_peer",
                "hybrid_path_always_carries_mlkem_ciphertext",
            ],
        },
        Proof {
            file: "tests/occurrence_kex_e2e.rs",
            tests: &["signed_occurrence_custody_replication_and_seal"],
        },
    ],
};

pub const BOTH_CONSENTS: Invariant = Invariant {
    id: "both-consents",
    preserves: "Replication consent (a peer may HOLD our traces) and CC#46 `analyze` consent (a \
                peer may SCORE them) are different dimensions on different edges. No scoring \
                without `analyze`.",
    unsafe_to_ship: "Measured on the production canonical 2026-08-01: 240 replication grants from \
                     240 distinct peers, 184 trace_events, and ZERO `consent:state:*` rows of any \
                     kind. Every one of those peers consented to SEND and not one could consent to \
                     be SCORED. Collapsing the two dimensions scores people who never agreed to \
                     be scored; dropping the `analyze` path leaves capacity scoring structurally \
                     dead on every node that boots through the fold — which is every embedded agent.",
    proofs: &[
        Proof {
            file: "tests/fold_consent_surface.rs",
            tests: &[
                "author_federation_consent_is_exported_to_the_fold",
                "the_fold_can_author_the_cc46_analyze_grant",
                "declining_to_be_scored_states_what_it_costs",
                "the_consent_disclosure_states_both_rules_and_all_three_costs",
            ],
        },
        Proof {
            file: "tests/capacity_scorer.rs",
            tests: &[
                "capacity_scorer_emits_n_eff_derived_attestation_end_to_end",
                "a_post_bound_capacity_row_stops_suppressing_the_scorer",
            ],
        },
    ],
};

pub const TRUST_ROOT: Invariant = Invariant {
    id: "trust-root-baked",
    preserves: "The canonical seed is baked, the kill-switch roster is 2-of-3, and a fresh node \
                boots rooted to it — first-run claim is single-use and refuses a tampered \
                signature or a wrong node pin.",
    unsafe_to_ship: "Without a baked recognition root the kill-switch falls back to an \
                     operator-writable roster, which is the whole reason 0.6 was held. Without \
                     the first-run claim arms, an unclaimed node on the network is a trust root \
                     anyone can take.",
    proofs: &[
        Proof {
            file: "tests/genesis_bundle_validate.rs",
            tests: &[
                "the_baked_seed_makes_every_fresh_node_serve",
                "the_baked_canonical_holds_every_scope_on_both_planes",
                "stage_one_is_idempotent_across_reboots",
            ],
        },
        Proof {
            file: "tests/root_bootstrap.rs",
            tests: &[
                "first_run_setup_root_claims_then_rejects_second_claim",
                "first_run_setup_root_rejects_tampered_signature",
                "first_run_setup_root_rejects_wrong_node_pin",
                "unarmed_node_rejects_claims",
                "claim_pin_is_consumed_after_successful_claim",
            ],
        },
        // The CEREMONY side, as opposed to the baked-artifact side above: mint a
        // portable accord+canonical root in substrate test mode and then USE it.
        // Behind `--features test-anchor`, which is only anchorable because
        // ci.yml now RUNS that target with the feature — until it did, these
        // seven reported as passing without ever executing.
        Proof {
            file: "tests/trust_root_qa.rs",
            tests: &[
                "qa_mints_and_produces_a_portable_genesis",
                "qa_envelope_carries_the_conferral",
                "qa_leg_a_serve_resolves",
                "qa_root_minimum_is_serve_and_attest",
                "qa_end_to_end_two_leg_gate",
                "qa_expired_trust_edge_is_dead",
                "qa_reblesses_an_unblessed_canonical_in_ceremony",
            ],
        },
    ],
};

pub const SIGNED_ROW_INTEGRITY: Invariant = Invariant {
    id: "signed-row-integrity",
    preserves: "A signed row's envelope-covered columns are never rewritten unsigned, a \
                revocation bound is enforced at every read that resolves whether a key's word \
                stands, and two claims at one instant from one key are recorded as equivocation \
                — including the node's own key.",
    unsafe_to_ship: "#541 is the carrier defect this class produced: an unsigned liveness refresh \
                     rewrote four envelope-covered columns while preserving the signature, so \
                     every peer refused the row and the whole trace plane went dark. Corrupt BY \
                     CONSTRUCTION, and green on the producer. Losing the revocation-bound or \
                     equivocation arms means a withdrawn key's statements keep standing and a \
                     peer can say two contradictory things without either being recorded.",
    proofs: &[
        Proof {
            file: "tests/revoked_after_enforcement.rs",
            tests: &[
                "compose_refuses_a_post_bound_score_and_keeps_the_pre_bound_one",
                "an_unbounded_revocation_refuses_every_score_including_the_oldest",
                "the_detector_drops_post_bound_rows_and_keeps_pre_bound_evidence",
                "ownership_survives_a_pre_bound_binding_and_fails_closed_on_a_post_bound_one",
                "config_reads_absent_after_the_bound_and_resolves_before_it",
            ],
        },
        Proof {
            file: "tests/equivocation.rs",
            tests: &[
                "a_peers_two_claims_at_one_instant_are_detected_and_recorded",
                "the_nodes_own_key_is_not_exempt",
                "an_unpublished_local_draft_is_not_evidence",
                "a_duplicated_statement_records_nothing",
            ],
        },
    ],
};

pub const REPLICATION_BY_CONSENT: Invariant = Invariant {
    id: "replication-by-consent",
    preserves: "Rows replicate because a consent state says they may — never by being copied into \
                an outbox. An unregistered peer's liveness is refused and a forged peer record is \
                not stored.",
    unsafe_to_ship: "An outbox is a second copy of the truth with its own lifetime, and it is the \
                     anti-pattern this model was built to delete: once a row exists in a send \
                     queue, revoking consent no longer stops it. Losing the forged-record arm \
                     means a merely-admitted peer can inject rows into canonical persist.",
    proofs: &[
        Proof {
            file: "tests/peer_replication.rs",
            tests: &[
                "peer_b_registered_admits_b_liveness_and_a_emits_directed_consent",
                "unregistered_peer_liveness_is_rejected",
                "forged_peer_record_is_rejected_and_not_stored",
                "consent_grant_states_its_whole_tuple",
            ],
        },
        // The policy that decides WHETHER a row may be served is persist's and
        // edge's, pinned by hash on our side — so a substrate bump that quietly
        // widens what replicates fails here rather than on the mesh.
        Proof {
            file: "tests/replication_policy_gate.rs",
            tests: &[
                "persist_replication_policy_hash_pinned",
                "edge_serve_advertise_policy_hash_pinned",
            ],
        },
        // The fail-secure half of the two-node round: with NO consent grant the
        // producer must offer NOTHING, which is exactly what "replicates only by
        // consent" means. The ARRIVAL half of that same file is a separate rung
        // ([`TRACE_FLOW_REPLICATION`]) because it answers a different question —
        // and for most of this cut it was a separate rung for a blunter reason:
        // it was RED, carried #[ignore]d in `boundary` against CIRISEdge#455, so
        // that the half which passed could not vouch for the half which did not.
        // Both are live now; they stay apart for the first reason.
        Proof {
            file: "tests/trace_round_e2e.rs",
            tests: &["without_a_grant_the_producer_offers_nothing"],
        },
    ],
};

pub const IDENTITY_DERIVED: Invariant = Invariant {
    id: "identity-derived",
    preserves: "A federation identity is DERIVED from the key material, never claimed. A surface \
                asks the engine who it is; it does not accept a key id from its caller \
                (CIRISServer#372).",
    unsafe_to_ship: "A surface that accepts a key id lets the caller name itself, and every \
                     authority decision downstream is then about a name the caller chose. The \
                     2026-08-05 outage is the same axis from the other side: `signing_key_id` \
                     carried identities minted by two different derivations and nothing in either \
                     type system said which namespace a value belonged to.",
    proofs: &[
        Proof {
            file: "tests/self_identity_fold.rs",
            tests: &[
                "the_label_and_the_engine_signer_are_different_facts",
                "resolve_is_the_engine_and_only_the_engine",
                "admin_ops_refuses_when_only_the_label_is_owner_bound",
                "admin_ops_refuses_loudly_when_it_cannot_resolve_itself",
                "federation_peers_does_not_render_an_unresolvable_self_as_zero_peers",
            ],
        },
        Proof {
            file: "tests/federation_key_id.rs",
            tests: &[
                "the_incident_id_cannot_become_a_federation_key_id",
                "every_derive_key_id_output_parses",
                "a_non_ed25519_key_cannot_mint_a_federation_id",
                "the_seal_stamps_the_derived_id_and_not_the_keystore_alias",
            ],
        },
    ],
};

pub const DISTINCT_ZEROES: Invariant = Invariant {
    id: "distinct-zeroes",
    preserves: "Could-not-ask is never rendered as nothing-there. Every zero on every operator \
                surface names its own cause, and the arms stay distinct within their closed set.",
    unsafe_to_ship: "Collapsing `not_exercised` into `idle` made an UNTESTED node read healthy — \
                     that is #356 restated, and it is the same shape as the RCA's \
                     `200 {\"peer_count_total\": 0}`: a confident, wrong, healthy-looking zero. A \
                     surface that cannot distinguish 'we could not ask' from 'the answer is none' \
                     reports safety it does not have.",
    proofs: &[
        Proof {
            file: "tests/operator_surface.rs",
            tests: &[
                "every_zero_carriage_reading_names_its_own_cause",
                "a_fresh_nodes_trace_and_ingest_zeroes_name_their_own_causes",
                "one_read_carries_both_sources_and_re_derives_neither",
            ],
        },
        Proof {
            file: "tests/mesh_config_surface.rs",
            tests: &[
                "property_4_every_standing_token_is_distinct_within_its_closed_set",
                "property_4_each_live_zero_arm_names_its_own_cause",
            ],
        },
        Proof {
            file: "tests/trace_plane_release_gate.rs",
            tests: &["the_three_trace_plane_zeroes_stay_three_on_a_real_engine"],
        },
    ],
};

pub const VOCABULARY_SINGLE_SOURCED: Invariant = Invariant {
    id: "vocabulary-single-sourced",
    preserves: "Envelope keys come from persist's exported constants, never a hand-mirrored \
                literal; the edge wire vocabulary matches the ratified hash.",
    unsafe_to_ship: "A raw `\"dimension\"` still COMPILES after persist renames the key, and then \
                     diverges on the wire. That is the silent-skew failure: green build, green \
                     tests, wrong bytes, and the divergence is only visible from a peer.",
    proofs: &[
        Proof {
            file: "tests/envelope_vocabulary_single_source.rs",
            tests: &["no_hand_mirrored_envelope_vocabulary_literals"],
        },
        Proof {
            file: "tests/wire_vocabulary_gate.rs",
            tests: &["edge_wire_vocabulary_matches_ratified_v1_0_1"],
        },
    ],
};

pub const LOCALIZATION_REACHABLE: Invariant = Invariant {
    id: "localization-reachable",
    preserves: "Every operator-facing message id resolves under the REAL loader semantics — \
                `LocalizationManager.resolveKey` always splits on `.` and walks nested objects, \
                with no top-level exact-match fallback.",
    unsafe_to_ship: "A flat dotted key is dead for every reader in every language, English \
                     included, and the bundle checker cannot see it: its `flatten()` maps a flat \
                     dotted key and a nested path to the SAME string, so a key the loader can \
                     never resolve passes the guard. That is this cut's defect class exactly — a \
                     check whose scope does not cover what it claims — and it ships an operator \
                     surface that renders raw dotted tokens.",
    proofs: &[
        Proof {
            file: "tests/localization_bundle_shape.rs",
            tests: &[
                "no_top_level_key_in_the_canonical_bundle_contains_a_dot",
                "no_key_at_any_depth_in_the_canonical_bundle_contains_a_dot",
                // The gate's own mutation proofs — the predicate is exercised
                // against a deliberately flattened key, so the gate is shown able
                // to fail without anyone having to break the real bundle.
                "the_top_level_predicate_catches_a_flattened_key",
                "the_any_depth_predicate_catches_a_key_flattened_below_the_root",
            ],
        },
        Proof {
            file: "tests/mesh_config_consumers.rs",
            tests: &["every_consumption_message_resolves_in_the_canonical_bundle"],
        },
        // CIRISServer#366 — the server-side census: every id the Rust emitters
        // actually produce, resolved through the loader's own rules, with a FLOOR
        // on the scraped population so a scraper that stopped seeing emission
        // sites cannot report zero findings and read green. `..._proves_it_can_fail`
        // is the falsifiability arm, and it is named in this anchor deliberately:
        // it is the difference between a guard and a guard someone has shown able
        // to fail.
        Proof {
            file: "tests/localization_gate.rs",
            tests: &[
                "server_emitted_message_ids_resolve_under_loader_semantics",
                "server_emitted_message_id_coverage_does_not_regress",
                "localization_bundles_pass_the_guard",
                "localization_guard_self_test_proves_it_can_fail",
                "rust_and_python_resolvers_agree_on_the_bundle",
            ],
        },
    ],
};

pub const ERASURE_NOISE_FLOOR: Invariant = Invariant {
    id: "erasure-noise-floor",
    preserves: "Provable individual-unrecoverability: revocation hard-deletes with no retained \
                tier reconstructing, the measured noise floor sits below the information floor, \
                and N→1 aggregation erases the individual below the 1/N gist bound.",
    unsafe_to_ship: "This is the erasure-compliance claim the project makes in public. It is a \
                     MEASURED property, not a design intent — losing the measurement means the \
                     claim is an assertion about code nobody re-measured.",
    // NB: the N→1 aggregation sub-claim is NOT in this list. It is declared in
    // [`UNPROVEN`] instead, because its test has never run — see the comment there.
    proofs: &[Proof {
        file: "tests/noise_floor.rs",
        tests: &[
            "revocation_hard_deletes_and_no_retained_tier_reconstructs",
            "revocation_purges_member_tiers_but_not_the_composite",
            "measured_noise_floor_below_information_floor",
            "structured_and_known_plaintext_stay_below_floor",
            "dominance_and_multiplicity_are_rejected_on_v3",
        ],
    }],
};

/// **What 0.5.156 does NOT prove, said out loud.**
///
/// A rung must never quietly narrow itself to whatever happens to be green. Where
/// part of an invariant has no live coverage, the gap is declared here — and the
/// declaration is itself gated by
/// [`gate0_the_unproven_gaps_are_still_gaps`], which re-derives each entry
/// rather than taking its word. So a gap cannot be forgotten, and it cannot be
/// closed without someone noticing that the declaration is now false.
///
/// `(rung id, file::test, why it does not run)`
pub const UNPROVEN: &[(&str, &str, &str, &str)] = &[(
    ERASURE_NOISE_FLOOR.id,
    "tests/noise_floor.rs",
    "aggregation_collapse_erases_the_individual_pending_ciris_edge_266",
    "#[ignore]d as a WAITING ACCEPTANCE TEST (CIRISServer#239). Edge's N→1 operator has \
     shipped since v9.0.0; what is missing is this test CALLING it. As written it builds a \
     fabricated independent composite, which makes residual_fidelity < 1/N true by \
     construction — a number, not a proof. So the '1/N gist bound' half of the erasure claim \
     is currently DESIGN INTENT, not a measurement, and 0.5.156 must not say otherwise.",
)];

/// **The dark test files** — compiled by CI, never executed by it.
///
/// A file opening `#![cfg(feature = "…")]` contains zero tests under a plain
/// `cargo test` and prints `test result: ok. 0 passed`. Worse, `ci.yml` DOES
/// compile this surface (`cargo clippy --all-targets --features test-anchor`), so
/// these files cannot rot into a compile error — which is exactly why nobody
/// noticed they never run. Compiled, never executed, reported as passing.
///
/// [`gate0_no_anchored_proof_is_an_empty_instrument`] stops the ladder ANCHORING
/// to them. This list is the other half: the set is pinned, so a fifth instance
/// cannot appear quietly, and a file that starts being run cannot stay declared
/// dark.
///
/// `(file, feature, live test count, what is dark)`
///
/// **Currently EMPTY, and that is a fact worth its own sentence.** Both entries
/// this list was created to hold — `tests/trace_round_e2e.rs` (4 tests) and
/// `tests/trust_root_qa.rs` (7) — were compiled by CI and executed by nothing:
/// `ci.yml` built the surface with `clippy --all-targets --features test-anchor`,
/// so they could never rot into a compile error, which is exactly why eleven
/// tests reported as passing for as long as they did. Among them was the
/// in-process two-node round harness — the instrument for the very outage main's
/// RCA commit is named after.
///
/// `ci.yml` now runs `cargo test --features test-anchor --test trace_round_e2e
/// --test trust_root_qa`, so both are live and both are anchored by rungs below.
/// The list stays, empty, because
/// [`gate0_the_dark_test_files_are_exactly_the_ones_we_know_about`] is what stops
/// a third instance appearing quietly — twice now the gap has been in CI's
/// SELECTION (which targets, which features) rather than in any assertion, and
/// compilation coverage is not execution coverage.
pub const DARK_TEST_FILES: &[(&str, &str, usize, &str)] = &[];

/// Every rung, in ladder order. The gates below iterate this; a rung that is not
/// here is not gated.
pub const LADDER: &[&Invariant] = &[
    &TRACE_FLOW_INGEST,
    &TRACE_FLOW_REPLICATION,
    &TRACE_PLANE_LIVENESS,
    &KEX,
    &BOTH_CONSENTS,
    &TRUST_ROOT,
    &SIGNED_ROW_INTEGRITY,
    &REPLICATION_BY_CONSENT,
    &IDENTITY_DERIVED,
    &DISTINCT_ZEROES,
    &VOCABULARY_SINGLE_SOURCED,
    &LOCALIZATION_REACHABLE,
    &ERASURE_NOISE_FLOOR,
];

// ─────────────────────────────────────────────────────────────────────────────
// Machinery
// ─────────────────────────────────────────────────────────────────────────────

pub fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Fail a gate that **cannot be evaluated**. Distinct wording from a failed
/// assertion on purpose: an un-evaluable gate must never be mistaken for one that
/// passed, and must never be mistaken for one that measured something and
/// disagreed.
#[track_caller]
pub fn blocked(gate: &str, why: &str) -> ! {
    panic!(
        "\n\
         ⛔ RELEASE GATE {gate} — BLOCKED, NOT PASSED.\n\
         \n\
         This gate could not be evaluated. That is not the same as an invariant\n\
         holding, and it must not be recorded as one.\n\
         \n\
         {why}\n"
    );
}

/// Read the pinned git `tag` of a substrate crate from the workspace `Cargo.toml`.
/// Returns the FIRST `<crate> = { … tag = "…" }` occurrence (the root
/// `[dependencies]` pin, which is what ships).
pub fn cargo_pin(crate_name: &str) -> Option<String> {
    pin_in(&cargo_toml(), crate_name).map(|(_, tag)| tag)
}

pub fn cargo_toml() -> String {
    std::fs::read_to_string(repo().join("Cargo.toml")).expect("Cargo.toml must be readable")
}

fn pin_in(toml: &str, crate_name: &str) -> Option<(usize, String)> {
    for (n, line) in toml.lines().enumerate() {
        if let Some(tag) = tag_on_line(line, crate_name) {
            return Some((n + 1, tag));
        }
    }
    None
}

/// `<crate> = { … tag = "…" }` on one line → the tag. `None` otherwise. Matches
/// the crate name followed by whitespace then `=`, so `ciris-persist-foo` does
/// not match `ciris-persist`.
pub fn tag_on_line(line: &str, crate_name: &str) -> Option<String> {
    let t = line.trim_start();
    if t.starts_with('#') {
        return None;
    }
    let rest = t.strip_prefix(crate_name)?;
    if !rest.trim_start().starts_with('=') {
        return None;
    }
    let i = line.find("tag = \"")?;
    let after = &line[i + "tag = \"".len()..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

/// Is this proof file gated behind a crate feature (`#![cfg(feature = "…")]`)?
/// Such a file compiles to ZERO tests without the feature and reports
/// `test result: ok. 0 passed` — an empty instrument.
pub fn feature_gate_of(src: &str) -> Option<String> {
    for line in src.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix("#![cfg(feature = \"") else {
            continue;
        };
        let end = rest.find('"')?;
        return Some(rest[..end].to_string());
    }
    None
}

/// The ATTRIBUTE block immediately above `fn name(`, or `None` if there is no
/// such function.
///
/// Walks upward from the `fn` line and stops at the first line of real code —
/// which is either the previous item's closing brace or the previous statement —
/// so the block can never reach across into another function's attributes. An
/// attribute whose string argument wraps over several lines (`#[ignore = "… \`)
/// is followed by bracket balance rather than by indentation, because rustfmt
/// re-wraps those freely and a walker a formatter can break is not a walker.
///
/// **Comments are walked THROUGH but not returned.** This gate's own first
/// version returned them, and immediately produced the defect it exists to
/// catch: `tests/noise_floor.rs` carries the prose line
/// `// … then drop the #[ignore].` above a test, and the walker read that
/// sentence ABOUT an attribute as the attribute itself. Same shape as everything
/// else in this cut — the scope of what was collected did not match what the
/// caller was told it meant.
fn attribute_block<'a>(src: &'a str, name: &str) -> Option<String> {
    let needle = format!("fn {name}(");
    let lines: Vec<&'a str> = src.lines().collect();
    let idx = lines.iter().position(|l| l.contains(&needle))?;
    let mut block: Vec<&str> = Vec::new();
    let mut i = idx;
    while i > 0 {
        i -= 1;
        let line = lines[i];
        let t = line.trim();
        let unbalanced = std::iter::once(line)
            .chain(block.iter().copied())
            .flat_map(|l| l.chars())
            .fold(0i32, |b, c| match c {
                '[' => b + 1,
                ']' => b - 1,
                _ => b,
            })
            != 0;
        if t.is_empty() || t.starts_with("#[") || t.starts_with("//") || unbalanced {
            block.insert(0, line);
            continue;
        }
        break;
    }
    Some(
        block
            .into_iter()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// Is `name` present in `src` as a test that will actually RUN?
///
/// Three ways coverage disappears, all of which keep compiling and keep reading
/// like coverage:
///   * the test is deleted or renamed;
///   * its `#[test]` attribute is stripped, leaving a dead helper;
///   * it is `#[ignore]`d — which is the quietest of the three, because the
///     suite still lists it and still reports `ok`.
fn armed_test(src: &str, name: &str) -> Result<(), String> {
    let Some(block) = attribute_block(src, name) else {
        return Err("ABSENT (no such function)".to_string());
    };
    if !(block.contains("#[test]") || block.contains("#[tokio::test")) {
        return Err(
            "present but NOT ARMED (no #[test]/#[tokio::test] attribute) — it compiles, it \
             reads like coverage, and it never runs"
                .to_string(),
        );
    }
    if block.contains("#[ignore") {
        return Err(
            "present and armed but #[ignore]d — it is listed in the suite, it reports `ok`, \
             and it has never executed"
                .to_string(),
        );
    }
    Ok(())
}

/// Is `name` in `src` genuinely NOT running? The inverse of [`armed_test`], used
/// to verify the declared-unproven list rather than take its word.
fn definitely_not_running(src: &str, name: &str) -> bool {
    armed_test(src, name).is_err()
}

/// Assert that every covering proof of `inv` is present and armed.
///
/// See the module header for the honest scope of this: it asserts the instrument
/// is installed and armed, not that it currently reads green.
#[track_caller]
pub fn assert_proven(inv: &Invariant) {
    let mut lost: Vec<String> = Vec::new();
    for p in inv.proofs {
        let path = repo().join(p.file);
        let Ok(src) = std::fs::read_to_string(&path) else {
            lost.push(format!("  {} — FILE ABSENT", p.file));
            continue;
        };
        // A feature-gated proof is anchorable only if CI actually RUNS it with
        // that feature. Compilation coverage is not execution coverage.
        if let Some(feat) = feature_gate_of(&src) {
            if !ci_runs_with_feature(&feat) {
                lost.push(format!(
                    "  {} — behind #![cfg(feature = \"{feat}\")] and NO CI step runs it with \
                     that feature: it compiles to ZERO tests and reports `ok. 0 passed`",
                    p.file
                ));
                continue;
            }
        }
        for name in p.tests {
            if let Err(why) = armed_test(&src, name) {
                lost.push(format!("  {}::{name} — {why}", p.file));
            }
        }
    }
    assert!(
        lost.is_empty(),
        "\n\
         🚫 RELEASE GATE [{id}] — DO NOT TAG.\n\
         \n\
         0.5 preserves: {preserves}\n\
         \n\
         Unsafe to ship: {unsafe_to_ship}\n\
         \n\
         The proof of this invariant is gone or disarmed:\n\
         {lost}\n\
         \n\
         Restore the named coverage, or — if the invariant genuinely moved — move this\n\
         rung's `Proof` entry in tests/release_gates/ladder.rs to wherever it now lives.\n\
         Deleting the rung is a decision to stop preserving the invariant, and must be\n\
         made deliberately, not as a way to make this message go away.\n",
        id = inv.id,
        preserves = inv.preserves,
        unsafe_to_ship = inv.unsafe_to_ship,
        lost = lost.join("\n"),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// GATE 0 — the ratchets that keep this ladder from becoming the last one
// ─────────────────────────────────────────────────────────────────────────────

/// Every `.rs` file of the ladder, as `(name, source)`.
fn gate_sources() -> Vec<(String, String)> {
    let dir = repo().join("tests/release_gates");
    let mut out = vec![(
        "release_gates.rs".to_string(),
        std::fs::read_to_string(repo().join("tests/release_gates.rs")).expect("suite root"),
    )];
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("tests/release_gates must be readable")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("rs"))
        .collect();
    entries.sort();
    for p in entries {
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        out.push((name, std::fs::read_to_string(&p).expect("gate source")));
    }
    out
}

/// The ONLY gates permitted to carry `#[ignore]`, each with the reason it is
/// RED-BY-DESIGN rather than merely inconvenient.
///
/// Every one of these is watched from the live side by
/// [`crate::boundary::gate0_no_forward_rung_has_quietly_become_satisfiable`], so
/// an ignored gate cannot sit here after reality has moved past it — which is
/// precisely how the previous ladder rotted.
///
/// This list is one shorter than it was. `gate_trace_flow_over_replication` sat
/// here against CIRISEdge#455; persist v30.1.0 / edge v15.18.3 closed the last
/// cause, the watcher fired in the same commit that made it true, and the rung
/// went live as [`crate::planes::gate_trace_flow_over_replication`]. An entry
/// leaving this list is the intended end state of every entry on it.
pub const IGNORE_ALLOWLIST: &[(&str, &str)] = &[
    (
        "gate_registry_surface_present",
        "the 0.6 boundary — RED by design while we are on 0.5.X",
    ),
    (
        "gate_peer_nodes_on_the_shipping_floor",
        "external fact — needs a reachable peer; BLOCKED, never passed, without one",
    ),
];

/// **The ratchet.** The previous ladder's fatal property was that its most
/// important gates did not run: ten of nineteen `#[ignore]`d against evidence
/// files nobody wrote, so they defaulted to silence and silence read as fine.
///
/// So: an `#[ignore]` in this suite is permitted only for a gate on
/// [`IGNORE_ALLOWLIST`], and only when the ignore reason says out loud that it is
/// red by design. Anything else is a gate that has been quietly switched off.
#[test]
fn gate0_no_gate_is_silently_ignored() {
    let mut offences: Vec<String> = Vec::new();
    for (file, src) in gate_sources() {
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("#[ignore") {
                continue;
            }
            // The test this ignore belongs to: the next `fn …(` below it.
            let owner = lines[i..]
                .iter()
                .find_map(|l| {
                    let t = l.trim_start();
                    let t = t.strip_prefix("pub ").unwrap_or(t);
                    let t = t.strip_prefix("async ").unwrap_or(t);
                    let rest = t.strip_prefix("fn ")?;
                    Some(rest.split('(').next().unwrap_or("").to_string())
                })
                .unwrap_or_else(|| "<no function below this attribute>".to_string());
            match IGNORE_ALLOWLIST.iter().find(|(n, _)| *n == owner) {
                None => offences.push(format!(
                    "  {file}:{} — `{owner}` is #[ignore]d and is NOT on the allowlist",
                    i + 1
                )),
                Some(_) if !line.contains("RED BY DESIGN") => offences.push(format!(
                    "  {file}:{} — `{owner}` is allowed to be ignored, but its reason does not \
                     say RED BY DESIGN",
                    i + 1
                )),
                Some(_) => {}
            }
        }
    }
    assert!(
        offences.is_empty(),
        "\n\
         🚫 RELEASE LADDER — a gate has been switched off.\n\
         \n\
         Unsafe to ship: an `#[ignore]`d gate does not run, and a gate that does not run\n\
         is indistinguishable from one that passed. That is exactly how the ladder this\n\
         replaced rotted: ten of nineteen tests ignored against evidence files nobody\n\
         ever wrote, so the suite reported 'safe to release' while measuring nothing.\n\
         \n\
         {}\n\
         \n\
         Either fix the invariant so the gate can run, or — if it is genuinely a forward\n\
         gate that is RED BY DESIGN — add it to IGNORE_ALLOWLIST in\n\
         tests/release_gates/ladder.rs together with a live watcher in boundary.rs that\n\
         fails the moment it becomes satisfiable.\n",
        offences.join("\n"),
    );
}

/// A rung with no proof, or with no stated consequence, is decoration. Also
/// catches a duplicated id, which would let one rung silently shadow another.
#[test]
fn gate0_every_rung_names_a_proof_and_a_consequence() {
    let mut bad: Vec<String> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for inv in LADDER {
        if inv.proofs.is_empty() {
            bad.push(format!("  [{}] declares no proof at all", inv.id));
        }
        if inv.proofs.iter().any(|p| p.tests.is_empty()) {
            bad.push(format!(
                "  [{}] names a proof FILE with no test functions in it — a file is not coverage",
                inv.id
            ));
        }
        if inv.unsafe_to_ship.len() < 60 {
            bad.push(format!(
                "  [{}] does not say what is unsafe to ship. Someone reads these at 2am.",
                inv.id
            ));
        }
        if seen.contains(&inv.id) {
            bad.push(format!("  [{}] is declared twice", inv.id));
        }
        seen.push(inv.id);
    }
    assert!(
        bad.is_empty(),
        "\n\
         🚫 RELEASE LADDER — a rung reports safety it does not provide.\n\n{}\n",
        bad.join("\n"),
    );
}

/// **Every declared gap is still a gap.**
///
/// [`UNPROVEN`] is the ladder telling the truth about what it does not cover. A
/// declaration like that decays in two directions and both are silent: the gap
/// gets fixed and the declaration lingers, so the ladder under-claims and the
/// entry becomes noise nobody reads; or the entry is edited to describe something
/// else and nothing checks. So the declaration is not taken on trust — each entry
/// is re-derived from the tree.
#[test]
fn gate0_the_unproven_gaps_are_still_gaps() {
    let mut stale: Vec<String> = Vec::new();
    for (rung, file, test, _why) in UNPROVEN {
        let Ok(src) = std::fs::read_to_string(repo().join(file)) else {
            stale.push(format!(
                "  [{rung}] {file} is GONE — the declared gap describes a file that no longer \
                 exists, so nobody can tell whether the gap closed or the coverage was deleted"
            ));
            continue;
        };
        if !definitely_not_running(&src, test) {
            stale.push(format!(
                "  [{rung}] {file}::{test} now RUNS — the declared gap has been closed. Move it \
                 out of UNPROVEN and into that rung's `proofs`, so the ladder starts claiming \
                 the coverage it now has."
            ));
        }
        if LADDER.iter().all(|inv| inv.id != *rung) {
            stale.push(format!("  [{rung}] is not a rung on the ladder"));
        }
    }
    assert!(
        stale.is_empty(),
        "\n\
         🔔 RELEASE LADDER — the declared-gap list no longer describes reality.\n\
         \n\
         {}\n",
        stale.join("\n"),
    );
}

/// Every test function in `src` that carries a live test attribute.
fn live_test_count(src: &str) -> usize {
    let lines: Vec<&str> = src.lines().collect();
    lines
        .iter()
        .enumerate()
        .filter(|(i, l)| {
            let t = l.trim_start();
            let t = t.strip_prefix("pub ").unwrap_or(t);
            let t = t.strip_prefix("async ").unwrap_or(t);
            if !t.starts_with("fn ") {
                return false;
            }
            let Some(name) = t[3..].split('(').next() else {
                return false;
            };
            let _ = i;
            attribute_block(src, name.trim()).is_some_and(|b| {
                (b.contains("#[test]") || b.contains("#[tokio::test")) && !b.contains("#[ignore")
            })
        })
        .count()
}

/// Does any CI workflow RUN `file` with `feature`?
fn ci_runs_with_feature(feature: &str) -> bool {
    let dir = repo().join(".github/workflows");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return false;
    };
    for e in entries.flatten() {
        let Ok(src) = std::fs::read_to_string(e.path()) else {
            continue;
        };
        for line in src.lines() {
            let code = line.split('#').next().unwrap_or("");
            if code.contains("cargo test")
                && (code.contains(&format!("--features {feature}"))
                    || code.contains(&format!("--features={feature}"))
                    || code.contains("--all-features"))
            {
                return true;
            }
        }
    }
    false
}

/// **The dark set is exactly the one we know about.**
///
/// Pins [`DARK_TEST_FILES`] against the tree and against CI, in both directions:
///
///   * a NEW feature-gated test file is a fifth instance of the pattern and must
///     be declared, not discovered later;
///   * a declared file that gains or loses tests changes how much is dark, and
///     the number is the whole point — "two tests" and "eleven tests" are
///     different propositions about this release;
///   * a declared file that CI STARTS running is no longer dark, and leaving it
///     on the list would understate the suite exactly as badly as omitting it
///     overstates it.
///
/// This gate is deliberately not the fix. Adding `--features test-anchor` to CI
/// means shipping a step nobody has run — the harness may well be red today (the
/// serve-gate leg-B fixture wants a trust-root ceremony `test_bless` never
/// performs), and shipping an unrun CI step is the same sin one level up. This
/// gate makes the debt VISIBLE and countable, and stops it growing, which is what
/// a release gate can honestly do about it.
#[test]
fn gate0_the_dark_test_files_are_exactly_the_ones_we_know_about() {
    let mut found: Vec<(String, String, usize)> = Vec::new();
    for e in std::fs::read_dir(repo().join("tests")).expect("tests/ readable") {
        let p = e.expect("dir entry").path();
        if p.extension().and_then(|x| x.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&p).expect("test source");
        // Dark = compiles but never EXECUTES. Feature-gated is only half of it;
        // a feature-gated file that CI runs with its feature is perfectly live.
        // Conflating the two is the same scope error one level up.
        if let Some(feat) = feature_gate_of(&src) {
            if ci_runs_with_feature(&feat) {
                continue;
            }
            found.push((
                format!(
                    "tests/{}",
                    p.file_name().and_then(|f| f.to_str()).unwrap_or_default()
                ),
                feat,
                live_test_count(&src),
            ));
        }
    }
    found.sort();

    let mut wrong: Vec<String> = Vec::new();
    for (file, feat, n) in &found {
        match DARK_TEST_FILES
            .iter()
            .find(|(f, _, _, _)| f == file && *n > 0)
        {
            None if DARK_TEST_FILES.iter().all(|(f, _, _, _)| f != file) => wrong.push(format!(
                "  UNDECLARED: {file} is behind #![cfg(feature = \"{feat}\")] with {n} test(s) \
                 that never run under `cargo test`"
            )),
            _ => {}
        }
        if let Some((_, want_feat, want_n, _)) =
            DARK_TEST_FILES.iter().find(|(f, _, _, _)| f == file)
        {
            if want_feat != feat {
                wrong.push(format!(
                    "  {file}: declared behind \"{want_feat}\", actually behind \"{feat}\""
                ));
            }
            if want_n != n {
                wrong.push(format!(
                    "  {file}: declared {want_n} dark test(s), tree now has {n} — the size of \
                     what never runs has changed"
                ));
            }
        }
    }
    for (file, feat, _, _) in DARK_TEST_FILES {
        if !found.iter().any(|(f, _, _)| f == file) {
            wrong.push(format!(
                "  {file}: declared dark, but it now RUNS — either CI gained a `cargo test \
                 --features {feat}` step for it, or the file is no longer feature-gated (or no \
                 longer exists). Take it off DARK_TEST_FILES and anchor the rungs it proves; \
                 leaving it declared understates the suite exactly as badly as omitting a real \
                 one overstates it."
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "\n\
         🔔 RELEASE LADDER — the set of tests that never run has changed.\n\
         \n\
         Unsafe to ship: a test file behind `#![cfg(feature = \"…\")]` compiles to ZERO\n\
         tests and prints `test result: ok. 0 passed`. CI DOES compile this surface\n\
         (`cargo clippy --all-targets --features test-anchor`), so it never rots into a\n\
         compile error — which is precisely why nobody notices it never executes.\n\
         Compiled, never run, reported as passing.\n\
         \n\
         {}\n\
         \n\
         Declare it in DARK_TEST_FILES with its count and what is dark about it, or —\n\
         better — get it running and anchor a rung to it.\n",
        wrong.join("\n"),
    );
}

/// **An anchored proof must actually run.**
///
/// `tests/trace_round_e2e.rs` and `tests/trust_root_qa.rs` open with
/// `#![cfg(feature = "test-anchor")]`. Under a plain `cargo test` they contain
/// zero tests and print `test result: ok. 0 passed` — a green line for an empty
/// instrument. Anchoring a rung to such a file would anchor it to a proof that
/// never executes, so [`assert_proven`] refuses them and this gate states the
/// rule up front rather than leaving it to be rediscovered.
#[test]
fn gate0_no_anchored_proof_is_an_empty_instrument() {
    let mut dead: Vec<String> = Vec::new();
    for inv in LADDER {
        for p in inv.proofs {
            let Ok(src) = std::fs::read_to_string(repo().join(p.file)) else {
                continue; // assert_proven reports the absence; not this gate's job.
            };
            if let Some(feat) = feature_gate_of(&src) {
                if !ci_runs_with_feature(&feat) {
                    dead.push(format!(
                        "  [{}] anchors {} — behind #![cfg(feature = \"{feat}\")], and no CI \
                         step runs it with that feature",
                        inv.id, p.file
                    ));
                }
            }
        }
    }
    assert!(
        dead.is_empty(),
        "\n\
         🚫 RELEASE LADDER — a rung is anchored to a proof that does not run.\n\
         \n\
         Unsafe to ship: a file behind `#![cfg(feature = \"…\")]` compiles to ZERO tests\n\
         without that feature and reports `test result: ok. 0 passed`. The ladder would\n\
         report the invariant covered while nothing executed — the empty-instrument\n\
         shape, which is worse than no gate because it reads green.\n\
         \n\
         {}\n\
         \n\
         Either anchor a rung to coverage that runs under a plain `cargo test`, or add a\n\
         CI step that runs the named file WITH its feature and re-anchor deliberately.\n",
        dead.join("\n"),
    );
}

/// Every workflow file is one GitHub Actions will actually accept.
///
/// This gate exists because of the way it was found. `0.5.158` added a
/// workflow-level `env:` block to `ci.yml` and `release.yml` for the crates.io
/// HTTP/2 hardening — and both files already HAD one. The result was a duplicate
/// top-level key. It was validated before the push, with `yaml.safe_load`, which
/// accepts duplicate keys silently and keeps the last: the check passed, and
/// Actions rejected both files outright on the tag push. Two workflows went from
/// green to `startup_failure` in under a second.
///
/// So the validator and the consumer disagreed, and the validator was the lenient
/// one. **A check is only worth what it shares with the thing it stands in for**;
/// `safe_load` answered "is this YAML" when the question was "will Actions run
/// this". That is the same shape as the rest of this cut's defects — an
/// instrument reporting on a plane adjacent to the one that matters — and it is
/// the most dangerous instance of it available in this repo, because a workflow
/// that fails to parse does not run ONE gate. It runs none of them, and a ladder
/// of thirty rungs reports nothing at all while `main` is red for a reason no
/// rung can see.
///
/// Failing here means: whatever else is true of this tree, CI cannot speak for it.
#[test]
fn gate0_every_workflow_is_one_actions_will_accept() {
    let dir = repo().join(".github/workflows");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
        .collect();
    files.sort();

    // A zero denominator is itself the error — see the rest of this suite.
    assert!(
        !files.is_empty(),
        "\n🚫 RELEASE LADDER — no workflow files found under {}.\n\
         Either CI was deleted or this gate is looking in the wrong place; both are\n\
         release-blocking, and neither may read as a pass.\n",
        dir.display(),
    );

    let mut bad = Vec::new();
    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let src = std::fs::read_to_string(path).unwrap_or_default();

        // Top-level keys only: column 0, not a comment, not a list item. Block
        // scalars (`run: |`) are always indented under a job, so their bodies
        // cannot produce a column-0 match.
        let mut seen: Vec<(String, usize)> = Vec::new();
        for (i, line) in src.lines().enumerate() {
            if line.starts_with([' ', '\t', '#', '-']) || line.trim().is_empty() {
                continue;
            }
            let Some((k, _)) = line.split_once(':') else {
                continue;
            };
            let key = k.trim().trim_matches(['"', '\'']).to_string();
            if key.is_empty() || !k.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
                continue;
            }
            if let Some((_, first)) = seen.iter().find(|(s, _)| *s == key) {
                bad.push(format!(
                    "  {name}: DUPLICATE top-level key `{key}` — line {} and line {}.\n    \
                     YAML parsers keep the last and drop the first silently; Actions refuses\n    \
                     the file. Merge the two blocks; never append a second one.",
                    first + 1,
                    i + 1,
                ));
            } else {
                seen.push((key, i));
            }
        }

        // The two keys Actions requires to schedule anything at all.
        for required in ["on", "jobs"] {
            if !seen.iter().any(|(k, _)| k == required) {
                bad.push(format!(
                    "  {name}: no top-level `{required}:` — Actions cannot schedule this file."
                ));
            }
        }
    }

    assert!(
        bad.is_empty(),
        "\n\
         🚫 RELEASE LADDER — a workflow file will not parse, so CI cannot speak for this tree.\n\
         \n\
         {}\n\
         \n\
         Examined {} workflow file(s) under .github/workflows.\n\
         \n\
         Note for whoever fixes this: `yaml.safe_load` will NOT reproduce a duplicate-key\n\
         failure — it accepts them and keeps the last. That leniency is what let this ship.\n",
        bad.join("\n"),
        files.len(),
    );
}

/// `scripts/preflight.sh` runs what `ci.yml` runs.
///
/// The preflight script duplicates CI's cargo invocations so they can be run
/// before a push. A duplicate that can drift is worth less than no duplicate:
/// it would keep reporting green about a CI that had moved on, and the person
/// trusting it would be worse off than the person who ran nothing. So the
/// duplication is checked rather than hoped about.
///
/// The allow-list is jobs whose commands genuinely cannot run on a contributor's
/// machine — the iOS legs need macOS and installed Apple targets. Naming them
/// here is the point: a skip that is written down is a decision, and a skip that
/// is silent is a gap nobody knows they have.
#[test]
fn gate0_preflight_runs_what_ci_runs() {
    const PLATFORM_ONLY: &[&str] = &["ios-build", "ios-package"];

    let ci = std::fs::read_to_string(repo().join(".github/workflows/ci.yml"))
        .expect("ci.yml unreadable");
    let pre = std::fs::read_to_string(repo().join("scripts/preflight.sh"))
        .expect("scripts/preflight.sh unreadable — CI's checks have no local runner");

    // Walk ci.yml tracking which job we are inside, collecting cargo commands.
    let mut job = String::new();
    let mut want: Vec<(String, String)> = Vec::new();
    for line in ci.lines() {
        // job ids sit at exactly two spaces of indent under `jobs:`
        if let Some(rest) = line.strip_prefix("  ") {
            if !rest.starts_with(' ') && rest.ends_with(':') && !rest.contains(' ') {
                job = rest.trim_end_matches(':').to_string();
            }
        }
        // CI writes these two ways, and only one of them starts with `cargo`:
        //   - run: cargo fmt --all --check      (inline)
        //     run: |                            (block, one command per line)
        //       cargo test
        let t = line
            .trim()
            .trim_start_matches("- ")
            .trim_start_matches("run:")
            .trim();
        if t.starts_with("cargo ") && !t.contains("--version") && !t.contains("--help") {
            if PLATFORM_ONLY.contains(&job.as_str()) {
                continue;
            }
            // matrix/env expansions cannot be compared literally
            if t.contains("${{") || t.contains('$') {
                continue;
            }
            want.push((job.clone(), t.to_string()));
        }
    }

    assert!(
        !want.is_empty(),
        "\n🚫 RELEASE LADDER — parsed ZERO cargo commands out of ci.yml.\n\
         The parser has drifted from the file's shape, so this gate is measuring\n\
         nothing and would pass no matter what preflight.sh contained. A zero\n\
         denominator is the error, not a pass.\n",
    );

    let missing: Vec<_> = want
        .iter()
        .filter(|(_, cmd)| !pre.contains(cmd.as_str()))
        .map(|(job, cmd)| format!("  [{job}]  {cmd}"))
        .collect();

    assert!(
        missing.is_empty(),
        "\n\
         🚫 RELEASE LADDER — scripts/preflight.sh does not run everything ci.yml runs.\n\
         \n\
         Missing:\n{}\n\
         \n\
         Checked {} cargo command(s) from ci.yml against scripts/preflight.sh.\n\
         \n\
         Add them to preflight.sh, or — if the command genuinely cannot run off-CI —\n\
         add its job to PLATFORM_ONLY in this gate, which is a decision on the record\n\
         rather than a hole nobody knows about.\n",
        missing.join("\n"),
        want.len(),
    );
}

/// Nothing in this workspace signs through persist's SYNC `local_sign` /
/// `local_pqc_sign` verbs.
///
/// The node's classical federation key lives in the sealed keystore
/// (CIRISServer#380 — one hardware-custodied identity). That makes its signer
/// **async**, and persist's sync `local_sign` refuses with a `sign_ed25519`
/// error. Every call site that still used it died silently: `capture_event`
/// sealed nothing (`sealed_and_persisted=0`), audit entries stopped being
/// written, and the adapter went on loading and reporting healthy — it simply
/// could not sign.
///
/// That failure was already fixed once. `ffi/pyo3.rs`'s assemble path moved to
/// `local_sign_hybrid` for CIRISServer#283, and its comment said it had removed
/// "the last surviving copy of the binding rule in this repo". **It had not.**
/// Two more copies existed — the `capture_event` seal and the audit chain — and
/// nobody re-grepped after fixing the one they were looking at. The claim was
/// load-bearing and unverified, which is the only kind of claim this gate exists
/// to replace.
///
/// `local_sign_hybrid` is the one verb: it dispatches the classical half through
/// the sealed HardwareSigner and composes `bound = message ‖ classical_sig`
/// itself, so the binding rule has exactly ONE implementation and it is
/// upstream's. Ed25519-only wire formats (the audit chain) take
/// `["classical_sig"]` — identical bytes, no migration.
#[test]
fn gate0_nothing_signs_through_the_sync_verb() {
    const BANNED: &[&str] = &["local_sign\"", "local_pqc_sign\""];

    let mut hits = Vec::new();
    let mut scanned = 0usize;
    for dir in ["src", "crates"] {
        let mut stack = vec![repo().join(dir)];
        while let Some(p) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&p) else {
                continue;
            };
            for e in rd.filter_map(Result::ok) {
                let path = e.path();
                if path.is_dir() {
                    if path.file_name().is_some_and(|n| n == "target") {
                        continue;
                    }
                    stack.push(path);
                } else if path.extension().is_some_and(|x| x == "rs") {
                    let Ok(src) = std::fs::read_to_string(&path) else {
                        continue;
                    };
                    scanned += 1;
                    for (i, line) in src.lines().enumerate() {
                        let t = line.trim_start();
                        // Only real call sites — doc comments describing the old
                        // contract are history, not behaviour.
                        if t.starts_with("//") {
                            continue;
                        }
                        if !line.contains("call_method") {
                            continue;
                        }
                        for b in BANNED {
                            if line.contains(b) {
                                hits.push(format!(
                                    "  {}:{}  {}",
                                    path.strip_prefix(repo()).unwrap_or(&path).display(),
                                    i + 1,
                                    t.trim()
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    assert!(
        scanned > 0,
        "\n🚫 RELEASE LADDER — scanned ZERO .rs files looking for sync-signing call \
         sites. The walker is broken, so this gate proves nothing. A zero denominator \
         is the error, not a pass.\n"
    );

    assert!(
        hits.is_empty(),
        "\n\
         🚫 RELEASE LADDER — a call site still signs through persist's SYNC verb.\n\
         \n\
         {}\n\
         \n\
         The node's classical key is in the sealed keystore (CIRISServer#380), so its\n\
         signer is ASYNC and `local_sign` refuses. This does not fail loudly: the caller\n\
         loads, reports healthy, and silently seals nothing — `sealed_and_persisted=0`\n\
         while the replication plane keeps moving envelopes, which is exactly the reading\n\
         that got mistaken for traces shipping.\n\
         \n\
         Use `engine.local_sign_hybrid(msg)`:\n\
           • hybrid seals  → take both `classical_sig` and `pqc_sig`\n\
           • Ed25519-only wire (the audit chain) → take `classical_sig` alone; identical\n\
             bytes over an identical preimage, so no chain migration\n\
         \n\
         It also composes `bound = message ‖ classical_sig` upstream, so the binding rule\n\
         stays at ONE implementation. Scanned {} .rs files.\n",
        hits.join("\n"),
        scanned,
    );
}

/// **No OAuth credential may live in committed source.**
///
/// The Google desktop client is a COMPILE-TIME input
/// (`CIRIS_DESKTOP_GOOGLE_OAUTH_CLIENT_*`), injected by CI from repo secrets.
/// It was briefly a pair of constants, and GitHub push protection refused the
/// push — rightly: scanning cannot tell a desktop client's non-confidential
/// secret from a web client's real one, and an embedded credential should be a
/// deliberate build input rather than a constant someone finds later.
///
/// Greps for the value SHAPES, not for the specific values, so a different
/// client pasted in tomorrow is caught just as well.
#[test]
fn gate0_no_oauth_credential_is_committed_to_source() {
    let mut offenders = Vec::new();
    for dir in ["src", "crates", "python"] {
        let walk = walk_files(std::path::Path::new(dir));
        for path in walk {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for (n, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                let has_secret = line.contains("GOCSPX-");
                // A full client ID, not the bare suffix: `ends_with(".apps.…")`
                // is a legitimate VALIDATION and must not trip this gate. A real
                // id carries the project number and a token before the suffix,
                // so require a quoted literal longer than the suffix itself.
                const SUFFIX: &str = ".apps.googleusercontent.com";
                let has_id = line
                    .split('"')
                    .any(|tok| tok.ends_with(SUFFIX) && tok.len() > SUFFIX.len() + 8);
                if has_secret || has_id {
                    offenders.push(format!("{}:{}", path.display(), n + 1));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "OAuth credential literal(s) in committed source at {offenders:?} — inject them at \
         build time via option_env!(\"CIRIS_*_GOOGLE_OAUTH_CLIENT_*\") instead. Committing one \
         blocks every future push (push protection flags each commit that carries it) and \
         publishes a credential as a side effect of a code change."
    );
}

/// Every wheel-producing build leg injects the OAuth credentials.
///
/// One leg missing them ships a wheel with no built-in Google while every other
/// platform has one — a per-platform difference nobody would think to look for.
#[test]
fn gate0_every_wheel_build_injects_the_oauth_client() {
    for wf in [
        ".github/workflows/build-wheels.yml",
        ".github/workflows/conformance.yml",
    ] {
        let text = std::fs::read_to_string(wf).unwrap_or_default();
        let builds = text.matches("maturin build --release").count();
        let injected = text
            .matches("CIRIS_DESKTOP_GOOGLE_OAUTH_CLIENT_SECRET: ${{ secrets.")
            .count();
        assert_eq!(
            builds, injected,
            "{wf}: {builds} maturin build step(s) but {injected} credential injection(s) — a \
             leg without them produces a wheel whose Google sign-in is silently absent"
        );
    }
}

/// Recursively list files under `dir` (test helper).
fn walk_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target" || n == ".git") {
                continue;
            }
            out.extend(walk_files(&p));
        } else if p
            .extension()
            .is_some_and(|x| x == "rs" || x == "py" || x == "kt")
        {
            out.push(p);
        }
    }
    out
}
