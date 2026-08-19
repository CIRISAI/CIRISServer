//! CIRISServer#327 §5 — the manifest-driven field-conformance harness (server half).
//!
//! The server joins the cross-repo #519 program the SAME way edge and persist do:
//! the ONE pinned `field_processor_matrix` that tags a field `owner_component ⊇
//! server` GENERATES the server's conformance obligation for it. A field tagged to
//! the server that the server neither PROCESSES (with a value-semantics check) nor
//! explicitly DEFERS (with a reason) is a completeness gap — the CIRISServer#315
//! carried-but-unprocessed dead-plane class the whole program exists to kill.
//!
//! Mirrors edge's `field_conformance` exemplar (`EDGE_FIELD_CONFORMANCE` +
//! `DEFERRED_PENDING_PLANE`, CIRISEdge#411 §5) and persist's
//! `persist_field_conformance()` (CIRISPersist#519). Every covered field is EITHER
//! a [`SERVER_FIELD_CONFORMANCE`] row whose `check` verifies the field's
//! VALUE/behaviour (never mere presence — an "assigned-but-wrong" processor that
//! writes the wrong constant must FAIL its own check; the live exemplar is the
//! `config:*` cohort_scope, whose CORRECT value is `self`, encoded in
//! [`check_config_cohort_scope_self`]), OR a [`DEFERRED_PENDING_PLANE`] row whose
//! reason names the upstream plane / owning wheel that must land first.
//!
//! ## Why this lives in the crate (not only in `tests/`)
//!
//! Edge and persist ship their harness IN the crate so the shared CIRISConformance
//! harness (CIRISConformance#83) can drive their `run_*_field_conformance()` entry
//! against the real wheel. This module is the server's twin: [`server_field_conformance`]
//! is that pub entry, and [`server_evidence_rows`] generates the evidence registry
//! from the SAME table it checks. The completeness gate, the evidence-drift gate,
//! and the partition gate that hold this table honest against persist's LIVE
//! `field_processor_matrix()` are the `#[test]`s in `tests/field_conformance.rs`
//! (kept there so a persist pin bump that changes the server surface reds the build
//! from the gate file, not silently here).
//!
//! The evidence registry `evidence/CIRISServer.cc_impl.tsv` (what the Constitution's
//! `check_evidence.py` vendors) is GENERATED from [`SERVER_FIELD_CONFORMANCE`] via
//! [`server_evidence_rows`] and pinned in sync by the gate file's
//! `evidence_tsv_matches_emitted`: a processor rename, a version bump, or a
//! hand-edit that diverges from the tested table is a build failure.

use ciris_persist::federation::types::KeyRecord;

/// One server-owned field's conformance obligation — a value/behaviour property
/// and a pure check that proves the server's processor honors it. Mirrors edge's
/// `FieldConformance` (a `fn() -> Result<(), String>`, so the whole table runs
/// without async / a live directory — every check asserts a pure value-semantics
/// invariant, never presence).
pub struct FieldConformance {
    /// The manifest field string (EXACT — matched against `field_processor_matrix`).
    pub field: &'static str,
    /// The value/behaviour property this check proves (human-readable).
    pub property: &'static str,
    /// The check — `Ok(())` conformant, `Err(reason)` a violation.
    pub check: fn() -> Result<(), String>,
    /// The Constitution CC section this server processor serves (the `CC-<section>`
    /// the `evidence/CIRISServer.cc_impl.tsv` row keys on).
    pub cc: &'static str,
    /// The `CLM-nsproc-*` claim name this row resolves.
    pub clm: &'static str,
    /// The `path#symbol` evidence anchor — the LIVE server processor the check
    /// exercises, so the evidence registry is generated from tested code and can
    /// never drift from it.
    pub evidence: &'static str,
}

/// Every server-tagged field the server PROCESSES, with a check that verifies the
/// value semantics (not presence). Kept to the fields whose live processor is a
/// pure, publicly-reachable server symbol — the rest are in
/// [`DEFERRED_PENDING_PLANE`] with a reason.
pub const SERVER_FIELD_CONFORMANCE: &[FieldConformance] = &[
    FieldConformance {
        field: "dimension",
        property: "the per-record composition polarity is a TOTAL, deterministic function of the \
                   dimension VALUE (an unknown dimension resolves to the CC 3.1 modal Signed, never panics)",
        check: check_dimension_polarity_total,
        cc: "3.1",
        clm: "CLM-nsproc-dimension",
        evidence: "src/compose_policy.rs#polarity_for",
    },
    FieldConformance {
        field: "aggregation_policy",
        property: "the fail-secure aggregation polarity is SELECTED by the dimension class VALUE \
                   (prohibited:→NegativeOnly/min, detection:→Detector/median, need:→PositiveOnly/max, \
                   attestation:/slashing:→BooleanViaScore/min) — a wrong arm is caught here",
        check: check_aggregation_policy_fail_secure,
        cc: "4.4.2",
        clm: "CLM-nsproc-aggregation-policy",
        evidence: "src/compose_policy.rs#polarity_for",
    },
    FieldConformance {
        field: "cohort_scope",
        property: "the config family's EMITTED cohort_scope (the one const both producers stamp) is \
                   exactly self — the ONE scope that suppresses holds_bytes (structural invisibility, \
                   CC 4.4.3.4.3); federation (the pre-#324 assigned-but-wrong value) does NOT \
                   suppress, so a repoint reds this check",
        check: check_config_cohort_scope_self,
        cc: "4.4.3.4.3",
        clm: "CLM-nsproc-cohort-scope",
        evidence: "src/graph_config.rs#set_config",
    },
    FieldConformance {
        field: "attestation_evidence",
        property: "a hardware-class claim is admitted ONLY against a verifying attestation: absent/null \
                   evidence ⇒ SoftwareUnattested (honest), present-but-unverifiable ⇒ REFUSED, never a \
                   weaker class silently (fail-secure, CC 4.2.2.1)",
        check: check_attestation_evidence_fail_secure,
        cc: "4.2.2.1",
        clm: "CLM-nsproc-attestation-evidence",
        evidence: "src/hardware_attestation.rs#admit_hardware_class_against_root",
    },
];

/// Every server-tagged field the server does NOT process with a pure runtime
/// value-check — each with the concrete reason (never a silent skip). Deferring is
/// NOT skipping: the field is still ACCOUNTED FOR (the gate file's completeness test
/// asserts it), and the reason names exactly what must land / who owns it. Mirrors
/// edge's `DEFERRED_PENDING_PLANE`. Reasons are the manifest's own
/// `field_processor_matrix` `processor` text (the source-of-truth explanation the
/// #519 walk recorded), prefixed by category.
pub const DEFERRED_PENDING_PLANE: &[(&str, &str)] = &[
    // ── proposed: the named server plane has not landed — no value to check yet.
    (
        "achieved_tier",
        "proposed:src/compliance.rs#ComplianceMap (extend to verify chain presence for committed L3/L4 and emit hard_case:sla_breach_unattested)",
    ),
    (
        "conformity_variant",
        "proposed: scoring/result.rs add CoherenceStanding-shaped Numeric/Indeterminate/Unavailable enum mirroring ManifoldConformity fail-secure discipline (LC-AV-18/LC-AV-11)",
    ),
    (
        "corroborating_refs",
        "proposed: client render surface only (non-load-bearing evidence list)",
    ),
    (
        "decision_id",
        "proposed:src/compose_policy.rs#Composer::compose (group by decision_id before the 4.4.2 mean)",
    ),
    (
        "decision_ref",
        "proposed:src/compose_policy.rs#Composer::compose - add decision_ref/evidence_refs sub-key to the (dimension, attested_key_id) grouping so repeated self-emitted veto verdicts about distinct decisions do not fold into one mean",
    ),
    (
        "epistemic_mode",
        "proposed: convention named in CC part_2 line 37; no code sets these for F-3 emissions",
    ),
    (
        "revocation",
        "proposed:src/compose_policy.rs#polarity_for (falls to Signed/mean today instead of the -1-only/NegativeOnly aggregation)",
    ),
    (
        "slashing",
        "proposed: slashing input validator rejecting detection:* rows as sole evidence; WA-quorum co-signal per T4",
    ),
    (
        "AdmittedHardwareClass",
        "proposed: emit scores Contribution when admit_hardware_class_against_root returns Attested(_) - today consumed only by the binary key-registration gate, never projected; verify-core ships to_attestation_entries() for TPM/Android/iOS but not ExternalSecureElement",
    ),
    (
        "FederationAnnouncement",
        "proposed: not located in CIRISServer; CC 4.2.4 places role-recognition in ciris-registry-core (not covered by this walk)",
    ),
    (
        "Signal_eff",
        "proposed: no sigma/sustainability-integral implementation exists anywhere",
    ),
    (
        "action_taken",
        "proposed: server enum validator (zero existing references)",
    ),
    (
        "axis_conditions",
        "proposed:src/compose_policy.rs#witness_diversity_bar_check",
    ),
    (
        "bond_posted",
        "proposed: ciris-server (FSD-005 sec.7; zero references in Server or Persist)",
    ),
    (
        "capability_declaration",
        "proposed: no processor gates declared-capability content; canonical_capabilities_json only sorts+hashes for signature, never checks against prohibited:*/capability allowlists before an import is promoted to an active grant",
    ),
    (
        "capacity-composite scoring input ('Scored by composite' clau",
        "proposed: lens-core score.rs has no Goal data dependency - build a composer or revise the CC clause",
    ),
    (
        "cohort attestation payload (agent_template_id + expected_occ",
        "proposed:src/compose_policy.rs#cohort_weighted_aggregate_attestation (no signed-envelope builder exists; nearest real code is the pure-compute src/aggregate.rs#cohort_weighted_aggregate/#CohortAggregate::meets_coverage_threshold, never called from a signing/admission path)",
    ),
    (
        "commitment_fulfillment",
        "proposed: read_track_record filters ONLY moderation:*/track_record:* prefixes - commitment_fulfillment never read despite CC 3.1.9.2 naming it an input (interim shim per its own doc)",
    ),
    (
        "correlation_score",
        "proposed: cross-attester verdict composer implementing MEDIAN (not mean) per CC 4.4.2",
    ),
    (
        "cross-attester fail-secure MIN composition",
        "proposed: no min() composer found in Persist/Verify/Server; AttestBundle uses first-wins - unbuilt",
    ),
    (
        "cross-model AI-consensus witness_diversity gate",
        "proposed:src/compose_policy.rs (no consensus/diversity function exists for judge merging)",
    ),
    (
        "dimension_polarity",
        "proposed: src/compose_policy.rs#polarity_for - missing arm; falls through to Signed",
    ),
    (
        "domain (normalized dimension segment)",
        "proposed: server vote-weight composer slug-normalizes {domain} identically across expertise and credits before CC 3.1.9.3 multiplication (zero expertise handling in src/)",
    ),
    (
        "encyclopedic",
        "proposed: ciris-server (compose_policy only distinguishes truth_grounding:detection:* from plain truth_grounding:{subject}; no discriminator between an encyclopedic-claim subject and a Tier-3 governance-object subject)",
    ),
    (
        "epistemic_humility_prompt",
        "proposed:CIRISServer src/compose.rs#strip_epistemic_humility_prompt_without_debug_tier",
    ),
    (
        "equity_basis",
        "proposed: server score_dial policy wiring equity_basis + disparity_metric to gauge bands",
    ),
    (
        "execution-provenance binding (agent_integrity/build_manifest",
        "proposed:src/compose_policy.rs (no gate exists; module rule table has no judge_model row)",
    ),
    (
        "forecast_value",
        "proposed:CIRISServer src/safety/beneficence_forecast.rs#check_forecast_calibration_package",
    ),
    (
        "high_stakes_trigger_kind",
        "proposed:src/compose_policy.rs (or federation-admission)#witness_diversity_required_for(contribution_kind) over {MODERATION_EVENT, WA_CANDIDACY, PROPOSAL-above-magnitude, EXPERTISE_ATTESTATION-standing-jump}",
    ),
    (
        "idma_algorithm_id",
        "proposed:src/compose.rs#dma_verdict_compose (extra-map only today, invisible to admission)",
    ),
    (
        "judge_model",
        "proposed:src/compose_policy.rs#polarity_for (no branch today - falls through to Signed/mean, contradicting the declared polarity)",
    ),
    (
        "kind vocabulary canonical registration (incl. non-constituti",
        "proposed: HARD_CASE_KIND_REGISTRY.md analog absent; server constants declared but unregistered/unwired",
    ),
    (
        "lag_seconds",
        "proposed: server ok/warn/breach badge computation (zero references to replication_lag/replica_id in codebase)",
    ),
    (
        "language (BCP-47 normalized segment)",
        "proposed: same composer - canonical-subtag normalization before pairing",
    ),
    (
        "moderation",
        "proposed: slashing composer refuses expertise_fraud-based fire absent a referenced WA-quorum verdict",
    ),
    (
        "n_required",
        "proposed:src/compose_policy.rs#witness_diversity_locality_scaled_n (reads locality:decision:{scale})",
    ),
    (
        "never-silent emission wiring at CC 4.5.4 existence-gate tran",
        "proposed: safety/named.rs#existence_verdict must call record_hard_case (currently response-payload-only)",
    ),
    (
        "overridden / override_reason (conscience veto -> PONDER; rep",
        "proposed:thought_processor/conscience_execution.py (computed in-process, not wired to attestation)",
    ),
    (
        "partner/license tier ceiling on software_fallback (UNLICENSE",
        "proposed: CIRISServer consumer-policy wiring of partner_role vs software_fallback; today enforced only client-locally in the keyring crate",
    ),
    (
        "partner_role",
        "proposed:src/compose_policy.rs#DIM_PARTNER_ROLE (no constant exists; mirror the DIM_LICENSURE pattern)",
    ),
    (
        "per-invocation_kind differentiated threshold",
        "proposed: src/accord.rs#kill_switch_quorum_m + src/accord_reactivate.rs apply ONE uniform quorum; CC 4.2.6 differentiated thresholds unimplemented (FSD-005 sec.9)",
    ),
    (
        "period",
        "proposed: no canonical {period} format pinned (constitution-silent); format mismatch fragments the fold",
    ),
    (
        "polarity",
        "proposed: src/compose_policy.rs#polarity_for has no `capacity_assurance:` arm (falls through to default Polarity::Signed instead of Polarity::Enumerated, unlike the sibling `age_assurance:` arm already present at line ~150); CIRISServer additionally has no src/safety/capacity.rs module analogous to the existing src/safety/age.rs (zero emit/read/gate call sites for capacity_assurance anywhere in src/)",
    ),
    (
        "prior_chain_depth",
        "proposed: server chain-walk resolving the supersedes chain back to the genesis canonical_seed anchor (display-only)",
    ),
    (
        "ratchet",
        "proposed:CIRISServer compose_policy.rs#Composer::screen (extend the testimonial-only guard at ~L770 to DIM_RATCHET_FLAG generically per CC 3.1.6)",
    ),
    (
        "realized_value",
        "proposed:CIRISServer beneficence_forecast.rs#reconcile_forecast_vs_realized_25pct",
    ),
    (
        "recipient_capability",
        "proposed: cross-check that trace strips for entitled recipients trigger hard_case:sla_breach_unattested",
    ),
    (
        "responder/match tally",
        "proposed: read-model aggregation over attestations referencing this claim's id per {kind} (makes seed's match_count non-fictional)",
    ),
    (
        "sender-consistency gate (declared_by==envelope sender; retir",
        "proposed: documented as lens-core Handler responsibility in edge doc comments; NOT found implemented in vendored crates/ciris-lens-core",
    ),
    (
        "severity (advisory|blocking)",
        "proposed:src/compose_policy.rs#revocation_severity_gate - ZERO existing consumption of revocation:* in this repo (grep confirms); field is pure decoration today",
    ),
    (
        "sibling",
        "proposed:src/compose.rs fold-join between dma:* and conscience:* (no join primitive exists)",
    ),
    (
        "single-source confidence cap (DRAFT RT-H7)",
        "proposed: mirror licensure_cap (<=0.5 until second diversity-qualified attester) IF adopted - DRAFT",
    ),
    (
        "slashing_evidence_set",
        "proposed:src/safety/slashing_composer.rs#exclude_ratchet_flag_as_sole_evidence",
    ),
    (
        "sole-evidence-for-slashing screen on detection:*/ratchet:fla",
        "proposed:src/compose_policy.rs#Composer::screen - add DetectorSoleEvidenceForSlashing arm mirroring TestimonialSoleEvidenceForSlashing",
    ),
    (
        "source (trusted-pubkey-per-source-type selection)",
        "proposed: SourceType classifies registry:/direct:/local: but delegates pubkey selection to the caller; no CIRISServer call site implements the per-source-type key-selection policy",
    ),
    (
        "stake (generic envelope field, currently untyped in extra)",
        "proposed:src/compose.rs#resolve_stake_backing (zero code hits for stake/bond_posted)",
    ),
    (
        "sub-quorum fallback selection + REQUIRED hard_case co-emissi",
        "proposed: sub-quorum fallback router - none exists; cc_impl.tsv:61 MISATTRIBUTES CC 4.4.3.1.1 to accord.rs#replicate_and_maybe_halt (the unrelated kill-switch quorum)",
    ),
    (
        "trust_root_valid",
        "proposed:src/auth/gate.rs#authorize_delegated (FSD Status: PROPOSED, not yet wired - CIRISServer#304)",
    ),
    (
        "verdict (sound|flagged|unsound|inconclusive)",
        "proposed:src/compose.rs aggregation entry under the signed mean default",
    ),
    (
        "window_start",
        "proposed: community_config#merit_window_policy (one uniform window per community for comparability)",
    ),
    (
        "{role} open-vocab documented-convention registry",
        "proposed: PARTNER_ROLE_KIND_REGISTRY.md analog absent (CC 4.5.1.1 requires one beyond the six tiers)",
    ),
    // ── server-implemented but reachable only via a private/async path, not the pure harness.
    (
        "identity_type",
        "server-implemented but unreachable from the pure cross-repo harness (src/accord.rs#register_holder) — a private Composer method or async Engine path, exercised by its own in-crate integration test rather than a sync pure check.",
    ),
    (
        "scope",
        "server-implemented but unreachable from the pure cross-repo harness (generic EnvelopeCore.scope; no family override; seed affiliations/Cohort unreviewed against the detection-surface purpose) — a private Composer method or async Engine path, exercised by its own in-crate integration test rather than a sync pure check.",
    ),
    (
        "valid_until",
        "server-implemented but unreachable from the pure cross-repo harness (src/compose_policy.rs#Composer (staleness check)) — a private Composer method or async Engine path, exercised by its own in-crate integration test rather than a sync pure check.",
    ),
    (
        "config_scope",
        "server-implemented but unreachable from the pure cross-repo harness (src/config_api.rs#require_owner treats BOTH scopes identically today (same SYSTEM_ADMIN+FullAccess gate for every write and read) - the module's own doc admits this is a 'Phase-2 enforcement TODO'; ALSO this field's wire key name 'scope' collides with CIRISPersist's reserved typed EnvelopeCore.scope path (an untagged ScopeSet that happily parses a bare lowercase string like 'local'/'identity'). Currently inert but fragile - proposed: rename the config-side wire key to `config_scope` and add a distinct, stronger enforcement gate for Identity-scope writes) — a private/async server path, exercised by its own in-crate integration test rather than a sync pure check.",
    ),
    (
        "consent",
        "server-implemented but unreachable from the pure cross-repo harness (src/peer.rs#register_peer_key + emit_replication_consent (existing; no gap)) — an async Engine emit path, exercised by tests/peer_replication.rs rather than a sync pure check.",
    ),
    (
        "meets_bar",
        "the BooleanViaScore/NegativeOnly fold (extremum-Min, NOT the CC 4.4.2 mean) lives in the \
         PRIVATE module fn src/compose_policy.rs#aggregate — not reachable from a tests/ integration \
         test; exercised today by the in-crate compose_policy unit tests. This is the first \
         promotion candidate: the moment `aggregate` (or a thin pub wrapper over the extremum fold) \
         is exposed, meets_bar lifts into SERVER_FIELD_CONFORMANCE as a real value-check.",
    ),
    (
        "updated_by",
        "server-implemented but unreachable from the pure cross-repo harness (src/config_api.rs (set_config/update_config/delete_config handlers) copies caller.wa_id verbatim into the signed envelope - protected against post-hoc third-party tampering but NOT cryptographically bound to the human's own personal signature; a compromised node process could misattribute any string here) — an async Engine path, exercised by its own in-crate integration test rather than a sync pure check.",
    ),
    // ── shared fields whose VALUE semantics are persist-owned.
    (
        "subject_key_ids",
        "persist-owned value semantics (src/federation/types.rs#Attestation.subject_key_ids (typed; no admission requirement since 4.5.2.1 pattern-match misses) - proposed producer convention for third-party roll-ups) — the server co-owns the field on the wire but runs no value processor; the check lives in the persist wheel.",
    ),
    (
        "score",
        "persist-owned value semantics (src/federation/scores.rs#score_of / value_of (BooleanMin arm) - ciris-persist@v21.4.0) — the server co-owns the field on the wire but runs no value processor; the check lives in the persist wheel.",
    ),
    (
        "attested_key_id",
        "persist-owned value semantics (CIRISPersist/src/federation/types.rs#Attestation.attested_key_id (FK-checked)) — the server co-owns the field on the wire but runs no value processor; the check lives in the persist wheel.",
    ),
    (
        "attesting_key_id",
        "persist-owned value semantics (src/federation/admission.rs#check_reserved_prefix_admission) — the server co-owns the field on the wire but runs no value processor; the check lives in the persist wheel.",
    ),
    (
        "witness_relation",
        "persist-owned value semantics (src/federation/admission.rs#check_capacity_not_self_attested (confirms scope-away)) — the server co-owns the field on the wire but runs no value processor; the check lives in the persist wheel.",
    ),
    (
        "references_attestation_id",
        "persist-owned value semantics (ciris-persist/src/federation/envelope.rs#EnvelopeCore (typed; witness-test bound)) — the server co-owns the field on the wire but runs no value processor; the check lives in the persist wheel.",
    ),
    (
        "confidence",
        "persist-owned value semantics (src/federation/scores.rs#confidence_of) — the server co-owns the field on the wire but runs no value processor; the check lives in the persist wheel.",
    ),
    (
        "attestation_prefixes",
        "persist-owned value semantics (src/federation/consent_grammar.rs#parse_grant_payload + src/engine.rs#promote_consented_backlog) — the server co-owns the field on the wire but runs no value processor; the check lives in the persist wheel.",
    ),
    (
        "witness_diversity",
        "persist-owned value semantics (proposed:CIRISPersist/src/federation/scores.rs#compose_verdict (witness_diversity hardcoded None ~L291; SignedMean branch ~L230-239 has no diversity hook)) — the server co-owns the field on the wire but runs no value processor; the check lives in the persist wheel.",
    ),
    (
        "agent_key_id",
        "persist-owned value semantics (CIRISPersist/src/store/sqlite.rs#list_trace_summaries (MIN(signing_key_id) AS agent_key_id, derived via trace_summary_contract's manifest-driven SELECT fragment; postgres.rs#list_trace_summaries is the twin)) — the server co-owns the field on the wire but runs no value processor; the check lives in the persist wheel.",
    ),
    // ── shared fields whose VALUE semantics are verify-owned.
    (
        "evidence_refs",
        "verify-owned (src/ciris-verify-core/src/holds_bytes.rs#verify_holds_bytes) — the server consumes the verified result and runs no value processor for this field.",
    ),
    (
        "resumes_halt_id",
        "verify-owned (ciris-verify-core/src/humanity_accord.rs#verify_invocation) — the server consumes the verified result and runs no value processor for this field.",
    ),
    // ── shared fields whose VALUE semantics are edge-owned.
    (
        "withdrawal_reason",
        "edge-owned (CIRISEdge src/edge.rs#emit_withdraws (WithdrawalReason::ContentMiss)) — the withdraws/relay processor lives in the edge wheel, not the server crate.",
    ),
    // ── server-tagged but the processor lives in another repo (Registry / NodeCore).
    (
        "PROFESSIONAL_",
        "cross-repo processor (CIRISRegistry http.rs#partner_composition (joins on organization_id) + CIRISServer compose_policy.rs#licensure_cap - implemented but only via the dedicated Registry endpoint, not the shared Composer pipeline) — the load-bearing gate is the Registry endpoint; the server-crate half (licensure_cap) is a private Composer method, not reachable from the pure harness.",
    ),
    (
        "cross-attester composition-policy pin (CC 4.4.2 mean vs Node",
        "cross-repo processor (proposed:src/compose_policy.rs weighted_aggregate composition entry (absent - falls through to generic Signed/Mean, conflicting with NodeCore compose.rs:390-394 latest-wins; neither documented as the pinned override)) — unbuilt; no server-crate value to check.",
    ),
    (
        "kind vocabulary discoverability record",
        "cross-repo processor (proposed: NodeCore-owned registry doc parallel to WITNESS_KIND_REGISTRY.md (which does not exist in this checkout for need:{kind})) — NodeCore-owned; no server-crate value to check.",
    ),
    (
        "max_supportable_scale",
        "cross-repo processor (CIRISNodeCore locality.rs#max_supportable_scale/#CellLocalityHealth (implemented, unit-tested, unwired - proposed RATCHET/Lens wiring)) — the processor is in the CIRISNodeCore crate; no server-crate value to check here.",
    ),
    (
        "merit_score",
        "cross-repo processor (proposed:node merit auto_promote_selector (deterministic highest-track-record comparator; persist disclaims computing it; ZERO references to this dimension in Persist or NodeCore source)) — unbuilt in every wheel; no server-crate value to check.",
    ),
    (
        "quorum_size",
        "cross-repo processor (proposed: quorum composer citing NodeCore locality.rs#default_quorum_size/#default_min_pool/#validate_cell_pool - zero call sites in CIRISServer (folds in at Server 1.0, compose.rs:3022 todo)) — the processor is in the CIRISNodeCore crate; no server-crate value to check here.",
    ),
    (
        "sla_breach_unattested",
        "cross-repo processor (proposed:CIRISNodeCore compose/explainability_sla.rs#emit_hard_case_on_tier_shortfall) — the processor is in the CIRISNodeCore crate; no server-crate value to check here.",
    ),
    (
        "write-authority gate (Registry-admin canonical vs community-",
        "cross-repo processor (CIRISRegistry services/admin.rs#register_partner (canonical ladder); proposed: no equivalent gate for community-admission civic extensions) — the canonical gate is in the CIRISRegistry crate; no server-crate value to check here.",
    ),
];

/// CIRISServer#327 §5 — emit the server's namespace-processor evidence rows in the
/// `CIRISServer.cc_impl.tsv` format the Constitution's `check_evidence.py` vendors
/// (`<cc>\t<clm>\tCIRISServer\t<path#symbol>\tciris-server@v<version>`). Generated
/// from [`SERVER_FIELD_CONFORMANCE`] — the SAME table the completeness witness
/// checks — so every published evidence row anchors a LIVE, tested processor and
/// can never drift from the code. The vendored `evidence/CIRISServer.cc_impl.tsv`
/// is regenerated from this and pinned in sync by the gate file's
/// `evidence_tsv_matches_emitted`.
/// One CC claim the server substantiates with a live symbol, where the claim is
/// NOT a manifest-field processor.
///
/// # Why this exists beside [`SERVER_FIELD_CONFORMANCE`]
///
/// That table is keyed by manifest FIELD — every row's `field` is matched
/// against `field_processor_matrix`, which is what makes the `CLM-nsproc-*`
/// family verifiable. Most of the Constitution's claims about this repo are not
/// field-processing claims: rough-only location enforcement, capacity
/// self-emission rejection, directed replication consent. They have live,
/// tested symbols and no manifest field to hang them on.
///
/// Without this table those claims sit in `claims.tsv` as
/// `impl:CIRISServer#155` — a pointer to the CLOSED issue whose own title is
/// *"Evidence registry: expose a CC-section → implementation-symbol map for the
/// impl: tier"*. That is circular: the claim cites the issue that asked for the
/// evidence as though it were the evidence. Nine claims are `established` on
/// that basis today.
///
/// A pointer at an issue is not the same kind of object as a pointer at a
/// symbol, and only one of them can go stale silently.
pub struct ClaimEvidence {
    /// The CC section (`cc_section` column).
    pub cc: &'static str,
    /// The `CLM-*` claim id this row resolves — MUST exist in the
    /// Constitution's `claims.tsv`. Inventing one to make a control resolvable
    /// is the precise overclaim this registry guards against; a shipped control
    /// with no claim belongs in the awaiting-a-claim-id comments instead.
    pub clm: &'static str,
    /// `path#symbol` — the live symbol, in THIS repo or a crate it owns.
    pub evidence: &'static str,
    /// What the symbol actually enforces. Not emitted; it is here so a reviewer
    /// can judge whether the pointer substantiates the claim rather than merely
    /// sitting near it.
    pub substantiates: &'static str,
}

/// Claim-keyed evidence: live symbols for CC claims that are not field
/// processors. Every `clm` here is verified to exist in `claims.tsv`.
pub const SERVER_CLAIM_EVIDENCE: &[ClaimEvidence] = &[
    ClaimEvidence {
        cc: "2.6.6.1",
        clm: "CLM-location",
        evidence: "src/location.rs#mint_location_proof",
        substantiates: "every minted cell passes persist's validate_location_cell BEFORE it is \
                        signed, so §0.8.1 rough-only (cell_resolution <= 7) is enforced at \
                        production time rather than promised by UI copy; the bound is read from \
                        MAX_LOCATION_PROOF_RESOLUTION, never restated",
    },
    ClaimEvidence {
        cc: "2.6.6",
        clm: "CLM-canonicalization-cell",
        evidence: "src/location.rs#mint_location_proof",
        substantiates: "cells are emitted lowercase-hex canonical, and validate_location_cell's \
                        resolution-redundancy check means a producer cannot assert a coarse \
                        resolution while shipping a fine cell",
    },
    ClaimEvidence {
        cc: "3.4.5",
        clm: "CLM-capacity-score",
        evidence: "src/scorer.rs#score_and_emit",
        substantiates: "CapacityAttestation::new (ciris-lens-core) refuses attesting_key_id == \
                        attested_key_id, so a self-emitted capacity score cannot be constructed, \
                        let alone reach put_attestation",
    },
    ClaimEvidence {
        cc: "3.3.7",
        clm: "CLM-consent-directed",
        evidence: "src/peer.rs#emit_replication_consent",
        substantiates: "authors the directed consent:replication:v1 grant and self-validates its \
                        own payload through persist's parse_grant_payload before signing, so a \
                        grant this node cannot itself parse is never emitted",
    },
];

/// A control the Constitution attributes to this repo that this repo does NOT
/// enforce.
///
/// Declared in code, and therefore generated into the vendored TSV and gated by
/// `evidence_tsv_matches_emitted`, for the same reason the resolved rows are:
/// a hand-maintained gap list decays into a stale one, and a stale gap list is
/// worse than none — it reads as a considered position while describing a
/// codebase that has moved.
///
/// Emitted with `open` in the version column, which `check_claims.py` reads as
/// unresolved. Stating the gap is the point: silence would be read as coverage.
pub struct DeclaredGap {
    /// CC section.
    pub cc: &'static str,
    /// The `CLM-*` claim that is NOT substantiated here.
    pub clm: &'static str,
    /// The tracked issue, in `Repo#N` form — this is a pointer at WORK, which is
    /// what an issue legitimately is. The failure mode being corrected is the
    /// reverse: an issue pointer standing in for a symbol in a RESOLVED row.
    pub tracked_at: &'static str,
    /// Why it is not enforced, so a reader need not open the issue to judge it.
    pub reason: &'static str,
}

/// Gaps declared against claims currently marked `established` in `claims.tsv`
/// on the strength of `impl:CIRISServer#155`.
///
/// #155 is CLOSED and its title is *"Evidence registry: expose a CC-section →
/// implementation-symbol map for the `impl:` tier"* — the issue that asked for
/// symbol-level evidence, cited as though it were that evidence. Each row below
/// is a claim whose server-side symbol does not exist.
pub const SERVER_DECLARED_GAPS: &[DeclaredGap] = &[
    DeclaredGap {
        cc: "6.1.2",
        clm: "CLM-noise-classify",
        tracked_at: "CIRISServer#239",
        reason: "no noise-floor classifier ships in src/ or ciris-lens-core — the only \
                 noise_floor code in this repo is tests/noise_floor.rs, which is test-tier and \
                 cannot substantiate an impl-tier claim",
    },
    DeclaredGap {
        cc: "6.1.2.3",
        clm: "CLM-noise-ejection",
        tracked_at: "CIRISServer#239",
        reason: "EjectionVerdict routing exists only in tests/noise_floor_verdicts.rs; no \
                 production symbol routes Keep/EjectToTier/AggregatedTierOnly/HardDelete",
    },
    DeclaredGap {
        cc: "6.1.2",
        clm: "CLM-noise-descent",
        tracked_at: "CIRISServer#239",
        reason: "the retirement operator (revocation/eviction/aging as pressure-driven descent) \
                 has no production implementation here",
    },
    DeclaredGap {
        cc: "4.2.6",
        clm: "CLM-accord-livequorum",
        tracked_at: "CIRISServer#122",
        reason: "the FSD-004 live-quorum runtime is not adopted — CIRISServer#122 is open and \
                 says so; no live_quorum symbol exists in src/",
    },
];

pub fn server_evidence_rows() -> Vec<String> {
    // THE HEADER ROW IS DATA, NOT DECORATION (CIRISServer#352).
    //
    // The Constitution's `check_claims.py` strips `#` lines and hands the rest
    // to `csv.DictReader`, which takes the first remaining line as the header.
    // With the column names living only inside a comment, DictReader consumed
    // the first real ROW as the header — `fieldnames` came back as
    // `['3.1', 'CLM-nsproc-dimension', 'CIRISServer', …]` — and every later row
    // lacked a `decimal_id` and was silently skipped. Vendoring the file added a
    // manifest that resolved nothing and reported nothing.
    //
    // That is the same failure this release fixes in the sign-in path: silence
    // reading as coverage. The names match CIRISPersist's manifest EXACTLY
    // (`decimal_id`, not our comment's older `cc_section`) because the consumer
    // keys on them and two spellings is how the two files drift.
    std::iter::once("decimal_id\tclaim_id\trepo\tpath#symbol\tcrate@version".to_string())
        .chain(
            SERVER_FIELD_CONFORMANCE
                .iter()
                .map(|c| {
                    format!(
                        "{}\t{}\tCIRISServer\t{}\tciris-server@v{}",
                        c.cc,
                        c.clm,
                        c.evidence,
                        env!("CARGO_PKG_VERSION"),
                    )
                })
                .chain(SERVER_CLAIM_EVIDENCE.iter().map(|c| {
                    format!(
                        "{}\t{}\tCIRISServer\t{}\tciris-server@v{}",
                        c.cc,
                        c.clm,
                        c.evidence,
                        env!("CARGO_PKG_VERSION"),
                    )
                }))
                .chain(
                    SERVER_DECLARED_GAPS.iter().map(|g| {
                        format!("{}\t{}\tCIRISServer\t{}\topen", g.cc, g.clm, g.tracked_at,)
                    }),
                ),
        )
        .collect()
}

/// Run the harness: `Ok(())` iff every [`SERVER_FIELD_CONFORMANCE`] check passes,
/// else the collected `"{field}: {reason}"` violations. This is the entry the shared
/// CIRISConformance harness (CIRISConformance#83) drives against the `ciris-server`
/// wheel, the twin of edge's `run_edge_field_conformance()` and persist's
/// `run_persist_field_conformance()`.
pub fn server_field_conformance() -> Result<(), Vec<String>> {
    let mut violations = Vec::new();
    for c in SERVER_FIELD_CONFORMANCE {
        if let Err(reason) = (c.check)() {
            violations.push(format!("{}: {reason}", c.field));
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

// ─── the pure value-semantics checks ────────────────────────────────────────

/// `dimension` (CC 3.1): the server routes each attestation's composition by its
/// dimension VALUE. `polarity_for` is a TOTAL, DETERMINISTIC function of the
/// dimension string — the same dimension resolves to the same polarity (a
/// non-deterministic or panicking resolution would be a composition hole), and an
/// unknown dimension resolves to the CC 3.1 modal `Signed`, never a panic.
pub fn check_dimension_polarity_total() -> Result<(), String> {
    use crate::compose_policy::{polarity_for, Polarity};
    let d = "trust:example:v1";
    let a = polarity_for(d);
    let b = polarity_for(d);
    if a != b {
        return Err(format!(
            "polarity_for({d:?}) is non-deterministic ({a:?} vs {b:?})"
        ));
    }
    if polarity_for("unknown_family_zzz:v1") != Polarity::Signed {
        return Err(
            "an unknown dimension must resolve to the CC 3.1 modal Signed (mean), never panic"
                .into(),
        );
    }
    Ok(())
}

/// `aggregation_policy` (CC 4.4.2): the fail-secure aggregation polarity is
/// SELECTED by the dimension class VALUE. This is where "assigned-but-wrong" would
/// bite — a `prohibited:*` dimension that resolved to `Signed` (mean) instead of
/// `NegativeOnly` (min) would let a positive attestation dilute a hard veto. The
/// check encodes the CORRECT arm for each class.
pub fn check_aggregation_policy_fail_secure() -> Result<(), String> {
    use crate::compose_policy::{polarity_for, Polarity};
    let cases = [
        ("prohibited:weapons", Polarity::NegativeOnly),
        ("detection:correlated_action:x", Polarity::Detector),
        ("need:shelter:v1", Polarity::PositiveOnly),
        ("attestation:l3", Polarity::BooleanViaScore),
        ("slashing:expertise_fraud:v1", Polarity::BooleanViaScore),
    ];
    for (dim, want) in cases {
        let got = polarity_for(dim);
        if got != want {
            return Err(format!(
                "aggregation polarity for {dim:?} must be {want:?} (fail-secure selection), got {got:?}"
            ));
        }
    }
    Ok(())
}

/// `cohort_scope` (CC 4.4.3.4.3) — THE assigned-but-wrong exemplar, asserted on the
/// value the server ACTUALLY emits. A `config:v1` row is a self-report about THIS
/// node's own runtime, so both config producers (`graph_config::config_envelope` and
/// the load-bearing typed `set_config`, CIRISServer#324) stamp
/// [`crate::graph_config::CONFIG_COHORT_SCOPE`] — the ONE const both route through.
/// The pre-#324 value was `federation`, the ONE scope `suppresses_holds_bytes`
/// (`SELF | FAMILY`) does NOT protect, which left config directory-advertised +
/// cohort-replicable. This check reads the emitted const, not persist's API in the
/// abstract: repointing `CONFIG_COHORT_SCOPE` at `federation` reds this check because
/// `suppresses_holds_bytes(CONFIG_COHORT_SCOPE)` goes false — a genuine
/// red-until-fix on the emitted value, the property T3's #324 fix actually changed
/// (the prior form validated only persist's function and would have stayed green
/// throughout the entire `federation` defect window).
pub fn check_config_cohort_scope_self() -> Result<(), String> {
    use ciris_persist::federation::types::cohort_scope;
    let emitted = crate::graph_config::CONFIG_COHORT_SCOPE;
    // (1) The emitted value MUST suppress holds_bytes — the red-until-fix core.
    // `federation` (pre-#324) does not, so a regression there reds here.
    if !cohort_scope::suppresses_holds_bytes(emitted) {
        return Err(format!(
            "config's emitted cohort_scope ({emitted:?}) must suppress holds_bytes (structural \
             invisibility, CC 4.4.3.4.3); `federation` — the pre-#324 assigned-but-wrong value — \
             does NOT suppress and would leave every config key directory-advertised + replicable"
        ));
    }
    // (2) Pin the EXACT value: `self`, not merely "some suppressing scope". `family`
    // also suppresses but is the wrong belonging tier for a node-self config report,
    // so this catches a repoint that (1) alone would let pass.
    if emitted != cohort_scope::SELF {
        return Err(format!(
            "config cohort_scope must be exactly `self` (a config row is a self-report about THIS \
             node's own runtime, CC 4.4.3.4.3), got {emitted:?}"
        ));
    }
    // (3) Sibling invariant the fix depends on: `federation` must NOT suppress — else
    // the pre-#324 value would have been harmless and the fix meaningless. Guards
    // against a persist-side change that would silently defang this whole check.
    if cohort_scope::suppresses_holds_bytes(cohort_scope::FEDERATION) {
        return Err(
            "cohort_scope=federation must NOT suppress holds_bytes — it is the assigned-but-wrong \
             config scope the #324 fix replaced with self"
                .into(),
        );
    }
    // (4) Anchor the config family to the server's public dimension const.
    if crate::graph_config::CONFIG_DIMENSION != "config:v1" {
        return Err(format!(
            "graph_config::CONFIG_DIMENSION drifted from config:v1 (got {:?})",
            crate::graph_config::CONFIG_DIMENSION
        ));
    }
    Ok(())
}

/// `attestation_evidence` (CC 4.2.2.1): a hardware-class claim is admitted ONLY
/// against a verifying attestation. The VALUE decision keys on the evidence value:
/// absent/null ⇒ `SoftwareUnattested` (declining to claim is honest), while
/// present-but-unverifiable evidence is REFUSED with a typed error — never silently
/// downgraded to a weaker `Attested` class. That fail-secure asymmetry is the point
/// of the gate. Drives the public production entrypoint `admit_hardware_class` — a
/// pure delegation to the anchored `admit_hardware_class_against_root`, the
/// pinned-root core where the `SoftwareUnattested` gate and the Layer-A/B binding
/// actually live — so the check exercises the evidence row's symbol through its one
/// production caller.
pub fn check_attestation_evidence_fail_secure() -> Result<(), String> {
    use crate::hardware_attestation::{admit_hardware_class, AdmittedHardwareClass};
    let now = chrono::Utc::now();

    match admit_hardware_class(&key_record(None), now) {
        Ok(AdmittedHardwareClass::SoftwareUnattested) => {}
        other => {
            return Err(format!(
                "absent attestation_evidence must admit as SoftwareUnattested, got {other:?}"
            ))
        }
    }
    match admit_hardware_class(&key_record(Some(serde_json::Value::Null)), now) {
        Ok(AdmittedHardwareClass::SoftwareUnattested) => {}
        other => {
            return Err(format!(
                "explicit-null attestation_evidence must admit as SoftwareUnattested, got {other:?}"
            ))
        }
    }
    let bogus = serde_json::json!({ "platform_attestation": { "kind": "forged" } });
    if admit_hardware_class(&key_record(Some(bogus)), now).is_ok() {
        return Err(
            "present-but-unverifiable attestation_evidence must be REFUSED, never admitted as a \
             weaker class (fail-secure, CC 4.2.2.1)"
                .into(),
        );
    }
    Ok(())
}

/// A minimal [`KeyRecord`] carrying exactly the `attestation_evidence` under test.
/// The gate short-circuits on the evidence value before reading the signature
/// fields, so the empty scrub fields never load-bear here.
fn key_record(evidence: Option<serde_json::Value>) -> KeyRecord {
    let now = chrono::Utc::now();
    KeyRecord {
        key_id: "conformance-test-key".into(),
        pubkey_ed25519_base64: String::new(),
        pubkey_ml_dsa_65_base64: None,
        algorithm: String::new(),
        identity_type: String::new(),
        identity_ref: String::new(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({}),
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: String::new(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: evidence,
        consent_role: None,
        additional_scrubs: Vec::new(),
    }
}
