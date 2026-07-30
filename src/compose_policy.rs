//! The **CEG consumer-composition tier** — turning edges (attestations) into
//! verdicts (compositions). CC 4.4 / CC 4.4.1 / CC 4.4.2 / CC 4.4.3.8 /
//! CC 4.4.3.9 / CC 3.4.9.
//!
//! ## Why this module exists (CIRISServer#155 evidence rows 4.4 / 4.4.1 / 3.4.9)
//!
//! CC 4.4: *"The substrate carries edges (attestations); consumers compose
//! traversals (verdicts). CEG specifies a library of named reference policies.
//! **A CEG-Conforming Consumer MUST implement at least Policy A**; the others
//! are RECOMMENDED for richer compositions."*
//!
//! This node **declares `CCC` (CEG-Conforming Consumer) on the wire**. That
//! declaration is a normative claim, and CC 4.4 is the MUST it entails. Before
//! this module the node had NO composition engine at all — it declared CCC
//! while implementing zero of Policy A. This module is what makes the
//! declaration honest.
//!
//! ## What is implemented here
//!
//! | CC | Rule | Where |
//! |---|---|---|
//! | 4.4.3.8 | Policy A — direct trust against a pinned trust set | [`TrustSet`] + [`Composer::compose`] |
//! | 4.4.2 | Polarity-keyed aggregation defaults | [`Polarity`] + `aggregate` |
//! | 4.4.1 | Frickerian (identity-prejudice-resistant) weighting | `Composer::weigh` |
//! | 4.4.3.9 | Policy D — lexical-vulnerability-priority tie-break | `lexical_vulnerability_winner` |
//! | 3.4.9 | `licensure:*` single-source `confidence ≤ 0.5` cap | `Composer::licensure_cap` |
//! | 3.4.5 | `capacity:*` self-emission rejection (consumer re-check) | `Composer::screen` |
//! | 3.1.9.3 | `testimonial_witness:*` is never sole evidence for `slashing:*` | `Composer::screen` |
//!
//! ## Fail-closed
//!
//! Per the CC 3.4.7 CCC discipline (*"the consumer's re-check is the second
//! [line of defense]"*), an attestation this node cannot resolve against its
//! pinned trust set is **refused**, never silently admitted. A (dimension,
//! attested_key_id) tuple with zero admitted contributions composes to
//! [`Decision::Undetermined`] — NOT to a passing zero. Every refusal is
//! surfaced in [`Composition::refusals`] with a typed [`RefusalReason`].
//!
//! ## Consumer-policy knobs vs. normative rules
//!
//! CC 4.4.1 tells a consumer what it MUST NOT downweight; it does not fix the
//! downweight *function* a consumer applies to everything else, nor the
//! self-attestation track-record function CC 3.4.7 mandates ("the consumer MUST
//! also weight `witness_relation: self` claims against the attester's
//! other-emission track record" — it mandates *that* they be weighted, not
//! *how*). Those functions live in [`PolicyConfig`] with documented defaults and
//! are marked CONSUMER POLICY below. The invariants (what must never be
//! downweighted, and the ordering) are normative and are not configurable.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::Result;
use chrono::{DateTime, Utc};
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::precedence::precedence_winner;
use ciris_persist::federation::types::{attestation_type, identity_type, Attestation};
use ciris_persist::prelude::Engine;
use ciris_verify_core::infrastructure_community::InfrastructureCommunity;
use serde::Serialize;

// ─── Dimension prefixes the composition tier is normatively sensitive to ─────

/// CC 3.1.9.3 — the singular-narrative preservation prefix. CC 4.4.1 bullet 1:
/// MUST NOT be downweighted for coming from a low-attestation-density cohort.
pub const DIM_TESTIMONIAL_WITNESS: &str = "testimonial_witness:";
/// CC 3.1 ("Avoid Harm") — CC 4.4.1 bullet 2: MUST NOT be downweighted because
/// the subject has a long `partner_role:*` track record.
pub const DIM_NON_MALEFICENCE: &str = "non_maleficence:";
/// CC 3.4.9 — the co-stewarded prefix (CIRISRegistry × CIRISVerify).
pub const DIM_LICENSURE: &str = "licensure:";
/// CC 3.1.9.2 — the adjudication outcome prefix (`PROVEN_ROGUE`/`NOT_PROVEN`).
pub const DIM_SLASHING: &str = "slashing:";
/// CC 3.4.5 — the anti-Goodhart self-emission-rejected prefix.
pub const DIM_CAPACITY: &str = "capacity:";
/// CC 3.4.8 — LensCore-only primary detector emissions (median-aggregated).
pub const DIM_DETECTION: &str = "detection:";
/// CC 4.4.2 — the other two median-aggregated detector families.
pub const DIM_RATCHET_FLAG: &str = "ratchet:flag:";
/// CC 3.1.1 / CC 1.13.2 — the `-1.0`-only, non-rollbackable entity-revocation
/// prefix. The manifest (`revocation:{entity_type}:{reason}`) pins the polarity:
/// *"defeating the -1-only/non-rollbackable polarity"* — it MUST NOT be averaged
/// into a signed mean, or a spurious positive could erase a live revocation.
pub const DIM_REVOCATION: &str = "revocation:";
/// CC 3.1.10 — the CIRISBench HE-300 benchmark family. Manifest
/// (`benchmark:he300:{category}:{version}`): *"composition MUST use PositiveOnly
/// max aggregation, never Signed mean; no negative value valid."*
pub const DIM_BENCHMARK_HE300: &str = "benchmark:he300:";
/// CC 3.1.9.4 — the LLM-as-judge verdict family. Manifest
/// (`judge_model:verdict:{model_id}`): *"boolean-via-score polarity: default
/// aggregation is Min across attesters … any FAIL trumps PASS; not mean."*
pub const DIM_JUDGE_MODEL: &str = "judge_model:";
/// CC 4.5.1.1 — the partner-relationship-role family. Manifest
/// (`partner_role:{role}`): *"Enumerated-polarity dimensions (incl.
/// partner_role) compose by most-recent-by-signed_at … mean/average
/// composition FORBIDDEN."*
pub const DIM_PARTNER_ROLE: &str = "partner_role:";

// ─── CC 4.4.2 — polarity-keyed aggregation defaults ──────────────────────────

/// The CC 3.1 *polarity column* of a dimension, which selects the CC 4.4.2
/// default aggregation.
///
/// CC 4.4.2: *"Per dimension+attested_key_id, the verdict is computed by
/// composing attestations under the chosen policy. Default aggregation by
/// polarity column (CC 3.1) … Specific dimensions override via consumer policy;
/// the defaults above are the CC 2.2 CEG-Conforming Consumer (CCC) minimum."*
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Polarity {
    /// `signed` → **mean** of `score × confidence` across attesters.
    Signed,
    /// `boolean-via-score` → **min** (any negative trumps positive — fail-secure
    /// for hard constraints like `prohibited:*`, `attestation:l*`).
    BooleanViaScore,
    /// `+1.0 only` / `positive-only` → **max** across attesters (any positive is
    /// conclusive).
    PositiveOnly,
    /// `-1.0 only` → **min** across attesters (any negative is conclusive).
    NegativeOnly,
    /// `enumerated` → **most-recent** by `signed_at` from the attester(s)
    /// authorized to emit per CC 3.4.
    Enumerated,
    /// Detector dimensions (`detection:correlated_action:*`,
    /// `detection:distributive:access:*`, `ratchet:flag:*`) → **median** across
    /// attesters (resists adversarial mean-pulling by a single captured
    /// detector).
    Detector,
}

/// Resolve a dimension's CC 3.1 polarity column → its CC 4.4.2 default
/// aggregation.
///
/// The prefix table below is the CC 3.1 namespace table's polarity column for
/// every family this node composes today. **Unknown dimensions default to
/// [`Polarity::Signed`]** — the CC 3.1 modal polarity and the one Policy A
/// itself names ("mean of `score × confidence`"). An unknown *dimension* is not
/// an untrusted *attester*: the fail-closed gate is the trust set (CC 4.4.3.8),
/// not the polarity table, so defaulting the aggregator here cannot admit an
/// unpinned attester.
pub fn polarity_for(dimension: &str) -> Polarity {
    // Detector dimensions FIRST — CC 3.4.8 reserves the whole `detection:*`
    // prefix-wildcard for primary detector emission, and CC 4.4.2 medians them.
    // A cross-attestation rides the DISTINCT `truth_grounding:detection:*`
    // prefix (CC 3.4.8), which does not start with `detection:` — so it falls
    // through to `signed`, exactly as CC 3.1.9.3 says (`truth_grounding:*` is
    // signed). The ordering here is what keeps those two apart.
    if dimension.starts_with(DIM_DETECTION) || dimension.starts_with(DIM_RATCHET_FLAG) {
        return Polarity::Detector;
    }
    // `-1.0 only` (CC 3.1: "Score is always -1 (NEVER_ALLOWED) or -0.5
    // (REQUIRES_SEPARATE_MODULE); never positive") → min is conclusive.
    // `revocation:*` (CC 3.1.1 / CC 1.13.2) rides the same fail-secure extremum:
    // it is `-1.0`-only and non-rollbackable, so it MUST NOT fold into a signed
    // mean where a spurious positive on the same (dimension, key) could dilute a
    // live revocation toward zero.
    if dimension.starts_with("prohibited:") || dimension.starts_with(DIM_REVOCATION) {
        return Polarity::NegativeOnly;
    }
    // `boolean-via-score` — fail-secure min. `attestation:l*` is the ladder
    // (CC 4.4.3.6 Policy I); `slashing:*` / `witness_diversity:*` per CC 3.1.9.3;
    // `judge_model:*` (CC 3.1.9.4) — any FAIL verdict trumps PASS, never a mean
    // (an open-vocabulary `model_id` string could otherwise mint fake multi-model
    // agreement that a mean would wave through); `activity_tier:*` (CC 3.1.9.6) —
    // any Below-Active attester trumps Active, never a mean.
    if dimension.starts_with("attestation:")
        || dimension.starts_with(DIM_SLASHING)
        || dimension.starts_with("witness_diversity:")
        || dimension.starts_with(DIM_JUDGE_MODEL)
        || dimension.starts_with("activity_tier:")
    {
        return Polarity::BooleanViaScore;
    }
    // `positive-only` — any positive is conclusive (CC 3.1.9.3 `need:*`).
    // `benchmark:he300:*` (CC 3.1.10) is positive-only: max is the best attested
    // score, never a mean (a mean would let a low run drag a validated capability
    // down, and no negative benchmark value is valid). `credits:*` (CC 4.4.2) is
    // positive-only: composed via max, never sum/count/mean.
    if dimension.starts_with("need:")
        || dimension.starts_with(DIM_BENCHMARK_HE300)
        || dimension.starts_with("credits:")
    {
        return Polarity::PositiveOnly;
    }
    // `enumerated` — most-recent by signed_at (CC 3.3.12 media triple).
    // `partner_role:*` (CC 4.5.1.1) is enumerated: a relationship role resolves to
    // its most-recent authorized attestation, never an average of past roles.
    if dimension.starts_with("content_class:")
        || dimension.starts_with("cw_class:")
        || dimension.starts_with("age_assurance:")
        || dimension.starts_with(DIM_PARTNER_ROLE)
    {
        return Polarity::Enumerated;
    }
    Polarity::Signed
}

// ─── CC 4.4.3.8 — Policy A: the pinned trust set ─────────────────────────────

/// CC 3.4.9 — the two co-stewards of `licensure:{authority_id}`.
///
/// *"`licensure:{authority_id}` is co-stewarded between CIRISRegistry (CC 3.1.1)
/// and CIRISVerify (CC 3.1.2) — both MAY emit; consumers compose."*
///
/// The substrate deliberately does NOT gate this (see the persist comment at
/// `src/federation/admission.rs`: *"`licensure:*` is co-owned — the admission
/// gate doesn't reject single-source emissions; per §7.3, consumers mark them
/// `confidence ≤ 0.5` until the second co-owner attests"*). It is the
/// consumer's job — ours.
///
/// Persist's `federation_keys.identity_type` vocabulary has no `registry` /
/// `verify` member, so "which of the two co-stewards is this key" is resolved
/// the only way CC leaves open to a consumer: **by pin**. The consumer pins the
/// Registry co-steward key(s) and the Verify co-steward key(s) into its trust
/// set (CC 4.4.3.8's "consumer-added pins"), and this enum names the class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum CoSteward {
    /// CIRISRegistry (CC 3.1.1).
    Registry,
    /// CIRISVerify (CC 3.1.2).
    Verify,
}

/// CC 4.4.3.8 Policy A's pinned trust set.
///
/// *"Consumer trusts an attestation if `attesting_key_id` is in the consumer's
/// pinned trust set (canonical bootstraps + consumer-added pins)."*
///
/// **Recommended default** (CC 4.4.3.8): `pinned_trust = {us-steward,
/// eu-steward, apac-steward, accord_holder_1, accord_holder_2,
/// accord_holder_3}`, with the **cold-start bootstrap**: *"a new consumer
/// obtains the pinned trust set by fetching `GET /v1/steward-key` +
/// `GET /v1/accord-holders` (CC 5.3.4)"*. On THIS node both surfaces are
/// server-owned and read out of our own federation directory — `src/accord.rs`
/// serves `GET /v1/accord-holders` off
/// `list_keys_by_identity_type(accord_holder)`, and the steward keys are the
/// `identity_type = steward` rows. [`TrustSet::bootstrap`] is exactly those two
/// reads, so the trust root is the node's EXISTING one; no new trust source is
/// invented here.
#[derive(Debug, Clone, Default)]
pub struct TrustSet {
    pinned: BTreeSet<String>,
    co_stewards: BTreeMap<String, CoSteward>,
}

impl TrustSet {
    /// An empty trust set. Composing against it admits nothing (fail-closed).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a consumer pin (CC 4.4.3.8 "consumer-added pins").
    pub fn pin(&mut self, key_id: impl Into<String>) -> &mut Self {
        self.pinned.insert(key_id.into());
        self
    }

    /// Pin a key AND classify it as one of the CC 3.4.9 `licensure:*`
    /// co-stewards. A co-steward is trusted by construction (pinning is
    /// implied) — an unpinned "co-steward" would be a contradiction.
    /// CIRISServer#253: RETIRED as a production path — `compose_for_key` now
    /// resolves co-steward roles from the substrate (`has_effective_role`,
    /// persist v17). Kept for unit tests, which compose over a synthetic
    /// corpus with no live accord roster to resolve against.
    pub fn pin_co_steward(&mut self, key_id: impl Into<String>, class: CoSteward) -> &mut Self {
        let key_id = key_id.into();
        self.pinned.insert(key_id.clone());
        self.co_stewards.insert(key_id, class);
        self
    }

    /// Pin the `ciris-canonical` founder-quorum roster (`src/quorum.rs`) — the
    /// entrenched 2-of-3 M-of-N that REPLACED the single vaulted steward key.
    /// Its founder `member_id`s are federation `key_id`s, so they are canonical
    /// bootstraps in the CC 4.4.3.8 sense.
    pub fn pin_founder_quorum(&mut self, community: &InfrastructureCommunity) -> &mut Self {
        for m in &community.members {
            self.pinned.insert(m.member_id.clone());
        }
        self
    }

    /// CC 4.4.3.8 Policy A membership test.
    pub fn contains(&self, key_id: &str) -> bool {
        self.pinned.contains(key_id)
    }

    /// The CC 3.4.9 co-steward class of `key_id`, if it is one.
    pub fn co_steward(&self, key_id: &str) -> Option<CoSteward> {
        self.co_stewards.get(key_id).copied()
    }

    /// True iff nothing is pinned — every composition against this set is
    /// [`Decision::Undetermined`]. Callers SHOULD treat this as a cold-start
    /// error rather than as "everything is untrusted but that's fine".
    pub fn is_empty(&self) -> bool {
        self.pinned.is_empty()
    }

    /// The pinned key_ids (sorted).
    pub fn pinned(&self) -> impl Iterator<Item = &str> {
        self.pinned.iter().map(String::as_str)
    }

    /// CC 4.4.3.8 **cold-start bootstrap**, resolved against this node's own
    /// federation directory: the `accord_holder` roster (what
    /// `GET /v1/accord-holders` serves, `src/accord.rs`) + the `steward` rows
    /// (the `GET /v1/steward-key` analogue). These are the node's EXISTING
    /// trust anchors — the same rows the HUMANITY_ACCORD kill-switch and the
    /// admission gate already root on.
    ///
    /// # Errors
    /// Propagates the federation-directory read error (fail-closed: a caller
    /// that cannot read its own trust root MUST NOT compose).
    pub async fn bootstrap(engine: &Engine) -> Result<Self> {
        let dir = engine.federation_directory();
        let mut set = Self::new();
        for it in [identity_type::ACCORD_HOLDER, identity_type::STEWARD] {
            let rows = dir
                .list_keys_by_identity_type(it)
                .await
                .map_err(|e| anyhow::anyhow!("trust-set bootstrap ({it}): {e}"))?;
            for r in rows {
                set.pin(r.key_id);
            }
        }
        Ok(set)
    }
}

// ─── CC 4.4.1 — the weighting order (NORMATIVE, not a knob) ──────────────────

/// The order in which the CC 4.4.1 Frickerian rule and the structural
/// safeguards it defers to are applied.
///
/// CC 4.4.1 **adversarial caveat** (the whole reason this type exists):
///
/// > *"an adversary can emit `testimonial_witness:victim_of_my_competitor`
/// > exploiting the Frickerian non-downweighting rule. Per CC 3.1.9.3,
/// > `testimonial_witness:*` is never sole evidence for `slashing:*`; per
/// > CC 3.4.7 the consumer MUST also weight `witness_relation: self` claims
/// > against the attester's other-emission track record. **The Frickerian rule
/// > applies AFTER these structural safeguards, not before them.**"*
///
/// So the ordering is normative. [`WeightingOrder::StructuralThenFrickerian`]
/// is the ONLY conformant value and is the default everywhere in production.
/// [`WeightingOrder::FrickerianFirst`] exists so the test suite can construct
/// the exact case the caveat warns about and prove the two orders give
/// different answers — i.e. so the ordering is *pinned by a test*, not merely
/// asserted in a comment. It MUST NOT be used in production paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WeightingOrder {
    /// CC 4.4.1-conformant: structural safeguards (CC 3.1.9.3 sole-evidence
    /// gate + CC 3.4.7 `witness_relation: self` track-record weighting) run
    /// FIRST; the Frickerian non-downweighting rule runs AFTER, over their
    /// output.
    #[default]
    StructuralThenFrickerian,
    /// **NON-CONFORMANT — test-only.** The naive reading CC 4.4.1 explicitly
    /// forbids: treat the Frickerian exemption as a blanket "never downweight
    /// this dimension", short-circuiting the structural safeguards. Kept so
    /// `tests/compose_policy.rs` can demonstrate the divergence.
    FrickerianFirst,
}

/// CONSUMER-POLICY knobs. The CC 4.4.1 *invariants* (never downweight
/// `testimonial_witness:*` for cohort density; never downweight
/// `non_maleficence:*`; structural-before-Frickerian ordering) are NOT here —
/// they are unconditional in [`Composer`]. What IS here is the shape of the
/// downweight a consumer applies to everything else, which CC leaves to the
/// consumer.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// A cohort with fewer than this many attestations in the composed corpus
    /// is "low attestation density" in the CC 4.4.1 sense. CONSUMER POLICY.
    pub low_density_min_emissions: usize,
    /// The factor a low-density cohort's attestation is multiplied by — the
    /// identity-prejudice CC 4.4.1 exists to bound. Applied ONLY to dimensions
    /// the Frickerian rule does not protect. CONSUMER POLICY.
    pub low_density_weight: f64,
    /// CC 4.4.3.8: *"Consumer threshold determines verdict."* A composed
    /// `value` at or above this is [`Decision::Affirm`]. CONSUMER POLICY.
    pub threshold: f64,
    /// The CC 4.4.1 ordering. Normative — the default is the only conformant
    /// value; see [`WeightingOrder`].
    pub order: WeightingOrder,
    /// Evaluation instant for CC 2.1 `valid_until` / row `expires_at`
    /// staleness. `None` → `Utc::now()`.
    pub now: Option<DateTime<Utc>>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            low_density_min_emissions: 3,
            low_density_weight: 0.5,
            threshold: 0.0,
            order: WeightingOrder::default(),
            now: None,
        }
    }
}

// ─── Output types ────────────────────────────────────────────────────────────

/// Why an attestation did not contribute to a verdict. Fail-closed: an
/// attestation the consumer cannot resolve NEVER silently passes — it lands
/// here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RefusalReason {
    /// CC 4.4.3.8 Policy A: `attesting_key_id` is not in the pinned trust set.
    NotInTrustSet,
    /// CC 2.1 `valid_until` / row `expires_at` has passed.
    Expired,
    /// The envelope is missing a REQUIRED CC 2.1 field (`dimension`, `score`,
    /// `confidence`) or it is out of range. Fail-closed: we do NOT default a
    /// missing `confidence` to 1.0 — CC 2.1 marks it required.
    MalformedEnvelope(String),
    /// CC 3.4.5 anti-Goodhart: a `capacity:*` score about oneself. The
    /// substrate rejects it at admission; per CC 3.4.7 the CCC re-checks
    /// ("Trust does not propagate").
    SelfEmission,
    /// CC 3.1.9.3 structural safeguard: a `slashing:*` attestation whose
    /// resolvable `evidence_refs` are **exclusively** `testimonial_witness:*`
    /// rows. *"`testimonial_witness:*` … never sole evidence for `slashing:*`"*.
    TestimonialSoleEvidenceForSlashing,
    /// CC 3.1.6 (FSD-005 App.A:182) structural safeguard, the SIBLING of the
    /// testimonial screen: a `slashing:*` attestation whose resolvable
    /// `evidence_refs` are **exclusively** `detection:*` / `ratchet:flag:*`
    /// detector rows. *"ratchet:flag:\* / detection:\* cannot be sole evidence
    /// for slashing … unreachable from ratchet/detection alone."* The WA quorum
    /// (a documented `moderation:*` antecedent or method-spoofing finding) is the
    /// load-bearing gate; a raw detector signal is never sufficient on its own.
    DetectorSoleEvidenceForSlashing,
    /// Not a `scores` row — the composition tier composes scores; structural
    /// composers (`supersedes` / `withdraws` / `recants`) are persist's
    /// precedence layer, not ours.
    NotAScore,
}

/// A refused attestation, with the reason. Surfaced so an operator can see
/// exactly what did NOT count.
#[derive(Debug, Clone, Serialize)]
pub struct Refusal {
    /// The refused row.
    pub attestation_id: String,
    /// Who emitted it.
    pub attesting_key_id: String,
    /// Its dimension (best-effort — may be absent on a malformed envelope).
    pub dimension: Option<String>,
    /// Why it did not contribute.
    pub reason: RefusalReason,
}

/// One admitted attestation's contribution to a verdict, with the CC 4.4.1
/// weight that was applied and WHY. Exposed (not internal) because the
/// weighting invariants are the normative content of CC 4.4.1 — an auditor
/// (and the test suite) must be able to see the weight, not just the verdict.
#[derive(Debug, Clone, Serialize)]
pub struct Contribution {
    /// The contributing row.
    pub attestation_id: String,
    /// Its attester.
    pub attesting_key_id: String,
    /// CC 2.1 `score`.
    pub score: f64,
    /// CC 2.1 `confidence`, AFTER the CC 3.4.9 single-source cap (if any).
    pub confidence: f64,
    /// The CC 4.4.1 weight in `[0, 1]`.
    pub weight: f64,
    /// CC 3.4.7 `witness_relation: self` track-record downweight was applied.
    pub self_track_record_applied: bool,
    /// The CONSUMER-POLICY low-cohort-density downweight was applied. MUST be
    /// `false` for `testimonial_witness:*` and `non_maleficence:*` (CC 4.4.1).
    pub low_density_applied: bool,
    /// CC 3.4.9 capped this row's `confidence` to ≤ 0.5 (single-source
    /// `licensure:*`).
    pub licensure_capped: bool,
}

/// The verdict for one (dimension, attested_key_id) tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Decision {
    /// Composed value ≥ the consumer threshold.
    Affirm,
    /// Composed value < the consumer threshold.
    Deny,
    /// **Fail-closed**: nothing survived screening (no trusted, unexpired,
    /// well-formed attestation for this tuple). NOT a pass, NOT a deny —
    /// the consumer has no basis for either.
    Undetermined,
}

/// A composed verdict — CC 4.4: *"consumers compose traversals (verdicts)"*.
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    /// CC 3.1 dimension.
    pub dimension: String,
    /// The attested key.
    pub attested_key_id: String,
    /// The CC 4.4.2 polarity that selected the aggregation.
    pub polarity: Polarity,
    /// The composed value. For [`Polarity::Signed`] this is Policy A's
    /// *"mean of `score × confidence`"* with the CC 4.4.1 weights folded in.
    pub value: f64,
    /// The composed confidence, in `[0, 1]`. For `licensure:*` this is ≤ 0.5
    /// while single-sourced (CC 3.4.9).
    pub confidence: f64,
    /// CC 3.4.9: only one of the two co-stewards has emitted → capped.
    pub single_source_licensure: bool,
    /// CC 4.4.3.9 Policy D decided a tie.
    pub lexical_tie_break_applied: bool,
    /// What contributed, and at what weight.
    pub contributions: Vec<Contribution>,
    /// The threshold decision.
    pub decision: Decision,
}

/// The output of one composition pass.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Composition {
    /// Verdicts keyed by `(dimension, attested_key_id)`, sorted.
    pub verdicts: Vec<Verdict>,
    /// Everything that did NOT contribute, and why (fail-closed audit trail).
    pub refusals: Vec<Refusal>,
}

impl Composition {
    /// Look up one verdict.
    pub fn verdict(&self, dimension: &str, attested_key_id: &str) -> Option<&Verdict> {
        self.verdicts
            .iter()
            .find(|v| v.dimension == dimension && v.attested_key_id == attested_key_id)
    }
}

// ─── The composer ────────────────────────────────────────────────────────────

/// A parsed, screened attestation ready for weighting + aggregation.
#[derive(Debug, Clone)]
struct Row<'a> {
    att: &'a Attestation,
    dimension: String,
    score: f64,
    confidence: f64,
    /// CC 2.1: default `external` when the member is absent.
    witness_relation: String,
    /// CC 4.4.3.9 `context.affected_population_estimate`.
    affected_population: Option<f64>,
    /// The attester's cohort, for the CC 4.4.1 density test. `None` → unknown
    /// cohort → NOT downweighted (see [`Composer::weigh`]).
    cohort_id: Option<String>,
}

/// CC 4.4 consumer-composition engine — Policy A (CC 4.4.3.8) + the CC 4.4.2
/// aggregation defaults + the CC 4.4.1 weighting invariants + the CC 3.4.9
/// co-steward cap.
#[derive(Debug, Clone)]
pub struct Composer {
    trust: TrustSet,
    cfg: PolicyConfig,
}

impl Composer {
    /// Build a composer over a pinned trust set with the default consumer
    /// policy.
    pub fn new(trust: TrustSet) -> Self {
        Self {
            trust,
            cfg: PolicyConfig::default(),
        }
    }

    /// Override the CONSUMER-POLICY knobs (see [`PolicyConfig`]).
    pub fn with_config(mut self, cfg: PolicyConfig) -> Self {
        self.cfg = cfg;
        self
    }

    /// The pinned trust set backing this composer.
    pub fn trust_set(&self) -> &TrustSet {
        &self.trust
    }

    /// Compose every `scores` attestation about `attested_key_id` that this
    /// node holds, reading from persist. The async convenience wrapper over
    /// [`Composer::compose`].
    ///
    /// # Errors
    /// Propagates the federation-directory read error.
    pub async fn compose_for_key(
        &self,
        engine: &Engine,
        attested_key_id: &str,
    ) -> Result<Composition> {
        let dir = engine.federation_directory();
        let rows = dir
            .list_attestations_for(attested_key_id)
            .await
            .map_err(|e| anyhow::anyhow!("list_attestations_for({attested_key_id}): {e}"))?;

        // CC 3.4.9 co-steward resolution — CIRISServer#253, persist v17.
        //
        // `licensure_cap` caps a `licensure:*` fold below full confidence until
        // BOTH co-stewards (CIRISRegistry + CIRISVerify) have emitted. Which
        // co-steward an attesting key IS was, pre-17.0.0, unresolvable from the
        // substrate — the identity_type vocabulary had no `registry`/`verify`
        // member — so the composer resolved it by an out-of-band consumer PIN
        // (`TrustSet::pin_co_steward`, the #159 workaround). persist v17
        // (CIRISPersist#440) carries the co-steward roles ON the key record with
        // accord-conferred, self-authenticating semantics, so we resolve from the
        // substrate here and RETIRE the by-pin fallback in production.
        //
        // `has_effective_role` is self-authenticating by design: a decorative
        // pre-17 self-claimed `roles=["registry"]` row reads `false` (its co-scrub
        // set must re-verify against the LIVE accord roster), so this read never
        // trusts write-gate history. Resolution happens in THIS async phase; the
        // pure `compose` stays synchronous (and the pin API remains, for tests).
        use ciris_persist::federation::admission::has_effective_role;
        use ciris_persist::federation::types::identity_type::{REGISTRY, VERIFY};
        let mut trust = self.trust.clone();
        let mut resolved: BTreeMap<String, CoSteward> = BTreeMap::new();
        for att in &rows {
            if !envelope_str(att, paths::DIMENSION).is_some_and(|d| d.starts_with(DIM_LICENSURE)) {
                continue;
            }
            let k = &att.attesting_key_id;
            if resolved.contains_key(k) {
                continue;
            }
            if has_effective_role(dir.as_ref(), k, REGISTRY)
                .await
                .map_err(|e| anyhow::anyhow!("has_effective_role({k}, registry): {e}"))?
            {
                resolved.insert(k.clone(), CoSteward::Registry);
            } else if has_effective_role(dir.as_ref(), k, VERIFY)
                .await
                .map_err(|e| anyhow::anyhow!("has_effective_role({k}, verify): {e}"))?
            {
                resolved.insert(k.clone(), CoSteward::Verify);
            }
        }
        for (k, class) in resolved {
            trust.pin_co_steward(k, class);
        }
        let composer = Composer {
            trust,
            cfg: self.cfg.clone(),
        };
        Ok(composer.compose(&rows))
    }

    /// Compose a corpus of attestations into verdicts. Pure — no I/O, so the
    /// normative rules are testable adversarially without a substrate.
    pub fn compose(&self, corpus: &[Attestation]) -> Composition {
        let now = self.cfg.now.unwrap_or_else(Utc::now);
        let mut out = Composition::default();

        // ── 0. Screen (fail-closed) ─────────────────────────────────────────
        // Policy A trust check, staleness, envelope well-formedness, and the
        // CCC re-checks (CC 3.4.7: "Trust does not propagate: the substrate's
        // admission check is the FIRST line of defense; the consumer's re-check
        // is the second. Both checks MUST agree.").
        let mut rows: Vec<Row<'_>> = Vec::new();
        for att in corpus {
            match self.screen(att, corpus, now) {
                Ok(row) => rows.push(row),
                Err(reason) => out.refusals.push(Refusal {
                    attestation_id: att.attestation_id.clone(),
                    attesting_key_id: att.attesting_key_id.clone(),
                    dimension: envelope_str(att, paths::DIMENSION),
                    reason,
                }),
            }
        }

        // ── 1. Corpus-level statistics the CC 4.4.1 weighting needs ─────────
        // Track record (CC 3.4.7) and cohort density (CC 4.4.1) are properties
        // of the WHOLE corpus, not of a single row — so they are computed once,
        // over every well-formed row, BEFORE any per-tuple aggregation.
        //
        // Deliberately computed over the SCREENED rows: an untrusted attester's
        // emissions must not pad a trusted cohort's density (that would let an
        // adversary manufacture "density" for free).
        let track = TrackRecord::of(&rows);
        let density = CohortDensity::of(&rows);

        // ── 2. Group by (dimension, attested_key_id) — CC 4.4.2's unit ──────
        let mut groups: BTreeMap<(String, String), Vec<Row<'_>>> = BTreeMap::new();
        for r in rows {
            groups
                .entry((r.dimension.clone(), r.att.attested_key_id.clone()))
                .or_default()
                .push(r);
        }

        // Every (dimension, attested_key_id) that appears in the corpus but had
        // ZERO rows survive screening still gets a verdict — an explicit
        // Undetermined. Fail-closed means "visibly undecided", not "absent".
        let mut undetermined: BTreeSet<(String, String)> = BTreeSet::new();
        for r in &out.refusals {
            if let Some(dim) = &r.dimension {
                if let Some(att) = corpus
                    .iter()
                    .find(|a| a.attestation_id == r.attestation_id)
                    .map(|a| a.attested_key_id.clone())
                {
                    undetermined.insert((dim.clone(), att));
                }
            }
        }

        for ((dimension, attested_key_id), group) in groups {
            undetermined.remove(&(dimension.clone(), attested_key_id.clone()));
            out.verdicts.push(self.compose_group(
                dimension,
                attested_key_id,
                group,
                &track,
                &density,
            ));
        }

        for (dimension, attested_key_id) in undetermined {
            let polarity = polarity_for(&dimension);
            out.verdicts.push(Verdict {
                dimension,
                attested_key_id,
                polarity,
                value: 0.0,
                confidence: 0.0,
                single_source_licensure: false,
                lexical_tie_break_applied: false,
                contributions: Vec::new(),
                decision: Decision::Undetermined,
            });
        }

        out.verdicts.sort_by(|a, b| {
            (&a.dimension, &a.attested_key_id).cmp(&(&b.dimension, &b.attested_key_id))
        });
        out
    }

    /// CC 4.4.3.8 Policy A screening + the CC 3.4.7 CCC re-checks. `Err` is a
    /// refusal — the fail-closed path.
    fn screen<'a>(
        &self,
        att: &'a Attestation,
        corpus: &[Attestation],
        now: DateTime<Utc>,
    ) -> std::result::Result<Row<'a>, RefusalReason> {
        // The composition tier composes `scores`. Structural composers
        // (supersedes/withdraws/recants) are persist's precedence layer
        // (`precedence_winner`), not a verdict input.
        if att.attestation_type != attestation_type::SCORES {
            return Err(RefusalReason::NotAScore);
        }

        // ── Policy A (CC 4.4.3.8): "Consumer trusts an attestation if
        // `attesting_key_id` is in the consumer's pinned trust set." Anything
        // else is REFUSED — it does not silently pass at weight 0, it is
        // recorded as untrusted.
        if !self.trust.contains(&att.attesting_key_id) {
            return Err(RefusalReason::NotInTrustSet);
        }

        // Staleness — the row's `expires_at` (persist mirrors CC 2.1
        // `valid_until` onto it; `src/scorer.rs` sets both).
        if let Some(exp) = att.expires_at {
            if exp <= now {
                return Err(RefusalReason::Expired);
            }
        }
        if let Some(vu) = envelope_str(att, "valid_until")
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|d| d.with_timezone(&Utc))
        {
            if vu <= now {
                return Err(RefusalReason::Expired);
            }
        }

        // CC 2.1 REQUIRED fields. `confidence` is REQUIRED ("yes" in the CC 2.1
        // table) — a missing one is malformed, NOT an implied 1.0. Defaulting it
        // would hand an attester full confidence for free.
        let dimension = envelope_str(att, paths::DIMENSION)
            .ok_or_else(|| RefusalReason::MalformedEnvelope("dimension".into()))?;
        let score = envelope_f64(att, "score")
            .ok_or_else(|| RefusalReason::MalformedEnvelope("score".into()))?;
        let confidence = envelope_f64(att, "confidence")
            .ok_or_else(|| RefusalReason::MalformedEnvelope("confidence".into()))?;
        if !(0.0..=1.0).contains(&confidence) {
            return Err(RefusalReason::MalformedEnvelope(
                "confidence out of [0,1]".into(),
            ));
        }
        if !(-1.0..=1.0).contains(&score) {
            return Err(RefusalReason::MalformedEnvelope(
                "score out of [-1,1]".into(),
            ));
        }

        // ── CCC re-check: CC 3.4.5 anti-Goodhart self-emission ──────────────
        // "a folded agent+lenscore_detector key still MUST NOT emit a
        // `capacity:*` score about itself." The substrate rejects it at
        // admission; CC 3.4.7 says the consumer re-checks anyway ("Both checks
        // MUST agree") — a peer's substrate may be lying.
        if dimension.starts_with(DIM_CAPACITY) && att.attesting_key_id == att.attested_key_id {
            return Err(RefusalReason::SelfEmission);
        }

        // ── STRUCTURAL SAFEGUARD #1 (CC 3.1.9.3, cited by CC 4.4.1) ─────────
        // "`testimonial_witness:*` … never sole evidence for `slashing:*`".
        // This is a SCREEN, not a weight: a slashing row whose whole resolvable
        // evidence base is testimonial does not get to contribute at ANY weight.
        // It runs HERE — before any Frickerian consideration — which is the
        // ordering CC 4.4.1 mandates.
        if dimension.starts_with(DIM_SLASHING) && testimonial_sole_evidence(att, corpus) {
            return Err(RefusalReason::TestimonialSoleEvidenceForSlashing);
        }

        // ── STRUCTURAL SAFEGUARD #1b (CC 3.1.6, FSD-005 App.A:182) ──────────
        // The SIBLING of the testimonial screen, same SHAPE: "`ratchet:flag:*` /
        // `detection:*` cannot be sole evidence for slashing … unreachable from
        // ratchet/detection alone." A slashing row whose whole resolvable evidence
        // base is detector emissions is refused — a raw detector signal is an
        // alert, not a WA-quorum finding. Like its testimonial twin this is a
        // SCREEN (contributes at NO weight), applied before any weighting.
        if dimension.starts_with(DIM_SLASHING) && detector_sole_evidence(att, corpus) {
            return Err(RefusalReason::DetectorSoleEvidenceForSlashing);
        }

        Ok(Row {
            att,
            dimension,
            score,
            confidence,
            // CC 2.6.1.2: `witness_relation` defaults to `external` when absent.
            witness_relation: envelope_str(att, "witness_relation")
                .unwrap_or_else(|| "external".to_string()),
            affected_population: envelope_context_f64(att, "affected_population_estimate"),
            cohort_id: envelope_context_str(att, "cohort_id"),
        })
    }

    /// The CC 4.4.1 weighting — **the normative core of this module**.
    ///
    /// > CC 4.4.1: *"consumers SHOULD apply identity-prejudice-resistant
    /// > weighting. Concretely: Don't downweight `testimonial_witness:*` from
    /// > cohorts with low overall attestation density (testimonial preservation
    /// > is precisely what corrects for that low density). Don't downweight
    /// > `non_maleficence:*` claims about a partner just because the partner has
    /// > a long `partner_role:*` track record."*
    ///
    /// > CC 4.4.1 adversarial caveat: *"per CC 3.4.7 the consumer MUST also
    /// > weight `witness_relation: self` claims against the attester's
    /// > other-emission track record. **The Frickerian rule applies AFTER these
    /// > structural safeguards, not before them.**"*
    ///
    /// The ORDER is the whole point, so it is explicit in the code:
    ///
    /// 1. **Structural** — CC 3.4.7 self-attestation track record. Applies to
    ///    EVERY dimension, including the Frickerian-protected ones. A
    ///    `testimonial_witness:*` row is `witness_relation: self` by CC 3.1.9.3
    ///    discipline, so this is exactly the rung the adversary of the caveat
    ///    tries to skip.
    /// 2. **Frickerian** — the identity-prejudice downweight (low cohort
    ///    density) is SUPPRESSED for `testimonial_witness:*` and
    ///    `non_maleficence:*`, and applied otherwise.
    ///
    /// Under [`WeightingOrder::FrickerianFirst`] (test-only, non-conformant) the
    /// protected dimensions short-circuit to weight 1.0 BEFORE step 1 runs —
    /// which is precisely the hole CC 4.4.1 closes, and what
    /// `tests/compose_policy.rs` pins.
    fn weigh(
        &self,
        r: &Row<'_>,
        track: &TrackRecord,
        density: &CohortDensity,
    ) -> (f64, bool, bool) {
        let protected = r.dimension.starts_with(DIM_TESTIMONIAL_WITNESS)
            || r.dimension.starts_with(DIM_NON_MALEFICENCE);

        if self.cfg.order == WeightingOrder::FrickerianFirst && protected {
            // NON-CONFORMANT ordering, retained ONLY to be contrasted in tests:
            // the Frickerian exemption is read as a blanket immunity and the
            // structural safeguard never runs. CC 4.4.1 forbids exactly this.
            return (1.0, false, false);
        }

        // ── 1. STRUCTURAL SAFEGUARD #2 (CC 3.4.7, cited by CC 4.4.1) ────────
        // "the consumer MUST also weight `witness_relation: self` claims against
        // the attester's other-emission track record". CC mandates THAT they be
        // weighted, not the function; ours is CONSUMER POLICY:
        //   w_self = (1 + other_emissions) / (1 + other_emissions + self_emissions)
        // Monotone in both arguments, bounded in (0, 1]: a serial self-attester
        // with no external track record decays toward 0; an attester with a
        // broad external record approaches 1. A lone self-claim from a fresh key
        // sits at 0.5 — attenuated, never silenced (CC 3.1.9.3: the narrative IS
        // preserved; it just is not conclusive).
        let mut weight = 1.0_f64;
        let mut self_track_record_applied = false;
        if r.witness_relation == "self" {
            weight *= track.self_weight(&r.att.attesting_key_id);
            self_track_record_applied = true;
        }

        // ── 2. FRICKERIAN (CC 4.4.1) — AFTER the structural safeguards ──────
        let mut low_density_applied = false;
        if !protected {
            // The identity-prejudice downweight a consumer would otherwise apply
            // to a sparsely-attesting cohort. CC 4.4.1 permits it here and
            // FORBIDS it on the protected prefixes above.
            //
            // An UNKNOWN cohort (no `context.cohort_id`) is NOT downweighted:
            // downweighting is the harm CC 4.4.1 bounds, so absence of density
            // evidence must not manufacture prejudice.
            if let Some(cohort) = &r.cohort_id {
                if density.is_low(cohort, self.cfg.low_density_min_emissions) {
                    weight *= self.cfg.low_density_weight;
                    low_density_applied = true;
                }
            }
        }

        (
            weight.clamp(0.0, 1.0),
            self_track_record_applied,
            low_density_applied,
        )
    }

    /// CC 3.4.9 — the co-stewarded-prefix single-source cap.
    ///
    /// > *"`licensure:{authority_id}` is co-stewarded between CIRISRegistry and
    /// > CIRISVerify — both MAY emit; consumers compose. **Single-source
    /// > attestations** (only one of the two co-stewards has emitted) **MUST be
    /// > marked as `confidence ≤ 0.5` in consumer composition** until the second
    /// > co-steward's attestation arrives."*
    ///
    /// Persist DELIBERATELY defers this to us (`src/federation/admission.rs`:
    /// *"`licensure:*` … is co-owned — the admission gate doesn't reject
    /// single-source emissions; … consumers mark them `confidence ≤ 0.5` until
    /// the second co-owner attests"*). If we don't do it, nobody does.
    ///
    /// Returns `true` iff the group is single-sourced and the cap applies. Note
    /// the fail-closed reading of "only one of the two co-stewards has emitted":
    /// **zero** co-stewards having emitted (an attester that is pinned but is
    /// not classified as a co-steward) is also < 2 and is capped. Two keys of
    /// the SAME co-steward class do not lift the cap either — CC names the two
    /// *institutions*, not two *keys*.
    fn licensure_cap(&self, dimension: &str, group: &[Row<'_>]) -> bool {
        if !dimension.starts_with(DIM_LICENSURE) {
            return false;
        }
        let classes: BTreeSet<CoSteward> = group
            .iter()
            .filter_map(|r| self.trust.co_steward(&r.att.attesting_key_id))
            .collect();
        classes.len() < 2
    }

    fn compose_group(
        &self,
        dimension: String,
        attested_key_id: String,
        group: Vec<Row<'_>>,
        track: &TrackRecord,
        density: &CohortDensity,
    ) -> Verdict {
        let polarity = polarity_for(&dimension);
        let capped = self.licensure_cap(&dimension, &group);

        let contributions: Vec<(Contribution, &Row<'_>)> = group
            .iter()
            .map(|r| {
                let (weight, self_track, low_density) = self.weigh(r, track, density);
                // CC 3.4.9: the cap is applied to the CONFIDENCE, before any
                // aggregation — so it propagates into every polarity's output
                // (mean, extremum, median alike). A single co-steward can never
                // reach full confidence no matter what it claims.
                let confidence = if capped {
                    r.confidence.min(0.5)
                } else {
                    r.confidence
                };
                (
                    Contribution {
                        attestation_id: r.att.attestation_id.clone(),
                        attesting_key_id: r.att.attesting_key_id.clone(),
                        score: r.score,
                        confidence,
                        weight,
                        self_track_record_applied: self_track,
                        low_density_applied: low_density,
                        licensure_capped: capped,
                    },
                    r,
                )
            })
            .collect();

        let (value, confidence, tie_break) = aggregate(polarity, &contributions);

        let decision = if contributions.is_empty() {
            Decision::Undetermined
        } else if value >= self.cfg.threshold {
            Decision::Affirm
        } else {
            Decision::Deny
        };

        Verdict {
            dimension,
            attested_key_id,
            polarity,
            value,
            confidence,
            single_source_licensure: capped,
            lexical_tie_break_applied: tie_break,
            contributions: contributions.into_iter().map(|(c, _)| c).collect(),
            decision,
        }
    }
}

// ─── CC 4.4.2 aggregation ────────────────────────────────────────────────────

/// CC 4.4.2 polarity-keyed aggregation. Returns `(value, confidence,
/// lexical_tie_break_applied)`.
///
/// The CC 4.4.1 weights bear on the **mean** polarities (`signed`, and the
/// detector median's ordering is weight-free by construction). They deliberately
/// do NOT scale the fail-secure **extremum** polarities' comparison key: CC 4.4.2
/// says `boolean-via-score` is *"Min (any negative trumps positive — fail-secure
/// for hard constraints)"*. If a downweight could shrink a `-1.0` toward zero, a
/// weighting rule could make a hard constraint disappear — so the extremum is
/// taken over the RAW score and the winner's (possibly capped) confidence is
/// reported alongside. Weighting must never be able to defeat fail-secure.
fn aggregate(polarity: Polarity, rows: &[(Contribution, &Row<'_>)]) -> (f64, f64, bool) {
    if rows.is_empty() {
        return (0.0, 0.0, false);
    }
    match polarity {
        // "Mean of `score × confidence` across attesters" (CC 4.4.2 + the same
        // sentence in CC 4.4.3.8 Policy A), with the CC 4.4.1 weight folded in.
        Polarity::Signed => {
            let n = rows.len() as f64;
            let value: f64 = rows
                .iter()
                .map(|(c, _)| c.score * c.confidence * c.weight)
                .sum::<f64>()
                / n;
            let confidence: f64 = rows.iter().map(|(c, _)| c.confidence).sum::<f64>() / n;

            // CC 4.4.3.9 Policy D — the tie. "When two otherwise-equivalent
            // attestations conflict, defer to whichever attestation names the
            // more-affected cohort." A conflicting set whose weighted mean is
            // exactly 0 IS the tie: the corpus says nothing. Rather than emit a
            // spurious neutral verdict, defer to the most-affected cohort.
            if rows.len() >= 2 && value.abs() < 1e-9 && has_conflict(rows) {
                if let Some(w) = lexical_vulnerability_winner(rows) {
                    return (
                        w.0.score * w.0.confidence * w.0.weight,
                        w.0.confidence,
                        true,
                    );
                }
            }
            (value, confidence.clamp(0.0, 1.0), false)
        }
        // "Min (any negative trumps positive — fail-secure)".
        Polarity::BooleanViaScore | Polarity::NegativeOnly => extremum(rows, Extremum::Min),
        // "Max across attesters (any positive is conclusive)".
        Polarity::PositiveOnly => extremum(rows, Extremum::Max),
        // "Most-recent by `signed_at` from the attester(s) authorized to emit".
        Polarity::Enumerated => {
            let latest = rows
                .iter()
                .map(|(_, r)| r.att.asserted_at)
                .max()
                .expect("non-empty");
            let tied: Vec<(Contribution, &Row<'_>)> = rows
                .iter()
                .filter(|(_, r)| r.att.asserted_at == latest)
                .cloned()
                .collect();
            if tied.len() == 1 {
                let (c, _) = &tied[0];
                return (c.score, c.confidence, false);
            }
            // Same `signed_at` from several authorized attesters → a genuine
            // tie → CC 4.4.3.9 Policy D decides it (CC 4.4.1 bullet 3: "Apply
            // CC 4.4.3.9 lexical-vulnerability-priority in tie-breaks").
            let w = lexical_vulnerability_winner(&tied).expect("non-empty");
            (w.0.score, w.0.confidence, true)
        }
        // "Median across attesters (resists adversarial mean-pulling by a single
        // captured detector)." The median is taken over the raw scores — a
        // weight cannot be allowed to move the median, or a single captured
        // detector's downweight would shift the very statistic that exists to
        // resist it.
        Polarity::Detector => {
            let mut vals: Vec<f64> = rows.iter().map(|(c, _)| c.score).collect();
            vals.sort_by(|a, b| a.partial_cmp(b).expect("no NaN — screened"));
            let mid = vals.len() / 2;
            let value = if vals.len() % 2 == 0 {
                (vals[mid - 1] + vals[mid]) / 2.0
            } else {
                vals[mid]
            };
            let n = rows.len() as f64;
            let confidence: f64 = rows.iter().map(|(c, _)| c.confidence).sum::<f64>() / n;
            (value, confidence.clamp(0.0, 1.0), false)
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Extremum {
    Min,
    Max,
}

/// CC 4.4.2's fail-secure extremum aggregations. Ties (equal raw score) are
/// broken by CC 4.4.3.9 Policy D.
fn extremum(rows: &[(Contribution, &Row<'_>)], ord: Extremum) -> (f64, f64, bool) {
    let target = rows
        .iter()
        .map(|(c, _)| c.score)
        .fold(None::<f64>, |acc, s| {
            Some(match (acc, ord) {
                (None, _) => s,
                (Some(a), Extremum::Min) => a.min(s),
                (Some(a), Extremum::Max) => a.max(s),
            })
        })
        .expect("non-empty");
    let tied: Vec<(Contribution, &Row<'_>)> = rows
        .iter()
        .filter(|(c, _)| (c.score - target).abs() < 1e-12)
        .cloned()
        .collect();
    if tied.len() == 1 {
        let (c, _) = &tied[0];
        return (c.score, c.confidence, false);
    }
    let w = lexical_vulnerability_winner(&tied).expect("non-empty");
    (w.0.score, w.0.confidence, true)
}

/// True iff the group holds both a positive and a negative score — i.e. the
/// attestations *conflict*, which is the precondition CC 4.4.3.9 names ("When
/// two otherwise-equivalent attestations **conflict**").
fn has_conflict(rows: &[(Contribution, &Row<'_>)]) -> bool {
    rows.iter().any(|(c, _)| c.score > 0.0) && rows.iter().any(|(c, _)| c.score < 0.0)
}

/// **CC 4.4.3.9 — Policy D, lexical-vulnerability-priority.**
///
/// > *"A composition tie-breaking rule layered on top of any base policy. When
/// > two otherwise-equivalent attestations conflict, defer to whichever
/// > attestation names the more-affected cohort — measured by
/// > `affected_population_estimate` in the attestation `context`, weighted
/// > inversely (smaller = more vulnerable, more weight). Inverts the default
/// > popularity-weighted aggregation specifically for ties."*
///
/// Smallest `affected_population_estimate` wins. An attestation that names NO
/// cohort size cannot claim vulnerability priority, so a missing estimate sorts
/// LAST (it is treated as unboundedly large) — otherwise omitting the field
/// would be the cheapest way to win a tie. Residual ties fall through to
/// persist's CEG §6.1 [`precedence_winner`] (composer rank → latest
/// `asserted_at` → lex-smallest `attestation_id`), so the outcome is
/// deterministic across peers.
///
/// Crate-private: it takes the internal parsed `Row`. The behaviour it pins is
/// observable on [`Verdict::lexical_tie_break_applied`] + [`Verdict::value`],
/// which is what `tests/compose_policy.rs` asserts against.
fn lexical_vulnerability_winner<'r, 'a>(
    rows: &'r [(Contribution, &'r Row<'a>)],
) -> Option<&'r (Contribution, &'r Row<'a>)> {
    let min = rows
        .iter()
        .filter_map(|(_, r)| r.affected_population)
        .fold(None::<f64>, |acc, p| Some(acc.map_or(p, |a| a.min(p))))?;
    let finalists: Vec<&(Contribution, &Row<'a>)> = rows
        .iter()
        .filter(|(_, r)| r.affected_population.map(|p| (p - min).abs() < 1e-9) == Some(true))
        .collect();
    if finalists.len() == 1 {
        return finalists.first().copied();
    }
    // Deterministic residual tie-break — reuse persist's CEG §6.1 rule rather
    // than inventing a second one.
    let atts: Vec<&Attestation> = finalists.iter().map(|(_, r)| r.att).collect();
    let winner = precedence_winner(&atts)?;
    finalists
        .into_iter()
        .find(|(_, r)| r.att.attestation_id == winner.attestation_id)
}

// ─── Corpus statistics ───────────────────────────────────────────────────────

/// CC 3.4.7 (as cited by the CC 4.4.1 adversarial caveat) — per-attester
/// self-vs-other emission counts, the "other-emission track record" a consumer
/// MUST weight `witness_relation: self` claims against.
#[derive(Debug, Default, Clone)]
struct TrackRecord {
    /// attester → (self_emissions, other_emissions)
    counts: HashMap<String, (usize, usize)>,
}

impl TrackRecord {
    fn of(rows: &[Row<'_>]) -> Self {
        let mut counts: HashMap<String, (usize, usize)> = HashMap::new();
        for r in rows {
            let e = counts.entry(r.att.attesting_key_id.clone()).or_default();
            if r.witness_relation == "self" {
                e.0 += 1;
            } else {
                e.1 += 1;
            }
        }
        Self { counts }
    }

    /// `(1 + other) / (1 + other + self)` — see [`Composer::weigh`] for the WHY.
    fn self_weight(&self, attester: &str) -> f64 {
        let (n_self, n_other) = self.counts.get(attester).copied().unwrap_or((0, 0));
        let other = n_other as f64;
        let slf = n_self as f64;
        (1.0 + other) / (1.0 + other + slf)
    }
}

/// CC 4.4.1 — "cohorts with low overall attestation density". Density is
/// measured over the composed corpus: how many attestations does this cohort
/// account for at all.
#[derive(Debug, Default, Clone)]
struct CohortDensity {
    counts: HashMap<String, usize>,
}

impl CohortDensity {
    fn of(rows: &[Row<'_>]) -> Self {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for r in rows {
            if let Some(c) = &r.cohort_id {
                *counts.entry(c.clone()).or_default() += 1;
            }
        }
        Self { counts }
    }

    fn is_low(&self, cohort: &str, min_emissions: usize) -> bool {
        self.counts.get(cohort).copied().unwrap_or(0) < min_emissions
    }
}

// ─── Envelope readers ────────────────────────────────────────────────────────

fn envelope_str(att: &Attestation, key: &str) -> Option<String> {
    att.attestation_envelope
        .get(key)?
        .as_str()
        .map(str::to_string)
}

fn envelope_f64(att: &Attestation, key: &str) -> Option<f64> {
    att.attestation_envelope.get(key)?.as_f64()
}

/// CC 4.4.3.9 reads `affected_population_estimate` out of the attestation
/// `context`. CC 2.1 types `context` as free-form, so we read it as an object
/// when it is one and ignore it otherwise (a string `context` simply carries no
/// vulnerability estimate → no Policy D priority).
fn envelope_context_f64(att: &Attestation, key: &str) -> Option<f64> {
    att.attestation_envelope.get("context")?.get(key)?.as_f64()
}

fn envelope_context_str(att: &Attestation, key: &str) -> Option<String> {
    att.attestation_envelope
        .get("context")?
        .get(key)?
        .as_str()
        .map(str::to_string)
}

/// CC 3.1.9.3 structural safeguard: true iff `att` is backed ONLY by
/// `testimonial_witness:*` evidence.
///
/// Resolves the envelope's `evidence_refs[]` (attestation_ids) against the
/// corpus. A slashing row with resolvable evidence, ALL of which is
/// testimonial, is "sole testimonial evidence" and is refused. Evidence we
/// cannot resolve is not counted as exculpatory support for the row (we cannot
/// see it, so we cannot credit it) — but neither does its mere presence rescue
/// an otherwise all-testimonial base.
fn testimonial_sole_evidence(att: &Attestation, corpus: &[Attestation]) -> bool {
    let refs = match att.attestation_envelope.get("evidence_refs") {
        Some(serde_json::Value::Array(a)) => a,
        _ => return false, // no evidence_refs → this rule has nothing to say
    };
    let mut resolved = 0usize;
    let mut testimonial = 0usize;
    for r in refs {
        let Some(id) = r.as_str() else { continue };
        let Some(row) = corpus.iter().find(|a| a.attestation_id == id) else {
            continue;
        };
        resolved += 1;
        if envelope_str(row, paths::DIMENSION)
            .is_some_and(|d| d.starts_with(DIM_TESTIMONIAL_WITNESS))
        {
            testimonial += 1;
        }
    }
    resolved > 0 && resolved == testimonial
}

/// CC 3.1.6 (FSD-005 App.A:182) structural safeguard: true iff `att` is backed
/// ONLY by detector evidence (`detection:*` / `ratchet:flag:*`).
///
/// The exact SHAPE of [`testimonial_sole_evidence`] — the manifest names it as
/// *"same SHAPE as the testimonial screen"* — over the detector prefixes. A
/// slashing row with resolvable evidence, ALL of which is `detection:*` or
/// `ratchet:flag:*`, is "sole detector evidence" and is refused. Evidence we
/// cannot resolve is not counted as corroboration (we cannot see it), and its
/// mere presence does not rescue an otherwise all-detector base.
fn detector_sole_evidence(att: &Attestation, corpus: &[Attestation]) -> bool {
    let refs = match att.attestation_envelope.get("evidence_refs") {
        Some(serde_json::Value::Array(a)) => a,
        _ => return false, // no evidence_refs → this rule has nothing to say
    };
    let mut resolved = 0usize;
    let mut detector = 0usize;
    for r in refs {
        let Some(id) = r.as_str() else { continue };
        let Some(row) = corpus.iter().find(|a| a.attestation_id == id) else {
            continue;
        };
        resolved += 1;
        if envelope_str(row, paths::DIMENSION)
            .is_some_and(|d| d.starts_with(DIM_DETECTION) || d.starts_with(DIM_RATCHET_FLAG))
        {
            detector += 1;
        }
    }
    resolved > 0 && resolved == detector
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polarity_table_matches_cc_4_4_2() {
        assert_eq!(
            polarity_for("capacity:sustained_coherence:v1"),
            Polarity::Signed
        );
        assert_eq!(polarity_for("prohibited:weapons"), Polarity::NegativeOnly);
        assert_eq!(
            polarity_for("slashing:PROVEN_ROGUE"),
            Polarity::BooleanViaScore
        );
        assert_eq!(
            polarity_for("attestation:license_validity"),
            Polarity::BooleanViaScore
        );
        assert_eq!(
            polarity_for("need:witness:evidence"),
            Polarity::PositiveOnly
        );
        assert_eq!(polarity_for("cw_class:horror"), Polarity::Enumerated);
        assert_eq!(
            polarity_for("detection:correlated_action:x"),
            Polarity::Detector
        );
        assert_eq!(
            polarity_for("ratchet:flag:counter_rii:l1"),
            Polarity::Detector
        );
        // CC 3.4.8: a cross-attestation on the DISTINCT `truth_grounding:*`
        // prefix is NOT a detector emission — it is `signed`.
        assert_eq!(
            polarity_for("truth_grounding:detection:correlated_action:x"),
            Polarity::Signed
        );
        // CC 3.4.9 co-stewarded prefix is `signed` (CC 3.1 table).
        assert_eq!(polarity_for("licensure:CA_medical_board"), Polarity::Signed);
    }

    /// The six manifest arms that previously fell through to [`Polarity::Signed`]
    /// (the acknowledged GAP in `field_processor_matrix`). Each classification is
    /// pinned to the `invariant_registry` entry that settles it.
    #[test]
    fn polarity_arms_match_manifest_invariants() {
        // `revocation:{entity_type}:{reason}` — CC 3.1.1 / CC 1.13.2: `-1.0`-only,
        // non-rollbackable → NegativeOnly (min), NOT a signed mean.
        assert_eq!(
            polarity_for("revocation:partner:bond_forfeit"),
            Polarity::NegativeOnly,
        );
        // `benchmark:he300:{category}:{version}` — CC 3.1.10: *"MUST use
        // PositiveOnly max aggregation, never Signed mean."*
        assert_eq!(
            polarity_for("benchmark:he300:reasoning:v2"),
            Polarity::PositiveOnly,
        );
        // `judge_model:verdict:{model_id}` — CC 3.1.9.4 + CC 4.4.2:
        // *"boolean-via-score … Min across attesters … not mean."*
        assert_eq!(
            polarity_for("judge_model:verdict:claude-opus"),
            Polarity::BooleanViaScore,
        );
        // `partner_role:{role}` — CC 4.4.2: *"most-recent-by-signed_at …
        // mean/average composition FORBIDDEN."*
        assert_eq!(polarity_for("partner_role:reseller"), Polarity::Enumerated,);
        // `activity_tier:{period}` — CC 3.1.9.6 + CC 4.4.2: boolean-via-score,
        // *"MIN (any Below-Active trumps Active) — never a mean"* (verified live
        // drift: previously fell through to Signed).
        assert_eq!(
            polarity_for("activity_tier:monthly"),
            Polarity::BooleanViaScore,
        );
        // `credits:{domain}:{language}:{subject}` — CC 4.4.2: *"Positive-only
        // polarity composes via MAX across attesters, not sum/count"* (verified
        // live drift: previously fell through to Signed).
        assert_eq!(
            polarity_for("credits:medicine:en:cardiology"),
            Polarity::PositiveOnly,
        );
    }

    #[test]
    fn empty_trust_set_admits_nothing() {
        let t = TrustSet::new();
        assert!(t.is_empty());
        assert!(!t.contains("anyone"));
    }

    #[test]
    fn track_record_weight_is_monotone() {
        let mut counts = HashMap::new();
        counts.insert("serial-self".to_string(), (10usize, 0usize));
        counts.insert("balanced".to_string(), (1usize, 5usize));
        counts.insert("fresh".to_string(), (1usize, 0usize));
        let t = TrackRecord { counts };
        let serial = t.self_weight("serial-self");
        let balanced = t.self_weight("balanced");
        let fresh = t.self_weight("fresh");
        assert!(serial < fresh, "a serial self-attester decays: {serial}");
        assert!(
            fresh < balanced,
            "an external track record lifts: {balanced}"
        );
        assert!((fresh - 0.5).abs() < 1e-9, "a lone self-claim sits at 0.5");
        assert!(serial > 0.0, "attenuated, never silenced (CC 3.1.9.3)");
    }
}
