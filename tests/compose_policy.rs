//! Adversarial pins for the **CEG consumer-composition tier** (`src/compose_policy.rs`).
//!
//! These tests are the evidence behind this node's `CCC` (CEG-Conforming
//! Consumer) declaration. CC 4.4: *"A CEG-Conforming Consumer **MUST implement
//! at least Policy A**; the others are RECOMMENDED."* Each test names the CC
//! rule it pins and constructs the case an adversary would use to break it.
//!
//! The composition engine is pure over a `&[Attestation]` corpus, so every rule
//! is exercised directly — no substrate, no I/O, no fixture drift.

use chrono::{Duration, TimeZone, Utc};
use ciris_persist::federation::types::{attestation_type, Attestation};
use ciris_server::compose_policy::{
    polarity_for, CoSteward, Composer, Decision, Polarity, PolicyConfig, RefusalReason, TrustSet,
    WeightingOrder,
};
use serde_json::{json, Value};

// ─── Fixtures ────────────────────────────────────────────────────────────────

/// Build a `scores` attestation row. `extra` is merged into the CEG envelope so
/// a test can add `witness_relation`, `context`, `evidence_refs`, … exactly as
/// the wire would carry them.
fn att(
    id: &str,
    attester: &str,
    attested: &str,
    dimension: &str,
    score: f64,
    confidence: f64,
    extra: Value,
) -> Attestation {
    let mut envelope = json!({
        "dimension": dimension,
        "attestation_type": attestation_type::SCORES,
        "attesting_key_id": attester,
        "attested_key_id": attested,
        "score": score,
        "confidence": confidence,
    });
    if let (Some(dst), Some(src)) = (envelope.as_object_mut(), extra.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    // `asserted_at` is the CC 4.4.2 `signed_at` the `enumerated` polarity orders
    // by; the tests that care set it explicitly via `with_asserted_at`.
    Attestation {
        attestation_id: id.to_string(),
        attesting_key_id: attester.to_string(),
        attested_key_id: attested.to_string(),
        attestation_type: attestation_type::SCORES.to_string(),
        weight: Some(score),
        asserted_at: Utc.with_ymd_and_hms(2026, 7, 1, 0, 0, 0).unwrap(),
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: format!("hash-{id}"),
        scrub_signature_classical: "sig".to_string(),
        scrub_signature_pqc: Some("pqc".to_string()),
        scrub_key_id: attester.to_string(),
        scrub_timestamp: Utc.with_ymd_and_hms(2026, 7, 1, 0, 0, 0).unwrap(),
        pqc_completed_at: None,
        persist_row_hash: format!("row-{id}"),
        subject_key_ids: vec![attested.to_string()],
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_string(),
        tier: "federation".to_string(),
        promoted_at: None,
    }
}

/// A `witness_relation: self` envelope member (CC 2.1; default is `external`).
fn self_witness() -> Value {
    json!({ "witness_relation": "self" })
}

/// A `context` carrying the attester's cohort (CC 4.4.1 density) and/or the
/// CC 4.4.3.9 `affected_population_estimate`.
fn context(cohort: Option<&str>, affected: Option<f64>) -> Value {
    let mut ctx = serde_json::Map::new();
    if let Some(c) = cohort {
        ctx.insert("cohort_id".into(), json!(c));
    }
    if let Some(a) = affected {
        ctx.insert("affected_population_estimate".into(), json!(a));
    }
    json!({ "context": Value::Object(ctx) })
}

fn merge(a: Value, b: Value) -> Value {
    let mut out = a;
    if let (Some(dst), Some(src)) = (out.as_object_mut(), b.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    out
}

/// Deterministic `now` so `expires_at` tests never race the wall clock.
fn cfg() -> PolicyConfig {
    PolicyConfig {
        now: Some(Utc.with_ymd_and_hms(2026, 7, 12, 0, 0, 0).unwrap()),
        ..Default::default()
    }
}

// ─── CC 4.4.3.8 — Policy A: direct trust ─────────────────────────────────────

/// **CC 4.4.3.8**: *"Consumer trusts an attestation if `attesting_key_id` is in
/// the consumer's pinned trust set (canonical bootstraps + consumer-added
/// pins)."*
///
/// The adversarial half is the SECOND assertion: an attester OUTSIDE the pinned
/// set must be REFUSED, and must not leak into the verdict at any weight.
#[test]
fn policy_a_admits_the_pinned_trust_set_and_refuses_everything_else() {
    let mut trust = TrustSet::new();
    trust.pin("accord-holder-1");
    let composer = Composer::new(trust).with_config(cfg());

    let corpus = vec![
        att(
            "a1",
            "accord-holder-1",
            "agent-x",
            "capacity:sustained_coherence:v1",
            0.8,
            1.0,
            json!({}),
        ),
        // The adversary: an unpinned key emitting a maximally-favourable score.
        att(
            "a2",
            "rogue-key",
            "agent-x",
            "capacity:sustained_coherence:v1",
            1.0,
            1.0,
            json!({}),
        ),
    ];

    let out = composer.compose(&corpus);
    let v = out
        .verdict("capacity:sustained_coherence:v1", "agent-x")
        .expect("verdict");

    assert_eq!(
        v.contributions.len(),
        1,
        "only the pinned attester composes"
    );
    assert_eq!(v.contributions[0].attesting_key_id, "accord-holder-1");
    assert!(
        (v.value - 0.8).abs() < 1e-9,
        "the rogue 1.0 must not pull the mean: {}",
        v.value
    );
    assert_eq!(v.decision, Decision::Affirm);

    // Fail-closed: the refusal is TYPED and VISIBLE, not a silent drop.
    let refusal = out
        .refusals
        .iter()
        .find(|r| r.attestation_id == "a2")
        .expect("the unpinned attestation is refused, not silently ignored");
    assert_eq!(refusal.reason, RefusalReason::NotInTrustSet);
}

/// Fail-closed: a tuple whose ONLY attestations are unresolvable against the
/// trust set composes to [`Decision::Undetermined`] — NOT to a passing zero and
/// NOT to an absent verdict the caller could mistake for "nothing to see".
#[test]
fn an_unresolvable_attestation_does_not_silently_pass() {
    let mut trust = TrustSet::new();
    trust.pin("accord-holder-1");
    let composer = Composer::new(trust).with_config(cfg());

    let corpus = vec![att(
        "a1",
        "rogue-key",
        "agent-x",
        "attestation:license_validity",
        1.0,
        1.0,
        json!({}),
    )];

    let out = composer.compose(&corpus);
    let v = out
        .verdict("attestation:license_validity", "agent-x")
        .expect("an Undetermined verdict is still emitted — visibly undecided");
    assert_eq!(v.decision, Decision::Undetermined);
    assert!(v.contributions.is_empty());
    assert_eq!(v.confidence, 0.0);
    assert_ne!(v.decision, Decision::Affirm, "MUST NOT pass");
}

/// CC 3.4.5 anti-Goodhart, re-checked consumer-side per CC 3.4.7 (*"Trust does
/// not propagate … the consumer's re-check is the second [line of defense]"*).
/// A peer substrate that admitted a self-`capacity:*` score is not believed.
#[test]
fn capacity_self_emission_is_refused_even_from_a_pinned_key() {
    let mut trust = TrustSet::new();
    trust.pin("agent-x");
    let composer = Composer::new(trust).with_config(cfg());

    let corpus = vec![att(
        "a1",
        "agent-x",
        "agent-x",
        "capacity:composite",
        1.0,
        1.0,
        json!({}),
    )];
    let out = composer.compose(&corpus);
    assert_eq!(out.refusals[0].reason, RefusalReason::SelfEmission);
    assert_eq!(
        out.verdict("capacity:composite", "agent-x")
            .unwrap()
            .decision,
        Decision::Undetermined
    );
}

/// CC 2.1 marks `confidence` REQUIRED. A missing one is malformed — we do NOT
/// default it to 1.0, which would hand an attester full confidence for free.
#[test]
fn a_missing_required_confidence_is_malformed_not_a_free_1_0() {
    let mut trust = TrustSet::new();
    trust.pin("steward-1");
    let composer = Composer::new(trust).with_config(cfg());

    let mut a = att(
        "a1",
        "steward-1",
        "agent-x",
        "vote:contrib-1",
        1.0,
        1.0,
        json!({}),
    );
    a.attestation_envelope
        .as_object_mut()
        .unwrap()
        .remove("confidence");

    let out = composer.compose(&[a]);
    assert!(matches!(
        out.refusals[0].reason,
        RefusalReason::MalformedEnvelope(_)
    ));
    assert_eq!(
        out.verdict("vote:contrib-1", "agent-x").unwrap().decision,
        Decision::Undetermined
    );
}

/// CC 2.1 `valid_until` / the row's `expires_at`: a stale attestation does not
/// compose.
#[test]
fn an_expired_attestation_is_refused() {
    let mut trust = TrustSet::new();
    trust.pin("steward-1");
    let composer = Composer::new(trust).with_config(cfg());

    let mut a = att(
        "a1",
        "steward-1",
        "agent-x",
        "vote:contrib-1",
        1.0,
        1.0,
        json!({}),
    );
    a.expires_at = Some(cfg().now.unwrap() - Duration::days(1));

    let out = composer.compose(&[a]);
    assert_eq!(out.refusals[0].reason, RefusalReason::Expired);
}

// ─── CC 3.4.9 — the co-stewarded `licensure:*` single-source cap ─────────────

/// **CC 3.4.9**: *"`licensure:{authority_id}` is co-stewarded between
/// CIRISRegistry and CIRISVerify — both MAY emit; consumers compose.
/// **Single-source attestations** (only one of the two co-stewards has emitted)
/// **MUST be marked as `confidence ≤ 0.5` in consumer composition** until the
/// second co-steward's attestation arrives."*
///
/// Persist deliberately defers this to the consumer
/// (`src/federation/admission.rs`), so this test is the only thing standing
/// between us and a single co-steward minting full-confidence licensure.
#[test]
fn cc_3_4_9_single_source_licensure_cannot_reach_full_confidence() {
    let mut trust = TrustSet::new();
    trust.pin_co_steward("registry-steward-1", CoSteward::Registry);
    trust.pin_co_steward("verify-steward-1", CoSteward::Verify);
    let composer = Composer::new(trust).with_config(cfg());

    // ── Single-source: ONLY the Registry co-steward has emitted, and it claims
    // maximal confidence. The cap MUST bite.
    let single = vec![att(
        "l1",
        "registry-steward-1",
        "doctor-key",
        "licensure:CA_medical_board",
        1.0,
        1.0,
        json!({}),
    )];
    let v = composer.compose(&single);
    let v = v
        .verdict("licensure:CA_medical_board", "doctor-key")
        .unwrap();

    assert!(v.single_source_licensure, "CC 3.4.9 cap must be flagged");
    assert!(
        v.confidence <= 0.5,
        "CC 3.4.9: single-source MUST be confidence ≤ 0.5, got {}",
        v.confidence
    );
    assert!(
        v.contributions[0].licensure_capped && (v.contributions[0].confidence - 0.5).abs() < 1e-9,
        "the cap is applied to the row's confidence BEFORE aggregation"
    );
    assert!(
        v.value < 1.0,
        "a single source MUST NOT reach full confidence: {}",
        v.value
    );
    let single_value = v.value;

    // ── The second CO-STEWARD arrives → the cap lifts.
    let both = vec![
        att(
            "l1",
            "registry-steward-1",
            "doctor-key",
            "licensure:CA_medical_board",
            1.0,
            1.0,
            json!({}),
        ),
        att(
            "l2",
            "verify-steward-1",
            "doctor-key",
            "licensure:CA_medical_board",
            1.0,
            1.0,
            json!({}),
        ),
    ];
    let v = composer.compose(&both);
    let v = v
        .verdict("licensure:CA_medical_board", "doctor-key")
        .unwrap();

    assert!(!v.single_source_licensure, "two co-stewards → no cap");
    assert!(
        (v.confidence - 1.0).abs() < 1e-9,
        "the second co-steward's arrival lifts the cap: {}",
        v.confidence
    );
    assert!(
        v.value > single_value,
        "the lifted verdict must dominate the capped one: {} vs {single_value}",
        v.value
    );
    assert!((v.value - 1.0).abs() < 1e-9);
}

/// The adversarial sharpening: CC 3.4.9 names **two co-stewards**
/// (institutions), not two keys. A single co-steward operating two keys — or a
/// pinned key that is no co-steward at all — MUST NOT lift the cap.
#[test]
fn cc_3_4_9_two_keys_of_the_same_co_steward_do_not_lift_the_cap() {
    let mut trust = TrustSet::new();
    trust.pin_co_steward("registry-steward-1", CoSteward::Registry);
    trust.pin_co_steward("registry-steward-2", CoSteward::Registry);
    trust.pin("random-pinned-peer"); // pinned, but NOT a co-steward
    let composer = Composer::new(trust).with_config(cfg());

    let corpus = vec![
        att(
            "l1",
            "registry-steward-1",
            "doctor-key",
            "licensure:CA_medical_board",
            1.0,
            1.0,
            json!({}),
        ),
        att(
            "l2",
            "registry-steward-2",
            "doctor-key",
            "licensure:CA_medical_board",
            1.0,
            1.0,
            json!({}),
        ),
        att(
            "l3",
            "random-pinned-peer",
            "doctor-key",
            "licensure:CA_medical_board",
            1.0,
            1.0,
            json!({}),
        ),
    ];
    let v = composer.compose(&corpus);
    let v = v
        .verdict("licensure:CA_medical_board", "doctor-key")
        .unwrap();

    assert!(
        v.single_source_licensure,
        "3 keys, ONE co-steward class → still single-source"
    );
    assert!(v.confidence <= 0.5, "still capped: {}", v.confidence);
    assert!(v.contributions.iter().all(|c| c.licensure_capped));
}

// ─── CC 4.4.1 — Frickerian discipline ────────────────────────────────────────

/// **CC 4.4.1 bullet 1**: *"Don't downweight `testimonial_witness:*` from
/// cohorts with low overall attestation density (testimonial preservation is
/// precisely what corrects for that low density)."*
///
/// THE epistemic-injustice case. The control row proves the consumer DOES apply
/// a low-density downweight in general — so the testimonial row's exemption is a
/// real, load-bearing difference, not a vacuous "we never downweight anything".
#[test]
fn cc_4_4_1_testimonial_witness_from_a_low_density_cohort_is_not_downweighted() {
    let mut trust = TrustSet::new();
    trust.pin("village-witness");
    let composer = Composer::new(trust).with_config(cfg());

    // The cohort has 2 attestations total — below the default density floor (3).
    let ctx = context(Some("small-village"), None);
    let corpus = vec![
        // PROTECTED — the affected party's singular narrative (CC 3.1.9.3
        // discipline: `witness_relation: self`).
        att(
            "t1",
            "village-witness",
            "polluter-corp",
            "testimonial_witness:environmental_harm",
            1.0,
            1.0,
            merge(self_witness(), ctx.clone()),
        ),
        // CONTROL — same attester, same low-density cohort, same
        // witness_relation, but an UNPROTECTED dimension.
        att(
            "c1",
            "village-witness",
            "polluter-corp",
            "vote:contrib-1",
            1.0,
            1.0,
            merge(self_witness(), ctx),
        ),
    ];

    let out = composer.compose(&corpus);
    let testimonial = out
        .verdict("testimonial_witness:environmental_harm", "polluter-corp")
        .unwrap();
    let control = out.verdict("vote:contrib-1", "polluter-corp").unwrap();

    assert!(
        !testimonial.contributions[0].low_density_applied,
        "CC 4.4.1: a low-density cohort's testimonial MUST NOT be downweighted"
    );
    assert!(
        control.contributions[0].low_density_applied,
        "the control PROVES the consumer downweights low-density cohorts in general"
    );
    assert!(
        testimonial.contributions[0].weight > control.contributions[0].weight,
        "the protected row must carry strictly more weight than the identical \
         unprotected one: {} vs {}",
        testimonial.contributions[0].weight,
        control.contributions[0].weight
    );
    // …and the structural safeguard STILL applied to the protected row (both
    // rows are `witness_relation: self` → both carry the CC 3.4.7 track-record
    // weight). Exemption from the Frickerian downweight is not immunity.
    assert!(testimonial.contributions[0].self_track_record_applied);
    assert!(
        testimonial.contributions[0].weight < 1.0,
        "protected ≠ unweighted — CC 3.4.7 still bites: {}",
        testimonial.contributions[0].weight
    );
}

/// **CC 4.4.1 bullet 2**: *"Don't downweight `non_maleficence:*` claims about a
/// partner just because the partner has a long `partner_role:*` track record
/// (the long track record may be the harm)."*
#[test]
fn cc_4_4_1_non_maleficence_is_not_downweighted() {
    let mut trust = TrustSet::new();
    trust.pin("lone-reporter");
    let composer = Composer::new(trust).with_config(cfg());

    let ctx = context(Some("tiny-cohort"), None);
    let corpus = vec![
        att(
            "n1",
            "lone-reporter",
            "long-standing-partner",
            "non_maleficence:physical_harm",
            -1.0,
            1.0,
            ctx.clone(),
        ),
        att(
            "c1",
            "lone-reporter",
            "long-standing-partner",
            "vote:contrib-9",
            -1.0,
            1.0,
            ctx,
        ),
    ];

    let out = composer.compose(&corpus);
    let harm = out
        .verdict("non_maleficence:physical_harm", "long-standing-partner")
        .unwrap();
    let control = out
        .verdict("vote:contrib-9", "long-standing-partner")
        .unwrap();

    assert!(!harm.contributions[0].low_density_applied);
    assert!(control.contributions[0].low_density_applied);
    assert!(
        (harm.contributions[0].weight - 1.0).abs() < 1e-9,
        "an external-witness non_maleficence claim composes at full weight: {}",
        harm.contributions[0].weight
    );
    assert!(
        harm.value < control.value,
        "the harm claim must land HARDER (more negative) than the downweighted \
         control: {} vs {}",
        harm.value,
        control.value
    );
    assert_eq!(harm.decision, Decision::Deny);
}

// ─── CC 4.4.3.9 — Policy D, lexical-vulnerability-priority ───────────────────

/// **CC 4.4.3.9**: *"When two otherwise-equivalent attestations conflict, defer
/// to whichever attestation names the more-affected cohort — measured by
/// `affected_population_estimate` in the attestation `context`, weighted
/// inversely (smaller = more vulnerable, more weight). Inverts the default
/// popularity-weighted aggregation specifically for ties."*
#[test]
fn cc_4_4_3_9_lexical_vulnerability_priority_decides_the_tie() {
    let mut trust = TrustSet::new();
    trust.pin("big-cohort-attester");
    trust.pin("small-cohort-attester");
    let composer = Composer::new(trust).with_config(cfg());

    // A perfect conflict: equal magnitude, opposite sign, equal weight. The
    // default popularity-weighted mean says exactly nothing (0.0).
    let corpus = vec![
        att(
            "b1",
            "big-cohort-attester",
            "policy-x",
            "truth_grounding:displacement",
            0.8,
            1.0,
            context(None, Some(5_000_000.0)),
        ),
        att(
            "s1",
            "small-cohort-attester",
            "policy-x",
            "truth_grounding:displacement",
            -0.8,
            1.0,
            context(None, Some(40.0)),
        ),
    ];

    let v = composer.compose(&corpus);
    let v = v
        .verdict("truth_grounding:displacement", "policy-x")
        .unwrap();

    assert!(
        v.lexical_tie_break_applied,
        "the 0.0 mean IS the tie CC 4.4.3.9 exists for"
    );
    assert!(
        v.value < 0.0,
        "the 40-person cohort's attestation wins the tie, not the 5M one: {}",
        v.value
    );
    assert_eq!(v.decision, Decision::Deny);
}

/// The cheap exploit CC 4.4.3.9 must not reward: OMIT the
/// `affected_population_estimate` and claim the tie by default. An attestation
/// that names no cohort size cannot claim vulnerability priority.
#[test]
fn cc_4_4_3_9_omitting_the_population_estimate_does_not_win_the_tie() {
    let mut trust = TrustSet::new();
    trust.pin("silent-attester");
    trust.pin("named-attester");
    let composer = Composer::new(trust).with_config(cfg());

    let corpus = vec![
        // No `context` at all — declines to name a cohort.
        att(
            "q1",
            "silent-attester",
            "policy-x",
            "truth_grounding:displacement",
            0.8,
            1.0,
            json!({}),
        ),
        att(
            "q2",
            "named-attester",
            "policy-x",
            "truth_grounding:displacement",
            -0.8,
            1.0,
            context(None, Some(900_000.0)),
        ),
    ];

    let v = composer.compose(&corpus);
    let v = v
        .verdict("truth_grounding:displacement", "policy-x")
        .unwrap();
    assert!(v.lexical_tie_break_applied);
    assert!(
        v.value < 0.0,
        "the attestation that NAMES a cohort beats the one that names none: {}",
        v.value
    );
}

// ─── CC 4.4.1 — the ORDERING (structural safeguards, THEN Frickerian) ────────

/// **CC 4.4.1 adversarial caveat** — the ordering rule, and the reason this
/// whole module has an explicit [`WeightingOrder`]:
///
/// > *"an adversary can emit `testimonial_witness:victim_of_my_competitor`
/// > exploiting the Frickerian non-downweighting rule. Per CC 3.1.9.3,
/// > `testimonial_witness:*` is never sole evidence for `slashing:*`; per
/// > CC 3.4.7 the consumer MUST also weight `witness_relation: self` claims
/// > against the attester's other-emission track record. **The Frickerian rule
/// > applies AFTER these structural safeguards, not before them.**"*
///
/// This is the case where the two orders DIVERGE — not just in magnitude, but
/// in the verdict itself. The adversary is a serial self-attester who has never
/// witnessed anything external; the CC-mandated order attenuates them via the
/// CC 3.4.7 track record BEFORE the Frickerian exemption can protect them, and
/// the composition DENIES. Run Frickerian-first and the exemption short-circuits
/// the safeguard, the row composes at full weight, and the composition AFFIRMS
/// the smear.
#[test]
fn cc_4_4_1_structural_safeguards_run_before_the_frickerian_rule() {
    let mut trust = TrustSet::new();
    // Worst case: the adversary is INSIDE the trust set. Policy A alone does
    // not save us here — only the ordering does.
    trust.pin("adversary-1");
    let corpus = adversarial_smear_corpus();

    let conformant = Composer::new(trust.clone()).with_config(PolicyConfig {
        threshold: 0.5,
        order: WeightingOrder::StructuralThenFrickerian,
        ..cfg()
    });
    let wrong_order = Composer::new(trust).with_config(PolicyConfig {
        threshold: 0.5,
        order: WeightingOrder::FrickerianFirst,
        ..cfg()
    });

    let good = conformant.compose(&corpus);
    let good = good
        .verdict("testimonial_witness:victim_of_my_competitor", "competitor")
        .unwrap();
    let bad = wrong_order.compose(&corpus);
    let bad = bad
        .verdict("testimonial_witness:victim_of_my_competitor", "competitor")
        .unwrap();

    // 1. The two ORDERS give different answers — the ordering is load-bearing,
    //    not decorative.
    assert!(
        good.value < bad.value,
        "structural-first must attenuate what Frickerian-first waves through: \
         {} vs {}",
        good.value,
        bad.value
    );
    assert!(
        good.contributions[0].self_track_record_applied,
        "CC 3.4.7 track-record weighting MUST have run on the protected row"
    );
    assert!(
        !bad.contributions[0].self_track_record_applied,
        "the non-conformant order skips the safeguard — that is the bug CC 4.4.1 closes"
    );

    // 2. And they give different VERDICTS at the same threshold. The smear is
    //    denied under the CC ordering and affirmed under the forbidden one.
    assert_eq!(
        good.decision,
        Decision::Deny,
        "CC-conformant: the serial self-attester's smear does not clear 0.5"
    );
    assert_eq!(
        bad.decision,
        Decision::Affirm,
        "Frickerian-first: the smear clears — exactly the exploit the caveat names"
    );

    // 3. The Frickerian rule STILL did its job under the correct order: the
    //    protected row was never hit by the cohort-density downweight. The
    //    safeguard attenuates the SELF-attestation; it does not resurrect the
    //    identity prejudice CC 4.4.1 forbids.
    assert!(!good.contributions[0].low_density_applied);
}

/// The adversary of the CC 4.4.1 caveat: a pinned key with a long
/// `witness_relation: self` emission history and ZERO external witnessing,
/// smearing a competitor via `testimonial_witness:*`, from a cohort of one.
fn adversarial_smear_corpus() -> Vec<Attestation> {
    let ctx = context(Some("adversary-cohort"), None);
    let mut corpus = vec![att(
        "smear",
        "adversary-1",
        "competitor",
        "testimonial_witness:victim_of_my_competitor",
        0.9,
        1.0,
        merge(self_witness(), ctx.clone()),
    )];
    // Four more self-claims, no external witnessing at all → the CC 3.4.7
    // "other-emission track record" is empty.
    for i in 0..4 {
        corpus.push(att(
            &format!("self-{i}"),
            "adversary-1",
            "adversary-1",
            &format!("truth_grounding:self_puffery_{i}"),
            1.0,
            1.0,
            merge(self_witness(), ctx.clone()),
        ));
    }
    corpus
}

/// **CC 3.1.9.3** (the OTHER structural safeguard the CC 4.4.1 caveat defers
/// to): *"`testimonial_witness:*` … never sole evidence for `slashing:*`"*.
///
/// This one is a SCREEN, not a weight — a slashing row whose entire resolvable
/// evidence base is testimonial does not contribute at ANY weight, so no
/// Frickerian consideration can revive it. That is the ordering, enforced
/// structurally.
#[test]
fn cc_3_1_9_3_testimonial_witness_is_never_sole_evidence_for_slashing() {
    let mut trust = TrustSet::new();
    trust.pin("adjudicator");
    trust.pin("witness-1");
    let composer = Composer::new(trust).with_config(cfg());

    let testimonial = att(
        "t1",
        "witness-1",
        "accused",
        "testimonial_witness:harm",
        1.0,
        1.0,
        self_witness(),
    );

    // Sole evidence = the testimonial row → REFUSED.
    let sole = vec![
        testimonial.clone(),
        att(
            "s1",
            "adjudicator",
            "accused",
            "slashing:PROVEN_ROGUE",
            1.0,
            1.0,
            json!({ "evidence_refs": ["t1"] }),
        ),
    ];
    let out = composer.compose(&sole);
    assert!(
        out.refusals.iter().any(|r| r.attestation_id == "s1"
            && r.reason == RefusalReason::TestimonialSoleEvidenceForSlashing),
        "a slashing row backed ONLY by testimony must be refused"
    );
    assert_eq!(
        out.verdict("slashing:PROVEN_ROGUE", "accused")
            .unwrap()
            .decision,
        Decision::Undetermined,
        "and the slashing verdict must not stand"
    );

    // Add ONE non-testimonial corroborating row → the safeguard is satisfied and
    // the slashing composes. (The narrative is preserved either way — CC 3.1.9.3
    // attenuates its *sufficiency*, never its *existence*.)
    let corroborated = vec![
        testimonial,
        att(
            "d1",
            "adjudicator",
            "accused",
            "truth_grounding:forensics",
            1.0,
            1.0,
            json!({}),
        ),
        att(
            "s1",
            "adjudicator",
            "accused",
            "slashing:PROVEN_ROGUE",
            1.0,
            1.0,
            json!({ "evidence_refs": ["t1", "d1"] }),
        ),
    ];
    let out = composer.compose(&corroborated);
    assert!(out.refusals.is_empty(), "{:?}", out.refusals);
    assert_eq!(
        out.verdict("slashing:PROVEN_ROGUE", "accused")
            .unwrap()
            .decision,
        Decision::Affirm
    );
}

// ─── CC 4.4.2 — polarity-keyed aggregation defaults ──────────────────────────

/// **CC 4.4.2**: `boolean-via-score` → *"**Min** (any negative trumps positive —
/// fail-secure for hard constraints like `prohibited:*`, `attestation:l*`)"*.
///
/// The adversarial shape: NINE positives and ONE negative. A mean would wave it
/// through; the fail-secure min must not.
#[test]
fn cc_4_4_2_boolean_via_score_is_min_any_negative_trumps() {
    let mut trust = TrustSet::new();
    let mut corpus = Vec::new();
    for i in 0..9 {
        let k = format!("booster-{i}");
        trust.pin(&k);
        corpus.push(att(
            &format!("p{i}"),
            &k,
            "subject",
            "attestation:license_validity",
            1.0,
            1.0,
            json!({}),
        ));
    }
    trust.pin("dissenter");
    corpus.push(att(
        "neg",
        "dissenter",
        "subject",
        "attestation:license_validity",
        -1.0,
        1.0,
        json!({}),
    ));

    let composer = Composer::new(trust).with_config(cfg());
    let v = composer.compose(&corpus);
    let v = v
        .verdict("attestation:license_validity", "subject")
        .unwrap();

    assert_eq!(v.polarity, Polarity::BooleanViaScore);
    assert!(
        (v.value + 1.0).abs() < 1e-9,
        "one negative trumps nine positives (fail-secure): {}",
        v.value
    );
    assert_eq!(v.decision, Decision::Deny);
}

/// CC 4.4.2 detector row: *"**Median** across attesters (resists adversarial
/// mean-pulling by a single captured detector)"*. One captured detector screams
/// `+1.0`; the median holds.
#[test]
fn cc_4_4_2_detector_dimensions_median_resists_a_captured_detector() {
    let mut trust = TrustSet::new();
    let mut corpus = Vec::new();
    for (i, s) in [(0, 0.0_f64), (1, 0.0), (2, 0.0), (3, 0.1), (4, 1.0)] {
        let k = format!("detector-{i}");
        trust.pin(&k);
        corpus.push(att(
            &format!("d{i}"),
            &k,
            "subject",
            "detection:correlated_action:pricing",
            s,
            1.0,
            json!({}),
        ));
    }

    let composer = Composer::new(trust).with_config(cfg());
    let v = composer.compose(&corpus);
    let v = v
        .verdict("detection:correlated_action:pricing", "subject")
        .unwrap();

    assert_eq!(v.polarity, Polarity::Detector);
    assert!(
        (v.value - 0.0).abs() < 1e-9,
        "median of [0,0,0,0.1,1.0] is 0.0 — the captured detector cannot pull it: {}",
        v.value
    );
}

/// CC 4.4.2 `positive-only` → *"**Max** across attesters (any positive is
/// conclusive)"*.
#[test]
fn cc_4_4_2_positive_only_is_max() {
    let mut trust = TrustSet::new();
    trust.pin("a").pin("b");
    let composer = Composer::new(trust).with_config(cfg());
    let corpus = vec![
        att(
            "n1",
            "a",
            "subject",
            "need:witness:evidence",
            0.0,
            1.0,
            json!({}),
        ),
        att(
            "n2",
            "b",
            "subject",
            "need:witness:evidence",
            1.0,
            1.0,
            json!({}),
        ),
    ];
    let v = composer.compose(&corpus);
    let v = v.verdict("need:witness:evidence", "subject").unwrap();
    assert_eq!(v.polarity, Polarity::PositiveOnly);
    assert!((v.value - 1.0).abs() < 1e-9, "{}", v.value);
}

/// The polarity table itself (CC 4.4.2 × the CC 3.1 polarity column).
#[test]
fn cc_4_4_2_polarity_table() {
    assert_eq!(polarity_for("capacity:core_identity"), Polarity::Signed);
    assert_eq!(polarity_for("licensure:CA_medical_board"), Polarity::Signed);
    assert_eq!(polarity_for("prohibited:weapons"), Polarity::NegativeOnly);
    assert_eq!(
        polarity_for("slashing:PROVEN_ROGUE"),
        Polarity::BooleanViaScore
    );
    assert_eq!(polarity_for("need:mentor:x"), Polarity::PositiveOnly);
    assert_eq!(polarity_for("cw_class:medical"), Polarity::Enumerated);
    assert_eq!(
        polarity_for("ratchet:flag:counter_rii:l2"),
        Polarity::Detector
    );
}
