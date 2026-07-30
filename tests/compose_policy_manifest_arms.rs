//! Manifest-arm pins for the **CEG consumer-composition tier**
//! (`src/compose_policy.rs`), added for the v0.3.0 `namespace_supersets.json`
//! adoption cut (CIRISServer#325 / #327).
//!
//! These exercise the `field_processor_matrix` rows whose processor is
//! `compose_policy.rs` and whose family arm previously fell through to the
//! generic [`Polarity::Signed`] mean (the acknowledged GAP), plus the
//! `slashing:*` sole-evidence sibling screen the manifest names *"same SHAPE as
//! the testimonial screen"*. Each test names the CC rule + the
//! `invariant_registry` primitive_constraint it pins and constructs the
//! adversarial corpus a signed-mean would mis-compose.
//!
//! The composition engine is pure over a `&[Attestation]` corpus, so every rule
//! is exercised directly — no substrate, no I/O.

use chrono::{TimeZone, Utc};
use ciris_persist::federation::types::{attestation_type, Attestation};
use ciris_server::compose_policy::{
    Composer, Decision, Polarity, PolicyConfig, RefusalReason, TrustSet,
};
use serde_json::{json, Value};

// ─── Fixtures (mirrors tests/compose_policy.rs) ──────────────────────────────

/// Build a `scores` attestation row. `extra` is merged into the CEG envelope.
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

/// Deterministic `now` so `expires_at` staleness never races the wall clock.
fn cfg() -> PolicyConfig {
    PolicyConfig {
        now: Some(Utc.with_ymd_and_hms(2026, 7, 12, 0, 0, 0).unwrap()),
        ..Default::default()
    }
}

fn approx(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

// ─── polarity_for arm: revocation:* → NegativeOnly (CC 3.1.1 / CC 1.13.2) ─────

/// **`revocation:{entity_type}:{reason}`** — `invariant_registry`: *"defeating
/// the -1-only/non-rollbackable polarity"*; a `revocation:*` claim MUST compose
/// as `-1.0`-only (NegativeOnly / min), NOT be averaged into a signed mean.
///
/// Adversarial shape: a live `-1.0` revocation and a spurious `+1.0` emission on
/// the SAME (dimension, key). A signed mean folds them to `0.0` — the revocation
/// erased. The fail-secure min keeps it at `-1.0`.
#[test]
fn revocation_is_negative_only_not_averaged() {
    let mut trust = TrustSet::new();
    trust.pin("registry-steward");
    trust.pin("adversary");
    let composer = Composer::new(trust).with_config(cfg());

    let corpus = vec![
        att(
            "rev",
            "registry-steward",
            "partner-x",
            "revocation:partner:bond_forfeit",
            -1.0,
            1.0,
            json!({}),
        ),
        // The adversary tries to dilute the revocation with a positive.
        att(
            "puff",
            "adversary",
            "partner-x",
            "revocation:partner:bond_forfeit",
            1.0,
            1.0,
            json!({}),
        ),
    ];
    let out = composer.compose(&corpus);
    let v = out
        .verdict("revocation:partner:bond_forfeit", "partner-x")
        .expect("verdict");
    assert_eq!(v.polarity, Polarity::NegativeOnly);
    assert!(
        approx(v.value, -1.0),
        "revocation must stand at -1.0 (min), not be averaged to {} (a signed mean would give 0.0)",
        v.value
    );
    assert_eq!(v.decision, Decision::Deny);
}

// ─── polarity_for arm: benchmark:he300:* → PositiveOnly (CC 3.1.10) ───────────

/// **`benchmark:he300:{category}:{version}`** — `invariant_registry`:
/// *"composition MUST use PositiveOnly max aggregation, never Signed mean; no
/// negative value valid."*
///
/// Adversarial shape: a high run (`0.9`) and a low run (`0.3`). A signed mean
/// drags the validated capability down to `0.6`; the max reports the best
/// attested score, `0.9`.
#[test]
fn benchmark_he300_is_positive_only_max_not_mean() {
    let mut trust = TrustSet::new();
    trust.pin("bench-a");
    trust.pin("bench-b");
    let composer = Composer::new(trust).with_config(cfg());

    let corpus = vec![
        att(
            "hi",
            "bench-a",
            "agent-x",
            "benchmark:he300:reasoning:v2",
            0.9,
            1.0,
            json!({}),
        ),
        att(
            "lo",
            "bench-b",
            "agent-x",
            "benchmark:he300:reasoning:v2",
            0.3,
            1.0,
            json!({}),
        ),
    ];
    let out = composer.compose(&corpus);
    let v = out
        .verdict("benchmark:he300:reasoning:v2", "agent-x")
        .expect("verdict");
    assert_eq!(v.polarity, Polarity::PositiveOnly);
    assert!(
        approx(v.value, 0.9),
        "benchmark must be max (0.9), not a mean (0.6); got {}",
        v.value
    );
    assert_eq!(v.decision, Decision::Affirm);
}

// ─── polarity_for arm: judge_model:* → BooleanViaScore (CC 3.1.9.4) ───────────

/// **`judge_model:verdict:{model_id}`** — `invariant_registry`:
/// *"boolean-via-score polarity: default aggregation is Min across attesters …
/// any FAIL trumps PASS; not mean."*
///
/// Adversarial shape: nine PASS (`+1.0`) verdicts and one FAIL (`-1.0`). A mean
/// (`+0.8`) waves the FAIL away; an open-vocabulary `model_id` string could mint
/// that fake multi-model agreement from one key. The fail-secure min holds the
/// FAIL at `-1.0`.
#[test]
fn judge_model_is_boolean_via_score_min_any_fail_trumps() {
    let mut trust = TrustSet::new();
    let mut corpus = Vec::new();
    for i in 0..9 {
        let k = format!("pass-judge-{i}");
        trust.pin(&k);
        corpus.push(att(
            &format!("p{i}"),
            &k,
            "agent-x",
            "judge_model:verdict:model-consensus",
            1.0,
            1.0,
            json!({}),
        ));
    }
    trust.pin("fail-judge");
    corpus.push(att(
        "f0",
        "fail-judge",
        "agent-x",
        "judge_model:verdict:model-consensus",
        -1.0,
        1.0,
        json!({}),
    ));

    let composer = Composer::new(trust).with_config(cfg());
    let out = composer.compose(&corpus);
    let v = out
        .verdict("judge_model:verdict:model-consensus", "agent-x")
        .expect("verdict");
    assert_eq!(v.polarity, Polarity::BooleanViaScore);
    assert!(
        approx(v.value, -1.0),
        "one FAIL must trump nine PASS (min = -1.0), not a mean (+0.8); got {}",
        v.value
    );
    assert_eq!(v.decision, Decision::Deny);
}

// ─── polarity_for arm: partner_role:* → Enumerated (CC 4.4.2) ─────────────────

/// **`partner_role:{role}`** — `invariant_registry`: *"Enumerated-polarity
/// dimensions (incl. partner_role) compose by most-recent-by-signed_at from
/// authorized attesters — mean/average composition FORBIDDEN."*
///
/// Adversarial shape: an OLD role attestation (`+1.0`, asserted earlier) and a
/// NEWER one (`+0.2`, asserted later). Enumerated resolves to the most-recent
/// (`0.2`), which distinguishes it from BOTH a mean (`0.6`) and a max (`1.0`).
#[test]
fn partner_role_is_enumerated_most_recent_not_mean() {
    let mut trust = TrustSet::new();
    trust.pin("registry");
    let composer = Composer::new(trust).with_config(cfg());

    let mut old = att(
        "old",
        "registry",
        "partner-x",
        "partner_role:reseller",
        1.0,
        1.0,
        json!({}),
    );
    old.asserted_at = Utc.with_ymd_and_hms(2026, 7, 1, 0, 0, 0).unwrap();
    let mut new = att(
        "new",
        "registry",
        "partner-x",
        "partner_role:reseller",
        0.2,
        1.0,
        json!({}),
    );
    new.asserted_at = Utc.with_ymd_and_hms(2026, 7, 10, 0, 0, 0).unwrap();

    let out = composer.compose(&[old, new]);
    let v = out
        .verdict("partner_role:reseller", "partner-x")
        .expect("verdict");
    assert_eq!(v.polarity, Polarity::Enumerated);
    assert!(
        approx(v.value, 0.2),
        "most-recent role wins (0.2), not a mean (0.6) or max (1.0); got {}",
        v.value
    );
}

// ─── polarity_for arm: activity_tier:* → BooleanViaScore (CC 3.1.9.6) ─────────

/// **`activity_tier:{period}`** — `invariant_registry`: *"activity_tier is
/// boolean-via-score, so CC 4.4.2 composes multiple attesters per (dimension,
/// attested_key_id) via MIN (any Below-Active trumps Active) — never a mean."*
/// Flagged as *"LIVE DRIFT (verified)"*: previously fell through to Signed.
///
/// Adversarial shape: several Active (`+1.0`) attesters and one Below-Active
/// (`-1.0`). A mean (`+0.6`) reports Active; the fail-secure min holds the
/// Below-Active signal at `-1.0`.
#[test]
fn activity_tier_is_boolean_via_score_min_below_active_trumps() {
    let mut trust = TrustSet::new();
    let mut corpus = Vec::new();
    for i in 0..4 {
        let k = format!("active-attester-{i}");
        trust.pin(&k);
        corpus.push(att(
            &format!("a{i}"),
            &k,
            "agent-x",
            "activity_tier:monthly",
            1.0,
            1.0,
            json!({}),
        ));
    }
    trust.pin("below-active-attester");
    corpus.push(att(
        "b0",
        "below-active-attester",
        "agent-x",
        "activity_tier:monthly",
        -1.0,
        1.0,
        json!({}),
    ));

    let composer = Composer::new(trust).with_config(cfg());
    let out = composer.compose(&corpus);
    let v = out
        .verdict("activity_tier:monthly", "agent-x")
        .expect("verdict");
    assert_eq!(v.polarity, Polarity::BooleanViaScore);
    assert!(
        approx(v.value, -1.0),
        "one Below-Active must trump four Active (min = -1.0), not a mean (+0.6); got {}",
        v.value
    );
    assert_eq!(v.decision, Decision::Deny);
}

// ─── polarity_for arm: credits:* → PositiveOnly (CC 4.4.2) ────────────────────

/// **`credits:{domain}:{language}:{subject}`** — `invariant_registry`:
/// *"Positive-only polarity composes via MAX across attesters, not sum/count."*
/// Flagged as *"LIVE DRIFT (verified)"*: previously fell through to Signed.
///
/// Adversarial shape: a small credit (`0.4`) and a large one (`0.9`). A signed
/// mean (`0.65`) understates the standing; the max reports `0.9`.
#[test]
fn credits_is_positive_only_max_not_mean() {
    let mut trust = TrustSet::new();
    trust.pin("grantor-a");
    trust.pin("grantor-b");
    let composer = Composer::new(trust).with_config(cfg());

    let corpus = vec![
        att(
            "c-lo",
            "grantor-a",
            "agent-x",
            "credits:medicine:en:cardiology",
            0.4,
            1.0,
            json!({}),
        ),
        att(
            "c-hi",
            "grantor-b",
            "agent-x",
            "credits:medicine:en:cardiology",
            0.9,
            1.0,
            json!({}),
        ),
    ];
    let out = composer.compose(&corpus);
    let v = out
        .verdict("credits:medicine:en:cardiology", "agent-x")
        .expect("verdict");
    assert_eq!(v.polarity, Polarity::PositiveOnly);
    assert!(
        approx(v.value, 0.9),
        "credits must be max (0.9), not a mean (0.65); got {}",
        v.value
    );
    assert_eq!(v.decision, Decision::Affirm);
}

// ─── screen sibling: detector-sole-evidence for slashing (CC 3.1.6) ──────────

/// **CC 3.1.6 (FSD-005 App.A:182)** — the SIBLING of the testimonial
/// sole-evidence screen. `invariant_registry` (`slashing:{outcome}`):
/// *"ratchet:flag:\* / detection:\* cannot be sole evidence for slashing …
/// unreachable from ratchet/detection alone."*
///
/// Like the testimonial twin this is a SCREEN, not a weight: a `slashing:*` row
/// whose entire resolvable evidence base is detector emissions contributes at NO
/// weight, so the verdict cannot stand. One non-detector corroborating row (the
/// WA-quorum finding) satisfies the safeguard and the slashing composes.
#[test]
fn cc_3_1_6_detector_is_never_sole_evidence_for_slashing() {
    let mut trust = TrustSet::new();
    trust.pin("adjudicator");
    trust.pin("lenscore");
    let composer = Composer::new(trust).with_config(cfg());

    let detection = att(
        "d1",
        "lenscore",
        "accused",
        "detection:correlated_action:votes",
        1.0,
        1.0,
        json!({}),
    );
    let ratchet = att(
        "r1",
        "lenscore",
        "accused",
        "ratchet:flag:coordinated_voting_cluster",
        1.0,
        1.0,
        json!({}),
    );

    // Sole evidence = detector rows only → REFUSED.
    let sole = vec![
        detection.clone(),
        ratchet.clone(),
        att(
            "s1",
            "adjudicator",
            "accused",
            "slashing:PROVEN_ROGUE",
            1.0,
            1.0,
            json!({ "evidence_refs": ["d1", "r1"] }),
        ),
    ];
    let out = composer.compose(&sole);
    assert!(
        out.refusals.iter().any(|r| r.attestation_id == "s1"
            && r.reason == RefusalReason::DetectorSoleEvidenceForSlashing),
        "a slashing row backed ONLY by detector emissions must be refused; refusals: {:?}",
        out.refusals
    );
    assert_eq!(
        out.verdict("slashing:PROVEN_ROGUE", "accused")
            .unwrap()
            .decision,
        Decision::Undetermined,
        "and the slashing verdict must not stand from detector signal alone"
    );

    // Add ONE non-detector corroborating row (the load-bearing WA-quorum finding)
    // → the safeguard is satisfied and the slashing composes.
    let corroborated = vec![
        detection,
        ratchet,
        att(
            "m1",
            "adjudicator",
            "accused",
            "moderation:method_spoofing",
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
            json!({ "evidence_refs": ["d1", "r1", "m1"] }),
        ),
    ];
    let out = composer.compose(&corroborated);
    assert!(
        !out.refusals.iter().any(|r| r.attestation_id == "s1"),
        "detector evidence + a non-detector finding is not sole-detector; refusals: {:?}",
        out.refusals
    );
    assert_eq!(
        out.verdict("slashing:PROVEN_ROGUE", "accused")
            .unwrap()
            .decision,
        Decision::Affirm
    );
}
