//! **`revoked_after` is enforced at every read that resolves whether a key's
//! claim stands** (CIRISServer#355 / CIRISPersist#570 ask 4).
//!
//! persist ships the history bound; the enforcement point is the consumer's
//! read, and before this arc `grep -rn revoked_after src/` returned nothing.
//! These gates drive the REAL read paths against a live sqlite substrate with a
//! REAL signed revocation in it, because the half that cannot be tested in
//! `src/key_standing.rs`'s unit tests is the half that has historically broken:
//! whether the check is on the path at all. A fold that is right about rows it
//! is never asked about reports a healthy node forever.
//!
//! Every gate asserts BOTH directions, and that is the whole point of a bounded
//! revocation: the statement after the bound must stop counting **and** the
//! statement before it must keep counting. A check that refuses everything from
//! a revoked key passes the first half and silently reimplements the
//! all-or-nothing behaviour the bound exists to replace.
//!
//! The fixtures also pin the axis: every seeded row's ROW COLUMN `asserted_at`
//! is `Utc::now()` (persist stamps it at write) while its SIGNED envelope
//! `asserted_at` is backdated. A check keyed on the column would find nothing
//! here and look healthy doing it — CIRISServer#350's lesson, re-armed.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::types::{
    algorithm, attestation_tier, attestation_type, cohort_scope, identity_type, Attestation,
    KeyRecord, SignedAttestation, SignedKeyRecord,
};
use ciris_persist::federation::KeyStatementStanding;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

use ciris_server::compose_policy::{Composer, Decision, RefusalReason, TrustSet};
use ciris_server::equivocation::{self, DetectorConfig};
use ciris_server::graph_config::{self, ConfigScope, ConfigValue};

#[path = "support/revocation.rs"]
mod revocation;
use revocation::revoke;

const NODE_KEY_ID: &str = "revoked-after-node";
const ATTESTER_KEY_ID: &str = "compromised-attester";
const SUBJECT_KEY_ID: &str = "subject-agent";
const SUBJECT_TWO_KEY_ID: &str = "subject-agent-two";

/// A dimension needing no duty-holder to emit and no self-emission screen —
/// `capacity:*` is refused at the local tier by CC 3.4.5 anti-Goodhart and
/// `moderation:*`/`slashing:*` are duty-gated, so neither can carry a fixture.
const DIM: &str = "trust:community_standing:v1";

// ─── fixture plumbing (mirrors tests/ownership.rs + tests/equivocation.rs) ───

/// An in-memory substrate keyed by a HYBRID node-identity signer.
async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer (sqlite::memory:)"),
    )
}

fn party_ed_seed(key_id: &str) -> [u8; 32] {
    let mut s = [0xE1u8; 32];
    for (i, b) in key_id.bytes().enumerate().take(32) {
        s[i] ^= b;
    }
    s
}

fn party_pqc_seed(key_id: &str) -> [u8; 32] {
    let mut s = [0xE2u8; 32];
    for (i, b) in key_id.bytes().enumerate().take(32) {
        s[i] ^= b;
    }
    s
}

fn party_signer(key_id: &str) -> LocalSigner {
    let signing_key = SigningKey::from_bytes(&party_ed_seed(key_id));
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&party_pqc_seed(key_id), format!("{key_id}-pqc"))
            .expect("party ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        signing_key,
        key_id.to_string(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    )
}

/// Register the node's OWN derived federation key with its real hybrid pubkeys
/// — the precondition for it to sign a revocation persist will admit.
async fn register_self(engine: &Engine) -> String {
    let key_id = engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id");
    let now = Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize self envelope");
    let sig = engine.sign_hybrid(&canonical).await.expect("self sign");
    let record = KeyRecord {
        key_id: key_id.clone(),
        pubkey_ed25519_base64: BASE64.encode(&sig.classical.public_key),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(&sig.pqc.public_key)),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::NODE.into(),
        identity_ref: key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .register_federation_key(SignedKeyRecord { record })
        .await
        .expect("register node key");
    key_id
}

/// Register a party under its REAL hybrid pubkeys, so federation-tier rows it
/// signs re-verify at `put_attestation`.
async fn register_party(engine: &Engine, key_id: &str, id_type: &str) -> LocalSigner {
    use ciris_keyring::PqcSigner as _;
    let signer = party_signer(key_id);
    let ed_pub = BASE64.encode(
        SigningKey::from_bytes(&party_ed_seed(key_id))
            .verifying_key()
            .to_bytes(),
    );
    let mldsa_pub = {
        let pqc = MlDsa65SoftwareSigner::from_seed_bytes(
            &party_pqc_seed(key_id),
            format!("{key_id}-pqc"),
        )
        .expect("party ML-DSA-65 seed");
        BASE64.encode(pqc.public_key().await.expect("party ML-DSA-65 pubkey"))
    };
    let now = Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize party envelope");
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: ed_pub,
        pubkey_ml_dsa_65_base64: Some(mldsa_pub),
        algorithm: algorithm::HYBRID.into(),
        identity_type: id_type.to_string(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register party key");
    signer
}

/// Seed one federation-tier `scores` row signed by `attester`, carrying a CHOSEN
/// signed instant in its envelope. The row column stays `Utc::now()` — the two
/// axes, held apart on purpose.
#[allow(clippy::too_many_arguments)]
async fn seed_score(
    engine: &Engine,
    attester: &LocalSigner,
    subject: &str,
    signed_at: DateTime<Utc>,
    score: f64,
    confidence: f64,
) -> String {
    let envelope = serde_json::json!({
        (paths::DIMENSION): DIM,
        "attesting_key_id": attester.key_id(),
        "attested_key_id": subject,
        "score": score,
        "confidence": confidence,
        "witness_relation": "external",
        "asserted_at": signed_at.to_rfc3339(),
    });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize score envelope");
    let sig = attester
        .sign_hybrid(&canonical)
        .await
        .expect("hybrid-sign the score");
    let now = Utc::now();
    let attestation_id = format!("att-{}-{}-{}", attester.key_id(), subject, score);
    let attestation = Attestation {
        attestation_id: attestation_id.clone(),
        attesting_key_id: attester.key_id().to_string(),
        attested_key_id: subject.to_string(),
        attestation_type: attestation_type::SCORES.to_string(),
        weight: Some(score),
        // The UNSIGNED column: deliberately `now`, never the signed instant.
        asserted_at: now,
        expires_at: Some(now + Duration::days(7)),
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: attester.key_id().to_string(),
        additional_scrubs: Vec::new(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
    };
    engine
        .federation_directory()
        .put_attestation(SignedAttestation { attestation })
        .await
        .expect("put federation-tier score row");
    attestation_id
}

fn hours_ago(h: i64) -> DateTime<Utc> {
    Utc::now() - Duration::hours(h)
}

// ─── (1) compose_policy — the CC 4.4 composed verdict ────────────────────────

/// A trust-pinned key revoked with a history bound: its pre-bound score still
/// composes, its post-bound score is REFUSED as `KeyStatementSuspect`.
#[tokio::test]
async fn compose_refuses_a_post_bound_score_and_keeps_the_pre_bound_one() {
    let engine = node().await;
    register_self(&engine).await;
    let node_signer = party_signer("revocation-authority");
    register_party(&engine, "revocation-authority", identity_type::STEWARD).await;
    let attester = register_party(&engine, ATTESTER_KEY_ID, identity_type::NODE).await;
    register_party(&engine, SUBJECT_KEY_ID, identity_type::AGENT).await;

    // Two claims by ONE key about ONE subject, straddling the bound.
    seed_score(&engine, &attester, SUBJECT_KEY_ID, hours_ago(48), 0.9, 1.0).await;
    seed_score(&engine, &attester, SUBJECT_KEY_ID, hours_ago(2), -0.9, 1.0).await;

    revoke(
        &engine,
        &node_signer,
        ATTESTER_KEY_ID,
        Utc::now(),
        Some(hours_ago(24)),
    )
    .await;

    let mut trust = TrustSet::new();
    trust.pin(ATTESTER_KEY_ID);
    let out = Composer::new(trust)
        .compose_for_key(&engine, SUBJECT_KEY_ID)
        .await
        .expect("compose");

    let suspect: Vec<&_> = out
        .refusals
        .iter()
        .filter(|r| {
            r.reason == RefusalReason::KeyStatementSuspect(KeyStatementStanding::SuspectAfterBound)
        })
        .collect();
    assert_eq!(
        suspect.len(),
        1,
        "exactly the post-bound row must be refused as KeyStatementSuspect; refusals = {:?}",
        out.refusals
    );

    let verdict = out
        .verdict(DIM, SUBJECT_KEY_ID)
        .expect("the pre-bound row must still produce a verdict");
    assert_eq!(
        verdict.contributions.len(),
        1,
        "the pre-bound row alone contributes — a bounded revocation is not all-or-nothing"
    );
    assert_eq!(verdict.decision, Decision::Affirm);
    assert!(
        verdict.value > 0.0,
        "the surviving contribution is the +0.9 pre-bound claim, not the -0.9 post-bound one \
         (value={})",
        verdict.value
    );
}

/// With NO revocation held, both rows compose — the gate above is measuring the
/// revocation and not some unrelated screen.
#[tokio::test]
async fn compose_admits_both_scores_when_no_revocation_is_held() {
    let engine = node().await;
    register_self(&engine).await;
    let attester = register_party(&engine, ATTESTER_KEY_ID, identity_type::NODE).await;
    register_party(&engine, SUBJECT_KEY_ID, identity_type::AGENT).await;
    seed_score(&engine, &attester, SUBJECT_KEY_ID, hours_ago(48), 0.9, 1.0).await;
    seed_score(&engine, &attester, SUBJECT_KEY_ID, hours_ago(2), -0.9, 1.0).await;

    let mut trust = TrustSet::new();
    trust.pin(ATTESTER_KEY_ID);
    let out = Composer::new(trust)
        .compose_for_key(&engine, SUBJECT_KEY_ID)
        .await
        .expect("compose");

    assert!(
        out.refusals.is_empty(),
        "nothing is revoked here — refusals = {:?}",
        out.refusals
    );
    assert_eq!(
        out.verdict(DIM, SUBJECT_KEY_ID)
            .expect("verdict")
            .contributions
            .len(),
        2
    );
}

/// An UNBOUNDED revocation still takes the whole corpus. The bound is a
/// leniency the revoker opts into; declining it keeps the pre-#570 meaning, and
/// this gate is what stops the new code from quietly turning every revocation
/// into a bounded one.
#[tokio::test]
async fn an_unbounded_revocation_refuses_every_score_including_the_oldest() {
    let engine = node().await;
    register_self(&engine).await;
    let node_signer = party_signer("revocation-authority");
    register_party(&engine, "revocation-authority", identity_type::STEWARD).await;
    let attester = register_party(&engine, ATTESTER_KEY_ID, identity_type::NODE).await;
    register_party(&engine, SUBJECT_KEY_ID, identity_type::AGENT).await;
    seed_score(&engine, &attester, SUBJECT_KEY_ID, hours_ago(48), 0.9, 1.0).await;
    seed_score(&engine, &attester, SUBJECT_KEY_ID, hours_ago(2), -0.9, 1.0).await;

    revoke(&engine, &node_signer, ATTESTER_KEY_ID, Utc::now(), None).await;

    let mut trust = TrustSet::new();
    trust.pin(ATTESTER_KEY_ID);
    let out = Composer::new(trust)
        .compose_for_key(&engine, SUBJECT_KEY_ID)
        .await
        .expect("compose");

    assert_eq!(
        out.refusals
            .iter()
            .filter(|r| r.reason
                == RefusalReason::KeyStatementSuspect(KeyStatementStanding::SuspectUnbounded))
            .count(),
        2,
        "an unbounded revocation scopes nothing; refusals = {:?}",
        out.refusals
    );
    assert_eq!(
        out.verdict(DIM, SUBJECT_KEY_ID).expect("verdict").decision,
        Decision::Undetermined,
        "fail-closed: nothing survived screening, so there is no basis for Affirm or Deny"
    );
}

// ─── (2) equivocation — the live-row evidence read ───────────────────────────

/// Two contradictions in one corpus, one on each side of the bound: the
/// pre-bound pair is still non-repudiable evidence, the post-bound pair is not
/// evidence at all and is COUNTED as dropped.
#[tokio::test]
async fn the_detector_drops_post_bound_rows_and_keeps_pre_bound_evidence() {
    let engine = node().await;
    let node_key_id = register_self(&engine).await;
    let node_signer = party_signer("revocation-authority");
    register_party(&engine, "revocation-authority", identity_type::STEWARD).await;
    let attester = register_party(&engine, ATTESTER_KEY_ID, identity_type::NODE).await;
    register_party(&engine, SUBJECT_KEY_ID, identity_type::AGENT).await;
    register_party(&engine, SUBJECT_TWO_KEY_ID, identity_type::AGENT).await;

    let before = hours_ago(48);
    let after = hours_ago(2);
    // Pair A (subject 1) at ONE signed instant BEFORE the bound.
    seed_score(&engine, &attester, SUBJECT_KEY_ID, before, 0.9, 1.0).await;
    seed_score(&engine, &attester, SUBJECT_KEY_ID, before, 0.1, 1.0).await;
    // Pair B (subject 2) at ONE signed instant AFTER the bound — the shape a
    // key thief manufactures to make the victim look like an equivocator.
    seed_score(&engine, &attester, SUBJECT_TWO_KEY_ID, after, 0.8, 1.0).await;
    seed_score(&engine, &attester, SUBJECT_TWO_KEY_ID, after, 0.2, 1.0).await;

    revoke(
        &engine,
        &node_signer,
        ATTESTER_KEY_ID,
        Utc::now(),
        Some(hours_ago(24)),
    )
    .await;

    let report = equivocation::run_pass(&engine, &node_key_id, &DetectorConfig::default())
        .await
        .expect("detector pass");

    assert_eq!(
        report.suspect_rows, 2,
        "the two post-bound rows must be dropped AND counted — a smaller scan with no \
         explanation is the truncation defect one field over"
    );
    assert_eq!(
        report.contradictions.len(),
        1,
        "the pre-bound contradiction is still evidence; the post-bound one was never the \
         victim's statement (contradictions = {:?})",
        report
            .contradictions
            .iter()
            .map(|c| (&c.subject_key_id, c.asserted_at))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        report.contradictions[0].subject_key_id, SUBJECT_KEY_ID,
        "the surviving contradiction is the pre-bound pair"
    );
}

// ─── (3) auth::ownership — owner-binding resolution ──────────────────────────

/// Emit a genuinely user-signed owner-binding whose SIGNED envelope instant is
/// `signed_at` (the row column stays `Utc::now()`).
async fn bind_owner(
    engine: &Engine,
    owner: &LocalSigner,
    node_key_id: &str,
    signed_at: DateTime<Utc>,
) {
    use ciris_server::auth::ownership::{
        build_owner_binding_envelope, canonicalize_owner_binding_envelope,
        persist_user_signed_owner_binding, OWNER_BINDING_INFRA_SCOPES,
    };
    let scopes: Vec<String> = OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let envelope = build_owner_binding_envelope(
        owner.key_id(),
        node_key_id,
        &scopes,
        &signed_at.to_rfc3339(),
    )
    .expect("build owner-binding envelope");
    let canonical = canonicalize_owner_binding_envelope(&envelope).expect("canonicalize binding");
    let sig = owner
        .sign_hybrid(&canonical)
        .await
        .expect("owner hybrid-signs the binding");
    persist_user_signed_owner_binding(
        engine,
        envelope,
        owner.key_id(),
        node_key_id,
        cohort_scope::SELF,
        &canonical,
        &BASE64.encode(&sig.classical.signature),
        &BASE64.encode(&sig.pqc.signature),
    )
    .await
    .expect("persist owner-binding");
}

/// The `self` boundary is exactly as time-bounded as the revocation says: a
/// binding signed before the bound keeps the node owned; one signed after it
/// does not.
#[tokio::test]
async fn ownership_survives_a_pre_bound_binding_and_fails_closed_on_a_post_bound_one() {
    use ciris_server::auth::ownership::is_steward_bound;

    // (a) binding signed BEFORE the bound → ownership stands.
    {
        let engine = node().await;
        let node_key_id = register_self(&engine).await;
        let authority =
            register_party(&engine, "revocation-authority", identity_type::STEWARD).await;
        let owner = register_party(&engine, "owner-user", identity_type::USER).await;
        bind_owner(&engine, &owner, &node_key_id, hours_ago(48)).await;
        assert_eq!(
            is_steward_bound(&engine, &node_key_id).await.as_deref(),
            Some("owner-user"),
            "sanity: the binding resolves before anything is revoked"
        );

        revoke(
            &engine,
            &authority,
            "owner-user",
            Utc::now(),
            Some(hours_ago(24)),
        )
        .await;
        assert_eq!(
            is_steward_bound(&engine, &node_key_id).await.as_deref(),
            Some("owner-user"),
            "the owner's key is revoked FROM an instant AFTER the binding — the ownership \
             was established while the key was sound, and destroying it is the DigiNotar \
             long tail the bound exists to prevent"
        );
    }

    // (b) binding signed AFTER the bound → fail closed.
    {
        let engine = node().await;
        let node_key_id = register_self(&engine).await;
        let authority =
            register_party(&engine, "revocation-authority", identity_type::STEWARD).await;
        let owner = register_party(&engine, "owner-user", identity_type::USER).await;
        bind_owner(&engine, &owner, &node_key_id, hours_ago(2)).await;
        assert_eq!(
            is_steward_bound(&engine, &node_key_id).await.as_deref(),
            Some("owner-user"),
            "sanity: the binding resolves before anything is revoked"
        );

        revoke(
            &engine,
            &authority,
            "owner-user",
            Utc::now(),
            Some(hours_ago(24)),
        )
        .await;
        assert_eq!(
            is_steward_bound(&engine, &node_key_id).await,
            None,
            "a node claimed with a compromised key AFTER the compromise is not owned"
        );
    }
}

// ─── (4) graph_config — the config plane ─────────────────────────────────────

/// A config row authored before the bound still resolves; one authored after it
/// reads as absent and the node falls back to its baked default.
#[tokio::test]
async fn config_reads_absent_after_the_bound_and_resolves_before_it() {
    // (a) bound AFTER the write → the row survives.
    {
        let engine = node().await;
        register_self(&engine).await;
        let authority =
            register_party(&engine, "revocation-authority", identity_type::STEWARD).await;
        let node_key_id = graph_config::self_key_id(&engine).await.expect("self key");
        graph_config::set_config(
            &engine,
            "ciris.test.knob",
            ConfigValue::Str("live".into()),
            "gate",
            ConfigScope::Local,
        )
        .await
        .expect("write config");

        // The bound is taken AFTER the write, so the row's signed instant is at
        // or before it. `revoked_after <= effective_at <= now` is persist's own
        // coherence rule (`BoundAfterEffective`), so a bound can never be in the
        // future — which is exactly why this direction has to be built this way.
        let bound = Utc::now();
        revoke(&engine, &authority, &node_key_id, bound, Some(bound)).await;

        assert_eq!(
            graph_config::get_str(&engine, "ciris.test.knob")
                .await
                .expect("read config")
                .as_deref(),
            Some("live"),
            "the config was written before the bound and still stands"
        );
    }

    // (b) bound BEFORE the write → the row reads as absent.
    {
        let engine = node().await;
        register_self(&engine).await;
        let authority =
            register_party(&engine, "revocation-authority", identity_type::STEWARD).await;
        let node_key_id = graph_config::self_key_id(&engine).await.expect("self key");
        graph_config::set_config(
            &engine,
            "ciris.test.knob",
            ConfigValue::Str("live".into()),
            "gate",
            ConfigScope::Local,
        )
        .await
        .expect("write config");

        revoke(
            &engine,
            &authority,
            &node_key_id,
            Utc::now(),
            Some(hours_ago(24)),
        )
        .await;

        assert_eq!(
            graph_config::get_str(&engine, "ciris.test.knob")
                .await
                .expect("read config"),
            None,
            "a config row authored by a key whose statements were revoked from an earlier \
             instant must read as absent — the node falls back to its baked default"
        );
    }
}
