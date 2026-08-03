//! Same-key equivocation detection against a REAL corpus (CIRISServer#350).
//!
//! `src/equivocation.rs`'s unit tests pin the predicate over hand-built rows.
//! These drive [`ciris_server::equivocation::run_pass`] against a live sqlite
//! Engine, because the half that cannot be tested in-module is the half that has
//! historically broken: the READ. A predicate that is right about rows it never
//! sees reports a clean corpus forever, and every narrowing in this codebase
//! (`graph_config`'s `Unauthenticated` scope, the scorer's `n_summaries=0`) read
//! exactly like health from the outside.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::hard_case::HardCaseFilter;
use ciris_persist::federation::types::LocalAttestationInput;
use ciris_persist::federation::types::{algorithm, cohort_scope, identity_type};
use ciris_persist::federation::{FederationDirectory as _, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};

use ciris_server::equivocation::{self, DetectorConfig, HARD_CASE_KIND};

const NODE_KEY_ID: &str = "node-a";
const PEER_KEY_ID: &str = "peer-scorer";
const SUBJECT_KEY_ID: &str = "agent-subject";

/// A dimension whose CLAIM VALUE lives in the envelope payload — the shape the
/// detector can compare.
///
/// NOT `capacity:*` (the issue's headline case): same shape, but refused at the
/// local tier by CEG §7.5 anti-Goodhart, so it cannot be seeded through the
/// local-write→promote route these fixtures use.
///
/// NOT `moderation:*` either, which this originally used. persist v26.0.0
/// (#589) closed a real hole: `attestation_promote` had been re-signing and
/// flipping `tier` WITHOUT re-running the admission stack, so promotion was a
/// path to launder an unauthorized row into federation tier. It now faces the
/// full stack — and `moderation:`/`slashing:` are duty-gated
/// (`check_moderation_admission`), so seeding one requires the signer to be a
/// duty-holder or reach one through a scoped delegation chain.
///
/// The fixture was exercising the hole. It is fixed here rather than worked
/// around: the detector is indifferent to WHICH dimension it compares — it keys
/// on (attester, subject, dimension, signed instant) — so the honest fixture
/// uses a family that needs no duty, and the gate stays intact.
const DIM: &str = "trust:community_standing:v1";

/// Node A: in-memory sqlite substrate keyed by a hybrid node-identity signer.
/// Mirrors `tests/capacity_self_revocation_pin.rs`.
async fn node_a() -> (Arc<Engine>, String, String) {
    use ciris_keyring::PqcSigner as _;
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    let ed_pub_b64 = BASE64.encode(signing_key.verifying_key().to_bytes());
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node-a ML-DSA-65 seed"),
    );
    let mldsa_pub_b64 = BASE64.encode(pqc.public_key().await.expect("node-a ML-DSA-65 pubkey"));
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    let engine = Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("Engine::with_signer (sqlite::memory:)");
    (Arc::new(engine), ed_pub_b64, mldsa_pub_b64)
}

async fn register_key(
    engine: &Engine,
    key_id: &str,
    ed_pubkey_b64: &str,
    ml_dsa_65_pubkey_b64: Option<&str>,
    id_type: &str,
) {
    let now = chrono::Utc::now();
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: ed_pubkey_b64.to_string(),
        pubkey_ml_dsa_65_base64: ml_dsa_65_pubkey_b64.map(str::to_string),
        algorithm: algorithm::HYBRID.into(),
        identity_type: id_type.to_string(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": key_id }),
        original_content_hash: "deadbeef".into(),
        scrub_signature_classical: ed_pubkey_b64.to_string(),
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .sqlite_backend()
        .expect("sqlite backend")
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register key");
}

/// Seed one federation-tier claim: local-tier write (which is where a caller
/// chooses `attesting_key_id` freely) then promote, the same route
/// `tests/capacity_self_revocation_pin.rs` uses. `attestation_insert_local` —
/// NOT `upsert_local`, which DELETEs the prior local row for the same
/// (attester, dimension) and would collapse the very pair under test.
async fn seed(
    engine: &Engine,
    attester: &str,
    subject: &str,
    signed_asserted_at: &str,
    rating: f64,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> String {
    let id = seed_local(
        engine,
        attester,
        subject,
        signed_asserted_at,
        rating,
        expires_at,
    )
    .await;
    engine
        .attestation_promote(&id, cohort_scope::FEDERATION)
        .await
        .expect("promote claim to federation tier");
    id
}

/// The local-tier half of [`seed`] — the unpublished draft, before promotion.
async fn seed_local(
    engine: &Engine,
    attester: &str,
    subject: &str,
    signed_asserted_at: &str,
    rating: f64,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> String {
    let envelope = serde_json::json!({
        (paths::DIMENSION): DIM,
        "asserted_at": signed_asserted_at,
        "rating": rating,
    });
    let core =
        ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope).expect("envelope");
    let id = engine
        .federation_directory()
        .attestation_insert_local(LocalAttestationInput {
            attestation_id: None,
            attesting_key_id: attester.to_string(),
            attested_key_id: Some(subject.to_string()),
            attestation_type: "scores".to_string(),
            weight: Some(rating),
            expires_at: Some(expires_at),
            attestation_envelope: core,
            subject_key_ids: Vec::new(),
            // Local rows are `self`-scoped by rule; the promote below widens
            // them to the federation audience.
            cohort_scope: cohort_scope::SELF.to_string(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        })
        .await
        .expect("insert local claim");
    id
}

async fn fixture() -> (Arc<Engine>, String) {
    let (engine, node_ed, node_mldsa) = node_a().await;
    let node_key_id = engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id");
    register_key(
        &engine,
        &node_key_id,
        &node_ed,
        Some(&node_mldsa),
        identity_type::NODE,
    )
    .await;
    let peer_ed = BASE64.encode(
        SigningKey::from_bytes(&[0xB1; 32])
            .verifying_key()
            .to_bytes(),
    );
    register_key(&engine, PEER_KEY_ID, &peer_ed, None, identity_type::NODE).await;
    let subj_ed = BASE64.encode(
        SigningKey::from_bytes(&[0xC1; 32])
            .verifying_key()
            .to_bytes(),
    );
    register_key(
        &engine,
        SUBJECT_KEY_ID,
        &subj_ed,
        None,
        identity_type::AGENT,
    )
    .await;
    (engine, node_key_id)
}

async fn hard_cases(engine: &Engine) -> Vec<ciris_persist::federation::hard_case::HardCaseEvent> {
    engine
        .federation_directory()
        .list_hard_case_events(HardCaseFilter {
            kind: Some(HARD_CASE_KIND.to_string()),
            since: None,
        })
        .await
        .expect("list hard cases")
}

const T0: &str = "2026-08-01T17:00:00Z";
const T1: &str = "2026-08-01T18:00:00Z";

fn hour_from_now(h: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + chrono::Duration::hours(h)
}

/// **The end-to-end property.** Two claims from ONE peer key about ONE subject
/// at ONE signed instant, both live in this node's corpus: the pass must find
/// them through the real read, and record the CC 6.1.1 N4 `hard_case` naming
/// BOTH rows.
#[tokio::test]
async fn a_peers_two_claims_at_one_instant_are_detected_and_recorded() {
    let (engine, node_key_id) = fixture().await;
    let a = seed(
        &engine,
        PEER_KEY_ID,
        SUBJECT_KEY_ID,
        T0,
        0.9,
        hour_from_now(24),
    )
    .await;
    let b = seed(
        &engine,
        PEER_KEY_ID,
        SUBJECT_KEY_ID,
        T0,
        0.1,
        hour_from_now(24),
    )
    .await;

    let report = equivocation::run_pass(&engine, &node_key_id, &DetectorConfig::default())
        .await
        .expect("detector pass");
    assert_eq!(
        report.contradictions.len(),
        1,
        "the pass did not find the seeded contradiction through the live read \
         (rows_scanned={}, pairs_compared={}, superseded={}, no_signed_instant={})",
        report.rows_scanned,
        report.pairs_compared,
        report.superseded,
        report.no_signed_instant
    );

    let cases = hard_cases(&engine).await;
    assert_eq!(cases.len(), 1, "expected exactly one recorded hard_case");
    let ev = &cases[0];
    assert_eq!(ev.target_key_id.as_deref(), Some(PEER_KEY_ID));
    assert_eq!(ev.subject_key_id.as_deref(), Some(SUBJECT_KEY_ID));
    let ids: Vec<&str> = ev.detail["attestation_ids"]
        .as_array()
        .expect("attestation_ids")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let mut expected = [a.as_str(), b.as_str()];
    expected.sort_unstable();
    assert_eq!(
        ids, expected,
        "the recorded evidence must name both real rows, sorted"
    );
    assert_eq!(
        ev.detail["differing_fields"],
        serde_json::json!(["rating"]),
        "the evidence must name the field the two claims disagree on"
    );
}

/// **Re-detection must be a no-op.** The condition never clears, so the pass
/// re-derives the same `event_id` every cadence forever; persist dedupes on it.
/// A time-varying id would grow one row per pass per standing contradiction.
#[tokio::test]
async fn re_detection_records_no_second_row() {
    let (engine, node_key_id) = fixture().await;
    seed(
        &engine,
        PEER_KEY_ID,
        SUBJECT_KEY_ID,
        T0,
        0.9,
        hour_from_now(24),
    )
    .await;
    seed(
        &engine,
        PEER_KEY_ID,
        SUBJECT_KEY_ID,
        T0,
        0.1,
        hour_from_now(24),
    )
    .await;

    let cfg = DetectorConfig::default();
    let first = equivocation::run_pass(&engine, &node_key_id, &cfg)
        .await
        .expect("first pass");
    let second = equivocation::run_pass(&engine, &node_key_id, &cfg)
        .await
        .expect("second pass");
    assert_eq!(
        first.contradictions, second.contradictions,
        "the same corpus produced two different contradiction sets across passes"
    );
    let cases = hard_cases(&engine).await;
    assert_eq!(
        cases.len(),
        1,
        "a second pass over the SAME standing contradiction wrote another row — the \
         event_id is not stable across passes, so this grows without bound"
    );
    // The RECORDED key must be exactly the derived one. Two passes inside one
    // second collide on any per-second decoration, so "one row survived" alone
    // cannot see a clock leaking into the key; comparing the stored id against
    // the pure derivation can.
    assert_eq!(
        cases[0].event_id,
        first.contradictions[0].event_id(),
        "the recorded event_id is not the one derived from the pair — something outside \
         the contradiction (a clock, a counter) is in persist's dedup key"
    );
}

/// A producer that revises its claim at a LATER signed instant is doing the
/// honest thing. Nothing may be recorded: latest-wins resolves it, and an
/// accusation against every producer that ever updated a score is worse than no
/// detector at all.
#[tokio::test]
async fn a_later_revision_records_nothing() {
    let (engine, node_key_id) = fixture().await;
    seed(
        &engine,
        PEER_KEY_ID,
        SUBJECT_KEY_ID,
        T0,
        0.9,
        hour_from_now(24),
    )
    .await;
    seed(
        &engine,
        PEER_KEY_ID,
        SUBJECT_KEY_ID,
        T1,
        0.1,
        hour_from_now(24),
    )
    .await;

    let report = equivocation::run_pass(&engine, &node_key_id, &DetectorConfig::default())
        .await
        .expect("detector pass");
    assert!(
        report.contradictions.is_empty(),
        "a revision was reported as equivocation: {:?}",
        report.contradictions
    );
    assert_eq!(
        report.superseded, 1,
        "the pair must be seen and classified as superseded, not missed entirely \
         (rows_scanned={})",
        report.rows_scanned
    );
    assert!(hard_cases(&engine).await.is_empty());
}

/// **The read narrows on validity, in the query.** An expired pair is not a
/// live contradiction; the `valid_at` pushdown is what makes that true, and it
/// is the only real bound on this scan.
#[tokio::test]
async fn an_expired_pair_is_outside_the_live_read() {
    let (engine, node_key_id) = fixture().await;
    seed(
        &engine,
        PEER_KEY_ID,
        SUBJECT_KEY_ID,
        T0,
        0.9,
        hour_from_now(-1),
    )
    .await;
    seed(
        &engine,
        PEER_KEY_ID,
        SUBJECT_KEY_ID,
        T0,
        0.1,
        hour_from_now(-1),
    )
    .await;

    let report = equivocation::run_pass(&engine, &node_key_id, &DetectorConfig::default())
        .await
        .expect("detector pass");
    assert_eq!(
        report.rows_scanned, 0,
        "expired rows reached the comparison — the read is not bounded by validity, so \
         this pass scans the whole corpus forever and reports dead contradictions as live"
    );
    assert!(report.contradictions.is_empty());
}

/// **An unpublished draft is not evidence.** Local-tier rows are producer-only
/// and were never shown to anyone, so two of them contradicting is a scratchpad,
/// not a key telling two peers different things. `AttestationFilter::tier` is
/// silently ignored by `list_attestations`, so this exclusion lives in Rust —
/// which means only a test can hold it.
///
/// Both rows are attested ABOUT this node (so the `self`-scope gate admits them
/// to the read) and left unpromoted: tier is then the only thing between them
/// and the comparison.
#[tokio::test]
async fn an_unpublished_local_draft_is_not_evidence() {
    let (engine, node_key_id) = fixture().await;
    seed_local(
        &engine,
        PEER_KEY_ID,
        &node_key_id,
        T0,
        0.9,
        hour_from_now(24),
    )
    .await;
    seed_local(
        &engine,
        PEER_KEY_ID,
        &node_key_id,
        T0,
        0.1,
        hour_from_now(24),
    )
    .await;

    let report = equivocation::run_pass(&engine, &node_key_id, &DetectorConfig::default())
        .await
        .expect("detector pass");
    assert_eq!(
        report.rows_scanned, 0,
        "an unpromoted local-tier draft reached the comparison — a row the attester never \
         published cannot be evidence that it told two peers different things"
    );
    assert!(hard_cases(&engine).await.is_empty());
}

/// **No exemption for our own key.** The node's own scorer manufactures this
/// exact shape whenever a score moves twice inside one coalescing bucket
/// (`scorer::coalesced_assertion` floors the signed instant; `standing_assertion`
/// only suppresses an UNCHANGED score). A detector that skips the local key
/// would be silent about the one producer it can actually fix.
#[tokio::test]
async fn the_nodes_own_key_is_not_exempt() {
    let (engine, node_key_id) = fixture().await;
    seed(
        &engine,
        &node_key_id,
        SUBJECT_KEY_ID,
        T0,
        0.9,
        hour_from_now(24),
    )
    .await;
    seed(
        &engine,
        &node_key_id,
        SUBJECT_KEY_ID,
        T0,
        0.1,
        hour_from_now(24),
    )
    .await;

    let report = equivocation::run_pass(&engine, &node_key_id, &DetectorConfig::default())
        .await
        .expect("detector pass");
    assert_eq!(
        report.contradictions.len(),
        1,
        "a contradiction authored by THIS node's own key was not reported"
    );
    let cases = hard_cases(&engine).await;
    assert_eq!(cases.len(), 1);
    assert_eq!(
        cases[0].target_key_id.as_deref(),
        Some(node_key_id.as_str()),
        "the hard_case must name the local key as the equivocator, unflatteringly"
    );
}

/// A clean corpus records nothing — the steady state, and the assertion that
/// keeps the detector from being a machine for manufacturing accusations. Two
/// rows carrying the SAME signed statement (a replicated duplicate) are one
/// claim recorded twice.
#[tokio::test]
async fn a_duplicated_statement_records_nothing() {
    let (engine, node_key_id) = fixture().await;
    seed(
        &engine,
        PEER_KEY_ID,
        SUBJECT_KEY_ID,
        T0,
        0.9,
        hour_from_now(24),
    )
    .await;
    seed(
        &engine,
        PEER_KEY_ID,
        SUBJECT_KEY_ID,
        T0,
        0.9,
        hour_from_now(24),
    )
    .await;

    let report = equivocation::run_pass(&engine, &node_key_id, &DetectorConfig::default())
        .await
        .expect("detector pass");
    assert_eq!(
        report.same_statement, 1,
        "the duplicate pair must be seen and classified, not missed (rows_scanned={})",
        report.rows_scanned
    );
    assert!(report.contradictions.is_empty());
    assert!(hard_cases(&engine).await.is_empty());
}
