//! **What an admitted-but-hostile peer can still do** — the residual abuse
//! surface of the last 0.5, demonstrated by running rather than reasoned about.
//!
//! Every test here is a **characterization pin**: it asserts what the substrate
//! this release pins (persist v29.0.0) actually does today. A test named
//! `..._is_admitted_today` is pinning a **hole**, not a property — when the
//! substrate closes it the test goes RED, and that RED is the signal to delete
//! the pin and file the good news. A test named `..._is_refused` is pinning a
//! control that fires, so a regression that re-opens it goes RED too.
//!
//! Which one a test is, is stated in its own doc comment. That distinction is
//! the whole discipline: a suite that cannot tell a pinned hole from a pinned
//! control is a suite that reads as reassurance either way.
//!
//! # Why this file exists at all
//!
//! `FSD/MESH_GOVERNANCE_AND_ADMIN_OPS.md` §0 names four preconditions that
//! killed every prior mesh, and §7 says the residual is *"unpaid, not
//! impossible"*. Neither statement is checkable. These are.
//!
//! # What is demonstrated
//!
//! | # | what | verdict pinned |
//! |---|---|---|
//! | 1 | `witness` is self-assertable, and it unlocks `age_assurance:*` about a third party | **HOLE** |
//! | 1b | `lenscore_detector` is self-assertable, and it unlocks the whole `detection:*` wildcard | **HOLE** — contradicts persist's own comment |
//! | 2 | `substrate_persist` is self-assertable, and it unlocks `hard_case:*` tombstones | **HOLE** |
//! | 2b | `accord_holder` is NOT self-assertable | **control** — the one identity gate that holds |
//! | 2c | which of the nine privileged claims a stranger may declare — the set, not one element | **HOLE**, as a population |
//! | 3 | any admitted key scores any third party on an ungated dimension | **HOLE** (architectural, FSD §0) |
//! | 4 | `capacity:*` self-inflation is refused three ways | **control**, exercised at all three doors |
//! | 4b | …and a two-key Sybil still lands it | **residual** (FSD §7: m-of-n counts keys) |
//! | 5 | AV-77 de-admission really does stop a hostile peer's writes | **control that fires** |
//! | 5b | …and `src/admin_ops.rs` now emits the row (`POST /v1/admin/refuse-writes`, CIRISServer#375) | **the recourse gap, CLOSED** |
//! | 5c | a de-admitted key keeps the one dimension that de-admits others | **HOLE** |
//! | 6 | `PeerWriteQuota` refuses a flood, and **nothing here counts the refusal** | **control with no reader** |
//!
//! Every assertion above was mutation-verified: the guarded thing was broken,
//! the test went RED, and the break was reverted. A check that cannot fail is
//! how this repo has been fooled five times.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::replication::admission::PER_PEER_ATTESTATION_WRITES_PER_WINDOW;
use ciris_persist::federation::types::{
    algorithm, attestation_tier, attestation_type, cohort_scope, identity_type, Attestation,
    KeyRecord, SignedAttestation, SignedKeyRecord,
};
use ciris_persist::federation::{Error as FedError, FederationDirectory};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

const NODE_ALIAS: &str = "ciris-abuse-node";

// ─── substrate + identity helpers (mirror tests/commons_surface.rs) ─────────

async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xB1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xB2; 32], format!("{NODE_ALIAS}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_ALIAS.to_string(),
        Some(pqc),
        Some(format!("{NODE_ALIAS}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer (sqlite::memory:)"),
    )
}

fn party_ed_seed(key_id: &str) -> [u8; 32] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&Sha256::digest(format!("ed:{key_id}")));
    s
}

fn party_pqc_seed(key_id: &str) -> [u8; 32] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&Sha256::digest(format!("pqc:{key_id}")));
    s
}

fn party_signer(key_id: &str) -> LocalSigner {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&party_pqc_seed(key_id), format!("{key_id}-pqc"))
            .expect("party ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        SigningKey::from_bytes(&party_ed_seed(key_id)),
        key_id.to_string(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    )
}

async fn party_pubkeys(key_id: &str) -> (String, String) {
    let ed = BASE64.encode(
        SigningKey::from_bytes(&party_ed_seed(key_id))
            .verifying_key()
            .to_bytes(),
    );
    let pqc =
        MlDsa65SoftwareSigner::from_seed_bytes(&party_pqc_seed(key_id), format!("{key_id}-pqc"))
            .expect("party ML-DSA-65 seed");
    (
        ed,
        BASE64.encode(pqc.public_key().await.expect("party ML-DSA-65 pubkey")),
    )
}

/// **The public bootstrap door.** Register `key_id` claiming `id_type` through
/// [`Engine::register_federation_key`] — the canonical admission gate, which
/// proves key CUSTODY (a self-signed hybrid proof-of-possession) and whatever
/// else persist chooses to demand of the claimed `identity_type`.
///
/// This is deliberately NOT `put_public_key`: the whole question these tests
/// ask is *what does the gate a stranger actually knocks on let through*, and
/// the raw store call answers a different one.
async fn self_register(
    engine: &Engine,
    key_id: &str,
    id_type: &str,
) -> Result<LocalSigner, ciris_server::attest::Error> {
    let signer = party_signer(key_id);
    let (ed_pub, mldsa_pub) = party_pubkeys(key_id).await;
    // Through the ONE door (CIRISServer#402): the registration envelope now BINDS
    // ITS SUBJECT. The hand-rolled `{"key_id": …}` shape named neither the
    // identity type nor either pubkey, and persist v31 refuses it — an envelope
    // that does not name its subject stands for any record it is pasted onto
    // (CIRISPersist#659).
    ciris_server::attest::register_key(
        engine,
        ciris_server::attest::KeySigner::Local(&signer),
        &key_id,
        id_type,
        serde_json::Value::Null,
    )
    .await?;
    Ok(signer)
}

/// The node's own key, registered through the same canonical gate.
async fn register_self(engine: &Engine) -> String {
    let key_id = engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id");
    // Through the ONE door (CIRISServer#402): the registration envelope now BINDS
    // ITS SUBJECT. The hand-rolled `{"key_id": …}` shape named neither the
    // identity type nor either pubkey, and persist v31 refuses it — an envelope
    // that does not name its subject stands for any record it is pasted onto
    // (CIRISPersist#659).
    ciris_server::attest::register_key(
        engine,
        ciris_server::attest::KeySigner::Engine(engine),
        &key_id,
        identity_type::STEWARD,
        serde_json::Value::Null,
    )
    .await
    .expect("register node steward key");
    key_id
}

/// Build a genuinely-signed federation-tier row. `attn_type` is the structural
/// primitive (or a reserved TYPE namespace such as `hard_case:*`).
async fn signed_row(
    signer: &LocalSigner,
    id: &str,
    attn_type: &str,
    attested: &str,
    envelope: serde_json::Value,
    asserted_at: DateTime<Utc>,
) -> Attestation {
    let key_id = signer.key_id().to_string();
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize row");
    let sig = signer.sign_hybrid(&canonical).await.expect("sign row");
    Attestation {
        attestation_id: id.to_string(),
        attesting_key_id: key_id.clone(),
        attested_key_id: attested.to_string(),
        attestation_type: attn_type.to_string(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: key_id,
        additional_scrubs: Vec::new(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: Some(asserted_at),
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
    }
}

fn scores_envelope(dimension: &str, subject: &str, score: f64) -> serde_json::Value {
    serde_json::json!({
        "dimension": dimension,
        "score": score,
        "confidence": 1.0,
        "epistemic_mode": "direct",
        "witness_relation": "external",
        "stake": "reputational",
        "attested_key_id": subject,
    })
}

async fn put(engine: &Engine, row: Attestation) -> Result<(), FedError> {
    engine
        .federation_directory()
        .put_attestation(SignedAttestation { attestation: row })
        .await
}

// ═══════════════════════════════════════════════════════════════════════════
//  1. `witness` is self-assertable — and it is an identity-type-only key to
//     the age-assurance plane.
// ═══════════════════════════════════════════════════════════════════════════

/// **PINS A HOLE.** persist v22.0.0 closed the self-asserted-authority hole
/// (`check_privileged_identity_type_admission`) for the claims whose conferral
/// root is the accord co-scrub. `witness` is deliberately excluded, on the
/// stated ground that it is *"DESCRIPTIVE; every use site re-derives the
/// authority from persist's own verified state, so a self-asserted claim buys
/// nothing"* (`types::identity_type::conferral_mode`).
///
/// That ground does not hold for `age_assurance:`. Its gate is
/// `default_reserved_prefix_rules()` → `required_identity_types: [witness]`,
/// which is a **pure identity-type membership test** run against the stored
/// registration row. Nothing is re-derived. So a stranger who self-registers as
/// `witness` may assert an age-assurance LEVEL about any third party, which is
/// the exact rung CC 3.4.11 reserves to a witness precisely because a subject
/// must not be able to reach it.
///
/// If this test goes RED because the write is now refused, the hole is closed:
/// delete the pin.
#[tokio::test]
async fn a_self_asserted_witness_can_forge_age_assurance_about_a_third_party_today() {
    let engine = node().await;
    register_self(&engine).await;

    // The victim: an ordinary agent, registered the ordinary way.
    self_register(&engine, "abuse-victim", identity_type::AGENT)
        .await
        .expect("victim registers as an ordinary agent");

    // The abuser: a stranger who simply SAYS it is a witness. No co-scrub, no
    // hardware, no delegation — one self-signed proof-of-possession.
    let abuser = self_register(&engine, "abuse-fake-witness", identity_type::WITNESS)
        .await
        .expect(
            "SELF-ASSERTED `witness` IS ADMITTED at the public bootstrap door — if this now \
             fails, check_privileged_identity_type_admission gained a witness arm and this \
             whole test is obsolete",
        );

    let row = signed_row(
        &abuser,
        "forged-age-assurance",
        attestation_type::SCORES,
        "abuse-victim",
        scores_envelope("age_assurance:level:adult:v1", "abuse-victim", 1.0),
        Utc::now(),
    )
    .await;

    let verdict = put(&engine, row).await;
    assert!(
        verdict.is_ok(),
        "PIN: a self-asserted witness lands an age-assurance LEVEL about a third party. If this \
         is now refused the hole is CLOSED and this pin should be deleted. Got: {verdict:?}"
    );

    // And the row is readable as what it claims to be — not quarantined, not
    // flagged. This half is what makes it a forgery rather than noise.
    let rows = engine
        .federation_directory()
        .list_attestations_for("abuse-victim")
        .await
        .expect("read the victim's rows");
    assert!(
        rows.iter()
            .any(|r| r.attesting_key_id == "abuse-fake-witness"
                && r.attestation_envelope
                    .get("dimension")
                    .and_then(serde_json::Value::as_str)
                    == Some("age_assurance:level:adult:v1")),
        "the forged age-assurance row reads back as a witness-attested level"
    );
}

/// **PINS A HOLE — and this one contradicts the substrate's own comment.**
///
/// `conferral_mode(LENSCORE_DETECTOR)` is `DelegatedFromTrustRoot`, and the
/// note above it in `types.rs` says of `trusted_publisher` and
/// `lenscore_detector`: *"Both assert about a THIRD PARTY … so self-assertion
/// IS the #543 attack and they must be conferred, not claimed."*
///
/// They are not. `check_privileged_identity_type_admission_over_roster` opens
/// with
///
/// ```text
/// if conferral_mode(claim) != Some(ConferralMode::AccordCoScrubbed) { continue; }
/// ```
///
/// so every claim on the delegation plane is skipped at registration — and the
/// use-site that was supposed to resolve it (`capability_roots_to_trusted_root`)
/// is only ever asked about `infra:*` scopes, never about these two roles. The
/// `detection:*` door is `default_reserved_prefix_rules()` →
/// `required_identity_types: [lenscore_detector]`, a pure membership test
/// against the stored registration row.
///
/// Net: the role persist names as the #543 attack is self-assertable, and it
/// unlocks the entire `detection:*` wildcard about anyone.
#[tokio::test]
async fn a_self_asserted_detector_can_forge_detection_rows_about_a_third_party_today() {
    let engine = node().await;
    register_self(&engine).await;
    self_register(&engine, "abuse-victim-detect", identity_type::AGENT)
        .await
        .expect("victim registers");

    let abuser = self_register(
        &engine,
        "abuse-fake-detector",
        identity_type::LENSCORE_DETECTOR,
    )
    .await
    .expect(
        "PIN: a self-asserted lenscore_detector IS ADMITTED, despite persist's own comment \
         calling exactly this 'the #543 attack'",
    );

    let row = signed_row(
        &abuser,
        "forged-detection",
        attestation_type::SCORES,
        "abuse-victim-detect",
        scores_envelope("detection:correlated_action:v1", "abuse-victim-detect", 1.0),
        Utc::now(),
    )
    .await;

    let verdict = put(&engine, row).await;
    assert!(
        verdict.is_ok(),
        "PIN: the self-asserted detector lands a detection:* row about a third party — the \
         adversarial-detector plane, authored by the adversary. If this is now refused the hole \
         is CLOSED. Got: {verdict:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  2. `substrate_persist` is self-assertable — and `hard_case:*` is where the
//     admin ladder writes its attribution.
// ═══════════════════════════════════════════════════════════════════════════

/// **PINS A HOLE.** `substrate_persist` is `DerivedFromVerifiedState` on the
/// stated ground that *"the families it unlocks are the node's own operational
/// telemetry about its own substrate, and nothing consumes them as authority
/// over a third party"*, with an explicit retirement condition: *"If a
/// `system:*` row ever becomes an input to a decision ABOUT ANOTHER PARTY, this
/// must move to AccordCoScrubbed."*
///
/// The condition is already met, by a family that list omits.
/// `check_reserved_prefix_admission` gates the `hard_case:` **type** namespace
/// on `substrate_persist` — and `hard_case:` is where `src/admin_ops.rs` writes
/// every tier 0–4 tombstone, whose entire purpose is to carry *"the authorizing
/// `delegates_to` id and a mandatory reason"* for an action taken about someone
/// else (FSD §3). A row on that family is by construction about another party.
///
/// So a stranger who self-registers as `substrate_persist` can author rows on
/// the plane the ladder's own accountability rests on.
#[tokio::test]
async fn a_self_asserted_substrate_persist_cannot_author_hard_case_rows() {
    let engine = node().await;
    register_self(&engine).await;
    self_register(&engine, "abuse-victim-2", identity_type::AGENT)
        .await
        .expect("victim registers");

    let abuser = self_register(
        &engine,
        "abuse-fake-substrate",
        identity_type::SUBSTRATE_PERSIST,
    )
    .await
    .expect(
        "SELF-ASSERTED `substrate_persist` IS ADMITTED at the public bootstrap door — if this \
         now fails, its conferral_mode moved and this test is obsolete",
    );

    // A `hard_case:` TYPE row naming a third party as its subject. This is the
    // shape `admin_ops` writes when it de-admits or quarantines someone.
    let row = signed_row(
        &abuser,
        "forged-hard-case",
        "hard_case:admin_action:v1",
        "abuse-victim-2",
        serde_json::json!({
            "dimension": "hard_case:admin_action:v1",
            "op": "deadmit",
            "reason": "authored by a key that simply called itself the substrate",
            "delegation_id": "no-such-delegation",
        }),
        Utc::now(),
    )
    .await;

    // CLOSED by persist v30.3.0 (CIRISPersist#607/#611). This pin was written
    // asserting `verdict.is_ok()` — that the hole was OPEN — with the note "if
    // this is now refused the hole is CLOSED and this pin should be deleted".
    // It was refused, so it is flipped rather than deleted: the same fixture
    // that demonstrated the hole is the cheapest regression guard against its
    // return, and deleting it would discard the one thing that proves the door
    // shut for the reason we think it did.
    //
    // The refusal must be the RESERVED-PREFIX gate specifically. A generic
    // `Err` would also satisfy `is_err()` while meaning something else entirely
    // — a malformed envelope, a missing key — and would let the hole reopen
    // under a gate that had stopped running.
    let verdict = put(&engine, row).await;
    let err = verdict.expect_err(
        "REGRESSION: a self-asserted `substrate_persist` landed a `hard_case:*` row about a \
         third party. persist v30.3.0 closed this (CIRISPersist#607/#611); `hard_case:` is the \
         prefix `admin_ops` writes every tier 0-4 tombstone under, so an open door here lets a \
         stranger forge de-admissions and quarantines about anyone.",
    );
    let msg = format!("{err:?}");
    assert!(
        msg.contains("ReservedPrefixEmitterMismatch") && msg.contains("hard_case:"),
        "the refusal must come from the reserved-prefix gate on `hard_case:`, not from some \
         other failure that happens to be an Err — otherwise this test passes while the gate \
         it guards has stopped running. Got: {msg}"
    );
    assert!(
        msg.contains("infra:record_hard_case"),
        "the refusal should name the delegated scope that WOULD authorise this, because the \
         emitter is the only party who can fix it. Got: {msg}"
    );
}

/// **PINS A CONTROL.** The one identity-gated type namespace that DOES hold
/// against a self-assertion: `accord:*` requires `accord_holder`, whose
/// conferral is hardware attestation, and the registration itself is refused.
///
/// This is the reason the kill switch is the operator's floor: the plane it
/// rides is the only one a stranger cannot reach by renaming itself.
#[tokio::test]
async fn a_self_asserted_accord_holder_is_refused_at_the_door() {
    let engine = node().await;
    register_self(&engine).await;

    let verdict = self_register(&engine, "abuse-fake-holder", identity_type::ACCORD_HOLDER).await;
    assert!(
        verdict.is_err(),
        "a self-asserted accord_holder MUST be refused — it is the root of the halt authority"
    );
}

/// **THE WHOLE CLAIM SET, in one place.** The three forgery tests above each
/// prove one door; this proves the *population* — exactly which members of
/// `AUTHORITY_CONFERRING_IDENTITY_TYPES` a stranger may simply declare.
///
/// It is a separate test because "these four are self-assertable" is a claim
/// about a set, and a set claim checked one element at a time is a claim nobody
/// re-derives when the set changes. `conferral_mode` is the axis:
/// `AccordCoScrubbed` / `HardwareAttested` / `AnchorScrubbed` are gated;
/// `DerivedFromVerifiedState` and `DelegatedFromTrustRoot` are not — and the
/// second of those is the one persist's own comment calls the #543 attack.
#[tokio::test]
async fn which_privileged_claims_are_self_assertable_and_which_are_gated() {
    let engine = node().await;
    register_self(&engine).await;

    let mut admitted = Vec::new();
    let mut refused = Vec::new();
    for (i, claim) in identity_type::AUTHORITY_CONFERRING_IDENTITY_TYPES
        .iter()
        .enumerate()
    {
        match self_register(&engine, &format!("claimant-{i}"), claim).await {
            Ok(_) => admitted.push(*claim),
            Err(_) => refused.push(*claim),
        }
    }
    admitted.sort_unstable();
    refused.sort_unstable();

    assert_eq!(
        admitted,
        vec![
            identity_type::LENSCORE_DETECTOR,
            identity_type::PARTNER,
            identity_type::STEWARD,
            identity_type::SUBSTRATE_PERSIST,
            identity_type::TRUSTED_PUBLISHER,
            identity_type::WISE_AUTHORITY,
            identity_type::WITNESS,
        ],
        "PIN: the self-assertable set. `steward` / `partner` / `wise_authority` are \
         genuinely re-derived at every use site, so their presence here is fine. The other \
         four are not: `witness` unlocks age_assurance / capacity_assurance / \
         transparency_log:cosigned, `lenscore_detector` the whole detection:* wildcard, \
         `trusted_publisher` the content_rating read chain, and `substrate_persist` the \
         hard_case:* plane the admin ladder writes its attribution on — every one of those \
         doors a pure identity_type membership test."
    );
    assert_eq!(
        refused,
        vec![identity_type::ACCORD_HOLDER, identity_type::CANONICAL],
        "and exactly two are gated: the hardware-attested and anchor-scrubbed roots"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  3. The receive plane has no subject.
// ═══════════════════════════════════════════════════════════════════════════

/// **PINS A HOLE — the architectural one.** `FSD/MESH_GOVERNANCE_AND_ADMIN_OPS.md`
/// §0 lists *"the receive plane has no subject — any admitted key writes signed
/// rows naming anyone; subject-side consent exists for `capacity:*` alone"* as
/// one of four findings that survive the proportion rule.
///
/// This is that finding, executed. An ordinary `agent` key — no privileged
/// identity_type, no delegation, no consent from the subject — writes a signed
/// row asserting a reputational judgement about a victim who never granted
/// anything, and it is admitted and readable under the victim's key.
#[tokio::test]
async fn any_admitted_key_scores_any_third_party_today() {
    let engine = node().await;
    register_self(&engine).await;
    self_register(&engine, "abuse-victim-3", identity_type::AGENT)
        .await
        .expect("victim registers");
    let abuser = self_register(&engine, "abuse-stranger", identity_type::AGENT)
        .await
        .expect("stranger registers as a plain agent — the cheapest possible admission");

    let row = signed_row(
        &abuser,
        "unconsented-judgement",
        attestation_type::SCORES,
        "abuse-victim-3",
        scores_envelope("health:liveness:v1", "abuse-victim-3", 0.0),
        Utc::now(),
    )
    .await;

    put(&engine, row)
        .await
        .expect("PIN: an unconsented third-party judgement is admitted (FSD §0 finding 1)");

    let rows = engine
        .federation_directory()
        .list_attestations_for("abuse-victim-3")
        .await
        .expect("read the victim's rows");
    assert!(
        rows.iter().any(|r| r.attesting_key_id == "abuse-stranger"),
        "and it is readable as a fact about the victim, under the victim's own key"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  4. `capacity:*` — the anti-Goodhart wall, and the gap a second key opens.
// ═══════════════════════════════════════════════════════════════════════════

/// **PINS A CONTROL, three ways.** The prior audit reported capacity
/// self-inflation via a dead guard. It is not dead now. persist refuses a
/// self-attested `capacity:*` row on the federation tier (AV-62/74), refuses it
/// on the local tier (AV-83 / #589 — `capacity:*` is never local, asked at BOTH
/// doors), and refuses a third-party one without the subject's `analyze` grant
/// (CC#46 / #569).
///
/// All three are exercised against the real substrate, and each refusal is
/// required to name its OWN rule — a wall that refuses everything for one
/// reason is a wall with two untested halves.
#[tokio::test]
async fn capacity_self_inflation_is_refused_at_every_door() {
    let engine = node().await;
    register_self(&engine).await;
    let abuser = self_register(&engine, "abuse-capacity-self", identity_type::AGENT)
        .await
        .expect("abuser registers");
    self_register(&engine, "abuse-capacity-scorer", identity_type::AGENT)
        .await
        .expect("a second key registers");

    // (a) federation tier, self-attested.
    let row = signed_row(
        &abuser,
        "capacity-self-fed",
        attestation_type::SCORES,
        "abuse-capacity-self",
        scores_envelope("capacity:composite:v1", "abuse-capacity-self", 1.0),
        Utc::now(),
    )
    .await;
    let err = put(&engine, row)
        .await
        .expect_err("a self-attested capacity:* row MUST be refused at the federation tier");
    let text = format!("{err:?}");
    assert!(
        text.contains("self-attested") || text.contains("SelfAttested"),
        "the refusal must name self-attestation (AV-62/74), got: {text}"
    );

    // (b) local tier, self-attested — the door #589/AV-83 found open.
    let local = ciris_persist::federation::types::LocalAttestationInput {
        attestation_id: None,
        attesting_key_id: "abuse-capacity-self".into(),
        attested_key_id: Some("abuse-capacity-self".into()),
        attestation_type: attestation_type::SCORES.into(),
        weight: None,
        expires_at: None,
        attestation_envelope: ciris_persist::federation::envelope::EnvelopeCore::from_value(
            scores_envelope("capacity:composite:v1", "abuse-capacity-self", 1.0),
        )
        .expect("envelope"),
        subject_key_ids: Vec::new(),
        cohort_scope: cohort_scope::SELF.into(),
        scrub_signature_classical: None,
        scrub_signature_pqc: None,
    };
    let err = engine
        .sqlite_backend()
        .expect("sqlite backend")
        .attestation_upsert_local(local)
        .await
        .expect_err("a capacity:* row MUST NOT be writable at the local tier (AV-83)");
    assert!(
        format!("{err:?}").contains("local"),
        "the refusal must name the tier rule, got: {err:?}"
    );

    // (c) federation tier, third-party, no `analyze` grant from the subject.
    let scorer = party_signer("abuse-capacity-scorer");
    let row = signed_row(
        &scorer,
        "capacity-third-party-unconsented",
        attestation_type::SCORES,
        "abuse-capacity-self",
        scores_envelope("capacity:composite:v1", "abuse-capacity-self", 1.0),
        Utc::now(),
    )
    .await;
    let err = put(&engine, row)
        .await
        .expect_err("a third-party capacity:* row without the subject's consent MUST be refused");
    let text = format!("{err:?}");
    assert!(
        !text.contains("self-attested"),
        "this refusal must be the CONSENT rule, not the self-attestation rule shadowing it: \
         {text}"
    );
}

/// **PINS THE RESIDUAL.** The wall above counts KEYS, not humans — which
/// `FSD/MESH_GOVERNANCE_AND_ADMIN_OPS.md` §7 lists as one of three permanently
/// unpayable costs (*"m-of-n counts keys, not independent humans"*).
///
/// One party holding two keys satisfies every arm of it: key P grants key Q the
/// `analyze` scope, Q scores P at the ceiling, and the row is admitted. Nothing
/// in the substrate can tell that P and Q are the same actor, and nothing here
/// tries to — the pin exists so the residual is a measured fact rather than a
/// paragraph.
#[tokio::test]
async fn a_two_key_sybil_still_inflates_its_own_capacity() {
    let engine = node().await;
    register_self(&engine).await;
    let subject = self_register(&engine, "sybil-subject", identity_type::AGENT)
        .await
        .expect("sybil's first key");
    let scorer = self_register(&engine, "sybil-scorer", identity_type::AGENT)
        .await
        .expect("sybil's second key — same human, different bytes");

    // The subject grants its own other key the `analyze` scope. This is the
    // reverse edge CC#46 requires, and it is entirely under the abuser's hand.
    let grant = signed_row(
        &subject,
        "sybil-analyze-grant",
        attestation_type::SCORES,
        "sybil-scorer",
        serde_json::json!({
            "dimension": "consent:state:granted:analyze:v1",
            "score": 1.0,
            "confidence": 1.0,
            "epistemic_mode": "direct",
            "witness_relation": "self",
            "stake": "reputational",
            "scope": ["analyze"],
            "attested_key_id": "sybil-scorer",
        }),
        Utc::now() - Duration::seconds(60),
    )
    .await;
    put(&engine, grant)
        .await
        .expect("a subject may grant analyze to any key, including its own second one");

    let row = signed_row(
        &scorer,
        "sybil-self-inflation",
        attestation_type::SCORES,
        "sybil-subject",
        scores_envelope("capacity:composite:v1", "sybil-subject", 1.0),
        Utc::now(),
    )
    .await;

    let verdict = put(&engine, row).await;
    assert!(
        verdict.is_ok(),
        "PIN: the consent wall is satisfied by the abuser's own second key. If this is now \
         refused, something learned to count humans and that is worth knowing. Got: {verdict:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  5. The one control that stops a hostile peer writing — and its caller.
// ═══════════════════════════════════════════════════════════════════════════

/// Sign a row with the NODE's own key (not a party's), so the de-admission is
/// authored by the "me" the AV-77 predicate compares against.
async fn node_signed_row(
    engine: &Engine,
    id: &str,
    attested: &str,
    envelope: serde_json::Value,
) -> Attestation {
    let key_id = engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id");
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize node row");
    let sig = engine.sign_hybrid(&canonical).await.expect("node sign");
    let now = Utc::now();
    Attestation {
        attestation_id: id.to_string(),
        attesting_key_id: key_id.clone(),
        attested_key_id: attested.to_string(),
        attestation_type: attestation_type::SCORES.to_string(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: key_id,
        additional_scrubs: Vec::new(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
    }
}

/// **PINS A CONTROL THAT FIRES — and, since CIRISServer#375, its caller.**
///
/// AV-77 (`revocation:peer_admission:v1`, persist v22.0.0 / #543 finding 5) is
/// the only primitive in the whole stack that *stops a hostile admitted peer
/// from writing*. `src/compose.rs::arm_peer_deadmission_gate` arms it at boot
/// and proves the arming by readback, refusing to serve if it did not stick.
///
/// This test drives it end to end: the abuser writes, the node emits the
/// de-admission, the abuser's next write is REFUSED. The control is real.
///
/// The second half used to be the finding: **no route in this server emitted
/// that row.** `POST /v1/admin/deadmit` — tier 4, the rung named "de-admit —
/// key may no longer write" — writes a `Revocation` on the append-only key
/// plane instead, and says so itself: *"It is evidence a reader folds, not a
/// door that slams … the replication cursors and row ingest all deliberately
/// keep working."* Those are two different acts and only one of them stops
/// writes. `POST /v1/admin/refuse-writes` is the other one, and
/// `tests/admin_ops.rs::refuse_writes_stops_the_next_write_and_accept_writes_admits_it_again`
/// walks the same round trip through the HTTP route.
///
/// The source scan below is now the regression pin in the other direction: it
/// keeps the caller from quietly disappearing and returning the operator to the
/// armed-and-unreachable state — the same discipline
/// `tests/commons_surface.rs::property_2_*` applies to threshold arithmetic.
#[tokio::test]
async fn av77_deadmission_stops_the_writes_and_admin_ops_emits_it() {
    let engine = node().await;
    let node_key = register_self(&engine).await;
    self_register(&engine, "av77-victim", identity_type::AGENT)
        .await
        .expect("victim registers");
    let abuser = self_register(&engine, "av77-abuser", identity_type::AGENT)
        .await
        .expect("abuser registers");

    // Arm the gate exactly as `compose::arm_peer_deadmission_gate` does.
    engine.set_self_key_id(Some(node_key.clone()));
    assert_eq!(
        engine.self_key_id().as_deref(),
        Some(node_key.as_str()),
        "the AV-77 predicate has no `me` to compare against until this sticks"
    );

    // Before: the abuser writes freely.
    let before = signed_row(
        &abuser,
        "av77-before",
        attestation_type::SCORES,
        "av77-victim",
        scores_envelope("health:liveness:v1", "av77-victim", 1.0),
        Utc::now(),
    )
    .await;
    put(&engine, before)
        .await
        .expect("an admitted peer writes freely before any sanction");

    // The node de-admits the abuser from its OWN corpus.
    let deadmit = node_signed_row(
        &engine,
        "av77-deadmission",
        "av77-abuser",
        serde_json::json!({
            "dimension": "revocation:peer_admission:v1",
            "score": -1.0,
            "confidence": 1.0,
            "epistemic_mode": "direct",
            "witness_relation": "external",
            "stake": "reputational",
            "attested_key_id": "av77-abuser",
        }),
    )
    .await;
    put(&engine, deadmit)
        .await
        .expect("a node may always de-admit a peer from its own corpus");

    // After: the same write is refused, before any DB-walking gate runs.
    let after = signed_row(
        &abuser,
        "av77-after",
        attestation_type::SCORES,
        "av77-victim",
        scores_envelope("health:liveness:v1", "av77-victim", 1.0),
        Utc::now(),
    )
    .await;
    let err = put(&engine, after)
        .await
        .expect_err("a de-admitted peer's writes MUST be refused (AV-77)");
    assert!(
        format!("{err:?}").contains("de-admitted"),
        "the refusal must name de-admission, not something incidental: {err:?}"
    );

    // ── and now: which surface here can emit that row? ────────────────────
    // A CALL SITE, not a mention. An emitter names the dimension one of exactly
    // two ways: the persist constant (the single-source form this repo's
    // `tests/envelope_vocabulary_single_source.rs` requires) or a Rust string
    // literal. Prose about the gate writes it in backticks, which is why
    // `src/compose.rs`'s three accurate paragraphs are not callers — and why
    // the discriminator is the QUOTE, not the token.
    //
    // **This half used to assert the list was EMPTY**, and it was — the gate
    // was armed, proven armed, and unreachable from every operator surface.
    // CIRISServer#375 landed the caller, so the pin is inverted rather than
    // deleted: an emitter that quietly disappears again puts the operator back
    // in the position this test was written to expose, and nothing else in the
    // suite would notice.
    let mut emitters = Vec::new();
    for entry in walk_rs("src") {
        let text = std::fs::read_to_string(&entry).expect("read source");
        if text.contains("\"revocation:peer_admission:v1\"")
            || text.contains("PEER_DEADMISSION_DIMENSION")
        {
            emitters.push(entry.display().to_string());
        }
    }
    assert!(
        emitters.iter().any(|e| e.ends_with("admin_ops.rs")),
        "PIN: `src/admin_ops.rs` must reach the ONE row that stops a hostile peer writing \
         (POST /v1/admin/refuse-writes, CIRISServer#375). If it no longer does, the gate is \
         armed and unreachable again — which is the exact state this test was written to \
         expose. Found: {emitters:?}"
    );
}

/// **PINS A HOLE.** `check_peer_deadmission` exempts the de-admission dimension
/// itself, so that a node can always lift its own denial. The exemption is
/// written as
///
/// ```text
/// if row.attesting_key_id == self_key_id || envelope_dimension(..) == PEER_DEADMISSION_DIMENSION
/// ```
///
/// — a disjunction, and the second arm does not ask WHO wrote the row. So a
/// de-admitted key keeps exactly one power: it may go on writing
/// `revocation:peer_admission:v1` rows into this node's corpus, about anyone.
///
/// They do not take effect here (the predicate reads only de-admissions THIS
/// node authored), but they are stored, signed, and replicable — so the one
/// dimension a sanctioned key retains is the one that sanctions others.
#[tokio::test]
async fn a_deadmitted_key_may_still_write_deadmission_rows_today() {
    let engine = node().await;
    let node_key = register_self(&engine).await;
    self_register(&engine, "av77-bystander", identity_type::AGENT)
        .await
        .expect("bystander registers");
    let abuser = self_register(&engine, "av77-abuser-2", identity_type::AGENT)
        .await
        .expect("abuser registers");
    engine.set_self_key_id(Some(node_key));

    let deadmit = node_signed_row(
        &engine,
        "av77-deadmission-2",
        "av77-abuser-2",
        serde_json::json!({
            "dimension": "revocation:peer_admission:v1",
            "score": -1.0,
            "confidence": 1.0,
            "epistemic_mode": "direct",
            "witness_relation": "external",
            "stake": "reputational",
            "attested_key_id": "av77-abuser-2",
        }),
    )
    .await;
    put(&engine, deadmit).await.expect("de-admit the abuser");

    // The sanctioned key now de-admits an innocent bystander.
    let row = signed_row(
        &abuser,
        "av77-retaliation",
        attestation_type::SCORES,
        "av77-bystander",
        serde_json::json!({
            "dimension": "revocation:peer_admission:v1",
            "score": -1.0,
            "confidence": 1.0,
            "epistemic_mode": "direct",
            "witness_relation": "external",
            "stake": "reputational",
            "attested_key_id": "av77-bystander",
        }),
        Utc::now(),
    )
    .await;
    let verdict = put(&engine, row).await;
    assert!(
        verdict.is_ok(),
        "PIN: the de-admission exemption is a disjunction that never asks who is writing, so a \
         sanctioned key keeps the sanctioning dimension. If this is now refused the hole is \
         CLOSED. Got: {verdict:?}"
    );
}

/// Every `.rs` under `root`, recursively. A test-local walker rather than a dev
/// dependency: one call site, six lines, no new supply chain.
fn walk_rs(root: &str) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(root)];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════
//  6. The quota fires — and no instrument on this node reads the refusal.
// ═══════════════════════════════════════════════════════════════════════════

/// **PINS A CONTROL THAT FIRES.** `PeerWriteQuota` leads the `put_attestation`
/// chain, and a single peer exceeding
/// [`PER_PEER_ATTESTATION_WRITES_PER_WINDOW`] inside the window is refused with
/// [`FedError::RateLimited`]. Demonstrated by driving real signed rows through
/// the real backend until the verdict changes.
///
/// The second half is the one that matters: **nothing on this node counts that
/// refusal.** persist's own `PeerQuotaObservation` says so in as many words
/// (*"ordinary quota refusals … are not counted here at all"*), and
/// `crate::operator_surface`'s `peer_quota` reading is derived from exactly
/// that observation — so it reports `clean` / green while a peer is being
/// refused on every write.
///
/// That is the shape `FSD/RCA_INGEST_REJECTION_2026-08-05.md` cost 71 hours to
/// learn: *a correct refusal with no reader*. This test asserts the refusal
/// AND asserts the blindness, so the day someone wires a counter it goes RED
/// and names itself.
#[tokio::test]
async fn the_peer_write_quota_refuses_a_flood_and_nothing_here_counts_it() {
    let engine = node().await;
    register_self(&engine).await;
    self_register(&engine, "quota-victim", identity_type::AGENT)
        .await
        .expect("victim registers");
    let flooder = self_register(&engine, "quota-flooder", identity_type::AGENT)
        .await
        .expect("flooder registers — one ordinary admitted key");

    let budget = PER_PEER_ATTESTATION_WRITES_PER_WINDOW as usize;
    let now = Utc::now();

    // Sign ONCE. The scrub signature covers the canonical ENVELOPE and nothing
    // else, so a flood of rows differing only in `attestation_id` is exactly as
    // valid as a flood of freshly-signed ones — and it is what an abuser would
    // actually do, because signing is the expensive half for them too. (That
    // the top-level columns ride outside the signature is the #541 shape; here
    // it is the attacker's economics, not a defect under test.)
    let template = signed_row(
        &flooder,
        "flood-template",
        attestation_type::SCORES,
        "quota-victim",
        scores_envelope("health:liveness:v1", "quota-victim", 1.0),
        now,
    )
    .await;

    // The burst allowance refills continuously (600 rows / 60 s = 10/s), so a
    // flood that takes T seconds may legitimately land 600 + 10·T rows before
    // the budget bites. The loop therefore runs to a ceiling well above the
    // allowance and asserts the boundary as an inequality — asserting an exact
    // index here would be asserting the machine's speed.
    let ceiling = budget * 4;
    let mut admitted = 0usize;
    let mut rate_limited_at: Option<usize> = None;
    for i in 0..ceiling {
        let mut row = template.clone();
        row.attestation_id = format!("flood-{i}");
        row.asserted_at = now + Duration::milliseconds(i as i64);
        row.scrub_timestamp = row.asserted_at;
        match put(&engine, row).await {
            Ok(()) => admitted += 1,
            Err(FedError::RateLimited { .. }) => {
                rate_limited_at = Some(i);
                break;
            }
            Err(e) => panic!("flood row {i} refused for an unrelated reason: {e:?}"),
        }
    }

    let refused_at = rate_limited_at.expect(
        "the per-peer write quota MUST refuse a single key that floods it — if this never fires \
         the only rate control on the receive plane is dead",
    );
    assert!(
        admitted >= budget,
        "the quota must not refuse BELOW its documented allowance ({budget}); it refused after \
         {admitted} admits at index {refused_at}"
    );
    assert_eq!(
        admitted, refused_at,
        "every write before the refusal was admitted, so the refusal is the boundary and not a \
         hole in the middle of the run"
    );

    // ── and now the half with no reader ────────────────────────────────────
    let observation = engine
        .federation_directory()
        .peer_quota_observation()
        .expect("the sqlite backend holds a quota");
    assert_eq!(
        observation.slot_denials, 0,
        "PIN: the ONLY counter persist exposes is the tail-squeeze tripwire, and a peer being \
         rate-limited on every write does not move it"
    );

    // The REAL composed read the operator sees — not a hand-built struct.
    let self_key = engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id");
    let state = ciris_persist::federation::node_state::resolve_node_state(
        engine.federation_directory().as_ref(),
        ciris_persist::federation::node_state::NodeStateOptions::new(Some(&self_key)),
    )
    .await
    .expect("compose the operator surface's node state");

    assert_eq!(
        ciris_server::operator_surface::PeerQuotaCause::of(&state),
        ciris_server::operator_surface::PeerQuotaCause::Clean,
        "PIN: the operator surface reports `clean` while this node is refusing 100% of a peer's \
         writes. The refusal is correct and NOBODY IS READING IT — the 2026-08-05 shape. When a \
         refusal counter is wired, this assertion is what should go RED."
    );
    assert_eq!(
        state.peer_quota.band,
        ciris_persist::federation::node_state::StateBand::Green,
        "and the band stays GREEN through the flood — there is no reading an operator could \
         have taken that would have shown this"
    );
}
