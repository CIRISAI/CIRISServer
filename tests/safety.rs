//! The substrate SAFETY FOUNDATION (CIRISServer#20) — integration tests over the
//! real persist v9.0.0 substrate.
//!
//! Proves the load-bearing properties of `src/safety/*`:
//!
//!   - **age-gate** (§4.2): a minor is BLOCKED from adult `content_class`, an
//!     adult is allowed; misdeclaration NEVER slashes (it is a value, not a
//!     punishment).
//!   - **moderation duty admission** (§11.10, composed): a duty-holder OR a live
//!     delegated `moderate` chain is ADMITTED; a non-holder is REJECTED.
//!   - **named-moderator existence invariant** (CC 4.5.4): a community with a
//!     live moderator OPERATES; on lapse, merit auto-promotion picks the highest
//!     track-record eligible member; with NO eligible member the community MUST
//!     NOT federate (fail-secure → quiesce).
//!   - **watchlist** (CC 4.5.7): enable is `moderate`-gated (CSAM also
//!     `takedown`), is per-group (bound to the group's `moderate` scope, never
//!     global), and the publish hook is opt-in (OFF ⇒ admit; ON ⇒ deferred to the
//!     NodeCore matcher, never a faked match).

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::types::{
    algorithm, attestation_tier, attestation_type, identity_type, Attestation, Community,
    CommunityMember, KeyRecord, SignedAttestation, SignedCommunity, SignedKeyRecord,
};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

use ciris_server::safety::age::{
    gate_content_for, AgeAssurance, AgeBand, AssuranceLevel, ContentClass,
};
use ciris_server::safety::moderation::{self, Duty};
use ciris_server::safety::named::{self, ExistenceVerdict};
use ciris_server::safety::watchlist::{
    self, SeamOutcome, WatchlistClass, WatchlistEnable, WatchlistMode,
};

const NODE_KEY_ID: &str = "ciris-safety-node";

// ─── substrate + identity helpers (mirror tests/ownership.rs) ───────────────

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
    let engine = Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer (sqlite::memory:)"),
    );
    // Register the node's OWN key (the engine's signer) so `attestation_promote`
    // — which co-signs with the node key (scrub_key_id = node) — satisfies the
    // FK. In production `compose.rs::register_self_key` does this at boot.
    register_node_self(&engine).await;
    engine
}

/// Register the node's own federation key (the engine's hybrid signer), so
/// federation-tier rows the node co-signs (promotions) satisfy the FK.
///
/// v9.3.0 (#247): `attestation_promote` now writes `scrub_key_id =
/// engine.local_derived_key_id()` = `derive_key_id(<alias>, <pubkey>)` — the
/// DERIVED wire key_id, never the raw alias — so the node must register under
/// that derived id for the promote FK to resolve. This mirrors prod, where
/// `compose.rs::register_self_key` registers `cfg.key_id = derive_key_id(
/// keystore_alias, ed_pub)` at boot. (Pre-v9.3.0 promote wrote the bare alias,
/// so the fixture registered under the literal `NODE_KEY_ID`.)
async fn register_node_self(engine: &Engine) {
    let now = chrono::Utc::now();
    let node_key_id = engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id");
    let envelope = serde_json::json!({ "key_id": node_key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize node envelope");
    let sig = engine.sign_hybrid(&canonical).await.expect("node sign");
    let record = KeyRecord {
        key_id: node_key_id.clone(),
        pubkey_ed25519_base64: BASE64.encode(&sig.classical.public_key),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(&sig.pqc.public_key)),
        algorithm: algorithm::HYBRID.into(),
        identity_type: "node".into(),
        identity_ref: node_key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: node_key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .register_federation_key(SignedKeyRecord { record })
        .await
        .expect("register node self key");
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

/// A party's hybrid `LocalSigner`, matching [`register_party`]'s keys.
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

/// Register a party with its REAL hybrid pubkeys under `identity_type`. Returns
/// the matching signer.
async fn register_party(engine: &Engine, key_id: &str, identity_type_str: &str) -> LocalSigner {
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
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize party envelope");
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: ed_pub,
        pubkey_ml_dsa_65_base64: Some(mldsa_pub),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type_str.to_string(),
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
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register signed party key");
    signer
}

/// Emit a signed `delegates_to(granter → recipient)` carrying `scopes` (the
/// envelope `scope` array the §11.10 walk reads). Signed by the GRANTER (attester
/// == signer, the v9.0.0 federation-tier ingest shape). `sub_delegation` controls
/// whether the recipient may further-delegate (the §11.10 deputization gate).
async fn emit_delegation(
    engine: &Engine,
    granter: &LocalSigner,
    recipient: &str,
    scopes: &[&str],
    sub_delegation: bool,
) {
    let granter_key_id = granter.key_id().to_string();
    let now = chrono::Utc::now();
    let scope: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    let envelope = serde_json::json!({
        "kind": "delegates_to",
        "dimension": "delegation:moderation:v1",
        "attesting_key_id": granter_key_id,
        "attested_key_id": recipient,
        "scope": scope,
        "sub_delegation": sub_delegation,
    });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize delegation");
    let sig = granter
        .sign_hybrid(&canonical)
        .await
        .expect("sign delegation");
    let attestation = Attestation {
        attestation_id: format!("deleg-{granter_key_id}-{recipient}-{}", scopes.join("_")),
        attesting_key_id: granter_key_id.clone(),
        attested_key_id: recipient.to_string(),
        attestation_type: attestation_type::DELEGATES_TO.to_string(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: granter_key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: vec![recipient.to_string()],
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
    };
    engine
        .federation_directory()
        .put_attestation(SignedAttestation { attestation })
        .await
        .expect("put delegation");
}

/// Make `member` owner-bound: register a `user`-role identity and a live
/// `delegates_to(user → member, infra:*)`. persist's `is_owner_bound` then reads
/// `member` as owner-bound (the named-moderator + auto-promotion eligibility
/// precondition, AND the `put_community` admission precondition for node/agent
/// members). MUST be called BEFORE `put_community`. Returns the owner signer so
/// the caller can later WITHDRAW the binding (the lapse path).
async fn make_owner_bound(engine: &Engine, member: &str) -> LocalSigner {
    let owner_key = format!("{member}-owner");
    let owner = register_party(engine, &owner_key, identity_type::USER).await;
    // user → member, infra-only (the CC 3.2 owner-binding the predicate reads).
    emit_delegation(engine, &owner, member, &["infra:membership"], false).await;
    owner
}

/// Withdraw the owner-binding `owner → member` (the binding lapses → `member`
/// becomes ineligible: not owner-bound, cannot be named or auto-promoted).
async fn withdraw_owner_binding(engine: &Engine, owner: &LocalSigner, member: &str) {
    let owner_key_id = owner.key_id().to_string();
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({
        "kind": "withdraws",
        "dimension": "ownership:withdraw:v1",
        "attesting_key_id": owner_key_id,
        "attested_key_id": member,
    });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize withdraw");
    let sig = owner.sign_hybrid(&canonical).await.expect("sign withdraw");
    let attestation = Attestation {
        attestation_id: format!("ownwd-{owner_key_id}-{member}"),
        attesting_key_id: owner_key_id.clone(),
        attested_key_id: member.to_string(),
        attestation_type: attestation_type::WITHDRAWS.to_string(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: owner_key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: vec![member.to_string()],
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
    };
    engine
        .federation_directory()
        .put_attestation(SignedAttestation { attestation })
        .await
        .expect("put owner-binding withdraw");
}

/// Seed `count` `moderation_track_record:{community}` reputation rows authored by
/// `member` (the auto-promotion ranking signal). Uses `attestation_upsert_local`
/// directly — the track-record dimension is NOT admission-gated (unlike a live
/// `moderation:*` ModerationEvent, which requires the author be an admitted
/// duty-holder). This models a member who accrued upheld-action reputation.
async fn seed_track_record(engine: &Engine, member: &str, community: &str, count: usize) {
    use ciris_persist::federation::types::LocalAttestationInput;
    for i in 0..count {
        let dimension = format!("moderation_track_record:{community}:item{i}:v1");
        let input = LocalAttestationInput {
            attesting_key_id: member.to_string(),
            attested_key_id: Some(member.to_string()),
            attestation_type: attestation_type::SCORES.to_string(),
            weight: None,
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "dimension": dimension,
                "community_id": community,
            }),
            subject_key_ids: vec![member.to_string()],
            cohort_scope: "self".to_string(),
        };
        let id = engine
            .federation_directory()
            .attestation_upsert_local(input)
            .await
            .expect("seed track record");
        // Promote so read_track_record (federation-tier reads) sees it.
        engine
            .attestation_promote(&id)
            .await
            .expect("promote track record");
    }
}

/// Put a community with the given roster. Each `(key_id, role)` is a member;
/// `role` is `"founder"` or `"member"`. `founder_only` consensus by default so
/// the authority set = founders. The community's OWN key is registered as a
/// federation key (a community has an identity) so attestations may name it as
/// `attested_key_id` (the watchlist config is group-keyed).
async fn put_community(engine: &Engine, community_id: &str, members: &[(&str, &str)]) {
    register_party(engine, community_id, "community").await;
    let now = chrono::Utc::now();
    let roster: Vec<CommunityMember> = members
        .iter()
        .enumerate()
        .map(|(i, (k, role))| CommunityMember {
            key_id: k.to_string(),
            joined_at: now + chrono::Duration::seconds(i as i64),
            role: Some(role.to_string()),
        })
        .collect();
    let community = Community {
        community_key_id: community_id.to_string(),
        community_name: format!("test-{community_id}"),
        members: roster,
        founded_at: now,
        consensus_protocol: "founder_only".to_string(),
        policy_blob: None,
        persist_row_hash: String::new(),
    };
    engine
        .federation_directory()
        .put_community(SignedCommunity { community })
        .await
        .expect("put_community");
}

// ════════════════════════════════════════════════════════════════════════════
// (1) AGE-GATE — minor blocked from adult content_class; adult allowed; the
//     gate is a visibility decision and NEVER slashes.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn age_gate_blocks_minor_from_adult_allows_adult() {
    let minor = AgeAssurance {
        band: AgeBand::Minor,
        level: AssuranceLevel::SelfDeclared,
    };
    let adult = AgeAssurance {
        band: AgeBand::Adult,
        level: AssuranceLevel::SelfDeclared,
    };
    // The protective default: a minor cannot see adult content; an adult can.
    assert!(
        !gate_content_for(minor, ContentClass::Adult),
        "minor blocked from adult"
    );
    assert!(
        gate_content_for(adult, ContentClass::Adult),
        "adult allowed adult"
    );
    // General content is visible to everyone (protective, not prudish).
    assert!(gate_content_for(minor, ContentClass::General));
    assert!(gate_content_for(adult, ContentClass::General));
}

#[tokio::test]
async fn age_assurance_emit_read_roundtrip_and_misdeclaration_does_not_slash() {
    let engine = node().await;
    let subject = "age-subject";
    register_party(&engine, subject, identity_type::USER).await;

    // No assurance on record → read None; the protective viewer default is minor.
    assert!(ciris_server::safety::age::read_age_level(&engine, subject)
        .await
        .is_none());
    let viewer = ciris_server::safety::age::viewer_or_minor(&engine, subject).await;
    assert_eq!(
        viewer.band,
        AgeBand::Minor,
        "unknown viewer defaults protective"
    );

    // Emit a self-declared adult assurance, then read it back.
    ciris_server::safety::age::emit_age_assurance(
        &engine,
        subject,
        AssuranceLevel::SelfDeclared,
        AgeBand::Adult,
    )
    .await
    .expect("emit age assurance");
    let read = ciris_server::safety::age::read_age_level(&engine, subject)
        .await
        .expect("assurance on record");
    assert_eq!(read.band, AgeBand::Adult);
    assert_eq!(read.level, AssuranceLevel::SelfDeclared);

    // MISDECLARATION DOES NOT SLASH: re-declaring a different band is just an
    // upsert of a value — no slashing attestation is produced. The misdeclaration
    // path is `moderation:age_assurance_misdeclaration` (adjudication), never
    // `slashing:*` alone.
    ciris_server::safety::age::emit_age_assurance(
        &engine,
        subject,
        AssuranceLevel::SelfDeclared,
        AgeBand::Minor,
    )
    .await
    .expect("re-declare (no slash)");
    // No `slashing:*` row exists for the subject.
    let rows = engine
        .sqlite_backend()
        .unwrap()
        .list_attestations_by(subject)
        .await
        .unwrap();
    assert!(
        !rows.iter().any(|r| r
            .attestation_envelope
            .get("dimension")
            .and_then(|v| v.as_str())
            .is_some_and(|d| d.starts_with("slashing:"))),
        "a misdeclaration must NEVER produce a slashing attestation"
    );
    assert_eq!(
        ciris_server::safety::age::MISDECLARATION_ALLEGATION,
        "age_assurance_misdeclaration"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// (2) MODERATION DUTY ADMISSION — duty-holder OR delegated chain admitted;
//     non-holder rejected (the §11.10 admit-iff gate, composed).
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn moderation_admission_duty_holder_and_delegate_admitted_nonholder_rejected() {
    let engine = node().await;
    let community = "community:moderated";
    let founder = "mod-founder"; // the named moderator (founder, owner-bound)
    let delegate = "mod-delegate"; // a party the founder delegates `moderate` to
    let stranger = "mod-stranger"; // holds no duty, no chain

    // Register the parties.
    register_party(&engine, founder, identity_type::AGENT).await;
    register_party(&engine, delegate, identity_type::AGENT).await;
    register_party(&engine, stranger, identity_type::AGENT).await;

    // The founder is owner-bound (the named-moderator predicate requires it,
    // AND put_community requires node/agent members be owner-bound).
    make_owner_bound(&engine, founder).await;
    // The community: the founder is the authority root (founder_only consensus).
    put_community(&engine, community, &[(founder, "founder")]).await;

    // (a) The founder is a named moderator → ADMITTED as-self for `moderate`.
    assert!(
        moderation::admit_moderation_action(&engine, founder, community, Duty::Moderate)
            .await
            .unwrap(),
        "the owner-bound founder holds the duty (as-self admit)"
    );

    // (b) A stranger holds no duty and no chain → REJECTED (absence never admits).
    assert!(
        !moderation::admit_moderation_action(&engine, stranger, community, Duty::Moderate)
            .await
            .unwrap(),
        "a non-holder with no delegated chain is rejected (fail-secure)"
    );

    // (c) The founder delegates `moderate` to the delegate → the delegate is now
    //     ADMITTED via a live scoped chain.
    let founder_signer = party_signer(founder);
    emit_delegation(&engine, &founder_signer, delegate, &["moderate"], false).await;
    assert!(
        moderation::admit_moderation_action(&engine, delegate, community, Duty::Moderate)
            .await
            .unwrap(),
        "a live moderate-scoped delegation from the duty-holder admits the delegate"
    );

    // (d) Scope isolation: the delegate holds `moderate`, NOT `takedown`.
    assert!(
        !moderation::admit_moderation_action(&engine, delegate, community, Duty::Takedown)
            .await
            .unwrap(),
        "a moderate-only chain cannot drive a takedown (per-edge scope isolation)"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// (3) NAMED-MODERATOR EXISTENCE INVARIANT (CC 4.5.4) — operate / auto-promote /
//     fail-secure.
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn existence_invariant_operates_with_a_live_moderator() {
    let engine = node().await;
    let community = "community:has-mod";
    let founder = "exist-founder";
    register_party(&engine, founder, identity_type::AGENT).await;
    make_owner_bound(&engine, founder).await;
    put_community(&engine, community, &[(founder, "founder")]).await;

    assert!(
        named::community_has_live_moderator(&engine, community)
            .await
            .unwrap(),
        "a community with an owner-bound founder has a live named moderator"
    );
    let verdict = named::existence_verdict(&engine, community).await.unwrap();
    assert_eq!(
        verdict,
        ExistenceVerdict::Operate {
            moderator_present: true
        }
    );
}

#[tokio::test]
async fn existence_invariant_auto_promotes_highest_track_record_on_lapse() {
    let engine = node().await;
    let community = "community:lapsed";
    // Three eligible (owner-bound) members, NONE of whom is a named moderator yet
    // (member-role, no moderate delegation) → the community has no live moderator
    // and must auto-promote by merit.
    let low = "promote-low";
    let high = "promote-high";
    let mid = "promote-mid";
    for m in [low, high, mid] {
        register_party(&engine, m, identity_type::AGENT).await;
        make_owner_bound(&engine, m).await;
    }
    // All members (not founders) so none is an authority root → no live moderator
    // (founder_only consensus ⇒ authority set = founders = ∅ here).
    put_community(
        &engine,
        community,
        &[(low, "member"), (high, "member"), (mid, "member")],
    )
    .await;

    // Seed track-record: `high` has the most, `mid` fewer, `low` none. These are
    // `moderation_track_record:{community}` reputation rows (the upheld-action
    // ledger a prior moderator accrued — it survives the lapse of their
    // `moderate` standing, which is exactly the signal merit auto-promotion
    // reads after a moderator steps down).
    seed_track_record(&engine, high, community, 3).await;
    seed_track_record(&engine, mid, community, 1).await;
    assert_eq!(
        moderation::read_track_record(&engine, high, community).await,
        3
    );
    assert_eq!(
        moderation::read_track_record(&engine, mid, community).await,
        1
    );
    assert_eq!(
        moderation::read_track_record(&engine, low, community).await,
        0
    );

    // No live moderator (all are bare members) → the verdict auto-promotes the
    // highest track-record eligible member.
    assert!(
        !named::community_has_live_moderator(&engine, community)
            .await
            .unwrap(),
        "a roster of bare members has no live moderator"
    );
    let candidate = named::auto_promotion_candidate(&engine, community)
        .await
        .unwrap();
    assert_eq!(
        candidate.as_deref(),
        Some(high),
        "merit auto-promotion picks the highest moderation_track_record"
    );
    let verdict = named::existence_verdict(&engine, community).await.unwrap();
    match verdict {
        ExistenceVerdict::AutoPromote {
            candidate_key_id,
            hard_case,
        } => {
            assert_eq!(candidate_key_id, high);
            assert_eq!(hard_case, named::HARD_CASE_COMMUNITY_MODERATOR_PROMOTED);
        }
        other => panic!("expected AutoPromote, got {other:?}"),
    }
}

#[tokio::test]
async fn existence_invariant_fails_secure_when_no_eligible_member() {
    let engine = node().await;
    let community = "community:unmoderatable";
    // The community was admitted with owner-bound members (put_community requires
    // it), but then EVERY owner-binding LAPSES (withdrawn) — the realistic
    // fail-secure path: a legitimate community whose accountable owners all
    // departed. No member is now owner-bound ⇒ none is eligible to be named or
    // auto-promoted ⇒ the community MUST fail secure (quiesce).
    let n1 = "lapse-node-1";
    let n2 = "lapse-node-2";
    register_party(&engine, n1, identity_type::AGENT).await;
    register_party(&engine, n2, identity_type::AGENT).await;
    let o1 = make_owner_bound(&engine, n1).await;
    let o2 = make_owner_bound(&engine, n2).await;
    put_community(&engine, community, &[(n1, "founder"), (n2, "member")]).await;

    // Sanity: while owned, the founder n1 IS a live moderator (operate).
    assert!(
        named::community_has_live_moderator(&engine, community)
            .await
            .unwrap(),
        "while owned, the owner-bound founder is a live moderator"
    );

    // Now BOTH owner-bindings lapse → no eligible member remains.
    withdraw_owner_binding(&engine, &o1, n1).await;
    withdraw_owner_binding(&engine, &o2, n2).await;

    assert!(
        !named::community_has_live_moderator(&engine, community)
            .await
            .unwrap(),
        "no owner-bound member ⇒ no live moderator"
    );
    assert!(
        named::auto_promotion_candidate(&engine, community)
            .await
            .unwrap()
            .is_none(),
        "no eligible (owner-bound) member ⇒ no auto-promotion candidate"
    );
    let verdict = named::existence_verdict(&engine, community).await.unwrap();
    match verdict {
        ExistenceVerdict::Quiesce { hard_case } => {
            assert_eq!(hard_case, named::HARD_CASE_COMMUNITY_UNMODERATED);
        }
        other => panic!("expected Quiesce (fail-secure), got {other:?}"),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// (4) WATCHLIST — enable is moderate-gated (CSAM also takedown), per-group not
//     global, and the publish hook is opt-in (OFF ⇒ admit; ON ⇒ deferred).
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn watchlist_enable_is_moderate_gated_and_per_group() {
    let engine = node().await;
    let community_a = "community:wl-a";
    let community_b = "community:wl-b";
    let mod_a = "wl-mod-a"; // moderator of A only
    let stranger = "wl-stranger";

    register_party(&engine, mod_a, identity_type::AGENT).await;
    register_party(&engine, stranger, identity_type::AGENT).await;
    register_party(&engine, "wl-other", identity_type::AGENT).await;
    make_owner_bound(&engine, mod_a).await;
    make_owner_bound(&engine, "wl-other").await;
    put_community(&engine, community_a, &[(mod_a, "founder")]).await;
    // Community B is moderated by a DIFFERENT founder — mod_a holds no authority
    // over it (the per-group, never-global property).
    put_community(&engine, community_b, &[("wl-other", "founder")]).await;

    let other_list = WatchlistEnable {
        group_key_id: community_a.to_string(),
        watchlist_id: "tos:banned-symbols".to_string(),
        class: WatchlistClass::OtherContent,
        enabled: true,
        mode: WatchlistMode::AlertOnly,
        route_to_moderator: Some(mod_a.to_string()),
    };

    // The moderator of A may enable a non-CSAM watchlist for A (moderate-gated).
    assert!(
        watchlist::authority_admits_enable(&engine, mod_a, &other_list)
            .await
            .unwrap(),
        "the moderator of A may enable a watchlist for A"
    );
    // A stranger (no moderate over A) may NOT.
    assert!(
        !watchlist::authority_admits_enable(&engine, stranger, &other_list)
            .await
            .unwrap(),
        "a non-moderator may not enable a watchlist"
    );
    // PER-GROUP, NOT GLOBAL: the SAME moderator may not enable for community B
    // (they hold no `moderate` over B).
    let for_b = WatchlistEnable {
        group_key_id: community_b.to_string(),
        ..other_list.clone()
    };
    assert!(
        !watchlist::authority_admits_enable(&engine, mod_a, &for_b)
            .await
            .unwrap(),
        "enabling is per-group — A's moderator cannot enable a watchlist over B"
    );
}

#[tokio::test]
async fn watchlist_csam_additionally_requires_takedown() {
    let engine = node().await;
    let community = "community:wl-csam";
    // `mod_only` is a founder owner-bound → holds `moderate` (as-self), but a
    // founder authority root natively holds ALL the community's duties as-self
    // (duty_holders_for_community materializes the owner-bound authority roots
    // regardless of duty). So a CSAM enable by the founder is admitted.
    let founder = "csam-founder";
    register_party(&engine, founder, identity_type::AGENT).await;
    make_owner_bound(&engine, founder).await;
    put_community(&engine, community, &[(founder, "founder")]).await;

    let csam = WatchlistEnable {
        group_key_id: community.to_string(),
        watchlist_id: "csam:ncmec".to_string(),
        class: WatchlistClass::Csam,
        enabled: true,
        mode: WatchlistMode::Enforce,
        route_to_moderator: None,
    };
    // The founder authority root holds both moderate and takedown as-self.
    assert!(
        watchlist::authority_admits_enable(&engine, founder, &csam)
            .await
            .unwrap(),
        "the founder authority root holds moderate AND takedown as-self → CSAM enable admitted"
    );

    // A delegate granted ONLY `moderate` (not `takedown`) may enable a non-CSAM
    // list but NOT a CSAM list (CSAM auto-files a takedown → needs takedown).
    let deleg = "csam-moderate-only";
    register_party(&engine, deleg, identity_type::AGENT).await;
    let founder_signer = party_signer(founder);
    emit_delegation(&engine, &founder_signer, deleg, &["moderate"], false).await;
    let other = WatchlistEnable {
        watchlist_id: "tos:list".to_string(),
        class: WatchlistClass::OtherContent,
        ..csam.clone()
    };
    assert!(
        watchlist::authority_admits_enable(&engine, deleg, &other)
            .await
            .unwrap(),
        "a moderate-only delegate may enable a non-CSAM watchlist"
    );
    assert!(
        !watchlist::authority_admits_enable(&engine, deleg, &csam)
            .await
            .unwrap(),
        "a moderate-only delegate may NOT enable a CSAM watchlist (needs takedown)"
    );
}

#[tokio::test]
async fn watchlist_publish_hook_is_opt_in_and_defers_the_matcher() {
    let engine = node().await;
    let community = "community:wl-hook";
    let founder = "hook-founder";
    register_party(&engine, founder, identity_type::AGENT).await;
    make_owner_bound(&engine, founder).await;
    put_community(&engine, community, &[(founder, "founder")]).await;

    // OPT-IN: no watchlist enabled → the publish hook admits (matcher not run).
    assert_eq!(
        watchlist::on_publish(&engine, community).await,
        SeamOutcome::Admit,
        "opt-in default OFF: no enable ⇒ admit"
    );

    // Enable a watchlist for the group.
    let enable = WatchlistEnable {
        group_key_id: community.to_string(),
        watchlist_id: "csam:ncmec".to_string(),
        class: WatchlistClass::Csam,
        enabled: true,
        mode: WatchlistMode::Enforce,
        route_to_moderator: None,
    };
    assert!(
        watchlist::authority_admits_enable(&engine, founder, &enable)
            .await
            .unwrap()
    );
    watchlist::enable_watchlist(&engine, founder, &enable)
        .await
        .expect("enable watchlist");

    // The enable is on the record (auditable, never silent).
    let enables = watchlist::watchlist_enables_for_group(&engine, community).await;
    assert_eq!(enables.len(), 1);
    assert_eq!(enables[0].watchlist_id, "csam:ncmec");

    // With a watchlist ON but NO matcher installed, the hook DEFERS — it does not
    // fake a match and does not silently admit unscanned content (the matcher +
    // the content seam land with NodeCore).
    assert_eq!(
        watchlist::on_publish(&engine, community).await,
        SeamOutcome::DeferredNoMatcher,
        "enabled watchlist with no matcher ⇒ deferred (honest, not faked)"
    );

    // Disable (a withdraws) → consent requires revocability → the hook admits.
    watchlist::disable_watchlist(&engine, founder, community, "csam:ncmec")
        .await
        .expect("disable watchlist");
    assert!(
        watchlist::watchlist_enables_for_group(&engine, community)
            .await
            .is_empty(),
        "a withdrawn enable drops out (revocable)"
    );
    assert_eq!(
        watchlist::on_publish(&engine, community).await,
        SeamOutcome::Admit,
        "after disable ⇒ admit again"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// (6) CEG-DX READER REACHABILITY (CIRISPersist#249 Cut B) — prove the v9.3.0
//     graph readers are reachable through ciris-server's Engine, so future
//     consumers compose them instead of re-deriving the walks. Mirrors the
//     CIRISEdge v6.2.0 adoption's active_roster / delegation_reads e2e proofs.
//     `is_owner_bound`/`nodes_owned_by` already consume `owner_bindings_of`
//     (this PR's reader collapse); `owner_binding_chain` / `reachable_under_scope`
//     / `active_{community,family}_members` are proven reachable here for the
//     consumers that will fold onto them next.
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn ceg_dx_owner_binding_readers_reachable_and_retraction_aware() {
    let engine = node().await;
    let node_key = "ceg-dx-node-a";
    register_party(&engine, node_key, "node").await;
    // user → node, infra-only owner-binding (make_owner_bound emits the edge).
    let owner = make_owner_bound(&engine, node_key).await;
    let owner_id = owner.key_id().to_string();

    // owner_bindings_of — the human anchor(s) that owner-bind the node.
    assert_eq!(
        engine
            .owner_bindings_of(node_key)
            .await
            .expect("owner_bindings_of reachable"),
        vec![owner_id.clone()],
        "node owner-bound to the user"
    );
    // owner_binding_chain — the resolving path, anchor-first.
    assert_eq!(
        engine
            .owner_binding_chain(node_key)
            .await
            .expect("owner_binding_chain reachable"),
        vec![owner_id.clone(), node_key.to_string()],
    );
    // reachable_under_scope — the user reaches the node under the granted scope.
    assert!(
        engine
            .reachable_under_scope(&owner_id, node_key, "infra:membership", 4)
            .await
            .expect("reachable_under_scope reachable"),
        "owner reaches node under infra:membership"
    );
    // The server's collapsed reader (now owner_bindings_of-backed) agrees, and
    // the inverse projection lists the node under the owner.
    assert_eq!(
        ciris_server::auth::ownership::is_owner_bound(&engine, node_key).await,
        Some(owner_id.clone()),
    );
    assert_eq!(
        ciris_server::auth::ownership::nodes_owned_by(&engine, &owner_id).await,
        vec![node_key.to_string()],
    );

    // Withdraw → every reader reflects the lapse (the §11.10 withdraws/recants
    // edge-retraction is folded into owner_bindings_of, so the whole projection
    // collapses, not just the predicate).
    withdraw_owner_binding(&engine, &owner, node_key).await;
    assert!(engine
        .owner_bindings_of(node_key)
        .await
        .unwrap()
        .is_empty());
    assert!(engine
        .owner_binding_chain(node_key)
        .await
        .unwrap()
        .is_empty());
    assert!(ciris_server::auth::ownership::is_owner_bound(&engine, node_key)
        .await
        .is_none());
    assert!(ciris_server::auth::ownership::nodes_owned_by(&engine, &owner_id)
        .await
        .is_empty());
}

#[tokio::test]
async fn ceg_dx_active_roster_readers_reachable() {
    let engine = node().await;
    // A member must be owner-bound + registered to satisfy put_community admission.
    register_party(&engine, "ceg-dx-founder", "node").await;
    make_owner_bound(&engine, "ceg-dx-founder").await;
    put_community(&engine, "ceg-dx-community", &[("ceg-dx-founder", "founder")]).await;

    // active_community_members = roster − effective membership revocations.
    let members = engine
        .active_community_members("ceg-dx-community")
        .await
        .expect("active_community_members reachable");
    assert!(
        members.iter().any(|m| m.key_id == "ceg-dx-founder"),
        "active roster includes the founder; got {members:?}"
    );

    // active_family_members is wired through the Engine too. It fail-CLOSES on an
    // unknown family (InvalidArgument, not a silent empty roster) — the point is
    // the reader is reachable for future consumers, with the correct fail-closed
    // contract.
    assert!(
        engine
            .active_family_members("ceg-dx-no-such-family")
            .await
            .is_err(),
        "active_family_members reachable + fail-closed on an unknown family"
    );
}
