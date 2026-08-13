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
    algorithm, attestation_tier, attestation_type, cohort_scope, identity_type, Attestation,
    Community, CommunityMember, KeyRecord, SignedAttestation, SignedCommunity, SignedKeyRecord,
};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

use ciris_server::safety::age::{
    gate_content_for, AgeAssurance, AgeBand, AssuranceLevel, ContentClass,
};
use ciris_server::safety::moderation::{self, Duty};
use ciris_server::safety::named::{self, ExistenceVerdict};
use ciris_server::safety::watchlist::{
    self, SeamOutcome, WatchlistClass, WatchlistEnable, WatchlistMode,
};

#[path = "support/revocation.rs"]
mod revocation;
use revocation::revoke;

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
    let node_key_id = engine
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
        &node_key_id,
        "node",
        serde_json::Value::Null,
    )
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
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
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
    let scope: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    let envelope = serde_json::json!({
        "kind": "delegates_to",
        "dimension": "delegation:moderation:v1",
        "attesting_key_id": granter_key_id,
        "attested_key_id": recipient,
        "scope": scope,
        "sub_delegation": sub_delegation,
    });
    let spec = ciris_server::attest::Spec::new(
        attestation_type::DELEGATES_TO,
        ciris_persist::federation::types::cohort_scope::FEDERATION,
        envelope,
    )
    .about(&recipient);
    // Through the ONE door (CIRISServer#402). Hand-rolled beside its envelope, this
    // row carried no signed `asserted_at` and no typed-column mirror — persist v31
    // refuses both (CIRISPersist#598/#643), so the fixture was proving the substrate
    // accepts a shape this server does not produce.
    ciris_server::attest::emit(
        engine,
        ciris_server::attest::KeySigner::Local(&granter),
        spec,
    )
    .await
    .expect("put delegation");
}

/// Make `member` owner-bound: register a `user`-role identity and a live
/// `delegates_to(user → member, infra:*)`. persist's `is_steward_bound` then reads
/// `member` as owner-bound (the named-moderator + auto-promotion eligibility
/// precondition, AND the `put_community` admission precondition for node/agent
/// members). MUST be called BEFORE `put_community`. Returns the owner signer so
/// the caller can later WITHDRAW the binding (the lapse path).
async fn make_owner_bound(engine: &Engine, member: &str) -> LocalSigner {
    let owner_key = format!("{member}-owner");
    let owner = register_party(engine, &owner_key, identity_type::USER).await;
    // user → member: a REAL owner-binding carrying the versioned owner-binding
    // dimension (`ownership:responsible_party:node:v1`) that the substrate's
    // single-owner `owner_of` (#162) keys on — NOT a generic capability
    // delegation. Built via the server's own envelope builder so the test edge is
    // byte-shaped exactly like a claim's owner-binding.
    emit_owner_binding(engine, &owner, member).await;
    owner
}

/// Emit a genuine `delegates_to(owner → member)` owner-binding (the owner-binding
/// dimension `owner_of` requires), reusing the real
/// [`ownership::build_owner_binding_envelope`]. `make_owner_bound`'s predicate now
/// resolves through `owner_of`, which is dimension-precise — a generic
/// `delegation:*` edge (what [`emit_delegation`] emits) is NOT an owner-binding.
async fn emit_owner_binding(engine: &Engine, owner: &LocalSigner, member: &str) {
    // Through the SAME door the server uses (CIRISServer#402). A fixture that
    // hand-rolls the row proves the substrate accepts a shape nothing ships —
    // which is how four binding defects reached a live claim with every gate green.
    let owner_key_id = owner.key_id().to_string();
    ciris_server::attest::emit(
        engine,
        ciris_server::attest::KeySigner::Local(owner),
        ciris_server::attest::Spec::new(
            attestation_type::DELEGATES_TO,
            ciris_persist::federation::types::cohort_scope::FEDERATION,
            ciris_server::auth::ownership::build_owner_binding_envelope(
                &owner_key_id,
                member,
                &["infra:hold_community_membership".to_string()],
            )
            .expect("build owner-binding envelope"),
        )
        .about(member),
    )
    .await
    .expect("put owner-binding");
}

/// Withdraw the owner-binding `owner → member` (the binding lapses → `member`
/// becomes ineligible: not owner-bound, cannot be named or auto-promoted).
async fn withdraw_owner_binding(engine: &Engine, owner: &LocalSigner, member: &str) {
    let owner_key_id = owner.key_id().to_string();
    ciris_server::attest::emit(
        engine,
        ciris_server::attest::KeySigner::Local(owner),
        ciris_server::attest::Spec::new(
            attestation_type::WITHDRAWS,
            ciris_persist::federation::types::cohort_scope::FEDERATION,
            serde_json::json!({
                "kind": "withdraws",
                "dimension": "ownership:withdraw:v1",
                "attesting_key_id": owner_key_id,
                "attested_key_id": member,
            }),
        )
        .about(member),
    )
    .await
    .expect("put owner-binding withdraw");
}

/// Seed `count` `moderation_track_record:{community}` reputation rows authored by
/// `member` (the auto-promotion ranking signal). Uses `attestation_upsert_local`
/// directly — the track-record dimension is NOT admission-gated (unlike a live
/// `moderation:*` ModerationEvent, which requires the author be an admitted
/// duty-holder). This models a member who accrued upheld-action reputation.
///
/// **Returns how many of the `count` rows actually reached FEDERATION tier** —
/// which is where `read_track_record` looks. Every caller asserts on that number
/// rather than assuming it, because "the fixture seeded 3" and "the reader can
/// see 3" turned out to be different facts (CIRISServer#357) and a fixture that
/// cannot tell them apart is how the seam stayed invisible.
async fn seed_track_record(engine: &Engine, member: &str, community: &str, count: usize) -> usize {
    seed_track_record_witnessed(engine, member, community, count, None).await
}

/// [`seed_track_record`] with an explicit `witness_relation` on the envelope
/// (`Some("self")` = the member vouching for its own action, the CC 6.2.3.1 /
/// CC 2.1 anti-gaming case; `None` = the field absent, which CC 2.6.1.2 defaults
/// to `external`).
async fn seed_track_record_witnessed(
    engine: &Engine,
    member: &str,
    community: &str,
    count: usize,
    witness_relation: Option<&str>,
) -> usize {
    use ciris_persist::federation::types::LocalAttestationInput;
    let mut promoted = 0usize;
    for i in 0..count {
        let tag = witness_relation.unwrap_or("default");
        let dimension = format!("moderation_track_record:{community}:{tag}item{i}:v1");
        let mut envelope = serde_json::json!({
            "dimension": dimension,
            "community_id": community,
        });
        if let Some(w) = witness_relation {
            envelope["witness_relation"] = serde_json::json!(w);
        }
        let input = LocalAttestationInput {
            attestation_id: None,
            attesting_key_id: member.to_string(),
            attested_key_id: Some(member.to_string()),
            attestation_type: attestation_type::SCORES.to_string(),
            weight: None,
            expires_at: None,
            attestation_envelope: ciris_persist::federation::envelope::EnvelopeCore::from_value(
                envelope,
            )
            .expect("test envelope is a JSON object"),
            subject_key_ids: vec![member.to_string()],
            cohort_scope: "self".to_string(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        };
        let id = engine
            .federation_directory()
            .attestation_upsert_local(input)
            .await
            .expect("seed track record");
        // Promote so read_track_record (federation-tier reads) sees it.
        //
        // persist v26.0.0 (#589) made `attestation_promote` face the FULL
        // admission stack — it had been re-signing and flipping `tier` without
        // re-running it, which made promotion a path to launder an unauthorized
        // row into federation tier. Correct, and it changes what a fixture may
        // assume.
        //
        // The lapsed-community test is the awkward case: its whole premise is a
        // community with NO live moderator, so the seed cannot satisfy a
        // moderator-bound gate — and granting one would delete the condition
        // under test. `CommunityHasNoModerator` here is therefore the substrate
        // agreeing with the fixture's setup, not rejecting it. Tolerated by
        // NAME so a different refusal still fails loudly; a bare `.ok()` would
        // swallow the next real gate.
        match engine
            .attestation_promote(&id, cohort_scope::FEDERATION)
            .await
        {
            Ok(_) => promoted += 1,
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("has no live `moderate`-duty holder"),
                    "promote track record failed for a reason this fixture does not \
                     deliberately create: {msg}"
                );
            }
        }
    }
    promoted
}

/// Put a community with the given roster. Each `(key_id, role)` is a member;
/// `role` is `"founder"` or `"member"`. `founder_only` consensus by default so
/// the authority set = founders. The community's OWN key is registered as a
/// federation key (a community has an identity) so attestations may name it as
/// `attested_key_id` (the watchlist config is group-keyed).
async fn put_community(engine: &Engine, community_id: &str, members: &[(&str, &str)]) {
    let authority = register_party(engine, community_id, "community").await;
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
    // persist v21.0.0 (#502 E4) — `put_community` now runs
    // `verify_community_admission`: a hybrid signature over
    // JCS(Community::signing_envelope()) by a REGISTERED authority key. No
    // grandfathering, so the fixture signs as the community's own key (registered
    // just above) rather than submitting an unsigned declaration.
    let canonical =
        ceg_produce_canonicalize(&community.signing_envelope()).expect("canonicalize community");
    let sig = authority
        .sign_hybrid(&canonical)
        .await
        .expect("sign community declaration");
    engine
        .federation_directory()
        .put_community(SignedCommunity {
            community,
            authority_key_id: community_id.to_string(),
            scrub_signature_classical: BASE64.encode(&sig.classical.signature),
            scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        })
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
async fn existence_invariant_fails_closed_when_merit_is_unreadable() {
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
    let promoted_high = seed_track_record(&engine, high, community, 3).await;
    let promoted_mid = seed_track_record(&engine, mid, community, 1).await;
    // ── CIRISServer#356/#357: this reads 0, and that is the SUBSTRATE being right ──
    //
    // `read_track_record` walks `list_attestations_by`, which is federation-tier
    // only. persist v26.0.0 (#589) made `attestation_promote` face the full
    // admission stack, and CC 4.5.4 / §11.11 refuses federation for a community
    // with no live `moderate`-duty holder — "better no group than an
    // unmoderated one".
    //
    // A lapsed community IS that state by definition. So the merit signal merit
    // auto-promotion reads cannot reach federation tier in the exact case merit
    // auto-promotion exists for. That is a real design conflict between two
    // correct rules, not a fixture defect, and it was not ours to resolve
    // unilaterally — filed as #356, ruled on as #357.
    //
    // ── WHAT THIS TEST USED TO PIN, AND WHY IT CHANGED ──────────────────────
    //
    // It was written to fail the day the conflict was resolved, pinned at the
    // observed values rather than the intended ones:
    //
    //     read_track_record(high) == 0            (seeded with 3)
    //     auto_promotion_candidate() == Some(..)  and NOT `high`
    //     existence_verdict() == AutoPromote { candidate: "promote-low", .. }
    //
    // `promote-low` — the member with no record at all. Measured, reproduced
    // before the fix: the ranking had silently degraded from "promote the most
    // proven member" to "promote whoever sorts first", wearing an entirely
    // correct AutoPromote shape, with nothing in the verdict to say so.
    //
    // The maintainer ruled options 3+1 (#357): FAIL CLOSED first. The zeroes
    // below still read 0 — that half was never the bug, and #589/§11.11 both
    // stay untouched. What changed is the ANSWER built from them: a merit
    // vector that is all-zero in a community that cannot reach the tier the
    // ledger lives on is now reported as UNREADABLE, not ranked.
    assert_eq!(
        promoted_high, 0,
        "the seam itself: a lapsed community cannot promote its merit rows to \
         federation tier (persist CommunityHasNoModerator). If this is 3, the \
         tier is no longer closed and this whole fixture premise moved."
    );
    assert_eq!(promoted_mid, 0, "same seam for the second seeded member");
    assert_eq!(
        moderation::read_track_record(&engine, high, community).await,
        Ok(0),
        "track record is federation-tier-only and a lapsed community cannot \
         federate — the read is honest, it is the RANKING that must not trust it"
    );
    assert_eq!(
        moderation::read_track_record(&engine, mid, community).await,
        Ok(0)
    );
    assert_eq!(
        moderation::read_track_record(&engine, low, community).await,
        Ok(0)
    );

    // No live moderator (all are bare members).
    assert!(
        !named::community_has_live_moderator(&engine, community)
            .await
            .unwrap(),
        "a roster of bare members has no live moderator"
    );

    // FAIL CLOSED (#357 part 1): no candidate, and a reason that says the
    // instrument was never connected — not that it read nothing.
    let outcome = named::auto_promotion_outcome(&engine, community)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        named::PromotionOutcome::MeritUnreadable {
            reason: moderation::MeritUnreadable::FederationTierClosed {
                community_key_id: community.to_string(),
            },
        },
        "an all-zero merit vector from a community that cannot reach the tier \
         its ledger lives on must be UNREADABLE, never a ranking"
    );
    // The specific thing that used to happen must not: no candidate at all, and
    // above all not `promote-low`, the member with no record.
    assert!(
        !matches!(outcome, named::PromotionOutcome::Candidate { .. }),
        "promoting on unreadable merit is not promoting on merit"
    );

    let verdict = named::existence_verdict(&engine, community).await.unwrap();
    match verdict {
        ExistenceVerdict::Quiesce { hard_case } => {
            assert_eq!(hard_case, named::HARD_CASE_COMMUNITY_MERIT_UNREADABLE);
            // The load-bearing property of #357 part 1: an operator can tell
            // "merit was read and nobody qualified" from "merit could not be
            // read at all". These two facts rendered identically before.
            assert_ne!(
                hard_case,
                named::HARD_CASE_COMMUNITY_UNMODERATED,
                "the unreadable-merit hard_case MUST be distinct from the \
                 nobody-qualified one — they are different facts"
            );
        }
        other => panic!("expected Quiesce (fail-closed on unreadable merit), got {other:?}"),
    }
}

/// #357, the OTHER side of the fail-closed rule: when the merit signal really IS
/// readable, merit auto-promotion still works and still picks the most proven
/// member. Failing closed must not mean failing always.
///
/// The fixture is the realistic ledger-before-the-lapse shape (#357 option 4):
/// the community accrues track records WHILE it has a live moderator — so the
/// rows reach federation tier, asserted here, not assumed — and only then does
/// the moderator's owner-binding lapse.
#[tokio::test]
async fn existence_invariant_auto_promotes_highest_track_record_on_lapse() {
    let engine = node().await;
    let community = "community:lapsed-with-ledger";
    let founder = "ledger-founder"; // the moderator who will later lapse
    let low = "ledger-low";
    let high = "ledger-high";
    let mid = "ledger-mid";
    for m in [founder, low, high, mid] {
        register_party(&engine, m, identity_type::AGENT).await;
    }
    let founder_owner = make_owner_bound(&engine, founder).await;
    for m in [low, high, mid] {
        make_owner_bound(&engine, m).await;
    }
    put_community(
        &engine,
        community,
        &[
            (founder, "founder"),
            (low, "member"),
            (high, "member"),
            (mid, "member"),
        ],
    )
    .await;

    // While the community HAS a moderator its ledger can reach federation tier.
    assert!(
        named::community_has_live_moderator(&engine, community)
            .await
            .unwrap(),
        "the owner-bound founder is a live moderator"
    );
    assert_eq!(
        seed_track_record(&engine, high, community, 3).await,
        3,
        "with a live moderator the merit rows DO reach federation tier"
    );
    assert_eq!(seed_track_record(&engine, mid, community, 1).await, 1);
    // CC 6.2.3.1 / CC 2.1 — `low` self-witnesses 5 actions. They promote fine
    // (the substrate has no opinion on `witness_relation`); the READ excludes
    // them. This is the anti-gaming exclusion biting in the real read path, not
    // just in the pure predicate's unit test.
    assert_eq!(
        seed_track_record_witnessed(&engine, low, community, 5, Some("self")).await,
        5,
        "self-witnessed rows are stored + promoted like any other"
    );

    assert_eq!(
        moderation::read_track_record(&engine, high, community).await,
        Ok(3)
    );
    assert_eq!(
        moderation::read_track_record(&engine, mid, community).await,
        Ok(1)
    );
    assert_eq!(
        moderation::read_track_record(&engine, low, community).await,
        Ok(0),
        "5 self-witnessed rows must count for NOTHING (CC 6.2.3.1 / CC 2.1): a \
         serial self-witness accrues zero promotion standing"
    );

    // Now the moderator LAPSES — its owner-binding is withdrawn, so it is no
    // longer steward-bound and no longer a named moderator.
    withdraw_owner_binding(&engine, &founder_owner, founder).await;
    assert!(
        !named::community_has_live_moderator(&engine, community)
            .await
            .unwrap(),
        "the founder's owner-binding lapsed ⇒ no live moderator"
    );

    // Merit is READABLE (the ledger reached federation tier before the lapse),
    // so the ranking runs and picks the most proven member.
    assert_eq!(
        named::auto_promotion_outcome(&engine, community)
            .await
            .unwrap(),
        named::PromotionOutcome::Candidate {
            key_id: high.to_string(),
            track_record: 3,
        },
        "readable merit ⇒ the highest track record wins, not the first sorted"
    );
    match named::existence_verdict(&engine, community).await.unwrap() {
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

/// #357 — the THIRD answer, and the one that proves the other two are not the
/// same: merit READ, and nobody qualified. Its `hard_case` must be distinct from
/// the unreadable one.
///
/// The tier is OPEN here (the community has a live moderator), so an all-zero
/// merit vector IS a measurement — and the honest answer is "nobody has a track
/// record", never "the ledger is unreachable". This is the guard that keeps the
/// fail-closed rule from over-firing and swallowing a real zero.
#[tokio::test]
async fn merit_read_but_nobody_qualified_is_a_distinct_zero() {
    let engine = node().await;
    let community = "community:no-merit-yet";
    let founder = "nomerit-founder";
    let member = "nomerit-member";
    for m in [founder, member] {
        register_party(&engine, m, identity_type::AGENT).await;
        make_owner_bound(&engine, m).await;
    }
    put_community(
        &engine,
        community,
        &[(founder, "founder"), (member, "member")],
    )
    .await;

    // Tier OPEN: the ledger is reachable, it is simply empty.
    assert!(named::community_has_live_moderator(&engine, community)
        .await
        .unwrap());
    assert_eq!(
        moderation::read_track_record(&engine, member, community).await,
        Ok(0),
        "a real, measured zero — the ledger was consulted"
    );
    let outcome = named::auto_promotion_outcome(&engine, community)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        named::PromotionOutcome::NoQualifiedCandidate,
        "an all-zero vector with the tier OPEN is a finding, not an unread \
         instrument — and a zero-merit member does not qualify for a MERIT \
         promotion (that is the arbitrary pick #357 exists to refuse)"
    );
    assert!(
        !matches!(outcome, named::PromotionOutcome::MeritUnreadable { .. }),
        "a measured zero must never be reported as unreadable"
    );

    // And at the verdict boundary the two zeroes carry DIFFERENT hard_cases.
    assert_ne!(
        named::HARD_CASE_COMMUNITY_UNMODERATED,
        named::HARD_CASE_COMMUNITY_MERIT_UNREADABLE,
        "the whole point: an operator must be able to tell them apart"
    );
}

/// **CIRISServer#357 part 2 (option 1) — WHY THE LOCAL-TIER READ IS HELD.**
///
/// The ruling was 3+1: fail closed, then read track records at LOCAL tier, since
/// "the rows exist; only their tier is blocked". Part 1 landed. Part 2 did not,
/// and this test is the reason, pinned so it cannot quietly stop being true.
///
/// A local-tier row is **producer-asserted end to end**. `attestation_upsert_local`
/// runs no §11.10 moderation-duty admission (persist wires
/// `check_delegated_duty_scores_admission` into `put_attestation`, the
/// FEDERATION door, only), the row carries NO signature (local rows defer it to
/// promote), and every field the counting predicate discriminates on —
/// `dimension`, `community_id`, `witness_relation` — is written by the producer.
/// `POST /v1/auth/attestation` exposes exactly this door to any registered key.
///
/// So a member with no record can mint its own merit, and the forgery is not
/// merely hard to distinguish from the real thing — it is **structurally
/// identical to it**. This test seeds an honest ledger and a forged one and
/// shows every discriminable field matching. There is no predicate to add:
/// the federation tier was not merely *where* the merit signal lived, it was
/// *the entire reason the signal meant anything*. Reading below it reads
/// unauthorized claims.
///
/// The self-witness exclusion (CC 6.2.3.1 / CC 2.1) does not save it either, in
/// two independent ways: `witness_relation` is producer-written, so a forger
/// simply omits it (CC 2.6.1.2 then defaults it to `external`, and it counts);
/// and even a STRUCTURAL exclusion (attester == subject) is sidestepped by
/// fabricating `moderation:*` events that name some other member as subject.
///
/// **What would make part 2 possible** (a follow-up, not this issue): a
/// node-signed admission receipt — at emit time, the gated path
/// (`admit_moderation_action` → `emit_moderation_event`) has already proven the
/// author held the duty; if that proof were recorded under the NODE's key rather
/// than inferred from the row's tier, a local-tier row could carry its own
/// authority and the read could be widened safely. Note it cannot simply be a
/// federation-tier receipt row: a row naming the community hits the same
/// §11.11 refusal, which is the seam all over again.
#[tokio::test]
async fn local_tier_merit_is_producer_asserted_so_the_local_read_stays_held() {
    use ciris_persist::federation::types::LocalAttestationInput;

    let engine = node().await;
    let community = "community:forgeable";
    let honest = "forge-honest";
    let forger = "forge-forger";
    for m in [honest, forger] {
        register_party(&engine, m, identity_type::AGENT).await;
        make_owner_bound(&engine, m).await;
    }
    // Bare members, no founder ⇒ the lapsed state part 2 would be read in.
    put_community(
        &engine,
        community,
        &[(honest, "member"), (forger, "member")],
    )
    .await;
    assert!(!named::community_has_live_moderator(&engine, community)
        .await
        .unwrap());

    // The honest member's ledger: 2 rows, stuck at local tier by the seam.
    assert_eq!(seed_track_record(&engine, honest, community, 2).await, 0);

    // The forger holds NO moderation duty here — the §11.10 gate says so.
    assert!(
        !moderation::admit_moderation_action(&engine, forger, community, Duty::Moderate)
            .await
            .unwrap(),
        "the forger is not admitted to exercise `moderate` in this community"
    );

    // …and yet the LOCAL door accepts its self-minted merit anyway: 3
    // track-record rows AND a `moderation:*` ModerationEvent, the very dimension
    // whose federation-tier writes are duty-gated. No admission, no signature.
    assert_eq!(seed_track_record(&engine, forger, community, 3).await, 0);
    let forged_event = LocalAttestationInput {
        attestation_id: None,
        attesting_key_id: forger.to_string(),
        attested_key_id: Some(forger.to_string()),
        attestation_type: attestation_type::SCORES.to_string(),
        weight: None,
        expires_at: None,
        attestation_envelope: ciris_persist::federation::envelope::EnvelopeCore::from_value(
            serde_json::json!({
                "dimension": "moderation:spam:v1",
                "community_id": community,
            }),
        )
        .unwrap(),
        subject_key_ids: vec![forger.to_string()],
        cohort_scope: "self".to_string(),
        scrub_signature_classical: None,
        scrub_signature_pqc: None,
    };
    engine
        .federation_directory()
        .attestation_upsert_local(forged_event)
        .await
        .expect(
            "THE HOLD: the local write door runs no §11.10 duty gate, so a \
             non-duty-holder mints an admissible-looking ModerationEvent. If this \
             ever fails, the local tier grew an authority boundary and #357 part \
             2 should be revisited.",
        );

    // Read both ledgers back at local tier and compare every field a
    // tier-widened `read_track_record` could discriminate on.
    let local_rows = engine
        .federation_directory()
        .list_local_tier_attestations(None, 1000)
        .await
        .expect("list local tier");
    let counts_for = |key: &str| -> Vec<&ciris_persist::federation::Attestation> {
        local_rows
            .iter()
            .filter(|r| {
                r.attesting_key_id == key
                    && r.attestation_type == attestation_type::SCORES
                    && r.attestation_envelope
                        .get("community_id")
                        .and_then(|v| v.as_str())
                        == Some(community)
            })
            .collect()
    };
    let honest_rows = counts_for(honest);
    let forged_rows = counts_for(forger);
    assert_eq!(honest_rows.len(), 2, "the honest ledger");
    assert_eq!(
        forged_rows.len(),
        4,
        "the forged ledger — MORE merit than the honest member, minted at will"
    );

    for (label, rows) in [("honest", &honest_rows), ("forged", &forged_rows)] {
        for r in rows.iter() {
            let dim = r
                .attestation_envelope
                .get("dimension")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            assert!(
                dim.starts_with("moderation:") || dim.starts_with("moderation_track_record:"),
                "{label}: counts as a moderation signal"
            );
            // CC 2.6.1.2 — no `witness_relation` ⇒ defaults to `external` ⇒ the
            // self-witness exclusion does not fire. The forger just omits it.
            assert!(
                r.attestation_envelope.get("witness_relation").is_none(),
                "{label}: witness_relation is producer-written, and absent here"
            );
            assert_eq!(r.tier, "local", "{label}: local tier");
            assert!(
                r.scrub_signature_classical.is_empty(),
                "{label}: a local row carries NO signature — nothing to verify"
            );
            assert_eq!(
                r.attesting_key_id.as_str(),
                r.attested_key_id.as_str(),
                "{label}: self-asserted, attester == attested"
            );
        }
    }

    // The verdict: on every discriminable field, the honest and the forged rows
    // agree. There is no predicate that admits one and refuses the other, so
    // widening the read to local tier would hand the moderator seat of a
    // moderator-less community to whoever minted the most rows. Part 1's
    // fail-closed answer stands instead.
    assert_eq!(
        named::auto_promotion_outcome(&engine, community)
            .await
            .unwrap(),
        named::PromotionOutcome::MeritUnreadable {
            reason: moderation::MeritUnreadable::FederationTierClosed {
                community_key_id: community.to_string(),
            },
        },
        "with part 2 held, the forger gains NOTHING: unreadable stays unreadable"
    );
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
    assert_eq!(
        named::auto_promotion_outcome(&engine, community)
            .await
            .unwrap(),
        named::PromotionOutcome::NoQualifiedCandidate,
        "no eligible (owner-bound) member ⇒ no auto-promotion candidate. This is \
         a MEASURED nothing — the roster was scanned and named nobody — so it is \
         NOT the #357 unreadable case and must not borrow its hard_case."
    );
    let verdict = named::existence_verdict(&engine, community).await.unwrap();
    match verdict {
        ExistenceVerdict::Quiesce { hard_case } => {
            assert_eq!(hard_case, named::HARD_CASE_COMMUNITY_UNMODERATED);
            assert_ne!(hard_case, named::HARD_CASE_COMMUNITY_MERIT_UNREADABLE);
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
//     `is_steward_bound`/`nodes_stewarded_by` already consume `steward_bindings_of`
//     (this PR's reader collapse); `steward_binding_chain` / `reachable_under_scope`
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

    // steward_bindings_of — the human anchor(s) that owner-bind the node.
    assert_eq!(
        engine
            .steward_bindings_of(node_key)
            .await
            .expect("steward_bindings_of reachable"),
        vec![owner_id.clone()],
        "node owner-bound to the user"
    );
    // steward_binding_chain — the resolving path, anchor-first.
    assert_eq!(
        engine
            .steward_binding_chain(node_key)
            .await
            .expect("steward_binding_chain reachable"),
        vec![owner_id.clone(), node_key.to_string()],
    );
    // reachable_under_scope — the user reaches the node under the granted scope.
    assert!(
        engine
            .reachable_under_scope(&owner_id, node_key, "infra:hold_community_membership", 4)
            .await
            .expect("reachable_under_scope reachable"),
        "owner reaches node under infra:hold_community_membership"
    );
    // The server's collapsed reader (now `owner_of`-backed, #162) agrees, and
    // the inverse projection lists the node under the owner.
    assert_eq!(
        ciris_server::auth::ownership::is_steward_bound(&engine, node_key).await,
        Some(owner_id.clone()),
    );
    assert_eq!(
        ciris_server::auth::ownership::nodes_stewarded_by(&engine, &owner_id).await,
        vec![node_key.to_string()],
    );

    // Withdraw → every reader reflects the lapse (the §11.10 withdraws/recants
    // edge-retraction is folded into steward_bindings_of, so the whole projection
    // collapses, not just the predicate).
    withdraw_owner_binding(&engine, &owner, node_key).await;
    assert!(engine
        .steward_bindings_of(node_key)
        .await
        .unwrap()
        .is_empty());
    assert!(engine
        .steward_binding_chain(node_key)
        .await
        .unwrap()
        .is_empty());
    assert!(
        ciris_server::auth::ownership::is_steward_bound(&engine, node_key)
            .await
            .is_none()
    );
    assert!(
        ciris_server::auth::ownership::nodes_stewarded_by(&engine, &owner_id)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn ceg_dx_active_roster_readers_reachable() {
    let engine = node().await;
    // A member must be owner-bound + registered to satisfy put_community admission.
    register_party(&engine, "ceg-dx-founder", "node").await;
    make_owner_bound(&engine, "ceg-dx-founder").await;
    put_community(
        &engine,
        "ceg-dx-community",
        &[("ceg-dx-founder", "founder")],
    )
    .await;

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

// ════════════════════════════════════════════════════════════════════════════
// (7) INFOHAZARD CONSENT-GATE (CC 4.5.13, CIRISServer#161) — the reveal gate:
//     a substrate-flagged subject is WITHHELD (403 interstitial) until the
//     signed viewer's consent-to-view is on the graph (then 200 allow); a
//     revoked consent re-closes the gate. End-to-end over the real substrate +
//     the `/v1/safety/reveal` HTTP surface.
// ════════════════════════════════════════════════════════════════════════════

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ciris_server::safety::infohazard;
use tower::ServiceExt as _;

/// The [`infohazard::FlagAuthority`] for a suite whose flags are put directly by
/// `flagger` rather than through the router's substrate signer (CIRISServer#363
/// — the reader has to be told whose withdrawal it believes, and these fixtures
/// name their own emitter).
fn authority_of(flagger: &LocalSigner) -> infohazard::FlagAuthority {
    infohazard::FlagAuthority::from_key_ids([flagger.key_id().to_string()])
}

/// Emit a `content_class:{class}` flag on `subject`, signed by a
/// `substrate_persist`-typed flagger.
///
/// **The identity_type is fixture colour, not a gate** (CIRISServer#363): at
/// persist v30.2.0 the family is open vocabulary, so this row would be admitted
/// from ANY key. What decides whether a reader believes it is the reader's own
/// [`infohazard::FlagAuthority`] — see `authority_of`.
async fn flag_subject(engine: &Engine, flagger: &LocalSigner, subject: &str, class: &str) {
    let flagger_key = flagger.key_id().to_string();
    let dimension = format!("content_class:{class}:v1");
    let envelope = serde_json::json!({ "dimension": dimension, "content_class": class });
    let spec = ciris_server::attest::Spec::new(
        attestation_type::SCORES,
        ciris_persist::federation::types::cohort_scope::FEDERATION,
        envelope,
    )
    .about(&subject);
    // Through the ONE door (CIRISServer#402). Hand-rolled beside its envelope, this
    // row carried no signed `asserted_at` and no typed-column mirror — persist v31
    // refuses both (CIRISPersist#598/#643), so the fixture was proving the substrate
    // accepts a shape this server does not produce.
    ciris_server::attest::emit(
        engine,
        ciris_server::attest::KeySigner::Local(&flagger),
        spec,
    )
    .await
    .expect("put content_class flag");
}

/// Emit the viewer's `consent:state:{state}` (`granted`/`revoked`) act naming
/// `{scope:"view", content_class}` against `subject` — the viewer's own signed
/// act, via the existing attestation surface. `secs` offsets `asserted_at` so a
/// later revoke supersedes an earlier grant (the latest-wins fold).
async fn emit_view_consent(
    engine: &Engine,
    viewer: &LocalSigner,
    subject: &str,
    state: &str,
    class: &str,
    secs: i64,
) {
    let viewer_key = viewer.key_id().to_string();
    let now = chrono::Utc::now() + chrono::Duration::seconds(secs);
    let dimension = format!("consent:state:{state}:v1");
    let envelope = serde_json::json!({
        "dimension": dimension,
        "scope": "view",
        "content_class": class,
    });
    let spec = ciris_server::attest::Spec::new(
        attestation_type::SCORES,
        ciris_persist::federation::types::cohort_scope::FEDERATION,
        envelope,
    )
    .about(&subject);
    // Through the ONE door (CIRISServer#402). Hand-rolled beside its envelope, this
    // row carried no signed `asserted_at` and no typed-column mirror — persist v31
    // refuses both (CIRISPersist#598/#643), so the fixture was proving the substrate
    // accepts a shape this server does not produce.
    ciris_server::attest::emit(
        engine,
        ciris_server::attest::KeySigner::Local(&viewer),
        spec,
    )
    .await
    .expect("put view consent");
}

/// `POST /v1/safety/reveal` with a hybrid-signed request from `viewer`.
async fn post_reveal(
    app: &axum::Router,
    viewer: &LocalSigner,
    subject: &str,
) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({ "subject_key_id": subject }).to_string();
    let sig = viewer
        .sign_hybrid(body.as_bytes())
        .await
        .expect("sign body");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/safety/reveal")
                .header("content-type", "application/json")
                .header("x-ciris-signing-key-id", viewer.key_id())
                .header(
                    "x-ciris-signature-ed25519",
                    BASE64.encode(&sig.classical.signature),
                )
                .header(
                    "x-ciris-signature-ml-dsa-65",
                    BASE64.encode(&sig.pqc.signature),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn reveal_unflagged_subject_allows() {
    let engine = node().await;
    let app = ciris_server::safety::router(Arc::clone(&engine), HybridPolicy::Strict, None);
    let viewer = register_party(&engine, "reveal-viewer", identity_type::USER).await;
    let subject = "reveal-clean-subject";
    register_party(&engine, subject, identity_type::USER).await;

    // No flag on the subject ⇒ 200 allow (unflagged is universally visible).
    let (status, body) = post_reveal(&app, &viewer, subject).await;
    assert_eq!(status, StatusCode::OK, "unflagged ⇒ allow; got {body:?}");
    assert_eq!(body["decision"], "allow");
}

#[tokio::test]
async fn reveal_requires_a_signature_401() {
    let engine = node().await;
    let app = ciris_server::safety::router(Arc::clone(&engine), HybridPolicy::Strict, None);
    // No x-ciris-* signature headers ⇒ 401 (every view must be attributable).
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/safety/reveal")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "subject_key_id": "x" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn reveal_flagged_subject_gates_then_allows_after_consent_and_recloses_on_revoke() {
    let engine = node().await;
    let app = ciris_server::safety::router(Arc::clone(&engine), HybridPolicy::Strict, None);

    // The viewer, the flagged subject, and the substrate_persist flagger.
    let viewer = register_party(&engine, "hazard-viewer", identity_type::USER).await;
    let subject = "hazard-subject";
    register_party(&engine, subject, identity_type::USER).await;
    let flagger = register_party(
        &engine,
        "hazard-flagger",
        ciris_persist::federation::types::identity_type::SUBSTRATE_PERSIST,
    )
    .await;

    // Substrate-flag the subject as a potential infohazard.
    flag_subject(&engine, &flagger, subject, "infohazard").await;

    // (a) Flagged, no consent yet ⇒ 403 INTERSTITIAL (the enforcement).
    let (status, body) = post_reveal(&app, &viewer, subject).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "flagged+no-consent ⇒ 403; {body:?}"
    );
    assert_eq!(body["decision"], "interstitial");
    assert_eq!(body["flag"], "infohazard");
    assert_eq!(body["required"]["state"], "consent:state:granted");
    assert_eq!(body["required"]["scope"], "consent:scope:view");
    assert_eq!(body["required"]["content_class"], "infohazard");
    assert!(
        body["prompt"].as_str().is_some(),
        "an interstitial carries a prompt"
    );

    // (b) The viewer emits consent-to-view via the existing attestation surface.
    emit_view_consent(&engine, &viewer, subject, "granted", "infohazard", 10).await;

    // Re-call ⇒ 200 ALLOW (the loop closes; no server-side emit).
    let (status, body) = post_reveal(&app, &viewer, subject).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "flagged+consented ⇒ allow; {body:?}"
    );
    assert_eq!(body["decision"], "allow");

    // (c) A LATER revoke supersedes the grant ⇒ the gate RE-CLOSES (403).
    emit_view_consent(&engine, &viewer, subject, "revoked", "infohazard", 20).await;
    let (status, body) = post_reveal(&app, &viewer, subject).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a revoked consent must re-close the gate; {body:?}"
    );
    assert_eq!(body["decision"], "interstitial");

    // Cross-viewer isolation: a DIFFERENT viewer's read is still gated (the
    // consent is the first viewer's own signed act, not a global unlock).
    let other = register_party(&engine, "hazard-viewer-2", identity_type::USER).await;
    emit_view_consent(&engine, &viewer, subject, "granted", "infohazard", 30).await; // re-grant for viewer 1
    let (s1, _) = post_reveal(&app, &viewer, subject).await;
    assert_eq!(s1, StatusCode::OK, "viewer 1 re-granted ⇒ allow");
    let (s2, _) = post_reveal(&app, &other, subject).await;
    assert_eq!(
        s2,
        StatusCode::FORBIDDEN,
        "viewer 2 never consented ⇒ still gated (consent is per-viewer)"
    );

    // sanity: the pure decision fn agrees with the substrate resolution.
    let d = infohazard::reveal_decision(
        &engine,
        other.key_id(),
        subject,
        None,
        &authority_of(&flagger),
    )
    .await
    .unwrap();
    assert!(matches!(d, infohazard::RevealDecision::Interstitial { .. }));
}

// ════════════════════════════════════════════════════════════════════════════
// (8) PRODUCER HOOK (CC 4.5.13, CIRISServer#181) — POST /v1/safety/flag: a
//     `moderate`-duty holder flags a subject and the NODE's substrate_persist
//     identity emits the `content_class` flag → the #161 reveal gate
//     fires. The producer→gate link, over the REAL /v1/safety/flag endpoint.
// ════════════════════════════════════════════════════════════════════════════

/// Build + register a node-scoped `substrate_persist` signer under its DERIVED
/// federation key_id (what `Engine::emit_attestation` FKs against) — the
/// production shape `compose::register_substrate_key` uses. Returns the signer
/// the flag router holds to author the `content_class:*` flag — and, since
/// CIRISServer#363, the emitter its own reveal gate allowlists.
async fn substrate_signer(engine: &Engine, alias: &str) -> Arc<LocalSigner> {
    let signer = party_signer(alias);
    let key_id = signer.derived_key_id();
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize substrate envelope");
    let sig = signer
        .sign_hybrid(&canonical)
        .await
        .expect("sign substrate registration");
    let record = KeyRecord {
        key_id: key_id.clone(),
        pubkey_ed25519_base64: BASE64.encode(&sig.classical.public_key),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(&sig.pqc.public_key)),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::SUBSTRATE_PERSIST.into(),
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
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register substrate_persist signer");
    Arc::new(signer)
}

/// `POST /v1/safety/flag` with a hybrid-signed request from `signer` acting for
/// `signer_key_id` (the moderator). Returns `(status, body)`.
#[allow(clippy::too_many_arguments)]
async fn post_flag(
    app: &axum::Router,
    signer: &LocalSigner,
    signer_key_id: &str,
    community_key_id: &str,
    subject_key_id: &str,
    content_class: &str,
    action: &str,
) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({
        "signer_key_id": signer_key_id,
        "community_key_id": community_key_id,
        "subject_key_id": subject_key_id,
        "content_class": content_class,
        "action": action,
    })
    .to_string();
    let sig = signer
        .sign_hybrid(body.as_bytes())
        .await
        .expect("sign body");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/safety/flag")
                .header("content-type", "application/json")
                .header("x-ciris-signing-key-id", signer.key_id())
                .header(
                    "x-ciris-signature-ed25519",
                    BASE64.encode(&sig.classical.signature),
                )
                .header(
                    "x-ciris-signature-ml-dsa-65",
                    BASE64.encode(&sig.pqc.signature),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// THE HEADLINE: a Moderate-duty holder flags a subject via the REAL
/// `/v1/safety/flag` endpoint → the substrate emits the `content_class`
/// flag → `subject_flag` now returns `Some(class)` → `/v1/safety/reveal` returns
/// the 403 interstitial for a non-consented viewer. The producer→gate link.
#[tokio::test]
async fn flag_endpoint_makes_the_reveal_gate_fire() {
    let engine = node().await;
    let community = "community:producer";
    let founder = "flag-founder"; // the named moderator (owner-bound)
    register_party(&engine, founder, identity_type::AGENT).await;
    make_owner_bound(&engine, founder).await;
    put_community(&engine, community, &[(founder, "founder")]).await;

    // The node's substrate_persist producer identity (what the router holds) —
    // and, since CIRISServer#363, the ONE emitter whose withdrawal the reveal
    // gate believes. `router` derives the same authority internally.
    let substrate = substrate_signer(&engine, "producer-substrate").await;
    let authority = infohazard::FlagAuthority::of_substrate_signer(&substrate);
    let app = ciris_server::safety::router(
        Arc::clone(&engine),
        HybridPolicy::Strict,
        Some(Arc::clone(&substrate)),
    );

    // The subject to flag + a non-consented viewer.
    let subject = "producer-subject";
    register_party(&engine, subject, identity_type::USER).await;
    let viewer = register_party(&engine, "producer-viewer", identity_type::USER).await;

    // BEFORE the flag: the subject is unflagged ⇒ reveal ALLOWS (the gate is inert).
    assert!(
        infohazard::subject_flag(&engine, subject, None, &authority)
            .await
            .unwrap()
            .is_none(),
        "no flag emitted yet"
    );
    let (pre, _) = post_reveal(&app, &viewer, subject).await;
    assert_eq!(pre, StatusCode::OK, "unflagged subject ⇒ reveal allows");

    // The duty-holder flags the subject through the REAL producer endpoint.
    let founder_signer = party_signer(founder);
    let (status, body) = post_flag(
        &app,
        &founder_signer,
        founder,
        community,
        subject,
        "infohazard",
        "flag",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "duty-holder flag admitted; {body:?}"
    );
    assert_eq!(body["content_class"], "infohazard");
    assert_eq!(body["action"], "flag");
    let flag_id = body["attestation_id"]
        .as_str()
        .expect("attestation id")
        .to_string();

    // THE SUBSTRATE signed it — the emitted row's attesting key is the
    // substrate_persist identity, NEVER the duty-holder.
    let emitter = body["emitter_key_id"].as_str().expect("emitter key id");
    assert_eq!(
        emitter,
        substrate.derived_key_id(),
        "the reserved flag is authored by the substrate_persist identity"
    );
    assert_ne!(
        emitter, founder,
        "the duty-holder does NOT sign the reserved flag"
    );
    let rows = engine
        .federation_directory()
        .list_attestations_for(subject)
        .await
        .unwrap();
    let flag_row = rows
        .iter()
        .find(|r| r.attestation_id == flag_id)
        .expect("the flag row is on the subject");
    assert_eq!(
        flag_row.attesting_key_id,
        substrate.derived_key_id(),
        "attesting_key_id is the substrate emitter"
    );
    let substrate_id_type = engine
        .federation_directory()
        .lookup_public_key(&substrate.derived_key_id())
        .await
        .unwrap()
        .expect("substrate key registered")
        .identity_type;
    assert_eq!(
        substrate_id_type,
        identity_type::SUBSTRATE_PERSIST,
        "the emitter is identity_type = substrate_persist — the production shape. \
         NB this is no longer a persist gate (CIRISServer#363): the family is open \
         vocabulary at v30.2.0 and it is the READ-side FlagAuthority that binds."
    );

    // THE LINK: subject_flag now resolves + the reveal gate FIRES (403).
    assert_eq!(
        infohazard::subject_flag(&engine, subject, None, &authority)
            .await
            .unwrap(),
        Some(infohazard::ContentFlag::Infohazard),
        "the producer made the flag resolvable"
    );
    let (status, body) = post_reveal(&app, &viewer, subject).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "flagged+no-consent ⇒ 403 interstitial (the gate now fires); {body:?}"
    );
    assert_eq!(body["decision"], "interstitial");
    assert_eq!(body["flag"], "infohazard");

    // CLEAR (retain→unflag): the same duty-holder clears the flag → the gate
    // re-opens (the substrate emits a superseding withdrawal; latest-wins fold).
    let (status, body) = post_flag(
        &app,
        &founder_signer,
        founder,
        community,
        subject,
        "infohazard",
        "clear",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "duty-holder clear admitted; {body:?}"
    );
    assert_eq!(body["action"], "clear");
    assert!(
        infohazard::subject_flag(&engine, subject, None, &authority)
            .await
            .unwrap()
            .is_none(),
        "a cleared flag no longer resolves (latest-wins withdrawal fold)"
    );
    let (status, _) = post_reveal(&app, &viewer, subject).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "cleared subject ⇒ reveal allows again"
    );
}

/// A non-duty caller is REFUSED at `/v1/safety/flag` (403) — the flag is a
/// duty-gated act, never assumed (mirrors `moderation`'s fail-secure gate).
#[tokio::test]
async fn flag_endpoint_rejects_a_non_duty_caller() {
    let engine = node().await;
    let community = "community:producer-2";
    let founder = "flag-founder-2";
    register_party(&engine, founder, identity_type::AGENT).await;
    make_owner_bound(&engine, founder).await;
    put_community(&engine, community, &[(founder, "founder")]).await;

    let substrate = substrate_signer(&engine, "producer-substrate-2").await;
    let authority = infohazard::FlagAuthority::of_substrate_signer(&substrate);
    let app =
        ciris_server::safety::router(Arc::clone(&engine), HybridPolicy::Strict, Some(substrate));

    // A stranger who holds no duty and no delegated chain.
    let stranger = register_party(&engine, "flag-stranger", identity_type::AGENT).await;
    let subject = "producer-subject-2";
    register_party(&engine, subject, identity_type::USER).await;

    let (status, body) = post_flag(
        &app,
        &stranger,
        "flag-stranger",
        community,
        subject,
        "infohazard",
        "flag",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a non-duty caller cannot flag; {body:?}"
    );
    // No flag landed on the subject (fail-secure — the gate stays inert).
    assert!(
        infohazard::subject_flag(&engine, subject, None, &authority)
            .await
            .unwrap()
            .is_none(),
        "a rejected flag emits nothing"
    );
}

/// Emit a `consent:state:*` row with EXPLICIT control over whether the envelope
/// names a `scope` / `content_class` at all. `None` on both = the **blanket**
/// stance ("I revoke my consent", unqualified) — the case CIRISServer#243 turns on.
#[allow(clippy::too_many_arguments)]
async fn emit_consent_scoped(
    engine: &Engine,
    viewer: &LocalSigner,
    subject: &str,
    state: &str,
    scope: Option<&str>,
    class: Option<&str>,
    secs: i64,
) {
    let viewer_key = viewer.key_id().to_string();
    let now = chrono::Utc::now() + chrono::Duration::seconds(secs);
    let mut envelope = serde_json::json!({ "dimension": format!("consent:state:{state}:v1") });
    if let Some(sc) = scope {
        envelope["scope"] = serde_json::json!(sc);
    }
    if let Some(c) = class {
        envelope["content_class"] = serde_json::json!(c);
    }
    let spec = ciris_server::attest::Spec::new(
        attestation_type::SCORES,
        ciris_persist::federation::types::cohort_scope::FEDERATION,
        envelope,
    )
    .about(&subject);
    // Through the ONE door (CIRISServer#402). Hand-rolled beside its envelope, this
    // row carried no signed `asserted_at` and no typed-column mirror — persist v31
    // refuses both (CIRISPersist#598/#643), so the fixture was proving the substrate
    // accepts a shape this server does not produce.
    ciris_server::attest::emit(
        engine,
        ciris_server::attest::KeySigner::Local(&viewer),
        spec,
    )
    .await
    .expect("put scoped consent");
}

// ════════════════════════════════════════════════════════════════════════════
// CIRISServer#243 — the SUBSTRATE-RESOLVER EQUIVALENCE TEST.
//
// 0.5.108 deleted this gate's hand-rolled consent fold and routed it through
// persist v16.1.1's `resolve_scoped_consent` (CIRISPersist#389, the DRY-audit H2
// finding). The fold we deleted carried a NAMED, TESTED safety property:
//
//     a scope-less BLANKET `consent:state:revoked` re-closes the gate.
//
// persist v16.1.0's first cut of the scoped resolver DROPPED scope-less rows
// before the latest-wins fold — which would have silently deleted that property:
// a viewer who withdrew ALL consent would have kept the infohazard gate OPEN,
// because an older scoped grant still won. On a CC 4.5.13 child-safety gate that
// is not an acceptable regression, so the adoption was HELD and persist fixed it
// in v16.1.1 (`matches_scoped_query`, asymmetric on stance).
//
// These tests are the reason the property survives the deletion: they exercise
// the REAL substrate resolver end-to-end through `reveal_decision`, so the fold
// can never silently regress in a future substrate bump. Deleting our own tests
// along with our own fold would have left this property untested ANYWHERE.
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn cc_243_blanket_revoke_re_closes_the_infohazard_gate() {
    let engine = node().await;
    let viewer = register_party(&engine, "viewer-blanket", identity_type::USER).await;
    let subject = "subject-blanket";
    register_party(&engine, subject, identity_type::USER).await;
    let flagger = register_party(
        &engine,
        "subject-blanket-flagger",
        ciris_persist::federation::types::identity_type::SUBSTRATE_PERSIST,
    )
    .await;
    flag_subject(&engine, &flagger, subject, "infohazard").await;

    // A scoped grant OPENS the gate.
    emit_consent_scoped(
        &engine,
        &viewer,
        subject,
        "granted",
        Some("view"),
        Some("infohazard"),
        10,
    )
    .await;
    assert!(
        matches!(
            infohazard::reveal_decision(
                &engine,
                viewer.key_id(),
                subject,
                None,
                &authority_of(&flagger),
            )
            .await
            .unwrap(),
            infohazard::RevealDecision::Allow
        ),
        "a scoped view-grant must open the gate"
    );

    // A LATER BLANKET revoke — no scope, no content_class: "I withdraw my consent",
    // unqualified — must RE-CLOSE it. This is the whole point of #243.
    emit_consent_scoped(&engine, &viewer, subject, "revoked", None, None, 20).await;
    assert!(
        matches!(
            infohazard::reveal_decision(
                &engine,
                viewer.key_id(),
                subject,
                None,
                &authority_of(&flagger),
            )
            .await
            .unwrap(),
            infohazard::RevealDecision::Interstitial { .. }
        ),
        "a BLANKET consent:state:revoked MUST re-close the infohazard gate — a viewer \
         who withdraws all consent must not keep seeing flagged material"
    );
}

#[tokio::test]
async fn cc_243_an_unrelated_scope_revoke_does_not_re_close_the_gate() {
    let engine = node().await;
    let viewer = register_party(&engine, "viewer-unrelated", identity_type::USER).await;
    let subject = "subject-unrelated";
    register_party(&engine, subject, identity_type::USER).await;
    let flagger = register_party(
        &engine,
        "subject-unrelated-flagger",
        ciris_persist::federation::types::identity_type::SUBSTRATE_PERSIST,
    )
    .await;
    flag_subject(&engine, &flagger, subject, "infohazard").await;

    emit_consent_scoped(
        &engine,
        &viewer,
        subject,
        "granted",
        Some("view"),
        Some("infohazard"),
        10,
    )
    .await;
    // Revoking an UNRELATED scope (e.g. replication) must NOT collaterally close the
    // view gate. This is the property the scoped resolver exists to give us, and the
    // reason a blanket revoke and a different-scope revoke must be told apart.
    emit_consent_scoped(
        &engine,
        &viewer,
        subject,
        "revoked",
        Some("replication"),
        None,
        20,
    )
    .await;
    assert!(
        matches!(
            infohazard::reveal_decision(
                &engine,
                viewer.key_id(),
                subject,
                None,
                &authority_of(&flagger),
            )
            .await
            .unwrap(),
            infohazard::RevealDecision::Allow
        ),
        "revoking an unrelated scope must NOT re-close the view gate"
    );
}

#[tokio::test]
async fn cc_243_a_scope_less_grant_cannot_back_into_a_view_consent() {
    let engine = node().await;
    let viewer = register_party(&engine, "viewer-bare", identity_type::USER).await;
    let subject = "subject-bare";
    register_party(&engine, subject, identity_type::USER).await;
    let flagger = register_party(
        &engine,
        "subject-bare-flagger",
        ciris_persist::federation::types::identity_type::SUBSTRATE_PERSIST,
    )
    .await;
    flag_subject(&engine, &flagger, subject, "infohazard").await;

    // `granted` is the ONLY fail-OPEN stance, so it must name its scope exactly.
    // A bare `consent:state:granted` must open NOTHING (the asymmetry's other half).
    emit_consent_scoped(&engine, &viewer, subject, "granted", None, None, 10).await;
    assert!(
        matches!(
            infohazard::reveal_decision(
                &engine,
                viewer.key_id(),
                subject,
                None,
                &authority_of(&flagger),
            )
            .await
            .unwrap(),
            infohazard::RevealDecision::Interstitial { .. }
        ),
        "a bare consent:state:granted must NOT back into a scoped view-consent"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// (9) THE READ-SIDE EMITTER PREDICATE (CIRISServer#363) — `content_class:` is
//     OPEN VOCABULARY at persist v30.2.0's write door (CC 3.3.12), so nothing
//     upstream stops an arbitrary admitted key from authoring a flag row. The
//     discrimination is ours, on READ, and it is asymmetric: anyone may impose
//     an interstitial, only an authorised emitter may lift one.
// ════════════════════════════════════════════════════════════════════════════

/// Put a `content_class:{class}:v1` `scores` row on `subject`, authored by
/// `emitter` under its REGISTERED `emitter_key_id`, with `withdrawn` and an
/// `asserted_at` offset of `secs` (so a later withdrawal supersedes an earlier
/// flag under the latest-wins fold).
///
/// This goes through the REAL `put_attestation` door, which re-verifies the
/// hybrid signature against `attesting_key_id`'s registered pubkeys — so every
/// row here is one the substrate actually admits, not a hand-written fixture.
async fn put_content_class_row(
    engine: &Engine,
    emitter: &LocalSigner,
    emitter_key_id: &str,
    subject: &str,
    class: &str,
    withdrawn: bool,
    secs: i64,
) {
    let now = chrono::Utc::now() + chrono::Duration::seconds(secs);
    let dimension = format!("content_class:{class}:v1");
    let mut envelope = serde_json::json!({ "dimension": dimension, "content_class": class });
    if withdrawn {
        envelope["withdrawn"] = serde_json::Value::Bool(true);
    }
    let spec = ciris_server::attest::Spec::new(
        attestation_type::SCORES,
        ciris_persist::federation::types::cohort_scope::FEDERATION,
        envelope,
    )
    .about(subject);
    // Through the ONE door (CIRISServer#402). Hand-rolled beside its envelope, this
    // row carried no signed `asserted_at` and no typed-column mirror — persist v31
    // refuses both (CIRISPersist#598/#643), so the fixture was proving the substrate
    // accepts a shape this server does not produce.
    //
    // Stamped AT `now` rather than at wall-clock: `secs` is what orders these rows
    // under the latest-wins fold, and the stamp writes the instant the signature
    // covers — so a fixture that let it default would be testing an arbitrary order.
    //
    // The attester is `emitter_key_id`, NOT the signer's own `key_id()`: the
    // substrate emitter is registered — and matched by `FlagAuthority` — under its
    // DERIVED id, while its `LocalSigner` still answers with the bare alias.
    let row = ciris_server::attest::Emit::stamp_at(emitter_key_id, spec, now)
        .expect("stamp content_class row")
        .sign_and_assemble(ciris_server::attest::KeySigner::Local(emitter))
        .await
        .expect("sign content_class row");
    ciris_server::attest::put(engine, row)
        .await
        .expect("put content_class row");
}

/// Flag `subject` from the node's own authorised substrate emitter.
async fn authorised_flag(engine: &Engine, substrate: &LocalSigner, subject: &str, secs: i64) {
    put_content_class_row(
        engine,
        substrate,
        &substrate.derived_key_id(),
        subject,
        "infohazard",
        false,
        secs,
    )
    .await;
}

/// **THE ATTACK (CIRISServer#363).** An ordinary admitted `agent`-typed key
/// authors `content_class:infohazard:v1 {"withdrawn": true}` naming a subject it
/// never flagged. The flag MUST survive, and the reveal gate MUST stay closed.
///
/// Verified RED against the pre-fix fold, driven end-to-end through the real
/// `put_attestation` door: the attacker's row was ADMITTED by persist v30.2.0
/// (the family is open vocabulary) and `subject_flag` returned `None`.
#[tokio::test]
async fn cc363_an_agent_key_cannot_clear_a_flag_it_did_not_set() {
    let engine = node().await;
    let subject = "cc363-subject";
    register_party(&engine, subject, identity_type::USER).await;
    let viewer = register_party(&engine, "cc363-viewer", identity_type::USER).await;

    // The node's own substrate flag producer — the one authorised emitter.
    let substrate = substrate_signer(&engine, "cc363-substrate").await;
    let authority = infohazard::FlagAuthority::of_substrate_signer(&substrate);
    authorised_flag(&engine, &substrate, subject, 0).await;
    assert_eq!(
        infohazard::subject_flag(&engine, subject, None, &authority)
            .await
            .unwrap(),
        Some(infohazard::ContentFlag::Infohazard),
        "the authorised emitter's flag resolves"
    );

    // THE ATTACK: a plain admitted agent key withdraws a flag it did not set.
    // Note the row is ADMITTED by the substrate — nothing upstream refuses it.
    let attacker = register_party(&engine, "cc363-attacker", identity_type::AGENT).await;
    put_content_class_row(
        &engine,
        &attacker,
        "cc363-attacker",
        subject,
        "infohazard",
        true,
        60,
    )
    .await;

    assert_eq!(
        infohazard::subject_flag(&engine, subject, None, &authority)
            .await
            .unwrap(),
        Some(infohazard::ContentFlag::Infohazard),
        "an agent-typed stranger CLEARED a child-safety flag it did not set \
         (CIRISServer#363 — the fail-open)"
    );
    // And the whole gate, not just the flag resolver, stays closed.
    assert!(
        matches!(
            infohazard::reveal_decision(&engine, viewer.key_id(), subject, None, &authority)
                .await
                .unwrap(),
            infohazard::RevealDecision::Interstitial { .. }
        ),
        "the reveal gate must not open on a forged withdrawal"
    );
}

/// The escape hatch an `identity_type` check would have left open: at v30.2.0
/// `substrate_persist` is SELF-ASSERTED (`conferral_mode` =
/// `DerivedFromVerifiedState`, and the only enforcement loop covers
/// `AccordCoScrubbed` claims — an empty set at this version). So an attacker
/// simply registers under that identity_type instead of `agent`. The predicate
/// is `attesting_key_id` membership, which this cannot fake.
#[tokio::test]
async fn cc363_a_self_declared_substrate_persist_key_cannot_clear_either() {
    let engine = node().await;
    let subject = "cc363-idtype-subject";
    register_party(&engine, subject, identity_type::USER).await;
    let substrate = substrate_signer(&engine, "cc363-idtype-substrate").await;
    let authority = infohazard::FlagAuthority::of_substrate_signer(&substrate);
    authorised_flag(&engine, &substrate, subject, 0).await;

    // The attacker registers itself as `substrate_persist` — self-assertable,
    // and persist admits the registration.
    let impostor =
        register_party(&engine, "cc363-impostor", identity_type::SUBSTRATE_PERSIST).await;
    assert_eq!(
        engine
            .federation_directory()
            .lookup_public_key("cc363-impostor")
            .await
            .unwrap()
            .expect("impostor registered")
            .identity_type,
        identity_type::SUBSTRATE_PERSIST,
        "the impostor really does carry the privileged identity_type"
    );
    put_content_class_row(
        &engine,
        &impostor,
        "cc363-impostor",
        subject,
        "infohazard",
        true,
        60,
    )
    .await;

    assert_eq!(
        infohazard::subject_flag(&engine, subject, None, &authority)
            .await
            .unwrap(),
        Some(infohazard::ContentFlag::Infohazard),
        "a key that merely CALLS ITSELF substrate_persist cleared the flag — \
         the predicate must be key identity, not a self-asserted identity_type"
    );
}

/// Not a fix-by-breaking-the-feature: the authorised emitter can still SET and
/// still CLEAR, and the gate follows both ways.
#[tokio::test]
async fn cc363_the_authorised_emitter_can_still_set_and_clear() {
    let engine = node().await;
    let subject = "cc363-legit-subject";
    register_party(&engine, subject, identity_type::USER).await;
    let viewer = register_party(&engine, "cc363-legit-viewer", identity_type::USER).await;
    let substrate = substrate_signer(&engine, "cc363-legit-substrate").await;
    let authority = infohazard::FlagAuthority::of_substrate_signer(&substrate);

    // SET.
    authorised_flag(&engine, &substrate, subject, 0).await;
    assert_eq!(
        infohazard::subject_flag(&engine, subject, None, &authority)
            .await
            .unwrap(),
        Some(infohazard::ContentFlag::Infohazard),
        "the authorised emitter can still flag"
    );
    assert!(matches!(
        infohazard::reveal_decision(&engine, viewer.key_id(), subject, None, &authority)
            .await
            .unwrap(),
        infohazard::RevealDecision::Interstitial { .. }
    ));

    // CLEAR — the same emitter, a newer row.
    put_content_class_row(
        &engine,
        &substrate,
        &substrate.derived_key_id(),
        subject,
        "infohazard",
        true,
        60,
    )
    .await;
    assert_eq!(
        infohazard::subject_flag(&engine, subject, None, &authority)
            .await
            .unwrap(),
        None,
        "the authorised emitter can still CLEAR — the feature is intact"
    );
    assert_eq!(
        infohazard::reveal_decision(&engine, viewer.key_id(), subject, None, &authority)
            .await
            .unwrap(),
        infohazard::RevealDecision::Allow,
        "a legitimately cleared subject reveals again"
    );
}

/// **FAIL CLOSED.** A node with no substrate flag signer wired has an EMPTY
/// authority — it cannot evaluate ANY emitter as authorised. The subject stays
/// flagged: "we could not check" is not "it is fine". This is the real
/// production shape (`router(.., None)` leaves `/v1/safety/flag` 503-inert).
#[tokio::test]
async fn cc363_an_unevaluable_emitter_leaves_the_subject_flagged() {
    let engine = node().await;
    let subject = "cc363-failclosed-subject";
    register_party(&engine, subject, identity_type::USER).await;
    let viewer = register_party(&engine, "cc363-failclosed-viewer", identity_type::USER).await;
    let substrate = substrate_signer(&engine, "cc363-failclosed-substrate").await;

    authorised_flag(&engine, &substrate, subject, 0).await;
    // The withdrawal is from the emitter that WOULD be authorised on a wired
    // node — the only thing missing is our ability to evaluate it.
    put_content_class_row(
        &engine,
        &substrate,
        &substrate.derived_key_id(),
        subject,
        "infohazard",
        true,
        60,
    )
    .await;

    let unevaluable = infohazard::FlagAuthority::none();
    assert!(unevaluable.is_empty());
    assert_eq!(
        infohazard::subject_flag(&engine, subject, None, &unevaluable)
            .await
            .unwrap(),
        Some(infohazard::ContentFlag::Infohazard),
        "an unevaluable emitter must NOT clear — the subject stays flagged"
    );
    assert!(
        matches!(
            infohazard::reveal_decision(&engine, viewer.key_id(), subject, None, &unevaluable)
                .await
                .unwrap(),
            infohazard::RevealDecision::Interstitial { .. }
        ),
        "and the gate stays closed"
    );
    // The SAME rows under a wired authority DO clear — so the assertion above
    // is about the authority, not about some unrelated defect in the fixture.
    let wired = infohazard::FlagAuthority::of_substrate_signer(&substrate);
    assert_eq!(
        infohazard::subject_flag(&engine, subject, None, &wired)
            .await
            .unwrap(),
        None,
        "the identical rows clear once the emitter CAN be evaluated"
    );
}

/// An authorised emitter whose key has been REVOKED loses the authority: a
/// rotated-out substrate key must not keep clearing child-safety flags.
#[tokio::test]
async fn cc363_a_revoked_authority_key_can_no_longer_clear() {
    let engine = node().await;
    let subject = "cc363-revoked-subject";
    register_party(&engine, subject, identity_type::USER).await;
    let substrate = substrate_signer(&engine, "cc363-revoked-substrate").await;
    let authority = infohazard::FlagAuthority::of_substrate_signer(&substrate);

    authorised_flag(&engine, &substrate, subject, 0).await;
    put_content_class_row(
        &engine,
        &substrate,
        &substrate.derived_key_id(),
        subject,
        "infohazard",
        true,
        60,
    )
    .await;
    // Before the revocation the clear lands (the control).
    assert_eq!(
        infohazard::subject_flag(&engine, subject, None, &authority)
            .await
            .unwrap(),
        None,
        "control: the live authorised emitter clears"
    );

    // The substrate emitter's key is revoked, effective now.
    let revoker = register_party(&engine, "cc363-revoker", identity_type::USER).await;
    revoke(
        &engine,
        &revoker,
        &substrate.derived_key_id(),
        chrono::Utc::now(),
        None,
    )
    .await;

    assert_eq!(
        infohazard::subject_flag(&engine, subject, None, &authority)
            .await
            .unwrap(),
        Some(infohazard::ContentFlag::Infohazard),
        "a REVOKED emitter's withdrawal must stop clearing — the flag returns"
    );
}

/// The deliberate asymmetry, pinned as a property so it cannot drift silently:
/// an UNauthorised emitter's flag still protects (over-withholding is this
/// gate's safe direction, and dropping peer-replicated flags would open it),
/// while the local authorised emitter can always lift what a stranger imposed.
#[tokio::test]
async fn cc363_an_unauthorised_set_still_protects_and_stays_liftable() {
    let engine = node().await;
    let subject = "cc363-asym-subject";
    register_party(&engine, subject, identity_type::USER).await;
    let substrate = substrate_signer(&engine, "cc363-asym-substrate").await;
    let authority = infohazard::FlagAuthority::of_substrate_signer(&substrate);

    // A stranger FLAGS. Protective, so it counts.
    let stranger = register_party(&engine, "cc363-asym-stranger", identity_type::AGENT).await;
    put_content_class_row(
        &engine,
        &stranger,
        "cc363-asym-stranger",
        subject,
        "infohazard",
        false,
        0,
    )
    .await;
    assert_eq!(
        infohazard::subject_flag(&engine, subject, None, &authority)
            .await
            .unwrap(),
        Some(infohazard::ContentFlag::Infohazard),
        "an unauthorised SET still withholds — the safe direction"
    );

    // ...and the stranger cannot undo its own flag.
    put_content_class_row(
        &engine,
        &stranger,
        "cc363-asym-stranger",
        subject,
        "infohazard",
        true,
        60,
    )
    .await;
    assert_eq!(
        infohazard::subject_flag(&engine, subject, None, &authority)
            .await
            .unwrap(),
        Some(infohazard::ContentFlag::Infohazard),
        "clearing is STRICTER than flagging — not even the setter may lift it"
    );

    // The local duty-holder's emitter CAN lift it — the censorship residual is
    // remediable, which is what makes the asymmetry acceptable.
    put_content_class_row(
        &engine,
        &substrate,
        &substrate.derived_key_id(),
        subject,
        "infohazard",
        true,
        120,
    )
    .await;
    assert_eq!(
        infohazard::subject_flag(&engine, subject, None, &authority)
            .await
            .unwrap(),
        None,
        "the authorised emitter lifts what a stranger imposed"
    );
}
