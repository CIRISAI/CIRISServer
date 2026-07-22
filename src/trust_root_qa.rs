//! TEST-ANCHOR-ONLY QA (release/0.5.133-genesis) — **mint a portable trust
//! root (accord + canonical) in substrate test mode, then USE it**, asserting
//! the exact end-state so this module is the acceptance gate for the next
//! persist repin.
//!
//! # What it builds ([`mint_portable_root`])
//!
//! Three SOFTWARE accord holders (A1/B1/C1, minted from three distinct seeds
//! exactly the way `src/test_bless.rs::mint_test_root` derives the SW root:
//! Ed25519 seed → domain-separated SHA-256 → ML-DSA-65 seed), keyed as the
//! synthesized test-anchor roster (`test-accord-holder-{i}`) and armed via
//! `CIRIS_TEST_TRUST_ROOT` / `CIRIS_TEST_TRUST_ROOT_PQC` so persist's
//! `effective_accord_holder_records()` IS this roster. On top of them:
//!
//! - the **canonical**: a `canonical,node` record carrying
//!   `roles: ["infra:serve"]` INSIDE the scrub-signed `registration_envelope`
//!   (CIRISVerify#185), genuinely **2-of-3 co-scrubbed** (A1 base scrub + B1
//!   `append_scrub`) and admitted through persist's REAL m-of-n canonical
//!   admission gate (`put_public_key` → `check_canonical_role_admission`);
//! - the **charter**: `delegates_to(root → root,
//!   scope [infra:attest, infra:serve, infra:store, infra:transport])`;
//! - the **grant**: `delegates_to(root → canonical, scope [infra:serve])`;
//! - the **trust edge**: `delegates_to(user → root)` — the user's own act.
//!
//! Every attestation is a REAL bound-hybrid signature (Ed25519 over
//! `JCS(envelope)`, ML-DSA-65 over `JCS ‖ ed_sig`) so the rows pass the
//! CC 5.3.2.4.3.1 federation-tier ingest gate — nothing here is stubbed.
//!
//! # The three test tiers
//!
//! 1. **Green today** — the mint works: the fixture produces a self-verifying
//!    portable genesis and the conferral rides the signed envelope.
//! 2. **Gap-documenting** — assert TODAY'S broken behavior (CIRISPersist#486
//!    envelope roles never lifted; CIRISPersist#488 vouch-only root accepted +
//!    edge expiry ignored). These FLIP red on the fixed-triple repin — the
//!    failure message tells you which acceptance test to un-ignore.
//! 3. **`#[ignore]` acceptance gates** — the states the fixed triple must
//!    reach. Run them with:
//!    `cargo test --lib --features "extension-module test-anchor" trust_root_qa -- --ignored`
//!
//! # Env hygiene
//!
//! Env vars are process-global; every test here funnels through
//! [`mint_portable_root`], which holds a module-local async mutex for the
//! fixture's whole lifetime and snapshot-restores every var it touches
//! (mirrors verify-core's `test_anchor::ENV_LOCK` discipline, which is
//! `pub(crate)` there and thus unreachable from this crate).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use ciris_persist::federation::admission::has_effective_role;
use ciris_persist::federation::trust_root::{capability_roots_to_trusted_root, trust_root_valid};
use ciris_persist::federation::trust_root::{pre_rotation_commitment, CHARTER_PRE_ROTATION_FIELD};
use ciris_persist::federation::types::delegation_scope::{
    INFRA_ATTEST, INFRA_SERVE, INFRA_STORE, INFRA_TRANSPORT,
};
use ciris_persist::federation::types::{
    attestation_tier, attestation_type, identity_type, Attestation, SignedAttestation,
};
use ciris_persist::federation::{FederationDirectory, SignedKeyRecord};
use ciris_persist::store::MemoryBackend;
use ciris_verify_core::federation_self_record::{
    append_scrub, produce_scrubbed_key_record, produce_self_key_record, ScrubTarget,
    SignedKeyRecord as VerifySignedKeyRecord,
};
use ciris_verify_core::self_at_login::{HybridSigningIdentity, SelfSigner};

use crate::mesh_genesis::{attach_genesis, produce_genesis, verify_bundle};

/// The delegation-plane trust root: accord holder A1, keyed as the synthesized
/// test-anchor roster id so the effective roster and our signer correspond.
const ROOT: &str = "test-accord-holder-0";
/// The full synthesized holder roster; `HOLDER_IDS[0]` is [`ROOT`]. B1/C1 are
/// the keys the root charter pre-commits to as its successors (#488 delta 1).
const HOLDER_IDS: [&str; 3] = [
    "test-accord-holder-0",
    "test-accord-holder-1",
    "test-accord-holder-2",
];
/// The 2-of-3-scrubbed serve node.
const CANONICAL: &str = "qa-canonical-1";
/// The user who signs the `delegates_to(user → root)` trust edge.
const USER: &str = "qa-user-1";
/// A SECOND root that can only VOUCH (`infra:attest`, no serve) — the
/// CIRISPersist#488 probe.
const VOUCH_ROOT: &str = "qa-vouch-root";
/// Deterministic `valid_from` for every minted key record (clock-free bytes).
const VALID_FROM: &str = "2026-07-01T00:00:00Z";

/// Serializes every test in this module: they all mutate the process-global
/// test-anchor env vars. Async so a guard held across the fixture's awaits is
/// sound (a `std` guard across `.await` trips `clippy::await_holding_lock`).
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Every env var this module (or the machinery it arms) reads. The
/// `ENVIRONMENT`/`CIRIS_ENV*` trio is verify's anti-production tripwire —
/// cleared so a developer shell can't silently disarm the test anchor.
const QA_ENV_VARS: &[&str] = &[
    "CIRIS_TESTING_MODE",
    "CIRIS_TEST_TRUST_ROOT",
    "CIRIS_TEST_TRUST_ROOT_PQC",
    "CIRIS_TEST_TRUST_ROOT_SCRUB",
    "CIRIS_TEST_TRUST_ROOT_SCRUB_PQC",
    "CIRIS_TEST_TRUST_ROOT_SEED",
    "ENVIRONMENT",
    "CIRIS_ENV",
    "CIRIS_ENVIRONMENT",
];

/// RAII env sandbox: snapshot + clear on entry, restore on drop — a test can
/// never leak `CIRIS_TESTING_MODE` (or inherit a stale anchor) into a sibling.
struct EnvSandbox {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvSandbox {
    fn capture_and_clear() -> Self {
        let saved = QA_ENV_VARS
            .iter()
            .map(|v| (*v, std::env::var(v).ok()))
            .collect();
        for v in QA_ENV_VARS {
            std::env::remove_var(v);
        }
        Self { saved }
    }
}

impl Drop for EnvSandbox {
    fn drop(&mut self) {
        for (k, v) in &self.saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}

/// A deterministic per-label Ed25519 seed (domain-separated, so QA seeds can
/// never collide with a harness `CIRIS_TEST_TRUST_ROOT_SEED`).
fn qa_seed(label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ciris-server/trust-root-qa/ed-seed/v1/");
    h.update(label.as_bytes());
    h.finalize().into()
}

/// Mint a SW hybrid identity from an Ed25519 seed — the exact
/// `test_bless::mint_test_root` derivation: the ML-DSA-65 seed is a
/// domain-separated SHA-256 of the Ed seed, so the whole identity comes from
/// ONE 32-byte secret.
fn seeded_identity(key_id: &str, ed_seed: [u8; 32]) -> HybridSigningIdentity {
    use ciris_crypto::{Ed25519Signer, MlDsa65Signer};
    let ml_seed: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"ciris-test-trust-root/mldsa/v1");
        h.update(ed_seed);
        h.finalize().into()
    };
    let ed = Ed25519Signer::from_seed(&ed_seed).expect("qa ed25519 seed");
    let mldsa = MlDsa65Signer::from_seed(&ml_seed).expect("qa ml-dsa-65 seed");
    HybridSigningIdentity::new(key_id.to_string(), ed, mldsa)
}

/// Convert a verify-produced record into persist's wire shape (the same
/// serde round-trip `test_bless::maybe_test_bless_self` adopts through).
fn to_persist(rec: &VerifySignedKeyRecord) -> SignedKeyRecord {
    serde_json::from_value(serde_json::to_value(rec).expect("verify record -> json"))
        .expect("verify record -> persist SignedKeyRecord")
}

/// Build a REAL bound-hybrid-signed federation-tier [`Attestation`] row —
/// Ed25519 over `ceg_produce_canonicalize(envelope)`, ML-DSA-65 over the bound
/// `canonical ‖ ed_sig` — exactly what persist's CC 5.3.2.4.3.1 ingest gate
/// Strict-verifies against the attester's REGISTERED pubkeys.
async fn sign_row(
    id: &str,
    attester: &HybridSigningIdentity,
    attested_key_id: &str,
    ty: &str,
    envelope: serde_json::Value,
    asserted_at: chrono::DateTime<chrono::Utc>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Attestation {
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .expect("canonicalize attestation envelope");
    let (ed_b64, pqc_b64) = attester
        .sign_bound(&canonical)
        .await
        .expect("bound-hybrid sign attestation envelope");
    Attestation {
        attestation_id: id.to_string(),
        attesting_key_id: attester.key_id().to_string(),
        attested_key_id: attested_key_id.to_string(),
        attestation_type: ty.to_string(),
        weight: Some(1.0),
        asserted_at,
        expires_at,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: ed_b64,
        scrub_signature_pqc: Some(pqc_b64),
        scrub_key_id: attester.key_id().to_string(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: Some(asserted_at),
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
    }
}

/// A signed **charter** — the self-referential `delegates_to(root → root)`
/// whose envelope `scope` is the domain's capability ceiling. persist
/// v19.0.0 (#488 delta 1, the KERI lesson) REFUSES a charter that does not
/// pre-commit to its successor key set: without it, compromise of the
/// charter key is unrecoverable by construction — the attacker owns the
/// tombstoning pen and a self-referential root has no superior to appeal
/// to. `successors` are the keys pre-committed to rotate this charter (here
/// the OTHER two accord holders — the m-of-n recovery shape).
async fn signed_charter(
    id: &str,
    root: &HybridSigningIdentity,
    root_key_id: &str,
    scope: serde_json::Value,
    successors: &[String],
) -> Attestation {
    let commitment = pre_rotation_commitment(successors).expect("pre-rotation commitment computes");
    let envelope = serde_json::json!({
        "references_attestation_id": id,
        "scope": scope,
        CHARTER_PRE_ROTATION_FIELD: commitment,
    });
    sign_row(
        id,
        root,
        root_key_id,
        attestation_type::DELEGATES_TO,
        envelope,
        chrono::Utc::now(),
        None,
    )
    .await
}

/// A signed `delegates_to(granter → grantee)` carrying `scope` in the
/// envelope — the trust-graph edge shape `trust_root_valid` walks.
async fn signed_delegates_to(
    id: &str,
    granter: &HybridSigningIdentity,
    grantee_key_id: &str,
    scope: serde_json::Value,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Attestation {
    let envelope = serde_json::json!({
        "references_attestation_id": id,
        "scope": scope,
    });
    sign_row(
        id,
        granter,
        grantee_key_id,
        attestation_type::DELEGATES_TO,
        envelope,
        chrono::Utc::now(),
        expires_at,
    )
    .await
}

/// A fresh, signed `accord:lifecycle:v1` `scores` row about `about_key_id`.
/// The attester must be an `accord_holder` (the `accord:*` × `accord_holder`
/// admission asymmetry) — pass one of the fixture holders.
async fn signed_lifecycle(
    id: &str,
    holder: &HybridSigningIdentity,
    about_key_id: &str,
) -> Attestation {
    let envelope = serde_json::json!({
        "id": id,
        "dimension": ciris_persist::federation::trust_root::ACCORD_LIFECYCLE_DIMENSION,
        "score": 1.0,
        "confidence": 0.9,
    });
    sign_row(
        id,
        holder,
        about_key_id,
        attestation_type::SCORES,
        envelope,
        chrono::Utc::now(),
        None,
    )
    .await
}

async fn put_att(dir: &MemoryBackend, row: Attestation) {
    let id = row.attestation_id.clone();
    dir.put_attestation(SignedAttestation { attestation: row })
        .await
        .unwrap_or_else(|e| panic!("attestation {id} must admit: {e}"));
}

/// The minted portable root — records, signers, and the directory they are
/// seeded into. Holds the env sandbox + module lock for its whole lifetime
/// (field order matters: `_env` restores the env BEFORE `_serialized` frees
/// the next test).
struct PortableRoot {
    dir: MemoryBackend,
    /// A1/B1/C1 — `test-accord-holder-{0,1,2}`; `holders[0]` is [`ROOT`].
    holders: Vec<HybridSigningIdentity>,
    user: HybridSigningIdentity,
    /// The canonical in verify's producer shape (for `roles_in_envelope()`).
    canonical_verify: VerifySignedKeyRecord,
    /// The same canonical in persist's wire shape (genesis serve candidate).
    canonical: SignedKeyRecord,
    _env: EnvSandbox,
    _serialized: tokio::sync::MutexGuard<'static, ()>,
}

/// **The fixture** — mint the whole portable trust root in substrate test
/// mode and seed it into a fresh directory through persist's REAL admission
/// gates (nothing is inserted behind the gates' backs).
async fn mint_portable_root() -> PortableRoot {
    let serialized = ENV_LOCK.lock().await;
    let env = EnvSandbox::capture_and_clear();

    // (1) Three SW accord holders from three distinct seeds, keyed as the
    // synthesized test-anchor roster ids so scrubs they sign verify against
    // the seeded rows.
    let holders: Vec<HybridSigningIdentity> = (0..3)
        .map(|i| {
            seeded_identity(
                &format!("test-accord-holder-{i}"),
                qa_seed(&format!("holder-{i}")),
            )
        })
        .collect();

    // (2) Arm the test anchor: ed pubkeys → CIRIS_TEST_TRUST_ROOT (the
    // verify/persist shared runtime gate), ML-DSA pubkeys →
    // CIRIS_TEST_TRUST_ROOT_PQC so the synthesized holder rows are
    // PQC-COMPLETE and the 2-of-3 co-scrub Strict-verifies (persist#451).
    let mut ed_pubs = Vec::with_capacity(3);
    let mut ml_pubs = Vec::with_capacity(3);
    for h in &holders {
        ed_pubs.push(B64.encode(h.ed25519_public_key().await.expect("holder ed pubkey")));
        ml_pubs.push(B64.encode(h.mldsa65_public_key().await.expect("holder ml-dsa pubkey")));
    }
    std::env::set_var("CIRIS_TESTING_MODE", "true");
    std::env::set_var("CIRIS_TEST_TRUST_ROOT", ed_pubs.join(","));
    std::env::set_var("CIRIS_TEST_TRUST_ROOT_PQC", ml_pubs.join(","));

    // (3) Fresh directory, seeded with the EFFECTIVE (synthesized) holder
    // roster — the same rows the admission quorum resolves pubkeys from.
    let dir = MemoryBackend::new();
    let holder_rows =
        ciris_persist::federation::genesis::effective_accord_holder_records().into_owned();
    assert_eq!(
        holder_rows.len(),
        3,
        "the armed test anchor must synthesize exactly the 3 QA holders \
         (a baked-roster fallback here means the runtime gate did not engage)"
    );
    for r in &holder_rows {
        assert!(
            r.record.key_id.starts_with("test-accord-holder-"),
            "effective roster must be the SYNTHESIZED holders, got {}",
            r.record.key_id
        );
        assert!(
            r.record.pubkey_ml_dsa_65_base64.is_some(),
            "holder {} must be PQC-complete (CIRIS_TEST_TRUST_ROOT_PQC armed)",
            r.record.key_id
        );
        dir.put_public_key(r.clone())
            .await
            .unwrap_or_else(|e| panic!("seed holder {}: {e}", r.record.key_id));
    }

    // (4) The canonical: A1 scrubs a `canonical,node` target whose envelope
    // carries the accord-attested `roles: ["infra:serve"]` (CIRISVerify#185),
    // B1 co-scrubs the SAME bytes → 2-of-3. `put_public_key` then runs the
    // REAL m-of-n canonical admission gate against the live roster — the
    // fixture only holds if the conferral ceremony genuinely verifies.
    let canonical_id = seeded_identity(CANONICAL, qa_seed("canonical"));
    let target = ScrubTarget {
        key_id: CANONICAL.to_string(),
        pubkey_ed25519_base64: B64.encode(
            canonical_id
                .ed25519_public_key()
                .await
                .expect("canonical ed pubkey"),
        ),
        pubkey_ml_dsa_65_base64: B64.encode(
            canonical_id
                .mldsa65_public_key()
                .await
                .expect("canonical ml-dsa pubkey"),
        ),
        identity_type: "canonical,node".to_string(),
        roles: vec![INFRA_SERVE.to_string()],
    };
    let partial = produce_scrubbed_key_record(&holders[0], target, VALID_FROM, &[])
        .await
        .expect("A1 scrub of the canonical");
    let canonical_verify = append_scrub(partial, &holders[1])
        .await
        .expect("B1 co-scrub completes the 2-of-3");
    let canonical = to_persist(&canonical_verify);
    dir.put_public_key(canonical.clone())
        .await
        .expect("the 2-of-3 co-scrubbed canonical must pass the m-of-n admission gate");

    // (5) The user — a self-signed `user` identity.
    let user = seeded_identity(USER, qa_seed("user"));
    let user_rec = produce_self_key_record(&user, "user", VALID_FROM, &[])
        .await
        .expect("user self record");
    dir.put_public_key(to_persist(&user_rec))
        .await
        .expect("user record admits");

    // (6) The delegation-plane trust graph (FSD/TRUST_ROOT_CAPABILITY_GATE.md):
    // charter, root→canonical grant, user→root trust edge, fresh lifecycle.
    put_att(
        &dir,
        signed_charter(
            "qa-charter",
            &holders[0],
            ROOT,
            serde_json::json!([INFRA_ATTEST, INFRA_SERVE, INFRA_STORE, INFRA_TRANSPORT]),
            // B1 + C1 pre-committed to rotate A1's charter (m-of-n recovery).
            &[HOLDER_IDS[1].to_string(), HOLDER_IDS[2].to_string()],
        )
        .await,
    )
    .await;
    put_att(
        &dir,
        signed_delegates_to(
            "qa-grant-serve",
            &holders[0],
            CANONICAL,
            serde_json::json!([INFRA_SERVE]),
            None,
        )
        .await,
    )
    .await;
    put_att(
        &dir,
        signed_delegates_to(
            "qa-trust-edge",
            &user,
            ROOT,
            serde_json::json!([INFRA_ATTEST, INFRA_SERVE]),
            None,
        )
        .await,
    )
    .await;
    put_att(
        &dir,
        signed_lifecycle("qa-lifecycle", &holders[1], ROOT).await,
    )
    .await;

    PortableRoot {
        dir,
        holders,
        user,
        canonical_verify,
        canonical,
        _env: env,
        _serialized: serialized,
    }
}

/// Add the CIRISPersist#488 probe on top of the fixture: a SECOND root whose
/// charter carries ONLY `infra:attest` — it can vouch but can never serve —
/// with every other leg green (user trust edge + fresh lifecycle).
async fn add_vouch_only_root(fx: &PortableRoot) {
    let vouch = seeded_identity(VOUCH_ROOT, qa_seed("vouch-root"));
    let rec = produce_self_key_record(&vouch, "node", VALID_FROM, &[])
        .await
        .expect("vouch-root self record");
    fx.dir
        .put_public_key(to_persist(&rec))
        .await
        .expect("vouch-root registers");
    put_att(
        &fx.dir,
        signed_charter(
            "qa-vouch-charter",
            &vouch,
            VOUCH_ROOT,
            serde_json::json!([INFRA_ATTEST]),
            &[HOLDER_IDS[1].to_string(), HOLDER_IDS[2].to_string()],
        )
        .await,
    )
    .await;
    put_att(
        &fx.dir,
        signed_delegates_to(
            "qa-vouch-edge",
            &fx.user,
            VOUCH_ROOT,
            serde_json::json!([INFRA_ATTEST]),
            None,
        )
        .await,
    )
    .await;
    put_att(
        &fx.dir,
        signed_lifecycle("qa-vouch-lifecycle", &fx.holders[2], VOUCH_ROOT).await,
    )
    .await;
}

// ────────────────────────────────────────────────────────────────────
// Tier 1 — green today: the mint works.
// ────────────────────────────────────────────────────────────────────

/// The minted root is PORTABLE: `produce_genesis` sees the envelope-attested
/// `infra:serve` (top-level `roles` is empty by design — the producer never
/// self-asserts what persist confers), the bundle self-verifies offline, and
/// attaching it onto a SECOND fresh directory re-seeds holders + serve node
/// through the REAL admission gates.
#[tokio::test]
async fn qa_mints_and_produces_a_portable_genesis() {
    let fx = mint_portable_root().await;

    let family = ciris_persist::federation::genesis::accord_family_genesis_record();

    // The delegation plane the seed ceremony mints: a charter pre-committing to
    // the OTHER seated holders as its recovery set, plus the serve grant. Signed
    // here in software by A1 — the live ceremony signs the identical shapes with
    // A1's YubiKey through `/v1/accord/genesis/propose`.
    let charter = SignedAttestation {
        attestation: sign_row(
            crate::mesh_genesis::CHARTER_ATTESTATION_ID,
            &fx.holders[0],
            ROOT,
            attestation_type::DELEGATES_TO,
            crate::mesh_genesis::charter_envelope(&[
                HOLDER_IDS[1].to_string(),
                HOLDER_IDS[2].to_string(),
            ])
            .expect("charter envelope"),
            chrono::Utc::now(),
            None,
        )
        .await,
    };
    let grant_id = format!(
        "{}:{CANONICAL}",
        crate::mesh_genesis::GRANT_ATTESTATION_ID_PREFIX
    );
    let grant = SignedAttestation {
        attestation: sign_row(
            &grant_id,
            &fx.holders[0],
            CANONICAL,
            attestation_type::DELEGATES_TO,
            crate::mesh_genesis::grant_envelope(CANONICAL),
            chrono::Utc::now(),
            None,
        )
        .await,
    };

    let mut bundle = produce_genesis(
        &family.family_key_id,
        "quorum:2/3",
        vec![fx.canonical.clone()],
        vec![charter, grant],
        Vec::new(),
        "2026-07-22T00:00:00Z",
    )
    .expect("an envelope-attested infra:serve canonical must produce a genesis");

    // Under-authorized: structurally sound, but not yet a seed. This is the
    // mid-ceremony state the card shows between A1 proposing and B1 cosigning.
    assert!(
        matches!(
            verify_bundle(&bundle),
            Err(crate::mesh_genesis::GenesisError::QuorumNotMet { needed: 2, .. })
        ),
        "an unauthorized bundle must not pass as a seed"
    );

    // A1 then B1 authorize — the m-of-n that makes minting a trust root a quorum
    // act. Each signs the digest binding the WHOLE artifact, so a signature
    // cannot be replayed onto a bundle with a swapped serve node.
    for h in [&fx.holders[0], &fx.holders[1]] {
        let digest =
            crate::mesh_genesis::authorization_digest(&bundle).expect("authorization digest");
        let (ed, pqc) = h.sign_bound(&digest).await.expect("authorize");
        bundle
            .authorizations
            .push(crate::mesh_genesis::GenesisAuthorization {
                holder_key_id: h.key_id().to_string(),
                signature_classical: ed,
                signature_pqc: pqc,
            });
    }
    assert_eq!(bundle.holders.len(), 3, "all 3 accord holders ride along");
    assert_eq!(
        bundle.serve_nodes.len(),
        1,
        "the canonical is the serve set"
    );
    assert!(
        bundle.serve_nodes[0].record.roles.is_empty(),
        "top-level roles is empty — the ENVELOPE is what carried the conferral"
    );
    verify_bundle(&bundle).expect("the produced genesis must self-verify offline");

    // Attach onto a SECOND, fresh directory — the portable half. The serve
    // node re-enters through `put_public_key`, i.e. the 2-of-3 canonical
    // admission gate re-verifies the co-scrub against the freshly seeded
    // holder rows.
    let dir2 = MemoryBackend::new();
    let report = attach_genesis(&dir2, &bundle)
        .await
        .expect("attach onto a fresh directory");
    assert_eq!(report.holders_seeded, 3);
    assert_eq!(report.serve_nodes_seeded, 1);
    let row = dir2
        .lookup_public_key(CANONICAL)
        .await
        .expect("lookup")
        .expect("the serve node is seeded in the second directory");
    assert!(
        identity_type::set_contains(&row.identity_type, identity_type::CANONICAL),
        "the attached serve node keeps its canonical identity"
    );
}

/// The conferral rides INSIDE the scrub-signed envelope: `roles_in_envelope()`
/// reads back exactly `["infra:serve"]`, attested by a genuine 2-of-3.
#[tokio::test]
async fn qa_envelope_carries_the_conferral() {
    let fx = mint_portable_root().await;
    assert_eq!(
        fx.canonical_verify.record.roles_in_envelope(),
        vec![INFRA_SERVE.to_string()],
        "the accord co-scrub attests infra:serve inside the signed envelope"
    );
    assert_eq!(
        fx.canonical_verify.record.distinct_scrub_count(),
        2,
        "A1 + B1 — the 2-of-3 quorum the admission gate verified"
    );
    assert!(
        fx.canonical.record.roles.is_empty(),
        "top-level roles is emitted empty by the producer — persist confers \
         (the lift is CIRISPersist#486, pending)"
    );
}

// ────────────────────────────────────────────────────────────────────
// Tier 2 — gap-documenting: assert TODAY'S broken behavior so these
// FLIP red on the fixed-triple repin.
// ────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────
// Tier 3 — the acceptance gates. GREEN as of the v13.13.0 triple
// (edge v13.13.0 / persist v19.0.0 / verify v10.6.0): CIRISPersist#486
// lifts envelope-attested roles, #488 landed charter pre-rotation, the
// serve∧attest root minimum, and edge expiry in the walk. They ran
// `#[ignore]`d until that repin; the gap tests that asserted the broken
// behavior were deleted when they flipped red, exactly as designed.
// ────────────────────────────────────────────────────────────────────

/// **Acceptance (leg A) — CIRISPersist#486.** The envelope-attested
/// `infra:serve` on the 2-of-3-conferred canonical resolves through
/// `has_effective_role`. Un-ignore on the fixed triple; until then it fails
/// with `claims_role` never reading the envelope surface.
#[tokio::test]
async fn qa_leg_a_serve_resolves() {
    let fx = mint_portable_root().await;
    assert!(
        has_effective_role(&fx.dir, CANONICAL, INFRA_SERVE)
            .await
            .expect("has_effective_role walk"),
        "acceptance: the accord-conferred (envelope-attested, 2-of-3) \
         infra:serve must read effective — CIRISPersist#486"
    );
}

/// **Acceptance — CIRISPersist#488.** A vouch-only root (charter carries ONLY
/// `infra:attest`) is REJECTED: the root minimum is attest AND serve. Until
/// the fix, `trust_root_valid`'s OR accepts it.
#[tokio::test]
async fn qa_root_minimum_is_serve_and_attest() {
    let fx = mint_portable_root().await;
    add_vouch_only_root(&fx).await;
    let v = trust_root_valid(&fx.dir, USER, VOUCH_ROOT)
        .await
        .expect("trust_root_valid walk");
    assert!(
        !v.valid,
        "acceptance: an infra:attest-only charter must NOT make a valid trust \
         root (minimum = attest AND serve) — CIRISPersist#488; verdict: {v:?}"
    );
}

/// **Acceptance (end-to-end) — CIRISPersist#486 + #488.** Both legs of the
/// edge trace-serve gate resolve against the minted portable root:
/// leg A `has_effective_role(canonical, infra:serve)` AND leg B
/// `capability_roots_to_trusted_root(user, canonical, infra:serve)` — the
/// state in which the trace plane would actually serve.
#[tokio::test]
async fn qa_end_to_end_two_leg_gate() {
    let fx = mint_portable_root().await;

    // Leg A — the recipient's serve capability is accord-conferred.
    assert!(
        has_effective_role(&fx.dir, CANONICAL, INFRA_SERVE)
            .await
            .expect("has_effective_role walk"),
        "leg A: the canonical's accord-conferred infra:serve must read \
         effective (CIRISPersist#486)"
    );

    // Leg B — that capability roots to a root the USER trusts.
    let grant = capability_roots_to_trusted_root(&fx.dir, USER, CANONICAL, INFRA_SERVE)
        .await
        .expect("capability walk")
        .expect("leg B: the canonical's infra:serve must root to a root the user trusts");
    assert_eq!(grant.root_key_id, ROOT);
    assert_eq!(grant.grant_attestation_id, "qa-grant-serve");
    assert!(
        grant.verdict.valid,
        "the winning root's verdict is all-green"
    );
}

/// **Acceptance — CIRISPersist#488 (edge expiry).** A `delegates_to(user →
/// root)` trust edge that expired 30 days ago no longer validates the root:
/// the walk consults `expires_at`, not just tombstones. Expiry is what bounds
/// any illicit cache and stops grants outliving their purpose (the OCSP /
/// Ronin lesson, `FSD/PRIOR_ART.md` §2.4).
#[tokio::test]
async fn qa_expired_trust_edge_is_dead() {
    let fx = mint_portable_root().await;

    let user2 = seeded_identity("qa-user-2", qa_seed("user-2"));
    let rec = produce_self_key_record(&user2, "user", VALID_FROM, &[])
        .await
        .expect("user-2 self record");
    fx.dir
        .put_public_key(to_persist(&rec))
        .await
        .expect("user-2 registers");
    let edge = sign_row(
        "qa-trust-edge-expired",
        &user2,
        ROOT,
        attestation_type::DELEGATES_TO,
        serde_json::json!({
            "references_attestation_id": "qa-trust-edge-expired",
            "scope": [INFRA_ATTEST, INFRA_SERVE],
        }),
        chrono::Utc::now() - chrono::Duration::days(60),
        Some(chrono::Utc::now() - chrono::Duration::days(30)),
    )
    .await;
    put_att(&fx.dir, edge).await;

    let v = trust_root_valid(&fx.dir, "qa-user-2", ROOT)
        .await
        .expect("trust_root_valid walk");
    assert!(
        !v.edge_exists && !v.valid,
        "acceptance: an expired trust edge must not validate the root \
         (CIRISPersist#488 delta 3); verdict: {v:?}"
    );
}
