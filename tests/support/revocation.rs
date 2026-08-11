//! Seed a REAL, admitted revocation — with or without the CIRISPersist#570
//! `revoked_after` history bound.
//!
//! Shared because two suites need it (`revoked_after_enforcement`, which gates
//! four read paths, and `capacity_scorer`, which gates the fifth on top of its
//! own trace-ingest fixture) and a second copy of the fixture is how two gates
//! end up testing two different things while reading identically.
//!
//! The bound is written into the SIGNED envelope as well as the typed field
//! because persist refuses any other shape (`check_revocation_bound`: a typed
//! bound with no envelope bound is not a lenient revocation, it is a forged
//! one). Building the fixture the only way the substrate accepts is what keeps
//! these gates about ENFORCEMENT rather than about a row someone hand-wrote.
//!
//! # v30.10.0 — a third-party revocation now has to prove it may
//!
//! persist v30.10.0 added `check_revocation_authority` (CIRISPersist#596 item 1):
//! revoking SOMEONE ELSE'S key is a moderation act, so it needs `slash` conferred
//! by a root THIS NODE trusts. Before it, `put_revocation`'s only gate was a
//! trust-score threshold — "may this peer write at all", never "does it have any
//! standing over the key it is erasing" — so any sufficiently-trusted key could
//! revoke any other key in the mesh.
//!
//! Seven tests across three suites went red on that, and the honest reading is
//! that this fixture had been minting revocations no real deployment would ever
//! admit. It seeded a bare STEWARD registration and called the result an
//! authority; the substrate had simply never asked. So the fix is not to route
//! around the new gate — it is to build the half that was always missing.
//! [`authorize_slash`] stands up the real chain (root + accord witness, charter,
//! heartbeat, conferral, plus the ONE edge that must genuinely come from the
//! node: `delegates_to(node → root)` signed by its own key), and `revoke` calls
//! it for any third-party revocation.
//!
//! Self-revocation deliberately does NOT go through it — persist admits that
//! unconditionally, because a holder must be able to retire its own compromised
//! key, and gating it would mean a leaked key can only be retired by someone
//! else. Asking for authority we do not need would have taught the fixture a
//! rule the substrate does not have.
//!
//! What this buys beyond a green suite: it is a WORKING example of the exact
//! grant CIRISServer#383's 61 keys are waiting on. That de-admission is blocked
//! on a conferral, not on code, and this is its shape.
//!
//! NB: files under `tests/support/` are not auto-compiled as test binaries; each
//! suite pulls this in with an explicit `#[path]`.

#![allow(dead_code)]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use ciris_persist::federation::types::{Revocation, SignedRevocation};
use ciris_persist::federation::verify_coord::region;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_verify_core::self_at_login::HybridSigningIdentity;

/// A deterministic hybrid identity for `key_id` — one 32-byte secret, with the
/// ML-DSA-65 seed a domain-separated hash of it (the `test_bless::mint_test_root`
/// derivation `trust_root_qa` also uses).
///
/// Derived from the id rather than a fixed seed so two authorities in one suite
/// never collide onto one keypair — a collision would register the second under
/// the first's pubkeys and fail at hybrid-verify, several layers from the cause.
fn seeded_identity(key_id: &str) -> HybridSigningIdentity {
    use ciris_crypto::{Ed25519Signer, MlDsa65Signer};
    let ed_seed: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"ciris-server/tests/support/revocation/ed/v1");
        h.update(key_id.as_bytes());
        h.finalize().into()
    };
    let ml_seed: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"ciris-test-trust-root/mldsa/v1");
        h.update(ed_seed);
        h.finalize().into()
    };
    HybridSigningIdentity::new(
        key_id.to_string(),
        Ed25519Signer::from_seed(&ed_seed).expect("ed25519 seed"),
        MlDsa65Signer::from_seed(&ml_seed).expect("ml-dsa-65 seed"),
    )
}

/// A stable id derived from `tag`. Deliberately NOT a random uuid: the whole
/// chain is a pure function of the revoking key, so a suite that calls
/// [`authorize_slash`] twice re-derives the SAME ids and the second pass is a
/// no-op rather than a second root competing with the first.
fn uuid_like(tag: &str) -> String {
    let h = hex::encode(Sha256::digest(tag.as_bytes()));
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Register `who`'s REAL hybrid halves, so persist's federation-tier ingest can
/// verify what it signs. A PQC half is mandatory for anything that attests
/// (`HybridPolicy::Strict`), which both the root and its witness do.
async fn register_hybrid(engine: &Engine, who: &HybridSigningIdentity, id_type: &str) {
    use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
    let now = Utc::now();
    // An `accord_holder` registration hits persist's #513 hardware-attestation
    // gate on sqlite (MemoryBackend skips it). The gate validates SHAPE and
    // FRESHNESS (≤24h), not a real cert chain, so the established mock
    // Android-StrongBox value with a fresh nonce is the accepted test path —
    // the same one persist's own `register_typed_key` takes.
    let attestation_evidence = (id_type == identity_type::ACCORD_HOLDER).then(|| {
        serde_json::json!({
            "platform_attestation": {
                "Android": {
                    "key_attestation_chain": [
                        [0x30u8, 0x82, 0x01, 0x00],
                        [0x30u8, 0x82, 0x02, 0x00],
                    ],
                    "play_integrity_token": "eyJhbGciOiJIUzI1NiJ9.fake.token",
                    "strongbox_backed": true,
                }
            },
            "nonce_captured_at": now.to_rfc3339(),
        })
    });
    let member = who.directory_member().expect("directory member halves");
    let ed = member.ed25519_public_key_base64.clone();
    let record = KeyRecord {
        key_id: who.key_id().to_string(),
        pubkey_ed25519_base64: ed.clone(),
        pubkey_ml_dsa_65_base64: member.mldsa65_public_key_base64.clone(),
        algorithm: algorithm::HYBRID.into(),
        identity_type: id_type.to_string(),
        identity_ref: who.key_id().to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": who.key_id() }),
        original_content_hash: "deadbeef".into(),
        scrub_signature_classical: ed,
        scrub_signature_pqc: None,
        scrub_key_id: who.key_id().to_string(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register the trust-root chain's key in the federation directory");
}

/// Hybrid-sign `envelope` as `attester` and put the row. Re-putting an identical
/// id is tolerated: [`authorize_slash`] is idempotent, and a backend that
/// refuses the duplicate has still left the chain standing.
async fn put_signed(
    engine: &Engine,
    attester: &HybridSigningIdentity,
    attested_key_id: &str,
    ty: &str,
    envelope: serde_json::Value,
    id: &str,
) {
    use ciris_persist::federation::types::{attestation_tier, cohort_scope, Attestation};
    use ciris_persist::federation::SignedAttestation;
    use ciris_verify_core::self_at_login::SelfSigner;

    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize envelope");
    let (ed_b64, pqc_b64) = attester
        .sign_bound(&canonical)
        .await
        .expect("bound-hybrid sign");
    let now = Utc::now();
    let row = Attestation {
        attestation_id: id.to_string(),
        attesting_key_id: attester.key_id().to_string(),
        attested_key_id: attested_key_id.to_string(),
        attestation_type: ty.to_string(),
        weight: Some(1.0),
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: ed_b64,
        scrub_signature_pqc: Some(pqc_b64),
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
    if let Err(e) = engine
        .federation_directory()
        .put_attestation(SignedAttestation { attestation: row })
        .await
    {
        // A duplicate id is the idempotent re-run; anything else is a real
        // refusal and must not be swallowed into a silently-absent leg.
        let msg = e.to_string();
        assert!(
            msg.contains("UNIQUE") || msg.contains("duplicate") || msg.contains("already"),
            "trust-root leg {id} ({ty}) refused: {msg}"
        );
    }
}

/// Confer `slash` on `revoking_key_id` from a root this node genuinely trusts,
/// so `check_revocation_authority` admits a third-party revocation by it.
///
/// Does the whole honest dance — it bypasses no gate. Four legs, hand-rolled
/// rather than taken from persist's `test_support::establish_trust_root_side`
/// because that module sits behind the `test-anchor` feature, and `test-anchor`
/// is a deliberate "NEVER in the prod wheel" fence (CIRISServer#258) that also
/// changes verify's trust-root behaviour. Switching it on for these three
/// suites to reach one helper would have let thirty others start passing under
/// a different root regime — a much bigger change than the one being made.
///
/// 1. **the root and its witness**, registered with REAL hybrid halves.
/// 2. **the charter** — `delegates_to(root → root)` on `trust:charter:v1`,
///    carrying the pre-rotation commitment.
/// 3. **the heartbeat** — an `accord:lifecycle:v1` row ABOUT the root, from the
///    accord-holder witness (that family is reserved, hence the witness).
/// 4. **the conferral** — `delegates_to(root → revoking)` on `trust:confers:v1`
///    carrying `slash`.
///
/// Then the one edge a fixture must NOT forge on the node's behalf:
/// `delegates_to(node → root)`, emitted by the node's OWN key. It carries the
/// INFRA scopes, not `slash` — trusting something as a root and being granted a
/// duty by it are different acts pointing in opposite directions, and a node-only
/// recipient may hold infra scopes alone (CC 4.4.3.4.3). Conflating them earns
/// `NodeAgencyForbidden`, which is the substrate correctly refusing to let a node
/// be handed agency.
///
/// Idempotent by ASKING rather than by remembering: if the walk already succeeds
/// there is nothing to build, so a suite that revokes twice under one authority
/// does not stand up a second competing root.
pub async fn authorize_slash(engine: &Engine, revoking_key_id: &str) {
    use ciris_persist::federation::admission::DELEGATION_SCOPE_SLASH;
    use ciris_persist::federation::trust_root::{self, capability_roots_to_trusted_root};
    use ciris_persist::federation::types::{attestation_type, identity_type};

    let dir = engine.federation_directory();
    let node = engine
        .local_derived_key_id()
        .await
        .expect("this node's own key id (the trust the conferral must root to)");

    if capability_roots_to_trusted_root(
        dir.as_ref(),
        &node,
        revoking_key_id,
        DELEGATION_SCOPE_SLASH,
    )
    .await
    .expect("capability walk")
    .is_some()
    {
        return;
    }

    let root = format!("{revoking_key_id}-slash-root");
    let witness = format!("{root}-la");
    let root_id = seeded_identity(&root);
    let witness_id = seeded_identity(&witness);
    register_hybrid(engine, &root_id, identity_type::NODE).await;
    register_hybrid(engine, &witness_id, identity_type::ACCORD_HOLDER).await;

    // Leg 2 — the root's self-declaration charter (R → R), carrying the
    // pre-rotation commitment that makes it a recoverable root rather than a
    // key that vanishes when it rotates.
    let charter_id = uuid_like(&format!("{root}/charter"));
    let successors = vec![format!("{root}-succ-a"), format!("{root}-succ-b")];
    let commitment = ciris_persist::federation::trust_root::pre_rotation_commitment(&successors)
        .expect("pre-rotation commitment");
    put_signed(
        engine,
        &root_id,
        &root,
        attestation_type::DELEGATES_TO,
        serde_json::json!({
            "references_attestation_id": charter_id,
            "dimension": trust_root::TRUST_CHARTER_DIMENSION,
            "scope": [trust_root::INFRA_ATTEST_SCOPE, trust_root::INFRA_SERVE_SCOPE],
            "pre_rotation_commitment": commitment,
        }),
        &charter_id,
    )
    .await;

    // Leg 3 — the accord heartbeat ABOUT the root. `accord:*` is
    // accord_holder-RESERVED, which is why the witness above is registered as
    // one; without this leg `trust_root_valid` reports the root un-witnessed.
    let lc_id = uuid_like(&format!("{root}/lifecycle"));
    put_signed(
        engine,
        &witness_id,
        &root,
        attestation_type::SCORES,
        serde_json::json!({
            "id": lc_id,
            "dimension": trust_root::ACCORD_HEARTBEAT_DIMENSION,
            "score": 1.0,
            "confidence": 0.9,
        }),
        &lc_id,
    )
    .await;

    // The conferral itself (root → revoking), carrying `slash`. `trust:confers`
    // is load-bearing, not decorative: a row here labelled charter or trust-edge
    // points the other way and confers nothing (CIRISPersist#551 item 2).
    let grant_id = uuid_like(&format!("{root}/grant"));
    put_signed(
        engine,
        &root_id,
        revoking_key_id,
        attestation_type::DELEGATES_TO,
        serde_json::json!({
            "references_attestation_id": grant_id,
            "dimension": trust_root::TRUST_CONFERS_DIMENSION,
            "scope": [DELEGATION_SCOPE_SLASH],
        }),
        &grant_id,
    )
    .await;

    // The node's own trust edge carries the INFRA scopes, never `slash`: this
    // says "I accept you as a root", not "I grant you a duty". The root is a
    // node-only identity, and CC 4.4.3.4.3 lets such a recipient hold infra
    // scopes ALONE — handing it `slash` here is `NodeAgencyForbidden`, the
    // substrate refusing to let infrastructure be given agency.
    let core = ciris_persist::federation::envelope::EnvelopeCore::from_value(serde_json::json!({
        "scope": [trust_root::INFRA_ATTEST_SCOPE, trust_root::INFRA_SERVE_SCOPE],
    }))
    .expect("trust edge envelope");
    let mut edge = ciris_persist::federation::EmitAttestationInput::with_envelope(
        ciris_persist::federation::types::attestation_type::DELEGATES_TO,
        core,
        ciris_persist::federation::types::cohort_scope::FEDERATION,
    );
    edge.attested_key_id = Some(root.clone());
    edge.subject_key_ids = vec![root.clone()];
    engine
        .emit_attestation_self(edge)
        .await
        .expect("the node emits its OWN delegates_to(node -> root) trust edge");

    // POSTCONDITION — never hand back a conferral that does not confer. Without
    // this, a fixture that quietly built nothing would surface as the revocation
    // being refused, one layer away from the cause.
    assert!(
        capability_roots_to_trusted_root(
            dir.as_ref(),
            &node,
            revoking_key_id,
            DELEGATION_SCOPE_SLASH
        )
        .await
        .expect("capability walk")
        .is_some(),
        "authorize_slash built the chain but {revoking_key_id} still holds `slash` from no root \
         {node} trusts — the conferral or the node's own trust edge did not admit"
    );
}

/// Persist a hybrid-signed revocation of `revoked_key_id`, effective at
/// `effective_at`, optionally bounded at `revoked_after`.
///
/// `revoking` must already be registered with the pubkeys it signs with —
/// persist re-verifies the revocation against the directory
/// (`verify_revocation_admission`), so an unregistered or mismatched signer is
/// refused rather than stored. A third-party revocation additionally gets its
/// `slash` conferral stood up ([`authorize_slash`]); self-revocation does not
/// need one and deliberately does not get one.
pub async fn revoke(
    engine: &Engine,
    revoking: &LocalSigner,
    revoked_key_id: &str,
    effective_at: DateTime<Utc>,
    revoked_after: Option<DateTime<Utc>>,
) {
    if revoking.key_id() != revoked_key_id {
        authorize_slash(engine, revoking.key_id()).await;
    }
    let mut envelope = serde_json::json!({
        "revoked_key_id": revoked_key_id,
        "revoking_key_id": revoking.key_id(),
        "revoked_at": effective_at.to_rfc3339(),
        "effective_at": effective_at.to_rfc3339(),
    });
    if let Some(b) = revoked_after {
        envelope["revoked_after"] = serde_json::Value::String(b.to_rfc3339());
    }
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize revocation envelope");
    let sig = revoking
        .sign_hybrid(&canonical)
        .await
        .expect("hybrid-sign the revocation");
    let now = Utc::now();
    let row = Revocation {
        revocation_id: format!("rev-{revoked_key_id}"),
        revoked_key_id: revoked_key_id.to_string(),
        revoking_key_id: revoking.key_id().to_string(),
        reason: None,
        revoked_at: effective_at,
        effective_at,
        revocation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: revoking.key_id().to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        observed_region: region::US.to_string(),
        revoked_after,
        persist_row_hash: String::new(),
    };
    engine
        .federation_directory()
        .put_revocation(SignedRevocation { revocation: row })
        .await
        .expect("put_revocation (the bound must be admitted by check_revocation_bound)");
}
