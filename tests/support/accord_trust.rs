// Shared fixture: stand up the node's TRUST IN THE ACCORD FAMILY — the three
// rows a real genesis-seeded node already has, verified against the live
// canonical-server-1:
//
// ```text
// delegates_to  A1+B1 -> humanity-accord  trust:charter:v1   (2-of-3 charter)
// scores        A1    -> humanity-accord  accord:lifecycle   (the heartbeat)
// delegates_to  node  -> humanity-accord                     (this node's edge)
// ```
//
// Without them `trust_root_valid(node, humanity-accord)` reports
// `edge_exists=false, root_self_declares=false, drill=Red`, and the
// FamilyQuorum walk correctly declines — the accord may have signed, but this
// node has not said it trusts the accord.
//
// A family is KEYLESS and cannot self-declare, so its charter is
// `delegates_to(holder -> family)` labelled `trust:charter:v1`, counted ONLY at
// the family's own threshold: *the roster charters the family*, and no single
// seat may declare itself the mesh's root (CIRISPersist#557).
//
// NB: files under `tests/support/` are not auto-compiled as test binaries; each
// suite pulls this in with an explicit `include!`.

/// Stand up the node's TRUST IN THE ACCORD FAMILY — the three rows a real
/// genesis-seeded node already has, verified against a live one:
///
/// ```text
/// delegates_to  A1   -> humanity-accord   [infra:*]          (the charter)
/// scores        A1   -> humanity-accord   accord:lifecycle   (the heartbeat)
/// delegates_to  node -> humanity-accord   [infra:*]          (this node's trust edge)
/// ```
///
/// Without these `trust_root_valid(node, humanity-accord)` reports
/// `edge_exists=false, root_self_declares=false, drill=Red`, and the
/// FamilyQuorum walk correctly declines — the accord may have signed, but this
/// node has not said it trusts the accord. The family is KEYLESS, so its charter
/// and heartbeat are signed by a SEAT (A1) about the family; that is the shape
/// `canonical_seed.json` ships.
use ciris_persist::federation::operational::test_support::Identity;
use ciris_persist::prelude::Engine;

pub async fn seed_accord_trust(e: &Engine, node: &Identity, hs: &[Identity]) {
    use ciris_persist::federation::trust_root::{
        pre_rotation_commitment, ACCORD_HEARTBEAT_DIMENSION, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE,
        TRUST_CHARTER_DIMENSION,
    };
    use ciris_persist::federation::types::attestation_type;

    // (1) THE FAMILY'S CHARTER — 2-of-3, because THE ROSTER CHARTERS THE FAMILY.
    // A family is keyless, so it cannot self-declare; its analogue is
    // `delegates_to(holder → family)` labelled `trust:charter:v1`, and it counts
    // as a charter ONLY when its full scrub set reaches the family's own
    // threshold. That is the whole of CIRISPersist#557 — no single seat may
    // declare itself the mesh's root. A one-scrub charter leaves
    // `root_self_declares = false`, which is what this test first hit.
    let successors = vec![
        "humanity-accord-succ-a".to_string(),
        "humanity-accord-succ-b".to_string(),
    ];
    let commitment = pre_rotation_commitment(&successors).expect("pre-rotation commitment");
    put_signed_by_many(
        e,
        &[&hs[0], &hs[1]],
        "humanity-accord",
        attestation_type::DELEGATES_TO,
        serde_json::json!({
            "dimension": TRUST_CHARTER_DIMENSION,
            "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            "pre_rotation_commitment": commitment,
        }),
    )
    .await;

    // (2) The freshness heartbeat ABOUT the family, from a seated holder.
    put_signed_by_many(
        e,
        &[&hs[0]],
        "humanity-accord",
        attestation_type::SCORES,
        serde_json::json!({
            "dimension": ACCORD_HEARTBEAT_DIMENSION, "score": 1.0, "confidence": 0.9,
        }),
    )
    .await;

    // (3) THE NODE'S OWN TRUST EDGE — node → family, signed by the NODE. The
    // direction is load-bearing: an edge pointing the other way leaves
    // `edge_exists = false`, and the accord may have signed while this node has
    // never said it trusts the accord. A real node emits this with its own
    // signer; canonical-server-1 carries exactly this row.
    put_signed_by_many(
        e,
        &[node],
        "humanity-accord",
        attestation_type::DELEGATES_TO,
        serde_json::json!({ "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE] }),
    )
    .await;
}

/// Put a row really signed by `who` over its canonical envelope.
pub async fn put_signed_by_many(
    e: &Engine,
    signers: &[&Identity],
    attested: &str,
    ty: &str,
    mut envelope: serde_json::Value,
) {
    let who = signers[0];
    use ciris_persist::federation::types::{attestation_tier, cohort_scope, Attestation};
    use ciris_persist::federation::SignedAttestation;
    use ciris_persist::verify::canonical::ceg_produce_canonicalize;
    use sha2::{Digest, Sha256};
    let id = hex::encode(Sha256::digest(
        format!("{}/{attested}/{ty}", who.key_id).as_bytes(),
    ))[..32]
        .to_string();
    envelope["references_attestation_id"] = serde_json::json!(id);
    if envelope.get("id").is_none()
        && ty == ciris_persist::federation::types::attestation_type::SCORES
    {
        envelope["id"] = serde_json::json!(id);
    }
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize");
    let (ed, pqc) = who.sign_bytes(&canonical);
    let extra: Vec<ciris_persist::federation::types::ScrubSig> = signers[1..]
        .iter()
        .map(|s| {
            let (e2, p2) = s.sign_bytes(&canonical);
            ciris_persist::federation::types::ScrubSig {
                scrub_key_id: s.key_id.clone(),
                scrub_signature_classical: e2,
                scrub_signature_pqc: Some(p2),
            }
        })
        .collect();
    let now = chrono::Utc::now();
    // NOT `let _ =`. A swallowed put here made `edge_exists` read false with no
    // hint why — the row had been refused for an unregistered signer and the
    // test blamed the walk. A discarded Result during investigation is how an
    // instrument lies to you.
    e.federation_directory()
        .put_attestation(SignedAttestation {
            attestation: Attestation {
                attestation_id: id,
                attesting_key_id: who.key_id.clone(),
                attested_key_id: attested.to_string(),
                attestation_type: ty.to_string(),
                weight: Some(1.0),
                asserted_at: now,
                expires_at: None,
                attestation_envelope: envelope,
                original_content_hash: hex::encode(Sha256::digest(&canonical)),
                scrub_signature_classical: ed,
                scrub_signature_pqc: Some(pqc),
                scrub_key_id: who.key_id.clone(),
                additional_scrubs: extra,
                scrub_timestamp: now,
                pqc_completed_at: Some(now),
                persist_row_hash: String::new(),
                subject_key_ids: Vec::new(),
                withdraws_admission_rule: None,
                cohort_scope: cohort_scope::FEDERATION.to_string(),
                tier: attestation_tier::FEDERATION.to_string(),
                promoted_at: None,
            },
        })
        .await
        .unwrap_or_else(|e| {
            panic!(
                "seed row {ty} by {} about {attested} refused: {e}",
                who.key_id
            )
        });
}

/// Register `key_id` as a user identity on this node.
///
/// The substrate REFUSES a conferral whose subject it does not know
/// (`attested_key_id … resolves as neither a registered federation_keys row nor
/// a constitutional family`), which is correct and is also an operational
/// ordering fact worth stating: **the subject's fed-ID must be present on the
/// node before the accord can grant it a duty.** In the real flow that happens
/// when the owner imports or enrolls their identity; here we do it directly.
pub async fn register_key_as_user(e: &Engine, key_id: &str) {
    use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
    let ident = Identity::new(key_id);
    let m = ident.member();
    let now = chrono::Utc::now();
    e.federation_directory()
        .put_public_key(SignedKeyRecord {
            record: KeyRecord {
                key_id: key_id.to_string(),
                pubkey_ed25519_base64: m.ed25519_public_key_base64.clone(),
                pubkey_ml_dsa_65_base64: m.mldsa65_public_key_base64.clone(),
                algorithm: algorithm::HYBRID.into(),
                identity_type: identity_type::USER.to_string(),
                identity_ref: key_id.to_string(),
                valid_from: now,
                valid_until: None,
                registration_envelope: serde_json::json!({ "key_id": key_id }),
                original_content_hash: "deadbeef".into(),
                scrub_signature_classical: m.ed25519_public_key_base64,
                scrub_signature_pqc: None,
                scrub_key_id: key_id.to_string(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .expect("register the subject identity");
}
