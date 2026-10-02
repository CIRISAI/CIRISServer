//! A consent is a CLAIM, so it rides `scores` (CC 2.4, CIRISConstitution#137,
//! CIRISServer#713).
//!
//! The Constitution closed the row-type slot at the five primitives plus two
//! carriers. The server wrote its analyze consent under a row type of its own,
//! `"consent"` — 1,060 such rows on the production canonical on 2026-10-01 —
//! and persist will refuse that type at admission (CIRISPersist#975).
//!
//! Two things must hold, and they are different:
//!
//! 1. a fresh grant is written as `scores`;
//! 2. a node that already holds its grant under the OLD type writes it again
//!    as `scores`, once. Without this the stance resolves Granted locally, the
//!    emitter returns "nothing to do" forever, and the only copy of the consent
//!    is a row no upgraded peer admits.
//!
//! The legacy fixture below is written through the same door the old code
//! used. When the pinned persist refuses that type the fixture write fails and
//! half (2) of this test has nothing left to prove: delete it then, keep (1).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::admission::ANALYZE_CONSENT_SCOPE;
use ciris_persist::federation::consent::consent_dimension;
use ciris_persist::federation::envelope::{paths, EnvelopeCore};
use ciris_persist::federation::types::{
    algorithm, attestation_type, cohort_scope, identity_type, KeyRecord,
};
use ciris_persist::federation::{EmitAttestationInput, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const NODE_ALIAS: &str = "a-node-that-consents-to-analysis";
const PEER: &str = "the-node-that-scores";

fn seed(label: &str, n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&Sha256::digest(format!("{label}:{n}").as_bytes())[..32]);
    s
}

fn signer_for(alias: &str) -> LocalSigner {
    let ed = SigningKey::from_bytes(&seed(alias, 1));
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&seed(alias, 2), format!("{alias}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        ed,
        alias.to_string(),
        Some(pqc),
        Some(format!("{alias}-pqc")),
    )
}

async fn register(engine: &Engine, signer: &LocalSigner, key_id: &str, ident: &str) {
    let mut envelope = serde_json::json!({ "key_id": key_id });
    let probe = signer.sign_hybrid(b"probe").await.expect("probe");
    let ed_pub = B64.encode(&probe.classical.public_key);
    let pqc_pub = B64.encode(&probe.pqc.public_key);
    ciris_persist::federation::admission::bind_subject_into_envelope(
        &mut envelope,
        key_id,
        ident,
        &ed_pub,
        Some(&pqc_pub),
        None,
    )
    .expect("bind subject");
    let canonical =
        ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope).expect("canon");
    let sig = signer.sign_hybrid(&canonical).await.expect("sign");
    let now = chrono::Utc::now();
    engine
        .register_federation_key(SignedKeyRecord {
            record: KeyRecord {
                key_id: key_id.to_string(),
                pubkey_ed25519_base64: ed_pub,
                pubkey_ml_dsa_65_base64: Some(pqc_pub),
                algorithm: algorithm::HYBRID.into(),
                identity_type: ident.to_string(),
                identity_ref: key_id.to_string(),
                valid_from: now,
                valid_until: None,
                registration_envelope: envelope,
                original_content_hash: hex::encode(Sha256::digest(&canonical)),
                scrub_signature_classical: B64.encode(&sig.classical.signature),
                scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
                scrub_key_id: key_id.to_string(),
                scrub_timestamp: now,
                pqc_completed_at: Some(now),
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .unwrap_or_else(|e| panic!("register {key_id}: {e}"));
}

async fn node() -> (Arc<Engine>, String) {
    let engine = Arc::new(
        Engine::with_signer(Arc::new(signer_for(NODE_ALIAS)), "sqlite::memory:")
            .await
            .expect("engine"),
    );
    let me = engine.local_derived_key_id().await.expect("derived id");
    register(&engine, &signer_for(NODE_ALIAS), &me, identity_type::NODE).await;
    register(&engine, &signer_for(PEER), PEER, identity_type::NODE).await;
    (engine, me)
}

/// The types of every analyze grant `me` authored toward [`PEER`].
async fn grant_types(engine: &Engine, me: &str) -> Vec<String> {
    let granted = format!("{}:v1", consent_dimension::STATE_GRANTED_PREFIX);
    let mut types: Vec<String> = engine
        .federation_directory()
        .list_attestations_by(me)
        .await
        .expect("list")
        .into_iter()
        .filter(|a| {
            a.attested_key_id == PEER
                && a.attestation_envelope
                    .get(paths::DIMENSION)
                    .and_then(|v| v.as_str())
                    == Some(granted.as_str())
        })
        .map(|a| a.attestation_type)
        .collect();
    types.sort();
    types
}

#[tokio::test]
async fn a_fresh_analyze_consent_is_a_scores_row() {
    let (engine, me) = node().await;
    let id = ciris_server::peer::emit_analyze_consent(&engine, &me, PEER)
        .await
        .expect("emit");
    assert!(id.is_some(), "the first call authors the grant");
    assert_eq!(
        grant_types(&engine, &me).await,
        vec![attestation_type::SCORES.to_string()],
        "the grant's row type is the claim primitive, never a type of its own (CC 2.4)"
    );
    assert_eq!(
        ciris_server::peer::emit_analyze_consent(&engine, &me, PEER)
            .await
            .expect("second emit"),
        None,
        "idempotent on the resolved stance: a live `scores` grant is nothing to do"
    );
}

#[tokio::test]
async fn a_grant_held_only_under_the_old_type_is_written_again_as_scores() {
    let (engine, me) = node().await;

    // What 0.5.218 and earlier wrote.
    let envelope = serde_json::json!({
        (paths::DIMENSION): format!("{}:v1", consent_dimension::STATE_GRANTED_PREFIX),
        "scope": ANALYZE_CONSENT_SCOPE,
    });
    let mut legacy = EmitAttestationInput::with_envelope(
        ciris_server::peer::LEGACY_CONSENT_ROW_TYPE,
        EnvelopeCore::from_value(envelope).expect("envelope"),
        cohort_scope::FEDERATION,
    );
    legacy.attested_key_id = Some(PEER.to_string());
    engine
        .emit_attestation_self(legacy)
        .await
        .expect("the legacy-typed grant (see the module note if persist now refuses it)");
    assert_eq!(
        grant_types(&engine, &me).await,
        vec![ciris_server::peer::LEGACY_CONSENT_ROW_TYPE.to_string()],
        "premise: the node holds its grant under the old type only"
    );

    let id = ciris_server::peer::emit_analyze_consent(&engine, &me, PEER)
        .await
        .expect("emit over a legacy grant");
    assert!(
        id.is_some(),
        "a grant that exists only under the old type must be re-authored — returning \
         'nothing to do' leaves the consent in a row no upgraded peer admits"
    );
    assert_eq!(
        grant_types(&engine, &me).await,
        vec![
            ciris_server::peer::LEGACY_CONSENT_ROW_TYPE.to_string(),
            attestation_type::SCORES.to_string()
        ],
        "the old row stays as history; the new one is the claim primitive"
    );
    assert_eq!(
        ciris_server::peer::emit_analyze_consent(&engine, &me, PEER)
            .await
            .expect("third emit"),
        None,
        "healed once, not once per boot"
    );
}
