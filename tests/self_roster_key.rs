//! A fedID's other keypair signs as the fedID (CC 3.3.6.3, CIRISServer#793).
//!
//! A device added by approval holds NEW key material under the SAME fedID: a
//! roster key named `<fedID>-<fingerprint of its own Ed25519 key>`
//! (`CLM-self-roster-key-id`), signed into the self roster by the owner as an
//! active occurrence. Any live roster key signs as the fedID for every owner act
//! (`CLM-self-roster-authority`). This pins the server half:
//!
//! 1. the add-device mint, run under the fedID as its alias, produces exactly
//!    the ruled name, and the approval's naming check accepts it while refusing
//!    0.5.231's `device-<hex>-<fp>`;
//! 2. on a node owned by the fedID whose seed dir holds only the roster key,
//!    the owner pen resolves to the roster key and consent is authored under it,
//!    FOR the node;
//! 3. a revoked roster key is refused, exactly as a stranger's seed is.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, device_class, identity_type, KeyRecord};
use ciris_persist::federation::{
    IdentityOccurrence, IdentityOccurrenceRevocation, SignedKeyRecord,
};
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const PEER: &str = "ciris-canonical-the-roster-key-peers-with";
const PREFIXES: &[&str] = &["trace:", "capacity:"];

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
    .expect("bind subject (#659)");
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

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir()
        .join(format!(
            "ciris-roster-key-{}-{}-{}",
            std::process::id(),
            tag,
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ))
        // `<home>/identity/user`-shaped: a device mint seals into the seed dir's
        // sibling `keys/`, which must be this test's own, not a shared `/tmp/keys`.
        .join("user");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_roster_key_of_the_owners_fedid_signs_as_the_fedid() {
    ciris_server::peer::set_owner_authored_consent(true);
    let node_signer = Arc::new(signer_for("ciris-node-for-the-roster-key-test"));
    let engine = Arc::new(
        Engine::with_signer(node_signer.clone(), "sqlite::memory:")
            .await
            .expect("engine signing as the node"),
    );
    let node = engine.local_derived_key_id().await.expect("node key_id");
    register(&engine, &node_signer, &node, identity_type::NODE).await;
    // persist v59 #1103: a registered key is named `<label>-<fp>` of its own key.
    let peer_signer = signer_for(PEER);
    let peer = peer_signer.derived_key_id();
    register(&engine, &peer_signer, &peer, identity_type::NODE).await;

    // The genesis key — the fedID — minted on the person's FIRST device.
    let first_device = scratch("genesis");
    let alias = format!("roster-owner-{}", std::process::id());
    let minted = ciris_server::identity::mint_user_identity(
        ciris_server::identity::UserIdentityBackend::Software,
        &alias,
        Some("Roster Owner"),
        first_device.clone(),
        ciris_server::identity::ActiveAlias::Adopt,
    )
    .await
    .expect("mint the fedID");
    let fed_id = minted.key_id.clone();
    let genesis = ciris_server::identity::hardware_user_signers(
        ciris_server::identity::UserIdentityBackend::Software,
        &alias,
        first_device.clone(),
    )
    .await
    .expect("re-open the genesis key")
    .0;
    register(&engine, &genesis, &fed_id, identity_type::USER).await;

    // ── 1. the add-device mint names the roster key under the fedID ─────────
    let this_device = scratch("roster");
    let roster = ciris_server::identity::mint_local_device_occurrence(&this_device, &fed_id)
        .await
        .expect("mint the roster key under the fedID");
    // A second mint under the same alias is REFUSED, never half-applied: the
    // sealed ML-DSA-65 half would re-open the FIRST mint's key under a record
    // naming the second's, and every hybrid row signed with it would be refused
    // at the ingest gate (an add-device retried after its 503, CIRISServer#793).
    let Err(again) =
        ciris_server::identity::mint_local_device_occurrence(&this_device, &fed_id).await
    else {
        panic!("a live alias is never minted over");
    };
    assert!(
        format!("{again:#}").contains("already holds key material"),
        "{again:#}"
    );
    let fp = roster
        .key_id
        .rsplit('-')
        .next()
        .expect("a fingerprint")
        .to_owned();
    assert_eq!(
        roster.key_id,
        format!("{fed_id}-{fp}"),
        "a roster key is `<fedID>-<fingerprint of its own Ed25519 key>` (CC 3.3.6.3)"
    );
    assert_ne!(
        roster.key_id, fed_id,
        "new key material: never the genesis key's own id"
    );
    ciris_server::add_device::roster_key_named_under(&fed_id, &roster.key_record)
        .expect("the approval accepts a roster key named under this fedID");
    let device_named = ciris_server::identity::mint_local_device_occurrence(
        &scratch("device-named"),
        "device-35ab167e7087",
    )
    .await
    .expect("mint a 0.5.231-shaped device key");
    let refused =
        ciris_server::add_device::roster_key_named_under(&fed_id, &device_named.key_record)
            .expect_err("a device-named key is never signed into a fedID's roster");
    assert!(refused.contains("CC 3.3.6.3"), "{refused}");

    // The owner signs it into the roster (the approval's occurrence), and the
    // node is owned by the FEDID — the same identity owns every device.
    engine
        .register_federation_key(roster.key_record.clone())
        .await
        .expect("register the roster key");
    engine
        .federation_directory()
        .put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: fed_id.clone(),
            occurrence_key_id: roster.key_id.clone(),
            device_class: device_class::LAPTOP.to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: roster.encryption_pubkeys.clone(),
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("the roster key is an active occurrence of the fedID");
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    ciris_server::auth::ownership::emit_steward_binding(&engine, &genesis, &node, &scopes)
        .await
        .expect("the fedID owns the node");

    // This device holds ONLY the roster key, active under the fedID's name —
    // what add-device's apply leaves behind.
    ciris_server::write_active_user_alias(&this_device, &fed_id).expect("active alias");
    ciris_server::node_key::set_user_seed_dir(this_device.clone(), fed_id.clone());

    // ── 2. the owner pen resolves to the roster key; consent is authored under it
    let pen = ciris_server::peer::owner_consent_pen(&engine, &node)
        .await
        .expect("a live roster key of the owner's fedID is the owner's pen")
        .expect("an owned node with the roster key on disk has a pen");
    assert_eq!(
        pen.key_id, roster.key_id,
        "the row is authored under the roster key's registered id"
    );
    let grant = ciris_server::peer::emit_replication_consent(&engine, &node, &peer, PREFIXES)
        .await
        .expect("consent authored by the roster key");
    assert!(grant.freshly_emitted);
    let by_roster = engine
        .federation_directory()
        .list_live_consent_grants_by(&roster.key_id)
        .await
        .expect("grants by the roster key");
    let row = by_roster
        .iter()
        .find(|g| g.subject_key_ids.first().map(String::as_str) == Some(peer.as_str()))
        .expect("the grant is attested by the roster key");
    assert_eq!(
        ciris_persist::federation::consent_by_humans::for_key_id_of(&row.attestation_envelope),
        Some(node.as_str()),
        "the grant is FOR this node (bound_own_key_for resolves a roster-key author)"
    );

    // ── 3. a revoked roster key is refused ──────────────────────────────────
    let now = chrono::Utc::now();
    engine
        .federation_directory()
        .put_identity_occurrence_revocation_local(IdentityOccurrenceRevocation {
            identity_key_id: fed_id.clone(),
            occurrence_key_id: roster.key_id.clone(),
            revoked_at: now,
            effective_at: now,
            reason: Some("evicted from the self roster".into()),
            witness_set: vec![fed_id.clone()],
            persist_row_hash: String::new(),
        })
        .await
        .expect("evict the roster key");
    let after = ciris_server::peer::owner_consent_pen(&engine, &node).await;
    assert!(
        after.is_err(),
        "an evicted roster key no longer signs as the fedID: {:?}",
        after.map(|p| p.map(|p| p.key_id))
    );
}
