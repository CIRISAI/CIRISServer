//! CIRISServer#632 / CIRISEdge#671 — a node CARRIES its own allegiance facts,
//! and a peer that adopts them can Root it from its own directory.
//!
//! Edge v30.2.0's `Rooted(P)` at node N is walked entirely from N's directory:
//! `∃R ∈ trusted_roots_of(subject(N)) ∩ trusted_roots_of(subject(P))`, both
//! `trust_root_valid`, with `subject` = the owner when the node is claimed. So N
//! must HOLD P's owner-binding and P's (owner's) root acceptance. On the wire,
//! edge's consent send-set gate withholds exactly those rows from a peer P has
//! not consented to (CIRISEdge#671), and production's canonical consents to
//! nobody. The server's belt: P serves its allegiance facts on the read API and
//! N carries them at first contact, admitting each through persist's own doors.
//!
//! This pins the round trip in-process — the canonical's `allegiance_facts` →
//! the agent's `adopt_allegiance_facts` — and then asks persist the walk's own
//! questions from the AGENT's directory:
//!
//! 1. the facts name only the canonical's identities (node key, owner) and carry
//!    federation-tier `delegates_to` rows that name one of them or a root;
//! 2. before the carry the agent resolves no owner for the canonical and lists no
//!    roots for it; after, `owner_of(canonical)` is the owner and
//!    `trusted_roots_of(owner)` lists the baked root — `trust_root_valid` true;
//! 3. adopting twice is a no-op (already held), never a fork;
//! 4. an UNOWNED canonical carries its node-keyed acceptance and no owner rows.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord};
use ciris_persist::federation::SignedKeyRecord;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

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

async fn node(alias: &str) -> (Arc<Engine>, String) {
    let engine = Arc::new(
        Engine::with_signer(Arc::new(signer_for(alias)), "sqlite::memory:")
            .await
            .expect("engine"),
    );
    let key = engine.local_derived_key_id().await.expect("derived id");
    register(&engine, &signer_for(alias), &key, identity_type::NODE).await;
    ciris_server::mesh_genesis::install_baked_trust_root(&engine)
        .await
        .expect("the baked trust root installs (node → R accepted)");
    (engine, key)
}

/// Claim `node` for a fresh software owner with a production-shaped pen; returns
/// the owner's key id. Registers the seed dir process-wide (one owner per test
/// binary is fine — each test here claims at most one node).
async fn claim(engine: &Engine, node_key: &str, tag: &str) -> (String, std::path::PathBuf) {
    let seed_dir = std::env::temp_dir().join(format!(
        "ciris-671-{tag}-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    std::fs::create_dir_all(&seed_dir).expect("owner seed dir");
    let alias = format!("allegiance-owner-{tag}-{}", std::process::id());
    let minted = ciris_server::identity::mint_user_identity(
        ciris_server::identity::UserIdentityBackend::Software,
        &alias,
        Some("Allegiance Owner"),
        seed_dir.clone(),
        ciris_server::identity::ActiveAlias::Adopt,
    )
    .await
    .expect("mint the owner");
    let owner = minted.key_id.clone();
    let owner_signer = ciris_server::identity::hardware_user_signers(
        ciris_server::identity::UserIdentityBackend::Software,
        &alias,
        seed_dir.clone(),
    )
    .await
    .expect("re-open the owner")
    .0;
    register(engine, &owner_signer, &owner, identity_type::USER).await;
    ciris_server::node_key::set_user_seed_dir(seed_dir.clone(), alias.clone());
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    ciris_server::auth::ownership::emit_steward_binding(engine, &owner_signer, node_key, &scopes)
        .await
        .expect("the human claims the node");
    let accepted =
        ciris_server::mesh_genesis::accept_trust_roots_as_owner(engine, &owner_signer, &owner)
            .await
            .expect("the owner accepts what the node accepted");
    assert_eq!(accepted.len(), 1, "the baked root, once");
    (owner, seed_dir)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_carries_the_canonicals_allegiance_can_root_it() {
    let (canonical, canonical_key) = node("carried-canonical").await;
    let (agent, _agent_key) = node("carrying-agent").await;
    let (owner, seed_dir) = claim(&canonical, &canonical_key, "canonical").await;
    let dir_c = canonical.federation_directory();
    let root = ciris_persist::federation::trust_root::trusted_roots_of(
        dir_c.as_ref(),
        &canonical_key,
        chrono::Utc::now(),
    )
    .await
    .expect("canonical's roots")
    .first()
    .cloned()
    .expect("the canonical accepted the baked root");

    // ── 1. the facts: only the canonical's identities, only allegiance rows ──
    let facts = ciris_server::mesh_genesis::allegiance_facts(&canonical)
        .await
        .expect("assemble allegiance facts");
    let key_ids: Vec<&str> = facts
        .key_records
        .iter()
        .map(|r| r.record.key_id.as_str())
        .collect();
    assert!(
        key_ids.contains(&canonical_key.as_str()),
        "the node's key: {key_ids:?}"
    );
    assert!(
        key_ids.contains(&owner.as_str()),
        "the owner's key: {key_ids:?}"
    );
    assert_eq!(key_ids.len(), 2, "nothing else: {key_ids:?}");
    let shapes: Vec<(String, String)> = facts
        .rows
        .iter()
        .map(|r| {
            (
                r.attestation.attesting_key_id.clone(),
                r.attestation.attested_key_id.clone(),
            )
        })
        .collect();
    assert!(
        shapes.contains(&(owner.clone(), canonical_key.clone())),
        "the owner-binding owner → node rides: {shapes:?}"
    );
    assert!(
        shapes.contains(&(canonical_key.clone(), root.clone())),
        "the node's acceptance node → R rides: {shapes:?}"
    );
    assert!(
        shapes.contains(&(owner.clone(), root.clone())),
        "the owner's acceptance owner → R rides: {shapes:?}"
    );
    for r in &facts.rows {
        assert_eq!(
            r.attestation.cohort_scope,
            ciris_persist::federation::types::cohort_scope::FEDERATION,
            "every carried row is federation-scoped"
        );
        assert!(
            [canonical_key.as_str(), owner.as_str()]
                .contains(&r.attestation.attesting_key_id.as_str()),
            "every carried row is authored by one of the canonical's identities: {:?}",
            r.attestation.attesting_key_id
        );
    }

    // ── 2. before: the agent knows nothing about the canonical's allegiance ──
    let dir_a = agent.federation_directory();
    assert_eq!(
        ciris_persist::federation::admission::owner_of(dir_a.as_ref(), &canonical_key)
            .await
            .expect("owner_of runs"),
        None,
        "before the carry the agent resolves no owner for the canonical"
    );
    let adopted = ciris_server::mesh_genesis::adopt_allegiance_facts(&agent, &facts)
        .await
        .expect("adopt");
    assert_eq!(adopted.keys_registered, 2, "{adopted:?}");
    assert_eq!(adopted.rows_inserted, facts.rows.len(), "{adopted:?}");
    assert!(
        adopted.refused.is_empty(),
        "persist admitted every row: {adopted:?}"
    );

    // ── after: the walk's own questions, from the AGENT's directory ──
    assert_eq!(
        ciris_persist::federation::admission::owner_of(dir_a.as_ref(), &canonical_key)
            .await
            .expect("owner_of runs"),
        Some(owner.clone()),
        "subject(canonical) at the agent is the canonical's owner"
    );
    let peer_roots = ciris_persist::federation::trust_root::trusted_roots_of(
        dir_a.as_ref(),
        &owner,
        chrono::Utc::now(),
    )
    .await
    .expect("owner's roots at the agent");
    assert!(
        peer_roots.contains(&root),
        "roots_of(subject(canonical)) at the agent lists the shared root: {peer_roots:?}"
    );
    let verdict =
        ciris_persist::federation::trust_root::trust_root_valid(dir_a.as_ref(), &owner, &root)
            .await
            .expect("trust_root_valid runs");
    assert!(
        verdict.valid,
        "the canonical's owner's acceptance is VALID at the agent — the pair can Root: {verdict:?}"
    );

    // ── 3. idempotent ──
    let again = ciris_server::mesh_genesis::adopt_allegiance_facts(&agent, &facts)
        .await
        .expect("adopt again");
    assert_eq!(again.keys_registered, 0, "{again:?}");
    assert_eq!(again.rows_inserted, 0, "{again:?}");
    assert!(again.refused.is_empty(), "no fork on a re-carry: {again:?}");
    let _ = std::fs::remove_dir_all(&seed_dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unowned_node_carries_its_node_keyed_acceptance_and_no_owner_rows() {
    let (canonical, canonical_key) = node("unowned-canonical").await;
    let facts = ciris_server::mesh_genesis::allegiance_facts(&canonical)
        .await
        .expect("assemble");
    let key_ids: Vec<&str> = facts
        .key_records
        .iter()
        .map(|r| r.record.key_id.as_str())
        .collect();
    assert_eq!(key_ids, vec![canonical_key.as_str()], "the node's key only");
    assert!(
        facts
            .rows
            .iter()
            .all(|r| r.attestation.attesting_key_id == canonical_key),
        "every row is the node's own"
    );
    assert!(
        facts
            .rows
            .iter()
            .any(|r| r.attestation.attested_key_id != canonical_key),
        "the node → R acceptance rides (an unowned node is its own trust subject)"
    );
}
