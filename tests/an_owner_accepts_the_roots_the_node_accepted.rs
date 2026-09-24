//! CIRISServer#632 step 2 — the OWNER accepts the trust root, in their own hand.
//!
//! Edge v30.2.0's `Rooted` (CIRISEdge#659, `FSD/CIRIS_EDGE_TRANSPORT.md` §5.3)
//! is a pair property: `∃R ∈ roots_of(owner_of(N)) ∩ roots_of(owner_of(P))`,
//! valid and pinned, where `roots_of(k)` is persist's `trusted_roots_of(k)` —
//! the live `delegates_to(k → R, infra:*)` at federation, keyed on the OWNER.
//! The server wrote only the NODE's edge (`accept_trust_root`, bootstrap
//! default trust), so under the new walk no node was Rooted by any peer. This
//! pins the owner's edge:
//!
//! 1. an UNOWNED node has nothing to sign as — `Ok(None)`, no row;
//! 2. once the human claims the node, `accept_roots_as_owner` writes
//!    `delegates_to(owner → R, infra:attest, infra:serve)` at federation for the
//!    baked root the node accepted, attested by the OWNER's key, and persist's
//!    `trusted_roots_of(owner)` — the walk's own reader — lists R;
//! 3. it is idempotent (a second call writes nothing);
//! 4. persist's `trust_root_valid(owner, R)` — the walk's validity leg, with
//!    v47.3.0's holder-hardware conjunct — is reported by name for the baked
//!    production root, whose three accord holders carry real custody evidence.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord};
use ciris_persist::federation::SignedKeyRecord;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

const NODE_ALIAS: &str = "ciris-node-whose-owner-accepts-the-root";

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_owner_accepts_the_baked_root_the_node_accepted() {
    let engine = Arc::new(
        Engine::with_signer(Arc::new(signer_for(NODE_ALIAS)), "sqlite::memory:")
            .await
            .expect("engine signing as the node"),
    );
    let node = engine
        .local_derived_key_id()
        .await
        .expect("node derived id");
    register(&engine, &signer_for(NODE_ALIAS), &node, identity_type::NODE).await;

    // The node accepts the baked root at boot (records + node→R edge).
    ciris_server::mesh_genesis::install_baked_trust_root(&engine)
        .await
        .expect("the baked trust root installs");
    let dir = engine.federation_directory();
    let now = chrono::Utc::now();
    let node_roots =
        ciris_persist::federation::trust_root::trusted_roots_of(dir.as_ref(), &node, now)
            .await
            .expect("node's roots");
    let root = node_roots
        .first()
        .cloned()
        .expect("premise: the node accepted the baked root");

    // ── 1. unowned: nothing to sign as ────────────────────────────────────
    assert_eq!(
        ciris_server::node_key::accept_roots_as_owner(&engine)
            .await
            .expect("runs"),
        None,
        "an unowned node has no owner to accept as"
    );

    // ── the human claims the node (production-shaped pen) ────────────────
    let seed_dir = std::env::temp_dir().join(format!(
        "ciris-632-owner-accepts-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    std::fs::create_dir_all(&seed_dir).expect("owner seed dir");
    let alias = format!("root-accepting-owner-{}", std::process::id());
    let minted = ciris_server::identity::mint_user_identity(
        ciris_server::identity::UserIdentityBackend::Software,
        &alias,
        Some("Root Accepting Owner"),
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
    register(&engine, &owner_signer, &owner, identity_type::USER).await;
    ciris_server::node_key::set_user_seed_dir(seed_dir.clone(), alias.clone());
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    ciris_server::auth::ownership::emit_steward_binding(&engine, &owner_signer, &node, &scopes)
        .await
        .expect("the human claims the node");
    // persist's `trusted_roots_of(owner)` folds EVERY live `delegates_to(owner →
    // X, infra:*)` at federation that is not self-referential — the owner-binding
    // just written (owner → node) is one such row. So the premise is "the owner
    // does not accept THE ROOT", never "accepts nothing".
    let before = ciris_persist::federation::trust_root::trusted_roots_of(dir.as_ref(), &owner, now)
        .await
        .expect("owner's roots");
    assert!(
        !before.contains(&root),
        "premise: before step 2 the OWNER does not accept the root — the walk had nothing \
         to read (owner's rows: {before:?})"
    );

    // ── 2. the owner accepts what the node accepted ───────────────────────
    let newly = ciris_server::node_key::accept_roots_as_owner(&engine)
        .await
        .expect("runs")
        .expect("the node is owned and the pen is here");
    assert_eq!(newly, vec![root.clone()], "the baked root, once");
    let owner_roots =
        ciris_persist::federation::trust_root::trusted_roots_of(dir.as_ref(), &owner, now)
            .await
            .expect("owner's roots");
    assert!(
        owner_roots.contains(&root),
        "persist's own reader — the walk's roots_of(owner) — lists the root: {owner_roots:?}"
    );
    let rows = dir
        .list_attestations_by(&owner)
        .await
        .expect("rows by the owner");
    let edge = rows
        .iter()
        .find(|a| {
            a.attested_key_id == root
                && a.attestation_type
                    == ciris_persist::federation::types::attestation_type::DELEGATES_TO
        })
        .expect("the owner's delegates_to(owner → root)");
    assert_eq!(
        edge.attesting_key_id, owner,
        "signed by the OWNER, not the node"
    );
    assert_eq!(
        edge.cohort_scope,
        ciris_persist::federation::types::cohort_scope::FEDERATION,
        "at federation — the row must cross to the peers that walk it"
    );
    assert!(
        edge.subject_key_ids.is_empty(),
        "the root is named, never made a subject: a root must not be able to revoke an \
         owner's acceptance of it"
    );

    // ── 3. idempotent ─────────────────────────────────────────────────────
    assert_eq!(
        ciris_server::node_key::accept_roots_as_owner(&engine)
            .await
            .expect("runs")
            .expect("still owned"),
        Vec::<String>::new(),
        "a second call writes nothing"
    );

    // ── 4. the validity leg the walk applies, by name ─────────────────────
    let verdict =
        ciris_persist::federation::trust_root::trust_root_valid(dir.as_ref(), &owner, &root)
            .await
            .expect("trust_root_valid runs");
    assert!(
        verdict.edge_exists,
        "leg 1 of trust_root_valid IS the row just written: {verdict:?}"
    );
    assert!(
        verdict.valid,
        "the OWNER's acceptance of the baked production root must be VALID under persist \
         v47.3.0 — its three accord holders carry real custody evidence (Layer A) chained to \
         Yubico's root (Layer B): {verdict:?}"
    );

    let _ = std::fs::remove_dir_all(&seed_dir);
}
