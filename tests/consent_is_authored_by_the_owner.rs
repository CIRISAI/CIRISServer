//! Consent is by humans, not infrastructure (CIRISServer#599).
//!
//! The wizard's opt-in is the OWNER's act, so the `consent:replication` /
//! `analyze` row that records it carries the OWNER's signature — the steward
//! the owner-binding names — never the node's or the engine's. This pins:
//!
//! 1. an UNOWNED node authors provisionally as itself (boot-environment
//!    peering, the harness) — loudly, and only until it is claimed;
//! 2. an OWNED node authors AS ITS OWNER, resolved through `owner_of` and the
//!    owner's software seed compose registers (`set_user_seed_dir`);
//! 3. the production read (`replication_peers_from_consent`, asked with the
//!    node's key the runtime passes) unions the owner's grants with the legacy
//!    machine-authored ones — this is the read that returned NOTHING on every
//!    split-key home from 0.5.203 to 0.5.209;
//! 4. `migrate_consent_to_owner` re-signs the provisional row as the owner,
//!    policy carried, and is idempotent;
//! 5. the CC#46 `analyze` grant is the owner's too, and the canonical's
//!    steward-first stance read finds it;
//! 6. nobody signs as a key this process does not hold.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord};
use ciris_persist::federation::SignedKeyRecord;
use ciris_persist::prelude::{Engine, LocalSigner};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::sync::Arc;

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

const NODE: &str = "ciris-node-for-the-owner-consent-test";
const PEER_PRE: &str = "ciris-canonical-peered-before-the-claim";
const PEER: &str = "ciris-canonical-peered-after-the-claim";
const PREFIXES: &[&str] = &["trace:", "capacity:"];

fn scratch_seed_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ciris-owner-consent-{}-{}-{}",
        std::process::id(),
        tag,
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("scratch seed dir");
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_owned_node_authors_consent_as_its_owner_and_reads_it_back() {
    use ciris_persist::federation::admission::ANALYZE_CONSENT_SCOPE;
    use ciris_persist::federation::hard_case::ConsentState;

    // The owner path is gated off in production until the pinned edge reads
    // steward-authored grants (CIRISEdge#609); this test pins the path itself.
    ciris_server::peer::set_owner_authored_consent(true);
    let node_signer = Arc::new(signer_for(NODE));
    let engine = Arc::new(
        Engine::with_signer(node_signer.clone(), "sqlite::memory:")
            .await
            .expect("engine signing as the node"),
    );
    let node = engine
        .local_derived_key_id()
        .await
        .expect("the node's derived key_id");
    register(&engine, &node_signer, &node, identity_type::NODE).await;
    register(
        &engine,
        &signer_for(PEER_PRE),
        PEER_PRE,
        identity_type::NODE,
    )
    .await;
    register(&engine, &signer_for(PEER), PEER, identity_type::NODE).await;

    // ── 1. UNOWNED: provisional, authored as the node itself ──────────────
    // Narrowed AND time-boxed, so the migration below is proven to carry the
    // operator's policy rather than rebuild it (Codex P1 on #489).
    let pre_expiry = chrono::Utc::now() + chrono::Duration::days(30);
    let pre = ciris_server::peer::emit_replication_consent_with_policy(
        &engine,
        &node,
        PEER_PRE,
        PREFIXES,
        &ciris_server::peer::ConsentGrantOptions {
            valid_until: Some(pre_expiry),
            ..Default::default()
        },
    )
    .await
    .expect("an unowned node may still peer (boot-environment peering)");
    assert!(pre.freshly_emitted);
    let by_node = engine
        .federation_directory()
        .list_live_consent_grants_by(&node)
        .await
        .expect("grants by the node");
    assert!(
        by_node
            .iter()
            .any(|g| g.subject_key_ids.first().map(String::as_str) == Some(PEER_PRE)),
        "before the claim there is no human to author as: the grant is the node's, provisionally"
    );

    // ── the OWNER: minted the way the wizard mints, registered, then the claim ──
    let seed_dir = scratch_seed_dir("owner");
    let alias = format!("owner-{}", std::process::id());
    let minted = ciris_server::identity::mint_user_identity(
        ciris_server::identity::UserIdentityBackend::Software,
        &alias,
        Some("Consent Owner"),
        seed_dir.clone(),
        ciris_server::identity::ActiveAlias::Adopt,
    )
    .await
    .expect("mint the owner's fed-ID");
    let owner = minted.key_id.clone();
    let owner_signer = ciris_server::identity::hardware_user_signers(
        ciris_server::identity::UserIdentityBackend::Software,
        &alias,
        seed_dir.clone(),
    )
    .await
    .expect("re-open the owner's fed-ID")
    .0;
    // The re-opened user signer names itself `<alias>-<fp>` via `key_id()` and
    // derives once more via `derived_key_id()` (CIRISServer#597 §4); `signer_holds`
    // accepts either convention, and it is the predicate the owner pen uses.
    assert!(
        ciris_server::peer::signer_holds(&owner_signer, &owner),
        "the owner's re-opened signer holds the registered (derived) owner id"
    );
    register(&engine, &owner_signer, &owner, identity_type::USER).await;
    // What compose does at boot: tell the process where the owner's pen lives.
    ciris_server::node_key::set_user_seed_dir(seed_dir.clone(), alias.clone());
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    ciris_server::auth::ownership::emit_steward_binding(&engine, &owner_signer, &node, &scopes)
        .await
        .expect("the owner claims the node (delegates_to user → node, infra:*)");
    assert_eq!(
        ciris_server::auth::ownership::is_steward_bound(&engine, &node)
            .await
            .as_deref(),
        Some(owner.as_str()),
        "owner_of(node) resolves to the human"
    );

    // ── 2. OWNED: the owner's pen, the owner's signature ──────────────────
    let pen = ciris_server::peer::owner_consent_pen(&engine, &node)
        .await
        .expect("resolve the owner's pen")
        .expect("an owned node with a software seed on disk has a pen");
    assert_eq!(pen.key_id, owner);
    assert!(
        pen.signer.is_some(),
        "the engine does not sign as the owner; the pen does"
    );
    let grant = ciris_server::peer::emit_replication_consent(&engine, &node, PEER, PREFIXES)
        .await
        .expect("consent authored as the owner");
    assert!(grant.freshly_emitted);
    let by_owner = engine
        .federation_directory()
        .list_live_consent_grants_by(&owner)
        .await
        .expect("grants by the owner");
    assert!(
        by_owner
            .iter()
            .any(|g| g.subject_key_ids.first().map(String::as_str) == Some(PEER)),
        "the grant is attested by the OWNER's fedID: consent is by humans"
    );
    let by_node = engine
        .federation_directory()
        .list_live_consent_grants_by(&node)
        .await
        .expect("grants by the node");
    assert!(
        !by_node
            .iter()
            .any(|g| g.subject_key_ids.first().map(String::as_str) == Some(PEER)),
        "an owned node does NOT sign consent as itself"
    );
    // Idempotent: a second request finds the owner's standing grant.
    let again = ciris_server::peer::emit_replication_consent(&engine, &node, PEER, PREFIXES)
        .await
        .expect("standing grant");
    assert!(!again.freshly_emitted);

    // ── 3. THE PRODUCTION READ, asked the way the runtime asks (node key) ──
    assert_eq!(
        ciris_server::peer::consent_grantors_for(&engine, &node)
            .await
            .expect("grantor set"),
        vec![node.clone(), owner.clone()],
        "the machine itself, then the humans steward_bindings_of resolves"
    );
    assert_eq!(
        ciris_server::peer::replication_peers_from_consent(&engine, &node)
            .await
            .expect("consent peers"),
        {
            let mut v = vec![PEER.to_string(), PEER_PRE.to_string()];
            v.sort();
            v
        },
        "the owner's grant AND the provisional one both resolve for the node — this \
         is the read that returned nothing on every split-key home 0.5.203–0.5.209"
    );

    // ── 4. MIGRATION: the provisional row is re-signed by the owner ───────
    let moved = ciris_server::node_key::migrate_consent_to_owner(&engine)
        .await
        .expect("re-sign as the owner");
    assert_eq!(moved, vec![PEER_PRE.to_string()]);
    let by_owner = engine
        .federation_directory()
        .list_live_consent_grants_by(&owner)
        .await
        .expect("grants by the owner");
    let re_signed = by_owner
        .iter()
        .find(|g| g.subject_key_ids.first().map(String::as_str) == Some(PEER_PRE))
        .expect("the owner now holds the pre-claim peer's grant");
    let prefixes = re_signed.attestation_envelope["payload"]["attestation_prefixes"]
        .as_array()
        .expect("prefixes carried")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();
    let mut expected: Vec<&str> = PREFIXES.to_vec();
    expected.sort(); // the grant payload is normalized (sorted + deduped)
    assert_eq!(
        prefixes, expected,
        "the policy is carried off the live row, not rebuilt"
    );
    let carried_until = re_signed.attestation_envelope["payload"]["valid_until"]
        .as_str()
        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
        .expect("valid_until carried onto the human-signed row");
    assert_eq!(
        carried_until.timestamp_millis(),
        pre_expiry.timestamp_millis(),
        "the time-box is the operator's, not dropped or widened"
    );
    assert_eq!(
        ciris_persist::federation::consent_by_humans::for_key_id_of(
            &re_signed.attestation_envelope
        ),
        Some(node.as_str()),
        "the human's re-signed row names the machine it is for"
    );
    assert!(
        ciris_server::node_key::migrate_consent_to_owner(&engine)
            .await
            .expect("second pass")
            .is_empty(),
        "idempotent"
    );

    // ── 5. The CC#46 analyze grant is the owner's; the steward-first read finds it ──
    let analyze = ciris_server::peer::emit_analyze_consent(&engine, &node, PEER)
        .await
        .expect("analyze consent");
    assert!(analyze.is_some(), "freshly authored");
    let stance = engine
        .federation_directory()
        .resolve_scoped_consent(
            PEER,
            &owner,
            ANALYZE_CONSENT_SCOPE,
            None,
            chrono::Utc::now(),
        )
        .await
        .expect("stance read");
    assert_eq!(
        stance,
        ConsentState::Granted,
        "the OWNER consented to being analyzed by PEER"
    );
    assert_eq!(
        ciris_server::peer::consent_author(&engine, &node, None)
            .await
            .expect("author")
            .key_id,
        owner,
        "`consent_author` — what the stance probe defaults its subject to — names the owner"
    );

    // ── 6. Nobody signs as a key this process does not hold ───────────────
    match ciris_server::peer::consent_author(&engine, PEER, None).await {
        Ok(author) => panic!(
            "a foreign key must be refused, got author {}",
            author.key_id
        ),
        Err(err) => assert!(err.to_string().contains("nobody here holds"), "{err}"),
    }
}
