//! **A staged owner-binding claims a node the owner's fed-ID was never on**
//! (CIRISServer#811).
//!
//! Two production shapes, both from before owner-bindings were universal:
//!
//! - a managed agent owned only by its legacy `admin` ROOT, with no
//!   owner-binding at all;
//! - a node claimed remotely on ≤0.5.188, whose binding stayed on the actor key
//!   when 0.5.189 split a node key off it.
//!
//! The owner signs on their own device (`stage_owner_binding`, behind
//! `POST /v1/setup/sign-owner-binding`) and the operator applies it on the target
//! (`apply_staged_owner_binding`, behind `POST /v1/self/upgrade-owner` under the
//! node's admin session). These pin what the target admits.

use std::sync::Arc;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::admission::owner_of;
use ciris_persist::federation::types::cohort_scope;
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use ed25519_dalek::SigningKey;

use ciris_server::attest::{register_key, KeySigner};
use ciris_server::auth::ownership::{
    apply_signed_owner_binding, build_signed_owner_binding, OWNER_BINDING_INFRA_SCOPES,
};
use ciris_server::claim_remote::{apply_staged_owner_binding, stage_owner_binding, StagedRefusal};

fn id_of(alias: &str, seed: u8) -> String {
    let ed = SigningKey::from_bytes(&[seed; 32]);
    ciris_verify_core::fedcode::derive_key_id(alias, ed.verifying_key().as_bytes())
}

/// A pen for `alias` from `seed`, named by its registered id.
fn pen(alias: &str, seed: u8) -> LocalSigner {
    let key_id = id_of(alias, seed);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x5A; 32], format!("{key_id}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        SigningKey::from_bytes(&[seed; 32]),
        key_id.clone(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    )
}

async fn engine_on(p: LocalSigner) -> Arc<Engine> {
    Arc::new(
        Engine::with_signer(Arc::new(p), "sqlite::memory:")
            .await
            .expect("engine"),
    )
}

/// A managed agent's node as the legacy setup left it: its node key registered,
/// owned by nobody (the `admin` ROOT is a login, not an owner-binding).
async fn legacy_node(alias: &str, seed: u8) -> (Arc<Engine>, String) {
    let engine = engine_on(pen(alias, seed)).await;
    let node = id_of(alias, seed);
    register_key(
        &engine,
        KeySigner::Engine(&engine),
        &node,
        "node",
        serde_json::Value::Null,
    )
    .await
    .expect("register the node key");
    (engine, node)
}

/// The owner's own device (where `sign-owner-binding` runs).
async fn owners_device() -> Arc<Engine> {
    engine_on(pen("owners-laptop", 0x70)).await
}

async fn owner_of_node(engine: &Engine, node: &str) -> Option<String> {
    owner_of(engine.federation_directory().as_ref(), node)
        .await
        .expect("owner_of")
}

#[tokio::test]
async fn a_legacy_admin_agent_takes_the_owners_staged_binding() {
    let owner = pen("owner-fedid", 0x33);
    let (t, node) = legacy_node("ciris-agent-datum", 0x11).await;
    assert_eq!(
        owner_of_node(&t, &node).await,
        None,
        "legacy: no owner-binding"
    );

    let staged = stage_owner_binding(&*owners_device().await, &owner, &node, "self")
        .await
        .expect("the owner signs on their device");
    // What crosses between the two is plain JSON, carried by the operator.
    let carried: ciris_server::claim_remote::StagedOwnerBinding =
        serde_json::from_str(&serde_json::to_string(&staged).unwrap()).unwrap();

    let applied = apply_staged_owner_binding(&t, &node, HybridPolicy::Strict, &carried)
        .await
        .expect("the target applies the owner's staged binding");
    assert_eq!(applied.responsible_user_key_id, owner.key_id());
    assert_eq!(
        owner_of_node(&t, &node).await.as_deref(),
        Some(owner.key_id())
    );

    // Once owned, a staged binding never re-points it — not even a second copy.
    let again = apply_staged_owner_binding(&t, &node, HybridPolicy::Strict, &carried)
        .await
        .expect_err("an owned node key takes no staged binding");
    assert!(matches!(again, StagedRefusal::AlreadyOwned(_)), "{again:?}");
}

/// The load-balanced scouts: a binding staged for one occurrence's node key,
/// applied on its sibling, is refused before anything is written.
#[tokio::test]
async fn a_binding_staged_for_another_node_is_refused_and_writes_nothing() {
    let owner = pen("owner-fedid", 0x33);
    let (scout_a, node_a) = legacy_node("ciris-agent-scout-a", 0x21).await;
    let (_scout_b, node_b) = legacy_node("ciris-agent-scout-b", 0x22).await;
    let for_b = stage_owner_binding(&*owners_device().await, &owner, &node_b, "self")
        .await
        .unwrap();

    let refused = apply_staged_owner_binding(&scout_a, &node_a, HybridPolicy::Strict, &for_b)
        .await
        .expect_err("scout A refuses scout B's binding");
    assert!(
        matches!(refused, StagedRefusal::BindingRejected(_)),
        "{refused:?}"
    );
    assert_eq!(
        owner_of_node(&scout_a, &node_a).await,
        None,
        "nothing written"
    );
}

#[tokio::test]
async fn a_bad_cohort_is_refused() {
    let owner = pen("owner-fedid", 0x33);
    let (t, node) = legacy_node("ciris-agent-echo", 0x12).await;
    let mut staged = stage_owner_binding(&*owners_device().await, &owner, &node, "self")
        .await
        .unwrap();
    staged.cohort_scope = "everyone".into();
    let refused = apply_staged_owner_binding(&t, &node, HybridPolicy::Strict, &staged)
        .await
        .expect_err("a cohort outside the closed set is refused");
    assert!(
        matches!(refused, StagedRefusal::CohortInvalid(_)),
        "{refused:?}"
    );
    assert_eq!(owner_of_node(&t, &node).await, None);
}

/// claimtest-f's shape: claimed remotely on ≤0.5.188 (the binding names the
/// ACTOR key), split by 0.5.189 (a separate node key, unowned). The staged
/// binding onto the node key claims it.
#[tokio::test]
async fn a_split_node_whose_owner_did_not_follow_takes_a_staged_binding() {
    let owner = pen("owner-fedid", 0x33);
    let actor_pen = pen("ciris-agent-bootstrap-split", 0x41);
    let actor = actor_pen.key_id().to_string();
    let t = engine_on(actor_pen).await;
    register_key(
        &t,
        KeySigner::Engine(&t),
        &actor,
        "agent",
        serde_json::Value::Null,
    )
    .await
    .unwrap();
    let node_pen = pen("ciris-node-bootstrap-split", 0x42);
    let node = node_pen.key_id().to_string();
    register_key(
        &t,
        KeySigner::Local(&node_pen),
        &node,
        "node",
        serde_json::Value::Null,
    )
    .await
    .unwrap();
    let scopes: Vec<String> = OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let old = build_signed_owner_binding(&owner, &actor, &scopes, cohort_scope::SELF)
        .await
        .unwrap();
    apply_signed_owner_binding(&t, &actor, cohort_scope::SELF, HybridPolicy::Strict, &old)
        .await
        .unwrap();
    assert_eq!(
        owner_of_node(&t, &node).await,
        None,
        "the owner did not follow"
    );

    let staged = stage_owner_binding(&*owners_device().await, &owner, &node, "self")
        .await
        .unwrap();
    apply_staged_owner_binding(&t, &node, HybridPolicy::Strict, &staged)
        .await
        .expect("the node key takes the owner's staged binding");
    assert_eq!(
        owner_of_node(&t, &node).await.as_deref(),
        Some(owner.key_id())
    );
}

/// The manager's case: the binding is signed by a ROSTER KEY of the owner's
/// fedID (#793) on the owner's device, which attaches the roster proof (#806).
/// The target admits the proof first, so its owner is the fedID.
#[tokio::test]
async fn a_roster_key_stages_with_its_proof_and_the_owner_is_the_fedid() {
    let root = std::env::temp_dir().join(format!(
        "ciris-811s-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let usb = root.join("usb");
    std::fs::create_dir_all(&usb).unwrap();
    let identity =
        ciris_server::identity::mint_portable_software_occurrence(&usb, "owner-portable-811s")
            .await
            .expect("mint the fedID");
    let fed_id = identity.key_id.clone();
    let authorizer =
        ciris_server::identity::open_portable_identity_transiently(&usb, "owner-portable-811s")
            .expect("open the fedID's custody");

    let laptop = owners_device().await;
    laptop
        .register_federation_key(identity.key_record.clone())
        .await
        .expect("the laptop admits the fedID's record");
    let seed = root.join("home").join("identity").join("user");
    let device = ciris_server::identity::mint_local_device_occurrence(&seed, &fed_id)
        .await
        .expect("mint the laptop's roster key");
    assert!(
        ciris_server::auth::portable_occurrence::record_signed_roster_occurrence(
            &laptop,
            &authorizer,
            &fed_id,
            &device,
        )
        .await
        .is_ok(),
        "the fedID signs the laptop's key into its roster"
    );
    let roster_pen = ciris_server::identity::hardware_user_local_signer(
        ciris_server::identity::UserIdentityBackend::Software,
        &fed_id,
        seed.clone(),
    )
    .await
    .expect("open the roster key as the node does");

    let (t, node) = legacy_node("ciris-agent-echo-core", 0x13).await;
    let staged = stage_owner_binding(&laptop, &roster_pen, &node, "self")
        .await
        .unwrap();
    assert!(
        staged.owner_roster_proof.is_some(),
        "the roster key's proof rides along"
    );
    apply_staged_owner_binding(&t, &node, HybridPolicy::Strict, &staged)
        .await
        .expect("the target applies it");
    assert_eq!(
        owner_of_node(&t, &node).await.as_deref(),
        Some(fed_id.as_str()),
        "the node's owner is the fedID, not the roster key that signed"
    );
    let _ = std::fs::remove_dir_all(&root);
}
