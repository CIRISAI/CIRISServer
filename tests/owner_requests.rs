//! **What a remotely claimed node needs its owner to sign** reaches the owner,
//! is signed on the owner's own device, and is applied back on the node
//! (`ciris_server::owner_requests`).
//!
//! The production shape: a managed agent claimed with a staged binding, whose
//! owner's pen is never on it. It used to log "DEFERRED" for every owner act
//! and never ship a trace.

use std::sync::Arc;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::admission::owner_of;
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use ed25519_dalek::SigningKey;

use ciris_server::attest::{register_key, KeySigner};
use ciris_server::claim_remote::{apply_staged_owner_binding, stage_owner_binding};
use ciris_server::owner_requests::{self, ApplyRefusal, KIND_ANNOUNCE, KIND_COMMUNITY_TRUST};

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

/// A node's pen, named by its keystore alias (`derived_key_id()` is the
/// registered id).
fn node_pen(alias: &str, seed: u8) -> LocalSigner {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x5A; 32], format!("{alias}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        SigningKey::from_bytes(&[seed; 32]),
        alias.to_owned(),
        Some(pqc),
        Some(format!("{alias}-pqc")),
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
    // A split home, as a managed agent runs: the ENGINE is the agent (keyed by
    // its keystore alias, so its derived key is its registered id), and the
    // node key is held beside it and is the wire identity.
    let agent_alias = format!("{alias}-agent");
    let engine = engine_on(node_pen(&agent_alias, seed ^ 0x01)).await;
    let agent = engine.local_derived_key_id().await.expect("agent key id");
    register_key(
        &engine,
        KeySigner::Engine(&engine),
        &agent,
        "agent",
        serde_json::Value::Null,
    )
    .await
    .expect("register the agent key");
    let node_signer = pen(alias, seed);
    let node = id_of(alias, seed);
    register_key(
        &engine,
        KeySigner::Local(&node_signer),
        &node,
        "node",
        serde_json::Value::Null,
    )
    .await
    .expect("register the node key");
    // The node's wire identity, as boot sets it: every test here is the same
    // node, so the process-wide value is the same in each.
    ciris_server::node_key::set_wire_identity(&node);
    (engine, node)
}

/// The owner's own device (where `sign-owner-binding` runs).
async fn owners_device() -> Arc<Engine> {
    let engine = engine_on(node_pen("owners-laptop", 0x70)).await;
    let me = engine.local_derived_key_id().await.expect("device key id");
    register_key(
        &engine,
        KeySigner::Engine(&engine),
        &me,
        "node",
        serde_json::Value::Null,
    )
    .await
    .expect("register the device's node key");
    engine
}

async fn owner_of_node(engine: &Engine, node: &str) -> Option<String> {
    owner_of(engine.federation_directory().as_ref(), node)
        .await
        .expect("owner_of")
}

/// A managed agent's node, claimed by `owner` with a staged `self` binding.
async fn claimed_node(owner: &LocalSigner) -> (Arc<Engine>, String) {
    let (t, node) = legacy_node("ciris-agent-echo", 0x11).await;
    let staged = stage_owner_binding(&*owners_device().await, owner, &node, "self")
        .await
        .expect("the owner signs the claim on their device");
    apply_staged_owner_binding(&t, &node, HybridPolicy::Strict, &staged)
        .await
        .expect("the node takes the staged claim");
    (t, node)
}

fn kinds(requests: &[owner_requests::OwnerRequest]) -> Vec<&str> {
    let mut k: Vec<&str> = requests.iter().map(|r| r.kind.as_str()).collect();
    k.sort_unstable();
    k
}

#[tokio::test]
async fn an_unowned_node_asks_nobody() {
    let (t, _node) = legacy_node("ciris-agent-echo", 0x11).await;
    assert!(owner_requests::pending(&t)
        .await
        .expect("pending")
        .is_empty());
}

#[tokio::test]
async fn the_owner_signs_on_their_device_and_the_node_stops_asking() {
    let owner = pen("owner-fedid", 0x33);
    let (t, node) = claimed_node(&owner).await;

    let pending = owner_requests::pending(&t).await.expect("pending");
    assert_eq!(
        kinds(&pending),
        [KIND_ANNOUNCE, KIND_COMMUNITY_TRUST],
        "a claimed, unannounced node with no capture grant asks for both: {pending:?}"
    );
    assert!(pending
        .iter()
        .all(|r| r.owner_key_id == owner.key_id() && r.node_key_id == node));

    // Carried as JSON both ways by the owner's tool.
    let carried: Vec<owner_requests::OwnerRequest> =
        serde_json::from_str(&serde_json::to_string(&pending).unwrap()).unwrap();
    let device = owners_device().await;
    let signed = owner_requests::sign(&device, &owner, &node, &carried)
        .await
        .expect("sign");
    assert!(signed.refused.is_empty(), "{:?}", signed.refused);
    assert!(signed.announce.is_some());
    assert_eq!(signed.rows.len(), 1);
    let signed: owner_requests::SignedOwnerRequests =
        serde_json::from_str(&serde_json::to_string(&signed).unwrap()).unwrap();

    let applied = owner_requests::apply(&t, HybridPolicy::Strict, &signed)
        .await
        .expect("apply");
    assert!(
        applied.outcomes.iter().all(|o| o.outcome == "applied"),
        "every row the owner signed is admitted: {:?}",
        applied.outcomes
    );
    assert_eq!(applied.owner_key_id, owner.key_id());

    assert!(
        owner_requests::pending(&t)
            .await
            .expect("pending")
            .is_empty(),
        "what the owner signed is held, so nothing is asked again"
    );
    assert!(
        ciris_persist::federation::community_trust_consent::community_trust_consent_for(
            t.federation_directory().as_ref(),
            &node,
        )
        .await
        .expect("fold")
        .is_some(),
        "the capture grant stands"
    );
    assert_eq!(
        owner_of_node(&t, &node).await.as_deref(),
        Some(owner.key_id()),
        "announcing adds a row beside the claim; the owner is unchanged"
    );

    // What the owner's list of what they own now says about this node
    // (GET /v1/setup/owned-nodes, CSD-132): announced, and its agent named by
    // the capture grant the owner just signed.
    let agent = t.local_derived_key_id().await.expect("agent key id");
    let view = ciris_server::auth::bootstrap::owned_nodes_view(&t, &node).await;
    assert_eq!(view["owner"], owner.key_id());
    let row = view["nodes"]
        .as_array()
        .and_then(|n| n.iter().find(|r| r["key_id"] == node.as_str()))
        .cloned()
        .unwrap_or_else(|| panic!("the node is listed: {view}"));
    assert_eq!(row["announced"], true, "{row}");
    assert_eq!(row["agents"], serde_json::json!([agent]), "{row}");
    assert_eq!(
        row["roster_member"], false,
        "a managed agent is owned, not a roster device"
    );
}

/// The owner names the node they sign for; a request about any other node, or
/// for another owner, is not signed.
#[tokio::test]
async fn the_device_signs_only_for_the_node_and_owner_it_was_asked_for() {
    let owner = pen("owner-fedid", 0x33);
    let (t, node) = claimed_node(&owner).await;
    let pending = owner_requests::pending(&t).await.expect("pending");
    let device = owners_device().await;

    let signed = owner_requests::sign(&device, &owner, "some-other-node", &pending)
        .await
        .expect("sign");
    assert!(signed.announce.is_none() && signed.rows.is_empty());
    assert!(signed.refused.iter().all(|o| o.outcome == "wrong_node"));

    let stranger = pen("stranger", 0x44);
    let signed = owner_requests::sign(&device, &stranger, &node, &pending)
        .await
        .expect("sign");
    assert!(signed.announce.is_none() && signed.rows.is_empty());
    assert!(signed.refused.iter().all(|o| o.outcome == "not_this_owner"));
}

/// The node applies only its own owner's signatures, and only for itself.
#[tokio::test]
async fn the_node_refuses_a_bundle_not_from_its_owner_or_not_for_it() {
    let owner = pen("owner-fedid", 0x33);
    let (t, node) = claimed_node(&owner).await;
    let pending = owner_requests::pending(&t).await.expect("pending");
    let device = owners_device().await;

    let mut signed = owner_requests::sign(&device, &owner, &node, &pending)
        .await
        .expect("sign");
    signed.node_key_id = "some-other-node".into();
    assert!(matches!(
        owner_requests::apply(&t, HybridPolicy::Strict, &signed).await,
        Err(ApplyRefusal::WrongNode(_))
    ));

    // A stranger signs the same requests as if they were the owner.
    let stranger = pen("stranger", 0x44);
    let mut forged = pending.clone();
    for r in &mut forged {
        r.owner_key_id = stranger.key_id().to_owned();
    }
    let signed = owner_requests::sign(&device, &stranger, &node, &forged)
        .await
        .expect("sign");
    assert!(matches!(
        owner_requests::apply(&t, HybridPolicy::Strict, &signed).await,
        Err(ApplyRefusal::NotTheOwner(_))
    ));
    assert_eq!(
        kinds(&owner_requests::pending(&t).await.expect("pending")),
        [KIND_ANNOUNCE, KIND_COMMUNITY_TRUST],
        "nothing a stranger signed was taken"
    );
}

/// A node that accepts the baked root asks its owner to accept it too (edge's
/// Rooted walk reads the OWNER, CIRISEdge#659); the owner's device, which
/// accepts the same root, signs it, and the node holds the owner's acceptance.
#[tokio::test]
async fn the_owner_accepts_the_root_the_node_accepts() {
    let owner = pen("owner-fedid", 0x33);
    let (t, node) = claimed_node(&owner).await;
    ciris_server::mesh_genesis::install_baked_trust_root(&t)
        .await
        .expect("the node installs and accepts the baked root");
    let pending = owner_requests::pending(&t).await.expect("pending");
    let roots: Vec<&owner_requests::OwnerRequest> = pending
        .iter()
        .filter(|r| r.kind == owner_requests::KIND_ROOT_ACCEPTANCE)
        .collect();
    assert_eq!(
        roots.len(),
        1,
        "the node asks for the root it accepts: {pending:?}"
    );
    let root = roots[0].root_key_id.clone().expect("names its root");

    let device = owners_device().await;
    ciris_server::mesh_genesis::install_baked_trust_root(&device)
        .await
        .expect("the owner's device accepts the same root");
    let signed = owner_requests::sign(&device, &owner, &node, &pending)
        .await
        .expect("sign");
    assert!(signed.refused.is_empty(), "{:?}", signed.refused);
    let applied = owner_requests::apply(&t, HybridPolicy::Strict, &signed)
        .await
        .expect("apply");
    assert!(
        applied.outcomes.iter().all(|o| o.outcome == "applied"),
        "{:?}",
        applied.outcomes
    );
    let owners_roots = ciris_persist::federation::trust_root::trusted_roots_of(
        t.federation_directory().as_ref(),
        owner.key_id(),
        chrono::Utc::now(),
    )
    .await
    .expect("trusted_roots_of");
    assert!(
        owners_roots.contains(&root),
        "the walk's reader lists it: {owners_roots:?}"
    );
    assert!(owner_requests::pending(&t)
        .await
        .expect("pending")
        .is_empty());
}
