//! **The owner re-binds a split node from their own device** (CIRISServer#811).
//!
//! The production state, built on a live substrate: a node claimed remotely on
//! ≤0.5.188 ran on its AGENT key, so the owner-binding names that key; 0.5.189
//! split a separate NODE key off it, and the binding could not follow because
//! the owner's pen was never on the node. `owner_of(node key)` is empty.
//!
//! These pin the door that closes it: the same owner (the same key, or a roster
//! key of the same fedID) re-binds; anyone else, an owned node, a node with no
//! predecessor binding, and a binding for another node are each refused by name,
//! and a refusal writes nothing.

use std::sync::Arc;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::admission::owner_of;
use ciris_persist::federation::types::cohort_scope;
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use ed25519_dalek::SigningKey;

use ciris_server::attest::{register_key, KeySigner};
use ciris_server::auth::ownership::{
    apply_signed_owner_binding, build_signed_owner_binding, SignedOwnerBinding,
    OWNER_BINDING_INFRA_SCOPES,
};
use ciris_server::owner_rebind::{
    admit_owner_rebind, owner_binding_state, OwnerBindingState, RebindRefusal,
};

const ACTOR_ALIAS: &str = "ciris-agent-bootstrap-rebind";
const NODE_ALIAS: &str = "ciris-node-bootstrap-rebind";

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

fn scopes() -> Vec<String> {
    OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// The split node as 0.5.189+ leaves it: the engine on the actor key (as ≤0.5.188
/// ran), the actor registered `agent` and owned by `owner`, a separate node key
/// registered `node` and owned by nobody.
async fn split_node(owner: &LocalSigner) -> (Arc<Engine>, String, String) {
    let actor_pen = Arc::new(pen(ACTOR_ALIAS, 0x11));
    let actor = actor_pen.key_id().to_string();
    let engine = Arc::new(
        Engine::with_signer(actor_pen, "sqlite::memory:")
            .await
            .expect("engine"),
    );
    register_key(
        &engine,
        KeySigner::Engine(&engine),
        &actor,
        "agent",
        serde_json::Value::Null,
    )
    .await
    .expect("register the actor key");
    let node_pen = pen(NODE_ALIAS, 0x22);
    let node = node_pen.key_id().to_string();
    register_key(
        &engine,
        KeySigner::Local(&node_pen),
        &node,
        "node",
        serde_json::Value::Null,
    )
    .await
    .expect("register the node key");

    let original = build_signed_owner_binding(owner, &actor, &scopes(), cohort_scope::SELF)
        .await
        .expect("the ≤0.5.188 owner-binding");
    apply_signed_owner_binding(
        &engine,
        &actor,
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &original,
    )
    .await
    .expect("apply it to the actor key");
    (engine, actor, node)
}

async fn binding_for(signer: &LocalSigner, node: &str) -> SignedOwnerBinding {
    build_signed_owner_binding(signer, node, &scopes(), cohort_scope::SELF)
        .await
        .expect("build the re-bind")
}

async fn owner_of_node(engine: &Engine, node: &str) -> Option<String> {
    owner_of(engine.federation_directory().as_ref(), node)
        .await
        .expect("owner_of")
}

#[tokio::test]
async fn the_same_owner_rebinds_the_split_node_from_their_device() {
    let owner = pen("owner-fedid", 0x33);
    let (engine, actor, node) = split_node(&owner).await;

    assert_eq!(
        owner_binding_state(&engine, &node, Some(&actor))
            .await
            .unwrap(),
        OwnerBindingState::SplitUnfollowed {
            actor_key_id: actor.clone(),
            actor_owner_key_id: owner.key_id().to_string(),
        },
        "the state the node reports before the re-bind"
    );
    assert_eq!(owner_of_node(&engine, &node).await, None);

    let applied = admit_owner_rebind(
        &engine,
        &node,
        Some(&actor),
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &binding_for(&owner, &node).await,
        None,
    )
    .await
    .expect("the actor key's owner re-binds the node key");
    assert_eq!(applied.responsible_user_key_id, owner.key_id());
    assert_eq!(
        owner_of_node(&engine, &node).await.as_deref(),
        Some(owner.key_id())
    );
    assert_eq!(
        owner_binding_state(&engine, &node, Some(&actor))
            .await
            .unwrap(),
        OwnerBindingState::Owned
    );

    // Shut once owned: a second re-bind, even by the owner, is refused.
    let again = admit_owner_rebind(
        &engine,
        &node,
        Some(&actor),
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &binding_for(&owner, &node).await,
        None,
    )
    .await
    .expect_err("an owned node key is not re-bound");
    assert!(matches!(again, RebindRefusal::AlreadyOwned), "{again}");
    assert_eq!(again.status(), axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn someone_else_cannot_rebind_and_nothing_is_written() {
    let owner = pen("owner-fedid", 0x33);
    let stranger = pen("stranger", 0x44);
    let (engine, actor, node) = split_node(&owner).await;

    let refused = admit_owner_rebind(
        &engine,
        &node,
        Some(&actor),
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &binding_for(&stranger, &node).await,
        None,
    )
    .await
    .expect_err("a stranger's binding is refused");
    assert!(
        matches!(refused, RebindRefusal::NotTheOwner { .. }),
        "{refused}"
    );
    assert_eq!(refused.status(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(owner_of_node(&engine, &node).await, None, "nothing written");
}

#[tokio::test]
async fn a_binding_for_another_node_is_refused() {
    let owner = pen("owner-fedid", 0x33);
    let (engine, actor, node) = split_node(&owner).await;
    let elsewhere = id_of("ciris-node-elsewhere", 0x55);

    let refused = admit_owner_rebind(
        &engine,
        &node,
        Some(&actor),
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &binding_for(&owner, &elsewhere).await,
        None,
    )
    .await
    .expect_err("a binding attesting another node key is refused");
    assert!(matches!(refused, RebindRefusal::Binding(_)), "{refused}");
    assert_eq!(owner_of_node(&engine, &node).await, None);
}

#[tokio::test]
async fn no_actor_or_an_unowned_actor_is_not_a_rebind() {
    let owner = pen("owner-fedid", 0x33);
    let (engine, actor, node) = split_node(&owner).await;
    let b = binding_for(&owner, &node).await;

    let no_split = admit_owner_rebind(
        &engine,
        &node,
        None,
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &b,
        None,
    )
    .await
    .expect_err("a node with no actor key has nothing to follow");
    assert!(matches!(no_split, RebindRefusal::NoSplit), "{no_split}");

    // A second, unclaimed split node: the actor key is unowned too — a claim, not a re-bind.
    let actor_pen = Arc::new(pen("ciris-agent-unowned", 0x66));
    let other_actor = actor_pen.key_id().to_string();
    let other = Arc::new(
        Engine::with_signer(actor_pen, "sqlite::memory:")
            .await
            .unwrap(),
    );
    register_key(
        &other,
        KeySigner::Engine(&other),
        &other_actor,
        "agent",
        serde_json::Value::Null,
    )
    .await
    .unwrap();
    let unowned = admit_owner_rebind(
        &other,
        &node,
        Some(&other_actor),
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &b,
        None,
    )
    .await
    .expect_err("an unowned actor key is a claim, not a re-bind");
    assert!(matches!(unowned, RebindRefusal::ActorUnowned), "{unowned}");
    assert_eq!(
        owner_binding_state(&other, &node, Some(&other_actor))
            .await
            .unwrap(),
        OwnerBindingState::Unowned
    );
    let _ = actor;
}

/// The manager's case: the owner's fedID claimed the node on ≤0.5.188, and the
/// re-bind is signed by a ROSTER KEY of that fedID (#793), carrying the roster
/// proof (#806). Without the proof the same binding is a stranger's.
#[tokio::test]
async fn a_roster_key_of_the_owners_fedid_rebinds_with_its_proof() {
    let root = std::env::temp_dir().join(format!(
        "ciris-811-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let usb = root.join("usb");
    std::fs::create_dir_all(&usb).unwrap();
    let identity =
        ciris_server::identity::mint_portable_software_occurrence(&usb, "owner-portable-811")
            .await
            .expect("mint the fedID");
    let fed_id = identity.key_id.clone();
    // The fedID's own pen, from its portable seeds (the ≤0.5.188 claimer).
    let read32 = |name: &str| -> [u8; 32] {
        std::fs::read(usb.join(name)).expect("portable seed")[..32]
            .try_into()
            .expect("32-byte seed")
    };
    let fed_pen = LocalSigner::from_parts(
        SigningKey::from_bytes(&read32("owner-portable-811.ed25519.seed")),
        fed_id.clone(),
        Some(Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(
                &read32("owner-portable-811.mldsa65.seed"),
                format!("{fed_id}-pqc"),
            )
            .expect("ML-DSA-65 seed"),
        )),
        Some(format!("{fed_id}-pqc")),
    );
    assert_eq!(fed_pen.key_id(), fed_id);
    let (engine, actor, node) = split_node(&fed_pen).await;

    // The owner's other device L: the fedID signs L's roster key into its roster.
    let l_pen = Arc::new(pen("ciris-local-device", 0x77));
    let l = Arc::new(Engine::with_signer(l_pen, "sqlite::memory:").await.unwrap());
    l.register_federation_key(identity.key_record.clone())
        .await
        .expect("L admits the fedID's record");
    let authorizer =
        ciris_server::identity::open_portable_identity_transiently(&usb, "owner-portable-811")
            .expect("open the fedID's custody");
    let seed = root.join("home").join("identity").join("user");
    let device = ciris_server::identity::mint_local_device_occurrence(&seed, &fed_id)
        .await
        .expect("mint the roster key");
    assert!(
        ciris_server::auth::portable_occurrence::record_signed_roster_occurrence(
            &l,
            &authorizer,
            &fed_id,
            &device,
        )
        .await
        .is_ok(),
        "the fedID signs L's key into its roster"
    );
    let proof = ciris_server::claim_remote::roster_proof_for(&l, &device.key_id)
        .await
        .expect("L holds a signed roster row for its key");
    let roster_pen = ciris_server::identity::hardware_user_local_signer(
        ciris_server::identity::UserIdentityBackend::Software,
        &fed_id,
        seed.clone(),
    )
    .await
    .expect("open the roster key as the node does");
    let b = binding_for(&roster_pen, &node).await;

    let without = admit_owner_rebind(
        &engine,
        &node,
        Some(&actor),
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &b,
        None,
    )
    .await
    .expect_err("without its proof a roster key is nobody's");
    assert!(
        matches!(without, RebindRefusal::NotTheOwner { .. }),
        "{without}"
    );
    assert_eq!(owner_of_node(&engine, &node).await, None);

    admit_owner_rebind(
        &engine,
        &node,
        Some(&actor),
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &b,
        Some(&proof),
    )
    .await
    .expect("with the proof, the fedID's roster key re-binds");
    assert_eq!(
        owner_of_node(&engine, &node).await.as_deref(),
        Some(fed_id.as_str()),
        "the node's owner is the fedID, as on the actor key — not the roster key that signed"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Over HTTP, as the owner's device drives it: `rebind_remote` reads the split
/// node's `GET /v1/identity`, signs onto its node key, and posts to
/// `POST /v1/setup/owner-rebind`; the node's `setup/status` reports the state
/// before and after.
#[tokio::test]
async fn the_owners_device_rebinds_over_http() {
    let owner = pen("owner-fedid", 0x33);
    let (engine, actor, node) = split_node(&owner).await;
    // The serve path records the split's actor (compose); this process is that node.
    ciris_server::node_key::set_actor_identity(&actor);

    let node_pub = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(
            SigningKey::from_bytes(&[0x22; 32])
                .verifying_key()
                .to_bytes(),
        )
    };
    let identity = serde_json::json!({ "node_key_id": node, "actor_key_id": actor });
    let app = ciris_server::auth::bootstrap::router(
        Arc::clone(&engine),
        HybridPolicy::Strict,
        node.clone(),
        node_pub,
        None,
        None,
    )
    .route(
        "/v1/identity",
        axum::routing::get(move || {
            let identity = identity.clone();
            async move { axum::Json(identity) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    let http = reqwest::Client::new();
    let status = |http: reqwest::Client, base: String| async move {
        http.get(format!("{base}/v1/setup/status"))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap()["data"]["owner_binding"]
            .clone()
    };
    let before = status(http.clone(), base.clone()).await;
    assert_eq!(before["state"], "split_unfollowed", "{before}");
    assert_eq!(before["actor_key_id"], actor.as_str());

    // A stranger's device is refused by name.
    let stranger = pen("stranger", 0x44);
    let err = ciris_server::owner_rebind::rebind_remote(&http, &stranger, &base, "self", None)
        .await
        .expect_err("a stranger is refused");
    assert!(
        err.to_string().contains("owner_rebind.not_the_owner"),
        "{err}"
    );

    let answer = ciris_server::owner_rebind::rebind_remote(&http, &owner, &base, "self", None)
        .await
        .expect("the owner's device re-binds");
    assert_eq!(answer["owner_key_id"], owner.key_id());
    assert_eq!(answer["node_key_id"], node.as_str());
    assert_eq!(status(http, base).await["state"], "owned");
}
