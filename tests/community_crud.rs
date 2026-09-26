//! **Communities and affiliations — N-member rooms, end to end over the real
//! router** (CIRISServer#594, `FSD/ROSTER_AND_DRIVE_CRUD.md` §4).
//!
//! # The fixture is a mesh that has already converged
//!
//! A room is between PEOPLE, and each person's node holds their key and signs
//! as them — so a test of "three members read each other's messages" needs
//! three owners on three nodes. Here the three (or four) nodes are three
//! `Engine`s over ONE sqlite file, each with its own node key, its own
//! owner-binding, its own minted owner and its own served router. That is a
//! mesh whose replication has fully converged: every row any node writes is on
//! every node the moment it is written. It is exactly the state the real mesh
//! reaches after a round-trip, with the round-trip removed — which is what an
//! in-process test can say. The crossing itself is the ladder's (`room3`,
//! `widened_reads`).
//!
//! Sessions: the auth store is in the same file, so each node is always driven
//! with ITS OWN owner's token. Nothing here relies on a token crossing nodes.
//!
//! # What is pinned
//!
//! * every route, every refusal id, and the policy matrix: founder, member,
//!   outsider, delegate, appointed moderator;
//! * add-by-widening writes a WIDENING ROW and leaves the record alone, and the
//!   fold — not the record — is what every read reports;
//! * remove, re-add, leave, the last-founder rule, dissolve, the affiliations
//!   tier, a non-member's 404;
//! * the quorum flow (envelope → cosign on each signer's own node → assemble)
//!   for `unanimous` and `quorum:M/N`;
//! * the CIRISPersist#907 gap as an IGNORED red test, named for the issue.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{
    algorithm, attestation_type, identity_type, KeyRecord, SignedKeyRecord,
};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};
use ciris_server::auth::session::DelegationConstraints;
use ciris_server::auth::store;
use ciris_server::contacts_chat;
use ciris_server::identity::UserIdentityBackend;
use serde_json::{json, Value};

// ─── Fixture ────────────────────────────────────────────────────────────────

fn ciris_home() -> PathBuf {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("ciris-community-home-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create CIRIS_HOME");
        std::env::set_var("CIRIS_HOME", &dir);
        dir
    })
    .clone()
}

/// A unique name per call — pid AND a counter, never pid alone (tests run in
/// parallel threads of one process).
fn unique(what: &str) -> String {
    static NTH: AtomicU32 = AtomicU32::new(0);
    format!(
        "{what}-{}-{}",
        std::process::id(),
        NTH.fetch_add(1, Ordering::Relaxed)
    )
}

/// The owner's fed-ID, actually held — minted the way `POST /v1/self/identity`
/// mints one, so the route's capsule can re-open it off disk and sign as them.
struct OwnerIdentity {
    alias: String,
    key_id: String,
    seed_dir: PathBuf,
    pubkey_ed25519_base64: String,
    pubkey_ml_dsa_65_base64: String,
}

impl OwnerIdentity {
    async fn mint(prefix: &str) -> Self {
        // Serialized: the software seal's per-directory master key is created
        // on first use and a parallel first use races (see tests/contacts_chat.rs).
        static MINT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _minting = MINT.lock().await;
        let alias = unique(prefix);
        let seed_dir = ciris_home().join(&alias);
        std::fs::create_dir_all(&seed_dir).expect("owner seed dir");
        let minted = ciris_server::identity::mint_user_identity(
            UserIdentityBackend::Software,
            &alias,
            Some(prefix),
            seed_dir.clone(),
            ciris_server::identity::ActiveAlias::Adopt,
        )
        .await
        .expect("mint the owner's fed-ID");
        Self {
            alias,
            key_id: minted.key_id,
            seed_dir,
            pubkey_ed25519_base64: minted.pubkey_ed25519_base64,
            pubkey_ml_dsa_65_base64: minted.pubkey_ml_dsa_65_base64,
        }
    }

    async fn signer(&self) -> LocalSigner {
        ciris_server::identity::hardware_user_signers(
            UserIdentityBackend::Software,
            &self.alias,
            self.seed_dir.clone(),
        )
        .await
        .expect("re-open the owner's minted fed-ID")
        .0
    }
}

/// One node of the converged mesh.
struct Node {
    engine: Arc<Engine>,
    base: String,
    token: String,
    wa_id: String,
    owner: OwnerIdentity,
    _server: tokio::task::JoinHandle<()>,
}

/// An engine over the SHARED database file, keyed by its own hybrid node signer.
async fn engine_on(db: &Path, node_alias: &str, seed: u8) -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{node_alias}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[seed; 32]),
        node_alias.to_string(),
        Some(pqc),
        Some(format!("{node_alias}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, &format!("sqlite:///{}", db.display()))
            .await
            .expect("engine over the shared file"),
    )
}

async fn node_edge_signer(
    engine: &Engine,
    node_alias: &str,
    seed: u8,
) -> Arc<ciris_edge::identity::LocalSigner> {
    let dir = ciris_home().join(unique("keystore"));
    std::fs::create_dir_all(&dir).expect("keystore dir");
    let classical =
        ciris_keyring::SealedEd25519Signer::adopt(node_alias.to_string(), dir, &[seed; 32])
            .expect("adopt the node's sealed ed25519 key");
    let pqc =
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{node_alias}-pqc"))
            .expect("node ML-DSA-65 seed");
    let key_id = engine
        .local_derived_key_id()
        .await
        .expect("the engine's derived federation key_id");
    Arc::new(ciris_edge::identity::LocalSigner::new(
        key_id,
        Arc::new(classical),
        Some(Arc::new(pqc)),
    ))
}

async fn register_node_key(engine: &Engine) {
    let key_id = engine.local_derived_key_id().await.expect("derive");
    ciris_server::attest::register_key(
        engine,
        ciris_server::attest::KeySigner::Engine(engine),
        &key_id,
        identity_type::NODE,
        serde_json::Value::Null,
    )
    .await
    .expect("register the node key");
}

async fn bind_owner(engine: &Engine, owner: &OwnerIdentity) {
    let now = chrono::Utc::now();
    let envelope = json!({ "key_id": owner.key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize");
    let record = KeyRecord {
        key_id: owner.key_id.clone(),
        pubkey_ed25519_base64: owner.pubkey_ed25519_base64.clone(),
        pubkey_ml_dsa_65_base64: Some(owner.pubkey_ml_dsa_65_base64.clone()),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::USER.into(),
        identity_ref: owner.key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: owner.key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register the owner's user key");
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let node = engine.local_derived_key_id().await.expect("derive");
    ciris_server::auth::ownership::emit_steward_binding(
        engine,
        &owner.signer().await,
        &node,
        &scopes,
    )
    .await
    .expect("emit the owner-binding");
}

async fn mint_session(engine: &Engine, wa_id: &str) -> String {
    let now = chrono::Utc::now();
    let cert = WaCert {
        wa_id: wa_id.to_string(),
        name: wa_id.to_string(),
        role: WaRole::Root,
        pubkey: BASE64.encode([0u8; 32]),
        jwt_kid: format!("kid-{wa_id}"),
        password_hash: None,
        api_key_hash: None,
        oauth_provider: None,
        oauth_external_id: None,
        oauth_links: None,
        veilid_id: None,
        auto_minted: false,
        parent_wa_id: None,
        parent_signature: None,
        scopes: json!([]),
        custom_permissions: None,
        adapter_id: None,
        adapter_name: None,
        adapter_metadata: None,
        token_type: TokenType::Session,
        created: now,
        last_login: None,
        active: true,
    };
    store::upsert(engine, cert).await.expect("mint wa_cert");
    ciris_server::auth::session::test_support_issue_session_token(wa_id)
}

async fn serve(
    engine: Arc<Engine>,
    signer: Arc<ciris_edge::identity::LocalSigner>,
    seed_dir: PathBuf,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = contacts_chat::router(engine, signer, seed_dir, None, None);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// The shared file, unique per test.
fn mesh_db() -> PathBuf {
    let dir = ciris_home().join(unique("mesh"));
    std::fs::create_dir_all(&dir).expect("mesh dir");
    dir.join("mesh.db")
}

/// One claimed node on the shared file: its own node key, its own owner.
async fn node(db: &Path, who: &str, seed: u8) -> Node {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ciris_server=warn".into()),
        )
        .with_test_writer()
        .try_init();
    let node_alias = unique(&format!("node-{who}"));
    let engine = engine_on(db, &node_alias, seed).await;
    register_node_key(&engine).await;
    let owner = OwnerIdentity::mint(who).await;
    bind_owner(&engine, &owner).await;
    let wa_id = unique(&format!("wa-{who}"));
    let token = mint_session(&engine, &wa_id).await;
    let signer = node_edge_signer(&engine, &node_alias, seed).await;
    let (base, server) = serve(Arc::clone(&engine), signer, owner.seed_dir.clone()).await;
    Node {
        engine,
        base,
        token,
        wa_id,
        owner,
        _server: server,
    }
}

/// `n` nodes on one file: alice, bob, carol, dave — in that order.
async fn mesh(n: usize) -> Vec<Node> {
    let db = mesh_db();
    let mut out = Vec::new();
    for (i, who) in ["alice", "bob", "carol", "dave"].iter().take(n).enumerate() {
        out.push(node(&db, who, 0x10 + (i as u8) * 0x10).await);
    }
    out
}

// ─── HTTP helpers ───────────────────────────────────────────────────────────

async fn call(
    node: &Node,
    method: &str,
    path: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (u16, Value) {
    let client = reqwest::Client::new();
    let url = format!("{}{path}", node.base);
    let mut req = match method {
        "GET" => client.get(&url),
        "DELETE" => client.delete(&url),
        _ => client.post(&url),
    };
    if let Some(t) = token.or(Some(node.token.as_str())) {
        req = req.bearer_auth(t);
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await.expect("request");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("body");
    let v = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, v)
}

async fn get(node: &Node, path: &str) -> (u16, Value) {
    call(node, "GET", path, None, None).await
}
async fn post(node: &Node, path: &str, body: Value) -> (u16, Value) {
    call(node, "POST", path, Some(body), None).await
}
async fn delete(node: &Node, path: &str) -> (u16, Value) {
    call(node, "DELETE", path, None, None).await
}

fn reason(v: &Value) -> &str {
    v["reason_id"].as_str().unwrap_or("<no reason_id>")
}

/// `on` makes `who` a contact (a live grant covering `chat:`).
async fn contact(on: &Node, who: &Node) {
    let (s, v) = post(on, "/v1/contacts", json!({ "key_id": who.owner.key_id })).await;
    assert_eq!(s, 200, "add contact: {v}");
}

/// Found a room on `founder` with `members`, after making each a contact.
async fn found(founder: &Node, name: &str, members: &[&Node], extra: Value) -> String {
    for m in members {
        contact(founder, m).await;
    }
    let mut body = json!({
        "name": name,
        "members": members.iter().map(|m| m.owner.key_id.clone()).collect::<Vec<_>>(),
    });
    if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.insert(k.clone(), v.clone());
        }
    }
    let (s, v) = post(founder, "/v1/communities", body).await;
    assert_eq!(s, 201, "create: {v}");
    assert_eq!(v["kind"], "room");
    v["community_id"].as_str().expect("community_id").to_owned()
}

/// The active roster by persist's fold, sorted.
async fn fold(engine: &Engine, room: &str) -> Vec<String> {
    let mut v: Vec<String> = engine
        .federation_directory()
        .active_community_members(room)
        .await
        .expect("active roster")
        .into_iter()
        .map(|m| m.key_id)
        .collect();
    v.sort();
    v
}

fn sorted(keys: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = keys.iter().map(|s| (*s).to_owned()).collect();
    v.sort();
    v
}

/// Register a throwaway `user` key — a delegate's device.
async fn register_device_key(engine: &Engine, key_id: &str) {
    let now = chrono::Utc::now();
    let ed = SigningKey::from_bytes(&[0xD5; 32]);
    let mldsa = MlDsa65SoftwareSigner::from_seed_bytes(&[0xD6; 32], format!("{key_id}-pqc"))
        .expect("ml-dsa");
    let pqc_pub = ciris_keyring::PqcSigner::public_key(&mldsa)
        .await
        .expect("ml-dsa pk");
    let envelope = json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize");
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: BASE64.encode(ed.verifying_key().to_bytes()),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(pqc_pub)),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::USER.into(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register the delegate device key");
}

/// A DELEGATED bearer for `node`'s owner, with an optional allow-list.
async fn delegated_token(node: &Node, allow: Option<&[&str]>) -> String {
    use ciris_server::auth::session::DelegatedGrant;
    // The delegate device must be a registered `user`-type key: the
    // `delegates_to` door admits a registered subject only, and refuses a
    // non-infra scope to a node-type one (CC 3.4.7.3 Clause B).
    let client_id = unique("delegate-device");
    register_device_key(&node.engine, &client_id).await;
    ciris_server::auth::ownership::emit_signed_attestation(
        &node.engine,
        &node.owner.signer().await,
        attestation_type::DELEGATES_TO,
        &client_id,
        ciris_persist::federation::delegates_to_envelope(
            &client_id,
            &["owner:act-on-behalf".to_string()],
            false,
        ),
        None,
    )
    .await
    .expect("emit delegates_to(owner -> actor)");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    ciris_server::auth::session::register_delegated_grant(DelegatedGrant {
        owner_wa_id: node.wa_id.clone(),
        owner_role: ciris_server::auth::roles::UserRole::SystemAdmin,
        owner_key_id: node.owner.key_id.clone(),
        client_id,
        scope: "owner:act-on-behalf".to_string(),
        expires_at: now + 600,
        issued_at: now,
        purpose: Some("an assistant".to_string()),
        attestation_id: None,
        constraints: DelegationConstraints {
            actions_allow: allow.map(|a| a.iter().map(|s| (*s).to_string()).collect()),
            ..Default::default()
        },
    })
}

/// `appointer` appoints `who` to the room's `moderate` duty: a founder-rooted,
/// moderate-scoped `delegates_to`, signed by the appointer's own key.
async fn appoint_moderator(appointer: &Node, who: &Node) {
    ciris_server::auth::ownership::emit_signed_attestation(
        &appointer.engine,
        &appointer.owner.signer().await,
        attestation_type::DELEGATES_TO,
        &who.owner.key_id,
        ciris_persist::federation::delegates_to_envelope(
            &who.owner.key_id,
            &["moderate".to_string()],
            false,
        ),
        None,
    )
    .await
    .expect("emit delegates_to(founder -> moderator, moderate)");
}

// ─── 1. Three members, three nodes, everyone reads everyone ─────────────────

/// **The room works.** Alice founds a room with Bob and Carol named at CREATE
/// (the record — the path persist's admission sees, unlike a widening). Each
/// speaks from their own node through the real send route; each reads the
/// transcript from their own node through the real read route; every body
/// opens for every reader. The MLS group converges on the way (creator adds
/// both joiners from their KeyPackages, each joins from the Welcome addressed
/// to them) without ever gating a send.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_three_member_room_where_all_three_read_each_other() {
    let nodes = mesh(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let room = found(a, "the three of us", &[b, c], json!({})).await;
    assert!(
        room.starts_with(ciris_edge::chat::ROOM_COMMUNITY_PREFIX),
        "{room}"
    );
    assert_eq!(
        fold(&a.engine, &room).await,
        sorted(&[&a.owner.key_id, &b.owner.key_id, &c.owner.key_id])
    );

    // Bob and Carol open the room first: provisions their content occurrence
    // (the seal's wrap target) and publishes their MLS KeyPackage.
    for n in [b, c] {
        let (s, v) = get(n, &format!("/v1/chat/{room}/messages")).await;
        assert_eq!(s, 200, "first read on a joiner: {v}");
        assert_eq!(v["kind"], "room");
        assert_eq!(v["handshake"], "chat.state.join_requested", "{v}");
    }

    let mut said = Vec::new();
    for (n, text) in [
        (a, "hello from alice"),
        (b, "hi from bob"),
        (c, "carol here"),
    ] {
        let (s, v) = post(
            n,
            &format!("/v1/chat/{room}/messages"),
            json!({ "body": text }),
        )
        .await;
        assert_eq!(s, 200, "send from {}: {v}", n.owner.key_id);
        assert_eq!(v["fully_readable"], true, "every member can open it: {v}");
        said.push(text);
    }

    for n in [a, b, c] {
        let (s, v) = get(n, &format!("/v1/chat/{room}/messages")).await;
        assert_eq!(s, 200, "read on {}: {v}", n.owner.key_id);
        assert_eq!(v["total"], 3, "{v}");
        let mut bodies: Vec<&str> = v["messages"]
            .as_array()
            .expect("messages")
            .iter()
            .map(|m| m["body"].as_str().unwrap_or("<unopened>"))
            .collect();
        bodies.sort_unstable();
        let mut want = said.clone();
        want.sort_unstable();
        assert_eq!(bodies, want, "{} reads every body: {v}", n.owner.key_id);
        let mine: Vec<bool> = v["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["author"] == json!(n.owner.key_id))
            .map(|m| m["mine"].as_bool().unwrap())
            .collect();
        assert_eq!(mine, vec![true], "exactly one message is the reader's own");
    }

    // THE GROUP CONVERGED: the creator (alice, the room's only founder) added
    // both joiners on her send; each joined on their next touch above.
    for n in [a, b, c] {
        let (_, v) = get(n, &format!("/v1/chat/{room}/messages")).await;
        assert_eq!(
            v["handshake"], "chat.state.ready",
            "{}: {v}",
            n.owner.key_id
        );
    }
    let dir = a.engine.federation_directory();
    for joiner in [b, c] {
        assert!(
            ciris_edge::chat::welcome_for(&*dir, &a.owner.key_id, &room, &joiner.owner.key_id)
                .await
                .expect("welcome_for")
                .is_some(),
            "a Welcome addressed to {} is in the room",
            joiner.owner.key_id
        );
    }
}

// ─── 2. Create: every refusal ───────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_refuses_with_a_typed_reason_each() {
    let nodes = mesh(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    contact(a, b).await;

    for (body, status, id) in [
        (json!({ "name": "  " }), 400, "community.name_empty"),
        (
            json!({ "name": "x", "tier": "species" }),
            400,
            "community.bad_tier",
        ),
        (
            json!({ "name": "x", "consensus_protocol": "weighted:x" }),
            400,
            "community.bad_consensus_protocol",
        ),
        (
            json!({ "name": "x", "consensus_protocol": "quorum:1/2", "members": [b.owner.key_id] }),
            400,
            "community.bad_consensus_protocol",
        ),
        (
            // A quorum's N is the roster size: 2 people are not a 2/3.
            json!({ "name": "x", "consensus_protocol": "quorum:2/3", "members": [b.owner.key_id] }),
            400,
            "community.bad_consensus_protocol",
        ),
        (
            json!({ "name": "x", "members": [c.owner.key_id] }),
            403,
            "community.not_a_contact",
        ),
        (json!({ "nombre": "x" }), 400, "community.malformed_body"),
    ] {
        let (s, v) = post(a, "/v1/communities", body.clone()).await;
        assert_eq!(s, status, "{body}: {v}");
        assert_eq!(reason(&v), id, "{body}: {v}");
    }

    // No session at all.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/communities", a.base))
        .json(&json!({ "name": "x" }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 401);

    // A delegate — even an unconstrained one — never authors a room: the
    // record is signed with the owner's key and would outlive the delegation.
    let delegate = delegated_token(a, None).await;
    let (s, v) = call(
        a,
        "POST",
        "/v1/communities",
        Some(json!({ "name": "x" })),
        Some(&delegate),
    )
    .await;
    assert_eq!(s, 403, "{v}");
    assert_eq!(reason(&v), "community.delegate_may_not_author");

    // The owner's fed-ID cannot be opened (a node served with an empty seed
    // dir): the room is not written under anybody else's key.
    let empty = ciris_home().join(unique("empty-seed"));
    std::fs::create_dir_all(&empty).expect("empty seed dir");
    let signer = node_edge_signer_for(a).await;
    let (base, _h) = serve(Arc::clone(&a.engine), signer, empty).await;
    let resp = client
        .post(format!("{base}/v1/communities"))
        .bearer_auth(&a.token)
        .json(&json!({ "name": "x" }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 403);
    let v: Value = resp.json().await.expect("json");
    assert_eq!(reason(&v), "community.author_signer_unavailable", "{v}");

    // The happy path, for contrast, with the default protocol and tier.
    let (s, v) = post(
        a,
        "/v1/communities",
        json!({ "name": "  Book club  ", "members": [b.owner.key_id] }),
    )
    .await;
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["name"], "Book club");
    assert_eq!(v["tier"], "community");
    assert_eq!(v["consensus_protocol"], "founder_only");
    assert_eq!(v["my_role"], "founder");
    assert_eq!(v["member_count"], 2);
}

/// A second edge signer over the same node key — the router needs one, and the
/// fixture keeps no copy.
async fn node_edge_signer_for(n: &Node) -> Arc<ciris_edge::identity::LocalSigner> {
    // Any hybrid signer whose derived id is the node's works for serving; the
    // refusal under test happens before the node ever signs.
    node_edge_signer(&n.engine, &unique("spare"), 0x7F).await
}

// ─── 3. List and read — members see it, nobody else can find it ─────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_and_read_are_member_only_and_include_pair_rooms() {
    let nodes = mesh(4).await;
    let (a, b, c, d) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
    let room = found(a, "garden", &[b, c], json!({})).await;
    // A pair room too, the existing way.
    let (s, v) = post(a, "/v1/chat", json!({ "key_id": b.owner.key_id })).await;
    assert_eq!(s, 200, "{v}");
    let pair = v["community_id"].as_str().expect("pair id").to_owned();

    let (s, v) = get(a, "/v1/communities").await;
    assert_eq!(s, 200, "{v}");
    let kinds: Vec<(String, String)> = v["communities"]
        .as_array()
        .expect("communities")
        .iter()
        .map(|c| {
            (
                c["community_id"].as_str().unwrap().to_owned(),
                c["kind"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert!(kinds.contains(&(room.clone(), "room".to_owned())), "{v}");
    assert!(kinds.contains(&(pair.clone(), "pair".to_owned())), "{v}");
    assert!(
        v.get("resume").is_some(),
        "every list carries a resume cursor"
    );

    // Paging: limit=1 returns one row and a cursor that resumes after it.
    let (_, p1) = get(a, "/v1/communities?limit=1").await;
    assert_eq!(p1["total"], 1);
    let cursor = p1["resume"]
        .as_str()
        .expect("a cursor when more remain")
        .to_owned();
    let (_, p2) = get(a, &format!("/v1/communities?limit=1&after={cursor}")).await;
    assert_ne!(
        p2["communities"][0]["community_id"],
        p1["communities"][0]["community_id"]
    );

    // A member on another node lists and reads it.
    let (_, v) = get(c, "/v1/communities").await;
    assert!(
        v["communities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["community_id"] == json!(room)),
        "{v}"
    );
    let (s, v) = get(c, &format!("/v1/communities/{room}")).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["my_role"], "member");
    assert_eq!(v["roles"]["founder"], json!([a.owner.key_id]));
    assert_eq!(v["member_count"], 3);
    assert!(
        v["moderators"]
            .as_array()
            .unwrap()
            .contains(&json!(a.owner.key_id)),
        "a steward-bound founder is a zero-hop appointed moderator: {v}"
    );

    // THE OUTSIDER cannot find out it is there: same 404 as a room that
    // does not exist, on read and on every write.
    let (_, v) = get(d, "/v1/communities").await;
    assert!(
        !v["communities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["community_id"] == json!(room)),
        "{v}"
    );
    for (method, path, body) in [
        ("GET", format!("/v1/communities/{room}"), None),
        (
            "POST",
            format!("/v1/communities/{room}/members"),
            Some(json!({ "key_id": d.owner.key_id })),
        ),
        (
            "POST",
            format!("/v1/communities/{room}/leave"),
            Some(json!({})),
        ),
        ("DELETE", format!("/v1/communities/{room}"), None),
        (
            "GET",
            "/v1/communities/chat:room:v1:doesnotexist".to_string(),
            None,
        ),
    ] {
        let (s, v) = call(d, method, &path, body, None).await;
        assert_eq!(s, 404, "{method} {path}: {v}");
        assert_eq!(reason(&v), "community.not_found", "{method} {path}");
    }

    // A delegate whose allow-list omits `chat_read` cannot even list.
    let narrow = delegated_token(a, Some(&["announce"])).await;
    let (s, v) = call(a, "GET", "/v1/communities", None, Some(&narrow)).await;
    assert_eq!(s, 403, "{v}");
    assert_eq!(reason(&v), "community.delegation_denied");
    // …and one granted `chat_read` can.
    let reader = delegated_token(a, Some(&["chat_read"])).await;
    let (s, v) = call(
        a,
        "GET",
        &format!("/v1/communities/{room}"),
        None,
        Some(&reader),
    )
    .await;
    assert_eq!(s, 200, "{v}");
}

// ─── 4. Add by widening, remove, re-add — the fold, not the record ──────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn add_by_widening_then_remove_and_re_add_move_the_fold_not_the_record() {
    let nodes = mesh(4).await;
    let (a, b, c, d) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
    let room = found(a, "widen me", &[b], json!({})).await;
    let dir = a.engine.federation_directory();

    // A member not yet a contact is refused.
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": c.owner.key_id }),
    )
    .await;
    assert_eq!((s, reason(&v)), (403, "community.not_a_contact"), "{v}");
    contact(a, c).await;

    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": c.owner.key_id }),
    )
    .await;
    assert_eq!(s, 200, "add: {v}");
    assert_eq!(v["applied"], true);

    // THE ROW: one widening, on its own plane — and the record untouched.
    let widenings = dir
        .list_community_membership_widenings_for(&room)
        .await
        .expect("widenings");
    assert_eq!(widenings.len(), 1, "{widenings:?}");
    assert_eq!(widenings[0].member_key_id, c.owner.key_id);
    let record = dir
        .lookup_community(&room)
        .await
        .expect("lookup")
        .expect("room");
    let founding: Vec<&str> = record.members.iter().map(|m| m.key_id.as_str()).collect();
    assert!(
        !founding.contains(&c.owner.key_id.as_str()),
        "v48 never grows the record: {founding:?}"
    );
    // THE FOLD names her — and so does every read this server serves.
    assert!(fold(&a.engine, &room).await.contains(&c.owner.key_id));
    let (s, v) = get(c, &format!("/v1/communities/{room}")).await;
    assert_eq!(s, 200, "the widened member reads the room's record: {v}");
    assert_eq!(v["widenings"], 1);
    let (_, v) = get(c, "/v1/communities").await;
    assert!(
        v["communities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["community_id"] == json!(room)),
        "a widened member's list finds the room through the widening plane: {v}"
    );

    // Already a member.
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": c.owner.key_id }),
    )
    .await;
    assert_eq!((s, reason(&v)), (409, "community.already_member"), "{v}");

    // POLICY: a plain member may not add; an outsider cannot see the room.
    contact(b, d).await;
    let (s, v) = post(
        b,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": d.owner.key_id }),
    )
    .await;
    assert_eq!((s, reason(&v)), (403, "community.not_authorized"), "{v}");
    let (s, v) = post(
        d,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": d.owner.key_id }),
    )
    .await;
    assert_eq!((s, reason(&v)), (404, "community.not_found"), "{v}");
    // A delegate of the founder may not author a roster change.
    let delegate = delegated_token(a, None).await;
    let (s, v) = call(
        a,
        "POST",
        &format!("/v1/communities/{room}/members"),
        Some(json!({ "key_id": d.owner.key_id })),
        Some(&delegate),
    )
    .await;
    assert_eq!(
        (s, reason(&v)),
        (403, "community.delegate_may_not_author"),
        "{v}"
    );

    // REMOVE: a revocation row, and the fold drops her.
    let (s, v) = delete(
        a,
        &format!("/v1/communities/{room}/members/{}", c.owner.key_id),
    )
    .await;
    assert_eq!(s, 200, "remove: {v}");
    assert!(!fold(&a.engine, &room).await.contains(&c.owner.key_id));
    assert_eq!(
        dir.list_community_membership_revocations_for(&room)
            .await
            .expect("revs")
            .len(),
        1
    );
    let (s, v) = get(c, &format!("/v1/communities/{room}")).await;
    assert_eq!((s, reason(&v)), (404, "community.not_found"), "{v}");
    // Removing a non-member.
    let (s, v) = delete(
        a,
        &format!("/v1/communities/{room}/members/{}", d.owner.key_id),
    )
    .await;
    assert_eq!((s, reason(&v)), (409, "community.not_a_member"), "{v}");

    // RE-ADD: a second widening strictly after the removal; the fold's latest
    // event wins and she is back.
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": c.owner.key_id }),
    )
    .await;
    assert_eq!(s, 200, "re-add: {v}");
    assert!(fold(&a.engine, &room).await.contains(&c.owner.key_id));
    assert_eq!(
        dir.list_community_membership_widenings_for(&room)
            .await
            .expect("w")
            .len(),
        2
    );
    // …and removed again: a re-added member can be removed again.
    let (s, v) = delete(
        a,
        &format!("/v1/communities/{room}/members/{}", c.owner.key_id),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert!(!fold(&a.engine, &room).await.contains(&c.owner.key_id));
}

/// **CIRISPersist#907, pinned red.** A member added by WIDENING is on the
/// fold — listed, shown, sealed to — and persist's caller admission still
/// refuses them the message read, because `build_caller_admission` →
/// `list_communities_for_member_active` walks the RECORD's members only
/// (persist `scope/admission.rs` ~195, `federation/mod.rs` ~3615). Not worked
/// around server-side: the admission is persist's. Un-ignore when #907 lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "CIRISPersist#907 — persist's caller admission ignores the widening plane, so a widened member is refused chat.not_a_member"]
async fn a_widened_member_reads_the_rooms_messages_cirispersist_907() {
    let nodes = mesh(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let room = found(a, "late joiner", &[b], json!({})).await;
    contact(a, c).await;
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": c.owner.key_id }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert!(fold(&a.engine, &room).await.contains(&c.owner.key_id));
    let (s, v) = get(c, &format!("/v1/chat/{room}/messages")).await;
    assert_eq!(s, 200, "a widened member reads the transcript: {v}");
}

// ─── 5. The appointed moderator ─────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_appointed_moderator_adds_and_removes_plain_members_only() {
    let nodes = mesh(4).await;
    let (a, b, c, d) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
    let room = found(a, "moderated", &[b, c], json!({})).await;
    appoint_moderator(a, b).await;
    let (_, v) = get(a, &format!("/v1/communities/{room}")).await;
    assert!(
        v["moderators"]
            .as_array()
            .unwrap()
            .contains(&json!(b.owner.key_id)),
        "the appointment is visible: {v}"
    );
    contact(b, d).await;
    contact(c, d).await;

    // Bob, appointed, adds Dave and removes him.
    let (s, v) = post(
        b,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": d.owner.key_id }),
    )
    .await;
    assert_eq!(s, 200, "an appointed moderator adds a plain member: {v}");
    let (s, v) = delete(
        b,
        &format!("/v1/communities/{room}/members/{}", d.owner.key_id),
    )
    .await;
    assert_eq!(s, 200, "…and removes one: {v}");
    // But may not add a FOUNDER, remove the founder, or change a role.
    let (s, v) = post(
        b,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": d.owner.key_id, "role": "founder" }),
    )
    .await;
    assert_eq!((s, reason(&v)), (403, "community.not_authorized"), "{v}");
    let (s, v) = post(
        b,
        &format!("/v1/communities/{room}/members/{}/role", c.owner.key_id),
        json!({ "role": "founder" }),
    )
    .await;
    assert_eq!((s, reason(&v)), (403, "community.not_authorized"), "{v}");
    let (s, v) = delete(b, &format!("/v1/communities/{room}")).await;
    assert_eq!((s, reason(&v)), (403, "community.not_authorized"), "{v}");
    // Carol, a plain member with no appointment, may do none of it.
    let (s, v) = post(
        c,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": d.owner.key_id }),
    )
    .await;
    assert_eq!((s, reason(&v)), (403, "community.not_authorized"), "{v}");

    // Removing a founder: make Carol a second founder first, so the refusal
    // below is about WHO removes, not about orphaning the room.
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members/{}/role", c.owner.key_id),
        json!({ "role": "founder" }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = delete(
        b,
        &format!("/v1/communities/{room}/members/{}", a.owner.key_id),
    )
    .await;
    assert_eq!((s, reason(&v)), (403, "community.not_authorized"), "{v}");
    // …while a founder may remove a founder.
    let (s, v) = delete(
        c,
        &format!("/v1/communities/{room}/members/{}", a.owner.key_id),
    )
    .await;
    assert_eq!(s, 200, "{v}");
}

// ─── 6. Roles, leaving, the last founder ────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leave_role_and_the_last_founder_rule() {
    let nodes = mesh(2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let room = found(a, "handover", &[b], json!({})).await;

    // The last founder of a room with other members may not leave, by either
    // door, nor be demoted.
    let (s, v) = post(a, &format!("/v1/communities/{room}/leave"), json!({})).await;
    assert_eq!((s, reason(&v)), (409, "community.last_founder"), "{v}");
    let (s, v) = delete(
        a,
        &format!("/v1/communities/{room}/members/{}", a.owner.key_id),
    )
    .await;
    assert_eq!((s, reason(&v)), (409, "community.last_founder"), "{v}");
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members/{}/role", a.owner.key_id),
        json!({ "role": "member" }),
    )
    .await;
    assert_eq!((s, reason(&v)), (409, "community.last_founder"), "{v}");
    // Role on a non-member; an empty role.
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members/nobody-at-all/role"),
        json!({ "role": "founder" }),
    )
    .await;
    assert_eq!((s, reason(&v)), (409, "community.not_a_member"), "{v}");
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members/{}/role", b.owner.key_id),
        json!({ "role": " " }),
    )
    .await;
    assert_eq!((s, reason(&v)), (400, "community.malformed_body"), "{v}");

    // Hand over: Bob becomes a founder (a widening carrying the new role).
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members/{}/role", b.owner.key_id),
        json!({ "role": "founder" }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let (_, v) = get(b, &format!("/v1/communities/{room}")).await;
    assert_eq!(v["my_role"], "founder", "{v}");

    // Now Alice may leave — her own act, no quorum.
    let (s, v) = post(a, &format!("/v1/communities/{room}/leave"), json!({})).await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = get(a, &format!("/v1/communities/{room}")).await;
    assert_eq!((s, reason(&v)), (404, "community.not_found"), "{v}");
    assert_eq!(fold(&b.engine, &room).await, vec![b.owner.key_id.clone()]);
    // A sole remaining member is not "orphaning" anyone: Bob may leave too.
    let (s, v) = post(b, &format!("/v1/communities/{room}/leave"), json!({})).await;
    assert_eq!(s, 200, "{v}");
    assert!(fold(&b.engine, &room).await.is_empty());
}

// ─── 7. Dissolve ────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dissolve_is_the_founders_and_empties_the_fold() {
    let nodes = mesh(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let room = found(a, "short-lived", &[b, c], json!({})).await;
    let (s, v) = delete(b, &format!("/v1/communities/{room}")).await;
    assert_eq!((s, reason(&v)), (403, "community.not_authorized"), "{v}");
    let (s, v) = delete(a, &format!("/v1/communities/{room}")).await;
    assert_eq!(s, 200, "{v}");
    assert!(fold(&a.engine, &room).await.is_empty(), "nobody is left");
    assert_eq!(
        a.engine
            .federation_directory()
            .list_community_membership_revocations_for(&room)
            .await
            .expect("revs")
            .len(),
        3,
        "one revocation per member"
    );
    for n in [a, b, c] {
        let (s, v) = get(n, &format!("/v1/communities/{room}")).await;
        assert_eq!((s, reason(&v)), (404, "community.not_found"), "{v}");
    }
}

// ─── 8. Affiliations ────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn affiliations_is_the_same_machinery_at_its_own_tier() {
    let nodes = mesh(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let room = found(a, "the guild", &[b], json!({ "tier": "affiliations" })).await;
    let record = a
        .engine
        .federation_directory()
        .lookup_community(&room)
        .await
        .expect("lookup")
        .expect("room");
    assert_eq!(
        record.policy_blob,
        Some(json!({ "cohort_scope": "affiliations" })),
        "the tier rides the signed record"
    );
    let (_, v) = get(b, &format!("/v1/communities/{room}")).await;
    assert_eq!(v["tier"], "affiliations", "{v}");
    contact(a, c).await;
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": c.owner.key_id }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert!(fold(&a.engine, &room).await.contains(&c.owner.key_id));
}

// ─── 9. The quorum flow ─────────────────────────────────────────────────────

/// A `unanimous` room: one signature is not enough, the direct route says so
/// WITH the envelope, each other member cosigns on their OWN node, assemble
/// applies it — and the spent envelope is stale afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_unanimous_room_changes_through_envelope_cosign_assemble() {
    let nodes = mesh(4).await;
    let (a, b, c, d) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
    let room = found(
        a,
        "consensus",
        &[b, c],
        json!({ "consensus_protocol": "unanimous" }),
    )
    .await;
    contact(a, d).await;

    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": d.owner.key_id }),
    )
    .await;
    assert_eq!((s, reason(&v)), (409, "community.quorum_pending"), "{v}");
    assert_eq!(
        (v["valid"].clone(), v["required"].clone()),
        (json!(1), json!(3)),
        "{v}"
    );
    let env = v["change_envelope"].clone();
    let mine = v["signatures"][0].clone();

    // The envelope route builds the same bytes.
    let (s, v2) = post(
        a,
        &format!("/v1/communities/{room}/changes/envelope"),
        json!({ "op": "add", "key_id": d.owner.key_id }),
    )
    .await;
    assert_eq!(s, 200, "{v2}");
    // One change, one envelope — apart from the instant its rows carry, which
    // each build pins (persist v49: every signer signs the rows, so the rows'
    // time is part of what they sign).
    let without_row_at = |e: &Value| {
        let mut e = e.clone();
        if let Some(c) = e.get_mut("community_change").and_then(Value::as_object_mut) {
            c.remove("row_at");
        }
        e
    };
    assert_eq!(
        without_row_at(&v2["change_envelope"]),
        without_row_at(&env),
        "one change, one envelope"
    );
    assert!(
        v2["change_envelope"]["community_change"]["row_at"].is_string(),
        "the rows' instant is pinned in the envelope: {v2}"
    );

    // Only alice's signature → still pending.
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/assemble"),
        json!({ "change_envelope": env, "signatures": [mine] }),
    )
    .await;
    assert_eq!((s, reason(&v)), (409, "community.quorum_pending"), "{v}");
    // An outsider's signature counts for nothing.
    let (s, v) = post(
        d,
        &format!("/v1/communities/{room}/changes/cosign"),
        json!({ "change_envelope": env }),
    )
    .await;
    assert_eq!((s, reason(&v)), (404, "community.not_found"), "{v}");

    let mut sigs = vec![mine];
    for n in [b, c] {
        let (s, v) = post(
            n,
            &format!("/v1/communities/{room}/changes/cosign"),
            json!({ "change_envelope": env }),
        )
        .await;
        assert_eq!(s, 200, "cosign on {}: {v}", n.owner.key_id);
        assert_eq!(v["signature"]["member_id"], json!(n.owner.key_id));
        sigs.push(v["signature"].clone());
    }
    // Signatures with nothing valid in them: not authorized, not pending.
    let forged: Vec<Value> = sigs
        .iter()
        .map(|s| {
            let mut s = s.clone();
            s["ed25519_signature_base64"] = json!(BASE64.encode([7u8; 64]));
            s
        })
        .collect();
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/assemble"),
        json!({ "change_envelope": env, "signatures": forged }),
    )
    .await;
    assert_eq!((s, reason(&v)), (403, "community.not_authorized"), "{v}");

    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/assemble"),
        json!({ "change_envelope": env, "signatures": sigs }),
    )
    .await;
    assert_eq!(s, 200, "assemble: {v}");
    assert!(fold(&a.engine, &room).await.contains(&d.owner.key_id));

    // The same envelope again describes a room that no longer exists.
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/assemble"),
        json!({ "change_envelope": env, "signatures": sigs }),
    )
    .await;
    assert_eq!((s, reason(&v)), (409, "community.change_stale"), "{v}");
}

/// A `quorum:2/3` room: persist judges each roster row by the room's protocol
/// over the row's own co-signatures (v49.0.0, #908). M is absolute, so the
/// room stays a "two signatures" room after it grows, and its SECOND
/// size-changing change is authorized by two signatures too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_quorum_room_is_verified_by_persist_and_stays_changeable() {
    let nodes = mesh(4).await;
    let (a, b, c, d) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
    let room = found(
        a,
        "two of three",
        &[b, c],
        json!({ "consensus_protocol": "quorum:2/3" }),
    )
    .await;
    contact(a, d).await;

    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/envelope"),
        json!({ "op": "add", "key_id": d.owner.key_id }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["required"], 2);
    let env = v["change_envelope"].clone();
    let mut sigs = vec![v["signatures"][0].clone()];
    let (s, v) = post(
        b,
        &format!("/v1/communities/{room}/changes/cosign"),
        json!({ "change_envelope": env }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    sigs.push(v["signature"].clone());
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/assemble"),
        json!({ "change_envelope": env, "signatures": sigs }),
    )
    .await;
    assert_eq!(s, 200, "persist verifies 2-of-3 and applies: {v}");
    assert_eq!(fold(&a.engine, &room).await.len(), 4);
    let record = a
        .engine
        .federation_directory()
        .lookup_community(&room)
        .await
        .expect("lookup")
        .expect("room");
    assert_eq!(
        record.consensus_protocol, "quorum:2/3",
        "M is absolute (CC 4.4.3.4.2.1): adding a member does not rewrite the room's rule"
    );

    // The second change: remove Dave, still under "two signatures".
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/envelope"),
        json!({ "op": "remove", "key_id": d.owner.key_id }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["required"], 2);
    let env = v["change_envelope"].clone();
    let mut sigs = vec![v["signatures"][0].clone()];
    for n in [b] {
        let (s, v) = post(
            n,
            &format!("/v1/communities/{room}/changes/cosign"),
            json!({ "change_envelope": env }),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        sigs.push(v["signature"].clone());
    }
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/assemble"),
        json!({ "change_envelope": env, "signatures": sigs }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert!(!fold(&a.engine, &room).await.contains(&d.owner.key_id));
}

// ─── 10. The pair room is listed, and fixed ─────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pair_rooms_roster_cannot_be_changed_here() {
    let nodes = mesh(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    contact(a, b).await;
    contact(a, c).await;
    let (s, v) = post(a, "/v1/chat", json!({ "key_id": b.owner.key_id })).await;
    assert_eq!(s, 200, "{v}");
    let pair = v["community_id"].as_str().unwrap().to_owned();
    let (s, v) = get(a, &format!("/v1/communities/{pair}")).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["kind"], "pair");
    for (method, path, body) in [
        (
            "POST",
            format!("/v1/communities/{pair}/members"),
            Some(json!({ "key_id": c.owner.key_id })),
        ),
        (
            "POST",
            format!("/v1/communities/{pair}/leave"),
            Some(json!({})),
        ),
        ("DELETE", format!("/v1/communities/{pair}"), None),
    ] {
        let (s, v) = call(a, method, &path, body, None).await;
        assert_eq!(
            (s, reason(&v)),
            (409, "community.pair_room_fixed"),
            "{method} {path}: {v}"
        );
    }
}
