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
//!   (0.5.218: persist v49 closed #907 — the test runs, un-ignored.)
//!
//! # Consent to join (0.5.218) — and the invite flow at persist v52
//!
//! **Since edge v38.0.0 / persist v52.0.0** the doors below open as the invite
//! flow: `POST …/members` and `POST …/invites` answer 202 `invited`; the
//! invitee accepts on their own node (`POST /v1/self/invites/{p}/accept`); a
//! founder listing `…/invites` seats them. [`join_by_invitation`] walks that
//! real path wherever a test needs a member added under `founder_only`, and
//! `the_invite_flow_seats_only_the_person_who_accepted` pins it end to end.
//! A founding roster with others is a TEST-ONLY record the members CO-SIGN
//! (persist Q1; the server has no founding-cosign flow). The paragraph below
//! is the record of the interim cut.
//!
//! Every roster-growing door now answers 409 `membership.consent_required`
//! (CIRISConstitution#133, CIRISPersist#955, `FSD/MEMBERSHIP_INVITES.md`): a
//! direct add, a quorum add, and a create naming anyone but the founder. The
//! tests below assert each refusal; where a test's PURPOSE is what a
//! multi-member room does (read, remove, role, moderator, quorum, the #907
//! read), the roster is built by the `test_only_*` fixtures, which write the
//! owner-signed record / widening rows straight through persist — the same
//! rows the routes wrote before 0.5.218, and never a production path.

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

    /// The same fed-ID in EDGE's signer type — what a record / widening is
    /// signed with (the capsule's `edge_signer`).
    async fn edge_signer(&self) -> ciris_edge::identity::LocalSigner {
        ciris_server::identity::hardware_user_signers(
            UserIdentityBackend::Software,
            &self.alias,
            self.seed_dir.clone(),
        )
        .await
        .expect("re-open the owner's minted fed-ID")
        .1
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
    let app = contacts_chat::router(Arc::clone(&engine), signer, seed_dir.clone(), None, None)
        .merge(ciris_server::membership_invites::router(engine, seed_dir));
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

// ─── TEST-ONLY roster fixtures — the consent-to-join BYPASS ─────────────────
//
// Since 0.5.218 `POST /v1/communities` refuses a founding roster naming anyone
// but the founder, and every add is `membership.consent_required`
// (CIRISConstitution#133, CIRISPersist#955). These write the rows the routes
// wrote before — owner-signed, through persist's own doors — so the tests of
// what a multi-member room DOES keep a room to do it in. Under `tests/` only;
// there is no production bypass.

/// TEST-ONLY (bypasses the consent-to-join door): found a room on `founder`
/// with `members` on its founding RECORD, after making each a contact — the
/// record `POST /v1/communities` wrote before 0.5.218, signed by the founder's
/// pen, plus the founder's content occurrence the route provisioned. `extra`
/// takes `consensus_protocol` and `tier` as the route did.
async fn test_only_found(founder: &Node, name: &str, members: &[&Node], extra: Value) -> String {
    for m in members {
        contact(founder, m).await;
    }
    let protocol = extra["consensus_protocol"]
        .as_str()
        .unwrap_or("majority")
        .to_owned();
    let community_id = ciris_edge::chat::new_room_community_key_id();
    // Rooms seeded here test the machinery of rooms of three or more, which
    // 0.5.246 closes in production (two people per room) and 0.6 re-opens.
    ciris_server::communities::lift_room_limit_for_tests(&community_id);
    let founded_at = chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
        .expect("ms instant");
    let mut roster: Vec<(&str, Option<&str>)> = vec![(
        founder.owner.key_id.as_str(),
        Some(ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER),
    )];
    roster.extend(members.iter().map(|m| (m.owner.key_id.as_str(), None)));
    let mut record =
        ciris_edge::chat::community(&community_id, name, &roster, &protocol, founded_at)
            .expect("TEST-ONLY: the room record");
    if extra["tier"] == json!("affiliations") {
        record.policy_blob = Some(json!({ "cohort_scope": "affiliations" }));
    }
    let canonical =
        ceg_produce_canonicalize(&record.signing_envelope()).expect("canonicalize the room");
    let mut signed = ciris_edge::chat::signed_community(record, &founder.owner.edge_signer().await)
        .await
        .expect("TEST-ONLY: the founder signs the room");
    // persist v52 Q1 (CIRISPersist#955): a founding member is seated only if
    // they SIGNED the founding record. The server has no founding-cosign flow,
    // so this fixture plays each member co-signing with their own pen.
    for m in members {
        let (classical, pqc) = ciris_edge::identity::sign_bound_hybrid(
            &m.owner.edge_signer().await,
            &canonical,
            "TEST-ONLY founding co-signature",
        )
        .await
        .expect("a founding member co-signs");
        signed
            .cosignatures
            .push(ciris_persist::federation::types::RosterCosignature {
                authority_key_id: m.owner.key_id.clone(),
                scrub_signature_classical: classical,
                scrub_signature_pqc: pqc,
            });
    }
    founder
        .engine
        .federation_directory()
        .put_community(signed)
        .await
        .expect("TEST-ONLY: put the multi-member room directly");
    ciris_server::backend::provision_engine_occurrence(&founder.engine, &founder.owner.key_id)
        .await
        .expect("the founder's content occurrence");
    community_id
}

/// A room change the way a room makes one: `on` builds the envelope and signs,
/// each of `voters` cosigns on their own node, and `on` assembles.
async fn carried(on: &Node, room: &str, voters: &[&Node], op: Value) -> Value {
    let (s, v) = post(on, &format!("/v1/communities/{room}/changes/envelope"), op).await;
    assert_eq!(s, 200, "envelope: {v}");
    let env = v["change_envelope"].clone();
    let mut sigs = vec![v["signatures"][0].clone()];
    for n in voters {
        let (s, v) = post(
            n,
            &format!("/v1/communities/{room}/changes/cosign"),
            json!({ "change_envelope": env }),
        )
        .await;
        assert_eq!(s, 200, "cosign: {v}");
        sigs.push(v["signature"].clone());
    }
    let (s, v) = post(
        on,
        &format!("/v1/communities/{room}/changes/assemble"),
        json!({ "change_envelope": env, "signatures": sigs }),
    )
    .await;
    assert_eq!(s, 200, "assemble: {v}");
    v
}

/// **`who` joins `room` the way a person does** (persist v52, CIRISPersist#955):
/// `on` invites them through the route, `who` accepts on THEIR node with
/// their own pen, and `on` — a founder of a `founder_only` room — lists the
/// invites, which seats the accepted invitee (edge's `widen_on_acceptance`
/// with `on`'s person key). No bypass: every row is one a production node
/// writes. Before 0.5.218's v52 adopt this was `test_only_widen`, a direct
/// owner-signed widening.
async fn join_by_invitation(
    on: &Node,
    room: &str,
    who: &Node,
    role: Option<&str>,
    voters: &[&Node],
) {
    // Strictly after any roster event just written (a re-add after a removal).
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let (s, v) = post(
        on,
        &format!("/v1/communities/{room}/invites"),
        json!({ "key_id": who.owner.key_id, "role": role }),
    )
    .await;
    assert_eq!(
        (s, v["state"].as_str()),
        (202, Some("invited")),
        "invite: {v}"
    );
    let proposal = v["proposal_id"].as_str().expect("proposal_id").to_owned();
    let (s, v) = post(
        who,
        &format!("/v1/self/invites/{proposal}/accept"),
        json!({}),
    )
    .await;
    assert_eq!(
        (s, v["state"].as_str()),
        (200, Some("accepted")),
        "accept: {v}"
    );
    let (s, v) = get(on, &format!("/v1/communities/{room}/invites")).await;
    assert_eq!(s, 200, "list invites: {v}");
    let seated = v["seated_now"]
        .as_array()
        .is_some_and(|a| a.contains(&json!(who.owner.key_id)));
    assert_eq!(
        seated,
        voters.is_empty(),
        "a founder alone seats in a room of one; past that it takes the protocol: {v}"
    );
    if !seated {
        carried(
            on,
            room,
            voters,
            json!({ "op": "add", "key_id": who.owner.key_id }),
        )
        .await;
    }
}

/// A roster-growing request answered as an INVITATION (persist v52): 202,
/// `state: invited`, a proposal id — never a membership.
fn invited(s: u16, v: &Value) {
    assert_eq!(
        (s, v["state"].as_str()),
        (202, Some("invited")),
        "an add is an invitation: {v}"
    );
    assert!(v["proposal_id"].is_string(), "{v}");
}

/// Any member of a `majority` room may invite, and inviting seats nobody: that
/// takes the invitee's acceptance and the room's signatures. A repeat of a live
/// invitation answers as the invitation it already is, or names itself.
fn founder_invites_only(s: u16, v: &Value) {
    assert!(s == 202 || s == 409, "any member may invite: {s} {v}");
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
        {
            let mut env = ciris_persist::federation::delegates_to_envelope(
                &who.owner.key_id,
                &["moderate".to_string()],
                false,
            );
            env["delegation_valid_until"] = json!((chrono::Utc::now()
                + chrono::Duration::days(30))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
            env
        },
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
async fn approving_one_seat_decision_seats_only_that_person() {
    // Kernel census, risk 1: before 0.5.247 an approval that met the room's
    // rule widened EVERY accepted invite, so approving Bob also seated Carol.
    let nodes = mesh(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    // A room of one under `majority`: the founder's one signature meets the
    // rule for the FIRST seat only. The old code widened the room's accepted
    // invites in list order, so approving Carol seated Bob, and Carol's own
    // widening was then refused (two members need two signatures).
    let room = test_only_found(a, "one at a time", &[], json!({})).await;
    for who in [b, c] {
        contact(a, who).await;
        let (s, v) = post(
            a,
            &format!("/v1/communities/{room}/invites"),
            json!({ "key_id": who.owner.key_id }),
        )
        .await;
        invited(s, &v);
        let proposal = v["proposal_id"].as_str().expect("proposal_id").to_owned();
        let (s, v) = post(
            who,
            &format!("/v1/self/invites/{proposal}/accept"),
            json!({}),
        )
        .await;
        assert_eq!((s, v["state"].as_str()), (200, Some("accepted")), "{v}");
    }
    // Both acceptances are decisions for the founder; nobody is seated yet.
    let (s, v) = get(a, &format!("/v1/self/decisions?circle={room}")).await;
    assert_eq!(s, 200, "{v}");
    let items = v["decisions"].as_array().expect("decisions").clone();
    assert_eq!(items.len(), 2, "{v}");
    assert_eq!(fold(&a.engine, &room).await, sorted(&[&a.owner.key_id]));

    let carols = items
        .iter()
        .find(|d| d["subject"] == c.owner.key_id.as_str())
        .expect("Carol's decision");
    let did = carols["decision_id"].as_str().expect("decision_id");
    let (s, v) = post(
        a,
        &format!("/v1/self/decisions/{did}/answer"),
        json!({ "answer": "approve" }),
    )
    .await;
    assert_eq!((s, v["state"].as_str()), (200, Some("applied")), "{v}");
    assert_eq!(v["seated"], json!([c.owner.key_id]), "{v}");
    assert_eq!(
        fold(&a.engine, &room).await,
        sorted(&[&a.owner.key_id, &c.owner.key_id]),
        "approving Carol seats Carol, not Bob"
    );
    // The answer is the founder's, on the founder's own listing.
    let (_, v) = get(a, &format!("/v1/self/decisions?circle={room}")).await;
    let left = v["decisions"].as_array().expect("decisions");
    assert_eq!(left.len(), 1, "{v}");
    assert_eq!(left[0]["subject"], b.owner.key_id.as_str());
    assert_eq!(left[0]["my_answer"], Value::Null, "{v}");
}

#[tokio::test]
async fn a_three_member_room_where_all_three_read_each_other() {
    let nodes = mesh(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let room = test_only_found(a, "the three of us", &[b, c], json!({})).await;
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
            // A quorum's N is the roster size: a founder alone is not a 2/3.
            json!({ "name": "x", "consensus_protocol": "quorum:2/3" }),
            400,
            "community.bad_consensus_protocol",
        ),
        // CONSENT TO JOIN (0.5.218): a founding roster naming anyone but the
        // founder is refused — contact or not, whatever the protocol.
        (
            json!({ "name": "x", "consensus_protocol": "quorum:1/2", "members": [b.owner.key_id] }),
            409,
            "membership.founding_member_unsigned",
        ),
        (
            json!({ "name": "x", "members": [b.owner.key_id] }),
            409,
            "membership.founding_member_unsigned",
        ),
        (
            json!({ "name": "x", "members": [c.owner.key_id] }),
            409,
            "membership.founding_member_unsigned",
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

    // The happy path, for contrast, with the default protocol and tier: the
    // founder alone (naming yourself is not naming anyone else).
    let (s, v) = post(
        a,
        "/v1/communities",
        json!({ "name": "  Book club  ", "members": [a.owner.key_id] }),
    )
    .await;
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["name"], "Book club");
    assert_eq!(v["tier"], "community");
    assert_eq!(v["consensus_protocol"], "majority");
    assert_eq!(v["my_role"], "founder");
    assert_eq!(v["member_count"], 1);
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
    let room = test_only_found(a, "garden", &[b, c], json!({})).await;
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
    let room = test_only_found(a, "widen me", &[b], json!({})).await;
    let dir = a.engine.federation_directory();

    // CONSENT TO JOIN (persist v52): the add route INVITES — contact or not
    // (an invitation reaches a stranger under first contact, CIRISEdge#756).
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": c.owner.key_id }),
    )
    .await;
    invited(s, &v);
    contact(a, c).await;
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": c.owner.key_id }),
    )
    .await;
    invited(s, &v);
    assert!(
        dir.list_community_membership_widenings_for(&room)
            .await
            .expect("widenings")
            .is_empty(),
        "an invitation writes no roster row"
    );
    // What the rest pins is the WIDENING plane: Carol accepts and the founder
    // seats her — the widening a production node writes.
    join_by_invitation(a, &room, c, None, &[b]).await;

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

    // POLICY: a plain member may not add either (the consent door answers
    // first); an outsider cannot see the room.
    contact(b, d).await;
    let (s, v) = post(
        b,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": d.owner.key_id }),
    )
    .await;
    founder_invites_only(s, &v);
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
    carried(
        a,
        &room,
        &[b],
        json!({ "op": "remove", "key_id": c.owner.key_id }),
    )
    .await;
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

    // RE-ADD: through the route it is a join like any other, so it is closed;
    // at the substrate a second widening strictly after the removal folds her
    // back (the fold's latest event wins).
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": c.owner.key_id }),
    )
    .await;
    invited(s, &v);
    join_by_invitation(a, &room, c, None, &[b]).await;
    assert!(fold(&a.engine, &room).await.contains(&c.owner.key_id));
    assert_eq!(
        dir.list_community_membership_widenings_for(&room)
            .await
            .expect("w")
            .len(),
        2
    );
    // …and removed again: a re-added member can be removed again.
    carried(
        a,
        &room,
        &[b],
        json!({ "op": "remove", "key_id": c.owner.key_id }),
    )
    .await;
    assert!(!fold(&a.engine, &room).await.contains(&c.owner.key_id));
}

/// **CIRISPersist#907, pinned red.** A member added by WIDENING is on the
/// fold — listed, shown, sealed to — and persist's caller admission still
/// refuses them the message read, because `build_caller_admission` →
/// `list_communities_for_member_active` walks the RECORD's members only
/// (persist `scope/admission.rs` ~195, `federation/mod.rs` ~3615). Not worked
/// around server-side: the admission is persist's. Un-ignore when #907 lands.
///
/// **0.5.218: #907 landed in persist v49** — the caller admission folds the
/// widening plane — so this runs, un-ignored. The widening is written by the
/// test-only fixture (the add route is closed until the joiner can consent,
/// CIRISPersist#955); what is pinned is the READ a widened member gets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_widened_member_reads_the_rooms_messages_cirispersist_907() {
    let nodes = mesh(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let room = test_only_found(a, "late joiner", &[b], json!({})).await;
    contact(a, c).await;
    join_by_invitation(a, &room, c, None, &[b]).await;
    assert!(fold(&a.engine, &room).await.contains(&c.owner.key_id));
    let (s, v) = get(c, &format!("/v1/chat/{room}/messages")).await;
    assert_eq!(s, 200, "a widened member reads the transcript: {v}");
}

// ─── 5. The appointed moderator ─────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_appointed_moderator_adds_and_removes_plain_members_only() {
    let nodes = mesh(4).await;
    let (a, b, c, d) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
    let room = test_only_found(a, "moderated", &[b, c], json!({})).await;
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

    // Bob, appointed, may not ADD Dave — nobody may, until Dave can consent
    // (0.5.218) — but removes a plain member. Dave is put on the roster by
    // the test-only fixture so the removal has someone to remove.
    let (s, v) = post(
        b,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": d.owner.key_id }),
    )
    .await;
    founder_invites_only(s, &v);
    contact(a, d).await;
    join_by_invitation(a, &room, d, None, &[b, c]).await;
    // A moderator's signature alone removes nobody (persist v61.0.3, #1200): it
    // takes the room's signatures.
    let (s, v) = delete(
        b,
        &format!("/v1/communities/{room}/members/{}", d.owner.key_id),
    )
    .await;
    assert_eq!((s, reason(&v)), (409, "community.quorum_pending"), "{v}");
    carried(
        a,
        &room,
        &[b, c],
        json!({ "op": "remove", "key_id": d.owner.key_id }),
    )
    .await;
    // But may not add a FOUNDER (closed to everyone — the consent door
    // answers first), remove the founder, or change a role.
    let (s, v) = post(
        b,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": d.owner.key_id, "role": "founder" }),
    )
    .await;
    founder_invites_only(s, &v);
    let (s, v) = post(
        b,
        &format!("/v1/communities/{room}/members/{}/role", c.owner.key_id),
        json!({ "role": "founder" }),
    )
    .await;
    assert_eq!((s, reason(&v)), (409, "community.quorum_pending"), "{v}");
    let (s, v) = delete(b, &format!("/v1/communities/{room}")).await;
    assert_eq!((s, reason(&v)), (403, "community.not_authorized"), "{v}");
    // Carol, a plain member with no appointment, may do none of it.
    let (s, v) = post(
        c,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": d.owner.key_id }),
    )
    .await;
    founder_invites_only(s, &v);

    // The last founder cannot be removed at all.
    let (s, v) = delete(
        b,
        &format!("/v1/communities/{room}/members/{}", a.owner.key_id),
    )
    .await;
    assert_eq!(reason(&v), "community.last_founder", "{s}: {v}");
}

/// One message of `room`'s transcript, as `n` reads it.
async fn message_in(n: &Node, room: &str, id: &str) -> Value {
    let (s, v) = get(n, &format!("/v1/chat/{room}/messages")).await;
    assert_eq!(s, 200, "{v}");
    v["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .find(|m| m["attestation_id"] == id)
        .cloned()
        .expect("the message is listed")
}

/// **A room's moderators flag and clear its items over the owner API**
/// (CC 4.5.5). Alice founded the room, Bob is her appointed moderator, Carol is
/// a plain member. Carol cannot flag; Bob's flag is signed by Bob's own pen, so
/// the read side believes it and withholds the message from every member until
/// they reveal it; Bob's clear lifts it; Alice, a founder, moderates zero-hop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_moderator_flags_and_clears_a_rooms_message_over_the_api() {
    let nodes = mesh(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let room = test_only_found(a, "moderated chat", &[b, c], json!({})).await;
    appoint_moderator(a, b).await;

    let (s, v) = post(
        c,
        &format!("/v1/chat/{room}/messages"),
        json!({ "body": "something contested" }),
    )
    .await;
    assert_eq!(s, 200, "Carol posts: {v}");
    let id = v["attestation_id"].as_str().expect("id").to_owned();
    let item = |what: &str| format!("/v1/chat/{room}/items/{id}/{what}");

    // Carol holds no duty: refused, and nothing changes.
    let (s, v) = post(c, &item("flag"), json!({})).await;
    assert_eq!((s, reason(&v)), (403, "moderation.not_a_moderator"), "{v}");
    assert!(message_in(a, &room, &id).await.get("moderation").is_none());

    // Bob: an unknown class, and a clear with nothing to clear.
    let (s, v) = post(b, &item("flag"), json!({ "class": "bogus" })).await;
    assert_eq!((s, reason(&v)), (400, "moderation.unknown_class"), "{v}");
    let (s, v) = post(b, &item("clear"), json!({})).await;
    assert_eq!((s, reason(&v)), (409, "moderation.nothing_to_clear"), "{v}");
    let (s, v) = post(b, &item("delete"), json!({})).await;
    assert_eq!((s, reason(&v)), (404, "moderation.unknown_action"), "{v}");

    // Bob flags it.
    let (s, v) = post(b, &item("flag"), json!({ "class": "reported" })).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["moderation"]["flag"], "reported", "{v}");
    assert_eq!(
        v["moderation"]["flagged_by"],
        b.owner.key_id.as_str(),
        "{v}"
    );
    let decision = v["decision_attestation_id"]
        .as_str()
        .expect("signed")
        .to_owned();
    // Every member reads it withheld, Carol (its author) included.
    for n in [a, c] {
        let m = message_in(n, &room, &id).await;
        assert_eq!(m["moderation"]["withheld"], true, "{m}");
        assert_eq!(
            m["moderation"]["flag_attestation_id"],
            decision.as_str(),
            "{m}"
        );
        assert!(m.get("body").is_none(), "the body is withheld: {m}");
        assert_eq!(m["unopened_reason"], "withheld_by_moderation", "{m}");
    }
    // Flagging it again the same way signs nothing new.
    let (s, v) = post(b, &item("flag"), json!({})).await;
    assert_eq!(s, 200, "{v}");
    assert!(v.get("decision_attestation_id").is_none(), "{v}");

    // Alice chooses to see it; Carol still reads it withheld.
    let (s, v) = post(a, &item("reveal"), json!({})).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(
        message_in(a, &room, &id).await["body"],
        "something contested"
    );
    assert_eq!(
        message_in(c, &room, &id).await["moderation"]["withheld"],
        true
    );

    // Bob clears it: the history stays, the flag does not.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let (s, v) = post(b, &item("clear"), json!({})).await;
    assert_eq!(s, 200, "{v}");
    assert!(v["moderation"]["flag"].is_null(), "cleared: {v}");
    let m = message_in(c, &room, &id).await;
    assert_eq!(m["moderation"]["withheld"], false, "{m}");
    assert_eq!(m["body"], "something contested", "{m}");

    // Alice, a founder, moderates zero-hop.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let (s, v) = post(a, &item("flag"), json!({ "class": "infohazard" })).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["moderation"]["flag"], "infohazard", "{v}");
    assert_eq!(
        message_in(c, &room, &id).await["moderation"]["withheld"],
        true
    );
}

/// **The appeal (CC 4.5.5)**: the flagged item's author files against the
/// flag, a `review` holder rules, and `reversed` lifts it for everyone. Bob
/// moderates but does not review; Alice founded the room and holds both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_author_appeals_a_flag_and_a_reviewer_rules() {
    let nodes = mesh(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let room = test_only_found(a, "appealed", &[b, c], json!({})).await;
    appoint_moderator(a, b).await;
    let (s, v) = post(
        c,
        &format!("/v1/chat/{room}/messages"),
        json!({ "body": "contested, appealed" }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let id = v["attestation_id"].as_str().expect("id").to_owned();
    let item = |what: &str| format!("/v1/chat/{room}/items/{id}/{what}");

    // Nothing flagged: nothing to appeal.
    let (s, v) = post(c, &item("reconsider"), json!({ "grounds": "new_evidence" })).await;
    assert_eq!(
        (s, reason(&v)),
        (409, "moderation.nothing_to_appeal"),
        "{v}"
    );

    let (s, v) = post(b, &item("flag"), json!({})).await;
    assert_eq!(s, 200, "{v}");

    // Standing and vocabulary.
    let (s, v) = post(b, &item("reconsider"), json!({ "grounds": "new_evidence" })).await;
    assert_eq!(
        (s, reason(&v)),
        (403, "moderation.no_standing"),
        "not the author: {v}"
    );
    let (s, v) = post(c, &item("reconsider"), json!({ "grounds": "because" })).await;
    assert_eq!((s, reason(&v)), (400, "moderation.unknown_grounds"), "{v}");
    let (s, v) = post(a, &item("rule"), json!({ "outcome": "upheld" })).await;
    assert_eq!((s, reason(&v)), (409, "moderation.nothing_to_rule"), "{v}");

    // Carol, the author, files.
    let (s, v) = post(
        c,
        &item("reconsider"),
        json!({ "grounds": "procedural_error" }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["moderation"]["reconsideration"], "filed", "{v}");
    assert_eq!(
        v["moderation"]["reconsideration_attestation_id"], v["appeal_attestation_id"],
        "{v}"
    );

    // Bob moderates but does not review; Carol neither.
    for n in [b, c] {
        let (s, v) = post(n, &item("rule"), json!({ "outcome": "reversed" })).await;
        assert_eq!((s, reason(&v)), (403, "moderation.not_a_reviewer"), "{v}");
    }
    let (s, v) = post(a, &item("rule"), json!({ "outcome": "maybe" })).await;
    assert_eq!((s, reason(&v)), (400, "moderation.unknown_outcome"), "{v}");

    // Alice upholds: the flag stands.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let (s, v) = post(a, &item("rule"), json!({ "outcome": "upheld" })).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["moderation"]["reconsideration"], "upheld", "{v}");
    assert_eq!(
        message_in(c, &room, &id).await["moderation"]["withheld"],
        true
    );

    // Alice reverses: lifted for every member.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let (s, v) = post(a, &item("rule"), json!({ "outcome": "reversed" })).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["moderation"]["reconsideration"], "reversed", "{v}");
    assert!(v["moderation"]["flag"].is_null(), "{v}");
    for n in [a, b, c] {
        let m = message_in(n, &room, &id).await;
        assert_eq!(m["moderation"]["withheld"], false, "{m}");
        assert_ne!(m["unopened_reason"], "withheld_by_moderation", "{m}");
    }
    // The author reads it (another member's body waits on their key grant,
    // which this shared-store fixture does not drive).
    assert_eq!(
        message_in(c, &room, &id).await["body"],
        "contested, appealed"
    );
    // A reversed flag has nothing left to appeal.
    let (s, v) = post(c, &item("reconsider"), json!({ "grounds": "new_evidence" })).await;
    assert_eq!(
        (s, reason(&v)),
        (409, "moderation.nothing_to_appeal"),
        "{v}"
    );
}

// ─── 6. Roles, leaving, the last founder ────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leave_role_and_the_last_founder_rule() {
    let nodes = mesh(2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let room = test_only_found(a, "handover", &[b], json!({})).await;

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
    carried(
        a,
        &room,
        &[b],
        json!({ "op": "role", "key_id": b.owner.key_id, "role": "founder" }),
    )
    .await;
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
    let room = test_only_found(a, "short-lived", &[b, c], json!({})).await;
    // Refused by name until the record's cosigned `withdraws` is here
    // (CIRISServer issue, CC 4.4.3.2.8): revocations cannot reach it past two.
    let (s, v) = delete(a, &format!("/v1/communities/{room}")).await;
    assert_eq!((s, reason(&v)), (403, "community.not_authorized"), "{v}");
    assert_eq!(fold(&a.engine, &room).await.len(), 3, "nothing half-done");
    // A room of one is its founder's to dissolve.
    let (s, v) = post(a, "/v1/communities", json!({ "name": "alone" })).await;
    assert_eq!(s, 201, "{v}");
    let alone = v["community_id"].as_str().expect("id").to_owned();
    let (s, v) = delete(a, &format!("/v1/communities/{alone}")).await;
    assert_eq!(s, 200, "{v}");
    assert!(fold(&a.engine, &alone).await.is_empty(), "nobody is left");
}

// ─── 8. Affiliations ────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn affiliations_is_the_same_machinery_at_its_own_tier() {
    let nodes = mesh(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let room = test_only_found(a, "the guild", &[b], json!({ "tier": "affiliations" })).await;
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
    invited(s, &v);
    // The same widening machinery at this tier, through the test-only fixture.
    join_by_invitation(a, &room, c, None, &[b]).await;
    assert!(fold(&a.engine, &room).await.contains(&c.owner.key_id));
}

// ─── 9. The quorum flow ─────────────────────────────────────────────────────

/// A `unanimous` room: one signature is not enough, the direct route says so
/// WITH the envelope, each other member cosigns on their OWN node, assemble
/// applies it — and the spent envelope is stale afterwards.
///
/// Until 0.5.218 the change walked here was an ADD. Every add is now
/// `membership.consent_required` however many members sign
/// (CIRISConstitution#133, CIRISPersist#955) — asserted at each quorum step —
/// so the flow is walked on a ROLE change, which admits nobody.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_unanimous_room_changes_through_envelope_cosign_assemble() {
    let nodes = mesh(4).await;
    let (a, b, c, d) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
    let room = test_only_found(
        a,
        "consensus",
        &[b, c],
        json!({ "consensus_protocol": "unanimous" }),
    )
    .await;
    contact(a, d).await;

    // CONSENT TO JOIN: an add is refused at the direct route and at the
    // envelope route, even with unanimity on offer.
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members"),
        json!({ "key_id": d.owner.key_id }),
    )
    .await;
    invited(s, &v);
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/envelope"),
        json!({ "op": "add", "key_id": d.owner.key_id }),
    )
    .await;
    assert_eq!(
        s, 200,
        "an add envelope is built; the joiner's consent is persist's check at assemble: {v}"
    );

    // The direct role route: one signature of three → pending, WITH the
    // envelope and the caller's signature.
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/members/{}/role", c.owner.key_id),
        json!({ "role": "founder" }),
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
        json!({ "op": "role", "key_id": c.owner.key_id, "role": "founder" }),
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
    let (_, v) = get(c, &format!("/v1/communities/{room}")).await;
    assert_eq!(
        v["my_role"], "founder",
        "the unanimous role change applied: {v}"
    );

    // The same envelope again describes a room that no longer exists.
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/assemble"),
        json!({ "change_envelope": env, "signatures": sigs }),
    )
    .await;
    assert_eq!((s, reason(&v)), (409, "community.change_stale"), "{v}");
}

/// A `quorum:3/4` room: persist judges each roster row by the room's protocol
/// over the row's own co-signatures (v49.0.0, #908). M is absolute, so the
/// room stays a "three signatures" room after its roster changes size, and
/// its SECOND size-changing change is authorized by three signatures too.
///
/// Until 0.5.218 the first size change was an ADD through the quorum flow;
/// that is now `membership.consent_required` at the envelope, cosign and
/// assemble steps alike (CIRISConstitution#133, CIRISPersist#955), so the room
/// is founded at four by the test-only fixture and shrinks twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_quorum_room_is_verified_by_persist_and_stays_changeable() {
    let nodes = mesh(4).await;
    let (a, b, c, d) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
    let room = test_only_found(
        a,
        "three of four",
        &[b, c, d],
        json!({ "consensus_protocol": "quorum:3/4" }),
    )
    .await;

    // An add of someone ALREADY in is not a join, and keeps its own answer.
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/envelope"),
        json!({ "op": "add", "key_id": d.owner.key_id }),
    )
    .await;
    assert_eq!(
        (s, reason(&v)),
        (409, "community.already_member"),
        "someone already in is not joining: {v}"
    );

    // The first change: remove Dave, under "two signatures".
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/envelope"),
        json!({ "op": "remove", "key_id": d.owner.key_id }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["required"], 3);
    let env = v["change_envelope"].clone();
    let mut sigs = vec![v["signatures"][0].clone()];
    for n in [b, c] {
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
    assert_eq!(s, 200, "persist verifies 3-of-4 and applies: {v}");
    assert_eq!(fold(&a.engine, &room).await.len(), 3);
    let record = a
        .engine
        .federation_directory()
        .lookup_community(&room)
        .await
        .expect("lookup")
        .expect("room");
    assert_eq!(
        record.consensus_protocol, "quorum:3/4",
        "M is absolute (CC 4.4.3.4.2.1): a size change does not rewrite the room's rule"
    );

    // Now Dave is out, an add of him is a JOIN — refused, whoever signs.
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/envelope"),
        json!({ "op": "add", "key_id": d.owner.key_id }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    // M of N members cannot stand in for the joiner: all three co-sign the
    // add, and persist refuses the widening at assemble — Dave never accepted
    // an invitation (CIRISPersist#955, `check_growth_accepted`).
    let add_env = v["change_envelope"].clone();
    let mut add_sigs = vec![v["signatures"][0].clone()];
    for n in [b, c] {
        let (s, v) = post(
            n,
            &format!("/v1/communities/{room}/changes/cosign"),
            json!({ "change_envelope": add_env }),
        )
        .await;
        assert_eq!(s, 200, "{v}");
        add_sigs.push(v["signature"].clone());
    }
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/assemble"),
        json!({ "change_envelope": add_env, "signatures": add_sigs }),
    )
    .await;
    assert_eq!(
        (s, reason(&v)),
        (409, "membership.awaiting_acceptance"),
        "a quorum cannot stand in for the joiner: {v}"
    );

    // The second change: remove Carol, still under "three signatures" — of
    // the three who remain, Carol's own among them.
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/envelope"),
        json!({ "op": "remove", "key_id": c.owner.key_id }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["required"], 3);
    let env = v["change_envelope"].clone();
    let mut sigs = vec![v["signatures"][0].clone()];
    for n in [b, c] {
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
    assert!(!fold(&a.engine, &room).await.contains(&c.owner.key_id));
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

// ─── 11. The invite flow (persist v52, CIRISPersist#955) ────────────────────

/// **Nobody joins without their own consent — the whole flow, on real routes.**
///
/// Alice founds a room alone (a founding roster naming others is refused).
/// - Bob is a STRANGER to her (no contact grant either way): the invitation
///   still reaches him (CIRISEdge#756's first-contact arm, here the shared
///   directory), he DECLINES, the decline is terminal (a later accept is
///   `membership.already_answered`), and nothing seats him.
/// - Carol's invitation is WITHDRAWN by Alice before she answers: it leaves
///   Carol's inbox and answering it is `membership.invite_expired`.
/// - Erin's invitation LAPSES (a two-second proposal through edge's own
///   `membership::propose`, since the route's floor is a day): answering it is
///   `membership.invite_expired`.
/// - Dave ACCEPTS: Alice's list seats him (`joined`), the fold names him.
/// - Only the invitee answers (`membership.not_the_invitee`), only a founder
///   invites under `founder_only`, an expiry outside 1..=30 days is
///   `membership.bad_expiry`, and only the proposer withdraws.
/// **Two people per room in 0.5.246** (Eric, 2026-11-11). A third person
/// would accept and never be seated (members' approvals combine in the mesh
/// only with CIRISPersist#1252, 0.6), so a room created through the route
/// refuses the invitation that would make a third: an open invitation counts,
/// a declined one does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_room_holds_two_people_for_now() {
    let nodes = mesh(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let (s, v) = post(a, "/v1/communities", json!({ "name": "two of us" })).await;
    assert_eq!(s, 201, "{v}");
    let room = v["community_id"].as_str().expect("id").to_owned();
    let (_, r) = get(a, &format!("/v1/communities/{room}")).await;
    assert_eq!(r["max_people"], 2, "the room says its limit: {r}");
    let (_, list) = get(a, "/v1/communities").await;
    assert!(
        list.to_string().contains("\"max_people\":2"),
        "the listing says it too: {list}"
    );
    let invite = |who: &Node| {
        let path = format!("/v1/communities/{room}/invites");
        let key = who.owner.key_id.clone();
        async move { post(a, &path, json!({ "key_id": key })).await }
    };
    // Bob is invited: one member and one open invitation make two.
    let (s, v) = invite(b).await;
    invited(s, &v);
    let bob_p = v["proposal_id"].as_str().unwrap().to_owned();
    let (s, v) = invite(c).await;
    assert_eq!((s, reason(&v)), (409, "community.two_people_only"), "{v}");
    assert_eq!(v["max_people"], 2, "{v}");
    assert_eq!(v["open_invitations"], 1, "{v}");
    // Bob declines: his invitation no longer holds the seat.
    let (s, v) = post(b, &format!("/v1/self/invites/{bob_p}/decline"), json!({})).await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = invite(c).await;
    invited(s, &v);
    // Carol accepts and is seated: two members, and no third.
    let carol_p = v["proposal_id"].as_str().unwrap().to_owned();
    let (s, v) = post(c, &format!("/v1/self/invites/{carol_p}/accept"), json!({})).await;
    assert_eq!(s, 200, "{v}");
    let _ = get(a, &format!("/v1/communities/{room}/invites")).await;
    assert!(fold(&a.engine, &room).await.contains(&c.owner.key_id));
    let (s, v) = invite(b).await;
    assert_eq!((s, reason(&v)), (409, "community.two_people_only"), "{v}");
    assert_eq!(v["members"], 2, "{v}");
    // The carried change refuses a third seat too — past the contact gate.
    contact(a, b).await;
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/envelope"),
        json!({ "op": "add", "key_id": b.owner.key_id }),
    )
    .await;
    assert_eq!((s, reason(&v)), (409, "community.two_people_only"), "{v}");
    assert_eq!(v["members"], 2, "{v}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_invite_flow_seats_only_the_person_who_accepted() {
    let nodes = mesh(4).await;
    let (a, b, c, d) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
    let (s, v) = post(a, "/v1/communities", json!({ "name": "by consent" })).await;
    assert_eq!(s, 201, "{v}");
    let room = v["community_id"].as_str().expect("id").to_owned();

    // A stranger is invited, sees it, declines — terminal.
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/invites"),
        json!({ "key_id": b.owner.key_id }),
    )
    .await;
    invited(s, &v);
    let bob_p = v["proposal_id"].as_str().unwrap().to_owned();
    let (s, inbox) = get(b, "/v1/self/invites").await;
    assert_eq!(s, 200, "{inbox}");
    let mine: Vec<&Value> = inbox["invites"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["proposal_id"] == json!(bob_p))
        .collect();
    assert_eq!(mine.len(), 1, "the invitee's inbox holds it: {inbox}");
    assert_eq!(mine[0]["group_kind"], "community");
    assert_eq!(mine[0]["group_id"], json!(room));
    let (s, v) = post(c, &format!("/v1/self/invites/{bob_p}/accept"), json!({})).await;
    assert_eq!((s, reason(&v)), (403, "membership.not_the_invitee"), "{v}");
    let (s, v) = post(b, &format!("/v1/self/invites/{bob_p}/decline"), json!({})).await;
    assert_eq!((s, v["state"].as_str()), (200, Some("declined")), "{v}");
    let (s, v) = post(b, &format!("/v1/self/invites/{bob_p}/accept"), json!({})).await;
    assert_eq!(
        (s, reason(&v)),
        (409, "membership.already_answered"),
        "a decline is final: {v}"
    );
    let (_, inbox) = get(b, "/v1/self/invites").await;
    assert!(
        !inbox["invites"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["proposal_id"] == json!(bob_p)),
        "an answered invitation leaves the inbox: {inbox}"
    );

    // Only a founder invites under founder_only; an expiry is 1..=30 days.
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/invites"),
        json!({ "key_id": c.owner.key_id, "expires_in_days": 31 }),
    )
    .await;
    assert_eq!((s, reason(&v)), (400, "membership.bad_expiry"), "{v}");

    // Carol's invitation is withdrawn before she answers.
    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/invites"),
        json!({ "key_id": c.owner.key_id }),
    )
    .await;
    invited(s, &v);
    let carol_p = v["proposal_id"].as_str().unwrap().to_owned();
    let (s, v) = delete(a, &format!("/v1/communities/{room}/invites/{carol_p}")).await;
    assert_eq!((s, v["state"].as_str()), (200, Some("withdrawn")), "{v}");
    let (s, v) = delete(a, &format!("/v1/communities/{room}/invites/{carol_p}")).await;
    assert_eq!((s, reason(&v)), (409, "membership.invite_closed"), "{v}");
    let (_, inbox) = get(c, "/v1/self/invites").await;
    assert!(
        !inbox["invites"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["proposal_id"] == json!(carol_p)),
        "a withdrawn invitation leaves the inbox: {inbox}"
    );
    let (s, v) = post(c, &format!("/v1/self/invites/{carol_p}/accept"), json!({})).await;
    assert_eq!((s, reason(&v)), (410, "membership.invite_expired"), "{v}");

    // A lapsed invitation (edge's own door, two seconds — the route's floor is
    // a day) is refused when answered.
    let short = ciris_edge::membership::propose(
        a.engine.federation_directory().as_ref(),
        ciris_edge::membership::GroupScope::Community,
        &room,
        &c.owner.key_id,
        None,
        chrono::Utc::now() + chrono::Duration::seconds(2),
        &a.owner.edge_signer().await,
    )
    .await
    .expect("a short-lived proposal");
    tokio::time::sleep(std::time::Duration::from_millis(2_500)).await;
    let (s, v) = post(
        c,
        &format!("/v1/self/invites/{}/accept", short.attestation_id),
        json!({}),
    )
    .await;
    assert_eq!((s, reason(&v)), (410, "membership.invite_expired"), "{v}");

    // Dave accepts, and the founder's read seats him.
    join_by_invitation(a, &room, d, None, &[]).await;
    let (s, v) = get(a, &format!("/v1/communities/{room}/invites")).await;
    assert_eq!(s, 200, "{v}");
    let states: std::collections::BTreeMap<String, String> = v["invites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["invitee_key_id"].as_str().unwrap().to_owned()
                    + "/"
                    + i["proposal_id"].as_str().unwrap(),
                i["state"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        states
            .get(&format!("{}/{bob_p}", b.owner.key_id))
            .map(String::as_str),
        Some("declined"),
        "{v}"
    );
    assert_eq!(
        states
            .get(&format!("{}/{carol_p}", c.owner.key_id))
            .map(String::as_str),
        Some("withdrawn"),
        "{v}"
    );
    assert!(
        states
            .iter()
            .any(|(k, st)| k.starts_with(&d.owner.key_id) && st == "joined"),
        "{v}"
    );
    let roster = fold(&a.engine, &room).await;
    assert_eq!(
        roster,
        sorted(&[&a.owner.key_id, &d.owner.key_id]),
        "only the person who accepted is in"
    );

    // Dave is a plain member: under founder_only he cannot invite.
    let (s, v) = post(
        d,
        &format!("/v1/communities/{room}/invites"),
        json!({ "key_id": b.owner.key_id }),
    )
    .await;
    founder_invites_only(s, &v);
}

/// **A quorum room seats an accepted invitee only when M of N sign the add.**
/// Alice invites Dave into a 3-of-3 room; Dave accepts; Alice's list does NOT
/// seat him (one signature is not the room's rule — "accepted, awaiting the
/// group", persist FSD §4); the add through envelope → cosign → assemble,
/// signed by all three, does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_quorum_room_seats_an_accepted_invitee_by_a_cosigned_widening() {
    let nodes = mesh(4).await;
    let (a, b, c, d) = (&nodes[0], &nodes[1], &nodes[2], &nodes[3]);
    let room = test_only_found(
        a,
        "three of three",
        &[b, c],
        json!({ "consensus_protocol": "quorum:3/3" }),
    )
    .await;
    contact(a, d).await;
    let (s, v) = post(
        b,
        &format!("/v1/communities/{room}/invites"),
        json!({ "key_id": d.owner.key_id }),
    )
    .await;
    invited(s, &v);
    let p = v["proposal_id"].as_str().unwrap().to_owned();
    let (s, v) = post(d, &format!("/v1/self/invites/{p}/accept"), json!({})).await;
    assert_eq!((s, v["state"].as_str()), (200, Some("accepted")), "{v}");
    let (s, v) = get(a, &format!("/v1/communities/{room}/invites")).await;
    assert_eq!(s, 200, "{v}");
    assert!(
        v["seated_now"].as_array().is_some_and(Vec::is_empty),
        "a read never seats anyone in a quorum room: {v}"
    );
    assert!(!fold(&a.engine, &room).await.contains(&d.owner.key_id));

    let (s, v) = post(
        a,
        &format!("/v1/communities/{room}/changes/envelope"),
        json!({ "op": "add", "key_id": d.owner.key_id }),
    )
    .await;
    assert_eq!(s, 200, "{v}");
    let env = v["change_envelope"].clone();
    let mut sigs = vec![v["signatures"][0].clone()];
    for n in [b, c] {
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
    assert_eq!(
        s, 200,
        "the group's M-of-N widening seats the accepted invitee: {v}"
    );
    assert!(fold(&a.engine, &room).await.contains(&d.owner.key_id));
}

/// **A contact request reaches the other person's inbox** (FSD/MEMBERSHIP_INVITES.md
/// §8; the Eric × Francesco gap). Alice adds Bob: Bob's `/v1/self/invites` and
/// `/v1/contacts/requests` show Alice before Bob does anything, and Alice's do
/// not show Bob (she asked; he did not). Bob adding Alice back answers it on both
/// sides.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_contact_request_reaches_the_other_persons_inbox() {
    let nodes = mesh(2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    contact(a, b).await;

    let (s, inbox) = get(b, "/v1/self/invites").await;
    assert_eq!(s, 200, "{inbox}");
    let reqs = inbox["contact_requests"]
        .as_array()
        .expect("contact_requests");
    assert_eq!(reqs.len(), 1, "Bob sees Alice's request: {inbox}");
    assert_eq!(reqs[0]["requester_key_id"], json!(a.owner.key_id));
    assert_eq!(reqs[0]["accept"]["body"]["key_id"], json!(a.owner.key_id));
    let (s, direct) = get(b, "/v1/contacts/requests").await;
    assert_eq!((s, direct["total"].as_u64()), (200, Some(1)), "{direct}");

    // The requester's label is their own claim, stated so no client parses ids.
    let label = reqs[0]["requester_label"]
        .as_str()
        .expect("requester_label");
    assert!(
        a.owner.key_id.starts_with(&format!("{label}-")),
        "the label is the fedID's self-chosen prefix: {label} / {}",
        a.owner.key_id
    );
    // The requester's own view: Bob is Alice's contact, not yet mutual.
    let mutual_of = |list: &Value, who: &str| {
        list["contacts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["key_id"] == json!(who))
            .map(|c| c["mutual"].clone())
    };
    let (_, alice_contacts) = get(a, "/v1/contacts").await;
    assert_eq!(
        mutual_of(&alice_contacts, &b.owner.key_id),
        Some(json!(false)),
        "pending on the requester's side: {alice_contacts}"
    );

    let (_, alice_inbox) = get(a, "/v1/self/invites").await;
    assert_eq!(
        alice_inbox["contact_requests"],
        json!([]),
        "the person who asked has nothing to answer: {alice_inbox}"
    );

    contact(b, a).await;
    let (_, after) = get(b, "/v1/self/invites").await;
    assert_eq!(after["contact_requests"], json!([]), "answered: {after}");
    let (_, alice_contacts) = get(a, "/v1/contacts").await;
    assert_eq!(
        mutual_of(&alice_contacts, &b.owner.key_id),
        Some(json!(true)),
        "connected on the requester's side once Bob added back: {alice_contacts}"
    );
}

/// A room stored under `founder_only`, which persist refuses above a family, takes
/// its one admissible version: the protocol changes, and nothing else. It can't be
/// founded that way any more, so the stored state is written in directly, as a room
/// from before the rule would be.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stored_founder_only_room_moves_to_majority_and_only_that() {
    let nodes = mesh(2).await;
    let (alice, bob) = (&nodes[0], &nodes[1]);
    let room = test_only_found(alice, "legacy", &[bob], json!({})).await;
    let dir = alice.engine.federation_directory();
    alice
        .engine
        .sqlite_backend()
        .expect("sqlite")
        .conn_handle()
        .lock()
        .execute(
            "UPDATE federation_communities SET consensus_protocol = 'founder_only' \
             WHERE community_key_id = ?1",
            [room.as_str()],
        )
        .expect("store the legacy protocol");
    let before = dir
        .lookup_community(&room)
        .await
        .unwrap()
        .expect("the room");
    assert_eq!(before.consensus_protocol, "founder_only");

    let node = alice.engine.local_derived_key_id().await.expect("node key");
    let seeds = alice.owner.seed_dir.clone();
    let moved =
        ciris_server::communities::escape_founder_only_rooms(&alice.engine, &node, seeds.clone())
            .await
            .expect("the sweep runs");
    assert_eq!(moved, 1, "the founder's room moves");

    let after = dir
        .lookup_community(&room)
        .await
        .unwrap()
        .expect("the room");
    assert_eq!(after.consensus_protocol, "majority");
    assert_eq!(after.members, before.members, "nothing else changes");
    assert_eq!(
        ciris_server::communities::escape_founder_only_rooms(&alice.engine, &node, seeds)
            .await
            .expect("the sweep runs again"),
        0,
        "and it happens once"
    );
}
