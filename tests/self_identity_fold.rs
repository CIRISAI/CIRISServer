//! **The fold case: the CLI label and the engine signer are different keys.**
//! (CIRISServer#372 Level 2, off `FSD/RCA_INGEST_REJECTION_2026-08-05.md`.)
//!
//! `main.rs` takes `--key-id <name>` and threads it — through
//! `ServerConfig::key_id` — into the surfaces. That value is an operator
//! **label**. `Engine::local_derived_key_id()` is what the engine **actually
//! signs with**. On the standalone binary they agree, because `compose::serve`
//! re-derives `cfg.key_id` from the engine before mounting anything. **In the
//! embedded fold they do not**: the reused agent Engine signs every row as the
//! AGENT's identity while the server's label is its own.
//!
//! That divergence is the condition `scorer.rs` names ("in the embedded fold
//! they differ") and the one no test covered. Every test in this file builds an
//! engine whose signer is a *different party* from the label, hands the router
//! **no key id at all**, and asserts the surface follows the SIGNER.
//!
//! # What each test would have caught
//!
//! Each of these fails if the corresponding surface goes back to threading a
//! label — see the mutation notes on each test. They are written so that
//! binding/registering the LABEL is not merely insufficient but *actively
//! wrong*: the label is a real, registered, owner-bound key here, so a surface
//! that reads it will find a coherent answer and return the wrong one, exactly
//! as production would.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::{HardwareSigner, MlDsa65SoftwareSigner, PqcSigner as _, SoftwareSigner};
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
use ciris_persist::graph::sqlite::SqliteGraphBackend;
use ciris_persist::graph::types::GraphScope;
use ciris_persist::graph::GraphService;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};

use ciris_server::auth::store;
use ciris_server::{admin_ops, federation_peers, memory_api, mesh_config_surface};

// ═══════════════════════════════════════════════════════════════════════════
//  The fold: two identities, one of which used to be threaded as the other
// ═══════════════════════════════════════════════════════════════════════════

/// The keystore alias of the identity the ENGINE actually signs with — in the
/// fold, the agent's. The derived id is `<this>-<fingerprint>`.
const ENGINE_ALIAS: &str = "ciris-agent-bootstrap";

/// The operator's `--key-id` **label** — what `ServerConfig::key_id` starts as
/// and what every converted surface used to receive. A plausible, registered,
/// owner-bound key that this engine has never signed with.
const CLI_LABEL: &str = "ciris-server";

const OWNER_USER: &str = "fold-owner";
/// An ordinary third party, so "the peer list is empty" can never be mistaken
/// for "the peer list correctly excluded self".
const BYSTANDER: &str = "fold-bystander";

/// The engine, built on the FOLD signer — never on the label.
async fn fold_engine() -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xF2; 32], format!("{ENGINE_ALIAS}-pqc"))
            .expect("engine ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xF1; 32]),
        ENGINE_ALIAS.to_string(),
        Some(pqc),
        Some(format!("{ENGINE_ALIAS}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer (sqlite::memory:)"),
    )
}

/// The id the engine's own signer produces — the ONE identity every converted
/// surface must follow.
async fn engine_key_id(engine: &Engine) -> String {
    engine
        .local_derived_key_id()
        .await
        .expect("derive the engine's federation key_id")
}

fn party_ed_seed(key_id: &str) -> [u8; 32] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&Sha256::digest(format!("ed:{key_id}")));
    s
}

fn party_pqc_seed(key_id: &str) -> [u8; 32] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&Sha256::digest(format!("pqc:{key_id}")));
    s
}

fn party_signer(key_id: &str) -> LocalSigner {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&party_pqc_seed(key_id), format!("{key_id}-pqc"))
            .expect("party ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        SigningKey::from_bytes(&party_ed_seed(key_id)),
        key_id.to_string(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    )
}

/// Register an arbitrary party in the federation directory under EXACTLY
/// `key_id` (no derivation) — how the label gets to be a real, findable key.
async fn register_party(engine: &Engine, key_id: &str, id_type: &str) -> LocalSigner {
    let signer = party_signer(key_id);
    let ed_pub = BASE64.encode(
        SigningKey::from_bytes(&party_ed_seed(key_id))
            .verifying_key()
            .to_bytes(),
    );
    let mldsa_pub = {
        let pqc = MlDsa65SoftwareSigner::from_seed_bytes(
            &party_pqc_seed(key_id),
            format!("{key_id}-pqc"),
        )
        .expect("party ML-DSA-65 seed");
        BASE64.encode(pqc.public_key().await.expect("party ML-DSA-65 pubkey"))
    };
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize party envelope");
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: ed_pub,
        pubkey_ml_dsa_65_base64: Some(mldsa_pub),
        algorithm: algorithm::HYBRID.into(),
        identity_type: id_type.to_string(),
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
        .expect("register party key");
    signer
}

/// Register the ENGINE's own self-signed steward record under its DERIVED id.
async fn register_engine_self(engine: &Engine) {
    let key_id = engine_key_id(engine).await;
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize self envelope");
    let sig = engine.sign_hybrid(&canonical).await.expect("self sign");
    let record = KeyRecord {
        key_id: key_id.clone(),
        pubkey_ed25519_base64: BASE64.encode(&sig.classical.public_key),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(&sig.pqc.public_key)),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::STEWARD.into(),
        identity_ref: key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .register_federation_key(SignedKeyRecord { record })
        .await
        .expect("register the engine's own steward key");
}

/// CC 3.2 owner-binding: `delegates_to(owner → subject, infra:*)`.
async fn bind_owner_to(engine: &Engine, owner: &LocalSigner, subject: &str) {
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    ciris_server::auth::ownership::emit_steward_binding(engine, owner, subject, &scopes)
        .await
        .expect("emit owner-binding");
}

async fn mint_owner_session(engine: &Engine, wa_id: &str) -> String {
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
        scopes: serde_json::json!([]),
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

async fn serve(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

// ═══════════════════════════════════════════════════════════════════════════
//  0 — the instrument can tell the two apart
// ═══════════════════════════════════════════════════════════════════════════

/// The premise every other test rests on, asserted rather than assumed: the
/// label and the engine's derived id are DIFFERENT strings. If this ever
/// collapses to equality, every test below would pass for the wrong reason —
/// which is precisely how four checks in this repo turned out unable to fail.
#[tokio::test]
async fn the_label_and_the_engine_signer_are_different_facts() {
    let engine = fold_engine().await;
    let derived = engine_key_id(&engine).await;
    assert_ne!(
        derived, CLI_LABEL,
        "the fold fixture must present two DIFFERENT identities, or nothing below is a test"
    );
    assert!(
        derived.starts_with(ENGINE_ALIAS),
        "the derived id must come from the ENGINE's alias ({ENGINE_ALIAS}), got {derived}"
    );
    assert_ne!(
        derived, ENGINE_ALIAS,
        "the derived id is `<alias>-<fingerprint>`, never the bare alias"
    );
}

/// `self_identity::resolve` IS `Engine::local_derived_key_id` and nothing else —
/// no re-implementation, no normalisation, no fallback (the ask's "do not
/// re-implement derivation").
#[tokio::test]
async fn resolve_is_the_engine_and_only_the_engine() {
    let engine = fold_engine().await;
    let direct = engine_key_id(&engine).await;
    let resolved = ciris_server::self_identity::resolve(&engine, "test")
        .await
        .expect("resolve");
    assert_eq!(direct, resolved);
}

// ═══════════════════════════════════════════════════════════════════════════
//  1 — admin_ops: the gate follows the signer
// ═══════════════════════════════════════════════════════════════════════════

/// **The fold failure, end to end.** The LABEL is registered and owner-bound;
/// the engine's own identity is not. A surface reading the label would find a
/// perfectly coherent owner and let the operator act — under a key this node
/// cannot sign as. The surface must refuse.
///
/// MUTATION: put `node_key_id: String` back on `AdminOpsState` and pass
/// `CLI_LABEL`; this returns 200 instead of 403 and the test goes RED.
#[tokio::test]
async fn admin_ops_refuses_when_only_the_label_is_owner_bound() {
    let engine = fold_engine().await;
    register_engine_self(&engine).await;
    let owner = register_party(&engine, OWNER_USER, identity_type::USER).await;
    // The LABEL is a real, registered, owner-bound node. It is simply not us.
    register_party(&engine, CLI_LABEL, identity_type::NODE).await;
    bind_owner_to(&engine, &owner, CLI_LABEL).await;

    let token = mint_owner_session(&engine, "wa-fold-owner").await;
    let (base, _h) = serve(admin_ops::router(Arc::clone(&engine))).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/admin/preview"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "attesting_key_id": BYSTANDER }))
        .send()
        .await
        .expect("preview");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "an owner-binding on the LABEL must not admit an op on THIS node"
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["refusal"], "node_unowned");
}

/// The other half of the same gate: bind the ENGINE's identity and the op runs.
/// Without this, the test above would pass on a surface that refuses
/// everything — an assertion that cannot distinguish "correctly refused" from
/// "broken" is the RCA's false-clean, restated.
///
/// MUTATION: as above; with the label threaded this returns 403 and goes RED.
#[tokio::test]
async fn admin_ops_admits_when_the_engine_identity_is_owner_bound() {
    let engine = fold_engine().await;
    register_engine_self(&engine).await;
    let owner = register_party(&engine, OWNER_USER, identity_type::USER).await;
    register_party(&engine, CLI_LABEL, identity_type::NODE).await;
    let derived = engine_key_id(&engine).await;
    bind_owner_to(&engine, &owner, &derived).await;

    let token = mint_owner_session(&engine, "wa-fold-owner").await;
    let (base, _h) = serve(admin_ops::router(Arc::clone(&engine))).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/admin/preview"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "attesting_key_id": BYSTANDER }))
        .send()
        .await
        .expect("preview");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "an owner-binding on the ENGINE's identity must admit the op"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  2 — mesh_config_surface: the subscriber is the signer
// ═══════════════════════════════════════════════════════════════════════════

/// The mesh-config read enumerates the roots THIS node subscribes to and folds
/// them for THIS node. The `node_key_id` it reports must be the identity the
/// rows would be signed under, not the label — otherwise the surface reports a
/// configuration belonging to a different subscriber than the one any write
/// would land under.
///
/// MUTATION: restore `MeshConfigState::node_key_id` and pass `CLI_LABEL`; the
/// served `node_key_id` becomes `ciris-server` and the test goes RED (and the
/// gate 403s first, which is a second, independent RED).
#[tokio::test]
async fn mesh_config_reports_the_engine_identity_as_the_subscriber() {
    let engine = fold_engine().await;
    register_engine_self(&engine).await;
    let owner = register_party(&engine, OWNER_USER, identity_type::USER).await;
    register_party(&engine, CLI_LABEL, identity_type::NODE).await;
    let derived = engine_key_id(&engine).await;
    bind_owner_to(&engine, &owner, &derived).await;

    let token = mint_owner_session(&engine, "wa-fold-owner").await;
    let (base, _h) = serve(mesh_config_surface::router(Arc::clone(&engine))).await;

    let resp = reqwest::Client::new()
        .get(format!("{base}/v1/mesh-config"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("mesh-config read");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        body["node_key_id"], derived,
        "the mesh-config subscriber must be the ENGINE's identity"
    );
    assert_ne!(body["node_key_id"], CLI_LABEL);
}

/// Same surface, the refusing arm: an owner-binding on the LABEL alone must not
/// open the mesh-config plane.
///
/// MUTATION: as above — with the label threaded this returns 200 and goes RED.
#[tokio::test]
async fn mesh_config_refuses_when_only_the_label_is_owner_bound() {
    let engine = fold_engine().await;
    register_engine_self(&engine).await;
    let owner = register_party(&engine, OWNER_USER, identity_type::USER).await;
    register_party(&engine, CLI_LABEL, identity_type::NODE).await;
    bind_owner_to(&engine, &owner, CLI_LABEL).await;

    let token = mint_owner_session(&engine, "wa-fold-owner").await;
    let (base, _h) = serve(mesh_config_surface::router(Arc::clone(&engine))).await;

    let resp = reqwest::Client::new()
        .get(format!("{base}/v1/mesh-config"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("mesh-config read");
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["refusal"], "node_unowned");
}

// ═══════════════════════════════════════════════════════════════════════════
//  3 — federation_peers: "self" is the signer
// ═══════════════════════════════════════════════════════════════════════════

/// The peer list excludes SELF. Which key is self decides who is missing from
/// the operator's Network card. With the label threaded, the node's own row is
/// listed as a peer of itself and the label is hidden — two wrong answers from
/// one wrong identity.
///
/// MUTATION: restore `PeersState::self_key_id` and pass `CLI_LABEL`; the
/// derived id appears in the listing and `CLI_LABEL` disappears — both halves
/// of this test go RED.
#[tokio::test]
async fn federation_peers_excludes_the_engine_identity_not_the_label() {
    let engine = fold_engine().await;
    register_engine_self(&engine).await;
    // Both the label and a bystander are registered as ordinary peer-visible
    // identities. Neither is this node.
    register_party(&engine, CLI_LABEL, identity_type::NODE).await;
    register_party(&engine, BYSTANDER, identity_type::WITNESS).await;
    let derived = engine_key_id(&engine).await;

    let (base, _h) = serve(federation_peers::router(Arc::clone(&engine))).await;
    let body: serde_json::Value = reqwest::get(format!("{base}/v1/federation/peers"))
        .await
        .expect("peers")
        .json()
        .await
        .expect("json");
    let ids: Vec<String> = body["peers"]
        .as_array()
        .expect("peers array")
        .iter()
        .map(|p| p["key_id"].as_str().unwrap_or_default().to_string())
        .collect();

    assert!(
        ids.contains(&BYSTANDER.to_string()),
        "the bystander must be listed — otherwise an empty list would pass this test: {ids:?}"
    );
    assert!(
        !ids.contains(&derived),
        "the ENGINE's own identity must be excluded from the peer list: {ids:?}"
    );
    assert!(
        ids.contains(&CLI_LABEL.to_string()),
        "the CLI label is another key, not self — it must be LISTED: {ids:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  4 — memory_api: the identity written into the graph is the signer's
// ═══════════════════════════════════════════════════════════════════════════

/// `seed_identity_graph` **writes the node's identity into the graph**. Under
/// the fold it must write the key the engine signs as; a label here would make
/// the Graph page confidently name a key this node has never signed with —
/// the 2026-08-05 outage's shape rendered in a UI.
///
/// MUTATION: restore the `node_key_id: &str` parameter and pass `CLI_LABEL`;
/// `node/identity` carries `ciris-server` and this goes RED.
#[tokio::test]
async fn seed_identity_graph_writes_the_engine_identity() {
    let engine = fold_engine().await;
    register_engine_self(&engine).await;
    let derived = engine_key_id(&engine).await;

    memory_api::seed_identity_graph(&engine, "node").await;

    let sq = engine.sqlite_backend().expect("sqlite backend");
    let graph = SqliteGraphBackend::new(sq.conn_handle());
    let node = graph
        .get_node("node/identity", GraphScope::Identity)
        .await
        .expect("identity node read")
        .expect("node/identity must exist");
    assert_eq!(
        node.attributes["key_id"], derived,
        "the graph must record the ENGINE's identity"
    );
    assert_ne!(node.attributes["key_id"], CLI_LABEL);
    assert_eq!(node.attributes["name"], derived);
    assert_eq!(node.updated_by, derived);
}

/// The CEG projection anchors every edge on "self". Under the fold, anchoring
/// on the label would draw the owner-binding, the accord membership and every
/// authored row against a key this node does not hold.
///
/// MUTATION: restore the `node_key_id: &str` parameter and pass `CLI_LABEL`;
/// the owner edge is drawn from the label's owner-binding and this goes RED.
#[tokio::test]
async fn seed_ceg_graph_anchors_on_the_engine_identity() {
    let engine = fold_engine().await;
    register_engine_self(&engine).await;
    let owner = register_party(&engine, OWNER_USER, identity_type::USER).await;
    // A DECOY: the label is owner-bound to a DIFFERENT user. A projection that
    // anchors on the label would draw that user as this node's owner.
    let decoy = register_party(&engine, "fold-decoy-owner", identity_type::USER).await;
    register_party(&engine, CLI_LABEL, identity_type::NODE).await;
    bind_owner_to(&engine, &decoy, CLI_LABEL).await;

    let derived = engine_key_id(&engine).await;
    bind_owner_to(&engine, &owner, &derived).await;

    memory_api::seed_identity_graph(&engine, "node").await;
    memory_api::seed_ceg_graph(&engine).await;

    let sq = engine.sqlite_backend().expect("sqlite backend");
    let graph = SqliteGraphBackend::new(sq.conn_handle());
    let real_owner = owner.key_id().to_string();
    let decoy_owner = decoy.key_id().to_string();
    assert_ne!(real_owner, decoy_owner);

    assert!(
        graph
            .get_node(&format!("owner/{real_owner}"), GraphScope::Identity)
            .await
            .expect("owner node read")
            .is_some(),
        "the projection must draw the ENGINE identity's owner"
    );
    assert!(
        graph
            .get_node(&format!("owner/{decoy_owner}"), GraphScope::Identity)
            .await
            .expect("decoy owner node read")
            .is_none(),
        "the projection must NOT draw the LABEL's owner"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  5 — the node that cannot say who it is: LOUD, never a fallback
// ═══════════════════════════════════════════════════════════════════════════

/// An engine whose signer is **ECDSA P-256**, not Ed25519 — the real
/// misconfiguration CIRISPersist#275 hardened against (a keystore fallback
/// hands back a 65-byte key). `local_derived_key_id` refuses to derive a
/// federation id over it, so this is a node that genuinely cannot resolve its
/// own identity.
async fn blind_engine() -> Arc<Engine> {
    let dir = std::env::temp_dir().join(format!(
        "ciris-372-blind-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let signer = SoftwareSigner::new("ciris-blind-node", &dir).expect("P-256 software signer");
    let signer: Arc<dyn HardwareSigner> = Arc::new(signer);
    Arc::new(
        Engine::with_hardware_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_hardware_signer (sqlite::memory:)"),
    )
}

/// The premise: this fixture really cannot resolve, and the failure names the
/// surface that asked. Without this, every test below would pass on an engine
/// that resolves fine.
#[tokio::test]
async fn the_blind_engine_really_cannot_resolve() {
    let engine = blind_engine().await;
    let e = ciris_server::self_identity::resolve(&engine, "test-surface")
        .await
        .expect_err("a P-256 signer must not yield a federation key id");
    assert_eq!(e.surface, "test-surface");
    assert!(
        e.to_string().contains("Ed25519") || e.to_string().contains("65"),
        "the cause must be the engine's own, unedited: {e}"
    );
}

/// **No silent fallback.** A surface that cannot resolve its identity refuses
/// with its OWN token — it does not reach for a label, and it does not render
/// as `node_unowned` (which would send the operator to claim a node that is
/// already claimed).
///
/// MUTATION: make `admin_ops::self_key_id` fall back to a label on error; this
/// returns 403 `node_unowned` (or 200) instead of 503
/// `self_identity_unresolved`, and goes RED.
#[tokio::test]
async fn admin_ops_refuses_loudly_when_it_cannot_resolve_itself() {
    let engine = blind_engine().await;
    let token = mint_owner_session(&engine, "wa-blind-owner").await;
    let (base, _h) = serve(admin_ops::router(Arc::clone(&engine))).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/admin/preview"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "attesting_key_id": BYSTANDER }))
        .send()
        .await
        .expect("preview");
    assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["refusal"], ciris_server::self_identity::REFUSAL_TOKEN);
    assert_ne!(
        body["refusal"], "node_unowned",
        "an unresolvable identity is NOT an unowned node"
    );
}

/// Same rule on the mesh-config plane, with the message id carried so the
/// refusal is localizable rather than an English sentence.
///
/// MUTATION: as above — a fallback makes this 403/200 and goes RED.
#[tokio::test]
async fn mesh_config_refuses_loudly_when_it_cannot_resolve_itself() {
    let engine = blind_engine().await;
    let token = mint_owner_session(&engine, "wa-blind-owner").await;
    let (base, _h) = serve(mesh_config_surface::router(Arc::clone(&engine))).await;

    let resp = reqwest::Client::new()
        .get(format!("{base}/v1/mesh-config"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("mesh-config read");
    assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["refusal"], ciris_server::self_identity::REFUSAL_TOKEN);
    assert_eq!(
        body["message"]["id"],
        ciris_server::self_identity::MESSAGE_ID
    );
}

/// **A distinct zero.** "I cannot work out which key is me" must not render as
/// "I have no peers" — an empty list is a measurement and this is not one.
///
/// MUTATION: make `federation_peers::self_key_id` fall back to a label and the
/// route answers `200 {"peers":[],"total":0}`; this goes RED on the status
/// line, which is exactly the false-clean the RCA describes.
#[tokio::test]
async fn federation_peers_does_not_render_an_unresolvable_self_as_zero_peers() {
    let engine = blind_engine().await;
    let (base, _h) = serve(federation_peers::router(Arc::clone(&engine))).await;
    let resp = reqwest::get(format!("{base}/v1/federation/peers"))
        .await
        .expect("peers");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "an unresolvable self must not be served as an empty peer list"
    );
}

/// The seed writes NOTHING rather than a guessed identity. An absent
/// `node/identity` row is a legible zero; a wrong one is a lie the whole Graph
/// page is drawn from.
///
/// MUTATION: give `seed_identity_graph` a fallback id; `node/identity` appears
/// and this goes RED.
#[tokio::test]
async fn seed_identity_graph_writes_nothing_when_it_cannot_resolve() {
    let engine = blind_engine().await;
    memory_api::seed_identity_graph(&engine, "node").await;
    memory_api::seed_ceg_graph(&engine).await;

    let sq = engine.sqlite_backend().expect("sqlite backend");
    let graph = SqliteGraphBackend::new(sq.conn_handle());
    assert!(
        graph
            .get_node("node/identity", GraphScope::Identity)
            .await
            .expect("identity node read")
            .is_none(),
        "no identity row may be written under a guessed key"
    );
}
