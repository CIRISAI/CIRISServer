//! **The graded admin-op ladder, tiers 0–4** (CIRISServer#346) — one test per
//! non-negotiable property, driven over the real router and the real persist
//! substrate.
//!
//! The five properties, and the test that gates each:
//!
//! 1. **Preview-hash commit** — `property_1_*`: a commit presenting a stale
//!    hash is REFUSED and writes nothing. Plus `preview_*` (the filter is a
//!    push-down) and `the_preview_never_scans_the_whole_self_authored_corpus`
//!    (the #343 source gate).
//! 2. **Authority in the artifact** — `property_2_*`: `{delegation_id, reason}`
//!    are required, land in the tombstone, and the delegation is RE-DERIVED
//!    from this node's own verified state rather than trusted.
//! 3. **Reversal ops exist** — `property_3_*`: three reversal routes, each
//!    naming how far it actually reaches; the tier-2 one round-trips through
//!    the real substrate marker plane.
//! 4. **Tier 3 takes quorum** — `property_4_*`: one chain refuses, two chains
//!    from ONE root refuse, two distinct roots proceed.
//! 5. **Tier 3 accepts `after:`** — `property_5_*`: it is a real filter
//!    push-down (it changes the selection and the hash) and it bounds the
//!    judgement.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::hard_case::HardCaseFilter;
use ciris_persist::federation::types::{
    algorithm, attestation_tier, attestation_type, identity_type, Attestation, Community,
    CommunityMember, KeyRecord, SignedAttestation, SignedCommunity, SignedKeyRecord,
};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};

use ciris_server::admin_ops::{self, Selection, DESCEND_QUORUM_MIN};
use ciris_server::auth::store;

const NODE_ALIAS: &str = "ciris-admin-node";
/// The key the ladder acts ON in most tests.
const TARGET: &str = "wl-target";
/// A second key whose rows must never be swept in by a selection about TARGET.
const NOISE: &str = "wl-noise";
/// The community whose named-moderator authority the quarantine marker is filed
/// under.
const COMMUNITY: &str = "wl-community";

// ─── substrate + identity helpers (mirror tests/safety.rs) ──────────────────

async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_ALIAS}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_ALIAS.to_string(),
        Some(pqc),
        Some(format!("{NODE_ALIAS}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer (sqlite::memory:)"),
    )
}

/// The node's #247 DERIVED federation key_id — the ACTING key of every op.
async fn node_key_id(engine: &Engine) -> String {
    engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id")
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

/// Register a party with its REAL hybrid pubkeys. Returns the matching signer.
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

/// Register THIS node's own steward key (the `put_attestation` attesting-key FK
/// precondition for every emit).
async fn register_self(engine: &Engine) {
    let now = chrono::Utc::now();
    let key_id = node_key_id(engine).await;
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
        .expect("register node steward key");
}

const OWNER_USER: &str = "ciris-admin-owner";

/// CC 3.2 owner-binding: a `user`-role responsible party plus
/// `delegates_to(user → node, infra:*)`. Without it every route 403s at the
/// serve-only floor.
async fn bind_owner(engine: &Engine) -> LocalSigner {
    let owner = register_party(engine, OWNER_USER, identity_type::USER).await;
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let nk = node_key_id(engine).await;
    ciris_server::auth::ownership::emit_steward_binding(engine, &owner, &nk, &scopes)
        .await
        .expect("emit owner-binding");
    owner
}

async fn mint_session(engine: &Engine, wa_id: &str, role: WaRole) -> String {
    let now = chrono::Utc::now();
    let cert = WaCert {
        wa_id: wa_id.to_string(),
        name: wa_id.to_string(),
        role,
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
    format!("sess:{wa_id}:testtoken")
}

async fn serve(engine: Arc<Engine>) -> (String, tokio::task::JoinHandle<()>) {
    // No key id is handed to the router (CIRISServer#372 Level 2).
    let app = admin_ops::router(engine);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// Emit a signed `delegates_to(granter → recipient)` carrying `scopes` — the
/// envelope `scope` array the §11.10 walk reads. Returns its `attestation_id`
/// (what a caller presents as `delegation_id`).
async fn emit_delegation(
    engine: &Engine,
    granter: &LocalSigner,
    recipient: &str,
    scopes: &[&str],
) -> String {
    let granter_key_id = granter.key_id().to_string();
    let now = chrono::Utc::now();
    let scope: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    let envelope = serde_json::json!({
        "kind": "delegates_to",
        "dimension": "delegation:moderation:v1",
        "attesting_key_id": granter_key_id,
        "attested_key_id": recipient,
        "scope": scope,
        "sub_delegation": true,
    });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize delegation");
    let sig = granter
        .sign_hybrid(&canonical)
        .await
        .expect("sign delegation");
    let attestation_id = format!("deleg-{granter_key_id}-{recipient}-{}", scopes.join("_"));
    let attestation = Attestation {
        attestation_id: attestation_id.clone(),
        attesting_key_id: granter_key_id.clone(),
        attested_key_id: recipient.to_string(),
        attestation_type: attestation_type::DELEGATES_TO.to_string(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: granter_key_id,
        additional_scrubs: Vec::new(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: vec![recipient.to_string()],
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
    };
    engine
        .federation_directory()
        .put_attestation(SignedAttestation { attestation })
        .await
        .expect("put delegation");
    attestation_id
}

/// A genuinely party-signed `scores` row on `dimension` — the corpus a
/// selection selects. `asserted_at` is explicit so the `after:` window can be
/// tested deterministically.
async fn emit_score(
    engine: &Engine,
    author: &LocalSigner,
    id: &str,
    dimension: &str,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> String {
    let key_id = author.key_id().to_string();
    let envelope = serde_json::json!({
        "dimension": dimension,
        "score": 1.0,
        "confidence": 1.0,
        "epistemic_mode": "direct",
        "witness_relation": "external",
        "stake": "reputational",
        "attested_key_id": key_id,
        "nonce": id,
    });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize score envelope");
    let sig = author.sign_hybrid(&canonical).await.expect("sign score");
    let attestation = Attestation {
        attestation_id: id.to_string(),
        attesting_key_id: key_id.clone(),
        attested_key_id: key_id.clone(),
        attestation_type: attestation_type::SCORES.to_string(),
        weight: Some(1.0),
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: key_id,
        additional_scrubs: Vec::new(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: Some(asserted_at),
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
    };
    engine
        .federation_directory()
        .put_attestation(SignedAttestation { attestation })
        .await
        .expect("put score");
    id.to_string()
}

/// A community whose founder is `founder` — persist resolves the `slash`
/// duty-holders from its named moderators, so a quarantine marker without one
/// is refused at the door.
async fn put_community(engine: &Engine, community_id: &str, founder: &str) {
    let authority = register_party(engine, community_id, "community").await;
    let now = chrono::Utc::now();
    let community = Community {
        community_key_id: community_id.to_string(),
        community_name: format!("test-{community_id}"),
        members: vec![CommunityMember {
            key_id: founder.to_string(),
            joined_at: now,
            role: Some("founder".to_string()),
        }],
        founded_at: now,
        consensus_protocol: "founder_only".to_string(),
        policy_blob: None,
        persist_row_hash: String::new(),
    };
    let canonical =
        ceg_produce_canonicalize(&community.signing_envelope()).expect("canonicalize community");
    let sig = authority
        .sign_hybrid(&canonical)
        .await
        .expect("sign community");
    engine
        .federation_directory()
        .put_community(SignedCommunity {
            community,
            authority_key_id: community_id.to_string(),
            scrub_signature_classical: BASE64.encode(&sig.classical.signature),
            scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        })
        .await
        .expect("put_community");
}

/// Every recorded `hard_case:*` row (the ladder's tombstones).
async fn hard_cases(engine: &Engine) -> Vec<ciris_persist::federation::HardCaseEvent> {
    engine
        .federation_directory()
        .list_hard_case_events(HardCaseFilter::default())
        .await
        .expect("list hard_case events")
}

// ─── the fixture ────────────────────────────────────────────────────────────

struct Fixture {
    engine: Arc<Engine>,
    base: String,
    owner_token: String,
    node_key: String,
    /// `slash`-bearing delegation from root A → node.
    slash_a: String,
    /// `slash`-bearing delegation from a DIFFERENT root B → node.
    slash_b: String,
    /// A second `slash` delegation from root A — same authority, two hats.
    slash_a2: String,
    /// `review`-only delegation from root A → node (the scope-isolation probe).
    review_only: String,
    /// A `slash` delegation granted to SOMEONE ELSE.
    slash_elsewhere: String,
    _handle: tokio::task::JoinHandle<()>,
}

/// `t0` — the fixed instant the corpus is laid out around, so `after:` windows
/// are deterministic rather than racing wall-clock.
fn t0() -> chrono::DateTime<chrono::Utc> {
    "2026-01-01T00:00:00Z".parse().expect("t0")
}

async fn fixture() -> Fixture {
    let engine = node().await;
    register_self(&engine).await;
    bind_owner(&engine).await;
    let node_key = node_key_id(&engine).await;

    let target = register_party(&engine, TARGET, identity_type::WITNESS).await;
    let noise = register_party(&engine, NOISE, identity_type::WITNESS).await;
    let root_a = register_party(&engine, "root-a", identity_type::USER).await;
    let root_b = register_party(&engine, "root-b", identity_type::USER).await;
    let bystander = register_party(&engine, "bystander", identity_type::WITNESS).await;

    // The corpus. TARGET: two rows BEFORE t0 (the history a bound leaves
    // standing) and two AFTER. NOISE: one row that must never be swept in.
    emit_score(
        &engine,
        &target,
        "t-early-1",
        "health:liveness:v1",
        t0() - chrono::Duration::hours(2),
    )
    .await;
    emit_score(
        &engine,
        &target,
        "t-early-2",
        "health:liveness:v1",
        t0() - chrono::Duration::hours(1),
    )
    .await;
    emit_score(
        &engine,
        &target,
        "t-late-1",
        "health:liveness:v1",
        t0() + chrono::Duration::hours(1),
    )
    .await;
    emit_score(
        &engine,
        &target,
        "t-late-2",
        "health:liveness:v1",
        t0() + chrono::Duration::hours(2),
    )
    .await;
    emit_score(&engine, &noise, "n-1", "health:liveness:v1", t0()).await;

    let slash_a = emit_delegation(&engine, &root_a, &node_key, &["slash"]).await;
    let slash_a2 = emit_delegation(&engine, &root_a, &node_key, &["slash", "moderate"]).await;
    let slash_b = emit_delegation(&engine, &root_b, &node_key, &["slash"]).await;
    let review_only = emit_delegation(&engine, &root_a, &node_key, &["review"]).await;
    let slash_elsewhere = emit_delegation(&engine, &root_a, "bystander", &["slash"]).await;
    let _ = bystander;

    let owner_token = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _handle) = serve(Arc::clone(&engine)).await;
    Fixture {
        engine,
        base,
        owner_token,
        node_key,
        slash_a,
        slash_b,
        slash_a2,
        review_only,
        slash_elsewhere,
        _handle,
    }
}

/// The selection every test uses: TARGET's `health:` rows.
fn target_selection() -> serde_json::Value {
    serde_json::json!({
        "attesting_key_id": TARGET,
        "dimension_prefixes": ["health:"],
    })
}

async fn post(
    f: &Fixture,
    path: &str,
    body: &serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("{}{path}", f.base))
        .bearer_auth(&f.owner_token)
        .json(body)
        .send()
        .await
        .expect("POST");
    let status = resp.status();
    let json = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Preview `selection` and return `(hash, response)`.
async fn preview(f: &Fixture, selection: &serde_json::Value) -> (String, serde_json::Value) {
    let (status, json) = post(f, "/v1/admin/preview", selection).await;
    assert_eq!(status, 200, "preview must succeed: {json}");
    (
        json["selection_hash"]
            .as_str()
            .expect("preview returns a selection_hash")
            .to_string(),
        json,
    )
}

/// A commit body over `selection` at `hash`.
fn commit(selection: serde_json::Value, hash: &str, delegation_id: &str) -> serde_json::Value {
    serde_json::json!({
        "selection": selection,
        "selection_hash": hash,
        "delegation_id": delegation_id,
        "reason": "abuse report 4711: sustained inauthentic liveness flood",
    })
}

/// Every operator-facing string must be an `{id, text}` pair — never a
/// pre-formatted sentence.
fn assert_localizable(v: &serde_json::Value, what: &str) {
    let o = v
        .as_object()
        .unwrap_or_else(|| panic!("{what} must be an object, got {v}"));
    assert!(
        o.get("id")
            .and_then(|x| x.as_str())
            .is_some_and(|s| !s.is_empty()),
        "{what} must carry a stable message id: {v}"
    );
    assert!(
        o.get("text")
            .and_then(|x| x.as_str())
            .is_some_and(|s| !s.is_empty()),
        "{what} must carry the English source text: {v}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  Preview — the filter IS the query filter (#343)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn preview_pushes_the_filter_down_and_hashes_the_exact_row_set() {
    let f = fixture().await;
    let (hash, json) = preview(&f, &target_selection()).await;

    assert_eq!(
        json["counts"]["rows"], 4,
        "TARGET authored four health: rows"
    );
    assert_eq!(
        json["counts"]["targets"], 1,
        "the selection names exactly one key"
    );
    assert_eq!(json["targets"][0], TARGET);
    let ids: Vec<&str> = json["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| r["attestation_id"].as_str().expect("id"))
        .collect();
    assert!(
        !ids.contains(&"n-1"),
        "NOISE's row must never be swept in by a selection about TARGET: {ids:?}"
    );
    assert!(!hash.is_empty());
    assert_localizable(&json["note"], "preview note");
    assert_eq!(json["source_locale"], "en");

    // A DIFFERENT selection over the SAME corpus hashes differently, so a hash
    // cannot be replayed against another question.
    let mut other = target_selection();
    other["dimension_prefixes"] = serde_json::json!(["trace:"]);
    let (other_hash, other_json) = preview(&f, &other).await;
    assert_eq!(other_json["counts"]["rows"], 0);
    assert_ne!(hash, other_hash, "the filter is inside the hash preimage");
}

/// The #343 gate. `list_attestations_by(self)` was a whole-corpus scan that
/// made `config_resolution` a 152-second boot phase; the preview must never
/// reintroduce it. **Comments are stripped before the scan** — this is about
/// what the code DOES, and the module deliberately discusses the anti-pattern
/// in prose.
#[test]
fn the_preview_never_scans_the_whole_self_authored_corpus() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/admin_ops.rs"))
        .expect("read src/admin_ops.rs");
    let code: String = src
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("list_attestations_by"),
        "the preview must push the filter into the QUERY, never scan the whole \
         self-authored corpus and filter in Rust (CIRISServer#343)"
    );
    assert!(
        code.contains("AttestationFilter"),
        "the preview is an AttestationFilter push-down"
    );
}

#[test]
fn the_selection_hash_is_versioned_and_set_ordered() {
    let sel = Selection {
        attesting_key_id: Some(TARGET.into()),
        dimension_prefixes: vec!["b:".into(), "a:".into(), "a:".into()],
        ..Selection::default()
    };
    let forward = admin_ops::selection_hash(&sel, &["r2".into(), "r1".into()]);
    let reverse = admin_ops::selection_hash(&sel, &["r1".into(), "r2".into()]);
    assert_eq!(
        forward, reverse,
        "the hash is a function of the row SET, never of the paging order"
    );
    // Prefix normalization is inside the preimage: two spellings of one
    // selection must not be two selections.
    let respelled = Selection {
        dimension_prefixes: vec![" a: ".into(), "b:".into()],
        ..sel.clone()
    };
    assert_eq!(
        forward,
        admin_ops::selection_hash(&respelled, &["r1".into(), "r2".into()])
    );
    // A different row set is a different hash — the TOCTOU closure.
    assert_ne!(
        forward,
        admin_ops::selection_hash(&sel, &["r1".into(), "r2".into(), "r3".into()])
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  Property 1 — preview-hash commit
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn property_1_a_stale_preview_hash_refuses_the_commit_and_writes_nothing() {
    let f = fixture().await;
    let (hash, _) = preview(&f, &target_selection()).await;

    // A fifth matching row lands between preview and commit — exactly the TOCTOU
    // window the hash exists to close.
    let target = party_signer(TARGET);
    emit_score(&f.engine, &target, "t-late-3", "health:liveness:v1", t0()).await;

    let before = hard_cases(&f.engine).await.len();
    let (status, json) = post(
        &f,
        "/v1/admin/annotate",
        &commit(target_selection(), &hash, &f.review_only),
    )
    .await;
    assert_eq!(status, 409, "a stale hash must refuse: {json}");
    assert_eq!(json["refusal"], "preview_hash_mismatch");
    assert_localizable(&json["message"], "hash-mismatch message");
    assert_eq!(json["presented_selection_hash"], hash);
    assert_ne!(json["current_selection_hash"], hash);
    assert_eq!(
        json["current"]["counts"]["rows"], 5,
        "the refusal hands back the CURRENT blast radius, so the operator can \
         re-ratify rather than guess"
    );
    assert_eq!(
        hard_cases(&f.engine).await.len(),
        before,
        "a refused commit writes nothing"
    );

    // Re-previewing and presenting the fresh hash proceeds.
    let (fresh, _) = preview(&f, &target_selection()).await;
    let (status, json) = post(
        &f,
        "/v1/admin/annotate",
        &commit(target_selection(), &fresh, &f.review_only),
    )
    .await;
    assert_eq!(status, 200, "the fresh hash commits: {json}");
    assert_eq!(json["counts"]["rows"], 5);
}

// ═══════════════════════════════════════════════════════════════════════════
//  Property 2 — authority in the artifact
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn property_2_a_commit_without_delegation_id_or_reason_is_refused() {
    let f = fixture().await;
    let (hash, _) = preview(&f, &target_selection()).await;

    let mut no_reason = commit(target_selection(), &hash, &f.review_only);
    no_reason["reason"] = serde_json::json!("   ");
    let (status, json) = post(&f, "/v1/admin/annotate", &no_reason).await;
    assert_eq!(status, 400, "an unreasoned act is refused: {json}");
    assert_eq!(json["refusal"], "attribution_absent");
    assert_eq!(json["message"]["id"], "admin.refusal.reason_absent");

    let mut no_delegation = commit(target_selection(), &hash, "");
    no_delegation["reason"] = serde_json::json!("a real reason");
    let (status, json) = post(&f, "/v1/admin/annotate", &no_delegation).await;
    assert_eq!(status, 400, "an unattributed act is refused: {json}");
    assert_eq!(json["refusal"], "attribution_absent");
    assert_eq!(json["message"]["id"], "admin.refusal.attribution_absent");

    assert!(
        hard_cases(&f.engine).await.is_empty(),
        "neither refusal wrote a tombstone"
    );
}

#[tokio::test]
async fn property_2_the_tombstone_carries_its_own_authority() {
    let f = fixture().await;
    let (hash, _) = preview(&f, &target_selection()).await;
    let (status, json) = post(
        &f,
        "/v1/admin/annotate",
        &commit(target_selection(), &hash, &f.review_only),
    )
    .await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["tier"], 0);
    assert_eq!(json["required_scope"], "review");
    assert_localizable(&json["enforcement"], "annotate enforcement note");

    let events = hard_cases(&f.engine).await;
    let ev = events
        .iter()
        .find(|e| e.kind == "admin_action:annotate")
        .expect("an attributed admin_action:annotate row");
    assert_eq!(ev.target_key_id.as_deref(), Some(TARGET));
    assert_eq!(ev.detail["delegation_id"], f.review_only);
    assert!(ev.detail["reason"]
        .as_str()
        .expect("reason")
        .contains("4711"));
    assert_eq!(
        ev.detail["selection_hash"], hash,
        "the tombstone names WHAT was acted on, not only who authorized it"
    );
    assert_eq!(ev.detail["selection_rows"], 4);
}

#[tokio::test]
async fn property_2_authority_is_re_derived_never_taken_from_the_request() {
    let f = fixture().await;
    let (hash, _) = preview(&f, &target_selection()).await;

    // (a) A REAL delegation that does not carry the scope this op needs.
    //     `review` cannot drive a `slash` op — the scope-isolation property.
    //
    //     This is the sharp case: the SAME issuer (`root-a`) also granted this
    //     node a live `slash` chain, so persist's issuer→actor walk answers
    //     "yes, reachable under slash". If the route trusted that walk alone it
    //     would run the op and record the `review` id as its authority. The
    //     recorded row has to bear the scope itself.
    let (status, json) = post(
        &f,
        "/v1/admin/deadmit",
        &commit(target_selection(), &hash, &f.review_only),
    )
    .await;
    assert_eq!(status, 403, "{json}");
    assert_eq!(json["refusal"], "authority_scope_absent");
    assert_localizable(&json["message"], "scope-absent message");

    // (b) A REAL `slash` delegation granted to someone ELSE.
    let (status, json) = post(
        &f,
        "/v1/admin/deadmit",
        &commit(target_selection(), &hash, &f.slash_elsewhere),
    )
    .await;
    assert_eq!(status, 403, "{json}");
    assert_eq!(json["refusal"], "authority_not_to_actor");

    // (c) A delegation id this node does not hold at all.
    let (status, json) = post(
        &f,
        "/v1/admin/deadmit",
        &commit(target_selection(), &hash, "deleg-invented"),
    )
    .await;
    assert_eq!(status, 403, "{json}");
    assert_eq!(json["refusal"], "authority_unresolved");

    assert!(
        hard_cases(&f.engine).await.is_empty(),
        "no unauthorized act left a trace"
    );
}

#[tokio::test]
async fn an_unpredicated_selection_is_refused() {
    let f = fixture().await;
    let empty = serde_json::json!({});
    let (hash, json) = preview(&f, &empty).await;
    assert!(json["counts"]["rows"].as_u64().expect("rows") > 0);
    let (status, json) = post(
        &f,
        "/v1/admin/annotate",
        &commit(empty, &hash, &f.review_only),
    )
    .await;
    assert_eq!(status, 400, "{json}");
    assert_eq!(json["refusal"], "selection_unpredicated");
}

// ═══════════════════════════════════════════════════════════════════════════
//  Property 3 — reversal ops exist, and say how far they reach
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn property_3_every_reversal_route_exists_and_names_its_reach() {
    let f = fixture().await;
    let (hash, _) = preview(&f, &target_selection()).await;

    let (status, json) = post(
        &f,
        "/v1/admin/un-throttle",
        &commit(target_selection(), &hash, &f.slash_a2),
    )
    .await;
    assert_eq!(status, 200, "un-throttle is a route: {json}");
    assert_eq!(json["reversal"]["reach"], "symmetric");
    assert_localizable(&json["reversal"]["note"], "un-throttle reversal note");

    let (status, json) = post(
        &f,
        "/v1/admin/re-admit",
        &commit(target_selection(), &hash, &f.slash_a),
    )
    .await;
    assert_eq!(status, 200, "re-admit is a route: {json}");
    assert_eq!(
        json["reversal"]["reach"], "evidence_only",
        "persist exposes no un-revoke; the route must not pretend otherwise"
    );

    let mut q = commit(target_selection(), &hash, &f.slash_a);
    q["community_id"] = serde_json::json!(COMMUNITY);
    let (status, json) = post(&f, "/v1/admin/un-quarantine", &q).await;
    assert_eq!(status, 200, "un-quarantine is a route: {json}");
    assert_eq!(json["reversal"]["reach"], "substrate");
}

#[tokio::test]
async fn property_3_quarantine_round_trips_through_the_real_substrate_marker() {
    let f = fixture().await;
    // The node is the community's named moderator, so persist's `slash` gate
    // admits its markers as-self.
    put_community(&f.engine, COMMUNITY, &f.node_key).await;
    let (hash, _) = preview(&f, &target_selection()).await;

    let mut body = commit(target_selection(), &hash, &f.slash_a);
    body["community_id"] = serde_json::json!(COMMUNITY);
    let (status, json) = post(&f, "/v1/admin/quarantine", &body).await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["tier"], 2);
    assert_eq!(
        json["required_scope"], "slash",
        "the FSD ladder says `moderate`; persist's own door says `slash`, and the \
         route must advertise the authority the substrate actually enforces"
    );
    assert_eq!(
        json["results"][0]["outcome"], "admitted",
        "the marker went through persist's own door: {json}"
    );

    // The FOLD is what makes this real: this node now withholds TARGET's rows.
    let fold = f
        .engine
        .resolve_quarantine(TARGET, chrono::Utc::now())
        .await
        .expect("resolve_quarantine");
    assert!(fold.withholds(), "the substrate state changed: {fold:?}");
    assert_eq!(
        fold.delegation_id.as_deref(),
        Some(f.slash_a.as_str()),
        "the marker carries the authority it was taken under, into the graph"
    );

    // ── the reversal, on the same plane ────────────────────────────────────
    let (hash2, _) = preview(&f, &target_selection()).await;
    let mut rel = commit(target_selection(), &hash2, &f.slash_a);
    rel["community_id"] = serde_json::json!(COMMUNITY);
    let (status, json) = post(&f, "/v1/admin/un-quarantine", &rel).await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["results"][0]["outcome"], "admitted", "{json}");
    let fold = f
        .engine
        .resolve_quarantine(TARGET, chrono::Utc::now())
        .await
        .expect("resolve_quarantine");
    assert!(!fold.withholds(), "the withholding stopped: {fold:?}");
    assert_eq!(
        fold.state.as_str(),
        "released",
        "'never withheld' and 'withheld and released' are different facts"
    );
}

#[tokio::test]
async fn quarantine_surfaces_the_substrates_own_refusal_token() {
    let f = fixture().await;
    // NO community → no named moderator → persist refuses at its own door.
    let (hash, _) = preview(&f, &target_selection()).await;
    let mut body = commit(target_selection(), &hash, &f.slash_a);
    body["community_id"] = serde_json::json!("no-such-community");
    let (status, json) = post(&f, "/v1/admin/quarantine", &body).await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["results"][0]["outcome"], "refused");
    assert_eq!(
        json["results"][0]["reason"], "slash_unauthorized",
        "the substrate's OWN stable token, never re-spelled here"
    );
    assert!(
        !hard_cases(&f.engine)
            .await
            .iter()
            .any(|e| e.kind == "admin_action:quarantine"),
        "a refused marker records no tombstone claiming it happened"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  Property 4 — tier 3 takes a QUORUM
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn property_4_tier_3_takes_a_quorum_of_distinct_roots() {
    let f = fixture().await;
    let (hash, _) = preview(&f, &target_selection()).await;

    // (a) one chain — the gating tier 3 previously had.
    let (status, json) = post(
        &f,
        "/v1/admin/descend",
        &commit(target_selection(), &hash, &f.slash_a),
    )
    .await;
    assert_eq!(status, 403, "one delegation chain is not a quorum: {json}");
    assert_eq!(json["refusal"], "quorum_insufficient");
    assert_eq!(json["quorum_required"], DESCEND_QUORUM_MIN);
    assert_eq!(json["quorum_distinct_roots"], 1);
    assert_localizable(&json["message"], "quorum message");

    // (b) two chains from the SAME root — one authority wearing two hats.
    let mut same_root = commit(target_selection(), &hash, &f.slash_a);
    same_root["quorum_delegation_ids"] = serde_json::json!([f.slash_a2]);
    let (status, json) = post(&f, "/v1/admin/descend", &same_root).await;
    assert_eq!(status, 403, "the quorum counts ROOTS, not chains: {json}");
    assert_eq!(json["refusal"], "quorum_insufficient");
    assert_eq!(json["quorum_distinct_roots"], 1);

    assert!(
        hard_cases(&f.engine).await.is_empty(),
        "neither refusal descended anything"
    );

    // (c) two DISTINCT roots.
    let mut quorum = commit(target_selection(), &hash, &f.slash_a);
    quorum["quorum_delegation_ids"] = serde_json::json!([f.slash_b]);
    let (status, json) = post(&f, "/v1/admin/descend", &quorum).await;
    assert_eq!(status, 200, "a real quorum proceeds: {json}");
    assert_eq!(json["quorum"]["distinct_roots"], 2);
    assert_localizable(&json["irreversible"], "descend irreversibility note");
    assert_localizable(&json["not_reached"], "descend not-reached note");
    assert!(
        hard_cases(&f.engine)
            .await
            .iter()
            .any(|e| e.kind == "admin_action:descend"),
        "the irreversible op is attributed like every other rung"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  Property 5 — tier 3 accepts `after:`
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn property_5_after_is_a_real_push_down_and_bounds_the_judgement() {
    let f = fixture().await;

    // (a) `after:` narrows the SELECTION — it is an AttestationFilter window,
    //     not a decoration, so it changes both the row set and the hash.
    let (all_hash, all_json) = preview(&f, &target_selection()).await;
    let mut bounded_sel = target_selection();
    bounded_sel["after"] = serde_json::json!(t0().to_rfc3339());
    let (bounded_hash, bounded_json) = preview(&f, &bounded_sel).await;
    assert_eq!(all_json["counts"]["rows"], 4);
    assert_eq!(all_json["window_enforced"], "none");
    assert_eq!(
        bounded_json["counts"]["rows"], 2,
        "the two rows asserted BEFORE the bound survive the selection"
    );
    assert_ne!(
        all_hash, bounded_hash,
        "a bounded judgement is a different judgement, and hashes differently"
    );
    // The window is enforced HERE, not in the query, and the response says so —
    // `list_attestations` does not read `AttestationFilter::window`. A preview
    // that ignored `after:` silently would hand the operator a hash over twice
    // the blast radius they asked to ratify.
    assert_eq!(
        bounded_json["window_enforced"], "application",
        "the preview must name where the window was applied"
    );
    assert_localizable(&bounded_json["window_note"], "window enforcement note");

    // (b) a BOUNDED descent records its judgement and refuses the unbounded
    //     payload leg, naming why.
    let mut quorum = commit(bounded_sel.clone(), &bounded_hash, &f.slash_a);
    quorum["quorum_delegation_ids"] = serde_json::json!([f.slash_b]);
    let (status, json) = post(&f, "/v1/admin/descend", &quorum).await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["bounded"], true);
    assert_eq!(json["after"], t0().to_rfc3339());
    let payload = &json["results"][0]["payload_descent"];
    assert_eq!(payload["performed"], false);
    assert_eq!(payload["refusal"], "bounded_descent_unsupported");
    assert_localizable(&payload["message"], "bounded-descent refusal");

    let ev = hard_cases(&f.engine)
        .await
        .into_iter()
        .find(|e| e.kind == "admin_action:descend")
        .expect("the bounded judgement is still recorded");
    assert_eq!(ev.detail["bounded"], true);
    assert_eq!(ev.detail["selection_after"], t0().to_rfc3339());

    // (c) an UNBOUNDED descent attempts the payload leg.
    let (all_hash, _) = preview(&f, &target_selection()).await;
    let mut quorum = commit(target_selection(), &all_hash, &f.slash_a);
    quorum["quorum_delegation_ids"] = serde_json::json!([f.slash_b]);
    let (status, json) = post(&f, "/v1/admin/descend", &quorum).await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["bounded"], false);
    assert_ne!(
        json["results"][0]["payload_descent"]["refusal"],
        serde_json::json!("bounded_descent_unsupported"),
        "an unbounded judgement may drive the unbounded primitive"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tier 4 — de-admission, with the history bound persist actually implements
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tier_4_deadmit_writes_a_signed_revocation_with_the_history_bound() {
    let f = fixture().await;
    let (hash, _) = preview(&f, &target_selection()).await;
    let bound = t0();
    let mut body = commit(target_selection(), &hash, &f.slash_a);
    body["after"] = serde_json::json!(bound.to_rfc3339());
    let (status, json) = post(&f, "/v1/admin/deadmit", &body).await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["tier"], 4);
    assert_eq!(json["results"][0]["outcome"], "revoked", "{json}");
    assert_eq!(json["revoked_after"], bound.to_rfc3339());

    let revocations = f
        .engine
        .federation_directory()
        .revocations_for(TARGET)
        .await
        .expect("revocations_for");
    assert_eq!(revocations.len(), 1);
    let r = &revocations[0];
    assert_eq!(r.revoked_after, Some(bound), "the typed bound landed");
    assert_eq!(
        r.revocation_envelope["revoked_after"],
        serde_json::json!(bound.to_rfc3339()),
        "and it is SIGNED — persist refuses a typed bound the envelope does not mirror"
    );
    assert_eq!(r.revoking_key_id, f.node_key);

    // The bound is the whole point: Monday survives.
    let stands = f
        .engine
        .resolve_key_statement_standing(
            TARGET,
            bound - chrono::Duration::hours(1),
            chrono::Utc::now(),
        )
        .await
        .expect("resolve_key_statement_standing");
    assert!(
        !stands.standing.is_suspect(),
        "a statement made at or before the bound still stands: {stands:?}"
    );
    let suspect = f
        .engine
        .resolve_key_statement_standing(
            TARGET,
            bound + chrono::Duration::hours(1),
            chrono::Utc::now(),
        )
        .await
        .expect("resolve_key_statement_standing");
    assert!(
        suspect.standing.is_suspect(),
        "a statement made after the bound is in doubt: {suspect:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  The owner gate
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn every_graded_route_is_owner_gated() {
    let f = fixture().await;
    let observer = mint_session(&f.engine, "wa-observer", WaRole::Observer).await;
    let client = reqwest::Client::new();
    for path in [
        "/v1/admin/preview",
        "/v1/admin/annotate",
        "/v1/admin/throttle",
        "/v1/admin/un-throttle",
        "/v1/admin/quarantine",
        "/v1/admin/un-quarantine",
        "/v1/admin/descend",
        "/v1/admin/deadmit",
        "/v1/admin/re-admit",
    ] {
        // No session at all.
        let resp = client
            .post(format!("{}{path}", f.base))
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("POST");
        assert_eq!(resp.status(), 401, "{path} must refuse an anonymous caller");

        // A real session that is not the owner.
        let resp = client
            .post(format!("{}{path}", f.base))
            .bearer_auth(&observer)
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("POST");
        assert_eq!(resp.status(), 403, "{path} must refuse a non-owner caller");
        let json: serde_json::Value = resp.json().await.expect("json");
        assert_eq!(json["refusal"], "not_owner");
        assert_localizable(&json["message"], "not-owner message");
    }
    assert!(hard_cases(&f.engine).await.is_empty());
}
