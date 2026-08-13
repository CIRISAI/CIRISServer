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

/// The ONE port of `LocalizationManager.resolveKey`. See the module doc there
/// for why this is shared rather than retyped per suite.
#[path = "support/localization.rs"]
mod localization;

const NODE_ALIAS: &str = "ciris-admin-node";
/// The key the ladder acts ON in most tests.
const TARGET: &str = "wl-target";
/// A second key whose rows must never be swept in by a selection about TARGET.
const NOISE: &str = "wl-noise";
/// The community whose named-moderator authority the quarantine marker is filed
/// under.
const COMMUNITY: &str = "wl-community";
/// The authority a tier R reader SUBSCRIBES to. Not a `user` identity: persist
/// refuses a steward → user `delegates_to` without guardianship, which is a
/// different plane's rule and not the one under test here.
const SUB_ROOT: &str = "wl-sub-root";

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
    let key_id = node_key_id(engine).await;
    // Through the ONE door (CIRISServer#402): the registration envelope now BINDS
    // ITS SUBJECT. The hand-rolled `{"key_id": …}` shape named neither the
    // identity type nor either pubkey, and persist v31 refuses it — an envelope
    // that does not name its subject stands for any record it is pasted onto
    // (CIRISPersist#659).
    ciris_server::attest::register_key(
        engine,
        ciris_server::attest::KeySigner::Engine(engine),
        &key_id,
        identity_type::STEWARD,
        serde_json::Value::Null,
    )
    .await
    .expect("register node steward key");
}

const OWNER_USER: &str = "ciris-admin-owner";

/// CC 3.2 owner-binding: a `user`-role responsible party plus
/// `delegates_to(user → node, infra:*)`. Without it every route 403s at the
/// serve-only floor. Returns the signer and the binding's `attestation_id` —
/// the `delegation_id` every tier S / tier R act is taken under.
async fn bind_owner(engine: &Engine) -> (LocalSigner, String) {
    let owner = register_party(engine, OWNER_USER, identity_type::USER).await;
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let nk = node_key_id(engine).await;
    let binding = ciris_server::auth::ownership::emit_steward_binding(engine, &owner, &nk, &scopes)
        .await
        .expect("emit owner-binding");
    (owner, binding)
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
    ciris_server::auth::session::test_support_issue_session_token(wa_id)
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
    let scope: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    let envelope = serde_json::json!({
        "kind": "delegates_to",
        "dimension": "delegation:moderation:v1",
        "attesting_key_id": granter_key_id,
        "attested_key_id": recipient,
        "scope": scope,
        "sub_delegation": true,
    });
    let spec = ciris_server::attest::Spec::new(
        attestation_type::DELEGATES_TO,
        ciris_persist::federation::types::cohort_scope::FEDERATION,
        envelope,
    )
    .about(&recipient);
    // Through the ONE door (CIRISServer#402). Hand-rolled beside its envelope, this
    // row carried no signed `asserted_at` and no typed-column mirror — persist v31
    // refuses both (CIRISPersist#598/#643), so the fixture was proving the substrate
    // accepts a shape this server does not produce. The id is now MINTED INTO the
    // signed bytes rather than composed from the inputs, so callers take it back
    // from the emit.
    ciris_server::attest::emit(
        engine,
        ciris_server::attest::KeySigner::Local(&granter),
        spec,
    )
    .await
    .expect("put delegation")
}

/// **This node's own subscription edge** — `delegates_to(node → root)` on
/// `trust:accepts:v1`, the deletable un-trust lever `trusted_roots_of` reads.
/// Authored as the node's DERIVED federation key (the identity `register_self`
/// registered), because that is the key the walk starts from.
async fn subscribe_to(engine: &Engine, root_key_id: &str) -> String {
    let node = node_key_id(engine).await;
    let envelope = serde_json::json!({
        "kind": "delegates_to",
        "dimension": ciris_persist::federation::trust_root::TRUST_ACCEPTS_DIMENSION,
        "attesting_key_id": node,
        "attested_key_id": root_key_id,
        "scope": ["review"],
    });
    let spec = ciris_server::attest::Spec::new(
        attestation_type::DELEGATES_TO,
        ciris_persist::federation::types::cohort_scope::FEDERATION,
        envelope,
    )
    .about(&root_key_id);
    // Through the ONE door (CIRISServer#402). Hand-rolled beside its envelope, this
    // row carried no signed `asserted_at` and no typed-column mirror — persist v31
    // refuses both (CIRISPersist#598/#643), so the fixture was proving the substrate
    // accepts a shape this server does not produce. The id is now MINTED INTO the
    // signed bytes rather than composed from the inputs, so callers take it back
    // from the emit.
    ciris_server::attest::emit(
        engine,
        ciris_server::attest::KeySigner::Engine(engine),
        spec,
    )
    .await
    .expect("put subscription edge")
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
    try_emit_score(engine, author, id, dimension, asserted_at)
        .await
        .expect("put score")
}

/// The same write, with the substrate's verdict returned instead of unwrapped.
/// The AV-77 round trip is *"the same write is refused"*, so the write has to
/// be a thing that can come back refused.
async fn try_emit_score(
    engine: &Engine,
    author: &LocalSigner,
    id: &str,
    dimension: &str,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> Result<String, String> {
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
    let mut spec = ciris_server::attest::Spec::new(
        attestation_type::SCORES,
        ciris_persist::federation::types::cohort_scope::FEDERATION,
        envelope,
    );
    spec.attested_key_id = Some(key_id.to_string());
    spec.subject_key_ids = Vec::new();
    let spec = spec.weighing(Some(1.0));
    // Through the ONE door (CIRISServer#402). Hand-rolled beside its envelope, this
    // row carried no signed `asserted_at` and no typed-column mirror — persist v31
    // refuses both (CIRISPersist#598/#643), so the fixture was proving the substrate
    // accepts a shape this server does not produce.
    //
    // `stamp_at`, not `stamp`: `asserted_at` is the axis the `after:` window and
    // the `revoked_after` bound are BOTH read on, so a fixture that let the door
    // read the wall clock instead laid its whole corpus down at `now` and left
    // every window test selecting all of it.
    //
    // The MINTED id is returned, never the caller's label. The id is now decided
    // inside the signed bytes, so the label names no row — a caller that ratified
    // it got `judgement_unresolved` from a node that genuinely did not hold it.
    let row = ciris_server::attest::Emit::stamp_at(author.key_id(), spec, asserted_at)
        .map_err(|e| format!("stamp score {id}: {e}"))?
        .sign_and_assemble(ciris_server::attest::KeySigner::Local(author))
        .await
        .map_err(|e| format!("sign score {id}: {e}"))?;
    // NOT `.expect(…)`. This function's whole reason to exist beside `emit_score`
    // is that the AV-77 round trip needs a write that can come back REFUSED; an
    // unwrap here panicked the test the substrate was answering correctly.
    ciris_server::attest::put(engine, row)
        .await
        .map_err(|e| e.to_string())
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
    /// The OWNER-BINDING's `attestation_id` — the only authority tier S and
    /// tier R accept.
    owner_binding: String,
    /// An `infra:serve` delegation from root A (NOT the owner) → node. Carries
    /// the right scope and the wrong issuer.
    serve_not_owner: String,
    /// The MINTED id of the corpus's first ordinary `scores` row — a row this
    /// node genuinely holds that is NOT a judgement. Carried on the fixture
    /// because ids are decided inside the signed bytes now (CIRISPersist#643):
    /// the `t-early-1` label names no row, and a test that posted it asked the
    /// reader about something absent instead of about something ineligible.
    ordinary_row: String,
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
    let (_owner, owner_binding) = bind_owner(&engine).await;
    let node_key = node_key_id(&engine).await;

    let target = register_party(&engine, TARGET, identity_type::WITNESS).await;
    let noise = register_party(&engine, NOISE, identity_type::WITNESS).await;
    let root_a = register_party(&engine, "root-a", identity_type::USER).await;
    let root_b = register_party(&engine, "root-b", identity_type::USER).await;
    let bystander = register_party(&engine, "bystander", identity_type::WITNESS).await;

    // The corpus. TARGET: two rows BEFORE t0 (the history a bound leaves
    // standing) and two AFTER. NOISE: one row that must never be swept in.
    let ordinary_row = emit_score(
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
    let serve_not_owner = emit_delegation(&engine, &root_a, &node_key, &["infra:serve"]).await;
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
        owner_binding,
        serve_not_owner,
        ordinary_row,
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

async fn get(f: &Fixture, path: &str) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = reqwest::Client::new()
        .get(format!("{}{path}", f.base))
        .bearer_auth(&f.owner_token)
        .send()
        .await
        .expect("GET");
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
    // **persist v30.0.0 (CIRISPersist#596 item 2): the window is a PUSH-DOWN.**
    //
    // `list_attestations` accepted `AttestationFilter::window` and silently
    // dropped it — a preview that ignored `after:` handed the operator a hash
    // over twice the blast radius they asked to ratify — so this node filtered
    // the page itself and said so. The axis binds now, and `window_enforced` is
    // MEASURED rather than declared: the in-process filter is still applied and
    // reports `application` if it ever has to drop a row, so this assertion goes
    // red the moment the push-down stops binding (verified by removing
    // `f.window = …` from `Selection::to_filter`, which flips it to
    // `application` and fails here).
    assert_eq!(
        bounded_json["window_enforced"], "substrate",
        "the window must bind in the query, and the preview must say where it bound"
    );
    assert!(
        bounded_json.get("window_note").is_none(),
        "the note is the substrate-did-not-honour-it arm only: {bounded_json}"
    );

    // (a') **The open side of a one-sided window must be a sentinel the
    // substrate's comparison can order.** persist stores and binds `asserted_at`
    // as RFC-3339 TEXT, so `DateTime::MAX_UTC` (`+262143-12-31T…`, whose `'+'`
    // sorts BELOW `'2'`) makes `asserted_at < end` false for every real row: an
    // `after:`-only selection came back EMPTY the moment the push-down started
    // binding. The `rows == 2` above is that regression pinned from the upper
    // side; this is the lower side, which the mirror-image sentinel guards.
    let mut before_sel = target_selection();
    before_sel["before"] = serde_json::json!(t0().to_rfc3339());
    let (_, before_json) = preview(&f, &before_sel).await;
    assert_eq!(
        before_json["counts"]["rows"], 2,
        "a `before:`-only window must select the rows below the bound, not none and not all — \
         an open LOWER sentinel outside the four-digit-year range would sort wrong the same way"
    );
    assert_eq!(before_json["window_enforced"], "substrate");

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

    // DE-ADMISSION IS A FEDERATION ACT, and its authority is the ACCORD.
    //
    // A directory KEY belongs to no community, so this routes to
    // `duty_holders_for_federation` (persist v30.10.0, CIRISPersist#632): the
    // LIVE humanity-accord roster, which a fresh node seeds at genesis.
    //
    // The roster therefore resolves — asserted below, because "resolves to the
    // accord" and "resolves to nothing" are the distinction this whole arc is
    // about. What this node lacks is a grant FROM that accord: it is not a
    // holder, and no accord-rooted `slash` chain reaches it. So the refusal is
    // CORRECT, and it is the shape a real operator resolves by delegating
    // moderation for federation duties from the trust root — not by the node
    // asserting authority it was never given.
    //
    // A harness cannot fake the other side: family membership is seed-then-
    // revoke-only, and the baked holders' keys cannot be signed as. Pretending
    // otherwise would re-create exactly the bypass v30.8.0 closed.
    let roster = ciris_persist::federation::admission::duty_holders_for_federation(
        f.engine.federation_directory().as_ref(),
        "slash",
    )
    .await
    .expect(
        "the accord roster RESOLVES on a seeded node — an unresolvable one must refuse, \
             never return an empty set (CIRISPersist#632)",
    );
    assert!(
        !roster.is_empty(),
        "the seeded accord roster must be non-empty, or this test proves nothing about authority"
    );
    assert!(
        !roster.contains(&f.node_key),
        "this node is deliberately NOT an accord holder — the point is that authority must be \
         granted, not assumed"
    );
    // AND THE OPERATOR HAS TO BE ABLE TO READ IT. The refusal reaches the UI as
    // a TYPED, LOCALIZABLE verdict, not a stringified store error: `refused`
    // (not `error` — the substrate answered, it did not fail), the stable
    // persist token, and an `{id, text}` pair the client renders in any of the
    // 29 languages. This is the difference between an operator who knows to go
    // ask an accord holder for a grant and one who files a bug against a
    // healthy node.
    let r = &json["results"][0];
    assert_eq!(r["outcome"], "refused", "{json}");
    assert_eq!(
        r["reason"], "federation_delegated_scope_unauthorized",
        "the stable persist token must survive to the client, not be flattened \
         into prose: {json}"
    );
    assert_eq!(
        r["message"]["id"], "admin.deadmit.refused.no_slash_grant",
        "{json}"
    );
    let text = r["message"]["text"].as_str().expect("localizable text");
    assert!(
        text.contains("slash") && text.contains("accord holder"),
        "the refusal must name the REMEDY (who grants `slash`), not merely the \
         denial — got: {text}"
    );
    assert!(
        r["error"].as_str().is_some_and(|e| e.contains("slash")),
        "the substrate's own words stay available for the debug pane: {json}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tier 4, the WRITE DOOR — refuse-writes / accept-writes (AV-77, #375)
// ═══════════════════════════════════════════════════════════════════════════

/// Arm the AV-77 gate exactly as `compose::arm_peer_deadmission_gate` does —
/// declare, then READ BACK, because the readback is the whole point.
async fn arm_av77(f: &Fixture) {
    f.engine.set_self_key_id(Some(f.node_key.clone()));
    assert_eq!(
        f.engine.self_key_id().as_deref(),
        Some(f.node_key.as_str()),
        "the AV-77 predicate has no `me` to compare against until this sticks"
    );
}

/// A fresh write by TARGET, timestamped now so it never collides with the
/// fixture's fixed corpus.
async fn target_write(f: &Fixture, target: &LocalSigner, id: &str) -> Result<String, String> {
    try_emit_score(
        &f.engine,
        target,
        id,
        "health:liveness:v1",
        chrono::Utc::now(),
    )
    .await
}

/// **THE ROUND TRIP.** An admitted key writes; the route de-admits it; the
/// SAME write is refused by the substrate; the reversal route lifts it; the
/// same write lands again.
///
/// A test that only asserted the row was emitted would prove nothing about the
/// door — that is the distinction CIRISServer#375 was filed over, so this
/// suite's tier-4 write-door test is the one that walks through it.
#[tokio::test]
async fn refuse_writes_stops_the_next_write_and_accept_writes_admits_it_again() {
    let f = fixture().await;
    arm_av77(&f).await;
    let target = party_signer(TARGET);

    // ── BEFORE: the key writes freely ─────────────────────────────────────
    target_write(&f, &target, "rt-before")
        .await
        .expect("an admitted key writes freely before any sanction");

    // ── THE ACT ───────────────────────────────────────────────────────────
    let (hash, _) = preview(&f, &target_selection()).await;
    let (status, json) = post(
        &f,
        "/v1/admin/refuse-writes",
        &commit(target_selection(), &hash, &f.slash_a),
    )
    .await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["tier"], 4);
    assert_eq!(json["required_scope"], "slash");
    assert_eq!(json["deadmission_gate"], "armed");
    let result = &json["results"][0];
    assert_eq!(result["target_key_id"], TARGET, "{json}");
    assert_eq!(result["outcome"], "refused", "{json}");
    assert_eq!(result["standing_before"]["standing"], "admitted");
    assert_eq!(result["standing_after"]["standing"], "refused");
    let deadmission_id = result["deadmission_id"]
        .as_str()
        .expect("the emitted row's id")
        .to_string();

    // The row is a real, signed, federation-tier AV-77 row authored by THIS
    // node — not an approximation of one.
    let row = f
        .engine
        .federation_directory()
        .get_attestation(&deadmission_id)
        .await
        .expect("read the de-admission")
        .expect("the de-admission is stored");
    assert_eq!(row.attesting_key_id, f.node_key);
    assert_eq!(row.attested_key_id, TARGET);
    assert_eq!(
        row.attestation_envelope["dimension"],
        serde_json::json!(ciris_persist::federation::admission::PEER_DEADMISSION_DIMENSION),
    );
    assert_eq!(
        row.attestation_envelope["delegation_id"],
        serde_json::json!(f.slash_a),
        "the authority travels with the act, not only in the local ledger"
    );
    assert!(!row.scrub_signature_classical.is_empty());
    assert!(row.scrub_signature_pqc.is_some(), "hybrid-signed");

    // ── AFTER: the SAME write is refused by the substrate ─────────────────
    let err = target_write(&f, &target, "rt-after")
        .await
        .expect_err("a de-admitted key's next write MUST be refused");
    assert!(
        err.contains("de-admitted"),
        "the refusal must name de-admission, not something incidental: {err}"
    );

    // ── THE REVERSAL, which genuinely reaches the substrate ───────────────
    let (hash, _) = preview(&f, &target_selection()).await;
    let (status, json) = post(
        &f,
        "/v1/admin/accept-writes",
        &commit(target_selection(), &hash, &f.slash_a),
    )
    .await;
    assert_eq!(status, 200, "{json}");
    let result = &json["results"][0];
    assert_eq!(result["outcome"], "accepted", "{json}");
    assert_eq!(result["standing_before"]["standing"], "refused");
    assert_eq!(result["standing_after"]["standing"], "admitted");
    assert_eq!(
        result["withdrew"][0]["deadmission_id"],
        serde_json::json!(deadmission_id),
        "the lift names the row it lifts, resolved from this node's own fold"
    );

    target_write(&f, &target, "rt-lifted")
        .await
        .expect("once the de-admission is withdrawn the key writes again");

    // Both acts are in the ledger, under distinct op suffixes, so an auditor
    // can tell which was done — the whole reason this is not spelled `deadmit`.
    let kinds: Vec<String> = hard_cases(&f.engine)
        .await
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert!(
        kinds.iter().any(|k| k.ends_with("refuse_writes"))
            && kinds.iter().any(|k| k.ends_with("accept_writes")),
        "both acts are recorded and distinguishable: {kinds:?}"
    );
}

/// **The negative.** `slash`, walked the same way as every neighbouring rung.
/// A `review` delegation is real, live, and issued to this node — and it does
/// not authorize refusing anyone's writes.
#[tokio::test]
async fn refuse_writes_takes_slash_and_a_review_delegation_does_not_reach_it() {
    let f = fixture().await;
    arm_av77(&f).await;
    let target = party_signer(TARGET);
    let (hash, _) = preview(&f, &target_selection()).await;

    for (delegation, expected) in [
        (&f.review_only, "authority_scope_absent"),
        (&f.slash_elsewhere, "authority_not_to_actor"),
        (&"no-such-delegation".to_string(), "authority_unresolved"),
    ] {
        let (status, json) = post(
            &f,
            "/v1/admin/refuse-writes",
            &commit(target_selection(), &hash, delegation),
        )
        .await;
        assert_eq!(status, 403, "{json}");
        assert_eq!(json["refusal"], expected, "{json}");
        assert_localizable(&json["message"], "refusal message");
    }

    // Property 1 binds to THIS route too: a real authority over a selection
    // that is not the one previewed is refused before anything is emitted.
    let (status, json) = post(
        &f,
        "/v1/admin/refuse-writes",
        &commit(target_selection(), "0".repeat(64).as_str(), &f.slash_a),
    )
    .await;
    assert_eq!(status, 409, "{json}");
    assert_eq!(json["refusal"], "preview_hash_mismatch", "{json}");

    // Nothing was written, and the key still writes.
    assert!(
        hard_cases(&f.engine).await.is_empty(),
        "a refused op records no tombstone"
    );
    target_write(&f, &target, "unauthorized-noop")
        .await
        .expect("an unauthorized de-admission attempt must not de-admit anyone");

    // The reversal takes the same authority — a laxer path to UN-refusing is
    // the same inversion in the other direction.
    let (status, json) = post(
        &f,
        "/v1/admin/accept-writes",
        &commit(target_selection(), &hash, &f.review_only),
    )
    .await;
    assert_eq!(status, 403, "{json}");
    assert_eq!(json["refusal"], "authority_scope_absent", "{json}");
}

/// **A sanction that would not be enforced is refused, not reported as done.**
///
/// AV-77's predicate compares a writer against the key the host declared. With
/// no declaration — or with someone else's — the emitted row refuses nothing.
/// `compose::arm_peer_deadmission_gate` refuses to BOOT over this, for the
/// reason it states: *"a silently-dormant sanction gate is strictly worse than
/// no gate, because operators will believe de-admission works."*
#[tokio::test]
async fn refuse_writes_refuses_when_the_av77_gate_would_not_enforce_it() {
    let f = fixture().await;
    let target = party_signer(TARGET);
    let (hash, _) = preview(&f, &target_selection()).await;
    let body = commit(target_selection(), &hash, &f.slash_a);

    // (a) dormant — the host never declared an identity.
    assert_eq!(f.engine.self_key_id(), None, "the gate starts dormant");
    let (status, json) = post(&f, "/v1/admin/refuse-writes", &body).await;
    assert_eq!(status, 503, "{json}");
    assert_eq!(json["refusal"], "deadmission_gate_dormant", "{json}");
    assert_localizable(&json["message"], "dormant-gate message");

    // (b) foreign identity — declared, and not the key this node signs as.
    f.engine
        .set_self_key_id(Some("some-other-node".to_string()));
    let (status, json) = post(&f, "/v1/admin/refuse-writes", &body).await;
    assert_eq!(status, 503, "{json}");
    assert_eq!(
        json["refusal"], "deadmission_gate_foreign_identity",
        "{json}"
    );
    assert_localizable(&json["message"], "foreign-identity message");

    assert!(
        hard_cases(&f.engine).await.is_empty(),
        "an op refused for being unenforceable writes nothing at all"
    );
    target_write(&f, &target, "dormant-noop")
        .await
        .expect("nothing was de-admitted");

    // The LIFT is not blocked by the same condition: withdrawing a sanction is
    // the lenient direction, and refusing to lift a de-admission because it was
    // not being enforced leaves it standing to bite when the node is fixed.
    arm_av77(&f).await;
    let (hash, _) = preview(&f, &target_selection()).await;
    let (status, json) = post(
        &f,
        "/v1/admin/refuse-writes",
        &commit(target_selection(), &hash, &f.slash_a),
    )
    .await;
    assert_eq!(status, 200, "{json}");
    f.engine.set_self_key_id(None);
    let (hash, _) = preview(&f, &target_selection()).await;
    let (status, json) = post(
        &f,
        "/v1/admin/accept-writes",
        &commit(target_selection(), &hash, &f.slash_a),
    )
    .await;
    assert_eq!(status, 200, "the lift is not gated on the gate: {json}");
    assert_eq!(
        json["deadmission_gate"], "dormant",
        "and it says so: {json}"
    );
    assert_eq!(json["results"][0]["outcome"], "accepted", "{json}");
}

/// **Three zeroes, three renderings.** "not de-admitted", "de-admitted" and
/// "could not read the admission state" are three facts, and the third is the
/// one that kills: rendered as the first it is a false clean.
///
/// The `refused` / `admitted` transition is driven through the real route
/// above; this pins that the three never collapse into each other, and that a
/// no-op is reported as a no-op rather than as an act.
#[tokio::test]
async fn the_write_doors_three_zeroes_never_render_alike() {
    let f = fixture().await;
    arm_av77(&f).await;

    // Nothing held: "not de-admitted" — not an error, and not silence.
    let (hash, _) = preview(&f, &target_selection()).await;
    let (status, json) = post(
        &f,
        "/v1/admin/accept-writes",
        &commit(target_selection(), &hash, &f.slash_a),
    )
    .await;
    assert_eq!(status, 200, "nothing to lift is a NORMAL outcome: {json}");
    assert_eq!(json["results"][0]["outcome"], "not_refused");
    assert_eq!(
        json["results"][0]["standing_before"]["standing"],
        "admitted"
    );
    assert_localizable(&json["results"][0]["message"], "not-refused message");
    assert!(
        hard_cases(&f.engine).await.is_empty(),
        "a lift with nothing to lift records no act"
    );

    // De-admitted, then asked again: idempotent, and reported as unchanged
    // rather than as a second sanction.
    let (hash, _) = preview(&f, &target_selection()).await;
    let body = commit(target_selection(), &hash, &f.slash_a);
    let (_, first) = post(&f, "/v1/admin/refuse-writes", &body).await;
    assert_eq!(first["results"][0]["outcome"], "refused");
    let (hash, _) = preview(&f, &target_selection()).await;
    let (status, again) = post(
        &f,
        "/v1/admin/refuse-writes",
        &commit(target_selection(), &hash, &f.slash_a),
    )
    .await;
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["results"][0]["outcome"], "already_refused", "{again}");
    assert_eq!(again["results"][0]["standing_after"]["standing"], "refused");

    // The three standings never render alike — ids AND English.
    let mut seen: Vec<(String, String)> = Vec::new();
    for standing in ["refused", "admitted", "unreadable"] {
        let bundle = localization::canonical_bundle();
        let id = format!("admin.admission.standing.{standing}");
        let text = localization::resolve_id(&bundle, &id)
            .unwrap_or_else(|| panic!("{id} must resolve by nested traversal"));
        seen.push((id, text.to_string()));
    }
    for i in 0..seen.len() {
        for j in (i + 1)..seen.len() {
            assert_ne!(seen[i].0, seen[j].0, "two standings share one message id");
            assert_ne!(
                seen[i].1, seen[j].1,
                "two standings render the same sentence"
            );
        }
    }
    assert!(
        seen[2].1.contains("NOT 'admitted'"),
        "the unreadable standing must say, in the string an operator reads, that it is not \
         the clean one: {}",
        seen[2].1
    );
}

/// **What the route says it does NOT reach must be true.** The response claims
/// the key's existing rows are untouched and still readable, and that the key
/// itself is not removed. Both are asserted against the substrate rather than
/// left as prose.
#[tokio::test]
async fn refuse_writes_says_what_it_does_not_reach_and_that_is_checkable() {
    let f = fixture().await;
    arm_av77(&f).await;
    let before: Vec<String> = f
        .engine
        .federation_directory()
        .list_attestations_by(TARGET)
        .await
        .expect("list TARGET's rows")
        .into_iter()
        .map(|a| a.attestation_id)
        .collect();
    assert!(!before.is_empty(), "the fixture gave TARGET a corpus");

    let (hash, _) = preview(&f, &target_selection()).await;
    let (status, json) = post(
        &f,
        "/v1/admin/refuse-writes",
        &commit(target_selection(), &hash, &f.slash_a),
    )
    .await;
    assert_eq!(status, 200, "{json}");
    assert_localizable(&json["enforcement"], "enforcement note");
    assert_localizable(&json["not_reached"], "not-reached note");
    assert_localizable(&json["reversal"], "reversal note");

    // "It unwrites nothing."
    let after: Vec<String> = f
        .engine
        .federation_directory()
        .list_attestations_by(TARGET)
        .await
        .expect("list TARGET's rows")
        .into_iter()
        .map(|a| a.attestation_id)
        .collect();
    assert_eq!(
        before, after,
        "every row the key already wrote is still here"
    );

    // "The keys are not removed."
    assert!(
        f.engine
            .federation_directory()
            .lookup_public_key(TARGET)
            .await
            .expect("lookup")
            .is_some(),
        "de-admission is about future writes, not about the key's existence"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tier S — self-directed
// ═══════════════════════════════════════════════════════════════════════════

/// A tier S / tier R commit body: attribution, no selection hash.
fn self_commit(delegation_id: &str, reason: &str) -> serde_json::Value {
    serde_json::json!({ "delegation_id": delegation_id, "reason": reason })
}

/// The three axes, and the route that declares each.
const SELF_ACTS: [(&str, &str, &str); 3] = [
    (
        "load_shed",
        "/v1/admin/self/shed",
        "/v1/admin/self/resume-load",
    ),
    (
        "accepting",
        "/v1/admin/self/stop-accepting",
        "/v1/admin/self/resume-accepting",
    ),
    (
        "legal_compulsion",
        "/v1/admin/self/compelled",
        "/v1/admin/self/compulsion-lifted",
    ),
];

#[tokio::test]
async fn tier_s_the_three_acts_are_independently_recorded_and_distinguishable() {
    let f = fixture().await;

    let mut event_ids = Vec::new();
    for (axis, declare, _) in SELF_ACTS {
        let (status, json) = post(
            &f,
            declare,
            &self_commit(
                &f.owner_binding,
                "hosting bill unpaid; shedding before eviction",
            ),
        )
        .await;
        assert_eq!(status, 200, "{declare}: {json}");
        assert_eq!(json["tier"], "S");
        assert_eq!(json["axis"], axis);
        assert_eq!(json["standing"]["standing"], "in_force");
        assert_localizable(&json["enforcement"], "tier S enforcement");
        assert_localizable(&json["partition"], "tier S partition note");
        event_ids.push(json["event_id"].as_str().expect("event_id").to_string());
    }
    let distinct: std::collections::BTreeSet<&String> = event_ids.iter().collect();
    assert_eq!(
        distinct.len(),
        3,
        "three acts are three records, not one: {event_ids:?}"
    );

    // Three distinct `admin_action:` kinds on the ledger.
    let kinds: std::collections::BTreeSet<String> = hard_cases(&f.engine)
        .await
        .into_iter()
        .filter(|e| e.kind.starts_with("admin_action:self_"))
        .map(|e| e.kind)
        .collect();
    assert_eq!(
        kinds.len(),
        3,
        "each act carries its own op suffix: {kinds:?}"
    );

    // All three stand, side by side, on the read.
    let (status, json) = get(&f, "/v1/admin/self").await;
    assert_eq!(status, 200, "{json}");
    for (axis, _, _) in SELF_ACTS {
        assert_eq!(
            json["standings"][axis]["standing"], "in_force",
            "{axis} must stand on its own axis: {json}"
        );
    }

    // Lifting ONE leaves the other two untouched — the axes do not fold
    // together.
    let (status, _) = post(
        &f,
        "/v1/admin/self/resume-load",
        &self_commit(&f.owner_binding, "bill paid; resuming"),
    )
    .await;
    assert_eq!(status, 200);
    let (_, json) = get(&f, "/v1/admin/self").await;
    assert_eq!(json["standings"]["load_shed"]["standing"], "lifted");
    assert_eq!(json["standings"]["accepting"]["standing"], "in_force");
    assert_eq!(
        json["standings"]["legal_compulsion"]["standing"],
        "in_force"
    );
}

#[tokio::test]
async fn tier_s_a_compulsion_is_never_conflatable_with_a_voluntary_stop() {
    let f = fixture().await;

    // A node that CHOSE to stop.
    let (status, json) = post(
        &f,
        "/v1/admin/self/stop-accepting",
        &self_commit(&f.owner_binding, "disk nearly full; taking nothing new"),
    )
    .await;
    assert_eq!(status, 200, "{json}");

    let (_, standing) = get(&f, "/v1/admin/self").await;
    assert_eq!(standing["standings"]["accepting"]["standing"], "in_force");
    assert_eq!(
        standing["standings"]["legal_compulsion"]["standing"], "never_declared",
        "choosing to stop must NOT read as being made to stop: {standing}"
    );

    // A node that was MADE to stop. Same observable — nothing arriving — and
    // the opposite meaning.
    let mut compelled = self_commit(&f.owner_binding, "order served; not permitted to say more");
    compelled["compelled_by"] = serde_json::json!("sealed order, district court");
    let (status, json) = post(&f, "/v1/admin/self/compelled", &compelled).await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["axis"], "legal_compulsion");

    let events = hard_cases(&f.engine).await;
    let compulsion = events
        .iter()
        .find(|e| e.kind == "admin_action:self_compelled")
        .expect("the compulsion has its own kind");
    let stop = events
        .iter()
        .find(|e| e.kind == "admin_action:self_stop_accepting")
        .expect("the voluntary stop has its own kind");
    assert_ne!(compulsion.kind, stop.kind);
    assert_ne!(compulsion.event_id, stop.event_id);
    assert_eq!(compulsion.detail["axis"], "legal_compulsion");
    assert_eq!(stop.detail["axis"], "accepting");
    assert_eq!(
        compulsion.detail["compelled_by"], "sealed order, district court",
        "the compelling authority rides on the compulsion: {:?}",
        compulsion.detail
    );
    assert!(
        stop.detail.get("compelled_by").is_none(),
        "a voluntary stop must never carry the marks of a compelled one: {:?}",
        stop.detail
    );

    // A gagged operator can still leave a trace: `compelled_by` is optional,
    // and its absence is recorded as an absence rather than refusing the act.
    let f2 = fixture().await;
    let (status, json) = post(
        &f2,
        "/v1/admin/self/compelled",
        &self_commit(
            &f2.owner_binding,
            "compelled; I am not permitted to say by whom",
        ),
    )
    .await;
    assert_eq!(
        status, 200,
        "the most constrained operator must still be able to record the act: {json}"
    );
    let gagged = hard_cases(&f2.engine)
        .await
        .into_iter()
        .find(|e| e.kind == "admin_action:self_compelled")
        .expect("recorded");
    assert!(
        gagged.detail["compelled_by"].is_null(),
        "an unnamed compelling authority is recorded as unnamed, not as absent: {:?}",
        gagged.detail
    );
}

#[tokio::test]
async fn tier_s_the_three_zeroes_never_render_alike() {
    let f = fixture().await;

    // Zero 1 — never declared, on every axis, on a fresh node.
    let (status, json) = get(&f, "/v1/admin/self").await;
    assert_eq!(status, 200, "{json}");
    for (axis, _, _) in SELF_ACTS {
        assert_eq!(json["standings"][axis]["standing"], "never_declared");
        assert_eq!(json["standings"][axis]["counts"]["declarations"], 0);
        assert!(json["standings"][axis]["since"].is_null());
        assert_localizable(
            &json["standings"][axis]["message"],
            "never-declared message",
        );
    }
    let never = json["standings"]["load_shed"]["message"]["id"]
        .as_str()
        .expect("id")
        .to_string();

    // Zero 2 — declared and lifted. A DIFFERENT fact, with a different token
    // and a different message id.
    post(
        &f,
        "/v1/admin/self/shed",
        &self_commit(&f.owner_binding, "shedding"),
    )
    .await;
    post(
        &f,
        "/v1/admin/self/resume-load",
        &self_commit(&f.owner_binding, "resuming"),
    )
    .await;
    let (_, json) = get(&f, "/v1/admin/self").await;
    let lifted = &json["standings"]["load_shed"];
    assert_eq!(lifted["standing"], "lifted");
    assert_ne!(
        lifted["message"]["id"].as_str().expect("id"),
        never,
        "'declared and lifted' must not render as 'never declared'"
    );
    assert_eq!(lifted["counts"]["declarations"], 1);
    assert_eq!(lifted["counts"]["lifts"], 1);
    assert!(
        !lifted["since"].is_null(),
        "a lifted axis knows WHEN it was lifted; a never-declared one has no instant"
    );

    // Zero 3 — unreadable. Distinct token, distinct message, and it is the one
    // that must never be mistaken for either of the other two.
    use ciris_server::admin_ops::SelfStanding;
    let tokens: std::collections::BTreeSet<&str> = [
        SelfStanding::InForce,
        SelfStanding::Lifted,
        SelfStanding::NeverDeclared,
        SelfStanding::Unreadable,
    ]
    .iter()
    .map(|s| s.token())
    .collect();
    assert_eq!(tokens.len(), 4, "four standings, four tokens: {tokens:?}");
}

#[tokio::test]
async fn tier_s_is_the_only_rung_a_partitioned_node_can_still_use() {
    // This fixture IS a partitioned node: an in-memory engine with no peer
    // registered, no transport configured and nothing to dial. Every other rung
    // is about someone else; these three are about this node, so they must all
    // complete here.
    let f = fixture().await;
    for (axis, declare, lift) in SELF_ACTS {
        let (status, json) = post(
            &f,
            declare,
            &self_commit(&f.owner_binding, "partitioned; acting on myself"),
        )
        .await;
        assert_eq!(status, 200, "{declare} must work while partitioned: {json}");
        assert_eq!(json["axis"], axis);

        let (status, json) =
            post(&f, lift, &self_commit(&f.owner_binding, "partition healed")).await;
        assert_eq!(status, 200, "{lift} must work while partitioned: {json}");
        assert_eq!(json["reversal"]["reach"], "symmetric");
    }
    let (status, _) = get(&f, "/v1/admin/self").await;
    assert_eq!(status, 200, "the standing read is local too");
}

#[tokio::test]
async fn tier_s_takes_the_owners_own_authority_and_no_one_elses() {
    let f = fixture().await;

    // Right scope, wrong issuer: root A granted this node `infra:serve`, but
    // root A is not this node's responsible party.
    let (status, json) = post(
        &f,
        "/v1/admin/self/shed",
        &self_commit(&f.serve_not_owner, "shedding"),
    )
    .await;
    assert_eq!(status, 403, "{json}");
    assert_eq!(json["refusal"], "authority_not_the_owner");
    assert_localizable(&json["message"], "not-the-owner message");

    // Right issuer, wrong scope: the `slash` chain is not a serve grant.
    let (status, json) = post(
        &f,
        "/v1/admin/self/shed",
        &self_commit(&f.slash_a, "shedding"),
    )
    .await;
    assert_eq!(status, 403, "{json}");
    assert_eq!(json["refusal"], "authority_scope_absent");

    // No reason: refused before anything is written.
    let (status, json) = post(
        &f,
        "/v1/admin/self/shed",
        &serde_json::json!({ "delegation_id": f.owner_binding, "reason": "  " }),
    )
    .await;
    assert_eq!(status, 400, "{json}");
    assert_eq!(json["refusal"], "attribution_absent");

    assert!(
        !hard_cases(&f.engine)
            .await
            .iter()
            .any(|e| e.kind.starts_with("admin_action:self_")),
        "no refused act leaves a record claiming it happened"
    );

    // The owner's own binding carries `infra:serve` and is accepted.
    let (status, json) = post(
        &f,
        "/v1/admin/self/shed",
        &self_commit(&f.owner_binding, "shedding, by the owner"),
    )
    .await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["delegation_id"], f.owner_binding);
    let ev = hard_cases(&f.engine)
        .await
        .into_iter()
        .find(|e| e.kind == "admin_action:self_shed")
        .expect("recorded");
    assert_eq!(
        ev.detail["delegation_id"], f.owner_binding,
        "the act carries the authority it was taken under"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tier R — subject-side / per-reader
// ═══════════════════════════════════════════════════════════════════════════

/// Raise a real quarantine marker about TARGET through the tier 2 route, and
/// return its `attestation_id` — a genuine third-party-shaped judgement, minted
/// through persist's own admission door.
async fn raise_judgement(f: &Fixture) -> String {
    put_community(&f.engine, COMMUNITY, &f.node_key).await;
    let (hash, _) = preview(f, &target_selection()).await;
    let mut body = commit(target_selection(), &hash, &f.slash_a);
    body["community_id"] = serde_json::json!(COMMUNITY);
    let (status, json) = post(f, "/v1/admin/quarantine", &body).await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["results"][0]["outcome"], "admitted", "{json}");
    json["results"][0]["marker_id"]
        .as_str()
        .expect("marker_id")
        .to_string()
}

async fn reader_fold(f: &Fixture, subject: &str) -> (reqwest::StatusCode, serde_json::Value) {
    post(
        f,
        "/v1/admin/reader/fold",
        &serde_json::json!({ "subject_key_id": subject }),
    )
    .await
}

#[tokio::test]
async fn tier_r_two_reader_policies_reach_different_both_valid_states_from_one_judgement() {
    let f = fixture().await;
    let judgement = raise_judgement(&f).await;
    // This reader subscribes to an authority that reaches the marker's signer
    // under `slash` — persist's own §11.10 walk, not a predicate of ours.
    // (Not one of the USER roots: persist refuses a steward→user delegation
    // without guardianship, which is a different plane's rule.)
    let sub_root = register_party(&f.engine, SUB_ROOT, identity_type::WITNESS).await;
    emit_delegation(&f.engine, &sub_root, &f.node_key, &["slash"]).await;
    subscribe_to(&f.engine, SUB_ROOT).await;

    // ── policy A: subscribed to the signer's authority, no explicit decision.
    // The judgement is honoured by policy, and the reader's fold agrees with
    // the node's serve-side fold.
    let (status, a) = reader_fold(&f, TARGET).await;
    assert_eq!(status, 200, "{a}");
    assert_eq!(a["standing"], "decided");
    assert_eq!(a["counts"]["judgements_held"], 1);
    let decision_a = a["judgements"][0]["decision"]
        .as_str()
        .expect("decision")
        .to_string();
    assert_eq!(
        decision_a, "honoured_by_subscription",
        "the subscription set is read from this node's own trust edges: {a}"
    );
    assert!(
        a["judgements"][0]["honoured"].as_bool().expect("honoured"),
        "policy A honours it: {a}"
    );
    assert_eq!(a["reader_fold"]["state"], "withheld", "{a}");
    assert_eq!(a["node_fold"]["state"], "withheld");
    assert_eq!(a["diverges"], false);

    // ── policy B: the same reader, having decided to refuse the same
    // judgement. Same row, same fold function, different row set in — and a
    // different, equally valid state out.
    let (status, decline) = post(
        &f,
        "/v1/admin/reader/decline",
        &serde_json::json!({
            "judgement_id": judgement,
            "delegation_id": f.owner_binding,
            "reason": "the grounds do not hold up; we will not relay this withhold",
        }),
    )
    .await;
    assert_eq!(status, 200, "{decline}");

    let (status, b) = reader_fold(&f, TARGET).await;
    assert_eq!(status, 200, "{b}");
    assert_eq!(b["judgements"][0]["decision"], "declined");
    assert_ne!(
        decision_a, "declined",
        "the two policies must not be the same policy"
    );
    assert_eq!(
        b["reader_fold"]["state"], "not_quarantined",
        "policy B's fold does not withhold: {b}"
    );
    assert_eq!(
        b["node_fold"]["state"], "withheld",
        "and the node's serve path still does — the divergence is reported, not hidden"
    );
    assert_eq!(b["diverges"], true);
    assert_localizable(&b["advisory"], "reader advisory");

    // Honouring it again is a decision too, and it wins over the decline.
    let (status, _) = post(
        &f,
        "/v1/admin/reader/honour",
        &serde_json::json!({
            "judgement_id": judgement,
            "delegation_id": f.owner_binding,
            "reason": "grounds corroborated on review",
        }),
    )
    .await;
    assert_eq!(status, 200);
    let (_, c) = reader_fold(&f, TARGET).await;
    assert_eq!(c["judgements"][0]["decision"], "honoured_explicit");
    assert_eq!(c["reader_fold"]["state"], "withheld");
}

#[tokio::test]
async fn tier_r_declining_a_judgement_is_a_normal_outcome_not_an_error() {
    let f = fixture().await;
    let judgement = raise_judgement(&f).await;

    let (status, json) = post(
        &f,
        "/v1/admin/reader/decline",
        &serde_json::json!({
            "judgement_id": judgement,
            "delegation_id": f.owner_binding,
            "reason": "we do not honour this signer's withholds",
        }),
    )
    .await;
    assert_eq!(status, 200, "a decline is not an error path: {json}");
    assert_eq!(json["outcome"], "declined");
    assert_eq!(
        json["refused"], false,
        "stated in the payload too, so a client branching on shape cannot read it as a failure"
    );
    assert_localizable(&json["message"], "decline message");
    assert_eq!(json["standing"]["judgements"][0]["decision"], "declined");

    let recorded = hard_cases(&f.engine)
        .await
        .into_iter()
        .find(|e| e.kind == "admin_action:reader_decline")
        .expect("a decline is recorded as its own act");
    assert_eq!(recorded.detail["judgement_id"], judgement);
    assert_eq!(recorded.detail["delegation_id"], f.owner_binding);
}

#[tokio::test]
async fn tier_r_distinguishes_not_honoured_from_refused_and_from_nothing_held() {
    let f = fixture().await;

    // Nothing held about a subject nobody has judged. Not "decided", not
    // "unreadable" — and the fold reports a state, not an absence.
    let (status, json) = reader_fold(&f, NOISE).await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["standing"], "no_judgements_held");
    assert_eq!(json["counts"]["judgements_held"], 0);
    assert_localizable(&json["message"], "no-judgements message");

    // A judgement from a signer this reader does not subscribe to is NOT
    // honoured — and that is nobody's decision yet, which is a different fact
    // from having refused it. No `subscribe_to` here, deliberately.
    let judgement = raise_judgement(&f).await;
    let (status, json) = reader_fold(&f, TARGET).await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["subscription"]["count"], 0);
    assert_eq!(
        json["judgements"][0]["decision"], "undecided_unsubscribed",
        "held, not honoured, and nobody has decided: {json}"
    );
    assert_eq!(json["reader_fold"]["state"], "not_quarantined");
    assert_eq!(
        json["node_fold"]["state"], "withheld",
        "the node's serve path still withholds — the gap is reported, not hidden"
    );

    // Refusing it is a DECISION, and it reads differently even though the
    // fold's answer is the same.
    let (status, _) = post(
        &f,
        "/v1/admin/reader/decline",
        &serde_json::json!({
            "judgement_id": judgement,
            "delegation_id": f.owner_binding,
            "reason": "reviewed and refused",
        }),
    )
    .await;
    assert_eq!(status, 200);
    let (_, after) = reader_fold(&f, TARGET).await;
    assert_eq!(after["judgements"][0]["decision"], "declined");
    assert_eq!(
        after["reader_fold"]["state"], json["reader_fold"]["state"],
        "same fold, different fact — which is exactly why the decision is \
         reported separately from the state"
    );

    use ciris_server::admin_ops::ReaderDecision;
    let tokens: std::collections::BTreeSet<&str> = [
        ReaderDecision::HonouredExplicit,
        ReaderDecision::HonouredBySubscription,
        ReaderDecision::UndecidedUnsubscribed,
        ReaderDecision::Declined,
    ]
    .iter()
    .map(|d| d.token())
    .collect();
    assert_eq!(tokens.len(), 4, "four decisions, four tokens: {tokens:?}");
    assert!(!ReaderDecision::UndecidedUnsubscribed.honoured());
    assert!(!ReaderDecision::Declined.honoured());
    assert_ne!(
        ReaderDecision::UndecidedUnsubscribed.token(),
        ReaderDecision::Declined.token(),
        "'nobody decided' and 'we refused' are the same outcome for the fold and \
         different facts for the operator"
    );
}

#[tokio::test]
async fn tier_r_only_decides_about_judgements_this_node_actually_holds() {
    let f = fixture().await;
    raise_judgement(&f).await;

    // A row this node does not hold.
    let (status, json) = post(
        &f,
        "/v1/admin/reader/decline",
        &serde_json::json!({
            "judgement_id": "no-such-row",
            "delegation_id": f.owner_binding,
            "reason": "pre-refusing something I have never seen",
        }),
    )
    .await;
    assert_eq!(status, 404, "{json}");
    assert_eq!(json["refusal"], "judgement_unresolved");

    // A row this node holds that is not a judgement. The MINTED id, not the
    // `t-early-1` label — the label resolves to nothing, and asking about an
    // absent row tests `judgement_unresolved` a second time instead of the
    // eligibility rule this leg is for.
    let (status, json) = post(
        &f,
        "/v1/admin/reader/honour",
        &serde_json::json!({
            "judgement_id": f.ordinary_row,
            "delegation_id": f.owner_binding,
            "reason": "honouring an ordinary attestation",
        }),
    )
    .await;
    assert_eq!(status, 400, "{json}");
    assert_eq!(json["refusal"], "not_a_judgement");

    // The owner's authority is required here too.
    let (status, json) = post(
        &f,
        "/v1/admin/reader/decline",
        &serde_json::json!({
            "judgement_id": "no-such-row",
            "delegation_id": f.serve_not_owner,
            "reason": "not the owner",
        }),
    )
    .await;
    assert_eq!(status, 403, "{json}");
    assert_eq!(json["refusal"], "authority_not_the_owner");

    assert!(
        !hard_cases(&f.engine)
            .await
            .iter()
            .any(|e| e.kind.starts_with("admin_action:reader_")),
        "no refused decision leaves a record"
    );
}

#[tokio::test]
async fn tier_r_two_decisions_in_one_second_are_two_decisions() {
    // Persist keys an admin-action `event_id` on `(op, target, whole second)`,
    // and the target of a reader decision is the judgement's SUBJECT — so two
    // declines about two judgements naming one subject, inside one second,
    // would collapse onto one row and silently lose a decision.
    let f = fixture().await;
    put_community(&f.engine, COMMUNITY, &f.node_key).await;
    let mut ids = Vec::new();
    for _ in 0..2 {
        let (hash, _) = preview(&f, &target_selection()).await;
        let mut body = commit(target_selection(), &hash, &f.slash_a);
        body["community_id"] = serde_json::json!(COMMUNITY);
        let (status, json) = post(&f, "/v1/admin/quarantine", &body).await;
        assert_eq!(status, 200, "{json}");
        ids.push(
            json["results"][0]["marker_id"]
                .as_str()
                .expect("marker_id")
                .to_string(),
        );
    }
    assert_ne!(ids[0], ids[1], "two markers, two rows");

    for id in &ids {
        let (status, json) = post(
            &f,
            "/v1/admin/reader/decline",
            &serde_json::json!({
                "judgement_id": id,
                "delegation_id": f.owner_binding,
                "reason": "both of these withholds are refused",
            }),
        )
        .await;
        assert_eq!(status, 200, "{json}");
    }

    let declines: Vec<_> = hard_cases(&f.engine)
        .await
        .into_iter()
        .filter(|e| e.kind == "admin_action:reader_decline")
        .collect();
    assert_eq!(
        declines.len(),
        2,
        "two decisions about two judgements are two records, whatever the clock says: {declines:?}"
    );
    let (_, json) = reader_fold(&f, TARGET).await;
    for j in json["judgements"].as_array().expect("judgements") {
        assert_eq!(j["decision"], "declined", "every decision survives: {json}");
    }
}

#[tokio::test]
async fn tier_r_reads_the_same_judgement_set_persist_folds() {
    let f = fixture().await;
    raise_judgement(&f).await;

    let (status, json) = reader_fold(&f, TARGET).await;
    assert_eq!(status, 200, "{json}");
    // Persist's own `resolve_quarantine` is the reference. `node_fold` is this
    // module's gatherer plus persist's fold, so a divergence here means the
    // gatherer drifted from `markers_about` — the two-lists defect this module
    // documents rather than risks silently.
    let reference = f
        .engine
        .resolve_quarantine(TARGET, chrono::Utc::now())
        .await
        .expect("resolve_quarantine");
    assert_eq!(
        json["node_fold"]["state"].as_str().expect("state"),
        reference.state.as_str(),
        "our gatherer must select exactly what persist's own read selects"
    );
    assert_eq!(
        json["node_fold"]["marker_id"].as_str(),
        reference.marker_id.as_deref()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  Every emitted string must be REACHABLE by the loader (CIRISServer#366)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn every_string_these_routes_emit_resolves_in_the_canonical_bundle() {
    // Harvested from REAL responses rather than a hand-listed vocabulary: a list
    // maintained beside the routes is a list that falls behind them, and this
    // module emits its strings from six different places (enforcement notes,
    // standings, decisions, reversals, refusals, advisories).
    //
    // Resolution goes through the shared port of the Kotlin loader, which walks
    // NESTED objects only. A flat dotted bundle key renders raw in every
    // language including English — the defect that has now bitten three times,
    // twice after being fixed.
    let bundle = localization::canonical_bundle();
    let f = fixture().await;
    let judgement = raise_judgement(&f).await;
    let mut seen = 0usize;

    let mut check = |what: &str, json: &serde_json::Value| {
        let mut pairs = Vec::new();
        localization::collect_pairs(json, &mut pairs);
        seen += pairs.len();
        localization::assert_pairs_resolve(&bundle, json, what);
    };

    // ── tier S: the standing read, then each of the six acts ───────────────
    let (_, json) = get(&f, "/v1/admin/self").await;
    check("GET /v1/admin/self (all three never declared)", &json);
    for (axis, declare, lift) in SELF_ACTS {
        let mut body = self_commit(&f.owner_binding, "gating the strings this act emits");
        body["compelled_by"] = serde_json::json!("a named authority");
        let (_, json) = post(&f, declare, &body).await;
        check(axis, &json);
        let (_, json) = post(&f, lift, &self_commit(&f.owner_binding, "lifting")).await;
        check(axis, &json);
    }
    let (_, json) = get(&f, "/v1/admin/self").await;
    check("GET /v1/admin/self (all three lifted)", &json);

    // ── tier R: the fold, a decline, an honour ─────────────────────────────
    let (_, json) = reader_fold(&f, TARGET).await;
    check("POST /v1/admin/reader/fold", &json);
    let (_, json) = reader_fold(&f, NOISE).await;
    check("POST /v1/admin/reader/fold (nothing held)", &json);
    for route in ["/v1/admin/reader/decline", "/v1/admin/reader/honour"] {
        let (_, json) = post(
            &f,
            route,
            &serde_json::json!({
                "judgement_id": judgement,
                "delegation_id": f.owner_binding,
                "reason": "gating the strings this decision emits",
            }),
        )
        .await;
        check(route, &json);
    }

    // ── the refusals, which are the strings an operator sees when stuck ────
    let refusals: Vec<(&str, serde_json::Value)> = vec![
        (
            "/v1/admin/self/shed",
            self_commit(&f.serve_not_owner, "wrong issuer"),
        ),
        (
            "/v1/admin/self/shed",
            self_commit(&f.slash_a, "wrong scope"),
        ),
        (
            "/v1/admin/self/shed",
            serde_json::json!({ "delegation_id": f.owner_binding, "reason": " " }),
        ),
        (
            "/v1/admin/reader/fold",
            serde_json::json!({ "subject_key_id": "  " }),
        ),
        (
            "/v1/admin/reader/decline",
            serde_json::json!({
                "judgement_id": "no-such-row",
                "delegation_id": f.owner_binding,
                "reason": "unresolvable",
            }),
        ),
        (
            "/v1/admin/reader/honour",
            serde_json::json!({
                "judgement_id": "t-early-1",
                "delegation_id": f.owner_binding,
                "reason": "not a judgement",
            }),
        ),
    ];
    for (route, body) in refusals {
        let (status, json) = post(&f, route, &body).await;
        assert!(status.is_client_error(), "{route} must refuse: {json}");
        check(route, &json);
    }

    // ── and the tier 0–4 strings this suite already drives ─────────────────
    let (hash, json) = preview(&f, &target_selection()).await;
    check("POST /v1/admin/preview", &json);
    let (_, json) = post(
        &f,
        "/v1/admin/annotate",
        &commit(target_selection(), &hash, &f.review_only),
    )
    .await;
    check("POST /v1/admin/annotate", &json);

    // ── the write door, in all four of its shapes ──────────────────────────
    // Dormant first (the refusal an operator hits when the node is misconfigured),
    // then armed: nothing-to-lift, the sanction, and the lift.
    let (status, json) = post(
        &f,
        "/v1/admin/refuse-writes",
        &commit(target_selection(), &hash, &f.slash_a),
    )
    .await;
    assert!(status.is_server_error(), "a dormant gate refuses: {json}");
    check("POST /v1/admin/refuse-writes (dormant)", &json);
    arm_av77(&f).await;
    for route in [
        "/v1/admin/accept-writes",
        "/v1/admin/refuse-writes",
        "/v1/admin/accept-writes",
    ] {
        let (hash, _) = preview(&f, &target_selection()).await;
        let (_, json) = post(&f, route, &commit(target_selection(), &hash, &f.slash_a)).await;
        check(route, &json);
    }

    // A zero denominator is not evidence — this gate must have looked at a
    // realistic number of strings, not at nothing.
    assert!(
        seen >= 40,
        "the gate examined only {seen} strings; it is meant to cover this module's whole \
         emitted vocabulary"
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
        "/v1/admin/refuse-writes",
        "/v1/admin/accept-writes",
        "/v1/admin/self/shed",
        "/v1/admin/self/resume-load",
        "/v1/admin/self/stop-accepting",
        "/v1/admin/self/resume-accepting",
        "/v1/admin/self/compelled",
        "/v1/admin/self/compulsion-lifted",
        "/v1/admin/reader/fold",
        "/v1/admin/reader/honour",
        "/v1/admin/reader/decline",
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

    // The one GET on the ladder, gated by the same stack.
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/v1/admin/self", f.base))
        .send()
        .await
        .expect("GET");
    assert_eq!(resp.status(), 401, "the standing read is owner-only too");
    let resp = client
        .get(format!("{}/v1/admin/self", f.base))
        .bearer_auth(&observer)
        .send()
        .await
        .expect("GET");
    assert_eq!(resp.status(), 403);

    assert!(hard_cases(&f.engine).await.is_empty());
}
