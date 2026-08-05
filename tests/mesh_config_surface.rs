//! **The Mesh Configuration surface** (CIRISServer#346, the fourth tab) — one
//! test per non-negotiable property, driven over the real router and the real
//! persist substrate.
//!
//! 1. **The key registry is READ from persist, never restated** —
//!    `property_1_*`: the served registry is `MeshConfigKey::ALL` projected
//!    through `spec()`, an unregistered key is refused by persist's OWN
//!    deserializer with persist's own sentence, and a source scan proves no
//!    wire key name, dimension prefix or namespace family is spelled in the
//!    module's code.
//! 2. **The durability rule is not hardcoded** — `property_2_*`: a cold durable
//!    submission renders the token `Engine::record_mesh_config_row` returns for
//!    the same act, compared against persist rather than against a constant, and
//!    a source scan proves the module's code contains no quorum predicate.
//! 3. **`EMERGENCY_MAX_TTL_HOURS` is read, never written down** —
//!    `property_3_*`: the served bound IS persist's constant, an over-long
//!    window is refused with persist's `ttl_too_long` (not a token minted here),
//!    and the module's code carries no bare `72`.
//! 4. **Distinct zeroes** — `property_4_*`: "no mesh-config set" and "could not
//!    read the plane" carry different tokens, and so do "no history" and
//!    "history unavailable"; each live arm is exercised end to end.
//! 5. **Strings are `{id, text}` localizable pairs** — `property_5_*`: every
//!    operator-facing string on every response is a pair, and a counting-down
//!    TTL is `remaining_seconds` plus a message id rather than a sentence.

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::mesh_config::{
    mesh_config_envelope, DIMENSION_PREFIX, EMERGENCY_MAX_TTL_HOURS, NAMESPACE_FAMILY,
};
use ciris_persist::federation::trust_root::{TRUST_ACCEPTS_DIMENSION, TRUST_CONFERS_DIMENSION};
use ciris_persist::federation::types::{
    algorithm, attestation_tier, attestation_type, cohort_scope, identity_type, Attestation,
    KeyRecord, SignedAttestation, SignedKeyRecord,
};
use ciris_persist::federation::{
    MeshConfigBaseline, MeshConfigForm, MeshConfigKey, MeshConfigRefusalReason,
};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};

use ciris_server::auth::store;
use ciris_server::graph_config::{ConfigScope, ConfigValue};
use ciris_server::mesh_config_surface::{
    self, HistoryStanding, PlaneStanding, ValueProvenance, BASELINE_CONFIG_PREFIX, ROUTE_DURABLE,
    ROUTE_HISTORY, ROUTE_READ, ROUTE_RELIEF,
};

const NODE_ALIAS: &str = "ciris-mesh-config-node";
/// The trust root this node subscribes to.
const ROOT: &str = "mc-root";
/// A root this node does NOT subscribe to.
const STRANGER: &str = "mc-stranger";
const OWNER_USER: &str = "ciris-mesh-config-owner";

/// The key every knob test turns. `LowerMeansMoreFlow` — a LARGER interval is
/// less gossip — so a restricting value is one ABOVE the owner default, which
/// is exactly the arm a naive `min()` fold would invert.
fn knob() -> MeshConfigKey {
    MeshConfigKey::AntientropyRoundSecs
}

/// A value that RESTRICTS (less flow than the baseline) — admissible under
/// relieve-never-expand.
fn restricting() -> i64 {
    knob().owner_default() * 5
}

/// A value that EXPANDS (more flow than the baseline) — refused at the door.
fn expanding() -> i64 {
    1
}

// ─── substrate + identity helpers (mirror tests/admin_ops.rs) ───────────────

async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xC1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xC2; 32], format!("{NODE_ALIAS}-pqc"))
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

async fn bind_owner(engine: &Engine) {
    let owner = register_party(engine, OWNER_USER, identity_type::USER).await;
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let nk = node_key_id(engine).await;
    ciris_server::auth::ownership::emit_steward_binding(engine, &owner, &nk, &scopes)
        .await
        .expect("emit owner-binding");
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

/// Put a `delegates_to` row on `dimension`, signed by `signer` (whose `key_id`
/// is `attesting`). The trust plane reads these rows by field, not by
/// signature, but they are genuinely signed so nothing here rests on a stub.
async fn put_delegation(
    engine: &Engine,
    attesting: &str,
    attested: &str,
    dimension: &str,
    signer: Option<&LocalSigner>,
) -> String {
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({
        "kind": "delegates_to",
        "dimension": dimension,
        "attesting_key_id": attesting,
        "attested_key_id": attested,
        "scope": ["infra:serve", "infra:attest"],
    });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize delegation");
    let sig = match signer {
        Some(s) => s.sign_hybrid(&canonical).await.expect("sign delegation"),
        None => engine
            .sign_hybrid(&canonical)
            .await
            .expect("node-sign delegation"),
    };
    let attestation_id = format!("deleg-{attesting}-{attested}-{dimension}");
    let attestation = Attestation {
        attestation_id: attestation_id.clone(),
        attesting_key_id: attesting.to_string(),
        attested_key_id: attested.to_string(),
        attestation_type: attestation_type::DELEGATES_TO.to_string(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: attesting.to_string(),
        additional_scrubs: Vec::new(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: vec![attested.to_string()],
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_string(),
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

async fn serve(engine: Arc<Engine>) -> (String, tokio::task::JoinHandle<()>) {
    // No key id is handed to the router (CIRISServer#372 Level 2) — it resolves
    // this node's identity from the engine. The harness therefore CANNOT restate
    // it, which is the point: a harness that can restate an identity is a harness
    // that can be wrong about it for eight releases while production ships
    // something else.
    let app = mesh_config_surface::router(engine);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

// ─── the fixture ────────────────────────────────────────────────────────────

struct Fixture {
    engine: Arc<Engine>,
    base: String,
    owner_token: String,
    node_key: String,
    /// `trust:confers:v1` from ROOT → node — the authority every write names.
    conferral: String,
    _handle: tokio::task::JoinHandle<()>,
}

/// A node that is owned and has a session, but subscribes to NO root yet.
async fn bare_fixture() -> Fixture {
    let engine = node().await;
    register_self(&engine).await;
    bind_owner(&engine).await;
    let node_key = node_key_id(&engine).await;
    let root = register_party(&engine, ROOT, identity_type::STEWARD).await;
    register_party(&engine, STRANGER, identity_type::STEWARD).await;
    // The conferral exists from the start; the SUBSCRIPTION (the node's own
    // trust edge) is what `subscribe` adds, so the two are testable apart.
    let conferral = put_delegation(
        &engine,
        ROOT,
        &node_key,
        TRUST_CONFERS_DIMENSION,
        Some(&root),
    )
    .await;
    let owner_token = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _handle) = serve(Arc::clone(&engine)).await;
    Fixture {
        engine,
        base,
        owner_token,
        node_key,
        conferral,
        _handle,
    }
}

/// Add the node's own `trust:accepts:v1` edge — the subscription.
async fn subscribe(f: &Fixture) {
    put_delegation(&f.engine, &f.node_key, ROOT, TRUST_ACCEPTS_DIMENSION, None).await;
}

async fn fixture() -> Fixture {
    let f = bare_fixture().await;
    subscribe(&f).await;
    f
}

// ─── HTTP helpers ───────────────────────────────────────────────────────────

async fn get(f: &Fixture, path: &str) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = reqwest::Client::new()
        .get(format!("{}{path}", f.base))
        .bearer_auth(&f.owner_token)
        .send()
        .await
        .expect("GET");
    let status = resp.status();
    (status, resp.json().await.unwrap_or(serde_json::Value::Null))
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
    (status, resp.json().await.unwrap_or(serde_json::Value::Null))
}

/// A relief body. `key` is spelled from persist's registry, never a literal.
fn relief_body(f: &Fixture, value: i64, ttl_hours: i64) -> serde_json::Value {
    serde_json::json!({
        "key": knob().wire_name(),
        "value": value,
        "root_ref": ROOT,
        "delegation_id": f.conferral,
        "grounds": "mesh congestion incident 4711",
        "ttl_hours": ttl_hours,
    })
}

fn durable_body(f: &Fixture, value: i64) -> serde_json::Value {
    serde_json::json!({
        "key": knob().wire_name(),
        "value": value,
        "root_ref": ROOT,
        "delegation_id": f.conferral,
        "grounds": "ratified at the winter meeting",
    })
}

/// The module's source with every comment removed — so a scan never trips on
/// prose that legitimately names what the code must not spell.
fn module_code() -> String {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/mesh_config_surface.rs"
    ))
    .expect("read src/mesh_config_surface.rs");
    src.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every maximal run of ASCII digits in `code`, as the integers they spell.
fn numeric_literals(code: &str) -> Vec<i64> {
    let mut out = Vec::new();
    let mut run = String::new();
    for c in code.chars() {
        if c.is_ascii_digit() {
            run.push(c);
        } else {
            if let Ok(n) = run.parse::<i64>() {
                out.push(n);
            }
            run.clear();
        }
    }
    if let Ok(n) = run.parse::<i64>() {
        out.push(n);
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════
//  PROPERTY 1 — the key registry is persist's, and is never restated here
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn property_1_the_served_registry_is_persists_own_closed_set() {
    let f = fixture().await;
    let (status, body) = get(&f, ROUTE_READ).await;
    assert_eq!(status, 200, "read surface must succeed: {body}");

    let served = body["registry"].as_array().expect("registry array");
    assert_eq!(
        served.len(),
        MeshConfigKey::ALL.len(),
        "the served registry must be persist's closed set, not a subset or a superset"
    );
    for (v, k) in served.iter().zip(MeshConfigKey::ALL.iter()) {
        let spec = k.spec();
        assert_eq!(v["key"], serde_json::json!(spec.wire_name));
        assert_eq!(v["polarity"], serde_json::json!(spec.polarity.as_str()));
        assert_eq!(v["unit"], serde_json::json!(spec.unit.as_str()));
        assert_eq!(v["min"], serde_json::json!(spec.min));
        assert_eq!(v["max"], serde_json::json!(spec.max));
        assert_eq!(v["owner_default"], serde_json::json!(spec.owner_default));
        assert_eq!(v["consumer"], serde_json::json!(spec.consumer));
        assert_eq!(v["knob"], serde_json::json!(spec.knob));
    }
    // Every key is always reported — an absent key is how a knob silently keeps
    // a stale value.
    let settings = body["settings"].as_array().expect("settings array");
    assert_eq!(settings.len(), MeshConfigKey::ALL.len());
}

#[tokio::test]
async fn property_1_an_unregistered_key_is_refused_by_persists_own_deserializer() {
    let f = fixture().await;
    let mut body = relief_body(&f, restricting(), 1);
    body["key"] = serde_json::json!("totally.made.up");
    let (status, resp) = post(&f, ROUTE_RELIEF, &body).await;
    assert_eq!(status, 400, "an unregistered key must not reach the door");
    assert_eq!(resp["refusal"], serde_json::json!("bad_request"));
    let text = resp["message"]["text"].as_str().expect("text");
    assert!(
        text.contains("registered mesh_config key"),
        "the closed-registry sentence must be persist's own, not one written here: {text}"
    );
}

#[test]
fn property_1_the_module_spells_no_key_name_prefix_or_family_of_its_own() {
    let code = module_code();
    for &k in MeshConfigKey::ALL {
        assert!(
            !code.contains(k.wire_name()),
            "src/mesh_config_surface.rs spells the wire key {:?} in CODE. The registry is \
             persist's closed set and must be READ from `MeshConfigKey::ALL` / `spec()` — a \
             hand-copied key list is the hand-mirrored-vocabulary defect \
             tests/envelope_vocabulary_single_source.rs exists for.",
            k.wire_name()
        );
        assert!(
            !code.contains(&k.dimension()),
            "src/mesh_config_surface.rs spells the dimension {:?} in CODE",
            k.dimension()
        );
    }
    // A STRING LITERAL opening with the prefix — the `ciris_persist::…::mesh_config::`
    // import path shares the substring and is exactly what this scan wants to allow.
    assert!(
        !code.contains(&format!("\"{DIMENSION_PREFIX}")),
        "src/mesh_config_surface.rs spells the dimension prefix {DIMENSION_PREFIX:?} as a \
         literal instead of importing it"
    );
    assert!(
        !code.contains(&format!("\"{NAMESPACE_FAMILY}\"")),
        "src/mesh_config_surface.rs spells the namespace family {NAMESPACE_FAMILY:?} as a \
         literal instead of importing it"
    );
    // The envelope field NAMES are persist's too (SRV-1/#322). Only the
    // spellings that can ONLY be an envelope field are forbidden outright:
    // `root_ref` and `ratifies_row_id` are also this surface's OWN request and
    // response keys, deliberately spelled the same as `RootValue::root_ref` and
    // persist's own field so a UI joins the halves on one name — banning the
    // string would ban the wire shape. The positive checks below are what hold
    // the envelope READS to persist's constants.
    for envelope_field in ["mesh_config_key", "valid_until"] {
        assert!(
            !code.contains(&format!("\"{envelope_field}\"")),
            "src/mesh_config_surface.rs spells the envelope field {envelope_field:?} as a \
             literal; use `mesh_config::field::*`"
        );
    }
    // …and the envelope READS go through persist's module, positively.
    for accessor in [
        "field::VALUE",
        "field::ROOT_REF",
        "field::FORM",
        "field::DELEGATION_ID",
        "field::RATIFIES",
        "field::GROUNDS",
        "field::VALID_UNTIL",
    ] {
        assert!(
            code.contains(accessor),
            "src/mesh_config_surface.rs must read the envelope through {accessor}, so a rename \
             upstream breaks the build instead of silently skewing the projection"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  PROPERTY 2 — the durability rule is the substrate's, rendered not decided
// ═══════════════════════════════════════════════════════════════════════════

/// The route reports what `Engine::record_mesh_config_row` reports for the same
/// act — compared against **persist**, never against a token written here.
///
/// This is the whole property: persist v29.0.0 reversed v28.3.0 on which acts
/// earn durability and CIRISConstitution#86 may reverse it again. When it does,
/// this test still passes and `src/mesh_config_surface.rs` still does not
/// change, because neither of them encodes the rule.
#[tokio::test]
async fn property_2_a_cold_durable_row_renders_the_substrates_own_ruling() {
    let f = fixture().await;
    let (_, resp) = post(&f, ROUTE_DURABLE, &durable_body(&f, restricting())).await;

    // Ask the substrate the same question directly, over an equivalent row.
    let now = chrono::Utc::now();
    let envelope = mesh_config_envelope(
        knob(),
        restricting(),
        ROOT,
        MeshConfigForm::Durable,
        None,
        &f.conferral,
        None,
        "ratified at the winter meeting",
    );
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize");
    let sig = f.engine.sign_hybrid(&canonical).await.expect("sign");
    let probe = Attestation {
        attestation_id: "probe-cold-durable".into(),
        attesting_key_id: f.node_key.clone(),
        attested_key_id: ROOT.into(),
        attestation_type: attestation_type::SCORES.to_string(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: BASE64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        scrub_key_id: f.node_key.clone(),
        additional_scrubs: Vec::new(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
    };
    let substrate = f
        .engine
        .record_mesh_config_row(
            &f.node_key,
            &MeshConfigBaseline::owner_defaults(),
            &probe,
            now,
        )
        .await
        .expect("substrate judges the probe");

    match substrate.refusal() {
        Some(reason) => assert_eq!(
            resp["refusal"],
            serde_json::json!(reason.as_str()),
            "the route must render the substrate's own token, whatever it is: {resp}"
        ),
        None => assert_eq!(
            resp["admitted"],
            serde_json::json!(true),
            "the substrate admitted the same act; the route must not refuse it: {resp}"
        ),
    }
    // Whatever the ruling, the route names WHO ruled — not a rule of its own.
    let (_, read) = get(&f, ROUTE_READ).await;
    let durability = read["durability"]["text"].as_str().expect("text");
    assert!(
        durability.contains("substrate"),
        "the surface must say the ruling is the substrate's: {durability}"
    );
}

#[test]
fn property_2_the_module_encodes_no_durability_predicate() {
    let code = module_code().to_lowercase();
    assert!(
        !code.contains("quorum"),
        "src/mesh_config_surface.rs names a quorum in CODE. Which acts earn durability is \
         persist's ruling (v29.0.0 reversed v28.3.0; CIRISConstitution#86 is open), and a copy \
         of it here is a second rule that will be wrong the moment CC rules."
    );
    for token in [
        MeshConfigRefusalReason::DurableWithoutRootQuorum.as_str(),
        MeshConfigRefusalReason::DurableUnratified.as_str(),
        MeshConfigRefusalReason::ExpandsBeyondConsent.as_str(),
        MeshConfigRefusalReason::TtlTooLong.as_str(),
    ] {
        assert!(
            !code.contains(token),
            "src/mesh_config_surface.rs spells the refusal token {token:?} in CODE. Every token \
             on the wire must come from `MeshConfigRefusalReason::as_str`, so the vocabulary \
             cannot drift from persist's."
        );
    }
    assert!(
        !code.contains("additional_scrubs.len"),
        "src/mesh_config_surface.rs counts scrubs. Counting co-signatures IS the durability \
         predicate; the substrate owns it."
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  PROPERTY 3 — EMERGENCY_MAX_TTL_HOURS is read, never written down
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn property_3_the_served_ttl_bound_is_persists_constant() {
    let f = fixture().await;
    let (_, body) = get(&f, ROUTE_READ).await;
    assert_eq!(
        body["emergency"]["max_ttl_hours"],
        serde_json::json!(EMERGENCY_MAX_TTL_HOURS),
        "the surfaced bound must BE persist's constant"
    );
}

#[tokio::test]
async fn property_3_an_over_long_window_is_refused_by_the_substrate_not_by_this_node() {
    let f = fixture().await;
    let (status, resp) = post(
        &f,
        ROUTE_RELIEF,
        &relief_body(&f, restricting(), EMERGENCY_MAX_TTL_HOURS * 10),
    )
    .await;
    assert_eq!(
        status, 409,
        "an over-long window is a substrate refusal: {resp}"
    );
    assert_eq!(
        resp["refusal"],
        serde_json::json!(MeshConfigRefusalReason::TtlTooLong.as_str()),
        "the refusal must be persist's own token, not one minted here: {resp}"
    );
    // …and a window INSIDE the bound is admitted, so the refusal above is the
    // bound biting rather than the path being broken.
    let (ok_status, ok) = post(&f, ROUTE_RELIEF, &relief_body(&f, restricting(), 1)).await;
    assert_eq!(ok_status, 200, "a bounded relief must be admitted: {ok}");
    assert_eq!(ok["admitted"], serde_json::json!(true));
}

#[test]
fn property_3_the_module_writes_the_ttl_bound_down_nowhere() {
    let code = module_code();
    assert!(
        !numeric_literals(&code).contains(&EMERGENCY_MAX_TTL_HOURS),
        "src/mesh_config_surface.rs contains the numeric literal {EMERGENCY_MAX_TTL_HOURS}. \
         EMERGENCY_MAX_TTL_HOURS is READ from persist and never written down — a copy is a \
         second bound that stops agreeing the day CC changes the first."
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  PROPERTY 4 — distinct zeroes
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn property_4_every_standing_token_is_distinct_within_its_closed_set() {
    for (n, tokens) in [
        (
            PlaneStanding::ALL.len(),
            PlaneStanding::ALL
                .iter()
                .map(|s| s.as_str())
                .collect::<BTreeSet<_>>(),
        ),
        (
            HistoryStanding::ALL.len(),
            HistoryStanding::ALL
                .iter()
                .map(|s| s.as_str())
                .collect::<BTreeSet<_>>(),
        ),
        (
            ValueProvenance::ALL.len(),
            ValueProvenance::ALL
                .iter()
                .map(|s| s.as_str())
                .collect::<BTreeSet<_>>(),
        ),
    ] {
        assert_eq!(tokens.len(), n, "two standings share a token");
    }
    // THE two collapses this surface exists to prevent, named.
    assert_ne!(
        PlaneStanding::Unreadable.as_str(),
        PlaneStanding::NoRowsHeld.as_str(),
        "'could not read the plane' and 'no mesh-config set' must not render the same"
    );
    assert_ne!(
        HistoryStanding::Unreadable.as_str(),
        HistoryStanding::Empty.as_str(),
        "'history unavailable' and 'no history' must not render the same"
    );
    assert_ne!(
        HistoryStanding::Partial.as_str(),
        HistoryStanding::Present.as_str(),
        "a history missing some roots is not a complete one"
    );
}

#[tokio::test]
async fn property_4_each_live_zero_arm_names_its_own_cause() {
    // (a) owned, sessioned, and subscribed to NO root: the plane is readable
    //     and there is nobody who could ever speak.
    let bare = bare_fixture().await;
    let (_, v) = get(&bare, ROUTE_READ).await;
    assert_eq!(
        v["standing"],
        serde_json::json!(PlaneStanding::NoSubscription.as_str())
    );
    let (_, h) = get(&bare, ROUTE_HISTORY).await;
    assert_eq!(
        h["standing"],
        serde_json::json!(HistoryStanding::NoSubscription.as_str())
    );
    // Nine settings, all at the owner's baseline — but NOT rendered as an
    // unreadable plane.
    assert_eq!(
        v["settings"].as_array().expect("settings").len(),
        MeshConfigKey::ALL.len()
    );
    assert_ne!(
        v["standing"],
        serde_json::json!(PlaneStanding::Unreadable.as_str())
    );

    // (b) subscribed, no row held.
    subscribe(&bare).await;
    let (_, v) = get(&bare, ROUTE_READ).await;
    assert_eq!(
        v["standing"],
        serde_json::json!(PlaneStanding::NoRowsHeld.as_str())
    );
    let (_, h) = get(&bare, ROUTE_HISTORY).await;
    assert_eq!(
        h["standing"],
        serde_json::json!(HistoryStanding::Empty.as_str())
    );
    assert_eq!(h["total"], serde_json::json!(0));
    for s in v["settings"].as_array().expect("settings") {
        assert_eq!(
            s["provenance"]["source"],
            serde_json::json!(ValueProvenance::BaselineUnspoken.as_str())
        );
    }

    // (c) a row is held and it binds.
    let (status, resp) = post(&bare, ROUTE_RELIEF, &relief_body(&bare, restricting(), 6)).await;
    assert_eq!(status, 200, "relief must be admitted: {resp}");
    let (_, v) = get(&bare, ROUTE_READ).await;
    assert_eq!(
        v["standing"],
        serde_json::json!(PlaneStanding::Configured.as_str())
    );
    let (_, h) = get(&bare, ROUTE_HISTORY).await;
    assert_eq!(
        h["standing"],
        serde_json::json!(HistoryStanding::Present.as_str())
    );
    assert_eq!(h["total"], serde_json::json!(1));
}

// ═══════════════════════════════════════════════════════════════════════════
//  PROPERTY 5 — every operator string is an {id, text} pair
// ═══════════════════════════════════════════════════════════════════════════

/// Recursively assert that every message-position value is a localizable pair.
fn assert_localizable(v: &serde_json::Value, path: &str) {
    match v {
        serde_json::Value::Object(o) => {
            for (k, child) in o {
                let here = format!("{path}.{k}");
                if k == "message" || k.ends_with("_message") || k == "note" || k == "durability" {
                    let pair = child.as_object().unwrap_or_else(|| {
                        panic!("{here} must be an {{id, text}} object: {child}")
                    });
                    let id = pair
                        .get("id")
                        .and_then(|x| x.as_str())
                        .unwrap_or_else(|| panic!("{here} carries no string `id`: {child}"));
                    let text = pair
                        .get("text")
                        .and_then(|x| x.as_str())
                        .unwrap_or_else(|| panic!("{here} carries no string `text`: {child}"));
                    assert!(
                        id.contains('.') && !id.contains(' '),
                        "{here} id {id:?} is not a stable message key"
                    );
                    assert!(!text.is_empty(), "{here} text is empty");
                    assert_eq!(
                        pair.len(),
                        2,
                        "{here} must be exactly {{id, text}}, got {child}"
                    );
                } else {
                    assert_localizable(child, &here);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                assert_localizable(child, &format!("{path}[{i}]"));
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn property_5_every_operator_string_is_a_localizable_pair() {
    let f = fixture().await;
    let (_, admitted) = post(&f, ROUTE_RELIEF, &relief_body(&f, restricting(), 6)).await;
    let (_, read) = get(&f, ROUTE_READ).await;
    let (_, history) = get(&f, ROUTE_HISTORY).await;
    let (_, refused) = post(
        &f,
        ROUTE_RELIEF,
        &relief_body(&f, restricting(), EMERGENCY_MAX_TTL_HOURS * 10),
    )
    .await;
    for (name, body) in [
        ("read", &read),
        ("history", &history),
        ("admitted", &admitted),
        ("refused", &refused),
    ] {
        assert_localizable(body, name);
        assert_eq!(
            body["source_locale"],
            serde_json::json!("en"),
            "{name} must declare the locale its `text` fallbacks are written in"
        );
    }
    // A refusal carries a stable token to branch on AND a pair to render.
    assert!(refused["refusal"].is_string());
    // And a TTL is a COUNTDOWN plus a message id, never a rendered sentence.
    let ttl = &read["settings"]
        .as_array()
        .expect("settings")
        .iter()
        .find(|s| s["relieved"] == serde_json::json!(true))
        .expect("one relieved setting")["ttl"];
    assert!(
        ttl["remaining_seconds"].as_i64().expect("remaining") > 0,
        "the countdown is data: {ttl}"
    );
    let text = ttl["message"]["text"].as_str().expect("ttl text");
    assert!(
        !text.chars().any(|c| c.is_ascii_digit()),
        "a TTL message must not render the countdown into a sentence: {text}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  The surface itself — provenance, history, the baseline, the refusals
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn the_read_surface_names_which_action_set_each_value() {
    let f = fixture().await;
    let (status, admitted) = post(&f, ROUTE_RELIEF, &relief_body(&f, restricting(), 6)).await;
    assert_eq!(status, 200, "relief must be admitted: {admitted}");
    let row_id = admitted["attestation_id"].as_str().expect("row id");

    let (_, read) = get(&f, ROUTE_READ).await;
    let setting = read["settings"]
        .as_array()
        .expect("settings")
        .iter()
        .find(|s| s["key"] == serde_json::json!(knob().wire_name()))
        .expect("the knob is always reported");

    assert_eq!(setting["effective"], serde_json::json!(restricting()));
    assert_eq!(
        setting["baseline"],
        serde_json::json!(knob().owner_default())
    );
    assert_eq!(setting["relieved"], serde_json::json!(true));
    let p = &setting["provenance"];
    assert_eq!(
        p["source"],
        serde_json::json!(ValueProvenance::Root.as_str())
    );
    assert_eq!(p["decided_by_root"], serde_json::json!(ROOT));
    assert_eq!(p["row_id"], serde_json::json!(row_id));
    assert_eq!(p["decided_by"], serde_json::json!(f.node_key));
    assert_eq!(p["delegation_id"], serde_json::json!(f.conferral));
    assert_eq!(
        p["form"],
        serde_json::json!(MeshConfigForm::Emergency.as_str())
    );
    assert_eq!(
        p["grounds"],
        serde_json::json!("mesh congestion incident 4711")
    );
    // Every other key still reports, unspoken.
    let unspoken = read["settings"]
        .as_array()
        .expect("settings")
        .iter()
        .filter(|s| s["provenance"]["source"] == serde_json::json!("baseline_unspoken"))
        .count();
    assert_eq!(unspoken, MeshConfigKey::ALL.len() - 1);

    // The history names the same row and marks it counted AND binding.
    let (_, history) = get(&f, ROUTE_HISTORY).await;
    let hrow = history["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|r| r["attestation_id"] == serde_json::json!(row_id))
        .expect("the admitted row is in the history");
    // Two different facts, both READ off persist's fold: this row is the one
    // its root's answer came from, AND the one that won across roots.
    assert_eq!(hrow["counted"], serde_json::json!(true));
    assert_eq!(hrow["binding"], serde_json::json!(true));
    assert_eq!(hrow["root_ref"], serde_json::json!(ROOT));
    assert_eq!(hrow["value"], serde_json::json!(restricting()));
    assert_eq!(hrow["delegation_id"], serde_json::json!(f.conferral));
    assert_eq!(hrow["ttl"]["bounded"], serde_json::json!(true));
    assert_eq!(hrow["ttl"]["expired"], serde_json::json!(false));
}

#[tokio::test]
async fn the_baseline_is_the_nodes_own_self_config_and_bounds_what_a_root_may_ask() {
    let f = fixture().await;
    // The owner tightens their OWN node below the registry default. The
    // config key is derived from persist's wire name, never spelled here.
    let tighter = knob().owner_default() * 2;
    ciris_server::graph_config::set_config(
        &f.engine,
        &format!("{BASELINE_CONFIG_PREFIX}{}", knob().wire_name()),
        ConfigValue::I64(tighter),
        OWNER_USER,
        ConfigScope::Local,
    )
    .await
    .expect("pin the baseline");

    let (_, read) = get(&f, ROUTE_READ).await;
    let setting = read["settings"]
        .as_array()
        .expect("settings")
        .iter()
        .find(|s| s["key"] == serde_json::json!(knob().wire_name()))
        .expect("knob");
    assert_eq!(
        setting["baseline"],
        serde_json::json!(tighter),
        "the owner's own pin is the ceiling, not the registry default"
    );
    assert_eq!(setting["effective"], serde_json::json!(tighter));

    // A root asking for the REGISTRY default now expands past the owner's own
    // consent — and the substrate, not this node, says so.
    let (status, resp) = post(
        &f,
        ROUTE_RELIEF,
        &relief_body(&f, knob().owner_default(), 6),
    )
    .await;
    assert_eq!(status, 409, "{resp}");
    assert_eq!(
        resp["refusal"],
        serde_json::json!(MeshConfigRefusalReason::ExpandsBeyondConsent.as_str())
    );
}

#[tokio::test]
async fn an_expanding_value_is_refused_and_an_unsubscribed_root_is_refused() {
    let f = fixture().await;
    let (status, resp) = post(&f, ROUTE_RELIEF, &relief_body(&f, expanding(), 6)).await;
    assert_eq!(status, 409, "{resp}");
    assert_eq!(
        resp["refusal"],
        serde_json::json!(MeshConfigRefusalReason::ExpandsBeyondConsent.as_str()),
        "relieve-never-expand is the substrate's gate: {resp}"
    );

    let mut stranger = relief_body(&f, restricting(), 6);
    stranger["root_ref"] = serde_json::json!(STRANGER);
    let (status, resp) = post(&f, ROUTE_RELIEF, &stranger).await;
    assert_eq!(status, 409, "{resp}");
    assert_eq!(
        resp["refusal"],
        serde_json::json!(MeshConfigRefusalReason::RootNotTrusted.as_str()),
        "the subscription IS the trust edge: {resp}"
    );
}

#[tokio::test]
async fn an_act_that_names_no_resolvable_authority_is_refused_before_anything_is_signed() {
    let f = fixture().await;
    for (field, value, expect) in [
        (
            "delegation_id",
            serde_json::json!("   "),
            "attribution_absent",
        ),
        ("grounds", serde_json::json!(""), "attribution_absent"),
        ("root_ref", serde_json::json!(" "), "root_absent"),
        (
            "delegation_id",
            serde_json::json!("no-such-row"),
            "authority_unresolved",
        ),
    ] {
        let mut body = relief_body(&f, restricting(), 6);
        body[field] = value.clone();
        let (_, resp) = post(&f, ROUTE_RELIEF, &body).await;
        assert_eq!(
            resp["refusal"],
            serde_json::json!(expect),
            "{field}={value} must refuse as {expect}: {resp}"
        );
    }
    // Nothing was written by any of those.
    let (_, history) = get(&f, ROUTE_HISTORY).await;
    assert_eq!(history["total"], serde_json::json!(0));
}

#[tokio::test]
async fn the_dry_run_hands_a_cosigner_the_exact_bytes_without_writing_anything() {
    let f = fixture().await;
    let mut body = durable_body(&f, restricting());
    body["dry_run"] = serde_json::json!(true);
    let (status, resp) = post(&f, ROUTE_DURABLE, &body).await;
    assert_eq!(status, 200, "{resp}");
    assert_eq!(resp["dry_run"], serde_json::json!(true));

    // The envelope is persist's own builder's output, byte for byte.
    let expected = mesh_config_envelope(
        knob(),
        restricting(),
        ROOT,
        MeshConfigForm::Durable,
        None,
        &f.conferral,
        None,
        "ratified at the winter meeting",
    );
    assert_eq!(resp["envelope"], expected);
    let canonical = ceg_produce_canonicalize(&expected).expect("canonicalize");
    assert_eq!(
        resp["payload_sha256"],
        serde_json::json!(hex::encode(Sha256::digest(&canonical)))
    );
    // …and nothing was stored.
    let (_, history) = get(&f, ROUTE_HISTORY).await;
    assert_eq!(history["total"], serde_json::json!(0));
}

#[tokio::test]
async fn the_surface_is_owner_gated_on_the_federation_admin_spine() {
    let f = fixture().await;
    let client = reqwest::Client::new();
    for path in [ROUTE_READ, ROUTE_HISTORY] {
        let resp = client
            .get(format!("{}{path}", f.base))
            .send()
            .await
            .expect("GET");
        assert_eq!(
            resp.status(),
            401,
            "{path} must refuse an unauthenticated read"
        );
    }
    for path in [ROUTE_DURABLE, ROUTE_RELIEF] {
        let resp = client
            .post(format!("{}{path}", f.base))
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("POST");
        assert_eq!(
            resp.status(),
            401,
            "{path} must refuse an unauthenticated write"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  PROPERTY 6 — the surface says whether anything READS the value it prints
// ═══════════════════════════════════════════════════════════════════════════
//
// CIRISServer#365. The plane was operable and NOT effective: nine keys, and
// this repo had a caller for none, so an operator could file a relief, watch it
// admit, watch it fold, watch its TTL count down — and nothing changed. Every
// signal said the setting took effect.
//
// An unbuilt plane refuses. A plane with no consumer CONFIRMS. `effective: 10`
// alone is a false statement about such a key; `effective: 10, consumed: false`
// is a true one.

#[tokio::test]
async fn property_6_every_key_says_whether_this_build_consumes_it() {
    use ciris_server::mesh_config_effect::{consumption, Consumption};

    let f = fixture().await;
    let (status, body) = get(&f, ROUTE_READ).await;
    assert_eq!(status, 200, "read surface must succeed: {body}");

    // ── The registry half. Every key, every time. ───────────────────────────
    let served = body["registry"].as_array().expect("registry array");
    assert_eq!(served.len(), MeshConfigKey::ALL.len());
    for (v, k) in served.iter().zip(MeshConfigKey::ALL.iter()) {
        let c = consumption(*k);
        assert_eq!(
            v["consumed"],
            serde_json::json!(c.consumed()),
            "{} must carry the consumption flag",
            k.wire_name()
        );
        assert_eq!(v["consumption"]["state"], serde_json::json!(c.as_str()));
        // Localizable {id, text}, like every other string on this surface.
        assert!(v["consumption"]["message"]["id"].is_string(), "{v}");
        assert!(v["consumption"]["message"]["text"].is_string(), "{v}");
        // "no consumer here" without saying WHERE sends an operator hunting in
        // the wrong repo.
        match c {
            Consumption::Wired { .. } => {
                assert!(v["consumption"]["site"].is_string(), "{v}");
                assert!(v["consumption"]["effect"].is_string(), "{v}");
            }
            Consumption::Elsewhere { .. } => {
                assert!(v["consumption"]["owner"].is_string(), "{v}");
                assert!(v["consumption"]["tracked_by"].is_string(), "{v}");
            }
            Consumption::Unbuilt { .. } => {
                assert!(v["consumption"]["tracked_by"].is_string(), "{v}");
            }
        }
    }

    // ── The settings half — where `effective` actually appears. ─────────────
    // This is the field that made the false statement, so this is the one that
    // must never be printed alone.
    let settings = body["settings"].as_array().expect("settings array");
    assert_eq!(settings.len(), MeshConfigKey::ALL.len());
    for s in settings {
        assert!(
            s["effective"].is_i64(),
            "every setting reports an effective value: {s}"
        );
        assert!(
            s["consumed"].is_boolean(),
            "a setting that prints `effective` MUST print `consumed` beside it — that pairing \
             is the whole of CIRISServer#365's honest interim: {s}"
        );
        let key = MeshConfigKey::from_wire(s["key"].as_str().expect("key")).expect("registered");
        assert_eq!(
            s["consumed"],
            serde_json::json!(consumption(key).consumed()),
            "the flag must be the effect registry's answer, never a second opinion: {s}"
        );
    }

    // ── At least one of each, so neither arm is vacuous. ────────────────────
    let consumed: Vec<&str> = MeshConfigKey::ALL
        .iter()
        .filter(|k| consumption(**k).consumed())
        .map(|k| k.wire_name())
        .collect();
    assert!(
        !consumed.is_empty(),
        "landing #365 means at least one key is genuinely consumed"
    );
    assert!(
        consumed.len() < MeshConfigKey::ALL.len(),
        "if every key were consumed the false-statement arm would go untested"
    );
}

#[tokio::test]
async fn property_6_a_relieved_value_still_admits_and_still_says_who_reads_it() {
    // The exact scenario #365 opens with, end to end: a root files a relief, the
    // substrate admits it, the fold binds it — and the surface now also says
    // whether anything on this node will act on it.
    let f = fixture().await;
    let (status, body) = post(&f, ROUTE_RELIEF, &relief_body(&f, restricting(), 4)).await;
    assert_eq!(status, 200, "the relief must admit: {body}");
    assert_eq!(body["admitted"], serde_json::json!(true), "{body}");

    let (_, read) = get(&f, ROUTE_READ).await;
    let s = read["settings"]
        .as_array()
        .expect("settings")
        .iter()
        .find(|s| s["key"] == serde_json::json!(knob().wire_name()))
        .expect("the relieved key");
    assert_eq!(s["effective"], serde_json::json!(restricting()), "{s}");
    assert_eq!(s["relieved"], serde_json::json!(true), "{s}");
    // `antientropy.round_secs` is edge's consumer, so this node reports the
    // relief as REAL and NOT acted on here — which is the true statement, and
    // the one the tab could not make before.
    assert_eq!(s["consumed"], serde_json::json!(false), "{s}");
    assert_eq!(
        s["consumption"]["state"],
        serde_json::json!("elsewhere"),
        "{s}"
    );
    assert_eq!(
        s["consumption"]["owner"],
        serde_json::json!("CIRISEdge"),
        "{s}"
    );
}
