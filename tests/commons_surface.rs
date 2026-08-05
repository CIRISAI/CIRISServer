//! **The commons surface** (CIRISServer#367) — one test per non-negotiable
//! property of the reverse-quorum brake, driven over the real router and the
//! real persist substrate.
//!
//! 1. **One objection raises the brake** — `property_1_*`: a single member's
//!    objection, posted through `POST /v1/commons/objections`, is admitted with
//!    no co-signature and flips `GET /v1/commons/standing` to `reversed` on a
//!    cohort that declared `reverse_quorum:1/5`. Protection is unilateral.
//! 2. **m-of-n dismisses; below-m does NOT** — `property_2_*`: the same
//!    dismissal, over the same canonical bytes, is refused at two verified
//!    roster co-signatures and admitted at three, with persist's own
//!    `{counted, required, roster_size}` on both arms. The threshold is
//!    persist's; a source scan proves this module's code contains no threshold
//!    arithmetic at all.
//! 3. **Silence is its own arm and escalation counts RESPONDENTS** —
//!    `property_3_*`: before the steward deadline the surface renders
//!    `awaiting`; after it, with no ruling, `silent` + escalation open; and
//!    three respondents resolve an escalated undo that costs five over the
//!    roster. A duty-holder who rules IN time keeps escalation shut, so
//!    "nobody answered" and "the answer was yes" never render alike.
//! 4. **The floor cannot be lowered by policy** — `property_4_*`: a cohort
//!    declaring a sub-floor `+escalate:…:1` is refused at persist's own
//!    `put_community` door, and a cohort declaring the cheapest legal brake
//!    (`reverse_quorum:1/9`) still cannot buy an escalated undo below
//!    `ESCALATION_RESPONDENT_FLOOR` — two respondents do not resolve it, three
//!    do.
//! 5. **Distinct zeroes** — `property_5_*`: "no objection has been raised",
//!    "we could not read the objections", "this community has no reverse-quorum
//!    policy", "there is no such action" and "there is no such cohort" carry
//!    five different tokens, and the unknown arms carry NO counts.
//!
//! # How the other members speak
//!
//! This node signs with ONE key, so every row the surface mints is that
//! member's voice. Peers' objections and ballots are admitted through persist's
//! own doors with genuinely party-signed rows — which is exactly how they would
//! arrive over replication — and co-signatures on a dismissal ride the route's
//! `additional_scrubs` after `dry_run` hands the co-signers the canonical
//! bytes. Nothing here is stubbed: every signature is a real hybrid signature
//! re-verified by persist against pubkeys registered on this node.

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::reverse_quorum::{
    ballot_envelope, objection_envelope, record_objection, record_objection_ballot,
    ESCALATION_RESPONDENT_FLOOR, OBJECTION_THRESHOLD,
};
use ciris_persist::federation::types::{
    algorithm, attestation_tier, attestation_type, cohort_scope, identity_type, Attestation,
    Community, CommunityMember, KeyRecord, ScrubSig, SignedAttestation, SignedCommunity,
    SignedKeyRecord,
};
use ciris_persist::federation::Cohort;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};

use ciris_server::auth::store;
use ciris_server::commons_surface::{
    self, CommonsStanding, EscalationStanding, ROUTE_BALLOT, ROUTE_DISMISS, ROUTE_OBJECT,
    ROUTE_STANDING,
};

const NODE_ALIAS: &str = "ciris-commons-node";
const OWNER_USER: &str = "ciris-commons-owner";

/// The five-member cohort: `reverse_quorum:1/5` — ONE objection reverses, and a
/// dismissal costs a strict majority of five.
const COMMUNITY_A: &str = "cm-a";
const PROTOCOL_A: &str = "reverse_quorum:1/5:3600";

/// The nine-member cohort WITH a steward tier — the escalation-on-silence case.
const COMMUNITY_B: &str = "cm-b";
const PROTOCOL_B: &str = "reverse_quorum:2/9:3600+escalate:1800:3";

/// The same nine-member roster declaring the CHEAPEST legal brake. Its
/// escalated undo is still floored at [`ESCALATION_RESPONDENT_FLOOR`].
const COMMUNITY_C: &str = "cm-c";
const PROTOCOL_C: &str = "reverse_quorum:1/9:3600+escalate:1800:3";

/// The declaration that tries to talk the floor down. persist refuses it at
/// `put_community`, so a cohort configured below the floor cannot exist.
const PROTOCOL_SUB_FLOOR: &str = "reverse_quorum:2/9:3600+escalate:1800:1";

/// The commons action's window, in seconds — `PROTOCOL_*`'s `{window}`.
const WINDOW_SECS: i64 = 3600;
/// The steward tier's own window — `PROTOCOL_B`/`PROTOCOL_C`'s `{steward_secs}`.
const STEWARD_SECS: i64 = 1800;

// ─── substrate + identity helpers (mirror tests/mesh_config_surface.rs) ─────

async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xD1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xD2; 32], format!("{NODE_ALIAS}-pqc"))
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
    let now = Utc::now();
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
    let now = Utc::now();
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
        .map(std::string::ToString::to_string)
        .collect();
    let nk = node_key_id(engine).await;
    ciris_server::auth::ownership::emit_steward_binding(engine, &owner, &nk, &scopes)
        .await
        .expect("emit owner-binding");
}

async fn mint_session(engine: &Engine, wa_id: &str, role: WaRole) -> String {
    let now = Utc::now();
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

/// Declare a community with an explicit `consensus_protocol` and roster.
/// Returns persist's own error kind on refusal, so the sub-floor case can be
/// asserted rather than merely observed to fail.
async fn try_put_community(
    engine: &Engine,
    community_id: &str,
    protocol: &str,
    members: &[(&str, &str)],
) -> Result<(), String> {
    let authority = register_party(engine, community_id, "community").await;
    let now = Utc::now();
    let roster: Vec<CommunityMember> = members
        .iter()
        .enumerate()
        .map(|(i, (k, role))| CommunityMember {
            key_id: (*k).to_string(),
            joined_at: now + Duration::seconds(i64::try_from(i).unwrap_or(0)),
            role: Some((*role).to_string()),
        })
        .collect();
    let community = Community {
        community_key_id: community_id.to_string(),
        community_name: format!("test-{community_id}"),
        members: roster,
        founded_at: now,
        consensus_protocol: protocol.to_string(),
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
        .map_err(|e| e.kind().to_string())
}

async fn put_community(engine: &Engine, id: &str, protocol: &str, members: &[(&str, &str)]) {
    try_put_community(engine, id, protocol, members)
        .await
        .unwrap_or_else(|k| panic!("put_community({id}, {protocol}) refused: {k}"));
}

/// A genuinely party-signed `scores` row — the commons ACTION an objection
/// names. Authored by `author`, asserted at `asserted_at`.
async fn emit_action(
    engine: &Engine,
    author: &LocalSigner,
    id: &str,
    asserted_at: DateTime<Utc>,
) -> Attestation {
    let key_id = author.key_id().to_string();
    let envelope = serde_json::json!({
        "dimension": "health:liveness:v1",
        "score": 1.0,
        "confidence": 1.0,
        "epistemic_mode": "direct",
        "witness_relation": "external",
        "stake": "reputational",
        "attested_key_id": key_id,
        "nonce": id,
    });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize action envelope");
    let sig = author.sign_hybrid(&canonical).await.expect("sign action");
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
        cohort_scope: cohort_scope::FEDERATION.to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
    };
    engine
        .federation_directory()
        .put_attestation(SignedAttestation {
            attestation: attestation.clone(),
        })
        .await
        .expect("put action");
    attestation
}

/// Sign one envelope as `signer` and wrap it as a row on this plane. Used for
/// the PEERS' rows — the ones that would arrive over replication — so their
/// signatures are genuine and persist re-verifies each against this node's
/// registered pubkeys.
async fn peer_row(
    signer: &LocalSigner,
    envelope: serde_json::Value,
    id: &str,
    actor: &str,
    asserted_at: DateTime<Utc>,
) -> Attestation {
    let key_id = signer.key_id().to_string();
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize peer row");
    let sig = signer.sign_hybrid(&canonical).await.expect("sign peer row");
    Attestation {
        attestation_id: id.to_string(),
        attesting_key_id: key_id.clone(),
        attested_key_id: actor.to_string(),
        attestation_type: attestation_type::SCORES.to_string(),
        weight: None,
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
        cohort_scope: cohort_scope::FEDERATION.to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
    }
}

/// A peer raises an objection through persist's own 1-of-N door.
async fn peer_objects(
    engine: &Engine,
    signer: &LocalSigner,
    community: &str,
    action: &Attestation,
    id: &str,
) -> String {
    let envelope = objection_envelope(
        Cohort::Community,
        community,
        &action.attestation_id,
        "a peer's grounds",
    );
    let row = peer_row(
        signer,
        envelope,
        id,
        &action.attesting_key_id,
        action.asserted_at + Duration::seconds(1),
    )
    .await;
    let dir = engine.federation_directory();
    let outcome = record_objection(&*dir, &row)
        .await
        .expect("record peer objection");
    assert_eq!(
        outcome.refusal(),
        None,
        "peer objection {id} must be admitted, got {:?}",
        outcome.refusal()
    );
    id.to_string()
}

/// A peer casts a ballot through persist's own door.
async fn peer_ballots(
    engine: &Engine,
    signer: &LocalSigner,
    community: &str,
    action: &Attestation,
    objection_id: &str,
    upholds: bool,
    id: &str,
) {
    let envelope = ballot_envelope(
        Cohort::Community,
        community,
        &action.attestation_id,
        objection_id,
        upholds,
        "a peer's ballot",
    );
    let row = peer_row(
        signer,
        envelope,
        id,
        &action.attesting_key_id,
        action.asserted_at + Duration::seconds(2),
    )
    .await;
    let dir = engine.federation_directory();
    let outcome = record_objection_ballot(&*dir, &row)
        .await
        .expect("record peer ballot");
    assert_eq!(
        outcome.refusal(),
        None,
        "peer ballot {id} must be admitted, got {:?}",
        outcome.refusal()
    );
}

async fn serve(engine: Arc<Engine>) -> (String, tokio::task::JoinHandle<()>) {
    let nk = node_key_id(&engine).await;
    let app = commons_surface::router(engine, nk);
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

/// Community A's roster, minus the node (added in `fixture`).
const A_MEMBERS: &[&str] = &["ca-founder", "ca-actor", "ca-p1", "ca-p2"];
/// The nine-member roster communities B and C share, minus the node.
const BC_MEMBERS: &[&str] = &[
    "cb-mod", "cb-actor", "cb-r1", "cb-r2", "cb-r3", "cb-x1", "cb-x2", "cb-x3",
];

struct Fixture {
    engine: Arc<Engine>,
    base: String,
    owner_token: String,
    _handle: tokio::task::JoinHandle<()>,
}

async fn fixture() -> Fixture {
    let engine = node().await;
    register_self(&engine).await;
    bind_owner(&engine).await;
    let node_key = node_key_id(&engine).await;

    for k in A_MEMBERS.iter().chain(BC_MEMBERS.iter()) {
        register_party(&engine, k, identity_type::USER).await;
    }

    // Community A — five members, `reverse_quorum:1/5`.
    let mut a: Vec<(&str, &str)> = vec![("ca-founder", "founder")];
    a.extend(A_MEMBERS[1..].iter().map(|k| (*k, "member")));
    a.push((node_key.as_str(), "member"));
    put_community(&engine, COMMUNITY_A, PROTOCOL_A, &a).await;

    // Communities B and C — the same nine-member roster, two declarations.
    let mut bc: Vec<(&str, &str)> = vec![("cb-mod", "founder")];
    bc.extend(BC_MEMBERS[1..].iter().map(|k| (*k, "member")));
    bc.push((node_key.as_str(), "member"));
    put_community(&engine, COMMUNITY_B, PROTOCOL_B, &bc).await;
    put_community(&engine, COMMUNITY_C, PROTOCOL_C, &bc).await;

    let owner_token = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _handle) = serve(Arc::clone(&engine)).await;
    Fixture {
        engine,
        base,
        owner_token,
        _handle,
    }
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

/// `GET /v1/commons/standing` at an explicit read-time instant.
async fn standing_at(
    f: &Fixture,
    community: &str,
    action_id: &str,
    now: Option<DateTime<Utc>>,
) -> (reqwest::StatusCode, serde_json::Value) {
    let mut q = format!(
        "{ROUTE_STANDING}?cohort=community&cohort_key_id={community}&action_id={action_id}"
    );
    if let Some(n) = now {
        // `Z`-suffixed, so the instant survives a query string untouched — a
        // `+00:00` offset would decode as a space.
        q.push_str(&format!(
            "&now={}",
            n.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
        ));
    }
    get(f, &q).await
}

async fn standing(
    f: &Fixture,
    community: &str,
    action_id: &str,
) -> (reqwest::StatusCode, serde_json::Value) {
    standing_at(f, community, action_id, None).await
}

/// The node raises an objection through the real route.
async fn node_objects(
    f: &Fixture,
    community: &str,
    action_id: &str,
) -> (reqwest::StatusCode, serde_json::Value) {
    post(
        f,
        ROUTE_OBJECT,
        &serde_json::json!({
            "cohort": "community",
            "cohort_key_id": community,
            "action_id": action_id,
            "grounds": "this crowds out everyone else in the commons",
        }),
    )
    .await
}

fn dismissal_body(
    community: &str,
    action_id: &str,
    objection_id: &str,
    scrubs: Vec<ScrubSig>,
    dry_run: bool,
) -> serde_json::Value {
    serde_json::json!({
        "cohort": "community",
        "cohort_key_id": community,
        "action_id": action_id,
        "objection_id": objection_id,
        "grounds": "the cohort holds that this objection does not stand",
        "additional_scrubs": scrubs,
        "dry_run": dry_run,
    })
}

/// Ask the route for the canonical bytes, have `cosigners` sign exactly those,
/// and submit. The m-of-n is over these bytes and no others.
async fn node_dismisses(
    f: &Fixture,
    community: &str,
    action_id: &str,
    objection_id: &str,
    cosigners: &[&str],
) -> (reqwest::StatusCode, serde_json::Value) {
    let (status, dry) = post(
        f,
        ROUTE_DISMISS,
        &dismissal_body(community, action_id, objection_id, Vec::new(), true),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "dry-run: {dry}");
    let envelope = dry["envelope"].clone();
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize dismissal");
    assert_eq!(
        dry["payload_sha256"],
        serde_json::json!(hex::encode(Sha256::digest(&canonical))),
        "the dry run must hand co-signers the hash of the bytes it printed"
    );
    let mut scrubs = Vec::new();
    for c in cosigners {
        let signer = party_signer(c);
        let sig = signer.sign_hybrid(&canonical).await.expect("co-sign");
        scrubs.push(ScrubSig {
            scrub_key_id: (*c).to_string(),
            scrub_signature_classical: BASE64.encode(&sig.classical.signature),
            scrub_signature_pqc: Some(BASE64.encode(&sig.pqc.signature)),
        });
    }
    post(
        f,
        ROUTE_DISMISS,
        &dismissal_body(community, action_id, objection_id, scrubs, false),
    )
    .await
}

/// Every operator-facing string on a response is a `{id, text}` pair.
fn assert_localizable(v: &serde_json::Value) {
    fn walk(v: &serde_json::Value, path: &str) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, child) in map {
                    if k == "message"
                        || k.ends_with("_message")
                        || k == "standing_message"
                        || k == "outcome_message"
                    {
                        assert!(
                            child
                                .get("id")
                                .and_then(serde_json::Value::as_str)
                                .is_some()
                                && child
                                    .get("text")
                                    .and_then(serde_json::Value::as_str)
                                    .is_some(),
                            "{path}.{k} must be an {{id, text}} pair, got {child}"
                        );
                    }
                    walk(child, &format!("{path}.{k}"));
                }
            }
            serde_json::Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    walk(child, &format!("{path}[{i}]"));
                }
            }
            _ => {}
        }
    }
    walk(v, "$");
}

// ════════════════════════════════════════════════════════════════════════════
//  PROPERTY 1 — one objection raises the brake
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn property_1_one_objection_raises_the_brake() {
    let f = fixture().await;
    let actor = party_signer("ca-actor");
    let action = emit_action(&f.engine, &actor, "a-1", Utc::now()).await;

    // Before anybody speaks: the plane was READ, and nobody objected.
    let (status, before) = standing(&f, COMMUNITY_A, &action.attestation_id).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{before}");
    assert_eq!(before["standing"], serde_json::json!("quiet"), "{before}");
    assert_eq!(before["fold"]["distinct_objectors"], serde_json::json!(0));
    assert_eq!(before["fold"]["required"], serde_json::json!(1));
    assert_eq!(before["fold"]["roster_size"], serde_json::json!(5));
    assert_localizable(&before);

    // ONE member. No co-signature, no quorum, no ceremony.
    let (status, raised) = node_objects(&f, COMMUNITY_A, &action.attestation_id).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{raised}");
    assert_eq!(raised["admitted"], serde_json::json!(true), "{raised}");
    assert_eq!(
        raised["threshold"],
        serde_json::json!(OBJECTION_THRESHOLD),
        "the protective threshold is ONE, named on the response"
    );
    assert_eq!(raised["threshold"], serde_json::json!(1));
    assert_localizable(&raised);

    let (status, after) = standing(&f, COMMUNITY_A, &action.attestation_id).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{after}");
    assert_eq!(
        after["standing"],
        serde_json::json!("reversed"),
        "one objection must reverse a `reverse_quorum:1/5` action: {after}"
    );
    assert_eq!(after["fold"]["distinct_objectors"], serde_json::json!(1));
    let counted = after["fold"]["counted_objection_ids"]
        .as_array()
        .expect("counted ids");
    assert_eq!(
        counted,
        &vec![raised["objection_id"].clone()],
        "the fold must name its evidence"
    );
}

#[tokio::test]
async fn property_1_one_member_is_one_objection() {
    let f = fixture().await;
    let actor = party_signer("ca-actor");
    let action = emit_action(&f.engine, &actor, "a-dup", Utc::now()).await;

    let (status, first) = node_objects(&f, COMMUNITY_A, &action.attestation_id).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{first}");

    // A second objection from the SAME member is persist's refusal, rendered
    // with persist's own token — a member cannot reach a threshold alone.
    let (status, second) = node_objects(&f, COMMUNITY_A, &action.attestation_id).await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "{second}");
    assert_eq!(
        second["refusal"],
        serde_json::json!("duplicate_objection"),
        "{second}"
    );
    assert_eq!(
        second["message"]["id"],
        serde_json::json!("commons_surface.refusal.duplicate_objection"),
        "the message id is derived from persist's token"
    );
}

// ════════════════════════════════════════════════════════════════════════════
//  PROPERTY 2 — m-of-n dismisses; below m does NOT
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn property_2_below_m_does_not_dismiss_and_m_of_n_does() {
    let f = fixture().await;
    let actor = party_signer("ca-actor");
    let action = emit_action(&f.engine, &actor, "a-2", Utc::now()).await;

    // A PEER raises the objection, so the node's dismissal is a genuine undo of
    // somebody else's protection (a self-retraction costs one, deliberately).
    let p1 = party_signer("ca-p1");
    let objection_id = peer_objects(&f.engine, &p1, COMMUNITY_A, &action, "a-2-obj").await;

    let (_, raised) = standing(&f, COMMUNITY_A, &action.attestation_id).await;
    assert_eq!(
        raised["standing"],
        serde_json::json!("reversed"),
        "{raised}"
    );

    // ── BELOW m. Two verified roster co-signatures (the node's own plus one).
    let (status, short) = node_dismisses(
        &f,
        COMMUNITY_A,
        &action.attestation_id,
        &objection_id,
        &["ca-p2"],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "{short}");
    assert_eq!(
        short["refusal"],
        serde_json::json!("dismissal_quorum_short"),
        "{short}"
    );
    assert_eq!(short["quorum"]["counted"], serde_json::json!(2), "{short}");
    assert_eq!(
        short["quorum"]["required"],
        serde_json::json!(3),
        "a strict majority of five — persist's number, not this node's: {short}"
    );
    assert_eq!(short["quorum"]["roster_size"], serde_json::json!(5));
    assert_localizable(&short);

    // The brake is UNTOUCHED by a short dismissal.
    let (_, still) = standing(&f, COMMUNITY_A, &action.attestation_id).await;
    assert_eq!(
        still["standing"],
        serde_json::json!("reversed"),
        "a below-threshold dismissal must change nothing: {still}"
    );

    // ── AT m. One more distinct roster member over the SAME canonical bytes.
    let (status, ok) = node_dismisses(
        &f,
        COMMUNITY_A,
        &action.attestation_id,
        &objection_id,
        &["ca-p2", "ca-founder"],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{ok}");
    assert_eq!(ok["admitted"], serde_json::json!(true), "{ok}");
    assert_eq!(ok["quorum"]["counted"], serde_json::json!(3), "{ok}");
    assert_eq!(ok["quorum"]["required"], serde_json::json!(3));
    assert_localizable(&ok);

    let (_, lifted) = standing(&f, COMMUNITY_A, &action.attestation_id).await;
    assert_eq!(
        lifted["standing"],
        serde_json::json!("quiet"),
        "the m-of-n dismissal lifts the brake: {lifted}"
    );
    let dismissed = lifted["fold"]["dismissed_objection_ids"]
        .as_array()
        .expect("dismissed ids");
    assert!(
        dismissed.contains(&serde_json::json!(objection_id)),
        "the fold names the objection it suppressed: {lifted}"
    );
}

/// **The fold is not re-implemented here.** A source scan over the module —
/// the same discipline `tests/mesh_config_surface.rs` applies to the durability
/// predicate — because a second implementation of a rule is a second answer.
#[test]
fn property_2_the_surface_encodes_no_threshold_arithmetic() {
    let src = std::fs::read_to_string("src/commons_surface.rs").expect("read commons_surface.rs");
    // The scan is over the SURFACE's code: cut the in-file `#[cfg(test)]`
    // module (whose fixtures legitimately spell policy strings), then strip
    // doc/line comments, because the prose NAMES these ideas and must.
    let surface = src
        .split_once("#[cfg(test)]")
        .map_or(src.as_str(), |(before, _)| before);
    let code: String = surface
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        code.contains("resolve_reverse_quorum("),
        "the surface must CALL persist's resolver — a scan that passes because the \
         module stopped calling it is not evidence"
    );

    for banned in [
        "strict_majority",
        "reversal_threshold",
        "dismissal_threshold",
        "escalated_dismissal_required",
        "steward_ruling_threshold",
        "ReverseQuorumPolicy",
        "fold_reverse_quorum",
        "steward_deadline(",
        ".window(",
    ] {
        assert!(
            !code.contains(banned),
            "src/commons_surface.rs must not compute `{banned}` — call \
             resolve_reverse_quorum and render what it returns"
        );
    }
    // No hand-rolled threshold comparison against a count persist supplies.
    for banned in [
        "distinct_objectors >=",
        "distinct_objectors <",
        "respondents >=",
        "counted >=",
        "counted <",
    ] {
        assert!(
            !code.contains(banned),
            "src/commons_surface.rs must not compare `{banned}` — the comparison is persist's"
        );
    }
    // And the vocabulary is single-sourced: no literal policy form and no
    // hand-spelled dimension anywhere. A STRING LITERAL is the test — the
    // `reverse_quorum::` module path is how the constants are imported.
    for banned in [
        "\"reverse_quorum",
        "\"objection:",
        "+escalate",
        "ESCALATE_INFIX",
    ] {
        assert!(
            !code.contains(banned),
            "src/commons_surface.rs must not spell `{banned}` — persist parses the policy \
             form and owns every dimension constant"
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  PROPERTY 3 — silence is its own arm, and escalation counts RESPONDENTS
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn property_3_silence_escalates_and_counts_respondents_not_roster() {
    let f = fixture().await;
    let t0 = Utc::now();
    let actor = party_signer("cb-actor");
    let action = emit_action(&f.engine, &actor, "b-1", t0).await;

    let (status, raised) = node_objects(&f, COMMUNITY_B, &action.attestation_id).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{raised}");
    let objection_id = raised["objection_id"].as_str().expect("id").to_owned();

    let deadline = t0 + Duration::seconds(WINDOW_SECS + STEWARD_SECS);

    // ── BEFORE the deadline. The duty-holders may still answer. This is the
    //    healthy in-progress state and must NOT read as silence.
    let (status, early) = standing_at(
        &f,
        COMMUNITY_B,
        &action.attestation_id,
        Some(t0 + Duration::seconds(60)),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{early}");
    assert_eq!(
        early["escalation"]["standing"],
        serde_json::json!(EscalationStanding::Awaiting.as_str()),
        "{early}"
    );
    let rec = &early["escalation"]["objections"][0];
    assert_eq!(rec["steward"], serde_json::json!("awaiting"), "{early}");
    assert_eq!(rec["escalation_open"], serde_json::json!(false));
    assert_eq!(rec["outcome"], serde_json::json!("not_escalated"));
    assert_eq!(
        early["escalation"]["steward_deadline"],
        serde_json::json!(deadline.to_rfc3339()),
        "the deadline is a function of the ACTION and the declaration alone"
    );
    assert_localizable(&early);

    // ── AFTER the deadline, with no ruling. SILENCE — its own arm, distinct
    //    from "the stewards said it was groundless" and from "there were none".
    let after = deadline + Duration::seconds(1);
    let (status, silent) = standing_at(&f, COMMUNITY_B, &action.attestation_id, Some(after)).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{silent}");
    assert_eq!(
        silent["escalation"]["standing"],
        serde_json::json!(EscalationStanding::Open.as_str()),
        "{silent}"
    );
    let rec = &silent["escalation"]["objections"][0];
    assert_eq!(rec["steward"], serde_json::json!("silent"), "{silent}");
    assert_eq!(rec["escalation_open"], serde_json::json!(true));
    assert_eq!(rec["duty_holders"], serde_json::json!(1), "{silent}");
    assert_eq!(rec["respondents"], serde_json::json!(0));
    assert_eq!(
        rec["outcome"],
        serde_json::json!("unresolved"),
        "an unresolved escalation changes nothing — fail-secure"
    );
    // The FLOOR, with an empty pool: the ratio alone would price this at two.
    assert_eq!(
        rec["required"],
        serde_json::json!(ESCALATION_RESPONDENT_FLOOR),
        "{silent}"
    );
    assert_eq!(
        silent["standing"],
        serde_json::json!("stood"),
        "one objection is below `reverse_quorum:2/9`, so the action stands: {silent}"
    );

    // ── THREE RESPONDENTS resolve it. The escalated denominator is the people
    //    who answered (3), not the roster (9).
    for (i, k) in ["cb-r1", "cb-r2", "cb-r3"].iter().enumerate() {
        peer_ballots(
            &f.engine,
            &party_signer(k),
            COMMUNITY_B,
            &action,
            &objection_id,
            false,
            &format!("b-1-ballot-{i}"),
        )
        .await;
    }
    let (status, resolved) =
        standing_at(&f, COMMUNITY_B, &action.attestation_id, Some(after)).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{resolved}");
    let rec = &resolved["escalation"]["objections"][0];
    assert_eq!(rec["respondents"], serde_json::json!(3), "{resolved}");
    assert_eq!(rec["overrule_ballots"], serde_json::json!(3));
    assert_eq!(rec["required"], serde_json::json!(3), "{resolved}");
    assert_eq!(rec["outcome"], serde_json::json!("dismissed"), "{resolved}");
    assert_eq!(
        resolved["fold"]["roster_size"],
        serde_json::json!(9),
        "the ROSTER is nine and the escalated decision was priced against three"
    );
    let esc_dismissed = resolved["fold"]["escalated_dismissed_objection_ids"]
        .as_array()
        .expect("escalated dismissed ids");
    assert!(
        esc_dismissed.contains(&serde_json::json!(objection_id)),
        "the escalated suppression is reported SEPARATELY from the ordinary one, \
         because the two were bought at two different prices: {resolved}"
    );
    assert!(
        resolved["fold"]["dismissed_objection_ids"]
            .as_array()
            .expect("dismissed ids")
            .is_empty(),
        "no ordinary dismissal was ever admitted here: {resolved}"
    );
    assert_eq!(resolved["standing"], serde_json::json!("quiet"));

    // ── THE SAME THREE KEYS on the ORDINARY path cost five. One ratio, two
    //    denominators — and this is the difference escalation buys.
    let peer_obj = peer_objects(
        &f.engine,
        &party_signer("cb-x1"),
        COMMUNITY_B,
        &action,
        "b-1-obj-x1",
    )
    .await;
    let (status, ordinary) = node_dismisses(
        &f,
        COMMUNITY_B,
        &action.attestation_id,
        &peer_obj,
        &["cb-r1", "cb-r2"],
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "{ordinary}");
    assert_eq!(
        ordinary["quorum"]["counted"],
        serde_json::json!(3),
        "{ordinary}"
    );
    assert_eq!(
        ordinary["quorum"]["required"],
        serde_json::json!(5),
        "a strict majority of NINE — the price the roster's own absence had made \
         unreachable, which is exactly what escalation is for: {ordinary}"
    );
}

#[tokio::test]
async fn property_3_a_duty_holder_who_rules_in_time_keeps_escalation_shut() {
    let f = fixture().await;
    let t0 = Utc::now();
    let actor = party_signer("cb-actor");
    let action = emit_action(&f.engine, &actor, "b-2", t0).await;

    let (status, raised) = node_objects(&f, COMMUNITY_B, &action.attestation_id).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{raised}");
    let objection_id = raised["objection_id"].as_str().expect("id").to_owned();

    // The appointed moderator answers, before the deadline.
    peer_ballots(
        &f.engine,
        &party_signer("cb-mod"),
        COMMUNITY_B,
        &action,
        &objection_id,
        true,
        "b-2-ruling",
    )
    .await;

    let after = t0 + Duration::seconds(WINDOW_SECS + STEWARD_SECS + 1);
    let (status, ruled) = standing_at(&f, COMMUNITY_B, &action.attestation_id, Some(after)).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{ruled}");
    let rec = &ruled["escalation"]["objections"][0];
    assert_eq!(rec["steward"], serde_json::json!("upheld"), "{ruled}");
    assert_eq!(
        rec["escalation_open"],
        serde_json::json!(false),
        "the matter WAS judged, by named people, on the record: {ruled}"
    );
    assert_eq!(rec["outcome"], serde_json::json!("not_escalated"));
    assert_eq!(
        ruled["escalation"]["standing"],
        serde_json::json!(EscalationStanding::Awaiting.as_str()),
    );
    // "nobody answered" and "the answer was yes" do not render alike.
    assert_ne!(rec["steward"], serde_json::json!("silent"));
}

// ════════════════════════════════════════════════════════════════════════════
//  PROPERTY 4 — the floor cannot be lowered by policy
// ════════════════════════════════════════════════════════════════════════════

/// A cohort cannot even DECLARE a sub-floor escalation: persist refuses the
/// string at its one parse door rather than clamping it silently, so a commons
/// configured below the floor does not exist to be read.
#[tokio::test]
async fn property_4_a_sub_floor_declaration_is_refused_at_the_door() {
    let f = fixture().await;
    let node_key = node_key_id(&f.engine).await;
    let mut bc: Vec<(&str, &str)> = vec![("cb-mod", "founder")];
    bc.extend(BC_MEMBERS[1..].iter().map(|k| (*k, "member")));
    bc.push((node_key.as_str(), "member"));

    let refused = try_put_community(&f.engine, "cm-sub-floor", PROTOCOL_SUB_FLOOR, &bc)
        .await
        .expect_err("a floor below the absolute floor must be refused");
    assert_eq!(
        refused, "federation_consensus_protocol_malformed",
        "the sub-floor declaration must be refused at the parse door, not clamped"
    );
    // The legal twin — identical but for the floor — IS admitted, so the
    // refusal is about the floor and nothing else.
    try_put_community(&f.engine, "cm-at-floor", PROTOCOL_B, &bc)
        .await
        .expect("the same declaration at the legal floor is admitted");
}

/// And a cohort that declares the CHEAPEST legal brake still cannot buy an
/// escalated undo below the floor: `reverse_quorum:1/9` prices its ordinary
/// reversal at one, and its escalated undo at three.
#[tokio::test]
async fn property_4_the_cheapest_declaration_still_pays_the_floor() {
    let f = fixture().await;
    let t0 = Utc::now();
    let actor = party_signer("cb-actor");
    let action = emit_action(&f.engine, &actor, "c-1", t0).await;

    let (status, raised) = node_objects(&f, COMMUNITY_C, &action.attestation_id).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{raised}");
    let objection_id = raised["objection_id"].as_str().expect("id").to_owned();

    let after = t0 + Duration::seconds(WINDOW_SECS + STEWARD_SECS + 1);

    // TWO respondents. The declared ratio alone would price this at two.
    for (i, k) in ["cb-r1", "cb-r2"].iter().enumerate() {
        peer_ballots(
            &f.engine,
            &party_signer(k),
            COMMUNITY_C,
            &action,
            &objection_id,
            false,
            &format!("c-1-ballot-{i}"),
        )
        .await;
    }
    let (status, two) = standing_at(&f, COMMUNITY_C, &action.attestation_id, Some(after)).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{two}");
    let rec = &two["escalation"]["objections"][0];
    assert_eq!(rec["respondents"], serde_json::json!(2), "{two}");
    assert_eq!(rec["overrule_ballots"], serde_json::json!(2));
    assert_eq!(
        rec["required"],
        serde_json::json!(ESCALATION_RESPONDENT_FLOOR),
        "a cohort declaring m=1 does NOT get a two-key escalated undo: {two}"
    );
    assert_eq!(
        rec["outcome"],
        serde_json::json!("unresolved"),
        "below the floor the escalation resolves nothing: {two}"
    );
    assert_eq!(
        two["standing"],
        serde_json::json!("reversed"),
        "and the brake still holds, because m=1 and the objection stands: {two}"
    );

    // A THIRD respondent reaches the floor, and only then.
    peer_ballots(
        &f.engine,
        &party_signer("cb-r3"),
        COMMUNITY_C,
        &action,
        &objection_id,
        false,
        "c-1-ballot-2",
    )
    .await;
    let (status, three) = standing_at(&f, COMMUNITY_C, &action.attestation_id, Some(after)).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{three}");
    let rec = &three["escalation"]["objections"][0];
    assert_eq!(rec["respondents"], serde_json::json!(3), "{three}");
    assert_eq!(rec["required"], serde_json::json!(3));
    assert_eq!(rec["outcome"], serde_json::json!("dismissed"), "{three}");
    assert_eq!(three["standing"], serde_json::json!("quiet"));
}

// ════════════════════════════════════════════════════════════════════════════
//  PROPERTY 5 — distinct zeroes
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn property_5_every_zero_names_its_own_cause() {
    let f = fixture().await;
    let actor = party_signer("ca-actor");
    let action = emit_action(&f.engine, &actor, "z-1", Utc::now()).await;

    // (a) NO OBJECTION HAS BEEN RAISED — a statement about a plane that WAS read.
    let (status, quiet) = standing(&f, COMMUNITY_A, &action.attestation_id).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{quiet}");
    assert_eq!(quiet["standing"], serde_json::json!("quiet"));
    assert_eq!(quiet["fold"]["distinct_objectors"], serde_json::json!(0));

    // (b) THIS COMMUNITY HAS NO REVERSE-QUORUM POLICY — not "nobody objected".
    let node_key = node_key_id(&f.engine).await;
    put_community(
        &f.engine,
        "cm-ungoverned",
        "founder_only",
        &[("ca-founder", "founder"), (node_key.as_str(), "member")],
    )
    .await;
    let (status, ungoverned) = standing(&f, "cm-ungoverned", &action.attestation_id).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{ungoverned}");
    assert_eq!(
        ungoverned["standing"],
        serde_json::json!("not_governed"),
        "{ungoverned}"
    );
    assert_eq!(ungoverned["fold"]["policy"], serde_json::Value::Null);

    // (c) THERE IS NO SUCH ACTION — and no counts are invented for it.
    let (status, no_action) = standing(&f, COMMUNITY_A, "no-such-action").await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND, "{no_action}");
    assert_eq!(no_action["standing"], serde_json::json!("action_unknown"));
    assert_eq!(no_action["fold"], serde_json::Value::Null, "{no_action}");
    assert_eq!(no_action["escalation"], serde_json::Value::Null);

    // (d) THERE IS NO SUCH COHORT — distinct from "it declares no policy".
    let (status, no_cohort) = standing(&f, "cm-nonexistent", &action.attestation_id).await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND, "{no_cohort}");
    assert_eq!(no_cohort["standing"], serde_json::json!("cohort_unknown"));
    assert_eq!(no_cohort["fold"], serde_json::Value::Null, "{no_cohort}");

    // (e) The `self` cohort has no commons to police, and says so.
    let (status, not_a_commons) = get(
        &f,
        &format!("{ROUTE_STANDING}?cohort=self&cohort_key_id=x&action_id=y"),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{not_a_commons}");
    assert_eq!(
        not_a_commons["refusal"],
        serde_json::json!("cohort_not_a_commons")
    );

    // All five facts carry five DIFFERENT tokens.
    let tokens: BTreeSet<String> = [&quiet, &ungoverned, &no_action, &no_cohort]
        .iter()
        .map(|v| v["standing"].as_str().expect("standing").to_owned())
        .collect();
    assert_eq!(tokens.len(), 4, "four facts, four tokens: {tokens:?}");

    // And the closed set itself has no duplicate token or duplicate message id.
    let all: BTreeSet<&str> = CommonsStanding::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(all.len(), CommonsStanding::ALL.len());
    let esc: BTreeSet<&str> = EscalationStanding::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(esc.len(), EscalationStanding::ALL.len());
    assert_localizable(&quiet);
    assert_localizable(&ungoverned);
    assert_localizable(&no_action);
}

/// A write that names an action this node does not hold is refused with its own
/// reason rather than assembled around a dangling id — and the refusal is not
/// the same token as "you may not act".
#[tokio::test]
async fn property_5_a_write_naming_nothing_is_refused_by_its_own_cause() {
    let f = fixture().await;
    let (status, v) = node_objects(&f, COMMUNITY_A, "no-such-action").await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND, "{v}");
    assert_eq!(v["refusal"], serde_json::json!("action_unknown"), "{v}");

    let actor = party_signer("ca-actor");
    let action = emit_action(&f.engine, &actor, "z-2", Utc::now()).await;
    let (status, v) = post(
        &f,
        ROUTE_OBJECT,
        &serde_json::json!({
            "cohort": "community",
            "cohort_key_id": COMMUNITY_A,
            "action_id": action.attestation_id,
            "grounds": "   ",
        }),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["refusal"], serde_json::json!("grounds_absent"), "{v}");

    // A ballot on a cohort with no steward tier is persist's own refusal — the
    // row would be stored and never read by anything.
    let (status, v) = post(
        &f,
        ROUTE_BALLOT,
        &serde_json::json!({
            "cohort": "community",
            "cohort_key_id": COMMUNITY_A,
            "action_id": action.attestation_id,
            "objection_id": "whatever",
            "upholds": true,
            "grounds": "no tier here",
        }),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "{v}");
    assert_eq!(
        v["refusal"],
        serde_json::json!("steward_tier_not_adopted"),
        "{v}"
    );
}

// ════════════════════════════════════════════════════════════════════════════
//  The gate
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn the_surface_is_owner_gated_on_every_route() {
    let f = fixture().await;
    let actor = party_signer("ca-actor");
    let action = emit_action(&f.engine, &actor, "g-1", Utc::now()).await;
    let client = reqwest::Client::new();
    // Fully-formed requests, so what is being tested is the GATE and not an
    // extractor rejection.
    let write = serde_json::json!({
        "cohort": "community",
        "cohort_key_id": COMMUNITY_A,
        "action_id": action.attestation_id,
        "objection_id": "whatever",
        "upholds": true,
        "grounds": "grounds",
    });
    let query = format!(
        "{ROUTE_STANDING}?cohort=community&cohort_key_id={COMMUNITY_A}&action_id={}",
        action.attestation_id
    );
    for (path, body) in [
        (query.as_str(), None),
        (ROUTE_OBJECT, Some(&write)),
        (ROUTE_BALLOT, Some(&write)),
        (ROUTE_DISMISS, Some(&write)),
    ] {
        let url = format!("{}{path}", f.base);
        let resp = match body {
            None => client.get(&url).send().await.expect("GET"),
            Some(b) => client.post(&url).json(b).send().await.expect("POST"),
        };
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{path} must refuse an unauthenticated caller"
        );
        let body: serde_json::Value = resp.json().await.expect("json");
        assert_eq!(body["refusal"], serde_json::json!("session_absent"));
        assert_localizable(&body);
    }
}
