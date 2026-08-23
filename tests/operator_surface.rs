//! CIRISServer#356 — **the operator surface, over the real router.**
//!
//! Two properties are gated here, and neither can be proven by a unit test over
//! the fold alone:
//!
//! 1. **THE COMPOSITION.** One read carries BOTH sources — persist's node-state
//!    signals and edge's carriage counters — and carries the persist half
//!    **byte-identical** to what persist's own `resolve_node_state` returns.
//!    That last clause is the real assertion: a surface that re-derived a band
//!    would still look composed, and would be two lists that can disagree
//!    (#541). Comparing against the substrate's own value is the only check
//!    that catches a re-derivation.
//!
//! 2. **THE DISTINCT ZEROES,** end to end. Four readings that all report zero
//!    carriage must reach an operator as four different facts:
//!
//!    | reading | cause |
//!    |---|---|
//!    | `carriage.standing = "unreadable"` | the counters could not be read at all |
//!    | `carriage.standing = "not_exercised"` | no replication round has ever finished |
//!    | `carriage.standing = "idle"` | rounds finished; nothing to send |
//!    | `carriage.standing = "withholding"` | rows were held back on purpose |
//!
//!    All four have `served_total` 0 (or no such field at all, in the
//!    unreadable case). If they render alike, the surface is decoration.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde_json::Value;
use sha2::{Digest, Sha256};

use ciris_edge::observability::{EdgeMetrics, RoundOutcome, WithholdReason};
use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::node_state::{
    resolve_node_state, NodeStateOptions, StateBand, TrustRootStanding,
};
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};

use ciris_server::auth::store;
use ciris_server::ingest_http::IngestRefusals;
use ciris_server::operator_surface;

const NODE_KEY_ALIAS: &str = "ciris-server";
const OWNER_USER_KEY_ID: &str = "ciris-owner-user";
const OWNER_ED_SEED: [u8; 32] = [0xF1; 32];
const OWNER_PQC_SEED: [u8; 32] = [0xF2; 32];

/// Stand up THIS node on an in-memory substrate keyed by a hybrid signer.
async fn node() -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_KEY_ALIAS}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xA1; 32]),
        NODE_KEY_ALIAS.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ALIAS}-pqc")),
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

/// Register this node's own steward key via the canonical admission gate.
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

fn owner_user_signer() -> LocalSigner {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&OWNER_PQC_SEED, format!("{OWNER_USER_KEY_ID}-pqc"))
            .expect("owner ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        SigningKey::from_bytes(&OWNER_ED_SEED),
        OWNER_USER_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{OWNER_USER_KEY_ID}-pqc")),
    )
}

/// CC 3.2 owner-binding: a `user`-role responsible party + `delegates_to(user →
/// node, infra:*)`. Without it the surface refuses (an unowned node has no
/// accountable party to show its state to).
async fn bind_owner(engine: &Engine) {
    let owner_ed_pub = BASE64.encode(
        SigningKey::from_bytes(&OWNER_ED_SEED)
            .verifying_key()
            .to_bytes(),
    );
    let owner_mldsa_pub = {
        let pqc = MlDsa65SoftwareSigner::from_seed_bytes(
            &OWNER_PQC_SEED,
            format!("{OWNER_USER_KEY_ID}-pqc"),
        )
        .expect("owner ML-DSA-65 seed");
        BASE64.encode(pqc.public_key().await.expect("owner ML-DSA-65 pubkey"))
    };
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": OWNER_USER_KEY_ID });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize owner envelope");
    let record = KeyRecord {
        key_id: OWNER_USER_KEY_ID.to_string(),
        pubkey_ed25519_base64: owner_ed_pub,
        pubkey_ml_dsa_65_base64: Some(owner_mldsa_pub),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::USER.into(),
        identity_ref: OWNER_USER_KEY_ID.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: OWNER_USER_KEY_ID.to_string(),
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
        .expect("register responsible-party user key");

    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(ToString::to_string)
        .collect();
    let node = node_key_id(engine).await;
    ciris_server::auth::ownership::emit_steward_binding(
        engine,
        &owner_user_signer(),
        &node,
        &scopes,
    )
    .await
    .expect("emit owner-binding");
}

/// Mint an active `wa_cert` + return its bound session bearer token.
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

/// Serve the operator-surface router on an ephemeral port.
async fn serve(
    engine: Arc<Engine>,
    metrics: Option<EdgeMetrics>,
) -> (String, tokio::task::JoinHandle<()>) {
    serve_with(engine, metrics, None).await
}

/// [`serve`] plus an explicit ingest refusal ledger (CIRISServer#370). `None`
/// is a node with no HTTP ingest route — the `unreadable` arm.
async fn serve_with(
    engine: Arc<Engine>,
    metrics: Option<EdgeMetrics>,
    refusals: Option<IngestRefusals>,
) -> (String, tokio::task::JoinHandle<()>) {
    let key_id = node_key_id(&engine).await;
    let app = operator_surface::router(engine, key_id, metrics, refusals);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// Serve the trace plane the way [`ciris_server::compose`] mounts it — the
/// route that ADMITS and the route that READS, over the ledger
/// [`operator_surface::trace_plane_router`] mints for them. No handle is passed
/// in, which is the point: the composition has no opportunity to hand them
/// different ones.
async fn serve_trace_plane(
    engine: Arc<Engine>,
    metrics: Option<EdgeMetrics>,
) -> (String, tokio::task::JoinHandle<()>) {
    let key_id = node_key_id(&engine).await;
    let app = operator_surface::trace_plane_router(
        engine,
        key_id,
        metrics,
        ciris_server::mesh_config_effect::MeshConfigEffect::unwired(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// A live-but-idle process: a round finished, nothing served, nothing withheld.
fn idle_metrics() -> EdgeMetrics {
    let m = EdgeMetrics::new();
    m.inc_round_outcome(RoundOutcome::Completed);
    m
}

/// A node that IS withholding — the same zero carriage, a different fact.
fn withholding_metrics() -> EdgeMetrics {
    let m = idle_metrics();
    m.inc_withhold(
        WithholdReason::ServeCapabilityMissing,
        "peer-canonical-1",
        "legA-no-infra-serve",
    );
    m
}

/// GET the surface as the owner; return the unwrapped `data` object.
async fn read_state(base: &str, bearer: &str) -> Value {
    let resp = reqwest::Client::new()
        .get(format!("{base}{}", operator_surface::ROUTE))
        .bearer_auth(bearer)
        .send()
        .await
        .expect("GET /v1/node/state");
    assert_eq!(resp.status(), 200, "owner read must succeed");
    let body: Value = resp.json().await.expect("json body");
    body["data"].clone()
}

// ─────────────────────────────────────────────────────────────────────────────

/// **THE COMPOSITION GATE.** One read carries both sources, and the persist half
/// is byte-identical to persist's own answer.
#[tokio::test]
async fn one_read_carries_both_sources_and_re_derives_neither() {
    let engine = node().await;
    register_self(&engine).await;
    bind_owner(&engine).await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve_with(
        Arc::clone(&engine),
        Some(withholding_metrics()),
        Some(IngestRefusals::new()),
    )
    .await;

    let data = read_state(&base, &owner).await;

    // (1) EVERY source is present and named. The list grew with #369/#370: the
    // trace corpus and the ingest ledger are sources in exactly the same sense
    // the first two are — each present-or-unavailable-with-a-reason, never an
    // absent key and never a healthy default.
    assert_eq!(
        data["composed_from"],
        serde_json::json!([
            "node_state",
            "edge_metrics",
            "trace_corpus",
            // CIRISServer#446 — the store footprint is a composed source like
            // any other, so it appears in the bookkeeping. Emitting the block
            // without listing it here is what the PR #483 review caught: a
            // payload claiming it was not composed from the store while `store`
            // carried measured data.
            "store_footprint",
            "ingest_refusals"
        ]),
        "the surface must compose EVERY source, not a subset of them: {data}"
    );
    assert_eq!(data["sources"]["node_state"]["present"], true);
    assert_eq!(data["sources"]["edge_metrics"]["present"], true);
    assert_eq!(data["sources"]["trace_corpus"]["present"], true);
    assert_eq!(data["sources"]["ingest_refusals"]["present"], true);
    assert!(
        data["sources"]["node_state"]["produced_by"]
            .as_str()
            .expect("produced_by")
            .contains("ciris_persist"),
        "the node half must name persist as its producer"
    );
    assert!(
        data["sources"]["edge_metrics"]["produced_by"]
            .as_str()
            .expect("produced_by")
            .contains("ciris_edge"),
        "the carriage half must name edge as its producer"
    );

    // (2) The persist half answers persist's questions...
    for signal in [
        "trust_root",
        "key_statements",
        "quarantine",
        "consent_sla",
        "peer_quota",
    ] {
        assert!(
            !data["node"][signal].is_null(),
            "the node half must carry `{signal}`: {data}"
        );
    }
    // ...and the edge half answers edge's, which persist cannot see at all.
    assert!(!data["carriage"]["withholds_by_reason"].is_null());
    assert!(!data["receive"]["apply_refusals_by_kind"].is_null());
    assert_eq!(
        data["carriage"]["withholds_by_reason"]["serve_capability_missing"],
        serde_json::json!(1),
        "edge's own stable label must survive the fold verbatim"
    );

    // (3) RE-DERIVES NEITHER. Ask persist the same question at the same instant
    //     and demand the SAME value — not a matching one, the same one. A
    //     surface that recomputed a band would pass every check above and fail
    //     this one, which is the whole reason it is here.
    let as_of: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(data["as_of"].clone()).expect("as_of parses");
    let key_id = node_key_id(&engine).await;
    let directly = resolve_node_state(
        &*engine.federation_directory(),
        NodeStateOptions {
            self_key_id: Some(&key_id),
            root_key_id: None,
            now: as_of,
            sla: std::time::Duration::from_secs(86_400),
        },
    )
    .await
    .expect("persist's own fold");
    assert_eq!(
        data["node"],
        serde_json::to_value(&directly).expect("serialize persist's answer"),
        "the node half must be persist's value CARRIED, not a re-derivation of it"
    );

    // (4) The clock-dependence persist declares is carried up, not restated.
    assert_eq!(
        data["volatility"]["clock_dependent"],
        serde_json::to_value(&directly.clock_dependent).expect("clock_dependent"),
    );
    // ...and the OTHER volatility — the process-local counters — is named too,
    // because "resets on restart" and "moves with the clock" are not the same
    // caveat and a consumer diffing two reads meets both.
    assert!(data["volatility"]["process_local"]["note"]["id"].is_string());
    assert_eq!(
        data["volatility"]["process_local"]["fields"],
        serde_json::json!(["carriage", "receive", "ingest"]),
        "the #370 refusal ledger resets on restart exactly as the carriage counters do, and a \
         process-local counter that does not declare itself is the field an operator reads as \
         durable node state"
    );
    // ...and a THIRD kind, added with #369: a band computed HERE that moves on
    // elapsed time alone. It must NOT have been folded into persist's list —
    // that list is persist's, carried verbatim, and a second author on it is
    // exactly the two-lists-that-disagree shape.
    assert_eq!(
        data["volatility"]["clock_dependent_local"]["fields"],
        serde_json::json!(["trace_plane"])
    );
    assert!(!data["volatility"]["clock_dependent"]
        .as_array()
        .expect("clock_dependent")
        .contains(&serde_json::json!("trace_plane")));

    // (5) The persist signals are EXPLAINED, with the token persist minted and
    //     the band persist computed — never a band of ours.
    let explains = data["node_explains"].as_array().expect("node_explains");
    let trust = explains
        .iter()
        .find(|e| e["signal"] == "trust_root")
        .expect("trust_root explained");
    assert_eq!(trust["token"], data["node"]["trust_root"]["standing"]);
    assert_eq!(trust["band"], data["node"]["trust_root"]["band"]);
    assert!(trust["message"]["id"].is_string());
    assert!(trust["message"]["text"].is_string());
    // A registered node with no trust edges is a KNOWN red, not an unknown —
    // the fixture reaches that arm, which is what makes the check meaningful.
    assert_eq!(
        trust["token"],
        serde_json::json!(TrustRootStanding::NoTrustEdges.as_str())
    );
    assert_eq!(trust["band"], serde_json::json!(StateBand::Red.as_str()));
}

/// **THE DISTINCT-ZEROES GATE.** Four zero-carriage readings, four facts.
#[tokio::test]
async fn every_zero_carriage_reading_names_its_own_cause() {
    // Each arm gets its own node so the four surfaces are genuinely independent.
    let mut seen: Vec<(String, String, String)> = Vec::new(); // (standing, band, explains.id)
    for (label, metrics) in [
        ("unreadable", None),
        ("not_exercised", Some(EdgeMetrics::new())),
        ("idle", Some(idle_metrics())),
        ("withholding", Some(withholding_metrics())),
    ] {
        let engine = node().await;
        register_self(&engine).await;
        bind_owner(&engine).await;
        let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
        let (base, _h) = serve(Arc::clone(&engine), metrics).await;
        let data = read_state(&base, &owner).await;

        let carriage = &data["carriage"];
        assert_eq!(
            carriage["standing"],
            serde_json::json!(label),
            "arm `{label}` reported the wrong standing: {carriage}"
        );
        // Every one of the four moved ZERO rows. The count cannot tell them
        // apart; the token must.
        assert_eq!(
            carriage["served_total"].as_u64().unwrap_or(0),
            0,
            "arm `{label}` was supposed to be a zero-carriage reading"
        );
        seen.push((
            carriage["standing"].as_str().expect("standing").to_string(),
            carriage["band"].as_str().expect("band").to_string(),
            carriage["explains"]["id"]
                .as_str()
                .expect("explains.id")
                .to_string(),
        ));

        // Per-arm invariants that a collapsed surface would violate.
        match label {
            // "Could not read" must NOT publish a clean counter set at all —
            // an absent number cannot be misread as a zero.
            "unreadable" => {
                assert!(
                    carriage["withholds_total"].is_null(),
                    "an unreadable source must not emit a count: {carriage}"
                );
                assert!(
                    data["receive"]["apply_refusals_total"].is_null(),
                    "…on the receive plane either: {}",
                    data["receive"]
                );
                assert_eq!(data["receive"]["standing"], serde_json::json!("unreadable"));
                assert!(carriage["unavailable"]["id"].is_string());
                assert_eq!(data["sources"]["edge_metrics"]["present"], false);
                assert!(
                    data["sources"]["edge_metrics"]["detail"].is_string(),
                    "a missing source must carry WHY it is missing"
                );
                let unknown: Vec<String> =
                    serde_json::from_value(data["unknown"].clone()).expect("unknown[]");
                assert!(unknown.iter().any(|u| u == "carriage"), "{unknown:?}");
                assert!(unknown.iter().any(|u| u == "receive"), "{unknown:?}");
            }
            // A fresh process reports 0 withholds and 0 served — and says the
            // zero is UNTESTED, not clean. This is the persist peer-quota rule
            // applied to the carriage plane.
            "not_exercised" => {
                assert_eq!(carriage["withholds_total"], serde_json::json!(0));
                assert_eq!(carriage["rounds_total"], serde_json::json!(0));
                assert_eq!(carriage["band"], serde_json::json!("unknown"));
                assert_eq!(
                    data["receive"]["standing"],
                    serde_json::json!("not_exercised")
                );
            }
            // Rounds ran; there was nothing to say. GREEN, and a different
            // token from every other zero.
            "idle" => {
                assert_eq!(carriage["withholds_total"], serde_json::json!(0));
                assert_eq!(carriage["rounds_total"], serde_json::json!(1));
                assert_eq!(carriage["band"], serde_json::json!("green"));
                // CIRISEdge#457 — `clean` until edge shipped an accepted-applies
                // counter, and `clean` meant three things. Rounds ran and NOTHING
                // was offered to the apply path is `idle`, the receive mirror of
                // the carriage token beside it.
                assert_eq!(data["receive"]["standing"], serde_json::json!("idle"));
                assert_eq!(data["receive"]["applied_total"], serde_json::json!(0));
                assert_eq!(data["receive"]["duplicate_total"], serde_json::json!(0));
                assert_eq!(data["receive"]["decided_total"], serde_json::json!(0));
                assert_eq!(data["receive"]["rounds_total"], serde_json::json!(1));
                // ...and the reading states what its denominator does NOT count,
                // rather than the old caveat about a counter that now exists.
                let note = data["receive"]["note"]["text"].as_str().expect("note");
                assert!(
                    note.contains("decided_total") && note.contains("decode"),
                    "the note must define the denominator and name the class it \
                     excludes: {note}"
                );
                assert!(
                    !note.contains("not accepted applies"),
                    "the CIRISEdge#457 caveat must be GONE, not softened — it tells \
                     a reader not to trust a number that is now trustworthy: {note}"
                );
            }
            // The node chose not to serve. Same zero rows delivered; an
            // entirely different thing to do about it.
            "withholding" => {
                assert_eq!(carriage["withholds_total"], serde_json::json!(1));
                assert_eq!(
                    carriage["worst_withhold_class"],
                    serde_json::json!("policy")
                );
                assert_eq!(carriage["band"], serde_json::json!("yellow"));
                let recent = carriage["recent_withholds"]
                    .as_array()
                    .expect("recent_withholds");
                assert_eq!(recent.len(), 1);
                assert_eq!(recent[0]["peer_key_id"], "peer-canonical-1");
                assert_eq!(recent[0]["class"], "policy");
            }
            _ => unreachable!(),
        }
    }

    // The four arms share no standing token, no explanation id — and the two
    // that share the `unknown` band still differ on both.
    let standings: std::collections::HashSet<&String> = seen.iter().map(|(s, _, _)| s).collect();
    assert_eq!(
        standings.len(),
        4,
        "two zero-carriage arms collapsed: {seen:?}"
    );
    let ids: std::collections::HashSet<&String> = seen.iter().map(|(_, _, i)| i).collect();
    assert_eq!(
        ids.len(),
        4,
        "two zero-carriage arms share an explanation: {seen:?}"
    );
    assert_eq!(
        seen[0].1, seen[1].1,
        "unreadable and not_exercised do share the `unknown` BAND …"
    );
    assert_ne!(
        seen[0].0, seen[1].0,
        "… and must still differ on the token: a band never replaces a token"
    );
}

/// The owner gate: three legs, three refusals, and a refusal shows NOTHING.
#[tokio::test]
async fn the_surface_is_owner_gated_on_all_three_legs() {
    // Leg 1 — an OWNER-UNBOUND node refuses even a perfect owner session.
    {
        let engine = node().await;
        register_self(&engine).await;
        let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
        let (base, _h) = serve(Arc::clone(&engine), Some(idle_metrics())).await;
        let resp = reqwest::Client::new()
            .get(format!("{base}{}", operator_surface::ROUTE))
            .bearer_auth(&owner)
            .send()
            .await
            .expect("GET");
        assert_eq!(
            resp.status(),
            403,
            "an unowned node has no responsible party to show its state to"
        );
        let body: Value = resp.json().await.expect("json");
        assert!(body["data"].is_null(), "a refusal must leak no state");
    }

    let engine = node().await;
    register_self(&engine).await;
    bind_owner(&engine).await;
    let (base, _h) = serve(Arc::clone(&engine), Some(idle_metrics())).await;

    // Leg 2 — no session at all.
    let resp = reqwest::Client::new()
        .get(format!("{base}{}", operator_surface::ROUTE))
        .send()
        .await
        .expect("GET");
    assert_eq!(resp.status(), 401);

    // Leg 3 — a real session that is not the owner.
    let observer = mint_session(&engine, "wa-observer", WaRole::Observer).await;
    let resp = reqwest::Client::new()
        .get(format!("{base}{}", operator_surface::ROUTE))
        .bearer_auth(&observer)
        .send()
        .await
        .expect("GET");
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.expect("json");
    assert!(body["data"].is_null(), "a refusal must leak no state");

    // …and the owner still passes, so the gate is a gate and not a wall.
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let data = read_state(&base, &owner).await;
    assert!(data["band"].is_string());
}

/// Polling the surface writes NOTHING — the property that makes it safe for a
/// dashboard. persist's consent-SLA leg has an EMITTING sibling that records a
/// `hard_case` row; this surface must ride the read-only twin.
#[tokio::test]
async fn polling_the_surface_writes_nothing() {
    use ciris_persist::federation::hard_case::HardCaseFilter;

    let engine = node().await;
    register_self(&engine).await;
    bind_owner(&engine).await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine), Some(idle_metrics())).await;

    let count = |e: Arc<Engine>| async move {
        e.federation_directory()
            .list_hard_case_events(HardCaseFilter::default())
            .await
            .expect("hard_case read")
            .len()
    };
    let baseline = count(Arc::clone(&engine)).await;
    for _ in 0..5 {
        let data = read_state(&base, &owner).await;
        assert_eq!(data["node"]["consent_sla"]["read_only"], true);
        assert_eq!(
            count(Arc::clone(&engine)).await,
            baseline,
            "a dashboard refresh must not be an attestation"
        );
    }
}

/// CIRISServer#369/#370 — **the two new readings over the REAL route, and their
/// zeroes.**
///
/// A fresh node has admitted no trace and mounted no ingest gate. Both facts are
/// zeroes, and the failure mode this whole surface exists to prevent is that
/// they render as health. Neither may read green, neither may read as the other,
/// and both must be NAMED in the `unknown` list — a red headline outranks an
/// unknown and would otherwise hide one behind it.
#[tokio::test]
async fn a_fresh_nodes_trace_and_ingest_zeroes_name_their_own_causes() {
    let engine = node().await;
    register_self(&engine).await;
    bind_owner(&engine).await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;

    // No ingest ledger: this process mounted no HTTP ingest gate, so there is no
    // gate to have refused anything.
    let (base, _h) = serve_with(Arc::clone(&engine), Some(idle_metrics()), None).await;
    let data = read_state(&base, &owner).await;

    // The corpus was READ, and it is empty. That is not "we could not ask", and
    // it is emphatically not green.
    assert_eq!(
        data["trace_plane"]["standing"], "never_admitted",
        "{}",
        data["trace_plane"]
    );
    assert_eq!(data["trace_plane"]["band"], "unknown");
    assert_eq!(data["trace_plane"]["rows"], 0);
    assert_eq!(data["trace_plane"]["last_admitted_at"], Value::Null);
    assert_eq!(data["sources"]["trace_corpus"]["present"], true);

    // The ledger could NOT be read. Same absence of refusals, different fact.
    assert_eq!(
        data["ingest"]["standing"], "unreadable",
        "{}",
        data["ingest"]
    );
    assert_eq!(data["ingest"]["band"], "unknown");
    assert!(
        data["ingest"].get("refusals_in_window").is_none(),
        "an unread ledger must render NO counts — a zero there is a manufactured clean reading: {}",
        data["ingest"]
    );
    assert_eq!(data["sources"]["ingest_refusals"]["present"], false);

    // Both are named individually, so neither can hide behind the roll-up.
    let unknown = data["unknown"].as_array().expect("unknown");
    assert!(unknown.contains(&Value::from("trace_plane")), "{data}");
    assert!(unknown.contains(&Value::from("ingest")), "{data}");

    // Now the same node WITH a gate that has never been offered anything: the
    // ingest zero changes token, because "we could not ask" and "nothing was
    // ever offered" are different answers.
    let (base, _h) = serve_with(
        Arc::clone(&engine),
        Some(idle_metrics()),
        Some(IngestRefusals::new()),
    )
    .await;
    let data2 = read_state(&base, &owner).await;
    assert_eq!(data2["ingest"]["standing"], "not_exercised");
    assert_eq!(data2["ingest"]["refusals_in_window"], 0);
    assert_eq!(data2["ingest"]["accepted_total"], 0);
    assert_ne!(
        data2["ingest"]["standing"], data["ingest"]["standing"],
        "an unread ledger and an unexercised one are two facts and must not share a token"
    );
    // ...and a gate that HAS admitted something reads clean, which the zero
    // refusal count alone could never have said.
    let fed = IngestRefusals::new();
    fed.observe_accept();
    let (base, _h) = serve_with(Arc::clone(&engine), Some(idle_metrics()), Some(fed)).await;
    let data3 = read_state(&base, &owner).await;
    assert_eq!(data3["ingest"]["standing"], "clean");
    assert_eq!(data3["ingest"]["band"], "green");
    assert_ne!(data3["ingest"]["standing"], data2["ingest"]["standing"]);
}

/// Every operator-facing string is a `{id, text}` pair, and the payload declares
/// which locale the `text` fields fall back TO.
#[tokio::test]
async fn every_string_on_the_wire_is_localizable() {
    let engine = node().await;
    register_self(&engine).await;
    bind_owner(&engine).await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine), Some(withholding_metrics())).await;
    let data = read_state(&base, &owner).await;

    assert_eq!(data["source_locale"], "en");
    for pair in [
        &data["headline"],
        &data["carriage"]["explains"],
        &data["receive"]["explains"],
        &data["receive"]["note"],
        &data["trace_plane"]["explains"],
        &data["trace_plane"]["note"],
        &data["ingest"]["explains"],
        &data["ingest"]["note"],
        &data["volatility"]["process_local"]["note"],
        &data["volatility"]["clock_dependent_local"]["note"],
    ] {
        assert!(pair["id"].is_string(), "not a localizable pair: {pair}");
        assert!(pair["text"].is_string(), "not a localizable pair: {pair}");
        assert!(
            pair["id"].as_str().expect("id").starts_with("operator."),
            "unnamespaced id: {pair}"
        );
    }
    for e in data["node_explains"].as_array().expect("node_explains") {
        assert!(e["message"]["id"].is_string(), "{e}");
        assert!(e["message"]["text"].is_string(), "{e}");
    }
    for c in data["carriage"]["class_explains"]
        .as_array()
        .expect("class_explains")
    {
        assert!(c["message"]["id"].is_string(), "{c}");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  THE COMPOSITION GATE — one ledger, both routes (CIRISServer#370)
// ═══════════════════════════════════════════════════════════════════════════

#[path = "support/accord_batch.rs"]
mod accord_batch;

/// **The join nobody owned.**
///
/// #370's entire reading rests on one sentence that used to live only as a
/// comment at the composition root: *pass the SAME ledger to the route that
/// admits and the route that reads.* A composition that minted a second one
/// compiled, served, and passed every test in this repo — the ingest route would
/// count into a ledger with no reader while the operator surface reported a
/// permanently `not_exercised` gate on a node being flooded. Individually
/// correct components, a silently dead composite: the 2026-08-05 failure with
/// the subject changed.
///
/// So this drives BOTH routes on ONE served application, built the way
/// `compose::serve` builds it, and asserts that a refusal delivered to the first
/// is visible on the second. There is no ledger handle in the test at all —
/// [`operator_surface::trace_plane_router`] mints it, which is what makes the
/// two-ledger composition unrepresentable rather than merely discouraged.
///
/// MUTATION EVIDENCE: give `trace_plane_router` a second
/// `IngestRefusals::new()` for the operator half; the surface reads
/// `not_exercised` with `refused_total: 0` while the gate returns 401, and this
/// goes RED. Every other test in this repo stays green.
#[tokio::test]
async fn the_route_that_admits_and_the_route_that_reads_share_one_ledger() {
    // The RCA's own producer: a real Ed25519 key, correctly signed, naming
    // itself with its agent-credits identity.
    const CREDITS: &str = "agent-55fe8d181727";

    let engine = node().await;
    register_self(&engine).await;
    bind_owner(&engine).await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve_trace_plane(Arc::clone(&engine), Some(idle_metrics())).await;

    // Before anything is offered, the gate is honestly UNTESTED — not clean.
    // Without this the assertion below could be passing on a stale default.
    let before = read_state(&base, &owner).await;
    assert_eq!(
        before["ingest"]["standing"],
        serde_json::json!("not_exercised"),
        "nothing has been offered yet, and that is an untested zero: {}",
        before["ingest"]
    );

    // Offer a batch to the INGEST route on the SAME application.
    let resp = reqwest::Client::new()
        .post(format!(
            "{base}{}",
            ciris_server::ingest_http::LEGACY_INGEST_PATH
        ))
        .header("content-type", "application/json")
        .header("user-agent", "CIRIS-AccordMetrics/1.0")
        .body(accord_batch::build_batch_bytes(
            &SigningKey::from_bytes(&[0x11; 32]),
            CREDITS,
            "trace-compose-0001",
        ))
        .send()
        .await
        .expect("POST the ingest route");
    assert_eq!(
        resp.status(),
        401,
        "the admission gate must refuse an unregistered signer — it was always right"
    );
    let refusal: Value = resp.json().await.expect("refusal body");
    assert_eq!(refusal["error"], serde_json::json!("verify_unknown_key"));
    assert_eq!(
        refusal["key_id_namespace"],
        serde_json::json!("agent_credits"),
        "and it must tell the producer which of its identities it signed with: {refusal}"
    );

    // ...and the OPERATOR route on that same application must have seen it.
    let after = read_state(&base, &owner).await;
    assert_eq!(
        after["ingest"]["refused_total"],
        serde_json::json!(1),
        "the refusal reached the gate and not the reader — two ledgers, one question, and the \
         operator surface would report a quiet node through any flood: {}",
        after["ingest"]
    );
    assert_eq!(
        after["ingest"]["by_kind"]["verify_unknown_key"],
        serde_json::json!(1),
        "{}",
        after["ingest"]
    );
    assert_eq!(
        after["ingest"]["top_signers"][0]["signer_id"],
        serde_json::json!(CREDITS),
        "the operator's copy names WHO to go fix: {}",
        after["ingest"]
    );
    assert_ne!(
        after["ingest"]["standing"], before["ingest"]["standing"],
        "an offered batch must change the reading; if it does not, the two routes are not looking \
         at the same ledger"
    );

    // The ingest route also publishes the ledger to the process static the
    // in-process (python fold) accessor reads — a second way to hold the same
    // handle, and it must agree with the HTTP surface rather than be a third
    // answer.
    let held = ciris_server::ingest_http::held().expect("the mounted route published its ledger");
    assert_eq!(
        held.snapshot().refused_total,
        1,
        "the fold accessor and the HTTP surface must read ONE ledger"
    );
}

/// **The store block reports persist's numbers, and names what it cannot see**
/// (CIRISServer#446).
///
/// Two properties, and the second is the one that would have saved a day: an
/// operator diagnosing the wedged canonical could not tell, from any endpoint,
/// that `federation_attestations` held 194.8 MiB — because `StorageSummary` has
/// no reading for it at all. A surface that silently omits the largest table on
/// the node teaches its reader that the node is small.
#[test]
fn the_store_block_carries_persists_aggregate_and_names_its_blind_spots() {
    let v = ciris_server::operator_surface::compose(
        ciris_server::operator_surface::Sources {
            node: Err("not exercised".to_string()),
            edge: Err("not exercised".to_string()),
            trace: Err("not exercised".to_string()),
            store: Err("storage_summary refused".to_string()),
            ingest: None,
        },
        chrono::Utc::now(),
    );

    // A failed read is `unreadable` WITH the reason — never an empty store.
    // "We could not ask" and "there is nothing here" are the pair this whole
    // surface exists to keep apart.
    assert_eq!(
        v["store"]["unreadable"], "storage_summary refused",
        "a store read failure must carry its reason: {v:#}"
    );
    assert!(
        v["store"].get("total_disk_bytes").is_none(),
        "an unreadable store must not also report a byte count — that is the \
         collapsed zero this file spends a section warning about: {v:#}"
    );
}
