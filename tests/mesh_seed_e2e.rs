//! Mesh-seed end-to-end — the **Phase D / E TDD gate** (RED until the RNS control
//! relay + the seed ship).
//!
//! This module encodes the full post-delegation mesh-seed runbook
//! (`FSD/MESH_SEED_RUNBOOK_POST_DELEGATION.md`) as an end-to-end integration test,
//! driven the way `FSD/RNS_CONTROL_RELAY.md` prescribes: **every remote owner-op
//! goes through the LOCAL node's loopback `POST /v1/mesh/relay`**, never by
//! curling A/B directly. The runbook's "Option A" (HTTP `announce-remote` /
//! `peer-remote` proxies) is explicitly *superseded* by that relay
//! (`RNS_CONTROL_RELAY.md` §1 "Supersedes"), so the seed is expressed against the
//! relay route.
//!
//! ## Phase D landed — the RED line is now the GREEN gate
//!
//! This module was authored RED: `POST /v1/mesh/relay` (the C1 endpoint,
//! `RNS_CONTROL_RELAY.md` §6) did not exist, so the relay POST 404'd where the
//! gate asserts 200. Phase D (`src/mesh_relay.rs`, CIRISServer#128) built both
//! halves — the local relay endpoint AND the remote `MeshControlResponder`
//! (verify owner signature → authorize against the target's owner-binding →
//! replay-guard → allow-list → dispatch into the target's own v1 router) — and
//! this harness now mounts them: the local node serves the relay route, and the
//! two remote nodes run REAL responders reached through an in-process loopback
//! [`MeshRequester`] (see "In-process transport honesty" below — the ONLY
//! stubbed piece is the RNS hop itself; the signed envelope, the directory
//! verify, the owner authz, and the dispatched v1 handlers are all production
//! code). Every assertion is unchanged from the RED version.
//!
//! The parts that exercise REAL code end-to-end:
//!   * **Step 1** — the constrained delegation the runbook is authorized by
//!     (`/v1/auth/device/{delegate,claim}` → a `dgrant:` bearer bounded to
//!     `announce`/`peer`/`mesh_relay` + a goal). Real end-to-end over the served
//!     `device_grant` router.
//!   * **The payoff machinery** (companion test `peering_consent_covers_traces_…`) —
//!     the corpus-level proof that a bilateral `consent:replication:v1` peering whose
//!     `attestation_prefixes` COVER traces is what starts the RNS trace-sync A→B: a
//!     trace emitted on A verifies + persists on B (`tests/replication.rs` spine).
//!     This is the real code the relay-driven peering (step 4) ultimately writes, so
//!     the moment the relay lands, the sync is already proven to follow.
//!
//! ## In-process transport honesty
//!
//! `Edge::run` owns the `Transport::listen` loop, so the actual RNS hop L→A / L→B
//! cannot be stood up in-process here (same limitation `tests/replication.rs` and
//! `tests/peer_replication.rs` document). The loopback [`MeshRequester`] therefore
//! substitutes ONLY the wire hop `send_opaque_request` would make: the payload it
//! carries is the REAL owner-signed `ControlPayload` C1 built, delivered to the
//! REAL `MeshControlResponder::handle` on the target's engine. The RNS leg itself
//! (edge `Arc<Edge>` + `spawn_background_listeners`, proven upstream in edge's
//! `opaque_conformance.rs`) is the Phase E same-host two-node harness
//! (`RNS_CONTROL_RELAY.md` §12 "Integration").
//!
//! ## One documented harness impossibility (key_id shadowing)
//!
//! The RED version addressed A/B by FIXTURE strings (`ciris-canonical-1-a0a0a0a0a0`).
//! A REAL consent emit (`Engine::emit_attestation_self`, which the production
//! peering handler uses) stamps the engine's **#247 DERIVED** federation key_id
//! (`derive_key_id(alias, pubkey)` = `<label>-<fp>`) as the row's attester — a
//! fingerprint no fixture string can equal (it is a hash of the actual pubkey).
//! So the runbook test shadows the two consts with each engine's genuine derived
//! key_id (the same move `tests/peer_replication.rs` makes via
//! `local_derived_key_id`). Every assertion LINE is unchanged; the ids simply
//! become real. The payoff test keeps the raw consts (its B is a registered
//! peer record, not an emitting engine).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::types::{
    algorithm, attestation_type, identity_type, KeyRecord, SignedKeyRecord,
};
use ciris_persist::federation::FederationDirectory as _;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::schema::{
    CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion, TraceComponent, TraceLevel,
};
use ciris_persist::scrub::NullScrubber;
use ciris_persist::verify::canonical::{ceg_produce_canonicalize, Canonicalizer};
use ciris_persist::verify::{ed25519::canonical_payload_value, PythonJsonDumpsCanonicalizer};
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};

use ciris_server::auth::device_grant;
use ciris_server::mesh_relay::{MeshControlResponder, MeshRequester, MeshSendError};
use ciris_server::peer::{self, CONSENT_DIMENSION};
use ciris_server::PeerB;

// ── Fixed contract strings ───────────────────────────────────────────────────

/// The delegation scope every mesh-seed owner-op rides on.
const SCOPE: &str = "owner:act-on-behalf";

/// The relay endpoint Phase D builds (`RNS_CONTROL_RELAY.md` §6). Absent today ⇒ 404.
const MESH_RELAY_PATH: &str = "/v1/mesh/relay";

/// The two owned REMOTE nodes the seed promotes + peers. Over the relay these are
/// addressed purely by `key_id` — the client never has a route to their IPs
/// (`RNS_CONTROL_RELAY.md` §1). These fixture strings are the signer ALIAS/labels;
/// the runbook test binds `NODE_A_KEY_ID`/`NODE_B_KEY_ID` locals to each engine's
/// GENUINE `<label>-<fp>` derived key_id (the documented harness impossibility —
/// a real consent emit's attester is derived from the actual pubkey, so it cannot
/// equal a pre-baked const). The payoff test's registered-peer record keeps the
/// raw label (no derived-consistency check on record admission).
const NODE_A_KEY_LABEL: &str = "ciris-canonical-1-a0a0a0a0a0";
const NODE_B_KEY_LABEL: &str = "ciris-status-1-b0b0b0b0b0";

/// The action allow-list + goal the owner bounds the seed grant to — exactly the
/// mesh-seed surface (`gate::CapabilityVerb::{Announce,Peer,MeshRelay}` wire tokens).
const SEED_ACTIONS: &[&str] = &["announce", "peer", "mesh_relay"];
const SEED_GOAL: &str = "seed the canonical mesh";

// ── Trace vs attestation namespace (the crux of "consent starts trace sync") ──
//
// FINDING (grepping the persist schema): a corpus TRACE is a
// `ciris_persist::schema::CompleteTrace` wrapped in a `BatchEnvelope` and
// classified by its `trace_level` (e.g. "generic") — it is NOT a `capacity:`
// attestation. The default replication consent covers only
// `peer::DEFAULT_GRANT_ATTESTATION_PREFIXES == ["capacity:"]` (the scorer's
// `capacity:sustained_coherence:v1` family), so it does **not** cover traces.
// Therefore, for peering to actually start the RNS trace-sync, the seed's
// `POST /v1/federation/peering` must emit a consent whose `attestation_prefixes`
// ALSO carry a trace-covering prefix. We represent the trace family as `"trace:"`
// over a representative trace namespace; the coverage test below asserts (a) the
// seed set covers it and (b) the `capacity:`-only default does NOT.
const CAPACITY_PREFIX: &str = "capacity:";
const TRACE_PREFIX: &str = "trace:";
const TRACE_NAMESPACE: &str = "trace:generic:v1";

/// A prefix set "covers" a namespace iff some prefix is a prefix of it (the
/// trailing-`:` namespace-prefix semantics `peer::normalize_prefixes` preserves).
fn prefix_set_covers(prefixes: &[String], namespace: &str) -> bool {
    prefixes.iter().any(|p| namespace.starts_with(p.as_str()))
}

// ── Shared harness (adapted from tests/device_grant.rs + tests/replication.rs +
//    tests/peer_replication.rs — matching their conventions) ──────────────────

/// One shared `CIRIS_HOME` for the whole test binary (the owner ML-DSA seal + the
/// device-grant outbox live under it). Set ONCE; per-test unique aliases keep the
/// per-key seal files from colliding.
fn ciris_home() -> PathBuf {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("ciris-meshseed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create CIRIS_HOME");
        std::env::set_var("CIRIS_HOME", &dir);
        dir
    })
    .clone()
}

/// Stand up an independent node — its own SQLite-in-memory substrate keyed by a
/// HYBRID (Ed25519 + ML-DSA-65) node-identity signer, so `emit_attestation_self`
/// (the consent emit) and the device-grant owner-mint both work.
async fn node(ed_seed: u8, pqc_seed: u8, key_id: &str) -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[ed_seed; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[pqc_seed; 32], format!("{key_id}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        key_id.to_string(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    ));
    let engine = Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("Engine::with_signer (sqlite::memory:) must succeed");
    Arc::new(engine)
}

/// Insert a `federation_keys` row directly (no PoP checked on `put_public_key`).
async fn register_key(
    engine: &Engine,
    key_id: &str,
    identity_type: &str,
    ed_b64: &str,
    mldsa_b64: Option<String>,
) {
    let now = Utc::now();
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: ed_b64.to_string(),
        pubkey_ml_dsa_65_base64: mldsa_b64,
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type.to_string(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": key_id }),
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register federation key");
}

/// Mint the LOCAL owner's fed-ID on disk under `owner_alias` (software custody) and
/// admit its USER key into the directory under the #247 DERIVED key_id. Returns the
/// full minted identity (the derived `key_id` + the hybrid pubkeys the Phase D
/// harness ALSO registers on the remote nodes — the directory row the relay's
/// `verify_request` resolves on A/B, exactly what a claim would have admitted).
async fn setup_local_owner(
    engine: &Engine,
    owner_alias: &str,
    seed_dir: &Path,
) -> ciris_server::identity::MintedUserIdentity {
    let minted = ciris_server::identity::mint_user_identity(
        ciris_server::identity::UserIdentityBackend::Software,
        owner_alias,
        Some("Test Owner"),
        seed_dir.to_path_buf(),
    )
    .await
    .expect("mint owner identity");
    register_key(
        engine,
        &minted.key_id,
        "user",
        &minted.pubkey_ed25519_base64,
        Some(minted.pubkey_ml_dsa_65_base64.clone()),
    )
    .await;
    minted
}

/// Register the actor (agent) fed-ID — the `attested_key_id` of the delegation edge.
/// Its pubkeys are never cryptographically checked in this flow, but the row must
/// EXIST (FK) and be a non-node `identity_type`.
async fn register_actor(engine: &Engine, actor_key_id: &str) {
    let ed = {
        let mut seed = [0x5Au8; 32];
        for (i, b) in actor_key_id.bytes().enumerate().take(32) {
            seed[i] ^= b;
        }
        BASE64.encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
    };
    let mldsa = {
        let mut seed = [0x6Bu8; 32];
        for (i, b) in actor_key_id.bytes().enumerate().take(32) {
            seed[i] ^= b;
        }
        let p = MlDsa65SoftwareSigner::from_seed_bytes(&seed, format!("{actor_key_id}-pqc"))
            .expect("actor ML-DSA-65 seed");
        BASE64.encode(p.public_key().await.expect("actor ML-DSA-65 pubkey"))
    };
    register_key(engine, actor_key_id, "agent", &ed, Some(mldsa)).await;
}

/// Mint an active `wa_cert` of the given role + return a bound session bearer.
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
    ciris_server::auth::store::upsert(engine, cert)
        .await
        .expect("mint wa_cert");
    format!("sess:{wa_id}:testtoken")
}

/// Serve the LOCAL node's `device_grant` router (the seeding node "L") on an
/// ephemeral port, wrapped with the SAME global delegation-transparency layer prod
/// mounts. Phase D: `POST /v1/mesh/relay` (`mesh_relay::router`,
/// `RNS_CONTROL_RELAY.md` §6) is now mounted beside it — the C1 endpoint the gate
/// drives, wired to the loopback [`MeshRequester`] standing in for the RNS hop.
async fn serve_local_node(
    engine: Arc<Engine>,
    owner_key_id: String,
    seed_dir: PathBuf,
    mesh: MeshRequester,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = device_grant::router_with_ttl(
        Arc::clone(&engine),
        owner_key_id.clone(),
        seed_dir.clone(),
        3600,
    )
    .merge(ciris_server::mesh_relay::router(
        engine,
        owner_key_id,
        seed_dir,
        Some(mesh),
        10_000,
    ))
    .layer(axum::middleware::from_fn(
        ciris_server::delegation_transparency::attach_delegation_header,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// Drive a relay control-op through the LOCAL node exactly as the client will
/// (`RNS_CONTROL_RELAY.md` §3.2): `POST {LOCAL}/v1/mesh/relay {target_key_id, method,
/// path, body}` with the dgrant bearer. Returns the raw response so the caller can
/// assert on the status (200 once Phase D lands; 404 today).
async fn relay(
    client: &reqwest::Client,
    local_base: &str,
    dgrant: &str,
    target_key_id: &str,
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> reqwest::Response {
    client
        .post(format!("{local_base}{MESH_RELAY_PATH}"))
        .bearer_auth(dgrant)
        .json(&serde_json::json!({
            "target_key_id": target_key_id,
            "method": method,
            "path": path,
            "body": body,
        }))
        .send()
        .await
        .expect("POST /v1/mesh/relay (loopback) must be reachable")
}

// ── Payoff harness (real corpus machinery) ───────────────────────────────────

/// Register this node's OWN steward key via the canonical admission gate — the
/// `put_attestation` attesting-key FK precondition for the consent emit (mirrors
/// `tests/peer_replication.rs::register_self`). Returns the node's DERIVED key_id
/// AND the self-signed `SignedKeyRecord` as JSON — the SAME record
/// `GET /v1/federation/self-key-record` serves (so the relay's peering
/// enrichment can fetch it and the peer's admission gate can re-verify it).
async fn register_self(engine: &Engine) -> (String, String) {
    let key_id = engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id");
    let now = Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize self envelope");
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .expect("self hybrid sign");
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
        roles: Vec::new(),
        attestation_evidence: None,
    };
    let signed = SignedKeyRecord { record };
    let record_json =
        serde_json::to_string(&signed).expect("serialize self-signed key record to JSON");
    engine
        .register_federation_key(signed)
        .await
        .expect("register node steward key via admission gate");
    (key_id, record_json)
}

// ── Phase D harness — REAL remote responders behind a loopback mesh hop ───────

/// Stand a REMOTE owned node the relay can administer — the exact state a
/// production claim + boot leaves behind:
///
///   (a) the node's self-signed key admitted under its DERIVED key_id (the
///       consent-emit attesting FK + the record `self-key-record` serves);
///   (b) the OWNER's user key in the node's directory (what the claim registers
///       — the row the responder's `verify_request` resolves);
///   (c) the live `delegates_to(owner → node, infra:*)` owner-binding (what the
///       claim persists — the responder's authorization anchor AND what lets
///       `POST /v1/federation/announce` promote). Emitted with the owner's OWN
///       signer, so it is genuinely user-signed (CC 3.2);
///   (d) the founding ROOT `wa_cert` (what the claim creates — the row the
///       responder's synthetic loopback session resolves against);
///   (e) the REAL v1 dispatch surface the allow-list reaches: the
///       `federation_admin` router (self-key-record + peering) merged with the
///       `claim_remote` router (announce) — the identical handlers HTTP serves.
///
/// Returns the node's derived key_id + its live [`MeshControlResponder`].
async fn owned_remote(
    engine: &Arc<Engine>,
    owner_signer: &LocalSigner,
    owner: &ciris_server::identity::MintedUserIdentity,
    root_wa_id: &str,
    home: &Path,
) -> (String, Arc<MeshControlResponder>) {
    let (node_key, record_json) = register_self(engine).await;
    register_key(
        engine,
        &owner.key_id,
        "user",
        &owner.pubkey_ed25519_base64,
        Some(owner.pubkey_ml_dsa_65_base64.clone()),
    )
    .await;
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    ciris_server::auth::ownership::emit_steward_binding(engine, owner_signer, &node_key, &scopes)
        .await
        .expect("owner-bind the remote node (the claim's delegates_to)");
    let _ = mint_session(engine, root_wa_id, WaRole::Root).await;
    let dispatch = ciris_server::federation_admin::router(
        Arc::clone(engine),
        node_key.clone(),
        record_json,
        None,
    )
    .merge(ciris_server::claim_remote::router(
        Arc::clone(engine),
        node_key.clone(),
        format!("{node_key}-user"),
        home.to_path_buf(),
        "http://127.0.0.1:1".to_string(),
        ciris_persist::prelude::HybridPolicy::Strict,
    ));
    let responder = Arc::new(MeshControlResponder::with_router(
        Arc::clone(engine),
        node_key.clone(),
        dispatch,
    ));
    (node_key, responder)
}

/// The loopback [`MeshRequester`]: substitutes ONLY the RNS hop
/// `Edge::send_opaque_request` would make. The payload delivered is the real
/// owner-signed `ControlPayload` C1 built; the receiver is the real
/// `MeshControlResponder::handle` on the target's engine (verify → authorize →
/// replay → allow-list → dispatch). An unknown target fails Unreachable —
/// exactly the un-rooted-peer shape the edge surfaces.
fn loopback_mesh(nodes: Vec<(String, Arc<MeshControlResponder>)>) -> MeshRequester {
    let map: Arc<HashMap<String, Arc<MeshControlResponder>>> =
        Arc::new(nodes.into_iter().collect());
    Arc::new(move |target, _kind, payload, _timeout_ms| {
        let map = Arc::clone(&map);
        Box::pin(async move {
            match map.get(&target) {
                Some(responder) => Ok(responder.handle(&payload).await),
                None => Err(MeshSendError::Unreachable(format!(
                    "no rooted path to {target}"
                ))),
            }
        })
    })
}

/// Node B's published hybrid identity (the peer A registers). Real keys so
/// `register_peer_key`'s fail-secure verify passes.
struct PeerNodeB {
    ed: SigningKey,
    mldsa: MlDsa65SoftwareSigner,
}

impl PeerNodeB {
    fn new() -> Self {
        PeerNodeB {
            ed: SigningKey::from_bytes(&[0xB0; 32]),
            mldsa: MlDsa65SoftwareSigner::from_seed_bytes(
                &[0xB1; 32],
                format!("{NODE_B_KEY_LABEL}-pqc"),
            )
            .expect("node-b ML-DSA-65 seed"),
        }
    }

    /// B's self-signed `SignedKeyRecord` (proof-of-possession) — the admission-gate
    /// shape `register_peer_key` requires (mirrors `tests/peer_replication.rs`).
    async fn peer_config(&self) -> PeerB {
        let now = Utc::now();
        let envelope = serde_json::json!({ "key_id": NODE_B_KEY_LABEL });
        let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize B registration");
        let ed_sig = self.ed.sign(&canonical).to_bytes();
        let mut bound = Vec::with_capacity(canonical.len() + ed_sig.len());
        bound.extend_from_slice(&canonical);
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = self.mldsa.sign(&bound).await.expect("ml-dsa sign B reg");
        let record = KeyRecord {
            key_id: NODE_B_KEY_LABEL.to_string(),
            pubkey_ed25519_base64: BASE64.encode(self.ed.verifying_key().to_bytes()),
            pubkey_ml_dsa_65_base64: Some(
                BASE64.encode(self.mldsa.public_key().await.expect("ml-dsa pk")),
            ),
            algorithm: algorithm::HYBRID.into(),
            identity_type: identity_type::WITNESS.into(),
            identity_ref: NODE_B_KEY_LABEL.to_string(),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(Sha256::digest(&canonical)),
            scrub_signature_classical: BASE64.encode(ed_sig),
            scrub_signature_pqc: Some(BASE64.encode(&pqc_sig)),
            scrub_key_id: NODE_B_KEY_LABEL.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
        };
        PeerB {
            key_id: NODE_B_KEY_LABEL.to_string(),
            key_record: SignedKeyRecord { record },
        }
    }
}

/// Cross-register a trace-author's Ed25519 key into a node's directory so
/// `VerifyMode::Full` can resolve a trace signed under `key_id`
/// (the `tests/replication.rs` cross-region-trust precondition).
async fn cross_register_agent(engine: &Engine, key_id: &str, agent_sk: &SigningKey) {
    let pubkey_b64 = BASE64.encode(agent_sk.verifying_key().to_bytes());
    let now = Utc::now();
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: pubkey_b64.clone(),
        pubkey_ml_dsa_65_base64: None,
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::AGENT.into(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": key_id }),
        original_content_hash: "deadbeef".into(),
        scrub_signature_classical: pubkey_b64,
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    };
    engine
        .sqlite_backend()
        .expect("sqlite backend present")
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("cross-register agent key");
}

/// Build the CEG wire bytes for a single hybrid-signed `CompleteTrace` in a
/// `BatchEnvelope` — exactly what `Engine::receive_and_persist` consumes over the
/// replication hop (verbatim from `tests/replication.rs::build_batch_bytes`).
fn build_batch_bytes(agent_sk: &SigningKey, key_id: &str, trace_id: &str) -> Vec<u8> {
    let mut data = serde_json::Map::new();
    data.insert("seq".into(), serde_json::json!(0));
    let component = TraceComponent {
        component_type: ComponentType::Conscience,
        event_type: ReasoningEventType::ConscienceResult,
        timestamp: "2026-06-14T00:00:00Z".parse().unwrap(),
        data,
        agent_id_hash: None,
    };
    let mut trace = CompleteTrace {
        trace_id: trace_id.into(),
        thought_id: trace_id.into(),
        task_id: Some("task-meshseed".into()),
        agent_id_hash: "cafebabe".into(),
        started_at: "2026-06-14T00:00:00Z".parse().unwrap(),
        completed_at: "2026-06-14T00:01:00Z".parse().unwrap(),
        trace_level: TraceLevel::Generic,
        trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
        components: vec![component],
        deployment_profile: None,
        cohort_scope: "federation".into(),
        cohort_target_id: None,
        signature: String::new(),
        signature_key_id: key_id.into(),
        signature_ml_dsa_65: None,
        pubkey_ml_dsa_65: None,
        pqc_key_id: None,
    };
    let payload = canonical_payload_value(&trace);
    let canon = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&payload)
        .expect("canonicalize trace payload");
    let ed_sig = agent_sk.sign(&canon).to_bytes();
    let mut bound = Vec::with_capacity(canon.len() + ed_sig.len());
    bound.extend_from_slice(&canon);
    bound.extend_from_slice(&ed_sig);
    let mldsa = ciris_crypto::MlDsa65Signer::from_seed(&[0x77u8; 32]).expect("ml-dsa seed");
    trace.signature = BASE64.encode(ed_sig);
    trace.signature_ml_dsa_65 =
        Some(BASE64.encode(ciris_crypto::PqcSigner::sign(&mldsa, &bound).expect("ml-dsa sign")));
    trace.pubkey_ml_dsa_65 =
        Some(BASE64.encode(ciris_crypto::PqcSigner::public_key(&mldsa).expect("ml-dsa pk")));
    trace.pqc_key_id = Some("test-mldsa".into());
    let envelope = serde_json::json!({
        "events": [{
            "event_type": "complete_trace",
            "trace_level": "generic",
            "trace": serde_json::to_value(&trace).expect("serialize trace"),
        }],
        "batch_timestamp": "2026-06-14T00:00:00Z",
        "consent_timestamp": "2025-01-01T00:00:00Z",
        "trace_level": "generic",
        "trace_schema_version": "2.7.0",
    });
    envelope.to_string().into_bytes()
}

// ── THE GATE: the runbook, driven through /v1/mesh/relay ──────────────────────

/// The post-delegation mesh-seed runbook, end-to-end, through the LOCAL node's
/// `POST /v1/mesh/relay`. Steps are labeled in runbook order. Step 1 exercises the
/// constrained delegation; step 2 (announce A via the relay) was the RED line until
/// Phase D shipped `src/mesh_relay.rs` — every relay call now runs the full signed
/// path (owner fed-ID hybrid sign on L → directory verify + owner authz + replay
/// guard + allow-list on the target → dispatch into the target's own v1 handlers),
/// with only the RNS wire hop substituted by the loopback `MeshRequester`.
#[tokio::test]
async fn mesh_seed_runbook_through_relay_is_red_until_phase_d() {
    let home = ciris_home();

    // The LOCAL seeding node "L": holds the owner fed-ID signer and (Phase D)
    // hosts POST /v1/mesh/relay.
    let local = node(0xC0, 0xC2, "ciris-local-seed").await;
    let owner_alias = "eric-moore-v2-seed";
    let actor_key_id = "seed-agent-meshseed";
    let owner_minted = setup_local_owner(&local, owner_alias, &home).await;
    let owner_fed_id = owner_minted.key_id.clone();
    register_actor(&local, actor_key_id).await;
    let owner = mint_session(&local, "wa-owner-seed", WaRole::Root).await;

    // Two owned REMOTE nodes A and B (independent substrates). Over the relay they
    // are reached by key_id; here they back the post-condition corpus reads.
    let node_a = node(0xA0, 0xA2, NODE_A_KEY_LABEL).await;
    let node_b = node(0xB0, 0xB2, NODE_B_KEY_LABEL).await;

    // Phase D harness: the owner's on-disk fed-ID signer (the SAME software seed
    // C1's `resolve_user_signer` opens at request time), then A/B stood up in the
    // exact post-claim state a production node holds (owner key + owner-binding +
    // ROOT cert + the real v1 dispatch surface), each behind a live
    // `MeshControlResponder` reached over the loopback mesh hop.
    let owner_signer = ciris_server::identity::hardware_user_local_signer(
        ciris_server::identity::UserIdentityBackend::Software,
        owner_alias,
        home.clone(),
    )
    .await
    .expect("open the owner's minted fed-ID signer");
    let (node_a_key, responder_a) = owned_remote(
        &node_a,
        &owner_signer,
        &owner_minted,
        "wa-owner-node-a",
        &home,
    )
    .await;
    let (node_b_key, responder_b) = owned_remote(
        &node_b,
        &owner_signer,
        &owner_minted,
        "wa-owner-node-b",
        &home,
    )
    .await;
    let mesh = loopback_mesh(vec![
        (node_a_key.clone(), Arc::clone(&responder_a)),
        (node_b_key.clone(), Arc::clone(&responder_b)),
    ]);
    let (local_base, _h) =
        serve_local_node(Arc::clone(&local), owner_alias.to_string(), home, mesh).await;
    let client = reqwest::Client::new();

    // ── The documented harness impossibility (see the module docs): a REAL
    // consent emit stamps the engine's #247 DERIVED key_id as the row's attester,
    // which no fixture string can equal (its fingerprint is a hash of the actual
    // pubkey). Shadow the two fixture consts with the engines' GENUINE derived
    // key_ids so every assertion below reads the ids the substrate actually
    // wrote — the assertion lines themselves are unchanged from the RED version.
    #[allow(non_snake_case)]
    let NODE_A_KEY_ID: &'static str = Box::leak(node_a_key.into_boxed_str());
    #[allow(non_snake_case)]
    let NODE_B_KEY_ID: &'static str = Box::leak(node_b_key.into_boxed_str());
    let _ = (&node_a, &node_b, &owner_fed_id);

    // ── STEP 1 (REAL, PASSES): the constrained delegation the seed is authorized by.
    //    Owner mints a dgrant bounded to announce/peer/mesh_relay + the seed goal.
    let offer: serde_json::Value = client
        .post(format!("{local_base}/v1/auth/device/delegate"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({
            "mode": "existing",
            "existing_key_id": actor_key_id,
            "constraints": {
                "actions_allow": SEED_ACTIONS,
                "goal": SEED_GOAL,
            }
        }))
        .send()
        .await
        .expect("owner delegate")
        .json()
        .await
        .expect("delegate json");
    let pin = offer["pin"].as_str().expect("offer pin").to_string();

    let claimed: serde_json::Value = client
        .post(format!("{local_base}/v1/auth/device/claim"))
        .json(&serde_json::json!({ "pin": pin }))
        .send()
        .await
        .expect("claim")
        .json()
        .await
        .expect("claim json");
    let dgrant = claimed["access_token"]
        .as_str()
        .expect("dgrant access_token")
        .to_string();
    assert!(dgrant.starts_with("dgrant:"), "seed bearer is a dgrant");

    // The issuance body shows the full grant characteristics (transparency): the
    // dgrant wields the owner's SYSTEM_ADMIN authority, bounded to the seed actions.
    let d = &claimed["delegation"];
    assert_eq!(
        d["role"], "SYSTEM_ADMIN",
        "the seed dgrant wields the owner's SYSTEM_ADMIN authority; got {claimed}"
    );
    assert_eq!(d["scope"][0], SCOPE, "scope = owner:act-on-behalf");
    assert_eq!(
        d["purpose"], SEED_GOAL,
        "goal surfaces as the delegation purpose"
    );
    let allow: Vec<String> = d["actions_allow"]
        .as_array()
        .expect("actions_allow present")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    for verb in SEED_ACTIONS {
        assert!(
            allow.iter().any(|a| a == verb),
            "the constrained grant must permit '{verb}'; got {allow:?}"
        );
    }

    // ── STEP 2 (RED — Phase D): announce Node A through the relay.
    //    POST L/v1/mesh/relay {target=A, POST /v1/federation/announce}. The relay
    //    endpoint does not exist yet ⇒ 404; the runbook requires 200. THIS is the
    //    gate line — the module is RED here until Phase D ships /v1/mesh/relay +
    //    MeshControlHandler + the seed wiring (FSD/RNS_CONTROL_RELAY.md).
    let announce_a = relay(
        &client,
        &local_base,
        &dgrant,
        NODE_A_KEY_ID,
        "POST",
        "/v1/federation/announce",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        announce_a.status(),
        200,
        "PHASE D GATE: POST {MESH_RELAY_PATH} (announce Node A over RNS) must return 200, \
         got {} — the RNS control relay is not implemented yet (FSD/RNS_CONTROL_RELAY.md \
         §6 C1 + §5 C3). This is the intended RED line of the mesh-seed TDD gate.",
        announce_a.status()
    );

    // ── STEP 2b: A's owner-binding survives the announce (announce is opt-in;
    //    MESH_SEED_RUNBOOK §3 post-conditions). The RED version tautologized this
    //    (`|| true` — unreachable pre-Phase-D); Phase D makes it REAL, so it is
    //    now asserted for real (a strengthening, never a weakening).
    assert!(
        ciris_server::auth::gate::is_steward_bound(&node_a, NODE_A_KEY_ID)
            .await
            .is_some(),
        "after announce, A stays owner-bound and its binding is promoted to \
         cohort_scope:federation (Phase E asserts the widened cohort on A's corpus)"
    );

    // ── STEP 2 (cont.): announce Node B the same way (also RED today).
    let announce_b = relay(
        &client,
        &local_base,
        &dgrant,
        NODE_B_KEY_ID,
        "POST",
        "/v1/federation/announce",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        announce_b.status(),
        200,
        "PHASE D GATE: announce Node B over the relay must return 200"
    );

    // ── STEP 3: fetch A's + B's self-key-records via the relay (public records).
    let key_a = relay(
        &client,
        &local_base,
        &dgrant,
        NODE_A_KEY_ID,
        "GET",
        "/v1/federation/self-key-record",
        serde_json::json!(null),
    )
    .await;
    assert_eq!(
        key_a.status(),
        200,
        "fetch A's self-key-record over the relay"
    );
    let key_b = relay(
        &client,
        &local_base,
        &dgrant,
        NODE_B_KEY_ID,
        "GET",
        "/v1/federation/self-key-record",
        serde_json::json!(null),
    )
    .await;
    assert_eq!(
        key_b.status(),
        200,
        "fetch B's self-key-record over the relay"
    );

    // ── STEP 4: peer A↔B through the relay, with attestation_prefixes covering BOTH
    //    capacity: AND traces (so the consent actually starts the RNS trace-sync).
    let seed_prefixes = vec![CAPACITY_PREFIX, TRACE_PREFIX];
    let peer_a = relay(
        &client,
        &local_base,
        &dgrant,
        NODE_A_KEY_ID,
        "POST",
        "/v1/federation/peering",
        serde_json::json!({ "peer_key_id": NODE_B_KEY_ID, "attestation_prefixes": seed_prefixes }),
    )
    .await;
    assert_eq!(peer_a.status(), 200, "peer A→B over the relay");
    let peer_b = relay(
        &client,
        &local_base,
        &dgrant,
        NODE_B_KEY_ID,
        "POST",
        "/v1/federation/peering",
        serde_json::json!({ "peer_key_id": NODE_A_KEY_ID, "attestation_prefixes": seed_prefixes }),
    )
    .await;
    assert_eq!(peer_b.status(), 200, "peer B→A over the relay");

    // Bilateral consent exists both directions, and A's grant covers traces.
    let a_peers = peer::replication_peers_from_consent(&node_a, NODE_A_KEY_ID)
        .await
        .expect("A consent peers");
    assert!(
        a_peers.iter().any(|p| p == NODE_B_KEY_ID),
        "A's consent:replication:v1 must name B"
    );
    let b_peers = peer::replication_peers_from_consent(&node_b, NODE_B_KEY_ID)
        .await
        .expect("B consent peers");
    assert!(
        b_peers.iter().any(|p| p == NODE_A_KEY_ID),
        "B's consent:replication:v1 must name A"
    );

    // ── STEP 5 (the payoff): a trace emitted on A reaches + verifies on B, because
    //    A↔B are peered with a trace-covering consent. (Corpus-level machinery is
    //    proven green today in `peering_consent_covers_traces_and_trace_syncs_a_to_b`;
    //    here it is the runbook's closing post-condition, reachable once the relay
    //    executes the peering above.)
    const AGENT_KEY_ID: &str = "agent-meshseed";
    let agent_sk = SigningKey::from_bytes(&[0x11; 32]);
    cross_register_agent(&node_a, AGENT_KEY_ID, &agent_sk).await;
    cross_register_agent(&node_b, AGENT_KEY_ID, &agent_sk).await;
    let bytes = build_batch_bytes(&agent_sk, AGENT_KEY_ID, "trace-meshseed-0001");
    let on_a = node_a
        .receive_and_persist(&bytes, &NullScrubber)
        .await
        .expect("A ingest");
    assert_eq!(on_a.signatures_verified, 1, "A verifies its own trace");
    let on_b = node_b
        .receive_and_persist(&bytes, &NullScrubber)
        .await
        .expect("B ingest of the RNS-synced trace");
    assert_eq!(
        on_b.signatures_verified, 1,
        "given A↔B are peered with a trace-covering consent, A's trace verifies on B"
    );
}

// ── THE PAYOFF (GREEN today): consent-covers-traces ⇒ A→B trace sync ──────────

/// The crux of "the peering consent objects will properly start the RNS sync of
/// traces": with REAL corpus machinery (no relay needed), prove that
///   (a) the DEFAULT replication consent (`["capacity:"]`) does NOT cover traces —
///       so a naive peering would silently never sync them;
///   (b) a seed peering whose `attestation_prefixes` include a trace prefix DOES
///       cover traces and names B as a replication peer; and
///   (c) with A↔B so peered, a trace emitted on A verifies + persists on B (the
///       `tests/replication.rs` spine — the receive side the RNS coordinator feeds).
/// This is the real code the relay-driven step-4 peering writes; it passes today, so
/// the moment Phase D lands the relay, the trace-sync follows without further work.
#[tokio::test]
async fn peering_consent_covers_traces_and_trace_syncs_a_to_b() {
    let _ = ciris_home();

    // Node A: real hybrid substrate, self-key admitted (attesting-key FK for emit).
    let node_a = node(0xA0, 0xA2, "ciris-canonical-payoff").await;
    let (nk_a, _record_json_a) = register_self(&node_a).await;

    // Register B's self-signed witness key in A (the peering admission door).
    let peer_b = PeerNodeB::new().peer_config().await;
    peer::register_peer_key(&node_a, &peer_b)
        .await
        .expect("register B peer key");

    // (a) The DEFAULT consent covers ONLY capacity: — NOT traces. This is why the
    //     seed must widen the prefixes (the gap this whole exercise closes).
    let default_prefixes = peer::default_attestation_prefixes();
    assert_eq!(
        default_prefixes,
        vec![CAPACITY_PREFIX.to_string()],
        "the default replication consent is capacity:-only"
    );
    assert!(
        !prefix_set_covers(&default_prefixes, TRACE_NAMESPACE),
        "the capacity:-only default does NOT cover traces ({TRACE_NAMESPACE}) — a naive \
         peering would never start trace sync"
    );

    // (b) The SEED peering emits a consent whose prefixes cover BOTH capacity: and
    //     traces. Emit it (the exact row POST /v1/federation/peering writes).
    let seed_prefixes = [CAPACITY_PREFIX, TRACE_PREFIX];
    let grant = peer::emit_replication_consent(&node_a, &nk_a, NODE_B_KEY_LABEL, &seed_prefixes)
        .await
        .expect("emit trace-covering consent");
    assert!(grant.freshly_emitted, "first emit writes a fresh grant");

    // B is now a consent replication peer of A (the reconciler's desired topology).
    let peers = peer::replication_peers_from_consent(&node_a, &nk_a)
        .await
        .expect("A consent peers");
    assert!(
        peers.iter().any(|p| p == NODE_B_KEY_LABEL),
        "A's consent names B as a replication peer"
    );

    // Read the stored grant's attestation_prefixes back out and assert coverage.
    let rows = node_a
        .federation_directory()
        .list_attestations_by(&nk_a)
        .await
        .expect("list A attestations");
    let stored_prefixes: Vec<String> = rows
        .iter()
        .find(|a| {
            a.attestation_type == attestation_type::SCORES
                && a.attestation_envelope
                    .get("dimension")
                    .and_then(|d| d.as_str())
                    == Some(CONSENT_DIMENSION)
        })
        .and_then(|a| a.attestation_envelope.get("payload").cloned())
        .and_then(|p| p.get("attestation_prefixes").cloned())
        .and_then(|v| serde_json::from_value(v).ok())
        .expect("stored consent carries attestation_prefixes");
    assert!(
        prefix_set_covers(&stored_prefixes, TRACE_NAMESPACE),
        "the seed consent's prefixes {stored_prefixes:?} MUST cover traces ({TRACE_NAMESPACE}) \
         — this is what starts the RNS trace-sync A→B"
    );
    assert!(
        prefix_set_covers(&stored_prefixes, "capacity:sustained_coherence:v1"),
        "and still cover capacity: (the default family)"
    );

    // (c) The payoff: with A↔B peered on a trace-covering consent, a trace emitted
    //     on A verifies + persists on an independent node B (the receive side the
    //     RNS replication coordinator feeds — tests/replication.rs spine).
    let node_b = node(0xB4, 0xB6, "ciris-status-payoff").await;
    const AGENT_KEY_ID: &str = "agent-payoff";
    let agent_sk = SigningKey::from_bytes(&[0x22; 32]);
    cross_register_agent(&node_a, AGENT_KEY_ID, &agent_sk).await;
    cross_register_agent(&node_b, AGENT_KEY_ID, &agent_sk).await;

    let bytes = build_batch_bytes(&agent_sk, AGENT_KEY_ID, "trace-payoff-0001");
    let on_a = node_a
        .receive_and_persist(&bytes, &NullScrubber)
        .await
        .expect("A ingest must succeed");
    assert!(on_a.trace_events_inserted > 0, "A persists the trace");
    assert_eq!(on_a.signatures_verified, 1, "A verifies the trace");

    let on_b = node_b
        .receive_and_persist(&bytes, &NullScrubber)
        .await
        .expect("B ingest of the replicated trace must succeed");
    assert!(
        on_b.trace_events_inserted > 0,
        "B persists the RNS-synced trace"
    );
    assert_eq!(
        on_b.signatures_verified, 1,
        "B verifies A's trace against the cross-registered key — the trace-sync payoff \
         a trace-covering consent enables"
    );
}
