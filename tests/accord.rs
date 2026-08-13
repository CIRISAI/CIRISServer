//! HUMANITY_ACCORD server surface (CIRISServer#41, CC 4.2 / §9.2) — the
//! accord-holder registry + the server-canonical 2-of-3 invocation kill-switch.
//!
//! Drives the real `accord::router` over a bound TCP listener and proves:
//!   1. owner-gated `POST /v1/accord/holder` admits a holder's self-signed
//!      `accord_holder` record; `GET /v1/accord-holders` lists the cold-start
//!      recognition roster.
//!   2. `POST /v1/accord/verify-invocation` verifies a 2-of-3 holder invocation,
//!      REJECTS a 1-of-3 (quorum not met), and REJECTS a replay (dedup).
//!   3. registering a holder WITHOUT an owner session is rejected (401/403).

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};
use ciris_verify_core::humanity_accord::{Invocation, InvocationKind};

use ciris_verify_core::accord_genesis::{
    accord_family_signing_bytes, build_accord_invocation_object,
};
use ciris_verify_core::threshold::{Role, ThresholdMember, ThresholdSignature};

use ciris_server::accord;
use ciris_server::auth::store;

const NODE_KEY_ID: &str = "ciris-server";

async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    // The TEST-ONLY seam (persist v13.3.1 / CIRISPersist#387): a clean engine with the
    // genesis seed SKIPPED. Production seeds the keyless HUMANITY_ACCORD family (2/3,
    // A1/B1/C1) at boot — but these tests stand up their OWN custom-holder family via the
    // assemble ceremony (holders they can sign with), which the baked family would
    // UNIQUE-conflict + can't be signed for. Skipping the seed lets the ceremony run as the
    // real trust-root founding it exercises.
    let engine = Engine::with_signer_pre_genesis(signer, "sqlite::memory:")
        .await
        .expect("Engine::with_signer_pre_genesis (sqlite::memory:) must succeed");
    let engine = Arc::new(engine);
    // Register the node's OWN key (under its DERIVED id) so genesis recording via
    // emit_attestation_self (attester = the node) satisfies the FK. Mirrors prod
    // compose::register_self_key + the safety-test fixture.
    register_node_self(&engine).await;
    engine
}

/// Register the node's own federation key under its derived id (the genesis
/// `accord_family_genesis` record is a node-self attestation).
async fn register_node_self(engine: &Engine) {
    let now = chrono::Utc::now();
    let key_id = engine
        .local_derived_key_id()
        .await
        .expect("derive node key_id");
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize node envelope");
    let sig = engine.sign_hybrid(&canonical).await.expect("node sign");
    let record = KeyRecord {
        key_id: key_id.clone(),
        pubkey_ed25519_base64: BASE64.encode(&sig.classical.public_key),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(&sig.pqc.public_key)),
        algorithm: algorithm::HYBRID.into(),
        identity_type: "node".into(),
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
        .expect("register node self key");
}

/// Mint an active `wa_cert` + return a bound session bearer (`sess:<wa_id>:<rand>`).
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

/// An accord holder with a real hybrid identity (self-provisions its own key).
struct Holder {
    key_id: String,
    ed: SigningKey,
    mldsa: MlDsa65SoftwareSigner,
}

impl Holder {
    fn new(key_id: &str, seed: u8) -> Self {
        Holder {
            key_id: key_id.to_string(),
            ed: SigningKey::from_bytes(&[seed; 32]),
            mldsa: MlDsa65SoftwareSigner::from_seed_bytes(
                &[seed ^ 0xFF; 32],
                format!("{key_id}-pqc"),
            )
            .expect("holder ML-DSA-65 seed"),
        }
    }

    /// Structurally-valid hardware `attestation_evidence` (Android StrongBox) with
    /// a FRESH `nonce_captured_at`. persist's accord-holder gate refuses
    /// `SoftwareOnly` and requires this hardware provenance (the safe-mesh custody
    /// floor — CIRISVerify#91 provides the real attestation in prod; the gate does
    /// structural field-presence checks, not chain validation, so a structurally
    /// complete fixture is admitted).
    fn android_attestation_evidence() -> serde_json::Value {
        serde_json::json!({
            "platform_attestation": {
                "Android": {
                    "key_attestation_chain": [[48, 130], [48, 130]],
                    "play_integrity_token": "eyJhbGciOiJIUzI1NiJ9.fake.token",
                    "strongbox_backed": true,
                }
            },
            "nonce_captured_at": chrono::Utc::now().to_rfc3339(),
        })
    }

    /// The holder's self-signed `accord_holder` SignedKeyRecord (the canonical
    /// admission-gate shape — hybrid bound PoP over `ceg_produce_canonicalize` +
    /// the required hardware `attestation_evidence`).
    async fn signed_key_record(&self) -> SignedKeyRecord {
        let now = chrono::Utc::now();
        let envelope = serde_json::json!({ "key_id": self.key_id });
        let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize holder reg");
        let ed_sig = self.ed.sign(&canonical).to_bytes();
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = self
            .mldsa
            .sign(&bound)
            .await
            .expect("ml-dsa sign holder reg");
        let record = KeyRecord {
            key_id: self.key_id.clone(),
            pubkey_ed25519_base64: BASE64.encode(self.ed.verifying_key().to_bytes()),
            pubkey_ml_dsa_65_base64: Some(
                BASE64.encode(self.mldsa.public_key().await.expect("ml-dsa pk")),
            ),
            algorithm: algorithm::HYBRID.into(),
            identity_type: identity_type::ACCORD_HOLDER.into(),
            identity_ref: self.key_id.clone(),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(Sha256::digest(&canonical)),
            scrub_signature_classical: BASE64.encode(ed_sig),
            scrub_signature_pqc: Some(BASE64.encode(&pqc_sig)),
            scrub_key_id: self.key_id.clone(),
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: Some(Self::android_attestation_evidence()),
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        SignedKeyRecord { record }
    }

    /// This holder as a `ThresholdMember` (the genesis founder set / roster).
    async fn threshold_member(&self, role: Option<Role>) -> ThresholdMember {
        ThresholdMember {
            member_id: self.key_id.clone(),
            ed25519_public_key_base64: BASE64.encode(self.ed.verifying_key().to_bytes()),
            mldsa65_public_key_base64: Some(
                BASE64.encode(self.mldsa.public_key().await.expect("ml-dsa pk")),
            ),
            role,
        }
    }

    /// Co-sign the accord family envelope (Ed25519 over JCS signing-bytes; ML-DSA
    /// over bytes ‖ ed_sig) — a founder's genesis cosignature.
    async fn family_cosign(&self, envelope: &serde_json::Value) -> ThresholdSignature {
        let bytes = accord_family_signing_bytes(envelope).expect("family signing bytes");
        let ed_sig = self.ed.sign(&bytes).to_bytes();
        let mut bound = bytes.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = self.mldsa.sign(&bound).await.expect("ml-dsa family cosign");
        ThresholdSignature {
            member_id: self.key_id.clone(),
            ed25519_signature_base64: BASE64.encode(ed_sig),
            mldsa65_signature_base64: Some(BASE64.encode(&pqc_sig)),
        }
    }

    /// Cosign an invocation: Ed25519 over the §9.2.1 canonical bytes, ML-DSA-65
    /// over the BOUND input (canonical ‖ ed_sig) — the ThresholdSignature shape
    /// `verify_invocation`/`verify_threshold_signatures` checks.
    async fn cosign(&self, inv: &Invocation) -> serde_json::Value {
        let canonical = inv.canonical_bytes();
        let ed_sig = self.ed.sign(&canonical).to_bytes();
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = self.mldsa.sign(&bound).await.expect("ml-dsa cosign");
        serde_json::json!({
            "member_id": self.key_id,
            "ed25519_signature_base64": BASE64.encode(ed_sig),
            "mldsa65_signature_base64": BASE64.encode(&pqc_sig),
        })
    }

    /// Sign RAW bytes (bound hybrid) — for the membership-change payload
    /// `jcs(change_envelope)`.
    async fn sign_bytes(&self, bytes: &[u8]) -> serde_json::Value {
        let ed_sig = self.ed.sign(bytes).to_bytes();
        let mut bound = bytes.to_vec();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = self.mldsa.sign(&bound).await.expect("ml-dsa sign bytes");
        serde_json::json!({
            "member_id": self.key_id,
            "ed25519_signature_base64": BASE64.encode(ed_sig),
            "mldsa65_signature_base64": BASE64.encode(&pqc_sig),
        })
    }
}

async fn serve(engine: Arc<Engine>) -> (String, tokio::task::JoinHandle<()>) {
    serve_app(accord::router(engine)).await
}

/// Serve an explicit router (used by the operational-halt tests, which need a
/// `router_with_halt` carrying a temp `home` + `exit_on_halt: false`).
async fn serve_app(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// A typed invocation cosignature (the `/v1/accord/message` object embeds
/// `ThresholdSignature`s, not the loose JSON `cosign` produces).
async fn cosign_typed(h: &Holder, inv: &Invocation) -> ThresholdSignature {
    serde_json::from_value(h.cosign(inv).await).expect("cosign → ThresholdSignature")
}

/// Build a signed accord invocation object (what a peer/holder app delivers to
/// `/v1/accord/message`) from a roster + cosignatures.
fn invocation_object(
    roster: &[ThresholdMember],
    inv: &Invocation,
    sigs: &[ThresholdSignature],
) -> serde_json::Value {
    let obj = build_accord_invocation_object(
        "humanity-accord",
        roster,
        inv,
        sigs,
        "2026-06-20T00:00:00.000Z",
    );
    serde_json::to_value(obj).expect("invocation object → json")
}

/// A CONSTITUTIONAL halt invocation (the real kill — the 2-of-3 EmergencyShutdown).
fn constitutional_invocation(id: &str) -> Invocation {
    Invocation {
        invocation_kind: InvocationKind::Constitutional,
        invocation_id: id.to_string(),
        // verify v8.3.0: forbidden for every kind except `lifecycle:active`.
        resumes_halt_id: None,
        nonce: BASE64.encode([9u8; 32]),
        asserted_at: "2026-06-20T00:00:00.000Z".to_string(),
        valid_until: "2030-01-01T00:00:00.000Z".to_string(),
        payload_sha256: hex::encode(Sha256::digest(b"halt-payload")),
    }
}

/// Seat N holders DIRECTLY into the engine (via the persist admission gate), used by
/// the kill-switch LOGIC tests. The HTTP `POST /v1/accord/holder` endpoint now
/// MANDATES a FIPS YubiKey custody attestation (B1 fix) that a software test cannot
/// produce — that endpoint's custody gate is exercised by the dedicated rejection
/// tests (`holder_without_custody_attestation_is_rejected`,
/// `accord_holder_with_bogus_custody_attestation_is_rejected`). The roster/quorum/
/// halt logic is independent of HOW a holder reached persist, so the logic tests seat
/// holders here (with the same hardware `attestation_evidence` the persist gate wants).
async fn registered_holders(engine: &Engine, holders: &[Holder]) {
    for h in holders {
        engine
            .register_federation_key(h.signed_key_record().await)
            .await
            .unwrap_or_else(|e| panic!("seat holder {}: {e}", h.key_id));
    }
}

/// Register `holders` AND assemble the HUMANITY_ACCORD family over them (the genesis
/// ceremony) so the kill-switch roster (`active_family_members`) is entrenched. The
/// first two holders co-sign the 2/3 founder quorum.
async fn establish_family(engine: &Engine, base: &str, owner: &str, holders: &[Holder]) {
    registered_holders(engine, holders).await;
    let client = reqwest::Client::new();
    let member_ids: Vec<String> = holders.iter().map(|h| h.key_id.clone()).collect();
    let env: serde_json::Value = client
        .post(format!("{base}/v1/accord/genesis/envelope"))
        .bearer_auth(owner)
        .json(
            &serde_json::json!({ "family_name": "HUMANITY_ACCORD", "member_key_ids": member_ids }),
        )
        .send()
        .await
        .expect("envelope")
        .json()
        .await
        .unwrap();
    let envelope = env["envelope"].clone();
    let mut founders = Vec::new();
    for h in holders {
        founders.push(h.threshold_member(Some(Role::Founder)).await);
    }
    let signatures = vec![
        holders[0].family_cosign(&envelope).await,
        holders[1].family_cosign(&envelope).await,
    ];
    let asm = client
        .post(format!("{base}/v1/accord/genesis/assemble"))
        .bearer_auth(owner)
        .json(&serde_json::json!({ "envelope": envelope, "founders": founders, "signatures": signatures }))
        .send()
        .await
        .expect("assemble");
    assert_eq!(
        asm.status(),
        200,
        "assemble family: {}",
        asm.text().await.unwrap_or_default()
    );
}

/// A drill invocation (never CONSTITUTIONAL in a test) over a fixed payload.
fn drill_invocation(id: &str) -> Invocation {
    Invocation {
        invocation_kind: InvocationKind::Drill,
        invocation_id: id.to_string(),
        // verify v8.3.0: forbidden for every kind except `lifecycle:active`.
        resumes_halt_id: None,
        nonce: BASE64.encode([7u8; 32]),
        asserted_at: "2026-06-20T00:00:00.000Z".to_string(),
        valid_until: "2030-01-01T00:00:00.000Z".to_string(),
        payload_sha256: hex::encode(Sha256::digest(b"drill-payload")),
    }
}

#[tokio::test]
async fn register_holders_list_roster_and_verify_2_of_3_invocation() {
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let holders = [
        Holder::new("accord-holder-a", 0xC1),
        Holder::new("accord-holder-b", 0xC2),
        Holder::new("accord-holder-c", 0xC3),
    ];

    // ── 1. Owner registers the 3 holders + assembles the family (the roster) ──
    establish_family(&engine, &base, &owner, &holders).await;

    // ── 2. Cold-start recognition roster = the 3 entrenched family SEATS ──────
    let roster: serde_json::Value = client
        .get(format!("{base}/v1/accord-holders"))
        .send()
        .await
        .expect("list holders")
        .json()
        .await
        .unwrap();
    assert_eq!(roster["family_established"], true, "got {roster}");
    assert_eq!(roster["seat_count"], 3, "got {roster}");
    assert_eq!(roster["holders"].as_array().unwrap().len(), 3);
    assert_eq!(roster["threshold"], 2);

    // ── 3. A 2-of-3 invocation verifies (the kill-switch concurrence) ─────────
    let inv = drill_invocation("drill-001");
    let sigs = vec![holders[0].cosign(&inv).await, holders[1].cosign(&inv).await];
    let verdict: serde_json::Value = client
        .post(format!("{base}/v1/accord/verify-invocation"))
        .json(&serde_json::json!({
            "invocation": inv,
            "signatures": sigs,
            "now": "2026-06-20T00:00:01.000Z",
        }))
        .send()
        .await
        .expect("verify 2/3")
        .json()
        .await
        .unwrap();
    assert_eq!(
        verdict["verified"], true,
        "2-of-3 must verify; got {verdict}"
    );
    assert_eq!(verdict["valid_signatures"], 2);

    // ── 4. A 1-of-3 invocation FAILS the threshold ───────────────────────────
    let inv2 = drill_invocation("drill-002");
    let one = vec![holders[0].cosign(&inv2).await];
    let verdict2: serde_json::Value = client
        .post(format!("{base}/v1/accord/verify-invocation"))
        .json(&serde_json::json!({
            "invocation": inv2,
            "signatures": one,
            "now": "2026-06-20T00:00:02.000Z",
        }))
        .send()
        .await
        .expect("verify 1/3")
        .json()
        .await
        .unwrap();
    assert_eq!(
        verdict2["verified"], false,
        "1-of-3 must NOT verify; got {verdict2}"
    );
    assert_eq!(verdict2["reason"], "quorum_not_met");

    // ── 5. Replaying the SAME invocation id is rejected by the dedup window ───
    let replay = client
        .post(format!("{base}/v1/accord/verify-invocation"))
        .json(&serde_json::json!({
            "invocation": inv,
            "signatures": vec![holders[0].cosign(&inv).await, holders[2].cosign(&inv).await],
            "now": "2026-06-20T00:00:03.000Z",
        }))
        .send()
        .await
        .expect("replay");
    assert_eq!(replay.status(), 409, "replayed invocation_id ⇒ 409");
    assert_eq!(
        replay.json::<serde_json::Value>().await.unwrap()["reason"],
        "duplicate_invocation"
    );
}

#[tokio::test]
async fn accord_holder_without_hardware_attestation_is_rejected() {
    // The safe-mesh custody floor: an accord holder MUST carry hardware
    // attestation_evidence (persist refuses SoftwareOnly / missing). A
    // software-custodied "holder" cannot wield the kill-switch.
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let holder = Holder::new("accord-holder-soft", 0xE0);
    let mut rec = holder.signed_key_record().await;
    rec.record.attestation_evidence = None; // strip the hardware provenance

    let resp = client
        .post(format!("{base}/v1/accord/holder"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_record": rec }))
        .send()
        .await
        .expect("register holder w/o evidence");
    assert_eq!(
        resp.status(),
        400,
        "an accord holder without hardware attestation_evidence must be refused"
    );
}

#[tokio::test]
async fn register_holder_without_owner_session_is_rejected() {
    let engine = node().await;
    let observer = mint_session(&engine, "wa-observer", WaRole::Observer).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();
    let holder = Holder::new("accord-holder-x", 0xD0);
    let body = serde_json::json!({ "key_record": holder.signed_key_record().await });

    // No bearer → 401.
    let no_auth = client
        .post(format!("{base}/v1/accord/holder"))
        .json(&body)
        .send()
        .await
        .expect("no auth");
    assert_eq!(no_auth.status(), 401, "missing session ⇒ 401");

    // Non-owner role → 403.
    let forbidden = client
        .post(format!("{base}/v1/accord/holder"))
        .bearer_auth(&observer)
        .json(&body)
        .send()
        .await
        .expect("observer");
    assert_eq!(forbidden.status(), 403, "non-owner ⇒ 403");
}

#[tokio::test]
async fn genesis_ceremony_assembles_and_entrenches_the_family() {
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let holders = [
        Holder::new("accord-gen-a", 0xA1),
        Holder::new("accord-gen-b", 0xA2),
        Holder::new("accord-gen-c", 0xA3),
    ];
    // Seat holders directly (the HTTP /v1/accord/holder custody gate now MANDATES a
    // FIPS attestation a software test can't produce — covered by the rejection tests).
    registered_holders(&engine, &holders).await;
    let member_key_ids: Vec<String> = holders.iter().map(|h| h.key_id.clone()).collect();

    // 1. Build the canonical family envelope.
    let env_resp: serde_json::Value = client
        .post(format!("{base}/v1/accord/genesis/envelope"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "family_name": "HUMANITY_ACCORD", "member_key_ids": member_key_ids }))
        .send()
        .await
        .expect("build envelope")
        .json()
        .await
        .unwrap();
    let envelope = env_resp["envelope"].clone();
    assert!(envelope.is_object(), "got {env_resp}");

    // 2. The full founder roster + a 2-of-3 co-signature set over the envelope.
    let mut founders = Vec::new();
    for h in &holders {
        founders.push(h.threshold_member(Some(Role::Founder)).await);
    }
    let signatures = vec![
        holders[0].family_cosign(&envelope).await,
        holders[1].family_cosign(&envelope).await,
    ];

    // 3. Assemble (2/3 verified) + entrench the family.
    let asm = client
        .post(format!("{base}/v1/accord/genesis/assemble"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "envelope": envelope, "founders": founders, "signatures": signatures }))
        .send()
        .await
        .expect("assemble");
    assert_eq!(
        asm.status(),
        200,
        "assemble must succeed: {}",
        asm.text().await.unwrap_or_default()
    );
    let aj: serde_json::Value = asm.json().await.unwrap();
    assert_eq!(aj["entrenched"], true);
    assert_eq!(aj["consensus_protocol"], "quorum:2/3");

    // 4. The entrenched family reads back with all 3 members.
    let fam: serde_json::Value = client
        .get(format!("{base}/v1/accord/family"))
        .send()
        .await
        .expect("get family")
        .json()
        .await
        .unwrap();
    assert_eq!(fam["consensus_protocol"], "quorum:2/3");
    assert_eq!(fam["entrenched"], true);
    assert_eq!(fam["members"].as_array().unwrap().len(), 3, "got {fam}");
}

#[tokio::test]
async fn invocation_concurrence_advances_to_quorum() {
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let holders = [
        Holder::new("accord-inv-a", 0xB1),
        Holder::new("accord-inv-b", 0xB2),
        Holder::new("accord-inv-c", 0xB3),
    ];
    establish_family(&engine, &base, &owner, &holders).await;

    let inv = drill_invocation("concur-001");

    // Holder A opens the invocation (1 cosignature — sub-quorum).
    let created: serde_json::Value = client
        .post(format!("{base}/v1/accord/invocation"))
        .json(&serde_json::json!({ "invocation": inv, "signature": holders[0].cosign(&inv).await }))
        .send()
        .await
        .expect("create invocation")
        .json()
        .await
        .unwrap();
    assert_eq!(
        created["quorum_met"], false,
        "1-of-3 is sub-quorum; got {created}"
    );

    // Holder B concurs → 2-of-3 quorum met.
    let concurred: serde_json::Value = client
        .post(format!("{base}/v1/accord/invocation/concur"))
        .json(&serde_json::json!({
            "invocation_kind": "drill", "invocation_id": "concur-001",
            "signature": holders[1].cosign(&inv).await,
        }))
        .send()
        .await
        .expect("concur")
        .json()
        .await
        .unwrap();
    assert_eq!(
        concurred["quorum_met"], true,
        "2-of-3 must meet quorum; got {concurred}"
    );

    // The pending list reflects the met quorum.
    let listed: serde_json::Value = client
        .get(format!("{base}/v1/accord/invocations"))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .unwrap();
    let invs = listed["invocations"].as_array().unwrap();
    assert!(
        invs.iter()
            .any(|i| i["invocation_id"] == "concur-001" && i["quorum_met"] == true),
        "got {listed}"
    );
}

#[tokio::test]
async fn accord_holder_with_bogus_custody_attestation_is_rejected() {
    // The custody GATE (safe-mesh floor): a custody attestation that does NOT chain
    // to the PINNED Yubico Attestation Root 1 (here a malformed / non-YubiKey one)
    // is refused BEFORE the key is admitted — proving the gate pins the durable root
    // and calls verify_accord_custody_attestation. (A real FIPS-YubiKey PIV chain is
    // validated on hardware by verify; that success path runs at the ceremony.)
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let holder = Holder::new("accord-holder-bogus-custody", 0xF1);
    let bogus_custody = serde_json::json!({
        "schema": "ciris.ceg.signed-object.v1",
        "kind": "accord_holder_custody_attestation",
        "key_id": "accord-holder-bogus-custody",
        "created_at": "2026-06-20T00:00:00.000Z",
        "body": {
            "holder_key_id": "accord-holder-bogus-custody",
            "custody_tier": "portable_2fa",
            "yubikey_attestation_chain_hex": ["30820100"]
        },
        "signatures": serde_json::Value::Null
    });

    let resp = client
        .post(format!("{base}/v1/accord/holder"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({
            "key_record": holder.signed_key_record().await,
            "custody_attestation": bogus_custody,
        }))
        .send()
        .await
        .expect("register w/ bogus custody");
    assert_eq!(
        resp.status(),
        400,
        "a custody attestation not chaining to Yubico Attestation Root 1 must be refused"
    );
    let body = resp.json::<serde_json::Value>().await.unwrap();
    assert!(
        body["error"].as_str().unwrap_or("").contains("custody"),
        "rejection must be the custody gate; got {body}"
    );

    // The key was NOT admitted (the custody gate runs before registration).
    let roster: serde_json::Value = client
        .get(format!("{base}/v1/accord-holders"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !roster["holders"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["key_id"] == "accord-holder-bogus-custody"),
        "a custody-rejected holder must not be in the roster"
    );
}

#[tokio::test]
async fn holder_without_custody_attestation_is_rejected() {
    // B1 (safe-mesh floor): the custody attestation is MANDATORY for an accord_holder.
    // A registration with NO custody_attestation — which previously slipped through on
    // the persist attestation_evidence gate alone (any non-Software hardware) — must
    // now be refused. A software-only / unattested key cannot hold the kill-switch.
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let holder = Holder::new("accord-holder-no-custody", 0xE7);
    let resp = client
        .post(format!("{base}/v1/accord/holder"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_record": holder.signed_key_record().await }))
        .send()
        .await
        .expect("register w/o custody");
    assert_eq!(
        resp.status(),
        400,
        "an accord_holder with no custody_attestation must be refused"
    );
    let body = resp.json::<serde_json::Value>().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("custody_attestation"),
        "rejection must name the missing custody_attestation; got {body}"
    );

    // The key was NOT admitted.
    let roster: serde_json::Value = client
        .get(format!("{base}/v1/accord-holders"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !roster["registered"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["key_id"] == "accord-holder-no-custody"),
        "an unattested holder must not be registered"
    );
}

#[tokio::test]
async fn genesis_refuses_a_member_that_is_not_a_custody_verified_accord_holder() {
    // B1 chokepoint: a family SEAT must be a registered accord_holder (⟹ FIPS custody).
    // Even with a valid 2/3 founder quorum, entrenching a member that never passed the
    // custody-gated holder admission is refused — so a non-FIPS key registered via some
    // OTHER route (e.g. peering) can never be seated into the kill-switch.
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let a = Holder::new("seat-a", 0x51);
    let b = Holder::new("seat-b", 0x52);
    let outsider = Holder::new("outsider-not-a-holder", 0x53);
    // Seat only a + b as custody-verified accord_holders; `outsider` is NEVER admitted
    // as an accord_holder (it never passed the custody gate).
    registered_holders(&engine, std::slice::from_ref(&a)).await;
    registered_holders(&engine, std::slice::from_ref(&b)).await;

    let member_key_ids = vec![a.key_id.clone(), b.key_id.clone(), outsider.key_id.clone()];
    let env: serde_json::Value = client
        .post(format!("{base}/v1/accord/genesis/envelope"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "family_name": "HUMANITY_ACCORD", "member_key_ids": member_key_ids }))
        .send()
        .await
        .expect("envelope")
        .json()
        .await
        .unwrap();
    let envelope = env["envelope"].clone();
    let founders = vec![
        a.threshold_member(Some(Role::Founder)).await,
        b.threshold_member(Some(Role::Founder)).await,
        outsider.threshold_member(Some(Role::Founder)).await,
    ];
    // A valid 2/3 founder quorum (a + b) — so assembly itself succeeds; the member-type
    // gate is what must reject the entrenchment.
    let signatures = vec![
        a.family_cosign(&envelope).await,
        b.family_cosign(&envelope).await,
    ];
    let resp = client
        .post(format!("{base}/v1/accord/genesis/assemble"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "envelope": envelope, "founders": founders, "signatures": signatures }))
        .send()
        .await
        .expect("assemble");
    assert_eq!(
        resp.status(),
        409,
        "entrenching a non-accord_holder seat must be refused"
    );
    let body = resp.json::<serde_json::Value>().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("outsider-not-a-holder"),
        "rejection must name the non-holder member; got {body}"
    );

    // The rejected genesis must not entrench THIS test's family. (Every node now
    // seeds + bakes the canonical HUMANITY_ACCORD genesis A1/B1/C1 — persist
    // v12.0.2 / verify v8.5.0 — so `family_established` is baseline-true and the
    // seats are the baked A1/B1/C1; that is orthogonal to this test. What must
    // hold is that NONE of the proposed test members became a seat.)
    let roster: serde_json::Value = client
        .get(format!("{base}/v1/accord-holders"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let seats = roster["holders"].as_array().expect("holders array");
    for member in ["seat-a", "seat-b", "outsider-not-a-holder"] {
        assert!(
            !seats.iter().any(|h| h["key_id"] == member),
            "a rejected genesis must not entrench member {member}; got {roster}"
        );
    }
}

// ─── Operational halt (CC 4.2.1 / 4.2.3 / §9.2.1) — the enforceable kill-switch ─

/// Build a router that latches its halt under a unique temp `home` (no peers, no
/// process exit) + return `(base_url, home, handle)`.
async fn serve_haltable(
    engine: Arc<Engine>,
    tag: &str,
) -> (String, std::path::PathBuf, tokio::task::JoinHandle<()>) {
    let home = std::env::temp_dir().join(format!("accord-halt-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&home).expect("temp home");
    let _ = std::fs::remove_file(home.join("HUMANITY_ACCORD_HALT"));
    let app = accord::router_with_halt(
        engine,
        accord::AccordHalt {
            home: Some(home.clone()),
            peers: Vec::new(),
            exit_on_halt: false, // never kill the test runner
            // #347: what the latch's release binding names this node.
            node_id: Some(format!("node-under-test-{tag}")),
        },
    );
    let (base, handle) = serve_app(app).await;
    (base, home, handle)
}

#[tokio::test]
async fn constitutional_2of3_message_latches_global_halt_and_gates_startup() {
    // The operational kill-switch: a 2-of-3 CONSTITUTIONAL accord message latches
    // the disk halt + the latch then gates startup (not a recoverable pause).
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, home, _h) = serve_haltable(Arc::clone(&engine), "halt").await;
    let client = reqwest::Client::new();

    let holders = [
        Holder::new("accord-holder-a", 0xC1),
        Holder::new("accord-holder-b", 0xC2),
        Holder::new("accord-holder-c", 0xC3),
    ];
    establish_family(&engine, &base, &owner, &holders).await;

    let inv = constitutional_invocation("halt-001");
    let roster = vec![
        holders[0].threshold_member(None).await,
        holders[1].threshold_member(None).await,
    ];
    let sigs = vec![
        cosign_typed(&holders[0], &inv).await,
        cosign_typed(&holders[1], &inv).await,
    ];
    let obj = invocation_object(&roster, &inv, &sigs);

    let resp = client
        .post(format!("{base}/v1/accord/message"))
        .json(&obj)
        .send()
        .await
        .expect("deliver halt message");
    assert_eq!(resp.status(), 200, "authentic halt message accepted");
    let body = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(body["quorum_met"], true, "2-of-3 met; got {body}");
    assert_eq!(
        body["halted"], true,
        "CONSTITUTIONAL 2-of-3 ⇒ halted; got {body}"
    );

    // The disk latch was written + now gates a fresh startup.
    let latch = home.join("HUMANITY_ACCORD_HALT");
    assert!(
        latch.exists(),
        "halt latch must be written to {}",
        latch.display()
    );
    assert!(
        ciris_server::accord_halt::check_halt_gate(&home).is_err(),
        "a present halt latch must refuse startup"
    );
    // #347: the latch states WHAT WOULD LIFT IT — a dark machine's own disk names
    // the exact payload the accord must cosign. Read it back off the file, not from
    // the in-process record, because "an operator with only this file" is the
    // scenario the release token exists for.
    let record: ciris_server::accord_halt::HaltRecord =
        serde_json::from_str(&std::fs::read_to_string(&latch).unwrap()).expect("latch parses");
    assert_eq!(
        record.node_id.as_deref(),
        Some("node-under-test-halt"),
        "the latch must name the node it is on"
    );
    assert_eq!(
        record.halt_payload_sha256.as_deref(),
        Some(hex::encode(Sha256::digest(b"halt-payload")).as_str()),
        "the latch must name the halt payload it honored"
    );
    assert!(
        record.latch_id.is_some(),
        "every latch mints a fresh latch_id"
    );
    assert_eq!(
        record.release_payload_sha256,
        ciris_server::accord_release::ReleaseBinding::from_halt_record(&record)
            .unwrap()
            .payload_sha256()
            .ok(),
        "the stamped release digest must match the recomputed one"
    );

    // Manual removal clears the gate (the NON-conformant operator override — CC 4.2.3).
    std::fs::remove_file(&latch).unwrap();
    assert!(ciris_server::accord_halt::check_halt_gate(&home).is_ok());
    let _ = std::fs::remove_dir_all(&home);
}

/// **CIRISServer#347 end-to-end** — a REAL 2-of-3 halt over HTTP, then the offline
/// release round-trip against the resulting latch. Two properties in one arc:
///
/// 1. the **boot gate** verifies a presented token against the BAKED accord genesis
///    and refuses anything else — proven by presenting a token that is perfectly
///    valid except that it is signed by these test seats rather than the pinned
///    founders. The latch survives and the refusal is journaled.
/// 2. with the authority those signatures actually belong to, the same token
///    releases: latch cleared, gate passes, honoured entry in the audit journal.
///
/// The split is honest about what a software test can reach: nothing in-process
/// holds the real A1/B1/C1 private halves, so the *honouring* leg injects its
/// authority while the *refusing* leg exercises the production one.
#[tokio::test]
async fn offline_release_token_round_trips_against_a_real_halt_latch() {
    use ciris_server::accord_release::{
        baked_release_authority, build_release_request, honor_release_token, read_release_journal,
        release_token_path, ReleaseAuthority, ReleaseBinding, ReleaseToken,
    };

    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, home, _h) = serve_haltable(Arc::clone(&engine), "release").await;
    let client = reqwest::Client::new();

    let holders = [
        Holder::new("accord-holder-a", 0xD1),
        Holder::new("accord-holder-b", 0xD2),
        Holder::new("accord-holder-c", 0xD3),
    ];
    establish_family(&engine, &base, &owner, &holders).await;

    // ── The halt, for real: 2-of-3 CONSTITUTIONAL over /v1/accord/message ──────
    let inv = constitutional_invocation("halt-release-001");
    let roster = vec![
        holders[0].threshold_member(None).await,
        holders[1].threshold_member(None).await,
    ];
    let sigs = vec![
        cosign_typed(&holders[0], &inv).await,
        cosign_typed(&holders[1], &inv).await,
    ];
    let obj = invocation_object(&roster, &inv, &sigs);
    let body = client
        .post(format!("{base}/v1/accord/message"))
        .json(&obj)
        .send()
        .await
        .expect("deliver halt")
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(body["halted"], true, "the halt must latch; got {body}");
    assert!(
        ciris_server::accord_halt::check_halt_gate(&home).is_err(),
        "a latched node must refuse to start"
    );

    // ── The release REQUEST: derived from the latch alone. No engine is opened, no
    //    peer dialed — this is what an operator can run on a dark machine. ───────
    let latch = home.join("HUMANITY_ACCORD_HALT");
    let record: ciris_server::accord_halt::HaltRecord =
        serde_json::from_str(&std::fs::read_to_string(&latch).unwrap()).unwrap();
    let request = build_release_request(&record, 72).expect("release request from the latch");
    assert_eq!(request["invocation"]["invocation_kind"], "lifecycle:active");
    assert_eq!(request["invocation"]["resumes_halt_id"], "halt-release-001");
    assert_eq!(request["binding"]["node_id"], "node-under-test-release");

    // ── Mint the token the request asked for, cosigned by two seats. ───────────
    let release_inv: Invocation = serde_json::from_value(request["invocation"].clone()).unwrap();
    let token = ReleaseToken {
        signatures: vec![
            cosign_typed(&holders[0], &release_inv).await,
            cosign_typed(&holders[1], &release_inv).await,
        ],
        binding: Some(request["binding"].clone()),
        invocation: release_inv,
    };

    // ── (1) The PRODUCTION gate: drop the token where the boot gate looks. These
    //    seats are not the baked founders, so it must be REFUSED and the latch must
    //    survive. This is the check that proves the gate's authority is the pinned
    //    genesis and not whatever the presenter supplies. ────────────────────────
    std::fs::write(
        release_token_path(&home),
        serde_json::to_vec_pretty(&token).unwrap(),
    )
    .unwrap();
    let refused = ciris_server::accord_halt::check_halt_gate(&home)
        .expect_err("a token signed by non-baked keys must NOT release the node");
    let refused = format!("{refused:#}");
    assert!(refused.contains("REFUSED"), "{refused}");
    assert!(
        latch.exists(),
        "a refused release must leave the latch in place"
    );
    let journal = read_release_journal(&home);
    assert_eq!(
        journal.len(),
        1,
        "the refusal must be journaled: {journal:?}"
    );
    assert_eq!(journal[0]["outcome"], "refused");
    // And the production authority it was judged against really is the baked one.
    let baked = baked_release_authority().expect("baked authority resolves offline");
    assert!(
        !baked
            .roster
            .iter()
            .any(|m| m.member_id == "accord-holder-a"),
        "the test seats must not be in the baked roster — otherwise (1) proves nothing"
    );

    // ── (2) The same token, judged against the authority those signatures DO
    //    belong to: it releases. ─────────────────────────────────────────────────
    let authority = ReleaseAuthority {
        roster: vec![
            holders[0].threshold_member(None).await,
            holders[1].threshold_member(None).await,
            holders[2].threshold_member(None).await,
        ],
        threshold: 2,
        source: "test-seats".to_string(),
    };
    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let verdict = honor_release_token(&home, &record, &token, &authority, &now)
        .expect("a 2-of-3 token bound to THIS latch must release it");
    assert_eq!(verdict.valid_signers, 2);
    assert_eq!(verdict.node_id, "node-under-test-release");
    assert_eq!(verdict.latch_id, record.latch_id.clone().unwrap());
    assert!(!latch.exists(), "the latch must be cleared");
    assert!(
        ciris_server::accord_halt::check_halt_gate(&home).is_ok(),
        "released ⇒ the node may start"
    );
    assert!(
        !release_token_path(&home).exists(),
        "the honoured token must be consumed, not left to re-trip the gate"
    );

    // ── The trace: a release is a governance act, as auditable as the halt. ────
    let journal = read_release_journal(&home);
    assert_eq!(journal.len(), 2, "refusal then honour: {journal:?}");
    assert_eq!(journal[1]["outcome"], "honored");
    assert_eq!(
        journal[1]["halt_record"]["invocation_id"],
        "halt-release-001"
    );
    assert_eq!(
        journal[1]["release_token"]["invocation"]["invocation_kind"],
        "lifecycle:active"
    );

    // ── Replay across halts: the node is halted AGAIN by the same invocation. The
    //    new latch mints a new latch_id, so the token just honoured is worthless. ─
    let body = client
        .post(format!("{base}/v1/accord/message"))
        .json(&obj)
        .send()
        .await
        .expect("re-deliver halt")
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(body["halted"], true, "the re-halt must latch; got {body}");
    let record2: ciris_server::accord_halt::HaltRecord =
        serde_json::from_str(&std::fs::read_to_string(&latch).unwrap()).unwrap();
    assert_ne!(
        record2.latch_id, record.latch_id,
        "a re-latch mints a new instance"
    );
    let e = ciris_server::accord_release::verify_release_token(&record2, &token, &authority, &now)
        .expect_err("a spent token must not release a LATER halt of the same invocation")
        .to_string();
    assert!(e.contains("not bound to THIS halt latch"), "{e}");
    assert!(
        ReleaseBinding::from_halt_record(&record2).unwrap()
            != ReleaseBinding::from_halt_record(&record).unwrap()
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test]
async fn drill_2of3_message_is_surfaced_but_does_not_halt() {
    // EAS-style: a drill (or notify) exercises the SAME delivery path — replicate +
    // surface — but NEVER halts, even at a full 2-of-3.
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, home, _h) = serve_haltable(Arc::clone(&engine), "drill").await;
    let client = reqwest::Client::new();

    let holders = [
        Holder::new("accord-holder-a", 0xC1),
        Holder::new("accord-holder-b", 0xC2),
        Holder::new("accord-holder-c", 0xC3),
    ];
    establish_family(&engine, &base, &owner, &holders).await;

    let inv = drill_invocation("drill-eas-001");
    let roster = vec![
        holders[0].threshold_member(None).await,
        holders[1].threshold_member(None).await,
    ];
    let sigs = vec![
        cosign_typed(&holders[0], &inv).await,
        cosign_typed(&holders[1], &inv).await,
    ];
    let obj = invocation_object(&roster, &inv, &sigs);

    let body = client
        .post(format!("{base}/v1/accord/message"))
        .json(&obj)
        .send()
        .await
        .expect("deliver drill")
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(body["quorum_met"], true, "drill quorum met; got {body}");
    assert_eq!(body["halted"], false, "a DRILL must NOT halt; got {body}");
    assert!(
        !home.join("HUMANITY_ACCORD_HALT").exists(),
        "a drill must not write a halt latch"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test]
async fn message_without_registered_holder_signature_is_dropped() {
    // Authenticity floor: a message whose cosignatures are NOT from registered
    // holders carries no authority — dropped (401), never replicated, never halts.
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, home, _h) = serve_haltable(Arc::clone(&engine), "unauth").await;
    let client = reqwest::Client::new();

    // A real 3-seat family exists, so the kill-switch roster is defined …
    let holders = [
        Holder::new("accord-holder-a", 0xC1),
        Holder::new("accord-holder-b", 0xC2),
        Holder::new("accord-holder-c", 0xC3),
    ];
    establish_family(&engine, &base, &owner, &holders).await;

    // … but the signer is NOT a seat (never registered) — no authority.
    let imposter = Holder::new("accord-holder-imposter", 0xBB);
    let inv = constitutional_invocation("halt-imposter");
    let roster = vec![imposter.threshold_member(None).await];
    let sigs = vec![cosign_typed(&imposter, &inv).await];
    let obj = invocation_object(&roster, &inv, &sigs);

    let resp = client
        .post(format!("{base}/v1/accord/message"))
        .json(&obj)
        .send()
        .await
        .expect("deliver imposter message");
    assert_eq!(resp.status(), 401, "unregistered-holder message ⇒ 401");
    assert!(
        !home.join("HUMANITY_ACCORD_HALT").exists(),
        "an unauthentic message must never latch a halt"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test]
async fn open_invocation_without_registered_holder_signature_is_rejected() {
    // DoS floor: an invocation opened with a NON-registered signer carries no
    // authority and is NOT persisted (an unauthenticated caller cannot grow the
    // pending table). Only holder-signed invocations are kept.
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    // A real 3-seat family (so the roster exists), and an imposter who opens.
    let holders = [
        Holder::new("accord-holder-a", 0xC1),
        Holder::new("accord-holder-b", 0xC2),
        Holder::new("accord-holder-c", 0xC3),
    ];
    establish_family(&engine, &base, &owner, &holders).await;
    let imposter = Holder::new("accord-holder-imposter", 0xBB);

    let inv = drill_invocation("dos-001");
    let resp = client
        .post(format!("{base}/v1/accord/invocation"))
        .json(&serde_json::json!({
            "invocation": inv,
            "signature": imposter.cosign(&inv).await,
        }))
        .send()
        .await
        .expect("open invocation");
    assert_eq!(resp.status(), 401, "unauthenticated opener ⇒ 401");

    // It was not persisted — the pending list stays empty.
    let listed: serde_json::Value = client
        .get(format!("{base}/v1/accord/invocations"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        listed["invocations"].as_array().unwrap().is_empty(),
        "an unauthenticated invocation must not be stored; got {listed}"
    );
}

#[tokio::test]
async fn registered_spare_is_not_a_seat_and_cannot_help_reach_quorum() {
    // The self-quorum hole, CLOSED: the kill-switch roster is the family SEATS
    // (active_family_members), NOT every accord_holder row. A vaulted spare can be a
    // registered + attested accord_holder identity, but it is NOT a seat — so one
    // human's primary + their own spare can NEVER self-satisfy the 2-of-3.
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, home, _h) = serve_haltable(Arc::clone(&engine), "spare").await;
    let client = reqwest::Client::new();

    // 3-seat family A/B/C …
    let holders = [
        Holder::new("accord-holder-a", 0xC1),
        Holder::new("accord-holder-b", 0xC2),
        Holder::new("accord-holder-c", 0xC3),
    ];
    establish_family(&engine, &base, &owner, &holders).await;
    // … plus A's cold SPARE: a registered accord_holder identity that is NOT a seat.
    let a_spare = Holder::new("accord-holder-a-spare", 0xC9);
    registered_holders(&engine, std::slice::from_ref(&a_spare)).await;

    // It IS registered (visible under `registered`) but is NOT one of the 3 seats.
    let roster: serde_json::Value = client
        .get(format!("{base}/v1/accord-holders"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(roster["seat_count"], 3, "exactly 3 seats; got {roster}");
    // This test's 3 seats + 1 spare are ALL registered accord_holders. (Every node
    // also seeds the baked A1/B1/C1 canonical genesis — persist v12.0.2 — so assert
    // membership rather than an exact `registered_total`, which now baselines +3.)
    let registered = roster["registered"].as_array().expect("registered array");
    for kid in [
        "accord-holder-a",
        "accord-holder-b",
        "accord-holder-c",
        "accord-holder-a-spare",
    ] {
        assert!(
            registered.iter().any(|h| h["key_id"] == kid),
            "the 3 seats + spare must all be registered; missing {kid}; got {roster}"
        );
    }
    assert!(
        !roster["holders"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["key_id"] == "accord-holder-a-spare"),
        "the spare must NOT be a seat"
    );

    // A CONSTITUTIONAL signed by seat A + A's SPARE = ONE human, two keys. The spare
    // is not a seat, so this is a 1-of-3 — NOT quorum, NOT halted, NO latch.
    let inv = constitutional_invocation("halt-selfquorum");
    let roster_obj = vec![
        holders[0].threshold_member(None).await,
        a_spare.threshold_member(None).await,
    ];
    let sigs = vec![
        cosign_typed(&holders[0], &inv).await,
        cosign_typed(&a_spare, &inv).await,
    ];
    let obj = invocation_object(&roster_obj, &inv, &sigs);
    let body = client
        .post(format!("{base}/v1/accord/message"))
        .json(&obj)
        .send()
        .await
        .expect("deliver")
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(
        body["quorum_met"], false,
        "one human's primary + spare must NOT reach 2-of-3; got {body}"
    );
    assert_eq!(body["halted"], false, "must NOT halt; got {body}");
    assert!(
        !home.join("HUMANITY_ACCORD_HALT").exists(),
        "the self-quorum attempt must not latch a halt"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test]
async fn family_supersede_replaces_a_seat_under_2of3_and_rejects_sub_quorum() {
    // The supersede/recover op: the CURRENT 2/3 authorizes replacing one seat with a
    // vaulted spare (same N). persist's quorum gate enforces ≥M prior cosignatures +
    // anti-replay + one-seat IN THE SUBSTRATE; a sub-quorum change is refused.
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let holders = [
        Holder::new("accord-holder-a", 0xC1),
        Holder::new("accord-holder-b", 0xC2),
        Holder::new("accord-holder-c", 0xC3),
    ];
    establish_family(&engine, &base, &owner, &holders).await;
    // A vaulted spare (registered accord_holder, not a seat).
    let spare = Holder::new("accord-holder-d", 0xC4);
    registered_holders(&engine, std::slice::from_ref(&spare)).await;

    // Build the change envelope: replace A → D (roster {b,c,d}, still quorum:2/3).
    let new_ids = vec![
        holders[1].key_id.clone(),
        holders[2].key_id.clone(),
        spare.key_id.clone(),
    ];
    let env: serde_json::Value = client
        .post(format!("{base}/v1/accord/family/change/envelope"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "new_member_key_ids": new_ids, "consensus_protocol": "quorum:2/3" }))
        .send()
        .await
        .expect("change envelope")
        .json()
        .await
        .unwrap();
    let change_envelope = env["change_envelope"].clone();
    let bytes = BASE64
        .decode(env["signing_bytes_base64"].as_str().unwrap())
        .expect("decode signing bytes");

    // SUB-QUORUM: a single prior-roster signature is refused (409), live row intact.
    let one = client
        .post(format!("{base}/v1/accord/family/supersede"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "change_envelope": change_envelope, "signatures": [holders[1].sign_bytes(&bytes).await] }))
        .send()
        .await
        .expect("1-sig supersede");
    assert_eq!(one.status(), 409, "a sub-quorum supersede must be refused");

    // QUORUM: B + C (2 of the prior {a,b,c}) cosign → the swap is applied.
    let two = client
        .post(format!("{base}/v1/accord/family/supersede"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({
            "change_envelope": change_envelope,
            "signatures": [holders[1].sign_bytes(&bytes).await, holders[2].sign_bytes(&bytes).await],
        }))
        .send()
        .await
        .expect("2-of-3 supersede");
    assert_eq!(
        two.status(),
        200,
        "2-of-3 authorizes the swap: {}",
        two.text().await.unwrap_or_default()
    );

    // The kill-switch roster now reflects {b,c,d} — A is gone, D is a seat.
    let roster: serde_json::Value = client
        .get(format!("{base}/v1/accord-holders"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(roster["seat_count"], 3, "got {roster}");
    let seats: Vec<String> = roster["holders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["key_id"].as_str().unwrap_or("").to_string())
        .collect();
    assert!(
        seats.contains(&"accord-holder-d".to_string()),
        "spare D is now a seat: {seats:?}"
    );
    assert!(
        !seats.contains(&"accord-holder-a".to_string()),
        "A was replaced: {seats:?}"
    );
}

/// Cosign arbitrary canonical bytes (Ed25519 over `bytes`, ML-DSA-65 over
/// `bytes ‖ ed_sig`) — the `ThresholdSignature` shape `verify_threshold_signatures`
/// checks. The Trust Root canonical-server ops sign `jcs::canonicalize(invocation)`.
async fn cosign_bytes(h: &Holder, bytes: &[u8]) -> ThresholdSignature {
    let ed_sig = h.ed.sign(bytes).to_bytes();
    let mut bound = bytes.to_vec();
    bound.extend_from_slice(&ed_sig);
    let pqc_sig = h.mldsa.sign(&bound).await.expect("ml-dsa cosign bytes");
    ThresholdSignature {
        member_id: h.key_id.clone(),
        ed25519_signature_base64: BASE64.encode(ed_sig),
        mldsa65_signature_base64: Some(BASE64.encode(&pqc_sig)),
    }
}

/// Trust Root — `POST /v1/accord/canonical/address` (CIRISServer#164): a canonical
/// server's transport address is (re)bound under **1-of-N** accord authority
/// (operational), resolved from the live roster via `canonical_op_quorum_m` — so it
/// scales to m-of-n as the founder set grows. One holder suffices; zero / a
/// non-holder is refused.
#[tokio::test]
async fn canonical_address_update_is_1_of_n_and_binds_transport_destination() {
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let holders = [
        Holder::new("accord-holder-a", 0xC1),
        Holder::new("accord-holder-b", 0xC2),
        Holder::new("accord-holder-c", 0xC3),
    ];
    establish_family(&engine, &base, &owner, &holders).await;

    // Register the canonical server as a node key so its transport_destination FK
    // is satisfied (the op binds the address of an existing directory key).
    {
        let cn = Holder::new("canonical-server-1", 0x77);
        let now = chrono::Utc::now();
        let envelope = serde_json::json!({ "key_id": "canonical-server-1" });
        let canonical = ceg_produce_canonicalize(&envelope).expect("canon canonical-node");
        let ed_sig = cn.ed.sign(&canonical).to_bytes();
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = cn.mldsa.sign(&bound).await.expect("pqc canonical-node");
        let record = KeyRecord {
            key_id: "canonical-server-1".into(),
            pubkey_ed25519_base64: BASE64.encode(cn.ed.verifying_key().to_bytes()),
            pubkey_ml_dsa_65_base64: Some(BASE64.encode(cn.mldsa.public_key().await.unwrap())),
            algorithm: algorithm::HYBRID.into(),
            identity_type: "node".into(),
            identity_ref: "canonical-server-1".into(),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(Sha256::digest(&canonical)),
            scrub_signature_classical: BASE64.encode(ed_sig),
            scrub_signature_pqc: Some(BASE64.encode(&pqc_sig)),
            scrub_key_id: "canonical-server-1".into(),
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
            .expect("register canonical node key");
    }

    let update = serde_json::json!({
        "op": "canonical:address",
        "canonical_key_id": "canonical-server-1",
        "transport_kind": "reticulum",
        "destination": "203.0.113.9:4242",
        "invocation_id": "addr-upd-1",
        "asserted_at": chrono::Utc::now().to_rfc3339(),
    });
    let bytes = ciris_verify_core::jcs::canonicalize(&update).expect("jcs canonicalize");

    // 1-of-N: ONE holder sig → accepted, address bound.
    let sig = cosign_bytes(&holders[0], &bytes).await;
    let resp = client
        .post(format!("{base}/v1/accord/canonical/address"))
        .json(&serde_json::json!({ "invocation": update, "signatures": [sig] }))
        .send()
        .await
        .expect("POST address update");
    assert_eq!(
        resp.status(),
        200,
        "1-of-N holder signature must be accepted"
    );
    let j: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(j["quorum_m"], 1, "operational op resolves to 1-of-N");
    assert_eq!(j["valid_signatures"], 1);
    assert_eq!(j["destination"], "203.0.113.9:4242");

    // The transport_destination is now bound in the directory.
    let dests = engine
        .federation_directory()
        .list_transport_destinations_for("canonical-server-1")
        .await
        .expect("list transport destinations");
    assert!(
        dests.iter().any(|d| d.destination == "203.0.113.9:4242"),
        "the canonical server's address must be bound after the op"
    );

    // Zero signatures → quorum not met (403).
    let no_sig = client
        .post(format!("{base}/v1/accord/canonical/address"))
        .json(&serde_json::json!({ "invocation": update, "signatures": [] }))
        .send()
        .await
        .expect("POST no-sig");
    assert_eq!(no_sig.status(), 403, "0 signatures must fail the quorum");

    // A non-holder signature → refused (not a seated key).
    let outsider = Holder::new("not-a-holder", 0xEE);
    let bad = cosign_bytes(&outsider, &bytes).await;
    let refused = client
        .post(format!("{base}/v1/accord/canonical/address"))
        .json(&serde_json::json!({ "invocation": update, "signatures": [bad] }))
        .send()
        .await
        .expect("POST outsider");
    assert_eq!(
        refused.status(),
        403,
        "a non-holder signature must not satisfy the quorum"
    );
}

// ─── Drill / announce surfacing + halt-status (CIRISServer#41 §9.2.1) ─────────

/// A notify (announce) invocation whose `payload_sha256` binds `message`.
fn notify_invocation(id: &str, message: &str) -> Invocation {
    Invocation {
        invocation_kind: InvocationKind::Notify,
        invocation_id: id.to_string(),
        resumes_halt_id: None,
        nonce: BASE64.encode([5u8; 32]),
        asserted_at: "2026-06-20T00:00:00.000Z".to_string(),
        valid_until: "2030-01-01T00:00:00.000Z".to_string(),
        payload_sha256: hex::encode(Sha256::digest(message.as_bytes())),
    }
}

#[tokio::test]
async fn complete_drill_via_message_is_recorded_in_events_and_never_latches() {
    // A VALID, quorum-COMPLETE drill arriving via gossip (/v1/accord/message) is
    // RECORDED as a surfaced non-binding event and NEVER latches a halt.
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, home, _h) = serve_haltable(Arc::clone(&engine), "drill-events").await;
    let client = reqwest::Client::new();

    let holders = [
        Holder::new("accord-holder-a", 0xC1),
        Holder::new("accord-holder-b", 0xC2),
        Holder::new("accord-holder-c", 0xC3),
    ];
    establish_family(&engine, &base, &owner, &holders).await;

    let inv = drill_invocation("drill-rec-001");
    let roster = vec![
        holders[0].threshold_member(None).await,
        holders[1].threshold_member(None).await,
    ];
    let sigs = vec![
        cosign_typed(&holders[0], &inv).await,
        cosign_typed(&holders[1], &inv).await,
    ];
    let obj = invocation_object(&roster, &inv, &sigs);

    let body = client
        .post(format!("{base}/v1/accord/message"))
        .json(&obj)
        .send()
        .await
        .expect("deliver drill")
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(body["halted"], false, "a DRILL must NOT halt; got {body}");
    assert!(
        !home.join("HUMANITY_ACCORD_HALT").exists(),
        "a drill must not write a halt latch"
    );

    // /v1/accord/events surfaces the completed drill with its signers.
    let events = client
        .get(format!("{base}/v1/accord/events"))
        .send()
        .await
        .expect("list events")
        .json::<serde_json::Value>()
        .await
        .unwrap();
    let drills = events["drills"].as_array().expect("drills[]");
    assert_eq!(
        drills.len(),
        1,
        "the completed drill must be surfaced; got {events}"
    );
    assert_eq!(drills[0]["invocation_id"], "drill-rec-001");
    assert_eq!(drills[0]["event_type"], "drill");
    assert_eq!(drills[0]["quorum_threshold"], 2);
    let signers = drills[0]["signers"].as_array().unwrap();
    assert_eq!(
        signers.len(),
        2,
        "both cosigning seats recorded; got {events}"
    );
    assert!(events["announcements"].as_array().unwrap().is_empty());

    // Re-delivering the SAME drill is idempotent — still exactly one event.
    let _ = client
        .post(format!("{base}/v1/accord/message"))
        .json(&obj)
        .send()
        .await
        .expect("re-deliver drill");
    let events2 = client
        .get(format!("{base}/v1/accord/events"))
        .send()
        .await
        .expect("list events 2")
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(
        events2["drills"].as_array().unwrap().len(),
        1,
        "re-gossip of a drill must be idempotent; got {events2}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test]
async fn announce_records_on_a_valid_single_holder_signature() {
    // An announce (notify, threshold 1) is complete on arrival: one valid holder
    // signature records a surfaced announcement carrying the bound message.
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let holders = [
        Holder::new("accord-holder-a", 0xC1),
        Holder::new("accord-holder-b", 0xC2),
        Holder::new("accord-holder-c", 0xC3),
    ];
    establish_family(&engine, &base, &owner, &holders).await;

    let message = "mesh maintenance window 02:00-03:00 UTC";
    let inv = notify_invocation("notify-001", message);
    let sig = holders[0].cosign(&inv).await;
    let posted = client
        .post(format!("{base}/v1/accord/announce"))
        .json(&serde_json::json!({ "invocation": inv, "signature": sig, "message": message }))
        .send()
        .await
        .expect("announce");
    assert_eq!(
        posted.status(),
        200,
        "a valid single-holder announce must post: {}",
        posted.text().await.unwrap_or_default()
    );

    let events = client
        .get(format!("{base}/v1/accord/events"))
        .send()
        .await
        .expect("list events")
        .json::<serde_json::Value>()
        .await
        .unwrap();
    let announcements = events["announcements"].as_array().expect("announcements[]");
    assert_eq!(
        announcements.len(),
        1,
        "the announce must be surfaced; got {events}"
    );
    assert_eq!(announcements[0]["invocation_id"], "notify-001");
    assert_eq!(announcements[0]["event_type"], "announce");
    assert_eq!(announcements[0]["quorum_threshold"], 1);
    assert_eq!(announcements[0]["message"], message);
    assert_eq!(
        announcements[0]["signers"].as_array().unwrap().len(),
        1,
        "one signing holder recorded; got {events}"
    );
    assert!(events["drills"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn announce_with_unbound_message_is_rejected() {
    // The message MUST bind to the signed payload_sha256 — a mismatched plaintext is
    // a malformed announce (400), never recorded.
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let holders = [
        Holder::new("accord-holder-a", 0xC1),
        Holder::new("accord-holder-b", 0xC2),
        Holder::new("accord-holder-c", 0xC3),
    ];
    establish_family(&engine, &base, &owner, &holders).await;

    let inv = notify_invocation("notify-bad", "the SIGNED text");
    let sig = holders[0].cosign(&inv).await;
    let resp = client
        .post(format!("{base}/v1/accord/announce"))
        .json(&serde_json::json!({
            "invocation": inv,
            "signature": sig,
            "message": "a DIFFERENT, tampered text",
        }))
        .send()
        .await
        .expect("announce unbound");
    assert_eq!(resp.status(), 400, "an unbound message must be rejected");
    let events = client
        .get(format!("{base}/v1/accord/events"))
        .send()
        .await
        .expect("list events")
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert!(
        events["announcements"].as_array().unwrap().is_empty(),
        "a rejected announce must not be recorded; got {events}"
    );
}

#[tokio::test]
async fn sub_quorum_drill_is_not_recorded() {
    // A drill opened with a single (sub-quorum) cosignature only ACCUMULATES — it is
    // NOT surfaced as a completed event until it reaches the family quorum.
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let holders = [
        Holder::new("accord-holder-a", 0xC1),
        Holder::new("accord-holder-b", 0xC2),
        Holder::new("accord-holder-c", 0xC3),
    ];
    establish_family(&engine, &base, &owner, &holders).await;

    let inv = drill_invocation("drill-sub-001");
    let sig = holders[0].cosign(&inv).await;
    let opened = client
        .post(format!("{base}/v1/accord/drill"))
        .json(&serde_json::json!({ "invocation": inv, "signature": sig }))
        .send()
        .await
        .expect("open drill");
    assert_eq!(opened.status(), 200, "a 1-of-3 drill opens (sub-quorum)");
    let opened_body = opened.json::<serde_json::Value>().await.unwrap();
    assert_eq!(
        opened_body["quorum_met"], false,
        "1-of-3 is sub-quorum; got {opened_body}"
    );

    let events = client
        .get(format!("{base}/v1/accord/events"))
        .send()
        .await
        .expect("list events")
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert!(
        events["drills"].as_array().unwrap().is_empty(),
        "a sub-quorum drill must NOT be recorded; got {events}"
    );

    // A concurring second seat reaches quorum → NOW the drill is surfaced.
    let sig2 = holders[1].cosign(&inv).await;
    let concur = client
        .post(format!("{base}/v1/accord/invocation/concur"))
        .json(&serde_json::json!({
            "invocation_kind": "drill",
            "invocation_id": "drill-sub-001",
            "signature": sig2,
        }))
        .send()
        .await
        .expect("concur drill");
    assert_eq!(concur.status(), 200, "concur advances the drill");
    let events2 = client
        .get(format!("{base}/v1/accord/events"))
        .send()
        .await
        .expect("list events 2")
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(
        events2["drills"].as_array().unwrap().len(),
        1,
        "reaching quorum via concur surfaces the drill; got {events2}"
    );
}

#[tokio::test]
async fn drill_endpoint_rejects_a_non_drill_kind() {
    // The drill endpoint pins the kind: a CONSTITUTIONAL invocation must be refused
    // (a halt can never be opened through the non-binding drill surface).
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    let holders = [
        Holder::new("accord-holder-a", 0xC1),
        Holder::new("accord-holder-b", 0xC2),
        Holder::new("accord-holder-c", 0xC3),
    ];
    establish_family(&engine, &base, &owner, &holders).await;

    let inv = constitutional_invocation("not-a-drill");
    let sig = holders[0].cosign(&inv).await;
    let resp = client
        .post(format!("{base}/v1/accord/drill"))
        .json(&serde_json::json!({ "invocation": inv, "signature": sig }))
        .send()
        .await
        .expect("drill wrong-kind");
    assert_eq!(
        resp.status(),
        400,
        "the drill endpoint must reject a non-drill kind"
    );
}

#[tokio::test]
async fn halt_status_reflects_the_disk_latch() {
    // GET /v1/accord/halt-status reads the disk latch: false before a halt, true
    // (with the record) after a 2-of-3 CONSTITUTIONAL halt.
    let engine = node().await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, home, _h) = serve_haltable(Arc::clone(&engine), "haltstatus").await;
    let client = reqwest::Client::new();

    let holders = [
        Holder::new("accord-holder-a", 0xC1),
        Holder::new("accord-holder-b", 0xC2),
        Holder::new("accord-holder-c", 0xC3),
    ];
    establish_family(&engine, &base, &owner, &holders).await;

    // Before any halt: not halted.
    let before = client
        .get(format!("{base}/v1/accord/halt-status"))
        .send()
        .await
        .expect("halt-status before")
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(before["halted"], false, "not halted before; got {before}");
    assert!(before["record"].is_null(), "no record before; got {before}");

    // Latch a real 2-of-3 CONSTITUTIONAL halt.
    let inv = constitutional_invocation("halt-status-001");
    let roster = vec![
        holders[0].threshold_member(None).await,
        holders[1].threshold_member(None).await,
    ];
    let sigs = vec![
        cosign_typed(&holders[0], &inv).await,
        cosign_typed(&holders[1], &inv).await,
    ];
    let obj = invocation_object(&roster, &inv, &sigs);
    let halted = client
        .post(format!("{base}/v1/accord/message"))
        .json(&obj)
        .send()
        .await
        .expect("deliver halt")
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(
        halted["halted"], true,
        "2-of-3 CONSTITUTIONAL halts; got {halted}"
    );

    // After the halt: halt-status reflects the latch + its record.
    let after = client
        .get(format!("{base}/v1/accord/halt-status"))
        .send()
        .await
        .expect("halt-status after")
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(after["halted"], true, "halted after; got {after}");
    assert_eq!(
        after["record"]["invocation_id"], "halt-status-001",
        "the halt record names the invocation; got {after}"
    );
    let _ = std::fs::remove_file(home.join("HUMANITY_ACCORD_HALT"));
    let _ = std::fs::remove_dir_all(&home);
}
