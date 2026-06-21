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
    let engine = Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("Engine::with_signer (sqlite::memory:) must succeed");
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
        roles: Vec::new(),
        attestation_evidence: None,
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
    format!("sess:{wa_id}:testtoken")
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
            roles: Vec::new(),
            attestation_evidence: Some(Self::android_attestation_evidence()),
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
        nonce: BASE64.encode([9u8; 32]),
        asserted_at: "2026-06-20T00:00:00.000Z".to_string(),
        valid_until: "2030-01-01T00:00:00.000Z".to_string(),
        payload_sha256: hex::encode(Sha256::digest(b"halt-payload")),
    }
}

/// Register N holders with the node (owner-gated) + return them.
async fn registered_holders(base: &str, owner: &str, holders: &[Holder]) {
    let client = reqwest::Client::new();
    for h in holders {
        let resp = client
            .post(format!("{base}/v1/accord/holder"))
            .bearer_auth(owner)
            .json(&serde_json::json!({ "key_record": h.signed_key_record().await }))
            .send()
            .await
            .expect("register holder");
        assert_eq!(resp.status(), 200, "register {}", h.key_id);
    }
}

/// Register `holders` AND assemble the HUMANITY_ACCORD family over them (the genesis
/// ceremony) so the kill-switch roster (`active_family_members`) is entrenched. The
/// first two holders co-sign the 2/3 founder quorum.
async fn establish_family(base: &str, owner: &str, holders: &[Holder]) {
    registered_holders(base, owner, holders).await;
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
    establish_family(&base, &owner, &holders).await;

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
    for h in &holders {
        let r = client
            .post(format!("{base}/v1/accord/holder"))
            .bearer_auth(&owner)
            .json(&serde_json::json!({ "key_record": h.signed_key_record().await }))
            .send()
            .await
            .expect("register holder");
        assert_eq!(r.status(), 200);
    }
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
    establish_family(&base, &owner, &holders).await;

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
    establish_family(&base, &owner, &holders).await;

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
    // Manual removal clears the gate (the only way back — CC 4.2.3).
    std::fs::remove_file(&latch).unwrap();
    assert!(ciris_server::accord_halt::check_halt_gate(&home).is_ok());
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
    establish_family(&base, &owner, &holders).await;

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
    establish_family(&base, &owner, &holders).await;

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
    establish_family(&base, &owner, &holders).await;
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
    establish_family(&base, &owner, &holders).await;
    // … plus A's cold SPARE: a registered accord_holder identity that is NOT a seat.
    let a_spare = Holder::new("accord-holder-a-spare", 0xC9);
    registered_holders(&base, &owner, std::slice::from_ref(&a_spare)).await;

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
    assert_eq!(
        roster["registered_total"], 4,
        "3 seats + 1 spare registered"
    );
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
