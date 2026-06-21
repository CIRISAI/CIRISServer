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
    Arc::new(engine)
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
    let app = accord::router(engine);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
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

    // ── 1. Owner registers the 3 genesis-established holders ──────────────────
    for h in &holders {
        let resp = client
            .post(format!("{base}/v1/accord/holder"))
            .bearer_auth(&owner)
            .json(&serde_json::json!({ "key_record": h.signed_key_record().await }))
            .send()
            .await
            .expect("register holder");
        assert_eq!(resp.status(), 200, "owner registers holder {}", h.key_id);
    }

    // ── 2. Cold-start recognition roster lists all 3 (no owner needed) ────────
    let roster: serde_json::Value = client
        .get(format!("{base}/v1/accord-holders"))
        .send()
        .await
        .expect("list holders")
        .json()
        .await
        .unwrap();
    assert_eq!(roster["holder_count"], 3, "got {roster}");
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
