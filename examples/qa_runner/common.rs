//! Shared harness for the desktop QA runner — software-key identities, an in-process
//! ciris-server engine + accord router, and a tiny live report.

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

use ciris_server::accord::AccordHalt;
use ciris_server::auth::store;

const NODE_KEY_ID: &str = "qa-node";

/// A live pass/fail ledger printed as the runner goes + summarized at the end.
#[derive(Default)]
pub struct Report {
    steps: Vec<(String, String, bool, String)>,
}

impl Report {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a step result, printing it immediately.
    pub fn record(&mut self, module: &str, name: &str, ok: bool, detail: impl Into<String>) {
        let detail = detail.into();
        let mark = if ok {
            "\x1b[32m✓\x1b[0m"
        } else {
            "\x1b[31m✗\x1b[0m"
        };
        println!(
            "  {mark} [{module}] {name}{}",
            if detail.is_empty() {
                String::new()
            } else {
                format!(" — {detail}")
            }
        );
        self.steps.push((module.into(), name.into(), ok, detail));
    }

    /// Assert a condition as a step; returns the condition.
    pub fn check(
        &mut self,
        module: &str,
        name: &str,
        cond: bool,
        detail: impl Into<String>,
    ) -> bool {
        self.record(module, name, cond, detail);
        cond
    }

    /// Print the summary; return true iff every step passed.
    pub fn print_and_status(&self) -> bool {
        let total = self.steps.len();
        let failed: Vec<_> = self.steps.iter().filter(|s| !s.2).collect();
        println!("\n────────────────────────────────────────");
        if failed.is_empty() {
            println!("\x1b[32mQA PASS\x1b[0m — {total}/{total} steps green");
        } else {
            println!("\x1b[31mQA FAIL\x1b[0m — {}/{total} failed:", failed.len());
            for (m, n, _, d) in &failed {
                println!("    ✗ [{m}] {n} — {d}");
            }
        }
        failed.is_empty()
    }
}

/// Build an in-memory ciris-server [`Engine`] with a SOFTWARE hybrid signer (the
/// node's own key registered under its derived id, mirroring prod compose).
pub async fn node() -> Arc<Engine> {
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
    let engine = Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer (sqlite::memory:)"),
    );
    register_node_self(&engine).await;
    engine
}

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

/// Mint an owner (ROOT) session bearer.
pub async fn mint_owner_session(engine: &Engine) -> String {
    let now = chrono::Utc::now();
    let cert = WaCert {
        wa_id: "qa-owner".into(),
        name: "qa-owner".into(),
        role: WaRole::Root,
        pubkey: BASE64.encode([0u8; 32]),
        jwt_kid: "kid-qa-owner".into(),
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
    "sess:qa-owner:testtoken".into()
}

/// Serve the accord router (with the given halt config) on an ephemeral port.
pub async fn serve(engine: Arc<Engine>, halt: AccordHalt) -> String {
    let app = ciris_server::accord::router_with_halt(engine, halt);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

/// A software-key identity (Ed25519 + ML-DSA-65) — a stand-in for a YubiKey-backed
/// holder / family member for the software QA pass.
pub struct SoftId {
    pub key_id: String,
    ed: SigningKey,
    mldsa: MlDsa65SoftwareSigner,
}

impl SoftId {
    pub fn new(key_id: &str, seed: u8) -> Self {
        SoftId {
            key_id: key_id.to_string(),
            ed: SigningKey::from_bytes(&[seed; 32]),
            mldsa: MlDsa65SoftwareSigner::from_seed_bytes(
                &[seed ^ 0xFF; 32],
                format!("{key_id}-pqc"),
            )
            .expect("ml-dsa seed"),
        }
    }

    pub fn ed_pub_b64(&self) -> String {
        BASE64.encode(self.ed.verifying_key().to_bytes())
    }

    pub async fn mldsa_pub_b64(&self) -> String {
        BASE64.encode(self.mldsa.public_key().await.expect("ml-dsa pk"))
    }

    fn android_evidence() -> serde_json::Value {
        serde_json::json!({
            "platform_attestation": { "Android": {
                "key_attestation_chain": [[48, 130], [48, 130]],
                "play_integrity_token": "eyJhbGciOiJIUzI1NiJ9.fake.token",
                "strongbox_backed": true,
            }},
            "nonce_captured_at": chrono::Utc::now().to_rfc3339(),
        })
    }

    /// A self-signed `SignedKeyRecord` of the given `identity_type`. `accord_holder`
    /// carries the hardware `attestation_evidence` the admission gate requires; other
    /// types (e.g. `user` family members) carry none.
    pub async fn signed_key_record(&self, identity_type: &str) -> SignedKeyRecord {
        let now = chrono::Utc::now();
        let envelope = serde_json::json!({ "key_id": self.key_id });
        let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize");
        let ed_sig = self.ed.sign(&canonical).to_bytes();
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = self.mldsa.sign(&bound).await.expect("ml-dsa sign reg");
        let evidence = if identity_type == identity_type::ACCORD_HOLDER {
            Some(Self::android_evidence())
        } else {
            None
        };
        let record = KeyRecord {
            key_id: self.key_id.clone(),
            pubkey_ed25519_base64: self.ed_pub_b64(),
            pubkey_ml_dsa_65_base64: Some(self.mldsa_pub_b64().await),
            algorithm: algorithm::HYBRID.into(),
            identity_type: identity_type.into(),
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
            attestation_evidence: evidence,
        };
        SignedKeyRecord { record }
    }

    /// Co-sign a JCS family envelope (Ed25519 over bytes; ML-DSA over bytes‖ed_sig).
    pub async fn family_cosign(&self, envelope: &serde_json::Value) -> serde_json::Value {
        let bytes =
            ciris_verify_core::accord_genesis::accord_family_signing_bytes(envelope).expect("jcs");
        let ed_sig = self.ed.sign(&bytes).to_bytes();
        let mut bound = bytes.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = self.mldsa.sign(&bound).await.expect("ml-dsa family cosign");
        serde_json::json!({
            "member_id": self.key_id,
            "ed25519_signature_base64": BASE64.encode(ed_sig),
            "mldsa65_signature_base64": BASE64.encode(&pqc_sig),
        })
    }

    /// Sign RAW bytes (bound hybrid: Ed25519 over `bytes`, ML-DSA over `bytes‖ed_sig`)
    /// — for membership-change payloads (`jcs(change_envelope)`).
    pub async fn sign_bytes(&self, bytes: &[u8]) -> serde_json::Value {
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

    /// This identity as a founder `ThresholdMember` JSON.
    pub async fn founder_member(&self) -> serde_json::Value {
        serde_json::json!({
            "member_id": self.key_id,
            "ed25519_public_key_base64": self.ed_pub_b64(),
            "mldsa65_public_key_base64": self.mldsa_pub_b64().await,
            "role": "founder",
        })
    }

    /// Co-sign an accord invocation (Ed25519 over canonical bytes; ML-DSA over
    /// canonical‖ed_sig). `kind` is "CONSTITUTIONAL" | "notify" | "drill".
    pub async fn cosign_invocation(&self, inv: &serde_json::Value) -> serde_json::Value {
        let canonical = invocation_canonical_bytes(inv);
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

/// Seat an accord holder DIRECTLY via the engine admission gate (the kill-switch
/// LOGIC path). The HTTP `POST /v1/accord/holder` now MANDATES a FIPS YubiKey custody
/// attestation a software run cannot produce (the B1 safe-mesh-floor fix); the QA
/// scenarios prove the roster / quorum / halt / governance logic, which is
/// independent of HOW a holder reached persist, so they seat holders here with the
/// same hardware `attestation_evidence` the persist gate requires. (The HTTP custody
/// gate is exercised by `tests/accord.rs`'s rejection tests.)
pub async fn seat_holder(engine: &Engine, h: &SoftId) -> bool {
    engine
        .register_federation_key(h.signed_key_record(identity_type::ACCORD_HOLDER).await)
        .await
        .is_ok()
}

/// Build an `Invocation` JSON (the §9.2.1 shape the server deserializes).
pub fn invocation(kind: &str, id: &str, payload: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "invocation_kind": kind,
        "invocation_id": id,
        "nonce": BASE64.encode([7u8; 32]),
        "asserted_at": "2026-06-21T00:00:00.000Z",
        "valid_until": "2031-01-01T00:00:00.000Z",
        "payload_sha256": hex::encode(Sha256::digest(payload)),
    })
}

/// Recompute the verify §9.2.1 canonical bytes for an invocation JSON (must match
/// `ciris_verify_core::humanity_accord::Invocation::canonical_bytes`).
fn invocation_canonical_bytes(inv: &serde_json::Value) -> Vec<u8> {
    let s = |k: &str| inv[k].as_str().unwrap_or_default().to_string();
    format!(
        "ciris.accord_invoke.v1\ninvocation_kind={}\ninvocation_id={}\nnonce={}\nasserted_at={}\nvalid_until={}\npayload_sha256={}",
        s("invocation_kind"),
        s("invocation_id"),
        s("nonce"),
        s("asserted_at"),
        s("valid_until"),
        s("payload_sha256"),
    )
    .into_bytes()
}
