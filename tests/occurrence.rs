//! Self-occurrence **enrollment** (CIRISServer#76) — "add a second device (e.g. a
//! phone) as an occurrence of my self, so a hardware-sealed fed-ID survives a
//! laptop loss".
//!
//! Drives the real `occurrence::router` over a bound TCP listener (full HTTP +
//! hybrid-auth stack) and proves the survive-a-device-loss story end to end:
//!
//!   1. The PRIMARY (the self's first device) signs `POST /v1/self/occurrence`
//!      to enroll a SECOND device. After it, `signer_acts_for(second, self)` is
//!      TRUE — the backup device can now act AS the self.
//!   2. `GET /v1/self/occurrences` lists both devices (the client device list).
//!   3. The PRIMARY then signs `POST /v1/self/occurrence/revoke` to revoke the
//!      second device. After it, `signer_acts_for(second, self)` is FALSE, and
//!      the list no longer shows it.
//!   4. A signer who does NOT act for the self (an unrelated key) is rejected 403.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::types::{algorithm, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};

use ciris_server::auth::occurrence;
use ciris_server::auth::verify::signer_acts_for;

const NODE_KEY_ID: &str = "ciris-server";

/// A software hybrid keypair standing in for a device's (or the self's) signing
/// key. Produces the `x-ciris-*` request signatures: Ed25519 over the body, then
/// ML-DSA-65 over `body ‖ ed25519_sig` (the bound hybrid scheme the verifier
/// rebuilds — ciris-crypto `HybridVerifier::verify`).
struct Device {
    key_id: String,
    ed: SigningKey,
    mldsa: MlDsa65SoftwareSigner,
}

impl Device {
    fn new(key_id: &str, seed: u8) -> Self {
        Device {
            key_id: key_id.to_string(),
            ed: SigningKey::from_bytes(&[seed; 32]),
            mldsa: MlDsa65SoftwareSigner::from_seed_bytes(
                &[seed ^ 0xFF; 32],
                format!("{key_id}-pqc"),
            )
            .expect("device ML-DSA-65 seed"),
        }
    }

    fn ed_pubkey_b64(&self) -> String {
        BASE64.encode(self.ed.verifying_key().to_bytes())
    }

    async fn mldsa_pubkey_b64(&self) -> String {
        BASE64.encode(self.mldsa.public_key().await.expect("ml-dsa pubkey"))
    }

    /// Compute the `(x-ciris-signing-key-id, x-ciris-signature-ed25519,
    /// x-ciris-signature-ml-dsa-65)` header trio over `body`.
    async fn sign_headers(&self, body: &[u8]) -> (String, String, String) {
        let ed_sig = self.ed.sign(body).to_bytes();
        let mut bound = body.to_vec();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = self.mldsa.sign(&bound).await.expect("ml-dsa sign body");
        (
            self.key_id.clone(),
            BASE64.encode(ed_sig),
            BASE64.encode(&pqc_sig),
        )
    }
}

/// Stand up THIS node — an in-memory hybrid substrate.
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

/// Insert a `federation_keys` row for a device's REAL pubkeys (so the request
/// hybrid-verify against the directory passes). `put_public_key` verifies no PoP,
/// so the test admits the key directly — mirrors the device_grant/accord fixtures.
async fn register_key(engine: &Engine, dev: &Device, identity_type: &str) {
    let now = chrono::Utc::now();
    let record = KeyRecord {
        key_id: dev.key_id.clone(),
        pubkey_ed25519_base64: dev.ed_pubkey_b64(),
        pubkey_ml_dsa_65_base64: Some(dev.mldsa_pubkey_b64().await),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type.to_string(),
        identity_ref: dev.key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": dev.key_id }),
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: dev.key_id.clone(),
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

/// Bind `dev` as the PRIMARY occurrence of `identity` directly through persist —
/// the precondition for the enrollment flow (the self already has one device).
async fn bind_primary(engine: &Engine, identity_key_id: &str, dev: &Device) {
    let now = chrono::Utc::now();
    engine
        .federation_directory()
        .put_identity_occurrence(ciris_persist::federation::SignedIdentityOccurrence {
            identity_occurrence: ciris_persist::federation::IdentityOccurrence {
                identity_key_id: identity_key_id.to_string(),
                occurrence_key_id: dev.key_id.clone(),
                device_class: "laptop".into(),
                hardware_attestation: None,
                asserted_at: now,
                valid_until: None,
                encryption_pubkeys: None,
                persist_row_hash: String::new(),
            },
        })
        .await
        .expect("bind primary occurrence");
}

/// Serve the occurrence router on an ephemeral port.
async fn serve(engine: Arc<Engine>) -> (String, tokio::task::JoinHandle<()>) {
    let app = occurrence::router(engine, HybridPolicy::Strict);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// POST a JSON body signed by `signer` to `path`, returning (status, json).
async fn signed_post(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    signer: &Device,
    body: &serde_json::Value,
) -> (u16, serde_json::Value) {
    let bytes = serde_json::to_vec(body).expect("serialize body");
    let (key_id, ed_sig, ml_dsa) = signer.sign_headers(&bytes).await;
    let resp = client
        .post(format!("{base}{path}"))
        .header("content-type", "application/json")
        .header("x-ciris-signing-key-id", key_id)
        .header("x-ciris-signature-ed25519", ed_sig)
        .header("x-ciris-signature-ml-dsa-65", ml_dsa)
        .body(bytes)
        .send()
        .await
        .expect("send signed POST");
    let status = resp.status().as_u16();
    let json = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn enroll_second_device_then_revoke_it() {
    let engine = node().await;

    // The self's root identity key, its PRIMARY device (laptop), and a SECOND
    // device (phone) the founder wants as a backup.
    let identity = "self-founder-root";
    let identity_dev = Device::new(identity, 0x10);
    let primary = Device::new("self-laptop-1", 0x20);
    let second = Device::new("self-phone-2", 0x30);
    let stranger = Device::new("unrelated-key", 0x40);

    register_key(&engine, &identity_dev, "user").await;
    register_key(&engine, &primary, "user").await;
    register_key(&engine, &second, "user").await;
    register_key(&engine, &stranger, "user").await;

    // The self already has one device (the laptop) as an active occurrence.
    bind_primary(&engine, identity, &primary).await;
    assert!(
        signer_acts_for(&engine, &primary.key_id, identity).await,
        "primary must act for the self before enrollment"
    );
    assert!(
        !signer_acts_for(&engine, &second.key_id, identity).await,
        "second device must NOT act for the self before enrollment"
    );

    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    // ── (1) ADD: the PRIMARY enrolls the SECOND device as a phone occurrence ──
    let add_body = serde_json::json!({
        "identity_key_id": identity,
        "occurrence": {
            "occurrence_key_id": second.key_id,
            "device_class": "phone",
        },
    });
    let (status, json) =
        signed_post(&client, &base, "/v1/self/occurrence", &primary, &add_body).await;
    assert_eq!(status, 200, "add occurrence must succeed: {json}");
    assert_eq!(json["occurrence_key_id"], second.key_id);
    assert_eq!(json["device_class"], "phone");
    assert_eq!(
        json["key_freshly_registered"], false,
        "key was pre-registered"
    );

    // The whole point: the second device can now act AS the self.
    assert!(
        signer_acts_for(&engine, &second.key_id, identity).await,
        "after enrollment the second device MUST act for the self"
    );

    // ── (2) LIST: both devices show in the roster ──
    let resp = client
        .get(format!(
            "{base}/v1/self/occurrences?identity_key_id={identity}"
        ))
        .send()
        .await
        .expect("GET occurrences");
    assert_eq!(resp.status(), 200);
    let list: serde_json::Value = resp.json().await.expect("list json");
    let occs = list["occurrences"].as_array().expect("occurrences array");
    assert_eq!(occs.len(), 2, "both devices listed: {list}");
    let ids: Vec<&str> = occs
        .iter()
        .map(|o| o["occurrence_key_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&primary.key_id.as_str()));
    assert!(ids.contains(&second.key_id.as_str()));

    // ── (3) REVOKE: the PRIMARY revokes the (lost) SECOND device ──
    let revoke_body = serde_json::json!({
        "identity_key_id": identity,
        "occurrence_key_id": second.key_id,
        "reason": "phone lost",
    });
    let (status, json) = signed_post(
        &client,
        &base,
        "/v1/self/occurrence/revoke",
        &primary,
        &revoke_body,
    )
    .await;
    assert_eq!(status, 200, "revoke must succeed: {json}");
    assert_eq!(
        json["revoked_by"], primary.key_id,
        "surviving key authored it"
    );

    // The revoked device can no longer act as the self.
    assert!(
        !signer_acts_for(&engine, &second.key_id, identity).await,
        "after revocation the second device must NOT act for the self"
    );
    // ...and the primary still can (revocation is scoped to the one device).
    assert!(
        signer_acts_for(&engine, &primary.key_id, identity).await,
        "the surviving device still acts for the self"
    );

    // The list drops the revoked device.
    let resp = client
        .get(format!(
            "{base}/v1/self/occurrences?identity_key_id={identity}"
        ))
        .send()
        .await
        .expect("GET occurrences after revoke");
    let list: serde_json::Value = resp.json().await.expect("list json");
    let occs = list["occurrences"].as_array().expect("occurrences array");
    assert_eq!(occs.len(), 1, "only the surviving device remains: {list}");
    assert_eq!(occs[0]["occurrence_key_id"], primary.key_id);
}

#[tokio::test]
async fn stranger_cannot_enroll_a_device_for_someone_elses_self() {
    let engine = node().await;
    let identity = "victim-root";
    let identity_dev = Device::new(identity, 0x11);
    let primary = Device::new("victim-laptop", 0x21);
    let stranger = Device::new("attacker-key", 0x31);
    let attacker_device = Device::new("attacker-device", 0x41);

    register_key(&engine, &identity_dev, "user").await;
    register_key(&engine, &primary, "user").await;
    register_key(&engine, &stranger, "user").await;
    register_key(&engine, &attacker_device, "user").await;
    bind_primary(&engine, identity, &primary).await;

    let (base, _h) = serve(Arc::clone(&engine)).await;
    let client = reqwest::Client::new();

    // A validly-signed request — but the SIGNER does not act for the victim's
    // self, so it must be refused: an attacker cannot graft a device onto your
    // identity even with a registered key of their own.
    let body = serde_json::json!({
        "identity_key_id": identity,
        "occurrence": {
            "occurrence_key_id": attacker_device.key_id,
            "device_class": "phone",
        },
    });
    let (status, json) = signed_post(&client, &base, "/v1/self/occurrence", &stranger, &body).await;
    assert_eq!(
        status, 403,
        "a non-occurrence signer must be forbidden: {json}"
    );
    assert!(
        !signer_acts_for(&engine, &attacker_device.key_id, identity).await,
        "the attacker's device must NOT have been enrolled"
    );
}
