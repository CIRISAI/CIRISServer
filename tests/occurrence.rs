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
//!   2. Both devices are in the roster (the client device list, which
//!      `GET /v1/self/occurrences` serves to the owner's own session only —
//!      CIRISServer#655; an unauthenticated read of this un-announced self is
//!      empty).
//!   3. The PRIMARY then signs `POST /v1/self/occurrence/revoke` to revoke the
//!      second device. After it, `signer_acts_for(second, self)` is FALSE, and
//!      the roster no longer holds it.
//!   4. A signer who does NOT act for the self (an unrelated key) is rejected 403.
//!
//! **0.5.218 (CSD-037).** The revoke moved to `crate::self_devices` and became
//! one act with node release (`evict_device`): the OWNER's session authorises
//! it and the owner's pen signs the revocation through persist's SIGNED,
//! replicating door. A device-signed request with no session is now refused
//! (step 3 asserts that, and that nothing was revoked); the revoke itself is
//! witnessed on a claimed node below — the signed row read back byte-exact
//! through `list_signed_identity_occurrence_revocations_for`, an occurrence
//! that IS an owned node losing its owner-binding too, and a source gate that
//! the trusted-local door has no caller in `src/`.

#[path = "support/owned_node.rs"]
mod owned_node;

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
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
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
    // v14 (CIRISPersist#418): fixture bind rides the TRUSTED-LOCAL path — the same
    // one `bind_occurrence_core` uses for content-only device binds (the signed gate
    // now requires a producer-signed envelope with a transport_destination).
    engine
        .federation_directory()
        .put_identity_occurrence_local(ciris_persist::federation::IdentityOccurrence {
            identity_key_id: identity_key_id.to_string(),
            occurrence_key_id: dev.key_id.clone(),
            device_class: "laptop".into(),
            hardware_attestation: None,
            asserted_at: now,
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("bind primary occurrence");
}

/// Serve the occurrence router — and, since 0.5.218, the self-device router
/// the revoke moved to — on an ephemeral port.
async fn serve(engine: Arc<Engine>) -> (String, tokio::task::JoinHandle<()>) {
    let app = occurrence::router(Arc::clone(&engine), HybridPolicy::Strict).merge(
        ciris_server::self_devices::router(engine, std::env::temp_dir().join("no-owner-seed")),
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

    // ── (2) LIST: both devices are in the roster ──
    //
    // Read from the directory the route serves the OWNER from: this fixture has
    // no owner session (the self here owns no node), and since CIRISServer#655
    // an unauthenticated read of a person who announced no node is the same
    // empty answer an unknown identity gets.
    let ids = active_roster(&engine, identity).await;
    assert_eq!(ids.len(), 2, "both devices bound: {ids:?}");
    assert!(ids.contains(&primary.key_id));
    assert!(ids.contains(&second.key_id));
    let resp = client
        .get(format!(
            "{base}/v1/self/occurrences?identity_key_id={identity}"
        ))
        .send()
        .await
        .expect("GET occurrences");
    assert_eq!(resp.status(), 200);
    let list: serde_json::Value = resp.json().await.expect("list json");
    assert_eq!(
        list["occurrences"].as_array().map(Vec::len),
        Some(0),
        "an unauthenticated caller sees nothing of an un-announced person: {list}"
    );

    // ── (3) REVOKE by a device signature alone: REFUSED since 0.5.218 ──
    //
    // The revocation is the OWNER's act, signed with the owner's pen through
    // persist's signed door (CSD-037); a request carrying only a device's
    // signature and no owner session never reaches it — and, before 0.5.218,
    // it wrote the unsigned local-only row that never left this node.
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
    assert_eq!(
        status, 401,
        "a device signature is not an owner session: {json}"
    );
    assert_eq!(json["reason_id"], "self.owner_session_required", "{json}");
    assert!(
        signer_acts_for(&engine, &second.key_id, identity).await,
        "nothing was revoked"
    );
    assert_eq!(active_roster(&engine, identity).await.len(), 2);
}

// ─── 0.5.218: the revoke is the owner's SIGNED, replicating act ─────────────

use owned_node::{assert_refused, Person};

/// Register a device key and bind it as an occurrence of `p`'s self, with
/// content-KEM keys (so it is a wrap recipient). Returns its key id.
async fn phone_of(p: &Person, tag: u8) -> String {
    let key_id = format!("{}-phone-{tag}", p.owner.alias);
    let dev = Device::new(&key_id, tag);
    register_key(&p.engine, &dev, "user").await;
    p.engine
        .federation_directory()
        .put_identity_occurrence_local(ciris_persist::federation::IdentityOccurrence {
            identity_key_id: p.key().to_owned(),
            occurrence_key_id: key_id.clone(),
            device_class: "phone".into(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: Some(
                ciris_server::identity::derive_self_enc_pubkeys(&[tag; 32]).expect("enc keys"),
            ),
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("bind the phone");
    key_id
}

/// **(i) The revoke writes a SIGNED revocation** — readable through persist's
/// byte-exact re-read (`list_signed_identity_occurrence_revocations_for`,
/// which omits the unsigned local rows), attested by the OWNER — and every
/// answer says what eviction does not do.
#[tokio::test]
async fn the_owner_revokes_a_device_with_a_signed_replicating_revocation() {
    let alice = Person::new("occ-rev").await;
    let phone = phone_of(&alice, 0x51).await;
    let kept = phone_of(&alice, 0x53).await;
    let dir = alice.engine.federation_directory();
    assert!(
        dir.list_signed_identity_occurrence_revocations_for(alice.key())
            .await
            .expect("signed revocations")
            .is_empty(),
        "precondition: nothing revoked"
    );

    let (st, v) = alice
        .as_owner(
            "POST",
            "/v1/self/occurrence/revoke",
            Some(serde_json::json!({
                "identity_key_id": alice.key(),
                "occurrence_key_id": phone,
                "reason": "phone stolen",
            })),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(v["revoked"], true, "{v}");
    assert_eq!(v["revoked_by"], alice.key());
    assert_eq!(
        v["occurrences_revoked"].as_array().map(Vec::len),
        Some(1),
        "{v}"
    );
    assert!(v["failed"].as_array().is_some_and(Vec::is_empty), "{v}");
    assert!(
        v["history"]
            .as_str()
            .is_some_and(|h| h.contains("Already-shared history stays readable")),
        "the answer says what eviction does NOT do: {v}"
    );

    // THE SIGNED ROW, read back the way a replicator re-publishes it.
    let signed = dir
        .list_signed_identity_occurrence_revocations_for(alice.key())
        .await
        .expect("signed revocations");
    let row = signed
        .iter()
        .find(|r| r.identity_occurrence_revocation.occurrence_key_id == phone)
        .expect("the revocation is on the SIGNED surface — not the local door");
    assert_eq!(row.attesting_key_id, alice.key(), "the owner signed it");
    assert_eq!(row.signed_envelope["occurrence_key_id"], phone.as_str());
    assert_eq!(row.signed_envelope["reason"], "phone stolen");
    assert!(row.signature.mldsa65_signature_base64.is_some(), "hybrid");

    // The device is out of the self; the other one is not.
    assert!(!signer_acts_for(&alice.engine, &phone, alice.key()).await);
    assert!(signer_acts_for(&alice.engine, &kept, alice.key()).await);
    let active = active_roster(&alice.engine, alice.key()).await;
    assert!(
        !active.contains(&phone) && active.contains(&kept),
        "{active:?}"
    );

    // Again: already revoked — nothing to sign, and said so.
    let (st, v) = alice
        .as_owner(
            "POST",
            "/v1/self/occurrence/revoke",
            Some(serde_json::json!({
                "identity_key_id": alice.key(),
                "occurrence_key_id": phone,
            })),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(v["occurrences_already_revoked"], serde_json::json!([phone]));
}

/// The revoke's gate: the owner's session, never a delegate, and only the
/// caller's own occurrences — one id for "someone else's" and "nobody's".
#[tokio::test]
async fn only_the_owner_revokes_and_only_their_own_devices() {
    let alice = Person::new("occ-gate").await;
    let bob = Person::new("occ-gate-b").await;
    let phone = phone_of(&alice, 0x61).await;
    let bobs = phone_of(&bob, 0x63).await;
    alice.knows(&bob).await;
    let body = |identity: &str, occ: &str| serde_json::json!({ "identity_key_id": identity, "occurrence_key_id": occ });
    let path = "/v1/self/occurrence/revoke";
    let r = alice
        .call("POST", path, None, Some(body(alice.key(), &phone)))
        .await;
    assert_refused(&r, 401, "self.owner_session_required");
    let guest = alice.stranger_session().await;
    let r = alice
        .call("POST", path, Some(&guest), Some(body(alice.key(), &phone)))
        .await;
    assert_refused(&r, 403, "self.owner_session_required");
    let delegated = alice.delegated_session().await;
    let r = alice
        .call(
            "POST",
            path,
            Some(&delegated),
            Some(body(alice.key(), &phone)),
        )
        .await;
    assert_refused(&r, 403, "self.delegate_may_not_author");
    // Bob's identity, Bob's phone under Alice's identity, a key nobody bound.
    let r = alice
        .as_owner("POST", path, Some(body(bob.key(), &bobs)))
        .await;
    assert_refused(&r, 404, "self.not_your_device");
    let r = alice
        .as_owner("POST", path, Some(body(alice.key(), &bobs)))
        .await;
    assert_refused(&r, 404, "self.not_your_device");
    let r = alice
        .as_owner("POST", path, Some(body(alice.key(), "no-such-device")))
        .await;
    assert_refused(&r, 404, "self.not_your_device");
    assert!(
        signer_acts_for(&alice.engine, &phone, alice.key()).await,
        "nothing was revoked"
    );
}

/// **The two routes are one act:** revoking an occurrence that IS one of the
/// owner's nodes also withdraws that node's owner-binding, so the self room
/// drops it too — not only the wraps.
#[tokio::test]
async fn revoking_a_node_occurrence_also_releases_the_node() {
    use ciris_persist::federation::admission::nodes_owned_by;
    let alice = Person::new("occ-node").await;
    let node = "occ-second-node-0x71".to_owned();
    let dev = Device::new(&node, 0x71);
    register_key(&alice.engine, &dev, "node").await;
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    ciris_server::auth::ownership::emit_steward_binding(
        &alice.engine,
        &alice.owner.signer().await,
        &node,
        &scopes,
    )
    .await
    .expect("owner-bind the second node");
    alice
        .engine
        .federation_directory()
        .put_identity_occurrence_local(ciris_persist::federation::IdentityOccurrence {
            identity_key_id: alice.key().to_owned(),
            occurrence_key_id: node.clone(),
            device_class: "server".into(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("the node's content occurrence");
    let owned = |e: Arc<Engine>, k: String| async move {
        nodes_owned_by(e.federation_directory().as_ref(), &k)
            .await
            .expect("nodes_owned_by")
    };
    assert!(owned(Arc::clone(&alice.engine), alice.key().to_owned())
        .await
        .contains(&node));

    let (st, v) = alice
        .as_owner(
            "POST",
            "/v1/self/occurrence/revoke",
            Some(serde_json::json!({
                "identity_key_id": alice.key(),
                "occurrence_key_id": node,
            })),
        )
        .await;
    assert_eq!(st.as_u16(), 200, "{v}");
    assert_eq!(v["nodes"], serde_json::json!([node]), "{v}");
    assert_eq!(v["withdrawn"].as_array().map(Vec::len), Some(1), "{v}");
    assert_eq!(
        v["occurrences_revoked"].as_array().map(Vec::len),
        Some(1),
        "{v}"
    );
    assert!(
        !owned(Arc::clone(&alice.engine), alice.key().to_owned())
            .await
            .contains(&node),
        "the owner-binding went with the occurrence"
    );
    // Revoking the occurrence of the node you are talking to needs force, as
    // releasing it does.
    let (occ, _) = ciris_server::backend::provision_engine_occurrence(&alice.engine, alice.key())
        .await
        .expect("this node's occurrence");
    let r = alice
        .as_owner(
            "POST",
            "/v1/self/occurrence/revoke",
            Some(serde_json::json!({
                "identity_key_id": alice.key(),
                "occurrence_key_id": occ,
            })),
        )
        .await;
    assert_refused(&r, 409, "self.release_self_requires_force");
}

/// **The trusted-local revocation door has no caller in `src/`.** Its rows
/// are unsigned and excluded from the signed replication read by
/// construction, so a revocation written through it never leaves the node —
/// the gap `evict_device` closed (CSD-037). The allow-list is empty on
/// purpose: a new caller must argue for itself here, by name.
#[test]
fn the_local_revocation_door_has_no_caller_in_src() {
    const ALLOWED: &[&str] = &[];
    let mut hits = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src"
    ))];
    let mut scanned = 0usize;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            scanned += 1;
            let text = std::fs::read_to_string(&path).expect("read source");
            for (n, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if code.contains("put_identity_occurrence_revocation_local") {
                    let rel = path
                        .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                        .unwrap_or(&path)
                        .display()
                        .to_string();
                    if !ALLOWED.contains(&rel.as_str()) {
                        hits.push(format!("{rel}:{}: {}", n + 1, line.trim()));
                    }
                }
            }
        }
    }
    assert!(
        scanned > 50,
        "the gate scanned {scanned} files — pointed at the wrong tree?"
    );
    assert!(
        hits.is_empty(),
        "put_identity_occurrence_revocation_local is called from src/ — its rows never replicate; \
         revoke through self_devices::evict_device (the signed door):\n{}",
        hits.join("\n")
    );
}

/// The ACTIVE occurrence keys of `identity` — what `GET /v1/self/occurrences`
/// serves the identity's own owner session.
async fn active_roster(engine: &Engine, identity: &str) -> Vec<String> {
    engine
        .federation_directory()
        .list_identity_occurrences_active(identity)
        .await
        .expect("active occurrences")
        .into_iter()
        .map(|o| o.occurrence_key_id)
        .collect()
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
