//! **CC 4.2.2.1 — a `hardware_class` claim is admitted only against a real
//! attestation** (CIRISServer#159; closes CC 8.3.1 R5).
//!
//! Drives [`ciris_server::hardware_attestation`] directly. The gap under test:
//! `federation_keys.hardware_class` (which rides inside `attestation_evidence`)
//! used to be an UNCHECKED SELF-REPORT — persist runs its
//! `HardwareAttestationPolicy` ONLY for `identity_type = 'accord_holder'` rows,
//! so every other admission path (peering, claim, occurrence, device grant) took
//! the node's word for "my key lives in a TPM / Secure Enclave / StrongBox".
//!
//! The four properties CC 4.2.2.1 requires, one test each:
//!
//! 1. a VALID attestation admits at the claimed class
//!    (`valid_yubikey_attestation_admits_at_the_claimed_class`);
//! 2. a MISSING attestation under a hardware-class claim is refused
//!    (`hardware_class_claim_with_no_attestation_is_refused`, plus
//!    `unverifiable_hardware_class_is_refused` — a class we hold no root for);
//! 3. a FORGED / MISMATCHED attestation is refused
//!    (`forged_attestation_under_an_attacker_root_is_refused`,
//!    `attestation_bound_to_another_key_is_refused`,
//!    `stale_attestation_nonce_is_refused`);
//! 4. a software-class claim needs no attestation
//!    (`no_attestation_evidence_is_admitted_as_software_class`).
//!
//! Plus the end-to-end fail-closed proof: a rejected claim leaves NO
//! `federation_keys` row (`refused_claim_leaves_no_federation_key_row`).
//!
//! The chain is GENERATED under a test root: nobody can mint a certificate under
//! the real pinned Yubico Attestation Root 1, so the tests drive
//! `admit_hardware_class_against_root` (the factored-out testable core — the same
//! shape CIRISVerify factors `verify_yubikey_piv_attestation` out for) and the
//! production `admit_hardware_class` is the one caller that passes the real root.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use rcgen::{CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair, PKCS_ED25519};
use sha2::{Digest, Sha256};

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

use ciris_server::hardware_attestation::{
    admit_hardware_class_against_root, register_attested_federation_key, AdmittedHardwareClass,
};

/// Yubico's touch-policy byte meaning "touch required for every use" — the floor
/// `verify_yubikey_piv_attestation` enforces on the 9c leaf.
const TOUCH_ALWAYS: u8 = 0x02;

// ─── the device under test: a key record + its (mock) YubiKey attestation ─────

/// A device that holds an Ed25519 + ML-DSA-65 federation key and can present a
/// PIV attestation for it. `seed` drives BOTH the federation Ed25519 half and the
/// rcgen keypair the mock 9c leaf attests, so the attestation is genuinely ABOUT
/// this record's key (which is exactly what the gate's key-binding check tests).
struct Device {
    key_id: String,
    seed: [u8; 32],
    ed: SigningKey,
    mldsa: MlDsa65SoftwareSigner,
}

impl Device {
    fn new(key_id: &str, seed_byte: u8) -> Self {
        let seed = [seed_byte; 32];
        Self {
            key_id: key_id.to_string(),
            seed,
            ed: SigningKey::from_bytes(&seed),
            mldsa: MlDsa65SoftwareSigner::from_seed_bytes(
                &[seed_byte ^ 0xFF; 32],
                format!("{key_id}-pqc"),
            )
            .expect("device ML-DSA-65 seed"),
        }
    }

    /// rcgen's view of the SAME Ed25519 key (PKCS#8 of the raw seed) — so the mock
    /// 9c certificate's SubjectPublicKeyInfo IS this record's `pubkey_ed25519`.
    fn rcgen_keypair(&self) -> KeyPair {
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(&self.seed);
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            BASE64.encode(&der)
        );
        KeyPair::from_pkcs8_pem_and_sign_algo(&pem, &PKCS_ED25519).expect("rcgen ed25519 keypair")
    }

    /// The device's self-signed `SignedKeyRecord` (the canonical admission shape:
    /// hybrid bound PoP over `ceg_produce_canonicalize(registration_envelope)`),
    /// carrying whatever `attestation_evidence` the test wants to claim.
    async fn key_record(&self, evidence: Option<serde_json::Value>) -> SignedKeyRecord {
        use ed25519_dalek::Signer as _;
        let now = chrono::Utc::now();
        let envelope = serde_json::json!({ "key_id": self.key_id });
        let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize registration");
        let ed_sig = self.ed.sign(&canonical).to_bytes();
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = self
            .mldsa
            .sign(&bound)
            .await
            .expect("ml-dsa sign registration");
        let record = KeyRecord {
            key_id: self.key_id.clone(),
            pubkey_ed25519_base64: BASE64.encode(self.ed.verifying_key().to_bytes()),
            pubkey_ml_dsa_65_base64: Some(
                BASE64.encode(self.mldsa.public_key().await.expect("ml-dsa pk")),
            ),
            algorithm: algorithm::HYBRID.into(),
            // A NODE row — the whole point: persist's own hardware gate does NOT run
            // for this identity_type (it fires only for `accord_holder`), so before
            // CIRISServer#159 this row's class claim was believed on sight.
            identity_type: identity_type::NODE.into(),
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
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        SignedKeyRecord { record }
    }
}

// ─── mock YubiKey PIV attestation chain (root → f9 → 9c) ──────────────────────

fn params(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    p.distinguished_name = dn;
    p
}

/// Build `root → f9 → 9c` attesting `leaf_kp`, mirroring the real YubiKey
/// encoding: the 9c leaf carries firmware (`…3.3`) + pin/touch (`…3.8`) as inner
/// DER OCTET STRINGs; the FIPS marker (`…3.10`) rides the factory f9 cert.
/// Returns `(9c_der, f9_der, root_der)`.
fn mock_chain(leaf_kp: &KeyPair) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let root_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let root = params("Yubico Attestation Root (TEST)")
        .self_signed(&root_kp)
        .unwrap();
    let f9_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut f9_params = params("YubiKey PIV Attestation (TEST f9)");
    f9_params.custom_extensions = vec![CustomExtension::from_oid_content(
        &[1, 3, 6, 1, 4, 1, 41482, 3, 10], // FIPS-certified marker
        vec![],
    )];
    let f9 = f9_params.signed_by(&f9_kp, &root, &root_kp).unwrap();

    let mut leaf = params("YubiKey PIV Attestation 9c");
    leaf.custom_extensions = vec![
        // firmware 5.7.4, OCTET STRING-wrapped
        CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 41482, 3, 3],
            vec![0x04, 0x03, 5, 7, 4],
        ),
        // [pin_policy=once, touch_policy=always], OCTET STRING-wrapped
        CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 41482, 3, 8],
            vec![0x04, 0x02, 0x01, TOUCH_ALWAYS],
        ),
    ];
    let cert_9c = leaf.signed_by(leaf_kp, &f9, &f9_kp).unwrap();
    (
        cert_9c.der().to_vec(),
        f9.der().to_vec(),
        root.der().to_vec(),
    )
}

/// The `{platform_attestation, nonce_captured_at}` shape persist's
/// `AttestationEvidence` deserializes — an `ExternalSecureElement` (FIPS YubiKey
/// PIV) hardware-class claim backed by `cert_9c` + `[f9]`.
fn ese_evidence(
    cert_9c: &[u8],
    f9: &[u8],
    captured_at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    serde_json::json!({
        "platform_attestation": {
            "ExternalSecureElement": {
                "hardware_class": "YubiKey_5_FIPS",
                "attestation_cert_der": cert_9c,
                "attestation_chain_der": [f9],
                "firmware": "5.7.4",
                "serial": 12_345_678,
                "fips_certified": true,
                "touch_always": true,
            }
        },
        "nonce_captured_at": captured_at.to_rfc3339(),
    })
}

// ─── 1. a VALID attestation admits at the claimed class ───────────────────────

#[tokio::test]
async fn valid_yubikey_attestation_admits_at_the_claimed_class() {
    let dev = Device::new("node-with-yubikey", 0x11);
    let (c9, f9, root) = mock_chain(&dev.rcgen_keypair());
    let rec = dev
        .key_record(Some(ese_evidence(&c9, &f9, chrono::Utc::now())))
        .await;

    let verdict = admit_hardware_class_against_root(&rec.record, chrono::Utc::now(), &root)
        .expect("a chain-verified, key-bound, fresh attestation must admit");
    assert_eq!(
        verdict,
        AdmittedHardwareClass::Attested(ciris_keyring::HardwareType::ExternalSecureElement),
        "the record must be admitted AT THE CLAIMED CLASS, proven — not merely believed"
    );
}

// ─── 2. a MISSING attestation under a hardware-class claim is refused ─────────

#[tokio::test]
async fn hardware_class_claim_with_no_attestation_is_refused() {
    // The naked self-report: "hardware_class: YubiKey_5_FIPS" with NO certificate
    // and NO chain behind it. This is the exact shape CC 4.2.2.1 exists to refuse —
    // persist's structural gate names the missing fields.
    let dev = Device::new("node-claims-yubikey-no-proof", 0x22);
    let (_c9, _f9, root) = mock_chain(&dev.rcgen_keypair());
    let naked = serde_json::json!({
        "platform_attestation": {
            "ExternalSecureElement": {
                "hardware_class": "YubiKey_5_FIPS",
                "attestation_cert_der": [],
                "attestation_chain_der": [],
                "fips_certified": true,
                "touch_always": true,
            }
        },
        "nonce_captured_at": chrono::Utc::now().to_rfc3339(),
    });
    let rec = dev.key_record(Some(naked)).await;

    let err = admit_hardware_class_against_root(&rec.record, chrono::Utc::now(), &root)
        .expect_err("a hardware-class claim with no attestation behind it must be REFUSED");
    let msg = err.to_string();
    assert!(
        msg.contains("attestation_cert_der") && msg.contains("attestation_chain_der"),
        "the refusal must name the missing attestation fields; got: {msg}"
    );
}

#[tokio::test]
async fn unverifiable_hardware_class_is_refused() {
    // A structurally COMPLETE Android StrongBox claim — persist's *default* policy
    // would accept it (it does no chain validation, by design; see its module doc).
    // This node pins no Google root and Verify's local chain validation (#32 Ask 5)
    // has not shipped, so the claim is UNVERIFIABLE → fail closed. Crediting it
    // would be believing a string, which is precisely the CC 4.2.2.1 gap.
    let dev = Device::new("node-claims-strongbox", 0x33);
    let (_c9, _f9, root) = mock_chain(&dev.rcgen_keypair());
    let android = serde_json::json!({
        "platform_attestation": {
            "Android": {
                "key_attestation_chain": [[48, 130], [48, 130]],
                "play_integrity_token": "eyJhbGciOiJIUzI1NiJ9.fake.token",
                "strongbox_backed": true,
            }
        },
        "nonce_captured_at": chrono::Utc::now().to_rfc3339(),
    });
    let rec = dev.key_record(Some(android)).await;

    let err = admit_hardware_class_against_root(&rec.record, chrono::Utc::now(), &root)
        .expect_err("a hardware class this node cannot verify must be REFUSED, never credited");
    assert!(
        err.to_string().contains("AndroidStrongbox") || err.to_string().contains("not accepted"),
        "the refusal must name the unaccepted class; got: {err}"
    );
}

// ─── 3. a FORGED / MISMATCHED attestation is refused ──────────────────────────

#[tokio::test]
async fn forged_attestation_under_an_attacker_root_is_refused() {
    // The forgery: a perfectly well-formed YubiKey attestation chain — right OIDs,
    // right FIPS marker, right touch policy, attesting the right key — minted by an
    // attacker's own CA. Structure proves nothing; only the chain to the PINNED root
    // does. Verified here by handing the gate the REAL pinned root's stand-in (a
    // different root than the one the chain was minted under).
    let dev = Device::new("node-forged-chain", 0x44);
    let (c9, f9, _attacker_root) = mock_chain(&dev.rcgen_keypair());
    let honest_root_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let honest_root = params("Yubico Attestation Root 1 (the pinned one)")
        .self_signed(&honest_root_kp)
        .unwrap();
    let rec = dev
        .key_record(Some(ese_evidence(&c9, &f9, chrono::Utc::now())))
        .await;

    let err = admit_hardware_class_against_root(&rec.record, chrono::Utc::now(), honest_root.der())
        .expect_err("a chain that does not reach the PINNED root must be REFUSED");
    assert!(
        err.to_string().contains("ChainInvalid"),
        "the refusal must be a chain failure; got: {err}"
    );
}

#[tokio::test]
async fn attestation_bound_to_another_key_is_refused() {
    // The lift-and-replay: a GENUINE attestation (real chain to the pinned root) for
    // someone ELSE's key, pasted onto this record. Refused by the key-binding half of
    // the check — the attested SubjectPublicKeyInfo must equal THIS record's Ed25519.
    let victim = Device::new("node-with-real-yubikey", 0x55);
    let (c9, f9, root) = mock_chain(&victim.rcgen_keypair());

    let impostor = Device::new("node-replaying-someone-elses-attestation", 0x66);
    let rec = impostor
        .key_record(Some(ese_evidence(&c9, &f9, chrono::Utc::now())))
        .await;

    let err = admit_hardware_class_against_root(&rec.record, chrono::Utc::now(), &root)
        .expect_err("an attestation bound to a DIFFERENT key must be REFUSED");
    assert!(
        err.to_string().contains("AttestedKeyMismatch"),
        "the refusal must be a key-binding mismatch; got: {err}"
    );
}

#[tokio::test]
async fn stale_attestation_nonce_is_refused() {
    // Replay of an OLD attestation against a NEW key-binding event: the evidence is
    // real and key-bound, but its captured nonce is 48h old — outside persist's 24h
    // `max_nonce_age`. This is the freshness half of the substrate policy.
    let dev = Device::new("node-replaying-old-attestation", 0x77);
    let (c9, f9, root) = mock_chain(&dev.rcgen_keypair());
    let stale = chrono::Utc::now() - chrono::Duration::hours(48);
    let rec = dev.key_record(Some(ese_evidence(&c9, &f9, stale))).await;

    let err = admit_hardware_class_against_root(&rec.record, chrono::Utc::now(), &root)
        .expect_err("a stale attestation nonce must be REFUSED (anti-replay)");
    assert!(
        err.to_string().contains("stale") || err.to_string().contains("86400"),
        "the refusal must be the freshness gate; got: {err}"
    );
}

// ─── 4. a software-class claim needs no attestation ───────────────────────────

#[tokio::test]
async fn no_attestation_evidence_is_admitted_as_software_class() {
    // The honest software node: it claims NO hardware class, so there is nothing to
    // attest and nothing to fake. Admitted, at software class. CC 4.2.2.1 constrains
    // hardware CLAIMS; declining to claim is always honest — and this is the escape
    // hatch for a device whose class we cannot verify (join as software, don't lie).
    let dev = Device::new("node-software-only", 0x88);
    let (_c9, _f9, root) = mock_chain(&dev.rcgen_keypair());
    let rec = dev.key_record(None).await;

    let verdict = admit_hardware_class_against_root(&rec.record, chrono::Utc::now(), &root)
        .expect("a record claiming no hardware class needs no attestation");
    assert_eq!(verdict, AdmittedHardwareClass::SoftwareUnattested);
}

#[tokio::test]
async fn explicit_software_attestation_is_not_a_hardware_class() {
    // A `Software` PlatformAttestation is not a hardware class — persist's one
    // structural floor (`SoftwareOnly.supports_professional_license() == false`).
    // Presenting `attestation_evidence` at all IS the hardware claim, so a Software
    // blob in that slot is a contradiction and is refused; the honest software path
    // is `attestation_evidence: None` (the test above).
    let dev = Device::new("node-software-blob", 0x99);
    let (_c9, _f9, root) = mock_chain(&dev.rcgen_keypair());
    let software =
        ciris_keyring::PlatformAttestation::Software(ciris_keyring::SoftwareAttestation::default());
    let rec = dev
        .key_record(Some(serde_json::json!({
            "platform_attestation": software,
            "nonce_captured_at": chrono::Utc::now().to_rfc3339(),
        })))
        .await;

    let err = admit_hardware_class_against_root(&rec.record, chrono::Utc::now(), &root)
        .expect_err("a SoftwareOnly platform attestation is not a hardware class");
    assert!(
        err.to_string().contains("SoftwareOnly"),
        "the refusal must name SoftwareOnly; got: {err}"
    );
}

// ─── fail-closed, end to end: a refused claim leaves NO row ───────────────────

/// An in-memory hybrid-signed Engine (mirrors `tests/graph_config.rs::node`).
async fn engine() -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], "ciris-server-pqc".to_string())
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xA1; 32]),
        "ciris-server".to_string(),
        Some(pqc),
        Some("ciris-server-pqc".to_string()),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine"),
    )
}

#[tokio::test]
async fn refused_claim_leaves_no_federation_key_row() {
    // Verify-before-mutation: the class gate runs BEFORE persist's PoP gate, so a
    // record whose hardware claim does not verify is never stored — the forger gets
    // no row, not even a software-class one (the no-silent-downgrade rule).
    let engine = engine().await;
    let victim = Device::new("real-yubikey-holder", 0xA5);
    let (c9, f9, _root) = mock_chain(&victim.rcgen_keypair());

    // An impostor replays the victim's genuine attestation onto its own key AND the
    // chain does not reach the REAL pinned Yubico root — two independent refusals.
    let impostor = Device::new("impostor-node", 0xB6);
    let rec = impostor
        .key_record(Some(ese_evidence(&c9, &f9, chrono::Utc::now())))
        .await;

    let err = register_attested_federation_key(&engine, rec)
        .await
        .expect_err("an unverifiable hardware-class claim must be refused at admission");
    assert!(
        err.to_string().contains("CC 4.2.2.1"),
        "the refusal must cite the constitutional rule it enforces; got: {err}"
    );

    assert!(
        engine
            .federation_directory()
            .lookup_public_key("impostor-node")
            .await
            .expect("directory lookup")
            .is_none(),
        "FAIL-CLOSED: a refused hardware-class claim must leave NO federation_keys row"
    );
}

#[tokio::test]
async fn unclaimed_key_still_registers_through_the_chokepoint() {
    // The gate must not break the ordinary path: a node that claims no hardware class
    // registers exactly as before (the chokepoint is a gate, not a wall).
    let engine = engine().await;
    let dev = Device::new("plain-software-node", 0xC7);
    register_attested_federation_key(&engine, dev.key_record(None).await)
        .await
        .expect("a key claiming no hardware class must still register");
    assert!(
        engine
            .federation_directory()
            .lookup_public_key("plain-software-node")
            .await
            .expect("directory lookup")
            .is_some(),
        "the software-class key must be in federation_keys"
    );
}
