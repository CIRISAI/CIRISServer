//! STAGE 1 gates — adopt verify v7.2 / persist v9.11 / edge v6.4, bake the
//! kill-switch, and prove the #268 entrenchment path. All hermetic + software:
//! no YubiKey, no running node, no network. These go GREEN once the substrate is
//! bumped and the v7.1 custody→evidence bridge is wired (both done in 0.5.35).

use chrono::Utc;

use ciris_keyring::{ExternalSecureElementAttestation, HardwareType, PlatformAttestation};
use ciris_persist::federation::hardware_attestation::HardwareAttestationPolicy;
use ciris_verify_core::accord_genesis::{accord_quorum_from_family, humanity_accord_genesis};

use crate::support::{cargo_pin, TARGET_EDGE, TARGET_PERSIST, TARGET_VERIFY};

/// 1.1 — the workspace is pinned to the verify-7 substrate floor.
#[test]
fn gate1_substrate_pins_at_target() {
    let verify = cargo_pin("ciris-verify-core").expect("verify pin present");
    let persist = cargo_pin("ciris-persist").expect("persist pin present");
    let edge = cargo_pin("ciris-edge").expect("edge pin present");
    assert_eq!(
        verify, TARGET_VERIFY,
        "verify-family must be {TARGET_VERIFY}"
    );
    assert_eq!(persist, TARGET_PERSIST, "persist must be {TARGET_PERSIST}");
    assert_eq!(edge, TARGET_EDGE, "edge must be {TARGET_EDGE}");
}

/// 1.2 — the HUMANITY_ACCORD genesis recognition root is BAKED (v7.2). Until
/// verify bakes it this is `None` and the kill-switch falls back to an
/// operator-writable roster — the whole reason 0.6 was held.
#[test]
fn gate1_genesis_recognition_baked() {
    assert!(
        humanity_accord_genesis().is_some(),
        "humanity_accord_genesis() is None — the kill-switch genesis is NOT baked \
         (verify < v7.2). The baked recognition root is the safe-mesh floor."
    );
}

/// 1.3 — the baked genesis carries the 2-of-3 kill-switch roster (3 seats, quorum 2).
#[test]
fn gate1_kill_switch_roster_is_2_of_3() {
    let g = humanity_accord_genesis().expect("baked genesis (see gate1_genesis_recognition_baked)");
    let quorum = accord_quorum_from_family(g).expect("resolve quorum from baked genesis");
    assert_eq!(
        quorum, 2,
        "HUMANITY_ACCORD quorum must be 2 (2-of-3 kill-switch)"
    );

    let members = g
        .body
        .get("family")
        .and_then(|f| f.get("members"))
        .and_then(|m| m.as_array())
        .expect("baked genesis family.members[]");
    assert!(
        members.len() >= 3,
        "kill-switch roster must seat at least 3 members, found {}",
        members.len()
    );
}

/// 1.4 — persist v9.11 (CIRISPersist#268) accepts `ExternalSecureElement` as an
/// accord_holder hardware type. Before #268 the FIPS-YubiKey custody could not be
/// admitted and genesis entrenchment 409'd.
#[test]
fn gate1_persist_accepts_external_secure_element() {
    let policy = HardwareAttestationPolicy::default();
    assert!(
        policy
            .accepted_hardware_types
            .contains(&HardwareType::ExternalSecureElement),
        "persist's default policy must accept ExternalSecureElement (CIRISPersist#268)"
    );
    // The floor still has teeth: software-only is NOT a valid kill-switch custody.
    assert!(
        !policy
            .accepted_hardware_types
            .contains(&HardwareType::SoftwareOnly),
        "software-only must NEVER be admitted as accord_holder custody"
    );
}

/// Build a fully-populated FIPS-YubiKey ExternalSecureElement attestation in the
/// shape the v7.1 bridge (`custody_attestation_to_platform_attestation`) emits.
fn external_se_evidence(nonce_at: chrono::DateTime<Utc>) -> serde_json::Value {
    let pa = PlatformAttestation::ExternalSecureElement(ExternalSecureElementAttestation {
        hardware_class: "YubiKey_5_FIPS".into(),
        attestation_cert_der: vec![0x30, 0x82, 0x01, 0x00], // slot-9c leaf
        attestation_chain_der: vec![vec![0x30, 0x82, 0x02, 0x00]], // [f9, ..]
        firmware: Some("5.7.4".into()),
        serial: Some(12_345_678),
        fips_certified: true,
        touch_always: true,
    });
    serde_json::json!({
        "platform_attestation": pa,
        "nonce_captured_at": nonce_at.to_rfc3339(),
    })
}

/// 1.5 — THE entrenchment-path gate: a correctly-shaped ExternalSecureElement
/// `attestation_evidence` (exactly what `register_holder` now builds via the v7.1
/// bridge) is ADMITTED by persist's accord_holder gate, while a software-only or
/// stale/missing one is REJECTED. This is the #268 unblock, proven without a
/// YubiKey.
#[test]
fn gate1_register_holder_evidence_admitted() {
    let now = Utc::now();
    let policy = HardwareAttestationPolicy::default();

    // Fresh, fully-populated FIPS-YubiKey evidence → admitted.
    let ev = external_se_evidence(now);
    policy
        .check("test-holder-A1", Some(&ev), now)
        .expect("a fresh ExternalSecureElement evidence MUST be admitted (the #268 fix)");

    // Missing evidence → rejected (an accord_holder MUST present custody).
    assert!(
        policy.check("test-holder-A1", None, now).is_err(),
        "missing attestation_evidence must be rejected"
    );

    // Software-only → rejected.
    let sw = serde_json::json!({
        "platform_attestation": PlatformAttestation::Software(Default::default()),
        "nonce_captured_at": now.to_rfc3339(),
    });
    assert!(
        policy.check("test-holder-A1", Some(&sw), now).is_err(),
        "software-only custody must be rejected"
    );

    // Stale nonce (older than 24h) → rejected (replay defense).
    let stale = external_se_evidence(now - chrono::Duration::hours(25));
    assert!(
        policy.check("test-holder-A1", Some(&stale), now).is_err(),
        "a >24h-stale nonce must be rejected"
    );
}
