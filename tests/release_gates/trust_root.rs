//! **The trust-root rungs** — the seed is baked, the kill switch seats 2-of-3,
//! and the custody floor still refuses software.
//!
//! Direct gates: they call the baked artifacts in the pinned substrate. Software
//! keys throughout, so the whole rung runs in CI with no YubiKey and no operator.

use chrono::Utc;

use ciris_keyring::{ExternalSecureElementAttestation, HardwareType, PlatformAttestation};
use ciris_persist::federation::genesis::canonical_genesis_bundle;
use ciris_persist::federation::hardware_attestation::HardwareAttestationPolicy;
use ciris_verify_core::accord_genesis::{accord_quorum_from_family, humanity_accord_genesis};

use crate::ladder::{assert_proven, TRUST_ROOT};

/// The recognition root that the kill switch resolves against must be BAKED into
/// the binary. While it was `None`, the kill switch fell back to an
/// operator-writable roster — a kill switch whose roster the operator can edit is
/// not a kill switch, and that is why 0.6 was held.
#[test]
fn gate_genesis_recognition_baked() {
    assert!(
        humanity_accord_genesis().is_some(),
        "\n\
         🚫 RELEASE GATE [trust-root-baked] — DO NOT TAG.\n\
         \n\
         Unsafe to ship: `humanity_accord_genesis()` is None, so there is no baked\n\
         recognition root in this binary. The accord kill switch then resolves against an\n\
         operator-writable roster — which means the one control that can stop a hostile\n\
         node mesh-wide can be edited by whoever holds the filesystem. This is the\n\
         safe-mesh floor; a cut without it is not one.\n"
    );
}

/// The kill-switch roster is 2-of-3: three seats, quorum two. One seat cannot act
/// alone, and losing one seat cannot lock everyone out.
#[test]
fn gate_kill_switch_roster_is_2_of_3() {
    let g = humanity_accord_genesis().expect("baked genesis (see gate_genesis_recognition_baked)");
    let quorum = accord_quorum_from_family(g).expect("resolve quorum from the baked genesis");
    assert_eq!(
        quorum, 2,
        "\n\
         🚫 RELEASE GATE [trust-root-baked] — DO NOT TAG.\n\
         \n\
         Unsafe to ship: the HUMANITY_ACCORD quorum is {quorum}, not 2. At quorum 1 a single\n\
         seat can halt the whole mesh unilaterally; above 2-of-3 the loss of one seat\n\
         locks everyone out of the control that exists for the worst day. Both failure\n\
         modes are unrecoverable in the field.\n"
    );

    let seats = g
        .body
        .get("family")
        .and_then(|f| f.get("members"))
        .and_then(|m| m.as_array())
        .map(|m| m.len())
        .unwrap_or(0);
    assert!(
        seats >= 3,
        "\n\
         🚫 RELEASE GATE [trust-root-baked] — DO NOT TAG.\n\
         \n\
         Unsafe to ship: the kill-switch roster seats {seats}, not 3. A 2-of-2 roster has no\n\
         redundancy at all — one lost key and the mesh has no kill switch for the rest of\n\
         its life.\n"
    );
}

/// The baked canonical seed must be a real ceremony BUNDLE — the authorizations
/// that carry its 2-of-3 into the graph, the `infra:serve`-blessed serve nodes,
/// and the delegation plane. A bundle missing any of those parses fine and seeds
/// a node that cannot serve.
#[test]
fn gate_canonical_seed_is_a_ceremony_bundle() {
    let b = canonical_genesis_bundle();
    let mut missing: Vec<String> = Vec::new();
    if b.serve_nodes.is_empty() {
        missing
            .push("serve_nodes[] is EMPTY — no `infra:serve`-blessed canonical to anchor".into());
    }
    if b.attestations.is_empty() {
        missing.push(
            "attestations[] is EMPTY — no delegation plane, so the serve gate's leg B \
                      (capability_roots_to_trusted_root) can never resolve"
                .into(),
        );
    }
    if b.authorizations.len() < 2 {
        missing.push(format!(
            "authorizations[] carries {} holder signature(s) — the 2-of-3 is what makes this a \
             ceremony output rather than a file someone wrote",
            b.authorizations.len()
        ));
    }
    if b.family_key_id.is_empty() {
        missing.push("family_key_id is empty — the bundle names no accord family".into());
    }
    assert!(
        missing.is_empty(),
        "\n\
         🚫 RELEASE GATE [trust-root-baked] — DO NOT TAG.\n\
         \n\
         Unsafe to ship: the baked canonical seed is not a complete ceremony bundle. A\n\
         node booting from it comes up UNROOTED, and an unrooted node's serve gate\n\
         refuses every peer — which presents as 'the mesh is quiet', not as an error.\n\
         That is CIRISPersist#480, and it is indistinguishable from a healthy idle node\n\
         from the outside.\n\
         \n\
         {}\n",
        missing.join("\n"),
    );
}

/// Build a fully-populated FIPS-YubiKey `ExternalSecureElement` attestation in the
/// shape the custody→evidence bridge emits.
fn external_se_evidence(nonce_at: chrono::DateTime<Utc>) -> serde_json::Value {
    let pa = PlatformAttestation::ExternalSecureElement(ExternalSecureElementAttestation {
        hardware_class: "YubiKey_5_FIPS".into(),
        attestation_cert_der: vec![0x30, 0x82, 0x01, 0x00], // slot-9c leaf
        attestation_chain_der: vec![vec![0x30, 0x82, 0x02, 0x00]],
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

/// **The custody floor still has teeth.** Real hardware evidence is admitted as
/// accord-holder custody; missing evidence, software-only custody and a stale
/// nonce are all refused.
///
/// Both directions are the gate. A floor that admits nothing blocks the ceremony;
/// a floor that admits software makes the kill switch forgeable by anyone who can
/// run this binary. Proven without a token.
#[test]
fn gate_custody_floor_admits_hardware_and_refuses_software() {
    let now = Utc::now();
    let policy = HardwareAttestationPolicy::default();

    assert!(
        policy
            .accepted_hardware_types
            .contains(&HardwareType::ExternalSecureElement),
        "\n\
         🚫 RELEASE GATE [trust-root-baked] — DO NOT TAG.\n\
         \n\
         Unsafe to ship: persist's default policy no longer accepts ExternalSecureElement,\n\
         so the FIPS-YubiKey custody the accord holders actually hold cannot be admitted.\n\
         Genesis entrenchment 409s and there is no path to re-seat a holder.\n"
    );
    assert!(
        !policy
            .accepted_hardware_types
            .contains(&HardwareType::SoftwareOnly),
        "\n\
         🚫 RELEASE GATE [trust-root-baked] — DO NOT TAG.\n\
         \n\
         Unsafe to ship: software-only custody is admitted as accord-holder custody.\n\
         Anyone who can run this binary can then mint a kill-switch seat, and the control\n\
         that exists for the worst day belongs to whoever asks for it first.\n"
    );

    policy
        .check("release-gate-holder", Some(&external_se_evidence(now)), now)
        .expect(
            "🚫 RELEASE GATE [trust-root-baked] — DO NOT TAG.\n\
             Unsafe to ship: correctly-shaped FIPS hardware custody evidence is REFUSED, so\n\
             no real holder can be entrenched and the ceremony cannot be repeated.",
        );

    for (what, evidence) in [
        ("missing evidence", None),
        (
            "software-only custody",
            Some(serde_json::json!({
                "platform_attestation": PlatformAttestation::Software(Default::default()),
                "nonce_captured_at": now.to_rfc3339(),
            })),
        ),
        (
            "a >24h-stale nonce (replay)",
            Some(external_se_evidence(now - chrono::Duration::hours(25))),
        ),
    ] {
        assert!(
            policy
                .check("release-gate-holder", evidence.as_ref(), now)
                .is_err(),
            "\n\
             🚫 RELEASE GATE [trust-root-baked] — DO NOT TAG.\n\
             \n\
             Unsafe to ship: the accord-holder custody gate ADMITTED {what}. The floor no\n\
             longer separates a hardware-held seat from a claimed one, so every downstream\n\
             quorum check is counting signatures whose custody nobody verified.\n"
        );
    }
}

/// The bake and the first-run claim are proven end to end elsewhere; this rung
/// keeps those instruments installed.
#[test]
fn gate_trust_root_bootstrap_stays_proven() {
    assert_proven(&TRUST_ROOT);
}
