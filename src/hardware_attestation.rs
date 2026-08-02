//! **CC 4.2.2.1 — a `hardware_class` claim is admitted only against a real
//! attestation** (CIRISServer#159; closes CC 8.3.1 R5).
//!
//! # The gap this closes
//!
//! Before this module, `federation_keys.hardware_class` — the class a key
//! asserts for itself (TPM / Secure Enclave / StrongBox / YubiKey) — was an
//! **unchecked self-report** on every server admission path except the accord
//! one. A node said "my key lives in a TPM" and the mesh believed the string.
//! CC 4.2.2 (`CLM-hardware-class`) only names the *vocabulary*
//! (`ciris_keyring::HardwareType`); CC 4.2.2.1 (`CLM-hardware-class-hardware`)
//! is the stronger claim — *the class is what the hardware actually is* — and
//! that is a claim only an **attestation** can carry.
//!
//! # Where the class actually rides
//!
//! There is no free-standing `hardware_class` column on persist's [`KeyRecord`]
//! (`ciris-persist` v15.1.2, `src/federation/types.rs`). The class rides
//! **inside** `attestation_evidence`:
//!
//! ```text
//! attestation_evidence = { platform_attestation: <PlatformAttestation>,
//!                          nonce_captured_at:    <RFC3339> }
//! ```
//!
//! and the `PlatformAttestation` **variant** (+ its `strongbox_backed` /
//! `discrete` discriminator, or its `ExternalSecureElement.hardware_class`
//! string) IS the class assertion. So "verify the `hardware_class` self-report"
//! means exactly: *verify the `attestation_evidence` that carries it.*
//!
//! # The two layers of the gate
//!
//! **Layer A — the substrate policy (persist, NOT hand-rolled).**
//! [`ciris_persist::federation::hardware_attestation::HardwareAttestationPolicy::check`]
//! is the enforcer: presence + non-null, deserializes to the canonical
//! `AttestationEvidence` shape, the derived [`HardwareType`] is in the accepted
//! set, the variant carries its required fields, and the captured nonce is fresh
//! (≤ `max_nonce_age`, default 24h — anti-replay). Persist runs this itself at
//! `put_public_key` **but ONLY for `identity_type = 'accord_holder'` rows**
//! (`store/sqlite.rs`: `if row.identity_type == identity_type::ACCORD_HOLDER`).
//! Every other identity type — `node`, `user`, `agent` — could carry any
//! `attestation_evidence` it liked and persist would store it unexamined. This
//! module applies the SAME substrate policy to EVERY row the server admits.
//!
//! **Layer B — the cryptographic binding the substrate explicitly defers to us.**
//! Persist's own module doc is blunt: *"Persist does NOT do active chain
//! validation … registry-side validation … does the chain verification."* A
//! structurally-complete blob is not a proof; a forger can hand-write one. So
//! the server does the real check for the class it holds a **pinned trust root**
//! for — `ExternalSecureElement` (a FIPS YubiKey PIV token, the canonical CIRIS
//! custody): [`ciris_verify_core::accord_custody_attestation::verify_yubikey_piv_attestation`]
//! walks `9c → f9 → …intermediates… → Yubico Attestation Root 1` (every link a
//! real signature verification) **and** asserts the attested key equals the
//! record's own Ed25519 pubkey. That second half is what refuses a *mismatched*
//! attestation — a genuine YubiKey attestation lifted from another key's record
//! and replayed onto this one.
//!
//! # Fail-closed semantics (and why REJECT, not downgrade)
//!
//! Persist's verdict type is `Result<(), Error>` — a **binary** admit/refuse.
//! Its error enum (`AccordHolderRequiresAttestationEvidence`,
//! `HardwareTypeNotAccepted`, `AttestationEvidenceIncomplete`,
//! `AttestationEvidenceStale`) expresses **no "downgraded to software" verdict**.
//! So this gate REFUSES an unverifiable claim rather than silently rewriting the
//! row to software-class, because:
//!
//! 1. A downgrade would be the server inventing a verdict the substrate does not
//!    have — precisely the "hand-rolled parallel checker" this wiring exists to
//!    avoid.
//! 2. A downgrade **destroys the audit trail**: persist stores the evidence
//!    exactly so an auditor can later re-examine a claim. Stripping a forged blob
//!    erases the forgery.
//! 3. For `accord_holder` a downgrade is *inexpressible* — persist REQUIRES the
//!    evidence, so a stripped row is refused by the substrate anyway. Rejecting
//!    uniformly keeps ONE rule for every identity type instead of a type-dependent
//!    one.
//!
//! The honest way to be software-class is therefore to carry **no**
//! `attestation_evidence` at all (`None`): no claim, nothing to attest, admitted
//! ([`AdmittedHardwareClass::SoftwareUnattested`]). `attestation_evidence` is
//! *hardware* evidence; presenting it IS the hardware-class claim.
//!
//! # Classes we cannot verify are refused, not credited
//!
//! Android (Play Integrity + key-attestation chain to a Google root), iOS
//! (App Attest / DeviceCheck to an Apple root) and TPM (EK cert to a vendor root)
//! are all *structurally* checkable by Layer A but **not** cryptographically
//! verifiable here. Under CC 4.2.2.1 an unverifiable class claim is exactly the
//! thing that must NOT be credited, so [`server_policy`] **tightens** persist's
//! accepted set — which persist explicitly invites ("deployments tighten further
//! by overriding") — to the classes this node can actually prove. A device whose
//! class we cannot check is not locked out of the mesh: it registers with no
//! `attestation_evidence` and joins honestly as software-class. It just cannot
//! *claim* hardware it cannot prove. When a chain validator for the other classes
//! lands, add the class here and add its verifier to [`verify_class_binding`] —
//! in that order, never one without the other.
//!
//! ## Android: the validator SHIPPED, and the gate still cannot use it
//!
//! This paragraph used to say Verify's device-attestation chain validators "have
//! not shipped". That sentence is **dead** — CIRISVerify v10.8.0 shipped
//! `ciris_verify_core::device_attestation::verify_android_key_attestation`, and
//! v10.9.0 added the CoTS trust-anchor store (#227) that resolves the root by
//! (purpose, environment). Both were read at the tag, not taken from a release
//! note. The API is exactly the right shape: a measurement, an explicit
//! anti-lift binding to the record's own key, and `refutes(claimed_class)` as
//! the decisive direction. CIRISServer#339 and CIRISPersist#568 both correctly
//! flagged the stale claim.
//!
//! Widening the gate to Android is still **refused**, for two reasons that
//! survive the correction. Neither is "verify hasn't built it":
//!
//! **1. The validator is unreachable from here (CIRISServer#340).** persist
//! v24.2.0 and edge v15.9.1 — the latest tag of each — pin verify at
//! `tag = "v10.6.3"`. A cargo git tag is part of the source id, so repinning the
//! server alone does not upgrade verify, it forks it into two crates with two
//! incompatible `HardwareType`/`PlatformAttestation` types (measured: 19 lib +
//! 24 lib-test errors; `[patch]` on the same repo URL is rejected outright by
//! cargo). The module simply is not in this build. See the pin note in
//! `Cargo.toml`.
//!
//! **2. Even reachable, this node cannot supply `expected_challenge`.** The
//! validator's step 4 is anti-replay: the `attestationChallenge` inside the
//! leaf's `KeyDescription` must equal the nonce **the verifier issued**. The
//! server issues none — there is no attestation-challenge channel on any
//! admission path — and persist's wire shape cannot carry one back either:
//! `HardwareCustodyEvidence` is `{ platform_attestation, nonce_captured_at }`,
//! a *timestamp* recording when Verify captured a nonce, never the nonce
//! **value**; and `ciris_keyring::AndroidAttestation` is
//! `{ key_attestation_chain, play_integrity_token, strongbox_backed }` — no
//! challenge field. So the only argument available is the challenge read out of
//! the attestation itself, which would be checking the envelope against itself:
//! the same tautology this module already refuses for a lifted YubiKey chain,
//! and the same class of defect as crediting a self-report. Verified against
//! CIRISVerify v11.0.0 as well — `expected_challenge` is not a v10.9.0 artifact.
//!
//! There is also a lesser, genuinely fixable gap: verify baked no Google root
//! until v10.11.0 (#227), so at v10.9.0 the caller must pin it — the same
//! discipline as [`crate::accord::YUBICO_ATTESTATION_ROOT_1_DER`]. That one is
//! only work. The challenge gap is a **missing wire field**, and it belongs
//! upstream: persist's `AttestationEvidence` needs to carry the issued nonce, or
//! Android custody needs to ride the `GenerationCustody` arm (attest-at-
//! generation, no nonce to replay) the way YubiKey PIV does. Widening
//! `server_policy` before then would credit a hardware claim whose freshness
//! nothing checks — which is precisely what CC 4.2.2.1 exists to refuse.

use chrono::{DateTime, Utc};
use ciris_keyring::{HardwareType, PlatformAttestation};
use ciris_persist::federation::hardware_attestation::{
    AttestationEvidence, HardwareAttestationPolicy,
};
use ciris_persist::federation::types::{KeyRecord, SignedKeyRecord};
use ciris_persist::federation::Error as FederationError;
use ciris_persist::prelude::Engine;
use ciris_verify_core::accord_custody_attestation::verify_yubikey_piv_attestation;

use crate::accord::YUBICO_ATTESTATION_ROOT_1_DER;

/// What the gate decided about a record's hardware-class claim. Only produced on
/// admission — every failure path is a [`FederationError`], never a weaker class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmittedHardwareClass {
    /// The record carries NO `attestation_evidence` — it claims no hardware
    /// class, so there is nothing to attest and nothing to fake. It is admitted
    /// as an (unattested) software-class key. CC 4.2.2.1 constrains *claims*;
    /// declining to claim is always honest.
    SoftwareUnattested,
    /// The record claimed a hardware class and the claim was verified: it passed
    /// persist's [`HardwareAttestationPolicy`] (shape / accepted class / fresh
    /// nonce) AND this node's cryptographic binding check for that class
    /// (attestation chain to a pinned root + attested-key == the record's key).
    Attested(HardwareType),
}

/// The server's hardware-attestation policy: persist's default, **tightened** to
/// only those classes this node can cryptographically verify (see the module
/// doc — CC 4.2.2.1 fail-closed). Today that is `ExternalSecureElement` (FIPS
/// YubiKey PIV, chain-pinned to Yubico Attestation Root 1). `max_nonce_age`
/// stays at persist's 24h default (the FSD-002 §7.3 anti-replay figure).
///
/// ## This narrowing is a TRACKED GAP, not the end state — CIRISVerify#199
///
/// CC 4.2.2.1 is the hardware-class half of the SAME rule the manifest-gated-KEX
/// chain enforces for builds: *never credit a peer's self-report; verify it
/// against a pinned trust root* (CIRISVerify#181 — "no hardware, no trust in the
/// peer's self-report"). The build half is tracked (#181 -> CIRISPersist#415 ->
/// CIRISEdge#303 -> CIRISServer#219); the DEVICE half had no tracker at all,
/// which is how a fail-closed gap quietly becomes "we refuse it because we never
/// built it". CIRISVerify#199 tracks pinning the Google / Apple / TPM-vendor
/// roots and exposing their chain validators (each of which MUST also assert the
/// attested SPKI equals the record's own Ed25519 — the check that refuses a
/// LIFTED attestation replayed under an attacker's key; without it the validator
/// is theatre).
///
/// ## Do NOT widen this on "#199 landed" alone (CIRISServer#339/#340)
///
/// The Android leg of #199 HAS landed — verify v10.8.0's
/// `verify_android_key_attestation`, read at the tag. This doc used to say
/// "when #199 lands, widen"; followed literally today that would open the gate
/// on a check this node cannot complete. The module doc records the two live
/// blockers in full (the substrate verify-pin ceiling, and the absent
/// `expected_challenge`). The honest precondition for widening is BOTH:
///
/// 1. `ciris_verify_core::device_attestation` is actually in the build — i.e.
///    persist and edge have repinned verify past v10.8.0 and we followed; and
/// 2. an issued nonce reaches this gate, so the validator's anti-replay leg is
///    a real check rather than the attestation quoting itself back at us.
///
/// Only then widen `accepted_hardware_types`, add the Android arm to
/// [`verify_class_binding`] in the SAME change, and flip
/// `unverifiable_hardware_class_is_refused` from "refused" to "valid chain
/// admits at the MEASURED class / forged + lifted + over-claimed refused".
/// Refuse on `AndroidAttestationVerdict::refutes`, never on absence: verify's
/// own doc is emphatic that a missing attestation is not a failure, and this
/// gate already agrees (no evidence ⇒ `SoftwareUnattested`, admitted).
#[must_use]
pub fn server_policy() -> HardwareAttestationPolicy {
    let mut policy = HardwareAttestationPolicy::default();
    policy.accepted_hardware_types.clear();
    policy
        .accepted_hardware_types
        .insert(HardwareType::ExternalSecureElement);
    policy
}

/// Apply CC 4.2.2.1 to one key record: a hardware-class claim is admitted ONLY
/// against an attestation that verifies. `now` is a parameter for testability;
/// production callers pass `Utc::now()`.
///
/// # Errors
///
/// The typed [`FederationError`] naming the first failing check — persist's own
/// (`HardwareTypeNotAccepted` / `AttestationEvidenceIncomplete` /
/// `AttestationEvidenceStale` / `AccordHolderRequiresAttestationEvidence` for a
/// malformed body) for Layer A, or `InvalidArgument` for a Layer-B binding
/// failure (broken/forged chain, or an attestation bound to a different key).
pub fn admit_hardware_class(
    record: &KeyRecord,
    now: DateTime<Utc>,
) -> Result<AdmittedHardwareClass, FederationError> {
    admit_hardware_class_against_root(record, now, YUBICO_ATTESTATION_ROOT_1_DER)
}

/// [`admit_hardware_class`] with the pinned `ExternalSecureElement` trust anchor
/// as a parameter. The security-critical core, factored out so it is directly
/// testable against a GENERATED chain (the same shape verify factors
/// `verify_yubikey_piv_attestation` out for) — nobody, including this test suite,
/// can mint a certificate under the real Yubico Attestation Root 1, so a test
/// that proves "a valid attestation admits" MUST be able to supply its own root.
/// Production has exactly one caller and it passes the pinned real root.
///
/// # Errors
///
/// See [`admit_hardware_class`].
pub fn admit_hardware_class_against_root(
    record: &KeyRecord,
    now: DateTime<Utc>,
    ese_root_der: &[u8],
) -> Result<AdmittedHardwareClass, FederationError> {
    // No evidence ⇒ no hardware-class claim ⇒ software-class. Note we treat an
    // explicit JSON `null` the same as absent: both are "claims nothing". (A
    // *null* on an accord_holder row is still refused — by persist, whose gate
    // REQUIRES the evidence for that identity type. We do not need to duplicate
    // that rule here, and duplicating it would be the parallel checker we are
    // avoiding.)
    let Some(evidence_value) = record
        .attestation_evidence
        .as_ref()
        .filter(|v| !v.is_null())
    else {
        return Ok(AdmittedHardwareClass::SoftwareUnattested);
    };

    // ── Layer A: the substrate policy. persist authors it; we only apply it. ──
    let policy = server_policy();
    policy.check(&record.key_id, Some(evidence_value), now)?;

    // The body deserialized cleanly inside `check` (it would have errored
    // otherwise); re-read it here to get the verified variant for Layer B and for
    // the returned verdict. Cloning the Value is fine — key records are small and
    // this runs once per admission, never on a hot path.
    let evidence: AttestationEvidence =
        serde_json::from_value(evidence_value.clone()).map_err(|e| {
            FederationError::InvalidArgument(format!(
                "attestation_evidence for {} is malformed: {e}",
                record.key_id
            ))
        })?;

    // ── Layer B: the cryptographic binding persist defers to the consumer. ──
    // persist v22.0.1 (CIRISPersist#545) made the evidence an explicit two-arm
    // enum, so the software test marker is representable by construction instead
    // of being a shape the parser could not express. Match it honestly:
    //
    //  * `Hardware`         → there IS a platform attestation; verify the chain
    //                         and the key binding, and report the proven class.
    //  * `SoftwareOnlyTest` → there is NO platform attestation to bind. Layer A
    //                         (persist's policy) has already refused this arm
    //                         unless a live test anchor is armed, so reaching
    //                         here means the marker is legitimately admitted —
    //                         but it is SOFTWARE, and Layer B must never invent a
    //                         hardware class for it. `SoftwareUnattested` is the
    //                         truthful verdict, and it is what every downstream
    //                         hardware-class gate already fails closed against.
    //  * `GenerationCustody` → attestation-at-GENERATION (persist v23.1.0 /
    //                         CIRISPersist#554). THIS is where the chain walk
    //                         belongs — see below.
    let class = match &evidence {
        AttestationEvidence::Hardware(hw) => {
            verify_class_binding(record, &hw.platform_attestation, ese_root_der)?
        }
        // The real YubiKey PIV custody attestation the accord ceremony produces.
        // The device attests once, at key generation, so there is no nonce and
        // nothing to age — a ceremony run in June is still the custody proof in
        // December.
        //
        // Persist verifies the contract identity, the holder binding, the tier
        // allowlist and the sha256 certificate commitments, and DELIBERATELY
        // defers four things to us, saying so in
        // `HardwareAttestationPolicy::check_generation_custody`: the holder's
        // hybrid signature over the envelope, the `9c → f9 → pinned Yubico root`
        // path, that the attested key IS the holder's federation Ed25519, and the
        // FIPS / touch-policy floor. It defers them because it holds neither the
        // directory-resolved holder pubkeys nor a pinned root — "verify provides
        // the verification, not the trust root" — and it refused to fake the
        // depth. This node holds BOTH, so the deferral lands exactly here.
        //
        // The holder member is built from the RECORD's own pubkeys — the key
        // being admitted — NOT from the pubkey inside the envelope. That is the
        // whole point: checking the envelope against itself would prove internal
        // consistency, not that this custody object belongs to this key. A real
        // YubiKey attestation lifted onto someone else's record fails here.
        AttestationEvidence::GenerationCustody(att) => {
            let obj: ciris_verify_core::ceg_outbox::SignedCegObject =
                serde_json::to_value(att.as_ref())
                    .and_then(serde_json::from_value)
                    .map_err(|e| {
                        FederationError::InvalidArgument(format!(
                            "hardware_class claim for {} REFUSED (CC 4.2.2.1): its \
                             GenerationCustody evidence is not a well-formed signed CEG object: {e}",
                            record.key_id
                        ))
                    })?;
            let holder_member = ciris_verify_core::threshold::ThresholdMember {
                member_id: record.key_id.clone(),
                ed25519_public_key_base64: record.pubkey_ed25519_base64.clone(),
                mldsa65_public_key_base64: record.pubkey_ml_dsa_65_base64.clone(),
                role: None,
            };
            let verdict =
                ciris_verify_core::accord_custody_attestation::verify_accord_custody_attestation(
                    &obj,
                    &holder_member,
                    ese_root_der,
                )
                .map_err(|e| {
                    FederationError::InvalidArgument(format!(
                        "hardware_class claim for {} REFUSED (CC 4.2.2.1): its YubiKey PIV custody \
                         attestation does not verify against the pinned Yubico Attestation Root 1, \
                         does not meet the FIPS + touch-always floor, or is not bound to this \
                         key: {e:?}",
                        record.key_id
                    ))
                })?;
            tracing::info!(
                key_id = %record.key_id,
                custody_tier = %verdict.custody_tier,
                "CC 4.2.2.1: attestation-at-generation custody VERIFIED — PIV chain walked to the \
                 pinned Yubico Attestation Root 1 and bound to this record's Ed25519 key"
            );
            HardwareType::ExternalSecureElement
        }
        AttestationEvidence::SoftwareOnlyTest(_) => {
            tracing::warn!(
                key_id = %record.key_id,
                identity_type = %record.identity_type,
                "SoftwareOnly_TEST custody marker admitted (test anchor armed) — reporting                  SoftwareUnattested, NOT a hardware class. This MUST NOT appear in production."
            );
            return Ok(AdmittedHardwareClass::SoftwareUnattested);
        }
    };

    tracing::info!(
        key_id = %record.key_id,
        identity_type = %record.identity_type,
        hardware_class = ?class,
        "CC 4.2.2.1: hardware-class claim ADMITTED — attestation chain verified to a \
         pinned root and bound to this record's Ed25519 key"
    );
    Ok(AdmittedHardwareClass::Attested(class))
}

/// Layer B — prove the attestation is (a) issued by real hardware (its chain
/// walks to a root we pin) and (b) about **this** key (the attested public key is
/// the record's own Ed25519). Returns the proven [`HardwareType`].
///
/// Layer A has already guaranteed the variant is in [`server_policy`]'s accepted
/// set, so any variant reaching the `_` arm is a policy/verifier skew — a class
/// was added to the accepted set without a verifier. That is a REJECT, never a
/// pass: an unverifiable claim must fail closed (CC 4.2.2.1).
fn verify_class_binding(
    record: &KeyRecord,
    attestation: &PlatformAttestation,
    ese_root_der: &[u8],
) -> Result<HardwareType, FederationError> {
    match attestation {
        PlatformAttestation::ExternalSecureElement(ese) => {
            // The record's OWN Ed25519 pubkey — the thing the YubiKey slot-9c
            // attestation certificate must attest to. Binding the attestation to
            // the record's key is what makes a lifted/replayed attestation (a real
            // YubiKey cert, wrong key) a REJECT rather than a pass.
            let expected_ed = base64_decode_ed25519(&record.pubkey_ed25519_base64, &record.key_id)?;
            let chain: Vec<&[u8]> = ese
                .attestation_chain_der
                .iter()
                .map(std::vec::Vec::as_slice)
                .collect();
            // Every link is a real signature verification up to the PINNED durable
            // Yubico Attestation Root 1 (the same anchor the accord custody gate
            // uses — one trust root for the node, not two).
            verify_yubikey_piv_attestation(
                &ese.attestation_cert_der,
                &chain,
                ese_root_der,
                &expected_ed,
            )
            .map_err(|e| {
                FederationError::InvalidArgument(format!(
                    "hardware_class claim for {} REFUSED (CC 4.2.2.1): its ExternalSecureElement \
                     attestation does not verify against the pinned Yubico Attestation Root 1, or \
                     is not bound to this key: {e:?}",
                    record.key_id
                ))
            })?;
            Ok(HardwareType::ExternalSecureElement)
        }
        other => Err(FederationError::InvalidArgument(format!(
            "hardware_class claim for {} REFUSED (CC 4.2.2.1): this node has no pinned trust root \
             for {other:?} and therefore cannot verify the claim — an unverifiable hardware class \
             is never credited. Register with no attestation_evidence to join as software-class.",
            record.key_id
        ))),
    }
}

/// Decode a record's base64 Ed25519 pubkey to the 32 raw bytes the attestation
/// certificate's SubjectPublicKeyInfo is compared against.
fn base64_decode_ed25519(b64: &str, key_id: &str) -> Result<Vec<u8>, FederationError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    B64.decode(b64).map_err(|e| {
        FederationError::InvalidArgument(format!(
            "key record {key_id} has an undecodable pubkey_ed25519_base64: {e}"
        ))
    })
}

/// The **single admission chokepoint** for a federation key on this server:
/// [`admit_hardware_class`] (CC 4.2.2.1) and then persist's canonical
/// `Engine::register_federation_key` (the hybrid proof-of-possession gate).
///
/// The class gate runs FIRST so a rejected claim leaves NO row — same
/// verify-before-mutation discipline persist applies internally. Every
/// `register_federation_key` call site in this crate goes through here; a new
/// admission path MUST use this function, not the raw engine call, or it
/// reopens the unchecked-self-report hole.
///
/// # Errors
///
/// The class-gate rejection, or persist's own registration error.
pub async fn register_attested_federation_key(
    engine: &Engine,
    signed: SignedKeyRecord,
) -> Result<(), FederationError> {
    admit_hardware_class(&signed.record, Utc::now())?;
    engine.register_federation_key(signed).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record with no evidence claims nothing → software-class, admitted.
    /// (The wire-level / forged-attestation coverage lives in
    /// `tests/hardware_class_admission.rs`, which builds real key records.)
    #[test]
    fn server_policy_accepts_only_verifiable_classes() {
        let p = server_policy();
        assert!(p
            .accepted_hardware_types
            .contains(&HardwareType::ExternalSecureElement));
        // Classes we hold no pinned root for MUST NOT be in the accepted set —
        // otherwise Layer A would pass them to a Layer-B arm that cannot prove
        // them (CC 4.2.2.1 fail-closed).
        assert_eq!(p.accepted_hardware_types.len(), 1);
        assert!(!p
            .accepted_hardware_types
            .contains(&HardwareType::SoftwareOnly));
        assert!(!p
            .accepted_hardware_types
            .contains(&HardwareType::AndroidStrongbox));
        assert!(!p
            .accepted_hardware_types
            .contains(&HardwareType::TpmDiscrete));
    }
}
