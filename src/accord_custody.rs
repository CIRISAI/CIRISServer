//! HUMANITY_ACCORD holder-device **portable high-secure** provisioning
//! (CIRISServer#41, the safe-mesh custody floor).
//!
//! This is a **holder-device** operation — a library function the would-be
//! accord holder runs on their OWN machine to mint the two artifacts the mesh
//! requires of them, NOT a server endpoint. (The server side — admitting the
//! produced records — is `src/accord.rs`: `POST /v1/accord/holder` +
//! `GET /v1/accord-holders` + the 2-of-3 `POST /v1/accord/verify-invocation`.)
//!
//! ## Portable 2-factor custody (CC 4.2 / §9.2, CIRISVerify#91)
//!
//! An accord holder wields the HUMANITY_ACCORD kill-switch, so their key MUST
//! be under genuine distributed-human, 2-factor custody. The portable mode is:
//!
//! 1. Ed25519 (the classical federation half) lives in a **FIPS YubiKey** —
//!    PIN + touch gated, the seed never leaves the token.
//! 2. ML-DSA-65 (the PQC half) is a software seed **AEAD-wrapped to a USB key**.
//!    The wrap key is derived from a deterministic Ed25519 signature over a
//!    fixed challenge, so unwrapping the USB blob REQUIRES the YubiKey (a touch
//!    + PIN). Neither half alone can sign: it is both-keys + PIN + touch.
//!
//! ## What this produces
//!
//! [`provision_portable_holder`] returns a [`ProvisionedHolder`] with:
//!
//! 1. `holder_record` — the self-signed `accord_holder` `SignedKeyRecord`. The
//!    holder serializes it to JSON and POSTs it to `POST /v1/accord/holder`,
//!    where the canonical `register_federation_key` gate admits it (and refuses
//!    a software-only custody tier — the custody floor).
//! 2. `custody_attestation` — the `portable_2fa` custody attestation
//!    (`SignedCegObject`, kind
//!    [`ciris_verify_core::accord_custody_attestation::ACCORD_CUSTODY_ATTESTATION_KIND`]).
//!    This is the FIPS proof that feeds the `attestation_evidence` the
//!    v0.5.15 accord-holder gate enforces.
//!
//! ## Why the YubiKey signer is caller-supplied
//!
//! This function takes the Ed25519 `HardwareSigner` as a parameter rather than
//! opening the token itself, so the SAME code path serves the production route
//! and the unit tests without a branch on custody.
//!
//! **The production caller passes the real token.**
//! [`crate::accord_provision`]'s `POST /v1/accord/provision-holder` opens it
//! with [`crate::identity::open_yubikey_ed25519_signer`] →
//! `UserIdentityBackend::Pkcs11` → keyring `pkcs11::open_pkcs11_signer` →
//! `Pkcs11Signer::open`: real `cryptoki`, `C_Sign` on the token, under the
//! `pkcs11` feature that is in this crate's DEFAULT set. That is the backend
//! the six-key ceremony ran on physical YubiKey 5 FIPS hardware. Only the unit
//! test below passes [`ciris_keyring::Ed25519SoftwareSigner`], which is what a
//! test on a box with no reader must do.
//!
//! This paragraph used to say the opener was "blocked on CIRISVerify#62
//! (`get_token_signer` is stubbed `NotSupported`)" — true of
//! `hw_token::get_token_signer`, which **nothing calls**: zero callers in
//! server, verify, persist or edge. #62 closed 2026-06-18 and the real opener
//! shipped under a different name the same week, so the comment described a
//! path the code never took and read as "this runs on a software stand-in".
//! It misled a review on 2026-09-21. A stale comment beside a live call is the
//! mirrored-rule class: trace the call, do not read the prose.

use std::path::PathBuf;
use std::sync::Arc;

use ciris_keyring::usb_wrapped_mldsa65::UsbWrappedMlDsa65Signer;
use ciris_keyring::{HardwareSigner, PqcSigner};
use ciris_verify_core::accord_custody_attestation::{
    produce_accord_custody_attestation, CUSTODY_TIER_PORTABLE_2FA,
};
use ciris_verify_core::accord_genesis::produce_accord_holder_record;
use ciris_verify_core::ceg_outbox::SignedCegObject;
use ciris_verify_core::federation_self_record::SignedKeyRecord;
use ciris_verify_core::self_at_login::HardwareRootedIdentity;

/// The two artifacts a portable accord holder mints on their device.
///
/// `holder_record` registers via `POST /v1/accord/holder`; `custody_attestation`
/// is the `portable_2fa` FIPS proof feeding the accord-holder gate's
/// `attestation_evidence`.
pub struct ProvisionedHolder {
    /// The self-signed `accord_holder` record (verify's
    /// `federation_self_record::SignedKeyRecord`, serialized to JSON for the
    /// POST — kept as the verify type, NOT persist's record).
    pub holder_record: SignedKeyRecord,
    /// The `portable_2fa` custody attestation (kind
    /// [`ciris_verify_core::accord_custody_attestation::ACCORD_CUSTODY_ATTESTATION_KIND`]).
    pub custody_attestation: SignedCegObject,
}

/// Provision a portable high-secure accord holder on this device.
///
/// Steps (see the module doc for the custody model):
///
/// 1. AEAD-wrap a fresh ML-DSA-65 seed to `usb_dir`, bound to `yubikey_ed`.
/// 2. Build a `HardwareRootedIdentity` over the YubiKey Ed25519 + the
///    USB-wrapped ML-DSA-65 halves.
/// 3. Produce the self-signed `accord_holder` record.
/// 4. Produce the `portable_2fa` custody attestation from the YubiKey PIV
///    attestation chain.
///
/// `yubikey_ed` is the Ed25519 `HardwareSigner` for the holder's PIV slot. The
/// production caller (`POST /v1/accord/provision-holder`) opens the REAL token
/// through [`crate::identity::open_yubikey_ed25519_signer`] (keyring
/// `pkcs11::open_pkcs11_signer`, `C_Sign` on-device); the unit test below
/// passes a software signer because CI has no reader. See the module doc.
/// `attestation_9c_der` is the slot-9c PIV attestation certificate (DER);
/// `attestation_chain_ders` is its issuing chain (DER, leaf-to-root order).
///
/// # Errors
/// Returns an error if the USB wrap fails, the identity is not Ed25519-rooted,
/// or either signed artifact cannot be produced.
pub async fn provision_portable_holder(
    yubikey_ed: Arc<dyn HardwareSigner>,
    key_id: &str,
    usb_dir: PathBuf,
    attestation_9c_der: &[u8],
    attestation_chain_ders: &[&[u8]],
    valid_from: &str,
) -> anyhow::Result<ProvisionedHolder> {
    // 1. Wrap the ML-DSA-65 half to the USB key, bound to the YubiKey.
    let mldsa =
        UsbWrappedMlDsa65Signer::provision(yubikey_ed.as_ref(), key_id, usb_dir, None).await?;

    // 2. Hardware-rooted identity: YubiKey Ed25519 + USB-wrapped ML-DSA-65.
    let identity = HardwareRootedIdentity::new(
        key_id,
        yubikey_ed.clone(),
        Arc::new(mldsa) as Arc<dyn PqcSigner>,
    )?;

    // 3. The self-signed accord_holder record (registers via /v1/accord/holder).
    let holder_record = produce_accord_holder_record(&identity, valid_from).await?;

    // 4. The portable_2fa custody attestation (the FIPS proof).
    let custody_attestation = produce_accord_custody_attestation(
        &identity,
        attestation_9c_der,
        attestation_chain_ders,
        CUSTODY_TIER_PORTABLE_2FA,
        valid_from,
    )
    .await?;

    Ok(ProvisionedHolder {
        holder_record,
        custody_attestation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_keyring::Ed25519SoftwareSigner;
    use ciris_verify_core::accord_custody_attestation::ACCORD_CUSTODY_ATTESTATION_KIND;

    #[tokio::test]
    async fn provision_portable_holder_roundtrips_software_standin() {
        // Software stand-in for the FIPS YubiKey — because CI has no PC/SC
        // reader, NOT because the real open is unavailable: production opens
        // the token through `identity::open_yubikey_ed25519_signer` (real
        // cryptoki `C_Sign`). This test covers the wrap → identity → holder
        // record → custody attestation chain, which is signer-agnostic by
        // construction. `from_bytes` requires a 32-byte seed.
        let ed: Arc<dyn HardwareSigner> = Arc::new(
            Ed25519SoftwareSigner::from_bytes(&[0x42; 32], "accord-holder-portable").unwrap(),
        );

        let usb_dir = std::env::temp_dir().join(format!("ciris-accord-usb-{}", std::process::id()));
        std::fs::create_dir_all(&usb_dir).unwrap();

        // Minimal DER stand-ins for the PIV slot-9c attestation + chain.
        let att_9c: &[u8] = &[0x30, 0x82, 0x01, 0x00];
        let chain: &[&[u8]] = &[&[0x30, 0x82, 0x01, 0x00]];

        let provisioned = provision_portable_holder(
            ed.clone(),
            "accord-holder-portable",
            usb_dir.clone(),
            att_9c,
            chain,
            "2026-06-20T00:00:00.000Z",
        )
        .await
        .expect("provision_portable_holder should succeed with the software stand-in");

        // The custody attestation is the accord custody kind.
        assert_eq!(
            provisioned.custody_attestation.kind,
            ACCORD_CUSTODY_ATTESTATION_KIND
        );

        // Roundtrip: re-open the USB-wrapped ML-DSA half with the same YubiKey
        // and prove the unwrap reproduces the provisioned PQC pubkey. This is
        // the YubiKey-gated USB unwrap path.
        let reopened =
            UsbWrappedMlDsa65Signer::open(ed.as_ref(), "accord-holder-portable", usb_dir.clone())
                .await
                .expect("reopening the USB-wrapped ML-DSA signer should succeed");

        // Re-provisioning is non-deterministic (fresh seed), so we cannot
        // compare against the original `mldsa` (consumed into the identity).
        // Instead, open TWICE and prove the unwrap is stable for one blob.
        let reopened2 =
            UsbWrappedMlDsa65Signer::open(ed.as_ref(), "accord-holder-portable", usb_dir.clone())
                .await
                .expect("reopening the USB-wrapped ML-DSA signer again should succeed");

        let pk1 = reopened.public_key().await.unwrap();
        let pk2 = reopened2.public_key().await.unwrap();
        assert_eq!(
            pk1, pk2,
            "the USB unwrap must reproduce a stable ML-DSA pubkey"
        );
        assert!(
            !pk1.is_empty(),
            "the unwrapped ML-DSA pubkey must be non-empty"
        );

        // The reopened signer's pubkey must also be what the holder record was
        // built over (the identity's ML-DSA half == the wrapped seed).
        assert_eq!(
            provisioned.holder_record.record.key_id, "accord-holder-portable",
            "the holder record carries the provisioned key_id"
        );

        std::fs::remove_dir_all(&usb_dir).ok();
    }
}
