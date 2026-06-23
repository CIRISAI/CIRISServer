//! **`POST /v1/accord/provision-holder`** — the guided, foolproof holder-device
//! provisioning endpoint that drives [`crate::accord_custody::provision_portable_holder`]
//! (CIRISServer#41, the safe-mesh custody floor).
//!
//! This is the SERVER side of the desktop "Provision Accord Holder" flow. The
//! holder runs the CIRIS desktop client ON THEIR OWN MACHINE, the client POSTs to
//! THIS loopback-only endpoint, and the node does the crypto (the app holds no
//! keys). The endpoint:
//!
//!   1. Opens the holder's **already-FIPS-approved** YubiKey PIV slot-9c Ed25519
//!      key as a [`ciris_keyring::HardwareSigner`] via the EXISTING PKCS#11 path
//!      ([`crate::identity::open_yubikey_ed25519_signer`] → `get_user_identity_signer`).
//!      The holder did the `ykman` / FIPS prep out of band; we only DETECT + USE
//!      the key (`provision: false`).
//!   2. Obtains the PIV custody-attestation chain — the slot-9c attestation cert
//!      (`ykman piv keys attest 9c`) + the f9 device attestation cert
//!      (`ykman piv certificates export f9`) — by shelling out to `ykman` (it is
//!      the holder's own device). Request fields can override these as a fallback.
//!   3. Calls [`provision_portable_holder`] with the YubiKey Ed25519 signer, the
//!      chosen ML-DSA USB path, and the attestation chain. This AEAD-wraps a fresh
//!      ML-DSA-65 seed to the USB key (unwrappable only by the YubiKey), builds the
//!      hardware-rooted identity, and mints the two artifacts.
//!   4. Returns `{ key_id, holder_record, custody_attestation }` as JSON — the
//!      holder then POSTs these to the owner-gated `POST /v1/accord/holder`, where
//!      the custody attestation is verified against the pinned Yubico Attestation
//!      Root 1 before the key is admitted.
//!
//! ## Loopback-only (NOT owner-gated)
//!
//! Like the other setup routes (`/v1/self/identity`, `/v1/setup/claim-remote`),
//! this is restricted to **loopback peers** (the per-route `require_loopback`
//! guard in `compose.rs`). It is NOT owner-gated: provisioning is a holder-device
//! op the would-be holder runs on their own box BEFORE they are an owner/holder of
//! anything; the OWNER gate is downstream at `POST /v1/accord/holder` (the node
//! owner admits the produced record). Touching a physical YubiKey (PIN + touch) is
//! the real authority here.
//!
//! ## `pkcs11`-feature gating (mirrors `identity.rs`)
//!
//! The real-YubiKey path needs the `pkcs11` cargo feature (→ `ciris-keyring/pkcs11`,
//! the cryptoki backend, CIRISVerify#62 closed). Without the feature the endpoint
//! returns a clear `NotSupported` (501) and never links cryptoki — a plain
//! `cargo build` is unaffected.
//!
//! ## Genesis cosign — `POST /v1/accord/family/cosign`
//!
//! The same file also hosts the genesis **cosign-with-the-YubiKey** step. After
//! `POST /v1/accord/genesis/envelope` returns the canonical family envelope, each
//! primary holder RE-INSERTS their YubiKey and cosigns the envelope on their own
//! token: the endpoint re-opens the YubiKey Ed25519 + the USB-wrapped ML-DSA half
//! (NO re-provision — the USB blob already exists), builds the same
//! [`ciris_verify_core::self_at_login::HardwareRootedIdentity`], and calls
//! [`ciris_verify_core::accord_genesis::co_sign_accord_family`]. The physical
//! touch the YubiKey requires on the bound signature IS the holder's consent. The
//! response carries the holder's [`ciris_verify_core::threshold::ThresholdSignature`]
//! **and** their founder [`ciris_verify_core::threshold::ThresholdMember`] — the
//! two inputs `POST /v1/accord/genesis/assemble` needs (`signatures` + `founders`),
//! produced together from the one re-opened identity so the operator never hand-
//! assembles a member set. Same `pkcs11` gating + loopback guard as provisioning.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::Deserialize;

use ciris_persist::prelude::Engine;

/// PKCS#11 / PIV knobs for opening the holder's already-provisioned YubiKey. All
/// optional — the defaults match `identity.rs` (`libykcs11.so`, slot `9c`).
///
/// The fields are consumed only on the `pkcs11` path; without the feature the
/// request still parses (so the endpoint can return a clear NotSupported), but
/// the values go unread — hence the conditional `allow(dead_code)`.
#[derive(Debug, Default, Deserialize)]
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct ProvisionPkcs11 {
    /// The PIV user PIN. When omitted the token may prompt out of band (or the
    /// open fails with a plain-language "PIN required" error the UI surfaces).
    #[serde(default)]
    user_pin: Option<String>,
    /// The PIV slot the Ed25519 key lives in (default `9c`).
    #[serde(default)]
    piv_slot: Option<String>,
    /// Path to the token's PKCS#11 module (default `libykcs11.so`).
    #[serde(default)]
    module_path: Option<String>,
}

/// `POST /v1/accord/provision-holder` request.
///
/// `key_id` + `mldsa_usb_path` are validated on every build; the remaining fields
/// drive the `pkcs11` path only (unread without the feature — see
/// [`ProvisionPkcs11`]), hence the conditional `allow(dead_code)`.
#[derive(Debug, Deserialize)]
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct ProvisionHolderRequest {
    /// The federation `key_id` (the keystore/seal alias the wrapped ML-DSA half +
    /// the holder record are minted under).
    key_id: String,
    /// **The one user choice (the UI centerpiece):** the filesystem directory on
    /// the holder's USB key where the AEAD-wrapped ML-DSA-65 seed is written.
    mldsa_usb_path: String,
    /// PKCS#11 / PIV knobs for the already-FIPS-approved YubiKey.
    #[serde(default)]
    pkcs11: ProvisionPkcs11,
    /// FALLBACK: the slot-9c PIV attestation certificate (DER), base64-standard.
    /// When absent the endpoint shells out to `ykman piv keys attest 9c`. Supplied
    /// only when `ykman` is not available on the host (the happy path needs no
    /// manual DER fiddling).
    #[serde(default)]
    attestation_9c_der_base64: Option<String>,
    /// FALLBACK: the attestation chain (DER, base64-standard, **leaf-first**:
    /// `[f9, …intermediates…]`). When absent the endpoint shells out to
    /// `ykman piv certificates export f9`.
    #[serde(default)]
    attestation_chain_ders_base64: Option<Vec<String>>,
}

/// `POST /v1/accord/family/cosign` request.
///
/// `key_id` + `mldsa_usb_path` are validated on every build (the USB half is
/// RE-OPENED, not provisioned); `envelope` is the verbatim family envelope JSON
/// returned by `POST /v1/accord/genesis/envelope`. The `pkcs11` knobs drive the
/// real-token path only (unread without the feature — see [`ProvisionPkcs11`]),
/// hence the conditional `allow(dead_code)`.
#[derive(Debug, Deserialize)]
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct CosignFamilyRequest {
    /// The holder's federation `key_id` — the SAME alias the wrapped ML-DSA half +
    /// the holder record were minted under at `provision-holder` time.
    key_id: String,
    /// The holder's USB directory holding the AEAD-wrapped ML-DSA-65 seed (the one
    /// chosen at provision time). RE-OPENED here — never re-provisioned.
    mldsa_usb_path: String,
    /// The verbatim family envelope JSON from `POST /v1/accord/genesis/envelope`.
    /// Cosigned byte-for-byte (JCS) — never rebuilt here.
    envelope: serde_json::Value,
    /// PKCS#11 / PIV knobs for the holder's already-FIPS-approved YubiKey.
    #[serde(default)]
    pkcs11: ProvisionPkcs11,
}

#[derive(Clone)]
struct ProvisionState {
    #[allow(dead_code)] // held for symmetry with the other setup routers + future use.
    engine: Arc<Engine>,
}

fn err(code: StatusCode, error: &str) -> Response {
    (code, Json(serde_json::json!({ "error": error }))).into_response()
}

/// `POST /v1/accord/provision-holder` — drive [`provision_portable_holder`] from
/// the holder's already-FIPS-approved YubiKey + the chosen ML-DSA USB path.
///
/// Behind the `pkcs11` feature this opens the real token; without it, it returns a
/// clear `NotSupported`.
async fn provision_holder(State(_st): State<ProvisionState>, body: axum::body::Bytes) -> Response {
    let req: ProvisionHolderRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };

    // Input validation (foolproof: refuse empty/blank before touching hardware).
    if req.key_id.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "key_id must not be empty");
    }
    let usb_path = req.mldsa_usb_path.trim();
    if usb_path.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "mldsa_usb_path must not be empty — insert your USB key and choose its folder",
        );
    }

    provision_holder_impl(req).await
}

/// `POST /v1/accord/family/cosign` — RE-OPEN the holder's YubiKey + USB-wrapped
/// ML-DSA half and cosign the genesis family envelope on their own token. Returns
/// the holder's `{ signature, member }` for `POST /v1/accord/genesis/assemble`.
///
/// Behind the `pkcs11` feature this opens the real token (the touch-required tap
/// IS the holder's consent); without it, it returns a clear `NotSupported`.
async fn cosign_family(State(_st): State<ProvisionState>, body: axum::body::Bytes) -> Response {
    let req: CosignFamilyRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };

    // Input validation (foolproof: refuse empty/non-object before touching hardware).
    if req.key_id.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "key_id must not be empty");
    }
    if req.mldsa_usb_path.trim().is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "mldsa_usb_path must not be empty — insert your USB key and choose its folder",
        );
    }
    if !req.envelope.is_object() {
        return err(
            StatusCode::BAD_REQUEST,
            "envelope must be the family-envelope JSON object from /v1/accord/genesis/envelope",
        );
    }

    cosign_family_impl(req).await
}

// ─── pkcs11 path: the real YubiKey-backed provisioning ────────────────────────

#[cfg(feature = "pkcs11")]
async fn provision_holder_impl(req: ProvisionHolderRequest) -> Response {
    use std::path::PathBuf;

    use base64::Engine as _;

    use crate::identity::{Pkcs11Options, DEFAULT_PIV_SLOT, DEFAULT_YKCS11_MODULE};

    let b64 = base64::engine::general_purpose::STANDARD;
    let usb_dir = PathBuf::from(req.mldsa_usb_path.trim());

    // The USB directory must exist + be writable (plain-language failure).
    if !usb_dir.is_dir() {
        return err(
            StatusCode::BAD_REQUEST,
            &format!(
                "the ML-DSA USB path is not a directory: {} — insert your USB key and choose its \
                 folder",
                usb_dir.display()
            ),
        );
    }
    if let Err(e) = writable_probe(&usb_dir) {
        return err(
            StatusCode::BAD_REQUEST,
            &format!(
                "the ML-DSA USB path is not writable ({}): {e} — check the USB is mounted \
                 read-write",
                usb_dir.display()
            ),
        );
    }

    let piv_slot = req
        .pkcs11
        .piv_slot
        .clone()
        .unwrap_or_else(|| DEFAULT_PIV_SLOT.to_string());

    // 1. Open the holder's ALREADY-provisioned YubiKey Ed25519 (no provisioning).
    let opts = Pkcs11Options {
        module_path: req
            .pkcs11
            .module_path
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_YKCS11_MODULE)),
        user_pin: req.pkcs11.user_pin.clone(),
        piv_slot: piv_slot.clone(),
        provision: false,
        ..Pkcs11Options::default()
    };
    tracing::info!(
        key_id = %req.key_id,
        piv_slot = %piv_slot,
        module = %opts.module_path.display(),
        usb_path = %usb_dir.display(),
        pin_supplied = opts.user_pin.is_some(),
        "accord provision-holder: opening the holder's YubiKey Ed25519 (slot {piv_slot})"
    );

    // AUTO-FIX the "key present, no certificate" case BEFORE opening: ykcs11 only
    // exposes a PIV key when its slot has a cert, so the node generates a self-signed
    // cert in the slot itself (using the PIN) — no manual `ykman` step for the holder.
    match ensure_slot_cert(
        &piv_slot,
        req.pkcs11.user_pin.as_deref(),
        &format!("CN=ciris-accord-{}", req.key_id),
    ) {
        Ok(true) => tracing::info!(
            key_id = %req.key_id, slot = %piv_slot,
            "accord provision-holder: auto-generated the slot certificate (ykcs11 enumeration fix)"
        ),
        Ok(false) => {} // a cert already existed
        Err(e) => tracing::warn!(
            key_id = %req.key_id, slot = %piv_slot, error = %e,
            "accord provision-holder: could not auto-generate the slot certificate — the open may fail"
        ),
    }

    let yubikey_ed = match crate::identity::open_yubikey_ed25519_signer(opts) {
        Ok(s) => Arc::<dyn ciris_keyring::HardwareSigner>::from(s),
        Err(e) => {
            tracing::warn!(
                key_id = %req.key_id,
                slot = %piv_slot,
                error = %e,
                "accord provision-holder: could NOT open the YubiKey slot key (even after the \
                 cert auto-fix) — check the YubiKey is inserted, FIPS-approved, and the PIN correct"
            );
            // Diagnose the most common silent failure: the slot is perfect, but the
            // HOST's ykcs11 is too old to expose an Ed25519 PIV key. "Key not found"
            // while pkcs11 enumerates NO private-key object is the fingerprint.
            let es = e.to_string();
            let key_not_found = es.contains("Key not found") || es.contains("Private key");
            let host_pkcs11_too_old =
                key_not_found && probe_pkcs11_surfaces_slot9c() == Some(false);
            let msg = if host_pkcs11_too_old {
                format!(
                    "your YubiKey slot-{piv_slot} is fine, but this HOST's PKCS#11 module \
                     (ykcs11/yubico-piv-tool) is TOO OLD to use an Ed25519 PIV key — it can't \
                     expose the private key to the signer (root cause: {e}). UPGRADE \
                     yubico-piv-tool to ≥ 2.5.0 (Ubuntu 24.04 ships 2.2.0): \
                     `sudo add-apt-repository ppa:yubico/stable && sudo apt update && sudo apt \
                     install ykcs11`, then retry. No change to the YubiKey is needed."
                )
            } else {
                format!(
                    "couldn't open your YubiKey's slot-{piv_slot} key: {e} — check the YubiKey is \
                     inserted + FIPS-approved, the PIN is correct, and slot {piv_slot} holds an \
                     Ed25519 key (the node tried to auto-generate the slot certificate; if that \
                     also failed the PIN may be missing or wrong)."
                )
            };
            return err(StatusCode::BAD_REQUEST, &msg);
        }
    };

    // 2. The PIV custody-attestation chain — request fallback OR shell to ykman.
    let attestation_9c_der: Vec<u8> = match &req.attestation_9c_der_base64 {
        Some(s) => match b64.decode(s.trim()) {
            Ok(d) => d,
            Err(e) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    &format!("bad attestation_9c_der_base64: {e}"),
                )
            }
        },
        None => match ykman_attest_9c(&piv_slot) {
            Ok(d) => d,
            Err(e) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    &format!(
                    "couldn't read the slot-{piv_slot} PIV attestation via ykman: {e} — install \
                         yubikey-manager, or supply attestation_9c_der_base64"
                ),
                )
            }
        },
    };
    let chain: Vec<Vec<u8>> = match &req.attestation_chain_ders_base64 {
        Some(list) => {
            let mut out = Vec::with_capacity(list.len());
            for (i, s) in list.iter().enumerate() {
                match b64.decode(s.trim()) {
                    Ok(d) => out.push(d),
                    Err(e) => {
                        return err(
                            StatusCode::BAD_REQUEST,
                            &format!("bad attestation_chain_ders_base64[{i}]: {e}"),
                        )
                    }
                }
            }
            out
        }
        None => match ykman_export_f9() {
            // ykman only yields the on-device f9 cert; the YubiKey does NOT hold the
            // Yubico CA intermediates above it. Path-build [f9, …intermediates…] up
            // to the pinned root from the bundled Yubico PKI so the custody
            // attestation validates (CIRISVerify expects the FULL chain to the root;
            // fw-5.7 FIPS devices have an extra level: f9 → PIV-Att-B1 → Att-Int-B1
            // → Root). See `complete_attestation_chain`.
            Ok(f9) => complete_attestation_chain(f9),
            Err(e) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        "couldn't export the f9 device attestation cert via ykman: {e} — install \
                         yubikey-manager, or supply attestation_chain_ders_base64"
                    ),
                )
            }
        },
    };
    let chain_refs: Vec<&[u8]> = chain.iter().map(|v| v.as_slice()).collect();

    // 3. Drive the custody provisioning (USB wrap + identity + the two artifacts).
    //    A touch-required YubiKey (slot 9c policy ALWAYS) BLOCKS on EACH Ed25519
    //    sign until tapped — THREE in all: the USB ML-DSA wrap-challenge, the holder
    //    record, and the custody attestation. The holder must touch for every blink.
    tracing::info!(
        key_id = %req.key_id.trim(),
        "accord provision-holder: YubiKey opened + attestation read; now signing — \
         TOUCH the YubiKey for EACH blink (3 signs: ML-DSA wrap, holder record, custody attestation)"
    );
    let now = chrono::Utc::now().to_rfc3339();
    let provisioned = match crate::accord_custody::provision_portable_holder(
        yubikey_ed,
        req.key_id.trim(),
        usb_dir.clone(),
        &attestation_9c_der,
        &chain_refs,
        &now,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(key_id = %req.key_id.trim(), error = %e, "accord provision-holder: custody provisioning FAILED");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("provision portable holder: {e}"),
            );
        }
    };
    tracing::info!(
        key_id = %req.key_id.trim(),
        "accord provision-holder: all 3 signs complete — holder record + custody attestation produced"
    );

    let key_id = req.key_id.trim().to_string();

    // OUTBOX — write the finished artifacts to the SAME shared CEG outbox that
    // verify's `create_federation_identity` already uses (`ceg_outbox()` =
    // `$CIRIS_HOME/ceg/outbox`, else `~/ciris/ceg/outbox`). The custody attestation
    // IS a `SignedCegObject` → `write_to_outbox` (the same exact case as verify);
    // the holder record (a `SignedKeyRecord`) rides alongside as a bundle. Every
    // holder's finished objects land in ONE place for verify to wrap into the
    // persist `attestation_evidence` (PlatformAttestation) + register — so the
    // touch-gated work is NEVER wasted even before that admission path is wired.
    match provisioned.custody_attestation.write_to_outbox(&key_id) {
        Ok(p) => tracing::info!(key_id = %key_id, path = %p.display(),
            "accord provision-holder: custody attestation written to the CEG outbox"),
        Err(e) => tracing::warn!(key_id = %key_id, error = %e,
            "accord provision-holder: could NOT write the custody attestation to the CEG outbox"),
    }

    let body = serde_json::json!({
        "key_id": key_id,
        "holder_record": provisioned.holder_record,
        "custody_attestation": provisioned.custody_attestation,
    });

    let holder_dir = ciris_verify_core::ceg_outbox::ceg_outbox().join("accord_holder");
    let holder_path = holder_dir.join(format!("{key_id}.json"));
    match std::fs::create_dir_all(&holder_dir)
        .map_err(|e| e.to_string())
        .and_then(|()| serde_json::to_vec_pretty(&body).map_err(|e| e.to_string()))
        .and_then(|b| std::fs::write(&holder_path, b).map_err(|e| e.to_string()))
    {
        Ok(()) => tracing::info!(key_id = %key_id, path = %holder_path.display(),
            "accord provision-holder: holder bundle saved to the CEG outbox (pass to verify to wrap + register)"),
        Err(e) => tracing::warn!(key_id = %key_id, error = %e,
            "accord provision-holder: could NOT write the holder bundle to the outbox"),
    }

    // 4. Return the two artifacts the holder POSTs to /v1/accord/holder.
    (StatusCode::OK, Json(body)).into_response()
}

#[cfg(feature = "pkcs11")]
async fn cosign_family_impl(req: CosignFamilyRequest) -> Response {
    use std::path::PathBuf;

    use ciris_keyring::usb_wrapped_mldsa65::UsbWrappedMlDsa65Signer;
    use ciris_keyring::PqcSigner;
    use ciris_verify_core::accord_genesis::{co_sign_accord_family, founder_member};
    use ciris_verify_core::self_at_login::HardwareRootedIdentity;

    use crate::identity::{Pkcs11Options, DEFAULT_PIV_SLOT, DEFAULT_YKCS11_MODULE};

    let key_id = req.key_id.trim().to_string();
    let usb_dir = PathBuf::from(req.mldsa_usb_path.trim());

    // The USB directory must already hold this holder's wrapped ML-DSA blob.
    if !usb_dir.is_dir() {
        return err(
            StatusCode::BAD_REQUEST,
            &format!(
                "the ML-DSA USB path is not a directory: {} — insert the SAME USB key you \
                 provisioned this holder with",
                usb_dir.display()
            ),
        );
    }

    let piv_slot = req
        .pkcs11
        .piv_slot
        .clone()
        .unwrap_or_else(|| DEFAULT_PIV_SLOT.to_string());

    // 1. Re-open the holder's YubiKey Ed25519 (NO provisioning).
    let opts = Pkcs11Options {
        module_path: req
            .pkcs11
            .module_path
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_YKCS11_MODULE)),
        user_pin: req.pkcs11.user_pin.clone(),
        piv_slot: piv_slot.clone(),
        provision: false,
        ..Pkcs11Options::default()
    };
    let yubikey_ed = match crate::identity::open_yubikey_ed25519_signer(opts) {
        Ok(s) => Arc::<dyn ciris_keyring::HardwareSigner>::from(s),
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                &format!(
                    "couldn't open your YubiKey's slot-{piv_slot} key: {e} — is the YubiKey \
                     inserted and the PIN correct?"
                ),
            )
        }
    };

    // 2. Re-open the USB-wrapped ML-DSA-65 half (bound to THIS YubiKey + key_id).
    let mldsa =
        match UsbWrappedMlDsa65Signer::open(yubikey_ed.as_ref(), &key_id, usb_dir.clone()).await {
            Ok(m) => m,
            Err(e) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    &format!(
                    "couldn't re-open the USB-wrapped ML-DSA key for '{key_id}' at {}: {e} — is \
                     this the SAME USB + YubiKey pair you provisioned this holder with?",
                    usb_dir.display()
                ),
                )
            }
        };

    // 3. Rebuild the hardware-rooted identity (YubiKey Ed25519 + USB-wrapped ML-DSA).
    let identity = match HardwareRootedIdentity::new(
        key_id.clone(),
        yubikey_ed.clone(),
        Arc::new(mldsa) as Arc<dyn PqcSigner>,
    ) {
        Ok(i) => i,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("build hardware-rooted identity: {e}"),
            )
        }
    };

    // 4. Cosign the genesis family envelope. A touch-required YubiKey BLOCKS on the
    //    bound signature until tapped — that physical tap IS the holder's consent.
    let signature = match co_sign_accord_family(&identity, &req.envelope).await {
        Ok(s) => s,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("cosign accord family envelope: {e}"),
            )
        }
    };

    // The founder ThresholdMember from the SAME identity — the assemble step needs
    // both `signatures` and `founders`; producing them together is foolproof.
    let member = match founder_member(&identity).await {
        Ok(m) => m,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("derive founder member: {e}"),
            )
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "key_id": key_id,
            "signature": signature,
            "member": member,
        })),
    )
        .into_response()
}

/// Probe that `dir` is writable by creating + removing a temp file.
#[cfg(feature = "pkcs11")]
fn writable_probe(dir: &std::path::Path) -> std::io::Result<()> {
    let probe = dir.join(format!(".ciris-accord-write-probe-{}", std::process::id()));
    std::fs::write(&probe, b"ciris")?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// `ykman piv keys attest <slot>` → the slot's PIV attestation cert (DER).
#[cfg(feature = "pkcs11")]
fn ykman_attest_9c(slot: &str) -> anyhow::Result<Vec<u8>> {
    // `-F DER` emits DER to stdout (the `-` output target).
    run_ykman_capture(&["piv", "keys", "attest", "-F", "DER", slot, "-"])
}

/// `ykman piv certificates export f9` → the f9 device attestation cert (DER).
#[cfg(feature = "pkcs11")]
fn ykman_export_f9() -> anyhow::Result<Vec<u8>> {
    run_ykman_capture(&["piv", "certificates", "export", "-F", "DER", "f9", "-"])
}

/// Yubico's published attestation-CA intermediate bundle
/// (`developers.yubico.com/PKI/yubico-intermediate.pem`). The YubiKey holds only
/// the 9c + f9 certs; the intermediates above f9 (which ROTATE, e.g. `Yubico PIV
/// Attestation B 1` → `Yubico Attestation Intermediate B 1`) are published here.
/// CIRISVerify pins the durable ROOT and expects the caller to carry the
/// intermediates, so we path-build them in.
#[cfg(feature = "pkcs11")]
const YUBICO_INTERMEDIATE_BUNDLE: &str = include_str!("yubico_attestation_ca.pem");

/// The pinned Yubico attestation root CN — the chain stops one short of it (verify
/// supplies the root out of band).
#[cfg(feature = "pkcs11")]
const YUBICO_ROOT_CN: &str = "Yubico Attestation Root 1";

/// Extract `(issuer_cn, subject_cn)` from a DER cert by scanning for the commonName
/// OID `2.5.4.3` (`06 03 55 04 03`) followed by a DirectoryString. In a
/// TBSCertificate the issuer RDNs precede the subject RDNs, so the 1st CN is the
/// issuer's and the 2nd the subject's. Sufficient for the simple Yubico CA certs.
#[cfg(feature = "pkcs11")]
fn cert_cns(der: &[u8]) -> Option<(String, String)> {
    const OID_CN: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x03];
    let mut cns: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i + 7 <= der.len() {
        if der[i..i + 5] == OID_CN {
            let tag = der[i + 5];
            let len = der[i + 6] as usize;
            // CNs are short DirectoryStrings (UTF8String/PrintableString/IA5String),
            // short-form length (< 128).
            if (tag == 0x0c || tag == 0x13 || tag == 0x16) && len < 0x80 {
                let start = i + 7;
                if start + len <= der.len() {
                    if let Ok(s) = std::str::from_utf8(&der[start..start + len]) {
                        cns.push(s.to_string());
                    }
                }
                i = start + len;
                continue;
            }
        }
        i += 1;
    }
    match cns.len() {
        0 => None,
        1 => Some((cns[0].clone(), cns[0].clone())),
        _ => Some((cns[0].clone(), cns[1].clone())),
    }
}

/// Parse the bundled Yubico intermediates into `(subject_cn, der)` pairs.
#[cfg(feature = "pkcs11")]
fn yubico_intermediates() -> Vec<(String, Vec<u8>)> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut out = Vec::new();
    for block in YUBICO_INTERMEDIATE_BUNDLE
        .split("-----BEGIN CERTIFICATE-----")
        .skip(1)
    {
        let body = block
            .split("-----END CERTIFICATE-----")
            .next()
            .unwrap_or("");
        let b64s: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(der) = b64.decode(b64s) {
            if let Some((_, subject)) = cert_cns(&der) {
                out.push((subject, der));
            }
        }
    }
    out
}

/// Build `[f9, …intermediates…]` (leaf-first, EXCLUDING the pinned root) by walking
/// each cert's issuer CN to the next bundled intermediate, until the issuer is the
/// pinned root. Best-effort: if an intermediate is missing it returns what it has +
/// logs (verify will then reject, with a clear chain error).
#[cfg(feature = "pkcs11")]
fn complete_attestation_chain(f9_der: Vec<u8>) -> Vec<Vec<u8>> {
    let bundle = yubico_intermediates();
    let mut chain = vec![f9_der.clone()];
    let mut cur = f9_der;
    for _ in 0..8 {
        let issuer = match cert_cns(&cur) {
            Some((iss, _)) => iss,
            None => break,
        };
        if issuer == YUBICO_ROOT_CN {
            tracing::info!(
                links = chain.len(),
                "accord provision-holder: attestation chain path-built to the pinned Yubico root"
            );
            return chain;
        }
        match bundle.iter().find(|(subj, _)| *subj == issuer) {
            Some((_, der)) => {
                chain.push(der.clone());
                cur = der.clone();
            }
            None => {
                tracing::warn!(
                    missing = %issuer,
                    "accord provision-holder: Yubico intermediate not in the bundle — \
                     attestation chain may not reach the pinned root (custody register may reject)"
                );
                break;
            }
        }
    }
    chain
}

/// Run `ykman <args>` capturing stdout as bytes (DER). `ykman` reads the token
/// directly; a missing binary or a non-zero exit is a plain error.
#[cfg(feature = "pkcs11")]
fn run_ykman_capture(args: &[&str]) -> anyhow::Result<Vec<u8>> {
    let out = std::process::Command::new("ykman")
        .args(args)
        .output()
        .map_err(|e| {
            anyhow::anyhow!("could not run `ykman` (is yubikey-manager installed?): {e}")
        })?;
    if !out.status.success() {
        anyhow::bail!(
            "`ykman {}` failed (exit {:?}): {}",
            args.join(" "),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    if out.stdout.is_empty() {
        anyhow::bail!("`ykman {}` produced no output", args.join(" "));
    }
    Ok(out.stdout)
}

/// **Auto-provision the slot certificate.** ykcs11 only exposes a PIV private key
/// when its slot ALSO holds a certificate — a key-without-cert slot enumerates
/// nothing ("Key not found"). Rather than make the holder run `ykman` by hand, the
/// node fixes it: if the slot has no cert, export the slot's public key and write a
/// self-signed cert into the slot (signed by the slot key itself — may require a
/// touch). The PIN is required (the management key is PIN-protected). Returns
/// `Ok(true)` if a cert was generated, `Ok(false)` if one already existed.
#[cfg(feature = "pkcs11")]
fn ensure_slot_cert(slot: &str, pin: Option<&str>, subject: &str) -> anyhow::Result<bool> {
    use std::io::Write;

    // Already has a certificate? (export succeeds + non-empty)
    let has_cert = std::process::Command::new("ykman")
        .args(["piv", "certificates", "export", "-F", "PEM", slot, "-"])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false);
    if has_cert {
        return Ok(false);
    }

    // Writing a cert needs the PIN (the PIN-protected management key).
    let pin = pin.ok_or_else(|| {
        anyhow::anyhow!(
            "slot {slot} has a key but no certificate, and no PIN was supplied to generate one"
        )
    })?;

    // Export the slot's PUBLIC key (PEM) — the cert is self-signed over it.
    let pub_pem = run_ykman_capture(&["piv", "keys", "export", slot, "-"])
        .map_err(|e| anyhow::anyhow!("export slot {slot} public key: {e}"))?;

    // `ykman piv certificates generate [OPTS] SLOT PUBLIC_KEY` — `-` reads the
    // pubkey from stdin; `--pin` unlocks the protected management key.
    let mut child = std::process::Command::new("ykman")
        .args([
            "piv",
            "certificates",
            "generate",
            "--pin",
            pin,
            "--subject",
            subject,
            slot,
            "-",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("run `ykman certificates generate`: {e}"))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("ykman generate: no stdin handle"))?;
        stdin
            .write_all(&pub_pem)
            .map_err(|e| anyhow::anyhow!("write pubkey to ykman: {e}"))?;
    } // stdin dropped → pipe closed so ykman proceeds
    let out = child
        .wait_with_output()
        .map_err(|e| anyhow::anyhow!("wait for ykman generate: {e}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "`ykman piv certificates generate {slot}` failed (exit {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(true)
}

// ─── no-pkcs11 path: honest NotSupported ──────────────────────────────────────

#[cfg(not(feature = "pkcs11"))]
async fn provision_holder_impl(_req: ProvisionHolderRequest) -> Response {
    err(
        StatusCode::NOT_IMPLEMENTED,
        "accord-holder provisioning needs a YubiKey (PKCS#11) — this build was compiled without \
         the `pkcs11` feature. Rebuild ciris-server with `--features pkcs11` on a Linux host with \
         the token attached.",
    )
}

#[cfg(not(feature = "pkcs11"))]
async fn cosign_family_impl(_req: CosignFamilyRequest) -> Response {
    err(
        StatusCode::NOT_IMPLEMENTED,
        "accord-family genesis cosign needs a YubiKey (PKCS#11) — this build was compiled without \
         the `pkcs11` feature. Rebuild ciris-server with `--features pkcs11` on a Linux host with \
         the token attached.",
    )
}

// ─── GET /v1/accord/yubikey-status — the "is this token ready?" probe ──────────

/// `GET /v1/accord/yubikey-status` — report the inserted YubiKey's readiness for
/// accord provisioning so the ceremony UI can show a clear banner ("YUBI DETECTED —
/// FIPS COMPLIANT — 9C PROVISIONED — READY") + the PIN/PUK tries remaining. Shells
/// `ykman piv info` (read-only; no cryptoki, so it works on any build); a missing
/// token / `ykman` returns `{detected:false,…}` with a hint rather than an error.
/// Loopback-only (same guard as the other accord-setup routes).
async fn yubikey_status(State(_st): State<ProvisionState>) -> Response {
    (StatusCode::OK, Json(probe_yubikey_status())).into_response()
}

/// Run `ykman piv info` and parse it into the readiness fields the UI shows. Never
/// errors out — a missing token / `ykman` is reported as `detected:false`.
fn probe_yubikey_status() -> serde_json::Value {
    use serde_json::json;
    let out = match std::process::Command::new("ykman")
        .args(["piv", "info"])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return json!({
                "detected": false,
                "ready": false,
                "hint": format!("could not run `ykman` (is yubikey-manager installed?): {e}"),
            })
        }
    };
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return json!({
            "detected": false,
            "ready": false,
            "hint": format!("no YubiKey PIV detected: {}", stderr.trim()),
        });
    }
    let text = String::from_utf8_lossy(&out.stdout);

    let line_after = |label: &str| -> Option<String> {
        text.lines()
            .find(|l| l.trim_start().starts_with(label))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
    };
    let fips = line_after("FIPS approved:")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let pin_tries = line_after("PIN tries remaining:");
    let puk_tries = line_after("PUK tries remaining:");
    let piv_version = line_after("PIV version:");

    // The Slot 9C block: a "Private key type" line ⇒ key present; any cert line
    // (Subject/Issuer/Fingerprint/Not before/Not after) ⇒ certificate present. The
    // certificate is what ykcs11 needs to ENUMERATE the key.
    let mut in_9c = false;
    let mut key_type: Option<String> = None;
    let mut has_cert = false;
    for line in text.lines() {
        let t = line.trim_start();
        if t.starts_with("Slot 9C") || t.starts_with("Slot 9c") {
            in_9c = true;
            continue;
        }
        // Indented lines belong to the current slot; a non-indented line ends it.
        if in_9c && !line.starts_with(' ') && !line.starts_with('\t') && !t.is_empty() {
            in_9c = false;
        }
        if in_9c {
            if let Some((_, v)) = t.split_once("Private key type:") {
                key_type = Some(v.trim().to_string());
            }
            if t.starts_with("Subject")
                || t.starts_with("Issuer")
                || t.starts_with("Fingerprint")
                || t.starts_with("Not before")
                || t.starts_with("Not after")
            {
                has_cert = true;
            }
        }
    }
    let key_present = key_type.is_some();
    let is_ed25519 = key_type
        .as_deref()
        .map(|t| t.to_ascii_uppercase().contains("ED25519"))
        .unwrap_or(false);

    // CRITICAL: `ykman piv info` reads the key via libykpiv, which sees an Ed25519
    // slot key fine — but the SIGNING path goes through pkcs11 (ykcs11), and ykcs11
    // < 2.5.0 (Ubuntu 24.04 ships 2.2.0) CANNOT expose an Ed25519 PIV private key as
    // a PKCS#11 object. So a slot can look perfect to ykman yet be unusable for
    // signing. Probe pkcs11 DIRECTLY so we don't report a false "ready".
    let pkcs11_ed25519_ok: Option<bool> = if key_present && has_cert && is_ed25519 {
        probe_pkcs11_surfaces_slot9c()
    } else {
        None
    };

    // ready iff: FIPS + key + cert AND (pkcs11 confirmed surfacing, or we couldn't
    // check — never block on an unknown, but DO block on a confirmed incompatibility).
    let ready = fips && key_present && has_cert && pkcs11_ed25519_ok != Some(false);

    json!({
        "detected": true,
        "piv_version": piv_version,
        "fips_approved": fips,
        "pin_tries_remaining": pin_tries,
        "puk_tries_remaining": puk_tries,
        "slot_9c_key": key_present,
        "slot_9c_key_type": key_type,
        "slot_9c_cert": has_cert,
        // Some(true)=pkcs11 surfaces the Ed25519 signing key; Some(false)=host ykcs11
        // too old (UPGRADE needed); null=couldn't verify (pkcs11-tool absent).
        "pkcs11_ed25519_ok": pkcs11_ed25519_ok,
        "ready": ready,
        // The slot needs a CERTIFICATE for ykcs11 to enumerate the key — surface the
        // exact next step when the key is there but the cert isn't.
        "hint": if pkcs11_ed25519_ok == Some(false) {
            Some("slot 9C is perfect (Ed25519 key + cert + FIPS), but this HOST's PKCS#11 module \
                  (ykcs11/yubico-piv-tool) is too old to expose an Ed25519 key — UPGRADE to \
                  yubico-piv-tool ≥ 2.5.0 (Ubuntu 24.04 ships 2.2.0: `add-apt-repository \
                  ppa:yubico/stable && apt update && apt install ykcs11`). The YubiKey is fine.".to_string())
        } else if key_present && !has_cert {
            Some("slot 9C has a key but NO certificate — ykcs11 can't see it; generate a self-signed cert in 9C".to_string())
        } else if !key_present {
            Some("slot 9C has no key — provision an Ed25519 key in slot 9C".to_string())
        } else if !fips {
            Some("YubiKey is not FIPS-approved".to_string())
        } else {
            None
        },
    })
}

/// Best-effort: does the host's ykcs11 actually expose the slot-9c **private key**
/// as a PKCS#11 object? `ykman piv info` uses libykpiv (sees Ed25519 fine), but the
/// signing path uses ykcs11 — and ykcs11 < 2.5.0 silently omits the Ed25519 private
/// key object, yielding the cryptic "Key not found: Private key for Digital
/// Signature" at sign time. We enumerate via `pkcs11-tool -O` (no login needed for
/// object presence) and look for a Private Key Object. Returns `None` if we can't
/// check (pkcs11-tool not installed) — callers must NOT treat unknown as failure.
fn probe_pkcs11_surfaces_slot9c() -> Option<bool> {
    let module = crate::identity::DEFAULT_YKCS11_MODULE;
    let out = std::process::Command::new("pkcs11-tool")
        .args(["--module", module, "-O"])
        .output()
        .ok()?;
    // pkcs11-tool emits warnings on stderr for the Ed25519 key it can't parse; the
    // object list is on stdout. If the binary ran at all, trust the enumeration.
    if !out.status.success() && out.stdout.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // A capable ykcs11 (≥ 2.5.0) renders the slot-9c Ed25519 key as an EDWARDS key
    // ("Public Key Object; EC_EDWARDS …"); the too-old 2.2.0 cannot represent it and
    // garbles it to a nonsensical "RSA 256 bits", so EDWARDS is absent. (The private
    // key object itself is login-gated and NOT listed pre-login, so we key off the
    // public-key TYPE, which lists without login.) Caller only invokes this when the
    // slot is known to hold an Ed25519 key, so EDWARDS present ⇒ usable.
    let ed25519_representable = text.contains("EC_EDWARDS") || text.contains("EDWARDS");
    Some(ed25519_representable)
}

/// The accord-provision router — merge onto the read-API listener behind the
/// loopback guard (see `compose.rs`).
pub fn router(engine: Arc<Engine>) -> Router {
    let state = ProvisionState { engine };
    Router::new()
        .route(
            "/v1/accord/provision-holder",
            axum::routing::post(provision_holder),
        )
        .route(
            "/v1/accord/family/cosign",
            axum::routing::post(cosign_family),
        )
        .route(
            "/v1/accord/yubikey-status",
            axum::routing::get(yubikey_status),
        )
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use ciris_persist::prelude::LocalSigner;
    use ed25519_dalek::SigningKey;
    use tower::ServiceExt;

    /// Build the router over a throwaway sqlite::memory engine. The provision
    /// endpoint never reads the engine; the validation/NotSupported arms we test
    /// all return BEFORE any token open or engine use.
    async fn router_with_engine() -> Router {
        let signing_key = SigningKey::from_bytes(&[0x7E; 32]);
        let signer = Arc::new(LocalSigner::from_parts(
            signing_key,
            "accord-provision-test".to_string(),
            None,
            None,
        ));
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer (sqlite::memory:) for provision tests");
        super::router(Arc::new(engine))
    }

    #[tokio::test]
    async fn empty_key_id_is_rejected() {
        let app = router_with_engine().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/accord/provision-holder")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"key_id":"","mldsa_usb_path":"/tmp/usb"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn empty_usb_path_is_rejected() {
        let app = router_with_engine().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/accord/provision-holder")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"key_id":"accord-holder-1","mldsa_usb_path":"  "}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[cfg(not(feature = "pkcs11"))]
    #[tokio::test]
    async fn without_pkcs11_returns_not_implemented() {
        let app = router_with_engine().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/accord/provision-holder")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"key_id":"accord-holder-1","mldsa_usb_path":"/tmp"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn cosign_empty_key_id_is_rejected() {
        let app = router_with_engine().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/accord/family/cosign")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"key_id":"","mldsa_usb_path":"/tmp/usb","envelope":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn cosign_non_object_envelope_is_rejected() {
        let app = router_with_engine().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/accord/family/cosign")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"key_id":"accord-holder-1","mldsa_usb_path":"/tmp","envelope":"nope"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[cfg(not(feature = "pkcs11"))]
    #[tokio::test]
    async fn cosign_without_pkcs11_returns_not_implemented() {
        let app = router_with_engine().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/accord/family/cosign")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"key_id":"accord-holder-1","mldsa_usb_path":"/tmp","envelope":{"members":[]}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
