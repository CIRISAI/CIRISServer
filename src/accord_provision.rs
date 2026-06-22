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
#[cfg_attr(
    not(all(feature = "pkcs11", any(target_os = "linux", target_os = "windows"))),
    allow(dead_code)
)]
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
#[cfg_attr(
    not(all(feature = "pkcs11", any(target_os = "linux", target_os = "windows"))),
    allow(dead_code)
)]
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
#[cfg_attr(
    not(all(feature = "pkcs11", any(target_os = "linux", target_os = "windows"))),
    allow(dead_code)
)]
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

#[cfg(all(feature = "pkcs11", any(target_os = "linux", target_os = "windows")))]
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
    let yubikey_ed = match crate::identity::open_yubikey_ed25519_signer(opts) {
        Ok(s) => Arc::<dyn ciris_keyring::HardwareSigner>::from(s),
        Err(e) => {
            // Log server-side too (the failure was previously visible ONLY in the
            // client). The most common cause when the key IS present: ykcs11 only
            // exposes a PIV private key when the slot also holds a CERTIFICATE — a
            // key-without-cert slot enumerates nothing ("Key not found").
            tracing::warn!(
                key_id = %req.key_id,
                slot = %piv_slot,
                error = %e,
                "accord provision-holder: could NOT open the YubiKey slot key — if the key IS \
                 present (ykman piv info), the slot likely has no CERTIFICATE (ykcs11 enumerates \
                 keys by cert) and/or no CHUID; generate a self-signed cert in the slot"
            );
            return err(
                StatusCode::BAD_REQUEST,
                &format!(
                    "couldn't open your YubiKey's slot-{piv_slot} key: {e} — if `ykman piv info` \
                     shows the key, the slot is likely missing a CERTIFICATE (ykcs11 only exposes \
                     a PIV key when its slot has a cert): generate a self-signed cert in slot \
                     {piv_slot}. Otherwise check the YubiKey is inserted, FIPS-approved, and the \
                     PIN is correct."
                ),
            );
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
            Ok(d) => vec![d],
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
    //    A touch-required YubiKey BLOCKS on the wrap-key signature until tapped.
    let now = chrono::Utc::now().to_rfc3339();
    let provisioned = match crate::accord_custody::provision_portable_holder(
        yubikey_ed,
        req.key_id.trim(),
        usb_dir,
        &attestation_9c_der,
        &chain_refs,
        &now,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("provision portable holder: {e}"),
            )
        }
    };

    // 4. Return the two artifacts the holder POSTs to /v1/accord/holder.
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "key_id": req.key_id.trim(),
            "holder_record": provisioned.holder_record,
            "custody_attestation": provisioned.custody_attestation,
        })),
    )
        .into_response()
}

#[cfg(all(feature = "pkcs11", any(target_os = "linux", target_os = "windows")))]
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
#[cfg(all(feature = "pkcs11", any(target_os = "linux", target_os = "windows")))]
fn writable_probe(dir: &std::path::Path) -> std::io::Result<()> {
    let probe = dir.join(format!(".ciris-accord-write-probe-{}", std::process::id()));
    std::fs::write(&probe, b"ciris")?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// `ykman piv keys attest <slot>` → the slot's PIV attestation cert (DER).
#[cfg(all(feature = "pkcs11", any(target_os = "linux", target_os = "windows")))]
fn ykman_attest_9c(slot: &str) -> anyhow::Result<Vec<u8>> {
    // `-F DER` emits DER to stdout (the `-` output target).
    run_ykman_capture(&["piv", "keys", "attest", "-F", "DER", slot, "-"])
}

/// `ykman piv certificates export f9` → the f9 device attestation cert (DER).
#[cfg(all(feature = "pkcs11", any(target_os = "linux", target_os = "windows")))]
fn ykman_export_f9() -> anyhow::Result<Vec<u8>> {
    run_ykman_capture(&["piv", "certificates", "export", "-F", "DER", "f9", "-"])
}

/// Run `ykman <args>` capturing stdout as bytes (DER). `ykman` reads the token
/// directly; a missing binary or a non-zero exit is a plain error.
#[cfg(all(feature = "pkcs11", any(target_os = "linux", target_os = "windows")))]
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

// ─── no-pkcs11 path: honest NotSupported ──────────────────────────────────────

#[cfg(not(all(feature = "pkcs11", any(target_os = "linux", target_os = "windows"))))]
async fn provision_holder_impl(_req: ProvisionHolderRequest) -> Response {
    err(
        StatusCode::NOT_IMPLEMENTED,
        "accord-holder provisioning needs a YubiKey (PKCS#11) — this build was compiled without \
         the `pkcs11` feature. Rebuild ciris-server with `--features pkcs11` on a Linux host with \
         the token attached.",
    )
}

#[cfg(not(all(feature = "pkcs11", any(target_os = "linux", target_os = "windows"))))]
async fn cosign_family_impl(_req: CosignFamilyRequest) -> Response {
    err(
        StatusCode::NOT_IMPLEMENTED,
        "accord-family genesis cosign needs a YubiKey (PKCS#11) — this build was compiled without \
         the `pkcs11` feature. Rebuild ciris-server with `--features pkcs11` on a Linux host with \
         the token attached.",
    )
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

    #[cfg(not(all(feature = "pkcs11", any(target_os = "linux", target_os = "windows"))))]
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

    #[cfg(not(all(feature = "pkcs11", any(target_os = "linux", target_os = "windows"))))]
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
