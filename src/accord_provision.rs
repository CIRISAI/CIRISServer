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

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

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
pub(crate) struct ProvisionPkcs11 {
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
    engine: Arc<Engine>,
    /// Accord peer base URLs (`http://host:port`, self excluded) a co-scrub partial
    /// gossips to — the SAME set the accord kill-switch replicates over. Empty on a
    /// lone node (the ceremony still closes via the returned/saved partial + the paste
    /// fallback).
    peers: Vec<String>,
    /// Shared HTTP client for the best-effort peer fan-out.
    http: reqwest::Client,
    /// In-flight co-scrub partials — the display store behind `GET /pending`. DISPLAY
    /// only: the cryptographic authority is persist's m-of-n gate at `cosign`→adopt.
    /// Ephemeral (not persisted; the gossip re-floods on the next hop).
    pending: Arc<Mutex<Vec<PendingCoscrub>>>,
    /// Re-gossip loop-stop: `(target_key_id, distinct_scrub_count)` already ingested.
    seen: Arc<Mutex<HashSet<(String, usize)>>>,
}

/// The receive-side cap on in-flight co-scrub partials, so a gossip flood into the OPEN
/// `/gossip-partial` endpoint can never grow memory without bound (mirrors the accord
/// event log's `MAX_ACCORD_EVENTS`).
const MAX_PENDING_COSCRUBS: usize = 256;

/// One in-flight co-scrub partial, surfaced in the client's "Pending co-signs" list. This
/// is DISPLAY state only — the security gate is persist's m-of-n at `cosign`→
/// `adopt_scrub_upgrade`, never this store. `roster_verified` is a best-effort hint (are
/// all scrubbers on the accord family roster?), not an admission decision.
#[derive(Clone, serde::Serialize)]
struct PendingCoscrub {
    target_key_id: String,
    distinct_scrub_count: usize,
    /// The family m-of-n `M` (0 when the family/quorum can't be resolved locally).
    quorum_needed: usize,
    scrubbers: Vec<String>,
    transport_hints: Vec<serde_json::Value>,
    roster_verified: bool,
    received_at: String,
    /// The verbatim verify `SignedKeyRecord` JSON — so `cosign` submits it byte-identical
    /// (append_scrub recanonicalizes the SAME envelope; a re-encode would break the anchor).
    partial: serde_json::Value,
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

    use crate::identity::{default_ykcs11_module, Pkcs11Options, DEFAULT_PIV_SLOT};

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
            .unwrap_or_else(default_ykcs11_module),
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

    use crate::identity::{default_ykcs11_module, Pkcs11Options, DEFAULT_PIV_SLOT};

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
            .unwrap_or_else(default_ykcs11_module),
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
    let module = crate::identity::default_ykcs11_module();
    let module = module.to_string_lossy();
    let out = std::process::Command::new("pkcs11-tool")
        .args(["--module", &module, "-O"])
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

// ─── POST /v1/accord/admit-node (CIRISServer#140 / CIRISVerify#162) ────────────

/// `POST /v1/accord/admit-node` request — an accord holder scrub-signs a node's
/// registration to admit it to the trust root.
#[derive(Debug, Deserialize)]
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct AdmitNodeRequest {
    /// The accord holder's federation `key_id` (the seal alias the wrapped ML-DSA
    /// + holder record were minted under) — the SCRUBBER (e.g. A1).
    key_id: String,
    /// The holder's USB dir holding the wrapped ML-DSA-65 half. RE-OPENED.
    mldsa_usb_path: String,
    /// PKCS#11 / PIV knobs for the holder's YubiKey.
    #[serde(default)]
    pkcs11: ProvisionPkcs11,
    /// The node being admitted (e.g. `canonical-server-1`) — its full hybrid identity.
    target: AdmitTarget,
}

/// The target node's public identity — the fields a holder scrub-signs (the holder
/// never derives them; the operator supplies them from the node's self-key-record).
#[derive(Debug, Deserialize, Clone)]
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct AdmitTarget {
    key_id: String,
    pubkey_ed25519_base64: String,
    pubkey_ml_dsa_65_base64: String,
    #[serde(default = "default_admit_identity_type")]
    identity_type: String,
}
fn default_admit_identity_type() -> String {
    "node".to_string()
}

/// `POST /v1/accord/admit-node` — the accord holder (A1) admits a node to the trust
/// root by scrub-signing its registration on their own YubiKey+USB, AND emits their
/// own self-signed `steward,accord_holder` **anchor** record. Both are written as
/// the genesis **seed object** to `ceg_outbox()/accord_admit_node/{target}.json`
/// (the predictable, persist-ingestable path the operator hands to CIRISPersist
/// v12.0.2 to bake) and returned. **1-of-N bootstrap:** a single holder suffices —
/// this is a trust EXTENSION, not the 2/3 kill-switch. Loopback + `pkcs11`-gated.
async fn admit_node(State(st): State<ProvisionState>, body: axum::body::Bytes) -> Response {
    let req: AdmitNodeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    if req.key_id.trim().is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "key_id (the accord holder / scrubber) must not be empty",
        );
    }
    if req.mldsa_usb_path.trim().is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "mldsa_usb_path must not be empty — insert your USB key and choose its folder",
        );
    }
    let t = &req.target;
    if t.key_id.trim().is_empty()
        || t.pubkey_ed25519_base64.trim().is_empty()
        || t.pubkey_ml_dsa_65_base64.trim().is_empty()
    {
        return err(
            StatusCode::BAD_REQUEST,
            "target must carry key_id + both hybrid pubkeys (ed25519 + ml_dsa_65)",
        );
    }
    // Defence: the target key_id is used as a filename — reject path metacharacters.
    if t.key_id.contains(['/', '\\']) || t.key_id.contains("..") {
        return err(
            StatusCode::BAD_REQUEST,
            "target key_id contains path separators — refusing to write it",
        );
    }
    // admit-node embeds no transport hint (it's a plain trust-root admission); the
    // reachability-carrying variant is add-canonical, which passes its ip hint.
    // No roles conferred — only a canonical node gets infra:serve (CIRISServer#300).
    admit_node_impl(st.engine, req, &[], &[]).await
}

#[cfg(not(feature = "pkcs11"))]
async fn admit_node_impl(
    _engine: Arc<Engine>,
    _req: AdmitNodeRequest,
    _transport_hints: &[ciris_verify_core::federation_self_record::TransportHint],
    _roles: &[String],
) -> Response {
    err(
        StatusCode::NOT_IMPLEMENTED,
        "admit-node needs the `pkcs11` feature (the holder's YubiKey + USB-wrapped ML-DSA signer)",
    )
}

/// Re-open a portable accord-holder's hardware identity: the YubiKey Ed25519
/// (slot-9c) + the USB-wrapped ML-DSA-65, as a `HardwareRootedIdentity` (a verify
/// `SelfSigner`). The single custody path shared by admit-node, add-canonical, and
/// the co-scrub propose/cosign — the touch-required tap on the first `sign_bound`
/// IS the holder's consent. Returns `(status, message)` on any open failure.
#[cfg(feature = "pkcs11")]
pub(crate) async fn open_holder_identity(
    key_id: &str,
    usb_path: &str,
    pkcs11: &ProvisionPkcs11,
) -> Result<ciris_verify_core::self_at_login::HardwareRootedIdentity, (StatusCode, String)> {
    use std::path::PathBuf;
    use std::sync::Arc;

    use ciris_keyring::usb_wrapped_mldsa65::UsbWrappedMlDsa65Signer;
    use ciris_keyring::PqcSigner;
    use ciris_verify_core::self_at_login::HardwareRootedIdentity;

    use crate::identity::{default_ykcs11_module, Pkcs11Options, DEFAULT_PIV_SLOT};

    let usb_dir = PathBuf::from(usb_path);
    if !usb_dir.is_dir() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "the ML-DSA USB path is not a directory: {} — insert the SAME USB key you \
                 provisioned this holder with",
                usb_dir.display()
            ),
        ));
    }
    let piv_slot = pkcs11
        .piv_slot
        .clone()
        .unwrap_or_else(|| DEFAULT_PIV_SLOT.to_string());
    let opts = Pkcs11Options {
        module_path: pkcs11
            .module_path
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(default_ykcs11_module),
        user_pin: pkcs11.user_pin.clone(),
        piv_slot: piv_slot.clone(),
        provision: false,
        ..Pkcs11Options::default()
    };
    let yubikey_ed = match crate::identity::open_yubikey_ed25519_signer(opts) {
        Ok(s) => Arc::<dyn ciris_keyring::HardwareSigner>::from(s),
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "couldn't open your YubiKey's slot-{piv_slot} key: {e} — is the YubiKey \
                     inserted and the PIN correct?"
                ),
            ))
        }
    };
    let mldsa =
        match UsbWrappedMlDsa65Signer::open(yubikey_ed.as_ref(), key_id, usb_dir.clone()).await {
            Ok(m) => m,
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!(
                    "couldn't re-open the USB-wrapped ML-DSA key for '{key_id}' at {}: {e} — is \
                     this the SAME USB + YubiKey pair you provisioned this holder with?",
                    usb_dir.display()
                ),
                ))
            }
        };
    HardwareRootedIdentity::new(
        key_id.to_string(),
        yubikey_ed.clone(),
        Arc::new(mldsa) as Arc<dyn PqcSigner>,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("build hardware-rooted identity: {e}"),
        )
    })
}

#[cfg(feature = "pkcs11")]
async fn admit_node_impl(
    engine: Arc<Engine>,
    req: AdmitNodeRequest,
    transport_hints: &[ciris_verify_core::federation_self_record::TransportHint],
    // Roles to confer INSIDE the scrub-signed envelope (accord-attested, not
    // self-claimed). Empty for a plain admit-node; add-canonical passes
    // [infra:serve] so the canonical KeyRecord carries the accord-blessed
    // "serve as infrastructure" capability — trusted-by-default as a trace
    // recipient, the role edge's #379 gate is fail-closed on (CIRISServer#300).
    roles: &[String],
) -> Response {
    use ciris_verify_core::federation_self_record::{
        produce_scrubbed_key_record, produce_self_key_record, ScrubTarget,
    };

    let key_id = req.key_id.trim().to_string();
    let identity = match open_holder_identity(&key_id, req.mldsa_usb_path.trim(), &req.pkcs11).await
    {
        Ok(i) => i,
        Err((code, msg)) => return err(code, &msg),
    };

    let valid_from = chrono::Utc::now().to_rfc3339();

    // (1) The holder's OWN self-signed `steward,accord_holder` anchor record — the
    //     rooting terminus persist bakes (its ed25519 pubkey IS a pinned anchor).
    let anchor =
        match produce_self_key_record(&identity, "steward,accord_holder", &valid_from, &[]).await {
            Ok(r) => r,
            Err(e) => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("produce the holder's self-signed anchor record: {e}"),
                )
            }
        };
    // (2) The TARGET node, scrub-signed by the holder (scrub_key_id = this holder)
    //     so `node → holder` chains to the anchor and roots.
    let scrubbed = match produce_scrubbed_key_record(
        &identity,
        ScrubTarget {
            key_id: req.target.key_id.trim().to_string(),
            pubkey_ed25519_base64: req.target.pubkey_ed25519_base64.trim().to_string(),
            pubkey_ml_dsa_65_base64: req.target.pubkey_ml_dsa_65_base64.trim().to_string(),
            identity_type: req.target.identity_type.trim().to_string(),
            roles: roles.to_vec(),
        },
        &valid_from,
        // #172: transport hints ride INSIDE this scrub-signed envelope, so the accord
        // holder attests the node's reachability along with its identity (empty for a
        // plain admit-node; the add-canonical ceremony passes the node's ip hint).
        transport_hints,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("scrub-sign the target node's registration: {e}"),
            )
        }
    };

    // The genesis seed object persist v12.0.2 bakes: the holder anchor + the
    // scrubbed node, both signed by the holder on hardware.
    let seed = serde_json::json!({
        "holder_anchor": anchor,
        "scrubbed_node": scrubbed,
        "scrubber_key_id": key_id,
        "target_key_id": req.target.key_id.trim(),
        "produced_at": valid_from,
    });

    // Write to the predictable, persist-ingestable outbox path (same convention as
    // provision-holder + genesis-assemble: `$CIRIS_HOME/ceg/outbox/...`).
    let dir = ciris_verify_core::ceg_outbox::ceg_outbox().join("accord_admit_node");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("create outbox dir {}: {e}", dir.display()),
        );
    }
    let out_path = dir.join(format!("{}.json", req.target.key_id.trim()));
    let seed_pretty = match serde_json::to_string_pretty(&seed) {
        Ok(s) => s,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("serialize seed object: {e}"),
            )
        }
    };
    if let Err(e) = std::fs::write(&out_path, &seed_pretty) {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("write seed to {}: {e}", out_path.display()),
        );
    }

    // #150 — PRODUCER: adopt the scrubbed record onto this node's OWN directory row
    // (persist v12.2.0 `Engine::adopt_scrub_upgrade`, CIRISPersist#351). When the
    // target IS this node, its boot-time self-signed own-key row is upgraded to the
    // accord-holder-scrubbed record, so the Key plane (edge publish-own) advertises
    // an ANCHORED, rootable record and consent peers root it. The primitive is
    // self-gating (verifies the scrub sig + only upgrades a self-signed → scrubbed
    // row for the SAME key_id/pubkey), so we call it unconditionally: a target whose
    // row isn't a valid local upgrade returns Err and we report it without failing
    // the outbox write (the JSON is still the transport for a remote target / bake).
    let applied: serde_json::Value = match serde_json::to_value(&scrubbed)
        .and_then(serde_json::from_value::<ciris_persist::federation::SignedKeyRecord>)
    {
        Ok(persist_rec) => match engine.adopt_scrub_upgrade(persist_rec).await {
            Ok(outcome) => {
                tracing::info!(
                    target_key_id = %req.target.key_id.trim(),
                    ?outcome,
                    "admit-node: adopted the scrubbed record onto the local directory row"
                );
                serde_json::json!({ "adopted": true, "outcome": format!("{outcome:?}") })
            }
            Err(e) => {
                tracing::warn!(
                    target_key_id = %req.target.key_id.trim(),
                    error = %e,
                    "admit-node: scrubbed record NOT adopted locally (not this node's own \
                     self-signed row?) — seed JSON saved for transport/bake"
                );
                serde_json::json!({ "adopted": false, "reason": e.to_string() })
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "admit-node: scrubbed record convert for local adoption");
            serde_json::json!({ "adopted": false, "reason": format!("record convert: {e}") })
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "saved_to": out_path.display().to_string(),
            "applied": applied,
            "seed": seed,
        })),
    )
        .into_response()
}

// ─── POST /v1/accord/canonical/add — the mesh-SEED op (CIRISServer#164) ────────

/// Force the `canonical` founding-server role into an `identity_type` **set**
/// string (persist stores the set comma-joined, sorted, de-duped). Setting it
/// here is safe: persist's `check_canonical_role_admission` gate CONFERS the role
/// only when the record is accord-holder-scrubbed (`scrub_key_id` ∈ the
/// `HUMANITY_ACCORD` anchor) — a non-anchor scrub is REJECTED at adopt
/// (`CanonicalRoleNotAccordConferred`), never silently accepted. So the trust root
/// is what makes a server canonical; this just names the intent.
fn ensure_canonical_role(existing: &str) -> String {
    use ciris_persist::federation::types::identity_type;
    let mut parts: Vec<&str> = existing
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    parts.push(identity_type::CANONICAL);
    identity_type::join_set(parts)
}

/// `POST /v1/accord/canonical/add` request — an accord holder (A1) admits a node
/// to the trust root **as a canonical / founding bootstrap server**. Same
/// hardware-scrub shape as admit-node (the holder's YubiKey + USB ML-DSA), plus an
/// optional Option-A transport binding published in the same op.
#[derive(Debug, Deserialize)]
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct AddCanonicalRequest {
    #[serde(flatten)]
    admit: AdmitNodeRequest,
    /// Optional initial transport binding (CC 3.3.6.2, the Option-A address). If
    /// both are present the canonical server's `transport_destination` is bound in
    /// the same op — the "publish the address" leg of the seed.
    #[serde(default)]
    transport_kind: Option<String>,
    #[serde(default)]
    destination: Option<String>,
}

/// `POST /v1/accord/canonical/add` — the **mesh-seed op**. A single accord holder
/// (1-of-N; the additive/operational class) scrub-signs the target with the
/// `canonical` role, the scrubbed record is adopted onto its own directory row
/// (the persist canonical gate confers the role iff the scrub is accord-anchored),
/// and — if supplied — its transport address is published. Composes: root + mark
/// canonical + publish address. Loopback + `pkcs11`-gated (the hardware scrub).
///
/// Scaling to m-of-n: the 1-of-N here is the single hardware scrub + the
/// accord-conferred gate; a future co-scrub (the genesis-ceremony 2/3 cosign path)
/// widens it. The *destructive* canonical ops (supersede/withdraw) are m-of-n via
/// the family's entrenched quorum (see `accord::canonical_op_quorum_m`).
async fn add_canonical(State(st): State<ProvisionState>, body: axum::body::Bytes) -> Response {
    let req: AddCanonicalRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    if req.admit.key_id.trim().is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "key_id (the accord holder / scrubber) must not be empty",
        );
    }
    if req.admit.mldsa_usb_path.trim().is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "mldsa_usb_path must not be empty — insert your USB key and choose its folder",
        );
    }
    let t = &req.admit.target;
    if t.key_id.trim().is_empty()
        || t.pubkey_ed25519_base64.trim().is_empty()
        || t.pubkey_ml_dsa_65_base64.trim().is_empty()
    {
        return err(
            StatusCode::BAD_REQUEST,
            "target must carry key_id + both hybrid pubkeys (ed25519 + ml_dsa_65)",
        );
    }
    if t.key_id.contains(['/', '\\']) || t.key_id.contains("..") {
        return err(
            StatusCode::BAD_REQUEST,
            "target key_id contains path separators — refusing to write it",
        );
    }
    add_canonical_impl(st.engine, req).await
}

#[cfg(not(feature = "pkcs11"))]
async fn add_canonical_impl(_engine: Arc<Engine>, _req: AddCanonicalRequest) -> Response {
    err(
        StatusCode::NOT_IMPLEMENTED,
        "add-canonical needs the `pkcs11` feature (the holder's YubiKey + USB-wrapped ML-DSA signer)",
    )
}

#[cfg(feature = "pkcs11")]
async fn add_canonical_impl(engine: Arc<Engine>, mut req: AddCanonicalRequest) -> Response {
    use ciris_verify_core::federation_self_record::TransportHint;
    // Force the `canonical` role — the persist gate confers it iff anchor-scrubbed.
    req.admit.target.identity_type = ensure_canonical_role(&req.admit.target.identity_type);
    let target_key_id = req.admit.target.key_id.trim().to_string();

    // The transport hint rides INSIDE the scrub-signed envelope (CIRISVerify#172 /
    // CIRISPersist#381), so the accord holder attests the node's reachability along
    // with its identity in ONE signature — a baked/replicated canonical record is then
    // self-describing (who + where) and can't be spoofed post-hoc. `kind=ip` is the
    // internet-dialable TCP bootstrap entry; a `reticulum` dest is pubkey-derivable
    // overlay and optional. (Runtime address moves still flow through the separate
    // update-address op + transport_destination overlay — this is the genesis default.)
    let hints: Vec<TransportHint> =
        match (req.transport_kind.as_deref(), req.destination.as_deref()) {
            (Some(k), Some(d)) if !k.trim().is_empty() && !d.trim().is_empty() => {
                vec![TransportHint {
                    kind: k.trim().to_string(),
                    destination: d.trim().to_string(),
                }]
            }
            _ => Vec::new(),
        };

    // (1) Hardware scrub (embedding the hint) + adopt via the shipped admit-node path.
    //     adopt_scrub_upgrade runs check_canonical_role_admission, so a non-anchor
    //     scrubber is rejected there (the role never lands). Surface non-200 verbatim.
    // add-canonical confers `infra:serve` in the scrub-signed envelope — the
    // accord-blessed "serve as infrastructure" capability (CC 4.4.3.4.3). A node
    // the trust root blesses with infra:serve is TRUSTED-BY-DEFAULT as a trace
    // recipient; edge's #379 serve gate is fail-closed on it. Withdrawing the role
    // (the canonical withdraw op) un-trusts the node. TRUST (this role) + CONSENT
    // (the self→community promotion) are jointly what make traces flow.
    let resp = admit_node_impl(
        engine.clone(),
        req.admit,
        &hints,
        &[ciris_persist::federation::types::delegation_scope::INFRA_SERVE.to_string()],
    )
    .await;
    if resp.status() != StatusCode::OK {
        return resp;
    }

    // (2) Confirm the role took on the local row (adopt succeeded + gate admitted).
    //     `false` for a remote target (its scrubbed record rides the seed JSON to be
    //     adopted on the node itself) — not an error, just not locally confirmable.
    let is_canonical = engine.is_canonical(&target_key_id).await.unwrap_or(false);

    let seed_path = ciris_verify_core::ceg_outbox::ceg_outbox()
        .join("accord_admit_node")
        .join(format!("{target_key_id}.json"));
    tracing::info!(
        canonical_key_id = %target_key_id,
        is_canonical,
        transport_hints = hints.len(),
        "Trust Root: add-canonical — node admitted to the canonical set (accord-conferred; hint in envelope)"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "canonical_key_id": target_key_id,
            "is_canonical": is_canonical,
            // The hint(s) now embedded in the signed envelope (the bake artifact).
            "address": serde_json::to_value(&hints).unwrap_or(serde_json::Value::Null),
            "seed_saved_to": seed_path.display().to_string(),
        })),
    )
        .into_response()
}

// ─── Cross-device m-of-n co-scrub (CIRISPersist#383) ──────────────────────────
//
// persist v13.2.0 makes canonical admission m-of-n (the family's entrenched
// `quorum:M/N`, via verify's `verify_quorum_policy`), so a single scrub no longer
// confers `canonical`. A canonical record now accumulates ≥M *distinct* anchor
// scrubs — across DEVICES: A1 proposes on one box, the partial travels (accord
// gossip, or the saved JSON), B1 cosigns on another. The scrub set lives in the
// record itself (verify's `additional_scrubs`), so a completed record proves its
// own m-of-n. All crypto is verify's: `produce_scrubbed_key_record` (scrub #1) and
// `append_scrub` (each subsequent, over the byte-identical envelope; rejects a
// duplicate `scrub_key_id`). Admission is persist's gate. The server adds no math.

/// `POST /v1/accord/canonical/propose` — the FIRST scrub of a co-scrub. An accord
/// holder (A1) scrub-signs the target with the `canonical` role + transport hint;
/// the resulting 1-scrub **partial** does NOT yet confer canonical (m-of-n). It is
/// returned + saved to the outbox — hand it to the next holder (it gossips as accord
/// traffic, or transfer the JSON) to `cosign`.
async fn propose_canonical(State(st): State<ProvisionState>, body: axum::body::Bytes) -> Response {
    let req: AddCanonicalRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    let t = &req.admit.target;
    if req.admit.key_id.trim().is_empty()
        || req.admit.mldsa_usb_path.trim().is_empty()
        || t.key_id.trim().is_empty()
        || t.pubkey_ed25519_base64.trim().is_empty()
        || t.pubkey_ml_dsa_65_base64.trim().is_empty()
    {
        return err(
            StatusCode::BAD_REQUEST,
            "propose requires the holder key_id + USB path and the target key_id + both hybrid pubkeys",
        );
    }
    if t.key_id.contains(['/', '\\']) || t.key_id.contains("..") {
        return err(
            StatusCode::BAD_REQUEST,
            "target key_id contains path separators",
        );
    }
    propose_canonical_impl(st, req).await
}

#[cfg(not(feature = "pkcs11"))]
async fn propose_canonical_impl(_st: ProvisionState, _req: AddCanonicalRequest) -> Response {
    err(
        StatusCode::NOT_IMPLEMENTED,
        "propose needs the `pkcs11` feature (the holder's YubiKey + USB-wrapped ML-DSA signer)",
    )
}

#[cfg(feature = "pkcs11")]
async fn propose_canonical_impl(st: ProvisionState, mut req: AddCanonicalRequest) -> Response {
    use ciris_verify_core::federation_self_record::{
        produce_scrubbed_key_record, ScrubTarget, TransportHint,
    };
    req.admit.target.identity_type = ensure_canonical_role(&req.admit.target.identity_type);
    let target_key_id = req.admit.target.key_id.trim().to_string();
    let hints: Vec<TransportHint> =
        match (req.transport_kind.as_deref(), req.destination.as_deref()) {
            (Some(k), Some(d)) if !k.trim().is_empty() && !d.trim().is_empty() => {
                vec![TransportHint {
                    kind: k.trim().to_string(),
                    destination: d.trim().to_string(),
                }]
            }
            _ => Vec::new(),
        };
    let identity = match open_holder_identity(
        req.admit.key_id.trim(),
        req.admit.mldsa_usb_path.trim(),
        &req.admit.pkcs11,
    )
    .await
    {
        Ok(i) => i,
        Err((code, msg)) => return err(code, &msg),
    };
    let valid_from = chrono::Utc::now().to_rfc3339();
    let partial = match produce_scrubbed_key_record(
        &identity,
        ScrubTarget {
            key_id: target_key_id.clone(),
            pubkey_ed25519_base64: req.admit.target.pubkey_ed25519_base64.trim().to_string(),
            pubkey_ml_dsa_65_base64: req.admit.target.pubkey_ml_dsa_65_base64.trim().to_string(),
            identity_type: req.admit.target.identity_type.clone(),
            // Confer `infra:serve` (CC 4.4.3.4.3 — "serve as infrastructure") INSIDE
            // this scrub-signed envelope so the accord co-scrub (m-of-n) attests the
            // role rather than the node self-claiming it (CIRISPersist#441). A node
            // the trust root blesses with infra:serve is trusted-by-default as a
            // trace recipient — the fail-closed gate (CIRISEdge#379 / CIRISServer#300)
            // that, together with the peer's consent, decides whether traces arrive.
            roles: vec![
                ciris_persist::federation::types::delegation_scope::INFRA_SERVE.to_string(),
            ],
        },
        &valid_from,
        &hints,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("scrub: {e}")),
    };
    let count = partial.record.distinct_scrub_count();
    let saved_to = save_coscrub_partial(&target_key_id, &partial);
    // Ingest into this node's display store + gossip to accord peers so the NEXT holder's
    // box surfaces the partial in "Pending co-signs" without a manual transfer.
    let partial_json = serde_json::to_value(&partial).unwrap_or(serde_json::Value::Null);
    let gossiped = ingest_partial(&st, partial_json)
        .await
        .map(|(_, _, g, _)| g)
        .unwrap_or(0);
    tracing::info!(
        canonical_key_id = %target_key_id,
        distinct_scrubs = count,
        gossiped_to = gossiped,
        "Trust Root: co-scrub proposed (scrub #1) — gossiped to peers; the next holder cosigns"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "target_key_id": target_key_id,
            "distinct_scrub_count": count,
            "partial": partial,
            "saved_to": saved_to,
            "gossiped_to": gossiped,
            "note": "1 scrub — not yet canonical. It has gossiped to accord peers; the next holder cosigns from their 'Pending co-signs' (or paste the partial).",
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct CosignCanonicalRequest {
    /// The cosigning accord holder (e.g. B1) — the seal alias its YubiKey+USB opens.
    key_id: String,
    mldsa_usb_path: String,
    #[serde(default)]
    pkcs11: ProvisionPkcs11,
    /// The partial (verify `SignedKeyRecord`) from `propose` or a prior `cosign`.
    partial: serde_json::Value,
}

/// `POST /v1/accord/canonical/cosign` — append THIS holder's scrub to a partial over
/// the byte-identical envelope (verify's `append_scrub` — rejects a duplicate anchor),
/// then try to adopt: persist's gate confers `canonical` iff the distinct-scrub set now
/// meets the family's m-of-n. If not yet, the advanced partial is returned for the next
/// cosign; if the target is a remote node, the completed record is the bake/relay artifact.
async fn cosign_canonical(State(st): State<ProvisionState>, body: axum::body::Bytes) -> Response {
    let req: CosignCanonicalRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    if req.key_id.trim().is_empty() || req.mldsa_usb_path.trim().is_empty() || req.partial.is_null()
    {
        return err(
            StatusCode::BAD_REQUEST,
            "cosign requires the holder key_id + USB path and the partial record",
        );
    }
    cosign_canonical_impl(st, req).await
}

#[cfg(not(feature = "pkcs11"))]
async fn cosign_canonical_impl(_st: ProvisionState, _req: CosignCanonicalRequest) -> Response {
    err(
        StatusCode::NOT_IMPLEMENTED,
        "cosign needs the `pkcs11` feature (the holder's YubiKey + USB-wrapped ML-DSA signer)",
    )
}

#[cfg(feature = "pkcs11")]
async fn cosign_canonical_impl(st: ProvisionState, req: CosignCanonicalRequest) -> Response {
    use ciris_verify_core::federation_self_record::{
        append_scrub, SignedKeyRecord as VSignedKeyRecord,
    };
    let partial: VSignedKeyRecord = match serde_json::from_value(req.partial) {
        Ok(p) => p,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                &format!("partial is not a SignedKeyRecord: {e}"),
            )
        }
    };
    let target_key_id = partial.record.key_id.clone();
    let identity =
        match open_holder_identity(req.key_id.trim(), req.mldsa_usb_path.trim(), &req.pkcs11).await
        {
            Ok(i) => i,
            Err((code, msg)) => return err(code, &msg),
        };
    // append_scrub recanonicalizes the EXISTING envelope + rejects a duplicate anchor.
    let advanced = match append_scrub(partial, &identity).await {
        Ok(r) => r,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                &format!(
                    "append scrub failed (already signed by this holder, or a signer fault): {e}"
                ),
            )
        }
    };
    let count = advanced.record.distinct_scrub_count();
    let saved_to = save_coscrub_partial(&target_key_id, &advanced);

    // Try to adopt — persist's m-of-n gate is the authority (verify_quorum_policy). A
    // sub-quorum set is REJECTED (still a partial); a remote target may fail for a
    // different reason (it's not this node's own row) but the record is still the
    // completed artifact to bake/relay.
    let (conferred, outcome) = match serde_json::to_value(&advanced)
        .ok()
        .and_then(|v| serde_json::from_value::<ciris_persist::federation::SignedKeyRecord>(v).ok())
    {
        Some(pr) => match st.engine.adopt_scrub_upgrade(pr).await {
            Ok(o) => (true, format!("{o:?}")),
            Err(e) => (false, e.to_string()),
        },
        None => (false, "record convert failed".to_string()),
    };
    // Converge every holder's view: ingest + gossip the advanced record (it floods the
    // mesh, loop-stopped by (target, count); the list filters out ≥-quorum records). On a
    // local confer, drop this node's pending entry — the ceremony for this target is done.
    let advanced_json = serde_json::to_value(&advanced).unwrap_or(serde_json::Value::Null);
    let gossiped = ingest_partial(&st, advanced_json)
        .await
        .map(|(_, _, g, _)| g)
        .unwrap_or(0);
    if conferred {
        clear_pending(&st, &target_key_id);
    }
    tracing::info!(
        canonical_key_id = %target_key_id,
        distinct_scrubs = count,
        conferred,
        gossiped_to = gossiped,
        "Trust Root: co-scrub cosigned (scrub appended)"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "target_key_id": target_key_id,
            "distinct_scrub_count": count,
            "conferred": conferred,
            "outcome": outcome,
            "advanced": advanced,
            "saved_to": saved_to,
            "gossiped_to": gossiped,
        })),
    )
        .into_response()
}

// ─── CI-key co-scrub (CIRISServer#290) ────────────────────────────────────────
//
// A CI build-signing pipeline key is blessed by the SAME m-of-n accord co-scrub
// as a canonical server (CIRISVerify#185), but carries `roles:["infra:attest"]`
// (NOT canonical / infra:serve) and keeps `identity_type="node"` — it is not a
// canonical, just an infrastructure attester whose hybrid signature verifies build
// manifests. The client blesses ALL substrate repos' pipeline keys in ONE ceremony
// (a BATCH of targets), so a single YubiKey session covers the whole fleet. The
// handlers mirror propose_canonical / cosign_canonical exactly; only the roles, the
// absent canonical-forcing + transport hint, and the batch shape differ.

#[derive(Debug, Deserialize)]
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct CiKeyTarget {
    key_id: String,
    pubkey_ed25519_base64: String,
    pubkey_ml_dsa_65_base64: String,
    #[serde(default = "ci_key_default_identity_type")]
    identity_type: String,
}

#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
fn ci_key_default_identity_type() -> String {
    ciris_persist::federation::types::identity_type::NODE.to_string()
}

#[derive(Debug, Deserialize)]
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct ProposeCiKeyRequest {
    /// The proposing accord holder (A1) — the seal alias its YubiKey+USB opens.
    key_id: String,
    mldsa_usb_path: String,
    #[serde(default)]
    pkcs11: ProvisionPkcs11,
    /// The CI pipeline keys to bless — all in ONE co-scrub (the whole substrate fleet).
    targets: Vec<CiKeyTarget>,
}

/// `POST /v1/accord/ci-key/propose` — the FIRST scrub of a BATCH CI-key co-scrub.
/// Each target is scrub-signed with `roles:["infra:attest"]` (identity_type stays
/// `node` — NOT canonical); the 1-scrub partials do not yet confer (m-of-n). Returns
/// one partial per target — hand them to the next holder (they gossip, or transfer the
/// JSON) to `cosign`. CIRISServer#290 / CIRISVerify#185.
async fn propose_ci_key(State(st): State<ProvisionState>, body: axum::body::Bytes) -> Response {
    let req: ProposeCiKeyRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    if req.key_id.trim().is_empty() || req.mldsa_usb_path.trim().is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "propose requires the holder key_id + USB path",
        );
    }
    if req.targets.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "propose requires at least one target CI key",
        );
    }
    for t in &req.targets {
        if t.key_id.trim().is_empty()
            || t.pubkey_ed25519_base64.trim().is_empty()
            || t.pubkey_ml_dsa_65_base64.trim().is_empty()
        {
            return err(
                StatusCode::BAD_REQUEST,
                "each target needs key_id + both hybrid pubkeys",
            );
        }
        if t.key_id.contains(['/', '\\']) || t.key_id.contains("..") {
            return err(
                StatusCode::BAD_REQUEST,
                "a target key_id contains path separators",
            );
        }
    }
    propose_ci_key_impl(st, req).await
}

#[cfg(not(feature = "pkcs11"))]
async fn propose_ci_key_impl(_st: ProvisionState, _req: ProposeCiKeyRequest) -> Response {
    err(
        StatusCode::NOT_IMPLEMENTED,
        "ci-key propose needs the `pkcs11` feature (the holder's YubiKey + USB ML-DSA signer)",
    )
}

#[cfg(feature = "pkcs11")]
async fn propose_ci_key_impl(st: ProvisionState, req: ProposeCiKeyRequest) -> Response {
    use ciris_verify_core::federation_self_record::{produce_scrubbed_key_record, ScrubTarget};
    // Open the holder's YubiKey+USB session ONCE for the whole batch.
    let identity =
        match open_holder_identity(req.key_id.trim(), req.mldsa_usb_path.trim(), &req.pkcs11).await
        {
            Ok(i) => i,
            Err((code, msg)) => return err(code, &msg),
        };
    let valid_from = chrono::Utc::now().to_rfc3339();
    let mut results = Vec::with_capacity(req.targets.len());
    for t in &req.targets {
        let target_key_id = t.key_id.trim().to_string();
        let partial = match produce_scrubbed_key_record(
            &identity,
            ScrubTarget {
                key_id: target_key_id.clone(),
                pubkey_ed25519_base64: t.pubkey_ed25519_base64.trim().to_string(),
                pubkey_ml_dsa_65_base64: t.pubkey_ml_dsa_65_base64.trim().to_string(),
                identity_type: t.identity_type.trim().to_string(),
                // A CI pipeline key is an infrastructure attester — infra:attest,
                // NOT canonical/infra:serve. Its hybrid signature verifies build
                // manifests (CIRISVerify#185). No transport hint — it doesn't serve.
                roles: vec![
                    ciris_persist::federation::types::delegation_scope::INFRA_ATTEST.to_string(),
                ],
            },
            &valid_from,
            &[],
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("scrub {target_key_id}: {e}"),
                )
            }
        };
        let count = partial.record.distinct_scrub_count();
        let saved_to = save_coscrub_partial(&target_key_id, &partial);
        let partial_json = serde_json::to_value(&partial).unwrap_or(serde_json::Value::Null);
        let gossiped = ingest_partial(&st, partial_json)
            .await
            .map(|(_, _, g, _)| g)
            .unwrap_or(0);
        results.push(serde_json::json!({
            "target_key_id": target_key_id,
            "distinct_scrub_count": count,
            "partial": partial,
            "saved_to": saved_to,
            "gossiped_to": gossiped,
        }));
    }
    tracing::info!(
        blessed = results.len(),
        "Trust Root: CI-key BATCH co-scrub proposed (scrub #1) — the next holder cosigns"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "results": results,
            "note": "1 scrub each — not yet blessed. They gossiped to accord peers; the next holder cosigns.",
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct CosignCiKeyRequest {
    /// The cosigning accord holder (e.g. B1).
    key_id: String,
    mldsa_usb_path: String,
    #[serde(default)]
    pkcs11: ProvisionPkcs11,
    /// The partials (verify `SignedKeyRecord`s) from `propose` or a prior `cosign`.
    partials: Vec<serde_json::Value>,
}

/// `POST /v1/accord/ci-key/cosign` — append THIS holder's scrub to each partial in the
/// batch (over the byte-identical envelope, roles preserved); persist's gate confers
/// each key at family m-of-n. Returns one advanced record per input. CIRISServer#290.
async fn cosign_ci_key(State(st): State<ProvisionState>, body: axum::body::Bytes) -> Response {
    let req: CosignCiKeyRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    if req.key_id.trim().is_empty() || req.mldsa_usb_path.trim().is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "cosign requires the holder key_id + USB path",
        );
    }
    if req.partials.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "cosign requires at least one partial",
        );
    }
    cosign_ci_key_impl(st, req).await
}

#[cfg(not(feature = "pkcs11"))]
async fn cosign_ci_key_impl(_st: ProvisionState, _req: CosignCiKeyRequest) -> Response {
    err(
        StatusCode::NOT_IMPLEMENTED,
        "ci-key cosign needs the `pkcs11` feature (the holder's YubiKey + USB ML-DSA signer)",
    )
}

#[cfg(feature = "pkcs11")]
async fn cosign_ci_key_impl(st: ProvisionState, req: CosignCiKeyRequest) -> Response {
    use ciris_verify_core::federation_self_record::{
        append_scrub, SignedKeyRecord as VSignedKeyRecord,
    };
    let identity =
        match open_holder_identity(req.key_id.trim(), req.mldsa_usb_path.trim(), &req.pkcs11).await
        {
            Ok(i) => i,
            Err((code, msg)) => return err(code, &msg),
        };
    let mut results = Vec::with_capacity(req.partials.len());
    for p in req.partials {
        let partial: VSignedKeyRecord = match serde_json::from_value(p) {
            Ok(x) => x,
            Err(e) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    &format!("a partial is not a SignedKeyRecord: {e}"),
                )
            }
        };
        let target_key_id = partial.record.key_id.clone();
        let advanced = match append_scrub(partial, &identity).await {
            Ok(r) => r,
            Err(e) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    &format!("append scrub {target_key_id} (already signed by this holder?): {e}"),
                )
            }
        };
        let count = advanced.record.distinct_scrub_count();
        let saved_to = save_coscrub_partial(&target_key_id, &advanced);
        let (conferred, outcome) = match serde_json::to_value(&advanced).ok().and_then(|v| {
            serde_json::from_value::<ciris_persist::federation::SignedKeyRecord>(v).ok()
        }) {
            Some(pr) => match st.engine.adopt_scrub_upgrade(pr).await {
                Ok(o) => (true, format!("{o:?}")),
                Err(e) => (false, e.to_string()),
            },
            None => (false, "record convert failed".to_string()),
        };
        let advanced_json = serde_json::to_value(&advanced).unwrap_or(serde_json::Value::Null);
        let gossiped = ingest_partial(&st, advanced_json)
            .await
            .map(|(_, _, g, _)| g)
            .unwrap_or(0);
        if conferred {
            clear_pending(&st, &target_key_id);
        }
        results.push(serde_json::json!({
            "target_key_id": target_key_id,
            "distinct_scrub_count": count,
            "conferred": conferred,
            "outcome": outcome,
            "advanced": advanced,
            "saved_to": saved_to,
            "gossiped_to": gossiped,
        }));
    }
    tracing::info!(count = results.len(), "Trust Root: CI-key BATCH cosigned");
    (
        StatusCode::OK,
        Json(serde_json::json!({ "results": results })),
    )
        .into_response()
}

/// Persist a co-scrub partial/complete record to the predictable outbox (the artifact
/// that gossips as accord traffic OR transfers device-to-device for the next cosign /
/// the persist bake). Best-effort — a write failure is logged, not fatal.
fn save_coscrub_partial<T: serde::Serialize>(target_key_id: &str, record: &T) -> String {
    let dir = ciris_verify_core::ceg_outbox::ceg_outbox().join("canonical_coscrub");
    let path = dir.join(format!("{target_key_id}.json"));
    let _ = std::fs::create_dir_all(&dir);
    match serde_json::to_string_pretty(record) {
        Ok(s) => {
            if let Err(e) = std::fs::write(&path, s) {
                tracing::warn!(path = %path.display(), error = %e, "co-scrub: partial not saved");
            }
        }
        Err(e) => tracing::warn!(error = %e, "co-scrub: partial serialize failed"),
    }
    path.display().to_string()
}

// ─── Co-scrub gossip + the "Pending co-signs" display store ───────────────────
//
// The partial produced by `propose`/`cosign` is (a) saved to the outbox, (b) ingested
// into THIS node's display store, and (c) gossiped to accord peers over the SAME HTTP
// peer set the kill-switch uses. A peer receives it at the OPEN `/gossip-partial`
// endpoint, stores it, and re-gossips (loop-stopped) so the partial floods the mesh —
// which is how B1's box surfaces A1's proposal in "Pending co-signs" without a manual
// transfer. All of this is DISPLAY/transport plumbing; the crypto stays in verify
// (`append_scrub`) and the admission gate stays in persist (`adopt_scrub_upgrade`).

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// The accord family's live m-of-n `M`, read from the entrenched persist family row
/// (persist v13.3.0 seeds it at boot on every node — CIRISPersist#386). `0` when the
/// family/quorum isn't resolvable. (The 0.5.83 baked-genesis fallback is retired.)
async fn family_quorum_m(engine: &Engine) -> usize {
    use ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
    use ciris_verify_core::threshold::QuorumPolicy;
    match crate::family::lookup(engine, HUMANITY_ACCORD_FAMILY_KEY_ID).await {
        Ok(Some(fam)) => QuorumPolicy::parse(&fam.consensus_protocol)
            .map(|p| p.m)
            .unwrap_or(0),
        _ => 0,
    }
}

/// The accord family roster's member `key_id`s (None when it can't be resolved — e.g. no
/// genesis yet). Used only to set the best-effort `roster_verified` display hint.
async fn roster_key_ids(engine: &Engine) -> Option<HashSet<String>> {
    use ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
    crate::family::active_threshold_roster(engine, HUMANITY_ACCORD_FAMILY_KEY_ID)
        .await
        .ok()
        .map(|members| members.into_iter().map(|m| m.member_id).collect())
}

/// Extract the scrubber `key_id`s + transport hints from a verify `SignedKeyRecord` JSON,
/// shape-tolerantly (the primary `scrub_key_id` plus any `additional_scrubs[].scrub_key_id`).
fn coscrub_scrubbers_and_hints(
    partial: &serde_json::Value,
) -> (Vec<String>, Vec<serde_json::Value>) {
    let rec = partial.get("record").unwrap_or(partial);
    let mut scrubbers = Vec::new();
    if let Some(s) = rec.get("scrub_key_id").and_then(|v| v.as_str()) {
        scrubbers.push(s.to_string());
    }
    if let Some(arr) = rec.get("additional_scrubs").and_then(|v| v.as_array()) {
        for s in arr {
            if let Some(k) = s.get("scrub_key_id").and_then(|v| v.as_str()) {
                scrubbers.push(k.to_string());
            }
        }
    }
    scrubbers.sort();
    scrubbers.dedup();
    let hints = rec
        .get("transport_hints")
        .or_else(|| {
            rec.get("registration_envelope")
                .and_then(|e| e.get("transport_hints"))
        })
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    (scrubbers, hints)
}

/// Upsert a partial into the pending store (keyed by target; a higher scrub count
/// supersedes a lower one for the same target). Returns `false` when this exact
/// `(target, count)` was already ingested (the re-gossip loop-stop).
fn upsert_pending(st: &ProvisionState, entry: PendingCoscrub) -> bool {
    {
        let mut seen = st.seen.lock().unwrap();
        if !seen.insert((entry.target_key_id.clone(), entry.distinct_scrub_count)) {
            return false;
        }
    }
    let mut pending = st.pending.lock().unwrap();
    pending.retain(|p| {
        !(p.target_key_id == entry.target_key_id
            && p.distinct_scrub_count <= entry.distinct_scrub_count)
    });
    pending.push(entry);
    if pending.len() > MAX_PENDING_COSCRUBS {
        let overflow = pending.len() - MAX_PENDING_COSCRUBS;
        pending.drain(0..overflow);
    }
    true
}

/// Drop every pending entry for a target (the co-scrub completed / conferred).
fn clear_pending(st: &ProvisionState, target_key_id: &str) {
    st.pending
        .lock()
        .unwrap()
        .retain(|p| p.target_key_id != target_key_id);
}

/// Best-effort fan-out of a co-scrub partial to accord peers. Spawned + per-peer
/// time-bounded so a stalling peer never blocks the holder's request. Returns the peer
/// count attempted.
fn gossip_partial(st: &ProvisionState, partial: serde_json::Value) -> usize {
    let peers = st.peers.clone();
    let http = st.http.clone();
    let n = peers.len();
    if n == 0 {
        return 0;
    }
    tokio::spawn(async move {
        let body = serde_json::json!({ "partial": partial });
        for peer in peers {
            let url = format!("{peer}/v1/accord/canonical/gossip-partial");
            match http
                .post(&url)
                .json(&body)
                .timeout(std::time::Duration::from_secs(4))
                .send()
                .await
            {
                Ok(r) => {
                    tracing::debug!(peer = %url, status = %r.status(), "co-scrub gossip sent")
                }
                Err(e) => {
                    tracing::debug!(peer = %url, error = %e, "co-scrub gossip failed (best-effort)")
                }
            }
        }
    });
    n
}

/// Validate a partial STRUCTURALLY (a well-formed `SignedKeyRecord` with ≥1 scrub + a
/// target), store it in the display store, and (if first-seen) gossip it onward. Returns
/// `(target_key_id, distinct_scrub_count, peers_gossiped_to)`. The security decision is
/// NOT here — it is persist's m-of-n gate at cosign→adopt.
async fn ingest_partial(
    st: &ProvisionState,
    partial: serde_json::Value,
) -> Result<(String, usize, usize, bool), (StatusCode, String)> {
    use ciris_verify_core::federation_self_record::SignedKeyRecord as VSignedKeyRecord;
    let (target_key_id, distinct_scrub_count) = {
        let p: VSignedKeyRecord = serde_json::from_value(partial.clone()).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("partial is not a SignedKeyRecord: {e}"),
            )
        })?;
        let c = p.record.distinct_scrub_count();
        let t = p.record.key_id.clone();
        if c == 0 || t.trim().is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "partial carries no scrubs / no target key_id".to_string(),
            ));
        }
        (t, c)
    };
    let (scrubbers, transport_hints) = coscrub_scrubbers_and_hints(&partial);
    let roster_verified = match roster_key_ids(&st.engine).await {
        Some(set) => !scrubbers.is_empty() && scrubbers.iter().all(|s| set.contains(s)),
        None => false,
    };
    let quorum_needed = family_quorum_m(&st.engine).await;
    let entry = PendingCoscrub {
        target_key_id: target_key_id.clone(),
        distinct_scrub_count,
        quorum_needed,
        scrubbers,
        transport_hints,
        roster_verified,
        received_at: now_rfc3339(),
        partial: partial.clone(),
    };
    let fresh = upsert_pending(st, entry);
    let gossiped = if fresh {
        gossip_partial(st, partial)
    } else {
        0
    };
    Ok((target_key_id, distinct_scrub_count, gossiped, fresh))
}

#[derive(Debug, Deserialize)]
struct GossipPartialRequest {
    /// The gossiped verify `SignedKeyRecord` (a co-scrub partial or a completed record).
    partial: serde_json::Value,
}

/// `POST /v1/accord/canonical/gossip-partial` — the OPEN (non-loopback) peer-receive for a
/// gossiped co-scrub partial. Validates it structurally for the display store (the crypto
/// gate stays at cosign→adopt), stores it, and re-gossips a first-seen partial so it floods
/// the mesh. Loop-stopped by `(target, scrub-count)`; the store is bounded.
async fn receive_gossip_partial(
    State(st): State<ProvisionState>,
    body: axum::body::Bytes,
) -> Response {
    let req: GossipPartialRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    match ingest_partial(&st, req.partial).await {
        Ok((target, count, gossiped, fresh)) => {
            let status = if fresh { "stored" } else { "duplicate" };
            tracing::info!(
                canonical_key_id = %target,
                distinct_scrubs = count,
                regossiped_to = gossiped,
                fresh,
                "co-scrub: received gossiped partial"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": status,
                    "target_key_id": target,
                    "distinct_scrub_count": count,
                    "regossiped_to": gossiped,
                })),
            )
                .into_response()
        }
        Err((code, msg)) => err(code, &msg),
    }
}

/// `GET /v1/accord/canonical/pending` — the "Pending co-signs" list: co-scrub partials that
/// have NOT yet reached the family m-of-n (when the quorum is unknown locally, all are
/// shown). Newest first. Each entry carries the verbatim `partial` so a cosign submits it
/// byte-identical.
async fn list_pending_coscrubs(State(st): State<ProvisionState>) -> Response {
    let mut items: Vec<PendingCoscrub> = st.pending.lock().unwrap().clone();
    items.retain(|p| p.quorum_needed == 0 || p.distinct_scrub_count < p.quorum_needed);
    items.sort_by(|a, b| b.received_at.cmp(&a.received_at));
    (
        StatusCode::OK,
        Json(serde_json::json!({ "pending": items })),
    )
        .into_response()
}

/// `GET /v1/accord/canonical/servers` — the canonical / founding bootstrap servers
/// (the `federation_keys` rows carrying the accord-conferred `canonical` role).
/// Backs the Trust Root card's "Canonical servers" list. Read-only; every row is
/// (by the admission gate) anchor-scrub-conferred, never self-claimed.
async fn list_canonical_servers(State(st): State<ProvisionState>) -> Response {
    match st.engine.list_canonical_servers().await {
        Ok(rows) => {
            let servers: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "key_id": r.key_id,
                        "identity_type": r.identity_type,
                        // Both hybrid pubkeys so the client can PRE-FILL a re-mint /
                        // replace of this record without re-deriving them.
                        "pubkey_ed25519_base64": r.pubkey_ed25519_base64,
                        "pubkey_ml_dsa_65_base64": r.pubkey_ml_dsa_65_base64,
                        "scrub_key_id": r.scrub_key_id,
                        "valid_from": r.valid_from,
                        // The record's current signed transport hints (the IP, if any)
                        // — so the UI shows where it's reachable + seeds the edit form.
                        "transport_hints": r.registration_envelope.get("transport_hints")
                            .cloned().unwrap_or(serde_json::Value::Null),
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "servers": servers })),
            )
                .into_response()
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("list_canonical_servers: {e}"),
        ),
    }
}

// ─── Destructive canonical ops (CIRISPersist#377) — 2-of-3, quorum-authorized ──
//
// Additive add-canonical is 1-of-N (a single accord holder's scrub). REMOVING or
// ROTATING a founding server is the destructive class: **2-of-3**. The authority is a
// STORED accord proposal (V091/#302) whose `payload_sha256` commits to the op and
// whose ≥2 verified holder participations persist re-tallies at write time — the
// server passes only the `proposal_digest`; persist is the authority. (The proposal
// ceremony itself — build the committing proposal + collect the 2nd/3rd holder
// participations — is the multi-holder step; a lone holder cannot complete it.)

/// Map a persist `federation::Error` from a destructive canonical op to an HTTP code:
/// an authority/quorum failure is the caller's problem (403); anything else is 500.
fn canonical_destructive_status(e: &ciris_persist::federation::Error) -> StatusCode {
    let kind = e.to_string().to_lowercase();
    if kind.contains("authority") || kind.contains("quorum") || kind.contains("proposal") {
        StatusCode::FORBIDDEN
    } else if kind.contains("withdrawn") {
        StatusCode::CONFLICT
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

#[derive(Debug, Deserialize)]
struct CanonicalWithdrawRequest {
    /// The canonical node whose `canonical` role is being tombstoned.
    key_id: String,
    /// The accord proposal digest (V091/#302) whose stored, 2-of-3-verified
    /// participations authorize this withdrawal. Persist re-tallies it.
    proposal_digest: String,
}

/// `POST /v1/accord/canonical/withdraw` — remove a canonical server from the trust
/// root (2-of-3). Durable tombstone: defeats anti-entropy re-add (revocation-wins).
async fn withdraw_canonical(State(st): State<ProvisionState>, body: axum::body::Bytes) -> Response {
    let req: CanonicalWithdrawRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    if req.key_id.trim().is_empty() || req.proposal_digest.trim().is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "key_id and proposal_digest are both required",
        );
    }
    match st
        .engine
        .withdraw_canonical_role(req.key_id.trim(), req.proposal_digest.trim())
        .await
    {
        Ok(()) => {
            tracing::info!(key_id = %req.key_id.trim(), "Trust Root: canonical server withdrawn (2-of-3)");
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "withdrawn": req.key_id.trim(),
                    "authority_proposal_digest": req.proposal_digest.trim(),
                })),
            )
                .into_response()
        }
        Err(e) => err(
            canonical_destructive_status(&e),
            &format!("withdraw_canonical_role: {e}"),
        ),
    }
}

#[derive(Debug, Deserialize)]
struct CanonicalSupersedeRequest {
    /// The canonical node being retired.
    old_key_id: String,
    /// The successor's full A1-scrubbed `SignedKeyRecord` (produced by the same
    /// add-canonical ceremony — anchor-scrubbed, `canonical` role, carrying the
    /// updated transport hint). Persist admits it BEFORE tombstoning the old, so
    /// the canonical set is never momentarily empty.
    new_record: ciris_persist::federation::SignedKeyRecord,
    /// The authorizing accord proposal digest (2-of-3).
    proposal_digest: String,
}

/// `POST /v1/accord/canonical/supersede` — rotate a canonical server: admit the
/// successor + tombstone the predecessor with `superseded_by` (the old→new link).
/// 2-of-3.
async fn supersede_canonical(
    State(st): State<ProvisionState>,
    body: axum::body::Bytes,
) -> Response {
    let req: CanonicalSupersedeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    if req.old_key_id.trim().is_empty() || req.proposal_digest.trim().is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "old_key_id and proposal_digest are both required",
        );
    }
    let new_key_id = req.new_record.record.key_id.clone();
    match st
        .engine
        .supersede_canonical(
            req.old_key_id.trim(),
            req.new_record,
            req.proposal_digest.trim(),
        )
        .await
    {
        Ok(()) => {
            tracing::info!(
                old_key_id = %req.old_key_id.trim(),
                new_key_id = %new_key_id,
                "Trust Root: canonical server superseded (2-of-3)"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "superseded": req.old_key_id.trim(),
                    "successor": new_key_id,
                    "authority_proposal_digest": req.proposal_digest.trim(),
                })),
            )
                .into_response()
        }
        Err(e) => err(
            canonical_destructive_status(&e),
            &format!("supersede_canonical: {e}"),
        ),
    }
}

/// `GET /v1/accord/canonical/withdrawals` — the canonical-role withdrawal tombstones
/// (the withdrawn-history view alongside the live `canonical/servers` list). A
/// `superseded_by` marks a rotation; `None` a plain withdrawal.
async fn list_canonical_withdrawals(State(st): State<ProvisionState>) -> Response {
    match st.engine.list_canonical_withdrawals().await {
        Ok(rows) => {
            let withdrawals: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|w| {
                    serde_json::json!({
                        "key_id": w.key_id,
                        "withdrawn_at": w.withdrawn_at,
                        "superseded_by": w.superseded_by,
                        "authority_proposal_digest": w.authority_decision_digest,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "withdrawals": withdrawals })),
            )
                .into_response()
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("list_canonical_withdrawals: {e}"),
        ),
    }
}

/// The accord-provision routers.
///
/// - [`ProvisionRouters::loopback`] carries the holder-device ops + read surfaces and MUST
///   be merged behind the `require_loopback` guard (the client talks to its OWN node).
/// - [`ProvisionRouters::gossip`] is the co-scrub peer-receive — it MUST accept REMOTE
///   peers (that is the whole point: A1's box POSTs the partial to B1's box), so it is
///   deliberately NOT loopback-gated. It validates structurally + is bounded, and the
///   security decision stays at persist's m-of-n admission gate.
///
/// Both share one [`ProvisionState`] so the pending store a peer writes via `gossip` is the
/// one the client reads via `loopback`'s `GET /pending`.
pub struct ProvisionRouters {
    pub loopback: Router,
    pub gossip: Router,
}

/// Build the accord-provision routers over a shared state. `peers` is the accord peer base
/// URL set (`http://host:port`, self excluded) co-scrub partials gossip to — pass the SAME
/// set the accord kill-switch uses (empty is fine: the ceremony still closes via the
/// returned/saved partial + the client's paste fallback).
pub fn build(engine: Arc<Engine>, peers: Vec<String>) -> ProvisionRouters {
    let state = ProvisionState {
        engine,
        peers,
        http: reqwest::Client::new(),
        pending: Arc::new(Mutex::new(Vec::new())),
        seen: Arc::new(Mutex::new(HashSet::new())),
    };
    let loopback = Router::new()
        .route(
            "/v1/accord/provision-holder",
            axum::routing::post(provision_holder),
        )
        .route(
            "/v1/accord/family/cosign",
            axum::routing::post(cosign_family),
        )
        .route("/v1/accord/admit-node", axum::routing::post(admit_node))
        // The mesh-seed op + its list — the Trust Root "Canonical servers" section.
        .route(
            "/v1/accord/canonical/add",
            axum::routing::post(add_canonical),
        )
        .route(
            "/v1/accord/canonical/servers",
            axum::routing::get(list_canonical_servers),
        )
        // Cross-device m-of-n co-scrub (CIRISPersist#383): propose (scrub #1) → the partial
        // gossips (open `/gossip-partial`) → cosign (append a scrub) → adopt at quorum.
        .route(
            "/v1/accord/canonical/propose",
            axum::routing::post(propose_canonical),
        )
        .route(
            "/v1/accord/canonical/cosign",
            axum::routing::post(cosign_canonical),
        )
        // CI-key co-scrub (CIRISServer#290) — bless the substrate fleet's CI
        // build-signing keys (roles:["infra:attest"]) in ONE batch ceremony. Same
        // m-of-n propose→cosign as canonical, driven by the client's "bless CI
        // workers" card.
        .route(
            "/v1/accord/ci-key/propose",
            axum::routing::post(propose_ci_key),
        )
        .route(
            "/v1/accord/ci-key/cosign",
            axum::routing::post(cosign_ci_key),
        )
        // The "Pending co-signs" list (partials below the family quorum), read by the client.
        .route(
            "/v1/accord/canonical/pending",
            axum::routing::get(list_pending_coscrubs),
        )
        // Destructive canonical ops (CIRISPersist#377, 2-of-3) + the withdrawn-history.
        .route(
            "/v1/accord/canonical/withdraw",
            axum::routing::post(withdraw_canonical),
        )
        .route(
            "/v1/accord/canonical/supersede",
            axum::routing::post(supersede_canonical),
        )
        .route(
            "/v1/accord/canonical/withdrawals",
            axum::routing::get(list_canonical_withdrawals),
        )
        .route(
            "/v1/accord/yubikey-status",
            axum::routing::get(yubikey_status),
        )
        .with_state(state.clone());
    let gossip = Router::new()
        .route(
            "/v1/accord/canonical/gossip-partial",
            axum::routing::post(receive_gossip_partial),
        )
        .with_state(state);
    ProvisionRouters { loopback, gossip }
}

/// Back-compat convenience: just the loopback router with no gossip peers (used by tests
/// that exercise the holder-device ops). Prefer [`build`] to also mount `/gossip-partial`.
pub fn router(engine: Arc<Engine>) -> Router {
    build(engine, Vec::new()).loopback
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

    /// The full provision surface (loopback ops + the OPEN `/gossip-partial`) merged, for
    /// exercising the co-scrub display store end to end.
    async fn coscrub_app() -> Router {
        let signing_key = SigningKey::from_bytes(&[0x5C; 32]);
        let signer = Arc::new(LocalSigner::from_parts(
            signing_key,
            "coscrub-test".to_string(),
            None,
            None,
        ));
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer for co-scrub tests");
        let r = super::build(Arc::new(engine), Vec::new());
        r.loopback.merge(r.gossip)
    }

    async fn get_json(app: &Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    async fn post_json(
        app: &Router,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// A self-signed (1-scrub) verify record JSON — the shape a `propose` partial has.
    async fn self_signed_partial(key_id: &str) -> serde_json::Value {
        use ciris_verify_core::federation_self_record::produce_self_key_record;
        use ciris_verify_core::self_at_login::HybridSigningIdentity;
        let id = HybridSigningIdentity::generate(key_id).expect("gen identity");
        let rec = produce_self_key_record(&id, "canonical,node", "2026-07-05T00:00:00Z", &[])
            .await
            .expect("produce self key record");
        serde_json::to_value(&rec).expect("record to json")
    }

    #[tokio::test]
    async fn pending_is_empty_on_a_fresh_node() {
        let app = coscrub_app().await;
        let (status, body) = get_json(&app, "/v1/accord/canonical/pending").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["pending"].as_array().map(|a| a.len()), Some(0));
    }

    #[tokio::test]
    async fn gossip_partial_rejects_a_non_record() {
        let app = coscrub_app().await;
        let (status, _) = post_json(
            &app,
            "/v1/accord/canonical/gossip-partial",
            serde_json::json!({ "partial": { "not": "a record" } }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn gossip_partial_stores_lists_and_dedups() {
        let app = coscrub_app().await;
        let partial = self_signed_partial("canonical-server-gossip-test").await;
        let target = partial["record"]["key_id"].as_str().unwrap().to_string();

        // First gossip → stored + echoed.
        let (s1, b1) = post_json(
            &app,
            "/v1/accord/canonical/gossip-partial",
            serde_json::json!({ "partial": partial.clone() }),
        )
        .await;
        assert_eq!(s1, StatusCode::OK);
        assert_eq!(b1["status"], "stored");
        assert_eq!(b1["target_key_id"], target);

        // It appears in the pending list (quorum unknown on a fresh node ⇒ shown).
        let (_, pend) = get_json(&app, "/v1/accord/canonical/pending").await;
        let items = pend["pending"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["target_key_id"], target);
        assert_eq!(items[0]["distinct_scrub_count"], 1);

        // Re-gossip of the SAME (target, count) is a no-op duplicate (loop-stop).
        let (s2, b2) = post_json(
            &app,
            "/v1/accord/canonical/gossip-partial",
            serde_json::json!({ "partial": partial }),
        )
        .await;
        assert_eq!(s2, StatusCode::OK);
        assert_eq!(b2["status"], "duplicate");
        let (_, pend2) = get_json(&app, "/v1/accord/canonical/pending").await;
        assert_eq!(pend2["pending"].as_array().unwrap().len(), 1);
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

    // ─── add-canonical (the mesh-seed op, #164) ──────────────────────────────

    #[test]
    fn ensure_canonical_role_adds_sorts_and_dedups() {
        assert_eq!(ensure_canonical_role("node"), "canonical,node");
        assert_eq!(ensure_canonical_role("canonical"), "canonical");
        assert_eq!(ensure_canonical_role("node,canonical"), "canonical,node");
        assert_eq!(ensure_canonical_role(""), "canonical");
        assert_eq!(
            ensure_canonical_role("  node ,  agent "),
            "agent,canonical,node"
        );
    }

    #[tokio::test]
    async fn list_canonical_servers_returns_the_baked_genesis_on_a_fresh_node() {
        // persist v13.4.0 (CIRISPersist#390/#391) BAKES the 2-of-3 canonical genesis
        // server `ciris-canonical-1-d7bdeu223k` — the operator's accord-co-scrubbed
        // record (A1 + B1), seeded at boot via `seed_canonical_servers`. So a fresh
        // node now ships trusting exactly that one canonical server, conferred via the
        // baked 2-of-3 genesis (NOT self-claimed — canonical admission stays m-of-n).
        // (Was: `..._is_empty_on_a_fresh_node`, the post-#383 gap before the 2-of-3
        // replacement existed — see #390.)
        let app = router_with_engine().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/accord/canonical/servers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let servers = v["servers"].as_array().expect("servers array");
        assert_eq!(
            servers.len(),
            1,
            "a fresh node ships exactly the baked genesis canonical server: {v}"
        );
        assert_eq!(
            servers[0]["key_id"].as_str(),
            Some("ciris-canonical-1-d7bdeu223k"),
            "the baked genesis canonical server is ciris-canonical-1: {v}"
        );
        assert!(
            servers[0]["identity_type"]
                .as_str()
                .is_some_and(|t| t.contains("canonical")),
            "the baked row carries the accord-conferred canonical role: {v}"
        );
    }

    #[tokio::test]
    async fn add_canonical_rejects_a_target_missing_pubkeys() {
        let app = router_with_engine().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/accord/canonical/add")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"key_id":"accord-holder-1","mldsa_usb_path":"/tmp/usb","target":{"key_id":"canonical-server-1","pubkey_ed25519_base64":"","pubkey_ml_dsa_65_base64":""}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_canonical_withdrawals_is_empty_on_a_fresh_node() {
        let app = router_with_engine().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/accord/canonical/withdrawals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["withdrawals"].as_array().map(|a| a.len()),
            Some(0),
            "no canonical withdrawals on a fresh node"
        );
    }

    #[tokio::test]
    async fn propose_canonical_rejects_missing_target_pubkeys() {
        let app = router_with_engine().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/accord/canonical/propose")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"key_id":"A1","mldsa_usb_path":"/tmp/usb","target":{"key_id":"canonical-server-1","pubkey_ed25519_base64":"","pubkey_ml_dsa_65_base64":""}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn cosign_canonical_rejects_a_null_partial() {
        let app = router_with_engine().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/accord/canonical/cosign")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"key_id":"B1","mldsa_usb_path":"/tmp/usb","partial":null}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[cfg(not(feature = "pkcs11"))]
    #[tokio::test]
    async fn propose_canonical_without_pkcs11_returns_not_implemented() {
        let app = router_with_engine().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/accord/canonical/propose")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"key_id":"A1","mldsa_usb_path":"/tmp/usb","target":{"key_id":"canonical-server-1","pubkey_ed25519_base64":"AA","pubkey_ml_dsa_65_base64":"BB"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[cfg(not(feature = "pkcs11"))]
    #[tokio::test]
    async fn add_canonical_without_pkcs11_returns_not_implemented() {
        let app = router_with_engine().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/accord/canonical/add")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"key_id":"accord-holder-1","mldsa_usb_path":"/tmp/usb","target":{"key_id":"canonical-server-1","pubkey_ed25519_base64":"AA","pubkey_ml_dsa_65_base64":"BB"}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
