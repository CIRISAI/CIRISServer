//! **Mint a hardware-rooted USER federation identity via ciris-server** — the
//! founder's goal: `ciris-server identity create --backend pkcs11` mints a
//! YubiKey-backed federation USER identity (CIRISServer#21, CIRISVerify#80).
//!
//! ## What this is
//!
//! A federation USER identity is a **hybrid, hardware-rooted** keypair: an
//! Ed25519 classical half (the human's *signing* key — custodied by a YubiKey
//! PIV slot, a TPM/SE-sealed key, or — for CI/dev — a software seed) plus an
//! ML-DSA-65 post-quantum half whose seed is **sealed at rest** by the platform
//! secure storage. It is a DISTINCT namespace from the node steward key (the
//! `Engine`'s `LocalSigner`): the whole point is that the responsible human's
//! owner-binding signature is custodied by the human's own hardware, never
//! co-resident with the node key.
//!
//! ## How it maps to verify v6.0.0
//!
//! - [`ciris_keyring::user_identity::get_user_identity_signer`] opens the
//!   Ed25519 *signing* half for the chosen [`SigningBackend`]
//!   (`PlatformSealed` / `Pkcs11` / `Software`) → a `Box<dyn HardwareSigner>`.
//! - [`ciris_verify_core::federation_identity::create_federation_identity`] does
//!   the backend-independent rest: derives the federation `key_id`, attaches the
//!   sealed ML-DSA-65 half **internally** (`get_platform_sealed_mldsa65_signer`),
//!   emits the self-signed genesis [`SignedCegObject`] to the CEG outbox, and
//!   returns the shareable **fedcode** (`CIRIS-V2-…`, [`ciris_verify_core::fedcode`],
//!   [`FedKind::User`](ciris_verify_core::fedcode::FedKind::User)).
//!
//! ## The YubiKey (PKCS#11) backend — gated + flagged
//!
//! The `pkcs11` cargo feature on `ciris-server` turns on `ciris-keyring`'s own
//! `pkcs11` feature (Linux operator hardware). It is OFF by default: a plain
//! `cargo build` never links `cryptoki`, and the `Pkcs11` backend honestly
//! returns [`KeyringError::NotSupported`] without it. The empty-slot
//! provisioning flow (`provision_piv_via_ykman`, default PIV slot `9c`,
//! touch/pin policy) mirrors the `ciris-verify identity create` CLI but is
//! driven here as a ciris-server operation.
//!
//! ## Wiring the minted identity as the claim-remote signer
//!
//! Once minted, the same hardware signer is composed into a persist
//! [`LocalSigner`](ciris_persist::prelude::LocalSigner) via
//! `LocalSigner::from_hardware_parts` (Ed25519 stays hardware-custodied; the
//! ML-DSA-65 half is the sealed PQC signer). `compose::user_identity_signer`
//! prefers this hardware-backed user identity, so `POST /v1/setup/claim-remote`
//! signs the `delegates_to(user → node, infra:*)` owner-binding with the user's
//! YubiKey-custodied key.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use ciris_keyring::user_identity::{get_user_identity_signer, SigningBackend, UserIdentityConfig};
use ciris_keyring::{HardwareSigner, PqcSigner};
use ciris_verify_core::fedcode;
use ciris_verify_core::federation_identity::create_federation_identity;

/// The default PIV slot an empty YubiKey is provisioned into — `9c` (Digital
/// Signature). ykcs11 maps `9c` to the label "Private key for Digital
/// Signature". Matches the `ciris-verify` CLI default.
pub const DEFAULT_PIV_SLOT: &str = "9c";

/// The default ykcs11 module path (Yubico PIV) used when none is supplied.
pub const DEFAULT_YKCS11_MODULE: &str = "/usr/lib/x86_64-linux-gnu/libykcs11.so";

/// Which custody backend the user-identity signing key is minted from. The
/// operator-facing selector behind `--backend` / the endpoint's `backend` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserIdentityBackend {
    /// **YubiKey** over PKCS#11 (operator hardware; Linux). Gated behind the
    /// `ciris-server` `pkcs11` cargo feature → `ciris-keyring/pkcs11`. The
    /// private key never leaves the token (`C_Sign` runs on-device).
    Pkcs11(Pkcs11Options),
    /// TPM 2.0 / Secure-Enclave-sealed Ed25519 (encrypted software fallback).
    /// Testable on any box.
    PlatformSealed,
    /// Software seed — explicit dev/CI custody (NO hardware guarantee).
    Software,
}

impl UserIdentityBackend {
    /// The honest hardware tier label for logs / the response.
    pub fn label(&self) -> &'static str {
        match self {
            UserIdentityBackend::Pkcs11(_) => "pkcs11-yubikey",
            UserIdentityBackend::PlatformSealed => "platform-sealed",
            UserIdentityBackend::Software => "software",
        }
    }
}

/// PKCS#11 / PIV options for the YubiKey backend (data only — always parseable;
/// the *signer* is `pkcs11`-feature-gated in `ciris-keyring`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs11Options {
    /// Path to the token's PKCS#11 module (`libykcs11.so` for Yubico PIV).
    pub module_path: PathBuf,
    /// The token user PIN (PIV PIN). `None` → operator is prompted out of band.
    pub user_pin: Option<String>,
    /// `CKA_LABEL` of the Ed25519 signing key (the PIV slot's label). Defaults to
    /// the ykcs11 label for the chosen PIV slot.
    pub key_label: Option<String>,
    /// Token slot index (default 0).
    pub slot_index: usize,
    /// The PIV slot to provision when the slot is empty (default `9c`).
    pub piv_slot: String,
    /// Whether to provision an Ed25519 key into an empty slot via `ykman`.
    pub provision: bool,
    /// `ykman` PIV touch policy for a provisioned key (e.g. `always`/`cached`).
    pub touch_policy: String,
    /// `ykman` PIV pin policy for a provisioned key (e.g. `once`/`always`).
    pub pin_policy: String,
    /// `ykman` PIV management key (factory default if unset).
    pub management_key: String,
}

impl Default for Pkcs11Options {
    fn default() -> Self {
        Self {
            module_path: PathBuf::from(DEFAULT_YKCS11_MODULE),
            user_pin: None,
            key_label: None,
            slot_index: 0,
            piv_slot: DEFAULT_PIV_SLOT.to_string(),
            provision: false,
            touch_policy: "cached".to_string(),
            pin_policy: "once".to_string(),
            management_key: "010203040506070801020304050607080102030405060708".to_string(),
        }
    }
}

/// The result of minting a USER federation identity.
#[derive(Debug, Clone)]
pub struct MintedUserIdentity {
    /// The federation `key_id` (FSD-002 `label-fingerprint` form when a label is
    /// given; else `sha256(ed_pubkey)`-derived).
    pub key_id: String,
    /// The shareable **fedcode** — a `usercode` (`CIRIS-V2-…`). Decodes to
    /// [`FedKind::User`](ciris_verify_core::fedcode::FedKind::User) + this `key_id`.
    pub fedcode: String,
    /// Always `"user"` (this mints a USER identity).
    pub identity_type: String,
    /// The Ed25519 signing public key, base64 standard.
    pub pubkey_ed25519_base64: String,
    /// The ML-DSA-65 PQC public key, base64 standard.
    pub pubkey_ml_dsa_65_base64: String,
    /// The honest custody tier the signer reported (`SoftwareOnly`, `Tpm2`, …).
    pub hardware_type: String,
}

/// Build the [`UserIdentityConfig`] for `backend` under the user-identity alias
/// `key_id` and its (distinct-from-the-node) `seed_dir`.
fn user_identity_config(
    backend: &UserIdentityBackend,
    key_id: &str,
    seed_dir: PathBuf,
) -> UserIdentityConfig {
    let backend = match backend {
        UserIdentityBackend::PlatformSealed => SigningBackend::PlatformSealed,
        UserIdentityBackend::Software => SigningBackend::Software,
        UserIdentityBackend::Pkcs11(opts) => {
            // Default the PKCS#11 key label to the ykcs11 PIV-slot label when the
            // operator didn't pin one explicitly (matches `ykman` provisioning).
            let key_label = opts
                .key_label
                .clone()
                .or_else(|| match opts.piv_slot.as_str() {
                    "9c" => Some("Private key for Digital Signature".to_string()),
                    "9a" => Some("Private key for PIV Authentication".to_string()),
                    other => Some(format!("Private key for slot {other}")),
                });
            SigningBackend::Pkcs11(ciris_keyring::pkcs11::Pkcs11Config {
                module_path: opts.module_path.clone(),
                user_pin: opts.user_pin.clone(),
                key_label,
                key_id: None,
                slot_index: opts.slot_index,
            })
        }
    };
    UserIdentityConfig {
        key_id: key_id.to_string(),
        seed_dir,
        backend,
    }
}

/// Open the user-identity **Ed25519** signing half — provisioning an empty
/// YubiKey PIV slot first when the `pkcs11` backend asks for it.
///
/// **verify v6.0.0 divergence (flagged):** the keyring `Software` backend
/// reached through `get_user_identity_signer` is a **P-256 ECDSA**
/// `SoftwareSigner`, but `create_federation_identity` REQUIRES an Ed25519
/// classical half (it rejects `EcdsaP256`). So the `Software` backend is
/// resolved here with a persisted **`Ed25519SoftwareSigner`** seed
/// (`<seed_dir>/<key_id>.ed25519.seed`, minted on first call, `0600`, re-read on
/// re-open) rather than `get_user_identity_signer(Software)`. The
/// `PlatformSealed` / `Pkcs11` backends go through `get_user_identity_signer`
/// (both yield Ed25519).
fn open_user_signer(
    backend: &UserIdentityBackend,
    cfg: &UserIdentityConfig,
) -> Result<Box<dyn HardwareSigner>> {
    // Software: a persisted Ed25519 seed (the keyring Software backend is ECDSA,
    // which the federation-identity core rejects).
    if let UserIdentityBackend::Software = backend {
        return open_software_ed25519_signer(&cfg.key_id, &cfg.seed_dir);
    }

    match get_user_identity_signer(cfg) {
        Ok(s) => Ok(s),
        Err(e) => {
            // Only the YubiKey path can auto-provision an empty slot via ykman.
            if let UserIdentityBackend::Pkcs11(opts) = backend {
                if opts.provision {
                    tracing::info!(
                        slot = %opts.piv_slot,
                        "no usable key in the PIV slot ({e}); provisioning an Ed25519 key via ykman…"
                    );
                    provision_piv_via_ykman(opts)
                        .context("provision an Ed25519 key into the YubiKey PIV slot via ykman")?;
                    return get_user_identity_signer(cfg).map_err(|e| {
                        anyhow::anyhow!("open the YubiKey signer after provisioning: {e}")
                    });
                }
            }
            Err(anyhow::anyhow!(
                "open the user-identity signing key ({}): {e}",
                backend.label()
            ))
        }
    }
}

/// Resolve a stable software **Ed25519** signing key for the user identity,
/// persisting a 32-byte seed under `seed_dir` so mint + the claim-remote signer
/// re-open the SAME key. `0600` on Unix.
fn open_software_ed25519_signer(
    key_id: &str,
    seed_dir: &std::path::Path,
) -> Result<Box<dyn HardwareSigner>> {
    use ciris_keyring::Ed25519SoftwareSigner;

    std::fs::create_dir_all(seed_dir)
        .with_context(|| format!("create user seed dir {}", seed_dir.display()))?;
    let seed_path = seed_dir.join(format!("{key_id}.ed25519.seed"));
    let seed: [u8; 32] = if seed_path.exists() {
        let bytes = std::fs::read(&seed_path)
            .with_context(|| format!("read user ed25519 seed {}", seed_path.display()))?;
        bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("{} must be a 32-byte ed25519 seed", seed_path.display())
        })?
    } else {
        let mut s = [0u8; 32];
        getrandom::fill(&mut s).map_err(|e| anyhow::anyhow!("mint user ed25519 seed: {e}"))?;
        std::fs::write(&seed_path, s).with_context(|| format!("write {}", seed_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600));
        }
        s
    };
    let signer = Ed25519SoftwareSigner::from_bytes(&seed, key_id)
        .map_err(|e| anyhow::anyhow!("load user ed25519 software signer: {e}"))?;
    Ok(Box::new(signer))
}

/// **Mint a hardware-rooted USER federation identity.** Opens the Ed25519
/// signing half for `backend`, then calls verify v6.0.0
/// `create_federation_identity(FedKind::User)` which attaches the sealed
/// ML-DSA-65 half, writes the self-signed genesis CEG object to the outbox, and
/// returns the user `key_id` + the `CIRIS-V2-` usercode + the pubkeys.
///
/// `seed_dir` is where the sealed/software Ed25519 seed lives for the
/// `PlatformSealed` / `Software` backends — DISTINCT from the node steward's
/// `identity_dir`. `label` (the human's display name) yields the FSD-002
/// `label-fingerprint` `key_id` when no explicit `fed_key_id` is given.
pub async fn mint_user_identity(
    backend: UserIdentityBackend,
    key_id_alias: &str,
    label: Option<&str>,
    seed_dir: PathBuf,
) -> Result<MintedUserIdentity> {
    let cfg = user_identity_config(&backend, key_id_alias, seed_dir);

    // 1. Open the user's Ed25519 signing half (YubiKey / sealed / software).
    let hw_signer = open_user_signer(&backend, &cfg)?;
    let hardware_type = format!("{:?}", hw_signer.hardware_type());
    let hw_signer: Arc<dyn HardwareSigner> = Arc::from(hw_signer);

    // 2. Mint the hybrid hardware-rooted identity. verify v6.0.0 attaches the
    //    sealed ML-DSA-65 half internally + emits the genesis CEG object + the
    //    fedcode. A touch-required YubiKey blocks on the signature until tapped.
    let now = chrono::Utc::now().to_rfc3339();
    let created = create_federation_identity(
        Arc::clone(&hw_signer),
        // identity_type "user" → FedKind::User (the accountable human).
        "user",
        // PIN the federation key_id to the user-identity ALIAS so the minted
        // identity's key_id is stable + predictable, and the sealed ML-DSA-65
        // half + the software Ed25519 seed (both keyed by this id) re-open under
        // the SAME id when wiring the claim-remote signer. `label` still flows
        // into the fedcode's alias_hint.
        Some(key_id_alias.to_string()),
        label,
        &now,
    )
    .await
    .map_err(|e| anyhow::anyhow!("create_federation_identity (user): {e}"))?;

    // Persist the genesis object to the CEG outbox so the local node drains +
    // admits the new user key into federation_keys (same as the CLI).
    created
        .object
        .write_to_outbox(&created.key_id)
        .map_err(|e| anyhow::anyhow!("write genesis CEG object to outbox: {e}"))?;

    // The pubkeys for the response: Ed25519 off the signer, ML-DSA-65 off the
    // sealed PQC half (re-opened from keys_dir, where create_federation_identity
    // sealed it under `key_id`).
    let ed_pub = hw_signer
        .public_key()
        .await
        .map_err(|e| anyhow::anyhow!("read user Ed25519 public key: {e}"))?;
    let pqc = ciris_keyring::get_platform_sealed_mldsa65_signer(
        &created.key_id,
        ciris_verify_core::ceg_outbox::keys_dir(),
    )
    .map_err(|e| anyhow::anyhow!("re-open sealed ML-DSA-65 half: {e}"))?;
    let ml_pub = pqc
        .public_key()
        .await
        .map_err(|e| anyhow::anyhow!("read user ML-DSA-65 public key: {e}"))?;

    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(MintedUserIdentity {
        key_id: created.key_id,
        fedcode: created.code,
        identity_type: "user".to_string(),
        pubkey_ed25519_base64: b64.encode(&ed_pub),
        pubkey_ml_dsa_65_base64: b64.encode(&ml_pub),
        hardware_type,
    })
}

/// Compose the minted USER identity into a persist
/// [`LocalSigner`](ciris_persist::prelude::LocalSigner) for `POST /v1/setup/
/// claim-remote`: the Ed25519 half stays hardware-custodied (signs through the
/// `HardwareSigner`), the ML-DSA-65 half is the sealed PQC signer. The resulting
/// signer's `sign_hybrid` is what `ownership::build_signed_owner_binding` uses.
///
/// `user_key_id` is the federation `key_id` of the minted user identity (e.g.
/// the one returned by [`mint_user_identity`], surfaced via `CIRIS_USER_KEY_ID`).
pub async fn hardware_user_local_signer(
    backend: UserIdentityBackend,
    user_key_id: &str,
    seed_dir: PathBuf,
) -> Result<ciris_persist::prelude::LocalSigner> {
    let cfg = user_identity_config(&backend, user_key_id, seed_dir);
    let hw = open_user_signer(&backend, &cfg)?;
    let classical: Arc<dyn HardwareSigner> = Arc::from(hw);

    // The ML-DSA-65 half was sealed under `user_key_id` at mint time; re-open it.
    let pqc = ciris_keyring::get_platform_sealed_mldsa65_signer(
        user_key_id,
        ciris_verify_core::ceg_outbox::keys_dir(),
    )
    .map_err(|e| anyhow::anyhow!("re-open sealed ML-DSA-65 half for the user signer: {e}"))?;
    let pqc: Arc<dyn PqcSigner> = Arc::from(pqc);
    let pqc_key_id = format!("{user_key_id}-pqc");

    ciris_persist::prelude::LocalSigner::from_hardware_parts(
        classical,
        user_key_id.to_string(),
        Some(pqc),
        Some(pqc_key_id),
    )
    .await
    .map_err(|e| anyhow::anyhow!("compose hardware-backed user LocalSigner: {e}"))
}

/// Provision an Ed25519 key + self-signed cert in a YubiKey PIV slot via
/// `ykman` (PIV slot policy + the slot cert are PIV-applet operations, NOT
/// PKCS#11). `ykman` inherits the terminal, so it prompts for the PIN and the
/// cert step requires a physical touch. Mirrors the `ciris-verify` CLI flow.
fn provision_piv_via_ykman(opts: &Pkcs11Options) -> Result<()> {
    let pub_tmp = std::env::temp_dir().join(format!("ciris_user_piv_{}_pub.pem", opts.piv_slot));
    let pub_path = pub_tmp.to_string_lossy().into_owned();

    tracing::info!(
        slot = %opts.piv_slot,
        touch_policy = %opts.touch_policy,
        pin_policy = %opts.pin_policy,
        "provisioning Ed25519 in the YubiKey PIV slot via ykman…"
    );
    run_ykman(&[
        "piv",
        "keys",
        "generate",
        "--algorithm",
        "ED25519",
        "--pin-policy",
        &opts.pin_policy,
        "--touch-policy",
        &opts.touch_policy,
        "-m",
        &opts.management_key,
        &opts.piv_slot,
        &pub_path,
    ])?;

    tracing::info!("generating the PIV slot certificate — enter your PIN and TAP the YubiKey…");
    run_ykman(&[
        "piv",
        "certificates",
        "generate",
        "--subject",
        "CN=ciris-federation-user",
        "-m",
        &opts.management_key,
        &opts.piv_slot,
        &pub_path,
    ])?;

    let _ = std::fs::remove_file(&pub_tmp);
    Ok(())
}

fn run_ykman(args: &[&str]) -> Result<()> {
    let status = std::process::Command::new("ykman")
        .args(args)
        .status()
        .map_err(|e| {
            anyhow::anyhow!("could not run `ykman` (is yubikey-manager installed?): {e}")
        })?;
    if !status.success() {
        anyhow::bail!(
            "`ykman {}` failed (exit {:?})",
            args.join(" "),
            status.code()
        );
    }
    Ok(())
}

// ─── POST /v1/self/identity (provision/ensure the local USER identity) ───────

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::prelude::Engine;
use serde::Deserialize;

use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::{resolve_bearer, SessionCaller};

/// State for `POST /v1/self/identity` — the local node's federation-ID wizard
/// backend (CIRISServer#21).
#[derive(Clone)]
struct SelfIdentityState {
    engine: Arc<Engine>,
    /// THIS node's federation `key_id` — the user alias defaults to `<node>-user`
    /// when the request doesn't pin one.
    node_key_id: String,
    /// The per-user seed dir (distinct from the node steward's identity dir).
    seed_dir: PathBuf,
}

/// `POST /v1/self/identity` request — the federation-ID wizard's inputs.
#[derive(Debug, Default, Deserialize)]
struct SelfIdentityRequest {
    /// Custody backend: `pkcs11` (YubiKey) | `platform-sealed` | `software`.
    /// Defaults to `platform-sealed` (best platform hardware, software fallback).
    #[serde(default)]
    backend: Option<String>,
    /// The human's display name → the FSD-002 `label-fingerprint` key_id.
    #[serde(default)]
    label: Option<String>,
    /// The user-identity alias (defaults to `<node_key_id>-user`).
    #[serde(default)]
    key_id: Option<String>,
    /// For the `pkcs11` backend: provision an empty PIV slot via `ykman`.
    #[serde(default)]
    provision: bool,
    /// For the `pkcs11` backend: the PIV slot (default `9c`).
    #[serde(default)]
    piv_slot: Option<String>,
}

fn http_err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// Owner/operator gate — provisioning the responsible-user identity on a node is
/// an apex act, gated on SYSTEM_ADMIN + FullAccess (same as claim-remote).
async fn require_owner(engine: &Engine, headers: &HeaderMap) -> Result<SessionCaller, Response> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return Err(http_err(
            StatusCode::UNAUTHORIZED,
            "missing bearer session token",
        ));
    };
    match resolve_bearer(engine, token).await {
        Ok(Some(caller))
            if caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) =>
        {
            Ok(caller)
        }
        Ok(Some(_)) => Err(http_err(
            StatusCode::FORBIDDEN,
            "provisioning the user identity requires the owner (SYSTEM_ADMIN) role",
        )),
        Ok(None) => Err(http_err(
            StatusCode::UNAUTHORIZED,
            "invalid or expired session",
        )),
        Err(e) => Err(http_err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("store: {e}"),
        )),
    }
}

// The Err arm is an axum `Response` (the error body); that asymmetry trips
// `result_large_err`, but a handler helper returning a ready Response is the
// idiomatic axum shape (mirrors `require_owner`).
#[allow(clippy::result_large_err)]
fn parse_backend(req: &SelfIdentityRequest) -> Result<UserIdentityBackend, Response> {
    match req.backend.as_deref().unwrap_or("platform-sealed") {
        "software" => Ok(UserIdentityBackend::Software),
        "platform-sealed" | "platform_sealed" => Ok(UserIdentityBackend::PlatformSealed),
        "pkcs11" | "yubikey" => {
            let mut opts = Pkcs11Options {
                provision: req.provision,
                ..Pkcs11Options::default()
            };
            if let Some(slot) = &req.piv_slot {
                opts.piv_slot = slot.clone();
            }
            Ok(UserIdentityBackend::Pkcs11(opts))
        }
        other => Err(http_err(
            StatusCode::BAD_REQUEST,
            format!("unknown backend {other:?} — use pkcs11 | platform-sealed | software"),
        )),
    }
}

async fn self_identity_handler(
    State(st): State<SelfIdentityState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner(&st.engine, &headers).await {
        return resp;
    }
    let req: SelfIdentityRequest = if body.is_empty() {
        SelfIdentityRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => return http_err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
        }
    };

    let backend = match parse_backend(&req) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let alias = req
        .key_id
        .clone()
        .unwrap_or_else(|| format!("{}-user", st.node_key_id));

    if let Err(e) = std::fs::create_dir_all(&st.seed_dir) {
        return http_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("create user seed dir: {e}"),
        );
    }

    match mint_user_identity(backend, &alias, req.label.as_deref(), st.seed_dir.clone()).await {
        Ok(minted) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "key_id": minted.key_id,
                "fedcode": minted.fedcode,
                "identity_type": minted.identity_type,
                "pubkey_ed25519_base64": minted.pubkey_ed25519_base64,
                "pubkey_ml_dsa_65_base64": minted.pubkey_ml_dsa_65_base64,
                "hardware_type": minted.hardware_type,
            })),
        )
            .into_response(),
        Err(e) => http_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("mint user identity: {e}"),
        ),
    }
}

/// The `POST /v1/self/identity` router — provision/ensure the local node's USER
/// federation identity, returning `{ key_id, fedcode, identity_type, … }`.
/// Owner/operator-gated. Merge onto the read-API listener.
pub fn router(engine: Arc<Engine>, node_key_id: String, seed_dir: PathBuf) -> Router {
    let state = SelfIdentityState {
        engine,
        node_key_id,
        seed_dir,
    };
    Router::new()
        .route(
            "/v1/self/identity",
            axum::routing::post(self_identity_handler),
        )
        .with_state(state)
}

/// Sanity helper: does this fedcode decode to a USER identity with `key_id`?
/// Used by the test + a defensive check after minting.
pub fn fedcode_is_user(code: &str, key_id: &str) -> bool {
    matches!(
        fedcode::decode(code),
        Ok(fc) if fc.kind == fedcode::FedKind::User && fc.key_id == key_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize tests that set the process-global CIRIS_HOME / CIRIS_DATA_DIR
    /// env (the verify outbox + seal root, and the software key dir).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn tmp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ciris-server-userid-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn mint_software_user_identity_yields_a_valid_usercode() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let home = tmp("home");
        let data = tmp("data");
        let seed = tmp("seed");
        std::env::set_var("CIRIS_HOME", &home);
        std::env::set_var("CIRIS_DATA_DIR", &data);

        let minted = mint_user_identity(
            UserIdentityBackend::Software,
            "ciris-user",
            Some("Test Founder"),
            seed.clone(),
        )
        .await
        .expect("mint software user identity");

        assert_eq!(minted.identity_type, "user");
        // The federation key_id is pinned to the user-identity alias (stable +
        // re-openable for the claim-remote signer).
        assert_eq!(minted.key_id, "ciris-user");
        // A valid CIRIS-V2- usercode that decodes to FedKind::User + this key_id.
        assert!(
            minted.fedcode.starts_with("CIRIS-V2-"),
            "got {}",
            minted.fedcode
        );
        assert!(
            fedcode_is_user(&minted.fedcode, &minted.key_id),
            "fedcode {} did not decode to User/{}",
            minted.fedcode,
            minted.key_id
        );
        assert!(!minted.pubkey_ed25519_base64.is_empty());
        assert!(!minted.pubkey_ml_dsa_65_base64.is_empty());

        std::env::remove_var("CIRIS_HOME");
        std::env::remove_var("CIRIS_DATA_DIR");
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&data);
        let _ = std::fs::remove_dir_all(&seed);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn mint_platform_sealed_user_identity_yields_a_valid_usercode() {
        // PlatformSealed degrades to an encrypted-software seal when no TPM/SE is
        // present (CI), so it is exercisable here.
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let home = tmp("ps-home");
        let data = tmp("ps-data");
        let seed = tmp("ps-seed");
        std::env::set_var("CIRIS_HOME", &home);
        std::env::set_var("CIRIS_DATA_DIR", &data);

        let minted = mint_user_identity(
            UserIdentityBackend::PlatformSealed,
            "ciris-user-sealed",
            Some("Sealed User"),
            seed.clone(),
        )
        .await
        .expect("mint platform-sealed user identity");

        assert_eq!(minted.identity_type, "user");
        assert!(fedcode_is_user(&minted.fedcode, &minted.key_id));

        std::env::remove_var("CIRIS_HOME");
        std::env::remove_var("CIRIS_DATA_DIR");
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&data);
        let _ = std::fs::remove_dir_all(&seed);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn minted_identity_composes_a_usable_claim_remote_signer() {
        use crate::auth::ownership;

        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let home = tmp("cr-home");
        let data = tmp("cr-data");
        let seed = tmp("cr-seed");
        std::env::set_var("CIRIS_HOME", &home);
        std::env::set_var("CIRIS_DATA_DIR", &data);

        // Mint with an explicit key_id alias so the sealed ML-DSA half is keyed
        // by a stable id we can re-open the signer under.
        let minted = mint_user_identity(
            UserIdentityBackend::Software,
            "claim-remote-user",
            None,
            seed.clone(),
        )
        .await
        .expect("mint user identity");

        // Compose the hardware-backed user LocalSigner (the claim-remote signer)
        // under the MINTED key_id, then prove it can hybrid-sign an owner-binding.
        let signer =
            hardware_user_local_signer(UserIdentityBackend::Software, &minted.key_id, seed.clone())
                .await
                .expect("compose hardware-backed user signer");

        assert_eq!(signer.key_id(), minted.key_id);

        // The substrate build/sign path used by POST /v1/setup/claim-remote.
        let infra_scopes: Vec<String> = ownership::OWNER_BINDING_INFRA_SCOPES
            .iter()
            .map(|s| s.to_string())
            .collect();
        let binding =
            ownership::build_signed_owner_binding(&signer, "target-node-key", &infra_scopes)
                .await
                .expect("build user-signed owner-binding with the minted identity");
        assert_eq!(binding.attesting_key_id, minted.key_id);

        std::env::remove_var("CIRIS_HOME");
        std::env::remove_var("CIRIS_DATA_DIR");
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&data);
        let _ = std::fs::remove_dir_all(&seed);
    }
}
