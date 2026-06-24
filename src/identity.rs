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

/// Map a custody-backend marker label (written by [`write_user_backend_marker`])
/// back to a [`UserIdentityBackend`] for RE-OPENING an existing user identity.
/// YubiKey re-opens with `provision: false` (the key already exists on the token;
/// reclaiming reads it, never generates). Unknown labels default to the secure
/// platform-sealed backend.
pub(crate) fn user_backend_from_label(label: &str) -> UserIdentityBackend {
    match label {
        "software" => UserIdentityBackend::Software,
        "pkcs11-yubikey" | "pkcs11" | "yubikey" => UserIdentityBackend::Pkcs11(Pkcs11Options {
            provision: false,
            ..Pkcs11Options::default()
        }),
        _ => UserIdentityBackend::PlatformSealed,
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
            // CIRISVerify v6.13.0 (#112) resolves the public half via the private
            // key's CKA_ID, so naming the PRIVATE object by label is sufficient.
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

    // #247 (CIRISVerify#89): the RECORDED federation key_id is the FSD-003 DERIVED
    // form `derive_key_id(<alias>, <ed_pub>)` (= `<alias>-<fp>`) — the same scheme
    // the NODE uses (compose.rs `cfg.key_id`), so a peer can re-derive + verify it
    // from the pubkey. The keystore ALIAS stays the seed/seal storage key. We read
    // the pubkey BEFORE the mint to derive the id, then pass `seal_alias = <alias>`
    // so create_federation_identity seals the ML-DSA half under the alias while
    // recording the derived id — re-open by the alias reproduces it (no custody
    // migration / no lockout).
    let ed_pub_pre = hw_signer
        .public_key()
        .await
        .map_err(|e| anyhow::anyhow!("read user Ed25519 pubkey for key_id derivation: {e}"))?;
    let derived_key_id = ciris_verify_core::fedcode::derive_key_id(key_id_alias, &ed_pub_pre);

    // 2. Mint the hybrid hardware-rooted identity. verify v6.0.0 attaches the
    //    sealed ML-DSA-65 half internally + emits the genesis CEG object + the
    //    fedcode. A touch-required YubiKey blocks on the signature until tapped.
    let now = chrono::Utc::now().to_rfc3339();
    let created = create_federation_identity(
        Arc::clone(&hw_signer),
        // identity_type "user" → FedKind::User (the accountable human).
        "user",
        // Record under the DERIVED key_id (#247). `label` flows into the fedcode's
        // alias_hint.
        Some(derived_key_id.clone()),
        label,
        &now,
        // seal_alias = the keystore alias: seal/re-open the ML-DSA half (and the
        // software Ed25519 seed) under `<alias>` while the recorded id is derived.
        Some(key_id_alias),
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
    // sealed PQC half (re-opened from keys_dir, sealed under the keystore ALIAS
    // via `seal_alias` — NOT `created.key_id`, which is now the derived form).
    let ed_pub = hw_signer
        .public_key()
        .await
        .map_err(|e| anyhow::anyhow!("read user Ed25519 public key: {e}"))?;
    let pqc = ciris_keyring::get_platform_sealed_mldsa65_signer(
        key_id_alias,
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

// ─── Portable software identity occurrence (CIRISServer — bootstrap) ──────────

/// A freshly-minted **portable software** hybrid keyset: both halves as plaintext
/// seeds in a chosen directory (a USB key) + the self-signed proof-of-possession
/// record needed to register it. Unlike [`mint_user_identity`] (which seals the
/// ML-DSA-65 half under the platform secure store at `keys_dir()`), this writes
/// BOTH halves to the target directory so the keyset is genuinely portable to
/// another device — the explicitly-accepted INSECURE software trade-off.
pub struct PortableSoftwareKeyset {
    /// The derived federation `key_id` (`derive_key_id(alias, ed_pub)`).
    pub key_id: String,
    /// The keystore **alias** the seeds are named/keyed under (`derive_key_id`'s
    /// label INPUT). Carried so the associate step can re-open under the SAME alias
    /// and reproduce the SAME `key_id` (re-opening under a different alias would
    /// re-derive a DIFFERENT id — the occurrence identity would not survive the
    /// move). The mint records it in the manifest + the `.backend` filename stem.
    pub alias: String,
    /// The shareable `CIRIS-V2-…` usercode (FedKind::User).
    pub fedcode: String,
    /// Always `"user"`.
    pub identity_type: String,
    /// The new key's self-signed `SignedKeyRecord` (proof-of-possession) — pass
    /// straight to `Engine::register_federation_key`.
    pub key_record: ciris_persist::federation::SignedKeyRecord,
    /// The seed/marker filenames written into the target dir (names only — NO
    /// private bytes leave the node).
    pub files_written: Vec<String>,
}

/// The conventional portable-keyset seed filenames for an `alias`. Named by the
/// ALIAS (not the derived key_id) so re-opening under the alias reproduces the id.
fn portable_ed_seed_name(alias: &str) -> String {
    format!("{alias}.ed25519.seed")
}
fn portable_mldsa_seed_name(alias: &str) -> String {
    format!("{alias}.mldsa65.seed")
}
fn portable_backend_marker_name(alias: &str) -> String {
    format!("{alias}.backend")
}

#[cfg(unix)]
fn write_seed_0600(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    Ok(())
}
#[cfg(not(unix))]
fn write_seed_0600(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

/// **Mint a fresh portable SOFTWARE identity occurrence keyset** into `target_dir`.
///
/// Generates two 32-byte seeds (Ed25519 + ML-DSA-65), writes them as `0600` seed
/// files keyed by `alias` (`<alias>.ed25519.seed`, `<alias>.mldsa65.seed`) plus an
/// `<alias>.backend` marker into `target_dir`, derives the federation `key_id` from
/// `derive_key_id(alias, ed_pub)`, and produces the self-signed PoP
/// `SignedKeyRecord` via the verify-native `produce_self_key_record` so it
/// registers through the canonical fail-secure admission gate.
///
/// The seeds are named by `alias` (NOT the derived id) on purpose: re-opening them
/// under the SAME alias on another device reproduces the SAME `key_id`
/// (`hardware_user_local_signer` re-derives `derive_key_id(alias, ed_pub)`), so the
/// occurrence identity survives the move. `alias` is also the fedcode's alias hint.
///
/// The whole keyset is software — there is NO hardware seal. That is the labeled,
/// deliberate trade-off (a copy that can MOVE to another device). The seeds never
/// cross the wire; only the public record + filenames are returned.
pub async fn mint_portable_software_occurrence(
    target_dir: &std::path::Path,
    alias: &str,
) -> Result<PortableSoftwareKeyset> {
    use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer};
    use ciris_verify_core::self_at_login::HybridSigningIdentity;

    std::fs::create_dir_all(target_dir)
        .with_context(|| format!("create portable target dir {}", target_dir.display()))?;

    // Generate both 32-byte seeds.
    let mut ed_seed = [0u8; 32];
    let mut ml_seed = [0u8; 32];
    getrandom::fill(&mut ed_seed).map_err(|e| anyhow::anyhow!("mint ed25519 seed: {e}"))?;
    getrandom::fill(&mut ml_seed).map_err(|e| anyhow::anyhow!("mint ml-dsa-65 seed: {e}"))?;

    let ed = Ed25519Signer::from_seed(&ed_seed)
        .map_err(|e| anyhow::anyhow!("build ed25519 signer from seed: {e}"))?;
    let mldsa = MlDsa65Signer::from_seed(&ml_seed)
        .map_err(|e| anyhow::anyhow!("build ml-dsa-65 signer from seed: {e}"))?;

    let ed_pub = ed
        .public_key()
        .map_err(|e| anyhow::anyhow!("read ed25519 pubkey: {e}"))?;
    // key_id derived from the ALIAS (the re-open input) so a device re-opening the
    // seeds under `alias` reproduces this exact id.
    let key_id = fedcode::derive_key_id(alias, &ed_pub);

    // The hybrid identity (a verify SelfSigner) over the two software halves.
    let identity = HybridSigningIdentity::new(key_id.clone(), ed, mldsa);

    // Self-signed genesis proof-of-possession (the exact bytes the persist
    // register gate recomputes). Bridged verify→persist by the structurally
    // identical JSON shape (the accord-holder path round-trips the same way).
    let now = chrono::Utc::now().to_rfc3339();
    let v_rec =
        ciris_verify_core::federation_self_record::produce_self_key_record(&identity, "user", &now)
            .await
            .map_err(|e| anyhow::anyhow!("produce portable self key record: {e}"))?;
    let key_record: ciris_persist::federation::SignedKeyRecord =
        serde_json::from_value(serde_json::to_value(&v_rec)?)
            .map_err(|e| anyhow::anyhow!("bridge verify→persist SignedKeyRecord: {e}"))?;

    // The shareable usercode.
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let fedcode = fedcode::encode(&fedcode::FedCode {
        kind: fedcode::FedKind::User,
        key_id: key_id.clone(),
        pubkey_ed25519_base64: b64.encode(&ed_pub),
        transport_hint: None,
        alias_hint: Some(alias.to_string()),
        group_key_id: None,
    })
    .map_err(|e| anyhow::anyhow!("encode portable fedcode: {e}"))?;

    // Persist BOTH seeds + the custody marker to the target dir (0600), keyed by the
    // alias. Only AFTER the record is built, so a crypto failure leaves no partial
    // keyset behind.
    let ed_path = target_dir.join(portable_ed_seed_name(alias));
    let ml_path = target_dir.join(portable_mldsa_seed_name(alias));
    let marker_path = target_dir.join(portable_backend_marker_name(alias));
    write_seed_0600(&ed_path, &ed_seed)?;
    write_seed_0600(&ml_path, &ml_seed)?;
    std::fs::write(&marker_path, "software")
        .with_context(|| format!("write {}", marker_path.display()))?;

    Ok(PortableSoftwareKeyset {
        key_id,
        alias: alias.to_string(),
        fedcode,
        identity_type: "user".to_string(),
        key_record,
        files_written: vec![
            portable_ed_seed_name(alias),
            portable_mldsa_seed_name(alias),
            portable_backend_marker_name(alias),
        ],
    })
}

/// **Install a portable software keyset** read from `source_dir` as THIS device's
/// active user fed-ID, KEYED by the SAME `alias` it was minted under (so re-opening
/// it on this device reproduces the SAME `key_id` — the occurrence identity is
/// preserved). Copies the `<alias>.{ed25519,mldsa65}.seed` halves + writes the
/// `<alias>.backend` marker into `dest_dir`, and re-seals the ML-DSA-65 half under
/// `alias` into the platform `keys_dir()`.
///
/// The local node resolves the user signer via
/// `hardware_user_local_signer(Software, alias, dest_dir)` — the Ed25519 seed is
/// read from `dest_dir` and the sealed ML-DSA-65 half from `keys_dir()`, BOTH keyed
/// by `alias`. So after this, opening the signer under `alias` yields the portable
/// occurrence key. Returns the destination filenames written. No private bytes are
/// returned.
pub fn install_portable_software_keyset(
    source_dir: &std::path::Path,
    alias: &str,
    dest_dir: &std::path::Path,
) -> Result<Vec<String>> {
    std::fs::create_dir_all(dest_dir)
        .with_context(|| format!("create dest seed dir {}", dest_dir.display()))?;

    let mut installed = Vec::new();

    // (1) Ed25519 seed → dest_dir/<alias>.ed25519.seed (what the software signer
    //     re-opens under the alias to reproduce the key_id).
    let src_ed = source_dir.join(portable_ed_seed_name(alias));
    let ed_bytes = std::fs::read(&src_ed)
        .with_context(|| format!("read portable ed25519 seed {}", src_ed.display()))?;
    let dst_ed = dest_dir.join(portable_ed_seed_name(alias));
    write_seed_0600(&dst_ed, &ed_bytes)?;
    installed.push(portable_ed_seed_name(alias));

    // (2) Custody marker → software.
    let dst_marker = dest_dir.join(portable_backend_marker_name(alias));
    std::fs::write(&dst_marker, "software")
        .with_context(|| format!("write {}", dst_marker.display()))?;
    installed.push(portable_backend_marker_name(alias));

    // (3) Re-seal the portable ML-DSA-65 half under `alias` into keys_dir() so
    //     `hardware_user_local_signer` re-opens the PQC half. Best-effort: a missing
    //     PQC seed degrades to Ed25519-only (logged), never a hard failure.
    let src_ml = source_dir.join(portable_mldsa_seed_name(alias));
    match std::fs::read(&src_ml) {
        Ok(ml_bytes) => match reseal_portable_mldsa(&ml_bytes, alias) {
            Ok(()) => installed.push(format!("{alias} (ML-DSA-65 re-sealed)")),
            Err(e) => tracing::warn!(
                alias = %alias, error = %e,
                "associate: could not re-seal the ML-DSA-65 half — the associated identity may \
                 sign Ed25519-only until the PQC half is provisioned"
            ),
        },
        Err(e) => tracing::warn!(
            path = %src_ml.display(), error = %e,
            "associate: no portable ML-DSA-65 seed found — associating Ed25519-only"
        ),
    }

    Ok(installed)
}

/// Discover the portable keyset's **alias** in `dir` by its `<alias>.ed25519.seed`
/// file. Errors if none / more than one (ambiguous). The alias is what the install
/// + re-open key on (re-opening under it reproduces the occurrence `key_id`).
pub fn find_portable_alias(dir: &std::path::Path) -> Result<String> {
    let mut found: Vec<String> = Vec::new();
    let entries = std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))?;
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if let Some(stem) = name.strip_suffix(".ed25519.seed") {
                found.push(stem.to_string());
            }
        }
    }
    match found.len() {
        0 => anyhow::bail!(
            "no portable keyset found in {} — expected an <alias>.ed25519.seed file",
            dir.display()
        ),
        1 => Ok(found.remove(0)),
        _ => anyhow::bail!(
            "{} portable keysets found in {} — point source_dir at a folder with exactly one",
            found.len(),
            dir.display()
        ),
    }
}

/// Re-seal a raw 32-byte ML-DSA-65 seed under `alias` into the platform
/// `keys_dir()` so `get_platform_sealed_mldsa65_signer(alias, keys_dir())` re-opens
/// it. Uses the keyring's `open_or_create(alias, keys_dir, adopt_seed)` import path
/// — the software backend AES-GCM-SEALS the adopted seed at rest (not a plaintext
/// file), so this is a true re-seal, not a raw copy. Idempotent: if a seed is
/// already sealed under `alias` it is adopted verbatim and we error iff it differs
/// (never silently clobber a distinct local PQC half).
fn reseal_portable_mldsa(seed: &[u8], alias: &str) -> Result<()> {
    use ciris_keyring::sealed_mldsa65::SealedMlDsa65Signer;

    let seed32: [u8; 32] = seed
        .try_into()
        .map_err(|_| anyhow::anyhow!("ML-DSA-65 seed must be 32 bytes, got {}", seed.len()))?;
    let keys_dir = ciris_verify_core::ceg_outbox::keys_dir();
    std::fs::create_dir_all(&keys_dir)
        .with_context(|| format!("create keys_dir {}", keys_dir.display()))?;
    // adopt_seed seals the supplied seed ONLY when no seed is yet stored under the
    // alias; an existing sealed seed is adopted as-is. Building the signer proves
    // the seal round-trips.
    SealedMlDsa65Signer::open_or_create(alias, &keys_dir, Some(&seed32))
        .map_err(|e| anyhow::anyhow!("seal portable ML-DSA-65 seed under {alias}: {e}"))?;
    Ok(())
}

/// Compose the minted USER identity into a persist
/// [`LocalSigner`](ciris_persist::prelude::LocalSigner) for `POST /v1/setup/
/// claim-remote`: the Ed25519 half stays hardware-custodied (signs through the
/// `HardwareSigner`), the ML-DSA-65 half is the sealed PQC signer. The resulting
/// signer's `sign_hybrid` is what `ownership::build_signed_owner_binding` uses.
///
/// `user_key_id` is the keystore ALIAS the identity's seed/seal are stored under
/// (`<keystore_alias>-user`) — the `derive_key_id` INPUT, not the wire id. The
/// returned signer's `key_id()` is the #247 DERIVED federation key_id
/// (`derive_key_id(<alias>, <ed_pub>)`), which is what the identity is RECORDED
/// under (see [`mint_user_identity`]) — so every `signer.key_id()` downstream
/// (the owner-binding attester, the age subject, the device-grant owner id) is
/// the correct registered federation id, while the Ed25519 seed + the sealed
/// ML-DSA-65 half are still re-opened under the stable alias (no re-key).
pub async fn hardware_user_local_signer(
    backend: UserIdentityBackend,
    user_key_id: &str,
    seed_dir: PathBuf,
) -> Result<ciris_persist::prelude::LocalSigner> {
    let cfg = user_identity_config(&backend, user_key_id, seed_dir);
    let hw = open_user_signer(&backend, &cfg)?;
    // Derive the recorded federation key_id from the alias + the opened pubkey
    // (the value mint recorded the identity under).
    let ed_pub = hw
        .public_key()
        .await
        .map_err(|e| anyhow::anyhow!("read user Ed25519 pubkey for key_id derivation: {e}"))?;
    let derived_key_id = ciris_verify_core::fedcode::derive_key_id(user_key_id, &ed_pub);
    let classical: Arc<dyn HardwareSigner> = Arc::from(hw);

    // The ML-DSA-65 half + the Ed25519 seed were sealed/stored under the ALIAS
    // (`seal_alias` at mint time); re-open under the alias.
    let pqc = ciris_keyring::get_platform_sealed_mldsa65_signer(
        user_key_id,
        ciris_verify_core::ceg_outbox::keys_dir(),
    )
    .map_err(|e| anyhow::anyhow!("re-open sealed ML-DSA-65 half for the user signer: {e}"))?;
    let pqc: Arc<dyn PqcSigner> = Arc::from(pqc);
    let pqc_key_id = format!("{user_key_id}-pqc");

    // key_id = the DERIVED federation id; the Ed25519/ML-DSA blobs stay under the
    // alias (opened above). `signer.key_id()` is therefore the registered wire id.
    ciris_persist::prelude::LocalSigner::from_hardware_parts(
        classical,
        derived_key_id,
        Some(pqc),
        Some(pqc_key_id),
    )
    .await
    .map_err(|e| anyhow::anyhow!("compose hardware-backed user LocalSigner: {e}"))
}

/// Open the holder's **already-provisioned** YubiKey PIV Ed25519 key as a
/// [`HardwareSigner`] (no provisioning — the holder did the FIPS / `ykman` prep
/// out of band; we only DETECT + USE the slot-9c key). Reuses the SAME PKCS#11
/// machinery [`mint_user_identity`] uses ([`open_user_signer`] →
/// [`get_user_identity_signer`]), so the accord-holder provisioning flow does
/// not reinvent the token open.
///
/// `provision` is forced `false`: a missing key is a plain error (the prep was
/// not done), never a silent generate — generating the accord-holder's classical
/// half is the holder's deliberate out-of-band FIPS ceremony, not the node's.
///
/// Gated behind the `pkcs11` cargo feature: without it `ciris-keyring`'s
/// `Pkcs11` backend honestly returns `NotSupported`, which surfaces here as a
/// clear open error (the caller maps it to a NotSupported response).
pub fn open_yubikey_ed25519_signer(opts: Pkcs11Options) -> Result<Box<dyn HardwareSigner>> {
    let backend = UserIdentityBackend::Pkcs11(Pkcs11Options {
        provision: false,
        ..opts
    });
    // The PKCS#11 user-identity config keys the signer open. The accord-holder
    // Ed25519 lives in the PIV slot directly (no seed_dir blob is read for the
    // YubiKey backend), so a throwaway seed_dir is fine.
    let cfg = user_identity_config(&backend, "accord-holder", std::env::temp_dir());
    open_user_signer(&backend, &cfg)
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
    // Apex act — owner-gated ONCE the node is owned. During first-run (no ROOT
    // yet) there is no owner to authenticate as, and minting the founder's fed-ID
    // is itself part of becoming the owner, so the gate opens (the route is also
    // loopback-only via the setup-route guard). Mirrors the agent's
    // require_setup_mode: open during first-run, owner-gated after.
    if !crate::auth::bootstrap::is_first_run(&st.engine).await {
        if let Err(resp) = require_owner(&st.engine, &headers).await {
            return resp;
        }
    } else {
        tracing::info!("self-identity: first-run (no ROOT) — minting fed-ID without an owner session (loopback-only)");
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

    let backend_label = backend.label();
    match mint_user_identity(backend, &alias, req.label.as_deref(), st.seed_dir.clone()).await {
        Ok(minted) => {
            // Record WHICH custody backend minted this identity, so the claim-remote
            // signer (resolved at request time) re-opens it with the SAME backend
            // (software seed file / TPM-sealed / YubiKey). Without this, resolution
            // would guess `software` and miss a platform-sealed or YubiKey mint.
            write_user_backend_marker(&st.seed_dir, &alias, backend_label);
            (
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
                .into_response()
        }
        Err(e) => http_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("mint user identity: {e}"),
        ),
    }
}

/// Path of the per-user-identity custody marker (`<seed_dir>/<alias>.backend`).
fn user_backend_marker_path(seed_dir: &std::path::Path, alias: &str) -> PathBuf {
    seed_dir.join(format!("{alias}.backend"))
}

/// Record which custody backend minted the user identity (best-effort; a failure
/// to write only degrades claim-remote signer resolution, never the mint itself).
fn write_user_backend_marker(seed_dir: &std::path::Path, alias: &str, backend_label: &str) {
    let path = user_backend_marker_path(seed_dir, alias);
    if let Err(e) = std::fs::write(&path, backend_label) {
        tracing::warn!(marker = %path.display(), error = %e, "could not write user backend marker");
    }
}

/// Read the recorded custody backend for the user identity, if any. Returns the
/// backend label written by [`write_user_backend_marker`] (e.g. `platform-sealed`).
pub(crate) fn read_user_backend_marker(seed_dir: &std::path::Path, alias: &str) -> Option<String> {
    std::fs::read_to_string(user_backend_marker_path(seed_dir, alias))
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
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
        // #247: the federation key_id is the DERIVED form `derive_key_id(<alias>,
        // <ed_pub>)` = `ciris-user-<fp>` (the alias is the seed/seal storage key,
        // not the wire id). The fedcode below decodes to exactly this derived id.
        assert!(
            minted.key_id.starts_with("ciris-user-") && minted.key_id.len() > "ciris-user-".len(),
            "expected a derived `ciris-user-<fp>` key_id, got {}",
            minted.key_id
        );
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
        // by re-opening under the keystore ALIAS (what prod callers pass), then
        // prove its key_id() is the DERIVED id mint recorded (#247 roundtrip) and
        // that it can hybrid-sign an owner-binding.
        let signer = hardware_user_local_signer(
            UserIdentityBackend::Software,
            "claim-remote-user",
            seed.clone(),
        )
        .await
        .expect("compose hardware-backed user signer");

        assert_eq!(
            signer.key_id(),
            minted.key_id,
            "re-open by alias reproduces the recorded derived key_id"
        );

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
