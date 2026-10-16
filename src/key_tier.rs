//! **Open a sealed key from the tier it actually lives in** — never let a
//! re-open mint (Eric's desktop, 2026-10-08; found 2026-10-16; CIRISServer#783).
//!
//! `ciris-keyring`'s `create_platform_storage` picks the BEST tier available
//! *right now*. When the TPM plugin is usable and `{alias}.tpmplugin_seal` does
//! not exist yet, `PluginTpmSecureBlobStorage::new` mints a fresh TPM master,
//! witnesses that as "the higher-tier mint landed", and archives every
//! software-tier artifact for the alias to `*.superseded-pre-v8` — even when the
//! caller was only RE-OPENING an existing key (`open_existing`, and the open half
//! of `open_or_create`). Nothing is written into the new tier, so the next load is
//! `KeyNotFound` and the identity is stranded: the node stays owned by a key it can
//! no longer wield, every owner act falls to the machine path, and consent grants
//! loop.
//!
//! A key minted under `platform-sealed` on a machine where the TPM was NOT usable
//! degrades to software storage, so this is reachable on any Linux desktop where
//! the plugin becomes loadable later (an installed `ciris_verify` ships
//! `libciris_tpm_plugin.so`; the user is in `tss`).
//!
//! The rule here: **the on-disk evidence decides the tier.** A software master
//! (`{alias}.master.key`) with no plugin seal is opened as software, directly; a
//! plugin seal is opened through the platform factory (it unseals, it does not
//! mint); only an alias with no artifacts at all goes to the factory to MINT.
//! Upstream: the keyring should make re-opens load-only at the storage layer too
//! (filed against CIRISVerify).
//!
//! And the heal: an alias left exactly as the bug leaves it — a plugin seal that
//! holds NO blob, beside a `*.superseded-pre-v8` software pair — is restored. The
//! TPM tier holds nothing, so restoring loses nothing; the orphan seal is renamed
//! aside (`*.orphaned-<unix>`), never deleted, and the restore is logged loudly.

use std::path::{Path, PathBuf};

use ciris_keyring::storage::{SecureBlobStorage, SoftwareSecureBlobStorage};
use ciris_keyring::{
    Ed25519SoftwareSigner, HardwareSigner, KeyringError, MlDsa65SoftwareSigner, PqcSigner,
    SealedEd25519Signer, SealedMlDsa65Signer,
};

/// The keyring's Ed25519 seed id inside an alias's storage (`sealed_ed25519.rs`).
const ED25519_SEED_ID: &str = "ed25519.seed";
/// The keyring's ML-DSA-65 seed id inside an alias's storage (`sealed_mldsa65.rs`).
const MLDSA65_SEED_ID: &str = "mldsa65.seed";
/// What the keyring appends when it archives a superseded artifact.
const SUPERSEDED_SUFFIX: &str = ".superseded-pre-v8";

/// Which tier an alias's key material is in, read from the files alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnDiskTier {
    /// `{alias}.tpmplugin_seal` — the plugin TPM tier.
    TpmPlugin,
    /// `{alias}.master.key` and no plugin seal — the keyring's software tier.
    Software,
    /// No file-tier artifacts for this alias: either nothing exists, or the key
    /// lives in a tier with no files here (Secure Enclave, keychain, Android
    /// Keystore) — the keyring's own open decides.
    Absent,
}

fn seal_path(alias: &str, dir: &Path) -> PathBuf {
    dir.join(format!("{alias}.tpmplugin_seal"))
}

fn software_master(alias: &str, dir: &Path) -> PathBuf {
    dir.join(format!("{alias}.master.key"))
}

/// Read the tier from disk. Never constructs storage, so it can never mint.
pub fn on_disk_tier(alias: &str, dir: &Path) -> OnDiskTier {
    if seal_path(alias, dir).exists() {
        OnDiskTier::TpmPlugin
    } else if software_master(alias, dir).exists() {
        OnDiskTier::Software
    } else {
        OnDiskTier::Absent
    }
}

/// Does the plugin tier hold any blob for `alias`?
fn plugin_tier_has_blobs(alias: &str, dir: &Path) -> bool {
    let prefix = format!("{alias}.");
    std::fs::read_dir(dir)
        .map(|it| {
            it.flatten().any(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.starts_with(&prefix) && n.ends_with(".tpmp_blob")
            })
        })
        .unwrap_or(false)
}

/// Restore an alias the keyring superseded into an EMPTY plugin tier.
///
/// Acts only when all three hold: a plugin seal exists, the plugin tier holds no
/// blob for the alias, and an archived software master
/// (`{alias}.master.key.superseded-pre-v8`) exists with no live one. Then every
/// `{alias}.*.superseded-pre-v8` whose original name is free is renamed back, and
/// the seal is renamed to `{alias}.tpmplugin_seal.orphaned-<unix>`. Returns the
/// restored paths (empty when nothing was done).
pub fn heal_orphaned_supersession(alias: &str, dir: &Path) -> Vec<PathBuf> {
    let seal = seal_path(alias, dir);
    let archived_master = dir.join(format!("{alias}.master.key{SUPERSEDED_SUFFIX}"));
    if !seal.exists()
        || plugin_tier_has_blobs(alias, dir)
        || !archived_master.exists()
        || software_master(alias, dir).exists()
    {
        return Vec::new();
    }
    let prefix = format!("{alias}.");
    let archived: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(it) => it
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(SUPERSEDED_SUFFIX))
            })
            .collect(),
        Err(_) => return Vec::new(),
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let orphan = dir.join(format!("{alias}.tpmplugin_seal.orphaned-{stamp}"));
    if let Err(e) = std::fs::rename(&seal, &orphan) {
        tracing::error!(alias, error = %e, seal = %seal.display(),
            "key heal: could not move the empty TPM seal aside — the superseded key stays archived");
        return Vec::new();
    }
    let mut restored = Vec::new();
    for from in archived {
        let name = from
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let to = dir.join(name.trim_end_matches(SUPERSEDED_SUFFIX));
        if to.exists() {
            continue;
        }
        match std::fs::rename(&from, &to) {
            Ok(()) => restored.push(to),
            Err(e) => tracing::error!(alias, error = %e, from = %from.display(),
                "key heal: could not restore a superseded artifact"),
        }
    }
    tracing::warn!(
        alias,
        restored = ?restored,
        orphaned_seal = %orphan.display(),
        "KEY RESTORED — a re-open had superseded this alias's software key into a TPM tier \
         that holds NO key (keyring re-open mint, tracked: CIRISServer#783). The TPM tier was empty, \
         so the archived key was the only key: it is back under its original name and the \
         empty seal is kept aside. Nothing was deleted."
    );
    restored
}

fn seed32(raw: Vec<u8>, what: &str) -> Result<[u8; 32], KeyringError> {
    raw.as_slice()
        .try_into()
        .map_err(|_| KeyringError::InvalidKey {
            reason: format!("{what} seed is {} bytes, expected 32", raw.len()),
        })
}

fn software_storage(alias: &str, dir: &Path) -> Result<SoftwareSecureBlobStorage, KeyringError> {
    SoftwareSecureBlobStorage::new(alias, dir)
}

/// Re-open an existing Ed25519 key — load-only, from its on-disk tier.
pub fn ed25519_open_existing(
    alias: &str,
    dir: &Path,
) -> Result<Box<dyn HardwareSigner>, KeyringError> {
    heal_orphaned_supersession(alias, dir);
    match on_disk_tier(alias, dir) {
        OnDiskTier::Software => {
            let mut seed = seed32(
                software_storage(alias, dir)?.load(ED25519_SEED_ID)?,
                "Ed25519",
            )?;
            let signer = Ed25519SoftwareSigner::from_bytes(&seed, alias.to_owned());
            seed.iter_mut().for_each(|b| *b = 0);
            Ok(Box::new(signer?))
        }
        // A plugin seal, or a tier with no files here (Secure Enclave / keychain
        // on macOS, Android Keystore): the keyring's own load-only re-open. Only
        // a recognised SOFTWARE key bypasses the factory.
        OnDiskTier::TpmPlugin | OnDiskTier::Absent => {
            Ok(Box::new(SealedEd25519Signer::open_existing(alias, dir)?))
        }
    }
}

/// Open an Ed25519 key, minting in the best tier ONLY when the alias has no
/// artifacts at all (the deliberate first mint).
pub fn ed25519_open_or_create(
    alias: &str,
    dir: &Path,
) -> Result<Box<dyn HardwareSigner>, KeyringError> {
    heal_orphaned_supersession(alias, dir);
    match on_disk_tier(alias, dir) {
        OnDiskTier::Absent => Ok(Box::new(SealedEd25519Signer::open_or_create(
            alias, dir, None,
        )?)),
        _ => ed25519_open_existing(alias, dir),
    }
}

/// Re-open an existing ML-DSA-65 key — load-only, from its on-disk tier.
pub fn mldsa65_open_existing(alias: &str, dir: &Path) -> Result<Box<dyn PqcSigner>, KeyringError> {
    heal_orphaned_supersession(alias, dir);
    match on_disk_tier(alias, dir) {
        OnDiskTier::Software => {
            let mut seed = seed32(
                software_storage(alias, dir)?.load(MLDSA65_SEED_ID)?,
                "ML-DSA-65",
            )?;
            let signer = MlDsa65SoftwareSigner::from_seed_bytes(&seed, alias.to_owned());
            seed.iter_mut().for_each(|b| *b = 0);
            Ok(Box::new(signer?))
        }
        OnDiskTier::TpmPlugin | OnDiskTier::Absent => {
            Ok(Box::new(SealedMlDsa65Signer::open_existing(alias, dir)?))
        }
    }
}

/// What [`pin_process_tier`] decided for a home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeTier {
    /// Software-tier keys and no live plugin tier: the TPM plugin is made
    /// unselectable for this process so no component can supersede them.
    PinnedSoftware,
    /// A live plugin tier exists (a seal WITH blobs): left alone.
    HasTpmKeys,
    /// No key material: a fresh home — new keys may take the best tier.
    Fresh,
}

/// The sentinel `CIRIS_TPM_PLUGIN` path that makes the keyring's plugin load
/// fail, so `create_platform_storage` never selects the TPM tier.
pub const TPM_PLUGIN_DISABLED: &str = "/nonexistent/ciris-tpm-plugin-disabled:software-tier-home";

fn scan(dir: &Path, depth: usize, found: &mut (bool, bool)) {
    let Ok(it) = std::fs::read_dir(dir) else {
        return;
    };
    for e in it.flatten() {
        let p = e.path();
        if p.is_dir() {
            if depth > 0 {
                scan(&p, depth - 1, found);
            }
            continue;
        }
        let n = e.file_name().to_string_lossy().into_owned();
        if n.ends_with(".master.key") {
            found.0 = true;
        }
        if n.ends_with(".tpmp_blob") {
            found.1 = true;
        }
    }
}

/// **Pin the whole process to the tier this home's keys live in** (#783).
///
/// The keyring's own components — CIRISEdge opening the node key at edge init,
/// persist's keyring signer under `identity/keyring/`, verify-core's identity
/// mint — open sealed keys through `create_platform_storage`, which supersedes a
/// software-tier key the moment the TPM plugin is loadable. The server cannot
/// route THEIR opens through [`ed25519_open_existing`], so it removes the hazard
/// at its source for this process: a home whose keys are all software-tier (a
/// `*.master.key` present, no plugin blob anywhere) gets `CIRIS_TPM_PLUGIN`
/// pointed at [`TPM_PLUGIN_DISABLED`] BEFORE any component opens a key. A fresh
/// home keeps TPM custody for new keys; a home with live TPM keys is untouched.
/// A deliberate software→TPM migration is a separate, explicit act (adopt).
pub fn pin_process_tier(home: &Path) -> HomeTier {
    let mut found = (false, false); // (software master, plugin blob)
    for sub in ["identity", "keys"] {
        scan(&home.join(sub), 2, &mut found);
    }
    let tier = match found {
        (_, true) => HomeTier::HasTpmKeys,
        (true, false) => HomeTier::PinnedSoftware,
        (false, false) => HomeTier::Fresh,
    };
    if tier == HomeTier::PinnedSoftware {
        let prior = std::env::var("CIRIS_TPM_PLUGIN").ok();
        if prior.as_deref() != Some(TPM_PLUGIN_DISABLED) {
            // SAFETY: called at process start (module init / the first boot
            // step), before any thread this crate spawns reads the environment.
            unsafe { std::env::set_var("CIRIS_TPM_PLUGIN", TPM_PLUGIN_DISABLED) };
            tracing::warn!(
                home = %home.display(),
                prior = ?prior,
                "keyring tier PINNED to software for this process: this home's keys live in the \
                 software tier and a newly loadable TPM plugin would supersede them on their next \
                 re-open (tracked: CIRISServer#783). The TPM stays unused until an explicit migration."
            );
            eprintln!(
                "ciris_server: keyring tier pinned to software — home {} holds software-tier keys \
                 (tracked: CIRISServer#783)",
                home.display()
            );
        }
    }
    tier
}

/// The embedded entry (PyO3 module init): the agent builds its persist Engine
/// — which opens keys — before any serve call names a home, so pin every home
/// this process could be serving: `CIRIS_HOME`, else the agent default `~/ciris`.
pub fn pin_process_tier_at_import() {
    let mut homes: Vec<PathBuf> = Vec::new();
    if let Some(h) = std::env::var_os("CIRIS_HOME") {
        homes.push(PathBuf::from(h));
    }
    if let Some(h) = std::env::var_os("HOME") {
        homes.push(PathBuf::from(h).join("ciris"));
    }
    for h in homes {
        if h.is_dir() && pin_process_tier(&h) == HomeTier::PinnedSoftware {
            return;
        }
    }
}
