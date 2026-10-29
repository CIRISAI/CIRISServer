//! **A released device wipes itself and starts over** (steward, 2026-10-29).
//!
//! Releasing a device is the owner's roster acting: from two roster keys the
//! eviction is held until a quorum lands it (CC 3.3.6.3, persist's roster
//! door; `self_devices::evict_device`). The owner's data belongs to the
//! roster, never the device: nothing is handed to whoever has the hardware
//! next, and a person who wants a new owner to have something shares it with
//! them. So once its eviction has landed, the device erases everything it held
//! and comes back as a brand-new node — a new node key, a new NodeCode, a new
//! claim PIN — that anyone can claim.
//!
//! Two halves, because nothing is deleted under a running store:
//!
//! 1. **[`released_by`] / [`spawn_release_watch`]** — while running, the node
//!    asks whether its own occurrence under a former owner has been revoked:
//!    an owner-binding names this node, and every occurrence the owner held for
//!    it is out of the owner's active roster. persist decides that from the
//!    signed eviction rows, so a held proposal never trips it, only a landed
//!    one. Then it writes [`MARKER`] and asks the node to stop.
//! 2. **[`wipe_if_released`]** — at the next boot, before any key is opened,
//!    the marker means: delete the data and identity directories (the node
//!    key, the transport identity, the keyring, every user seed), the claim
//!    PIN and the device-auth session; then boot as a fresh node.
//!
//! A device that is off, or in a thief's hands and never reconnects, cannot be
//! made to wipe; it wipes the next time it sees the rows. The roster's own
//! protection does not wait for it: the self room's next epoch excludes it.

use std::path::Path;
use std::sync::Arc;

use ciris_persist::prelude::Engine;

use crate::attestation_reads::AllAttestations as _;
use serde::{Deserialize, Serialize};

use crate::config::ServerConfig;

/// Written in the node's home when its release has landed; read and acted on
/// at the next boot.
pub const MARKER: &str = "released.json";

/// Left in the home by a wipe: when it happened, and nothing about who owned
/// the device. `GET /v1/setup/status` reports it while the node is unclaimed,
/// so the first-run screen can say "this device was released and erased"
/// rather than show a node that simply went away.
pub const WIPED: &str = "wiped.json";

/// When this home was wiped after a release, if it was.
#[must_use]
pub fn wiped_at(home: &Path) -> Option<String> {
    let body = std::fs::read_to_string(home.join(WIPED)).ok()?;
    serde_json::from_str::<serde_json::Value>(&body)
        .ok()?
        .get("wiped_at")?
        .as_str()
        .map(str::to_owned)
}

/// The device-auth session file the setup routes keep in the home.
const DEVICE_AUTH_SESSION: &str = ".device_auth_session.json";

/// Why this node is wiping: who released it and which of its occurrences the
/// roster revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Released {
    pub owner_key_id: String,
    pub occurrences: Vec<String>,
}

/// **Has this node's owner released it?** `Some` when an owner-binding names
/// this node and every occurrence that owner held for it is revoked. `None`
/// otherwise, including on a node nobody ever owned and on one whose eviction
/// is only proposed.
///
/// `roster_key` is this device's own roster key (`<fedID>-<fp>`) when it
/// joined by approval: that, not the node key, is its occurrence under the
/// owner, and it is resolved once while the device is still on the roster (a
/// revoked roster key no longer opens as an owner pen).
///
/// # Errors
/// A directory read failed.
pub async fn released_by(
    engine: &Engine,
    roster_key: Option<&str>,
) -> anyhow::Result<Option<Released>> {
    let node = crate::node_key::this_node_id(engine).await?;
    let mut mine = vec![node.clone()];
    if let Some(k) = roster_key {
        mine.push(k.to_owned());
    }
    if let Ok(engine_key) = engine.local_derived_key_id().await {
        for k in crate::peer::own_keys_of_this_node(&engine_key) {
            if !mine.contains(&k) {
                mine.push(k);
            }
        }
    }
    released_by_keys(engine.federation_directory().as_ref(), &mine).await
}

/// [`released_by`] for a node known by `mine` (its node key and every key that
/// is this node), over `dir`.
///
/// # Errors
/// A directory read failed.
pub async fn released_by_keys(
    dir: &dyn ciris_persist::federation::FederationDirectory,
    mine: &[String],
) -> anyhow::Result<Option<Released>> {
    // The owners that ever bound this node: the attesters of owner-bindings
    // naming it, as the selves they signed for.
    let mut owners: Vec<String> = Vec::new();
    for key in mine {
        let rows = dir
            .attestations_to_all(key)
            .await
            .map_err(|e| anyhow::anyhow!("attestations_to_all({key}): {e}"))?;
        for r in rows.iter().filter(|r| {
            r.attestation_type == ciris_persist::federation::types::attestation_type::DELEGATES_TO
                && r.attestation_envelope
                    .get("delegation_purpose")
                    .and_then(serde_json::Value::as_str)
                    == Some(crate::auth::ownership::OWNER_BINDING_PURPOSE)
        }) {
            let me = ciris_persist::federation::self_roster::self_of_at(
                dir,
                &r.attesting_key_id,
                chrono::Utc::now(),
            )
            .await
            .unwrap_or_else(|_| r.attesting_key_id.clone());
            if !owners.contains(&me) {
                owners.push(me);
            }
        }
    }
    for owner in owners {
        let all = dir
            .list_identity_occurrences_for(&owner)
            .await
            .map_err(|e| anyhow::anyhow!("list_identity_occurrences_for({owner}): {e}"))?;
        let held: Vec<String> = all
            .into_iter()
            .map(|o| o.occurrence_key_id)
            .filter(|k| mine.iter().any(|m| m == k))
            .collect();
        if held.is_empty() {
            continue;
        }
        let active = dir
            .list_identity_occurrences_active(&owner)
            .await
            .map_err(|e| anyhow::anyhow!("list_identity_occurrences_active({owner}): {e}"))?;
        if active.iter().any(|o| held.contains(&o.occurrence_key_id)) {
            continue;
        }
        let mut occurrences = held;
        occurrences.sort();
        occurrences.dedup();
        return Ok(Some(Released {
            owner_key_id: owner,
            occurrences,
        }));
    }
    Ok(None)
}

/// Record the release in the home and ask the node to stop; the wipe runs at
/// the next boot.
///
/// # Errors
/// The marker could not be written.
pub fn mark_released(home: &Path, released: &Released) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "owner_key_id": released.owner_key_id,
        "occurrences": released.occurrences,
        "marked_at": chrono::Utc::now().to_rfc3339(),
    });
    std::fs::write(home.join(MARKER), serde_json::to_vec_pretty(&body)?)
        .map_err(|e| anyhow::anyhow!("write {}: {e}", home.join(MARKER).display()))
}

/// **Wipe a released node at boot.** When [`MARKER`] is in the home, delete
/// the data and identity directories, the claim PIN and the device-auth
/// session, then the marker itself. Returns whether it wiped. Runs before any
/// key is opened, so the node that boots after it is a new node.
///
/// # Errors
/// A path that exists could not be removed; the marker stays, so the next boot
/// tries again rather than booting on half a node.
pub fn wipe_if_released(cfg: &ServerConfig) -> anyhow::Result<bool> {
    let marker = cfg.home.join(MARKER);
    if !marker.exists() {
        return Ok(false);
    }
    let why = std::fs::read_to_string(&marker).unwrap_or_default();
    tracing::warn!(
        home = %cfg.home.display(),
        marker = %why.trim(),
        "RELEASED BY ITS OWNER'S ROSTER — wiping this node: its data, its keys and its identity \
         are deleted and it boots as a new, unclaimed node. The owner's data belongs to their \
         roster, never to this device."
    );
    for dir in [&cfg.data_dir, &cfg.identity_dir] {
        if dir.exists() {
            std::fs::remove_dir_all(dir)
                .map_err(|e| anyhow::anyhow!("wipe {}: {e}", dir.display()))?;
        }
    }
    for file in [cfg.claim_pin_file(), cfg.home.join(DEVICE_AUTH_SESSION)] {
        if file.exists() {
            std::fs::remove_file(&file)
                .map_err(|e| anyhow::anyhow!("wipe {}: {e}", file.display()))?;
        }
    }
    // What the first-run screen reads: when, never whose.
    let _ = std::fs::write(
        cfg.home.join(WIPED),
        serde_json::json!({ "wiped_at": chrono::Utc::now().to_rfc3339() }).to_string(),
    );
    std::fs::remove_file(&marker)
        .map_err(|e| anyhow::anyhow!("remove {}: {e}", marker.display()))?;
    tracing::warn!(
        home = %cfg.home.display(),
        "wipe complete — booting as a new node; claim it with the PIN printed below"
    );
    Ok(true)
}

/// How often a running node asks whether it has been released.
const WATCH_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// **Watch for this node's release** for the life of the process: on the
/// first tick that finds it released, mark the home and stop the node.
pub fn spawn_release_watch(
    engine: Arc<Engine>,
    home: std::path::PathBuf,
    roster_key: Option<String>,
) {
    tokio::spawn(async move {
        let mut cadence = crate::loop_cadence::Cadence::new("device_release", WATCH_EVERY);
        loop {
            cadence.tick().await;
            match released_by(&engine, roster_key.as_deref()).await {
                Ok(Some(released)) => {
                    match mark_released(&home, &released) {
                        Ok(()) => tracing::warn!(
                            owner = %released.owner_key_id,
                            occurrences = ?released.occurrences,
                            "this node was RELEASED by its owner's roster (the eviction \
                             landed) — stopping; it wipes itself and starts over unclaimed at \
                             the next boot"
                        ),
                        Err(e) => {
                            tracing::error!(error = %format!("{e:#}"), "release marker not written; \
                                will retry");
                            continue;
                        }
                    }
                    crate::node_control::request_shutdown_from("released by its owner's roster");
                    return;
                }
                Ok(None) => {}
                Err(e) => tracing::debug!(error = %format!("{e:#}"), "release watch: read failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_in(home: &Path) -> ServerConfig {
        ServerConfig::from_home(home.to_path_buf(), "ciris-test".into()).expect("config")
    }

    #[test]
    fn a_marked_home_is_wiped_and_an_unmarked_one_is_not() {
        let home = std::env::temp_dir().join(format!(
            "ciris-release-wipe-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let cfg = cfg_in(&home);
        cfg.ensure_dirs().unwrap();
        std::fs::write(cfg.data_dir.join("engine.db"), b"rows").unwrap();
        std::fs::write(cfg.identity_dir.join("node.seed"), b"key").unwrap();
        std::fs::write(cfg.claim_pin_file(), b"1234-5678").unwrap();
        std::fs::write(home.join("operator.toml"), b"kept").unwrap();

        assert!(!wipe_if_released(&cfg).unwrap(), "no marker, nothing wiped");
        assert!(cfg.data_dir.join("engine.db").exists());

        mark_released(
            &home,
            &Released {
                owner_key_id: "owner-x".into(),
                occurrences: vec!["node-y".into()],
            },
        )
        .unwrap();
        assert!(wipe_if_released(&cfg).unwrap());
        assert!(!cfg.data_dir.exists() && !cfg.identity_dir.exists());
        assert!(!cfg.claim_pin_file().exists());
        assert!(!home.join(MARKER).exists(), "the marker goes last");
        assert!(
            wiped_at(&home).is_some(),
            "the wipe is reported, when and not whose"
        );
        assert!(
            !std::fs::read_to_string(home.join(WIPED))
                .unwrap()
                .contains("owner-x"),
            "nothing of the former owner survives the wipe"
        );
        assert!(
            home.join("operator.toml").exists(),
            "what the operator put in the home is theirs, not the owner's"
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}
