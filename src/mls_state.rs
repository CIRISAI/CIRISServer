//! **Durable MLS state** (CIRISServer#630, edge v32 CIRISEdge#676,
//! `FSD/MLS_STATE_AT_REST.md` in CIRISEdge).
//!
//! Every room this node is in (the owner's self room and every chat room)
//! keeps its MLS group state (ratchet tree, epoch secrets, own leaf, signer)
//! in ONE sealed store per node, opened once at boot and rooted in persist's
//! single hardware-sealed seed. Before this, each room opened its own
//! in-memory store keyed by the room id, so a restart lost every group and the
//! KeyPackage material a pending Welcome was sealed to. A restarted device
//! could never rejoin its own self room (`decide` saw its stale leaf as
//! present and never Welcomed it again).
//!
//! # What lives where
//!
//! - **The key is persist's** (`XChaChaKvStore::open_mls_state`, HKDF from
//!   the one sealed seed under `mls-state-at-rest-v1`). This module derives
//!   nothing. A room id is public; a store keyed by one is a store keyed by
//!   nothing, which is why the old per-room in-memory stores were never
//!   written to disk.
//! - **No seed, no durable store.** A host without hardware custody (no TPM,
//!   Keystore or Secure Enclave; CI runners) gets
//!   `ScopeStateProvider::ephemeral()`, the pre-#630 behaviour, stated as such
//!   in the boot log. A store that EXISTS and will not open is not papered
//!   over: it is logged at ERROR by name and the node runs ephemeral, so the
//!   operator can inspect the store rather than lose it.
//! - **One store per NODE, keyed by the node's key id.** In-process tests run
//!   several nodes in one process, and two nodes of one pair room share its
//!   room id. A process-wide single store would mix their groups. A node that
//!   registered no store (every test fixture) gets its own ephemeral one on
//!   first use.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use ciris_edge::mls::cohort_group::CohortKeyMaterial;
use ciris_edge::mls::{CohortGroup, ScopeStateProvider};

/// The retained-epoch window every room here opens with (the value both
/// drives already used).
pub const RETAINED_EPOCHS: u64 = 16;

/// How this node's MLS state is held, as the boot log and `/v1/health`-style
/// readers state it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Posture {
    /// Sealed on disk under persist's hardware-rooted key: groups survive a
    /// restart.
    Durable { path: String },
    /// In memory: a restart loses every group, and a restarted device rejoins
    /// by publishing a fresh KeyPackage (the rejoin rule, `Rejoin` at the
    /// holder).
    Ephemeral { reason: String },
}

/// `(store, posture, explicit)` — `explicit` for a store a host registered on
/// purpose (`register_for_node`), which the boot open must not replace.
type Registry = HashMap<String, (ScopeStateProvider, Posture, bool)>;

fn registry() -> &'static Mutex<Registry> {
    static R: OnceLock<Mutex<Registry>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Open this node's store at `path` ONCE, at boot, and register it for
/// `node_key_id`. Never fails the boot: every outcome is a posture, and the
/// degraded ones are logged by name.
pub async fn open_for_node(node_key_id: &str, path: &Path) -> Posture {
    use ciris_edge::mls::scope_state::{open_mls_state, MlsStateUnavailable};
    // A store the embedding host registered ON PURPOSE (an operator
    // passphrase store, edge FSD §1) is kept: opening over it would replace a
    // durable store with an ephemeral one on a host with no hardware seed, and
    // record a posture that skips the boot re-address (Codex, #689).
    if let Some(p) = explicit_posture(node_key_id) {
        tracing::info!(posture = ?p, "MLS state: keeping the store the host registered for this node");
        return p;
    }
    let (store, posture) = match open_mls_state(path).await {
        Ok(store) => {
            let posture = Posture::Durable {
                path: path.display().to_string(),
            };
            tracing::info!(
                path = %path.display(),
                "MLS state DURABLE — every room's group state is sealed on disk under persist's \
                 hardware-rooted key; rooms survive a restart (CIRISServer#630)"
            );
            (store, posture)
        }
        Err(MlsStateUnavailable::HardwareCustodyUnavailable(detail)) => {
            tracing::warn!(
                detail = %detail,
                "MLS state EPHEMERAL — this host has no hardware-sealed seed to root the store in, \
                 so room state lives in memory: a restart loses every group, and this device \
                 rejoins its rooms by publishing a fresh KeyPackage (CIRISServer#630)"
            );
            (
                ScopeStateProvider::ephemeral(),
                Posture::Ephemeral {
                    reason: format!("hardware custody unavailable: {detail}"),
                },
            )
        }
        Err(e) => {
            tracing::error!(
                path = %path.display(),
                error = %e,
                "MLS state store EXISTS and will NOT open (wrong key, tampered rows or a backend \
                 fault) — running with EPHEMERAL room state rather than overwrite it. Inspect \
                 the store before deleting anything (CIRISServer#630)"
            );
            (
                ScopeStateProvider::ephemeral(),
                Posture::Ephemeral {
                    reason: format!("store refused to open: {e}"),
                },
            )
        }
    };
    if let Ok(mut r) = registry().lock() {
        r.insert(node_key_id.to_owned(), (store, posture.clone(), false));
    }
    posture
}

fn explicit_posture(node_key_id: &str) -> Option<Posture> {
    registry()
        .lock()
        .ok()
        .and_then(|r| r.get(node_key_id).filter(|e| e.2).map(|e| e.1.clone()))
}

/// Release `node_key_id`'s store: its opened KV and state-access key go with
/// it. Called at serve teardown and on a failed boot, because the embedded
/// restart flow can serve another identity in the same process and the
/// registry would otherwise hold every stopped identity's store (Codex, #689).
/// An explicit registration is released too: the host registers again before
/// the next serve if it wants one.
pub fn unregister(node_key_id: &str) {
    if let Ok(mut r) = registry().lock() {
        r.remove(node_key_id);
    }
}

/// Unregisters its node's store when dropped — held by the serve function for
/// its whole life, so a teardown AND every early return of a failed boot
/// release the store without each path remembering to.
pub struct Registration(String);

impl Registration {
    pub fn new(node_key_id: &str) -> Self {
        Self(node_key_id.to_owned())
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        unregister(&self.0);
    }
}

/// Delete `room`'s durable state (group, join map, pending material) — for a
/// room this node INTENTIONALLY drops (abandoned in a creation contest, or a
/// removal whose Commit could not be placed). Without it the reload on the
/// next tick restores the very group the drive just discarded (Codex, #689).
pub async fn forget(store: &ScopeStateProvider, room: &str) {
    if let Err(e) = store.forget_room(room).await {
        tracing::warn!(%room, error = %e, "the dropped room's durable MLS state could not be deleted — the next reload may restore it");
    }
}

/// Register `store` for `node_key_id` directly: an operator-passphrase store
/// (edge FSD §1, the phone-class tier) or a test's on-disk store. Replaces any
/// store already registered for the node.
pub fn register_for_node(node_key_id: &str, store: ScopeStateProvider, posture: Posture) {
    if let Ok(mut r) = registry().lock() {
        r.insert(node_key_id.to_owned(), (store, posture, true));
    }
}

/// This node's store. A node that registered none gets its own ephemeral one,
/// created on first use and kept for the process's life.
pub fn store_for(node_key_id: &str) -> ScopeStateProvider {
    let mut r = match registry().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    r.entry(node_key_id.to_owned())
        .or_insert_with(|| {
            (
                ScopeStateProvider::ephemeral(),
                Posture::Ephemeral {
                    reason: "no store opened for this node (in-process)".to_owned(),
                },
                false,
            )
        })
        .0
        .clone()
}

/// This node's posture, when a store has been opened or created for it.
pub fn posture_for(node_key_id: &str) -> Option<Posture> {
    registry()
        .lock()
        .ok()
        .and_then(|r| r.get(node_key_id).map(|(_, p, _)| p.clone()))
}

/// Reload `room`'s group from the store, if this node persisted one — the
/// restart path. `Ok(None)`: this node never had the room (or runs ephemeral).
pub async fn load(store: &ScopeStateProvider, room: &str) -> Result<Option<CohortGroup>, String> {
    CohortGroup::load(store.clone(), room, RETAINED_EPOCHS)
        .await
        .map_err(|e| format!("reload the MLS group for {room}: {e}"))
}

/// Keep a published KeyPackage's private material across a restart, so the
/// Welcome sealed to it can still be consumed (edge FSD §3). One slot per
/// room; the newest publication wins.
pub async fn stash_pending(store: &ScopeStateProvider, room: &str, material: &CohortKeyMaterial) {
    let bytes = match ciris_edge::mls::key_material_to_bytes(material) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(%room, error = %e, "pending-join material could not be encoded — a restart before the Welcome will need a fresh KeyPackage");
            return;
        }
    };
    if let Err(e) = store.pending_join_put(room, &bytes).await {
        tracing::warn!(%room, error = %e, "pending-join material not stashed — a restart before the Welcome will need a fresh KeyPackage");
    }
}

/// The stashed material for `room`, if a KeyPackage was published and no
/// Welcome consumed it yet.
pub async fn restore_pending(store: &ScopeStateProvider, room: &str) -> Option<CohortKeyMaterial> {
    match store.pending_join_get(room).await {
        Ok(Some(bytes)) => match ciris_edge::mls::key_material_from_bytes(&bytes) {
            Ok(m) => Some(m),
            Err(e) => {
                tracing::warn!(%room, error = %e, "stashed pending-join material is unreadable — minting a fresh KeyPackage");
                None
            }
        },
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(%room, error = %e, "pending-join material unreadable — minting a fresh KeyPackage");
            None
        }
    }
}

/// The room's state now supersedes the pending material (edge's
/// `CohortGroups::join` does the same).
pub async fn clear_pending(store: &ScopeStateProvider, room: &str) {
    if let Err(e) = store.pending_join_delete(room).await {
        tracing::debug!(%room, error = %e, "pending-join material not cleared after the join");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A store ON DISK under a fixed test passphrase: the restart is a second
    /// open of the same file, which is exactly what a durable node does.
    fn disk_store(path: &Path) -> ScopeStateProvider {
        ScopeStateProvider::new(Arc::new(
            ciris_persist::encrypted_kv::XChaChaKvStore::open(path, b"mls-state-test-passphrase")
                .expect("open the on-disk sealed store"),
        ))
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ciris-mls-{name}-{}-{}.kv",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ))
    }

    /// A group created before a "restart" reloads after it: same room, same
    /// epoch, same members — the path both drives take when they find nothing
    /// in memory.
    #[tokio::test]
    async fn a_room_created_before_a_restart_reloads_after_it() {
        let path = tmp("reload");
        let room = "chat:room:v1:reload-test";
        let (epoch, members) = {
            let store = disk_store(&path);
            let group = CohortGroup::create(store, room, "node-a", RETAINED_EPOCHS)
                .await
                .expect("create");
            // One add, so a COMMIT persists the member-join map: edge's
            // `create` writes the genesis snapshot and head but not the join
            // map (only commits do), so a creator alone in its room reloads
            // with no recorded instant — see `reloaded_claim`'s fallback.
            let (_m, kp) =
                ciris_edge::mls::cohort_group::mint_cohort_key_material("node-b").expect("mint");
            let _commit = group.add_member("node-b", kp).await.expect("add node-b");
            (group.epoch().await, group.member_key_ids().await)
        };
        // THE RESTART: a fresh provider over the same file.
        let store = disk_store(&path);
        let reloaded = load(&store, room)
            .await
            .expect("load")
            .expect("the persisted group reloads");
        assert_eq!(reloaded.epoch().await, epoch);
        assert_eq!(reloaded.member_key_ids().await, members);
        for m in ["node-a", "node-b"] {
            assert!(
                reloaded.member_added_at(m).await.is_some(),
                "{m}'s join instant is persisted with the group: the rejoin signal and the \
                 reloaded claim are dated by it"
            );
        }
        assert!(load(&store, "chat:room:v1:never-created")
            .await
            .expect("load")
            .is_none());
        let _ = std::fs::remove_file(&path);
    }

    /// A KeyPackage's private material survives a restart until its Welcome
    /// is joined, then it is gone.
    #[tokio::test]
    async fn pending_join_material_survives_a_restart_and_clears_after_the_join() {
        let path = tmp("pending");
        let room = "self-room-owner";
        {
            let store = disk_store(&path);
            let (material, _kp) =
                ciris_edge::mls::cohort_group::mint_cohort_key_material("node-b").expect("mint");
            stash_pending(&store, room, &material).await;
        }
        let store = disk_store(&path);
        assert!(
            restore_pending(&store, room).await.is_some(),
            "the material a published KeyPackage commits to is still here after the restart"
        );
        clear_pending(&store, room).await;
        assert!(restore_pending(&store, room).await.is_none());
        let _ = std::fs::remove_file(&path);
    }

    /// One store per NODE: two nodes in one process never share groups (two
    /// nodes of one pair room share its room id), and one node always gets
    /// the same store back.
    #[tokio::test]
    async fn every_node_has_its_own_store() {
        let a = format!("node-a-{}", std::process::id());
        let b = format!("node-b-{}", std::process::id());
        let room = "chat:pair:v1:shared-id";
        CohortGroup::create(store_for(&a), room, &a, RETAINED_EPOCHS)
            .await
            .expect("create on a");
        assert!(load(&store_for(&a), room).await.expect("load").is_some());
        assert!(
            load(&store_for(&b), room).await.expect("load").is_none(),
            "node b must not see node a's group under the shared room id"
        );
        assert!(matches!(posture_for(&b), Some(Posture::Ephemeral { .. })));
    }

    /// Codex #689: a store the host registered on purpose (the
    /// operator-passphrase posture) survives the boot open, the teardown guard
    /// releases it, and a forgotten room does not come back on reload.
    #[tokio::test]
    async fn an_explicit_store_survives_the_boot_open_and_teardown_releases_it() {
        let node = format!("explicit-node-{}", std::process::id());
        let path = tmp("explicit");
        register_for_node(
            &node,
            disk_store(&path),
            Posture::Durable {
                path: path.display().to_string(),
            },
        );
        let posture = open_for_node(&node, &tmp("never-opened")).await;
        assert!(
            matches!(posture, Posture::Durable { .. }),
            "the boot open kept the host's durable store: {posture:?}"
        );
        let room = "chat:room:v1:explicit";
        let _g = CohortGroup::create(store_for(&node), room, &node, RETAINED_EPOCHS)
            .await
            .expect("create");
        assert!(load(&disk_store(&path), room)
            .await
            .expect("load")
            .is_some());

        // FORGET: an intentionally dropped room does not reload.
        forget(&store_for(&node), room).await;
        assert!(load(&disk_store(&path), room)
            .await
            .expect("load")
            .is_none());

        // TEARDOWN: the guard releases the registration.
        {
            let _reg = Registration::new(&node);
        }
        assert!(
            posture_for(&node).is_none(),
            "the stopped node's store is released"
        );
        let _ = std::fs::remove_file(&path);
    }
}
