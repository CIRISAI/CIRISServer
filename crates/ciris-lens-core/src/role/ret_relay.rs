//! RET-native relay mode — [`LensCore::ret_relay`] + [`RetRelayHandle`].
//!
//! Mirrors [`super::relay`] (HTTP relay) but wires a Reticulum transport
//! instead of an HTTP transport. The canonical wire per `MISSION.md` §2
//! is Reticulum (HTTP is the documented fallback); this module is the
//! lens-core side of that canonical-wire cutover (CIRISLensCore#34).
//!
//! `LensCore::ret_relay` builds an Edge runtime over Reticulum, registers
//! the [`LensCoreHandler`], spawns the listener, and returns a
//! [`RetRelayHandle`]. After it returns, lens-core is a RET-addressable
//! Edge endpoint: peers that resolve the relay's Reticulum destination
//! (via the authenticated announce cold-start path, CIRISEdge#15) can
//! route `AccordEventsBatch` traffic to it over Reticulum mesh / TCP-RET.
//!
//! # Reticulum identity separation (AV-17)
//!
//! Edge maintains a **dedicated transport-tier Reticulum identity**
//! (dual-key x25519 + ed25519, generated on first run and persisted to
//! `ret_identity_path`) that is **distinct** from the federation signing
//! identity. The federation Ed25519 key lives behind the keyring
//! (`LocalSigner::from_keyring_seed_dir`, the same as HTTP relay mode) and
//! signs announce attestations to bind the transport identity to the
//! `key_id` (AV-42 authenticated cold-start). The two identities are never
//! interchangeable.
//!
//! # Key configurables vs HTTP relay
//!
//! - `ret_identity_path` — file path for the persisted Reticulum transport
//!   identity (64 raw private-key bytes; created + chmod-600 on first run).
//! - `ret_listen_addr` — TCP socket the Reticulum TCP-server interface binds
//!   (Leviculum `TcpServerInterface`). Use `0.0.0.0:4242` as the default.
//! - `ret_bootstrap_peers` — zero or more remote Reticulum TCP servers to
//!   dial as clients on startup (Leviculum `TcpClientInterface`).
//! - `announce_interval` — how often to re-announce the local destination.
//!   Defaults to 5 minutes (Leviculum default).
//!
//! # Node (v0.4) extension point
//!
//! The scoring oracle + egress filter that constitute the node role
//! (`role::node`, FSD §3) compose on top of this relay by calling
//! `LensCore::attach_handler` on the shared `Edge` this function
//! returns — same cohabitation pattern as HTTP relay.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::{Edge, EdgeError, LocalSigner};
use ciris_persist::prelude::Engine;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::pipeline::lifecycle::LensCore;
use crate::role::handler::LensCoreHandler;
use crate::role::RelayError;

/// Default announce interval — 5 minutes.
const DEFAULT_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);

impl LensCore {
    /// Start lens-core in **RET-native relay mode** — a Reticulum-
    /// addressable store-and-forward Edge endpoint.
    ///
    /// Builds an Edge runtime over the host `Engine`'s shared
    /// `SqliteBackend` (directory + queue), a keyring-loaded
    /// transport-signing identity, and a Reticulum transport bound to
    /// `ret_listen_addr` (Leviculum `TcpServerInterface`); registers the
    /// [`LensCoreHandler`]; spawns the listener on the ambient tokio
    /// runtime; returns a [`RetRelayHandle`].
    ///
    /// # Arguments
    ///
    /// - `engine` — the host's persist `Engine` (CIRIS 3.0
    ///   process-singleton). Must be SQLite-backed;
    ///   a Postgres-backed Engine yields [`RelayError::NotSqliteBacked`].
    /// - `key_id` — the relay's `federation_keys.key_id`; the identity
    ///   peers address it by; also stamped in the Reticulum announce
    ///   attestation (AV-42 binding).
    /// - `seed_dir` — directory holding `ed25519.seed` and, optionally,
    ///   `ml_dsa_65.seed` for the transport-signing identity (keyring
    ///   convention — see `LocalSigner::from_keyring_seed_dir`).
    /// - `ret_identity_path` — file path for the persisted Reticulum
    ///   transport-tier identity (NOT the federation signing key; AV-17).
    /// - `ret_listen_addr` — TCP socket the Leviculum TCP-server interface
    ///   binds for inbound Reticulum peers.
    /// - `ret_bootstrap_peers` — optional remote Reticulum TCP servers
    ///   dialled as clients on startup. Empty is valid (listen-only).
    ///
    /// # Runtime ownership
    ///
    /// The Edge listener is spawned with [`tokio::spawn`] onto the
    /// **caller's** runtime — the same runtime persist's singleton
    /// `Engine` was built on. Mirrors the HTTP relay's runtime-ownership
    /// invariant (dual-runtime deadlock closed in persist v1.6.8).
    pub async fn ret_relay(
        engine: Arc<Engine>,
        key_id: impl Into<String>,
        seed_dir: PathBuf,
        ret_identity_path: PathBuf,
        ret_listen_addr: SocketAddr,
        ret_bootstrap_peers: Vec<SocketAddr>,
    ) -> Result<RetRelayHandle, RelayError> {
        let key_id = key_id.into();

        // Directory + queue: share the host Engine's existing
        // SqliteBackend — one connection pool, not a second opened from
        // the same db_path. Same cohabitation invariant as HTTP relay.
        let backend = engine
            .sqlite_backend()
            .ok_or(RelayError::NotSqliteBacked)?
            .clone();

        // Transport-signing identity (federation key, NOT the Reticulum
        // transport-tier key). Same keyring seed-dir convention as HTTP
        // relay.
        let signer = Arc::new(
            LocalSigner::from_keyring_seed_dir(&key_id, seed_dir.clone())
                .await
                .map_err(|e| RelayError::Signer(e.to_string()))?,
        );

        // Reticulum transport configuration. `local_key_id` binds this
        // relay's `key_id` to its Reticulum transport identity in the
        // announce attestation (CIRISEdge#15 / AV-42). `local_epoch: 0`
        // is the first-deployment value; bump on transport-identity rotation.
        let ret_config = ReticulumTransportConfig {
            listen_addr: ret_listen_addr,
            bootstrap_peers: ret_bootstrap_peers,
            identity_path: ret_identity_path,
            announce_interval: DEFAULT_ANNOUNCE_INTERVAL,
            local_key_id: key_id.clone(),
            local_epoch: 0,
            interfaces: vec![], // legacy TCP path: listen_addr + bootstrap_peers
            // CIRISEdge#168 (v5.0) — leaf relay role: do NOT forward packets
            // for non-local destinations. Transport-node mode is a deliberate
            // composition-root choice (CIRISServer build_edge), not a default
            // every lens relay inherits.
            enable_transport: false,
        };

        // Auth bundle — wire the federation signer into the
        // authenticated cold-start path (AV-42 announce attestation).
        // `rooting` + `resolver` are `None` for the initial cutover:
        // announce-driven discovery is the only active resolution path
        // until a `PeerResolver` adapter is wired in (tracked as the
        // "directory-backed resolver" follow-on, CIRISEdge#53 §"Verify-via-persist
        // contract"). `HybridPolicy::Strict` is the production posture.
        let ret_auth = ReticulumAuth {
            signer: Some(Arc::clone(&signer)),
            rooting: None, // FUTURE: wire persist FederationDirectory as RootingDirectory
            resolver: None, // FUTURE: wire persist FederationDirectory as PeerResolver
            ..ReticulumAuth::default()
        };

        // Build and start the Reticulum transport. `ReticulumTransport::new`
        // load-or-generates the transport-tier Reticulum identity from
        // `ret_identity_path` (chmod 600 on first run), builds the Leviculum
        // node with the TCP interfaces, signs the announce attestation, and
        // starts the event loop. The transport is running once this returns.
        let ret_transport = Arc::new(
            ReticulumTransport::new(ret_config, ret_auth)
                .await
                .map_err(RelayError::Transport)?,
        );

        // Capture the generated transport-tier Reticulum dual-key public
        // material BEFORE the transport Arc is moved into the Edge builder.
        // `local_transport_pubkey()` is `[x25519(32) || ed25519(32)]` (edge
        // reticulum.rs splits at [32..64]); these are exactly the
        // caller-supplied inputs persist's `Engine::local_identity_aggregate`
        // (CIRISPersist#199) needs to fold the RET-transport role into the
        // aggregate federation identity. Exposing them is how a deployed
        // lens turns its null `reticulum_*_pubkey_b64` identity fields live.
        let transport_pubkey = ret_transport.local_transport_pubkey();

        let edge = Edge::builder()
            .directory(backend.clone())
            .queue(backend)
            .signer(signer)
            // `reticulum_transport` registers the typed Arc AND pushes the
            // `Arc<dyn Transport>` upcast into the transport collection —
            // the edge dispatch loop picks it up automatically. This is the
            // CIRISEdge#32 v0.14.0 dual-registration path (typed handle for
            // Links FFI + generic handle for listen/send fan-out).
            .reticulum_transport(ret_transport)
            .build()?;

        LensCoreHandler::spawn_subscriber(engine, &edge);

        // Capture the announced RNS destination hash — the dialable
        // reticulum address peers resolve — BEFORE `edge` moves into the
        // run-spawn. `Edge::local_dest_hash` (edge v2.2.2, CIRISEdge#97)
        // returns the canonical `*dest.hash()` computed at
        // `Destination::register` time; `Some` because we just wired a
        // Reticulum transport. This is NOT re-derivable from the transport
        // pubkey (RNS hashes over identity + app aspects), so edge owns it.
        let local_dest_hash = edge.local_dest_hash();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let join = tokio::spawn(async move { edge.run(shutdown_rx).await });

        Ok(RetRelayHandle {
            shutdown_tx,
            join,
            ret_listen_addr,
            transport_pubkey,
            local_dest_hash,
        })
    }
}

/// Handle to a running RET-native relay-mode Edge runtime.
///
/// Dropping the handle does **not** stop the relay. Call
/// [`shutdown`](Self::shutdown) for an orderly stop.
pub struct RetRelayHandle {
    shutdown_tx: watch::Sender<bool>,
    join: JoinHandle<Result<(), EdgeError>>,
    ret_listen_addr: SocketAddr,
    transport_pubkey: [u8; 64],
    local_dest_hash: Option<[u8; 16]>,
}

impl RetRelayHandle {
    /// The TCP socket address the relay's Reticulum TCP-server interface
    /// is bound to.
    pub fn ret_listen_addr(&self) -> SocketAddr {
        self.ret_listen_addr
    }

    /// The announced RNS destination hash — the dialable reticulum
    /// address peers resolve this relay at (edge v2.2.2, CIRISEdge#97).
    /// `Some` for a live RET relay; `None` only if no Reticulum transport
    /// was wired (not reachable through this constructor).
    pub fn reticulum_dest_hash(&self) -> Option<[u8; 16]> {
        self.local_dest_hash
    }

    /// The reticulum address as canonical RNS lowercase hex (32 chars),
    /// or `None` if unset. This is the address record a deployed lens
    /// publishes for peers to dial.
    pub fn reticulum_dest_hash_hex(&self) -> Option<String> {
        self.local_dest_hash.map(hex::encode)
    }

    /// The generated transport-tier Reticulum dual-key public material:
    /// `[x25519(32) || ed25519(32)]`. This is the identity the announce
    /// attestation binds (AV-42) and the input persist's
    /// `Engine::local_identity_aggregate` (CIRISPersist#199) folds into
    /// the aggregate federation identity's RET-transport role.
    pub fn transport_pubkey(&self) -> [u8; 64] {
        self.transport_pubkey
    }

    /// The x25519 (encryption) half of the transport identity — the
    /// `reticulum_x25519_pubkey_b64` field source.
    pub fn transport_x25519_pubkey(&self) -> [u8; 32] {
        let mut k = [0u8; 32];
        k.copy_from_slice(&self.transport_pubkey[..32]);
        k
    }

    /// The ed25519 (signing) half of the transport identity — the
    /// `reticulum_ed25519_pubkey_b64` field source.
    pub fn transport_ed25519_pubkey(&self) -> [u8; 32] {
        let mut k = [0u8; 32];
        k.copy_from_slice(&self.transport_pubkey[32..]);
        k
    }

    /// Signal the Edge runtime to stop and await the listener task.
    ///
    /// Consumes the handle. Returns the Edge runtime's exit result —
    /// `Ok(())` on a clean shutdown. Mirrors [`super::relay::RelayHandle::shutdown`].
    pub async fn shutdown(self) -> Result<(), RelayError> {
        let _ = self.shutdown_tx.send(true);
        match self.join.await {
            Ok(run_result) => run_result.map_err(RelayError::Edge),
            Err(join_err) => Err(RelayError::Join(join_err.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_announce_interval_is_five_minutes() {
        assert_eq!(DEFAULT_ANNOUNCE_INTERVAL, Duration::from_secs(300));
    }

    #[test]
    fn ret_relay_handle_exposes_listen_addr() {
        // Construction smoke test — verifies `RetRelayHandle::ret_listen_addr`
        // round-trips the configured address without requiring a live Edge.
        use tokio::sync::watch;
        let (tx, _rx) = watch::channel(false);
        let addr: SocketAddr = "0.0.0.0:4242".parse().unwrap();
        // Build a no-op JoinHandle by spawning a task that immediately
        // returns Ok(()). `block_on(spawn(fut))` gives back a
        // `JoinHandle<Result<(), EdgeError>>` — not awaited here so
        // we hold the handle (the shutdown path awaits it in production).
        #[allow(clippy::async_yields_async)]
        let handle: JoinHandle<Result<(), EdgeError>> = {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(async { tokio::spawn(async { Ok(()) }) })
        };
        let mut pubkey = [0u8; 64];
        for (i, b) in pubkey.iter_mut().enumerate() {
            *b = i as u8;
        }
        let dest = [0xABu8; 16];
        let rh = RetRelayHandle {
            shutdown_tx: tx,
            join: handle,
            ret_listen_addr: addr,
            transport_pubkey: pubkey,
            local_dest_hash: Some(dest),
        };
        assert_eq!(rh.ret_listen_addr(), addr);
        // The two halves split at byte 32 (x25519 || ed25519).
        assert_eq!(rh.transport_x25519_pubkey(), pubkey[..32]);
        assert_eq!(rh.transport_ed25519_pubkey(), pubkey[32..]);
        assert_eq!(rh.transport_pubkey(), pubkey);
        // RNS dest hash → canonical 32-char lowercase hex.
        assert_eq!(rh.reticulum_dest_hash(), Some(dest));
        assert_eq!(
            rh.reticulum_dest_hash_hex().as_deref(),
            Some("abababababababababababababababab")
        );
    }
}
