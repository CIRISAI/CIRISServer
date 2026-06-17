//! Zero-setup configuration for the fabric node.
//!
//! `ciris-server` boots with **no wizard**: every field has a sensible default
//! (mirrored from CIRISAgent — MISSION §3.4) and an env override. Defaults:
//! data `~/ciris/data`, a SQLite corpus, mint-on-first-boot identity, listen
//! `0.0.0.0:4242` (the Reticulum node port), mode = `server`.
//!
//! Installing the server means a server. There is **no refusal gate** — instead
//! heavier features gate behind realistic resource minimums ([`Capabilities`]):
//! the node always runs as a Reticulum node; the lens corpus + read API light up
//! when the host has the disk for them.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};

/// Default minimum free disk (GiB) to run the local lens corpus + read API.
/// Below this the node still runs as a Reticulum relay node. Tunable via
/// `CIRIS_SERVER_LENS_STORE_MIN_GIB`.
const DEFAULT_LENS_STORE_MIN_GIB: u64 = 5;

/// Transport posture (the agent's `AgentMode`). **Orthogonal** to the §3.3
/// self/family/server/agent axis (agency + cohort). CIRISServer defaults to
/// `Server` — installing the server means a server. What the node can *do*
/// scales with [`Capabilities`], never a hard refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Egress-only, no listener.
    Client,
    /// Bidirectional; listens and forwards (the agent's default).
    Proxy,
    /// Always-on public node — CIRISServer's default.
    #[default]
    Server,
}

impl Mode {
    fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "client" => Mode::Client,
            "proxy" => Mode::Proxy,
            // Anything else (incl. typos) → server: never silently downgrade a
            // node's posture on a malformed value.
            _ => Mode::Server,
        }
    }
}

/// Which composed slices are active. **0.1 ships lens-only**; registry (0.5) and
/// node (1.0) fold in as their co-bumps land (CIRISRegistry#76 / CIRISNodeCore#38).
#[derive(Debug, Clone, Copy)]
pub struct Slices {
    pub lens: bool,
    pub registry: bool,
    pub node: bool,
}

impl Default for Slices {
    fn default() -> Self {
        Slices {
            lens: true,
            registry: false,
            node: false,
        }
    }
}

/// Realistic-minimum feature gating. The node always runs as a Reticulum node;
/// resource-hungry features light up only when the host meets their minimums.
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    pub disk_free_bytes: u64,
    /// Local lens corpus + read API — needs realistic disk for the growing corpus.
    pub lens_store: bool,
}

impl Capabilities {
    pub fn detect(cfg: &ServerConfig) -> Self {
        let disk_free_bytes = fs2::available_space(&cfg.data_dir).unwrap_or(0);
        let min = cfg.lens_store_min_gib.saturating_mul(1024 * 1024 * 1024);
        Capabilities {
            disk_free_bytes,
            lens_store: disk_free_bytes >= min,
        }
    }

    pub fn disk_free_gib(&self) -> u64 {
        self.disk_free_bytes / (1024 * 1024 * 1024)
    }
}

/// A federation peer the node bidirectionally replicates with under **directed
/// consent** (NOT in-group trust) — the canonical example being Node B
/// (`ciris-status`), which is OUT of the canonical CIRIS infrastructure
/// community. Sourced from the optional `CIRIS_PEER_B_*` env; when unset the
/// node skips peer registration + replication entirely (logged at info).
///
/// **v8.8.0 admission-gate shape (CEG 1.0-RC29 §5.6.8.15):** A admits B's key
/// through `Engine::register_federation_key`, which is fail-secure — it REQUIRES
/// B's own *self-signed* `SignedKeyRecord` (proof-of-possession). A can no longer
/// mint B's row from raw pubkeys, so the config carries B's exported
/// `SignedKeyRecord` as JSON (`CIRIS_PEER_B_KEY_RECORD`), deserialized into
/// [`PeerB::key_record`]. The peer's `key_id` is also carried separately
/// (`CIRIS_PEER_B_KEY_ID`) for the replication-peer wiring (and consistency-
/// checked against the record). Both nodes are on persist v8.8.0, so the serde
/// shape matches byte-for-byte (the cross-repo peering contract).
#[derive(Debug, Clone)]
pub struct PeerB {
    /// The peer's federation `key_id` (Node B's `ciris-status` identity) — used
    /// for replication-peer wiring; matches `key_record.record.key_id`.
    pub key_id: String,
    /// Node B's self-signed `SignedKeyRecord` (proof-of-possession), as exported
    /// by B and supplied via `CIRIS_PEER_B_KEY_RECORD`. Passed verbatim to
    /// `Engine::register_federation_key`, which verifies B's signature
    /// (fail-secure) before admitting the key.
    pub key_record: ciris_persist::federation::types::SignedKeyRecord,
}

/// The fully-resolved node configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub data_dir: PathBuf,
    pub identity_dir: PathBuf,
    /// The node's primary (Reticulum TCP) listen address.
    pub listen_addr: SocketAddr,
    pub bootstrap_peers: Vec<SocketAddr>,
    pub key_id: String,
    pub occurrence_id: String,
    pub mode: Mode,
    pub slices: Slices,
    pub lens_store_min_gib: u64,
    /// Optional directed-consent replication peer (Node B / `ciris-status`).
    /// `Some` only when the full `CIRIS_PEER_B_*` trio is present.
    pub peer_b: Option<PeerB>,
}

impl ServerConfig {
    /// Build from the environment with zero-setup defaults — no field required.
    pub fn from_env() -> Result<Self> {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let ciris_home = std::env::var("CIRIS_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(&home).join("ciris"));

        let data_dir = env_path("CIRIS_SERVER_DATA_DIR").unwrap_or_else(|| ciris_home.join("data"));
        let identity_dir =
            env_path("CIRIS_SERVER_IDENTITY_DIR").unwrap_or_else(|| ciris_home.join("identity"));

        let listen_addr = std::env::var("CIRIS_SERVER_LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:4242".to_string())
            .parse()
            .context("CIRIS_SERVER_LISTEN_ADDR must be host:port")?;

        let bootstrap_peers = std::env::var("CIRIS_SERVER_BOOTSTRAP_PEERS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .filter_map(|p| p.parse::<SocketAddr>().ok())
                    .collect()
            })
            .unwrap_or_default();

        let key_id =
            std::env::var("CIRIS_SERVER_KEY_ID").unwrap_or_else(|_| "ciris-server".to_string());

        let occurrence_id = std::env::var("CIRIS_OCCURRENCE_ID")
            .or_else(|_| std::env::var("AGENT_OCCURRENCE_ID"))
            .unwrap_or_else(|_| "default".to_string());

        let mode = std::env::var("CIRIS_SERVER_MODE")
            .or_else(|_| std::env::var("AGENT_MODE"))
            .map(|s| Mode::parse(&s))
            .unwrap_or_default();

        let lens_store_min_gib = std::env::var("CIRIS_SERVER_LENS_STORE_MIN_GIB")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(DEFAULT_LENS_STORE_MIN_GIB);

        // Directed-consent replication peer (Node B / ciris-status). All THREE
        // env vars must be present, non-empty, for the peer to be admitted —
        // a partial trio is treated as "no peer" (and warned), never a partial
        // registration that could not actually replicate or verify.
        let peer_b = Self::peer_b_from_env();

        Ok(Self {
            data_dir,
            identity_dir,
            listen_addr,
            bootstrap_peers,
            key_id,
            occurrence_id,
            mode,
            slices: Slices::default(),
            lens_store_min_gib,
            peer_b,
        })
    }

    /// Parse the optional `CIRIS_PEER_B_*` env into a [`PeerB`]. `None` when the
    /// pair is absent; a *partial* config (or a record that fails to deserialize,
    /// or a `key_id` mismatch) logs a warning and yields `None` (we never
    /// half-register a peer whose self-signed record we can't fully carry).
    ///
    /// **v8.8.0 shape:** instead of raw pubkeys, B's own *self-signed*
    /// `SignedKeyRecord` (proof-of-possession) is supplied as JSON via
    /// `CIRIS_PEER_B_KEY_RECORD` — the v8.8.0 admission gate requires it and
    /// verifies B's signature fail-secure. `CIRIS_PEER_B_KEY_ID` is still carried
    /// for replication wiring and is consistency-checked against the record.
    fn peer_b_from_env() -> Option<PeerB> {
        let nonempty = |k: &str| {
            std::env::var(k)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let key_id = nonempty("CIRIS_PEER_B_KEY_ID");
        let key_record_json = nonempty("CIRIS_PEER_B_KEY_RECORD");
        match (key_id, key_record_json) {
            (Some(key_id), Some(json)) => {
                let key_record: ciris_persist::federation::types::SignedKeyRecord =
                    match serde_json::from_str(&json) {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "CIRIS_PEER_B_KEY_RECORD is not a valid SignedKeyRecord JSON \
                                 (persist v8.8.0 serde shape) — skipping Node B peering"
                            );
                            return None;
                        }
                    };
                if key_record.record.key_id != key_id {
                    tracing::warn!(
                        config_key_id = %key_id,
                        record_key_id = %key_record.record.key_id,
                        "CIRIS_PEER_B_KEY_ID does not match CIRIS_PEER_B_KEY_RECORD.record.key_id \
                         — skipping Node B peering (refusing an inconsistent peer config)"
                    );
                    return None;
                }
                Some(PeerB { key_id, key_record })
            }
            (None, None) => None,
            _ => {
                tracing::warn!(
                    "incomplete CIRIS_PEER_B_* env (need both CIRIS_PEER_B_KEY_ID + \
                     CIRIS_PEER_B_KEY_RECORD) — skipping Node B peer registration + replication"
                );
                None
            }
        }
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("ciris_engine.db")
    }

    /// persist DSN — a SQLite file (relay mode requires a SQLite-backed Engine).
    pub fn dsn(&self) -> String {
        format!("sqlite:///{}", self.db_path().display())
    }

    /// The ed25519 seed both the persist Engine signer and the edge transport
    /// signer load — one federation identity per node.
    pub fn seed_path(&self) -> PathBuf {
        self.identity_dir.join("ed25519.seed")
    }

    /// The Reticulum transport-tier dual-key identity (64-byte X25519‖Ed25519;
    /// distinct from the federation key). On first run the transport mints it
    /// here; when migrating from an existing deployment (agent/lens/registry),
    /// point `CIRIS_SERVER_RET_IDENTITY_PATH` at its `*.rid` and the keystore
    /// adopts it byte-identically (preserving the destination hash), archiving
    /// the original to `*.migrated-<ts>`.
    pub fn ret_identity_path(&self) -> PathBuf {
        std::env::var("CIRIS_SERVER_RET_IDENTITY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| self.identity_dir.join("reticulum.identity"))
    }

    /// Storage dir for the hardware-backed transport-identity keystore
    /// (TPM-sealed blob when available; encrypted software blob otherwise).
    pub fn keyring_dir(&self) -> PathBuf {
        self.identity_dir.join("keyring")
    }

    /// The lens read-API HTTP address — the primary (RET) port + 1.
    pub fn read_api_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.listen_addr.ip(),
            self.listen_addr.port().saturating_add(1),
        )
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("create {}", self.data_dir.display()))?;
        std::fs::create_dir_all(&self.identity_dir)
            .with_context(|| format!("create {}", self.identity_dir.display()))?;
        Ok(())
    }
}

fn env_path(k: &str) -> Option<PathBuf> {
    std::env::var(k).ok().map(PathBuf::from)
}
