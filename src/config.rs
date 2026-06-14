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
        Slices { lens: true, registry: false, node: false }
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
        Capabilities { disk_free_bytes, lens_store: disk_free_bytes >= min }
    }

    pub fn disk_free_gib(&self) -> u64 {
        self.disk_free_bytes / (1024 * 1024 * 1024)
    }
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

        let key_id = std::env::var("CIRIS_SERVER_KEY_ID").unwrap_or_else(|_| "ciris-server".to_string());

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
        })
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
        SocketAddr::new(self.listen_addr.ip(), self.listen_addr.port().saturating_add(1))
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
