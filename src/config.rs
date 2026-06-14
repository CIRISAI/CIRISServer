//! Zero-setup configuration for the fabric node.
//!
//! `ciris-server` boots with **no wizard**: every field has a sensible default
//! (mirrored from CIRISAgent — MISSION §3.4) and an env override. Defaults:
//! data `~/ciris/data`, a SQLite corpus, mint-on-first-boot identity, listen
//! `0.0.0.0:4242`, mode = `server` (the public, always-on posture).

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};

/// Transport posture (the agent's `AgentMode`). **Orthogonal** to the §3.3
/// self/family/server/agent axis (agency + cohort). CIRISServer defaults to
/// `Server`. The agent's 256 GiB disk gate on `Server` is an open decision —
/// not enforced here yet (MISSION §3.4 / SERVER_1.0_PLAN §6).
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

/// Which composed slices are active. **0.1 ships lens-only**; registry (0.5)
/// and node (1.0) fold in as their co-bumps land (CIRISRegistry#76 /
/// CIRISNodeCore#38) — see `compose.rs`.
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

/// The fully-resolved node configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub data_dir: PathBuf,
    pub identity_dir: PathBuf,
    pub listen_addr: SocketAddr,
    pub key_id: String,
    pub occurrence_id: String,
    pub mode: Mode,
    pub slices: Slices,
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

        let key_id = std::env::var("CIRIS_SERVER_KEY_ID").unwrap_or_else(|_| "ciris-server".to_string());

        let occurrence_id = std::env::var("CIRIS_OCCURRENCE_ID")
            .or_else(|_| std::env::var("AGENT_OCCURRENCE_ID"))
            .unwrap_or_else(|_| "default".to_string());

        let mode = std::env::var("CIRIS_SERVER_MODE")
            .or_else(|_| std::env::var("AGENT_MODE"))
            .map(|s| Mode::parse(&s))
            .unwrap_or_default();

        Ok(Self {
            data_dir,
            identity_dir,
            listen_addr,
            key_id,
            occurrence_id,
            mode,
            slices: Slices::default(),
        })
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("ciris_engine.db")
    }

    /// persist DSN — a SQLite file (relay mode requires a SQLite-backed Engine).
    pub fn dsn(&self) -> String {
        format!("sqlite:///{}", self.db_path().display())
    }

    /// The ed25519 seed that BOTH the persist Engine signer and lens-core's
    /// transport signer load — one identity per node.
    pub fn seed_path(&self) -> PathBuf {
        self.identity_dir.join("ed25519.seed")
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
