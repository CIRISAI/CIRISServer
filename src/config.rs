//! Zero-setup configuration for the fabric node.
//!
//! **Server 0.5 — zero env vars.** `ciris-server` boots with NO environment
//! variables. The bootstrap floor is *conventions + a single `--home` flag*
//! (plus `--key-id`); everything else is either a baked constant or a signed
//! `config:*` CEG object (resolved at boot by [`crate::config_reconcile`]).
//!
//! The ONE input is the data root ([`DEFAULT_CIRIS_HOME`], overridable with
//! `--home`). Everything under it is derived by convention:
//!   - `home/data`      — the corpus / SQLite Engine + the lens store gate;
//!   - `home/identity`  — the node + user federation keys, keyring, RET identity;
//!   - `home/claim_pin` — the optional one-time claim-PIN sink (conventional).
//!
//! Installing the server means a server. There is **no refusal gate** — instead
//! heavier features gate behind realistic resource minimums ([`Capabilities`]):
//! the node always runs as a Reticulum node; the lens corpus + read API light up
//! when the host has the disk for them.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;

/// The baked default data root (a **server convention**, not an env). `--home
/// <path>` on the serve path overrides it. Everything the node needs is derived
/// from this single root by convention (see the module docs).
pub const DEFAULT_CIRIS_HOME: &str = "/var/lib/ciris";

/// The baked default federation `key_id` (labels the node's minted federation
/// key). `--key-id <name>` on the serve path overrides it (the status-node deploy
/// passes `--key-id ciris-status`).
///
/// This cannot be a `config:*` CEG read: the key_id labels the federation key
/// that is minted at boot BEFORE the corpus exists.
// TODO(0.6+): derive key_id from the minted identity fingerprint for guaranteed uniqueness
pub const DEFAULT_KEY_ID: &str = "ciris-server";

/// The conventional federation-identity seed filename (under `identity_dir`).
const SEED_FILENAME: &str = "ed25519.seed";
/// The conventional Reticulum transport-identity filename (under `identity_dir`).
const RET_IDENTITY_FILENAME: &str = "reticulum.identity";

/// Minimum free disk (GiB) to run the local lens corpus + read API. Below this
/// the node still runs as a Reticulum relay node.
///
/// **A baked constant, NOT a config knob (Server 0.5 Phase 2).** Unlike the other
/// runtime-tunable knobs, this gate is read by [`Capabilities::detect`] BEFORE the
/// Engine/corpus is open — so it CANNOT be sourced from a `config:*` CEG object
/// (there is no corpus to read yet). It is a **pre-corpus structural gate**:
/// whether the host even mounts a corpus. So it is no longer env, no longer CEG —
/// just this constant. (Acceptable under "no env": a structural pre-corpus value.)
pub const DEFAULT_LENS_STORE_MIN_GIB: u64 = 5;

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
    /// Parse a posture string (the value carried by the `mode` config:* key, or a
    /// baked default). Anything else (incl. typos) → server: never silently
    /// downgrade a node's posture on a malformed value.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "client" => Mode::Client,
            "proxy" => Mode::Proxy,
            _ => Mode::Server,
        }
    }
}

/// Which composed slices are active. **0.1 ships lens-only**; registry (0.6) and
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
/// community.
///
/// **Server 0.5: owner-authored, not env.** A peer is admitted ONLY through
/// `POST /v1/federation/peering` (owner-gated) — the operator supplies the peer's
/// own self-signed `SignedKeyRecord` in the request body. The prior
/// `CIRIS_PEER_B_*` env-seed boot path is deleted (zero env vars); this struct is
/// the in-memory shape the runtime peering handler builds and hands to
/// [`crate::peer::register_peer_key`].
///
/// **admission-gate shape (CEG 1.0-RC29 §5.6.8.15):** A admits B's key through
/// `Engine::register_federation_key`, which is fail-secure — it REQUIRES B's own
/// *self-signed* `SignedKeyRecord` (proof-of-possession). A can no longer mint B's
/// row from raw pubkeys, so the peer carries B's exported `SignedKeyRecord`.
#[derive(Debug, Clone)]
pub struct PeerB {
    /// The peer's federation `key_id` — used for replication-peer wiring; matches
    /// `key_record.record.key_id`.
    pub key_id: String,
    /// The peer's self-signed `SignedKeyRecord` (proof-of-possession). Passed
    /// verbatim to `Engine::register_federation_key`, which verifies the peer's
    /// signature (fail-secure) before admitting the key.
    pub key_record: ciris_persist::federation::types::SignedKeyRecord,
}

/// The fully-resolved node configuration.
///
/// Built from the **conventions + CLI** ([`ServerConfig::from_home`]) — NO env.
/// The boot-structural network knobs (`listen_addr`, `bootstrap_peers`) carry
/// baked defaults here and are overwritten from the resolved `config:*` snapshot
/// in [`crate::compose`] once the Engine/corpus is open (Server 0.5).
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// The data root (the ONE input — [`DEFAULT_CIRIS_HOME`] or `--home`).
    pub home: PathBuf,
    pub data_dir: PathBuf,
    pub identity_dir: PathBuf,
    /// The node's primary (Reticulum TCP) listen address. Baked default until
    /// overwritten from `config:* net.listen_addr` at boot.
    pub listen_addr: SocketAddr,
    /// Reticulum mesh bootstrap peers. Baked default ([`CANONICAL_BOOTSTRAP_PEERS`])
    /// until overwritten from `config:* net.bootstrap_peers` at boot.
    pub bootstrap_peers: Vec<SocketAddr>,
    /// The **on-disk keystore alias** — the RAW `--key-id` label (e.g.
    /// `ciris-server`). Names the sealed seed / PQC / user / transport keystore
    /// BLOBS (`<alias>.ed25519.seed.blob`, `<alias>.master.key`, `{alias}-pqc`,
    /// `{alias}-user`). It MUST stay the raw label and stable across boots, or the
    /// existing sealed blobs become unreachable → silent re-key / identity loss
    /// (CIRISServer#27, FSD-003). DISTINCT from [`Self::key_id`].
    pub keystore_alias: String,
    /// The **federation-directory / wire** identity. From boot this is the
    /// FSD-003 fingerprinted form
    /// `ciris_verify_core::fedcode::derive_key_id(keystore_alias, ed25519_pubkey)`
    /// = `"<label>-<10char-b32(sha256(pubkey))>"` — collision-free + verifiable
    /// from the pubkey. `from_home` seeds it with the raw label; it is REPLACED
    /// with the derived value in [`crate::compose::serve_with_adapter`] once the
    /// node's federation pubkey is known. NEVER use this to name a keystore blob
    /// (use [`Self::keystore_alias`]).
    pub key_id: String,
    pub occurrence_id: String,
    pub slices: Slices,
    /// Pre-corpus structural gate: minimum free disk (GiB) to mount the lens
    /// corpus. A **baked constant** ([`DEFAULT_LENS_STORE_MIN_GIB`]).
    pub lens_store_min_gib: u64,
}

impl ServerConfig {
    /// Build from the **conventions + CLI** — the Server 0.5 zero-env constructor.
    ///
    /// `home` is the data root (`--home` or [`DEFAULT_CIRIS_HOME`]); `key_id` is
    /// the federation key label (`--key-id` or [`DEFAULT_KEY_ID`]). Everything
    /// else is derived by convention or carries a baked default (the network knobs
    /// are overwritten from `config:*` at boot). No environment variable is read.
    pub fn from_home(home: PathBuf, key_id: String) -> Result<Self> {
        let data_dir = home.join("data");
        let identity_dir = home.join("identity");

        // Baked default; overwritten from config:* net.listen_addr at boot.
        let listen_addr = crate::config_reconcile::DEFAULT_LISTEN_ADDR
            .parse()
            .expect("baked DEFAULT_LISTEN_ADDR is a valid host:port");

        // Baked default; overwritten from config:* net.bootstrap_peers at boot.
        let bootstrap_peers = parse_bootstrap_peers(
            crate::config_reconcile::CANONICAL_BOOTSTRAP_PEERS
                .iter()
                .map(|s| s.to_string()),
        );

        // The keystore alias is the RAW `--key-id` label — it names the on-disk
        // sealed keystore blobs and MUST stay stable across boots (re-key risk).
        let keystore_alias = key_id.clone();

        // occurrence_id mirrors the wire identity. At `from_home` time the pubkey
        // is not yet known, so it seeds from the raw label; both `key_id` and
        // `occurrence_id` are replaced with the FSD-003 derived value at boot
        // (see `compose::serve_with_adapter`, CIRISServer#27).
        let occurrence_id = key_id.clone();

        Ok(Self {
            home,
            data_dir,
            identity_dir,
            listen_addr,
            bootstrap_peers,
            keystore_alias,
            key_id,
            occurrence_id,
            slices: Slices::default(),
            lens_store_min_gib: DEFAULT_LENS_STORE_MIN_GIB,
        })
    }

    /// Convenience: the baked-default node config (home = [`DEFAULT_CIRIS_HOME`],
    /// key_id = [`DEFAULT_KEY_ID`]). Used by the non-serve entry points
    /// (`identity create`) that don't take the serve flags.
    pub fn defaults() -> Result<Self> {
        Self::from_home(
            PathBuf::from(DEFAULT_CIRIS_HOME),
            DEFAULT_KEY_ID.to_string(),
        )
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("ciris_engine.db")
    }

    /// persist DSN — a SQLite file (relay mode requires a SQLite-backed Engine).
    pub fn dsn(&self) -> String {
        format!("sqlite:///{}", self.db_path().display())
    }

    /// The ed25519 seed both the persist Engine signer and the edge transport
    /// signer load — one federation identity per node (conventional path).
    pub fn seed_path(&self) -> PathBuf {
        self.identity_dir.join(SEED_FILENAME)
    }

    /// The Reticulum transport-tier dual-key identity (`<identity_dir>/<conventional>.rid`
    /// — 64-byte X25519‖Ed25519; distinct from the federation key). On first run
    /// the transport mints it here; an existing deployment's `*.rid` at this
    /// conventional path is adopted byte-identically (preserving the destination
    /// hash), archiving the original to `*.migrated-<ts>`.
    pub fn ret_identity_path(&self) -> PathBuf {
        self.identity_dir.join(RET_IDENTITY_FILENAME)
    }

    /// The conventional one-time claim-PIN sink path (`home/claim_pin`). On a
    /// fresh boot the PIN is ALSO written here (`0600`) for headless ops; it is
    /// never served over HTTP (see [`crate::auth::bootstrap`]).
    pub fn claim_pin_file(&self) -> PathBuf {
        self.home.join("claim_pin")
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
        use anyhow::Context;
        std::fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("create {}", self.data_dir.display()))?;
        std::fs::create_dir_all(&self.identity_dir)
            .with_context(|| format!("create {}", self.identity_dir.display()))?;
        Ok(())
    }
}

/// Parse a sequence of `host:port` strings into [`SocketAddr`]s, skipping (and
/// warning on) any invalid entry — the same lenient parse the old env path used,
/// reused for both the baked default and the `config:*` boot read.
pub fn parse_bootstrap_peers(entries: impl IntoIterator<Item = String>) -> Vec<SocketAddr> {
    entries
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|p| !p.is_empty())
        .filter_map(|p| match p.parse::<SocketAddr>() {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::warn!(peer = %p, error = %e, "skipping invalid bootstrap peer (must be host:port)");
                None
            }
        })
        .collect()
}
