//! The composition root — CIRISServer builds the substrate ONCE (one persist
//! `Engine` + one edge `Edge` = one federation identity) and orchestrates that
//! shared access into the cores. **No core builds its own Engine or Edge** —
//! that is the whole point of the fabric node (MISSION §1.2/§4): take
//! persist/edge/verify and orchestrate their access efficiently from
//! lens/registry/node.
//!
//! **0.1 attaches the lens slice** to the shared Edge — ingest via
//! `LensCore::attach_handler`, plus the 7 frozen `GET /lens/api/v1/*` read
//! endpoints via `LensCore::read_api` over the shared Engine. The **registry**
//! (0.5) and **node** (1.0) slices attach to the *same* Edge as their co-bumps
//! land — never a second Edge, never a second identity.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use ciris_edge::transport::http::{HttpTransport, HttpTransportConfig};
use ciris_edge::{Edge, LocalSigner as EdgeSigner};
use ciris_lens_core::{LensCore, PeerAcl, ScoringConfig, UxConfig};
use ciris_persist::prelude::{Engine, LocalSigner, LocalSignerConfig};
use tokio::sync::watch;

use crate::config::ServerConfig;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Boot the node: build the shared Engine + Edge, attach the active slices, serve.
pub async fn serve(cfg: ServerConfig) -> Result<()> {
    cfg.ensure_dirs()?;
    mint_seed_if_absent(&cfg)?;

    // ── ONE shared persist Engine ────────────────────────────────────────────
    let engine = build_engine(&cfg).await?;

    // ── ONE shared edge runtime — the node's single federation transport
    //    identity. CIRISServer builds it; the cores ATTACH to it. ─────────────
    let edge = build_edge(&engine, &cfg).await?;

    // ── Observation slice (LIVE in 0.1): ingest handler on the shared Edge ───
    LensCore::attach_handler(&edge, Arc::clone(&engine))
        .await
        .map_err(|e| anyhow::anyhow!("attach lens ingest handler: {e}"))?;

    // ── Authority slice (0.5; CIRISRegistry#76) — attaches to THIS edge ──────
    if cfg.slices.registry {
        compose_registry(&edge, &engine, &cfg).await?;
    }
    // ── Consensus slice (1.0; CIRISNodeCore#38) — attaches to THIS edge ──────
    if cfg.slices.node {
        compose_node(&edge, &engine, &cfg).await?;
    }

    // ── Run the one shared Edge (a single transport listener per node) ───────
    let (edge_shutdown_tx, edge_shutdown_rx) = watch::channel(false);
    let edge_join = tokio::spawn(async move { edge.run(edge_shutdown_rx).await });

    // ── Lens read API (the 7 frozen endpoints) over the shared Engine ────────
    let read = LensCore::read_api(
        Arc::clone(&engine),
        cfg.listen_addr,
        PeerAcl::AllowAll,
        ScoringConfig::default(),
        UxConfig::api_only("/lens/api/v1"),
    )
    .await
    .context("start lens read API")?;
    tracing::info!(
        read_api = %read.listen_addr(),
        mode = ?cfg.mode,
        "CIRISServer up — GET /lens/api/v1/* + relay ingest; ctrl-c to stop"
    );

    tokio::signal::ctrl_c().await.context("await ctrl_c")?;

    read.shutdown().await.context("shutdown lens read API")?;
    let _ = edge_shutdown_tx.send(true);
    let _ = edge_join.await;
    Ok(())
}

/// The one shared persist `Engine` (SQLite-backed; builds + migrates).
async fn build_engine(cfg: &ServerConfig) -> Result<Arc<Engine>> {
    let signer = Arc::new(
        LocalSigner::from_config(&LocalSignerConfig {
            key_id: cfg.key_id.clone(),
            key_path: cfg.seed_path(),
            pqc_key_id: None,
            pqc_key_path: None,
        })
        .context("load persist LocalSigner")?,
    );
    let engine = Engine::with_signer(signer, &cfg.dsn())
        .await
        .context("build shared persist Engine")?;
    Ok(Arc::new(engine))
}

/// The one shared edge runtime over the Engine's `SqliteBackend` (directory +
/// queue) and the node's transport-signing identity (the same seed the Engine
/// loads). HTTP transport in 0.1; the relay listener binds `listen_addr.port()+1`.
async fn build_edge(engine: &Arc<Engine>, cfg: &ServerConfig) -> Result<Edge> {
    let backend = engine
        .sqlite_backend()
        .context("Engine must be SQLite-backed for the relay")?
        .clone();
    let signer = Arc::new(
        EdgeSigner::from_keyring_seed_dir(&cfg.key_id, cfg.identity_dir.clone())
            .await
            .map_err(|e| anyhow::anyhow!("load edge transport signer: {e}"))?,
    );
    let relay_addr =
        SocketAddr::new(cfg.listen_addr.ip(), cfg.listen_addr.port().saturating_add(1));
    let transport = Arc::new(
        HttpTransport::new(HttpTransportConfig {
            listen_addr: relay_addr,
            peer_urls: HashMap::new(),
            request_timeout: REQUEST_TIMEOUT,
        })
        .context("build edge HTTP transport")?,
    );
    let edge = Edge::builder()
        .directory(backend.clone())
        .queue(backend)
        .signer(signer)
        .transport(transport)
        .build()
        .map_err(|e| anyhow::anyhow!("build shared Edge: {e}"))?;
    tracing::info!(relay = %relay_addr, "shared edge runtime built");
    Ok(edge)
}

/// Authority slice — folds in at **Server 0.5** (CIRISRegistry#76). Attaches to
/// the shared Edge (the node's single identity) and serves the registry trust
/// surface over the shared Engine. SCAFFOLD.
async fn compose_registry(_edge: &Edge, _engine: &Arc<Engine>, _cfg: &ServerConfig) -> Result<()> {
    todo!("registry slice (Server 0.5) — pin ciris-registry-core (CIRISRegistry#76) + attach to the shared Edge")
}

/// Consensus slice — folds in at **Server 1.0** (CIRISNodeCore#38). `install(&edge)`
/// on the shared Edge + the WBD `route_deferral` / Wise-Authority surface. SCAFFOLD.
async fn compose_node(_edge: &Edge, _engine: &Arc<Engine>, _cfg: &ServerConfig) -> Result<()> {
    todo!("node slice (Server 1.0) — pin ciris-node-core (CIRISNodeCore#38) + install(&edge)")
}

/// Zero-setup identity: mint a 32-byte ed25519 seed on first boot if absent
/// (chmod 600 on unix). Both the persist Engine signer and the edge transport
/// signer load this same seed — one identity per node.
fn mint_seed_if_absent(cfg: &ServerConfig) -> Result<()> {
    let seed = cfg.seed_path();
    if seed.exists() {
        return Ok(());
    }
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).context("CSPRNG for identity seed")?;
    std::fs::write(&seed, bytes).with_context(|| format!("write {}", seed.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 600 {}", seed.display()))?;
    }
    tracing::info!(path = %seed.display(), "minted node identity seed (first boot)");
    Ok(())
}
