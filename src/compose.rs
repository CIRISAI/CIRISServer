//! The composition root — CIRISServer builds the substrate ONCE (one persist
//! `Engine` + one **Reticulum** `Edge` = one federation identity) and
//! orchestrates that shared access into the cores. **No core builds its own
//! Edge** (MISSION §1.2/§4): take persist/edge/verify and orchestrate their
//! access from lens/registry/node.
//!
//! **The floor is a Reticulum node.** The Edge transport is Reticulum, so the
//! node is reachable/routable on the CEG/RET fabric the moment it boots —
//! always, on any host. Heavier features gate behind **realistic resource
//! minimums** ([`Capabilities`]): the lens corpus + read API need real disk, so
//! below the minimum the node still runs as a Reticulum relay node (no local
//! corpus / read API). The registry (0.5) and node (1.0) slices attach to the
//! *same* Edge as their co-bumps land.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use ciris_edge::transport::reticulum::{ReticulumAuth, ReticulumTransport, ReticulumTransportConfig};
use ciris_edge::{Edge, LocalSigner as EdgeSigner};
use ciris_lens_core::{LensCore, PeerAcl, ScoringConfig, UxConfig};
use ciris_persist::prelude::{Engine, LocalSigner, LocalSignerConfig};
use tokio::sync::watch;

use crate::config::{Capabilities, ServerConfig};

/// Re-announce cadence for the local Reticulum destination (Leviculum default).
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);

/// Boot the node: build the shared Engine + Reticulum Edge, attach the active
/// slices the host can support, serve until shutdown.
pub async fn serve(cfg: ServerConfig) -> Result<()> {
    cfg.ensure_dirs()?;
    mint_seed_if_absent(&cfg)?;

    let caps = Capabilities::detect(&cfg);
    tracing::info!(
        disk_free_gib = caps.disk_free_gib(),
        lens_store = caps.lens_store,
        "host capabilities"
    );

    // ── ONE shared persist Engine ────────────────────────────────────────────
    let engine = build_engine(&cfg).await?;

    // ── ONE shared Reticulum edge runtime — the node's single federation
    //    transport identity. From here the node IS a Reticulum node. ───────────
    let edge = build_edge(&engine, &cfg).await?;

    // ── Attach the slices the host can support (before running the Edge) ──────
    if caps.lens_store {
        // Observation slice: ingest handler on the shared Edge.
        LensCore::attach_handler(&edge, Arc::clone(&engine))
            .await
            .map_err(|e| anyhow::anyhow!("attach lens ingest handler: {e}"))?;
    } else {
        tracing::warn!(
            min_gib = cfg.lens_store_min_gib,
            "disk below the lens-store minimum — running as a Reticulum relay node only \
             (no local corpus / read API); set CIRIS_SERVER_LENS_STORE_MIN_GIB to tune"
        );
    }
    if cfg.slices.registry {
        compose_registry(&edge, &engine, &cfg).await?;
    }
    if cfg.slices.node {
        compose_node(&edge, &engine, &cfg).await?;
    }

    // ── Run the one shared Edge (a single Reticulum transport per node) ───────
    let (edge_shutdown_tx, edge_shutdown_rx) = watch::channel(false);
    let edge_join = tokio::spawn(async move { edge.run(edge_shutdown_rx).await });

    // ── Lens read API (the 7 frozen endpoints) over the shared Engine — only
    //    when the host meets the lens-store minimum. ───────────────────────────
    let read = if caps.lens_store {
        let read = LensCore::read_api(
            Arc::clone(&engine),
            cfg.read_api_addr(),
            PeerAcl::AllowAll,
            ScoringConfig::default(),
            UxConfig::api_only("/lens/api/v1"),
        )
        .await
        .context("start lens read API")?;
        tracing::info!(read_api = %read.listen_addr(), "lens slice up — GET /lens/api/v1/*");
        Some(read)
    } else {
        None
    };

    tracing::info!(
        ret = %cfg.listen_addr,
        mode = ?cfg.mode,
        "CIRISServer up as a Reticulum node — ctrl-c to stop"
    );
    tokio::signal::ctrl_c().await.context("await ctrl_c")?;

    if let Some(read) = read {
        read.shutdown().await.context("shutdown lens read API")?;
    }
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

/// The one shared **Reticulum** edge runtime over the Engine's `SqliteBackend`
/// (directory + queue) and the node's transport-signing identity. The federation
/// signer is wired into the authenticated-announce path (AV-42); the transport-
/// tier RET dual-key identity load-or-generates at `ret_identity_path`.
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
    let ret_config = ReticulumTransportConfig {
        listen_addr: cfg.listen_addr,
        bootstrap_peers: cfg.bootstrap_peers.clone(),
        identity_path: cfg.ret_identity_path(),
        announce_interval: ANNOUNCE_INTERVAL,
        local_key_id: cfg.key_id.clone(),
        local_epoch: 0,
        interfaces: vec![],
    };
    let ret_auth = ReticulumAuth {
        signer: Some(Arc::clone(&signer)),
        rooting: None,
        resolver: None,
        ..ReticulumAuth::default()
    };
    let transport = Arc::new(
        ReticulumTransport::new(ret_config, ret_auth)
            .await
            .map_err(|e| anyhow::anyhow!("build reticulum transport: {e}"))?,
    );
    let edge = Edge::builder()
        .directory(backend.clone())
        .queue(backend)
        .signer(signer)
        .transport(transport)
        .build()
        .map_err(|e| anyhow::anyhow!("build shared Edge: {e}"))?;
    tracing::info!(ret = %cfg.listen_addr, "shared reticulum edge runtime built");
    Ok(edge)
}

/// Authority slice — folds in at **Server 0.5** (CIRISRegistry#76). Attaches to
/// the shared Edge (the node's single identity) + serves the registry trust
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
/// signer load this same seed — one federation identity per node. (The RET
/// transport-tier dual-key identity is separate, minted by the transport at
/// `ret_identity_path`.)
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
