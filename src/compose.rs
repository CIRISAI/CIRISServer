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
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::{Edge, LocalSigner as EdgeSigner};
use ciris_keyring::{
    get_platform_ed25519_signer, BlobTransportKeystore, HardwareSigner, SealedEd25519Signer,
    TransportIdentityKeystore,
};
use ciris_lens_core::{LensCore, PeerAcl, ScoringConfig, UxConfig};
use ciris_persist::prelude::Engine;
use tokio::sync::watch;

use crate::config::{Capabilities, ServerConfig};

/// Re-announce cadence for the local Reticulum destination (Leviculum default).
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);

/// Boot the node: build the shared Engine + Reticulum Edge, attach the active
/// slices the host can support, serve until shutdown.
pub async fn serve(cfg: ServerConfig) -> Result<()> {
    cfg.ensure_dirs()?;

    let caps = Capabilities::detect(&cfg);
    tracing::info!(
        disk_free_gib = caps.disk_free_gib(),
        lens_store = caps.lens_store,
        "host capabilities"
    );

    // ── ONE federation signing identity — a TPM / Secure-Enclave / StrongBox
    //    SEALED Ed25519 seed (verify v5.4.0 get_platform_ed25519_signer;
    //    CIRISVerify#70). The seed is hardware-custodied at rest, yet the pubkey
    //    stays 32-byte Ed25519 — so key_id + the Reticulum announce (AV-42) are
    //    preserved, and an existing `ed25519.seed` is adopted byte-identically
    //    (no re-key on takeover). Shared by the persist Engine AND the edge
    //    transport signer => ONE federation identity, hardware-custodied
    //    (MISSION §1.5). Software-encrypted fallback when no hardware. ──────────
    let signer: Arc<dyn HardwareSigner> = Arc::from(federation_signer(&cfg)?);

    // ── ONE shared persist Engine ────────────────────────────────────────────
    let engine = build_engine(&cfg, Arc::clone(&signer)).await?;

    // ── ONE shared Reticulum edge runtime — the node's single federation
    //    transport identity. From here the node IS a Reticulum node. ───────────
    let edge = build_edge(&engine, &cfg, Arc::clone(&signer)).await?;

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

/// The node's federation signing identity, hardware-custodied.
///
/// **Migrates an existing key.** If a plaintext `ed25519.seed` is present at
/// `identity_dir` (an agent/lens/registry takeover — see
/// FSD/LENS_TO_SERVER_MIGRATION.md), it is **adopted byte-identically** into the
/// sealed keystore (`SealedEd25519Signer::adopt`) — the `key_id` is preserved (no
/// re-key) and the plaintext is archived off the live path. Otherwise the
/// already-sealed seed is loaded, or a fresh one is generated + sealed
/// (`get_platform_ed25519_signer`). Either way the seed is TPM/SE/StrongBox-sealed
/// at rest with software-encrypted fallback; the pubkey stays 32-byte Ed25519.
fn federation_signer(cfg: &ServerConfig) -> Result<Box<dyn HardwareSigner>> {
    let seed_path = cfg.seed_path(); // identity_dir/ed25519.seed — the takeover source
    if seed_path.exists() {
        let bytes =
            std::fs::read(&seed_path).with_context(|| format!("read {}", seed_path.display()))?;
        let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "{} must be a 32-byte ed25519 seed (got {} bytes)",
                seed_path.display(),
                bytes.len()
            )
        })?;
        let signer =
            SealedEd25519Signer::adopt(cfg.key_id.clone(), cfg.identity_dir.clone(), &seed)
                .map_err(|e| {
                    anyhow::anyhow!("adopt existing federation seed into the keystore: {e}")
                })?;
        // The sealed copy is now load-bearing; move the plaintext off the live path.
        let archived = seed_path.with_file_name("ed25519.seed.migrated");
        std::fs::rename(&seed_path, &archived).with_context(|| {
            format!("archive {} -> {}", seed_path.display(), archived.display())
        })?;
        tracing::info!(
            archived = %archived.display(),
            "adopted existing federation seed into the sealed keystore (key_id preserved)"
        );
        Ok(Box::new(signer))
    } else {
        get_platform_ed25519_signer(&cfg.key_id, cfg.identity_dir.clone())
            .map_err(|e| anyhow::anyhow!("open sealed-Ed25519 federation signer: {e}"))
    }
}

/// The one shared persist `Engine` (SQLite-backed; builds + migrates), keyed by
/// the node's sealed-Ed25519 hardware federation signer.
async fn build_engine(cfg: &ServerConfig, signer: Arc<dyn HardwareSigner>) -> Result<Arc<Engine>> {
    let engine = Engine::with_hardware_signer(signer, &cfg.dsn())
        .await
        .context("build shared persist Engine")?;
    Ok(Arc::new(engine))
}

/// The one shared **Reticulum** edge runtime over the Engine's `SqliteBackend`
/// (directory + queue) and the node's transport-signing identity. The federation
/// signer is wired into the authenticated-announce path (AV-42); the transport-
/// tier RET dual-key identity load-or-generates at `ret_identity_path`.
async fn build_edge(
    engine: &Arc<Engine>,
    cfg: &ServerConfig,
    signer: Arc<dyn HardwareSigner>,
) -> Result<Edge> {
    let backend = engine
        .sqlite_backend()
        .context("Engine must be SQLite-backed for the relay")?
        .clone();
    // The edge transport signer wraps the SAME sealed-Ed25519 federation key as
    // the Engine — one federation identity per node (distinct from the RNS
    // transport-tier identity held in the keystore below).
    let signer = Arc::new(EdgeSigner::new(cfg.key_id.clone(), signer, None));

    // Hardware-backed transport-identity keystore (verify v5.2.0 #68 / edge #99):
    // TPM-sealed when available (the `tpm` feature + hardware), encrypted software
    // otherwise — auto-detects, never errors on absent hardware. Setting it on
    // ReticulumAuth makes ReticulumTransport::new adopt an existing
    // `ret_identity_path` *.rid byte-identically (archiving it to *.migrated-<ts>),
    // or generate-and-store the transport identity in the keystore.
    let keyring_dir = cfg.keyring_dir();
    std::fs::create_dir_all(&keyring_dir)
        .with_context(|| format!("create {}", keyring_dir.display()))?;
    let transport_keystore: Arc<dyn TransportIdentityKeystore> = Arc::new(
        BlobTransportKeystore::platform(cfg.key_id.clone(), keyring_dir.clone())
            .map_err(|e| anyhow::anyhow!("open transport-identity keystore: {e}"))?,
    );
    tracing::info!(
        hardware_backed = transport_keystore.is_hardware_backed(),
        dir = %keyring_dir.display(),
        "transport-identity keystore opened"
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
        transport_identity_keystore: Some(transport_keystore),
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
