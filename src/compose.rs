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
    get_platform_ed25519_signer, BlobTransportKeystore, HardwareSigner, MlDsa65SoftwareSigner,
    PqcSigner, SealedEd25519Signer, TransportIdentityKeystore,
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

    // ── The post-quantum half (ML-DSA-65) → the federation signature is a FULL
    //    HYBRID (Ed25519 + ML-DSA-65). Classical is hardware-sealed; PQC is a
    //    software seed (no sealed-ML-DSA backend exists). ───────────────────────
    let pqc: Arc<dyn PqcSigner> = federation_pqc_signer(&cfg)?;

    // ── ONE shared persist Engine (hybrid hardware signer — hard cut) ─────────
    let engine = build_engine(&cfg, Arc::clone(&signer), Arc::clone(&pqc)).await?;

    // ── ONE shared Reticulum edge runtime — the node's single federation
    //    transport identity. From here the node IS a Reticulum node. ───────────
    let edge = build_edge(&engine, &cfg, Arc::clone(&signer), Arc::clone(&pqc)).await?;

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

    // The node's identity aggregate (CEG §5.6.8.8.2) for GET /v1/identity —
    // assembled ONCE at boot from the federation signing key + the RNS transport
    // identity (both stable). Captured before edge.run() consumes the Edge.
    let identity_json = local_identity_json(&engine, edge.local_transport_pubkey())
        .await
        .context("assemble /v1/identity aggregate")?;

    // ── Run the one shared Edge (a single Reticulum transport per node) ───────
    let (edge_shutdown_tx, edge_shutdown_rx) = watch::channel(false);
    let edge_join = tokio::spawn(async move { edge.run(edge_shutdown_rx).await });

    // ── Lens read API (the 7 frozen endpoints) over the shared Engine — only
    //    when the host meets the lens-store minimum. ───────────────────────────
    let read = if caps.lens_store {
        let read = LensCore::read_api_with_extra(
            Arc::clone(&engine),
            cfg.read_api_addr(),
            PeerAcl::AllowAll,
            ScoringConfig::default(),
            UxConfig::api_only("/lens/api/v1"),
            // /v1/identity + the full fabric auth surface (CIRISServer#9). All
            // auth routers merge onto the one read-API listener. Federation-
            // signed control routes default to HybridPolicy::Strict (no
            // classical-only path).
            {
                use ciris_persist::prelude::HybridPolicy;
                let strict = HybridPolicy::Strict;
                identity_router(identity_json)
                    // login ceremony (self-at-login → user-managed consent)
                    .merge(crate::auth::self_login::router(Arc::clone(&engine), strict))
                    // sessions/tokens: login / logout / me / refresh / owner-hint
                    .merge(crate::auth::session::router(Arc::clone(&engine)))
                    // OAuth front-door + native google/apple
                    .merge(crate::auth::oauth::router(Arc::clone(&engine)))
                    // API keys + service-token revocation
                    .merge(crate::auth::api_keys::router(Arc::clone(&engine)))
                    // attestation / consent / erasure (CEG-native)
                    .merge(crate::auth::attestation::router(Arc::clone(&engine), strict))
                    .merge(crate::auth::consent::router(Arc::clone(&engine), strict))
                    .merge(crate::auth::erasure::router(Arc::clone(&engine), strict))
                    // device-auth setup (scaffold)
                    .merge(crate::auth::device_auth::router(Arc::clone(&engine)))
            },
        )
        .await
        .context("start read API")?;
        tracing::info!(read_api = %read.listen_addr(), "read API up — GET /lens/api/v1/* + GET /v1/identity");
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

/// Assemble the node's `LocalIdentityAggregate` (CEG §5.6.8.8.2) as JSON for
/// `GET /v1/identity` — the migration's identity-continuity check (same `key_id`).
///
/// Sourced directly from persist's `Engine::local_identity_aggregate`
/// (CIRISPersist#223 + #224), so all SIX keys are populated:
///   - **signing** role — a FULL HYBRID, Ed25519 (hardware-sealed) + ML-DSA-65,
///     because the Engine is built with `with_hardware_signer_hybrid` and its
///     `local_signer` carries both halves;
///   - **content-KEM** pair (x25519 + ML-KEM-768) — persist-minted/sealed and now
///     reachable for a hardware-signed Engine (#223 closed the `null` gap);
///   - **RET-transport** role (x25519 ‖ ed25519, RNS `get_public_key` order),
///     supplied here from the Reticulum transport identity.
async fn local_identity_json(
    engine: &Engine,
    transport_pubkey: Option<[u8; 64]>,
) -> Result<String> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let (ret_x25519_b64, ret_ed25519_b64) = match transport_pubkey {
        Some(tp) => (Some(b64.encode(&tp[..32])), Some(b64.encode(&tp[32..]))),
        None => (None, None),
    };
    let aggregate = engine
        .local_identity_aggregate(ret_x25519_b64, ret_ed25519_b64)
        .await
        .map_err(|e| anyhow::anyhow!("persist local_identity_aggregate: {e}"))?;
    serde_json::to_string(&aggregate).context("serialize LocalIdentityAggregate")
}

/// `GET /v1/identity` → the cached identity-aggregate JSON (stable for the
/// node's lifetime), merged onto the read-API listener.
fn identity_router(identity_json: String) -> axum::Router {
    let body = std::sync::Arc::new(identity_json);
    axum::Router::new().route(
        "/v1/identity",
        axum::routing::get(move || {
            let body = std::sync::Arc::clone(&body);
            async move {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    (*body).clone(),
                )
            }
        }),
    )
}

/// The node's **post-quantum** federation signing half — ML-DSA-65 — so the
/// federation signature is a FULL HYBRID (Ed25519 + ML-DSA-65), per CEG.
///
/// Custody caveat: the keyring has no sealed/TPM ML-DSA backend (a TPM can't do
/// ML-DSA), so this is a **software** signer over a seed at `ml_dsa_65.seed`
/// (minted on first boot, `0600`; **adopted** byte-identically on takeover — the
/// PQC half of a migrating steward/lens/registry identity). The classical half
/// stays hardware-sealed ([`federation_signer`]); together they hybrid-sign.
pub(crate) fn federation_pqc_signer(cfg: &ServerConfig) -> Result<Arc<dyn PqcSigner>> {
    let path = cfg.identity_dir.join("ml_dsa_65.seed");
    let alias = format!("{}-pqc", cfg.key_id);
    let signer = if path.exists() {
        // Adopt an existing ML-DSA-65 seed (migration: the steward/lens PQC half).
        let s = MlDsa65SoftwareSigner::from_seed_file(&path, alias)
            .map_err(|e| anyhow::anyhow!("adopt ML-DSA-65 seed {}: {e}", path.display()))?;
        tracing::info!(seed = %path.display(), "adopted existing ML-DSA-65 federation seed (hybrid PQC)");
        s
    } else {
        // Mint a fresh 32-byte ML-DSA-65 seed on first boot.
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("mint ML-DSA-65 seed: {e}"))?;
        std::fs::write(&path, seed).with_context(|| format!("write {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        let s = MlDsa65SoftwareSigner::from_seed_bytes(&seed, alias)
            .map_err(|e| anyhow::anyhow!("load minted ML-DSA-65 seed: {e}"))?;
        tracing::info!(seed = %path.display(), "minted ML-DSA-65 federation seed (hybrid PQC; software-at-rest)");
        s
    };
    Ok(Arc::new(signer))
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
pub(crate) fn federation_signer(cfg: &ServerConfig) -> Result<Box<dyn HardwareSigner>> {
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
/// the node's **hybrid hardware** federation signer.
///
/// Hard cut to hybrid (CIRISVerify#75 — no classical-only anywhere): the
/// storage-tier scrub signature is a FULL HYBRID (sealed Ed25519 + ML-DSA-65) via
/// `Engine::with_hardware_signer_hybrid` (CIRISPersist#224). The Ed25519 half
/// stays hardware-sealed (never unsealed); the ML-DSA-65 half is the software PQC
/// signer. This also lets `local_identity_aggregate` surface the ML-DSA + the
/// persist-minted content-KEM halves for `/v1/identity` (#223).
async fn build_engine(
    cfg: &ServerConfig,
    signer: Arc<dyn HardwareSigner>,
    pqc: Arc<dyn PqcSigner>,
) -> Result<Arc<Engine>> {
    let pqc_key_id = format!("{}-pqc", cfg.key_id);
    let engine =
        Engine::with_hardware_signer_hybrid(signer, Some(pqc), Some(pqc_key_id), &cfg.dsn())
            .await
            .context("build shared persist Engine (hybrid hardware signer)")?;
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
    pqc: Arc<dyn PqcSigner>,
) -> Result<Edge> {
    let backend = engine
        .sqlite_backend()
        .context("Engine must be SQLite-backed for the relay")?
        .clone();
    // The edge transport signer wraps the SAME sealed-Ed25519 federation key as
    // the Engine PLUS the ML-DSA-65 PQC half — so every federation envelope the
    // node emits carries a FULL HYBRID signature (Ed25519 + ML-DSA-65). One
    // federation identity per node (distinct from the RNS transport-tier identity
    // held in the keystore below).
    let signer = Arc::new(EdgeSigner::new(cfg.key_id.clone(), signer, Some(pqc)));

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
        // The TYPED reticulum path (not the generic `.transport(Arc<dyn Transport>)`):
        // it both wires the transport for run/dispatch AND records it so
        // `Edge::local_transport_pubkey()` / `local_dest_hash()` resolve — which
        // populate the RET-transport role of GET /v1/identity.
        .reticulum_transport(transport)
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
