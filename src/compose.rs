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

    // ── Self-register Node A's own signing key in the federation directory ────
    // Required BEFORE any attestation Node A authors will be admitted:
    // `put_attestation` enforces that BOTH the attesting and attested keys exist
    // as `federation_keys` rows. Node A is a trust-root substrate process, so it
    // registers itself as identity_type "steward" through the v8.8.0 canonical
    // admission gate (`Engine::register_federation_key`, CIRISPersist#234 / CEG
    // 1.0-RC29 §5.6.8.15): self-signed proof-of-possession, hybrid-verified
    // fail-secure BEFORE store. Idempotent: a matching row returns Ok; a Conflict
    // (differing row) is benign and logged at debug. This also LOGS A's own
    // self-signed SignedKeyRecord as JSON (info) so an operator can hand it to
    // peer B as CIRIS_PEER_B_KEY_RECORD (the symmetric cross-repo contract).
    register_self_key(&engine, &cfg).await?;

    // ── ROOT-user bootstrap (CIRISServer#19) ──────────────────────────────────
    // Faithful port of the agent's `auth_service.bootstrap_if_needed`: if no ROOT
    // WA exists, load the baked ROOT trust-anchor seed (env CIRIS_ROOT_SEED_PATH or
    // CIRIS_ROOT_PUBKEY+CIRIS_ROOT_WA_ID) and store it + a child-of-root SYSTEM WA.
    // With no seed it is a clean no-op (info-logged) — the first-run
    // POST /v1/setup/root claim then lets the founder claim ROOT on a fresh node.
    // Either way the founder's identity becomes WaRole::Root → UserRole::SystemAdmin,
    // which is what the owner-gated POST /v1/federation/peering requires. Idempotent.
    let bootstrap_outcome = match crate::auth::bootstrap::bootstrap_if_needed(&engine).await {
        Ok(outcome) => {
            tracing::info!(?outcome, "root-user bootstrap evaluated");
            outcome
        }
        // A bad seed must not silently downgrade owner-claim to "open forever"; fail boot.
        Err(e) => return Err(anyhow::anyhow!("root-user bootstrap: {e}")),
    };

    // The node's OWN self-signed SignedKeyRecord as JSON — built ONCE at boot
    // (stable for the node's lifetime), served verbatim by
    // GET /v1/federation/self-key-record and the public record a peer registers
    // to admit this node's replicated rows.
    let self_key_record_json = self_key_record_json(&engine, &cfg).await?;

    // THIS node's own NodeCode (the QR-able federation-key bootstrap handle, CEG
    // §0.10) — built ONCE at boot from the node's steward key_id + the raw Ed25519
    // pubkey of its federation signing key + env-derived transport/alias hints.
    // Served (unauthenticated) by GET /v1/federation/node-code and used to
    // identity-pin the first-run ROOT claim (POST /v1/setup/root). Stable for the
    // node's lifetime.
    let node_code = node_self_code(&engine, &cfg).await?;
    let node_code_response_json = crate::federation_nodecode::render_response_json(&node_code)
        .map_err(|e| anyhow::anyhow!("render this node's NodeCode response: {e}"))?;

    // ── One-time CLAIM PIN — the operator-presence secret for the first-run
    //    ownership claim (CIRISServer first-run-PIN). On a FRESH, UNCLAIMED boot
    //    (no ROOT WaCert, no seed → BootstrapOutcome::NoSeedAvailable) mint a
    //    cryptographically-random, operator-typable PIN, print it in an unmissable
    //    banner ALONGSIDE the NodeCode, and arm the POST /v1/setup/root route with
    //    it. If a ROOT already exists (AlreadyBootstrapped / SeededRoot) NO PIN is
    //    minted — the route is 409-closed anyway. The PIN closes the hole that the
    //    NodeCode alone is a freely-shareable PUBLIC handle; it is printed ONLY to
    //    the console/log (optionally CIRIS_CLAIM_PIN_FILE) and is NEVER served over
    //    any HTTP route.
    let claim_pin: Option<String> = if bootstrap_outcome
        == crate::auth::bootstrap::BootstrapOutcome::NoSeedAvailable
    {
        let pin = crate::auth::bootstrap::generate_claim_pin();
        let node_code_str = crate::nodecode::encode(&node_code).map_err(|e| {
            anyhow::anyhow!("encode this node's NodeCode for the claim banner: {e}")
        })?;
        crate::auth::bootstrap::announce_ownership_unclaimed(&node_code_str, &pin);
        Some(pin)
    } else {
        tracing::info!(
            "node already has a ROOT owner — no first-run claim PIN minted (setup/root is closed)"
        );
        None
    };

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

    // ── Directed-consent federation peering with Node B (ciris-status) ────────
    // Bidirectional replication A<->B is authorized by DIRECTED CONSENT
    // ATTESTATIONS (federation scope) + MUTUAL KEY REGISTRATION — NOT in-group
    // trust (B is out of the canonical CIRIS infrastructure community). Gated on
    // the optional CIRIS_PEER_B_KEY_ID + CIRIS_PEER_B_KEY_RECORD env (B's own
    // self-signed SignedKeyRecord as JSON, per the v8.8.0 admission gate); when
    // unset the node skips peering.
    // Built BEFORE edge.run() consumes the Edge: the ReplicationRuntime reuses
    // the SAME Reticulum transport, and `install_replication_routing` wires the
    // runtime's registry into the Edge's inbound dispatch (so B's replicated
    // health:liveness lands in A's corpus). The handle is held for the node's
    // lifetime so the scheduler task isn't dropped.
    let _replication = setup_peer_replication(&engine, &edge, &cfg).await?;

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
                    // first-run ROOT claim (CIRISServer#19): POST /v1/setup/root —
                    // founder claims ROOT (→ SYSTEM_ADMIN) on a fresh, seedless node.
                    // Identity-pinned to THIS node's NodeCode (CEG §0.10): the claim
                    // must carry the node's own key_id+pubkey (the out-of-band code),
                    // proving the founder reached the intended node, not a spoof.
                    .merge(crate::auth::bootstrap::router(
                        Arc::clone(&engine),
                        strict,
                        node_code.key_id.clone(),
                        node_code.pubkey_ed25519_base64.clone(),
                        claim_pin.clone(),
                    ))
                    // sessions/tokens: login / logout / me / refresh / owner-hint
                    .merge(crate::auth::session::router(Arc::clone(&engine)))
                    // OAuth front-door + native google/apple
                    .merge(crate::auth::oauth::router(Arc::clone(&engine)))
                    // API keys + service-token revocation
                    .merge(crate::auth::api_keys::router(Arc::clone(&engine)))
                    // attestation / consent / erasure (CEG-native)
                    .merge(crate::auth::attestation::router(
                        Arc::clone(&engine),
                        strict,
                    ))
                    .merge(crate::auth::consent::router(Arc::clone(&engine), strict))
                    .merge(crate::auth::erasure::router(Arc::clone(&engine), strict))
                    // device-auth setup (scaffold)
                    .merge(crate::auth::device_auth::router(Arc::clone(&engine)))
                    // owner-directed federation peering: GET self-key-record +
                    // POST peering (each node authors its OWN consent grant).
                    .merge(crate::federation_admin::router(
                        Arc::clone(&engine),
                        cfg.key_id.clone(),
                        self_key_record_json.clone(),
                    ))
                    // THIS node's public NodeCode (CEG §0.10): GET
                    // /v1/federation/node-code — the QR-able bootstrap handle an
                    // operator reads off the node and hands to a founder's app.
                    .merge(crate::federation_nodecode::router(
                        node_code_response_json.clone(),
                    ))
            },
        )
        .await
        .context("start read API")?;
        tracing::info!(read_api = %read.listen_addr(), "read API up — GET /lens/api/v1/* + GET /v1/identity");
        Some(read)
    } else {
        None
    };

    // ── Capacity scorer — the score→emit pipeline (periodic, NOT in the ingest
    //    hot path). Derives per-agent N_eff from ingested traces and emits
    //    federation-tier `capacity:*` attestations to Node A's own corpus. Only
    //    when the host carries the local corpus (no corpus ⇒ nothing to score).
    //    Cadence + window are config-driven (CIRIS_SERVER_SCORER_*). ───────────
    let _scorer = if caps.lens_store {
        let scorer_cfg = crate::scorer::ScorerConfig::from_env();
        tracing::info!(
            cadence_secs = scorer_cfg.cadence.as_secs(),
            window = scorer_cfg.window,
            sample_gate = scorer_cfg.sample_size_gate,
            target_n_eff = scorer_cfg.target_n_eff,
            "capacity scorer spawned (score→emit; capacity:sustained_coherence:v1)"
        );
        Some(crate::scorer::spawn(
            Arc::clone(&engine),
            cfg.key_id.clone(),
            scorer_cfg,
        ))
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

/// Register Node A's own federation signing key in the federation directory as
/// identity_type **"steward"** (a trust-root substrate process) through the
/// **single canonical admission gate** — `Engine::register_federation_key`
/// (persist v8.8.0, CIRISPersist#234, CEG 1.0-RC29 §5.6.8.15).
///
/// We no longer hand-roll `put_public_key`: the gate is fail-secure — it
/// `verify_key_registration`s the row (hybrid Ed25519+ML-DSA-65, Strict,
/// proof-of-possession over `ceg_produce_canonicalize(registration_envelope)`
/// against `scrub_key_id`'s pubkeys, cross-checking `original_content_hash`)
/// BEFORE any store. For self-registration `scrub_key_id == key_id`, so A proves
/// possession of its OWN private keys and the verifier reads the pubkeys straight
/// off the submitted record. The hybrid Engine signs both halves, so the row
/// lands PQC-complete.
///
/// **Canonicalization MUST be `ceg_produce_canonicalize` (V2/JCS)** — the exact
/// form `verify_key_registration` re-canonicalizes and hashes against. (The older
/// `canonicalize_envelope_for_signing` is the Python-compat/strip-signature
/// writer; it would fail the gate's `original_content_hash` cross-check.)
///
/// Idempotent like the agent's bootstrap (edge_runtime.py:148): a row that
/// already matches returns `Ok(())`; an `Err(Conflict(..))` (a *differing* row
/// already holds this key_id) is benign here (logged at debug) — re-registering
/// our own stable identity should never legitimately conflict, and we must not
/// fail boot over a directory race.
///
/// This MUST happen before the scorer (or any other Node-A-authored attestation)
/// can be admitted: `put_attestation` requires the attesting key to exist as a
/// `federation_keys` row.
///
/// On success the (verified) record is **logged at info as JSON** so an operator
/// can hand A's self-signed `SignedKeyRecord` to peer B — see [`build_self_key_record`].
async fn register_self_key(engine: &Engine, cfg: &ServerConfig) -> Result<()> {
    use ciris_persist::federation::Error as FederationError;
    use ciris_persist::federation::SignedKeyRecord;

    let record = build_self_key_record(engine, cfg).await?;

    // Export A's own signed record for the operator to hand to peer B (the
    // cross-repo peering contract: CIRIS_PEER_B_KEY_RECORD = the peer's
    // SignedKeyRecord as serde_json). Both nodes on persist v8.8.0, so the serde
    // shape matches byte-for-byte. Logged BEFORE the (idempotent) register so it
    // is emitted even when the directory row already exists.
    match serde_json::to_string(&SignedKeyRecord {
        record: record.clone(),
    }) {
        Ok(json) => tracing::info!(
            key_id = %cfg.key_id,
            self_key_record = %json,
            "Node A's self-signed SignedKeyRecord (hand this JSON to peer B as CIRIS_PEER_B_KEY_RECORD)"
        ),
        Err(e) => {
            tracing::warn!(error = %e, "could not serialize Node A's self key record for export")
        }
    }

    match engine
        .register_federation_key(SignedKeyRecord { record })
        .await
    {
        Ok(()) => {
            tracing::info!(
                key_id = %cfg.key_id,
                "registered Node A's own steward key via register_federation_key \
                 (fail-secure admission gate; hybrid, PQC-complete)"
            );
            Ok(())
        }
        // Conflict = a differing row already holds this key_id. Benign on a
        // trust-root self-registration (edge_runtime.py:148 treats it the same):
        // do not fail boot.
        Err(FederationError::Conflict(msg)) => {
            tracing::debug!(
                key_id = %cfg.key_id,
                conflict = %msg,
                "self-registration is a benign conflict (key already present) — continuing"
            );
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("self-register Node A federation key: {e}")),
    }
}

/// Serialize THIS node's own self-signed `SignedKeyRecord` to JSON — the public
/// record `GET /v1/federation/self-key-record` serves and a peer registers (via
/// its own `POST /v1/federation/peering`) to admit this node's replicated rows.
/// Built from the SAME [`build_self_key_record`] assembly `register_self_key`
/// uses, so the GET output round-trips byte-identically through a peer's
/// `register_federation_key`.
async fn self_key_record_json(engine: &Engine, cfg: &ServerConfig) -> Result<String> {
    use ciris_persist::federation::SignedKeyRecord;
    let record = build_self_key_record(engine, cfg).await?;
    serde_json::to_string(&SignedKeyRecord { record })
        .context("serialize this node's self-signed SignedKeyRecord")
}

/// Build THIS node's own [`NodeCode`](crate::nodecode::NodeCode) (CEG §0.10).
/// Sourced from the SAME [`build_self_key_record`] assembly the self-key-record +
/// steward registration use, so the embedded Ed25519 pubkey is exactly this node's
/// federation signing-key pubkey. Hints come from the env surface
/// ([`crate::federation_nodecode`]). Built once at boot.
async fn node_self_code(engine: &Engine, cfg: &ServerConfig) -> Result<crate::nodecode::NodeCode> {
    let record = build_self_key_record(engine, cfg).await?;
    Ok(crate::federation_nodecode::build_node_code(
        &record.key_id,
        &record.pubkey_ed25519_base64,
    ))
}

/// Build Node A's self-signed [`KeyRecord`](ciris_persist::federation::types::KeyRecord)
/// — `scrub_key_id == key_id`, hybrid proof-of-possession over
/// `ceg_produce_canonicalize(registration_envelope)`. This is the exact record
/// the v8.8.0 admission gate verifies and that A exports for peer B to register.
pub(crate) async fn build_self_key_record(
    engine: &Engine,
    cfg: &ServerConfig,
) -> Result<ciris_persist::federation::types::KeyRecord> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ciris_persist::federation::types::{algorithm, KeyRecord};
    use ciris_persist::verify::canonical::ceg_produce_canonicalize;
    use sha2::{Digest, Sha256};

    // Registration envelope (the proof-of-possession signing payload). Minimal +
    // stable. Canonicalized via the CEG PRODUCE gate (V2/JCS) so it matches the
    // form `verify_key_registration` re-derives and hash-cross-checks.
    let envelope = serde_json::json!({ "key_id": cfg.key_id });
    let canonical = ceg_produce_canonicalize(&envelope)
        .map_err(|e| anyhow::anyhow!("ceg_produce_canonicalize self-registration envelope: {e}"))?;
    let original_content_hash = hex::encode(Sha256::digest(&canonical));

    // Hybrid-sign the canonical bytes (Ed25519 hardware-sealed + ML-DSA-65; the
    // PQC half is bound over canonical || classical_sig inside sign_hybrid). The
    // signature carries both pubkeys, so the registered row is PQC-complete.
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .context("hybrid-sign self-registration envelope")?;

    let now = chrono::Utc::now();
    Ok(KeyRecord {
        key_id: cfg.key_id.clone(),
        pubkey_ed25519_base64: B64.encode(&sig.classical.public_key),
        pubkey_ml_dsa_65_base64: Some(B64.encode(&sig.pqc.public_key)),
        algorithm: algorithm::HYBRID.to_owned(),
        // Node A is a trust-root substrate process → "steward" (published vocab).
        identity_type: "steward".to_owned(),
        identity_ref: cfg.key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash,
        scrub_signature_classical: B64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
        // Self-signed proof-of-possession: scrub_key_id == key_id.
        scrub_key_id: cfg.key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(), // server-computed on insert
        roles: Vec::new(),
        attestation_evidence: None,
    })
}

/// Set up directed-consent replication with Node B (`ciris-status`), if the
/// `CIRIS_PEER_B_*` env (KEY_ID + KEY_RECORD) is configured. Returns the live
/// [`ReplicationRuntime`] handle (held by the caller for the node's lifetime so
/// its scheduler task is not dropped), or `None` when no peer is configured /
/// the host carries no local corpus.
///
/// Steps (Node A side of the shared wire contract):
///   1. **Admission** — register B's published hybrid key (identity_type
///      `"witness"`) so B's replicated `health:liveness:*` is admitted.
///   2. **Consent** — emit the directed `consent:replication:v1` grant at B
///      (idempotent; the auditable "A consents to replicate capacity:* to B").
///   3. **Replication** — start a [`ReplicationRuntime`] (peer = B, kind =
///      `EnvelopeKind::Attestation`, which carries BOTH directions' attestations:
///      `capacity:*` out, `health:liveness` in) over the SAME Reticulum
///      transport the Edge already built, then `install_replication_routing` so
///      the Edge's inbound dispatch routes B's CRPL frames into the runtime's
///      registry (CIRISEdge#119) — B's `health:liveness` lands in A's corpus.
///
/// MUST run BEFORE `edge.run()` consumes the Edge:
/// `install_replication_routing` is a set-once `OnceLock` consulted by the
/// inbound loop, and `reticulum_transport()` must be cloned off the live Edge.
async fn setup_peer_replication(
    engine: &Arc<Engine>,
    edge: &Edge,
    cfg: &ServerConfig,
) -> Result<Option<ciris_edge::replication::ReplicationRuntime>> {
    use ciris_edge::replication::{
        EnvelopeKind, ReplicationPeer, ReplicationRuntime, ReplicationRuntimeConfig,
    };
    use ciris_persist::federation::FederationDirectory;

    let Some(peer) = cfg.peer_b.as_ref() else {
        tracing::info!(
            "no CIRIS_PEER_B_* configured — directed-consent replication disabled (single-node)"
        );
        return Ok(None);
    };

    // 1. Admission: register B's witness key (benign Conflict).
    crate::peer::register_peer_key(engine, peer).await?;

    // 2. Consent: emit the directed consent:replication:v1 grant at B (idempotent).
    //    Boot-env peering uses the DEFAULT prefix set (capacity:*); the owner can
    //    later author a different set via POST /v1/federation/peering.
    crate::peer::emit_replication_consent(
        engine,
        &cfg.key_id,
        &peer.key_id,
        &crate::peer::default_attestation_prefixes(),
    )
    .await?;

    // 3. Replication: reuse the Edge's Reticulum transport for the runtime.
    let Some(transport) = edge.reticulum_transport() else {
        tracing::warn!(
            "Edge has no Reticulum transport — cannot start replication runtime (peer configured \
             but no transport)"
        );
        return Ok(None);
    };
    let directory: Arc<dyn FederationDirectory> = engine
        .sqlite_backend()
        .context("replication runtime requires a SQLite-backed Engine")?
        .clone();

    let peers = vec![ReplicationPeer {
        peer_key_id: peer.key_id.clone(),
        // EnvelopeKind::Attestation carries BOTH directions: A's capacity:*
        // attestations out, B's health:liveness attestations in.
        kind: EnvelopeKind::Attestation,
    }];
    let runtime = ReplicationRuntime::start(
        directory,
        transport as Arc<dyn ciris_edge::transport::Transport>,
        peers,
        ReplicationRuntimeConfig::default(),
    )
    .await;

    // Wire the runtime's registry into the Edge's inbound dispatch (CIRISEdge#119):
    // inbound CRPL frames from B route to the matching coordinator → B's
    // health:liveness is applied to A's corpus via the directory put_* admits.
    edge.install_replication_routing(&runtime);

    tracing::info!(
        peer_key_id = %peer.key_id,
        kind = "attestation",
        "directed-consent replication runtime started + routed into the shared Edge"
    );
    Ok(Some(runtime))
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
