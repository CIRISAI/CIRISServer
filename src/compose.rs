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
use ciris_edge::transport::store_and_forward::{
    MemoryStoreAndForward, StoreAndForward, StoreAndForwardConfig,
};
use ciris_edge::transport::PendingDelivery;
use ciris_edge::{Edge, LocalSigner as EdgeSigner};
use ciris_keyring::{
    BlobTransportKeystore, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner, SealedEd25519Signer,
    TransportIdentityKeystore,
};
use ciris_lens_core::{LensCore, PeerAcl, ScoringConfig, UxConfig};
use ciris_persist::prelude::Engine;
use tokio::sync::watch;

use crate::adapter::{Adapter, AdapterContext, NoopAdapter};
use crate::config::{Capabilities, ServerConfig};

/// Re-announce cadence for the local Reticulum destination (Leviculum default).
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);

/// Boot the node with the default ([`NoopAdapter`]) — the byte-identical
/// pre-seam composition: build the shared Engine + Reticulum Edge, attach the
/// active slices the host can support, serve until shutdown.
pub async fn serve(cfg: ServerConfig) -> Result<()> {
    serve_with_adapter(cfg, Arc::new(NoopAdapter)).await
}

/// Boot the node with a downstream [`Adapter`] folded into the SAME shared core
/// (one persist `Engine` + one Reticulum `Edge`): the adapter's routers merge
/// onto the read-API listener, its `start` runs before the lifecycle, its
/// `run_lifecycle` runs as a supervised background task, and its `stop` runs on
/// shutdown. This is the "ciris-server + an adapter" seam (MISSION §1.2); the
/// default [`serve`] passes [`NoopAdapter`], so existing behavior is unchanged.
pub async fn serve_with_adapter(cfg: ServerConfig, adapter: Arc<dyn Adapter>) -> Result<()> {
    cfg.ensure_dirs()?;

    // ── HUMANITY_ACCORD STARTUP GATE (CC 4.2.3) ───────────────────────────────
    // Before anything else: refuse to boot if a 2-of-3 CONSTITUTIONAL halt latch
    // exists. "Not a recoverable pause" — only a manual removal of the latch (the
    // human act a valid accord:lifecycle:active re-activation authorizes) clears it.
    crate::accord_halt::check_halt_gate(&cfg.home)?;

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
    // build_engine + the federation/pqc/user signers above all key their KEYSTORE
    // blobs off `cfg.keystore_alias` (the RAW --key-id label) — so they MUST run
    // BEFORE the key_id derivation below, which leaves `keystore_alias` untouched.
    //
    // CIRISServer#221 — the AGENT FOLD. When the wheel runs with an already-composed
    // in-process engine (the brain's embedded runtime installed the persist
    // process-singleton via `Engine(config)`, so `current_rust_engine()` returns it),
    // REUSE it rather than `build_engine`'s `Engine::with_hardware_signer_hybrid`,
    // which opens a SECOND connection pool + sweeper on the same DSN (WAL-safe but
    // not clean; SQLITE_BUSY under a bursty cognitive loop). Mirrors
    // `start_federation_delivery`'s reuse. `embedded` then also drives the edge reuse
    // + skip-run below. The standalone binary (no embedded engine → `None`) builds
    // fresh, byte-for-byte unchanged.
    #[cfg(feature = "python")]
    let embedded_engine = ciris_persist::ffi::pyo3::current_rust_engine();
    #[cfg(not(feature = "python"))]
    let embedded_engine: Option<Arc<Engine>> = None;
    let embedded = embedded_engine.is_some();
    let engine = match embedded_engine {
        Some(e) => {
            tracing::info!(
                "serve_with_adapter: folding onto the in-process embedded Engine \
                 (CIRISServer#221) — one pool, one sweeper, no second writer"
            );
            e
        }
        None => build_engine(&cfg, Arc::clone(&signer), Arc::clone(&pqc)).await?,
    };

    // ── Derive the FSD-003 fingerprinted federation key_id (CIRISServer#27) ────
    // `cfg.key_id` started as the BARE label (== keystore_alias). Replace it with
    // the WIRE/DIRECTORY identity `derive_key_id(label, ed25519_pubkey)` =
    // `"<label>-<10char-b32(sha256(pubkey))>"`, derivable + verifiable from the
    // node's own federation pubkey. From here on every wire/directory surface
    // (KeyRecord.key_id, attestation author, NodeCode, config:*/consent author,
    // AdapterContext.key_id, occurrence_id, edge announce id) carries the derived
    // value; the KEYSTORE alias stays the raw label (no re-key). This re-keys the
    // node's directory ROW vs. a prior bare-"ciris-server" deploy — intended (#27).
    let ed_pub = signer
        .public_key()
        .await
        .context("read node ed25519 pubkey for key_id derivation")?;
    let mut cfg = cfg;
    cfg.key_id = ciris_verify_core::fedcode::derive_key_id(&cfg.keystore_alias, &ed_pub);
    cfg.occurrence_id = cfg.key_id.clone();
    let cfg = cfg;
    tracing::info!(
        key_id = %cfg.key_id,
        keystore_alias = %cfg.keystore_alias,
        "derived node federation key_id (FSD-003 label-fingerprint; CIRISServer#27)"
    );

    // ── The ADAPTER SEAM's shared-core handle (mirror of the agent adapter's
    //    `runtime`). Built ONCE the Engine exists; captured by clone into both
    //    the read-API router closure (adapter.routers) and the lifecycle task. ─
    let adapter_ctx = AdapterContext {
        engine: Arc::clone(&engine),
        key_id: cfg.key_id.clone(),
        cfg: cfg.clone(),
    };

    // ── Self-register Node A's own signing key in the federation directory ────
    // Required BEFORE any attestation Node A authors will be admitted:
    // `put_attestation` enforces that BOTH the attesting and attested keys exist
    // as `federation_keys` rows. Node A is a fabric NODE (infrastructure, NO
    // agency — CC 1.13.5), so it registers itself as identity_type "node"
    // (corrected from "steward") through the v8.8.0 canonical
    // admission gate (`Engine::register_federation_key`, CIRISPersist#234 / CEG
    // 1.0-RC29 §5.6.8.15): self-signed proof-of-possession, hybrid-verified
    // fail-secure BEFORE store. Idempotent: a matching row returns Ok; a Conflict
    // (differing row) is benign and logged at debug. This also LOGS A's own
    // self-signed SignedKeyRecord as JSON (info) so an operator can hand it to
    // peer B as CIRIS_PEER_B_KEY_RECORD (the symmetric cross-repo contract).
    register_self_key(&engine, &cfg).await?;

    // ── The node-scoped `substrate_persist` producer identity (CIRISServer#181) ─
    // A SEPARATE hybrid key (identity_type = substrate_persist) the node uses to
    // author substrate-RESERVED rows — today the CC 4.5.13 `content_class:*`
    // infohazard flag (POST /v1/safety/flag). The node's OWN key is `node`-typed
    // (infrastructure, CC 1.13.5) and CANNOT emit a reserved prefix
    // (`federation_reserved_prefix_emitter_mismatch`); a federation_keys row is
    // one identity_type per key_id, so the reserved-flag authority lives in this
    // second, dedicated key. Minted+sealed at boot, registered through the same
    // canonical admission gate as the node key. The duty-HOLDER authorizes the
    // flag at the HTTP layer; THIS key SIGNS it.
    let (substrate_signer, substrate_identity) = substrate_persist_signer(&cfg).await?;
    let substrate_key_id = register_substrate_key(&engine, &substrate_identity).await?;
    tracing::info!(
        substrate_key_id = %substrate_key_id,
        "registered node substrate_persist identity (content_class flag producer; \
         CIRISServer#181)"
    );

    // Seed the node's federation identity into the graph so the client's Graph page
    // is never empty on a fresh install (mirrors the agent's agent/identity seed).
    crate::memory_api::seed_identity_graph(&engine, &cfg.key_id, "node").await;

    // Project persist's rich CEG state (owner-binding, owned nodes, the humanity
    // accord family + holders, canonical servers, every config:* value, and the
    // node's authored attestations) into the memory graph as typed, CEG-native
    // nodes + edges — so the client's Graph page is a contextual mesh of
    // AttestationCards, not a single lonely identity node (CIRISServer#127++).
    // Idempotent, version-safe, fail-secure (a projection error only logs).
    crate::memory_api::seed_ceg_graph(&engine, &cfg.key_id).await;

    // ── CONFIG-AS-CEG resolution (Server 0.5 Phase 2) ─────────────────────────
    // Resolve the migrated runtime-tunable knobs from the corpus's signed
    // `config:*` objects (baked default per absent key) into the initial snapshot,
    // and publish it on a `watch` channel. Consumers read the LIVE snapshot: the
    // scorer reads it HOT each cycle (cadence/window/gate/target retune with no
    // restart); the replication reconciler sources its cadence from it (hot); the
    // edge transport + posture (`transport.*`, `mode`) are boot-structural — built
    // once from this snapshot, reconcile on next boot (the value now lives in CEG,
    // not env). The config reconciler (spawned below) re-resolves + republishes on
    // its cadence + a `POST /v1/config` nudge.
    let initial_config = crate::config_reconcile::resolve(&engine, &cfg.key_id).await;
    tracing::info!(
        ?initial_config,
        "resolved initial config:* snapshot (Server 0.5 — knobs now live in CEG, not env)"
    );

    // Apply the boot-structural NETWORK knobs from the resolved snapshot onto the
    // node config BEFORE the edge is built. `net.listen_addr` / `net.bootstrap_peers`
    // were env (CIRIS_SERVER_LISTEN_ADDR / CIRIS_SERVER_BOOTSTRAP_PEERS); they are
    // now config:* objects with baked defaults. A malformed listen_addr falls back
    // to the value `from_home` already baked in (never wedge boot on a bad row).
    let mut cfg = cfg;
    match initial_config.listen_addr.parse::<std::net::SocketAddr>() {
        Ok(addr) => cfg.listen_addr = addr,
        Err(e) => tracing::warn!(
            value = %initial_config.listen_addr,
            error = %e,
            "config:* net.listen_addr is not a valid host:port — keeping the baked default"
        ),
    }
    // Reachability = the BAKED canonical servers' signed envelope transport hints
    // (CIRISPersist#381), unioned with the optional `net.bootstrap_peers` override.
    // The baked hints are the primary source (self-describing seed, no compiled-in
    // IP); config is the break-glass. Returns empty until persist bakes the hints,
    // so this is a no-op on a substrate without the field (forward-compatible).
    {
        let mut peers = canonical_bootstrap_addrs(&engine).await;
        let n_canonical = peers.len();
        peers.extend(crate::config::parse_bootstrap_peers(
            initial_config.bootstrap_peers.iter().cloned(),
        ));
        peers.sort();
        peers.dedup();
        tracing::info!(
            canonical_hints = n_canonical,
            total = peers.len(),
            "bootstrap dial set resolved (baked canonical envelope hints + net.bootstrap_peers override)"
        );
        cfg.bootstrap_peers = peers;
    }
    let cfg = cfg;

    let (config_tx, config_rx) = watch::channel(initial_config.clone());

    // ── ROOT-user bootstrap (CIRISServer#19) ──────────────────────────────────
    // Server 0.5 (zero env): a fresh node has NO baked root — it trusts
    // ciris-canonical (per the constitution) and the FOUNDER claims ROOT via the
    // first-run POST /v1/setup/root (NodeCode + one-time PIN) flow. The prior
    // env-seed pre-seed branch (CIRIS_ROOT_*) is deleted, so this is always a clean
    // no-op-then-claim: `bootstrap_if_needed` returns NoSeedAvailable and the
    // serve-only-until-owned floor + the require_owner_bound gate stay EXACTLY as-is.
    // On a successful claim the founder's identity becomes WaRole::Root →
    // UserRole::SystemAdmin, which is what the owner-gated peering requires. Idempotent.
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
    let self_key_record_json = self_key_record_json(&cfg).await?;

    // THIS node's own NodeCode (the QR-able federation-key bootstrap handle, CEG
    // §0.10) — built ONCE at boot from the node's steward key_id + the raw Ed25519
    // pubkey of its federation signing key + the config:* node.alias hint.
    // Served (unauthenticated) by GET /v1/federation/node-code and used to
    // identity-pin the first-run ROOT claim (POST /v1/setup/root). Stable for the
    // node's lifetime.
    // The node alias hint comes from the resolved config:* `node.alias` (Server
    // 0.5 — no CIRIS_NODE_ALIAS env); falls back to the node key_id when unset.
    let node_alias = if initial_config.node_alias.trim().is_empty() {
        cfg.key_id.clone()
    } else {
        initial_config.node_alias.clone()
    };
    let node_code = node_self_code(&cfg, Some(node_alias)).await?;
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
    //    the console/log (and ALSO to the conventional `home/claim_pin` file for
    //    headless ops) and is NEVER served over any HTTP route.
    let claim_pin: Option<String> =
        if bootstrap_outcome == crate::auth::bootstrap::BootstrapOutcome::NoSeedAvailable {
            let pin = crate::auth::bootstrap::generate_claim_pin();
            let node_code_str = crate::nodecode::encode(&node_code).map_err(|e| {
                anyhow::anyhow!("encode this node's NodeCode for the claim banner: {e}")
            })?;
            crate::auth::bootstrap::announce_ownership_unclaimed(
                &node_code_str,
                &pin,
                Some(cfg.claim_pin_file()),
            );
            Some(pin)
        } else {
            tracing::info!(
            "node already has a ROOT owner — no first-run claim PIN minted (setup/root is closed)"
        );
            None
        };

    // ── ONE shared Reticulum edge runtime — the node's single federation
    //    transport identity. From here the node IS a Reticulum node. ───────────
    // Edge transport flags are boot-structural: built ONCE from the resolved
    // config:* snapshot (transport.node / transport.store_and_forward). Changing
    // them in CEG reconciles on the next boot.
    // CIRISServer#221 — in the fold, REUSE the agent's already-running edge
    // (`init_edge_runtime` installed it; `current_edge()` returns the `Arc<Edge>`)
    // instead of `build_edge`, which would bind a SECOND Reticulum transport on the
    // same `net.listen_addr` (:4242) — a hard "address in use" conflict with the
    // agent's transport. The reused edge is already `run()`ing, so the edge.run()
    // spawn below is skipped for `embedded`. Slice attach + read-API mount proceed
    // on the shared edge (the routing registries edge reads live per inbound frame).
    let edge: Arc<Edge> = if embedded {
        ciris_edge::current_edge().context(
            "CIRISServer#221 fold: embedded Engine present but current_edge() is None — \
             init_edge_runtime must run before serve_with_python_adapter",
        )?
    } else {
        Arc::new(
            build_edge(
                &engine,
                &cfg,
                initial_config.transport_node,
                initial_config.store_and_forward,
                &initial_config,
                Arc::clone(&signer),
                Arc::clone(&pqc),
            )
            .await?,
        )
    };

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
             (no local corpus / read API); free up disk to the baked minimum"
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
    let identity_json = local_identity_json(&engine, edge.local_transport_pubkey(), &cfg.key_id)
        .await
        .context("assemble /v1/identity aggregate")?;

    // ── Self-publish this node's reticulum transport-tier binding ─────────────
    // (dest_hash + transport-tier Ed25519) into the federation directory, so a
    // peer can `prime_peer`-root this node even though a v7.0.0 explicit-hash
    // destination CANNOT announce (Leviculum `ExplicitHashCannotAnnounce`).
    // CIRISServer#205 gap #2 / CIRISPersist#397: the baked/self-signed record
    // carries only the identity-tier Ed25519 + the IP hint; the transport
    // identity is edge-runtime-derived (unknown at genesis-bake), so the node
    // asserts it here at boot — the same self-authenticating basis (its own
    // key_id, its own edge-owned transport identity) as an attested announce.
    // Best-effort; a node with no Reticulum transport is a no-op. This is why
    // delivery converges with ZERO operator action: restarting the node IS the
    // publish (the directory row replicates, peers resolve + prime it).
    publish_self_transport_destination(&engine, &edge, &cfg.key_id).await;

    // ── Sealability twin (#227 S1): publish this node's SIGNED identity occurrence
    // (content-enc pubkeys from sealed custody) so peers can resolve + SEAL to it —
    // transport binding = how to REACH me, occurrence = how to SEAL to me. Best-effort,
    // idempotent (last-signed-wins re-assert each boot); the agent does nothing.
    publish_self_identity_occurrence(&engine, &edge, &cfg).await;

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
    // health:liveness lands in A's corpus). The handle (an Arc) is held for the
    // node's lifetime AND shared with the CEG-driven reconcile loop below.
    let replication = setup_peer_replication(&engine, &edge, &cfg).await?;

    // ── CEG-native trusted-peer boot prime (CIRISServer#221 companion) ────────
    // An explicit-hash canonical (v7.0.0, Leviculum ExplicitHashCannotAnnounce)
    // NEVER self-roots via the inbound admit-advisory path — it is the OUTBOUND
    // delivery target the node DIALS, so it must be rooted out-of-band via
    // `prime_peer`. `start_federation_delivery` primes on the embedded edge; the
    // node-composed runtime (the agent fold, serve_with_python_adapter) needs the
    // same, or the canonical stays knows_peer=false → coordinator error → 0
    // envelopes. Runs in BOTH the standalone node and the fold (edge is shared).
    prime_trusted_peers(&engine, &edge).await;

    // ── Canonical bootstrap boot prime (CIRISServer#238) ──────────────────────
    // `prime_trusted_peers` primes from Rooted `transport_destination` ROWS — but
    // the baked canonical seed carries only a KeyRecord (+ an IP dial hint), no
    // such row, so the canonical was NEVER boot-primed and rooted only via its
    // slow/unreliable announce (~130-200s, or never). An explicit-hash peer needs
    // just `(dest_hash, ed25519)`, BOTH deterministically derivable from the fed
    // Ed25519 pubkey the seed already carries: `dest_hash =
    // reticulum_destination_for_pubkey(fed_ed25519) = sha256(fed_ed25519)[..16]`,
    // and the link signing key IS that same fed Ed25519 (transport and federation
    // share the Ed25519 signing half; the v10.1.0 split was in the unused X25519).
    prime_canonical_bootstrap_peers(&engine, &edge).await;

    // ── Holonomic-tier swarm runtime (CIRISServer#11) ─────────────────────────
    // The publisher advertises the fountain content THIS node holds as signed
    // FountainHoldingClaim envelopes to the consent cohort; the converger acts
    // on PEERS' claims (tier-evict / hard-delete locally-held symbols once a
    // content unit is sufficiently replicated). Like the ReplicationRuntime it
    // reuses the SAME Reticulum transport and MUST install BEFORE edge.run()
    // consumes the Edge (install routes verified inbound claims into the
    // converger, CIRISEdge#184). Gated on `caps.lens_store`: the holonomic tier
    // only makes sense when the node carries the corpus — a relay-only node
    // holds no fountain content and has nothing to publish or converge. The
    // handle is bound for the node's lifetime so the publisher/converger tasks
    // are not dropped.
    let _swarm = if caps.lens_store {
        crate::holonomic::install_swarm_runtime(&engine, &edge, &cfg).await
    } else {
        None
    };

    // ── CEG-driven reconcile nudge ────────────────────────────────────────────
    // The peering API (POST /v1/federation/peering) NEVER touches the runtime — it
    // writes a consent:replication CEG object and fires this Notify so the
    // reconcile loop converges promptly instead of waiting for the next cadence
    // tick. When there is no runtime (no transport) the API still writes CEG; the
    // notify target is then `None`.
    let reconcile_notify = Arc::new(tokio::sync::Notify::new());

    // ── Mesh control-plane relay, remote half (#128 Phase D — C3) ─────────────
    // Register the RNS control RESPONDER on the shared Edge BEFORE `edge.run()`
    // consumes it (registration is `&self`; the run loop's inbound dispatcher
    // invokes the handler inline). Kind 0x0000_0001 — CIRISServer's CC 0.7
    // Tier-2 allocation (WIRE_VOCABULARY_KINDS.md). The responder's v1 dispatch
    // router does not exist yet at this point in boot, so it rides an
    // Arc<OnceLock<Router>> the read-API block below fills; a relay arriving in
    // the boot gap gets an honest 503 (never a drop). This makes every owned
    // node ADMINISTRABLE over RNS by its owner's signature.
    let mesh_dispatch_router: Arc<std::sync::OnceLock<axum::Router>> =
        Arc::new(std::sync::OnceLock::new());
    let mesh_responder = Arc::new(crate::mesh_relay::MeshControlResponder::new(
        Arc::clone(&engine),
        node_code.key_id.clone(),
        Arc::clone(&mesh_dispatch_router),
    ));
    crate::mesh_relay::register_mesh_control_handler(&edge, Arc::clone(&mesh_responder));

    // edge v8.2.0 (CIRISEdge#249) makes `Edge::run` take `self: Arc<Self>`, so
    // the composition root can now retain a live `Arc<Edge>` ACROSS the run loop
    // — the enabler for the C1 initiator leg. All the pre-run captures above
    // (`local_transport_pubkey`, `setup_peer_replication`, the swarm runtime,
    // the mesh responder registration) took `&edge` before this point and are
    // done; from here `edge` (already an `Arc<Edge>` — freshly built + wrapped, or
    // the reused embedded edge per #221) is shared between the run task and the
    // requester.

    // The local SEND leg (C1's mesh hop) — the Phase E INITIATOR leg, now LIVE.
    // `target == self` short-circuits into the in-process responder (edge does
    // not loop a send back to its own destination); every OTHER owned target
    // sends for real over RNS via `send_opaque_request` on the retained
    // `Arc<Edge>` (FSD §6). This retires the v8.0.0 `local_only_requester` stub
    // that 502'd cross-node sends while edge's `run(self)` consumed the Edge.
    let mesh_requester = crate::mesh_relay::edge_mesh_requester_with_loopback(
        Arc::clone(&edge),
        node_code.key_id.clone(),
        Arc::clone(&mesh_responder),
    );

    // ── Run the one shared Edge (a single Reticulum transport per node) ───────
    // CIRISServer#221: in the fold the embedded edge is ALREADY `run()`ing (the
    // agent spawned it from init_edge_runtime) — spawning a second run loop on the
    // same Edge would double-drive one transport. Skip it; the standalone node runs it.
    let (edge_shutdown_tx, edge_shutdown_rx) = watch::channel(false);
    let edge_join = if embedded {
        drop(edge_shutdown_rx);
        None
    } else {
        let edge_run = Arc::clone(&edge);
        Some(tokio::spawn(
            async move { edge_run.run(edge_shutdown_rx).await },
        ))
    };

    // ── The CEG-driven replication reconcile loop ─────────────────────────────
    // Converges the live ReplicationRuntime to the corpus's consent:replication
    // objects (the desired topology). Driven by a cadence tick
    // (CIRIS_SERVER_REPLICATION_RECONCILE_SECS, default 30) AND the Notify the
    // peering API fires after a CEG write. Spawned only when a runtime exists.
    let (reconcile_sd_tx, reconcile_sd_rx) = watch::channel(false);
    let reconcile_join = replication.as_ref().map(|runtime| {
        crate::replication_reconcile::spawn(
            Arc::clone(&engine),
            cfg.key_id.clone(),
            Arc::clone(runtime),
            Arc::clone(&reconcile_notify),
            config_rx.clone(),
            reconcile_sd_rx,
        )
    });

    // ── The CEG-driven CONFIG reconcile loop (Server 0.5 Phase 2) ─────────────
    // Re-resolves the migrated knobs from the corpus's `config:*` objects on its
    // own cadence + the SAME `reconcile_notify` the config API fires after a write,
    // and republishes the live `ResolvedConfig` on `config_tx`. Consumers (scorer,
    // replication reconciler) read the receiver: scorer knobs are hot; transport /
    // mode are boot-structural. ONE Notify is shared by config_api + this loop.
    let (config_sd_tx, config_sd_rx) = watch::channel(false);
    let config_reconcile_join = crate::config_reconcile::spawn(
        Arc::clone(&engine),
        cfg.key_id.clone(),
        config_tx,
        Arc::clone(&reconcile_notify),
        config_sd_rx,
    );

    // ── The responsible-USER signer for POST /v1/setup/claim-remote is no longer
    //    resolved at boot (it would be absent on a fresh node — the fed-ID is minted
    //    DURING the first-run wizard). The claim-remote router resolves it at request
    //    time from the conventional user-seed path; see `resolve_user_signer`. ─────

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
                // Capture the adapter + its shared-core handle for the move
                // closure (the seam: fold the adapter's routers in below).
                let adapter = Arc::clone(&adapter);
                let adapter_ctx = adapter_ctx.clone();
                // The accord peer base URLs (self excluded) — the shared gossip set for
                // BOTH the kill-switch (accord::router_with_halt) and the co-scrub partial
                // fan-out (accord_provision::build). Same discipline as the halt: never
                // gossip back to self.
                let accord_peers: Vec<String> = cfg
                    .bootstrap_peers
                    .iter()
                    .filter(|a| **a != cfg.listen_addr)
                    .map(|a| format!("http://{a}"))
                    .collect();
                let provision =
                    crate::accord_provision::build(Arc::clone(&engine), accord_peers.clone());
                let r = identity_router(identity_json)
                    // Server health — the node's OWN liveness (/health, /v1/health,
                    // /v1/system/health). Mandatory base; the agent enriches the
                    // /v1/system/health endpoint with optional cognitive health.
                    .merge(crate::health::router())
                    // GET /v1/system/verify-status — read-only CIRISVerify status
                    // (loaded + the node's derived key_id + custody class) for the
                    // client's Trust & Security display. The verify family is in the
                    // node substrate, so this is node-valid. TODO(verify-status):
                    // report the real custody class from the federation signer's
                    // attestation; SOFTWARE_ONLY is the honest floor until then.
                    .merge(crate::health::verify_status_router(
                        Arc::clone(&engine),
                        "SOFTWARE_ONLY".to_string(),
                    ))
                    // login ceremony (self-at-login → user-managed consent). The
                    // admin-eligibility allowlist is the boot-resolved config:*
                    // auth.admin_key_ids (Server 0.5 — replaces CIRIS_ADMIN_KEY_IDS).
                    .merge(crate::auth::self_login::router(
                        Arc::clone(&engine),
                        strict,
                        initial_config.admin_key_ids.clone(),
                    ))
                    // self-occurrence enrollment (CIRISServer#76): add a second
                    // device (phone) as an occurrence of the self + revoke a
                    // lost/stolen one + list the device roster. Signed by an
                    // existing active occurrence / the identity root (the
                    // signature is the gate — same posture as self/login).
                    .merge(crate::auth::occurrence::router(Arc::clone(&engine), strict))
                    // first-run ROOT claim (CIRISServer#19): POST /v1/setup/root —
                    // founder claims ROOT (→ SYSTEM_ADMIN) on a fresh, seedless node.
                    // Identity-pinned to THIS node's NodeCode (CEG §0.10): the claim
                    // must carry the node's own key_id+pubkey (the out-of-band code),
                    // proving the founder reached the intended node, not a spoof.
                    // Setup/apex routes (bootstrap, claim-remote, self/identity)
                    // open during first-run WITHOUT an owner session, so they are
                    // additionally restricted to LOOPBACK peers (the read API binds
                    // 0.0.0.0; federation reads stay public, these do not).
                    // bootstrap::router self-guards now (v0.5.37): /v1/setup/root is
                    // PIN + signed-owner-binding gated and network-reachable (no
                    // tunnel needed for a remote/delegated claim); the no-PIN setup
                    // reads (status, owned-nodes) keep their own loopback layer
                    // INSIDE the router. So no blanket loopback layer here.
                    .merge(crate::auth::bootstrap::router(
                        Arc::clone(&engine),
                        strict,
                        node_code.key_id.clone(),
                        node_code.pubkey_ed25519_base64.clone(),
                        claim_pin.clone(),
                        // The durable PIN file to delete on a successful claim
                        // (the same conventional path announce_ownership_unclaimed
                        // writes). Only meaningful when a PIN was minted.
                        claim_pin.as_ref().map(|_| cfg.claim_pin_file()),
                    ))
                    // claim REMOTE ownership (substrate-native, node-to-node):
                    // POST /v1/setup/claim-remote — the LOCAL node decodes the
                    // target NodeCode, builds + hybrid-signs the owner-binding
                    // with the responsible USER's key, and POSTs it to the
                    // target's POST /v1/setup/root. Owner-gated once owned; open on
                    // first-run + loopback. The user signer is resolved at request
                    // time (see below) so a fed-ID minted during this same wizard is
                    // available to the self-claim that follows it.
                    .merge(
                        crate::claim_remote::router(
                            Arc::clone(&engine),
                            node_code.key_id.clone(),
                            // Resolve the responsible-user signer at REQUEST time from
                            // these inputs (the fed-ID is minted during the wizard, after
                            // boot), so the automated self-claim that follows the mint
                            // finds it. Was a boot-resolved Option (always None on a fresh
                            // node) — which left claim-remote permanently disabled.
                            format!("{}-user", cfg.keystore_alias),
                            crate::user_seed_dir(&cfg),
                            // SELF-claim loopback fallback: this node's own read-API URL,
                            // used when a loopback node's NodeCode carries no transport.
                            format!("http://127.0.0.1:{}", cfg.read_api_addr().port()),
                            // Hybrid-verify policy for the local upgrade-owner apply.
                            strict,
                        )
                        .layer(axum::middleware::from_fn(
                            crate::auth::loopback::require_loopback,
                        )),
                    )
                    // MESH CONTROL RELAY (#128 Phase D — C1): POST /v1/mesh/relay.
                    // The owner (or an `owner:act-on-behalf` dgrant whose
                    // constraints permit `mesh_relay`) drives an allow-listed
                    // owner-op on an owned REMOTE node addressed purely by
                    // key_id: the endpoint hybrid-signs the control envelope
                    // with the owner fed-ID (same request-time signer inputs as
                    // claim-remote above) and ships it over the mesh seam as
                    // opaque kind 0x0000_0001 (FSD/RNS_CONTROL_RELAY.md §6).
                    .merge(crate::mesh_relay::router(
                        Arc::clone(&engine),
                        format!("{}-user", cfg.keystore_alias),
                        crate::user_seed_dir(&cfg),
                        Some(mesh_requester.clone()),
                        crate::mesh_relay::RELAY_TIMEOUT_MS,
                    ))
                    // provision/ensure the local node's USER federation identity
                    // (CIRISServer#21): POST /v1/self/identity — mints a hardware-
                    // rooted (YubiKey / TPM-SE / software) user identity + returns
                    // its key_id + fedcode. Owner-gated; the federation-ID wizard
                    // in the app drives it.
                    .merge(
                        crate::identity::router(
                            Arc::clone(&engine),
                            // The user-identity mint alias is `<keystore_alias>-user`
                            // (a KEYSTORE blob) — pass the RAW label so the minted
                            // blob matches what `user_identity_signer` re-opens.
                            cfg.keystore_alias.clone(),
                            crate::user_seed_dir(&cfg),
                        )
                        .layer(axum::middleware::from_fn(
                            crate::auth::loopback::require_loopback,
                        )),
                    )
                    // PORTABLE software identity occurrence (bootstrap): POST
                    // /v1/self/occurrence/portable mints a fresh *software* hybrid
                    // keyset into a chosen USB dir + binds it as a primary-authorized
                    // occurrence of the owner's self; POST /v1/self/associate installs
                    // a portable keyset as THIS device's user fed-ID. Owner-gated
                    // per-handler + loopback-only (the node does all the file I/O; no
                    // key material crosses the wire). The owner accepts that a software
                    // keyset is inherently insecure — the labeled trade-off.
                    .merge(
                        crate::auth::portable_occurrence::router(
                            Arc::clone(&engine),
                            node_code.key_id.clone(),
                            Arc::new(cfg.clone()),
                        )
                        .layer(axum::middleware::from_fn(
                            crate::auth::loopback::require_loopback,
                        )),
                    )
                    // sessions/tokens: login / logout / me / refresh / owner-hint
                    .merge(crate::auth::session::router(Arc::clone(&engine)))
                    // OAuth front-door + native google/apple. The callback base
                    // is the boot-resolved config:* auth.oauth_callback_base_url
                    // (Server 0.5 — replaces OAUTH_CALLBACK_BASE_URL).
                    .merge(crate::auth::oauth::router(
                        Arc::clone(&engine),
                        initial_config.oauth_callback_base_url.clone(),
                    ))
                    // API keys + service-token revocation
                    .merge(crate::auth::api_keys::router(Arc::clone(&engine)))
                    // device-authorization grant (RFC 8628 shape): authorize an
                    // external client/agent to act on the OWNER's behalf via the
                    // node API. code → owner-approve (hardware fed-ID session) →
                    // poll → DELEGATED token (owner authority + actor attribution).
                    .merge(crate::auth::device_grant::router(
                        Arc::clone(&engine),
                        // The LOCAL responsible-owner's fed-ID (the delegates_to
                        // issuer) + where its signer re-opens (hardware presence
                        // prompted on approve/revoke).
                        format!("{}-user", cfg.keystore_alias),
                        crate::user_seed_dir(&cfg),
                    ))
                    // attestation / consent / erasure (CEG-native)
                    .merge(crate::auth::attestation::router(
                        Arc::clone(&engine),
                        strict,
                    ))
                    .merge(crate::auth::consent::router(Arc::clone(&engine), strict))
                    .merge(crate::auth::erasure::router(Arc::clone(&engine), strict))
                    // device-auth setup (scaffold). The session file lives under
                    // the node home (Server 0.5 — no CIRIS_HOME/$HOME env).
                    .merge(crate::auth::device_auth::router(
                        Arc::clone(&engine),
                        cfg.home.clone(),
                    ))
                    // owner-directed federation peering: GET self-key-record +
                    // POST peering (each node authors its OWN consent grant).
                    .merge(crate::federation_admin::router(
                        Arc::clone(&engine),
                        cfg.key_id.clone(),
                        self_key_record_json.clone(),
                        // Nudge the reconciler after a consent write (CEG changed)
                        // — but ONLY when a runtime exists to converge. The handler
                        // itself never touches the runtime; this is just a signal.
                        replication.as_ref().map(|_| Arc::clone(&reconcile_notify)),
                    ))
                    // CONFIG-AS-CEG (Server 0.5): the owner-gated /v1/config
                    // surface over the signed GraphConfig store. A write is gated
                    // the SAME way peering is (serve-only floor + SYSTEM_ADMIN owner
                    // session). Phase 2 wires the SHARED reconcile_notify: a
                    // successful write nudges the config reconciler so the live
                    // ResolvedConfig snapshot converges promptly (the API never
                    // touches the runtime — it writes CEG + nudges this loop).
                    .merge(crate::config_api::router(
                        Arc::clone(&engine),
                        cfg.key_id.clone(),
                        Some(Arc::clone(&reconcile_notify)),
                    ))
                    // THIS node's public NodeCode (CEG §0.10): GET
                    // /v1/federation/node-code — the QR-able bootstrap handle an
                    // operator reads off the node and hands to a founder's app.
                    .merge(crate::federation_nodecode::router(
                        node_code_response_json.clone(),
                    ))
                    // The SAFETY FOUNDATION (CIRISServer#20): the /v1/safety/*
                    // surface the client safety cards drive — age-assurance +
                    // the protective age-gate, moderation as a delegable DUTY
                    // (the §11.10 admit-iff gate, composed from persist v9.0.0),
                    // the CC 4.5.4 named-moderator existence invariant
                    // (fail-secure + merit auto-promotion), and the opt-in
                    // per-group watchlist config (the matcher defers to the
                    // NodeCore content seam). Built AHEAD of media/social content.
                    .merge(crate::safety::router(
                        Arc::clone(&engine),
                        strict,
                        // The node's substrate_persist producer identity — authors
                        // the reserved content_class flag POST /v1/safety/flag emits.
                        Some(Arc::clone(&substrate_signer)),
                    ))
                    // HUMANITY_ACCORD surface (CIRISServer#41): accord-holder
                    // registry (owner-gated register + cold-start GET
                    // /v1/accord-holders) + the server-canonical 2-of-3 invocation
                    // kill-switch (CC 4.2.1 / §9.2.1) + the OPERATIONAL halt — POST
                    // /v1/accord/message replicates an authentic accord message to
                    // all known peers and, for a 2-of-3 CONSTITUTIONAL, replicates
                    // FIRST then latches the disk halt (HUMANITY_ACCORD_HALT under
                    // home, gating all future startups) and terminates. The
                    // safe-mesh floor.
                    .merge(crate::accord::router_with_halt(
                        Arc::clone(&engine),
                        crate::accord::AccordHalt {
                            home: Some(cfg.home.clone()),
                            // Replicate accord messages to known peers — EXCLUDING
                            // self (an operator who lists this node in bootstrap_peers
                            // must not make it gossip/halt-loop back to itself).
                            peers: accord_peers.clone(),
                            exit_on_halt: true,
                        },
                    ))
                    // ACCORD-HOLDER PROVISIONING (CIRISServer#41, the safe-mesh
                    // floor): POST /v1/accord/provision-holder — the loopback-only
                    // setup route behind the guided desktop "Provision Accord
                    // Holder" flow. Drives accord_custody::provision_portable_holder
                    // from the holder's already-FIPS-approved YubiKey + the chosen
                    // ML-DSA USB path. LOOPBACK-only (a holder-device op run on the
                    // node's own host; the OWNER gate is downstream at POST
                    // /v1/accord/holder). pkcs11-feature-gated (NotSupported
                    // without it). Mirrors the other setup routers' loopback guard.
                    .merge(provision.loopback.layer(axum::middleware::from_fn(
                        crate::auth::loopback::require_loopback,
                    )))
                    // Co-scrub gossip receive — the OPEN counterpart. A remote accord
                    // peer POSTs a gossiped co-scrub partial here (A1's box → B1's box),
                    // so this ONE endpoint must NOT be loopback-gated. Shares the pending
                    // store with the loopback `GET /pending` the client reads. Structural
                    // validation + bounded; the security gate stays at persist's m-of-n.
                    .merge(provision.gossip)
                    // FEDERATION PEERS (agent-compat Network card): GET
                    // /v1/federation/peers + GET /v1/federation/peers/{key_id}
                    // — projects the federation_directory `federation_keys`
                    // rows onto the client's LocalPeerState wire contract so
                    // the desktop/mobile Network card works in server mode (the
                    // data was there; the route was missing → 404). Read-only,
                    // unauthenticated like the other directory read surfaces;
                    // excludes the node's own self key.
                    .merge(crate::federation_peers::router(
                        Arc::clone(&engine),
                        cfg.key_id.clone(),
                    ))
                    // MEMORY READ SURFACE (agent-compat Memory + GraphMemory cards):
                    // GET /v1/memory/stats, GET /v1/memory/timeline, POST /v1/memory/query,
                    // GET /v1/memory/{node_id}, GET /v1/memory/{node_id}/edges. Projects
                    // the cirisgraph_nodes / cirisgraph_edges SQLite tables onto the
                    // client's wire contract so both cards work in server mode.
                    // Unauthenticated (read-only public surface, same posture as
                    // federation_peers and the health endpoint).
                    .merge(crate::memory_api::router(Arc::clone(&engine)))
                    // GET /v1/telemetry/logs — the node's own logs for the client
                    // Logs screen (tails <home>/logs/ciris-server.log*). Read-only.
                    .merge(crate::telemetry_logs::router(cfg.home.join("logs")))
                    // Data page: owner-gated data wipe (reset-account = data-only;
                    // wipe-signing-key = data+keys) + GET /v1/my-data/lens-identifier.
                    .merge(crate::system_data::router(Arc::clone(&engine), cfg.clone()))
                    // HTTP TRACE INGEST (the listen+1 relay runbook §3.4 promised):
                    // POST /lens-api/api/v1/accord/events (legacy path, forwarded
                    // verbatim by the Caddy bridge) + POST /v1/ingest/accord-events
                    // (canonical alias). The agent's CIRIS-AccordMetrics/1.0 emitter
                    // ships a signed AccordEventsBatch JSON; this feeds it to the
                    // SAME Engine::receive_and_persist verify-before-persist path the
                    // Reticulum relay uses (LensCoreHandler). Unauthenticated like the
                    // relay — the per-trace CEG signature IS the auth.
                    .merge(crate::ingest_http::router(Arc::clone(&engine)));
                // ── ADAPTER SEAM (get_services_to_register) ──────────────────
                // Fold the downstream adapter's HTTP surface onto the SAME
                // read-API listener, AFTER all built-in routers. NoopAdapter
                // contributes none, so the default merged Router is unchanged.
                let mut r = r;
                for ar in adapter.routers(&adapter_ctx) {
                    r = r.merge(ar);
                }
                // "Never guess" — log every 4xx/5xx (method + path + status + FULL
                // body) to the node log file, so a failed request always leaves a
                // complete server-side trace even when the client truncates it.
                let r = r
                    .layer(axum::middleware::from_fn(
                        crate::http_log::log_error_responses,
                    ))
                    // TRANSPARENCY: stamp `X-CIRIS-Delegation` on every response to a
                    // `dgrant:` caller so a delegated actor always sees its live
                    // authority (scope/purpose/expiry/attestation) — no silent scope.
                    .layer(axum::middleware::from_fn(
                        crate::delegation_transparency::attach_delegation_header,
                    ));
                // #128 Phase D (C3 dispatch): hand the mesh control responder the
                // SAME merged v1 router HTTP serves — the RNS path and the HTTP
                // path execute identical handler code (RNS_CONTROL_RELAY.md §5.4
                // "reuse, do not fork"). The responder's closed allow-list is
                // enforced BEFORE any dispatch, so mounting the full surface here
                // widens nothing.
                let _ = mesh_dispatch_router.set(r.clone());
                r
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
    //    Cadence + window + gates are config-driven (config:* scorer.*) and HOT:
    //    the scorer reads the LIVE ResolvedConfig snapshot (config_rx) each cycle,
    //    so a POST /v1/config retunes the next pass with no restart (Phase 2). ──
    let _scorer = if caps.lens_store {
        let scorer_cfg = crate::scorer::ScorerConfig::from_resolved(&initial_config);
        tracing::info!(
            cadence_secs = scorer_cfg.cadence.as_secs(),
            window = scorer_cfg.window,
            sample_gate = scorer_cfg.sample_size_gate,
            target_n_eff = scorer_cfg.target_n_eff,
            "capacity scorer spawned (score→emit; capacity:sustained_coherence:v1; \
             knobs HOT from config:* scorer.*)"
        );
        Some(crate::scorer::spawn(
            Arc::clone(&engine),
            cfg.key_id.clone(),
            config_rx.clone(),
        ))
    } else {
        None
    };

    // ── ADAPTER SEAM (start + run_lifecycle) ──────────────────────────────────
    // Mirror of the agent adapter contract: `start()` is the one-shot setup run
    // BEFORE the long-running lifecycle, then `run_lifecycle(agent_task)` runs as
    // a supervised background task that returns when its shutdown watch flips to
    // `true`. NoopAdapter's defaults make both no-ops, so the default boot is
    // unchanged.
    adapter
        .start(&adapter_ctx)
        .await
        .context("adapter start()")?;
    let (adapter_sd_tx, adapter_sd_rx) = watch::channel(false);
    let adapter_join = tokio::spawn({
        let a = Arc::clone(&adapter);
        let ctx = adapter_ctx.clone();
        async move {
            if let Err(e) = a.run_lifecycle(&ctx, adapter_sd_rx).await {
                tracing::error!(error = %e, "adapter lifecycle ended with error");
            }
        }
    });

    tracing::info!(
        ret = %cfg.listen_addr,
        mode = %initial_config.mode,
        "CIRISServer up as a Reticulum node — ctrl-c to stop"
    );
    tokio::signal::ctrl_c().await.context("await ctrl_c")?;

    if let Some(read) = read {
        read.shutdown().await.context("shutdown lens read API")?;
    }
    // ── ADAPTER SEAM teardown (stop) ──────────────────────────────────────────
    // Signal the lifecycle to return, run the adapter's `stop()`, and join the
    // lifecycle task — around the edge teardown so the adapter unwinds with the
    // rest of the shared core.
    let _ = adapter_sd_tx.send(true);
    let _ = adapter.stop().await;
    let _ = adapter_join.await;
    // Tear down the CEG-driven reconcile loop (if it was spawned).
    let _ = reconcile_sd_tx.send(true);
    if let Some(join) = reconcile_join {
        let _ = join.await;
    }
    // Tear down the CEG-driven config reconcile loop (Server 0.5 Phase 2).
    let _ = config_sd_tx.send(true);
    let _ = config_reconcile_join.await;
    let _ = edge_shutdown_tx.send(true);
    // `None` in the #221 fold — the agent owns the edge's run loop (init_edge_runtime).
    if let Some(edge_join) = edge_join {
        let _ = edge_join.await;
    }
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
    wire_key_id: &str,
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

    // persist's aggregate reports `key_id`/`pqc_key_id` from the engine's
    // configured local labels — which are the KEYSTORE alias (the raw `--key-id`),
    // NOT the derived federation/wire identity. The `federation_keys` row and the
    // `SignedKeyRecord` both carry the derived `key_id`, so override here so
    // GET /v1/identity matches the canonical surfaces (CIRISServer#34). The
    // federation registers the hybrid (Ed25519 + ML-DSA-65) under ONE key_id, so
    // `pqc_key_id` is that same derived key_id (the keystore `{alias}-pqc` blob is
    // an internal storage label, not the federation identity).
    let mut v = serde_json::to_value(&aggregate).context("serialize LocalIdentityAggregate")?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "key_id".into(),
            serde_json::Value::String(wire_key_id.to_string()),
        );
        if obj.get("pqc_key_id").is_some_and(|p| !p.is_null()) {
            obj.insert(
                "pqc_key_id".into(),
                serde_json::Value::String(wire_key_id.to_string()),
            );
        }
    }
    serde_json::to_string(&v).context("serialize identity aggregate JSON")
}

/// Self-publish this node's **reticulum transport-tier binding** (dest-hash +
/// transport Ed25519) into the federation directory so any peer can
/// [`prime_peer`]-root it — the durable close of CIRISServer#205 gap #2.
///
/// A v7.0.0 explicit-hash canonical (e.g. `ciris-canonical-1`, baked with an IP
/// hint) **cannot announce** (Leviculum `ExplicitHashCannotAnnounce`), so the only
/// rooting path is out-of-band `prime_peer(key_id, dest_hash, transport_ed25519)`.
/// That transport-tier Ed25519 is edge-owned and **not** in the (genesis-baked)
/// identity record — so the node asserts it here at boot, for its OWN key_id, from
/// its OWN live edge (`local_dest_hash` / `local_transport_pubkey`). Same
/// self-authenticating basis as an attested announce; no accord quorum needed for
/// a node to declare its own reachability. Once written it replicates, and a
/// consuming node's `start_federation_delivery` resolves + primes it.
///
/// Best-effort: a node without a Reticulum transport (relay-off / non-reticulum
/// build) is a silent no-op, and a directory-write failure is logged, never fatal.
async fn publish_self_transport_destination(engine: &Engine, edge: &Edge, key_id: &str) {
    use base64::Engine as _;
    let (Some(dest_hash), Some(transport_pubkey)) =
        (edge.local_dest_hash(), edge.local_transport_pubkey())
    else {
        tracing::debug!(
            key_id,
            "no Reticulum transport identity — skipping self transport-destination publish"
        );
        return;
    };
    let dest_hex = hex::encode(dest_hash);
    // The transport identity is X25519(0..32) ‖ Ed25519(32..64). prime_peer wants
    // the Ed25519 half (rooting/addressing); the X25519 half is the transport-tier
    // KEX pubkey a peer needs to SEAL to this node (CIRISPersist#411 / CIRISEdge#299).
    // Persist BOTH so this node's own binding is fully sealable after a peer's boot-load.
    let transport_x25519_b64 =
        base64::engine::general_purpose::STANDARD.encode(&transport_pubkey[0..32]);
    let transport_ed25519_b64 =
        base64::engine::general_purpose::STANDARD.encode(&transport_pubkey[32..64]);
    let record = ciris_persist::federation::TransportDestination {
        occurrence_key_id: key_id.to_string(),
        transport_kind: "reticulum".to_string(),
        destination: dest_hex.clone(),
        asserted_at: chrono::Utc::now(),
        last_seen_at: None,
        transport_ed25519_pubkey_base64: Some(transport_ed25519_b64),
        transport_x25519_pubkey_base64: Some(transport_x25519_b64),
        binding_provenance: ciris_persist::federation::self_at_login::BindingProvenance::Rooted,
    };
    match engine
        .federation_directory()
        .put_transport_destination(&record)
        .await
    {
        Ok(()) => tracing::info!(
            key_id,
            dest_hash = %dest_hex,
            "published self reticulum transport-tier binding — peers can now prime_peer this node (#205 gap #2)"
        ),
        Err(e) => tracing::warn!(
            key_id,
            error = %e,
            "could not publish self transport-destination — peers cannot prime this node until it is asserted"
        ),
    }
}

/// **Boot self-publish of THIS node's SIGNED identity occurrence** — the sealability
/// twin of [`publish_self_transport_destination`] (CIRISServer#227 S1, occurrence-KEX
/// arc 4/4). The transport binding says *how to reach me*; the occurrence says *how to
/// SEAL to me*: it carries the content-tier `encryption_pubkeys` (x25519 + ML-KEM-768)
/// that a peer's `resolve_peer_kex_pubkeys` reads before `FederationSession::initiate`.
///
/// Custody-agnostic by construction (CIRISVerify#183): the enc pubkeys come from
/// [`ciris_keyring::self_enc_keys::SelfEncKeys`] — derived INSIDE the keyring from the
/// same sealed Ed25519 seed the federation signer uses (retrieve → HKDF → scrub; no
/// private half ever crosses an API). Deterministic, so every boot and every restore
/// republishes the identical keypair (the #151 restore property).
///
/// The occurrence is SIGNED (CIRISPersist#418, v14): the envelope — byte-matching what
/// `verify_transport_binding` JCS-canonicalizes, including the REQUIRED
/// `transport_destination` member (edge's transport identity + dest-hash, which the
/// gate recomputes per §5.6.8.8.1.1, and which satisfies C4 since the content-KEM
/// x25519 is HKDF-derived, distinct from the transport x25519) — is signed by the
/// node's own hybrid signer via `produce_signed_identity_occurrence` and admitted
/// through the ONE fail-secure gate (`put_identity_occurrence`). Signed-put rows are
/// exactly what `list_signed_identity_occurrences_for` re-publishes byte-exact on the
/// replication plane (edge v9.8.0 #305), so peers verify the SAME signature this
/// node's persist verified.
///
/// Idempotent every boot: a re-assert carries a fresh `asserted_at` and supersedes
/// under persist's last-signed-wins upsert; a stale replay elsewhere is a no-op.
/// Best-effort (mirrors the transport publish): no Reticulum transport → debug no-op.
/// THE AGENT DOES NOTHING — the node self-publishes its sealability, deleting the
/// agent-side publish step entirely.
async fn publish_self_identity_occurrence(engine: &Engine, edge: &Edge, cfg: &ServerConfig) {
    use ciris_keyring::self_enc_keys::SelfEncKeys;
    use ciris_verify_core::self_at_login::HardwareRootedIdentity;
    use ciris_verify_core::transport_binding::produce_signed_identity_occurrence;

    let key_id = cfg.key_id.as_str();
    let Some(transport_pubkey) = edge.local_transport_pubkey() else {
        tracing::debug!(
            key_id,
            "no Reticulum transport identity — skipping self identity-occurrence publish"
        );
        return;
    };

    // The occurrence's transport_destination MUST carry the NAMED Reticulum dest hash
    // — `sha256(name_hash("ciris"."edge") || sha256(x25519||ed25519)[..16])[..16]` — the
    // one `verify_transport_binding` recomputes per §5.6.8.8.1.1 and the one edge
    // announces + listens on for mesh-routed delivery (`local_named_dest_hash`). NOT
    // `edge.local_dest_hash()`, which is the *explicit* hash `sha256(fed_pubkey)[..16]`
    // (v7.0.0 direct-dial) — that mismatches the gate's recompute (DestinationHashMismatch,
    // field-reported on 0.5.100) and blocks inbound sealing. Computed here with the gate's
    // own `compute_destination_hash` so the two are byte-identical by construction (the
    // 0.5.100 e2e used this same fn to BUILD the envelope, which is why it never caught
    // the divergence — the bug lived only in the local_dest_hash() call this replaces).
    let Some(named_dest_hash) = ciris_verify_core::transport_binding::compute_destination_hash(
        "ciris",
        &["edge".to_string()],
        &transport_pubkey[0..32],
        &transport_pubkey[32..64],
    ) else {
        tracing::warn!(
            key_id,
            "could not compute the named RNS destination hash for the self occurrence — \
             skipping (peers cannot seal until this publishes)"
        );
        return;
    };

    // Content-enc pubkeys from CUSTODY (never a raw seed in this function).
    let enc = match SelfEncKeys::open(cfg.keystore_alias.clone(), cfg.identity_dir.clone())
        .and_then(|k| k.enc_pubkeys())
    {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                key_id,
                error = %e,
                "self content-enc pubkeys unavailable from the keyring — this node cannot be \
                 SEALED to until the sealed federation seed opens (peers will resolve None)"
            );
            return;
        }
    };

    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let now = chrono::Utc::now();
    // Envelope member names byte-match persist's admission parse + the producer the
    // gate verifies (verify_signed_identity_occurrence). app_name/aspects are edge's
    // RNS destination constants ("ciris"."edge") — the gate recomputes dest_hash from
    // (app_name, aspects, x25519, ed25519) and must land on edge's own hash.
    let tb_env = serde_json::json!({
        "reticulum_x25519_pubkey": b64.encode(&transport_pubkey[0..32]),
        "reticulum_ed25519_pubkey": b64.encode(&transport_pubkey[32..64]),
        "destination_hash": b64.encode(named_dest_hash),
        "app_name": "ciris",
        "aspects": ["edge"],
    });
    let envelope = serde_json::json!({
        "identity_key_id": key_id,
        "occurrence_key_id": key_id,
        "transport_destination": tb_env,
        "encryption_pubkeys": {
            "x25519_base64": enc.x25519_base64,
            "ml_kem_768_base64": enc.ml_kem_768_base64,
        },
        "asserted_at": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });

    // Sign with the node's own hybrid identity (the build_self_key_record pattern);
    // attesting_key_id == identity_key_id == this node's registered key, so the
    // gate's signer_acts_for is satisfied by the identity's own key.
    let signed = async {
        let ed: Arc<dyn HardwareSigner> = Arc::from(federation_signer(cfg)?);
        let pqc: Arc<dyn PqcSigner> = federation_pqc_signer(cfg)?;
        let identity = HardwareRootedIdentity::new(cfg.key_id.clone(), ed, pqc)
            .map_err(|e| anyhow::anyhow!("node self-signer identity: {e}"))?;
        let (signed_envelope, signature) = produce_signed_identity_occurrence(&identity, envelope)
            .await
            .map_err(|e| anyhow::anyhow!("produce signed identity occurrence: {e}"))?;
        anyhow::Ok((signed_envelope, signature))
    }
    .await;
    let (signed_envelope, signature) = match signed {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(key_id, error = %e, "could not sign the self identity occurrence");
            return;
        }
    };

    let row = ciris_persist::federation::IdentityOccurrence {
        identity_key_id: key_id.to_string(),
        occurrence_key_id: key_id.to_string(),
        device_class: "agent".to_string(),
        hardware_attestation: None,
        asserted_at: now,
        valid_until: None,
        encryption_pubkeys: Some(ciris_persist::federation::EncryptionPubkeys {
            x25519_base64: enc.x25519_base64.clone(),
            ml_kem_768_base64: enc.ml_kem_768_base64.clone(),
        }),
        transport_binding: Some(
            ciris_persist::federation::types::OccurrenceTransportBinding {
                reticulum_x25519_pubkey_base64: b64.encode(&transport_pubkey[0..32]),
                reticulum_ed25519_pubkey_base64: b64.encode(&transport_pubkey[32..64]),
                destination_hash_base64: b64.encode(named_dest_hash),
                app_name: "ciris".to_string(),
                aspects: vec!["edge".to_string()],
            },
        ),
        persist_row_hash: String::new(),
    };
    match engine
        .federation_directory()
        .put_identity_occurrence(ciris_persist::federation::SignedIdentityOccurrence {
            identity_occurrence: row,
            attesting_key_id: key_id.to_string(),
            signed_envelope,
            signature,
        })
        .await
    {
        Ok(()) => tracing::info!(
            key_id,
            "published this node's SIGNED self identity-occurrence (content-enc pubkeys from \
             sealed custody) — peers can now resolve + SEAL to this node (#227 S1)"
        ),
        Err(e) => tracing::warn!(
            key_id,
            error = %e,
            "could not publish the signed self identity-occurrence — peers cannot seal to this \
             node until it is admitted"
        ),
    }
}

/// **CEG-native trusted-peer boot prime.** Root — via edge's out-of-band
/// `prime_peer` (`inject_rooted_peer_for_test`) — every peer the persisted CEG
/// state marks TRUSTED, i.e. every `transport_destinations` row with
/// [`BindingProvenance::Rooted`](ciris_persist::federation::self_at_login::BindingProvenance::Rooted).
///
/// **No hardcoded canonical list** — the trust set is loaded from the directory:
/// - `Rooted` = authoritative (a federation-key-signed occurrence / `root_binding`
///   verified it / this node or a peer self-published it) → an outbound trust target.
/// - `Advisory` (CIRISEdge#301) = a self-consistent announce, a routing hint only,
///   NOT an outbound authorization → skipped.
/// - An operator who **untrusts** a canonical/community withdraws it (the row is
///   removed or downgraded), so it is simply absent from the Rooted set → not primed.
///
/// On first boot the Rooted set IS the baked canonicals (which cannot announce, so
/// prime is their only rooting path); as the mesh grows it is whatever the corpus
/// trusts. Mirrors `start_federation_delivery`'s prime, but driven by the FULL
/// directory rather than a delivery-controller target list — so the node-composed
/// runtime (the agent fold) roots its trusted peers too. Best-effort: a
/// missing/undecodable binding or a transport-less build warns + skips, never fatal.
async fn prime_trusted_peers(engine: &Engine, edge: &Edge) {
    use ciris_persist::federation::self_at_login::BindingProvenance;
    let Some(transport) = edge.reticulum_transport() else {
        tracing::debug!("trusted-peer prime: no Reticulum transport on this build — skipping");
        return;
    };
    let dests = match engine
        .federation_directory()
        .list_all_transport_destinations()
        .await
    {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "trusted-peer prime: list_all_transport_destinations failed — skipping");
            return;
        }
    };
    // Trusted = Rooted-provenance rows only. Group per peer key_id;
    // `resolve_reticulum_prime_binding` selects the reticulum entry carrying the
    // transport-tier Ed25519 (paired with the dest-hash) for that peer.
    let mut trusted: std::collections::BTreeMap<
        String,
        Vec<ciris_persist::federation::TransportDestination>,
    > = std::collections::BTreeMap::new();
    for d in dests {
        if d.binding_provenance == BindingProvenance::Rooted {
            trusted
                .entry(d.occurrence_key_id.clone())
                .or_default()
                .push(d);
        }
    }
    let mut primed = 0usize;
    for (key_id, peer_dests) in &trusted {
        match crate::federation_delivery::resolve_reticulum_prime_binding(peer_dests) {
            Ok(Some((dest_hash, ed25519))) => {
                let before = transport.knows_peer(key_id).await;
                transport
                    .inject_rooted_peer_for_test(key_id, dest_hash, ed25519)
                    .await;
                let after = transport.knows_peer(key_id).await;
                primed += 1;
                tracing::info!(
                    peer = %key_id,
                    dest_hash = %hex::encode(dest_hash),
                    knows_peer_before = before,
                    knows_peer_after = after,
                    "trusted-peer boot prime: rooted {key_id} (CEG-native, provenance=Rooted)"
                );
            }
            Ok(None) => tracing::debug!(
                peer = %key_id,
                "trusted-peer prime: Rooted row(s) but no reticulum transport binding — skip"
            ),
            Err(e) => tracing::warn!(
                peer = %key_id,
                error = %e,
                "trusted-peer prime: binding decode failed — skip"
            ),
        }
    }
    tracing::info!(
        trusted_peers = trusted.len(),
        primed,
        "trusted-peer boot prime complete — trusted (explicit-hash) peers reachable-by-key_id with no announce"
    );
}

/// Boot-prime the canonical bootstrap peer(s) as explicit-hash Reticulum
/// destinations, derived purely from the baked KeyRecord — CIRISServer#238.
///
/// The canonical seed carries a `KeyRecord` (with `pubkey_ed25519_base64`) and an
/// IP dial hint, but NO `transport_destination` row, so [`prime_trusted_peers`]
/// (which primes from Rooted rows) never touches it and the canonical roots only
/// via its slow announce. But an explicit-hash peer (edge v7.0.0) needs only
/// `(dest_hash, ed25519)`, and both come from the fed Ed25519 pubkey:
///   - `dest_hash = reticulum_destination_for_pubkey(fed_ed25519) = sha256(fed)[..16]`
///   - `signing_key = fed_ed25519` — transport and federation share the Ed25519
///     signing half (the split is in the X25519 half, which priming doesn't use).
///
/// So we look up the canonical's KeyRecord, derive both, and inject a Rooted peer.
/// Deterministic, no announce dependency, no seed change. Runs in BOTH the
/// standalone node and the agent fold.
async fn prime_canonical_bootstrap_peers(engine: &Engine, edge: &Edge) {
    use base64::Engine as _;
    let Some(transport) = edge.reticulum_transport() else {
        tracing::debug!("canonical prime: no Reticulum transport on this build — skipping");
        return;
    };
    let hints = match engine.canonical_bootstrap_hints().await {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, "canonical prime: canonical_bootstrap_hints failed — skipping");
            return;
        }
    };
    let canonical_key_ids = crate::federation_delivery::distinct_canonical_key_ids(&hints);
    let mut primed = 0usize;
    for key_id in &canonical_key_ids {
        // NB: on the canonical node ITSELF this primes its own key_id. That is
        // benign (a self-entry in the peers map is never a delivery target) and is
        // the same behaviour `prime_trusted_peers` already has — so we don't special
        // -case it rather than thread the node's own key_id down here for nothing.
        let rec = match engine
            .federation_directory()
            .lookup_public_key(key_id)
            .await
        {
            Ok(Some(r)) => r,
            Ok(None) => {
                tracing::warn!(
                    canonical = %key_id,
                    "canonical prime: no KeyRecord for canonical key_id — cannot derive explicit-hash binding, will fall back to announce"
                );
                continue;
            }
            Err(e) => {
                tracing::warn!(canonical = %key_id, error = %e, "canonical prime: lookup_public_key failed — skip");
                continue;
            }
        };
        let ed_bytes = match base64::engine::general_purpose::STANDARD
            .decode(rec.pubkey_ed25519_base64.as_bytes())
        {
            Ok(b) if b.len() == 32 => b,
            Ok(b) => {
                tracing::warn!(
                    canonical = %key_id,
                    len = b.len(),
                    "canonical prime: pubkey_ed25519_base64 is not 32 bytes — skip"
                );
                continue;
            }
            Err(e) => {
                tracing::warn!(canonical = %key_id, error = %e, "canonical prime: pubkey_ed25519_base64 not base64 — skip");
                continue;
            }
        };
        let mut fed_ed = [0u8; 32];
        fed_ed.copy_from_slice(&ed_bytes);
        let dest_hash =
            ciris_edge::transport::addressing::reticulum_destination_for_pubkey(&fed_ed);
        let before = transport.knows_peer(key_id).await;
        transport
            .inject_rooted_peer_for_test(key_id, dest_hash, fed_ed)
            .await;
        let after = transport.knows_peer(key_id).await;
        primed += 1;
        tracing::info!(
            canonical = %key_id,
            dest_hash = %hex::encode(dest_hash),
            knows_peer_before = before,
            knows_peer_after = after,
            "canonical boot prime: rooted {key_id} from baked KeyRecord (explicit-hash, no announce)"
        );
    }
    tracing::info!(
        canonical_peers = canonical_key_ids.len(),
        primed,
        "canonical boot prime complete — canonical(s) reachable-by-key_id at boot with no announce dependency"
    );
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

/// The responsible **USER's** hybrid signer used by `POST /v1/setup/claim-remote`
/// to sign the `delegates_to(user → target, infra:*)` owner-binding — NOT the
/// node's steward signer (the owner-binding asserts an accountable *human* is
/// responsible).
///
/// Authorization to wield the owner's fed-ID — the most powerful key on the node (it
/// signs owner-bindings + delegations + age, and re-roots ownership). [`resolve_user_signer`]
/// is the ENFORCED choke point: it releases the signer ONLY for one of these, so the
/// fed-ID is "bound to the login" — no live owner session (or first-run bootstrap), no
/// fed-ID. A future caller can't reach the signer without declaring its authority.
pub(crate) enum FedIdUse {
    /// A VERIFIED owner session — the caller already passed `require_owner`
    /// (SystemAdmin + FullAccess via `resolve_bearer`). The post-claim path.
    OwnerSession,
    /// First-run BOOTSTRAP: no owner exists yet, so the fed-ID is minted + used to
    /// CREATE the owner. `resolve_user_signer` RE-VERIFIES `is_first_run` for this
    /// arm, so it can never wield the fed-ID once the node is owned.
    FirstRunBootstrap,
}

/// Resolve the responsible-user (owner) fed-ID signer from its on-disk seed, **only
/// when authorized** ([`FedIdUse`]). Pulled out of [`user_identity_signer`] so
/// `claim-remote` can resolve it **at request time** (the fed-ID is minted DURING the
/// first-run wizard, after boot). Returns `None` (not an error) when no user seed
/// exists yet; `Err` when the use is unauthorized (bootstrap on an owned node).
pub(crate) async fn resolve_user_signer(
    engine: &Engine,
    auth: FedIdUse,
    user_key_id: &str,
    seed_dir: std::path::PathBuf,
) -> Result<Option<Arc<ciris_persist::prelude::LocalSigner>>> {
    // CHOKE POINT — the fed-ID is bound to the login: release it only to a verified
    // owner session, or during the first-run bootstrap window (which CREATES the
    // owner). The bootstrap arm is re-checked here, so it can never wield the fed-ID
    // on an already-owned node (defense-in-depth — even if a caller forgot its gate).
    if matches!(auth, FedIdUse::FirstRunBootstrap)
        && !crate::auth::bootstrap::is_first_run(engine).await
    {
        anyhow::bail!(
            "fed-ID use refused — this node is already owned, so the responsible-user \
             identity may be wielded only under a live owner session (login)"
        );
    }

    // Determine WHICH custody backend minted the identity, so we re-open it the
    // SAME way (software seed / TPM-sealed / YubiKey). The mint records a marker
    // (`<seed_dir>/<alias>.backend`); fall back to the software seed file for
    // identities minted before the marker existed. Absent both ⇒ no fed-ID yet.
    let software_seed = seed_dir.join(format!("{user_key_id}.ed25519.seed"));
    let backend = match crate::identity::read_user_backend_marker(&seed_dir, user_key_id) {
        Some(label) => crate::identity::user_backend_from_label(&label),
        None if software_seed.exists() => crate::identity::UserIdentityBackend::Software,
        None => {
            tracing::info!(
                seed_dir = %seed_dir.display(),
                "no responsible-user identity at the conventional path yet — create your \
                 federation ID (POST /v1/self/identity) to enable POST /v1/setup/claim-remote"
            );
            return Ok(None);
        }
    };

    // Re-open the user identity under user_key_id with its recorded backend (the
    // Ed25519 half per backend; the ML-DSA-65 half is the sealed PQC signer).
    let signer =
        crate::identity::hardware_user_local_signer(backend, user_key_id, seed_dir).await?;
    tracing::info!(
        user_key_id = %user_key_id,
        "responsible-user signer resolved for claim-remote (minted user identity at \
         the conventional path — Server 0.5, no env)"
    );
    Ok(Some(Arc::new(signer)))
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
    // KEYSTORE alias (the PQC keystore blob) — RAW label, NOT the derived key_id.
    let alias = format!("{}-pqc", cfg.keystore_alias);
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
            SealedEd25519Signer::adopt(cfg.keystore_alias.clone(), cfg.identity_dir.clone(), &seed)
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
        // Open the sealed seed, or MINT a fresh one if absent — first-boot mint,
        // mirroring federation_pqc_signer's mint-if-absent (CIRISServer 0.5.58). The
        // old `get_platform_ed25519_signer` was open-ONLY (SealedEd25519Signer::open),
        // so a fresh OR wiped home (e.g. after POST /v1/system/data/wipe-signing-key)
        // bricked the node with "Key not found: ed25519.seed" instead of coming back
        // up to first-run. `open_or_create(.., None)` mints a random sealed seed when
        // none exists, so the node self-bootstraps its federation identity.
        SealedEd25519Signer::open_or_create(
            cfg.keystore_alias.clone(),
            cfg.identity_dir.clone(),
            None,
        )
        .map(|s| Box::new(s) as Box<dyn HardwareSigner>)
        .map_err(|e| anyhow::anyhow!("open-or-mint sealed-Ed25519 federation signer: {e}"))
    }
}

/// The node-scoped **`substrate_persist`** signing identity (CIRISServer#181) — a
/// SEPARATE hybrid keypair from the node's own federation key, minted + sealed at
/// boot under the `<keystore_alias>-substrate` alias.
///
/// ## Why a distinct key
///
/// `content_class:*` (the CC 4.5.13 infohazard flag), `system:*`, `audit_chain:*`
/// are **substrate-reserved** prefixes: persist's `default_reserved_prefix_rules`
/// admit them ONLY from an emitter whose `federation_keys` row is `identity_type =
/// substrate_persist`. The node's own key is `identity_type = node`
/// (infrastructure, CC 1.13.5) — it CANNOT author a reserved flag
/// (`federation_reserved_prefix_emitter_mismatch`), and a federation_keys row is
/// keyed by key_id (one identity_type per key). So the node holds this second,
/// dedicated identity purely to author the reserved rows the fabric attributes to
/// "the substrate": the duty-holder authorizes at the HTTP layer; THIS key signs.
///
/// The Ed25519 half is hardware-sealed (open-or-mint under the keystore — stable
/// across restarts, so a later CLEAR by the same key resolves); the ML-DSA-65 half
/// is a software seed at `substrate_ml_dsa_65.seed` (no sealed-ML-DSA backend
/// exists), mirroring [`federation_pqc_signer`]. `from_hardware_parts` receives the
/// ALIAS as its key_id (the `derive_key_id` input), so the signer's
/// `derived_key_id()` — the value [`Engine::emit_attestation`] FKs against — is
/// `derive_key_id(alias, ed_pub)`, exactly what [`register_substrate_key`] registers.
pub(crate) async fn substrate_persist_signer(
    cfg: &ServerConfig,
) -> Result<(
    Arc<ciris_persist::prelude::LocalSigner>,
    ciris_verify_core::self_at_login::HardwareRootedIdentity,
)> {
    let alias = format!("{}-substrate", cfg.keystore_alias);
    // Ed25519 half — sealed keystore, open-or-mint (stable seed across restarts).
    let ed: Arc<dyn HardwareSigner> = Arc::from(
        SealedEd25519Signer::open_or_create(alias.clone(), cfg.identity_dir.clone(), None)
            .map(|s| Box::new(s) as Box<dyn HardwareSigner>)
            .map_err(|e| anyhow::anyhow!("open-or-mint substrate Ed25519 signer: {e}"))?,
    );
    // ML-DSA-65 half — software seed at substrate_ml_dsa_65.seed (mint-if-absent).
    let pqc_alias = format!("{alias}-pqc");
    let pqc_path = cfg.identity_dir.join("substrate_ml_dsa_65.seed");
    let pqc = if pqc_path.exists() {
        MlDsa65SoftwareSigner::from_seed_file(&pqc_path, pqc_alias.clone())
            .map_err(|e| anyhow::anyhow!("adopt substrate ML-DSA-65 seed: {e}"))?
    } else {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|e| anyhow::anyhow!("mint substrate ML-DSA-65 seed: {e}"))?;
        std::fs::write(&pqc_path, seed).with_context(|| format!("write {}", pqc_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&pqc_path, std::fs::Permissions::from_mode(0o600));
        }
        MlDsa65SoftwareSigner::from_seed_bytes(&seed, pqc_alias.clone())
            .map_err(|e| anyhow::anyhow!("load minted substrate ML-DSA-65 seed: {e}"))?
    };
    let pqc: Arc<dyn PqcSigner> = Arc::new(pqc);
    // Compose the persist emit-signer AND a verify `HardwareRootedIdentity` (a
    // `SelfSigner`) from the SAME hybrid halves — the latter feeds
    // `produce_self_key_record` so the registration envelope is the RICH,
    // replay-resistant shape (binds pubkeys + identity_type), identical to the node
    // key's `build_self_key_record` path (DRY audit H1 — no hand-rolled minimal
    // `{key_id}` envelope on the highest-trust key).
    let signer = Arc::new(
        ciris_persist::prelude::LocalSigner::from_hardware_parts(
            ed.clone(),
            alias.clone(),
            Some(pqc.clone()),
            Some(pqc_alias),
        )
        .await
        .map_err(|e| anyhow::anyhow!("compose substrate_persist LocalSigner: {e}"))?,
    );
    let identity = ciris_verify_core::self_at_login::HardwareRootedIdentity::new(
        signer.derived_key_id(),
        ed,
        pqc,
    )
    .map_err(|e| anyhow::anyhow!("build substrate_persist self-signer identity: {e}"))?;
    Ok((signer, identity))
}

/// Register the node's `substrate_persist` identity ([`substrate_persist_signer`])
/// in the federation directory as `identity_type = substrate_persist`, so the
/// reserved-prefix admission rule admits the `content_class:*` flags it authors.
///
/// Self-signed proof-of-possession through the canonical `register_federation_key`
/// gate (the same fail-secure hybrid-verify path [`register_self_key`] uses — the
/// signer proves possession of its OWN keys, `scrub_key_id == key_id`). Idempotent:
/// a matching row → `Ok`; a benign `Conflict` (row already present) → `Ok`.
/// Returns the registered (derived) key_id.
async fn register_substrate_key(
    engine: &Engine,
    identity: &ciris_verify_core::self_at_login::HardwareRootedIdentity,
) -> Result<String> {
    use ciris_persist::federation::types::identity_type;
    use ciris_persist::federation::{Error as FederationError, SignedKeyRecord};
    use ciris_verify_core::federation_self_record::produce_self_key_record;

    // The RICH self-signed record (verify's canonical producer) — the envelope binds
    // key_id + BOTH pubkeys + identity_type, so a captured record can't be replayed
    // with those fields flipped (the minimal `{key_id}` envelope did not). Same path
    // the node key uses (`build_self_key_record`), bridged verify→persist by the
    // structurally-identical JSON shape.
    let valid_from = chrono::Utc::now().to_rfc3339();
    let v_rec =
        produce_self_key_record(identity, identity_type::SUBSTRATE_PERSIST, &valid_from, &[])
            .await
            .map_err(|e| anyhow::anyhow!("produce substrate_persist self key record: {e}"))?;
    let signed: SignedKeyRecord = serde_json::from_value(serde_json::to_value(&v_rec)?)
        .map_err(|e| anyhow::anyhow!("bridge verify→persist substrate SignedKeyRecord: {e}"))?;
    let key_id = signed.record.key_id.clone();
    match engine.register_federation_key(signed).await {
        Ok(()) | Err(FederationError::Conflict(_)) => Ok(key_id),
        Err(e) => Err(anyhow::anyhow!("register substrate_persist key: {e}")),
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
    // The PQC signer's KEYSTORE alias — must match `federation_pqc_signer`'s
    // `{keystore_alias}-pqc`, so it is the RAW label, NOT the derived key_id.
    let pqc_key_id = format!("{}-pqc", cfg.keystore_alias);
    let engine =
        Engine::with_hardware_signer_hybrid(signer, Some(pqc), Some(pqc_key_id), &cfg.dsn())
            .await
            .context("build shared persist Engine (hybrid hardware signer)")?;
    Ok(Arc::new(engine))
}

/// Register Node A's own federation signing key in the federation directory as
/// identity_type **"node"** (a fabric node — infrastructure, NO agency per
/// CC 1.13.5 / CC 3.4.7.1; corrected from the prior "steward") through the
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

    let record = build_self_key_record(cfg).await?;

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
                "registered Node A's own node key via register_federation_key \
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
async fn self_key_record_json(cfg: &ServerConfig) -> Result<String> {
    use ciris_persist::federation::SignedKeyRecord;
    let record = build_self_key_record(cfg).await?;
    serde_json::to_string(&SignedKeyRecord { record })
        .context("serialize this node's self-signed SignedKeyRecord")
}

/// Build THIS node's own [`NodeCode`](crate::nodecode::NodeCode) (CEG §0.10).
/// Sourced from the SAME [`build_self_key_record`] assembly the self-key-record +
/// steward registration use, so the embedded Ed25519 pubkey is exactly this node's
/// federation signing-key pubkey. The alias hint is the resolved config:*
/// `node.alias` (Server 0.5 — no env). Built once at boot.
async fn node_self_code(
    cfg: &ServerConfig,
    alias_hint: Option<String>,
) -> Result<crate::nodecode::NodeCode> {
    let record = build_self_key_record(cfg).await?;
    Ok(crate::federation_nodecode::build_node_code(
        &record.key_id,
        &record.pubkey_ed25519_base64,
        alias_hint,
        // No transport hint on the zero-env boot path (the prior CIRIS_TRANSPORT_HINT
        // / CIRIS_PUBLIC_BASE_URL envs are deleted; Edge resolves real transports
        // via its own discovery). A future config:* key can carry it if needed.
        None,
    ))
}

/// Build Node A's self-signed [`KeyRecord`](ciris_persist::federation::types::KeyRecord)
/// — `scrub_key_id == key_id`, a bound-hybrid proof-of-possession over the
/// JCS-canonicalized registration envelope. This is the exact record the admission
/// gate verifies and that A exports for peer B to register.
///
/// Produced by verify's single-source [`produce_self_key_record`] over this node's
/// own hardware/sealed federation signers wrapped as a [`HardwareRootedIdentity`]
/// (a verify `SelfSigner`) — the SAME producer identity.rs / accord.rs /
/// accord_provision.rs use, whose JCS canonicalization + bound-hybrid signature are
/// byte-exact to what persist's `register_federation_key` recanonicalizes and
/// verifies. (verify's `ceg_produce_canonicalize` **is** its own JCS, so the row
/// round-trips the gate by construction.) The signed envelope binds the pubkeys +
/// identity_type + validity, not just `{key_id}` — a strictly richer, harder-to-
/// replay PoP than the prior hand-rolled minimal envelope.
pub(crate) async fn build_self_key_record(
    cfg: &ServerConfig,
) -> Result<ciris_persist::federation::types::KeyRecord> {
    use ciris_verify_core::federation_self_record::produce_self_key_record;
    use ciris_verify_core::self_at_login::HardwareRootedIdentity;

    // Wrap this node's OWN Ed25519 (hardware-sealed) + ML-DSA-65 signers — the same
    // halves the Engine is composed from — as a verify `SelfSigner`. Re-opened here
    // (boot-time, called ~3× while assembling the boot state); the software path is
    // a cheap seal read, and the pkcs11 path mirrors accord_provision's admit-node
    // ceremony which opens a fresh identity alongside the running engine.
    let ed: Arc<dyn HardwareSigner> = Arc::from(federation_signer(cfg)?);
    let pqc: Arc<dyn PqcSigner> = federation_pqc_signer(cfg)?;
    let identity = HardwareRootedIdentity::new(cfg.key_id.clone(), ed, pqc)
        .map_err(|e| anyhow::anyhow!("build node self-signer identity: {e}"))?;

    // CC 1.13.5 / CC 3.4.7.1: a fabric node is `node`-role (infrastructure, NO
    // agency) — NOT a trust-root steward. No transport hints in the node's own
    // self record (Edge discovers real transports); `&[]` keeps the pre-#172
    // envelope shape.
    let valid_from = chrono::Utc::now().to_rfc3339();
    let v_rec = produce_self_key_record(
        &identity,
        ciris_persist::federation::types::identity_type::NODE,
        &valid_from,
        &[],
    )
    .await
    .map_err(|e| anyhow::anyhow!("produce node self-signed key record: {e}"))?;

    // Bridge the verify `SignedKeyRecord` into persist's `SignedKeyRecord` via the
    // structurally-identical JSON shape (the exact bridge the portable-mint path in
    // identity.rs uses), then hand back the inner persist `KeyRecord`.
    let signed: ciris_persist::federation::SignedKeyRecord =
        serde_json::from_value(serde_json::to_value(&v_rec)?)
            .map_err(|e| anyhow::anyhow!("bridge verify→persist self SignedKeyRecord: {e}"))?;
    Ok(signed.record)
}

/// Set up **CEG-driven** directed-consent replication. The corpus's
/// `consent:replication` objects ARE the desired replication topology
/// ([`crate::peer::replication_peers_from_consent`]); this function derives the
/// boot Initiator set from them and starts the single long-lived
/// [`ReplicationRuntime`]. The reconcile loop ([`crate::replication_reconcile`])
/// then converges the runtime to the consent objects on an ongoing basis.
///
/// Returns the live runtime as an `Arc` (held by the caller for the node's
/// lifetime so its scheduler task is not dropped AND shared with the reconcile
/// loop), or `None` when the host carries no Reticulum transport / no SQLite
/// corpus (the read API can still write CEG; there is just nothing to converge).
///
/// Steps (Node A side of the shared wire contract):
///   0. **Optional env bootstrap** — if `CIRIS_PEER_B_*` is configured, admit B's
///      key + emit the `consent:replication:v1` grant FIRST, so the env peer
///      becomes a NORMAL consent CEG object that flows through the SAME
///      consent-derived path as any owner-authored grant (no downstream
///      special-casing). `CIRIS_PEER_B_*` is now only a convenience bootstrap, not
///      the mechanism.
///   1. **Desired Initiator set from CEG** — read the admitted
///      `consent:replication` subjects back out of the corpus. An unadmitted
///      consent subject is skipped + warned (can't replicate with an unknown key).
///   2. **Always start the runtime** — even when the desired set is empty — so the
///      registry + inbound routing exist for the reconciler to hot-add into. The
///      runtime is started ONCE on the single long-lived transport;
///      `install_replication_routing` is called EXACTLY ONCE (it is a set-once
///      `OnceLock` — first call wins), and the runtime is NEVER rebuilt.
///
/// MUST run BEFORE `edge.run()` consumes the Edge: `install_replication_routing`
/// is consulted by the inbound loop, and `reticulum_transport()` must be cloned
/// off the live Edge.
async fn setup_peer_replication(
    engine: &Arc<Engine>,
    edge: &Edge,
    cfg: &ServerConfig,
) -> Result<Option<Arc<ciris_edge::replication::ReplicationRuntime>>> {
    // Server 0.5 (zero env): there is NO env peer-bootstrap branch. The replication
    // topology is owner-authored consent ONLY — a peer is admitted + a
    // consent:replication object emitted via the owner-gated POST
    // /v1/federation/peering. The prior CIRIS_PEER_B_* env-seed branch is deleted.
    tracing::info!(
        "replication topology is owner-authored consent only (POST /v1/federation/peering) — \
         zero env (Server 0.5)"
    );
    // Compose seeds NO extra targets: the boot topology is exactly the corpus's
    // consent:replication set. The agent-embedded delivery controller
    // (crate::federation_delivery) is the caller that seeds the baked canonical
    // key_ids as extra_targets — the ONLY behavioural difference between the two.
    start_replication_runtime(engine, edge, &cfg.key_id, &[]).await
}

/// Assemble the per-peer [`ReplicationPeer`] coordinator set from a set of
/// admitted peer `key_id`s. Three coordinators per peer:
///   - [`EnvelopeKind::Attestation`] — capacity:* / trace out, health:liveness in.
///   - [`EnvelopeKind::Key`] (#144, CIRISEdge#257) — the KERI publish-own key plane
///     (verification + transport identity).
///   - [`EnvelopeKind::IdentityOccurrence`] (CIRISEdge#305) — the KEX plane: the
///     occurrence carries the content-tier `encryption_pubkeys` (x25519 + ML-KEM-768)
///     that `resolve_peer_kex_pubkeys` reads. Without this coordinator the plane is
///     never exchanged, so a peer's enc keys never reach the directory → sealing to it
///     resolves `None` → 0 content delivery (the last trace-flow gap). Publish-own is
///     the `occurrence_selector` in [`start_replication_runtime`]; this is the
///     anti-entropy carriage.
///
/// Pure (no I/O) so both the compose boot path and the agent-embedded delivery
/// controller share ONE assembly, and it is unit-testable without an engine.
pub(crate) fn build_replication_peers(
    desired: &[String],
) -> Vec<ciris_edge::replication::ReplicationPeer> {
    use ciris_edge::replication::{EnvelopeKind, ReplicationPeer};
    desired
        .iter()
        .flat_map(|p| {
            [
                ReplicationPeer {
                    peer_key_id: p.clone(),
                    kind: EnvelopeKind::Attestation,
                },
                ReplicationPeer {
                    peer_key_id: p.clone(),
                    kind: EnvelopeKind::Key,
                },
                ReplicationPeer {
                    peer_key_id: p.clone(),
                    kind: EnvelopeKind::IdentityOccurrence,
                },
            ]
        })
        .collect()
}

/// Core replication-runtime bring-up, shared by the compose boot path
/// ([`setup_peer_replication`], `extra_targets = &[]`) AND the agent-embedded
/// federation-delivery controller ([`crate::federation_delivery`], `extra_targets`
/// = the baked canonical `key_id`s). Factoring the body here keeps the two callers
/// byte-identical except for the extra seed set, so compose's boot behaviour is
/// unchanged when `extra_targets` is empty.
///
/// `node_key_id` is the local federation signing key (the consent AUTHOR + the
/// KERI publish-own selector); compose passes `cfg.key_id`, the delivery
/// controller passes `edge.signer_key_id()`.
///
/// Returns `Ok(None)` when the Edge carries no Reticulum transport — the read API
/// still writes CEG (consent objects), there is just no runtime to converge.
///
/// MUST run BEFORE `edge.run()` consumes the Edge on the COMPOSE path (so
/// `install_replication_routing` + `reticulum_transport()` are wired before the
/// inbound loop starts). On the agent-embedded path the Edge is ALREADY running;
/// this is safe because `Edge::run` clones the `Arc<OnceLock>` replication-registry
/// and reads `.get()` LIVE per inbound frame (edge.rs `run`), so a post-boot
/// `install_replication_routing` is observed on the next frame — see
/// [`crate::federation_delivery`] for the full ordering note.
pub(crate) async fn start_replication_runtime(
    engine: &Arc<Engine>,
    edge: &Edge,
    node_key_id: &str,
    extra_targets: &[String],
) -> Result<Option<Arc<ciris_edge::replication::ReplicationRuntime>>> {
    use ciris_edge::replication::{ReplicationRuntime, ReplicationRuntimeConfig};
    use ciris_persist::federation::FederationDirectory;

    // Require a Reticulum transport to run replication at all. Without it the read
    // API still writes CEG (consent objects), there is just no runtime to converge.
    let Some(transport) = edge.reticulum_transport() else {
        tracing::warn!(
            "Edge has no Reticulum transport — replication runtime not started (the peering API \
             can still write consent CEG; there is no runtime to converge)"
        );
        return Ok(None);
    };
    let directory: Arc<dyn FederationDirectory> = engine
        .sqlite_backend()
        .context("replication runtime requires a SQLite-backed Engine")?
        .clone();

    // 1. Desired Initiator set from CEG — admitted consent:replication subjects,
    //    UNIONED with any caller-seeded `extra_targets` (the delivery controller's
    //    baked canonical key_ids). Every candidate is admission-filtered against the
    //    federation directory (an unknown key has no record to route/verify).
    let consented = crate::peer::replication_peers_from_consent(engine, node_key_id).await?;
    let mut candidates: Vec<String> = consented;
    for t in extra_targets {
        if !candidates.contains(t) {
            candidates.push(t.clone());
        }
    }
    let mut desired: Vec<String> = Vec::with_capacity(candidates.len());
    for peer in candidates {
        match directory.lookup_public_key(&peer).await {
            Ok(Some(_)) => desired.push(peer),
            Ok(None) => tracing::warn!(
                peer_key_id = %peer,
                "consent:replication for an UNADMITTED peer key at boot — skipping (register the \
                 peer's self-signed key via POST /v1/federation/peering)"
            ),
            Err(e) => tracing::warn!(
                peer_key_id = %peer,
                error = %e,
                "directory lookup for a consent peer failed at boot — skipping it"
            ),
        }
    }

    // 2. Always start the ONE long-lived runtime (even with an empty desired set)
    //    so the registry + routing exist for the reconciler's runtime hot-add.
    //    v5.1.0 `start` installs the scheduler control channel unconditionally, so
    //    the runtime accepts `set_peers` mutation with no extra opt-in
    //    (CIRISEdge#173 resolved).
    let peers = build_replication_peers(&desired);

    // Key-plane publish selector (CIRISEdge#257 / edge v8.6.0): the Key plane's
    // `list_keys` advertises the key_ids THIS selector yields — the node's OWN
    // record — instead of the cohort's-own-keys projection. `list_keys` re-reads
    // the record live each tick, so once admit-node scrub-signs this node's own
    // record (scrub_key_id = an accord holder), the NEXT anti-entropy round
    // publishes the scrubbed, ANCHORED record to consent peers → they root it.
    // (KERI publish-own: the controller publishes its own establishment record.)
    // Publish-own **self_provider** (CIRISEdge#311 / edge v9.10.0): the namespace-policy
    // replication engine collapses the former per-plane `key_selector` (#257) and
    // `occurrence_selector` (#305) into ONE hook. It yields THIS node's own key_id so the
    // engine self-publishes every self-owned plane — the Key record (peers root it), the
    // IdentityOccurrence (its `encryption_pubkeys`, the KEX half peers seal to), and the
    // TransportDestination — resolved by namespace/cohort_scope from persist's registry
    // (v15.1.0) rather than a hand-wired list_* + selector per object type. `None` would
    // preserve the pre-selector cohort projection; we publish our own.
    let own_key_id = node_key_id.to_string();
    let self_provider: ciris_edge::replication::CohortProvider =
        Arc::new(move || vec![own_key_id.clone()]);

    let runtime = ReplicationRuntime::start(
        directory,
        transport as Arc<dyn ciris_edge::transport::Transport>,
        peers,
        ReplicationRuntimeConfig::default(),
        Some(self_provider),
    )
    .await;

    // Wire the runtime's registry into the Edge's inbound dispatch (CIRISEdge#119) —
    // EXACTLY ONCE on the single long-lived runtime (set-once OnceLock; never
    // rebuild the runtime). Safe post-boot on the embedded path (see the fn doc).
    edge.install_replication_routing(&runtime);

    tracing::info!(
        initiator_peers = desired.len(),
        "CEG-driven replication runtime started + routed into the shared Edge ({} consent-derived \
         Initiator peers; reconciler converges the rest at runtime via set_peers — no restart, \
         CIRISEdge#173 resolved)",
        desired.len(),
    );
    Ok(Some(Arc::new(runtime)))
}

/// The one shared **Reticulum** edge runtime over the Engine's `SqliteBackend`
/// (directory + queue) and the node's transport-signing identity. The federation
/// signer is wired into the authenticated-announce path (AV-42); the transport-
/// tier RET dual-key identity load-or-generates at `ret_identity_path`.
/// Bridge the edge's Reticulum **announce-event bus** to `tracing`. Every
/// inbound announce the transport processes is logged — rooted (`Info`) with
/// the peer `key_id`, or rejected/failed (`Warning`/`Error`) with the reason —
/// so RNS rooting is observable in `ciris-server.log` instead of silent. This
/// is the diagnosability half of the rooting fix: the original `rooting: None`
/// gap was invisible precisely because announce processing logged nothing.
///
/// Runs for the process lifetime; the task exits when the bus is dropped
/// (transport teardown) or on a closed channel. A lagged receiver logs the
/// drop count rather than aborting — announces are periodic, so a missed batch
/// is re-emitted on the next `ANNOUNCE_INTERVAL`.
pub(crate) fn spawn_announce_logger(bus: Arc<ciris_edge::events::EventBus>) {
    use ciris_edge::events::EventSeverity;
    use tokio::sync::broadcast::error::RecvError;
    let mut rx = bus.subscribe_announces();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(ev) => match ev.severity {
                    EventSeverity::Warning | EventSeverity::Error => tracing::warn!(
                        peer = ?ev.peer_key_id,
                        "RNS announce not rooted: {}",
                        ev.message
                    ),
                    EventSeverity::Info => tracing::info!(
                        peer = ?ev.peer_key_id,
                        "RNS announce rooted (peer now reachable by key_id): {}",
                        ev.message
                    ),
                },
                Err(RecvError::Lagged(n)) => {
                    tracing::warn!("announce-logger lagged; dropped {n} announce events");
                }
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn build_edge(
    engine: &Arc<Engine>,
    cfg: &ServerConfig,
    transport_node: bool,
    store_and_forward: bool,
    resolved: &crate::config_reconcile::ResolvedConfig,
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
        BlobTransportKeystore::platform(cfg.keystore_alias.clone(), keyring_dir.clone())
            .map_err(|e| anyhow::anyhow!("open transport-identity keystore: {e}"))?,
    );
    tracing::info!(
        hardware_backed = transport_keystore.is_hardware_backed(),
        dir = %keyring_dir.display(),
        "transport-identity keystore opened"
    );

    // CIRISEdge#168 (v5.0) / CIRISServer#24 — Transport-node mode. When on, the
    // node forwards inbound packets for non-local destinations across its warm
    // interfaces, so a NAT'd/mobile edge that holds one outbound TCPClient link
    // to this public node (0.0.0.0:4242) gets its inbound routed back down that
    // link. Default ON for a fabric node (it IS the NAT-traversal infra); the
    // owner opts out via the `transport.node` config:* object (Phase 2). (Leviculum's builder
    // default is true; edge always calls .enable_transport explicitly, so this
    // value is honoured either way.)
    let ret_config = ReticulumTransportConfig {
        listen_addr: cfg.listen_addr,
        bootstrap_peers: cfg.bootstrap_peers.clone(),
        identity_path: cfg.ret_identity_path(),
        announce_interval: ANNOUNCE_INTERVAL,
        local_key_id: cfg.key_id.clone(),
        local_epoch: 0,
        interfaces: vec![],
        enable_transport: transport_node,
    };
    // CIRISServer#125 — gate the Reticulum announce's federation-IDENTITY
    // attestation on the `net.announce_ownership` opt-in (default FALSE). The
    // `ReticulumAuth.signer` is used ONCE at construction to sign edge's own
    // announce attestation (the AV-42 binding `key_id → transport destination` that
    // rooting peers verify). When the owner has NOT announced (self-scoped default),
    // we wire `None`: the transport still brings up + announces its raw destination
    // hash (so transport-node forwarding / NAT-traversal / link establishment all
    // work), but the announce carries NO identity attestation → rooting peers drop
    // it (fail-honest) → the node is not federation-identity-discoverable. The
    // promote op (POST /v1/federation/announce) sets `net.announce_ownership=true`;
    // this is BOOT-STRUCTURAL (the attestation is built once at transport
    // construction), so the authenticated announce takes effect on the NEXT boot.
    // This does NOT touch the envelope-signing path: the Edge builder's `.signer(…)`
    // below still wires the SAME signer for federation envelope signatures.
    // Edge v7.0+ requires the federation signer for BOTH the announce attestation
    // (AV-42 app-data) AND the explicit-hash destination derivation. Setting signer=None
    // was valid in v6.x for "no attestation in announce", but now hard-fails at transport
    // construction. The signer is always wired.
    //
    // Privacy is delivered by the OWNER BINDING being `cohort_scope: self` by default
    // (not by suppressing the transport announce). The announce attests the NODE key
    // (ciris-client-XXX) — NOT the owner's fed-ID; the owner identity is invisible until
    // promoted via POST /v1/federation/announce (cohort_scope: federation).
    if resolved.announce_ownership {
        tracing::info!(
            "net.announce_ownership=true — owner binding promoted to federation scope; \
             federation-identity-discoverable"
        );
    } else {
        tracing::info!(
            "net.announce_ownership=false (self-scoped default) — owner binding is private \
             (cohort_scope: self); transport announces the NODE key for routing but the OWNER \
             identity is not federation-visible. Promote via POST /v1/federation/announce."
        );
    }
    // ── Announce rooting (the AV-42 authenticated cold-start) ──────────────
    // The persist `federation_keys` directory IS the edge's `RootingDirectory`
    // — `ciris_edge::verify` blanket-implements `RootingDirectory` for any
    // `FederationDirectory`, so `backend` (the shared `SqliteBackend`) drops in
    // directly. This is load-bearing: on every inbound announce the edge calls
    // `root_binding(key_id, claimed_ed25519)` against this directory, verifies
    // the AV-42 attestation, and records `key_id → transport-identity` so the
    // peer becomes addressable by `key_id` over RNS. With `rooting: None` the
    // edge DROPS every announce ("no rooting directory configured") and NO peer
    // is EVER reachable by key_id — the mesh-relay times out even though the
    // peer's key record is right there in the directory. That silent gap was
    // the root cause of the mesh-seed relay timeouts; wiring it here is the fix.
    // Rooting is announce-driven and self-heals: a peer re-roots within one
    // ANNOUNCE_INTERVAL (300 s) — sooner on link reconnect — after any restart.
    let rooting: Arc<dyn ciris_edge::RootingDirectory> = backend.clone();

    // ── Observability: surface every announce root/reject in the node log ──
    // The reason the rooting gap was invisible for so long is that announce
    // processing emitted NOTHING to the log. Wire the edge announce-event bus
    // and bridge it to `tracing`, so "did peer X root, or why was it rejected?"
    // is answerable from `ciris-server.log` instead of a mystery. Subscribe
    // BEFORE the transport starts so no early announce is missed.
    let event_bus = Arc::new(ciris_edge::events::EventBus::default());
    spawn_announce_logger(Arc::clone(&event_bus));

    let ret_auth = ReticulumAuth {
        signer: Some(Arc::clone(&signer)),
        rooting: Some(rooting),
        // `resolver` stays `None` BY DESIGN, not oversight. An out-of-band
        // `PeerResolver` must return the peer's 64-byte Reticulum transport
        // identity (x25519‖ed25519); that is conveyed ONLY inside the
        // authenticated announce that `rooting` above already consumes, and is
        // NOT stored in `federation_keys` (which holds the fed *signing* key).
        // So `rooting` covers 100% of key_id addressing; a standalone resolver
        // would need edge to expose the rooted identity for persistence and
        // would add a second, weaker (non-announce-verified) trust path.
        resolver: None,
        event_bus: Some(Arc::clone(&event_bus)),
        transport_identity_keystore: Some(transport_keystore),
        ..ReticulumAuth::default()
    };
    let mut transport = ReticulumTransport::new(ret_config, ret_auth)
        .await
        .map_err(|e| anyhow::anyhow!("build reticulum transport: {e}"))?;

    // CIRISEdge#169 (v5.0, §24 propagation) / CIRISServer#24 — store-and-forward.
    // Messages addressed to a currently-unreachable (asleep/offline) mobile edge
    // are queued in a bounded per-destination store and drained on the
    // destination's wake-up fetch, instead of failing. We use edge's own
    // reference `MemoryStoreAndForward` (bounded: 256 entries/dest, 64 MiB total,
    // 7-day TTL — its `StoreAndForwardConfig::default`); a persist-backed queue
    // is a future upgrade. `PendingOrLive` makes a send to an unreachable
    // destination fall back to the queue (returning `Queued`) rather than error.
    // APNs push-to-wake is a mobile/bridge concern and stays out of scope here.
    if store_and_forward {
        let saf: Arc<dyn StoreAndForward> =
            Arc::new(MemoryStoreAndForward::new(StoreAndForwardConfig::default()));
        transport = transport.with_store_and_forward(saf, PendingDelivery::PendingOrLive);
    }
    let transport = Arc::new(transport);
    tracing::info!(
        transport_node,
        store_and_forward,
        "reticulum NAT-traversal infra configured (CIRISServer#24): transport-node forwarding + store-and-forward propagation"
    );
    let mut builder = Edge::builder()
        .directory(backend.clone())
        .queue(backend)
        .signer(signer)
        // The TYPED reticulum path (not the generic `.transport(Arc<dyn Transport>)`):
        // it both wires the transport for run/dispatch AND records it so
        // `Edge::local_transport_pubkey()` / `local_dest_hash()` resolve — which
        // populate the RET-transport role of GET /v1/identity.
        .reticulum_transport(transport);

    // CIRISServer 0.5.58 — attach a serial LoRa/RNode radio transport when
    // `net.radio.enabled` is set (Transport card). SERIAL-CAPABLE TARGETS ONLY
    // (matches the `serialport`/`mod radio` gate): macOS, Windows, linux-gnu
    // x86_64/aarch64. Excluded on armv7/musl (no cross libudev) + android/ios
    // (sandboxed — that's the host-app shim path). A driver-open failure is logged
    // and the node continues on Reticulum alone (never fatal to boot).
    #[cfg(any(
        target_os = "macos",
        target_os = "windows",
        all(
            target_os = "linux",
            target_env = "gnu",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    if resolved.radio_enabled && !resolved.radio_serial_port.trim().is_empty() {
        let params = crate::radio::RadioParams {
            serial_port: resolved.radio_serial_port.clone(),
            frequency_hz: resolved.radio_frequency_hz,
            bandwidth_hz: resolved.radio_bandwidth_hz,
            spreading_factor: resolved.radio_spreading_factor,
            coding_rate: resolved.radio_coding_rate,
            tx_power_dbm: resolved.radio_tx_power_dbm,
        };
        match crate::radio::build_packet_radio_transport(&params, Arc::clone(engine)) {
            Ok(radio) => {
                builder = builder.transport(radio as Arc<dyn ciris_edge::transport::Transport>);
                tracing::info!(
                    port = %resolved.radio_serial_port,
                    freq_hz = resolved.radio_frequency_hz,
                    sf = resolved.radio_spreading_factor,
                    "attached serial LoRa/RNode radio transport to the Edge"
                );
            }
            Err(e) => tracing::error!(
                error = %e, port = %resolved.radio_serial_port,
                "radio transport open FAILED — continuing on Reticulum only"
            ),
        }
    }
    // On non-serial-capable targets (armv7/musl/android/ios) the radio attach is
    // compiled out, so `resolved` would be unused there — silence it.
    #[cfg(not(any(
        target_os = "macos",
        target_os = "windows",
        all(
            target_os = "linux",
            target_env = "gnu",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    let _ = resolved;

    let edge = builder
        .build()
        .map_err(|e| anyhow::anyhow!("build shared Edge: {e}"))?;
    tracing::info!(ret = %cfg.listen_addr, "shared reticulum edge runtime built");
    Ok(edge)
}

/// Open the shared Engine for an OFFLINE, console-trusted CLI op (`config set/get`)
/// WITHOUT starting the transport / read API. Mirrors the boot prelude in [`serve`]:
/// open the hybrid federation signer, build the Engine, derive the FSD-003
/// fingerprinted federation `key_id` (so the config rows are authored under — and
/// read back at boot under — the SAME node `key_id`), and self-register the node key
/// (so `put_attestation` admits the node-signed config row). Returns the Engine +
/// the config with `key_id`/`occurrence_id` set to the derived wire identity.
async fn open_engine_for_cli(cfg: &ServerConfig) -> Result<(Arc<Engine>, ServerConfig)> {
    cfg.ensure_dirs()?;
    let signer: Arc<dyn HardwareSigner> = Arc::from(federation_signer(cfg)?);
    let pqc: Arc<dyn PqcSigner> = federation_pqc_signer(cfg)?;
    let engine = build_engine(cfg, Arc::clone(&signer), Arc::clone(&pqc)).await?;
    let ed_pub = signer
        .public_key()
        .await
        .context("read node ed25519 pubkey for key_id derivation")?;
    let mut cfg = cfg.clone();
    cfg.key_id = ciris_verify_core::fedcode::derive_key_id(&cfg.keystore_alias, &ed_pub);
    cfg.occurrence_id = cfg.key_id.clone();
    // The node key MUST be a federation_keys row before it can author the config
    // attestation (put_attestation FK). Idempotent (benign conflict on re-run).
    register_self_key(&engine, &cfg).await?;
    Ok((engine, cfg))
}

/// Bootstrap dial targets sourced from the BAKED canonical servers' signed envelope
/// transport hints (CIRISPersist#381) — the reachability half of the mesh seed. Each
/// canonical `KeyRecord` carries its transport hint inside the accord-scrubbed
/// `registration_envelope`, so a fresh node learns WHERE to dial from the same object
/// that establishes WHO it trusts — no hardcoded const, no config list to maintain.
///
/// Only `kind == "ip"` hints are dialable TCP entries; a `reticulum` hint is a
/// pubkey-derived overlay address (not an internet bootstrap target) and is skipped.
/// Returns empty on a substrate whose canonical records carry no `transport_hints`
/// yet (forward-compatible: a pre-#381 record simply has no such envelope key).
pub(crate) async fn canonical_bootstrap_addrs(engine: &Engine) -> Vec<std::net::SocketAddr> {
    match engine.canonical_bootstrap_hints().await {
        Ok(hints) => ip_addrs_from_hints(&hints),
        Err(e) => {
            tracing::warn!(error = %e, "canonical_bootstrap_hints failed — using config override only");
            Vec::new()
        }
    }
}

/// Pure extraction of dialable `ip` bootstrap addresses from persist's
/// `canonical_bootstrap_hints()` — the `(key_id, TransportHint)` pairs read from the
/// canonical records' signed envelopes (CIRISPersist#381). Split out so the filter is
/// unit-testable without an engine. Skips non-`ip` kinds (a `reticulum` hint is a
/// pubkey-derived overlay address, not a TCP bootstrap target) + un-parseable dests.
pub(crate) fn ip_addrs_from_hints(
    hints: &[(String, ciris_persist::federation::types::TransportHint)],
) -> Vec<std::net::SocketAddr> {
    let mut out = Vec::new();
    for (key_id, h) in hints {
        if h.kind != "ip" {
            continue;
        }
        match h.destination.parse::<std::net::SocketAddr>() {
            Ok(addr) => out.push(addr),
            Err(e) => tracing::warn!(
                canonical = %key_id,
                dest = %h.destination,
                error = %e,
                "canonical ip transport hint is not host:port — skipping"
            ),
        }
    }
    out
}

/// `ciris-server config set <key> <value>` (console-trusted, node-signed). Writes a
/// signed `config:v1` CEG object — the SAME path the node itself + `POST /v1/config`
/// use — so a HEADLESS node (console-only, no app/session) can set `config:*` knobs
/// like `net.bootstrap_peers`. Returns the freshly-written entry.
pub async fn run_config_set(
    cfg: ServerConfig,
    key: &str,
    value: crate::graph_config::ConfigValue,
    reason: &str,
) -> Result<crate::graph_config::ConfigEntry> {
    let (engine, cfg) = open_engine_for_cli(&cfg).await?;
    crate::graph_config::set_config(
        &engine,
        &cfg.key_id,
        key,
        value,
        reason,
        crate::graph_config::ConfigScope::default(),
    )
    .await
}

/// `ciris-server config get <key>` (console). Reads the latest-wins value for `key`
/// from the node's signed `config:v1` store (`None` if unset/tombstoned).
pub async fn run_config_get(
    cfg: ServerConfig,
    key: &str,
) -> Result<Option<crate::graph_config::ConfigEntry>> {
    let (engine, cfg) = open_engine_for_cli(&cfg).await?;
    crate::graph_config::get_config(&engine, &cfg.key_id, key).await
}

/// Authority slice — folds in at **Server 0.6** (CIRISRegistry#76). Attaches to
/// the shared Edge (the node's single identity) + serves the registry trust
/// surface over the shared Engine. SCAFFOLD. (0.5 is config-as-CEG; registry is 0.6.)
async fn compose_registry(_edge: &Edge, _engine: &Arc<Engine>, _cfg: &ServerConfig) -> Result<()> {
    todo!("registry slice (Server 0.6) — pin ciris-registry-core (CIRISRegistry#76) + attach to the shared Edge")
}

/// Consensus slice — folds in at **Server 1.0** (CIRISNodeCore#38). `install(&edge)`
/// on the shared Edge + the WBD `route_deferral` / Wise-Authority surface. SCAFFOLD.
async fn compose_node(_edge: &Edge, _engine: &Arc<Engine>, _cfg: &ServerConfig) -> Result<()> {
    todo!("node slice (Server 1.0) — pin ciris-node-core (CIRISNodeCore#38) + install(&edge)")
}

#[cfg(test)]
mod bootstrap_hint_tests {
    use super::ip_addrs_from_hints;
    use ciris_persist::federation::types::TransportHint;

    fn hint(kind: &str, dest: &str) -> TransportHint {
        TransportHint {
            kind: kind.to_string(),
            destination: dest.to_string(),
        }
    }

    #[test]
    fn extracts_ip_hints_skips_reticulum_and_unparseable() {
        let hints = vec![
            ("canonical-1".to_string(), hint("ip", "108.61.242.236:4242")),
            // reticulum: pubkey-derived overlay, not a TCP bootstrap target → skipped
            (
                "canonical-1".to_string(),
                hint("reticulum", "81cabcf78a6ee16f197ba7e530a2f6db"),
            ),
            // malformed ip → skipped (warned)
            ("canonical-1".to_string(), hint("ip", "not-a-socket-addr")),
            ("canonical-3".to_string(), hint("ip", "10.0.0.9:4242")),
        ];
        let addrs = ip_addrs_from_hints(&hints);
        assert_eq!(
            addrs.len(),
            2,
            "only the two well-formed ip hints (reticulum + bad skipped)"
        );
        assert!(addrs.contains(&"108.61.242.236:4242".parse().unwrap()));
        assert!(addrs.contains(&"10.0.0.9:4242".parse().unwrap()));
    }

    #[test]
    fn empty_without_canonical_hints() {
        assert!(ip_addrs_from_hints(&[]).is_empty());
    }
}
