//! CIRISServer — the fabric node composition library.
//!
//! The federation's headless cohabitation runtime: `ciris-lens-core`
//! (observation) — and, as their co-bumps land, `ciris-registry-core`
//! (authority, Server 0.5) and `ciris-node-core` (consensus, Server 1.0) —
//! composed over **one shared persist `Engine`**. `agent = fabric node + brain`;
//! this is that composition with the brain removed.
//!
//! ONE composition, TWO shapes (MISSION.md §1.2/§6):
//!   - this crate as a **PyO3 abi3 wheel** (`crate-type = cdylib`, `python`
//!     feature) that CIRISAgent — pure Python — pip-installs and links instead
//!     of composing the cores itself (`pip install ciris-server` → the
//!     `ciris-server` command);
//!   - this crate as an **rlib** linked by the `ciris-server` binary
//!     (src/main.rs) for the headless deployment.
//!
//! It authors no primitives and holds no ethical agency (MISSION.md §1.3): it
//! attests, stores, observes, reaches consensus, and transports — it does not
//! reason, decide, or act. The separation-of-powers invariant is held
//! cryptographically per **CEG §7.0.1** (MISSION.md §1.5).
//!
//! STATUS: **0.1 — lens-only, implemented.** `run()` boots a working lens fabric
//! node (relay ingest + the 7 frozen `GET /lens/api/v1/*` read endpoints) over a
//! shared SQLite persist Engine, zero-setup. The registry (0.5) and node (1.0)
//! slices are scaffolded in `compose.rs` and fold in as their co-bumps land.

/// HUMANITY_ACCORD server surface (CIRISServer#41, CC 4.2 / §9.2) — the
/// accord-holder registry + the 2-of-3 invocation kill-switch (the safe-mesh
/// floor that gates cutting 0.6 / bootstrapping the canonical mesh).
pub mod accord;
/// HUMANITY_ACCORD holder-device **portable high-secure** provisioning
/// (CIRISServer#41) — the caller-run library tool that mints a holder's
/// self-signed `accord_holder` record + its `portable_2fa` custody attestation
/// (FIPS YubiKey Ed25519 + USB-wrapped ML-DSA-65; both-keys + PIN + touch).
pub mod accord_custody;
/// HUMANITY_ACCORD operational halt (CIRISServer#41) — the disk-latched full halt
/// + the startup gate that makes the 2-of-3 kill-switch enforceable (CC 4.2.3).
pub mod accord_halt;
/// `POST /v1/accord/provision-holder` — the loopback-only server endpoint behind
/// the guided desktop "Provision Accord Holder" flow. Drives
/// [`accord_custody::provision_portable_holder`] from the holder's already-FIPS-
/// approved YubiKey + the chosen ML-DSA USB path. `pkcs11`-feature-gated for the
/// real-token path (returns NotSupported without it).
pub mod accord_provision;
/// HUMANITY_ACCORD reactivation (CIRISServer#41, CC 4.2.1 §69) — the offline
/// `accord reactivate` op: a verified 2/3 `accord:lifecycle:active` clears the halt
/// latch (the quorum brings the node back, never an operator restart).
pub mod accord_reactivate;
/// The public **adapter seam** — a Rust mirror of CIRISAgent's
/// `BaseAdapterProtocol`. A downstream crate (e.g. CIRISStatus) implements
/// [`adapter::Adapter`] and boots via [`serve_with_adapter`] to become
/// "ciris-server + an adapter": it contributes HTTP routes + a background
/// lifecycle to the SAME shared core, instead of re-composing the substrate.
pub mod adapter;
/// The fabric auth subsystem — CIRISServer as the single auth authority
/// (CIRISServer#9): one hybrid request contract, the CEG role-set, self-at-login
/// (so consent/erasure are user-signed in 3.x, not agent-signed in 2.x), the
/// owner-binding gate, and the absorbed agent auth surface (sessions, OAuth,
/// api-keys/service-tokens, attestation/consent/erasure) over the shared
/// `wa_cert` substrate. Public so the wheel exposes the auth API the agent
/// consumes as a delegate (the single-authority contract).
pub mod auth;
/// Operator-facing holonomic federation scoreboard (CIRISServer#12/#13).
pub mod benchmarks;
/// Claim remote ownership — the SUBSTRATE-NATIVE, node-to-node claiming side of
/// the 1-phase owner-binding (`POST /v1/setup/claim-remote`). The local node
/// decodes the target NodeCode, builds + hybrid-signs the `delegates_to(user →
/// target, infra:*)` owner-binding with the responsible USER's key, and POSTs it
/// to the target's `POST /v1/setup/root`. The app does NO crypto. Public so the
/// integration test (`tests/claim_remote.rs`) can drive build + apply directly.
pub mod claim_remote;
/// **CC 4.5.2.2 `compliance-vertical`** — the machine-readable vertical/statutory
/// compliance map (CIRISServer#159). Bakes `evidence/cc_compliance_map.tsv` (a faithful
/// transcription of CC 4.5.2.2 + CC 8.8.5 Annex C) into the binary and parses it into
/// typed rows. Mappings the Constitution does not state are `unmapped`, never invented.
/// Gated by `tests/compliance_map.rs`.
pub mod compliance;
mod compose;
/// **The CEG consumer-composition tier** (CC 4.4 / CC 4.4.1 / CC 4.4.2 /
/// CC 4.4.3.8 / CC 4.4.3.9 / CC 3.4.9) — the MUST behind this node's `CCC`
/// (CEG-Conforming Consumer) wire declaration: *"A CEG-Conforming Consumer MUST
/// implement at least Policy A"* (CC 4.4). Turns attestations read from persist
/// into typed, fail-closed verdicts. Public so `tests/compose_policy.rs` can
/// drive the composition adversarially.
pub mod compose_policy;
/// Compose-phase boot progress + record-and-continue watchdog (CIRISServer#279)
/// — the in-process channel that localizes an embedded-fold compose hang to a
/// named phase. Read via the `ciris_server.compose_status()` PyO3 accessor.
pub mod compose_status;
/// Zero-setup node configuration (Server 0.5 — conventions + CLI, NO env). Public
/// so the binary's flag parser can read the baked-default constants
/// ([`config::DEFAULT_CIRIS_HOME`] / [`config::DEFAULT_KEY_ID`]).
pub mod config;
/// **Config-as-CEG HTTP** (Server 0.5 Phase 1) — the owner-gated `/v1/config`
/// surface over [`graph_config`]. A config WRITE is gated the SAME way federation
/// peering is (serve-only floor + SYSTEM_ADMIN owner session). Public so the
/// integration test (`tests/graph_config.rs`) can drive the router directly.
pub mod config_api;
/// **CEG-driven config reconciler** (Server 0.5 Phase 2) — resolves the migrated
/// runtime-tunable knobs (transport/scorer/replication-cadence/mode) from the
/// corpus's signed `config:*` objects into a live [`config_reconcile::ResolvedConfig`]
/// snapshot consumers read (the scorer reads it HOT each cycle). The API never
/// touches the runtime — it writes CEG and nudges this loop. Public so the
/// integration test (`tests/config_reconcile.rs`) can drive `resolve` directly.
pub mod config_reconcile;
/// **CC 2.2 conformance levels + CC 2.6.4 versioning policy** (CIRISServer#159) —
/// the node's DECLARED conformance level (CCP / CCC / CCS) and the enforcement that
/// HONORS it (a federation-wire op whose profiles the declaration does not claim is
/// REFUSED), plus the CC 2.6.4 SemVer wire-version + wire-vocabulary-hash
/// negotiation that REFUSES an incompatible peer rather than silently proceeding.
/// Both fail closed. Public so the integration test (`tests/conformance_gate.rs`)
/// can drive the gate + the negotiation directly.
pub mod conformance;
/// Delegation-transparency middleware — stamps a `dgrant:` caller's full grant
/// characteristics onto every response (the "no silent authority" layer).
pub mod delegation_transparency;
/// Generic CEWP **family operations** over persist's family CEG DX
/// (`federation_families` + membership revocations) — create / add / live-roster /
/// swap, NOT accord-aware. The HUMANITY_ACCORD kill-switch is one specialization.
pub mod family;
/// Owner-directed federation operations (the keystone for on-demand
/// `consent:replication` peering): `GET /v1/federation/self-key-record` +
/// `POST /v1/federation/peering`. Each node authors its OWN consent grant
/// (owner-authority model). Public so the integration test
/// (`tests/federation_admin.rs`) can drive the router directly.
pub mod federation_admin;
/// Agent-embedded federation-delivery controller (CIRISServer#205, subsuming
/// #204): the ONE entry a bare AGENT calls after its embedded edge is up so it
/// drives the compose delivery machinery (ReplicationRuntime + consent:replication
/// reconcile + announce logger) against the baked canonical peer — in-process, via
/// `current_rust_engine()` + `current_edge()`.
pub mod federation_delivery;
/// THIS node's own NodeCode (the QR-able federation-key bootstrap handle, CEG
/// §0.10): `GET /v1/federation/node-code` — the PUBLIC bootstrap code an operator
/// reads off the node and hands to a founder's app. Public so the integration
/// test (`tests/nodecode.rs`) can drive the router directly.
pub mod federation_nodecode;
/// **Federation peers READ surface** (agent-compat Network card): `GET
/// /v1/federation/peers` + `GET /v1/federation/peers/{key_id}`. Projects the
/// `federation_directory` `federation_keys` rows onto the client's
/// `LocalPeerState` wire contract so the desktop/mobile Network card works in
/// server mode.
pub mod federation_peers;
/// **The agent-compat federation edge surface** (CIRISServer#261): `GET
/// /v1/federation/identity` + `GET /v1/federation/metrics` + `POST
/// /v1/federation/content/{content_id}` + the `GET
/// /v1/federation/events/{channel}` SSE bridge over the edge event bus — the
/// four routes the CIRISAgent wave-2 DRY purge deletes from Python that need
/// the live `Arc<Edge>`. The deleted agent route files are the wire spec.
pub mod federation_surface;
/// **Config-as-CEG** (Server 0.5 Phase 1) — a signed, owner-gated GraphConfig
/// service over the CEG, mirroring CIRISAgent's `GraphConfigService` but
/// hybrid-signed + owner-gated. Config entries are self-attested `config:v1`
/// `scores` rows (latest-wins by version). Public so the integration test
/// (`tests/graph_config.rs`) can drive the store directly.
pub mod graph_config;
/// **CC 4.2.2.1** (CIRISServer#159, closes CC 8.3.1 R5) — the hardware-class
/// admission gate. `federation_keys.hardware_class` (which rides inside
/// `attestation_evidence`) was an UNCHECKED SELF-REPORT on every admission path
/// but the accord one: persist enforces its `HardwareAttestationPolicy` only for
/// `identity_type = 'accord_holder'`. This module applies that same substrate
/// policy to EVERY key the server admits, and adds the cryptographic chain +
/// key-binding check persist explicitly defers to the consumer. An unverifiable
/// hardware claim is REFUSED (fail-closed); a key that claims nothing is admitted
/// as software-class. `register_attested_federation_key` is the chokepoint every
/// `register_federation_key` call site in this crate goes through.
pub mod hardware_attestation;
/// Server health — the fabric node's own liveness endpoint (`/health`,
/// `/v1/health`, `/v1/system/health`). Mandatory base health; the agent enriches
/// `/v1/system/health` with optional cognitive health.
pub mod health;
/// CIRISServer#11 — wire CIRISEdge's holonomic-tier `FountainSwarmRuntime`
/// (the publisher + converger that advertise this node's held fountain
/// content and act on peers' holding claims) into the shared Edge. The
/// persist-backed trait adapters + the `install_swarm_runtime` entry point
/// that mirrors the replication wiring shape (build before `edge.run()`).
pub mod holonomic;
/// HTTP error-response logging middleware (the "never guess" layer).
pub mod http_log;
/// Mint a hardware-rooted (YubiKey / TPM-SE / software) **USER** federation
/// identity via ciris-server (the founder's goal, CIRISServer#21 /
/// CIRISVerify#80). `mint_user_identity` opens the user's Ed25519 signing half
/// for the chosen backend, calls verify v6.0.0 `create_federation_identity`
/// (which attaches the sealed ML-DSA-65 half + emits the genesis CEG object),
/// and returns the user `key_id` + the `CIRIS-V2-` usercode. The minted identity
/// also composes into the `POST /v1/setup/claim-remote` signer. Public so the
/// CLI subcommand, the `POST /v1/self/identity` endpoint, and the integration
/// test can drive it.
pub mod identity;
/// A single cosmetic-id helper (`new_id`) shared by the attestation builders —
/// replaces the per-module hand-rolled `new_uuid_v4` copies.
pub mod ids;
mod import;
/// HTTP trace-ingest endpoint (the `listen+1` relay runbook §3.4 promised) — the
/// legacy lens-python path `POST /lens-api/api/v1/accord/events` (+ a canonical
/// alias) re-opened on the read-API listener. Deserializes the agent emitter's
/// signed `AccordEventsBatch` JSON and feeds it to the SAME verify-before-persist
/// path the Reticulum relay uses (`Engine::receive_and_persist`); the CEG
/// signature is the auth, so it is unauthenticated like the relay. Public so the
/// integration test (`tests/ingest_http.rs`) can drive the router directly.
pub mod ingest_http;
/// **Memory READ surface** — agent-compat Memory + GraphMemory card endpoints
/// (`GET /v1/memory/stats`, `GET /v1/memory/timeline`, `POST /v1/memory/query`,
/// `GET /v1/memory/{node_id}`, `GET /v1/memory/{node_id}/edges`). Projects the
/// `cirisgraph_nodes` / `cirisgraph_edges` SQLite tables onto the client's
/// wire contract so both cards work in server mode.
pub mod memory_api;
/// **Mesh control-plane relay** (CIRISServer#128 Phase D): `POST /v1/mesh/relay`
/// (the local RNS-gateway endpoint) + the remote `MeshControlResponder` riding
/// edge v8.0.0's generic opaque RPC on CIRISServer's CC 0.7 Tier-2 kind
/// `0x0000_0001` (`WIRE_VOCABULARY_KINDS.md`). An owner administers an IP-less
/// owned node by federation `key_id`, authorized by the owner fed-ID signature
/// (`FSD/RNS_CONTROL_RELAY.md` + `FSD/EDGE_8_0_OPAQUE_MIGRATION.md` §6). Public
/// so the mesh-seed TDD gate (`tests/mesh_seed_e2e.rs`) can drive both halves.
pub mod mesh_relay;
/// In-process node lifecycle control — the `shutdown_node()` stop handle that
/// frees `:4243` deterministically on an embedded-fold restart (CIRISServer#276).
pub mod node_control;
/// The NodeCode codec — a faithful Rust port of the agent's authoritative
/// `node_code_codec.py` (CEG §0.10). `encode`/`encode_qr`/`decode` round-trip
/// byte-identically with the agent so a code shared from one app decodes on the
/// other. Public so the node-code endpoint + the founder's client can use it.
pub mod nodecode;
/// Directed-consent federation peering (CIRISServer federation Round 2): mutual
/// key registration + the `consent:replication:v1` grant that authorizes
/// bidirectional replication with an out-of-group peer (Node B / `ciris-status`).
/// Public so the integration test (`tests/peer_replication.rs`) can drive the
/// admission + consent-emit logic directly.
pub mod peer;
/// Mount-by-proxy router (CIRISServer#80) — reverse-proxy a path prefix to a
/// sibling service's upstream base URL, so an out-of-process brain folds onto the
/// node's one read-API. Used by the Python adapter bridge ([`py_adapter`]).
pub mod proxy;
/// PyO3 adapter bridge (CIRISServer#80) — wrap a Python adapter object as an
/// [`adapter::Adapter`] so a Python brain folds into the node's router via
/// [`serve_with_adapter`] (`ciris_server.serve_with_python_adapter`).
#[cfg(feature = "python")]
mod py_adapter;
/// The `ciris-canonical` founder-quorum (steward-key replacement) — shared with
/// the registry slice at Server 0.5 (CIRISServer#1; FSD/REGISTRY_FOLD_DERISK.md).
pub mod quorum;
/// Serial-attached RNode LoRa radio driver for the edge packet-radio transport
/// (CIRISServer LoRa medium). Desktop-only (the `serialport` crate is not
/// available on the android/ios wheels), so the whole module is gated off the
/// mobile targets.
// Serial-capable targets only (matches the `serialport` dep gate in Cargo.toml):
// macOS, Windows, linux-gnu x86_64/aarch64. Excludes armv7/musl (no cross libudev)
// + android/ios (sandboxed).
#[cfg(any(
    target_os = "macos",
    target_os = "windows",
    all(
        target_os = "linux",
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
pub mod radio;
/// The **CEG-driven replication reconciler** (the controller loop): the corpus's
/// `consent:replication` objects ARE the desired replication topology, and this
/// loop converges the live `ReplicationRuntime` to them. The API never touches
/// the runtime — it writes CEG and nudges this loop. Public so the integration
/// test (`tests/replication_reconcile.rs`) can drive `reconcile_once` directly.
pub mod replication_reconcile;
/// The substrate **safety foundation** (CIRISServer#20) — moderation +
/// child-safety as first-class fabric primitives, built AHEAD of content
/// features: age-assurance + the protective age-gate, moderation as a delegable
/// DUTY (composing persist v9.0.0's §11.10 admit-iff gate), the CC 4.5.4
/// named-moderator existence invariant (fail-secure + merit auto-promotion), and
/// the opt-in per-group watchlist config + duty/authority gate + publish-seam
/// hook (the matcher defers to the NodeCore content seam). Public so the
/// integration test (`tests/safety.rs`) can drive the modules + routers directly.
pub mod safety;
/// The capacity score→emit pipeline — a periodic task that derives per-agent
/// N_eff from ingested traces and emits federation-tier `capacity:*` attestations
/// (CIRISServer federation Round 1, deliverable 2). Public so the integration
/// test (`tests/capacity_scorer.rs`) can drive a single deterministic pass.
pub mod scorer;
pub mod system_data;
pub mod telemetry_logs;
#[cfg(feature = "test-anchor")]
mod test_bless;
/// **CC 4.1.4** — the `withdraws`:`recants` arbitrage countermeasure
/// (CIRISServer#159). Consumer-policy behavioral analysis: per-attester
/// precedence-collapsed `withdraws:recants` ratio over a rolling window, with a
/// fail-closed refusal to consume from an over-threshold (default 5:1) attester.
/// Gates federation peering + the replication reconciler; it does NOT touch
/// substrate admission (CC 2.4.1.1 MUST-admit stays intact).
pub mod withdraws_arbitrage;

pub use config::{Mode, PeerB, ServerConfig, Slices};

/// The config-as-CEG schema types (Server 0.5 Phase 1) — re-exported at the crate
/// root for downstream/test use.
pub use graph_config::{ConfigEntry, ConfigScope, ConfigValue};

/// The resolved runtime-tunable config snapshot (Server 0.5 Phase 2) — re-exported
/// at the crate root for downstream/test use.
pub use config_reconcile::ResolvedConfig;

// The adapter seam's public surface — what a downstream crate (CIRISStatus)
// imports to be "ciris-server + an adapter".
pub use adapter::{Adapter, AdapterConfig, AdapterContext, AdapterStatus, NoopAdapter};
pub use compose::{serve, serve_with_adapter};

/// The console-trusted `config set`/`config get` CLI ops (Server 0.5.73) — open the
/// node's Engine offline + read/write a signed `config:v1` CEG object, so a HEADLESS
/// node can set `config:*` knobs (e.g. `net.bootstrap_peers`) with no app/session.
pub use compose::{run_config_get, run_config_set};

/// The shared persist `Engine` (re-exported so a downstream adapter crate gets
/// the EXACT type [`AdapterContext::engine`] carries, without depending on
/// `ciris-persist` directly or guessing its path).
pub use ciris_persist::prelude::Engine;

use anyhow::Result;

/// Run the fabric node from the **conventions + CLI** (Server 0.5 zero-env):
/// `home` is the data root (`--home` or [`config::DEFAULT_CIRIS_HOME`]); `key_id`
/// is the federation key label (`--key-id` or [`config::DEFAULT_KEY_ID`]). All
/// other config is baked constants or `config:*` CEG resolved at boot.
pub async fn run(home: std::path::PathBuf, key_id: String) -> Result<()> {
    let cfg = ServerConfig::from_home(home, key_id)?;
    tracing::info!(
        home = %cfg.home.display(),
        data_dir = %cfg.data_dir.display(),
        listen = %cfg.listen_addr,
        key_id = %cfg.key_id,
        "CIRISServer (the fabric node) starting — lens-only (0.1); ZERO env vars: home is the one \
         input (--home), all other config is baked constants or config:* CEG resolved at boot \
         (Server 0.5)"
    );
    compose::serve(cfg).await
}

/// Run with the baked defaults (home = [`config::DEFAULT_CIRIS_HOME`], key_id =
/// [`config::DEFAULT_KEY_ID`]) — the entry point for hosts that take no flags
/// (the PyO3 wheel `main`).
pub async fn run_default() -> Result<()> {
    run(
        std::path::PathBuf::from(config::DEFAULT_CIRIS_HOME),
        config::DEFAULT_KEY_ID.to_string(),
    )
    .await
}

/// Parse the default-serve flags `--home <path>` and `--key-id <name>` (both
/// optional; `--flag=value` also accepted). `leading` is the first token already
/// pulled off the iterator by the caller's subcommand match (itself a flag on the
/// serve path; `None` for a bare invocation). Unknown args are an error — fail
/// loud, NEVER silently ignore a misspelled flag on the security-relevant serve
/// path. Shared by BOTH entry points (the `ciris-server` binary AND the PyO3 wheel
/// `main`) so the wheel honors `--home`/`--key-id` identically — without this the
/// wheel fell through to `run_default()` and ignored the flags (CIRISServer#27).
pub fn parse_serve_flags(
    leading: Option<String>,
    rest: impl Iterator<Item = String>,
) -> Result<(std::path::PathBuf, String)> {
    let mut home: Option<String> = None;
    let mut key_id: Option<String> = None;

    let take_value = |arg: &str,
                      eq_value: Option<String>,
                      it: &mut dyn Iterator<Item = String>|
     -> Result<String> {
        match eq_value {
            Some(v) => Ok(v),
            None => it
                .next()
                .ok_or_else(|| anyhow::anyhow!("{arg} needs a value")),
        }
    };

    let mut it = leading.into_iter().chain(rest);
    while let Some(arg) = it.next() {
        let (name, eq_value) = match arg.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (arg.clone(), None),
        };
        match name.as_str() {
            "--home" => home = Some(take_value("--home", eq_value, &mut it)?),
            "--key-id" => key_id = Some(take_value("--key-id", eq_value, &mut it)?),
            other => {
                return Err(anyhow::anyhow!(
                    "unknown serve arg: {other} (usage: ciris-server [--home <path>] [--key-id <name>])"
                ))
            }
        }
    }

    let home = home.unwrap_or_else(|| config::DEFAULT_CIRIS_HOME.to_string());
    let key_id = key_id.unwrap_or_else(|| config::DEFAULT_KEY_ID.to_string());
    Ok((std::path::PathBuf::from(home), key_id))
}

/// Import the legacy CIRISLens TimescaleDB trace dump into the persist corpus as
/// CEG objects (the `import-traces <dump-dir>` subcommand). See `src/import.rs`.
pub async fn import_traces(dump_dir: &str) -> Result<()> {
    import::run(dump_dir).await
}

/// The user-identity seed directory — DISTINCT from the node steward's
/// `identity_dir` (the human's signing key must NOT be co-resident with the node
/// key). The **conventional** path `<identity_dir>/user` (Server 0.5: no env). The
/// `ciris-server identity create` CLI mints into here.
pub fn user_seed_dir(cfg: &ServerConfig) -> std::path::PathBuf {
    cfg.identity_dir.join("user")
}

/// The filename, inside [`user_seed_dir`], that records the **active owner user
/// identity's keystore alias** — the slug the user chose at mint (e.g.
/// `eric-moore-v1`), so the user's chosen name DRIVES their fed-ID `key_id`
/// (`<alias>-<fp>`) instead of the node-derived `<keystore_alias>-user` fallback.
pub const ACTIVE_USER_ALIAS_FILE: &str = "active_user_alias";

/// Resolve the active owner user-signer alias, READ AT REQUEST TIME (not boot):
/// the mint writes [`ACTIVE_USER_ALIAS_FILE`] into `user_seed_dir`, and every
/// owner-signer resolution (claim-remote, portable-occurrence, post-claim owner
/// ops) reads it here so it finds the signer the user actually minted under their
/// chosen name. Falls back to `default_alias` (the conventional
/// `<keystore_alias>-user`) when the pointer is absent — back-compat for an
/// identity minted before this pointer existed.
pub fn active_user_alias(user_seed_dir: &std::path::Path, default_alias: &str) -> String {
    let p = user_seed_dir.join(ACTIVE_USER_ALIAS_FILE);
    match std::fs::read_to_string(&p) {
        Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => default_alias.to_string(),
    }
}

/// Record the active owner user alias (the slug the user chose at mint) into
/// `user_seed_dir/active_user_alias`, so subsequent owner-signer resolutions
/// ([`active_user_alias`]) find it. Best-effort: a write failure is logged by the
/// caller, never fatal to the mint.
pub fn write_active_user_alias(
    user_seed_dir: &std::path::Path,
    alias: &str,
) -> std::io::Result<()> {
    std::fs::create_dir_all(user_seed_dir)?;
    std::fs::write(user_seed_dir.join(ACTIVE_USER_ALIAS_FILE), alias)
}

/// Drive `ciris-server identity create` — the founder's "mint my YubiKey-backed
/// federation ID via ciris-server" command. Mints the USER identity for `backend`
/// (defaulting the alias/seed-dir from config), persists the genesis CEG object,
/// and returns the minted identity (the caller prints it). Public so both the
/// binary and the wheel CLI can call it.
pub async fn provision_user_identity(
    cfg: &ServerConfig,
    backend: identity::UserIdentityBackend,
    label: Option<String>,
    seed_dir_override: Option<std::path::PathBuf>,
) -> Result<identity::MintedUserIdentity> {
    cfg.ensure_dirs()?;
    // `--seed-dir` overrides the conventional per-user seed location (Server 0.5:
    // a CLI flag, not the old CIRIS_USER_SEED_DIR env).
    let seed_dir = seed_dir_override.unwrap_or_else(|| user_seed_dir(cfg));
    std::fs::create_dir_all(&seed_dir)?;
    // The user-identity alias: a stable default distinct from the node identity
    // (Server 0.5: convention, not env). This names the on-disk user KEYSTORE
    // blob, so it derives from the RAW keystore_alias (NOT the derived key_id).
    let alias = format!("{}-user", cfg.keystore_alias);
    identity::mint_user_identity(backend, &alias, label.as_deref(), seed_dir).await
}

/// Emit the **modeled** holonomic federation scoreboard (CIRISServer#12/#13) as
/// JSON — the operator surface for measured-vs-modeled capacity/survival. The
/// storage tier is fully grounded (binomial survival reproduces scale_model v0.7);
/// substrate/holonomic tiers are honest "gated" stubs until their data lands.
pub fn scoreboard_json() -> String {
    benchmarks::Scoreboard::modeled(benchmarks::FountainPolicy::REFERENCE).to_json()
}

/// Emit the holonomic federation scoreboard with the **substrate tier promoted to
/// MEASURED** from a criterion output directory (`target/criterion`). Reads
/// criterion's own `estimates.json` per bench and derives `aead_throughput_per_core`,
/// `alm_tree_depth_vs_n`, `replication_ingest_per_sec`, and `stream_fanout_core_frac`
/// from the real median time/iter — "numbers through the fabric." Any metric whose
/// bench didn't run falls back to gated; `mls_commit_barrier`/`cold_join_burst_latency`
/// and the whole holonomic tier stay gated (no bench grounds them).
pub fn scoreboard_json_with_criterion(criterion_dir: &str) -> String {
    benchmarks::Scoreboard::modeled(benchmarks::FountainPolicy::REFERENCE)
        .with_criterion_dir(criterion_dir)
        .to_json()
}

/// Emit the unified **`bench_results.json`** (schema v2) — the honest source of truth
/// for the public bench page. EVERY entry is `"measured"` or `"gated"` (never
/// `modeled`/`attested`): substrate throughput/scoring/KEX/fanout/signature metrics from
/// real criterion medians (`criterion_dir`), the EMPIRICAL erasure-survival curve from
/// the `erasure_survival` bench sidecar (`erasure_sidecar`; GATED if absent), and live
/// in-process MESH measurements (cohort propagation + isolation + A↔B replication) over
/// the real `FountainSwarmRuntime`.
pub fn bench_results_json(
    commit: &str,
    date: &str,
    criterion_dir: &str,
    erasure_sidecar: &str,
) -> String {
    benchmarks::build_bench_results(
        commit,
        date,
        std::path::Path::new(criterion_dir),
        std::path::Path::new(erasure_sidecar),
    )
    .to_json()
}

/// Arm the RNG SP 800-90B startup health-check latch ONCE per process
/// (CIRISServer#283 finding 2). Until this runs, `ciris_crypto::random::fill`'s
/// fail-secure gate is inert (it only READS the latch). Idempotent across calls;
/// the check itself draws entropy once. Called from `serve_with_adapter` (node
/// boot) and the CLI entry so every secret-drawing path is gated.
pub fn init_rng_health() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let verdict = ciris_crypto::rng_health::run_startup_health_check();
        tracing::info!(?verdict, "RNG SP 800-90B startup health-check armed (#283)");
    });
}

/// Initialize tracing — stdout ONLY. Kept for short-lived CLI subcommands that
/// have no data root. Node serve paths use [`init_tracing_with`] so the node logs
/// reliably to a file.
pub fn init_tracing() {
    init_tracing_with(None);
}

/// Initialize tracing with an optional file sink under `log_dir`.
///
/// A headless node is launched as a subprocess by the desktop app, so its stdout
/// is whatever the launcher captures (often nothing durable). That left the
/// node's logs unrecoverable for debugging. When `log_dir` is `Some`, we ALSO
/// install a non-blocking daily-rolling file appender (`<log_dir>/ciris-server.log`)
/// — the node logs RELIABLY to disk, mirroring how the agent logs to files.
/// stdout stays on too (the console still works when present).
/// Build the `<dir>/ciris-server.log` file layer with a SYNCHRONOUS rolling
/// appender — no `tracing_appender::non_blocking` worker thread. CIRISServer#264
/// must-have 4: under Chaquopy/JNI the non_blocking worker never flushed and
/// mobile shipped a 0-byte log file on every boot, so every Android substrate
/// issue started blind. Synchronous writes cost microseconds per line and ALWAYS
/// land. Probes writability up front and says so loudly either way, so "where
/// are the rust logs" is answerable from stderr alone.
pub(crate) fn sync_file_layer<S>(
    dir: &std::path::Path,
) -> Option<
    tracing_subscriber::fmt::Layer<
        S,
        tracing_subscriber::fmt::format::DefaultFields,
        tracing_subscriber::fmt::format::Format,
        SyncDailyMakeWriter,
    >,
>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    use std::io::Write as _;
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!(
            "ciris-server: WARN could not create log dir {} ({e}) — file logging disabled",
            dir.display()
        );
        return None;
    }
    // Probe: prove the dir is actually writable HERE (Chaquopy sandboxes can
    // create-but-not-append) and stamp a boot marker so even a crash-before-
    // first-tracing-line leaves evidence in the file.
    let probe = dir.join("ciris-server.log.boot");
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&probe)
        .and_then(|mut f| {
            writeln!(f, "boot marker {}", chrono::Utc::now().to_rfc3339())?;
            f.flush()
        }) {
        Ok(()) => {}
        Err(e) => {
            eprintln!(
                "ciris-server: WARN log dir {} is not writable ({e}) — file logging disabled",
                dir.display()
            );
            return None;
        }
    }
    eprintln!(
        "ciris-server: logging to {}/ciris-server.log (per-event append writer)",
        dir.display()
    );
    Some(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(SyncDailyMakeWriter {
                dir: dir.to_path_buf(),
            }),
    )
}

/// Per-event append writer for the `<dir>/ciris-server.log.<utc-date>` sink
/// (CIRISServer#279 ask 1, part 2). The field showed the install-race fix alone
/// wasn't enough: with the layer LIVE (`file_layer_attached=true`) the write
/// itself still failed on Android (`first_write_ok=false`) — while the `.boot`
/// probe, a plain `OpenOptions::append` + `writeln`, always lands. So the sink
/// now uses EXACTLY that proven primitive: every event opens the dated file
/// append-mode, writes, and closes. No held FD across the Chaquopy lifecycle,
/// no roll state, no worker thread — daily rolling falls out of the filename.
/// Open cost is microseconds and the node's log volume is modest; correctness
/// on the fold beats throughput here. Filename matches the first-write probe
/// (both derive the date via chrono UTC).
struct SyncDailyMakeWriter {
    dir: std::path::PathBuf,
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SyncDailyMakeWriter {
    type Writer = Box<dyn std::io::Write>;
    fn make_writer(&'a self) -> Self::Writer {
        let dated = self.dir.join(format!(
            "ciris-server.log.{}",
            chrono::Utc::now().format("%Y-%m-%d")
        ));
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dated)
        {
            Ok(f) => Box::new(f),
            // Never panic the fmt layer: an unwritable event degrades to /dev/null
            // (the init-time probe + first_write_ok already report the condition).
            Err(_) => Box::new(std::io::sink()),
        }
    }
}

/// Result of a tracing init/reattach attempt — the host-visible verdict on
/// whether rust diagnostics will actually become bytes (CIRISServer#279 ask 1).
/// Surfaced to Python by `init_tracing` so the embedding agent can detect a
/// dark file sink at t=0 instead of discovering it via a t+60s sentinel.
#[derive(Debug, Clone)]
pub struct TracingInitStatus {
    /// This call installed the process's global subscriber (first-in wins).
    pub fresh_subscriber: bool,
    /// The `<log_dir>/ciris-server.log.<date>` file layer is LIVE — either
    /// installed fresh or retrofitted onto our existing subscriber.
    pub file_layer_attached: bool,
    /// Verdict of the first-write probe THROUGH the tracing pipeline: a marker
    /// event was emitted and the dated file verified non-empty. `None` when no
    /// `log_dir` was requested.
    pub first_write_ok: Option<bool>,
    /// The dated log file the probe checked, when a `log_dir` was requested.
    pub log_path: Option<String>,
}

/// The file sink slot, kept hot-swappable behind a `reload` handle so LATER
/// init calls can retrofit/replace the file layer on the live subscriber.
type ErasedFileLayer =
    Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>;
static FILE_RELOAD: std::sync::OnceLock<
    tracing_subscriber::reload::Handle<Option<ErasedFileLayer>, tracing_subscriber::Registry>,
> = std::sync::OnceLock::new();

/// Install the tracing subscriber, or RETROFIT the file sink onto the one this
/// process already installed (CIRISServer#279 ask 1 — the dark-sink fix).
///
/// The old path attached the file layer only if its `try_init()` was the FIRST
/// in the process, and `let _ =` swallowed the loss. On Android the agent's
/// early bare `init_tracing()` (no log_dir; CIRISAgent#919) — or a subscriber
/// surviving Chaquopy's process reuse across app relaunches — always won, so
/// the later `init_tracing(log_dir=…)` was a silent no-op: `sync_file_layer`
/// had already eagerly CREATED the dated file (tracing-appender opens at
/// construction), which then stayed 0 bytes forever — the exact field
/// signature. Compose ran with no observable byte channel.
///
/// Now the file sink lives behind a process-global `reload` handle: the first
/// call through here installs `reload(file) → filter → fmt` and stows the
/// handle; every later call `modify()`s the slot in place — bare-then-dir,
/// re-serve, and process-reuse all end with a LIVE file sink. Only a FOREIGN
/// subscriber (installed by something other than this fn) is unfixable, and
/// that is now REPORTED in the returned status instead of swallowed.
fn install_or_reattach_tracing(
    log_dir: Option<&std::path::Path>,
    filter: tracing_subscriber::EnvFilter,
) -> TracingInitStatus {
    use tracing_subscriber::{fmt, prelude::*};
    let build_file_layer = |dir: Option<&std::path::Path>| -> Option<ErasedFileLayer> {
        dir.and_then(|d| {
            sync_file_layer::<tracing_subscriber::Registry>(d)
                .map(|l| Box::new(l) as ErasedFileLayer)
        })
    };

    // Our subscriber already live → hot-swap the file slot (the reattach path).
    if let Some(handle) = FILE_RELOAD.get() {
        let layer = build_file_layer(log_dir);
        let built = layer.is_some();
        let attached = built && handle.modify(|slot| *slot = layer).is_ok();
        return probe_first_write(false, attached, log_dir);
    }

    let layer = build_file_layer(log_dir);
    let built = layer.is_some();
    let (reload_layer, handle) = tracing_subscriber::reload::Layer::new(layer);
    let fresh = tracing_subscriber::registry()
        // reload(file) sits closest to the Registry so the handle's type is
        // nameable; the EnvFilter above it still gates ALL layers globally.
        .with(reload_layer)
        .with(filter)
        .with(fmt::layer()) // stdout/console
        // CIRISServer#264 — MUST NOT panic when a subscriber is already set:
        // `.init()`'s panic crossed pyo3 as PanicException and killed
        // `serve_with_python_adapter` silently. try_init + explicit handling.
        .try_init()
        .is_ok();
    if fresh {
        let _ = FILE_RELOAD.set(handle);
        return probe_first_write(true, built, log_dir);
    }
    // Lost the install race. If OUR handle appeared meanwhile (two threads of
    // this fn racing), retrofit through it; otherwise a FOREIGN subscriber owns
    // the process and no file sink is attachable — say so, loudly and in the
    // returned status (#279: never swallow this again).
    if let Some(handle) = FILE_RELOAD.get() {
        let layer = build_file_layer(log_dir);
        let built = layer.is_some();
        let attached = built && handle.modify(|slot| *slot = layer).is_ok();
        return probe_first_write(false, attached, log_dir);
    }
    eprintln!(
        "ciris-server: a FOREIGN tracing subscriber is already installed — file sink \
         to <home>/logs NOT attachable (rust diagnostics may be dark) [#279]"
    );
    probe_first_write(false, false, log_dir)
}

/// Emit a marker event through the pipeline and verify the dated file grew —
/// the "one compose line = one-line RCA" guarantee, checked at init time.
fn probe_first_write(
    fresh: bool,
    attached: bool,
    log_dir: Option<&std::path::Path>,
) -> TracingInitStatus {
    let (first_write_ok, log_path) = match log_dir {
        None => (None, None),
        Some(dir) => {
            let dated = dir.join(format!(
                "ciris-server.log.{}",
                chrono::Utc::now().format("%Y-%m-%d")
            ));
            let path = dated.display().to_string();
            let ok = if attached {
                tracing::info!(
                    target: "ciris_server::boot",
                    fresh_subscriber = fresh,
                    "tracing file sink online (first-write probe) [#279]"
                );
                std::fs::metadata(&dated)
                    .map(|m| m.len() > 0)
                    .unwrap_or(false)
            } else {
                false
            };
            (Some(ok), Some(path))
        }
    };
    let status = TracingInitStatus {
        fresh_subscriber: fresh,
        file_layer_attached: attached,
        first_write_ok,
        log_path,
    };
    if log_dir.is_some() && status.first_write_ok != Some(true) {
        eprintln!(
            "ciris-server: WARN file sink verdict: attached={} first_write_ok={:?} — \
             rust file diagnostics are DARK this boot [#279]",
            status.file_layer_attached, status.first_write_ok
        );
    }
    status
}

pub fn init_tracing_with(log_dir: Option<&std::path::Path>) {
    let _ = init_tracing_with_status(log_dir);
}

/// [`init_tracing_with`] returning the [`TracingInitStatus`] verdict — the
/// entry the Python binding and tests use to assert the file sink is LIVE
/// (attached + first-write-verified) rather than trusting a silent init.
pub fn init_tracing_with_status(log_dir: Option<&std::path::Path>) -> TracingInitStatus {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    install_or_reattach_tracing(log_dir, filter)
}

/// Resolve the node log directory from CLI args: `<home>/logs`, where `home` is
/// the value of `--home <path>` / `--home=<path>` if present, else
/// [`config::DEFAULT_CIRIS_HOME`]. Used by every node serve entry so file logging
/// targets the same data root the node boots against.
pub fn log_dir_from_args(args: &[String]) -> std::path::PathBuf {
    let mut home: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--home" {
            home = it.next().cloned();
        } else if let Some(v) = a.strip_prefix("--home=") {
            home = Some(v.to_string());
        }
    }
    std::path::PathBuf::from(home.unwrap_or_else(|| config::DEFAULT_CIRIS_HOME.to_string()))
        .join("logs")
}

// ── `config set/get` console subcommand (shared by the binary AND the wheel) ──
// These live in the LIB (not `src/main.rs`) so the pip console-script — which
// enters through `python::py_main`, NOT the binary's `main()` — has the exact
// same `ciris-server config set/get` surface. Before this, `config` was only in
// the binary, so the published WHEEL/image `ciris-server` had no way to set
// boot-structural knobs (e.g. `net.announce_ownership`) on a headless node
// (CIRISServer mesh-seed blocker: Node A runs the wheel, couldn't self-configure).

/// `ciris-server config set <key> <json-value> [--home <path>] [--key-id <name>]
/// [--reason <text>]` — write a node-signed `config:*` object from the console.
/// JSON-first value parse (`'["a:1"]'`→List, `true`→Bool, `7`→I64), bare-string
/// fallback. Used by the headless/no-session path.
pub async fn run_config_set_cli(mut args: impl Iterator<Item = String>) -> anyhow::Result<()> {
    use anyhow::Context;
    let mut home: Option<String> = None;
    let mut key_id = config::DEFAULT_KEY_ID.to_string();
    let mut reason = "console-cli".to_string();
    let mut key: Option<String> = None;
    let mut value_raw: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--home" => home = Some(args.next().context("--home needs a path")?),
            "--key-id" => key_id = args.next().context("--key-id needs a name")?,
            "--reason" => reason = args.next().context("--reason needs a value")?,
            other if other.starts_with("--") => {
                return Err(anyhow::anyhow!("unknown config-set arg: {other}"))
            }
            positional => {
                if key.is_none() {
                    key = Some(positional.to_string());
                } else if value_raw.is_none() {
                    value_raw = Some(positional.to_string());
                } else {
                    return Err(anyhow::anyhow!(
                        "unexpected extra config-set arg: {positional}"
                    ));
                }
            }
        }
    }
    let key = key.context("config set requires <key> (e.g. net.announce_ownership)")?;
    let value_raw = value_raw
        .context("config set requires <json-value> (e.g. true or '[\"108.61.242.236:4242\"]')")?;
    let value = parse_config_value(&value_raw);
    let home = home.unwrap_or_else(|| config::DEFAULT_CIRIS_HOME.to_string());
    let cfg = config::ServerConfig::from_home(std::path::PathBuf::from(home), key_id)?;
    let entry = run_config_set(cfg, &key, value, &reason).await?;
    println!(
        "✅ config set {} (version {}, authored by {})",
        entry.key, entry.version, entry.updated_by
    );
    println!("{}", serde_json::to_string_pretty(&entry.value)?);
    Ok(())
}

/// `ciris-server config get <key> [--home <path>] [--key-id <name>]` — read the
/// latest-wins `config:*` value from the console.
pub async fn run_config_get_cli(mut args: impl Iterator<Item = String>) -> anyhow::Result<()> {
    use anyhow::Context;
    let mut home: Option<String> = None;
    let mut key_id = config::DEFAULT_KEY_ID.to_string();
    let mut key: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--home" => home = Some(args.next().context("--home needs a path")?),
            "--key-id" => key_id = args.next().context("--key-id needs a name")?,
            other if other.starts_with("--") => {
                return Err(anyhow::anyhow!("unknown config-get arg: {other}"))
            }
            positional => {
                if key.is_none() {
                    key = Some(positional.to_string());
                } else {
                    return Err(anyhow::anyhow!(
                        "unexpected extra config-get arg: {positional}"
                    ));
                }
            }
        }
    }
    let key = key.context("config get requires <key> (e.g. net.announce_ownership)")?;
    let home = home.unwrap_or_else(|| config::DEFAULT_CIRIS_HOME.to_string());
    let cfg = config::ServerConfig::from_home(std::path::PathBuf::from(home), key_id)?;
    match run_config_get(cfg, &key).await? {
        Some(entry) => println!("{}", serde_json::to_string_pretty(&entry.value)?),
        None => eprintln!("(no config for key {key:?})"),
    }
    Ok(())
}

/// Parse a `config set` value: JSON-first (so `'["a:1"]'`→List, `true`→Bool,
/// `7`→I64), with a bare-string fallback.
pub fn parse_config_value(raw: &str) -> ConfigValue {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(v) => serde_json::from_value::<ConfigValue>(v)
            .unwrap_or_else(|_| ConfigValue::Str(raw.to_string())),
        Err(_) => ConfigValue::Str(raw.to_string()),
    }
}

// ── PyO3 abi3 wheel surface (the shape CIRISAgent consumes) ──────────────────
// Gated behind the `python` feature so the binary never links libpython.
#[cfg(feature = "python")]
mod python {
    use pyo3::prelude::*;

    // ── Verify-FFI keep-alive (CIRISServer#232 / CIRISVerify#189) ────────────
    // We fold `ciris-verify-ffi` (rlib) into `_native.so` so the agent rides us
    // for verify and drops its standalone `ciris-verify` wheel. But NOTHING in
    // our Rust code calls the FFI's `#[no_mangle] extern "C"` fns (the agent
    // reaches them via `ctypes`/`dlopen` at runtime), so the linker's
    // `--gc-sections` would dead-strip all ~84 `ciris_verify_*` symbols out of
    // the final cdylib — per-platform-silently. Referencing the crate's
    // `ciris_verify_ffi_link_anchor()` from a `#[used]` static transitively pins
    // every FFI object file; the anchor takes the address of every export, which
    // the compiler cannot resolve without keeping the symbol. `verify_ffi_path()`
    // (python/ciris_server/__init__.py) resolves `_native`'s own path for the
    // agent's ctypes loader. A cross-platform `nm`/`dumpbin` CI smoke asserts the
    // surface is actually present in the built artifact (never trust cargo-green).
    #[used]
    static _KEEP_VERIFY_FFI: extern "C" fn() -> usize =
        ciris_verify_ffi::ciris_verify_ffi_link_anchor;

    /// Plain block_on for the CLI-shaped entries (`import-traces`, `config`,
    /// console serve) — always fresh processes with no ambient runtime, and
    /// their futures need not be `Send` (import_traces holds a `dyn io::Read`
    /// across awaits). The EMBEDDED entry uses [`rt_block_on_reentrant`].
    fn rt_block_on<F: std::future::Future<Output = anyhow::Result<()>>>(fut: F) -> PyResult<()> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        rt.block_on(fut)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    fn rt_block_on_reentrant<F>(fut: F) -> PyResult<()>
    where
        F: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        // ONE multi-thread runtime; the node spawns onto it (never a second
        // runtime around the Engine — the persist dual-runtime-deadlock rule).
        //
        // REENTRANCY-SAFE (CIRISServer#264 must-fix): on the agent-EMBEDDED
        // topology the calling thread can carry an ambient tokio context (live
        // asyncio + the reused `current_rust_engine()`'s runtime enters context
        // through pyo3 callbacks), and `Runtime::new()`/`block_on` there panics
        // `Cannot start a runtime from within a runtime` — the true root cause
        // of the entire configured-home fold saga (the panic crossed FFI as a
        // silent PanicException before 0.5.116's catch_unwind). When a handle
        // is current, HOP to a fresh OS thread: it has NO ambient context, so
        // the nested-runtime rule cannot fire — topology-independent by
        // construction, and the same shield covers every inner persist/lens
        // sync helper reached from this entry.
        let run = || -> PyResult<()> {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            rt.block_on(fut)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
        };
        if tokio::runtime::Handle::try_current().is_err() {
            return run();
        }
        eprintln!(
            "ciris-server: ambient tokio runtime detected on the calling thread — \
             hopping to a dedicated OS thread (embedded-fold reentrancy shield, #264)"
        );
        std::thread::Builder::new()
            .name("ciris-serve-rt".into())
            .spawn(run)
            .map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("spawn serve thread: {e}"))
            })?
            .join()
            .unwrap_or_else(|panic| {
                Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "serve thread panicked: {}{}",
                    panic_message(&panic),
                    last_panic_detail()
                )))
            })
    }

    /// Best-effort string from a panic payload.
    fn panic_message(p: &(dyn std::any::Any + Send)) -> String {
        p.downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_string())
    }

    /// CIRISServer#264 must-have 3 — a process-wide panic hook that CAPTURES the
    /// panic location + backtrace so the catch_unwind sites can attach file:line
    /// to the error a Python caller sees (RUST_BACKTRACE on the Python side
    /// yields zero rust frames otherwise; tonight's field diagnosis took four
    /// instrumented boots for want of one line). The hook also eprintln!s the
    /// full detail immediately — competent logging on every platform even when
    /// the exception path is swallowed upstream. Chains the previous hook.
    static PANIC_DETAIL: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
    static PANIC_HOOK_ONCE: std::sync::Once = std::sync::Once::new();

    fn install_panic_capture() {
        PANIC_HOOK_ONCE.call_once(|| {
            let prev = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                let loc = info
                    .location()
                    .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                    .unwrap_or_else(|| "<unknown location>".to_string());
                let bt = std::backtrace::Backtrace::force_capture();
                let detail = format!(" [at {loc}]\nbacktrace:\n{bt}");
                eprintln!("ciris-server PANIC{detail}");
                if let Ok(mut slot) = PANIC_DETAIL.lock() {
                    *slot = Some(detail);
                }
                prev(info);
            }));
        });
    }

    /// The last captured panic's `[at file:line]` + backtrace (consumed), or "".
    fn last_panic_detail() -> String {
        PANIC_DETAIL
            .lock()
            .ok()
            .and_then(|mut s| s.take())
            .unwrap_or_default()
    }

    /// Console entry point: `pip install ciris-server` → the `ciris-server`
    /// command (pyproject `[project.scripts]`). Mirrors the binary's CLI:
    /// `ciris-server import-traces <dump-dir>` runs the legacy-trace import;
    /// otherwise boots a zero-setup node (mode = server, trusts `ciris-canonical`).
    #[pyfunction]
    #[pyo3(name = "main")]
    fn py_main(py: Python<'_>) -> PyResult<()> {
        // Read PYTHON's `sys.argv`, NOT Rust's `std::env::args()`. Under the
        // pip console-script the OS process is `python <script-path> <args…>`, so
        // `std::env::args()` carries the interpreter + the script path as spurious
        // leading positionals — `skip(1)` drops only the interpreter, leaving the
        // script path to land as `unknown serve arg: /usr/local/bin/ciris-server`
        // (CIRISServer#32; every wheel invocation, incl. --help, crashed). Python
        // sets `sys.argv[0]` = the program and `sys.argv[1:]` = the real args, so
        // `skip(1)` here yields exactly the user args — matching the binary path.
        let argv: Vec<String> = py.import("sys")?.getattr("argv")?.extract()?;
        // File logging to <home>/logs (the node serve paths); resolved from argv so
        // it targets the same --home the node boots against.
        crate::init_tracing_with(Some(&crate::log_dir_from_args(&argv)));
        let mut args = argv.into_iter().skip(1);
        let first = args.next();
        match first.as_deref() {
            Some("import-traces") => {
                let dir = args.next().ok_or_else(|| {
                    pyo3::exceptions::PyRuntimeError::new_err(
                        "usage: ciris-server import-traces <dump-dir>",
                    )
                })?;
                rt_block_on(crate::import_traces(&dir))
            }
            // `ciris-server config set/get <key> [value] …` — node-signed
            // `config:*` write/read from the console. This arm MUST live here (not
            // just in the binary's `main()`) so the pip WHEEL/image `ciris-server`
            // can set boot-structural knobs (e.g. `net.announce_ownership`,
            // `net.bootstrap_peers`) on a headless node with no app/owner session.
            Some("config") => {
                let sub = args.next();
                match sub.as_deref() {
                    Some("set") => rt_block_on(crate::run_config_set_cli(args)),
                    Some("get") => rt_block_on(crate::run_config_get_cli(args)),
                    other => Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "usage: ciris-server config set <key> <json-value> [--home <path>] [--key-id <name>]\n\
                         \x20      ciris-server config get <key> [--home <path>] [--key-id <name>] (got {other:?})"
                    ))),
                }
            }
            // Default-serve path. `first` is the already-consumed first token (a
            // leading flag like `--home`/`--key-id`, or `None` for a bare boot).
            // Parse it the SAME way the binary does so the WHEEL honors the flags
            // — without this it fell through to run_default() and ignored
            // --home/--key-id, minting the bare "ciris-server" label (CIRISServer#27).
            _ => {
                let (home, key_id) = crate::parse_serve_flags(first, args)
                    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
                rt_block_on(crate::run(home, key_id))
            }
        }
    }

    /// `ciris_server.import_traces(dump_dir)` — programmatic legacy-trace import
    /// for a pip-only bridge (the CIRISLens TimescaleDB dump → persist corpus as
    /// CEG objects). Uses the baked-default home convention, same as the node.
    #[pyfunction]
    #[pyo3(name = "import_traces")]
    fn py_import_traces(dump_dir: String) -> PyResult<()> {
        crate::init_tracing_with(Some(
            &std::path::PathBuf::from(crate::config::DEFAULT_CIRIS_HOME).join("logs"),
        ));
        rt_block_on(crate::import_traces(&dump_dir))
    }

    /// Boot the node with a Python adapter folded in (CIRISServer#80) — the seam
    /// that lets a Python "brain" mount onto the node's router without
    /// re-composing the substrate. `adapter` is a duck-typed Python object (see
    /// [`crate::py_adapter`]); its declared `proxy_routes()` are reverse-proxied
    /// onto the node's read-API and its `start`/`stop` hooks fire around the
    /// lifecycle. `home`/`key_id` default to the bare-node values, matching the
    /// flagless boot.
    #[pyfunction]
    #[pyo3(name = "serve_with_python_adapter", signature = (adapter, home=None, key_id=None))]
    fn py_serve_with_python_adapter(
        py: Python<'_>,
        adapter: Py<pyo3::PyAny>,
        home: Option<String>,
        key_id: Option<String>,
    ) -> PyResult<()> {
        let home = home
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(crate::config::DEFAULT_CIRIS_HOME));
        // FIRST BREATH (CIRISServer#264 ask 1) — emitted via eprintln (NOT tracing:
        // the subscriber may not exist yet, or belong to the host) BEFORE any call
        // that can block or die, so a field hang is attributable to a phase instead
        // of reading as silence. Tonight's four instrumented boots = this one line.
        install_panic_capture();
        eprintln!(
            "ciris-server: serve_with_python_adapter entered (home={}) — init tracing → adapter \
             config → ServerConfig::from_home → compose",
            home.display()
        );
        crate::init_tracing_with(Some(&home.join("logs")));
        // Read the Python adapter's static config under the GIL.
        let adapter = crate::py_adapter::build(py, adapter)?;
        let key_id = key_id.unwrap_or_else(|| crate::config::DEFAULT_KEY_ID.to_string());
        let cfg = crate::config::ServerConfig::from_home(home, key_id)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        tracing::info!(
            key_id = %cfg.key_id,
            "serve_with_python_adapter: config resolved — entering the blocking serve \
             (next log lines come from compose)"
        );
        // Release the GIL while the (blocking) server runs so the adapter's
        // start/stop hooks can re-acquire it on their blocking threads.
        // catch_unwind (#264): a rust panic here crosses pyo3 as PanicException —
        // a BaseException the agent fold's `except Exception` does NOT catch, so
        // the fold thread dies silently and 4243 never binds with zero log output.
        // Convert to a normal RuntimeError the fold catches + logs as node_error.
        py.detach(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                rt_block_on_reentrant(crate::serve_with_adapter(cfg, adapter))
            }))
            .unwrap_or_else(|p| {
                // #264 must-have 3: the hook captured location + backtrace —
                // attach it so the Python-side error names file:line.
                Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "serve_with_python_adapter panicked: {}{}",
                    panic_message(&p),
                    last_panic_detail()
                )))
            })
        })
    }

    /// `ciris_server.start_federation_delivery(cadence_seconds=None,
    /// announce_logger=True)` — CIRISServer#205 (subsuming #204). The ONE entry a
    /// bare AGENT calls AFTER its embedded edge is up (`init_edge_runtime`) so the
    /// edge actually DELIVERS its CEG traces to the canonical mesh.
    ///
    /// It drives the SAME delivery machinery ciris-server's compose node runs, but
    /// against the in-process embedded handles rather than a freshly-composed node:
    /// grabs `current_rust_engine()` + `current_edge()`, seeds the baked canonical
    /// key_ids as replication targets (reading their transport hints — subsumes
    /// #204), authors this node's `consent:replication` grant at the canonical
    /// peer, starts the `ReplicationRuntime` + the reconcile loop, and subscribes
    /// the announce logger. Returns the number of admitted canonical targets
    /// seeded. Idempotent per process (a second call is a no-op).
    ///
    /// The controller + its driving runtime are held in a process static, so the
    /// caller need not retain the return value for delivery to keep running.
    /// A clear Python error is raised if the engine or edge is not yet initialized,
    /// or the embedded edge carries no Reticulum transport.
    /// Initialize the rust tracing subscriber inside a Python-embedded process
    /// (stdout, `RUST_LOG`-filtered) — the same `init_tracing` the binary paths
    /// use. Without this a Python host (e.g. the harness `agent_boot.py`) sees
    /// NO rust-side logs at all. Idempotent (`try_init` inside — a second call
    /// is a no-op).
    /// `log_dir` (CIRISServer#264 ask 5): also attach the `<log_dir>/ciris-server.log`
    /// daily file sink — the ONE subscriber a Python host installs should carry the
    /// file layer, because a later `serve_with_python_adapter` cannot retrofit it
    /// onto an existing subscriber (its `init_tracing_with` falls through, #264).
    /// `filter` overrides the env filter (e.g. `"info,ciris_edge=debug"`) — on
    /// Android the host env whitelist can drop `RUST_LOG` before this runs, so an
    /// explicit arg beats the env round-trip. Both optional; bare call unchanged.
    #[pyfunction]
    #[pyo3(name = "init_tracing", signature = (log_dir=None, filter=None))]
    fn py_init_tracing(
        py: Python<'_>,
        log_dir: Option<String>,
        filter: Option<String>,
    ) -> PyResult<pyo3::Py<pyo3::types::PyDict>> {
        use tracing_subscriber::EnvFilter;
        let filter = filter
            .map(EnvFilter::new)
            .or_else(|| EnvFilter::try_from_default_env().ok())
            .unwrap_or_else(|| EnvFilter::new("info"));
        install_panic_capture();
        // #279 ask 1: route through the reload-handle installer, so a LATER call
        // with a log_dir retrofits the file sink onto the live subscriber (the
        // old try_init lost that race silently — the 0-byte dated log on every
        // Android boot). Return the verdict so the host detects a dark sink at
        // t=0: {"fresh_subscriber", "file_layer_attached", "first_write_ok",
        // "log_path"}. Existing callers that ignore the return are unchanged.
        let status = crate::install_or_reattach_tracing(
            log_dir.map(std::path::PathBuf::from).as_deref(),
            filter,
        );
        let d = pyo3::types::PyDict::new(py);
        d.set_item("fresh_subscriber", status.fresh_subscriber)?;
        d.set_item("file_layer_attached", status.file_layer_attached)?;
        d.set_item("first_write_ok", status.first_write_ok)?;
        d.set_item("log_path", status.log_path)?;
        Ok(d.into())
    }

    #[pyfunction]
    #[pyo3(name = "start_federation_delivery", signature = (cadence_seconds=None, announce_logger=true))]
    fn py_start_federation_delivery(
        py: Python<'_>,
        cadence_seconds: Option<u64>,
        announce_logger: bool,
    ) -> PyResult<u64> {
        // Release the GIL: the controller bring-up awaits async engine/edge I/O on
        // its own runtime and the spawned scheduler tasks run detached afterwards.
        let count = py.detach(|| {
            crate::federation_delivery::start_and_hold(cadence_seconds, announce_logger)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
        })?;
        Ok(count as u64)
    }

    /// `ciris_server.reprime_federation_delivery(cadence_seconds=None,
    /// announce_logger=True)` — re-drive the canonical delivery prime on a
    /// post-restart re-serve (CIRISServer#288). Unlike `start_federation_delivery`
    /// (which no-ops once started), this re-roots canonical as a KEX'd delivery
    /// peer against the CURRENT embedded handles on the held runtime, so the
    /// mobile fold's in-process restart re-establishes `peer_count_canonical`
    /// instead of leaving the sealed trace with no peer to sail to. Idempotent;
    /// safe every restart. Returns the re-seeded canonical target count.
    #[pyfunction]
    #[pyo3(name = "reprime_federation_delivery", signature = (cadence_seconds=None, announce_logger=true))]
    fn py_reprime_federation_delivery(
        py: Python<'_>,
        cadence_seconds: Option<u64>,
        announce_logger: bool,
    ) -> PyResult<u64> {
        let count = py.detach(|| {
            crate::federation_delivery::reprime_and_hold(cadence_seconds, announce_logger)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
        })?;
        Ok(count as u64)
    }

    /// `ciris_server.delivery_status()` (CIRISServer#294) — a one-shot JSON
    /// snapshot of federation-delivery state so "why isn't the trace sailing for
    /// peer X?" is one query, not log archaeology: `{delivery_started, edge_up,
    /// node_key_id, transport_present, canonical_targets, peers:[{key_id,
    /// knows_peer, kex_present, deliverable}]}`. `knows_peer=false` ⇒ never primed;
    /// `deliverable=true` but no delivery ⇒ driver-layer frame loss (grep the log
    /// for the edge FramesDropped WARN, leviculum#25). In-process only, never over
    /// the wire; GIL released.
    #[pyfunction]
    #[pyo3(name = "delivery_status")]
    fn py_delivery_status(py: Python<'_>) -> String {
        py.detach(crate::federation_delivery::delivery_status_json)
    }

    /// In-process accessor for the first-run ownership claim PIN (CIRISServer#277).
    ///
    /// On the agent-embedded (fold) topology the embedding process IS the console:
    /// it launched the node in-process via `serve_with_python_adapter`, so it is
    /// the party the console-only claim PIN is minted for. But on Android the
    /// banner may never become observable bytes (0-byte rust file sink at compose;
    /// nothing in logcat or `<home>/logs/*`), so log-scrape capture is unreliable.
    /// `compose` stashes the PIN in memory the instant it is minted; this returns
    /// it directly — deterministic capture with no wire exposure.
    ///
    /// Returns the PIN string on a fresh, UNCLAIMED first-run, or `None` once the
    /// node has a ROOT owner (no PIN minted) — or if called before compose has
    /// minted it (the host should poll). Non-consuming: safe to call repeatedly
    /// and to retry the claim; the value lives only for this process.
    #[pyfunction]
    #[pyo3(name = "first_run_claim_pin")]
    fn py_first_run_claim_pin() -> Option<String> {
        crate::auth::bootstrap::first_run_claim_pin()
    }

    /// In-process compose-progress snapshot (CIRISServer#279). Returns a JSON
    /// string: `{"completed": bool, "current": {"phase", "elapsed_s", "stuck",
    /// "stuck_warnings"} | null, "history": [{"phase", "ms"}, ...]}`.
    ///
    /// On the embedded fold every byte-channel diagnostic can be dark (0-byte
    /// tracing file sink at compose; rust `eprintln!` dropped under Chaquopy),
    /// so when compose hangs — serve thread alive, 4243 never binds, no panic —
    /// the host polls THIS: `current.phase` names the exact seam the boot is
    /// wedged in, and `stuck` flips true after the watchdog threshold. Cheap,
    /// callable from any thread, at any time (null `current` before serve).
    #[pyfunction]
    #[pyo3(name = "compose_status")]
    fn py_compose_status() -> String {
        crate::compose_status::snapshot_json()
    }

    /// `ciris_server.shutdown_node(timeout_secs=30.0)` — stop the node started by
    /// `serve_with_python_adapter` and DON'T return until `:4243` is bindable
    /// again (CIRISServer#276). The embedded fold's clean-restart primitive:
    /// detect the port held → `shutdown_node()` → re-serve, mirroring the agent's
    /// own `:8080` local-shutdown-and-wait. Returns `True` once the port is free
    /// (or immediately if no node is serving — idempotent), `False` on timeout.
    /// Blocks with the GIL released; safe to call from the agent's Python thread.
    #[pyfunction]
    #[pyo3(name = "shutdown_node", signature = (timeout_secs=30.0))]
    fn py_shutdown_node(py: Python<'_>, timeout_secs: f64) -> bool {
        let timeout = std::time::Duration::from_secs_f64(timeout_secs.max(0.0));
        py.detach(|| crate::node_control::shutdown_node_blocking(timeout))
    }

    // ── Substrate re-export (the one-wheel surface, CIRISServer#4) ───────────
    // The agent consumes the substrate as the SINGLE `ciris-server` wheel and
    // drops its standalone ciris_persist / ciris_edge wheels. Re-hosting the
    // substrate `#[pyclass]`es into THIS module means one `.so` = one PyO3 type
    // registry: the persist `Engine` PyObject the agent hands to edge's
    // `init_edge_runtime` is the SAME registered type both crates see, so the
    // CIRISPersist#109 cross-wheel type-identity bug class cannot occur.
    //
    // MECHANISM NOTE (load-bearing — see FSD/ONE_WHEEL_REEXPORT.md): each substrate
    // crate exposes a `pub fn register(m)` (the lens-core pattern) that its own
    // standalone `#[pymodule]` delegates to. We call the SAME `register` here, so
    // THIS module re-hosts the crate's FULL PyO3 surface — pyclasses, exception
    // types, AND the free `#[pyfunction]`s — into one `.so` / one type registry.
    // Both hooks now ship in our pinned substrate: persist v10 (CIRISPersist#231)
    // exposes `reset_engine`; edge v7.0.2 (CIRISEdge#199, restoring the v4.3.1 hook
    // that regressed in the v7.x line) exposes `init_edge_runtime`. So the agent
    // re-hosts the FULL persist+edge surface from the single `ciris-server` wheel
    // and can drop its standalone `ciris_persist` / `ciris_edge` wheels.

    /// Re-host persist's FULL PyO3 surface via its `pub fn register` (persist v10,
    /// CIRISPersist#231): the `Engine` pyclass, the typed exception hierarchy, and
    /// the free `reset_engine`. Covers `from ciris_server import Engine, NotFound,
    /// reset_engine` and the rest of the agent's persist import sites.
    fn register_persist(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
        ciris_persist::ffi::pyo3::register(py, m)
    }

    /// Re-host edge's FULL PyO3 surface via its `pub fn register` (edge v7.0.2,
    /// CIRISEdge#199): the `Edge` handle, the session/conformance pyclasses, and
    /// the free `init_edge_runtime` constructor. The agent can now mint an `Edge`
    /// from this one wheel — the federated boot no longer needs `ciris_edge`.
    /// (edge's `register` takes only the module; `_py` is unused but kept to match
    /// the `add_child_module` build-closure signature.)
    fn register_edge(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
        ciris_edge::ffi::pyo3::register(m)
    }

    /// Add a child module to `ciris_server` AND register it in `sys.modules` as
    /// `ciris_server.<name>` so `from ciris_server.<name> import X` resolves
    /// (PyO3 submodules aren't auto-importable without the sys.modules entry).
    fn add_child_module(
        py: Python<'_>,
        parent: &Bound<'_, PyModule>,
        name: &str,
        build: impl FnOnce(Python<'_>, &Bound<'_, PyModule>) -> PyResult<()>,
    ) -> PyResult<()> {
        let child = PyModule::new(py, name)?;
        build(py, &child)?;
        parent.add_submodule(&child)?;
        py.import("sys")?
            .getattr("modules")?
            .set_item(format!("ciris_server.{name}"), &child)?;
        Ok(())
    }

    /// The compiled abi3 extension. Built by maturin as the in-package submodule
    /// `ciris_server._native` (`module-name = "ciris_server._native"`), so the
    /// init symbol is `PyInit__native` and the fn is named `_native`. The
    /// hand-written `python/ciris_server/__init__.py` does `from ._native import *`,
    /// so `import ciris_server` still exposes this whole surface — `main`,
    /// `import_traces`, the re-hosted persist/lens pyclasses (`Engine`,
    /// `LensClient`, …) and the `ciris_server.persist` / `ciris_server.edge`
    /// submodules registered below. The composition CIRISAgent embeds is
    /// unchanged at the import sites; only the .so's in-wheel location moved.
    #[pymodule]
    fn _native(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
        // Belt-and-suspenders alongside the `#[used]` static: a live reference to
        // the verify-FFI anchor at init, so the fold survives even a linker that
        // ignores `#[used]` on statics (CIRISServer#232). Cheap XOR-fold; discarded.
        let _ = std::hint::black_box(ciris_verify_ffi::ciris_verify_ffi_link_anchor());
        m.add_function(wrap_pyfunction!(py_main, m)?)?;
        m.add_function(wrap_pyfunction!(py_import_traces, m)?)?;
        m.add_function(wrap_pyfunction!(py_serve_with_python_adapter, m)?)?;
        m.add_function(wrap_pyfunction!(py_start_federation_delivery, m)?)?;
        m.add_function(wrap_pyfunction!(py_reprime_federation_delivery, m)?)?;
        m.add_function(wrap_pyfunction!(py_delivery_status, m)?)?;
        m.add_function(wrap_pyfunction!(py_init_tracing, m)?)?;
        m.add_function(wrap_pyfunction!(py_first_run_claim_pin, m)?)?;
        m.add_function(wrap_pyfunction!(py_compose_status, m)?)?;
        m.add_function(wrap_pyfunction!(py_shutdown_node, m)?)?;
        // Re-export lens-core's Python surface so CIRISAgent can swap
        // `from ciris_lens_core import LensClient` → `from ciris_server import
        // LensClient` (drop-in). One wheel bundles the lens slice; registry +
        // node join the same `register` call as they fold in.
        ciris_lens_core::ffi::pyo3::register(m)?;

        // Substrate submodules: `ciris_server.persist` / `ciris_server.edge`.
        add_child_module(py, m, "persist", register_persist)?;
        add_child_module(py, m, "edge", register_edge)?;
        // Top-level aliases matching the agent's flat persist imports
        // (`from ciris_persist import Engine, NotFound` → `from ciris_server
        // import Engine, NotFound`). One registration, shared type identity.
        register_persist(py, m)?;
        // `Edge` at top level too (the agent reaches it as `ciris_edge.Edge`).
        register_edge(py, m)?;

        // The NodeCode fabric UX handle (CEG §0.10) is realized: the codec lives
        // in `crate::nodecode` and the node's own code is served (unauthenticated)
        // at `GET /v1/federation/node-code` (`crate::federation_nodecode`). The
        // remaining UX handles (trust/consent toggles, membership) fold into the
        // wheel API the KMP client consumes as their slices land (MISSION §3.4).
        Ok(())
    }
}
