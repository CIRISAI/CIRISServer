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
mod compose;
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
/// Owner-directed federation operations (the keystone for on-demand
/// `consent:replication` peering): `GET /v1/federation/self-key-record` +
/// `POST /v1/federation/peering`. Each node authors its OWN consent grant
/// (owner-authority model). Public so the integration test
/// (`tests/federation_admin.rs`) can drive the router directly.
pub mod federation_admin;
/// THIS node's own NodeCode (the QR-able federation-key bootstrap handle, CEG
/// §0.10): `GET /v1/federation/node-code` — the PUBLIC bootstrap code an operator
/// reads off the node and hands to a founder's app. Public so the integration
/// test (`tests/nodecode.rs`) can drive the router directly.
pub mod federation_nodecode;
/// **Config-as-CEG** (Server 0.5 Phase 1) — a signed, owner-gated GraphConfig
/// service over the CEG, mirroring CIRISAgent's `GraphConfigService` but
/// hybrid-signed + owner-gated. Config entries are self-attested `config:v1`
/// `scores` rows (latest-wins by version). Public so the integration test
/// (`tests/graph_config.rs`) can drive the store directly.
pub mod graph_config;
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
/// The `ciris-canonical` founder-quorum (steward-key replacement) — shared with
/// the registry slice at Server 0.5 (CIRISServer#1; FSD/REGISTRY_FOLD_DERISK.md).
pub mod quorum;
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

/// Initialize tracing (shared by the binary and the wheel entry point).
pub fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer())
        .init();
}

// ── PyO3 abi3 wheel surface (the shape CIRISAgent consumes) ──────────────────
// Gated behind the `python` feature so the binary never links libpython.
#[cfg(feature = "python")]
mod python {
    use pyo3::prelude::*;

    fn rt_block_on<F: std::future::Future<Output = anyhow::Result<()>>>(fut: F) -> PyResult<()> {
        // ONE multi-thread runtime; the node spawns onto it (never a second
        // runtime around the Engine — the persist dual-runtime-deadlock rule).
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        rt.block_on(fut)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    /// Console entry point: `pip install ciris-server` → the `ciris-server`
    /// command (pyproject `[project.scripts]`). Mirrors the binary's CLI:
    /// `ciris-server import-traces <dump-dir>` runs the legacy-trace import;
    /// otherwise boots a zero-setup node (mode = server, trusts `ciris-canonical`).
    #[pyfunction]
    #[pyo3(name = "main")]
    fn py_main(py: Python<'_>) -> PyResult<()> {
        crate::init_tracing();
        // Read PYTHON's `sys.argv`, NOT Rust's `std::env::args()`. Under the
        // pip console-script the OS process is `python <script-path> <args…>`, so
        // `std::env::args()` carries the interpreter + the script path as spurious
        // leading positionals — `skip(1)` drops only the interpreter, leaving the
        // script path to land as `unknown serve arg: /usr/local/bin/ciris-server`
        // (CIRISServer#32; every wheel invocation, incl. --help, crashed). Python
        // sets `sys.argv[0]` = the program and `sys.argv[1:]` = the real args, so
        // `skip(1)` here yields exactly the user args — matching the binary path.
        let argv: Vec<String> = py.import("sys")?.getattr("argv")?.extract()?;
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
        crate::init_tracing();
        rt_block_on(crate::import_traces(&dump_dir))
    }

    // ── Substrate re-export (the one-wheel surface, CIRISServer#4) ───────────
    // The agent consumes the substrate as the SINGLE `ciris-server` wheel and
    // drops its standalone ciris_persist / ciris_edge wheels. Re-hosting the
    // substrate `#[pyclass]`es into THIS module means one `.so` = one PyO3 type
    // registry: the persist `Engine` PyObject the agent hands to edge's
    // `init_edge_runtime` is the SAME registered type both crates see, so the
    // CIRISPersist#109 cross-wheel type-identity bug class cannot occur.
    //
    // MECHANISM NOTE (load-bearing — see FSD/ONE_WHEEL_REEXPORT.md): persist and
    // edge expose ONLY their macro-generated `#[pymodule]` init fns, which are
    // PRIVATE (`fn ciris_persist`, `fn ciris_edge` — no `pub`). The PyO3 0.29
    // `#[pymodule]`/`#[pyfunction]` macros emit their `_PYO3_DEF` glue with the
    // item's own visibility, so `wrap_pymodule!`/`wrap_pyfunction!` cannot reach
    // them from this crate. We therefore re-register the PUB-reachable surface
    // directly: the `#[pyclass]`es (`pub struct PyEngine`/`PyEdge`/…) and
    // persist's `pub use`d exception types. The free `#[pyfunction]`s the agent
    // needs — persist `reset_engine`, edge `init_edge_runtime` — are PRIVATE and
    // CANNOT be re-hosted from here; they require an upstream `pub fn register`
    // (the lens-core pattern). Tracked as the two upstream asks in the FSD.

    /// Re-host persist's pub `#[pyclass]`es + exception types onto a host module.
    /// Covers `from ciris_server import Engine, NotFound` (the agent's persist
    /// import sites). Does NOT cover `reset_engine` (private upstream fn — needs
    /// `CIRISPersist: pub fn register`).
    fn register_persist(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
        use ciris_persist::ffi::pyo3 as persist_pyo3;
        m.add_class::<persist_pyo3::PyEngine>()?; // exposed to Python as `Engine`
                                                  // Typed exception hierarchy (`from ciris_persist import NotFound, …`).
        m.add("PersistError", py.get_type::<persist_pyo3::PersistError>())?;
        m.add("NotFound", py.get_type::<persist_pyo3::NotFound>())?;
        m.add("Conflict", py.get_type::<persist_pyo3::Conflict>())?;
        m.add("Transient", py.get_type::<persist_pyo3::Transient>())?;
        m.add("Permanent", py.get_type::<persist_pyo3::Permanent>())?;
        m.add(
            "EngineConfigMismatch",
            py.get_type::<persist_pyo3::EngineConfigMismatch>(),
        )?;
        m.add("EngineClosed", py.get_type::<persist_pyo3::EngineClosed>())?;
        m.add(
            "EngineUsedAcrossFork",
            py.get_type::<persist_pyo3::EngineUsedAcrossFork>(),
        )?;
        m.add(
            "LensQueryError",
            py.get_type::<persist_pyo3::LensQueryError>(),
        )?;
        Ok(())
    }

    /// Re-host edge's pub `#[pyclass]`es onto a host module. Covers the `Edge`
    /// handle + the conformance/session pyclasses. Does NOT cover the free
    /// `init_edge_runtime` constructor (private upstream fn — needs
    /// `CIRISEdge: pub fn register`); without it the agent cannot actually mint
    /// an `Edge` from this wheel, so edge re-export is INCOMPLETE until upstream.
    fn register_edge(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
        use ciris_edge::ffi::pyo3 as edge_pyo3;
        m.add_class::<edge_pyo3::PyEdge>()?; // exposed to Python as `Edge`
        m.add_class::<edge_pyo3::PyDurableHandle>()?;
        m.add_class::<edge_pyo3::PySubscriptionHandle>()?;
        m.add_class::<edge_pyo3::PyVerifiedFeedSubscription>()?;
        m.add_class::<edge_pyo3::PyNetworkEventSubscription>()?;
        m.add_class::<edge_pyo3::PyReplicationHandle>()?;
        m.add_class::<edge_pyo3::PyAvSession>()?;
        m.add_class::<edge_pyo3::PyRelayNode>()?;
        Ok(())
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

    /// `import ciris_server` — the composition CIRISAgent embeds.
    #[pymodule]
    fn ciris_server(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(py_main, m)?)?;
        m.add_function(wrap_pyfunction!(py_import_traces, m)?)?;
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
