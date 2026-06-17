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
mod compose;
mod config;
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
mod import;
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
/// The capacity score→emit pipeline — a periodic task that derives per-agent
/// N_eff from ingested traces and emits federation-tier `capacity:*` attestations
/// (CIRISServer federation Round 1, deliverable 2). Public so the integration
/// test (`tests/capacity_scorer.rs`) can drive a single deterministic pass.
pub mod scorer;

pub use config::{Mode, PeerB, ServerConfig, Slices};

use anyhow::Result;

/// Run the fabric node: load zero-setup config, compose the active slices, serve.
pub async fn run() -> Result<()> {
    let cfg = ServerConfig::from_env()?;
    tracing::info!(
        mode = ?cfg.mode,
        data_dir = %cfg.data_dir.display(),
        listen = %cfg.listen_addr,
        "CIRISServer (the fabric node) starting — lens-only (0.1)"
    );
    compose::serve(cfg).await
}

/// Import the legacy CIRISLens TimescaleDB trace dump into the persist corpus as
/// CEG objects (the `import-traces <dump-dir>` subcommand). See `src/import.rs`.
pub async fn import_traces(dump_dir: &str) -> Result<()> {
    import::run(dump_dir).await
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
    fn py_main() -> PyResult<()> {
        crate::init_tracing();
        let mut args = std::env::args().skip(1);
        match args.next().as_deref() {
            Some("import-traces") => {
                let dir = args.next().ok_or_else(|| {
                    pyo3::exceptions::PyRuntimeError::new_err(
                        "usage: ciris-server import-traces <dump-dir>",
                    )
                })?;
                rt_block_on(crate::import_traces(&dir))
            }
            _ => rt_block_on(crate::run()),
        }
    }

    /// `ciris_server.import_traces(dump_dir)` — programmatic legacy-trace import
    /// for a pip-only bridge (the CIRISLens TimescaleDB dump → persist corpus as
    /// CEG objects). Reads `CIRIS_HOME`/DSN from the environment, same as the node.
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
