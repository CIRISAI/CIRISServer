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

mod compose;
mod config;

pub use config::{Mode, ServerConfig, Slices};

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

    /// Console entry point: `pip install ciris-server` → the `ciris-server`
    /// command (pyproject `[project.scripts]`). Boots a node with zero-setup
    /// defaults — mode = server, trusting `ciris-canonical` — no wizard.
    #[pyfunction]
    #[pyo3(name = "main")]
    fn py_main() -> PyResult<()> {
        crate::init_tracing();
        // ONE multi-thread runtime; the lens node spawns onto it (never a second
        // runtime around the Engine — the persist dual-runtime-deadlock rule).
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        rt.block_on(crate::run())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    /// `import ciris_server` — the composition CIRISAgent embeds.
    #[pymodule]
    fn ciris_server(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(py_main, m)?)?;
        // TODO: expose the fabric UX handles (trust/consent toggles, NodeCode,
        // membership) as the wheel API the KMP client consumes (MISSION §3.4).
        Ok(())
    }
}
