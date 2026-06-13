//! CIRISServer — the fabric node composition library.
//!
//! The federation's headless cohabitation runtime: `ciris-registry-core`
//! (authority) + `ciris-lens-core` (observation) [+ `ciris-node-core` at
//! Server 1.0] composed over **one shared persist `Engine`**. `agent = fabric
//! node + brain`; this is that composition with the brain removed.
//!
//! ONE composition, TWO shapes (MISSION.md §1.2/§6):
//!   - this crate as a **PyO3 abi3 wheel** (`crate-type = cdylib`, `python`
//!     feature) that CIRISAgent — pure Python — pip-installs and links instead
//!     of composing the cores itself;
//!   - this crate as an **rlib** linked by the `ciris-server` binary
//!     (src/main.rs) for the headless deployment.
//!
//! It authors no primitives and holds no ethical agency (MISSION.md §1.3): it
//! attests, stores, observes, reaches consensus, and transports — it does not
//! reason, decide, or act. The load-bearing invariant is separation of powers
//! held cryptographically (MISSION.md §1.5 ⇒ **CEG §7.0.1** fabric-node
//! discipline): authority is quorum-bound, observation is non-authoritative by
//! namespace, even though both share this process.
//!
//! STATUS: Spec — this is a skeleton. The composition cannot be wired until:
//!   1. **CIRISEdge tags v3.0.0** (the family-lockstep work: persist 6.0.1 +
//!      pyo3 0.29). Until then persist 6.x and edge cannot co-resolve.
//!   2. **registry-core + lens-core co-bump** to the 6.x/edge-3.0 floor.
//!   3. Two adapter gaps land — a registry-core `compose()` entrypoint with an
//!      injectable edge identity, and a Rust-native edge shared-singleton
//!      acquisition API (today `init_edge_runtime` is PyO3-only).
//! The `todo!()` sites below mark exactly where that wiring goes. See
//! MISSION.md §4/§5 and the tracked downstream issues.

use anyhow::Result;

/// Run the fabric node: compose the cores over one shared substrate and serve.
///
/// Boot order (MISSION.md §2; corrected to the v6.0.1 / edge-3.0 substrate).
/// The composition root owns the singleton; no core constructs its own Engine.
pub async fn run() -> Result<()> {
    tracing::info!(
        "CIRISServer (the fabric node) — Spec skeleton; boot blocked on \
         CIRISEdge v3.0.0 tag + registry/lens co-bump to the 6.x floor + the \
         compose()/Rust-edge-singleton adapters. See MISSION.md §4."
    );

    // 1. ONE shared persist Engine — the durable corpus + federation directory.
    //    `Engine::with_signer(signer, &dsn)` builds AND runs migrations; DSN is
    //    URL-sniffed (postgresql:// | sqlite://... | sqlite::memory:). The two
    //    slices then read/write the SAME substrate via cheap per-slice views:
    //      let registry_engine = Engine::from_shared(engine.backend().clone(),
    //                                                 engine.signer().clone());
    //      let lens_engine     = Engine::from_shared(engine.backend().clone(),
    //                                                 engine.signer().clone());
    //    (DSN from CIRIS_SERVER_PERSIST_DSN; sqlite::memory: for dev.)
    // let engine = build_shared_persist_engine().await?;

    // 2. ONE edge runtime — CEG/RET transport + the node's SINGLE Reticulum
    //    transport identity, with cross-process leader election over the shared
    //    backend (persist `SharedInstanceLease::try_acquire_shared_instance`,
    //    role="auto"). NOTE: edge's `init_edge_runtime` is currently a PyO3
    //    #[pyfunction]; a pure-Rust fabric node needs a Rust-native path
    //    (tracked downstream). This is NOT a separate "federation identity" —
    //    that is `Engine::local_identity_aggregate(x25519_b64, ed25519_b64)`.
    // let edge = acquire_edge_runtime(&engine).await?;   // BLOCKED: edge Rust API

    // 3. Compose each core over the shared singletons (node-core at Server 1.0).
    //    Observation (READY today): the proven cohabitation entry point —
    //      ciris_lens_core::LensCore::attach_handler(&edge, registry_engine)?;
    //    Authority (BLOCKED): registry-core has no compose() yet; its boot is
    //    hand-rolled in its bin's main.rs and its edge identity is not
    //    injectable. Target shape:
    //      ciris_registry_core::compose(&engine, &edge, &settings)?;

    // 4. Expose the unified surface: registry gRPC/HTTP (which already mounts
    //    `/v1/identity` → the §5.6.8.8.2 six-key LocalIdentityAggregate, the
    //    federation ID by which `ciris-canonical` enrolls this node) + the lens
    //    read surface (the 7 frozen GET /lens/api/v1/* endpoints).

    let _ = build_shared_persist_engine;
    let _ = acquire_edge_runtime;
    todo!(
        "Wire the composition once CIRISEdge v3.0.0 tags, registry/lens co-bump \
         to the 6.x floor, and the compose()/Rust-edge-singleton adapters land. \
         See MISSION.md §4."
    );
}

/// 1. Construct the one shared persist `Engine` both slices read/write.
async fn build_shared_persist_engine() -> Result<()> {
    // ciris_persist::engine::Engine::with_signer(signer, &dsn).await — builds +
    // migrates once; derive per-slice views with Engine::from_shared so the
    // authority view and the observation view never diverge (MISSION.md §2).
    todo!("shared persist Engine — Engine::with_signer + from_shared views")
}

/// 2. Acquire the one shared edge runtime (one Reticulum transport identity).
///    BLOCKED: edge's shared-singleton acquisition is PyO3-only; needs a
///    Rust-native API (downstream issue on CIRISEdge).
async fn acquire_edge_runtime() -> Result<()> {
    // The node holds ONE Reticulum transport identity, surfaced by both slices;
    // leader election rides persist's SharedInstanceLease over the shared
    // backend. Replaces the retired shared-vaulted registry steward key; this
    // node's key becomes its founder share of the ciris-canonical quorum.
    todo!("shared edge runtime — blocked on a Rust-native edge acquisition API")
}

/// Initialize tracing (shared by the binary and any embedding host).
pub fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer())
        .init();
}

// ── PyO3 abi3 wheel surface (the shape CIRISAgent consumes) ──────────────────
// Gated behind the `python` feature so the binary never links libpython. The
// wheel exposes the composition entry point + the fabric control handles
// (MISSION.md §3.4) to the agent client. Skeleton until the composition wires.
#[cfg(feature = "python")]
mod python {
    use pyo3::prelude::*;

    /// `import ciris_server` — the composition CIRISAgent embeds.
    #[pymodule]
    fn ciris_server(_py: Python<'_>, _m: &Bound<'_, PyModule>) -> PyResult<()> {
        // TODO: expose run()/compose handles once the Rust composition wires.
        Ok(())
    }
}
