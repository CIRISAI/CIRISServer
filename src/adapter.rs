//! The public **adapter seam** — a Rust mirror of CIRISAgent's
//! `BaseAdapterProtocol`, so a downstream crate (e.g. CIRISStatus) can be
//! "ciris-server + an adapter": it contributes HTTP routes + a background
//! lifecycle task to the SAME shared core (one persist `Engine` + one Reticulum
//! `Edge`) the composition root already builds, instead of re-composing the
//! substrate itself (MISSION §1.2 — no core builds its own Edge).
//!
//! The agent's adapter contract (Python) is:
//!   `start()` / `stop()` / `get_config()` / `get_status()` /
//!   `get_services_to_register()` / `run_lifecycle(agent_task)`, with a `runtime`
//!   handle to the shared core. The Rust equivalents on ciris-server are the
//!   methods of [`Adapter`] below; [`AdapterContext`] is the `runtime` handle.
//!
//! This is **additive**: `serve()` keeps booting with the [`NoopAdapter`], so the
//! default behavior and all existing tests are unchanged.

use std::sync::Arc;

use crate::config::ServerConfig;
use ciris_persist::prelude::Engine;

/// The shared-core handle an [`Adapter`] receives — the Rust mirror of the
/// agent adapter's `runtime` argument. Carries the ONE persist [`Engine`] (the
/// shared corpus), the node's federation `key_id`, and the resolved
/// [`ServerConfig`]. Cheap to clone (the engine is already `Arc`, the rest are
/// owned `String`/config), so it is captured by clone into both the router
/// closure and the lifecycle task.
#[derive(Clone)]
pub struct AdapterContext {
    /// The one shared persist `Engine` (the corpus the whole node reads/writes).
    pub engine: Arc<Engine>,
    /// The node's federation `key_id` (the steward identity attestations are
    /// authored under).
    pub key_id: String,
    /// The fully-resolved node configuration.
    pub cfg: ServerConfig,
}

/// An adapter's runtime status — the mirror of the agent adapter's
/// `get_status()`.
#[derive(Debug, Clone)]
pub struct AdapterStatus {
    /// A stable identifier for this adapter instance.
    pub adapter_id: String,
    /// Whether the adapter's lifecycle is currently running.
    pub running: bool,
}

/// An adapter's static configuration — the mirror of the agent adapter's
/// `get_config()`.
#[derive(Debug, Clone)]
pub struct AdapterConfig {
    /// The adapter's type tag (e.g. `"noop"`, `"status"`).
    pub adapter_type: String,
    /// Whether the adapter is enabled.
    pub enabled: bool,
}

/// The adapter seam — a Rust mirror of CIRISAgent's `BaseAdapterProtocol`.
///
/// An adapter contributes HTTP routes + a background lifecycle task to the shared
/// core. The composition root ([`crate::serve_with_adapter`]) calls these methods
/// in the same order the agent runtime drives a Python adapter: `get_config` /
/// `get_status` for introspection, `get_services_to_register` ([`Adapter::routers`])
/// to fold in the HTTP surface, `start` once before the lifecycle, then
/// `run_lifecycle` for the long-running loop, and finally `stop` on shutdown.
#[async_trait::async_trait]
pub trait Adapter: Send + Sync {
    /// Mirror of the agent adapter's **`get_config()`** — the adapter's static
    /// configuration (type tag + enabled flag).
    fn adapter_config(&self) -> AdapterConfig;

    /// Mirror of the agent adapter's **`get_status()`** — the adapter's current
    /// runtime status.
    fn status(&self) -> AdapterStatus;

    /// Mirror of the agent adapter's **`get_services_to_register()`** — the HTTP
    /// surface the adapter contributes. Each returned [`axum::Router`] is merged
    /// onto the node's read-API listener. Defaults to no routes.
    fn routers(&self, ctx: &AdapterContext) -> Vec<axum::Router> {
        let _ = ctx;
        Vec::new()
    }

    /// Mirror of the agent adapter's **`start()`** — one-shot setup run once
    /// before the lifecycle task is spawned. Defaults to a no-op.
    async fn start(&self, ctx: &AdapterContext) -> anyhow::Result<()> {
        let _ = ctx;
        Ok(())
    }

    /// Mirror of the agent adapter's **`run_lifecycle(agent_task)`** — the
    /// long-running background loop. Returns when `shutdown` flips to `true`
    /// (the composition root sends `true` on ctrl-c). Defaults to returning
    /// immediately.
    async fn run_lifecycle(
        &self,
        ctx: &AdapterContext,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let _ = (ctx, &mut shutdown);
        Ok(())
    }

    /// Mirror of the agent adapter's **`stop()`** — teardown run once on
    /// shutdown, after the lifecycle is signalled to stop. Defaults to a no-op.
    async fn stop(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// The default adapter — contributes nothing. `serve()` boots with this, so the
/// node's default behavior is byte-identical to the pre-seam composition.
pub struct NoopAdapter;

#[async_trait::async_trait]
impl Adapter for NoopAdapter {
    fn adapter_config(&self) -> AdapterConfig {
        AdapterConfig {
            adapter_type: "noop".to_string(),
            enabled: true,
        }
    }

    fn status(&self) -> AdapterStatus {
        AdapterStatus {
            adapter_id: "noop".to_string(),
            running: false,
        }
    }
}
