//! PyO3 adapter bridge (CIRISServer#80) — let a Python "brain" fold into the
//! node's router via [`crate::serve_with_adapter`], without re-composing the
//! substrate.
//!
//! The Rust [`crate::adapter::Adapter`] trait takes `axum::Router`s, which a
//! Python object cannot build. So [`PyAdapter`] wraps a Python adapter object and
//! bridges it with the **mount-by-proxy** model (the interim of the agent
//! adoption — `FSD/CIRISAGENT_ADOPTION.md`): the Python side declares
//! `{prefix → upstream}` pairs (its own sibling HTTP service, e.g. the brain on
//! :8080), and we mount a reverse proxy ([`crate::proxy`]) for each onto the
//! node's one read-API (4243). Lifecycle hooks (`start`/`stop`) bridge to the
//! Python object; the long-running cognitive loop stays in the sibling process,
//! so [`PyAdapter::run_lifecycle`] just parks until shutdown.
//!
//! ## The Python adapter contract (all members optional, duck-typed)
//! ```python
//! class MyAdapter:
//!     adapter_type = "brain"          # str   (default "python")
//!     enabled = True                  # bool  (default True)
//!     def proxy_routes(self):         # -> [{"prefix": "/v1/agent",
//!         return [...]                #       "upstream": "http://127.0.0.1:8080"}]
//!     def start(self): ...            # one-shot setup (sync)
//!     def stop(self): ...             # teardown (sync)
//! ```
//! Entry point: `ciris_server.serve_with_python_adapter(adapter, home=None, key_id=None)`.

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyAnyMethods;

use crate::adapter::{Adapter, AdapterConfig, AdapterContext, AdapterStatus};

/// A Rust [`Adapter`] backed by a Python adapter object.
pub struct PyAdapter {
    obj: Py<PyAny>,
    adapter_type: String,
    enabled: bool,
    /// `(prefix, upstream)` reverse-proxy specs read from `proxy_routes()`.
    proxy_specs: Vec<(String, String)>,
}

impl PyAdapter {
    /// Read the (static) config off a Python adapter object. The GIL is held for
    /// the duration; the proxy specs + flags are snapshotted so the trait methods
    /// (which axum/tokio may call without the GIL) never need to re-enter Python
    /// for routing.
    pub fn from_python(py: Python<'_>, obj: Py<PyAny>) -> PyResult<Self> {
        let b = obj.bind(py);

        let adapter_type = b
            .getattr("adapter_type")
            .ok()
            .and_then(|v| v.extract::<String>().ok())
            .unwrap_or_else(|| "python".to_string());

        let enabled = b
            .getattr("enabled")
            .ok()
            .and_then(|v| v.extract::<bool>().ok())
            .unwrap_or(true);

        let mut proxy_specs = Vec::new();
        if b.hasattr("proxy_routes").unwrap_or(false) {
            let routes = b.call_method0("proxy_routes")?;
            for item in routes.try_iter()? {
                let item = item?;
                // Accept {"prefix":..,"upstream":..} or a (prefix, upstream) pair.
                let (prefix, upstream) =
                    if let (Ok(p), Ok(u)) = (item.get_item("prefix"), item.get_item("upstream")) {
                        (p.extract::<String>()?, u.extract::<String>()?)
                    } else {
                        let p = item.get_item(0)?.extract::<String>()?;
                        let u = item.get_item(1)?.extract::<String>()?;
                        (p, u)
                    };
                proxy_specs.push((prefix, upstream));
            }
        }

        Ok(Self {
            obj,
            adapter_type,
            enabled,
            proxy_specs,
        })
    }

    /// Call a no-arg Python method (if present) on a blocking thread with the GIL,
    /// so a slow `start`/`stop` never stalls the async runtime. Errors are logged,
    /// not fatal (a brain hook failing shouldn't wedge the node).
    async fn call_optional(&self, method: &'static str) {
        let obj = Python::attach(|py| self.obj.clone_ref(py));
        let _ = tokio::task::spawn_blocking(move || {
            Python::attach(|py| {
                let b = obj.bind(py);
                if b.hasattr(method).unwrap_or(false) {
                    if let Err(e) = b.call_method0(method) {
                        tracing::error!(method, error = %e, "python adapter hook failed");
                    }
                }
            });
        })
        .await;
    }
}

#[async_trait::async_trait]
impl Adapter for PyAdapter {
    fn adapter_config(&self) -> AdapterConfig {
        AdapterConfig {
            adapter_type: self.adapter_type.clone(),
            enabled: self.enabled,
        }
    }

    fn status(&self) -> AdapterStatus {
        AdapterStatus {
            adapter_id: self.adapter_type.clone(),
            running: true,
        }
    }

    fn routers(&self, _ctx: &AdapterContext) -> Vec<axum::Router> {
        self.proxy_specs
            .iter()
            .map(|(prefix, upstream)| crate::proxy::reverse_proxy_router(prefix, upstream))
            .collect()
    }

    async fn start(&self, _ctx: &AdapterContext) -> anyhow::Result<()> {
        self.call_optional("start").await;
        Ok(())
    }

    async fn run_lifecycle(
        &self,
        _ctx: &AdapterContext,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        // Interim mount-by-proxy model: the brain runs its own loop in the sibling
        // process. Park until the composition root signals shutdown.
        loop {
            if *shutdown.borrow() {
                break;
            }
            if shutdown.changed().await.is_err() {
                break;
            }
        }
        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        self.call_optional("stop").await;
        Ok(())
    }
}

/// Build a [`PyAdapter`] from a Python object + an `Arc<dyn Adapter>` ready to
/// hand to [`crate::serve_with_adapter`]. Reads the Python config under the GIL.
pub fn build(py: Python<'_>, adapter: Py<PyAny>) -> PyResult<Arc<dyn Adapter>> {
    Ok(Arc::new(PyAdapter::from_python(py, adapter)?))
}
