//! **Where the node's host-side signals meet edge.** Two seams were left open
//! until edge shipped the far side, so a node under load never told its transport,
//! and a backgrounded phone kept its links open:
//!
//! - [`EdgePressure`]: `capacity_monitor` samples the host, edge picks what to shed.
//! - [`EdgeSleep`]: `node_lifecycle` backgrounds and foregrounds the transport.
//!
//! `Edge::resume` reopens the transport and starts no round (edge, 2026-11-05), so
//! the next one would wait out its 30 s cadence. Waking kicks every round at once;
//! kicks coalesce, so this costs at most one round per peer and kind. A round needs
//! a dialled link first, so the first one may still take a moment.

use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use ciris_edge::Edge;

use crate::capacity_monitor::{LoadPressure, PressureSink};
use crate::node_lifecycle::TransportSleep;

/// How long past its own deadline to wait for `suspend` to answer: it reports the
/// deadline it hit, so a slower answer means the runtime itself is stuck.
const SUSPEND_GRACE: Duration = Duration::from_millis(500);
/// How long a foregrounding host waits for the transport before its loops resume.
const RESUME_WAIT: Duration = Duration::from_secs(5);

/// Feeds the capacity monitor's pressure to edge's service ladder.
pub struct EdgePressure(pub Arc<Edge>);

impl PressureSink for EdgePressure {
    fn set_load_pressure(&self, p: LoadPressure) {
        let _tier = self.0.set_load_pressure(match p {
            LoadPressure::Normal => ciris_edge::LoadPressure::Normal,
            LoadPressure::Warning => ciris_edge::LoadPressure::Warning,
            LoadPressure::Critical => ciris_edge::LoadPressure::Critical,
        });
    }
}

/// Sleeps and wakes edge's transport. The host calls these from its lifecycle
/// callback, which may be on a runtime thread, so the work goes to the node's
/// runtime and the caller waits on a channel, never with `block_on`.
pub struct EdgeSleep {
    pub edge: Arc<Edge>,
    pub runtime: tokio::runtime::Handle,
}

impl TransportSleep for EdgeSleep {
    fn suspend(&self, deadline: Duration) -> bool {
        let (tx, rx) = mpsc::channel();
        let edge = Arc::clone(&self.edge);
        self.runtime.spawn(async move {
            let _ = tx.send(edge.suspend(deadline).await.quiescent);
        });
        rx.recv_timeout(deadline + SUSPEND_GRACE).unwrap_or(false)
    }

    fn resume(&self) {
        let (tx, rx) = mpsc::channel();
        let edge = Arc::clone(&self.edge);
        self.runtime.spawn(async move {
            if let Err(e) = edge.resume().await {
                tracing::warn!(error = %e, "LIFECYCLE foreground — the transport did not reopen");
            }
            let _ = tx.send(());
            if let Some(runtime) = crate::compose::held_replication_runtime() {
                if let Err(e) = runtime.round_now_all().await {
                    tracing::warn!(error = %e, "LIFECYCLE foreground — no catch-up round kicked");
                }
            }
        });
        if rx.recv_timeout(RESUME_WAIT).is_err() {
            tracing::warn!(
                wait_ms = RESUME_WAIT.as_millis() as u64,
                "LIFECYCLE foreground — the transport is still reopening; the loops resume anyway"
            );
        }
    }
}

/// Connect the monitor and the lifecycle to this edge. A re-serve replaces both.
pub fn register(edge: &Arc<Edge>) {
    crate::capacity_monitor::set_sink(Arc::new(EdgePressure(Arc::clone(edge))));
    crate::node_lifecycle::set_transport(Arc::new(EdgeSleep {
        edge: Arc::clone(edge),
        runtime: tokio::runtime::Handle::current(),
    }));
}
