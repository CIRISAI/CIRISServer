//! The **CEG-driven config reconciler** (Server 0.5 Phase 2) — the controller
//! loop that resolves ciris-server's runtime-tunable knobs from the corpus's
//! signed `config:*` CEG objects and publishes a live [`ResolvedConfig`] snapshot
//! consumers read.
//!
//! ## Architecture rule (mirrors [`crate::replication_reconcile`])
//!
//! **The API never touches the runtime — it writes CEG; the runtime is
//! CEG-driven.** `POST /v1/config` (see [`crate::config_api`]) only ever writes a
//! signed `config:v1` object to the corpus ([`crate::graph_config::set_config`])
//! and nudges this loop via a [`tokio::sync::Notify`]. The `config:v1` objects in
//! the corpus ARE the desired runtime configuration; this loop is the single
//! place that re-resolves them and republishes the live snapshot.
//!
//! ## What is hot vs boot-structural
//!
//! Each tick [`resolve`]s every migrated knob (typed read with a baked default
//! fallback) and `watch::Sender::send_replace`s the new [`ResolvedConfig`]:
//!
//!   - **scorer.{cadence_secs,window,sample_gate,target_n_eff}** — fully HOT: the
//!     scorer reads `*rx.borrow()` each cycle, so a `POST /v1/config` retunes the
//!     next scoring pass with no restart.
//!   - **replication.reconcile_secs** — HOT-ish: the replication reconciler reads
//!     the live snapshot to compute its sleep, so a change applies on the next
//!     tick (no restart).
//!   - **transport.{node,store_and_forward}** — BOOT-STRUCTURAL: the Reticulum
//!     transport is built once at boot from the resolved snapshot. Changing these
//!     in CEG takes effect on the next boot (the value now lives in CEG, not env).
//!   - **mode** — BOOT-STRUCTURAL (informational posture; resolved at boot).
//!
//! The loop is robust: a corpus read error logs + skips the tick and never panics
//! the controller (the consumers keep the last good snapshot).
//!
//! ## Cadence
//!
//! The config reconciler ticks on its OWN fixed cadence
//! ([`CONFIG_RECONCILE_SECS`]) rather than `replication.reconcile_secs` — config
//! resolution is cheap and decoupled from the replication topology cadence — plus
//! the `Notify` nudge for prompt convergence after a write.

use std::sync::Arc;
use std::time::Duration;

use ciris_persist::prelude::Engine;
use tokio::sync::{watch, Notify};

use crate::graph_config;

// ── Baked default constants (the value when the config:* key is absent) ────────

/// Default for `transport.node` — a public fabric node binding `0.0.0.0:4242`
/// SHOULD relay (it IS the NAT-traversal infra). Was `CIRIS_SERVER_TRANSPORT_NODE`.
pub const DEFAULT_TRANSPORT_NODE: bool = true;
/// Default for `transport.store_and_forward` — hold mail for asleep edges. Was
/// `CIRIS_SERVER_STORE_AND_FORWARD`.
pub const DEFAULT_STORE_AND_FORWARD: bool = true;
/// Default for `scorer.cadence_secs` — hourly (the score→emit pass is negligible
/// load, short enough that a fresh corpus produces a capacity row promptly).
pub const DEFAULT_SCORER_CADENCE_SECS: u64 = 3600;
/// Default for `scorer.window` — the measure_n_eff.py default window cap.
pub const DEFAULT_SCORER_WINDOW: i64 = 500;
/// Default for `scorer.sample_gate` — measure_n_eff.py refuses fewer than 20 rows.
pub const DEFAULT_SCORER_SAMPLE_GATE: u32 = 20;
/// Default for `scorer.target_n_eff` — a modest saturation target for an early
/// federation (RATCHET owns the real value).
pub const DEFAULT_SCORER_TARGET_N_EFF: f64 = 8.0;
/// Default for `replication.reconcile_secs`. Was
/// `CIRIS_SERVER_REPLICATION_RECONCILE_SECS`.
pub const DEFAULT_REPLICATION_RECONCILE_SECS: u64 = 30;
/// Default for `mode`. Was `CIRIS_SERVER_MODE` / `AGENT_MODE`. CIRISServer is a
/// server: installing the server means a server.
pub const DEFAULT_MODE: &str = "server";

/// The config reconciler's own tick cadence (seconds). Config resolution is cheap
/// and decoupled from the replication topology cadence, so it runs on a fixed
/// short period plus the `Notify` nudge.
const CONFIG_RECONCILE_SECS: u64 = 30;

// ── The migrated config keys (config:* dimension keys) ─────────────────────────

/// `transport.node` — Reticulum transport-node (packet forwarding) toggle.
pub const KEY_TRANSPORT_NODE: &str = "transport.node";
/// `transport.store_and_forward` — store-and-forward propagation toggle.
pub const KEY_STORE_AND_FORWARD: &str = "transport.store_and_forward";
/// `scorer.cadence_secs` — how often the capacity scorer runs.
pub const KEY_SCORER_CADENCE_SECS: &str = "scorer.cadence_secs";
/// `scorer.window` — max trace summaries pulled per agent per pass.
pub const KEY_SCORER_WINDOW: &str = "scorer.window";
/// `scorer.sample_gate` — LC-AV-18 sample-size gate.
pub const KEY_SCORER_SAMPLE_GATE: &str = "scorer.sample_gate";
/// `scorer.target_n_eff` — N_eff saturation point (capacity 1.0).
pub const KEY_SCORER_TARGET_N_EFF: &str = "scorer.target_n_eff";
/// `replication.reconcile_secs` — the replication reconciler cadence.
pub const KEY_REPLICATION_RECONCILE_SECS: &str = "replication.reconcile_secs";
/// `mode` — the node transport posture (client/proxy/server).
pub const KEY_MODE: &str = "mode";

/// The resolved, runtime-tunable configuration — the migrated knobs, read at boot
/// for the initial snapshot AND on every reconcile tick. [`Default`] is the baked
/// defaults (the value when no `config:*` row is present).
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedConfig {
    /// `transport.node` (boot-structural). Reticulum transport-node forwarding.
    pub transport_node: bool,
    /// `transport.store_and_forward` (boot-structural). Mail held for asleep edges.
    pub store_and_forward: bool,
    /// `scorer.cadence_secs` (HOT). How often the capacity scorer runs.
    pub scorer_cadence_secs: u64,
    /// `scorer.window` (HOT). Max trace summaries per agent per pass.
    pub scorer_window: i64,
    /// `scorer.sample_gate` (HOT). LC-AV-18 sample-size gate.
    pub scorer_sample_gate: u32,
    /// `scorer.target_n_eff` (HOT). N_eff saturation point.
    pub scorer_target_n_eff: f64,
    /// `replication.reconcile_secs` (HOT-ish — applies next reconcile tick).
    pub replication_reconcile_secs: u64,
    /// `mode` (boot-structural). The node transport posture string.
    pub mode: String,
}

impl Default for ResolvedConfig {
    fn default() -> Self {
        ResolvedConfig {
            transport_node: DEFAULT_TRANSPORT_NODE,
            store_and_forward: DEFAULT_STORE_AND_FORWARD,
            scorer_cadence_secs: DEFAULT_SCORER_CADENCE_SECS,
            scorer_window: DEFAULT_SCORER_WINDOW,
            scorer_sample_gate: DEFAULT_SCORER_SAMPLE_GATE,
            scorer_target_n_eff: DEFAULT_SCORER_TARGET_N_EFF,
            replication_reconcile_secs: DEFAULT_REPLICATION_RECONCILE_SECS,
            mode: DEFAULT_MODE.to_owned(),
        }
    }
}

impl ResolvedConfig {
    /// The replication reconciler's cadence as a [`Duration`], with a `0`/absurd
    /// value clamped to the default (a zero-period interval would busy-spin).
    pub fn replication_reconcile_interval(&self) -> Duration {
        let secs = if self.replication_reconcile_secs == 0 {
            DEFAULT_REPLICATION_RECONCILE_SECS
        } else {
            self.replication_reconcile_secs
        };
        Duration::from_secs(secs)
    }

    /// The scorer cadence as a [`Duration`], with `0` clamped to the default.
    pub fn scorer_cadence(&self) -> Duration {
        let secs = if self.scorer_cadence_secs == 0 {
            DEFAULT_SCORER_CADENCE_SECS
        } else {
            self.scorer_cadence_secs
        };
        Duration::from_secs(secs)
    }
}

/// Read each migrated `config:*` key via the [`crate::graph_config`] typed
/// accessors and fall back to the baked default per key. **Pure read** (no loop),
/// so it is used both for the boot snapshot and each reconcile tick — and is
/// directly testable.
///
/// A read error on any single key falls back to that key's default (a malformed /
/// missing row must never wedge resolution); the overall call returns a complete
/// [`ResolvedConfig`].
pub async fn resolve(engine: &Arc<Engine>, node_key_id: &str) -> ResolvedConfig {
    let d = ResolvedConfig::default();

    let transport_node = graph_config::get_bool(engine, node_key_id, KEY_TRANSPORT_NODE)
        .await
        .ok()
        .flatten()
        .unwrap_or(d.transport_node);
    let store_and_forward = graph_config::get_bool(engine, node_key_id, KEY_STORE_AND_FORWARD)
        .await
        .ok()
        .flatten()
        .unwrap_or(d.store_and_forward);
    let scorer_cadence_secs = graph_config::get_i64(engine, node_key_id, KEY_SCORER_CADENCE_SECS)
        .await
        .ok()
        .flatten()
        .filter(|s| *s > 0)
        .map(|s| s as u64)
        .unwrap_or(d.scorer_cadence_secs);
    let scorer_window = graph_config::get_i64(engine, node_key_id, KEY_SCORER_WINDOW)
        .await
        .ok()
        .flatten()
        .filter(|w| (1..=10_000).contains(w))
        .unwrap_or(d.scorer_window);
    let scorer_sample_gate = graph_config::get_i64(engine, node_key_id, KEY_SCORER_SAMPLE_GATE)
        .await
        .ok()
        .flatten()
        .filter(|g| (0..=u32::MAX as i64).contains(g))
        .map(|g| g as u32)
        .unwrap_or(d.scorer_sample_gate);
    let scorer_target_n_eff = graph_config::get_f64(engine, node_key_id, KEY_SCORER_TARGET_N_EFF)
        .await
        .ok()
        .flatten()
        .filter(|t| t.is_finite() && *t > 0.0)
        .unwrap_or(d.scorer_target_n_eff);
    let replication_reconcile_secs =
        graph_config::get_i64(engine, node_key_id, KEY_REPLICATION_RECONCILE_SECS)
            .await
            .ok()
            .flatten()
            .filter(|s| *s > 0)
            .map(|s| s as u64)
            .unwrap_or(d.replication_reconcile_secs);
    let mode = graph_config::get_str(engine, node_key_id, KEY_MODE)
        .await
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(d.mode);

    ResolvedConfig {
        transport_node,
        store_and_forward,
        scorer_cadence_secs,
        scorer_window,
        scorer_sample_gate,
        scorer_target_n_eff,
        replication_reconcile_secs,
        mode,
    }
}

/// Spawn the config reconcile controller loop. Returns the task handle (held by
/// the caller for the node's lifetime). The loop ticks on the fixed
/// [`CONFIG_RECONCILE_SECS`] cadence, on an explicit `notify` nudge (the config
/// API fires this after writing CEG so the live snapshot converges promptly), and
/// exits when `shutdown` flips to `true`.
///
/// Each tick re-[`resolve`]s and `send_replace`s the new [`ResolvedConfig`] onto
/// `tx`; consumers holding a `watch::Receiver` see the update (the scorer reads it
/// HOT per cycle). A change is logged at info.
pub fn spawn(
    engine: Arc<Engine>,
    node_key_id: String,
    tx: watch::Sender<ResolvedConfig>,
    notify: Arc<Notify>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let period = Duration::from_secs(CONFIG_RECONCILE_SECS);
        let mut interval = tokio::time::interval(period);
        // Skip missed ticks rather than burst-catch-up if a reconcile runs long.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            period_secs = period.as_secs(),
            "CEG-driven config reconciler started (config:* objects are the desired runtime config; \
             API writes CEG, this loop re-resolves + republishes the live snapshot — scorer knobs \
             are hot, transport/mode are boot-structural)"
        );

        // The first immediate interval.tick() implies an initial reconcile; the
        // boot snapshot was already resolved in compose, so this just refreshes it.
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = notify.notified() => {
                    tracing::debug!("config reconcile nudged (CEG changed) — reconciling now");
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        tracing::info!("config reconciler shutting down");
                        return;
                    }
                    continue;
                }
            }

            let resolved = resolve(&engine, &node_key_id).await;
            tx.send_if_modified(|current| {
                if *current != resolved {
                    tracing::info!(
                        ?resolved,
                        "config snapshot changed — republished (scorer knobs apply next cycle; \
                         transport/mode apply next boot)"
                    );
                    *current = resolved.clone();
                    true
                } else {
                    false
                }
            });
        }
    })
}
