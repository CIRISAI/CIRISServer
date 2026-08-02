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
//!   - **retention.{cadence_secs,max_age_days,max_disk_gb,audit_log_max_age_days}**
//!     — fully HOT: [`crate::retention_loop`] reads the live snapshot each pass
//!     and re-arms its timer mid-sleep when the cadence changes, so tightening a
//!     bound on a node that is filling its disk takes effect without a restart
//!     (which is the only moment anyone will ever touch these).
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
/// How often the capacity scorer sweeps the corpus.
///
/// **60s, not the previous 3600.** The old value carried a rationale that
/// contradicted itself — "short enough that a fresh corpus produces a capacity
/// row promptly" — while making a first-run agent wait up to an hour to see any
/// score at all. That is not a happy path; it is a happy path with an hour-long
/// hole in the middle, and it made every trace-delivery investigation slower
/// because "no score yet" and "no score ever" looked identical for 60 minutes.
///
/// A pass is cheap and BOUNDED regardless of corpus size: one `LIMIT
/// scorer_window` (500) paged read, grouped by `trace_id`, with feature
/// extraction over those rows only. It does not walk the corpus. So the cadence
/// was never the thing protecting load — `scorer_window` is.
///
/// Noise is prevented by the SAMPLE GATE, not by the clock: `capacity()` returns
/// 0.0 at or below `scorer_sample_gate` (20) surviving rows, so sweeping more
/// often cannot manufacture signal from a thin corpus. It only shortens the wait
/// once a corpus is genuinely scoreable.
pub const DEFAULT_SCORER_CADENCE_SECS: u64 = 60;
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

// ── Retention / eviction (CIRISServer#348) ────────────────────────────────────

/// Default for `retention.cadence_secs` — how often the retention loop enforces
/// the policy. HOURLY.
///
/// Eviction is a COARSE clock. Its finest configurable bound is a day
/// (`retention.max_age_days`), so anything faster than hourly is re-asking a
/// question whose answer cannot have changed, against a table scan. And unlike
/// the scorer there is no detection latency to buy: nobody is waiting to see an
/// eviction happen.
pub const DEFAULT_RETENTION_CADENCE_SECS: u64 = 3600;

/// Default for `retention.max_age_days` — the global trace age cap. **90 days.**
///
/// lens-core's own [`RetentionPolicy::default`](ciris_lens_core::RetentionPolicy)
/// is all-`None`, i.e. keep everything forever, and that is the right default for
/// a LIBRARY: it cannot know whether its embedder is a sovereign archive or a Pi.
/// A NODE can. A node with no time bound grows monotonically until the disk fills
/// — measured on the production canonical at 9,811 rows of a single dimension —
/// and the failure mode of an unbounded store is not a slow query, it is a node
/// that stops.
///
/// 90 days is deliberately far wider than any consumer of this data needs: the
/// scorer reads a `scorer.window` (500) row page and never looks at age, and a
/// capacity assertion is valid for 7 days. The bound is here to stop pathological
/// growth, NOT to express a privacy posture — an operator wanting a privacy
/// posture sets a much shorter one, and one wanting a sovereign archive sets
/// `retention.max_age_days = 0` (see [`ResolvedConfig::retention_max_age_days`]).
pub const DEFAULT_RETENTION_MAX_AGE_DAYS: u32 = 90;

/// Default for `retention.max_disk_gb` — **0, meaning no disk cap** (opt-in).
///
/// Not a shrug: disk-pressure eviction is unsafe to bake on SQLite, which is what
/// a node actually runs. The pressure signal is `PRAGMA page_count * page_size`,
/// and SQLite does not return pages to the OS on DELETE — freed pages go on the
/// freelist and `page_count` stays put. So the signal that TRIGGERED the eviction
/// cannot be cleared BY the eviction: once over the cap, every pass would cut to
/// the remaining trace window's midpoint, halving it again and again until the
/// table is empty, and the operator's first symptom would be a node with no
/// traces at all. Time-bound eviction has no such feedback path — it removes
/// exactly what is older than the cutoff and then stops.
///
/// The knob stays live for Postgres deployments (where `pg_relation_size` does
/// fall after a delete) and for operators who accept the SQLite behaviour.
pub const DEFAULT_RETENTION_MAX_DISK_GB: u64 = 0;

/// Default for `retention.audit_log_max_age_days` — **0, meaning never** (opt-in).
///
/// The audit hash chain MUST stay unbroken, so eviction there is "archive +
/// truncate", never delete — and lens-core's executor cannot yet run the archive
/// (its `cirisaudit` passthrough is off). Baking a default would plan an action
/// on every pass that the executor then declines to perform, which is a standing
/// lie in the log.
pub const DEFAULT_RETENTION_AUDIT_LOG_MAX_AGE_DAYS: u32 = 0;
/// Default for `mode`. Was `CIRIS_SERVER_MODE` / `AGENT_MODE`. CIRISServer is a
/// server: installing the server means a server.
pub const DEFAULT_MODE: &str = "server";

/// Default for `net.listen_addr` — the Reticulum node port. Was
/// `CIRIS_SERVER_LISTEN_ADDR`. Boot-structural (binds the edge).
pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:4242";

// NOTE (0.5.81): the hardcoded `CANONICAL_BOOTSTRAP_PEERS` const is RETIRED. A
// fresh node no longer learns the mesh entry addresses from a compiled-in list —
// it reads them from the BAKED canonical servers' **signed envelope transport
// hints** (CIRISPersist#381): each canonical `KeyRecord` carries its `ip` transport
// hint inside the same accord-scrubbed `registration_envelope` that establishes its
// trust, so who + where arrive together, self-describing, with no invented IP in
// the binary. `compose::canonical_bootstrap_addrs` unions those into the dial set at
// boot; `net.bootstrap_peers` config stays as an optional break-glass override
// (empty default). See `net.bootstrap_peers` in `config.rs`.

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
/// `retention.cadence_secs` — how often the retention/eviction loop runs.
pub const KEY_RETENTION_CADENCE_SECS: &str = "retention.cadence_secs";
/// `retention.max_age_days` — global trace age cap (`0` = keep forever).
pub const KEY_RETENTION_MAX_AGE_DAYS: &str = "retention.max_age_days";
/// `retention.max_disk_gb` — soft disk cap (`0` = no disk-pressure eviction).
pub const KEY_RETENTION_MAX_DISK_GB: &str = "retention.max_disk_gb";
/// `retention.audit_log_max_age_days` — audit archival cap (`0` = never).
pub const KEY_RETENTION_AUDIT_LOG_MAX_AGE_DAYS: &str = "retention.audit_log_max_age_days";
/// `mode` — the node transport posture (client/proxy/server).
pub const KEY_MODE: &str = "mode";
/// `net.listen_addr` — the Reticulum node listen address (boot-structural).
pub const KEY_LISTEN_ADDR: &str = "net.listen_addr";
/// `net.bootstrap_peers` — Reticulum mesh entry addresses (boot-structural, list).
pub const KEY_BOOTSTRAP_PEERS: &str = "net.bootstrap_peers";
/// `net.announce_ownership` — the "announce yourself to the federation" opt-in
/// (boot-structural). DEFAULT FALSE: a fresh / self-scoped node does NOT advertise
/// its federation IDENTITY on the Reticulum announce (CIRISServer#125). When the
/// owner promotes (POST /v1/federation/announce), the promote sets this `true`; on
/// the next boot the node wires its federation signer into the announce so its
/// announce carries the AV-42 authenticated identity attestation (peers can root
/// `key_id → destination`). When false the transport still brings up + announces
/// its raw destination hash, but with NO identity attestation → rooting peers drop
/// it (fail-honest) → the node is not federation-identity-discoverable.
pub const KEY_ANNOUNCE_OWNERSHIP: &str = "net.announce_ownership";
/// `net.radio.*` — serial LoRa/RNode radio transport (boot-structural; desktop-only).
pub const KEY_RADIO_ENABLED: &str = "net.radio.enabled";
pub const KEY_RADIO_SERIAL_PORT: &str = "net.radio.serial_port";
pub const KEY_RADIO_FREQUENCY: &str = "net.radio.frequency_hz";
pub const KEY_RADIO_BANDWIDTH: &str = "net.radio.bandwidth_hz";
pub const KEY_RADIO_SF: &str = "net.radio.spreading_factor";
pub const KEY_RADIO_CR: &str = "net.radio.coding_rate";
pub const KEY_RADIO_TXPOWER: &str = "net.radio.tx_power_dbm";
/// Baked LoRa defaults (915 MHz ISM / SF7 / CR4-5 / 17 dBm) — overridden by the
/// `net.radio.*` config:* objects the Transport card writes.
const DEFAULT_RADIO_FREQUENCY_HZ: u32 = 915_000_000;
const DEFAULT_RADIO_BANDWIDTH_HZ: u32 = 125_000;
const DEFAULT_RADIO_SF: u8 = 7;
const DEFAULT_RADIO_CR: u8 = 5;
const DEFAULT_RADIO_TX_POWER_DBM: u8 = 17;
/// `node.alias` — the human-readable alias the node suggests for itself.
pub const KEY_NODE_ALIAS: &str = "node.alias";
/// `auth.admin_key_ids` — admin-eligible federation `key_id`s (auto-mint gate, list).
pub const KEY_ADMIN_KEY_IDS: &str = "auth.admin_key_ids";
/// `auth.oauth_callback_base_url` — the OAuth front-door callback base URL.
pub const KEY_OAUTH_CALLBACK_BASE_URL: &str = "auth.oauth_callback_base_url";

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
    /// `retention.cadence_secs` (HOT). How often the retention loop enforces the
    /// policy; the loop re-arms its timer when this changes.
    pub retention_cadence_secs: u64,
    /// `retention.max_age_days` (HOT). Global trace age cap.
    ///
    /// **`0` means "no time bound"** — the encoding, not a sentinel picked for
    /// convenience. The config store's numeric shape is `i64`; there is no way to
    /// write `null` through it, so "keep forever" needs a value. Zero is the only
    /// one that cannot also be a legitimate cap (a 0-day cap would delete every
    /// trace the instant it lands, which no operator means). It is projected to
    /// `RetentionPolicy::max_age_days = None`.
    pub retention_max_age_days: u32,
    /// `retention.max_disk_gb` (HOT). Soft disk cap; `0` = no disk-pressure
    /// eviction (same zero-means-unbounded encoding as above).
    pub retention_max_disk_gb: u64,
    /// `retention.audit_log_max_age_days` (HOT). Audit archival cap; `0` = never.
    pub retention_audit_log_max_age_days: u32,
    /// `mode` (boot-structural). The node transport posture string.
    pub mode: String,
    /// `net.listen_addr` (boot-structural). The Reticulum node listen address
    /// (the raw `host:port` string; parsed at the build site, baked default on a
    /// malformed value).
    pub listen_addr: String,
    /// `net.bootstrap_peers` (boot-structural). Reticulum mesh entry `host:port`
    /// strings; parsed to `SocketAddr` at the build site (invalid entries skipped
    /// + warned).
    pub bootstrap_peers: Vec<String>,
    /// `net.announce_ownership` (boot-structural). The "announce yourself to the
    /// federation" opt-in (CIRISServer#125). DEFAULT FALSE — a self-scoped node
    /// does not advertise its federation identity. When true, the build site wires
    /// the federation signer into the Reticulum announce attestation (AV-42).
    pub announce_ownership: bool,
    /// `node.alias` (boot-structural). The human-readable alias the node suggests
    /// for itself in its NodeCode (empty = none).
    pub node_alias: String,
    /// `auth.admin_key_ids` (boot-structural). Admin-eligible federation `key_id`s
    /// (the auto-mint eligibility allowlist).
    pub admin_key_ids: Vec<String>,
    /// `auth.oauth_callback_base_url` (boot-structural). The OAuth front-door
    /// callback base URL (empty = the baked localhost default at the build site).
    pub oauth_callback_base_url: String,
    /// `net.radio.enabled` (boot-structural). Attach a serial LoRa/RNode radio
    /// transport to the Edge (desktop nodes only; the android/ios wheels can't
    /// open a serial port, so the attach is cfg-gated off at the build site).
    pub radio_enabled: bool,
    /// `net.radio.serial_port` — the RNode serial device (e.g. `/dev/ttyUSB0`,
    /// `/dev/tty.usbserial-XXXX`, `COM3`). Empty ⇒ no radio attached.
    pub radio_serial_port: String,
    /// `net.radio.frequency_hz` — LoRa centre frequency in Hz.
    pub radio_frequency_hz: u32,
    /// `net.radio.bandwidth_hz` — LoRa bandwidth in Hz.
    pub radio_bandwidth_hz: u32,
    /// `net.radio.spreading_factor` — LoRa SF (7–12).
    pub radio_spreading_factor: u8,
    /// `net.radio.coding_rate` — LoRa CR denominator (5–8).
    pub radio_coding_rate: u8,
    /// `net.radio.tx_power_dbm` — LoRa TX power in dBm.
    pub radio_tx_power_dbm: u8,
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
            retention_cadence_secs: DEFAULT_RETENTION_CADENCE_SECS,
            retention_max_age_days: DEFAULT_RETENTION_MAX_AGE_DAYS,
            retention_max_disk_gb: DEFAULT_RETENTION_MAX_DISK_GB,
            retention_audit_log_max_age_days: DEFAULT_RETENTION_AUDIT_LOG_MAX_AGE_DAYS,
            mode: DEFAULT_MODE.to_owned(),
            listen_addr: DEFAULT_LISTEN_ADDR.to_owned(),
            // No baked default — reachability is sourced from the baked canonical
            // records' envelope transport hints (CIRISPersist#381) + optional
            // `net.bootstrap_peers` override. The retired const shipped no IPs anyway.
            bootstrap_peers: Vec::new(),
            announce_ownership: false,
            node_alias: String::new(),
            admin_key_ids: Vec::new(),
            oauth_callback_base_url: String::new(),
            radio_enabled: false,
            radio_serial_port: String::new(),
            radio_frequency_hz: DEFAULT_RADIO_FREQUENCY_HZ,
            radio_bandwidth_hz: DEFAULT_RADIO_BANDWIDTH_HZ,
            radio_spreading_factor: DEFAULT_RADIO_SF,
            radio_coding_rate: DEFAULT_RADIO_CR,
            radio_tx_power_dbm: DEFAULT_RADIO_TX_POWER_DBM,
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

    /// The retention loop's cadence as a [`Duration`], with `0` clamped to the
    /// default (a zero-period interval would busy-spin).
    ///
    /// Note that `0` means the OPPOSITE thing here than it does for the age /
    /// disk BOUNDS: an unbounded cadence is not a coherent request, so zero can
    /// only be a mistake and falls back; an unbounded age cap IS coherent, so
    /// zero is honoured there. Same literal, two different questions — which is
    /// exactly why each one is decoded in its own named accessor rather than by
    /// a shared "0 means off" helper.
    pub fn retention_cadence(&self) -> Duration {
        let secs = if self.retention_cadence_secs == 0 {
            DEFAULT_RETENTION_CADENCE_SECS
        } else {
            self.retention_cadence_secs
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
pub async fn resolve(engine: &Arc<Engine>) -> ResolvedConfig {
    let d = ResolvedConfig::default();

    let transport_node = graph_config::get_bool(engine, KEY_TRANSPORT_NODE)
        .await
        .ok()
        .flatten()
        .unwrap_or(d.transport_node);
    let store_and_forward = graph_config::get_bool(engine, KEY_STORE_AND_FORWARD)
        .await
        .ok()
        .flatten()
        .unwrap_or(d.store_and_forward);
    let scorer_cadence_secs = graph_config::get_i64(engine, KEY_SCORER_CADENCE_SECS)
        .await
        .ok()
        .flatten()
        .filter(|s| *s > 0)
        .map(|s| s as u64)
        .unwrap_or(d.scorer_cadence_secs);
    let scorer_window = graph_config::get_i64(engine, KEY_SCORER_WINDOW)
        .await
        .ok()
        .flatten()
        .filter(|w| (1..=10_000).contains(w))
        .unwrap_or(d.scorer_window);
    let scorer_sample_gate = graph_config::get_i64(engine, KEY_SCORER_SAMPLE_GATE)
        .await
        .ok()
        .flatten()
        .filter(|g| (0..=u32::MAX as i64).contains(g))
        .map(|g| g as u32)
        .unwrap_or(d.scorer_sample_gate);
    let scorer_target_n_eff = graph_config::get_f64(engine, KEY_SCORER_TARGET_N_EFF)
        .await
        .ok()
        .flatten()
        .filter(|t| t.is_finite() && *t > 0.0)
        .unwrap_or(d.scorer_target_n_eff);
    let replication_reconcile_secs = graph_config::get_i64(engine, KEY_REPLICATION_RECONCILE_SECS)
        .await
        .ok()
        .flatten()
        .filter(|s| *s > 0)
        .map(|s| s as u64)
        .unwrap_or(d.replication_reconcile_secs);
    let retention_cadence_secs = graph_config::get_i64(engine, KEY_RETENTION_CADENCE_SECS)
        .await
        .ok()
        .flatten()
        .filter(|s| *s > 0)
        .map(|s| s as u64)
        .unwrap_or(d.retention_cadence_secs);
    // The retention BOUNDS accept `0` (= unbounded) — so the filter is `>= 0`,
    // not `> 0`. Using the cadence's `> 0` filter here would silently fall back
    // to the 90-day default on the one write an operator makes to turn eviction
    // OFF, and their sovereign archive would quietly start deleting.
    let retention_max_age_days = graph_config::get_i64(engine, KEY_RETENTION_MAX_AGE_DAYS)
        .await
        .ok()
        .flatten()
        .filter(|days| (0..=u32::MAX as i64).contains(days))
        .map(|days| days as u32)
        .unwrap_or(d.retention_max_age_days);
    let retention_max_disk_gb = graph_config::get_i64(engine, KEY_RETENTION_MAX_DISK_GB)
        .await
        .ok()
        .flatten()
        .filter(|g| *g >= 0)
        .map(|g| g as u64)
        .unwrap_or(d.retention_max_disk_gb);
    let retention_audit_log_max_age_days =
        graph_config::get_i64(engine, KEY_RETENTION_AUDIT_LOG_MAX_AGE_DAYS)
            .await
            .ok()
            .flatten()
            .filter(|days| (0..=u32::MAX as i64).contains(days))
            .map(|days| days as u32)
            .unwrap_or(d.retention_audit_log_max_age_days);
    let mode = graph_config::get_str(engine, KEY_MODE)
        .await
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(d.mode);
    let listen_addr = graph_config::get_str(engine, KEY_LISTEN_ADDR)
        .await
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(d.listen_addr);
    let bootstrap_peers = graph_config::get_str_list(engine, KEY_BOOTSTRAP_PEERS)
        .await
        .ok()
        .flatten()
        .unwrap_or(d.bootstrap_peers);
    let announce_ownership = graph_config::get_bool(engine, KEY_ANNOUNCE_OWNERSHIP)
        .await
        .ok()
        .flatten()
        .unwrap_or(d.announce_ownership);
    // `node.alias` defaults to empty (the build site falls back to key_id).
    let node_alias = graph_config::get_str(engine, KEY_NODE_ALIAS)
        .await
        .ok()
        .flatten()
        .unwrap_or(d.node_alias);
    let admin_key_ids = graph_config::get_str_list(engine, KEY_ADMIN_KEY_IDS)
        .await
        .ok()
        .flatten()
        .unwrap_or(d.admin_key_ids);
    let oauth_callback_base_url = graph_config::get_str(engine, KEY_OAUTH_CALLBACK_BASE_URL)
        .await
        .ok()
        .flatten()
        .unwrap_or(d.oauth_callback_base_url);
    // net.radio.* — serial LoRa/RNode radio transport (boot-structural; the build
    // site attaches it on desktop only). Integers come in via get_i64 (the config
    // store's numeric shape) and are range-clamped into u32/u8.
    let radio_enabled = graph_config::get_bool(engine, KEY_RADIO_ENABLED)
        .await
        .ok()
        .flatten()
        .unwrap_or(d.radio_enabled);
    let radio_serial_port = graph_config::get_str(engine, KEY_RADIO_SERIAL_PORT)
        .await
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(d.radio_serial_port);
    let radio_u32 = |v: Option<i64>, dflt: u32| -> u32 {
        v.filter(|n| *n > 0).map(|n| n as u32).unwrap_or(dflt)
    };
    let radio_u8 = |v: Option<i64>, dflt: u8| -> u8 {
        v.filter(|n| *n > 0 && *n <= 255)
            .map(|n| n as u8)
            .unwrap_or(dflt)
    };
    let radio_frequency_hz = radio_u32(
        graph_config::get_i64(engine, KEY_RADIO_FREQUENCY)
            .await
            .ok()
            .flatten(),
        d.radio_frequency_hz,
    );
    let radio_bandwidth_hz = radio_u32(
        graph_config::get_i64(engine, KEY_RADIO_BANDWIDTH)
            .await
            .ok()
            .flatten(),
        d.radio_bandwidth_hz,
    );
    let radio_spreading_factor = radio_u8(
        graph_config::get_i64(engine, KEY_RADIO_SF)
            .await
            .ok()
            .flatten(),
        d.radio_spreading_factor,
    );
    let radio_coding_rate = radio_u8(
        graph_config::get_i64(engine, KEY_RADIO_CR)
            .await
            .ok()
            .flatten(),
        d.radio_coding_rate,
    );
    let radio_tx_power_dbm = radio_u8(
        graph_config::get_i64(engine, KEY_RADIO_TXPOWER)
            .await
            .ok()
            .flatten(),
        d.radio_tx_power_dbm,
    );

    ResolvedConfig {
        transport_node,
        store_and_forward,
        scorer_cadence_secs,
        scorer_window,
        scorer_sample_gate,
        scorer_target_n_eff,
        replication_reconcile_secs,
        retention_cadence_secs,
        retention_max_age_days,
        retention_max_disk_gb,
        retention_audit_log_max_age_days,
        mode,
        listen_addr,
        bootstrap_peers,
        announce_ownership,
        radio_enabled,
        radio_serial_port,
        radio_frequency_hz,
        radio_bandwidth_hz,
        radio_spreading_factor,
        radio_coding_rate,
        radio_tx_power_dbm,
        node_alias,
        admin_key_ids,
        oauth_callback_base_url,
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

            let resolved = resolve(&engine).await;
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
