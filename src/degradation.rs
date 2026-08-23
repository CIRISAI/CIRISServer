//! **The node says when it is in trouble** (CIRISServer#446, #480).
//!
//! # The silence this exists to end
//!
//! `/health` served a hardcoded `"status": "ok"` on every route. On 2026-08-23
//! the production canonical was SIGKILLed by its cgroup 193 times — climbing to
//! 93% of its memory limit within two minutes of every restart — and answered
//! `ok` right up to each kill. Before that it spent a day at 7.64 GB with a
//! runtime worker parked in `wait_on_page_bit_common`, unable to answer HTTP at
//! all, and #446 had already named the shape: *health cannot report it*.
//!
//! A node that is failing and says `ok` is worse than one that is simply down,
//! because every watcher above it — the operator, the status page, the client's
//! own probe — reads the lie and stands down.
//!
//! # The contract already existed on the other side
//!
//! The client has parsed `data.warnings[]` and `data.degraded_mode` since long
//! before this module (`CIRISApiClient`: `if (status != "ok" || degradedMode ||
//! warnings.isNotEmpty())`), including the `{code, message, severity,
//! action_url}` warning shape. The server simply never emitted them. This is
//! the producer for a consumer that was already waiting — which is why the wire
//! shape here is copied from the client's parse and not designed fresh.
//!
//! # Rules
//!
//! * **A warning names its remedy.** `message` says what an operator does, not
//!   only what is wrong. A warning nobody can act on is noise that trains people
//!   to ignore the channel.
//! * **Raising is idempotent and clearing is explicit.** A condition that ends
//!   must clear its own warning; nothing expires on a timer, because a warning
//!   that ages out silently is the same silence in slow motion.
//! * **`degraded_mode` is not "any warning".** It is true when something is
//!   actually *reduced* — severity `error` or `critical`. A `warning` says "look
//!   at this soon"; `degraded_mode` says "this node is not doing its whole job
//!   right now", and collapsing them would make the flag useless the first time
//!   an advisory fired.
//! * **Cannot-measure is not healthy.** A probe that fails to read its input
//!   reports that it could not read it (see [`MemoryReading`](crate::degradation::MemoryReading)),
//!   never a comfortable number — the distinct-zeroes discipline this repo has
//!   now paid for four times.

use std::sync::RwLock;

/// One operator-facing condition, in the shape the client already parses.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Warning {
    /// Stable machine id — `resource.memory_pressure`, `retention.bound_unenforceable`.
    /// Dotted, namespaced by subsystem, and never localized: this is the key a
    /// dashboard groups on.
    pub code: String,
    /// What is wrong AND what to do about it, in one sentence a human can act on.
    pub message: String,
    /// `info` | `warning` | `error` | `critical`. `error` and above set
    /// [`degraded_mode`].
    pub severity: String,
    /// Where to go to act on it, when there is such a place.
    pub action_url: Option<String>,
}

impl Warning {
    /// A condition an operator should look at, but which is not reducing service.
    pub fn advisory(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            severity: "warning".to_string(),
            action_url: None,
        }
    }

    /// A condition that IS reducing what this node does. Sets `degraded_mode`.
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            severity: "error".to_string(),
            action_url: None,
        }
    }

    /// A condition that threatens the node's continued operation. Sets
    /// `degraded_mode`.
    pub fn critical(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            severity: "critical".to_string(),
            action_url: None,
        }
    }

    /// Does this severity mean the node is not doing its whole job?
    #[must_use]
    pub fn is_degrading(&self) -> bool {
        matches!(self.severity.as_str(), "error" | "critical")
    }
}

/// The process-wide registry. A global rather than router state on purpose:
/// producers live all over the tree (the retention loop, a memory probe, a
/// replication reconciler) and the ONE consumer is the health surface. Threading
/// a handle to every producer would make raising a warning a plumbing exercise,
/// and a channel that is inconvenient to use goes unused — which is how the node
/// ends up silent again.
static WARNINGS: RwLock<Vec<Warning>> = RwLock::new(Vec::new());

/// # Every access here recovers from poisoning, and that is not laziness
///
/// A `RwLock` is POISONED when a thread panics while holding it. The obvious
/// `.expect("poisoned")` would then panic on every subsequent access — so one
/// transient panic anywhere in the process would permanently break the surface
/// whose entire job is REPORTING trouble, and it would break it by panicking
/// inside the health handler.
///
/// This module ships to iOS, Android, arm32 and Home Assistant add-ons, where a
/// crash loop is expensive and a health endpoint may be the only way anyone can
/// see what happened. The warning list is a plain `Vec` with no invariant a
/// panic could have corrupted mid-write, so taking the inner value is safe and
/// is strictly better than propagating the panic.
///
/// The same reasoning applies to every read of `/sys` and `/proc` below: they
/// return `Result`, never `unwrap`, and an unreadable or unparsable file
/// resolves to an explicit `Unavailable` state rather than a default number.
/// On iOS, Android, arm32 and Home Assistant add-ons those paths are variously
/// absent, sandboxed, or cgroup v1 — every one of which is a supported answer
/// here, not an error path.
///
/// # Why these reads are safe from an async handler, and safe WHEN WEDGED
///
/// `/sys/fs/cgroup/*` and `/proc/*` are kernel-virtual: a read is a formatted
/// snapshot of in-memory counters and touches no block device. So the probes do
/// not block the executor, and — the property that matters — they still answer
/// when the node is stalled on disk. An instrument that needed the disk to
/// report that the disk is stalled would be useless at exactly the moment it is
/// needed.
fn read_registry() -> std::sync::RwLockReadGuard<'static, Vec<Warning>> {
    WARNINGS.read().unwrap_or_else(|e| e.into_inner())
}

fn write_registry() -> std::sync::RwLockWriteGuard<'static, Vec<Warning>> {
    WARNINGS.write().unwrap_or_else(|e| e.into_inner())
}

/// Raise (or update) the warning under `code`. Idempotent: re-raising the same
/// code replaces its message rather than accumulating duplicates, so a probe on
/// a cadence can call this every pass without growing the list.
pub fn raise(w: Warning) {
    let mut guard = write_registry();
    match guard.iter_mut().find(|existing| existing.code == w.code) {
        Some(existing) => *existing = w,
        None => guard.push(w),
    }
}

/// Clear the warning under `code`. Returns whether one was present — callers
/// that want to log a RECOVERY can use it, and a recovery is worth logging: the
/// end of a degradation is as much news as its start.
pub fn clear(code: &str) -> bool {
    let mut guard = write_registry();
    let before = guard.len();
    guard.retain(|w| w.code != code);
    guard.len() != before
}

/// Every live warning, newest-raised last.
#[must_use]
pub fn snapshot() -> Vec<Warning> {
    read_registry().clone()
}

/// Is this node failing to do its whole job right now?
#[must_use]
pub fn degraded_mode() -> bool {
    read_registry().iter().any(Warning::is_degrading)
}

/// The single word for `data.status`: `"ok"` unless something is reduced.
///
/// Deliberately NOT "any warning makes it not-ok". A node with an advisory is
/// still doing its job, and a `status` that flips on advisories would be
/// ignored within a week.
#[must_use]
pub fn status_word() -> &'static str {
    if degraded_mode() {
        "degraded"
    } else {
        "ok"
    }
}

/// Test-only: empty the registry so cases do not leak into each other.
#[cfg(test)]
pub fn reset_for_test() {
    write_registry().clear();
}

// ─── The memory probe ────────────────────────────────────────────────────────

/// What this process is using against what it is allowed — or why we cannot say.
///
/// The three states are deliberately distinct. On 2026-08-23 the canonical sat
/// at 93% of its cgroup limit for minutes before each SIGKILL, and nothing on
/// the node could be asked that question: the number existed only in
/// `docker stats`, outside the process, invisible to `/health` and to every
/// remote watcher. A node that cannot report its own headroom cannot warn about
/// running out of it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum MemoryReading {
    /// Measured, with a ceiling to measure against.
    Limited {
        usage_bytes: u64,
        limit_bytes: u64,
        /// Usage as a percentage of the limit, one decimal.
        used_pct: f64,
    },
    /// Measured, but unbounded — no cgroup limit is set. NOT the same as
    /// healthy: an unlimited container is exactly how one process took the whole
    /// host down (CIRISServer#482), so this state is reported rather than
    /// rendered as a comfortable number.
    Unlimited { usage_bytes: u64 },
    /// Could not read the cgroup — not a container, an unexpected layout, or a
    /// permission problem. Says so; never reports 0.
    Unavailable { reason: String },
}

/// Warn at this fraction of the limit.
pub const MEMORY_WARN_PCT: f64 = 80.0;
/// Declare the node degraded at this fraction — close enough to the ceiling
/// that the kill is minutes away, which is what 93% turned out to mean.
pub const MEMORY_CRITICAL_PCT: f64 = 90.0;

const WARNING_CODE_MEMORY: &str = "resource.memory_pressure";

/// Read this process's cgroup memory usage and limit.
///
/// cgroup v2 first (`memory.current` / `memory.max`), then v1
/// (`memory.usage_in_bytes` / `memory.limit_in_bytes`). v1 reports "no limit" as
/// a sentinel near `u64::MAX` rather than a keyword, so an implausibly large
/// limit is read as unlimited — treating that sentinel as a real ceiling would
/// compute a reassuring 0.0% forever.
#[must_use]
pub fn read_memory() -> MemoryReading {
    fn num(path: &str) -> Option<u64> {
        std::fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    // cgroup v2
    if let Some(usage) = num("/sys/fs/cgroup/memory.current") {
        let raw = std::fs::read_to_string("/sys/fs/cgroup/memory.max").unwrap_or_default();
        let raw = raw.trim();
        if raw == "max" {
            return MemoryReading::Unlimited { usage_bytes: usage };
        }
        if let Ok(limit) = raw.parse::<u64>() {
            return bounded(usage, limit);
        }
        return MemoryReading::Unlimited { usage_bytes: usage };
    }

    // cgroup v1
    if let Some(usage) = num("/sys/fs/cgroup/memory/memory.usage_in_bytes") {
        match num("/sys/fs/cgroup/memory/memory.limit_in_bytes") {
            // v1's "unlimited" is a huge sentinel, not a word.
            Some(limit) if limit < (1u64 << 62) => return bounded(usage, limit),
            _ => return MemoryReading::Unlimited { usage_bytes: usage },
        }
    }

    MemoryReading::Unavailable {
        reason: "no cgroup v2 (memory.current) or v1 (memory/memory.usage_in_bytes) \
                 memory accounting found for this process"
            .to_string(),
    }
}

fn bounded(usage_bytes: u64, limit_bytes: u64) -> MemoryReading {
    let used_pct = if limit_bytes == 0 {
        0.0
    } else {
        ((usage_bytes as f64 / limit_bytes as f64) * 1000.0).round() / 10.0
    };
    MemoryReading::Limited {
        usage_bytes,
        limit_bytes,
        used_pct,
    }
}

/// Read memory and raise/clear `resource.memory_pressure` accordingly.
///
/// Returns the reading so a caller can report it alongside the verdict — the
/// number and the judgement travel together, so a reader never has to trust one
/// without seeing the other.
pub fn probe_memory() -> MemoryReading {
    let reading = read_memory();
    match &reading {
        MemoryReading::Limited {
            usage_bytes,
            limit_bytes,
            used_pct,
        } => {
            let mib = |b: &u64| *b as f64 / (1024.0 * 1024.0);
            if *used_pct >= MEMORY_CRITICAL_PCT {
                raise(Warning::critical(
                    WARNING_CODE_MEMORY,
                    format!(
                        "memory at {used_pct:.1}% of this container's limit \
                         ({:.0} MiB of {:.0} MiB) — the cgroup will SIGKILL this \
                         process, not slow it down. Reduce what this node holds \
                         (replication planes/peers) or raise the limit; a restart \
                         only resets the clock.",
                        mib(usage_bytes),
                        mib(limit_bytes),
                    ),
                ));
            } else if *used_pct >= MEMORY_WARN_PCT {
                raise(Warning::advisory(
                    WARNING_CODE_MEMORY,
                    format!(
                        "memory at {used_pct:.1}% of this container's limit \
                         ({:.0} MiB of {:.0} MiB) — headroom is thinning; there \
                         is no back-pressure between here and a SIGKILL.",
                        mib(usage_bytes),
                        mib(limit_bytes),
                    ),
                ));
            } else {
                clear(WARNING_CODE_MEMORY);
            }
        }
        // Unlimited and Unavailable raise nothing: neither is a pressure
        // reading. Both are REPORTED in the stats block, which is where the
        // absence belongs — an alarm on every dev laptop would train the
        // channel to be ignored.
        MemoryReading::Unlimited { .. } | MemoryReading::Unavailable { .. } => {
            clear(WARNING_CODE_MEMORY);
        }
    }
    reading
}

// ─── Contention: CPU, disk, and the kernel's own answer ──────────────────────

/// Pressure Stall Information for one resource — the fraction of the last ten
/// seconds during which work was BLOCKED on it.
///
/// # Why PSI rather than a utilization number
///
/// Utilization answers "how busy", which is the wrong question: a node at 100%
/// CPU doing useful work is healthy, and a node at 12% CPU with every thread
/// parked on a page fault is wedged. PSI answers "how much time was work
/// *stalled*", which is the thing an operator and a client actually feel.
///
/// Measured on the wedged production canonical while writing this, from inside
/// the container:
///
/// ```text
/// io.pressure   some avg10=26.98  full avg10=24.23
/// cpu.pressure  some avg10=22.50  full avg10=5.39
/// ```
///
/// `full avg10=24.23` on io means that for a quarter of that window **every**
/// task in the cgroup was stalled waiting for disk — which is precisely the
/// `wait_on_page_bit_common` parking that stopped futures being polled, expired
/// `reqwest` timeouts against a healthy network, and made the node unreachable
/// while it reported `ok`. The kernel knew. Nothing asked it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Pressure {
    /// Read successfully. `full_avg10` is `None` on kernels that do not report a
    /// `full` line for that resource (commonly CPU) — absent, never zero.
    Measured {
        some_avg10: f64,
        full_avg10: Option<f64>,
    },
    /// PSI is not exposed here (kernel < 4.20, `CONFIG_PSI` off, or an
    /// unexpected cgroup layout). Says so rather than reporting a calm 0.0.
    Unavailable { reason: String },
}

/// Work stalled this fraction of the last 10s ⇒ advisory.
pub const PRESSURE_WARN_SOME_PCT: f64 = 25.0;
/// EVERY task stalled this fraction of the last 10s ⇒ the node is not doing its
/// whole job. Calibrated against the live wedge: io `full` sat at 24.23% while
/// the node could not answer HTTP at all.
pub const PRESSURE_DEGRADE_FULL_PCT: f64 = 15.0;

/// Read `<resource>.pressure` for this cgroup, falling back to the host file.
///
/// cgroup-scoped first on purpose: `/proc/pressure/io` is the whole HOST, and a
/// noisy neighbour would make this node report a degradation it is not
/// suffering — and, worse, mask its own when the host is quiet.
#[must_use]
pub fn read_pressure(resource: &str) -> Pressure {
    let cgroup = format!("/sys/fs/cgroup/{resource}.pressure");
    let host = format!("/proc/pressure/{resource}");
    let text = std::fs::read_to_string(&cgroup)
        .or_else(|_| std::fs::read_to_string(&host))
        .ok();
    let Some(text) = text else {
        return Pressure::Unavailable {
            reason: format!(
                "neither {cgroup} nor {host} is readable (PSI off or not a cgroup v2 host)"
            ),
        };
    };
    let avg10 = |line_prefix: &str| -> Option<f64> {
        text.lines()
            .find(|l| l.starts_with(line_prefix))?
            .split_whitespace()
            .find_map(|f| f.strip_prefix("avg10="))?
            .parse()
            .ok()
    };
    match avg10("some") {
        Some(some_avg10) => Pressure::Measured {
            some_avg10,
            full_avg10: avg10("full"),
        },
        None => Pressure::Unavailable {
            reason: format!("{cgroup} had no parsable `some avg10=` line"),
        },
    }
}

/// Read CPU and IO pressure, raising/clearing `resource.cpu_stall` and
/// `resource.io_stall`.
///
/// Returns both readings so the surface reports the numbers beside the verdict.
pub fn probe_contention() -> (Pressure, Pressure) {
    let cpu = read_pressure("cpu");
    let io = read_pressure("io");
    judge(
        "cpu",
        "resource.cpu_stall",
        &cpu,
        "work is waiting for CPU. On a 2-vCPU node the runtime has a two-slot budget \
         before HTTP becomes unschedulable (CIRISServer#446) — reduce concurrent work \
         or give the node more cores.",
    );
    judge(
        "io",
        "resource.io_stall",
        &io,
        "work is waiting for DISK. This is what parks runtime threads in \
         wait_on_page_bit_common: futures stop being polled, client timeouts expire \
         against a healthy network, and the node stops answering while looking alive. \
         Reduce what this node reads per round (replication planes/peers) or give it \
         faster storage.",
    );
    (cpu, io)
}

fn judge(resource: &str, code: &'static str, p: &Pressure, remedy: &str) {
    let Pressure::Measured {
        some_avg10,
        full_avg10,
    } = p
    else {
        // Unavailable raises nothing — it is reported in the resources block.
        // An alarm for "this kernel has no PSI" would fire on every dev box.
        clear(code);
        return;
    };
    let full = full_avg10.unwrap_or(0.0);
    if full >= PRESSURE_DEGRADE_FULL_PCT {
        raise(Warning::error(
            code,
            format!(
                "{resource} stalled: EVERY task in this container was blocked on \
                 {resource} {full:.1}% of the last 10s (some {some_avg10:.1}%) — {remedy}"
            ),
        ));
    } else if *some_avg10 >= PRESSURE_WARN_SOME_PCT {
        raise(Warning::advisory(
            code,
            format!(
                "{resource} contention: work was blocked on {resource} \
                 {some_avg10:.1}% of the last 10s (full {full:.1}%) — {remedy}"
            ),
        ));
    } else {
        clear(code);
    }
}

/// **Network contention has no kernel pressure class**, and this module will not
/// invent one.
///
/// PSI covers cpu / io / memory. There is no `/proc/pressure/network`, and the
/// process-local proxies (retransmits, socket errors) measure the HOST's stack
/// rather than this node's mesh. The honest network signal already exists one
/// layer over: edge's round outcomes (`completed` / `refused` / `timed_out` /
/// `error`) and its link lifecycle — which is how CIRISEdge#532's churn was
/// caught, 29 establishes per minute across 20 links.
///
/// So this is a RAISE POINT, not a probe: whoever holds the `EdgeMetrics`
/// bundle calls it with what edge measured. Keeping it here means every
/// degradation reaches one registry and one health payload, while the
/// measurement stays with the component that can actually make it.
///
/// `timed_out` / `total` are the round-outcome counters for the window; the
/// caller decides the window.
pub fn report_network_rounds(timed_out: u64, total: u64) {
    const CODE: &str = "network.rounds_timing_out";
    if total == 0 {
        // No rounds ran. That is NOT "no timeouts" — it is a different fact,
        // and one this function must not launder into health. The caller that
        // knows why no rounds ran should say so with its own warning.
        clear(CODE);
        return;
    }
    let pct = (timed_out as f64 / total as f64) * 100.0;
    if pct >= 50.0 {
        raise(Warning::error(
            CODE,
            format!(
                "{timed_out} of {total} replication rounds timed out ({pct:.0}%) — this \
                 node is not converging with its peers. Check link churn and the \
                 withhold ledger before assuming the network: a stalled runtime \
                 expires its own timeouts against a healthy path."
            ),
        ));
    } else if pct >= 20.0 {
        raise(Warning::advisory(
            CODE,
            format!("{timed_out} of {total} replication rounds timed out ({pct:.0}%)."),
        ));
    } else {
        clear(CODE);
    }
}

/// **Cumulative counters are not a health reading.** This is the bridge.
///
/// Every counter on [`EdgeMetricsBundle`] is monotonic for the process
/// lifetime. Health is a question about NOW. Feeding a lifetime total to
/// [`report_network_rounds`] would mean a node that timed out badly during a
/// two-minute network partition on Tuesday still reads `degraded` on Friday —
/// and, worse, a node that is timing out RIGHT NOW but has a long healthy
/// history reads fine, because the fresh failures are diluted by a denominator
/// that only ever grows. Both errors are silent.
///
/// So the window lives here, in ONE place, rather than in each caller. The
/// previous snapshot is process-global for the same reason the registry is:
/// there is one edge runtime per process, and two callers differencing against
/// two different baselines would produce two different verdicts about the same
/// node.
static LAST_EDGE_COUNTERS: std::sync::Mutex<Option<EdgeCounters>> = std::sync::Mutex::new(None);

#[derive(Clone, Copy, Default)]
struct EdgeCounters {
    timed_out: u64,
    rounds_total: u64,
    backpressure_drops: u64,
}

/// Saturating difference. A counter that went BACKWARDS means the edge runtime
/// restarted and reset its metrics — the honest window is then "everything
/// since the restart", which is what a saturating subtract against a zeroed
/// baseline gives once the baseline is replaced below.
const fn window(now: u64, then: u64) -> u64 {
    now.saturating_sub(then)
}

/// Read edge's own round + back-pressure counters and raise what they say.
///
/// **Nothing here is re-derived.** Edge books `RoundOutcome` at the scheduler
/// and `replication_inbound_backpressure_drops` at the coordinator drain; this
/// differences those two counters and hands them to the raise points. Counting
/// rounds from this side would be a second implementation of a number edge
/// already owns — the [`crate::operator_surface`] rule, and the shape
/// CIRISPersist#541 cost a week.
///
/// Call it on a cadence from wherever the bundle is already in hand. The FIRST
/// call establishes the baseline and raises nothing: with no previous snapshot
/// the only available window is "since process start", which is the lifetime
/// total this function exists to avoid.
pub fn report_edge_metrics(bundle: &ciris_edge::observability::EdgeMetricsBundle) {
    use ciris_edge::observability::RoundOutcome;

    let now = EdgeCounters {
        timed_out: bundle
            .replication_round_outcomes_total
            .get(&RoundOutcome::TimedOut)
            .copied()
            .unwrap_or(0),
        // `sum()` would panic on overflow in a debug build. These are
        // free-running counters read on a health path that must not be able to
        // take a node down — on a 32-bit target (arm32, some Home Assistant
        // installs) an integer panic here would be an outage caused by the
        // instrument. Saturating is also the honest arithmetic: a total that
        // has run to u64::MAX is "more than any window cares about", not a
        // wrapped small number.
        rounds_total: bundle
            .replication_round_outcomes_total
            .values()
            .fold(0u64, |a, b| a.saturating_add(*b)),
        backpressure_drops: bundle.replication_inbound_backpressure_drops,
    };

    // Poison-recovering, like every other lock in this module: a panic in one
    // reporter must not blind the node for the rest of its life.
    let mut slot = LAST_EDGE_COUNTERS.lock().unwrap_or_else(|e| e.into_inner());
    let previous = slot.replace(now);
    drop(slot);

    let Some(previous) = previous else {
        // Baseline established. Raising nothing here is deliberate and is NOT
        // "all clear" — the very next call has a real window.
        return;
    };

    report_network_rounds(
        window(now.timed_out, previous.timed_out),
        window(now.rounds_total, previous.rounds_total),
    );
    report_backpressure_drops(window(now.backpressure_drops, previous.backpressure_drops));
}

/// **Back-pressure that DROPS is not back-pressure that holds** (CIRISEdge#373).
///
/// This is the counter behind "we need to be able to trust our backpressure".
/// A queue that fills and blocks is a system protecting itself; a queue that
/// fills and discards inbound frames is a system losing data while every
/// surface above it reports a successful round. Edge raised this from a silent
/// WARN to a counter precisely so it could be alarmed on, and it is the one
/// number here that should sit at exactly zero on a healthy node.
///
/// So there is no advisory band. Any drop inside the window is an error: the
/// frames are already gone, and the peer that sent them has no way to know.
pub fn report_backpressure_drops(dropped_in_window: u64) {
    const CODE: &str = "network.inbound_frames_dropped";
    if dropped_in_window == 0 {
        clear(CODE);
        return;
    }
    raise(Warning::error(
        CODE,
        format!(
            "{dropped_in_window} inbound replication frames were DROPPED on coordinator \
             back-pressure — rows a peer sent this node are gone, and the peer was not told. \
             This is data loss, not delay: the round can still report `completed`. A stalled \
             responder reply parks the drain, so look at what this node is slow to ANSWER \
             before looking at what it is slow to receive."
        ),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry is a PROCESS-GLOBAL and libtest runs cases in parallel
    /// threads of one process, so a `reset_for_test` in one case races a
    /// `raise` in another. Caught here by a count that read 2 where 1 was
    /// asserted — the same shape `oauth_state_matrix.rs` records, where a
    /// process-global env var leaked across rows and the PASSING row was the
    /// dangerous half. Every case that touches the global takes this lock.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Acquire the lock and start from empty. Returns the guard, which the
    /// caller must hold for the body of the test.
    fn exclusive() -> std::sync::MutexGuard<'static, ()> {
        let g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        g
    }

    /// **The first call must not alarm, and the second must.**
    ///
    /// The failure this pins is the one that makes cumulative counters
    /// dangerous in a health surface: if the baseline were treated as zero, a
    /// process whose edge had ever timed out would raise on its very first
    /// health read and stay raised, because the lifetime total is not a window.
    #[test]
    fn the_first_edge_report_establishes_a_baseline_and_raises_nothing() {
        use ciris_edge::observability::RoundOutcome;
        let _g = exclusive();
        *LAST_EDGE_COUNTERS.lock().unwrap_or_else(|e| e.into_inner()) = None;

        let mut bundle = ciris_edge::observability::EdgeMetrics::new().snapshot();
        // A long, ugly history: 90 of 100 rounds timed out before we ever looked.
        bundle
            .replication_round_outcomes_total
            .insert(RoundOutcome::TimedOut, 90);
        bundle
            .replication_round_outcomes_total
            .insert(RoundOutcome::Completed, 10);
        bundle.replication_inbound_backpressure_drops = 4_000;

        report_edge_metrics(&bundle);
        assert!(
            snapshot().is_empty(),
            "the first read has no window — it must establish a baseline silently, \
             not convict the process of its whole history: {:?}",
            snapshot()
        );

        // Second read, same counters: nothing happened SINCE, so nothing is wrong.
        report_edge_metrics(&bundle);
        assert!(
            snapshot().is_empty(),
            "an unchanged counter is an idle window, not a failing one: {:?}",
            snapshot()
        );

        // Now the window carries real failures.
        bundle
            .replication_round_outcomes_total
            .insert(RoundOutcome::TimedOut, 96);
        bundle
            .replication_round_outcomes_total
            .insert(RoundOutcome::Completed, 14);
        report_edge_metrics(&bundle);
        let raised = snapshot();
        let codes: Vec<&str> = raised.iter().map(|w| w.code.as_str()).collect();
        assert!(
            codes.contains(&"network.rounds_timing_out"),
            "6 of 10 rounds in the window timed out and nothing was raised: {codes:?}"
        );
        assert!(degraded_mode(), "a 60% timeout window is not an advisory");
    }

    /// **A dropped inbound frame has no advisory band.**
    ///
    /// Back-pressure that discards is data loss with a `completed` round on top
    /// of it — the peer is never told. One drop is an error.
    #[test]
    fn any_backpressure_drop_in_the_window_is_an_error_and_recovery_clears_it() {
        let _g = exclusive();

        report_backpressure_drops(1);
        assert!(
            degraded_mode(),
            "a single dropped inbound frame is lost data, not a hint: {:?}",
            snapshot()
        );

        report_backpressure_drops(0);
        assert!(
            !degraded_mode(),
            "a clean window must take the alarm DOWN — a warning that only ever \
             goes up is one operators learn to ignore: {:?}",
            snapshot()
        );
    }

    /// A counter that went backwards means edge restarted and zeroed its
    /// metrics. The window must not underflow into a colossal false alarm.
    #[test]
    fn a_counter_reset_does_not_underflow_into_a_false_alarm() {
        use ciris_edge::observability::RoundOutcome;
        let _g = exclusive();
        *LAST_EDGE_COUNTERS.lock().unwrap_or_else(|e| e.into_inner()) = None;

        let mut bundle = ciris_edge::observability::EdgeMetrics::new().snapshot();
        bundle
            .replication_round_outcomes_total
            .insert(RoundOutcome::Completed, 5_000);
        bundle.replication_inbound_backpressure_drops = 77;
        report_edge_metrics(&bundle);

        // Edge restarted: every counter is back to zero.
        let fresh = ciris_edge::observability::EdgeMetrics::new().snapshot();
        report_edge_metrics(&fresh);
        assert!(
            snapshot().is_empty(),
            "a metrics reset must read as an empty window, never as u64 wraparound: {:?}",
            snapshot()
        );
    }

    /// The registry's contract, and the reason `degraded_mode` is not "any
    /// warning": an advisory must not flip the flag, or the flag stops meaning
    /// "this node is not doing its whole job" within a week of shipping.
    #[test]
    fn advisories_do_not_degrade_but_errors_do() {
        let _g = exclusive();
        assert_eq!(status_word(), "ok");
        assert!(!degraded_mode());

        raise(Warning::advisory("t.advisory", "look at this soon"));
        assert!(!degraded_mode(), "a `warning` severity must not degrade");
        assert_eq!(status_word(), "ok");
        assert_eq!(snapshot().len(), 1, "but it IS reported");

        raise(Warning::error("t.reduced", "a plane is shed"));
        assert!(degraded_mode());
        assert_eq!(status_word(), "degraded");

        assert!(clear("t.reduced"));
        assert!(!degraded_mode(), "clearing the error restores ok");
        assert_eq!(status_word(), "ok");
        reset_for_test();
    }

    /// Raising the same code twice REPLACES it. A probe on a cadence calls this
    /// every pass; without idempotence the list grows without bound and the
    /// surface that exists to report trouble becomes trouble.
    #[test]
    fn re_raising_a_code_replaces_rather_than_accumulates() {
        let _g = exclusive();
        raise(Warning::advisory("t.same", "first"));
        raise(Warning::advisory("t.same", "second"));
        let snap = snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].message, "second");
        reset_for_test();
    }

    /// **Cannot-measure is not healthy.** The three memory states are distinct
    /// by construction; none of them renders as a comfortable zero. This is the
    /// same discipline the trace plane needed (`Unreadable` != `NeverAdmitted`)
    /// and that retention needed (`WithinBounds` != `BoundUnenforceable`).
    #[test]
    fn the_memory_states_are_distinguishable_and_none_is_a_silent_zero() {
        let unavailable = MemoryReading::Unavailable {
            reason: "no cgroup".into(),
        };
        let unlimited = MemoryReading::Unlimited { usage_bytes: 1 };
        let limited = MemoryReading::Limited {
            usage_bytes: 1,
            limit_bytes: 2,
            used_pct: 50.0,
        };
        assert_ne!(unavailable, unlimited);
        assert_ne!(unlimited, limited);

        // And they serialize to distinguishable shapes — a reader must be able
        // to tell them apart on the wire, not only in Rust.
        let s = |m: &MemoryReading| serde_json::to_value(m).expect("serialize");
        assert_eq!(s(&unavailable)["state"], "unavailable");
        assert_eq!(s(&unlimited)["state"], "unlimited");
        assert_eq!(s(&limited)["state"], "limited");
        assert!(
            s(&unavailable).get("usage_bytes").is_none(),
            "an unreadable cgroup must not report a usage number at all — \
             reporting 0 is exactly the lie this type exists to prevent"
        );
    }

    /// The thresholds bracket the failure that motivated them: the canonical sat
    /// at 93% for minutes before each SIGKILL, so 93% must be CRITICAL — and a
    /// node at half its limit must stay quiet or the channel trains people to
    /// ignore it.
    // These compare constants, which clippy correctly notes is decidable at
    // compile time. They are kept as a TEST because the assertion messages are
    // the artifact: they record why 80/90 are the numbers, against the incident
    // that chose them. A future edit that inverts them fails here reading the
    // reason, rather than silently shipping a probe that cannot warn in time.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn the_thresholds_bracket_the_kill_that_motivated_them() {
        assert!(MEMORY_WARN_PCT < MEMORY_CRITICAL_PCT);
        assert!(
            93.0 >= MEMORY_CRITICAL_PCT,
            "93% of the limit was ~2 minutes from a SIGKILL on the production \
             canonical; if that is not critical this probe is decoration"
        );
        assert!(
            50.0 < MEMORY_WARN_PCT,
            "a node at half its limit is healthy and must not warn"
        );
    }

    /// **Nothing here may panic on a platform that lacks these files.** This
    /// ships to iOS, Android, arm32 and Home Assistant add-ons, where
    /// `/sys/fs/cgroup` is variously absent, sandboxed, or cgroup v1. A probe
    /// that panicked on a missing file would take down the surface whose job is
    /// to report trouble — and would do it inside the health handler.
    #[test]
    fn probes_never_panic_and_degrade_to_unavailable_off_linux() {
        let _g = exclusive();

        // A resource with no PSI file anywhere must report Unavailable, with a
        // reason — never a calm 0.0, never a panic.
        match read_pressure("not-a-real-resource-xyz") {
            Pressure::Unavailable { reason } => assert!(
                !reason.is_empty(),
                "Unavailable must say WHY, or it is indistinguishable from silence"
            ),
            other => panic!("a missing PSI file must be Unavailable, got {other:?}"),
        }

        // The real probes must return on ANY host — cgroup v2, v1, or none —
        // without unwinding. The values differ by platform; the not-panicking
        // does not.
        let _ = read_memory();
        let _ = probe_memory();
        let (_cpu, _io) = probe_contention();

        // Degenerate inputs that would divide by zero if unguarded.
        report_network_rounds(0, 0);
        report_network_rounds(5, 0);
        assert!(
            !snapshot()
                .iter()
                .any(|w| w.code == "network.rounds_timing_out"),
            "zero rounds is not a timeout rate — it must raise nothing"
        );
        reset_for_test();
    }

    /// The wire shape is the one the client has always parsed. If a field is
    /// renamed here, the client silently stops seeing warnings — it reads by
    /// key and defaults to empty.
    #[test]
    fn the_warning_wire_shape_matches_what_the_client_parses() {
        let w = Warning::critical("resource.memory_pressure", "at the ceiling");
        let v = serde_json::to_value(&w).expect("serialize");
        for key in ["code", "message", "severity", "action_url"] {
            assert!(
                v.get(key).is_some(),
                "the client reads `{key}` off each warning \
                 (CIRISApiClient.systemHealth); dropping it makes the warning invisible"
            );
        }
        assert_eq!(v["severity"], "critical");
    }
}
