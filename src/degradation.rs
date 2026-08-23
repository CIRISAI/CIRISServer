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
// NOTE: `status_word()` used to live here, composed from `degraded_mode()`.
// It was DELETED rather than kept for convenience: its only purpose was to be
// put in a payload beside the other two, and doing that takes three separate
// read locks — the torn read `verdict()` exists to prevent (PR #483 review).
// A helper whose only correct use is the one thing you must not do is a trap,
// not an API.
//
// The two below stay: asking ONE question is fine, and the tests do. Composing
// them into one payload is not — use `verdict()`.
pub fn snapshot() -> Vec<Warning> {
    read_registry().clone()
}

/// Is this node failing to do its whole job right now?
#[must_use]
pub fn degraded_mode() -> bool {
    read_registry().iter().any(Warning::is_degrading)
}

/// The three verdict fields, derived from ONE read of the registry.
///
/// `snapshot()` and `degraded_mode()` each take their own read
/// lock. A reporter raising or clearing between them produces a torn response —
/// `degraded` with an empty `warnings` list, or an error warning sitting beside
/// `degraded_mode: false` (codex review, PR #483). Both are worse than either
/// truth: a watcher cannot act on the first and will not act on the second.
///
/// Producers run on their own cadences (the retention loop, the reconcile tick)
/// with no relationship to when a health request arrives, so the interleaving
/// is ordinary rather than exotic.
///
/// One lock, one instant, three fields that agree by construction.
#[must_use]
pub fn verdict() -> (Vec<Warning>, bool, &'static str) {
    let guard = read_registry();
    let degraded = guard.iter().any(Warning::is_degrading);
    let warnings = guard.clone();
    drop(guard);
    (warnings, degraded, if degraded { "degraded" } else { "ok" })
}

/// **Absence of evidence is not evidence of recovery** (codex review, PR #483).
///
/// `clear` is for a SUCCESSFUL measurement that came back healthy. When a probe
/// cannot measure at all — the cgroup file vanished, PSI was turned off, no
/// replication round ran in the window — there is nothing to clear WITH, and
/// calling `clear` there converts "we stopped being able to look" into "the
/// problem is gone".
///
/// That is the worst possible moment to go quiet: observability is lost exactly
/// when something is going wrong, and a transient permission or mount failure
/// would turn a known degradation into `status: "ok"`.
///
/// So a no-evidence path calls THIS, which leaves any standing warning
/// standing. It is a deliberate no-op with a name, so the call site reads as a
/// decision rather than an omission — an empty statement here would be
/// indistinguishable from a forgotten one, and the reviewer of the next change
/// could not tell them apart.
///
/// The trade-off is real and is the right way round: a node whose probe breaks
/// permanently keeps its last verdict, which is loud, rather than falling
/// silent, which is not. A code raised by a probe that can no longer run is
/// cleared by that probe measuring healthy again — never by it failing.
pub(crate) fn no_evidence(_code: &str) {}

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
/// Resolve the accounting directory for THIS process, not the hierarchy root.
///
/// **The defect this closes (codex review, PR #483).** Reading
/// `/sys/fs/cgroup/memory.current` directly is correct only when the process
/// has a private cgroup namespace — a container. Under systemd, which is how
/// #480 and #482 describe the box that actually died, the process lives at
/// `/system.slice/ciris-server.service` while the root files still exist and
/// describe the WHOLE HOST. The probe then reported host-wide usage against a
/// root `memory.max` of `max`, so a `MemoryMax=` on the unit was invisible and
/// the alarm this module exists to raise could never fire on the deployment
/// that needed it most.
///
/// `/proc/self/cgroup` names the path; v2 emits a single `0::/<path>` line, v1
/// a `N:memory:/<path>` line. The mount point is the conventional
/// `/sys/fs/cgroup` — and when the resolved directory is not readable (a
/// namespaced container reports a path it cannot see), the ROOT is the correct
/// fallback, because in that case the root files really are this process's.
fn cgroup_relative_path(controller: Option<&str>) -> Option<String> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    for line in text.lines() {
        let mut parts = line.splitn(3, ':');
        let (_id, ctrls, path) = (parts.next()?, parts.next()?, parts.next()?);
        let matches = match controller {
            // v2: the unified line has an empty controller field.
            None => ctrls.is_empty(),
            Some(c) => ctrls.split(',').any(|x| x == c),
        };
        if matches {
            let p = path.trim_start_matches('/');
            return Some(p.to_string());
        }
    }
    None
}

/// The first of `candidates` that contains `probe`, else `None`.
fn first_dir_with(candidates: &[String], probe: &str) -> Option<String> {
    candidates
        .iter()
        .find(|d| std::path::Path::new(&format!("{d}/{probe}")).exists())
        .cloned()
}

#[must_use]
pub fn read_memory() -> MemoryReading {
    fn num(path: &str) -> Option<u64> {
        std::fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    // ── cgroup v2 ────────────────────────────────────────────────────────────
    // This process's own directory first, the root only as the fallback that is
    // correct inside a cgroup namespace.
    let mut v2: Vec<String> = Vec::new();
    if let Some(rel) = cgroup_relative_path(None) {
        if !rel.is_empty() {
            v2.push(format!("/sys/fs/cgroup/{rel}"));
        }
    }
    v2.push("/sys/fs/cgroup".to_string());

    if let Some(dir) = first_dir_with(&v2, "memory.current") {
        if let Some(usage) = num(&format!("{dir}/memory.current")) {
            let max_path = format!("{dir}/memory.max");
            return match std::fs::read_to_string(&max_path) {
                Ok(raw) => {
                    let raw = raw.trim();
                    if raw == "max" {
                        // POSITIVELY unlimited: the kernel said so in words.
                        MemoryReading::Unlimited { usage_bytes: usage }
                    } else if let Ok(limit) = raw.parse::<u64>() {
                        bounded(usage, limit)
                    } else {
                        // Readable but not parsable. NOT unlimited — we do not
                        // know, and saying "unlimited" would be a fact invented
                        // from a failed read.
                        MemoryReading::Unavailable {
                            reason: format!(
                                "{max_path} is readable but holds {raw:?}, which is neither \
                                 `max` nor a byte count — the limit is unknown, which is not \
                                 the same as absent"
                            ),
                        }
                    }
                }
                Err(e) => MemoryReading::Unavailable {
                    reason: format!(
                        "{max_path} could not be read ({e}) — usage is {usage} bytes but the \
                         LIMIT is unknown. Reporting this as unlimited would assert that no \
                         ceiling is configured on the evidence of a failed read."
                    ),
                },
            };
        }
    }

    // ── cgroup v1 ────────────────────────────────────────────────────────────
    let mut v1: Vec<String> = Vec::new();
    if let Some(rel) = cgroup_relative_path(Some("memory")) {
        if !rel.is_empty() {
            v1.push(format!("/sys/fs/cgroup/memory/{rel}"));
        }
    }
    v1.push("/sys/fs/cgroup/memory".to_string());

    if let Some(dir) = first_dir_with(&v1, "memory.usage_in_bytes") {
        if let Some(usage) = num(&format!("{dir}/memory.usage_in_bytes")) {
            let limit_path = format!("{dir}/memory.limit_in_bytes");
            return match num(&limit_path) {
                // v1's "unlimited" is a huge sentinel, not a word — and it IS a
                // positive answer, so it stays `Unlimited`.
                Some(limit) if limit >= (1u64 << 62) => {
                    MemoryReading::Unlimited { usage_bytes: usage }
                }
                Some(limit) => bounded(usage, limit),
                None => MemoryReading::Unavailable {
                    reason: format!(
                        "{limit_path} could not be read or parsed — usage is {usage} bytes but \
                         the LIMIT is unknown, which is not the same as unlimited"
                    ),
                },
            };
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
        // Unlimited raises nothing AND clears: a process with no ceiling
        // cannot be at a percentage of one, and that is a real measurement —
        // the kernel said `max` in words (or v1's sentinel). Positive evidence,
        // so a stale alarm from a previously-limited run comes down.
        MemoryReading::Unlimited { .. } => {
            clear(WARNING_CODE_MEMORY);
        }
        // Unavailable is NOT that. We could not measure, so we have learned
        // nothing about whether the earlier pressure went away — see
        // `no_evidence`. Both states are REPORTED in the resources block, which
        // is where the absence belongs; an alarm for "this laptop has no
        // cgroup" would train the channel to be ignored.
        MemoryReading::Unavailable { .. } => {
            no_evidence(WARNING_CODE_MEMORY);
        }
    }
    reading
}

// ─── Contention: CPU, disk, and the kernel's own answer ──────────────────────

/// Where a PSI reading came from — and therefore what it is a statement ABOUT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureScope {
    /// Read from this process's own cgroup — the reading describes THIS node.
    Cgroup,
    /// Read from `/proc/pressure/*`, which describes the WHOLE HOST.
    ///
    /// A noisy neighbour shows up here. The verdict must not be worded as, or
    /// escalated to, a statement about this node (codex review, PR #483): a
    /// responsive node would otherwise advertise degradation and advise
    /// reducing its own workload because something else on the box is thrashing.
    Host,
}

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
        /// WHOSE stall this is. Host-scoped readings describe the box, not this
        /// node, and are never escalated to a degradation (PR #483 review).
        scope: PressureScope,
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
    // THIS PROCESS'S cgroup, not the hierarchy root — the same defect the memory
    // probe carried (see `cgroup_relative_path`). Reading
    // `/sys/fs/cgroup/io.pressure` under systemd gets the ROOT cgroup's file,
    // which is host-wide, and this function would then label it `Cgroup` scope:
    // a host reading wearing a container reading's name, which is worse than
    // the honest `Host` fallback because `judge` trusts the label and escalates
    // it to a degradation.
    let scoped = cgroup_relative_path(None)
        .filter(|rel| !rel.is_empty())
        .map(|rel| format!("/sys/fs/cgroup/{rel}/{resource}.pressure"));
    let cgroup = scoped.unwrap_or_else(|| format!("/sys/fs/cgroup/{resource}.pressure"));
    let host = format!("/proc/pressure/{resource}");
    let (text, scope) = match std::fs::read_to_string(&cgroup) {
        Ok(t) => (Some(t), PressureScope::Cgroup),
        // The fallback answers a DIFFERENT question — "is this box stalling?"
        // rather than "is this node stalling?" — so the scope travels with the
        // number instead of being forgotten at the read.
        Err(_) => (std::fs::read_to_string(&host).ok(), PressureScope::Host),
    };
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
            scope,
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
        "host.cpu_contention",
        &cpu,
        "work is waiting for CPU. On a 2-vCPU node the runtime has a two-slot budget \
         before HTTP becomes unschedulable (CIRISServer#446) — reduce concurrent work \
         or give the node more cores.",
    );
    judge(
        "io",
        "resource.io_stall",
        "host.io_contention",
        &io,
        "work is waiting for DISK. This is what parks runtime threads in \
         wait_on_page_bit_common: futures stop being polled, client timeouts expire \
         against a healthy network, and the node stops answering while looking alive. \
         Reduce what this node reads per round (replication planes/peers) or give it \
         faster storage.",
    );
    (cpu, io)
}

/// Raise or clear the stall verdict for one resource.
///
/// **Two codes, because they are two different claims** (found in self-review
/// after the PR #483 scope fix). `code` says "THIS NODE is stalling" and can
/// degrade; `host_code` says "this BOX is contended" and never can.
///
/// One shared code had two failures, both in the dangerous direction, and both
/// only reachable when the scoped file goes away mid-flight — a container
/// reconfigured, a cgroup moved:
///
///   * the host fallback with a QUIET host called `clear`, taking down a
///     cgroup-scoped degradation on evidence about a different subject;
///   * a host ADVISORY raise replaced a standing cgroup ERROR on the same code,
///     so a noisy neighbour could DOWNGRADE a genuinely stalling node.
///
/// Split, each scope owns its own code and can neither clear nor overwrite the
/// other's. A scope we did not read this pass gets `no_evidence`, not a clear.
fn judge(resource: &str, code: &'static str, host_code: &'static str, p: &Pressure, remedy: &str) {
    let Pressure::Measured {
        scope,
        some_avg10,
        full_avg10,
    } = p
    else {
        // Unavailable raises nothing — it is reported in the resources block,
        // and an alarm for "this kernel has no PSI" would fire on every dev
        // box. But it does not CLEAR either: PSI going away tells us nothing
        // about whether the stall went away. See `no_evidence`. Neither scope
        // was read, so neither verdict moves.
        no_evidence(code);
        no_evidence(host_code);
        return;
    };
    let full = full_avg10.unwrap_or(0.0);

    // HOST-SCOPED READINGS ARE NEVER A DEGRADATION (codex review, PR #483).
    //
    // `/proc/pressure/*` describes the whole box. On a cgroup-v1 container —
    // or anywhere the scoped file is missing — a noisy neighbour would
    // otherwise make a perfectly responsive node report itself degraded and
    // advise reducing ITS OWN workload, which is both false and actively
    // misleading. So a host reading is reported, attributed, and capped at
    // advisory; only a cgroup-scoped reading can say "this node".
    if *scope == PressureScope::Host {
        // We reached the host file only BECAUSE the scoped one was unreadable,
        // so this pass has no evidence about this node — its verdict stands
        // untouched rather than being cleared by a fact about the box.
        no_evidence(code);
        if full >= PRESSURE_DEGRADE_FULL_PCT || *some_avg10 >= PRESSURE_WARN_SOME_PCT {
            raise(Warning::advisory(
                host_code,
                format!(
                    "{resource} contention ON THIS HOST: work somewhere on the box was blocked \
                     on {resource} {some_avg10:.1}% of the last 10s (full {full:.1}%). This is \
                     the HOST-WIDE reading — no per-cgroup {resource}.pressure was available — \
                     so it may be a neighbour rather than this node, and it is reported without \
                     degrading this node. {remedy}"
                ),
            ));
        } else {
            clear(host_code);
        }
        return;
    }

    // A cgroup reading says nothing about the box, so the host verdict stands.
    no_evidence(host_code);

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
pub fn report_network_rounds(w: RoundWindow) {
    const CODE: &str = "network.rounds_timing_out";
    let total = w.total;
    if total == 0 {
        // No rounds ran. That is NOT "no timeouts" — it is a different fact,
        // and one this function must not launder into health.
        //
        // The first cut CLEARED here, and the doc two lines up already said why
        // that was wrong: the comment and the code disagreed, and the code won.
        // Replication rounds can be slower than the reconcile cadence that
        // samples them, so a genuinely failing node produces empty windows
        // routinely — and every one of them would have taken the alarm down
        // before an operator ever polled health.
        //
        // The caller that knows WHY no rounds ran should say so with its own
        // warning; this one keeps its last verdict until a non-empty window
        // demonstrates recovery.
        no_evidence(CODE);
        return;
    }

    // **FAILURE IS `total - completed`, NOT `timed_out`** (codex review,
    // PR #483). The first cut keyed solely on the timeout counter while
    // dividing by every outcome, so a window of pure `Error` rounds — a
    // transport or protocol abort, nothing reaching the wire — computed 0% and
    // CLEARED the alarm. A node where no round completes at all would have read
    // healthy, which is the worst possible reading of that state.
    //
    // Derived by subtraction rather than by summing the failure variants on
    // purpose: a RoundOutcome added to edge tomorrow lands in the failure count
    // by default and shows up, instead of being silently treated as success by
    // a match arm nobody remembered to extend.
    let failed = total.saturating_sub(w.completed);
    let pct = (failed as f64 / total as f64) * 100.0;
    // Named per-outcome so the remedy differs: timeouts point at the path or a
    // stalled runtime, errors at transport/protocol, refusals at peer state.
    let breakdown = format!(
        "timed_out={} refused={} error={} completed={}",
        w.timed_out, w.refused, w.error, w.completed
    );
    if pct >= 50.0 {
        raise(Warning::error(
            CODE,
            format!(
                "{failed} of {total} replication rounds did not complete ({pct:.0}%; \
                 {breakdown}) — this node is not converging with its peers. Check link \
                 churn and the withhold ledger before assuming the network: a stalled \
                 runtime expires its own timeouts against a healthy path, and an `error` \
                 round aborted on transport or protocol before it could."
            ),
        ));
    } else if pct >= 20.0 {
        raise(Warning::advisory(
            CODE,
            format!(
                "{failed} of {total} replication rounds did not complete ({pct:.0}%; \
                 {breakdown})."
            ),
        ));
    } else {
        clear(CODE);
    }
}

/// One window's replication-round outcomes.
///
/// Carried as a struct rather than two numbers because the VERDICT and the
/// REMEDY need different things from it: convergence is `completed` against
/// `total`, but what an operator should go and do differs per outcome —
/// timeouts point at the path or a stalled runtime, `error` at transport or
/// protocol, `refused` at peer state. Collapsing them at the call site threw
/// that away before the message could use it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RoundWindow {
    pub completed: u64,
    pub timed_out: u64,
    pub refused: u64,
    pub error: u64,
    pub total: u64,
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
    completed: u64,
    timed_out: u64,
    refused: u64,
    error: u64,
    rounds_total: u64,
    backpressure_drops: u64,
}

/// The window between two reads of one counter.
///
/// A counter that went BACKWARDS means the edge runtime restarted and zeroed
/// its metrics. The honest window is then "everything since the restart" —
/// i.e. `now` itself, measured from zero.
///
/// **The first cut wrote `now.saturating_sub(then)` and a doc claiming exactly
/// the behaviour above** (codex review, PR #483). Saturating returns 0 for any
/// counter that moved backwards, so a runtime that restarted and then failed
/// before the next sample had those failures silently discarded — permanently,
/// because the post-restart snapshot becomes the new baseline. The comment
/// described the right rule and the code did the opposite, which is worse than
/// either alone: it reads as considered.
///
/// The saturation still matters for the ordinary case, where it prevents an
/// underflow panic on a 32-bit debug build.
const fn window(now: u64, then: u64) -> u64 {
    if now < then {
        // Reset detected: everything the counter holds was accumulated after
        // the restart, so all of it belongs to this window.
        now
    } else {
        now - then
    }
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

    let at = |o: RoundOutcome| -> u64 {
        bundle
            .replication_round_outcomes_total
            .get(&o)
            .copied()
            .unwrap_or(0)
    };
    let now = EdgeCounters {
        completed: at(RoundOutcome::Completed),
        timed_out: at(RoundOutcome::TimedOut),
        refused: at(RoundOutcome::Refused),
        error: at(RoundOutcome::Error),
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

    report_network_rounds(RoundWindow {
        completed: window(now.completed, previous.completed),
        timed_out: window(now.timed_out, previous.timed_out),
        refused: window(now.refused, previous.refused),
        error: window(now.error, previous.error),
        total: window(now.rounds_total, previous.rounds_total),
    });
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
        // Unlike the rounds ratio, a zero here IS a measurement: the counter was
        // read at both ends of the window and did not move. Nothing was
        // dropped, so the alarm comes down.
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

    /// **An empty window must not clear a standing timeout alarm**
    /// (codex review, PR #483).
    ///
    /// Replication rounds can be slower than the reconcile cadence that samples
    /// them, so a genuinely failing node produces empty windows routinely. If
    /// `(0, 0)` cleared, every one of them would take the alarm down before an
    /// operator ever polled health — the alarm would be least visible exactly
    /// when it was most true.
    #[test]
    fn an_empty_window_neither_raises_nor_clears() {
        let _g = exclusive();

        report_network_rounds(RoundWindow {
            timed_out: 9,
            completed: 1,
            total: 10,
            ..Default::default()
        });
        assert!(degraded_mode(), "fixture: 9/10 timing out must degrade");

        report_network_rounds(RoundWindow {
            timed_out: 0,
            completed: 0,
            total: 0,
            ..Default::default()
        });
        assert!(
            degraded_mode(),
            "an EMPTY window cleared a standing timeout alarm. No rounds ran, so nothing was \
             learned about recovery — and this function's own doc says so two lines above the \
             code that did it: {:?}",
            snapshot()
        );

        // Only a real, healthy window takes it down.
        report_network_rounds(RoundWindow {
            timed_out: 0,
            completed: 10,
            total: 10,
            ..Default::default()
        });
        assert!(
            !degraded_mode(),
            "10 rounds with no timeouts is positive evidence of recovery and must clear: {:?}",
            snapshot()
        );
    }

    /// **A probe that cannot measure must not clear what it previously found.**
    ///
    /// A transient permission, mount, or kernel-interface failure would
    /// otherwise turn a known degradation into `status: "ok"` at precisely the
    /// moment observability is lost.
    #[test]
    fn an_unavailable_probe_leaves_a_standing_alarm_standing() {
        let _g = exclusive();

        raise(Warning::critical("resource.cpu_stall", "measured, and bad"));
        judge(
            "cpu",
            "resource.cpu_stall",
            "host.cpu_contention",
            &Pressure::Unavailable {
                reason: "PSI turned off mid-flight".to_string(),
            },
            "remedy",
        );
        assert!(
            degraded_mode(),
            "losing the ability to measure was reported as the problem going away: {:?}",
            snapshot()
        );

        // A healthy MEASUREMENT is what clears it.
        judge(
            "cpu",
            "resource.cpu_stall",
            "host.cpu_contention",
            &Pressure::Measured {
                scope: PressureScope::Cgroup,
                some_avg10: 0.0,
                full_avg10: Some(0.0),
            },
            "remedy",
        );
        assert!(
            !degraded_mode(),
            "a healthy measurement must clear: {:?}",
            snapshot()
        );
    }

    /// **Host-wide PSI is never this node's degradation.**
    ///
    /// A noisy neighbour on a cgroup-v1 container would otherwise make a
    /// perfectly responsive node advertise degradation and advise reducing its
    /// own workload.
    #[test]
    fn host_scoped_pressure_is_reported_but_never_degrades_this_node() {
        let _g = exclusive();

        let brutal = |scope| Pressure::Measured {
            scope,
            some_avg10: 99.0,
            full_avg10: Some(99.0),
        };

        judge(
            "io",
            "resource.io_stall",
            "host.io_contention",
            &brutal(PressureScope::Host),
            "remedy",
        );
        let raised = snapshot();
        assert_eq!(
            raised.len(),
            1,
            "the host reading must still be REPORTED: {raised:?}"
        );
        assert!(
            !degraded_mode(),
            "a HOST-WIDE reading degraded this node. It may be a neighbour, and the node would \
             be advising an operator to reduce a workload that is not the cause: {raised:?}"
        );
        assert!(
            raised[0].message.contains("HOST"),
            "a host reading must say so in the message, or an operator reads it as this \
             container's: {:?}",
            raised[0].message
        );

        // The identical numbers, cgroup-scoped, DO degrade.
        judge(
            "io",
            "resource.io_stall",
            "host.io_contention",
            &brutal(PressureScope::Cgroup),
            "remedy",
        );
        assert!(
            degraded_mode(),
            "the same stall measured on THIS node's cgroup must degrade it: {:?}",
            snapshot()
        );
    }

    /// **A window of pure ERRORS is not a healthy window** (codex review,
    /// PR #483).
    ///
    /// The first cut keyed on the timeout counter alone while dividing by every
    /// outcome, so rounds that aborted on transport or protocol counted in the
    /// denominator and nowhere else. A node where NOTHING completed computed 0%
    /// and cleared its alarm — the worst possible reading of that state.
    #[test]
    fn rounds_that_error_or_are_refused_count_as_failures_not_successes() {
        let _g = exclusive();

        // Ten rounds, none completed, none timed out.
        report_network_rounds(RoundWindow {
            error: 7,
            refused: 3,
            total: 10,
            ..Default::default()
        });
        let standing = snapshot();
        assert!(
            degraded_mode(),
            "not one round completed and the node reported healthy, because none of them \
             happened to TIME OUT: {standing:?}"
        );
        assert!(
            standing[0].message.contains("error=7") && standing[0].message.contains("refused=3"),
            "the verdict must name the outcomes — a timeout points at the path, an error at \
             transport, a refusal at peer state, and the operator does different things: {:?}",
            standing[0].message
        );

        // Every round completing is the only thing that clears it.
        report_network_rounds(RoundWindow {
            completed: 10,
            total: 10,
            ..Default::default()
        });
        assert!(
            !degraded_mode(),
            "a fully converged window must clear: {:?}",
            snapshot()
        );
    }

    /// A future `RoundOutcome` must land in the FAILURE count by default.
    ///
    /// Failure is derived as `total - completed` rather than by summing the
    /// failure variants, precisely so an outcome edge adds tomorrow shows up
    /// instead of being silently treated as success by a match arm nobody
    /// remembered to extend.
    #[test]
    fn an_unknown_future_outcome_counts_as_a_failure_not_a_success() {
        let _g = exclusive();
        // `total` exceeds the sum of the named variants: the excess stands in
        // for an outcome this build does not know about.
        report_network_rounds(RoundWindow {
            completed: 1,
            timed_out: 0,
            refused: 0,
            error: 0,
            total: 10,
        });
        assert!(
            degraded_mode(),
            "nine rounds resolved as something this build cannot name, and they were counted \
             as successes: {:?}",
            snapshot()
        );
    }

    /// **A quiet HOST must not clear a stalling NODE, and must not downgrade
    /// it either** (self-review after the PR #483 scope fix).
    ///
    /// Reachable whenever the scoped file goes away mid-flight — a container
    /// reconfigured, a cgroup moved. With one shared code, the host fallback
    /// either cleared the cgroup verdict outright or replaced a standing ERROR
    /// with its own ADVISORY, so a neighbour could downgrade a genuinely
    /// stalling node. Both failures are in the dangerous direction.
    #[test]
    fn a_host_reading_can_neither_clear_nor_downgrade_a_node_scoped_stall() {
        let _g = exclusive();

        // The node is genuinely stalling, measured on its own cgroup.
        judge(
            "io",
            "resource.io_stall",
            "host.io_contention",
            &Pressure::Measured {
                scope: PressureScope::Cgroup,
                some_avg10: 90.0,
                full_avg10: Some(90.0),
            },
            "remedy",
        );
        assert!(
            degraded_mode(),
            "fixture: a cgroup-scoped stall must degrade"
        );

        // The scoped file vanishes; the host is calm.
        judge(
            "io",
            "resource.io_stall",
            "host.io_contention",
            &Pressure::Measured {
                scope: PressureScope::Host,
                some_avg10: 0.0,
                full_avg10: Some(0.0),
            },
            "remedy",
        );
        assert!(
            degraded_mode(),
            "a QUIET HOST cleared this node's stall. The host is a different subject — the \
             node's verdict must stand until the node is measured again: {:?}",
            snapshot()
        );

        // And a NOISY host must not replace the error with its own advisory.
        judge(
            "io",
            "resource.io_stall",
            "host.io_contention",
            &Pressure::Measured {
                scope: PressureScope::Host,
                some_avg10: 99.0,
                full_avg10: Some(99.0),
            },
            "remedy",
        );
        let standing = snapshot();
        assert!(
            standing
                .iter()
                .any(|w| w.code == "resource.io_stall" && w.severity == "error"),
            "a host advisory DOWNGRADED a node-scoped error — a neighbour's noise made this \
             node look healthier than it is: {standing:?}"
        );
        assert!(
            standing.iter().any(|w| w.code == "host.io_contention"),
            "the host reading must still be reported under its OWN code: {standing:?}"
        );
    }

    /// **A counter reset means "everything since the restart", as documented.**
    ///
    /// Saturating subtraction returned 0 for any counter that moved backwards,
    /// so a runtime that restarted and then failed before the next sample had
    /// those failures discarded permanently — the post-restart snapshot becomes
    /// the new baseline. The doc described the right rule; the code did the
    /// opposite.
    #[test]
    fn a_reset_counter_reports_everything_since_the_restart() {
        use ciris_edge::observability::{EdgeMetrics, RoundOutcome};
        let _g = exclusive();
        *LAST_EDGE_COUNTERS.lock().unwrap_or_else(|e| e.into_inner()) = None;

        let mut bundle = EdgeMetrics::new().snapshot();
        bundle
            .replication_round_outcomes_total
            .insert(RoundOutcome::Completed, 5_000);
        bundle.replication_inbound_backpressure_drops = 0;
        report_edge_metrics(&bundle); // baseline

        // Edge restarts, and immediately drops frames + times out rounds.
        let mut after = EdgeMetrics::new().snapshot();
        after
            .replication_round_outcomes_total
            .insert(RoundOutcome::TimedOut, 8);
        after
            .replication_round_outcomes_total
            .insert(RoundOutcome::Completed, 2);
        after.replication_inbound_backpressure_drops = 17;
        report_edge_metrics(&after);

        let codes: Vec<String> = snapshot().into_iter().map(|w| w.code).collect();
        assert!(
            codes.contains(&"network.inbound_frames_dropped".to_string()),
            "17 frames were dropped after an edge restart and the window reported ZERO — those \
             drops are now permanently invisible, because this snapshot becomes the baseline: \
             {codes:?}"
        );
        assert!(
            codes.contains(&"network.rounds_timing_out".to_string()),
            "8 of 10 post-restart rounds timed out and the window reported nothing: {codes:?}"
        );
    }

    /// The three verdict fields come from ONE registry read and cannot disagree.
    #[test]
    fn the_verdict_fields_agree_by_construction() {
        let _g = exclusive();

        let (w, d, s) = verdict();
        assert!(
            w.is_empty() && !d && s == "ok",
            "a clean registry: {w:?} {d} {s}"
        );

        raise(Warning::error("t.v", "a reason"));
        let (w, d, s) = verdict();
        assert_eq!(
            (d, s),
            (true, "degraded"),
            "degraded_mode and status must move together"
        );
        assert!(
            !w.is_empty(),
            "`degraded` with an EMPTY reason list is the torn read this exists to prevent"
        );

        raise(Warning::advisory("t.v2", "worth knowing"));
        let (w, d, _) = verdict();
        assert!(
            d && w.len() == 2,
            "an advisory rides along without changing the flag"
        );
    }
    /// The registry's contract, and the reason `degraded_mode` is not "any
    /// warning": an advisory must not flip the flag, or the flag stops meaning
    /// "this node is not doing its whole job" within a week of shipping.
    #[test]
    fn advisories_do_not_degrade_but_errors_do() {
        let _g = exclusive();
        assert_eq!(verdict().2, "ok");
        assert!(!degraded_mode());

        raise(Warning::advisory("t.advisory", "look at this soon"));
        assert!(!degraded_mode(), "a `warning` severity must not degrade");
        assert_eq!(verdict().2, "ok");
        assert_eq!(snapshot().len(), 1, "but it IS reported");

        raise(Warning::error("t.reduced", "a plane is shed"));
        assert!(degraded_mode());
        assert_eq!(verdict().2, "degraded");

        assert!(clear("t.reduced"));
        assert!(!degraded_mode(), "clearing the error restores ok");
        assert_eq!(verdict().2, "ok");
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
        report_network_rounds(RoundWindow {
            timed_out: 0,
            completed: 0,
            total: 0,
            ..Default::default()
        });
        // Failures reported with a ZERO denominator: nonsense input that must
        // not divide by zero, and must not be laundered into a verdict either.
        report_network_rounds(RoundWindow {
            timed_out: 5,
            total: 0,
            ..Default::default()
        });
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
