//! **Capacity monitoring: the node knows when it is overloaded** (steward
//! 2026-11-01: "make sure we can shed load using the same approach agent does
//! with capacity monitoring — edge can help us identify and shed load"; "we
//! degrade from full ops, to audio and files, to supporting basic
//! chat/contacts").
//!
//! The agent's model (`ResourceMonitorService`): sample once a second against
//! a budget; each resource has a warning and a critical threshold; crossing one
//! raises a signal, and the consumer decides what to cut. Here the consumer is
//! edge: `Edge::set_load_pressure(Normal | Warning | Critical)` maps to its
//! service tiers (full ops → audio and files → chat and contacts) and picks the
//! flows to shed, least disruptive first. Edge owns that ladder; this module
//! only says how loaded the host is. Shedding A/V and relay traffic is the
//! node's own transport decision; its federation duty is not shed here (that
//! stays report-then-root-relief, `config:load` → `mesh_config`, CC 4.2.1).
//!
//! **What is sampled** (from `/proc`, where the platform has one; elsewhere
//! the monitor reports `Normal` and says so once):
//!
//! - **Process CPU**, as a share of the cores this process may use.
//! - **The hottest thread's CPU.** A single thread pinned near 100% is how the
//!   canonical's read storms look (2026-10-31, 2026-11-01: one thread at 99%
//!   for hours while the process total stayed modest), and a starved serial
//!   path is overload even with idle cores.
//! - **Resident memory**, as a share of the cgroup limit (or of the machine
//!   when unlimited).
//!
//! Each reading is smoothed over the last [`WINDOW`] samples, so one busy
//! second is not overload. The pressure is the worst level across resources.
//! A level is entered at once and left only after it has stayed below its
//! threshold for [`COOLDOWN`] — the agent's cooldown, so pressure does not
//! flap. (Edge applies its own step-down cooldown on top.)
//!
//! **Its own OS thread**, not a tokio task: a read storm starves the runtime's
//! workers, which is exactly when the monitor must still run.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

/// How often the host is sampled.
pub const SAMPLE: Duration = Duration::from_secs(1);
/// Samples a reading is averaged over.
pub const WINDOW: usize = 5;
/// How long a level must stay below its threshold before it is left.
pub const COOLDOWN: Duration = Duration::from_secs(30);

/// How loaded the host is — the value edge's `set_load_pressure` takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LoadPressure {
    /// Within budget: full operation.
    Normal,
    /// Over a warning threshold.
    Warning,
    /// Over a critical threshold.
    Critical,
}

impl LoadPressure {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
    fn from_u8(v: u8) -> Self {
        match v {
            2 => Self::Critical,
            1 => Self::Warning,
            _ => Self::Normal,
        }
    }
}

/// One resource's thresholds, as fractions (1.0 = all of it).
#[derive(Debug, Clone, Copy)]
pub struct Limit {
    pub warning: f64,
    pub critical: f64,
}

/// The budget the monitor holds the host to.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    /// Process CPU over the cores it may use.
    pub process_cpu: Limit,
    /// The busiest single thread (1.0 = one full core).
    pub hottest_thread: Limit,
    /// Resident memory over the memory limit.
    pub memory: Limit,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            process_cpu: Limit {
                warning: 0.70,
                critical: 0.90,
            },
            hottest_thread: Limit {
                warning: 0.85,
                critical: 0.97,
            },
            memory: Limit {
                warning: 0.75,
                critical: 0.90,
            },
        }
    }
}

/// One smoothed reading of the host.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Reading {
    pub process_cpu: f64,
    pub hottest_thread: f64,
    pub memory: f64,
}

/// The level a reading puts the host at, and the resource that set it.
#[must_use]
pub fn assess(r: &Reading, b: &Budget) -> (LoadPressure, &'static str) {
    let mut worst = (LoadPressure::Normal, "none");
    for (v, l, name) in [
        (r.process_cpu, b.process_cpu, "process_cpu"),
        (r.hottest_thread, b.hottest_thread, "hottest_thread"),
        (r.memory, b.memory, "memory"),
    ] {
        let level = if v >= l.critical {
            LoadPressure::Critical
        } else if v >= l.warning {
            LoadPressure::Warning
        } else {
            LoadPressure::Normal
        };
        if level > worst.0 {
            worst = (level, name);
        }
    }
    worst
}

/// Enter a higher level at once; leave a level only after `cooldown` below it.
#[derive(Debug)]
pub struct Hysteresis {
    level: LoadPressure,
    below_since: Option<Instant>,
    cooldown: Duration,
}

impl Hysteresis {
    #[must_use]
    pub fn new(cooldown: Duration) -> Self {
        Self {
            level: LoadPressure::Normal,
            below_since: None,
            cooldown,
        }
    }
    /// Feed the level the latest reading assessed at `now`; returns the held level.
    pub fn step(&mut self, assessed: LoadPressure, now: Instant) -> LoadPressure {
        if assessed >= self.level {
            self.level = assessed;
            self.below_since = None;
        } else {
            let since = *self.below_since.get_or_insert(now);
            if now.duration_since(since) >= self.cooldown {
                self.level = assessed;
                self.below_since = None;
            }
        }
        self.level
    }
}

/// Where the pressure goes — edge's `Edge::set_load_pressure` (agreed with edge
/// 2026-11-01), registered at its adoption. Called every sample; cheap.
pub trait PressureSink: Send + Sync {
    fn set_load_pressure(&self, p: LoadPressure);
}

static SINK: RwLock<Option<Arc<dyn PressureSink>>> = RwLock::new(None);
static CURRENT: AtomicU8 = AtomicU8::new(0);

/// Register the sink the pressure is fed to. A later call replaces it.
pub fn set_sink(s: Arc<dyn PressureSink>) {
    *SINK.write().unwrap_or_else(|p| p.into_inner()) = Some(s);
}

/// The pressure the monitor currently holds.
#[must_use]
pub fn current() -> LoadPressure {
    LoadPressure::from_u8(CURRENT.load(Ordering::Relaxed))
}

// ── /proc sampling ───────────────────────────────────────────────────────────

/// Cumulative CPU ticks (utime + stime) from a `/proc/.../stat` line.
fn stat_ticks(stat: &str) -> Option<u64> {
    // The command name is parenthesised and may contain spaces: split after it.
    let rest = &stat[stat.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // After the name: state is field 0, utime field 11, stime field 12.
    Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod host {
    use super::stat_ticks;
    use std::collections::HashMap;

    pub fn clock_ticks() -> f64 {
        // SAFETY: sysconf reads a process-wide constant.
        let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if t > 0 {
            t as f64
        } else {
            100.0
        }
    }

    pub fn cores() -> f64 {
        std::thread::available_parallelism().map_or(1.0, |n| n.get() as f64)
    }

    pub fn process_ticks() -> Option<u64> {
        stat_ticks(&std::fs::read_to_string("/proc/self/stat").ok()?)
    }

    pub fn thread_ticks() -> HashMap<u64, u64> {
        let mut out = HashMap::new();
        if let Ok(rd) = std::fs::read_dir("/proc/self/task") {
            for e in rd.flatten() {
                let Some(tid) = e.file_name().to_str().and_then(|s| s.parse().ok()) else {
                    continue;
                };
                if let Some(t) = std::fs::read_to_string(e.path().join("stat"))
                    .ok()
                    .and_then(|s| stat_ticks(&s))
                {
                    out.insert(tid, t);
                }
            }
        }
        out
    }

    /// Resident bytes over the memory limit (cgroup v2, else the machine).
    pub fn memory_share() -> Option<f64> {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let rss_pages: f64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        // SAFETY: sysconf reads a process-wide constant.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as f64;
        let rss = rss_pages * page;
        let limit = std::fs::read_to_string("/sys/fs/cgroup/memory.max")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .or_else(|| {
                let m = std::fs::read_to_string("/proc/meminfo").ok()?;
                let kb: f64 = m
                    .lines()
                    .find(|l| l.starts_with("MemTotal:"))?
                    .split_whitespace()
                    .nth(1)?
                    .parse()
                    .ok()?;
                Some(kb * 1024.0)
            })?;
        (limit > 0.0).then(|| rss / limit)
    }
}

/// Raw per-second readings, before smoothing.
struct Sampler {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    last: Option<(Instant, u64, std::collections::HashMap<u64, u64>)>,
}

impl Sampler {
    fn new() -> Self {
        Self {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            last: None,
        }
    }

    /// `None` until two samples exist, and always on a platform without `/proc`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn sample(&mut self) -> Option<Reading> {
        let now = Instant::now();
        let proc_t = host::process_ticks()?;
        let threads = host::thread_ticks();
        let prev = self.last.replace((now, proc_t, threads.clone()));
        let (t0, p0, th0) = prev?;
        let secs = now.duration_since(t0).as_secs_f64().max(1e-3);
        let hz = host::clock_ticks();
        let process_cpu = (proc_t.saturating_sub(p0) as f64 / hz / secs) / host::cores();
        let hottest_thread = threads
            .iter()
            .filter_map(|(tid, t)| th0.get(tid).map(|t0| t.saturating_sub(*t0)))
            .max()
            .map_or(0.0, |d| d as f64 / hz / secs);
        Some(Reading {
            process_cpu,
            hottest_thread,
            memory: host::memory_share().unwrap_or(0.0),
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn sample(&mut self) -> Option<Reading> {
        None
    }
}

fn smooth(window: &VecDeque<Reading>) -> Reading {
    let n = window.len().max(1) as f64;
    let mut r = Reading::default();
    for w in window {
        r.process_cpu += w.process_cpu / n;
        r.hottest_thread += w.hottest_thread / n;
        r.memory += w.memory / n;
    }
    r
}

/// Start the monitor once per process. `CIRIS_CAPACITY_MONITOR=0` turns it off.
pub fn start() {
    static STARTED: OnceLock<()> = OnceLock::new();
    if std::env::var("CIRIS_CAPACITY_MONITOR").as_deref() == Ok("0") {
        return;
    }
    STARTED.get_or_init(|| {
        let _ = std::thread::Builder::new()
            .name("ciris-capacity".into())
            .spawn(run);
    });
}

fn run() {
    let budget = Budget::default();
    let mut sampler = Sampler::new();
    let mut window: VecDeque<Reading> = VecDeque::with_capacity(WINDOW);
    let mut hold = Hysteresis::new(COOLDOWN);
    let mut warned_unavailable = false;
    loop {
        // A backgrounded phone node samples nothing (node_lifecycle).
        if crate::node_lifecycle::phase() == crate::node_lifecycle::Phase::Background {
            std::thread::sleep(SAMPLE * 5);
            continue;
        }
        std::thread::sleep(SAMPLE);
        let Some(r) = sampler.sample() else {
            if !warned_unavailable && cfg!(not(any(target_os = "linux", target_os = "android"))) {
                warned_unavailable = true;
                tracing::info!(
                    "capacity monitor: no /proc on this platform — pressure stays normal"
                );
            }
            continue;
        };
        if window.len() == WINDOW {
            window.pop_front();
        }
        window.push_back(r);
        let smoothed = smooth(&window);
        let (assessed, cause) = assess(&smoothed, &budget);
        let held = hold.step(assessed, Instant::now());
        let was = LoadPressure::from_u8(CURRENT.swap(held as u8, Ordering::Relaxed));
        if held != was {
            let line = format!(
                "CAPACITY {} → {} — cause={cause} process_cpu={:.0}% hottest_thread={:.0}% memory={:.0}% \
                 (edge sheds by tier: full ops → audio and files → chat and contacts)",
                was.as_str(),
                held.as_str(),
                smoothed.process_cpu * 100.0,
                smoothed.hottest_thread * 100.0,
                smoothed.memory * 100.0,
            );
            if held > was {
                tracing::warn!("{line}");
            } else {
                tracing::info!("{line}");
            }
        }
        if let Some(s) = SINK.read().unwrap_or_else(|p| p.into_inner()).clone() {
            s.set_load_pressure(held);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_worst_resource_sets_the_level() {
        let b = Budget::default();
        let calm = Reading {
            process_cpu: 0.2,
            hottest_thread: 0.3,
            memory: 0.4,
        };
        assert_eq!(assess(&calm, &b).0, LoadPressure::Normal);
        // The canonical's storm: modest process total, one thread pinned.
        let spin = Reading {
            hottest_thread: 0.99,
            ..calm
        };
        assert_eq!(
            assess(&spin, &b),
            (LoadPressure::Critical, "hottest_thread")
        );
        let mem = Reading {
            memory: 0.8,
            ..calm
        };
        assert_eq!(assess(&mem, &b), (LoadPressure::Warning, "memory"));
    }

    #[test]
    fn a_level_is_entered_at_once_and_left_only_after_the_cooldown() {
        let t0 = Instant::now();
        let mut h = Hysteresis::new(Duration::from_secs(30));
        assert_eq!(h.step(LoadPressure::Critical, t0), LoadPressure::Critical);
        assert_eq!(
            h.step(LoadPressure::Normal, t0 + Duration::from_secs(10)),
            LoadPressure::Critical,
            "inside the cooldown the level holds"
        );
        assert_eq!(
            h.step(LoadPressure::Critical, t0 + Duration::from_secs(20)),
            LoadPressure::Critical
        );
        assert_eq!(
            h.step(LoadPressure::Normal, t0 + Duration::from_secs(25)),
            LoadPressure::Critical,
            "a fresh spike restarts the cooldown"
        );
        assert_eq!(
            h.step(LoadPressure::Normal, t0 + Duration::from_secs(56)),
            LoadPressure::Normal,
            "30 s calm after the last spike: the level is left"
        );
    }

    #[test]
    fn a_proc_stat_line_with_spaces_in_the_name_parses() {
        let line = "1234 (ciris node x) S 1 2 3 4 5 6 7 8 9 10 250 50 0 0 20 0";
        assert_eq!(stat_ticks(line), Some(300));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_sampler_reads_this_process() {
        let mut s = Sampler::new();
        assert!(s.sample().is_none(), "the first sample has nothing to diff");
        let t = Instant::now();
        while t.elapsed() < Duration::from_millis(300) {
            std::hint::black_box(0u64.wrapping_add(1));
        }
        let r = s.sample().expect("second sample");
        assert!(
            r.hottest_thread > 0.3,
            "a busy loop shows on the hottest thread: {r:?}"
        );
        assert!(r.memory > 0.0 && r.memory < 1.0, "{r:?}");
    }
}
