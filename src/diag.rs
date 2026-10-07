//! Operator diagnostics — RUNTIME-GATED (`--diagnostics` / `CIRIS_DIAGNOSTICS=1`)
//! and loopback-only (CIRISServer#549, CIRISServer#550).
//!
//! # What is here
//!
//! * [`memory_report`] — glibc's own allocator accounting (`mallinfo2`) beside
//!   the kernel's view of this process, served on `GET /v1/node/diagnostics/memory`.
//!   The one number it exists to produce is `live_fraction`: near 1 means the
//!   heap is a live working set and the fix is to retain less; near 0 means the
//!   heap is the allocator's free lists and the fix is an allocator one (arena
//!   cap, trim). No read of `/proc/<pid>` can make that split, because glibc
//!   does not zero on `free()` — a freed chunk keeps its bytes until reused, so
//!   a scan cannot tell live from held. It is byte-for-byte the instrument
//!   CIRISStatus ships (its `src/diag.rs`, CIRISStatus#69), on purpose: the two
//!   nodes share the canonical host and #550 is the question of why one floor
//!   moves and the other does not, so they must be read with one ruler.
//! * [`thread_cpu`] / [`process_cpu`] — the CPU clocks `compose_status::mark`
//!   reads beside wall time, so a slow boot step says WHICH kind of slow it is:
//!   wall ≈ thread CPU is code that is expensive; wall ≫ thread CPU with process
//!   CPU high is this process starving itself (the #549 hypothesis on a 2-vCPU
//!   box); wall ≫ both is the host, or blocking I/O.
//!
//! # Why a runtime gate and not a cargo feature
//!
//! Test mode is a compile-time feature (`test-anchor`) because a software trust
//! root must not EXIST in a production build — that is a security property, and
//! only the linker can give it. A read-only memory report has no such property.
//! Its risk is exposure, and `require_loopback` is the standing answer to that on
//! this listener (the setup routes live behind the same guard). And the process
//! that #550 needs to read is the production canonical, which runs the PyPI
//! wheel (`pip install ciris-server==X` in its Dockerfile): a feature that is off
//! in the wheel would leave exactly that process without the instrument. So the
//! shape is the one every runtime uses for allocator introspection — pprof, JMX,
//! `--inspect`: compiled in, OFF by default, switched on by the operator, bound
//! to localhost. Off costs one relaxed atomic load per boot mark and nothing at
//! all on the request path (the route is simply not mounted).
//!
//! Read-only in the sense that matters: it reports, it does not trim. Deciding to
//! release memory is a separate act from measuring it.
//!
//! The allocator POLICY that measurement led to lives here too, outside the
//! switch: [`tune_allocator`] (the arena cap, #552) and [`spawn_trimmer`] /
//! [`trim_after`] (return retained heap on a period and after the boot's and the
//! scorer's peaks — the 0.5.222 capped run read 152 MB live under 1.04 GB held).

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::{routing::get, Json, Router};
use serde_json::{json, Value};

/// The CLI flag on the serve path (`ciris-server --diagnostics …`).
pub const FLAG: &str = "--diagnostics";
/// The environment switch, for a container whose entrypoint is baked
/// (`environment: CIRIS_DIAGNOSTICS=1` in compose). Truthy set is the agent's
/// own — `1` / `true` / `yes`, case-insensitive — so the two cannot disagree
/// about what "on" looks like (CIRISAgent#1149).
pub const ENV: &str = "CIRIS_DIAGNOSTICS";
/// `GET` — the memory report. Loopback-only.
pub const ROUTE_MEMORY: &str = "/v1/node/diagnostics/memory";

static ENABLED: AtomicBool = AtomicBool::new(false);

/// Does the environment ask for diagnostics? Read once at boot by the serve
/// entry points; never on a request path.
pub fn env_requests() -> bool {
    std::env::var(ENV)
        .ok()
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false)
}

/// Switch diagnostics on for the life of the process, saying what asked.
pub fn enable(source: &'static str) {
    ENABLED.store(true, Ordering::SeqCst);
    tracing::info!(
        source,
        route = ROUTE_MEMORY,
        "diagnostics ON — loopback-only memory report mounted; compose marks record \
         wall vs thread-CPU vs process-CPU per boot step (#549/#550)"
    );
}

/// `POST` — release what the allocator can give back (`malloc_trim(0)`) and
/// report the heap before and after. Loopback-only, under the same switch.
pub const ROUTE_TRIM: &str = "/v1/node/diagnostics/memory/trim";

/// The arena cap this process asks glibc for when the operator has not.
///
/// CIRISStatus#69 measured `MALLOC_ARENA_MAX=2` on the sister node: committed
/// 1458 → 611 MB, live unchanged. The canonical's `ciris-server` sat at the
/// default cap (8 × nproc = 16 arenas, 15 in use) until the same variable
/// took it from 2.47 GB to 1.0 GB (CIRISServer#552). Every glibc node gets
/// that here without an operator knowing the knob exists; an explicit
/// `MALLOC_ARENA_MAX` in the environment always wins.
pub const ARENA_MAX: i32 = 2;

/// Tune the process allocator, once, before the runtime spawns its threads.
/// glibc only; a no-op everywhere else (bionic, iOS, macOS, Windows have no
/// `mallopt` and no arena model to cap). Called by the same three serve
/// entries as [`arm`], and independent of the diagnostics switch: it is not an
/// instrument, it is the fix the instrument found.
pub fn tune_allocator() {
    #[cfg(target_env = "gnu")]
    {
        if std::env::var_os("MALLOC_ARENA_MAX").is_some() {
            tracing::info!(
                "allocator: MALLOC_ARENA_MAX set in the environment — leaving glibc's arena cap alone"
            );
            return;
        }
        // SAFETY: `mallopt` sets a process-wide allocator parameter; it takes
        // two plain integers and touches no memory of ours. Called before any
        // thread contention could have created arenas beyond the cap.
        let rc = unsafe { libc::mallopt(libc::M_ARENA_MAX, ARENA_MAX) };
        if rc == 1 {
            tracing::info!(
                arena_max = ARENA_MAX,
                "allocator: glibc arena cap set (CIRISServer#552)"
            );
        } else {
            tracing::warn!(
                arena_max = ARENA_MAX,
                rc,
                "allocator: mallopt(M_ARENA_MAX) refused"
            );
        }
    }
}

/// The environment knob for the background trimmer's period, in seconds.
/// `0` turns it off; unset means [`TRIM_INTERVAL_SECS`].
pub const TRIM_ENV: &str = "CIRIS_MALLOC_TRIM_SECS";

/// How often the trimmer hands retained heap back to the kernel.
///
/// The bridge's capped run of 0.5.222 against a copy of the canonical's data
/// (2 GiB cgroup) read 152 MB live beside 1.04 GB free-but-retained
/// (`fordblks`) before the OOM: transient peaks freed into a heap glibc never
/// shrinks on its own, so every peak raised the floor the next one stood on. A
/// `malloc_trim(0)` returns those pages (the top of the heap and, since glibc
/// 2.8, whole free pages inside every arena). It cannot lower a peak; it stops
/// peaks from stacking. 30 s keeps the floor near the live set while costing one
/// arena walk per period, off every request path.
pub const TRIM_INTERVAL_SECS: u64 = 30;

/// Below this, a trim's release is debug-level; at or above it, info.
const TRIM_LOG_FLOOR_KB: i64 = 64 * 1024;

/// One `kB` field of `/proc/self/status` (`RssAnon`, `VmHWM`, …); `None` off
/// Linux or when the kernel does not report it.
pub fn proc_status_kb(field: &str) -> Option<i64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix(field)?.strip_prefix(':'))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
}

/// `RssAnon` in kB — the figure a memory cgroup charges.
fn rss_anon_kb() -> Option<i64> {
    proc_status_kb("RssAnon")
}

/// Live heap in kB (`mallinfo2().uordblks`); `None` where there is no glibc.
pub fn heap_live_kb() -> Option<i64> {
    #[cfg(target_env = "gnu")]
    {
        // SAFETY: see `memory_report` — reads glibc's own accounting.
        Some((unsafe { libc::mallinfo2() }.uordblks / 1024) as i64)
    }
    #[cfg(not(target_env = "gnu"))]
    {
        None
    }
}

/// Trim now and say what it released. `why` names the caller (the period, the
/// end of boot, a scorer pass) so a log reader can tie a release to the work
/// that made the peak. A no-op where there is no glibc.
pub fn trim_after(why: &'static str) {
    #[cfg(target_env = "gnu")]
    {
        // A new process peak since the last trim, named by when it was seen:
        // the 0.5.222 run had a +512 MB single step that no log line explained;
        // this puts that step inside a ≤ TRIM_INTERVAL_SECS window to read the
        // other logs against.
        static LAST_PEAK_KB: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
        if let Some(peak) = proc_status_kb("VmHWM") {
            let last = LAST_PEAK_KB.swap(peak, Ordering::Relaxed);
            if last > 0 && peak - last >= TRIM_LOG_FLOOR_KB {
                tracing::warn!(
                    why,
                    peak_rss_kb = peak,
                    previous_peak_rss_kb = last,
                    risen_kb = peak - last,
                    "allocator: process peak RSS rose since the last trim"
                );
            }
        }
        let before = rss_anon_kb();
        let t0 = std::time::Instant::now();
        let released = trim();
        let after = rss_anon_kb();
        let freed_kb = before.zip(after).map(|(b, a)| b - a);
        if freed_kb.is_some_and(|k| k >= TRIM_LOG_FLOOR_KB) {
            tracing::info!(
                why,
                rss_anon_before_kb = before,
                rss_anon_after_kb = after,
                freed_kb,
                elapsed_us = t0.elapsed().as_micros() as u64,
                "allocator: malloc_trim returned retained heap to the kernel"
            );
        } else {
            tracing::debug!(
                why,
                ?released,
                rss_anon_after_kb = after,
                freed_kb,
                elapsed_us = t0.elapsed().as_micros() as u64,
                "allocator: malloc_trim"
            );
        }
    }
    #[cfg(not(target_env = "gnu"))]
    let _ = why;
}

/// Start the background trimmer, once per process: a plain OS thread (no
/// runtime needed, none starved) that calls [`trim_after`] every
/// [`TRIM_INTERVAL_SECS`], or every `CIRIS_MALLOC_TRIM_SECS` (`0` = off).
/// Independent of the diagnostics switch, like [`tune_allocator`]: it is the
/// fix the instrument found, not an instrument.
pub fn spawn_trimmer() {
    #[cfg(target_env = "gnu")]
    {
        static STARTED: std::sync::Once = std::sync::Once::new();
        STARTED.call_once(|| {
            let secs = match std::env::var(TRIM_ENV) {
                Ok(v) => match v.trim().parse::<u64>() {
                    Ok(n) => n,
                    Err(_) => {
                        tracing::warn!(
                            value = %v,
                            default_secs = TRIM_INTERVAL_SECS,
                            "allocator: {TRIM_ENV} is not a whole number of seconds — using the default"
                        );
                        TRIM_INTERVAL_SECS
                    }
                },
                Err(_) => TRIM_INTERVAL_SECS,
            };
            if secs == 0 {
                tracing::info!("allocator: periodic malloc_trim OFF ({TRIM_ENV}=0)");
                return;
            }
            let spawned = std::thread::Builder::new()
                .name("ciris-malloc-trim".into())
                .spawn(move || loop {
                    std::thread::sleep(Duration::from_secs(secs));
                    trim_after("period");
                });
            match spawned {
                Ok(_) => tracing::info!(
                    period_secs = secs,
                    "allocator: periodic malloc_trim started"
                ),
                Err(e) => tracing::warn!(
                    error = %e,
                    "allocator: could not start the malloc_trim thread — retained heap will not be returned"
                ),
            }
        });
    }
}

/// The open spans, by `target::name`, for [`spawn_burst_sampler`] to name what
/// was running when memory jumped. Every layer of the stack opens spans for its
/// units of work (edge's replication rounds, the server's loops, persist's
/// calls), so the live set at the moment of a jump names the work that made it
/// — without symbols (the wheel ships stripped) or a profiler (none on the
/// canonical's host). Only spans the subscriber's filter enables are counted.
#[derive(Default)]
pub struct LiveSpans;

/// A span's key in the table, kept on the span so `on_close` decrements the
/// same entry `on_new_span` raised.
struct LiveKey(String);

/// The span fields worth naming in a burst report: which round KIND and toward
/// which PEER (edge's `anti_entropy_round` carries both). Five rounds open at
/// every burst of the third capped run said nothing until it said which.
const NAMED_FIELDS: &[&str] = &["kind", "peer"];

#[derive(Default)]
struct LabelVisitor(String);

impl tracing::field::Visit for LabelVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        if NAMED_FIELDS.contains(&field.name()) {
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }
}

static LIVE_SPANS: std::sync::Mutex<Option<std::collections::HashMap<String, i64>>> =
    std::sync::Mutex::new(None);

impl<S> tracing_subscriber::Layer<S> for LiveSpans
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let m = attrs.metadata();
        let mut label = LabelVisitor::default();
        attrs.record(&mut label);
        let key = format!("{}::{}{}", m.target(), m.name(), label.0);
        if let Ok(mut g) = LIVE_SPANS.lock() {
            *g.get_or_insert_with(Default::default)
                .entry(key.clone())
                .or_default() += 1;
        }
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(LiveKey(key));
        }
    }

    fn on_close(&self, id: tracing::span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let ext = span.extensions();
        let Some(LiveKey(key)) = ext.get::<LiveKey>() else {
            return;
        };
        if let Ok(mut g) = LIVE_SPANS.lock() {
            if let Some(map) = g.as_mut() {
                if let Some(n) = map.get_mut(key) {
                    *n -= 1;
                    if *n <= 0 {
                        map.remove(key);
                    }
                }
            }
        }
    }
}

/// The open spans right now, most numerous first, as `target::name[ kind= peer=]=count`.
pub fn live_spans(limit: usize) -> Vec<String> {
    let Ok(g) = LIVE_SPANS.lock() else {
        return Vec::new();
    };
    let Some(map) = g.as_ref() else {
        return Vec::new();
    };
    let mut v: Vec<_> = map.iter().map(|(k, c)| (*c, k.as_str())).collect();
    v.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
    v.into_iter()
        .take(limit)
        .map(|(c, k)| format!("{k}={c}"))
        .collect()
}

/// A rise in `RssAnon` within one second that names itself.
const BURST_KB: i64 = 64 * 1024;
/// A rise over the last [`CLIMB_SECS`] seconds that names itself: the third
/// capped run climbed 718 → 1,190 MB over five seconds with no single second
/// past the one-second floor.
const CLIMB_KB: i64 = 256 * 1024;
const CLIMB_SECS: usize = 5;

/// Sample `RssAnon` every second; on a one-second rise of [`BURST_KB`] or a
/// [`CLIMB_SECS`]-second rise of [`CLIMB_KB`], WARN with the rise and the open
/// spans. The 0.5.223 capped runs had bursts of +500 MB to +1.1 GB inside 10 s
/// with no log line naming the work; a 30 s trim period is too coarse to catch
/// one in flight. One /proc read a second; the span table is read only on a
/// burst.
pub fn spawn_burst_sampler() {
    #[cfg(target_os = "linux")]
    {
        static STARTED: std::sync::Once = std::sync::Once::new();
        STARTED.call_once(|| {
            let _ = std::thread::Builder::new()
                .name("ciris-mem-burst".into())
                .spawn(|| {
                    let mut recent: std::collections::VecDeque<i64> =
                        std::collections::VecDeque::with_capacity(CLIMB_SECS + 1);
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                        let Some(now) = rss_anon_kb() else { continue };
                        let last = recent.back().copied();
                        let oldest = recent.front().copied();
                        let second = last.map(|p| now - p);
                        let climb = oldest.map(|p| now - p);
                        if second.is_some_and(|d| d >= BURST_KB)
                            || climb.is_some_and(|d| d >= CLIMB_KB)
                        {
                            tracing::warn!(
                                rss_anon_kb = now,
                                risen_1s_kb = second,
                                risen_5s_kb = climb,
                                live_spans = %live_spans(25).join(" | "),
                                "allocator: memory burst — RssAnon rising; open spans named"
                            );
                        }
                        recent.push_back(now);
                        if recent.len() > CLIMB_SECS {
                            recent.pop_front();
                        }
                    }
                });
        });
    }
}

/// Arm diagnostics from the serve entry point: ON if the CLI flag was given or
/// the environment asks, naming which; returns the resulting state so the
/// caller can record it on `ServerConfig`. The ONE place the two switches meet,
/// so the binary, the wheel's `py_main` and the embedded adapter cannot read
/// them differently. Also the one place the allocator is tuned, for the same
/// reason.
pub fn arm(flag: bool) -> bool {
    tune_allocator();
    spawn_trimmer();
    spawn_burst_sampler();
    if flag {
        enable(FLAG);
    } else if env_requests() {
        enable(ENV);
    }
    enabled()
}

/// Whether diagnostics are on. One relaxed load; safe on any path.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// CPU time consumed by the CALLING THREAD so far. `None` where the clock is
/// not available (non-unix).
pub fn thread_cpu() -> Option<Duration> {
    cpu_clock(ClockKind::Thread)
}

/// CPU time consumed by the whole process so far (all threads).
pub fn process_cpu() -> Option<Duration> {
    cpu_clock(ClockKind::Process)
}

#[derive(Clone, Copy)]
enum ClockKind {
    Thread,
    Process,
}

#[cfg(unix)]
fn cpu_clock(kind: ClockKind) -> Option<Duration> {
    let id = match kind {
        ClockKind::Thread => libc::CLOCK_THREAD_CPUTIME_ID,
        ClockKind::Process => libc::CLOCK_PROCESS_CPUTIME_ID,
    };
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` writes one `timespec` we own and reads nothing
    // else; both clock ids are POSIX and present on every unix target we build.
    let rc = unsafe { libc::clock_gettime(id, &mut ts) };
    if rc != 0 {
        return None;
    }
    Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

#[cfg(not(unix))]
fn cpu_clock(_kind: ClockKind) -> Option<Duration> {
    None
}

/// A snapshot of what the allocator and the kernel each think this process is
/// using. Fields are bytes unless named otherwise. Same shape and field names
/// as CIRISStatus's report, plus this node's `node` block so a reading can be
/// tied to the process (`instance_id`) that produced it.
pub fn memory_report() -> Value {
    let mut out = json!({
        "proc": proc_status(),
        "node": crate::node_identity::wire_json(),
        "compose": serde_json::from_str::<Value>(&crate::compose_status::snapshot_json())
            .unwrap_or(Value::Null),
    });
    #[cfg(target_env = "gnu")]
    {
        // SAFETY: `mallinfo2` reads glibc's own accounting and takes no
        // arguments. It walks arena bookkeeping under the allocator's locks,
        // so it is safe to call from any thread; it returns a plain value
        // struct with no pointers to free.
        let m = unsafe { libc::mallinfo2() };
        out["mallinfo2"] = json!({
            // Live: what the program asked for and has not freed.
            "uordblks": m.uordblks as u64,
            // Free-but-held: returned to the allocator, still owned by the
            // process. A large value here is fragmentation/churn, NOT a leak,
            // and is what an arena cap or a trim would reclaim.
            "fordblks": m.fordblks as u64,
            // Total non-mmapped space obtained from the OS (sbrk).
            "arena": m.arena as u64,
            // Space in mmapped regions — untouched by malloc_trim.
            "hblkhd": m.hblkhd as u64,
            "hblks": m.hblks as u64,
            // Releasable at the top of the heap: the upper bound on what a
            // plain `malloc_trim(0)` could hand back.
            "keepcost": m.keepcost as u64,
            "ordblks": m.ordblks as u64,
        });
        let live = m.uordblks as f64;
        let held = m.fordblks as f64;
        let total = live + held;
        if total > 0.0 {
            // The one number this endpoint exists to produce, as a FRACTION of
            // 1 — near 1 means the heap is a live working set and the fix is to
            // retain less; near 0 means the heap is mostly the allocator's
            // free lists and the fix is an allocator one (arena cap, trim).
            out["live_fraction"] = json!((live / total * 10_000.0).round() / 10_000.0);
        }
    }
    #[cfg(not(target_env = "gnu"))]
    {
        out["mallinfo2"] = Value::Null;
        out["note"] = json!("mallinfo2 is glibc-only; this build is not gnu");
    }
    out
}

/// The kernel's view, for correlation: a plateau in `RssAnon` with a large
/// `fordblks` is the churn story, and the two numbers disagreeing is itself
/// informative. `RssAnon + VmSwap` is the committed figure #550 tracks, so both
/// are here.
fn proc_status() -> Value {
    let mut o = serde_json::Map::new();
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            if matches!(
                k,
                "VmRSS" | "RssAnon" | "RssFile" | "VmSwap" | "VmPeak" | "VmSize" | "Threads"
            ) {
                // Values arrive as "  1151234 kB"; keep the kB unit rather than
                // converting, so a reader comparing against /proc directly sees
                // the same number.
                o.insert(k.to_string(), json!(v.trim().to_string()));
            }
        }
    }
    Value::Object(o)
}

async fn memory() -> Json<Value> {
    Json(memory_report())
}

/// `malloc_trim(0)`: hand back every whole free page the allocator holds — the
/// top of the brk heap AND, since glibc 2.8, free pages inside free chunks of
/// every arena. Returns whether the call reported releasing anything; `None`
/// where there is no glibc.
pub fn trim() -> Option<bool> {
    #[cfg(target_env = "gnu")]
    {
        // SAFETY: `malloc_trim` walks the allocator's own bookkeeping under its
        // locks and takes one integer; it frees nothing the program holds.
        Some(unsafe { libc::malloc_trim(0) } == 1)
    }
    #[cfg(not(target_env = "gnu"))]
    {
        None
    }
}

/// The trim door. Measurement first: the report before, the call, the report
/// after, and the deltas that matter (`fordblks`, `RssAnon`, `VmSwap`), so one
/// call on the canonical says how much of an 888 MB free list a trim can
/// actually return — before anyone writes a trim POLICY. It changes nothing a
/// program can observe except its footprint; it is still a POST because it acts.
async fn memory_trim() -> Json<Value> {
    let before = memory_report();
    let released = trim();
    let after = memory_report();
    let kb = |r: &Value, k: &str| -> Option<i64> {
        r["proc"][k]
            .as_str()
            .and_then(|s| s.split_whitespace().next())
            .and_then(|n| n.parse::<i64>().ok())
    };
    let u = |r: &Value, k: &str| r["mallinfo2"][k].as_u64().map(|v| v as i64);
    let delta = |f: &dyn Fn(&Value) -> Option<i64>| match (f(&before), f(&after)) {
        (Some(a), Some(b)) => json!(b - a),
        _ => Value::Null,
    };
    Json(json!({
        "released": released,
        "delta": {
            "fordblks_bytes": delta(&|r| u(r, "fordblks")),
            "arena_bytes": delta(&|r| u(r, "arena")),
            "keepcost_bytes": delta(&|r| u(r, "keepcost")),
            "RssAnon_kb": delta(&|r| kb(r, "RssAnon")),
            "VmSwap_kb": delta(&|r| kb(r, "VmSwap")),
        },
        "before": before,
        "after": after,
    }))
}

/// The diagnostics router. Mounted by compose ONLY when diagnostics are on;
/// every route in it sits behind the loopback guard the setup routes use.
pub fn router() -> Router {
    Router::new()
        .route(ROUTE_MEMORY, get(memory))
        .route(ROUTE_TRIM, axum::routing::post(memory_trim))
        .layer(axum::middleware::from_fn(
            crate::auth::loopback::require_loopback,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_burst_report_names_open_spans_and_forgets_closed_ones() {
        use tracing_subscriber::prelude::*;
        let sub = tracing_subscriber::registry().with(LiveSpans);
        tracing::subscriber::with_default(sub, || {
            let held = tracing::info_span!("probe_round_open", kind = "Attestation", peer = "p1");
            let named = |s: &str| live_spans(500).iter().any(|l| l.contains(s));
            {
                let _brief = tracing::info_span!("probe_round_closed");
                assert!(named("probe_round_closed"));
            }
            assert!(
                named("probe_round_open"),
                "a span alive across the read is named"
            );
            assert!(
                !named("probe_round_closed"),
                "a dropped span leaves the table"
            );
            assert!(
                named("probe_round_open kind=\"Attestation\" peer=\"p1\""),
                "the round's kind and peer are part of its name: {:?}",
                live_spans(500)
            );
            drop(held);
            assert!(!named("probe_round_open"));
        });
    }

    #[cfg(all(target_env = "gnu", target_os = "linux"))]
    #[test]
    fn the_trimmer_reads_the_figure_a_cgroup_charges() {
        // The release log is only as good as this read: a parse that silently
        // returned None would log every trim as freeing nothing.
        let kb = rss_anon_kb().expect("RssAnon in /proc/self/status");
        assert!(kb > 0);
        assert!(proc_status_kb("VmHWM").is_some_and(|hwm| hwm >= kb));
        assert!(proc_status_kb("Rss").is_none(), "a prefix is not a field");
        assert!(heap_live_kb().is_some());
        trim_after("test");
    }

    /// The report's whole purpose is the live-vs-held split, so the test
    /// asserts the two numbers are present and that the derived fraction
    /// agrees with them — a report that silently lost `fordblks` would look
    /// perfectly healthy while answering the wrong question.
    #[test]
    fn the_report_carries_live_and_held_separately() {
        let r = memory_report();
        assert!(r.get("proc").is_some(), "kernel view present: {r}");
        assert!(
            r["node"].get("instance_id").is_some(),
            "tied to a process: {r}"
        );
        assert!(
            r["compose"].get("completed").is_some(),
            "boot record present: {r}"
        );

        #[cfg(target_env = "gnu")]
        {
            let m = &r["mallinfo2"];
            let live = m["uordblks"].as_u64().expect("uordblks");
            let held = m["fordblks"].as_u64().expect("fordblks");
            assert!(live > 0, "this test allocated, so something is live");
            let frac = r["live_fraction"].as_f64().expect("live_fraction");
            assert!(
                (0.0..=1.0).contains(&frac),
                "live_fraction is a fraction of 1, got {frac}"
            );
            let expect = live as f64 / (live + held) as f64;
            assert!(
                (frac - expect).abs() < 0.001,
                "live_fraction {frac} should track uordblks/(uordblks+fordblks) {expect}"
            );
        }
    }

    /// A held allocation must move the in-use figure. This is the sanity check
    /// that the numbers are this process's and not a constant.
    ///
    /// Two glibc facts shape it (the first version of this test tripped on
    /// both in CI): a block past the mmap threshold is NOT in `uordblks` — it
    /// is mmapped and counted in `hblkhd` — and in a 480-test binary other
    /// threads free arena memory in the same millisecond, so `uordblks` alone
    /// can fall while this thread holds its block. So: 64 MiB (past the 32 MiB
    /// ceiling of glibc's dynamic mmap threshold, hence always mmapped), and
    /// the in-use figure is `uordblks + hblkhd`, which only an mmapped free of
    /// tens of MiB elsewhere could pull back down; half the block is the slack
    /// for exactly that.
    #[cfg(target_env = "gnu")]
    #[test]
    fn live_bytes_track_a_real_allocation() {
        const BLOCK: usize = 64 * 1024 * 1024;
        fn in_use() -> u64 {
            let m = &memory_report()["mallinfo2"];
            m["uordblks"].as_u64().unwrap() + m["hblkhd"].as_u64().unwrap()
        }
        let before = in_use();
        // Touched so it cannot be optimised away and the pages are real.
        let mut v: Vec<u8> = vec![7; BLOCK];
        v[BLOCK / 2] = 9;
        std::hint::black_box(&v);
        let during = in_use();
        assert!(
            during >= before + (BLOCK as u64) / 2,
            "in-use bytes (uordblks + hblkhd) should rise by ~64 MiB while the block is held: \
             before={before} during={during}"
        );
        drop(v);
    }

    /// The clocks are the boot marks' whole reason to exist: they must be
    /// present on unix and move when this thread works.
    #[cfg(unix)]
    #[test]
    fn the_cpu_clocks_exist_and_advance_with_work() {
        let t0 = thread_cpu().expect("thread clock");
        let p0 = process_cpu().expect("process clock");
        let mut acc = 0u64;
        for i in 0..20_000_000u64 {
            acc = acc.wrapping_mul(6364136223846793005).wrapping_add(i);
        }
        std::hint::black_box(acc);
        let t1 = thread_cpu().unwrap();
        let p1 = process_cpu().unwrap();
        assert!(t1 > t0, "thread CPU advanced: {t0:?} → {t1:?}");
        assert!(p1 >= p0, "process CPU is monotonic: {p0:?} → {p1:?}");
        assert!(
            p1 - p0 >= (t1 - t0) / 2,
            "process CPU covers this thread's work (allowing clock granularity): \
             thread {:?} process {:?}",
            t1 - t0,
            p1 - p0
        );
    }

    #[test]
    fn the_env_switch_reads_the_agents_truthy_set() {
        // Not touching the real environment (tests run in parallel); the rule is
        // the predicate, so test it on the values.
        let truthy = |v: &str| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        };
        for v in ["1", "true", "TRUE", " yes ", "Yes"] {
            assert!(truthy(v), "{v:?} should switch diagnostics on");
        }
        for v in ["0", "false", "no", "on", "", "enabled"] {
            assert!(
                !truthy(v),
                "{v:?} must NOT switch diagnostics on (the agent's set is 1/true/yes)"
            );
        }
    }
}
