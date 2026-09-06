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

/// Arm diagnostics from the serve entry point: ON if the CLI flag was given or
/// the environment asks, naming which; returns the resulting state so the
/// caller can record it on `ServerConfig`. The ONE place the two switches meet,
/// so the binary, the wheel's `py_main` and the embedded adapter cannot read
/// them differently.
pub fn arm(flag: bool) -> bool {
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

/// The diagnostics router. Mounted by compose ONLY when diagnostics are on;
/// every route in it sits behind the loopback guard the setup routes use.
pub fn router() -> Router {
    Router::new()
        .route(ROUTE_MEMORY, get(memory))
        .layer(axum::middleware::from_fn(
            crate::auth::loopback::require_loopback,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
