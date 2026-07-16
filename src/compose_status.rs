//! Compose-phase status — the in-process boot progress channel (CIRISServer#279).
//!
//! The fourth embedded-fold layer: on android_24_x86_64 `serve_with_python_adapter`
//! can hang INSIDE compose — 4243 never binds, no panic surfaces, and every
//! byte-channel diagnostic is dark on that topology (the tracing file sink writes
//! 0 bytes at compose time, and rust `eprintln!` to raw fd 2 is dropped under
//! Chaquopy — only Python's `sys.stderr` object reaches logcat). So progress must
//! ride the one channel proven to work there: an **in-process accessor**, the
//! same pattern as `first_run_claim_pin()` (#277).
//!
//! Mechanism: `serve_with_adapter` stamps [`phase`] at each boot seam. The stamp
//! records the previous phase's elapsed time into a bounded history and starts
//! the clock on the new one. The embedding host polls
//! `ciris_server.compose_status()` (PyO3, lib.rs) and gets a JSON snapshot —
//! when compose hangs, **the `current` phase in the snapshot IS the hang point**:
//! a one-line RCA instead of a 13-minute dark timeout.
//!
//! A watchdog thread (spawned on the first stamp) turns a hang into a loud,
//! *fast* verdict: any phase older than [`STUCK_AFTER`] is flagged `stuck: true`
//! in the snapshot and re-WARNed via `tracing` every [`WATCHDOG_TICK`] — a
//! record-and-continue watchdog, deliberately NOT an abort: boot semantics are
//! unchanged on the platforms that complete (Docker ~2s, arm32 ~minutes), and
//! the embedding host owns the kill decision (it can see `stuck` + `elapsed_s`
//! and time out on its own policy).
//!
//! Everything here is IN-PROCESS ONLY: never serialized to disk, never served
//! over any HTTP route, gone at process exit.

use std::sync::Mutex;
use std::time::Instant;

/// A phase is considered STUCK once it has run this many seconds. The slowest
/// legitimate phase observed in the field is fresh-home keyring genesis on an
/// old arm32 phone (minutes) — so the flag is a *diagnostic* signal, not proof
/// of deadlock; the watchdog never aborts.
const STUCK_AFTER_SECS: u64 = 60;
/// Watchdog re-check + re-WARN cadence while a phase is stuck.
const WATCHDOG_TICK_SECS: u64 = 15;
/// Bounded phase history (compose has ~20 seams; headroom for re-serves).
const MAX_HISTORY: usize = 64;

struct State {
    /// Name of the phase currently executing (None before the first stamp and
    /// after `complete()`).
    current: Option<&'static str>,
    /// When the current phase started.
    started: Option<Instant>,
    /// Completed phases in order: (name, elapsed milliseconds).
    history: Vec<(&'static str, u128)>,
    /// Set by `complete()` — compose finished and the read-API is bound.
    completed: bool,
    /// Whether the watchdog thread has been spawned (once per process).
    watchdog_running: bool,
    /// How many times the watchdog has flagged the CURRENT phase (resets on
    /// each new phase). Serialized so the host can see repeat-WARN pressure.
    stuck_warnings: u32,
}

static STATE: Mutex<State> = Mutex::new(State {
    current: None,
    started: None,
    history: Vec::new(),
    completed: false,
    watchdog_running: false,
    stuck_warnings: 0,
});

/// Stamp entry into a named compose phase. Records the previous phase's elapsed
/// time into the history and starts the clock on `name`. Called at each boot
/// seam in `serve_with_adapter`; cheap (one mutex lock), safe from any thread.
pub fn phase(name: &'static str) {
    let mut s = STATE.lock().unwrap_or_else(|p| p.into_inner());
    // A re-serve in the same process (tests, desktop restarts) starts a fresh
    // record — the snapshot describes the CURRENT boot, not a prior one.
    if s.completed {
        s.history.clear();
        s.completed = false;
    }
    if let (Some(prev), Some(started)) = (s.current, s.started) {
        if s.history.len() < MAX_HISTORY {
            s.history.push((prev, started.elapsed().as_millis()));
        }
    }
    s.current = Some(name);
    s.started = Some(Instant::now());
    s.stuck_warnings = 0;
    tracing::info!(phase = name, "compose phase");
    if !s.watchdog_running {
        s.watchdog_running = true;
        spawn_watchdog();
    }
}

/// Mark compose complete (the read-API listener is bound and serving). The
/// watchdog goes quiet; the final phase's elapsed joins the history.
pub fn complete() {
    let mut s = STATE.lock().unwrap_or_else(|p| p.into_inner());
    if let (Some(prev), Some(started)) = (s.current, s.started) {
        if s.history.len() < MAX_HISTORY {
            s.history.push((prev, started.elapsed().as_millis()));
        }
    }
    s.current = None;
    s.started = None;
    s.completed = true;
    let total_ms: u128 = s.history.iter().map(|(_, ms)| ms).sum();
    tracing::info!(total_ms, "compose complete — read API bound");
}

/// JSON snapshot of compose progress for the embedding host (the
/// `ciris_server.compose_status()` PyO3 accessor). Shape:
///
/// ```json
/// {
///   "completed": false,
///   "current": {"phase": "edge_runtime", "elapsed_s": 74.2, "stuck": true},
///   "history": [{"phase": "halt_gate", "ms": 3}, ...]
/// }
/// ```
///
/// `current` is `null` before the first stamp and after completion. `stuck`
/// flips true once the phase exceeds the stuck threshold — on a compose hang,
/// `current.phase` is the one-line RCA.
pub fn snapshot_json() -> String {
    let s = STATE.lock().unwrap_or_else(|p| p.into_inner());
    let current = match (s.current, s.started) {
        (Some(name), Some(started)) => {
            let elapsed = started.elapsed().as_secs_f64();
            serde_json::json!({
                "phase": name,
                "elapsed_s": (elapsed * 10.0).round() / 10.0,
                "stuck": elapsed as u64 >= STUCK_AFTER_SECS,
                "stuck_warnings": s.stuck_warnings,
            })
        }
        _ => serde_json::Value::Null,
    };
    let history: Vec<serde_json::Value> = s
        .history
        .iter()
        .map(|(name, ms)| serde_json::json!({"phase": name, "ms": ms}))
        .collect();
    serde_json::json!({
        "completed": s.completed,
        "current": current,
        "history": history,
    })
    .to_string()
}

/// The record-and-continue watchdog: while compose is in flight, WARN (via
/// tracing — visible wherever ANY sink works, and mirrored into the snapshot's
/// `stuck_warnings`) every tick that the current phase exceeds the stuck
/// threshold. A plain OS thread: no runtime dependency, works even when the
/// tokio runtime itself is what's wedged.
fn spawn_watchdog() {
    std::thread::Builder::new()
        .name("compose-watchdog".into())
        .spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(WATCHDOG_TICK_SECS));
            let mut s = STATE.lock().unwrap_or_else(|p| p.into_inner());
            if s.completed {
                // Boot finished — park until a re-serve stamps a new phase.
                if s.current.is_none() {
                    continue;
                }
            }
            if let (Some(name), Some(started)) = (s.current, s.started) {
                let elapsed = started.elapsed().as_secs();
                if elapsed >= STUCK_AFTER_SECS {
                    s.stuck_warnings += 1;
                    let warnings = s.stuck_warnings;
                    drop(s);
                    tracing::warn!(
                        phase = name,
                        elapsed_s = elapsed,
                        warnings,
                        "compose phase STUCK — boot has not progressed past this \
                         phase (watchdog record-and-continue; poll \
                         ciris_server.compose_status() for the live snapshot) [#279]"
                    );
                }
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phases_accumulate_and_complete() {
        phase("test_alpha");
        phase("test_beta");
        let snap: serde_json::Value = serde_json::from_str(&snapshot_json()).unwrap();
        assert_eq!(snap["completed"], false);
        assert_eq!(snap["current"]["phase"], "test_beta");
        assert_eq!(snap["current"]["stuck"], false);
        // alpha's elapsed landed in history.
        assert!(snap["history"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["phase"] == "test_alpha"));

        complete();
        let snap: serde_json::Value = serde_json::from_str(&snapshot_json()).unwrap();
        assert_eq!(snap["completed"], true);
        assert!(snap["current"].is_null());
        // beta joined the history on completion.
        assert!(snap["history"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["phase"] == "test_beta"));

        // A re-serve starts a fresh record.
        phase("test_gamma");
        let snap: serde_json::Value = serde_json::from_str(&snapshot_json()).unwrap();
        assert_eq!(snap["completed"], false);
        assert_eq!(snap["current"]["phase"], "test_gamma");
        assert!(!snap["history"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["phase"] == "test_alpha"));
        complete();
    }
}
