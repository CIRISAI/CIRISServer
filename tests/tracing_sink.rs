//! CIRISServer#279 ask 1 — the file sink must survive losing the install race.
//!
//! The Android field failure: the agent calls a bare `init_tracing()` first
//! (no log_dir), then `init_tracing(log_dir=…)` — and the old code's second
//! `try_init()` silently lost to the first, leaving the eagerly-created dated
//! log 0 bytes forever while compose ran dark. This test reproduces exactly
//! that bare-then-dir sequence in one process (integration tests run in their
//! own process, so the global subscriber is ours alone) and asserts the
//! reload-handle installer retrofits a LIVE, first-write-verified file sink.

use ciris_server::init_tracing_with_status;

fn fresh_dir(tag: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("ciris-tracing-sink-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn dated_len(dir: &std::path::Path) -> u64 {
    let dated = dir.join(format!(
        "ciris-server.log.{}",
        chrono::Utc::now().format("%Y-%m-%d")
    ));
    std::fs::metadata(dated).map(|m| m.len()).unwrap_or(0)
}

#[test]
fn bare_then_dir_retrofits_a_live_file_sink() {
    // 1. The agent's early bare call: installs the subscriber, no file layer.
    let s0 = init_tracing_with_status(None);
    assert!(s0.fresh_subscriber, "first init must win the install");
    assert!(
        !s0.file_layer_attached,
        "no log_dir requested → no file layer"
    );
    assert_eq!(s0.first_write_ok, None);

    // 2. The later log_dir call — the one that silently no-op'd before the fix.
    let dir_a = fresh_dir("a");
    let s1 = init_tracing_with_status(Some(&dir_a));
    assert!(!s1.fresh_subscriber, "subscriber already ours");
    assert!(
        s1.file_layer_attached,
        "the fix: file sink RETROFITS onto the live subscriber"
    );
    assert_eq!(
        s1.first_write_ok,
        Some(true),
        "first-write probe must verify bytes on disk"
    );
    let after_probe = dated_len(&dir_a);
    assert!(
        after_probe > 0,
        "dated log must be non-empty after the probe"
    );

    // 3. Subsequent events keep landing (the sink is live, not a one-off).
    tracing::info!("tracing_sink test event — must reach the dated file");
    assert!(
        dated_len(&dir_a) > after_probe,
        "events after init must grow the dated log"
    );

    // 4. Re-init to a NEW dir (in-process re-serve / process-reuse relaunch):
    //    the slot hot-swaps and the new dir goes live too.
    let dir_b = fresh_dir("b");
    let s2 = init_tracing_with_status(Some(&dir_b));
    assert!(!s2.fresh_subscriber);
    assert!(s2.file_layer_attached);
    assert_eq!(s2.first_write_ok, Some(true));
    assert!(
        dated_len(&dir_b) > 0,
        "swapped sink must write to the new dir"
    );
}
