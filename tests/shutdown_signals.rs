//! The node stops cleanly on SIGTERM as well as SIGINT (CIRISServer#555),
//! with the receiver installed BEFORE anything is bound, kept for the life of
//! the process, and the process ending afterwards the way the default action
//! would have (#556 review, four rounds).
//!
//! `docker stop`, systemd and every launcher's polite kill send SIGTERM first.
//! Until 0.5.201 the serve's stop-select awaited only `ctrl_c()` (SIGINT) and
//! the in-process `shutdown_node()`, so SIGTERM took the default action: the
//! process died mid-write with `:4243` / `:4242` released whenever the kernel
//! got to it — the "ports held ~2 s after the pid is gone" the desktop client
//! measured (CIRISClient#40). Signal delivery itself is exercised by
//! `node_control::tests::a_real_sigterm_is_latched_and_observed`; this scrapes
//! the shapes no unit test can see — the ORDER of installation, the arms of the
//! ONE select, what the broker thread may and may not do, and who answers a
//! signal the serve did not get to.

fn compose_src() -> String {
    // A Windows checkout carries CRLF; the patterns below embed `\n`, so
    // normalise first or the gate reads "no select" on one OS (0.5.202).
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/compose.rs"))
        .unwrap()
        .replace("\r\n", "\n")
}

fn node_control_code() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/node_control.rs"))
        .unwrap()
        .replace("\r\n", "\n")
        .split("#[cfg(test)]")
        .next()
        .unwrap()
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_sigterm_broker_is_installed_before_the_first_boot_phase() {
    let src = compose_src();
    let serve = src.find("pub async fn serve_with_adapter(").unwrap();
    let install = src
        .find("crate::node_control::install_terminate_broker()")
        .expect("serve_with_adapter installs the SIGTERM broker");
    let began = src
        .find("crate::node_control::serve_began()")
        .expect("serve_with_adapter marks the serve active");
    let first_phase = src
        .find("compose_status::phase(\"halt_gate\")")
        .expect("the first boot phase is stamped");
    assert!(
        serve < install && install < began && began < first_phase,
        "install the broker, then mark the serve active, BEFORE the first phase — before \
         anything is bound or spawned"
    );
    assert!(
        src.contains("crate::node_control::serve_ended()"),
        "serve_ended must run on every exit (the guard), so a boot that fails past installation \
         still answers a latched SIGTERM"
    );
}

#[test]
fn the_stop_select_awaits_sigint_sigterm_and_shutdown_node() {
    let src = compose_src();
    let start = src
        .find("tokio::select! {\n        r = tokio::signal::ctrl_c()")
        .expect("the serve's stop-select starts with the SIGINT arm");
    let end = start + src[start..].find("\n    }\n").expect("select closes");
    let select = &src[start..end];
    for arm in [
        "tokio::signal::ctrl_c()",
        "crate::node_control::terminated()",
        "crate::node_control::shutdown_requested()",
    ] {
        assert!(
            select.contains(arm),
            "stop-select is missing the {arm} arm:\n{select}"
        );
    }
    assert!(
        !src.contains("fn terminate_signal("),
        "the per-serve SIGTERM helper is back; the receiver must live in node_control for the process lifetime"
    );
    assert!(
        src.contains("stopped_by_sigterm || crate::node_control::terminated_now()"),
        "the LATCH decides propagation after teardown, not only the arm that won the select"
    );
}

#[test]
fn the_broker_owns_the_signal_and_never_blocks_on_a_log() {
    let code = node_control_code();
    assert!(
        code.contains("signal_hook_registry::register(libc::SIGTERM"),
        "node_control's broker must install a real OS-level SIGTERM handler"
    );
    let spawn_at = code
        .find(".name(\"sigterm-broker\"")
        .expect("broker thread");
    let register_at = code
        .find("signal_hook_registry::register(libc::SIGTERM")
        .unwrap();
    assert!(
        spawn_at < register_at,
        "the reader thread must exist BEFORE the handler is registered"
    );
    assert!(
        code.contains("set_nonblocking(true)"),
        "the handler's notifier must be non-blocking"
    );
    assert!(
        code.contains("terminated_latch().send_replace(true)"),
        "the latch stores unconditionally"
    );
    assert!(
        code.contains("latch().send_replace(false)"),
        "arm() must reset with send_replace: a retained request would stop every later serve"
    );
    // The broker closure: no tracing, and it propagates when nothing is serving.
    let broker_end = spawn_at
        + code[spawn_at..]
            .find("if let Err(e) = spawned")
            .expect("the spawn result is checked");
    let broker = &code[spawn_at..broker_end];
    assert!(
        !broker.contains("tracing::"),
        "the broker thread must not touch tracing:\n{broker}"
    );
    assert!(
        broker.contains("propagate_terminate()"),
        "with no serve active the broker propagates itself"
    );
    // propagate_terminate may run on the broker thread: no tracing there either.
    let p0 = code.find("pub fn propagate_terminate()").unwrap();
    let p1 = p0 + code[p0..].find("\n}\n").unwrap();
    assert!(
        !code[p0..p1].contains("tracing::"),
        "propagate_terminate must not touch tracing"
    );
}
