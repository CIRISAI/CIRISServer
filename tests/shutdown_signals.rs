//! The node stops cleanly on SIGTERM as well as SIGINT (CIRISServer#555),
//! with the receiver installed BEFORE anything is bound and kept for the life
//! of the process (#556 review).
//!
//! `docker stop`, systemd and every launcher's polite kill send SIGTERM first.
//! Until 0.5.201 the serve's stop-select awaited only `ctrl_c()` (SIGINT) and
//! the in-process `shutdown_node()`, so SIGTERM took the default action: the
//! process died mid-write with `:4243` / `:4242` released whenever the kernel
//! got to it — the "ports held ~2 s after the pid is gone" the desktop client
//! measured (CIRISClient#40). The first fix installed the handler inside the
//! select, i.e. after the bind and the spawns, and only for one serve call;
//! review caught both. Signal delivery itself is exercised by
//! `node_control::tests::a_real_sigterm_is_latched_and_observed`; this scrapes
//! the ORDER, which no unit test can see: the broker must be installed before
//! the first boot phase, and all three stop triggers must be arms of the ONE
//! select.

fn compose_src() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/compose.rs")).unwrap()
}

#[test]
fn the_sigterm_broker_is_installed_before_the_first_boot_phase() {
    let src = compose_src();
    let install = src
        .find("crate::node_control::install_terminate_broker()")
        .expect("serve_with_adapter installs the SIGTERM broker");
    let first_phase = src
        .find("compose_status::phase(\"halt_gate\")")
        .expect("the first boot phase is stamped");
    let serve = src.find("pub async fn serve_with_adapter(").unwrap();
    assert!(
        serve < install && install < first_phase,
        "install_terminate_broker() must run inside serve_with_adapter BEFORE the first phase \
         (halt_gate) — before anything is bound or spawned"
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
    let nc = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/node_control.rs"))
        .unwrap();
    let code: String = nc
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        code.contains("SignalKind::terminate()"),
        "node_control's broker must install a real SIGTERM handler (SignalKind::terminate())"
    );
}
