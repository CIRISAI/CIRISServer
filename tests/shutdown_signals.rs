//! The node stops cleanly on SIGTERM as well as SIGINT (CIRISServer#555).
//!
//! `docker stop`, systemd and every launcher's polite kill send SIGTERM first.
//! Until 0.5.201 the serve's stop-select awaited only `ctrl_c()` (SIGINT) and
//! the in-process `shutdown_node()`, so SIGTERM took the default action: the
//! process died mid-write with `:4243` / `:4242` released whenever the kernel
//! got to it — the "ports held ~2 s after the pid is gone" the desktop client
//! measured (CIRISClient#40). Signal delivery is not unit-testable without
//! forking a node, so this scrapes the select: all three stop triggers must be
//! arms of the ONE select, and the SIGTERM arm must be a real handler, not a
//! comment.

#[test]
fn the_stop_select_awaits_sigint_sigterm_and_shutdown_node() {
    let src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/compose.rs")).unwrap();
    let start = src
        .find("tokio::select! {\n        r = tokio::signal::ctrl_c()")
        .expect("the serve's stop-select starts with the SIGINT arm");
    let end = start + src[start..].find("\n    }\n").expect("select closes");
    let select = &src[start..end];
    for arm in [
        "tokio::signal::ctrl_c()",
        "terminate_signal()",
        "crate::node_control::shutdown_requested()",
    ] {
        assert!(
            select.contains(arm),
            "stop-select is missing the {arm} arm:\n{select}"
        );
    }
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        code.contains("SignalKind::terminate()"),
        "terminate_signal() must install a real SIGTERM handler (SignalKind::terminate())"
    );
}
