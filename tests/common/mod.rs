//! Shared scaffolding for the integration tests.

#![allow(dead_code)] // each binary uses a different subset

use ciris_server::degradation::{self, Warning};

/// **A raised degradation warning that cannot outlive the test that raised it.**
///
/// # The bug this exists to make impossible
///
/// The degradation registry is a process-global. A test that raised into it and
/// cleared afterwards leaked the warning whenever anything between the two
/// unwound — and in `folded_health` the space between them contained an
/// assertion, a loopback bind and two HTTP round-trips, any of which can fail
/// under a loaded runner:
///
/// ```text
///     raise("test.forced_node_fault");                  // 575
///     assert_eq!(baseline, ("degraded", true), ...);    // can panic
///     spawn_brain(...).await; get_health(...).await;    // can panic
///     clear("test.forced_node_fault");                  // 593 — skipped on unwind
/// ```
///
/// A leaked `critical` degrades every later case's baseline, so ONE failure
/// became four, none of them in the test that actually broke. That is what
/// landed on `main` at the 0.5.196 merge after eleven consecutive green runs.
///
/// A guard is the fix rather than a tidier call order: correctness stops
/// depending on the body of the test completing, which is the one thing a test
/// cannot promise.
///
/// It also clears BEFORE raising, so a stale twin from an earlier crashed run
/// cannot make a fixture look already-degraded — the defensive shape
/// `health_reports_degradation` and `retention_loop` already use.
///
/// Deliberately per-code, never a registry reset: `degradation::reset_for_test`
/// is private on purpose, so a test "clears exactly what it asserts on rather
/// than being handed a lever that empties a live node's health".
#[must_use = "the warning is cleared when this guard drops — binding it to `_` clears it immediately"]
pub struct RaisedWarning {
    code: &'static str,
}

impl RaisedWarning {
    /// Raise a `critical` for the lifetime of the guard.
    pub fn critical(code: &'static str, message: &str) -> Self {
        degradation::clear(code);
        degradation::raise(Warning::critical(code, message));
        Self { code }
    }

    /// Raise an `error` for the lifetime of the guard.
    pub fn error(code: &'static str, message: &str) -> Self {
        degradation::clear(code);
        degradation::raise(Warning::error(code, message));
        Self { code }
    }

    /// Raise an `advisory` for the lifetime of the guard.
    pub fn advisory(code: &'static str, message: &str) -> Self {
        degradation::clear(code);
        degradation::raise(Warning::advisory(code, message));
        Self { code }
    }

    /// The code this guard will clear.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }
}

impl Drop for RaisedWarning {
    fn drop(&mut self) {
        // Runs on the unwind path too, which is the entire point.
        degradation::clear(self.code);
    }
}
