//! **Managed vs personal deployment** — the port of CIRISAgent's
//! `path_resolution.is_managed()` (CIRISServer#396).
//!
//! # Why this distinction is load-bearing for AUTH
//!
//! The two deployments answer "who may sign in?" in opposite ways, and the same
//! code serves both:
//!
//! - **Managed** (CIRIS Manager, the web agents): an operator provisions people
//!   ahead of time and a fresh OAuth identity getting an `observer` account is a
//!   sensible default. That is the behaviour the Python has had for a year.
//! - **Personal** (this desktop, this phone): the node has exactly ONE human.
//!   Creating an account for whoever can reach the port is a foothold handed out
//!   for proving control of an unrelated email.
//!
//! `resolve_oauth_user` therefore refuses an unknown identity on a CLAIMED
//! PERSONAL node, and keeps creating on a managed one. Getting the detection
//! wrong in the permissive direction re-opens the hole; getting it wrong in the
//! restrictive direction locks every web agent's users out. So the logic is
//! COPIED, not invented — a second, cleverer answer to a question the agent has
//! already answered in production is exactly how two systems drift apart.
//!
//! # The majority rule is deliberate
//!
//! Upstream takes five indicators and requires ≥2. Not one, because any single
//! signal is absent in some legitimate deployment (an env var nobody set, a
//! bind-mount that is a plain directory); not all five, because that would fail
//! the moment a deployment differs in one detail. Two independent signals is the
//! judgement they landed on, and it is preserved here exactly rather than
//! re-derived.

/// `true` when this process looks like a CIRIS Manager deployment.
///
/// Five indicators, managed iff at least two agree — the upstream rule:
///
/// 1. `CIRIS_MANAGED=true`
/// 2. `/app/data` is a mount point
/// 3. `/app/logs` is a mount point
/// 4. `CIRIS_SERVICE_TOKEN` is set (only the manager sets it)
/// 5. Docker (`/.dockerenv`) **and** `/app/data` **and** `/app/logs` exist
pub fn is_managed() -> bool {
    let indicators = [
        std::env::var("CIRIS_MANAGED")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        is_mount_point("/app/data"),
        is_mount_point("/app/logs"),
        std::env::var("CIRIS_SERVICE_TOKEN")
            .map(|v| !v.is_empty())
            .unwrap_or(false),
        std::path::Path::new("/.dockerenv").exists()
            && std::path::Path::new("/app/data").exists()
            && std::path::Path::new("/app/logs").exists(),
    ];
    indicators.iter().filter(|b| **b).count() >= 2
}

/// Is `path` a mount point? (`os.path.ismount` — a directory whose device
/// differs from its parent's.)
///
/// A path that does not exist, or that cannot be stat'd, is NOT a mount — the
/// permissive direction here would be to guess "managed", which re-opens the
/// account-creation hole on a personal node. Unknown ⇒ not an indicator.
fn is_mount_point(path: &str) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let p = std::path::Path::new(path);
        let Ok(meta) = std::fs::metadata(p) else {
            return false;
        };
        if !meta.is_dir() {
            return false;
        }
        // The filesystem root is its own parent; treat it as a mount.
        let Some(parent) = p.parent() else {
            return true;
        };
        match std::fs::metadata(parent) {
            Ok(pm) => meta.dev() != pm.dev(),
            Err(_) => false,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bare developer box is PERSONAL. If this ever flips, every personal node
    /// silently starts creating accounts for any OAuth identity again — the exact
    /// hole CIRISServer#396 closed, re-opened by a detection change rather than
    /// by an auth change, which is where nobody would look.
    #[test]
    fn a_plain_workstation_is_not_managed() {
        // Only meaningful when the env is not deliberately set (CI sets neither).
        if std::env::var("CIRIS_MANAGED").is_ok() || std::env::var("CIRIS_SERVICE_TOKEN").is_ok() {
            eprintln!("SKIP (not a pass): the managed env vars are set in this environment");
            return;
        }
        assert!(
            !is_managed(),
            "a workstation with no manager env vars and no /app mounts must read as PERSONAL"
        );
    }

    /// A path that does not exist is not a mount. The unknown case must fall to
    /// `false` on EVERY platform, because `true` is the permissive answer here.
    #[test]
    fn mount_detection_fails_closed_on_the_unknown() {
        assert!(
            !is_mount_point("/definitely/not/a/real/path/ciris"),
            "a nonexistent path must not read as a mount — guessing 'managed' re-opens the hole"
        );
    }

    /// The POSITIVE case is POSIX-only. `/` being its own parent's device is a
    /// Unix fact, and the `cfg(not(unix))` arm returns `false` for everything by
    /// design — the `/app/*` mount indicators describe a Linux container, so on
    /// Windows they SHOULD contribute nothing rather than be emulated.
    ///
    /// Asserting this unconditionally is what turned CI red on windows-latest
    /// only: the test claimed a portable fact about a deliberately
    /// platform-specific function.
    #[cfg(unix)]
    #[test]
    fn the_filesystem_root_is_a_mount_on_unix() {
        assert!(is_mount_point("/"), "the filesystem root is a mount point");
    }

    /// …and on non-Unix the detector is inert, which must stay TRUE-by-test
    /// rather than true-by-nobody-looking. A Windows host is personal unless the
    /// env vars say otherwise, and that is the intended reading.
    #[cfg(not(unix))]
    #[test]
    fn mount_indicators_are_inert_off_unix() {
        assert!(
            !is_mount_point("/") && !is_mount_point("/app/data"),
            "the non-Unix arm must contribute NO mount indicators — the /app/* signals describe a \
             Linux container, and emulating them would let a Windows box read as managed"
        );
    }
}
