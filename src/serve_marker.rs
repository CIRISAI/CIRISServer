//! # The serve marker — a stop that did not go through the door leaves a trace
//!
//! `<data_dir>/serving.json` is written the moment the read API is bound and
//! removed after a CLEAN stop — one that went through `shutdown_node()`,
//! SIGTERM or SIGINT, drained the read API and closed the listener. A boot
//! that finds the file still there therefore knows, from this home alone,
//! that the previous serve ended some other way: the process was replaced
//! (`exec`), killed, or crashed. It says so, with the previous pid, instance
//! and start time, and whether that pid is still alive.
//!
//! # Why this exists (CIRISServer#568)
//!
//! On macOS an agent-hosted node announced itself, and one second later a
//! fresh boot appeared in the same log; the caller of the announce saw a bare
//! `ReadError`. Reading the node log alone there was no way to tell a node
//! that restarts itself from a host that replaced it — the "re-compose" was
//! the agent's setup-complete hand-off, and the dropped response was the
//! client side of that hand-off. The node's own stop door never drops a
//! response (the read API drains under axum's graceful shutdown), but a stop
//! that skips the door leaves no line saying so. Now it leaves this one.
//!
//! The file is not a lock. A live listener already refuses a second bind
//! (`AddrInUse`, enriched with the holder's identity); the marker only makes
//! the PREVIOUS serve's ending legible to the next one.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// File name under the data dir.
pub const FILE_NAME: &str = "serving.json";

/// What a serving node writes about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marker {
    /// The serving process.
    pub pid: u32,
    /// `node_identity::instance_id()` — the same id `/health.node` answers.
    pub instance_id: String,
    /// `node_identity::started_at_rfc3339()` — the same instant `/health.node` answers.
    pub started_at: String,
    /// The read API listener.
    pub listen_addr: String,
    /// The configured key the node serves as.
    pub key_id: String,
    /// The process's start identity where the platform has one (Linux:
    /// `/proc/<pid>/stat` starttime, in clock ticks since boot). A container
    /// restart commonly re-uses the pid — often PID 1 — so pid alone cannot
    /// tell "still running" from "replaced"; this can (Codex on #569).
    #[serde(default)]
    pub proc_start: Option<u64>,
}

/// What the previous serve on this home left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Previous {
    /// No marker: the previous serve stopped through the door (or there was none).
    Clean,
    /// A marker: the previous serve did NOT stop through the door.
    Unclean {
        marker: Marker,
        /// Whether that pid still exists (`None` where the platform cannot say).
        pid_alive: Option<bool>,
    },
    /// A marker that could not be read — still evidence of an unclean stop.
    Unreadable { path: PathBuf, error: String },
}

/// Where the marker lives for a data dir.
#[must_use]
pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

/// Read what the previous serve left, without touching it.
#[must_use]
pub fn inspect(data_dir: &Path) -> Previous {
    let p = path(data_dir);
    let bytes = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Previous::Clean,
        Err(e) => {
            return Previous::Unreadable {
                path: p,
                error: e.to_string(),
            }
        }
    };
    match serde_json::from_slice::<Marker>(&bytes) {
        Ok(marker) => {
            let pid_alive = previous_is_alive(&marker);
            Previous::Unclean { marker, pid_alive }
        }
        Err(e) => Previous::Unreadable {
            path: p,
            error: e.to_string(),
        },
    }
}

/// Is the serve that wrote `marker` still running — the SAME process, not a
/// later one that inherited its pid?
///
/// Three questions, in order: is the pid ours (a re-used pid after a restart
/// — PID 1 in a container — is us, not a survivor); does the pid exist; and,
/// where the platform records one, does its start identity match what the
/// marker recorded. `None` where the platform can answer none of it.
#[must_use]
pub fn previous_is_alive(marker: &Marker) -> Option<bool> {
    if marker.pid == std::process::id() {
        return Some(false);
    }
    match pid_is_alive(marker.pid) {
        Some(true) => match (marker.proc_start, proc_start_of(marker.pid)) {
            (Some(recorded), Some(now)) if recorded != now => Some(false),
            _ => Some(true),
        },
        other => other,
    }
}

/// A process's start identity: Linux `/proc/<pid>/stat` field 22 (starttime,
/// clock ticks since boot). `None` elsewhere or when unreadable.
#[must_use]
pub fn proc_start_of(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // The comm field is parenthesised and may contain spaces: split after
        // the LAST ')' so a process named "a b)" cannot shift the columns.
        let rest = stat.rsplit_once(')')?.1;
        // `rest` begins with the state field (3); starttime is field 22, so
        // index 22 - 3 = 19 among the remaining whitespace-separated fields.
        rest.split_whitespace().nth(19)?.parse().ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// Does `pid` name a live process? `None` where the platform cannot say.
#[must_use]
pub fn pid_is_alive(pid: u32) -> Option<bool> {
    #[cfg(unix)]
    {
        // SAFETY: `kill(pid, 0)` sends no signal; it only checks existence
        // and permission. EPERM means the process exists but is not ours —
        // still alive for this question.
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if rc == 0 {
            return Some(true);
        }
        Some(std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM))
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        None
    }
}

/// First thing in a serve: say what the previous serve left, record it for the
/// in-process status channel, and clear it so this serve's own marker can be
/// written. Returns what was found.
pub fn inspect_at_boot(data_dir: &Path) -> Previous {
    let prev = inspect(data_dir);
    match &prev {
        Previous::Clean => {
            tracing::debug!(
                path = %path(data_dir).display(),
                "no serve marker — the previous serve on this home stopped through the door"
            );
        }
        Previous::Unclean { marker, pid_alive } => {
            crate::compose_status::mark("previous_serve_unclean");
            match pid_alive {
                Some(true) => tracing::error!(
                    previous_pid = marker.pid,
                    previous_instance_id = %marker.instance_id,
                    previous_started_at = %marker.started_at,
                    previous_listen_addr = %marker.listen_addr,
                    previous_key_id = %marker.key_id,
                    "the previous serve on this home is STILL RUNNING (its serve marker is \
                     present and its pid is alive) — this boot will fail to bind the read API \
                     with AddrInUse. Stop it through shutdown_node() / SIGTERM first \
                     (CIRISServer#568)"
                ),
                _ => tracing::warn!(
                    previous_pid = marker.pid,
                    previous_instance_id = %marker.instance_id,
                    previous_started_at = %marker.started_at,
                    previous_listen_addr = %marker.listen_addr,
                    previous_key_id = %marker.key_id,
                    pid_alive = ?pid_alive,
                    "the previous serve on this home did NOT stop through the shutdown door: \
                     the process was replaced (exec), killed, or crashed before \
                     shutdown_node() / SIGTERM drained its read API. Any HTTP response in \
                     flight at that instant was lost to its caller, and a client that kept a \
                     pooled connection to it will see a reset on its next request. This is the \
                     HOST's hand-off, not a node restart (CIRISServer#568)"
                ),
            }
        }
        Previous::Unreadable { path, error } => {
            crate::compose_status::mark("previous_serve_unclean");
            tracing::warn!(
                path = %path.display(),
                error = %error,
                "a serve marker is present but unreadable — the previous serve did not stop \
                 through the door, and what it wrote is damaged (CIRISServer#568)"
            );
        }
    }
    // A marker owned by a LIVE serve is that serve's, not ours to clear: this
    // boot will fail its bind, and if the survivor is later killed the next
    // boot must still find its marker (Codex on #569). Only a dead or damaged
    // one is cleared, so this serve can write its own.
    let keep = previous_still_running(&prev);
    if !keep && !matches!(prev, Previous::Clean) {
        let _ = std::fs::remove_file(path(data_dir));
    }
    prev
}

/// Whether [`inspect_at_boot`] found a previous serve still running — in which
/// case this serve must NOT write a marker over it.
#[must_use]
pub fn previous_still_running(prev: &Previous) -> bool {
    matches!(
        prev,
        Previous::Unclean {
            pid_alive: Some(true),
            ..
        }
    )
}

/// Write this serve's marker. Called just BEFORE the read API binds: lens-core
/// binds and exposes the accept loop inside one call, so a marker written
/// after it returns leaves a window in which a request can be accepted and the
/// process killed with no marker on disk (Codex on #569). A bind failure
/// clears it again (see `compose`).
pub fn write(data_dir: &Path, listen_addr: SocketAddr, key_id: &str) -> std::io::Result<()> {
    let marker = Marker {
        pid: std::process::id(),
        instance_id: crate::node_identity::instance_id().to_owned(),
        started_at: crate::node_identity::started_at_rfc3339(),
        listen_addr: listen_addr.to_string(),
        key_id: key_id.to_owned(),
        proc_start: proc_start_of(std::process::id()),
    };
    let p = path(data_dir);
    let tmp = p.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(&marker).map_err(std::io::Error::other)?;
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &p)?;
    tracing::info!(
        path = %p.display(),
        pid = marker.pid,
        instance_id = %marker.instance_id,
        "serve marker written — cleared only by a stop through the door; a boot that \
         finds it here will say this serve was replaced or killed (CIRISServer#568)"
    );
    Ok(())
}

/// Remove this serve's marker — and ONLY this serve's: the file is read first
/// and left alone unless its `pid` and `instance_id` are ours. Two boots
/// racing for one home can both write before one loses the bind; the loser's
/// clean-up must not take the winner's marker with it (Codex on #569). Called
/// after the read API has drained (no response can be in flight) and on the
/// bind-failure arm (no listener ever existed).
pub fn clear(data_dir: &Path) {
    let p = path(data_dir);
    match std::fs::read(&p)
        .ok()
        .and_then(|b| serde_json::from_slice::<Marker>(&b).ok())
    {
        Some(m)
            if m.pid != std::process::id()
                || m.instance_id != crate::node_identity::instance_id() =>
        {
            tracing::info!(
                path = %p.display(),
                owner_pid = m.pid,
                owner_instance_id = %m.instance_id,
                "serve marker left in place — it belongs to another serve on this home, not \
                 to this one"
            );
            return;
        }
        _ => {}
    }
    match std::fs::remove_file(&p) {
        Ok(()) => tracing::info!(
            path = %p.display(),
            "serve marker cleared — the read API drained and the listener closed through \
             the shutdown door; nothing was in flight"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(path = %p.display(), error = %e, "could not clear the serve marker")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ciris-serve-marker-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&d).expect("scratch dir");
        d
    }

    #[test]
    fn a_clean_home_has_no_marker_and_a_bound_serve_writes_one() {
        let d = scratch();
        assert_eq!(inspect(&d), Previous::Clean);
        write(&d, "127.0.0.1:4243".parse().unwrap(), "ciris-server").expect("write");
        match inspect(&d) {
            Previous::Unclean { marker, pid_alive } => {
                assert_eq!(marker.pid, std::process::id());
                assert_eq!(marker.listen_addr, "127.0.0.1:4243");
                assert_eq!(marker.key_id, "ciris-server");
                // A marker naming OUR OWN pid is by definition not a survivor
                // (a re-used pid after a restart — Codex on #569), so the
                // question "is the previous serve still running" is `false`.
                assert_eq!(
                    pid_alive,
                    Some(false),
                    "our own marker is a replaced serve, not a survivor"
                );
            }
            other => panic!("expected the marker we just wrote, got {other:?}"),
        }
        clear(&d);
        assert_eq!(inspect(&d), Previous::Clean, "a clean stop leaves nothing");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_marker_from_a_dead_process_reads_as_an_unclean_stop_and_is_cleared_at_boot() {
        let d = scratch();
        let stale = Marker {
            pid: 4_000_000, // beyond any sane pid space; dead everywhere we run
            instance_id: "prev-instance".into(),
            started_at: "2026-09-08T13:12:27Z".into(),
            listen_addr: "127.0.0.1:4243".into(),
            key_id: "ciris-server".into(),
            proc_start: None,
        };
        std::fs::write(path(&d), serde_json::to_vec(&stale).unwrap()).unwrap();
        match inspect_at_boot(&d) {
            Previous::Unclean { marker, pid_alive } => {
                assert_eq!(marker.instance_id, "prev-instance");
                #[cfg(unix)]
                assert_eq!(pid_alive, Some(false));
                #[cfg(not(unix))]
                assert_eq!(pid_alive, None);
            }
            other => panic!("expected an unclean previous serve, got {other:?}"),
        }
        assert_eq!(inspect(&d), Previous::Clean, "boot clears the stale marker");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A container restart hands the new serve the old serve's pid (PID 1).
    /// A marker naming OUR OWN pid is a replaced serve, never a survivor.
    #[test]
    fn a_marker_with_our_own_pid_is_a_replaced_serve_not_a_survivor() {
        let d = scratch();
        let reused = Marker {
            pid: std::process::id(),
            instance_id: "the-previous-life-of-pid-1".into(),
            started_at: "2026-09-08T15:15:20Z".into(),
            listen_addr: "0.0.0.0:4243".into(),
            key_id: "ciris-server".into(),
            proc_start: Some(1),
        };
        std::fs::write(path(&d), serde_json::to_vec(&reused).unwrap()).unwrap();
        match inspect_at_boot(&d) {
            Previous::Unclean { pid_alive, .. } => assert_eq!(pid_alive, Some(false)),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            inspect(&d),
            Previous::Clean,
            "and it was cleared for this serve's own"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A marker owned by a LIVE, different process is left alone: the bind
    /// will fail, and the survivor's marker must outlive this failed boot.
    #[cfg(unix)]
    #[test]
    fn a_live_previous_serve_keeps_its_marker() {
        let d = scratch();
        // pid 1 (init) is alive on every unix and is never us in a test.
        let live = Marker {
            pid: 1,
            instance_id: "the-survivor".into(),
            started_at: "2026-09-08T15:15:20Z".into(),
            listen_addr: "0.0.0.0:4243".into(),
            key_id: "ciris-server".into(),
            proc_start: proc_start_of(1),
        };
        std::fs::write(path(&d), serde_json::to_vec(&live).unwrap()).unwrap();
        let prev = inspect_at_boot(&d);
        assert!(previous_still_running(&prev), "{prev:?}");
        assert!(
            path(&d).exists(),
            "the survivor's marker is not ours to clear"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_reused_pid_with_a_different_start_identity_is_not_alive() {
        let d = scratch();
        // pid 1 is alive; a marker claiming pid 1 with the WRONG start identity
        // describes a process that no longer exists.
        let stale = Marker {
            pid: 1,
            instance_id: "prev".into(),
            started_at: "2026-09-08T15:15:20Z".into(),
            listen_addr: "0.0.0.0:4243".into(),
            key_id: "ciris-server".into(),
            proc_start: Some(u64::MAX),
        };
        std::fs::write(path(&d), serde_json::to_vec(&stale).unwrap()).unwrap();
        match inspect(&d) {
            Previous::Unclean { pid_alive, .. } => assert_eq!(pid_alive, Some(false)),
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `clear` takes only its own marker: another serve's stays.
    #[test]
    fn clear_leaves_another_serves_marker_alone() {
        let d = scratch();
        let theirs = Marker {
            pid: std::process::id().wrapping_add(1),
            instance_id: "someone-else".into(),
            started_at: "2026-09-08T16:00:00Z".into(),
            listen_addr: "0.0.0.0:4243".into(),
            key_id: "ciris-server".into(),
            proc_start: None,
        };
        std::fs::write(path(&d), serde_json::to_vec(&theirs).unwrap()).unwrap();
        clear(&d);
        assert!(
            path(&d).exists(),
            "another serve's marker survives our clear"
        );
        write(&d, "127.0.0.1:4243".parse().unwrap(), "ciris-server").expect("write ours");
        clear(&d);
        assert!(!path(&d).exists(), "our own marker is cleared");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_damaged_marker_is_still_evidence_and_is_cleared() {
        let d = scratch();
        std::fs::write(path(&d), b"{not json").unwrap();
        assert!(matches!(inspect_at_boot(&d), Previous::Unreadable { .. }));
        assert_eq!(inspect(&d), Previous::Clean);
        let _ = std::fs::remove_dir_all(&d);
    }
}
