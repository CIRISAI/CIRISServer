//! In-process node lifecycle control — a shutdown handle for the embedded fold
//! (CIRISServer#276).
//!
//! `serve_with_python_adapter` blocks on its own tokio runtime "until shutdown",
//! and the only stop trigger was ctrl-c or process death — which RACES on an
//! in-process resume/restart (mobile setup-complete → the runtime reloads and a
//! new `serve_with_python_adapter` collides with the prior node still holding
//! `127.0.0.1:4243`, burning the whole ~100s bind window on EADDRINUSE).
//!
//! This exposes the contract the agent needs (issue ask #2): a
//! `ciris_server.shutdown_node()` that (a) signals the running serve to stop and
//! (b) does NOT return until `:4243` is bindable again — the same
//! local-shutdown-and-wait discipline the agent already applies to its own
//! `:8080` brain port. Idempotent: a no-op that returns immediately when no node
//! is serving.
//!
//! Design: a process-global `watch<bool>` latch the serve loop selects on
//! alongside ctrl-c, plus the bound read-API address recorded at bind time so
//! `shutdown_node()` can poll the ACTUAL port to confirm release (testing the
//! postcondition directly beats trusting teardown ordering). All in-process,
//! nothing over the wire.

use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::watch;

/// The shutdown latch. `send(true)` requests stop; the serve loop resets it to
/// `false` when it arms (so a stale request from a prior serve can't kill the
/// next one). A `Sender` with no live receivers still hands out fresh receivers
/// via `subscribe()`, so a static Sender is all we need.
fn latch() -> &'static watch::Sender<bool> {
    static TX: OnceLock<watch::Sender<bool>> = OnceLock::new();
    TX.get_or_init(|| watch::channel(false).0)
}

/// The address the read API is currently bound to, or `None` when not serving.
static BOUND_ADDR: Mutex<Option<SocketAddr>> = Mutex::new(None);

/// Serve start: reset the latch and record the bound read-API address. Called
/// once the read-API listener is up, so `shutdown_node()` knows what port to
/// free and can't act on a stale request from a previous serve.
pub fn arm(read_api_addr: SocketAddr) {
    let _ = latch().send(false);
    *BOUND_ADDR.lock().unwrap_or_else(|p| p.into_inner()) = Some(read_api_addr);
}

/// Serve teardown complete: the port is released, forget it. After this,
/// `shutdown_node()` is a no-op.
pub fn disarm() {
    *BOUND_ADDR.lock().unwrap_or_else(|p| p.into_inner()) = None;
}

/// The address the node is serving on, if any.
pub fn bound_addr() -> Option<SocketAddr> {
    *BOUND_ADDR.lock().unwrap_or_else(|p| p.into_inner())
}

/// Await an in-process shutdown request. Used inside `serve_with_adapter`'s
/// wait-for-shutdown select, alongside ctrl-c. Returns when `shutdown_node()`
/// (or any `request_shutdown()`) fires.
pub async fn shutdown_requested() {
    let mut rx = latch().subscribe();
    // `wait_for` returns immediately if the value is already `true`.
    let _ = rx.wait_for(|v| *v).await;
}

/// Signal the running node to stop (does not wait). `shutdown_node()` layers the
/// port-free wait on top of this.
pub fn request_shutdown() {
    let _ = latch().send(true);
}

// ── SIGTERM, for the life of the PROCESS (CIRISServer#555, #556 review) ──────
//
// Two things a per-serve `tokio::signal::unix::signal(...)` inside the stop
// select gets wrong, both found by review: (1) an async fn installs its handler
// only when the select first polls it, which is AFTER the listener is bound and
// every loop is spawned, so a SIGTERM during boot still killed the process
// abruptly; (2) the stream lived only as long as one serve call, and tokio
// never restores the default disposition once a handler is registered, so a
// SIGTERM between the embedded fold's serve calls was swallowed outright.
//
// So the receiver is owned by a dedicated OS thread with its own tiny runtime,
// installed ONCE per process before the first boot phase, and it latches into a
// `watch<bool>` that every serve's select awaits. A SIGTERM during boot is
// latched and honoured the moment the serve starts waiting — a clean stop
// right after boot instead of a corpse with half-written state. A SIGTERM
// between serves is latched and honoured by the next serve. A SECOND SIGTERM
// after the first is the operator insisting: the process exits at once (143),
// which is what `docker stop`'s escalation and every init system expect.

/// The SIGTERM latch. `true` once the process has received SIGTERM; never
/// reset — a terminated process does not un-terminate.
fn terminated_latch() -> &'static watch::Sender<bool> {
    static TX: OnceLock<watch::Sender<bool>> = OnceLock::new();
    TX.get_or_init(|| watch::channel(false).0)
}

/// Install the process-wide SIGTERM broker, once. Idempotent; returns when the
/// handler is REGISTERED (not merely requested), so a caller may rely on the
/// disposition from this line on. Where the platform has no SIGTERM, or the
/// handler cannot be installed, this returns and [`terminated`] simply never
/// resolves — the other stop triggers behave exactly as before.
pub fn install_terminate_broker() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        #[cfg(unix)]
        {
            let (ready_tx, ready_rx) = std::sync::mpsc::channel::<bool>();
            let spawned = std::thread::Builder::new()
                .name("sigterm-broker".into())
                .spawn(move || {
                    let rt = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(e) => {
                            tracing::warn!(error = %e, "SIGTERM broker: no runtime — SIGTERM will not stop this node cleanly");
                            let _ = ready_tx.send(false);
                            return;
                        }
                    };
                    rt.block_on(async move {
                        use tokio::signal::unix::{signal, SignalKind};
                        let mut sigterm = match signal(SignalKind::terminate()) {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "cannot install a SIGTERM handler — only SIGINT and shutdown_node() will \
                                     stop this node cleanly; SIGTERM will kill it abruptly"
                                );
                                let _ = ready_tx.send(false);
                                return;
                            }
                        };
                        let _ = ready_tx.send(true);
                        sigterm.recv().await;
                        tracing::info!("SIGTERM received — latched; the serve stops cleanly (releasing :4243)");
                        let _ = terminated_latch().send(true);
                        // The operator insisting. Do not swallow it.
                        sigterm.recv().await;
                        tracing::warn!("second SIGTERM — exiting immediately (143)");
                        std::process::exit(143);
                    });
                });
            match spawned {
                Ok(_) => {
                    let registered = ready_rx
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap_or(false);
                    if registered {
                        tracing::info!("SIGTERM broker installed — docker stop / systemd stop now end the node cleanly");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "SIGTERM broker thread could not be spawned");
                }
            }
        }
    });
}

/// Await the process's SIGTERM. Resolves at once if it has already arrived
/// (during boot, or between serves); never resolves where no broker could be
/// installed. Used inside `serve_with_adapter`'s stop select beside ctrl-c and
/// [`shutdown_requested`].
pub async fn terminated() {
    let mut rx = terminated_latch().subscribe();
    // `wait_for` returns immediately if the value is already `true`; the sender
    // is a static, so this only errors if the process is tearing down.
    if rx.wait_for(|v| *v).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// The `ciris_server.shutdown_node()` contract: request stop, then block until
/// the read-API port is bindable again (or `timeout` elapses). Returns `true`
/// once the port is free (or if nothing was serving — idempotent no-op), `false`
/// on timeout. Runs no async/tokio itself — pure blocking probe, safe to call
/// from the agent's Python thread with the GIL released.
pub fn shutdown_node_blocking(timeout: Duration) -> bool {
    let addr = match bound_addr() {
        Some(a) => a,
        None => return true, // not serving — nothing to free
    };
    request_shutdown();
    let start = Instant::now();
    loop {
        // Directly test the postcondition: can we bind the port? An ACTIVE
        // listener still blocks this bind (SO_REUSEADDR permits rebinding a
        // TIME_WAIT socket, NOT stealing a live listener), so a success means
        // the node's listener is truly gone and the next serve can bind.
        match std::net::TcpListener::bind(addr) {
            Ok(l) => {
                drop(l);
                return true;
            }
            Err(_) => {
                if start.elapsed() >= timeout {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // One serial test: `arm`/`disarm`/`latch` are process-global, so parallel
    // sub-tests would race the shared state. Exercise the whole contract in
    // sequence instead.
    #[test]
    fn node_control_contract() {
        // 1. No node serving → shutdown is an immediate no-op success.
        disarm();
        assert!(shutdown_node_blocking(Duration::from_secs(1)));

        // 2. arm records the addr AND resets a stale shutdown request.
        let _ = latch().send(true); // simulate a stale request from a prior serve
        let addr: SocketAddr = "127.0.0.1:4243".parse().unwrap();
        arm(addr);
        assert_eq!(bound_addr(), Some(addr));
        assert!(
            !*latch().subscribe().borrow(),
            "arm must reset the latch to false"
        );

        // 3. With a FREE port recorded as bound, the probe returns at once.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let free = l.local_addr().unwrap();
        drop(l);
        arm(free);
        assert!(shutdown_node_blocking(Duration::from_secs(2)));

        // 4. disarm clears the recorded addr.
        disarm();
        assert_eq!(bound_addr(), None);
    }

    /// The broker is installed BEFORE the signal is raised (the install blocks
    /// until the handler is registered), and a real SIGTERM to this process is
    /// latched and observed by `terminated()` — proving both review findings
    /// closed: no window before installation, and a receiver that outlives any
    /// one serve. One raise only: the second SIGTERM exits the process.
    #[cfg(unix)]
    #[test]
    fn a_real_sigterm_is_latched_and_observed() {
        install_terminate_broker();
        install_terminate_broker(); // idempotent
                                    // SAFETY: raises SIGTERM in this process; the broker's handler is
                                    // registered (install blocked on it), so the default action does not run.
        let rc = unsafe { libc::raise(libc::SIGTERM) };
        assert_eq!(rc, 0, "raise(SIGTERM)");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), terminated())
                .await
                .expect("terminated() resolves after SIGTERM");
        });
        assert!(
            *terminated_latch().subscribe().borrow(),
            "latched, never reset"
        );
    }
}
