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
    // `send_replace`, not `send`: `watch::Sender::send` drops the value when no
    // receiver is alive, and a `shutdown_node()` that lands after `arm()` but
    // before the serve reaches its stop-select had no receiver yet — the
    // request evaporated and the node kept serving. Same defect the SIGTERM
    // latch had; `arm()` still resets a request that predates the bind.
    latch().send_replace(true);
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

/// Diagnostics for the two halves of the broker: how many times the OS handler
/// ran, and how many bytes the broker thread read. Read by the test and by an
/// operator who wants to know whether a SIGTERM reached the handler.
pub static HANDLER_HITS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
pub static BROKER_READS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The SIGTERM latch. `true` once the process has received SIGTERM; never
/// reset — a terminated process does not un-terminate.
fn terminated_latch() -> &'static watch::Sender<bool> {
    static TX: OnceLock<watch::Sender<bool>> = OnceLock::new();
    TX.get_or_init(|| watch::channel(false).0)
}

/// Whether the process had its OWN SIGTERM handler before the broker chained
/// onto it. `true` = a host (the agent's Python runtime, say) handles SIGTERM
/// and decides what the process does after this node has stopped; `false` =
/// the disposition was the default (terminate), so after a clean teardown the
/// node must finish what the default would have done — see
/// [`propagate_terminate`]. Read once at install; never changes after.
static HOST_OWNS_SIGTERM: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Install the process-wide SIGTERM broker, once. Idempotent; returns when the
/// handler is REGISTERED (not merely requested), so a caller may rely on the
/// disposition from this line on. Where the platform has no SIGTERM, or the
/// handler cannot be installed, this returns and [`terminated`] simply never
/// resolves — the other stop triggers behave exactly as before.
///
/// No tokio in the path, deliberately: a `tokio::signal` stream is drained by
/// whichever runtime's driver wakes first, and a receiver that must outlive
/// every serve call and be observable from any of them cannot depend on which
/// runtimes happen to be alive. The OS handler is async-signal-safe — one
/// non-blocking `write(2)` of one byte to a socketpair — and a plain blocking
/// thread reads it. Order of construction is load-bearing (#556 review): the
/// reader thread exists BEFORE the handler is registered, so there is never a
/// registered handler with nobody behind it; if the handler cannot be
/// registered the writer is dropped and the reader exits.
pub fn install_terminate_broker() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        #[cfg(unix)]
        {
            use std::io::Read as _;
            use std::os::unix::io::{AsRawFd, IntoRawFd};
            let (mut reader, writer) = match std::os::unix::net::UnixStream::pair() {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, "SIGTERM broker: no socketpair — SIGTERM will not stop this node cleanly");
                    return;
                }
            };
            // Non-blocking writer: the handler must never block inside a
            // signal context. If the buffer is full the notification is
            // already pending, and EAGAIN is the right answer.
            if let Err(e) = writer.set_nonblocking(true) {
                tracing::warn!(error = %e, "SIGTERM broker: cannot make the notifier non-blocking — not installing");
                return;
            }
            // Who owned SIGTERM before us? SIG_DFL means nobody: after a clean
            // teardown the node finishes the default action itself.
            // SAFETY: `sigaction` with a null new action only READS the current
            // disposition into `old`, which is zero-initialised storage we own.
            let host_owns = unsafe {
                let mut old: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut old) == 0 {
                    old.sa_sigaction != libc::SIG_DFL
                } else {
                    false
                }
            };
            HOST_OWNS_SIGTERM.store(host_owns, std::sync::atomic::Ordering::SeqCst);

            // 1. The reader, BEFORE the handler exists.
            let spawned = std::thread::Builder::new()
                .name("sigterm-broker".into())
                .spawn(move || {
                    let mut byte = [0u8; 1];
                    // First byte: LATCH FIRST, log second. A stuck tracing sink
                    // must not stand between the signal and the serve loop.
                    if reader.read_exact(&mut byte).is_err() {
                        return;
                    }
                    terminated_latch().send_replace(true);
                    BROKER_READS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::info!("SIGTERM received — latched; the serve stops cleanly (releasing :4243)");
                    // Second byte: the operator insisting. Exit BEFORE anything
                    // that can block; one raw write to stderr is the whole log.
                    if reader.read_exact(&mut byte).is_ok() {
                        let msg = b"ciris-server: second SIGTERM - exiting immediately (143)\n";
                        // SAFETY: a plain write(2) to fd 2 of a static buffer.
                        let _ = unsafe { libc::write(2, msg.as_ptr().cast(), msg.len()) };
                        std::process::exit(143);
                    }
                });
            if let Err(e) = spawned {
                // No reader → no handler. The default disposition stays.
                tracing::warn!(error = %e, "SIGTERM broker thread could not be spawned — SIGTERM keeps its default action");
                return;
            }

            // 2. The handler, now that the reader is waiting. The writer fd is
            // owned by the handler for the life of the process on success; on
            // failure it is dropped here, which ends the reader.
            let wfd = writer.as_raw_fd();
            // SAFETY: the handler does exactly one async-signal-safe call —
            // a non-blocking `write(2)` of a single byte to an fd that is
            // never closed — plus one relaxed atomic add. Registration chains
            // with any handler a host had installed rather than replacing it.
            let registered = unsafe {
                signal_hook_registry::register(libc::SIGTERM, move || {
                    HANDLER_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    // EAGAIN = a byte is already queued = already notified.
                    let _ = libc::write(wfd, b"t".as_ptr().cast(), 1);
                })
            };
            match registered {
                Ok(_) => {
                    let _ = writer.into_raw_fd(); // leak: the handler owns it now
                    tracing::info!(
                        host_owns_sigterm = host_owns,
                        "SIGTERM broker installed — docker stop / systemd stop now end the node cleanly"
                    );
                }
                Err(e) => {
                    drop(writer); // the reader's read_exact fails → thread exits
                    tracing::warn!(
                        error = %e,
                        "cannot install a SIGTERM handler — only SIGINT and shutdown_node() will \
                         stop this node cleanly; SIGTERM keeps its default action"
                    );
                }
            }
        }
    });
}

/// After a SIGTERM-initiated teardown has COMPLETED: finish what the signal
/// asked for. The broker's handler suppressed the default action so the node
/// could unwind cleanly; if nobody else in this process handles SIGTERM (the
/// standalone binary; an embedding host whose disposition was the default),
/// the process must now terminate the way the default would have — restore
/// `SIG_DFL` and re-raise, so the exit status is the conventional one and
/// nothing above us keeps a stopped node's process alive until `docker stop`
/// escalates to SIGKILL (#556 review). If a host DID own SIGTERM, its handler
/// already ran (the registration chains) and the host decides; this returns.
pub fn propagate_terminate() {
    if HOST_OWNS_SIGTERM.load(std::sync::atomic::Ordering::SeqCst) {
        tracing::info!(
            "node stopped on SIGTERM; the embedding host owns SIGTERM and decides what the process does next"
        );
        return;
    }
    #[cfg(unix)]
    {
        tracing::info!(
            "node stopped on SIGTERM — terminating the process (default action, after cleanup)"
        );
        // SAFETY: restoring the default disposition and re-raising a signal
        // this process has already received and finished handling.
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_DFL);
            libc::raise(libc::SIGTERM);
        }
    }
    // Not reached on unix unless the raise was blocked; the conventional status.
    std::process::exit(143);
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

    /// The broker is installed BEFORE the signal is raised (the install returns
    /// only after the OS handler is registered), and a real SIGTERM to this
    /// process is latched and observed by `terminated()` from a runtime the
    /// broker knows nothing about — proving both review findings closed: no
    /// window before installation, and a receiver that outlives any one serve
    /// and any one runtime. One raise only: the second SIGTERM exits the process.
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
            if tokio::time::timeout(Duration::from_secs(5), terminated())
                .await
                .is_err()
            {
                panic!(
                    "terminated() did not resolve after SIGTERM: handler_hits={} broker_reads={} latched={}",
                    HANDLER_HITS.load(std::sync::atomic::Ordering::Relaxed),
                    BROKER_READS.load(std::sync::atomic::Ordering::Relaxed),
                    *terminated_latch().subscribe().borrow()
                );
            }
        });
        assert!(
            *terminated_latch().subscribe().borrow(),
            "latched, never reset"
        );
    }
}
