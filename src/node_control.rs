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
}
