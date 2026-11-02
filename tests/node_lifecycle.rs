//! The node sleeps with its phone (`ciris_server::node_lifecycle`). Its own
//! test binary: the phase is process-global, and the library tests' cadences
//! would stall while one of these holds the node backgrounded.

use ciris_server::loop_cadence::Cadence;
use ciris_server::node_lifecycle::*;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

/// The phase and the in-pass count are process-global.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A loop that counts its passes and holds each one for `work`.
fn spawn_loop(passes: Arc<AtomicU32>, work: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut c = Cadence::new("config_reconcile", Duration::from_millis(50));
        loop {
            c.tick().await;
            passes.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(work).await;
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backgrounded_loop_starts_no_pass_and_resumes_on_foreground() {
    let _s = SERIAL.lock().await;
    enter_foreground();
    let passes = Arc::new(AtomicU32::new(0));
    let h = spawn_loop(passes.clone(), Duration::from_millis(5));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        passes.load(Ordering::SeqCst) >= 2,
        "foreground: the loop runs"
    );

    let r = tokio::task::spawn_blocking(|| enter_background(Duration::from_secs(2)))
        .await
        .unwrap();
    assert!(r.drained, "a short pass drains inside the deadline: {r:?}");
    assert_eq!(phase(), Phase::Background);
    let frozen = passes.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        passes.load(Ordering::SeqCst),
        frozen,
        "background: no new pass starts across six periods"
    );

    enter_foreground();
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(
        passes.load(Ordering::SeqCst) > frozen,
        "foreground: the overdue pass runs at once, inside one period"
    );
    h.abort();
    enter_foreground();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enter_background_waits_for_the_pass_in_flight_and_honours_its_deadline() {
    let _s = SERIAL.lock().await;
    enter_foreground();
    let passes = Arc::new(AtomicU32::new(0));
    // Each pass holds 400 ms.
    let h = spawn_loop(passes.clone(), Duration::from_millis(400));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(in_pass(), 1, "the loop is mid-pass");

    // A deadline shorter than the pass: reported, not hidden.
    let short = tokio::task::spawn_blocking(|| enter_background(Duration::from_millis(50)))
        .await
        .unwrap();
    assert!(!short.drained && short.still_in_pass == 1, "{short:?}");

    // A deadline longer than the rest of the pass: it drains.
    let long = tokio::task::spawn_blocking(|| enter_background(Duration::from_secs(2)))
        .await
        .unwrap();
    assert!(long.drained, "{long:?}");
    assert_eq!(in_pass(), 0);

    h.abort();
    enter_foreground();
}

/// A transport that records what it was asked, and says whether it closed.
struct FakeTransport {
    quiescent: bool,
    suspends: std::sync::Mutex<Vec<Duration>>,
    resumes: AtomicU32,
}

impl TransportSleep for FakeTransport {
    fn suspend(&self, deadline: Duration) -> bool {
        self.suspends.lock().unwrap().push(deadline);
        self.quiescent
    }
    fn resume(&self) {
        self.resumes.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_transport_sleeps_after_the_loops_and_wakes_before_them() {
    let _s = SERIAL.lock().await;
    enter_foreground();
    let t = Arc::new(FakeTransport {
        quiescent: true,
        suspends: std::sync::Mutex::new(Vec::new()),
        resumes: AtomicU32::new(0),
    });
    set_transport(t.clone());

    let r = tokio::task::spawn_blocking(|| enter_background(Duration::from_secs(3)))
        .await
        .unwrap();
    assert!(
        r.transport_suspended,
        "a quiescent transport is reported: {r:?}"
    );
    let asked = t.suspends.lock().unwrap().clone();
    assert_eq!(asked.len(), 1, "suspended once");
    assert!(
        asked[0] <= Duration::from_secs(3),
        "the transport gets what is LEFT of the host's deadline, never more: {asked:?}"
    );

    enter_foreground();
    assert_eq!(t.resumes.load(Ordering::SeqCst), 1, "resumed on foreground");

    // A transport that could not close in time is reported as such.
    set_transport(Arc::new(FakeTransport {
        quiescent: false,
        suspends: std::sync::Mutex::new(Vec::new()),
        resumes: AtomicU32::new(0),
    }));
    let r = tokio::task::spawn_blocking(|| enter_background(Duration::from_millis(200)))
        .await
        .unwrap();
    assert!(!r.transport_suspended, "{r:?}");
    enter_foreground();
}
