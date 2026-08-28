//! **Public mesh status** — counts, cached, with an `as_of` (CIRISServer#498).
//!
//! The mesh being alive is public information, and today nothing says so: this
//! node's own state lives behind a session on `/v1/node/state`, and `/v1/health`
//! carries identity only.
//!
//! # Why the cache is part of the contract
//!
//! The figures are `COUNT(*)`-class reads over the largest tables the node holds —
//! 101,631 `trace_events` and 15,477 attestations on the canonical when this was
//! written, while that same node ran at ~91% CPU and 85–88% of a 2 GiB limit. An
//! uncached public endpoint doing those reads per request is an amplification
//! vector aimed at the mesh's bridge, which is simultaneously the most-queried and
//! most-loaded member. So the snapshot is served from cache and refreshed on a
//! cadence, never computed for a caller.
//!
//! `as_of` ships with it. A stale answer is fine; a stale answer that reads as
//! current is not.
//!
//! # Whose numbers these are
//!
//! One observer's converged view, and the payload says which observer. A canonical
//! is where peers' rows converge, so a canonical's view IS the mesh status for
//! practical purposes — but it is still a view, and labelling it as one is the
//! difference between a fact and a claim about the whole world.
//!
//! Deliberately NOT reported as "nodes in the mesh": of 748 federation keys on the
//! canonical, 715 are agents and 14 are nodes. A bare count of the directory would
//! be wrong by two orders of magnitude as a node count, and "14" would silently
//! mean "nodes this observer has heard of".
//!
//! # Unknown is not zero
//!
//! Every figure is optional and a read failure leaves it `None`, which serializes
//! as `null`. Reporting `0` for a count we could not take would say the mesh is
//! empty — the strongest possible claim — on the evidence of a failed query. The
//! same discipline `operator_surface` applies to the trace corpus: *absence of
//! arrivals from an unread corpus is not absence of arrivals.*

use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;

/// How long a snapshot is served before a refresh is due.
///
/// Fifteen minutes, not one. The read underneath is `storage_summary()`, whose
/// SQLite path runs `SELECT COALESCE(SUM(pgsize),0) FROM dbstat` — a virtual table
/// that walks EVERY PAGE of the database. On the canonical's 1.24 GiB store that
/// is O(database size), not a cheap count, and it took the read API down at a
/// 60-second cadence (CIRISServer#501). Mesh counts do not move meaningfully
/// inside fifteen minutes; the read API does.
pub const CACHE_TTL: Duration = Duration::from_secs(900);

/// How long a FAILED snapshot is served before another attempt.
///
/// A failed read IS cached — its `unavailable` notes are the current truth, and
/// discarding them would leave callers reading a healthy older snapshot while the
/// store is unreadable. But caching it for the full TTL turns a transient database
/// error into fifteen minutes of "mesh unavailable" on a public surface, with no
/// periodic loop left to retry it (Codex, PR #502). Short enough to recover
/// promptly, long enough that a persistent failure is not a retry storm against a
/// store already in trouble.
pub const FAILED_TTL: Duration = Duration::from_secs(30);

/// The freshness window for a given snapshot — the short one when the read failed.
fn ttl_for(snap: &MeshStatus) -> Duration {
    if snap.unavailable.is_empty() {
        CACHE_TTL
    } else {
        FAILED_TTL
    }
}

/// A point-in-time, public view of the mesh as one observer has converged it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MeshStatus {
    /// When these figures were taken. Always present — a snapshot with no age is
    /// indistinguishable from a live read.
    pub as_of: DateTime<Utc>,
    /// Seconds after `as_of` at which a consumer should expect a fresher figure.
    pub stale_after_seconds: u64,
    /// The node whose converged view this is. `null` when it could not be resolved.
    pub observer_key_id: Option<String>,
    /// Federation identities known to this observer — keys of every kind, NOT a
    /// node count. `null` when unread.
    pub identities: Option<u64>,
    /// Trace events this observer holds. `null` when unread.
    pub trace_events: Option<u64>,
    /// Human-readable notes for every figure that could not be read, so a consumer
    /// can tell "nothing there" from "we could not look".
    pub unavailable: Vec<String>,
}

impl MeshStatus {
    /// A snapshot that reports nothing, because nothing could be read yet.
    ///
    /// Every figure `null` and the reason in words — never zeroes, which would say
    /// the mesh is empty on the evidence of not having looked.
    #[must_use]
    pub fn unread(why: &str) -> Self {
        Self {
            as_of: Utc::now(),
            // ZERO, not the TTL. This is a transient placeholder handed to a caller
            // that lost the refresh race, and a real snapshot may land moments
            // later. Stamping the full TTL would tell a consumer honouring the
            // contract that an all-null mesh is current for fifteen minutes, so it
            // would keep showing "unavailable" long after the winner populated the
            // cache (Codex, PR #502). Already stale ⇒ retry at will.
            stale_after_seconds: 0,
            observer_key_id: None,
            identities: None,
            trace_events: None,
            unavailable: vec![why.to_owned()],
        }
    }

    /// Is this snapshot still inside its TTL at `now`?
    #[must_use]
    pub fn is_fresh_at(taken: Instant, now: Instant, ttl: Duration) -> bool {
        now.duration_since(taken) < ttl
    }
}

static CACHE: Mutex<Option<(Instant, MeshStatus)>> = Mutex::new(None);
static REFRESHING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Serve the cached snapshot, refreshing only when it has aged past [`CACHE_TTL`].
///
/// A poisoned lock recomputes rather than failing: a status surface that goes dark
/// because of its own cache is worse than one that costs a query.
pub async fn cached(engine: &std::sync::Arc<ciris_persist::prelude::Engine>) -> MeshStatus {
    let now = Instant::now();
    if let Some(snap) = fresh_snapshot(now) {
        return snap;
    }

    // SINGLE-FLIGHT. Without it, a burst arriving after the TTL expires starts one
    // page-walk per request — and this endpoint is public, so a burst is the
    // expected shape rather than the unlucky one. A caller that loses the race is
    // served the stale snapshot, which is what `as_of` is for.
    let Some(flight) = RefreshFlight::claim() else {
        return last_snapshot().unwrap_or_else(|| {
            MeshStatus::unread("a refresh is already in flight and no snapshot has been taken yet")
        });
    };
    refresh_off_runtime(engine, flight).await
}

/// The cached snapshot if it is still inside its TTL at `now`.
fn fresh_snapshot(now: Instant) -> Option<MeshStatus> {
    let guard = CACHE.lock().ok()?;
    let (taken, snap) = guard.as_ref()?;
    MeshStatus::is_fresh_at(*taken, now, ttl_for(snap)).then(|| snap.clone())
}

/// The cached snapshot regardless of age.
fn last_snapshot() -> Option<MeshStatus> {
    CACHE.lock().ok()?.as_ref().map(|(_, s)| s.clone())
}

/// Marks a refresh in flight and clears it on drop, so a panic in the read cannot
/// wedge the flag and leave the surface permanently stale.
struct RefreshFlight;

impl RefreshFlight {
    fn claim() -> Option<Self> {
        (!REFRESHING.swap(true, std::sync::atomic::Ordering::SeqCst)).then_some(Self)
    }
}

impl Drop for RefreshFlight {
    fn drop(&mut self) {
        REFRESHING.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Take the snapshot on a BLOCKING thread, never on a runtime worker.
///
/// `storage_summary()` does its SQLite work inline — no `spawn_blocking` anywhere
/// in persist's retention path — so awaiting it from a worker occupies that worker
/// for the whole page walk. A `#[tokio::main]` runtime sizes to core count, so on a
/// 2-vCPU host that is one of TWO workers, and the accept loop loses: the socket
/// stays LISTEN while `Recv-Q` climbs and nothing is ever accepted
/// (CIRISServer#501). A blocking thread is not a worker, so the walk cannot starve
/// the read API however long it takes.
async fn refresh_off_runtime(
    engine: &std::sync::Arc<ciris_persist::prelude::Engine>,
    flight: RefreshFlight,
) -> MeshStatus {
    let engine = std::sync::Arc::clone(engine);
    let handle = tokio::runtime::Handle::current();
    // The claim is MOVED INTO the blocking task, and that placement IS the
    // protection. A started blocking task cannot be cancelled, but the future
    // awaiting it can be — a client disconnect drops this frame. If the guard lived
    // here it would release while the page walk was still running, letting the next
    // request claim the slot and start a SECOND walk; repeated cancellation against
    // a public endpoint would defeat single-flight entirely and rebuild the
    // amplification it exists to prevent (Codex, PR #502). Owned by the work.
    match tokio::task::spawn_blocking(move || {
        let _flight = flight;
        handle.block_on(refresh_into_cache(&engine))
    })
    .await
    {
        Ok(snap) => snap,
        Err(e) => last_snapshot()
            .unwrap_or_else(|| MeshStatus::unread(&format!("refresh task failed: {e}"))),
    }
}

/// Take a new snapshot, reading each figure independently so one failure does not
/// blank the rest.
pub async fn refresh(engine: &ciris_persist::prelude::Engine) -> MeshStatus {
    let mut unavailable: Vec<String> = Vec::new();

    let (identities, trace_events) = match engine.storage_summary().await {
        Ok(s) => (Some(s.federation_keys.rows), Some(s.trace_events.rows)),
        Err(e) => {
            unavailable.push(format!(
                "identities and trace_events: the store summary could not be read ({e}). \
                 These are reported as null, not zero — an unread count is not an empty mesh."
            ));
            (None, None)
        }
    };

    let observer_key_id = match crate::node_key::wire_identity() {
        Some(k) => Some(k.to_owned()),
        None => match engine.local_derived_key_id().await {
            Ok(k) => Some(k),
            Err(e) => {
                unavailable.push(format!(
                    "observer_key_id: could not resolve this node's key ({e})"
                ));
                None
            }
        },
    };

    let mut snap = MeshStatus {
        as_of: Utc::now(),
        stale_after_seconds: CACHE_TTL.as_secs(),
        observer_key_id,
        identities,
        trace_events,
        unavailable,
    };
    // The advertised retry interval must match the one actually enforced, or a
    // consumer honouring the contract waits fifteen minutes on a snapshot this node
    // will itself replace in thirty seconds.
    snap.stale_after_seconds = ttl_for(&snap).as_secs();
    snap
}

/// Take a snapshot and store it, whatever its outcome.
///
/// A refresh that FAILED is still worth caching: its `unavailable` notes are the
/// current truth, and discarding it would leave callers reading a healthy older
/// snapshot while the store is unreadable.
async fn refresh_into_cache(engine: &ciris_persist::prelude::Engine) -> MeshStatus {
    let fresh = refresh(engine).await;
    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some((Instant::now(), fresh.clone()));
    }
    fresh
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap() -> MeshStatus {
        MeshStatus {
            as_of: Utc::now(),
            stale_after_seconds: CACHE_TTL.as_secs(),
            observer_key_id: Some("obs".into()),
            identities: Some(748),
            trace_events: Some(101_631),
            unavailable: Vec::new(),
        }
    }

    #[test]
    fn an_unread_count_is_null_not_zero() {
        // Reporting 0 for a count we could not take says the mesh is EMPTY — the
        // strongest possible claim — on the evidence of a failed query.
        let mut s = snap();
        s.identities = None;
        s.trace_events = None;
        let v = serde_json::to_value(&s).expect("serialize");
        assert!(v["identities"].is_null(), "{v}");
        assert!(v["trace_events"].is_null(), "{v}");
        assert_ne!(v["identities"], serde_json::json!(0));
    }

    #[test]
    fn a_genuine_zero_is_still_zero() {
        // The other half: an empty store must report 0, not null, or "we looked and
        // found nothing" becomes indistinguishable from "we could not look".
        let mut s = snap();
        s.identities = Some(0);
        let v = serde_json::to_value(&s).expect("serialize");
        assert_eq!(v["identities"], serde_json::json!(0));
        assert!(!v["identities"].is_null());
    }

    #[test]
    fn every_snapshot_carries_its_age() {
        let v = serde_json::to_value(snap()).expect("serialize");
        assert!(
            v["as_of"].is_string(),
            "a snapshot with no age reads as live"
        );
        assert_eq!(v["stale_after_seconds"], serde_json::json!(900));
    }

    #[test]
    fn freshness_is_bounded_by_the_ttl() {
        let t0 = Instant::now();
        assert!(MeshStatus::is_fresh_at(
            t0,
            t0 + Duration::from_secs(899),
            CACHE_TTL
        ));
        assert!(!MeshStatus::is_fresh_at(
            t0,
            t0 + Duration::from_secs(900),
            CACHE_TTL
        ));
    }

    /// The read underneath walks every page of the database. At a 60-second TTL
    /// that took the read API down on a 2-vCPU canonical (CIRISServer#501), so the
    /// interval is pinned: a future tightening should have to argue with this test.
    #[test]
    fn the_ttl_is_long_because_the_read_is_a_page_walk() {
        assert!(
            CACHE_TTL >= Duration::from_secs(600),
            "storage_summary() runs SUM(pgsize) FROM dbstat — O(database size). \
             A short TTL turns a status endpoint into a scheduled full scan."
        );
    }

    /// A failed read is served briefly, not for the full TTL — otherwise a
    /// transient database error becomes fifteen minutes of "mesh unavailable" on a
    /// public surface, with no periodic loop left to retry it.
    #[test]
    fn a_failed_snapshot_expires_fast_and_says_so() {
        let mut failed = snap();
        failed.unavailable.push("store unreadable".into());
        assert_eq!(ttl_for(&failed), FAILED_TTL);
        assert!(FAILED_TTL < CACHE_TTL);

        let good = snap();
        assert_eq!(
            ttl_for(&good),
            CACHE_TTL,
            "a healthy snapshot keeps the long TTL"
        );
    }

    /// Only ONE page walk in flight, ever — and the slot survives a panic.
    ///
    /// ONE test, not two: `REFRESHING` is a process-global and the harness runs
    /// tests in parallel, so two tests each claiming it would fail each other
    /// nondeterministically while the implementation was correct (Codex, PR #502).
    /// Sequential assertions in one test cannot race themselves.
    #[test]
    fn the_refresh_slot_is_exclusive_and_panic_safe() {
        let first = RefreshFlight::claim().expect("first wins");
        assert!(
            RefreshFlight::claim().is_none(),
            "a second walk must not start while one is running"
        );
        drop(first);
        assert!(RefreshFlight::claim().is_some(), "the slot is reusable");

        let _ = std::panic::catch_unwind(|| {
            let _f = RefreshFlight::claim().expect("claim");
            panic!("read blew up");
        });
        assert!(
            RefreshFlight::claim().is_some(),
            "Drop releases the slot even when the read panics"
        );
    }

    /// "Nothing read yet" reports nulls and a reason — never zeroes, which would
    /// say the mesh is empty on the evidence of not having looked.
    #[test]
    fn an_unread_snapshot_is_null_everywhere_with_a_reason() {
        let v = serde_json::to_value(MeshStatus::unread("no snapshot yet")).expect("serialize");
        assert!(v["identities"].is_null());
        assert!(v["trace_events"].is_null());
        assert!(v["observer_key_id"].is_null());
        assert_eq!(v["unavailable"][0], "no snapshot yet");
    }

    #[test]
    fn the_observer_is_named_so_the_view_is_not_mistaken_for_the_world() {
        // 715 of the canonical's 748 keys are agents and 14 are nodes. An unlabelled
        // count invites "748 nodes in the mesh", wrong by two orders of magnitude.
        let v = serde_json::to_value(snap()).expect("serialize");
        assert_eq!(v["observer_key_id"], "obs");
        assert!(
            v.get("nodes").is_none(),
            "must not claim a node count it cannot take"
        );
    }

    #[test]
    fn a_failed_read_says_so_in_words() {
        let mut s = snap();
        s.identities = None;
        s.unavailable
            .push("identities: the store summary could not be read".into());
        let v = serde_json::to_value(&s).expect("serialize");
        assert!(!v["unavailable"].as_array().unwrap().is_empty());
    }

    #[test]
    fn contents_are_never_enumerated() {
        // A public surface that lists peers is a reconnaissance surface. Counts only.
        let v = serde_json::to_value(snap()).expect("serialize");
        let obj = v.as_object().expect("object");
        for k in ["peers", "keys", "key_ids", "nodes_list", "agents"] {
            assert!(!obj.contains_key(k), "{k} must not be on a public surface");
        }
    }
}
