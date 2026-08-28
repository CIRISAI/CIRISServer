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
pub const CACHE_TTL: Duration = Duration::from_secs(60);

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
    /// Is this snapshot still inside its TTL at `now`?
    #[must_use]
    pub fn is_fresh_at(taken: Instant, now: Instant, ttl: Duration) -> bool {
        now.duration_since(taken) < ttl
    }
}

static CACHE: Mutex<Option<(Instant, MeshStatus)>> = Mutex::new(None);

/// Serve the cached snapshot, refreshing only when it has aged past [`CACHE_TTL`].
///
/// A poisoned lock recomputes rather than failing: a status surface that goes dark
/// because of its own cache is worse than one that costs a query.
pub async fn cached(engine: &ciris_persist::prelude::Engine) -> MeshStatus {
    let now = Instant::now();
    if let Ok(guard) = CACHE.lock() {
        if let Some((taken, snap)) = guard.as_ref() {
            if MeshStatus::is_fresh_at(*taken, now, CACHE_TTL) {
                return snap.clone();
            }
        }
    }
    let fresh = refresh(engine).await;
    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some((Instant::now(), fresh.clone()));
    }
    fresh
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

    MeshStatus {
        as_of: Utc::now(),
        stale_after_seconds: CACHE_TTL.as_secs(),
        observer_key_id,
        identities,
        trace_events,
        unavailable,
    }
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
        assert_eq!(v["stale_after_seconds"], serde_json::json!(60));
    }

    #[test]
    fn freshness_is_bounded_by_the_ttl() {
        let t0 = Instant::now();
        assert!(MeshStatus::is_fresh_at(
            t0,
            t0 + Duration::from_secs(59),
            CACHE_TTL
        ));
        assert!(!MeshStatus::is_fresh_at(
            t0,
            t0 + Duration::from_secs(60),
            CACHE_TTL
        ));
        assert!(!MeshStatus::is_fresh_at(
            t0,
            t0 + Duration::from_secs(3600),
            CACHE_TTL
        ));
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
