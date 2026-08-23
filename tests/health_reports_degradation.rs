//! **`GET /v1/health` says when the node is in trouble** (CIRISServer#446/#480).
//!
//! The route returned a hardcoded `"status": "ok"` while the canonical was
//! SIGKILLed 193 times at 93% of its memory limit. Every watcher above it —
//! ciris-status, the client's own `degradedMode` banner, the load balancer —
//! read that word and believed the node. The client had been parsing
//! `status != "ok" || degradedMode || warnings.isNotEmpty()` the whole time
//! against a producer that never populated any of the three.
//!
//! These are the properties a watcher relies on. They are pinned here rather
//! than in `health_names_the_node.rs` because that file documents a strict
//! single-`stamp()` ordering discipline for `node_identity`, and nothing below
//! touches it.
//!
//! PROCESS-GLOBAL STATE: the degradation registry is shared by every case in
//! this binary, so each takes `REGISTRY_LOCK` and clears only what it asserts
//! on. `reset_for_test` is deliberately not public — a test gets no lever that
//! would empty a live node's health.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _; // for `oneshot`

use ciris_server::degradation::{self, Warning};
use ciris_server::health;

static REGISTRY_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const TEST_CODE: &str = "test.synthetic_fault";

async fn health_data(path: &str) -> serde_json::Value {
    let resp = health::router()
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("collect body");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    v["data"].clone()
}

/// **Every resource reading is a STATE, never a bare number.**
///
/// This is the distinct-zeroes discipline at the wire. A node that cannot read
/// its cgroup and a node using 0% must not render alike: the first is a probe
/// that failed and the second is an idle node, and a watcher that cannot tell
/// them apart will eventually page someone about the wrong one — or, far worse,
/// not page them at all.
///
/// Asserted on the DISCRIMINANT rather than on values, because the values
/// legitimately differ per host: CI containers have cgroup v2 and PSI, the
/// macOS runners have neither, and both must produce a well-formed reading.
#[tokio::test]
async fn every_resource_reading_names_its_state_on_every_host() {
    let _g = REGISTRY_LOCK.lock().await;
    let data = health_data("/v1/health").await;

    for probe in ["memory", "cpu", "io"] {
        let r = &data["resources"][probe];
        assert!(
            r.is_object(),
            "resources.{probe} is missing or not an object — a health surface that omits a \
             probe teaches its reader the probe is fine: {data:#}"
        );
        let state = r["state"].as_str().unwrap_or_default();
        assert!(
            !state.is_empty(),
            "resources.{probe} carries no `state` discriminant, so 'we could not measure' and \
             'the answer is zero' render alike — the exact collapse this module exists to \
             prevent: {r:#}"
        );
        if state == "unavailable" {
            assert!(
                r["reason"].as_str().is_some_and(|s| !s.is_empty()),
                "an unavailable {probe} reading must SAY WHY it is unavailable — 'no PSI on \
                 this kernel' and 'permission denied' send an operator to different places: \
                 {r:#}"
            );
        }
    }
}

/// The status word is DERIVED, and an error-severity warning flips it.
///
/// The two halves are one property: the word must move, and it must move
/// *because of the registry* rather than because some handler asserted it.
#[tokio::test]
async fn an_error_warning_flips_the_status_word_and_rides_the_payload() {
    let _g = REGISTRY_LOCK.lock().await;
    degradation::clear(TEST_CODE);

    let before = health_data("/v1/health").await;
    assert_eq!(
        before["degraded_mode"], false,
        "fixture: this node must start undegraded — if a real probe on the CI host is \
         raising, this test's premise is wrong, not its assertion: {before:#}"
    );

    degradation::raise(Warning::error(
        TEST_CODE,
        "a synthetic fault, to prove the word is derived and not asserted",
    ));
    let after = health_data("/v1/health").await;

    assert_eq!(
        after["status"], "degraded",
        "a standing error left the status word at `ok`. This is verbatim the 0.5.182 \
         condition: 193 SIGKILLs under a surface that said the node was fine: {after:#}"
    );
    assert_eq!(after["degraded_mode"], true);
    let codes: Vec<&str> = after["warnings"]
        .as_array()
        .expect("warnings must always be an array, empty on a healthy node")
        .iter()
        .filter_map(|w| w["code"].as_str())
        .collect();
    assert!(
        codes.contains(&TEST_CODE),
        "the flag flipped but the REASON did not ride along, leaving a watcher that knows \
         something is wrong and cannot say what: {codes:?}"
    );

    degradation::clear(TEST_CODE);
    let recovered = health_data("/v1/health").await;
    assert_eq!(
        recovered["status"], "ok",
        "a cleared registry must read `ok` again — a status word that only ever degrades is \
         one operators stop reading: {recovered:#}"
    );
}

/// An ADVISORY must not degrade the node.
///
/// If `degraded_mode` meant "any warning", it would mean nothing within a week
/// of shipping: an advisory is "worth knowing", a degradation is "this node is
/// not doing its whole job", and a load balancer draining traffic on the former
/// is an outage caused by the health surface.
#[tokio::test]
async fn an_advisory_is_reported_without_degrading_the_node() {
    let _g = REGISTRY_LOCK.lock().await;
    degradation::clear(TEST_CODE);

    degradation::raise(Warning::advisory(
        TEST_CODE,
        "worth knowing, not worth draining",
    ));
    let data = health_data("/v1/health").await;

    assert_eq!(
        data["status"], "ok",
        "an advisory degraded the node. A drain on 'worth knowing' is an outage the health \
         surface caused: {data:#}"
    );
    assert_eq!(data["degraded_mode"], false);
    let codes: Vec<&str> = data["warnings"]
        .as_array()
        .expect("warnings array")
        .iter()
        .filter_map(|w| w["code"].as_str())
        .collect();
    assert!(
        codes.contains(&TEST_CODE),
        "not degrading is not the same as not REPORTING — the advisory must still be \
         visible: {codes:?}"
    );

    degradation::clear(TEST_CODE);
}

/// **The expensive reading must stay off this route.**
///
/// Byte counts and row totals are what an operator wants, and this is exactly
/// the route they will be tempted to add them to. `storage_summary` is six
/// `count(*)`s plus two PRAGMAs; `count(*)` is a full scan on Postgres and the
/// attestation table is the largest thing on the node. `/v1/health` is polled
/// by every watcher in the mesh on a timer — putting the footprint here would
/// turn the health check into the load.
///
/// That reading lives on `GET /v1/node/state`, which is documented as
/// not-for-seconds-cadence polling. This test is the guard on the comment.
#[tokio::test]
async fn health_stays_cheap_and_leaves_the_store_footprint_to_node_state() {
    let _g = REGISTRY_LOCK.lock().await;
    let data = health_data("/v1/health").await;

    for expensive in ["store", "total_disk_bytes", "rows", "records"] {
        assert!(
            data.get(expensive).is_none() && data["resources"].get(expensive).is_none(),
            "`{expensive}` reached /v1/health. It costs a full-table scan per poll, and every \
             watcher in the mesh polls this route on a timer — the health check would become \
             the load it is meant to detect. It belongs on /v1/node/state: {data:#}"
        );
    }
}

/// **Nothing here may take a node down** (the arm32 / iOS / Home Assistant
/// rule).
///
/// This module is an INSTRUMENT. An instrument that panics is worse than one
/// that reads `unavailable`, because the failure it causes is bigger than the
/// one it was watching for — and these run on 32-bit targets where integer
/// overflow panics in a debug build, on iOS and Android where there is no
/// cgroup and no PSI, and inside Home Assistant add-ons where `/sys` may not
/// be readable at all.
///
/// So: saturated counters, a counter that ran backwards, and a probe pass on
/// whatever host this happens to be. Any panic fails the test.
#[tokio::test]
async fn the_instrument_survives_saturated_counters_and_a_hostile_host() {
    use ciris_edge::observability::{EdgeMetrics, RoundOutcome};
    let _g = REGISTRY_LOCK.lock().await;

    let mut bundle = EdgeMetrics::new().snapshot();
    // Every counter at the ceiling: the sum of these overflows u64, which is a
    // debug-build panic for `Iterator::sum` and a wrapped garbage denominator
    // for the release build. Both are unacceptable in a health path.
    bundle
        .replication_round_outcomes_total
        .insert(RoundOutcome::TimedOut, u64::MAX);
    bundle
        .replication_round_outcomes_total
        .insert(RoundOutcome::Completed, u64::MAX);
    bundle
        .replication_round_outcomes_total
        .insert(RoundOutcome::Refused, u64::MAX);
    bundle.replication_inbound_backpressure_drops = u64::MAX;
    degradation::report_edge_metrics(&bundle);
    degradation::report_edge_metrics(&bundle);

    // And straight back to zero — an edge restart, mid-window.
    degradation::report_edge_metrics(&EdgeMetrics::new().snapshot());

    // The raise points, driven directly at their edges.
    degradation::report_network_rounds(0, 0);
    degradation::report_network_rounds(u64::MAX, 1);
    degradation::report_backpressure_drops(u64::MAX);

    // The probes, on whatever this host is. On CI that is Linux with cgroup v2
    // and PSI; on the macOS runners it is neither, and the requirement is the
    // same: report, do not panic.
    let _ = degradation::probe_memory();
    let _ = degradation::probe_contention();

    // Still serving, and still well-formed. A surface that survives by
    // returning nothing has not survived.
    let data = health_data("/v1/health").await;
    assert!(
        data["warnings"].is_array() && !data["status"].as_str().unwrap_or_default().is_empty(),
        "the health payload did not survive the hostile pass intact: {data:#}"
    );

    degradation::report_backpressure_drops(0);
    degradation::report_network_rounds(0, 0);
}
