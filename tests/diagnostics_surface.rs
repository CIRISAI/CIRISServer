//! Operator diagnostics are OFF by default, ON by an explicit switch, and
//! loopback-only when on; and the read-API listener binds before the three
//! corpus-growth loops start (CIRISServer#549 / #550).
//!
//! Three gates on three claims:
//! 1. the switch — `--diagnostics` parses, `--diagnostics=x` does not, and the
//!    default is off (the flag parser is the ONE place both serve entry points
//!    read it);
//! 2. the guard — the memory route answers a loopback caller and refuses any
//!    other, and refuses when the caller's address cannot be established
//!    (fail closed, same posture as the setup routes);
//! 3. the order — in `compose.rs` the `read_api_bind` stamp precedes the
//!    `edge_run`, `replication_loop` and `config_reconcile_loop` stamps, and the
//!    marks that make the bind phase legible exist. A src-scrape, like the
//!    repo's other order gates, because the boot path has no in-process
//!    reordering seam to test against and a reorder that regresses would be
//!    invisible everywhere but a 2-vCPU box.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

const ROUTE: &str = ciris_server::diag::ROUTE_MEMORY;

fn compose_src() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/compose.rs")).unwrap()
}

#[test]
fn the_switch_is_a_bare_flag_and_off_by_default() {
    let (_, _, on) = ciris_server::parse_serve_flags(None, std::iter::empty()).unwrap();
    assert!(!on, "diagnostics must default OFF");

    let args = ["--home=/tmp/x", "--diagnostics", "--key-id", "k"].map(String::from);
    let (home, key_id, on) = ciris_server::parse_serve_flags(None, args.into_iter()).unwrap();
    assert!(on, "--diagnostics switches it on");
    assert_eq!(home.to_string_lossy(), "/tmp/x");
    assert_eq!(key_id, "k");

    // The flag takes no value: `--diagnostics=on` is the spelling drift that
    // would let one entry point read "on" and the other read nothing.
    let args = ["--diagnostics=on"].map(String::from);
    let err = ciris_server::parse_serve_flags(None, args.into_iter()).unwrap_err();
    assert!(
        err.to_string().contains("unknown serve arg"),
        "a valued --diagnostics is refused: {err}"
    );
}

async fn get(from: Option<SocketAddr>) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder().uri(ROUTE).method("GET");
    if let Some(addr) = from {
        req = req.extension(ConnectInfo(addr));
    }
    let resp = ciris_server::diag::router()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, body)
}

#[tokio::test]
async fn the_memory_route_answers_loopback_and_refuses_everyone_else() {
    let (status, body) = get(Some(SocketAddr::from(([127, 0, 0, 1], 51423)))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["proc"].is_object(), "kernel view present: {body}");
    assert!(
        body["node"]["instance_id"].is_string(),
        "tied to a process: {body}"
    );
    assert!(
        body["compose"]["detail"].is_array(),
        "boot marks present: {body}"
    );
    #[cfg(target_env = "gnu")]
    {
        assert!(
            body["mallinfo2"]["uordblks"].is_u64(),
            "allocator view present: {body}"
        );
        assert!(body["live_fraction"].is_f64(), "the one number: {body}");
    }

    let (status, _) = get(Some(SocketAddr::from(([10, 0, 0, 7], 40000)))).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a non-loopback caller is refused"
    );

    // No ConnectInfo at all — the listener was not served with connect info, or
    // a test forgot. Fail CLOSED, like the setup routes.
    let (status, _) = get(None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an unknown caller address is refused"
    );
}

#[test]
fn the_listener_binds_before_the_loops_start() {
    let src = compose_src();
    let at = |stamp: &str| {
        src.find(&format!("compose_status::phase(\"{stamp}\")"))
            .unwrap_or_else(|| panic!("compose.rs stamps phase {stamp:?}"))
    };
    let bind = at("read_api_bind");
    let serving = at("read_api_serving");
    assert!(bind < serving);
    for late in ["edge_run", "replication_loop", "config_reconcile_loop"] {
        assert!(
            at(late) > serving,
            "phase {late:?} must start AFTER read_api_serving (#549: the loops' first \
             ticks starved the router build on a 2-vCPU box); found it before the bind"
        );
    }
    // The pieces the router DOES need stay ahead of the bind.
    for early in [
        "edge_runtime",
        "edge_slices",
        "transport_binding",
        "peering",
        "holonomic",
    ] {
        assert!(
            at(early) < bind,
            "phase {early:?} must precede read_api_bind"
        );
    }
    // And the loops still start before the adapter and the boot is complete.
    let adapter = at("adapter_start");
    for late in ["edge_run", "replication_loop", "config_reconcile_loop"] {
        assert!(
            at(late) < adapter,
            "phase {late:?} starts before adapter_start"
        );
    }
}

#[test]
fn the_bind_phase_carries_its_marks() {
    let src = compose_src();
    for m in ["provision_built", "router_built", "listener_bound"] {
        assert!(
            src.contains(&format!("compose_status::mark(\"{m}\")")),
            "compose.rs marks {m:?} inside read_api_bind (#549)"
        );
    }
    let bind = src
        .find("compose_status::phase(\"read_api_bind\")")
        .unwrap();
    let serving = src
        .find("compose_status::phase(\"read_api_serving\")")
        .unwrap();
    for m in ["provision_built", "router_built", "listener_bound"] {
        let i = src.find(&format!("compose_status::mark(\"{m}\")")).unwrap();
        assert!(
            bind < i && i < serving,
            "mark {m:?} sits inside the read_api_bind phase"
        );
    }
}
