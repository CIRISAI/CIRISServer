//! `POST /v1/system/local-shutdown` (0.5.250): the desktop app stops the node
//! it attached to before a device reset wipes the home. Loopback only, never
//! through a proxy. A run of its own: a successful call flips this process's
//! stop switch.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

fn call(peer: [u8; 4], forwarded: bool) -> Request<Body> {
    let mut req = Request::post(ciris_server::local_shutdown::ROUTE);
    if forwarded {
        req = req.header("x-forwarded-for", "203.0.113.9");
    }
    let mut req = req.body(Body::empty()).expect("request");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((peer, 50_000))));
    req
}

#[tokio::test]
async fn only_a_direct_loopback_caller_stops_the_node() {
    let app = ciris_server::local_shutdown::router();
    let off_box = app
        .clone()
        .oneshot(call([192, 168, 1, 20], false))
        .await
        .expect("served");
    assert_eq!(off_box.status(), StatusCode::FORBIDDEN, "another machine");
    let proxied = app
        .clone()
        .oneshot(call([127, 0, 0, 1], true))
        .await
        .expect("served");
    assert_eq!(
        proxied.status(),
        StatusCode::FORBIDDEN,
        "a same-host proxy relays the internet from loopback"
    );
    // A server-class node refuses it: a seat has no desktop app.
    let server = app
        .clone()
        .oneshot(call([127, 0, 0, 1], false))
        .await
        .expect("served");
    assert_eq!(
        server.status(),
        StatusCode::FORBIDDEN,
        "the default class off mobile is server"
    );
    // The desktop launcher declares its node a laptop. One test in this
    // binary, so setting the process environment races nothing.
    std::env::set_var("CIRIS_DEVICE_CLASS", "laptop");
    let local = app
        .oneshot(call([127, 0, 0, 1], false))
        .await
        .expect("served");
    assert_eq!(local.status(), StatusCode::ACCEPTED, "the desktop app");
}
