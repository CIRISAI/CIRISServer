//! **verify-status** scenario — proves the node serves a read-only
//! `GET /v1/system/verify-status`.
//!
//! The desktop client's Trust & Security view GET-ed `/v1/auth/attestation`, but
//! that route is POST-only (it *emits* a federation-signed CEG attestation), so a
//! GET 405'd — and there was no read-only verify-status route at all. The client
//! had to skip the check in NODE mode. This scenario boots an in-process node and
//! asserts the new read route returns CIRISVerify status (loaded + the node's
//! derived federation key_id + custody class).

use std::sync::Arc;

use crate::common::{node, Report};

pub async fn run(report: &mut Report) {
    let m = "verify-status";
    let engine = node().await;

    // Serve just the verify-status router on an ephemeral port.
    let app =
        ciris_server::health::verify_status_router(Arc::clone(&engine), "SOFTWARE_ONLY".into());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let resp = reqwest::Client::new()
        .get(format!("{url}/v1/system/verify-status"))
        .send()
        .await
        .expect("GET verify-status");
    let code = resp.status().as_u16();
    // The gap: a GET used to 405/404. It must now be a clean 200.
    report.check(
        m,
        "GET /v1/system/verify-status → 200 (was 405/404)",
        code == 200,
        format!("HTTP {code}"),
    );

    let body: serde_json::Value = resp.json().await.expect("json body");
    let d = &body["data"];
    report.check(m, "loaded = true", d["loaded"] == true, "");
    report.check(m, "binary_ok = true", d["binary_ok"] == true, "");
    report.check(
        m,
        "key_status = active",
        d["key_status"] == "active",
        d["key_status"].to_string(),
    );
    let kid = d["key_id"].as_str().unwrap_or("");
    report.check(
        m,
        "key_id present (the node's derived federation id)",
        !kid.is_empty(),
        kid.to_string(),
    );
    report.check(
        m,
        "attestation_status = verified",
        d["attestation_status"] == "verified",
        "",
    );
    report.check(
        m,
        "hardware_type reported",
        d["hardware_type"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        d["hardware_type"].to_string(),
    );
}
