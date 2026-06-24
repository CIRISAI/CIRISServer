//! Mount-by-proxy router (CIRISServer#80) — fold an out-of-process sibling's HTTP
//! surface onto the node's read-API listener by reverse-proxying a path prefix to
//! an upstream base URL.
//!
//! The motivating case: the CIRISAgent "brain" runs as a sibling service on
//! :8080 (the interim of the agent adoption — see `FSD/CIRISAGENT_ADOPTION.md`),
//! and we want its cognitive endpoints reachable on the node's one read-API
//! (4243) so the client talks to a single port. An [`crate::adapter::Adapter`]
//! (incl. the Python [`crate::py_adapter::PyAdapter`]) returns one of these
//! routers per `{prefix → upstream}` it declares; the composition root merges
//! them onto the read-API router like any other adapter surface.
//!
//! This is a transparent reverse proxy: method, path (verbatim), query, headers
//! (minus `Host`), and body are forwarded to `<upstream><path><?query>`, and the
//! upstream's status/headers/body are returned unchanged.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};

#[derive(Clone)]
struct ProxyState {
    /// Upstream base URL, no trailing slash (e.g. `http://127.0.0.1:8080`).
    upstream: String,
    client: reqwest::Client,
}

/// Build a [`Router`] that reverse-proxies `prefix` (and everything under it) to
/// `upstream`. Merge the result onto the node's read-API router.
///
/// `prefix` is matched exactly AND as a wildcard subtree: a request to
/// `<prefix>` or `<prefix>/<anything>` is forwarded to `<upstream>` with the
/// original request path preserved verbatim (the upstream sees the same path the
/// client used — no prefix stripping, so the sibling mounts its routes under the
/// same prefix it advertises).
pub fn reverse_proxy_router(prefix: &str, upstream: &str) -> Router {
    let state = ProxyState {
        upstream: upstream.trim_end_matches('/').to_string(),
        client: reqwest::Client::new(),
    };
    let prefix = format!("/{}", prefix.trim_matches('/'));
    Router::new()
        .route(&prefix, any(proxy))
        .route(&format!("{prefix}/{{*rest}}"), any(proxy))
        .with_state(state)
}

async fn proxy(State(st): State<ProxyState>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let url = format!("{}{}{}", st.upstream, path, query);
    let method = req.method().clone();

    // Forward all request headers except Host (reqwest sets the upstream Host).
    let mut fwd_headers = req.headers().clone();
    fwd_headers.remove(header::HOST);

    let body_bytes = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(e) => return gateway_err(format!("read request body: {e}")),
    };

    let upstream_resp = st
        .client
        .request(method, &url)
        .headers(fwd_headers)
        .body(body_bytes.to_vec())
        .send()
        .await;

    let resp = match upstream_resp {
        Ok(r) => r,
        Err(e) => return gateway_err(format!("upstream {url}: {e}")),
    };

    let status = resp.status();
    let resp_headers: HeaderMap = resp.headers().clone();
    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => return gateway_err(format!("read upstream body: {e}")),
    };

    let mut builder = Response::builder().status(status);
    // Hop-by-hop headers (transfer-encoding, connection) must not be copied
    // verbatim onto a re-framed body; drop them and let axum re-frame.
    for (k, v) in resp_headers.iter() {
        if k == header::TRANSFER_ENCODING || k == header::CONNECTION {
            continue;
        }
        builder = builder.header(k, v);
    }
    builder
        .body(Body::from(bytes))
        .unwrap_or_else(|e| gateway_err(format!("re-frame upstream response: {e}")))
}

fn gateway_err(msg: String) -> Response {
    tracing::warn!(error = %msg, "reverse proxy");
    (StatusCode::BAD_GATEWAY, msg).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, routing::post, Json};

    // Spin a tiny upstream + the proxy in front of it, then drive a real request
    // through the proxy and assert it reached the upstream with path + body intact.
    #[tokio::test]
    async fn proxies_method_path_and_body_to_upstream() {
        // Upstream: echoes the path on GET, echoes the JSON body on POST.
        let upstream = Router::new()
            .route("/v1/agent/ping", get(|| async { "pong" }))
            .route(
                "/v1/agent/echo",
                post(|Json(v): Json<serde_json::Value>| async move { Json(v) }),
            );
        let up_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up_listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(up_listener, upstream).await.unwrap() });

        // Proxy: forward /v1/agent/* to the upstream.
        let app = reverse_proxy_router("/v1/agent", &format!("http://{up_addr}"));
        let px_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let px_addr = px_listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(px_listener, app).await.unwrap() });

        let client = reqwest::Client::new();

        // GET through the proxy reaches the upstream path verbatim.
        let r = client
            .get(format!("http://{px_addr}/v1/agent/ping"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.text().await.unwrap(), "pong");

        // POST body is forwarded and echoed back.
        let r = client
            .post(format!("http://{px_addr}/v1/agent/echo"))
            .json(&serde_json::json!({"k": "v"}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(
            r.json::<serde_json::Value>().await.unwrap(),
            serde_json::json!({"k": "v"})
        );
    }
}
