//! **One port must answer both meanings** (CIRISServer#390).
//!
//! A folded deployment serves the node and the brain on one port, and the
//! universal client decides node-vs-agent from `/v1/system/health`: AGENT iff
//! `cognitive_state` is present or the service map is non-empty
//! (`clientModeFrom` in the vendored KMP client).
//!
//! Health is a SUBSTRATE path — the node answers it natively and never proxies
//! it — so on the folded port a full agent reported as a bare NODE, and the
//! client hid the 22 cognitive services of the agent it was connected to.
//! Pointing the client at the brain's own port does not help: that port 404s the
//! node's surface. Neither port served both meanings.
//!
//! These tests drive the REAL router against a REAL upstream, because the
//! failure was never in the merge logic — it was that nobody asked the brain at
//! all. A unit test over a merge function would have passed the whole time.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

/// The degradation registry is a PROCESS-GLOBAL, and libtest runs these cases
/// in parallel threads of one process. Exactly one case below raises into it —
/// and the moment it does, every OTHER case asserting `status == "ok"` can read
/// `"degraded"` instead and fail for a reason that has nothing to do with what
/// it is testing. So every case that reads `status` or `degraded_mode` takes
/// this lock. `src/degradation.rs` and `tests/retention_loop.rs` carry the same
/// lock for the same reason; `oauth_state_matrix.rs` records the first time
/// this repo paid for a leaked process-global.
static REGISTRY_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Serve a fake brain on a loopback port and return its base URL.
async fn spawn_brain(body: serde_json::Value) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/v1/system/health",
        axum::routing::get(move || {
            let b = body.clone();
            async move { axum::Json(b) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a brain port");
    let addr = listener.local_addr().expect("addr");
    let h = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), h)
}

/// The node's OWN verdict on this host, right now, with no brain folded.
///
/// **The baseline every status assertion here is measured against** (codex
/// review, PR #483). `node_health` runs the real memory and PSI probes, so on a
/// loaded CI worker `status` is legitimately `degraded` and an unconditional
/// `assert_eq!(status, "ok")` fails for host load rather than for a regression.
/// The registry mutex serialises the tests; it cannot quiet the kernel.
///
/// So these cases assert what they are actually about — that folding a brain
/// does or does not MOVE the node's own verdict — which holds however loud the
/// runner is.
async fn bare_node_verdict() -> (String, bool) {
    let v = get_health(ciris_server::health::router()).await;
    (
        v["data"]["status"].as_str().unwrap_or_default().to_string(),
        v["data"]["degraded_mode"].as_bool().unwrap_or(false),
    )
}

async fn get_health(router: axum::Router) -> serde_json::Value {
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/v1/system/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// A BARE node: no brain, no cognitive_state — and it says so explicitly rather
/// than by omission.
#[tokio::test]
async fn a_bare_node_reports_no_agent_and_no_cognitive_state() {
    let _registry = REGISTRY_LOCK.lock().await;
    let v = get_health(ciris_server::health::router()).await;
    // Not `== "ok"`: this node's own probes decide that, and a loaded runner is
    // entitled to say `degraded`. What a BARE node must never do is claim an
    // agent — which is what this case is about.
    assert!(
        matches!(v["data"]["status"].as_str(), Some("ok" | "degraded")),
        "the status word must be one of the derived values: {v}"
    );
    assert_eq!(v["data"]["role"], "fabric-node");
    assert!(
        v["data"]["cognitive_state"].is_null(),
        "a bare node must not claim a cognitive state: {v}"
    );
    assert_eq!(v["data"]["agent"]["folded"], false);
    assert_eq!(v["data"]["agent"]["reachable"], false);
}

/// **The bug, closed.** A folded brain's `cognitive_state` and service map reach
/// the client through the NODE's port, so `clientModeFrom` resolves AGENT.
#[tokio::test]
async fn a_folded_brain_enriches_the_nodes_own_health() {
    // LOCK FIRST, then sample (codex review, PR #483). Taken the other way, the
    // baseline request runs while another case is holding the lock with a
    // synthetic critical raised — so this captures `degraded`, then waits, then
    // compares that stale baseline against an `ok` folded response and fails
    // nondeterministically. The lock has to span BOTH reads or it is not
    // protecting the comparison, only one half of it.
    let _registry = REGISTRY_LOCK.lock().await;
    let baseline = bare_node_verdict().await;
    let (base, h) = spawn_brain(serde_json::json!({
        "data": {
            "status": "ok",
            "cognitive_state": "WORK",
            "services": { "llm": "ok", "memory": "ok" },
        }
    }))
    .await;

    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;

    // The agent half arrived...
    assert_eq!(
        v["data"]["cognitive_state"], "WORK",
        "the folded brain's cognitive_state must reach the client on the NODE's port: {v}"
    );
    assert_eq!(v["data"]["services"]["llm"], "ok");
    assert_eq!(v["data"]["agent"]["folded"], true);
    assert_eq!(v["data"]["agent"]["reachable"], true);

    // ...and the NODE's own half survived. Proxying this path wholesale would
    // have answered the agent question and silently lost node liveness — the
    // endpoint has to be the union, not a redirect.
    // The brain reported healthy, so the pair's verdict must equal the node's
    // OWN — not a hardcoded "ok", which the node's real probes may legitimately
    // contradict on a loaded runner.
    assert_eq!(
        v["data"]["status"].as_str().unwrap_or_default(),
        baseline.0,
        "a healthy brain moved the node's own verdict: {v}"
    );
    assert_eq!(
        v["data"]["degraded_mode"].as_bool().unwrap_or(false),
        baseline.1
    );
    assert_eq!(v["data"]["role"], "fabric-node");
    assert!(
        v["data"]["conformance"].is_object(),
        "the node's own conformance block must survive the merge: {v}"
    );
    h.abort();
}

/// THREE STATES, NOT TWO. A brain that is attached but not answering is NOT the
/// same as no brain — and before this both rendered as a bare node, which is
/// exactly the failure. The node stays up and says which case it is.
#[tokio::test]
async fn an_unreachable_brain_is_distinguished_from_no_brain() {
    // LOCK FIRST, then sample (codex review, PR #483). Taken the other way, the
    // baseline request runs while another case is holding the lock with a
    // synthetic critical raised — so this captures `degraded`, then waits, then
    // compares that stale baseline against an `ok` folded response and fails
    // nondeterministically. The lock has to span BOTH reads or it is not
    // protecting the comparison, only one half of it.
    let _registry = REGISTRY_LOCK.lock().await;
    let baseline = bare_node_verdict().await;
    // A port nobody is listening on: bind then drop, so the address is dead.
    let dead = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let a = l.local_addr().expect("addr");
        drop(l);
        format!("http://{a}")
    };

    let v = get_health(ciris_server::health::router_with_brain(Some(dead))).await;

    // The node's own liveness is UNAFFECTED — a dead brain must not take the
    // node's health answer down with it.
    // The brain reported healthy, so the pair's verdict must equal the node's
    // OWN — not a hardcoded "ok", which the node's real probes may legitimately
    // contradict on a loaded runner.
    assert_eq!(
        v["data"]["status"].as_str().unwrap_or_default(),
        baseline.0,
        "a healthy brain moved the node's own verdict: {v}"
    );
    assert_eq!(
        v["data"]["degraded_mode"].as_bool().unwrap_or(false),
        baseline.1
    );
    assert!(v["data"]["cognitive_state"].is_null());

    // And the distinction is on the wire: attached, but not answering.
    assert_eq!(
        v["data"]["agent"]["folded"], true,
        "a configured brain is FOLDED even when it is not answering: {v}"
    );
    assert_eq!(
        v["data"]["agent"]["reachable"], false,
        "…and unreachable, which is a different fact from 'there is no brain'"
    );
}

/// **The brain cannot rename the node** (CIRISServer#410). The `node` block is
/// the port's own name — the thing a bind-collision probe trusts to decide
/// which process to kill — so a folded brain that ships its own `node` (or a
/// stray `key_id`) must not overwrite it. The merge is an allow-list of
/// cognitive fields; this pins that `node` never joins it.
#[tokio::test]
async fn a_folded_brain_cannot_overwrite_the_nodes_own_name() {
    let _registry = REGISTRY_LOCK.lock().await;
    let (base, h) = spawn_brain(serde_json::json!({
        "data": {
            "status": "ok",
            "cognitive_state": "WORK",
            "node": {
                "standing": "identified",
                "instance_id": "brain-forged-instance",
                "key_id": "brain-forged-key",
            },
            "key_id": "brain-forged-key",
        }
    }))
    .await;

    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;

    // The brain's cognitive half still merges…
    assert_eq!(v["data"]["cognitive_state"], "WORK");
    // …but the node's own name survives: the served instance_id is THIS
    // process's, not the brain's forgery.
    assert_eq!(
        v["data"]["node"]["instance_id"],
        ciris_server::node_identity::instance_id(),
        "a folded brain must not be able to rename the node: {v}"
    );
    assert_ne!(v["data"]["node"]["instance_id"], "brain-forged-instance");
    assert_ne!(v["data"]["node"]["key_id"], "brain-forged-key");
    // And the brain's stray top-level key_id does not ride in beside it.
    assert!(
        v["data"]["key_id"].is_null(),
        "no brain key_id may join the node's health envelope: {v}"
    );
    h.abort();
}

/// A brain that answers a BARE object rather than the `{"data":{…}}` envelope
/// still contributes. Being strict here would reintroduce the same outcome —
/// a real agent rendered as a bare node — over a shape difference.
#[tokio::test]
async fn a_brain_answering_without_the_data_envelope_still_contributes() {
    let _registry = REGISTRY_LOCK.lock().await;
    let (base, h) = spawn_brain(serde_json::json!({
        "status": "ok",
        "cognitive_state": "DREAM",
    }))
    .await;
    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;
    assert_eq!(v["data"]["cognitive_state"], "DREAM", "{v}");
    assert_eq!(v["data"]["agent"]["reachable"], true);
    h.abort();
}

// ── The pair's health is the union of both halves (CIRISServer#446) ──────────

/// **A folded pair is degraded if EITHER half is.**
///
/// The allow-list that keeps a brain from renaming the node also dropped the
/// brain's own verdict, and the node then answered for the pair using half the
/// evidence. The client reads `degraded_mode` off exactly this route, and its
/// own comment says the flag means "no working LLM provider" — a brain-tier
/// condition the node had no way to report.
#[tokio::test]
async fn a_degraded_brain_degrades_the_folded_pair() {
    let _registry = REGISTRY_LOCK.lock().await;
    let (base, h) = spawn_brain(serde_json::json!({
        "data": {
            "status": "degraded",
            "cognitive_state": "WORK",
            "degraded_mode": true,
            "warnings": [{
                "code": "llm.no_provider",
                "message": "every configured LLM provider failed its last probe",
                "severity": "error",
            }],
        }
    }))
    .await;
    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;
    h.abort();

    assert_eq!(
        v["data"]["degraded_mode"], true,
        "the brain reported itself degraded and the pair still answered `false`. The node \
         answered a question about the pair while looking at half of it: {v:#}"
    );
    assert_eq!(v["data"]["status"], "degraded");

    let codes: Vec<&str> = v["data"]["warnings"]
        .as_array()
        .expect("warnings must be an array")
        .iter()
        .filter_map(|w| w["code"].as_str())
        .collect();
    assert!(
        codes.contains(&"agent.llm.no_provider"),
        "the brain's warning must ride through NAMESPACED. A dashboard groups on `code`, and \
         the same code from two tiers means two different things to go and do: {codes:?}"
    );
    assert!(
        !codes.contains(&"llm.no_provider"),
        "an un-namespaced brain code can collide with a node code of the same name, and then \
         the operator cannot tell which tier to fix: {codes:?}"
    );
}

/// **Escalate only.** A cheerful brain must not be able to clear the node's own
/// alarm — that would be #480 with an extra hop in it.
#[tokio::test]
async fn a_healthy_brain_cannot_clear_the_nodes_own_degradation() {
    let _registry = REGISTRY_LOCK.lock().await;
    ciris_server::degradation::raise(ciris_server::degradation::Warning::critical(
        "test.node_tier_fault",
        "a node-tier fault the brain knows nothing about",
    ));

    let (base, h) = spawn_brain(serde_json::json!({
        "data": {
            "status": "ok",
            "cognitive_state": "WORK",
            "degraded_mode": false,
            "warnings": [],
        }
    }))
    .await;
    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;
    h.abort();
    ciris_server::degradation::clear("test.node_tier_fault");

    assert_eq!(
        v["data"]["degraded_mode"], true,
        "a healthy brain LOWERED the node's own verdict. The node's reading is the floor: a \
         brain can move this payload toward `degraded` and never the other way: {v:#}"
    );
    assert_eq!(v["data"]["status"], "degraded");
    let codes: Vec<&str> = v["data"]["warnings"]
        .as_array()
        .expect("warnings array")
        .iter()
        .filter_map(|w| w["code"].as_str())
        .collect();
    assert!(
        codes.contains(&"test.node_tier_fault"),
        "the node's own warning was dropped by the fold: {codes:?}"
    );
}

/// The brain is a remote process and its document is hostile input.
///
/// A malformed or enormous `warnings` payload must not be able to make the
/// node's liveness answer unservable — that would be a denial of service
/// through the health probe, caused by the thing watching for one.
#[tokio::test]
async fn a_malformed_or_flooding_brain_cannot_break_the_nodes_liveness_answer() {
    let _registry = REGISTRY_LOCK.lock().await;
    let mut flood: Vec<serde_json::Value> = (0..500)
        .map(|i| serde_json::json!({"code": format!("flood.{i}"), "message": "x"}))
        .collect();
    // Entries with nothing to group on, and entries that are not objects at all.
    flood.push(serde_json::json!({"message": "no code at all"}));
    flood.push(serde_json::json!("not even an object"));
    flood.push(serde_json::Value::Null);

    let (base, h) = spawn_brain(serde_json::json!({
        "data": { "cognitive_state": "WORK", "degraded_mode": "not-a-bool", "warnings": flood }
    }))
    .await;
    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;
    h.abort();

    let warnings = v["data"]["warnings"]
        .as_array()
        .expect("the payload must still be well-formed after hostile input");
    assert!(
        warnings.len() <= 40,
        "the brain's 503 warnings were carried whole — a runaway brain can bloat the node's \
         liveness response, which every watcher in the mesh polls on a timer: {}",
        warnings.len()
    );
    let codes: Vec<&str> = warnings.iter().filter_map(|w| w["code"].as_str()).collect();
    assert!(
        codes.contains(&"agent.warnings_truncated"),
        "truncation must SAY it truncated. A silent cap reads as 'the brain had nothing more \
         to say', which is the collapsed zero this repo has paid for five times: {codes:?}"
    );
    // A non-bool `degraded_mode` is not a degradation claim — and not a panic.
    assert_eq!(v["data"]["degraded_mode"], false);
    assert_eq!(v["data"]["agent"]["reachable"], true);
}

/// **A non-`ok` brain STATUS is its own degradation signal** (codex review,
/// PR #483).
///
/// The client's contract is `status != "ok" || degradedMode ||
/// warnings.isNotEmpty()` — three independent signals. The fold said every
/// field was optional and every shape tolerated, then keyed solely on the
/// boolean, so an older or partially-compatible brain reporting
/// `status: "degraded"` with no `degraded_mode` had a valid verdict discarded.
#[tokio::test]
async fn a_brain_that_reports_only_a_bad_status_still_degrades_the_pair() {
    let _registry = REGISTRY_LOCK.lock().await;
    let (base, h) = spawn_brain(serde_json::json!({
        "data": { "status": "degraded", "cognitive_state": "WORK" }
    }))
    .await;
    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;
    h.abort();

    assert_eq!(
        v["data"]["degraded_mode"], true,
        "the brain said `status: degraded` and the pair reported healthy. The boolean is not \
         the only signal — the client reads all three: {v:#}"
    );
    assert_eq!(v["data"]["status"], "degraded");
}

/// An ABSENT status is not a claim of health — a brain that omits the field
/// entirely must change nothing, or every bare-object brain degrades the node.
#[tokio::test]
async fn a_brain_that_omits_status_entirely_changes_nothing() {
    let _registry = REGISTRY_LOCK.lock().await;
    let baseline = bare_node_verdict().await;
    let (base, h) = spawn_brain(serde_json::json!({
        "data": { "cognitive_state": "WORK" }
    }))
    .await;
    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;
    h.abort();

    assert_eq!(
        v["data"]["status"].as_str().unwrap_or_default(),
        baseline.0,
        "a missing brain `status` moved this node's own verdict — absent is not a claim: {v:#}"
    );
    assert_eq!(
        v["data"]["degraded_mode"].as_bool().unwrap_or(false),
        baseline.1
    );
}

/// **Malformed entries must not consume the warning budget** (codex review).
///
/// The cap was applied to the first 32 RAW entries. A brain emitting 32 junk
/// objects followed by one real `llm.no_provider` would have the real one
/// silently dropped, and the response would carry nothing but a truncation
/// notice — the one actionable warning lost to noise.
#[tokio::test]
async fn junk_entries_cannot_crowd_out_a_real_warning() {
    let _registry = REGISTRY_LOCK.lock().await;
    let mut ws: Vec<serde_json::Value> = (0..40)
        .map(|_| serde_json::json!({"message": "no code, nothing to act on"}))
        .collect();
    ws.push(serde_json::json!({
        "code": "llm.no_provider",
        "message": "every configured LLM provider failed its last probe",
        "severity": "error",
    }));

    let (base, h) = spawn_brain(serde_json::json!({
        "data": { "cognitive_state": "WORK", "warnings": ws }
    }))
    .await;
    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;
    h.abort();

    let codes: Vec<&str> = v["data"]["warnings"]
        .as_array()
        .expect("warnings array")
        .iter()
        .filter_map(|w| w["code"].as_str())
        .collect();
    assert!(
        codes.contains(&"agent.llm.no_provider"),
        "40 junk entries ate the budget and the ONE actionable warning was dropped. The cap is \
         a question about valid warnings, so it has to be applied to those: {codes:?}"
    );
    assert!(
        !codes.contains(&"agent.warnings_truncated"),
        "only one warning was valid — nothing was truncated, so claiming truncation sends an \
         operator to look for warnings that do not exist: {codes:?}"
    );
}

/// **Count is not size** (codex review, PR #483).
///
/// A 32-entry cap bounds nothing if ONE entry carries a megabyte. This route is
/// public and every request re-fetches and re-serializes the brain's document,
/// so a buggy or compromised brain could turn concurrent health polling into
/// unbounded memory and bandwidth — using the liveness probe as the amplifier.
///
/// The oversized entry is REDUCED, not dropped: `code` is the part an operator
/// acts on, so discarding the whole entry would throw away the signal to save
/// the noise.
#[tokio::test]
async fn one_enormous_warning_cannot_bloat_the_liveness_answer() {
    let _registry = REGISTRY_LOCK.lock().await;
    let (base, h) = spawn_brain(serde_json::json!({
        "data": { "cognitive_state": "WORK", "warnings": [{
            "code": "llm.no_provider",
            "message": "x".repeat(4 * 1024 * 1024),
            "severity": "error",
        }]}
    }))
    .await;
    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;
    h.abort();

    let body = serde_json::to_string(&v).expect("serialize");
    assert!(
        body.len() < 64 * 1024,
        "a single 4 MiB brain warning produced a {} byte health response. The entry cap counts \
         entries, not bytes — one is enough to make this public route an amplifier.",
        body.len()
    );

    let codes: Vec<&str> = v["data"]["warnings"]
        .as_array()
        .expect("warnings array")
        .iter()
        .filter_map(|w| w["code"].as_str())
        .collect();
    assert!(
        codes.contains(&"agent.llm.no_provider"),
        "the oversized warning was DROPPED rather than reduced. `code` is the part an operator \
         acts on and is nearly always small — discarding the entry throws away the signal to \
         save the noise: {codes:?}"
    );
    let msg = v["data"]["warnings"][0]["message"]
        .as_str()
        .unwrap_or_default();
    assert!(
        msg.contains("truncated by this node"),
        "a reduced message must SAY this node reduced it, and where to read the whole thing — \
         otherwise an operator reads a sentence that stops mid-thought and distrusts the \
         surface: {msg:.200}"
    );
}

/// **The suite must pass on a node that is legitimately degraded** (codex
/// review, PR #483).
///
/// `node_health` runs the real memory and PSI probes, so on a loaded CI worker
/// `status` is genuinely `degraded` — and every case here that hardcoded
/// `"ok"` failed for host load rather than for a regression. That is not a
/// stricter test; it is a test asserting something it cannot control.
///
/// This forces the condition rather than waiting to meet it on a bad day: raise
/// a real node-tier fault, then drive the whole fold and check the properties
/// each case actually cares about still hold.
#[tokio::test]
async fn folding_still_behaves_when_the_node_itself_is_degraded() {
    let _registry = REGISTRY_LOCK.lock().await;
    ciris_server::degradation::raise(ciris_server::degradation::Warning::critical(
        "test.forced_node_fault",
        "a node-tier fault, to simulate a loaded runner",
    ));

    let baseline = bare_node_verdict().await;
    assert_eq!(
        baseline,
        ("degraded".to_string(), true),
        "fixture: the node must be degraded for this case to mean anything"
    );

    let (base, h) = spawn_brain(serde_json::json!({
        "data": { "status": "ok", "cognitive_state": "WORK", "degraded_mode": false }
    }))
    .await;
    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;
    h.abort();
    ciris_server::degradation::clear("test.forced_node_fault");

    // The fold still does its job — the agent's cognitive state arrives, which
    // is what `clientModeFrom` reads — and the node's own verdict is untouched.
    assert_eq!(
        v["data"]["cognitive_state"], "WORK",
        "a degraded node stopped reporting its folded brain's cognitive state, so the client \
         would resolve it as a bare NODE: {v:#}"
    );
    assert_eq!(v["data"]["agent"]["folded"], true);
    assert_eq!(v["data"]["agent"]["reachable"], true);
    assert_eq!(
        v["data"]["status"], "degraded",
        "a healthy brain cleared a degraded node's verdict: {v:#}"
    );
}

/// **A cap with an exempt field is not a cap** (codex review, PR #483).
///
/// The reducer bounded `message` and copied `code` and `severity` verbatim, so
/// a brain whose size came from a multi-megabyte CODE sailed straight through
/// the entry bound the reducer exists to enforce — and got re-serialized on
/// every public health request.
#[tokio::test]
async fn an_enormous_code_or_severity_cannot_bypass_the_entry_bound() {
    let _registry = REGISTRY_LOCK.lock().await;
    let (base, h) = spawn_brain(serde_json::json!({
        "data": { "cognitive_state": "WORK", "warnings": [{
            "code": "c".repeat(3 * 1024 * 1024),
            "message": "short",
            "severity": "s".repeat(1024 * 1024),
        }]}
    }))
    .await;
    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;
    h.abort();

    let body = serde_json::to_string(&v).expect("serialize");
    assert!(
        body.len() < 64 * 1024,
        "a 3 MiB `code` produced a {} byte health response — the size cap was applied to \
         `message` alone, so the field carrying the bytes was the one exempt from it.",
        body.len()
    );
    let w = &v["data"]["warnings"][0];
    assert!(
        w["code"].as_str().unwrap_or_default().len() <= 300,
        "the code was not clipped: {} bytes",
        w["code"].as_str().unwrap_or_default().len()
    );
    assert!(
        matches!(
            w["severity"].as_str(),
            Some("info" | "warning" | "error" | "critical")
        ),
        "severity must be normalised to the closed vocabulary the client switches on — a \
         clipped token would be neither valid nor obviously wrong: {:?}",
        w["severity"].as_str().map(|s| &s[..s.len().min(40)])
    );
}

/// **A degrading WARNING is the third signal** (codex review, PR #483).
///
/// The client's contract is `status != "ok" || degradedMode ||
/// warnings.isNotEmpty()`. The fold honoured the first two, so a brain emitting
/// an `error` or `critical` warning while omitting BOTH flags — an older or
/// partially compatible one — had that warning appended to the payload while
/// the outer verdict stayed `ok`. A status-only watcher then ignored a critical
/// condition visible three lines below it in the same response.
#[tokio::test]
async fn a_brain_warning_alone_degrades_the_folded_pair() {
    let _registry = REGISTRY_LOCK.lock().await;
    let baseline = bare_node_verdict().await;
    assert!(!baseline.1, "fixture: this case needs an undegraded node");

    let (base, h) = spawn_brain(serde_json::json!({
        "data": {
            "cognitive_state": "WORK",
            // Neither flag. Only the warning's own severity says anything.
            "warnings": [{
                "code": "llm.all_providers_down",
                "message": "every configured provider failed its last probe",
                "severity": "critical",
            }],
        }
    }))
    .await;
    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;
    h.abort();

    assert_eq!(
        v["data"]["degraded_mode"], true,
        "a CRITICAL brain warning rode through into the payload while the verdict stayed \
         healthy. A watcher keying on status alone would ignore it, and the reason is right \
         there in the same response: {v:#}"
    );
    assert_eq!(v["data"]["status"], "degraded");
}

/// An INFO-severity brain warning is reported and changes nothing — otherwise
/// "the brain said something" and "the brain is in trouble" collapse, which is
/// the distinction the severity field exists to carry.
#[tokio::test]
async fn an_informational_brain_warning_does_not_degrade_the_pair() {
    let _registry = REGISTRY_LOCK.lock().await;
    let baseline = bare_node_verdict().await;

    let (base, h) = spawn_brain(serde_json::json!({
        "data": {
            "cognitive_state": "WORK",
            "warnings": [{"code": "model.switched", "message": "now on the fallback model", "severity": "info"}],
        }
    }))
    .await;
    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;
    h.abort();

    assert_eq!(
        v["data"]["degraded_mode"].as_bool().unwrap_or(false),
        baseline.1,
        "an INFO warning moved the verdict: {v:#}"
    );
    let codes: Vec<&str> = v["data"]["warnings"]
        .as_array()
        .expect("warnings array")
        .iter()
        .filter_map(|w| w["code"].as_str())
        .collect();
    assert!(
        codes.contains(&"agent.model.switched"),
        "not degrading is not the same as not reporting: {codes:?}"
    );
}

/// **A degrading warning BEYOND the cap still degrades the pair** (codex
/// review, PR #483).
///
/// The cap deliberately does no work past its limit — no clone, no serialize,
/// no reduce — but severity is one string comparison, and it is the difference
/// between reporting a pair healthy and not. A brain with 33 warnings whose
/// 33rd is `critical`, and which omits both flags, would otherwise have that
/// condition counted and discarded while the verdict read `ok`.
#[tokio::test]
async fn a_critical_warning_past_the_cap_still_degrades_the_pair() {
    let _registry = REGISTRY_LOCK.lock().await;
    let baseline = bare_node_verdict().await;
    assert!(!baseline.1, "fixture: this case needs an undegraded node");

    let mut ws: Vec<serde_json::Value> = (0..40)
        .map(|i| serde_json::json!({"code": format!("noise.{i}"), "message": "x", "severity": "info"}))
        .collect();
    // Well past the 32-entry cap.
    ws.push(serde_json::json!({
        "code": "llm.all_providers_down",
        "message": "every configured provider failed its last probe",
        "severity": "critical",
    }));

    let (base, h) = spawn_brain(serde_json::json!({
        "data": { "cognitive_state": "WORK", "warnings": ws }
    }))
    .await;
    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;
    h.abort();

    assert_eq!(
        v["data"]["degraded_mode"], true,
        "a CRITICAL warning past the retained prefix was counted and discarded without \
         examining its severity, so the pair reported healthy over a critical condition it \
         had literally just looked at: {v:#}"
    );
    assert_eq!(v["data"]["status"], "degraded");
}

/// **An empty `code` is not a code** (codex review, PR #483).
///
/// `Some("")` passed the presence test, namespaced to the identical `agent.`
/// for every entry, and 32 of them consumed the whole cap — pushing the
/// actionable warning out while the truncation notice claimed only valid
/// entries had been retained. "Has a code field" and "has something to group
/// on" are different questions.
#[tokio::test]
async fn empty_codes_are_not_valid_and_cannot_consume_the_cap() {
    let _registry = REGISTRY_LOCK.lock().await;
    let mut ws: Vec<serde_json::Value> = (0..40)
        .map(|_| serde_json::json!({"code": "", "message": "nothing to group on", "severity": "info"}))
        .collect();
    ws.push(serde_json::json!({
        "code": "llm.no_provider",
        "message": "every configured provider failed its last probe",
        "severity": "error",
    }));

    let (base, h) = spawn_brain(serde_json::json!({
        "data": { "cognitive_state": "WORK", "warnings": ws }
    }))
    .await;
    let v = get_health(ciris_server::health::router_with_brain(Some(base))).await;
    h.abort();

    let codes: Vec<&str> = v["data"]["warnings"]
        .as_array()
        .expect("warnings array")
        .iter()
        .filter_map(|w| w["code"].as_str())
        .collect();
    assert!(
        codes.contains(&"agent.llm.no_provider"),
        "40 empty-coded entries ate the cap and the one actionable warning was dropped: \
         {codes:?}"
    );
    assert!(
        !codes.contains(&"agent."),
        "an empty code was namespaced into `agent.` and carried — every such entry collides \
         on one meaningless key: {codes:?}"
    );
}
