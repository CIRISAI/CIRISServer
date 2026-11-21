//! **Workload attribution: every unit of work names who it was for**
//! (`FSD/WORKLOAD_ATTRIBUTION.md`; Eric 2026-11-21, "the telemetry needs to allow for
//! clear attribution so we can attribute and shed workload in emergencies").
//!
//! Three things live here:
//!
//! * **A1, the persist caller scope.** A request runs under
//!   [`ciris_persist::observe::caller_scope`] for its ROUTE GROUP ([`route_group`]), and a
//!   background loop under `server.loop.<name>` ([`spawn_loop`]), so the server's own
//!   reads on the shared engine stop counting as `unattributed`.
//! * **A2, the server's own series.** Requests per matched route TEMPLATE, by status class
//!   and duration ([`attribute_request`]), and the loop registry ([`register_loop`],
//!   [`LoopPass`]): name, interval, passes by outcome, pass duration. Rendered as OTLP by
//!   `telemetry_otlp`.
//! * **A6, quiet repeats.** [`say_on_change`]: a line that a loop would print on every
//!   tick is printed when its state CHANGES, and the repeats are counted instead.
//!
//! # Why the fine labels wait for persist's cap
//!
//! persist interns at most [`MAX_CALLER_LABELS`] caller labels per process; a label past
//! the cap is counted under `other`. On 0.5.x that cap is 32 and edge's own sites already
//! take 26. Interning this server's 11 route groups and its loop names against that would
//! hand the remaining slots to whichever side asked first, and could push EDGE's sites —
//! the ones the 0.5.251 read depended on — into `other`. So below
//! [`FINE_LABELS_FROM_CAP`] every server read is credited to ONE label, [`COARSE_LABEL`]
//! (one slot: the server's half is separated from edge's, the split inside it comes from
//! the route and loop series here). When persist raises the cap the fine labels switch on
//! with no change in this file.
//!
//! # Bounded cardinality (A8)
//!
//! Every label value here is a route template, a method, a status class, a loop name or a
//! site name. Never a raw path, a peer, a key or a community.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use ciris_persist::observe::{caller_scope, current_caller, Caller, MAX_CALLER_LABELS};

/// The persist caller-label cap at which the server interns its fine labels.
pub const FINE_LABELS_FROM_CAP: usize = 64;

/// Whether this build interns route-group and loop labels (see the module docs).
pub const FINE_LABELS: bool = MAX_CALLER_LABELS >= FINE_LABELS_FROM_CAP;

/// The one label every server read is credited to while [`FINE_LABELS`] is off.
pub const COARSE_LABEL: &str = "server";

/// The route groups, by path prefix. The FIRST matching prefix wins, so a narrower prefix
/// sits above the wider one it is inside (`/v1/chat/{room}/call` above `/v1/chat`).
pub const ROUTE_GROUPS: &[(&str, &str)] = &[
    // Calls ride the chat room's path; they are their own load class.
    ("/v1/chat/{room}/call", "server.route.calls"),
    ("/v1/qa/call", "server.route.calls"),
    ("/v1/calls", "server.route.calls"),
    ("/v1/chat", "server.route.chat"),
    ("/v1/contacts", "server.route.chat"),
    ("/v1/files", "server.route.files"),
    ("/v1/drive", "server.route.files"),
    ("/v1/media", "server.route.files"),
    ("/v1/communities", "server.route.communities"),
    ("/v1/families", "server.route.communities"),
    ("/v1/commons", "server.route.communities"),
    ("/v1/safety", "server.route.communities"),
    ("/v1/accord", "server.route.accord"),
    ("/v1/accord-holders", "server.route.accord"),
    ("/v1/trust-root", "server.route.accord"),
    ("/v1/federation", "server.route.federation"),
    ("/v1/mesh", "server.route.federation"),
    ("/v1/ingest", "server.route.federation"),
    ("/v1/traces", "server.route.federation"),
    ("/lens-api", "server.route.federation"),
    ("/v1/telemetry", "server.route.telemetry"),
    ("/v1/health", "server.route.health"),
    ("/v1/system", "server.route.health"),
    ("/health", "server.route.health"),
    ("/v1/admin", "server.route.admin"),
    ("/v1/setup", "server.route.admin"),
    ("/v1/node", "server.route.admin"),
    ("/v1/config", "server.route.admin"),
    ("/v1/mesh-config", "server.route.admin"),
    ("/v1/operations", "server.route.admin"),
    ("/v1/vocabulary", "server.route.admin"),
    ("/v1/qa", "server.route.admin"),
    ("/v1/self", "server.route.self"),
    ("/v1/auth", "server.route.self"),
    ("/v1/my-data", "server.route.self"),
    ("/v1/notes", "server.route.self"),
    ("/v1/memory", "server.route.self"),
    ("/v1/identity", "server.route.self"),
    ("/v1/agent", "server.route.self"),
];

/// The group for a path that matches no prefix.
pub const OTHER_GROUP: &str = "server.route.other";

/// The `http.route` value for a request no route matched (its raw path is never a label).
pub const UNMATCHED_ROUTE: &str = "unmatched";

/// The route group a path belongs to. `path` is the matched route TEMPLATE where there is
/// one; a raw path gives the same group, because the prefixes are literal.
#[must_use]
pub fn route_group(path: &str) -> &'static str {
    ROUTE_GROUPS
        .iter()
        .find(|(prefix, _)| {
            path.strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
        .map_or(OTHER_GROUP, |(_, group)| group)
}

/// The label a fine label is credited under in this build.
#[must_use]
pub fn effective_label(fine: &str) -> &str {
    if FINE_LABELS {
        fine
    } else {
        COARSE_LABEL
    }
}

/// The interned caller for `label` (its effective form), made once per label.
fn caller_for(label: &str) -> Option<Caller> {
    static CALLERS: OnceLock<Mutex<HashMap<String, Option<Caller>>>> = OnceLock::new();
    let label = effective_label(label);
    let map = CALLERS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = map.lock().ok()?;
    if let Some(c) = map.get(label) {
        return *c;
    }
    let c = match Caller::new(label) {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!(
                label,
                "workload attribution: persist refused the caller label: {e}"
            );
            None
        }
    };
    map.insert(label.to_owned(), c);
    c
}

/// Run `fut` with its persist reads credited to `label` (in its effective form).
pub async fn scoped<F: Future>(label: &str, fut: F) -> F::Output {
    match caller_for(label) {
        Some(c) => caller_scope(c, fut).await,
        None => fut.await,
    }
}

/// The persist label of loop `name`.
#[must_use]
pub fn loop_label(name: &str) -> String {
    format!("server.loop.{name}")
}

/// `tokio::spawn` for a long-lived loop: its reads are credited to `server.loop.<name>`.
/// The drop-in form: `spawn_loop("name", async move { … })`.
pub fn spawn_loop<F>(name: &'static str, fut: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let label = loop_label(name);
    tokio::spawn(async move { scoped(&label, fut).await })
}

/// `tokio::spawn` that keeps the caller in force where it is CALLED: per-tick work a loop
/// or a request hands to its own task stays credited to that loop or route group.
pub fn spawn_carried<F>(fut: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    match current_caller() {
        Some(c) => tokio::spawn(caller_scope(c, fut)),
        None => tokio::spawn(fut),
    }
}

// ─── histograms ─────────────────────────────────────────────────────────────

/// Duration bucket upper bounds, seconds (the last bucket is everything above).
pub const DURATION_BOUNDS_SECS: [f64; 14] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// A fixed-bound duration histogram: per-bucket (not cumulative) counts, with the
/// overflow last.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Hist {
    pub counts: Vec<u64>,
    pub count: u64,
    pub sum_secs: f64,
}

impl Hist {
    fn record(&mut self, d: Duration) {
        if self.counts.is_empty() {
            self.counts = vec![0; DURATION_BOUNDS_SECS.len() + 1];
        }
        let s = d.as_secs_f64();
        let i = DURATION_BOUNDS_SECS
            .iter()
            .position(|b| s <= *b)
            .unwrap_or(DURATION_BOUNDS_SECS.len());
        self.counts[i] += 1;
        self.count += 1;
        self.sum_secs += s;
    }
}

// ─── A2: requests ───────────────────────────────────────────────────────────

/// One (route template, method) series.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RouteStats {
    /// Responses by status class: index 0 = 1xx … 4 = 5xx.
    pub by_class: [u64; 5],
    pub duration: Hist,
}

type Routes = BTreeMap<String, BTreeMap<&'static str, RouteStats>>;

fn routes() -> &'static Mutex<Routes> {
    static ROUTES: OnceLock<Mutex<Routes>> = OnceLock::new();
    ROUTES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// A method as a bounded label.
fn method_label(m: &axum::http::Method) -> &'static str {
    match m.as_str() {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "DELETE" => "DELETE",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        _ => "other",
    }
}

/// Count one response.
pub fn record_request(route: &str, method: &'static str, status: u16, took: Duration) {
    let class = usize::from((status / 100).clamp(1, 5)) - 1;
    let Ok(mut r) = routes().lock() else { return };
    if !r.contains_key(route) {
        r.insert(route.to_owned(), BTreeMap::new());
    }
    if let Some(by_method) = r.get_mut(route) {
        let s = by_method.entry(method).or_default();
        s.by_class[class] += 1;
        s.duration.record(took);
    }
}

/// The request middleware: the handler runs under its route group's persist caller, and
/// the response is counted against its matched route TEMPLATE. Wire it with
/// `Router::layer` on the final merged router, where `MatchedPath` is set.
pub async fn attribute_request(req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned());
    let group = route_group(route.as_deref().unwrap_or_else(|| req.uri().path()));
    let method = method_label(req.method());
    let started = Instant::now();
    let resp = scoped(group, next.run(req)).await;
    record_request(
        route.as_deref().unwrap_or(UNMATCHED_ROUTE),
        method,
        resp.status().as_u16(),
        started.elapsed(),
    );
    resp
}

// ─── A2: the loop registry ──────────────────────────────────────────────────

/// One loop's series.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LoopStats {
    pub interval_secs: f64,
    pub ok: u64,
    pub error: u64,
    pub duration: Hist,
}

fn loops() -> &'static Mutex<BTreeMap<&'static str, LoopStats>> {
    static LOOPS: OnceLock<Mutex<BTreeMap<&'static str, LoopStats>>> = OnceLock::new();
    LOOPS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Register (or retune) loop `name` with its interval. `loop_cadence::Cadence` calls this
/// for every registered cadence; a loop on its own sleep calls it once.
pub fn register_loop(name: &'static str, interval: Duration) {
    if let Ok(mut l) = loops().lock() {
        l.entry(name).or_default().interval_secs = interval.as_secs_f64();
    }
}

/// One pass of a loop: begun when the pass starts, recorded when it is dropped (ok unless
/// [`LoopPass::failed`] was called).
#[derive(Debug)]
pub struct LoopPass {
    name: &'static str,
    started: Instant,
    failed: bool,
}

impl LoopPass {
    #[must_use]
    pub fn begin(name: &'static str) -> Self {
        Self {
            name,
            started: Instant::now(),
            failed: false,
        }
    }

    /// Mark this pass as failed.
    pub fn failed(&mut self) {
        self.failed = true;
    }
}

impl Drop for LoopPass {
    fn drop(&mut self) {
        let took = self.started.elapsed();
        if let Ok(mut l) = loops().lock() {
            let s = l.entry(self.name).or_default();
            if self.failed {
                s.error += 1;
            } else {
                s.ok += 1;
            }
            s.duration.record(took);
        }
    }
}

// ─── A6: quiet repeats ──────────────────────────────────────────────────────

fn said() -> &'static Mutex<HashMap<(&'static str, String), String>> {
    static SAID: OnceLock<Mutex<HashMap<(&'static str, String), String>>> = OnceLock::new();
    SAID.get_or_init(|| Mutex::new(HashMap::new()))
}

fn suppressed() -> &'static Mutex<BTreeMap<&'static str, u64>> {
    static SUPPRESSED: OnceLock<Mutex<BTreeMap<&'static str, u64>>> = OnceLock::new();
    SUPPRESSED.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Whether to log `state` for `(site, key)`: true the first time, and whenever the state
/// differs from the last one logged. A repeat returns false and is counted under `site`
/// (`ciris.server.log.suppressed_repeats`). `key` distinguishes instances (a seed dir, an
/// alias) and is never exported; `site` is the bounded label.
pub fn say_on_change(site: &'static str, key: &str, state: &str) -> bool {
    let changed = match said().lock() {
        Ok(mut m) => {
            let k = (site, key.to_owned());
            if m.get(&k).is_some_and(|s| s == state) {
                false
            } else {
                m.insert(k, state.to_owned());
                true
            }
        }
        Err(_) => true,
    };
    if !changed {
        if let Ok(mut s) = suppressed().lock() {
            *s.entry(site).or_default() += 1;
        }
    }
    changed
}

// ─── the snapshot telemetry_otlp renders ────────────────────────────────────

/// Everything this module counts, at one instant.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// `(route template, method, stats)`.
    pub routes: Vec<(String, &'static str, RouteStats)>,
    pub loops: Vec<(&'static str, LoopStats)>,
    pub suppressed: Vec<(&'static str, u64)>,
    pub fine_labels: bool,
    pub caller_label_cap: usize,
}

/// Read every series.
#[must_use]
pub fn snapshot() -> Snapshot {
    let routes = routes()
        .lock()
        .map(|r| {
            r.iter()
                .flat_map(|(route, by)| by.iter().map(move |(m, s)| (route.clone(), *m, s.clone())))
                .collect()
        })
        .unwrap_or_default();
    let loops = loops()
        .lock()
        .map(|l| l.iter().map(|(n, s)| (*n, s.clone())).collect())
        .unwrap_or_default();
    let suppressed = suppressed()
        .lock()
        .map(|s| s.iter().map(|(k, v)| (*k, *v)).collect())
        .unwrap_or_default();
    Snapshot {
        routes,
        loops,
        suppressed,
        fine_labels: FINE_LABELS,
        caller_label_cap: MAX_CALLER_LABELS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    #[test]
    fn route_groups_by_prefix() {
        let table = [
            ("/v1/chat/{room}/call", "server.route.calls"),
            ("/v1/chat/{room}/call/frames", "server.route.calls"),
            ("/v1/qa/call/start", "server.route.calls"),
            ("/v1/chat/{community_id}/messages", "server.route.chat"),
            ("/v1/contacts/requests", "server.route.chat"),
            ("/v1/files/{attestation_id}", "server.route.files"),
            ("/v1/drive/x", "server.route.files"),
            ("/v1/communities/{community_id}", "server.route.communities"),
            ("/v1/families/{id}/members", "server.route.communities"),
            ("/v1/safety/moderation", "server.route.communities"),
            ("/v1/accord/final-genesis", "server.route.accord"),
            ("/v1/accord-holders/x", "server.route.accord"),
            ("/v1/accordion", "server.route.other"),
            ("/v1/trust-root/import", "server.route.accord"),
            ("/v1/federation/peers", "server.route.federation"),
            ("/v1/mesh-config/x", "server.route.admin"),
            ("/v1/mesh/relay", "server.route.federation"),
            ("/lens-api/api/v1/accord/events", "server.route.federation"),
            ("/v1/telemetry/otlp/metrics", "server.route.telemetry"),
            ("/v1/system/health", "server.route.health"),
            ("/health", "server.route.health"),
            ("/healthz", "server.route.other"),
            ("/v1/admin/throttle", "server.route.admin"),
            ("/v1/setup/status", "server.route.admin"),
            ("/v1/qa/other", "server.route.admin"),
            ("/v1/self/occurrences", "server.route.self"),
            ("/v1/auth/login", "server.route.self"),
            ("/v1/identity", "server.route.self"),
            ("/", "server.route.other"),
        ];
        for (path, want) in table {
            assert_eq!(route_group(path), want, "{path}");
        }
    }

    #[test]
    fn every_label_fits_persists_grammar() {
        for (_, g) in ROUTE_GROUPS {
            ciris_persist::observe::validate_caller_label(g).expect(g);
        }
        ciris_persist::observe::validate_caller_label(OTHER_GROUP).unwrap();
        ciris_persist::observe::validate_caller_label(COARSE_LABEL).unwrap();
        for name in crate::loop_cadence::LOOPS {
            let l = loop_label(name);
            ciris_persist::observe::validate_caller_label(&l).expect(&l);
        }
        let groups: std::collections::BTreeSet<_> = ROUTE_GROUPS.iter().map(|(_, g)| *g).collect();
        assert!(groups.len() < 12, "the group budget: {groups:?}");
    }

    /// A read inside a request is credited to its route group's caller, and the response
    /// is counted under its route TEMPLATE, never its raw path (A8).
    #[tokio::test]
    async fn a_request_runs_under_its_groups_caller() {
        async fn who() -> String {
            current_caller().map(Caller::label).unwrap_or_default()
        }
        let app = Router::new()
            .route("/v1/chat/{room}/messages", get(who))
            .layer(axum::middleware::from_fn(attribute_request));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chat/room-abc-123/messages")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let label = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(label, effective_label("server.route.chat"));
        let snap = snapshot();
        let row = snap
            .routes
            .iter()
            .find(|(r, m, _)| r == "/v1/chat/{room}/messages" && *m == "GET")
            .expect("counted under the template");
        assert_eq!(row.2.by_class[1], 1);
        assert_eq!(row.2.duration.count, 1);
        assert!(
            !snap
                .routes
                .iter()
                .any(|(r, _, _)| r.contains("room-abc-123")),
            "a raw path is never a label"
        );
    }

    #[tokio::test]
    async fn a_loop_and_its_carried_task_run_under_the_loops_caller() {
        let (a, b) = spawn_loop("scorer", async {
            let mine = current_caller().map(Caller::label);
            let child = spawn_carried(async { current_caller().map(Caller::label) })
                .await
                .unwrap();
            (mine, child)
        })
        .await
        .unwrap();
        let want = effective_label(&loop_label("scorer")).to_owned();
        assert_eq!(a.as_deref(), Some(want.as_str()));
        assert_eq!(b.as_deref(), Some(want.as_str()));
    }

    #[test]
    fn the_loop_registry_counts_passes_by_outcome() {
        register_loop("workload_test_loop", Duration::from_secs(45));
        drop(LoopPass::begin("workload_test_loop"));
        let mut p = LoopPass::begin("workload_test_loop");
        p.failed();
        drop(p);
        let snap = snapshot();
        let (_, s) = snap
            .loops
            .iter()
            .find(|(n, _)| *n == "workload_test_loop")
            .unwrap();
        assert_eq!(s.interval_secs, 45.0);
        assert_eq!((s.ok, s.error), (1, 1));
        assert_eq!(s.duration.count, 2);
    }

    #[test]
    fn a_repeat_is_counted_not_said() {
        assert!(say_on_change("workload_test_site", "k", "absent"));
        assert!(!say_on_change("workload_test_site", "k", "absent"));
        assert!(!say_on_change("workload_test_site", "k", "absent"));
        assert!(say_on_change("workload_test_site", "k", "resolved"));
        assert!(say_on_change("workload_test_site", "other-key", "absent"));
        let n = snapshot()
            .suppressed
            .iter()
            .find(|(s, _)| *s == "workload_test_site")
            .map(|(_, n)| *n);
        assert_eq!(n, Some(2));
    }

    #[test]
    fn a_duration_lands_in_its_bucket() {
        let mut h = Hist::default();
        h.record(Duration::from_millis(3));
        h.record(Duration::from_secs(100));
        assert_eq!(h.counts[2], 1, "3 ms is in (2.5 ms, 5 ms]");
        assert_eq!(*h.counts.last().unwrap(), 1, "overflow");
        assert_eq!(h.count, 2);
    }
}
