//! `GET /v1/telemetry/otlp/metrics`: the node's metrics as OTLP JSON
//! (OpenTelemetry protocol 1.x, the JSON encoding), the way the agent serves
//! its own. Eric 2026-11-19: a call's connection info comes over the same
//! telemetry as everything else, and the client's "?" panel reads it here.
//!
//! **What it serves.** Edge's telemetry, rendered generically. Every field of
//! edge's `EdgeMetricsBundle` has a row in `ciris_edge::telemetry::
//! TELEMETRY_CATALOGUE` (its `ciris.edge.*` name, kind, unit and label key),
//! and the bundle's `flatten()` projects each value as `field` (the total) or
//! `field.<label>`. This module maps one onto the other, so a field edge adds
//! appears here with no server change, and a value edge does not report is
//! absent, never 0 (the catalogue's rule, and the client's: "not reported").
//! The per-call series (edge 45.1.7 `call_legs`: path, RTT, bitrate, loss,
//! jitter, reorder window, codec, each per leg) render the same way once that
//! edge is pinned.
//!
//! **Who may read it.** The node's operator: its host or its owner
//! (`auth::operator_gate`), exactly as `/v1/telemetry/logs`. Some series are
//! keyed by a peer (the catalogue's `PeerKeyed`, and a call leg names its
//! member), so the route is never public.
//!
//! **Filtering.** `?attr=<key>:<value>`, repeatable, keeps only the data
//! points carrying every named attribute (e.g. `attr=ciris.call.id:<id>`),
//! so a client need not pull the whole export. A metric left with no points
//! is dropped.

use std::collections::BTreeMap;

use axum::extract::{RawQuery, State};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde_json::{json, Value};

use ciris_edge::observability::{EdgeMetrics, FlatMetrics};
use ciris_edge::telemetry::{Kind, TelemetrySpec, Unit, TELEMETRY_CATALOGUE};

#[derive(Clone)]
struct OtlpState {
    metrics: EdgeMetrics,
    node_key_id: String,
}

/// The router. `metrics` is edge's live handle; `node_key_id` names this
/// node in the resource attributes.
pub fn router(
    engine: std::sync::Arc<ciris_persist::prelude::Engine>,
    metrics: EdgeMetrics,
    node_key_id: String,
) -> Router {
    Router::new()
        .route(
            "/v1/telemetry/otlp/metrics",
            axum::routing::get(get_metrics),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            engine,
            crate::auth::operator_gate::require_operator,
        ))
        .with_state(OtlpState {
            metrics,
            node_key_id,
        })
}

async fn get_metrics(State(st): State<OtlpState>, RawQuery(q): RawQuery) -> Response {
    let filter = parse_filter(q.as_deref().unwrap_or(""));
    let flat = st.metrics.snapshot().flatten();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let server = crate::workload::snapshot();
    Json(render(&flat, &server, &st.node_key_id, now, &filter)).into_response()
}

/// `attr=k:v` pairs, percent-decoded. A pair without `:` is ignored.
fn parse_filter(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .filter(|(k, _)| *k == "attr")
        .filter_map(|(_, v)| {
            let v = percent_decode(v);
            v.split_once(':').map(|(a, b)| (a.to_owned(), b.to_owned()))
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(v) => {
                    out.push(v);
                    i += 3;
                    continue;
                }
                Err(_) => out.push(b'%'),
            },
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// OTLP's UCUM unit for an edge unit.
fn ucum(u: Unit) -> &'static str {
    match u {
        Unit::Count | Unit::Ratio => "1",
        Unit::Seconds => "s",
        Unit::Milliseconds => "ms",
        Unit::Nanoseconds => "ns",
        Unit::Bytes => "By",
        Unit::BitsPerSecond => "bit/s",
    }
}

fn attr(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}

/// One flat value: an integer counter, or a real-valued gauge.
#[derive(Clone, Copy)]
enum V {
    Int(u64),
    Real(f64),
}

/// The flat entries of one catalogue field: `(label, value)`, where the
/// label is `None` for the field's own key.
fn entries_of(flat: &FlatMetrics, field: &str) -> Vec<(Option<String>, V)> {
    let dotted = format!("{field}.");
    let mut out = Vec::new();
    for (k, v) in &flat.counters {
        if k == field {
            out.push((None, V::Int(*v)));
        } else if let Some(rest) = k.strip_prefix(&dotted) {
            out.push((Some(rest.to_owned()), V::Int(*v)));
        }
    }
    for (k, v) in &flat.gauges {
        if k == field {
            out.push((None, V::Real(*v)));
        } else if let Some(rest) = k.strip_prefix(&dotted) {
            out.push((Some(rest.to_owned()), V::Real(*v)));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn keeps(points_attrs: &[(String, String)], filter: &[(String, String)]) -> bool {
    filter
        .iter()
        .all(|(k, v)| points_attrs.iter().any(|(a, b)| a == k && b == v))
}

fn point(attrs: &[(String, String)], v: V, now: u128) -> Value {
    let mut p = json!({
        "attributes": attrs.iter().map(|(k, v)| attr(k, v)).collect::<Vec<_>>(),
        "timeUnixNano": now.to_string(),
    });
    match v {
        V::Int(n) => p["asInt"] = json!(n.to_string()),
        V::Real(x) => p["asDouble"] = json!(x),
    }
    p
}

/// A counter or gauge metric from its catalogue row.
fn scalar_metric(
    spec: &TelemetrySpec,
    flat: &FlatMetrics,
    now: u128,
    filter: &[(String, String)],
) -> Option<Value> {
    let label_key = spec.label.as_ref().map(|(k, _)| *k);
    let mut points = Vec::new();
    for (label, v) in entries_of(flat, spec.field) {
        let attrs: Vec<(String, String)> = match (&label, label_key) {
            // A labelled family's own key is the sum over its labels: the
            // per-label points carry the information, so it is not repeated.
            (None, Some(_)) => continue,
            (None, None) => vec![],
            (Some(l), Some(k)) => vec![(k.to_owned(), l.clone())],
            (Some(l), None) => vec![("ciris.edge.key".to_owned(), l.clone())],
        };
        if keeps(&attrs, filter) {
            points.push(point(&attrs, v, now));
        }
    }
    if points.is_empty() {
        return None;
    }
    let body = match spec.kind {
        Kind::Counter => json!({ "sum": {
            "aggregationTemporality": 2, "isMonotonic": true, "dataPoints": points } }),
        _ => json!({ "gauge": { "dataPoints": points } }),
    };
    let mut m =
        json!({ "name": spec.name, "unit": ucum(spec.unit), "description": spec.description });
    if let (Some(o), Some(b)) = (m.as_object_mut(), body.as_object()) {
        for (k, v) in b {
            o.insert(k.clone(), v.clone());
        }
    }
    Some(m)
}

/// A histogram from its flattened `bucket.<le>` / `count` / `sum` keys,
/// optionally under one label: cumulative buckets become OTLP's per-bucket
/// counts with explicit bounds.
fn histogram_metric(
    spec: &TelemetrySpec,
    flat: &FlatMetrics,
    now: u128,
    filter: &[(String, String)],
) -> Option<Value> {
    #[derive(Default)]
    struct H {
        buckets: Vec<(f64, u64)>,
        count: Option<u64>,
        sum: Option<f64>,
    }
    let label_key = spec.label.as_ref().map(|(k, _)| *k);
    let mut by_label: BTreeMap<Option<String>, H> = BTreeMap::new();
    for (rest, v) in entries_of(flat, spec.field) {
        let Some(rest) = rest else { continue };
        let (label, tail) = if rest.starts_with("bucket.") || rest == "count" || rest == "sum" {
            (None, rest.as_str())
        } else {
            match rest.split_once('.') {
                Some((l, t)) => (Some(l.to_owned()), t),
                None => continue,
            }
        };
        let h = by_label.entry(label).or_default();
        match (tail, v) {
            ("count", V::Int(n)) => h.count = Some(n),
            ("sum", V::Real(x)) => h.sum = Some(x),
            (t, V::Int(n)) if t.starts_with("bucket.") => {
                let le = &t["bucket.".len()..];
                let bound = if le.eq_ignore_ascii_case("+inf") || le == "inf" {
                    f64::INFINITY
                } else {
                    match le.parse::<f64>() {
                        Ok(b) => b,
                        Err(_) => continue,
                    }
                };
                h.buckets.push((bound, n));
            }
            _ => {}
        }
    }
    let mut points = Vec::new();
    for (label, mut h) in by_label {
        let attrs: Vec<(String, String)> = match (label, label_key) {
            (Some(l), Some(k)) => vec![(k.to_owned(), l)],
            (Some(l), None) => vec![("ciris.edge.key".to_owned(), l)],
            (None, _) => vec![],
        };
        if !keeps(&attrs, filter) {
            continue;
        }
        h.buckets.sort_by(|a, b| a.0.total_cmp(&b.0));
        let mut bounds = Vec::new();
        let mut counts = Vec::new();
        let mut prev = 0u64;
        for (b, cumulative) in &h.buckets {
            if b.is_finite() {
                bounds.push(*b);
            }
            counts.push(cumulative.saturating_sub(prev).to_string());
            prev = *cumulative;
        }
        let total = h.count.unwrap_or(prev);
        if h.buckets.last().is_none_or(|(b, _)| b.is_finite()) {
            // No +Inf bucket in the flat form: the overflow is count - last.
            counts.push(total.saturating_sub(prev).to_string());
        }
        let mut p = json!({
            "attributes": attrs.iter().map(|(k, v)| attr(k, v)).collect::<Vec<_>>(),
            "timeUnixNano": now.to_string(),
            "count": total.to_string(),
            "explicitBounds": bounds,
            "bucketCounts": counts,
        });
        if let Some(s) = h.sum {
            p["sum"] = json!(s);
        }
        points.push(p);
    }
    if points.is_empty() {
        return None;
    }
    Some(json!({
        "name": spec.name, "unit": ucum(spec.unit), "description": spec.description,
        "histogram": { "aggregationTemporality": 2, "dataPoints": points },
    }))
}

/// The whole export: one resource (this node), two scopes: edge's catalogue, and the
/// server's own workload series (`crate::workload`, FSD/WORKLOAD_ATTRIBUTION.md A2).
pub fn render(
    flat: &FlatMetrics,
    server: &crate::workload::Snapshot,
    node_key_id: &str,
    now: u128,
    filter: &[(String, String)],
) -> Value {
    let metrics: Vec<Value> = TELEMETRY_CATALOGUE
        .iter()
        .filter_map(|spec| match spec.kind {
            Kind::Histogram => histogram_metric(spec, flat, now, filter),
            _ => scalar_metric(spec, flat, now, filter),
        })
        .collect();
    json!({
        "resourceMetrics": [{
            "resource": { "attributes": [
                attr("service.name", "ciris-server"),
                attr("service.version", env!("CARGO_PKG_VERSION")),
                attr("ciris.node.key_id", node_key_id),
            ]},
            "scopeMetrics": [
                {
                    "scope": { "name": "ciris-edge" },
                    "metrics": metrics,
                },
                {
                    "scope": { "name": "ciris-server" },
                    "metrics": server_metrics(server, now, filter),
                },
            ],
        }]
    })
}

fn pairs(a: &[(&str, &str)]) -> Vec<(String, String)> {
    a.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

/// A histogram data point from a workload histogram.
fn hist_point(attrs: &[(String, String)], h: &crate::workload::Hist, now: u128) -> Value {
    json!({
        "attributes": attrs.iter().map(|(k, v)| attr(k, v)).collect::<Vec<_>>(),
        "timeUnixNano": now.to_string(),
        "count": h.count.to_string(),
        "sum": h.sum_secs,
        "explicitBounds": crate::workload::DURATION_BOUNDS_SECS,
        "bucketCounts": h.counts.iter().map(u64::to_string).collect::<Vec<_>>(),
    })
}

fn sum_of(name: &str, unit: &str, description: &str, points: Vec<Value>) -> Option<Value> {
    (!points.is_empty()).then(|| {
        json!({ "name": name, "unit": unit, "description": description,
            "sum": { "aggregationTemporality": 2, "isMonotonic": true, "dataPoints": points } })
    })
}

fn gauge_of(name: &str, unit: &str, description: &str, points: Vec<Value>) -> Option<Value> {
    (!points.is_empty()).then(|| {
        json!({ "name": name, "unit": unit, "description": description,
            "gauge": { "dataPoints": points } })
    })
}

fn hist_of(name: &str, unit: &str, description: &str, points: Vec<Value>) -> Option<Value> {
    (!points.is_empty()).then(|| {
        json!({ "name": name, "unit": unit, "description": description,
            "histogram": { "aggregationTemporality": 2, "dataPoints": points } })
    })
}

/// The server's `ciris.server.*` series. Labels are route templates, methods, status
/// classes, loop names and log sites only (A8). The `?attr=` filter applies as to edge's.
fn server_metrics(
    s: &crate::workload::Snapshot,
    now: u128,
    filter: &[(String, String)],
) -> Vec<Value> {
    const CLASSES: [&str; 5] = ["1xx", "2xx", "3xx", "4xx", "5xx"];
    let mut requests = Vec::new();
    let mut durations = Vec::new();
    for (route, method, st) in &s.routes {
        for (i, n) in st.by_class.iter().enumerate() {
            if *n == 0 {
                continue;
            }
            let a = pairs(&[
                ("http.route", route),
                ("http.request.method", method),
                ("http.response.status_class", CLASSES[i]),
            ]);
            if keeps(&a, filter) {
                requests.push(point(&a, V::Int(*n), now));
            }
        }
        let a = pairs(&[("http.route", route), ("http.request.method", method)]);
        if st.duration.count > 0 && keeps(&a, filter) {
            durations.push(hist_point(&a, &st.duration, now));
        }
    }
    let mut ticks = Vec::new();
    let mut loop_durations = Vec::new();
    let mut intervals = Vec::new();
    for (name, st) in &s.loops {
        for (outcome, n) in [("ok", st.ok), ("error", st.error)] {
            let a = pairs(&[("ciris.loop.name", name), ("ciris.loop.outcome", outcome)]);
            if n > 0 && keeps(&a, filter) {
                ticks.push(point(&a, V::Int(n), now));
            }
        }
        let a = pairs(&[("ciris.loop.name", name)]);
        if !keeps(&a, filter) {
            continue;
        }
        if st.duration.count > 0 {
            loop_durations.push(hist_point(&a, &st.duration, now));
        }
        intervals.push(point(&a, V::Real(st.interval_secs), now));
    }
    let mut suppressed = Vec::new();
    for (site, n) in &s.suppressed {
        let a = pairs(&[("ciris.log.site", site)]);
        if keeps(&a, filter) {
            suppressed.push(point(&a, V::Int(*n), now));
        }
    }
    // Unlabelled facts about this build; a filter on any attribute drops them.
    let unlabelled = |v: V| {
        if filter.is_empty() {
            vec![point(&[], v, now)]
        } else {
            Vec::new()
        }
    };
    [
        sum_of(
            "ciris.server.http.requests",
            "1",
            "Responses per matched route template, method and status class",
            requests,
        ),
        hist_of(
            "ciris.server.http.duration",
            "s",
            "Request duration (to the response head) per route template and method",
            durations,
        ),
        sum_of(
            "ciris.server.loop.ticks",
            "1",
            "Background loop passes, by loop and outcome",
            ticks,
        ),
        hist_of(
            "ciris.server.loop.duration",
            "s",
            "Background loop pass duration",
            loop_durations,
        ),
        gauge_of(
            "ciris.server.loop.interval_secs",
            "s",
            "Each background loop's configured interval",
            intervals,
        ),
        sum_of(
            "ciris.server.log.suppressed_repeats",
            "1",
            "Repeated log lines counted instead of logged, by site",
            suppressed,
        ),
        gauge_of(
            "ciris.server.attribution.caller_label_cap",
            "1",
            "persist's caller-label cap in this build",
            unlabelled(V::Int(s.caller_label_cap as u64)),
        ),
        gauge_of(
            "ciris.server.attribution.fine_labels",
            "1",
            "1 when the server interns route-group and loop caller labels; 0 when every \
             server read is credited to the one `server` label (persist's cap is too small)",
            unlabelled(V::Int(u64::from(s.fine_labels))),
        ),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flat(counters: &[(&str, u64)], gauges: &[(&str, f64)]) -> FlatMetrics {
        let mut f = FlatMetrics::default();
        for (k, v) in counters {
            f.counters.insert((*k).to_owned(), *v);
        }
        for (k, v) in gauges {
            f.gauges.insert((*k).to_owned(), *v);
        }
        f
    }

    fn metric<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
        v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()?
            .iter()
            .find(|m| m["name"] == name)
    }

    /// A real snapshot renders every catalogue name it carries, and nothing
    /// the bundle did not report.
    #[test]
    fn a_live_snapshot_renders_through_the_catalogue() {
        let m = EdgeMetrics::new();
        let f = m.snapshot().flatten();
        let v = render(&f, &crate::workload::Snapshot::default(), "node-1", 1, &[]);
        let names: Vec<&str> = v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|m| m["name"].as_str())
            .collect();
        assert!(!names.is_empty(), "{v}");
        for n in &names {
            assert!(n.starts_with("ciris.edge."), "{n}");
            assert!(
                TELEMETRY_CATALOGUE.iter().any(|s| s.name == *n),
                "{n} is in the catalogue"
            );
        }
        assert_eq!(
            v["resourceMetrics"][0]["resource"]["attributes"][2]["value"]["stringValue"],
            "node-1"
        );
    }

    #[test]
    fn a_labelled_family_is_one_point_per_label_and_the_filter_keeps_matches() {
        let spec = TELEMETRY_CATALOGUE
            .iter()
            .find(|s| s.label.is_some() && !matches!(s.kind, Kind::Histogram))
            .expect("a labelled scalar in the catalogue");
        let key = spec.label.as_ref().unwrap().0;
        let f = flat(
            &[
                (spec.field, 7),
                (&format!("{}.alpha", spec.field), 3),
                (&format!("{}.beta", spec.field), 4),
            ],
            &[],
        );
        let all = render(&f, &crate::workload::Snapshot::default(), "n", 1, &[]);
        let m = metric(&all, spec.name).expect("rendered");
        let body = m.get("sum").or_else(|| m.get("gauge")).unwrap();
        assert_eq!(body["dataPoints"].as_array().unwrap().len(), 2, "{m}");
        let only = render(
            &f,
            &crate::workload::Snapshot::default(),
            "n",
            1,
            &[(key.to_owned(), "beta".to_owned())],
        );
        let m = metric(&only, spec.name).expect("filtered");
        let body = m.get("sum").or_else(|| m.get("gauge")).unwrap();
        let pts = body["dataPoints"].as_array().unwrap();
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0]["asInt"], "4");
        // A filter nothing matches drops the metric: absent, never zero.
        let none = render(
            &f,
            &crate::workload::Snapshot::default(),
            "n",
            1,
            &[(key.to_owned(), "gamma".to_owned())],
        );
        assert!(metric(&none, spec.name).is_none());
    }

    #[test]
    fn a_histogram_becomes_per_bucket_counts() {
        let spec = TELEMETRY_CATALOGUE
            .iter()
            .find(|s| matches!(s.kind, Kind::Histogram) && s.label.is_none())
            .expect("an unlabelled histogram in the catalogue");
        let f = flat(
            &[
                (&format!("{}.bucket.0.1", spec.field), 2),
                (&format!("{}.bucket.1", spec.field), 5),
                (&format!("{}.count", spec.field), 6),
            ],
            &[(&format!("{}.sum", spec.field), 2.5)],
        );
        let v = render(&f, &crate::workload::Snapshot::default(), "n", 1, &[]);
        let p = &metric(&v, spec.name).expect("rendered")["histogram"]["dataPoints"][0];
        assert_eq!(p["explicitBounds"], json!([0.1, 1.0]));
        assert_eq!(p["bucketCounts"], json!(["2", "3", "1"]));
        assert_eq!(p["count"], "6");
        assert_eq!(p["sum"], 2.5);
    }

    #[test]
    fn the_filter_reads_repeated_percent_encoded_pairs() {
        assert_eq!(
            parse_filter("attr=ciris.call.id%3Aabc&x=1&attr=ciris.media.kind:video"),
            vec![
                ("ciris.call.id".to_owned(), "abc".to_owned()),
                ("ciris.media.kind".to_owned(), "video".to_owned())
            ]
        );
    }

    /// The server's own series render as `ciris.server.*`, labelled by template, method,
    /// class, loop and site only, and the filter applies to them as to edge's.
    #[test]
    fn the_server_series_render_beside_edges() {
        let mut counts = vec![0; crate::workload::DURATION_BOUNDS_SECS.len() + 1];
        counts[6] = 3;
        let h = crate::workload::Hist {
            counts,
            count: 3,
            sum_secs: 0.3,
        };
        let route = crate::workload::RouteStats {
            by_class: [0, 2, 0, 1, 0],
            duration: h.clone(),
        };
        let lp = crate::workload::LoopStats {
            interval_secs: 30.0,
            ok: 5,
            error: 1,
            duration: h,
        };
        let server = crate::workload::Snapshot {
            routes: vec![("/v1/chat/{room}/messages".to_owned(), "GET", route)],
            loops: vec![("self_room", lp)],
            suppressed: vec![("owner_pen", 47)],
            fine_labels: false,
            caller_label_cap: 32,
        };
        let v = render(&FlatMetrics::default(), &server, "n", 1, &[]);
        let scope = &v["resourceMetrics"][0]["scopeMetrics"][1];
        assert_eq!(scope["scope"]["name"], "ciris-server");
        let find = |name: &str| {
            scope["metrics"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["name"] == name)
                .cloned()
                .unwrap_or_else(|| panic!("{name} in {scope}"))
        };
        let req = find("ciris.server.http.requests");
        let pts = req["sum"]["dataPoints"].as_array().unwrap();
        assert_eq!(pts.len(), 2, "one point per non-zero status class");
        let ok = pts
            .iter()
            .find(|p| p["attributes"].to_string().contains("2xx"))
            .unwrap();
        assert_eq!(ok["asInt"], "2");
        assert!(ok["attributes"]
            .to_string()
            .contains("/v1/chat/{room}/messages"));
        let dur = find("ciris.server.http.duration");
        assert_eq!(dur["histogram"]["dataPoints"][0]["count"], "3");
        let ticks = find("ciris.server.loop.ticks");
        assert_eq!(ticks["sum"]["dataPoints"].as_array().unwrap().len(), 2);
        assert_eq!(
            find("ciris.server.loop.interval_secs")["gauge"]["dataPoints"][0]["asDouble"],
            30.0
        );
        assert_eq!(
            find("ciris.server.log.suppressed_repeats")["sum"]["dataPoints"][0]["asInt"],
            "47"
        );
        assert_eq!(
            find("ciris.server.attribution.fine_labels")["gauge"]["dataPoints"][0]["asInt"],
            "0"
        );
        // The filter: only the self_room loop's series survive.
        let only = render(
            &FlatMetrics::default(),
            &server,
            "n",
            1,
            &[("ciris.loop.name".to_owned(), "self_room".to_owned())],
        );
        let names: Vec<String> = only["resourceMetrics"][0]["scopeMetrics"][1]["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["name"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            names,
            [
                "ciris.server.loop.ticks",
                "ciris.server.loop.duration",
                "ciris.server.loop.interval_secs"
            ],
            "{names:?}"
        );
    }
}
