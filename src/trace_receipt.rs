//! **The receipt** — did *my* traces reach the canonical?
//!
//! Two instruments already exist and neither answers that question:
//!
//!   * The RECEIVER's `trace_plane` band on `/v1/node/state` (CIRISServer#369)
//!     says whether *any* trace was admitted recently. It is what the canonical
//!     acts on, and it cannot tell one producer from another.
//!   * The PRODUCER's `delivery_status()` (CIRISServer#205/#377) says whether the
//!     canonical is known, KEX is present, consent covers `trace:`, rows are
//!     offerable and rounds complete. Every one of those is a PRECONDITION. A
//!     node can report all of them true and ship nothing — CIRISServer#487 was
//!     exactly that shape, and the question "did they land?" was answered by an
//!     operator querying the canonical's database by key.
//!
//! What was missing is a number the producer can read that the RECEIVER
//! asserts: *of the traces this agent authored, the canonical holds N.* This
//! module is that number, on both sides:
//!
//!   * **Canonical door** — [`router`] serves [`RECEIPT_ROUTE`]
//!     (`GET /v1/traces/receipt?agent_id_hash=…`): count + newest trace for one
//!     agent, index-served by persist's `trace_events_agenthash_ts`. No
//!     payloads, no components — the asker names the hash, and gets back how
//!     many and how recent. Unauthenticated on purpose: a producer proving its
//!     own delivery holds no credential on the canonical, and the mesh already
//!     replicates these rows to every consented peer. (AV-9 gates trace READS
//!     on `agent_id_hash` at the caller's layer; this surface returns nothing
//!     that read would — see the PR for the exposure argument.)
//!   * **Producer door** — [`delivery_receipt`] counts what this node authored
//!     per agent, asks each canonical's receipt route for the same hashes, and
//!     reports `authored / held / lag` per pair. Two front doors, one function:
//!     `ciris_server.delivery_receipt()` in-process for the embedded agent
//!     (the door its QA runner already uses for `delivery_status()`), and
//!     `GET /v1/node/delivery-receipt` (owner-gated, on the operator surface)
//!     for a compose node.
//!
//! Kept OUT of `delivery_status()` deliberately: that surface is polled in a
//! wait loop, and this one makes an HTTP round-trip per canonical. A receipt is
//! read once at the end of a run, not on every poll.
//!
//! The canonical's read-API address is DERIVED unless configured: the baked
//! record advertises only its Reticulum transport (`ip host:4242`), so the
//! producer assumes the read API on the same host at [`READ_API_PORT`] and says
//! so in `url_source`. A wrong guess reads as `reachable: false` with the URL it
//! tried — never as "zero held" — and the config key
//! [`crate::config_reconcile::KEY_CANONICAL_READ_URLS`] overrides it.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use ciris_persist::prelude::{CallerScope, Engine, TraceFilter};

/// The canonical door: `GET /v1/traces/receipt?agent_id_hash=…`.
pub const RECEIPT_ROUTE: &str = "/v1/traces/receipt";

/// The producer door on the operator surface (owner-gated, see
/// [`crate::operator_surface`]).
pub const PRODUCER_ROUTE: &str = "/v1/node/delivery-receipt";

/// The read-API port a canonical is assumed to answer on when its record
/// advertises only a Reticulum `ip` hint. The default `:4243` every node binds
/// (see `compose`); override per canonical with
/// [`crate::config_reconcile::KEY_CANONICAL_READ_URLS`].
pub const READ_API_PORT: u16 = 4243;

/// How long one canonical gets to answer before `reachable: false`.
pub const ASK_TIMEOUT: Duration = Duration::from_secs(3);

/// How many local summaries the producer pages to discover its agent hashes.
/// Counts are exact regardless (`count_traces` per hash); this only bounds the
/// discovery read.
pub const LOCAL_WINDOW: i64 = 5_000;

/// The newest trace the canonical holds for an agent — enough to recognise
/// "the one I just sent", nothing of its content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Newest {
    pub trace_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

/// What a canonical asserts about one agent's traces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub agent_id_hash: String,
    /// Distinct traces held for this agent.
    pub traces: i64,
    /// `None` when the canonical holds none — and, on the producer side, the
    /// reader must keep that apart from "could not ask".
    pub newest: Option<Newest>,
    pub read_at: DateTime<Utc>,
}

/// One agent's receipt from THIS engine's store.
pub async fn receipt_for(engine: &Engine, agent_id_hash: &str) -> Result<Receipt, String> {
    let filter = TraceFilter {
        agent_id_hash: Some(agent_id_hash.to_string()),
        ..TraceFilter::default()
    };
    let traces = crate::backend::count_traces(engine, filter.clone(), CallerScope::Unauthenticated)
        .await
        .map_err(|e| format!("count traces: {e}"))?;
    let page =
        crate::backend::list_trace_summaries(engine, filter, None, 1, CallerScope::Unauthenticated)
            .await
            .map_err(|e| format!("newest trace: {e}"))?;
    let newest = page.items.first().map(|s| Newest {
        trace_id: s.trace_id.clone(),
        started_at: s.started_at,
        completed_at: s.completed_at,
    });
    Ok(Receipt {
        agent_id_hash: agent_id_hash.to_string(),
        traces,
        newest,
        read_at: Utc::now(),
    })
}

#[derive(Deserialize)]
struct ReceiptQuery {
    agent_id_hash: Option<String>,
}

async fn get_receipt(State(engine): State<Arc<Engine>>, Query(q): Query<ReceiptQuery>) -> Response {
    let hash = q
        .agent_id_hash
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if hash.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "`agent_id_hash` query parameter is required" })),
        )
            .into_response();
    }
    match receipt_for(&engine, hash).await {
        Ok(r) => (StatusCode::OK, Json(json!({ "data": r }))).into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": e }))).into_response(),
    }
}

/// The canonical door. Merge into the node's public router.
pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route(RECEIPT_ROUTE, axum::routing::get(get_receipt))
        .with_state(engine)
}

/// Where the producer will ask, and how it decided.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CanonicalRead {
    /// The canonical's federation `key_id` when known from the baked record;
    /// `config` entries carry none.
    pub key_id: Option<String>,
    /// Base URL of the canonical's read API, no trailing slash.
    pub url: String,
    pub url_source: UrlSource,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UrlSource {
    /// From `federation.canonical_read_urls`.
    Config,
    /// From the baked record's `ip` hint, host kept, port replaced by
    /// [`READ_API_PORT`].
    DerivedFromIpHint,
    /// From a baked `http`/`https` hint, used as-is.
    HttpHint,
}

/// The canonicals this node will ask. Config first, else the baked record's
/// hints; empty when neither names one.
pub async fn canonical_reads(engine: &Arc<Engine>) -> Vec<CanonicalRead> {
    if let Ok(Some(urls)) =
        crate::graph_config::get_str_list(engine, crate::config_reconcile::KEY_CANONICAL_READ_URLS)
            .await
    {
        let cfg: Vec<CanonicalRead> = urls
            .iter()
            .map(|u| u.trim().trim_end_matches('/'))
            .filter(|u| !u.is_empty())
            .map(|u| CanonicalRead {
                key_id: None,
                url: u.to_string(),
                url_source: UrlSource::Config,
            })
            .collect();
        if !cfg.is_empty() {
            return cfg;
        }
    }
    let hints = match engine.canonical_bootstrap_hints().await {
        Ok(h) => h,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<CanonicalRead> = Vec::new();
    for (key_id, hint) in hints {
        let read = match hint.kind.as_str() {
            "http" | "https" => CanonicalRead {
                key_id: Some(key_id),
                url: hint.destination.trim_end_matches('/').to_string(),
                url_source: UrlSource::HttpHint,
            },
            "ip" => {
                let host = host_of(&hint.destination);
                CanonicalRead {
                    key_id: Some(key_id),
                    url: format!("http://{host}:{READ_API_PORT}"),
                    url_source: UrlSource::DerivedFromIpHint,
                }
            }
            _ => continue,
        };
        if !out.iter().any(|r| r.url == read.url) {
            out.push(read);
        }
    }
    out
}

/// `host:port` → `host`; a bracketed IPv6 literal keeps its brackets.
fn host_of(destination: &str) -> String {
    let d = destination.trim();
    if let Some(end) = d.strip_prefix('[').and_then(|_| d.find(']')) {
        return d[..=end].to_string();
    }
    match d.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host.to_string(),
        _ => d.to_string(),
    }
}

/// What this node authored for one agent.
#[derive(Debug, Clone, Serialize)]
pub struct Authored {
    pub agent_id_hash: String,
    pub authored: i64,
    pub newest_authored: Option<Newest>,
}

/// Discover the agent hashes this node holds traces for, with exact counts.
pub async fn authored_here(engine: &Engine) -> Result<Vec<Authored>, String> {
    let page = crate::backend::list_trace_summaries(
        engine,
        TraceFilter::default(),
        None,
        LOCAL_WINDOW,
        CallerScope::Unauthenticated,
    )
    .await
    .map_err(|e| format!("list local traces: {e}"))?;
    let mut order: Vec<String> = Vec::new();
    let mut newest: std::collections::BTreeMap<String, Newest> = Default::default();
    for s in &page.items {
        if !order.contains(&s.agent_id_hash) {
            order.push(s.agent_id_hash.clone());
        }
        // The page is newest-first, so the first sighting is the newest.
        newest
            .entry(s.agent_id_hash.clone())
            .or_insert_with(|| Newest {
                trace_id: s.trace_id.clone(),
                started_at: s.started_at,
                completed_at: s.completed_at,
            });
    }
    let mut out = Vec::with_capacity(order.len());
    for hash in order {
        let filter = TraceFilter {
            agent_id_hash: Some(hash.clone()),
            ..TraceFilter::default()
        };
        let authored = crate::backend::count_traces(engine, filter, CallerScope::Unauthenticated)
            .await
            .map_err(|e| format!("count local traces for {hash}: {e}"))?;
        out.push(Authored {
            newest_authored: newest.remove(&hash),
            agent_id_hash: hash,
            authored,
        });
    }
    Ok(out)
}

/// Ask one canonical for one agent's receipt.
async fn ask(client: &reqwest::Client, base: &str, agent_id_hash: &str) -> Result<Receipt, String> {
    let url = format!("{base}{RECEIPT_ROUTE}");
    let resp = client
        .get(&url)
        .query(&[("agent_id_hash", agent_id_hash)])
        .send()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("{url}: read body: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "{url}: HTTP {status}: {}",
            body.chars().take(200).collect::<String>()
        ));
    }
    let v: Value = serde_json::from_str(&body).map_err(|e| format!("{url}: not JSON: {e}"))?;
    serde_json::from_value::<Receipt>(v.get("data").cloned().unwrap_or(Value::Null))
        .map_err(|e| format!("{url}: not a receipt: {e}"))
}

/// The producer's receipt: what this node authored, per agent, against what
/// each canonical says it holds. One function behind two doors.
///
/// Every number that could not be read is `null`, never `0`: an unreachable
/// canonical is `reachable: false` with the URL it tried and the error, and
/// `held`/`lag` stay absent for it.
pub async fn delivery_receipt(engine: &Engine, canonicals: Vec<CanonicalRead>) -> Value {
    let read_at = Utc::now();
    let agents = match authored_here(engine).await {
        Ok(a) => a,
        Err(e) => {
            return json!({
                "read_at": read_at,
                "error": e,
                "hint": "this node's own trace store could not be read — nothing to receipt against",
            })
        }
    };
    let client = reqwest::Client::builder().timeout(ASK_TIMEOUT).build().ok();

    let mut canonical_views = Vec::with_capacity(canonicals.len());
    let mut any_reachable = false;
    let mut all_shipped_to_reachable = true;
    let mut worst_lag: i64 = 0;
    for c in &canonicals {
        let Some(client) = client.as_ref() else {
            canonical_views.push(json!({
                "key_id": c.key_id, "url": c.url, "url_source": c.url_source,
                "reachable": false, "error": "http client could not be built",
            }));
            all_shipped_to_reachable = false;
            continue;
        };
        let mut per_agent = Vec::with_capacity(agents.len());
        let mut reachable = true;
        let mut first_error: Option<String> = None;
        for a in &agents {
            match ask(client, &c.url, &a.agent_id_hash).await {
                Ok(r) => {
                    let lag = (a.authored - r.traces).max(0);
                    if lag > 0 {
                        all_shipped_to_reachable = false;
                    }
                    worst_lag = worst_lag.max(lag);
                    per_agent.push(json!({
                        "agent_id_hash": a.agent_id_hash,
                        "authored": a.authored,
                        "held": r.traces,
                        "lag": lag,
                        // Landed at all — the yes/no #487 needed.
                        "shipped": r.traces > 0,
                        "newest_authored": a.newest_authored,
                        "newest_held": r.newest,
                        // The strongest form of yes: the newest thing we made
                        // is the newest thing they hold.
                        "newest_matches": a.newest_authored.as_ref().map(|n| Some(n) == r.newest.as_ref()),
                    }));
                }
                Err(e) => {
                    reachable = false;
                    first_error.get_or_insert(e);
                    per_agent.push(json!({
                        "agent_id_hash": a.agent_id_hash,
                        "authored": a.authored,
                        "held": Value::Null,
                        "lag": Value::Null,
                        "shipped": Value::Null,
                        "newest_authored": a.newest_authored,
                    }));
                }
            }
        }
        if agents.is_empty() {
            // Nothing to ask about — probe reachability once so the URL guess
            // is still verified.
            if let Err(e) = ask(client, &c.url, "probe").await {
                reachable = false;
                first_error = Some(e);
            }
        }
        any_reachable |= reachable;
        if !reachable {
            all_shipped_to_reachable = false;
        }
        canonical_views.push(json!({
            "key_id": c.key_id,
            "url": c.url,
            "url_source": c.url_source,
            "reachable": reachable,
            "error": first_error,
            "agents": per_agent,
        }));
    }

    let authored_total: i64 = agents.iter().map(|a| a.authored).sum();
    let hint = if canonicals.is_empty() {
        "no canonical read URL: the baked record carries no transport hint and \
         `federation.canonical_read_urls` is unset — there is nothing to ask. Set the \
         config key to the canonical's read API (e.g. http://host:4243)."
            .to_string()
    } else if authored_total == 0 {
        "this node has authored no traces yet — nothing to receipt. Emit first, then re-read."
            .to_string()
    } else if !any_reachable {
        "no canonical answered: `held` is UNKNOWN for every one of them, not zero. The URL \
         each was asked at is in `canonicals[].url` with how it was chosen; a derived one \
         may be wrong — set `federation.canonical_read_urls` to the real read API."
            .to_string()
    } else if all_shipped_to_reachable {
        "every trace authored here is held by every canonical that answered — the plane \
         delivered."
            .to_string()
    } else {
        format!(
            "up to {worst_lag} trace(s) authored here are not held by a canonical that \
             answered. `shipped: true` with a lag means the plane works and is behind (a \
             round has not run, or the newest rows were sealed after the last one); \
             `shipped: false` on a canonical that answered means NOTHING from this agent has \
             ever landed there — read `delivery_status().trace_plane.hint` and \
             `round_diagnostics` for which gate."
        )
    };

    json!({
        "read_at": read_at,
        "agents": agents,
        "canonicals": canonical_views,
        "verdict": {
            "any_canonical_reachable": any_reachable,
            "shipped_to_every_reachable_canonical": if any_reachable { Value::Bool(all_shipped_to_reachable) } else { Value::Null },
            "worst_lag": if any_reachable { json!(worst_lag) } else { Value::Null },
        },
        "hint": hint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_strips_a_port_and_keeps_ipv6_brackets() {
        assert_eq!(host_of("108.61.242.236:4242"), "108.61.242.236");
        assert_eq!(host_of("node.example:4242"), "node.example");
        assert_eq!(host_of("node.example"), "node.example");
        assert_eq!(host_of("[2001:db8::1]:4242"), "[2001:db8::1]");
    }
}
