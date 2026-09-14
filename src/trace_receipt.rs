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
//! What was missing is a statement the producer can read that the RECEIVER
//! asserts and SIGNS: *of the traces this agent authored, I hold N, and I hold
//! the one you name.* This module is that statement, on both sides:
//!
//!   * **Canonical door** — [`router`] serves [`RECEIPT_ROUTE`]
//!     (`GET /v1/traces/receipt?agent_id_hash=…[&trace_id=…]`): count + newest
//!     trace for one agent, and whether one named trace is held, index-served
//!     by persist's `trace_events_agenthash_ts`. No payloads, no components.
//!     Unauthenticated on purpose: a producer proving its own delivery holds no
//!     credential on the canonical, and the mesh already replicates these rows
//!     to every consented peer. The RESPONSE is signed with the canonical's
//!     hybrid node key ([`crate::sign_object`]), because the default path to a
//!     canonical is plain `http://` to a public address and an unsigned
//!     receipt is one an intermediary could write.
//!   * **Producer door** — [`delivery_receipt`] counts what this node authored
//!     per agent, asks each canonical for the same hashes AND for the newest
//!     trace by id, verifies each answer against the canonical's REGISTERED
//!     pubkeys in this node's own directory (the baked record), and reports per
//!     pair whether the newest authored trace is held. Two front doors, one
//!     function: `ciris_server.delivery_receipt(agent_id_hash=None)` in-process
//!     for the embedded agent (the door its QA runner already uses for
//!     `delivery_status()`), and `GET /v1/node/delivery-receipt[?agent_id_hash=]`
//!     (owner-gated, on the operator surface) for a compose node.
//!
//! **Delivery is a fact about identity, not cardinality.** `held >= authored`
//! proves nothing when local retention has pruned rows or the canonical holds
//! history from before this run (Codex, PR #592). The verdict is therefore
//! "the newest trace this node authored is held by the canonical", asked by
//! `trace_id`; the counts are reported beside it as context, never as the
//! answer.
//!
//! **"Authored here" is a fact about the signer, not the store.** A node holds
//! traces it replicated from peers too, and a canonical asking itself holds
//! everyone's. Discovery keeps only summaries whose signing key is THIS
//! process's own federation key; a caller that knows its agent hash names it
//! and skips discovery altogether.
//!
//! Kept OUT of `delivery_status()` deliberately: that surface is polled in a
//! wait loop, and this one makes HTTP round-trips. A receipt is read once at
//! the end of a run, not on every poll.
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

/// The canonical door: `GET /v1/traces/receipt?agent_id_hash=…[&trace_id=…]`.
pub const RECEIPT_ROUTE: &str = "/v1/traces/receipt";

/// The producer door on the operator surface (owner-gated, see
/// [`crate::operator_surface`]).
pub const PRODUCER_ROUTE: &str = "/v1/node/delivery-receipt";

/// The read-API port a canonical is assumed to answer on when its record
/// advertises only a Reticulum `ip` hint. The default `:4243` every node binds
/// (see `compose`); override per canonical with
/// [`crate::config_reconcile::KEY_CANONICAL_READ_URLS`].
pub const READ_API_PORT: u16 = 4243;

/// Per-request timeout on one ask.
pub const ASK_TIMEOUT: Duration = Duration::from_secs(3);

/// The deadline for EVERYTHING one canonical is asked, however many agents
/// this node authored for. A canonical that accepts connections and answers
/// slowly cannot hold the caller for `agents × ASK_TIMEOUT`.
pub const CANONICAL_DEADLINE: Duration = Duration::from_secs(6);

/// The label the canonical signs its receipts under ([`crate::sign_object`]).
pub const SIGN_LABEL: &str = "trace-receipt";

/// How many local summaries the producer pages to discover its agent hashes.
/// Counts are exact regardless (`count_traces` per hash); this only bounds the
/// discovery read.
pub const LOCAL_WINDOW: i64 = 5_000;

/// The newest trace held for an agent — enough to recognise "the one I just
/// sent", nothing of its content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Newest {
    pub trace_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

/// What a canonical asserts about one agent's traces. This struct's
/// `serde_json` bytes are what the canonical signs and what the producer
/// re-derives to verify — see [`receipt_bytes`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    pub agent_id_hash: String,
    /// Distinct traces held for this agent.
    pub traces: i64,
    /// `None` when the canonical holds none — and, on the producer side, the
    /// reader must keep that apart from "could not ask".
    pub newest: Option<Newest>,
    /// The `trace_id` the asker named, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked_trace_id: Option<String>,
    /// Whether that trace is held FOR THIS AGENT. `None` when none was asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holds_trace: Option<bool>,
    pub read_at: DateTime<Utc>,
}

/// The bytes a receipt is signed over: its own `serde_json` encoding. Both
/// sides compute this from the same struct, so the producer re-derives the
/// canonical's bytes from the parsed `data` without a canonicalizer.
pub fn receipt_bytes(r: &Receipt) -> Vec<u8> {
    serde_json::to_vec(r).expect("a Receipt serializes")
}

/// One agent's receipt from THIS engine's store.
pub async fn receipt_for(
    engine: &Engine,
    agent_id_hash: &str,
    trace_id: Option<&str>,
) -> Result<Receipt, String> {
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
    let holds_trace = match trace_id {
        None => None,
        Some(id) => {
            let held = crate::backend::get_trace_summary(engine, id, CallerScope::Unauthenticated)
                .await
                .map_err(|e| format!("look up trace {id}: {e}"))?;
            // Held FOR THIS AGENT: a trace id is producer-chosen, and a row
            // under the same id from another agent is not this agent's.
            Some(held.is_some_and(|s| s.agent_id_hash == agent_id_hash))
        }
    };
    Ok(Receipt {
        agent_id_hash: agent_id_hash.to_string(),
        traces,
        newest,
        asked_trace_id: trace_id.map(str::to_string),
        holds_trace,
        read_at: Utc::now(),
    })
}

#[derive(Deserialize)]
struct ReceiptQuery {
    agent_id_hash: Option<String>,
    trace_id: Option<String>,
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
    let trace_id = q
        .trace_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let receipt = match receipt_for(&engine, hash, trace_id).await {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": e }))).into_response()
        }
    };
    // Signed by this node's hybrid key. A receipt that cannot be signed is not
    // served unsigned: the producer would have to either trust it or discard
    // it, and "trust it" is what an intermediary wants.
    let signature =
        match crate::sign_object::sign_object_bytes(&engine, &receipt_bytes(&receipt), SIGN_LABEL)
            .await
        {
            Ok(doc) => doc,
            Err(e) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": format!("sign the receipt: {e:#}") })),
                )
                    .into_response()
            }
        };
    (
        StatusCode::OK,
        Json(json!({ "data": receipt, "signature": signature })),
    )
        .into_response()
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
    /// `config` entries carry none. When known, the receipt's signer MUST be
    /// this key — any other registered key signing "as the canonical" is a
    /// forgery, not a receipt.
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

/// Which agents this node authored for, with exact counts.
///
/// `only`: the caller names its agent hash and discovery is skipped — the
/// embedded agent knows its own. Otherwise discovery keeps summaries whose
/// signing key is THIS process's own federation key; rows replicated from
/// peers, and everyone's rows on a canonical asking itself, are not "authored
/// here" however many of them the store holds.
pub async fn authored_here(engine: &Engine, only: Option<&str>) -> Result<Vec<Authored>, String> {
    let mut hashes: Vec<String> = Vec::new();
    let mut newest: std::collections::BTreeMap<String, Newest> = Default::default();
    match only.map(str::trim).filter(|s| !s.is_empty()) {
        Some(h) => hashes.push(h.to_string()),
        None => {
            let own_key = engine
                .local_derived_key_id()
                .await
                .map_err(|e| format!("this node's own key id: {e}"))?;
            let page = crate::backend::list_trace_summaries(
                engine,
                TraceFilter::default(),
                None,
                LOCAL_WINDOW,
                CallerScope::Unauthenticated,
            )
            .await
            .map_err(|e| format!("list local traces: {e}"))?;
            for s in page
                .items
                .iter()
                .filter(|s| s.agent_key_id.as_deref() == Some(own_key.as_str()))
            {
                if !hashes.contains(&s.agent_id_hash) {
                    hashes.push(s.agent_id_hash.clone());
                }
            }
        }
    }
    let mut out = Vec::with_capacity(hashes.len());
    for hash in hashes {
        let filter = TraceFilter {
            agent_id_hash: Some(hash.clone()),
            ..TraceFilter::default()
        };
        let authored =
            crate::backend::count_traces(engine, filter.clone(), CallerScope::Unauthenticated)
                .await
                .map_err(|e| format!("count local traces for {hash}: {e}"))?;
        // Newest-first page of one, filtered to the hash — the same read the
        // canonical makes, so the two `newest` values are comparable.
        let page = crate::backend::list_trace_summaries(
            engine,
            filter,
            None,
            1,
            CallerScope::Unauthenticated,
        )
        .await
        .map_err(|e| format!("newest local trace for {hash}: {e}"))?;
        if let Some(s) = page.items.first() {
            newest.insert(
                hash.clone(),
                Newest {
                    trace_id: s.trace_id.clone(),
                    started_at: s.started_at,
                    completed_at: s.completed_at,
                },
            );
        }
        out.push(Authored {
            newest_authored: newest.remove(&hash),
            agent_id_hash: hash,
            authored,
        });
    }
    Ok(out)
}

/// How one canonical's answer for one agent checked out.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    /// Signature verifies against the named key's registered pubkeys, and the
    /// key is the canonical's when the canonical is named.
    Verified,
    /// The signature did not verify, or a key other than the canonical's
    /// signed it. The numbers were discarded.
    Failed,
    /// The check could not be performed (no signature document, signer not in
    /// this node's directory, …). Distinct from `failed`: not proof of
    /// forgery, not proof of anything.
    Unavailable,
}

/// One ask, verified. `Err` carries why the numbers are NOT to be used.
async fn ask(
    engine: &Engine,
    client: &reqwest::Client,
    c: &CanonicalRead,
    agent_id_hash: &str,
    trace_id: Option<&str>,
) -> Result<(Receipt, String), (Verification, String)> {
    let url = format!("{}{RECEIPT_ROUTE}", c.url);
    let mut query: Vec<(&str, &str)> = vec![("agent_id_hash", agent_id_hash)];
    if let Some(id) = trace_id {
        query.push(("trace_id", id));
    }
    let resp = client
        .get(&url)
        .query(&query)
        .send()
        .await
        .map_err(|e| (Verification::Unavailable, format!("{url}: {e}")))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| (Verification::Unavailable, format!("{url}: read body: {e}")))?;
    if !status.is_success() {
        return Err((
            Verification::Unavailable,
            format!(
                "{url}: HTTP {status}: {}",
                body.chars().take(200).collect::<String>()
            ),
        ));
    }
    let v: Value = serde_json::from_str(&body)
        .map_err(|e| (Verification::Unavailable, format!("{url}: not JSON: {e}")))?;
    let receipt: Receipt = serde_json::from_value(v.get("data").cloned().unwrap_or(Value::Null))
        .map_err(|e| {
            (
                Verification::Unavailable,
                format!("{url}: not a receipt: {e}"),
            )
        })?;
    let Some(doc) = v.get("signature").filter(|d| d.is_object()) else {
        return Err((
            Verification::Unavailable,
            format!("{url}: the receipt carries no signature — numbers discarded"),
        ));
    };
    // `sign_object` names the signer inside its manifest — the part the
    // signature covers — not beside it.
    let signer = doc
        .pointer("/manifest/signer_key_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if let Some(expected) = c.key_id.as_deref() {
        if signer != expected {
            return Err((
                Verification::Failed,
                format!(
                    "{url}: receipt signed by `{signer}`, but this canonical is `{expected}` — \
                     not its receipt"
                ),
            ));
        }
    }
    match crate::sign_object::verify_object_bytes(engine, &receipt_bytes(&receipt), doc).await {
        Ok(true) => Ok((receipt, signer)),
        Ok(false) => Err((
            Verification::Failed,
            format!(
                "{url}: receipt signature does not verify against `{signer}`'s registered keys"
            ),
        )),
        Err(e) => Err((
            Verification::Unavailable,
            format!("{url}: could not verify the receipt (signer `{signer}`): {e:#}"),
        )),
    }
}

/// The producer's receipt: what this node authored, per agent, against what
/// each canonical says — and signs — it holds. One function behind two doors.
///
/// Every number that could not be read OR could not be verified is `null`,
/// never `0`. An unreachable canonical is `reachable: false` with the URL it
/// tried and the error; a canonical whose receipt did not verify is
/// `reachable: true, verification: failed` with `held` absent.
pub async fn delivery_receipt(
    engine: &Engine,
    canonicals: Vec<CanonicalRead>,
    only_agent_id_hash: Option<&str>,
) -> Value {
    let read_at = Utc::now();
    let agents = match authored_here(engine, only_agent_id_hash).await {
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
    let mut answered = 0usize;
    let mut unreachable = 0usize;
    // Over canonicals that ANSWERED with a verified receipt: is every agent's
    // newest trace held there?
    let mut newest_held_everywhere_answered = true;
    let mut worst_gap: i64 = 0;
    for c in &canonicals {
        let Some(client) = client.as_ref() else {
            unreachable += 1;
            canonical_views.push(json!({
                "key_id": c.key_id, "url": c.url, "url_source": c.url_source,
                "reachable": false, "error": "http client could not be built",
            }));
            continue;
        };
        // One deadline for the whole canonical, asks in flight together.
        let asks = agents.iter().map(|a| {
            ask(
                engine,
                client,
                c,
                &a.agent_id_hash,
                a.newest_authored.as_ref().map(|n| n.trace_id.as_str()),
            )
        });
        let results: Option<Vec<_>> =
            tokio::time::timeout(CANONICAL_DEADLINE, futures_util::future::join_all(asks))
                .await
                .ok();
        let Some(results) = results else {
            unreachable += 1;
            canonical_views.push(json!({
                "key_id": c.key_id, "url": c.url, "url_source": c.url_source,
                "reachable": false,
                "error": format!("no complete answer within {} s", CANONICAL_DEADLINE.as_secs()),
                "agents": agents.iter().map(|a| json!({
                    "agent_id_hash": a.agent_id_hash, "authored": a.authored,
                    "newest_authored": a.newest_authored,
                })).collect::<Vec<_>>(),
            }));
            continue;
        };

        let mut per_agent = Vec::with_capacity(agents.len());
        let mut reachable = true;
        let mut any_verified = false;
        let mut first_error: Option<String> = None;
        let mut signer: Option<String> = None;
        for (a, r) in agents.iter().zip(results) {
            match r {
                Ok((rcpt, who)) => {
                    any_verified = true;
                    signer.get_or_insert(who);
                    let gap = (a.authored - rcpt.traces).max(0);
                    worst_gap = worst_gap.max(gap);
                    // THE answer: is the newest thing we made there. A node with
                    // nothing authored has nothing to deliver, which is not a
                    // failure to deliver.
                    let newest_held = match (&a.newest_authored, rcpt.holds_trace) {
                        (None, _) => None,
                        (Some(_), held) => Some(held.unwrap_or(false)),
                    };
                    if newest_held == Some(false) {
                        newest_held_everywhere_answered = false;
                    }
                    per_agent.push(json!({
                        "agent_id_hash": a.agent_id_hash,
                        "verification": Verification::Verified,
                        "authored": a.authored,
                        "held": rcpt.traces,
                        // Context, not verdict: retention here or history there
                        // makes counts disagree for benign reasons.
                        "count_gap": gap,
                        "shipped_any": rcpt.traces > 0,
                        "newest_authored": a.newest_authored,
                        "newest_authored_held": newest_held,
                        "newest_held": rcpt.newest,
                        "newest_matches": a.newest_authored.as_ref().map(|n| Some(n) == rcpt.newest.as_ref()),
                    }));
                }
                Err((verification, e)) => {
                    if verification == Verification::Unavailable
                        && e.contains(": error sending request")
                    {
                        reachable = false;
                    }
                    first_error.get_or_insert(e);
                    per_agent.push(json!({
                        "agent_id_hash": a.agent_id_hash,
                        "verification": verification,
                        "authored": a.authored,
                        "held": Value::Null,
                        "count_gap": Value::Null,
                        "shipped_any": Value::Null,
                        "newest_authored": a.newest_authored,
                        "newest_authored_held": Value::Null,
                    }));
                }
            }
        }
        if agents.is_empty() {
            // Nothing to ask about — probe once so the URL guess is still
            // verified, and so a canonical whose receipts do not verify is
            // reported even before anything is authored.
            match ask(engine, client, c, "probe", None).await {
                Ok((_, who)) => {
                    any_verified = true;
                    signer = Some(who);
                }
                Err((_, e)) => {
                    reachable = !e.contains(": error sending request");
                    first_error = Some(e);
                }
            }
        }
        if !reachable {
            unreachable += 1;
        } else if any_verified {
            answered += 1;
        } else {
            // Reachable, but nothing it said could be used.
            newest_held_everywhere_answered = false;
        }
        canonical_views.push(json!({
            "key_id": c.key_id,
            "url": c.url,
            "url_source": c.url_source,
            "reachable": reachable,
            "signer_key_id": signer,
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
    } else if answered == 0 {
        "no canonical answered with a receipt this node could verify: `held` is UNKNOWN \
         for every one of them, not zero. Each `canonicals[].error` says which — \
         unreachable (the URL was asked at is there, with how it was chosen; a derived \
         one may be wrong — set `federation.canonical_read_urls`), or a receipt that \
         could not be verified against this node's directory."
            .to_string()
    } else if authored_total == 0 {
        "this node has authored no traces yet — a canonical answered, so the path is \
         open, but there is nothing to deliver. Emit first, then re-read."
            .to_string()
    } else if newest_held_everywhere_answered {
        let tail = if unreachable > 0 {
            format!(" ({unreachable} canonical(s) did not answer and are not counted.)")
        } else {
            String::new()
        };
        format!(
            "the newest trace this node authored is held by every canonical that \
             answered — the plane delivered.{tail}"
        )
    } else {
        format!(
            "a canonical that answered does NOT hold the newest trace this node authored \
             (`newest_authored_held: false`). `shipped_any: true` there means the plane has \
             worked before and is behind — a round has not run since the newest row was \
             sealed; `shipped_any: false` means NOTHING from this agent has ever landed there — \
             read `delivery_status().trace_plane.hint` and `round_diagnostics` for which gate. \
             (`count_gap` up to {worst_gap} is context: counts disagree for benign reasons.)"
        )
    };

    json!({
        "read_at": read_at,
        "authored_as": only_agent_id_hash.map(|h| json!({ "agent_id_hash": h })).unwrap_or(json!({ "signing_key": "this node's own federation key" })),
        "agents": agents,
        "canonicals": canonical_views,
        "verdict": {
            "canonicals_answered": answered,
            "canonicals_unreachable": unreachable,
            "newest_authored_held_by_every_answering_canonical": if answered > 0 && authored_total > 0 { Value::Bool(newest_held_everywhere_answered) } else { Value::Null },
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

    /// The producer verifies the canonical's signature over bytes it RE-DERIVES
    /// from the parsed `data`. That only works if serialize → parse →
    /// serialize is byte-identical, nanosecond timestamps included.
    #[test]
    fn receipt_bytes_survive_a_wire_round_trip() {
        let r = Receipt {
            agent_id_hash: "h".into(),
            traces: 3,
            newest: Some(Newest {
                trace_id: "t".into(),
                started_at: DateTime::parse_from_rfc3339("2026-09-14T14:05:04.123456789Z")
                    .unwrap()
                    .with_timezone(&Utc),
                completed_at: DateTime::parse_from_rfc3339("2026-09-14T14:05:04.100000000Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }),
            asked_trace_id: Some("t".into()),
            holds_trace: Some(true),
            read_at: Utc::now(),
        };
        let wire: Value = serde_json::from_slice(&receipt_bytes(&r)).unwrap();
        let back: Receipt = serde_json::from_value(wire).unwrap();
        assert_eq!(back, r);
        assert_eq!(receipt_bytes(&back), receipt_bytes(&r));
    }
}
