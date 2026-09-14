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
//! the one you name — and this is my answer to YOUR question.* This module is
//! that statement, on both sides:
//!
//!   * **Canonical door** — [`router`] serves [`RECEIPT_ROUTE`]
//!     (`GET /v1/traces/receipt?agent_id_hash=…[&trace_id=…][&nonce=…]`): count
//!     and newest trace for one agent, whether one named trace is held, and the
//!     asker's nonce, index-served by persist's `trace_events_agenthash_ts`. No
//!     payloads, no components. Unauthenticated on purpose: a producer proving
//!     its own delivery holds no credential on the canonical, and the mesh
//!     already replicates these rows to every consented peer. The RESPONSE is
//!     signed with the canonical's hybrid node key ([`crate::sign_object`]),
//!     because the default path to a canonical is plain `http://` to a public
//!     address and an unsigned receipt is one an intermediary could write.
//!   * **Producer door** — [`delivery_receipt`] counts what this node authored
//!     per agent, asks each canonical for the same hashes AND for the newest
//!     trace by id, verifies each answer against the canonical's REGISTERED
//!     pubkeys in this node's own directory (the baked record), checks that the
//!     signed answer is the answer to the question it asked, and reports per
//!     pair whether the newest authored trace is held. Two front doors, one
//!     function: `ciris_server.delivery_receipt(agent_id_hash=None)` in-process
//!     for the embedded agent (the door its QA runner already uses for
//!     `delivery_status()`), and `GET /v1/node/delivery-receipt[?agent_id_hash=]`
//!     (owner-gated, on the operator surface) for a compose node.
//!
//! **A receipt is bound to its request.** The signature proves the canonical
//! said it; it does not by itself prove it said it *now, to this question*.
//! An on-path party holding a valid signed receipt for another agent, another
//! trace, or last week could replay it (Codex, PR #592, round 2). So the
//! producer sends a fresh nonce per ask, the canonical echoes it INSIDE the
//! signed receipt, and the producer accepts only a receipt whose signed
//! `agent_id_hash`, `asked_trace_id` and `nonce` are exactly what it asked, and
//! whose `read_at` is within [`MAX_RECEIPT_AGE`] of its own clock.
//!
//! **Delivery is a fact about identity, not cardinality.** `held >= authored`
//! proves nothing when local retention has pruned rows or the canonical holds
//! history from before this run. The verdict is therefore "the newest trace
//! this node authored is held by the canonical", asked by `trace_id`; the
//! counts are reported beside it as context, never as the answer.
//!
//! **"Authored here" is a fact about the signer, not the store.** A node holds
//! traces it replicated from peers too, and a canonical asking itself holds
//! everyone's. Discovery pages the corpus (newest first, cursor-paged, up to
//! [`DISCOVERY_MAX_ROWS`]) and keeps only summaries whose signing key is THIS
//! process's own federation key; if the cap is hit before the corpus ends the
//! receipt SAYS so rather than reporting "nothing authored". A caller that
//! knows its agent hash names it and skips discovery altogether.
//!
//! **A canonical is a key, not a URL.** Every ask names the key it expects to
//! sign the answer. Baked canonicals carry theirs; a configured entry is
//! `key_id=url` and a bare URL is refused, because "any registered key may
//! sign as this canonical" is not a canonical.
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

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use ciris_persist::prelude::{CallerScope, Engine, TraceFilter};

/// The canonical door: `GET /v1/traces/receipt?agent_id_hash=…[&trace_id=…][&nonce=…]`.
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

/// How many asks a producer keeps in flight per canonical. Discovery can name
/// thousands of agent hashes on a busy node; one request each, all at once,
/// is a connection flood against the canonical and a buffer flood here.
pub const MAX_INFLIGHT_ASKS: usize = 2;

/// How long the canonical door waits for a signing permit before answering
/// 429 — a legitimate burst of a few asks queues, a flood does not.
pub const PERMIT_WAIT: Duration = Duration::from_secs(2);

/// How many times one ask retries a 429, honouring `Retry-After`, inside
/// the canonical's deadline.
pub const MAX_429_RETRIES: usize = 3;

/// The most a receipt body may be. A receipt is a few hundred bytes plus a
/// signature document; anything larger is not one, and is not buffered.
pub const MAX_RECEIPT_BYTES: usize = 64 * 1024;

/// How old (or how far in the future) a receipt's `read_at` may be and still
/// be accepted. Belt beside the nonce's braces: the nonce defeats replay, this
/// bounds a canonical whose clock is wrong.
pub const MAX_RECEIPT_AGE: chrono::Duration = chrono::Duration::minutes(10);

/// The label the canonical signs its receipts under ([`crate::sign_object`]).
pub const SIGN_LABEL: &str = "trace-receipt";

/// Discovery keeps at most this many agent hashes: each costs one exact
/// count read, and a node that authored for thousands of agents would turn
/// the receipt into thousands of reads before a single canonical is asked.
/// Past the cap the receipt says `agents_truncated` and the verdict is
/// unknown.
pub const MAX_DISCOVERED_AGENTS: usize = 50;

/// Discovery pages this many summaries per read…
pub const DISCOVERY_PAGE: i64 = 1_000;
/// …and stops after this many rows in total, SAYING it stopped.
pub const DISCOVERY_MAX_ROWS: usize = 50_000;

/// The newest trace held for an agent — enough to recognise "the one I just
/// sent", nothing of its content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Newest {
    pub trace_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

/// What a canonical asserts about one agent's traces, in answer to one
/// question. This struct's `serde_json` bytes are what the canonical signs and
/// what the producer re-derives to verify — see [`receipt_bytes`].
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
    /// The asker's nonce, echoed — what binds this signed answer to that ask.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
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
    nonce: Option<&str>,
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
        nonce: nonce.map(str::to_string),
        read_at: Utc::now(),
    })
}

#[derive(Deserialize)]
struct ReceiptQuery {
    agent_id_hash: Option<String>,
    trace_id: Option<String>,
    nonce: Option<String>,
}

fn nonblank(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|s| !s.is_empty())
}

/// Admission for the canonical door. Receipts are credential-free by design,
/// and each one costs two indexed reads plus a hybrid signature (ML-DSA-65 is
/// not cheap), so the door is metered rather than open: at most
/// `max_inflight` signings at once, and a token bucket of `burst` refilled at
/// `per_second`. Over either, the answer is `429` with `Retry-After`, before
/// any read or signing happens. One gate per router, so a test's gate is its
/// own.
#[derive(Debug)]
pub struct ReceiptGate {
    inflight: tokio::sync::Semaphore,
    max_inflight: usize,
    bucket: Mutex<(f64, Instant)>,
    burst: f64,
    per_second: f64,
}

impl ReceiptGate {
    pub const DEFAULT_MAX_INFLIGHT: usize = 4;
    pub const DEFAULT_BURST: f64 = 30.0;
    pub const DEFAULT_PER_SECOND: f64 = 10.0;

    #[must_use]
    pub fn new(max_inflight: usize, burst: f64, per_second: f64) -> Self {
        Self {
            inflight: tokio::sync::Semaphore::new(max_inflight.max(1)),
            max_inflight: max_inflight.max(1),
            bucket: Mutex::new((burst, Instant::now())),
            burst,
            per_second,
        }
    }

    /// Take one token, or say how long until one exists.
    fn take_token(&self) -> Result<(), u64> {
        let mut b = self.bucket.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let refilled =
            (b.0 + now.duration_since(b.1).as_secs_f64() * self.per_second).min(self.burst);
        b.1 = now;
        if refilled >= 1.0 {
            b.0 = refilled - 1.0;
            Ok(())
        } else {
            b.0 = refilled;
            let wait = if self.per_second > 0.0 {
                ((1.0 - refilled) / self.per_second).ceil() as u64
            } else {
                60
            };
            Err(wait.max(1))
        }
    }
}

impl Default for ReceiptGate {
    fn default() -> Self {
        Self::new(
            Self::DEFAULT_MAX_INFLIGHT,
            Self::DEFAULT_BURST,
            Self::DEFAULT_PER_SECOND,
        )
    }
}

#[derive(Clone)]
struct DoorState {
    engine: Arc<Engine>,
    gate: Arc<ReceiptGate>,
}

fn too_many(retry_after_secs: u64, why: &str) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(
            axum::http::header::RETRY_AFTER,
            retry_after_secs.to_string(),
        )],
        Json(json!({ "error": why })),
    )
        .into_response()
}

async fn get_receipt(State(st): State<DoorState>, Query(q): Query<ReceiptQuery>) -> Response {
    // Metered before anything is read or signed.
    if let Err(wait) = st.gate.take_token() {
        return too_many(wait, "receipt rate limit — try again shortly");
    }
    // A permit, waited for briefly: a burst of a few asks queues behind the
    // signer; only a queue that does not drain inside PERMIT_WAIT is refused.
    let Ok(Ok(_permit)) = tokio::time::timeout(PERMIT_WAIT, st.gate.inflight.acquire()).await
    else {
        return too_many(
            1,
            &format!(
                "{} receipts are being signed right now — try again shortly",
                st.gate.max_inflight
            ),
        );
    };
    let engine = st.engine;
    let Some(hash) = nonblank(q.agent_id_hash.as_deref()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "`agent_id_hash` query parameter is required" })),
        )
            .into_response();
    };
    let nonce = nonblank(q.nonce.as_deref());
    if nonce.is_some_and(|n| n.len() > 128) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "`nonce` is limited to 128 characters" })),
        )
            .into_response();
    }
    let receipt = match receipt_for(&engine, hash, nonblank(q.trace_id.as_deref()), nonce).await {
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

/// The canonical door with the default gate. Merge into the node's public
/// router.
pub fn router(engine: Arc<Engine>) -> Router {
    router_with_gate(engine, Arc::new(ReceiptGate::default()))
}

/// The canonical door with an explicit gate — a test's own, or an operator's.
pub fn router_with_gate(engine: Arc<Engine>, gate: Arc<ReceiptGate>) -> Router {
    Router::new()
        .route(RECEIPT_ROUTE, axum::routing::get(get_receipt))
        .with_state(DoorState { engine, gate })
}

/// Where the producer will ask, whose signature it will accept, and how it
/// decided.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CanonicalRead {
    /// The canonical's federation `key_id`. The receipt's signer MUST be this
    /// key — any other registered key signing "as the canonical" is a forgery,
    /// not a receipt — which is why there is no way to name a URL without one.
    pub key_id: String,
    /// Base URL of the canonical's read API, no trailing slash.
    pub url: String,
    pub url_source: UrlSource,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UrlSource {
    /// From `federation.canonical_read_urls` (`key_id=url`).
    Config,
    /// From the baked record's `ip` hint, host kept, port replaced by
    /// [`READ_API_PORT`].
    DerivedFromIpHint,
    /// From a baked `http`/`https` hint, used as-is.
    HttpHint,
}

/// The canonicals this node will ask, and the config entries it would not.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct CanonicalRoster {
    pub reads: Vec<CanonicalRead>,
    /// Config entries refused, each with why — a bare URL with no key, most
    /// likely. Reported, never silently dropped.
    pub refused: Vec<String>,
}

/// One `federation.canonical_read_urls` entry: `key_id=url`.
pub fn parse_config_entry(entry: &str) -> Result<CanonicalRead, String> {
    let e = entry.trim();
    let Some((key, url)) = e.split_once('=') else {
        return Err(format!(
            "`{e}`: no key id — entries are `key_id=url`, because a URL alone says nothing \
             about whose signature to accept"
        ));
    };
    let key = key.trim();
    let url = url.trim().trim_end_matches('/');
    if key.is_empty() || url.is_empty() {
        return Err(format!("`{e}`: empty key id or url"));
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(format!("`{e}`: url must start with http:// or https://"));
    }
    Ok(CanonicalRead {
        key_id: key.to_string(),
        url: url.to_string(),
        url_source: UrlSource::Config,
    })
}

/// The canonicals this node will ask. Config first (`key_id=url` entries),
/// else the baked record's hints. `Err` when the directory could not be read
/// — which is not "no canonical", and the receipt keeps the two apart.
pub async fn canonical_reads(engine: &Arc<Engine>) -> Result<CanonicalRoster, String> {
    let mut roster = CanonicalRoster::default();
    match crate::graph_config::get_str_list(
        engine,
        crate::config_reconcile::KEY_CANONICAL_READ_URLS,
    )
    .await
    {
        Ok(Some(entries)) => {
            for e in entries.iter().filter(|e| !e.trim().is_empty()) {
                match parse_config_entry(e) {
                    // One read per canonical KEY: two URLs for one key would be
                    // two "canonicals" whose disagreement fails the verdict.
                    Ok(r) if roster.reads.iter().any(|x| x.key_id == r.key_id) => {
                        roster.refused.push(format!(
                            "`{}`: a second url for canonical `{}` — one read per canonical; the \
                             first entry wins",
                            e.trim(),
                            r.key_id
                        ))
                    }
                    Ok(r) => roster.reads.push(r),
                    Err(why) => roster.refused.push(why),
                }
            }
            if !roster.reads.is_empty() || !roster.refused.is_empty() {
                return Ok(roster);
            }
        }
        Ok(None) => {}
        Err(e) => {
            return Err(format!(
                "read config `federation.canonical_read_urls`: {e:#}"
            ))
        }
    }
    let hints = engine
        .canonical_bootstrap_hints()
        .await
        .map_err(|e| format!("read the baked canonical records: {e}"))?;
    roster.reads = roster_from_hints(hints);
    Ok(roster)
}

/// One read per canonical KEY from its transport hints: an explicit
/// `http`/`https` hint wins over a URL derived from an `ip` hint, and a second
/// usable hint for the same key is not a second canonical. A canonical that
/// advertises a stale endpoint beside a current one must not be able to fail
/// its own verdict by disagreeing with itself.
pub fn roster_from_hints(
    hints: Vec<(String, ciris_persist::federation::types::TransportHint)>,
) -> Vec<CanonicalRead> {
    let mut out: Vec<CanonicalRead> = Vec::new();
    for (key_id, hint) in hints {
        let read = match hint.kind.as_str() {
            "http" | "https" => CanonicalRead {
                key_id,
                url: hint.destination.trim_end_matches('/').to_string(),
                url_source: UrlSource::HttpHint,
            },
            "ip" => {
                let host = host_of(&hint.destination);
                CanonicalRead {
                    key_id,
                    url: format!("http://{host}:{READ_API_PORT}"),
                    url_source: UrlSource::DerivedFromIpHint,
                }
            }
            _ => continue,
        };
        match out.iter_mut().find(|r| r.key_id == read.key_id) {
            None => out.push(read),
            Some(existing) => {
                if existing.url_source == UrlSource::DerivedFromIpHint
                    && read.url_source == UrlSource::HttpHint
                {
                    *existing = read;
                }
            }
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

/// How discovery went — so "nothing authored" is never asserted by a scan
/// that stopped early.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Discovery {
    /// `explicit`: the caller named the hash, nothing was scanned.
    pub mode: &'static str,
    pub rows_scanned: usize,
    /// The scan hit [`DISCOVERY_MAX_ROWS`] before the corpus ended; locally
    /// authored rows older than that are not represented.
    pub truncated: bool,
    /// More than [`MAX_DISCOVERED_AGENTS`] hashes were found; only the newest
    /// are represented.
    pub agents_truncated: bool,
}

/// Which agents this node authored for, with exact counts.
///
/// `only`: the caller names its agent hash and discovery is skipped — the
/// embedded agent knows its own. Otherwise discovery pages the corpus
/// newest-first and keeps summaries whose signing key is THIS process's own
/// federation key; rows replicated from peers, and everyone's rows on a
/// canonical asking itself, are not "authored here" however many of them the
/// store holds.
pub async fn authored_here(
    engine: &Engine,
    only: Option<&str>,
) -> Result<(Vec<Authored>, Discovery), String> {
    authored_here_with(
        engine,
        only,
        DISCOVERY_PAGE,
        DISCOVERY_MAX_ROWS,
        MAX_DISCOVERED_AGENTS,
    )
    .await
}

/// [`authored_here`] with the page size and cap as parameters, so the paging
/// itself can be tested on a small corpus.
pub async fn authored_here_with(
    engine: &Engine,
    only: Option<&str>,
    page_size: i64,
    max_rows: usize,
    max_agents: usize,
) -> Result<(Vec<Authored>, Discovery), String> {
    let mut hashes: Vec<String> = Vec::new();
    // The newest row per hash, as seen during the newest-first scan: the
    // first sighting IS the newest, under the same ordering the canonical's
    // limit-1 read uses, so the two `newest` values stay comparable without
    // a second read per hash.
    let mut newest: std::collections::BTreeMap<String, Newest> = Default::default();
    let mut discovery = Discovery {
        mode: "explicit",
        rows_scanned: 0,
        truncated: false,
        agents_truncated: false,
    };
    match nonblank(only) {
        Some(h) => hashes.push(h.to_string()),
        None => {
            discovery.mode = "signing_key";
            let own_key = engine
                .local_derived_key_id()
                .await
                .map_err(|e| format!("this node's own key id: {e}"))?;
            let mut cursor = None;
            loop {
                let page = crate::backend::list_trace_summaries(
                    engine,
                    TraceFilter::default(),
                    cursor,
                    page_size,
                    CallerScope::Unauthenticated,
                )
                .await
                .map_err(|e| format!("list local traces: {e}"))?;
                discovery.rows_scanned += page.items.len();
                for s in page
                    .items
                    .iter()
                    .filter(|s| s.agent_key_id.as_deref() == Some(own_key.as_str()))
                {
                    if !hashes.contains(&s.agent_id_hash) {
                        if hashes.len() >= max_agents {
                            discovery.agents_truncated = true;
                            continue;
                        }
                        hashes.push(s.agent_id_hash.clone());
                        newest.insert(
                            s.agent_id_hash.clone(),
                            Newest {
                                trace_id: s.trace_id.clone(),
                                started_at: s.started_at,
                                completed_at: s.completed_at,
                            },
                        );
                    }
                }
                match page.next_cursor {
                    None => break,
                    Some(_) if discovery.rows_scanned >= max_rows => {
                        discovery.truncated = true;
                        break;
                    }
                    Some(c) => cursor = Some(c),
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
        // An explicitly named hash was not scanned: one newest-first read for
        // it — the same read the canonical makes, so the two `newest` values
        // are comparable. A discovered hash already has its newest from the
        // scan.
        let newest_authored = match newest.remove(&hash) {
            Some(n) => Some(n),
            None => {
                let page = crate::backend::list_trace_summaries(
                    engine,
                    filter,
                    None,
                    1,
                    CallerScope::Unauthenticated,
                )
                .await
                .map_err(|e| format!("newest local trace for {hash}: {e}"))?;
                page.items.first().map(|s| Newest {
                    trace_id: s.trace_id.clone(),
                    started_at: s.started_at,
                    completed_at: s.completed_at,
                })
            }
        };
        out.push(Authored {
            agent_id_hash: hash,
            authored,
            newest_authored,
        });
    }
    Ok((out, discovery))
}

/// How one canonical's answer for one agent checked out.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    /// Signature verifies against the canonical's registered pubkeys, the
    /// signer is the canonical, and the signed answer is the answer to THIS
    /// ask (agent, trace, nonce, fresh).
    Verified,
    /// The signature did not verify, another key signed it, or the signed
    /// answer is to a different question (replayed). The numbers were
    /// discarded.
    Failed,
    /// The check could not be performed (unreachable, no signature document,
    /// signer not in this node's directory, body too large, …). Distinct from
    /// `failed`: not proof of forgery, not proof of anything.
    Unavailable,
}

/// Read a body of at most [`MAX_RECEIPT_BYTES`], refusing a larger one before
/// buffering it — the size is checked as it arrives, not after.
async fn bounded_body(mut resp: reqwest::Response, url: &str) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length() {
        if len as usize > MAX_RECEIPT_BYTES {
            return Err(format!(
                "{url}: declared body of {len} bytes exceeds the {MAX_RECEIPT_BYTES}-byte receipt \
                 limit — not a receipt"
            ));
        }
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("{url}: read body: {e}"))?
    {
        if body.len() + chunk.len() > MAX_RECEIPT_BYTES {
            return Err(format!(
                "{url}: body exceeds the {MAX_RECEIPT_BYTES}-byte receipt limit — not a receipt"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// What one ask yields: the bound receipt, or why its numbers are not to be used.
pub type AskResult = Result<Receipt, (Verification, String)>;

/// Whether a statement by a key with this standing may be believed.
pub fn standing_permits(
    standing: ciris_persist::federation::register::KeyStatementStanding,
) -> Result<(), &'static str> {
    use ciris_persist::federation::register::KeyStatementStanding as S;
    match standing {
        S::Stands => Ok(()),
        S::SuspectAfterBound => Err("is revoked as of before this receipt was signed"),
        S::SuspectUnbounded => Err("is revoked without a bound: nothing it signed is believed"),
    }
}

/// One ask with 429s retried per `Retry-After` (bounded by
/// [`MAX_429_RETRIES`] and the caller's deadline): the door meters itself,
/// and a producer that treated "come back in a second" as "unavailable"
/// would grade a healthy canonical `partial`.
async fn ask(
    engine: &Engine,
    client: &reqwest::Client,
    c: &CanonicalRead,
    agent_id_hash: &str,
    trace_id: Option<&str>,
    deadline: tokio::time::Instant,
) -> AskResult {
    let mut attempt = 0usize;
    loop {
        match ask_once(engine, client, c, agent_id_hash, trace_id).await {
            Err((Verification::Unavailable, e))
                if e.contains(": HTTP 429") && attempt < MAX_429_RETRIES =>
            {
                attempt += 1;
                // The stated delay, or nothing: retrying EARLY is a guaranteed
                // second refusal, so a Retry-After that does not fit the
                // deadline ends the ask as unavailable instead.
                let wait = Duration::from_secs(
                    e.rsplit_once("retry-after=")
                        .and_then(|(_, t)| t.trim().parse::<u64>().ok())
                        .unwrap_or(1)
                        .max(1),
                );
                if tokio::time::Instant::now() + wait > deadline {
                    return Err((
                        Verification::Unavailable,
                        format!("{e} (Retry-After does not fit the canonical deadline)"),
                    ));
                }
                tokio::time::sleep(wait).await;
            }
            other => return other,
        }
    }
}

/// One ask, verified and bound. `Err` carries why the numbers are NOT to be
/// used; `Verification::Unavailable` with a transport error is how
/// "unreachable" is told apart from "answered badly".
async fn ask_once(
    engine: &Engine,
    client: &reqwest::Client,
    c: &CanonicalRead,
    agent_id_hash: &str,
    trace_id: Option<&str>,
) -> AskResult {
    let url = format!("{}{RECEIPT_ROUTE}", c.url);
    let nonce = crate::ids::new_id();
    // The instant THIS ask was made. The nonce proves the signature was
    // produced after it, so this — not the signer's own `read_at` — is the
    // instant the signer's standing is judged at.
    let asked_at = Utc::now();
    let mut query: Vec<(&str, &str)> = vec![("agent_id_hash", agent_id_hash), ("nonce", &nonce)];
    if let Some(id) = trace_id {
        query.push(("trace_id", id));
    }
    let resp = client.get(&url).query(&query).send().await.map_err(|e| {
        (
            Verification::Unavailable,
            format!("{url}: error sending request: {e}"),
        )
    })?;
    let status = resp.status();
    let retry_after = resp
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = bounded_body(resp, &url)
        .await
        .map_err(|e| (Verification::Unavailable, e))?;
    if !status.is_success() {
        let tail = retry_after
            .map(|r| format!(" retry-after={r}"))
            .unwrap_or_default();
        return Err((
            Verification::Unavailable,
            format!(
                "{url}: HTTP {status}: {}{tail}",
                String::from_utf8_lossy(&body)
                    .chars()
                    .take(200)
                    .collect::<String>()
            ),
        ));
    }
    let v: Value = serde_json::from_slice(&body)
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
        .unwrap_or_default();
    if signer != c.key_id {
        return Err((
            Verification::Failed,
            format!(
                "{url}: receipt signed by `{signer}`, but this canonical is `{}` — not its receipt",
                c.key_id
            ),
        ));
    }
    match crate::sign_object::verify_object_bytes(engine, &receipt_bytes(&receipt), doc).await {
        Ok(true) => {
            // The signature is mathematically the canonical's. Does the KEY
            // still stand at the instant it signed? A revoked canonical key
            // verifies just as well (Codex, PR #592, round 4); the standing
            // fold honours history-bounded revocations, so a receipt signed
            // before a bound still stands.
            match engine
                .resolve_key_statement_standing(signer, asked_at, Utc::now())
                .await
            {
                Ok(fold) => {
                    if let Err(why) = standing_permits(fold.standing) {
                        return Err((
                            Verification::Failed,
                            format!("{url}: signer `{signer}` {why} — receipt discarded"),
                        ));
                    }
                }
                Err(e) => {
                    return Err((
                        Verification::Unavailable,
                        format!("{url}: could not read signer `{signer}`'s standing: {e}"),
                    ))
                }
            }
        }
        Ok(false) => {
            return Err((
                Verification::Failed,
                format!(
                    "{url}: receipt signature does not verify against `{signer}`'s registered keys"
                ),
            ))
        }
        Err(e) => {
            return Err((
                Verification::Unavailable,
                format!("{url}: could not verify the receipt (signer `{signer}`): {e:#}"),
            ))
        }
    }
    // Signed, by the right key — now: is it the answer to THIS question?
    if receipt.agent_id_hash != agent_id_hash
        || receipt.asked_trace_id.as_deref() != trace_id
        || receipt.nonce.as_deref() != Some(nonce.as_str())
    {
        return Err((
            Verification::Failed,
            format!(
                "{url}: a valid receipt, but not for this ask (agent `{}`, trace {:?}, nonce echoed: \
                 {}) — replayed",
                receipt.agent_id_hash,
                receipt.asked_trace_id,
                receipt.nonce.as_deref() == Some(nonce.as_str())
            ),
        ));
    }
    let age = Utc::now().signed_duration_since(receipt.read_at);
    if age > MAX_RECEIPT_AGE || age < -MAX_RECEIPT_AGE {
        return Err((
            Verification::Failed,
            format!(
                "{url}: receipt read_at {} is {} s from this node's clock — outside the {} s window",
                receipt.read_at,
                age.num_seconds(),
                MAX_RECEIPT_AGE.num_seconds()
            ),
        ));
    }
    Ok(receipt)
}

/// The producer's receipt: what this node authored, per agent, against what
/// each canonical says — and signs — it holds. One function behind two doors.
///
/// Every number that could not be read OR could not be verified is `null`,
/// never `0`. An unreachable canonical is `reachable: false` with the URL it
/// tried and the error; a canonical whose receipt did not verify is
/// `reachable: true, verification: failed` with `held` absent; and neither
/// moves the verdict, which ranges over canonicals that ANSWERED with a
/// verified, bound receipt.
pub async fn delivery_receipt(
    engine: &Engine,
    roster: Result<CanonicalRoster, String>,
    only_agent_id_hash: Option<&str>,
) -> Value {
    delivery_receipt_with(
        engine,
        roster,
        only_agent_id_hash,
        DISCOVERY_PAGE,
        DISCOVERY_MAX_ROWS,
        MAX_DISCOVERED_AGENTS,
        CANONICAL_DEADLINE,
    )
    .await
}

/// How one canonical stood at the end of its asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalStanding {
    /// A verified, bound receipt for EVERY authored agent. Only these move
    /// the verdict.
    Answered,
    /// Verified for some agents, not for others. Something is unknown, so
    /// the verdict cannot be "delivered" — it is unknown.
    Partial,
    /// Reachable, nothing usable.
    Unverified,
    /// Did not answer.
    Unreachable,
}

/// Fold one canonical's per-agent outcomes into its standing.
pub fn standing_of(verified: usize, total: usize, reachable: bool) -> CanonicalStanding {
    // Some verified and some not is PARTIAL whatever the failure was — a
    // connection error on one agent must not relabel a canonical that
    // answered for another as "unreachable" and drop the unknown (Codex,
    // PR #592, round 4).
    match verified {
        n if n > 0 && n == total => CanonicalStanding::Answered,
        n if n > 0 => CanonicalStanding::Partial,
        _ if reachable => CanonicalStanding::Unverified,
        _ => CanonicalStanding::Unreachable,
    }
}

/// [`delivery_receipt`] with discovery's page size and cap as parameters.
pub async fn delivery_receipt_with(
    engine: &Engine,
    roster: Result<CanonicalRoster, String>,
    only_agent_id_hash: Option<&str>,
    page_size: i64,
    max_rows: usize,
    max_agents: usize,
    canonical_deadline: Duration,
) -> Value {
    let read_at = Utc::now();
    let (agents, discovery) = match authored_here_with(
        engine,
        only_agent_id_hash,
        page_size,
        max_rows,
        max_agents,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            return json!({
                "read_at": read_at,
                "error": e,
                "hint": "this node's own trace store could not be read — nothing to receipt against",
            })
        }
    };
    let (canonicals, roster_error, refused) = match roster {
        Ok(r) => (r.reads, None, r.refused),
        Err(e) => (Vec::new(), Some(e), Vec::new()),
    };
    let client = reqwest::Client::builder().timeout(ASK_TIMEOUT).build().ok();

    let mut canonical_views = Vec::with_capacity(canonicals.len());
    let mut answered = 0usize;
    let mut partial = 0usize;
    let mut unverified = 0usize;
    let mut unreachable = 0usize;
    // Over canonicals that ANSWERED with a verified receipt: is every agent's
    // newest trace held there? Untouched by anything else.
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
        // The asks — or, on a node that authored nothing, one probe, so the
        // URL guess is still verified and a canonical whose receipts do not
        // verify is reported before anything is authored. The probe runs
        // INSIDE the deadline like any ask.
        let deadline = tokio::time::Instant::now() + canonical_deadline;
        let probe_only = agents.is_empty();
        let asks: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = AskResult> + Send + '_>>> =
            if probe_only {
                vec![Box::pin(ask(engine, client, c, "probe", None, deadline))]
            } else {
                agents
                    .iter()
                    .map(|a| {
                        Box::pin(ask(
                            engine,
                            client,
                            c,
                            &a.agent_id_hash,
                            a.newest_authored.as_ref().map(|n| n.trace_id.as_str()),
                            deadline,
                        ))
                            as std::pin::Pin<
                                Box<dyn std::future::Future<Output = AskResult> + Send + '_>,
                            >
                    })
                    .collect()
            };
        let total = asks.len();
        // At most MAX_INFLIGHT_ASKS in flight, results in order, and the
        // deadline cuts the STREAM, not the collected results: an agent
        // verified before it stays verified, the rest read unavailable, and
        // the standing fold sees both (Codex, PR #592, round 5).
        let mut results: Vec<AskResult> = Vec::with_capacity(total);
        {
            use futures_util::StreamExt as _;
            let mut stream = futures_util::stream::iter(asks).buffered(MAX_INFLIGHT_ASKS);
            loop {
                match tokio::time::timeout_at(deadline, stream.next()).await {
                    Ok(Some(r)) => results.push(r),
                    Ok(None) => break,
                    Err(_) => {
                        while results.len() < total {
                            results.push(Err((
                                Verification::Unavailable,
                                format!(
                                    "no answer within the {} s canonical deadline",
                                    canonical_deadline.as_secs()
                                ),
                            )));
                        }
                        break;
                    }
                }
            }
        }

        let mut per_agent = Vec::with_capacity(agents.len());
        let mut reachable = true;
        let mut verified = 0usize;
        let mut first_error: Option<String> = None;
        for (i, r) in results.into_iter().enumerate() {
            let a = if probe_only { None } else { agents.get(i) };
            match r {
                Ok(rcpt) => {
                    verified += 1;
                    let Some(a) = a else { continue };
                    let gap = (a.authored - rcpt.traces).max(0);
                    worst_gap = worst_gap.max(gap);
                    // THE answer: is the newest thing we made there. A node with
                    // nothing authored has nothing to deliver, which is not a
                    // failure to deliver.
                    let newest_held = a
                        .newest_authored
                        .as_ref()
                        .map(|_| rcpt.holds_trace.unwrap_or(false));
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
                    if e.contains(": error sending request") {
                        reachable = false;
                    }
                    first_error.get_or_insert(e);
                    let Some(a) = a else { continue };
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
        // A canonical ANSWERED only if every ask verified. One verified beside
        // one unknown is not "answered": the verdict would be true over an
        // unknown (Codex, PR #592, rounds 3–5).
        let standing = standing_of(verified, total, reachable);
        match standing {
            CanonicalStanding::Answered => answered += 1,
            CanonicalStanding::Partial => partial += 1,
            CanonicalStanding::Unverified => unverified += 1,
            CanonicalStanding::Unreachable => unreachable += 1,
        }
        canonical_views.push(json!({
            "key_id": c.key_id,
            "url": c.url,
            "url_source": c.url_source,
            "reachable": reachable,
            "standing": standing,
            "error": first_error,
            "agents": per_agent,
        }));
    }

    let authored_total: i64 = agents.iter().map(|a| a.authored).sum();
    // Discovery that stopped early may have missed agents this node authored
    // for; a verdict over the visible subset is not a verdict. Explicit hashes
    // are never truncated.
    let discovery_incomplete =
        (discovery.truncated || discovery.agents_truncated) && discovery.mode == "signing_key";
    // A count without a newest identity (retention took the last row between
    // the two reads) leaves nothing to ask the canonical about by id, and a
    // verdict on the count alone is the round-1 mistake again.
    let identity_unavailable = agents
        .iter()
        .any(|a| a.authored > 0 && a.newest_authored.is_none());
    let verdict_known = answered > 0
        && authored_total > 0
        && partial == 0
        && !discovery_incomplete
        && !identity_unavailable;
    let not_counted = |n: usize, what: &str| -> String {
        if n > 0 {
            format!(" {n} canonical(s) {what} and are not counted.")
        } else {
            String::new()
        }
    };
    let hint = if let Some(e) = &roster_error {
        format!(
            "the canonical roster could not be read ({e}) — this is a STORE fault, not a missing \
             configuration; nothing was asked."
        )
    } else if canonicals.is_empty() && !refused.is_empty() {
        "every `federation.canonical_read_urls` entry was refused (see `canonical_roster.refused`): \
         entries are `key_id=url`, because a URL alone says nothing about whose signature to \
         accept. Nothing was asked."
            .to_string()
    } else if canonicals.is_empty() {
        "no canonical read URL: the baked record carries no transport hint and \
         `federation.canonical_read_urls` is unset — there is nothing to ask. Set the \
         config key (`key_id=http://host:4243`)."
            .to_string()
    } else if answered == 0 {
        format!(
            "no canonical answered with a receipt this node could verify: `held` is UNKNOWN for \
             every one of them, not zero. Each `canonicals[].error` says which — unreachable (the \
             URL asked is there, with how it was chosen; a derived one may be wrong — set \
             `federation.canonical_read_urls`), or a receipt that could not be verified against \
             this node's directory.{}{}",
            not_counted(unreachable, "were unreachable"),
            not_counted(unverified, "answered but could not be verified")
        )
    } else if discovery_incomplete {
        format!(
            "discovery stopped early ({} rows scanned{}), so agents this node authored for may \
             be missing from the receipt — the verdict is UNKNOWN, not a pass. Name the agent \
             hash (`agent_id_hash=`) to skip discovery.",
            discovery.rows_scanned,
            if discovery.agents_truncated {
                format!(", more than {MAX_DISCOVERED_AGENTS} agents found")
            } else {
                String::new()
            }
        )
    } else if identity_unavailable {
        "an agent has a positive authored count but no newest trace to name — the local rows \
         moved between two reads (retention) — so nothing was asked by id and the verdict is \
         UNKNOWN. Re-read."
            .to_string()
    } else if partial > 0 {
        format!(
            "{partial} canonical(s) answered for SOME agents and not others (`standing: partial`): \
             one verified receipt beside one that could not be verified is an unknown, so the \
             verdict is UNKNOWN. Read `canonicals[].agents[].verification` for which ask failed \
             and why."
        )
    } else if authored_total == 0 {
        let scan = if discovery.truncated {
            format!(
                " NOTE: discovery stopped after {} rows without reaching the end of the corpus — \
                 rows this node authored may be older than that; name the agent hash to skip \
                 discovery.",
                discovery.rows_scanned
            )
        } else {
            String::new()
        };
        format!(
            "this node has authored no traces yet — a canonical answered, so the path is open, \
             but there is nothing to deliver. Emit first, then re-read.{scan}"
        )
    } else if newest_held_everywhere_answered {
        format!(
            "the newest trace this node authored is held by every canonical that answered — the \
             plane delivered.{}{}",
            not_counted(unreachable, "did not answer"),
            not_counted(unverified, "answered but could not be verified")
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
        "discovery": discovery,
        "agents": agents,
        "canonical_roster": { "error": roster_error, "refused": refused },
        "canonicals": canonical_views,
        "verdict": {
            "canonicals_answered": answered,
            "canonicals_partial": partial,
            "canonicals_unverified": unverified,
            "canonicals_unreachable": unreachable,
            "discovery_incomplete": discovery_incomplete,
            "identity_unavailable": identity_unavailable,
            "newest_authored_held_by_every_answering_canonical": if verdict_known { Value::Bool(newest_held_everywhere_answered) } else { Value::Null },
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

    /// A configured canonical is a key AND a URL; a URL alone is refused.
    #[test]
    fn a_config_entry_names_the_key_or_is_refused() {
        let r = parse_config_entry(" ciris-canonical-1-abc = http://10.0.0.5:4243/ ").unwrap();
        assert_eq!(r.key_id, "ciris-canonical-1-abc");
        assert_eq!(r.url, "http://10.0.0.5:4243");
        assert_eq!(r.url_source, UrlSource::Config);
        assert!(
            parse_config_entry("http://10.0.0.5:4243").is_err(),
            "no key"
        );
        assert!(parse_config_entry("k=").is_err());
        assert!(parse_config_entry("=http://x").is_err());
        assert!(parse_config_entry("k=ftp://x").is_err());
    }

    #[test]
    fn a_revoked_signer_is_refused_and_a_bounded_revocation_honours_its_bound() {
        use ciris_persist::federation::register::KeyStatementStanding as S;
        assert!(standing_permits(S::Stands).is_ok());
        assert!(standing_permits(S::SuspectAfterBound).is_err());
        assert!(standing_permits(S::SuspectUnbounded).is_err());
    }

    #[test]
    fn a_canonical_answered_only_when_every_agent_verified() {
        use CanonicalStanding::*;
        assert_eq!(standing_of(0, 2, false), Unreachable);
        assert_eq!(standing_of(0, 2, true), Unverified);
        assert_eq!(standing_of(1, 2, true), Partial);
        assert_eq!(
            standing_of(1, 2, false),
            Partial,
            "one verified, one connection error: partial, not unreachable"
        );
        assert_eq!(standing_of(2, 2, true), Answered);
        assert_eq!(standing_of(1, 1, true), Answered);
    }

    #[test]
    fn one_read_per_canonical_key_preferring_an_explicit_http_hint() {
        use ciris_persist::federation::types::TransportHint;
        let h = |kind: &str, dest: &str| TransportHint {
            kind: kind.into(),
            destination: dest.into(),
        };
        let reads = roster_from_hints(vec![
            ("c1".into(), h("ip", "10.0.0.5:4242")),
            ("c1".into(), h("https", "https://c1.example/")),
            ("c1".into(), h("ip", "10.0.0.6:4242")),
            ("c2".into(), h("reticulum", "abcd")),
            ("c2".into(), h("ip", "10.0.0.7:4242")),
        ]);
        assert_eq!(reads.len(), 2, "{reads:?}");
        assert_eq!(reads[0].key_id, "c1");
        assert_eq!(reads[0].url, "https://c1.example");
        assert_eq!(reads[0].url_source, UrlSource::HttpHint);
        assert_eq!(reads[1].key_id, "c2");
        assert_eq!(reads[1].url, "http://10.0.0.7:4243");
        assert_eq!(reads[1].url_source, UrlSource::DerivedFromIpHint);
    }

    /// The producer verifies the canonical's signature over bytes it RE-DERIVES
    /// from the parsed `data`. That only works if serialize → parse →
    /// serialize is byte-identical, nanosecond timestamps and nonce included.
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
            nonce: Some(crate::ids::new_id()),
            read_at: Utc::now(),
        };
        let wire: Value = serde_json::from_slice(&receipt_bytes(&r)).unwrap();
        let back: Receipt = serde_json::from_value(wire).unwrap();
        assert_eq!(back, r);
        assert_eq!(receipt_bytes(&back), receipt_bytes(&r));
    }
}
