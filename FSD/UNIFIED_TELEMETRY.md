# Unified telemetry — one model from leviculum to the agent

**Status:** accepted 2026-10-07 (decisions in §5).
**Owners:** server (host and exposure); persist, edge and leviculum (their own signals).
**Substrate at writing:** persist v53.1.7, edge v40.0.6, leviculum 0.27 (canonical) / 0.29 (edge main), verify v19.0.0. Agent `2e1eccf54`.

The maintainer, after the 0.5.222 OOM and the 0.5.223 link leak:

> Profile the usage carefully as needed, prioritize instrumentation, we need to
> get this behaviour fully understood before we can scale. Clearly we have a
> leak, and it will not be our last.

No new scale step (more agents, more canonicals, larger communities) until the
P0 and P1 items below are in production.

---

## 1. Why: what we could not see

The 0.5.222 OOM took about a day to explain, and the 0.5.223 link leak could not be
measured from outside the process at all, because **no layer could say, from
inside the process, what it was doing.**

| Incident | What answered it | What should have answered it |
|---|---|---|
| 0.5.222 OOM-loop on the canonical | A capped Docker harness on a prod copy, five runs; persist's out-of-tree counting-allocator binary; two never-merge diag-span builds; a failed heaptrack run (stripped wheel, no symbols) | A `rows_decoded`/`bytes_decoded` counter per persist read, a round-duration histogram, per-component memory, and a heap profile with symbols |
| Scorer +1.63 GB per pass | Persist's read probe, which exists but is `#[cfg(test)]` only | The same probe, always on, exported |
| Proactive push fetching the whole plane per round (edge v40.0.5) | Reading the code | A "fetched but not shipped" counter |
| Link leak, 1024 → 2048 links in 35 min (CIRISEdge#819) | A leviculum code read; the server's link count ships only in 0.5.224 | Live established links, per destination, with age and idle, plus pool size, all on `/metrics` |
| Boot phases 4–24 missing from logs | Noticing a gap | The log dedup layer counting what it suppresses, as a metric |

The common defect class: **"we couldn't see it."** It is a design defect, not
bad luck, and it will recur until the stack shares one telemetry model.

---

## 2. Where we are (surveyed 2026-10-07)

The premise was that instrumentation is ad hoc and driven by need. That holds in every repo.

### leviculum
- **Strongest discipline in the stack:** about 120 structured events in one
  `EVENT_CATALOG`, with a test that fails on any emitted event name not in the
  catalogue (`leviculum-std/src/event_log.rs:178`, `event_catalog_completeness.rs`).
- **Metrics:** six separate pull-only snapshot structs (`LinkStats`,
  `TransportStats` with about 21 drop reasons, `PlaneStats`, interface stats).
  There is no registry and no metrics crate.
- **Gaps:**
  - Two link counts that are never reconciled: the completion mirror versus the core table.
  - No API a host can call to list its links. `link_table_entries` exists but isn't exposed on `ReticulumNode`.
  - No idle time, no per-destination count, no lifecycle counters (established, closed-by-reason, failed).
  - Per-link memory accounting only on nRF.

### persist
- **No metrics crate, no spans** (no `#[instrument]` or `*_span!` anywhere).
  No timing on any query or fold. `tracing` is already a dependency, so spans
  need no new crate.
- **Instruments exist but are switched off:**
  - The read probe (`federation/read_probe.rs`) records rows and bytes per read
    at 38 call sites (13 sqlite, 13 pg, 12 memory), but under `#[cfg(test)]`.
    It can't simply be switched on: it's a thread-local Vec with an owned key
    String per read, and it re-serializes each envelope to count bytes.
    Production needs aggregate atomics fed from the same sites, with bytes
    taken from the stored column length.
  - `CacheStats` and `AdmissionStats` count hits, misses, evictions and resident
    bytes, each with a `stats()`. The Engine and PyEngine accessors,
    `cache_stats()` and `admission_cache_stats()`, are documented in
    `prelude.rs` but were never written.
- **No database-level signals:** no SQLite status or memory high-water, no
  saturation signal for the reader pool (the pool itself exists since v43.1,
  #829), no Postgres pool status or slow-query log, no blocking-pool gauge
  (145 `spawn_blocking` sites).
- **What a host can read today:** `storage_summary` (disk only), warnings and
  errors, and about 56 `info!` sites. There is no logging per operation.

### edge
- **One hand-rolled struct**, `EdgeMetrics`
  (`observability.rs:857`, 41 fields). Labels come in four styles (typed enums,
  `&'static str`, owned `String`, tuples), and naming is mixed (`_total` on some
  fields, not others).
- **No histograms.** Round duration, permit wait, sweep pages and resolution
  cost are not recorded.
- **Dead or wrong counters:**
  - The transport-side counters read 0 on v40.0.x because `with_metrics` has no
    caller. Fixed on main by "one metrics bag", v40.1.0.
  - `durable_queue_depth` is a cumulative counter presented as a gauge.
  - The UniFFI `queue_depth()` always returns 0.
- **27 separate `LogThrottle`s**, none counting what it suppresses.
- **Spans:** one INFO span (`anti_entropy_round`) and a handful of
  `#[instrument]` on send paths. Nothing inside a round, and no taxonomy.
- **Uneven exports:** PyO3 omits about 8 bundle fields, and UniFFI exposes
  `link_count` but PyO3 doesn't.

### server
- **No metrics framework.** `/v1/federation/metrics` hand-copies about 24 of
  edge's 41 fields into JSON. Each field carries a comment naming the release
  where it was found missing.
- **No spans of its own**, no request or correlation IDs, no histograms, no
  time series. Every surface is a point-in-time snapshot.
- **Memory:** process-wide only (`RssAnon`, `mallinfo2`). The memory route is
  off unless the canonical restarts with `CIRIS_DIAGNOSTICS=1`.
- **Logs:**
  - Plain text, even though JSON is compiled in.
  - The dedup layer suppresses every component's output and keeps one sample line.
  - A 512 MiB daily cap drops evidence during storms.
- **Wheels are stripped,** so no profiler can name a frame in production.
- **13 edge fields are never read** (first-contact outcomes, inbound low-trust
  drops, apply refusals by class, …).

### agent (the reference)
**Worth aligning to:**
- One collection model: `TelemetryAggregator` polls every service and bus.
- A standard per-service summary (uptime, requests, errors, error rate, healthy).
- One surface that exports JSON, OTLP-shaped JSON, Prometheus or Graphite, by pull or scheduled push.
- A resource monitor whose thresholds act: throttle, defer, reject, shutdown.
- The signed lens trace contract (`FSD/TRACE_WIRE_FORMAT.md`).

**Not worth copying:**
- No registry of metric names (dotted, snake, legacy and label-in-name, with readers that drift from writers).
- Unbounded labels (a `timestamp` tag, `thought_id` as a tag).
- Every sample stored as a graph node and typed "gauge".
- Prometheus output without labels, guessing counter vs gauge from the name.
- Hand-rolled OTLP with non-W3C trace IDs.
- Unstructured logs with no trace ID.
- RSS-only memory telemetry.

**Conclusion:** align to the agent's *shape* (per-component summary, one
export surface, action thresholds, written contracts), and fix the
implementation in both.

---

## 3. The model

### 3.1 Standards, not inventions
- **Names and units:** OpenTelemetry semantic conventions. They render to
  Prometheus/OpenMetrics names mechanically (`ciris.edge.round.duration` (s) →
  `ciris_edge_round_duration_seconds`).
- **Exposition:**
  - Prometheus/OpenMetrics text at `/metrics` (pull), with exemplars that carry trace IDs.
  - OTLP push, when an endpoint is configured.
- **Traces:** W3C Trace Context, so `trace_id` and `span_id` appear in logs, exemplars and spans.
- **Logs:** JSON lines, with `trace_id`/`span_id` attached when a span is current.

### 3.2 Libraries emit, the host exports
- **persist, edge and leviculum** depend only on two zero-cost facades:
  - `tracing` for spans and events;
  - the `metrics` crate facade for counters, gauges and histograms.
  With no recorder installed they cost nothing, which keeps the embedded and
  mobile builds lean.
- **The server, the only host,** installs:
  - the recorder, via `metrics-exporter-prometheus`;
  - the `tracing-opentelemetry` layer;
  - the JSON log layer.
  The agent-embedded fold uses the same host code.
- **leviculum's `no_std` core** keeps its counter structs. `leviculum-std`
  bridges them into the facade once, so firmware is unaffected.

### 3.3 One name registry per repo, checked by test
Generalise leviculum's `EVENT_CATALOG` pattern to metrics and spans:
- **Each repo carries a `telemetry_catalog`:** name, kind, unit, allowed label
  keys with their bounded value sets, description, owner.
- **A completeness test** fails when code emits a name that isn't catalogued,
  or the catalogue lists a name nothing emits. This is the same mechanism as
  leviculum's `event_catalog_completeness`.
- **The server merges the four catalogues** into the served `/metrics` HELP
  text and gates on two things:
  - no name collisions across repos;
  - every label key bounded, so no free-form IDs (peer keys go through
    hashing or top-k, never raw).

### 3.4 What every component reports

| Signal | What | Example |
|---|---|---|
| **RED per unit of work** | rate, errors, duration histogram | edge rounds by `kind` and outcome; persist folds and reads by door; server HTTP routes and periodic loops |
| **USE per resource** | utilisation, saturation, errors | tokio blocking pool, SQLite readers, Postgres pool, sweep permits, round gate, dial pool, link table, queues (as real gauges) |
| **Cost per unit** | rows/bytes decoded, allocations | persist's read probe, always on, as counters and histograms per door; optional sampled allocation counts per span |
| **Lifecycle** | created, closed by reason, failed | links, pooled links, sessions, rounds, retries |
| **Invariants** | two counts that must agree | leviculum mirror versus core link table; edge pool versus transport links; queue enqueued minus dequeued versus depth |
| **Suppression** | everything we chose not to log | log dedup and every `LogThrottle`, counted by key, so silence is visible |
| **Memory** | process, allocator, component | RSS/anon/HWM; allocator live and held; resident bytes per component (caches, link table estimate, queues, pools) |

### 3.5 Profiling with symbols
- **Symbols:** publish split debuginfo for each wheel as a release asset, keyed
  by build ID. Wheels stay stripped.
- **On-demand heap profiling** behind a cargo feature that the canonical image
  enables: jemalloc with `prof`, dumping a profile on request at a loopback
  route; or dhat for test harnesses.
- **The memory route** (`/v1/node/diagnostics/memory`) becomes always on and
  loopback-only, because it is read-only.

### 3.6 Exposure
- **`/metrics`** (OpenMetrics) on the read API. Loopback-only by default, plus
  an authenticated scrape for the bridge and CIRISStatus.
- **OTLP push** of metrics and traces when `CIRIS_OTLP_ENDPOINT` is set.
- **The existing JSON surfaces stay** (`/v1/federation/metrics`, `/v1/node/state`)
  as views derived from the same recorder, so no field is hand-copied again.
- **The agent** points its aggregator at the same names. Its Prometheus and OTLP
  output gains labels, real types and W3C IDs. That is a follow-up on the agent
  side, tracked separately.

---

## 4. Asks, in priority order

**P0** is needed to fully understand the current leak. **P1** is the unified
model. **P2** is SOTA polish.

### leviculum (through edge)
- **P0:**
  - Expose the live link list on `ReticulumNode`: id, destination, state, age, idle (`last_inbound`), and initiator or responder.
  - Expose established-link count per destination.
  - Add cumulative counters: links established, closed by reason, handshake failed.
  - Add an alarm when the mirror and core link counts diverge.
- **P1:**
  - Bridge `LinkStats`/`TransportStats`/`PlaneStats` into the `metrics` facade in `leviculum-std`.
  - Extend the catalogue to metrics.
  - Report per-link memory on std hosts (call the heap census).
- **P2:** histograms of link age and RTT.

### edge
- **P0 (v40.0.7, alongside the #819 reap):**
  - A gauge for dial-pool size, per destination class.
  - A counter of pooled links closed, by reason.
  - Round duration and permit-wait histograms.
  - Wire the transport metrics on the v40.0.x line.
  - Export every bundle field through PyO3 and UniFFI alike.
- **P1:**
  - Move `EdgeMetrics` onto the facade, with a catalogue and one label style.
  - Histograms for round duration by kind, sweep pages and rows, per-peer resolution, permit wait, and serve-tier refresh.
  - A "fetched but not shipped" counter.
  - Rename or retire `durable_queue_depth`.
  - Count `LogThrottle` suppressions.
  - A span taxonomy (`edge.round` › `edge.sweep.page`, `edge.resolve.*`, `edge.push`), as INFO only on unit-of-work boundaries.
  - Ship `init_logging()` (#814).
- **P2:** exemplars on round histograms.

### persist
- **P0 (CIRISPersist#1014, planned with #1013 as pin-compatible v53.1.8):**
  - Read counters always on, as aggregate atomics fed from the read-probe
    sites, with bytes taken from the stored column length:
    `ciris.persist.read.rows` and `.bytes` by door (`list_attestations_by/for/since/…`).
  - Counters attributed per fold: consent, trust-root walks, audience, serve
    tier, admission gates. Door counters show the rows but not which fold
    read them; this attribution is what found the 1.63 GB scorer pass.
  - The Engine and PyEngine accessors `cache_stats()` and `admission_cache_stats()`.
  - Snapshot accessor on Engine and PyEngine, plus a catalogue with a
    completeness gate. Neither needs the facade; P1 emits through it on top of
    the same counters.
- **P1:**
  - Spans with `rows`/`bytes`/`elapsed` on every fold entry point: trust-root walks, consent, admission and audience checks, serve tier.
  - Histograms for duration and rows per fold.
  - SQLite `sqlite3_status` / `db_status` gauges (page cache, memory high-water) and reader-pool saturation.
  - Postgres pool status and a slow-query threshold.
  - A blocking-pool gauge, owned by whoever builds the tokio runtime: persist
    on the PyEngine path, the host when embedded. Tokio's blocking-thread
    metrics need `tokio_unstable`.
- **P2:** an `EXPLAIN` capture for slow queries above a threshold, of the exact
  statement the code builds (lesson from the trace-summaries diagnosis).

### server
- **P0:**
  - `reticulum_link_count` (#745).
  - Make the memory route always on, loopback-only.
  - Read the 13 edge fields we currently ignore.
  - Make dedup count suppressions, as a metric.
- **P1:**
  - Install the recorder and the Prometheus `/metrics` endpoint.
  - JSON logs with trace IDs.
  - Spans per HTTP request and per periodic-loop pass (RED).
  - A per-component memory gauge.
  - Merge the catalogues, plus the server-side catalogue gate.
  - Split debuginfo on release.
  - Retire the hand-copy in `federation_surface.rs`.
- **P2:**
  - OTLP push.
  - The jemalloc profiling feature on the canonical image.
  - A health/readiness split that matches the agent's.

### agent (follow-up, tracked on CIRISAgent)
- Adopt the shared names.
- Real counters and histograms in-process instead of gauge graph nodes.
- Bounded labels.
- W3C trace IDs.
- JSON logs.
- Expose `/metrics` with labels.

---

## 5. Decisions (the maintainer, 2026-10-07)
1. **Facade: the `metrics` crate in libraries, OTel only in the host.**
   persist, edge and leviculum depend on `tracing` + `metrics` only; the server
   installs the Prometheus exporter and the OpenTelemetry layer.
2. **`/metrics` exposure: loopback-only plus an authenticated scrape** for the
   bridge and CIRISStatus. Not public.
3. **Debug symbols: split debuginfo published per release**, keyed by build ID.
   Wheels stay stripped.
4. **Scale gate: P0 and P1 in production before the next scale step** (more
   agents, more canonicals, larger communities).
