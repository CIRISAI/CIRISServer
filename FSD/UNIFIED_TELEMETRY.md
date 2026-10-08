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
- **Metrics:** separate pull-only snapshot structs (`LinkStats`,
  `TransportStats` with about 21 drop reasons, `PlaneStats`, interface stats,
  and now `LinkCensus` and `LinkLifecycle`). There was no registry and no
  metrics crate.
- **Gaps:**
  - Two link counts that are never reconciled: the completion mirror versus
    the core table's ESTABLISHED links (Active + Stale; the table also holds
    pending links). On #819 leviculum showed by code that they can't diverge
    at c2f8d3f; a divergence alarm is still cheap insurance, provided it
    tolerates a brief in-flight skew.
  - No API a host can call to list its links. `link_table_entries` exists but isn't exposed on `ReticulumNode`.
  - No idle time, no per-destination count, no lifecycle counters (established, closed-by-reason, failed).
    Idle time can only come from `last_inbound`, at 1 s resolution and
    recorded before decryption, so it means "a packet arrived", not "the
    peer authenticated".
  - Memory accounting not exposed. The core's `NodeHeapCensus` is
    platform-independent and works on std, but it's per component (links in
    aggregate, plus count), not per link, and only the nRF firmware called it.

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
- **Uneven exports:** PyO3 omits 8 bundle fields, and UniFFI exposes
  `link_count` but PyO3 doesn't.
- **No edge logs in standalone Python hosts.** Edge's own PyO3 wheel never
  installed a `tracing` subscriber, so a Python process that loads edge
  without the server dropped every edge line. The fix is `init_logging()`
  (CIRISEdge#814, PR #815). The agent-embedded one-wheel path is not
  affected: `ciris_server.init_tracing` installs the process-global
  subscriber, which captures `ciris_edge` and `ciris_persist`.
- **#819's cause is edge's dial pool:** it reuses links only while idle and
  never shrinks, and edge's own keepalives keep idle pooled links alive.

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
  - A 512 MiB daily cap writes one marker line and then drops every later
    event that day, novel errors included, and nothing counts what it drops.
- **Wheels are stripped,** so no profiler can name a frame in production.
- **13 edge bundle fields were never read** (inbound low-trust drops,
  backpressure drops by role, blob carriers/phases/chunks, delivery receipts,
  announce intake/queue/binding, apply refusals by reason and by class,
  removal delivery). `first_contact_outcomes`, `apply_refusals_by_kind` and
  `transport_inbound_drops` were already served. #745 serves the 13.

### agent (the reference)
Corrected by the agent team against agent main + #1232 (2.14.0); paths are
under `ciris_engine/`.

**Worth aligning to:**
- **A per-service summary** (uptime, requests, errors, error rate, healthy,
  `schemas/services/graph/telemetry.py:126`). Two bugs to fix rather than
  copy: `error_rate` is a 0–1 ratio documented as a percentage, and uptime is
  read under five aliases.
- **Two collection models:**
  - pull: `TelemetryAggregator` over the 6 buses, ~30 services and registry
    services, on demand behind a 30 s cache;
  - push: `record_metric` writes a graph node per sample, and handlers
    memorize metrics directly.
- **Export in several formats:** two pull endpoints
  (`/telemetry/unified?format=json|prometheus|graphite` and
  `/telemetry/otlp/{signal}`) plus a scheduled push in all four formats.
  The trace push drains the shared reasoning-event buffer, which could starve
  other consumers.
- **The lens trace contract, as it lives today:**
  `CIRISLensCore/docs/PUBLIC_SCHEMA_CONTRACT.md` (TRACE_SCHEMA_VERSION 3.0.0),
  with sealing and signing in ciris-lens-core (Rust). `FSD/TRACE_WIRE_FORMAT.md`
  is stale except for §8.
- **Memory tooling beyond RSS**, though it's tooling, not exported telemetry:
  - `utils/memory_release.py`: heap give-back on every platform (glibc
    `malloc_trim`, Bionic `mallopt`, Darwin pressure relief, Windows
    `_heapmin`), reported as release counts and MB;
  - `tools/memory_composition.py`: an out-of-process `/proc` smaps report;
  - an opt-in tracemalloc probe;
  - Android PSS on the five-platform gate.
- **`FSD/LOGGING_STANDARD.md`:** normative logging rules.

**Not a model yet — resource thresholds:** the monitor emits
throttle/defer/reject/shutdown signals, but the only subscriber is the
monitor itself. The only action taken is `release_memory` for memory, the
disk limit is never checked, and nothing calls `check_available`. Wiring
them is an agent follow-up; the shape (thresholds that act) is still the
target for the server.

**Not worth copying:**
- **No registry of metric names, and it's a live correctness bug.** Token
  usage is written as both `llm_tokens_used` and `llm.tokens.total`, both
  map to "tokens", and they're summed, so token totals are inflated. A reader
  (`thought_processing_started`) has no writer.
- **Unbounded labels:** a `timestamp` tag on every sample, and `thought_id`
  as a tag in four places.
- **Every sample stored as a gauge graph node.** TSDB consolidation bounds
  the storage, but there are no in-process counters or histograms.
- **Prometheus output without labels,** guessing counter vs gauge from the
  name. The OTLP metrics path does carry attributes and real sum/gauge types.
- **OTLP trace IDs that can't correlate:** non-hex characters are kept and
  uppercased, push uses `thought_id` as the trace ID and a sequence number as
  the span ID, and log-record IDs are SHA-256 hashes unrelated to spans.
- **Python logs are plain text without trace IDs.** The Rust substrate
  already logs structured `tracing` into `ciris-server.log`.

**Conclusion:** align to the agent's *shape* (per-component summary, one
export surface, thresholds that act, written contracts), and fix the
implementation in both. Neither stack has acting thresholds yet.

---

## 3. The model

### 3.1 Standards, not inventions
- **Names and units:** OpenTelemetry semantic conventions. The Prometheus
  name (`ciris.edge.round.duration` (s) → `ciris_edge_round_duration_seconds`,
  counters ending `_total`) is part of the host contract: the exporter is
  built with `with_recommended_naming(true)`, which is off by default, so the
  catalogue, the served names and the queries agree.
- **Exposition:**
  - Prometheus text format at `/metrics` (pull). The selected exporter
    renders Prometheus text and protobuf, not OpenMetrics; OpenMetrics with
    `Accept` negotiation needs a different renderer and is not promised here.
  - OTLP metrics push (§3.7).
- **Traces:** W3C Trace Context, propagated across process boundaries, not
  just started locally (§3.9).
- **Logs:** JSON lines, with `trace_id`/`span_id` written by a correlation
  layer (§3.9).
- **Exemplars are not promised.** A `metrics` facade histogram records only a
  number, so `/metrics` from the facade carries no exemplars. If P2 wants
  them for the few cost histograms, it dual-records those observations
  through an exemplar-capable OpenTelemetry instrument.

### 3.2 Libraries emit, the host exports
- **persist, edge and leviculum** depend only on two zero-cost facades:
  - `tracing` for spans and events;
  - the `metrics` crate facade for counters, gauges and histograms.
  With no recorder installed they cost nothing, which keeps the embedded and
  mobile builds lean.
- **The server, the only host,** installs:
  - **its own recorder**, built on `metrics-util`'s registry rather than
    `metrics-exporter-prometheus`'s handle. The exporter's handle can only be
    read back as rendered text, needs an upkeep task that dies with an
    embedded fold's Tokio runtime, and can't reset when a different node is
    served. The host recorder is:
    - **validating:** every emitted label key and value is checked against
      the merged catalogue. An undeclared value is recorded as `other`, and
      `ciris.telemetry.label_rejected` counts it by metric, so a runtime
      string (a peer, an error message) can never mint a series;
    - **queryable:** the JSON views read typed values from it directly,
      instead of parsing exposition text and reversing name translation;
    - **resettable per fold** (below);
    - **bucketed:** histograms are stored straight into the catalogue's fixed
      buckets as atomic counters, so there are no sample buffers to drain
      and no upkeep task to keep alive;
    - **rendered by us** as Prometheus text, applying the recommended naming
      rules (unit and `_total` suffixes) from §3.1;
  - the `tracing-opentelemetry` layer;
  - the JSON log layer, plus the correlation layer (§3.9).
  The agent-embedded fold uses the same host code, on Android and iOS too
  (§3.8).
- **One `metrics` facade version, linked once.** Each 0.x minor of `metrics`
  owns its own global recorder, so if persist, edge, leviculum and the server
  pull different minors, emissions through the other one silently go
  nowhere. All four pin the same minor (leviculum chose 0.24), and the server
  gains a gate that fails the build unless exactly one `metrics` package is in
  the dependency graph (the same idea as the substrate pin-coupling gate).
- **The recorder is installed once for the process; its contents belong to
  the fold.** The facade permits one global recorder, while the server
  supports stopping and re-serving a node in the same process, possibly with
  a different `home` and `key_id` (`serve_with_python_adapter`). So the
  recorder is installed once, idempotently, and **every fold start clears its
  registry**: counters, gauges and histograms all start from zero, and
  `ciris.host.fold.generation` increments. One node's counts never appear
  under another's `/metrics`, and a scraper sees an ordinary counter reset,
  which Prometheus handles.
- **The OpenTelemetry layer is in place from the first install; only its
  export pipeline is reloaded.** On the one-wheel path Python may call
  `ciris_server.init_tracing` before the node starts. Today that subscriber
  wins and later calls can only swap the file slot
  (`install_or_reattach_tracing`), so a later OTel layer can never be added.
  The first install therefore includes a `tracing-opentelemetry` layer
  backed by an ID-generating tracer that exports nothing. Every span gets a
  W3C trace and span ID from the start, so JSON logs correlate even with no
  OTLP endpoint configured. Configuring an endpoint swaps in a real export
  pipeline behind the same layer.
- **leviculum's `no_std` core** keeps its counter structs. `leviculum-std`
  bridges them into the facade once, so firmware is unaffected.

### 3.3 One name registry per repo, checked by test
Generalise leviculum's `EVENT_CATALOG` pattern to metrics and spans:
- **Each repo carries a `telemetry_catalog`:** name, kind, unit, allowed label
  keys with their bounded value sets, description, owner, and, for each
  histogram, its bucket boundaries. The exporter renders a histogram as a
  summary unless buckets are configured, so buckets are part of the contract.
  Changing a histogram's buckets is a breaking change to that series: it
  gets a new name or a version suffix, never a silent edit.
- **A completeness test** fails when code emits a name that isn't catalogued,
  or the catalogue lists a name nothing emits. This is the same mechanism as
  leviculum's `event_catalog_completeness`.
- **The server merges the four catalogues** into the served `/metrics` HELP
  text and gates on two things:
  - no collisions among **rendered series names**, compared independently of
    kind. Every name a metric will emit is computed after sanitizing dots and
    invalid characters and adding unit and `_total` suffixes, including the
    `_bucket`, `_sum` and `_count` names a histogram generates. Any name
    produced by two catalogue entries fails the gate. Prometheus allows one
    type per metric family, so including the kind in the comparison would
    wrongly let a counter and a gauge both render `ciris_foo`. Distinct
    catalogue spellings (dotted vs underscored, a unit-bearing name vs an
    explicitly suffixed one) can render as one name too;
  - every label key bounded. **No per-peer series of any kind.** Hashing a
    peer key redacts it but still makes one series per peer, so a long-lived
    or adversarial node could grow the recorder without limit. Per-peer
    detail is aggregated (by peer class or role), bucketed by a fixed scheme,
    or held in a capped top-k with an `other` bucket. Per-peer views are
    served on demand from domain state, not as metric labels.

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

### 3.5 Open spans name what ran, not what allocated
The diag-span builds taught one rule: the count of open spans during a memory
climb shows what was *running*, not what *allocated*. A round waiting on an
unroutable dial stays open while untraced work allocates. Allocation
attribution needs a heap profiler (§3.6) or exemplars on cost histograms, not
span counts alone.

### 3.6 Profiling with symbols
- **Symbols:** publish split debuginfo for each wheel as a release asset, keyed
  by build ID. Wheels stay stripped.
- **On-demand heap profiling,** without breaking the allocator signals we
  already rely on. `diag.rs` reads live and held heap from glibc `mallinfo2`
  and returns retained memory with glibc `malloc_trim`, which is the 0.5.223
  mitigation. Swapping in jemalloc for `prof` would leave both pointing at a
  heap Rust no longer uses. So:
  - the profiling feature carries an allocator-specific backend for the
    memory report and the trim: under jemalloc, `stats.allocated` /
    `stats.resident` and an arena purge, behind the same routes;
  - or profiles are taken without replacing the allocator (heaptrack or
    bytehound against the symbolised build, or dhat in test harnesses).
- **The memory route** (`/v1/node/diagnostics/memory`) is always on (#745),
  loopback-only, and refuses requests carrying proxy forwarding headers.

### 3.7 Exposure
- **`/metrics`** (Prometheus text):
  - **unauthenticated only on a dedicated listener bound to `127.0.0.1`,**
    which no reverse proxy is configured to reach;
  - **authenticated on the public read listener,** for the bridge and
    CIRISStatus. A peer address of loopback is not treated as local there,
    because a same-host reverse proxy connects from loopback and would make
    every forwarded request look local.
- **OTLP metrics push** when `CIRIS_OTLP_ENDPOINT` is set. The `metrics`
  facade allows one global recorder, so there are two paths:
  - an OpenTelemetry Collector scrapes `/metrics` and pushes OTLP (no
    in-process change);
  - or a fanout recorder (`metrics-util`) feeds both the Prometheus handle
    and an OTLP recorder.
  OTLP traces go through the `tracing-opentelemetry` exporter.
- **The host owns the OTLP providers' lifecycle.** Batch span processors and
  periodic metric readers buffer completed telemetry, so the host keeps the
  tracer and meter providers in its state and runs:
  - a bounded `force_flush` on fold teardown and on any OTel layer reload;
  - `shutdown` on process exit.
  Otherwise the last telemetry before a shutdown or failure, the part an
  investigation needs most, is silently lost.
- **`/v1/federation/metrics`: its catalogued aggregates become a view of the
  recorder,** so no aggregate is hand-copied again. Every other field the
  client reads (`FederationMetrics.kt`) stays sourced from the live handle it
  comes from today, until it has a catalogued equivalent:
  - `peer_reachability_ratio`, per peer, from `reachability_tracker()` (the
    metrics forbid per-peer series, §3.3);
  - `inline_text_subscriber_count`, from `edge.verified_feed_subscriber_count()`
    (catalogue it as a gauge before retiring the read);
  - `durable_queue_depth`, which the client sums: it keeps its name and its
    current source until persist's `outbound_counts()` (CIRISPersist#996) can
    serve a real resident depth. `durable_enqueued_total` is served beside
    it. The contract then changes once, in a release that says so: the field
    becomes the real gauge.
- **`/v1/node/state` stays sourced from its domain folds.** It reports persist
  state, storage timestamps, signer attribution and categorical causes
  (`unreadable`, `never_admitted`, `not_exercised`) that tell identical
  numeric zeroes apart; aggregated series can't carry those. It shares
  primitive observations with the recorder rather than being rebuilt from it.
- **The agent rides on this surface** (§3.8); it doesn't run a second one.

### 3.8 The agent inherits the substrate's telemetry
The maintainer's ruling, 2026-10-07 (relayed by the agent team): the agent
**inherits** unified telemetry from the substrate. It rides on top and adds
its own signals; it does not build a parallel stack. The folded node is the
agent's one export surface on every platform, Android and iOS included.

The `ciris_server` wheel provides, through PyO3 into the same recorder and
tracing pipeline:
1. **An emit API:** counter, gauge and histogram by catalogued name with
   bounded labels. Agent metrics appear in the same `/metrics` and OTLP push,
   with the same HELP text.
2. **A fifth catalogue:** the agent ships its `telemetry_catalog` (prefix
   `ciris.agent.*`). The host loads it at fold start and merges it under the
   same gates: no name collisions, every label key bounded. The agent runs
   its own completeness test against its emit sites.
3. **Spans, with task-local context:** a Python context manager that holds
   the span's context in a `contextvars` variable, not a Rust span "entered"
   on a thread. asyncio tasks interleave on one thread and PyO3 work may run
   on others, while an entered `tracing` span is thread-scoped and must exit
   in stack order, so a plain start/end API would attach concurrent thoughts'
   work to the wrong parent. Each Rust call made under the context manager
   attaches that context explicitly (to the call, or by instrumenting its
   future). A thought or LLM call becomes a real span; the node's spans for
   that work (persist writes, edge sends) parent under it, and lens trace
   IDs can link to it. The current W3C trace and span IDs are readable from
   Python.
   Executor hops need care: `loop.run_in_executor(None, …)` does not copy
   `contextvars` into the worker thread (only `asyncio.to_thread` and
   `contextvars.copy_context().run` do), and the agent uses it for the node
   fold start and some persist calls. So the API also:
   - accepts the span context as an explicit argument on each Rust call,
     captured before the hop;
   - offers a helper that wraps a callable with the current span context for
     executor use.
   Without these, spans parent correctly inside coroutines but silently
   detach across executor hops.
4. **One log stream:** a Python logging handler that writes into the host's
   JSON log layer, with `trace_id`/`span_id` attached when a span is current.
   One structured log per process.
5. **Readable host gauges:** read access to process and memory figures
   (RSS/anon/HWM, allocator held), so the agent's resource monitor acts on
   the host's numbers instead of sampling RSS itself. Each platform needs a
   backend, and anything unavailable is reported as unavailable, never as 0:
   - Linux/glibc: `/proc/self/status` and `mallinfo2` (today's `diag.rs`);
   - Android/Bionic: `/proc/self/status` and Bionic's `mallinfo`;
   - iOS and macOS: `task_info(TASK_VM_INFO)` footprint and
     `malloc_zone_statistics` (no `/proc`);
   - Windows: the process memory counters, allocator held unavailable.
6. **Fold and mobile parity:** the recorder and layers are installed in the
   agent-embedded fold on Android and iOS too. The emit API is a cheap no-op
   when no recorder is installed.


### 3.9 Trace context across processes and into logs
- **Propagation is explicit.** Installing a tracing layer and opening local
  spans doesn't connect processes; each one starts unrelated traces unless
  context is injected into outgoing carriers and extracted from incoming
  ones (OpenTelemetry's `TextMapPropagator`).
  - **HTTP:** the server extracts `traceparent`/`tracestate` from incoming
    requests and injects them into outgoing ones (client ↔ server, agent ↔
    server, server → peers).
  - **Federation transport:** edge carries the trace context in an envelope
    or frame field outside the signed content, so it never changes what is
    signed or verified, and extracts it on receive. This is edge P2.
- **Logs carry the IDs through a correlation layer.** The standard JSON
  formatter serializes event and span fields; it doesn't write OpenTelemetry
  IDs. A small layer reads the current span's OTel context
  (`get_otel_context`) and writes `trace_id`/`span_id` into each JSON line.

---

## 4. Asks, in priority order

**P0** is needed to fully understand the current leak. **P1** is the unified
model. **P2** is SOTA polish.

### leviculum (through edge; leviculum#77)
**Status:** P0 and P1 implemented in leviculum PR #76, not merged yet. Edge
adopts it on main with leviculum's next tag (CIRISEdge#820). It contains:
- `link_list()`: per link, role, state, age, idle, RTT, interface;
- `link_census()`;
- `link_lifecycle()`: established, closed by 7 reasons, handshake-failed,
  with the invariant established − closed = live tested;
- `link_count_check()`, with a catalogued `LINK_MIRROR_DIVERGED` alarm
  (compare every 10 s, alarm after 30 s);
- `heap_census()`, plus a `leviculum.memory.link_bytes_mean` gauge;
- the `metrics` 0.24 facade through a pull-based `publish_metrics()`;
- a 24-entry `METRIC_CATALOG` with bounded labels only (no link, destination
  or peer IDs);
- the completeness test extended to metric names, labels and unused entries.

The original asks:
- **P0:**
  - Expose the live link list on `ReticulumNode`: id, destination, state, age, idle (`last_inbound`), and initiator or responder.
  - Established-link count per destination: covered by leviculum PR #76,
    `ReticulumNode::link_census()` (initiator, responder, pending,
    per-destination), pending a tag.
  - Add cumulative counters: links established, closed by reason, handshake failed.
  - Add an alarm when the mirror and core link counts diverge.
- **P1:**
  - Bridge `LinkStats`/`TransportStats`/`PlaneStats` into the `metrics` facade in `leviculum-std`.
  - Extend the catalogue to metrics.
  - Report per-link memory on std hosts (call the heap census).
- **P2:** histograms of link age and RTT.

### edge (CIRISEdge#820)
- **P0 (v40.0.7, alongside the #819 reap):**
  - A gauge for dial-pool size, per destination class.
  - A counter of pooled links closed, by reason.
  - Round duration and permit-wait histograms.
  - Wire the transport metrics on the v40.0.x line: a back-port of v40.1.0's
    attach-at-build. Counters that only exist in leviculum 0.29 can't exist on
    0.27.
  - Export every bundle field through PyO3 and UniFFI alike, with a test that
    walks the bundle so a new field can't be omitted again.
  - `init_logging()` (#814/#815) for standalone edge Python hosts only. In the
    one-wheel agent fold the server's `init_tracing` owns the single
    subscriber, and a second install would race it.
- **P1:**
  - Move `EdgeMetrics` onto the facade, with a catalogue and one label style.
  - Histograms for round duration by kind, sweep pages and rows, per-peer resolution, permit wait, and serve-tier refresh.
  - A "fetched but not shipped" counter.
  - Replace `durable_queue_depth` with `durable_enqueued_total` (#815). A real
    resident depth needs persist's `outbound_counts()` (CIRISPersist#996).
  - Count `LogThrottle` suppressions.
  - A span taxonomy (`edge.round` › `edge.sweep.page`, `edge.resolve.*`, `edge.push`), as INFO only on unit-of-work boundaries.
- **P2:**
  - Trace context carried in a federation envelope or frame field outside
    the signed content (§3.9).
  - Exemplars on round histograms, if wanted, through dual-recording (§3.1).

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
- **P0 (all in #745, 0.5.224):**
  - `reticulum_link_count` on `/v1/federation/metrics`.
  - The memory route always on, loopback-only (trim stays behind the switch).
  - The 13 edge fields we used to ignore, served.
  - Dedup suppressions counted (`log_dedup_suppressed_total`).
- **P1:**
  - Install the recorder and the Prometheus `/metrics` endpoint.
  - JSON logs with trace IDs (the correlation layer, §3.9), migrating
    `telemetry_logs.rs::parse_line` (behind `/v1/telemetry/logs` and the
    client Logs screen) to parse JSON lines while still reading text lines
    from older, mixed-format files.
  - A log-sink drop counter with a bounded reason (`daily_cap`,
    `write_error`, …) for every event the file sink discards, plus a
    rollover policy so a storm can't silence novel errors for the rest of
    the day.
  - The dedicated loopback-only `/metrics` listener and the authenticated
    scrape on the public read listener (§3.7).
  - The trace-context extraction and injection on HTTP (§3.9).
  - Spans per HTTP request and per periodic-loop pass (RED).
  - A per-component memory gauge.
  - Merge the catalogues, plus the server-side catalogue gate.
  - Split debuginfo on release.
  - Retire the hand-copy in `federation_surface.rs`.
  - The agent host API (§3.8, items 1–6), alongside the recorder install:
    Python emit, the agent catalogue merged under the same gates, Python spans
    with W3C IDs, a Python log handler into the JSON layer, readable host
    gauges, and the same install in the mobile fold.
- **P2:**
  - OTLP push of metrics (Collector or fanout recorder) and traces.
  - Heap profiling on the canonical image, with its allocator-specific
    memory report and trim (§3.6).
  - A health/readiness split that matches the agent's.

### agent (follow-up, tracked on CIRISAgent)
The agent inherits the host's telemetry (§3.8).

Correctness first:
- Fix the token double count (`llm_tokens_used` + `llm.tokens.total`).
- Wire the resource thresholds to subscribers that act, reading the host's
  gauges.

Then move onto the host:
- Ship a `telemetry_catalog` (`ciris.agent.*`) with a completeness test.
- Emit metrics, spans and logs through the host API (§3.8).
- Delete each agent exporter only once the host serves an equivalent:
  - the Prometheus converter once `/metrics` serves agent metrics;
  - the OTLP converter, trace-ID normalisation and OTLP push once the host's
    OTLP metrics and traces push is live (§3.7);
  - Graphite and the JSON push have no host equivalent planned; they stay
    until a host exporter exists, or are retired through an announced,
    staged deprecation, never silently.
  This is the same "delete the Python layer the substrate owns" pattern as
  earlier substrate swaps.

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
