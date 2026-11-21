# Workload attribution: every unit of work names who it was for

Eric, 2026-11-21: "the telemetry needs to allow for clear attribution so we can attribute and shed
workload in emergencies."

## Why: what the 0.5.251 CPU read could not answer

On 2026-11-21 the canonical's quiet CPU was 15–30% higher on 0.5.251 than on 0.5.248. It took
five rounds of read-only probing across three sessions to attribute it, and half of it is still
only inferred. The gaps, each a rule below:

| What we couldn't see | Cost | Rule |
|---|---|---|
| Half of all persist reads were `unattributed`: the server's own reads on the shared engine carry no caller | the server's half of the growth is inferred, not measured | A1 |
| No per-route request count or latency on the canonical (no access log, no route metrics) | couldn't tell whether a server route grew | A2 |
| The first reading (2.5×) came from the `PERSIST READS HOT` log, which samples the top callers every ~30 s | a wrong number reached three sessions before the counters corrected it to +45% | A3 |
| No gauge for the send set's size, and the "attestation plane served" line is DEBUG | rows per read had to be derived | A4 |
| A memoised read didn't say WHY it re-read (miss, TTL, invalidation) | took a code read to find the 10 s TTL re-reading an unchanged set (CIRISEdge#1022) | A5 |
| A timer loop logs at INFO on every tick (the owner-pen retry, 48/h) and has no name, cadence or cost metric | only log-line spacing showed it was a loop | A6 |

## The rules

**A1. Every persist read is credited to a site.** A request is read under
`ciris_persist::observe::caller_scope(server.route.<group>)`, and a background loop under
`server.loop.<name>`. A spawned task carries the scope (`current_caller`). `unattributed` must be
near zero in production; a residue above 1% of reads is a defect.

**A2. Per-route and per-loop metrics, exported over OTLP.** Next to edge's bundle at
`GET /v1/telemetry/otlp/metrics`:
- `ciris.server.http.requests{route,status_class}`, a counter, and
  `ciris.server.http.duration{route}`, a histogram. `route` is the axum MATCHED PATH TEMPLATE
  (`/v1/self/rooms/{id}`), never a raw path, so cardinality is the route table's size.
- `ciris.server.loop.ticks{loop,outcome}`, `ciris.server.loop.duration{loop}`, and
  `ciris.server.loop.interval_secs{loop}`, a gauge.

**A3. Counters are the source of truth; logs are evidence.** Any number used to decide something
(a regression call, a shed) comes from a counter series over a window. A sampled or top-N log line
may point at a caller, never measure it.

**A4. Sizes are gauges.** Every set or index a hot path walks exports its size: send set, holdings,
key plane, store rows by tier.

**A5. A memoised read says why it read.** `reason = miss | ttl | invalidated | forced`, counted per
memo.

**A6. Loops are named and quiet.** Every timer loop registers a name and interval. A tick logs only
on a change of outcome (first failure, recovery), never on a repeat; repeats are counted. The
owner-pen retry on a remote-claimed node is the first one to quiet down.

**A7. Attribution is the shedding key.** The load-shedding ladder (Eric 11-01: full → audio + files →
chat + contacts; never shed own devices, the owner, or federation duty) acts on the same site names.
Under Warning or Critical, the node:
1. reads the last window's cost per site (A1/A2);
2. sheds the costliest site that its tier allows (e.g. `server.loop.*` maintenance stretches,
   `edge.advertise.*` rounds stretch, relayed A/V legs are refused);
3. logs every shed with a stable token and site, and counts it.

Shedding never drops a site that the "never shed" list names, whatever its cost.

**A8. Bounded cardinality.** Labels are site names, route templates, loop names and outcome
classes. Never a peer id, key id, community id or raw path. Per-peer cost, when needed, is a
separate top-K sketch, not a label.

## Who does what

- **persist:** raise `MAX_CALLER_LABELS` (32 today; edge already uses 26) so that edge and the
  server both fit. Ask: 128, in a 61.4.x LTS patch and in v62. Keep the cap's `other` bucket, and
  count how many reads land in it.
- **edge:** A4 gauges (send set, holdings, key plane), A5 memo reasons (CIRISEdge#1022 needs these
  first), and A7's shed decision consuming the per-site window.
- **server (this branch, 0.5.253):** A1 route and loop scopes, A2 metrics in the OTLP endpoint, A6
  loop registry and quiet logging, and the route-group table below.

## Server caller labels (as built, 0.5.253)

Route groups, by matched-path prefix (first match wins; `src/workload.rs` `ROUTE_GROUPS`):

| label | prefixes |
|---|---|
| `server.route.calls` | `/v1/chat/{room}/call`, `/v1/qa/call`, `/v1/calls` |
| `server.route.chat` | `/v1/chat`, `/v1/contacts` |
| `server.route.files` | `/v1/files`, `/v1/drive`, `/v1/media` |
| `server.route.communities` | `/v1/communities`, `/v1/families`, `/v1/commons`, `/v1/safety` |
| `server.route.accord` | `/v1/accord`, `/v1/accord-holders`, `/v1/trust-root` |
| `server.route.federation` | `/v1/federation`, `/v1/mesh`, `/v1/ingest`, `/v1/traces`, `/lens-api` |
| `server.route.telemetry` | `/v1/telemetry` |
| `server.route.health` | `/v1/health`, `/v1/system`, `/health` |
| `server.route.admin` | `/v1/admin`, `/v1/setup`, `/v1/node`, `/v1/config`, `/v1/mesh-config`, `/v1/operations`, `/v1/vocabulary`, `/v1/qa` |
| `server.route.self` | `/v1/self`, `/v1/auth`, `/v1/my-data`, `/v1/notes`, `/v1/memory`, `/v1/identity`, `/v1/agent` |
| `server.route.other` | anything else |

There's no `/v1/rooms` surface (room routes live under chat and communities), so there's no
rooms group. Federation carries the heaviest inbound plane, so it gets one. Setup is folded into
admin.

Loops: `server.loop.<name>` for each `loop_cadence::LOOPS` name, plus `self_publish` (the
publish-own set loop, on its own 30 s sleep).

**The cap gate.** persist v61.4.2 interns at most 32 labels and edge holds 26. Interning 11
groups plus 15 loops against that would push edge's own sites into `other`. So below a cap of
64 (`workload::FINE_LABELS_FROM_CAP`), every server read is credited to the one label `server`.
That separates the server from edge, and the split inside the server comes from
`ciris.server.http.*` and `ciris.server.loop.*`. Persist 61.4.3's cap of 128 switches the fine
labels on with no server change. `ciris.server.attribution.fine_labels` says which mode a build
is in.
