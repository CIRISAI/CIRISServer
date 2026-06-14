# BENCHMARKS.md

`ciris-lens-core` ships a criterion benchmark suite (`benches/`) that
characterizes the science-layer hot paths. This doc names each bench,
documents the **expected curve shape**, and explains what a
deviation surface-wise means — so the suite is useful as a
regression-shape detector, not just a "what's the number" snapshot.

Companion to
[`CIRISPersist/docs/...`](https://github.com/CIRISAI/CIRISPersist) and
[`CIRISEdge/docs/BENCHMARKS.md`](https://github.com/CIRISAI/CIRISEdge/blob/main/docs/BENCHMARKS.md)
benches — same `cargo bench` + `Bench` workflow pattern; same
"curve shape, not absolute numbers" interpretation.

## TL;DR — how to run

```sh
# Run the whole suite (slow; ~5 min on a workstation).
cargo bench --no-default-features

# Just one bench.
cargo bench --no-default-features --bench canonicalize

# Compile-only gate (fast; what CI's ci.yml runs as the per-PR check).
cargo bench --no-default-features --no-run
```

Criterion writes its report to `target/criterion/`. The top-level
`target/criterion/report.html` is the visual entry point; the
per-bench `<bench>/<size>/report/` paths drill down to the
distribution + outlier breakdowns criterion records.

## When the suite runs in CI

Three triggers, no pass/fail gating (GitHub's shared runners are
too noisy):

- **Daily cron** (`bench.yml`, 05:37 UTC) — drift detection within 24h
- **Manual dispatch** — run against any branch for PR review
- **Tag push** — every `v*` tag records the baseline for that release
  in the GH Actions artifact set

The fast inner-loop bit-rot check is `cargo bench --no-run` in
`ci.yml`'s `benches` job — that's a pass/fail gate on every PR.

## Reading the curves

Each bench sweeps its input geometrically. The interesting
information is the **shape** of the curve relative to its
expectation, not the absolute number on any single point. A flat
expectation that bows means an O(1) routine grew an iterator; a
linear expectation that knees up means an O(n) routine hit a
super-linear inner step.

Per-bench expectations:

| Bench           | Sweep parameter         | Expected curve | A bowed curve means …                                    |
|---              |---                      |---             |---                                                       |
| `canonicalize`  | envelope body bytes     | linear         | the canonicalizer started re-serializing the body        |
| `project`       | noise blob count        | constant       | path-lookups became iteration (broken indexing)          |
| `aggregate`     | event count             | linear         | someone added a sort / quadratic compare in the loop     |

When a curve bows the wrong way, open the bench's source comment
block (each `benches/*.rs` has a `# Expected curve` section) +
inspect the function under test. The mapping from bench → source is
documented in each bench file.

---

## Benches

### `canonicalize` — `crate::wire::canonical_bytes(&BatchEnvelope)`

Lens-core's signing hot path canonicalizes the envelope once per
detection event. The throughput here bounds `sign_detection` at the
bottom (canonicalization → hash → sign sequence).

- **Sweep:** envelope body bytes, geometrically `256` → `262_144`
- **Expected curve:** linear in body size
- **Reports throughput in:** MB/s (criterion `Throughput::Bytes`)
- **Source under test:** `src/wire/mod.rs` →
  `ciris_persist::prelude::canonicalize_envelope_for_signing` (single-
  source-of-truth canonicalizer; CIRISPersist#7 lesson)
- **Regression-shape signal:** non-linear ⇒ canonicalization is
  re-serializing the `RawValue` body instead of writing its bytes
  verbatim. AV-5 regression; the canonical path's bytes-only
  invariant is violated. Open `CIRISPersist/src/canonicalize.rs`
  and look for a fresh `serde_json::to_string` over `body`.

### `project` — `crate::extract::project(&Features)`

The 16-feature CRC projection on the science-layer hot path. One
call per trace; the ceiling on per-trace scoring rate.

- **Sweep:** noise-blob count in `Features.component_blobs`,
  geometrically `0` → `4096` (the three blobs `project` actually
  reads are always present; noise pads the HashMap)
- **Expected curve:** **constant** in blob count
- **Source under test:** `src/extract/projection.rs` →
  `pub fn project(features: &Features) -> [f64; PROJECTION_DIM]`
- **Regression-shape signal:** rising curve ⇒ the projection started
  iterating where it should be indexing. `Features.component_blobs`
  is a `HashMap<String, Value>`; `project` does six `.get(key)`
  calls (O(1) per call). A linear-in-blob-count curve means someone
  introduced a `.iter().filter(...)` somewhere. Open
  `src/extract/projection.rs::project` + check the path-descend
  helpers.

### `aggregate` — `crate::scores::compute_aggregate(...)`

The pure reduction over a slice of `DetectionEvent`s that produces
an `AgentScoreAggregate` (FSD §4.6). Every
`lens.scores.get_for_agent_window(...)` call lands here after
persist's read; it sets the ceiling on the agent-side score read
path's response time.

- **Sweep:** event count, geometrically `100` → `100_000`
- **Expected curve:** linear in event count
- **Reports throughput in:** events/sec (criterion
  `Throughput::Elements`)
- **Source under test:** `src/scores/aggregate.rs` →
  `pub fn compute_aggregate(...) -> AgentScoreAggregate`
- **Regression-shape signal:** super-linear ⇒ a sort or quadratic
  comparison snuck into the loop. The function is a single pass
  over the slice with a `HashMap::entry()` per-detector update;
  any operation more expensive than `O(1)` per event breaks the
  shape. Open `src/scores/aggregate.rs::compute_aggregate` + check
  for accidental `.collect()` / `.sort()` calls inside the
  iteration.

---

## Realistic deployment volumes

The bench sweeps match realistic federation deployments — the
biggest size in each sweep is what a busy production-class lens
sees in a 24h window:

| Bench           | Pi-class 24h   | Production-class 24h |
|---              |---             |---                   |
| `canonicalize`  | ≈ 10k traces   | ≈ 1M traces          |
| `project`       | ≈ 10k traces   | ≈ 1M traces          |
| `aggregate`     | ≈ 1k events    | ≈ 100k events        |

The `aggregate` bench's `100_000` point IS the production-class
"one full day in one window" call. If that point's wall-clock
exceeds the operator's `/scores` SLO, the `get_for_agent_window`
read path needs to either reduce the window or move the aggregation
substrate-side (file a persist ask for an aggregated read).

---

## Adding a new bench

Mirror the pattern of an existing bench:

1. Create `benches/<name>.rs` with the criterion harness +
   `#[derive(Debug)]`-style fixture builder + a `bench_<name>`
   function.
2. Add `[[bench]] name = "<name>" harness = false` to `Cargo.toml`.
3. Document **expected curve** in the file's module-doc comment
   block — that's the regression-shape detector for future
   reviewers.
4. Add a row to the "Reading the curves" table in this doc.
5. Verify `cargo bench --no-run` compiles before pushing — that's
   the ci.yml gate.

The criterion suite is not a place to chase nanosecond-tuning;
it's a curve-shape detector. Optimize for "the shape is right",
not "the number is low."

---

## References

- [`benches/`](../benches/) — the bench sources (each file has its
  own module-doc with expected curve + regression-shape signal)
- [`.github/workflows/bench.yml`](../.github/workflows/bench.yml) —
  the daily-cron Bench workflow
- [`Cargo.toml`](../Cargo.toml) `[[bench]]` entries — what's wired
- [criterion docs](https://bheisler.github.io/criterion.rs/book/) —
  upstream criterion concepts (groups, throughput, baseline)
- [CIRISEdge `docs/BENCHMARKS.md`](https://github.com/CIRISAI/CIRISEdge/blob/main/docs/BENCHMARKS.md)
  — sister doc; same pattern, different surfaces
