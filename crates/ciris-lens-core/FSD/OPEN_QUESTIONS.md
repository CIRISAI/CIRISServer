# Open Questions — CIRISLensCore

Decisions deferred to implementation kickoff. The threat model
(`docs/THREAT_MODEL.md`) closed most of the architectural questions
already (cohort routing, fail-secure floor, layered defense across 5
ratchet detectors); what's left is integration shape + naming +
calibration ownership.

Each question states the choice, the trade-off, and a starting
position. Resolutions move to `CLOSED` at the bottom.

---

## OQ-02: Cohort centroid storage + delivery

**Question:** Where do cohort centroids (calibrated by RATCHET) live
+ how does lens-core get them?

**Options:**
- **A — Persist substrate table** (`cirislens.cohort_centroids`).
  RATCHET writes; lens-core reads via Engine. Centroids signed by
  RATCHET's steward identity; lens-core verifies + uses.
- **B — Per-release static config baked into lens-core's binary.**
  Centroids ship as a compile-time embedded JSON. Updates require
  lens-core release.
- **C — File-mounted at deploy.** Centroids in `/etc/ciris-lens-core/centroids.json`;
  operator updates by replacing the file.

**Trade-offs:**

| Dimension | Persist table | Embedded | File-mount |
|---|---|---|---|
| Update cadence | RATCHET-driven, federation-wide | Lens-core release-driven | Operator-driven |
| Federation determinism | All peers see same centroids (after replication) | All peers see same centroids (per release) | Per-deployment |
| RATCHET workflow integration | Direct | Indirect | Indirect |
| Cold-start handling (LC-AV-9) | Centroid absent → fail-secure naturally | Same | Same |

**Starting position:** A (persist table). RATCHET's calibration
output is itself federation evidence; storing centroids in persist
makes them auditable + replicable across peers + signature-verifiable.

**Status:** OPEN — coordinate with RATCHET on the calibration→centroid
publication workflow + with persist on the schema (likely a new
schema-versioned migration).

---

## OQ-03: Detector parameter rotation cadence + delivery

**Question:** Detector operating points are CIRIS-RED-incubated and
must rotate between calibration cycles (LC-AV-14 closure). How are
parameters delivered to lens-core + how often do they rotate?

**Options:**
- **A — Quarterly calibration cycle** with parameter rotation at each
  cycle boundary. Parameters delivered via persist (similar to OQ-02)
  or via a separate config crate.
- **B — Continuous calibration** with RATCHET publishing updated
  parameters on a faster cadence (monthly?) as new red-team fixtures
  validate.
- **C — Per-cohort independent cadence.** Cohorts with high
  trace volume calibrate faster; cohorts with low volume stay on
  older parameters longer.

**Starting position:** A (quarterly). Faster cadence is research-
team's domain; lens-core's contract is "consume what RATCHET ships,
on whatever cadence." A quarterly default is operationally
predictable.

**Status:** OPEN — RATCHET-owned. Decision sits with the calibration
team, not lens-core implementation.

---

## OQ-04: SLO budget for the per-trace pipeline

**Question:** What's the bounded latency budget that
`LC-AV-11` enforces? When `score_unavailable` should fire?

**Options:**
- **A — 50 ms p99**, mirroring lens's existing trace ingest latency
  envelope. Aggressive but matches today's hot-path expectation.
- **B — 100 ms p99**, more headroom for cold-cache cohort lookups +
  detector recompute.
- **C — Per-cohort SLO**, derived from the cohort's centroid-lookup
  cost + its detector parameter density.

**Starting position:** A (50 ms p99) for Phase 1. Move to C in Phase
2 once production data shows real per-cohort latency distributions.

**Status:** OPEN — empirical, depends on detector implementation
costs; revisit during Phase 1 benchmarking.

---

## OQ-05: Detection event schema in persist

**Question:** What's the SQL shape for the detection-event records
lens-core writes back to persist?

**Options:**
- **A — New persist table** (`cirislens.detection_events`) with
  schema designed for lens-core's outputs (cohort, detector, score,
  ManifoldConformity variant, signed envelope, lens_core_version).
- **B — Extend `trace_events`** with detection-event rows tagged by
  a new `event_type='LENS_DETECTION'`. Reuses the existing audit
  pattern.
- **C — Lens-derived schema** (`cirislens_derived.detection_events`)
  per the discussion in CIRISLens#8. Lens-core writes to lens-derived;
  persist substrate stays untouched.

**Starting position:** C (lens-derived schema). Detection events are
analytical output, not substrate. Same architectural distinction as
`coherence_ratchet_alerts` and other lens-derived tables. Keeps
persist's substrate clean.

**Status:** OPEN — depends on the lens-derived schema work tracked at
CIRISLens#8.

---

## OQ-06: Lens-deployed-product cutover path

**Question:** How does the existing CIRISLens Python lens (with
`cirislens-core` Rust crate) consume `ciris-lens-core` once it ships?

**Options:**
- **A — Replace `cirislens-core` wholesale.** CIRISLens links
  `ciris-lens-core` instead. The existing `cirislens-core` retires.
- **B — Sit alongside.** `cirislens-core` keeps doing what it does
  today (scrub callback for persist + validation/security/sanitize);
  `ciris-lens-core` adds the cohort + scoring layer. Both run in the
  same Python lens process.
- **C — Lift the scrubber into `ciris-lens-core`** (gift it from
  patterns_from_cirislens_core/scrubber/), retire that subset of
  `cirislens-core`, leave the rest (validate/security/sanitize/route)
  in CIRISLens until those concerns are handled by Edge or retired.

**Starting position:** C. The scrubber is the only piece of today's
`cirislens-core` that genuinely belongs in lens-core's per-trace
pipeline. The rest either migrates to Edge (validation, security
sanitization) or stays with the lens-deployed-product (storage
routing, mock detection) or gets retired (Engine.receive_and_persist
already does signature verification).

**Status:** OPEN — sequencing decision; depends on Phase 1 implementation
landing the scrubber port first.

---

## OQ-07: ManifoldConformity discretization at federation publication

**Question:** LC-AV-14 closure says federation-published scores get
discretized (coarse bands) to defeat differential-observation attacks.
What's the discretization shape?

**Options:**
- **A — Five-band discretization**: high / above-average / typical /
  below-average / low. Per-cohort adjusted.
- **B — Quartiles within the cohort** with explicit
  "below-min-sample" indicator for cold-start.
- **C — Three-band**: conforms / atypical / anomalous. Coarse;
  hard to invert; loses information.

**Starting position:** B (quartiles + cold-start indicator).
Operationally meaningful; harder to invert than five bands; preserves
the cold-start signal that LC-AV-18's `indeterminate` produces.

**Status:** OPEN — RATCHET will weigh in based on the published-
signal information-leak budget.

---

## OQ-08: Build attestation parity with persist + edge

**Question:** Should `ciris-lens-core` publish a signed BuildManifest
to CIRISRegistry on every release, same shape as persist + edge?

**Starting position:** Yes. Every signed primitive in the federation
publishes its own provenance — there's no "library exemption."

**Status:** OPEN, but trivial yes. Confirm at v0.1.0 release prep.

---

## CLOSED

### OQ-09 (CLOSED 2026-05-03): Extract module is static-coded, not schema-driven

**Resolution:** Lift concerns #1 (step timestamps), #2 (observation
weights), #4 (full-component blobs) from
`patterns_from_cirislens_core/extraction/metadata.rs` into
`src/extract/`. **Drop concern #3** (schema-driven dynamic field
rules) entirely.

**What concern #3 was:** the legacy crate read field rules from a
`schema_cache` (`get_field_rules(schema_version, event_type) ->
Vec<{json_path, db_column, data_type, required}>`) and applied them
dynamically. Output type was `HashMap<String, String>` keyed by
`db_column` — designed to populate analytics-DB columns for the
lens-deployed-product's downstream Postgres-derived schema.

**Why drop:** lens-core writes detection events, not analytics rows.
Detector inputs are TYPED FEATURES (`Features` struct), not
stringified DB columns. Configurable extraction was an operator-
convenience for lens-deployed-product (add columns without re-
deploying); lens-core is a federation-deterministic library where
extraction logic is version-stamped per `lens_core_version` (LC-AV-19).
Post-fold, there's no analytics schema for these rules to feed.

**If configurability ever becomes load-bearing:** RATCHET ships
extraction parameters via the OQ-03 calibration delivery channel,
same as detector parameters. Single mechanism for "stuff RATCHET
ships." Do not re-introduce a schema cache.

---

### OQ-10 (CLOSED 2026-05-03): Resourcing classification — derived analytic, not Phase 1 cohort axis

**Resolution (updated 2026-05-04, RATCHET-confirmed):** Cohort cells
at v0.1.0 are the **6-tuple** of agent-declared `deployment_profile`
fields (CIRISAgent FSD `TRACE_WIRE_FORMAT.md` §3.2):

```
(agent_role, agent_template, deployment_domain, deployment_type,
 deployment_region, deployment_trust_mode)
```

`deployment_resourcing` (TRACE_WIRE_FORMAT.md §3.3, lens-computed,
4-band closed enum) is **NOT in the cohort key** — used for
explainability/analytics, not routing.

**Two false starts before this lock-in:**

1. **Initial closure (5-tuple, my mistake)**: drew from
   `deployment_profile` but dropped `agent_role` for no good reason.
2. **Projection-v1 closure (5-tuple, RATCHET's mistake)**: included
   `agent_role` but mis-named two fields (`dsdma_domain` instead of
   `deployment_domain`, `agent_type` instead of `deployment_type`)
   and missed `deployment_trust_mode` entirely.

RATCHET (2026-05-04) walked the FSD §3.2 enum closures + the 2.7.9
wire format and confirmed the cohort key is the full
`deployment_profile` 6-tuple. Sovereign vs federated_peer agents
have materially different behavioral manifolds — `deployment_trust_mode`
is load-bearing for cohort separation, not optional.

**`dsdma_domain` is a real field but NOT a cohort key.** RATCHET
confirmed `DMA_RESULTS.payload.dsdma.domain` is the per-thought
subject inferred from prompt (free-form, 247 distinct values in
n=6,465 corpus). Could be a feature dimension someday; not in
projection v1, not in the cohort key.

**Projection v1 extraction paths against 2.7.9 wire format
(RATCHET-confirmed 2026-05-04):** all 16 projection fields are
reachable in 2.7.9 traffic via JOIN across event types keyed by
`(trace_id, thought_id, attempt_index)`. Concrete paths in
CIRISLensCore#3 (projection comment) — `DMA_RESULTS.payload.csdma.*`,
`DMA_RESULTS.payload.dsdma.*`, `IDMA_RESULT.payload.*`,
`CONSCIENCE_RESULT.payload.*`. Conditional-presence pattern in 2.7.9
(50–67% present for conscience-gated fields) matches historical corpus
null rates (33–50% null) almost exactly — calibration translates
across wire versions.

**Last-CONSCIENCE_RESULT-per-thought rule (RATCHET-confirmed):** in
2.7.9, `CONSCIENCE_RESULT` fires multiple times per thought (initial
pass, recursive retries, finalization). The projection extracts ONE
conscience snapshot per thought — use the **last** `CONSCIENCE_RESULT`
row (the FINALIZE_ACTION emission) because it represents the
post-bounce stable state that shipped in the action. PDMA bounces
(4× on Tiananmen-class prompts per CIRIS-RED MISSION) change the
conscience snapshot mid-thought; final pass is the right anchor.
Lens-core's `static_extract.rs` must implement last-wins (not
first-wins like the legacy blob storage rule) for `CONSCIENCE_RESULT`
component traversal when populating `CrcFeatures`.

`deployment_resourcing` (`CIRISAgent/FSD/TRACE_WIRE_FORMAT.md` §3.3,
4-band closed enum `{scarcity, constrained, standard, abundance}`)
is **NOT a Phase 1 cohort axis**. The closed-enum value space is
normative; the threshold partition is research-grade and not
normative.

**What lens-core does compute at v0.1.0:** continuous cost/tokens/
model_class features in the `Features` struct. These are P0 inputs
to LC-AV-2 (declared-vs-inferred mismatch). Detection compares the
trace's `(cost_estimate, total_tokens, model_class)` against the
declared-cohort's expected distribution — no categorical bucketing
required.

**What lens-core does NOT compute on the v0.1.0 hot path:** the
4-band `ResourcingTier` projection. The classifier exists in
`src/cohort/resourcing.rs` for downstream analytics + post-
calibration RATCHET use, but is not called by `pipeline::lifecycle`
or by Phase 1 cohort routing.

**Why defer:** adding resourcing as a 6th cohort axis quadruples
cohort-cell count and worsens LC-AV-18 cold-start at v0.1.0 corpus
sizes. Of the threat-model citations, only LC-AV-3 (within-cohort
variance preservation) genuinely needs the tier as a categorical
axis — and LC-AV-3 is post-P0. LC-AV-2 / LC-AV-4 work on continuous
features.

**Storage:** none per-trace. Detection events that fire under
LC-AV-2 carry `(cost_estimate, total_tokens, model_class,
declared_cohort)` in their signed payload — that's all peers need
to verify the routing decision. The `cirislens.trace_context.
deployment_resourcing` column reserved in `CIRISPersist`'s V006
migration stays reserved-not-implemented at v0.1.0; post-fold-into-
agent it stays unimplemented since the agent doesn't run analytics
schemas.

**Future extension to 6-tuple:** if RATCHET's calibration determines
the tier-as-cohort-axis is load-bearing, the parameters
(`(cost_rate_table, tier_thresholds, axis_inclusion_flag)`) ride on
the OQ-03 delivery channel alongside detector parameters. Single
delivery mechanism.

---

### OQ-01 (CLOSED 2026-05-03): Persist integration — both rlib and PyO3 cdylib via Cargo feature

**Resolution:** Option C — both paths, gated by the `python` Cargo
feature already declared in `Cargo.toml`:

- **rlib (default)** — pure-Rust link to `ciris-persist`. Primary
  trajectory; what lens-core ships when consumed by agent post-fold
  per PoB §3.1.
- **PyO3 cdylib (`--features python`)** — what `CIRISLens` (the
  deployed Python product) consumes during the v0.1.0 – v0.2.x cutover
  window. Same calling convention as today's in-tree `cirislens-core`
  PyO3 binding; drop-in target.

**What unblocked closure:**

- **CIRISPersist v0.4.2 (2026-05-03)** — landed `signing::StewardSigner`
  as a Rust-public struct + prelude export, closing the only remaining
  rlib gap (CIRISPersist#17). PyO3 `Engine.steward_sign` is now a thin
  wrapper over the same struct, so both paths share one implementation.
- **CIRISPersist v0.4.1 prelude** — already exposed
  `canonicalize_envelope_for_signing`, `verify_hybrid_via_directory`,
  `body_sha256`, `FederationDirectory`, `Backend`, `OutboundQueue`.
  Combined with v0.4.2's signer, lens-core has every substrate
  primitive it needs from prelude alone.
- **CIRISEdge v0.1.0** — `VerifiedTrace` typed alias (`src/verify.rs:154`)
  and verify-via-persist pipeline; lens-core consumes `VerifiedTrace`
  with no re-verify obligation (AV-9 structural gate).

**Distribution:** persist + edge are consumed via `git = "...", tag = "vX.Y.Z"`
following the pattern edge already uses against persist. Crates.io
publication is not required; the federation distributes via tagged
git refs + PyPI for the cdylib variants.

**Open coordination item (release-prep, not blocker):** edge v0.1.0
pins persist at `tag = "v0.4.1"`. For the dep tree to unify cleanly
when lens-core pins both, edge needs to bump its persist floor to
v0.4.2 in a v0.1.1 patch release. During Phase 1 sketching lens-core
uses path deps + a `[patch.*]` override; the formal git-tag pinning
lands at lens-core v0.1.0 release prep, post-edge-v0.1.1.

---

(Other entries below were closed before the OQ list was written and
don't need to be re-litigated.)

The threat model (`docs/THREAT_MODEL.md`) closed these architectural
questions before this OQ list got written, so they don't need to be
re-litigated:

- ✓ Library vs sidecar — library (consumes Edge + Persist as Rust deps)
- ✓ Wire format — n/a, lens-core consumes verified bytes from Edge
- ✓ Hosting — folds into agent per PoB §3.1
- ✓ Detector layering — five ratchet detectors + manifold conformity
  per `coherence_ratchet_detection.md`; layered defense per LC-AV-6
- ✓ Fail-secure shape — `ManifoldConformity` enum (Numeric /
  Indeterminate / Unavailable); never silently elevated
- ✓ Detector parameter visibility — incubated in CIRIS-RED;
  framework public, operating point internal
