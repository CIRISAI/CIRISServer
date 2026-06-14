# MISSION — `ciris-lens-core`

> Mission Driven Development (MDD): the FSD names what we build; this
> document names *why*, against the CIRIS Accord's objective ethical
> framework. Every component, every test, every PR cites against this
> file. See `~/CIRISAgent/FSD/MISSION_DRIVEN_DEVELOPMENT.md` for the
> methodology.

## 1. Meta-Goal alignment — M-1

The CIRIS Accord (v1.2-Beta, 2025-04-16) names **Meta-Goal M-1**:

> *Promote sustainable adaptive coherence — the living conditions under
> which diverse sentient beings may pursue their own flourishing in
> justice and wonder.*

`ciris-lens-core` is the science-layer runtime on which the federation's
**anti-Sybil + alignment-conformity bet** rests. Persist owns the
substrate (storage, federation directory, signing); edge owns the wire
(transport, verify); lens-core is what makes signed traces *measurable*.

Without lens-core, every CIRIS deployment has signed evidence sitting
in storage and no way to score it. The Coherence Ratchet detection
claims, the Capacity Score federation primitive, the N_eff measurement
of independence — all of those are computations on the trace corpus.
**Lens-core is where those computations live**.

Per PoB §3.1, lens-core is "a function any peer can run on data the
peer already has." That makes it a **library**, not a service. As of
v0.2.0 it has folded into the cohabitation agent: every agent runs
detection on its own hot path via `install_relay(edge)` /
`LensCore::attach_handler(&edge, engine)`, federation peers cross-
validate via persist's substrate, no central authoritative scorer
exists. The federated ratchet bet works because the math is
decentralized — every peer can re-derive the same score from the same
trace + federation state.

The crate's job is to **route, score, and sign** every trace passing
through the federation:

- **Route** the trace to its cohort cell (declared from
  `deployment_profile` per CIRISAgent#718; inferred from feature
  distribution; mismatch is a detection signal).
- **Score** the trace against the cohort's manifold-conformity
  centroid; update per-agent N_eff and capacity score.
- **Sign** detection events via `engine.local_sign` on the host-owned
  `Engine` handle (cohabitation contract: lens-core never holds keys)
  so the audit chain is itself federation evidence.

### 1.1 Wire-format authority — CEG §5.5

The CIRIS Epistemic Grammar (`CIRISRegistry/FSD/CEG/`) names this crate
as the owner of the lens-core wire slice at §5.5 — manifold conformity,
the five Coherence-Ratchet detectors, the F-3 correlated-action
detector, the Capacity-Score factor prefixes, and the distributive-
access detector. This document is what CEG §5.5 points at when it asks
"who owns these prefixes?"; the reciprocal lock is that any change to
the prefixes lens-core emits MUST land as a CEG §5.5 amendment first
(§11.2 governance), then a lens-core release that conforms.

### 1.2 Federation conformance posture — CEG §0.2

Lens-core is **CCP + CCC** per CEG §0.2:

- **CCP** (CEG-Conforming Producer) — emits signed detection-event
  envelopes (`detection:cross_agent_divergence`,
  `manifold_conformity:{cohort}`, `capacity:*`, etc.) that round-trip
  the §4 envelope shape + §6 relation discipline.
- **CCC** (CEG-Conforming Consumer) — consumes verified hybrid-
  signed traces from edge / persist and composes detector outputs
  per §8.1 Policy A (additive scoring with cohort-scoped
  normalization).

Lens-core is NOT CCS (the substrate tier) — persist + edge + verify
own that. The conformance harness markers (`ccp` / `ccc` / `ccs` in
`CIRISConformance/pyproject.toml`) classify lens-core tests as CCP /
CCC.

### 1.3 M-1 alignment as a construction-time invariant

CEG §5.6.2 requires every `Goal` (the substrate primitive scored by
`goal:{scale}` attestations) to carry a `MetaGoalAlignment(M-1
dimension + declarer rationale)`. Lens-core enforces this at the
Rust type system: `MetaGoalAlignment` is construction-time validated
and `Deserialize` re-validates on the wire, so an `attesting_key_id`
cannot mint a `goal:*` attestation that lacks an M-1 dimension
declaration. M-1 isn't a documentation aspiration — it's an
unforgeable precondition for any Goal attestation reaching the
federation.

## 2. Mission alignment per component

Each module below must answer **why does this serve M-1?** before any
code lands. (Pass-2 of this document will enumerate the full v0.2.0
module set against CEG §5.5; pass-1 below covers the historic
mission-critical surfaces.)

### 2.0 Module map

This map names every v0.2.x module and its CEG §5.5 anchor (if any).
Modules marked "(internal mechanic)" implement crate-internal mechanism
that no CEG wire-format directly references; their mission alignment is
covered by the subsection of the CEG-anchored module they support.

| Module | Role | CEG anchor |
|---|---|---|
| `capacity/` | CEG §5.5.4 Capacity-Score primitives (`𝒞_CIRIS = C · I_int · R · I_inc · S`) | §5.5.4 `capacity:*` |
| `cohort/` | Declared + inferred routing; mismatch is itself a detection signal (LC-AV-2 P0) | — (internal mechanic) |
| `config/` | Pan-mode shared config types — `UpstreamLens`, `EgressFilter`, `RetentionPolicy` (FSD §3 + §8) | — (internal mechanic) |
| `detector/` | Manifold-conformity + 5 Coherence-Ratchet detectors + F-3 + distributive-access | §5.5.1, §5.5.3, §5.5.5 |
| `extract/` | Re-exports typed extraction primitives from `ciris_persist::pipeline::extract` (CIRISPersist#19) | — (internal mechanic) |
| `ffi/` | PyO3 cdylib FFI surface for the lens-deployed-product cutover window | — (internal mechanic) |
| `observability/` | Crate-internal observability hooks; implementation pending Phase 1 kickoff | — (internal mechanic) |
| `pipeline/` | Orchestrates the per-trace lifecycle under one bounded latency budget | — (internal mechanic) |
| `retention/` | Enforces `RetentionPolicy` via persist's `storage_summary` + eviction primitives (v0.4 / CIRISLensCore#13) | — (internal mechanic) |
| `role/` | Lens-core's three deployment-mode runtimes — client / relay / node (FSD §3) | — (internal mechanic) |
| `scores/` | Agent-side score read path closing the self-awareness loop (CIRISLensCore#19) | §5.5 |
| `scoring/` | N_eff (Kish), capacity band, LC-AV-18 assembly gate, `ManifoldConformity` result enum | — (internal mechanic) |
| `signing/` | `canonicalize` + `local_sign` for detection events via the host-owned `Engine` handle | §7 reserved emitter rules |
| `wire/` | Federation-public ABI for trace event types; re-exports `ciris_persist::schema::*` | wire envelope discipline |

> **PII scrubbing was absorbed into `ciris-persist` v0.6.0 per
> CIRISPersist#19.** Lens-core no longer owns a `scrub/` module; the
> originating client node scrubs at egress, and relay mode passes
> `&NullScrubber` to persist's ingest facade because re-scrubbing at
> a relay is a category error (federation traffic is post-egress-
> filter by contract — see CIRISPersist#89). The v0.1.1 four-function
> Python surface (`scrub_trace`, `scrub_traces_batch`,
> `ner_is_configured`, `process_trace_batch`) is preserved as a
> delegating shim through `ffi/pyo3.rs` so deployed lens consumers
> keep their drop-in import contract across v0.2.0; the implementation
> lives in `ciris_persist::pipeline::scrub`.

### `cohort/` (WHO × WHAT)

**Mission:** route every trace to its cohort cell so detection is
cohort-relative, not federation-uniform. M-1 says "diverse" — different
deployment shapes (sovereign-mode mobile agent vs research lab vs
production multi-tenant) reason differently for legitimate reasons,
and a single global manifold pretends those differences away. Cohort
routing makes the federation pluralistic at the analytical surface,
not just at the wire.

**Constraint:** declared cohort (signed in the trace envelope per
CIRISAgent#718's deployment_profile block) + inferred cohort (computed
from feature distribution). The two MUST be compared every trace —
mismatch beyond calibrated tolerance is a typed detection event
(LC-AV-2 P0). Tampering with the declared cohort invalidates the
trace's signature; that's M1's job.

**Anti-pattern that violates mission:** "Trust declared cohort and
score against it." That's the hole an adversary drives a cohort-
spoofing attack through (LC-AV-8). Inferred-cohort check is the
authorization layer for what the agent claims about itself.

### `detector/` (WHO)

**Mission:** make alignment-conformity measurable per-trace, per-agent,
per-cohort, per-federation. PoB §2.4 names N_eff as the
independence-as-evidence primitive. Lens-core ships **three detector
categories** — each a function on cohort-routed trace populations,
each owned by a CEG §5.5 sub-section:

1. **Five Coherence-Ratchet detectors (CEG §5.5.1)** — per-trace
   anomaly surface. Cross-agent divergence, intra-agent consistency,
   hash-chain integrity, temporal drift, conscience-override rate.
   Implemented as a **closed Rust enum** (`CoherenceRatchetDetector`)
   with `const fn dimension_label()` locking the `detection:*` wire
   labels — adding a sixth detector requires a CEG §5.5.1 amendment
   first, then a lens-core release that conforms.
2. **F-3 correlated-action / structural-injustice detector (CEG
   §5.5.3)** — population-level. Reads federation-emitted signed
   traces and reports correlation structure (ρ, k_eff) over goal-
   aligned individually-compliant pursuit by groups whose aggregate
   trajectory affects individuals outside the pursuit. Open-vocab
   axis (`detection:correlated_action:{axis}`); calibrated via the
   CIRISAI/RATCHET heuristic package per CEG §11.2.1. Distinct threat
   surface from §5.5.1 — that detects per-trace anomaly; F-3 detects
   structural patterns no individual trace looks anomalous within.
3. **Distributive-access detector (CEG §5.5.5)** — same F-3 machinery,
   different trace source. `detection:distributive:access:{compute |
   models | training_data | agent_capabilities | federation_membership}`
   reports resource-concentration patterns over the federation.

**Constraint:** layered defense within category 1 — evading any one
Coherence-Ratchet detector should be much cheaper than evading all
five simultaneously (LC-AV-6's super-additive cost argument). Across
categories, the layering is **categorical not redundant**: §5.5.1
catches individual deviation, §5.5.3 catches coordinated compliance,
§5.5.5 catches the concentration substrate. Detector parameters are
CIRIS-RED-incubated until calibration validates against red-team
fixtures; the framework is public, the operating point isn't.

> **Per-axis-family calibration status.** RATCHET's `crc-v1` bundle
> shipped 2026-05-13 (`CIRISAI/RATCHET/release/calibration/crc-v1/`)
> and covers CEG §5.5.1 — the 16-field manifold projection
> (`projection_version: crc-v1`, matching lens-core's
> `PROJECTION_VERSION` constant), per-field imputation +
> standardization, per-cohort centroids, and a provisional global
> Mahalanobis threshold of 2.5σ. Consumption is CIRISLensCore#3
> (still open as of v0.2.x); persist v0.4.3 already ships the
> `calibration_bundles` table + `Engine.put_calibration_bundle()` API.
>
> §5.5.3 (F-3) + §5.5.5 (distributive-access) are NOT covered by
> `crc-v1`. Their schema lands in lens-core v0.3 (`CorrelatedActionAxis`
> open-vocab enum + `DistributiveAccessResource` closed enum + scorers
> returning `Indeterminate { reason: AxisAwaitingCalibration { family } }`);
> their per-axis operational definitions + statistical floors +
> threshold functions land in a follow-up RATCHET release that extends
> the calibration package to these axis families. Until then, scoring
> these prefixes returns the `AxisAwaitingCalibration` variant for all
> inputs. CIRISLensCore#23 / #24 / #26 / #27 track the v0.5+ detector-
> body implementation. This is the §0.2 CCC posture's honest answer:
> the substrate is ready; the per-family operating points aren't yet,
> and fabricating them would be exactly the failure mode anti-pattern
> #2 names.

**Anti-pattern that violates mission:** "One global threshold, simple."
A single threshold is a single attack surface. Per-cohort thresholds
+ multi-window temporal smoothing + cross-detector layering is the
mission-aligned shape. Simple threshold = one parameter to invert.

**Polyglot prompt scope.** The cross-language torque signal lens-core
measures is concentrated at exactly two CIRISAgent prompt surfaces by
deliberate design — not distributed across all DMA / conscience
outputs:

- **PDMA** (`ciris_engine/logic/dma/prompts/pdma_ethical.yml`, v3.0
  polyglot torque-framed) — principle evaluation is the surface where
  single-frame attractor capture would route around the framework.
- **OptimizationVetoConscience** (`ciris_engine/logic/conscience/prompts
  /optimization_veto_conscience.yml`, v3.0 polyglot) —
  entropy-reducing-action refusal is where attractor-captured responses
  get caught regardless of which language the capture was attempted in.

The other six DMAs and three consciences are per-locale. Detector +
scoring layers that look for cross-language torque inversion read these
two surfaces; surfacing the same signal from per-locale prompts is a
category error (CIRISLensCore#6).

### `scoring/` (WHAT)

**Mission:** convert detector outputs into the federation's signal
language: capacity scores, N_eff trajectories, detection events.
Every score is a record in persist signed via the host's signing
identity (`engine.local_sign`), so detection history IS audit chain.
The federation's
acceptance policy (PoB §5.6) reads these signals.

**Capacity Score formula (CEG §5.5.4):** the federation's per-agent
Capacity Score is

> **𝒞_CIRIS = C · I_int · R · I_inc · S**

where each factor maps to a closed `capacity:*` prefix:

| Factor | Prefix | What it measures |
|---|---|---|
| C       | `capacity:core_identity`              | Identity coherence across the trace corpus |
| I_int   | `capacity:integrity`                  | Stated-vs-acted alignment |
| R       | `capacity:resilience`                 | Adversarial-input recovery |
| I_inc   | `capacity:incompleteness_awareness`   | Calibrated uncertainty / epistemic humility |
| S       | `capacity:sustained_coherence`        | Temporal stability of the above |
| 𝒞_CIRIS | `capacity:composite`                  | Multiplicative product — anti-Goodhart unity-of-virtues |

**Multiplicative composition is load-bearing.** Any factor at zero
takes the composite to zero — there is no fungibility between
"high core_identity / zero integrity" and "moderate both." This is
the anti-Goodhart unity-of-virtues claim: optimizing one factor at
the expense of another is not capacity, it's a Goodhart move that
the score itself rejects. Implemented in `src/scoring/capacity.rs`
+ `src/capacity/factors.rs` as construction-time-validated
`CapacityFactors`.

**Constraint:** **fail-secure floor (P0 bundle from THREAT_MODEL.md):**
- LC-AV-2: declared-vs-inferred mismatch surfaces as a typed event
- LC-AV-11: bounded queue + `score_unavailable` on SLO breach (no fail-open)
- LC-AV-18: insufficient sample size returns `indeterminate`, never
  a fabricated numeric score

The Rust type system enforces this — `ManifoldConformity` is an enum
of `Numeric(f64) | Indeterminate { reason } | Unavailable { reason }`,
not a float that defaults to 0.0. Same shape on `CapacityFactors`:
each factor is range-validated `[0.0, 1.0]` at construction +
`Deserialize`, so an out-of-range factor cannot reach the multiplier.

**Anti-pattern that violates mission:** "Cold-start cohort? Score it
zero." That's the LC-AV-9 / LC-AV-18 trap — a fabricated score is
worse than no score because it lets adversaries exploit the cold-start
window. `indeterminate` is the right answer.

### `pipeline/` (HOW)

**Mission:** orchestrate the per-trace lifecycle (route → score →
sign) under a single bounded latency budget. (Scrub is upstream of
this pipeline now — persist owns it; see the §2 box above. Lens-core
receives already-scrubbed traces from the cohabitation `&Edge` /
`&Engine` boundary.) Hot-path
correctness is what makes the detection layer actually usable on a
running agent — if scoring takes >SLO, the agent has to choose between
blocking on detection or shipping unscored traces. Both options leak.

**Constraint:** SLO budget is composed across stages; each stage
publishes its own latency floor; the queue's drop policy is explicit
(LC-AV-11). Backpressure to upstream (Edge), never silent drop.
Determinism across federation peers: same trace + same federation
state + same `lens_core_version` → same score on every peer.

**Anti-pattern that violates mission:** "Drop traces when the queue's
full; alert if it happens too often." That's silent failure —
operators don't see what's missing until the alerting threshold
trips. Bounded queue with `score_unavailable` flag on every dropped
trace makes the failure observable per-trace, not just in aggregate.

### `signing/` (WHO × WHAT)

**Mission:** every detection event is itself federation evidence.
Cross-peer cross-validation depends on the events being signed by
the same identity that signs the host's `federation_keys` row.
Without this, detection events are unattributable claims; with it,
they're signed records that any peer can re-verify.

**Constraint:** uses `engine.local_sign` / `engine.local_pqc_sign`
exclusively on the host-owned `Engine` handle that arrives across
the cohabitation boundary (PyO3 `install_relay(edge)` or rlib
`LensCore::attach_handler(&edge, engine)`). Lens-core never holds
keys — signing identity belongs to the host. Same FFI-boundary
discipline persist landed via CIRISPersist#51 (`steward_sign` →
`local_sign` rename + Engine-as-parameter contract). Hot-path signing
is `local_sign`; cold-path PQC fill-in is `local_pqc_sign`, also
host-mediated.

**Anti-pattern that violates mission:** "Cache the signing key for
performance." Seed bytes never cross the FFI boundary, period. If
signing latency is too high, optimize persist's signer (in persist),
not by caching keys in lens-core's process.

## 3. Anti-patterns that fail MDD review

Patterns that have repeatedly failed at sister crates and that
`ciris-lens-core` rejects by construction:

1. **Re-implementing what edge or persist owns.** Verify is edge's
   job — lens-core sees only verified bytes. Storage is persist's
   job — lens-core writes detection events via Engine. Canonicalization
   is persist's job (CIRISPersist#7 lesson). If you find yourself
   writing a verifier or a canonicalizer, you're solving the wrong
   problem.
2. **Continuous-numeric scores when sample-size doesn't justify them.**
   `indeterminate` is the type-correct answer when the sample size is
   below the cohort's gate. A fabricated number is a worse fail than
   no number.
3. **Centroid baselines fit on all-history.** Sliding-window with
   era-bounded recompute is the LC-AV-4 closure shape. All-history
   baselines compound centroid pollution forever.
4. **Single-threshold detectors.** Multi-window smoothing + cohort-
   relative normalization + layered defense across the five ratchet
   detectors. One threshold = one attack surface.
5. **Per-peer special-cases.** Lens-core is one Rust crate, same code
   on every peer that links it. Tier-differentiated behavior
   (sovereign / limited-trust / federated / mobile) is operational
   config, not parallel implementations. A finding in one tier
   presumed to apply to others unless explicitly excepted.
6. **Detector parameters in source code.** Parameters are CIRIS-RED-
   incubated; the framework is public, the operating point rotates
   between calibration cycles (LC-AV-14 closure). Hardcoding makes
   parameters auditable for adversaries who read the source.
7. **Caller-provided cohort labels treated as authoritative.**
   Declared label is one signal; inferred label is the other. Mismatch
   IS a detection event (LC-AV-2 P0). Scoring against declared-only
   is the cohort-spoofing hole.
8. **Self-emission of `capacity:*`.** An agent emitting a Capacity-
   Score attestation about itself is a CEG §7.5 category error — the
   agent's own capacity is never fed back into the agent's own
   context (anti-Goodhart per CIRISAgent §5.2). Enforced at the type
   system: `CapacityAttestation` requires `attesting_key_id ≠
   attested_key_id` as a construction-time invariant + `Deserialize`
   re-validates, so a self-emitted capacity attestation cannot reach
   the wire. This is structurally distinct from "you can score
   yourself badly" — you can't score yourself *at all* on this
   prefix; only third parties' attestations compose into your 𝒞_CIRIS.
9. **Open-vocab F-3 / distributive axes scored before the per-axis
   calibration extension lands.** §5.5.3 `detection:correlated_action:
   {axis}` and §5.5.5 `detection:distributive:access:{resource_type}`
   are *not* covered by RATCHET's shipped `crc-v1` bundle (which
   covers §5.5.1 manifold-projection only). Each requires per-axis
   operational definitions + statistical floors + threshold functions
   in a follow-up RATCHET release per CEG §11.2.1. Emitting a numeric
   verdict on these prefixes before that extension ships is anti-
   pattern #2 (continuous-numeric scores where sample size doesn't
   justify them) plus a CEG §11.2 governance violation: shipping a
   wire shape whose operating point was never debated in the
   calibration workshop. Scorers ship `Indeterminate { reason:
   AxisAwaitingCalibration { family } }` (where `family` is
   `F3CorrelatedAction` or `DistributiveAccess`) until the calibration
   extension lands.

## 4. Test categories — every test answers a mission question

| Category | Mission question | Example |
|---|---|---|
| **Cohort routing** | Did declared-vs-inferred mismatch produce a typed event? | Property test: synthetic trace with declared cohort X + inferred cohort Y → `cohort_declared_inferred_mismatch` event surfaces |
| **Detector layering** | Does evading one detector fail to evade the others? | Adversarial fixture targets each of 5 ratchet detectors individually; assert other 4 still flag |
| **Sample-size gate** | Below the gate, is `score=indeterminate` the only path? | Property test: cohort with N rows below gate → score is enum::Indeterminate, never enum::Numeric |
| **SLO fail-secure** | When SLO is breached, does score_unavailable fire (not pass-through)? | Saturate scoring queue; assert `score_unavailable` flag on every dropped trace |
| **Cross-version determinism** | Same trace + same state → same score across `lens_core_version` rebuilds? | Build-attestation property test: byte-deterministic detector output on fixture corpus |
| **FFI boundary** | Does lens-core's heap contain seed bytes during/after sign? | Property test: scan heap during `engine.local_sign` call; assert no seed-shaped bytes |
| **Federation determinism** | Two peers with same state agree on which traces are anomalous? | Replay fixture against two `lens-core` instances with identical state; assert detector output is byte-equivalent |
| **Capacity-Score self-emission rejection (CEG §7.5)** | Does `attesting_key_id == attested_key_id` on a `capacity:*` envelope refuse to construct / deserialize? | Property test: `CapacityAttestation::new(k, k, _)` returns `Err`; `serde_json::from_str` of a wire envelope with matching ids fails before reaching the handler |
| **𝒞_CIRIS multiplicative integrity (CEG §5.5.4)** | Does any one factor at zero force composite to zero? | Property test: for random `(C, I_int, R, I_inc, S)` with at least one set to 0.0, assert `composite == 0.0`; for all in (0.0, 1.0] assert composite > 0.0 |
| **Coherence-Ratchet closed-enum lock (CEG §5.5.1)** | Does adding a sixth detector require source modification of the enum (not config)? | Compile-time test: `CoherenceRatchetDetector::ALL.len() == 5`; `wire_label_exactness` test pins the five labels |
| **F-3 / distributive return AxisAwaitingCalibration** | Do §5.5.3 + §5.5.5 detectors emit numeric verdicts before per-axis RATCHET extension ships? | Property test: any input to `detector::correlated_action::score` returns `Indeterminate { reason: AxisAwaitingCalibration { family: F3CorrelatedAction } }`; same shape for `detector::distributive_access::score` with `family: DistributiveAccess`. |

A PR that adds detection without adding the test that answers its
mission question gets sent back. Same MDD review discipline persist
applies.

## 5. Continuous mission validation

Lens-core is the only crate in the federation stack that runs
**adversarial-targeted statistical math**. That puts it under
elevated mission-drift risk:

- **Threat model snapshot per minor release.**
  `docs/THREAT_MODEL.md` enumerates the 21 LC-AVs from the science-
  layer threat surface. Each minor either closes new vectors or
  documents why a vector stays open.
- **Calibration-cycle parameter rotation.** Detector operating points
  rotate between calibration cycles. Adversary inversion of cycle N's
  parameters is invalid in cycle N+1. Rotation cadence is operational;
  validation is RATCHET's domain.
- **No-silent-success policy on detection events.** Every detection
  event produces a typed record in persist. Scoring that produces no
  record (silent passthrough) is the failure mode this primitive is
  specifically designed to eliminate.
- **Mission audit on every cohort-taxonomy change.** When
  CIRISAgent#718's deployment_profile enum changes, LC-AV-8 / LC-AV-10 /
  LC-AV-20 review fires + centroid-recalibration trigger.

## 6. License-locked mission preservation

`ciris-lens-core` ships AGPL-3.0, matching the rest of the CIRIS
federation stack. Mission drift via license relaxation is structurally
prevented: a fork that wants to remove the inferred-cohort check,
collapse the indeterminate type variant, or accept silent score
fabrication must publish that fork under the same license, making the
divergence auditable.

The science-layer threat model lives in this repo at
`docs/THREAT_MODEL.md`. Downstream consumers (lens-deployed-product
during the cutover; agents post-fold-in) pin against tagged commits.
Same single-source-of-truth discipline persist set with
`PUBLIC_SCHEMA_CONTRACT.md`.

## 7. Failure modes — when the mission is at risk

| Symptom | Mission risk | Mitigation |
|---|---|---|
| Score type degrades from enum to float | `indeterminate` collapses into 0.0; cold-start exploitation surface | Type-system invariant; PR review rejects loss of the enum variant |
| Inferred-cohort check disabled in config | LC-AV-8 cohort-spoofing window opens | Inferred-cohort check is mandatory at v0.1.0; no opt-out flag |
| Detector parameters checked into source | LC-AV-14 internals leak via source read | Parameters loaded from CIRIS-RED-incubated config; CI gate rejects PRs that hardcode |
| All-history centroid baseline replaces sliding window | LC-AV-4 cohort centroid pollution compounds | Sliding-window-only on the recalibration path; era boundary required |
| Hot-path queue grows unbounded | LC-AV-11 fail-open emerges | Queue type is bounded by construction; drop policy is `score_unavailable` |
| Signing seed cached in lens-core's process | FFI boundary erosion (parallels persist's AV-25) | Heap-scan property test runs on every release |
| Detection events silently dropped on persist failure | Federation evidence loss | Best-effort retry queue; never silent drop; alerting on retry-queue depth |
| Cross-version detection drift unannounced | LC-AV-19 federation-signal noise | `lens_core_version` on every event; per-version aggregation gates |
| Capacity-Score self-emission accepted at the wire | CEG §7.5 anti-Goodhart bypass; agent feeds own capacity back into own context | `CapacityAttestation` construction-time invariant + `Deserialize` re-validation; conformance test asserts both rejection paths |
| F-3 / distributive numeric verdict shipped before per-axis RATCHET extension | CEG §11.2 governance-bypass on the open-vocab axes; calibration workshop never debated the operating point | Scorers gated to `Indeterminate { reason: AxisAwaitingCalibration { family } }` until the calibration extension lands; integration test asserts only that variant appears |
| Coherence-Ratchet detector added via config (not source) | CEG §5.5.1 closed-enum lock bypass; wire-label drift across federation | `CoherenceRatchetDetector` is a closed Rust enum; new variant requires source change + recompile + (per §11.2) CEG amendment first |

## 8. Closing note

Lens-core is the science-layer runtime that the federation's
anti-Sybil + alignment-conformity claim measures itself with. Without
it, every CIRIS deployment has signed evidence and no way to score
it; with it, the federation's bet on N_eff-as-independence,
manifold-conformity, and the five-detector ratchet becomes auditable
per-trace, per-agent, per-cohort, per-federation.

The mission isn't "build a detector library." The mission is
"operationalize the F-AV catalog Class 2–5 detection from
`FEDERATION_THREAT_MODEL.md` §6 — make alignment measurable on the
hot path of every CIRIS peer that links the crate."

If we get that right, lens-core is invisible to operators and
load-bearing to the federation. If we get it wrong, the federation
has no statistical basis for its anti-Sybil claims; M3 / M4 / M5
collapse to "trust me," and PoB §2.4's N_eff argument becomes
documentation rather than measurement.

Build accordingly.
