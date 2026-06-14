# FSD: CIRISLensCore — Science-layer runtime for the CIRIS federation

**Status:** Proposed
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.7
**Created:** 2026-05-03
**Repo:** `~/CIRISLensCore` (this document is the spec; code lands in this repo)
**Risk:** Architectural. Implements the science-layer runtime per
`docs/THREAT_MODEL.md` (21 LC-AVs). Does NOT replace any production
path — the existing CIRISLens Python ingest + cirislens-core scrubber
keep running until this crate is consumable; lens cuts over when
v0.1.0 ships and the P0 bundle (LC-AV-2 / LC-AV-11 / LC-AV-18) is
calibrated.

---

## 1. Why this exists

CIRIS has the trace evidence and no science layer to score it. Today:

- **CIRISAgent** emits signed reasoning traces with the
  `deployment_profile` block at 2.7.9 (CIRISAgent#718). Cohort labels
  declared, signed, on the wire.
- **CIRISPersist** stores them. `trace_events` + `trace_llm_calls` +
  `federation_keys`. Audit chain intact.
- **CIRISEdge** (in flight) carries them between peers. Reticulum-
  native; verify-via-persist before any byte reaches the host.
- **CIRISLens** runs the existing Python lens with `cirislens-core`
  Rust crate — which does scrub + validate + security-sanitize +
  field-extract + storage-routing.

What's missing: the **detection layer**. Cohort-relative manifold-
conformity scoring. Per-agent N_eff. Capacity score. The five ratchet
detectors. PoB §2.4's federation-level independence claim is
documentation, not measurement, until that math runs on the hot path
of every CIRIS peer.

`CIRISLens/docs/THREAT_MODEL_CORE.md` (now `~/CIRISLensCore/docs/THREAT_MODEL.md`)
landed 2026-05-03 with 21 LC-AVs scoping the science-layer threat
surface. Three P0 invariants must hold at v0.1.0:

```
LC-AV-2   Inferred-vs-declared cohort mismatch detection
LC-AV-11  Bounded scoring queue; score_unavailable on SLO breach
LC-AV-18  Min-sample-size gate; indeterminate, not fabricated numeric
```

Without those, lens-core has no defensible operating envelope. The
remaining 18 LC-AVs are layered defenses on top.

`ciris-lens-core` is the Rust crate that implements the detection
layer. It consumes Edge (verified bytes) and Persist (substrate +
signing) day-1; it produces signed detection events that go back into
persist's audit chain. Per PoB §3.1, it folds into the agent —
becoming a library every CIRIS peer links against rather than a
service the federation depends on.

## 2. Why one crate, not two

The original framing in CIRISLens was to split today's `cirislens-core`
(scrub + validate + extract + sanitize) from a future `lens-core`
(cohort + detector + scoring). That was the wrong shape. Operator
pushback (correctly) identified the artificial separation: scrub and
score are sequential stages of the same per-trace lifecycle.

```
Edge (verified bytes arrive)
    ▼
SCRUB         strip PII per trace_level (generic bypass; detailed
              strips text; full_traces NER+regex)
    ▼
COHORT-ROUTE  declared cohort (signed envelope) + inferred cohort
              (feature distribution); mismatch is a detection event
    ▼
SCORE         manifold conformity vs cohort centroid; N_eff;
              capacity score; 5 ratchet detectors
    ▼
SIGN          via persist.steward_sign; detection event becomes
              part of the audit chain
    ▼
Persist (event lands as signed record)
```

One pipeline. One bounded latency budget. One crate. The trace flows
through stages — splitting stages into separate Rust crates would
require N × (FFI + observability + error-mapping + threat-model
maintenance) overhead for zero architectural benefit.

## 3. Scope

This FSD specifies a Rust crate, **`ciris-lens-core`**, delivered in
phases:

| Phase | What lands | Risk |
|---|---|---|
| **Phase 1** (v0.1.0) | Crate skeleton with the P0 bundle live: scrub pipeline (lifted from existing cirislens-core); cohort routing with declared+inferred mismatch; bounded scoring queue with `score_unavailable`; insufficient-sample `indeterminate` enum variant. **CIRISLens consumes this in-repo** (replaces the existing cirislens-core scrubber path while the existing Python lens runs). | Low — replaces in-repo crate one stage at a time; no production cutover. |
| **Phase 2** (v0.2.x) | Calibrated detector operating points land per CIRIS-RED's validation schedule. P1 LC-AVs close. Federation-level cross-peer score agreement gates federation signal publication. | Medium — calibration + cross-peer protocol; coordinated with RATCHET's release cadence. |
| **Phase 3** (post-fold) | Lens-core folds into agent per PoB §3.1. Each agent runs detection on its own hot path; federation cross-validates via persist. CIRISLens deployed-product retires (or scopes down to operator UI only). | Higher — touches every peer; coordinated tag pin across the federation stack. |
| **Out of scope** | Operator-facing HTTP / Grafana / OAuth (lens-deployed-product's job). Trace transport (Edge's job). Trace storage (Persist's job). Wire-format verification (Edge does verify-via-persist; lens-core sees only verified bytes). |

The phases are differentiated by **calibration maturity and fold
trajectory**, not by architectural separation:

- **Phase 1** delivers the fail-secure floor (P0 bundle).
- **Phase 2** brings calibrated operating points online.
- **Phase 3** folds the library into agent.

## 4. Crate shape

```
ciris-lens-core/
├── Cargo.toml              ← deps: ciris-persist (rlib), ciris-edge (rlib),
│                              ort, tokenizers, serde, regex, sha2, tokio,
│                              tracing, opentelemetry
├── MISSION.md              ← M-1 alignment per module
├── README.md               ← pointer + read order
├── FSD/
│   ├── CIRIS_LENS_CORE.md  ← this file
│   └── OPEN_QUESTIONS.md   ← decisions deferred to implementation
├── docs/
│   └── THREAT_MODEL.md     ← 21 LC-AVs (lifted from CIRISLens 2026-05-03)
├── src/
│   ├── lib.rs              ← public API surface
│   ├── pipeline/           ← orchestrates scrub → route → score → sign
│   │   ├── mod.rs
│   │   └── lifecycle.rs    ← per-trace bounded-latency pipeline
│   ├── scrub/              ← PII pipeline (lift from cirislens-core)
│   │   ├── mod.rs
│   │   ├── ner.rs          ← DistilBERT INT8 backend
│   │   ├── regex.rs        ← email/phone/IP/URL/SSN/CC patterns
│   │   ├── walker.rs       ← recursive JSONB field traversal
│   │   ├── fields.rs       ← 21-field scrub map per CIRISLens FSD §5
│   │   └── tier.rs         ← per-trace_level dispatch
│   ├── cohort/             ← cohort routing + mismatch detection (LC-AV-2)
│   │   ├── mod.rs
│   │   ├── declared.rs     ← parse deployment_profile from envelope
│   │   ├── inferred.rs     ← compute cohort from feature distribution
│   │   └── mismatch.rs     ← typed event when declared != inferred
│   ├── detector/           ← manifold conformity + 5 ratchet detectors
│   │   ├── mod.rs
│   │   ├── manifold.rs     ← per-trace conformity to cohort centroid
│   │   ├── divergence.rs   ← cross-agent divergence detector
│   │   ├── intra_agent.rs  ← intra-agent stability detector
│   │   ├── hash_chain.rs   ← audit-chain integrity detector
│   │   ├── temporal.rs     ← temporal drift detector (multi-window)
│   │   └── conscience.rs   ← conscience-override pattern detector
│   ├── scoring/            ← capacity score + N_eff + result types
│   │   ├── mod.rs
│   │   ├── capacity.rs     ← capacity score (bounded by federation N_eff)
│   │   ├── n_eff.rs        ← Kish formula (LC-AV-15 cohort-relative)
│   │   └── result.rs       ← ManifoldConformity { Numeric / Indeterminate / Unavailable }
│   ├── extract/            ← feature extraction (lift from cirislens-core)
│   │   ├── mod.rs
│   │   ├── json_path.rs
│   │   └── features.rs     ← cohort + detector input feature pipeline
│   ├── signing/            ← detection event signing via persist
│   │   ├── mod.rs
│   │   └── event.rs        ← signed-record shape; persist.steward_sign integration
│   └── observability/      ← OTLP metrics + structured per-event logs
│       ├── mod.rs
│       └── metrics.rs
├── benches/
│   ├── scrub_bench.rs      ← lift from cirislens-core/benches/scrubber_bench
│   ├── cohort_bench.rs     ← P1 — bounded latency on cohort routing
│   └── score_bench.rs      ← P1 — bounded latency on full pipeline
├── tests/
│   ├── golden_test.rs      ← lift from cirislens-core; fixture corpus
│   ├── property/
│   │   ├── score_type_invariant.rs   ← LC-AV-18: never numeric below gate
│   │   ├── cohort_mismatch.rs        ← LC-AV-2: mismatch produces event
│   │   ├── slo_fail_secure.rs        ← LC-AV-11: SLO breach → score_unavailable
│   │   ├── ffi_boundary.rs           ← heap-scan during steward_sign
│   │   └── cross_version_determinism.rs ← LC-AV-19: byte-deterministic detector output
│   └── integration/
│       └── full_lifecycle.rs ← Edge → scrub → route → score → sign → Persist round-trip
├── patterns_from_cirislens_core/  ← gift code; lift into src/ when impl starts
│   ├── scrubber/                  ← 9 files; proven NER+regex pipeline
│   └── extraction/                ← 3 files; JSONPath + metadata helpers
└── LICENSE                        ← AGPL-3.0
```

## 5. Public API surface

```rust
use ciris_lens_core::{LensCore, Score, ManifoldConformity};
use ciris_persist::Engine;
use ciris_edge::VerifiedTrace;

// Construction. lens-core takes the persist Engine (federation_keys
// directory, steward signing identity, trace storage).
let core = LensCore::builder()
    .persist(persist_engine)                 // ciris-persist::Engine
    .cohort_centroids(centroid_baseline)     // RATCHET-calibrated baseline
    .scoring_slo(Duration::from_millis(50))  // Phase 1 SLO budget
    .build()?;

// Hot path: per-trace score-and-sign. Returns the score + the
// detection events (if any). Score events are signed and persisted
// internally; caller doesn't manage signing.
let outcome = core.process(verified_trace).await?;

match outcome.score {
    Score::Conformity(ManifoldConformity::Numeric(score)) => {
        // Standard case — sufficient sample size, score in band
    }
    Score::Conformity(ManifoldConformity::Indeterminate { reason }) => {
        // LC-AV-18 fail-secure — insufficient sample. Federation
        // acceptance falls through to M1+M2 fallback.
    }
    Score::Conformity(ManifoldConformity::Unavailable { reason }) => {
        // LC-AV-11 SLO breach OR persist-read failure. Operationally
        // visible; never silently elevated to a numeric score.
    }
}

// Detection events (optional; produced when any of the 5 ratchet
// detectors flag, OR when LC-AV-2 declared-vs-inferred mismatch fires)
for event in outcome.detection_events {
    // Already signed, already persisted. Caller can observe + alert.
    tracing::info!(detector=%event.detector, severity=%event.severity, ...);
}
```

The Rust type system enforces the P0 invariants:
- `ManifoldConformity` is an enum with three variants. Calling code
  cannot accidentally treat `Indeterminate` as 0.0 or any other
  numeric value.
- `Score` carries the variant + the cohort + the `lens_core_version`
  + the detection events as one bundle. Per-event aggregation is the
  receiver's job; lens-core hands a complete record.

## 6. Day-1 integration: edge + persist consumed implicitly

### Edge (verify is implicit)

Lens-core's `process(verified_trace)` takes a `VerifiedTrace` —
edge's output type. By construction, every byte in a `VerifiedTrace`
has already been:

- Ed25519-verified against persist's federation_keys directory
- canonicalized via persist's `Engine.canonicalize_envelope`
- deduped via persist's AV-9 tuple
- replay-protected via edge's `(signing_key_id, nonce)` window

Lens-core does NOT re-verify. The `VerifiedTrace` type carries an
edge-issued attestation that all checks passed; constructing one
outside edge's control is intentionally awkward. CIRISPersist#7
lesson holds: byte-stable crypto behavior belongs in one place; lens-
core consumes the result.

### Persist (storage + signing implicit)

Lens-core's signing path is `engine.steward_sign(canonical_event_bytes)`.
The seed never crosses the FFI boundary (same discipline persist
established for v0.2.2). Detection events are signed records written
back to persist via `engine.put_detection_event` (or equivalent
typed write — naming pending Phase 1 implementation; a tracked OQ).

Lens-core does NOT manage its own DB connection. It reads cohort
centroids from persist (via the `Engine`'s read surface) and writes
detection events via persist's typed write. The lens-core process
holds the `Engine` handle, calls into persist, never holds keys or
opens its own connection.

## 7. Module mission alignment (per MDD)

Each module's mission is named in `MISSION.md` §2; one-sentence
summary here for the FSD:

| Module | One-sentence mission |
|---|---|
| `pipeline/` | "Orchestrate the per-trace lifecycle under one bounded latency budget; backpressure to upstream, never silent drop." |
| `scrub/` | "Strip PII deterministically per trace_level while preserving cryptographic provenance." |
| `cohort/` | "Route every trace to a cohort cell using declared (signed) + inferred (computed) labels; surface mismatches as typed detection events." |
| `detector/` | "Make alignment-conformity measurable via layered defense across five ratchet detectors and manifold conformity to cohort centroid." |
| `scoring/` | "Convert detector outputs into the federation's signal language: capacity, N_eff, conformity — with `indeterminate` as a first-class variant when sample size doesn't justify a number." |
| `extract/` | "Pull cohort + detector input features from trace payloads via schema-driven JSONPath; deterministic across federation peers." |
| `signing/` | "Make every detection event federation evidence by signing with the host's steward identity via persist.steward_sign." |
| `observability/` | "Make every per-trace decision auditable via OTLP metrics + structured logs; SLO breach observable per-trace." |

## 8. Anti-patterns (call out in PR review)

1. **Re-implementing edge or persist primitives.** No verifier in
   lens-core; Engine.receive_and_persist owns it. No canonicalizer
   (CIRISPersist#7). No transport (Edge). Find yourself implementing
   one → wrong layer.
2. **Untyped score returns.** `f64` instead of `ManifoldConformity`.
   The enum variant IS the contract; type-erasing it loses the
   invariant.
3. **Single-detector reliance.** Five ratchet detectors layered.
   Code that runs only one and returns "looks fine" is the LC-AV-6
   evasion path.
4. **Detector parameters in source.** Parameters load from CIRIS-RED-
   incubated config; CI gate rejects PRs that hardcode thresholds.
5. **Centroid baselines without era-bound sliding window.** All-
   history baselines compound LC-AV-4 pollution forever.
6. **Caller-trusted declared cohort.** Always compare declared vs
   inferred; mismatch IS a detection event (LC-AV-2 P0).
7. **Silent passthrough on persist failure.** Detection event signing
   fails → retry queue, not silent drop. SLO breach → `score_unavailable`,
   not pass-through.

## 9. Test categories

Tested against the 21 LC-AVs from `docs/THREAT_MODEL.md` §4 + the
mission-question table in `MISSION.md` §4:

```
property/score_type_invariant.rs    LC-AV-18: never numeric below gate
property/cohort_mismatch.rs          LC-AV-2: mismatch surfaces event
property/slo_fail_secure.rs          LC-AV-11: SLO breach → unavailable
property/ffi_boundary.rs             FFI: no seed bytes in lens-core heap
property/cross_version_determinism.rs LC-AV-19: byte-deterministic outputs

integration/full_lifecycle.rs        Edge → process() → Persist round-trip

golden_test.rs                       Fixture corpus (lift pattern from
                                     CIRISLens/cirislens-core/tests/)

benches/                              Hot-path latency budget verification
```

## 10. Build-manifest provenance for `ciris-lens-core` itself

Same hybrid Ed25519 + ML-DSA-65 build-manifest pattern lens uses
today (`scripts/emit_lens_extras.py` + `.github/workflows/docker-publish.yml`):

- Per-release `LensCoreExtras` JSON (FSD content hash, threat-model
  hash, persist + edge version pins, calibration baseline ref).
- Hybrid sig via `ciris-build-sign` (transitively installed via persist).
- Registered with CIRISRegistry on every release.
- Round-trip verified before tag publishes.

## 11. References

- Mission: `MISSION.md` — M-1 alignment per module.
- Threat model: `docs/THREAT_MODEL.md` — 21 LC-AVs.
- Open questions: `FSD/OPEN_QUESTIONS.md` — implementation-time decisions.
- Patterns to lift: `patterns_from_cirislens_core/` — proven scrubber
  + extraction code.
- Architectural collapse argument (lens-core folds into agent):
  `~/CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md` §3.1.
- Cohort declaration source (deployment_profile block):
  `~/CIRISAgent/FSD/TRACE_WIRE_FORMAT.md @ v2.7.9-stable`,
  CIRISAgent#718, CIRISPersist v0.3.4.
- N_eff substrate: `~/CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md` §2.4.
- Coherence ratchet detectors:
  `~/CIRISLens/FSD/coherence_ratchet_detection.md`.
- Federation threat-model context (F-AV catalog Class 2–5):
  `~/RATCHET/FEDERATION_THREAT_MODELS/FEDERATION_THREAT_MODEL.md` §6.
- Persist substrate API:
  `~/CIRISPersist/MISSION.md`, `~/CIRISPersist/docs/PUBLIC_SCHEMA_CONTRACT.md`.
- Edge transport:
  `~/CIRISEdge/MISSION.md`, `~/CIRISEdge/FSD/CIRIS_EDGE.md`.
