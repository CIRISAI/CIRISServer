# `ciris-lens-core`

The science-layer Rust crate for the CIRIS federation. Routes traces
to cohorts, scores conformity to the alignment manifold, signs
detection events. Folds into the agent post-PoB §3.1.

**Status:** Proposed. Spec + threat model + lifted patterns from
existing `cirislens-core` are in this repo; v0.1.0 implementation
work to come.

## Read in this order

1. **[`MISSION.md`](MISSION.md)** — the WHY. M-1 alignment per module;
   anti-patterns; failure modes; what mission risk looks like for each
   component.
2. **[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)** — the security
   surface. 21 LC-AVs covering score-gaming, manifold-evasion,
   cohort-routing, detector-attacks, statistical-attacks, federation-
   level. P0 must-have-at-v0.1.0 bundle: LC-AV-2, LC-AV-11, LC-AV-18.
3. **[`FSD/CIRIS_LENS_CORE.md`](FSD/CIRIS_LENS_CORE.md)** — the WHAT.
   Crate shape, public API, per-trace lifecycle (scrub → route →
   score → sign), edge + persist integration boundaries.
4. **[`FSD/OPEN_QUESTIONS.md`](FSD/OPEN_QUESTIONS.md)** — the HOW.
   Decisions deferred to implementation kickoff.
5. **[`patterns_from_cirislens_core/`](patterns_from_cirislens_core/)** —
   gifts. Working scrubber + extraction code lifted from CIRISLens's
   existing `cirislens-core` Rust crate. Proven NER+regex pipeline,
   per-field walker, ort/distilbert backends, JSONPath extraction.
   Lift into `src/scrub/` + `src/extract/` when implementation starts;
   refactor as needed.

## TL;DR

```
Edge ──(verified bytes)──► CIRISLensCore ──(signed events)──► Persist
                              │
                              ├── scrub        PII pipeline (NER + regex)
                              ├── cohort       declared + inferred routing
                              ├── detector     5 ratchet detectors + manifold
                              ├── scoring      capacity + N_eff + conformity
                              ├── pipeline     orchestrate the per-trace flow
                              └── signing      via persist.steward_sign
```

**One crate, one trace lifecycle.** Scrub + score + sign are sequential
stages of the same per-trace pipeline; splitting them artificially is
the mistake that motivated this repo.

**Consumes Edge + Persist day-1.** Verify is implicit (Edge guarantees
verified bytes before lens-core sees them; lens-core does not
re-verify). Storage is implicit (persist owns trace_events,
trace_llm_calls, federation_keys; lens-core writes detection events
via `Engine.steward_sign` + `Engine.put_*`).

**Folds into agent.** Per PoB §3.1, lens-core is "a function any peer
can run on data the peer already has." Library, not service. Every
agent runs detection on its own hot path; federation cross-validates.

## Sister repos

- [`CIRISAgent`](../CIRISAgent) — agent reasoning loop. Emits
  signed traces. Wire-format spec at `FSD/TRACE_WIRE_FORMAT.md`;
  `deployment_profile` block (CIRISAgent#718) is the declared-cohort
  input lens-core's routing layer reads.
- [`CIRISPersist`](../CIRISPersist) — substrate. Owns federation_keys,
  trace storage, canonicalization, steward signing, federation
  directory. Lens-core consumes via `Engine`.
- [`CIRISEdge`](../CIRISEdge) — federation transport. Owns wire-side
  verify; lens-core never sees unverified bytes.
- [`CIRISVerify`](../CIRISVerify) — cryptographic primitives.
  Lens-core depends transitively via persist.
- [`CIRISLens`](../CIRISLens) — the existing deployed-product Python
  layer. Currently hosts `cirislens-core` (the trace-ingest pipeline
  this crate's scrubber descends from). Will consume `ciris-lens-core`
  when implementation lands; eventually folds into agent per PoB §3.1.

## License

AGPL-3.0, matching the rest of the CIRIS federation stack.
