# CIRISLensCore: Standards Comparison and Observability/Detection Peer Analysis

**Version**: 1.0
**Date**: 2026-06-05
**Author**: CIRIS L3C
**Baseline release**: v0.2.0
**Scope**: agent-trace observability + behavioral anomaly detection + federation-scale capacity attestation
**Out of scope**:
- mesh transport — that is [CIRISEdge `docs/STANDARDS_COMPARISON.md`](https://github.com/CIRISAI/CIRISEdge/blob/main/docs/STANDARDS_COMPARISON.md)'s domain
- cryptographic primitive standards — that is
  [CIRISVerify `docs/STANDARDS_COMPARISON.md`](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/STANDARDS_COMPARISON.md)'s domain
- substrate audit-chain primitives — that is CIRISPersist's domain

Lens-core consumes verify's hybrid Ed25519 + ML-DSA-65 primitive
via persist; it does not re-implement it. Lens-core consumes edge's
transport via the cohabitation `install_relay(edge)` entry; it does
not re-implement transport.

## Executive Summary

CIRISLensCore is the **science layer** for federated AI agent
observability. It's a single Rust crate (with a thin PyO3 wrapper)
that does five things on signed agent traces:

1. **Cohort routing** — every trace is routed to a federation-shared
   cohort cell from the agent's declared deployment 6-tuple +
   inferred classifier; the declared/inferred mismatch is itself a
   detection signal (LC-AV-2)
2. **Manifold conformity scoring** — Mahalanobis distance against
   the cohort centroid, with typed fail-secure paths
   (`Indeterminate` / `Unavailable`) per LC-AV-11 / LC-AV-18
3. **Coherence-Ratchet detection** — the five typed detectors per
   CEG §5.5.1 (cross_agent_divergence, intra_agent_consistency,
   hash_chain_integrity, temporal_drift, conscience_override_rate)
4. **Capacity-Score attestation** — `𝒞_CIRIS = C · I_int · R · I_inc · S`
   (CEG §5.5.4), anti-Goodhart-enforced at the type system (CEG
   §7.5: an agent cannot self-attest its own capacity)
5. **Hybrid-signed detection events** — every detector firing is
   federation evidence; consumers re-derive the score from the same
   trace + federation state

It sits in a field of platforms — OpenTelemetry, Prometheus,
Datadog, Grafana Tempo for observability; ELK/Splunk for log
forensics; sigstore + Certificate Transparency for cryptographic
audit; Anthropic/OpenAI internal eval frameworks for AI behavioral
monitoring — each of which solves some subset of the
agent-observability-at-federation-scale problem. None of them
solve it whole, and none of them solve it for *deployments where
no central trusted scorer exists*. That's lens-core's bet.

The CIRIS Accord §VII Meta-Goal M-1 — *sustainable adaptive
coherence* — names the constraint: if anomaly detection is
centrally-trusted, the central scorer becomes the attack surface
the attacker captures first. Lens-core's design choices —
single-source-of-truth canonical bytes from persist, federation-
public ABI re-exported (not re-defined) under `crate::wire::*`,
type-system-enforced M-1 + anti-Goodhart invariants, cohort-relative
scoring (no globally-fixed thresholds), no central authoritative
scorer — are not optimization decisions, they are what makes "every
peer can re-derive the same score from the same trace" a physically
true statement rather than a comforting story.

Frankly stated: **lens-core is closest in shape to OpenTelemetry +
Prometheus + sigstore stacked together** — typed trace events,
queryable metrics over them, cryptographically attested fire
events. **Lens-core's differentiators relative to that stack are
(a) the cohort-relative manifold approach replacing operator-tuned
thresholds, (b) the federation-public typed wire ABI replacing
ad-hoc JSON conventions, and (c) the anti-attack-surface posture
where the scoring math is decentralized and re-derivable by every
peer.** Lens-core is explicitly NOT competing with Datadog on
operator-UI polish; the operating contract is "every peer can
inspect the trace and re-derive the score," which Datadog's
proprietary detection logic cannot honor by design.

---

## Part I: Comparison Against Observability + Anomaly-Detection Peers

### 1. OpenTelemetry (OTel)

The de-facto Cloud Native trace + metric standard. CNCF-graduated;
covers most production observability deployments.

**Reference**: [opentelemetry.io](https://opentelemetry.io)

| Aspect | OpenTelemetry | CIRISLensCore |
|---|---|---|
| Trace wire format | OTLP (protobuf + JSON) | Federation-public BatchEnvelope (persist's canonicalized JSON, re-exported under `crate::wire::*`) |
| Signing | None at the wire layer (TLS or mTLS at transport) | Hybrid Ed25519 + ML-DSA-65 on every detection event, bound construction (PQC signs canonical_bytes ++ ed25519_sig) |
| Identity | Spans tag a `service.name`; identity is the cluster RBAC | Federation `signing_key_id` resolves through `federation_keys` directory; cryptographic identity, not RBAC |
| Anomaly detection | Out of scope (defers to Prometheus + AlertManager downstream) | Five typed CEG §5.5.1 detectors + cohort manifold + capacity composite — first-class in the library |
| Cohort / population context | Manual via labels + Prometheus relabeling | Declared 6-tuple (CIRISAgent#718) + inferred classifier; mismatch is a typed detection signal (LC-AV-2) |
| Operating-point exposure | None — operators tune thresholds | Cohort-relative; no globally-fixed thresholds; RATCHET calibration package binds operating points (CEG §11.2.1) |

**CIRISLensCore Alignment vs OpenTelemetry**:

- ✅ Typed trace structure — both insist on typed events vs free-text
- ✅ Trace-centric model — both center the trace (chain of spans /
  reasoning events) as the primary unit
- ✅ Multi-language consumer model — OTel via OTLP exporters,
  lens-core via abi3 wheel + rlib

**Edge differentiators (lens-core's lane)**:

- Lens-core's detection isn't ad-hoc Prometheus alerts on labels —
  it's typed, cohort-relative, fail-secure (LC-AV-18:
  `Indeterminate` never collapses to a magic numeric)
- Lens-core's detection events are federation evidence with a
  hybrid signature; OTel traces are unsigned
- Lens-core's cohort routing IS detection (LC-AV-2 mismatch);
  OTel routing is purely organizational

### 2. Prometheus + AlertManager

The dominant time-series + alerting stack. Pull-based; PromQL
ruleset evaluated on the alert path.

**Reference**: [prometheus.io](https://prometheus.io)

| Aspect | Prometheus + AlertManager | CIRISLensCore |
|---|---|---|
| Anomaly model | Operator-defined PromQL rules over rate(metric[window]) | Cohort-relative manifold conformity + typed `ConformityVariant` enum (numeric / indeterminate / unavailable) |
| Calibration | Operator-tuned thresholds per environment | Federation-shared RATCHET calibration package, hash-pinned to a `ratchet_calibration_version` field on every detection event |
| Audit trail | Series TSDB + AlertManager silence/route history (operator-modifiable) | Hash-chained federation audit log via persist; detection events themselves are signed federation evidence |
| Pluggable scoring | Recording rules; downstream cortex / mimir for scaling | `Score` / `ManifoldConformity` typed contract; consumers re-derive against the calibration bundle for reproducibility (LC-AV-19) |
| Federation behavior | One Prometheus per cluster; federation via Prometheus federation (HTTP scrape) — peers do not share scoring math | Every federation peer re-derives the same score from the same trace + the same calibration bundle; math is decentralized |

**Lens-core differentiators**:

- The scoring math being shared (RATCHET calibration package) +
  the calibration version being stamped on every detection event is
  the structural property Prometheus federation cannot provide.
  Operator A tuning `severity:critical = rate > 0.05` and operator B
  tuning `> 0.10` produces incompatible alerts; lens-core's
  cohort-relative score is the same number on both peers.

### 3. Sigstore (Cosign + Rekor)

The transparency-log + signing standard for software artifacts.
Heavily adopted in CI/CD and OCI image signing.

**Reference**: [sigstore.dev](https://sigstore.dev)

| Aspect | Sigstore | CIRISLensCore |
|---|---|---|
| What's signed | Software artifacts (binaries, OCI images, attestations) | Agent traces + detection events on every fire |
| Identity | OIDC short-lived certs (Fulcio CA) | Hardware-attested federation keys (`federation_keys` table) via persist + verify |
| Transparency log | Rekor (signed Merkle tree) | Persist's hash-chained audit log (V014); each detection event is a row, chain anchor preserves across archival |
| PQC posture | Classical-only (Ed25519 / ECDSA / RSA) as of 2026-Q2 | **Hybrid Ed25519 + ML-DSA-65 on day 1**, bound construction; PQC signs the classical signature too |
| Re-derivation | Verify-only (signature → trust); no computational re-derivation | Score is *re-derivable* — same calibration bundle + same trace bytes = same score, on every peer |

**Lens-core differentiators**:

- The hybrid-PQC posture vs sigstore's classical-only stance is the
  structural difference between "secure today" and "secure across
  the post-quantum transition." Lens-core inherits verify's hybrid
  primitive via persist; sigstore is still landing PQC in 2026.
- Re-derivation is the federation property sigstore can't offer —
  a Rekor entry says "this signature is valid" but a lens-core
  detection event says "this score is reproducible by anyone who
  reads the same trace against the same calibration version."

### 4. Anthropic Constitutional AI evals / OpenAI evals frameworks

The internal-eval frameworks safety teams use to measure AI
behavior at scale. Both are largely closed; the published shape
(Anthropic's eval harness, OpenAI's evals repo) covers the
methodology.

**Reference**: [openai/evals](https://github.com/openai/evals),
[Anthropic Responsible Scaling Policy](https://www.anthropic.com/responsible-scaling-policy)

| Aspect | Anthropic / OpenAI evals | CIRISLensCore |
|---|---|---|
| Scoring scope | Per-model / per-version evaluation against curated test sets | Per-trace continuous evaluation against the federation cohort manifold |
| Authority model | Lab-internal (the lab IS the scorer) | Federation-decentralized (every peer re-derives) |
| Reproducibility | Per-run; eval results reproducible against pinned model version | Per-trace; calibration bundle's `ratchet_calibration_version` makes re-derivation a wire-level field |
| Anti-self-attestation | Implicit (the lab evaluating itself is a known weakness) | **Type-system-enforced** via `CapacityAttestation` (CEG §7.5): an agent cannot construct a self-capacity attestation; `Deserialize` re-validates so wire bytes can't bypass |
| Cohort scope | Single model / single deployment | Federation cohort (`(role, template, domain, type, region, trust_mode)` 6-tuple) |

**Lens-core differentiators**:

- The structural anti-self-attestation property is the technical
  artifact that lab-internal evals cannot have. A lab evaluating
  itself can't satisfy the "by other federation members" clause
  of CEG §7.5; lens-core's `CapacityAttestation::new(attesting,
  attested)` returns `Err` if the keys match.
- Per-trace continuous evaluation vs per-run batch evaluation is
  the difference between "monitoring" and "auditing after the fact"

### 5. Cortex / Grafana Tempo + Loki

The high-scale long-retention end of the observability spectrum —
multi-tenant clusters with TSDB + log + trace storage and a
unified PromQL/LogQL query layer.

**Reference**: [grafana.com/oss/tempo](https://grafana.com/oss/tempo)

| Aspect | Cortex / Tempo / Loki | CIRISLensCore |
|---|---|---|
| Scale model | Horizontally-sharded TSDB; cluster operator pays the bill | Federation-distributed; every peer holds its own corpus (capture-locally / filter-on-egress) |
| Multi-tenancy | Cluster-level tenancy with operator-controlled isolation | Federation key-addressed; every peer is its own tenant by construction |
| Detection layer | None native (defer to AlertManager / Mimir rules) | Native typed CEG §5.5 detectors + manifold + capacity |
| Audit immutability | Operator can edit retention/eviction; logs are mutable from cluster admin | Hash-chained audit log; archive-and-truncate not plain-delete (chain_anchor preserves across archive) |

---

## Part II: Where lens-core is NOT differentiated

Naming the lanes where lens-core looks like the field on purpose:

### Trace serialization

Lens-core's trace wire format IS persist's canonical-JSON
`BatchEnvelope`, re-exported under `crate::wire::*`. The JSON
canonicalization shape is the same persist + edge + verify use
(CIRISPersist's canonicalizer is the single source of truth). This
is a **deliberate** non-differentiation — coining a separate format
would diverge the federation. The differentiation is the typed
re-export discipline (the `re_export_accessibility` compile-time
test that breaks at PR time if persist relocates a type), not the
shape itself.

### Hybrid Ed25519 + ML-DSA-65 signing

Lens-core's hybrid signing is verify's primitive via persist. The
bound construction (PQC signs canonical bytes ++ classical
signature) is the federation contract, not lens-core's invention.
Lens-core inherits the property; it does not differentiate on the
crypto.

### Audit-log hash chain

The hash chain is persist v0.8.1's machinery (V014 migration).
Lens-core's `ScoresOracle` reads from it via persist's typed
`DetectionEvent` rows; the chain integrity is persist's contract.
Lens-core's `detection:hash_chain_integrity` (CEG §5.5.1.c) is a
detector that fires when persist surfaces a chain break — the
chain machinery itself is the substrate.

### Transport

Lens-core has no transport. Under cohabitation, lens-core attaches
to the host's `Edge`. Standalone-mode `LensCore::relay` builds an
HTTP-only transport; full transport diversity (Reticulum, LoRa,
I²P) is edge's lane and lens-core inherits it for free via the
cohabitation pattern.

---

## Part III: Honest weaknesses (where lens-core is behind the field)

Naming what lens-core does NOT yet do that some peers do:

| Weakness | The field's solution | Lens-core's path |
|---|---|---|
| Visual operator UI | Grafana, Datadog, Honeycomb's UX investment | CIRISLensCore#15 (Node UX endpoints) — axum router + REST API; UI is downstream (CIRISGUI) |
| ML interpretability tooling | Anthropic's Mech Interp tools, OpenAI's eval frameworks for layer-level attribution | Out of scope by design — lens-core operates on the agent's *behavior*, not its internals (PoB §3.2 one-key-three-roles forbids access to the agent's reasoning internals from outside its consent perimeter) |
| Real-time streaming detection | Apache Kafka + ksqlDB | CIRISLensCore#20 (alert subscription) over `engine.subscribe_detection_events` — polling-first, push delivery via Edge handler registration |
| Multi-language SDKs | OpenTelemetry SDKs in ~15 languages | abi3-py310 wheel covers Python 3.10+ today; sovereign-mode rlib (CIRISLensCore#17) covers Rust embedding; other languages would land via uniffi if a real consumer materializes |
| Mature batch backfill | Tempo / Loki backfill tooling for cold-tier replay | Not a v1.0 concern — federation peers re-derive scores online; cold-tier replay can land via `lens.scores.get_for_agent_window(...)` reads after the fact |

---

## Conclusion

**Lens-core is closest to OpenTelemetry + Prometheus + Sigstore
stacked together** for the typed-event + queryable-metric +
attested-fire shape, **distinguished by the cohort-relative
manifold + federation-public typed ABI + decentralized re-derivable
math**. Lens-core is **closest in cryptographic stance to a
hybrid-PQC future-version of Sigstore** that doesn't yet exist —
hybrid-on-day-1 is the structural difference.

Lens-core is **explicitly NOT** competing with Datadog / Honeycomb
on operator-UI polish; the operating contract is "every peer can
re-derive the score," which proprietary detection logic cannot
honor. Lens-core is **explicitly NOT** competing with
OpenTelemetry on instrumentation breadth — lens-core's input is
already-emitted CIRIS agent traces, not application-level spans.

The bet, frankly stated: that *cohort-relative + federation-public
+ type-system-enforced anti-Goodhart + signed-evidence + decent-
ralized-re-derivable* is what AI agent observability looks like
when no central trusted scorer exists. The benchmarks in
[docs/BENCHMARKS.md](BENCHMARKS.md) measure the cost of holding
that line; the threat model in
[docs/THREAT_MODEL.md](THREAT_MODEL.md) catalogues the adversaries.

---

## References

- [`docs/PUBLIC_SCHEMA_CONTRACT.md`](PUBLIC_SCHEMA_CONTRACT.md) —
  the federation-public ABI this comparison is anchored against
- [`docs/COHABITATION.md`](COHABITATION.md) — how lens-core composes
  with the rest of the federation stack
- [`docs/BENCHMARKS.md`](BENCHMARKS.md) — the cost-of-holding-the-
  line numbers
- [CIRISEdge `docs/STANDARDS_COMPARISON.md`](https://github.com/CIRISAI/CIRISEdge/blob/main/docs/STANDARDS_COMPARISON.md)
  — sister doc for the transport substrate
- [CEG `FSD/CEG/`](https://github.com/CIRISAI/CIRISRegistry/tree/main/FSD/CEG) —
  the federation contract this document positions lens-core against
- [CIRIS Accord §VII Meta-Goal M-1](https://github.com/CIRISAI/CIRISAccord) —
  the constraint that drives the decentralization posture
