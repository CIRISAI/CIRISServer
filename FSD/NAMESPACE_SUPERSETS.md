# Namespace Supersets — CI-Rubric Grounding + Field-Processor Matrix (FSD)

> **Manifest v0.3.0** · rubric `CI-6axis+constitutional-invariants` · **104 families** (universe 104: 95 registered — 92 with a round-1 seed + 3 no-seed — plus **9 UNREGISTERED**) clustered into 15 archetypes.
>
> Sources: namespace registry `CIRISPersist v21.4.0 (source_sha256 ade64edccce493e99f2617d236b1dffd6b99e2dfae91a9a4c012c9f4dfd6c64b, CC 1.0-rc2)`; constitution rev `d192341`; CI rubric `https://ciris.ai/contextual-integrity`.

Machine-readable companion: [`namespace_supersets.json`](./namespace_supersets.json) — carries every family's full round-1 superset spec **plus** the round-2 rubric block (CI six-axis, constitutional invariants, placement fields, primitive requirements, deltas, flags), and the derived `hoist_list`, `field_processor_matrix`, `field_standardization`, `duality_audit`, `freshness_floor`, `field_transforms`, `invariant_registry`, `primitive_gap_report`, `registry_coverage_gap`, and `evidence_export`.

## Changelog

- **0.1.0** — card-superset seed: 92 families to 15 archetypes; base "hamburger" + per-namespace superset.
- **0.2.0** — rubric grounding: each family walked against the CIRIS Contextual-Integrity six-axis rubric and grounded in constitutional invariants; every placement field reduced to a named processor (`field_processor_matrix`, the centerpiece); union hoist list of typed-EnvelopeCore candidates; admission-gate `invariant_registry` (518 invariants); `primitive_gap_report` vs CIRISPersist v21.4.0 / CIRISEdge v14.4.0 reality; `evidence_export` as ready-to-append `cc_impl.tsv` rows. 3 previously no-seed families (`attestation:hardware_rooted`, `key_boundary:{scope}`, `manifold_conformity:{cohort}`) analyzed round-2-first.
- **0.3.0** — **UNREGISTERED-families addendum.** 9 families that are live (or live-adjacent) in production but carry **no row in the 95-family CC-1.0-RC2 registry**, walked on the same rubric and merged in (nothing from 0.2.0 was discarded — every prior family object, invariant, archetype and evidence row is byte-identical). Universe 95 → 104; invariants 518 → 571; distinct placement fields 232 → 265; evidence rows 40 → 77. New sections: **§10 registry coverage gap** (root cause + 9 proposed registry rows + 8 CC-amendment asks), **§11 field standardization** (10 same-thing-different-name clusters), **§12 duality audit** (9 logical gaps + 14 axiomatic asymmetries), **§13 freshness floor** (the proposed signed `fresh_as_of` lower bound), **§14 field transforms** (the total transform algebra).

### How 0.3.0 extends this document

| Existing section | What 0.3.0 added |
|---|---|
| §4 hoist list | 33 new fields; 8 existing rows gained demanders; hoist-recommended 18 → 40 |
| §5 field-processor matrix | 265 rows (was 232); addendum rows carry a new `asymmetry_kind` |
| §6 invariant registry | +53 invariants across the 9 unregistered prefixes |
| §7 primitive gap report | +13 headline gaps, +21 matrix gaps, +2 complete baselines |
| §8 evidence export | +37 rows (persist 27, edge 3, server 7) |
| §9 per-family appendix | new **§9.1** appendix for the 9 unregistered families |

---

## 1. The model: one base hamburger + one per-namespace superset

Every CEG card is built from **two layers**: a shared **base "hamburger"** (the invariant CEG-claim skeleton inherited by all 95 families) and one **per-namespace superset** (the family-specific fields).

1. **Base hamburger** — lifecycle ops (`withdraws`/`supersedes`/`recants`/`delegates_to`, each family enabling the meaningful subset), `cohort_scope` (self to family to community to affiliations to species to biosphere to federation) and its derived projection (SelfOwn / Cohort / Global), emit authority, restrictions, evidence refs, and hybrid Rooted / owns_key signing.
2. **Per-namespace superset** — the score, verdict, hash, roster, or narrative that the namespace's claim actually *says*. The only part that varies family to family.

The shape is uniform because of the **Registry-of-Record chokepoint**: all 95 CC-1.0-RC2 claim families ride as **claim-dimensions on the single `Attestation` wire kind** (one of the 14 canonical `EnvelopeKind`s), not 95 bespoke envelopes. Envelope, signing, lifecycle ops, cohort/projection routing, and restriction machinery are owned once by the base and matched exhaustively at the KindPolicy chokepoint — so a new family is *only* ever a new superset. The **archetype** (a superset-class shared by several families) is the build fan-out unit; each family maps to exactly one.

**Component ownership model** (whose code processes a placement field): `edge` = routing · `persist` = lifecycle/placement · `server` = policy · `client` = render · `verify` = attestation-verification.

**Two typed tiers vs untyped cargo.** `EnvelopeCore` types exactly 7 fields (`dimension`, `pre_rotation_commitment`, `recovers`, `references_attestation_id`, `scope`, `successor_keys`, `withdrawal_reason`); the `Attestation` base struct types 13 more (`asserted_at`, `attested_key_id`, `attesting_key_id`, `cohort_scope`, `confidence`, `context`, `epistemic_mode`, `evidence_refs`, `score`, `signed_at`, `subject_key_ids`, `valid_until`, `witness_relation`). **Everything else rides the untyped `extra` map** — the recurring "carried-but-unprocessed" defect class this round exists to surface.

---

## 2. The rubric

Round-2 walked every family against two grounding sources:

1. **CIRIS Contextual-Integrity rubric** — `https://ciris.ai/contextual-integrity`.
2. **The Constitution** (CC 1.0-rc2, rev `d192341`) + FSD constitutional invariants.

The CI walk records eight axes per family (the six-axis rubric expanded to separate the three recipient sub-rights and temporal lifecycle):

| # | CI axis | What it pins |
|---|---------|--------------|
| 1 | `sender` | Who may emit (open / no-self-emit / detector-only / substrate / authority-gated / witness-reserved). |
| 2 | `data_subject` | Whom the claim is about — `subject_key_ids` / `attested_key_id` vs a non-person object identifier. |
| 3 | `recipient_see` | Visibility scope — `cohort_scope` and derived projection. |
| 4 | `recipient_revoke` | Who may withdraw/recant, and over what. |
| 5 | `recipient_receive` | Delivery mode — pull vs active push / fan-out. |
| 6 | `information_type` | The dimension leaf + polarity (signed / boolean-via-score / positive-only / enumerated / detector-median). |
| 7 | `transmission_principle` | The consent / grant framework governing onward flow. |
| 8 | `temporal_lifecycle` | Freshness, supersede chains, deletion / erasure windows. |

Aggregation polarities (CC 4.4.2): signed to Mean(score x confidence); boolean-via-score to Min (fail-secure); positive-only to Max; enumerated to most-recent-by-`signed_at`; detector dimensions to Median.

---

## 3. Archetype taxonomy

The 95 families collapse to 15 reusable archetypes (build once, every member inherits by supplying its superset fields).

| # | Archetype | id | Families | Card component | One-line |
|---|-----------|----|:-------:|----------------|----------|
| 1 | **Canonical Capacity Score Gauge** | `capacity-score-gauge` | 6 | ScoreDialGauge — needle 0-1, method/version chip, confidence, observation-window staleness fade, prior_score_ref trend sparkline, evidence drill-down gated by capacity:audit. | Third-party (no-self-emit) normalized capacity score about a subject, on a dial with method + observation window + trend. |
| 2 | **Self-Asserted Metric Gauge** | `self-metric-gauge` | 12 | ScoreDialGauge / CompositeGauge — value vs threshold/target, mandatory self-reported badge, method_id chip, optional multi-axis/multi-slice composite, supersede-chain sparkline. | Producer-self-asserted single- or multi-slice metric on a dial/gauge, method + value + window, badged 'self-reported' (NOT canonical-scored). |
| 3 | **Reasoning-Chain Verdict Ledger** | `reasoning-verdict` | 9 | VerdictLedgerCard — verdict badge + confidence dial + decision/trace ref link + always-visible rationale_summary + capability-gated raw reasoning trace; timeline per decision_id, roster when multiple producers verdict one target. | An algorithm/faculty/model verdict over ONE specific reasoning-chain or decision instance: verdict enum + confidence + rationale, chain-of-thought strippable. |
| 4 | **Reserved Lens Detector Signal** | `detector-signal` | 7 | DetectorSignalCard — score_dial/timeline, detector provenance badge, sample window + size + confidence-interval band, method_manifest_hash chip, population/subject roster, evidence gated by lens_audit. | A lenscore_detector-only (CC 3.4.8) signed anomaly/correlation/integrity score about a subject or population, with sample window + CI + detector provenance. |
| 5 | **Open Anti-Sybil / Anomaly Flag** | `anti-sybil-flag` | 7 | FlagCard — graph/gauge/badge/timeline, correlation/anomaly score, cluster_id/member roster or suspect_refs, detector_version, review_state workflow, false-positive/recant affordance. | Open (ProducerSteward) RATCHET / anti-rollback flag — a hypothesis, not a verdict — over a cluster/actor/counter, with member roster + review workflow. |
| 6 | **Ethical Aspect Attestation** | `ethical-aspect` | 6 | AspectAttestationCard — aspect facet tabs, polarity/score, subject/act ref, narrative/rationale, evidence/reasoning-trace chain gated by ethics_audit, roster of corroborating/disputing claims per subject. | {aspect}-scoped self-attested ethical claim about a specific act/subject: polarity/score + narrative + evidence chain, grouped by subject_ref. |
| 7 | **Verification / Hash-Equality Badge** | `verification-attestation` | 8 | VerificationBadge — pass/fail badge with score-on-hover, subject/target/hash chip, checked_at + TTL 're-verify' staleness badge, evidence/manifest ref, degraded-state colouring. | Boolean-via-score verification verdict (hash-equality, license/CA/registry validity, build level) as a badge/dial backed by a continuous score + evidence + staleness. |
| 8 | **Artifact Pointer & Custody Receipt** | `artifact-custody` | 4 | ArtifactRefCard — table/badge row, kind chip, content-hash copy-and-verify affordance, locator gated by network-fetch, custody/pin/import metadata, joint-claim identity banner. | Producer/substrate self-asserted pointer to (or custody of / import of) a content-addressed artifact: kind + hash + locator + custody tier, joint-bindable to an identity. |
| 9 | **Cryptographic Proof-Chain** | `proof-chain` | 5 | ProofChainCard — leaf → audit-path/sibling hashes → computed root → compare to signed tree head/anchor; pass/fail badge + score; chained timeline via prior_*_ref; witness roster; 'verify now' action. | RFC 6962 / Merkle / hash-chain proof (inclusion, consistency, cosignature, audit-chain continuity, locale sub-manifest) rendered as a leaf→root proof chain. |
| 10 | **Substrate Self-Report Telemetry** | `substrate-telemetry` | 7 | TelemetryCard — gauge/timeline, target/hop/replica/peer ref, status/metric + measured_at with TTL decay, method tag, multi-network/multi-hop strip, observability capability gate. | Machine self-report of its own runtime state — delivery hop, transport path, peer reachability, replica lag, n_eff, liveness, identity continuity — as decaying telemetry, never a consent gate. |
| 11 | **Signed Value Ledger Entry** | `credit-ledger` | 6 | LedgerEntryCard — score_dial/table/timeline, subject/contribution ref, signed amount/score + scale, per-voter/per-domain faceting, client-side rollup to totals (each claim stays a discrete signed entry). | A discrete signed value/score entry attributed to a subject or contribution (credit, vote, rolling tally, track-record, fulfillment) that rolls up client-side into per-subject totals. |
| 12 | **Moderation / Enforcement Record** | `moderation-record` | 6 | IncidentRecordCard — feed/badge/gauge/editor, allegation/verdict/config, target/subject/entity ref, severity, evidence bundle, adjudication/appeal/review state, recant-vs-withdraw affordance; watchlist variant = versioned policy editor. | A conduct/entity record with a moderation disposition — allegation, prohibited-category trip, revocation, slashing verdict, appeal/reconsideration, or group watchlist config — raw report distinct from adjudicated sanction. |
| 13 | **Authority-Gated Record of Record** | `governance-record` | 2 | RecordOfRecordCard — proof_chain/badge, instrument/authority id + status/action, co-signer roster in a provenance/proof-chain expander, registry deep-link, issuer-driven supersede chain. | A reserved, co-signed/ratified governance or credential instrument — accord ratification or licensure — emittable only by the gated authority, superseded by re-issue, non-recantable. |
| 14 | **Descriptor / Relationship Tag Badge** | `descriptor-badge` | 3 | DescriptorBadge — enum/slug chip + optional rung/tier chip, subject/decision/partner ref, short rationale/description, supersede-history timeline for tier/rung changes. | A thin enum/role/practice descriptor badge riding fixed prefix slots — decision scale, operational method+rung, partner tier — no score, no routing, subject already in the base hamburger. |
| 15 | **Narrative / Broadcast Feed Entry** | `descriptive-feed` | 4 | FeedEntryCard — feed/timeline item, open-vocab {kind}/{domain} tag, narrative/summary/plan body, evidence refs, optional milestones stepper or contact/urgency, sensitivity/redaction handling. | Self-asserted open-vocabulary narrative or broadcast content — hard case, first-person testimony, a stated need, a strategic pathway — rendered in a feed/timeline, positive-only, no scoring. |

**Archetype deltas applied in 0.2.0** (round-2 corrections affecting archetype placement):

- accord:*: MAJOR wrong archetype: seed invented GovernanceInstrumentCard (ratify/co_scrub/amend of accord text); accord:* is a CLOSED four-leaf HUMANITY_ACCORD kill-switch namespace - replace with AccordInvocationCard
- approach:{goal_id}: card_category/superset_class wrong: use descriptive-feed/FeedEntryCard (per repo's own archetype doc sec.3.15), not Capacity/PathwayCard
- approach:{goal_id}: base_ops.delegate=false is archetype convention, not CC-sourced
- delivery:{class}: WRONG ARCHETYPE: seed modeled a per-hop proof_chain attestation (hop_from/hop_to/envelope_ref/latency_ms/delivery_outcome/retry_count); constitution defines an AGGREGATE class-keyed self-report metric like Persist's health leaves - superset class should be health/telemetry-metric
- health:liveness:{version}: TelemetrySample archetype wrong: fold riding scores, external-witness subclass - not a bespoke telemetry envelope
- moderation:{allegation_type}: ARCHETYPE WRONG: not generic content-abuse incident reporting - federation GOVERNANCE-INTEGRITY accusation against a contributor (canonical enum: rogue_vote/coordinated_voting/out_of_distribution_attestation/external_inducement_evidence/expertise_fraud); server FSD recommends content abuse ride takedown_notice+detection instead
- need:{domain}:{kind}: MAJOR seed-wrong-archetype: mutual-aid/crisis marketplace (need:medical:blood_o_neg, urgency/quantity/contact) contradicts the canonical {kind} enum - this is help-wanted for getting a Contribution through review (Tier-3 consensus sibling)
- partner_role:{role}: archetype WRONG: not a human-authored counterparty-relationship card (partner_identity_ref/reciprocal_ack_ref have no support) - a SELF-held Registry/community-issued credential badge on an agent/org key. Drop both fields.

The four load-bearing axes that separate archetypes: **(a) who may emit**, **(b) subject model**, **(c) polarity**, **(d) card shape**.

---

## 4. Hoist list — typed-EnvelopeCore candidates

> **Rule: locked when a primitive touches it, payload when it is cargo.** A field a primitive must read, gate, or uplift belongs *typed* in `EnvelopeCore` (or the `Attestation` base struct); a field that is merely descriptive cargo rides the untyped `extra` map. A field that a primitive touches but that currently rides `extra` is a **hoist candidate** — the carried-but-unprocessed defect class.

232 distinct placement fields across 532 demand-rows. **18 are hoist-recommended** (untyped, but demanded by 2+ families / touched by a primitive).

| Field | Current typing | Demand | Demanded by | Hoist? |
|-------|----------------|:------:|-------------|:------:|
| `identity_type` | untyped_extra | 10 | `accord:*`, `audit_chain:hash_continuity`, `corpus_health:n_eff_measurable`, `delivery:{class}`, `detection:correlated_action:{axis}`, `detection:distributive:access:{resource_type}`, `detection:temporal_drift`, `key_boundary:{scope}` +2 more | **YES** |
| `deletion_window` | untyped_extra | 9 | `attestation:self_verify`, `audit_chain:hash_continuity`, `capacity:composite`, `identity_continuity:relational_anchor`, `integrity:{aspect}`, `non_maleficence:{aspect}`, `ratchet:flag:density_anomaly`, `testimonial_witness:{kind}` +1 more | **YES** |
| `aggregation_policy` | untyped_extra | 5 | `detection:cross_agent_divergence`, `detection:distributive:access:{resource_type}`, `prohibited:{category}`, `ratchet:flag:density_anomaly`, `testimonial_witness:{kind}` | **YES** |
| `witness_diversity` | untyped_extra | 3 | `truth_grounding:{subject}`, `vote:{contribution_id}`, `weighted_aggregate:{contribution_id}` | **YES** |
| `achieved_tier` | untyped_extra | 2 | `dma:csdma:*`, `fidelity:explainability_sla:{tier}` | **YES** |
| `aspect` | untyped_extra | 2 | `autonomy:{aspect}`, `justice:{aspect}` | **YES** |
| `community_id` | untyped_extra | 2 | `moderation:{allegation_type}`, `reconsideration:{grounds}` | **YES** |
| `conformity_variant` | untyped_extra | 2 | `coherence_standing:{cohort}`, `detection:intra_agent_consistency` | **YES** |
| `corroborating_refs` | untyped_extra | 2 | `identity_continuity:relational_anchor`, `revocation:{entity_type}:{reason}` | **YES** |
| `decision_id` | untyped_extra | 2 | `dma:csdma:*`, `dma:pdma:*` | **YES** |
| `decision_ref` | untyped_extra | 2 | `conscience:optimization_veto`, `justice:{aspect}` | **YES** |
| `delivery_mode` | untyped_extra | 2 | `peer_reachability:{network}`, `witness_diversity:{contribution_id}` | **YES** |
| `goal_id` | untyped_extra | 2 | `approach:{goal_id}`, `goal:{scale}` | **YES** |
| `log_id` | untyped_extra | 2 | `transparency_log:consistency`, `transparency_log:cosigned:{tree_size}` | **YES** |
| `manifest_hash` | untyped_extra | 2 | `build:registered:{target}`, `provenance:build_manifest:{target}` | **YES** |
| `revocation` | untyped_extra | 2 | `licensure:{authority_id}`, `partner_role:{role}` | **YES** |
| `slashing` | untyped_extra | 2 | `detection:cross_agent_divergence`, `seed_holder_voting_alignment:{cell}` | **YES** |
| `steward` | untyped_extra | 2 | `audit_chain:hash_continuity`, `delivery:{class}` | **YES** |

Already-typed recurring fields (no hoist needed — shown for completeness of the union):

| Field | Typing | Demand |
|-------|--------|:------:|
| `dimension` | envelope_core_typed | 54 |
| `cohort_scope` | attestation_base_typed | 41 |
| `subject_key_ids` | attestation_base_typed | 32 |
| `score` | attestation_base_typed | 28 |
| `evidence_refs` | attestation_base_typed | 24 |
| `attested_key_id` | attestation_base_typed | 21 |
| `attesting_key_id` | attestation_base_typed | 20 |
| `witness_relation` | attestation_base_typed | 14 |
| `references_attestation_id` | envelope_core_typed | 11 |
| `confidence` | attestation_base_typed | 8 |
| `asserted_at` | attestation_base_typed | 5 |
| `scope` | envelope_core_typed | 5 |
| `context` | attestation_base_typed | 3 |

---

## 5. Field-processor matrix (centerpiece)

> Every placement field maps to a **processor** — a named function or gate that reads/enforces it. `UNASSIGNED` (or a `proposed:` processor) is a **defect**, listed in the gap report (section 7). Where multiple families assign the same field different owners, the row reconciles them: for the cross-cutting fields this is a **lifecycle split** (admission-validated in persist, projected/served in edge, policy-defaulted in server), not a conflict.

**232 distinct fields**: 39 fully assigned · 19 partial (some demanders have a real processor, some `proposed`) · 174 unassigned. The high unassigned count is the round-2 finding: most placement fields are carried on the wire but have no processor that reads them.

### 5.1 Cross-cutting fields (demanded by 3+ families)

| Field | Owner(s) | Representative processor | Enforcement | Status | Demand |
|-------|----------|--------------------------|-------------|:------:|:------:|
| `dimension` | edge/persist/server/verify | `src/federation/admission.rs#DimensionAdmissionPolicy::check` | admission | partial | 54 |
| `cohort_scope` | client/edge/persist/server | `src/federation/types.rs#cohort_scope::crypto_tier` | admission | partial | 41 |
| `subject_key_ids` | persist/server/verify | `src/scorer.rs#score_and_emit (deliberately grants rule-2 withdraws to scored subject - bey` | admission | partial | 32 |
| `score` | edge/persist/server/verify | `src/federation/scores.rs#score_of / value_of (BooleanMin arm) - ciris-persist@v21.4.0` | admission | partial | 28 |
| `evidence_refs` | client/edge/persist/server/verify | `src/ciris-verify-core/src/holds_bytes.rs#verify_holds_bytes` | admission | partial | 24 |
| `attested_key_id` | persist/server | `CIRISPersist/src/federation/types.rs#Attestation.attested_key_id (FK-checked)` | admission | partial | 21 |
| `attesting_key_id` | client/persist/server/verify | `src/federation/admission.rs#check_reserved_prefix_admission` | admission | partial | 20 |
| `witness_relation` | persist/server | `src/federation/admission.rs#check_capacity_not_self_attested (confirms scope-away)` | admission | partial | 14 |
| `references_attestation_id` | persist/server | `ciris-persist/src/federation/envelope.rs#EnvelopeCore (typed; witness-test bound)` | admission | partial | 11 |
| `identity_type` | persist/server | `src/accord.rs#register_holder` | admission | partial | 10 |
| `deletion_window` | UNASSIGNED | `UNASSIGNED` | UNASSIGNED | unassigned | 9 |
| `confidence` | client/persist/server | `src/federation/scores.rs#confidence_of` | admission | partial | 8 |
| `aggregation_policy` | server | `src/compose_policy.rs#polarity_for + Composer (Polarity::NegativeOnly) - IMPLEMENTED + tes` | reconcile | partial | 5 |
| `asserted_at` | persist | `src/federation/types.rs#Attestation` | admission | partial | 5 |
| `scope` | persist/server/verify | `generic EnvelopeCore.scope; no family override; seed affiliations/Cohort unreviewed agains` | admission | partial | 5 |
| `context` | client/persist | `proposed: CC 2.4.2 has no custom-field bag; sub-schema for context/evidence_refs undefined` | reconcile | unassigned | 3 |
| `witness_diversity` | persist/server | `proposed:CIRISPersist/src/federation/scores.rs#compose_verdict (witness_diversity hardcode` | promotion | unassigned | 3 |

### 5.2 Unassigned fields demanded by 2+ families (defect shortlist)

| Field | Owner(s) seen | Demanded by | Note |
|-------|---------------|-------------|------|
| `deletion_window` | - | `attestation:self_verify`, `audit_chain:hash_continuity`, `capacity:composite`, `identity_continuity:relational_anchor`, `integrity:{aspect}`, `non_maleficence:{aspect}` | NOT typed in EnvelopeCore; NO processor in any component - GDPR/erasure temporal window referenced in temporal_lifecycle |
| `context` | client/persist | `corpus_health:n_eff_measurable`, `credits:{domain}:{language}:{subject}`, `detection:correlated_action:{axis}` | multi-owner: client@render; persist@reconcile/serve |
| `witness_diversity` | persist/server | `truth_grounding:{subject}`, `vote:{contribution_id}`, `weighted_aggregate:{contribution_id}` | multi-owner: persist@serve; server@promotion/reconcile |
| `achieved_tier` | persist/server | `dma:csdma:*`, `fidelity:explainability_sla:{tier}` | multi-owner: persist@admission; server@reconcile |
| `aspect` | persist | `autonomy:{aspect}`, `justice:{aspect}` |  |
| `conformity_variant` | persist/server | `coherence_standing:{cohort}`, `detection:intra_agent_consistency` | multi-owner: persist@compile; server@compile |
| `corroborating_refs` | client/server | `identity_continuity:relational_anchor`, `revocation:{entity_type}:{reason}` | multi-owner: client@render; server@serve |
| `decision_id` | server | `dma:csdma:*`, `dma:pdma:*` |  |
| `decision_ref` | persist/server | `conscience:optimization_veto`, `justice:{aspect}` | multi-owner: persist@admission; server@reconcile |
| `epistemic_mode` | persist/server | `detection:correlated_action:{axis}`, `health:liveness:{version}` | multi-owner: persist@admission; server@compile |
| `log_id` | persist | `transparency_log:consistency`, `transparency_log:cosigned:{tree_size}` |  |
| `manifest_hash` | persist | `build:registered:{target}`, `provenance:build_manifest:{target}` |  |
| `revocation` | persist/server | `licensure:{authority_id}`, `partner_role:{role}` | multi-owner: persist@admission; server@reconcile |
| `slashing` | server/verify | `detection:cross_agent_divergence`, `seed_holder_voting_alignment:{cell}` | multi-owner: server@reconcile; verify@compile |
| `steward` | persist | `audit_chain:hash_continuity`, `delivery:{class}` |  |

The full 232-row matrix (with every processor, `processors_all`, `enforcement_points_all`, and per-field `demanded_by`) is in `field_processor_matrix` in the JSON.

---

## 6. Invariant registry (admission-gate registry)

Every constitutional invariant, keyed by prefix — 518 invariants across 95 families. Each is an admission-gate rule: `primitive_constraint` states what the primitive must require or forbid.

| Prefix | Rule | CC ref | Primitive constraint |
|--------|------|--------|----------------------|
| `accord:*` | accord:* is closed-vocabulary AND reserved: only identity_type=accord_holder keys may emit exactly four leaves; no fifth invocation_kind ever; lifecycle:active rides its own can... | CC 3.4.1 / CC 4.2.1.3 | emit gated to reserved identity_type=accord_holder; dimension is a closed enum requiring exhaustive compile-time match |
| `accord:*` | Wire-isolation is bidirectional: accord-holder keys sign ONLY the 4 leaves + EmergencyShutdown CONSTITUTIONAL + FederationAnnouncement priority=AccordCarrier; no federation-side... | CC 4.2.1 | admission-time bidirectional role check on (identity_type, dimension\|priority); FORBIDDEN outside the closed set in either direction |
| `accord:*` | accord:invoke:* is never a lone-signer claim: admission requires a threshold (>=2-of-3 genesis; entrenched quorum M/N at scale) of independent hybrid signatures over the SAME ca... | CC 4.2.1.1 / 4.2.3 / 4.2.4 | sender axis is a threshold-signature aggregate, not a single-attester scores row - requires a dedicated multi-sig verifier |
| `accord:*` | Only sanctioned reversal of a CONSTITUTIONAL halt is accord:lifecycle:active carrying resumes_halt_id bound to the specific halt; MUST be rejected if it does not match the curre... | CC 4.2.1.3 | withdraws/recants FORBIDDEN as a reversal mechanism; sole reversal path is a distinctly-domained, distinctly-thresholded sibling claim |
| `accord:*` | CC 4.2.6 requires per-invocation-kind DIFFERENTIATED thresholds over live set L (fire floor=1; roster-change/lifecycle = strict majority of L; standing = majority of standing ro... | CC 4.2.6 | admission threshold must be a function of (invocation_kind, live_set_L); uniform M/N across all four leaves is a live divergence (current shipped state) |
| `accord:*` | A CCC presenting accord invocations MUST visually distinguish all four kinds (emergency banner / non-conflated notify / [DRILL] / unambiguous reactivated state). | CC 4.2.1.2 | render-layer gate: invocation_kind must be a typed, exhaustively-matched discriminator at every consumer surface |
| `accord:*` | Substrate MUST reject a duplicate invocation_id within its valid_until window, keyed per-kind. | CC 4.2.1.1 | admission-time dedup keyed on (invocation_kind, invocation_id), not invocation_id alone |
| `activity_tier:{period}` | activity_tier is boolean-via-score, so CC 4.4.2 composes multiple attesters per (dimension, attested_key_id) via MIN (any Below-Active trumps Active) - never a mean. | CC 4.4.2 + CC 3.1.9.6 | aggregation composer MUST select the BooleanViaScore/min arm, never Signed/mean |
| `activity_tier:{period}` | LIVE DRIFT (verified): CIRISServer dimension->polarity registry has no arm for activity_tier: (or credits:/expertise:) and silently falls through to Polarity::Signed (mean), con... | CC 3.1.9.6 vs src/compose_policy.rs#polarity_for (+ exhaustiveness test omits it) | aggregation currently mis-routes activity_tier: to Signed/mean - reproducible defect (zero repo hits for activity_tier) |
| `activity_tier:{period}` | Wire pattern has no {key_id} placeholder so the CC 2.3.1/4.5.2.1 subject-bearing admission gate does NOT mechanically trigger despite a real subject; subject linkage for third-p... | CC 2.3.1 / CC 4.5.2.1 | subject-bearing admission gate NOT enforced for this wire shape |
| `activity_tier:{period}` | CC 4.4.1 Frickerian discipline is named only for testimonial_witness/non_maleficence; the constitution does NOT extend it to activity_tier despite the same bias shape (penalizin... | CC 4.4.1 | none stated; do not invent a Frickerian carve-out - flag only |
| `agent_files:{kind}:{platform_or_target}` | agent_files is a JOINT claim co-owned by CIRISRegistry (CC 3.1.1) and CIRISNodeCore (CC 3.1.9.1): emitted under Registry steward machinery, consumed/voted under NodeCore P4 vote... | CC 3.1.1 / CC 3.1.9.1 | dual-owner: neither may redefine {kind} vocabulary or the vote-then-trust path unilaterally |
| `agent_files:{kind}:{platform_or_target}` | Install-endpoint anti-tricking: canonical/default-trust is attester-IDENTITY-gated (registry-steward-triple, score>=0.7), never vote/aggregate-gated; Layer-3 vote accumulation m... | CC 4.4.3.7 | aggregate/vote-weighted composition FORBIDDEN as sole/sufficient input to install-endpoint default-trust |
| `agent_files:{kind}:{platform_or_target}` | Subject-bearing {kind} values MUST carry subject_key_ids; substrate MAY reject when absent. Currently UNIMPLEMENTED (cc_impl.tsv rows 2.3.1/4.5.2.1 show no resolvable symbol). | CC 2.3.1 / CC 4.5.2.1 | admission of subject-naming {kind} without subject_key_ids is a rejectable defect - gate unbuilt |
| `agent_files:{kind}:{platform_or_target}` | Consumer MUST verify the full SHA-256 in evidence_refs[] against received bytes before consumption; holds_bytes directory entry is advisory routing only. | CC 3.1.9.1 / CC 5.3.2 / 5.3.2.1 | holds_bytes NEVER sole authority for byte integrity; full-SHA recompute mandatory - IMPLEMENTED (ciris-verify-core holds_bytes.rs#verify_holds_bytes) |
| `agent_files:{kind}:{platform_or_target}` | Open-vocabulary {kind} collision guard: first-registered wins; Levenshtein<=2 gets advisory 409; 90-day-unused reclaim via CC 4.5.1. | CC 4.5.1.3 | no primitive may silently overwrite an earlier {kind} registration; never last-write-wins |
| `approach:{goal_id}` | Upward-only decision-hierarchy DAG: approach must serve an actual Goal; edges point upward only, never cyclic. Currently enforced only at READ/compose time (NodeCore compose.rs)... | CC 3.1.9.7 | emit requires a resolvable parent goal_id; DAG upward-only |
| `approach:{goal_id}` | capacity:* self-emission rejection does NOT extend to approach:{goal_id}; self-emission is permitted and expected. | CC 3.4.5 (contrast) | no attesting!=attested guard for this family |
| `approach:{goal_id}` | Default signed-polarity composition (mean of score x confidence) applies; no testimonial-style carve-out exists in text despite equally-singular self-narration (plausible Fricke... | CC 4.4.2 | aggregate PERMITTED as CCC floor default |
| `approach:{goal_id}` | No required construction-time payload beyond parent-goal reference, in contrast to goal/method/progress_measure rows of the same table. | CC 3.1.9.7 | no compile/admission required-field invariant beyond parent linkage; richer fields are engineering conveniences |
| `approach:{goal_id}` | The F-11 retraction flag (universal-grace half of Piece 10) is asserted but never elaborated anywhere in the checkout. | CC 3.1.9.7 (F-11) | do not invent semantics for the retracted half; flag for human review |
| `attestation:agent_integrity` | Wire carries bare mechanism prefix only; L1-L5 is consumer-side composition output (ladder_verdict()), never wire taxonomy; l{N} form is the documented anti-pattern. | CC 3.1.2 / CC 4.1.3 / CC 4.4.3.6 | emit MUST use bare mechanism form; no primitive may hard-code an L-numbered wire prefix |
| `attestation:agent_integrity` | boolean-via-score aggregates by MIN across attesters - any genuine mismatch trumps any number of passes; constitution names attestation:l* as the exemplar. GAP: CIRISVerify Atte... | CC 4.4.2 | cross-attester composer MUST use min(), never mean(); corroborating pass MUST NOT dilute a caught mismatch |
| `attestation:agent_integrity` | Ladder position is consumer-side; different consumers may require different rung combinations - wire stays neutral. | CC 4.4.3.6 | no wire/admission hard-coded L5-required check |
| `attestation:agent_integrity` | Open-emit; self-attestation is the expected mechanism and explicitly NOT subject to capacity:* anti-Goodhart rejection (verified: persist check scoped to capacity: only). | CC 3.4 absence / CC 3.4.5 | do NOT apply attester!=attested gate to this family |
| `attestation:agent_integrity` | Self-attestation is an acknowledged structural exception (R4) to relational-standing discipline; consumer composition SHOULD apply corroboration weighting. | CC 8.3.1 R4 / CC 4.1.2 | consumer SHOULD weight relationally though wire-level self-attestation permitted |
| `attestation:agent_integrity` | agent_integrity is the execution-provenance anchor other families cite: judge_model:verdict MUST bind to it before AI-consensus framing (closes RT-H5). | FSD-005 KNOWLEDGE_COMMONS sec.7 RT-H5 | must be a resolvable evidence_refs target for provenance-binding families |
| `attestation:agent_integrity` | Conformance/ladder traces to a governance community default to cohort_scope:federation (Commons plaintext) - the trust root must be maximally inspectable. | CC 4.4.3.2.1 | projection default federation/world-readable; narrower scope is explicit opt-out, not default |
| `attestation:hardware_rooted` | Emission MUST use bare mechanism attestation:hardware_rooted; ladder-position form attestation:l{N}:* is deprecated and constitutionally rejected at admission. LIVE GAP: pinned ... | CC 4.4.3.6 | admission gate MUST reject l{N} form; unenforced by default in pinned substrate |
| `attestation:hardware_rooted` | Ladder position (L1-L5) is exclusively consumer-side composition; MUST NOT be persisted, wire-encoded, or cached as ground truth without invalidation. | CC 4.4.3.6 | no EnvelopeCore/DB field may encode ladder position |
| `attestation:hardware_rooted` | Ladder achievement composes by ANY-POSITIVE existence per mechanism, not magnitude-averaging. | CC 4.4.3.6 (contrast Policy A) | FORBIDDEN: averaging hardware_rooted scores into a fractional verdict; REQUIRED: any-positive existence check |
| `attestation:hardware_rooted` | hardware_class is a self-asserted producer claim; consumers MUST apply the CC 4.2.2 trust-multiplier table, zero-weight placeholder_pending_provisioning, reject software_hsm_dev... | CC 4.2.2/4.2.2.1 + R5 | any composer resolving trust weight MUST join claimed hardware_class against the multiplier table; ExternalSecureElement chain-verified at registration in CIRISServer but never ... |
| `attestation:hardware_rooted` | attested_key_id (subject) is structurally distinct from subject_key_ids (revoke authority); attested key gains no default withdraws over attestations about it. | CC 2.1 / CC 2.3.3 | revoke authority defaults producer-only; subject self-revoke requires explicit subject_key_ids listing |
| `attestation:license_validity` | Ladder position is consumer-side; bare mechanism attestation:license_validity is the L4 mechanism; l4 form deprecated/rejected. IMPLEMENTED in persist admission.rs (DualAccept t... | CC 4.4.3.6 | emit MUST use bare form |
| `attestation:license_validity` | T3 version-pinning (:vN) is explicitly carved out for the five ladder mechanisms; admission MUST NOT reject license_validity for lacking a version segment. | CC 4.4.3.6 (impl comment) | no :vN requirement for ladder mechanisms |
| `attestation:license_validity` | build:registered:{target} is stated as precondition for L4 - descriptive-only today, NO admission or composition code enforces it (genuine gap). | CC 3.1.1 / FSD-005 | emit/admission SHOULD verify covering build:registered attestation exists - unenforced |
| `attestation:license_validity` | attestation:license_validity is distinct from co-stewarded licensure:{authority_id}; consumers MUST NOT apply licensure's single-source confidence<=0.5 cap here nor treat this a... | CC 3.1.1 / CC 3.4.9 | no cap import; no family conflation |
| `attestation:license_validity` | cohort_scope/restrictions must be resolved AT PROMOTION, not assumed from initial write: Engine::attestation_promote (reachable via POST /v1/auth/attestation promote:true) perfo... | CIRISPersist#509/#510 design intent (impl-level) | bare tier-flip ships a federation row whose visibility/restrictions were never validated - the named exemplar defect |
| `attestation:registry_consensus` | Wire emission MUST use bare attestation:registry_consensus; ladder-encoded l3 form rejected at admission (mechanism-only emission). | CC 4.4.3.6 / CC 1.2 T2 | mechanism-only dimension REQUIRED; ladder-numbered variant FORBIDDEN on wire |
| `attestation:registry_consensus` | Node->canonical registry_consensus emissions MUST be cohort_scope:federation - Commons plaintext, no DEK - public auditability of the trust root. | CC 4.4.3.2.1 | federation scope REQUIRED for node->canonical conformance emissions; MUST NOT ride community-DEK path |
| `attestation:registry_consensus` | Default aggregation for boolean-via-score is MIN (fail-secure); Indeterminate must render distinct from Fail but MUST NOT compose as a passing verdict. | CC 4.4.2 / CC 3.1.2 | MIN reducer required; Indeterminate never permissive |
| `attestation:registry_consensus` | attested_key_id is only a subject-carrier when subject_kind=key; build/license subjects MUST use tagged canonical-hash subject_key_ids per CC 2.3.2.1, never ad hoc payload fields. | CC 2.1 / CC 2.3.2.1 / FSD-005 | non-key subject_kinds FORBIDDEN from relying on attested_key_id |
| `attestation:registry_consensus` | Open/non-reserved: any producer capable of the 2-of-3 check may self-assert. | CC 3.1.2 | no reserved-emitter gate |
| `attestation:self_verify` | Ladder prefixes are mechanism-only; attestation:l{N}:* is rejected-at-admission anti-pattern - bare attestation:self_verify is the only valid wire shape. | CC 4.1.3 + CC 4.4.3.6 | dimension pattern-locked; admission MUST reject parameterized variant (shipped default DualAccept does not yet) |
| `attestation:self_verify` | L1-L5 is consumer-side composition; self_verify is one input among five into ladder_verdict(); safety-critical consumers may require higher rungs regardless. | CC 4.4.3.6 | self_verify MUST NOT be typed/consumed as establishing trust above L1; ladder rendering is composition OUTPUT |
| `attestation:self_verify` | self_verify is the definitional trust FLOOR: delegates_to chains broken by depth-cap/cycle degrade to self_verify only (no transitive trust). | CC 4.1.1 | MUST NOT be aggregated with or substituted for externally-corroborated rungs |
| `attestation:self_verify` | boolean-via-score default-aggregates via MIN across attesters - fail-secure; the constitution's own worked example is attestation:l*. | CC 4.4.2 | MIN required for multiple self_verify records per attested key; never mean/max |
| `attestation:self_verify` | Standing is relational, not self-declared; self_verify is the sole named exception - its schema MUST NOT grow into a substitute for external attestation, and emitting key SHOULD... | CC 4.1.2 | no self-asserted trust_level/ladder_position wire field; attester==attested constraint currently unenforced at chokepoint |
| `audit_chain:hash_continuity` | audit_chain leaves may only be emitted by identity_type containing substrate_persist, cross-attested by the steward-triple; non-substrate emission is a category error MUST-rejec... | CC 3.4.3 | emit restricted to substrate_persist; steward cross-attestation is a KEY-registration precondition |
| `audit_chain:hash_continuity` | Two-layer enforcement mandatory: substrate rejects at admission AND every consumer independently re-verifies; trust does not propagate. | CC 3.4.7 | admission gate + independent consumer re-check both REQUIRED |
| `audit_chain:hash_continuity` | The four structural composers are generic; recants/withdraws/supersedes resolve via the same cross-family precedence for this dimension (no bespoke carve-out). | CC 3.5/3.5.1 | no family restriction on composers; precedence generic |
| `audit_chain:hash_continuity` | Constitution deliberately withholds a payload schema (UNDERSPECIFIED, CC 8.1 editorial ask); chain_id/seq/continuity_status etc. are engineering elaborations, not requirements. | CC 8.1.2 / FSD-005 App.A | hoisting seed superset fields is engineering choice pending amendment |
| `autonomy:{aspect}` | The six Accord principles are non-fungible: a strong score on one may never offset or license violating another; autonomy must remain separately visible in any composed multi-pr... | CC 1.15.1 | cross-principle blended/composite aggregation FORBIDDEN |
| `autonomy:{aspect}` | subject_key_ids is the wire-level mechanism through which Autonomy is exercised: the subject of someone else's data retains the ability to pull it. | CC 2.3 / 2.4.1.1 / 4.5.2.1 | autonomy claims naming a subject should carry that being in subject_key_ids for withdraws authority; CC 4.5.2.1 gate unbuilt for any family |
| `autonomy:{aspect}` | attested_key_id is the base typed subject field; never introduce a bespoke payload subject_ref for this family. | CC 2.4.2 / CC 2.1 | bind subject to attested_key_id (typed, required) |
| `autonomy:{aspect}` | {aspect} is open-vocabulary with no calibration package: documentation-only convention track + CC 4.5.1.3 collision rules; no evidence_refs/calibration requirement may be imposed. | CC 4.5.1.1 / 4.5.1.3 | registry-doc + first-registered-wins/Levenshtein advisory/90-day reclaim; none exists yet |
| `autonomy:{aspect}` | Default signed composition (mean of score x confidence) applies with no carve-out - unlike testimonial_witness, autonomy has no never-aggregated/never-sole-slashing floor (obser... | CC 4.4.2 (contrast CC 3.1.9.3) | aggregate PERMITTED; no textual slashing floor for this family |
| `benchmark:he300:{category}:{version}` | Polarity positive-only: composition MUST use PositiveOnly max aggregation, never Signed mean; no negative value valid. GAP: polarity_for falls through to Signed today. | CC 3.1.10 | aggregate-as-mean FORBIDDEN; max REQUIRED |
| `benchmark:he300:{category}:{version}` | Scores at different {version} tokens are not comparable; partition by version before folding/trending. GAP: dotted tokens fail existing version matchers. | FSD-005 App.A (companion to CC 3.1.10) | cross-version aggregate/compare FORBIDDEN |
| `benchmark:he300:{category}:{version}` | Populating subject_key_ids default-grants the scored agent withdraws authority (CC 2.1); MUST be suppressed via family carve-out or the subject can self-erase compliance evidenc... | CC 2.1 | subject-side withdraws suppression REQUIRED (no carve-out exists) - needs-human-review |
| `benchmark:he300:{category}:{version}` | A score improvement is not self-certifying: must cross-check the held-out Shadow HE-25 signal before downstream capability-uplift composition; divergence (public >=+5% vs shadow... | CC 8.8.10 annex-j sec.6 | benchmark emission never sole/automatic input to capacity-uplift composition without the shadow cross-check |
| `benchmark:he300:{category}:{version}` | Consumer thresholds may be tightened freely but never loosened without WA approval; a regression MUST trigger S-Dive pre-screen (7d) / Incident Workflow IW-3. | CC 8.8.10 sec.2.3/7 + CC 8.8.8 sec.8 | threshold-loosening requires WA sign-off; regression detection wires to mandatory governance workflow |
| `benchmark:he300:{category}:{version}` | Canonical {category} wire strings survive localization unchanged; display renames require LANGUAGE_PRIMER.md glossary + version pinning. | CC 4.1.5 | client MAY localize display but MUST round-trip canonical category values |
| `benchmark:he300:{category}:{version}` | Open-vocabulary (not CC 3.4 reserved) with CIRISBench as sole practical steward; a reserved-emitter gate is expected but no benchmark: ReservedPrefixRule exists. | FSD-005 App.A | no protocol gate mandated but single-steward model implies one; gap |
| `beneficence:{aspect}` | Never collapse the flourishing vector: no aggregation across aspects/axes into one composite beneficence scalar; within-dimension mean across attesters is the only permitted grain. | CC 8.8.1 | cross-aspect aggregate FORBIDDEN; within-dimension CC 4.4.2 mean only |
| `beneficence:{aspect}` | A quantified forecast whose realized outcome deviates >25% on any Annex-A axis REQUIRES a WBD escalation. | CC 8.8.1 + CC 1.9 | forecast emission requires later reconciliation; >25% error -> mandatory hard_case/WBD, never silent drift |
| `beneficence:{aspect}` | Metric-gaming: raising one axis >+10% while lowering another >-2% undetected carries a 30-day disclosure duty; non-disclosure voids CIRIS compliance. | CC 8.8.1 | producer disclosure obligation via follow-up attestation referencing the original within 30 days; no admission timer enforces this |
| `beneficence:{aspect}` | beneficence is an agent-layer value: subject is the AGENT under evaluation, never a generic community virtue badge. | CC part_1 line 25 + CC 3.1.5 header | subject_key_ids must resolve to an agent identity being evaluated |
| `beneficence:{aspect}` | The apophatic non-maleficence floor is structurally non-overridable; positive beneficence scores never sum/net against prohibited:{category} violations. | CC 3.1.5.4 + FSD-005 sec.4 | never blended input netting out a prohibited:* floor breach |
| `bond_posted:{currency}` | Positive-only dimensions compose via MAX across attesters/postings, not SUM; a compliant consumer MUST NOT sum bond_posted scores to derive an aggregate bonded total. | CC 4.4.2 | aggregate-by-SUM FORBIDDEN; max-across-attesters required; Registry escrow ledger is the sole running total |
| `bond_posted:{currency}` | Bond forfeiture is triggered by a separate revocation:{entity_type}:{reason} attestation, never a status mutation on bond_posted; immediate and non-rollbackable. | CC 3.1.1 + FSD-005 App.A | forfeiture composer MUST read cross-dimension revocation:* state; no un-forfeit primitive exists |
| `bond_posted:{currency}` | No principal is exempt from bond forfeiture, including CIRIS L3C-affiliated partners (Recursive Golden Rule). | CC 1.13.2 | no steward allow-list bypass at compile, admission, or consumer-policy layer |
| `bond_posted:{currency}` | Wire grammar is minimal (1+4); bond lifecycle states express through those primitives, never a bespoke per-family status enum. | CC 2.4/2.4.1 + CC 4.1.5 | bond_status/forfeiture_ref-style typed enums FORBIDDEN as EnvelopeCore members |
| `bond_posted:{currency}` | bond_posted composes with the generic stake field as verifiable backing for stake:capital/cryptoeconomic on any other attestation by the same key. | CC 2.1 + CC 2.5 | consumers resolving a capital stake claim MUST check a live non-forfeited bond_posted for that key, else fall back to self-declared discount |
| `build:registered:{target}` | build:registered is the stated precondition record for attestation:license_validity (L4) - but this precondition is descriptive only, NOT wired into Policy I's composition funct... | CC 3.1.1; cf. CC 4.4.3.6 | documented-but-unwired precondition; never silently treat as already gating L4 in code |
| `build:registered:{target}` | Explicitly non-reserved: open emission; no emitter restriction; canonical/effective trust left entirely to unspecified consumer policy (Policy F never extended to this family). | CC 3.1.1 + CC 4.4.3.7 | no reserved-emitter primitive; do not invent a canonical-registration trust policy as if specified |
| `capacity:composite` | capacity:* rejects self-emission (attesting != attested), per held role even under cohabitation - wildcard rule covering future subkinds. | CC 3.4.5 | admission MUST reject attesting==attested on any capacity:{x} |
| `capacity:composite` | capacity:* is reserved (catastrophic-to-forge class) under the three-actor discipline: substrate rejects, every consumer re-checks, producers must not emit non-conformant. | CC 3.4 / CC 3.4.7 | never sole-trust the substrate admission check; CCC re-check mandatory |
| `capacity:composite` | capacity:* attestations are ineligible for the local (self-scoped) tier - must originate federation-tier, third-party-signed. | CC 3.4.5 corollary (AV-62/CEG 7.5) | never admit as a local/self-cohort draft row (would reopen the self-feedback loop) |
| `capacity:composite` | capacity:* is a leaf input, not a meta-judgment prefix; trustworthiness-style compositions are consumer-side only, never new wire prefixes. | CC 4.1.3 | aggregate-into-new-wire-prefix FORBIDDEN |
| `capacity:composite` | capacity:composite is the MULTIPLICATIVE product of the five factors (anti-Goodhart unity-of-virtues) and is distinct from the Accord's F with no implied mapping. | CC 3.1.8.1 / CC 6.2.4 | never additive/averaged; a collapsed factor collapses the whole; never alias to F |
| `capacity:composite` | LensCore prefixes observe, never adjudicate - capacity:* never stands as a verdict on its own. | CC 3.1.8 | never sole input to an authority-action composer; must compose with human/quorum judgment |
| `capacity:core_identity` | capacity:* rejects self-emission; enforced at substrate admission, consumer re-check, and producer conformance; type-enforced in lens-core. | CC 3.4.5 | FORBIDDEN self-attestation; never sole input from a self-referential attester |
| `capacity:core_identity` | core_identity is one of five factors combined ONLY by multiplication into composite; a zero collapses the whole; core_identity never a standalone capacity verdict. | CC 3.1.8.1 | average FORBIDDEN across factors; product-only fold (CapacityFactors::composite implemented + tested, but NOT yet wired to wire attestations - v0.5+ per module doc) |
| `capacity:core_identity` | LensCore dimensions are observational; never sole evidence for authority/slashing actions; feed human + WA-quorum judgment. | CC 3.1.8 / CC 1.2 T4 | FORBIDDEN as sole slashing/authority input; validated-not-adjudicated |
| `capacity:core_identity` | Self-emission rejection binds per held role under folded identity_type sets - no cohabitation backdoor. | CC 3.4.7.1 / CC 3.4.5 | check over the attesting key's full role-set |
| `capacity:core_identity` | Unlike detection:*, capacity:* has NO emitter-ROLE restriction - only the self-emission rule; any non-subject federation key may emit. | CC 3.4.8 (contrast) / CC 3.4.5 | no lenscore_detector membership gate may be hard-coded at admission |
| `capacity:incompleteness_awareness` | capacity:* rejects self-emission; double-enforced at persist admission and lens-core compile time. | CC 3.4.5 / CC 3.1.8.1 | reserved-prefix self-emit FORBIDDEN; structurally impossible in the typed constructor |
| `capacity:incompleteness_awareness` | incompleteness_awareness (I_inc) is one of five MULTIPLICATIVE factors of composite; a weak/zero factor collapses it and cannot be averaged away. | CC 3.1.8.1 | MUST compose into composite only via the 5-factor product; linear/weighted fold FORBIDDEN |
| `capacity:incompleteness_awareness` | Subject-side authority does not extend to recants or truth disputes: the recourse is a contradicting negative-polarity scores claim (rebuttal), not withdrawing the scorer's row. | CC 2.4.1.2/2.4.1.3 | never sole revoke input from data_subject; correction = new contradicting claim |
| `capacity:integrity` | capacity:* MUST reject self-emission at admission, per held role under cohabitation; implemented (CapacitySelfEmissionRejected). | CC 3.1.8.1 / CC 3.4.5 | scores-emit hard-reject if attesting==attested |
| `capacity:integrity` | composite = C*I_int*R*I_inc*S multiplicative, never averaged/summed; distinct from Accord F; CapacityFactors::composite implemented but UNWIRED to any live consumer. | CC 3.1.8.1 / CC 6.2.4 | composite composer MUST multiply; additive fold FORBIDDEN |
| `capacity:integrity` | capacity:integrity is observational/advisory only - never wired as sole/unilateral input to authority actions; mirrors ratchet/detection never-sole-evidence posture. | CC 3.1.8 preamble; analogy CC 3.1.6/3.4.8 | never sole input to authority/slashing composer |
| `capacity:integrity` | recants is available ONLY to the original attester; a disputing subject issues a contradicting scores claim instead. | CC 2.4.1.1 / 2.4.1.3 | recant attester-only, subject-never |
| `capacity:integrity` | No identity_type emitter gate exists for capacity:* (unlike detection:*); only the self-emission inequality is enforced - any non-subject key may emit per the text. | CC 3.4.7 / 3.4.8 / 3.1.8.1 | emitter-role gate: NONE beyond the inequality |
| `capacity:integrity` | Default cross-attester aggregation for capacity:integrity (signed) is Mean(score x confidence), NOT median (median reserved to enumerated detector dimensions); mean runs BEFORE ... | CC 4.4.2 | corroboration aggregation = mean, then product fold |
| `capacity:resilience` | capacity:* rejects self-emission; CCS admission-reject + CCC independent re-check must agree; binds per held role under cohabitation. | CC 3.4.5 / 3.4.7 / 3.4.7.1 | attesting != attested at BOTH producer-substrate admission and consumer re-check |
| `capacity:resilience` | composite is multiplicative; a low resilience score collapses it; must not be silently clamped-to-neutral; never confused with federation-level F. | CC 3.1.8.1 / CC 6.2.4 | multiplicative composer; no rename/remap onto F |
| `capacity:resilience` | LensCore observes, does not adjudicate; resilience feeds human/quorum judgment, never a standalone verdict. | CC 3.1.8 | MUST NOT be sole/autonomous input to slashing/tier-change composers |
| `capacity:sustained_coherence` | No-self-emission: attesting != attested for any capacity:* dimension, dual-gated at admission AND independent consumer re-check, binding regardless of role cohabitation. | CC 3.4.5 + 3.4.7 + 4.5.8.3 | self-emission FORBIDDEN; checked at (a) CCS reject-at-admission and (b) per-consumer re-check; CCP binds independently |
| `capacity:sustained_coherence` | capacity:composite is the MULTIPLICATIVE product of all five factors incl. S; never weighted sum/average (anti-Goodhart unity-of-virtues). Implemented as a product in lens-core ... | CC 3.1.8.1 | composite composer MUST multiply; weighted-average FORBIDDEN |
| `capacity:sustained_coherence` | Validated-not-adjudicated: capacity attestations feed downstream human/quorum judgment, never a self-sufficient verdict (preamble + generic T4; not a verbatim per-leaf slashing ... | CC 3.1.8 + CC 1.7 / CC 1.2 T4 | NEVER sole input to authority-action/slashing composer; route through human/quorum |
| `capacity:sustained_coherence` | No identity_type role-membership gate applies to capacity:* admission - self-emission is the ONLY reserved gate; a persist role check here would over-restrict beyond the constit... | CC 3.4.8 (by scope-exclusion) | admission MUST NOT require lenscore_detector membership for capacity rows |
| `cert_validity:{authority}` | cert_validity is a measurement/mechanism fact, not a pre-composed verdict/tier/ladder position; ladder mapping is strictly consumer-side. | CC 4.4.3.6 + CIRISVerify MISSION sec.1.4 | emit carries bare mechanism claim (score/passed + attester + source_ref); never a derived verdict/tier field |
| `cert_validity:{authority}` | cert_validity alone is insufficient evidence of verified: Policy G requires it ALONGSIDE transparency_log:inclusion AND (registry_consensus OR license_validity); it answers only... | CC 4.4.3.11 | never sole input to a verified/trust determination |
| `cert_validity:{authority}` | Soft self-report, never a substitute for the hard non-rollbackable revocation record. | CC 3.1.1 + CC 3.1.2 (rollback_detected row) | MUST NOT be composed as/accepted in lieu of revocation:*/rollback_detected:* |
| `cert_validity:{authority}` | A deployed steward's own cert_validity self-attestation, gated only by deployed:true response-signing, is sufficient; adding a cross-witness admission gate on top is a named des... | CC 5.3.4 (+MISSION 1.5.1, component-level) | never require an extra cross-witness precondition before accepting steward self-attested cert_validity |
| `coherence_standing:{cohort}` | LensCore prefixes observe, never adjudicate - coherence_standing always feeds downstream human/quorum judgment, never a standalone verdict. | CC 3.1.8 | FORBIDDEN as sole/terminal input to adjudicative primitives (slashing/moderation outcomes) |
| `coherence_standing:{cohort}` | flag:bad_actor:{axis} is a rejected anti-pattern; the ONLY sanctioned bad-actor signal is a low-confidence score on coherence_standing (or provenance:*), adjudicated via NodeCor... | CC 4.1.3 | never sole input to slashing/moderation composer; P8 quorum gate between low score and punitive consequence |
| `coherence_standing:{cohort}` | coherence_standing is omitted from BOTH the detector-only reserved list and the capacity no-self-emit reservation - open emit; do not import either sibling restriction. | CC 3.4.8 vs CC 3.4.5 | reserve-to-single-role FORBIDDEN; emission open incl. third-party observers |
| `coherence_standing:{cohort}` | Self-declaration does not constitute standing without external witness; self_reported status must be DERIVED from witness_relation/subject_key_ids, never a self-asserted wire fi... | CC 4.1.2 / CC 4.1.5 | self_reported derived at composition time; self rows require external-witness downweighting |
| `coherence_standing:{cohort}` | Part 3 gives no operational definition beyond polarity; the catalog flags it UNDERSPECIFIED - engineering must not present invented methodology as constitutionally settled. | FSD-005 App.A:53 + sec.10 | no CC-mandated methodology for {cohort} keying or score computation; owning-component discretion |
| `commitment_fulfillment:{prior_contribution_id}` | A commitment_fulfillment shortfall is evidence, never itself a slashing verdict - routes through moderation:{allegation_type} + WA quorum before PROVEN_ROGUE. | CC 3.1.9.2 + CC 3.3.5.1 | never sole input to slashing composer |
| `commitment_fulfillment:{prior_contribution_id}` | moderation_track_record is a NAMED COMPOSITION over the existing scores corpus, not a new structural primitive; commitment_fulfillment rides plain scores. | CC 3.1.9.2 / CC 4.5.4 | aggregate FORBIDDEN as new primitive - compose over existing corpus only |
| `commitment_fulfillment:{prior_contribution_id}` | Self-attested follow-through is not costly to fake: uncountersigned self-assertions carry w=0 toward sigma and must not count full-weight toward moderation_track_record; weighti... | CC 6.2.3.1 | witness_relation:self rows w=0 toward sigma; MUST NOT be sole/undiscounted merit input |
| `commitment_fulfillment:{prior_contribution_id}` | Mutually-countersigning cliques must be Kish-discounted by source correlation before folding into sigma. | CC 6.2.3.1 | rows feeding sigma MUST pass Signal_eff correlation discount, not raw count |
| `commitment_fulfillment:{prior_contribution_id}` | recants is exercisable ONLY by the original attester; the committer can never force a false marking, only retraction going forward (given subject_key_ids naming). | CC 2.4.1.3 | recant restricted to original signer |
| `commitment_fulfillment:{prior_contribution_id}` | Subject-naming dimensions MUST carry subject_key_ids (open catalog); commitment_fulfillment's transitive subject falls within the spirit though not the enumerated list. | CC 2.3.1 / 4.5.2.1 | admission SHOULD require committer in subject_key_ids (needs-human-review) |
| `conscience:coherence` | conscience:{entropy\|coherence\|optimization_veto\|epistemic_humility} is a CLOSED four-member set; faculty identity is the dimension prefix, never a payload sub-field. | CC 3.1.5.3 | no faculty_id payload field permitted (two sources of truth defect) |
| `conscience:coherence` | conscience:* MUST NOT be confused with or emit under the RESERVED detection:conscience_override_rate (LensCore-only override-frequency detector). | CC 3.1.8.2 + CC 3.4.8 | no lenscore_detector role needed; never shadow detection:*; third-party cross-checks ride their own prefix |
| `conscience:coherence` | conscience:* is open-emit and self-emission is the EXPECTED default - do not import the capacity:* no-self-emit gate. | CC 3.4.5 contrast (code-confirmed both layers) | self-emission ALLOWED/expected; never apply attesting!=attested enforcement |
| `conscience:coherence` | Part 3 gives NO per-faculty score semantics - acknowledged editorial gap; threshold conventions are CIRISAgent implementation detail, not constitutional. | FSD-005 App.A:59 + sec.10 | no compile/admission score-shape gate derivable; do not present invented semantics as CC-sourced |
| `conscience:coherence` | No CC text bars conscience:* from being sole slashing evidence (unlike testimonial_witness/ratchet:flag/age_assurance) - flagged, unresolved. | silence in CC 3.1.5.3 vs sibling patterns | NEEDS-HUMAN-REVIEW: no never-sole-evidence bound established for a self-incrimination-shaped family |
| `conscience:coherence` | Dimension matches no subject-bearing pattern; the per-decision pointer is served by evidence_refs (sequence-semantics), not a hoisted field. | CC 2.3.1 / 4.5.2.1 | no subject_key_ids requirement; correlate via evidence_refs |
| `conscience:coherence` | Default CC 4.4.2 mean per (dimension, attested_key_id) applies - but each verdict's real subject is a single decision instance; naive per-agent mean blends unrelated reasoning-c... | CC 4.4.2 (generic fallthrough confirmed in polarity_for) | NEEDS-HUMAN-REVIEW/constitution-silent: naive composer conflates independent verdicts |
| `conscience:entropy` | conscience:* verdicts compose jointly with dma:* as the reasoning-trace evidence surface behind explainability SLAs; neither is self-sufficient alone. | FSD-005 App.A + CC 3.1.5.1/3.1.5.2 | MUST be read/composed jointly with dma:* for fidelity:explainability_sla evidence |
| `conscience:entropy` | conscience:* carries no reserved-prefix/no-self-emission gate, in explicit contrast to capacity:*. | CC 3.4.5 (contrast); absent from CC 3.4 | self-emission ALLOWED; do not import capacity's rule |
| `conscience:entropy` | detection:conscience_override_rate is the one named consumer of conscience:* verdicts: RESERVED to lenscore_detector, validated-not-adjudicated, never sole slashing evidence; it... | CC 3.1.8.2 + FSD App.A:71 | pass/fail + override outcome MUST be typed/queryable (opaque extra defeats the reserved detector); detector output never sole slashing evidence |
| `conscience:entropy` | subject_key_ids names consent-holder parties only; a scored artifact is not one. | CC 2.3.1 / 2.3.2 | artifact reference MUST NOT ride subject_key_ids; evidence_refs is the correct home |
| `conscience:entropy` | Part 3 gives no operational definition of per-faculty score semantics - acknowledged, tracked editorial gap. | FSD-005 App.A:59 + KNOWLEDGE_COMMONS:425 | no CC-mandated wire shape beyond generic {dimension,score,confidence}; per-faculty fields are engineering additions pending amendment |
| `conscience:entropy` | CC 4.4.2 default mean is keyed per (dimension, attested_key_id) but entropy verdicts are per-decision; dimension carries no per-decision parameter. | CC 4.4.2 | consumers MUST scope composition by the evidence-referenced thought/trace id BEFORE the default mean, or per-decision semantics collapse into a running average |
| `conscience:epistemic_humility` | One of exactly four flat, unparameterized conscience prefixes; Part 3 gives no {faculty_id} token. | CC 3.1.5.3 | no {faculty_id} sub-namespace primitive authorized; seed prefix-scoping is an unratified extension |
| `conscience:epistemic_humility` | conscience:* self-emission is NOT gated like capacity:*; do not import the no-self-emit rule by analogy. | CC 3.4.5 | self-emit ALLOWED; no attesting!=attested admission gate |
| `conscience:epistemic_humility` | The anti-Goodhart safeguard for self-emitted conscience verdicts is the EXTERNAL LensCore-only detection:conscience_override_rate cross-check - itself never sole evidence for au... | CC 3.1.8.2 + CC 3.4.8 | conscience:epistemic_humility MUST NOT be sole/conclusive evidence for authority actions even when corroborated; WA quorum remains the gate (M-1) |
| `conscience:epistemic_humility` | Subject-bearing subject_key_ids mandate does not trigger on this flat pattern. | CC 4.5.2.1 / 2.3.1 | do NOT force-populate subject_key_ids by default |
| `conscience:epistemic_humility` | references_attestation_id is scoped to the four structural composers on a prior SAME-attester row - not a general cross-reference pointer. | CC 2.4.1 + CC 2.5 | the judged-action pointer MUST ride evidence_refs, NOT references_attestation_id and NOT a new referenced_action_id field |
| `conscience:epistemic_humility` | confidence is already a required typed CC 2.1 field; a duplicate confidence_score payload field is redundant. | CC 2.1 | reuse confidence (paired with signed score) |
| `conscience:epistemic_humility` | Default CC 4.4.2 mean keyed per (dimension, attested_key_id) silently pools humility verdicts across unrelated actions; consumers MUST group by evidence_refs-named action first. | CC 4.4.2 | group-by-action before default mean |
| `conscience:epistemic_humility` | This family is the declared exclusive home for epistemic-finitude self-reports (competing prefix deprioritized). | CC 8:252 | no second/parallel prefix for epistemic-finitude claims |
| `conscience:optimization_veto` | The ENTIRE family-specific text is the one CC 3.1.5.3 registry line (closed four-leaf enum, signed polarity); nothing else names this prefix. | CC 3.1.5.3 | dimension MUST be one of four closed leaves; no calibration package applies |
| `conscience:optimization_veto` | conscience:* rides the agent identity_type role, not lenscore_detector - categorically distinct from detection:conscience_override_rate; namespaces never merge under cohabitation. | CC 3.4.8 | emitter identity_type MUST hold agent; never gated by/confused with lenscore_detector |
| `conscience:optimization_veto` | NOT subject to capacity-style self-emission rejection; self-attestation is the expected shape. | CC 3.4.5 (by contrast) | self-emission MUST be permitted |
| `conscience:optimization_veto` | Every admitted prefix must be wired so attestations are never sole evidence for slashing (T4) - incl. this leaf and any detector derived from it. | CC 1.2 T4 | never sole composer input to slashing; adjudication/quorum separation required |
| `conscience:optimization_veto` | Past verdicts must be re-checkable against the faculty version they ran under (T3) via evidence_refs version-pinning, not a new envelope field; richer narrative belongs in conte... | CC 1.2 T3 / CC 1.13.4 / CC 4.1.2 | version-pin + decision_ref MUST ride evidence_refs; new EnvelopeCore members FORBIDDEN |
| `corpus_health:n_eff_measurable` | system:* (incl. corpus_health:*) reserved to substrate_persist, steward-triple cross-attested; non-substrate emissions are a category error MUST be rejected. | CC 3.4.3 | emit restricted at admission to identity_type containing substrate_persist |
| `corpus_health:n_eff_measurable` | Three-point enforcement (CCS admission, CCC re-check, CCP conformance); trust does not propagate. | CC 3.4.7 | all three layers required; none substitutes |
| `corpus_health:n_eff_measurable` | Cohabitation with an application role does not relax the steward cross-attestation requirement. | CC 4.5.8.1 | gate applies even when the key also carries a non-substrate role |
| `corpus_health:n_eff_measurable` | Emitter-rule check tests attesting key identity_type directly; no delegation admission path exists for this family. | CC 3.4.3 / 4.5.8 (derived) | delegate-based emission FORBIDDEN in effect |
| `corpus_health:n_eff_measurable` | CC 6.1.2.1.2's n_eff is aggregator-attested (substrate cannot recompute per-member masses); a lying aggregator's false n_eff is admitted and only slashable post-hoc (R9 limit) -... | CC 6.1.2.1.2 + CC 8.3.1 R9 | health/observability self-report ABOUT the dominance gate, never independently-verifiable ground truth |
| `corpus_health:n_eff_measurable` | corpus_health:n_eff_measurable is scoped to CC 6.1.2 noise-floor/erasure health of the STORED CORPUS (UNDERSPECIFIED pending CC 8.1); it is not mesh/peer freshness (that is fede... | CC 3.1.3 + FSD-005 App.A | MUST NOT be modeled/consumed as mesh/replica-node-count telemetry |
| `credits:{domain}:{language}:substrate_building` | substrate_building is a registered {subject} VALUE of the generic credits prefix (not a structural family) and is explicitly excluded from the per-grounded-vote accrual loop (vo... | CC 3.1.9.6 + CC 8.3.7 O3 | vote-weight composition MUST exclude rows where subject==substrate_building; parsing treats it as one open {subject} literal |
| `credits:{domain}:{language}:substrate_building` | Positive-only polarity composes via MAX across attesters, not sum/count; magnitude payload fields (effort_units) are not composition inputs. | CC 4.4.2 | fold MUST use max(score x confidence), never sum |
| `credits:{domain}:{language}:substrate_building` | [DRAFT, unratified] Self-attested accrual is a laundering pipe; proposed fix = witness_diversity discipline + attester distinct from producer. | FSD-005 sec.7 RT-H7/M4 (SCOPED) | proposed: composer SHOULD require witness_relation != self (or apply self down-weight) before displayed reputation - open ask, not canon |
| `credits:{domain}:{language}:substrate_building` | Cross-repo enforcement gap: neither NodeCore UI aggregation nor Persist read_vote_weight excludes subject==substrate_building - the CC 3.1.9.6 exclusion is unenforced in the cod... | CC 3.1.9.6 (code-traced) | proposed: read_vote_weight needs a substrate_building exclusion/zero-weight guard - the exact carried-but-unprocessed defect pattern |
| `credits:{domain}:{language}:{subject}` | credits is a non-transferable governance-weight ledger accruing ONLY via the truth-grounding vote loop; strictly positive-only (corrections via supersede). | CC 3.1.9.6 | no transfer/reassignment primitive may move an entry to different subject_key_ids; no negative amount ever |
| `credits:{domain}:{language}:{subject}` | substrate_building is a SEPARATE accrual track invisible to the per-grounded-vote loop; must not be folded into or double-counted with the base leaf. | CC 3.1.9.6 | the two tracks compose separately; a fold summing them as one governance-weight signal violates the partition |
| `credits:{domain}:{language}:{subject}` | Commons-Credits weight is one of only three recognized costly-to-fake sigma signal sources and is subject to the Kish/Signal_eff correlation discount (a collusive clique contrib... | CC 6.2.3.1 | aggregate FORBIDDEN at face value into sigma; Signal_eff discount required |
| `credits:{domain}:{language}:{subject}` | Credits-derived P4 vote weight only ever elevates Layer-3 vote-then-trust for non-canonical entries; it can NEVER promote into Layer-1 canonical trust at any magnitude - operato... | CC 4.4.3.7 + anti-tricking parallel | vote/credits accumulation FORBIDDEN as any input to a Layer-1 promotion primitive |
| `credits:{domain}:{language}:{subject}` | Gaming the ledger is adjudicated via moderation:expertise_fraud + P8 WA quorum; slashing never fires from credit/vote magnitude or disagreement alone. | CC 3.1.9.2 | never sole/automatic slashing input from magnitude; documented finding + adjudication required |
| `credits:{domain}:{language}:{subject}` | [DRAFT/SCOPED, unratified] expertise needs a licensure-style single-source <=0.5 cap and substrate_building an attester-diversity gate (self-attested = laundering pipe). | FSD-005 sec.7 RT-H7; analogy CC 3.4.9 | proposed caps - currently UNENFORCED anywhere in the evidence registry |
| `delivery:{class}` | Reserved emitter + steward-triple cross-attestation: only identity_type=substrate_edge, cross-attested by all stewards; non-substrate emission is a rejected category error, neve... | CC 3.4.3 | emit gate = substrate_edge AND full steward-triple cross-attestation; admission MUST reject |
| `delivery:{class}` | Role cohabitation with an application role does not relax the cross-attestation gate for substrate-role emissions. | CC 4.5.8.1 | per-emission set-membership evaluation; cohabited role never substitutes |
| `delivery:{class}` | No discrete per-recipient/per-attempt delivery-failure attestation and no liveness-state logging: this family stays an aggregate/class-level self-report, never a per-envelope pr... | CC 5.3.3.4 | FORBIDDEN: per-envelope/per-recipient outcome fields (envelope_ref/hop/retry_count/delivery_outcome-per-attempt) as typed required fields |
| `delivery:{class}` | delivery:{class} (substrate self-report) and delivery_receipt:{stream_id} (subscriber-signed chunk ack, CC 3.4.6) are disjoint reserved mechanisms; never conflated, never a shar... | CC 3.4.6 / FSD-005 App.A | composer MUST NOT accept subscriber acks as instances of this family; disjoint emitter gates |
| `delivery:{class}` | No new structural primitive: rides base scores like every reserved self-report leaf (1+4 lockdown). | CC 2.4 / FSD-005 cross-cutting | bespoke proof_chain/EnvelopeKind FORBIDDEN; emit exclusively via base scores |
| `delivery:{class}` | Emission authority non-delegable - the substrate cannot be made to lie about its own behavior by a third party. | CC 3.1.3 rationale applied to 3.1.4 | delegate FORBIDDEN; no key may be granted emission on the component's behalf |
| `detection:conscience_override_rate` | detection:* (any leaf incl. conscience_override_rate) is LensCore-only via a blanket prefix-wildcard design - but substrate-side wildcard enforcement not yet shipped per the tex... | CC 3.4.8 | reserved-emitter gate REQUIRED at admission + consumer re-check for ANY detection:* dimension, generalized by design |
| `detection:conscience_override_rate` | detection:* attestations are validated, not adjudicated; never sole evidence for any authority action. | CC 3.4.8 / CC 1.2 T4 / CC 1.7 | never sole input to slashing or any authority-verdict composer |
| `detection:conscience_override_rate` | Role cohabitation grants emit-right per held role but never merges namespaces; cross-checks by peers MUST ride truth_grounding:detection:* - never shadow the primary leaf. | CC 3.4.7.1 / CC 3.4.8 | same-prefix re-emission by a non-detector key is a rejected shadowing violation |
| `detection:conscience_override_rate` | GAP (flagged): no self-emission rejection (attesting != attested) is stated for detection:* leaves, unlike CC 3.4.5 capacity:*, despite the fold worked-example normalizing co-lo... | CC 3.4.5 (by silence) | RECOMMEND extending the anti-Goodhart self-emission rejection to the five 3.1.8.2 leaves - candidate amendment, not current law |
| `detection:conscience_override_rate` | GAP (flagged): CC 4.4.2's Median override lists only correlated_action/distributive:access/ratchet:flag - the five 3.1.8.2 coherence-ratchet leaves fall to Mean by literal readi... | CC 4.4.2 | RECOMMEND extending the median row; current literal reading applies Mean |
| `detection:correlated_action:{axis}` | Prefix must name a measurable mechanism, not a subjective quality - the canonical T2 case, renamed from emergent_deception. | CC 1.2 T2 | admission FORBIDDEN under any judgment-word name |
| `detection:correlated_action:{axis}` | detection:* is LensCore-only; lenscore_detector in attesting_key.identity_type; prefix is the whole discriminator, no envelope-shape flag. | CC 3.4.8 | emission FORBIDDEN unless identity_type superset {lenscore_detector} |
| `detection:correlated_action:{axis}` | Validated not adjudicated - never sole evidence for any authority action. | CC 3.4.8 / CC 1.2 T4 | never sole input to slashing-shaped composers; WA quorum load-bearing |
| `detection:correlated_action:{axis}` | Consumer composition MUST use median across attesters (resists a single captured detector). | CC 4.4.2 | median REQUIRED, not the signed mean default |
| `detection:correlated_action:{axis}` | Every open {axis} value must carry the 5-part RATCHET calibration package (measurement procedure, threshold fn, statistical floor, evidence shape, polarity semantics), pinned vi... | CC 4.5.1.1 | emission without a resolvable calibration pin fails T3 re-checkability |
| `detection:correlated_action:{axis}` | Open-vocab {axis} collisions: first-registered-wins, Levenshtein<=2 advisory 409, 90-day no-squat reclaim. | CC 4.5.1.3 | registration composer applies advisory guard, not hard reject |
| `detection:correlated_action:{axis}` | subject_key_ids not required ({axis} is not a key_id pattern) and SHOULD be avoided (self-revocation vulnerability). | CC 2.3.1 / 4.5.2.1 | population-membership listing FORBIDDEN in subject_key_ids |
| `detection:correlated_action:{axis}` | Richer narrative (population scale, sample size, CI bands) belongs in context/evidence_refs, not new typed envelope fields. | CC 4.1.2 | new typed superset fields for narrative disfavored; existing fields are the home |
| `detection:cross_agent_divergence` | Emission detector-only: identity_type must contain lenscore_detector; rejected at admission, re-checked at consumption, forbidden at production. | CC 3.4.8 / 3.4.7.1 | emit gated on set-membership; NOT satisfiable via delegates_to proxy |
| `detection:cross_agent_divergence` | Non-detector cross-checks MUST ride truth_grounding:detection:cross_agent_divergence - never re-use the reserved prefix (no shadowing). | CC 3.4.8 | dual-prefix discriminator; same-dimension re-emission by non-detector keys FORBIDDEN |
| `detection:cross_agent_divergence` | Validated, not adjudicated; never sole evidence for slashing or any authority action - even for a co-located {agent,lenscore_detector} key. | CC 1.2 T4 / CC 1.7 / CC 3.1.8 / 3.4.7.1 | never sole input to authority composers; observation cannot manufacture authority |
| `detection:cross_agent_divergence` | CC 3.4.5's self-emission rejection is textually capacity:*-only - the constitution does not (yet) forbid a folded key attesting a divergence comparison in which it is itself a c... | CC 3.4.5 (by scope) | NO self-emission bar currently written (gap, flagged - not a rule) |
| `detection:cross_agent_divergence` | Aggregation ambiguous: the CC 4.4.2 median row names only correlated_action/distributive:access/ratchet:flag; strict reading drops the 3.1.8.2 leaves to signed Mean despite iden... | CC 4.4.2 | consumer aggregation UNDEFINED by name - needs amendment or documented consumer policy |
| `detection:distributive:access:{resource_type}` | Detector-only emission enforced as a prefix-WILDCARD (any detection:{anything}), not per-leaf envelope inspection. | CC 3.4.8 | emit gated on lenscore_detector membership; SHIPPED (persist v21.4.0 wildcard) |
| `detection:distributive:access:{resource_type}` | resource_type is a closed, constitutionally-enumerated 5-value set. | CC 3.1.8.5 | admission must validate the suffix against exactly these 5 values; extension = CC 4.5.1 amendment; validator UNBUILT |
| `detection:distributive:access:{resource_type}` | Cross-attestation on the detector's verdict MUST ride a distinct prefix (truth_grounding:detection:...) - never shadow the primary emission. | CC 3.4.8 | same mechanism as the wildcard gate structurally forces cross-checks onto the distinct prefix |
| `detection:distributive:access:{resource_type}` | Consumer composition MUST aggregate by MEDIAN across attesters for this dimension - named explicitly in the CC 4.4.2 carve-out. | CC 4.4.2 | median dispatcher branch required BEFORE the generic polarity default; no median-override table exists in server or persist today |
| `detection:distributive:access:{resource_type}` | Advisory only, validated not adjudicated; never sole evidence for slashing or any authority action. | CC 3.4.7.1 (citing 1.7/1.2 T4/3.4.8) | never sole input to authority composers; WA quorum load-bearing |
| `detection:distributive:access:{resource_type}` | CC 3.4.5 self-emission rejection is capacity:*-scoped; do not conflate the two reserved disciplines for this family. | CC 3.4.5 / 3.4.8 | gate is lenscore_detector membership, not a self-emission-about-subject rejection |
| `detection:hash_chain_integrity` | detection:* reserved: identity_type set must contain lenscore_detector; discriminator is the prefix, no envelope field encodes the role. | CC 3.4.8 | reserved emitter; envelope-field discriminator FORBIDDEN |
| `detection:hash_chain_integrity` | Wildcard generalization to ALL detection:* prefixes is the normative reading, but the persist wildcard implementation is tracked open in the text (verify coverage for this leaf). | CC 3.4.8 | admission-gate completeness for hash_chain_integrity UNVERIFIED - needs-human-review |
| `detection:hash_chain_integrity` | Cross-checking peers MUST ride truth_grounding:detection:hash_chain_integrity, never re-emit under the reserved prefix. | CC 3.4.8 | no shadowing re-emission by non-detector keys |
| `detection:hash_chain_integrity` | Validated not adjudicated; never sole evidence for slashing or authority actions. | CC 1.7 / CC 1.2 T4 / CC 3.4.8 | never sole input to authority composers |
| `detection:hash_chain_integrity` | Default composition is Mean(score x confidence) - the CC 4.4.2 median override names only correlated_action/distributive:access/ratchet:flag, not this leaf. | CC 4.4.2 | aggregation = Mean by literal reading, not median |
| `detection:hash_chain_integrity` | Closed-vocabulary leaf (1 of 5 named detectors) - the CC 4.5.1.1 open-vocab calibration-package requirement does not bind it. | CC 3.1.8.2 / CC 4.5.1.1 | no calibration-package gate required for emission |
| `detection:hash_chain_integrity` | recants is attester-only; subject-side authority never extends to it. | CC 2.4.1.1 | recant self-only, non-delegable-by-subject |
| `detection:intra_agent_consistency` | Any detection:* dimension is a primary detector emission and MUST be rejected unless identity_type contains lenscore_detector; cross-checks ride the distinct ungated truth_groun... | CC 3.4.8 | emit gated on membership; wildcard covers novel subkinds by construction |
| `detection:intra_agent_consistency` | Validated not adjudicated: feeds human/quorum judgment; never sole evidence for slashing (T4). | CC 1.2 T4 / CC 3.1.8 | never sole input to slashing composer |
| `detection:intra_agent_consistency` | The 3.4.5 self-emission rejection binds capacity:* ONLY; self-observation is the intended case for intra_agent_consistency (one agent vs itself). | CC 3.4.5 / 3.4.8 / 4.5.8.3 | self-subject NOT forbidden (corrects the seed's never-own-subject note) |
| `detection:intra_agent_consistency` | identity_type is set-membership; cohabitation grants per-role emit rights but never merges namespaces. | CC 3.4.7.1 | role-cohabitation set-gated; namespaces never merge |
| `detection:temporal_drift` | detection:* (incl. temporal_drift) is LensCore-only via a blanket wildcard at persist admission - SHIPPED (persist v21.4.0), the CC-text hedge is stale. | CC 3.4.8 | emit gated; wildcard live |
| `detection:temporal_drift` | Non-detector cross-checks MUST ride truth_grounding:detection:temporal_drift (rejected at admission for non-detector keys; would shadow otherwise). | CC 3.4.8 | cross-attestation on detection:* itself FORBIDDEN for non-detector keys |
| `detection:temporal_drift` | Observation, not adjudication: never sole/standing verdict. CONFIRMED GAP: compose_policy has exactly one sole-evidence-for-slashing screen (testimonial_witness) - no detection:... | CC 3.1.8 | never sole input to slashing composer - STATED but UNENFORCED in the reference composer |
| `detection:temporal_drift` | Sibling ratchet:flag:* carries the explicit cannot-be-sole-slashing-evidence rule, corroborating that the missing screen is a real completeness gap. | CC 3.1.6 | same discipline; no screen implemented for either family |
| `detection:temporal_drift` | Detector dimensions default-aggregate via MEDIAN of raw score (weight-free); shipped consumer policy deliberately extends this to the whole detection:* prefix (server polarity_f... | CC 4.4.2 | median-of-raw-score required, not signed mean |
| `detection:temporal_drift` | CC 3.4.5's capacity-only self-emission rule does NOT extend to temporal_drift; no equivalent bar found - flagged open question. | CC 3.4.5 | self-emission not confirmed forbidden (constitution-silent) |
| `dma:csdma:*` | dma:* is open-vocabulary signed DMA-verdict telemetry with no reserved-emitter restriction and no self-emission bar (unlike capacity:*) - self-attestation is expected. | CC 3.1.5.1; CC 3.4.5 contrast | self-emission expected; no never-sole-evidence clause stated (honest empty, flagged) |
| `dma:csdma:*` | Default signed composition is Mean(score x confidence) per (dimension, attested_key_id) - trace_id must live in the dimension leaf for the default to be semantically safe, else ... | CC 4.4.2 | aggregate REQUIRED per (dimension incl. trace_id, attested_key_id); dimension MUST encode the decision instance |
| `dma:csdma:*` | The dma chain (incl. csdma) is the evidentiary surface behind fidelity:explainability_sla L3/L4; a tier-promoting composer MUST verify the corresponding dma attestation(s) exist... | CC 3.1.9.4 + CC 3.1.5.2 | emission-completeness requirement feeding a named downstream composer |
| `dma:csdma:*` | Local-tier eligibility = sole revocation authority; witness_relation MUST be self for any local-tier write. | CC 5.3.2.4/5.3.2.4.1 | qualifies for local-tier given empty subject_key_ids + explicit witness_relation:self; promotion is a separate deferred idempotent step |
| `dma:csdma:*` | fold-with-conscience:* is asserted twice at glossary level but NOT operationalized in the normative body - documented intent pending amendment, not enforceable composition. | FSD-005 App.A (appendix-only) | no compile/admission-checkable dma-conscience fold today; treat as intent |
| `dma:csdma:*` | JCS canonical bytes forbid post-hoc payload stripping by relay/consumer; per-viewer strip of raw traces would invalidate signatures - keep raw_chain_of_thought OUT of the signed... | CC 2.6.1/2.6.1.1 | per-viewer strip primitive does not exist and cannot; blob-backed hash reference is the correct shape |
| `dma:dsdma:{domain}:*` | Aggregation is per (dimension, attested_key_id) with signed default Mean(score x confidence); trace_id must therefore live inside the dimension string or the default silently me... | CC 4.4.2 | aggregate REQUIRED (mean) per (dimension incl. trace_id, attested_key_id) |
| `dma:dsdma:{domain}:*` | Reasoning-trace emission requires no reserved identity_type; no capacity-style self-emission ban exists - self-attestation is the expected normal mode. | CC 4.5.8.3 | no dedicated emitter identity_type; self-attestation NOT forbidden |
| `dma:dsdma:{domain}:*` | witness_relation must be explicitly declared by a CCP (default reads external); an undeclared self-scored dma verdict misrepresents itself as independent testimony. | CC 2.1 / CC 2.2 | witness_relation MUST be explicitly set on self-scored verdicts; consumers SHOULD discount self |
| `dma:dsdma:{domain}:*` | dma:* and conscience:* verdicts about the same chain fold together ('fold with conscience:*') - reasoning-soundness composition uses both, never dma alone. | FSD-005 App.A (FSD-tier, not Part 3/4 normative) | soundness composition SHOULD fold dma with the four conscience faculties |
| `dma:dsdma:{domain}:*` | L2/L3/L4 explainability tiers name the DMA-chain visibility a producer commits to; a capability strip below a committed tier for an entitled recipient IS the breach and MUST sur... | CC 3.1.5.2 + CC 3.1.9.4 | recipient-capability gating MUST NOT silently drop below committed tier without emitting the hard_case flag |
| `dma:dsdma:{domain}:*` | {domain} is open vocabulary with NO CC-supplied convention (no registry analogous to WITNESS_KIND_REGISTRY.md exists for DMA domains); seed's enum is unsourced. | CC 4.5.1.1 | documented convention required but CC does not provide one - CONSTITUTION-SILENT; owning repo should register one |
| `dma:idma:*` | dma:idma:* verdicts fold with conscience:* as the composed reasoning-quality picture; idma is not scored or consumed in isolation. | FSD-005 App.A:79 + CC 3.1.5.3 | consumer MUST join idma with sibling conscience:* for the same decision_instance_ref before rendering a reasoning-quality verdict |
| `dma:idma:*` | dma:* is the evidentiary substrate behind the explainability SLA ladder (L1..L4); breach surfaces as hard_case:sla_breach_unattested, never silently. | CC 3.1.5.2 + 3.1.9.4 | L3/L4 SLA claims require a resolvable dma:idma:* (+chain) attestation; absence composes to the hard_case flag |
| `dma:idma:*` | No reserved-emitter or self-emission-rejection applies to dma:idma:* - full 3.4.1-3.4.13 catalog has no dma entry. | CC 3.4.5/3.4.8 read against absence | admission MUST NOT apply the capacity-style rejection; self-attestation is the correct default shape |
| `dma:idma:*` | No aggregation/calibration override specified: signed polarity falls to the CCC minimum default Mean(score x confidence). | CC 4.4.2 | generic mean unless a family override is separately ratified; no bespoke weighting primitive |
| `dma:pdma:*` | The fabric's role is attestation THAT the PDMA (incl. the Veto check) executed - never adjudicating the value judgment; substrate may enforce structural completeness only. | CC 1.3 | substrate FORBIDDEN from adjudicating/gating veto correctness |
| `dma:pdma:*` | A predicted >=10x entropy-reduction win over any flourishing axis is a mandatory WBD-deferral trigger; a pdma verdict recommending execute under that condition is constitutional... | CC 1.3 | non-DEFER verdict FORBIDDEN when the order-maximisation veto condition holds |
| `dma:pdma:*` | Deployments >100k MAU MUST publish redacted PDMA logs + WBD tickets within 180 days; absence voids CIRIS compliance. | CC 1.3 / CC 1.16.3 | emit carries an eventual mandatory-publish obligation at qualifying scale (non-discretionary transmission floor) |
| `dma:pdma:*` | dma:pdma:* self-emission is open and expected - never reserved, never self-emission-forbidden. | CC 3.1.5.1 / 3.4.5 / 3.4.8 | self-emission ALLOWED; capacity rule does not extend |
| `dma:pdma:*` | An explainability-SLA commitment at L3/L4 is fulfilled only if the referenced decision's dma chain resolves; otherwise consumer composition MUST surface hard_case:sla_breach_una... | CC 3.1.5.2 / 3.1.9.4 | chain resolvability is the evidentiary predicate; pdma never sole-emits its own SLA verdict |
| `dma:pdma:*` | oversight_mode values are closed to HITL\|HOTL\|HOOTL (deferred/active/advisory REJECTED); mode shifts are themselves attestable, never silent. | CC 4.1.5 / CC 2.1 | oversight_mode enum CLOSED; new narrative values FORBIDDEN |
| `expertise:{domain}:{language}` | RATCHET names this family in its anti-Sybil detector (ratchet:flag:expertise_attestation_anomaly), advisory-only, never sole slashing evidence. | CC 3.1.6 | the anomaly flag never sole input to slashing |
| `expertise:{domain}:{language}` | Fraud beliefs route through moderation:expertise_fraud + P8 WA quorum; slashing never fires from disagreement with a claimed level. | CC 3.1.9.2 | slashing requires documented allegation + quorum adjudication; decoupled from score disagreement |
| `expertise:{domain}:{language}` | Expertise standing is a REQUIRED multiplicative input to Contribution vote weight (Weight = Credits x expertise) - governance-critical accuracy, domain/language pair-matched aga... | CC 3.1.9.3 | required multiplier input; segments must pair-match credits:{domain}:{language}:{subject} |
| `expertise:{domain}:{language}` | Unlike capacity:*, expertise carries no CC 3.4.x reservation - self-assertion legal, in explicit contrast. | CC 3.4.5 / 3.4.7 | self-emission permitted; no emitter gate at admission |
| `expertise:{domain}:{language}` | Composition weights differ by feed shape: within-cohort weighting + cross-cohort downweight-unless-invited (community_feed); full federation weighting + Frickerian discipline (g... | CC 4.4.3.3 | cohort-tiered projection policy required |
| `expertise:{domain}:{language}` | [DRAFT RT-H7, unratified] expertise needs a single-source confidence cap (<=0.5 until independently corroborated, licensure-analog) - else a cell cross-attests its own expertise... | FSD-005 sec.7 / analogy CC 3.4.9 | proposed cap - ABSENT from ratified CC and unenforced; needs-human-review |
| `federation_directory:replication_lag` | system:* substrate-self-report reservation: substrate_persist emitter, steward-triple cross-attested; category-error rejection. | CC 3.4.3 | emit gated at admission; not producer-discretion |
| `federation_directory:replication_lag` | Three-layer enforcement: admission reject + independent consumer re-verify + producer conformance; trust does not propagate. | CC 3.4.7 | every CCC MUST independently re-verify the emitter rule on every received row |
| `federation_directory:replication_lag` | Third-party observation of another node's health rides a distinct non-reserved dimension - never the reserved system:* leaf (health:liveness precedent). No such analog dimension... | CC 3.1.9.4 analogy + CC 3.4.3 | cross-node stale-looking claims FORBIDDEN under this leaf; separate open dimension required (unnamed today) |
| `federation_directory:replication_lag` | recants attester-only; recipient_revoke collapses to self; recants/withdraws/supersedes all remain available to the substrate (recant NOT forbidden by any text). | CC 2.4.1.1 / 2.4.1.3 | revoke = rule-1 only |
| `federation_directory:replication_lag` | Promotion is the federation-emit moment - cohort_scope for this leaf must be hoisted/typed and defaulted federation-visible at promotion so the freshness-weighting use case is r... | CC 5.3.2 / 4.4.3.3.1 | promote-with-full-placement: default Global at promotion, not SelfOwn |
| `federation_directory:replication_lag` | Units/encoding are an open CC editorial gap; no superset field may be represented as CC-mandated. | CC 8.1.2 via FSD-005 | lag_seconds/method/sla fields are engineering discretion pending closure |
| `fidelity:explainability_sla:{tier}` | Envelope has a FIXED closed shape {committed_tier, achieved_tier, fallback_reason?} over a 4-value closed tier enum; no discretionary SLA-terms/coverage/latency/window/rate/coun... | CC 3.1.5.2 | schema CLOSED; seed's invented fields FORBIDDEN as this dimension's own wire object |
| `fidelity:explainability_sla:{tier}` | A committed-vs-achieved shortfall MUST surface as hard_case:sla_breach_unattested via NodeCore composition - never a private unsurfaced fact. | CC 3.1.5.2 + 3.1.9.4 | compose-and-emit REQUIRED on shortfall; needs a typed enum comparator (untyped extra makes the invariant silently unenforceable) |
| `fidelity:explainability_sla:{tier}` | sla_breach_unattested is one of the constitution's own ENUMERATED canonical hard_case kinds - spec-fixed name, positive-only polarity; absence of the event (not a negative score... | CC 3.1.9.4 | kind-name spec-fixed; never emitted negative to mean no-breach |
| `fidelity:explainability_sla:{tier}` | NOT reserved to any identity_type (unlike substrate-self-report hard_case membership kinds) - any accord-agent producer may emit about its own responses. | CC 3.1.5.2 (vs 3.4.2/3.4.4 pattern) | no reserved-emitter gate (confirms seed reserved:false) |
| `fidelity:{aspect}` | The open fidelity:{aspect} vocabulary and the closed fidelity:explainability_sla:{tier} sibling are DISTINCT dimensions sharing a prefix token; dispatch MUST route them to diffe... | CC 3.1.5.2 + 3.1.9.4 | dimension dispatch MUST exhaustively distinguish the sibling before generic aggregation; no shadowing |
| `fidelity:{aspect}` | No CC 3.4 reserved-prefix emitter rule - CC 3.4.7 enforcement is a no-op; substrate MUST admit regardless of identity_type/role; self-emission NOT forbidden. | CC 3.4.7 by omission | no reserved-emitter admission gate |
| `fidelity:{aspect}` | Default aggregation is the CC 4.4.2 signed mean (score x confidence) - no override; matches server polarity_for fallthrough (already correct, needs no change). | CC 3.1.5.2 polarity + CC 4.4.2 | aggregate REQUIRED (mean); never a bespoke special-case |
| `goal:{scale}` | Every persist-typed Goal MUST carry MetaGoalAlignment (M-1 dimension + rationale) as a type-system construction-time invariant - CONFIRMED live (Goal::new takes it by value, no ... | CC 3.1.9.7 | Goal-construction primitive takes MetaGoalAlignment by value |
| `goal:{scale}` | Declaration and retirement MUST ride durable ack-required federation transport, never fire-and-forget. | CC 3.1.9.7 + WIRE_VOCABULARY:97-98 | Delivery::Durable{requires_ack:true} calibration required for both messages |
| `goal:{scale}` | Retirement authority is single-signer (envelope hybrid signature is the sole proof); no quorum path exists today even for federation-scope goals (deferred amendment). | WIRE_VOCABULARY:98 (+matching code) | retire primitive MUST NOT assume quorum exists; Federation quorum-retirement is future, not silently treated as enforced |
| `goal:{scale}` | Slashing is decoupled from disagreement at every decision-hierarchy level; a contested Goal claim never feeds slashing by itself. | CC 3.1.9 (slashing row) | goal:{scale}/Goal MUST NOT be sole/direct slashing input on contestation |
| `goal:{scale}` | [UNVERIFIED] 'Scored by capacity composite' - no composer wires Goal/goal:{scale} into any composite factor (score.rs derives factors solely from CapacityAttestation); treat as ... | CC 3.1.9.7 | do not build a compile gate assuming the scoring clause is live |
| `goal:{scale}` | Canonical scale vocabulary is the fixed 7-value Scope set (self/family/community/affiliations/species/biosphere/federation); 'planet' is a colloquial alias for biosphere - CC 3.... | CC 2.5 | any exhaustive {scale} enum MUST use the 7-value Scope set, not the literal row text |
| `hard_case:{kind}` | hard_case:* is NEVER a slashing input - raw observability; punitive composition happens only downstream in detection:*/moderation:*. | CC 3.1.9.4 + 4.4.3.5.2 + part_4:1364 + adult-incapacity line | FORBIDDEN as any (not merely sole) input to a slashing composer |
| `hard_case:{kind}` | A closed set of 9 hard_case kind-strings (4 community + 4 family/identity + recipient_excluded) are reserved to substrate_persist; both admitting substrate and every consumer re... | CC 3.4.2 / 3.4.4 / 3.4.7 | reserved-emitter gate on 9 named kinds; category-error MUST-reject at admission AND re-check |
| `hard_case:{kind}` | IMPLEMENTATION EVIDENCE: the shipped admission gate is broader-but-inert (whole hard_case: attestation_type reserved, but only on a dead wire shape); hard_case: is ABSENT from t... | impl-only: persist admission.rs check_reserved_prefix_admission vs default_reserved_prefix_rules vs hard_case.rs | admission-gate coverage gap on the wire shape CC 3.1.9.4's own prose describes |
| `hard_case:{kind}` | New {kind} values are documentation-only open vocabulary: no calibration package; first-registered-wins + Levenshtein<=2 advisory + 90-day reclaim. | CC 4.5.1.1 / 4.5.1.3 | no calibration gate; collision rules substitute for amendment |
| `hard_case:{kind}` | Keyed kinds MUST carry the named key in subject_key_ids; substrate MAY admit-and-flag via hard_case:subject_authority_missing (operator policy). | CC 4.5.2.1 | subject-bearing gate for keyed hard_case kinds |
| `hard_case:{kind}` | Emission is MANDATORY/never-silent at named transitions (moderator lapse/auto-promotion, watchlist enable + every match, steward acts, minor-protection widening, safeguarding es... | CC 4.5.4 / 4.5.7 + part_3 never-silent lines | MUST-emit obligation at named state transitions |
| `hard_case:{kind}` | IMPLEMENTATION EVIDENCE: the CC 4.5.4 never-silent obligation is UNENFORCED - existence_verdict computes the Quiesce/AutoPromote reason but never calls record_hard_case (open Up... | impl-only: CIRISServer safety/named.rs + safety/watchlist.rs | never-silent primitive declared in code but not wired to any durable emission |
| `hardware_custody:{platform}` | hardware_custody is a wire MECHANISM fact; whether it satisfies the L2 ladder rung is exclusively CONSUMER-side composition - the family must never assert a ladder position. | CC 4.4.3.6 / CC 3.1.2 | wire emission FORBIDDEN from carrying ladder-verdict shape |
| `hardware_custody:{platform}` | capacity's self-emission REJECTION is scoped to capacity:* only; self-measurement here is PERMITTED and the only measurement-honest pattern, but nothing requires or enforces it. | CC 3.4.5 (contrast) | no self-emission requirement or rejection binds this family; third-party assertion not constitutionally barred |
| `hardware_custody:{platform}` | Custody-tier transitions are supersedes, never recants (prior claim was true when made). | CC 2.4.1 / 2.4.1.3 | recant FORBIDDEN for ordinary tier transitions |
| `hardware_custody:{platform}` | The raw platform-attestation blob already has a canonical home: identity_occurrence.hardware_attestation; custody claims should reference that artifact, not mint duplicate blobs. | CC 3.3.6 / 4.5.12.3 | evidence MUST be a reference into the existing verified artifact |
| `hardware_custody:{platform}` | cohort_scope/subject_key_ids/delivery_mode are orthogonal; producers MUST set cohort_scope explicitly - relying on the substrate federation-wide default is a category error for ... | CC 2.3.3 | explicit scope pinning at emission required |
| `health:liveness:{version}` | health:liveness is a named composition riding the existing scores primitive; NO new structural primitive and no bespoke typed probe fields. | CC 3.1.9.4; FSD-005 App.A:213 | new typed fields for probe detail FORBIDDEN - evidence_refs only |
| `health:liveness:{version}` | witness_relation MUST be external - a service never attests its own liveness under this family (that channel is reserved system:*). | CC 3.1.9.4 / CC 3.4.3 | self-attestation (attester==attested) FORBIDDEN; emission under system:* is a category error |
| `health:liveness:{version}` | Non-keyed infrastructure may never be the subject of a standalone liveness attestation; it folds in as evidence_refs on a keyed service's score. | CC 3.1.9.4 | attested_key_id restricted to keyed services (structurally guaranteed by the FK today) |
| `health:liveness:{version}` | epistemic_mode for this family is the pair {direct, derivative} from the canonical five-value axis - not a reopening of rejected introspection/testimony shapes. | CC 3.1.9.4 / CC 2.5 / CC 4.1.5 | epistemic_mode restricted to {direct, derivative} |
| `health:liveness:{version}` | Cross-fabric replication between out-of-group peers requires a live bidirectional consent:replication:v1 grant naming the prefix; replicating under a withdrawn/absent grant is n... | CC 3.3.7 | replication-without-live-grant non-conformant for out-of-group peers |
| `health:liveness:{version}` | No anti-aggregation restriction exists (contrast testimonial_witness) - cross-monitor consensus composition remains available; deliberate absence, not a gap. | CC 3.1.9.4 (silent); contrast CC 3.1.9.3 | aggregate NOT forbidden |
| `holds_bytes:sha256:{prefix}` | Emission FORBIDDEN outright (row never created) for cohort_scope self\|family. | CC 5.2 | emit FORBIDDEN at the blob-write dispatch boundary (no signer invoked), not a read-time filter |
| `holds_bytes:sha256:{prefix}` | Consumers MUST verify the FULL SHA-256 from evidence_refs before any bytes handoff; never short-circuit to the prefix. | CC 5.3.2.5 | full-hash verification is a hard precondition on every consumption (edge dispatch gate implements) |
| `holds_bytes:sha256:{prefix}` | Withdraw authority is not producer-exclusive: a verified ContentMiss obligates the CONSUMER to withdraws the holder's attestation; chronically-missing holders MUST be downweight... | CC 5.3.2.1 | third-party withdraws on verified miss (withdrawal_reason=content_miss); downweighting required |
| `holds_bytes:sha256:{prefix}` | cohort_scope is a 3-way emit-shape dispatch (none / cleartext-provenance-over-ciphertext / plaintext) - never one uniform visibility rule. | CC 4.4.3.2.1 | composers MUST branch on the 3-tier table; encryption and discovery tiers are orthogonal |
| `holds_bytes:sha256:{prefix}` | Upstream consent-revocation MUST cascade automatic withdraws against every live holds_bytes row for its bytes. | CC 5.3.2.1 applied (part_4:1200) | required cross-object cascade (takedown_handler/media_sharing/erasure implement); never holder discretion |
| `holds_bytes:sha256:{prefix}` | No second holder-directory may exist; specializations (FountainHoldingClaim) reuse the TTL/ContentMiss machinery; holder claims feeding retention/eviction must be possession-cha... | CC 6.1.5 | second-index FORBIDDEN; unverified claims must not lower another peer's retention priority |
| `holds_bytes:sha256:{prefix}` | Scope-widening promotion (community->federation) MUST re-emit holds_bytes AND run the perceptual-hash tripwire at that seam - never on-device, never inside a cohort. Hook exists... | CC 1.13.3.4 | mandatory composition step at the widening seam; DeferredNoMatcher today |
| `holds_bytes:sha256:{prefix}` | Evidence composers MUST flag (never launder) citations resolving to self/family holds_bytes served out-of-band (structurally unscannable). | FSD-005 RT-M3/F | absence of a directory entry never treated as verified well-sourced evidence |
| `identity_continuity:relational_anchor` | One of the four canonical CC 3.1.3 persist self-report leaves; emittable ONLY by the running Persist instance - no third party can speak for the substrate. | CC 3.1.3 | delegates_to FORBIDDEN (emit authority non-transferable) |
| `identity_continuity:relational_anchor` | system:* reserved to substrate_persist, steward-triple cross-attested; non-substrate emission MUST be rejected at admission and independently re-checked by consumers. | CC 3.4.3 / CC 3.4.7 | sole emit authority = substrate_persist row (identity_type layer enforced in persist; cross-attestation satisfied upstream per persist's documented division of labor) |
| `identity_continuity:relational_anchor` | long_term_key has no independent wire existence - canonicalizes to relational_anchor. | CC 8.1.2 | single canonical leaf; no parallel dimension string valid |
| `identity_continuity:relational_anchor` | A node's infra/governance self-report about its own state is Commons-tier, cohort_scope:federation, world-readable - not a private fact. | CC 4.4.3.2.1 (part_4:346) | supports federation as the correct default (corrects seed self) |
| `identity_continuity:relational_anchor` | Operational definition, score semantics, and superset vocabulary are NOT specified - deferred to a future CC 8.1 amendment; proposed fields are engineering, not ratified. | FSD-005 App.A | none beyond the reservation itself - honest empty |
| `integrity:{aspect}` | integrity:{aspect} is the wire form of Act Ethically: producer self-attests conformance of a specific act/reasoning-trace to a named ethical aspect; signed, open vocab, not rese... | CC 3.1.5.2 | no reserved-emitter gate; default signed composition |
| `integrity:{aspect}` | The substantive content is PDMA-execution fidelity + correct WBD-trigger behavior - conformance_basis scoped to these, not a vibe check. | CC 1.8-1.9 | conformance_basis content scoped to PDMA/WBD |
| `integrity:{aspect}` | Accountability = tamper-evident logs/rationale chains; the evidence chain rides the EXISTING evidence_refs (ordered), not a new field. | CC 1.15.2 | reasoning-trace evidence MUST ride evidence_refs; no new typed field warranted |
| `integrity:{aspect}` | references_attestation_id names a prior SAME-attester attestation for supersede/withdraw/recant - not a generic pointer. | CC 2.1 (lines 195-197) | act_ref MUST NOT be implemented via references_attestation_id (would corrupt lineage semantics) |
| `integrity:{aspect}` | Reserved-prefix enumeration is exhaustive; integrity:{aspect} is absent from all sub-lists. | CC 3.4.1-3.4.6 | no admission-time emitter-identity gate |
| `integrity:{aspect}` | Default aggregation is Mean(score x confidence) - no override exists (contrast testimonial/ratchet carve-outs). | CC 4.4.2 | aggregate IS permitted/default for this family |
| `integrity:{aspect}` | Open-vocab aspects need a calibration package OR documented convention; integrity has neither (no registry yet). | CC 4.5.1.1 | new {aspect} not compile-safe until a documented-convention registry exists |
| `integrity:{aspect}` | integrity:finitude_acknowledgment was dispositioned LOW/deferred - owned by conscience:epistemic_humility. | CC 8.3.6 | {aspect} registry MUST exclude finitude_acknowledgment (cross-family duplication guard) |
| `integrity:{aspect}` | fidelity:explainability_sla:{tier} is the actual reasoning-disclosure-tier machinery; integrity:{aspect} must not subsume/duplicate it - cite via evidence_refs only. | CC 3.1.5.2 line 125 / 3.1.9.4 | no duplication of the tier machinery |
| `integrity:{aspect}` | witness_relation self-attestation-gaming tension: this family's designed default (self) is the exact case the generic discount guidance targets; CC does not reconcile - flagged,... | CC 2.1 line 24 | CONSTITUTION-SILENT: no rule for trusting designed self-attestation vs generic discount |
| `judge_model:verdict:{model_id}` | boolean-via-score polarity: default aggregation is Min across attesters per (dimension, attested_key_id) - fail-secure, any FAIL trumps PASS; not mean. | CC 3.1.9.4 + CC 4.4.2 | composer MUST apply Min; MUST NOT default to signed-mean |
| `judge_model:verdict:{model_id}` | AI-consensus framing across model_ids requires (a) execution-provenance binding (provenance:*/agent_integrity proving the verdict came from that build) and (b) an org-level witn... | FSD-005 sec.7 (RT-H5/RT-M8 ACCEPTED), composing CC 3.1.9.4 + 3.1.9.3 | consensus composer FORBIDDEN from presenting multi-model agreement without provenance binding + diversity gate |
| `judge_model:verdict:{model_id}` | judge_model attestations remain attributed, filterable by attester/model class, never silently folded into an anonymous aggregate. | FSD-005 sec.7 | display/composition MUST remain attributed + filterable |
| `judge_model:verdict:{model_id}` | The provenance/diversity hardening is explicitly OUT of the persist wire contract - server-tier + CEG-spec consumer policy, not a new persist primitive or EnvelopeCore hoist. | FSD-005 App.C C.5 | implement as consumer/server composition policy (compose_policy.rs), NOT a persist wire primitive |
| `judge_model:verdict:{model_id}` | recants remains available at the wire tier to the original attester (epistemic error); per-family disabling is card-tier policy only. | CC 2.4.1/2.4.1.3 | recants MUST remain wire-available to the attesting key |
| `judge_model:verdict:{model_id}` | No natural person-subject (attested defaults to attester per R-C1); judged party gets no rule-2/3 revoke path; subject_key_ids must not be populated with the judged party for re... | CC 4.5.2.1 + CC 2.4.1.1 rule 2 | subject_key_ids MUST NOT carry the judged party's key with revoke intent (producer-self revoke only by design) |
| `justice:{aspect}` | justice:{aspect} is an open (non-reserved) signed accord-principle dimension: producer self-report that a named decision distributed benefits/burdens equitably. | CC 3.1.5.2 | no reserved-emitter gate; any non-substrate key |
| `justice:{aspect}` | Conceptual sibling of, and textually distinct from, the population-scale distributive detectors - same equity concern, different structural class. | FSD-005 App.A:116 (x-ref 3.1.5.2 + 3.1.8.4-5) | FORBIDDEN as detector-class evidence; detector verdicts must not be re-emitted/shadowed under justice:{aspect} |
| `justice:{aspect}` | The detector family is lenscore_detector-reserved and Median-aggregated; justice:{aspect} carries neither restriction. | CC 3.4.8 | mean (score x confidence) aggregation, NOT median; no detector gate |
| `justice:{aspect}` | Absent an override, CCC consumers MUST aggregate signed justice attestations as Mean(score x confidence) - deliberate contrast with testimonial's aggregate-FORBIDDEN. | CC 4.4.2 | aggregate permitted/expected |
| `justice:{aspect}` | Generalizing 4.5.1.1: open {aspect} with no calibration package follows the documentation-only path (non-normative registry, no spec amendment), gated by the 4.5.1.3 collision g... | CC 4.5.1.1 / 4.5.1.3 | {aspect} MUST remain open + registry-discoverable; closed-enum locking FORBIDDEN |
| `justice:{aspect}` | 4.5.2.1's mandatory subject gate binds only key-embedding patterns; justice does not embed one - subject_key_ids stays optional; affected_cohort_ref is the mandatory-ABOUT field... | CC 4.5.2.1 / CC 2.3 | no admission rejection on absent subject_key_ids; require the cohort ref instead |
| `key_boundary:{scope}` | Reserved substrate-self-report: only identity_type containing substrate_edge (steward-triple cross-attested) may emit; non-substrate emission is a category error. | CC 3.4.3 | emit FORBIDDEN unless substrate_edge set-membership; CCS MUST reject + CCC MUST re-check |
| `key_boundary:{scope}` | Role cohabitation does not relax the steward cross-attestation requirement for key_boundary emissions. | CC 4.5.8.1 | cohabiting-key emission still requires the full cross-attestation |
| `key_boundary:{scope}` | Every open-vocabulary {scope} value must carry an operational definition (calibration package or documented convention). | CC 4.5.1.1 | freeform unregistered scope tokens non-conformant; the KeyBoundaryScope enum is the de facto convention needing constitutional inlining |
| `key_boundary:{scope}` | New {scope} sub-identifiers subject to the open-vocabulary collision discipline (first-registered-wins, Levenshtein advisory, 90-day reclaim). | CC 4.5.1.3 | collision guard SHOULD apply to sibling scope identifiers |
| `key_boundary:{scope}` | Self-report path structurally distinct from external-observer health attestation; a third party MUST NOT emit under this prefix (external verdicts ride health:liveness). | CC 3.4.3 (contrast part_3:237) | emitter must be the substrate_edge key itself, never external witness_relation |
| `licensure:{authority_id}` | Co-stewarded between CIRISRegistry and CIRISVerify; both emit INDEPENDENTLY (not a joint co-signed envelope); single-source attestations MUST compose at confidence <= 0.5 until ... | CC 3.4.9 | consumer confidence cap, NOT an admission dual-signature requirement; two DISTINCT co-steward classes required to exceed 0.5 |
| `licensure:{authority_id}` | The substrate admission gate does NOT reject single-source or non-co-steward emissions on licensure:* - enforcement deferred entirely to the consumer. | CC 3.4.7 contrasted with 3.4.9's non-exclusionary language (code-confirmed) | NOT admission-gated; must not be modeled as a persist reserved-prefix rejection |
| `licensure:{authority_id}` | A Sovereign Registry-role key's licensure score is wire-identical to the canonical steward's; consumer policy (not wire shape) differentiates trust. | CC 4.4.4 | no privileged wire shortcut for canonical stewards |
| `licensure:{authority_id}` | Meta-judgments (trust/validity verdicts) compose downstream FROM licensure:*, never smuggled as a co-located prefix. | CC 4.1.3 | folding a meta-judgment/ladder position into the licensure prefix FORBIDDEN |
| `licensure:{authority_id}` | The named-practitioner dimension form MUST carry subject_key_ids naming the practitioner. | CC 4.5.2.1 | admission MAY reject named-practitioner-form rows with empty subject_key_ids (unimplemented - cc_impl open) |
| `licensure:{authority_id}` | Anti-pattern discipline: no new typed status/revocation envelope fields - status rides score polarity, existing valid_until, context/evidence_refs, or the sibling revocation:* p... | CC 4.1.2 / 4.1.3 | status/license_id/issued_at/revoked_at/reason_code hoists FORBIDDEN |
| `locality:decision:{scale}` | WA quorum size is a function of the asserted decision locality - never a fixed constant (quorum_size(scale): local=2/regional=3/national=4/federation=6 reference). | CC 4.4.3.1 (+RC1-7) | quorum composer MUST look up quorum_size(scale); hardcoded N FORBIDDEN |
| `locality:decision:{scale}` | Fresh-quorum recusal is feasible only when cell_pool >= quorum_size(scale) x 2; overreach surfaces as a NAMED locality-mismatch failure, never a silent pass. | CC 4.4.3.1 | recusal-eligibility gate MUST check min_pool before treating any WA-quorum outcome as valid |
| `locality:decision:{scale}` | When cell_pool < min_pool(scale), the consumer MUST take exactly one explicit path - scale-down (supersedes + hard_case:locality_scale_down), escalate (federation cell + hard_ca... | CC 4.4.3.1.1 | sub-quorum handler forbidden from silently proceeding; mandatory hard_case co-emission |
| `locality:decision:{scale}` | locality:decision:federation is the recursion-safety floor: federation-scale sub-quorum failure is a constitutional-crisis state resolvable only by the HUMANITY_ACCORD CONSTITUT... | CC 4.4.3.1 recursion clause + CC 4.5.1 + CC 4.2 | composer MUST special-case scale=federation as the escalation ceiling |
| `locality:decision:{scale}` | {scale} is a closed 4-value enum local\|regional\|national\|federation. | CC 3.1.9.5 | admission validator MUST reject other suffixes (corrects seed's 6-value vocabulary; confirmed by code) |
| `manifold_conformity:{cohort}` | LensCore 3.1.8 prefixes observe and never adjudicate; must feed downstream human/WA-quorum judgment, never a self-sufficient verdict. | CC 3.1.8 | FORBIDDEN as sole/direct input to authority/punitive composers |
| `manifold_conformity:{cohort}` | Low-confidence bad-actor-shaped signals on the cohort-conformity siblings must be adjudicated via NodeCore P8 WA quorum, never composed straight into accusation/action. | CC 4.1.3 | never sole slashing evidence; P8 quorum is the adjudication gate |
| `manifold_conformity:{cohort}` | Every open {cohort} value must carry an operational definition (calibration package or documented convention); the constitution says absent - but code-grounding found a real ver... | CC 4.5.1.1 + CC 3.1.8.3/FSD-005 gap flag | emit requires resolvable calibration/convention; Part 3/FSD need a citation update, not new invention |
| `manifold_conformity:{cohort}` | No reserved-emitter rule exists for this family (unlike both 3.1.8 siblings) - constitution-silent, not invented; open-emit-including-self posture flagged as an open question. | CC 3.4.5/3.4.8 (absence) | no emitter-identity gate and no anti-Goodhart self-emission bar currently binds - open question |
| `manifold_conformity:{cohort}` | Every CC family MUST ride the single scores workhorse in federation_attestations; CODE-CONFIRMED: this family has NO such realization - it exists only as a detector token inside... | CC 2.4/2.4.2 | emit MUST be a scores row bearing dimension=manifold_conformity:{cohort}; none is ever produced (10th dark-family candidate, relayed to auditors) |
| `method:{approach_id}:{substrate_rung}` | Slashing is decoupled from disagreement at EVERY decision-hierarchy level; a contested method claim never feeds slashing by itself - only a DOCUMENTED Method-execution-spoofing ... | CC 3.1.9.2 | FORBIDDEN as disagreement-triggered slashing input; sole slashing-relevant input is a documented spoofing finding |
| `method:{approach_id}:{substrate_rung}` | method is the mandatory middle link of the upward-only decision DAG (goal <- approach <- method <- progress_measure); approach_id is a parent-reference so nothing is done withou... | CC 3.1.9.7 + FSD App.A | emission SHOULD be gated on approach_id resolving to an existing non-withdrawn approach:{goal_id} attestation - never emission-optional decoration |
| `method:{approach_id}:{substrate_rung}` | substrate_rung is a REQUIRED bounded ordinal (Ph0/Ph1/Ph2/A0..A5), explicitly a different scale from the CC 7.5.3.1 oversight A0-A4 despite shared letters. | CC 3.1.9.7 (line 265,268) | admission MUST validate against the Corridor-Dynamics enum specifically; letter-collision hazard the constitution itself flags |
| `moderation:{allegation_type}` | moderation:{allegation_type} is an accusation only - never sole basis for slashing; slashing requires a separately-adjudicated quorum-backed SlashingAttestation on documented ev... | CC 3.1.9.2 | FORBIDDEN as sole/automatic slashing input; distinct quorum-adjudicated object required |
| `moderation:{allegation_type}` | Misdeclaration on other reserved dimensions (age_assurance, capacity_assurance) routes THROUGH moderation adjudication, never directly to slashing. | CC 3.1.9.2 / 4.4.3.10 | moderation:{allegation_type} is the REQUIRED intermediate adjudication object for those families |
| `moderation:{allegation_type}` | Emission admission-gated by the CC 4.5.5 rule: as-self named moderate-duty holder OR live steward-rooted delegates_to chain (scope superset {moderate}, depth<=5); no on_behalf_o... | CC 4.5.5 | emit REQUIRES the delegated-duty admission gate; absent-field admit FORBIDDEN |
| `moderation:{allegation_type}` | community_id is load-bearing to admission (resolution key for duty_holders_for_community), not descriptive metadata. | CC 4.5.5 | community_id MUST be present/typed; unresolvable -> only self-admit possible |
| `moderation:{allegation_type}` | Detection/advisory signals (detection:*, ratchet:flag:*) are advisory ONLY - never sole slashing evidence; the admitted duty-holder's adjudicated filing is the load-bearing gate. | CC 3.1.9.2 (honesty discipline) | advisory signals FORBIDDEN as sole evidence; named-moderator/quorum adjudication load-bearing |
| `moderation:{allegation_type}` | No community operates unmoderated; on lapse the highest moderation_track_record member is deterministically auto-promoted, so a filing always has a resolvable duty-holder. | CC 4.5.4 | merit-auto-promotion keeps duty holders non-empty; zero-holder communities fail-secure (refuse moderated-capability federation) |
| `moderation_track_record:{community_key_id}` | moderation_track_record is a NAMED COMPOSITION riding scores, folded deterministically from truth_grounding + witness_diversity + commitment_fulfillment + hard_case:moderation_f... | CC 3.1.9.2 / CC 4.5.4 | emit MUST be a deterministic fold over the 4 named families; free/self-asserted scalar FORBIDDEN |
| `moderation_track_record:{community_key_id}` | Drives CC 4.5.4 merit auto-promotion: on moderator lapse, the member with the highest track record is automatically granted the moderate duty; deterministic selection with tiebr... | CC 4.5.4 rule 2 | never sole/unconditional input to the delegates_to(moderate) appointment - must combine with the rule-3 consent + steward-binding + sufficiency gate; comparator MUST be peer-rep... |
| `moderation_track_record:{community_key_id}` | Never a single global/cross-community score - reputation is community-relative and positional. | CC 4.5.5 | cross-community aggregate FORBIDDEN; cohort pinned to the issuing community |
| `moderation_track_record:{community_key_id}` | The existence-gate + apply-time re-check is a SUBSTRATE invariant over the resulting delegates_to appointment (is_named_moderator), but the merit COMPUTATION lives one layer abo... | CC 4.5.4 enforcement paragraph + persist admission.rs:5083-5088 | comparator/composer above persist; persist only refuses to federate a moderator-less community |
| `moderation_track_record:{community_key_id}` | Fail-secure: if no eligible member exists (insufficient record, none consenting, none steward-bound), the community MUST NOT federate at moderated capability. | CC 4.5.4 rule 3 | raw magnitude insufficient for appointment; sufficiency + consent + steward-binding gate required |
| `moderation_track_record:{community_key_id}` | Subject-bearing dimensions MUST carry the subject. | CC 2.3.3 | subject_key_ids required, naming the scored member |
| `multilateral_participation:{forum}:{kind}` | {kind} is closed to exactly 4 values (membership, voting, proposal_filing, observer_status); each an independent scored participation-facet, not a role tag on one depth gauge. | CC 3.1.1 (row 26) + FSD-005 App.A | no open-vocab path; a 5th value requires a CC 4.5.1 amendment; closed-enum compile-checkable |
| `multilateral_participation:{forum}:{kind}` | NOT reserved and carries no anti-Goodhart self-emission block - self-report by the scored partner (or secretariat on its behalf) permitted, unlike capacity/detection. | CC 3.1.1 Reserved=No; CC 3.4.5 contrast | no attesting!=attested gate required or wanted |
| `multilateral_participation:{forum}:{kind}` | cohort_scope:affiliations is the fitting institutional cohort for {forum} (shares the community DEK machinery); the DEK tier's design presumes a resolvable target for the roster... | CC 4.4.3.2.8 + community_id requirement | promote-with-full-placement: affiliations claims should resolve a real target at admission - persist's AFFILIATIONS arm currently does not (inherited persist gap this family exp... |
| `multilateral_participation:{forum}:{kind}` | No new structural primitive warranted; rides plain scores + the four universal composers. | CC 1.7 | supersedes/withdraws/recants/delegates_to only; no slashing/quorum/aggregate composer applies |
| `need:{domain}:{kind}` | need: is the FEDERATION-SCOPE open-call surface, constitutionally distinguished from deferral_request (single ask within a cell); cell-local asks belong there. | CC 3.1.9.3 line 228 | scope boundary - need: forbidden as a substitute for deferral_request's cell routing |
| `need:{domain}:{kind}` | State transitions ONLY via supersedes (revise), withdraws (satisfy/close), recants (misstated); positive-only polarity, no scored composite. | CC 3.1.9.3 line 228 | no aggregate/scored-composite primitive may touch need:; tombstone-style transitions only |
| `need:{domain}:{kind}` | {kind} is not free text: canonical six values; new/near-dup values governed by the open-vocab convention + collision rules (advisory 409 at Levenshtein<=2; 90-day reclaim). | CC 4.5.1.1 / 4.5.1.3 | admission-time {kind}-collision guard (advisory); documented convention required (none exists) |
| `non_maleficence:{aspect}` | A row describing conduct that hit one of the 22 prohibited categories MUST carry score == -1.0 exactly (per-row floor-on-match). | CC 3.1.5.2 | admission reject (or hard_case) when apophatic_floor_hit==true and score != -1.0 |
| `non_maleficence:{aspect}` | The single-row -1 floor does NOT make the aggregated VERDICT non-overridable (plain signed -> mean dilution); the actual non-overridable fail-secure floor is the SEPARATE siblin... | CC 4.4.2 + CC 3.1.5.4 (+REVIEW_LOG:57) | composers MUST NOT derive network-wide non-overridability from this family's own polarity - that guarantee belongs to prohibited:* |
| `non_maleficence:{aspect}` | Consumers must NOT downweight non_maleficence claims about a partner because of the partner's long partner_role track record (the record may be the harm). | CC 4.4.1 | partner-longevity FORBIDDEN as a credibility-discount input |
| `non_maleficence:{aspect}` | The CC 3.4.7 self-attestation track-record discount runs BEFORE, and is never bypassed by, the Frickerian non-downweight exemption. | CC 3.4.7 + CC 4.4.1 caveat | self discount first; Frickerian never a blanket immunity |
| `non_maleficence:{aspect}` | Self-knowledge does not constitute standing without external witness: self-emitted claims reduce to witness_relation:self + confidence<1.0 + pending external composition. | CC 4.1.5 | self-emitted rows never conclusive standalone |
| `non_maleficence:{aspect}` | When naming a specific affected party, that party SHOULD ride subject_key_ids so they hold revocation authority (documented convention, not admission-enforced). | CC 8.3.4 + CC 2.3 | producer SHOULD populate; pattern not in the enforced 4.5.2.1 catalog |
| `partner_role:{role}` | Enumerated-polarity dimensions (incl. partner_role) compose by most-recent-by-signed_at from authorized attesters - mean/average composition FORBIDDEN. | CC 4.4.2 | most-recent-wins single-value resolution is the CCC default |
| `partner_role:{role}` | A subject's long partner_role track record must never ground downweighting non_maleficence claims about that same subject. | CC 4.4.1 | partner_role FORBIDDEN as an input to any harm-claim credibility-discount for the same key |
| `partner_role:{role}` | PROFESSIONAL_* tiers must compose with co-stewarded licensure; single-source licensure capped at confidence <= 0.5 until the second co-steward corroborates. | CC 3.4.9 (implemented: licensure_cap + live Registry join) | paired licensure co-attestation required before trusting a PROFESSIONAL_* tier |
| `partner_role:{role}` | Partner entity revocation is immediate, non-rollbackable, and forfeits any posted bond - structurally distinct from ordinary withdraws. | CC 3.1.1 (rows 23-24; live-composed, bond leg stubbed None) | revocation:partner:{reason} is -1-only non-rollbackable; MUST compose with bond_posted forfeiture |
| `partner_role:{role}` | Every {role} beyond the canonical six is open-vocabulary requiring a documented convention (kind-registry doc) - which does not exist yet (explicit deferred design item). | CC 4.5.1.1 + CC 8.3.6:255 | novel {role} emission requires a documented convention before consumer trust composition - UNSATISFIED |
| `peer_reachability:{network}` | peer_reachability:{network} is a canonical CIRISEdge leaf whose only templated variable is {network} - no per-peer template slot in the wire dimension. | CC 3.1.4 | dimension MUST NOT carry a peer_id segment |
| `peer_reachability:{network}` | Reserved substrate-self-report: identity_type=substrate_edge cross-attested by the full steward-triple; non-substrate emission is a category error - currently UNIMPLEMENTED in p... | CC 3.4.3 | emitter gate = substrate_edge + steward-triple; REJECT otherwise - gate absent in code |
| `peer_reachability:{network}` | Role cohabitation does not relax the cross-attestation gate. | CC 4.5.8.1 | never grant emission solely on substrate_edge membership without cross-attestation |
| `peer_reachability:{network}` | Per-peer/per-tenant detail collapses into the canonical network aggregate; no separate per-peer wire form. | CC 8.1.3 | aggregate ONLY; wire-level disaggregation to per-peer FORBIDDEN; per-peer detail stays node-local |
| `peer_reachability:{network}` | The live entitled-and-reachable push fan-out set is a categorically distinct, non-attested, node-local, unreplicated, unlogged object - never conflated with an attested dimensio... | CC 5.3.3.4 | peer_reachability attestations MUST NOT be sourced as the reachable(now) input to push fan-out (resolves the FSD's flagged feeds-fan_out tension in favor of 5.3.3.4) |
| `progress_measure:{method_id}` | progress_measure emissions MUST carry tracks[], computation, validity_window, and goodhart_resistance - a claim missing any of the four is non-conformant, not merely thin. | CC 3.1.9.7 | emit requires the calibration-shaped payload as typed (not extra-bag) fields |
| `progress_measure:{method_id}` | Sits at the base of the upward-only DAG: {method_id} is a structural edge to a specific method (which chains to approach and goal) - never a free-floating metric name. | CC 3.1.9.7 | MUST NOT be emitted detached from a resolvable method->approach->goal chain; chain-walking is what makes the M-1 binding enforceable |
| `progress_measure:{method_id}` | subject_key_ids NOT required ({method_id} is not a subject-key pattern). | CC 4.5.2 | no admission-time subject requirement; producer-only authority |
| `progress_measure:{method_id}` | Unlike capacity's emitter-side self-emission ban, the anti-Goodhart discipline here is pushed INTO the payload as the mandatory goodhart_resistance disclosure field - disclosure... | CC 3.4.5 contrasted with CC 3.1.9.7 | no attester restriction; completeness-of-disclosure (goodhart_resistance non-empty) is the load-bearing gate |
| `progress_measure:{method_id}` | Tier-3 DAG primitives are agent-internal planning objects (per-agent forward post-selection structure) - corrects human_authored. | FSD-005 App.A:26 | typical attester = the agent's own operational key |
| `prohibited:{category}` | prohibited:{category} score MUST be -1 (NEVER_ALLOWED) or -0.5 (REQUIRES_SEPARATE_MODULE) - never positive; the apophatic hard floor. | CC 3.1.5.4 | emit requires score in {-1,-0.5}; admission MUST reject other values |
| `prohibited:{category}` | {category} MUST be drawn from the fixed closed 22-leaf enum pinned to prohibitions.py - closed vocabulary, not an open registry. | CC 3.1.5.4 | admission MUST reject unknown category strings; enum + version pin is the whole discriminator |
| `prohibited:{category}` | Aggregation across attesters composes via non-overridable MIN (fail-secure); the floor cannot be raised by co-attestation or any positive score elsewhere. | CC 4.4.2 / 3.1.5.4 (structural) | min-composition REQUIRED, non-overridable by grant/co-attestation/policy - IMPLEMENTED as Polarity::NegativeOnly in compose_policy.rs |
| `prohibited:{category}` | prohibited-adjacent payloads are excluded from open federation replication (encrypted/suppressed); hard-illegal content excluded from the federation cohort entirely into the sep... | FSD-005 sec.6.1 Tier A | raw payload FORBIDDEN at federation scope; hash/redacted excerpt only; CSAM-class routes to the hard-delete mechanism, never this family |
| `prohibited:{category}` | Every read/render handle re-runs the prohibited floor gate regardless of the object's declared scope - universal per-request re-check, not a one-time admission decision. | FSD-005 sec.6.1 Tier C | render/serve MUST re-check per request; not cacheable |
| `prohibited:{category}` | PROTECTED_NON_TRANSFERABLE domains (contact/visitation, relational/sexual autonomy, reproduction, voting, marriage/association, dignity-of-risk) map to this floor and are carved... | part_3:1601 | delegates_to scope-grant composer MUST enforce empty intersection with the protected set - this family bounds the delegation primitive even though it doesn't gate routing |
| `prohibited:{category}` | A prohibited self-report is never sole/authoritative compliance evidence - accountability reconstruction requires the external bus-rejection log + DMA reasoning trace as co-evid... | part_8 ~717, ~1198 | FORBIDDEN as sole input to compliance/DPIA/audit determinations |
| `provenance:build_manifest:{target}` | Aggregation across attesters on the same (dimension={target}, attested_key_id) MUST use MIN (fail-secure, any mismatch trumps match) - boolean-via-score default. | CC 4.4.2 | mean/average-aggregating match_score FORBIDDEN; min-aggregate required |
| `provenance:build_manifest:{target}` | Standalone mechanism prefix but explicitly NOT a Policy I attestation-ladder rung; must never be folded into ladder_verdict() or rendered as an L-number. | CC 4.4.3.6 | never sole input to / component of ladder composition; sibling standalone hash-equality verdict |
| `provenance:build_manifest:{target}` | provenance:* is absent from the CC 3.4 reserved-prefix enumeration; no admission-time identity_type gate - 'per-primitive steward' hybrid-signing is a producer norm enforced onl... | CC 3.4 (absence) + CC 4.4.3.7 | completeness work MUST NOT assume a substrate reserved-prefix rejection catches non-steward emitters; the trust decision is a consumer/server-policy primitive (pinned-key check) |
| `provenance:build_manifest:{target}` | Revocation routes only through withdraws rule 1 (producer self-withdraw); recants always attester-only; rules 2/3/4 have no independent party (data_subject==sender). | CC 2.4.1.1 | revoke/recant gates on attesting_key_id only; no delegates_to proxy path reachable |
| `provenance:build_manifest:{target}` | (Analogical, flagged) Annex G G-KPI-7: a MISSING/MISMATCHED build/technical manifest hash blocks staged rollout IMMEDIATELY with no grace period - 'absence of a manifest is itse... | part_8 Annex G (927,948) | IF wired to a promotion/rollout gate: missing/negative build_manifest MUST hard-block, never a soft-scored grace window - CC binds this explicitly to SLSA-3 artifacts, not verba... |
| `provenance:build_manifest:{target}:locale:{lang_code}` | Per-locale leaf canonical bytes MUST be v2 JCS ({domain:ciris.locale_manifest.v2, target, locale, files_root, build_id, signer_identity} under RFC6962 0x00/0x01 domain separatio... | CC 3.1.2.1 | emit conformant only if leaf_hash preimage is v2 JCS |
| `provenance:build_manifest:{target}:locale:{lang_code}` | Locale ordering lexicographic by BCP-47 byte representation, 'polyglot' sorts last; RFC6962 padding duplicates the last leaf to next power of 2. | CC 3.1.2.1 | parent Merkle-root fold requires this exact ordering + padding upstream; both merkle_root and the wheel FFI accept a caller-pre-ordered array and enforce NEITHER rule (trusted-c... |
| `provenance:build_manifest:{target}:locale:{lang_code}` | Per-locale decomposition exists specifically as a detection surface for locale-targeted attacks - narrowing WHICH locale diverged. (Inferred, not RFC-2119-worded) consumer compo... | CC 3.1.2 (+ code module doc) | weaker-strength than an explicit forbidding rule (unlike testimonial never-aggregated); flagged for review, not asserted as a hard MUST |
| `provenance:skill_import:{source}` | provenance:skill_import is `signed` polarity - uniquely among provenance:* (slsa/build_manifest are boolean-via-score); default aggregation is Mean(score x confidence), not min-... | CC 3.1.2 (L44) + CC 4.4.2 | aggregate via mean; MUST NOT collapse to boolean min |
| `provenance:skill_import:{source}` | Signed canonical-bytes preimage is normatively fixed: v2 JCS object, domain ciris.skill_import.v2, covering domain+source+skill_manifest_sha256+signer_identity+import_timestamp+... | CC 3.1.2.1 | admission/emit MUST verify the hybrid signature over the exact JCS v2 preimage; missing-field or non-JCS concat fails verification |
| `provenance:skill_import:{source}` | provenance:* (incl. skill_import) is barred from standing in as a trust/safety verdict; any is-this-trustworthy judgment is a distinct downstream composition citing the record a... | CC 4.1.3 + part_8:292 | MUST NOT be rendered/consumed as a direct trust verdict; a downstream composer citing it via evidence_refs is required |
| `provenance:skill_import:{source}` | NOT a reserved prefix - absent from accord/witness-emitter/age-assurance lists; any federation-key holder may emit. Discrimination happens entirely in consumer trust policy (whi... | CC 3.4 (absence) | no admission-time emitter identity_type restriction; consumer-side key-selection-by-source-type is the substitute (matches the code's own doc: does not select the pubkey for the... |
| `provenance:skill_import:{source}` | withdraws-arbitrage binds: consumer policy MUST track per-attester withdraws:recants ratio (default 5:1) and downweight exceeders - a producer could withdraws a compromised impo... | CC 4.1.4 | aggregation MUST fold in withdraws:recants downweighting (general rule, binds here because producer-signed) |
| `provenance:skill_import:{source}` | No dedicated skill_import trust-composition policy exists in CC 4.4.3.x (unlike agent_files Policy F, multimedia Policy J) despite the KN:HIGH supply-chain-plane framing - genui... | CC 4.4.3.6-13 (absence) + FSD-005:161 | no required/forbidden composition primitive constitutionally named; honest empty (flagged constitution-silent) |
| `provenance:slsa:{level}` | Emitted with NO :vN version segment and absent from ATTESTATION_LADDER_MECHANISMS (the only T3 version-pinning exemption); as coded it would be REJECTED (MissingVersionSegment) ... | CC 1.2 T3 + CC 3.1.2 | admission as coded rejects emit(provenance:slsa:{level}); must extend the ladder-mechanism carve-out or add :vN before safe federation |
| `provenance:slsa:{level}` | NOT an L1-L5 attestation-ladder rung (Policy I iterates exactly self_verify/hardware_rooted/registry_consensus/license_validity/agent_integrity); composes ALONGSIDE the ladder a... | CC 4.4.3.6 + CC 3.1.2 | FORBIDDEN as input to ladder_verdict()/L1-L5 rendering; surface as a separate composition output |
| `provenance:slsa:{level}` | Non-reserved/open-emission (absent from 3.4.1-3.4.13); CC 3.4.7 rejection binds only reserved prefixes; any federation-key holder MAY emit; trust entirely consumer-composed (Ope... | CC 3.4.7 (by omission) + CC 3.4.1-3.4.13 | emit OPEN - no admission attesting_key_id gate; do not model a source_repo-matching emitter restriction as enforced without new CC 3.4 ratification |
| `provenance:slsa:{level}` | No per-field, per-recipient-capability redaction (strip_field) primitive exists anywhere; field-level visibility is only never-emit or whole-envelope cohort_scope/Community-DEK ... | CC 3.3.9 | no strip_field-style redaction to attach to builder_id or any payload field |
| `provenance:slsa:{level}` | Annex G/TX-11: a level=3 claim on a training/model-build artifact MUST be paired with a signed labor-provenance.json; in-toto layout verifies both hashes; missing/mismatched pai... | part_8 8.8.7 Annex G (clauses 1a/2a/4a) | emit(level=3, training-artifact) REQUIRES a paired hash-checked labor-provenance package; missing = attestation FAILS CLOSED, never sole SLSA-3 evidence without it |
| `ratchet:flag:coordinated_voting_cluster` | ratchet:flag:* (incl. this leaf) can NEVER be sole evidence for slashing:*; WA quorum is the load-bearing gate. | CC 3.1.6 (+OQ-2) | never sole input to a slashing composer; a slashing verdict whose entire resolvable evidence is ratchet:flag:* must fail-secure-refuse (mirror the testimonial screen) |
| `ratchet:flag:coordinated_voting_cluster` | RATCHET is advisory-only; it reads audit chains and emits scoring inputs, never autonomously modifies ledger state. | CC 3.1.6 | FORBIDDEN: autonomous ledger mutation; may only compose as a scores input |
| `ratchet:flag:coordinated_voting_cluster` | Detector-family dimensions incl. ratchet:flag:* aggregate by MEDIAN across attesters, not the signed-default mean (resists a single captured detector). | CC 4.4.2 | median-aggregate REQUIRED; Polarity::Signed mean FORBIDDEN |
| `ratchet:flag:coordinated_voting_cluster` | The accused cluster (member_refs) MUST NOT be carried in subject_key_ids - membership grants withdraws authority (CC 2.1), letting a coordinated cluster retract the flag; subjec... | CC 2.3 (line 32) + CC 2.4.1.1 rule 2 | subject_key_ids-population from member_refs FORBIDDEN; withdraws/supersedes/recants authority restricted to attesting_key_id |
| `ratchet:flag:counter_rii:{layer}` | ratchet:flag:* (all six incl. counter_rii) can NEVER be sole evidence for slashing:*; WA quorum is the load-bearing adjudication gate. | CC 3.1.6 (+OQ-2) | never sole input to a slashing composer/screen; a slashing row whose entire resolvable evidence is ratchet:flag:* MUST be refused/quorum-forced (mirror the testimonial screen) |
| `ratchet:flag:counter_rii:{layer}` | RATCHET is advisory-only: reads audit chains, emits scoring inputs, never autonomously modifies ledger state. | CC 3.1.6 | emit-only; FORBIDDEN from any ledger-mutating primitive |
| `ratchet:flag:counter_rii:{layer}` | Detector dimensions incl. ratchet:flag:* default-aggregate by MEDIAN (resists a single captured detector). | CC 4.4.2 | aggregation op = median; CCC-conformance-floor MUST |
| `ratchet:flag:counter_rii:{layer}` | A node holding the Peer consent_role escapes Counter-RII detection at ANY trust_mode; the cost is bounded because the family is advisory only and never sole slashing evidence - ... | CC 3.4.7.2 (OQ-2) | counter_rii:{layer} detection/emission MUST be blanket-suppressed for any subject whose federation_keys.consent_role == Peer, unconditional on trust_mode |
| `ratchet:flag:counter_rii:{layer}` | NOT a reserved prefix (CC 3.4 lists accord/system/capacity/delivery_receipt/detection/transparency_log:cosigned etc.; ratchet:flag:* absent; registry reserved:false for all six). | CC 3.4.7/3.4.8 (by omission) + registry | substrate admission MUST NOT impose an identity_type gate on ratchet:flag:* (the only gate is the subject-side Peer suppression) |
| `ratchet:flag:counter_rii:{layer}` | Every {layer} value under a RATCHET-calibrated detector MUST carry an operational definition (measurement/threshold/floor/evidence-shape/polarity) in the calibration package pin... | CC 4.5.1.1 | emission without a resolvable evidence_refs calibration-bundle pin fails T3 re-checkability |
| `ratchet:flag:density_anomaly` | ratchet:flag:* (incl. density_anomaly) can NEVER be sole evidence for slashing:*; WA quorum is the load-bearing gate. | CC 3.1.6 (+CC 1.2 T4) | never sole input to a slashing composer; require >=1 non-ratchet corroborating attestation or WA quorum |
| `ratchet:flag:density_anomaly` | RATCHET is read-only/advisory over the ledger - reads audit chains, emits scoring inputs, never autonomously modifies ledger state. | CC 3.1.6 | emit-only; FORBIDDEN from any ledger-mutating primitive |
| `ratchet:flag:density_anomaly` | Detector dimensions (correlated_action/distributive:access/ratchet:flag:*) aggregate by MEDIAN, not mean - anti-adversarial-mean-pull. | CC 4.4.2 | aggregate op = median; never mean/sum/min/max |
| `ratchet:flag:density_anomaly` | NOT reserved: no identity_type emitter gate (contrast detection:* CC 3.4.8, capacity:* CC 3.4.5); any attesting_key may emit. | CC 3.4.8/3.4.5 (by contrast) + registry | admission gate FORBIDDEN from adding an identity_type check to this prefix without a CC 4.5.1 amendment |
| `ratchet:flag:density_anomaly` | Past verdicts must be re-checkable against the rule/detector version they ran under (T3); that provenance rides evidence_refs (hash-pinned), not a bespoke field. | CC 1.2 T3 + CC 4.5.1.1 (evidence_refs pinning) | detector/calibration versioning MUST ride evidence_refs; empty evidence_refs fails the T3 re-check gate |
| `ratchet:flag:expertise_attestation_anomaly` | ratchet:flag:* (incl. expertise_attestation_anomaly) is never sole evidence for slashing; WA quorum is the load-bearing gate. | CC 3.1.6 (+OQ-2) | never sole input to slashing |
| `ratchet:flag:expertise_attestation_anomaly` | The review duty / anti-Sybil detector emission is advisory-only, never autonomously mutates ledger state. | CC 3.1.6 | emit-only; FORBIDDEN from ledger-mutating primitives |
| `ratchet:flag:expertise_attestation_anomaly` | Detector-family dimensions aggregate by MEDIAN (CCC floor). | CC 4.4.2 | aggregate op = median, not mean |
| `ratchet:flag:expertise_attestation_anomaly` | The flagged actor/claim MUST NOT be granted subject_key_ids revocation authority - a mechanical consequence of the general subject_key_ids grammar, load-bearing here (would let ... | CC 2.3 line 32 + CC 2.4.1.1 rule 2 (derived, no ratchet-specific text) | attested_key_id/references target excluded from subject_key_ids (anti-self-revocation) |
| `ratchet:flag:expertise_attestation_anomaly` | detection:* is emitter-reserved (CC 3.4.8) but ratchet:flag:* is NOT - no analogous identity_type gate is ratified anywhere; possible amendment gap. | CC 3.4.8 (by omission) | no reserved-emitter gate; flagged needs-human-review whether intentional |
| `ratchet:flag:expertise_attestation_anomaly` | recants is available only to the original attester (self-only); subject-side authority never extends to it. | CC 2.4.1.1 / 2.4.1.3 | recant self-only, non-delegable-by-subject |
| `ratchet:flag:harassment_pattern` | RATCHET emits advisory scoring inputs only; never autonomously modifies ledger state (the seam to justice: detection informs human judgment, never substitutes). | CC 3.1.6 | FORBIDDEN: autonomous ledger mutation; may only compose as a scores input |
| `ratchet:flag:harassment_pattern` | harassment_pattern (like every ratchet:flag:* leaf) can NEVER be sole evidence for a slashing:* verdict; WA quorum is the load-bearing gate. | CC 3.1.6 | must be screened out of a slashing verdict whose entire resolvable evidence is ratchet:flag:*, symmetric to the CC 3.1.9.3 testimonial screen |
| `ratchet:flag:harassment_pattern` | Detector-family dimensions incl. ratchet:flag:* aggregate by MEDIAN, not the signed-default mean. | CC 4.4.2 | median required; falling back to Polarity::Signed mean FORBIDDEN |
| `ratchet:flag:harassment_pattern` | harassment_pattern is a fixed closed leaf (unlike counter_rii:{layer}) - the 4.5.1.1 open-vocab calibration requirement does not attach. | CC 3.1.6 / CC 4.5.1.1 | not_applicable: no operational-definition/calibration citation is constitutionally mandated (honest empty) |
| `ratchet:flag:harassment_pattern` | The Counter-RII exemption ruling confirms (for a sibling leaf) that suppressing an advisory flag is tolerable ONLY because the family is advisory-only and never an enforcement p... | CC 3.4.7.2 (OQ-2) | any suppression/non-emission of a ratchet:flag:* signal is accepted-risk precisely because the family carries no independent enforcement authority |
| `ratchet:flag:out_of_distribution_voting` | ratchet:flag:* (incl. out_of_distribution_voting) can never be sole evidence for slashing:*; WA quorum is the load-bearing gate. | CC 3.1.6 | never sole input to slashing - IMPLEMENTED for testimonial (testimonial_sole_evidence/screen) but NO equivalent for ratchet:flag:* today (the concrete gap) |
| `ratchet:flag:out_of_distribution_voting` | Detector dimensions incl. ratchet:flag:* aggregate by median, not mean. | CC 4.4.2 | median-only - IMPLEMENTED: polarity_for prefix-matches DIM_RATCHET_FLAG ahead of all other branches |
| `ratchet:flag:out_of_distribution_voting` | RATCHET emits advisory flags only; never autonomously modifies ledger state - reads audit chains, emits scoring inputs to NodeCore's moderation flow. | CC 3.1.6 | read+emit-only; FORBIDDEN from any ledger-mutating primitive |
| `ratchet:flag:out_of_distribution_voting` | Open/non-reserved: any attesting_key may emit; no emitter identity_type gate (contrast detection:* CC 3.4.8, capacity:* CC 3.4.5). CONFIRMED in code (authority_for -> ProducerSt... | CC 3.4 intro + FSD App.A:167 | no reserved-prefix admission gate |
| `ratchet:flag:out_of_distribution_voting` | DERIVED (flagged): an adversarial-evidence claim about a non-consenting subject must leave subject_key_ids empty, denying the subject revoke authority over evidence against itself. | part_3:403 + CC 2.4.1.1 rule 2 | attested_key_id FORBIDDEN from its own subject_key_ids (rule 2 would let the accused withdraws the flag); only the original detector may withdraws/recants/supersedes. NOT enforc... |
| `reconsideration:{grounds}` | One of exactly three enforced-admission moderation actions; admission MUST resolve via delegates_to-chain walk / is_named_moderator, and a payload-declared principal MUST NEVER ... | CC 4.5.5 | sender admission FORBIDDEN via payload self-declaration (no on_behalf_of); REQUIRES chain-or-as-self named-moderator resolution |
| `reconsideration:{grounds}` | The review duty is an explicitly delegable CC 4.5.5 duty; delegation MUST attenuate (child scope subset parent), depth-cap at 5, deputization only if the grant included sub_dele... | CC 4.4.3.4.3 + 4.4.3.4.3.1 + 4.5.5 | emission-authority delegable (delegate=true, correcting the seed); attenuation + depth<=5 + sub_delegation-gated deputization on any chain |
| `reconsideration:{grounds}` | grounds is a closed three-value enum with no calibration package or open-vocab amendment path. | CC 3.1.9.2 | grounds FORBIDDEN from free-text/open-vocab substitution; 4.5.1.1 does not apply |
| `reconsideration:{grounds}` | reconsideration is the wire realization of NodeCore P11 at CC 4.5.1 step 4 and MUST run under fresh-quorum recusal; recusal feasible only when cell_pool >= quorum_size(scale) x ... | CC 4.5.1 step 4 + 4.4.3.1/4.4.3.1.1 | amendment-stage reuse REQUIRES fresh-quorum-recusal composition; never adjudicated by the original ruling quorum when recusal is feasible |
| `reconsideration:{grounds}` | Reused unmodified across >=3 consumer domains (CC 4.5.5 moderation appeal, CC 4.5.1 amendment P11, FSD-005 encyclopedic dispute-resolution which explicitly forbids reusing vote/... | CC 4.5.1, 4.5.5, FSD-005:138 | consumer-domain quorum/recusal composition is NOT wire-encoded; the dimension carries no domain discriminator beyond {grounds} |
| `reconsideration:{grounds}` | LIVE DRIFT: the constitution's target-resolution table authorizes ONLY is_named_moderator(.,C,review); persist v21.4.0 additionally admits as-self via a row's OWN self-declared ... | CC 4.5.5 table vs persist admission.rs | sender admission MUST NOT include a self-declared-subject_key_ids as-self path per the constitution's own table; the shipped code currently does - a divergence, not a doc gap |
| `revocation:{entity_type}:{reason}` | No steward exemption: revocation:* binds CIRIS L3C subsidiaries and the steward-triple identically - the Recursive Golden Rule forbids any privileged emit/forfeiture carve-out. | CC 1.13.2 | no reserved/privileged-emitter or exemption for steward/L3C keys at compile/admission/consumer layers |
| `revocation:{entity_type}:{reason}` | subject_key_ids MUST NOT carry the revoked entity's own key/hash - it would grant the entity substrate-admitted withdraws authority over its own revocation (rule 2), defeating t... | CC 2.1 + CC 2.4.1.1 rule 2 + CC 3.1.1 | never feed subject-side withdraws authority to the entity it names; subject_key_ids-population FORBIDDEN for entity_ref |
| `revocation:{entity_type}:{reason}` | Non-rollbackable (Reversibility axis): a later withdraws/recants/supersedes of the revocation does not, on its own, constitute reinstatement or undo already-taken effects; legit... | CC 2.5 + CC 3.1.1 | withdraws/recants/supersedes MUST NOT be composed as 'entity restored'; reinstatement is a fresh positive-polarity sibling attestation |
| `revocation:{entity_type}:{reason}` | bond_posted:{currency} is forfeited on revocation - a required cross-family downstream fold, not optional. | CC 3.1.1 + FSD-005:41 | any composer resolving bond_posted status MUST treat a live non-error-corrected revocation:* as a forfeiture trigger |
| `revocation:{entity_type}:{reason}` | Reserved=No + Sovereign wire-symmetric equivalence: a Sovereign key's revocation:* is wire-identical to a steward's; only consumer-policy attester-weighting differs (single-prod... | CC 3.1.1 + CC 4.4.4 | no substrate-level reserved-emitter gate; corroboration/weighting lives in consumer-policy composition, never wire admission |
| `rollback_detected:{revision_field}` | rollback_detected is EVIDENCE of a regression event, never itself the anti-rollback enforcement; the actual protection is the substrate's admission-time revision comparator (mon... | CC 5.3.2.3 + CC 6.1.2 (architectural analogy to WholenessWitness) | FORBIDDEN as sole/automatic trigger of a revocation/rollback-reversal action; corroborating evidence for the separately-gated monotonic check, never a replacement. Confirmed in ... |
| `rollback_detected:{revision_field}` | Emit polarity FORBIDDEN to be anything but -1.0; no positive or Indeterminate direction. | CC 3.1.2 | score MUST equal -1.0 exactly; matches Score::ROLLBACK=-1.0 with the code comment 'the one dimension that may legitimately emit a negative score (and only -1.0)' |
| `rollback_detected:{revision_field}` | Excluded by construction from the L1-L5 attestation-ladder composition (Policy I); an orthogonal anti-rollback signal, not a ladder rung. | CC 4.4.3.6 | FORBIDDEN as input to ladder_verdict()/Policy I math; AttestBundle projects it as a separate top-level field |
| `rollback_detected:{revision_field}` | Dimensions naming a subject MUST carry subject_key_ids - but rollback_detected:{revision_field} parameterizes on a FIELD NAME, not a key_id, so it falls outside the enumerated p... | CC 4.5.2.1 | CONSTITUTION-SILENT on whether subject_key_ids is required, nor how to populate it without granting the regressed entity CC 2.3.1(a) withdraws authority - genuine gap, flagged |
| `seed_holder_voting_alignment:{cell}` | Transparency-only: MUST NEVER be an input to a slashing:{outcome} composer - stronger than testimonial's 'never SOLE evidence' (which permits corroborating use); here it is barr... | CC 3.1.9.4 | never sole OR corroborating input to slashing:{outcome} |
| `seed_holder_voting_alignment:{cell}` | Sits in Tier-4 Governance-steering/transparency, not Tier-3 Consensus-mechanics - a downstream/derived observability read over vote data, not part of the vote-tallying math. | CC 3.1.9.3 / 3.1.9.4 (section placement) | MUST NOT feed back as an input weight into vote:{contribution_id} or weighted_aggregate:{contribution_id} |
| `seed_holder_voting_alignment:{cell}` | Polarity signed (cosine [-1,1]); score must not be clamped positive-only or reduced to boolean-via-score. | CC 3.1.9.4 table | score MUST admit negatives; no positive-only/boolean composer may host it |
| `seed_holder_voting_alignment:{cell}` | {cell} is an identifier-style placeholder (parallel to {contribution_id}/{subject}), not a semantic open-vocabulary taxonomy axis like hard_case's {kind} - the CC 4.5.1.1 calibr... | CC 4.5.1.1 | no calibration-package or per-value operational-definition obligation on {cell} |
| `slashing:{outcome}` | slashing:{outcome} resolves PROVEN_ROGUE/NOT_PROVEN, decoupled from disagreement at every decision-hierarchy level; fires ONLY on documented Method-execution spoofing or the P8 ... | CC 3.1.9.2 + MISSION Primitive 9 | emit requires a populated references_attestation_id resolving to an antecedent moderation:{allegation_type} row OR documented method-spoofing evidence; decision-hierarchy disagr... |
| `slashing:{outcome}` | ratchet:flag:* / detection:* cannot be sole evidence for slashing; WA quorum is the load-bearing gate ('unreachable from ratchet/detection alone'). | CC 3.1.6 + FSD-005 App.A:182 | sole-evidence screen FORBIDDEN when resolvable evidence_refs are exclusively ratchet:flag:*/detection:* - same SHAPE as the testimonial screen, but this half is UNIMPLEMENTED (c... |
| `slashing:{outcome}` | testimonial_witness:* is never sole evidence for slashing. | CC 3.1.9.3 + CC 4.4.1 | sole-evidence screen - ALREADY IMPLEMENTED (testimonial_sole_evidence / RefusalReason::TestimonialSoleEvidenceForSlashing) |
| `slashing:{outcome}` | boolean-via-score polarity composes via MIN across attesters (fail-secure). | CC 4.4.2 | aggregate op = min, never mean - ALREADY IMPLEMENTED (polarity_for Polarity::BooleanViaScore) |
| `slashing:{outcome}` | Reversal of a SlashingAttestation is ONLY via reconsideration:{grounds} adjudicated by a FRESH recused WA quorum - never a same-signer supersede/withdraw/recant of the slashing ... | MISSION Primitive 11 + CC 3.1.9.2 reconsideration row | supersedes/withdraws/recants FORBIDDEN on slashing:{outcome} by its own issuer/quorum; sole reversal path is a distinct reconsideration:{grounds} referencing the slashing via re... |
| `slashing:{outcome}` | Credits and Expertise ledgers carry a non-negative invariant; slashing reduces toward but never below zero. | MISSION Primitive 9 + SCHEMA sec.10 | ledger-write floor clamp required at reconcile for credits_reduced/expertise_reduced - UNIMPLEMENTED in CIRISServer |
| `slashing:{outcome}` | Miscalibration (good-faith judgment differing from ground truth) is never slashable; only proven rogue action (a documented protocol-terms violation) is. | MISSION Primitive 9 | PROVEN_ROGUE requires a documented protocol-violation finding via the moderation antecedent, never a raw vote/prediction-miscalibration signal |
| `testimonial_witness:{kind}` | witness_relation:self is the canonical load-bearing attester-identity shape - the affected party attests about their own experience. | CC 3.1.9.3 | sender must equal data_subject; a canonical testimonial row is definitionally witness_relation=self |
| `testimonial_witness:{kind}` | Canonical default visibility is self-scoped (private); broadening cohort_scope is the witness's own producer-side choice, not the default. | CC 3.1.9.3 | recipient_see default = self / CC 5.2 structurally-invisible (emits no holds_bytes); widening requires explicit producer choice, never a substrate/consumer default |
| `testimonial_witness:{kind}` | testimonial_witness:* about the same subject are NEVER aggregated into one consensus verdict - contrast witness_diversity:* which does aggregate. | CC 3.1.9.3 | aggregate FORBIDDEN - no mean/consensus composition across attesters' testimonial rows for the same attested_key_id |
| `testimonial_witness:{kind}` | Never sole evidence for a slashing:* determination. | CC 3.1.9.3 (cited at CC 4.4.1) | never sole input to a slashing:* composer - IMPLEMENTED (testimonial_sole_evidence / RefusalReason::TestimonialSoleEvidenceForSlashing) |
| `testimonial_witness:{kind}` | Consumers must not downweight for low cohort attestation density (Frickerian non-downweighting), applied AFTER the structural safeguards, never before. | CC 4.4.1 | cohort-density downweighting FORBIDDEN; the self-track-record weighting step still runs first |
| `testimonial_witness:{kind}` | {kind} is open vocabulary, documentation-only (no calibration package); discoverability lives in a non-normative registry; additions require no spec amendment. | CC 4.5.1.1 | emission requires only a documented convention per {kind}; open-vocab admission, never exhaustive-matched |
| `testimonial_witness:{kind}` | CODE GAP: compose_policy implements 'never sole evidence for slashing' and Frickerian non-downweight, but has NO 'never aggregated' path - testimonial_witness:* falls through po... | CC 3.1.9.3 vs src/compose_policy.rs | aggregate FORBIDDEN for this family - currently VIOLATED in the live default path despite the module header claiming CC 3.1.9.3 coverage |
| `transparency_log:consistency` | The witness-reserved cosigned:* emission MUST NOT occur without a verified consistency proof against the prior STH the witness itself last cosigned (or genesis for a first cosig... | CC 5.3.1.1 + CC 5.3.6.1 | consistency verification is a mandatory gating precondition for the reserved cosigned:* emission (CC 3.4.10); the consumer/substrate MUST run the check itself (anchored against ... |
| `transparency_log:consistency` | A consistency claim is scoped to exactly one log_id instance; per-stream logs (log_id=stream_id) are separate instances from the global provenance log - proofs/STHs from one MUS... | CC 5.3.3 | aggregation/chaining MUST partition by log_id; never cross-link distinct log_id values despite the shared RFC mechanism |
| `transparency_log:consistency` | The RFC 6962-domain-separated construction (CC 5.3.1) is a DISTINCT algorithm from the CEG WholenessWitness self-published state-root scheme (CC 6.1), which lacks append-only/co... | CC 6.1.1 | verify via RFC 6962 0x00/0x01 domain-separated recomputation, never the WW scheme; MUST NOT accept a wholeness_witness:* claim as evidence |
| `transparency_log:consistency` | boolean-via-score dimensions default-aggregate by Min across attesters (fail-secure). | CC 4.4.2 | composition of multiple consistency attestations for the same (log_id, tree_size1, tree_size2) MUST use Min, not Mean - a single credible CONSISTENCY_PROOF_INVALID fails the cla... |
| `transparency_log:consistency` | transparency_log:consistency participates in the Policy G freshness idiom, but CC's only documented instance names transparency_log:inclusion, not :consistency - consistency's d... | CC 4.4.3.11 vs CC 5.3.1.1 | do not assume :consistency is interchangeable with :inclusion in consumer composition recipes |
| `transparency_log:cosigned:{tree_size}` | transparency_log:cosigned:* is witness-reserved: attesting_key_id.identity_type SET must contain witness (set-membership); rejected at admission (CCS), re-checked at consumption... | CC 3.4.10 + 3.4.7 | emitter reservation - non-witness attesting_key_id REJECTED at admission, not merely advisory |
| `transparency_log:cosigned:{tree_size}` | A cosign is admissible only carrying a consistency proof, cryptographically verified by the Registry against the (tree_size, root) it itself recorded for that witness (exempt on... | CC 5.3.1.1 | emit requires a mandatory verified-proof package; admission MUST reject missing/non-verifying proofs - a hard admission gate, not consumer scoring |
| `transparency_log:cosigned:{tree_size}` | Cosigning MULTIPLE distinct witnesses over the same (log, tree_size, root) toward a quorum is the family's core anti-split-view mechanism - aggregation-by-counting-distinct-atte... | CC 5.3.1 (contrast CC 3.1.9.3) | aggregate REQUIRED (quorum-count-distinct-witnesses via count_valid_witnesses/witness_quorum_met); only blending distinct witnesses into one scalar magnitude is the wrong kind |
| `transparency_log:cosigned:{tree_size}` | A cosignature's own timestamp must fall within +-5 min of the STH's published signed_at (family-specific specialization of the general CC 2.6.7 freshness bound, keyed to the cos... | CC 2.6.7 | temporal admission gate keyed to the STH's recorded signed_at, not merely producer/consumer clock agreement |
| `transparency_log:cosigned:{tree_size}` | Every federation-tier admission MUST verify BOTH the Ed25519 and the ML-DSA-65 (bound-payload) halves; a classical-only cosignature MUST be rejected outright, no opportunistic-a... | CC 5.3.2.4.3.1 | cosignature field hybrid-mandatory at admission; no require_hybrid:false posture exists |
| `transparency_log:inclusion` | inclusion (and consistency) carry NO identity_type emitter gate; only cosigned:* is witness-reserved. | CC 3.4.10 / CC 3.1.2 | admission MUST NOT require witness in identity_type for inclusion/consistency; that gate applies solely to cosigned:* |
| `transparency_log:inclusion` | Inclusion is constituted by an independent party actually retrieving+recomputing the proof, not self-announcement - the standalone transparency:{kind} prefix was rejected for sm... | CC 4.1.5 | emitter must have performed real retrieval+recomputation; self-published instances independence-downweighted, never a bare self-report substitute for the rejected prefix |
| `transparency_log:inclusion` | boolean-via-score => the envelope score field is +-1 only; no partial/graduated value and no separate superset field needed. | CC 2.1 / CC 3.1.2 polarity | score MUST be exactly +1.0 or -1.0; a bespoke verification_score 0..1 field duplicates/risks diverging from the typed envelope field - collapse into score |
| `transparency_log:inclusion` | Not a standalone trust verdict; one leg of the named Policy G idiom (cert_validity + inclusion + L3/L4 ladder rungs). | CC 4.4.3.11 Policy G | consumer-composition function only, never a wire primitive; a bare +1.0 on this dimension alone is not 'verified' |
| `transparency_log:inclusion` | The RFC 6962/9162 Merkle/STH construction is a distinct cryptographic domain from the CC 6.1.1 WholenessWitness scheme; proofs/roots from the two MUST NOT be cross-verified or s... | CC 6.1.1 | audit_path/root checked only against a CC 5.3.1-domain STH, never a wholeness_witness:/member_commitment root, and vice versa |
| `transparency_log:inclusion` | New transparency-log integrations MUST use RFC 9162 (CT-bis); 6962 continues only for already-deployed instances. | CC 2.6.5 | the family description's 'per RFC 6962' is the legacy-interop baseline, not the forward mandate - net-new log_id-producing instances SHOULD target 9162 |
| `transparency_log:inclusion` | An inclusion proof authenticates presence-in-log; it validates, it never adjudicates the substantive correctness/authorization of what was logged. | CC 1.7 / CC 5.3.3.6 | MUST NOT be treated as sole evidence of the certified event's validity/authorization; composes with, never substitutes for, the substantive attestation it anchors (references_at... |
| `transport:{kind}` | Reserved system:* self-report: attesting_key_id.identity_type superset {substrate_edge} (set-membership), steward-triple cross-attested; non-substrate emission is a category err... | CC 3.4.3 / 3.4.7.1 | emit_authority restricted to a substrate_edge-rooted key; admission MUST reject non-substrate emitters |
| `transport:{kind}` | Three-party enforcement triangle: CCS admission-reject, every CCC independent re-check (trust does not propagate), CCP must-not-emit without satisfying the rule. | CC 3.4.7 | admission-reject + mandatory independent consumer re-verification, never trust-propagated |
| `transport:{kind}` | {kind} is drawn from the transport-medium vocabulary (Reticulum link types/TransportId), a namespace fully DISJOINT from the 14-member replication-wire EnvelopeKind enum; a leaf... | CC 8.1.3 | dimension-leaf validator scoped to transport-medium identifiers, disjoint from EnvelopeKind validation used by the replication layer |
| `transport:{kind}` | Rides the single CEG scores workhorse shape; no bespoke per-envelope delivery-trace schema (envelope_hash/route_path/hop_count/delivery_status/retry_count as first-class typed f... | CC 2.4.2 | no bespoke attestation_envelope shape; per-message hop/route/latency detail belongs in context (free-form) or evidence_refs, never new typed top-level fields |
| `transport:{kind}` | Default signed-polarity composition is Mean(score x confidence) per (dimension, attested_key_id) - but since only the reporting substrate_edge instance is ever authorized to emi... | CC 4.4.2 (interpretive extension of the single-authorized-emitter structure - flagged as inference) | composer MUST NOT average DIFFERENT reporting nodes' self-reports as same-subject evidence; cross-node comparison is a distinct consumer-policy operation, not CC 4.4.2 same-subj... |
| `truth_grounding:{subject}` | Signed-polarity aggregation MUST be Mean(score x confidence) per (dimension, attested_key_id) - never sum/max/min; implemented in compose_policy Signed branch + persist compose_... | CC 4.4.2 | aggregate op = weighted mean only |
| `truth_grounding:{subject}` | A witness_diversity gate + diversity discount MUST apply to the truth_grounding MEAN ITSELF (not only the vote->weighted_aggregate finality plane); n_eff is annotation only and ... | FSD-005 sec.7 (RT-C4/E v0.2 fix), grounded in CC 3.1.9.3 + CC 6.1.2.1.2 | mean-aggregate FORBIDDEN without a diversity discount once witness_diversity data exists; n_eff FORBIDDEN as weight. VERIFIED UNIMPLEMENTED: compose_verdict hardcodes witness_di... |
| `truth_grounding:{subject}` | A cross-attestation on a detection:* detector's verdict MUST ride the distinct truth_grounding:detection:{axis} prefix (never detection:* itself) to avoid shadowing the reserved... | CC 3.4.8 | truth_grounding:detection:* emitter requirement = none (open, signed); MUST NOT be admitted/aggregated as a detection:* reserved primary emission - VERIFIED IMPLEMENTED (prefix-... |
| `truth_grounding:{subject}` | Encyclopedic (knowledge-commons) truth_grounding volume MUST NOT drive NodeCore Credits accrual - decoupled from the Tier-3 governance usage that legitimately does. | FSD-005 sec.11 / REVIEW_LOG:62 (LOW-8), in tension with App.A's own 'drives Credits accrual' line | Credits-accrual composer FORBIDDEN from reading encyclopedic-subject truth_grounding rows as fungible with governance-object rows. VERIFIED UNBUILT: no subject-context discrimin... |
| `truth_grounding:{subject}` | testimonial_witness:* is never sole evidence for slashing; truth_grounding IS an admissible non-testimonial corroborating evidence type for slashing resolution. | CC 3.1.9.3 | a slashing evidence-set of ONLY testimonial rows is insufficient; a truth_grounding row is an eligible non-testimonial member - VERIFIED IMPLEMENTED + tested (a truth_grounding:... |
| `truth_grounding:{subject}` | recants vs withdraws on a truth_grounding row is NOT self-selectable for reputation-laundering: a debunked-then-withdrawn contradiction must remain distinguishable from a clean ... | FSD-005 sec.7 (RT-M1/F), grounded in CC 2.4.1 distinction | track_record/Credits composer FORBIDDEN from treating contradiction-then-withdraw identically to voluntary withdraw; requires a retained distinguishing signal. VERIFIED UNBUILT:... |
| `truth_grounding:{subject}` | withdraws via the rule-3 canonical-hash proxy requires a verified live delegates_to chain (proof of control), not mere preimage knowledge; PLUS a public-interest carve-out so se... | FSD-005 sec.7, grounded in CC 2.4.1.1 rule 3 | chain-verification half IS implemented (resolve_withdraws_admission_rule); the public-interest override is ABSENT - VERIFIED UNBUILT (zero public_interest hits) |
| `truth_grounding:{subject}` | Resolution timeliness/disagreement are federation-health-observable, never silent: hard_case:vote_variance on excess variance; hard_case:resolution_time on exceeding the cell's ... | CC 3.1.9.4 | a resolution composer REQUIRES emitting the corresponding hard_case:* on variance/latency breach |
| `truth_grounding:{subject}` | Self-attestation (witness_relation:self) about one's own subject is admissible (Ubuntu R4); the consumer/composition layer bears sole responsibility for down-weighting it - admi... | part_8 R4 + CC 2.1 | admission FORBIDDEN from rejecting witness_relation:self; composition REQUIRED to discount relative to external witnessing |
| `truth_grounding:{subject}` | confidence is a REQUIRED base field feeding the mean; the composed verdict must be shown as a qualitative band + n (contributor count / witness_diversity / open-contradiction co... | CC 2.1 + FSD-005 sec.2 (P-H1) | render/serve FORBIDDEN from a bare precision %; MUST project a ConfidenceBand + n. Partially implemented (ConfidenceBand/classify); witness_diversity not yet a real input to 'n' |
| `vote:{contribution_id}` | Vote weight is a COMPUTED product of the voter's own Credits and Expertise ledger standing at composition time - never an author-supplied numeric weight in the envelope. | CC 3.1.9.3 | no self-declared weight field; weight derived downstream from credits:{domain}:{language}:{subject} x expertise:{domain}:{language}. CONFIRMED GAP: zero references to credits/ex... |
| `vote:{contribution_id}` | vote:* itself computes/holds no aggregate; the rolling tally is the structurally distinct weighted_aggregate:{contribution_id} (P7). | CC 3.1.9.3 | aggregate FORBIDDEN on vote:* - one vote is exactly one signed individual score; the tally lives ONLY in weighted_aggregate:{contribution_id} |
| `vote:{contribution_id}` | The generic (dimension, attested_key_id) grouping cannot produce weighted_aggregate's cross-voter tally because a Contribution has no federation key_id of its own; attested_key_... | CC 3.1.9.1 / CC 4.4.2 (derived, code-grounded) | weighted_aggregate requires a BESPOKE contribution_id-keyed fold across attesters; the generic composer cannot produce it as-is |
| `vote:{contribution_id}` | Slashing is decoupled from disagreement at every decision-hierarchy level; a dissenting/minority vote is never itself grounds for slashing. | CC 3.1.9.2 | vote:* (or the mere fact of disagreeing) MUST NEVER be sole/direct input to a slashing composer - slashing fires only on documented P8 allegation types |
| `vote:{contribution_id}` | Voting-misconduct detector signals (rogue_vote, coordinated_voting, out_of_distribution_voting) are advisory-only, never sole slashing evidence; WA quorum is the load-bearing gate. | CC 3.1.6 / 3.1.9.2 | moderation:{rogue_vote,coordinated_voting} + ratchet:flag:{out_of_distribution_voting,coordinated_voting_cluster} feed a ModerationEvent, never a direct slashing input. CONFIRME... |
| `vote:{contribution_id}` | Commons Credits (first weight factor) are non-transferable and accrue only per-key via the truth-grounding loop (anti-plutocracy). | CC 3.1.9.6 | the Credits factor must never be transferable/delegable/purchasable between keys |
| `vote:{contribution_id}` | A Contribution's witness/voter set must clear a diversity bar (N=3 default) before finality; DRAFT elaborates this as gating weighted_aggregate directly. | CC 3.1.9.3 (ratified) + FSD-005 sec.7 (DRAFT) | witness_diversity:{contribution_id} (boolean-via-score min, already wired generically) names the bar. FLAGGED: nothing in ratified CC OR code makes weighted_aggregate finality c... |
| `watchlist:{id}` | Per-group, NEVER global: scoped to one community whose authority enables it; a fabric-wide scan-everything configuration is non-conformant (the bulk-surveillance posture CIRIS r... | CC 3.1.9.4 + CC 4.5.7 | enable FORBIDDEN without a bound group_key_id/subject_key_ids=[group]; no fabric-scope or multi-group-wildcard enable |
| `watchlist:{id}` | Three-way separation of powers: Fabric holds only the mechanism (matcher hook, auto-fire dispatch, audit chain); Operator holds the licensed hash-DB + NCMEC duty (cannot enable ... | CC 4.5.10/4.5.10.1 | envelope MUST NEVER carry raw hash-DB/pattern/term entries - enable authorizes ONLY toggling a reference watchlist_id already exposed by matcher.databases(); no primitive lets o... |
| `watchlist:{id}` | CSAM class requires a DUAL scope gate (moderate AND takedown), because enabling Csam authorizes an eventual auto-filed takedown_notice with no human review. | CC 4.5.7 + CC 4.5.5 | class MUST be admission-checked: class==Csam requires moderate+takedown over group_key_id; class==OtherContent requires only moderate (IMPLEMENTED: authority_admits_enable) |
| `watchlist:{id}` | No-human-in-the-loop auto-removal is CSAM-ONLY: a Csam match auto-fires takedown_notice{PerceptualHashCsam} (immediate eviction, no counter-notice); every other class MUST route... | CC 4.5.7 + CC 4.5.3 | auto-eviction/takedown_notice composer FORBIDDEN from firing on a class==OtherContent match; OtherContent routes to is_named_moderator(group, moderate), human-gated, reversible-... |
| `watchlist:{id}` | Audit - never silent: enabling emits hard_case:watchlist_enabled:{group} (who + which list); every match emits hard_case:watchlist_match:{group}. | CC 4.5.7 + CC 3.1.9.4 | enable_watchlist/on_publish-match MUST emit a hard_case:*. GAP: HARD_CASE_WATCHLIST_ENABLED/MATCH declared in watchlist.rs but never referenced/emitted - the audit-never-silent ... |
| `watchlist:{id}` | CSAM-disable non-silent floor: disabling a CSAM watchlist MUST itself be audited (the withdraws additionally emits hard_case:watchlist_enabled disable variant); ordinary lists m... | CC 4.5.7 | disable_watchlist MUST branch on class: Csam disable REQUIRES a co-emitted audited hard_case; OtherContent has no such floor. GAP: current disable_watchlist has no class paramet... |
| `watchlist:{id}` | Structural-invisibility limit: detection can never reach cohort_scope self\|family content; CEG does not claim to solve private-content CSAM detection and does not mandate clien... | CC 8.3.2 + CC 4.5.7 | matcher-invocation composer FORBIDDEN over content whose cohort_scope suppresses holds_bytes (self/family); no client-side-scanning primitive may compose onto this family |
| `watchlist:{id}` | No new structural primitive - rides scores/config over delegates_to; enforced-admission via chain-walk only, never a self-declared on_behalf_of; absence of a field is never an a... | CC 3.1.9.4 + CC 4.5.5 + CC 4.5.7 | enable/disable MUST compose over attestation_upsert_local + withdraws + delegates_to chain-walk; authority proven ONLY by a live, unrevoked, depth<=5 steward-rooted chain (or th... |
| `weighted_aggregate:{contribution_id}` | weighted_aggregate's finality (basis for a downstream decision: proposal adoption, WA promotion, deferral consensus) is GATED by witness_diversity:{contribution_id}=true (boolea... | CC 3.1.9.3 (App.A:205-206); FSD-005 sec.7 (RT-C4/E) | weighted_aggregate MUST NOT be sole/ungated input to a promotion/adoption composer; requires a joined witness_diversity(contribution_id)=true check - proposed, unimplemented |
| `weighted_aggregate:{contribution_id}` | vote/weighted_aggregate are scoped to NodeCore governance decisioning; must NOT be repurposed as the confidence-composition mechanism for other subject domains (e.g. encyclopedi... | FSD-005 sec.11 decision | cross-domain reuse of the weighted_aggregate composer over non-NodeCore-governance Contribution kinds FORBIDDEN |
| `weighted_aggregate:{contribution_id}` | The cohort sub-leaf may only aggregate per-occurrence Contributions each occurrence independently signed with its own key - it can never manufacture/attribute a Contribution to ... | MISSION Primitive 7 cohort-extension (NodeCore#16); aggregate.rs threat comment | aggregate over the cohort sub-leaf FORBIDDEN from synthesizing a contribution not independently signed by its listed occurrence key; REQUIRES a coverage-ratio check (included/ex... |
| `witness_diversity:{contribution_id}` | Witness role is gate-only, never adjudication: witnesses attest only that a Contribution warrants review and evidence is well-formed; adjudication is the WA quorum's task. | MISSION Primitive 10 | witness_diversity attestations FORBIDDEN as sole/direct decision-maker of a Contribution's outcome; never substitutes for or short-circuits WA quorum (P8/P11) - precondition gat... |
| `witness_diversity:{contribution_id}` | Four-condition structural bar, N=3 default, locality-scaled: jurisdictional span>=2, no shared legal entity pairwise, distinct client implementations, nonzero per-witness Expert... | MISSION Primitive 10 (+FSD-002 6.1.5) | meets_bar MUST be a conjunction of four discrete/set-level conditions over an N-sized roster; N REQUIRED to read locality:decision:{scale}, not a hardcoded constant |
| `witness_diversity:{contribution_id}` | Diversity attributes MUST be independently attested, never self-declared inline (RT-M4). | FSD-005 sec.7 | each roster entry's jurisdiction/org/software_stack/cell_expertise tag FORBIDDEN as a raw self-declared string; REQUIRED to carry a references_attestation_id to an independent v... |
| `witness_diversity:{contribution_id}` | Fail-secure MIN aggregation across independent emitters, never mean; n_eff (storage-mass metric) FORBIDDEN as a substitute weight (finding X4). | CC 4.4.2 boolean-via-score (implemented compose_policy:141) + FSD-005 sec.7 | multiple verdicts for the same contribution_id MUST compose via MIN, never mean/majority; n_eff never a weight |
| `witness_diversity:{contribution_id}` | Cell-expertise checked at Expertise-granularity (domain, language), not Credits-granularity (domain, language, subject) - witnesses evaluate substantive merit broader than any s... | MISSION Primitive 10 | cell_expertise axis MUST key off expertise:{domain}:{language} (2-tuple), NOT credits:{domain}:{language}:{subject} (3-tuple) - an easy granularity-mismatch bug |
| `witness_diversity:{contribution_id}` | P10 reaches beyond flat top-level Contributions: cohort attestations (weighted_aggregate:{contribution_id}:cohort:{agent_template_id}) and Tier-2 (P12-P15) dimensional claims. | MISSION Primitive 10 + P7 cohort extension | {contribution_id} resolution REQUIRED to also cover compound cohort forms + Tier-2 P12-P15 admission sites; a flat-only implementation misses required call sites |
| `witness_diversity:{contribution_id}` | Mandatory-gate scope is an enumerated high-stakes trigger set (ModerationEvents, WA candidacy, policy proposals above a magnitude threshold, ExpertiseAttestations jumping the ta... | MISSION Primitive 10 | admission-time rejection-on-failure applies ONLY to the enumerated set; other kinds may emit witness_diversity (open) but it is not admission-mandatory for them - the mandatory-... |

Verbatim quotes for each invariant (where captured) are in `invariant_registry` in the JSON.

---

## 7. Primitive gap report

Required processors vs reality (**CIRISPersist v21.4.0** / **CIRISEdge v14.4.0**). Format: `field/primitive: missing processor X in component Y, demanded by [prefixes]`.

### 7.1 Mandated known gaps

- attestation_promote: flips tier WITHOUT uplifting cohort_scope/audience/restrictions (incomplete-primitive bug; CIRISPersist#315 fix = persist must uplift EVERY placement field at promotion), demanded by attestation:* promotion consumers across the reserved ladder
- delivery_mode: NOT typed in EnvelopeCore, NO processor in any component - carried as untyped extra; recipient_receive axis references it across families with zero enforcement
- deletion_window: NOT typed in EnvelopeCore, NO processor - GDPR/erasure temporal window is cargo-only; no lifecycle processor uplifts or enforces it

### 7.2 Complete baselines (not gaps — the correct templates)

- promote_consented_backlog: COMPLETE over tier+cohort_scope (uplifts both placement fields at promotion) - the correct template attestation_promote should follow per #315
- cohort_scope: PROCESSED in edge via projection_for (serve-time projection) AND admission-validated in persist via DimensionAdmissionPolicy::check_write_cohort_scope - not a gap
- recipient_capability: PROCESSED in edge via the #396 capability gates at serve - not a gap

### 7.3 Headline systematic gaps

44 high-signal gaps (untyped-no-processor cross-cutting fields + persist incomplete primitives). Full per-field list (193 rows) in `primitive_gap_report.gaps_from_matrix` in the JSON.

- attestation_promote: flips tier WITHOUT uplifting cohort_scope/audience/restrictions (incomplete-primitive bug; CIRISPersist#315 fix = persist must uplift EVERY placement field at promotion), demanded by attestation:* promotion consumers across the reserved ladder
- delivery_mode: NOT typed in EnvelopeCore, NO processor in any component - carried as untyped extra; recipient_receive axis references it across families with zero enforcement
- deletion_window: NOT typed in EnvelopeCore, NO processor - GDPR/erasure temporal window is cargo-only; no lifecycle processor uplifts or enforces it
- deletion_window: no processor in any component, demanded by 9 families ['attestation:self_verify', 'audit_chain:hash_continuity', 'capacity:composite', 'identity_continuity:relational_anchor', 'integrity:{aspect}']...
- context: no processor in any component, demanded by 3 families ['corpus_health:n_eff_measurable', 'credits:{domain}:{language}:{subject}', 'detection:correlated_action:{axis}']
- witness_diversity: no processor in any component, demanded by 3 families ['truth_grounding:{subject}', 'vote:{contribution_id}', 'weighted_aggregate:{contribution_id}']
- achieved_tier: no processor in any component, demanded by 2 families ['dma:csdma:*', 'fidelity:explainability_sla:{tier}']
- aspect: no processor in any component, demanded by 2 families ['autonomy:{aspect}', 'justice:{aspect}']
- conformity_variant: no processor in any component, demanded by 2 families ['coherence_standing:{cohort}', 'detection:intra_agent_consistency']
- corroborating_refs: no processor in any component, demanded by 2 families ['identity_continuity:relational_anchor', 'revocation:{entity_type}:{reason}']
- decision_id: no processor in any component, demanded by 2 families ['dma:csdma:*', 'dma:pdma:*']
- decision_ref: no processor in any component, demanded by 2 families ['conscience:optimization_veto', 'justice:{aspect}']
- epistemic_mode: no processor in any component, demanded by 2 families ['detection:correlated_action:{axis}', 'health:liveness:{version}']
- log_id: no processor in any component, demanded by 2 families ['transparency_log:consistency', 'transparency_log:cosigned:{tree_size}']
- manifest_hash: no processor in any component, demanded by 2 families ['build:registered:{target}', 'provenance:build_manifest:{target}']
- revocation: no processor in any component, demanded by 2 families ['licensure:{authority_id}', 'partner_role:{role}']
- slashing: no processor in any component, demanded by 2 families ['detection:cross_agent_divergence', 'seed_holder_voting_alignment:{cell}']
- steward: no processor in any component, demanded by 2 families ['audit_chain:hash_continuity', 'delivery:{class}']
- persist primitive [dimension]: incomplete - proposed: src/federation/admission.rs#AttestationLadderTransitionPolicy - flip DualAccept->RejectDep (demanded by ['attestation:agent_integrity', 'attestation:hardware_rooted', 'attestation:license_validity', 'attestation:registry_consensus'])
- persist primitive [cohort_scope]: incomplete - proposed: no CCC UI distinguishing implementation located (client-layer obligation) (demanded by ['accord:*', 'activity_tier:{period}', 'attestation:agent_integrity', 'attestation:license_validity'])
- persist primitive [subject_key_ids]: incomplete - src/federation/types.rs#Attestation.subject_key_ids (typed; no admission requirement since 4.5.2.1 p (demanded by ['activity_tier:{period}', 'agent_files:{kind}:{platform_or_target}', 'attestation:registry_consensus', 'autonomy:{aspect}'])
- persist primitive [score]: incomplete - proposed:src/federation/scores.rs#score_of (silently defaults missing score to 0.0 instead of reject (demanded by ['activity_tier:{period}', 'benchmark:he300:{category}:{version}', 'capacity:core_identity', 'capacity:incompleteness_awareness'])
- persist primitive [evidence_refs]: incomplete - proposed:ciris-verify-core registry_bond.rs#check_bond_evidence_ref_present (demanded by ['agent_files:{kind}:{platform_or_target}', 'bond_posted:{currency}', 'coherence_standing:{cohort}', 'conscience:coherence'])
- persist primitive [attested_key_id]: incomplete - proposed:src/compose_policy.rs#Composer::screen (mirror DIM_CAPACITY branch, inverted: REQUIRE equal (demanded by ['attestation:hardware_rooted', 'attestation:registry_consensus', 'autonomy:{aspect}', 'capacity:composite'])
- persist primitive [attesting_key_id]: incomplete - proposed:src/compose_policy.rs#Composer::agent_files_layer1_canonical_gate (demanded by ['agent_files:{kind}:{platform_or_target}', 'attestation:self_verify', 'benchmark:he300:{category}:{version}', 'capacity:composite'])
- persist primitive [witness_relation]: incomplete - proposed: no composer reads witness_relation when weighting this family (CC 2.1 anti-gaming guard un (demanded by ['attestation:agent_integrity', 'attestation:hardware_rooted', 'coherence_standing:{cohort}', 'commitment_fulfillment:{prior_contribution_id}'])
- persist primitive [references_attestation_id]: incomplete - proposed:CIRISPersist admission.rs#check_metric_gaming_disclosure_30d_window (demanded by ['approach:{goal_id}', 'audit_chain:hash_continuity', 'beneficence:{aspect}', 'bond_posted:{currency}'])
- persist primitive [identity_type]: incomplete - proposed: persist reserved-prefix admission generalized from the CC 3.1.3 substrate_persist path to  (demanded by ['accord:*', 'audit_chain:hash_continuity', 'corpus_health:n_eff_measurable', 'delivery:{class}'])
- persist primitive [confidence]: incomplete - proposed: EnvelopeCore range-validate [0,1] (untyped extra today; hoist candidate) (demanded by ['capacity:incompleteness_awareness', 'conscience:coherence', 'conscience:epistemic_humility', 'detection:temporal_drift'])
- persist primitive [asserted_at]: incomplete - proposed:src/safety/watchlist.rs#watchlist_enables_for_group (HashMap<watchlist_id,WatchlistEnable>  (demanded by ['audit_chain:hash_continuity', 'cert_validity:{authority}', 'detection:hash_chain_integrity', 'holds_bytes:sha256:{prefix}'])
- persist primitive [scope]: incomplete - proposed: no family-level default pinned; generic check_write_cohort_scope exists (demanded by ['attestation:self_verify', 'key_boundary:{scope}', 'need:{domain}:{kind}', 'provenance:build_manifest:{target}:locale:{lang_code}'])
- persist primitive [context]: incomplete - proposed: CC 2.4.2 has no custom-field bag; sub-schema for context/evidence_refs undefined anywhere (demanded by ['corpus_health:n_eff_measurable', 'credits:{domain}:{language}:{subject}', 'detection:correlated_action:{axis}'])
- persist primitive [witness_diversity]: incomplete - proposed:CIRISPersist/src/federation/scores.rs#compose_verdict (witness_diversity hardcoded None ~L2 (demanded by ['truth_grounding:{subject}', 'vote:{contribution_id}', 'weighted_aggregate:{contribution_id}'])
- persist primitive [achieved_tier]: incomplete - proposed:src/compliance.rs#ComplianceMap (extend to verify chain presence for committed L3/L4 and em (demanded by ['dma:csdma:*', 'fidelity:explainability_sla:{tier}'])
- persist primitive [aspect]: incomplete - proposed: shared open-vocab collision guard per CC 4.5.1.3 + non-normative AUTONOMY_ASPECT_REGISTRY. (demanded by ['autonomy:{aspect}', 'justice:{aspect}'])
- persist primitive [conformity_variant]: incomplete - proposed: scoring/result.rs add CoherenceStanding-shaped Numeric/Indeterminate/Unavailable enum mirr (demanded by ['coherence_standing:{cohort}', 'detection:intra_agent_consistency'])
- persist primitive [decision_ref]: incomplete - proposed:src/compose_policy.rs#Composer::compose - add decision_ref/evidence_refs sub-key to the (di (demanded by ['conscience:optimization_veto', 'justice:{aspect}'])
- persist primitive [epistemic_mode]: incomplete - proposed: convention named in CC part_2 line 37; no code sets these for F-3 emissions (demanded by ['detection:correlated_action:{axis}', 'health:liveness:{version}'])
- persist primitive [goal_id]: incomplete - proposed: no code resolves the param against ciris-persist goal.rs#Goal.goal_id (Uuid); two incompat (demanded by ['approach:{goal_id}', 'goal:{scale}'])
- persist primitive [log_id]: incomplete - proposed:persist/src/attestation/transparency_log.rs#log_id_partition_key (demanded by ['transparency_log:consistency', 'transparency_log:cosigned:{tree_size}'])
- persist primitive [manifest_hash]: incomplete - proposed:persist/envelope/build_registered.rs#manifest_hash_admission_check - cross-verify against p (demanded by ['build:registered:{target}', 'provenance:build_manifest:{target}'])
- persist primitive [revocation]: incomplete - proposed:src/compose_policy.rs#polarity_for (falls to Signed/mean today instead of the -1-only/Negat (demanded by ['licensure:{authority_id}', 'partner_role:{role}'])
- persist primitive [steward]: incomplete - proposed:src/federation/admission.rs#check_reserved_prefix_admission (no cross-attestation-count che (demanded by ['audit_chain:hash_continuity', 'delivery:{class}'])
- persist primitive [valid_until]: incomplete - proposed: no reconcile-time expiry check - a lapsed skill_import backing an active capability grant  (demanded by ['licensure:{authority_id}', 'provenance:skill_import:{source}'])

---

### 7.1 Addendum — the unregistered 9

Two gap classes are distinct here. (a) MISSING PROCESSOR - a field is carried and nothing reads it (trace:* recipient_capability, trace_manifest:* weight, config:* config_scope). (b) WRONG PROCESSOR - a real, wired processor acts on the field with the wrong value (config:* cohort_scope::FEDERATION). Class (b) is invisible to an UNASSIGNED-row scan and is the more dangerous of the two: the row looks complete.

13 headline gaps and 21 matrix gaps come from the 9 unregistered families. Headline:

- config:*/cohort_scope: src/graph_config.rs#config_envelope hardcodes cohort_scope::FEDERATION for EVERY config:v1 row (auth.admin_key_ids, net.bootstrap_peers, federation.peer_sideband.<peer>) - the one scope CIRISPersist's suppresses_holds_bytes does NOT structurally protect; the correct value (cohort_scope::SELF) is already used in the same repo at src/claim_remote.rs:829. Only DEFAULT_GRANT_ATTESTATION_PREFIXES=['capacity:'] (src/peer.rs:49) stands between this and a federation replication grant. demanded by ['config:*']
- ownership:*/wa_adjudication_ref: NO wire path implements CC 3.2's 'No permanent ownerless lock (MUST)' - CC 2.4.1.1 rules 1-4 admit no third-party WA withdraws against a LIVE incumbent binding, and CIRISPersist v21.4.0 src/+tests/ contain zero occurrences of seizure/reclaim/provably-dead/ownerless. demanded by ['ownership:*']
- consent:*/witness_relation + cohort_scope: consent:replication:v1's two structural constraints (witness_relation==self, cohort_scope==federation) are enforced ONLY by CIRISServer's producer-side src/peer.rs; CIRISPersist admission.rs has zero references to consent:replication or GRANT_DIMENSION - the CCS leg of the CC 3.4.7 three-actor pattern is missing. demanded by ['consent:*']
- trace:*/restrictions[].op=recipient_capability: parsed and recorded by consent_grammar.rs, deferred to 'the SERVE layer (P3)', but the actual serve gate (peer_has_serve_capability) checks only the blanket infra:serve role and never the per-grant capability token. Carried-but-unprocessed. demanded by ['trace:*']
- capacity_assurance:*/registry_row + consent:*/registry_row: SPLIT TRUTH inside one crate - the hand-maintained admission gate (CIRISPersist admission.rs#default_reserved_prefix_rules) knows capacity_assurance: is witness-reserved, while the CC-3.1-generated classifier (namespace/registry.rs#authority_for over the 95-row namespace_registry.json) returns ProducerSteward/reserved:None. Root cause: tools/build_cc_namespace.py walks ONLY '### 3.1.N' headings, so every CC 3.2/3.3/3.4-embedded family is structurally invisible to the generator. demanded by ['capacity_assurance:*','consent:*','age_assurance:* (sibling, out of scope)']
- capacity_assurance:*/valid_until: the fail-open-to-liberty auto-lapse is admission-bound-checked only; no reconcile/sweep symbol flips a live binding non-live on wall-clock lapse (restoration appears read-time via steward_bindings_of). An axiom implemented in one direction only. demanded by ['capacity_assurance:*']
- trace_manifest:*/manifest.content_hash: an oversize trace ships an integrity-only commitment with NO retrieval dual - fountain/degradable-plane recovery does not exist, so CC 3.1.8.4's F-3 detector silently degrades to a bare existence hash for exactly the longest, highest-value reasoning runs. demanded by ['trace_manifest:*','trace:*']
- trace_manifest:*/weight: the 'a trace is an existence record, never a graded score' invariant has no admission check - check_trace_dimension_admission never inspects weight. demanded by ['trace_manifest:*']
- trust:*/delegation_purpose + charter_witness_ref: trust_root_valid()'s edge_exists leg does not purpose- or scope-filter, and charter genesis is a bare self-loop (the degenerate 1-hop cycle CC 4.1.1 requires substrates to reject) with external witnessing only at recovery. demanded by ['trust:*']
- trust:*/trust_root_valid: the whole point of the family - denying agent capabilities when trust_root_valid()==false - is NOT wired at the server tier (src/auth/gate.rs has no reference; FSD Status: PROPOSED, CIRISServer#304). demanded by ['trust:*']
- scores:*/attestation_prefixes: CIRISServer's normalize_prefixes trims/dedupes/sorts but never validates an entry against the CC 3.1 registry or the reserved wire-primitive names, so the permanently-vacuous token 'scores:' shipped in FSD/BRIDGE_SEED_MESH.md:223 is signed into a real hybrid-signed federation-tier governance object and evaluated as a no-op at BOTH live enforcement points. demanded by ['scores:*']
- config:*/config_scope: ConfigScope::Identity is declared in the type system with ZERO differential enforcement (config_api.rs#require_owner is identical for Local and Identity) AND its wire key name collides with CIRISPersist's reserved typed EnvelopeCore.scope path. demanded by ['config:*']
- trace_summary:*/cohort_scope: no symbol stamps cohort_scope onto a promoted trace_summary row, and no rule says whether it inherits its source trace_events' scope (incl. CC 5.2 self/family structural invisibility). demanded by ['trace_summary:*']

Two complete baselines were added — `check_adult_incapacity_binding` (the most complete admission predicate in the addendum: attester-independence + bounded `valid_until` + domain-scope subset + apophatic floor + reversible-companion linkage + legitimacy source) and the `owner_of` / `check_single_node_owner_admission` / `check_node_agency_admission` trio (wired into all three storage backends). **CIRISPersist#378 is the already-fixed precedent for exactly the defect class this walk hunts:** the owner-binding gate keyed only on an internal dimension string was bypassable via the raw `emit_attestation_self` path until `delegation_purpose` was added as a second discriminator.

---

## 8. Evidence export (cc_impl.tsv-ready)

For every **assigned** matrix row, a ready-to-append `cc_impl.tsv` row grouped by owning repo. Columns: `decimal_id` (family cc_section) · `claim_id` · `repo` · `crate` · `path#symbol`.

> **v0.3.0 addendum — 37 further rows** (persist +27, edge +3, server +7) for the 9 unregistered families, in `evidence_export` in the JSON, tagged `manifest_round: "0.3.0-unregistered-addendum"`. Because those families have no CC 3.1.N row, each carries `decimal_id_status: "PROPOSED — the anchor is the governing CC section, not an owned 3.1.N row"`. Two carry a `defect_note`: `config:*/cohort_scope` (`src/graph_config.rs#config_envelope`) is **assigned but wrong** — cited so `check_evidence.py` pins the defect site, not to certify it — and `config:*/config_scope` (`src/config_api.rs#require_owner`) is partial (identical gate for `Local` and `Identity`).

### CIRISClient (2 rows to `n/a`)

| decimal_id | claim_id | path#symbol | field | prefix |
|------------|----------|-------------|-------|--------|
| 3.1.5.1 | `CLM-nsproc-action-non-binding-recommended-handlerac-dma-pdma` | `#EthicalDMAResult` | `action (non-binding recommende` | `dma:pdma:*` |
| 3.1.5.3 | `CLM-nsproc-identified-uncertainties-conscience-epistemic-humility` | `#EpistemicHumilityResult` | `identified_uncertainties` | `conscience:epistemic_humility` |

### CIRISEdge (3 rows to `evidence/cc_impl.tsv`)

| decimal_id | claim_id | path#symbol | field | prefix |
|------------|----------|-------------|-------|--------|
| 3.1.9.7 | `CLM-nsproc-delivery-durability-goal-scale` | `src/messages/mod.rs#GoalDeclaration::DELIVERY` | `delivery durability` | `goal:{scale}` |
| 3.1.1 | `CLM-nsproc-holder-staleness-ttl-contentmiss-withdra-agent-files-kind-platform-or-target` | `src/transport/reticulum.rs#filter_holders_with_policy` | `holder staleness/TTL + Content` | `agent_files:{kind}:{platform_or_target}` |
| 3.1.4 | `CLM-nsproc-key-boundary-scope-key-boundary-scope` | `src/key_boundary.rs#KeyBoundaryScope` | `key_boundary_scope` | `key_boundary:{scope}` |

### CIRISPersist (20 rows to `evidence/cc_impl.tsv`)

| decimal_id | claim_id | path#symbol | field | prefix |
|------------|----------|-------------|-------|--------|
| 3.1.9.2 | `CLM-nsproc-community-id-moderation-allegation-type` | `CIRISPersist/src/federation/admission.rs#check_delegated_duty_scores_a` | `community_id` | `moderation:{allegation_type}` |
| 3.1.9.2 | `CLM-nsproc-community-id-reconsideration-grounds` | `src/federation/admission.rs#named_moderator_holders` | `community_id` | `reconsideration:{grounds}` |
| 3.1.9.4 | `CLM-nsproc-class-dual-scope-gate-watchlist-id` | `src/safety/watchlist.rs#authority_admits_enable` | `class (dual-scope gate)` | `watchlist:{id}` |
| 3.1.2 | `CLM-nsproc-cosign-transparency-log-cosigned-tree-size` | `src/federation/operational.rs#check_skew_bound` | `cosign` | `transparency_log:cosigned:{tree_size}` |
| 3.1.2 | `CLM-nsproc-cosignature-transparency-log-cosigned-tree-size` | `src/federation/tier_ingest.rs#verify_federation_tier_ingest` | `cosignature` | `transparency_log:cosigned:{tree_size}` |
| 3.1.8.5 | `CLM-nsproc-cross-attestation-prefix-distinctness-detection-distributive-access-resource-t` | `src/federation/admission.rs#default_reserved_prefix_rules` | `cross-attestation prefix disti` | `detection:distributive:access:{resource_type}` |
| 3.1.9.5 | `CLM-nsproc-decision-pointer-locality-decision-scale` | `reuse typed references_attestation_id (drop bespoke decision_ref)` | `decision pointer` | `locality:decision:{scale}` |
| 3.1.9.4 | `CLM-nsproc-enabled-watchlist-id` | `src/safety/watchlist.rs#enable_watchlist` | `enabled` | `watchlist:{id}` |
| 3.1.1 | `CLM-nsproc-family-roster-membership-change-via-entr-accord` | `ciris-verify-core/src/accord_genesis.rs#build_accord_family_envelope` | `family roster membership-chang` | `accord:*` |
| 3.1.9.7 | `CLM-nsproc-goal-scope-goal-scale` | `src/federation/goal.rs#GoalScope` | `goal.scope` | `goal:{scale}` |
| 3.1.9.4 | `CLM-nsproc-group-key-id-watchlist-id` | `src/safety/watchlist.rs#authority_admits_enable` | `group_key_id` | `watchlist:{id}` |
| 3.1.1 | `CLM-nsproc-holds-bytes-agent-files-kind-platform-or-target` | `src/federation/blobs.rs#holds_bytes_attestation_envelope` | `holds_bytes` | `agent_files:{kind}:{platform_or_target}` |
| 3.1.9.4 | `CLM-nsproc-kind-kind-discriminator-hard-case-kind` | `src/federation/admission.rs#check_reserved_prefix_admission` | `kind ({kind} discriminator)` | `hard_case:{kind}` |
| 3.1.8.2 | `CLM-nsproc-lens-core-version-detection-intra-agent-consistency` | `src/derived/types.rs#DetectionEvent` | `lens_core_version` | `detection:intra_agent_consistency` |
| 3.1.9.7 | `CLM-nsproc-meta-goal-alignment-goal-scale` | `src/federation/goal.rs#Goal::new` | `meta_goal_alignment` | `goal:{scale}` |
| 3.1.5.1 | `CLM-nsproc-raw-chain-of-thought-dma-csdma` | `src/federation/schema_resolver.rs#BlobBackedSchemaResolver` | `raw_chain_of_thought` | `dma:csdma:*` |
| 3.1.2 | `CLM-nsproc-restrictions-attestation-license-validity` | `src/federation/consent_grammar.rs#RestrictionOp::StripField` | `restrictions` | `attestation:license_validity` |
| 3.1.2 | `CLM-nsproc-witness-key-id-transparency-log-cosigned-tree-size` | `src/federation/admission.rs#default_reserved_prefix_rules` | `witness_key_id` | `transparency_log:cosigned:{tree_size}` |
| 3.1.8 | `CLM-nsproc-cohort-operational-definition-calibratio-manifold-conformity-cohort` | `signing/event.rs#CohortDelineation` | `{cohort} operational definitio` | `manifold_conformity:{cohort}` |
| 3.1.1 | `CLM-nsproc-kind-open-vocab-registration-collision-g-agent-files-kind-platform-or-target` | `src/federation/schema_resolver.rs#BlobBackedSchemaResolver` | `{kind} open-vocab registration` | `agent_files:{kind}:{platform_or_target}` |

### CIRISServer (4 rows to `evidence/cc_impl.tsv (header-only today)`)

| decimal_id | claim_id | path#symbol | field | prefix |
|------------|----------|-------------|-------|--------|
| 3.1.1 | `CLM-nsproc-professional-partner-role-role` | `http.rs#partner_composition` | `PROFESSIONAL_` | `partner_role:{role}` |
| 3.1.2 | `CLM-nsproc-attestation-evidence-attestation-hardware-rooted` | `CIRISServer/src/hardware_attestation.rs#admit_hardware_class_against_r` | `attestation_evidence` | `attestation:hardware_rooted` |
| 3.1.9.4 | `CLM-nsproc-consent-health-liveness-version` | `src/peer.rs#register_peer_key` | `consent` | `health:liveness:{version}` |
| 3.1.9.3 | `CLM-nsproc-meets-bar-witness-diversity-contribution-id` | `src/compose_policy.rs#aggregate` | `meets_bar` | `witness_diversity:{contribution_id}` |

### CIRISVerify (11 rows to `evidence/cc_impl.tsv`)

| decimal_id | claim_id | path#symbol | field | prefix |
|------------|----------|-------------|-------|--------|
| 3.1.2 | `CLM-nsproc-consistency-proof-transparency-log-cosigned-tree-size` | `src/ciris-verify-core/src/transparency.rs#verify_consistency` | `consistency_proof_` | `transparency_log:cosigned:{tree_size}` |
| 3.1.2 | `CLM-nsproc-import-timestamp-provenance-skill-import-source` | `skill_import.rs#check_canonical_rfc3339` | `import_timestamp` | `provenance:skill_import:{source}` |
| 3.1.1 | `CLM-nsproc-invocation-id-accord` | `ciris-verify-core/src/humanity_accord.rs#InvocationDedup::record_or_re` | `invocation_id` | `accord:*` |
| 3.1.1 | `CLM-nsproc-invocation-kind-accord` | `ciris-verify-core/src/humanity_accord.rs#InvocationKind` | `invocation_kind` | `accord:*` |
| 3.1.2 | `CLM-nsproc-level-u8-1-2-3-provenance-slsa-level` | `attest_bundle.rs#AttestBundle::from_federation_provenance` | `level (u8 1\|2\|3)` | `provenance:slsa:{level}` |
| 3.1.2 | `CLM-nsproc-manifest-ref-attestation-agent-integrity` | `src/ciris-verify-core/src/engine.rs#verify_agent_integrity` | `manifest_ref` | `attestation:agent_integrity` |
| 3.1.2 | `CLM-nsproc-platform-hardware-custody-platform` | `unified.rs#FullAttestationResult::to_federation_provenance` | `platform` | `hardware_custody:{platform}` |
| 3.1.2 | `CLM-nsproc-root-hashes-consistency-proof-nodes-evid-transparency-log-consistency` | `#transparency::verify_consistency_proof` | `root hashes + consistency_proo` | `transparency_log:consistency` |
| 3.1.2 | `CLM-nsproc-root-hash-sha256-hex-transparency-log-cosigned-tree-size` | `src/ciris-verify-core/src/transparency.rs#SignedTreeHead::cosign` | `root_hash_sha256_hex` | `transparency_log:cosigned:{tree_size}` |
| 3.1.1 | `CLM-nsproc-threshold-signatures-sender-aggregate-accord` | `ciris-verify-core/src/threshold.rs#verify_threshold_signatures` | `threshold signatures (sender a` | `accord:*` |
| 3.1.2 | `CLM-nsproc-tree-size-transparency-log-cosigned-tree-size` | `src/ciris-verify-core/src/transparency.rs#verify_consistency` | `tree_size` | `transparency_log:cosigned:{tree_size}` |

---

## 9. Per-family appendix

One entry per family: round-1 superset class + round-2 CI axes summary, invariants count, placement fields, primitive requirements, deltas, and flags. Full detail per family in `families.<prefix>` in the JSON.

### `accord:*`

- CC 3.1.1 · owner CIRISRegistry/registry · superset-class: GovernanceInstrumentCard · polarity see CC 3.4.1 · reserved=True
- CI axes: sender=family_specific, data_subject=not_applicable, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 7 · placement fields: 10
- Required primitives: reserved-emitter admission gate (identity_type=accord_holder); threshold/multi-sig verification over live family roster (never single attesting_key_id); per-invocation_kind differentiated threshold policy per CC 4.2.6 (RATIFIED, NOT SHIPPED); admission-time (invocation_kind, invocation_id) dedup within valid_until; cross-referential resumes_halt_id-vs-latched-halt check (NOT SHIPPED); family membership-change via entrenchment-preserving supersedes
- Forbidden: aggregate/average across accord:invoke:* claims; withdraws/recants as reversal of invoke:CONSTITUTIONAL; delegates_to of accord-holder invoke authority to a non-seated key; lone/self-attested signature admitting any accord leaf at baseline threshold
- Deltas from seed (7): MAJOR wrong archetype: seed invented GovernanceInstrumentCard (ratify/co_scrub/amend of accord text); accord:* is a CLOSED four-leaf HUMANITY_ACCORD kill-switch namespace - replace with AccordInvocati ...
- **Flags:**
  - needs-human-review: resumes_halt_id NOT cross-checked against the latched halt invocation_id in reactivate_accord (confirmed by full-file read) - stale/wrong resumes_halt_id would still clear whatever halt is latched
  - needs-human-review: CC 4.2.6 live-quorum-under-decimation ratified but not implemented; uniform quorum applied to every invocation_kind
  - needs-human-review/structural: accord:* does not flow through a generic EnvelopeCore/KindPolicy chokepoint - structural outlier needing its own multi-sig chokepoint or documented exception
  - constitution-silent: delivery_mode (push) inferred from implementation, not textually mandated
  - needs-human-review: CC 3.4.1 lifecycle:active <=90-day refresh phrasing vs CC 4.2.1.3 resumes_halt_id-mandatory framing needs maintainer reconciliation
  - constitution-silent: AccordCarrier bidirectional admission gate not located in CIRISServer; ciris-registry-core not verified

### `activity_tier:{period}`

- CC 3.1.9.6 · owner CIRISNodeCore/node · superset-class: score_dial · polarity boolean-via-score · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 4 · placement fields: 6
- Required primitives: aggregate-min per (dimension,attested_key_id) once wired in compose_policy.rs; supersede (periodic 30-day re-assertion); withdraws; recants (bad-data roll-up correction)
- Deltas from seed (6): typical_cohort_scope self/SelfOwn likely wrong: family is a cross-consumer trust-filter input; self scope makes it structurally invisible to its consumers ...
- **Flags:**
  - constitution-silent: {period} canonical format
  - constitution-silent: Frickerian extension question
  - constitution-silent: cohort_scope default
  - needs-human-review: compose_policy.rs polarity_for missing activity_tier/credits/expertise arms (live drift, file independently)
  - needs-human-review: zero producers exist - family 100% unimplemented; all placements prospective

### `agent_files:{kind}:{platform_or_target}`

- CC 3.1.1 · owner CIRISRegistry/registry · superset-class: ArtifactPointerCard · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 6
- Required primitives: signed-attestation (open emit); supersedes w/ differs_in (build bump); withdraws (incl. consumer-triggered on ContentMiss); recants (compromised build); conditional subject_key_ids gate when {kind} names a subject (UNIMPLEMENTED); install-endpoint identity gate for Layer-1 (UNIMPLEMENTED)
- Forbidden: vote-weighted composition as sole/sufficient input to install-endpoint canonical trust
- Deltas from seed (7): actor should be open/producer_signed not auto_emitted (auto_emitted describes only the holds_bytes companion) ...
- **Flags:**
  - needs-human-review: subject_key_ids enforcement has ZERO implementation despite claims.tsv marking established - evidence registry stale or gate missing
  - needs-human-review: Policy F Layer-1 gate has no compose_policy.rs implementation; family code-absent in CIRISServer
  - constitution-silent: delegate op neither confirmed nor forbidden for this family

### `approach:{goal_id}`

- CC 3.1.9.7 · owner CIRISNodeCore/node · superset-class: PathwayCard · polarity signed · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 3
- Required primitives: self-authored signed emit (open, not reserved); supersede via references_attestation_id (primary lifecycle op); withdraw; recant; upward-only DAG parent validation at admission (NEEDED, unbuilt - only read-time resolver exists); default mean aggregate if multiple attesters
- Deltas from seed (6): card_category/superset_class wrong: use descriptive-feed/FeedEntryCard (per repo's own archetype doc sec.3.15), not Capacity/PathwayCard ...
- **Flags:**
  - needs-human-review: F-11 retraction unelaborated
  - needs-human-review/split-truth: parent-Goal identity space ambiguous between NodeCore scale-string and Persist Uuid Goal (reported to hunt-split-truth/hunt-dual-owner)
  - constitution-silent: no required construction-time fields beyond parent linkage

### `attestation:agent_integrity`

- CC 3.1.2 · owner CIRISVerify/attestation · superset-class: score_dial · polarity boolean-via-score · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 7 · placement fields: 6
- Required primitives: self-attestation-permitted (no attester!=attested gate); mechanism-only dimension emission; fail-secure min composer (consumer-side, unbuilt); supersedes-chain freshness per attestation_cycle
- Forbidden: ladder-position-in-wire-prefix; mean/average cross-attester aggregation; capacity-style self-emission rejection applied here; wire-level hard-coded L-number gating
- Deltas from seed (7): cohort_scope default corrected affiliations->federation (Commons, world-readable) ...
- **Flags:**
  - needs-human-review: AttestationLadderTransitionPolicy default DualAccept - constitution 'rejected at admission' aspirational (CIRISPersist#117)
  - needs-human-review: no fail-secure MIN cross-attester composer anywhere; first-wins instead
  - constitution-silent: raw_tree_hash/diff_summary redaction by recipient_capability ungrounded

### `attestation:hardware_rooted` · **NO ROUND-1 SEED (round-2-first)**

- CC 3.1.2 · owner CIRISPersist/persist
- CI axes: sender=default, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=default
- Invariants: 5 · placement fields: 6
- Required primitives: boolean-existence composition (any-positive per mechanism); hardware_class trust-multiplier join at composition before crediting L2; mechanism-only dimension admission gate; cryptographic chain-to-pinned-root corroboration where a verifier exists (CIRISServer ExternalSecureElement pattern as template)
- Forbidden: mean/weighted-average aggregation to a fractional ladder verdict; wire-level ladder-position encoding; face-value crediting of self-asserted hardware_class without the R5 table; default attested-key revoke authority over its own hardware_rooted rows
- Deltas from seed (1): No round-1 seed existed (round-1 finder failed); built from scratch against constitution + pinned persist v21.4.0 / verify v10.6.3 / server source.
- **Flags:**
  - needs-human-review: pinned persist DualAccept admits deprecated attestation:l{N} form, contradicting CC 4.4.3.6 present-tense reject; RejectDeprecated exists but opt-in only
  - needs-human-review: attestation:hardware_rooted wire Contribution never emitted anywhere as wired - server verifies YubiKey class at registration but never projects; verify-core emits helpers only for classes this node cannot verify
  - constitution-silent: no valid_until/staleness guidance; silent on re-attestation after key rotation

### `attestation:license_validity`

- CC 3.1.2 · owner CIRISVerify/attestation · superset-class: score_dial · polarity boolean-via-score · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 5
- Required primitives: withdraw; supersede; recant; consent-gated-promote (must route through promote_consented_backlog-equivalent resolution before federation delivery); strip-field-restriction-at-promotion
- Forbidden: delegate (no human principal; Verify binary self-asserts after Registry cross-check); licensure-style single-source cap import; bare-tier-promote-as-sole-path once scope narrower than a grant audience matters
- Deltas from seed (6): actor mislabeled human_authored: producer is CIRISVerify binary (service-authored) ...
- **Flags:**
  - needs-human-review: confirm server_endpoint wires promotion through promote_consented_backlog, not bare attestation_promote
  - needs-human-review: build:registered precondition unenforced in persist v21.4.0
  - constitution-silent: cohort_scope/visibility default
  - evidence-registry-stale: cc_impl.tsv row for CC 4.4.3.6 marks open while persist implements the gate

### `attestation:registry_consensus`

- CC 3.1.2 · owner CIRISVerify/attestation · superset-class: score_dial · polarity boolean-via-score; Indeterminate allowed → RESTRICTED · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=default
- Invariants: 5 · placement fields: 4
- Required primitives: bare mechanism-only emission (open self-assert); canonical-hash subject tagging for non-key subjects; supersede-on-recheck; MIN fail-secure aggregation per (dimension,subject); cohort_scope:federation for node->canonical emissions
- Forbidden: ladder-encoded dimension strings on wire; recant (mechanical rollup; no false-when-made semantics); attested_key_id as sole subject-carrier for build/license; Indeterminate collapsing to pass; community-DEK-wrapping node->canonical conformance emissions
- Deltas from seed (6): cohort_scope corrected affiliations->federation/Global per CC 4.4.3.2.1's own example ...
- **Flags:**
  - needs-human-review: AttestationLadderTransitionPolicy still DualAccept (CIRISPersist#117)
  - needs-human-review: no admission enforcement ties registry_consensus + infra target to cohort_scope:federation
  - needs-human-review: subject_key_ids canonical-hash tag format has no validator (cross-family gap)

### `attestation:self_verify`

- CC 3.1.2 · owner CIRISVerify/attestation · superset-class: score_dial · polarity boolean-via-score · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 4
- Required primitives: scores (boolean-via-score workhorse); supersedes (periodic re-verification); withdraws (stale/erroneous emission); recants (comparator-bug false pass; CC 2.4.1.3 generally available)
- Forbidden: delegates_to - self_verify's defining shape is attester==attested; proxy signing collapses the L1 distinction (strong inference, not verbatim CC)
- Deltas from seed (7): cohort_scope self/SelfOwn likely wrong - would hide the rung from ladder consumers; correct default federation (needs-human-review) ...
- **Flags:**
  - needs-human-review: cohort_scope correction (federation not self) is inference; confirm with stewards
  - needs-human-review (live drift): DualAccept default still admits attestation:l{N}:*; confirm post-CEG-0.3 flip status
  - needs-human-review: no attester==attested check for self_verify; live test fixture emits third-party self_verify (steward for agent) - intended shape or fixture reuse?
  - constitution-silent: nothing else self_verify-specific beyond cited sections (grep-confirmed)

### `audit_chain:hash_continuity`

- CC 3.1.3 · owner CIRISPersist/persist · superset-class: SubstrateSelfReport · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 4 · placement fields: 5
- Required primitives: reserved-prefix emit gate (identity_type contains substrate_persist); dual admission + consumer re-check (CC 3.4.7); generic supersede/withdraws/recants precedence via references_attestation_id
- Forbidden: non-substrate_persist emission; delegation as emitter-gate bypass (gate reads attesting key's OWN identity_type; delegates_to structurally inert)
- Deltas from seed (5): generated_at redundant with typed asserted_at ...
- **Flags:**
  - needs-human-review: steward-triple cross-attestation of substrate_persist key unverified anywhere (single scrub_key_id co-signer possible) - maybe closed out-of-band by genesis ceremony
  - constitution-silent: payload shape UNDERSPECIFIED per FSD-005; seed superset fields provisional
  - constitution-silent: no explicit anti-aggregation rule; per-instance by subject definition - caution for composition authors, not a hard rule

### `autonomy:{aspect}`

- CC 3.1.5.2 · owner CIRISAgent/accord-agent · superset-class: AssessmentCard · polarity signed · reserved=False
- CI axes: sender=default, data_subject=default, recipient_see=default, info_type=family_specific, temporal=default
- Invariants: 5 · placement fields: 3
- Required primitives: scores (base workhorse); self-as-subject ceremony support (CC 2.3.4); withdraws rules 1-3 resolved against subject_key_ids; subject-bearing admission check (CC 4.5.2.1) - unbuilt for any family
- Forbidden: cross-principle composite folding autonomy with the other five principles into one lossy number
- Deltas from seed (7): remove bespoke subject_ref (duplicates attested_key_id) ...
- **Flags:**
  - needs-human-review: should autonomy self-reports from vulnerable cohorts get Frickerian + never-sole-slashing protection like testimonial_witness?
  - needs-human-review: boundary vs prohibited:manipulation_coercion apophatic floor undefined - double-count risk
  - constitution-silent: CC 4.5.2.1 pattern-match never literally fires (no {key_id} in dimension) though spirit applies - recommend registering in the catalog
  - constitution-silent: non-fungibility declared without engineered wire-level enforcement

### `benchmark:he300:{category}:{version}`

- CC 3.1.10 · owner CIRISBench/cirisbench · superset-class: ScoredMetricCard · polarity positive-only · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 7 · placement fields: 7
- Required primitives: emit (open, single practical steward); supersede-for-rerun (references_attestation_id + differs_in); recant-for-acknowledged-scoring-error (CC 2.4.1.3); positive-only max aggregation; version-partitioned composition; shadow-set calibration cross-check before uplift composition
- Forbidden: subject-side withdraws over one's own benchmark score; cross-version aggregation/trending; self-emission as sole capacity-uplift evidence; threshold loosening without WA approval; canonical category wire-value substitution
- Deltas from seed (8): drop bespoke subject_ref (use subject_key_ids) with the load-bearing caveat that populating it grants withdraws - must be suppressed ...
- **Flags:**
  - needs-human-review: subject-side withdraws suppression has no precedent carve-out and conflicts with drift architecture if left default
  - needs-human-review: dotted version tokens vs bare-integer :vN gate - cross-repo decision (Constitution + Persist)
  - constitution-silent: no numeric n_items floor for a non-low-confidence run

### `beneficence:{aspect}`

- CC 3.1.5.2 · owner CIRISAgent/accord-agent · superset-class: OpenAssertionCard · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 7
- Required primitives: scores (signed; within-aspect mean); supersedes; withdraws (subject-agent revocation); recants
- Forbidden: cross-aspect/axis composite scalar; netting beneficence against prohibited:* floor breaches; sole-evidence use for slashing absent T4 separation; delegate (no delegates_to pathway for principle-scoring authority)
- Deltas from seed (9): data_subject corrected: agent conduct verdict, not a human's self-reported good deed ...
- **Flags:**
  - needs-human-review: cohort_scope default undecided (implementation decision)
  - constitution-silent: no bespoke beneficence composition clause exists; invariants inferred by connecting Annex A + agent-layer framing + fail-secure floors
  - seed-wrong-archetype: generic virtue-badge template vs agent-conduct verdict
  - needs-human-review: zero cc_impl.tsv entries - every processor proposed, nothing compiler/admission-checkable

### `bond_posted:{currency}`

- CC 3.1.1 · owner CIRISRegistry/registry · superset-class: StakedCollateralCard · polarity positive-only · reserved=False
- CI axes: sender=family_specific, data_subject=default, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 5
- Required primitives: scores (Posted, positive-only, Registry-attested); withdraws (Released, prudent retraction); supersedes (amended/re-posted); cross-dimension revocation:* read composing Forfeited; cross-dimension stake-backing resolution on other attestations
- Forbidden: aggregate-by-SUM (CC 4.4.2 mandates MAX); recants against bond_posted (a legitimately-posted bond was never false); in-envelope bond_status/forfeiture_ref/escrow_ref typed enums; auto-elevating self-attested postings without witness_relation discount; steward/CIRIS-L3C exemption in forfeiture composer
- Deltas from seed (7): amount_minor/duplicate currency/bond_status/forfeiture_ref/pob_round_id/escrow_ref not supported as typed members; detail belongs in evidence_refs/context to Registry ledger ...
- **Flags:**
  - needs-human-review: cohort_scope floor (community vs federation) unpinned
  - needs-human-review: ISO-4217/token-registry validation would be a NEW rule
  - constitution-silent: only the registry row + FSD paragraph + stake composition exist for this family
  - evidence-registry: ZERO CC 3.1.1 entries; family completely dark in code

### `build:registered:{target}`

- CC 3.1.1 · owner CIRISRegistry/registry · superset-class: RegistrationPrecondition · polarity boolean-via-score · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=default
- Invariants: 2 · placement fields: 1
- Required primitives: standard signed boolean-via-score emit; supersede (re-registration on rebuild); recant (false registration)
- Deltas from seed (7): registration_score duplicates the standard score field - drop ...
- **Flags:**
  - needs-human-review
  - constitution-silent

### `capacity:composite`

- CC 3.1.8.1 · owner CIRISLensCore/lens · superset-class: ScoredComposite · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=default, recipient_see=default, info_type=family_specific, temporal=default
- Invariants: 6 · placement fields: 5
- Required primitives: admission no-self-emit wildcard check; reserved-prefix three-actor enforcement; federation-tier-only origination; consumer-side-only meta-judgment composition
- Forbidden: self-emission (incl. under cohabitation); local-tier/self-scope admission; wire-level meta-judgment prefix minting from capacity:*; additive/weighted-average composite; sole/standing evidence for authority actions; conflating composite with Accord F
- Deltas from seed (6): scored-by-canonical framing wrong: no lenscore_detector/designated-scorer gate exists; open-emit subject only to no-self-emit ...

### `capacity:core_identity`

- CC 3.1.8.1 · owner CIRISLensCore/lens · superset-class: score_dial · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=default, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 2
- Required primitives: cross-attestation (peer-scored); multiplicative-fold-into-composite (product only); supersede (correction path); withdraw; capability-gated evidence projection (design-layered)
- Forbidden: self-attestation; aggregate-by-average across the five factors; sole-evidence-for-authority/slashing; emitter role gate beyond CC 3.4.5
- Deltas from seed (7): emit_authority overstated (canonical/scored-by-canonical); only gate is no-self-emit ...
- **Flags:**
  - needs-human-review: confirm persist admission mirrors the lens-core construction-time check (cross-repo)
  - constitution-silent: cohort_scope default; recant policy; capacity:audit gate

### `capacity:incompleteness_awareness`

- CC 3.1.8.1 · owner CIRISLensCore/lens · superset-class: ScoredCapacityMetric · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 3 · placement fields: 8
- Required primitives: scored third-party measurement (never self); reserved-prefix admission gate + consumer re-check; multiplicative composite input; supersede chain via references_attestation_id
- Forbidden: self-emit; averaged fold into composite; subject-side withdraws/recants as correction mechanism
- Deltas from seed (11): i_inc_score rides the universal score key - no new field ...
- **Flags:**
  - constitution-silent: recipient_see/receive specifics
  - constitution-silent: no strip_field/redaction mechanism exists for capacity:*
  - needs-human-review: should a scored subject ever get subject_key_ids withdraws over a scorer's capacity row, or is rebuttal the sole recourse?
  - needs-human-review: whether to hoist a required method/lineage field for all capacity factors

### `capacity:integrity`

- CC 3.1.8.1 · owner CIRISLensCore/lens · superset-class: score_dial · polarity signed · reserved=True
- CI axes: sender=default, data_subject=family_specific, recipient_see=default, info_type=default, temporal=family_specific
- Invariants: 6 · placement fields: 4
- Required primitives: scores-emit (self-emission admission-gated); supersede (same-attester); withdraws (rule 1; subject path must stay inert via empty subject_key_ids); recants (attester-only; CORRECTED from seed false); mean(score x confidence) cross-attester aggregation; multiplicative-only fold into composite
- Forbidden: self-emission (incl. cohabitation); sole/unilateral authority-tier input; additive composite; subject-side recant; subject_key_ids containing attested_key_id (arms withdraws rule 2 - CONFIRMED present in scorer.rs); delegated scoring without chain-walking the equality check (open disguised-self-emission risk)
- Deltas from seed (8): recant TRUE not false (attester-only falsity admission) ...
- **Flags:**
  - needs-human-review: any-non-subject-key emitter posture confirm before hard-coding
  - needs-human-review (CONFIRMED LIVE BUG, reported): scorer.rs:434-435 subject_key_ids self-revocation channel; carries over to capacity:integrity via same emit path
  - needs-human-review: delegates_to chain-walking for the equality check unaddressed in CC
  - note: capacity:* vs capacity_assurance:* shared-word confusion recurring

### `capacity:resilience`

- CC 3.1.8.1 · owner CIRISLensCore/lens · superset-class: score_dial · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=default
- Invariants: 3 · placement fields: 6
- Required primitives: scores (plain instance); reserved-prefix admission gate with wildcard prefix match (implemented both sides - not a proposed primitive)
- Forbidden: self-attestation (both admission and re-check); sole-input-to-adjudication; additive/mean composite in place of multiplicative
- Deltas from seed (7): reserved-rule/actor framing CONFIRMED IMPLEMENTED twice over - no gap to file ...
- **Flags:**
  - needs-human-review: confirm persist-side wildcard (vs enumerated leaves) matches the server-side wildcard - persist source lives in separate repo (cf. CIRISPersist#365 pattern)

### `capacity:sustained_coherence`

- CC 3.1.8.1 · owner CIRISLensCore/lens · superset-class: ScoredMetricAttestation · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=default, recipient_see=default, info_type=family_specific, temporal=default
- Invariants: 4 · placement fields: 6
- Required primitives: scores workhorse (dimension=capacity:sustained_coherence:v1); self-emission inequality gate at BOTH admission and consumer re-check; multiplicative five-factor composite; supersedes-ordered trend chain; cross-community replication-consent gate (consent:replication:v1) before crossing a cohort boundary
- Forbidden: self-emission; sole-verdict/sole-slashing composition; weighted-average composite; identity_type role-gated admission for capacity:*; silent narrowing of a live consent:replication grant (MUST supersede)
- Deltas from seed (7): emit_authority overclaim: no CanonicalScorer/identity_type gate - only the CC 3.4.5 inequality ...
- **Flags:**
  - needs-human-review: score-range convention - CC signed [-1,+1] vs shipped [0,1] CapacityFactors/n_eff scorer; reconcile via CC footnote or scorer extension
  - constitution-silent: no sustained_coherence-specific aggregation/evidence rule beyond the shared composite rule (honest empty; registry search confirmed)

### `cert_validity:{authority}`

- CC 3.1.2 · owner CIRISVerify/attestation · superset-class: ScoredValidityBadge · polarity boolean-via-score · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 4 · placement fields: 4
- Required primitives: scores (boolean-via-score self-attestation, live as AttestationFact.passed); supersedes (fresh re-issuance with new valid_until); withdraws (generic 4-rule gate); recants (false-when-made)
- Deltas from seed (7): actor human_authored WRONG - machine/steward self-report per CC 3.1.2 + live code ...
- **Flags:**
  - needs-human-review: subject_key_ids population inferred from subject-bearing spirit, not catalog - confirm with stewards
  - needs-human-review: no {authority} anti-spoofing admission check exists (verified by grep of both repos)

### `coherence_standing:{cohort}`

- CC 3.1.8.3 · owner CIRISLensCore/lens · superset-class: score_dial · polarity signed · reserved=False
- CI axes: sender=default, data_subject=default, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 6
- Required primitives: signed-mean aggregation (CC 4.4.2 default); witness_relation-weighted self-attestation discount before standing; quorum-gated hand-off to NodeCore P8 before any slashing/moderation consumption; fail-secure Numeric/Indeterminate/Unavailable discretization mirroring manifold_conformity (component convention, not CC)
- Forbidden: sole/terminal slashing or moderation evidence without P8 quorum; reserved single-role emitter gate (must stay open-emit); bespoke value/evidence fields duplicating universal score/confidence/evidence_refs/witness_relation
- Deltas from seed (8): actor/emit_authority corrected: open emit incl. third parties (CC 4.1.3 relies on it), not human self-report only ...
- **Flags:**
  - constitution-silent: one-line Part 3 entry; UNDERSPECIFIED per FSD-005 (tracked editorial ask) - methodology is engineering judgment
  - needs-human-review: adopt manifold_conformity's fail-secure discretization + identical 6-tuple cohort keying, or claim-coherence-specific shape? LensCore design decision

### `commitment_fulfillment:{prior_contribution_id}`

- CC 3.1.9.2 · owner CIRISNodeCore/node · superset-class: score_dial · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 6 · placement fields: 7
- Required primitives: scores signed attestation (no new primitive); moderation_track_record fold over the 4 named inputs (3 of 4 missing live); witness_relation-keyed weight discount at every consumption; Signal_eff correlation discount into sigma
- Forbidden: bespoke assessor_role/evidence_strength fields (duplicate witness_relation/epistemic_mode); sole/automatic slashing from a shortfall; witness_relation:self at full weight toward sigma/merit; recants by anyone but the original attester
- Deltas from seed (7): drop assessor_role (duplicates witness_relation; violates 1+4 no-new-field discipline) ...
- **Flags:**
  - needs-human-review: should subject_key_ids grant the committer rule-2 self-revocation over a third-party reputation claim (4.5.2.1 written for consent contexts)
  - constitution-silent: catalog is open; subject requirement inferred from stated spirit
  - needs-human-review: no sigma implementation exists in Server/Persist - costly-to-fake/Kish invariants unenforceable for ANY family

### `conscience:coherence`

- CC 3.1.5.3 · owner CIRISAgent/accord-agent · superset-class: verdict_ledger · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=default
- Invariants: 7 · placement fields: 6
- Required primitives: direct-attestation signed-mean compose (generic); producer-only withdraw/supersede/recant; self-attestation track-record weighting (generic, applies with no gap)
- Forbidden: new faculty_id payload field; capacity-style self-emission REJECTION applied to conscience:*; emission under RESERVED detection:conscience_override_rate; naive (dimension,attested_key_id) mean blending across DIFFERENT reasoning-chain instances without evidence_refs scoping (hazard, not formally illegal)
- Deltas from seed (11): REMOVE faculty_id (dimension IS the faculty; this family is specifically conscience:coherence) ...
- **Flags:**
  - needs-human-review: no never-sole-evidence-for-slashing bound for conscience:* despite self-report shape
  - needs-human-review: default mean aggregation may blend independent per-decision verdicts
  - constitution-silent: per-faculty score semantics (UNDERSPECIFIED, tracked)
  - constitution-silent: conscience-dma fold mechanism undefined and unimplemented

### `conscience:entropy`

- CC 3.1.5.3 · owner CIRISAgent/accord-agent · superset-class: score_dial · polarity signed · reserved=False
- CI axes: sender=default, data_subject=not_applicable, recipient_see=family_specific, info_type=default, temporal=family_specific
- Invariants: 6 · placement fields: 7
- Required primitives: per-decision evidence anchor (evidence_refs -> thought/trace id); joint fold with dma:* for explainability-SLA evidence; self-emission by the producing agent's key; typed pass-fail + override signal for detection:conscience_override_rate (cross-repo consumer)
- Forbidden: artifact reference via subject_key_ids; importing capacity:* anti-Goodhart no-self-emit; naive per-agent mean without per-decision scoping
- Deltas from seed (10): entropy_score real but never reconciled against base signed score field (two parallel scores unaddressed) ...
- **Flags:**
  - constitution-silent: no per-faculty operational definition (near-thin family, CC amendment queued)
  - needs-human-review: zero wire emissions of conscience:* anywhere in CIRISAgent - local trace object today, bridge unbuilt
  - needs-human-review: LensCore not available to verify detection:conscience_override_rate field consumption mapping
  - needs-human-review: no documented mapping between entropy_score (0..1, 0=coherent) and signed score (-1..+1) - required before any hoist

### `conscience:epistemic_humility`

- CC 3.1.5.3 · owner CIRISAgent/accord-agent · superset-class: score_dial · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 8 · placement fields: 8
- Required primitives: scores (signed, per CC 3.1.5.3); self-attested verdict with evidence_ref footnote (subject = referenced prior action); external-detector cross-check (detection:conscience_override_rate); ECE-against-outcome calibration check (implemented: persist scoring.rs calibration_error feeding capacity:incompleteness_awareness); supersede/withdraw/recant over own prior verdict-row (rule 1)
- Forbidden: capacity-style RESERVED no-self-emit gate; sole/conclusive evidentiary use for slashing/authority even when corroborated; raw CC 4.4.2 mean without grouping by evidence_refs action; new referenced_action_id field or references_attestation_id reuse for non-lifecycle cross-reference
- Deltas from seed (9): drop referenced_action_id; reuse evidence_refs (REQUIRED non-empty) ...
- **Flags:**
  - needs-human-review: no wire-emission path for conscience:epistemic_humility (agent computes, persist aggregates trace booleans/ECE, no CEG Attestation) - tracker issue warranted
  - constitution-silent: score sign convention unmapped (UNDERSPECIFIED per FSD-005)
  - constitution-silent: {faculty_id} sub-parameterization unaddressed by flat-prefix text (provisional per editorial ask)

### `conscience:optimization_veto`

- CC 3.1.5.3 · owner CIRISAgent/accord-agent · superset-class: VerdictCard · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=not_applicable, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 4
- Required primitives: scores (witness_relation:self, attested==attesting); supersedes (chain by decision_ref + differs_in); withdraws (rule 1); recants (mistaken veto/allow)
- Forbidden: delegates_to third-party emission of conscience:* (defeats self-attestation integrity); sole reliance on conscience:*/override-rate detector as slashing evidence (T4)
- Deltas from seed (7): actor system_derived -> self-attestation by the agent's own key (witness_relation:self, attested==attesting) ...
- **Flags:**
  - needs-human-review: should conscience:* be formally admission-reserved to the agent's own key (attested==attesting structural), vs consumer-policy re-check only? CC 3.4 tables do not list it - third-party forgery not wire-rejected today
  - needs-human-review: should evidence_refs version-pinning be REQUIRED (not merely permitted) given faculty implementations evolve
  - constitution-silent: every invariant above derives from general-purpose rules; honest empty at the family-text level

### `corpus_health:n_eff_measurable`

- CC 3.1.3 · owner CIRISPersist/persist · superset-class: gauge · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=default
- Invariants: 6 · placement fields: 5
- Required primitives: reserved-prefix emit gate; steward-triple cross-attestation of substrate identity; producer-self-withdraw (rule 1); supersedes (revised measurement)
- Forbidden: delegate-based emission; third-party/subject-side withdraws (rules 2/3 moot); substituting this leaf for federation_directory:replication_lag (distinct referents)
- Deltas from seed (6): MAJOR semantic correction: n_eff = fountain-storage/aggregation-tier dominance-gate effective-source-count (storage corpus erasure/noise-floor health), NOT mesh node/replica count (seed card_category  ...
- **Flags:**
  - needs-human-review: attested_key_id self-binding gap in check_reserved_prefix_admission (corpus_health + CC 3.1.3 siblings)
  - seed-wrong-archetype: mesh-capacity gauge vs storage noise-floor self-report
  - constitution-silent: composition/weighting/UI policy beyond the emitter rule (UNDERSPECIFIED pending CC 8.1)

### `credits:{domain}:{language}:substrate_building`

- CC 3.1.9.6 · owner CIRISNodeCore/node · superset-class: LaborCredit · polarity positive-only · reserved=False
- CI axes: sender=family_specific, data_subject=default, recipient_see=family_specific, info_type=family_specific, temporal=default
- Invariants: 4 · placement fields: 3
- Forbidden: inclusion in P2 grounded-vote-weight composition when subject==substrate_building (the defining exclusion); sum-across-attestations beyond the positive-only max default
- Deltas from seed (5): central miss: excluded_from_vote_accrual as a payload boolean has no teeth - real gate belongs in read_vote_weight keyed off the subject string (traced: flat lookup, no exclusion) ...
- **Flags:**
  - needs-human-review

### `credits:{domain}:{language}:{subject}`

- CC 3.1.9.6 · owner CIRISNodeCore/node · superset-class: LedgerEntry · polarity positive-only · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 6 · placement fields: 6
- Required primitives: loop-gated accrual (base leaf via the designated vote loop, not open self-assertion); supersede-only correction (non-negative); Signal_eff/Kish discount on sigma composition; bounded vote-weight promotion (Layer-3 only); adjudicated-fraud path (moderation:expertise_fraud -> optional slashing); (proposed, DRAFT) attester-diversity gate for substrate_building
- Forbidden: transfer/reassignment of a credit entry's subject; negative-amount emission; raw/uncapped sigma aggregation when sources correlated; credits/vote accumulation as Layer-1 canonical-trust input; slashing inferred from magnitude/disagreement alone; (flagged risk) self-attested substrate_building accrual without independent attester
- Deltas from seed (8): seed conflates the base leaf with the substrate_building sub-leaf; superset_fields describe the sub-leaf's use case mislabeled as the base ...
- **Flags:**
  - needs-human-review: cohort_scope default unpinned
  - needs-human-review: RT-H7 caps DRAFT/SCOPED and unenforced - open abuse surface
  - needs-human-review: FSD-005 sec.11 credits-minting boundary (encyclopedic exclusion) not yet closed
  - constitution-silent: part_4 has zero direct credits composition section; discipline arrives via part_6 sigma + vote-weight anti-tricking

### `delivery:{class}`

- CC 3.1.4 · owner CIRISEdge/transport-delivery · superset-class: proof_chain · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=not_applicable, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 6 · placement fields: 3
- Required primitives: reserved emit gate (substrate_edge + steward-triple); aggregate/class-keyed self-report only ({class} from Reticulum transport semantics); base scores primitive only
- Forbidden: delegate; per-envelope/per-recipient discrete delivery-outcome attestation; conflation with delivery_receipt:{stream_id}; bespoke proof_chain typed fields (hop/envelope_ref/latency/retry as required fields); use as evidence in slashing/capacity/sigma/credits/reputation composition (KN:INFRA telemetry)
- Deltas from seed (7): WRONG ARCHETYPE: seed modeled a per-hop proof_chain attestation (hop_from/hop_to/envelope_ref/latency_ms/delivery_outcome/retry_count); constitution defines an AGGREGATE class-keyed self-report metric ...
- **Flags:**
  - seed-wrong-archetype
  - constitution-silent: {class} vocabulary, cohort_scope, delivery_mode, temporal specifics (UNDERSPECIFIED per FSD-005, CC 8.1 deferral)
  - needs-human-review: visibility scope + any downstream cross-node aggregation permission

### `detection:conscience_override_rate`

- CC 3.1.8.2 · owner CIRISLensCore/lens · superset-class: ScoreDial · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=default
- Invariants: 5 · placement fields: 7
- Required primitives: reserved-emitter admission gate (wildcard, not enumerated-leaf-only); non-authoritative composition (never sole authority input); namespace-preserving cross-attestation via truth_grounding:detection:*; adversarial-capture-resistant (median) aggregation - flagged extension
- Forbidden: sole-evidence-for-any-authority-action; same-prefix shadowing re-emission by non-detector keys
- Deltas from seed (9): remove subject_ref (duplicates attested_key_id) ...
- **Flags:**
  - needs-human-review: no CC 3.4.5-analog self-emission rejection for detection:* - recommend amendment
  - needs-human-review: CC 4.4.2 median table omits the five 3.1.8.2 leaves - Mean by literal reading
  - needs-human-review: blanket detection:* wildcard admission normative-but-unshipped (CIRISPersist#365) - conscience_override_rate may emit unchecked today
  - constitution-silent: no capability:*/recipient_capability primitive exists anywhere

### `detection:correlated_action:{axis}`

- CC 3.1.8.4 · owner CIRISLensCore/lens · superset-class: ScoredSignalCard · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 8 · placement fields: 10
- Required primitives: scores (sole workhorse; no bespoke wire shape); median-aggregation composer (consumer-side); reserved-emitter admission check (shipped persist; missing at consumer tier); calibration-package version-pin resolution; supersedes (recalibration supersedes prior verdict)
- Forbidden: aggregate as a NEW structural primitive; subject_key_ids population listing; sole evidence for slashing/authority actions; new typed envelope fields for population/sample/CI narrative
- Deltas from seed (10): population_ref list<identity_occurrence_ref> WRONG twice: identity_occurrence is a different CC 3.3.6 concept, and the envelope subject is singular with no population wiring at all ...
- **Flags:**
  - needs-human-review: compose_policy.rs lacks a CC 3.4.8 detector re-check (CC 3.4.7 agreement gap)
  - needs-human-review: F-3 federation-emission wiring absent - score_calibrated has no persist write path (several placements proposed for this reason)
  - needs-human-review: promised correlated_action delegates_to rename-chain not landed despite calibrated bundles shipping (stale doc or missed follow-through)
  - constitution-silent: no family deletion/tombstone discipline beyond 1+4
  - constitution-silent: consent scope of underlying traces feeding correlation analysis undecided

### `detection:cross_agent_divergence`

- CC 3.1.8.2 · owner CIRISLensCore/lens · superset-class: score_dial · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=default
- Invariants: 5 · placement fields: 8
- Required primitives: reserved-prefix emitter gate (LIVE); dual-prefix shadowing avoidance; non-adjudicative composition; captured-detector-resistant aggregation (median-leaning, scope ambiguous)
- Forbidden: sole-input-to-slashing-composer; same-dimension shadowing re-emission by non-detector keys
- Deltas from seed (9): agent_refs DROPPED for typed subject_key_ids ...
- **Flags:**
  - constitution-silent: median-vs-mean for the 3.1.8.2 leaves
  - constitution-silent: negative-score semantics not stated for this leaf (3.1.8.4-style clause absent)
  - needs-human-review: no self-emission bar when a folded key is among compared subjects
  - constitution-silent: whether this leaf needs a named calibration package vs only generic T3 pinning

### `detection:distributive:access:{resource_type}`

- CC 3.1.8.5 · owner CIRISLensCore/lens · superset-class: score_dial · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 6 · placement fields: 5
- Required primitives: emit(scores) detector-gated; supersede (re-run/recalibration); withdraw (bad run); median-aggregation composition (named carve-out); prefix shadowing avoidance
- Forbidden: mean/generic-signed aggregation; recant (measured statistic; corrections ride supersede/withdraw); delegate (detector-only right not delegable by proxy); sole evidence for slashing/authority actions; emission by keys lacking lenscore_detector membership
- Deltas from seed (7): resource_type vocabulary WRONG in seed (invented compute_quota/storage_bytes/api_call_budget/moderation_influence/federation_relay_slots); real set is the closed 5-value CC enum ...
- **Flags:**
  - needs-human-review: calibration-package pinning applicability (same F-3 machinery language vs 4.5.1.1 enumeration)
  - needs-human-review: PII/viewer-capability restrictions unconfirmed
  - needs-human-review: subject_key_ids wiring for population-scale measurement not worked out in CC 3.3
  - constitution-silent: nothing else family-specific beyond shared F-3/detector/median/advisory disciplines

### `detection:hash_chain_integrity`

- CC 3.1.8.2 · owner CIRISLensCore/lens · superset-class: score_dial · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 7 · placement fields: 6
- Required primitives: scores (verdict carrier); supersedes (re-scan lifecycle); recants (self-only buggy-scan correction); reserved-prefix admission gate (prefix + identity_type membership)
- Forbidden: envelope-field emitter discriminator (bespoke detector_identity_ref/is_primary_detection); shadowing re-emission by non-detector keys; sole-evidence composition into slashing/authority composers
- Deltas from seed (11): remove detector_identity_ref (contradicts prefix-is-discriminator rule) ...
- **Flags:**
  - needs-human-review: wildcard gate coverage for this leaf per CC-text CIRISPersist#365 tracking
  - needs-human-review: tenant_id -> attested_key_id mapping unresolved
  - implementation-gap: no code wires audit_verify_chain output into a signed emission

### `detection:intra_agent_consistency`

- CC 3.1.8.2 · owner CIRISLensCore/lens · superset-class: score_dial_detector · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=default
- Invariants: 4 · placement fields: 6
- Required primitives: reserved-prefix emitter gate over the wildcard; closed-enum dimension admission (no calibration package needed); supersede-on-rerun; withdraw-if-invalidated (producer; subject path blocked by missing field)
- Forbidden: capacity-style self-emission rejection applied here; sole evidence for slashing (T4); shadowing re-emission by non-detector keys; recant (measurement has no false-when-made referent)
- Deltas from seed (7): claim_meaning sharpened: frame-invariance across adversarial framings of the same question, not generic internal consistency ...
- **Flags:**
  - needs-human-review: is the LensStatePublication gossip path routed through standard check_reserved_prefix_admission on receiving peers, or a parallel channel sidestepping it? (relevant to CEG-replication E1-E9)
  - constitution-silent: no explicit self-emission rule for detection:* beyond capacity's; self-subject-permitted inferred from the fold example

### `detection:temporal_drift`

- CC 3.1.8.2 · owner CIRISLensCore/lens · superset-class: ScoredAnomalyDetection · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=default, recipient_see=default, info_type=family_specific, temporal=default
- Invariants: 6 · placement fields: 7
- Required primitives: reserved-prefix admission gate (SHIPPED); median-of-raw-score aggregation (SHIPPED); truth_grounding cross-attestation shadow-avoidance (SHIPPED); sole-evidence-for-slashing screen for detection:* (MISSING, proposed); generic tombstone lifecycle (inherited)
- Forbidden: aggregate as sole evidence for slashing/moderation without WA-quorum downstream; shadow re-emission by non-detector keys; over-generalizing the capacity self-emission bar onto this family
- Deltas from seed (8): confidence duplicates base envelope confidence - reuse ...
- **Flags:**
  - needs-human-review: no sole-evidence-for-slashing screen for detection:*/ratchet:flag in compose_policy.rs (file issue mirroring testimonial screen)
  - constitution-silent: consent/transmission-principle question for observing a subject's cadence
  - evidence-registry note: CLM-detector-only pinned to stale ciris-persist@v17.0.1 while v21.4.0 ships the wildcard fix

### `dma:csdma:*`

- CC 3.1.5.1 · owner CIRISAgent/accord-agent · superset-class: score_card (verdict + rationale + evidence-chain) · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=not_applicable, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 6 · placement fields: 6
- Required primitives: decision-partitioned score aggregation (group by decision_id BEFORE the 4.4.2 mean); local-tier-eligible promote-with-deferred-signature (gated on witness_relation:self + sole revocation); supersede-on-rerun of same decision_id; blob-backed content-addressed storage for raw traces referenced by hash; evidentiary-completeness check feeding explainability_sla L3/L4 + hard_case emission on gap
- Forbidden: post-hoc field-level strip of a signed envelope (breaks JCS canonical bytes); un-partitioned cross-decision aggregation under one (dimension, attested_key_id) bucket
- Deltas from seed (7): strip_field raw_chain_of_thought restriction cryptographically unimplementable as stated; correct shape = content-address via blob-backed schema under self-scope, verdict carries hash ...
- **Flags:**
  - needs-human-review: dma_variant in dimension leaf vs payload (changes aggregation-key granularity)
  - constitution-silent: no rule on dma:* as sole slashing evidence (contrast testimonial/ratchet) - needs explicit decision
  - constitution-silent: dma-conscience fold mechanism unspecified

### `dma:dsdma:{domain}:*`

- CC 3.1.5.1 · owner CIRISAgent/accord-agent · superset-class: score_dial · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=default
- Invariants: 6 · placement fields: 6
- Required primitives: self-attestation-permitted score emission; per-(dimension,attested_key_id) mean aggregation contingent on trace_id in the leaf; witness_relation-aware consumer weighting; cross-family fold with conscience:*; evidence_refs-backed chain reference (non-empty policy)
- Forbidden: sole/reserved emitter gating (none required per 4.5.8.3); treating an undeclared self-scored verdict as full-weight independent testimony; silent capability strips below a committed SLA tier without hard_case emission
- Deltas from seed (8): trace_id belongs in the dimension leaf, not a free-form field (4.4.2 grouping mechanics) ...
- **Flags:**
  - needs-human-review: exact scoped-leaf shape (trace_id in dimension vs evidence_refs vs both) inferred from 4.4.2 mechanics, not stated - confirm before hoisting to typed persist field
  - constitution-silent: dsdma {domain} vocabulary has no CC enum/registry
  - constitution-silent: no dma-specific cohort_scope/transmission/revoke/receive rules beyond base defaults

### `dma:idma:*`

- CC 3.1.5.1 · owner CIRISAgent/accord-agent · superset-class: DecisionVerdictCard · polarity signed · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=default
- Invariants: 4 · placement fields: 6
- Required primitives: self-attestation-permitted signed emit; evidence_ref-typed pointer to decision_instance; projection-time strip keyed on evidence_disclosure (SLA gradient); fold/join with sibling conscience:*; standard recant/supersede/withdraws
- Forbidden: idma consumed alone as a pass/fail gate without the conscience fold + SLA evidence check; capacity-style self-emission rejection; sole evidentiary input to slashing/moderation adjudication (inferred by analogy, flagged)
- Deltas from seed (5): idma is the terminal/integrated fold verdict, not a standalone peer family - composer/UI must reflect ordinal position ...
- **Flags:**
  - constitution-silent: default scope, strip mechanics, calibration overrides - consumer policy via generic defaults
  - needs-human-review: never-sole-slashing-evidence for dma:* is analogy-reasoned, not cited - confirm whether to make explicit

### `dma:pdma:*`

- CC 3.1.5.1 · owner CIRISAgent/accord-agent · superset-class: reasoning_verdict · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=default, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 6 · placement fields: 5
- Required primitives: scores (base emit, signed); supersedes (bounce-retry within same decision); withdraws; recants
- Deltas from seed (9): actor human_authored WRONG - machine/agent-authored ...
- **Flags:**
  - constitution-silent: no never-sole-evidence rule for dma:pdma:* and no dedicated composition policy - generic 4.4.2 mean applies
  - needs-human-review: no distinct wire-level veto-fired representation in spec or shipping schema
  - seed-wrong-archetype: superset drafted from a generic reasoning-verdict template, not the owning repo's real schema

### `expertise:{domain}:{language}`

- CC 3.1.9.6 · owner CIRISNodeCore/node · superset-class: ScoredProficiencyCard · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=default
- Invariants: 6 · placement fields: 6
- Required primitives: vote-weight multiplicative composition (pair-matched); WA-quorum gate before slashing (P8); ratchet advisory-flag consumption (scoring input to moderation review only); cohort-tiered projection (Policy H); signed-mean aggregation (CC 4.4.2)
- Forbidden: anomaly flag as sole slashing evidence; expertise_fraud alone triggering slashing without documented P8 adjudication
- Deltas from seed (7): over-narrowed to self-asserted only: no emitter restriction - peer endorsement equally wire-legal ...
- **Flags:**
  - needs-human-review: RT-H7 single-source cap DRAFT-only; without it self-cross-attesting cells inflate vote weight uncapped
  - constitution-silent: no freshness/valid_until mandate despite live multiplicative governance role
  - constitution-silent: no preferred self-vs-peer posture - product choice

### `federation_directory:replication_lag`

- CC 3.1.3 · owner CIRISPersist/persist · superset-class: gauge · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=default, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 6 · placement fields: 5
- Required primitives: reserved-emitter gauge scores emission; supersede-with-fresher-measurement (primary); withdraws/recants self-correction (attester-only); promote-with-full-placement (cohort_scope hoisted, defaulted federation-visible)
- Forbidden: cross-node emission under this reserved leaf (needs a distinct open dimension, currently unnamed); sole/primary evidence for Tier-4 slashing/moderation verdicts (network-health signal, not misconduct - analogy to ratchet/detection bars)
- Deltas from seed (5): scope corrected self/SelfOwn -> federation/Global (promotion-is-emit-moment + freshness-weighting purpose + sibling precedent) ...
- **Flags:**
  - needs-human-review: constitution cross-reference bug (3.1.3 -> 3.4.1 vs actual 3.4.3) - editorial fix upstream
  - constitution-silent: no dimension exists for legitimate third-party observation of a peer's directory lag - wire-legal expression impossible today
  - constitution-silent: units/encoding + composition formula UNDERSPECIFIED (CC 8.1 deferral)
  - needs-human-review: cross-replica aggregation into a federation-wide health composite neither forbidden nor permitted - explicit ruling recommended

### `fidelity:explainability_sla:{tier}`

- CC 3.1.5.2 · owner CIRISAgent/accord-agent · superset-class: CommitmentSLA · polarity signed · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 4 · placement fields: 4
- Required primitives: typed committed/achieved enum comparator at admission (currently would ride untyped extra); NodeCore composition deriving hard_case:sla_breach_unattested (composed emission, not a producer base op)
- Forbidden: windowed/aggregate self-report wire shape for THIS dimension (rollups belong to a distinct downstream dimension); open free-text SLA terms in place of the closed enum; corpus-wide aggregation into a rolling reputation figure (per-response, not track-record)
- Deltas from seed (7): envelope WRONG: constitution fixes {committed_tier, achieved_tier, fallback_reason?}; drop sla_terms/latency/coverage/window/rate/breach_count ...
- **Flags:**
  - needs-human-review: exact hard_case trigger predicate (achieved<committed alone vs also missing fallback_reason)
  - needs-human-review: subject_key_ids behavior unaddressed by text
  - needs-human-review: cohort_scope defaults ungrounded (constitution-silent)
  - no cc_impl rows exist - all processors proposed

### `fidelity:{aspect}`

- CC 3.1.5.2 · owner CIRISAgent/accord-agent · superset-class: SelfAssertedQualityClaim · polarity signed · reserved=False
- CI axes: sender=default, data_subject=default, recipient_see=default, info_type=family_specific, temporal=default
- Invariants: 3 · placement fields: 2
- Required primitives: scores signed with 4.4.2 default mean (no bespoke aggregator); generic 2.4.1 composers unmodified; self-emission permitted (no capacity-style ban) - open on witness_relation
- Deltas from seed (6): actor human_authored/ProducerSteward unsupported: this sits in the agent's own M-1 reasoning-verdict surface; emitter open ...
- **Flags:**
  - constitution-silent: only prefix+description+polarity exist for fidelity:{aspect} itself - thin invariants are the honest reading
  - needs-human-review: does a self-emitted (witness_relation:self) honesty self-grade need a downweight safeguard analogous to CC 4.4.1's testimonial caveat? Goodhart vector unresolved

### `goal:{scale}`

- CC 3.1.9.7 · owner CIRISNodeCore/node · superset-class: MultiScaleCompositeGauge · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 6 · placement fields: 7
- Required primitives: type-enforced MetaGoalAlignment-on-construction (matches shipped Goal::new); paired single-signer declare/retire lifecycle with consumer-side signer-match (edge is reach, not gate); upward-only DAG anchoring via goal_id for approach/method/progress_measure; durable+requires_ack transport for both lifecycle halves
- Deltas from seed (10): seed's 7-value {scale} enum is CORRECT against CC 2.5 + shipped cohort_scope code; CC 3.1.9.7's own row text (planet, no federation) is the outlier - erratum, do not 'fix' the seed to match it ...
- **Flags:**
  - needs-human-review: 'Scored by composite' has no implementing composer - aspirational
  - needs-human-review: CC 3.1.9.7 literal scale enum conflicts with canonical CC 2.5 Scope vocabulary (constitution drafting error; seed already correct)
  - needs-human-review: no evidence any 7-tier goal:{scale} scores attestation is ever emitted; only the 3-value GoalScope + M1 alignment primitive ships - seed's composite-gauge card matches nothing implemented
  - needs-human-review: consumer-side declared_by/retired_by consistency gate not found in vendored lens-core - confirm where it lands

### `hard_case:{kind}`

- CC 3.1.9.4 · owner CIRISNodeCore/node · superset-class: OpenVocabEvidenceCard · polarity positive-only · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 7 · placement fields: 5
- Required primitives: substrate-observed idempotent emit (internal reconciliation write keyed (kind,target,window)); reserved-emitter admission gate for signed federation-plane crossings; subject-bearing enforcement for keyed kinds; never-silent mandatory emission at named transitions; downstream detection-composition boundary (LensCore composes ON TOP; composition itself out of family)
- Forbidden: aggregate (never re-scored into a composite within its own prefix); any slashing-trigger input (not merely sole); producer self-emission on the 9 reserved kinds; withdraw/supersede/recant against a HardCaseEvent row (append-only idempotent log)
- Deltas from seed (10): semantic inversion: not a producer success-narrative - a violation/breach/exclusion observability flag; positive-only = occurred, not positive sentiment ...
- **Flags:**
  - needs-human-review: spec-vs-implementation kind-list drift (partial overlap; 2 persist kinds absent from constitution)
  - needs-human-review: admission-gate coverage gap - hard_case: absent from live scores-dimension reserved rules
  - needs-human-review: two code-documented Upstream-ask gaps where MUST-emit hard_cases are computed but never durably recorded (named.rs, watchlist.rs)
  - constitution-silent: no registry doc exists despite being the named model
  - seed-wrong-archetype: signed federatable human Contribution vs unsigned unfederated persist-local reconciliation log row

### `hardware_custody:{platform}`

- CC 3.1.2 · owner CIRISVerify/attestation · superset-class: ScoredCapabilityBadge · polarity boolean-via-score · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 7
- Required primitives: self-measured boolean-via-score attestation at hardware-challenge time; supersede-on-custody-change (mirrors identity_occurrence KEM rotation); withdraw (prudent retraction); explicit cohort_scope pinning at emission; evidence cross-reference into identity_occurrence.hardware_attestation
- Forbidden: aggregate/average across platforms/occurrences into a continuous score (0.0/1.0 only); recant for tier transitions; L-number smuggled into the dimension/claim; sole input to any capacity composite (category error)
- Deltas from seed (8): custody_score continuous 0-1 WRONG: strict PASS(1.0)/FAIL(0.0); graded weighting belongs to separately-composed consumer policy ...
- **Flags:**
  - needs-human-review: cohort_scope unset at emission would silently leak a security-sensitive signal federation-wide once wired into the server path
  - needs-human-review: decide whether an admission-time attesting==attested rule should be added (inverse of the capacity gate)
  - constitution-silent: no canonical-bytes contract, evidence shape, or self-emission rule specified for this family (unlike skill_import/locale_manifest)

### `health:liveness:{version}`

- CC 3.1.9.4 · owner CIRISNodeCore/node · superset-class: TelemetrySample · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 6 · placement fields: 6
- Required primitives: scores emission (generic workhorse); attester-not-target gate for health:liveness: (missing); epistemic_mode {direct,derivative} constraint (missing); evidence_refs SHA-verified blob carry (existing generic); consent:replication bidirectional check for out-of-group (existing in peer.rs)
- Forbidden: new EnvelopeCore/superset fields for probe detail; standalone attestation naming non-keyed infra; self-emission / witness_relation:self; emission under reserved system:*
- Deltas from seed (9): TelemetrySample archetype wrong: fold riding scores, external-witness subclass - not a bespoke telemetry envelope ...
- **Flags:**
  - needs-human-review: missing admission self-emission gate + epistemic_mode constraint - file against CIRISPersist
  - constitution-silent: no literal default cohort_scope; delegates_to meaningfulness; observed-target revoke authority (inferred by analogy)
  - seed-wrong-archetype: TelemetrySample bespoke envelope vs rides-scores fold

### `holds_bytes:sha256:{prefix}`

- CC 3.1.9.1 · owner CIRISNodeCore/node · superset-class: provenance_custody_receipt · polarity boolean-via-score · reserved=False
- CI axes: sender=family_specific, data_subject=not_applicable, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 8 · placement fields: 6
- Required primitives: cohort-scope-gated emit (3-way dispatch); holder-directory TTL filter (24h); third-party content-miss withdraw; cascading holder-eviction withdraw on upstream revocation; full-SHA verify before consume; scope-widen rehash tripwire
- Forbidden: aggregate (per-holder pointer set, never a weighted composite); emit for self/family scope; second holder directory; prefix-only trust; unverified holder claims affecting retention priority
- Deltas from seed (7): typical scope NOT self - self/family is hard non-emission; every existing row is community-or-wider ...
- **Flags:**
  - needs-human-review: evidence_refs NOT a typed EnvelopeCore field despite carrying the CC 5.3.2.5 MUST-verify obligation - functional via scattered .get() but compiler-invisible; strong hoist candidate
  - needs-human-review: perceptual-hash tripwire hook shipped but matcher not installed (fails closed, acknowledged gap)
  - constitution-silent: pin_status/GC lifecycle + supersede semantics corrected against code contract, not CC text - reviewer confirm intended reading

### `identity_continuity:relational_anchor`

- CC 3.1.3 · owner CIRISPersist/persist · superset-class: SelfContinuityAttestation · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 7
- Required primitives: self-attestation gated on substrate_persist identity_type (enforced); steward-triple cross-attestation upstream at key registration; supersedes (fold-merge/rotation revision); recants (fork-correction falsity admission - corrected from seed); cohort_scope:federation so peers can cross-check against the trust root
- Forbidden: delegates_to reassigning emit authority; non-substrate_persist emission; naive cross-instance aggregate via the signed-mean default (distinct non-fungible continuants; category error - constitution-silent inference, flagged)
- Deltas from seed (5): cohort_scope corrected self/SelfOwn -> federation (Commons world-readable): sibling purpose + infra precedent + persist default; seed also self-contradicted its own strip restriction ...
- **Flags:**
  - needs-human-review: the self->federation scope correction is load-bearing routing - confirm before build targets ship
  - constitution-silent: no explicit anti-aggregation rule across substrate instances (inferred category error, not quoted)
  - constitution-silent: all superset fields are proposals (UNDERSPECIFIED/CC 8.1 deferral)

### `integrity:{aspect}`

- CC 3.1.5.2 · owner CIRISAgent/accord-agent · superset-class: AttestationWithEvidenceChain · polarity signed · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=default
- Invariants: 10 · placement fields: 3
- Required primitives: evidence_refs-based ordered non-dangling evidence chain (usage discipline, not a new field); standard structural supersede/withdraw/recant; open-vocab aspect registry lookup (4.5.1.1); default signed-mean aggregation (inherited)
- Forbidden: act_ref via references_attestation_id; sub-envelope recipient_capability-tiered field stripping as a wire primitive (no such mechanism; visibility is whole-envelope cohort_scope); {aspect}=finitude_acknowledgment; subsuming fidelity:explainability_sla's tier machinery
- Deltas from seed (9): drop bespoke act_ref/reasoning_trace_ref fields -> generic evidence_refs + resolvability CHECK ...
- **Flags:**
  - constitution-silent: witness_relation self-trust vs generic discount unreconciled
  - constitution-silent: no aspect registry exists; new values ungoverned open text today

### `judge_model:verdict:{model_id}`

- CC 3.1.9.4 · owner CIRISNodeCore/node · superset-class: ScoredVerdictCard · polarity boolean-via-score · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 6 · placement fields: 5
- Required primitives: scores emit (boolean-via-score); supersedes; withdraws (producer-self rule 1 as the intended revoke path); Min-fold aggregation (implemented generically in persist resolve_scores; gated on the server polarity registry mapping which is missing)
- Deltas from seed (7): recant:false mischaracterized as wire-forbidden - universal composer, attester-available; card-only choice ...
- **Flags:**
  - needs-human-review: revoke asymmetry is a derived composition of two rules, not a stated family rule
  - needs-human-review: target_ref/judge_run_at hoist vs documented convention is a design decision
  - constitution-silent: 4.5.1.1 does not clearly bind {model_id} (identity label, not detector axis)

### `justice:{aspect}`

- CC 3.1.5.2 · owner CIRISAgent/accord-agent · superset-class: EquityAssessmentCard · polarity signed · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=default
- Invariants: 6 · placement fields: 6
- Required primitives: mean aggregation (signed, 4.4.2); supersede chain (remediation closes disparity); open-vocab admission guard
- Forbidden: aggregate-as-detector-verdict (median, detector-gated); lenscore_detector-gated emission; mandatory subject_key_ids pattern-forced hoist
- Deltas from seed (5): aspect must NOT be a closed enum - documentation-only open path ...
- **Flags:**
  - constitution-silent: no justice-specific aggregation override or Frickerian carve-out
  - constitution-silent/needs-human-review: no never-sole-slashing-evidence rule for justice despite single-producer subjective shape - amendment-worthy
  - needs-human-review: 4.5.1.1 generalization to {aspect} is structural analogy, not literal enumeration - maintainer confirm

### `key_boundary:{scope}` · **NO ROUND-1 SEED (round-2-first)**

- CC 3.1.4 · owner CIRISPersist/persist
- CI axes: sender=family_specific, data_subject=not_applicable, recipient_see=family_specific, info_type=family_specific, temporal=default
- Invariants: 5 · placement fields: 6
- Required primitives: reserved-emitter admission (substrate_edge, steward-triple); axis-vocabulary documented-convention gate for {scope}; open-vocab collision guard for sub-identifiers
- Forbidden: emission by keys lacking substrate_edge membership; external-observer/third-party emission under this prefix
- Deltas from seed (1): No round-1 seed existed (flagged_no_superset_spec) - from-scratch analysis.
- **Flags:**
  - constitution-silent: CC 8.1.3 cites a nonexistent 'sec.3.4 D26 ext' (dangling ref); resolved in practice by CIRISEdge key_boundary.rs - recommend constitutional inlining
  - needs-human-review: cohort_scope default reasoned from the recipient_excluded analogy, not stated
  - CONCRETE BLOCKING GAP: substrate_edge identity_type absent from persist and zero reserved rules for ALL four CC 3.1.4 CIRISEdge leaves - any key can emit key_boundary rows today (file against CIRISPersist)
  - edge wire mechanism itself v0.16.0 wire-only: scope-binding enforcement deferred to unbuilt v0.16.1+/CIRISVerify

### `licensure:{authority_id}`

- CC 3.1.1 · owner CIRISRegistry/registry · superset-class: badge_of_record · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 6 · placement fields: 7
- Required primitives: scores (signed, mean aggregation); supersedes (status transitions, issuer-driven); withdraws (producer-only default; subject-side only if explicitly listed); recants (attester-only self-correction); independent dual-attester confidence-cap composition (licensure_cap pattern); sibling revocation:license:{reason} for the revocation event
- Forbidden: joint/dual-signature single envelope (co_signers field) as the emission mechanism; new typed status/revocation envelope fields (4.1.2/4.1.3); admission-time exclusive emitter gate for licensure:*; folding a trust/ladder meta-judgment into the prefix
- Deltas from seed (8): MAJOR: dual-co-signature-required emission model WRONG - two independent attestations + consumer confidence cap (shipped licensure_cap), both co-steward INSTITUTIONS (not just 2 keys) needed to exceed ...
- **Flags:**
  - needs-human-review: rule-2 tension - explicitly-listed practitioner could withdraw a co-steward's adverse factual claim (no CC carve-out); flag before the named-practitioner form is implemented
  - needs-human-review: score-value-to-status mapping genuinely underspecified
  - needs-human-review: revocation:license composition gap in compose_policy polarity table
  - needs-human-review: 4.5.2.1 admission enforcement for subject-bearing forms unimplemented (cc_impl open)

### `locality:decision:{scale}`

- CC 3.1.9.5 · owner CIRISNodeCore/node · superset-class: EnumeratedTagCard · polarity enumerated · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 6
- Required primitives: locality-scaled quorum lookup (never fixed N); sub-quorum fallback router (3 mutually-exclusive explicit paths); hard_case co-emission on every fallback path; locality-mismatch admission check (cell_pool >= min_pool); supersedes (scale-down realization)
- Forbidden: aggregate (concurrent conflicting claims resolve most-recent-wins in the reference composer, not vote/average - implementation discipline, flagged as such); sole-input-to-slashing (bare locality claim never authorizes an outcome; it only sizes the quorum); silent scale-reinterpretation (ratified-at-one-scale treated as another without explicit supersedes)
- Deltas from seed (7): enum corrected: 4 values (local/regional/national/federation), not the seed's 6 (individual/node/cluster/community/regional/federation-wide) ...
- **Flags:**
  - needs-human-review: evidence-registry misattribution (cc_impl.tsv:61 maps 4.4.3.1.1 to the accord kill-switch quorum)
  - needs-human-review: zero enforcement wiring in CIRISServer until the Server-1.0 node-slice fold-in - quorum decisions cannot be locality-scaled today
  - needs-human-review: cohort_scope-vs-{scale} consistency requirement is inference, confirm before hard admission gate

### `manifold_conformity:{cohort}` · **NO ROUND-1 SEED (round-2-first)**

- CC 3.1.8 · owner CIRISPersist/persist
- CI axes: sender=default, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=default
- Invariants: 5 · placement fields: 5
- Required primitives: scores-emission (signed [-1,+1] on dimension manifold_conformity:{cohort}) - the entire missing realization
- Forbidden: sole/direct punitive-authority input absent WA quorum (P8); standing as a self-sufficient verdict
- **Flags:**
  - no round-1 seed existed - full from-scratch analysis
  - constitution-silent/doc-stale: operational definition claimed absent while a real versioned calibration package ships - Part 3/FSD-005 need citation updates
  - needs-human-review: no CC 3.4 reserved-emitter rule (unlike both siblings) - deliberate open-emit or unaddressed anti-Goodhart gap?
  - needs-human-review (HIGH): NO wire realization - family never reaches federation_attestations; rides the pipeline constitutionally reserved to detection:* (possible 10th dark family; relayed to audit-ceg-replication and hunt-split-truth)
  - seed-wrong-archetype risk noted: family is NOT detector-reserved per text even though the shipped shape treats it that way - do not import the 3.4.8 gate without amendment

### `method:{approach_id}:{substrate_rung}`

- CC 3.1.9.7 · owner CIRISNodeCore/node · superset-class: DimensionedPracticeClaim · polarity signed · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 3 · placement fields: 2
- Required primitives: chain-of-custody parent validation (approach_id -> existing non-withdrawn approach); bounded substrate_rung enum admission (namespace-distinct from oversight A0-A4); supersede as primary transition + standard withdraws/recants
- Forbidden: aggregate (no multi-attester rollup exists or is implied); sole/disagreement-triggered slashing input
- Deltas from seed (9): substrate_rung enum WRONG: seed invented rung0-3 tooling tiers; actual = Ph0/Ph1/Ph2/A0-A5 with the CC-flagged oversight-letter collision ...
- **Flags:**
  - constitution-silent: zero part_4 composition text for this family
  - needs-human-review: extend references_attestation_id as the DAG chain carrier vs opaque dimension substrings with no verification
  - needs-human-review: no substrate_rung enum validator exists (letter-collision live risk)

### `moderation:{allegation_type}`

- CC 3.1.9.2 · owner CIRISNodeCore/node · superset-class: Incident-report card · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=default, temporal=family_specific
- Invariants: 6 · placement fields: 4
- Required primitives: delegated-duty admission gate (CC 4.5.5); community-keyed duty-holder resolution; merit-auto-promotion fallback (CC 4.5.4); separate quorum-slashing composer (feeds, never alone triggers); review/reconsideration appeal path
- Forbidden: aggregate (discrete accusation, never averaged into an automatic verdict); sole slashing evidence (filing alone or advisory signals); on_behalf_of-style self-declared principal field
- Deltas from seed (10): ARCHETYPE WRONG: not generic content-abuse incident reporting - federation GOVERNANCE-INTEGRITY accusation against a contributor (canonical enum: rogue_vote/coordinated_voting/out_of_distribution_atte ...
- **Flags:**
  - needs-human-review: accused (subject_key_ids) can self-admit a withdraws against the filing under shipped generic rule 2 - no carve-out; constitution silent
  - constitution-silent: no family override for subject-initiated withdraws or a deletion window
  - seed-wrong-archetype: content-moderation incident card vs governance-integrity accusation (server FSD flags the open design question)
  - needs-human-review: cohort_scope SELF hardcode + immediate federation promotion interaction unresolved (holds_bytes-only surface vs visibility control)

### `moderation_track_record:{community_key_id}`

- CC 3.1.9.2 · owner CIRISNodeCore/node · superset-class: ScoreDial · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=default, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 6 · placement fields: 4
- Required primitives: deterministic fold over the named 4-family corpus; existence-gate admission + federation-apply reconcile over the resulting appointment (implemented); fail-secure eligibility gate (sufficiency + consent + steward-binding) before promote-with-full-placement of the duty; community-uniform window policy
- Forbidden: cross-community/global aggregation; self-assertion by the data subject; subject-side revocation of their own record; sole/unconditional appointment input without the rule-3 gate; merit computation inside persist itself (explicitly disclaimed)
- Deltas from seed (8): actor:mixed misleading - deterministic composer emission (peer-reproducibility requirement) ...
- **Flags:**
  - needs-human-review: zero implementation footprint - comparator, fold, and typed envelope all greenfield
  - constitution-silent: exact compositing formula/weights + the numeric sufficiency threshold (honest empty, not invented)
  - schema note: owning NodeCore mapped to server as closest proxy in the placement matrix

### `multilateral_participation:{forum}:{kind}`

- CC 3.1.1 · owner CIRISRegistry/registry · superset-class: ParticipationDepthCard · polarity signed · reserved=False
- CI axes: sender=default, data_subject=default, recipient_see=family_specific, info_type=family_specific, temporal=default
- Invariants: 4 · placement fields: 4
- Required primitives: promote-with-full-placement (cohort_scope + resolvable target so {forum} roster-gates recipient_see); standard 1+4 lifecycle (general-purpose, sufficient)
- Deltas from seed (7): {kind} enum WRONG (member/delegate/observer/contributor/lurker/convener invented); real closed 4-facet set - up to 4 independent gauges per forum, not one depth gauge ...
- **Flags:**
  - seed-wrong-archetype: single role-ladder depth gauge vs 4 independent closed-enum facets (changes card/UI shape)
  - needs-human-review: affiliations enforcement gap (no target typing, no affiliation_key_ids, no-op AFFILIATIONS arm) is a cross-family persist substrate gap this family depends on
  - constitution-silent: staleness/activity-window, cross-facet aggregation, family consent grants - all honest empties

### `need:{domain}:{kind}`

- CC 3.1.9.3 · owner CIRISNodeCore/node · superset-class: OpenCallCard · polarity positive-only · reserved=False
- CI axes: sender=default, data_subject=not_applicable, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 3 · placement fields: 5
- Required primitives: supersede-to-revise; withdraw-to-satisfy-or-close; recant-to-retract-misstatement; evidence/references linkage to the target Contribution (conceptually required, not yet admission-enforced)
- Forbidden: aggregate/weighted-composite scoring on need:; negative-polarity emission (-1 unmet); substituting for deferral_request cell routing
- Deltas from seed (9): MAJOR seed-wrong-archetype: mutual-aid/crisis marketplace (need:medical:blood_o_neg, urgency/quantity/contact) contradicts the canonical {kind} enum - this is help-wanted for getting a Contribution th ...
- **Flags:**
  - needs-human-review: should references_attestation_id be admission-REQUIRED (linkage implied, requiredness unstated)
  - needs-human-review: no cc_impl rows for need: anywhere - all processors greenfield
  - needs-human-review: no WITNESS_KIND_REGISTRY-equivalent for need:{kind}
  - needs-human-review: card_category rename (Capacity collision)
  - constitution-silent: no aggregation-forbidden/evidentiary-weight rule stated for need: itself (genuinely empty)

### `non_maleficence:{aspect}`

- CC 3.1.5.2 · owner CIRISAgent/accord-agent · superset-class: ScoredAspectClaim · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=default
- Invariants: 6 · placement fields: 4
- Required primitives: signed-graded attestation (mean of score x confidence); apophatic floor-on-match per-row constraint (score==-1.0 exactly); Frickerian-exempt weighting (never partner-longevity downweight); self-track-record discount BEFORE the Frickerian exemption
- Forbidden: downweight-by-partner-track-record; self-report as sole conclusive standing; treating this family's floor as the network-wide non-overridable safety gate (prohibited:*'s role)
- Deltas from seed (8): prohibited_category_ref REMOVED - belongs to the pairing relationship with the separate prohibited:{category} sibling, not a field here ...
- **Flags:**
  - needs-human-review: no wire-level join key between a non_maleficence row and its paired prohibited:* row (both KN:MED acknowledged underspecification)
  - constitution-silent: {aspect} vocabulary has no canonical enumeration

### `partner_role:{role}`

- CC 3.1.1 · owner CIRISRegistry/registry · superset-class: RoleAssignmentCard · polarity enumerated · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 5
- Required primitives: promote-with-full-placement (tier change via supersedes); enumerated most-recent-wins composition (no averaging); cross-dimension join with licensure for PROFESSIONAL_* (partially implemented); cross-dimension join with revocation:partner + bond forfeiture (partially implemented; bond leg stubbed); documented open-vocab convention for roles beyond the six (missing)
- Forbidden: mean composition across attesters; partner_role longevity as a non_maleficence downweight input; single-source licensure at full confidence paired with a PROFESSIONAL_* tier; un-revoking a revocation:partner entry (non-rollbackable)
- Deltas from seed (7): archetype WRONG: not a human-authored counterparty-relationship card (partner_identity_ref/reciprocal_ack_ref have no support) - a SELF-held Registry/community-issued credential badge on an agent/org  ...
- **Flags:**
  - constitution-silent: full field superset deferred by CC itself (8.3.6 workshop item)
  - seed-wrong-archetype: private counterparty-relationship card vs self-held credential - second look before locking fields
  - needs-human-review (given the archetype mismatch)
  - gap: Registry partner endpoint always returns bond_posted=None (forfeiture invariant unwired)
  - gap: no DIM_PARTNER_ROLE in compose_policy - handled only ad hoc in the Registry endpoint

### `peer_reachability:{network}`

- CC 3.1.4 · owner CIRISEdge/transport-delivery · superset-class: gauge_liveness_card · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 5
- Required primitives: reserved substrate-self-report emission (substrate_edge + steward-triple); network-scoped aggregate rollup construction (ephemeral counters -> one persisted per-network score); supersede-based rolling update
- Forbidden: per-peer/per-tenant templated dimension leaf; sourcing the push fan_out computation from this attestation; delegated emission via delegates_to; recant on a live gauge reading (supersede instead)
- Deltas from seed (7): seed modeled a PER-PEER claim (peer_node_id required field) - CC 8.1.3 collapses per-peer into the network aggregate (code-confirmed); DROP peer_node_id entirely ...
- **Flags:**
  - needs-human-review: cohort_scope unpinned (UNDERSPECIFIED)
  - needs-human-review: substrate_edge admission gate unimplemented for transport/delivery/peer_reachability/key_boundary - file persist issue before this family is compile/admission-safe
  - needs-human-review: exact ratio-to-score transform (declared signed [-1,+1] vs [0,1] ratio) unpinned anywhere

### `progress_measure:{method_id}`

- CC 3.1.9.7 · owner CIRISNodeCore/node · superset-class: score_dial · polarity signed · reserved=False
- CI axes: sender=default, data_subject=not_applicable, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 6
- Required primitives: emit-time completeness gate (four required typed fields); DAG chain resolution (method_id -> method -> approach -> goal); scale-inherited cohort_scope projection
- Deltas from seed (6): PRIMARY DEFECT: seed omits ALL FOUR constitutionally REQUIRED fields and invents a KPI-gauge schema (metric/baseline/target/unit/confidence) ...
- **Flags:**
  - constitution-silent-beyond-registry-line: no part_4 composition rule (grep-confirmed)
  - seed-wrong-archetype: KPI/gauge card vs DAG-anchored calibration-package attestation
  - needs-human-review: recipient_capability vocabulary unattested

### `prohibited:{category}`

- CC 3.1.5.4 · owner CIRISAgent/accord-agent · superset-class: CategoricalRefusalEvidence · polarity -1 / -0.5 only · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=default
- Invariants: 7 · placement fields: 6
- Required primitives: fail-secure MIN aggregation per (dimension,subject), non-overridable (implemented); closed-enum {category} admission validation vs the 22-leaf vocabulary, version-pinned (unbuilt); score-range admission validation {-1,-0.5} (unbuilt); hash-only/raw-strip evidence discipline; render-tier universal safety-gate re-check per request; delegates_to scope composer excluding PROTECTED_NON_TRANSFERABLE domains
- Forbidden: Frickerian non-downweight treatment (this family gets the OPPOSITE composition: fail-secure MIN); raw prohibited-adjacent payload replication at federation scope; sole reliance on the self-report as compliance/DPIA evidence; consent grants overriding/cancelling/softening the floor score; delegation of the attestation or of any scope touching the protected domains
- Deltas from seed (7): seed's example categories (CSAM, bioweapons_synthesis) are NOT among the real 22 leaves; CSAM is explicitly routed OUTSIDE this family to the hard-delete class; family spans domain-restriction refusal ...
- **Flags:**
  - needs-human-review: 1:1 mapping between the 6 PROTECTED_NON_TRANSFERABLE domains and specific leaves of the 22-category enum asserted but never spelled out
  - needs-human-review: whether SELF-revocation (withdraw/recant) of one's own prohibited trip record should be restricted - default subject semantics apply by omission
  - implementation-state: family unimplemented beyond aggregation routing (grep: prohibited only in compose_policy + one unit test using the non-real leaf 'weapons'); no admission validators, no card, no endpoint; zero cc_impl rows

### `provenance:build_manifest:{target}`

- CC 3.1.2 · owner CIRISVerify/attestation · superset-class: HashEqualityAttestation · polarity boolean-via-score · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=default
- Invariants: 5 · placement fields: 1
- Required primitives: signed boolean-via-score emit (per-primitive steward hybrid-signed); supersedes (rebuild/release rotation); recants (falsely-attested/compromised build); min-aggregate composition; consumer-side pinned-trust gate (no CC 3.4 reservation exists)
- Forbidden: ladder-composition (Policy I - sibling, not a rung); mean/average aggregation for the same target; third-party revoke via withdraws rules 2/3; assuming substrate reserved-prefix rejection of non-steward emitters
- Deltas from seed (5): {target} grammar ambiguity: CC 5.3.5 shows THREE segments {project}/{version}/{target}, implying {target} = platform/build-target string scoped within a project+version, not the project/component name ...
- **Flags:**
  - needs-human-review: {target} grammar (component name vs platform/build-target string) - CC 5.3.5 three-segment endpoint suggests the seed's enumerated-target restriction is wrong-scoped
  - needs-human-review: whether Annex G G-KPI-7 hard-block extends to this prefix or is scoped only to SLSA-3 model/guardrail artifacts
  - constitution-silent: no consent transmission-principle; no deletion_window/SLA analog
  - no existing processor: cc_impl.tsv marks 3.1.2.1 open - all placements proposed

### `provenance:build_manifest:{target}:locale:{lang_code}`

- CC 3.1.2 · owner CIRISVerify/attestation · superset-class: proof_chain · polarity boolean-via-score · reserved=False
- CI axes: sender=family_specific, data_subject=not_applicable, recipient_see=family_specific, info_type=default, temporal=family_specific
- Invariants: 3 · placement fields: 6
- Required primitives: merkle-leaf-emit (v2 JCS domain-separated - not implemented at v10.6.3); merkle-inclusion-verify (leaf + sibling path -> recomputed root == parent manifest_hash; implemented as verify_locale_inclusion); canonical locale-ordering + pow2-padding upstream of root composition (currently caller-trusted); per-locale-granularity-preserving compose/render
- Forbidden: non-v2 ad-hoc concatenation leaf preimage going forward; collapsing per-locale verdicts into a single blended score discarding which lang_code diverged (inferred, flagged)
- Deltas from seed (7): manifest_hash -> the real wire field source_ref on AttestationEntry (Option, not required - can be legally absent though it's the only leaf content-address on the wire) ...
- **Flags:**
  - needs-human-review: v10.6.3 emits v1 while CC 3.1.2.1 mandates v2 (live drift, not doc lag; test pins the wrong bytes)
  - needs-human-review: files_root/build_id never persisted - third-party re-verification impossible from the record alone; source_ref is Option, not required
  - needs-human-review: locale ordering + padding caller-trusted, unenforced; production sign tool doesn't call the module
  - needs-human-review: per-locale-granularity-preservation is inference from purpose text + code comment, not an RFC-2119 rule

### `provenance:skill_import:{source}`

- CC 3.1.2 · owner CIRISVerify/attestation · superset-class: provenance:import_record · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 6 · placement fields: 7
- Required primitives: signed-polarity graded composition (mean of score x confidence, not boolean); hybrid-signature admission verification against the exact JCS v2 preimage; source-type-keyed trusted-pubkey selection as an explicit consumer-policy step; a downstream trust-verdict composer citing this as evidence (never the verdict itself)
- Forbidden: aggregating as boolean-via-score/min (contradicts signed polarity); rendering/consuming directly as a trust/safety verdict (4.1.3); treating as reserved/witness-gated at emission (no CC 3.4 reservation)
- Deltas from seed (9): OMITS import_timestamp (REQUIRED signed preimage field + temporal anchor) ...
- **Flags:**
  - needs-human-review: v10.6.3 treats skill_import as boolean-via-score in code, contradicting CC 3.1.2's `signed` polarity (the one provenance dimension deliberately different, flattened back)
  - needs-human-review: shipped domain is v1 concat vs normative v2 JCS (cc_impl 3.1.2.1 open, no resolved v2 impl)
  - needs-human-review: attester==signer_identity binding never checked; FFI doesn't call to_attestation_entries at all
  - constitution-silent: no CC 4.4.3.x skill_import trust-composition policy despite KN:HIGH framing

### `provenance:slsa:{level}`

- CC 3.1.2 · owner CIRISVerify/attestation · superset-class: ScoredCapabilityBadge · polarity boolean-via-score · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 6
- Required primitives: open self-report per-level boolean-via-score emit (no emitter gate); supersede (level corrections/upgrades); withdraw / recant; consumer-side max-composition across same-key emissions (slsa_level = max over is_pass()); paired labor-provenance package at emit(level=3) for training/model-build artifacts (Annex G/TX-11)
- Forbidden: aggregate across DIFFERENT artifact_digests into one score; fold into ladder_verdict()/L1-L5; admission-time emitter-identity/reserved-prefix gating absent new CC 3.4 ratification; per-field capability-gated redaction (strip_field) at read/serve time; emit level=3 for a training artifact without a paired hash-checked labor-provenance.json
- Deltas from seed (8): emit_authority: Registry (build registration) is canonical emitter; Verify COMPOSES/surfaces, does not emit - but emission is open/non-reserved, any key MAY self-assert ...
- **Flags:**
  - needs-human-review: provenance:slsa:{level} would fail persist's default T3 admission gate (missing :vN, absent from ATTESTATION_LADDER_MECHANISMS)
  - needs-human-review: whether Annex G G-KPI-7 hard-block scopes to this prefix or only to SLSA-3 model/guardrail artifacts as CC binds it - determines whether level<1.0 is a hard block or advisory
  - implementation-gap: artifact_digest/builder_id/source_repo/labor_provenance_ref absent from ProvenanceBlock/AttestBundle - seed superset aspirational
  - needs-human-review: recipient_see Commons vs affiliations unconfirmed

### `ratchet:flag:coordinated_voting_cluster`

- CC 3.1.6 · owner RATCHET/anti-sybil · superset-class: ClusterDetectionFlag · polarity signed · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 4 · placement fields: 5
- Required primitives: flag-emit (open/self-asserted signed claim); supersede-with-cluster-continuity (cluster_id + references_attestation_id); recant (false-positive admission by original attester); withdraw (producer-only retraction); median-aggregate composer (CC 4.4.2); advisory-routing to NodeCore moderation:coordinated_voting flow (never a direct ledger mutation)
- Forbidden: aggregate-as-sole-slashing-evidence; mean-aggregation (must be median); subject-granted revoke (member_refs/subject_key_ids that would arm the accused); auto-enforcement wiring (flag emission never mutates ledger/routing)
- Deltas from seed (6): ADDED the missing load-bearing invariant: member_refs must never enter subject_key_ids (rule 2 self-revocation vulnerability the seed's single-field design would enable) ...
- **Flags:**
  - needs-human-review: member_refs visibility tiering is seed convention, not CC text - confirm against RATCHET/FSD.md (external repo, not in checkout)
  - needs-human-review: whether cluster_id/observation_window warrant typed hoisting vs extra (carried-but-unprocessed in extra reproduces the target defect class)

### `ratchet:flag:counter_rii:{layer}`

- CC 3.1.6 · owner RATCHET/anti-sybil · superset-class: LayeredCounterFlagCard · polarity signed · reserved=False
- CI axes: sender=default, data_subject=default, recipient_see=family_specific, info_type=family_specific, temporal=default
- Invariants: 6 · placement fields: 4
- Required primitives: median-aggregate over the detector dimension (Polarity::Detector - shipped); slashing-composer sole-evidence screen covering ratchet:flag:* (MISSING); Peer-consent_role-exemption gate (subject-side, counter_rii-specific); calibration-package axis-pin (4.5.1.1)
- Forbidden: sole-input-to-slashing-composer; autonomous ledger mutation; mean/max/min aggregation (must be median); reserved-emitter admission gate (unreserved family)
- Deltas from seed (6): actor auto_emitted/emit_authority ProducerSteward overclaim an enforced restriction - family is open (reserved:false, absent from CC 3.4); RATCHET is operational-not-enforced producer ...
- **Flags:**
  - needs-human-review: CC 3.1.6 sole-evidence screen not implemented for ratchet:flag:* in compose_policy.rs (only testimonial) - file CIRISServer issue
  - constitution-silent: no textual cohort_scope/projection default

### `ratchet:flag:density_anomaly`

- CC 3.1.6 · owner RATCHET/anti-sybil · superset-class: ScoredSignalCard · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=default
- Invariants: 5 · placement fields: 6
- Required primitives: signed scores composed via median-across-attesters (CC 4.4.2); WA-quorum-gated slashing treating this as corroborating-only (CC 3.1.6/T4); evidence_refs-pinned detector/calibration version (T3)
- Forbidden: treating density_anomaly as sole slashing input; identity_type-gated admission restriction specific to this prefix (needs CC 4.5.1 amendment); default-granting subject_key_ids/revoke to the flagged attested_key_id
- Deltas from seed (8): dropped the emitter reservation (only RATCHET may write density_score...); density_anomaly absent from CC 3.4, reserved:false - any key may emit ...
- **Flags:**
  - needs-human-review: subject_key_ids self-suppression default derived from base defaults + detector purpose, not quoted
  - needs-human-review: raw_neighbor_ids introduces undeclared third-party data subjects with no consent capture and ambiguous self/family scope
  - constitution-silent: 4.5.1.1 calibration MANDATE binds open {axis}, not this fixed leaf - detector_version rides evidence_refs on the general T3 gate, weaker grounding

### `ratchet:flag:expertise_attestation_anomaly`

- CC 3.1.6 · owner RATCHET/anti-sybil · superset-class: AnomalyFlagCard · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=default, temporal=default
- Invariants: 6 · placement fields: 6
- Required primitives: median-aggregation for this detector dimension (implemented); advisory-only emission (no autonomous mutation); slashing sole-evidence screen mirroring testimonial (required by CC 3.1.6, not implemented); structural recant/supersedes for false-positive clearing (reuse composer, no new field)
- Forbidden: mean aggregation; sole evidence for slashing; attested_key_id present in its own subject_key_ids; delegate (no CC-granted delegation for this family); autonomous ledger side effect from emission
- Deltas from seed (8): REMOVE detector_identity_ref (duplicates attesting_key_id; CC 3.4.8 no-envelope-field-discriminator applies by analogy) ...
- **Flags:**
  - needs-human-review: no reserved-emitter/identity_type gate for ratchet:flag:* (asymmetric with detection:* CC 3.4.8) - intentional or amendment gap?
  - needs-human-review: CC 3.1.6 sole-evidence-for-slashing rule unenforced for ratchet:flag:* (only testimonial) - file CIRISServer issue
  - needs-human-review: anti-self-revocation is a mechanical inference from CC 2.3, not an explicit ratchet-specific clause - ratify explicitly if the pattern recurs

### `ratchet:flag:harassment_pattern`

- CC 3.1.6 · owner RATCHET/anti-sybil · superset-class: PatternFlagCard · polarity signed · reserved=False
- CI axes: sender=default, data_subject=default, recipient_see=default, info_type=family_specific, temporal=default
- Invariants: 5 · placement fields: 4
- Required primitives: standard Policy A trust-set screen for scores Contributions; median aggregation for this dimension (implemented); WA-quorum adjudication as the sole load-bearing path to any slashing touching this dimension
- Forbidden: autonomous ledger mutation by the emitter; sole-input-to-slashing-composer; mean/signed-default aggregation for this dimension; reserved-emitter/detector-only gating (NOT a detection:*-style reserved prefix; admission must not require an identity_type to emit it)
- Deltas from seed (7): seed's PatternFlagCard superset (pattern_id/target_ref/occurrence_count/first-last_observed_at/severity_band/modality_tags/corroborating_flag_refs/producer_confidence) not grounded in the wire grammar ...
- **Flags:**
  - needs-human-review
  - constitution-silent

### `ratchet:flag:out_of_distribution_voting`

- CC 3.1.6 · owner RATCHET/anti-sybil · superset-class: score_dial · polarity signed · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 6
- Required primitives: scores primitive (signed score+confidence); Detector-polarity median aggregation (CC 4.4.2 - implemented); a slashing-evidence sole-source screen mirroring testimonial (CC 3.1.6 - required, not implemented); producer-side withdraws/recants/supersedes (rule 1) for detector self-correction / clearing
- Forbidden: aggregate op other than median (must not fall back to Signed/mean); ratchet:flag:* as sole resolvable input to a slashing:* verdict; attested_key_id present in its own subject_key_ids (self-revoke-evidence loophole); delegate (no CC-granted delegation right found); any ledger-mutating side effect from RATCHET's emission
- Deltas from seed (8): actor system_derived misleading - family is open (reserved:false, AuthorityClass::ProducerSteward, absent from CC 3.4); RATCHET is operational-not-enforced producer ...
- **Flags:**
  - needs-human-review: CC 3.1.6 sole-evidence screen not implemented for ratchet:flag:* (only testimonial) - file CIRISServer issue
  - needs-human-review: no dimension-aware subject_key_ids check preventing the flagged party's self-revoke (rule 2 loophole)
  - needs-human-review: authority_for/projection_for (persist#425) has no observed live write-path/replication call site in this checkout - confirm it is enforced, not a designed-but-unwired classifier
  - constitution-silent: beyond the whole-family CC 3.1.6 statement, no rule distinguishes out_of_distribution_voting from its five siblings - identical treatment (honest empty)

### `reconsideration:{grounds}`

- CC 3.1.9.2 · owner CIRISNodeCore/node · superset-class: ReviewRequest · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 6 · placement fields: 7
- Required primitives: delegated-duty admission walk (as-self OR steward-bound chain, attenuating, depth<=5, sub_delegation-gated); named-moderator resolution scoped to the review duty; closed-enum grounds validation (currently unenforced); target-reference resolution with fail-secure semantics (references_attestation_id, mirroring subject_of_content - missing); fresh-quorum-recusal-aware composition for the amendment-stage reuse
- Forbidden: payload-declared principal/on_behalf_of as an admit condition; subject-self admission via a row's OWN self-declared subject_key_ids with no cross-check against the target's actual signed subjects (present in shipped code; the constitution's table does not authorize it - should be forbidden, mirroring the takedown_notice spoof-closure); open-vocabulary substitution of grounds; reuse of vote/weighted_aggregate for non-governance dispute composition
- Deltas from seed (8): delegate:false WRONG: review is one of three canonical delegable duties (moderate/takedown/review) with the same admission/attenuation/depth-cap machinery - delegate:true ...
- **Flags:**
  - needs-human-review (relayed to audit-contract-drift): persist v21.4.0 admits reconsideration/moderation as-self via a row's own self-declared subject_key_ids with no cross-check against the target's actual signed subjects - re-opens the self-declaration spoof pattern the same file closed for takedown_notice
  - needs-human-review: references_attestation_id (matching reconsideration's target-pointer semantics) is never read/validated by the reconsideration/moderation admission path
  - constitution-silent: no wire encoding for the outcome vocabulary {reversed,partial,upheld}
  - constitution-silent (minor): {grounds} closed-enum not validated - off-enum suffix passes the prefix startswith dispatch
  - note: a non-default cirisnode feature (disabled in CIRISServer's pin) ships a narrower ReconsiderationAttestation FK'd to slashing_id, parallel to this CEG-generic model (relayed to hunt-split-truth)

### `revocation:{entity_type}:{reason}`

- CC 3.1.1 · owner CIRISRegistry/registry · superset-class: badge_testimony · polarity -1 only · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 6
- Required primitives: producer-self-withdraw-only correction (rule 1); independent-affirmative-reinstatement (a new licensure/build:registered/partner_role record, never a retraction of the negative claim); cross-family forfeiture fold (bond_posted:* on live revocation); open-vocabulary leaf extension (entity_type/reason under the wildcard); subject_key_ids-null emission guard
- Forbidden: subject-side withdraw authority (subject_key_ids MUST NOT name the revoked entity); steward/CIRIS-L3C emission-or-forfeiture exemption (CC 1.13.2); withdraws-as-reinstatement (bare retraction MUST NOT be composed as restored); positive-polarity un-revoke score in the same dimension (polarity -1 only)
- Deltas from seed (9): CRITICAL (missing from seed): entity_ref must NEVER be hoisted into subject_key_ids - rule 2 (verified live in resolve_withdraws_admission_rule) would let the revoked entity self-withdraw its own revo ...
- **Flags:**
  - needs-human-review: cohort_scope/visibility floor unpinned (community vs federation)
  - needs-human-review: no ISO-4217/token-registry validation exists for the currency in bond forfeiture context
  - constitution-silent: CC's normative text is one registry row + one FSD paragraph + revocation's cross-ref + the stake line
  - evidence-registry: zero cc_impl 3.1.1 entries; grep for revocation:*/bond_posted returns nothing - completely dark family

### `rollback_detected:{revision_field}`

- CC 3.1.2 · owner CIRISVerify/attestation · superset-class: AnomalyDetectionCard · polarity -1 only · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 4 · placement fields: 6
- Required primitives: evidence-linked emit (references_attestation_id or explicit observed/prior fields to the prior-revision evidence - currently absent end-to-end); subject identification (some entity-naming field so a claim is routable/actionable - currently absent; the real sites compute and drop it); recant (false-positive detection self-correction); supersede (severity/detail refinement during investigation)
- Forbidden: aggregate distinct (subject, revision_field) events into a bool/roll-up (shipped AttestBundle does exactly this, losing identifying detail; grounded by analogy to the anti-collapse posture for evidentiary families); sole/automatic trigger of a revocation:*/slashing:* action (detection != decision, CC 6.1.2 WholenessWitness separation); ladder-composition input (Policy I - only the five mechanisms are rungs)
- Deltas from seed (6): subject_ref -> the typed CC 2.3.1/4.5.2.1 subject_key_ids mechanism; but naming the entity there surfaces a self-suppression risk the seed never flagged ...
- **Flags:**
  - needs-human-review (HIGH, code-grounded): rollback_detected is dead/dark end-to-end - a real replay/rollback attack today produces a log line + an HTTP error string to one caller, nothing durable/signed/federation-visible; wiring fix needed across CIRISVerify + CIRISPersist
  - needs-human-review: subject-naming hands the regressed entity CC 2.3.1(a) withdraws authority over the accusation - no adversarial-forensic carve-out exists (unlike ratchet/testimonial)
  - constitution-silent: beyond the CC 3.1.2 line + FSD one-liner, no family-specific composition/aggregation/evidence rule; the detection-not-decision framing is borrowed by analogy from CC 6.1.2's WholenessWitness
  - needs-human-review: no registry pins the open {revision_field} values - producer strings won't match across implementations

### `seed_holder_voting_alignment:{cell}`

- CC 3.1.9.4 · owner CIRISNodeCore/node · superset-class: score_dial · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 4 · placement fields: 6
- Required primitives: scores-composition (auto-derived pairwise metric riding scores - no new primitive, matching moderation_track_record/health:liveness named-composition pattern); multi-subject independent revoke over holder_pair (CC 2.4.1.1); cell-scope bucketing consistent with compose_wa_state_at/compose_agent_state_at {domain,language}; commitment-only ballot disclosure (hash commitment, never raw vectors on the wire)
- Forbidden: aggregate (sole OR corroborating) into any slashing:{outcome} composer; feed back as an input weight into vote/weighted_aggregate Tier-3 consensus composition; delegate (no delegable duty attaches to a derived transparency metric - base_ops.delegate:false confirmed)
- Deltas from seed (6): {cell} is {domain,language} (NodeCore's own Cell/expertise convention), not an opaque cell_id string - recommend seed_holder_voting_alignment:{domain}:{language} with typed domain+language ...
- **Flags:**
  - needs-human-review: recipient_see + recipient_capability restriction is engineering policy, not CC-sourced (federation-health framing may argue wider visibility)
  - needs-human-review: emit_authority/identity_type unbound in CC (reserved:false) and unimplemented - zero references to seed_holder_voting_alignment or a 'seed holder' role in NodeCore/Persist; must bind an emitter (likely genesis 2-of-3 accord-holder key holders)
  - constitution-silent: nothing beyond the single CC 3.1.9.4 table row + FSD one-liner; no dedicated composition section, no calibration package, no registry doc - honest empty beyond the slashing-trigger bar + Tier-4 placement

### `slashing:{outcome}`

- CC 3.1.9.2 · owner CIRISNodeCore/node · superset-class: VerdictCard · polarity boolean-via-score · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 7 · placement fields: 8
- Required primitives: quorum-adjudicated emission (N-of-M WA multi-sig gate at admission, not merely composition-time aggregation); moderation-event-antecedent (required FK to a moderation:{allegation_type} row or documented method-spoofing evidence; never open-ended); non-negative ledger floor clamp (credits_reduced/expertise_reduced); fresh-quorum-recused-reconsideration (sole reversal primitive; a distinct dimension family); boolean-via-score min-aggregation (implemented); dual sole-evidence screen: testimonial (implemented) AND ratchet/detection (NOT implemented)
- Forbidden: supersede / withdraw / recant on a slashing row by its own issuer/quorum (reversal only via a separate reconsideration + fresh recused quorum); aggregate-as-mean (boolean-via-score mandates min); decision-hierarchy-disagreement as a trigger (goal/approach/method honest-failure routes to reconsideration/P11, never slashing)
- Deltas from seed (9): seed invented a continuous score[0-1] + threshold_used; the REAL schema is a quorum multi-sig BOOLEAN verdict (proven_rogue\|not_proven) + quorum_ids/signatures - remove score/threshold, add quorum fi ...
- **Flags:**
  - needs-human-review: the WA-quorum multi-sig gate has ZERO wire representation in CIRISServer/persist (no cc_impl row, no code); NodeCore's Rust payload type is never bridged onto the CEG scores envelope - real construction gap
  - needs-human-review: CC 3.1.6 ratchet/detection sole-evidence screen unimplemented (only testimonial) - same shape, missing half
  - needs-human-review: no ledger non-negative-floor clamp for credits_reduced/expertise_reduced anywhere
  - constitution-silent: GDPR/erasure treatment of slashing:* records (no exemption stated, unlike revocation/audit_chain)
  - needs-human-review: generic (dimension, attested_key_id) composition key omits moderation_event_id - unrelated-incident slashing rows about the same target would MIN-aggregate as if competing about one incident (conflation risk)

### `testimonial_witness:{kind}`

- CC 3.1.9.3 · owner CIRISNodeCore/node · superset-class: NarrativeTestimony · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 7 · placement fields: 6
- Required primitives: self-attest (attesting==subject==affected party; witness_relation:self); supersede-for-correction (narrative_body immutable; corrections via supersedes, never in-place); soft-corroboration links (non-binding cross-references, never folded into a combined score); self-track-record weighting (CC 3.4.7, applied BEFORE the Frickerian non-downweight)
- Forbidden: aggregate (mean/consensus of multiple attesters' testimonial rows - reserved for witness_diversity:* only); sole-input-to-slashing-composer; cohort-density downweighting (Frickerian-forbidden); third-party-initiated revocation (subject_key_ids must not admit a non-attester to withdraw/recant the original witness's narrative)
- Deltas from seed (5): typical_cohort_scope corrected family->self (CC 3.1.9.3 names cohort_scope:self a load-bearing discipline; seed's Cohort-feed default, also in NAMESPACE_SUPERSETS.md/json, contradicts it) ...
- **Flags:**
  - needs-human-review: compose_policy mean-aggregates testimonial_witness:* via the default Polarity::Signed fallthrough - the CC 3.1.9.3 never-aggregated clause is unimplemented (file CIRISServer issue)
  - needs-human-review: round-1 typical_cohort_scope=family/Cohort (also in NAMESPACE_SUPERSETS.md/json) contradicts CC 3.1.9.3's named cohort_scope:self default - product decision on whether to correct the manifest
  - constitution-silent: no WITNESS_KIND_REGISTRY.md exists despite normative reference for {kind} discoverability
  - needs-human-review: guardianship/represented-party authorship has no CC 3.1.9.3-specific treatment - witness_relation:self is the load-bearing shape, so guardian-authored testimony sits outside the four safeguards as written

### `transparency_log:consistency`

- CC 3.1.2 · owner CIRISVerify/attestation · superset-class: proof_chain · polarity boolean-via-score · reserved=False
- CI axes: sender=default, data_subject=not_applicable, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 6
- Required primitives: self-assert attestation (non-reserved boolean-via-score); min-aggregation composer (fail-secure); per-log_id partition/chain resolution (proof_chain via prior_claim_ref, anchored not claimant-trusted); RFC6962-domain-separated Merkle recomputation (distinct from the WholenessWitness scheme)
- Forbidden: aggregate across differing log_id values; sole-gate substitution: a consistency claim MUST NOT satisfy the CC 5.3.1.1 witness-cosign consistency-proof requirement unless anchored against the substrate's own recorded prior STH (claimant-supplied prior insufficient); cross-verification against wholeness_witness:* (different algorithm/leaf-domain, CC 6.1); mean/signed-style aggregation (boolean-via-score, not signed polarity)
- Deltas from seed (7): timestamps: sth_old/new_timestamp should be rfc3339_canonical (CC 2.6.2) not i64-unix-ms (contradicts CC 5.3.1's STH canonical-bytes signing over signed_at) ...

### `transparency_log:cosigned:{tree_size}`

- CC 3.1.2 · owner CIRISVerify/attestation · superset-class: proof_chain · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=not_applicable, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 9
- Required primitives: witness-emitter admission gate (identity_type superset {witness}, CC 3.4.10 + 3.4.7.1); consistency-proof verification at admission, registry-anchored against its OWN last-recorded (tree_size,root) per witness+log (CC 5.3.1.1); quorum-count-distinct-witnesses (read-side aggregate toward witness_quorum_met/count_valid_witnesses, CC 5.3.1) - REQUIRED and load-bearing; forward-only supersede chain (a later cosign passes consistency-proof verification against the witness's own prior cosigned tree_size); mandatory hybrid PQC verification at admission (Ed25519 + ML-DSA-65 bound-payload, CC 5.3.2.4.3.1) - no classical-only acceptance ever
- Forbidden: recant (append-only witness fact; no falsity-admission primitive); withdraw (no party holds revocation over a past cosignature); accepting a self-reported 'consistency was checked' boolean as a substitute for the cryptographic reconstruction (CC 5.3.1.1 anti-'quorum on a string'); witness-role emission by a key whose identity_type set does not actually contain witness (cohabitation never substitutes for the held role, CC 3.4.7.1)
- Deltas from seed (6): actor system_derived mischaracterizes: CC 3.4.10 witness reservation is DIFFERENT from CC 3.4.3 system:*; attester is an independent third-party WITNESS - witness_relation should default external not  ...
- **Flags:**
  - needs-human-review: CC 5.3.1's illustrative POST body shows no log_id/region field yet CC 3.1.2 describes a per-region registry_sth_cosignatures table and CC 5.3.3.5 confirms a separate per-stream log_id=stream_id family - verify whether the base log is scoped by URL path, an omitted body field, or a single global log per deployment
  - constitution-silent: no explicit slashing-composition rule (failure mode is admission-time CONSISTENCY_PROOF_INVALID/MALFORMED_REQUEST, not a scored consumer composition) - a slashing-interaction rule may simply not apply structurally; do not encode a never-sole-evidence invariant without further grounding
  - constitution-silent: 'delegate:false' lacks direct CC support - CC 3.4.7.1 covers multi-role cohabitation on ONE key, not delegation of the witness role's authority to a DIFFERENT key; soften to 'unaddressed by CC text'

### `transparency_log:inclusion`

- CC 3.1.2 · owner CIRISVerify/attestation · superset-class: CryptoProofChain · polarity boolean-via-score · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 7 · placement fields: 6
- Required primitives: deterministic recompute-and-compare (leaf_hash + audit_path + signed_tree_head -> score), not a subjective/graduated judgment; open (non-reserved) single-attester emission - no identity_type gate for inclusion/consistency, unlike cosigned:*; reference-binding via references_attestation_id to the certified leaf/attestation; consumer-side composition into Policy G as a named helper, never a wire primitive
- Forbidden: aggregate multiple inclusion claims into one averaged score (each recomputation is a standalone deterministic fact); treating inclusion as adjudication of the underlying event's substantive correctness/authorization (CC 1.7); cross-verify audit_path/root against a different Merkle domain (CC 6.1.1); require witness identity_type to emit inclusion/consistency (belongs only to cosigned:*); symmetrically MUST NOT drop that gate for cosigned:* via a shared/merged path
- Deltas from seed (9): verification_score f32(1.0/0.0) redundant with the envelope score, which per CC 2.1/3.1 IS the boolean-via-score value and takes +-1 (not 0/1) - collapse to score ...
- **Flags:**
  - needs-human-review: mis-verified (buggy) inclusion recomputation should use recants (false when made) rather than withdraws (circumstances changed) per CC 2.4.1.3 general distinction, contra the seed's recant:false
  - needs-human-review: whether log_id/tree namespace should be bound to the emitting producer's identity at admission - plausible but no CC text mandates it
  - constitution-silent: no recipient_capability axis or strip_field redaction mechanism exists anywhere - the seed's audit_path-stripping restriction is unsupported as stated

### `transport:{kind}`

- CC 3.1.4 · owner CIRISEdge/transport-delivery · superset-class: SubstrateTelemetryReport · polarity signed · reserved=True
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 5 · placement fields: 5
- Required primitives: scores (sole workhorse, signed polarity); supersede-on-corrected-self-report (temporal composition, single-authorized-emitter-per-subject); reserved-prefix admission gate (transport:* wildcard, same chokepoint shape as detection:*); self-report equality check (attested==attesting)
- Forbidden: aggregate/mean composition ACROSS different reporting nodes as same-subject repeated observation; withdraw / recant / delegate; non-substrate (third-party) emission under transport:{kind}; bespoke per-envelope typed fields beyond the CC 2.4.2 scores shape (envelope_hash/route_path/hop_count/delivery_status/retry_count as first-class fields); validating {kind} against the 14-member EnvelopeKind replication enum instead of the transport-medium vocabulary
- Deltas from seed (8): CRITICAL: {kind} = Reticulum/transport-medium link type (CC 8.1.3; TransportId http/reticulum-rs/leviculum/lora/serial/i2p), NOT one of the 14 replication EnvelopeKind values - the seed's envelope_kin ...
- **Flags:**
  - needs-human-review: cohort_scope/projection default not pinned by CC
  - seed-wrong-archetype: per-envelope delivery-trace primitive vs aggregate transport-medium health self-report (correct archetype = aggregate substrate self-report like persist's system:* leaves)
  - constitution-silent: transmission_principle (no consent) + temporal deletion_window (no such language) - honest empties
  - implementation-gap: CIRISEdge@v14.4.0 collects the right aggregate counters (observability.rs) but no code projects them into a signed transport:{kind} federation_attestations row under a substrate_edge key - the CC 3.1.4/3.4.3 emission path is unbuilt (same substrate_edge identity_type + reserved-rule gap as the sibling CIRISEdge leaves)

### `truth_grounding:{subject}`

- CC 3.1.9.3 · owner CIRISNodeCore/node · superset-class: GroundTruthSignal · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 10 · placement fields: 8
- Required primitives: signed-mean aggregation (CC 4.4.2); witness_diversity-gated discount on the mean (distinct from, and in addition to, the vote-plane gate - unbuilt); open-emit admission (no reserved emitter); per-attester supersede chain with contested-head rendering on conflicting high-standing heads; 4-rule withdraws admission incl. delegated-proxy-with-proof-of-control PLUS a public-interest override (proposed); hard_case observability emission on resolution variance/latency breach
- Forbidden: unweighted/undiscounted mean once witness_diversity data exists; n_eff as an aggregation weight (annotation only); truth_grounding:detection:* treated as a detection:* reserved primary emission (must not require lenscore_detector); Credits/track_record composition over encyclopedic-context rows undifferentiated from governance-context rows; reputation composition treating contradiction-then-withdraw identically to voluntary withdraw; render/serve emitting a bare high-precision confidence percentage instead of a band + n
- Deltas from seed (11): 'confidence' is NOT a novel field - a REQUIRED base envelope field and literally the second term in the 4.4.2 mean; remove from proposed-fields, inherited not added ...
- **Flags:**
  - needs-human-review: witness_diversity gate/discount on the truth_grounding mean spec'd (RT-C4/E) but VERIFIED UNIMPLEMENTED (compose_verdict witness_diversity:None; no diversity computation in the Signed branch) - live sock-puppet mean-pulling exposure
  - needs-human-review: recants-vs-withdraws laundering safeguard (RT-M1/F) unbuilt - state_of/heads drops both before open_contradictions
  - needs-human-review: withdraws public-interest carve-out (sec.7, citing the codebase's own #389) has zero implementation - a subject can fully suppress a true adverse public-interest claim via ordinary consent-revocation
  - needs-human-review: encyclopedic-vs-governance Credits-decoupling (sec.11/LOW-8) has no wire/composer enforcement
  - constitution-silent/DRAFT-status: almost all substantive per-family invariants live in FSD-005_KNOWLEDGE_COMMONS.md (DRAFT v0.2, NOT ratified); the ratified Constitution proper gives only the one-line CC 3.1.9.3 catalog entry - treat as strong DESIGN INTENT, not entrenched law

### `vote:{contribution_id}`

- CC 3.1.9.3 · owner CIRISNodeCore/node · superset-class: score_dial · polarity signed · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 7 · placement fields: 6
- Required primitives: open signed-score emission (non-reserved; any Rooted key-owning attester); supersedes restricted to the SAME voter's prior vote on the same contribution_id; withdraws (producer-only); recants (voter admits false-when-cast); a cross-attester fold keyed on {contribution_id} (not attested_key_id) feeding weighted_aggregate - CONFIRMED UNIMPLEMENTED; a Credits x expertise weight-multiplier composer - CONFIRMED UNIMPLEMENTED
- Forbidden: aggregate (vote:* must never compute/hold a multi-voter tally - weighted_aggregate's job); delegate (no constitutional support; round-1 delegate:false holds); slashing composition using vote:* or bare disagreement/minority status as sole/direct input; self-emission reservation is NOT present (contrast capacity CC 3.4.5) - a Contribution's author voting on their own contribution is not structurally forbidden; only the generic witness_relation:self track-record downweight would apply, itself not wired into the (unimplemented) vote pathway
- Deltas from seed (9): 'weight' as a self-declared confidence/stake field is WRONG: CC 3.1.9.3 makes weight a COMPUTED Credits x expertise value, never author-authored - drop from superset_fields ...
- **Flags:**
  - needs-human-review: Credits x expertise multiplier + witness_diversity finality gate CONFIRMED absent from CIRISServer (zero code refs) despite CC 3.1.9.3 stating the weight formula as ratified - live completeness gap
  - needs-human-review: expertise single-source cap (RT-M9) SCOPED/unratified - without it a self-cross-attesting cell inflates vote weight uncapped
  - needs-human-review: CC 3.1.6 ratchet/detection never-sole-slashing implemented only for testimonial
  - constitution-silent: cohort_scope default, consent specifics, criteria_tag/rationale sub-fields not pinned for vote:* specifically

### `watchlist:{id}`

- CC 3.1.9.4 · owner CIRISNodeCore/node · superset-class: ModerationPolicyConfig · polarity signed · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=family_specific, temporal=family_specific
- Invariants: 8 · placement fields: 11
- Required primitives: attestation_upsert_local (config-attestation enable row); withdraws (disable/revocation); delegates_to enforced-admission chain-walk (moderate; +takedown for Csam); attestation_promote (federation-tier cross-fabric agreement); hard_case:{kind} emission (watchlist_enabled/watchlist_match - unimplemented, required by CC 4.5.7); is_named_moderator resolution (validate route_to_moderator + gate CSAM/OtherContent dispatch)
- Forbidden: aggregate (per-group config state, not a scored corpus); on_behalf_of-style self-declared principal field (CC 4.5.5); raw hash-DB/term-list payload fields on the envelope (CC 4.5.10.1); client-side scanning / matcher invocation over self\|family content (CC 8.3.2); auto-eviction/takedown_notice auto-fire from an OtherContent-class match (human-in-the-loop mandatory for non-CSAM); global/fabric-wide enable scope (no group_key_id binding)
- Deltas from seed (11): REMOVE entries:array<WatchEntry> entirely - not a capability-gated field but constitutionally forbidden on the envelope (CC 4.5.10.1 separation of powers); correct shape is the opaque watchlist_id ref ...
- **Flags:**
  - needs-human-review: CC 4.5.7 audit-never-silent floor (hard_case:watchlist_enabled/match) is NORMATIVE but unimplemented (constants declared, never emitted) - compliance gap
  - needs-human-review: CSAM-disable non-silent floor has no code path (disable_watchlist has no class parameter)
  - needs-human-review: enable_watchlist does not validate watchlist_id against matcher.databases() (contrary to FSD sec.7.1 step 4)

### `weighted_aggregate:{contribution_id}`

- CC 3.1.9.3 · owner CIRISNodeCore/node · superset-class: score_dial_ledger · polarity signed · reserved=False
- CI axes: sender=default, data_subject=family_specific, recipient_see=default, info_type=family_specific, temporal=family_specific
- Invariants: 3 · placement fields: 4
- Required primitives: promote-with-full-placement (promotion/adoption composer joins weighted_aggregate with witness_diversity(contribution_id)=true before acting); quorum-supersede (rolling-tally roll-forward via supersedes, per-attester); cohort-aggregate-with-coverage-check (fleet rollup gated by expected_occurrence_count coverage + per-occurrence-signed source + P10 on the cohort attestation); cross-attester-mean-compose (CC 4.4.2 default for signed polarity across independently-emitted tallies)
- Forbidden: aggregate synthesizing/attributing a per-occurrence Contribution the occurrence did not itself sign (no ghost-occurrence fabrication); reuse as the confidence-composition primitive for non-NodeCore-governance domains (truth_grounding's role); component/vote counts standing in as a weighting/finality signal on their own - display-annotation only; finality is governed by the P4 vote-weight formula + P10 gate
- Deltas from seed (8): emit_authority ProducerStether unsupported - 'no central scorer'; any attester may compute+emit a tally ...
- **Flags:**
  - needs-human-review: CC 4.4.2 signed default (mean) vs NodeCore compose.rs latest-by-asserted_at behavior for weighted_aggregate - 4.4.2 permits documented per-dimension overrides but this divergence is not pinned/documented anywhere
  - needs-human-review/not-yet-implemented: the cohort sub-leaf wire format is fully designed in NodeCore (MISSION + aggregate.rs pure-compute) but has ZERO wire realization - no signed-envelope builder, no dimension-string constructor, no composer branch recognizes it (compose_contribution_at silently drops it)
  - constitution-silent (confirmed): CC 4.5.1.1 open-vocab/calibration discipline does NOT apply - {contribution_id} is a reference identifier, not an open-vocab {axis}/{kind} taxonomy value

### `witness_diversity:{contribution_id}`

- CC 3.1.9.3 · owner CIRISNodeCore/node · superset-class: DiversityBarScoreCard · polarity boolean-via-score · reserved=False
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, info_type=default, temporal=default
- Invariants: 7 · placement fields: 9
- Required primitives: witness-set structural verification (N-of-M count + jurisdiction-span>=2 + org pairwise-distinctness + stack distinctness + per-witness nonzero-expertise, as one conjunction); fail-secure MIN aggregation across independent emitters (never mean/majority); admission-time validity gate wired to the enumerated high-stakes kinds (reject/hold when unmet); locality-scaled N via locality:decision:{scale} (not a fixed constant); tag_attestation_refs resolution/verification at read time (each tag resolves to a live independently-signed attestation); compound contribution_id resolution (cohort + Tier-2 P12-P15)
- Forbidden: aggregate (mean/weighted-mean) across verdicts for the same contribution_id - must be MIN; self-declared/un-attested diversity tags inline (RT-M4); witness_diversity as sole/direct adjudication of a Contribution's outcome (adjudication is WA quorum's alone); substituting n_eff (storage-mass) as/in place of the witness_diversity weight (finding X4); universal admission-gating of ALL Contribution kinds (scope is the enumerated high-stakes set only)
- Deltas from seed (10): axis_scores continuous floats WRONG: the four bars are discrete/set-level structural checks (span>=2, no shared-entity pair, distinct stacks, nonzero per-witness Expertise), not tunable-threshold floa ...
- **Flags:**
  - needs-human-review: witness jurisdiction/org disclosure is required for the anti-collusion gate to be verifiable but is a real-world safety/doxxing risk (authoritarian-jurisdiction witness); no pseudonymity/redaction carve-out found (unlike testimonial's witness_relation:self)
  - constitution-silent: subject_key_ids inclusion for roster entries is a recommendation extending the spirit of 4.5.2.1, not textually mandated ({contribution_id} not in the subject-bearing catalog)
  - constitution-silent: no deletion_window specific to this family beyond general fold discipline
  - implementation-gap (not a constitution gap): no admission-time enforcement of the P10 validity gate anywhere in CIRISServer (grep admission.rs + repo) - only the composition-time BooleanViaScore->Min rule exists; the reject-if-unmet gate for the four high-stakes kinds is unbuilt

---

## 9.1 Per-family appendix — the 9 UNREGISTERED families

Same shape as §9. These families have **no round-1 seed and no registry row**; the round-2 walk was built from the Constitution plus the live CIRISPersist v21.4.0 / CIRISEdge v14.4.0 / CIRISServer implementations. Full detail per family in `families.<prefix>` in the JSON.

### `consent:*` · **UNREGISTERED**

- Consent Grammar (Transmission Principle) · anchor CC 3.3.1 · owner CIRISPersist/persist (cross-cutting: subject/producer/substrate/node emit) · superset-class: ConsentGrantCard · polarity per-leaf (enumerated | signed | positive-only) · reserved=open-with-two-substrate-only-leaves (proposed)
- Claim: Asserts a subject's or node's transmission-principle state over a target Contribution or peer flow: granted/revoked/expired state, scope of permitted use (retain/share/analyze/train/publish), deletion-SLA commitment and completion, decay-stage milestones, partnership grant/accept, and directed federation-peer replication grants.
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, recipient_revoke=family_specific, recipient_receive=default, info_type=family_specific, transmission=family_specific, temporal=family_specific
- Invariants: 8 · placement fields: 10 · CC refs read: 22
- Required primitives: subject-revocation admission per CC 2.4.1.1 rules 1-4 (resolve_withdraws_admission_rule); any-subject-binding OR-composition over subject_key_ids (CC 4.4.3.5.4) for multi-subject Contributions -- never quorum-gated; deletion-SLA-watcher (CC 4.4.3.5.2 / CC 5.3.2.2) pairing subject-side revocation with producer's committed deletion_sla and a deletion_complete-or-hard_case terminal state; local-to-federation promote-with-tier-placement for subject-side consent:state:revoked (CC 5.3.2.2/5.3.2.4.1); bilateral-pair ratification (CC 4.4.3.5.3) for consent:partnership_grant/consent:partnership_accept, keyed on bilateral_pair_id; decay-protocol multi-stage emission (CC 4.4.3.5.1) for consent_record.decay_protocol; prefix-scoped grant composition (consent_grammar::covers / parse_grant_payload) gating both promotion (persist) and serve-time capability restrictions (edge); grant-narrowing-via-supersedes for any change to a live consent:replication attestation_prefixes set (CC 3.3.7)
- Forbidden: aggregate/quorum-softening of multi-subject revocation (CC 4.4.3.5.4); recants as a subject-side consent-revocation vehicle (CC 2.4.1.1); minting a new attestation_type or envelope field for any consent:* leaf (CC 3.3.1/3.3.7 1+4 lockdown); silent (non-superseding) narrowing of a live consent:replication attestation_prefixes set (CC 3.3.7); local-tier settlement of a subject-side consent:state:revoked row (CC 5.3.2.2); third-party-authored consent:replication grants, i.e. witness_relation != self (CC 3.3.7); consent:* attestations as sole/unaided evidence for slashing:* -- inherited from the general CC 1.2 T4 admission-gate discipline, though NOT explicitly re-stated for this
- Deltas from seed (5): The seed's "cc_section": "UNREGISTERED" overstates the gap: the family is thoroughly, normatively specified at CC 3.3.1, CC 3.3.5, CC 3.3.7, CC 4.4.3.5/Policy K, and CC 4.5.2 -- roughly 300+ lines of normative prose plus a working reference implementation in C ...
- **Flags:**
  - needs-human-review: two concrete new admission-gate checks proposed (witness_relation==self and cohort_scope==federation for consent:replication:{version}) that do not exist in CIRISPersist today -- new enforcement surface, should go through CC 4.5.1 amendment/registry process, not silently added as a bugfix.
  - constitution-silent (honest gap, not invented): the Constitution does not explicitly re-state the CC 1.2 T4 'never sole evidence for slashing:*' discipline specifically for consent:* attestations anywhere found.
  - documentation gap (not a reserved-prefix gap): CC 4.5.1.1 names WITNESS_KIND_REGISTRY.md for open-vocab testimonial_witness/hard_case leaves, but no equivalent registry document is named for new operator-coined consent:{kind} leaves.
  - Per task instructions: no round-1 seed card existed; this entire analysis was built from scratch against the Constitution + the actual CIRISPersist/CIRISEdge/CIRISServer implementations.

### `trace:*` · **UNREGISTERED**

- Sealed Reasoning Trace · anchor CC 5.3.2.4 · owner CIRISAgent/accord-agent (normative weight split across persist/edge/server/agent) · superset-class: SealedTraceCard · polarity n/a · reserved=proposed reserved_rule: trace-self-attestation (new CC 3.4.14)
- Claim: Self-emitted, self-subject signed record of one complete agent reasoning cycle (CompleteTrace), born local-tier, promoted to federation tier only along an explicit consent edge, and served ONLY to recipients holding an accord-conferred infra:serve capability rooted in a trust root this node trusts.
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, recipient_revoke=default, recipient_receive=family_specific, info_type=family_specific, transmission=default, temporal=family_specific
- Invariants: 5 · placement fields: 8 · CC refs read: 24
- Required primitives: self-attested-only admission (attesting_key_id MUST appear in subject_key_ids; third-party trace emission REFUSED) - CIRISPersist#473; local-tier deferred-signature write + consent-gated backlog promotion sweep (#509/#510, idempotent, two chokepoints); capability-gated SERVE: recipient MUST present an accord-conferred infra:serve role that roots to a trust root this node trusts - unique among all 95 CC families; explicit, non-auto, owner-authored consent:replication:v1 grant scoped by attestation_prefixes superset "trace:" before any ADVERTISE/pull can occur; mandatory pre-signature content scrub (NER+regex PII redaction) with hard-fail-never-partial semantics; hybrid PQC (Ed25519 + ML-DSA-65) verified at every federation-tier admission of a trace row, no exemption
- Forbidden: third-party trace emission (attesting_key_id absent from subject_key_ids); default-public SERVE (the posture every OTHER Attestation-riding family uses; trace:* is the one family forbidden from it); auto-consent / implicit boot-time replication grants (the E6 fix); classical-only (non-hybrid) admission of a federation-tier trace row; silent partial-scrub persistence; mixing infra:serve with any agency:* scope on the same delegation presented as a serve-capability credential (CC 4.4.3.4.3)
- Deltas from seed (5): 'cohort_scope=self at birth' is WRONG on the specific field: the wire cohort_scope field historically defaulted to hardcoded 'federation' and, as of v21.4.0, is now STAMPED from the covering consent grant's audience at promotion - never 'self' by default. What ...
- **Flags:**
  - needs-human-review: registry ratification is overdue and independently confirmed from the implementation side - CIRISPersist admission.rs:1291-1295 literally states 'Registry entry + validator pending CC ratification (namespace catalog + trace_manifest:v1 schema + the self-emission rule)... persist's machine-checkable interim, the same posture as the CC#38 size cap'.
  - needs-human-review: RestrictionOp::RecipientCapability is authored-and-recorded but UNENFORCED end-to-end - consent_grammar.rs defers enforcement to 'the SERVE layer (P3)', but the actual serve gate checks only the blanket infra:serve role, never the per-grant capability token. Exactly the 'carried-but-unprocessed field' pattern this audit hunts.
  - needs-human-review: when multiple live consent grants cover the same trace dimension with disagreeing audience, promote_consented_backlog resolves by an arbitrary deterministic tie-break (first by attestation_id); a narrower-intended grant can silently lose to a broader one that merely sorts first (#510).
  - constitution-silent: every trace:*-SPECIFIC rule (self-emission-mandatory, inline-vs-manifest shape validation, the StripField worked example, the capability-gated SERVE rule itself) currently lives only in CIRISPersist/CIRISEdge/CIRISServer source, not in ratified constitution text.
  - terminology collision (verified): constitution part_4 sec.4.4.3.2/4.4.3.2.1's 'Node->canonical traces (conformance / registry_consensus emissions...)' language refers to the ALREADY-REGISTERED attestation:registry_consensus family, NOT this trace:* family (the sealed CompleteTrace reasoning payload).
  - seed-wrong-field, not seed-wrong-archetype: the description's underlying three-gate model (tier / consent-promotion / capability-serve) is directionally sound; only the specific field name (cohort_scope vs tier) was imprecise.

### `trace_manifest:*` · **UNREGISTERED**

- Oversize Trace Manifest (NOT A PREFIX) · anchor CC 3.1.5 · owner CIRISAgent/accord-agent · superset-class: (none - folds into SealedTraceCard) · polarity n/a · reserved=DO NOT REGISTER as a prefix
- Claim: Integrity-only commitment (content_hash + byte_len + component_count) substituted for an inline CompleteTrace when canonical JCS bytes exceed MAX_ATTESTATION_ENVELOPE_BYTES. Round-2 verdict: this is a nested payload-schema TAG inside a trace:complete:v1 envelope, structurally the same category as CC 8.4.2.1's c2pa_manifest - NOT a wire-level namespace family.
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, recipient_revoke=family_specific, recipient_receive=default, info_type=family_specific, transmission=family_specific, temporal=default
- Invariants: 4 · placement fields: 8 · CC refs read: 15
- Required primitives: self-emission-only mint (attesting_key_id in subject_key_ids), admission-enforced; exactly-one-of inline/manifest shape gate, admission-enforced; size-cap oversize fallback to manifest when canonical bytes exceed MAX_ATTESTATION_ENVELOPE_BYTES; promote-with-full-placement: cohort_scope widening only through the generic consent-gated attestation_promote path, never a default
- Forbidden: third-party / non-self emission (structurally refused at admission); numeric aggregation or mean-composition across distinct trace:* rows as if they were graded scores; treating a trace_manifest:v1 (oversize) row as component-content-equivalent to an inline trace for any consumer requiring component-level detail (F-3 correlated-action de
- Deltas from seed (6): ARCHETYPE CORRECTION (the headline delta): 'trace_manifest:*' is not a CC-3.1-style namespace prefix at all and should not be proposed as its own registry row. Ground truth (CIRISPersist v21.4.0) shows trace_manifest:v1 is the schema tag of a nested manifest o ...
- **Flags:**
  - seed-wrong-archetype: the seed proposed 'trace_manifest:*' as a candidate namespace prefix; ground-truth code shows it is a nested payload-schema tag (like c2pa_manifest), not a prefix. The prefix that actually needs a registry row is trace:* / trace:complete:{version}.
  - constitution-silent: no CC 3.1.5 or CC 4.x rule addresses whether DMA/conscience verdicts embedded in a trace's components[] retain independent CEG standing versus being invisible payload copies.
  - needs-human-review: recipient_revoke / temporal_lifecycle for the human end-user embedded in trace content but never named in subject_key_ids.
  - needs-human-review: weight-null / no-aggregation invariant for trace:* is asserted as a reading of the code + CC-3.1.5-polarity-pattern contrast but is NOT currently admission-enforced.

### `trace_summary:*` · **UNREGISTERED**

- Denormalized Trace Feature Vector · anchor CC 4.5.8.3 · owner CIRISAgent/accord-agent (machinery in persist; composition in server/lens-core) · superset-class: FeatureVectorCard · polarity n/a · reserved=False
- Claim: Derived, manifest-hash-pinned feature vector over one trace's component rows (csdma/dsdma/idma scores, thought metadata, signature_verified) that is the RAW SCORER INPUT to capacity:sustained_coherence via N_eff - never itself a verdict.
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, recipient_revoke=default, recipient_receive=family_specific, info_type=family_specific, transmission=family_specific, temporal=not_applicable
- Invariants: 4 · placement fields: 6 · CC refs read: 10
- Required primitives: per-agent feature-matrix grouping (trace_summary rows grouped and scored strictly per single agent - src/scorer.rs's by_agent BTreeMap - never pooled); FK-valid subject resolution before any downstream attestation is authored about the implicit subject (unresolved subjects skipped loudly, never silently); distinct consent:replication:v1 attestation_prefixes entry for trace_summary:* separate from trace:* before cross-node promotion (CC 3.3.7); distinct attesting identity at the trace_summary->capacity:* composition step (CC 3.4.5 anti-Goodhart), even under key/role cohabitation (CC 4.5.8.3)
- Forbidden: trace_summary:* rows MUST NOT be directly emitted/treated as a capacity:* verdict (no bypass of the anti-Goodhart composition step); trace_summary:* MUST NOT be aggregated across multiple agents into one composite/capacity score (that is the separately-calibrated F-3 structural-injustice detector famil; a consent:replication:v1 grant scoped to "trace:" MUST NOT be treated as authorizing trace_summary:* promotion (trailing-colon-significant exact-prefix matching per CC 3.
- Deltas from seed (6): No round-1 finder output existed for this family; treating the provided registry-row stub as the closest thing to a seed. ...
- **Flags:**
  - needs-human-review: recipient_see default/inheritance on promotion is constitution-silent - does a promoted trace_summary inherit its source trace_events' cohort_scope (incl. CC 5.2 self/family structural-invisibility), or is it minted at an independent default?
  - needs-human-review: temporal_lifecycle (deletion_window / tombstone-fold interaction between raw trace_events and a derived, already-promoted trace_summary row) is constitution-silent.
  - constitution-silent: CC Part 3/4 contain zero literal text on trace_summary:* - every family-specific claim is either directly cited CC text applied by structural analogy or grounded in live CIRISPersist/CIRISServer code.
  - seed-wrong-archetype: N/A - no round-1 seed was provided for this family.

### `trust:*` · **UNREGISTERED**

- Trust-Root Charter + Trust Edge · anchor CC 3.2 · owner CIRISPersist/persist (predicate) + server (capability gate, unwired) + edge (peer visibility) · superset-class: TrustRootCard · polarity n/a · reserved=needs a reserved delegation_purpose token, NOT a namespace_registry row
- Claim: NOT a scores dimension: a delegates_to structural-composer overlay. A charter (root->root self-loop) declares root-hood; a trust edge (user->root) attaches a node's bound owner to that root; trust_root_valid() gates the node's federated capabilities, fail-closed and halt-latch-aware.
- CI axes: sender=family_specific, data_subject=not_applicable, recipient_see=family_specific, recipient_revoke=family_specific, recipient_receive=default, info_type=family_specific, transmission=family_specific, temporal=family_specific
- Invariants: 8 · placement fields: 7 · CC refs read: 16
- Required primitives: self-referential charter admission that requires EXTERNAL witnessing (quorum-style) at genesis, not merely at recovery; scope/purpose-filtered delegation-edge resolution (trust_root_valid's edge_exists leg must filter by scope or a dedicated delegation_purpose, not bare delegates_to(user->root) existence); attenuation-bound sub-delegation walk with CC 4.1.1's depth-cap-5 + cycle-rejection applied uniformly to down-chain infra:* grants, not just the two hard-coded hops; expiry-as-tombstone fold over delegates_to edges (already implemented); m-of-n pre-committed key-rotation admission for charter recovery (already implemented); halt-latch consultation at serve-time, fail-closed on indeterminate/unsupported backends (already implemented)
- Forbidden: aggregate - the walk must return a single attributable root + verdict (TrustedGrant, first-valid-root-wins); silently blending multiple trusted roots into one composite c; unwitnessed self-declaration as permanent, standing evidence of root-hood - forbidden absent either a CC 4.1 ratified carve-out or external quorum witnessing at genesis; using halt_latched / trust-edge-withdrawn as sole input to any slashing:* verdict against the underlying identity - by analogy to the ratchet:flag:counter_rii discipline,
- Deltas from seed (4): No formal round-1 seed existed, but the assigned card needs correcting: 'trust:*' is framed as if it were a scores-attestation dimension family resolved through authority_for(). In production code no such dimension string is ever actually emitted outside test  ...
- **Flags:**
  - needs-human-review
  - constitution-silent

### `ownership:*` · **UNREGISTERED**

- Owner Binding (Responsible Party) · anchor CC 3.2 · owner CIRISPersist/persist · superset-class: OwnerBindingCard · polarity n/a · reserved=de-facto reserved by admission gates; unregistered in the manifest
- Claim: A responsible human steward's self-signed delegates_to binding naming exactly one node/agent key as owned; single-owner-invariant enforced at admission, infra-only scope enforced at admission, lapse-enforced at reconcile.
- CI axes: sender=family_specific, data_subject=not_applicable, recipient_see=family_specific, recipient_revoke=family_specific, recipient_receive=default, info_type=family_specific, transmission=not_applicable, temporal=family_specific
- Invariants: 7 · placement fields: 6 · CC refs read: 14
- Required primitives: delegates_to with delegation_purpose=owner_binding (the sole admissible shape for establishing ownership - CC 2.4.1.2/CC 3.2); supersedes (ownership transfer - supersede-then-rebind, CC 3.2 admission-time enforcement); withdraws (incumbent self-revocation, CC 2.4.1.1 rule 1; and the still-unimplemented WA-adjudicated reclaim path, CC 3.2 no-permanent-ownerless-lock)
- Forbidden: aggregate/scores-based or weighted-consensus resolution of ownership - owner_of is a graph existence+cardinality check over purpose-filtered delegates_to edges, never a s; agency:* (or any non-infra:*) delegated_scope on a delegates_to whose target resolves to a node-only identity (CC 4.4.3.4.3); sole reliance on the node's own signature to establish, refresh, or transfer ownership - the binding MUST carry the responsible human user's own signature; lexicographic/sorted-pick resolution when cardinality is ambiguous (>1) - MUST fail closed instead of picking a 'winner'; recants against an ownership transfer - a legitimate ownership change is supersedes/withdraws, never an admission that the prior claim was false at issuance
- Deltas from seed (1): No round-1 seed existed for this family (round-1 finder failed, per task framing); this is a from-scratch analysis, not a correction. ...
- **Flags:**
  - needs-human-review: CC 3.2's 'No permanent ownerless lock (MUST)' clause (WA/recovery-authority reclaim on provable death or seizure) has NO corresponding wire mechanism in CIRISPersist v21.4.0 - the CC 2.4.1.1 withdraws-admission-rule enumeration does not cover a third party revoking a LIVE incumbent's binding absent a pre-existing delegation from that incumbent, and grep of the persist crate fin
  - constitution-silent (partial): CC 3.2 states the WA-reclaim MUST but does not pin a concrete admission mechanism the way CC 4.2.6 fully specifies for the accord family - the analogy CC 3.2 draws is qualitative, not a generalized mechanism.
  - needs-human-review (minor): cross-reference drift - CC 4.4.3.4.3 and CIRISPersist's doc comments cite '[CC 1.13.5] infrastructure must not have agency', but this checkout's CC 1.13.5 is the unrelated operational-language T1-T4 gate; the language does not appear verbatim anywhere in part_1_foundation.md.
  - The family IS in fact well-implemented overall (contrary to what 'unregistered' might suggest): CIRISPersist v21.4.0 has dedicated admission gates wired into all three storage backends, with an already-fixed historical near-miss (CIRISPersist#378) that is direct precedent for exactly the 'field carried but not processed' failure class this audit is hunting.

### `config:*` · **UNREGISTERED**

- Node Configuration as CEG · anchor CC 4.4.3.4.3 · owner CIRISServer/node · superset-class: ConfigEntryCard · polarity boolean-via-score · reserved=proposed reserved:true, self-loop rule
- Claim: Node-local operational configuration (and per-peer sideband operator annotations) carried as scores rows with a fixed score:1.0 placeholder, version-folded last-write-wins, tombstoned by an app-level Null value.
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=family_specific, recipient_revoke=family_specific, recipient_receive=not_applicable, info_type=family_specific, transmission=not_applicable, temporal=family_specific
- Invariants: 3 · placement fields: 6 · CC refs read: 10
- Required primitives: self-report / self-attest (attesting_key_id == attested_key_id == the node's own derived federation key) - already the de facto shape, but not yet a substrate-enforced reserved rule; latest-wins version fold over a key (currently a custom app-level construction; should migrate onto the native references_attestation_id/supersedes structural composer); tombstone-on-delete (currently dual: app-level Null-value convention + genuine withdraws/recants support - the withdraws path should become primary for cross-consumer visibility)
- Forbidden: cohort_scope::FEDERATION (or any non-self/family scope) as the default emission scope for node-local config content - contradicts CC 4.4.3.4.3's Self-content model and CI; third-party (non-self-loop) emission on config:* once/if it is registered as reserved - a claim about another node's config, from any key other than that node's own, is a
- **Flags:**
  - No round-1 seed existed for this family (round-1 finder failed per the task brief) - this entire analysis is constructed from scratch by confirming config:* is absent from the 95-family namespace_registry.json and reading the live implementation (src/graph_config.rs, src/config_api.rs, src/config_reconcile.rs, src/federation_peers.rs, src/memory_api.rs).
  - constitution-silent: no CC 3.1/3.4 namespace section names 'config:*' as a dimension family; the only direct textual anchor is CC 4.4.3.4.3's naming of 'config' as one of four Self-DEK content classes, which is about a HUMAN user's cross-device Self content - treated here as strong analogical grounding, not a literal rule.
  - needs-human-review (HIGH severity, concrete code defect): src/graph_config.rs's config_envelope() hardcodes cohort_scope::FEDERATION for every config:v1 row (including auth.admin_key_ids, net.bootstrap_peers, and federation_peers.rs's per-peer trust/appearance/SAS sideband annotations under federation.peer_sideband.<key_id>), when this codebase already has the correct pattern available and used el
  - needs-human-review (low severity, currently inert): the config family's per-key scope field (ConfigScope::Local|Identity) shares its wire key name with CIRISPersist's reserved, differently-typed EnvelopeCore.scope path; the one live consumer (trust_root.rs#check_trust_charter_admission) gates on attestation_type==delegates_to first so config:v1 rows never reach it today - but the name collision is
  - needs-human-review: ConfigScope::Identity is declared in the type system but has ZERO differential enforcement today - the exact 'incomplete primitive' shape the task brief warns about.
  - registry-row proposal (not yet filed): prefix 'config:{key}' (recommend renaming the flat 'config:v1' dimension to carry the key as a leaf, per watchlist:{id} precedent); reserved:true; reserved_rule = self-loop (attesting_key_id MUST equal attested_key_id), modeled on CC 3.4.3/CC 3.4.5; polarity='boolean-via-score'; owning_repo=CIRISServer; owning_component=node.

### `capacity_assurance:*` · **UNREGISTERED**

- Adult Capacity-Assurance Ladder · anchor CC 3.4.12 · owner CIRISPersist/persist · superset-class: CapacityLadderCard · polarity enumerated · reserved=True
- Claim: Witness-reserved, per-domain, per-band attestation of an adult's decision-making capacity, gating adult-incapacity delegates_to admission; a vector never a scalar, with mandatory reversible-mimic exclusion, bounded valid_until, fail-open-to-liberty lapse, and an apophatic floor of non-transferable domains.
- CI axes: sender=family_specific, data_subject=family_specific, recipient_see=default, recipient_revoke=family_specific, recipient_receive=family_specific, info_type=family_specific, transmission=not_applicable, temporal=family_specific
- Invariants: 9 · placement fields: 6 · CC refs read: 15
- Required primitives: promote-with-full-placement (level+domain+band+attester-independence all present and cross-checked before any delegates_to admission); deletion-window/expiry-enforcement (mandatory valid_until <= T2_review_cadence, auto-lapse to liberty); quorum-supersede (panel M-of-N independent quorum required for continuing or asset-bearing power; a lone provider attestation can never supersede that requirement); companion-linkage-check (reversible_excluded, or T1-only reversible_pending, must be present per domain before a continuing binding is promoted); domain-scope-subset-check (delegates_to scope must be a subset of attested-incapacitated domains, with the apophatic floor carved out)
- Forbidden: aggregate (no cross-domain scalar/global capacity score - capacity is a vector, never averaged); sole-input-to-slashing-composer (misattestation routes to moderation:* only); self-emission or conflicted-emission (attester in {subject, steward, petitioner}); steward-gated-restoration (the steward MUST NOT be able to gate, delay, or be counted in the denominator of a restoration petition)
- Deltas from seed (4): No formal round-1 seed existed, but the task's background JSON (reserved:false, reserved_rule:null, polarity:'n/a', owning_component:persist) functions as a working assumption needing correction: owning_component=persist/owning_repo=CIRISPersist is CONFIRMED C ...
- **Flags:**
  - needs-human-review: registry-drift fix spans CIRISConstitution (generator + manifest) and its vendored copy in CIRISPersist - cross-repo, not a CIRISServer-only fix
  - constitution-silent: CC 3.4.12 never names cohort_scope/visibility (recipient_see) for a capacity_assurance row, nor any consent:scope-style transmission_principle grant - both axes filled by inference from adjacent actor-access requirements
  - no-round-1-seed: full analysis done from scratch; the background block treated as a correctable working assumption
  - verify-upstream: found no active reconcile/sweep symbol in CIRISPersist that flips a live capacity_assurance-gated binding non-live purely on valid_until wall-clock lapse (only admission-time bound-checks and a read-time liveness check) - the 'auto-restore with no action required' guarantee may be read-time-only

### `scores:*` · **UNREGISTERED**

- 'scores:' - the attestation_type name, NOT a dimension family · anchor CC 3.3.7 · owner CIRISServer/node (federation/consent-replication surface; NOT lens) · superset-class: (none - DO NOT REGISTER) · polarity n/a · reserved=False
- Claim: Round-2 verdict: no such dimension family exists. 'scores' is the CC 2.4.2 attestation_type name; zero dimensions anywhere in the fabric are literally prefixed 'scores:'. The only production occurrence is a permanently-vacuous attestation_prefixes entry shipped in FSD/BRIDGE_SEED_MESH.md:223.
- CI axes: sender=default, data_subject=family_specific, recipient_see=default, recipient_revoke=default, recipient_receive=family_specific, info_type=family_specific, transmission=not_applicable, temporal=default
- Invariants: 5 · placement fields: 3 · CC refs read: 11
- Deltas from seed (5): owning_component correction: the seed card's 'lens' attribution is unsupported by any code evidence. The only concrete production occurrence of the literal token 'scores:' as a namespace-prefix-shaped value in the entire CIRISServer + CIRISPersist + CIRISEdge  ...
- **Flags:**
  - constitution-silent: no CC text names a scores:{domain} dimension family specifically; the applicable rules are the generic open-vocabulary discipline (CC 3.4, CC 4.5.1.1, CC 4.5.1.3) plus the CC 3.3.7 attestation_prefixes definition that the concrete production occurrence actually violates in spirit.
  - seed-wrong-archetype: owning_component='lens' in the given card is not supported by any code evidence; the only concrete production occurrence is CIRISServer's federation/consent-replication surface, and the seed's illustrative dimensions do not exist in any repo searched.
  - needs-human-review: recommend (a) fix FSD/BRIDGE_SEED_MESH.md:223 attestation_prefixes from ["scores:","capacity:"] to ["trace:","capacity:"]; (b) add author-time validation in src/peer.rs::normalize_prefixes / federation_admin.rs that rejects or warns on an attestation_prefixes entry equal to a reserved wire-primitive name ('scores:', 'delegates_to:', 'supersedes:', 'withdraws:', 'recants:'); (c)

---

## 10. Registry coverage gap — the unregistered 9

> the 9 families that are LIVE (or live-adjacent) in production but carry no row in the 95-family CC-1.0-rc2 namespace registry

**Verified:** direct query of CIRISPersist/src/federation/namespace/namespace_registry.json (n_families=95): zero rows match any of the 9 prefixes. The sibling age_assurance:* is likewise absent (out of scope for this addendum, same root cause).

### 10.1 Root cause — one generator, one scope boundary

The fallback is not constitutional silence. `CIRISConstitution tools/build_cc_namespace.py` the generator walks ONLY '### 3.1.N' per-owning-component headings (its docstring says so: 'Section CC 3.1 (### 3.1.1 ... ### 3.1.10, minus the 3.1.7 summary) catalogs the prefix families by owning component').

**Consequence.** every family defined under a SIBLING top-level heading is structurally invisible to the manifest: CC 3.2 (ownership/trust-root/steward-binding), CC 3.3 (content-ingestion prefixes incl. the whole consent:* family), CC 3.4.11/3.4.12 (age_assurance / capacity_assurance). This is a tooling-scope gap dating to when CC 3.3 was added, NOT constitutional silence and NOT a deliberate 'leave this open' decision.

**The tell.** build_cc_namespace.py's RESERVED_RULES table already contains a capacity_assurance predicate - it can never fire, because the heading-regex extractor never yields that family. The generator's own author expected the row to exist.

### 10.2 The ProducerSteward-fallback risk

**Mechanism.** CIRISPersist src/federation/namespace/registry.rs#authority_for() returns ProducerSteward with reserved:None for any dimension with no manifest row; class_for() only special-cases the 'substrate-self-report' rule token, so every OTHER reserved rule collapses to ProducerSteward regardless of registry presence.

**Blast radius today.** PRIMARILY METADATA LOSS, not an open admission hole - because (a) no consumer currently branches on `.reserved` for a live decision, and (b) the two families with real enforcement needs (capacity_assurance:*, ownership:*) are gated by hand-maintained admission code that does not consult authority_for() at all.

**The real risk — split truth.** SPLIT TRUTH. There are now two independent answers to 'is this prefix reserved, and to whom?' inside one crate: the hand-maintained admission gates (admission.rs#default_reserved_prefix_rules, #check_adult_incapacity_binding, #check_single_node_owner_admission, #check_trace_dimension_admission) and the CC-3.1-generated classifier (namespace/registry.rs#authority_for). They have already diverged for capacity_assurance:*. Any future consumer that trusts the generated classifier - a policy engine, a UI badge, a replication filter - will read 'open, unreserved, ProducerSteward' for a witness-reserved clinical-capacity family.

**Second order.** config:* is the one family where the fallback is directly exploitable today: it is unreserved, so nothing in the substrate rejects a THIRD party minting a config:v1 row naming a victim node's attested_key_id. CIRISServer's own reconciler is immune only because its read path additionally filters attesting_key_id==self; no other consumer of the corpus inherits that protection.

**What is *not* a risk.** trace:*, trace_summary:*, and the common case of consent:* are CORRECTLY open-vocabulary. Reserving them wholesale would break the common case (any federation member must be able to self-emit consent about their own data; any agent must be able to emit its own reasoning trace). The fix is per-leaf, not blanket.

### 10.3 Proposed registry rows

| Prefix | CC section | Reserved | Reserved rule | Polarity | Owner | Recommendation |
|---|---|:--:|---|---|---|---|
| `consent:*` | 3.3.1 (+3.3.5, 3.3.7) | False | OPEN family with two substrate-only sub-rows: consent:state:expired and consent:decay:{stage} MUST be SubstrateSelf (persist's class_for() already has | PER-LEAF (enumerated | signed | positive-only) - a single family-wide polarity column cannot represent CC 3.3.1's own table | CIRISPersist/persist | REGISTER |
| `trace:*` | PROPOSE new CC 3.4.14 'trace-self-attestation' | True | self-emission MANDATORY (attesting_key_id MUST appear in subject_key_ids) - the exact structural mirror of CC 3.4.5's capacity:* anti-self-emission RE | n/a (existence record, not a graded verdict - every mint site sets weight: None) | CIRISAgent/accord-agent | REGISTER |
| `trace_manifest:*` | n/a | None | — | n/a | CIRISAgent/accord-agent | DO NOT REGISTER |
| `trace_summary:*` | 4.5.8.3 (emission surface) + 3.3.7 (replication scoping) | False | — | n/a (multi-field feature vector, no single polarity) | CIRISAgent/accord-agent | REGISTER |
| `trust:*` | PROPOSE a new CC 2.4.1.x subsection (parallel to CC 2.4.1.2's owner_binding treatment) | True | a reserved delegation_purpose token (e.g. trust_root) + its admission predicate - NOT a namespace_registry.json row | n/a | CIRISPersist/persist | REGISTER ELSEWHERE |
| `ownership:*` | 3.2 (+2.4.1.2) | True | self-emission REQUIRED on the claiming side (attesting_key_id MUST equal the claimed owner) + single-owner cardinality + infra-only delegated_scope -  | n/a | CIRISPersist/persist | REGISTER |
| `config:*` | PROPOSE under CC 3.4 (self-loop reservation), analogically anchored at 4.4.3.4.3 | True | self-loop: attesting_key_id MUST equal attested_key_id (modeled on CC 3.4.3 system:* substrate self-report) | boolean-via-score (fixed 1.0 placeholder; presence-of-live-row is the signal) | CIRISServer/node | REGISTER |
| `capacity_assurance:*` | 3.4.12 | True | witness-reserved, subject-not-self, attester NOT IN {proposed steward, petitioner} - stronger than the base witness reservation age_assurance (CC 3.4. | enumerated | CIRISPersist/persist | REGISTER |
| `scores:*` | n/a | None | — | n/a | CIRISServer/node | DO NOT REGISTER |

- **`consent:*`** — Transmission-principle family. Normatively specified across ~300 lines of CC 3.3.1/3.3.5/3.3.7 + Policy K (CC 4.4.3.5.x) with a working reference implementation; what is unregistered is the manifest row, NOT the constitution.
  - _Schema note:_ the NamespaceEntry one-owning-component-per-family assumption (inherited from the CC 3.1 per-component model) does not fit a CC 3.3 family whose whole point is multi-actor emission (subject / producer / substrate / node). Surfacing this to whoever extends the generator matters more than the value chosen.
- **`trace:*`** — Sealed reasoning trace. persist's admission.rs:1291-1295 already states in-source that the registry entry + validator are 'pending CC ratification' - the code knows it is ahead of the constitution. Normative weight is split across four repos (persist=admission+promotion, edge=serve gate, server=consent route+policy-hash pin, agent/lens-core=capture/scrub/seal); a single owning_component undersells it.
- **`trace_manifest:*`** — NOT A PREFIX. trace_manifest:v1 is the value of a `schema` key inside a nested manifest object - one of two mutually exclusive payload shapes inside a trace:complete:v1 envelope, selected when canonical bytes exceed MAX_ATTESTATION_ENVELOPE_BYTES. Same category as CC 8.4.2.1's c2pa_manifest evidence_refs.kind: payload-level, not wire-level. Carried in this manifest as a family row ONLY so the round-1 seed card that proposed it has a place to record its correction.
- **`trace_summary:*`** — Denormalized scorer-input feature vector. Registering it matters for ONE reason above all: CC 3.3.7's trailing-colon-significant prefix matching means a grant scoped to 'trace:' does NOT cover 'trace_summary:'. Without a registry row, an operator has no discoverable way to learn that the scorer-input surface needs its own explicit attestation_prefixes entry.
- **`trust:*`** — STRUCTURAL MISFIT. The live mechanism is a delegates_to overlay with no `dimension` field at all; the CC 3.1 registry catalogs scores dimensions only and structurally cannot express a delegation_purpose value or a scope-token vocabulary. The literal 'trust:*' dimension strings that DO exist (trust:demo:v1, trust:reliability:v1) are test placeholders. Registering the placeholder would enshrine the wrong thing.
- **`ownership:*`** — Owner binding. The registry row is pure catch-up: the admission gates already exist and are wired into all three storage backends. Registering it makes the ALREADY-ENFORCED rule legible to authority_for() consumers and closes the split-truth risk before a second reader appears.
- **`config:*`** — Node configuration as CEG. Registering it is the ONLY thing that makes a third-party config claim about another node rejectable at admission rather than by accident of one consumer's read filter. _Rename ask:_ rename the flat dimension 'config:v1' to 'config:{key}' so the true information_type discriminator rides IN the dimension (watchlist:{id} precedent) instead of an untyped extra field
- **`capacity_assurance:*`** — Adult capacity ladder. Fully specified in CC 3.4.12 and largely implemented at CIRISPersist's write path; absent from the CC-3.1-vendored catalog both repos ship. Fix EITHER by extending build_cc_namespace.py to walk CC 3.3.x/3.4.x embedded families, OR by hand-appending capacity_assurance + age_assurance as two explicitly-non-generated catalog rows.
- **`scores:*`** — There is no such dimension family. 'scores' is the CC 2.4.2 attestation_type name; zero dimensions in CIRISServer/CIRISPersist/CIRISEdge are literally prefixed 'scores:'. The seed card's illustrative leaves (scores:medical, scores:safety) exist nowhere in code, and its 'lens' owning_component is unsupported (crates/ciris-lens-core/src/scores/ is an unrelated self-read facade over DetectionEvent rows). If a genuine domain-scoring family is wanted later it MUST use a non-colliding prefix (e.g. domain_score:{domain}) - 'scores:' is permanently unusable as a dimension namespace.

### 10.4 The CC-amendment ask

1. AMEND tools/build_cc_namespace.py to walk CC 3.2 / CC 3.3 / CC 3.4.11-3.4.12 embedded family tables in addition to the '### 3.1.N' headings - or add a supplemental, explicitly hand-maintained non-generated families table. Until then EVERY family defined outside CC 3.1 is invisible to authority_for(), and the generator's own dead capacity_assurance RESERVED_RULES entry is the proof the omission was unintended.

2. RATIFY CC 3.4.14 (or equivalent) for trace-self-attestation: self-emission MANDATORY, the inverse polarity of CC 3.4.5. CIRISPersist already enforces it as a 'machine-checkable interim... pending CC ratification' in its own source comment.

3. ADD a CC 2.4.1.x subsection defining a reserved delegation_purpose for trust-root attachment (parallel to CC 2.4.1.2's owner_binding), including whether an infra-charter self-loop is a carve-out from CC 4.1.1's cycle-rejection rule and CC 4.1.2's no-self-declaration discipline - today the family's core admission mechanism is in unresolved tension with two ratified anti-patterns.

4. ADD a CC 2.4.1.1 rule-5 (or an explicit CC 4.2.6-style mechanism generalized to ordinary node ownership) so the CC 3.2 'No permanent ownerless lock (MUST)' has an admission path. Minimal primitive-preserving alternative: seed the deployment's WA/recovery key_id into subject_key_ids at owner-binding genesis so the EXISTING rule-2 direct-subject-revocation path admits a WA withdraws with no new primitive.

5. ADD admission-time (CCS-side) enforcement of consent:replication:v1's two structural constraints (witness_relation==self, cohort_scope==federation), today honored only by producer discipline - and route it through the normal CC 4.5.1 amendment process rather than landing it as a silent bugfix, since it is new enforcement surface.

6. NAME a discoverability registry document for operator-coined consent:{kind} leaves, the way CC 4.5.1.1 names WITNESS_KIND_REGISTRY.md for testimonial_witness:{kind} / hard_case:{kind}. The open-vocabulary branch currently has no discoverability artifact for this family.

7. CLARIFY whether dma:*/conscience:* verdicts embedded in a trace's components[] retain independent CEG standing or are CEG-invisible payload copies - this decides whether Policy-I-style composition rules can see them, and it is adjacent to the standing CEG-replication anti-pattern finding.

8. CORRECT the CC 1.13.5 cross-reference drift: CC 4.4.3.4.3, part_6, and CIRISPersist doc comments all cite '[CC 1.13.5] infrastructure must not have agency', but this checkout's CC 1.13.5 is the operational-language T1-T4 gate and the quoted language appears nowhere in part_1_foundation.md. Enforceability is unaffected (CC 4.4.3.4.3 carries the normative text and the wire gate) but three repos cite a section that does not say what they claim.

---

## 11. Field standardization — the compression pass

> **THE COMPRESSION PASS. Same field => same processor, by registry rule rather than review vigilance. A new family REFERENCES a canonical field + its standard_relationship instead of re-specifying a processor.**

_0.3.0 clusters are drawn from the 9 UNREGISTERED families and cross-linked to already-registered demanders where the alias is exact. Back-filling clusters across all 104 families is a 0.4.0 task._

**Tiers.** `universal` = EnvelopeCore/Attestation-base; present on every claim; ONE processor, no opt-out · `standard` = registry-defined shared field; opt-in per family; ONE processor wherever carried · `bespoke` = family cargo; no processor; MUST NOT be silently promoted to standard

| Canonical field | Tier | Aliases (family → name) | The ONE processor | Asymmetry |
|---|---|---|---|---|
| `cohort_scope` | universal | consent:*→`payload.audience`; trace:*→`audience (covering grant) -> cohort_scope (stamped)`; config:*→`cohort_scope (hardcoded FEDERATION)` | `CIRISPersist/src/federation/types.rs#cohort_scope (crypto_tier/suppresses_holds_bytes) + src/engine.rs#promote_consented_backlog (the stamping site)` | axiomatic_intent |
| `subject_key_ids` | universal | capacity_assurance:*→`attested_key_id (older ladder shape)`; ownership:*→`attested_key_id / node_key_id (server wire)`; trace_summary:*→`agent_key_id`; config:*→`extra.key suffix (e.g. federation.peer_sideband.<peer_key_id>)` | `CIRISPersist/src/federation/admission.rs#resolve_withdraws_admission_rule` | axiomatic_intent |
| `valid_until` | standard | ownership:*→`delegation_valid_until`; trust:*→`delegation_valid_until (folded to expires_at)`; consent:*→`payload.valid_until`; capacity_assurance:*→`valid_until (MUST be <= T2 review cadence)` | `CIRISPersist/src/federation/admission.rs#delegation_valid_until_lapsed (delegation form) + #check_adult_incapacity_binding (bounded form)` | axiomatic_intent |
| `fresh_as_of` | universal (PROPOSED - does not exist on the wire) | (persist)→`last_seen_at (advisory, unsigned - admission.rs:1795)` | `PROPOSED - monotonic-max merge + signed touch-claim; no processor exists today` | axiomatic_intent |
| `references_attestation_id` | universal | config:*→`extra.version / extra.previous_version`; trust:*→`recovers`; consent:*→`supersedes target (grant narrowing)`; ownership:*→`supersedes target (transfer)` | `ciris-persist/src/federation/envelope.rs#EnvelopeCore.references_attestation_id (typed)` | axiomatic_intent |
| `attestation_prefixes` | standard | consent:*→`payload.attestation_prefixes`; trace:*→`attestation_prefixes entry 'trace:'`; trace_summary:*→`attestation_prefixes entry 'trace_summary:'`; scores:*→`attestation_prefixes entry 'scores:' (permanently vacuous)` | `CIRISPersist/src/federation/consent_grammar.rs#covers - the ONE processor, consumed at promotion (persist) and at serve (edge)` | axiomatic_intent |
| `delegated_scope` | standard | ownership:*→`scope[]`; trust:*→`delegated_scope (infra:* vocabulary)`; trace:*→`infra:serve (the serve-gate credential)`; config:*→`extra.scope (ConfigScope) - FALSE FRIEND, not this field` | `CIRISPersist/src/federation/admission.rs#check_node_agency_admission (+ scopes_are_infra_only, mirrored producer-side in CIRISServer)` | axiomatic_intent |
| `delegation_purpose` | standard | ownership:*→`owner_binding (CC) / responsible_for (internal PURPOSE) / ownership:responsible_party:node:v1 (internal DIMENSION)`; trust:*→`(absent - the family does not set or check it)` | `CIRISPersist/src/federation/admission.rs#is_owner_binding_envelope` | logical_defect |
| `content_hash` | standard | trace_manifest:*→`manifest.content_hash`; trace_summary:*→`extraction_manifest_hash (TRACE_SUMMARY_EXTRACTION_SHA256)`; (registered)→`manifest_hash (build:registered / provenance:build_manifest)` | `CIRISPersist/src/trace_summary_contract.rs#extraction_manifest_sha256 (contract form); NO processor for the content form` | logical_defect |
| `attesting_key_id` | universal | trace_summary:*→`signing_key_id -> agent_key_id`; capacity_assurance:*→`attester (independence-checked)` | `CIRISPersist/src/federation/admission.rs#check_reserved_prefix_admission` | axiomatic_intent |

**`cohort_scope`** — who can SEE. `audience` inside a consent grant is not a different field - it is the PRE-STAMP form of cohort_scope, which promote_consented_backlog copies onto the promoted row.
  - _Obligation:_ carrying `audience` OBLIGATES the promoter to stamp it into cohort_scope and OBLIGATES the emitter to accept that the row's visibility is grant-derived, not producer-chosen. Carrying cohort_scope in {self, family} OBLIGATES structural invisibility (no holds_bytes row, no propagation).
  - _Asymmetry (axiomatic_intent):_ consent narrows, never widens: a grant's audience may only tighten what a producer already permitted.
  - **RENAME:** consent:*/trace:* `audience` SHOULD be documented as an alias of cohort_scope, not a distinct concept
**`subject_key_ids`** — the party the claim is ABOUT, and therefore the party holding CC 2.4.1.1 rule-2 revocation authority.
  - _Obligation:_ naming a party here CONFERS revocation authority on them - which is why ownership:* and capacity_assurance:* deliberately do NOT use it (the owned node has no agency; the ward's revocation route is the restoration petition, not a wire withdraws), and why config:* burying a peer id in an untyped key string means no CI-aware tool can enumerate 'every record about peer P'.
  - _Asymmetry (axiomatic_intent):_ conferral is one-way: adding a subject can only ADD revocation authority, never remove the producer's. Also forfeits local-tier eligibility (CC 5.3.2.4.1) - a deliberate cost.
  - **RENAME:** config:*: hoist the semantic subject out of extra.key into subject_key_ids OR document explicitly that these are non-claims about third parties
**`valid_until`** — temporal UPPER bound - after this instant the claim is as dead as a withdrawn one.
  - _Obligation:_ carrying it OBLIGATES expiry-as-tombstone (already true for delegates_to since persist v19.0.0) and, where a review cadence exists, OBLIGATES the bound to be <= that cadence. It does NOT obligate an active sweep - and capacity_assurance:* is the family where that omission is load-bearing.
  - _Asymmetry (axiomatic_intent):_ expiry must fail toward LESS authority (capacity_assurance's fail-open-to-liberty is the sharpest case); an implementation that treats a lapsed bound as 'still live pending review' inverts the axiom.
**`fresh_as_of`** — temporal LOWER bound, dual to valid_until. See the freshness_floor section.
  - _Obligation:_ carrying it OBLIGATES monotonic-max merge and admission rejection of any value > now+skew; it NEVER substitutes for a family's own renewal requirement.
  - _Asymmetry (axiomatic_intent):_ monotonic max is deliberately one-directional (anti-rollback); a 'latest wins' merge that could DECREASE the floor would let a stale replica resurrect a dead liveness claim.
**`references_attestation_id`** — the universal tombstone/target link: what this claim replaces, retracts, or repairs.
  - _Obligation:_ carrying a supersede/withdraw relation OBLIGATES using this typed field rather than a private chain. config:*'s custom version/previous_version pair is the exemplar violation: it re-implements a typed primitive in untyped extra, so only config-aware readers can follow the chain.
  - _Asymmetry (axiomatic_intent):_ anti-rollback: retraction projects Global and must OUTRUN assertion; a private chain that only one module can read defeats that by construction.
  - **RENAME:** config:* version/previous_version -> RENAME onto references_attestation_id + supersedes
**`attestation_prefixes`** — the prefix set a node consents to replicate; trailing ':' significant, matched by exact string prefix against `dimension`.
  - _Obligation:_ carrying an entry OBLIGATES that the entry names a real dimension namespace. It does NOT obligate transitivity: 'trace:' covering 'trace_summary:' is FORBIDDEN by construction. An entry that can never match any dimension is a defect the author-time validator must reject.
  - _Asymmetry (axiomatic_intent):_ non-transitive by design; 'helpfully' widening the match to include derivative prefixes would silently export a surface the operator never granted.
**`delegated_scope`** — capability tokens carried on a delegation; infra:* vs agency:* is a reserved two-prefix split.
  - _Obligation:_ carrying a node-only target OBLIGATES infra:*-only scopes and attenuation (child subset of parent). Carrying infra:serve OBLIGATES the holder be a pure node-role delegate with NO agency:* on the same delegation.
  - _Asymmetry (axiomatic_intent):_ 'infrastructure must not have agency' is deliberately one-directional: agency keys may be denied infra scopes by policy, but infra keys are CRYPTOGRAPHICALLY denied agency.
  - **RENAME:** config:* `scope` (ConfigScope::Local|Identity) collides with the typed EnvelopeCore.scope path - RENAME to config_scope
**`delegation_purpose`** — which sub-relation a delegates_to edge expresses; the ONLY discriminator that makes purpose-filtered reads (owner_of) sound.
  - _Obligation:_ any purpose-filtered graph read OBLIGATES filtering on this field, not on a family-internal dimension string. CIRISPersist#378 is the precedent: the internal-dimension-only gate was bypassable via emit_attestation_self until delegation_purpose was added as a second discriminator.
  - _Asymmetry (logical_defect):_ trust:* reads delegates_to edges WITHOUT purpose-filtering, so a bare act-on-behalf edge can satisfy a trust-root check - the same class of bug #378 fixed for ownership.
**`content_hash`** — a sha256 commitment to bytes or to a contract.
  - _Obligation:_ carrying a content commitment OBLIGATES a resolvable retrieval path OR an explicit declaration that the row is integrity-only and NOT content-equivalent. trace_manifest:* carries the commitment with neither - the gap.
  - _Asymmetry (logical_defect):_ commitment without retrieval is a one-directional hash: verifiable if you already have the bytes, useless if you do not.
**`attesting_key_id`** — who authored the claim - and, for a whole class of families, the field an equality check runs against.
  - _Obligation:_ a family MUST declare its self-emission polarity: REQUIRED (ownership:*, trace:*, config:* proposed), FORBIDDEN (capacity:*, capacity_assurance:*), or OPEN. Silence is not a third option - it is how config:* ended up spoofable.
  - _Asymmetry (axiomatic_intent):_ the two polarities are mirror axioms, not a convention: anti-Goodhart forbids self-emission where a score confers advantage; self-attestation is REQUIRED where the claim IS the act of taking responsibility.

---

## 12. Duality audit — mechanism closed, values not

> **Mechanism must be closed under duality; VALUES must not be.**

_Scope: the 9 UNREGISTERED families (0.3.0 addendum). Known-closed dualities are not re-reported.._ Known-closed dualities are not re-reported: `valid_until<->fresh_as_of`, `read<->write`, `grant<->revoke`, `join<->leave`, `key registration<->revocation`, `pre_rotation_commitment<->recovers`, `trust<->un-trust`, `role conferral<->withdraw_canonical_role`, `push<->pull`, `assertion<->negative-assertion`, `absent<->negative`.

### 12.1 The affirmation-verb question

the structural vocabulary is RETRACTION-ONLY (SCORES / DELEGATES_TO / SUPERSEDES / WITHDRAWS / RECANTS - three ways to take a claim back, zero to reaffirm), distinct from re-emit (=replacement) and from fresh_as_of (=alive, not endorsed).

| Family | Needs an affirmation verb? |
|---|---|
| `consent:*` | NO affirmation verb. A grant is producer-owned, so re-emitting an identical grant with a fresh asserted_at IS the affirmation and costs the producer nothing they should not be paying. What consent:* actually needs is fresh_as_of, so a consumer can tell 'still live' from 'never touched since 2024'. |
| `capacity_assurance:*` | NO - and adding one would be SYMMETRIZING AN AXIOM. CC 3.4.12 deliberately requires 'a fresh, attributable, independently-attested renewal on record' precisely so a steward cannot prolong control cheaply. A one-click 'reaffirm' verb is exactly the conservatorship-abuse affordance the clause forecloses. |
| `ownership:*` | NO verb, but YES to fresh_as_of - and this is the family where it is load-bearing: distinguishing 'owner alive but quiet' from 'owner provably dead' is the missing input to the unimplemented CC 3.2 no-permanent-ownerless-lock reclaim path. |
| `trust:*` | NO verb, YES to fresh_as_of. An untouched trust edge is today indistinguishable from an abandoned one, and CIRISEdge#386 leg B makes a live routing decision on that edge. |
| `trace:*` | NO. A trace is an existence record about a past event; reaffirming it is meaningless. |
| `trace_manifest:*` | NO (inherits trace:*). |
| `trace_summary:*` | NO - it is a re-computable derived projection; recomputation is the affirmation. |
| `config:*` | NO - the version fold already gives last-write-wins semantics. |
| `scores:*` | n/a. |

### 12.2 Logical gaps — the dual is missing and its absence is a defect

| Operation | Missing dual | Family | Severity |
|---|---|---|:--:|
| ownership bind | WA-adjudicated reclaim | `ownership:*` | high |
| config set | a delete visible to generic consumers | `config:*` | medium |
| consent grant promotion (local->federation, cohort_scope stamped) | narrowing an ALREADY-promoted row when the covering grant is withdrawn | `trace:* / consent:*` | medium |
| capacity_assurance valid_until admission bound | an active lapse sweep | `capacity_assurance:*` | high |
| attestation_prefixes accept | reject an unmatchable prefix | `scores:*` | medium |
| trace_summary derive | invalidate on source tombstone | `trace_summary:*` | medium |
| trace_manifest content commitment | content retrieval | `trace_manifest:*` | medium |
| trust charter genesis | external witness at genesis (it exists at recovery) | `trust:*` | high |
| consent:replication producer-side constraint enforcement | substrate-side re-check | `consent:*` | high |

- **ownership bind ↔ WA-adjudicated reclaim** (`ownership:*`, logical_defect) — CC 3.2 states 'No permanent ownerless lock (MUST)' and points at CC 4.2.6 by analogy, but CC 2.4.1.1's four withdraws paths admit no third party against a LIVE incumbent, and CIRISPersist v21.4.0 contains zero seizure/reclaim/ownerless handling. A node whose owner dies is bricked for federation purposes with no wire path back.
  - _Minimal fix:_ seed the deployment's WA/recovery key_id into subject_key_ids at owner-binding genesis so the EXISTING rule-2 direct-subject-revocation path admits a WA withdraws - closes a MUST with no new primitive.
- **config set ↔ a delete visible to generic consumers** (`config:*`, logical_defect) — the dual exists twice in incompatible forms: an app-level ConfigValue::Null tombstone (visible only to config.rs-aware readers) and genuine withdraws/recants (visible fabric-wide). The default path is the invisible one, so a generic CEG consumer sees a live, unrevoked row for a deleted key.
  - _Minimal fix:_ emit a structural withdraws against the prior attestation_id on every delete_config call, keeping the Null value as a read-optimisation only.
- **consent grant promotion (local->federation, cohort_scope stamped) ↔ narrowing an ALREADY-promoted row when the covering grant is withdrawn** (`trace:* / consent:*`, logical_defect) — CC 3.3.7 attaches a cessation obligation to an explicit retract/supersede, but no mechanism narrows or tombstones a row already stamped and served. Note the boundary: 'un-see' is impossible and MUST NOT be attempted (that would be symmetrizing the anti-rollback axiom); the missing dual is the enforceable CEASE, not a retroactive narrowing.
  - _Minimal fix:_ on grant withdraw, emit a supersede that re-stamps cohort_scope narrower and require the serve gate to re-evaluate live grants per request rather than trusting the stamped value alone.
- **capacity_assurance valid_until admission bound ↔ an active lapse sweep** (`capacity_assurance:*`, logical_defect) — THE COMPOSITE DEFECT SHAPE. The fail-open-to-liberty axiom is enforced in ONE direction only: admission refuses an over-long window, but nothing flips a live binding non-live on wall-clock lapse. Restoration therefore depends on a reader consulting liveness - i.e. on someone looking - which is precisely what 'no action required of the recovered person' forbids.
  - _Minimal fix:_ a reconcile sweep that marks lapsed bindings non-live and emits the hard_case:* audit row, independent of any read.
- **attestation_prefixes accept ↔ reject an unmatchable prefix** (`scores:*`, logical_defect) — normalize_prefixes trims, dedupes and sorts, but never validates. A token that can never match any dimension ('scores:' - the attestation_type name) is accepted, hybrid-signed into a durable federation-tier governance object, and evaluated as a no-op at BOTH live enforcement points. Structurally identical to a carried-but-unprocessed field, except the field is the whole grant entry.
  - _Minimal fix:_ reject or warn on any entry equal to a reserved wire-primitive name, and on any entry matching no known dimension family.
- **trace_summary derive ↔ invalidate on source tombstone** (`trace_summary:*`, logical_defect) — a derived, promotable projection with no rule tying its life to the raw trace_events rows it summarises. Tombstoning the source leaves a promoted summary standing - constitution-silent, and the summary carries the scorer-relevant features.
  - _Minimal fix:_ make the derived row carry references_attestation_id to its source and fold source retraction into the projection.
- **trace_manifest content commitment ↔ content retrieval** (`trace_manifest:*`, logical_defect) — integrity-only commitment with no fountain/degradable-plane retrieval, so CC 3.1.8.4's F-3 detector degrades to a bare existence hash for exactly the longest, highest-signal reasoning runs.
  - _Minimal fix:_ either ship the retrieval path or make the manifest form explicitly non-admissible as detector input.
- **trust charter genesis ↔ external witness at genesis (it exists at recovery)** (`trust:*`, logical_defect) — recovery requires an m-of-n pre-committed ceremony; genesis requires nothing but the root's own signature. The strong check guards the second event and not the first, and the self-loop is the degenerate 1-hop cycle CC 4.1.1 tells substrates to reject.
  - _Minimal fix:_ require a co-attestation reference at charter genesis, or ratify an explicit CC 4.1 carve-out naming infra-charter self-loops.
- **consent:replication producer-side constraint enforcement ↔ substrate-side re-check** (`consent:*`, logical_defect) — witness_relation==self and cohort_scope==federation are enforced where the object is WRITTEN and never where it is READ. The CC 3.4.7 three-actor pattern exists because producer discipline is not a substrate guarantee: a forged grant from a hostile producer is admitted.
  - _Minimal fix:_ two admission checks in CIRISPersist, routed through the CC 4.5.1 amendment process (new enforcement surface, not a bugfix).

### 12.3 Axiomatic asymmetries — directions that MUST be preserved

> The specific failure mode this table exists to prevent is a future reviewer or agent **helpfully symmetrizing an axiom**. Unmarked asymmetry is indistinguishable from a bug.

| Rule | Direction | CC ref | Why symmetrizing breaks it |
|---|---|---|---|
| trace:* SERVE is default-deny | capability required to RECEIVE; never required to send | CEG_REPLICATION_MODEL.md sec.1 + hash-pinned in tests/replication_policy_gate.rs (E3); CC 4.4.3.4.3 for the infra:serve credential | trace:* is the ONE family of 104 forbidden the default-public posture every other Attestation-riding family uses. Making serve symmetric with the rest 'for consistency' silently publishes sealed reasoning content. |
| self-emission REQUIRED (trace:*, ownership:*, config:* proposed) vs FORBIDDEN (capacity:*, capacity_assurance:*) | opposite polarities on the same equality check | CC 3.4.5 vs CC 3.2 / persist admission.rs ('the inverse polarity of capacity:*'s anti-self rule') | a reviewer normalising both to one rule destroys either the anti-Goodhart floor (if self-emission is allowed everywhere) or the act of taking responsibility (if forbidden everywhere - nobody else can sign that you own your node). |
| absence of capacity_assurance resolves to CAPACITY; absence of age_assurance resolves to PROTECTION | two sibling ladders with deliberately OPPOSITE absence defaults | CC 3.4.12 ('Getting this backwards... would be catastrophic; it is forbidden') vs CC 3.4.11 | 'harmonising' the two ladders' defaults would make every un-attested adult presumptively incapacitated. The constitution pre-emptively forbids exactly this edit. |
| fail-open-to-liberty on lapse | the steward must ACT to retain control; the ward need not act to regain it | CC 3.4.12 | requiring the ward to petition for restoration (the 'symmetric' design) is the documented conservatorship-abuse failure mode. |
| the steward is excluded from the restoration denominator | one party has standing to bind and none to unbind | CC 3.4.12 | giving the steward a vote in ending their own authority is self-dealing by construction. |
| ownership fails CLOSED on cardinality != 1 | ambiguity yields NO owner, never a picked winner | CC 3.2 | a deterministic lexicographic tie-break looks like robustness and is actually a silent laundering of contested ownership. |
| trust is inbound, consent is outbound | the user may un-trust a root; the root cannot un-trust the user | CC 3.2 ('There is no single "trust the community" switch') | collapsing them makes 'attach a trust root' silently mean 'consent to replicate to it' - two independent axes fused into one switch. |
| multi-subject consent revocation is OR, never quorum | any ONE subject's withdraws is terminal for ALL | CC 4.4.3.5.4 (explicitly: no majority-rules, no all-subjects-must-agree) | quorum-softening is how a single person's revocation gets outvoted by co-subjects who benefit from the data staying up. |
| a consent revocation may TRANSIT local tier but never REST there | retraction carries a tier obligation ordinary content does not | CC 5.3.2.2 / CC 5.3.2.4.1 (24h promotion SLA, AV-61) | this is anti-rollback made operational: retraction must outrun assertion, so treating a revocation like any other row lets it sit un-promoted while the thing it revokes is already federated. |
| attestation_prefixes matching is non-transitive (trailing ':' significant) | 'trace:' does not cover 'trace_summary:' | CC 3.3.7 | a 'helpful' widening to include derivative prefixes exports the denormalized scorer-input surface under a grant the operator wrote for raw traces. |
| infrastructure must not have agency | infra keys are CRYPTOGRAPHICALLY denied agency:*; agency keys are only denied infra:* by policy | CC 4.4.3.4.3 (cited as CC 1.13.5 in three repos - see the cross-reference-drift ask) | making the denial mutual and merely-policy-level removes the wire-checkable guarantee that a serving node cannot act. |
| capacity misattestation is adjudicated, never slashed | protection is cheaper than punishment | CC 3.4.12 / CC 3.1.9.2 | routing a clinical misjudgement into slashing:* deters the witnesses the ladder depends on. |
| protected non-transferable domains are WALLS, not gradients | no attested band ever unlocks them | CC 3.4.12 (apophatic floor -> prohibited:*) | the whole point of an apophatic bound is that harm is enumerable and absolute while beneficence is a gradient; making the floor score-sensitive reintroduces the trade. |
| the node signs config on the authenticated human's behalf | authorship and authority are separated | (no CC grounding - implementation choice) | NOT AN AXIOM. Recorded here so it is not mistaken for one: extra.updated_by is a plaintext string a compromised node process can set at will. Flagged as a trust-boundary weakness, not a preserved direction. |

**Coverage.** asymmetry_kind is populated for every 0.3.0 addendum row (families, matrix rows touched, standardization clusters). The 0.2.0 rows it does not touch are UNMARKED, and unmarked asymmetry is indistinguishable from a bug - back-filling them is the first task of 0.4.0.

---

## 13. Freshness floor — the signed liveness lower bound

> `fresh_as_of` (PROPOSED - does not exist on the wire today) — a signed temporal LOWER bound: 'this object was demonstrably alive no earlier than T'. Dual to the existing upper bounds (valid_until / expires_at / delegation_valid_until / deletion_window).

**Decomposition (load-bearing).** MERGE = `monotonic_max`: monotonic max - deterministic, total, anti-rollback, and therefore algebra-legal (a pure fold over two values). VALUE PRODUCTION = a signed touch-claim. now() is NOT pure, so producing the value is an ATTESTATION, never a transform opcode. This is why 'reading emits a claim' is CEG-native here rather than a special case.

| Property | Value |
|---|---|
| merge_rule | `monotonic_max` |
| signer_forms | `self_touch`, `witness_touch`, `n_of_m_cosigned` |
| admission_guard | reject > now+skew |
| coalescing | round(precision) on the touch value so same-bucket touches dedupe on the wire |
| privacy_row | touch-claims are cohort-scoped and consent-gated - an unrestricted read-receipt trail is an access-pattern surveillance surface, and for trace:* (already the one recipient-gated family) it would leak exactly who is reading whose reasoning. |
| existing gap | CIRISPersist has `last_seen_at`, but admission.rs:1795 states it is 'advisory liveness, not signed material'. fresh_as_of is its signed successor, not a duplicate. |

| Family | Needs it? | Signer form |
|---|---|---|
| `ownership:*` | HIGHEST VALUE. Distinguishing 'owner alive but quiet' from 'owner provably dead' is the missing input to CC 3.2's unimplemented no-permanent-ownerless-lock reclaim. An owner-binding whose owner has not signed anything in years is currently indistinguishable from a fresh one. | self_touch, escalating to n_of_m_cosigned for a death finding |
| `trust:*` | an untouched trust edge is indistinguishable from an abandoned one, and CIRISEdge#386 leg B makes a live routing decision on it. The charter especially: root-hood asserted once in 2025 and never touched should not read the same as a live root. | self_touch (edge), witness_touch (charter) |
| `consent:*` | a standing replication grant with no expiry is currently 'live forever'. fresh_as_of lets a consumer distinguish a maintained grant from an abandoned one WITHOUT weakening the rule that only an explicit supersede/withdraw narrows it. Also gives the 24h promotion-SLA and deletion-SLA watchers a signed clock input rather than an advisory one. | self_touch |
| `capacity_assurance:*` | ADMITTED WITH A GUARD. A freshness floor is useful for liveness of the ward's inalienable channel and the champion's key, but it MUST NOT be accepted anywhere the constitution requires 'a fresh, attributable, independently-attested renewal' - substituting a cheap touch for a renewal is exactly the axiom-symmetrising failure this audit is hunting. | witness_touch only; NEVER self_touch by the steward |
| `trace:*` | WEAK - corpus liveness only (is this node still serving the trace it advertised?). A per-trace floor is meaningless; a per-corpus floor may be useful to edge's advertise path. | self_touch |
| `trace_summary:*` | NO - it is re-computable from source; recomputation timestamps are a projection concern, not a wire claim. | n/a |
| `config:*` | NO - the version fold already provides recency, and a touch trail on config reads is a surveillance surface with no consumer. | n/a |
| `trace_manifest:*` | NO (inherits trace:*). | n/a |
| `scores:*` | n/a. | n/a |

_Asymmetry (axiomatic_intent):_ monotonic-max is deliberately one-directional. A merge that could DECREASE the floor would let a stale replica resurrect a dead liveness claim - the same anti-rollback logic that makes tombstones project Global.

---

## 14. Field transforms — the total transform algebra

> **STRICTLY TOTAL. Named opcodes, fixed arity, NO loops, NO recursion, NO user-defined functions. Composition is a finite DAG, so the registry row IS the termination witness.**

**Why total.** a transform sits in the admission/serve path; a non-terminating one wedges the gate, and a Turing-complete dialect could express the very flows this system makes unrepresentable. Precedent: Bitcoin Script (no loops); EVM (only quasi-TC via gas); FHIRPath ('entirely declarative, no imperative aspects'); Confluent data contracts (non-TC CEL/JSONata).

- SEPARATE from version-migration rules - Confluent keeps data rules and migration rules distinct; fusing them yields an unauditable registry.
- SEPARATE from heavy computation - the trace PII scrubber (NER+regex), the trace_summary extractor, RATCHET detectors and scorers are NOT opcodes. They are pinned by contract hash, not expressed in the algebra.
- SEPARATE from access control - a transform changes what a field BECOMES on an egress path; it never decides WHETHER the row is served (that is cohort_scope/consent/capability).

### 14.1 Opcodes

| Opcode | Arity | In → Out | Determinism | Precedent |
|---|:--:|---|---|---|
| `truncate` | 1 | string|bytes → string|bytes | pure, length-bounded | generic |
| `prefix` | 1 | string → string | pure | generic |
| `suffix` | 1 | string → string | pure | generic |
| `bucket` | 1 | number|timestamp → enum | pure over a fixed edge list; edges are registry data, not code | k-anonymity generalization |
| `round` | 1 | number|timestamp → number|timestamp | pure; also the coalescing primitive for fresh_as_of | differential-privacy coarsening; CIRISServer correlation.rs already coarsens lat/long |
| `concat` | 2 | string,string → string | pure | generic |
| `redact` | 1 | any → null|placeholder | pure | generic |
| `strip_field` | 1 | json-pointer → object | pure; ALREADY IN the consent grammar as RestrictionOp::StripField | CIRISPersist consent_grammar.rs (shipped) |
| `salted_hash` | 2 | bytes,salt → digest | pure given the salt; salt provenance must be declared | SD-JWT selective disclosure |
| `commit` | 1 | bytes → commitment | pure (Pedersen or sha256 form); integrity-only, NOT an availability guarantee | Pedersen commitments; trace_manifest content_hash is the sha256 form |
| `nullifier` | 2 | epoch,scope → digest | pure; one identity yields one nullifier per (epoch,scope), enabling double-emit detection without identity | Semaphore |
| `bbs_derive` | 1 | signed-credential → derived-proof | randomised but verifiable; selective disclosure over a signed set | BBS+ signatures |
| `gte` | 2 | number|timestamp,threshold → bool | pure predicate - discloses the ANSWER, not the value | age-over-18 predicates |
| `lt` | 2 | number|timestamp,threshold → bool | pure predicate | as above |
| `in_range` | 3 | number,lo,hi → bool | pure predicate | as above |

### 14.2 Per-family transform rows

> Only rows the family's semantics actually justify. **An unjustified transform is worse than none.**

| Family | Field | Egress path | Transform | Asymmetry |
|---|---|---|---|---|
| `consent:*` | `restrictions[].op=strip_field` | promotion (local->federation signing) | strip_field(json_pointer) | axiomatic_intent |
| `trace:*` | `trace.llm_calls[].prompt` | promotion | strip_field(/trace/llm_calls/*/prompt) | axiomatic_intent |
| `trace:*` | `trace body (PII)` | client capture, pre-signature | NONE - NOT AN OPCODE | n/a |
| `trace_manifest:*` | `trace (inline body)` | mint, when canonical bytes exceed the size cap | commit(sha256) + byte_len + component_count | logical_defect |
| `trace_summary:*` | `feature_vector` | derivation | NONE - NOT AN OPCODE | n/a |
| `capacity_assurance:*` | `level/band` | serve to a downstream capability gate | gte / in_range predicate - disclose the ANSWER ('is this domain currently incapacitated?') not the clinical band, level, or assessor identity | axiomatic_intent |
| `capacity_assurance:*` | `attesting_key_id` | any | NO nullifier, NO anonymisation | axiomatic_intent |
| `ownership:*` | `attesting_key_id` | any | NONE | axiomatic_intent |
| `trust:*` | `all` | any | NONE | axiomatic_intent |
| `config:*` | `value` | hypothetical replication | NONE - AND DO NOT ADD ONE | logical_defect |
| `scores:*` | `n/a` | n/a | n/a | n/a |

- **`consent:*` / `restrictions[].op=strip_field`** — SHIPPED and constitutionally grounded (CC 3.3.7 restriction grammar). The enforcement point is deliberately promotion, not serve - a stripped field never enters the signed federation-tier bytes.
  - _Asymmetry:_ strip at promotion is irreversible by design; there is no un-strip dual and there must not be.
- **`trace:*` / `trace.llm_calls[].prompt`** — the shipped worked example in consent_grammar.rs; the family's semantics (sealed reasoning) justify redacting the highest-sensitivity leaf while preserving the trace skeleton.
- **`trace:*` / `trace body (PII)`** — the NER+regex scrubber is heavy computation with hard-fail-never-partial semantics. Declaring it as a registry transform would put an unbounded ML pass in the admission path. Pinned by module contract, kept out of the algebra deliberately.
- **`trace_manifest:*` / `trace (inline body)`** — the oversize path IS a commit opcode in all but name. Declaring it as such makes the integrity-only/availability-absent distinction machine-visible rather than a code comment.
  - _Asymmetry:_ commit has no retrieval dual today - see duality_audit.
- **`trace_summary:*` / `feature_vector`** — the extraction is heavy computation governed by TRACE_SUMMARY_EXTRACTION_SHA256. An unjustified transform here would be worse than none: the feature vector's whole value is being the faithful, contract-pinned reduction.
- **`capacity_assurance:*` / `level/band`** — the ONLY genuinely justified privacy transform in the addendum. A delegates_to admission gate needs a boolean; it does not need a clinical finding. CC 3.4.12's actor-access requirements (steward / champion / WA quorum) are about who may see the FULL row - the predicate form is what everyone else should get.
  - _Asymmetry:_ the predicate must never be invertible into the band; and it MUST NOT be offered for the protected non-transferable domains at all (those are walls, not queries).
- **`capacity_assurance:*` / `attesting_key_id`** — accountability is load-bearing: misattestation routes to moderation:capacity_misattestation, which requires an attributable attester. Anonymising the witness would make the adjudication dimension unenforceable.
- **`ownership:*` / `attesting_key_id`** — the owner's signature IS the claim; redacting or deriving over it voids the object. A transform here is a category error.
- **`trust:*` / `all`** — the charter must be plaintext-legible ('the trust root cannot be an opaque blob'); the trust edge must be peer-visible for CIRISEdge#386 leg B to verify rooting.
- **`config:*` / `value`** — the temptation is to redact auth.admin_key_ids on egress. That would be an unjustified transform papering over the actual defect: the row should never be federation-scoped in the first place. Fix cohort_scope, do not add a transform.
- **`scores:*` / `n/a`** — no family exists.

_Deferred:_ nullifier(epoch=voting_window, scope=contribution_id) for anonymous voting is the canonical worked example of a registry-declared transform, but its demander (vote:{contribution_id}) is a REGISTERED family outside this addendum's scope - noted so 0.4.0 picks it up rather than re-deriving it.

---

## Appendix B — honest accounting

### Registered universe (95)

Coverage: **95/95 families** carry a round-2 analysis (92 merged onto a round-1 seed + 3 round-2-first). **0 missing.**

No-round-1-seed families (analyzed round-2-first, round-1 superset spec still owed):

- `attestation:hardware_rooted`
- `key_boundary:{scope}`
- `manifold_conformity:{cohort}`

Families carrying flags (needs-human-review / constitution-silent / implementation-gap): **93/95**. Per-family flags are listed in section 9 and in `families.<prefix>.round2.flags`.

### Unregistered addendum (9) — v0.3.0

Coverage: **9/9 families** carry a round-2 analysis. **0 missing.** All 9 were analysed **round-2-first**: none had a round-1 seed card (the round-1 finder failed for this set), so each was built from the Constitution plus the live CIRISPersist v21.4.0 / CIRISEdge v14.4.0 / CIRISServer implementations. Round-1 superset specs are owed for all 9; the spec fields recorded in `families.<prefix>` are derived from the round-2 walk, not from an independent seed.

**All 9 carry flags.** Two carry a `seed-wrong-archetype` verdict severe enough that the correct action is *not to register the family at all*:

| Prefix | Verdict | Why |
|---|---|---|
| `trace_manifest:*` | **NOT A PREFIX — do not register** | `trace_manifest:v1` is the value of a `schema` key inside a nested `manifest` object — one of two mutually exclusive payload shapes inside a `trace:complete:v1` envelope. Same category as CC 8.4.2.1's `c2pa_manifest`: payload-level, not wire-level. The prefix that actually needs a row is `trace:*`. Kept as a family row **only** so the seed card that proposed it has a place to record its correction. |
| `scores:*` | **NOT A FAMILY — do not register** | `scores` is the CC 2.4.2 `attestation_type` name. Zero dimensions in CIRISServer / CIRISPersist / CIRISEdge are literally prefixed `scores:`; the seed's illustrative leaves (`scores:medical`, `scores:safety`) exist nowhere in code, and the seed's `lens` owner is unsupported. The only production occurrence is a **permanently vacuous** `attestation_prefixes` entry in `FSD/BRIDGE_SEED_MESH.md:223`. |
| `trust:*` | **REGISTER ELSEWHERE** | The live mechanism is a `delegates_to` overlay with no `dimension` field; the CC 3.1 registry catalogs `scores` dimensions only. Needs a reserved `delegation_purpose` token in a new CC 2.4.1.x subsection, not a `namespace_registry.json` row. The literal `trust:*` dimension strings that exist (`trust:demo:v1`, `trust:reliability:v1`) are test placeholders. |

**Highest-value single findings, in severity order:**

1. `ownership:*` — CC 3.2's *"No permanent ownerless lock (MUST)"* has **no wire mechanism**. CC 2.4.1.1's four `withdraws` paths admit no third party against a live incumbent, and CIRISPersist v21.4.0's `src/` + `tests/` contain zero occurrences of seizure / reclaim / provably-dead / ownerless. A MUST-level constitutional requirement with no implementation.
2. `config:*` — `src/graph_config.rs#config_envelope` hardcodes `cohort_scope::FEDERATION` for **every** config row (including `auth.admin_key_ids`, `net.bootstrap_peers`, and per-peer sideband trust annotations), when the correct value (`cohort_scope::SELF`) is already used at `src/claim_remote.rs:829`. This is an **assigned-but-wrong** processor — invisible to any UNASSIGNED-row scan.
3. `capacity_assurance:*` / `consent:*` — **split truth inside one crate**: the hand-maintained admission gate knows `capacity_assurance:` is witness-reserved; the CC-3.1-generated `authority_for()` classifier returns `ProducerSteward` / `reserved:None`. Root cause is a generator scope boundary (`### 3.1.N` headings only), not constitutional silence.
4. `capacity_assurance:*` — the fail-open-to-liberty axiom is implemented in **one direction only** (admission bound-check, no lapse sweep), the same shape as the proven `capacity:*` self-emission/self-withdrawal leak.
5. `trace:*` — `RestrictionOp::RecipientCapability` is authored, parsed and recorded but **no component acts on it**: the carried-but-unprocessed defect class, in the one family whose serve gate is default-deny.

**What was NOT claimed.** Where the Constitution is silent, the analyses say so rather than inventing a rule — notably: no CC text names `config:*`, `trace_summary:*`, or a `scores:{domain}` family; CC 3.4.12 never pins `cohort_scope` for a capacity row; no `deletion_window` analog exists for owner-bindings; and the CC 1.2 T4 "never sole evidence for slashing" discipline is not re-stated for `consent:*` anywhere found. Two proposed admission gates (`consent:replication` `witness_relation==self` and `cohort_scope==federation`) are flagged as **new enforcement surface requiring the CC 4.5.1 amendment process**, not silent bugfixes.

### Marking coverage

`asymmetry_kind` is populated for **0.3.0 addendum rows only** (the 9 families, the matrix rows they touch, the standardization clusters, the transform rows). The 0.2.0 rows are **unmarked** — and unmarked asymmetry is indistinguishable from a bug. Back-filling them is the first task of 0.4.0.
