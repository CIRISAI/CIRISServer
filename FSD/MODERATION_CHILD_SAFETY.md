# FSD — Moderation & Child-Safety as First-Class Fabric Primitives

**Issue:** CIRISServer#15
**Status:** Design + requirements (research pass — no production code; type scaffolding only where it sharpens the design)
**Branch:** `wt/moderation`
**Substrate pins:** ciris-persist `v8.4.0` (`7b40aae`), ciris-edge `v4.3.0` (`ab4f1bc`), ciris-verify-core `v5.10.0` (`be25114`), CEG `1.0-RC17`
**Author scope:** defensive child-protection + mesh-governance. CSAM detection/takedown, age-assurance, content-class/rating gates, report→surface→act, the §11.4 takedown fast-path, the accord/transparency surfaces. This is protective safety infrastructure.

---

## 0. The spine: moderation is a *delegable duty*, not a built-in moderator role

The load-bearing reframe for this whole document: **there is no fabric-assigned "moderator."** The fabric ships moderation/child-safety *primitives* and the *delegation scope* that authorizes their exercise. WHO exercises a duty is a **delegation choice**, never a fabric role.

CEG gives us exactly the mechanism — `delegates_to` (§3.2), the second of the locked 1+4 attestation vocabulary (`scores`, `delegates_to`, `supersedes`, `withdraws`, `recants`). "A authorizes B to sign on A's behalf within scope S." So any participant can:

1. **Exercise the duty themselves** — *as the user*: the data subject signs the moderation/takedown/review action directly with their own self-occurrence (`witness_relation: self`).
2. **Delegate it to their agent** — *AI-on-behalf*: `delegates_to(user → agent, scope: moderate)`. The agent's brain decides, signs *on behalf of* the user, and the action is attributable up the chain.
3. **Delegate it to any trusted party** — another human, a community moderator, a specialized service: `delegates_to(user → moderator_key, scope: review)`.

Anyone can delegate; anyone can be delegated to. This is precisely the **"takedown isn't a coup"** property made structural (CEG §11.4, `11_governance.md:71`): every moderation/takedown action is

- **signed by the delegate** (attributable — we know who acted),
- **traceable to the delegator** via the `delegates_to` chain (accountable — we know whose authority),
- **revocable instantly** by a `withdraws` against the delegation (consent requires revocability),
- **coordinated, never unilateral** — a platform never *seizes* content; a participant (or their delegate) acts under a delegation, and the §9 HUMANITY_ACCORD remains the one asymmetry above all of it.

Everything below is organized around this spine. Each feature names: the **CEG primitive it rides**, its **fabric Rust home**, the **fabric-vs-agent split** (mechanism vs brain), and its **data-subject/accountability property**.

### 0.1 The delegation seam already exists in the fabric

`src/auth/verify.rs::signer_acts_for` is the resolution point today:

```rust
// True if `signer` may act for `identity_key_id`: it IS the identity, or an
// admitted, active occurrence of it (§5.6.8.8). user device OR user's agent.
pub async fn signer_acts_for(engine: &Engine, signer: &str, identity_key_id: &str) -> bool
```

It currently resolves only the **occurrence** relation (self-at-login: app + agent occurrences of the *same* identity). The moderation work *generalizes* this seam to resolve an arbitrary **`delegates_to` chain bearing a moderation scope** — exactly as persist already does for `consent_revocation` (the only scope with enforced delegated semantics today; see §6).

The reserved-scope split lives in `src/auth/roles.rs::scope`:

```rust
pub const INFRA:  &[&str] = &["network_presence","join_communities","serve","store","attest","transport"];
pub const AGENCY: &[&str] = &["act_on_behalf","message_io","reason","decide"];
```

The new moderation scope tokens (`moderate`, `takedown`, `review`) are **agency** scopes — only a brain or an explicitly-authorized human/service may hold them — and this module is their fabric home.

---

## 1. The existing surface to inherit (what to absorb, what to leave)

### 1.1 CIRISAgent (`/home/emoore/CIRISAgent`) — the agent-side moderation surface

There is **no `ModerationService` and no `ModerationEvent` class** in the agent. Moderation is decomposed into a mechanical filter layer, an LLM "conscience" gate layer, a DMA/PDMA reasoning core that can choose DEFER, and a Wise-Bus routing layer that ships deferrals to a human Wise Authority. Child-safety/CSAM/age-assurance exist only as **prohibition declarations + deferral routing** — no working detection mechanism.

| Component | Path | Role | Verdict |
|---|---|---|---|
| `AdaptiveFilterService` | `ciris_engine/logic/services/governance/adaptive_filter/service.py` | message filtering, trust tracking, anti-gaming → `FilterResult` (no bus event) | MECHANISM (regex/count/freq) → **fabric**; semantic triggers stay agent |
| `prohibitions.py` | `ciris_engine/logic/buses/prohibitions.py` | pre-compiled forbidden-capability regex frozensets + severity | **MECHANISM → fabric (prime candidate)** |
| `WiseBus` | `ciris_engine/logic/buses/wise_bus.py` | capability validation, tier gating, `send_deferral()` broadcast | MECHANISM (routing) → **fabric** |
| consciences (entropy/coherence/optimization-veto/epistemic-humility) | `ciris_engine/logic/conscience/core.py` | LLM gates | **REASONING → stays agent** |
| `ThoughtDepthGuardrail`, `ActionSequenceConscience` | `conscience/*.py` | deterministic gates | MECHANISM (could move; low priority) |
| `EthicalPDMA` / `ActionSelectionPDMA` | `ciris_engine/logic/dma/` | the DEFER *decision* | **REASONING → stays agent** |
| `SecretsFilter` | `ciris_engine/logic/secrets/filter.py` | regex credential detection | MECHANISM (out of scope here) |

**The clean seam (confirmed by the agent codebase):** the agent decides *whether* to flag/defer (reasoning); the fabric performs *matching / hashing / age-assurance / routing / emission / signing* (mechanism). The agent **already routes** unimplementable safety capabilities out via a `LICENSED_DOMAIN_REQUIRED` deferral (`wise_bus.py request_guidance`): a `REQUIRES_SEPARATE_MODULE` capability auto-constructs a deferral to a domain-capable Wise Authority. **A fabric child-safety module is exactly the licensed-domain service this path expects.** It registers as a domain-capable service; the agent's existing deferral router plugs straight in.

**Shapes to mirror for any fabric wire event** (no external `ModerationEvent` exists agent-side, so the fabric contract is net-new but should base on these):
- `FilterResult` — `ciris_engine/schemas/services/filters_core.py` (`message_id`, `priority`, `triggered_filters[]`, `should_process`, `should_defer`, `reasoning`, `suggested_action?`).
- `MessageHandlingResult` — `ciris_engine/schemas/runtime/messages.py` (`status`, `filtered`, `filter_reasoning?`, …) — the observer's final emitted result.
- `DeferralContext` / `DeferralRequest` — `ciris_engine/schemas/services/context.py` + `authority_core.py` (`reason`, `domain_hint`, `reason_code`, `needs_category`, `rights_basis[]`).

QA modules to keep as conformance harness: `tools/qa_runner/modules/safety_battery.py` (captures multilingual safety responses, signed JSONL), `safety_interpret.py` (independent-lineage judge, deterministic safety floor), `filter_tests.py` (filter-threshold persistence + secrets detection).

**Migration note:** the agent's *prohibition system would currently block* an agent from doing CSAM-hash / age-assurance directly. The fabric absorbing them as a delegated-scope primitive is *consistent* with the existing "defer to a separate licensed module" architecture — the agent gains the duty by `delegates_to(user → agent, scope: moderate)`, the fabric performs the mechanism, and the audit chain runs delegator → agent → action.

### 1.2 The fabric's current surfaces (this worktree)

- `src/auth/{attestation,consent,erasure}.rs` — **the exact pattern every moderation endpoint follows**: a thin axum router that (1) verifies the `x-ciris-*` hybrid signature via `verify::verify_request`, (2) checks `verify::signer_acts_for` (the delegation seam), (3) drives one or two substrate `Engine` calls. `consent.rs` writes an `attestation_type:"consent"` row + optional `attestation_promote`; `erasure.rs` calls `Engine::evict_actor` (bundled `withdraws` + hard-delete).
- `src/auth/roles.rs::scope` — the INFRA/AGENCY reserved-scope split (home for new moderation scope tokens).
- `src/auth/gate.rs` — owner-binding gate (TRUST ≠ JOIN); the precedent for fabric-added optional-normative rules filed upstream.
- `crates/ciris-lens-core/` — the detection/scoring corpus (`src/scoring/`, `src/canonical/ceg_egress.rs`, `src/cohort/`, `src/capacity/attestation.rs`). This is where `detection:*` / `scores` dimensions are assembled and canonicalized for egress.
- `app/fabric-client/.../net/FabricEndpoints.kt` — **the client already targets the endpoints this doc specifies**, marked scaffold:
  - `SAFETY_REPORTS = "/v1/safety/reports"` (report → surface → act)
  - `SAFETY_TAKEDOWNS = "/v1/safety/takedowns"` (mesh takedown coordination)
  - `TRANSPARENCY = "/v1/transparency"` (accord/PDMA disclosures)
  - `WISE_AUTHORITY_DEFERRALS = "/v1/wa/deferrals"`
  - `ERASURE_WITHDRAW = "/v1/erasure/withdraw"` / `ERASURE_RECEIPTS`

---

## 2. CEG primitives inventory (what each feature rides)

All section refs are `/home/emoore/CIRISRegistry/FSD/CEG/`. **No new primitives are introduced by this design** except the upstream-ask delegation scope tokens (§9). Each feature adapts to a shipped core.

| Primitive | CEG ref | Substrate status (v8.4.0 / v5.10.0) |
|---|---|---|
| `delegates_to` + scopes | §3.2 (`03_primitives.md`) | **Ships.** `attestation_type::DELEGATES_TO`, `build_delegation_graph()` (`persist .../federation/topology.rs:417`), depth cap 16, `DelegationEdge.withdrawn_by`. Scopes that ship: `act_on_behalf`,`message_io`,`network_presence`,`sub_delegation`,`consent_revocation`. **`moderate`/`takedown`/`review` are a GAP.** |
| `scores` / `withdraws` / `recants` | §3.1, §3.2 | **Ship.** `persist .../federation/types.rs:405` (`Attestation`), bound hybrid Ed25519 + ML-DSA-65. |
| `ModerationEvent` | §5.6.4 (`05_namespace.md:198`) | **Ships.** `persist .../cirisnode/types.rs:202` (`moderation_id`, `target_contributor`, `accuser_id`, `payload`, `filed_at`, `signature: HybridSignature`); a `ContributionType::ModerationEvent`. Companions: `SlashingAttestation`, `ReconsiderationRequest/Attestation`. |
| `moderation:{allegation_type}` | §5.6.4 | Dimension. Members: `rogue_vote`,`coordinated_voting`,`out_of_distribution_attestation`,`external_inducement_evidence`,`expertise_fraud`, + `age_assurance_misdeclaration` (open-vocab, the age-misdeclaration **adjudication** path — never `slashing:*` alone). |
| `takedown_notice` + `LegalBasis` | §11.4, §5.6.8.4 (`05_namespace.md:303-332`) | **Ships fully.** `persist .../cirisnode/media_sharing.rs:111` — all 10 `LegalBasis` variants; `TakedownNoticePayload:400` (`content_sha256`, `perceptual_hash`, `legal_basis`, `jurisdiction`, `good_faith_statement`, `counter_notice_channel`, …); `requires_immediate_eviction()`, `admits_counter_notice()`, `composes_with_age_gate()`. Handler `takedown_handler.rs:104 process_takedown_admission`. |
| `hard_case:fast_path_takedown` | §11.4 step 4 (`11_governance.md:69`) | Audit-trail Contribution; rides §5.6.6 hard-case. |
| `PerceptualHashMatcher` (hash-DB §11.5) | §11.5 (`11_governance.md:73`) | **Trait ships** (`persist .../federation/perceptual_hash.rs:127`): `check()`, `databases()`, `on_match_policy()`, `matcher_unreachable_policy()` (default `FailClosed`). `OnMatchPolicy::{Refuse,ReportThenRefuse,AlertOnly}`. `NullPerceptualHashMatcher` default. **Concrete PDQ/PhotoDNA/Arachnid adapters NOT shipped (intentional — operator-tier, out-of-tree).** Registration: `system:perceptual_hash_matcher:registered`. |
| `age_assurance:{level}` | §5.6.8.3 (`05_namespace.md:283`), gate §8.1.10-L3 (`08_composition.md:165`) | **Dimension is a GAP** — no `age_assurance` type in substrate. Only the *takedown* age-gate composition ships (`AvmsdAgeInappropriate` + `composes_with_age_gate()` + `MultimediaConfig::age_gate_legal_bases`). Levels: `self < provider:{verifier_key}:adult < government:{credential_class}:adult`. |
| `content_rating:{scheme}:{rating}` / `content_class:{class}` / `cw_class:{class}` | §5.6.8.3 (`05_namespace.md:280-282`), gate §8.1.10-L2 | **Dimensions are a GAP** — none exist in substrate. Schemes: mpaa/bbfc/pegi/esrb/ifco/csm/operator. |
| `detection:*` + `ratchet:flag:*` | §5.5 / §5.7 (`05_namespace.md:130,140,159,1173`) | Advisory `scores` dimensions assembled in lens-core. `ratchet:flag:harassment_pattern` is the harassment primitive. **Critical:** advisory only — `ratchet:flag:*` cannot be sole evidence for `slashing:*`; WA quorum is the load-bearing gate. |
| directory eviction (`holds_bytes` + `withdraws`) | §10.1.2, §5.6.7 | **Ships.** `persist .../federation/replication/eviction.rs` (`SweepReport{rows_evicted, withdraws_emitted, withdraws_failed}`); verify `holds_bytes.rs:105 verify_holds_bytes`. |
| `EjectionVerdict` / hard-delete / noise-floor (§19.7) | §19.7 (`19_holonomic.md:73`) | **Ships** in verify-core (`holonomic/aggregation.rs:158 EjectionVerdict{Keep,EjectToTier,EjectHardDelete}`, `ejection_verdict(consent, pressure)`). Persist erasure primitive is `Engine::evict_actor` (NOT `evict_fountain_content_hard_delete` — that symbol is **not in v8.4.0**; `evict_actor` is stronger, bundling the §10.1.2 `withdraws`). |
| transparency log (STH co-sign, witnesses) | §10.3 (`10_endpoints.md:257`) | `POST /v1/transparency/sth/cosign` (consistency-proof enforced), `GET /v1/transparency/witnesses`, per-stream log `log_id=stream_id` (§10.5.4). |
| §9 HUMANITY_ACCORD / CONSTITUTIONAL kill | §9 (`09_humanity_accord.md`), §9.2 | `accord:invoke:CONSTITUTIONAL:{halt_id}`, `EmergencyShutdown CONSTITUTIONAL` (`IncidentSeverity=5`), 2-of-3 multi-sig, wire+scope isolated. Entrenched (§11.2). `GET /v1/accord-holders`. |
| `DsaArticle16` | §5.6.8.4 (`05_namespace.md:325`) | `LegalBasis` value — **counter-notice (Art.17 redress), NOT fast-path**; routes through standard §11.2 on counter-notice via `reconsideration:new_evidence`. |

**Two spec gaps flagged for honesty (do not invent):**
- **WBD ("wisdom-based deferral")** and the **>100k-MAU redacted-PDMA/WBD transparency mandate** named in the brief **do not exist in CEG** (zero hits for `WBD`/`MAU`/`100k`/`redacted PDMA`/`transparency mandate`). CEG has `deferral_request` Contributions + `locality:decision:*` prefixes, and the §10.3 transparency *log*, but not a MAU-thresholded PDMA-publication mandate. These live (if anywhere) in CIRISAgent/MISSION docs, not the substrate. This design uses the agent's `DeferralRequest` shape for deferral and the §10.3 transparency log for disclosure, and treats any MAU-mandate as **out of scope until authored upstream** (§9 upstream-asks).
- There is **no dedicated takedown/moderation HTTP endpoint in CEG** by deliberate "1+4 wire lockdown" design — takedown *rides* `withdraws`-against-`holds_bytes`. The `/v1/safety/*` endpoints in `FabricEndpoints.kt` are therefore a **fabric-added convenience surface** over the CEG primitives (precedent: the owner-binding gate in `gate.rs`, filed as optional-normative CIRISRegistry#83). Filed as an upstream-ask (§9).

---

## 3. Feature: Delegated moderation authority (the spine primitive)

**What it is.** The `delegates_to` scope tokens that authorize the exercise of a moderation/child-safety duty, plus the resolution that makes every downstream feature attributable + revocable.

**CEG primitive:** `delegates_to` (§3.2), scope set on the attestation envelope.

**Fabric Rust home:**
- `src/auth/roles.rs::scope` — add the three tokens to a new `MODERATION` const (agency-class):
  ```rust
  // SCAFFOLD — sharpens the design; not wired this pass.
  pub mod scope {
      /// Moderation/child-safety duties — delegable; agency-class (brain or
      /// explicitly-authorized human/service only). Mirrors persist's
      /// `consent_revocation` enforced-scope model (federation/admission.rs).
      pub const MODERATION: &[&str] = &[
          "moderate",  // emit ModerationEvent / detection flags on behalf of delegator
          "takedown",  // file a takedown_notice on behalf of delegator
          "review",    // adjudicate reports, route deferrals on behalf of delegator
      ];
  }
  ```
- `src/auth/verify.rs` — generalize `signer_acts_for` into `signer_may_act_in_scope(engine, signer, principal, scope)` that walks the `delegates_to` graph (persist `build_delegation_graph()`), accepting the signer when it is the principal, an admitted occurrence, OR the tail of a `delegates_to` chain from the principal bearing `scope` and not `withdrawn_by`.

**Fabric vs agent split.** Fabric: the scope vocabulary, the chain-walk/verification, the per-action signer check, the revocation honoring. Agent (or any delegate brain): the *decision* to act and what action to take.

**Accountability property.** This IS "takedown isn't a coup," structurally: action signed by delegate → chain to delegator → instantly revocable by `withdraws` against the delegation edge (persist surfaces `DelegationEdge.withdrawn_by` so the chain-walk drops a revoked edge mid-flight). No platform-assigned moderator; no unilateral seizure.

**Upstream-ask:** `moderate`/`takedown`/`review` scope tokens need enforced semantics in persist's `federation/admission.rs` (the way `consent_revocation` is gate-enforced today). See §9.

---

## 4. Feature: Child-safety

### 4.1 CSAM hash-DB matching (§11.5)

**CEG primitive:** `PerceptualHashMatcher` trait + `perceptual_hash` field on `takedown_notice`; `PerceptualHashCsam` legal-basis; `system:perceptual_hash_matcher:registered` registration Contribution.
**Fabric Rust home:** new `src/safety/hash_match.rs` — holds an `Arc<dyn PerceptualHashMatcher>` (persist's `SharedMatcher`), invoked on `BlobBody::Inline` ingress in the content path; emits the registration Contribution on startup.
**Fabric vs agent split.** Fabric: the match mechanism, `OnMatchPolicy` enforcement (`Refuse`/`ReportThenRefuse`/`AlertOnly`), `FailClosed` on matcher-unreachable, and on a `Match` driving the §11.4 fast-path. **No brain involved** — hash matching is pure mechanism. Agent: never sees the bytes (the agent's own design already withholds raw images from consciences).
**Accountability property.** On match → NCMEC CyberTipline obligation (operator action), hash + minimal metadata retained for the federal-legal window only, **no content retention** (§11.4 step 3). Auditable via `hard_case:fast_path_takedown`.
**Upstream-ask:** concrete matcher (self-hosted PDQ against public feeds) is intentionally out-of-tree — the fabric must ship or pin a `PdqHashMatcher` impl. The trait is ready; the adapter is the gap.

### 4.2 Age-assurance (§3 / §5.6.8.3 / §8.1.10-L3)

**CEG primitive:** `age_assurance:{level}` dimension (`self` < `provider:{verifier_key}:adult` < `government:{credential_class}:adult`); the §8.1.10 Layer-3 `age_gate()` composition; `moderation:age_assurance_misdeclaration` adjudication path.
**Fabric Rust home:** `src/safety/age.rs` — a thin emitter (like `consent.rs`) writing an `attestation_type:"scores"` row on the `age_assurance:{level}` dimension, signed by the subject's self-occurrence; plus the `age_gate()` consumer-side helper.
**Fabric vs agent split.** Fabric: emission, the gate function, the ordering comparison. Brain: only needed to *evaluate* a third-party verifier's evidence (a `provider:` attestation), which is a verifier service, not the agent.
**Accountability property.** Subject-signed; **misdeclaration NEVER fires `slashing:*` alone** — it routes to the `moderation:age_assurance_misdeclaration` adjudication path (a `ModerationEvent` + WA quorum). Data-subject controls their own assurance level.
**Upstream-ask:** the `age_assurance:{level}` dimension and verifier-attestation type are **not in the substrate** (only the AVMSD takedown age-gate composition ships). File the dimension + the consumer-side `age_gate()` helper as an upstream ask, OR implement age-gate composition purely fabric-side over generic `scores` rows (preferred near-term: it needs no new primitive, just a fixed dimension name).

### 4.3 Content-class / rating gates (§5.6.8.3 / §8.1.10-L2)

**CEG primitive:** `content_rating:{scheme}:{rating}` (mpaa/bbfc/pegi/esrb/ifco/csm/operator), `content_class:{class}` (producer-declared), `cw_class:{class}` (community content-warning); the §8.1.10 Layer-2 `gate_decision()`.
**Fabric Rust home:** `src/safety/rating.rs` — emit these as `scores` dimensions (producer signs `content_class`, cohorts sign `cw_class`); `gate_decision()` + the Layer-3 `age_gate()` chain as a pure consumer-side function.
**Fabric vs agent split.** Fabric: the dimensions + the gate composition (producer-declared is *consultable, not authoritative* — the gate combines producer claim + cohort `cw_class` + consumer prefs). Brain: optional — a classifier agent may *propose* a `content_class`, but the producer signs it.
**Accountability property.** No vote weight elevates an unverified distributor; the only path to authority is the operator trust list (§8.1.10 anti-tricking, binds CIRIS L3C). Consumer chooses; producer/cohort declare.
**Upstream-ask:** like §4.2, these dimensions are not in the substrate. Implement fabric-side over generic `scores` with fixed dimension names (no new primitive needed) and file the canonical dimension vocabulary upstream for cross-fabric agreement.

### 4.4 Report → surface → act (`/v1/safety/reports`)

**CEG primitive:** a report is a `scores` attestation on a detection/moderation dimension (the *surface* step); acting is a `ModerationEvent` (§5.6.4) and/or a `takedown_notice` (§11.4). The client endpoint already exists: `SAFETY_REPORTS`.
**Fabric Rust home:** `src/safety/report.rs` — the `/v1/safety/reports` router (same axum+verify pattern as `attestation.rs`). Verifies the reporter signs in `review`/`moderate` scope (self, or delegated), writes the report attestation, and (when policy/quorum permits) emits the `ModerationEvent` or routes to the deferral path.
**Fabric vs agent split.** Fabric: ingest, sign, surface, route, emit. Brain: the *adjudication* (is this report valid? what action?) — done by whoever holds the `review` delegation (the user, their agent, or a community moderator), via the agent's existing `ActionSelectionPDMA` → DEFER path.
**Accountability property.** report→surface→act is fully attributed: reporter-signed report, delegate-signed action, all on the audit chain. Acts are coordinated (quorum/delegation), not unilateral.

---

## 5. Feature: Takedown (the §11.4 fast-path)

**CEG primitive:** `takedown_notice` subject-kind + `LegalBasis` enum + `hard_case:fast_path_takedown`; the eviction rides `withdraws`-against-`holds_bytes` (§10.1.2). All shipped in persist.

**The §11.4 5-step protocol (the fabric implements the substrate side):**
1. **Notice admission** — accept the `takedown_notice` signed by `claimant_key_id`, **no §11.2 quorum** (speed). Fabric: `process_takedown_admission`.
2. **Holder eviction** — emit `withdraws` against each matching `holds_bytes:sha256:{prefix}`; holders cease serving.
3. **Per-basis dispatch:**
   - `TvecTerrorist` — TVEC channel, 1-hour regulator notify; log notice + eviction.
   - `GifctCip` — GIFCT CIP channel; audit-log.
   - `NcmecCsam` + `PerceptualHashCsam` — operator MUST file NCMEC CyberTipline (18 USC §2258A); retain hash + minimal metadata for legal window only; **no content retention**.
   - `CourtOrder` — follow court timeline; log order text + eviction.
4. **Audit trail** — every fast-path takedown → `hard_case:fast_path_takedown` Contribution; reviewers MAY file `reconsideration:procedural_error`.
5. **No counter-notice for immediate bases** (TVEC/NCMEC/GIFCT/PerceptualHashCsam/CourtOrder). The counter-notice bases (`Dmca512`/`DsaArticle16`/`CommunityStandards`/`OsaIllegalContent`) route through standard §11.2 amendment on counter-notice via `reconsideration:new_evidence`.

**Fabric Rust home:** `src/safety/takedown.rs` — the `/v1/safety/takedowns` router over persist's `takedown_handler::process_takedown_admission_with_config` + `MultimediaConfig`.

**Fabric vs agent split.** Fabric: the entire protocol — admission, eviction, dispatch, audit. **No brain** — it's all mechanism keyed off `LegalBasis`. The *claimant's decision to file* may be a delegate (a CSAM-hash auto-match files `PerceptualHashCsam` with no human in the loop; a court order is filed by the operator under `takedown` scope).

**Accountability property.** This is the canonical "not a coup": the takedown is a *signed notice* causing a *signed `withdraws`*, fully audited, with the §9 HUMANITY_ACCORD as the backstop — a `takedown_notice` targeting the substrate's own `federation_keys` (a state actor silencing dissenters) does **not** propagate the same way; it intersects substrate-protective discipline + accord veto and SHOULD escalate via §9.2.

**Upstream-ask:** none for the core protocol (it ships). The convenience HTTP endpoint `/v1/safety/takedowns` is a fabric-added surface (CEG has no dedicated endpoint by design — file as optional-normative alongside §9).

---

## 6. Feature: Moderation (ModerationEvent + detection/ratchet corpus)

**CEG primitive:** `ModerationEvent` Contribution (§5.6.4) + `moderation:{allegation_type}` dimension; `detection:*` and `ratchet:flag:*` advisory `scores` dimensions (incl. `ratchet:flag:harassment_pattern`).
**Fabric Rust home:**
- Emission: `src/safety/moderation.rs` — emit `ModerationEvent` (persist `cirisnode::ModerationEvent`, hybrid-signed) when a `review`/`moderate`-scope delegate adjudicates.
- Detection corpus: `crates/ciris-lens-core/src/scoring/` + `canonical/ceg_egress.rs` — already the home for assembling/canonicalizing `detection:*` / `ratchet:flag:*` dimensions for egress. The harassment/pattern flags are lens-core scoring outputs.
**Fabric vs agent split.** Fabric: emit `ModerationEvent`, compute + canonicalize advisory `detection:*`/`ratchet:flag:*` (deterministic corpus, RATCHET hash-pinned). Brain: the adjudication that *turns* an advisory flag into a `ModerationEvent` (the agent's reasoning).
**Accountability property.** **Critical enforcement:** `ratchet:flag:*` cannot be the sole evidence for `slashing:*` — **WA quorum is the load-bearing gate** (`05_namespace.md:1175`). RATCHET emits advisory flags, never autonomously modifies ledger state. So detection never auto-punishes; it surfaces, a delegate adjudicates, quorum gates slashing. Fully attributable, coordinated.

---

## 7. Feature: Accord / governance surfaces

### 7.1 Transparency disclosures (`/v1/transparency`)

**CEG primitive:** §10.3 transparency log (STH co-signing, witness directory), per-stream `log_id=stream_id` (§10.5.4).
**Fabric Rust home:** `src/safety/transparency.rs` — `/v1/transparency` router; expose witness directory + STH co-sign (consistency-proof enforced per Registry v2.3.0).
**Fabric vs agent split.** Fabric: the append-only log + witness co-signing + the disclosure read surface. Brain: none.
**Accountability property.** Tamper-evident (consistency-proof-gated), publicly verifiable. Every takedown's audit Contribution and every `ModerationEvent` is disclosable here.
**Upstream-ask:** the >100k-MAU redacted-PDMA/WBD *publication mandate* is **not in CEG** — if required it must be authored upstream (it's a policy threshold, not a primitive). The disclosure *mechanism* (§10.3 log) ships; the *mandate* does not.

### 7.2 CONSTITUTIONAL emergency path (§9)

**CEG primitive:** `accord:invoke:CONSTITUTIONAL:{halt_id}`, `EmergencyShutdown CONSTITUTIONAL` (`IncidentSeverity=5`), 2-of-3 HUMANITY_ACCORD multi-sig, wire-isolated + scope-isolated, entrenched.
**Fabric Rust home:** consumes — `src/safety/accord.rs` (read `GET /v1/accord-holders`; honor `accord:*` invocations; reject CONSTITUTIONAL invocations against placeholder/unprovisioned holders). Emission is accord-holder-only (`identity_type="accord_holder"`); the fabric never signs `AccordCarrier`.
**Fabric vs agent split.** Fabric: honor + enforce the halt; verify the 2-of-3; the `notify` vs `CONSTITUTIONAL` consumer-UI distinction (social-engineering safeguard, §9.2.2). Brain: never — this is the one constitutional asymmetry, held by three named humans, outside the system being halted.
**Accountability property.** The ultimate "not a coup" backstop: kill authority that no federation-internal authority can grant/revoke/override/decay. Consent requires revocability; revocability requires a halt-authority outside the system.

### 7.3 Deferral routing (`/v1/wa/deferrals`)

**CEG primitive:** `deferral_request` Contribution + `locality:decision:*` prefixes (note: **"WBD" is not a CEG term** — this is the agent's deferral shape over CEG's deferral primitive).
**Fabric Rust home:** `src/safety/deferral.rs` — `/v1/wa/deferrals` router; route a `DeferralRequest` (agent shape) to a domain-capable Wise Authority by `domain_hint`. This is the seam the agent's `LICENSED_DOMAIN_REQUIRED` path connects to (§1.1).
**Fabric vs agent split.** Fabric: the routing/envelope/broadcast (mechanism, mirrors agent `WiseBus.send_deferral`). Brain: the WA's guidance (reasoning), and the agent's decision to defer.
**Accountability property.** Deferral is the explicit "I don't have authority for this — route to one who does" — the structural humility that keeps moderation accountable to a human/authorized authority rather than auto-resolved by a brain.

---

## 8. Build plan / priority order

Load-bearing child-safety + takedown primitives first (they ride shipped cores); video/streaming last.

**Phase 0 — the delegation spine (blocks everything).**
1. `src/auth/roles.rs::scope::MODERATION` tokens (`moderate`/`takedown`/`review`).
2. Generalize `verify.rs::signer_acts_for` → `signer_may_act_in_scope` walking `delegates_to` (persist `build_delegation_graph`), honoring `withdrawn_by`.
3. File the upstream-ask for enforced scope semantics in persist `admission.rs` (§9).

**Phase 1 — takedown + CSAM (highest child-protection leverage; cores ship).**
4. `src/safety/takedown.rs` over `process_takedown_admission_with_config` — the full §11.4 protocol. (Pure mechanism, no new primitive.)
5. `src/safety/hash_match.rs` — wire persist's `PerceptualHashMatcher` on inline-blob ingress; on `PerceptualHashCsam` match → §11.4 fast-path. Ship a `PdqHashMatcher` adapter (the one out-of-tree gap).
6. `/v1/safety/takedowns` endpoint (matches `FabricEndpoints.kt`).

**Phase 2 — report→surface→act + moderation events.**
7. `src/safety/report.rs` → `/v1/safety/reports`.
8. `src/safety/moderation.rs` — `ModerationEvent` emission (persist core ships).
9. lens-core: confirm `detection:*` / `ratchet:flag:harassment_pattern` egress canonicalization.

**Phase 3 — gates (fabric-side over generic `scores`; no new primitive).**
10. `src/safety/age.rs` — `age_assurance:{level}` emit + `age_gate()`.
11. `src/safety/rating.rs` — `content_rating`/`content_class`/`cw_class` + `gate_decision()` (§8.1.10 Layer 2+3 chain).

**Phase 4 — accord/transparency surfaces.**
12. `src/safety/transparency.rs` → `/v1/transparency` (read + STH co-sign).
13. `src/safety/accord.rs` — honor §9 CONSTITUTIONAL (consume-only).
14. `src/safety/deferral.rs` → `/v1/wa/deferrals` (the agent integration seam).

**Phase 5 — video/streaming (deferred).** Per-stream transparency log (§10.5.4), removal coalescing (§10.5.3, 2s STH window). After the static-content primitives prove out.

**Module home:** a new `src/safety/` sibling to `src/auth/`, mirroring its thin-router-over-Engine pattern; `mod.rs` exposes the routers, composed onto the listener in `src/compose.rs` (where `identity_router`/`read_api_with_extra` already merge).

---

## 9. Open questions & upstream-asks (genuine substrate gaps)

**Substrate gaps (file as upstream issues):**

1. **[persist] Delegation scope tokens `moderate`/`takedown`/`review`** — `delegates_to` ships, but only `consent_revocation` has *enforced* delegated semantics (`federation/admission.rs:1077`). The moderation scopes need the same gate-enforcement so a delegated moderation/takedown action is admitted iff a valid unrevoked chain bears the scope. **This is the load-bearing gap for the whole delegation spine.** (Precedent: the one-wheel hooks ask.)

2. **[persist] `age_assurance:{level}` dimension + verifier-attestation** — absent; only the AVMSD takedown age-gate composition ships. *Near-term workaround:* implement fabric-side over generic `scores` with a fixed dimension name (no new primitive). *Upstream:* canonicalize the dimension + the `provider:`/`government:` ordering for cross-fabric agreement.

3. **[persist] `content_rating` / `content_class` / `cw_class` dimensions** — absent. Same workaround/ask as #2.

4. **[persist] concrete `PerceptualHashMatcher` adapter** — trait ships; PDQ/PhotoDNA/Arachnid adapters are intentionally out-of-tree. The fabric must ship/pin a self-hosted `PdqHashMatcher` against public feeds (CEG §11.5.2 default). Decide: in-fabric crate vs upstream-contributed adapter.

5. **[CEG] dedicated takedown/moderation/safety HTTP endpoints** — none exist by deliberate "1+4 wire lockdown" design; takedown rides `withdraws`-against-`holds_bytes`. The `/v1/safety/*` + `/v1/transparency` + `/v1/wa/deferrals` endpoints are a **fabric-added convenience surface** (precedent: owner-binding gate, CIRISRegistry#83). File as optional-normative so clients (`FabricEndpoints.kt`) have a ratified contract.

**Spec gaps (do not invent — confirm intent before building):**

6. **WBD ("wisdom-based deferral")** — named in the brief but **absent from CEG** (zero hits). CEG has `deferral_request` + `locality:decision:*`; the agent has `DeferralRequest`/`DeferralContext`. This design uses the agent's deferral shape over CEG's deferral primitive. *Open question:* is "WBD" just the agent's deferral by another name, or a distinct primitive to author?

7. **>100k-MAU redacted-PDMA/WBD transparency publication mandate** — **absent from CEG** (zero hits for MAU/100k/redacted-PDMA/transparency-mandate). It's a *policy threshold*, not a primitive; the §10.3 transparency *log mechanism* ships. *Open question:* author the mandate upstream (where? CEG §10 or §11?), and define "redacted PDMA" wire shape. Out of scope until authored.

8. **`ModerationEvent` is contributor-reputation, not content-moderation** — persist's shipped `ModerationEvent` (`cirisnode/types.rs:202`) is an *accusation of rogue contributor action* (rogue_vote/coordinated_voting/…), adjudicated by slashing/reconsideration. *Open question:* does content-moderation (a flagged *post*) reuse this Contribution with a content-targeting `allegation_type`, or does it ride purely `takedown_notice` + `detection:*`? **Recommendation:** content actions ride `takedown_notice` + `detection:*`/`cw_class`; `ModerationEvent` stays for participant-conduct adjudication. Confirm.

9. **Age-gate authority for minors** — FERPA/parental authority composes via `delegates_to` (`11_governance.md:119`), i.e. a parent delegating the minor's consent/age scope. Confirm the delegation-spine handles the minor-subject case (delegator = parent, principal = minor) cleanly. **Audit note (§B.5):** this composition assumes a *non-abusive* guardian; the coerced-household case is a named residual, not a closed gap.

**Existence-invariant asks (new — §A / §B):**

10. **[fabric-side, then upstream] `moderation_track_record` dimension** — the auto-promotion ranking signal (§A.3). *Near-term:* compute fabric-side as a consumer composition over the shipped reputation basis (`commitment_fulfillment` / `truth_grounding` / `witness_diversity` + upheld-`reconsideration` count) under a fixed dimension name — **no new primitive** (same workaround pattern as age/rating #2–#3). *Upstream:* canonicalize the dimension name + the deterministic ranking tiebreak (so every node computes the same promotion — no split-brain on "who is the moderator now").

11. **[CEG §7.8] `hard_case:community_unmoderated:{community_key_id}` reserved reason** — the existence gate's fail-secure / rejection emission (§A.2, §A.3 step 4) needs a reserved `hard_case:*` reason so a quiesced/rejected-unmoderated community is **auditable, not silent** (the §10.1.4 anti-soft-censorship discipline). Companion to the shipped `community_membership_change` / `consensus_protocol_violation` reasons. Also useful: `hard_case:community_moderator_promoted:{community_key_id}` for the auto-promotion event. **No new structural primitive** — additions to the §7.8 closed reason set.

12. **[persist `admission.rs`] named-moderator predicate at community admission** — the existence gate (§A.2) is an admission precondition: `community` creation + every membership-change `supersedes` admitted **iff** `named_moderator_present(C)`. This rides the existing `verify_founder_quorum` + owner-binding machinery (no new primitive) but needs the predicate wired into the admission path alongside the `consensus_protocol` and owner-binding checks, plus the auto-promotion trigger on last-moderator-removal events.

---

## 9bis. Spine status update (CEG 1.0-RC19)

This document's §3 / §9 originally flagged `moderate` / `takedown` / `review` as a **substrate gap**. That gap is **now closed upstream**: CEG **§11.10** (1.0-RC19, CIRISRegistry#90) names the three duties as canonical `delegated_scope` kinds and **enforces their admission** — mirroring `consent_revocation` (§3.2.3 rule 3). The normative rule:

> A moderation action is admitted **iff** its `attesting_key_id` is the duty-holder itself, **or** sits on a live `delegates_to` chain bearing the matching scope from the duty-holder … A verifier MUST **reject** (treat as non-authoritative) a `takedown_notice`, `moderation:*` ModerationEvent, or `reconsideration:*` from an actor with no such authority — the duty is **held or delegated, never assumed**. — CEG §11.10

The remaining work is therefore *persist `admission.rs` enforcement → CIRISServer `src/safety/*` wiring*, not a primitive ask. **Accountability ships ahead of capability**: per §11.10, *no media/chat feature ships until this is solved and working.* The sections below build the existence invariant on top of this enforced spine.

---

## A. The named-moderator existence invariant

> **Invariant (normative): a group without a named, accountable moderator cannot exist.**
> Every multi-party `community` (and any `family` operating beyond the intimate-trust default) MUST, at all times, name at least one **provisioned, accountable identity holding the `moderate` scope for that group**. The group's *existence* — its admission to federation, its ability to emit `holds_bytes:*` and accept members — is gated on this. There is **never** an unmoderated window: an auto-promotion rule fills any gap the instant it opens, and if no eligible moderator can be named, the group **fails secure** (cannot federate/operate). No unmoderated multi-party space, ever.

This is the child-safety load-bearer. Predator playbooks across every surveyed network (§SAFETY_LANDSCAPE) exploit exactly the space CIRIS forbids here: the unmoderated relay, the orphaned room with no admin left, the absentee-admin instance. CIRIS does not "moderate better" in those spaces — it makes them **structurally non-existent**.

### A.1 What it rides (no new primitive)

The invariant is a *composition rule over shipped primitives*, not a new wire shape:

- **`community` subject_kind** (§5.6.8.10) already carries `members[]` with `role: founder | member`, a `consensus_protocol`, and `consensus_protocol_entrenched`. The named moderator is a member who additionally bears the `moderate` scope.
- **Owner-binding gate** (§5.6.8.10, RC7, CIRISRegistry#83): a `node`/`agent`-role key MUST have a bound **owner** — a `user`-role human with a live `delegates_to(user → key, …)` — *before it may be admitted to any non-`infrastructure` community.* **Authority roots in an accountable human, never a bare node.** The named-moderator invariant is the same principle applied to the *group as a whole*: a community's authority to exist roots in an accountable moderator.
- **`moderate` delegated_scope** (§11.10, RC19): the enforced authority the named moderator holds. They may exercise it themselves or sub-delegate it (`delegates_to(moderator → agent | trusted_party, scope: moderate)`), depth-capped (§13.3), revocable by `withdraws`.
- **`moderation_track_record`** — the auto-promotion signal. Built from the shipped reputation basis: `commitment_fulfillment:{prior_contribution_id}` (follow-through on prior duties), `truth_grounding:{subject}` (verdicts that held), `witness_diversity:{contribution_id}` (cross-validated review), and a successful `reconsideration` history (appeals that *upheld* their verdicts). This is a **consumer-side composition over existing `scores` dimensions** — no new primitive. (Open dimension-name ask in §9 #10, mirroring the age/rating workaround: fixed dimension name `moderation_track_record`, fabric-computed.)

### A.2 The existence gate (admission-time)

A substrate evaluating a `community` Contribution (creation, or a `supersedes` membership change) MUST run the **named-moderator predicate** as an admission precondition, alongside the existing `consensus_protocol` and owner-binding checks:

```
named_moderator_present(community C) :=
    ∃ m ∈ C.members such that
        m is owner-bound (a real provisioned user-role identity, or a key
            with a live delegates_to from one — §5.6.8.10 owner-binding), AND
        m holds the `moderate` scope for C — either:
            (a) m is the community founder/creator (creator carries the duty
                by default — "community = creator's responsibility", §0 spine), OR
            (b) ∃ live, unrevoked delegates_to(founder|prior_moderator → m,
                scope ⊇ {moderate}) naming C as principal.

ADMISSION:
    community admission (and every membership-change supersedes) is admitted
        IFF named_moderator_present(C).
    If the predicate is false → REJECT, emit
        hard_case:community_unmoderated:{community_key_id} (§7.8 reserved,
        new reason in the closed set — upstream ask §9 #11) into the
        community scope so the failure is auditable, NOT silent
        (same anti-soft-censorship discipline as §10.1.4's recipient_excluded).
```

**Creator carries the duty by default (the §0 spine).** A community cannot be *created* without its creator either holding `moderate` themselves or having named someone who does. There is no "create now, moderate later" path — the door does not open without a named moderator behind it. This closes the unmoderated-creation vector at genesis.

**Family note.** The intimate-trust `family` default (≤ ~20, `founder_only`/`unanimous`, structurally invisible per §10.1.4) is *self-moderating by the founders* — every founder holds the duty over a space only they can see. The invariant **bites when a family operates as a de-facto community** (promotes content to `cohort_scope: community`, or grows past the intimate-trust threshold an operator sets): at that point the named-moderator predicate applies. The honest boundary: a structurally-invisible family is moderated *only* by its own members (see §B.1).

### A.3 Auto-promotion-by-merit (no unmoderated window)

The hard requirement is **continuity** — there must never be even a transient gap. A named moderator can vanish: key revoked, member removed by `supersedes`, owner-binding withdrawn, account erased (`evict_actor`), or simply gone dark. The instant the named-moderator predicate would go false, the substrate runs **auto-promotion**:

```
On any event that removes/invalidates the last moderate-scope holder of C
    (withdraws against the delegation, member-removal supersedes, owner
     unbind, evict_actor, key supersession leaving no scope holder):

  1. CANDIDATE SET := current members of C who are owner-bound AND eligible
        (not under an open moderation:* allegation, not slashed).
  2. RANK by moderation_track_record (A.1): commitment_fulfillment desc,
        then witness_diversity, then upheld-reconsideration count, then
        tenure (joined_at asc) as a deterministic tiebreak.
        (Deterministic ⇒ every node computes the same promotion ⇒ no
         split-brain on "who is the moderator now" — the §safety-vs-censorship
         "same inputs → same verdict" discipline applied to promotion.)
  3. AUTO-DELEGATE: emit, under the community's consensus_protocol authority
        (founder-quorum / the entrenched protocol — NOT a unilateral act),
        delegates_to(community → top_candidate, scope: moderate).
        The promotion is itself a signed, attributable, revocable Contribution
        + hard_case:community_moderator_promoted:{community_key_id}.
  4. IF candidate set is empty (no eligible member can be named):
        FAIL SECURE — the community CANNOT continue as a federating space:
          - substrate ceases to admit new cohort_scope: community content
            (stops emitting holds_bytes:* for C),
          - stops admitting new members,
          - emits hard_case:community_unmoderated:{community_key_id},
          - existing content is governed under the standard takedown/eviction
            path; the community is quiesced, not silently running unmoderated.
        Re-activation requires the consensus_protocol to name a moderator.
```

The promotion is **never a coup**: it is emitted under the community's own `consensus_protocol` (the same founder-quorum machinery that admits members — `verify_founder_quorum`), is fully signed and audited, and is revocable. Merit fills the gap; the *group's own governance* ratifies; fail-secure is the floor. The auto-promotion is the mechanism that lets the existence-gate be *strict* without bricking real communities whose moderator simply left.

### A.4 Fail-secure, not fail-open — and why that's the right default

The CIRIS default everywhere (`CLAUDE.md` non-maleficence) is fail-*secure*: a missing key denies access, never downgrades protection (§10.1.4's `wrap_algorithm` exclusion is the precedent). The named-moderator invariant inherits it: **the failure mode of "we cannot name an accountable moderator" is the group quiescing, not the group running open.** An unmoderated multi-party space is the predator-enabling state; the design makes it unreachable. This is the deliberate inversion of every surveyed network, all of which fail *open* (a relay/instance/room with no moderator keeps operating).

The honest cost (stated, not hidden): fail-secure can quiesce a *legitimate* community whose moderator left and whose members are all ineligible (e.g. all under allegations, or all bare unowned nodes). That is an availability cost knowingly traded for the safety floor — and it is recoverable (name a moderator → re-activate), unlike the harm an unmoderated window enables.

### A.5 What the invariant does NOT do (honesty)

- It does **not** make moderation *correct* — only *present and accountable*. A named moderator can be lazy, captured, or colluding; §B.4 covers that containment.
- It does **not** reach **structurally-invisible self/family content** (§10.1.4) — that content is moderated only by its own members, by construction. The invariant narrows the unmoderated surface to *exactly* the irreducible E2EE-equivalent core, and no further (§B.1).
- It does **not** prevent a determined actor from running a **private off-fabric** group; it governs what can exist *as a CIRIS community*. A predator who wants an unmoderated space must leave the fabric — which is the point: the fabric never hosts one.

---

## B. Anti-predator audit

Honest pass over the model for predator-enabling gaps. Format per gap: **the vector → how the design contains it → residual risk (stated plainly).** The maintainer asked for "you tell me," not reassurance; residuals are real.

### B.1 The hard problem — structural-invisibility (§10.1.4) vs CSAM detection

**The vector.** `cohort_scope: self | family` content **never emits `holds_bytes:*`** and **never federates** — it is delivered member-to-member, optionally at-rest-encrypted (PQC v2). This is **E2EE-equivalent**: a non-member cannot even discover the content exists, let alone fetch it. This is precisely the property offenders exploit on every E2EE network (Signal/Session/SimpleX/Matrix encrypted rooms — see §SAFETY_LANDSCAPE). **A predator's own device and a colluding family-scope are, by construction, a place hash-matching cannot reach.** We must not pretend otherwise.

**How the design contains it (precisely — where detection *can* run):**

1. **The publish/promote boundary is the detection seam.** The moment content crosses *out* of self/family — a `supersedes` promotion to `cohort_scope: community | federation` (§8.1.8.1 Tiered-Scope), or any inline-blob ingress to a shared scope — it emits `holds_bytes:*` and enters the path where `src/safety/hash_match.rs` runs the `PerceptualHashMatcher` (§4.1). **Sharing is the act that exposes content to matching; private holding is not.** Most CSAM harm is *distribution* and *grooming-to-distribution*; the boundary is exactly where the network gains leverage. This mirrors the only honest answer the field has (Matrix scans unencrypted/shared content; nobody scans the private core).
2. **Client-side, at the producing occurrence, is the *only* place private content is in cleartext** — and it is the one place CIRIS deliberately does **not** mandate scanning, for the same reason Apple abandoned client-side scanning (§SAFETY_LANDSCAPE: the mass-surveillance backdoor it creates, the false-positive and scope-creep risk). The design's position is explicit: hash-matching runs at **share/publish ingress**, not as a mandated client-side scan of private holdings. We inherit the unsolved tension; we do not claim to have solved it.
3. **Structural-invisibility is content-*holding* confidentiality only** (§10.1.4 normative scope) — it is **NOT** relationship-existence, metadata, or traffic-analysis privacy. So the *graph* around private content is still observable: `delegates_to` edges, membership-change `hard_case:*` events, the *existence and shape* of a family, age-assurance attestations, report attestations naming a canonical-hash subject. **Behavioral/coordination detection (`detection:*`, `ratchet:flag:*`, grooming patterns — §B.3) operates on this observable metadata layer even when the content bytes are invisible.** This is the genuine, non-magical lever the invariant + the metadata grain give us.
4. **The named-moderator invariant narrows the surface** to *exactly* self/family — every *multi-party* space (`community`) has a named moderator who *can* see community-scoped content and on whom the duty + the hash-match seam land. There is no unmoderated *multi-party* space for a predator to operate a ring in; they are pushed down to self/family, which is small, member-gated, and not a distribution surface.

**Residual risk (honest).** A predator operating purely within self/family scope — solo possession, or a fully-colluding family-scope (e.g. an abuser and a coerced household member) — is **not detectable by the substrate**, exactly as on every E2EE system. Hash-matching cannot run on bytes that never cross the share boundary and are never presented for matching. The containment is: (a) the moment they *distribute*, they hit the seam; (b) the metadata/coordination layer is still visible; (c) NCMEC/CyberTipline + law-enforcement process (device seizure, undercover, victim report) remain the out-of-band path the fabric does not replace. **CIRIS does not solve the private-content problem. No one has. What it does is refuse to *add* unmoderated multi-party spaces on top of that irreducible core** — the opposite of the surveyed networks, which add many.

### B.2 The unmoderated-group vector — closed by the invariant

**The vector.** The single highest-leverage predator structure on decentralized networks: a multi-party space with **no accountable moderator** — an unmoderated Nostr relay, an orphaned Matrix room, an absentee-admin Mastodon instance, an unmonitored group chat. Rings form, content circulates, grooming proceeds, and *no one is responsible*.

**How the design contains it.** §A directly: such a space **cannot exist** as a CIRIS community. The existence gate refuses admission without a named moderator; auto-promotion prevents any transient gap; fail-secure quiesces a group that cannot name one. There is no protocol-conformant unmoderated multi-party CIRIS space. This is the one place CIRIS is *structurally* different from every surveyed network (all of which permit unmoderated spaces — §SAFETY_LANDSCAPE table).

**Residual risk.** (a) The moderator can be *present but negligent/captured* — see §B.4 (presence ≠ diligence; containment is the accountability chain + appeals + canonical authority, not the invariant alone). (b) The self/family core (§B.1) is by-design member-moderated only. (c) A determined ring can run **off-fabric**; CIRIS governs CIRIS communities, not the existence of other software.

### B.3 Grooming / coordination patterns

**The vector.** Grooming is a *behavioral pattern over time* (trust-building, isolation, escalation, off-platform migration), not a single matchable artifact. Hash-matching is blind to it.

**How the design contains it.** The `detection:*` / `ratchet:flag:*` advisory corpus (§6, lens-core `scoring/`) operates on the **observable metadata/behavioral layer** (§B.1 point 3) — message-rate/asymmetry, contact-graph anomalies (an adult node initiating many edges to age-assured-minor nodes), cross-scope migration attempts, `ratchet:flag:harassment_pattern` and sibling pattern flags. Critically, these are **advisory only — `ratchet:flag:*` can NEVER be sole evidence for `slashing:*`; a WA-quorum / named-moderator adjudication is the load-bearing gate** (§6, CEG `05_namespace.md:1175`). Detection *surfaces to the named moderator*; the moderator (or their delegate brain) adjudicates; quorum gates any punitive action. RATCHET is hash-pinned + deterministic, so a flag is reproducible and contestable.

**Residual risk.** Grooming detection is **probabilistic and adversarial** — sophisticated actors throttle to stay under thresholds, migrate off-fabric early (the metadata shows the *attempt* to migrate, not the off-fabric continuation), and groom within structurally-invisible scope where the behavioral signal is thin. False positives are a real harm (an innocent adult-minor mentor relationship flagged). The design's honesty: detection is a *surfacing aid for an accountable human*, never an autonomous verdict — which both limits the false-positive harm and limits the catch rate. No decentralized network has solved grooming detection; CIRIS's contribution is that there is **always a named, accountable human the flag lands on**, which the unmoderated networks lack.

### B.4 Collusion — a predator delegating moderation to a colluding party

**The vector.** The named-moderator invariant requires *a* moderator — what if the predator *is* the moderator, or delegates `moderate` to a colluding party who rubber-stamps the ring? Presence of a moderator ≠ safety if the moderator is captured.

**How the design contains it (defense in depth — no single layer suffices):**

1. **Attribution + the chain.** Every moderation action and every delegation is **signed and traceable** up the `delegates_to` chain to an **owner-bound accountable human** (§5.6.8.10). A colluding moderator is *named and on the record* — there is no anonymous capture. Collusion leaves a signed audit trail.
2. **Rules are crowdsourced + operational-language-gated; verdicts are deterministic.** Per the CIRIS safety-vs-censorship position, the *rules* a moderator enforces are "public, dated, signed, reversible," proposed and voted by the community — **not the moderator's private discretion** — and every rule must pass the operational-language gate ("checkable without judgment, or it isn't ready"). A captured moderator **cannot quietly invent a permissive rule**: rule-changes are public and voted. And because "same response + same rule → same verdict," a colluding moderator who *fails to act* on content that mechanically violates a public rule is **visibly deviating from the deterministic verdict** — the non-action is itself detectable.
3. **Appeals with recusal.** Reconsideration (`reconsideration:{grounds}`, §11.10 `review` scope) goes to **a fresh review group with the original adjudicators recused** (safety-vs-censorship position; CEG §8.1.5 fresh-quorum recusal). A colluding moderator cannot sit on the appeal of their own (in)action. `witness_diversity` (jurisdictional + organizational + software-stack diversity, N≥3) raises the bar for a *colluding quorum*.
4. **Canonical / founder authority + HUMANITY_ACCORD.** Above the community sits `ciris-canonical` (the founder-quorum `infrastructure` trust root) and, at the apex, the §9 HUMANITY_ACCORD 2-of-3. A community whose entire moderation is captured can be reached by the takedown/eviction path and, in the limit (a community structured to systematically host abuse), the constitutional path — neither of which the captured local moderator can block.
5. **Reputation consequences feed auto-promotion.** A moderator found colluding (via appeal-overturn, `moderation:*` allegation upheld) is slashed / loses `moderation_track_record`, which **demotes them out of the auto-promotion candidate ranking** (§A.3) and surfaces a successor.

**Residual risk (honest).** A **fully-colluding community** — predator-moderator + colluding members + a colluding appeal quorum who all decline to file reports — defeats the *internal* layers, because every internal check ultimately needs *someone* to file a report or appeal. The genuine backstops then are: the **operational-language-gated public rules** (the colluding group still can't make abuse *rule-compliant* without a public, voted, signed rule-change that the wider federation sees), the **observable metadata/coordination layer** (§B.1/§B.3 — a tight collusive ring has anomalous graph structure), **out-of-band reporting** (a victim, a departing member, law enforcement), and **canonical/accord authority from above.** This is the same residual every system has against a fully-closed colluding group; CIRIS's edge is that the collusion is **signed, attributed, and forced to operate against public deterministic rules** rather than in an anonymous unmoderated void. It is *harder and more exposed*, not impossible.

### B.5 Private-group abuse + age-gate evasion

**The vector.** (a) A private `community` (small, invite-only) used to host a ring under a complicit moderator. (b) Age-gate evasion: an adult self-declaring as a minor to enter youth spaces, or a minor declaring adult to bypass protections, or a predator declaring minor to approach minors.

**How the design contains it.**

- **Private community ≠ unmoderated community.** Even a small invite-only `community` is bound by §A: named moderator, accountability chain, public operational-language-gated rules. It is **not** structurally-invisible (only self/family is — §10.1.4); community-scoped content emits `holds_bytes:*` with cleartext provenance and is reachable by the named moderator and the hash-match seam. The "private group" predators rely on elsewhere does not get the §10.1.4 invisibility — it gets the §B.2 invariant. (A predator who wants *true* invisibility must drop to self/family, i.e. §B.1's irreducible core — they cannot have both invisibility *and* multi-party reach inside the fabric.)
- **Age-assurance is layered, subject-signed, and misdeclaration is adjudicated, never auto-trusted** (§4.2). The ladder `self < provider:{verifier_key}:adult < government:{credential_class}:adult` means a youth space can require a *verified* assurance level, not bare self-declaration — a predator's `self`-declared age does not clear a `provider:`-gated space. **Misdeclaration routes to `moderation:age_assurance_misdeclaration` adjudication** (a `ModerationEvent` + quorum), and an adult who self-declared minor to approach minors is exactly the high-signal event the `detection:*` graph layer surfaces (adult-pattern node with minor self-declaration + edges to verified minors).

**Residual risk (honest).** **Self-level age assurance is unfalsifiable from inside the fabric** — a determined predator self-declaring minor cannot be caught by the assurance mechanism alone; only the *requirement of a verified level* for sensitive spaces, plus the behavioral/graph layer, constrains them. Verified levels (`provider:`/`government:`) depend on **out-of-fabric verifiers** whose own integrity the fabric must trust (a compromised verifier mints false adulthood/minority). And age-assurance for minors composes via parental `delegates_to` (§9 #9) — which assumes a *non-abusive* parent; the coerced-household case (§B.1) is the gap where the delegating "guardian" is the threat. CIRIS narrows age-gate evasion to the verifier-trust and coerced-guardian edges; it does not eliminate them.

### B.6 Audit summary table

| Vector | Primary containment | Fails open elsewhere? | CIRIS residual (honest) |
|---|---|---|---|
| Unmoderated multi-party space | §A existence invariant + auto-promotion + fail-secure | **Yes — all surveyed nets** | Self/family core is member-moderated only; off-fabric groups exist |
| Private self/family CSAM (E2EE-equivalent) | Detection at share/publish seam; metadata layer; NCMEC out-of-band | n/a (universal) | **Unsolved — same as all E2EE; not claimed solved** |
| Grooming / coordination | `detection:*`/`ratchet:flag:*` advisory → named moderator adjudicates; quorum gates slashing | Mostly yes | Probabilistic, adversarial, off-fabric migration; false-positive harm |
| Colluding moderator | Signed chain + public op-language rules + deterministic verdicts + recused appeals + canonical/accord | Yes | Fully-closed colluding ring needs out-of-band trigger; harder + exposed, not impossible |
| Private-group ring | §A applies (private ≠ unmoderated; not §10.1.4-invisible) | Yes | Predator can drop to invisible self/family — but loses multi-party reach |
| Age-gate evasion | Layered subject-signed assurance + verified-level gates + misdeclaration adjudication + graph layer | Yes | `self`-level unfalsifiable; verifier-trust + coerced-guardian edges remain |

---

## 10. Summary

Moderation and child-safety are **delegable duties over shipped CEG primitives**, not a centralized moderator role. The fabric provides the primitives + the `delegates_to` scope; any participant exercises a duty themselves, delegates it to their agent, or delegates it to any trusted party — and because `agent = fabric app + agent cards`, the agent inherits these by delegation. Every action is delegate-signed, delegator-traceable, instantly revocable, and coordinated — the structural form of "takedown isn't a coup," with the §9 HUMANITY_ACCORD as the one asymmetry above it all.

The takedown fast-path, `ModerationEvent`, hash-matcher trait, eviction, erasure, and ejection/noise-floor all **ship in the substrate today**; the three delegation scope tokens (`moderate`/`takedown`/`review`) are **now named + enforced upstream** (CEG §11.10, RC19 — see §9bis), so the remaining work is persist enforcement + fabric wiring, not a primitive ask. The genuine remaining gaps are the age/rating dimensions (workable fabric-side over generic `scores`), the `moderation_track_record`/`hard_case:community_unmoderated` vocabulary the existence invariant needs (§9 #10–#11), and a concrete PDQ matcher adapter. Build the delegation spine + the named-moderator existence gate (§A) + takedown + CSAM first; video last.

**The two child-safety load-bearers are §A and §B.** §A — *a group without a named moderator cannot exist* — is the structural invariant: no unmoderated multi-party space, ever; auto-promotion-by-merit closes any gap; fail-secure is the floor. §B — the anti-predator audit — names each predator-enabling vector, how the design contains it, and the honest residual (the structurally-invisible self/family core is E2EE-equivalent and is **not** claimed solved — it is narrowed to the irreducible minimum and no further). The comparative grounding for both is `FSD/SAFETY_LANDSCAPE.md`: every surveyed network (Nostr, Matrix, Mastodon, Bluesky, IPFS, Signal, Session, SimpleX, Briar) **permits** unmoderated multi-party spaces and fails *open*; CIRIS is the only one that fails *secure* — uniquely suited on governance, while inheriting the universal private-content detection limit.
