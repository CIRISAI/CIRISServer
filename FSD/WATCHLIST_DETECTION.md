# FSD — Content-Watchlist Auto-Detection (opt-in, per-group, fabric-level)

**Issue:** CIRISServer#15 (child-safety / moderation fabric primitives — watchlist feature)
**Status:** Design + build-plan (research pass — no production code beyond type scaffolding that sharpens the design)
**Branch:** `wt/watchlist`
**Substrate pins:** ciris-persist `v8.4.0` (`7b40aae`), ciris-edge `v4.3.0` (`ab4f1bc`), ciris-verify-core `v5.10.0` (`be25114`), CEG `1.0-RC19`
**Companion:** `FSD/MODERATION_CHILD_SAFETY.md` (the delegation spine §0/§3, the §A named-moderator invariant, the §B anti-predator audit), `FSD/SAFETY_LANDSCAPE.md` (Bluesky hash-match-at-upload → auto-remove → NCMEC, the peer model).

---

## 0. The feature in one paragraph

The maintainer's spec: *"anyone should optionally be able to turn on a CSAM or other content watchlist — for groups they moderate or have authority over; a fabric-level feature to auto-fire a detection. That is on us now that we've absorbed lens."* Concretely: a holder of the `moderate` scope over a group can **opt in** (default OFF) to one or more **watchlists** — a CSAM perceptual-hash DB, or any other named exact/fuzzy content list — and from that moment the fabric **auto-fires the matcher at the publish/share seam** of that group, and **auto-fires an action under the enabling authority** on a hit: CSAM → `takedown_notice{legal_basis: PerceptualHashCsam}` (immediate §11.4 eviction + the operator's §2258A reporting duty); other lists → a flag / `ModerationEvent` / `detection:*` routed to the named moderator. Every step is signed, attributed to the enabling authority, and on the audit chain. The watchlist is not a new structural primitive — it is a **config attestation** (the consent.rs recipe) wired to the **already-shipped** §11.5 `PerceptualHashMatcher` trait and the §11.4 takedown fast-path.

This document is the watchlist-specific deepening of `MODERATION_CHILD_SAFETY.md` §4.1 (CSAM hash-DB matching). MCS §4.1 designed the *matcher at ingress*; this designs the *opt-in, per-group, by-authority enable/disable control over it* and the *auto-fire-the-action* path, with the honest hard parts.

---

## 1. The three-way split (who is responsible for what)

The single most important framing — every honest claim and every hard part flows from it:

| Concern | Owner | What they hold | What they do NOT do |
|---|---|---|---|
| **The fabric** (CIRISServer) | the protocol/code | the *mechanism*: the config primitive, the seam hook, the matcher invocation, the auto-fire-of-action, the audit chain | does NOT provide the hash-DB; does NOT make the legal report; does NOT decide policy |
| **The operator** (deployment) | the node/instance operator | the *matcher backend*: the operator-provisioned `PerceptualHashMatcher` impl + its hash-DB(s) under the operator's own IWF/NCMEC/PhotoDNA agreement (§11.5); the §2258A NCMEC CyberTipline report | does NOT silently scan; does NOT reach §10.1.4 private content |
| **The authority** (a `moderate`-scope holder) | a human/agent over a group | the *opt-in decision*: turning a watchlist ON for a group they moderate; this enable is itself a signed, attributed, revocable act | does NOT see raw matched bytes (hash-match is mechanism, no human in the CSAM match loop); cannot enable for a group they lack `moderate` over |

The watchlist is **opt-in by the authority, executed by the fabric, powered by the operator's hash-DB.** No single party can both (a) turn it on and (b) provide the illegal-content list and (c) write the legal report — the responsibilities are deliberately separated, which is also why no single party's compromise silently turns the fabric into a surveillance tool.

---

## 2. What ships vs the gap (grounding in the absorbed lens engine + persist)

`crates/ciris-lens-core/` is the absorbed detection engine. Two distinct detection families live there, and the watchlist uses the *second* path, plus the persist hash-match trait:

| Surface | Where | Watchlist relevance |
|---|---|---|
| `PerceptualHashMatcher` trait | `CIRISPersist .../federation/perceptual_hash.rs` (re-exported) — `check(sha256, body) -> HashMatchResult{NoMatch \| Match{database, score, threshold}}`, `databases()`, `on_match_policy() -> {Refuse, ReportThenRefuse, AlertOnly}`, `matcher_unreachable_policy() -> {FailClosed (default), FailOpen}` | **The CSAM/exact-hash watchlist runs over THIS.** Trait ships; `NullPerceptualHashMatcher` is the default; concrete PDQ/PhotoDNA/Arachnid adapters are **intentionally out-of-tree** (operator-tier, per §11.5.1). |
| `DetectionEvent` / `detection:*` + `ceg_egress.rs` | `crates/ciris-lens-core/src/canonical/ceg_egress.rs`, `src/detector/`, `src/scoring/` | **The non-CSAM "other content list" + behavioral-flag path.** `DetectionAttestation::from_event` already federates `detection:*` events, and **already suppresses `self`/`family` scope** (`cohort_scope::suppresses_holds_bytes`) — the structural-invisibility limit is *already enforced in the egress code* (see §6). Note: `src/detector/detect()` is a v0.1.0 **no-op** (returns `None` until the Phase-2 Mahalanobis port lands) — so the behavioral-detection family is not yet firing; the hash-match family does not depend on it. |
| `takedown_notice` + `LegalBasis` | `CIRISPersist .../cirisnode/media_sharing.rs` — `TakedownNoticePayload{content_sha256, perceptual_hash, legal_basis, jurisdiction, good_faith_statement, counter_notice_channel, ...}`; `LegalBasis::PerceptualHashCsam`; `requires_immediate_eviction()` true for the five immediate bases; handler `process_takedown_admission` | **The auto-fire target for a CSAM hit.** Ships fully. |
| `delegates_to` scopes `moderate`/`takedown`/`review` | CEG §11.10 (RC19), enforced-admission like `consent_revocation` | **The authority gate** on enabling a watchlist + on the auto-fired action. |

**The gap, stated honestly:** (1) the **concrete matcher adapter** is not shipped — the trait + the seam are ready, the hash-DB-backed `PdqHashMatcher` is operator-provisioned (§7.1); (2) there is **no `watchlist_config` dimension** in the substrate — but per the §4.2/§4.3 precedent in MCS, the config rides a **generic `scores`/attestation row under a fixed dimension name, fabric-side, no new primitive** (§3); (3) `src/safety/` does not exist yet — this is the new fabric home (§5).

---

## 3. The watchlist config primitive (enable / disable, per-group, by-authority, signed, revocable)

**No new structural primitive.** The enable is a **config attestation** — exactly the `consent.rs` recipe (`attestation_upsert_local` + optional `attestation_promote`), specialized to a fixed dimension `watchlist:{watchlist_id}` and gated on the `moderate`/`takedown` scope rather than self-occurrence. This mirrors how MCS §4.2/§4.3 land the age/rating dimensions fabric-side over generic `scores`.

### 3.1 The enable attestation (shape)

```rust
// SCAFFOLD (src/safety/watchlist.rs) — sharpens the design; not wired this pass.

/// A watchlist enable/disable is a config attestation, NOT a new wire primitive.
/// It rides `attestation_upsert_local` + (optionally) `attestation_promote`, the
/// same path consent.rs uses, with `attestation_type = "watchlist_config"` and a
/// fixed dimension. The act is admitted IFF the signer holds `moderate` (CSAM:
/// also `takedown`) over `group_key_id` — a live, unrevoked delegates_to chain
/// per CEG §11.10 (the same enforcement consent_revocation gets).
pub struct WatchlistEnable {
    /// The group (`community` key_id) the watchlist is scoped to. The authority
    /// MUST hold `moderate` for THIS group — enable is per-group, never global.
    pub group_key_id: String,
    /// Which watchlist. Free-form operator-pinned id (e.g. "csam:ncmec",
    /// "csam:iwf", "tos:extremist-symbols-v3"). Maps to a HashDatabaseId the
    /// operator's matcher exposes via `databases()` (§7.1).
    pub watchlist_id: String,
    /// CSAM vs other-content — drives the auto-fire branch (§4) and the no-human
    /// -in-the-loop rule (CSAM only).
    pub class: WatchlistClass,
    /// true = enable, false = disable. Disable emits a `withdraws` against the
    /// enable attestation (revocability == consent requires revocability).
    pub enabled: bool,
    /// For non-CSAM lists: the moderator key_id a match routes the flag to
    /// (§4.2). For CSAM this is ignored (no human in the match loop).
    pub route_to_moderator: Option<String>,
    /// Optional shadow window: enable as AlertOnly (log, don't act) to
    /// characterize false-positive rate before flipping to enforce (§8 over-blocking).
    pub mode: WatchlistMode,
}

pub enum WatchlistClass { Csam, OtherContent }
pub enum WatchlistMode  { AlertOnly, Enforce } // maps to OnMatchPolicy at the seam
```

The wire envelope written to persist:

```json
{
  "dimension": "watchlist:csam:ncmec",
  "group_key_id": "community:...",
  "class": "csam",
  "enabled": true,
  "mode": "enforce",
  "route_to_moderator": null
}
```

`attestation_type: "watchlist_config"`, `cohort_scope: "community"` (the group's scope), `subject_key_ids: [group_key_id]`, signed by the enabling authority's key.

### 3.2 Authority gate (the load-bearing check)

```
enable/disable a watchlist for group G is ADMITTED IFF
  signer_may_act_in_scope(engine, signer, G, "moderate")   // §11.10 chain-walk
  AND (class != Csam OR signer_may_act_in_scope(engine, signer, G, "takedown"))
```

`signer_may_act_in_scope` is the generalization of `verify::signer_acts_for` that MCS §3 specifies (walk persist's `build_delegation_graph()`, accept the principal / an admitted occurrence / the tail of a live unrevoked `delegates_to` chain bearing the scope). CSAM additionally requires `takedown` because a CSAM match auto-files a `takedown_notice` (the action it fires demands the action's own scope — you cannot enable an auto-takedown without holding takedown authority).

### 3.3 Revocation

Disable = `withdraws` against the enable attestation (persist `DelegationEdge.withdrawn_by` / attestation-withdraw path). The seam reads the **current** enable set per group on each publish; a withdrawn enable drops out mid-flight, exactly like a revoked delegation. **Consent requires revocability** — turning a watchlist off is as attributed and immediate as turning it on. (Honesty: a CSAM watchlist *can* be disabled by the authority who enabled it, but disabling it does not un-fire reports already made, and a deployment/operator MAY pin certain `csam:*` lists as non-disensableable at the operator tier — that is an operator-policy choice above the fabric, not a fabric default.)

### 3.4 Why per-group, not global

Global "scan everything" is exactly the bulk-surveillance posture CIRIS refuses (Apple-CSS / EU-CSAR critique, `SAFETY_LANDSCAPE`). Scoping the enable to *a group the authority already moderates* keeps the act **proportionate and attributed**: the authority is acting within authority they already hold (CEG §11.10 "the duty is held or delegated, never assumed"), over a multi-party space that already has a named accountable moderator (MCS §A). There is no fabric-wide watchlist; there is no watchlist over a group you do not moderate.

---

## 4. The auto-fire path (match → action under the enabling authority)

### 4.1 CSAM (the one no-human-in-the-loop case)

Mirrors Bluesky's shape exactly (`SAFETY_LANDSCAPE` line 32/53: hash-match at upload → immediate removal → NCMEC report): the match is mechanism, the removal is automatic, the human enters only at the operator's legal-reporting step.

```
On content published/shared into group G that has a Csam watchlist enabled:
  1. seam computes sha256 + invokes matcher.check(sha256, body)   (§5)
  2. NoMatch  -> admit, done.
  3. Match{database, score, threshold} AND mode == Enforce:
       a. AUTO-FILE takedown_notice {
            content_sha256, perceptual_hash: Some(hash),
            legal_basis: PerceptualHashCsam,        // requires_immediate_eviction() == true
            jurisdiction, good_faith_statement: "<auto: watchlist match on {database}>",
            counter_notice_channel: None,           // CSAM admits no counter-notice (§11.4 step 5)
          }
          signed under the ENABLING AUTHORITY's key (the takedown-scope holder
          who turned the watchlist on) — NOT the publisher, NOT the fabric itself.
       b. process_takedown_admission -> withdraws against holds_bytes (§11.4 step 2): holders evict.
       c. emit hard_case:fast_path_takedown audit Contribution (§11.4 step 4).
       d. OPERATOR duty fires: the operator's matcher impl (ReportThenRefuse policy)
          files the §2258A NCMEC CyberTipline report. The FABRIC emits the evidence
          row (hash + minimal metadata, NO content retention §11.4 step 3); the
          OPERATOR reports. (§7.2 — this split is legally load-bearing.)
  4. Match AND mode == AlertOnly: admit + emit detection:csam_watchlist_alert
     (shadow rollout — characterize FP before flipping to Enforce; §8).
```

**No human reviews the match before removal.** This is deliberate and is the *only* place the design auto-acts without a human adjudicator — justified by (a) the legal posture (you may not "review" suspected CSAM — viewing it is itself the offense; the operator's NCMEC pipeline is the only lawful handling), and (b) the peer norm (Bluesky/IFTAS/PhotoDNA all auto-remove on hash-match). The accountability is *post-hoc and audited*, not pre-hoc and human (§4.3).

### 4.2 Other content lists (human-named-moderator in the loop)

For `WatchlistClass::OtherContent` (a ToS list, an extremist-symbol set, a community-specific banned-media list), the auto-fire is a **surface-to-the-moderator**, never an autonomous punitive act — the MCS §6 / `ratchet:flag:*` discipline ("advisory only; WA-quorum/named-moderator is the load-bearing gate; never sole evidence for slashing"):

```
Match (OtherContent) ->
  1. emit detection:watchlist_match{watchlist_id, content_sha256, score} as an
     advisory scores attestation (the lens-core detection:* egress path, §6).
  2. emit a ModerationEvent OR route a flag to route_to_moderator (the named
     moderator of G) for adjudication — the moderator (or their delegate brain)
     decides the action via the report->surface->act path (MCS §4.4).
  3. NO auto-eviction. The human-named-moderator-in-the-loop is the gate; the
     content stays until adjudicated (with mode==Enforce optionally hiding it
     pending review per operator policy — a soft, reversible hide, not a takedown).
```

The asymmetry — CSAM auto-removes, everything else routes to a human — is the core safety/over-blocking calibration (§8).

### 4.3 Attribution & the audit chain

Every auto-fired action carries the full chain — *who turned it on, what matched, what fired*:

| Step | Attested by | Audit artifact |
|---|---|---|
| watchlist enabled | enabling authority (moderate/takedown scope holder) | `watchlist_config` attestation (§3.1), signed, on chain, revocable |
| match fired | the fabric seam (deterministic) | the `Match{database, score, threshold}` recorded on the takedown/detection event |
| takedown auto-filed (CSAM) | enabling authority's key (the action is *attributed up the delegation chain to the human who enabled it*) | `takedown_notice` + `hard_case:fast_path_takedown` |
| eviction | the `withdraws`-against-`holds_bytes` | persist `SweepReport` |
| NCMEC report (CSAM) | the **operator** | operator's CyberTipline submission ref (out-of-fabric; the fabric logs that a report was due, not the report body) |
| flag routed (other) | enabling authority's key | `detection:watchlist_match` + `ModerationEvent` |

This is "takedown isn't a coup" (MCS §0/§5) applied to auto-detection: an auto-fired takedown is *still* a signed notice traceable to an accountable human (the authority who enabled the watchlist), instantly revocable (disable the watchlist), and audited — it is not the fabric unilaterally seizing content. The fabric is the *executor* of an authority's standing, signed instruction, not an autonomous censor.

---

## 5. The detection runtime (the matcher at the seam) + the fabric Rust home

### 5.1 The seam

Detection runs at exactly one place: the **publish/share seam** — `put_blob_signing` inline-blob ingress (the persist hook the §11.5 matcher already targets) for content crossing into a watchlist-enabled group's scope. This is the same seam MCS §4.1/§B.1 identifies: *sharing is the act that exposes content to matching; private holding is not.* `External`-body content is skipped (its bytes never transit the fabric — nothing to hash; §11.5 "external-body skip").

### 5.2 The fabric home

```
src/safety/                     (new — sibling to src/auth/, same thin-router-over-Engine pattern)
  mod.rs                        exposes routers + the seam hook; composed in src/compose.rs
  watchlist.rs                  THIS feature: WatchlistEnable config, the per-group enable
                                 registry read, the seam hook that (a) checks "is a watchlist
                                 enabled for G?", (b) invokes matcher.check, (c) drives §4 auto-fire.
  hash_match.rs                 (MCS §4.1) holds Arc<dyn PerceptualHashMatcher>; the matcher
                                 invocation + OnMatchPolicy/FailClosed enforcement. watchlist.rs
                                 calls into this; hash_match.rs is matcher mechanics, watchlist.rs
                                 is the per-group/by-authority opt-in control over it.
  takedown.rs                   (MCS §5) the §11.4 fast-path the CSAM branch auto-fires into.
  report.rs / moderation.rs     (MCS §4.4/§6) the other-content flag/ModerationEvent route.
```

The seam hook (pseudocode):

```rust
// src/safety/watchlist.rs — SCAFFOLD
pub async fn on_publish(engine: &Engine, matcher: &SharedMatcher,
                        group: &str, sha256: &[u8;32], body: &[u8]) -> SeamOutcome {
    let enabled = watchlist_enables_for_group(engine, group).await; // §3 config read
    if enabled.is_empty() { return SeamOutcome::Admit; }            // opt-in: default OFF
    match matcher.check(sha256, body).await {
        Ok(HashMatchResult::NoMatch)        => SeamOutcome::Admit,
        Ok(HashMatchResult::Match{database, score, threshold}) => {
            let wl = enabled.matching(&database);                   // which enable owns this DB
            auto_fire(engine, wl, sha256, score, threshold).await   // §4 branch on class/mode
        }
        Err(HashMatchError::Unreachable(_)) => match matcher.matcher_unreachable_policy() {
            MatcherUnreachablePolicy::FailClosed => SeamOutcome::Refuse, // default — never admit unscanned
            MatcherUnreachablePolicy::FailOpen   => SeamOutcome::Admit,
        },
        Err(HashMatchError::InputMalformed(_)) => SeamOutcome::RejectInput,
    }
}
```

**Fail-closed is the default** (inherited from the trait + MCS §A.4): if the matcher is unreachable, a watchlist-enabled group does **not** admit unscanned content. The availability cost is the deliberate trade for the safety floor (an operator with a high-SLA matcher MAY flip `FailOpen`).

### 5.3 Fabric vs operator vs authority at the runtime

- **Fabric:** owns `on_publish` — the enable lookup, the `check` invocation, the policy enforcement, the auto-fire dispatch. Pure mechanism; no brain in the CSAM loop.
- **Operator:** owns the `SharedMatcher` impl installed via persist's `set_perceptual_hash_matcher` — the hash-DB, the threshold, the `on_match_policy` (CSAM operators set `ReportThenRefuse`), the NCMEC carrier.
- **Authority:** owns the `WatchlistEnable` rows — which groups, which lists, enforce-vs-alert. The fabric reads their standing instruction on every publish.

---

## 6. The structural-invisibility limit (honest — do not claim otherwise)

Detection runs **only at the share/publish seam of watchlist-enabled groups.** It **cannot** reach `cohort_scope: self | family` content (CEG §10.1.4) — that content never emits `holds_bytes:*`, never federates, is delivered member-to-member, and is the E2EE-equivalent irreducible core. This is **already enforced in code, not just promised**: `ceg_egress.rs::build_state_publication` filters every event where `cohort_scope::suppresses_holds_bytes(scope)` is true (`self`/`family`), and the test `build_state_publication_filters_invisible_scopes` pins it. The watchlist inherits this — a watchlist enabled over a group cannot scan content that never enters the group's shared scope.

Consequences, stated plainly (these mirror MCS §B.1):
- A predator's own device (`self`) and a fully-colluding `family`-scope are, by construction, places the watchlist cannot reach. **CIRIS does not solve the private-content CSAM problem. No one has.** (Apple abandoned client-side scanning; the EU CSAR retreated; §2258A has no scan mandate.)
- The watchlist deliberately does **not** mandate client-side scanning of private holdings — that is the bulk-surveillance backdoor the field rejected.
- What the watchlist *does*: catches content **the moment it is distributed** (the share boundary, where most CSAM harm and grooming-to-distribution lives), over **multi-party groups that already have a named accountable moderator** (MCS §A). The metadata/coordination layer (`detection:*`, graph anomalies) remains visible even where bytes are not (§4.2, MCS §B.3). Out-of-band NCMEC/law-enforcement process remains the path the fabric does not replace.

The watchlist narrows the undetectable surface to *exactly* the irreducible self/family core and no further — it does not pretend to reach inside it.

---

## 7. The hash-DB licensing & provisioning seam (honest hard part #1)

### 7.1 You cannot ship the hashes — the matcher is operator-provisioned

IWF, NCMEC, PhotoDNA, and Project Arachnid hash sets are **access-gated**: they require signed operator agreements, are not redistributable, and CIRIS has no privileged access to them. Therefore **the fabric ships the seam, never the hashes** — exactly as persist already designed (`perceptual_hash.rs`: "concrete in-tree adapters are NOT shipped … operators wire their own matcher"; CEG §11.5.1 ratified self-hosted PDQ against publicly-distributed feeds as the default operator path).

The provisioning seam:

```
1. Operator obtains hash-DB access under their OWN agreement (IWF membership,
   NCMEC hash-sharing, Thorn/Safer, or the open PDQ + public feeds path §11.5.1).
2. Operator implements `PerceptualHashMatcher` (the out-of-tree adapter) wrapping
   their DB + algorithm (PDQ perceptual for images/video per §11.5; exact SHA-256
   or fuzzy for other lists), sets on_match_policy = ReportThenRefuse (CSAM) and
   the NCMEC carrier inside the impl.
3. Operator installs it via persist's `set_perceptual_hash_matcher`. The fabric
   emits `system:perceptual_hash_matcher:registered` on startup (operator-UI/telemetry
   introspection via `databases()`).
4. The `watchlist_id` an authority enables (§3.1) maps to a `HashDatabaseId` the
   operator's matcher exposes. Enabling a watchlist_id the operator has NOT
   provisioned -> reject the enable (you cannot turn on a list the node cannot match).
```

**The one out-of-tree gap the fabric should close:** a reference `PdqHashMatcher` adapter against the **open** PDQ algorithm + **publicly-distributed** feeds (the §11.5.1 default — no restricted-DB agreement needed). This proves the seam end-to-end and gives small operators a no-license-required starting matcher. The restricted DBs (PhotoDNA/IWF/NCMEC) stay strictly operator-provisioned. Decide: in-fabric optional crate (feature-flagged) vs upstream-contributed persist adapter (recommend: a `ciris-server` optional crate `crates/ciris-pdq-matcher/`, feature-gated, so the default build ships no matcher and no hash-DB dependency).

### 7.2 The legal duty is the operator's, not the fabric's (hard part #4)

18 USC §2258A is **reactive reporting on knowledge** (subsection (f): *no* scanning mandate) and it is the **operator's** duty as the provider, not the fabric's. The split:

- **The fabric emits the evidence**: the `takedown_notice` + `hard_case:fast_path_takedown` + the hash/minimal-metadata row (no content retention, §11.4 step 3), and a marker that a §2258A report is *due*.
- **The operator files the report**: the operator's matcher impl (`ReportThenRefuse`) carries the NCMEC CyberTipline submission; the operator is the legal reporter.

The fabric must **not** claim to make NCMEC reports (it is not the provider-of-record and has no NCMEC ESP registration). The watchlist design's correctness depends on never blurring this — the fabric is evidence + mechanism; the operator is the legal actor.

---

## 8. Over-blocking / false positives (honest hard part #3)

Perceptual hashing (PDQ/PhotoDNA) is **fuzzy by design** — it matches visually-similar, not byte-identical, content, so collisions and false positives are real (a benign image perceptually near a known-bad one). The design's calibration:

1. **Shadow / AlertOnly mode (§3.1, §5.2).** An authority enabling a *new* watchlist or a *new* operator matcher SHOULD start in `WatchlistMode::AlertOnly` (maps to `OnMatchPolicy::AlertOnly`): log the match, do not act, characterize the false-positive rate, then flip to `Enforce`. This is the persist trait's documented shadow-rollout use.
2. **The CSAM/other-content asymmetry (§4).** CSAM auto-removes (the one no-human case — legally you cannot review it, and the peer norm is auto-remove). **Everything else routes to the human named moderator** (§4.2) — no autonomous punitive action on the fuzzier non-CSAM lists, where a human gate is both lawful and warranted.
3. **The operational-language gate + deterministic verdicts (MCS §B.4, `SAFETY_LANDSCAPE`).** A non-CSAM watchlist is enforcing a *rule*; that rule must be public, dated, signed, reversible, and pass the operational-language ("checkable without judgment") test. Same inputs → same verdict → a false positive is reproducible and contestable.
4. **Reconsideration appeals with recused review (MCS §B.4, CEG §8.1.5).** A takedown — including an auto-fired CSAM one — is appealable via `reconsideration:{grounds}` to a fresh quorum with original adjudicators recused. CSAM auto-removes *and logs for audit* precisely so the (rare) false positive is recoverable through appeal, not silently lost. The threshold/score is recorded on the event so an appeal can examine the match quality.
5. **Threshold is the operator's, surfaced for audit.** `Match{score, threshold}` is recorded; an operator running a too-loose threshold is visible in the audit chain (high match volume, appeal-overturn rate).

Honest residual: a CSAM auto-removal false-positive *does* remove benign content before any human sees it, with only post-hoc appeal as recourse. This is the deliberate trade (the harm of leaving even one true-positive CSAM item up, plus the illegality of human pre-review, outweighs the over-block — the same judgment Bluesky/IFTAS/the field makes). The appeal path + the audited score are the mitigation; the trade is named, not hidden.

---

## 9. Build plan (priority + dependencies)

The watchlist rides on top of the MCS build plan — it is **Phase 1.5**, after the delegation spine and the CSAM matcher seam, layering the opt-in control + auto-fire over them.

**Dependencies (must land first):**
- MCS Phase 0 — the delegation spine: `scope::MODERATION` tokens + `signer_may_act_in_scope` chain-walk (`verify.rs`). *(CEG §11.10 names + enforces the scopes upstream RC19; remaining work is persist `admission.rs` enforcement + fabric wiring — MCS §9bis.)*
- MCS Phase 1 — `src/safety/hash_match.rs` (the `PerceptualHashMatcher` wired at `put_blob_signing` ingress) + `src/safety/takedown.rs` (the §11.4 fast-path).
- The operator-provisioned matcher (§7.1) — at minimum the reference `PdqHashMatcher` over open PDQ + public feeds to prove the seam.

**The watchlist work itself (Phase 1.5):**
1. `src/safety/watchlist.rs` — the `WatchlistEnable` config type + the enable/disable endpoint (consent.rs pattern, gated on `moderate`/`takedown` via `signer_may_act_in_scope`). Fixed dimension `watchlist:{id}`, `attestation_type: "watchlist_config"`, revocable by `withdraws`.
2. The per-group enable registry read (`watchlist_enables_for_group`) — a scores/attestation query, current (unrevoked) enables only.
3. The `on_publish` seam hook (§5.2) wired into the ingest path alongside `hash_match.rs`; the enable lookup gates whether the matcher runs at all (opt-in: no enable → matcher not invoked for that group).
4. The CSAM auto-fire branch → `takedown.rs::process_takedown_admission` under the enabling authority's key (§4.1).
5. The other-content auto-fire branch → `detection:watchlist_match` + `ModerationEvent`/route-to-moderator (§4.2).
6. `AlertOnly` shadow mode + the audited-score recording (§8).
7. Endpoint: a `/v1/safety/watchlists` enable/disable router (fabric-added convenience surface, same optional-normative status as the other `/v1/safety/*` endpoints — MCS §9 #5).

**Deferred:** video/streaming watchlist (per-frame/per-segment PDQ over the §10.5 streaming seam) — after static-content proves out (MCS Phase 5).

---

## 10. Upstream asks (genuine, beyond what MCS already files)

These are *in addition to* MCS §9 (the `moderate`/`takedown`/`review` enforcement, the PDQ adapter, the `/v1/safety/*` optional-normative endpoints — all of which the watchlist also needs).

1. **[fabric, then CEG] `watchlist:{id}` config-dimension vocabulary.** Like MCS §4.2/§4.3 age/rating: implement fabric-side over generic `scores` with a fixed `attestation_type: "watchlist_config"` + `watchlist:{id}` dimension (no new primitive needed near-term). *Upstream ask:* canonicalize the dimension name + the `class`/`mode`/`route_to_moderator` envelope shape so a watchlist enabled on one node is read identically on a federated peer (cross-fabric agreement on "is a watchlist on for this group").
2. **[persist] reference `PdqHashMatcher` adapter** (open PDQ + public feeds, §7.1) — the same ask as MCS §9 #4, sharpened: the watchlist is the *first concrete consumer* that makes the missing adapter a hard blocker, not just a nicety. Recommend the feature-gated `crates/ciris-pdq-matcher/` so the default build ships no hash-DB dependency.
3. **[CEG §7.8] `hard_case:watchlist_enabled:{group}` / `hard_case:watchlist_match:{group}` reserved reasons** — so a watchlist enable and an auto-fired match are auditable in the closed `hard_case:*` reason set (companion to MCS §9 #11's `community_unmoderated`/`community_moderator_promoted`). No new structural primitive — additions to the §7.8 reason set, so the enable + the auto-fire are *not silent* (the §10.1.4 anti-soft-censorship discipline applies to detection too: turning on a watchlist must itself be on the record).
4. **[CEG, policy] confirm the CSAM-disable semantics** — §3.3's open question: can the enabling authority disable a `csam:*` watchlist, or is it operator-pinned non-disensableable once on? Recommend: fabric default = disensableable by the enabling authority (consent requires revocability), operator MAY pin specific `csam:*` lists above the fabric. Confirm the intended default.

---

## 11. Summary

The content-watchlist is **opt-in (default OFF), per-group, by-authority auto-detection** built entirely over shipped primitives: a **config attestation** (the consent.rs recipe, gated on the §11.10 `moderate`/`takedown` scope, revocable by `withdraws`) wired to the **already-shipped §11.5 `PerceptualHashMatcher` seam** at the publish/share boundary, auto-firing the **§11.4 takedown fast-path** (CSAM) or a **named-moderator route** (other lists) — every step signed, attributed to the enabling authority, and on the audit chain. The three-way split is load-bearing: the **fabric** owns the mechanism, the **operator** owns the (un-shippable, licensed) hash-DB + the §2258A legal report, the **authority** owns the opt-in. The honest hard parts are real and named: (1) the hashes are operator-provisioned (you cannot ship IWF/NCMEC) — the fabric ships the seam + a reference open-PDQ adapter, never the restricted lists; (2) detection cannot reach §10.1.4 self/family private content (the E2EE-equivalent limit, already enforced in `ceg_egress.rs` — not claimed solved); (3) over-blocking is calibrated by AlertOnly shadow mode + the CSAM-auto / other-routes-to-human asymmetry + recused Reconsideration appeals; (4) the §2258A duty is the operator's — the fabric emits evidence, the operator reports. No new structural primitive; the gaps are the config-dimension vocabulary (fabric-side workaround + upstream canonicalization), the reference PDQ adapter (the first hard-blocking consumer), and two `hard_case:*` reserved reasons so the enable + the match are auditable, never silent. CIRIS's distinctive posture mirrors Bluesky's auto-remove peer model while adding what Bluesky lacks: the auto-fire is **attributed to a named accountable human and revocable**, not a platform's unilateral chokepoint — and it is scoped to a group that, by the §A invariant, already has a named moderator behind it.
```