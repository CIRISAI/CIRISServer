# Evidence registry — the `impl:` tier (CIRISServer#155)

[`cc_impl.tsv`](cc_impl.tsv) is CIRISServer's **spec-map manifest**: it resolves the
`impl:CIRISServer#155` pointers in the Constitution's
[`claims.tsv`](../../CIRISConstitution/constitution/claims.tsv) (CIRISConstitution#17,
CC 1.0-rc2) to the concrete reference-implementation symbol that establishes each
fabric/substrate claim — in CIRISServer itself or the **pinned** substrate crates
(`ciris-persist` / `ciris-verify-core` / `ciris-keyring` / `ciris-crypto` / `ciris-edge`).

It operationalizes the four-artifact view (Constitution ↔ Spec ↔ **Implementation** ↔
Formal): a reviewer — or CI — follows a claim from the Constitution to the code that
backs it, and a moved symbol can never silently rot the pointer.

## Format

Tab-separated, one row per `(claim, symbol)`:

```
decimal_id    claim_id    repo    path#symbol    crate@version
```

- `repo` ∈ `CIRISServer | CIRISPersist | CIRISVerify | CIRISEdge`
- `path#symbol` — repo-relative file path + the load-bearing fn/struct/enum/const/mod
  (the definer/enforcer: an admission gate, a canonicalizer, a wire struct, a verdict enum)
- `crate@version` — the crate the symbol lives in, at the version this workspace pins
  (`ciris-persist@v12.5.0`, `ciris-verify-core@v8.7.0`, `ciris-edge@v8.7.2`, …)
- `repo = —`, `crate@version = open` — the claim has **no** reference-implementation
  symbol at the substrate tier (see *Open findings* below); the row is informational.

## The gate — `tools/check_evidence.py`

Run in CI (the Linux `clippy + test` job, after the build populates the cargo git
checkouts). For every non-`open` row it asserts:

1. the `path#symbol` **resolves** at the pinned crate version — in-repo for
   `CIRISServer`; in the vendored checkout for the pinned git rev otherwise
   (a dead pointer is a **build failure**, i.e. a spec-regression test);
2. the row's `crate@version` **matches** the workspace pin in `Cargo.toml` (drift fails);
3. (locally, when the sibling repo is present) every `impl:CIRISServer#155`-tagged claim
   in the Constitution's `claims.tsv` has a manifest row (coverage).

## Coverage

**83** rows resolve to a symbol that was read against the CC text and confirmed to
*enforce* the claim; **30** rows are `open` — no enforcer exists at the substrate tier.

A row is only non-`open` when the cited symbol carries the section's normative weight.
A struct/const that merely *carries* a field the CC demands be *gated* is not evidence,
and several rows were demoted to `open` on exactly that ground (2026-07 evidence audit:
137 rows re-read against the CC text; 29 mis-assignments + 44 over-claims corrected).
An honest `open` is worth more than a plausible symbol that does not hold the line.

## Open findings → close them (implement) or `normative-only`

These claims are tagged `impl:CIRISServer#155` but have no reference-implementation
symbol yet. A claim the Constitution tags `impl:` asserts a reference implementation
*should* exist — so where one is genuinely possible, the disposition is **implement it**
(tracked below), not retag it away. Only claims with no realizable runtime artifact (a
bibliography, a MUST/SHOULD glossary) stay `normative-only`.

**Coverage gaps exposed by the evidence audit** (no enforcer anywhere; each needs an issue):

| decimal | claim | the missing enforcer |
|---|---|---|
| 2.1.1 | CLM-forward-compatibility | consumer-side unknown-envelope-field discipline (preserve on read + re-emission, exclude from verdict, never reject) |
| 2.3.1 | CLM-subject_kind-subject-2 | admission gate: a subject-naming dimension MUST carry `subject_key_ids` |
| 2.3.2.1 | CLM-registry-canonical | the `canonical:{hashalg}:{hex}` wire tag + `{platform}:{entity_kind}:{id}` preimage codec |
| 2.6.1.2 | CLM-per-field | the per-field omit-vs-materialize catalog (informational; no encoder implements the table) |
| 3.1.2.1 | CLM-provenance | the **v2** canonical-bytes contracts — shipped code is the v1 line-oriented preimage (`ciris.skill_import.v1` / `ciris.locale_manifest.v1`), CC pins JCS `…v2` |
| 3.4.6 | CLM-reservation-delivery | `delivery_receipt:` reserved-prefix rule + the "attester is a current stream/community member" emitter gate |
| 4.1.1 | CLM-anti-pattern-delegation | admission-time `delegates_to` **cycle rejection** (traversal is cycle-safe; the cycle-closing emission is never refused) + the 5-hop default cap |
| 4.4.3.1.1 | CLM-sub-quorum | the locality cell-pool `min_pool` fallback (`hard_case:locality_{scale_down,underpopulated,quorum_unreachable}`) |
| 4.4.3.2.4.1 | CLM-deterministic | `resolve_community` determinism pins (latest-non-superseded comparator, member ordering, founder-subset) + `resolve_member_transport` |
| 4.4.3.2.8 | CLM-affiliations | the affiliation institutional-governance record (`membership_basis`, classification/retention limbs, archetype presets) |
| 4.4.3.6 | CLM-policy-attestation | Policy I `ladder_verdict` composition; persist also still defaults to `DualAccept` (the deprecated `attestation:l{N}:*` form is admitted, contra the CC) |
| 4.4.3.10 | CLM-policy-trusted | Policy J composition gate (distributor chain ∧ content_class ∧ content_rating ∧ age_assurance) |
| 4.5.2.1 | CLM-subject_kind-subject-3 | same gate as 2.3.1 — `subject_key_ids` bearing for subject-naming dimensions |
| 4.5.8.1 | CLM-cohabitation | steward cross-attestation for substrate-role emissions (no cross-attestation surface exists in persist) |
| 4.5.13 | CLM-reverse-quorum | the **community** instance: 48 h proposal window, moderator/steward single-signature fast path, live-majority fallback tally |
| 5.3.2.4.1 | CLM-authority-local | `witness_relation` MUST be `self` on local-tier writes (`witness_relation` appears in no persist non-test code) |
| 5.3.4 | CLM-multi-steward | signed steward discovery responses — **CIRISServer#248** |

**Implement (tracked):**

| decimal | claim | disposition |
|---|---|---|
| 2.2 | CLM-conformance | implement — CIRISServer#159 (declared conformance level + gate) |
| 2.6.4 | CLM-policy-versioning | implement — CIRISServer#159 (version-negotiation policy) |
| 4.1.4 | CLM-withdraws-arbitrage | implement — CIRISServer#159 (arbitrage countermeasure) |
| 4.2.2.1 | CLM-hardware-class-hardware | implement — CIRISServer#159 (attest hardware_class; closes CC 8.3.1 R5) |
| 4.5.2.2 | CLM-compliance-vertical | implement — CIRISServer#159 (machine-readable vertical map) |
| 3.4.9 | CLM-co-stewarded | implement — CIRISPersist#365 (`licensure:*` co-stewarded admission) |
| 4.4.1 | CLM-frickerian | implement — CIRISAgent#911 (consumer tier) |
| 4.5.8.3 | CLM-settled | implement — CIRISAgent#911 (consumer tier) |
| 2.6.1.4 | CLM-worked | add a `test` vector — CIRISConformance#59 (the rule is impl'd via JCS) |

**Genuinely `normative-only`** (no realizable impl artifact):

| decimal | claim | why |
|---|---|---|
| 2.6.5 | CLM-references | normative references (bibliography) |
| 2.6.9 | CLM-conformance-language | MUST/SHOULD/SHALL definitions |
| 4.4 | CLM-composition-policies | policy preamble — the sub-policies A/I/J/L are already implemented |
| 4.5.10.4 | CLM-documents-what-2 | meta "what this documents" |

**Partial note (4.2.6, CLM-accord-livequorum):** resolved here to the live-quorum roster
enforcer (`verify_membership_change_by_live_quorum`), but the specific *"post-W contest on
append-log evidence + mandatory restore"* refinement has no symbol yet — tracked by
CIRISServer#122 (FSD-004 live-quorum Phase 3).

**Resolved-but-partial (the cited symbol enforces the section's core, a named limb is missing):**

| decimal | claim | what the cite does NOT cover |
|---|---|---|
| 3.4.3 | CLM-system | only the `substrate_persist` half — `substrate_edge` is not a representable `identity_type` in persist, so Edge's `system:*` reservation is unenforceable |
| 3.4.7.1 | CLM-identity-set | the reserved-prefix **rule table** uses `identity_type::set_contains`, but the inline `accord:` / `hard_case:` arms of `check_reserved_prefix_admission` still use scalar `!=` — a folded `{accord_holder, agent}` key is wrongly rejected (persist bug) |
| 4.2.1.2 | CLM-notify | the client badge distinguishes CONSTITUTIONAL / DRILL / NOTIFY, but `lifecycle:active` falls through to the NOTIFY branch — the CC forbids exactly that conflation |
| 4.5.1.1 | CLM-axis | per-axis schema validation exists (`BlobBackedSchemaResolver`) but the **default** resolver is `NoOpSchemaResolver` (fail-open) |
| 5.3.2.1 | CLM-holder | TTL + ContentMiss downweight ship; the `withdrawal_reason: "content_miss"` stamp is never emitted and the 2-holder-parallel policy is deferred |
| 5.3.6.1 | CLM-envelope-error | `CONSISTENCY_PROOF_INVALID` (422) is absent from `CegErrorCode` |
| 5.4.4 | CLM-welcome-wrap | the ML-DSA-65 inviter signature **is** implemented and verified before `open_base`; `unwrap_welcome` still falls back to the message's **inline** inviter pubkey when the directory misses (TOFU ⇒ no real sender authentication) — **CIRISEdge#331** |
| 5.4.5 | CLM-witness-content | the rate-hiding cover leaf ships; the per-tier witness-content scoping discipline does not |

---

## Also in this directory — `blocked_upstream.tsv` (a different manifest, a different gate)

[`blocked_upstream.tsv`](blocked_upstream.tsv) is **not** part of the `impl:` tier. It is
the adoption manifest for issues labelled `state:blocked-upstream`: one row per blocking
predicate, naming the upstream fact the issue waits on in a form a test can evaluate
against the substrate revisions `Cargo.lock` pins.

Where `cc_impl.tsv` asserts that a symbol we DEPEND on still resolves, this one asserts
that a capability we are WAITING FOR still does not — and goes red when it lands, so the
relabel to `state:unwired` happens on the substrate bump that caused it rather than at the
next hand audit. CIRISServer#361 asked for this three times: filing an upstream issue
creates a tracked obligation *there* and nothing *here*.

- gate: [`tests/blocked_upstream_gate.rs`](../tests/blocked_upstream_gate.rs) — offline,
  reads the pinned rev out of `Cargo.lock`
- label reconciliation (needs the GitHub API, so it cannot be a test):
  [`tools/check_blocked_upstream.sh`](../tools/check_blocked_upstream.sh)
